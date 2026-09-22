#include "DiskMonitorPage.h"
#include "../framework/PrivilegeElevationPrompt.h"
#include "../ui/TableInteractionSupport.h"
#include "../ui/VisibleTableWidget.h"

// ============================================================
// DiskMonitorPage.cpp
// Purpose:
// 1) Implement the independent 'Disk Monitor' page under the Hardware Dock.
// 2) Calculate the read/write rate per process using Toolhelp + GetProcessIoCounters;
// 3) Provide true file-level "disk activity" via Microsoft-Windows-Kernel-File ETW.
// ============================================================

#include "../Theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QClipboard>
#include <QCheckBox>
#include <QDateTime>
#include <QFileIconProvider>
#include <QFileInfo>
#include <QGuiApplication>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMetaObject>
#include <QModelIndex>
#include <QPointer>
#include <QPushButton>
#include <QSignalBlocker>
#include <QSizePolicy>
#include <QSplitter>
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstring>
#include <string>
#include <utility>

#include <TlHelp32.h>
// evntrace/evntcons/tdh provide ETW real-time session and event attribute decoding capabilities.
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>

#ifndef TRACE_LEVEL_VERBOSE
#define TRACE_LEVEL_VERBOSE 5
#endif

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Tdh.lib")

namespace
{
    constexpr double kActiveBytesPerSecondThreshold = 1.0; // kActiveBytesPerSecondThreshold: Minimum B/s to determine 'active IO'.
    constexpr int kRefreshIntervalMs = 1000;               // kRefreshIntervalMs: Page refresh interval.
    constexpr std::uint64_t kFileActivityRetentionMs = 5000; // kFileActivityRetentionMs: Time to retain unique logical rows after activity stops.
    constexpr wchar_t kDiskMonitorEtwSessionName[] = L"KswordDiskMonitorFileIo"; // kDiskMonitorEtwSessionName: ETW session name.
    constexpr GUID kDiskMonitorEtwSessionGuid =
        { 0x2b1f0d2a, 0x0d85, 0x4cd7, { 0xa5, 0x1e, 0xf5, 0x21, 0x5c, 0x48, 0x73, 0xe2 } };
    constexpr GUID kKernelFileProviderGuid =
        { 0xedd08927, 0x9cc4, 0x4e65, { 0xb9, 0x70, 0xc2, 0x56, 0x0f, 0xb5, 0xc2, 0x89 } };
    constexpr ULONGLONG kKernelFileKeywordFileName = 0x10ULL; // kKernelFileKeywordFileName: NameCreate/NameDelete path events.
    constexpr ULONGLONG kKernelFileKeywordFileIo = 0x20ULL;   // kKernelFileKeywordFileIo: Generic file I/O events.
    constexpr ULONGLONG kKernelFileKeywordOpEnd = 0x40ULL;    // kKernelFileKeywordOpEnd: OperationEnd completion event.
    constexpr ULONGLONG kKernelFileKeywordCreate = 0x80ULL;   // kKernelFileKeywordCreate: Create event, carrying FileObject and path.
    constexpr ULONGLONG kKernelFileKeywordRead = 0x100ULL;    // kKernelFileKeywordRead: Read event.
    constexpr ULONGLONG kKernelFileKeywordWrite = 0x200ULL;   // kKernelFileKeywordWrite: Write event.
    constexpr ULONGLONG kKernelFileKeywordMask =
        kKernelFileKeywordFileName
        | kKernelFileKeywordFileIo
        | kKernelFileKeywordOpEnd
        | kKernelFileKeywordCreate
        | kKernelFileKeywordRead
        | kKernelFileKeywordWrite;
    constexpr USHORT kKernelFileTaskNameCreate = 10;          // kKernelFileTaskNameCreate: FileKey to path mapping.
    constexpr USHORT kKernelFileTaskCreate = 12;              // kKernelFileTaskCreate: Mapping from FileObject to path.
    constexpr USHORT kKernelFileTaskClose = 14;               // kKernelFileTaskClose: Cleans up mappings when closing a file object.
    constexpr USHORT kKernelFileTaskRead = 15;                // kKernelFileTaskRead: Start of read request.
    constexpr USHORT kKernelFileTaskWrite = 16;               // kKernelFileTaskWrite: Write request start.
    constexpr USHORT kKernelFileTaskOperationEnd = 24;        // kKernelFileTaskOperationEnd: Request completion, used for response time.
    constexpr int kProcessIoPriorityInformationClass = 33;    // kProcessIoPriorityInformationClass：NtQueryInformationProcess(ProcessIoPriority)。

    void installDiskMonitorTableCopyMenu(QTableWidget* tableWidget, const int processIdColumn)
    {
        // installDiskMonitorTableCopyMenu：
        // - Input: Process rate table or file activity table of the disk monitoring page;
        // - Processing: On right-clicking a selected row, copy all visible columns of that row as TSV.
        // - Returns: None. Only copies monitoring evidence without affecting the ETW session or sampling state.
        if (tableWidget == nullptr)
        {
            return;
        }

        tableWidget->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(tableWidget, &QTableWidget::customContextMenuRequested, tableWidget, [tableWidget, processIdColumn](const QPoint& localPosition)
        {
            const QModelIndex kClickedIndex = tableWidget->indexAt(localPosition);
            if (kClickedIndex.isValid())
            {
                tableWidget->setCurrentCell(kClickedIndex.row(), kClickedIndex.column());
            }

            QMenu contextMenu(tableWidget);
            contextMenu.setStyleSheet(ksword_theme::contextMenuStyle());
            QAction* copyRowAction = contextMenu.addAction(
                QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
                QStringLiteral("复制当前行"));
            copyRowAction->setEnabled(tableWidget->currentRow() >= 0);
            quint32 processId = 0;
            if (processIdColumn >= 0 && processIdColumn < tableWidget->columnCount() &&
                tableWidget->currentRow() >= 0 && tableWidget->currentRow() < tableWidget->rowCount())
            {
                const QTableWidgetItem* processIdItem = tableWidget->item(
                    tableWidget->currentRow(),
                    processIdColumn);
                bool parseOk = false;
                const uint kParsedProcessId = processIdItem != nullptr
                    ? processIdItem->text().toUInt(&parseOk, 10)
                    : 0U;
                if (parseOk && kParsedProcessId != 0U)
                {
                    processId = static_cast<quint32>(kParsedProcessId);
                }
            }
            QAction* openProcessDetailAction = nullptr;
            if (processIdColumn >= 0)
            {
                openProcessDetailAction = contextMenu.addAction(
                    QIcon(QStringLiteral(":/Icon/process_details.svg")),
                    QStringLiteral("转到进程详细信息"));
                openProcessDetailAction->setEnabled(processId != 0U);
            }

            const QAction* selectedAction = contextMenu.exec(tableWidget->viewport()->mapToGlobal(localPosition));
            if (selectedAction == openProcessDetailAction)
            {
                ks::ui::openProcessDetailByPid(processId);
                return;
            }
            if (selectedAction != copyRowAction)
            {
                return;
            }

            QClipboard* clipboardObject = QGuiApplication::clipboard();
            const int kRowIndex = tableWidget->currentRow();
            if (clipboardObject == nullptr || kRowIndex < 0 || kRowIndex >= tableWidget->rowCount())
            {
                return;
            }

            QStringList rowFields;
            rowFields.reserve(tableWidget->columnCount());
            for (int columnIndex = 0; columnIndex < tableWidget->columnCount(); ++columnIndex)
            {
                const QTableWidgetItem* item = tableWidget->item(kRowIndex, columnIndex);
                rowFields.push_back(item != nullptr ? item->text() : QString());
            }
            clipboardObject->setText(rowFields.join(QLatin1Char('\t')));
        });
    }

    // ProcessColumn：
    // - Purpose: Define the column order for the process-level disk rate table.
    // - Usage: Reused when populating the table, setting column widths, and synchronizing checkboxes.
    enum ProcessColumn
    {
        kProcessColumnChecked = 0,
        kProcessColumnPid,
        kProcessColumnName,
        kProcessColumnReadRate,
        kProcessColumnWriteRate,
        kProcessColumnTotalRate,
        kProcessColumnResponse,
        kProcessColumnReadOps,
        kProcessColumnWriteOps,
        kProcessColumnPath,
        kProcessColumnCount
    };

    // ActivityColumn：
    // - Purpose: Define the column order for the 'Disk Activity' table below.
    // - Call: Aggregates activity output based on user-selected PIDs.
    enum ActivityColumn
    {
        kActivityColumnPid = 0,
        kActivityColumnProcess,
        kActivityColumnFile,
        kActivityColumnReadRate,
        kActivityColumnWriteRate,
        kActivityColumnTotalRate,
        kActivityColumnIoPriority,
        kActivityColumnResponse,
        kActivityColumnCount
    };

    // UniqueHandle：
    // - Purpose: RAII wrapper for Win32 HANDLE;
    // - Processing: automatically CloseHandle on destruction;
    // - Returns: valid() indicates whether the handle is usable.
    class UniqueHandle final
    {
    public:
        explicit UniqueHandle(HANDLE handleValue = nullptr)
            : handle_(handleValue)
        {
        }

        ~UniqueHandle()
        {
            reset(nullptr);
        }

        UniqueHandle(const UniqueHandle&) = delete;
        UniqueHandle& operator=(const UniqueHandle&) = delete;

        UniqueHandle(UniqueHandle&& other) noexcept
            : handle_(other.handle_)
        {
            other.handle_ = nullptr;
        }

        UniqueHandle& operator=(UniqueHandle&& other) noexcept
        {
            if (this == &other)
            {
                return *this;
            }
            reset(nullptr);
            handle_ = other.handle_;
            other.handle_ = nullptr;
            return *this;
        }

        HANDLE get() const
        {
            return handle_;
        }

        bool valid() const
        {
            return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
        }

    void reset(HANDLE newHandle)
        {
            if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE)
            {
                ::CloseHandle(handle_);
            }
            handle_ = newHandle;
        }

    private:
        HANDLE handle_ = nullptr; // m_handle: Currently held Win32 handle.
    };

    // steadyTickMs：
    // - Purpose: Return the monotonic clock value in milliseconds.
    // - Processing: Used only for differences between adjacent samples, not for mapping real time;
    // - Returns: steady_clock millisecond count.
    std::uint64_t steadyTickMs()
    {
        const auto kNowValue = std::chrono::steady_clock::now().time_since_epoch();
        return static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(kNowValue).count());
    }

    // fileTimeToUInt64：
    // - Purpose: Convert FILETIME to a 100ns count.
    // - Processing: Concatenate high and low bits.
    // - Returns: 64-bit FILETIME value.
    std::uint64_t fileTimeToUInt64(const FILETIME& fileTimeValue)
    {
        return (static_cast<std::uint64_t>(fileTimeValue.dwHighDateTime) << 32U)
            | static_cast<std::uint64_t>(fileTimeValue.dwLowDateTime);
    }

    // queryProcessPath：
    // - Purpose: Read the image path via the provided process handle.
    // - Processing: Prefer QueryFullProcessImageNameW.
    // - Returns: full path on success, empty string on failure.
    QString queryProcessPath(const HANDLE processHandle)
    {
        if (processHandle == nullptr || processHandle == INVALID_HANDLE_VALUE)
        {
            return QString();
        }

        std::vector<wchar_t> pathBuffer(32768, L'\0');
        DWORD pathLength = static_cast<DWORD>(pathBuffer.size());
        if (::QueryFullProcessImageNameW(processHandle, 0, pathBuffer.data(), &pathLength) == FALSE)
        {
            return QString();
        }
        if (pathLength == 0)
        {
            return QString();
        }
        return QString::fromWCharArray(pathBuffer.data(), static_cast<int>(pathLength));
    }

    // NtQueryInformationProcessFunction：
    // - Input: process handle, information class, output buffer, buffer size, and optional return length.
    // - Processing: Bind ntdll!NtQueryInformationProcess at runtime to avoid conflicts with SDK winternl declarations.
    // - Returns: NTSTATUS; non-negative values indicate successful query.
    using NtQueryInformationProcessFunction = LONG(WINAPI*)(
        HANDLE processHandle,
        ULONG processInformationClass,
        PVOID processInformation,
        ULONG processInformationLength,
        PULONG returnLength);

    // ioPriorityHintToText：
    // - Purpose: Convert Windows I/O priority enum to Resource Monitor-style Chinese text.
    // - Handling: 0/1/2/3/4 map to VeryLow/Low/Normal/High/Critical respectively;
    // - Return: Unknown enum returns "Unknown (n)".
    QString ioPriorityHintToText(const std::uint32_t priorityValue)
    {
        switch (priorityValue)
        {
        case 0:
            return QStringLiteral("后台");
        case 1:
            return QStringLiteral("低");
        case 2:
            return QStringLiteral("普通");
        case 3:
            return QStringLiteral("高");
        case 4:
            return QStringLiteral("关键");
        default:
            return QStringLiteral("未知(%1)").arg(priorityValue);
        }
    }

    // queryProcessIoPriorityText：
    // - Purpose: Query process-level I/O priority as the display value when file events lack a priority field.
    // - Processing: Dynamically resolve NtQueryInformationProcess to avoid importing additional libraries.
    // - Returns: The priority text in Chinese on success, or an empty string on failure.
    QString queryProcessIoPriorityText(const HANDLE processHandle)
    {
        if (processHandle == nullptr || processHandle == INVALID_HANDLE_VALUE)
        {
            return QString();
        }

        HMODULE ntdllModule = ::GetModuleHandleW(L"ntdll.dll");
        if (ntdllModule == nullptr)
        {
            return QString();
        }

        auto* queryFunction = reinterpret_cast<NtQueryInformationProcessFunction>(
            ::GetProcAddress(ntdllModule, "NtQueryInformationProcess"));
        if (queryFunction == nullptr)
        {
            return QString();
        }

        ULONG ioPriorityValue = 0;
        const LONG kStatus = queryFunction(
            processHandle,
            kProcessIoPriorityInformationClass,
            &ioPriorityValue,
            sizeof(ioPriorityValue),
            nullptr);
        if (kStatus < 0)
        {
            return QString();
        }
        return ioPriorityHintToText(static_cast<std::uint32_t>(ioPriorityValue));
    }

    // queryProcessCreateTime：
    // - Purpose: Read the process creation time to identify PID reuse;
    // - Processing: Call GetProcessTimes, caring only about creationTime.
    // - Returns: Returns FILETIME in 100ns units on success; returns 0 on failure.
    std::uint64_t queryProcessCreateTime(const HANDLE processHandle)
    {
        if (processHandle == nullptr || processHandle == INVALID_HANDLE_VALUE)
        {
            return 0;
        }

        FILETIME createTime{};
        FILETIME exitTime{};
        FILETIME kernelTime{};
        FILETIME userTime{};
        if (::GetProcessTimes(processHandle, &createTime, &exitTime, &kernelTime, &userTime) == FALSE)
        {
            return 0;
        }
        return fileTimeToUInt64(createTime);
    }

    // isSameProcessIdentity：
    // - Purpose: Determine if the current PID's historical baseline still belongs to the same process instance.
    // - Processing: Both creation times must match if available; otherwise, allow fallback to reusing the PID baseline.
    // - Returns: true if the values can be used for difference calculation.
    bool isSameProcessIdentity(
        const std::uint64_t currentCreateTime100ns,
        const std::uint64_t previousCreateTime100ns)
    {
        if (currentCreateTime100ns != 0 && previousCreateTime100ns != 0)
        {
            return currentCreateTime100ns == previousCreateTime100ns;
        }
        return true;
    }

    // deltaOrZero：
    // - Purpose: Calculate the positive delta of a monotonic cumulative counter.
    // - Processing: Return 0 when encountering counter wraparound or reset;
    // - Returns: currentValue - previousValue or 0.
    std::uint64_t deltaOrZero(
        const std::uint64_t currentValue,
        const std::uint64_t previousValue)
    {
        return currentValue >= previousValue ? currentValue - previousValue : 0;
    }

    // tableHeaderStyle：
    // - Purpose: Generate disk monitor table header style.
    // - Processing: Directly use the project theme color.
    // - Returns: A style snippet assignable to QTableWidget.
    QString tableHeaderStyle()
    {
        return QStringLiteral(
            "QHeaderView::section{"
            "  color:%1;"
            "  background:transparent; /* %2 */"
            "  border:1px solid %3;"
            "  padding:4px;"
            "  font-weight:600;"
            "}"
            "QTableWidget{"
            "  gridline-color:%3;"
            "  background:transparent;"
            "  background-color:transparent;"
            "  alternate-background-color:transparent;"
            "  color:%1;"
            "}"
            "QTableWidget::viewport{"
            "  background:transparent;"
            "  background-color:transparent;"
            "}"
            "}")
            .arg(ksword_theme::textPrimaryHex())
            .arg(ksword_theme::surfaceAltHex())
            .arg(ksword_theme::borderHex());
    }

    // trimWideString：
    // - Purpose: Convert UTF-16 buffers from ETW properties into QString.
    // - Processing: Trim padding after the first NUL;
    // - Returns: Cleaned text.
    QString trimWideString(const wchar_t* textPointer, const int charCount)
    {
        if (textPointer == nullptr || charCount <= 0)
        {
            return QString();
        }

        QString textValue = QString::fromWCharArray(textPointer, charCount);
        const int kNullIndex = textValue.indexOf(QChar(u'\0'));
        if (kNullIndex >= 0)
        {
            textValue.truncate(kNullIndex);
        }
        return textValue.trimmed();
    }

    // readScalar：
    // - Purpose: Read a fixed-width integer from an ETW property buffer.
    // - Processing: Return false if length is insufficient.
    // - Return: true indicates that valueOut has been populated.
    template <typename TValue>
    bool readScalar(const std::vector<unsigned char>& dataBuffer, TValue* valueOut)
    {
        if (valueOut == nullptr || dataBuffer.size() < sizeof(TValue))
        {
            return false;
        }

        TValue localValue{};
        std::memcpy(&localValue, dataBuffer.data(), sizeof(TValue));
        *valueOut = localValue;
        return true;
    }

    // normalizeEtwPropertyName：
    // - Purpose: normalize ETW property names to lowercase alphanumeric characters.
    // - Processing: ignore differences in spaces, underscores, etc.
    // - Returns: a property name suitable for heuristic matching.
    QString normalizeEtwPropertyName(const QString& propertyNameText)
    {
        QString normalizedText;
        normalizedText.reserve(propertyNameText.size());
        for (const QChar kCh : propertyNameText.toLower())
        {
            if (kCh.isLetterOrNumber())
            {
                normalizedText.push_back(kCh);
            }
        }
        return normalizedText;
    }

    // isFileObjectProperty：
    // - Purpose: Identify properties like FileObject / FileKey that can serve as path mapping keys.
    // - Processing: Slight differences in field names for Kernel FileIo events across versions.
    // - Return: true indicates this property can be used for m_filePathByObject.
    bool isFileObjectProperty(const QString& normalizedName)
    {
        return normalizedName == QStringLiteral("fileobject")
            || normalizedName == QStringLiteral("filekey")
            || normalizedName == QStringLiteral("fileid")
            || normalizedName == QStringLiteral("fileobj")
            || normalizedName == QStringLiteral("fileobjectkey");
    }

    // isIrpProperty：
    // - Purpose: Identify IRP pointers in Kernel-File events.
    // - Processing: Read/Write and OperationEnd are linked via the same IRP to associate start and completion;
    // - Returns: true indicates this field can serve as a key for m_pendingFileIoByIrp.
    bool isIrpProperty(const QString& normalizedName)
    {
        return normalizedName == QStringLiteral("irp")
            || normalizedName == QStringLiteral("irpptr")
            || normalizedName == QStringLiteral("irpaddress")
            || normalizedName == QStringLiteral("irpobject");
    }

    // isTransferSizeProperty：
    // - Purpose: Identify the byte count attribute in read/write events.
    // - Processing: Support field names such as IoSize, TransferSize, Size, and Length.
    // - Returns: true if it can be used as the transfer size in bytes.
    bool isTransferSizeProperty(const QString& normalizedName)
    {
        return normalizedName == QStringLiteral("iosize")
            || normalizedName == QStringLiteral("transfersize")
            || normalizedName == QStringLiteral("size")
            || normalizedName == QStringLiteral("length")
            || normalizedName == QStringLiteral("bytecount")
            || normalizedName == QStringLiteral("bytes");
    }

    // isDurationProperty：
    // - Purpose: Identify attributes in ETW events that may represent duration.
    // - Handling: Different Providers may use ElapsedTime or Duration;
    // - Returns: true indicates the property can be used for response time estimation.
    bool isDurationProperty(const QString& normalizedName)
    {
        return normalizedName == QStringLiteral("duration")
            || normalizedName == QStringLiteral("elapsedtime")
            || normalizedName == QStringLiteral("responsetime")
            || normalizedName == QStringLiteral("iotime");
    }

    // isIoPriorityProperty：
    // - Purpose: Identify the I/O priority field that may be directly provided in the ETW manifest.
    // - Processing: The current Kernel-File common template lacks this field, but compatibility with other system versions is retained.
    // - Returns: true indicates numericValue can be converted to priority text.
    bool isIoPriorityProperty(const QString& normalizedName)
    {
        return normalizedName == QStringLiteral("iopriority")
            || normalizedName == QStringLiteral("priority")
            || normalizedName == QStringLiteral("priorityhint")
            || normalizedName == QStringLiteral("iopriorityhint")
            || normalizedName == QStringLiteral("ioprio");
    }

    // isFileNameProperty：
    // - Purpose: Identify the ETW filename property.
    // - Handling: Name, FileName, OpenPath, etc., may all appear.
    // - Returns: true if valueText can be considered a path candidate.
    bool isFileNameProperty(const QString& normalizedName)
    {
        return normalizedName == QStringLiteral("filename")
            || normalizedName == QStringLiteral("name")
            || normalizedName == QStringLiteral("pathname")
            || normalizedName == QStringLiteral("filepath")
            || normalizedName == QStringLiteral("openpath")
            || normalizedName == QStringLiteral("filepathname");
    }

    // trimNtPathPrefix：
    // - Purpose: Cleans the NT namespace prefix from ETW paths.
    // - Processing: Convert \??\C:\x to C:\x and \\?\C:\x to C:\x.
    // - Return: A path format closer to the Resource Monitor display convention.
    QString trimNtPathPrefix(const QString& pathText)
    {
        QString normalizedPath = pathText.trimmed();
        if (normalizedPath.startsWith(QStringLiteral("\\??\\")))
        {
            normalizedPath = normalizedPath.mid(4);
        }
        if (normalizedPath.startsWith(QStringLiteral("\\\\?\\")))
        {
            normalizedPath = normalizedPath.mid(4);
        }
        return normalizedPath;
    }

    // queryDosDevicePrefixMap：
    // - Purpose: enumerate the mapping from DOS drive letters to \Device\HarddiskVolumeX.
    // - Processing: Perform a lightweight query of current drive letters on each conversion to avoid caching drive letter hot-plug states.
    // - Returns: A mapping list sorted by NT device name prefix length in descending order.
    std::vector<std::pair<QString, QString>> queryDosDevicePrefixMap()
    {
        static std::mutex cacheMutex;
        static std::vector<std::pair<QString, QString>> cachedMappingList;
        static std::uint64_t lastRefreshMs = 0;

        std::lock_guard<std::mutex> cacheLock(cacheMutex);
        const std::uint64_t kNowMs = steadyTickMs();
        if (lastRefreshMs != 0 && kNowMs >= lastRefreshMs && (kNowMs - lastRefreshMs) < 30000)
        {
            // Path events may occur frequently; refreshing drive letter mappings every 30 seconds covers common hot-plug scenarios.
            return cachedMappingList;
        }

        std::vector<std::pair<QString, QString>> mappingList;
        DWORD driveMask = ::GetLogicalDrives();
        for (wchar_t driveLetter = L'A'; driveLetter <= L'Z'; ++driveLetter)
        {
            if ((driveMask & (1UL << (driveLetter - L'A'))) == 0)
            {
                continue;
            }

            wchar_t driveName[] = { driveLetter, L':', L'\0' };
            std::vector<wchar_t> targetBuffer(4096, L'\0');
            const DWORD kTargetLength = ::QueryDosDeviceW(
                driveName,
                targetBuffer.data(),
                static_cast<DWORD>(targetBuffer.size()));
            if (kTargetLength == 0)
            {
                continue;
            }

            const QString kDevicePrefix = QString::fromWCharArray(targetBuffer.data()).trimmed();
            if (kDevicePrefix.isEmpty())
            {
                continue;
            }
            mappingList.emplace_back(kDevicePrefix, QString::fromWCharArray(driveName));
        }

        std::sort(
            mappingList.begin(),
            mappingList.end(),
            [](const std::pair<QString, QString>& left, const std::pair<QString, QString>& right)
            {
                return left.first.size() > right.first.size();
            });

        cachedMappingList = mappingList;
        lastRefreshMs = kNowMs;
        return cachedMappingList;
    }

    // normalizeEtwFilePath：
    // - Purpose: normalize paths from Kernel-File events into a display format similar to Resource Monitor.
    // Handling: Preferably convert \Device\HarddiskVolumeX to a drive letter path; if conversion fails, retain the original NT path.
    // - Returns: The cleaned file path; returns an empty string if the input is empty.
    QString normalizeEtwFilePath(const QString& pathText)
    {
        QString normalizedPath = trimNtPathPrefix(pathText);
        if (normalizedPath.isEmpty())
        {
            return QString();
        }
        if (normalizedPath.contains(QStringLiteral(":\\")))
        {
            return normalizedPath;
        }

        const std::vector<std::pair<QString, QString>> kMappingList = queryDosDevicePrefixMap();
        for (const auto& mapping : kMappingList)
        {
            const QString& devicePrefix = mapping.first;
            if (!normalizedPath.startsWith(devicePrefix, Qt::CaseInsensitive))
            {
                continue;
            }

            QString suffix = normalizedPath.mid(devicePrefix.size());
            if (!suffix.startsWith(QStringLiteral("\\")) && !suffix.isEmpty())
            {
                suffix.prepend(QStringLiteral("\\"));
            }
            return mapping.second + suffix;
        }
        return normalizedPath;
    }

    // fileActivityIdentityKey：
    // - Purpose: Generate a stable identity for file activity in the resource monitor style.
    // - Handling: PID maintains process instance boundaries; paths use unified separators, case normalization, and trimmed leading/trailing whitespace.
    // - Return: Same PID + file path always yields the same identity; different PIDs never merge.
    QString fileActivityIdentityKey(
        const std::uint32_t pid,
        const QString& filePath)
    {
        QString normalizedPath = filePath.trimmed();
        normalizedPath.replace(QLatin1Char('/'), QLatin1Char('\\'));
        return QStringLiteral("%1|%2")
            .arg(pid)
            .arg(normalizedPath.toCaseFolded());
    }

    // queryEventNameFromTdh：
    // - Purpose: Extract task name/opcode name from TRACE_EVENT_INFO;
    // - Handling: Prefer EventNameOffset; otherwise use TaskName + OpcodeName.
    // - Returns: the event name on success; returns "OpcodeN" if the manifest lacks a name; returns an empty string if TDH fails.
    QString queryEventNameFromTdh(
        const EVENT_RECORD* eventRecord,
        std::vector<unsigned char>* eventInfoBufferOut = nullptr)
    {
        if (eventRecord == nullptr)
        {
            return QString();
        }

        DWORD infoBufferSize = 0;
        ULONG status = ::TdhGetEventInformation(
            const_cast<EVENT_RECORD*>(eventRecord),
            0,
            nullptr,
            nullptr,
            &infoBufferSize);
        if (status != ERROR_INSUFFICIENT_BUFFER || infoBufferSize == 0)
        {
            return QString();
        }

        std::vector<unsigned char> infoBuffer(infoBufferSize, 0);
        auto* eventInfo = reinterpret_cast<PTRACE_EVENT_INFO>(infoBuffer.data());
        status = ::TdhGetEventInformation(
            const_cast<EVENT_RECORD*>(eventRecord),
            0,
            nullptr,
            eventInfo,
            &infoBufferSize);
        if (status != ERROR_SUCCESS || eventInfo == nullptr)
        {
            return QString();
        }

        QString eventNameText;
        if (eventInfo->EventNameOffset != 0)
        {
            eventNameText = QString::fromWCharArray(reinterpret_cast<const wchar_t*>(
                infoBuffer.data() + eventInfo->EventNameOffset)).trimmed();
        }
        if (eventNameText.isEmpty() && eventInfo->TaskNameOffset != 0)
        {
            eventNameText = QString::fromWCharArray(reinterpret_cast<const wchar_t*>(
                infoBuffer.data() + eventInfo->TaskNameOffset)).trimmed();
        }
        if (eventInfo->OpcodeNameOffset != 0)
        {
            const QString kOpcodeText = QString::fromWCharArray(reinterpret_cast<const wchar_t*>(
                infoBuffer.data() + eventInfo->OpcodeNameOffset)).trimmed();
            if (!kOpcodeText.isEmpty())
            {
                eventNameText = eventNameText.isEmpty()
                    ? kOpcodeText
                    : QStringLiteral("%1/%2").arg(eventNameText, kOpcodeText);
            }
        }

        if (eventInfoBufferOut != nullptr)
        {
            *eventInfoBufferOut = std::move(infoBuffer);
        }
        // Retains the opcode number when the manifest lacks a friendly name to aid debugging of unknown provider events.
        if (eventNameText.isEmpty())
        {
            eventNameText = QStringLiteral("Opcode%1")
                .arg(static_cast<unsigned int>(eventRecord->EventHeader.EventDescriptor.Opcode));
        }
        return eventNameText;
    }

    QWidget* createDiskMonitorSection(
        QWidget* parentWidget,
        QToolButton** toggleButtonOut,
        const QString& titleText,
        QWidget* contentWidget,
        QWidget* firstHeaderControl = nullptr,
        QWidget* secondHeaderControl = nullptr)
    {
        // createDiskMonitorSection：
        // - Input: Parent widget, title, content widget, and optional A/B widgets;
        // - Processing: Create a collapsible resource monitor-style section with synchronized visibility for the arrow and content;
        // - Returns: A widget region ready to be added to a vertical QSplitter.
        auto* sectionWidget = new QWidget(parentWidget);
        auto* sectionLayout = new QVBoxLayout(sectionWidget);
        sectionLayout->setContentsMargins(0, 0, 0, 0);
        sectionLayout->setSpacing(0);

        auto* headerWidget = new QWidget(sectionWidget);
        auto* headerLayout = new QHBoxLayout(headerWidget);
        headerLayout->setContentsMargins(4, 2, 4, 2);
        headerLayout->setSpacing(0);
        headerWidget->setStyleSheet(QStringLiteral(
            "QWidget{background:%1;border:1px solid %2;}")
            .arg(ksword_theme::surfaceAltHex(), ksword_theme::borderHex()));

        auto* toggleButton = new QToolButton(headerWidget);
        toggleButton->setText(titleText);
        toggleButton->setCheckable(true);
        toggleButton->setChecked(true);
        toggleButton->setArrowType(Qt::NoArrow);
        toggleButton->setToolButtonStyle(Qt::ToolButtonTextOnly);
        toggleButton->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        toggleButton->setStyleSheet(QStringLiteral(
            "QToolButton{border:0;background:transparent;color:%1;"
            "font-size:14px;font-weight:700;text-align:left;padding:3px;}")
            .arg(ksword_theme::textPrimaryHex()));
        toggleButton->setToolTip(QStringLiteral("展开或折叠该磁盘监控区域"));
        headerLayout->addWidget(toggleButton, 1);

        if (firstHeaderControl != nullptr)
        {
            headerLayout->addWidget(firstHeaderControl, 0);
        }
        if (secondHeaderControl != nullptr)
        {
            headerLayout->addWidget(secondHeaderControl, 0);
        }

        auto* arrowButton = new QToolButton(headerWidget);
        arrowButton->setArrowType(Qt::DownArrow);
        arrowButton->setAutoRaise(true);
        arrowButton->setFocusPolicy(Qt::NoFocus);
        arrowButton->setFixedWidth(24);
        arrowButton->setToolTip(
            QStringLiteral("展开或折叠该磁盘监控区域"));
        arrowButton->setStyleSheet(QStringLiteral(
            "QToolButton{border:0;background:transparent;color:%1;padding:2px;}")
            .arg(ksword_theme::textPrimaryHex()));
        headerLayout->addWidget(arrowButton, 0);

        sectionLayout->addWidget(headerWidget, 0);
        sectionLayout->addWidget(contentWidget, 1);
        sectionWidget->setSizePolicy(
            QSizePolicy::Preferred,
            QSizePolicy::Expanding);

        QObject::connect(
            toggleButton,
            &QToolButton::toggled,
            sectionWidget,
            [
                toggleButton,
                arrowButton,
                contentWidget,
                headerWidget,
                sectionWidget
            ](const bool expanded)
            {
                auto* splitter =
                    qobject_cast<QSplitter*>(sectionWidget->parentWidget());
                const int kSplitterIndex =
                    splitter != nullptr
                    ? splitter->indexOf(sectionWidget)
                    : -1;
                QList<int> splitterSizes =
                    splitter != nullptr
                    ? splitter->sizes()
                    : QList<int>{};

                if (expanded)
                {
                    sectionWidget->setMinimumHeight(0);
                    sectionWidget->setMaximumHeight(QWIDGETSIZE_MAX);
                    contentWidget->setVisible(true);
                    const int kPreviousExpandedHeight =
                        sectionWidget->property(
                            "kswordDiskMonitorExpandedHeight").toInt();
                    if (kSplitterIndex >= 0 &&
                        kSplitterIndex < splitterSizes.size() &&
                        kPreviousExpandedHeight > 0)
                    {
                        splitterSizes[kSplitterIndex] =
                            kPreviousExpandedHeight;
                        splitter->setSizes(splitterSizes);
                    }
                }
                else
                {
                    if (kSplitterIndex >= 0 &&
                        kSplitterIndex < splitterSizes.size())
                    {
                        sectionWidget->setProperty(
                            "kswordDiskMonitorExpandedHeight",
                            splitterSizes[kSplitterIndex]);
                    }
                    contentWidget->setVisible(false);
                    const int kCollapsedHeight =
                        std::max(1, headerWidget->sizeHint().height());
                    sectionWidget->setMinimumHeight(kCollapsedHeight);
                    sectionWidget->setMaximumHeight(kCollapsedHeight);
                    if (kSplitterIndex >= 0 &&
                        kSplitterIndex < splitterSizes.size())
                    {
                        splitterSizes[kSplitterIndex] = kCollapsedHeight;
                        splitter->setSizes(splitterSizes);
                    }
                }
                sectionWidget->updateGeometry();
                arrowButton->setArrowType(
                    expanded ? Qt::DownArrow : Qt::RightArrow);
            });
        QObject::connect(
            arrowButton,
            &QToolButton::clicked,
            toggleButton,
            [toggleButton]()
            {
                toggleButton->toggle();
            });
        if (toggleButtonOut != nullptr)
        {
            *toggleButtonOut = toggleButton;
        }
        return sectionWidget;
    }
}

DiskMonitorPage::DiskMonitorPage(QWidget* parent)
    : QWidget(parent)
{
    // Construction order: build UI and connect events first; start ETW/process enumeration after the first frame.
    initializeUi();
    initializeConnections();

    refreshTimer_ = new QTimer(this);
    refreshTimer_->setInterval(kRefreshIntervalMs);
    connect(refreshTimer_, &QTimer::timeout, this, [this]()
    {
        refreshNow();
    });

    // Defer the first sampling to the event loop to allow parent tab switching to complete rendering, avoiding blocking user clicks during construction.
    QTimer::singleShot(120, this, [this]()
    {
        startInitialSampling();
    });
}

DiskMonitorPage::~DiskMonitorPage()
{
    if (refreshTimer_ != nullptr)
    {
        refreshTimer_->stop();
    }
    processSamplingStopRequested_.store(
        true,
        std::memory_order_release);
    if (processSamplingThread_ != nullptr && processSamplingThread_->joinable())
    {
        // First cooperatively cancel the sampling thread's current synchronous volume I/O, then join;
        // keep the object alive and avoid detach, which could cause a UAF in raw-this callbacks.
        CancelSynchronousIo(processSamplingThread_->native_handle());
        processSamplingThread_->join();
    }
    processSamplingThread_.reset();
    processSamplingInProgress_.store(false);
    if (storagePanel_ != nullptr)
    {
        // Transfer the lease only after collectSamples has fully exited; the GUI thread does not execute OFF.
        storagePanel_->retirePerformanceCountersAsync(
            QStringLiteral("disk-monitor-page-destructor"));
    }
    stopFileActivityEtw();
}

void DiskMonitorPage::initializeUi()
{
    rootLayout_ = new QVBoxLayout(this);
    rootLayout_->setContentsMargins(6, 6, 6, 6);
    rootLayout_->setSpacing(6);

    QHBoxLayout* headerLayout = new QHBoxLayout();
    headerLayout->setContentsMargins(0, 0, 0, 0);
    headerLayout->setSpacing(8);

    titleLabel_ = new QLabel(QStringLiteral("硬盘监控"), this);
    titleLabel_->setStyleSheet(
        QStringLiteral("font-size:18px;font-weight:700;color:%1;")
        .arg(ksword_theme::textPrimaryHex()));
    headerLayout->addWidget(titleLabel_, 0);

    statusLabel_ = new QLabel(QStringLiteral("正在建立采样基线..."), this);
    statusLabel_->setStyleSheet(
        QStringLiteral("font-size:13px;color:%1;").arg(ksword_theme::textSecondaryHex()));
    headerLayout->addWidget(statusLabel_, 1);

    refreshButton_ = new QPushButton(QStringLiteral("刷新"), this);
    refreshButton_->setToolTip(QStringLiteral("立即刷新进程磁盘 IO 计数器"));
    refreshButton_->setStyleSheet(ksword_theme::themedButtonStyle());
    headerLayout->addWidget(refreshButton_, 0);
    rootLayout_->addLayout(headerLayout, 0);

    summaryLabel_ = new QLabel(QStringLiteral("读: 0 B/s    写: 0 B/s    勾选进程: 0"), this);
    summaryLabel_->setStyleSheet(
        QStringLiteral("font-size:13px;font-weight:600;color:%1;")
        .arg(ksword_theme::textPrimaryHex()));
    rootLayout_->addWidget(summaryLabel_, 0);

    QHBoxLayout* filterLayout = new QHBoxLayout();
    filterLayout->setContentsMargins(0, 0, 0, 0);
    filterLayout->setSpacing(8);

    filterEdit_ = new QLineEdit(this);
    filterEdit_->setPlaceholderText(QStringLiteral("过滤进程名、PID 或路径"));
    filterEdit_->setClearButtonEnabled(true);
    filterLayout->addWidget(filterEdit_, 1);

    onlyActiveCheckBox_ = new QCheckBox(QStringLiteral("仅显示有磁盘 IO"), this);
    onlyActiveCheckBox_->setToolTip(QStringLiteral("只显示当前采样周期读/写速率大于 0 的进程"));
    filterLayout->addWidget(onlyActiveCheckBox_, 0);

    selectActiveButton_ = new QPushButton(QStringLiteral("勾选活跃进程"), this);
    selectActiveButton_->setToolTip(QStringLiteral("勾选当前采样周期存在读写活动的进程"));
    selectActiveButton_->setStyleSheet(ksword_theme::themedButtonStyle());
    filterLayout->addWidget(selectActiveButton_, 0);

    clearSelectionButton_ = new QPushButton(QStringLiteral("清空勾选"), this);
    clearSelectionButton_->setToolTip(QStringLiteral("清空下方磁盘活动表的 PID 过滤条件"));
    clearSelectionButton_->setStyleSheet(ksword_theme::themedButtonStyle());
    filterLayout->addWidget(clearSelectionButton_, 0);
    rootLayout_->addLayout(filterLayout, 0);

    splitter_ = new QSplitter(Qt::Vertical, this);
    rootLayout_->addWidget(splitter_, 1);

    processTable_ = new ks::ui::VisibleTableWidget(this);
    configureTableWidget(processTable_);
    processTable_->setColumnCount(kProcessColumnCount);
    processTable_->setHorizontalHeaderLabels({
        QStringLiteral("选择"),
        QStringLiteral("PID"),
        QStringLiteral("进程"),
        QStringLiteral("读字节/s"),
        QStringLiteral("写字节/s"),
        QStringLiteral("总字节/s"),
        QStringLiteral("响应时间"),
        QStringLiteral("读次数/s"),
        QStringLiteral("写次数/s"),
        QStringLiteral("路径")
        });
    processTable_->horizontalHeader()->setSectionResizeMode(kProcessColumnChecked, QHeaderView::Fixed);
    processTable_->horizontalHeader()->setSectionResizeMode(kProcessColumnPid, QHeaderView::Fixed);
    processTable_->horizontalHeader()->setSectionResizeMode(kProcessColumnName, QHeaderView::Interactive);
    processTable_->horizontalHeader()->setSectionResizeMode(kProcessColumnPath, QHeaderView::Stretch);
    processTable_->setColumnWidth(kProcessColumnChecked, 54);
    processTable_->setColumnWidth(kProcessColumnPid, 80);
    processTable_->setColumnWidth(kProcessColumnName, 180);
    processTable_->horizontalHeader()->moveSection(
        processTable_->horizontalHeader()->visualIndex(kProcessColumnName),
        1);
    installProcessColumnMenu();
    QWidget* processSection = createDiskMonitorSection(
        splitter_,
        &processSectionButton_,
        QStringLiteral("磁盘活动的进程"),
        processTable_);
    splitter_->addWidget(processSection);

    activityTable_ = new ks::ui::VisibleTableWidget(this);
    configureTableWidget(activityTable_, kActivityColumnPid);
    activityTable_->setColumnCount(kActivityColumnCount);
    activityTable_->setHorizontalHeaderLabels({
        QStringLiteral("PID"),
        QStringLiteral("进程"),
        QStringLiteral("文件"),
        QStringLiteral("读(字节/秒)"),
        QStringLiteral("写(字节/秒)"),
        QStringLiteral("总数(字节/秒)"),
        QStringLiteral("I/O 优先级"),
        QStringLiteral("响应时间(ms)")
        });
    activityTable_->horizontalHeader()->setSectionResizeMode(kActivityColumnPid, QHeaderView::Fixed);
    activityTable_->horizontalHeader()->setSectionResizeMode(kActivityColumnProcess, QHeaderView::Interactive);
    activityTable_->horizontalHeader()->setSectionResizeMode(kActivityColumnFile, QHeaderView::Stretch);
    activityTable_->horizontalHeader()->setSectionResizeMode(kActivityColumnIoPriority, QHeaderView::Interactive);
    activityTable_->horizontalHeader()->setSectionResizeMode(kActivityColumnResponse, QHeaderView::Fixed);
    activityTable_->setColumnWidth(kActivityColumnPid, 80);
    activityTable_->setColumnWidth(kActivityColumnProcess, 180);
    activityTable_->setColumnWidth(kActivityColumnIoPriority, 100);
    activityTable_->setColumnWidth(kActivityColumnResponse, 110);
    activityTable_->horizontalHeader()->moveSection(
        activityTable_->horizontalHeader()->visualIndex(
            kActivityColumnProcess),
        0);
    QWidget* activitySection = createDiskMonitorSection(
        splitter_,
        &activitySectionButton_,
        QStringLiteral("磁盘活动"),
        activityTable_);
    splitter_->addWidget(activitySection);

    // Completes the third-level view of the Resource Monitor in the 'Storage' section. Capacity and performance
    // counters are read in the same background thread as process sampling; the page adds no extra refresh timer.
    storagePanel_ = new DiskMonitorStoragePanel(this);
    QWidget* storageSection = createDiskMonitorSection(
        splitter_,
        &storageSectionButton_,
        QStringLiteral("存储"),
        storagePanel_);
    splitter_->addWidget(storageSection);
    splitter_->setStretchFactor(0, 2);
    splitter_->setStretchFactor(1, 2);
    splitter_->setStretchFactor(2, 1);
    splitter_->setSizes({ 300, 300, 170 });
}

void DiskMonitorPage::startInitialSampling()
{
    if (initialSamplingStarted_)
    {
        return;
    }

    initialSamplingStarted_ = true;
    if (!ks::ui::isCurrentProcessElevated())
    {
        (void)ks::ui::requestAdministratorRestartForFeature(
            this,
            QStringLiteral("文件级磁盘活动监控"));
    }
    startFileActivityEtw();
    refreshNow();

    if (refreshTimer_ != nullptr)
    {
        refreshTimer_->start();
    }
}

void DiskMonitorPage::initializeConnections()
{
    if (refreshButton_ != nullptr)
    {
        connect(refreshButton_, &QPushButton::clicked, this, [this]()
        {
            refreshNow();
        });
    }

    if (filterEdit_ != nullptr)
    {
        connect(filterEdit_, &QLineEdit::textChanged, this, [this]()
        {
            updateProcessTable(lastSampleList_);
            updateActivityTable();
        });
    }

    if (onlyActiveCheckBox_ != nullptr)
    {
        connect(onlyActiveCheckBox_, &QCheckBox::toggled, this, [this]()
        {
            updateProcessTable(lastSampleList_);
        });
    }

    if (clearSelectionButton_ != nullptr)
    {
        connect(clearSelectionButton_, &QPushButton::clicked, this, [this]()
        {
            selectedPidSet_.clear();
            updateProcessTable(lastSampleList_);
            updateActivityTable();
            updateSummaryLabels(lastSampleList_);
        });
    }

    if (selectActiveButton_ != nullptr)
    {
        connect(selectActiveButton_, &QPushButton::clicked, this, [this]()
        {
            for (const ProcessDiskSample& sample : lastSampleList_)
            {
                if (sample.totalBytesPerSec > kActiveBytesPerSecondThreshold)
                {
                    selectedPidSet_.insert(sample.pid);
                }
            }
            updateProcessTable(lastSampleList_);
            updateActivityTable();
            updateSummaryLabels(lastSampleList_);
        });
    }

    if (processTable_ != nullptr)
    {
        connect(processTable_, &QTableWidget::itemChanged, this, [this](QTableWidgetItem* itemPointer)
        {
            if (itemPointer == nullptr || updatingProcessTable_)
            {
                return;
            }
            if (itemPointer->column() != kProcessColumnChecked)
            {
                return;
            }
            syncSelectionFromTable();
            updateActivityTable();
            updateSummaryLabels(lastSampleList_);
        });
    }

}

void DiskMonitorPage::configureTableWidget(QTableWidget* tableWidget, const int processIdColumn) const
{
    if (tableWidget == nullptr)
    {
        return;
    }

    // Configure the table uniformly according to the monitoring panel style to prevent users from accidentally editing sampling results.
    tableWidget->setAlternatingRowColors(true);
    tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    tableWidget->setSelectionMode(QAbstractItemView::SingleSelection);
    tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
    tableWidget->setSortingEnabled(true);
    // Both the table body and viewport remain transparent to prevent the two tables on the disk monitoring page from covering the Dock background image.
    tableWidget->setAutoFillBackground(false);
    tableWidget->setAttribute(Qt::WA_StyledBackground, true);
    if (tableWidget->viewport() != nullptr)
    {
        tableWidget->viewport()->setAutoFillBackground(false);
        tableWidget->viewport()->setAttribute(Qt::WA_StyledBackground, true);
    }
    tableWidget->verticalHeader()->setVisible(false);
    tableWidget->verticalHeader()->setDefaultSectionSize(24);
    tableWidget->horizontalHeader()->setStretchLastSection(false);
    tableWidget->setStyleSheet(tableHeaderStyle());
    installDiskMonitorTableCopyMenu(tableWidget, processIdColumn);
}

void DiskMonitorPage::installProcessColumnMenu()
{
    if (processTable_ == nullptr ||
        processTable_->horizontalHeader() == nullptr)
    {
        return;
    }

    // By default, all fields are displayed; right-clicking the header still allows users to temporarily hide individual columns.
    QHeaderView* headerView = processTable_->horizontalHeader();
    headerView->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(
        headerView,
        &QHeaderView::customContextMenuRequested,
        processTable_,
        [this, headerView](const QPoint& localPosition)
        {
            QMenu menu(processTable_);
            menu.setStyleSheet(ksword_theme::contextMenuStyle());
            for (int columnIndex = 0;
                 columnIndex < processTable_->columnCount();
                 ++columnIndex)
            {
                const QTableWidgetItem* headerItem =
                    processTable_->horizontalHeaderItem(columnIndex);
                QAction* columnAction = menu.addAction(
                    headerItem != nullptr
                        ? headerItem->text()
                        : QStringLiteral("Column %1").arg(columnIndex));
                columnAction->setCheckable(true);
                columnAction->setChecked(
                    !processTable_->isColumnHidden(columnIndex));
                columnAction->setData(columnIndex);
            }

            QAction* selectedAction = menu.exec(
                headerView->viewport()->mapToGlobal(localPosition));
            if (selectedAction == nullptr)
            {
                return;
            }

            int visibleColumnCount = 0;
            for (int columnIndex = 0;
                 columnIndex < processTable_->columnCount();
                 ++columnIndex)
            {
                if (!processTable_->isColumnHidden(columnIndex))
                {
                    ++visibleColumnCount;
                }
            }
            const int kSelectedColumn = selectedAction->data().toInt();
            const bool kShouldShow = selectedAction->isChecked();
            if (!kShouldShow && visibleColumnCount <= 1)
            {
                return;
            }

            processTable_->setColumnHidden(kSelectedColumn, !kShouldShow);
        });
}

void DiskMonitorPage::refreshNow()
{
    if (processSamplingStopRequested_.load(
        std::memory_order_acquire))
    {
        return;
    }
    if (processSamplingInProgress_.exchange(true))
    {
        return;
    }

    // The previous round's thread exits immediately after submitting results; it is reaped before the next round starts to avoid terminating the process during joinable thread destruction.
    if (processSamplingThread_ != nullptr && processSamplingThread_->joinable())
    {
        processSamplingThread_->join();
    }
    processSamplingThread_.reset();

    if (refreshButton_ != nullptr) refreshButton_->setEnabled(false);
    processSamplingThread_ = std::make_unique<std::thread>([this]()
    {
        std::vector<ProcessDiskSample> sampleList = collectProcessDiskSamples();
        if (processSamplingStopRequested_.load(
            std::memory_order_acquire))
        {
            return;
        }
        DiskMonitorStorageBatch storageSampleBatch =
            storagePanel_ != nullptr
            ? storagePanel_->collectSamples(
                &processSamplingStopRequested_)
            : DiskMonitorStorageBatch{};
        if (processSamplingStopRequested_.load(
            std::memory_order_acquire))
        {
            return;
        }
        QMetaObject::invokeMethod(
            this,
            [
                this,
                sampleList = std::move(sampleList),
                storageSampleBatch = std::move(storageSampleBatch)
            ]() mutable
        {
            processSamplingInProgress_.store(false);
            if (refreshButton_ != nullptr) refreshButton_->setEnabled(true);
            applyProcessDiskSamples(
                std::move(sampleList),
                std::move(storageSampleBatch));
        },
            Qt::QueuedConnection);
    });
}

void DiskMonitorPage::applyProcessDiskSamples(
    std::vector<ProcessDiskSample> sampleList,
    DiskMonitorStorageBatch storageSampleBatch)
{
    const QList<QTableView*> kDiskActivityTables = {
        processTable_,
        activityTable_
    };
    if (ks::ui::isTableUiCommitBlockedByContextMenu(kDiskActivityTables))
    {
        // Defer full sampling commit; keep the ETW activity queue until it can be safely consumed upon return.
        const QPointer<DiskMonitorPage> kSafeThis(this);
        ks::ui::deferTableUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("disk-monitor-process-snapshot-apply"),
            kDiskActivityTables,
            [kSafeThis,
                sampleList = std::move(sampleList),
                storageSampleBatch = std::move(storageSampleBatch)]() mutable
            {
                if (!kSafeThis.isNull())
                {
                    kSafeThis->applyProcessDiskSamples(
                        std::move(sampleList),
                        std::move(storageSampleBatch));
                }
            });
        return;
    }

    std::sort(
        sampleList.begin(),
        sampleList.end(),
        [](const ProcessDiskSample& left, const ProcessDiskSample& right)
        {
            if (!qFuzzyCompare(left.totalBytesPerSec + 1.0, right.totalBytesPerSec + 1.0))
            {
                return left.totalBytesPerSec > right.totalBytesPerSec;
            }
            return left.pid < right.pid;
        });

    pruneStaleSelection(sampleList);
    lastSampleList_ = sampleList;
    lastFileActivityList_ = consumeFileActivitySamples(lastSampleList_);

    updateProcessTable(lastSampleList_);
    updateActivityTable();
    if (storagePanel_ != nullptr)
    {
        storagePanel_->applySamples(std::move(storageSampleBatch));
    }
    updateSummaryLabels(lastSampleList_);

    if (statusLabel_ != nullptr)
    {
        const std::uint32_t kEtwStatus = fileActivityEtwLastStatus_.load();
        const QString kEtwStateText = fileActivityEtwRunning_.load()
            ? QStringLiteral("ETW文件级")
            : QStringLiteral("文件级ETW未运行");
        const QString kStatusSuffix = (!fileActivityEtwRunning_.load() && kEtwStatus != ERROR_SUCCESS)
            ? QStringLiteral("(错误:%1)").arg(kEtwStatus)
            : QString();
        statusLabel_->setText(
            QStringLiteral("最近刷新：%1，进程数：%2，活动来源：%3%4")
            .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss")))
            .arg(static_cast<int>(lastSampleList_.size()))
            .arg(kEtwStateText)
            .arg(kStatusSuffix));
    }
}

std::vector<DiskMonitorPage::ProcessDiskSample> DiskMonitorPage::collectProcessDiskSamples()
{
    std::vector<ProcessDiskSample> sampleList;
    const std::uint64_t kCurrentTickMs = steadyTickMs();

    UniqueHandle snapshotHandle(::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snapshotHandle.valid())
    {
        return sampleList;
    }

    PROCESSENTRY32W processEntry{};
    processEntry.dwSize = sizeof(processEntry);
    if (::Process32FirstW(snapshotHandle.get(), &processEntry) == FALSE)
    {
        return sampleList;
    }

    std::unordered_set<std::uint32_t> observedPidSet;
    do
    {
        ProcessDiskSample sample;
        sample.pid = static_cast<std::uint32_t>(processEntry.th32ProcessID);
        sample.threadCount = static_cast<std::uint32_t>(processEntry.cntThreads);
        sample.processName = QString::fromWCharArray(processEntry.szExeFile).trimmed();
        if (sample.processName.isEmpty())
        {
            sample.processName = QStringLiteral("<PID %1>").arg(sample.pid);
        }

        observedPidSet.insert(sample.pid);

        // System Idle Process / System may not be openable via standard means; keep the line on failure to allow users to verify PID existence.
        UniqueHandle processHandle(::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            static_cast<DWORD>(sample.pid)));
        if (processHandle.valid())
        {
            sample.processImagePath = queryProcessPath(processHandle.get());
            sample.ioPriorityText = queryProcessIoPriorityText(processHandle.get());
            const std::uint64_t kCreateTime100ns = queryProcessCreateTime(processHandle.get());

            IO_COUNTERS ioCounters{};
            if (::GetProcessIoCounters(processHandle.get(), &ioCounters) != FALSE)
            {
                sample.rawReadBytes = static_cast<std::uint64_t>(ioCounters.ReadTransferCount);
                sample.rawWriteBytes = static_cast<std::uint64_t>(ioCounters.WriteTransferCount);
                sample.rawOtherBytes = static_cast<std::uint64_t>(ioCounters.OtherTransferCount);
                sample.rawReadOps = static_cast<std::uint64_t>(ioCounters.ReadOperationCount);
                sample.rawWriteOps = static_cast<std::uint64_t>(ioCounters.WriteOperationCount);
                sample.rawOtherOps = static_cast<std::uint64_t>(ioCounters.OtherOperationCount);
                sample.countersReady = true;

                const auto kBaselineIt = baselineByPid_.find(sample.pid);
                if (kBaselineIt != baselineByPid_.end()
                    && isSameProcessIdentity(kCreateTime100ns, kBaselineIt->second.identityCreateTime100ns)
                    && kCurrentTickMs > kBaselineIt->second.sampleTickMs)
                {
                    const double kDeltaSeconds =
                        static_cast<double>(kCurrentTickMs - kBaselineIt->second.sampleTickMs) / 1000.0;
                    if (kDeltaSeconds > 0.0)
                    {
                        const std::uint64_t kDeltaReadBytes =
                            deltaOrZero(sample.rawReadBytes, kBaselineIt->second.rawReadBytes);
                        const std::uint64_t kDeltaWriteBytes =
                            deltaOrZero(sample.rawWriteBytes, kBaselineIt->second.rawWriteBytes);
                        const std::uint64_t kDeltaOtherBytes =
                            deltaOrZero(sample.rawOtherBytes, kBaselineIt->second.rawOtherBytes);
                        const std::uint64_t kDeltaReadOps =
                            deltaOrZero(sample.rawReadOps, kBaselineIt->second.rawReadOps);
                        const std::uint64_t kDeltaWriteOps =
                            deltaOrZero(sample.rawWriteOps, kBaselineIt->second.rawWriteOps);
                        const std::uint64_t kDeltaOtherOps =
                            deltaOrZero(sample.rawOtherOps, kBaselineIt->second.rawOtherOps);

                        sample.readBytesPerSec = static_cast<double>(kDeltaReadBytes) / kDeltaSeconds;
                        sample.writeBytesPerSec = static_cast<double>(kDeltaWriteBytes) / kDeltaSeconds;
                        sample.otherBytesPerSec = static_cast<double>(kDeltaOtherBytes) / kDeltaSeconds;
                        sample.totalBytesPerSec = sample.readBytesPerSec + sample.writeBytesPerSec;
                        sample.readOpsPerSec = static_cast<double>(kDeltaReadOps) / kDeltaSeconds;
                        sample.writeOpsPerSec = static_cast<double>(kDeltaWriteOps) / kDeltaSeconds;

                        const std::uint64_t kTransferOps = kDeltaReadOps + kDeltaWriteOps;
                        const std::uint64_t kTransferBytes = kDeltaReadBytes + kDeltaWriteBytes;
                        if (kTransferOps > 0)
                        {
                            // Note: User-mode IO_COUNTERS lacks a field for actual completion time.
                            // Here, the average interval of active requests within a 1-second window is used as a lightweight estimate, solely for sorting and trend hints.
                            sample.responseTimeMs = (kDeltaSeconds * 1000.0) / static_cast<double>(kTransferOps);
                            if (kTransferBytes == 0 && kDeltaOtherOps > 0)
                            {
                                sample.responseTimeMs =
                                    (kDeltaSeconds * 1000.0) / static_cast<double>(kDeltaOtherOps);
                            }
                        }
                        else if (kDeltaOtherOps > 0)
                        {
                            sample.responseTimeMs =
                                (kDeltaSeconds * 1000.0) / static_cast<double>(kDeltaOtherOps);
                        }
                        sample.rateReady = true;
                    }
                }

                ProcessDiskBaseline baseline;
                baseline.identityCreateTime100ns = kCreateTime100ns;
                baseline.sampleTickMs = kCurrentTickMs;
                baseline.rawReadBytes = sample.rawReadBytes;
                baseline.rawWriteBytes = sample.rawWriteBytes;
                baseline.rawOtherBytes = sample.rawOtherBytes;
                baseline.rawReadOps = sample.rawReadOps;
                baseline.rawWriteOps = sample.rawWriteOps;
                baseline.rawOtherOps = sample.rawOtherOps;
                baselineByPid_[sample.pid] = baseline;
            }
        }

        sampleList.push_back(std::move(sample));
    } while (::Process32NextW(snapshotHandle.get(), &processEntry) != FALSE);

    // Remove historical baselines for exited processes to prevent old samples from lingering due to PID reuse.
    for (auto baselineIt = baselineByPid_.begin(); baselineIt != baselineByPid_.end();)
    {
        if (observedPidSet.find(baselineIt->first) == observedPidSet.end())
        {
            baselineIt = baselineByPid_.erase(baselineIt);
        }
        else
        {
            ++baselineIt;
        }
    }

    return sampleList;
}

std::vector<DiskMonitorPage::FileActivitySample> DiskMonitorPage::consumeFileActivitySamples(
    const std::vector<ProcessDiskSample>& sampleList)
{
    const std::uint64_t kNowMs = steadyTickMs();
    double deltaSeconds = 1.0;
    if (lastFileActivityDrainMs_ != 0 && kNowMs > lastFileActivityDrainMs_)
    {
        deltaSeconds = std::max(0.001, static_cast<double>(kNowMs - lastFileActivityDrainMs_) / 1000.0);
    }
    lastFileActivityDrainMs_ = kNowMs;

    std::unordered_map<std::uint32_t, QString> processNameByPid;
    std::unordered_map<std::uint32_t, QString> processPathByPid;
    std::unordered_map<std::uint32_t, QString> processIoPriorityByPid;
    processNameByPid.reserve(sampleList.size());
    processPathByPid.reserve(sampleList.size());
    processIoPriorityByPid.reserve(sampleList.size());
    if (recentProcessNameByPid_.size() > 4096U)
    {
        recentProcessNameByPid_.clear();
        recentProcessPathByPid_.clear();
    }
    for (const ProcessDiskSample& sample : sampleList)
    {
        processNameByPid[sample.pid] = sample.processName;
        processPathByPid[sample.pid] = sample.processImagePath;
        recentProcessNameByPid_[sample.pid] = sample.processName;
        if (!sample.processImagePath.isEmpty())
        {
            recentProcessPathByPid_[sample.pid] =
                sample.processImagePath;
        }
        if (!sample.ioPriorityText.isEmpty())
        {
            processIoPriorityByPid[sample.pid] = sample.ioPriorityText;
        }
    }

    const bool kFileActivityEtwRunning = fileActivityEtwRunning_.load();
    QHash<QString, FileActivityAccumulator> activitySnapshot;
    {
        std::lock_guard<std::mutex> lock(fileActivityMutex_);
        activitySnapshot = fileActivityByKey_;
        fileActivityByKey_.clear();
        if (!kFileActivityEtwRunning)
        {
            // Clean up cross-window state after the ETW session exits to avoid misassociating old IRPs/paths with new events on the next startup.
            pendingFileIoByIrp_.clear();
            filePathByObject_.clear();
            activitySnapshot.clear();
        }
        else if (pendingFileIoByIrp_.size() > 32768)
        {
            // Long-pending IRPs likely lost completion events; periodic trimming protects the UI process memory usage.
            pendingFileIoByIrp_.clear();
        }
    }

    std::vector<FileActivitySample> resultList;
    resultList.reserve(static_cast<std::size_t>(activitySnapshot.size()));
    for (auto activityIt = activitySnapshot.constBegin(); activityIt != activitySnapshot.constEnd(); ++activityIt)
    {
        const FileActivityAccumulator& accumulator = activityIt.value();
        if (accumulator.filePath.trimmed().isEmpty())
        {
            continue;
        }

        FileActivitySample sample;
        sample.pid = accumulator.pid;
        const auto kProcessNameIt = processNameByPid.find(sample.pid);
        if (kProcessNameIt != processNameByPid.end())
        {
            sample.processName = kProcessNameIt->second;
        }
        else
        {
            const auto kRecentNameIt =
                recentProcessNameByPid_.find(sample.pid);
            sample.processName =
                kRecentNameIt != recentProcessNameByPid_.end()
                ? kRecentNameIt->second
                : QStringLiteral("<PID %1>").arg(sample.pid);
        }
        const auto kProcessPathIt = processPathByPid.find(sample.pid);
        if (kProcessPathIt != processPathByPid.end())
        {
            sample.processImagePath = kProcessPathIt->second;
        }
        else
        {
            const auto kRecentPathIt =
                recentProcessPathByPid_.find(sample.pid);
            if (kRecentPathIt != recentProcessPathByPid_.end())
            {
                sample.processImagePath = kRecentPathIt->second;
            }
        }
        sample.filePath = accumulator.filePath;
        sample.readBytesPerSec = static_cast<double>(accumulator.readBytes) / deltaSeconds;
        sample.writeBytesPerSec = static_cast<double>(accumulator.writeBytes) / deltaSeconds;
        sample.ioPriorityText = !accumulator.ioPriorityText.isEmpty()
            ? accumulator.ioPriorityText
            : QStringLiteral("未知");
        if (sample.ioPriorityText == QStringLiteral("未知"))
        {
            const auto kPriorityIt = processIoPriorityByPid.find(sample.pid);
            if (kPriorityIt != processIoPriorityByPid.end() && !kPriorityIt->second.isEmpty())
            {
                sample.ioPriorityText = kPriorityIt->second;
            }
        }
        sample.eventCount = accumulator.eventCount;
        if (accumulator.responseCount > 0)
        {
            sample.responseTimeMs =
                accumulator.responseMsTotal / static_cast<double>(accumulator.responseCount);
            sample.responseAvailable = true;
        }
        resultList.push_back(std::move(sample));
    }

    if (!kFileActivityEtwRunning)
    {
        fileActivityStateByKey_.clear();
        return {};
    }

    // In each iteration, first zero out the rate for rows still within the retention period but with no new events this second; then only overwrite keys active in this round.
    // This prevents the previous second's rate from being falsely reported as the current rate when activity pauses during sustained long-term reads/writes to the same line.
    for (auto stateIt = fileActivityStateByKey_.begin();
        stateIt != fileActivityStateByKey_.end();
        ++stateIt)
    {
        FileActivitySample& sample = stateIt.value().sample;
        sample.readBytesPerSec = 0.0;
        sample.writeBytesPerSec = 0.0;
        sample.responseTimeMs = 0.0;
        sample.responseAvailable = false;
        sample.eventCount = 0;
    }

    for (const FileActivitySample& sample : resultList)
    {
        if (sample.eventCount == 0U && !sample.responseAvailable)
        {
            continue;
        }

        const QString kKeyText = fileActivityIdentityKey(sample.pid, sample.filePath);
        FileActivityStateEntry& stateEntry = fileActivityStateByKey_[kKeyText];
        stateEntry.lastActivityMs = kNowMs;
        stateEntry.sample = sample;
    }

    std::unordered_set<std::uint32_t> alivePidSet;
    alivePidSet.reserve(sampleList.size());
    for (const ProcessDiskSample& processSample : sampleList)
    {
        alivePidSet.insert(processSample.pid);
    }
    for (auto stateIt = fileActivityStateByKey_.begin();
        stateIt != fileActivityStateByKey_.end();)
    {
        const FileActivityStateEntry& stateEntry = stateIt.value();
        const bool kExpired = kNowMs >= stateEntry.lastActivityMs
            && (kNowMs - stateEntry.lastActivityMs) > kFileActivityRetentionMs;
        const bool kProcessExited = !alivePidSet.empty()
            && alivePidSet.find(stateEntry.sample.pid) == alivePidSet.end();
        if (kExpired || kProcessExited)
        {
            stateIt = fileActivityStateByKey_.erase(stateIt);
        }
        else
        {
            ++stateIt;
        }
    }

    if (fileActivityStateByKey_.size() > 2048)
    {
        std::vector<std::pair<QString, std::uint64_t>> stateAgeList;
        stateAgeList.reserve(static_cast<std::size_t>(fileActivityStateByKey_.size()));
        for (auto stateIt = fileActivityStateByKey_.constBegin();
            stateIt != fileActivityStateByKey_.constEnd();
            ++stateIt)
        {
            stateAgeList.emplace_back(stateIt.key(), stateIt.value().lastActivityMs);
        }
        std::sort(
            stateAgeList.begin(),
            stateAgeList.end(),
            [](const auto& left, const auto& right)
            {
                return left.second < right.second;
            });
        const std::size_t kRemoveCount = stateAgeList.size() - 2048U;
        for (std::size_t index = 0; index < kRemoveCount; ++index)
        {
            fileActivityStateByKey_.remove(stateAgeList[index].first);
        }
    }

    resultList.clear();
    resultList.reserve(static_cast<std::size_t>(fileActivityStateByKey_.size()));
    for (auto stateIt = fileActivityStateByKey_.constBegin();
        stateIt != fileActivityStateByKey_.constEnd();
        ++stateIt)
    {
        resultList.push_back(stateIt.value().sample);
    }
    std::sort(
        resultList.begin(),
        resultList.end(),
        [](const FileActivitySample& left, const FileActivitySample& right)
        {
            const double kLeftTotal = left.readBytesPerSec + left.writeBytesPerSec;
            const double kRightTotal = right.readBytesPerSec + right.writeBytesPerSec;
            if (!qFuzzyCompare(kLeftTotal + 1.0, kRightTotal + 1.0))
            {
                return kLeftTotal > kRightTotal;
            }
            if (left.pid != right.pid)
            {
                return left.pid < right.pid;
            }
            return left.filePath < right.filePath;
        });
    return resultList;
}

void DiskMonitorPage::pruneStaleSelection(const std::vector<ProcessDiskSample>& sampleList)
{
    std::unordered_set<std::uint32_t> alivePidSet;
    for (const ProcessDiskSample& sample : sampleList)
    {
        alivePidSet.insert(sample.pid);
    }

    for (auto selectedIt = selectedPidSet_.begin(); selectedIt != selectedPidSet_.end();)
    {
        if (alivePidSet.find(*selectedIt) == alivePidSet.end())
        {
            selectedIt = selectedPidSet_.erase(selectedIt);
        }
        else
        {
            ++selectedIt;
        }
    }
}

void DiskMonitorPage::updateProcessTable(const std::vector<ProcessDiskSample>& sampleList)
{
    if (processTable_ == nullptr)
    {
        return;
    }

    QSignalBlocker tableSignalBlocker(processTable_);
    updatingProcessTable_ = true;
    const bool kUpdatesEnabled = processTable_->updatesEnabled();
    processTable_->setUpdatesEnabled(false);
    processTable_->setSortingEnabled(false);
    processTable_->clearContents();
    std::vector<const ProcessDiskSample*> visibleSampleList;
    visibleSampleList.reserve(sampleList.size());
    for (const ProcessDiskSample& sample : sampleList)
    {
        if (sampleMatchesFilter(sample)) visibleSampleList.push_back(&sample);
    }
    processTable_->setRowCount(static_cast<int>(visibleSampleList.size()));

    for (int rowIndex = 0; rowIndex < static_cast<int>(visibleSampleList.size()); ++rowIndex)
    {
        const ProcessDiskSample& sample = *visibleSampleList[static_cast<std::size_t>(rowIndex)];

        QTableWidgetItem* checkItem = createReadOnlyItem(QString());
        checkItem->setFlags((checkItem->flags() | Qt::ItemIsUserCheckable) & ~Qt::ItemIsEditable);
        checkItem->setData(Qt::UserRole, static_cast<qulonglong>(sample.pid));
        applyProcessRowCheckState(checkItem, sample.pid);
        setTableItemText(processTable_, rowIndex, kProcessColumnChecked, checkItem);

        setTableItemText(
            processTable_,
            rowIndex,
            kProcessColumnPid,
            createNumericItem(QString::number(sample.pid), static_cast<double>(sample.pid)));
        QTableWidgetItem* processNameItem =
            createReadOnlyItem(sample.processName);
        processNameItem->setIcon(
            processIconForPath(sample.processImagePath));
        setTableItemText(
            processTable_,
            rowIndex,
            kProcessColumnName,
            processNameItem);
        setTableItemText(
            processTable_,
            rowIndex,
            kProcessColumnReadRate,
            createNumericItem(formatBytesPerSecond(sample.readBytesPerSec), sample.readBytesPerSec));
        setTableItemText(
            processTable_,
            rowIndex,
            kProcessColumnWriteRate,
            createNumericItem(formatBytesPerSecond(sample.writeBytesPerSec), sample.writeBytesPerSec));
        setTableItemText(
            processTable_,
            rowIndex,
            kProcessColumnTotalRate,
            createNumericItem(formatBytesPerSecond(sample.totalBytesPerSec), sample.totalBytesPerSec));
        setTableItemText(
            processTable_,
            rowIndex,
            kProcessColumnResponse,
            createNumericItem(formatMilliseconds(sample.responseTimeMs), sample.responseTimeMs));
        setTableItemText(
            processTable_,
            rowIndex,
            kProcessColumnReadOps,
            createNumericItem(formatOpsPerSecond(sample.readOpsPerSec), sample.readOpsPerSec));
        setTableItemText(
            processTable_,
            rowIndex,
            kProcessColumnWriteOps,
            createNumericItem(formatOpsPerSecond(sample.writeOpsPerSec), sample.writeOpsPerSec));
        setTableItemText(
            processTable_,
            rowIndex,
            kProcessColumnPath,
            createReadOnlyItem(sample.processImagePath.isEmpty()
                ? QStringLiteral("<权限不足或系统进程>")
                : sample.processImagePath));

    }

    processTable_->setSortingEnabled(true);
    updatingProcessTable_ = false;
    processTable_->setUpdatesEnabled(kUpdatesEnabled);
    if (kUpdatesEnabled) processTable_->viewport()->update();
}

void DiskMonitorPage::updateActivityTable()
{
    if (activityTable_ == nullptr)
    {
        return;
    }

    const bool kUpdatesEnabled = activityTable_->updatesEnabled();
    activityTable_->setUpdatesEnabled(false);
    // filterBySelectedPid: Enable PID filtering only when at least one process is selected.
    // An empty selection is consistent with the Resource Monitor, indicating that all recently captured file activities are displayed.
    const bool kFilterBySelectedPid = !selectedPidSet_.empty();
    std::vector<FileActivitySample> selectedFileActivityList;
    selectedFileActivityList.reserve(lastFileActivityList_.size());
    for (const FileActivitySample& fileActivity : lastFileActivityList_)
    {
        if ((!kFilterBySelectedPid ||
                selectedPidSet_.find(fileActivity.pid) != selectedPidSet_.end()) &&
            activityMatchesFilter(fileActivity))
        {
            selectedFileActivityList.push_back(fileActivity);
        }
    }

    if (!selectedFileActivityList.empty())
    {
        std::sort(
            selectedFileActivityList.begin(),
            selectedFileActivityList.end(),
            [](const FileActivitySample& left, const FileActivitySample& right)
            {
                const double kLeftTotal = left.readBytesPerSec + left.writeBytesPerSec;
                const double kRightTotal = right.readBytesPerSec + right.writeBytesPerSec;
                if (!qFuzzyCompare(kLeftTotal + 1.0, kRightTotal + 1.0))
                {
                    return kLeftTotal > kRightTotal;
                }
                if (left.pid != right.pid)
                {
                    return left.pid < right.pid;
                }
                return left.filePath < right.filePath;
            });

        activityTable_->setSortingEnabled(false);
        activityTable_->clearContents();
        activityTable_->setRowCount(static_cast<int>(selectedFileActivityList.size()));

        for (int rowIndex = 0; rowIndex < static_cast<int>(selectedFileActivityList.size()); ++rowIndex)
        {
            const FileActivitySample& sample = selectedFileActivityList[static_cast<std::size_t>(rowIndex)];
            const double kTotalBytesPerSec = sample.readBytesPerSec + sample.writeBytesPerSec;
            const QString kResponseText = sample.responseAvailable
                ? formatMilliseconds(sample.responseTimeMs)
                : QStringLiteral("N/A");

            setTableItemText(
                activityTable_,
                rowIndex,
                kActivityColumnPid,
                createNumericItem(QString::number(sample.pid), static_cast<double>(sample.pid)));
            QTableWidgetItem* processNameItem =
                createReadOnlyItem(sample.processName);
            processNameItem->setIcon(
                processIconForPath(sample.processImagePath));
            setTableItemText(
                activityTable_,
                rowIndex,
                kActivityColumnProcess,
                processNameItem);
            setTableItemText(activityTable_, rowIndex, kActivityColumnFile, createReadOnlyItem(sample.filePath));
            setTableItemText(
                activityTable_,
                rowIndex,
                kActivityColumnReadRate,
                createNumericItem(formatBytesPerSecond(sample.readBytesPerSec), sample.readBytesPerSec));
            setTableItemText(
                activityTable_,
                rowIndex,
                kActivityColumnWriteRate,
                createNumericItem(formatBytesPerSecond(sample.writeBytesPerSec), sample.writeBytesPerSec));
            setTableItemText(
                activityTable_,
                rowIndex,
                kActivityColumnTotalRate,
                createNumericItem(formatBytesPerSecond(kTotalBytesPerSec), kTotalBytesPerSec));
            setTableItemText(
                activityTable_,
                rowIndex,
                kActivityColumnIoPriority,
                createReadOnlyItem(sample.ioPriorityText.isEmpty() ? QStringLiteral("未知") : sample.ioPriorityText));
            setTableItemText(
                activityTable_,
                rowIndex,
                kActivityColumnResponse,
                createNumericItem(kResponseText, sample.responseAvailable ? sample.responseTimeMs : 0.0));
        }

        activityTable_->setSortingEnabled(true);
        activityTable_->setUpdatesEnabled(kUpdatesEnabled);
        if (kUpdatesEnabled) activityTable_->viewport()->update();
        return;
    }

    // When file-level ETW does not capture activity, stop faking file activity using the EXE path.
    // This allows users to clearly distinguish between "no file-level events in the last few seconds" and "only process totals were collected."
    activityTable_->setSortingEnabled(false);
    activityTable_->clearContents();
    activityTable_->setRowCount(1);
    // stateText: Distinguishes between 'All Activity' and 'Selected PID' views to
    // avoid prompting the user to select a process when the selection is empty.
    const QString kStateText = fileActivityEtwRunning_.load()
        ? (kFilterBySelectedPid
            ? QStringLiteral("<最近 5 秒未捕获到所选 PID 的文件级 Read/Write 事件>")
            : QStringLiteral("<最近 5 秒未捕获到文件级 Read/Write 事件>"))
        : (kFilterBySelectedPid
            ? QStringLiteral("<文件级 ETW 未运行；请用管理员权限启动以捕获 PID 对应文件活动>")
            : QStringLiteral("<文件级 ETW 未运行；请用管理员权限启动以捕获文件活动>"));
    setTableItemText(activityTable_, 0, kActivityColumnPid, createReadOnlyItem(QStringLiteral("-")));
    setTableItemText(activityTable_, 0, kActivityColumnProcess, createReadOnlyItem(QStringLiteral("-")));
    setTableItemText(activityTable_, 0, kActivityColumnFile, createReadOnlyItem(kStateText));
    setTableItemText(activityTable_, 0, kActivityColumnReadRate, createNumericItem(QStringLiteral("0 B/s"), 0.0));
    setTableItemText(activityTable_, 0, kActivityColumnWriteRate, createNumericItem(QStringLiteral("0 B/s"), 0.0));
    setTableItemText(activityTable_, 0, kActivityColumnTotalRate, createNumericItem(QStringLiteral("0 B/s"), 0.0));
    setTableItemText(activityTable_, 0, kActivityColumnIoPriority, createReadOnlyItem(QStringLiteral("未知")));
    setTableItemText(activityTable_, 0, kActivityColumnResponse, createNumericItem(QStringLiteral("N/A"), 0.0));
    activityTable_->setSortingEnabled(true);
    activityTable_->setUpdatesEnabled(kUpdatesEnabled);
    if (kUpdatesEnabled) activityTable_->viewport()->update();
}

void DiskMonitorPage::updateSummaryLabels(const std::vector<ProcessDiskSample>& sampleList)
{
    double totalReadBytesPerSec = 0.0;
    double totalWriteBytesPerSec = 0.0;
    int activeProcessCount = 0;
    for (const ProcessDiskSample& sample : sampleList)
    {
        totalReadBytesPerSec += sample.readBytesPerSec;
        totalWriteBytesPerSec += sample.writeBytesPerSec;
        if (sample.totalBytesPerSec > kActiveBytesPerSecondThreshold)
        {
            ++activeProcessCount;
        }
    }

    if (summaryLabel_ != nullptr)
    {
        const QString kModeText = fileActivityEtwRunning_.load()
            ? QStringLiteral("ETW文件级")
            : QStringLiteral("文件级ETW未运行");
        summaryLabel_->setText(
            QStringLiteral("进程读: %1    进程写: %2    活跃进程: %3    勾选进程: %4    磁盘活动: %5")
            .arg(formatBytesPerSecond(totalReadBytesPerSec))
            .arg(formatBytesPerSecond(totalWriteBytesPerSec))
            .arg(activeProcessCount)
            .arg(static_cast<int>(selectedPidSet_.size()))
            .arg(kModeText));
    }

    // Keep key metrics in the collapsed header when the section is closed, aligning with the partition summary in Resource Monitor.
    if (processSectionButton_ != nullptr)
    {
        processSectionButton_->setText(
            QStringLiteral("磁盘活动的进程    读: %1    写: %2")
            .arg(formatBytesPerSecond(totalReadBytesPerSec))
            .arg(formatBytesPerSecond(totalWriteBytesPerSec)));
    }
    if (activitySectionButton_ != nullptr)
    {
        const int kActivityRowCount = activityTable_ != nullptr
            ? activityTable_->rowCount()
            : 0;
        activitySectionButton_->setText(
            QStringLiteral("磁盘活动    当前行: %1    勾选进程: %2")
            .arg(kActivityRowCount)
            .arg(static_cast<int>(selectedPidSet_.size())));
    }
    if (storageSectionButton_ != nullptr &&
        storagePanel_ != nullptr)
    {
        storageSectionButton_->setText(storagePanel_->summaryText());
    }
}

void DiskMonitorPage::syncSelectionFromTable()
{
    if (processTable_ == nullptr)
    {
        return;
    }

    for (int rowIndex = 0; rowIndex < processTable_->rowCount(); ++rowIndex)
    {
        QTableWidgetItem* checkItem = processTable_->item(rowIndex, kProcessColumnChecked);
        if (checkItem == nullptr)
        {
            continue;
        }

        const std::uint32_t kPid =
            static_cast<std::uint32_t>(checkItem->data(Qt::UserRole).toULongLong());
        if (kPid == 0 && checkItem->data(Qt::UserRole).toULongLong() == 0ULL)
        {
            // PID 0 is a valid system process and cannot be skipped directly; this comment is retained for explicit documentation.
        }

        if (checkItem->checkState() == Qt::Checked)
        {
            selectedPidSet_.insert(kPid);
        }
        else
        {
            selectedPidSet_.erase(kPid);
        }
    }
}

void DiskMonitorPage::startFileActivityEtw()
{
    if (fileActivityEtwThread_ != nullptr && fileActivityEtwThread_->joinable())
    {
        return;
    }

    fileActivityEtwStopRequested_.store(false);
    fileActivityEtwLastStatus_.store(ERROR_SUCCESS);

    fileActivityEtwThread_ = std::make_unique<std::thread>([this]()
    {
        const std::wstring kSessionNameWide(kDiskMonitorEtwSessionName);
        const ULONG kTraceNameBytes =
            static_cast<ULONG>((kSessionNameWide.size() + 1) * sizeof(wchar_t));
        const ULONG kPropertyBufferSize =
            static_cast<ULONG>(sizeof(EVENT_TRACE_PROPERTIES) + kTraceNameBytes);
        std::vector<unsigned char> propertyBuffer(kPropertyBufferSize, 0);
        auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(propertyBuffer.data());
        properties->Wnode.BufferSize = kPropertyBufferSize;
        properties->Wnode.ClientContext = 2;
        properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        // The private real-time session serves only as a container; the Kernel-File provider is explicitly enabled via EnableTraceEx2.
        properties->Wnode.Guid = kDiskMonitorEtwSessionGuid;
        properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        properties->FlushTimer = 1;
        properties->BufferSize = 256;
        properties->MinimumBuffers = 16;
        properties->MaximumBuffers = 64;

        wchar_t* loggerNamePointer = reinterpret_cast<wchar_t*>(
            propertyBuffer.data() + properties->LoggerNameOffset);
        ::wcscpy_s(loggerNamePointer, kSessionNameWide.size() + 1, kSessionNameWide.c_str());

        TRACEHANDLE sessionHandle = 0;
        ULONG startStatus = ::StartTraceW(&sessionHandle, loggerNamePointer, properties);
        if (startStatus == ERROR_ALREADY_EXISTS)
        {
            ::ControlTraceW(0, loggerNamePointer, properties, EVENT_TRACE_CONTROL_STOP);
            startStatus = ::StartTraceW(&sessionHandle, loggerNamePointer, properties);
        }
        if (startStatus != ERROR_SUCCESS)
        {
            fileActivityEtwLastStatus_.store(startStatus);
            fileActivityEtwRunning_.store(false);
            return;
        }

        fileActivityEtwSessionHandle_.store(static_cast<std::uint64_t>(sessionHandle));
        if (fileActivityEtwStopRequested_.load())
        {
            const std::uint64_t kOwnedSessionHandle = fileActivityEtwSessionHandle_.exchange(0);
            if (kOwnedSessionHandle != 0)
            {
                ::ControlTraceW(
                    static_cast<TRACEHANDLE>(kOwnedSessionHandle),
                    loggerNamePointer,
                    properties,
                    EVENT_TRACE_CONTROL_STOP);
            }
            fileActivityEtwRunning_.store(false);
            return;
        }
        fileActivityEtwRunning_.store(true);

        const ULONG kEnableStatus = ::EnableTraceEx2(
            sessionHandle,
            &kKernelFileProviderGuid,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_VERBOSE,
            kKernelFileKeywordMask,
            0,
            0,
            nullptr);
        if (kEnableStatus != ERROR_SUCCESS)
        {
            fileActivityEtwLastStatus_.store(kEnableStatus);
            fileActivityEtwRunning_.store(false);
            const std::uint64_t kOwnedSessionHandle = fileActivityEtwSessionHandle_.exchange(0);
            if (kOwnedSessionHandle != 0)
            {
                ::ControlTraceW(
                    static_cast<TRACEHANDLE>(kOwnedSessionHandle),
                    loggerNamePointer,
                    properties,
                    EVENT_TRACE_CONTROL_STOP);
            }
            return;
        }

        if (fileActivityEtwStopRequested_.load())
        {
            const std::uint64_t kOwnedSessionHandle = fileActivityEtwSessionHandle_.exchange(0);
            if (kOwnedSessionHandle != 0)
            {
                ::ControlTraceW(
                    static_cast<TRACEHANDLE>(kOwnedSessionHandle),
                    loggerNamePointer,
                    properties,
                    EVENT_TRACE_CONTROL_STOP);
            }
            fileActivityEtwRunning_.store(false);
            return;
        }

        EVENT_TRACE_LOGFILEW traceLogFile{};
        traceLogFile.LoggerName = loggerNamePointer;
        traceLogFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        traceLogFile.EventRecordCallback = &DiskMonitorPage::fileActivityEtwCallback;
        traceLogFile.Context = this;

        TRACEHANDLE traceHandle = ::OpenTraceW(&traceLogFile);
        if (traceHandle == INVALID_PROCESSTRACE_HANDLE)
        {
            const ULONG kLastError = ::GetLastError();
            fileActivityEtwLastStatus_.store(kLastError);
            fileActivityEtwRunning_.store(false);
            const std::uint64_t kOwnedSessionHandle = fileActivityEtwSessionHandle_.exchange(0);
            if (kOwnedSessionHandle != 0)
            {
                ::ControlTraceW(
                    static_cast<TRACEHANDLE>(kOwnedSessionHandle),
                    loggerNamePointer,
                    properties,
                    EVENT_TRACE_CONTROL_STOP);
            }
            return;
        }

        fileActivityEtwTraceHandle_.store(static_cast<std::uint64_t>(traceHandle));
        if (fileActivityEtwStopRequested_.load())
        {
            const std::uint64_t kOwnedTraceHandle = fileActivityEtwTraceHandle_.exchange(0);
            if (kOwnedTraceHandle != 0)
            {
                ::CloseTrace(static_cast<TRACEHANDLE>(kOwnedTraceHandle));
            }
            const std::uint64_t kOwnedSessionHandle = fileActivityEtwSessionHandle_.exchange(0);
            if (kOwnedSessionHandle != 0)
            {
                ::ControlTraceW(
                    static_cast<TRACEHANDLE>(kOwnedSessionHandle),
                    loggerNamePointer,
                    properties,
                    EVENT_TRACE_CONTROL_STOP);
            }
            fileActivityEtwRunning_.store(false);
            return;
        }
        const ULONG kProcessStatus = ::ProcessTrace(&traceHandle, 1, nullptr, nullptr);
        fileActivityEtwLastStatus_.store(
            fileActivityEtwStopRequested_.load() ? ERROR_SUCCESS : kProcessStatus);

        const std::uint64_t kOwnedTraceHandle = fileActivityEtwTraceHandle_.exchange(0);
        if (kOwnedTraceHandle != 0)
        {
            ::CloseTrace(static_cast<TRACEHANDLE>(kOwnedTraceHandle));
        }

        const std::uint64_t kOwnedSessionHandle = fileActivityEtwSessionHandle_.exchange(0);
        if (kOwnedSessionHandle != 0)
        {
            ::ControlTraceW(
                static_cast<TRACEHANDLE>(kOwnedSessionHandle),
                loggerNamePointer,
                properties,
                EVENT_TRACE_CONTROL_STOP);
        }

        fileActivityEtwRunning_.store(false);
    });
}

void DiskMonitorPage::stopFileActivityEtw()
{
    fileActivityEtwStopRequested_.store(true);

    // The worker exclusively closes the trace consumer handle: it can still be
    // publishing that handle when this stop request arrives. Stopping the session
    // wakes ProcessTrace without invalidating the worker's local trace handle.
    const std::uint64_t kOwnedSessionHandle = fileActivityEtwSessionHandle_.exchange(0);
    if (kOwnedSessionHandle != 0)
    {
        const std::wstring kSessionNameWide(kDiskMonitorEtwSessionName);
        std::vector<unsigned char> propertyBuffer(
            sizeof(EVENT_TRACE_PROPERTIES) + (kSessionNameWide.size() + 1) * sizeof(wchar_t),
            0);
        auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(propertyBuffer.data());
        properties->Wnode.BufferSize = static_cast<ULONG>(propertyBuffer.size());
        properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        wchar_t* loggerNamePointer = reinterpret_cast<wchar_t*>(
            propertyBuffer.data() + properties->LoggerNameOffset);
        ::wcscpy_s(loggerNamePointer, kSessionNameWide.size() + 1, kSessionNameWide.c_str());
        ::ControlTraceW(
            static_cast<TRACEHANDLE>(kOwnedSessionHandle),
            loggerNamePointer,
            properties,
            EVENT_TRACE_CONTROL_STOP);
    }

    if (fileActivityEtwThread_ == nullptr || !fileActivityEtwThread_->joinable())
    {
        fileActivityEtwThread_.reset();
        fileActivityEtwRunning_.store(false);
        return;
    }

    fileActivityEtwThread_->join();
    fileActivityEtwThread_.reset();
    fileActivityEtwRunning_.store(false);
}

void WINAPI DiskMonitorPage::fileActivityEtwCallback(struct _EVENT_RECORD* eventRecordPointer)
{
    if (eventRecordPointer == nullptr || eventRecordPointer->UserContext == nullptr)
    {
        return;
    }

    auto* pagePointer = reinterpret_cast<DiskMonitorPage*>(eventRecordPointer->UserContext);
    pagePointer->handleFileActivityEtwEvent(eventRecordPointer);
}

void DiskMonitorPage::handleFileActivityEtwEvent(const struct _EVENT_RECORD* eventRecordPointer)
{
    const EVENT_RECORD* eventRecord = reinterpret_cast<const EVENT_RECORD*>(eventRecordPointer);
    if (eventRecord == nullptr || fileActivityEtwStopRequested_.load())
    {
        return;
    }

    std::vector<unsigned char> eventInfoBuffer;
    queryEventNameFromTdh(eventRecord, &eventInfoBuffer);
    if (eventInfoBuffer.empty())
    {
        return;
    }

    const USHORT kTaskValue = eventRecord->EventHeader.EventDescriptor.Task;
    const USHORT kEventIdValue = eventRecord->EventHeader.EventDescriptor.Id;
    const bool kIsNameEvent = kTaskValue == kKernelFileTaskNameCreate || kEventIdValue == kKernelFileTaskNameCreate;
    const bool kIsCreateEvent = kTaskValue == kKernelFileTaskCreate || kEventIdValue == kKernelFileTaskCreate;
    const bool kIsCloseEvent = kTaskValue == kKernelFileTaskClose || kEventIdValue == kKernelFileTaskClose;
    const bool kIsReadEvent = kTaskValue == kKernelFileTaskRead || kEventIdValue == kKernelFileTaskRead;
    const bool kIsWriteEvent = kTaskValue == kKernelFileTaskWrite || kEventIdValue == kKernelFileTaskWrite;
    const bool kIsOperationEndEvent =
        kTaskValue == kKernelFileTaskOperationEnd || kEventIdValue == kKernelFileTaskOperationEnd;
    if (!kIsNameEvent && !kIsCreateEvent && !kIsCloseEvent && !kIsReadEvent && !kIsWriteEvent && !kIsOperationEndEvent)
    {
        return;
    }

    auto* eventInfo = reinterpret_cast<PTRACE_EVENT_INFO>(eventInfoBuffer.data());
    std::uint64_t fileObjectValue = 0;
    std::uint64_t fileKeyValue = 0;
    std::uint64_t irpValue = 0;
    std::uint64_t transferSize = 0;
    std::uint64_t durationValue = 0;
    std::uint64_t ioPriorityValue = 0;
    QString filePathText;
    QString ioPriorityText;

    for (ULONG indexValue = 0; indexValue < eventInfo->TopLevelPropertyCount; ++indexValue)
    {
        const EVENT_PROPERTY_INFO& propertyInfo = eventInfo->EventPropertyInfoArray[indexValue];
        if ((propertyInfo.Flags & PropertyStruct) != 0 || propertyInfo.NameOffset == 0)
        {
            continue;
        }

        const wchar_t* propertyNamePointer = reinterpret_cast<const wchar_t*>(
            eventInfoBuffer.data() + propertyInfo.NameOffset);
        const QString kPropertyNameText = propertyNamePointer != nullptr
            ? QString::fromWCharArray(propertyNamePointer)
            : QString();
        const QString kNormalizedName = normalizeEtwPropertyName(kPropertyNameText);

        PROPERTY_DATA_DESCRIPTOR descriptor{};
        descriptor.PropertyName = reinterpret_cast<ULONGLONG>(propertyNamePointer);
        descriptor.ArrayIndex = ULONG_MAX;

        ULONG propertySize = 0;
        ULONG status = ::TdhGetPropertySize(
            const_cast<EVENT_RECORD*>(eventRecord),
            0,
            nullptr,
            1,
            &descriptor,
            &propertySize);
        if (status != ERROR_SUCCESS || propertySize == 0 || propertySize > 65536)
        {
            continue;
        }

        std::vector<unsigned char> propertyBuffer(propertySize, 0);
        status = ::TdhGetProperty(
            const_cast<EVENT_RECORD*>(eventRecord),
            0,
            nullptr,
            1,
            &descriptor,
            propertySize,
            propertyBuffer.data());
        if (status != ERROR_SUCCESS)
        {
            continue;
        }

        const USHORT kInTypeValue = propertyInfo.nonStructType.InType;
        if (kInTypeValue == TDH_INTYPE_UNICODESTRING)
        {
            const QString kStringValue = trimWideString(
                reinterpret_cast<const wchar_t*>(propertyBuffer.data()),
                static_cast<int>(propertyBuffer.size() / sizeof(wchar_t)));
            if (isFileNameProperty(kNormalizedName)
                || kStringValue.startsWith(QStringLiteral("\\"))
                || kStringValue.contains(QStringLiteral(":\\"))
                || kStringValue.startsWith(QStringLiteral("\\\\?\\"))
                || kStringValue.startsWith(QStringLiteral("\\??\\")))
            {
                filePathText = normalizeEtwFilePath(kStringValue);
            }
            continue;
        }

        std::uint64_t numericValue = 0;
        if (kInTypeValue == TDH_INTYPE_POINTER
            || kInTypeValue == TDH_INTYPE_HEXINT64
            || kInTypeValue == TDH_INTYPE_UINT64)
        {
            readScalar(propertyBuffer, &numericValue);
        }
        else if (kInTypeValue == TDH_INTYPE_UINT32 || kInTypeValue == TDH_INTYPE_HEXINT32)
        {
            std::uint32_t value32 = 0;
            if (readScalar(propertyBuffer, &value32))
            {
                numericValue = value32;
            }
        }
        else if (kInTypeValue == TDH_INTYPE_UINT16)
        {
            std::uint16_t value16 = 0;
            if (readScalar(propertyBuffer, &value16))
            {
                numericValue = value16;
            }
        }

        if (isFileObjectProperty(kNormalizedName))
        {
            if (kNormalizedName == QStringLiteral("filekey") || kNormalizedName == QStringLiteral("fileid"))
            {
                fileKeyValue = numericValue;
            }
            else
            {
                fileObjectValue = numericValue;
            }
        }
        else if (isIrpProperty(kNormalizedName))
        {
            irpValue = numericValue;
        }
        else if (isTransferSizeProperty(kNormalizedName))
        {
            transferSize = numericValue;
        }
        else if (isDurationProperty(kNormalizedName))
        {
            durationValue = numericValue;
        }
        else if (isIoPriorityProperty(kNormalizedName))
        {
            ioPriorityValue = numericValue;
            ioPriorityText = ioPriorityHintToText(static_cast<std::uint32_t>(numericValue));
        }
    }

    std::lock_guard<std::mutex> lock(fileActivityMutex_);
    if (kIsOperationEndEvent)
    {
        if (irpValue == 0)
        {
            return;
        }

        const auto kPendingIt = pendingFileIoByIrp_.find(irpValue);
        if (kPendingIt == pendingFileIoByIrp_.end())
        {
            return;
        }

        const PendingFileIoOperation kPendingOperation = kPendingIt->second;
        pendingFileIoByIrp_.erase(kPendingIt);
        if (kPendingOperation.filePath.isEmpty())
        {
            return;
        }

        double responseTimeMs = 0.0;
        bool responseAvailable = false;
        if (durationValue > 0)
        {
            // Some system versions directly provide Duration/IoTime; convert from 100ns to milliseconds.
            responseTimeMs = static_cast<double>(durationValue) / 10000.0;
            responseAvailable = true;
        }
        else if (kPendingOperation.startTime100ns != 0
            && eventRecord->EventHeader.TimeStamp.QuadPart > static_cast<LONGLONG>(kPendingOperation.startTime100ns))
        {
            // Kernel-File start/complete events belong to the same real-time session; when ClientContext=2, TimeStamp is in 100ns units.
            const std::uint64_t kDelta100ns =
                static_cast<std::uint64_t>(eventRecord->EventHeader.TimeStamp.QuadPart)
                - kPendingOperation.startTime100ns;
            responseTimeMs = static_cast<double>(kDelta100ns) / 10000.0;
            responseAvailable = true;
        }
        if (responseAvailable)
        {
            const QString kKeyText = fileActivityIdentityKey(
                kPendingOperation.pid,
                kPendingOperation.filePath);
            FileActivityAccumulator& accumulator = fileActivityByKey_[kKeyText];
            accumulator.pid = kPendingOperation.pid;
            accumulator.filePath = kPendingOperation.filePath;
            if (!kPendingOperation.ioPriorityText.isEmpty())
            {
                accumulator.ioPriorityText = kPendingOperation.ioPriorityText;
            }
            accumulator.responseMsTotal += responseTimeMs;
            ++accumulator.responseCount;
        }
        return;
    }

    if (!filePathText.isEmpty())
    {
        if (fileObjectValue != 0)
        {
            filePathByObject_[fileObjectValue] = filePathText;
        }
        if (fileKeyValue != 0)
        {
            filePathByObject_[fileKeyValue] = filePathText;
        }
        if (filePathByObject_.size() > 65536)
        {
            // File object mapping is only an aid to associate subsequent Read/Write operations with paths; clearing it when too large is acceptable.
            filePathByObject_.clear();
            if (fileObjectValue != 0)
            {
                filePathByObject_[fileObjectValue] = filePathText;
            }
            if (fileKeyValue != 0)
            {
                filePathByObject_[fileKeyValue] = filePathText;
            }
        }
    }
    if (kIsCloseEvent && fileObjectValue != 0)
    {
        filePathByObject_.erase(fileObjectValue);
        return;
    }
    if (filePathText.isEmpty())
    {
        if (fileObjectValue != 0)
        {
            const auto kObjectPathIt = filePathByObject_.find(fileObjectValue);
            if (kObjectPathIt != filePathByObject_.end())
            {
                filePathText = kObjectPathIt->second;
            }
        }
        if (filePathText.isEmpty() && fileKeyValue != 0)
        {
            const auto kKeyPathIt = filePathByObject_.find(fileKeyValue);
            if (kKeyPathIt != filePathByObject_.end())
            {
                filePathText = kKeyPathIt->second;
            }
        }
    }
    if (filePathText.isEmpty() || (!kIsReadEvent && !kIsWriteEvent))
    {
        return;
    }

    const std::uint32_t kPid = static_cast<std::uint32_t>(eventRecord->EventHeader.ProcessId);
    // Read/Write operations themselves serve as immediate evidence of the start of independent I/O requests and are counted in the current window right away.
    // OperationEnd only supplements response time to prevent long-running requests or lost completion events from making throughput invisible for extended periods.
    const QString kKeyText = fileActivityIdentityKey(kPid, filePathText);
    FileActivityAccumulator& accumulator = fileActivityByKey_[kKeyText];
    accumulator.pid = kPid;
    accumulator.filePath = filePathText;
    if (kIsReadEvent)
    {
        accumulator.readBytes += transferSize;
    }
    if (kIsWriteEvent)
    {
        accumulator.writeBytes += transferSize;
    }
    if (!ioPriorityText.isEmpty())
    {
        accumulator.ioPriorityText = ioPriorityText;
    }
    if (ioPriorityValue != 0 && accumulator.ioPriorityText.isEmpty())
    {
        accumulator.ioPriorityText = ioPriorityHintToText(static_cast<std::uint32_t>(ioPriorityValue));
    }
    ++accumulator.eventCount;

    if (irpValue != 0)
    {
        PendingFileIoOperation& pendingOperation = pendingFileIoByIrp_[irpValue];
        pendingOperation.pid = kPid;
        pendingOperation.filePath = filePathText;
        pendingOperation.ioPriorityText = ioPriorityText;
        pendingOperation.startTime100ns =
            eventRecord->EventHeader.TimeStamp.QuadPart > 0
            ? static_cast<std::uint64_t>(eventRecord->EventHeader.TimeStamp.QuadPart)
            : 0;
        if (pendingFileIoByIrp_.size() > 65536)
        {
            // Prevent infinite growth of incomplete IRP cache when OperationEnd is lost or system load is high.
            pendingFileIoByIrp_.clear();
        }
        return;
    }
}

QTableWidgetItem* DiskMonitorPage::createReadOnlyItem(const QString& text) const
{
    QTableWidgetItem* itemPointer = new QTableWidgetItem(text);
    itemPointer->setFlags(itemPointer->flags() & ~Qt::ItemIsEditable);
    itemPointer->setToolTip(text);
    return itemPointer;
}

QTableWidgetItem* DiskMonitorPage::createNumericItem(
    const QString& text,
    const double numericValue) const
{
    QTableWidgetItem* itemPointer = createReadOnlyItem(text);
    itemPointer->setData(Qt::UserRole, numericValue);
    itemPointer->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
    return itemPointer;
}

void DiskMonitorPage::setTableItemText(
    QTableWidget* tableWidget,
    const int rowIndex,
    const int columnIndex,
    QTableWidgetItem* itemPointer) const
{
    if (tableWidget == nullptr || itemPointer == nullptr)
    {
        delete itemPointer;
        return;
    }

    tableWidget->setItem(rowIndex, columnIndex, itemPointer);
}

void DiskMonitorPage::applyProcessRowCheckState(
    QTableWidgetItem* checkItem,
    const std::uint32_t pid) const
{
    if (checkItem == nullptr)
    {
        return;
    }

    checkItem->setCheckState(
        selectedPidSet_.find(pid) != selectedPidSet_.end()
        ? Qt::Checked
        : Qt::Unchecked);
}

QString DiskMonitorPage::processSearchText(const ProcessDiskSample& sample) const
{
    return QStringLiteral("%1 %2 %3")
        .arg(sample.pid)
        .arg(sample.processName)
        .arg(sample.processImagePath)
        .toLower();
}

bool DiskMonitorPage::sampleMatchesFilter(const ProcessDiskSample& sample) const
{
    if (onlyActiveCheckBox_ != nullptr
        && onlyActiveCheckBox_->isChecked()
        && sample.totalBytesPerSec <= kActiveBytesPerSecondThreshold)
    {
        return false;
    }

    const QString kFilterText = filterEdit_ != nullptr
        ? filterEdit_->text().trimmed().toLower()
        : QString();
    if (kFilterText.isEmpty())
    {
        return true;
    }

    return processSearchText(sample).contains(kFilterText);
}

bool DiskMonitorPage::activityMatchesFilter(
    const FileActivitySample& sample) const
{
    const QString kFilterText = filterEdit_ != nullptr
        ? filterEdit_->text().trimmed().toLower()
        : QString();
    if (kFilterText.isEmpty())
    {
        return true;
    }

    return QStringLiteral("%1 %2 %3 %4")
        .arg(sample.pid)
        .arg(sample.processName)
        .arg(sample.processImagePath)
        .arg(sample.filePath)
        .toLower()
        .contains(kFilterText);
}

QIcon DiskMonitorPage::processIconForPath(const QString& imagePath)
{
    const QString kCacheKey = imagePath.trimmed().isEmpty()
        ? QStringLiteral("<default-process-icon>")
        : imagePath.trimmed().toLower();
    const auto kCachedIterator =
        processIconByPath_.constFind(kCacheKey);
    if (kCachedIterator != processIconByPath_.constEnd())
    {
        return kCachedIterator.value();
    }

    QIcon processIcon;
    if (!imagePath.trimmed().isEmpty())
    {
        static QFileIconProvider iconProvider;
        processIcon = iconProvider.icon(QFileInfo(imagePath));
    }
    if (processIcon.isNull())
    {
        processIcon =
            QIcon(QStringLiteral(":/Icon/process_main.svg"));
    }
    processIconByPath_.insert(kCacheKey, processIcon);
    return processIcon;
}

QString DiskMonitorPage::formatBytesPerSecond(const double bytesPerSecond) const
{
    return QStringLiteral("%1/s").arg(formatBytes(bytesPerSecond));
}

QString DiskMonitorPage::formatBytes(const double bytesValue) const
{
    const double kSafeValue = std::max(0.0, bytesValue);
    if (kSafeValue < 1024.0)
    {
        return QStringLiteral("%1 B").arg(kSafeValue, 0, 'f', 0);
    }
    if (kSafeValue < 1024.0 * 1024.0)
    {
        return QStringLiteral("%1 KB").arg(kSafeValue / 1024.0, 0, 'f', 1);
    }
    if (kSafeValue < 1024.0 * 1024.0 * 1024.0)
    {
        return QStringLiteral("%1 MB").arg(kSafeValue / (1024.0 * 1024.0), 0, 'f', 2);
    }
    return QStringLiteral("%1 GB").arg(kSafeValue / (1024.0 * 1024.0 * 1024.0), 0, 'f', 2);
}

QString DiskMonitorPage::formatOpsPerSecond(const double opsPerSecond) const
{
    const double kSafeValue = std::max(0.0, opsPerSecond);
    if (kSafeValue < 10.0)
    {
        return QStringLiteral("%1").arg(kSafeValue, 0, 'f', 2);
    }
    if (kSafeValue < 1000.0)
    {
        return QStringLiteral("%1").arg(kSafeValue, 0, 'f', 1);
    }
    return QStringLiteral("%1").arg(kSafeValue, 0, 'f', 0);
}

QString DiskMonitorPage::formatMilliseconds(const double milliseconds) const
{
    if (milliseconds <= 0.0 || !std::isfinite(milliseconds))
    {
        return QStringLiteral("N/A");
    }
    if (milliseconds < 1.0)
    {
        return QStringLiteral("%1 ms").arg(milliseconds, 0, 'f', 3);
    }
    if (milliseconds < 100.0)
    {
        return QStringLiteral("%1 ms").arg(milliseconds, 0, 'f', 2);
    }
    return QStringLiteral("%1 ms").arg(milliseconds, 0, 'f', 1);
}
