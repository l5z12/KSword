#include "MemoryDock.Internal.h"
#include "../framework/PrivilegeElevationPrompt.h"
#include "../ui/TableInteractionSupport.h"

#include <QCoreApplication>
#include <QImage>
#include <QPixmap>
#include <QRunnable>
#include <QSet>
#include <QThread> // QThread::idealThreadCount: CPU utilization denominator must be normalized by logical core count.
#include <QVector>

#include <algorithm> // std::clamp / std::max: Clamp utilization and enforce lower bound on core count.
#include <functional>
#include <memory>
#include <utility>

#include <Shellapi.h>

#pragma comment(lib, "Shell32.lib")

// Note: Migrated from the original aggregated implementation to a standalone .cpp file; member function implementations remain unchanged.
using namespace ksword::memory_dock_internal;

// ============================================================
// MemoryDock.ProcessRegion.cpp
// Purpose:
// - Responsible for process list, module list, memory region enumeration, and filtered display.
// - Focus on the capability for 'attached target and address space overview'.
// ============================================================

namespace
{
    // processRegionTableRowText:
    // - Input: MemoryDock process/region and other standard table row indices.
    // - Processing: Read full row text by column order, including hidden columns, to facilitate copying PID/Session context;
    // - Returns: TSV text; returns an empty string if the row is invalid.
    QString processRegionTableRowText(QTableWidget* table, const int rowIndex)
    {
        if (table == nullptr || rowIndex < 0 || rowIndex >= table->rowCount())
        {
            return QString();
        }

        QStringList fields;
        fields.reserve(table->columnCount());
        for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
        {
            const QTableWidgetItem* item = table->item(rowIndex, columnIndex);
            fields.push_back(item != nullptr ? item->text() : QString());
        }
        return fields.join(QLatin1Char('\t'));
    }

    // copyProcessRegionTableRow:
    // - Input: target table and row index;
    // - Processing: Write the entire row to the system clipboard as TSV.
    // - Return: None; returns immediately if the clipboard is unavailable or the row is invalid.
    void copyProcessRegionTableRow(QTableWidget* table, const int rowIndex)
    {
        if (table == nullptr || QApplication::clipboard() == nullptr)
        {
            return;
        }

        const QString kRowText = processRegionTableRowText(table, rowIndex);
        if (!kRowText.isEmpty())
        {
            QApplication::clipboard()->setText(kRowText);
        }
    }

    // ============================================================
    // Asynchronous refresh state registration Note: This refactoring does not expand members in MemoryDock.h. The refresh
    // generation and in-flight markers are stored entirely in the dynamic properties of the MemoryDock object itself. These
    // dynamic properties are read/written only on the UI thread and are released along with the control's destruction,
    // avoiding leaks or ID collisions that would occur with a 'file-level static table indexed by instance address'.
    // ============================================================

    // Process list refresh generation: incremented once per background enumeration submission; results are discarded against expired snapshots based on this generation.
    constexpr const char* kProcessRefreshGenerationProperty = "kswordMemoryProcessRefreshGeneration";
    // Whether the process list refresh is in-flight: during in-flight, new requests are merged into pending rather than stacking a second Toolhelp snapshot.
    constexpr const char* kProcessRefreshInFlightProperty = "kswordMemoryProcessRefreshInFlight";
    // Whether the process list has a pending refresh, and whether that pending request requires retaining the current selection.
    constexpr const char* kProcessRefreshPendingProperty = "kswordMemoryProcessRefreshPending";
    constexpr const char* kProcessRefreshPendingKeepSelectionProperty =
        "kswordMemoryProcessRefreshPendingKeepSelection";
    // Pending PID for cross-page jump registration: the process table is rebuilt from async results, so resolution must wait for the callback.
    constexpr const char* kProcessFocusPendingPidProperty = "kswordMemoryProcessFocusPendingPid";
    // Indicates whether region enumeration is in flight and if there are pending region refresh requests.
    constexpr const char* kRegionRefreshInFlightProperty = "kswordMemoryRegionRefreshInFlight";
    constexpr const char* kRegionRefreshPendingProperty = "kswordMemoryRegionRefreshPending";
    // Whether this region refresh was initiated by the attach process: the attach button must immediately return control, prohibiting synchronous traversal of the address space.
    constexpr const char* kRegionRefreshFromAttachProperty = "kswordMemoryRegionRefreshFromAttach";

    // Icon path role: both the 0th column of the process table and the module tree path column use it to record the icon source path; after
    // background extraction completes, the rows needing refresh are looked up by path. UserRole/UserRole+1 are already occupied by other data.
    constexpr int kIconPathItemRole = Qt::UserRole + 2;

    // readBoolProperty:
    // - Input: property owner object and property name;
    // - Processing: Read boolean dynamic properties; treat unset properties as false.
    // - Returns: the current boolean value of the property.
    bool readBoolProperty(const QObject* const propertyOwner, const char* const propertyName)
    {
        return propertyOwner != nullptr && propertyOwner->property(propertyName).toBool();
    }

    // bumpGenerationProperty:
    // - Input: Property owner object and generation property name;
    // - Processing: Increment generation by one and write back; UI thread only.
    // - Return: The new generation number to be included in this request.
    quint64 bumpGenerationProperty(QObject* const propertyOwner, const char* const propertyName)
    {
        const quint64 kNextGeneration = propertyOwner->property(propertyName).toULongLong() + 1ULL;
        propertyOwner->setProperty(propertyName, QVariant::fromValue(kNextGeneration));
        return kNextGeneration;
    }

    // ============================================================
    // Icon asynchronous parsing: QIcon/QPixmap/QFileIconProvider can only be used on the UI thread.
    // Worker threads must only produce QImage objects that can be safely transferred across
    // threads. Converting to QIcon and writing back to the table are executed on the UI thread.
    // ============================================================

    // pathIconCache:
    // - Inputs: None;
    // - Processing: Provide an icon cache indexed by absolute path, accessible only by the UI thread.
    // - Returns: Cache reference shared by processes and modules.
    QHash<QString, QIcon>& pathIconCache()
    {
        static QHash<QString, QIcon> iconCacheByPath;
        return iconCacheByPath;
    }

    // IconApplyCallback: The write-back action executed on the UI thread after icon materialization (parameters: path and constructed icon).
    using IconApplyCallback = std::function<void(const QString&, const QIcon&)>;

    // pathIconWaiterTable:
    // - Inputs: None;
    // - Processing: Record pending write-back waiters for each in-flight path; duplicate requests for the same path
    //   only append waiters without re-querying the Shell (also holds when multiple MemoryDock instances coexist).
    // - Returns: Reference to the wait table, accessible only by the UI thread.
    QHash<QString, QVector<IconApplyCallback>>& pathIconWaiterTable()
    {
        static QHash<QString, QVector<IconApplyCallback>> waiterTableByPath;
        return waiterTableByPath;
    }

    // fallbackPathIcon:
    // - Inputs: None;
    // - Processing: Provide a placeholder icon when the icon fails to resolve or is unavailable.
    // - Returns: Shared placeholder icon reference.
    const QIcon& fallbackPathIcon()
    {
        static const QIcon kPlaceholderIcon(QStringLiteral(":/Icon/process_main.svg"));
        return kPlaceholderIcon;
    }

    // extractShellIconImageFromPath:
    // - Input: Absolute path of an executable or module;
    // - Processing: Query small icons from Windows Shell on a worker thread and copy them into independent bitmaps.
    // - Return: A QImage on successful parsing; an empty QImage on failure.
    QImage extractShellIconImageFromPath(const QString& absolutePath)
    {
        // shellFileInfo holds an HICON allocated by the Shell; it must be explicitly destroyed after conversion to QImage.
        SHFILEINFOW shellFileInfo{};
        const DWORD_PTR kShellQueryResult = ::SHGetFileInfoW(
            reinterpret_cast<const wchar_t*>(absolutePath.utf16()),
            0,
            &shellFileInfo,
            sizeof(shellFileInfo),
            SHGFI_ICON | SHGFI_SMALLICON);
        if (kShellQueryResult == 0 || shellFileInfo.hIcon == nullptr)
        {
            return QImage();
        }

        QImage iconImage = QImage::fromHICON(shellFileInfo.hIcon);
        ::DestroyIcon(shellFileInfo.hIcon);
        return iconImage;
    }

    // lookupCachedPathIcon:
    // - Input: absolute path
    // - Processing: Query only the cache; never trigger any disk or Shell queries to ensure zero blocking during table construction.
    // - Returns: Cached icon on hit; placeholder icon on miss.
    QIcon lookupCachedPathIcon(const QString& absolutePath)
    {
        const QString kNormalizedPath = absolutePath.trimmed();
        if (kNormalizedPath.isEmpty())
        {
            return fallbackPathIcon();
        }

        const auto kCachedIt = pathIconCache().constFind(kNormalizedPath);
        if (kCachedIt != pathIconCache().constEnd())
        {
            return kCachedIt.value();
        }
        return fallbackPathIcon();
    }

    // queuePathIconExtraction:
    // - Input: Absolute path and UI thread callback to apply the icon after extraction;
    // - Processing: On cache miss, submit a thread pool task for Shell query; merge concurrent requests for the same path into a single task.
    // - Return: None; the write-back action is invoked exactly once on the UI thread.
    void queuePathIconExtraction(const QString& absolutePath, IconApplyCallback applyIconOnUiThread)
    {
        const QString kNormalizedPath = absolutePath.trimmed();
        if (kNormalizedPath.isEmpty() || pathIconCache().contains(kNormalizedPath))
        {
            return;
        }

        auto waiterIt = pathIconWaiterTable().find(kNormalizedPath);
        if (waiterIt != pathIconWaiterTable().end())
        {
            waiterIt.value().push_back(std::move(applyIconOnUiThread));
            return;
        }
        pathIconWaiterTable().insert(
            kNormalizedPath,
            QVector<IconApplyCallback>{ std::move(applyIconOnUiThread) });

        QRunnable* const kExtractionTask = QRunnable::create([kNormalizedPath]() {
            QImage iconImage = extractShellIconImageFromPath(kNormalizedPath);
            QCoreApplication* const kAppInstance = QCoreApplication::instance();
            if (kAppInstance == nullptr)
            {
                return;
            }

            QMetaObject::invokeMethod(
                kAppInstance,
                [kNormalizedPath, iconImage = std::move(iconImage)]() mutable {
                    // QPixmap/QIcon construction is deferred here to ensure it only occurs on the UI thread.
                    QIcon resolvedIcon = fallbackPathIcon();
                    if (!iconImage.isNull())
                    {
                        const QPixmap kIconPixmap = QPixmap::fromImage(iconImage);
                        if (!kIconPixmap.isNull())
                        {
                            resolvedIcon = QIcon(kIconPixmap);
                        }
                    }
                    pathIconCache().insert(kNormalizedPath, resolvedIcon);

                    const QVector<IconApplyCallback> kWaiterList =
                        pathIconWaiterTable().take(kNormalizedPath);
                    for (const IconApplyCallback& waiterCallback : kWaiterList)
                    {
                        waiterCallback(kNormalizedPath, resolvedIcon);
                    }
                },
                Qt::QueuedConnection);
            });
        kExtractionTask->setAutoDelete(true);
        QThreadPool::globalInstance()->start(kExtractionTask);
    }

    // applyIconToProcessTableRows:
    // - Input: Process table, image path corresponding to the icon, and the constructed icon;
    // - Processing: The process table allows sorting, so row numbers no longer match cache indices; reverse lookup by path must be performed row by row for write-back.
    // - Returns: Nothing.
    void applyIconToProcessTableRows(
        QTableWidget* const processTable,
        const QString& imagePath,
        const QIcon& resolvedIcon)
    {
        if (processTable == nullptr)
        {
            return;
        }

        for (int rowIndex = 0; rowIndex < processTable->rowCount(); ++rowIndex)
        {
            QTableWidgetItem* const kProcessNameItem = processTable->item(rowIndex, 0);
            if (kProcessNameItem != nullptr &&
                kProcessNameItem->data(kIconPathItemRole).toString() == imagePath)
            {
                kProcessNameItem->setIcon(resolvedIcon);
            }
        }
    }

    // applyIconToModuleTreeRows:
    // - Input: Module tree, path column index, module path for the icon, and the pre-constructed icon;
    // - Processing: Reverse-lookup all matching nodes by path and update icons without rebuilding the entire tree;
    // - Returns: Nothing.
    void applyIconToModuleTreeRows(
        QTreeWidget* const moduleTree,
        const int pathColumnIndex,
        const QString& modulePath,
        const QIcon& resolvedIcon)
    {
        if (moduleTree == nullptr)
        {
            return;
        }

        for (int itemIndex = 0; itemIndex < moduleTree->topLevelItemCount(); ++itemIndex)
        {
            QTreeWidgetItem* const kRowItem = moduleTree->topLevelItem(itemIndex);
            if (kRowItem != nullptr &&
                kRowItem->data(pathColumnIndex, kIconPathItemRole).toString() == modulePath)
            {
                kRowItem->setIcon(pathColumnIndex, resolvedIcon);
            }
        }
    }

    // selectProcessRowByPid:
    // - Input: process table, process combo box, and target PID;
    // - Processing: Locate the target row and scroll it into view, while switching the combo box to the same target (do not reset if
    //   the value hasn't changed to avoid triggering an extra `currentIndexChanged` event that causes duplicate module enumeration);
    // - Returns true if the process table row is found and selected.
    bool selectProcessRowByPid(
        QTableWidget* const processTable,
        QComboBox* const processCombo,
        const std::uint32_t pid)
    {
        bool rowSelected = false;
        if (processTable != nullptr)
        {
            for (int rowIndex = 0; rowIndex < processTable->rowCount(); ++rowIndex)
            {
                QTableWidgetItem* const kPidItem = processTable->item(rowIndex, 1);
                if (kPidItem == nullptr || kPidItem->text().toUInt() != pid)
                {
                    continue;
                }
                processTable->selectRow(rowIndex);
                processTable->scrollToItem(kPidItem, QAbstractItemView::PositionAtCenter);
                rowSelected = true;
                break;
            }
        }

        if (processCombo != nullptr)
        {
            const int kComboIndex =
                processCombo->findData(QVariant::fromValue(static_cast<uint>(pid)), Qt::UserRole);
            if (kComboIndex >= 0 && kComboIndex != processCombo->currentIndex())
            {
                processCombo->setCurrentIndex(kComboIndex);
            }
        }
        return rowSelected;
    }

    // ============================================================
    // Background collection data structure. Note: MemoryDock::ProcessEntry and RegionEntry are private
    // nested types and cannot appear in file-level function signatures. Here, an equivalent plain
    // value type carries the collection results, which are then converted back on the UI thread.
    // ============================================================

    // ProcessSnapshotRow:
    // - Stores single-process info collected by background threads; all fields are value types, allowing safe cross-thread transfer.
    struct ProcessSnapshotRow
    {
        std::uint32_t pid = 0;          // Process PID.
        std::uint32_t sessionId = 0;    // Session ID.
        QString processName;            // Process name (image file name from Toolhelp snapshot).
        QString imagePath;              // Full image path, used for icon resolution (may be empty).
        double workingSetMB = 0.0;      // Working set size (MB); remains 0 if the query fails.
        // CPU usage cannot be determined from a single sample; it must be derived from the increment between two samples. This returns only the cumulative
        // CPU time for this iteration and whether it was captured. The usage rate is calculated by the UI thread by subtracting the previous round's value.
        std::uint64_t cpuTime100ns = 0; // Accumulated time in kernel mode + user mode, unit: 100ns.
        bool cpuTimeValid = false;      // Processes where time cannot be retrieved (insufficient permissions, already exited) remain false.
    };

    // kProcessNumericSortRole: Numeric sort key.
    constexpr int kProcessNumericSortRole = Qt::UserRole + 50;

    // NumericSortTableItem:
    // - Display text with units; sorting is based on the raw numeric value hidden in the role.
    //
    // Why custom implementation is required: QTableWidgetItem's default operator< compares **DisplayRole**, i.e., the text
    // string with units, using lexicographical order. Thus, "10.00%" sorts before "9.00%", and "100.0 MB" sorts before
    // "9.0 MB". The Working Set column is used to select the main process from a group of processes with the same name; if
    // this column is sorted incorrectly, it becomes completely meaningless, and no error is reported for such a mistake.
    class NumericSortTableItem final : public QTableWidgetItem
    {
    public:
        NumericSortTableItem(const QString& displayText, const double sortValue)
        {
            setData(Qt::DisplayRole, displayText);
            setData(kProcessNumericSortRole, sortValue);
        }

        bool operator<(const QTableWidgetItem& other) const override
        {
            const QVariant kLeftValue = data(kProcessNumericSortRole);
            const QVariant kRightValue = other.data(kProcessNumericSortRole);
            if (kLeftValue.isValid() && kRightValue.isValid())
            {
                return kLeftValue.toDouble() < kRightValue.toDouble();
            }
            return QTableWidgetItem::operator<(other);
        }
    };

    // ProcessSnapshotResult:
    // - Saves the complete result of a process enumeration and the failure reason; the UI thread decides whether to display a prompt.
    struct ProcessSnapshotResult
    {
        bool snapshotCreated = false;       // Whether CreateToolhelp32Snapshot succeeded.
        bool enumerationStarted = false;    // Whether Process32FirstW succeeded.
        std::uint32_t lastErrorCode = 0;    // Win32 error code on failure.
        std::vector<ProcessSnapshotRow> rows; // Process snapshots sorted by PID in ascending order.
        // Sampling timestamp in units of 100ns, consistent with cpuTime100ns. CPU utilization = CPU time delta /
        // (wall-clock time delta × logical core count). The denominator must be calculated using this timestamp, not a
        // nominal value like 'refresh interval'—if refresh is delayed or advanced, the nominal value becomes invalid.
        std::uint64_t sampleTime100ns = 0;
    };

    // collectProcessSnapshotRows:
    // - Inputs: None;
    // - Processing: Perform Toolhelp snapshot, session query, working set query, and
    //   image path resolution on the worker thread without touching any Qt controls.
    // - Returns: Collection results sorted by PID in ascending order (including failure reasons).
    ProcessSnapshotResult collectProcessSnapshotRows()
    {
        ProcessSnapshotResult snapshotResult;

        // Process enumeration uses the Toolhelp snapshot interface as needed.
        HANDLE snapshotHandle = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshotHandle == INVALID_HANDLE_VALUE)
        {
            snapshotResult.lastErrorCode = static_cast<std::uint32_t>(::GetLastError());
            return snapshotResult;
        }
        snapshotResult.snapshotCreated = true;

        PROCESSENTRY32W processEntry{};
        processEntry.dwSize = sizeof(processEntry);
        if (::Process32FirstW(snapshotHandle, &processEntry) == FALSE)
        {
            snapshotResult.lastErrorCode = static_cast<std::uint32_t>(::GetLastError());
            ::CloseHandle(snapshotHandle);
            return snapshotResult;
        }
        snapshotResult.enumerationStarted = true;

        do
        {
            ProcessSnapshotRow snapshotRow;
            snapshotRow.pid = static_cast<std::uint32_t>(processEntry.th32ProcessID);
            snapshotRow.processName = QString::fromWCharArray(processEntry.szExeFile);

            DWORD sessionId = 0;
            if (::ProcessIdToSessionId(toDwordPid(snapshotRow.pid), &sessionId) != FALSE)
            {
                snapshotRow.sessionId = static_cast<std::uint32_t>(sessionId);
            }

            // Attempt to read working set size: if failed, keep 0 without affecting the main flow.
            HANDLE processHandle = ::OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                FALSE,
                toDwordPid(snapshotRow.pid));
            if (processHandle != nullptr)
            {
                PROCESS_MEMORY_COUNTERS_EX memoryCounter{};
                if (::GetProcessMemoryInfo(
                    processHandle,
                    reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&memoryCounter),
                    sizeof(memoryCounter)) != FALSE)
                {
                    snapshotRow.workingSetMB =
                        static_cast<double>(memoryCounter.WorkingSetSize) / (1024.0 * 1024.0);
                }

                // Also retrieve cumulative CPU time on the same handle: since PROCESS_QUERY_LIMITED_INFORMATION
                // is already available here, there is no need to open the process again for it.
                FILETIME creationTime{};
                FILETIME exitTime{};
                FILETIME kernelTime{};
                FILETIME userTime{};
                if (::GetProcessTimes(
                    processHandle, &creationTime, &exitTime, &kernelTime, &userTime) != FALSE)
                {
                    const auto kToU64 = [](const FILETIME& fileTime) {
                        return (static_cast<std::uint64_t>(fileTime.dwHighDateTime) << 32)
                            | static_cast<std::uint64_t>(fileTime.dwLowDateTime);
                    };
                    snapshotRow.cpuTime100ns = kToU64(kernelTime) + kToU64(userTime);
                    snapshotRow.cpuTimeValid = true;
                }
                ::CloseHandle(processHandle);
            }

            // Image path resolution internally opens the process handle again, so it is also performed in a background thread.
            snapshotRow.imagePath =
                QString::fromStdString(ks::process::queryProcessPathByPid(snapshotRow.pid));

            snapshotResult.rows.push_back(std::move(snapshotRow));
        } while (::Process32NextW(snapshotHandle, &processEntry) != FALSE);
        ::CloseHandle(snapshotHandle);

        // The sampling timestamp is taken after the traversal: since the traversal itself takes time, taking it before would make the denominator shorter
        // than the actual observation window, resulting in an inflated utilization rate. Taking it after yields a slightly lower rate, which is preferable.
        FILETIME sampleFileTime{};
        ::GetSystemTimeAsFileTime(&sampleFileTime);
        snapshotResult.sampleTime100ns =
            (static_cast<std::uint64_t>(sampleFileTime.dwHighDateTime) << 32)
            | static_cast<std::uint64_t>(sampleFileTime.dwLowDateTime);

        // Sort by PID in ascending order here to ensure a stable display order.
        std::sort(
            snapshotResult.rows.begin(),
            snapshotResult.rows.end(),
            [](const ProcessSnapshotRow& left, const ProcessSnapshotRow& right) {
                return left.pid < right.pid;
            });
        return snapshotResult;
    }

    // RegionSnapshotRow:
    // - Stores a single virtual memory region collected by the background thread; all fields are value types, allowing safe cross-thread transfer.
    struct RegionSnapshotRow
    {
        std::uint64_t baseAddress = 0;  // Region start address.
        std::uint64_t regionSize = 0;   // Region size (bytes).
        std::uint32_t protect = 0;      // Protection attribute bits (PAGE_*).
        std::uint32_t state = 0;        // State (MEM_COMMIT / MEM_RESERVE / MEM_FREE).
        std::uint32_t type = 0;         // Type (MEM_IMAGE / MEM_MAPPED / MEM_PRIVATE).
        QString mappedFilePath;         // Mapped file path (if available).
    };

    // collectVirtualMemoryRegionRows:
    // - Input: Target process handle (caller guarantees handle validity during traversal);
    // - Processing: Iterate from the lower bound to the upper bound of the user address space; IMAGE/MAPPED regions include
    //   resolved mapped file paths. No Qt control access is performed throughout, allowing direct execution in thread pool tasks.
    // - Returns: An array of region snapshots; returns an empty array if the address space is unreadable.
    std::vector<RegionSnapshotRow> collectVirtualMemoryRegionRows(const HANDLE processHandle)
    {
        std::vector<RegionSnapshotRow> regionRows;
        if (processHandle == nullptr)
        {
            return regionRows;
        }

        SYSTEM_INFO systemInfo{};
        ::GetSystemInfo(&systemInfo);
        const std::uint64_t kMinAddress =
            reinterpret_cast<std::uintptr_t>(systemInfo.lpMinimumApplicationAddress);
        const std::uint64_t kMaxAddress =
            reinterpret_cast<std::uintptr_t>(systemInfo.lpMaximumApplicationAddress);

        std::uint64_t currentAddress = kMinAddress;
        while (currentAddress < kMaxAddress)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            const SIZE_T kQuerySize = ::VirtualQueryEx(
                processHandle,
                reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(currentAddress)),
                &mbi,
                sizeof(mbi));
            if (kQuerySize != sizeof(mbi))
            {
                break;
            }

            RegionSnapshotRow regionRow{};
            regionRow.baseAddress = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            regionRow.regionSize = static_cast<std::uint64_t>(mbi.RegionSize);
            regionRow.protect = static_cast<std::uint32_t>(mbi.Protect);
            regionRow.state = static_cast<std::uint32_t>(mbi.State);
            regionRow.type = static_cast<std::uint32_t>(mbi.Type);

            // IMAGE/MAPPED regions should attempt to resolve the mapped file path to help users locate the module.
            if (regionRow.state == MEM_COMMIT &&
                (regionRow.type == MEM_IMAGE || regionRow.type == MEM_MAPPED))
            {
                wchar_t mappedPath[MAX_PATH] = {};
                const DWORD kLength = ::GetMappedFileNameW(
                    processHandle,
                    mbi.BaseAddress,
                    mappedPath,
                    static_cast<DWORD>(std::size(mappedPath)));
                if (kLength > 0)
                {
                    regionRow.mappedFilePath =
                        QString::fromWCharArray(mappedPath, static_cast<int>(kLength));
                }
            }

            regionRows.push_back(std::move(regionRow));
            if (mbi.RegionSize == 0)
            {
                break;
            }

            const std::uint64_t kNextAddress =
                reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) +
                static_cast<std::uint64_t>(mbi.RegionSize);
            if (kNextAddress <= currentAddress)
            {
                break;
            }
            currentAddress = kNextAddress;
        }
        return regionRows;
    }

    // reportRegionEnumerateFailure:
    // - Input: The parent window hosting the dialog and the enumeration failure text;
    // - Processing: Output failure logs, prioritize permission recovery prompts; fall back to standard alert dialogs if not handled.
    // - Return: None. The synchronous fallback path and the asynchronous re-injection path share the same notification logic to avoid behavioral divergence.
    void reportRegionEnumerateFailure(QWidget* const parentWidget, const QString& errorText)
    {
        KLogEvent regionEnumerateFailEvent;
        err << regionEnumerateFailEvent
            << "[MemoryDock] refreshMemoryRegionList: 枚举区域失败, error="
            << errorText.toStdString()
            << eol;

        // privilegePromptHandled: Records whether the region enumeration failure has been handled by the privilege recovery prompt.
        const bool kPrivilegePromptHandled = ks::ui::promptForPrivilegeFailure(
            parentWidget,
            QStringLiteral("枚举进程内存区域"),
            errorText);
        if (!kPrivilegePromptHandled)
        {
            QMessageBox::warning(parentWidget, "区域刷新", errorText);
        }
    }
}

bool MemoryDock::isComboPopupVisible(QComboBox* const comboBox) const
{
    if (comboBox == nullptr)
    {
        return false;
    }
    // Both combo boxes, which are entirely rebuilt by asynchronous results, enter the pre-state via showPopup(); thus,
    // qScrollEffect temporarily hiding the QComboBoxPrivateContainer will not inadvertently allow the popup to proceed.
    if (comboBox == processCombo_)
    {
        return processComboPopupLifecycleActive_;
    }
    if (comboBox == driverMemoryBaseCombo_)
    {
        return driverMemoryBaseComboPopupLifecycleActive_;
    }

    // Reserve a side-effect-free fallback for unprotected subclasses; do not call view(), as it lazily creates private popups.
    QWidget* const kActivePopupWidget = QApplication::activePopupWidget();
    return kActivePopupWidget != nullptr &&
        (kActivePopupWidget == comboBox || comboBox->isAncestorOf(kActivePopupWidget));
}

bool MemoryDock::isProcessComboPopupOpen()
{
    // A process-cache update rebuilds both dropdowns; do not commit it while either dropdown is open.
    return isComboPopupVisible(processCombo_) ||
        isComboPopupVisible(driverMemoryBaseCombo_);
}

bool MemoryDock::deferCommitWhileProcessComboPopupOpen(std::function<void()> commitAction)
{
    if (!commitAction)
    {
        return false;
    }
    if (!isProcessComboPopupOpen())
    {
        return false;
    }

    // Clearing and repopulating the dropdown when the popup expands keeps the popup capturing the mouse while invalidating content,
    // resulting in "the entire interface becomes unclickable after clicking the dropdown". Here, only the latest submission is retained.
    KLogEvent deferCommitEvent;
    info << deferCommitEvent
        << "[MemoryDock] 进程下拉框展开中，推迟本轮进程列表提交。"
        << eol;
    processComboDeferredCommit_ = std::move(commitAction);
    return true;
}

void MemoryDock::flushProcessComboDeferredCommit()
{
    if (isProcessComboPopupOpen())
    {
        // The dialog is reopened; wait for the next close.
        return;
    }

    const bool kDriverBaseRefreshPending = driverMemoryBaseComboRefreshPending_;
    driverMemoryBaseComboRefreshPending_ = false;

    if (!processComboDeferredCommit_)
    {
        if (kDriverBaseRefreshPending)
        {
            updateDriverMemoryBaseComboFromProcessCache();
        }
        return;
    }

    std::function<void()> commitAction;
    commitAction.swap(processComboDeferredCommit_);

    KLogEvent flushCommitEvent;
    info << flushCommitEvent
        << "[MemoryDock] 进程下拉框已收起，回投被推迟的进程列表提交。"
        << eol;
    // Committing a full process snapshot itself rebuilds the driver target dropdown, thereby overwriting the pending single-box refresh.
    commitAction();
}

void MemoryDock::refreshProcessList(const bool keepSelection)
{
    // Output refresh entry log, recording whether an attempt was made to retain the previous selection.
    KLogEvent refreshProcessStartEvent;
    info << refreshProcessStartEvent
        << "[MemoryDock] refreshProcessList: 开始刷新进程列表, keepSelection="
        << (keepSelection ? "true" : "false")
        << eol;

    // Fallback: If the popup has closed but the Hide callback was lost, the deferred old commit is applied
    // here. Otherwise, the in-flight flag would remain stuck, and the process list would never update again.
    flushProcessComboDeferredCommit();

    // Do not stack a second Toolhelp snapshot while an enumeration is in flight: clicking a tab in the process details page triggers two
    // calls; the later request is merged into a pending task and waits for the in-flight result to complete before triggering a follow-up.
    if (readBoolProperty(this, kProcessRefreshInFlightProperty))
    {
        setProperty(kProcessRefreshPendingProperty, true);
        setProperty(kProcessRefreshPendingKeepSelectionProperty, keepSelection);
        return;
    }

    // Record the currently selected PID before refresh to restore the user experience as much as possible after refresh.
    std::uint32_t previousPid = 0;
    if (keepSelection)
    {
        const int kIndex = processCombo_->currentIndex();
        if (kIndex >= 0)
        {
            previousPid = static_cast<std::uint32_t>(processCombo_->itemData(kIndex, Qt::UserRole).toUInt());
        }
    }

    // Do not clear m_processCache here: Clearing it before filling would cause the dropdown/R0 page reads to encounter an
    // empty cache. The cache and table are unified and replaced in a single step during the commit phase after data injection.
    setProperty(kProcessRefreshInFlightProperty, true);
    const quint64 kRequestGeneration = bumpGenerationProperty(this, kProcessRefreshGenerationProperty);
    const QPointer<MemoryDock> kGuardedSelf(this);

    QRunnable* const kRefreshProcessTask = QRunnable::create([kGuardedSelf, kRequestGeneration, previousPid]() {
        // The background thread performs pure data collection: Toolhelp snapshots, handle queries, and image path resolution do not touch Qt controls.
        ProcessSnapshotResult snapshotResult = collectProcessSnapshotRows();

        QCoreApplication* const kAppInstance = QCoreApplication::instance();
        if (kAppInstance == nullptr)
        {
            return;
        }

        QMetaObject::invokeMethod(
            kAppInstance,
            [kGuardedSelf, kRequestGeneration, previousPid, snapshotResult = std::move(snapshotResult)]() mutable {
                if (kGuardedSelf == nullptr)
                {
                    return;
                }
                MemoryDock* const kResultDock = kGuardedSelf.data();

                // Generation expiration indicates a new enumeration was initiated during the period; discard the old snapshot.
                if (kResultDock->property(kProcessRefreshGenerationProperty).toULongLong() != kRequestGeneration)
                {
                    return;
                }

                if (!snapshotResult.snapshotCreated)
                {
                    KLogEvent snapshotFailEvent;
                    err << snapshotFailEvent
                        << "[MemoryDock] refreshProcessList: CreateToolhelp32Snapshot 失败, error="
                        << snapshotResult.lastErrorCode
                        << eol;
                    kResultDock->setProperty(kProcessRefreshInFlightProperty, false);
                    kResultDock->setProperty(kProcessRefreshPendingProperty, false);
                    QMessageBox::warning(kResultDock, "进程刷新", "CreateToolhelp32Snapshot 失败。");
                    return;
                }
                if (!snapshotResult.enumerationStarted)
                {
                    KLogEvent processFirstFailEvent;
                    err << processFirstFailEvent
                        << "[MemoryDock] refreshProcessList: Process32FirstW 失败, error="
                        << snapshotResult.lastErrorCode
                        << eol;
                    kResultDock->setProperty(kProcessRefreshInFlightProperty, false);
                    kResultDock->setProperty(kProcessRefreshPendingProperty, false);
                    return;
                }

                const auto kSnapshotRows =
                    std::make_shared<std::vector<ProcessSnapshotRow>>(std::move(snapshotResult.rows));
                const std::uint64_t kSnapshotSampleTime = snapshotResult.sampleTime100ns;
                auto commitProcessSnapshot =
                    [kGuardedSelf, kRequestGeneration, previousPid, kSnapshotRows, kSnapshotSampleTime]() {
                    if (kGuardedSelf == nullptr)
                    {
                        return;
                    }
                    MemoryDock* const kCommitDock = kGuardedSelf.data();
                    if (kCommitDock->property(kProcessRefreshGenerationProperty).toULongLong() != kRequestGeneration)
                    {
                        return;
                    }

                    // Logical core count: The denominator for utilization must be multiplied by this; otherwise, a process saturating a
                    // single core on a 16-core machine would be calculated as 100%, whereas Task Manager shows 6.25%, causing a mismatch.
                    const int kLogicalCoreCount =
                        (std::max)(1, QThread::idealThreadCount());

                    // Replace cache and table atomically to avoid other pages reading partial data.
                    kCommitDock->processCache_.clear();
                    kCommitDock->processCache_.reserve(kSnapshotRows->size());
                    QHash<std::uint32_t, ProcessCpuSample> freshCpuSamples;
                    freshCpuSamples.reserve(static_cast<int>(kSnapshotRows->size()));
                    for (const ProcessSnapshotRow& snapshotRow : *kSnapshotRows)
                    {
                        ProcessEntry entry{};
                        entry.pid = snapshotRow.pid;
                        entry.sessionId = snapshotRow.sessionId;
                        entry.processName = snapshotRow.processName;
                        entry.workingSetMB = snapshotRow.workingSetMB;

                        if (snapshotRow.cpuTimeValid)
                        {
                            freshCpuSamples.insert(
                                snapshotRow.pid,
                                ProcessCpuSample{
                                    snapshotRow.cpuTime100ns, kSnapshotSampleTime });

                            const auto kPrevious =
                                kCommitDock->previousCpuSamples_.constFind(snapshotRow.pid);
                            if (kPrevious != kCommitDock->previousCpuSamples_.constEnd()
                                && kSnapshotSampleTime > kPrevious->sampleTime100ns
                                && snapshotRow.cpuTime100ns >= kPrevious->cpuTime100ns)
                            {
                                // PIDs are recycled by the system: a new process with the same PID resets CPU
                                // time to 0, causing a negative increment. The >= check above filters this out;
                                // it is better to display '-' for this round than to report a false value.
                                const double kCpuDelta = static_cast<double>(
                                    snapshotRow.cpuTime100ns - kPrevious->cpuTime100ns);
                                const double kWallDelta = static_cast<double>(
                                    kSnapshotSampleTime - kPrevious->sampleTime100ns);
                                const double kPercent =
                                    (kCpuDelta / (kWallDelta * kLogicalCoreCount)) * 100.0;
                                // Data sampling at the start and end of the window is not performed at the exact same instant;
                                // in extreme cases, the calculated value may slightly exceed bounds, so clamp it before display.
                                entry.cpuPercent = std::clamp(kPercent, 0.0, 100.0);
                                entry.cpuPercentValid = true;
                            }
                        }
                        kCommitDock->processCache_.push_back(std::move(entry));
                    }
                    // Replace the entire table instead of updating row-by-row: exited processes must disappear immediately;
                    // otherwise, their samples persist and cause incorrect time subtraction when the PID is reused for a new process.
                    kCommitDock->previousCpuSamples_ = std::move(freshCpuSamples);

                    // Rebuild the process table first.
                    QTableWidget* const kProcessTable = kCommitDock->processTable_;
                    kProcessTable->setSortingEnabled(false);
                    kProcessTable->setRowCount(static_cast<int>(kSnapshotRows->size()));
                    for (int row = 0; row < static_cast<int>(kCommitDock->processCache_.size()); ++row)
                    {
                        // Cache entries correspond one-to-one with snapshot rows (the same collection result is converted in the
                        // same order). Image paths are stored only in snapshot rows and are used solely for icon resolution.
                        const ProcessEntry& entry = kCommitDock->processCache_[static_cast<std::size_t>(row)];
                        // The icon key consistently uses the trimmed path to maintain text consistency with the background extraction task and back-write comparison.
                        const QString kImagePath =
                            (*kSnapshotRows)[static_cast<std::size_t>(row)].imagePath.trimmed();

                        // Prepend icon to process name: use cache hit directly; on miss, use placeholder first, then
                        // Shell query fills the corresponding cell with the correct icon after thread pool completion.
                        QTableWidgetItem* const kProcessNameItem = new QTableWidgetItem(entry.processName);
                        kProcessNameItem->setData(kIconPathItemRole, kImagePath);
                        kProcessNameItem->setIcon(lookupCachedPathIcon(kImagePath));
                        kProcessTable->setItem(row, 0, kProcessNameItem);

                        // The PID, Session, CPU, and Working Set columns must all use NumericSortTableItem: display
                        // text with units, but sort by raw numeric values (see the class comments for rationale).
                        const auto kMakeNumericItem =
                            [](const QString& displayText, const double sortValue) {
                                return new NumericSortTableItem(displayText, sortValue);
                            };

                        kProcessTable->setItem(row, 1, kMakeNumericItem(
                            QString::number(entry.pid), static_cast<double>(entry.pid)));
                        kProcessTable->setItem(row, 2, kMakeNumericItem(
                            QString::number(entry.sessionId), static_cast<double>(entry.sessionId)));
                        // Display "-" instead of "0.00%" when CPU usage cannot be retrieved: this applies to the first
                        // refresh, newly started processes, and cases with insufficient permissions. These represent "unknown"
                        // states, distinct from "idle"; displaying 0% would incorrectly report a non-existent reading.
                        kProcessTable->setItem(row, 3, kMakeNumericItem(
                            entry.cpuPercentValid
                                ? (QString::number(entry.cpuPercent, 'f', 2) + "%")
                                : QStringLiteral("-"),
                            entry.cpuPercentValid ? entry.cpuPercent : -1.0));
                        kProcessTable->setItem(row, 4, kMakeNumericItem(
                            QString("%1 MB").arg(entry.workingSetMB, 0, 'f', 1),
                            entry.workingSetMB));
                    }
                    kProcessTable->setSortingEnabled(true);

                    // Newly refreshed rows are visible by default; they must be immediately re-filtered against the current
                    // keyword. Without this step, if the filter box retains a keyword, the list will silently revert to the
                    // full set after the next refresh, and the user won't realize they are no longer viewing filtered results.
                    kCommitDock->applyProcessTableFilter();

                    // Image paths not found in the cache are uniformly submitted for background extraction; the callback only updates the corresponding cell icon without rebuilding the entire table.
                    QSet<QString> queuedIconPaths;
                    for (const ProcessSnapshotRow& snapshotRow : *kSnapshotRows)
                    {
                        const QString kImagePath = snapshotRow.imagePath.trimmed();
                        if (kImagePath.isEmpty() || queuedIconPaths.contains(kImagePath))
                        {
                            continue;
                        }
                        queuedIconPaths.insert(kImagePath);
                        queuePathIconExtraction(
                            kImagePath,
                            [kGuardedSelf](const QString& resolvedPath, const QIcon& resolvedIcon) {
                                if (kGuardedSelf == nullptr)
                                {
                                    return;
                                }
                                applyIconToProcessTableRows(
                                    kGuardedSelf->processTable_,
                                    resolvedPath,
                                    resolvedIcon);
                            });
                    }

                    // Resynchronize and rebuild the top dropdown.
                    kCommitDock->updateProcessComboFromCache();

                    // Attempt to restore the previously selected PID.
                    if (previousPid != 0)
                    {
                        for (int comboIndex = 0; comboIndex < kCommitDock->processCombo_->count(); ++comboIndex)
                        {
                            if (kCommitDock->processCombo_->itemData(comboIndex, Qt::UserRole).toUInt() == previousPid)
                            {
                                kCommitDock->processCombo_->setCurrentIndex(comboIndex);
                                break;
                            }
                        }
                    }

                    // Cross-page jumps (focusProcessForOperations) can only be resolved after the list is repopulated.
                    const std::uint32_t kPendingFocusPid = static_cast<std::uint32_t>(
                        kCommitDock->property(kProcessFocusPendingPidProperty).toUInt());
                    if (kPendingFocusPid != 0)
                    {
                        kCommitDock->setProperty(kProcessFocusPendingPidProperty, 0U);
                        selectProcessRowByPid(
                            kCommitDock->processTable_,
                            kCommitDock->processCombo_,
                            kPendingFocusPid);
                    }

                    // Output refresh completion log, recording the total process count and restored PIDs for this round.
                    KLogEvent refreshProcessFinishEvent;
                    info << refreshProcessFinishEvent
                        << "[MemoryDock] refreshProcessList: 刷新完成, processCount="
                        << kCommitDock->processCache_.size()
                        << ", previousPid="
                        << previousPid
                        << eol;

                    // Release the in-flight flag after this round and process the merged pending requests in a new round.
                    kCommitDock->setProperty(kProcessRefreshInFlightProperty, false);
                    if (kCommitDock->property(kProcessRefreshPendingProperty).toBool())
                    {
                        const bool kPendingKeepSelection =
                            kCommitDock->property(kProcessRefreshPendingKeepSelectionProperty).toBool();
                        kCommitDock->setProperty(kProcessRefreshPendingProperty, false);
                        kCommitDock->refreshProcessList(kPendingKeepSelection);
                    }
                };

                // Cache this commit while the top process dropdown is expanding: after the expanding popup is cleared and
                // repopulated, it will continue to grab the mouse, causing the user to see the entire interface freeze.
                if (kResultDock->deferCommitWhileProcessComboPopupOpen(commitProcessSnapshot))
                {
                    return;
                }

                // Cache the current commit when the right-click menu is open to avoid replacing the entire table of rows the user is currently operating on.
                if (ks::ui::deferItemViewUiCommitIfContextMenuOpen(
                        kResultDock,
                        QStringLiteral("memory-process-list-snapshot-apply"),
                        {kResultDock->processTable_},
                        commitProcessSnapshot))
                {
                    return;
                }
                commitProcessSnapshot();
            },
            Qt::QueuedConnection);
        });
    kRefreshProcessTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(kRefreshProcessTask);
}

void MemoryDock::syncTamperDetectionTargets()
{
    if (tamperDetectionPage_ == nullptr)
    {
        return;
    }
    tamperDetectionPage_->setAttachedProcess(attachedPid_, attachedProcessName_);

    // Convert module list to "scan targets". Only pass base address and size: Tamper Detection Page does not need to
    // know signatures, entry points, etc. Sending extra data creates additional states that require synchronization.
    std::vector<ksword::memory_dock::TamperDetectionPage::ModuleCandidate> candidates;
    candidates.reserve(moduleCache_.size());
    for (const ModuleEntry& module : moduleCache_)
    {
        ksword::memory_dock::TamperDetectionPage::ModuleCandidate candidate;
        candidate.displayText = QString("%1  (%2 KB)")
            .arg(module.moduleName)
            .arg(module.sizeBytes / 1024ULL);
        // The reference path for the disk image must normalize file bytes based on the load base address, so the full path must be passed along.
        candidate.filePath = module.fullPath;
        candidate.baseAddress = module.baseAddress;
        candidate.sizeBytes = module.sizeBytes;
        candidates.push_back(std::move(candidate));
    }
    tamperDetectionPage_->setModuleCandidates(candidates);
}

void MemoryDock::applyProcessTableFilter()
{
    if (processTable_ == nullptr)
    {
        return;
    }
    const QString kKeyword = (processFilterEdit_ != nullptr)
        ? processFilterEdit_->text().trimmed()
        : QString();

    int shownRows = 0;
    const int kTotalRows = processTable_->rowCount();
    for (int row = 0; row < kTotalRows; ++row)
    {
        bool matched = kKeyword.isEmpty();
        if (!matched)
        {
            // A match on either the process name or PID counts as a hit: the user may only have one of them.
            const QTableWidgetItem* const kNameItem = processTable_->item(row, 0);
            const QTableWidgetItem* const kPidItem = processTable_->item(row, 1);
            matched =
                (kNameItem != nullptr && kNameItem->text().contains(kKeyword, Qt::CaseInsensitive))
                || (kPidItem != nullptr && kPidItem->text().contains(kKeyword, Qt::CaseInsensitive));
        }
        processTable_->setRowHidden(row, !matched);
        if (matched)
        {
            ++shownRows;
        }
    }

    if (processCountLabel_ != nullptr)
    {
        processCountLabel_->setText(kKeyword.isEmpty()
            ? QString("共 %1 个进程").arg(kTotalRows)
            : QString("显示 %1 / 共 %2").arg(shownRows).arg(kTotalRows));
    }
}

void MemoryDock::updateProcessComboFromCache()
{
    // Combo box rebuild entry log: record cache size.
    KLogEvent comboUpdateEvent;
    dbg << comboUpdateEvent
        << "[MemoryDock] updateProcessComboFromCache: 重建下拉框, cacheSize="
        << processCache_.size()
        << eol;

    // Block signals during dropdown reconstruction to prevent repeated module refresh triggers.
    QSignalBlocker blocker(processCombo_);
    processCombo_->clear();

    // Handling multiple processes with the same name: For applications like QQ that launch multiple instances with identical names, the name alone is
    // insufficient to identify the target. Selecting the wrong one results in "address read failure," even though the read code itself is correct—this
    // misleads the debugging process entirely toward memory reading issues. Therefore, when names match, display the working set as well: the memory
    // usage of the main process and auxiliary processes typically differs by one or two orders of magnitude, allowing for immediate visual distinction.
    QHash<QString, int> nameCount;
    for (const ProcessEntry& entry : processCache_)
    {
        nameCount[entry.processName] += 1;
    }

    for (const ProcessEntry& entry : processCache_)
    {
        QString text = QString("%1 [PID:%2]").arg(entry.processName).arg(entry.pid);
        if (nameCount.value(entry.processName) > 1)
        {
            text += QString(" · %1 MB · 同名 %2 个")
                .arg(entry.workingSetMB, 0, 'f', 0)
                .arg(nameCount.value(entry.processName));
        }
        processCombo_->addItem(text, QVariant::fromValue(static_cast<uint>(entry.pid)));
        const int kRow = processCombo_->count() - 1;
        processCombo_->setItemData(kRow, entry.processName, Qt::UserRole + 1);
    }

    // When the attached PID still exists, select it by default.
    bool selectedAttachedProcess = false;
    if (attachedPid_ != 0)
    {
        for (int comboIndex = 0; comboIndex < processCombo_->count(); ++comboIndex)
        {
            if (processCombo_->itemData(comboIndex, Qt::UserRole).toUInt() == attachedPid_)
            {
                processCombo_->setCurrentIndex(comboIndex);
                selectedAttachedProcess = true;
                break;
            }
        }
    }
    if (!selectedAttachedProcess && processCombo_->count() > 0)
    {
        processCombo_->setCurrentIndex(0);
    }

    // Tab6's R0 read/write pages also reuse the process cache; after the top dropdown rebuild completes, synchronize and refresh the target selection.
    updateDriverMemoryBaseComboFromProcessCache();
}

void MemoryDock::rebuildModuleTableFromCache()
{
    // Redraw the module table using only the cache: this path does not trigger Win32 enumeration, making it suitable for high-frequency calls during input filtering.
    const QString kFilterText = (moduleFilterEdit_ == nullptr) ? QString() : moduleFilterEdit_->text().trimmed();
    std::vector<const ModuleEntry*> filteredModules;
    filteredModules.reserve(moduleCache_.size());
    for (const ModuleEntry& entry : moduleCache_)
    {
        if (!kFilterText.isEmpty() &&
            !entry.moduleName.contains(kFilterText, Qt::CaseInsensitive) &&
            !entry.fullPath.contains(kFilterText, Qt::CaseInsensitive))
        {
            continue;
        }
        filteredModules.push_back(&entry);
    }

    // Disable painting and signals during batch updates to reduce reflow overhead and avoid redundant callbacks.
    moduleTable_->setUpdatesEnabled(false);
    const QSignalBlocker kTableBlocker(moduleTable_);
    moduleTable_->clear();

    // Icons are cached by path: on a miss, only place a placeholder and record the source path; never synchronously query the Shell here.
    // Modules often number in the hundreds; querying each QFileIconProvider individually during a cold cache will stall both the first frame and filtered input.
    const int kModulePathColumnIndex = toModuleTreeColumnIndex(ModuleTreeColumn::kPath);
    for (const ModuleEntry* moduleEntryPtr : filteredModules)
    {
        const ModuleEntry& entry = *moduleEntryPtr;
        QTreeWidgetItem* rowItem = new QTreeWidgetItem();
        rowItem->setText(toModuleTreeColumnIndex(ModuleTreeColumn::kPath), entry.fullPath);
        rowItem->setText(toModuleTreeColumnIndex(ModuleTreeColumn::kSize), formatSize(entry.sizeBytes));
        rowItem->setText(toModuleTreeColumnIndex(ModuleTreeColumn::kSignature), entry.signatureState);
        rowItem->setText(
            toModuleTreeColumnIndex(ModuleTreeColumn::kEntryOffset),
            QString("0x%1").arg(entry.entryPointOffset, 0, 16).toUpper());
        rowItem->setText(toModuleTreeColumnIndex(ModuleTreeColumn::kState), entry.runningState);
        rowItem->setText(toModuleTreeColumnIndex(ModuleTreeColumn::kThreadId), entry.threadIdText);
        // The icon key consistently uses the trimmed path to maintain text consistency with the background extraction task and back-write comparison.
        const QString kModuleIconPath = entry.fullPath.trimmed();
        rowItem->setIcon(kModulePathColumnIndex, lookupCachedPathIcon(kModuleIconPath));
        rowItem->setData(kModulePathColumnIndex, kIconPathItemRole, kModuleIconPath);

        // Saves the base address and thread ID for double-click navigation and right-click reverse lookup.
        rowItem->setData(
            toModuleTreeColumnIndex(ModuleTreeColumn::kPath),
            Qt::UserRole,
            QVariant::fromValue<qulonglong>(entry.baseAddress));
        rowItem->setData(
            toModuleTreeColumnIndex(ModuleTreeColumn::kPath),
            Qt::UserRole + 1,
            QVariant::fromValue(entry.representativeThreadId));

        // Signature column color strategy: green for trusted, gray for unknown, red for untrusted.
        if (entry.signatureTrusted)
        {
            rowItem->setForeground(
                toModuleTreeColumnIndex(ModuleTreeColumn::kSignature),
                ksword_theme::successColor());
        }
        else if (entry.signatureState.compare("Pending", Qt::CaseInsensitive) == 0 ||
            entry.signatureState.compare("Unknown", Qt::CaseInsensitive) == 0)
        {
            rowItem->setForeground(
                toModuleTreeColumnIndex(ModuleTreeColumn::kSignature),
                ksword_theme::textSecondaryColor());
        }
        else
        {
            rowItem->setForeground(
                toModuleTreeColumnIndex(ModuleTreeColumn::kSignature),
                ksword_theme::errorColor());
        }

        moduleTable_->addTopLevelItem(rowItem);
    }

    // Sorting still executes on the path column to maintain consistency with the original interaction habit.
    moduleTable_->sortItems(kModulePathColumnIndex, Qt::AscendingOrder);
    moduleTable_->setUpdatesEnabled(true);

    // For module paths not found in cache, submit them to a thread pool to extract icons; the callback only updates the corresponding node without rebuilding the entire tree.
    const QPointer<MemoryDock> kGuardedSelf(this);
    QSet<QString> queuedIconPaths;
    for (const ModuleEntry* moduleEntryPtr : filteredModules)
    {
        const QString kModulePath = moduleEntryPtr->fullPath.trimmed();
        if (kModulePath.isEmpty() || queuedIconPaths.contains(kModulePath))
        {
            continue;
        }
        queuedIconPaths.insert(kModulePath);
        queuePathIconExtraction(
            kModulePath,
            [kGuardedSelf, kModulePathColumnIndex](const QString& resolvedPath, const QIcon& resolvedIcon) {
                if (kGuardedSelf == nullptr)
                {
                    return;
                }
                applyIconToModuleTreeRows(
                    kGuardedSelf->moduleTable_,
                    kModulePathColumnIndex,
                    resolvedPath,
                    resolvedIcon);
            });
    }

    // End of redraw log: used to confirm the visible count after filtering.
    KLogEvent rebuildModuleTableEvent;
    dbg << rebuildModuleTableEvent
        << "[MemoryDock] rebuildModuleTableFromCache: 完成, cacheCount="
        << moduleCache_.size()
        << ", visibleCount="
        << filteredModules.size()
        << ", filterText="
        << kFilterText.toStdString()
        << eol;
}

bool MemoryDock::refreshModuleListForPid(const std::uint32_t pid)
{
    // Module refresh is now asynchronous to prevent signature verification and module enumeration from blocking the main thread.
    KLogEvent refreshModuleStartEvent;
    info << refreshModuleStartEvent
        << "[MemoryDock] refreshModuleListForPid: 请求刷新模块, pid="
        << pid
        << eol;

    if (pid == 0)
    {
        // If pid is 0, indicating no valid target, clear the cache and table directly.
        moduleCache_.clear();
        rebuildModuleTableFromCache();
        if (moduleStatusLabel_ != nullptr)
        {
            moduleStatusLabel_->setText("● 未选择有效进程");
            moduleStatusLabel_->setStyleSheet(
                QStringLiteral("color:%1; font-weight:700;")
                    .arg(ksword_theme::errorColor().name(QColor::HexRgb)));
        }
        return false;
    }

    // Generate an incrementing ticket for each request; old task callbacks will be discarded.
    const std::uint64_t kRefreshTicket = moduleRefreshTicket_.fetch_add(1) + 1;
    const bool kIncludeSignatureCheck =
        (moduleSignatureCheck_ != nullptr) && moduleSignatureCheck_->isChecked();
    moduleRefreshInProgress_.store(true);

    // Update the status bar and temporarily disable the button during refresh to prevent users from mistakenly thinking the click is invalid and triggering it repeatedly.
    if (moduleRefreshButton_ != nullptr)
    {
        moduleRefreshButton_->setEnabled(false);
    }
    if (moduleStatusLabel_ != nullptr)
    {
        moduleStatusLabel_->setText(
            QString("● 正在刷新模块(PID=%1, 签名校验=%2)...")
            .arg(pid)
            .arg(kIncludeSignatureCheck ? "开启" : "关闭"));
        moduleStatusLabel_->setStyleSheet(
            QStringLiteral("color:%1; font-weight:700;").arg(ksword_theme::kPrimaryBlueHex));
    }

    // Use QPointer to guard 'this', preventing access to a dangling object after the window is destroyed.
    // enumerate via the global thread pool instead of detaching raw threads: when switching processes continuously, concurrency
    // is capped by the pool limit, preventing the system from being overwhelmed by creating a new thread for every switch.
    const QPointer<MemoryDock> kSelfGuard(this);
    QRunnable* const kRefreshModuleTask = QRunnable::create(
        [kSelfGuard, pid, kIncludeSignatureCheck, kRefreshTicket]() {
        if (kSelfGuard == nullptr)
        {
            return;
        }

        // Background threads perform only time-consuming enumeration and data conversion, without directly manipulating any Qt controls.
        const auto kRefreshStartTime = std::chrono::steady_clock::now();
        const ks::process::ProcessModuleSnapshot kModuleSnapshot =
            ks::process::enumerateProcessModulesAndThreads(pid, kIncludeSignatureCheck);

        std::vector<ModuleEntry> moduleCache;
        moduleCache.reserve(kModuleSnapshot.modules.size());
        for (const ks::process::ProcessModuleRecord& moduleRecord : kModuleSnapshot.modules)
        {
            ModuleEntry entry{};
            entry.fullPath = QString::fromStdString(moduleRecord.modulePath);
            entry.moduleName = QFileInfo(entry.fullPath).fileName();
            entry.baseAddress = moduleRecord.moduleBaseAddress;
            entry.sizeBytes = moduleRecord.moduleSizeBytes;
            entry.signatureState = QString::fromStdString(moduleRecord.signatureState);
            entry.signatureTrusted = moduleRecord.signatureTrusted;
            entry.entryPointOffset = moduleRecord.entryPointRva;
            entry.runningState = QString::fromStdString(moduleRecord.runningState);
            entry.threadIdText = QString::fromStdString(moduleRecord.threadIdText);
            entry.representativeThreadId = moduleRecord.representativeThreadId;
            moduleCache.push_back(std::move(entry));
        }
        std::sort(moduleCache.begin(), moduleCache.end(), [](const ModuleEntry& left, const ModuleEntry& right) {
            return left.baseAddress < right.baseAddress;
            });

        const std::uint64_t kElapsedMs = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - kRefreshStartTime).count());
        const std::size_t kModuleCount = kModuleSnapshot.modules.size();
        const std::size_t kThreadCount = kModuleSnapshot.threads.size();
        const QString kDiagnosticText = QString::fromStdString(kModuleSnapshot.diagnosticText).trimmed();

        // Results are committed on the main thread to ensure Qt view update thread safety.
        QMetaObject::invokeMethod(kSelfGuard.data(), [kSelfGuard,
            pid,
            kIncludeSignatureCheck,
            kRefreshTicket,
            kElapsedMs,
            kModuleCount,
            kThreadCount,
            kDiagnosticText,
            moduleCache = std::move(moduleCache)]() mutable {
                if (kSelfGuard == nullptr)
                {
                    return;
                }

                // If the ticket has expired, it means the user initiated a new refresh; discard the old result directly.
                if (kRefreshTicket < kSelfGuard->moduleRefreshTicket_.load())
                {
                    KLogEvent staleModuleEvent;
                    dbg << staleModuleEvent
                        << "[MemoryDock] refreshModuleListForPid: 丢弃过期模块结果, ticket="
                        << kRefreshTicket
                        << ", latestTicket="
                        << kSelfGuard->moduleRefreshTicket_.load()
                        << eol;
                    return;
                }

                auto moduleCacheSnapshot =
                    std::make_shared<std::vector<ModuleEntry>>(std::move(moduleCache));
                auto commitModuleSnapshot = [
                    kSelfGuard,
                    pid,
                    kIncludeSignatureCheck,
                    kRefreshTicket,
                    kElapsedMs,
                    kModuleCount,
                    kThreadCount,
                    kDiagnosticText,
                    moduleCacheSnapshot]() mutable
                {
                    if (kSelfGuard == nullptr ||
                        kRefreshTicket < kSelfGuard->moduleRefreshTicket_.load())
                    {
                        return;
                    }

                    // Cache and tree must be committed atomically; the menu cannot switch to a new cache while retaining old nodes.
                    kSelfGuard->moduleCache_ = std::move(*moduleCacheSnapshot);
                    kSelfGuard->rebuildModuleTableFromCache();
                    kSelfGuard->syncTamperDetectionTargets();

                    kSelfGuard->moduleRefreshInProgress_.store(false);
                    if (kSelfGuard->moduleRefreshButton_ != nullptr)
                    {
                        kSelfGuard->moduleRefreshButton_->setEnabled(true);
                    }

                    if (kSelfGuard->moduleStatusLabel_ != nullptr)
                    {
                        QString statusText = QString("● %1 ms | 模块:%2 线程:%3 显示:%4")
                            .arg(kElapsedMs)
                            .arg(kModuleCount)
                            .arg(kThreadCount)
                            .arg(kSelfGuard->moduleTable_->topLevelItemCount());
                        if (!kDiagnosticText.isEmpty())
                        {
                            statusText += QStringLiteral(
                                " | 存在诊断；详情已写入日志。");
                        }
                        kSelfGuard->moduleStatusLabel_->setText(statusText);
                        kSelfGuard->moduleStatusLabel_->setStyleSheet(
                            QStringLiteral("color:%1; font-weight:%2;")
                                .arg(kModuleCount == 0
                                    ? ksword_theme::errorColor().name(QColor::HexRgb)
                                    : ksword_theme::successColor().name(QColor::HexRgb))
                                .arg(kModuleCount == 0 ? 700 : 600));
                    }

                    KLogEvent refreshModuleFinishEvent;
                    info << refreshModuleFinishEvent
                        << "[MemoryDock] refreshModuleListForPid: 刷新完成, pid="
                        << pid
                        << ", elapsedMs="
                        << kElapsedMs
                        << ", moduleCount="
                        << kModuleCount
                        << ", threadCount="
                        << kThreadCount
                        << ", visibleCount="
                        << kSelfGuard->moduleTable_->topLevelItemCount()
                        << ", includeSignatureCheck="
                        << (kIncludeSignatureCheck ? "true" : "false")
                        << ", diagnostic="
                        << kDiagnosticText.toStdString()
                        << eol;
                };

                if (ks::ui::deferItemViewUiCommitIfContextMenuOpen(
                        kSelfGuard.data(),
                        QStringLiteral("memory-process-modules-snapshot-apply"),
                        {kSelfGuard->moduleTable_},
                        commitModuleSnapshot))
                {
                    return;
                }
                commitModuleSnapshot();
            }, Qt::QueuedConnection);
        });
    kRefreshModuleTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(kRefreshModuleTask);

    return true;
}

bool MemoryDock::attachToProcess(
    const std::uint32_t pid,
    const QString& processName,
    const bool showMessage)
{
    // Attach entry log: record target PID and whether a popup feedback is shown.
    KLogEvent attachStartEvent;
    info << attachStartEvent
        << "[MemoryDock] attachToProcess: 开始附加, pid="
        << pid
        << ", processName="
        << processName.toStdString()
        << ", showMessage="
        << (showMessage ? "true" : "false")
        << eol;

    // Clean up the old process context before attaching to avoid residual handles.
    detachProcess();

    // Prefer read/write permissions to satisfy memory write and breakpoint capabilities.
    HANDLE processHandle = ::OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
        FALSE,
        toDwordPid(pid));
    if (processHandle == nullptr)
    {
        // On failure, fall back to read-only permissions to ensure at least browsing capability.
        processHandle = ::OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
            FALSE,
            toDwordPid(pid));
        if (processHandle == nullptr)
        {
            const DWORD kOpenError = ::GetLastError();
            KLogEvent attachOpenFailEvent;
            err << attachOpenFailEvent
                << "[MemoryDock] attachToProcess: 读写+只读权限均失败, pid="
                << pid
                << ", error="
                << kOpenError
                << eol;
            if (showMessage)
            {
                if (kOpenError == ERROR_ACCESS_DENIED)
                {
                    (void)ks::ui::requestAdministratorRestartForFeature(
                        this,
                        QStringLiteral("附加进程内存"));
                }
                else
                {
                    QMessageBox::warning(
                        this,
                        "附加失败",
                        "OpenProcess 失败，目标进程可能已退出或不可访问。");
                }
            }
            updateStatusBarText();
            return false;
        }
        canReadWriteMemory_ = false;
        KLogEvent attachReadonlyEvent;
        warn << attachReadonlyEvent
            << "[MemoryDock] attachToProcess: 退化为只读句柄, pid="
            << pid
            << eol;
    }
    else
    {
        canReadWriteMemory_ = true;
        KLogEvent attachReadWriteEvent;
        info << attachReadWriteEvent
            << "[MemoryDock] attachToProcess: 获取到可读写句柄, pid="
            << pid
            << eol;
    }

    attachedProcessHandle_ = processHandle;
    attachedPid_ = pid;
    attachedProcessName_ = processName;
    updateStatusBarText();
    syncTamperDetectionTargets();

    // Refresh the module and region lists immediately after attachment to reduce the wait for the next step. Both operations run in the background, so
    // the interface becomes usable instantly after clicking the attach button, avoiding a blank screen even if the target process address space is large.
    refreshModuleListForPid(pid);

    // The explicit attach path requires region enumeration to take the asynchronous branch: the region cache must be empty at this point (cleared by
    // detachProcess). Without this flag, it would fall back to the 'synchronous traversal when cache is empty' fallback branch, freezing the UI again.
    setProperty(kRegionRefreshFromAttachProperty, true);
    refreshMemoryRegionList(true);

    if (showMessage)
    {
        QMessageBox::information(
            this,
            "附加成功",
            QString("已附加到 %1 (PID=%2)\n读写状态: %3")
            .arg(processName)
            .arg(pid)
            .arg(canReadWriteMemory_ ? "可读可写" : "只读"));
    }

    // Attach completion log: record final status.
    KLogEvent attachFinishEvent;
    info << attachFinishEvent
        << "[MemoryDock] attachToProcess: 附加完成, pid="
        << pid
        << ", canReadWrite="
        << (canReadWriteMemory_ ? "true" : "false")
        << eol;
    return true;
}

void MemoryDock::focusProcessForOperations(const std::uint32_t pid, const bool showMessage)
{
    // Jumping from the Process Dock: refresh the process list, locate the target row, and switch to the 'Process & Modules/Memory Region' operation context.
    if (pid == 0)
    {
        return;
    }

    // Process list refresh is now asynchronous; attaching can no longer wait for table reconstruction to complete. Process names are
    // prioritized from the existing cache; on cache miss, only a single image path query is performed (single process handle, negligible cost).
    QString processName;
    for (const ProcessEntry& entry : processCache_)
    {
        if (entry.pid == pid)
        {
            processName = entry.processName.trimmed();
            break;
        }
    }
    if (processName.isEmpty())
    {
        const QString kImagePath = QString::fromStdString(ks::process::queryProcessPathByPid(pid));
        processName = QFileInfo(kImagePath).fileName().trimmed();
    }
    if (processName.isEmpty())
    {
        processName = QStringLiteral("PID_%1").arg(pid);
    }

    // Register the target row as pending: the selection and scrolling will be completed by the commit phase after the current asynchronous refresh backfills the process table.
    setProperty(kProcessFocusPendingPidProperty, static_cast<uint>(pid));
    refreshProcessList(true);

    // If the process already exists in the current table, locate it immediately without waiting for asynchronous results.
    (void)selectProcessRowByPid(processTable_, processCombo_, pid);

    attachToProcess(pid, processName, showMessage);
    if (tabWidget_ != nullptr && tabRegions_ != nullptr)
    {
        tabWidget_->setCurrentWidget(tabRegions_);
    }
}

void MemoryDock::focusProcessForSearch(const std::uint32_t pid, const bool showMessage)
{
    // The search page requires a valid process handle and the latest region cache; first reuse the standard attach flow, then switch to the search page.
    focusProcessForOperations(pid, showMessage);
    if (attachedPid_ == pid && tabWidget_ != nullptr && tabSearch_ != nullptr)
    {
        tabWidget_->setCurrentWidget(tabSearch_);
    }
}

void MemoryDock::setProcessDetailMemoryScope()
{
    // Process details require only the basic memory analysis entry point for the current PID.
    // Remaining breakpoints, R0 read/write, kernel scanning, and evidence pages remain in the independent Memory Dock to avoid the embedded window becoming a full copy.
    if (tabWidget_ == nullptr)
    {
        return;
    }

    for (int tabIndex = 0; tabIndex < tabWidget_->count(); ++tabIndex)
    {
        QWidget* const kTabPage = tabWidget_->widget(tabIndex);
        const bool kVisibleInProcessDetail =
            kTabPage == tabProcessModule_ ||
            kTabPage == tabRegions_ ||
            kTabPage == tabSearch_ ||
            kTabPage == tabViewer_;
        tabWidget_->setTabVisible(tabIndex, kVisibleInProcessDetail);
    }

    if (tabRegions_ != nullptr)
    {
        tabWidget_->setCurrentWidget(tabRegions_);
    }
}

void MemoryDock::detachProcess()
{
    // Detach entry log: Record the old PID for tracking.
    KLogEvent detachStartEvent;
    info << detachStartEvent
        << "[MemoryDock] detachProcess: 开始分离, oldPid="
        << attachedPid_
        << eol;

    // Cancel and wait for all scanning coordination threads to exit first, then close the process
    // HANDLE to prevent background ReadProcessMemory operations from using closed or reused HANDLEs.
    cancelAndWaitForMemoryScanTasks();

    // First, invalidate all asynchronous snapshots based on the old attachment context. PTE/evidence tasks hold copy handles,
    // so they can safely complete system calls, but their results must not be written back to the new attached process.
    processAttachmentGeneration_.fetch_add(1U);

    // The in-flight and pending flags for region enumeration are bound to the attachment context: they are not reset here. If not reset, the in-flight
    // flags left by the previous task will block re-attachment, causing new targets to wait indefinitely for the region list. When the old task is
    // re-injected, it compares generation numbers; if the context has changed, it abandons the entire segment and will not revisit these flags.
    setProperty(kRegionRefreshInFlightProperty, false);
    setProperty(kRegionRefreshPendingProperty, false);
    setProperty(kRegionRefreshFromAttachProperty, false);

    processPteTranslateRefreshTicket_.fetch_add(1U);
    processMemoryEvidenceRefreshTicket_.fetch_add(1U);
    processPteTranslateRefreshInProgress_.store(false);
    processMemoryEvidenceRefreshInProgress_.store(false);
    if (processPteTranslateRefreshButton_ != nullptr)
    {
        processPteTranslateRefreshButton_->setEnabled(true);
    }
    if (processMemoryEvidenceRefreshButton_ != nullptr)
    {
        processMemoryEvidenceRefreshButton_->setEnabled(true);
    }

    // Synchronously increment the module refresh ticket to ensure old asynchronous module callbacks do not overwrite the 'detached' state.
    moduleRefreshTicket_.fetch_add(1);
    moduleRefreshInProgress_.store(false);
    if (moduleRefreshButton_ != nullptr)
    {
        moduleRefreshButton_->setEnabled(true);
    }

    if (attachedProcessHandle_ != nullptr)
    {
        ::CloseHandle(attachedProcessHandle_);
        attachedProcessHandle_ = nullptr;
    }

    attachedPid_ = 0;
    attachedProcessName_.clear();
    canReadWriteMemory_ = false;

    // Clear dependent context data caches upon detachment.
    moduleCache_.clear();
    regionCache_.clear();
    searchResultCache_.clear();
    searchResultVisibleCount_ = 0;
    processPteTranslateCache_.clear();
    processPteTranslateVisibleCount_ = 0;
    processMemoryEvidenceCache_.clear();
    processMemoryEvidenceVisibleCount_ = 0;

    // Clear the table display to prevent users from accidentally operating on stale data.
    moduleTable_->clear();
    if (moduleStatusLabel_ != nullptr)
    {
        moduleStatusLabel_->setText("● 未附加进程");
        moduleStatusLabel_->setStyleSheet(
            QStringLiteral("color:%1; font-weight:600;")
                .arg(ksword_theme::textSecondaryColor().name(QColor::HexRgb)));
    }
    regionTable_->setRowCount(0);
    searchResultTable_->setRowCount(0);
    if (processPteTranslateTable_ != nullptr)
    {
        processPteTranslateTable_->setRowCount(0);
    }
    if (processMemoryEvidenceTable_ != nullptr)
    {
        processMemoryEvidenceTable_->setRowCount(0);
    }
    if (processPteTranslateStatusLabel_ != nullptr)
    {
        processPteTranslateStatusLabel_->setText(QStringLiteral("状态：请先附加进程。"));
    }
    if (processMemoryEvidenceStatusLabel_ != nullptr)
    {
        processMemoryEvidenceStatusLabel_->setText(QStringLiteral("状态：请先附加进程。"));
    }
    if (hexEditorWidget_ != nullptr)
    {
        hexEditorWidget_->setEditable(false);
        hexEditorWidget_->clearData();
    }
    resetDriverMemoryRwState();
    viewerStatusLabel_->setText("未附加进程。");

    updateStatusBarText();

    // Detach end log: Confirm cache is cleared.
    KLogEvent detachFinishEvent;
    info << detachFinishEvent
        << "[MemoryDock] detachProcess: 分离完成，缓存与表格已重置。"
        << eol;
}

std::shared_ptr<void> MemoryDock::duplicateAttachedProcessHandleForWorker(
    std::uint32_t* const errorCodeOut) const
{
    // Background tasks must not borrow m_attachedProcessHandle: detachment or re-attachment closes it, and Windows may immediately assign
    // the same value to another kernel object. Independently duplicating the handle decouples the system call lifecycle from the UI.
    if (errorCodeOut != nullptr)
    {
        *errorCodeOut = ERROR_SUCCESS;
    }

    if (attachedProcessHandle_ == nullptr)
    {
        if (errorCodeOut != nullptr)
        {
            *errorCodeOut = ERROR_INVALID_HANDLE;
        }
        return {};
    }

    HANDLE duplicatedHandle = nullptr;
    if (::DuplicateHandle(
            ::GetCurrentProcess(),
            attachedProcessHandle_,
            ::GetCurrentProcess(),
            &duplicatedHandle,
            0U,
            FALSE,
            DUPLICATE_SAME_ACCESS) == FALSE)
    {
        if (errorCodeOut != nullptr)
        {
            *errorCodeOut = static_cast<std::uint32_t>(::GetLastError());
        }
        return {};
    }

    return std::shared_ptr<void>(duplicatedHandle, [](void* const rawHandle) {
        if (rawHandle != nullptr)
        {
            ::CloseHandle(static_cast<HANDLE>(rawHandle));
        }
    });
}

HANDLE MemoryDock::openProcessHandleForRead(const std::uint32_t pid, QString* const errorTextOut) const
{
    // Read handle logs: used to diagnose insufficient permission issues.
    KLogEvent openReadHandleEvent;
    dbg << openReadHandleEvent
        << "[MemoryDock] openProcessHandleForRead: pid="
        << pid
        << eol;

    HANDLE processHandle = ::OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        FALSE,
        toDwordPid(pid));
    if (processHandle == nullptr && errorTextOut != nullptr)
    {
        *errorTextOut = QString("OpenProcess 失败，错误码=%1").arg(::GetLastError());
        KLogEvent openReadHandleFailEvent;
        warn << openReadHandleFailEvent
            << "[MemoryDock] openProcessHandleForRead: 打开失败, pid="
            << pid
            << ", error="
            << ::GetLastError()
            << eol;
    }
    return processHandle;
}

void MemoryDock::showProcessTableContextMenu(const QPoint& localPosition)
{
    // Right-click entry log: Record the trigger location to facilitate diagnosis of menu behavior.
    KLogEvent contextMenuEvent;
    dbg << contextMenuEvent
        << "[MemoryDock] showProcessTableContextMenu: x="
        << localPosition.x()
        << ", y="
        << localPosition.y()
        << eol;

    if (processTable_ == nullptr)
    {
        return;
    }

    const QModelIndex kIndex = processTable_->indexAt(localPosition);
    if (!kIndex.isValid())
    {
        return;
    }

    const int kRow = kIndex.row();
    const QTableWidgetItem* pidItem = processTable_->item(kRow, 1);
    const QTableWidgetItem* nameItem = processTable_->item(kRow, 0);
    if (pidItem == nullptr || nameItem == nullptr)
    {
        return;
    }

    bool pidOk = false;
    const std::uint32_t kPid = pidItem->text().toUInt(&pidOk);
    if (!pidOk || kPid == 0)
    {
        return;
    }
    const QString kProcessName = nameItem->text().trimmed();
    processTable_->setCurrentCell(kRow, kIndex.column());

    QMenu contextMenu(this);
    contextMenu.setStyleSheet(ksword_theme::contextMenuStyle());
    QAction* attachAction = contextMenu.addAction(
        QIcon(":/Icon/process_start.svg"),
        QStringLiteral("附加进程"));
    QAction* dumpAction = contextMenu.addAction(
        QIcon(":/Icon/process_details.svg"),
        QStringLiteral("Dump内存到文件"));
    QAction* copyRowAction = contextMenu.addAction(
        QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
        QStringLiteral("复制当前行"));

    QAction* selectedAction = contextMenu.exec(processTable_->viewport()->mapToGlobal(localPosition));
    if (selectedAction == nullptr)
    {
        return;
    }

    if (selectedAction == attachAction)
    {
        attachToProcess(kPid, kProcessName, true);
        return;
    }

    if (selectedAction == dumpAction)
    {
        requestDumpProcessMemoryByPid(kPid, kProcessName);
        return;
    }

    if (selectedAction == copyRowAction)
    {
        copyProcessRegionTableRow(processTable_, kRow);
        KLogEvent copyProcessRowEvent;
        dbg << copyProcessRowEvent
            << "[MemoryDock] 进程表右键复制当前行, row="
            << kRow
            << ", pid="
            << kPid
            << eol;
    }
}

void MemoryDock::requestDumpProcessMemoryByPid(const std::uint32_t pid, const QString& processName)
{
    // Dump request log: records PID and process name for subsequent auditing.
    KLogEvent dumpRequestEvent;
    info << dumpRequestEvent
        << "[MemoryDock] requestDumpProcessMemoryByPid: pid="
        << pid
        << ", processName="
        << processName.toStdString()
        << eol;

    const QString kDefaultFileName = QStringLiteral("%1_pid%2_%3.kmdump")
        .arg(processName.isEmpty() ? QStringLiteral("process") : processName)
        .arg(pid)
        .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss")));

    const QString kOutputPath = QFileDialog::getSaveFileName(
        this,
        QStringLiteral("保存进程内存Dump"),
        kDefaultFileName,
        QStringLiteral("Ksword Memory Dump (*.kmdump);;All Files (*.*)"));
    if (kOutputPath.trimmed().isEmpty())
    {
        return;
    }

    if (dumpMemoryProgressPid_ == 0)
    {
        dumpMemoryProgressPid_ = kPro.addReusable(this, "内存", "Dump进程内存");
    }
    kPro.set(dumpMemoryProgressPid_, "准备读取内存区域", 0, 5.0f);

    QPointer<MemoryDock> guardThis(this);
    std::thread([guardThis, pid, processName, kOutputPath]() {
        if (guardThis == nullptr)
        {
            return;
        }

        QString errorText;
        const bool kDumpOk = guardThis->dumpProcessMemoryToFile(pid, kOutputPath, errorText);
        QMetaObject::invokeMethod(qApp, [guardThis, kDumpOk, pid, processName, kOutputPath, errorText]() {
            if (guardThis == nullptr)
            {
                return;
            }

            if (kDumpOk)
            {
                kPro.set(guardThis->dumpMemoryProgressPid_, "Dump完成", 0, 100.0f);

                KLogEvent dumpFinishEvent;
                info << dumpFinishEvent
                    << "[MemoryDock] Dump完成, pid="
                    << pid
                    << ", path="
                    << kOutputPath.toStdString()
                    << eol;

                QMessageBox::information(
                    guardThis,
                    QStringLiteral("Dump完成"),
                    QStringLiteral("进程 %1 (PID=%2) 内存已保存到：\n%3")
                    .arg(processName)
                    .arg(pid)
                    .arg(kOutputPath));
            }
            else
            {
                kPro.set(guardThis->dumpMemoryProgressPid_, "Dump失败", 0, 100.0f);

                KLogEvent dumpFailEvent;
                err << dumpFailEvent
                    << "[MemoryDock] Dump失败, pid="
                    << pid
                    << ", error="
                    << errorText.toStdString()
                    << eol;

                // privilegePromptHandled: Record whether the Dump failure was handled by the privilege escalation prompt.
                const bool kPrivilegePromptHandled = ks::ui::promptForPrivilegeFailure(
                    guardThis,
                    QStringLiteral("导出进程内存"),
                    errorText);
                if (!kPrivilegePromptHandled)
                {
                    QMessageBox::warning(
                        guardThis,
                        QStringLiteral("Dump失败"),
                        QStringLiteral("进程 %1 (PID=%2) Dump失败：\n%3")
                        .arg(processName)
                        .arg(pid)
                        .arg(errorText));
                }
            }
        }, Qt::QueuedConnection);
    }).detach();
}

bool MemoryDock::dumpProcessMemoryToFile(
    const std::uint32_t pid,
    const QString& dumpFilePath,
    QString& errorTextOut)
{
    errorTextOut.clear();

    HANDLE processHandle = ::OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE,
        toDwordPid(pid));
    if (processHandle == nullptr)
    {
        errorTextOut = QString("OpenProcess 失败, error=%1").arg(::GetLastError());
        return false;
    }

    QFile outputFile(dumpFilePath);
    if (!outputFile.open(QIODevice::WriteOnly | QIODevice::Truncate))
    {
        ::CloseHandle(processHandle);
        errorTextOut = QString("无法写入文件: %1").arg(dumpFilePath);
        return false;
    }

    // Dump file header structure:
    // - magic: file signature
    // - version: Version number (to facilitate future format upgrades);
    // - pid: target process PID.
    // - timestamp100ns: creation timestamp (100ns units);
    // - regionCount: Number of regions successfully written.
    struct DumpFileHeader final
    {
        char magic[8];
        std::uint32_t version = 1;
        std::uint32_t pid = 0;
        std::uint64_t timestamp100ns = 0;
        std::uint32_t regionCount = 0;
        std::uint32_t reserved = 0;
    };

    struct DumpRegionHeader final
    {
        std::uint64_t baseAddress = 0;
        std::uint64_t declaredRegionSize = 0;
        std::uint64_t dumpedBytes = 0;
        std::uint32_t protect = 0;
        std::uint32_t state = 0;
        std::uint32_t type = 0;
        std::uint32_t reserved = 0;
    };

    FILETIME fileTime{};
    ::GetSystemTimeAsFileTime(&fileTime);
    ULARGE_INTEGER fileTimeValue{};
    fileTimeValue.LowPart = fileTime.dwLowDateTime;
    fileTimeValue.HighPart = fileTime.dwHighDateTime;

    DumpFileHeader fileHeader{};
    std::memcpy(fileHeader.magic, "KMDUMP1", 7);
    fileHeader.magic[7] = '\0';
    fileHeader.pid = pid;
    fileHeader.timestamp100ns = fileTimeValue.QuadPart;

    outputFile.write(reinterpret_cast<const char*>(&fileHeader), static_cast<qint64>(sizeof(fileHeader)));

    SYSTEM_INFO systemInfo{};
    ::GetSystemInfo(&systemInfo);
    const std::uint64_t kMinAddress = reinterpret_cast<std::uintptr_t>(systemInfo.lpMinimumApplicationAddress);
    const std::uint64_t kMaxAddress = reinterpret_cast<std::uintptr_t>(systemInfo.lpMaximumApplicationAddress);

    constexpr SIZE_T kChunkSize = 256 * 1024;
    std::vector<std::uint8_t> chunkBuffer(kChunkSize, 0);

    std::uint64_t currentAddress = kMinAddress;
    std::uint32_t dumpedRegionCount = 0;
    while (currentAddress < kMaxAddress)
    {
        MEMORY_BASIC_INFORMATION mbi{};
        const SIZE_T kQuerySize = ::VirtualQueryEx(
            processHandle,
            reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(currentAddress)),
            &mbi,
            sizeof(mbi));
        if (kQuerySize != sizeof(mbi))
        {
            break;
        }

        const std::uint64_t kRegionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
        const std::uint64_t kRegionSize = static_cast<std::uint64_t>(mbi.RegionSize);

        if (mbi.State == MEM_COMMIT && isReadableProtect(static_cast<std::uint32_t>(mbi.Protect)))
        {
            DumpRegionHeader regionHeader{};
            regionHeader.baseAddress = kRegionBase;
            regionHeader.declaredRegionSize = kRegionSize;
            regionHeader.protect = static_cast<std::uint32_t>(mbi.Protect);
            regionHeader.state = static_cast<std::uint32_t>(mbi.State);
            regionHeader.type = static_cast<std::uint32_t>(mbi.Type);

            const qint64 kHeaderPosition = outputFile.pos();
            outputFile.write(reinterpret_cast<const char*>(&regionHeader), static_cast<qint64>(sizeof(regionHeader)));

            std::uint64_t offsetInRegion = 0;
            std::uint64_t dumpedBytes = 0;
            while (offsetInRegion < kRegionSize)
            {
                const SIZE_T kRemainSize = static_cast<SIZE_T>(std::min<std::uint64_t>(kRegionSize - offsetInRegion, kChunkSize));
                SIZE_T bytesRead = 0;
                const BOOL kReadOk = ::ReadProcessMemory(
                    processHandle,
                    reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(kRegionBase + offsetInRegion)),
                    chunkBuffer.data(),
                    kRemainSize,
                    &bytesRead);

                if (kReadOk == FALSE || bytesRead == 0)
                {
                    break;
                }

                outputFile.write(reinterpret_cast<const char*>(chunkBuffer.data()), static_cast<qint64>(bytesRead));
                dumpedBytes += static_cast<std::uint64_t>(bytesRead);
                offsetInRegion += static_cast<std::uint64_t>(bytesRead);
            }

            regionHeader.dumpedBytes = dumpedBytes;
            const qint64 kEndPosition = outputFile.pos();
            outputFile.seek(kHeaderPosition);
            outputFile.write(reinterpret_cast<const char*>(&regionHeader), static_cast<qint64>(sizeof(regionHeader)));
            outputFile.seek(kEndPosition);

            if (dumpedBytes > 0)
            {
                ++dumpedRegionCount;
            }
        }

        const std::uint64_t kTotalRange = kMaxAddress - kMinAddress;
        if (kTotalRange > 0)
        {
            const float kProgressValue = static_cast<float>(
                std::min<std::uint64_t>(
                    95,
                    ((kRegionBase - kMinAddress) * 95ULL) / kTotalRange));
            kPro.set(dumpMemoryProgressPid_, "读取并写入内存区域中", 0, kProgressValue);
        }

        const std::uint64_t kNextAddress = kRegionBase + kRegionSize;
        if (kNextAddress <= currentAddress)
        {
            break;
        }
        currentAddress = kNextAddress;
    }

    // Write the region count back to the file header.
    fileHeader.regionCount = dumpedRegionCount;
    outputFile.seek(0);
    outputFile.write(reinterpret_cast<const char*>(&fileHeader), static_cast<qint64>(sizeof(fileHeader)));
    outputFile.close();

    ::CloseHandle(processHandle);

    if (dumpedRegionCount == 0)
    {
        errorTextOut = "未读取到可导出的有效区域。";
        return false;
    }
    return true;
}

void MemoryDock::refreshMemoryRegionList(const bool forceRequery)
{
    // Region refresh entry log: records whether a forced re-query is performed.
    KLogEvent regionRefreshStartEvent;
    info << regionRefreshStartEvent
        << "[MemoryDock] refreshMemoryRegionList: 开始刷新区域, forceRequery="
        << (forceRequery ? "true" : "false")
        << ", attachedPid="
        << attachedPid_
        << eol;

    // The 'must be asynchronous' flag set by the attach process is valid only for this call; clear it immediately after reading.
    const bool kRequestedByAttach = readBoolProperty(this, kRegionRefreshFromAttachProperty);
    if (kRequestedByAttach)
    {
        setProperty(kRegionRefreshFromAttachProperty, false);
    }

    if (attachedProcessHandle_ == nullptr)
    {
        regionCache_.clear();
        regionTable_->setRowCount(0);
        return;
    }

    if (!forceRequery && !regionCache_.empty())
    {
        // If cache is available and no re-check is required, only re-apply the filter without traversing the address space.
        applyRegionFilterAndRebuildTable();

        // Region refresh completion log: Record cache count.
        KLogEvent regionCachedFinishEvent;
        info << regionCachedFinishEvent
            << "[MemoryDock] refreshMemoryRegionList: 刷新完成, regionCount="
            << regionCache_.size()
            << eol;
        return;
    }

    // When an enumeration is already in flight, register the pending request only once: region traversal takes hundreds of milliseconds, so repeated clicks must not stack tasks.
    if (readBoolProperty(this, kRegionRefreshInFlightProperty))
    {
        setProperty(kRegionRefreshPendingProperty, true);
        return;
    }

    // asyncAllowed: Re-checks during attach and when data already exists in the table are always asynchronous.
    // Synchronous mode is maintained only when the cache is empty and no in-flight tasks exist; otherwise, the caller on that path (page scanning range collection) reads
    // m_regionCache immediately after the call returns, and asynchronous execution would cause it to incorrectly determine that no regions are available for scanning.
    const bool kAsyncAllowed = kRequestedByAttach || !regionCache_.empty();
    std::uint32_t duplicateError = ERROR_SUCCESS;
    const std::shared_ptr<void> kProcessHandleLease =
        kAsyncAllowed ? duplicateAttachedProcessHandleForWorker(&duplicateError) : std::shared_ptr<void>();
    if (kProcessHandleLease)
    {
        setProperty(kRegionRefreshInFlightProperty, true);

        // Attachment context generation: old snapshots must not be written back to the new target after separation or re-attachment.
        const std::uint64_t kAttachmentGeneration = processAttachmentGeneration_.load();
        const QPointer<MemoryDock> kGuardedSelf(this);

        QRunnable* const kEnumerateRegionTask =
            QRunnable::create([kGuardedSelf, kProcessHandleLease, kAttachmentGeneration]() {
                // The worker thread only performs VirtualQueryEx / GetMappedFileNameW traversal to produce pure value-type rows.
                std::vector<RegionSnapshotRow> regionRows =
                    collectVirtualMemoryRegionRows(static_cast<HANDLE>(kProcessHandleLease.get()));

                QCoreApplication* const kAppInstance = QCoreApplication::instance();
                if (kAppInstance == nullptr)
                {
                    return;
                }

                QMetaObject::invokeMethod(
                    kAppInstance,
                    [kGuardedSelf, kAttachmentGeneration, regionRows = std::move(regionRows)]() mutable {
                        if (kGuardedSelf == nullptr)
                        {
                            return;
                        }
                        MemoryDock* const kResultDock = kGuardedSelf.data();

                        // Discard stale snapshots immediately when the attachment context changes (detached or re-attached). Note:
                        // do not clear the in-flight flags here. Those flags were already reset in detachProcess and reassigned to
                        // the new task; clearing them again would strip the deduplication protection from the new task.
                        if (kAttachmentGeneration != kResultDock->processAttachmentGeneration_.load())
                        {
                            return;
                        }

                        if (regionRows.empty())
                        {
                            kResultDock->setProperty(kRegionRefreshInFlightProperty, false);
                            kResultDock->setProperty(kRegionRefreshPendingProperty, false);
                            reportRegionEnumerateFailure(
                                kResultDock,
                                QStringLiteral("VirtualQueryEx 未返回有效区域。"));
                            return;
                        }

                        const auto kRegionRowsSnapshot =
                            std::make_shared<std::vector<RegionSnapshotRow>>(std::move(regionRows));
                        auto commitRegionSnapshot = [kGuardedSelf, kAttachmentGeneration, kRegionRowsSnapshot]() {
                            if (kGuardedSelf == nullptr)
                            {
                                return;
                            }
                            MemoryDock* const kCommitDock = kGuardedSelf.data();
                            if (kAttachmentGeneration != kCommitDock->processAttachmentGeneration_.load())
                            {
                                return;
                            }

                            // Replace cache and table atomically to avoid the filtering action reading partial cache.
                            kCommitDock->regionCache_.clear();
                            kCommitDock->regionCache_.reserve(kRegionRowsSnapshot->size());
                            for (const RegionSnapshotRow& regionRow : *kRegionRowsSnapshot)
                            {
                                RegionEntry entry{};
                                entry.baseAddress = regionRow.baseAddress;
                                entry.regionSize = regionRow.regionSize;
                                entry.protect = regionRow.protect;
                                entry.state = regionRow.state;
                                entry.type = regionRow.type;
                                entry.mappedFilePath = regionRow.mappedFilePath;
                                kCommitDock->regionCache_.push_back(std::move(entry));
                            }
                            kCommitDock->applyRegionFilterAndRebuildTable();

                            // Region refresh completion log: Record cache count.
                            KLogEvent regionRefreshFinishEvent;
                            info << regionRefreshFinishEvent
                                << "[MemoryDock] refreshMemoryRegionList: 刷新完成, regionCount="
                                << kCommitDock->regionCache_.size()
                                << eol;

                            // Release the in-flight flag only at the commit stage: when the right-click menu opens, the current commit is deferred;
                            // during this period, new tasks must remain blocked, otherwise the old commit will overwrite the updated result.
                            kCommitDock->setProperty(kRegionRefreshInFlightProperty, false);

                            // Merge-down pending requests are retried after this round completes to prevent results from lagging behind user operations.
                            if (kCommitDock->property(kRegionRefreshPendingProperty).toBool())
                            {
                                kCommitDock->setProperty(kRegionRefreshPendingProperty, false);
                                kCommitDock->refreshMemoryRegionList(true);
                            }
                        };

                        // Cache the current commit when the right-click menu is open to avoid replacing the entire table of rows the user is currently operating on.
                        if (ks::ui::deferItemViewUiCommitIfContextMenuOpen(
                                kResultDock,
                                QStringLiteral("memory-region-list-snapshot-apply"),
                                {kResultDock->regionTable_},
                                commitRegionSnapshot))
                        {
                            return;
                        }
                        commitRegionSnapshot();
                    },
                    Qt::QueuedConnection);
                });
        kEnumerateRegionTask->setAutoDelete(true);
        QThreadPool::globalInstance()->start(kEnumerateRegionTask);
        return;
    }

    // Fallback synchronization: The caller must immediately obtain the region cache, or handle copying failed (normally unreachable).
    QString errorText;
    std::vector<RegionEntry> regionList;
    if (!enumerateMemoryRegionsByVirtualQuery(attachedProcessHandle_, regionList, &errorText))
    {
        reportRegionEnumerateFailure(this, errorText);
        return;
    }
    regionCache_ = std::move(regionList);

    applyRegionFilterAndRebuildTable();

    // Region refresh completion log: Record cache count.
    KLogEvent regionRefreshFinishEvent;
    info << regionRefreshFinishEvent
        << "[MemoryDock] refreshMemoryRegionList: 刷新完成, regionCount="
        << regionCache_.size()
        << eol;
}

bool MemoryDock::enumerateMemoryRegionsByVirtualQuery(
    HANDLE processHandle,
    std::vector<RegionEntry>& regionsOut,
    QString* const errorTextOut) const
{
    // VirtualQueryEx enumeration entry log: output handle validity explanation.
    KLogEvent enumerateRegionStartEvent;
    dbg << enumerateRegionStartEvent
        << "[MemoryDock] enumerateMemoryRegionsByVirtualQuery: 开始遍历虚拟内存区域。"
        << eol;

    regionsOut.clear();

    // Actual traversal sinks into a Qt-independent collection function: the same logic serves both the synchronous fallback here
    // and the thread pool task submitted by refreshMemoryRegionList, preventing two implementations from diverging over time.
    const std::vector<RegionSnapshotRow> kRegionRows = collectVirtualMemoryRegionRows(processHandle);
    regionsOut.reserve(kRegionRows.size());
    for (const RegionSnapshotRow& regionRow : kRegionRows)
    {
        RegionEntry entry{};
        entry.baseAddress = regionRow.baseAddress;
        entry.regionSize = regionRow.regionSize;
        entry.protect = regionRow.protect;
        entry.state = regionRow.state;
        entry.type = regionRow.type;
        entry.mappedFilePath = regionRow.mappedFilePath;
        regionsOut.push_back(std::move(entry));
    }

    if (regionsOut.empty())
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = "VirtualQueryEx 未返回有效区域。";
        }
        KLogEvent enumerateRegionEmptyEvent;
        warn << enumerateRegionEmptyEvent
            << "[MemoryDock] enumerateMemoryRegionsByVirtualQuery: 枚举结果为空。"
            << eol;
        return false;
    }

    // Enumeration completion log: used to measure the complexity of the target process address space.
    KLogEvent enumerateRegionFinishEvent;
    dbg << enumerateRegionFinishEvent
        << "[MemoryDock] enumerateMemoryRegionsByVirtualQuery: 完成, count="
        << regionsOut.size()
        << eol;
    return true;
}

void MemoryDock::applyRegionFilterAndRebuildTable()
{
    // Filter entry log: Record the current cache size and filter switch status.
    KLogEvent regionFilterStartEvent;
    dbg << regionFilterStartEvent
        << "[MemoryDock] applyRegionFilterAndRebuildTable: 开始过滤, cacheSize="
        << regionCache_.size()
        << ", committedOnly="
        << (regionCommittedOnlyCheck_->isChecked() ? "true" : "false")
        << ", imageOnly="
        << (regionImageOnlyCheck_->isChecked() ? "true" : "false")
        << ", readableOnly="
        << (regionReadableOnlyCheck_->isChecked() ? "true" : "false")
        << eol;

    // Keyword filtering: leaving it empty means no filtering; a match covers base address text, protection attributes, and mapped file paths.
    const QString kFilterKeyword = (regionFilterEdit_ != nullptr)
        ? regionFilterEdit_->text().trimmed()
        : QString();

    // Filter condition combination: committed / IMAGE / readable / keyword.
    std::vector<const RegionEntry*> filteredRegions;
    filteredRegions.reserve(regionCache_.size());
    for (const RegionEntry& entry : regionCache_)
    {
        if (regionCommittedOnlyCheck_->isChecked() && entry.state != MEM_COMMIT)
        {
            continue;
        }
        if (regionImageOnlyCheck_->isChecked() && entry.type != MEM_IMAGE)
        {
            continue;
        }
        if (regionReadableOnlyCheck_->isChecked() && !isReadableProtect(entry.protect))
        {
            continue;
        }
        if (!kFilterKeyword.isEmpty())
        {
            const bool kKeywordMatched =
                formatAddress(entry.baseAddress).contains(kFilterKeyword, Qt::CaseInsensitive)
                || protectToText(entry.protect).contains(kFilterKeyword, Qt::CaseInsensitive)
                || entry.mappedFilePath.contains(kFilterKeyword, Qt::CaseInsensitive);
            if (!kKeywordMatched)
            {
                continue;
            }
        }
        filteredRegions.push_back(&entry);
    }

    regionTable_->setSortingEnabled(false);
    regionTable_->setRowCount(static_cast<int>(filteredRegions.size()));
    for (int row = 0; row < static_cast<int>(filteredRegions.size()); ++row)
    {
        const RegionEntry& entry = *filteredRegions[static_cast<std::size_t>(row)];
        // Columns 0 and 1 include the original UserRole values to enable reliable reverse lookup during right-click actions.
        //
        // Originally, setData(Qt::EditRole, raw_value) was used here: QTableWidgetItem::setData internally rewrites EditRole to
        // DisplayRole, causing the "0x00007FF6.../4.00 MB" strings generated by formatAddress()/formatSize() to be immediately
        // overwritten by raw decimal numbers. A kernel analysis tool's memory region table would then fail to display hexadecimal
        // addresses. Sorting is now handled by NumericSortRole, so the display text is no longer passively overwritten.
        QTableWidgetItem* baseItem = new ks::ui::NumericTableItem(
            formatAddress(entry.baseAddress),
            static_cast<qulonglong>(entry.baseAddress));
        baseItem->setData(Qt::UserRole, QVariant::fromValue<qulonglong>(static_cast<qulonglong>(entry.baseAddress)));
        regionTable_->setItem(row, 0, baseItem);

        QTableWidgetItem* sizeItem = new ks::ui::NumericTableItem(
            formatSize(entry.regionSize),
            static_cast<qulonglong>(entry.regionSize));
        sizeItem->setData(Qt::UserRole, QVariant::fromValue<qulonglong>(static_cast<qulonglong>(entry.regionSize)));
        regionTable_->setItem(row, 1, sizeItem);

        regionTable_->setItem(row, 2, new QTableWidgetItem(protectToText(entry.protect)));
        regionTable_->setItem(row, 3, new QTableWidgetItem(stateToText(entry.state)));
        regionTable_->setItem(row, 4, new QTableWidgetItem(typeToText(entry.type)));
        regionTable_->setItem(row, 5, new QTableWidgetItem(entry.mappedFilePath));
    }
    regionTable_->setSortingEnabled(true);

    // The status label explicitly states 'displayed / total' to prevent users from mistaking filtered results for all regions.
    if (regionStatusLabel_ != nullptr)
    {
        if (attachedPid_ == 0U)
        {
            regionStatusLabel_->setText("未附加进程。");
        }
        else
        {
            regionStatusLabel_->setText(
                QString("显示 %1 / 共 %2 个区域")
                    .arg(filteredRegions.size())
                    .arg(regionCache_.size()));
        }
    }

    // Filter completion log: record the final displayed entry count.
    KLogEvent regionFilterFinishEvent;
    info << regionFilterFinishEvent
        << "[MemoryDock] applyRegionFilterAndRebuildTable: 完成, visibleCount="
        << filteredRegions.size()
        << eol;
}
