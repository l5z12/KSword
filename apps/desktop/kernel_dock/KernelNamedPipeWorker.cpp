#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "KernelNamedPipeWorker.h"
#include "KernelDock.h"

// ============================================================
// KernelNamedPipeWorker.cpp
// Purpose:
// 1) enumerate NPFS Named Pipe directories using NtOpenFile + NtQueryDirectoryFile;
// 2) Retain path candidates and failure status to facilitate UI display of compatibility differences;
// 3) Explicitly avoids enumerating system handle tables and does not enumerate any process handles.
// ============================================================

#include <QDateTime>
#include <QStringList>
#include <QTimeZone>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <set>
#include <vector>

using ksword::kernel_dock_internal::kernelText;

#include <Windows.h>
#include <Winternl.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef FILE_LIST_DIRECTORY
#define FILE_LIST_DIRECTORY 0x0001
#endif

namespace
{
    constexpr NTSTATUS kStatusNoMoreFiles = static_cast<NTSTATUS>(0x80000006L);
    constexpr NTSTATUS kStatusInfoLengthMismatch = static_cast<NTSTATUS>(0xC0000004L);
    constexpr NTSTATUS kStatusBufferOverflow = static_cast<NTSTATUS>(0x80000005L);
    constexpr NTSTATUS kStatusBufferTooSmall = static_cast<NTSTATUS>(0xC0000023L);
    constexpr ULONG kFileDirectoryInformationClass = 1U;
    constexpr ULONG kInitialDirectoryBufferBytes = 64U * 1024U;
    constexpr ULONG kMaximumDirectoryBufferBytes = 1024U * 1024U;
    constexpr std::size_t kMaximumPipeRowsPerDirectory = 65536U;

    using NtOpenFileFn = NTSTATUS(NTAPI*)(
        PHANDLE fileHandle,
        ACCESS_MASK desiredAccess,
        POBJECT_ATTRIBUTES objectAttributes,
        PIO_STATUS_BLOCK ioStatusBlock,
        ULONG shareAccess,
        ULONG openOptions);

    using NtQueryDirectoryFileFn = NTSTATUS(NTAPI*)(
        HANDLE fileHandle,
        HANDLE event,
        PVOID apcRoutine,
        PVOID apcContext,
        PIO_STATUS_BLOCK ioStatusBlock,
        PVOID fileInformation,
        ULONG length,
        ULONG fileInformationClass,
        BOOLEAN returnSingleEntry,
        PUNICODE_STRING fileName,
        BOOLEAN restartScan);

    struct NtFileDirectoryApi
    {
        HMODULE ntdllModule = nullptr;
        NtOpenFileFn openFile = nullptr;
        NtQueryDirectoryFileFn queryDirectoryFile = nullptr;
    };

    struct ScopedHandle
    {
        HANDLE handle = nullptr;

        ~ScopedHandle()
        {
            if (handle != nullptr && handle != INVALID_HANDLE_VALUE)
            {
                ::CloseHandle(handle);
                handle = nullptr;
            }
        }

        ScopedHandle() = default;
        ScopedHandle(const ScopedHandle&) = delete;
        ScopedHandle& operator=(const ScopedHandle&) = delete;
    };

    struct KsFileDirectoryInformation
    {
        ULONG nextEntryOffset;
        ULONG fileIndex;
        LARGE_INTEGER creationTime;
        LARGE_INTEGER lastAccessTime;
        LARGE_INTEGER lastWriteTime;
        LARGE_INTEGER changeTime;
        LARGE_INTEGER endOfFile;
        LARGE_INTEGER allocationSize;
        ULONG fileAttributes;
        ULONG fileNameLength;
        WCHAR fileName[1];
    };

    // isNeedGrowBufferStatus：
    // - Input status: NTSTATUS returned by NtQueryDirectoryFile;
    // - Processing logic: Identify status indicating current directory enumeration buffer is insufficient or records are truncated.
    // - Return value: true indicates the caller should enlarge the buffer and retry the current scan batch.
    bool isNeedGrowBufferStatus(const NTSTATUS status)
    {
        return status == kStatusInfoLengthMismatch
            || status == kStatusBufferOverflow
            || status == kStatusBufferTooSmall;
    }

    // initializeUnicodeString：
    // - Input unicodeTextOut: UNICODE_STRING to be filled; sourceText: wide string whose lifetime is maintained by the caller;
    // - Handling: Fill Buffer/Length/MaximumLength per NT API requirements and prevent USHORT length overflow.
    // - Return value: None; unicodeTextOut points to the internal buffer of sourceText.
    void initializeUnicodeString(UNICODE_STRING& unicodeTextOut, const std::wstring& sourceText)
    {
        unicodeTextOut.Buffer = const_cast<PWSTR>(sourceText.c_str());
        unicodeTextOut.Length = static_cast<USHORT>(
            std::min<std::size_t>(
                sourceText.size() * sizeof(wchar_t),
                static_cast<std::size_t>(std::numeric_limits<USHORT>::max() - sizeof(wchar_t))));
        unicodeTextOut.MaximumLength = static_cast<USHORT>(
            std::min<std::size_t>(
                unicodeTextOut.Length + sizeof(wchar_t),
                static_cast<std::size_t>(std::numeric_limits<USHORT>::max())));
    }

    // ntStatusToText：
    // - Input ntdllModule: Handle to the ntdll module for FormatMessageW; status: NTSTATUS to be formatted.
    // - Handling logic: Prefer outputting the hexadecimal status code, then attempt to append system text from the ntdll message table.
    // - Returns a status string suitable for UI display; if the message table is missing, returns only the hexadecimal value.
    QString ntStatusToText(const HMODULE ntdllModule, const NTSTATUS status)
    {
        const QString kHexText = QStringLiteral("0x%1")
            .arg(static_cast<std::uint32_t>(status), 8, 16, QChar('0'))
            .toUpper();

        std::array<wchar_t, 256> messageBuffer{};
        const DWORD kMessageLength = ::FormatMessageW(
            FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK,
            ntdllModule,
            static_cast<DWORD>(status),
            0,
            messageBuffer.data(),
            static_cast<DWORD>(messageBuffer.size()),
            nullptr);
        if (kMessageLength == 0)
        {
            return kHexText;
        }

        return QStringLiteral("%1 %2")
            .arg(kHexText, QString::fromWCharArray(messageBuffer.data()).trimmed());
    }

    // fileTimeToText：
    // - Input fileTime: 100ns Windows timestamp from FILE_DIRECTORY_INFORMATION.
    // - Handling logic: convert valid FILETIME to a local time zone string; retain diagnostic text for unavailable or invalid values.
    // - Return value: formatted time text, or <Unavailable>/<Invalid:...>.
    QString fileTimeToText(const LARGE_INTEGER& fileTime)
    {
        if (fileTime.QuadPart <= 0)
        {
            return QStringLiteral("<Unavailable>");
        }

        constexpr std::int64_t kWindowsToUnix100Ns = 116444736000000000LL;
        const std::int64_t kUnixMilliseconds = (fileTime.QuadPart - kWindowsToUnix100Ns) / 10000LL;
        if (kUnixMilliseconds <= 0)
        {
            return QStringLiteral("<Invalid:%1>").arg(static_cast<qlonglong>(fileTime.QuadPart));
        }

        return QDateTime::fromMSecsSinceEpoch(kUnixMilliseconds, QTimeZone::UTC)
            .toLocalTime()
            .toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"));
    }

    // attributesToText：
    // - Input attributes: FILE_DIRECTORY_INFORMATION.FileAttributes bitmap;
    // - Handling: Decompose common FILE_ATTRIBUTE_* flags and retain the original hexadecimal value;
    // - Return: UI display text for the result, e.g., 0x00000010 (DIRECTORY).
    QString attributesToText(const ULONG attributes)
    {
        QStringList parts;
        if ((attributes & FILE_ATTRIBUTE_READONLY) != 0U) parts << QStringLiteral("READONLY");
        if ((attributes & FILE_ATTRIBUTE_HIDDEN) != 0U) parts << QStringLiteral("HIDDEN");
        if ((attributes & FILE_ATTRIBUTE_SYSTEM) != 0U) parts << QStringLiteral("SYSTEM");
        if ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0U) parts << QStringLiteral("DIRECTORY");
        if ((attributes & FILE_ATTRIBUTE_ARCHIVE) != 0U) parts << QStringLiteral("ARCHIVE");
        if ((attributes & FILE_ATTRIBUTE_NORMAL) != 0U) parts << QStringLiteral("NORMAL");
        if ((attributes & FILE_ATTRIBUTE_TEMPORARY) != 0U) parts << QStringLiteral("TEMPORARY");
        if (parts.isEmpty())
        {
            parts << QStringLiteral("0");
        }

        return QStringLiteral("0x%1 (%2)")
            .arg(static_cast<std::uint32_t>(attributes), 8, 16, QChar('0'))
            .arg(parts.join(QStringLiteral("|")))
            .toUpper();
    }

    // joinPipeNtPath：
    // - Input directoryPath: a successfully enumerated candidate directory; pipeName: the pipe name returned by NPFS;
    // - Handling logic: normalizes directory separators and avoids redundant trailing backslashes.
    // - Return value: complete NT-style path, e.g., \Device\NamedPipe\InitShutdown.
    QString joinPipeNtPath(const QString& directoryPath, const QString& pipeName)
    {
        QString normalizedDirectory = directoryPath.trimmed();
        normalizedDirectory.replace('/', '\\');
        while (normalizedDirectory.endsWith('\\') && normalizedDirectory.size() > 1)
        {
            normalizedDirectory.chop(1);
        }
        return QStringLiteral("%1\\%2").arg(normalizedDirectory, pipeName);
    }

    // buildNamedPipeDirectoryCandidates：
    // - Inputs: None;
    // - Handling logic: retain multiple equivalent or compatible paths, prioritizing the native \Device\NamedPipe.
    // - Returns the result: NPFS named pipe directory candidates sorted by attempt order.
    std::vector<QString> buildNamedPipeDirectoryCandidates()
    {
        std::vector<QString> candidates;
        candidates.push_back(QStringLiteral("\\Device\\NamedPipe"));
        candidates.push_back(QStringLiteral("\\Device\\NamedPipe\\"));
        candidates.push_back(QStringLiteral("\\??\\PIPE"));
        candidates.push_back(QStringLiteral("\\??\\PIPE\\"));
        return candidates;
    }

    // loadNtFileDirectoryApi：
    // - Input apiOut: receives the ntdll module and function pointers; errorTextOut: receives the failure reason;
    // - Handling: Dynamically resolve NtOpenFile/NtQueryDirectoryFile to avoid adding new static linking dependencies;
    // - Return result: true indicates both entry points are available; false indicates the worker should stop enumeration.
    bool loadNtFileDirectoryApi(NtFileDirectoryApi& apiOut, QString& errorTextOut)
    {
        errorTextOut.clear();
        apiOut.ntdllModule = ::GetModuleHandleW(L"ntdll.dll");
        if (apiOut.ntdllModule == nullptr)
        {
            apiOut.ntdllModule = ::LoadLibraryW(L"ntdll.dll");
        }
        if (apiOut.ntdllModule == nullptr)
        {
            errorTextOut = kernelText("kernel.named_pipe.worker.load_ntdll_failed", QStringLiteral("加载 ntdll.dll 失败。"));
            return false;
        }

        apiOut.openFile = reinterpret_cast<NtOpenFileFn>(
            ::GetProcAddress(apiOut.ntdllModule, "NtOpenFile"));
        apiOut.queryDirectoryFile = reinterpret_cast<NtQueryDirectoryFileFn>(
            ::GetProcAddress(apiOut.ntdllModule, "NtQueryDirectoryFile"));
        if (apiOut.openFile == nullptr || apiOut.queryDirectoryFile == nullptr)
        {
            errorTextOut = kernelText("kernel.named_pipe.worker.resolve_api_failed", QStringLiteral("解析 NtOpenFile/NtQueryDirectoryFile 失败。"));
            return false;
        }
        return true;
    }

    // openNamedPipeDirectory：
    // - Input api: parsed NT file API; directoryPath: NT path to be opened;
    // - Handling logic: Open the NPFS directory with FILE_LIST_DIRECTORY | SYNCHRONIZE, requiring a directory object and synchronous I/O;
    // - Return result: The original NTSTATUS from NtOpenFile, with the handle and I/O status returned via handleOut/ioStatusOut.
    NTSTATUS openNamedPipeDirectory(
        const NtFileDirectoryApi& api,
        const QString& directoryPath,
        HANDLE& handleOut,
        IO_STATUS_BLOCK& ioStatusOut)
    {
        handleOut = nullptr;
        ioStatusOut = IO_STATUS_BLOCK{};

        const std::wstring kPathWide = directoryPath.trimmed().toStdWString();
        UNICODE_STRING objectName{};
        initializeUnicodeString(objectName, kPathWide);

        OBJECT_ATTRIBUTES objectAttributes{};
        InitializeObjectAttributes(&objectAttributes, &objectName, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

        return api.openFile(
            &handleOut,
            FILE_LIST_DIRECTORY | SYNCHRONIZE,
            &objectAttributes,
            &ioStatusOut,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT);
    }

    // parseDirectoryBuffer：
    // - Input buffer/validBytes: The batch of FILE_DIRECTORY_INFORMATION returned by NtQueryDirectoryFile.
    // - Processing logic: validates NextEntryOffset/FileNameLength boundaries item by item and converts to KernelNamedPipeEntry.
    // - Return result: true indicates batch parsing completed; false indicates errorTextOut contains boundary or format errors.
    bool parseDirectoryBuffer(
        const NtFileDirectoryApi& api,
        const QString& directoryPath,
        const std::vector<std::uint8_t>& buffer,
        const ULONG validBytes,
        const NTSTATUS batchStatus,
        std::vector<KernelNamedPipeEntry>& rowsOut,
        QString& errorTextOut)
    {
        errorTextOut.clear();
        if (validBytes < sizeof(KsFileDirectoryInformation))
        {
            errorTextOut = kernelText("kernel.named_pipe.worker.buffer_too_small", QStringLiteral("NtQueryDirectoryFile 返回缓冲区过小。"));
            return false;
        }

        std::size_t offset = 0;
        std::size_t guardCount = 0;
        while (offset + sizeof(KsFileDirectoryInformation) <= validBytes)
        {
            if (++guardCount > kMaximumPipeRowsPerDirectory)
            {
                errorTextOut = kernelText("kernel.named_pipe.worker.row_limit", QStringLiteral("目录项数量超过保护上限。"));
                return false;
            }

            const auto* info = reinterpret_cast<const KsFileDirectoryInformation*>(buffer.data() + offset);
            const std::size_t kFileNameBytes = static_cast<std::size_t>(info->fileNameLength);
            const std::size_t kRecordMinimumBytes = offsetof(KsFileDirectoryInformation, fileName) + kFileNameBytes;
            if (offset + kRecordMinimumBytes > validBytes)
            {
                errorTextOut = kernelText("kernel.named_pipe.worker.filename_out_of_bounds", QStringLiteral("目录项文件名越过返回缓冲区。"));
                return false;
            }

            const QString kPipeName = QString::fromWCharArray(
                info->fileName,
                static_cast<int>(kFileNameBytes / sizeof(wchar_t))).trimmed();
            if (!kPipeName.isEmpty() && kPipeName != QStringLiteral(".") && kPipeName != QStringLiteral(".."))
            {
                KernelNamedPipeEntry row;
                row.pipeName = kPipeName;
                row.ntPath = joinPipeNtPath(directoryPath, kPipeName);
                row.sourceDirectory = directoryPath;
                row.statusText = ntStatusToText(api.ntdllModule, batchStatus);
                row.querySucceeded = true;
                row.attributes = static_cast<std::uint32_t>(info->fileAttributes);
                row.attributesText = attributesToText(info->fileAttributes);
                row.lastWriteTime = static_cast<std::int64_t>(info->lastWriteTime.QuadPart);
                row.lastWriteTimeText = fileTimeToText(info->lastWriteTime);
                rowsOut.push_back(std::move(row));
            }

            if (info->nextEntryOffset == 0)
            {
                break;
            }
            offset += info->nextEntryOffset;
        }

        return true;
    }

    // enumerateNamedPipeDirectory：
    // - Input api: Parsed NT API; directoryPath: A candidate NPFS directory;
    // - Handling logic: After opening the directory, loop NtQueryDirectoryFile to handle STATUS_NO_MORE_FILES, buffer insufficient, and permission failures;
    // - Return: true indicates the directory was fully enumerated or reached the protection limit; rowsOut contains successfully parsed entries.
    bool enumerateNamedPipeDirectory(
        const NtFileDirectoryApi& api,
        const QString& directoryPath,
        KernelNamedPipeDirectoryStatus& directoryStatusOut,
        std::vector<KernelNamedPipeEntry>& rowsOut)
    {
        directoryStatusOut = KernelNamedPipeDirectoryStatus{};
        directoryStatusOut.candidatePath = directoryPath;

        IO_STATUS_BLOCK openIoStatus{};
        ScopedHandle directoryHandle;
        const NTSTATUS kOpenStatus = openNamedPipeDirectory(
            api,
            directoryPath,
            directoryHandle.handle,
            openIoStatus);
        directoryStatusOut.lastStatus = static_cast<std::uint32_t>(kOpenStatus);
        directoryStatusOut.statusText = ntStatusToText(api.ntdllModule, kOpenStatus);
        if (!NT_SUCCESS(kOpenStatus))
        {
            directoryStatusOut.openSucceeded = false;
            return false;
        }
        directoryStatusOut.openSucceeded = true;

        ULONG bufferSize = kInitialDirectoryBufferBytes;
        BOOLEAN restartScan = TRUE;
        std::size_t emittedRows = 0;

        for (;;)
        {
            std::vector<std::uint8_t> buffer(bufferSize, 0);
            IO_STATUS_BLOCK queryIoStatus{};
            const NTSTATUS kQueryStatus = api.queryDirectoryFile(
                directoryHandle.handle,
                nullptr,
                nullptr,
                nullptr,
                &queryIoStatus,
                buffer.data(),
                bufferSize,
                kFileDirectoryInformationClass,
                FALSE,
                nullptr,
                restartScan);
            restartScan = FALSE;

            directoryStatusOut.lastStatus = static_cast<std::uint32_t>(kQueryStatus);
            directoryStatusOut.statusText = ntStatusToText(api.ntdllModule, kQueryStatus);

            if (kQueryStatus == kStatusNoMoreFiles)
            {
                directoryStatusOut.querySucceeded = true;
                directoryStatusOut.statusText = kernelText("kernel.named_pipe.worker.directory_completed", QStringLiteral("%1 (枚举完成)"))
                    .arg(ntStatusToText(api.ntdllModule, kQueryStatus));
                directoryStatusOut.returnedRows = emittedRows;
                return true;
            }

            if (isNeedGrowBufferStatus(kQueryStatus))
            {
                if (bufferSize >= kMaximumDirectoryBufferBytes)
                {
                    directoryStatusOut.querySucceeded = false;
                    directoryStatusOut.statusText = kernelText("kernel.named_pipe.worker.buffer_limit", QStringLiteral("%1 (缓冲区已达上限)"))
                        .arg(ntStatusToText(api.ntdllModule, kQueryStatus));
                    directoryStatusOut.returnedRows = emittedRows;
                    return false;
                }
                bufferSize = std::min<ULONG>(bufferSize * 2U, kMaximumDirectoryBufferBytes);
                continue;
            }

            if (!NT_SUCCESS(kQueryStatus))
            {
                directoryStatusOut.querySucceeded = false;
                directoryStatusOut.returnedRows = emittedRows;
                return false;
            }

            const ULONG kValidBytes = static_cast<ULONG>(
                std::min<ULONG_PTR>(
                    static_cast<ULONG_PTR>(queryIoStatus.Information),
                    static_cast<ULONG_PTR>(buffer.size())));
            QString parseErrorText;
            const std::size_t kBeforeRows = rowsOut.size();
            if (!parseDirectoryBuffer(api, directoryPath, buffer, kValidBytes, kQueryStatus, rowsOut, parseErrorText))
            {
                directoryStatusOut.querySucceeded = false;
                directoryStatusOut.statusText = parseErrorText;
                directoryStatusOut.returnedRows = emittedRows;
                return false;
            }

            emittedRows += rowsOut.size() - kBeforeRows;
            if (emittedRows >= kMaximumPipeRowsPerDirectory)
            {
                directoryStatusOut.querySucceeded = true;
                directoryStatusOut.statusText = kernelText("kernel.named_pipe.worker.directory_row_limit", QStringLiteral("达到单目录保护上限，结果已截断。"));
                directoryStatusOut.returnedRows = emittedRows;
                return true;
            }
        }
    }

    // deduplicateAndSortRows：
    // - Input rows: Original rows returned by multiple candidate directories;
    // - Logic: Case-insensitive deduplication by NT path, followed by sorting by pipeName/ntPath.
    // - Return value: None. The rows vector is replaced with the deduplicated and sorted result.
    void deduplicateAndSortRows(std::vector<KernelNamedPipeEntry>& rows)
    {
        std::set<QString> seenPathSet;
        std::vector<KernelNamedPipeEntry> uniqueRows;
        uniqueRows.reserve(rows.size());

        for (const KernelNamedPipeEntry& row : rows)
        {
            const QString kKey = row.ntPath.toCaseFolded();
            if (seenPathSet.find(kKey) != seenPathSet.end())
            {
                continue;
            }
            seenPathSet.insert(kKey);
            uniqueRows.push_back(row);
        }

        std::sort(
            uniqueRows.begin(),
            uniqueRows.end(),
            [](const KernelNamedPipeEntry& left, const KernelNamedPipeEntry& right)
            {
                const int kNameCompare = QString::compare(left.pipeName, right.pipeName, Qt::CaseInsensitive);
                if (kNameCompare != 0)
                {
                    return kNameCompare < 0;
                }
                return QString::compare(left.ntPath, right.ntPath, Qt::CaseInsensitive) < 0;
            });

        rows.swap(uniqueRows);
    }
}

KernelNamedPipeSnapshot runKernelNamedPipeSnapshotTask()
{
    const auto kBeginTime = std::chrono::steady_clock::now();

    KernelNamedPipeSnapshot snapshot;
    NtFileDirectoryApi api;
    if (!loadNtFileDirectoryApi(api, snapshot.errorText))
    {
        snapshot.taskSucceeded = false;
        snapshot.summaryText = snapshot.errorText;
        snapshot.elapsedMs = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - kBeginTime).count());
        return snapshot;
    }

    std::vector<KernelNamedPipeEntry> collectedRows;
    const std::vector<QString> kCandidates = buildNamedPipeDirectoryCandidates();
    for (const QString& candidatePath : kCandidates)
    {
        KernelNamedPipeDirectoryStatus directoryStatus;
        const bool kQueryOk = enumerateNamedPipeDirectory(api, candidatePath, directoryStatus, collectedRows);
        snapshot.anyQuerySucceeded = snapshot.anyQuerySucceeded || kQueryOk;
        snapshot.directories.push_back(directoryStatus);
    }

    deduplicateAndSortRows(collectedRows);
    snapshot.rows = std::move(collectedRows);
    snapshot.taskSucceeded = true;
    snapshot.elapsedMs = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - kBeginTime).count());
    snapshot.summaryText = kernelText("kernel.named_pipe.worker.summary", QStringLiteral("候选路径:%1 | 成功路径:%2 | 管道:%3 | %4 ms"))
        .arg(static_cast<qulonglong>(snapshot.directories.size()))
        .arg(static_cast<qulonglong>(std::count_if(
            snapshot.directories.begin(),
            snapshot.directories.end(),
            [](const KernelNamedPipeDirectoryStatus& status) { return status.querySucceeded; })))
        .arg(static_cast<qulonglong>(snapshot.rows.size()))
        .arg(static_cast<qulonglong>(snapshot.elapsedMs));
    if (!snapshot.anyQuerySucceeded)
    {
        snapshot.errorText = kernelText("kernel.named_pipe.worker.all_candidates_failed", QStringLiteral("所有 Named Pipe 候选目录均未成功枚举，请查看详情面板中的 NTSTATUS。"));
    }
    return snapshot;
}
