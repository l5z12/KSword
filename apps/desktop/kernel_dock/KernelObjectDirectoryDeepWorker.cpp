
#include "KernelObjectDirectoryDeepWorker.h"
#include "KernelDock.h"

// ============================================================
// KernelObjectDirectoryDeepWorker.cpp
// Purpose:
// 1) Dynamically resolve Object Manager Directory query APIs in ntdll;
// 2) Recursively enumerate Directory objects from the specified root directory.
// 3) Enforces hard limits on depth, single-directory entry count, and total entry count to prevent hangs.
// ============================================================

#include "../Framework.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <queue>
#include <string>
#include <vector>

using ksword::kernel_dock_internal::kernelText;

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <Winternl.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef DIRECTORY_QUERY
#define DIRECTORY_QUERY 0x0001
#endif
#ifndef DIRECTORY_TRAVERSE
#define DIRECTORY_TRAVERSE 0x0002
#endif

namespace
{
    constexpr NTSTATUS kStatusSuccess = static_cast<NTSTATUS>(0x00000000L);
    constexpr NTSTATUS kStatusUnsuccessful = static_cast<NTSTATUS>(0xC0000001L);
    constexpr NTSTATUS kStatusInfoLengthMismatch = static_cast<NTSTATUS>(0xC0000004L);
    constexpr NTSTATUS kStatusBufferOverflow = static_cast<NTSTATUS>(0x80000005L);
    constexpr NTSTATUS kStatusBufferTooSmall = static_cast<NTSTATUS>(0xC0000023L);
    constexpr NTSTATUS kStatusNoMoreEntries = static_cast<NTSTATUS>(0x8000001AL);

    constexpr ACCESS_MASK kDirectoryQueryAccess = DIRECTORY_QUERY | DIRECTORY_TRAVERSE;
    constexpr ULONG kInitialDirectoryQueryBuffer = 16 * 1024U;
    constexpr int kDefaultMaxDepth = 4;
    constexpr int kHardMaxDepth = 32;
    constexpr std::size_t kDefaultMaxEntriesPerDirectory = 4096;
    constexpr std::size_t kHardMaxEntriesPerDirectory = 65536;
    constexpr std::size_t kDefaultMaxTotalEntries = 50000;
    constexpr std::size_t kHardMaxTotalEntries = 500000;

    using NtOpenDirectoryObjectFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
    using NtQueryDirectoryObjectFn = NTSTATUS(NTAPI*)(HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG);

    // NtDirectoryDeepApi：
    // - Purpose: Cache entries for NtOpenDirectoryObject / NtQueryDirectoryObject.
    struct NtDirectoryDeepApi
    {
        HMODULE ntdllModule = nullptr;
        NtOpenDirectoryObjectFn openDirectoryObject = nullptr;
        NtQueryDirectoryObjectFn queryDirectoryObject = nullptr;
    };

    // ScopedNtHandle：
    // - Purpose: Manage the HANDLE returned by NtOpenDirectoryObject.
    // - Return behavior: automatically calls CloseHandle during destruction; no explicit return value.
    struct ScopedNtHandle
    {
        HANDLE handle = nullptr;

        ScopedNtHandle() = default;
        ScopedNtHandle(const ScopedNtHandle&) = delete;
        ScopedNtHandle& operator=(const ScopedNtHandle&) = delete;

        ~ScopedNtHandle()
        {
            if (handle != nullptr)
            {
                ::CloseHandle(handle);
                handle = nullptr;
            }
        }
    };

    // ObjectDirectoryInformation：
    // - Purpose: Describe a directory entry returned by NtQueryDirectoryObject.
    // - Field: Name is the object name, TypeName is the object type name.
    struct ObjectDirectoryInformation
    {
        UNICODE_STRING name;
        UNICODE_STRING typeName;
    };

    // DirectoryChildRecord：
    // - Purpose: Stores child object records obtained from a single directory query for use in recursive dispatching.
    struct DirectoryChildRecord
    {
        QString objectName;
        QString objectType;
    };

    // PendingDirectory：
    // - Purpose: BFS queue element representing a Directory object waiting to be enumerated.
    struct PendingDirectory
    {
        QString rootPath;
        QString directoryPath;
        int depth = 0;
    };

    QString normalizeObjectDirectoryPath(const QString& rawPath)
    {
        // Input: The object directory path from user input or recursive concatenation.
        // Processing: Replace slashes, compress consecutive backslashes, and ensure the path starts with a backslash.
        // Returns: Normalized Object Manager path; empty input returns root directory "\".
        QString normalizedPath = rawPath.trimmed();
        normalizedPath.replace('/', '\\');
        while (normalizedPath.contains(QStringLiteral("\\\\")))
        {
            normalizedPath.replace(QStringLiteral("\\\\"), QStringLiteral("\\"));
        }
        if (normalizedPath.isEmpty())
        {
            return QStringLiteral("\\");
        }
        if (!normalizedPath.startsWith('\\'))
        {
            normalizedPath.prepend('\\');
        }
        while (normalizedPath.size() > 1 && normalizedPath.endsWith('\\'))
        {
            normalizedPath.chop(1);
        }
        return normalizedPath;
    }

    QString joinObjectDirectoryPath(const QString& directoryPath, const QString& objectName)
    {
        // Input: parent directory path and object name.
        // Processing: Concatenate per Object Manager path rules with special handling for the root directory.
        // Returns: Full object path.
        const QString kNormalizedDirectory = normalizeObjectDirectoryPath(directoryPath);
        if (kNormalizedDirectory == QStringLiteral("\\"))
        {
            return QStringLiteral("\\%1").arg(objectName);
        }
        return kNormalizedDirectory + QStringLiteral("\\") + objectName;
    }

    QString leafNameFromPath(const QString& objectPath)
    {
        // Input: Full object path.
        // Handling: Extract the name after the last backslash; return "\" for the root directory.
        // Return: displayable leaf name.
        const QString kNormalizedPath = normalizeObjectDirectoryPath(objectPath);
        if (kNormalizedPath == QStringLiteral("\\"))
        {
            return QStringLiteral("\\");
        }
        const int kSlashIndex = kNormalizedPath.lastIndexOf('\\');
        return kSlashIndex >= 0 ? kNormalizedPath.mid(kSlashIndex + 1) : kNormalizedPath;
    }

    QString parentPathFromPath(const QString& objectPath)
    {
        // Input: Full object path.
        // Processing: Retrieve parent directory path; return "\" for root directory or parent paths of first-level objects.
        // Returns: Parent directory path.
        const QString kNormalizedPath = normalizeObjectDirectoryPath(objectPath);
        if (kNormalizedPath == QStringLiteral("\\"))
        {
            return QStringLiteral("\\");
        }
        const int kSlashIndex = kNormalizedPath.lastIndexOf('\\');
        if (kSlashIndex <= 0)
        {
            return QStringLiteral("\\");
        }
        return kNormalizedPath.left(kSlashIndex);
    }

    QString unicodeStringToQString(const UNICODE_STRING& unicodeText)
    {
        // Input: UNICODE_STRING returned by NtQueryDirectoryObject.
        // Processing: Convert based on byte length without relying on NUL termination.
        // Return: QString; returns an empty string if Buffer is null or Length is zero.
        if (unicodeText.Buffer == nullptr || unicodeText.Length == 0)
        {
            return QString();
        }
        return QString::fromWCharArray(
            unicodeText.Buffer,
            unicodeText.Length / static_cast<USHORT>(sizeof(wchar_t)));
    }

    void initializeUnicodeString(UNICODE_STRING& unicodeTextOut, const std::wstring& sourceText)
    {
        // Input: std::wstring with a stable lifetime.
        // Processing: Fill the UNICODE_STRING, truncating the length to the USHORT upper limit for protection.
        // Return: None; results are written to unicodeTextOut.
        unicodeTextOut.Buffer = const_cast<PWSTR>(sourceText.c_str());
        unicodeTextOut.Length = static_cast<USHORT>(
            std::min<std::size_t>(
                sourceText.size() * sizeof(wchar_t),
                static_cast<std::size_t>(std::numeric_limits<USHORT>::max() - sizeof(wchar_t))));
        unicodeTextOut.MaximumLength = static_cast<USHORT>(unicodeTextOut.Length + sizeof(wchar_t));
    }

    bool isNeedGrowBufferStatus(const NTSTATUS statusCode)
    {
        // Input: Return status from NtQueryDirectoryObject.
        // Returns: true indicates the buffer should be expanded and retried.
        return statusCode == kStatusInfoLengthMismatch
            || statusCode == kStatusBufferTooSmall
            || statusCode == kStatusBufferOverflow;
    }

    QString ntStatusToText(const HMODULE ntdllModule, const NTSTATUS statusCode)
    {
        // Input: NTSTATUS and ntdll module handle.
        // Handling: Prefer parsing ntdll messages via FormatMessageW; if failed, return only the hexadecimal value.
        // Returns: status text for UI display.
        const QString kHexText = QStringLiteral("0x%1")
            .arg(static_cast<unsigned long>(statusCode), 8, 16, QChar('0'))
            .toUpper();

        std::array<wchar_t, 256> messageBuffer{};
        const DWORD kMessageLength = ::FormatMessageW(
            FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK,
            ntdllModule,
            static_cast<DWORD>(statusCode),
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

    bool loadNtDirectoryDeepApi(NtDirectoryDeepApi& apiOut, QString& errorTextOut)
    {
        // Input: apiOut is the output structure.
        // Handling: Dynamically resolve directory object query APIs from ntdll.dll.
        // Returns: true = parsing succeeded; false = ntdll or required exports missing.
        errorTextOut.clear();
        apiOut.ntdllModule = ::GetModuleHandleW(L"ntdll.dll");
        if (apiOut.ntdllModule == nullptr)
        {
            apiOut.ntdllModule = ::LoadLibraryW(L"ntdll.dll");
        }
        if (apiOut.ntdllModule == nullptr)
        {
            errorTextOut = kernelText("kernel.object_directory.worker.load_ntdll_failed", QStringLiteral("加载 ntdll.dll 失败。"));
            return false;
        }

        apiOut.openDirectoryObject = reinterpret_cast<NtOpenDirectoryObjectFn>(
            ::GetProcAddress(apiOut.ntdllModule, "NtOpenDirectoryObject"));
        apiOut.queryDirectoryObject = reinterpret_cast<NtQueryDirectoryObjectFn>(
            ::GetProcAddress(apiOut.ntdllModule, "NtQueryDirectoryObject"));
        if (apiOut.openDirectoryObject == nullptr || apiOut.queryDirectoryObject == nullptr)
        {
            errorTextOut = kernelText("kernel.object_directory.worker.resolve_api_failed", QStringLiteral("解析 NtOpenDirectoryObject 或 NtQueryDirectoryObject 失败。"));
            return false;
        }
        return true;
    }

    NTSTATUS openDirectoryHandle(
        const NtDirectoryDeepApi& api,
        const QString& directoryPath,
        HANDLE& directoryHandleOut)
    {
        // Input: API and Object Manager directory paths.
        // Note: Construct OBJECT_ATTRIBUTES requesting only DIRECTORY_QUERY/TRAVERSE.
        // Returns: NTSTATUS from NtOpenDirectoryObject; handle written to directoryHandleOut.
        directoryHandleOut = nullptr;
        const QString kNormalizedPath = normalizeObjectDirectoryPath(directoryPath);
        const std::wstring kPathWideText = kNormalizedPath.toStdWString();

        UNICODE_STRING objectPath{};
        initializeUnicodeString(objectPath, kPathWideText);

        OBJECT_ATTRIBUTES objectAttributes{};
        InitializeObjectAttributes(&objectAttributes, &objectPath, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
        return api.openDirectoryObject(&directoryHandleOut, kDirectoryQueryAccess, &objectAttributes);
    }

    KernelObjectDirectoryDeepOptions sanitizeOptions(const KernelObjectDirectoryDeepOptions& rawOptions)
    {
        // Input: Raw limit parameters provided by the caller.
        // Processing: Correct empty paths, negative depths, and excessive upper limits.
        // Returns: Safe execution limit parameters.
        KernelObjectDirectoryDeepOptions options = rawOptions;
        options.rootPath = normalizeObjectDirectoryPath(options.rootPath);
        if (options.maxDepth < 0)
        {
            options.maxDepth = kDefaultMaxDepth;
        }
        options.maxDepth = std::min(options.maxDepth, kHardMaxDepth);

        if (options.maxEntriesPerDirectory == 0)
        {
            options.maxEntriesPerDirectory = kDefaultMaxEntriesPerDirectory;
        }
        options.maxEntriesPerDirectory = std::min(
            options.maxEntriesPerDirectory,
            kHardMaxEntriesPerDirectory);

        if (options.maxTotalEntries == 0)
        {
            options.maxTotalEntries = kDefaultMaxTotalEntries;
        }
        options.maxTotalEntries = std::min(options.maxTotalEntries, kHardMaxTotalEntries);
        return options;
    }

    bool appendRowWithTotalLimit(
        KernelObjectDirectoryDeepResult& result,
        const KernelObjectDirectoryDeepOptions& options,
        KernelObjectDirectoryDeepEntry row)
    {
        // Input: Result object, safety limit, and records to write.
        // Processing: Reject further writes and set totalLimitReached when total record count reaches the limit.
        // Return: true on successful write; false if total limit reached.
        if (result.rows.size() >= options.maxTotalEntries)
        {
            result.totalLimitReached = true;
            return false;
        }
        result.rows.push_back(std::move(row));
        return true;
    }

    KernelObjectDirectoryDeepEntry makeDirectoryFailureRow(
        const QString& rootPath,
        const QString& directoryPath,
        const int depth,
        const QString& statusText)
    {
        // Input: Failed directory context.
        // Processing: Construct a Directory record with querySucceeded=false.
        // Returns: A failure record ready to be written directly to the result list.
        KernelObjectDirectoryDeepEntry row;
        row.rootPath = rootPath;
        row.directoryPath = parentPathFromPath(directoryPath);
        row.objectName = leafNameFromPath(directoryPath);
        row.objectType = QStringLiteral("Directory");
        row.fullPath = normalizeObjectDirectoryPath(directoryPath);
        row.depth = depth;
        row.statusText = statusText;
        row.querySucceeded = false;
        row.isDirectory = true;
        return row;
    }

    bool enumerateSingleDirectory(
        const NtDirectoryDeepApi& api,
        const QString& directoryPath,
        const std::size_t maxEntriesPerDirectory,
        std::vector<DirectoryChildRecord>& recordsOut,
        NTSTATUS& statusCodeOut,
        bool& perDirectoryLimitReachedOut)
    {
        // Input: Nt API, directory path, and per-directory limit.
        // Processing: Call NtQueryDirectoryObject iteratively to collect Name/TypeName up to the limit.
        // Returns: true = directory opened and enumeration process completed; false = open or query failed.
        recordsOut.clear();
        statusCodeOut = kStatusUnsuccessful;
        perDirectoryLimitReachedOut = false;

        ScopedNtHandle directoryHandle;
        statusCodeOut = openDirectoryHandle(api, directoryPath, directoryHandle.handle);
        if (!NT_SUCCESS(statusCodeOut))
        {
            return false;
        }

        ULONG queryContext = 0;
        BOOLEAN restartScan = TRUE;
        ULONG queryBufferSize = kInitialDirectoryQueryBuffer;

        for (std::size_t entryIndex = 0; entryIndex < maxEntriesPerDirectory; ++entryIndex)
        {
            std::vector<std::uint8_t> queryBuffer;
            NTSTATUS queryStatus = kStatusUnsuccessful;
            ULONG returnLength = 0;
            bool queryFinished = false;

            for (int retryIndex = 0; retryIndex < 6; ++retryIndex)
            {
                queryBuffer.assign(queryBufferSize, 0);
                queryStatus = api.queryDirectoryObject(
                    directoryHandle.handle,
                    queryBuffer.data(),
                    queryBufferSize,
                    TRUE,
                    restartScan,
                    &queryContext,
                    &returnLength);

                if (queryStatus == kStatusNoMoreEntries)
                {
                    statusCodeOut = kStatusSuccess;
                    return true;
                }
                if (isNeedGrowBufferStatus(queryStatus))
                {
                    queryBufferSize = std::max(queryBufferSize * 2U, returnLength + 512U);
                    continue;
                }

                queryFinished = true;
                break;
            }

            restartScan = FALSE;
            if (!queryFinished)
            {
                statusCodeOut = queryStatus;
                return false;
            }
            if (!NT_SUCCESS(queryStatus))
            {
                statusCodeOut = queryStatus;
                return false;
            }
            if (queryBuffer.size() < sizeof(ObjectDirectoryInformation))
            {
                statusCodeOut = kStatusBufferTooSmall;
                return false;
            }

            const auto* recordInfo = reinterpret_cast<const ObjectDirectoryInformation*>(queryBuffer.data());
            DirectoryChildRecord record;
            record.objectName = unicodeStringToQString(recordInfo->name).trimmed();
            record.objectType = unicodeStringToQString(recordInfo->typeName).trimmed();
            if (!record.objectName.isEmpty())
            {
                recordsOut.push_back(std::move(record));
            }
        }

        perDirectoryLimitReachedOut = true;
        statusCodeOut = kStatusSuccess;
        return true;
    }
}

KernelObjectDirectoryDeepResult runKernelObjectDirectoryDeepSnapshotTask(
    const KernelObjectDirectoryDeepOptions& rawOptions)
{
    KernelObjectDirectoryDeepResult result;
    const KernelObjectDirectoryDeepOptions kOptions = sanitizeOptions(rawOptions);
    result.normalizedRootPath = kOptions.rootPath;

    NtDirectoryDeepApi api;
    if (!loadNtDirectoryDeepApi(api, result.errorText))
    {
        result.success = false;
        return result;
    }

    std::queue<PendingDirectory> pendingDirectories;
    pendingDirectories.push(PendingDirectory{ kOptions.rootPath, kOptions.rootPath, 0 });

    while (!pendingDirectories.empty() && !result.totalLimitReached)
    {
        const PendingDirectory kCurrentDirectory = pendingDirectories.front();
        pendingDirectories.pop();

        std::vector<DirectoryChildRecord> childRecords;
        NTSTATUS queryStatus = kStatusUnsuccessful;
        bool perDirectoryLimitReached = false;
        const bool kQueryOk = enumerateSingleDirectory(
            api,
            kCurrentDirectory.directoryPath,
            kOptions.maxEntriesPerDirectory,
            childRecords,
            queryStatus,
            perDirectoryLimitReached);

        ++result.visitedDirectoryCount;
        if (!kQueryOk)
        {
            ++result.failedDirectoryCount;
            appendRowWithTotalLimit(
                result,
                kOptions,
                makeDirectoryFailureRow(
                    kCurrentDirectory.rootPath,
                    kCurrentDirectory.directoryPath,
                    kCurrentDirectory.depth,
                    kernelText("kernel.object_directory.worker.directory_access_failed", QStringLiteral("目录访问失败：%1")).arg(ntStatusToText(api.ntdllModule, queryStatus))));
            continue;
        }

        if (perDirectoryLimitReached)
        {
            result.perDirectoryLimitReached = true;
        }

        for (const DirectoryChildRecord& childRecord : childRecords)
        {
            const bool kChildIsDirectory =
                childRecord.objectType.compare(QStringLiteral("Directory"), Qt::CaseInsensitive) == 0;
            const QString kChildFullPath = joinObjectDirectoryPath(
                kCurrentDirectory.directoryPath,
                childRecord.objectName);

            KernelObjectDirectoryDeepEntry row;
            row.rootPath = kCurrentDirectory.rootPath;
            row.directoryPath = kCurrentDirectory.directoryPath;
            row.objectName = childRecord.objectName;
            row.objectType = childRecord.objectType;
            row.fullPath = kChildFullPath;
            row.depth = kCurrentDirectory.depth;
            row.querySucceeded = true;
            row.isDirectory = kChildIsDirectory;
            row.statusText = kChildIsDirectory
                ? kernelText("kernel.object_directory.worker.directory_found", QStringLiteral("Directory 已发现"))
                : kernelText("kernel.object_directory.worker.leaf_object", QStringLiteral("叶子对象"));

            if (!appendRowWithTotalLimit(result, kOptions, std::move(row)))
            {
                break;
            }

            if (!kChildIsDirectory)
            {
                continue;
            }
            if (kCurrentDirectory.depth >= kOptions.maxDepth)
            {
                result.depthLimitReached = true;
                continue;
            }
            pendingDirectories.push(PendingDirectory{
                kCurrentDirectory.rootPath,
                kChildFullPath,
                kCurrentDirectory.depth + 1
                });
        }
    }

    if (result.totalLimitReached)
    {
        KernelObjectDirectoryDeepEntry limitRow;
        limitRow.rootPath = kOptions.rootPath;
        limitRow.directoryPath = kOptions.rootPath;
        limitRow.objectName = QStringLiteral("<TotalLimit>");
        limitRow.objectType = QStringLiteral("Diagnostic");
        limitRow.fullPath = kOptions.rootPath;
        limitRow.depth = 0;
        limitRow.statusText = kernelText("kernel.object_directory.worker.total_limit", QStringLiteral("达到总条目上限 %1，递归已停止。")).arg(kOptions.maxTotalEntries);
        limitRow.querySucceeded = false;
        limitRow.isDirectory = false;
        if (result.rows.size() < kOptions.maxTotalEntries)
        {
            result.rows.push_back(std::move(limitRow));
        }
    }

    result.success = true;
    return result;
}
