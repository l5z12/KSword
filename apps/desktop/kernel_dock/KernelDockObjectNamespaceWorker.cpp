
#include "KernelDockObjectNamespaceWorker.h"

// ============================================================
// KernelDockObjectNamespaceWorker.cpp
// Purpose:
// 1) Enumerates key directories in the object manager namespace;
// 2) Resolve target path for symbolic link objects.
// 3) Provide DOS drive letter mapping candidates for device paths.
// ============================================================

#include "../Framework.h"

#include <QStringList>

#include <algorithm> // std::sort/std::max: Sorting and expansion.
#include <array>     // std::array: Fixed buffer for FormatMessage.
#include <cstdint>   // std::uintXX_t: Fixed-width integer.
#include <limits>    // std::numeric_limits: Limits UNICODE_STRING length.
#include <vector>    // std::vector: Result container.

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <Winternl.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// Compatibility constant definition:
// - In some Windows SDK combinations, Winternl.h does not export object directory/symbolic link access masks.
// - Completes definitions according to NT kernel object definitions here to avoid compiler errors for 'undeclared identifier'.
#ifndef DIRECTORY_QUERY
#define DIRECTORY_QUERY 0x0001
#endif
#ifndef DIRECTORY_TRAVERSE
#define DIRECTORY_TRAVERSE 0x0002
#endif
#ifndef SYMBOLIC_LINK_QUERY
#define SYMBOLIC_LINK_QUERY 0x0001
#endif

namespace
{
    // NTSTATUS constants: Unified management to avoid scattered magic numbers.
    constexpr NTSTATUS kStatusSuccess = static_cast<NTSTATUS>(0x00000000L);
    constexpr NTSTATUS kStatusUnsuccessful = static_cast<NTSTATUS>(0xC0000001L);
    constexpr NTSTATUS kStatusInfoLengthMismatch = static_cast<NTSTATUS>(0xC0000004L);
    constexpr NTSTATUS kStatusBufferOverflow = static_cast<NTSTATUS>(0x80000005L);
    constexpr NTSTATUS kStatusBufferTooSmall = static_cast<NTSTATUS>(0xC0000023L);
    constexpr NTSTATUS kStatusNoMoreEntries = static_cast<NTSTATUS>(0x8000001AL);

    // Query control constants: Uniformly control enumeration limits and buffer sizes.
    constexpr std::size_t kMaxEntriesPerDirectory = 8192; // Maximum 8192 entries per directory to prevent extreme lag.
    constexpr ULONG kInitialDirectoryQueryBuffer = 16 * 1024U; // Initial buffer size for directory enumeration.
    constexpr ULONG kInitialSymbolicLinkChars = 1024U; // Initial character buffer size for the symbolic link target.

    // Access mask constant: request only query permissions to avoid excessive authorization.
    constexpr ACCESS_MASK kDirectoryQueryAccess = DIRECTORY_QUERY | DIRECTORY_TRAVERSE;
    constexpr ACCESS_MASK kSymbolicLinkQueryAccess = SYMBOLIC_LINK_QUERY;

    // Nt API function pointer types: Unified signatures for easier dynamic loading.
    using NtOpenDirectoryObjectFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
    using NtQueryDirectoryObjectFn = NTSTATUS(NTAPI*)(HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG);
    using NtOpenSymbolicLinkObjectFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
    using NtQuerySymbolicLinkObjectFn = NTSTATUS(NTAPI*)(HANDLE, PUNICODE_STRING, PULONG);

    // NtObjectNamespaceApi: Caches the ntdll handle and object manager-related entry points.
    struct NtObjectNamespaceApi
    {
        HMODULE ntdllModule = nullptr;                           // ntdllModule: The handle to the ntdll module.
        NtOpenDirectoryObjectFn openDirectoryObject = nullptr;   // openDirectoryObject：NtOpenDirectoryObject。
        NtQueryDirectoryObjectFn queryDirectoryObject = nullptr; // queryDirectoryObject：NtQueryDirectoryObject。
        NtOpenSymbolicLinkObjectFn openSymbolicLinkObject = nullptr;   // openSymbolicLinkObject：NtOpenSymbolicLinkObject。
        NtQuerySymbolicLinkObjectFn querySymbolicLinkObject = nullptr; // querySymbolicLinkObject：NtQuerySymbolicLinkObject。
    };

    // ScopedNtHandle：
    // - Purpose: Automatically manage Nt-opened HANDLEs to prevent missing CloseHandle calls.
    struct ScopedNtHandle
    {
        HANDLE handle = nullptr; // handle: managed kernel object handle.

        ~ScopedNtHandle()
        {
            if (handle != nullptr)
            {
                ::CloseHandle(handle);
                handle = nullptr;
            }
        }

        ScopedNtHandle() = default;
        ScopedNtHandle(const ScopedNtHandle&) = delete;
        ScopedNtHandle& operator=(const ScopedNtHandle&) = delete;
    };

    // DirectoryRecord: Stores object names and type names obtained from directory enumeration.
    struct DirectoryRecord
    {
        QString objectNameText; // objectNameText: Object name.
        QString objectTypeText; // objectTypeText: Object type name.
    };

    // NamespaceRootSpec: Defines the root directory and semantic metadata to enumerate.
    struct NamespaceRootSpec
    {
        QString queryPathText;         // queryPathText: The directory path actually passed to NtOpenDirectoryObject.
        QString displayPathText;       // displayPathText: Display path text in the UI.
        QString scopeDescriptionText;  // scopeDescriptionText: Root directory semantic description.
        QString enumApiText;           // enumApiText: Default enumeration API for this root directory.
    };

    // KsObjectDirectoryInformation：
    // - Purpose: Parse a single return entry from NtQueryDirectoryObject.
    // - Note: Only the Name and TypeName fields are needed here to meet requirements.
    struct KsObjectDirectoryInformation
    {
        UNICODE_STRING name;
        UNICODE_STRING typeName;
    };

    // normalizePathText：
    // - Purpose: normalize the path to the "\\xxx" format.
    QString normalizePathText(const QString& rawPathText)
    {
        QString normalizedPathText = rawPathText.trimmed();
        normalizedPathText.replace('/', '\\');

        while (normalizedPathText.contains(QStringLiteral("\\\\")))
        {
            normalizedPathText.replace(QStringLiteral("\\\\"), QStringLiteral("\\"));
        }

        if (normalizedPathText.isEmpty())
        {
            return QStringLiteral("\\");
        }

        if (!normalizedPathText.startsWith('\\'))
        {
            normalizedPathText.prepend('\\');
        }
        return normalizedPathText;
    }

    // joinObjectPath：
    // - Purpose: Concatenate the directory path and object name to form a complete object path.
    QString joinObjectPath(const QString& directoryPathText, const QString& objectNameText)
    {
        const QString kNormalizedDirectoryPathText = normalizePathText(directoryPathText);
        if (kNormalizedDirectoryPathText == QStringLiteral("\\"))
        {
            return QStringLiteral("\\%1").arg(objectNameText);
        }
        if (kNormalizedDirectoryPathText.endsWith('\\'))
        {
            return kNormalizedDirectoryPathText + objectNameText;
        }
        return kNormalizedDirectoryPathText + QStringLiteral("\\") + objectNameText;
    }

    // unicodeStringToQString：
    // - Purpose: Convert UNICODE_STRING to QString.
    QString unicodeStringToQString(const UNICODE_STRING& unicodeText)
    {
        if (unicodeText.Buffer == nullptr || unicodeText.Length == 0)
        {
            return QString();
        }

        return QString::fromWCharArray(
            unicodeText.Buffer,
            unicodeText.Length / static_cast<USHORT>(sizeof(wchar_t)));
    }

    // initializeUnicodeString：
    // - Purpose: Populate UNICODE_STRING from std::wstring.
    void initializeUnicodeString(UNICODE_STRING& unicodeTextOut, const std::wstring& sourceText)
    {
        unicodeTextOut.Buffer = const_cast<PWSTR>(sourceText.c_str());
        unicodeTextOut.Length = static_cast<USHORT>(
            std::min<std::size_t>(
                sourceText.size() * sizeof(wchar_t),
                static_cast<std::size_t>(std::numeric_limits<USHORT>::max() - sizeof(wchar_t))));
        unicodeTextOut.MaximumLength = static_cast<USHORT>(unicodeTextOut.Length + sizeof(wchar_t));
    }

    // isNeedGrowBufferStatus：
    // - Purpose: Determine if the status code indicates 'buffer insufficient, requires expansion and retry'.
    bool isNeedGrowBufferStatus(const NTSTATUS statusCode)
    {
        return statusCode == kStatusInfoLengthMismatch
            || statusCode == kStatusBufferTooSmall
            || statusCode == kStatusBufferOverflow;
    }

    // ntStatusToText：
    // - Purpose: Convert NTSTATUS to hexadecimal + readable text.
    QString ntStatusToText(const HMODULE ntdllModule, const NTSTATUS statusCode)
    {
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

    // loadNtObjectNamespaceApi：
    // - Purpose: Parse the Nt APIs required for object namespace enumeration.
    bool loadNtObjectNamespaceApi(NtObjectNamespaceApi& apiOut, QString& errorTextOut)
    {
        errorTextOut.clear();

        apiOut.ntdllModule = ::GetModuleHandleW(L"ntdll.dll");
        if (apiOut.ntdllModule == nullptr)
        {
            apiOut.ntdllModule = ::LoadLibraryW(L"ntdll.dll");
        }
        if (apiOut.ntdllModule == nullptr)
        {
            errorTextOut = QStringLiteral("加载 ntdll.dll 失败。");
            return false;
        }

        apiOut.openDirectoryObject = reinterpret_cast<NtOpenDirectoryObjectFn>(
            ::GetProcAddress(apiOut.ntdllModule, "NtOpenDirectoryObject"));
        apiOut.queryDirectoryObject = reinterpret_cast<NtQueryDirectoryObjectFn>(
            ::GetProcAddress(apiOut.ntdllModule, "NtQueryDirectoryObject"));
        apiOut.openSymbolicLinkObject = reinterpret_cast<NtOpenSymbolicLinkObjectFn>(
            ::GetProcAddress(apiOut.ntdllModule, "NtOpenSymbolicLinkObject"));
        apiOut.querySymbolicLinkObject = reinterpret_cast<NtQuerySymbolicLinkObjectFn>(
            ::GetProcAddress(apiOut.ntdllModule, "NtQuerySymbolicLinkObject"));

        if (apiOut.openDirectoryObject == nullptr
            || apiOut.queryDirectoryObject == nullptr
            || apiOut.openSymbolicLinkObject == nullptr
            || apiOut.querySymbolicLinkObject == nullptr)
        {
            errorTextOut = QStringLiteral("解析 NtOpen/NtQuery Directory 或 SymbolicLink API 失败。");
            return false;
        }
        return true;
    }

    // openDirectoryHandle：
    // - Purpose: Open an object directory handle by directory path.
    NTSTATUS openDirectoryHandle(
        const NtObjectNamespaceApi& api,
        const QString& directoryPathText,
        HANDLE& directoryHandleOut)
    {
        directoryHandleOut = nullptr;

        const QString kNormalizedPathText = normalizePathText(directoryPathText);
        const std::wstring kPathWideText = kNormalizedPathText.toStdWString();

        UNICODE_STRING objectPath{};
        initializeUnicodeString(objectPath, kPathWideText);

        OBJECT_ATTRIBUTES objectAttributes{};
        InitializeObjectAttributes(&objectAttributes, &objectPath, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

        return api.openDirectoryObject(&directoryHandleOut, kDirectoryQueryAccess, &objectAttributes);
    }

    // openSymbolicLinkHandle：
    // - Purpose: Open a symbolic link handle by object path.
    NTSTATUS openSymbolicLinkHandle(
        const NtObjectNamespaceApi& api,
        const QString& symbolicLinkPathText,
        HANDLE& symbolicLinkHandleOut)
    {
        symbolicLinkHandleOut = nullptr;

        const QString kNormalizedPathText = normalizePathText(symbolicLinkPathText);
        const std::wstring kPathWideText = kNormalizedPathText.toStdWString();

        UNICODE_STRING objectPath{};
        initializeUnicodeString(objectPath, kPathWideText);

        OBJECT_ATTRIBUTES objectAttributes{};
        InitializeObjectAttributes(&objectAttributes, &objectPath, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

        return api.openSymbolicLinkObject(&symbolicLinkHandleOut, kSymbolicLinkQueryAccess, &objectAttributes);
    }

    // enumerateDirectoryEntries：
    // - Purpose: enumerate object names and types in the directory.
    bool enumerateDirectoryEntries(
        const NtObjectNamespaceApi& api,
        const QString& directoryPathText,
        std::vector<DirectoryRecord>& recordsOut,
        NTSTATUS& statusCodeOut,
        bool& truncatedOut)
    {
        recordsOut.clear();
        statusCodeOut = kStatusUnsuccessful;
        truncatedOut = false;

        ScopedNtHandle directoryHandle;
        statusCodeOut = openDirectoryHandle(api, directoryPathText, directoryHandle.handle);
        if (!NT_SUCCESS(statusCodeOut))
        {
            return false;
        }

        ULONG queryContext = 0; // queryContext: Cursor for NtQueryDirectoryObject.
        BOOLEAN restartScan = TRUE; // restartScan: TRUE for the initial query, fixed FALSE for subsequent queries.
        ULONG queryBufferSize = kInitialDirectoryQueryBuffer; // queryBufferSize: Directory query buffer size.

        for (std::size_t entryIndex = 0; entryIndex < kMaxEntriesPerDirectory; ++entryIndex)
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

            if (queryBuffer.size() < sizeof(KsObjectDirectoryInformation))
            {
                statusCodeOut = kStatusBufferTooSmall;
                return false;
            }

            const auto* recordInfo = reinterpret_cast<const KsObjectDirectoryInformation*>(queryBuffer.data());
            const QString kObjectNameText = unicodeStringToQString(recordInfo->name).trimmed();
            const QString kObjectTypeText = unicodeStringToQString(recordInfo->typeName).trimmed();

            if (kObjectNameText.isEmpty())
            {
                continue;
            }

            DirectoryRecord record;
            record.objectNameText = kObjectNameText;
            record.objectTypeText = kObjectTypeText;
            recordsOut.push_back(std::move(record));
        }

        truncatedOut = true;
        statusCodeOut = kStatusSuccess;
        return true;
    }

    // querySymbolicLinkTargetInternal：
    // - Purpose: Internal utility function that resolves symbolic link targets by path.
    bool querySymbolicLinkTargetInternal(
        const NtObjectNamespaceApi& api,
        const QString& symbolicLinkPathText,
        QString& targetTextOut,
        QString& statusTextOut)
    {
        targetTextOut.clear();
        statusTextOut.clear();

        ScopedNtHandle symbolicLinkHandle;
        const NTSTATUS kOpenStatus = openSymbolicLinkHandle(api, symbolicLinkPathText, symbolicLinkHandle.handle);
        if (!NT_SUCCESS(kOpenStatus))
        {
            statusTextOut = ntStatusToText(api.ntdllModule, kOpenStatus);
            return false;
        }

        ULONG targetChars = kInitialSymbolicLinkChars; // targetChars: Number of characters in the target path buffer.
        for (int retryIndex = 0; retryIndex < 6; ++retryIndex)
        {
            std::vector<wchar_t> targetBuffer(targetChars, L'\0');
            UNICODE_STRING targetUnicode{};
            targetUnicode.Buffer = targetBuffer.data();
            targetUnicode.Length = 0;
            targetUnicode.MaximumLength = static_cast<USHORT>(
                std::min<std::size_t>(
                    targetChars * sizeof(wchar_t),
                    static_cast<std::size_t>(std::numeric_limits<USHORT>::max() - sizeof(wchar_t))));

            ULONG returnLength = 0;
            const NTSTATUS kQueryStatus = api.querySymbolicLinkObject(
                symbolicLinkHandle.handle,
                &targetUnicode,
                &returnLength);

            if (NT_SUCCESS(kQueryStatus))
            {
                targetTextOut = QString::fromWCharArray(
                    targetUnicode.Buffer,
                    targetUnicode.Length / static_cast<USHORT>(sizeof(wchar_t)));
                statusTextOut = ntStatusToText(api.ntdllModule, kQueryStatus);
                return true;
            }

            if (!isNeedGrowBufferStatus(kQueryStatus))
            {
                statusTextOut = ntStatusToText(api.ntdllModule, kQueryStatus);
                return false;
            }

            targetChars = std::max<ULONG>(
                targetChars * 2U,
                static_cast<ULONG>(returnLength / sizeof(wchar_t) + 8U));
        }

        statusTextOut = QStringLiteral("符号链接目标解析重试达到上限。");
        return false;
    }

    // isNumericString：
    // - Purpose: Check if the string consists entirely of numeric characters.
    bool isNumericString(const QString& valueText)
    {
        if (valueText.trimmed().isEmpty())
        {
            return false;
        }

        for (const QChar kSingleChar : valueText)
        {
            if (!kSingleChar.isDigit())
            {
                return false;
            }
        }
        return true;
    }

    // querySessionIdList：
    // - Purpose: enumerate the \Sessions directory to extract the session ID list.
    std::vector<unsigned long> querySessionIdList(const NtObjectNamespaceApi& api)
    {
        std::vector<unsigned long> sessionIdList;

        std::vector<DirectoryRecord> sessionsDirectoryRecords;
        NTSTATUS queryStatus = kStatusUnsuccessful;
        bool truncated = false;
        if (enumerateDirectoryEntries(
            api,
            QStringLiteral("\\Sessions"),
            sessionsDirectoryRecords,
            queryStatus,
            truncated))
        {
            for (const DirectoryRecord& record : sessionsDirectoryRecords)
            {
                if (record.objectTypeText.compare(QStringLiteral("Directory"), Qt::CaseInsensitive) != 0)
                {
                    continue;
                }
                if (!isNumericString(record.objectNameText))
                {
                    continue;
                }

                bool parseOk = false;
                const unsigned long kParsedSessionId = record.objectNameText.toULong(&parseOk);
                if (parseOk)
                {
                    sessionIdList.push_back(kParsedSessionId);
                }
            }
        }

        if (sessionIdList.empty())
        {
            DWORD currentSessionId = 0;
            if (::ProcessIdToSessionId(::GetCurrentProcessId(), &currentSessionId))
            {
                sessionIdList.push_back(static_cast<unsigned long>(currentSessionId));
            }
            sessionIdList.push_back(0UL);
        }

        std::sort(sessionIdList.begin(), sessionIdList.end());
        sessionIdList.erase(std::unique(sessionIdList.begin(), sessionIdList.end()), sessionIdList.end());
        return sessionIdList;
    }

    // buildRootSpecList：
    // - Purpose: Constructs the directory specifications to be traversed for this task.
    std::vector<NamespaceRootSpec> buildRootSpecList(const NtObjectNamespaceApi& api)
    {
        std::vector<NamespaceRootSpec> rootSpecList;

        rootSpecList.push_back(NamespaceRootSpec{
            QStringLiteral("\\"),
            QStringLiteral("\\"),
            QStringLiteral("对象管理器根目录"),
            QStringLiteral("NtOpenDirectoryObject + NtQueryDirectoryObject")
            });

        rootSpecList.push_back(NamespaceRootSpec{
            QStringLiteral("\\BaseNamedObjects"),
            QStringLiteral("\\BaseNamedObjects"),
            QStringLiteral("跨会话全局对象（互斥体、事件、信号量、节区等）"),
            QStringLiteral("NtOpenDirectoryObject + NtQueryDirectoryObject")
            });

        const std::vector<unsigned long> kSessionIdList = querySessionIdList(api);
        for (const unsigned long kSessionId : kSessionIdList)
        {
            const QString kSessionPathText = QStringLiteral("\\Sessions\\%1\\BaseNamedObjects").arg(kSessionId);
            rootSpecList.push_back(NamespaceRootSpec{
                kSessionPathText,
                kSessionPathText,
                QStringLiteral("会话 %1 私有命名对象").arg(kSessionId),
                QStringLiteral("NtOpenDirectoryObject + NtQueryDirectoryObject")
                });
        }

        rootSpecList.push_back(NamespaceRootSpec{
            QStringLiteral("\\GLOBAL??"),
            QStringLiteral("\\Global")
                + QStringLiteral("\\?\\?")
                + QStringLiteral(" (即 ")
                + QStringLiteral("\\\\?\\?)"),
            QStringLiteral("设备符号链接（DOS 设备名映射）"),
            QStringLiteral("NtOpenDirectoryObject + NtQueryDirectoryObject + NtOpenSymbolicLinkObject + NtQuerySymbolicLinkObject")
            });

        rootSpecList.push_back(NamespaceRootSpec{
            QStringLiteral("\\Device"),
            QStringLiteral("\\Device"),
            QStringLiteral("设备对象"),
            QStringLiteral("NtOpenDirectoryObject + NtQueryDirectoryObject")
            });

        rootSpecList.push_back(NamespaceRootSpec{
            QStringLiteral("\\Driver"),
            QStringLiteral("\\Driver"),
            QStringLiteral("已加载驱动对象"),
            QStringLiteral("NtOpenDirectoryObject + NtQueryDirectoryObject")
            });

        rootSpecList.push_back(NamespaceRootSpec{
            QStringLiteral("\\ObjectTypes"),
            QStringLiteral("\\ObjectTypes"),
            QStringLiteral("系统中所有对象类型定义"),
            QStringLiteral("NtOpenDirectoryObject + NtQueryDirectoryObject")
            });

        rootSpecList.push_back(NamespaceRootSpec{
            QStringLiteral("\\Callback"),
            QStringLiteral("\\Callback"),
            QStringLiteral("内核回调对象"),
            QStringLiteral("NtOpenDirectoryObject + NtQueryDirectoryObject")
            });

        rootSpecList.push_back(NamespaceRootSpec{
            QStringLiteral("\\KnownDlls"),
            QStringLiteral("\\KnownDlls"),
            QStringLiteral("已知 DLL 的节区对象"),
            QStringLiteral("NtOpenDirectoryObject + NtQueryDirectoryObject")
            });

        rootSpecList.push_back(NamespaceRootSpec{
            QStringLiteral("\\RPC Control"),
            QStringLiteral("\\RPC Control"),
            QStringLiteral("RPC 端口/接口"),
            QStringLiteral("NtOpenDirectoryObject + NtQueryDirectoryObject")
            });

        rootSpecList.push_back(NamespaceRootSpec{
            QStringLiteral("\\Windows"),
            QStringLiteral("\\Windows"),
            QStringLiteral("WindowStation 对象"),
            QStringLiteral("NtOpenDirectoryObject + NtQueryDirectoryObject")
            });

        return rootSpecList;
    }
}

bool runObjectNamespaceSnapshotTask(std::vector<KernelObjectNamespaceEntry>& rowsOut, QString& errorTextOut)
{
    rowsOut.clear();
    errorTextOut.clear();

    KLogEvent taskEvent;
    info << taskEvent << "[KernelDockObjectNamespaceWorker] 开始枚举对象命名空间。" << eol;

    NtObjectNamespaceApi api;
    if (!loadNtObjectNamespaceApi(api, errorTextOut))
    {
        err << taskEvent
            << "[KernelDockObjectNamespaceWorker] Nt API 装载失败: "
            << errorTextOut.toStdString()
            << eol;
        return false;
    }

    const std::vector<NamespaceRootSpec> kRootSpecList = buildRootSpecList(api);
    std::vector<KernelObjectNamespaceEntry> resultRows;

    for (const NamespaceRootSpec& rootSpec : kRootSpecList)
    {
        std::vector<DirectoryRecord> directoryRecords;
        NTSTATUS directoryStatus = kStatusUnsuccessful;
        bool truncated = false;
        const bool kEnumerateOk = enumerateDirectoryEntries(
            api,
            rootSpec.queryPathText,
            directoryRecords,
            directoryStatus,
            truncated);

        if (!kEnumerateOk)
        {
            KernelObjectNamespaceEntry failedEntry;
            failedEntry.rootPathText = rootSpec.displayPathText;
            failedEntry.scopeDescriptionText = rootSpec.scopeDescriptionText;
            failedEntry.directoryPathText = rootSpec.queryPathText;
            failedEntry.objectNameText = QStringLiteral("<打开失败>");
            failedEntry.objectTypeText = QStringLiteral("<错误>");
            failedEntry.fullPathText = rootSpec.queryPathText;
            failedEntry.enumApiText = rootSpec.enumApiText;
            failedEntry.symbolicLinkTargetText = QString();
            failedEntry.statusCode = directoryStatus;
            failedEntry.statusText = ntStatusToText(api.ntdllModule, directoryStatus);
            failedEntry.querySucceeded = false;
            failedEntry.isDirectory = false;
            failedEntry.isSymbolicLink = false;
            failedEntry.detailText = QStringLiteral(
                "根目录: %1\n"
                "作用说明: %2\n"
                "目录路径: %3\n"
                "枚举 API: %4\n"
                "状态: %5")
                .arg(
                    failedEntry.rootPathText,
                    failedEntry.scopeDescriptionText,
                    failedEntry.directoryPathText,
                    failedEntry.enumApiText,
                    failedEntry.statusText);
            resultRows.push_back(std::move(failedEntry));
            continue;
        }

        std::sort(directoryRecords.begin(), directoryRecords.end(), [](const DirectoryRecord& left, const DirectoryRecord& right) {
            const int kTypeCompare = QString::compare(left.objectTypeText, right.objectTypeText, Qt::CaseInsensitive);
            if (kTypeCompare != 0)
            {
                return kTypeCompare < 0;
            }
            return QString::compare(left.objectNameText, right.objectNameText, Qt::CaseInsensitive) < 0;
        });

        if (directoryRecords.empty())
        {
            KernelObjectNamespaceEntry emptyEntry;
            emptyEntry.rootPathText = rootSpec.displayPathText;
            emptyEntry.scopeDescriptionText = rootSpec.scopeDescriptionText;
            emptyEntry.directoryPathText = rootSpec.queryPathText;
            emptyEntry.objectNameText = QStringLiteral("<空目录>");
            emptyEntry.objectTypeText = QStringLiteral("Directory");
            emptyEntry.fullPathText = rootSpec.queryPathText;
            emptyEntry.enumApiText = rootSpec.enumApiText;
            emptyEntry.symbolicLinkTargetText = QString();
            emptyEntry.statusCode = kStatusSuccess;
            emptyEntry.statusText = QStringLiteral("SUCCESS");
            emptyEntry.querySucceeded = true;
            emptyEntry.isDirectory = true;
            emptyEntry.isSymbolicLink = false;
            emptyEntry.detailText = QStringLiteral(
                "根目录: %1\n"
                "作用说明: %2\n"
                "目录路径: %3\n"
                "枚举 API: %4\n"
                "状态: 空目录")
                .arg(
                    emptyEntry.rootPathText,
                    emptyEntry.scopeDescriptionText,
                    emptyEntry.directoryPathText,
                    emptyEntry.enumApiText);
            resultRows.push_back(std::move(emptyEntry));
            continue;
        }

        for (const DirectoryRecord& record : directoryRecords)
        {
            KernelObjectNamespaceEntry entry;
            entry.rootPathText = rootSpec.displayPathText;
            entry.scopeDescriptionText = rootSpec.scopeDescriptionText;
            entry.directoryPathText = rootSpec.queryPathText;
            entry.objectNameText = record.objectNameText;
            entry.objectTypeText = record.objectTypeText;
            entry.fullPathText = joinObjectPath(rootSpec.queryPathText, record.objectNameText);
            entry.enumApiText = rootSpec.enumApiText;
            entry.symbolicLinkTargetText = QString();
            entry.statusCode = kStatusSuccess;
            entry.statusText = QStringLiteral("SUCCESS");
            entry.querySucceeded = true;
            entry.isDirectory = record.objectTypeText.compare(QStringLiteral("Directory"), Qt::CaseInsensitive) == 0;
            entry.isSymbolicLink = record.objectTypeText.compare(QStringLiteral("SymbolicLink"), Qt::CaseInsensitive) == 0;

            if (entry.isSymbolicLink)
            {
                QString targetText;
                QString linkStatusText;
                const bool kResolveOk = querySymbolicLinkTargetInternal(api, entry.fullPathText, targetText, linkStatusText);
                entry.symbolicLinkTargetText = kResolveOk ? targetText : QStringLiteral("<解析失败>");
                entry.statusText = QStringLiteral("%1 | Link: %2").arg(entry.statusText, linkStatusText);

                if (!entry.enumApiText.contains(QStringLiteral("NtOpenSymbolicLinkObject"), Qt::CaseInsensitive))
                {
                    entry.enumApiText += QStringLiteral(" + NtOpenSymbolicLinkObject + NtQuerySymbolicLinkObject");
                }
            }

            entry.detailText = QStringLiteral(
                "根目录: %1\n"
                "作用说明: %2\n"
                "当前目录: %3\n"
                "对象名: %4\n"
                "对象类型: %5\n"
                "完整路径: %6\n"
                "枚举 API: %7\n"
                "符号链接目标: %8\n"
                "状态: %9")
                .arg(
                    entry.rootPathText,
                    entry.scopeDescriptionText,
                    entry.directoryPathText,
                    entry.objectNameText,
                    entry.objectTypeText,
                    entry.fullPathText,
                    entry.enumApiText,
                    entry.symbolicLinkTargetText.isEmpty() ? QStringLiteral("<无>") : entry.symbolicLinkTargetText,
                    entry.statusText);
            resultRows.push_back(std::move(entry));
        }

        if (truncated)
        {
            KernelObjectNamespaceEntry truncatedEntry;
            truncatedEntry.rootPathText = rootSpec.displayPathText;
            truncatedEntry.scopeDescriptionText = rootSpec.scopeDescriptionText;
            truncatedEntry.directoryPathText = rootSpec.queryPathText;
            truncatedEntry.objectNameText = QStringLiteral("<已截断>");
            truncatedEntry.objectTypeText = QStringLiteral("<Info>");
            truncatedEntry.fullPathText = rootSpec.queryPathText;
            truncatedEntry.enumApiText = rootSpec.enumApiText;
            truncatedEntry.symbolicLinkTargetText = QString();
            truncatedEntry.statusCode = kStatusSuccess;
            truncatedEntry.statusText = QStringLiteral("达到单目录上限 %1 项").arg(kMaxEntriesPerDirectory);
            truncatedEntry.querySucceeded = true;
            truncatedEntry.isDirectory = false;
            truncatedEntry.isSymbolicLink = false;
            truncatedEntry.detailText = QStringLiteral(
                "根目录: %1\n"
                "目录路径: %2\n"
                "提示: 为避免 UI 卡顿，单目录结果已截断到 %3 项。")
                .arg(
                    truncatedEntry.rootPathText,
                    truncatedEntry.directoryPathText)
                .arg(kMaxEntriesPerDirectory);
            resultRows.push_back(std::move(truncatedEntry));
        }
    }

    std::sort(resultRows.begin(), resultRows.end(), [](const KernelObjectNamespaceEntry& left, const KernelObjectNamespaceEntry& right) {
        const int kRootCompare = QString::compare(left.rootPathText, right.rootPathText, Qt::CaseInsensitive);
        if (kRootCompare != 0)
        {
            return kRootCompare < 0;
        }

        const int kDirectoryCompare = QString::compare(left.directoryPathText, right.directoryPathText, Qt::CaseInsensitive);
        if (kDirectoryCompare != 0)
        {
            return kDirectoryCompare < 0;
        }

        const int kTypeCompare = QString::compare(left.objectTypeText, right.objectTypeText, Qt::CaseInsensitive);
        if (kTypeCompare != 0)
        {
            return kTypeCompare < 0;
        }

        return QString::compare(left.objectNameText, right.objectNameText, Qt::CaseInsensitive) < 0;
    });

    rowsOut = std::move(resultRows);

    std::size_t failedCount = 0;
    for (const KernelObjectNamespaceEntry& row : rowsOut)
    {
        if (!row.querySucceeded)
        {
            ++failedCount;
        }
    }

    info << taskEvent
        << "[KernelDockObjectNamespaceWorker] 枚举完成, rowCount="
        << rowsOut.size()
        << ", failedCount="
        << failedCount
        << eol;
    return true;
}

bool queryObjectNamespaceSymbolicLinkTarget(
    const QString& symbolicLinkPathText,
    QString& targetTextOut,
    QString& statusTextOut)
{
    targetTextOut.clear();
    statusTextOut.clear();

    NtObjectNamespaceApi api;
    QString errorText;
    if (!loadNtObjectNamespaceApi(api, errorText))
    {
        statusTextOut = errorText;
        return false;
    }

    return querySymbolicLinkTargetInternal(api, symbolicLinkPathText, targetTextOut, statusTextOut);
}

std::vector<QString> queryDosPathCandidatesByNtPath(const QString& ntPathText)
{
    std::vector<QString> resultList;

    const QString kNormalizedNtPathText = normalizePathText(ntPathText);
    if (!kNormalizedNtPathText.startsWith(QStringLiteral("\\Device\\"), Qt::CaseInsensitive))
    {
        return resultList;
    }

    QStringList uniqueCandidateList;
    for (wchar_t driveLetter = L'A'; driveLetter <= L'Z'; ++driveLetter)
    {
        wchar_t driveName[3]{ driveLetter, L':', L'\0' };
        wchar_t mappingBuffer[4096]{};
        const DWORD kMappingLength = ::QueryDosDeviceW(
            driveName,
            mappingBuffer,
            static_cast<DWORD>(std::size(mappingBuffer)));
        if (kMappingLength == 0)
        {
            continue;
        }

        const wchar_t* mappingCursor = mappingBuffer;
        while (*mappingCursor != L'\0')
        {
            const QString kMappingText = QString::fromWCharArray(mappingCursor).trimmed();
            if (!kMappingText.isEmpty()
                && kNormalizedNtPathText.startsWith(kMappingText, Qt::CaseInsensitive))
            {
                const QString kSuffixText = kNormalizedNtPathText.mid(kMappingText.size());
                QString candidateText = QString::fromWCharArray(driveName);
                if (kSuffixText.isEmpty())
                {
                    candidateText += QStringLiteral("\\");
                }
                else
                {
                    candidateText += kSuffixText;
                }

                if (!uniqueCandidateList.contains(candidateText, Qt::CaseInsensitive))
                {
                    uniqueCandidateList.push_back(candidateText);
                }
            }

            mappingCursor += (wcslen(mappingCursor) + 1);
        }
    }

    for (const QString& candidateText : uniqueCandidateList)
    {
        resultList.push_back(candidateText);
    }
    return resultList;
}
