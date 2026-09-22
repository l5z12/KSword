
#include "KernelDeviceDriverObjectsWorker.h"
#include "KernelDock.h"

// ============================================================
// KernelDeviceDriverObjectsWorker.cpp
// Purpose:
// 1) enumerate only the four directories \Device, \Driver,
//    \FileSystem, and \FileSystem\Filters using R3 object manager APIs.
// 2) Attempt to resolve the target path of the symbolic link object to understand the device path and driver entry point.
// 3) Consolidate directory objects, driver objects, file system objects, and symbolic link objects into a single read-only row.
// ============================================================

#include "../Framework.h"

#include <QStringList>

#include <algorithm> // std::max/std::sort: Sorting and expansion.
#include <array>     // std::array: Fixed buffer for FormatMessage.
#include <cstdint>   // std::uint8_t: Raw buffer bytes.
#include <limits>    // std::numeric_limits: length constraint for UNION_STRING.
#include <utility>   // std::move: Move enumeration result entries.
#include <vector>    // std::vector: Enum results and temporary buffers.

using ksword::kernel_dock_internal::kernelText;

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <Winternl.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// ============================================================
// Compatibility completion:
// - Some SDK combinations do not export object directory/symbolic link access masks;
// - Here, object manager constants are filled in to avoid compilation risks caused by header file discrepancies.
// ============================================================
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
    // ============================================================
    // Task constants:
    // - Unify control of enumeration buffer and maximum return count for single directory.
    // - Here, a conservative upper limit is maintained to prevent the UI from being slowed down by an abnormally large number of objects.
    // ============================================================
    constexpr NTSTATUS kStatusSuccess = static_cast<NTSTATUS>(0x00000000L);
    constexpr NTSTATUS kStatusUnsuccessful = static_cast<NTSTATUS>(0xC0000001L);
    constexpr NTSTATUS kStatusInfoLengthMismatch = static_cast<NTSTATUS>(0xC0000004L);
    constexpr NTSTATUS kStatusBufferOverflow = static_cast<NTSTATUS>(0x80000005L);
    constexpr NTSTATUS kStatusBufferTooSmall = static_cast<NTSTATUS>(0xC0000023L);
    constexpr NTSTATUS kStatusNoMoreEntries = static_cast<NTSTATUS>(0x8000001AL);

    constexpr std::size_t kMaxEntriesPerDirectory = 4096; // Maximum enumeration count per directory.
    constexpr ULONG kInitialDirectoryQueryBuffer = 16 * 1024U; // Initial directory query buffer size.
    constexpr ULONG kInitialSymbolicLinkChars = 1024U; // Initial buffer character count for symbolic links.

    constexpr ACCESS_MASK kDirectoryQueryAccess = DIRECTORY_QUERY | DIRECTORY_TRAVERSE;
    constexpr ACCESS_MASK kSymbolicLinkQueryAccess = SYMBOLIC_LINK_QUERY;

    // ============================================================
    // Nt API function pointers:
    // - Use dynamic loading to avoid additional dependencies at link time.
    // - Only require directory enumeration and symbolic link resolution capabilities.
    // ============================================================
    using NtOpenDirectoryObjectFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
    using NtQueryDirectoryObjectFn = NTSTATUS(NTAPI*)(HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG);
    using NtOpenSymbolicLinkObjectFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
    using NtQuerySymbolicLinkObjectFn = NTSTATUS(NTAPI*)(HANDLE, PUNICODE_STRING, PULONG);

    // ============================================================
    // NtKernelObjectApi
    // - Cache ntdll module handle and required entry points;
    // - Carries only the R3 APIs used by this worker.
    // ============================================================
    struct NtKernelObjectApi
    {
        HMODULE ntdllModule = nullptr;                           // ntdllModule: Handle to ntdll.dll.
        NtOpenDirectoryObjectFn openDirectoryObject = nullptr;   // openDirectoryObject：NtOpenDirectoryObject。
        NtQueryDirectoryObjectFn queryDirectoryObject = nullptr; // queryDirectoryObject：NtQueryDirectoryObject。
        NtOpenSymbolicLinkObjectFn openSymbolicLinkObject = nullptr;   // openSymbolicLinkObject：NtOpenSymbolicLinkObject。
        NtQuerySymbolicLinkObjectFn querySymbolicLinkObject = nullptr;  // querySymbolicLinkObject：NtQuerySymbolicLinkObject。
    };

    // ============================================================
    // ScopedNtHandle
    // - Purpose: Automatically close Nt-opened object handles.
    // - Return: No return value on destruction; solely responsible for releasing resources.
    // ============================================================
    struct ScopedNtHandle
    {
        HANDLE handle = nullptr; // handle: managed handle.

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

    // ============================================================
    // KsObjectDirectoryInformation
    // - Purpose: Match the layout returned by NtQueryDirectoryObject;
    // - Note: Only the Name and TypeName fields are required for the current task.
    // ============================================================
    struct KsObjectDirectoryInformation
    {
        UNICODE_STRING name;
        UNICODE_STRING typeName;
    };

    // ============================================================
    // RootSpec
    // - Purpose: Describe a root directory enumeration task.
    // - Contains only the input path, display title, and semantic description; no write operations are involved.
    // ============================================================
    struct RootSpec
    {
        QString directoryPathText;  // directoryPathText: The actual enumerated object directory path.
        QString displayNameText;    // displayNameText: Directory title in the UI.
        QString descriptionText;    // descriptionText: directory usage description.
    };

    // normalizePathText：
    // - Input: Original object path;
    // - Processing: Trim whitespace, normalize slashes, and ensure it starts with a backslash;
    // - Return: The normalized object path text.
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
    // - Input: Directory path and object name;
    // - Processing: Concatenate according to Object Manager path rules.
    // - Returns: full object path.
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
    // - Input: UNICODE_STRING returned by NT API;
    // - Processing: Convert to Qt string by character length;
    // - Returns: A QString with null values removed.
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
    // - Input: std::wstring source text;
    // - Processing: Fill UNICODE_STRING with the original wide string.
    // - Return: None. The result is written to unicodeTextOut.
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
    // - Input: NTSTATUS.
    // - Processing: Check if the status indicates 'buffer too small, need to expand and retry'.
    // - Return: true indicates buffer expansion is required.
    bool isNeedGrowBufferStatus(const NTSTATUS statusCode)
    {
        return statusCode == kStatusInfoLengthMismatch
            || statusCode == kStatusBufferOverflow
            || statusCode == kStatusBufferTooSmall;
    }

    // ntStatusToText：
    // - Input: ntdll module handle and NTSTATUS;
    // - Processing: Combine the hexadecimal code with the system message for easier diagnosis.
    // - Returns: Readable status text.
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

    // loadNtKernelObjectApi：
    // - Inputs: None;
    // - Processing: Load ntdll.dll and resolve entries related to object directories and symbolic links.
    // - Return: true indicates enumeration can continue; false indicates a fatal error, with the reason written to errorTextOut.
    bool loadNtKernelObjectApi(NtKernelObjectApi& apiOut, QString& errorTextOut)
    {
        errorTextOut.clear();

        apiOut.ntdllModule = ::GetModuleHandleW(L"ntdll.dll");
        if (apiOut.ntdllModule == nullptr)
        {
            apiOut.ntdllModule = ::LoadLibraryW(L"ntdll.dll");
        }
        if (apiOut.ntdllModule == nullptr)
        {
            errorTextOut = kernelText("kernel.device_driver.worker.load_ntdll_failed", QStringLiteral("加载 ntdll.dll 失败。"));
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
            errorTextOut = kernelText("kernel.device_driver.worker.resolve_api_failed", QStringLiteral("解析 NtOpen/NtQuery Directory 或 SymbolicLink API 失败。"));
            return false;
        }
        return true;
    }

    // openDirectoryHandle：
    // - Input: Object directory path;
    // - Processing: Request read-only query permissions using NtOpenDirectoryObject.
    // - Returns: NTSTATUS; on success, directoryHandleOut holds a valid handle.
    NTSTATUS openDirectoryHandle(
        const NtKernelObjectApi& api,
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
    // - Input: Full symbolic link path;
    // - Processing: Open a symbolic link handle by object path;
    // - Return: NTSTATUS; symbolicLinkHandleOut holds a valid handle on success.
    NTSTATUS openSymbolicLinkHandle(
        const NtKernelObjectApi& api,
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

    // querySymbolicLinkTargetInternal：
    // - Input: loaded API and symbolic link path;
    // - Processing: Open the symbolic link and read the target path; retain status text on failure.
    // - Returns: true indicates the target resolution succeeded; false indicates failure.
    bool querySymbolicLinkTargetInternal(
        const NtKernelObjectApi& api,
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

        ULONG targetChars = kInitialSymbolicLinkChars;
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

        statusTextOut = kernelText("kernel.device_driver.worker.symbolic_link_retry_limit", QStringLiteral("符号链接目标解析重试达到上限。"));
        return false;
    }

    // enumerateDirectoryEntries：
    // - Input: API handle and directory path;
    // - Processing: Loop calling NtQueryDirectoryObject to extract object names and types one by one.
    // - Returns: true if directory enumeration completed; false if a fatal error occurred mid-way.
    bool enumerateDirectoryEntries(
        const NtKernelObjectApi& api,
        const QString& directoryPathText,
        std::vector<KernelDeviceDriverObjectEntry>& rowsOut,
        NTSTATUS& statusCodeOut,
        bool& truncatedOut)
    {
        rowsOut.clear();
        statusCodeOut = kStatusUnsuccessful;
        truncatedOut = false;

        ScopedNtHandle directoryHandle;
        statusCodeOut = openDirectoryHandle(api, directoryPathText, directoryHandle.handle);
        if (!NT_SUCCESS(statusCodeOut))
        {
            return false;
        }

        ULONG queryContext = 0;
        BOOLEAN restartScan = TRUE;
        ULONG queryBufferSize = kInitialDirectoryQueryBuffer;

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

            KernelDeviceDriverObjectEntry entry;
            entry.directoryPathText = normalizePathText(directoryPathText);
            entry.objectNameText = kObjectNameText;
            entry.objectTypeText = kObjectTypeText.isEmpty()
                ? kernelText("kernel.device_driver.worker.placeholder.unknown", QStringLiteral("<未知>"))
                : kObjectTypeText;
            entry.fullPathText = joinObjectPath(entry.directoryPathText, entry.objectNameText);
            entry.querySucceeded = true;
            entry.statusCode = queryStatus;
            entry.isDirectory = entry.objectTypeText.compare(QStringLiteral("Directory"), Qt::CaseInsensitive) == 0;
            entry.isSymbolicLink = entry.objectTypeText.compare(QStringLiteral("SymbolicLink"), Qt::CaseInsensitive) == 0;
            entry.statusText = kernelText("kernel.device_driver.worker.status.enumerated", QStringLiteral("已枚举"));
            entry.capabilityHintText = kernelText("kernel.device_driver.worker.capability.inspect_properties", QStringLiteral("叶子对象，建议查属性"));

            if (entry.isDirectory)
            {
                entry.capabilityHintText = kernelText("kernel.device_driver.worker.capability.directory_recursive", QStringLiteral("可用目录递归继续展开（本 tab 不做深递归）"));
            }
            else if (entry.isSymbolicLink)
            {
                QString targetText;
                QString targetStatusText;
                if (querySymbolicLinkTargetInternal(api, entry.fullPathText, targetText, targetStatusText))
                {
                    entry.targetPathText = targetText;
                    entry.statusText = kernelText("kernel.device_driver.worker.status.symbolic_link_resolved", QStringLiteral("已枚举，符号链接目标已解析"));
                    entry.capabilityHintText = kernelText("kernel.device_driver.worker.capability.symbolic_link", QStringLiteral("可解析符号链接，用于理解设备路径"));
                }
                else
                {
                    entry.targetPathText = QString();
                    entry.statusText = kernelText("kernel.device_driver.worker.status.symbolic_link_failed", QStringLiteral("已枚举，符号链接目标解析失败：%1")).arg(targetStatusText);
                    entry.capabilityHintText = kernelText("kernel.device_driver.worker.capability.symbolic_link", QStringLiteral("可解析符号链接，用于理解设备路径"));
                }
            }
            else if (entry.objectTypeText.compare(QStringLiteral("Device"), Qt::CaseInsensitive) == 0)
            {
                entry.capabilityHintText = kernelText("kernel.device_driver.worker.capability.inspect_properties", QStringLiteral("叶子对象，建议查属性"));
            }
            else if (entry.objectTypeText.compare(QStringLiteral("Driver"), Qt::CaseInsensitive) == 0)
            {
                entry.capabilityHintText = kernelText("kernel.device_driver.worker.capability.driver_analysis", QStringLiteral("叶子对象，建议结合服务名和加载顺序分析"));
            }
            else if (entry.objectTypeText.compare(QStringLiteral("FileSystem"), Qt::CaseInsensitive) == 0)
            {
                entry.capabilityHintText = kernelText("kernel.device_driver.worker.capability.filesystem_analysis", QStringLiteral("叶子对象，建议结合挂载卷与过滤器链路分析"));
            }

            entry.detailText = kernelText(
                "kernel.device_driver.worker.detail.entry",
                QStringLiteral(
                    "目录路径: %1\n"
                    "对象名称: %2\n"
                    "对象类型: %3\n"
                    "完整路径: %4\n"
                    "符号链接目标: %5\n"
                    "状态: %6\n"
                    "能力提示: %7"))
                .arg(
                    entry.directoryPathText,
                    entry.objectNameText,
                    entry.objectTypeText,
                    entry.fullPathText,
                    entry.targetPathText.isEmpty()
                        ? kernelText("kernel.device_driver.worker.placeholder.no_target", QStringLiteral("<无>"))
                        : entry.targetPathText,
                    entry.statusText,
                    entry.capabilityHintText);
            rowsOut.push_back(std::move(entry));
        }

        truncatedOut = true;
        statusCodeOut = kStatusSuccess;
        return true;
    }

    // buildScopeEntry：
    // - Input: Directory spec, enumeration status, and success flag;
    // - Handling: Generate a single read-only 'directory scope' description line to help the UI understand the current grouping.
    // - Returns: an entry that can be directly added to the result set.
    KernelDeviceDriverObjectEntry buildScopeEntry(
        const RootSpec& rootSpec,
        const NTSTATUS statusCode,
        const bool querySucceeded)
    {
        KernelDeviceDriverObjectEntry entry;
        entry.directoryPathText = normalizePathText(rootSpec.directoryPathText);
        entry.objectNameText = entry.directoryPathText.section('\\', -1, -1).trimmed();
        if (entry.objectNameText.isEmpty())
        {
            entry.objectNameText = entry.directoryPathText;
        }
        entry.objectTypeText = QStringLiteral("Directory");
        entry.fullPathText = entry.directoryPathText;
        entry.targetPathText = QString();
        entry.statusCode = statusCode;
        entry.querySucceeded = querySucceeded;
        entry.isDirectory = true;
        entry.isSymbolicLink = false;
        entry.isScopeEntry = true;
        entry.statusText = querySucceeded
            ? kernelText("kernel.device_driver.worker.status.directory_opened", QStringLiteral("目录已打开，可继续枚举"))
            : ntStatusToText(::GetModuleHandleW(L"ntdll.dll"), statusCode);
        entry.capabilityHintText = kernelText("kernel.device_driver.worker.capability.directory_recursive", QStringLiteral("可用目录递归继续展开（本 tab 不做深递归）"));
        entry.detailText = kernelText(
            "kernel.device_driver.worker.detail.scope",
            QStringLiteral(
                "目录路径: %1\n"
                "目录标题: %2\n"
                "目录说明: %3\n"
                "状态: %4\n"
                "能力提示: %5"))
            .arg(
                entry.directoryPathText,
                rootSpec.displayNameText,
                rootSpec.descriptionText,
                entry.statusText,
                entry.capabilityHintText);
        return entry;
    }

    // buildRootSpecList：
    // - Inputs: None;
    // - Processing: Return the four object directories to enumerate in this specific view.
    // - Returns: Directory specification list.
    std::vector<RootSpec> buildRootSpecList()
    {
        return {
            {
                QStringLiteral("\\Device"),
                QStringLiteral("Device"),
                kernelText("kernel.device_driver.worker.scope.device", QStringLiteral("设备对象与设备符号链接")),
            },
            {
                QStringLiteral("\\Driver"),
                QStringLiteral("Driver"),
                kernelText("kernel.device_driver.worker.scope.driver", QStringLiteral("已加载驱动对象")),
            },
            {
                QStringLiteral("\\FileSystem"),
                QStringLiteral("FileSystem"),
                kernelText("kernel.device_driver.worker.scope.filesystem", QStringLiteral("文件系统驱动对象")),
            },
            {
                QStringLiteral("\\FileSystem\\Filters"),
                QStringLiteral("FileSystem\\Filters"),
                kernelText("kernel.device_driver.worker.scope.filters", QStringLiteral("文件系统过滤器对象")),
            },
        };
    }
}

// runKernelDeviceDriverObjectsSnapshotTask：
// - Input: rowsOut receives all read-only enumeration results; errorTextOut receives the fatal error reason;
// - Processing: enumerate four object directories and resolve symbolic link targets; all information is for diagnostic display only.
// - Returns: true if enumeration completed successfully; false indicates unrecoverable errors such as ntdll loading failure.
bool runKernelDeviceDriverObjectsSnapshotTask(
    std::vector<KernelDeviceDriverObjectEntry>& rowsOut,
    QString& errorTextOut)
{
    rowsOut.clear();
    errorTextOut.clear();

    KLogEvent taskEvent;
    info << taskEvent << "[KernelDeviceDriverObjectsWorker] 开始枚举设备与驱动对象。" << eol;

    NtKernelObjectApi api;
    if (!loadNtKernelObjectApi(api, errorTextOut))
    {
        err << taskEvent
            << "[KernelDeviceDriverObjectsWorker] Nt API 装载失败: "
            << errorTextOut.toStdString()
            << eol;
        return false;
    }

    std::vector<KernelDeviceDriverObjectEntry> resultRows;
    const std::vector<RootSpec> kRootSpecList = buildRootSpecList();

    for (const RootSpec& rootSpec : kRootSpecList)
    {
        std::vector<KernelDeviceDriverObjectEntry> directoryRows;
        NTSTATUS directoryStatus = kStatusUnsuccessful;
        bool truncated = false;
        const bool kEnumerateOk = enumerateDirectoryEntries(
            api,
            rootSpec.directoryPathText,
            directoryRows,
            directoryStatus,
            truncated);

        resultRows.push_back(buildScopeEntry(rootSpec, directoryStatus, kEnumerateOk));

        if (!kEnumerateOk)
        {
            continue;
        }

        std::sort(directoryRows.begin(), directoryRows.end(), [](const KernelDeviceDriverObjectEntry& left, const KernelDeviceDriverObjectEntry& right) {
            if (left.isScopeEntry != right.isScopeEntry)
            {
                return left.isScopeEntry && !right.isScopeEntry;
            }

            const int kTypeCompare = QString::compare(left.objectTypeText, right.objectTypeText, Qt::CaseInsensitive);
            if (kTypeCompare != 0)
            {
                return kTypeCompare < 0;
            }

            return QString::compare(left.objectNameText, right.objectNameText, Qt::CaseInsensitive) < 0;
        });

        for (KernelDeviceDriverObjectEntry& entry : directoryRows)
        {
            entry.detailText = kernelText(
                "kernel.device_driver.worker.detail.entry",
                QStringLiteral(
                    "目录路径: %1\n"
                    "对象名称: %2\n"
                    "对象类型: %3\n"
                    "完整路径: %4\n"
                    "符号链接目标: %5\n"
                    "状态: %6\n"
                    "能力提示: %7"))
                .arg(
                    entry.directoryPathText,
                    entry.objectNameText,
                    entry.objectTypeText,
                    entry.fullPathText,
                    entry.targetPathText.isEmpty()
                        ? kernelText("kernel.device_driver.worker.placeholder.no_target", QStringLiteral("<无>"))
                        : entry.targetPathText,
                    entry.statusText,
                    entry.capabilityHintText);
            resultRows.push_back(std::move(entry));
        }

        if (truncated)
        {
            KernelDeviceDriverObjectEntry truncatedEntry;
            truncatedEntry.directoryPathText = normalizePathText(rootSpec.directoryPathText);
            truncatedEntry.objectNameText = kernelText("kernel.device_driver.worker.placeholder.truncated", QStringLiteral("<已截断>"));
            truncatedEntry.objectTypeText = QStringLiteral("<Info>");
            truncatedEntry.fullPathText = rootSpec.directoryPathText;
            truncatedEntry.targetPathText = QString();
            truncatedEntry.statusCode = kStatusSuccess;
            truncatedEntry.querySucceeded = true;
            truncatedEntry.isDirectory = false;
            truncatedEntry.isSymbolicLink = false;
            truncatedEntry.isScopeEntry = false;
            truncatedEntry.statusText = kernelText("kernel.device_driver.worker.status.directory_limit", QStringLiteral("达到单目录上限 %1 项")).arg(kMaxEntriesPerDirectory);
            truncatedEntry.capabilityHintText = kernelText("kernel.device_driver.worker.capability.filter_current", QStringLiteral("可继续筛选当前结果，避免一次性加载更大范围"));
            truncatedEntry.detailText = kernelText(
                "kernel.device_driver.worker.detail.truncated",
                QStringLiteral(
                    "目录路径: %1\n"
                    "提示: 为避免 UI 卡顿，单目录结果已截断到 %2 项。"))
                .arg(
                    truncatedEntry.directoryPathText,
                    QString::number(kMaxEntriesPerDirectory));
            resultRows.push_back(std::move(truncatedEntry));
        }
    }

    std::sort(resultRows.begin(), resultRows.end(), [](const KernelDeviceDriverObjectEntry& left, const KernelDeviceDriverObjectEntry& right) {
        const int kDirectoryCompare = QString::compare(left.directoryPathText, right.directoryPathText, Qt::CaseInsensitive);
        if (kDirectoryCompare != 0)
        {
            return kDirectoryCompare < 0;
        }

        if (left.isScopeEntry != right.isScopeEntry)
        {
            return left.isScopeEntry && !right.isScopeEntry;
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
    for (const KernelDeviceDriverObjectEntry& row : rowsOut)
    {
        if (!row.querySucceeded)
        {
            ++failedCount;
        }
    }

    info << taskEvent
        << "[KernelDeviceDriverObjectsWorker] 枚举完成, rowCount="
        << rowsOut.size()
        << ", failedCount="
        << failedCount
        << eol;
    return true;
}
