#pragma once

// ============================================================
// ksword/file/file_handle_tools.h
// Namespace: ks::file.
// Purpose:
// - Provide path normalization, system handle enumeration, NtQueryObject/NtQuerySystemInformation
//   wrappers, and file occupancy scanning capabilities shared by FileDock and Handle Dock;
// - This layer exposes only std text types and Win32 basic types, with no dependency on Qt controls or UI string types.
// - UI layer is responsible for converting results into table, color, button state, and progress bar displays.
// ============================================================

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <winternl.h>

namespace ks::file
{
    // ProgressCallback:
    // - Report plain text stage and percentage during backend scanning.
    // - The UI can be redirected to kPro/status bar; command-line callers may ignore it.
    using ProgressCallback = std::function<void(const std::string& stepText, float progressValue)>;

    // CancellationCallback:
    // - Ensure time-consuming handle scanning terminates promptly when FileDock closes or the user cancels;
    // - Returns true to indicate the caller no longer needs the current round of results; the backend performs only necessary resource cleanup.
    using CancellationCallback = std::function<bool()>;

    // HandleEnumMode:
    // - Describes the enumeration path used to build the handle snapshot.
    // - Maintains semantic consistency with the UI dropdown in the handle Dock, but does not depend on the UI enum.
    enum class HandleEnumMode : int
    {
        kUserSnapshot = 0,      // UserSnapshot: Collects R3 system handle snapshots only.
        kDuplicateHandle = 1,   // DuplicateHandle: after the R3 snapshot, duplicate the handle and resolve the reference count and object name.
        kKernelHandleTable = 2  // KernelHandleTable: Superimposes R0 HandleTable differences on top of the R3 snapshot.
    };

    // HandleDiffStatus:
    // - Describes the difference status in the R3/R0 dual-source enumeration.
    // - The UI layer is responsible only for rendering this as localized text.
    enum class HandleDiffStatus : int
    {
        kNotCompared = 0,
        kUserOnly,
        kKernelOnly,
        kBoth
    };

    // NtApiSet:
    // - Stores the dynamically resolved ntdll entry point;
    // - Callers can reuse the same function pointer to avoid repeated GetProcAddress calls.
    struct NtApiSet
    {
        using NtQuerySystemInformationFn = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
        using NtQueryObjectFn = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

        HMODULE ntdllModule = nullptr;                               // ntdllModule: Handle to the ntdll module, valid for the process lifetime.
        NtQuerySystemInformationFn querySystemInformation = nullptr; // querySystemInformation: Address of NtQuerySystemInformation.
        NtQueryObjectFn queryObject = nullptr;                       // queryObject: Address of NtQueryObject.

        // ready: Determines if the current Nt API dynamic loading meets the minimum handle functionality requirements.
        bool ready() const;
    };

    // RawSystemHandle:
    // - Represents the safe decoded result of NtQuerySystemInformation(SystemExtendedHandleInformation).
    // - Retain only fields shared between the UI and the scanning backend.
    struct RawSystemHandle
    {
        std::uint32_t processId = 0;
        std::uint64_t handleValue = 0;
        std::uint16_t typeIndex = 0;
        std::uint64_t objectAddress = 0;
        std::uint32_t grantedAccess = 0;
        std::uint32_t attributes = 0;
    };

    // ObjectBasicInfo:
    // - Wraps handle and pointer counts from ObjectBasicInformation;
    // - Suppress layout differences of fields not exposed in the SDK headers.
    struct ObjectBasicInfo
    {
        std::uint32_t handleCount = 0;
        std::uint32_t pointerCount = 0;
    };

    // ObjectNameQueryResult:
    // - Represents the complete status of an object name resolution.
    // - Distinguish between 'found empty name' and 'query failed'.
    struct ObjectNameQueryResult
    {
        bool available = false;
        bool failed = false;
        bool usedFallback = false;
        std::wstring objectName;
    };

    // TargetPathPattern:
    // - Represents a comparison rule in file occupation scanning.
    // - displayPath retains the user-view path; normalizedPath is used for case-insensitive matching.
    struct TargetPathPattern
    {
        std::wstring displayPath;
        std::wstring normalizedPath;
        bool directoryMode = false;
    };

    // ReparsePointQueryResult:
    // - Represents the complete result of a single FSCTL_GET_REPARSE_POINT query.
    // - Retains both structured fields and raw information required for degraded display;
    // - Callers can reuse the same result in property pages, list column text, or right-click actions.
    struct ReparsePointQueryResult
    {
        bool pathOpened = false;                 // pathOpened: Whether the handle was successfully obtained via 'open reparse point'.
        bool querySucceeded = false;             // querySucceeded: indicates whether FSCTL_GET_REPARSE_POINT returned successfully.
        bool isReparsePoint = false;             // isReparsePoint: Whether the target is confirmed as a reparse point.
        bool isMicrosoftTag = false;             // isMicrosoftTag: Whether the tag is a Microsoft predefined tag.
        bool isNameSurrogate = false;            // isNameSurrogate: Whether it is a 'name surrogate' type reparse point.
        bool isRelative = false;                 // isRelative: Only meaningful for symbolic links; indicates whether it is a relative link.
        std::uint32_t tag = 0;                   // tag: The original 32-bit value of the reparse point tag.
        std::wstring tagName;                    // tagName: Human-readable tag name, e.g., IO_REPARSE_TAG_SYMLINK.
        std::wstring kindName;                   // kindName: Category name for UI display, e.g., SYMLINK/JUNCTION/MOUNT_POINT.
        std::wstring substituteName;            // substituteName: Substitute Name in the reparse buffer.
        std::wstring printName;                 // printName: Print Name in the reparse buffer.
        std::wstring resolvedTargetPath;        // resolvedTargetPath: Final target path after resolution attempts.
        std::wstring rawPayloadText;             // rawPayloadText: Raw text or summary when structured parsing fails.
        std::wstring rawHexPreview;             // rawHexPreview: Hexadecimal summary of the raw buffer for fallback troubleshooting.
        std::wstring errorText;                 // errorText: Reason for open or query failure; does not block UI display.
        std::uint32_t win32Error = 0;            // win32Error: Raw GetLastError result.
    };

    // HandleSnapshotOptions:
    // - Package input conditions for background refresh of the Handle Dock.
    // - All fields are std types to prevent the backend layer from reading Qt controls.
    struct HandleSnapshotOptions
    {
        bool hasPidFilter = false;
        std::uint32_t pidFilter = 0;
        std::wstring typeFilterText;
        bool resolveObjectName = true;
        int nameResolveBudget = 300;
        int basicInfoQueryBudget = -1; // < 0 indicates no limit; avoids iterating and counting all system handles in read-only scenarios.
        HandleEnumMode enumMode = HandleEnumMode::kDuplicateHandle;
        std::unordered_map<std::uint16_t, std::string> typeNameCacheByIndex;
        std::unordered_map<std::uint16_t, std::string> typeNameMapFromObjectTab;
    };

    // HandleSnapshotRow:
    // - A single row of backend data that the Handle Dock can render directly;
    // - Excludes UI state such as colors, table items, and icons
    struct HandleSnapshotRow
    {
        std::uint32_t processId = 0;
        std::uint64_t processCreationTime = 0;
        std::wstring processName;
        std::uint64_t handleValue = 0;
        std::uint16_t typeIndex = 0;
        std::wstring typeName;
        std::wstring objectName;
        std::uint64_t objectAddress = 0;
        std::uint32_t grantedAccess = 0;
        std::uint32_t attributes = 0;
        std::uint32_t handleCount = 0;
        std::uint32_t pointerCount = 0;
        bool basicInfoAvailable = false;
        bool objectNameAvailable = false;
        bool objectNameFailed = false;
        bool objectNameFromFallback = false;
        HandleEnumMode sourceMode = HandleEnumMode::kUserSnapshot;
        HandleDiffStatus diffStatus = HandleDiffStatus::kNotCompared;
        std::uint32_t decodeStatus = 0;
        std::uint32_t r0FieldFlags = 0;
        std::uint64_t r0DynDataCapabilityMask = 0;
        std::uint32_t epObjectTableOffset = 0xFFFFFFFFUL;
        std::uint32_t htHandleContentionEventOffset = 0xFFFFFFFFUL;
        std::uint32_t obDecodeShift = 0xFFFFFFFFUL;
        std::uint32_t obAttributesShift = 0xFFFFFFFFUL;
        std::uint32_t otNameOffset = 0xFFFFFFFFUL;
        std::uint32_t otIndexOffset = 0xFFFFFFFFUL;
    };

    // HandleSnapshotResult:
    // - Aggregate results from one round of background refresh for the Handle Dock;
    // - Keep diagnostic text as wide strings so the UI can directly convert them to interface strings.
    struct HandleSnapshotResult
    {
        std::vector<HandleSnapshotRow> rows;
        std::vector<std::wstring> availableTypeList;
        std::unordered_map<std::uint16_t, std::string> updatedTypeNameCacheByIndex;
        std::size_t totalHandleCount = 0;
        std::size_t visibleHandleCount = 0;
        std::size_t basicInfoResolvedCount = 0;
        std::size_t resolvedNameCount = 0;
        std::size_t fallbackNameCount = 0;
        std::size_t objectTypeMappedCount = 0;
        std::size_t kernelHandleCount = 0;
        std::size_t userOnlyCount = 0;
        std::size_t kernelOnlyCount = 0;
        std::size_t bothCount = 0;
        std::uint64_t elapsedMs = 0;
        std::wstring diagnosticText;
    };

    // HandleUsageEntry:
    // - Represents a source found during file/directory usage scanning.
    // - May originate from a real file handle, process image, or module snapshot.
    struct HandleUsageEntry
    {
        std::uint32_t processId = 0;
        std::uint64_t processCreationTime = 0; // processCreationTime: Creation time from GetProcessTimes, used to prevent PID reuse.
        std::wstring processName;
        std::wstring processImagePath;
        std::uint64_t handleValue = 0;
        std::uint16_t typeIndex = 0;
        std::wstring typeName;
        std::wstring objectName;
        std::uint32_t grantedAccess = 0;
        std::uint32_t attributes = 0;
        std::wstring matchedTargetPath;
        bool matchedByDirectoryRule = false;
        std::wstring matchRuleText;
        std::wstring enumerationSource;
    };

    // HandleUsageScanOptions:
    // - Control file usage scan strategy;
    // - By default, first attempt R0 HandleTable, falling back to R3 DuplicateHandle only when the R0 backend is unavailable;
    // - R0 success without a target hit is a valid empty result; do not re-scan the R3 handle table.
    struct HandleUsageScanOptions
    {
        bool tryKernelHandleTable = true;
        ProgressCallback progressCallback;
        CancellationCallback cancellationCallback;
    };

    // HandleUsageScanResult:
    // - Aggregates FileDock file usage scan results and statistics.
    // - The UI layer is only responsible for displaying entries and diagnosticText.
    struct HandleUsageScanResult
    {
        std::vector<HandleUsageEntry> entries;
        std::size_t totalHandleCount = 0;
        std::size_t fileLikeHandleCount = 0;
        std::size_t matchedHandleCount = 0;
        std::size_t processImageMatchCount = 0;
        std::size_t loadedModuleMatchCount = 0;
        std::size_t kernelHandleMatchCount = 0;
        bool kernelHandleTableAttempted = false; // kernelHandleTableAttempted: Indicates whether the R0 HandleTable path was invoked in this round.
        bool kernelHandleTableUsed = false;      // kernelHandleTableUsed: Whether the R0 path is available and used as the source for file handle results.
        bool r3HandleFallbackUsed = false;       // r3HandleFallbackUsed: Indicates whether to fall back to R3 DuplicateHandle after R0 becomes unavailable.
        std::uint64_t elapsedMs = 0;
        std::wstring diagnosticText;
    };

    // normalizeNativePath purpose: Unify Windows path separators and long path prefixes.
    std::wstring normalizeNativePath(const std::wstring& pathText);

    // normalizePathForCompare purpose: Generate a case-insensitive comparison key without trailing separators.
    std::wstring normalizePathForCompare(const std::wstring& pathText);

    // buildNtPathEquivalent purpose: Convert DOS/UNC paths to NT device paths.
    bool buildNtPathEquivalent(const std::wstring& absolutePath, std::wstring& ntPathOut);

    // buildTargetPathPatterns purpose: Generate DOS/NT dual-perspective matching rules for a set of user paths.
    std::vector<TargetPathPattern> buildTargetPathPatterns(const std::vector<std::wstring>& absolutePaths);

    // matchTargetPath purpose: Matches candidate paths against exact file or directory prefix rules.
    bool matchTargetPath(
        const std::wstring& normalizedCandidatePath,
        const std::vector<TargetPathPattern>& patternList,
        std::wstring& matchedTargetPathOut,
        bool& matchedByDirectoryRuleOut);

    // queryNtApis purpose: Dynamically load NtQuerySystemInformation and NtQueryObject.
    NtApiSet queryNtApis();

    // querySystemHandles: Safely read an extended system handle snapshot.
    bool querySystemHandles(
        const NtApiSet& apiSet,
        std::vector<RawSystemHandle>& recordsOut,
        std::wstring& diagnosticTextOut,
        const CancellationCallback& cancellationCallback = {});

    // queryNtObjectText purpose: Read the UNICODE_STRING text returned by NtQueryObject.
    bool queryNtObjectText(
        const NtApiSet& apiSet,
        HANDLE objectHandle,
        ULONG informationClass,
        std::wstring& textOut);

    // queryReparsePointInfo:
    // - Open the file or directory with FILE_FLAG_OPEN_REPARSE_POINT.
    // - Read the reparse buffer via FSCTL_GET_REPARSE_POINT;
    // - Generate human-readable results for SYMLINK / MOUNT_POINT / APPEXECLINK while preserving original downgrade information.
    // Input parameter absolutePath:
    // - DOS/UNC absolute path of the target file or directory.
    // Parameter directoryHint:
    // - true indicates the target is more likely a directory, allowing FILE_FLAG_BACKUP_SEMANTICS to be appended when opening the directory handle;
    // Return value:
    // - The structure always returns; the caller determines the display hierarchy based on pathOpened, querySucceeded, and isReparsePoint.
    ReparsePointQueryResult queryReparsePointInfo(
        const std::wstring& absolutePath,
        bool directoryHint);

    // queryObjectBasicInfo purpose: Read the object's HandleCount and PointerCount.
    bool queryObjectBasicInfo(
        const NtApiSet& apiSet,
        HANDLE objectHandle,
        ObjectBasicInfo& basicInfoOut);

    // resolveObjectNameText purpose: First call NtQueryObject, then follow the fallback path based on the object type.
    ObjectNameQueryResult resolveObjectNameText(
        const NtApiSet& apiSet,
        HANDLE objectHandle,
        const std::wstring& typeNameText);

    // duplicateRemoteHandleToLocal: Copies a handle from the target process to the current process; the caller is responsible for calling CloseHandle.
    bool duplicateRemoteHandleToLocal(
        HANDLE sourceProcessHandle,
        std::uint64_t handleValue,
        HANDLE& localHandleOut);

    // queryFinalDosPathByHandle: Read the standard DOS path with GetFinalPathNameByHandleW.
    bool queryFinalDosPathByHandle(HANDLE objectHandle, std::wstring& pathOut);

    // openProcessForVerifiedAction:
    // - Open the target process and verify the creation time recorded during scanning;
    // - The caller must call CloseHandle upon success, and the PID will not be reused for a new process while the handle is held.
    bool openProcessForVerifiedAction(
        std::uint32_t processId,
        std::uint64_t expectedCreationTime,
        DWORD desiredAccess,
        HANDLE& processHandleOut,
        std::string& detailTextOut);

    // closeRemoteHandle:
    // - Validate process creation time against the file path associated with the current handle.
    // - Suspend the target process, then close the verified handle via DuplicateHandle(DUPLICATE_CLOSE_SOURCE).
    bool closeRemoteHandle(
        std::uint32_t processId,
        std::uint64_t handleValue,
        std::uint64_t expectedProcessCreationTime,
        const std::wstring& expectedTargetPath,
        bool expectedDirectoryMatch,
        std::string& detailTextOut);

    // closeRemoteHandleByObjectIdentity:
    // - Verifies handles of any type using process creation time plus object addresses from the system handle snapshot.
    // - Used by HandleDock for single and batch close operations; reject stale or unverifiable rows.
    bool closeRemoteHandleByObjectIdentity(
        std::uint32_t processId,
        std::uint64_t handleValue,
        std::uint64_t expectedProcessCreationTime,
        std::uint64_t expectedObjectAddress,
        std::string& detailTextOut);

    // buildHandleSnapshot purpose: Construct the complete backend snapshot used by the Handle Dock.
    HandleSnapshotResult buildHandleSnapshot(const HandleSnapshotOptions& options);

    // scanHandleUsageByPaths purpose: scan usage sources by file/directory paths.
    HandleUsageScanResult scanHandleUsageByPaths(
        const std::vector<std::wstring>& absolutePaths,
        const HandleUsageScanOptions& options = HandleUsageScanOptions{});
}
