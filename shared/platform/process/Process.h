#pragma once

// ============================================================
// ksword/process/process.h
// Namespace:
// ks::process Purpose:
// - Encapsulate Win32 APIs for process enumeration, process details, and process control;
// - For direct invocation by UI layers such as ProcessDock;
// - Can be reused as an independent tool library after decoupling from the project.
// ============================================================

#include <cstdint> // std::uint32_t/std::uint64_t: PID, counter, and timestamp.
#include <string>  // std::string: Unified text type across layers (UTF-8).
#include <vector>  // std::vector: Process list container.

#include "../../driver/KswordArkProcessIoctl.h" // R0 process extension field constants.
#include "../../driver/KswordArkDynDataIoctl.h" // R0 DynData field source constants.
#include "../../driver/KswordArkThreadIoctl.h"  // R0 thread extension field constants.

namespace ks::process
{
    // ProcessEnumStrategy: Process enumeration strategy.
    enum class ProcessEnumStrategy
    {
        kSnapshotProcess32 = 0,   // CreateToolhelp32Snapshot + Process32First/Next。
        kNtQuerySystemInfo = 1,   // NtQuerySystemInformation(SystemProcessInformation)。
        kAuto = 2                 // Auto: Prefer NtQuery; fall back to Snapshot on failure.
    };

    // ProcessFeatureState：
    // - Purpose: Unify expression of tri-state/tetra-state switch fields (DEP, Control Flow Guard, UAC virtualization, etc.) that require additional queries to determine.
    // - Unknown indicates data was not collected or the query failed; the UI layer displays a placeholder instead of fabricating a "disabled" state.
    enum class ProcessFeatureState : std::uint32_t
    {
        kUnknown = 0,     // Not collected or query failed.
        kNotAllowed,      // This feature is not applicable to the target process (e.g., 64-bit processes do not support UAC virtualization).
        kDisabled,        // Disabled.
        kEnabled,         // Enabled.
        kEnabledPermanent // Enabled and cannot be changed (DEP permanently enabled).
    };

    // ProcessDpiAwarenessLevel：
    // - Purpose: Represent the value for the Task Manager 'DPI Awareness' column.
    // - Unknown indicates data has not been collected or the target process refused the query; the UI displays a placeholder based on this.
    enum class ProcessDpiAwarenessLevel : std::uint32_t
    {
        kUnknown = 0,        // Not collected or query failed.
        kUnaware,            // DPI is unrecognized.
        kSystemAware,        // System DPI awareness.
        kPerMonitorAware,    // Per-monitor DPI awareness.
        kPerMonitorAwareV2,  // Per-monitor DPI awareness V2.
        kUnawareGdiScaled    // Unrecognized (GDI scaling).
    };

    // process_detail_demand：
    // - Purpose: Describe the set of process fields that require additional cost to collect in this round.
    // - Usage: ProcessDock calculates the bitmap based on currently visible columns and dispatches it; unrequested fields retain default values;
    // - Goal: Limit the collection cost of Task Manager's aligned columns to only the columns actually displayed by the user, incurring zero overhead for the default layout.
    namespace process_detail_demand
    {
        constexpr std::uint32_t kNone = 0x00000000U;              // Do not collect any on-demand fields.
        constexpr std::uint32_t kGuiResources = 0x00000001U;      // GDI / USER object count (dynamic, changes each round).
        constexpr std::uint32_t kJobObject = 0x00000002U;         // Job object ownership (static).
        constexpr std::uint32_t kMitigationPolicy = 0x00000004U;  // Data Execution Prevention and Control Flow Protection (static).
        constexpr std::uint32_t kUacVirtualization = 0x00000008U; // Token UAC virtualization state (static).
        constexpr std::uint32_t kFileDescription = 0x00000010U;   // Description in the image version resource (static, cached by path).
        constexpr std::uint32_t kOsContext = 0x00000020U;         // Image manifest supportedOS (static, cached by path).
        constexpr std::uint32_t kEnterpriseContext = 0x00000040U; // Enterprise context (WIP/EDP, static).
        constexpr std::uint32_t kGpuMemory = 0x00000080U;         // GPU dedicated/shared video memory (dynamic, PDH global once).
        constexpr std::uint32_t kGpuEngine = 0x00000100U;         // GPU engine name (dynamic, PDH global once).
        constexpr std::uint32_t kPackageName = 0x00000200U;        // UWP package full name (static).
        constexpr std::uint32_t kDpiAwareness = 0x00000400U;       // Process DPI awareness level (static).

        // PerProcessHandleMask: Bitmask for handles that must be opened individually per process for collection.
        constexpr std::uint32_t kPerProcessHandleMask =
            kGuiResources | kJobObject | kMitigationPolicy | kUacVirtualization |
            kEnterpriseContext | kPackageName | kDpiAwareness;

        // ImageFileMask: A bitset relying solely on image files, cacheable by path.
        constexpr std::uint32_t kImageFileMask = kFileDescription | kOsContext;

        // GpuMask: A bitset covering all processes with a single global PDH sample.
        constexpr std::uint32_t kGpuMask = kGpuMemory | kGpuEngine;
    }

    // ProcessPriorityLevel: Process priority enumeration (maps to Win32 PriorityClass).
    enum class ProcessPriorityLevel
    {
        kIdle = 0,
        kBelowNormal,
        kNormal,
        kAboveNormal,
        kHigh,
        kRealtime
    };

    // TokenPrivilegeAction: Token privilege adjustment action (used by AdjustTokenPrivileges).
    enum class TokenPrivilegeAction
    {
        kKeep = 0,   // Keep current state without adjustment.
        kEnable,     // Enable this privilege.
        kDisable,    // Disable this privilege.
        kRemove      // Remove this privilege from the token (high risk).
    };

    // TokenPrivilegeEdit: Single privilege adjustment request.
    struct TokenPrivilegeEdit
    {
        std::string privilegeName;               // For example, "SeDebugPrivilege".
        TokenPrivilegeAction action = TokenPrivilegeAction::kKeep;
    };

    // TokenPrivilegeState: Query status for a single privilege within the target process's token.
    enum class TokenPrivilegeState : std::uint32_t
    {
        kUnknown = 0,    // Failed to query privileged LUID; cannot safely display or adjust.
        kNotPresent,     // Target token does not contain this privilege.
        kDisabled,       // The target token contains this privilege, but it is currently disabled.
        kEnabled         // The target token contains this privilege, and it is currently enabled.
    };

    // TokenPrivilegeInfo: a privilege snapshot used uniformly by the process list, details page, and R0 fallback path.
    struct TokenPrivilegeInfo
    {
        std::string privilegeName;                         // Se*privilege names defined by the Windows SDK.
        TokenPrivilegeState state = TokenPrivilegeState::kUnknown;
        std::uint32_t attributes = 0;                      // Original Attributes in TOKEN_PRIVILEGES.
        std::uint32_t luidLowPart = 0;                     // Note: Low 32 bits of the LUID returned by LookupPrivilegeValue.
        std::int32_t luidHighPart = 0;                     // Note: High 32 bits of the LUID returned by LookupPrivilegeValue.
        bool luidKnown = false;                            // false indicates the name could not be resolved to a LUID.
    };

    struct TokenPrivilegeLuidEntry
    {
        std::uint32_t luidLowPart = 0;
        std::int32_t luidHighPart = 0;
        std::uint32_t attributes = 0;
    };

    // SecurityAttributesInput: Input mirror for the two SECURITY_ATTRIBUTES parameters of CreateProcessW.
    struct SecurityAttributesInput
    {
        bool useValue = false;                   // false -> pass nullptr.
        std::uint32_t nLength = 0;               // 0 indicates the implementation layer uses sizeof(SECURITY_ATTRIBUTES).
        std::uint64_t securityDescriptor = 0;    // Pointer address (0 indicates nullptr).
        bool inheritHandle = false;              // bInheritHandle。
    };

    // StartupInfoInput: STARTUPINFOW input mirror (all fields customizable via UI).
    struct StartupInfoInput
    {
        bool useValue = false;                   // false -> pass the default zero-initialized required STARTUPINFOW.
        std::uint32_t cb = 0;                    // 0 indicates using sizeof(STARTUPINFOW).
        std::string lpReserved;
        std::string lpDesktop;
        std::string lpTitle;
        std::uint32_t dwX = 0;
        std::uint32_t dwY = 0;
        std::uint32_t dwXSize = 0;
        std::uint32_t dwYSize = 0;
        std::uint32_t dwXCountChars = 0;
        std::uint32_t dwYCountChars = 0;
        std::uint32_t dwFillAttribute = 0;
        std::uint32_t dwFlags = 0;
        std::uint16_t wShowWindow = 0;
        std::uint16_t cbReserved2 = 0;
        std::uint64_t lpReserved2 = 0;
        std::uint64_t hStdInput = 0;
        std::uint64_t hStdOutput = 0;
        std::uint64_t hStdError = 0;
    };

    // ProcessInformationInput: Reserved PROCESS_INFORMATION form mirror.
    // CreateProcess* uses this structure as an output buffer; the implementation layer always passes
    // its own zero-initialized buffer, so pre-filled fields here are never used as API inputs.
    struct ProcessInformationInput
    {
        bool useValue = false;                   // Compatible with existing UI/serialization; never omit required output buffer.
        std::uint64_t hProcess = 0;
        std::uint64_t hThread = 0;
        std::uint32_t dwProcessId = 0;
        std::uint32_t dwThreadId = 0;
    };

    // CreateProcessRequest: Process creation parameter object (covers all CreateProcessW parameters + Token extensions).
    struct CreateProcessRequest
    {
        bool useApplicationName = false;         // false -> lpApplicationName is passed as nullptr.
        std::string applicationName;
        bool useCommandLine = false;             // false -> lpCommandLine is passed as nullptr.
        std::string commandLine;

        SecurityAttributesInput processAttributes;   // lpProcessAttributes。
        SecurityAttributesInput threadAttributes;    // lpThreadAttributes。

        bool inheritHandles = false;             // bInheritHandles。
        std::uint32_t creationFlags = 0;         // dwCreationFlags。

        bool useEnvironment = false;             // false -> lpEnvironment is passed as nullptr.
        bool environmentUnicode = true;          // When true, automatically attaches CREATE_UNICODE_ENVIRONMENT.
        std::vector<std::string> environmentEntries; // One "KEY=VALUE" per line.

        bool useCurrentDirectory = false;        // false -> pass nullptr to lpCurrentDirectory.
        std::string currentDirectory;

        StartupInfoInput startupInfo;            // lpStartupInfo。
        ProcessInformationInput processInfo;     // lpProcessInformation。

        // When tokenModeEnabled=false, call CreateProcessW;
        // When true, executes 'Open PID token + optional privilege adjustment + CreateProcessAsUserW'.
        bool tokenModeEnabled = false;
        std::uint32_t tokenSourcePid = 0;
        std::uint32_t tokenDesiredAccess = 0;    // 0 indicates the implementation layer uses the default access mask.
        bool duplicatePrimaryToken = true;       // When true, first call DuplicateTokenEx(TokenPrimary).
        std::vector<TokenPrivilegeEdit> tokenPrivilegeEdits;
    };

    // CreateProcessResult: A snapshot of the process creation result (for UI feedback and log output).
    struct CreateProcessResult
    {
        bool success = false;
        std::uint32_t win32Error = 0;
        std::string detailText;
        bool usedTokenPath = false;
        bool usedCreateProcessWithTokenFallback = false;
        bool processInfoAvailable = false;
        std::uint64_t hProcess = 0;             // Return snapshot: The backend has already called CloseHandle; it is no longer a valid handle.
        std::uint64_t hThread = 0;              // Return snapshot: The backend has already called CloseHandle; it is no longer a valid handle.
        std::uint32_t dwProcessId = 0;
        std::uint32_t dwThreadId = 0;
    };

    // SuspendedProcessLaunchFailure: Failure classification when creating a suspended target for process directed monitoring.
    // - Used by UI to distinguish between "requires administrator", "unable to downgrade token", and ordinary CreateProcess failures.
    enum class SuspendedProcessLaunchFailure
    {
        kNone = 0,
        kInvalidArgument,
        kAdministratorRequired,
        kUnelevatedTokenUnavailable,
        kCreateFailed
    };

    // SuspendedProcessLaunchRequest: Controlled creation parameters for process targeted monitoring.
    // - imagePath: absolute path of the target executable;
    // - argumentText: optional arguments appended verbatim to the command line;
    // - workingDirectory: target process working directory; null value indicates Windows decides.
    // - When runAsAdministrator is true, require the caller to be already elevated and do not trigger UAC;
    // - allowElevatedFallback: If a standard access token is unavailable, allow an explicit fallback to the current elevated token.
    struct SuspendedProcessLaunchRequest
    {
        std::string imagePath;
        std::string argumentText;
        std::string workingDirectory;
        bool runAsAdministrator = false;
        bool allowElevatedFallback = false;
    };

    // SuspendedProcessLaunchResult: Controlled suspended creation result.
    // - initialThreadHandle and processHandle are both valid Win32 handle snapshots; the caller must close them.
    // - Retain processHandle so that subsequent termination always targets the same process object created at launch, rather than re-querying by PID.
    struct SuspendedProcessLaunchResult
    {
        bool success = false;
        SuspendedProcessLaunchFailure failure = SuspendedProcessLaunchFailure::kNone;
        std::uint32_t win32Error = 0;
        std::string detailText;
        std::uint32_t processId = 0;
        std::uint32_t threadId = 0;
        std::uint64_t processHandle = 0;
        std::uint64_t initialThreadHandle = 0;
        bool usedUnelevatedToken = false;
        bool usedElevatedFallback = false;
    };

    // ProcessRecord: A single-process snapshot data structure.
    struct ProcessRecord
    {
        std::uint32_t pid = 0;             // Process ID.
        std::uint32_t parentPid = 0;       // Parent process ID.
        std::uint32_t threadCount = 0;     // Thread count (snapshot statistics).
        std::uint32_t handleCount = 0;     // Handle count (snapshot-time statistics; available under some policies).
        std::uint32_t sessionId = 0;       // Session ID (used to distinguish login sessions).

        // creationTime100ns：
        // - Process creation time (FILETIME 100ns base).
        // - Forms a stable identity together with PID (used for the "reuse old data" rule).
        std::uint64_t creationTime100ns = 0;

        std::string processName;           // Process name (display name).
        std::string imagePath;             // Full path of the executable file.
        std::string commandLine;           // Startup arguments (command line).
        std::string userName;              // Process token user (DOMAIN\\User).
        // signatureState: Signature text for direct UI display.
        // Typical value:
        // - "Microsoft Corporation (Trusted)"
        // - "Unknown Publisher (Untrusted)"
        // - "Unsigned"
        // - "Pending"
        std::string signatureState;
        std::string signaturePublisher;    // Name of the signature publisher (vendor).
        bool signatureTrusted = false;     // Whether the signature has been verified by the Windows trust chain.
        std::string startTimeText;         // Start time text (YYYY-MM-DD HH:MM:SS).
        std::string architectureText;      // Architecture text (x64/x86/ARM/Unknown).
        std::string priorityText;          // Priority text (Normal/High/...).
        bool efficiencyModeSupported = false; // Whether the efficiency mode status was successfully queried.
        bool efficiencyModeEnabled = false;   // Whether efficiency mode (PowerThrottling ExecutionSpeed) is enabled.
        bool isAdmin = false;              // Whether the process token is elevated (administrator privileges).
        std::uint32_t protectionLevel = 0;  // PPL protection level enumeration value, from manual snapshot refresh.
        bool protectionLevelKnown = false;  // protectionLevelKnown: true indicates PPL was manually queried in this round.
        std::string protectionLevelText;    // protectionLevelText: PPL enumeration text; remains empty if not refreshed.
        // Injection surface filtering (issue #196): populated only by manual actions, not by periodic refreshes.
        // injectionSurfaceState takes the numeric value from ksword::evidence::SurfaceScreenState;
        // When not Screened, the 0 values for the two counts below mean 'unknown', not 'none'.
        std::uint32_t injectionSurfaceState = 0;      // 0 = NotScreened
        std::uint32_t injectionDynamicRegions = 0;    // Count of dynamic/non-image executable regions
        std::uint32_t injectionWritableExecRegions = 0; // Writable and executable regions among them.
        std::uint64_t injectionDynamicBytes = 0;      // Dynamic code byte count

        // ======== Original performance counters (used for difference calculation between adjacent two rounds) ========
        std::uint64_t rawCpuTime100ns = 0;      // Total CPU time (Kernel + User) in 100ns units.
        std::uint64_t rawWorkingSetBytes = 0;   // Working set memory in bytes.
        std::uint64_t rawPrivateBytes = 0;      // Private committed/allocated memory in bytes.
        std::uint64_t rawIoBytes = 0;           // Cumulative bytes for Read/Write/Other transfers.

        // ======== UI-Directly Displayed Derived Performance Data ========
        double cpuPercent = 0.0;           // CPU percentage (normalized relative to all logical processors, 0~100).
        double cpuCorePercent = 0.0;       // CPU single-core equivalent percentage (100% = one logical processor, can exceed 100).
        double ramMB = 0.0;                // RAM memory allocation (MB, prioritize PrivateUsage).
        double workingSetMB = 0.0;         // Actual RAM working set usage (MB).
        double diskMBps = 0.0;             // Disk throughput (MB/s).
        double gpuPercent = 0.0;           // GPU percentage (R3 aggregates by PID via PDH GPU Engine).
        double netKBps = 0.0;              // Total network throughput (KB/s, equal to download + upload).
        double netRxKBps = 0.0;            // Network download throughput (KB/s, aggregated and written by the process page packet capture).
        double netTxKBps = 0.0;            // Network upload throughput (KB/s, aggregated and written by the process page packet capture).

        bool staticDetailsReady = false;   // true indicates that the detail fields are fully populated.
        bool dynamicCountersReady = false; // true indicates that performance counters are available.

        // ======== Alignment fields for Task Manager 'Details'
        // tab ======== Collection layering description:
        // - The first half of this section (scheduling/memory/IO) comes from NtQuerySystemInformation or
        //   GetProcessMemoryInfo, representing zero-overhead data obtained during enumeration that is always populated.
        // - The latter part of this section (GUI resources, jobs, mitigation policies, image descriptions, GPU VRAM, etc.) requires additional handles
        //   or parsing. Data is collected only when requested via the process_detail_demand bitmap in ProcessDock; otherwise, default values are retained.

        // -------- Runtime Status --------
        std::uint32_t suspendedThreadCount = 0; // Number of threads in the Suspended waiting state.
        bool processSuspended = false;          // true indicates all threads are suspended ("Suspended" in Task Manager).
        bool processStateKnown = false;         // true indicates the running/suspended state was successfully determined in this round.

        // -------- Scheduling --------
        std::int32_t basePriority = 0;      // Base priority value (0~31), corresponding to Task Manager's 'Base Priority'.
        std::uint64_t cycleTime = 0;        // Accumulated CPU cycles (Task Manager 'cycles').
        bool cycleTimeKnown = false;        // true indicates cycleTime is valid (some enum paths cannot retrieve it).

        // -------- Memory --------
        std::uint64_t peakWorkingSetBytes = 0;    // Peak working set size in bytes.
        std::uint64_t privateWorkingSetBytes = 0; // Private working set bytes (WorkingSetPrivateSize).
        std::uint64_t sharedWorkingSetBytes = 0;  // Shared working set bytes (working set minus private working set, a derived value).
        // activePrivateWorkingSetBytes：
        // - Task Manager 'Memory (Active Private Working Set)' column;
        // - Semantically, this refers to "the portion of the private working set that is still active"; it is 0 for frozen/suspended processes.
        // - Derived from privateWorkingSetBytes and suspended state; no additional queries required.
        std::uint64_t activePrivateWorkingSetBytes = 0;
        std::uint64_t commitSizeBytes = 0;        // Commit size (PagefileUsage).
        std::uint64_t peakCommitSizeBytes = 0;    // Peak committed size (PeakPagefileUsage).
        std::uint64_t pagedPoolBytes = 0;         // Paged pool quota usage.
        std::uint64_t nonPagedPoolBytes = 0;      // Non-paged pool quota usage.
        std::uint64_t pageFaultCount = 0;         // Accumulated page fault count.
        std::uint64_t hardFaultCount = 0;         // Accumulate hard page fault count (NtQuery specific).
        std::int64_t workingSetDeltaBytes = 0;    // Working set delta between adjacent iterations (can be negative).
        std::int64_t pageFaultDeltaCount = 0;     // Incremental page fault count between adjacent rounds (can be negative; fallback when PID is reused).
        bool memoryDetailKnown = false;           // true indicates that the above set of memory fields was successfully populated in this round.
        bool privateWorkingSetKnown = false;      // true indicates that private/shared working sets are available (only provided via the NtQuery path).

        // -------- I/O counts ----
        std::uint64_t ioReadOperationCount = 0;  // I/O read count.
        std::uint64_t ioWriteOperationCount = 0; // I/O write count.
        std::uint64_t ioOtherOperationCount = 0; // I/O other count.
        std::uint64_t ioReadTransferBytes = 0;   // I/O read bytes.
        std::uint64_t ioWriteTransferBytes = 0;  // I/O write bytes.
        std::uint64_t ioOtherTransferBytes = 0;  // I/O other bytes.
        bool ioDetailKnown = false;              // true indicates that the above set of I/O fields was successfully populated in this round.

        // -------- GUI Resources (on-demand: process_detail_demand::GuiResources) --------
        std::uint32_t gdiObjectCount = 0;  // GDI object count.
        std::uint32_t userObjectCount = 0; // User object count.
        bool guiResourceKnown = false;     // true indicates GetGuiResources query succeeded.

        // -------- Job object (on-demand: process_detail_demand::JobObject) --------
        bool inJobObject = false;    // true indicates the process belongs to a job object.
        bool jobObjectKnown = false; // true indicates successful job ownership query.

        // -------- Security and mitigation strategies (on-demand) --------
        ProcessFeatureState uacVirtualizationState = ProcessFeatureState::kUnknown;  // UAC virtualization.
        ProcessFeatureState dataExecutionPreventionState = ProcessFeatureState::kUnknown; // Data Execution Prevention.
        ProcessFeatureState controlFlowGuardState = ProcessFeatureState::kUnknown;   // Control flow protection.
        // hardwareStackProtectionState：
        // - Task Manager "Hardware-enforced Stack Protection" column;
        // - Data source: `EnableUserShadowStack` from `ProcessUserShadowStackPolicy` (Intel CET shadow stack).
        ProcessFeatureState hardwareStackProtectionState = ProcessFeatureState::kUnknown;
        // dpiAwarenessLevel: The 'DPI Awareness' column in Task Manager.
        ProcessDpiAwarenessLevel dpiAwarenessLevel = ProcessDpiAwarenessLevel::kUnknown;

        // -------- Image Description (on-demand) --------
        std::string packageFullName;      // Full UWP package name, corresponding to the 'Package Name' column in Task Manager; empty for non-packaged processes.
        bool packageNameKnown = false;    // true indicates the package membership has been successfully determined.
        std::string fileDescription;      // Image version resource FileDescription, shown as 'Description' in Task Manager.
        std::string osContextText;        // System name mapped from the manifest's supportedOS, corresponding to the Task Manager's 'Operating System Context'.
        std::string enterpriseContextText;// Enterprise context (WIP/EDP); defaults to 'Personal' when not enabled.

        // -------- GPU extension (on-demand: process_detail_demand::GpuMemory / GpuEngine) --------
        std::uint64_t gpuDedicatedMemoryBytes = 0; // Dedicated GPU memory in bytes.
        std::uint64_t gpuSharedMemoryBytes = 0;    // Shared GPU memory size in bytes.
        bool gpuMemoryKnown = false;               // true indicates the GPU memory counter was retrieved in this round.
        std::string gpuEngineText;                 // Name of the GPU engine with the highest usage, e.g., 'GPU 0 - 3D'.

        // ======== R0 / EPROCESS Extension Info (Phase 2) ========
        std::uint32_t r0Flags = 0;          // R0 enumerates raw flags, such as hidden process markers.
        std::uint32_t r0FieldFlags = 0;     // KSWORD_ARK_PROCESS_FIELD_* availability bitmap.
        std::uint32_t r0Status = KSWORD_ARK_PROCESS_R0_STATUS_UNAVAILABLE; // R0 extended read status.
        std::uint64_t r0DynDataCapabilityMask = 0; // Driver DynData capability bitmap snapshot.
        std::string r0ImagePath;            // R0 image path returned via public API (typically an NT path).

        std::uint8_t r0Protection = 0;      // EPROCESS.Protection original bytes.
        std::uint8_t r0SignatureLevel = 0;  // Raw bytes of EPROCESS.SignatureLevel.
        std::uint8_t r0SectionSignatureLevel = 0; // EPROCESS.SectionSignatureLevel raw byte.

        std::uint32_t r0SessionSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE; // Source of the Session field.
        std::uint32_t r0ImagePathSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE; // Image path source.
        std::uint32_t r0ProtectionSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE; // Protection source.
        std::uint32_t r0SignatureLevelSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE; // SignatureLevel source.
        std::uint32_t r0SectionSignatureLevelSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE; // SectionSignatureLevel source.
        std::uint32_t r0ObjectTableSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE; // ObjectTable source.
        std::uint32_t r0SectionObjectSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE; // SectionObject source.

        std::uint32_t r0ProtectionOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE; // EPROCESS.Protection offset.
        std::uint32_t r0SignatureLevelOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE; // EPROCESS.SignatureLevel - Offset.
        std::uint32_t r0SectionSignatureLevelOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE; // Offset of EPROCESS.SectionSignatureLevel.
        std::uint32_t r0ObjectTableOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE; // EPROCESS.ObjectTable offset.
        std::uint32_t r0SectionObjectOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE; // EPROCESS.SectionObject offset.
        std::uint64_t r0ObjectTableAddress = 0; // EPROCESS.ObjectTable - Current pointer value.
        std::uint64_t r0SectionObjectAddress = 0; // Current pointer value of EPROCESS.SectionObject.
    };

    // ProcessModuleRecord: A single row of data in the process module list.
    struct ProcessModuleRecord
    {
        std::string modulePath;                // Module full path.
        std::string moduleName;                // Module name (file name).
        std::uint64_t moduleBaseAddress = 0;   // Module load base address.
        std::uint32_t moduleSizeBytes = 0;     // Module image size (bytes).
        // Module signature display text and publisher/trusted markers are semantically aligned with ProcessRecord.
        std::string signatureState;            // Module signature display text.
        std::string signaturePublisher;        // Module signature publisher (vendor).
        bool signatureTrusted = false;         // Whether the module signature is trusted by Windows.
        std::uint32_t entryPointRva = 0;       // Entry point RVA (relative offset).
        std::string runningState;              // Running state text (Loaded/Unknown).
        std::uint32_t representativeThreadId = 0; // Representative thread ID (used as a shortcut entry for thread operations).
        std::uint64_t representativeThreadCreationTime100ns = 0; // Representative thread creation time (used for identity verification).
        std::string threadIdText;              // Thread ID summary text (comma-separated).
    };

    // ProcessThreadRecord: Single-thread data in the process thread list.
    struct ProcessThreadRecord
    {
        std::uint32_t threadId = 0;        // Thread ID.
        std::uint32_t ownerPid = 0;        // Associated process PID.
        int basePriority = 0;              // Thread base priority.
        std::string stateText;             // Thread state text (Running/Unknown).
    };

    // SystemThreadRecord: Single-thread data in a full system thread snapshot.
    struct SystemThreadRecord
    {
        std::uint32_t threadId = 0;            // Thread ID (TID).
        std::uint32_t ownerPid = 0;            // Associated process PID.
        std::string ownerProcessName;          // Owner process name (for list display).
        std::uint64_t startAddress = 0;        // Thread start address (pointer value returned by kernel).
        int priority = 0;                      // Current dynamic priority
        int basePriority = 0;                  // Base priority.
        std::uint32_t threadState = 0;         // Thread state code (KTHREAD_STATE value).
        std::uint32_t waitReason = 0;          // Wait reason code (KWAIT_REASON value).
        std::uint64_t kernelTime100ns = 0;     // Kernel-mode cumulative time (100ns).
        std::uint64_t userTime100ns = 0;       // User-mode cumulative time (100ns).
        std::uint64_t createTime100ns = 0;     // Creation time (FILETIME in 100ns units).
        std::uint32_t waitTimeTick = 0;        // Wait duration counter (Nt raw field).
        std::uint32_t contextSwitchCount = 0;  // Context switch count (Nt raw field).
        std::uint64_t stackBase = 0;           // R3: User stack base address returned by SystemExtendedProcessInformation.
        std::uint64_t stackLimit = 0;          // R3: User stack boundary returned by SystemExtendedProcessInformation.
        std::uint64_t win32StartAddress = 0;   // Win32StartAddress returned by R3 SystemExtendedProcessInformation.
        std::uint64_t tebBaseAddress = 0;      // TEB base address returned by R3 SystemExtendedProcessInformation.
        std::uint32_t r0ThreadFlags = 0;        // KSWORD_ARK_THREAD_FLAG_*: Cross-view flags.
        bool isR0OnlyThread = false;            // true indicates R3 thread snapshot is missing but R0/CID view is visible.
        std::uint32_t r0ThreadFieldFlags = 0;  // Availability bitmap for KSWORD_ARK_THREAD_FIELD_*.
        std::uint32_t r0ThreadStatus = KSWORD_ARK_THREAD_R0_STATUS_UNAVAILABLE; // R0 KTHREAD extended status.
        std::uint32_t r0StackFieldSource = KSW_DYN_FIELD_SOURCE_UNAVAILABLE; // KTHREAD stack field source.
        std::uint32_t r0IoFieldSource = KSW_DYN_FIELD_SOURCE_UNAVAILABLE;    // Source of the KTHREAD I/O counter.
        std::uint64_t r0InitialStack = 0;      // KTHREAD.InitialStack。
        std::uint64_t r0StackLimit = 0;        // KTHREAD.StackLimit。
        std::uint64_t r0StackBase = 0;         // KTHREAD.StackBase。
        std::uint64_t r0KernelStack = 0;       // KTHREAD.KernelStack。
        std::uint64_t r0ReadOperationCount = 0; // KTHREAD ReadOperationCount。
        std::uint64_t r0WriteOperationCount = 0; // KTHREAD WriteOperationCount。
        std::uint64_t r0OtherOperationCount = 0; // KTHREAD OtherOperationCount。
        std::uint64_t r0ReadTransferCount = 0; // KTHREAD ReadTransferCount。
        std::uint64_t r0WriteTransferCount = 0; // KTHREAD WriteTransferCount。
        std::uint64_t r0OtherTransferCount = 0; // KTHREAD OtherTransferCount。
        std::uint32_t r0KtInitialStackOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE; // DynData KtInitialStack offset.
        std::uint32_t r0KtStackLimitOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;   // DynData KtStackLimit offset.
        std::uint32_t r0KtStackBaseOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;    // DynData KtStackBase offset.
        std::uint32_t r0KtKernelStackOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;  // DynData KtKernelStack offset.
        std::uint32_t r0KtReadOperationCountOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE; // Offset for DynData KtReadOperationCount.
        std::uint32_t r0KtWriteOperationCountOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE; // DynData KtWriteOperationCount offset.
        std::uint32_t r0KtOtherOperationCountOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE; // DynData KtOtherOperationCount offset.
        std::uint32_t r0KtReadTransferCountOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;   // DynData KtReadTransferCount offset.
        std::uint32_t r0KtWriteTransferCountOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;  // Offset for DynData KtWriteTransferCount.
        std::uint32_t r0KtOtherTransferCountOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;  // Offset for DynData KtOtherTransferCount.
        std::uint64_t r0ThreadDynDataCapabilityMask = 0; // Driver DynData capability bitmap snapshot.
        double cpuPercent = 0.0;            // CPU single-core usage of adjacent snapshot threads (0~100).
        bool cpuUsageReady = false;         // false indicates no previous baseline from the same thread instance is available.
    };

    // ProcessModuleSnapshot: Snapshot data required for the modules tab (modules + threads).
    struct ProcessModuleSnapshot
    {
        std::vector<ProcessModuleRecord> modules; // Module list.
        std::vector<ProcessThreadRecord> threads; // Thread list.
        std::string diagnosticText;              // Refresh diagnostic text (failure reason / fallback path).
    };

    // CounterSample: Historical sample used to calculate differences across refresh cycles.
    struct CounterSample
    {
        std::uint64_t cpuTime100ns = 0;    // Accumulated CPU value from the previous round.
        std::uint64_t ioBytes = 0;         // Accumulated IO value from the previous round.
        std::uint64_t networkRxBytes = 0;  // Previous round's network download cumulative bytes aggregated by PID.
        std::uint64_t networkTxBytes = 0;  // Previous round's network upload cumulative bytes aggregated by PID.
        std::uint64_t sampleTick100ns = 0; // Sample timestamp (steady_clock converted to 100ns).
        std::uint64_t workingSetBytes = 0; // Previous round's working set bytes, used for the 'Working Set Increment' column.
        std::uint64_t pageFaultCount = 0;  // Accumulated page fault count from the previous round, used for the "Page Fault Increment" column.
        bool hasMemoryBaseline = false;    // true indicates the two baseline values above are valid (false during the first sampling round).
    };

    // ThreadCounterSample: Stores thread CPU differential baseline by PID/TID/creation time.
    struct ThreadCounterSample
    {
        std::uint64_t cpuTime100ns = 0;    // Accumulated Kernel + User time from the previous round.
        std::uint64_t sampleTick100ns = 0; // Monotonic clock sample point from the previous round.
    };

    // buildProcessIdentityKey:
    // - Uses 'PID + creation time' to generate a stable identity string.
    // - Used to determine if it is the same process instance.
    std::string buildProcessIdentityKey(std::uint32_t pid, std::uint64_t creationTime100ns);

    // buildThreadIdentityKey: Generates a stable thread instance identifier using PID + TID + creation time.
    std::string buildThreadIdentityKey(
        std::uint32_t pid,
        std::uint32_t threadId,
        std::uint64_t creationTime100ns);

    // updateThreadCpuUsage: Calculates single-core thread usage based on adjacent cumulative Kernel/User time.
    void updateThreadCpuUsage(
        SystemThreadRecord& threadRecord,
        const ThreadCounterSample* previousSample,
        ThreadCounterSample& nextSampleOut,
        std::uint32_t logicalCpuCount,
        std::uint64_t currentTick100ns);

    // enumerateProcesses:
    // - Return the current system process list (including basic performance counters) according to the strategy.
    // - Does not guarantee that every record contains complete static details.
    // Parameter strategy: enumeration strategy.
    // Parameter actualStrategyOut:
    // Optional output parameter
    // - Returns the actual enumeration strategy executed (e.g., Auto may fall back to Snapshot).
    // Parameter detailDemandFlags:
    // - process_detail_demand bitmap; only affects fields requiring additional sampling (currently GPU memory/engines).
    // - Passing None behaves exactly as in the old version, generating no additional PDH queries.
    std::vector<ProcessRecord> enumerateProcesses(
        ProcessEnumStrategy strategy,
        ProcessEnumStrategy* actualStrategyOut = nullptr,
        std::uint32_t detailDemandFlags = process_detail_demand::kNone);

    // enumerateSystemThreads:
    // - enumerate all threads in the current system (prefer NtQuerySystemInformation).
    // - Automatically fall back to Toolhelp snapshots when Nt paths are unavailable.
    // Parameter usedNtQueryOut:
    // Optional output parameter
    // - true indicates NtQuerySystemInformation was used; false indicates a fallback to Toolhelp.
    // Parameter diagnosticTextOut:
    // Optional output parameter
    // - Returns a path description for this enumeration run or the failure reason, for UI diagnostic display.
    std::vector<SystemThreadRecord> enumerateSystemThreads(
        bool* usedNtQueryOut = nullptr,
        std::string* diagnosticTextOut = nullptr);

    // fillProcessStaticDetails:
    // - Fill 'relatively static' fields such as path, command line, user, signature, and administrator status.
    // - Typically called only once for 'newly appearing processes'.
    // Parameter processRecord: Target record (modified by reference).
    // Parameter includeSignatureCheck:
    // - true: Executes WinVerifyTrust for signature verification (slower).
    // - false: skip signature check and fill only basic static information (fast mode).
    // Returns: true on success; false indicates some fields could not be retrieved.
    bool fillProcessStaticDetails(ProcessRecord& processRecord, bool includeSignatureCheck = true);

    // fillProcessOnDemandDetails:
    // - Collect fields corresponding to 'requires additional handles or additional parsing' in the Task Manager aligned columns.
    // - Each bit is set only when the corresponding column is visible in ProcessDock; fields not requested are completely skipped during query.
    // Parameter processRecord: Target record (modified by reference).
    // Parameter detailDemandFlags: process_detail_demand bitmap.
    // Parameter resolvedFlagsOut:
    // - Optional output parameter; returns the bits indicating what was successfully collected this time.
    // - Note: Callers mark fields that remain unchanged during the lifecycle as completed based on this to
    //   avoid repeated queries in each round, while allowing rejected processes to retry in subsequent rounds.
    // Return value:
    // - true indicates that at least one requested field was successfully collected.
    // - false indicates the target process cannot be opened or all requested items failed; the caller may use this to retain placeholder display.
    bool fillProcessOnDemandDetails(
        ProcessRecord& processRecord,
        std::uint32_t detailDemandFlags,
        std::uint32_t* resolvedFlagsOut = nullptr);

    // ProcessDetailDemandForImageFileCacheClear:
    // - Clear the cached description and OS context results for 'by image path'.
    // - Used to proactively release caches after long-running operations or to force re-parsing when the image on disk is replaced.
    // Parameters: None.
    // Return value: None.
    void clearProcessImageDescriptionCache();

    // refreshProcessDynamicCounters:
    // - Refresh dynamic fields such as CPU raw time, RAM working set, and cumulative IO values;
    // - Supports completing performance counters under the Snapshot path.
    // Parameter processRecord: Target record (modified by reference).
    // Return value: true on success; false indicates failure to retrieve dynamic counters.
    bool refreshProcessDynamicCounters(ProcessRecord& processRecord);

    // queryProcessProtectionLevelByPid:
    // - Queries the target process PPL enumeration via user-mode ProcessProtectionLevelInfo;
    // - This value is a manual refresh field; ProcessDock does not write it to the cross-round static cache.
    // Parameter pid: Target process PID.
    // Parameter levelOut: Output raw PROTECTION_LEVEL_* enum value; may be null.
    // Parameter displayTextOut: Output readable text, may be null.
    // Parameter errorMessageOut: reason for failure, may be null.
    // Return value: returns true on success, false on failure.
    bool queryProcessProtectionLevelByPid(
        std::uint32_t pid,
        std::uint32_t* levelOut,
        std::string* displayTextOut,
        std::string* errorMessageOut = nullptr);

    // updateDerivedCounters:
    // - Calculate CPU% and DiskMB/s based on the "previous sample + current raw counter".
    // - GPU is written by PDH GPU Engine sampling during the enumeration phase; this function only retains the value.
    // - Net is written by the packet capture aggregation logic of ProcessDock after this function returns; non-process page calls remain 0.
    // Parameter processRecord: target record (derived values written by reference).
    // Parameter previousSample: The previous sample (may be null).
    // Parameter nextSampleOut: Output next sample.
    // Parameter logicalCpuCount: number of logical processors (used for CPU percentage conversion).
    // Parameter currentTick100ns: The current sampling timestamp (in 100ns units).
    void updateDerivedCounters(
        ProcessRecord& processRecord,
        const CounterSample* previousSample,
        CounterSample& nextSampleOut,
        std::uint32_t logicalCpuCount,
        std::uint64_t currentTick100ns);

    // getProcessNameByPid: Reads the process name by PID (returns empty string on failure).
    std::string getProcessNameByPid(std::uint32_t pid);

    // queryProcessCreationTimeByPid:
    // - Read the FILETIME creation time of the current process instance for the target PID.
    // - Call pattern: Save identity for historical events or check if the PID has been reused before jumping.
    // - Input parameter pid: target process PID;
    // - Output creationTime100nsOut: Returns a non-zero creation time in 100ns units on success;
    // - Output parameter detailTextOut: Win32 diagnostic information returned on failure; may be null.
    // - Return: true if creation time is read successfully, otherwise false.
    bool queryProcessCreationTimeByPid(
        std::uint32_t pid,
        std::uint64_t* creationTime100nsOut,
        std::string* detailTextOut = nullptr);

    // queryProcessPathByPid purpose: Read the executable path by PID (returns an empty string on failure).
    std::string queryProcessPathByPid(std::uint32_t pid);

    // executeTaskKill: Executes taskkill to terminate a process (optional /F).
    bool executeTaskKill(std::uint32_t pid, bool forceKill, std::string* errorMessage);

    // terminateProcessByWin32: Calls TerminateProcess to terminate the process.
    bool terminateProcessByWin32(std::uint32_t pid, std::string* errorMessage);

    // terminateProcessByWin32IfCreationTimeMatches：
    // - Call TerminateProcess only when the PID and creation time still point to the same process instance.
    // - Validation and termination share a single held process handle to avoid TOCTOU errors due to PID reuse.
    bool terminateProcessByWin32IfCreationTimeMatches(
        std::uint32_t pid,
        std::uint64_t expectedCreationTime100ns,
        std::string* errorMessage);

    // terminateProcessByNtNative:
    // - Calls NtTerminateProcess / ZwTerminateProcess to terminate the process.
    bool terminateProcessByNtNative(std::uint32_t pid, std::string* errorMessage);

    // terminateProcessByWtsApi:
    // - Call WTSTerminateProcess (WTS API) to terminate the process.
    bool terminateProcessByWtsApi(std::uint32_t pid, std::string* errorMessage);

    // terminateProcessByWinStationApi:
    // - Call WinStationTerminateProcess (winsta interface) to terminate the process.
    bool terminateProcessByWinStationApi(std::uint32_t pid, std::string* errorMessage);

    // terminateProcessByJobObject:
    // - Creates a temporary Job, adds the target process to it, and then calls TerminateJobObject to terminate it.
    bool terminateProcessByJobObject(std::uint32_t pid, std::string* errorMessage);

    // terminateProcessByNtJobObject:
    // - Creates a temporary Job, adds the target process to it, and calls NtTerminateJobObject to terminate it.
    bool terminateProcessByNtJobObject(std::uint32_t pid, std::string* errorMessage);

    // terminateProcessByRestartManager:
    // - Register the target process via Restart Manager and invoke RmShutdown;
    // - When forceShutdown=true, use the force-close option.
    bool terminateProcessByRestartManager(
        std::uint32_t pid,
        bool forceShutdown,
        std::string* errorMessage);

    // terminateProcessByDuplicateHandlePseudo:
    // - Open the target process with PROCESS_DUP_HANDLE;
    // - Handle: Duplicate the target process pseudo-handle (-1) to the current process, then call TerminateProcess.
    bool terminateProcessByDuplicateHandlePseudo(std::uint32_t pid, std::string* errorMessage);

    // terminateAllThreadsByPid purpose: enumerate and TerminateThread to end all threads of the specified process.
    bool terminateAllThreadsByPid(std::uint32_t pid, std::string* errorMessage);

    // terminateAllThreadsByPidNtNative:
    // - enumerate all threads of the target process and call NtTerminateThread / ZwTerminateThread.
    bool terminateAllThreadsByPidNtNative(std::uint32_t pid, std::string* errorMessage);

    // terminateProcessByNtUnmapNtdll:
    // - Open the target process with PROCESS_VM_OPERATION access.
    // - Locate and call NtUnmapViewOfSection to unload the ntdll.dll mapping (high risk).
    bool terminateProcessByNtUnmapNtdll(std::uint32_t pid, std::string* errorMessage);

    // terminateProcessByDebugAttach:
    // - Attach to the debug target via DebugActiveProcess.
    // - Can serve as a link in a debugger attack chain (immediate termination not guaranteed).
    bool terminateProcessByDebugAttach(std::uint32_t pid, std::string* errorMessage);

    // terminateProcessByNtsdCommand:
    // - Calls ntsd to attach via command line and immediately exit (`ntsd -c q -p <pid>`);
    // - As an external tool method for the debugger attack chain.
    bool terminateProcessByNtsdCommand(std::uint32_t pid, std::string* errorMessage);

    // injectInvalidShellcode: Remote allocation and execution of invalid shellcode (experimental, high-risk operation).
    bool injectInvalidShellcode(std::uint32_t pid, std::string* errorMessage);

    // suspendProcess function: suspends a process (via NtSuspendProcess).
    bool suspendProcess(std::uint32_t pid, std::string* errorMessage);

    // resumeProcess function: Resumes a process (NtResumeProcess).
    bool resumeProcess(std::uint32_t pid, std::string* errorMessage);

    // suspendProcessIfCreationTimeMatches / resumeProcessIfCreationTimeMatches：
    // - First, verify the creation time of the instance corresponding to the PID on the same process handle.
    // - Reject actions on identity change to prevent impact on unrelated processes after PID recycling.
    bool suspendProcessIfCreationTimeMatches(
        std::uint32_t pid,
        std::uint64_t expectedCreationTime100ns,
        std::string* errorMessage);
    bool resumeProcessIfCreationTimeMatches(
        std::uint32_t pid,
        std::uint64_t expectedCreationTime100ns,
        std::string* errorMessage);

    // setProcessCriticalFlag purpose: set/clear the critical process flag (NtSetInformationProcess).
    bool setProcessCriticalFlag(std::uint32_t pid, bool enableCritical, std::string* errorMessage);

    // setProcessPriority: Sets process priority (SetPriorityClass).
    bool setProcessPriority(std::uint32_t pid, ProcessPriorityLevel priorityLevel, std::string* errorMessage);

    // setProcessEfficiencyMode: Enables/disables Windows process efficiency mode (PowerThrottling).
    bool setProcessEfficiencyMode(std::uint32_t pid, bool enableEfficiencyMode, std::string* errorMessage);

    // openProcessFolder purpose: Locate the file path containing the process in File Explorer.
    bool openProcessFolder(std::uint32_t pid, std::string* errorMessage);

    // queryProcessStaticDetailByPid:
    // - Query static detail snapshot for a single process using PID as entry;
    // - When includeSignatureCheck=true, signature verification is performed, which may be slower.
    // - The UI window opening path should pass false or use a background task to avoid blocking the event loop.
    // Parameter pid: Target process PID.
    // Parameter outRecord: Output record; on failure, retains fields already obtained.
    // Parameter includeSignatureCheck: whether to synchronously execute WinVerifyTrust signature verification.
    // Return value: true if basic static details were read successfully, false otherwise.
    bool queryProcessStaticDetailByPid(
        std::uint32_t pid,
        ProcessRecord& outRecord,
        bool includeSignatureCheck = true);

    // enumerateProcessModulesAndThreads:
    // - enumerate target process modules and thread information (for refreshing the "Modules" tab);
    // - When includeSignatureCheck=true, additional module signature verification is performed (slower).
    ProcessModuleSnapshot enumerateProcessModulesAndThreads(
        std::uint32_t pid,
        bool includeSignatureCheck);

    // enumerateProcessModulesAndThreadsIfIdentityMatches:
    // - Maintain the same process handle throughout the enumeration and verify PID + creation time.
    // - Returns an empty snapshot if identity is unavailable or does not match, preventing module data from reused PIDs from being used for old detail windows.
    ProcessModuleSnapshot enumerateProcessModulesAndThreadsIfIdentityMatches(
        std::uint32_t pid,
        std::uint64_t expectedCreationTime100ns,
        bool includeSignatureCheck);

    // unloadModuleByBaseAddressIfIdentityMatches:
    // - After verifying PID and creation time on the same process handle, call FreeLibrary on the remote process to unload the module at the specified base address.
    bool unloadModuleByBaseAddressIfIdentityMatches(
        std::uint32_t pid,
        std::uint64_t expectedCreationTime100ns,
        std::uint64_t moduleBaseAddress,
        std::string* errorMessage);

    // suspendThreadById purpose: Suspend the specified thread.
    bool suspendThreadById(std::uint32_t threadId, std::string* errorMessage);

    // resumeThreadById purpose: Resume the specified thread.
    bool resumeThreadById(std::uint32_t threadId, std::string* errorMessage);

    // terminateThreadById purpose: Terminate the specified thread.
    bool terminateThreadById(std::uint32_t threadId, std::string* errorMessage);

    // * IfIdentityMatches series:
    // - Validates TID, owning PID, and FILETIME creation time on the same thread handle.
    // - Only perform R3 suspend/resume/terminate after successful validation to avoid operating on the wrong object after thread ID reuse.
    bool suspendThreadIfIdentityMatches(
        std::uint32_t threadId,
        std::uint32_t expectedOwnerPid,
        std::uint64_t expectedCreationTime100ns,
        std::string* errorMessage);
    bool resumeThreadIfIdentityMatches(
        std::uint32_t threadId,
        std::uint32_t expectedOwnerPid,
        std::uint64_t expectedCreationTime100ns,
        std::string* errorMessage);
    bool terminateThreadIfIdentityMatches(
        std::uint32_t threadId,
        std::uint32_t expectedOwnerPid,
        std::uint64_t expectedCreationTime100ns,
        std::string* errorMessage);
    // *IfProcessAndThreadIdentityMatches series:
    // - Verify PID + creation time on the same process handle and keep the handle until the thread action returns;
    // - Further verify the thread's PID and creation time to avoid the details window falling onto a new instance where both PID and TID have been reused.
    bool suspendThreadIfProcessAndThreadIdentityMatches(
        std::uint32_t threadId,
        std::uint32_t expectedOwnerPid,
        std::uint64_t expectedProcessCreationTime100ns,
        std::uint64_t expectedThreadCreationTime100ns,
        std::string* errorMessage);
    bool resumeThreadIfProcessAndThreadIdentityMatches(
        std::uint32_t threadId,
        std::uint32_t expectedOwnerPid,
        std::uint64_t expectedProcessCreationTime100ns,
        std::uint64_t expectedThreadCreationTime100ns,
        std::string* errorMessage);
    bool terminateThreadIfProcessAndThreadIdentityMatches(
        std::uint32_t threadId,
        std::uint32_t expectedOwnerPid,
        std::uint64_t expectedProcessCreationTime100ns,
        std::uint64_t expectedThreadCreationTime100ns,
        std::string* errorMessage);

    // injectDllByPath:
    // - Inject the specified DLL path into the target process (using the LoadLibraryW remote thread approach).
    bool injectDllByPath(std::uint32_t pid, const std::string& dllPath, std::string* errorMessage);

    // injectShellcodeBuffer:
    // - Write the original shellcode bytes to the remote process and create a remote thread to execute it.
    bool injectShellcodeBuffer(
        std::uint32_t pid,
        const std::vector<std::uint8_t>& shellcodeBuffer,
        std::string* errorMessage);

    // openFolderByPath:
    // - Navigate to the target path (file or directory) in File Explorer.
    bool openFolderByPath(const std::string& targetPath, std::string* errorMessage);

    // knownTokenPrivilegeNames:
    // - Returns the complete list of Se*privilege entries as defined by the current Windows SDK.
    // Startup-time privilege requests, process page creation, process list, and details page must reuse this directory.
    const std::vector<std::string>& knownTokenPrivilegeNames();

    // buildKnownTokenPrivilegeSnapshot:
    // Maps LUID/Attributes entries from R3 TOKEN_PRIVILEGES or R0 IOCTL returns to a unified SDK directory.
    // - Does not rely on private Token layouts; known privilege entries not present in the list are marked as NotPresent.
    bool buildKnownTokenPrivilegeSnapshot(
        const std::vector<TokenPrivilegeLuidEntry>& entries,
        std::vector<TokenPrivilegeInfo>* privilegesOut,
        std::string* errorMessage);

    // queryTokenPrivilegesByPid:
    // - Query full privilege snapshot of specified process via Win32 Token API;
    // - Returns true on successful token read; individual LookupPrivilegeValue failures are represented as Unknown.
    bool queryTokenPrivilegesByPid(
        std::uint32_t sourcePid,
        std::vector<TokenPrivilegeInfo>* privilegesOut,
        std::string* errorMessage);

    // queryTokenPrivilegesByProcessHandle:
    // - Reuse the process handle with verified creation time (already checked by the caller) to read the token.
    // - Avoid reopening the process by PID after identity verification, which could hit a reused process.
    bool queryTokenPrivilegesByProcessHandle(
        HANDLE processHandle,
        std::vector<TokenPrivilegeInfo>* privilegesOut,
        std::string* errorMessage);

    // applyTokenPrivilegeEditsByPid:
    // - Open the process token for the specified PID (DuplicateTokenEx is optional).
    // - Adjust privileges via edits (AdjustTokenPrivileges).
    bool applyTokenPrivilegeEditsByPid(
        std::uint32_t sourcePid,
        std::uint32_t tokenDesiredAccess,
        bool duplicatePrimaryToken,
        const std::vector<TokenPrivilegeEdit>& edits,
        std::string* errorMessage);

    // applyTokenPrivilegeEditsByProcessHandle:
    // - Directly open the token from a stable process handle and apply adjustments.
    // - Identity-sensitive UI must prefer this entry point; do not fall back to opening by PID after validation.
    bool applyTokenPrivilegeEditsByProcessHandle(
        HANDLE processHandle,
        std::uint32_t tokenDesiredAccess,
        bool duplicatePrimaryToken,
        const std::vector<TokenPrivilegeEdit>& edits,
        std::string* errorMessage);

    // launchProcess:
    // - Create a process by calling CreateProcessW or using the Token path based on the request;
    // - Uniformly returns CreateProcessResult externally;
    bool launchProcess(
        const CreateProcessRequest& request,
        CreateProcessResult* resultOut);

    // launchSuspendedProcess: creates a process with CREATE_SUSPENDED to target for directed monitoring.
    // - When the current process is elevated and request.runAsAdministrator=false,
    //   prefer creating the target with normal privileges using TokenLinkedToken.
    // - On success, retain the primary thread handle for precise restoration by resumeSuspendedProcessInitialThread.
    // - resultOut must be a valid output address; a null pointer causes immediate failure
    //   before process creation to avoid losing the CREATE_SUSPENDED main thread handle.
    bool launchSuspendedProcess(
        const SuspendedProcessLaunchRequest& request,
        SuspendedProcessLaunchResult* resultOut);

    // resumeSuspendedProcessInitialThread: Resumes the main thread once that was suspended by launchSuspendedProcess.
    bool resumeSuspendedProcessInitialThread(
        std::uint64_t initialThreadHandle,
        std::string* errorMessage);

    // terminateSuspendedProcessByHandle: Terminates the target process using the original process handle retained by launchSuspendedProcess.
    bool terminateSuspendedProcessByHandle(
        std::uint64_t processHandle,
        std::string* errorMessage);

    // closeSuspendedProcessInitialThreadHandle: Close the main thread handle returned by the controlled suspended creation.
    void closeSuspendedProcessInitialThreadHandle(std::uint64_t initialThreadHandle);

    // closeSuspendedProcessHandle: Closes the original process handle returned by controlled suspended creation.
    void closeSuspendedProcessHandle(std::uint64_t processHandle);

    std::wstring getCurrentProcessPath();

}
