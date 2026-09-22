#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace ksword::features::kernel {

// KernelFeatureId is the stable Win32-light identifier for every kernel entry
// retained from the original KernelDock. Input values are selected by the UI
// or controller; processing uses the id to route to facade methods; return
// behavior is value-only with no side effects.
enum class KernelFeatureId : std::uint32_t {
    kObjectNamespaceOverview = 1,
    kObjectDirectoryRecursive,
    kNamedPipe,
    kBaseNamedObjects,
    kSymbolicLink,
    kDeviceDriverObjects,
    kObjectTypeMatrix,
    kCommunicationEndpoint,
    kAtomTable,
    kNtQueryLegacy,
    kSsdt,
    kShadowSsdt,
    kInlineHook,
    kIatEatHook,
    kDynData,
    kDriverStatus,
    kCallbackIntercept,
    kCallbackEnumeration,
    kKernelExecutableMemory,
    kKernelMemoryEvidence,
    kProcessCrossView,
    kThreadCrossView,
    kDriverIntegrity,
    kKernelCpuIntegrity,
    kCpuHardwareSnapshot,
    kPhysicalMemoryLayout,
    kMutationAudit,
    kKeyboardHotkeys,
    kKeyboardHooks,
    kDynDataCapabilities,
    kMinifilterBypassPids,
    kKernelTimerDpc,
    kIoctlRegistry,
    kPdbProfileStatus,
    kCidTableSummary,
    kIpcSummary,
    kHookAuditSummary,
    kWorkQueueThreads,
    kSlatIommuAudit,
    kHvmStatus,
    kHvmEvents,
    kDriverDispatchTable,
    kDriverImageFields,
    kDriverCommunication,
    kPlatformAudit,
    kSystemTimeState,
    kI8042Audit,
    kPiDdbCache,
    kRawDiskSectors,
    kNetworkTrafficPackets
};

// KernelFeatureBackend describes where a feature obtains data. Input is fixed
// feature metadata; processing lets facade and UI decide whether the operation
// is user-mode-only, driver-backed, or mixed; return behavior is enum value use.
enum class KernelFeatureBackend : std::uint32_t {
    kUserModeNative,
    kArkDriverClient,
    kHybrid
};

// KernelFeatureDescriptor is one UI/catalog row. Inputs are constants supplied
// by each feature file; processing copies them into the module catalog; output is
// the data rendered by the Win32 lightweight kernel page.
struct KernelFeatureDescriptor {
    KernelFeatureId id = KernelFeatureId::kObjectNamespaceOverview;
    std::wstring title;
    std::wstring category;
    std::wstring summary;
    KernelFeatureBackend backend = KernelFeatureBackend::kUserModeNative;
    bool requiresAdministrator = false;
    bool mayModifyKernelState = false;
};

// KernelRequest carries one operation request from UI/controller to facade.
// Inputs are selected feature id, optional filter strings, and feature flags;
// processing is owned by KernelFacade; return behavior is via KernelOperationResult.
struct KernelRequest {
    KernelFeatureId featureId = KernelFeatureId::kObjectNamespaceOverview;
    std::wstring filterText;
    std::wstring moduleFilterText;
    std::uint32_t flags = 0;
    std::uint64_t startAddress = 0;
    std::uint64_t endAddress = 0;
    std::uint32_t maxRows = 0;
    std::uint32_t idtVectorLimit = 0;
};

// KernelRequestFlag is the UI/facade bridge for per-page scan options. Inputs
// are set by Win32 controls such as the Hook include combo; processing in
// KernelFacade translates these stable bits into shared driver protocol flags;
// return behavior is normal bitmask use inside KernelRequest::flags.
enum KernelRequestFlag : std::uint32_t {
    kKernelRequestFlagIncludeInternal = 0x00000001U,
    kKernelRequestFlagIncludeClean = 0x00000002U,
    kKernelRequestFlagIncludeIat = 0x00000004U,
    kKernelRequestFlagIncludeEat = 0x00000008U,
    kKernelRequestFlagRiskOnly = 0x00000010U,
    kKernelRequestFlagIncludeNonModuleExecutableRanges = 0x00000020U,
};

// KernelResultRow is a generic row used before final per-feature tables are
// wired. Inputs are key/value columns plus detail text from a worker or facade;
// processing is UI rendering only; output is copied into list/detail controls.
struct KernelResultRow {
    std::vector<std::pair<std::wstring, std::wstring>> columns;
    std::wstring detailText;
};

// KernelObjectNamespaceEntry stores one object-namespace snapshot row used by
// the Win32 kernel page. Inputs come from the native object-namespace worker;
// processing keeps the row immutable in the UI model; output is the same
// detail/copy payload that the original Qt object namespace tree rendered.
struct KernelObjectNamespaceEntry {
    std::wstring rootPathText;
    std::wstring scopeDescriptionText;
    std::wstring directoryPathText;
    std::wstring objectNameText;
    std::wstring objectTypeText;
    std::wstring fullPathText;
    std::wstring enumApiText;
    std::wstring symbolicLinkTargetText;
    std::wstring statusText;
    std::wstring detailText;
    long statusCode = 0;
    bool querySucceeded = false;
    bool isDirectory = false;
    bool isSymbolicLink = false;
};

// KernelOperationResult is the common facade return packet. Inputs come from a
// query/action method; processing reports support, success, diagnostics, and
// rows; return behavior is value-only and never throws by contract.
struct KernelOperationResult {
    bool supported = false;
    bool success = false;
    bool destructiveAction = false;
    std::wstring message;
    std::vector<KernelResultRow> rows;
};

// KernelActionId identifies explicit row/menu operations that may change R0
// state. Inputs are chosen only by the Win32 context menu; processing is routed
// through KernelFacade and ArkDriverClient; return behavior is a normal
// KernelOperationResult so actions render in the same table as queries.
enum class KernelActionId : std::uint32_t {
    kNone = 0,
    kInlineHookNopPatch,
    kCallbackCancelPendingDecisions,
    kCallbackAnswerEvent,
    kCallbackApplyDisabledEmptyRules,
    kCallbackApplyLocalRules,
    kCallbackSafeRemove,
    kCallbackExperimentalUnlink,
    kMinifilterSetBypassPids,
    kMinifilterClearBypassPids,
    kFileMonitorStartFsctl,
    kFileMonitorDrain,
    kFileMonitorClear,
    kDriverObjectQueryDetail,
    kDriverObjectForceUnload,
    kNativeObjectQueryDetail,
    kNativeSymbolicLinkResolve,
    kNativeNamedPipeProbe,
    kDynDataApplyMatchedProfile,
    kMutationCommitDryRun,
    kMutationRollbackDryRun,
    kMutationRollbackConfirmed,
    kNetworkCaptureStart,
    kNetworkCaptureStop,
    kPiDdbDeleteEntry,
    kDriverDispatchRestore,
    kDriverDispatchAbandon,
    kDriverImageRestore,
    kDriverImageAbandon,
    kDriverCommunicationRestore
};

// KernelActionRequest carries one explicit action from the UI to the facade.
// Inputs are the selected feature/action, selected row field snapshot, generic
// filter text for PID-list entry, and a force flag for second-confirmation flows;
// processing is owned by KernelFacade; return is KernelOperationResult.
struct KernelActionRequest {
    KernelFeatureId featureId = KernelFeatureId::kObjectNamespaceOverview;
    KernelActionId actionId = KernelActionId::kNone;
    std::vector<std::pair<std::wstring, std::wstring>> rowFields;
    std::wstring filterText;
    std::wstring moduleFilterText;
    bool force = false;
};

// toDisplayName converts a feature id into a human-readable Chinese title.
// Input is one KernelFeatureId; processing uses a switch over stable ids; output
// is a display string for logs, diagnostic messages, and fallback UI text.
std::wstring toDisplayName(KernelFeatureId id);

// backendToDisplayName converts backend metadata into a compact UI label. Input
// is one backend enum; processing uses a switch; output is a display string.
std::wstring backendToDisplayName(KernelFeatureBackend backend);

} // namespace Ksword::Features::Kernel
