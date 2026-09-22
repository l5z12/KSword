/*++

Module Name:

    platform_audit.c

Abstract:

    Audit of the HAL and KMDF binding tables, along with controlled atomic edits of their function slots. The KMDF binding
    table resides in a read-only section of Wdf01000.sys; the commit path creates a temporary writable MDL alias for it.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "driver/KswordArkPlatformAuditIoctl.h"
#include "../kernel/hook_scan_support.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntimage.h>
#include <ntstrsafe.h>
#include <stdarg.h>

// ntddk.h exposes these HAL_DISPATCH members as object-like convenience
// macros.  Undefine the aliases in this translation unit so FIELD_OFFSET and
// member-size expressions below refer to the actual structure fields.
#undef HalQuerySystemInformation
#undef HalSetSystemInformation
#undef HalQueryBusSlots
#undef HalReferenceHandlerForBus
#undef HalReferenceBusHandler
#undef HalDereferenceBusHandler
#undef HalInitPnpDriver
#undef HalInitPowerManagement
#undef HalGetDmaAdapter
#undef HalGetInterruptTranslator
#undef HalStartMirroring
#undef HalEndMirroring
#undef HalMirrorPhysicalMemory
#undef HalEndOfBoot
#undef HalMirrorVerify
#undef HalGetCachedAcpiTable
#undef HalSetPciErrorHandlerCallback
#undef HalGetPrmCache
#undef HalInvokePrmFwHandler

#define KSW_PLATFORM_RESPONSE_HEADER_SIZE \
    (FIELD_OFFSET(KSWORD_ARK_QUERY_PLATFORM_AUDIT_RESPONSE, entries))
// Note: The ULONG value in memory is 0x48414C20; do not mistakenly write it as 0x204C4148
// based on the ASCII byte order of "HAL ", or all real tables will be rejected.
#define KSW_PLATFORM_HAL_ACPI_SIGNATURE 0x48414C20UL
#define KSW_PLATFORM_HAL_ACPI_VERSION_V4 4UL
#define KSW_PLATFORM_HAL_ACPI_VERSION_V5 5UL
#define KSW_PLATFORM_HAL_ACPI_V4_FUNCTION_COUNT 21UL
#define KSW_PLATFORM_HAL_ACPI_V5_FUNCTION_COUNT 18UL
#define KSW_PLATFORM_HAL_ACPI_MAX_FUNCTION_COUNT \
    KSW_PLATFORM_HAL_ACPI_V4_FUNCTION_COUNT
#define KSW_PLATFORM_HAL_SUBCOMPONENT_LEGACY_COUNT 21UL
#define KSW_PLATFORM_HAL_SUBCOMPONENT_MAX_COUNT    22UL
#define KSW_PLATFORM_HAL_SUBCOMPONENT_QOS_INDEX    18UL

typedef struct KswPlatformSlotDescriptor
{
    ULONG offset;
    ULONG width;
    PCWSTR name;
    ULONG slotKind;
    ULONG ownerPolicy;
} KswPlatformSlotDescriptor;

typedef struct KswPlatformPrivateBuildDescriptor
{
    ULONG buildNumber;
    ULONG version;
    ULONG byteSize;
    ULONG signatureId;
} KswPlatformPrivateBuildDescriptor;

typedef struct KswPlatformHalAcpiView
{
    ULONG signature;
    ULONG version;
    PVOID functions[KSW_PLATFORM_HAL_ACPI_MAX_FUNCTION_COUNT];
} KswPlatformHalAcpiView;

typedef struct KswPlatformHalSubcomponent
{
    PVOID function;
    PCWSTR name;
} KswPlatformHalSubcomponent;

typedef struct KswPlatformCallbackDescriptor
{
    PVOID address;
    PCWSTR name;
} KswPlatformCallbackDescriptor;

#define KSW_PLATFORM_WIDE_IMPL(Value) L##Value
#define KSW_PLATFORM_WIDE(Value) KSW_PLATFORM_WIDE_IMPL(#Value)
#define KSW_HAL_PUBLIC_FUNCTION(Field, Policy) \
    { FIELD_OFFSET(HAL_DISPATCH, Field), sizeof(((PHAL_DISPATCH)0)->Field), \
      KSW_PLATFORM_WIDE(Field), KSWORD_ARK_PLATFORM_SLOT_FUNCTION, Policy }
#define KSW_HAL_PUBLIC_SCALAR(Field) \
    { FIELD_OFFSET(HAL_DISPATCH, Field), sizeof(((PHAL_DISPATCH)0)->Field), \
      KSW_PLATFORM_WIDE(Field), KSWORD_ARK_PLATFORM_SLOT_SCALAR, KSWORD_ARK_PLATFORM_OWNER_NONE }

static const KswPlatformSlotDescriptor kGKswHalDispatchSlots[] = {
    KSW_HAL_PUBLIC_FUNCTION(HalQuerySystemInformation, KSWORD_ARK_PLATFORM_OWNER_NT_HAL),
    KSW_HAL_PUBLIC_FUNCTION(HalSetSystemInformation, KSWORD_ARK_PLATFORM_OWNER_NT_HAL),
    KSW_HAL_PUBLIC_FUNCTION(HalQueryBusSlots, KSWORD_ARK_PLATFORM_OWNER_NT_HAL),
    KSW_HAL_PUBLIC_SCALAR(Spare1),
    KSW_HAL_PUBLIC_FUNCTION(HalExamineMBR, KSWORD_ARK_PLATFORM_OWNER_NT_HAL),
    KSW_HAL_PUBLIC_FUNCTION(HalIoReadPartitionTable, KSWORD_ARK_PLATFORM_OWNER_NT_HAL),
    KSW_HAL_PUBLIC_FUNCTION(HalIoSetPartitionInformation, KSWORD_ARK_PLATFORM_OWNER_NT_HAL),
    KSW_HAL_PUBLIC_FUNCTION(HalIoWritePartitionTable, KSWORD_ARK_PLATFORM_OWNER_NT_HAL),
    KSW_HAL_PUBLIC_FUNCTION(HalReferenceHandlerForBus, KSWORD_ARK_PLATFORM_OWNER_NT_HAL),
    KSW_HAL_PUBLIC_FUNCTION(HalReferenceBusHandler, KSWORD_ARK_PLATFORM_OWNER_NT_HAL),
    KSW_HAL_PUBLIC_FUNCTION(HalDereferenceBusHandler, KSWORD_ARK_PLATFORM_OWNER_NT_HAL),
    KSW_HAL_PUBLIC_FUNCTION(HalInitPnpDriver, KSWORD_ARK_PLATFORM_OWNER_NT_HAL),
    KSW_HAL_PUBLIC_FUNCTION(HalInitPowerManagement, KSWORD_ARK_PLATFORM_OWNER_NT_HAL_ACPI),
    KSW_HAL_PUBLIC_FUNCTION(HalGetDmaAdapter, KSWORD_ARK_PLATFORM_OWNER_NT_HAL),
    KSW_HAL_PUBLIC_FUNCTION(HalGetInterruptTranslator, KSWORD_ARK_PLATFORM_OWNER_NT_HAL),
    KSW_HAL_PUBLIC_FUNCTION(HalStartMirroring, KSWORD_ARK_PLATFORM_OWNER_NT_HAL),
    KSW_HAL_PUBLIC_FUNCTION(HalEndMirroring, KSWORD_ARK_PLATFORM_OWNER_NT_HAL),
    KSW_HAL_PUBLIC_FUNCTION(HalMirrorPhysicalMemory, KSWORD_ARK_PLATFORM_OWNER_NT_HAL),
    KSW_HAL_PUBLIC_FUNCTION(HalEndOfBoot, KSWORD_ARK_PLATFORM_OWNER_NT_HAL),
    KSW_HAL_PUBLIC_FUNCTION(HalMirrorVerify, KSWORD_ARK_PLATFORM_OWNER_NT_HAL),
    KSW_HAL_PUBLIC_FUNCTION(HalGetCachedAcpiTable, KSWORD_ARK_PLATFORM_OWNER_NT_HAL_ACPI),
    KSW_HAL_PUBLIC_FUNCTION(HalSetPciErrorHandlerCallback, KSWORD_ARK_PLATFORM_OWNER_NT_HAL_PCI),
    KSW_HAL_PUBLIC_FUNCTION(HalGetPrmCache, KSWORD_ARK_PLATFORM_OWNER_NT_HAL),
    KSW_HAL_PUBLIC_FUNCTION(HalInvokePrmFwHandler, KSWORD_ARK_PLATFORM_OWNER_NT_HAL)
};

#undef KSW_HAL_PUBLIC_SCALAR
#undef KSW_HAL_PUBLIC_FUNCTION
#undef KSW_PLATFORM_WIDE
#undef KSW_PLATFORM_WIDE_IMPL

#define KSW_PRIVATE_FUNCTION(OffsetValue, NameValue, PolicyValue) \
    { OffsetValue, sizeof(PVOID), L##NameValue, KSWORD_ARK_PLATFORM_SLOT_FUNCTION, PolicyValue }
#define KSW_PRIVATE_DUMMY(OffsetValue, NameValue) \
    { OffsetValue, sizeof(PVOID), L##NameValue, KSWORD_ARK_PLATFORM_SLOT_DUMMY, KSWORD_ARK_PLATFORM_OWNER_NONE }
#define KSW_PF(OffsetValue, NameValue) \
    KSW_PRIVATE_FUNCTION(OffsetValue, NameValue, KSWORD_ARK_PLATFORM_OWNER_NT_HAL)
#define KSW_PFP(OffsetValue, NameValue) \
    KSW_PRIVATE_FUNCTION(OffsetValue, NameValue, KSWORD_ARK_PLATFORM_OWNER_NT_HAL_PCI)
#define KSW_PFA(OffsetValue, NameValue) \
    KSW_PRIVATE_FUNCTION(OffsetValue, NameValue, KSWORD_ARK_PLATFORM_OWNER_NT_HAL_ACPI)

// Note: This descriptor table is the common prefix for ntdiff 22000/22621/26100 structures.
// Each version can only read the ByteSize specified in its build descriptor; never treat the tail or padding as functions.
static const KswPlatformSlotDescriptor kGKswHalPrivateSlots[] = {
    KSW_PF(0x008, "HalHandlerForBus"),
    KSW_PF(0x010, "HalHandlerForConfigSpace"),
    KSW_PF(0x018, "HalLocateHiberRanges"),
    KSW_PF(0x020, "HalRegisterBusHandler"),
    KSW_PFA(0x028, "HalSetWakeEnable"),
    KSW_PFA(0x030, "HalSetWakeAlarm"),
    KSW_PFP(0x038, "HalPciTranslateBusAddress"),
    KSW_PFP(0x040, "HalPciAssignSlotResources"),
    KSW_PF(0x048, "HalHaltSystem"),
    KSW_PF(0x050, "HalFindBusAddressTranslation"),
    KSW_PF(0x058, "HalResetDisplay"),
    KSW_PF(0x060, "HalAllocateMapRegisters"),
    KSW_PFP(0x068, "KdSetupPciDeviceForDebugging"),
    KSW_PFP(0x070, "KdReleasePciDeviceForDebugging"),
    KSW_PFA(0x078, "KdGetAcpiTablePhase0"),
    KSW_PFA(0x080, "KdCheckPowerButton"),
    KSW_PF(0x088, "HalVectorToIDTEntry"),
    KSW_PF(0x090, "KdMapPhysicalMemory64"),
    KSW_PF(0x098, "KdUnmapVirtualAddress"),
    KSW_PFP(0x0A0, "KdGetPciDataByOffset"),
    KSW_PFP(0x0A8, "KdSetPciDataByOffset"),
    KSW_PFA(0x0B0, "HalGetInterruptVectorOverride"),
    KSW_PFA(0x0B8, "HalGetVectorInputOverride"),
    KSW_PF(0x0C0, "HalLoadMicrocode"),
    KSW_PF(0x0C8, "HalUnloadMicrocode"),
    KSW_PF(0x0D0, "HalPostMicrocodeUpdate"),
    KSW_PFA(0x0D8, "HalAllocateMessageTargetOverride"),
    KSW_PFA(0x0E0, "HalFreeMessageTargetOverride"),
    KSW_PF(0x0E8, "HalDpReplaceBegin"),
    KSW_PF(0x0F0, "HalDpReplaceTarget"),
    KSW_PF(0x0F8, "HalDpReplaceControl"),
    KSW_PF(0x100, "HalDpReplaceEnd"),
    KSW_PF(0x108, "HalPrepareForBugcheck"),
    KSW_PFA(0x110, "HalQueryWakeTime"),
    KSW_PF(0x118, "HalReportIdleStateUsage"),
    KSW_PF(0x120, "HalTscSynchronization"),
    KSW_PF(0x128, "HalWheaInitProcessorGenericSection"),
    KSW_PF(0x130, "HalStopLegacyUsbInterrupts"),
    KSW_PF(0x138, "HalReadWheaPhysicalMemory"),
    KSW_PF(0x140, "HalWriteWheaPhysicalMemory"),
    KSW_PF(0x148, "HalDpMaskLevelTriggeredInterrupts"),
    KSW_PF(0x150, "HalDpUnmaskLevelTriggeredInterrupts"),
    KSW_PF(0x158, "HalDpGetInterruptReplayState"),
    KSW_PF(0x160, "HalDpReplayInterrupts"),
    KSW_PF(0x168, "HalQueryIoPortAccessSupported"),
    KSW_PF(0x170, "KdSetupIntegratedDeviceForDebugging"),
    KSW_PF(0x178, "KdReleaseIntegratedDeviceForDebugging"),
    KSW_PF(0x180, "HalGetEnlightenmentInformation"),
    KSW_PF(0x188, "HalAllocateEarlyPages"),
    KSW_PF(0x190, "HalMapEarlyPages"),
    KSW_PRIVATE_DUMMY(0x198, "Dummy1"),
    KSW_PRIVATE_DUMMY(0x1A0, "Dummy2"),
    KSW_PF(0x1A8, "HalNotifyProcessorFreeze"),
    KSW_PF(0x1B0, "HalPrepareProcessorForIdle"),
    KSW_PF(0x1B8, "HalRegisterLogRoutine"),
    KSW_PF(0x1C0, "HalResumeProcessorFromIdle"),
    KSW_PRIVATE_DUMMY(0x1C8, "Dummy"),
    KSW_PF(0x1D0, "HalVectorToIDTEntryEx"),
    KSW_PF(0x1D8, "HalSecondaryInterruptQueryPrimaryInformation"),
    KSW_PF(0x1E0, "HalMaskInterrupt"),
    KSW_PF(0x1E8, "HalUnmaskInterrupt"),
    KSW_PF(0x1F0, "HalIsInterruptTypeSecondary"),
    KSW_PF(0x1F8, "HalAllocateGsivForSecondaryInterrupt"),
    KSW_PF(0x200, "HalAddInterruptRemapping"),
    KSW_PF(0x208, "HalRemoveInterruptRemapping"),
    KSW_PF(0x210, "HalSaveAndDisableHvEnlightenment"),
    KSW_PF(0x218, "HalRestoreHvEnlightenment"),
    KSW_PF(0x220, "HalFlushIoBuffersExternalCache"),
    KSW_PF(0x228, "HalFlushExternalCache"),
    KSW_PFP(0x230, "HalPciEarlyRestore"),
    KSW_PF(0x238, "HalGetProcessorId"),
    KSW_PF(0x240, "HalAllocatePmcCounterSet"),
    KSW_PF(0x248, "HalCollectPmcCounters"),
    KSW_PF(0x250, "HalFreePmcCounterSet"),
    KSW_PF(0x258, "HalProcessorHalt"),
    KSW_PF(0x260, "HalTimerQueryCycleCounter"),
    KSW_PRIVATE_DUMMY(0x268, "Dummy3"),
    KSW_PFP(0x270, "HalPciMarkHiberPhase"),
    KSW_PF(0x278, "HalQueryProcessorRestartEntryPoint"),
    KSW_PF(0x280, "HalRequestInterrupt"),
    KSW_PF(0x288, "HalEnumerateUnmaskedInterrupts"),
    KSW_PF(0x290, "HalFlushAndInvalidatePageExternalCache"),
    KSW_PF(0x298, "KdEnumerateDebuggingDevices"),
    KSW_PF(0x2A0, "HalFlushIoRectangleExternalCache"),
    KSW_PFA(0x2A8, "HalPowerEarlyRestore"),
    KSW_PF(0x2B0, "HalQueryCapsuleCapabilities"),
    KSW_PF(0x2B8, "HalUpdateCapsule"),
    KSW_PFP(0x2C0, "HalPciMultiStageResumeCapable"),
    KSW_PF(0x2C8, "HalDmaFreeCrashDumpRegisters"),
    KSW_PFA(0x2D0, "HalAcpiAoacCapable"),
    KSW_PF(0x2D8, "HalInterruptSetDestination"),
    KSW_PF(0x2E0, "HalGetClockConfiguration"),
    KSW_PF(0x2E8, "HalClockTimerActivate"),
    KSW_PF(0x2F0, "HalClockTimerInitialize"),
    KSW_PF(0x2F8, "HalClockTimerStop"),
    KSW_PF(0x300, "HalClockTimerArm"),
    KSW_PF(0x308, "HalTimerOnlyClockInterruptPending"),
    KSW_PFA(0x310, "HalAcpiGetMultiNode"),
    KSW_PFA(0x318, "HalPowerSetRebootHandler"),
    KSW_PF(0x320, "HalIommuRegisterDispatchTable"),
    KSW_PF(0x328, "HalTimerWatchdogStart"),
    KSW_PF(0x330, "HalTimerWatchdogResetCountdown"),
    KSW_PF(0x338, "HalTimerWatchdogStop"),
    KSW_PF(0x340, "HalTimerWatchdogGeneratedLastReset"),
    KSW_PF(0x348, "HalTimerWatchdogTriggerSystemReset"),
    KSW_PF(0x350, "HalInterruptVectorDataToGsiv"),
    KSW_PF(0x358, "HalInterruptGetHighestPriorityInterrupt"),
    KSW_PF(0x360, "HalProcessorOn"),
    KSW_PF(0x368, "HalProcessorOff"),
    KSW_PF(0x370, "HalProcessorFreeze"),
    KSW_PF(0x378, "HalDmaLinkDeviceObjectByToken"),
    KSW_PF(0x380, "HalDmaCheckAdapterToken"),
    KSW_PRIVATE_DUMMY(0x388, "Dummy4"),
    KSW_PF(0x390, "HalTimerConvertPerformanceCounterToAuxiliaryCounter"),
    KSW_PF(0x398, "HalTimerConvertAuxiliaryCounterToPerformanceCounter"),
    KSW_PF(0x3A0, "HalTimerQueryAuxiliaryCounterFrequency"),
    KSW_PF(0x3A8, "HalConnectThermalInterrupt"),
    KSW_PF(0x3B0, "HalIsEFIRuntimeActive"),
    KSW_PF(0x3B8, "HalTimerQueryAndResetRtcErrors"),
    KSW_PFA(0x3C0, "HalAcpiLateRestore"),
    KSW_PF(0x3C8, "KdWatchdogDelayExpiration"),
    KSW_PF(0x3D0, "HalGetProcessorStats"),
    KSW_PF(0x3D8, "HalTimerWatchdogQueryDueTime"),
    KSW_PF(0x3E0, "HalConnectSyntheticInterrupt"),
    KSW_PF(0x3E8, "HalPreprocessNmi"),
    KSW_PF(0x3F0, "HalEnumerateEnvironmentVariablesWithFilter"),
    KSW_PF(0x3F8, "HalCaptureLastBranchRecordStack"),
    KSW_PF(0x400, "HalClearLastBranchRecordStack"),
    KSW_PF(0x408, "HalConfigureLastBranchRecord"),
    KSW_PF(0x410, "HalGetLastBranchInformation"),
    KSW_PF(0x418, "HalResumeLastBranchRecord"),
    KSW_PF(0x420, "HalStartLastBranchRecord"),
    KSW_PF(0x428, "HalStopLastBranchRecord"),
    KSW_PF(0x430, "HalIommuBlockDevice"),
    KSW_PF(0x438, "HalIommuUnblockDevice"),
    KSW_PF(0x440, "HalGetIommuInterface"),
    KSW_PF(0x448, "HalRequestGenericErrorRecovery"),
    KSW_PF(0x450, "HalTimerQueryHostPerformanceCounter"),
    KSW_PF(0x458, "HalTopologyQueryProcessorRelationships"),
    KSW_PF(0x460, "HalInitPlatformDebugTriggers"),
    KSW_PF(0x468, "HalRunPlatformDebugTriggers"),
    KSW_PF(0x470, "HalTimerGetReferencePage"),
    KSW_PF(0x478, "HalGetHiddenProcessorPowerInterface"),
    KSW_PF(0x480, "HalGetHiddenProcessorPackageId"),
    KSW_PF(0x488, "HalGetHiddenPackageProcessorCount"),
    KSW_PF(0x490, "HalGetHiddenProcessorApicIdByIndex"),
    KSW_PF(0x498, "HalRegisterHiddenProcessorIdleState"),
    KSW_PF(0x4A0, "HalIommuReportIommuFault"),
    KSW_PF(0x4A8, "HalIommuDmaRemappingCapable"),
    KSW_PF(0x4B0, "HalAllocatePmcCounterSetEx"),
    KSW_PF(0x4B8, "HalStartProfileInterruptEx"),
    KSW_PF(0x4C0, "HalGetIommuInterfaceEx"),
    KSW_PF(0x4C8, "HalNotifyIommuDomainPolicyChange"),
    KSW_PFP(0x4D0, "HalPciGetDeviceLocationFromPhysicalAddress"),
    KSW_PF(0x4D8, "HalInvokeSmc"),
    KSW_PF(0x4E0, "HalInvokeHvc"),
    KSW_PF(0x4E8, "HalGetSoftRebootDatabase"),
    KSW_PF(0x4F0, "HalRequestPmuAccess"),
    KSW_PF(0x4F8, "HalTopologyQueryProcessorCacheInformation"),
    KSW_PF(0x500, "HalReleasePmuAccessRequest"),
    KSW_PF(0x508, "HalTimerQueryRtcErrors"),
    KSW_PFP(0x510, "HalExternalPciConfigSpaceAccess")
};

#undef KSW_PFA
#undef KSW_PFP
#undef KSW_PF
#undef KSW_PRIVATE_DUMMY
#undef KSW_PRIVATE_FUNCTION

static const KswPlatformPrivateBuildDescriptor kGKswHalPrivateBuilds[] = {
    // Note: Versions 19041–19045 share the Vibranium kernel structure. At runtime, both Version=51 and the complete
    // 0x4B0 boundary range must be confirmed; do not rely solely on the system-reported product build for authorization.
    { 19041UL, 51UL, 0x4B0UL, KSWORD_ARK_PLATFORM_SIGNATURE_HAL_PRIVATE_V51 },
    { 22000UL, 54UL, 0x4D8UL, KSWORD_ARK_PLATFORM_SIGNATURE_HAL_PRIVATE_V54 },
    { 22621UL, 58UL, 0x4F0UL, KSWORD_ARK_PLATFORM_SIGNATURE_HAL_PRIVATE_V58 },
    { 26100UL, 61UL, 0x518UL, KSWORD_ARK_PLATFORM_SIGNATURE_HAL_PRIVATE_V61 },
    { 26220UL, 61UL, 0x518UL, KSWORD_ARK_PLATFORM_SIGNATURE_HAL_PRIVATE_V61 }
};

static const PCWSTR
kGKswHalAcpiFunctionNames[KSW_PLATFORM_HAL_ACPI_MAX_FUNCTION_COUNT] = {
    // Note: This displays implementation semantic names verified against public symbol samples, rather than misleading
    // field aliases found in old header files. Slot ordering remains constrained by HAL ACPI v5 structural identity.
    L"HalpAcpiTimerInterrupt",
    L"HaliAcpiMachineStateInit",
    L"HalpAcpiQueryFlags",
    L"HalpInterruptIsPicStateIntact",
    L"HalpInterruptRestoreAllControllerState",
    L"HaliPciInterfaceReadConfig",
    L"HaliPciInterfaceWriteConfig",
    L"HalpInterruptGetApicVersion",
    L"HaliSetMaxLegacyPciBusNumber",
    L"HalpInterruptIsGsiValid",
    L"HalAcpiGetTableDispatch",
    L"HalAcpiGetRsdpDispatch",
    L"HalAcpiGetFacsMappingDispatch",
    L"HalAcpiGetAllTablesDispatch",
    L"HalpAcpiPmRegisterAvailable",
    L"HalpAcpiPmRegisterRead",
    L"HalpAcpiPmRegisterWrite",
    L"HalpAcpiAccessSecureAddress",
    // Note: ACPI v4 retains three legacy PCI I/O configuration read slots at the tail.
    // v5 removed these slots, so the output count must be determined by the Version header.
    L"HalpPciReadIoConfigUlong",
    L"HalpPciReadIoConfigUchar",
    L"HalpPciReadIoConfigUshort"
};

static const PCWSTR
kGKswHalSubcomponentNames[KSW_PLATFORM_HAL_SUBCOMPONENT_MAX_COUNT] = {
    L"Acpi", L"Dbg", L"Dma", L"Dp", L"Errata", L"ExtEnv", L"Firmware",
    L"HalExt", L"Hv", L"HwPerfCnt", L"Interrupt", L"Iommu", L"Misc", L"Mm",
    L"Pci", L"Pnp", L"Power", L"Proc", L"Qos", L"Timer", L"Topology", L"Whea"
};

static const PCWSTR
kGKswHalSubcomponentFunctionNames[KSW_PLATFORM_HAL_SUBCOMPONENT_MAX_COUNT] = {
    L"HalpAcpiInitSystem",
    L"HalpDbgInitSystem",
    L"HalpDmaInitSystem",
    L"HalpDpInitSystem",
    L"HalpErrataInitSystem",
    L"HalpExtEnvInitSystem",
    L"HalpFirmwareInitSystem",
    L"HalpHalExtInitSystem",
    L"HalpHvInitSystem",
    L"HalpHwPerfCntInitSystem",
    L"HalpInterruptInitSystem",
    L"HalpIommuInitSystem",
    L"HalpMiscInitSystem",
    L"HalpMmInitSystem",
    L"HalpPciInitSystem",
    L"HalpPnpInitSystem",
    L"HalpPowerInitSystem",
    L"HalpProcInitSystem",
    L"HalpQosInitSystem",
    L"HalpTimerInitSystem",
    L"HalpTopologyInitSystem",
    L"HalpWheaInitSystem"
};

// KMDF 1.15 wdffuncenum.h defines a contiguous, index-stable table of 444 APIs.
// Keep the display names in that exact order so every WdfFunctions slot is named
// without relying on PDBs or runtime signature guesses.
static const PCWSTR kGKswWdfFunctionNames[] = {
    L"WdfChildListCreate",
    L"WdfChildListGetDevice",
    L"WdfChildListRetrievePdo",
    L"WdfChildListRetrieveAddressDescription",
    L"WdfChildListBeginScan",
    L"WdfChildListEndScan",
    L"WdfChildListBeginIteration",
    L"WdfChildListRetrieveNextDevice",
    L"WdfChildListEndIteration",
    L"WdfChildListAddOrUpdateChildDescriptionAsPresent",
    L"WdfChildListUpdateChildDescriptionAsMissing",
    L"WdfChildListUpdateAllChildDescriptionsAsPresent",
    L"WdfChildListRequestChildEject",
    L"WdfCollectionCreate",
    L"WdfCollectionGetCount",
    L"WdfCollectionAdd",
    L"WdfCollectionRemove",
    L"WdfCollectionRemoveItem",
    L"WdfCollectionGetItem",
    L"WdfCollectionGetFirstItem",
    L"WdfCollectionGetLastItem",
    L"WdfCommonBufferCreate",
    L"WdfCommonBufferGetAlignedVirtualAddress",
    L"WdfCommonBufferGetAlignedLogicalAddress",
    L"WdfCommonBufferGetLength",
    L"WdfControlDeviceInitAllocate",
    L"WdfControlDeviceInitSetShutdownNotification",
    L"WdfControlFinishInitializing",
    L"WdfDeviceGetDeviceState",
    L"WdfDeviceSetDeviceState",
    L"WdfWdmDeviceGetWdfDeviceHandle",
    L"WdfDeviceWdmGetDeviceObject",
    L"WdfDeviceWdmGetAttachedDevice",
    L"WdfDeviceWdmGetPhysicalDevice",
    L"WdfDeviceWdmDispatchPreprocessedIrp",
    L"WdfDeviceAddDependentUsageDeviceObject",
    L"WdfDeviceAddRemovalRelationsPhysicalDevice",
    L"WdfDeviceRemoveRemovalRelationsPhysicalDevice",
    L"WdfDeviceClearRemovalRelationsDevices",
    L"WdfDeviceGetDriver",
    L"WdfDeviceRetrieveDeviceName",
    L"WdfDeviceAssignMofResourceName",
    L"WdfDeviceGetIoTarget",
    L"WdfDeviceGetDevicePnpState",
    L"WdfDeviceGetDevicePowerState",
    L"WdfDeviceGetDevicePowerPolicyState",
    L"WdfDeviceAssignS0IdleSettings",
    L"WdfDeviceAssignSxWakeSettings",
    L"WdfDeviceOpenRegistryKey",
    L"WdfDeviceSetSpecialFileSupport",
    L"WdfDeviceSetCharacteristics",
    L"WdfDeviceGetCharacteristics",
    L"WdfDeviceGetAlignmentRequirement",
    L"WdfDeviceSetAlignmentRequirement",
    L"WdfDeviceInitFree",
    L"WdfDeviceInitSetPnpPowerEventCallbacks",
    L"WdfDeviceInitSetPowerPolicyEventCallbacks",
    L"WdfDeviceInitSetPowerPolicyOwnership",
    L"WdfDeviceInitRegisterPnpStateChangeCallback",
    L"WdfDeviceInitRegisterPowerStateChangeCallback",
    L"WdfDeviceInitRegisterPowerPolicyStateChangeCallback",
    L"WdfDeviceInitSetIoType",
    L"WdfDeviceInitSetExclusive",
    L"WdfDeviceInitSetPowerNotPageable",
    L"WdfDeviceInitSetPowerPageable",
    L"WdfDeviceInitSetPowerInrush",
    L"WdfDeviceInitSetDeviceType",
    L"WdfDeviceInitAssignName",
    L"WdfDeviceInitAssignSDDLString",
    L"WdfDeviceInitSetDeviceClass",
    L"WdfDeviceInitSetCharacteristics",
    L"WdfDeviceInitSetFileObjectConfig",
    L"WdfDeviceInitSetRequestAttributes",
    L"WdfDeviceInitAssignWdmIrpPreprocessCallback",
    L"WdfDeviceInitSetIoInCallerContextCallback",
    L"WdfDeviceCreate",
    L"WdfDeviceSetStaticStopRemove",
    L"WdfDeviceCreateDeviceInterface",
    L"WdfDeviceSetDeviceInterfaceState",
    L"WdfDeviceRetrieveDeviceInterfaceString",
    L"WdfDeviceCreateSymbolicLink",
    L"WdfDeviceQueryProperty",
    L"WdfDeviceAllocAndQueryProperty",
    L"WdfDeviceSetPnpCapabilities",
    L"WdfDeviceSetPowerCapabilities",
    L"WdfDeviceSetBusInformationForChildren",
    L"WdfDeviceIndicateWakeStatus",
    L"WdfDeviceSetFailed",
    L"WdfDeviceStopIdleNoTrack",
    L"WdfDeviceResumeIdleNoTrack",
    L"WdfDeviceGetFileObject",
    L"WdfDeviceEnqueueRequest",
    L"WdfDeviceGetDefaultQueue",
    L"WdfDeviceConfigureRequestDispatching",
    L"WdfDmaEnablerCreate",
    L"WdfDmaEnablerGetMaximumLength",
    L"WdfDmaEnablerGetMaximumScatterGatherElements",
    L"WdfDmaEnablerSetMaximumScatterGatherElements",
    L"WdfDmaTransactionCreate",
    L"WdfDmaTransactionInitialize",
    L"WdfDmaTransactionInitializeUsingRequest",
    L"WdfDmaTransactionExecute",
    L"WdfDmaTransactionRelease",
    L"WdfDmaTransactionDmaCompleted",
    L"WdfDmaTransactionDmaCompletedWithLength",
    L"WdfDmaTransactionDmaCompletedFinal",
    L"WdfDmaTransactionGetBytesTransferred",
    L"WdfDmaTransactionSetMaximumLength",
    L"WdfDmaTransactionGetRequest",
    L"WdfDmaTransactionGetCurrentDmaTransferLength",
    L"WdfDmaTransactionGetDevice",
    L"WdfDpcCreate",
    L"WdfDpcEnqueue",
    L"WdfDpcCancel",
    L"WdfDpcGetParentObject",
    L"WdfDpcWdmGetDpc",
    L"WdfDriverCreate",
    L"WdfDriverGetRegistryPath",
    L"WdfDriverWdmGetDriverObject",
    L"WdfDriverOpenParametersRegistryKey",
    L"WdfWdmDriverGetWdfDriverHandle",
    L"WdfDriverRegisterTraceInfo",
    L"WdfDriverRetrieveVersionString",
    L"WdfDriverIsVersionAvailable",
    L"WdfFdoInitWdmGetPhysicalDevice",
    L"WdfFdoInitOpenRegistryKey",
    L"WdfFdoInitQueryProperty",
    L"WdfFdoInitAllocAndQueryProperty",
    L"WdfFdoInitSetEventCallbacks",
    L"WdfFdoInitSetFilter",
    L"WdfFdoInitSetDefaultChildListConfig",
    L"WdfFdoQueryForInterface",
    L"WdfFdoGetDefaultChildList",
    L"WdfFdoAddStaticChild",
    L"WdfFdoLockStaticChildListForIteration",
    L"WdfFdoRetrieveNextStaticChild",
    L"WdfFdoUnlockStaticChildListFromIteration",
    L"WdfFileObjectGetFileName",
    L"WdfFileObjectGetFlags",
    L"WdfFileObjectGetDevice",
    L"WdfFileObjectWdmGetFileObject",
    L"WdfInterruptCreate",
    L"WdfInterruptQueueDpcForIsr",
    L"WdfInterruptSynchronize",
    L"WdfInterruptAcquireLock",
    L"WdfInterruptReleaseLock",
    L"WdfInterruptEnable",
    L"WdfInterruptDisable",
    L"WdfInterruptWdmGetInterrupt",
    L"WdfInterruptGetInfo",
    L"WdfInterruptSetPolicy",
    L"WdfInterruptGetDevice",
    L"WdfIoQueueCreate",
    L"WdfIoQueueGetState",
    L"WdfIoQueueStart",
    L"WdfIoQueueStop",
    L"WdfIoQueueStopSynchronously",
    L"WdfIoQueueGetDevice",
    L"WdfIoQueueRetrieveNextRequest",
    L"WdfIoQueueRetrieveRequestByFileObject",
    L"WdfIoQueueFindRequest",
    L"WdfIoQueueRetrieveFoundRequest",
    L"WdfIoQueueDrainSynchronously",
    L"WdfIoQueueDrain",
    L"WdfIoQueuePurgeSynchronously",
    L"WdfIoQueuePurge",
    L"WdfIoQueueReadyNotify",
    L"WdfIoTargetCreate",
    L"WdfIoTargetOpen",
    L"WdfIoTargetCloseForQueryRemove",
    L"WdfIoTargetClose",
    L"WdfIoTargetStart",
    L"WdfIoTargetStop",
    L"WdfIoTargetGetState",
    L"WdfIoTargetGetDevice",
    L"WdfIoTargetQueryTargetProperty",
    L"WdfIoTargetAllocAndQueryTargetProperty",
    L"WdfIoTargetQueryForInterface",
    L"WdfIoTargetWdmGetTargetDeviceObject",
    L"WdfIoTargetWdmGetTargetPhysicalDevice",
    L"WdfIoTargetWdmGetTargetFileObject",
    L"WdfIoTargetWdmGetTargetFileHandle",
    L"WdfIoTargetSendReadSynchronously",
    L"WdfIoTargetFormatRequestForRead",
    L"WdfIoTargetSendWriteSynchronously",
    L"WdfIoTargetFormatRequestForWrite",
    L"WdfIoTargetSendIoctlSynchronously",
    L"WdfIoTargetFormatRequestForIoctl",
    L"WdfIoTargetSendInternalIoctlSynchronously",
    L"WdfIoTargetFormatRequestForInternalIoctl",
    L"WdfIoTargetSendInternalIoctlOthersSynchronously",
    L"WdfIoTargetFormatRequestForInternalIoctlOthers",
    L"WdfMemoryCreate",
    L"WdfMemoryCreatePreallocated",
    L"WdfMemoryGetBuffer",
    L"WdfMemoryAssignBuffer",
    L"WdfMemoryCopyToBuffer",
    L"WdfMemoryCopyFromBuffer",
    L"WdfLookasideListCreate",
    L"WdfMemoryCreateFromLookaside",
    L"WdfDeviceMiniportCreate",
    L"WdfDriverMiniportUnload",
    L"WdfObjectGetTypedContextWorker",
    L"WdfObjectAllocateContext",
    L"WdfObjectContextGetObject",
    L"WdfObjectReferenceActual",
    L"WdfObjectDereferenceActual",
    L"WdfObjectCreate",
    L"WdfObjectDelete",
    L"WdfObjectQuery",
    L"WdfPdoInitAllocate",
    L"WdfPdoInitSetEventCallbacks",
    L"WdfPdoInitAssignDeviceID",
    L"WdfPdoInitAssignInstanceID",
    L"WdfPdoInitAddHardwareID",
    L"WdfPdoInitAddCompatibleID",
    L"WdfPdoInitAddDeviceText",
    L"WdfPdoInitSetDefaultLocale",
    L"WdfPdoInitAssignRawDevice",
    L"WdfPdoMarkMissing",
    L"WdfPdoRequestEject",
    L"WdfPdoGetParent",
    L"WdfPdoRetrieveIdentificationDescription",
    L"WdfPdoRetrieveAddressDescription",
    L"WdfPdoUpdateAddressDescription",
    L"WdfPdoAddEjectionRelationsPhysicalDevice",
    L"WdfPdoRemoveEjectionRelationsPhysicalDevice",
    L"WdfPdoClearEjectionRelationsDevices",
    L"WdfDeviceAddQueryInterface",
    L"WdfRegistryOpenKey",
    L"WdfRegistryCreateKey",
    L"WdfRegistryClose",
    L"WdfRegistryWdmGetHandle",
    L"WdfRegistryRemoveKey",
    L"WdfRegistryRemoveValue",
    L"WdfRegistryQueryValue",
    L"WdfRegistryQueryMemory",
    L"WdfRegistryQueryMultiString",
    L"WdfRegistryQueryUnicodeString",
    L"WdfRegistryQueryString",
    L"WdfRegistryQueryULong",
    L"WdfRegistryAssignValue",
    L"WdfRegistryAssignMemory",
    L"WdfRegistryAssignMultiString",
    L"WdfRegistryAssignUnicodeString",
    L"WdfRegistryAssignString",
    L"WdfRegistryAssignULong",
    L"WdfRequestCreate",
    L"WdfRequestCreateFromIrp",
    L"WdfRequestReuse",
    L"WdfRequestChangeTarget",
    L"WdfRequestFormatRequestUsingCurrentType",
    L"WdfRequestWdmFormatUsingStackLocation",
    L"WdfRequestSend",
    L"WdfRequestGetStatus",
    L"WdfRequestMarkCancelable",
    L"WdfRequestUnmarkCancelable",
    L"WdfRequestIsCanceled",
    L"WdfRequestCancelSentRequest",
    L"WdfRequestIsFrom32BitProcess",
    L"WdfRequestSetCompletionRoutine",
    L"WdfRequestGetCompletionParams",
    L"WdfRequestAllocateTimer",
    L"WdfRequestComplete",
    L"WdfRequestCompleteWithPriorityBoost",
    L"WdfRequestCompleteWithInformation",
    L"WdfRequestGetParameters",
    L"WdfRequestRetrieveInputMemory",
    L"WdfRequestRetrieveOutputMemory",
    L"WdfRequestRetrieveInputBuffer",
    L"WdfRequestRetrieveOutputBuffer",
    L"WdfRequestRetrieveInputWdmMdl",
    L"WdfRequestRetrieveOutputWdmMdl",
    L"WdfRequestRetrieveUnsafeUserInputBuffer",
    L"WdfRequestRetrieveUnsafeUserOutputBuffer",
    L"WdfRequestSetInformation",
    L"WdfRequestGetInformation",
    L"WdfRequestGetFileObject",
    L"WdfRequestProbeAndLockUserBufferForRead",
    L"WdfRequestProbeAndLockUserBufferForWrite",
    L"WdfRequestGetRequestorMode",
    L"WdfRequestForwardToIoQueue",
    L"WdfRequestGetIoQueue",
    L"WdfRequestRequeue",
    L"WdfRequestStopAcknowledge",
    L"WdfRequestWdmGetIrp",
    L"WdfIoResourceRequirementsListSetSlotNumber",
    L"WdfIoResourceRequirementsListSetInterfaceType",
    L"WdfIoResourceRequirementsListAppendIoResList",
    L"WdfIoResourceRequirementsListInsertIoResList",
    L"WdfIoResourceRequirementsListGetCount",
    L"WdfIoResourceRequirementsListGetIoResList",
    L"WdfIoResourceRequirementsListRemove",
    L"WdfIoResourceRequirementsListRemoveByIoResList",
    L"WdfIoResourceListCreate",
    L"WdfIoResourceListAppendDescriptor",
    L"WdfIoResourceListInsertDescriptor",
    L"WdfIoResourceListUpdateDescriptor",
    L"WdfIoResourceListGetCount",
    L"WdfIoResourceListGetDescriptor",
    L"WdfIoResourceListRemove",
    L"WdfIoResourceListRemoveByDescriptor",
    L"WdfCmResourceListAppendDescriptor",
    L"WdfCmResourceListInsertDescriptor",
    L"WdfCmResourceListGetCount",
    L"WdfCmResourceListGetDescriptor",
    L"WdfCmResourceListRemove",
    L"WdfCmResourceListRemoveByDescriptor",
    L"WdfStringCreate",
    L"WdfStringGetUnicodeString",
    L"WdfObjectAcquireLock",
    L"WdfObjectReleaseLock",
    L"WdfWaitLockCreate",
    L"WdfWaitLockAcquire",
    L"WdfWaitLockRelease",
    L"WdfSpinLockCreate",
    L"WdfSpinLockAcquire",
    L"WdfSpinLockRelease",
    L"WdfTimerCreate",
    L"WdfTimerStart",
    L"WdfTimerStop",
    L"WdfTimerGetParentObject",
    L"WdfUsbTargetDeviceCreate",
    L"WdfUsbTargetDeviceRetrieveInformation",
    L"WdfUsbTargetDeviceGetDeviceDescriptor",
    L"WdfUsbTargetDeviceRetrieveConfigDescriptor",
    L"WdfUsbTargetDeviceQueryString",
    L"WdfUsbTargetDeviceAllocAndQueryString",
    L"WdfUsbTargetDeviceFormatRequestForString",
    L"WdfUsbTargetDeviceGetNumInterfaces",
    L"WdfUsbTargetDeviceSelectConfig",
    L"WdfUsbTargetDeviceWdmGetConfigurationHandle",
    L"WdfUsbTargetDeviceRetrieveCurrentFrameNumber",
    L"WdfUsbTargetDeviceSendControlTransferSynchronously",
    L"WdfUsbTargetDeviceFormatRequestForControlTransfer",
    L"WdfUsbTargetDeviceIsConnectedSynchronous",
    L"WdfUsbTargetDeviceResetPortSynchronously",
    L"WdfUsbTargetDeviceCyclePortSynchronously",
    L"WdfUsbTargetDeviceFormatRequestForCyclePort",
    L"WdfUsbTargetDeviceSendUrbSynchronously",
    L"WdfUsbTargetDeviceFormatRequestForUrb",
    L"WdfUsbTargetPipeGetInformation",
    L"WdfUsbTargetPipeIsInEndpoint",
    L"WdfUsbTargetPipeIsOutEndpoint",
    L"WdfUsbTargetPipeGetType",
    L"WdfUsbTargetPipeSetNoMaximumPacketSizeCheck",
    L"WdfUsbTargetPipeWriteSynchronously",
    L"WdfUsbTargetPipeFormatRequestForWrite",
    L"WdfUsbTargetPipeReadSynchronously",
    L"WdfUsbTargetPipeFormatRequestForRead",
    L"WdfUsbTargetPipeConfigContinuousReader",
    L"WdfUsbTargetPipeAbortSynchronously",
    L"WdfUsbTargetPipeFormatRequestForAbort",
    L"WdfUsbTargetPipeResetSynchronously",
    L"WdfUsbTargetPipeFormatRequestForReset",
    L"WdfUsbTargetPipeSendUrbSynchronously",
    L"WdfUsbTargetPipeFormatRequestForUrb",
    L"WdfUsbInterfaceGetInterfaceNumber",
    L"WdfUsbInterfaceGetNumEndpoints",
    L"WdfUsbInterfaceGetDescriptor",
    L"WdfUsbInterfaceSelectSetting",
    L"WdfUsbInterfaceGetEndpointInformation",
    L"WdfUsbTargetDeviceGetInterface",
    L"WdfUsbInterfaceGetConfiguredSettingIndex",
    L"WdfUsbInterfaceGetNumConfiguredPipes",
    L"WdfUsbInterfaceGetConfiguredPipe",
    L"WdfUsbTargetPipeWdmGetPipeHandle",
    L"WdfVerifierDbgBreakPoint",
    L"WdfVerifierKeBugCheck",
    L"WdfWmiProviderCreate",
    L"WdfWmiProviderGetDevice",
    L"WdfWmiProviderIsEnabled",
    L"WdfWmiProviderGetTracingHandle",
    L"WdfWmiInstanceCreate",
    L"WdfWmiInstanceRegister",
    L"WdfWmiInstanceDeregister",
    L"WdfWmiInstanceGetDevice",
    L"WdfWmiInstanceGetProvider",
    L"WdfWmiInstanceFireEvent",
    L"WdfWorkItemCreate",
    L"WdfWorkItemEnqueue",
    L"WdfWorkItemGetParentObject",
    L"WdfWorkItemFlush",
    L"WdfCommonBufferCreateWithConfig",
    L"WdfDmaEnablerGetFragmentLength",
    L"WdfDmaEnablerWdmGetDmaAdapter",
    L"WdfUsbInterfaceGetNumSettings",
    L"WdfDeviceRemoveDependentUsageDeviceObject",
    L"WdfDeviceGetSystemPowerAction",
    L"WdfInterruptSetExtendedPolicy",
    L"WdfIoQueueAssignForwardProgressPolicy",
    L"WdfPdoInitAssignContainerID",
    L"WdfPdoInitAllowForwardingRequestToParent",
    L"WdfRequestMarkCancelableEx",
    L"WdfRequestIsReserved",
    L"WdfRequestForwardToParentDeviceIoQueue",
    L"WdfCxDeviceInitAllocate",
    L"WdfCxDeviceInitAssignWdmIrpPreprocessCallback",
    L"WdfCxDeviceInitSetIoInCallerContextCallback",
    L"WdfCxDeviceInitSetRequestAttributes",
    L"WdfCxDeviceInitSetFileObjectConfig",
    L"WdfDeviceWdmDispatchIrp",
    L"WdfDeviceWdmDispatchIrpToIoQueue",
    L"WdfDeviceInitSetRemoveLockOptions",
    L"WdfDeviceConfigureWdmIrpDispatchCallback",
    L"WdfDmaEnablerConfigureSystemProfile",
    L"WdfDmaTransactionInitializeUsingOffset",
    L"WdfDmaTransactionGetTransferInfo",
    L"WdfDmaTransactionSetChannelConfigurationCallback",
    L"WdfDmaTransactionSetTransferCompleteCallback",
    L"WdfDmaTransactionSetImmediateExecution",
    L"WdfDmaTransactionAllocateResources",
    L"WdfDmaTransactionSetDeviceAddressOffset",
    L"WdfDmaTransactionFreeResources",
    L"WdfDmaTransactionCancel",
    L"WdfDmaTransactionWdmGetTransferContext",
    L"WdfInterruptQueueWorkItemForIsr",
    L"WdfInterruptTryToAcquireLock",
    L"WdfIoQueueStopAndPurge",
    L"WdfIoQueueStopAndPurgeSynchronously",
    L"WdfIoTargetPurge",
    L"WdfUsbTargetDeviceCreateWithParameters",
    L"WdfUsbTargetDeviceQueryUsbCapability",
    L"WdfUsbTargetDeviceCreateUrb",
    L"WdfUsbTargetDeviceCreateIsochUrb",
    L"WdfDeviceWdmAssignPowerFrameworkSettings",
    L"WdfDmaTransactionStopSystemTransfer",
    L"WdfCxVerifierKeBugCheck",
    L"WdfInterruptReportActive",
    L"WdfInterruptReportInactive",
    L"WdfDeviceInitSetReleaseHardwareOrderOnFailure",
    L"WdfGetTriageInfo",
    L"WdfDeviceInitSetIoTypeEx",
    L"WdfDeviceQueryPropertyEx",
    L"WdfDeviceAllocAndQueryPropertyEx",
    L"WdfDeviceAssignProperty",
    L"WdfFdoInitQueryPropertyEx",
    L"WdfFdoInitAllocAndQueryPropertyEx",
    L"WdfDeviceStopIdleActual",
    L"WdfDeviceResumeIdleActual",
    L"WdfDeviceGetSelfIoTarget",
    L"WdfDeviceInitAllowSelfIoTarget",
    L"WdfIoTargetSelfAssignDefaultIoQueue",
    L"WdfDeviceOpenDevicemapKey"
};
C_ASSERT(RTL_NUMBER_OF(kGKswWdfFunctionNames) == WdfFunctionTableNumEntries);

static const KswPlatformCallbackDescriptor kGKswWdfCallbacks[] = {
    { (PVOID)kswordArkDriverEvtDriverUnload, L"KswordARKDriverEvtDriverUnload" },
    { (PVOID)kswordArkDriverEvtDriverContextCleanup, L"KswordARKDriverEvtDriverContextCleanup" },
    { (PVOID)kswordArkDriverEvtIoDeviceControl, L"KswordARKDriverEvtIoDeviceControl" },
    { (PVOID)kswordArkDriverEvtIoRead, L"KswordARKDriverEvtIoRead" },
    { (PVOID)kswordArkDriverEvtIoStop, L"KswordARKDriverEvtIoStop" },
    { (PVOID)kswordArkDriverEvtDevicePrepareHardware, L"KswordARKDriverEvtDevicePrepareHardware" }
};

static VOID
kswPlatformCopyWide(
    _Out_writes_(destinationChars) PWCHAR destination,
    _In_ ULONG destinationChars,
    _In_opt_z_ PCWSTR source
    )
{
    if (destination == NULL || destinationChars == 0UL) {
        return;
    }
    destination[0] = L'\0';
    if (source != NULL) {
        (VOID)RtlStringCchCopyNW(destination, destinationChars, source, destinationChars - 1UL);
    }
}

static PVOID
kswPlatformGetRoutine(
    _In_z_ PCWSTR routineName
    )
{
    UNICODE_STRING routineNameString;

    if (routineName == NULL) {
        return NULL;
    }
    RtlInitUnicodeString(&routineNameString, routineName);
    return MmGetSystemRoutineAddress(&routineNameString);
}

static BOOLEAN
kswPlatformModuleNameEquals(
    _In_opt_ const KswHookSystemModuleEntry* module,
    _In_z_ PCSTR expectedName
    )
{
    const UCHAR* fileName = NULL;
    ULONG fileNameBytes = 0UL;

    if (module == NULL || expectedName == NULL) {
        return FALSE;
    }
    kswordArkHookGetModuleFileName(module, &fileName, &fileNameBytes);
    return kswordArkHookBoundedAnsiEqualsInsensitive(fileName, fileNameBytes, expectedName);
}

static BOOLEAN
kswPlatformIsExpectedHalOwner(
    _In_opt_ const KswHookSystemModuleEntry* module
    )
{
    return kswPlatformModuleNameEquals(module, "ntoskrnl.exe") ||
        kswPlatformModuleNameEquals(module, "ntkrnlmp.exe") ||
        kswPlatformModuleNameEquals(module, "ntkrnlpa.exe") ||
        kswPlatformModuleNameEquals(module, "ntkrpamp.exe") ||
        kswPlatformModuleNameEquals(module, "hal.dll");
}

static BOOLEAN
kswPlatformOwnerMatchesPolicy(
    _In_opt_ const KswHookSystemModuleEntry* module,
    _In_ ULONG ownerPolicy
    )
{
    switch (ownerPolicy) {
    case KSWORD_ARK_PLATFORM_OWNER_NT_HAL:
        return kswPlatformIsExpectedHalOwner(module);
    case KSWORD_ARK_PLATFORM_OWNER_NT_HAL_PCI:
        return kswPlatformIsExpectedHalOwner(module) ||
            kswPlatformModuleNameEquals(module, "pci.sys");
    case KSWORD_ARK_PLATFORM_OWNER_NT_HAL_ACPI:
        return kswPlatformIsExpectedHalOwner(module) ||
            kswPlatformModuleNameEquals(module, "ACPI.sys");
    case KSWORD_ARK_PLATFORM_OWNER_WDF:
        return kswPlatformModuleNameEquals(module, "Wdf01000.sys");
    case KSWORD_ARK_PLATFORM_OWNER_KSWORD:
        return kswPlatformModuleNameEquals(module, "KswordARK.sys");
    default:
        return FALSE;
    }
}

static VOID
kswPlatformFillModule(
    _Inout_ KSWORD_ARK_PLATFORM_AUDIT_ENTRY* entry,
    _In_opt_ const KswHookSystemModuleEntry* module
    )
{
    if (entry == NULL || module == NULL) {
        return;
    }

    entry->moduleBase = (ULONGLONG)(ULONG_PTR)module->imageBase;
    entry->moduleSize = module->imageSize;
    entry->fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_MODULE;
    kswordArkHookCopyBoundedAnsiToWide(
        module->fullPathName,
        RTL_NUMBER_OF(module->fullPathName),
        entry->modulePath,
        RTL_NUMBER_OF(entry->modulePath));
}

static BOOLEAN
kswPlatformAddressSectionMatches(
    _In_ const KswHookSystemModuleEntry* module,
    _In_ ULONG_PTR address,
    _In_ BOOLEAN requireExecutable
    )
{
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS ntHeaders;
    ULONG sectionIndex = 0UL;
    ULONG sectionTableRva = 0UL;

    if (module == NULL ||
        address < (ULONG_PTR)module->imageBase ||
        address >= ((ULONG_PTR)module->imageBase + module->imageSize)) {
        return FALSE;
    }
    if (!kswordArkHookReadMemorySafe(module->imageBase, &dosHeader, sizeof(dosHeader)) ||
        dosHeader.e_magic != IMAGE_DOS_SIGNATURE ||
        dosHeader.e_lfanew <= 0 ||
        !kswordArkHookValidateRvaRange((ULONG)dosHeader.e_lfanew, sizeof(ntHeaders), module->imageSize) ||
        !kswordArkHookReadMemorySafe(
            (const UCHAR*)module->imageBase + (ULONG)dosHeader.e_lfanew,
            &ntHeaders,
            sizeof(ntHeaders)) ||
        ntHeaders.Signature != IMAGE_NT_SIGNATURE ||
        ntHeaders.FileHeader.NumberOfSections == 0U ||
        ntHeaders.FileHeader.NumberOfSections > 96U) {
        return FALSE;
    }

    sectionTableRva = (ULONG)dosHeader.e_lfanew +
        FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) +
        ntHeaders.FileHeader.SizeOfOptionalHeader;
    for (sectionIndex = 0UL; sectionIndex < ntHeaders.FileHeader.NumberOfSections; ++sectionIndex) {
        IMAGE_SECTION_HEADER sectionHeader;
        ULONG currentRva = sectionTableRva + (sectionIndex * sizeof(IMAGE_SECTION_HEADER));
        ULONG span = 0UL;
        ULONG_PTR startAddress = 0U;
        ULONG_PTR endAddress = 0U;
        BOOLEAN executable = FALSE;

        if (!kswordArkHookValidateRvaRange(currentRva, sizeof(sectionHeader), module->imageSize) ||
            !kswordArkHookReadMemorySafe(
                (const UCHAR*)module->imageBase + currentRva,
                &sectionHeader,
                sizeof(sectionHeader))) {
            return FALSE;
        }

        span = sectionHeader.Misc.VirtualSize;
        if (span < sectionHeader.SizeOfRawData) {
            span = sectionHeader.SizeOfRawData;
        }
        if (span == 0UL ||
            !kswordArkHookValidateRvaRange(sectionHeader.VirtualAddress, span, module->imageSize)) {
            continue;
        }

        startAddress = (ULONG_PTR)module->imageBase + sectionHeader.VirtualAddress;
        endAddress = startAddress + span;
        executable = (sectionHeader.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0UL;
        if (address >= startAddress &&
            address < endAddress &&
            executable == requireExecutable) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN
kswPlatformRangeInSection(
    _In_ const KswHookSystemModuleEntry* module,
    _In_ ULONG_PTR address,
    _In_ SIZE_T byteCount,
    _In_ BOOLEAN requireExecutable,
    _In_ BOOLEAN requireReadOnly
    )
{
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS ntHeaders;
    ULONG sectionIndex = 0UL;
    ULONG sectionTableRva = 0UL;
    ULONG_PTR rangeEnd = 0U;

    if (module == NULL || byteCount == 0U ||
        address < (ULONG_PTR)module->imageBase ||
        address > MAXULONG_PTR - byteCount) {
        return FALSE;
    }
    rangeEnd = address + byteCount;
    if (rangeEnd > (ULONG_PTR)module->imageBase + module->imageSize) {
        return FALSE;
    }
    if (!kswordArkHookReadMemorySafe(module->imageBase, &dosHeader, sizeof(dosHeader)) ||
        dosHeader.e_magic != IMAGE_DOS_SIGNATURE ||
        dosHeader.e_lfanew <= 0 ||
        !kswordArkHookValidateRvaRange((ULONG)dosHeader.e_lfanew, sizeof(ntHeaders), module->imageSize) ||
        !kswordArkHookReadMemorySafe(
            (const UCHAR*)module->imageBase + (ULONG)dosHeader.e_lfanew,
            &ntHeaders,
            sizeof(ntHeaders)) ||
        ntHeaders.Signature != IMAGE_NT_SIGNATURE ||
        ntHeaders.FileHeader.NumberOfSections == 0U ||
        ntHeaders.FileHeader.NumberOfSections > 96U) {
        return FALSE;
    }

    sectionTableRva = (ULONG)dosHeader.e_lfanew +
        FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) +
        ntHeaders.FileHeader.SizeOfOptionalHeader;
    for (sectionIndex = 0UL; sectionIndex < ntHeaders.FileHeader.NumberOfSections; ++sectionIndex) {
        IMAGE_SECTION_HEADER sectionHeader;
        ULONG currentRva = sectionTableRva + (sectionIndex * sizeof(IMAGE_SECTION_HEADER));
        ULONG span = 0UL;
        ULONG_PTR sectionStart = 0U;
        ULONG_PTR sectionEnd = 0U;
        BOOLEAN executable = FALSE;
        BOOLEAN writable = FALSE;

        if (!kswordArkHookValidateRvaRange(currentRva, sizeof(sectionHeader), module->imageSize) ||
            !kswordArkHookReadMemorySafe(
                (const UCHAR*)module->imageBase + currentRva,
                &sectionHeader,
                sizeof(sectionHeader))) {
            return FALSE;
        }
        span = sectionHeader.Misc.VirtualSize;
        if (span < sectionHeader.SizeOfRawData) {
            span = sectionHeader.SizeOfRawData;
        }
        if (span == 0UL ||
            !kswordArkHookValidateRvaRange(sectionHeader.VirtualAddress, span, module->imageSize)) {
            continue;
        }
        sectionStart = (ULONG_PTR)module->imageBase + sectionHeader.VirtualAddress;
        sectionEnd = sectionStart + span;
        executable = (sectionHeader.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0UL;
        writable = (sectionHeader.Characteristics & IMAGE_SCN_MEM_WRITE) != 0UL;
        if (address >= sectionStart && rangeEnd <= sectionEnd &&
            executable == requireExecutable &&
            (!requireReadOnly || !writable)) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN
kswPlatformRangeInWritableDataSection(
    _In_ const KswHookSystemModuleEntry* module,
    _In_ ULONG_PTR address,
    _In_ SIZE_T byteCount
    )
/*++

Routine Description:

    Check if the non-executable section containing the range has IMAGE_SCN_MEM_WRITE. Express this using two existing queries to avoid
    modifying the section validation function relied upon by over a dozen read-only paths for a single edit-time criterion: first
    confirm the range falls within a non-executable section, then confirm it is not a 'non-executable and non-writable' section.

Return Value:

    TRUE indicates the slot falls within a writable data section, allowing a direct CAS; if FALSE, the caller must
    first establish a writable MDL alias, otherwise writing to a read-only image page will cause a bug check 0xBE.

--*/
{
    return (BOOLEAN)(
        kswPlatformRangeInSection(module, address, byteCount, FALSE, FALSE) &&
        !kswPlatformRangeInSection(module, address, byteCount, FALSE, TRUE));
}

static BOOLEAN
kswPlatformAddSignedDisplacement(
    _In_ ULONG64 base,
    _In_ LONGLONG displacement,
    _Out_ ULONG64* resultOut
    );

static BOOLEAN
kswPlatformDecodeDetourTarget(
    _In_ ULONG64 address,
    _Out_ ULONG64* targetOut
    )
{
    UCHAR codeBytes[16];
    ULONG offset = 0UL;

    if (targetOut == NULL || address == 0ULL) {
        return FALSE;
    }
    *targetOut = 0ULL;
    RtlZeroMemory(codeBytes, sizeof(codeBytes));
    if (!kswordArkHookReadMemorySafe((const VOID*)(ULONG_PTR)address, codeBytes, sizeof(codeBytes))) {
        return FALSE;
    }

    if (codeBytes[0] == 0xF3U && codeBytes[1] == 0x0FU &&
        codeBytes[2] == 0x1EU && codeBytes[3] == 0xFAU) {
        offset = 4UL;
    }

    if (codeBytes[offset] == 0xE9U) {
        LONG displacement = 0;
        ULONG64 instructionEnd = 0ULL;
        RtlCopyMemory(&displacement, &codeBytes[offset + 1UL], sizeof(displacement));
        if (address > MAXULONGLONG - offset - 5ULL) {
            return FALSE;
        }
        instructionEnd = address + offset + 5ULL;
        return kswPlatformAddSignedDisplacement(
            instructionEnd,
            (LONGLONG)displacement,
            targetOut);
    }
    if (codeBytes[offset] == 0xEBU) {
        CHAR displacement8 = (CHAR)codeBytes[offset + 1UL];
        ULONG64 instructionEnd = 0ULL;
        if (address > MAXULONGLONG - offset - 2ULL) {
            return FALSE;
        }
        instructionEnd = address + offset + 2ULL;
        return kswPlatformAddSignedDisplacement(
            instructionEnd,
            (LONGLONG)displacement8,
            targetOut);
    }
    if (codeBytes[offset] == 0xFFU && codeBytes[offset + 1UL] == 0x25U) {
        LONG displacement = 0;
        ULONG64 pointerAddress = 0ULL;
        ULONG64 instructionEnd = 0ULL;
        RtlCopyMemory(&displacement, &codeBytes[offset + 2UL], sizeof(displacement));
        if (address > MAXULONGLONG - offset - 6ULL) {
            return FALSE;
        }
        instructionEnd = address + offset + 6ULL;
        if (!kswPlatformAddSignedDisplacement(
                instructionEnd,
                (LONGLONG)displacement,
                &pointerAddress)) {
            return FALSE;
        }
        return kswordArkHookReadMemorySafe(
            (const VOID*)(ULONG_PTR)pointerAddress,
            targetOut,
            sizeof(*targetOut));
    }
    if (codeBytes[offset] == 0x48U && codeBytes[offset + 1UL] == 0xB8U &&
        codeBytes[offset + 10UL] == 0xFFU && codeBytes[offset + 11UL] == 0xE0U) {
        RtlCopyMemory(targetOut, &codeBytes[offset + 2UL], sizeof(*targetOut));
        return TRUE;
    }
    return FALSE;
}

static BOOLEAN
kswPlatformAddSignedDisplacement(
    _In_ ULONG64 base,
    _In_ LONGLONG displacement,
    _Out_ ULONG64* resultOut
    )
{
    ULONG64 magnitude = 0ULL;

    if (resultOut == NULL) {
        return FALSE;
    }
    *resultOut = 0ULL;
    if (displacement >= 0) {
        magnitude = (ULONG64)displacement;
        if (base > MAXULONGLONG - magnitude) {
            return FALSE;
        }
        *resultOut = base + magnitude;
        return TRUE;
    }

    // Note: Avoid signed overflow by not directly negating the minimum LONGLONG.
    magnitude = (ULONG64)(-(displacement + 1LL)) + 1ULL;
    if (base < magnitude) {
        return FALSE;
    }
    *resultOut = base - magnitude;
    return TRUE;
}

typedef struct KswPlatformMaskedSignature
{
    UCHAR bytes[12];
    UCHAR mask[12];
    ULONG length;
    ULONG identifier;
} KswPlatformMaskedSignature;

static const KswPlatformMaskedSignature kGKswX64PrologueSignatures[] = {
    { { 0x48, 0x89, 0x5C, 0x24, 0x00, 0x57, 0x48, 0x83, 0xEC, 0x00 },
      { 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00 },
      10UL, 1UL },
    { { 0x40, 0x53, 0x48, 0x83, 0xEC, 0x00 },
      { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00 },
      6UL, 2UL },
    { { 0x48, 0x83, 0xEC, 0x00 },
      { 0xFF, 0xFF, 0xFF, 0x00 },
      4UL, 3UL },
    { { 0x4C, 0x8B, 0xDC, 0x49, 0x89, 0x5B, 0x00 },
      { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00 },
      7UL, 4UL },
    { { 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x00 },
      { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00 },
      7UL, 5UL },
    { { 0x48, 0x89, 0x5C, 0x24, 0x00, 0x48, 0x89, 0x6C, 0x24, 0x00 },
      { 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00 },
      10UL, 6UL },
    { { 0x48, 0x8B, 0xC4, 0x55, 0x53, 0x56, 0x57 },
      { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
      7UL, 7UL },
    { { 0x40, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54 },
      { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
      7UL, 8UL }
};

static BOOLEAN
kswPlatformMaskedBytesMatch(
    _In_reads_(byteCount) const UCHAR* data,
    _In_reads_(byteCount) const UCHAR* bytes,
    _In_reads_(byteCount) const UCHAR* mask,
    _In_ ULONG byteCount
    )
{
    ULONG index = 0UL;

    if (data == NULL || bytes == NULL || mask == NULL || byteCount == 0UL) {
        return FALSE;
    }
    for (index = 0UL; index < byteCount; ++index) {
        if ((data[index] & mask[index]) != (bytes[index] & mask[index])) {
            return FALSE;
        }
    }
    return TRUE;
}

static BOOLEAN
kswPlatformIdentifyX64Prologue(
    _In_ ULONG64 address,
    _Out_ ULONG* signatureIdOut
    )
{
    UCHAR bytes[20];
    ULONG codeOffset = 0UL;
    ULONG index = 0UL;
    ULONG matchedCount = 0UL;
    ULONG matchedId = 0UL;

    if (signatureIdOut == NULL) {
        return FALSE;
    }
    *signatureIdOut = 0UL;
    RtlZeroMemory(bytes, sizeof(bytes));
    if (address == 0ULL ||
        !kswordArkHookReadMemorySafe((const VOID*)(ULONG_PTR)address, bytes, sizeof(bytes))) {
        return FALSE;
    }
    if (bytes[0] == 0xF3U && bytes[1] == 0x0FU &&
        bytes[2] == 0x1EU && bytes[3] == 0xFAU) {
        codeOffset = 4UL;
    }

    // Note: Each pattern consists of real bytes plus a mask, checking only the fixed 20 bytes at the function prologue.
    // Accept only if exactly one pattern matches; treat multiple matches or zero matches as an unknown version and fail safely.
    for (index = 0UL; index < RTL_NUMBER_OF(kGKswX64PrologueSignatures); ++index) {
        const KswPlatformMaskedSignature* signature =
            &kGKswX64PrologueSignatures[index];
        if (codeOffset + signature->length > sizeof(bytes)) {
            continue;
        }
        if (kswPlatformMaskedBytesMatch(
                bytes + codeOffset,
                signature->bytes,
                signature->mask,
                signature->length)) {
            matchedCount += 1UL;
            matchedId = signature->identifier;
        }
    }
    if (matchedCount != 1UL) {
        return FALSE;
    }
    *signatureIdOut = matchedId;
    return TRUE;
}

static VOID
kswPlatformSetDetail(
    _Inout_ KSWORD_ARK_PLATFORM_AUDIT_ENTRY* entry,
    _In_ ULONG detailCode,
    _In_ ULONGLONG arg0,
    _In_ ULONGLONG arg1,
    _In_ ULONGLONG arg2,
    _In_ ULONGLONG arg3
    )
{
    if (entry == NULL) {
        return;
    }
    entry->detailCode = detailCode;
    entry->detailArgs[0] = arg0;
    entry->detailArgs[1] = arg1;
    entry->detailArgs[2] = arg2;
    entry->detailArgs[3] = arg3;
    if (detailCode != KSWORD_ARK_PLATFORM_DETAIL_NONE) {
        entry->fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_DETAIL_ARGS;
    }
}

static VOID
kswPlatformClassifyFunction(
    _Inout_ KSWORD_ARK_PLATFORM_AUDIT_ENTRY* entry,
    _In_ const KswHookSystemModuleInformation* moduleInfo,
    _In_ ULONG ownerPolicy
    )
{
    const KswHookSystemModuleEntry* owner = NULL;
    const KswHookSystemModuleEntry* detourOwner = NULL;
    ULONG64 detourTarget = 0ULL;
    BOOLEAN ownerExpected = FALSE;
    BOOLEAN executable = FALSE;
    ULONG prologueSignatureId = 0UL;

    if (entry == NULL || entry->liveAddress == 0ULL) {
        return;
    }

    owner = kswordArkHookFindModuleForAddress(moduleInfo, (ULONG_PTR)entry->liveAddress);
    kswPlatformFillModule(entry, owner);
    executable = owner != NULL &&
        kswPlatformAddressSectionMatches(owner, (ULONG_PTR)entry->liveAddress, TRUE);
    entry->ownerPolicy = ownerPolicy;
    ownerExpected = kswPlatformOwnerMatchesPolicy(owner, ownerPolicy);

    if (ownerExpected) {
        entry->fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_OWNER_VALIDATED;
    }
    if (!ownerExpected) {
        entry->hookStatus = KSWORD_ARK_PLATFORM_HOOK_SUSPICIOUS;
        entry->confidence = KSWORD_ARK_PLATFORM_CONFIDENCE_HIGH;
        entry->status = KSWORD_ARK_PLATFORM_AUDIT_STATUS_SIGNATURE_MISMATCH;
        entry->lastStatus = STATUS_OBJECT_TYPE_MISMATCH;
        kswPlatformSetDetail(
            entry,
            KSWORD_ARK_PLATFORM_DETAIL_OWNER_MISMATCH,
            entry->liveAddress,
            entry->moduleBase,
            ownerPolicy,
            0ULL);
        return;
    }
    if (!executable) {
        entry->hookStatus = KSWORD_ARK_PLATFORM_HOOK_SUSPICIOUS;
        entry->confidence = KSWORD_ARK_PLATFORM_CONFIDENCE_HIGH;
        entry->status = KSWORD_ARK_PLATFORM_AUDIT_STATUS_SIGNATURE_MISMATCH;
        entry->lastStatus = STATUS_INVALID_ADDRESS;
        kswPlatformSetDetail(
            entry,
            KSWORD_ARK_PLATFORM_DETAIL_NON_EXECUTABLE,
            entry->liveAddress,
            entry->moduleBase,
            ownerPolicy,
            0ULL);
        return;
    }
    entry->fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_EXECUTABLE_VALIDATED;

    if (kswPlatformDecodeDetourTarget(entry->liveAddress, &detourTarget)) {
        detourOwner = kswordArkHookFindModuleForAddress(moduleInfo, (ULONG_PTR)detourTarget);
        if (!kswPlatformOwnerMatchesPolicy(detourOwner, ownerPolicy)) {
            entry->hookStatus = KSWORD_ARK_PLATFORM_HOOK_SUSPICIOUS;
            entry->confidence = KSWORD_ARK_PLATFORM_CONFIDENCE_HIGH;
            entry->status = KSWORD_ARK_PLATFORM_AUDIT_STATUS_SIGNATURE_MISMATCH;
            entry->lastStatus = STATUS_OBJECT_TYPE_MISMATCH;
            kswPlatformSetDetail(
                entry,
                KSWORD_ARK_PLATFORM_DETAIL_DETOUR_EXTERNAL,
                entry->liveAddress,
                detourTarget,
                ownerPolicy,
                0ULL);
        }
        else {
            entry->hookStatus = KSWORD_ARK_PLATFORM_HOOK_UNKNOWN;
            entry->confidence = KSWORD_ARK_PLATFORM_CONFIDENCE_MEDIUM;
            kswPlatformSetDetail(
                entry,
                KSWORD_ARK_PLATFORM_DETAIL_DETOUR_SAME_OWNER,
                entry->liveAddress,
                detourTarget,
                ownerPolicy,
                0ULL);
        }
        return;
    }

    if (kswPlatformIdentifyX64Prologue(entry->liveAddress, &prologueSignatureId)) {
        entry->fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_PROLOGUE_FORMAT;
        entry->prologueSignatureId = prologueSignatureId;
        entry->hookStatus = KSWORD_ARK_PLATFORM_HOOK_UNKNOWN;
        entry->confidence = KSWORD_ARK_PLATFORM_CONFIDENCE_MEDIUM;
        kswPlatformSetDetail(
            entry,
            KSWORD_ARK_PLATFORM_DETAIL_FORMAT_RECOGNIZED,
            prologueSignatureId,
            ownerPolicy,
            0ULL,
            0ULL);
    }
    else {
        entry->hookStatus = KSWORD_ARK_PLATFORM_HOOK_UNKNOWN;
        entry->confidence = KSWORD_ARK_PLATFORM_CONFIDENCE_LOW;
        kswPlatformSetDetail(
            entry,
            KSWORD_ARK_PLATFORM_DETAIL_FORMAT_UNKNOWN,
            ownerPolicy,
            0ULL,
            0ULL,
            0ULL);
    }
}

static ULONG
kswPlatformOutputCapacity(
    _In_ size_t outputBytes
    )
{
    size_t payloadBytes = 0U;
    size_t capacity = 0U;

    if (outputBytes <= KSW_PLATFORM_RESPONSE_HEADER_SIZE) {
        return 0UL;
    }
    payloadBytes = outputBytes - KSW_PLATFORM_RESPONSE_HEADER_SIZE;
    capacity = payloadBytes / sizeof(KSWORD_ARK_PLATFORM_AUDIT_ENTRY);
    if (capacity > MAXULONG) {
        return MAXULONG;
    }
    return (ULONG)capacity;
}

static VOID
kswPlatformAppend(
    _Inout_ KSWORD_ARK_QUERY_PLATFORM_AUDIT_RESPONSE* response,
    _In_ ULONG capacity,
    _In_ ULONG maxRows,
    _In_ const KSWORD_ARK_PLATFORM_AUDIT_ENTRY* entry
    )
{
    if (response == NULL || entry == NULL) {
        return;
    }
    response->totalCount += 1UL;
    if (response->returnedCount >= capacity || response->returnedCount >= maxRows) {
        response->responseFlags |= KSWORD_ARK_PLATFORM_RESPONSE_TRUNCATED |
            KSWORD_ARK_PLATFORM_RESPONSE_PARTIAL;
        response->queryStatus = KSWORD_ARK_PLATFORM_AUDIT_STATUS_PARTIAL;
        response->lastStatus = STATUS_BUFFER_OVERFLOW;
        return;
    }
    response->entries[response->returnedCount] = *entry;
    response->returnedCount += 1UL;
    if (entry->status != KSWORD_ARK_PLATFORM_AUDIT_STATUS_OK) {
        response->responseFlags |= KSWORD_ARK_PLATFORM_RESPONSE_PARTIAL;
        if (response->queryStatus == KSWORD_ARK_PLATFORM_AUDIT_STATUS_OK) {
            response->queryStatus = KSWORD_ARK_PLATFORM_AUDIT_STATUS_PARTIAL;
        }
    }
}

static VOID
kswPlatformAddDiagnostic(
    _Inout_ KSWORD_ARK_QUERY_PLATFORM_AUDIT_RESPONSE* response,
    _In_ ULONG capacity,
    _In_ ULONG maxRows,
    _In_ ULONG scope,
    _In_ ULONG status,
    _In_ NTSTATUS lastStatus,
    _In_z_ PCWSTR name,
    _In_ ULONG detailCode,
    _In_ ULONGLONG detailArg0,
    _In_ ULONGLONG detailArg1
    )
{
    KSWORD_ARK_PLATFORM_AUDIT_ENTRY entry;

    RtlZeroMemory(&entry, sizeof(entry));
    entry.size = sizeof(entry);
    entry.scope = scope;
    entry.rowKind = KSWORD_ARK_PLATFORM_AUDIT_ROW_DIAGNOSTIC;
    entry.status = status;
    entry.hookStatus = KSWORD_ARK_PLATFORM_HOOK_UNSUPPORTED;
    entry.confidence = KSWORD_ARK_PLATFORM_CONFIDENCE_NONE;
    entry.signatureId = KSWORD_ARK_PLATFORM_SIGNATURE_EXACT_EXPORT_ONLY;
    entry.lastStatus = lastStatus;
    kswPlatformCopyWide(entry.name, RTL_NUMBER_OF(entry.name), name);
    kswPlatformSetDetail(&entry, detailCode, detailArg0, detailArg1, 0ULL, 0ULL);
    kswPlatformAppend(response, capacity, maxRows, &entry);
    response->responseFlags |= KSWORD_ARK_PLATFORM_RESPONSE_PARTIAL |
        KSWORD_ARK_PLATFORM_RESPONSE_FAIL_CLOSED;
    if (response->queryStatus == KSWORD_ARK_PLATFORM_AUDIT_STATUS_OK) {
        response->queryStatus = KSWORD_ARK_PLATFORM_AUDIT_STATUS_PARTIAL;
    }
    response->lastStatus = lastStatus;
}





static VOID
kswPlatformInitializeEntry(
    _Out_ KSWORD_ARK_PLATFORM_AUDIT_ENTRY* entry,
    _In_ ULONG scope,
    _In_ ULONG rowKind,
    _In_ ULONG signatureId,
    _In_ ULONG slotKind,
    _In_ ULONG ownerPolicy,
    _In_ ULONG entryIndex,
    _In_opt_ PVOID tableAddress,
    _In_z_ PCWSTR name
    )
{
    RtlZeroMemory(entry, sizeof(*entry));
    entry->size = sizeof(*entry);
    entry->scope = scope;
    entry->rowKind = rowKind;
    entry->status = KSWORD_ARK_PLATFORM_AUDIT_STATUS_OK;
    entry->hookStatus = KSWORD_ARK_PLATFORM_HOOK_UNKNOWN;
    entry->confidence = KSWORD_ARK_PLATFORM_CONFIDENCE_NONE;
    entry->signatureId = signatureId;
    entry->slotKind = slotKind;
    entry->ownerPolicy = ownerPolicy;
    entry->entryIndex = entryIndex;
    entry->lastStatus = STATUS_SUCCESS;
    if (tableAddress != NULL) {
        entry->tableAddress = (ULONGLONG)(ULONG_PTR)tableAddress;
        entry->fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_TABLE_ADDRESS;
    }
    kswPlatformCopyWide(entry->name, RTL_NUMBER_OF(entry->name), name);
}

static BOOLEAN
kswPlatformAddExportedFunction(
    _Inout_ KSWORD_ARK_QUERY_PLATFORM_AUDIT_RESPONSE* response,
    _In_ ULONG capacity,
    _In_ ULONG maxRows,
    _In_ ULONG scope,
    _In_ const KswHookSystemModuleInformation* moduleInfo,
    _In_z_ PCWSTR exportName,
    _In_ ULONG ownerPolicy
    )
{
    PVOID functionAddress = kswPlatformGetRoutine(exportName);
    KSWORD_ARK_PLATFORM_AUDIT_ENTRY entry;

    if (functionAddress == NULL) {
        return FALSE;
    }
    kswPlatformInitializeEntry(
        &entry,
        scope,
        KSWORD_ARK_PLATFORM_AUDIT_ROW_FUNCTION,
        KSWORD_ARK_PLATFORM_SIGNATURE_EXACT_EXPORT_ONLY,
        KSWORD_ARK_PLATFORM_SLOT_FUNCTION,
        ownerPolicy,
        0UL,
        NULL,
        exportName);
    entry.liveAddress = (ULONGLONG)(ULONG_PTR)functionAddress;
    entry.fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_LIVE_ADDRESS |
        KSWORD_ARK_PLATFORM_FIELD_EXACT_EXPORT;
    kswPlatformClassifyFunction(&entry, moduleInfo, ownerPolicy);
    kswPlatformAppend(response, capacity, maxRows, &entry);
    return TRUE;
}

static ULONG
kswPlatformHalDispatchSlotCount(
    _In_ ULONG version
    )
{
    // Note: HAL_DISPATCH evolves by appending fields at the end; v4 includes
    // HalSetPciErrorHandlerCallback, v5 adds HalGetPrmCache, and v6 contains all fields.
    if (version == 4UL) {
        return 22UL;
    }
    if (version == 5UL) {
        return 23UL;
    }
    if (version == 6UL) {
        return (ULONG)RTL_NUMBER_OF(kGKswHalDispatchSlots);
    }
    return 0UL;
}

static VOID
kswPlatformAddHalDispatch(
    _Inout_ KSWORD_ARK_QUERY_PLATFORM_AUDIT_RESPONSE* response,
    _In_ ULONG capacity,
    _In_ ULONG maxRows,
    _In_ const KswHookSystemModuleInformation* moduleInfo
    )
{
    PVOID tableAddress = kswPlatformGetRoutine(L"HalDispatchTable");
    const KswHookSystemModuleEntry* tableOwner = NULL;
    ULONG version = 0UL;
    ULONG index = 0UL;
    ULONG slotCount = 0UL;
    ULONG tableBytes = 0UL;
    ULONG signatureId = KSWORD_ARK_PLATFORM_SIGNATURE_NONE;
    KSWORD_ARK_PLATFORM_AUDIT_ENTRY versionEntry;

    if (tableAddress == NULL) {
        kswPlatformAddDiagnostic(
            response, capacity, maxRows,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_DISPATCH,
            KSWORD_ARK_PLATFORM_AUDIT_STATUS_UNSUPPORTED,
            STATUS_PROCEDURE_NOT_FOUND,
            L"HalDispatchTable",
            KSWORD_ARK_PLATFORM_DETAIL_LOCATOR_NOT_FOUND,
            0ULL,
            0ULL);
        return;
    }

    tableOwner = kswordArkHookFindModuleForAddress(moduleInfo, (ULONG_PTR)tableAddress);
    if (!kswPlatformIsExpectedHalOwner(tableOwner) ||
        !kswPlatformRangeInSection(
            tableOwner,
            (ULONG_PTR)tableAddress,
            sizeof(version),
            FALSE,
            FALSE) ||
        !kswordArkHookReadMemorySafe(tableAddress, &version, sizeof(version))) {
        kswPlatformAddDiagnostic(
            response, capacity, maxRows,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_DISPATCH,
            KSWORD_ARK_PLATFORM_AUDIT_STATUS_SIGNATURE_MISMATCH,
            STATUS_DATA_ERROR,
            L"HalDispatchTable",
            KSWORD_ARK_PLATFORM_DETAIL_RANGE_INVALID,
            sizeof(version),
            0ULL);
        return;
    }
    slotCount = kswPlatformHalDispatchSlotCount(version);
    if (slotCount == 0UL) {
        kswPlatformAddDiagnostic(
            response, capacity, maxRows,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_DISPATCH,
            KSWORD_ARK_PLATFORM_AUDIT_STATUS_UNSUPPORTED,
            STATUS_REVISION_MISMATCH,
            L"HalDispatchTable",
            KSWORD_ARK_PLATFORM_DETAIL_VERSION_MISMATCH,
            4ULL,
            version);
        return;
    }
    tableBytes = kGKswHalDispatchSlots[slotCount - 1UL].offset +
        kGKswHalDispatchSlots[slotCount - 1UL].width;
    if (!kswPlatformIsExpectedHalOwner(tableOwner) ||
        !kswPlatformRangeInSection(
            tableOwner,
            (ULONG_PTR)tableAddress,
            tableBytes,
            FALSE,
            FALSE)) {
        kswPlatformAddDiagnostic(
            response, capacity, maxRows,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_DISPATCH,
            KSWORD_ARK_PLATFORM_AUDIT_STATUS_SIGNATURE_MISMATCH,
            STATUS_DATA_ERROR,
            L"HalDispatchTable",
            KSWORD_ARK_PLATFORM_DETAIL_RANGE_INVALID,
            tableBytes,
            0ULL);
        return;
    }
    signatureId = version == HAL_DISPATCH_VERSION ?
        KSWORD_ARK_PLATFORM_SIGNATURE_PUBLIC_HAL_V6 :
        KSWORD_ARK_PLATFORM_SIGNATURE_PUBLIC_HAL_V4_V5;
    kswPlatformInitializeEntry(
        &versionEntry,
        KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_DISPATCH,
        KSWORD_ARK_PLATFORM_AUDIT_ROW_TABLE,
        signatureId,
        KSWORD_ARK_PLATFORM_SLOT_SCALAR,
        KSWORD_ARK_PLATFORM_OWNER_NONE,
        0UL,
        tableAddress,
        L"Version");
    versionEntry.fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_EXACT_EXPORT |
        KSWORD_ARK_PLATFORM_FIELD_STRUCTURE_VALIDATED;
    kswPlatformSetDetail(
        &versionEntry,
        KSWORD_ARK_PLATFORM_DETAIL_SCALAR_VALUE,
        version,
        tableBytes,
        slotCount,
        0ULL);
    kswPlatformAppend(response, capacity, maxRows, &versionEntry);

    for (index = 0UL; index < slotCount; ++index) {
        const KswPlatformSlotDescriptor* descriptor = &kGKswHalDispatchSlots[index];
        KSWORD_ARK_PLATFORM_AUDIT_ENTRY entry;
        ULONGLONG value = 0ULL;

        kswPlatformInitializeEntry(
            &entry,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_DISPATCH,
            descriptor->slotKind == KSWORD_ARK_PLATFORM_SLOT_FUNCTION ?
                KSWORD_ARK_PLATFORM_AUDIT_ROW_FUNCTION :
                KSWORD_ARK_PLATFORM_AUDIT_ROW_TABLE,
            signatureId,
            descriptor->slotKind,
            descriptor->ownerPolicy,
            index,
            tableAddress,
            descriptor->name);
        entry.fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_STRUCTURE_VALIDATED |
            KSWORD_ARK_PLATFORM_FIELD_EXACT_EXPORT;

        if (descriptor->width > sizeof(value) ||
            !kswordArkHookReadMemorySafe(
                (const UCHAR*)tableAddress + descriptor->offset,
                &value,
                descriptor->width)) {
            entry.status = KSWORD_ARK_PLATFORM_AUDIT_STATUS_QUERY_FAILED;
            entry.lastStatus = STATUS_PARTIAL_COPY;
            kswPlatformSetDetail(
                &entry,
                KSWORD_ARK_PLATFORM_DETAIL_READ_FAILED,
                descriptor->offset,
                descriptor->width,
                0ULL,
                0ULL);
        }
        else if (descriptor->slotKind == KSWORD_ARK_PLATFORM_SLOT_SCALAR) {
            kswPlatformSetDetail(
                &entry,
                KSWORD_ARK_PLATFORM_DETAIL_SCALAR_VALUE,
                value,
                descriptor->offset,
                descriptor->width,
                0ULL);
        }
        else if (value == 0ULL) {
            entry.status = KSWORD_ARK_PLATFORM_AUDIT_STATUS_UNAVAILABLE;
            kswPlatformSetDetail(
                &entry,
                KSWORD_ARK_PLATFORM_DETAIL_NULL_SLOT,
                descriptor->offset,
                0ULL,
                0ULL,
                0ULL);
        }
        else {
            entry.liveAddress = value;
            entry.fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_LIVE_ADDRESS;
            kswPlatformClassifyFunction(&entry, moduleInfo, descriptor->ownerPolicy);
        }
        kswPlatformAppend(response, capacity, maxRows, &entry);
    }
}

static ULONG
kswPlatformCanonicalBuildNumber(
    _In_ ULONG buildNumber
    )
{
    // Note: Windows 10 versions 2004 through 22H2 report different product builds but share the
    // 19041 kernel baseline; similarly, 22621 and 22631 share the same 22H2/23H2 structural family.
    if (buildNumber >= 19041UL && buildNumber <= 19045UL) {
        return 19041UL;
    }
    if (buildNumber >= 22621UL && buildNumber <= 22631UL) {
        return 22621UL;
    }
    return buildNumber;
}

static const KswPlatformPrivateBuildDescriptor*
kswPlatformFindPrivateBuild(
    _In_ ULONG buildNumber
    )
{
    ULONG canonicalBuild = kswPlatformCanonicalBuildNumber(buildNumber);
    ULONG index = 0UL;

    for (index = 0UL; index < RTL_NUMBER_OF(kGKswHalPrivateBuilds); ++index) {
        if (kGKswHalPrivateBuilds[index].buildNumber == canonicalBuild) {
            return &kGKswHalPrivateBuilds[index];
        }
    }
    return NULL;
}

static const KswPlatformPrivateBuildDescriptor*
kswPlatformFindPrivateVersion(
    _In_ ULONG version
    )
{
    ULONG index = 0UL;

    for (index = 0UL; index < RTL_NUMBER_OF(kGKswHalPrivateBuilds); ++index) {
        if (kGKswHalPrivateBuilds[index].version == version) {
            return &kGKswHalPrivateBuilds[index];
        }
    }
    return NULL;
}

static NTSTATUS
kswPlatformLocateHalPrivateBySignature(
    _In_ const KswHookSystemModuleInformation* moduleInfo,
    _In_ ULONG buildNumber,
    _In_ const KswPlatformPrivateBuildDescriptor* build,
    _Outptr_ PVOID* tableAddressOut,
    _Out_ ULONG* versionOut
    );

static VOID
kswPlatformAddHalPrivate(
    _Inout_ KSWORD_ARK_QUERY_PLATFORM_AUDIT_RESPONSE* response,
    _In_ ULONG capacity,
    _In_ ULONG maxRows,
    _In_ const KswHookSystemModuleInformation* moduleInfo,
    _In_ ULONG buildNumber
    )
{
    const KswPlatformPrivateBuildDescriptor* build =
        kswPlatformFindPrivateBuild(buildNumber);
    PVOID tableAddress = NULL;
    ULONG version = 0UL;
    ULONG index = 0UL;
    NTSTATUS locateStatus = STATUS_NOT_SUPPORTED;
    BOOLEAN exactExport = FALSE;
    KSWORD_ARK_PLATFORM_AUDIT_ENTRY versionEntry;
    const KswHookSystemModuleEntry* tableOwner = NULL;

    // Note: Data exports provide the precise table address. First verify the owner, bounded range, and version to avoid
    // relying on instruction windows from a single system build. Only expand slots if the Version and ByteSize are known.
    tableAddress = kswPlatformGetRoutine(L"HalPrivateDispatchTable");
    tableOwner = kswordArkHookFindModuleForAddress(
        moduleInfo,
        (ULONG_PTR)tableAddress);
    if (tableAddress != NULL &&
        kswPlatformIsExpectedHalOwner(tableOwner) &&
        kswPlatformRangeInSection(
            tableOwner,
            (ULONG_PTR)tableAddress,
            sizeof(version),
            FALSE,
            FALSE) &&
        kswordArkHookReadMemorySafe(
            tableAddress,
            &version,
            sizeof(version))) {
        const KswPlatformPrivateBuildDescriptor* versionBuild =
            kswPlatformFindPrivateVersion(version);
        if (versionBuild != NULL &&
            kswPlatformRangeInSection(
                tableOwner,
                (ULONG_PTR)tableAddress,
                versionBuild->byteSize,
                FALSE,
                FALSE)) {
            build = versionBuild;
            locateStatus = STATUS_SUCCESS;
            exactExport = TRUE;
        }
        else {
            kswPlatformInitializeEntry(
                &versionEntry,
                KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_PRIVATE,
                KSWORD_ARK_PLATFORM_AUDIT_ROW_TABLE,
                KSWORD_ARK_PLATFORM_SIGNATURE_EXACT_EXPORT_ONLY,
                KSWORD_ARK_PLATFORM_SLOT_SCALAR,
                KSWORD_ARK_PLATFORM_OWNER_NONE,
                0UL,
                tableAddress,
                L"Version");
            versionEntry.fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_EXACT_EXPORT;
            kswPlatformSetDetail(
                &versionEntry,
                KSWORD_ARK_PLATFORM_DETAIL_SCALAR_VALUE,
                version,
                buildNumber,
                0ULL,
                0ULL);
            kswPlatformAppend(response, capacity, maxRows, &versionEntry);
            (VOID)kswPlatformAddExportedFunction(
                response,
                capacity,
                maxRows,
                KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_PRIVATE,
                moduleInfo,
                L"HalTranslateBusAddress",
                KSWORD_ARK_PLATFORM_OWNER_NT_HAL_PCI);
            (VOID)kswPlatformAddExportedFunction(
                response,
                capacity,
                maxRows,
                KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_PRIVATE,
                moduleInfo,
                L"HalAssignSlotResources",
                KSWORD_ARK_PLATFORM_OWNER_NT_HAL_PCI);
            return;
        }
    }

    // Note: On older systems that do not expose data exports, RIP-relative positioning within bounds is retained.
    // The candidate must be unique, and both the full Version and ByteSize must be validated simultaneously.
    if (!NT_SUCCESS(locateStatus) && build != NULL) {
        locateStatus = kswPlatformLocateHalPrivateBySignature(
            moduleInfo,
            buildNumber,
            build,
            &tableAddress,
            &version);
    }
    if (!NT_SUCCESS(locateStatus)) {
        if (kswPlatformAddExportedFunction(
                response,
                capacity,
                maxRows,
                KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_PRIVATE,
                moduleInfo,
                L"HalTranslateBusAddress",
                KSWORD_ARK_PLATFORM_OWNER_NT_HAL_PCI)) {
            return;
        }
        kswPlatformAddDiagnostic(
            response, capacity, maxRows,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_PRIVATE,
            locateStatus == STATUS_NOT_SUPPORTED ?
                KSWORD_ARK_PLATFORM_AUDIT_STATUS_UNSUPPORTED :
                KSWORD_ARK_PLATFORM_AUDIT_STATUS_SIGNATURE_MISMATCH,
            locateStatus,
            L"HalPrivateDispatchTable",
            locateStatus == STATUS_OBJECT_NAME_COLLISION ?
                KSWORD_ARK_PLATFORM_DETAIL_LOCATOR_NOT_UNIQUE :
                (locateStatus == STATUS_REVISION_MISMATCH ?
                    KSWORD_ARK_PLATFORM_DETAIL_VERSION_MISMATCH :
                    (locateStatus == STATUS_NOT_SUPPORTED ?
                        KSWORD_ARK_PLATFORM_DETAIL_BUILD_UNSUPPORTED :
                        KSWORD_ARK_PLATFORM_DETAIL_LOCATOR_NOT_FOUND)),
            locateStatus == STATUS_REVISION_MISMATCH && build != NULL ?
                build->version :
                buildNumber,
            locateStatus == STATUS_REVISION_MISMATCH && build != NULL ?
                version :
                (build != NULL ? build->byteSize : 0UL));
        return;
    }

    kswPlatformInitializeEntry(
        &versionEntry,
        KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_PRIVATE,
        KSWORD_ARK_PLATFORM_AUDIT_ROW_TABLE,
        build->signatureId,
        KSWORD_ARK_PLATFORM_SLOT_SCALAR,
        KSWORD_ARK_PLATFORM_OWNER_NONE,
        0UL,
        tableAddress,
        L"Version");
    versionEntry.fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_STRUCTURE_VALIDATED |
        (exactExport ?
            KSWORD_ARK_PLATFORM_FIELD_EXACT_EXPORT :
            KSWORD_ARK_PLATFORM_FIELD_LOCATOR_VALIDATED);
    kswPlatformSetDetail(
        &versionEntry,
        KSWORD_ARK_PLATFORM_DETAIL_SCALAR_VALUE,
        version,
        build->byteSize,
        buildNumber,
        0ULL);
    kswPlatformAppend(response, capacity, maxRows, &versionEntry);

    for (index = 0UL; index < RTL_NUMBER_OF(kGKswHalPrivateSlots); ++index) {
        const KswPlatformSlotDescriptor* descriptor = &kGKswHalPrivateSlots[index];
        KSWORD_ARK_PLATFORM_AUDIT_ENTRY entry;
        PVOID functionAddress = NULL;

        if (descriptor->offset + descriptor->width > build->byteSize) {
            break;
        }
        kswPlatformInitializeEntry(
            &entry,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_PRIVATE,
            descriptor->slotKind == KSWORD_ARK_PLATFORM_SLOT_FUNCTION ?
                KSWORD_ARK_PLATFORM_AUDIT_ROW_FUNCTION :
                KSWORD_ARK_PLATFORM_AUDIT_ROW_TABLE,
            build->signatureId,
            descriptor->slotKind,
            descriptor->ownerPolicy,
            index + 1UL,
            tableAddress,
            descriptor->name);
        entry.fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_STRUCTURE_VALIDATED |
            (exactExport ?
                KSWORD_ARK_PLATFORM_FIELD_EXACT_EXPORT :
                KSWORD_ARK_PLATFORM_FIELD_LOCATOR_VALIDATED);

        if (!kswordArkHookReadMemorySafe(
                (const UCHAR*)tableAddress + descriptor->offset,
                &functionAddress,
                descriptor->width)) {
            entry.status = KSWORD_ARK_PLATFORM_AUDIT_STATUS_QUERY_FAILED;
            entry.lastStatus = STATUS_PARTIAL_COPY;
            kswPlatformSetDetail(
                &entry,
                KSWORD_ARK_PLATFORM_DETAIL_READ_FAILED,
                descriptor->offset,
                descriptor->width,
                buildNumber,
                version);
        }
        else if (descriptor->slotKind == KSWORD_ARK_PLATFORM_SLOT_DUMMY) {
            kswPlatformSetDetail(
                &entry,
                KSWORD_ARK_PLATFORM_DETAIL_DUMMY_SLOT,
                (ULONGLONG)(ULONG_PTR)functionAddress,
                descriptor->offset,
                buildNumber,
                version);
        }
        else if (functionAddress == NULL) {
            entry.status = KSWORD_ARK_PLATFORM_AUDIT_STATUS_UNAVAILABLE;
            kswPlatformSetDetail(
                &entry,
                KSWORD_ARK_PLATFORM_DETAIL_NULL_SLOT,
                descriptor->offset,
                buildNumber,
                version,
                0ULL);
        }
        else {
            entry.liveAddress = (ULONGLONG)(ULONG_PTR)functionAddress;
            entry.fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_LIVE_ADDRESS;
            kswPlatformClassifyFunction(&entry, moduleInfo, descriptor->ownerPolicy);
        }
        kswPlatformAppend(response, capacity, maxRows, &entry);
    }
}

typedef struct KswPlatformRipLocatorDescriptor
{
    ULONG buildNumber;
    PCWSTR anchorName;
    ULONG scanOffset;
    ULONG scanBytes;
    LONG candidateAdjustment;
    ULONG tableByteSize;
    ULONG expectedVersion;
    UCHAR bytes[7];
    UCHAR mask[7];
} KswPlatformRipLocatorDescriptor;

typedef BOOLEAN
(*KswPlatformValidateTableRoutine)(
    _In_ const KswHookSystemModuleInformation* moduleInfo,
    _In_ PVOID candidate,
    _In_ const KswPlatformRipLocatorDescriptor* locator
    );

// HalTranslateBusAddress is dispatched via HalPrivateDispatchTable+0x38.
// The table base address must be deduced via a unique RIP-relative read within the trusted exported bounded code
// window; falling back to the HalPrivateDispatchTable export or scanning the entire kernel image is not allowed.
static const KswPlatformRipLocatorDescriptor kGKswHalPrivateLocators[] = {
    {
        19041UL, L"HalTranslateBusAddress", 0x00UL, 0x80UL, -0x38L,
        0x4B0UL, 51UL,
        { 0x48U, 0x8BU, 0x05U, 0U, 0U, 0U, 0U },
        { 0xFFU, 0xFFU, 0xFFU, 0U, 0U, 0U, 0U }
    },
    {
        22000UL, L"HalTranslateBusAddress", 0x00UL, 0x80UL, -0x38L,
        0x4D8UL, 54UL,
        { 0x48U, 0x8BU, 0x05U, 0U, 0U, 0U, 0U },
        { 0xFFU, 0xFFU, 0xFFU, 0U, 0U, 0U, 0U }
    },
    {
        22621UL, L"HalTranslateBusAddress", 0x00UL, 0x80UL, -0x38L,
        0x4F0UL, 58UL,
        { 0x48U, 0x8BU, 0x05U, 0U, 0U, 0U, 0U },
        { 0xFFU, 0xFFU, 0xFFU, 0U, 0U, 0U, 0U }
    },
    {
        26100UL, L"HalTranslateBusAddress", 0x00UL, 0x80UL, -0x38L,
        0x518UL, 61UL,
        { 0x48U, 0x8BU, 0x05U, 0U, 0U, 0U, 0U },
        { 0xFFU, 0xFFU, 0xFFU, 0U, 0U, 0U, 0U }
    },
    {
        26220UL, L"HalTranslateBusAddress", 0x00UL, 0x80UL, -0x38L,
        0x518UL, 61UL,
        { 0x48U, 0x8BU, 0x05U, 0U, 0U, 0U, 0U },
        { 0xFFU, 0xFFU, 0xFFU, 0U, 0U, 0U, 0U }
    }
};

static const KswPlatformRipLocatorDescriptor kGKswHalAcpiLocators[] = {
    {
        19041UL, NULL, 0x00UL, 0xC0UL, 0L,
        FIELD_OFFSET(KswPlatformHalAcpiView, functions), 0UL,
        { 0x48U, 0x8DU, 0x05U, 0U, 0U, 0U, 0U },
        { 0xF8U, 0xFFU, 0xC7U, 0U, 0U, 0U, 0U }
    },
    {
        22000UL, NULL, 0x00UL, 0xC0UL, 0L,
        FIELD_OFFSET(KswPlatformHalAcpiView, functions), 0UL,
        { 0x48U, 0x8DU, 0x05U, 0U, 0U, 0U, 0U },
        { 0xF8U, 0xFFU, 0xC7U, 0U, 0U, 0U, 0U }
    },
    {
        22621UL, NULL, 0x00UL, 0xC0UL, 0L,
        FIELD_OFFSET(KswPlatformHalAcpiView, functions), 0UL,
        { 0x48U, 0x8DU, 0x05U, 0U, 0U, 0U, 0U },
        { 0xF8U, 0xFFU, 0xC7U, 0U, 0U, 0U, 0U }
    },
    {
        26100UL, NULL, 0x00UL, 0x80UL, 0L,
        FIELD_OFFSET(KswPlatformHalAcpiView, functions), 0UL,
        { 0x48U, 0x8DU, 0x05U, 0U, 0U, 0U, 0U },
        { 0xF8U, 0xFFU, 0xC7U, 0U, 0U, 0U, 0U }
    },
    {
        26220UL, NULL, 0x00UL, 0x80UL, 0L,
        FIELD_OFFSET(KswPlatformHalAcpiView, functions), 0UL,
        { 0x48U, 0x8DU, 0x05U, 0U, 0U, 0U, 0U },
        { 0xF8U, 0xFFU, 0xC7U, 0U, 0U, 0U, 0U }
    }
};

static const KswPlatformRipLocatorDescriptor kGKswHalSubcomponentLocators[] = {
    {
        // Note: Vibranium's export entry first redirects to the adjacent phase/helper. The
        // helper retrieves the 21-element table at +0xAB via `lea r12, [HalSubComponents]`.
        // Scan only this short window and continue confirming candidate identities using all read-only names.
        19041UL, L"HalInitSystem", 0xA0UL, 0x20UL, 0L,
        sizeof(KswPlatformHalSubcomponent) *
            KSW_PLATFORM_HAL_SUBCOMPONENT_LEGACY_COUNT,
        KSW_PLATFORM_HAL_SUBCOMPONENT_LEGACY_COUNT,
        { 0x4CU, 0x8DU, 0x25U, 0U, 0U, 0U, 0U },
        { 0xFFU, 0xFFU, 0xFFU, 0U, 0U, 0U, 0U }
    },
    {
        26100UL, L"HalInitSystem", 0x00UL, 0x90UL, 0L,
        sizeof(KswPlatformHalSubcomponent) *
            KSW_PLATFORM_HAL_SUBCOMPONENT_MAX_COUNT,
        KSW_PLATFORM_HAL_SUBCOMPONENT_MAX_COUNT,
        { 0x48U, 0x8DU, 0x05U, 0U, 0U, 0U, 0U },
        { 0xF8U, 0xFFU, 0xC7U, 0U, 0U, 0U, 0U }
    },
    {
        26220UL, L"HalInitSystem", 0x70UL, 0x20UL, 0L,
        sizeof(KswPlatformHalSubcomponent) *
            KSW_PLATFORM_HAL_SUBCOMPONENT_MAX_COUNT,
        KSW_PLATFORM_HAL_SUBCOMPONENT_MAX_COUNT,
        { 0x4CU, 0x8DU, 0x25U, 0U, 0U, 0U, 0U },
        { 0xFFU, 0xFFU, 0xFFU, 0U, 0U, 0U, 0U }
    }
};

static const KswPlatformRipLocatorDescriptor*
kswPlatformFindRipLocator(
    _In_reads_(descriptorCount) const KswPlatformRipLocatorDescriptor* descriptors,
    _In_ ULONG descriptorCount,
    _In_ ULONG buildNumber
    )
{
    ULONG canonicalBuild = kswPlatformCanonicalBuildNumber(buildNumber);
    ULONG index = 0UL;

    for (index = 0UL; index < descriptorCount; ++index) {
        if (descriptors[index].buildNumber == canonicalBuild) {
            return &descriptors[index];
        }
    }
    return NULL;
}

static NTSTATUS
kswPlatformLocateRipTable(
    _In_ const KswHookSystemModuleInformation* moduleInfo,
    _In_opt_ PVOID anchor,
    _In_ const KswPlatformRipLocatorDescriptor* locator,
    _In_ KswPlatformValidateTableRoutine validateCandidate,
    _Outptr_ PVOID* tableAddressOut
    )
{
    const KswHookSystemModuleEntry* anchorOwner = NULL;
    ULONG offset = 0UL;
    ULONG uniqueCount = 0UL;
    PVOID uniqueCandidate = NULL;

    if (moduleInfo == NULL || anchor == NULL || locator == NULL ||
        validateCandidate == NULL || tableAddressOut == NULL ||
        locator->scanBytes < RTL_NUMBER_OF(locator->bytes) ||
        locator->scanOffset > MAXULONG - locator->scanBytes ||
        locator->tableByteSize == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    *tableAddressOut = NULL;
    anchorOwner = kswordArkHookFindModuleForAddress(moduleInfo, (ULONG_PTR)anchor);
    if (!kswPlatformIsExpectedHalOwner(anchorOwner) ||
        !kswPlatformRangeInSection(
            anchorOwner,
            (ULONG_PTR)anchor,
            locator->scanOffset + locator->scanBytes,
            TRUE,
            FALSE)) {
        return STATUS_INVALID_ADDRESS;
    }

    // Note: Only check the small window specified by the build descriptor, requiring a complete structure
    // verification that yields exactly one candidate; other regions of the kernel image are not scanned.
    for (offset = 0UL;
         offset + RTL_NUMBER_OF(locator->bytes) <= locator->scanBytes;
         ++offset) {
        UCHAR instruction[7];
        LONG displacement = 0;
        ULONG_PTR candidateAddress = 0U;
        ULONG64 candidateAddress64 = 0ULL;
        ULONG64 instructionEnd = 0ULL;
        PVOID candidate = NULL;

        RtlZeroMemory(instruction, sizeof(instruction));
        if (!kswordArkHookReadMemorySafe(
                (const UCHAR*)anchor + locator->scanOffset + offset,
                instruction,
                sizeof(instruction)) ||
            !kswPlatformMaskedBytesMatch(
                instruction,
                locator->bytes,
                locator->mask,
                RTL_NUMBER_OF(locator->bytes))) {
            continue;
        }
        RtlCopyMemory(&displacement, instruction + 3UL, sizeof(displacement));
        if ((ULONG64)(ULONG_PTR)anchor >
            MAXULONGLONG -
                (ULONG64)locator->scanOffset -
                (ULONG64)offset -
                (ULONG64)RTL_NUMBER_OF(locator->bytes)) {
            continue;
        }
        instructionEnd =
            (ULONG64)(ULONG_PTR)anchor +
            (ULONG64)locator->scanOffset +
            (ULONG64)offset +
            (ULONG64)RTL_NUMBER_OF(locator->bytes);
        if (!kswPlatformAddSignedDisplacement(
                instructionEnd,
                (LONGLONG)displacement,
                &candidateAddress64) ||
            !kswPlatformAddSignedDisplacement(
                candidateAddress64,
                (LONGLONG)locator->candidateAdjustment,
                &candidateAddress64) ||
            candidateAddress64 > MAXULONG_PTR) {
            continue;
        }
        candidateAddress = (ULONG_PTR)candidateAddress64;
        candidate = (PVOID)candidateAddress;
        if (!validateCandidate(moduleInfo, candidate, locator)) {
            continue;
        }
        if (candidate == uniqueCandidate) {
            continue;
        }
        uniqueCandidate = candidate;
        uniqueCount += 1UL;
    }

    if (uniqueCount == 0UL) {
        return STATUS_NOT_FOUND;
    }
    if (uniqueCount != 1UL) {
        return STATUS_OBJECT_NAME_COLLISION;
    }
    *tableAddressOut = uniqueCandidate;
    return STATUS_SUCCESS;
}

static BOOLEAN
kswPlatformValidateHalPrivateCandidate(
    _In_ const KswHookSystemModuleInformation* moduleInfo,
    _In_ PVOID candidate,
    _In_ const KswPlatformRipLocatorDescriptor* locator
    )
{
    const KswHookSystemModuleEntry* tableOwner = NULL;
    ULONG version = 0UL;

    if (moduleInfo == NULL || candidate == NULL || locator == NULL ||
        locator->tableByteSize < sizeof(version)) {
        return FALSE;
    }
    tableOwner = kswordArkHookFindModuleForAddress(
        moduleInfo,
        (ULONG_PTR)candidate);
    return kswPlatformIsExpectedHalOwner(tableOwner) &&
        kswPlatformRangeInSection(
            tableOwner,
            (ULONG_PTR)candidate,
            locator->tableByteSize,
            FALSE,
            FALSE) &&
        kswordArkHookReadMemorySafe(candidate, &version, sizeof(version)) &&
        version == locator->expectedVersion;
}

static NTSTATUS
kswPlatformLocateHalPrivateBySignature(
    _In_ const KswHookSystemModuleInformation* moduleInfo,
    _In_ ULONG buildNumber,
    _In_ const KswPlatformPrivateBuildDescriptor* build,
    _Outptr_ PVOID* tableAddressOut,
    _Out_ ULONG* versionOut
    )
{
    const KswPlatformRipLocatorDescriptor* locator = NULL;
    PVOID anchor = NULL;
    NTSTATUS status = STATUS_NOT_SUPPORTED;

    if (moduleInfo == NULL || build == NULL ||
        tableAddressOut == NULL || versionOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *tableAddressOut = NULL;
    *versionOut = 0UL;
    locator = kswPlatformFindRipLocator(
        kGKswHalPrivateLocators,
        RTL_NUMBER_OF(kGKswHalPrivateLocators),
        buildNumber);
    if (locator == NULL ||
        locator->anchorName == NULL ||
        locator->tableByteSize != build->byteSize ||
        locator->expectedVersion != build->version) {
        return STATUS_NOT_SUPPORTED;
    }
    anchor = kswPlatformGetRoutine(locator->anchorName);
    if (anchor == NULL) {
        return STATUS_NOT_SUPPORTED;
    }
    status = kswPlatformLocateRipTable(
        moduleInfo,
        anchor,
        locator,
        kswPlatformValidateHalPrivateCandidate,
        tableAddressOut);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (!kswordArkHookReadMemorySafe(
            *tableAddressOut,
            versionOut,
            sizeof(*versionOut))) {
        *tableAddressOut = NULL;
        return STATUS_PARTIAL_COPY;
    }
    if (*versionOut != build->version) {
        *tableAddressOut = NULL;
        return STATUS_REVISION_MISMATCH;
    }
    return STATUS_SUCCESS;
}

static BOOLEAN
kswPlatformGetHalAcpiLayout(
    _In_ ULONG version,
    _Out_ ULONG* functionCountOut,
    _Out_ ULONG* byteSizeOut
    )
{
    ULONG functionCount = 0UL;

    if (functionCountOut == NULL || byteSizeOut == NULL) {
        return FALSE;
    }
    *functionCountOut = 0UL;
    *byteSizeOut = 0UL;
    if (version == KSW_PLATFORM_HAL_ACPI_VERSION_V4) {
        functionCount = KSW_PLATFORM_HAL_ACPI_V4_FUNCTION_COUNT;
    }
    else if (version == KSW_PLATFORM_HAL_ACPI_VERSION_V5) {
        functionCount = KSW_PLATFORM_HAL_ACPI_V5_FUNCTION_COUNT;
    }
    else {
        return FALSE;
    }
    *functionCountOut = functionCount;
    *byteSizeOut =
        FIELD_OFFSET(KswPlatformHalAcpiView, functions) +
        (ULONG)(sizeof(PVOID) * functionCount);
    return TRUE;
}

static BOOLEAN
kswPlatformHalAcpiIdentityMatches(
    _In_ const KswPlatformHalAcpiView* view,
    _Out_opt_ ULONG* functionCountOut,
    _Out_opt_ ULONG* byteSizeOut
    )
{
    ULONG functionCount = 0UL;
    ULONG byteSize = 0UL;

    if (view == NULL ||
        view->signature != KSW_PLATFORM_HAL_ACPI_SIGNATURE ||
        !kswPlatformGetHalAcpiLayout(
            view->version,
            &functionCount,
            &byteSize)) {
        return FALSE;
    }
    if (functionCountOut != NULL) {
        *functionCountOut = functionCount;
    }
    if (byteSizeOut != NULL) {
        *byteSizeOut = byteSize;
    }
    return TRUE;
}

static BOOLEAN
kswPlatformValidateHalAcpiCandidate(
    _In_ const KswHookSystemModuleInformation* moduleInfo,
    _In_ PVOID candidate,
    _In_ const KswPlatformRipLocatorDescriptor* locator
    )
{
    const KswHookSystemModuleEntry* tableOwner = NULL;
    KswPlatformHalAcpiView view;
    ULONG functionCount = 0UL;
    ULONG byteSize = 0UL;
    const ULONG kHeaderSize =
        FIELD_OFFSET(KswPlatformHalAcpiView, functions);

    if (moduleInfo == NULL || candidate == NULL || locator == NULL ||
        locator->tableByteSize != kHeaderSize ||
        locator->expectedVersion != 0UL) {
        return FALSE;
    }
    tableOwner = kswordArkHookFindModuleForAddress(moduleInfo, (ULONG_PTR)candidate);
    RtlZeroMemory(&view, sizeof(view));
    if (!kswPlatformIsExpectedHalOwner(tableOwner) ||
        !kswPlatformRangeInSection(
            tableOwner,
            (ULONG_PTR)candidate,
            kHeaderSize,
            FALSE,
            TRUE) ||
        !kswordArkHookReadMemorySafe(candidate, &view, kHeaderSize) ||
        !kswPlatformHalAcpiIdentityMatches(
            &view,
            &functionCount,
            &byteSize) ||
        functionCount > RTL_NUMBER_OF(view.functions) ||
        !kswPlatformRangeInSection(
            tableOwner,
            (ULONG_PTR)candidate,
            byteSize,
            FALSE,
            TRUE) ||
        !kswordArkHookReadMemorySafe(candidate, &view, byteSize) ||
        !kswPlatformHalAcpiIdentityMatches(&view, NULL, NULL)) {
        return FALSE;
    }
    // Function slot content is not a table identity condition: external owner, non-executable address, or NULL are precisely the anomalies
    // that must be retained and reported line-by-line; they must not cause the entire candidate to be swallowed as 'locator-not-found'.
    return TRUE;
}

static BOOLEAN
kswPlatformValidateBoundedWideName(
    _In_ const KswHookSystemModuleInformation* moduleInfo,
    _In_ PCWSTR nameAddress,
    _In_z_ PCWSTR expectedName
    )
{
    const KswHookSystemModuleEntry* owner = NULL;
    SIZE_T expectedChars = 0U;
    WCHAR buffer[32];

    if (moduleInfo == NULL || nameAddress == NULL || expectedName == NULL) {
        return FALSE;
    }
    while (expectedName[expectedChars] != L'\0' &&
           expectedChars < RTL_NUMBER_OF(buffer) - 1U) {
        expectedChars += 1U;
    }
    if (expectedName[expectedChars] != L'\0') {
        return FALSE;
    }
    owner = kswordArkHookFindModuleForAddress(moduleInfo, (ULONG_PTR)nameAddress);
    RtlZeroMemory(buffer, sizeof(buffer));
    if (!kswPlatformIsExpectedHalOwner(owner) ||
        !kswPlatformRangeInSection(
            owner,
            (ULONG_PTR)nameAddress,
            (expectedChars + 1U) * sizeof(WCHAR),
            FALSE,
            TRUE) ||
        !kswordArkHookReadMemorySafe(
            nameAddress,
            buffer,
            (expectedChars + 1U) * sizeof(WCHAR))) {
        return FALSE;
    }
    return RtlCompareMemory(
        buffer,
        expectedName,
        (expectedChars + 1U) * sizeof(WCHAR)) ==
        (expectedChars + 1U) * sizeof(WCHAR);
}

static BOOLEAN
kswPlatformHalSubcomponentIndex(
    _In_ ULONG entryIndex,
    _In_ ULONG entryCount,
    _Out_ ULONG* nameIndexOut
    )
{
    ULONG nameIndex = entryIndex;

    if (nameIndexOut == NULL ||
        (entryCount != KSW_PLATFORM_HAL_SUBCOMPONENT_LEGACY_COUNT &&
         entryCount != KSW_PLATFORM_HAL_SUBCOMPONENT_MAX_COUNT) ||
        entryIndex >= entryCount) {
        return FALSE;
    }

    // Note: Vibranium's 21-item table lacks QoS; the new table inserts QoS between Proc and
    // Timer, so the old table must skip one display/identity name starting from this index.
    if (entryCount == KSW_PLATFORM_HAL_SUBCOMPONENT_LEGACY_COUNT &&
        entryIndex >= KSW_PLATFORM_HAL_SUBCOMPONENT_QOS_INDEX) {
        nameIndex += 1UL;
    }
    if (nameIndex >= RTL_NUMBER_OF(kGKswHalSubcomponentNames)) {
        return FALSE;
    }
    *nameIndexOut = nameIndex;
    return TRUE;
}

static BOOLEAN
kswPlatformHalSubcomponentIdentityMatches(
    _In_ const KswHookSystemModuleInformation* moduleInfo,
    _In_reads_(entryCount) const KswPlatformHalSubcomponent* entries,
    _In_ ULONG entryCount
    )
{
    ULONG index = 0UL;

    if (moduleInfo == NULL || entries == NULL ||
        (entryCount != KSW_PLATFORM_HAL_SUBCOMPONENT_LEGACY_COUNT &&
         entryCount != KSW_PLATFORM_HAL_SUBCOMPONENT_MAX_COUNT)) {
        return FALSE;
    }
    for (index = 0UL; index < entryCount; ++index) {
        ULONG nameIndex = 0UL;

        if (!kswPlatformHalSubcomponentIndex(
                index,
                entryCount,
                &nameIndex)) {
            return FALSE;
        }
        if (!kswPlatformValidateBoundedWideName(
                moduleInfo,
                entries[index].name,
                kGKswHalSubcomponentNames[nameIndex])) {
            return FALSE;
        }
    }
    return TRUE;
}

static BOOLEAN
kswPlatformValidateHalSubcomponentCandidate(
    _In_ const KswHookSystemModuleInformation* moduleInfo,
    _In_ PVOID candidate,
    _In_ const KswPlatformRipLocatorDescriptor* locator
    )
{
    const KswHookSystemModuleEntry* tableOwner = NULL;
    KswPlatformHalSubcomponent
        entries[KSW_PLATFORM_HAL_SUBCOMPONENT_MAX_COUNT];
    ULONG entryCount = 0UL;

    if (moduleInfo == NULL || candidate == NULL || locator == NULL) {
        return FALSE;
    }
    entryCount = locator->expectedVersion;
    if ((entryCount != KSW_PLATFORM_HAL_SUBCOMPONENT_LEGACY_COUNT &&
         entryCount != KSW_PLATFORM_HAL_SUBCOMPONENT_MAX_COUNT) ||
        locator->tableByteSize !=
            (ULONG)(sizeof(KswPlatformHalSubcomponent) * entryCount)) {
        return FALSE;
    }
    tableOwner = kswordArkHookFindModuleForAddress(moduleInfo, (ULONG_PTR)candidate);
    RtlZeroMemory(entries, sizeof(entries));
    if (!kswPlatformIsExpectedHalOwner(tableOwner) ||
        !kswPlatformRangeInSection(
            tableOwner,
            (ULONG_PTR)candidate,
            locator->tableByteSize,
            FALSE,
            TRUE) ||
        !kswordArkHookReadMemorySafe(
            candidate,
            entries,
            locator->tableByteSize)) {
        return FALSE;
    }

    if (!kswPlatformHalSubcomponentIdentityMatches(
            moduleInfo,
            entries,
            entryCount)) {
        return FALSE;
    }
    // 21/22 read-only name pairs and candidate identities responsible for the bounded table range; function slots classified item by item.
    // Therefore, functions replaced with external modules, unknown addresses, or NULL still return for the corresponding line.
    return TRUE;
}

static BOOLEAN
kswPlatformGetHalPowerAnchor(
    _In_ const KswHookSystemModuleInformation* moduleInfo,
    _Outptr_ PVOID* anchorOut
    )
{
    PVOID tableAddress = kswPlatformGetRoutine(L"HalDispatchTable");
    const KswHookSystemModuleEntry* tableOwner = NULL;
    ULONG version = 0UL;
    PVOID anchor = NULL;
    ULONG minimumBytes =
        FIELD_OFFSET(HAL_DISPATCH, HalInitPowerManagement) +
        sizeof(((PHAL_DISPATCH)0)->HalInitPowerManagement);

    if (anchorOut == NULL) {
        return FALSE;
    }
    *anchorOut = NULL;
    tableOwner = kswordArkHookFindModuleForAddress(moduleInfo, (ULONG_PTR)tableAddress);
    if (tableAddress == NULL ||
        !kswPlatformIsExpectedHalOwner(tableOwner) ||
        !kswPlatformRangeInSection(
            tableOwner,
            (ULONG_PTR)tableAddress,
            minimumBytes,
            FALSE,
            FALSE) ||
        !kswordArkHookReadMemorySafe(tableAddress, &version, sizeof(version)) ||
        version != HAL_DISPATCH_VERSION ||
        !kswordArkHookReadMemorySafe(
            (const UCHAR*)tableAddress +
                FIELD_OFFSET(HAL_DISPATCH, HalInitPowerManagement),
            &anchor,
            sizeof(anchor)) ||
        anchor == NULL) {
        return FALSE;
    }
    *anchorOut = anchor;
    return TRUE;
}

static VOID
kswPlatformAddHalAcpi(
    _Inout_ KSWORD_ARK_QUERY_PLATFORM_AUDIT_RESPONSE* response,
    _In_ ULONG capacity,
    _In_ ULONG maxRows,
    _In_ const KswHookSystemModuleInformation* moduleInfo,
    _In_ ULONG buildNumber
    )
{
    const KswPlatformRipLocatorDescriptor* locator =
        kswPlatformFindRipLocator(
            kGKswHalAcpiLocators,
            RTL_NUMBER_OF(kGKswHalAcpiLocators),
            buildNumber);
    PVOID anchor = NULL;
    PVOID tableAddress = NULL;
    KswPlatformHalAcpiView view;
    NTSTATUS locateStatus = STATUS_NOT_SUPPORTED;
    ULONG functionCount = 0UL;
    ULONG byteSize = 0UL;
    const ULONG kHeaderSize =
        FIELD_OFFSET(KswPlatformHalAcpiView, functions);
    ULONG index = 0UL;

    if (locator == NULL ||
        !kswPlatformGetHalPowerAnchor(moduleInfo, &anchor)) {
        if (kswPlatformAddExportedFunction(
                response,
                capacity,
                maxRows,
                KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_ACPI,
                moduleInfo,
                L"HalAcpiGetTableEx",
                KSWORD_ARK_PLATFORM_OWNER_NT_HAL_ACPI)) {
            return;
        }
        kswPlatformAddDiagnostic(
            response, capacity, maxRows,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_ACPI,
            KSWORD_ARK_PLATFORM_AUDIT_STATUS_UNSUPPORTED,
            STATUS_NOT_SUPPORTED,
            L"HalAcpiDispatchTable",
            KSWORD_ARK_PLATFORM_DETAIL_BUILD_UNSUPPORTED,
            buildNumber,
            0ULL);
        return;
    }
    locateStatus = kswPlatformLocateRipTable(
        moduleInfo,
        anchor,
        locator,
        kswPlatformValidateHalAcpiCandidate,
        &tableAddress);
    if (!NT_SUCCESS(locateStatus)) {
        if (kswPlatformAddExportedFunction(
                response,
                capacity,
                maxRows,
                KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_ACPI,
                moduleInfo,
                L"HalAcpiGetTableEx",
                KSWORD_ARK_PLATFORM_OWNER_NT_HAL_ACPI)) {
            return;
        }
        kswPlatformAddDiagnostic(
            response, capacity, maxRows,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_ACPI,
            KSWORD_ARK_PLATFORM_AUDIT_STATUS_UNSUPPORTED,
            locateStatus,
            L"HalAcpiDispatchTable",
            locateStatus == STATUS_OBJECT_NAME_COLLISION ?
                KSWORD_ARK_PLATFORM_DETAIL_LOCATOR_NOT_UNIQUE :
                KSWORD_ARK_PLATFORM_DETAIL_LOCATOR_NOT_FOUND,
            buildNumber,
            (ULONGLONG)(ULONG_PTR)anchor);
        return;
    }

    RtlZeroMemory(&view, sizeof(view));
    if (!kswordArkHookReadMemorySafe(tableAddress, &view, kHeaderSize)) {
        if (kswPlatformAddExportedFunction(
                response,
                capacity,
                maxRows,
                KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_ACPI,
                moduleInfo,
                L"HalAcpiGetTableEx",
                KSWORD_ARK_PLATFORM_OWNER_NT_HAL_ACPI)) {
            return;
        }
        kswPlatformAddDiagnostic(
            response, capacity, maxRows,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_ACPI,
            KSWORD_ARK_PLATFORM_AUDIT_STATUS_QUERY_FAILED,
            STATUS_PARTIAL_COPY,
            L"HalAcpiDispatchTable",
            KSWORD_ARK_PLATFORM_DETAIL_READ_FAILED,
            (ULONGLONG)(ULONG_PTR)tableAddress,
            kHeaderSize);
        return;
    }
    if (!kswPlatformHalAcpiIdentityMatches(
            &view,
            &functionCount,
            &byteSize)) {
        if (kswPlatformAddExportedFunction(
                response,
                capacity,
                maxRows,
                KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_ACPI,
                moduleInfo,
                L"HalAcpiGetTableEx",
                KSWORD_ARK_PLATFORM_OWNER_NT_HAL_ACPI)) {
            return;
        }
        kswPlatformAddDiagnostic(
            response, capacity, maxRows,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_ACPI,
            KSWORD_ARK_PLATFORM_AUDIT_STATUS_QUERY_FAILED,
            STATUS_REVISION_MISMATCH,
            L"HalAcpiDispatchTable",
            KSWORD_ARK_PLATFORM_DETAIL_TABLE_INVALID,
            view.signature,
            view.version);
        return;
    }
    if (functionCount > RTL_NUMBER_OF(view.functions) ||
        byteSize > sizeof(view) ||
        !kswordArkHookReadMemorySafe(tableAddress, &view, byteSize)) {
        if (kswPlatformAddExportedFunction(
                response,
                capacity,
                maxRows,
                KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_ACPI,
                moduleInfo,
                L"HalAcpiGetTableEx",
                KSWORD_ARK_PLATFORM_OWNER_NT_HAL_ACPI)) {
            return;
        }
        kswPlatformAddDiagnostic(
            response, capacity, maxRows,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_ACPI,
            KSWORD_ARK_PLATFORM_AUDIT_STATUS_QUERY_FAILED,
            STATUS_PARTIAL_COPY,
            L"HalAcpiDispatchTable",
            KSWORD_ARK_PLATFORM_DETAIL_READ_FAILED,
            (ULONGLONG)(ULONG_PTR)tableAddress,
            byteSize);
        return;
    }
    if (!kswPlatformHalAcpiIdentityMatches(&view, NULL, NULL)) {
        kswPlatformAddDiagnostic(
            response, capacity, maxRows,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_ACPI,
            KSWORD_ARK_PLATFORM_AUDIT_STATUS_QUERY_FAILED,
            STATUS_REVISION_MISMATCH,
            L"HalAcpiDispatchTable",
            KSWORD_ARK_PLATFORM_DETAIL_TABLE_INVALID,
            view.signature,
            view.version);
        return;
    }

    for (index = 0UL; index < functionCount; ++index) {
        KSWORD_ARK_PLATFORM_AUDIT_ENTRY entry;
        ULONG ownerPolicy =
            (index == 5UL || index == 6UL || index == 8UL ||
             index >= KSW_PLATFORM_HAL_ACPI_V5_FUNCTION_COUNT) ?
                KSWORD_ARK_PLATFORM_OWNER_NT_HAL_PCI :
                KSWORD_ARK_PLATFORM_OWNER_NT_HAL_ACPI;
        ULONG signatureId =
            view.version == KSW_PLATFORM_HAL_ACPI_VERSION_V4 ?
                KSWORD_ARK_PLATFORM_SIGNATURE_HAL_ACPI_V4 :
                KSWORD_ARK_PLATFORM_SIGNATURE_HAL_ACPI_V5;

        kswPlatformInitializeEntry(
            &entry,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_ACPI,
            KSWORD_ARK_PLATFORM_AUDIT_ROW_FUNCTION,
            signatureId,
            KSWORD_ARK_PLATFORM_SLOT_FUNCTION,
            ownerPolicy,
            index,
            tableAddress,
            kGKswHalAcpiFunctionNames[index]);
        entry.fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_STRUCTURE_VALIDATED |
            KSWORD_ARK_PLATFORM_FIELD_READ_ONLY_RANGE |
            KSWORD_ARK_PLATFORM_FIELD_LOCATOR_VALIDATED;
        if (view.functions[index] == NULL) {
            entry.status = KSWORD_ARK_PLATFORM_AUDIT_STATUS_UNAVAILABLE;
            kswPlatformSetDetail(
                &entry,
                KSWORD_ARK_PLATFORM_DETAIL_NULL_SLOT,
                index,
                buildNumber,
                view.version,
                0ULL);
        }
        else {
            entry.liveAddress = (ULONGLONG)(ULONG_PTR)view.functions[index];
            entry.fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_LIVE_ADDRESS;
            kswPlatformClassifyFunction(&entry, moduleInfo, ownerPolicy);
        }
        kswPlatformAppend(response, capacity, maxRows, &entry);
    }
}

static VOID
kswPlatformAddHalSubcomponents(
    _Inout_ KSWORD_ARK_QUERY_PLATFORM_AUDIT_RESPONSE* response,
    _In_ ULONG capacity,
    _In_ ULONG maxRows,
    _In_ const KswHookSystemModuleInformation* moduleInfo,
    _In_ ULONG buildNumber
    )
{
    const KswPlatformRipLocatorDescriptor* locator =
        kswPlatformFindRipLocator(
            kGKswHalSubcomponentLocators,
            RTL_NUMBER_OF(kGKswHalSubcomponentLocators),
            buildNumber);
    PVOID anchor = NULL;
    PVOID tableAddress = NULL;
    KswPlatformHalSubcomponent
        entries[KSW_PLATFORM_HAL_SUBCOMPONENT_MAX_COUNT];
    NTSTATUS locateStatus = STATUS_NOT_SUPPORTED;
    ULONG entryCount = 0UL;
    ULONG index = 0UL;

    if (locator == NULL) {
        if (kswPlatformAddExportedFunction(
                response,
                capacity,
                maxRows,
                KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_SUBCOMPONENTS,
                moduleInfo,
                L"HalInitSystem",
                KSWORD_ARK_PLATFORM_OWNER_NT_HAL)) {
            return;
        }
        kswPlatformAddDiagnostic(
            response, capacity, maxRows,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_SUBCOMPONENTS,
            KSWORD_ARK_PLATFORM_AUDIT_STATUS_UNSUPPORTED,
            STATUS_NOT_SUPPORTED,
            L"HalSubComponents",
            KSWORD_ARK_PLATFORM_DETAIL_BUILD_UNSUPPORTED,
            buildNumber,
            26100ULL);
        return;
    }
    entryCount = locator->expectedVersion;
    anchor = locator->anchorName != NULL ?
        kswPlatformGetRoutine(locator->anchorName) :
        NULL;
    locateStatus = kswPlatformLocateRipTable(
        moduleInfo,
        anchor,
        locator,
        kswPlatformValidateHalSubcomponentCandidate,
        &tableAddress);
    if (!NT_SUCCESS(locateStatus)) {
        if (kswPlatformAddExportedFunction(
                response,
                capacity,
                maxRows,
                KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_SUBCOMPONENTS,
                moduleInfo,
                L"HalInitSystem",
                KSWORD_ARK_PLATFORM_OWNER_NT_HAL)) {
            return;
        }
        kswPlatformAddDiagnostic(
            response, capacity, maxRows,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_SUBCOMPONENTS,
            KSWORD_ARK_PLATFORM_AUDIT_STATUS_UNSUPPORTED,
            locateStatus,
            L"HalSubComponents",
            locateStatus == STATUS_OBJECT_NAME_COLLISION ?
                KSWORD_ARK_PLATFORM_DETAIL_LOCATOR_NOT_UNIQUE :
                KSWORD_ARK_PLATFORM_DETAIL_LOCATOR_NOT_FOUND,
            buildNumber,
            (ULONGLONG)(ULONG_PTR)anchor);
        return;
    }

    RtlZeroMemory(entries, sizeof(entries));
    if (!kswordArkHookReadMemorySafe(
            tableAddress,
            entries,
            locator->tableByteSize)) {
        if (kswPlatformAddExportedFunction(
                response,
                capacity,
                maxRows,
                KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_SUBCOMPONENTS,
                moduleInfo,
                L"HalInitSystem",
                KSWORD_ARK_PLATFORM_OWNER_NT_HAL)) {
            return;
        }
        kswPlatformAddDiagnostic(
            response, capacity, maxRows,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_SUBCOMPONENTS,
            KSWORD_ARK_PLATFORM_AUDIT_STATUS_QUERY_FAILED,
            STATUS_PARTIAL_COPY,
            L"HalSubComponents",
            KSWORD_ARK_PLATFORM_DETAIL_READ_FAILED,
            (ULONGLONG)(ULONG_PTR)tableAddress,
            locator->tableByteSize);
        return;
    }
    if (!kswPlatformHalSubcomponentIdentityMatches(
            moduleInfo,
            entries,
            entryCount)) {
        if (kswPlatformAddExportedFunction(
                response,
                capacity,
                maxRows,
                KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_SUBCOMPONENTS,
                moduleInfo,
                L"HalInitSystem",
                KSWORD_ARK_PLATFORM_OWNER_NT_HAL)) {
            return;
        }
        kswPlatformAddDiagnostic(
            response, capacity, maxRows,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_SUBCOMPONENTS,
            KSWORD_ARK_PLATFORM_AUDIT_STATUS_QUERY_FAILED,
            STATUS_REVISION_MISMATCH,
            L"HalSubComponents",
            KSWORD_ARK_PLATFORM_DETAIL_TABLE_INVALID,
            (ULONGLONG)(ULONG_PTR)tableAddress,
            entryCount);
        return;
    }

    for (index = 0UL; index < entryCount; ++index) {
        KSWORD_ARK_PLATFORM_AUDIT_ENTRY entry;
        ULONG nameIndex = 0UL;
        ULONG signatureId =
            entryCount == KSW_PLATFORM_HAL_SUBCOMPONENT_LEGACY_COUNT ?
                KSWORD_ARK_PLATFORM_SIGNATURE_HAL_SUBCOMPONENTS_21 :
                KSWORD_ARK_PLATFORM_SIGNATURE_HAL_SUBCOMPONENTS_22;

        if (!kswPlatformHalSubcomponentIndex(
                index,
                entryCount,
                &nameIndex)) {
            break;
        }
        kswPlatformInitializeEntry(
            &entry,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_SUBCOMPONENTS,
            KSWORD_ARK_PLATFORM_AUDIT_ROW_FUNCTION,
            signatureId,
            KSWORD_ARK_PLATFORM_SLOT_FUNCTION,
            KSWORD_ARK_PLATFORM_OWNER_NT_HAL,
            index,
            tableAddress,
            kGKswHalSubcomponentFunctionNames[nameIndex]);
        entry.fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_STRUCTURE_VALIDATED |
            KSWORD_ARK_PLATFORM_FIELD_READ_ONLY_RANGE |
            KSWORD_ARK_PLATFORM_FIELD_LOCATOR_VALIDATED;
        if (entries[index].function == NULL) {
            entry.status = KSWORD_ARK_PLATFORM_AUDIT_STATUS_UNAVAILABLE;
            kswPlatformSetDetail(
                &entry,
                KSWORD_ARK_PLATFORM_DETAIL_NULL_SLOT,
                index,
                buildNumber,
                entryCount,
                0ULL);
        }
        else {
            entry.liveAddress =
                (ULONGLONG)(ULONG_PTR)entries[index].function;
            entry.fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_LIVE_ADDRESS;
            kswPlatformClassifyFunction(
                &entry,
                moduleInfo,
                KSWORD_ARK_PLATFORM_OWNER_NT_HAL);
        }
        kswPlatformAppend(response, capacity, maxRows, &entry);
    }
}

static VOID
kswPlatformAddWdfFunctions(
    _Inout_ KSWORD_ARK_QUERY_PLATFORM_AUDIT_RESPONSE* response,
    _In_ ULONG capacity,
    _In_ ULONG maxRows,
    _In_ const KswHookSystemModuleInformation* moduleInfo
    )
{
    const WDFFUNC* functionTable = WdfFunctions;
    const KswHookSystemModuleEntry* tableOwner = NULL;
    ULONG index = 0UL;
    ULONG functionCount = (ULONG)WdfFunctionTableNumEntries;

    if (functionTable == NULL ||
        functionCount == 0UL ||
        functionCount > KSWORD_ARK_PLATFORM_HARD_MAX_ROWS) {
        kswPlatformAddDiagnostic(
            response, capacity, maxRows,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_WDF_FUNCTIONS,
            KSWORD_ARK_PLATFORM_AUDIT_STATUS_UNSUPPORTED,
            STATUS_NOT_SUPPORTED,
            L"WdfFunctions",
            KSWORD_ARK_PLATFORM_DETAIL_WDF_TABLE_INVALID,
            functionCount,
            0ULL);
        return;
    }
    tableOwner = kswordArkHookFindModuleForAddress(moduleInfo, (ULONG_PTR)functionTable);
    if (!kswPlatformModuleNameEquals(tableOwner, "Wdf01000.sys") ||
        !kswPlatformRangeInSection(
            tableOwner,
            (ULONG_PTR)functionTable,
            (SIZE_T)functionCount * sizeof(WDFFUNC),
            FALSE,
            FALSE)) {
        kswPlatformAddDiagnostic(
            response, capacity, maxRows,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_WDF_FUNCTIONS,
            KSWORD_ARK_PLATFORM_AUDIT_STATUS_SIGNATURE_MISMATCH,
            STATUS_DATA_ERROR,
            L"WdfFunctions",
            KSWORD_ARK_PLATFORM_DETAIL_WDF_TABLE_INVALID,
            (ULONGLONG)(ULONG_PTR)functionTable,
            functionCount);
        return;
    }

    for (index = 0UL; index < functionCount; ++index) {
        KSWORD_ARK_PLATFORM_AUDIT_ENTRY entry;
        WDFFUNC functionAddress = NULL;
        WCHAR fallbackName[KSWORD_ARK_PLATFORM_NAME_CHARS];
        PCWSTR functionName =
            index < RTL_NUMBER_OF(kGKswWdfFunctionNames)
            ? kGKswWdfFunctionNames[index]
            : NULL;
        RtlZeroMemory(fallbackName, sizeof(fallbackName));
        if (functionName == NULL) {
            (VOID)RtlStringCchPrintfW(
                fallbackName,
                RTL_NUMBER_OF(fallbackName),
                L"WdfFunctions[%lu]",
                index);
            functionName = fallbackName;
        }

        kswPlatformInitializeEntry(
            &entry,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_WDF_FUNCTIONS,
            KSWORD_ARK_PLATFORM_AUDIT_ROW_FUNCTION,
            KSWORD_ARK_PLATFORM_SIGNATURE_WDF_BINDING_TABLE,
            KSWORD_ARK_PLATFORM_SLOT_FUNCTION,
            KSWORD_ARK_PLATFORM_OWNER_WDF,
            index,
            (PVOID)functionTable,
            functionName);
        entry.fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_STRUCTURE_VALIDATED;

        if (!kswordArkHookReadMemorySafe(
                &functionTable[index],
                &functionAddress,
                sizeof(functionAddress))) {
            entry.status = KSWORD_ARK_PLATFORM_AUDIT_STATUS_QUERY_FAILED;
            entry.lastStatus = STATUS_PARTIAL_COPY;
            kswPlatformSetDetail(
                &entry,
                KSWORD_ARK_PLATFORM_DETAIL_READ_FAILED,
                index,
                functionCount,
                0ULL,
                0ULL);
            kswPlatformAppend(response, capacity, maxRows, &entry);
            continue;
        }
        if (functionAddress == NULL) {
            entry.status = KSWORD_ARK_PLATFORM_AUDIT_STATUS_UNAVAILABLE;
            kswPlatformSetDetail(
                &entry,
                KSWORD_ARK_PLATFORM_DETAIL_NULL_SLOT,
                index,
                functionCount,
                0ULL,
                0ULL);
            kswPlatformAppend(response, capacity, maxRows, &entry);
            continue;
        }
        entry.liveAddress = (ULONGLONG)(ULONG_PTR)functionAddress;
        entry.fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_LIVE_ADDRESS;
        kswPlatformClassifyFunction(
            &entry,
            moduleInfo,
            KSWORD_ARK_PLATFORM_OWNER_WDF);
        kswPlatformAppend(response, capacity, maxRows, &entry);
    }
}

static VOID
kswPlatformAddWdfCallbacks(
    _Inout_ KSWORD_ARK_QUERY_PLATFORM_AUDIT_RESPONSE* response,
    _In_ ULONG capacity,
    _In_ ULONG maxRows,
    _In_ const KswHookSystemModuleInformation* moduleInfo
    )
{
    ULONG index = 0UL;

    for (index = 0UL; index < RTL_NUMBER_OF(kGKswWdfCallbacks); ++index) {
        KSWORD_ARK_PLATFORM_AUDIT_ENTRY entry;

        kswPlatformInitializeEntry(
            &entry,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_WDF_CALLBACKS,
            KSWORD_ARK_PLATFORM_AUDIT_ROW_CALLBACK,
            KSWORD_ARK_PLATFORM_SIGNATURE_X64_PROLOGUE,
            KSWORD_ARK_PLATFORM_SLOT_FUNCTION,
            KSWORD_ARK_PLATFORM_OWNER_KSWORD,
            index,
            NULL,
            kGKswWdfCallbacks[index].name);
        entry.liveAddress = (ULONGLONG)(ULONG_PTR)kGKswWdfCallbacks[index].address;
        entry.fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_LIVE_ADDRESS;
        kswPlatformClassifyFunction(
            &entry,
            moduleInfo,
            KSWORD_ARK_PLATFORM_OWNER_KSWORD);
        kswPlatformAppend(response, capacity, maxRows, &entry);
    }
}

static VOID
kswordArkPlatformAuditLog(
    _In_ WDFDEVICE device,
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR formatText,
    ...
    )
/*++

Routine Description:

    Format and enqueue one platform-audit log line.

Arguments:

    Device - WDF device owning the log channel.
    levelText - Log level string.
    FormatText - printf-style ANSI template.
    ... - Template arguments.

Return Value:

    None.  Formatting or enqueue failures are ignored; diagnostics must never
    change the outcome of the request they describe.

--*/
{
    CHAR logMessage[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
    va_list arguments;

    va_start(arguments, formatText);
    if (NT_SUCCESS(RtlStringCbVPrintfA(logMessage, sizeof(logMessage), formatText, arguments))) {
        (VOID)kswordArkDriverEnqueueLogFrame(device, levelText, logMessage);
    }
    va_end(arguments);
}

static BOOLEAN
kswordArkPlatformAuditRequestIsValid(
    _In_ WDFDEVICE device,
    _In_ const KSWORD_ARK_QUERY_PLATFORM_AUDIT_REQUEST* requestPacket,
    _In_ BOOLEAN callerSuppliedInput
    )
/*++

Routine Description:

    Validate the request packet, naming the field that failed.  The dispatch
    layer only reports STATUS_INVALID_PARAMETER, which cannot distinguish a
    protocol-version mismatch from a malformed packet; a user-mode binary built
    against a different version of the shared header is by far the most common
    cause and used to require reading the source to diagnose.

Arguments:

    Device - WDF device owning the log channel.
    RequestPacket - Caller packet, or the driver's default packet.
    CallerSuppliedInput - FALSE when the defaults are in use, so a rejection
        would indicate a driver-side defect rather than a caller mismatch.

Return Value:

    TRUE when every field is acceptable.

--*/
{
    if (requestPacket == NULL) {
        return FALSE;
    }
    if (requestPacket->size != sizeof(*requestPacket)) {
        kswordArkPlatformAuditLog(
            device,
            "Warn",
            "Platform audit request rejected: size=%lu, expected=%lu, caller_supplied=%u.",
            (unsigned long)requestPacket->size,
            (unsigned long)sizeof(*requestPacket),
            (unsigned)callerSuppliedInput);
        return FALSE;
    }
    if (requestPacket->version != KSWORD_ARK_PLATFORM_AUDIT_PROTOCOL_VERSION) {
        kswordArkPlatformAuditLog(
            device,
            "Warn",
            "Platform audit protocol mismatch: request_version=%lu, driver_version=%lu, "
            "caller_supplied=%u. User-mode and driver binaries are from different builds.",
            (unsigned long)requestPacket->version,
            (unsigned long)KSWORD_ARK_PLATFORM_AUDIT_PROTOCOL_VERSION,
            (unsigned)callerSuppliedInput);
        return FALSE;
    }
    if (requestPacket->flags != 0UL || requestPacket->reserved0 != 0UL) {
        kswordArkPlatformAuditLog(
            device,
            "Warn",
            "Platform audit request rejected: flags=0x%08lX, reserved0=0x%08lX, both must be zero.",
            (unsigned long)requestPacket->flags,
            (unsigned long)requestPacket->reserved0);
        return FALSE;
    }
    if ((requestPacket->scopeMask & ~KSWORD_ARK_PLATFORM_AUDIT_SCOPE_ALL) != 0UL) {
        kswordArkPlatformAuditLog(
            device,
            "Warn",
            "Platform audit request rejected: scopeMask=0x%08lX carries bits outside 0x%08lX.",
            (unsigned long)requestPacket->scopeMask,
            (unsigned long)KSWORD_ARK_PLATFORM_AUDIT_SCOPE_ALL);
        return FALSE;
    }
    return TRUE;
}

NTSTATUS
kswordArkPlatformAuditIoctlQuery(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
    KSWORD_ARK_QUERY_PLATFORM_AUDIT_REQUEST defaultRequest;
    const KSWORD_ARK_QUERY_PLATFORM_AUDIT_REQUEST* requestPacket = NULL;
    KSWORD_ARK_QUERY_PLATFORM_AUDIT_RESPONSE* response = NULL;
    KswHookSystemModuleInformation* moduleInfo = NULL;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputBytes = 0U;
    size_t actualOutputBytes = 0U;
    ULONG moduleInfoBytes = 0UL;
    ULONG capacity = 0UL;
    ULONG maxRows = KSWORD_ARK_PLATFORM_DEFAULT_MAX_ROWS;
    ULONG scopeMask = KSWORD_ARK_PLATFORM_AUDIT_SCOPE_ALL;
    ULONG majorVersion = 0UL;
    ULONG minorVersion = 0UL;
    ULONG buildNumber = 0UL;
    BOOLEAN hasInput = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;
    RtlZeroMemory(&defaultRequest, sizeof(defaultRequest));
    defaultRequest.size = sizeof(defaultRequest);
    defaultRequest.version = KSWORD_ARK_PLATFORM_AUDIT_PROTOCOL_VERSION;
    defaultRequest.scopeMask = KSWORD_ARK_PLATFORM_AUDIT_SCOPE_ALL;
    defaultRequest.maxRows = KSWORD_ARK_PLATFORM_DEFAULT_MAX_ROWS;

    status = kswordArkRetrieveOptionalInputBuffer(
        request,
        inputBufferLength,
        sizeof(KSWORD_ARK_QUERY_PLATFORM_AUDIT_REQUEST),
        &inputBuffer,
        &actualInputBytes,
        &hasInput);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    UNREFERENCED_PARAMETER(actualInputBytes);
    requestPacket = hasInput ?
        (const KSWORD_ARK_QUERY_PLATFORM_AUDIT_REQUEST*)inputBuffer :
        &defaultRequest;
    if (!kswordArkPlatformAuditRequestIsValid(device, requestPacket, hasInput)) {
        return STATUS_INVALID_PARAMETER;
    }
    scopeMask = requestPacket->scopeMask == 0UL ?
        KSWORD_ARK_PLATFORM_AUDIT_SCOPE_ALL :
        requestPacket->scopeMask;
    maxRows = requestPacket->maxRows == 0UL ?
        KSWORD_ARK_PLATFORM_DEFAULT_MAX_ROWS :
        requestPacket->maxRows;
    if (maxRows > KSWORD_ARK_PLATFORM_HARD_MAX_ROWS) {
        maxRows = KSWORD_ARK_PLATFORM_HARD_MAX_ROWS;
    }

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        KSW_PLATFORM_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputBytes);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    RtlZeroMemory(outputBuffer, actualOutputBytes);
    response = (KSWORD_ARK_QUERY_PLATFORM_AUDIT_RESPONSE*)outputBuffer;
    response->size = KSW_PLATFORM_RESPONSE_HEADER_SIZE;
    response->version = KSWORD_ARK_PLATFORM_AUDIT_PROTOCOL_VERSION;
    response->queryStatus = KSWORD_ARK_PLATFORM_AUDIT_STATUS_OK;
    response->scopeMask = scopeMask;
    response->responseFlags = KSWORD_ARK_PLATFORM_RESPONSE_NO_PDB;
    response->entrySize = sizeof(KSWORD_ARK_PLATFORM_AUDIT_ENTRY);
    response->signaturePolicyFlags =
        KSWORD_ARK_PLATFORM_FIELD_EXACT_EXPORT |
        KSWORD_ARK_PLATFORM_FIELD_STRUCTURE_VALIDATED |
        KSWORD_ARK_PLATFORM_FIELD_OWNER_VALIDATED |
        KSWORD_ARK_PLATFORM_FIELD_PROLOGUE_FORMAT |
        KSWORD_ARK_PLATFORM_FIELD_LOCATOR_VALIDATED;
    response->lastStatus = STATUS_SUCCESS;
    capacity = kswPlatformOutputCapacity(actualOutputBytes);
    (VOID)PsGetVersion(&majorVersion, &minorVersion, &buildNumber, NULL);
    UNREFERENCED_PARAMETER(majorVersion);
    UNREFERENCED_PARAMETER(minorVersion);
    response->buildNumber = buildNumber;

    status = kswordArkHookBuildModuleSnapshot(&moduleInfo, &moduleInfoBytes);
    if (!NT_SUCCESS(status) || moduleInfo == NULL || moduleInfoBytes == 0UL) {
        if (NT_SUCCESS(status)) {
            status = STATUS_UNSUCCESSFUL;
        }
        kswPlatformAddDiagnostic(
            response, capacity, maxRows, scopeMask,
            KSWORD_ARK_PLATFORM_AUDIT_STATUS_QUERY_FAILED,
            status,
            L"LoadedModuleSnapshot",
            KSWORD_ARK_PLATFORM_DETAIL_MODULE_SNAPSHOT_FAILED,
            moduleInfoBytes,
            0ULL);
        if (moduleInfo != NULL) {
            ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
            moduleInfo = NULL;
        }
        *bytesReturned = KSW_PLATFORM_RESPONSE_HEADER_SIZE +
            ((size_t)response->returnedCount * sizeof(KSWORD_ARK_PLATFORM_AUDIT_ENTRY));
        return STATUS_SUCCESS;
    }

    if ((scopeMask & KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_DISPATCH) != 0UL) {
        kswPlatformAddHalDispatch(response, capacity, maxRows, moduleInfo);
    }
    if ((scopeMask & KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_PRIVATE) != 0UL) {
        kswPlatformAddHalPrivate(
            response, capacity, maxRows, moduleInfo, buildNumber);
    }
    if ((scopeMask & KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_ACPI) != 0UL) {
        kswPlatformAddHalAcpi(
            response, capacity, maxRows, moduleInfo, buildNumber);
    }
    if ((scopeMask & KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_SUBCOMPONENTS) != 0UL) {
        kswPlatformAddHalSubcomponents(
            response, capacity, maxRows, moduleInfo, buildNumber);
    }
    if ((scopeMask & KSWORD_ARK_PLATFORM_AUDIT_SCOPE_WDF_FUNCTIONS) != 0UL) {
        kswPlatformAddWdfFunctions(response, capacity, maxRows, moduleInfo);
    }
    if ((scopeMask & KSWORD_ARK_PLATFORM_AUDIT_SCOPE_WDF_CALLBACKS) != 0UL) {
        kswPlatformAddWdfCallbacks(response, capacity, maxRows, moduleInfo);
    }

    ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
    if ((response->responseFlags & KSWORD_ARK_PLATFORM_RESPONSE_TRUNCATED) != 0UL) {
        response->queryStatus = KSWORD_ARK_PLATFORM_AUDIT_STATUS_BUFFER_TRUNCATED;
    }
    *bytesReturned = KSW_PLATFORM_RESPONSE_HEADER_SIZE +
        ((size_t)response->returnedCount * sizeof(KSWORD_ARK_PLATFORM_AUDIT_ENTRY));
    return STATUS_SUCCESS;
}

typedef struct KswPlatformEditSlot
{
    PVOID tableAddress;
    PVOID volatile* slotAddress;
    PVOID currentValue;
    // Set if the section containing the slot lacks IMAGE_SCN_MEM_WRITE; this is the case for the KMDF binding table.
    BOOLEAN requiresWritableAlias;
} KswPlatformEditSlot;

#define KSW_PLATFORM_EDIT_RECORD_LIMIT 64UL

typedef struct KswPlatformEditRecord
{
    BOOLEAN inUse;
    BOOLEAN requiresWritableAlias;
    ULONG scope;
    ULONG entryIndex;
    PVOID tableAddress;
    PVOID volatile* slotAddress;
    PVOID originalValue;
    PVOID appliedValue;
} KswPlatformEditRecord;

typedef struct KswPlatformEditState
{
    // Use ERESOURCE instead of FAST_MUTEX: read-only slot entries must call
    // MmProtectMdlSystemAddress within the lock to establish a writable alias, but this
    // routine only allows PASSIVE_LEVEL, whereas FAST_MUTEX would raise IRQL to APC_LEVEL.
    ERESOURCE lock;
    volatile LONG initialized;
    KswPlatformEditRecord records[KSW_PLATFORM_EDIT_RECORD_LIMIT];
} KswPlatformEditState;

static KswPlatformEditState gKswPlatformEditState;

static NTSTATUS
kswPlatformExchangeSlotPointer(
    _In_ PVOID volatile* slotAddress,
    _In_ BOOLEAN requiresWritableAlias,
    _In_opt_ PVOID expectedValue,
    _In_opt_ PVOID newValue,
    _Out_ PVOID* previousValueOut
    )
/*++

Routine Description:

    Perform an atomic CAS on a single function pointer slot. When the slot resides in a read-only image section (as with the KMDF binding
    table), first establish a writable system alias via MDL, then perform the CAS on the alias: the alias and original address map to the same
    physical page, lock cmpxchg is atomic on physical memory, and accesses via the original address remain mutually exclusive with other CPUs.
    Directly writing to read-only image pages triggers ATTEMPTED_WRITE_TO_READONLY_MEMORY, which
    the __except block cannot catch. Therefore, this check must be determined before the call.

Arguments:

    SlotAddress - A slot address that fits within a pointer width and does not cross page boundaries.
    RequiresWritableAlias - TRUE when the section containing the slot lacks IMAGE_SCN_MEM_WRITE.
    ExpectedValue - CAS comparison value.
    NewValue: Value for CAS write.
    PreviousValueOut: Writes back the original value read by CAS; equals ExpectedValue if CAS did not occur.

Return Value:

    STATUS_SUCCESS indicates CAS execution completed (value swap determined by caller comparing PreviousValueOut).
    Under HVCI, MmProtectMdlSystemAddress will reject privilege escalation; return its NTSTATUS in that case.

--*/
{
    PMDL mdl = NULL;
    PVOID mappedAddress = NULL;
    PVOID volatile* aliasSlot = NULL;
    BOOLEAN pagesLocked = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (slotAddress == NULL || previousValueOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *previousValueOut = expectedValue;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (!requiresWritableAlias) {
        __try {
            *previousValueOut = InterlockedCompareExchangePointer(
                slotAddress,
                newValue,
                expectedValue);
            KeMemoryBarrier();
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            *previousValueOut = expectedValue;
            status = GetExceptionCode();
        }
        return status;
    }

    __try {
        mdl = IoAllocateMdl(
            (PVOID)slotAddress,
            (ULONG)sizeof(PVOID),
            FALSE,
            FALSE,
            NULL);
        if (mdl == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }
        // Probe-only read-only image pages will directly raise an exception with IoModifyAccess. They must be locked as read-only
        // first, then temporarily elevated via a separate alias, while the original mapping's protection attributes remain unchanged.
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
        pagesLocked = TRUE;
        mappedAddress = MmMapLockedPagesSpecifyCache(
            mdl,
            KernelMode,
            MmCached,
            NULL,
            FALSE,
            NormalPagePriority | MdlMappingNoExecute);
        if (mappedAddress == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }
        status = MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
        if (!NT_SUCCESS(status)) {
            __leave;
        }
        aliasSlot = (PVOID volatile*)mappedAddress;
        *previousValueOut = InterlockedCompareExchangePointer(
            aliasSlot,
            newValue,
            expectedValue);
        KeMemoryBarrier();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        *previousValueOut = expectedValue;
        status = GetExceptionCode();
    }

    if (mappedAddress != NULL) {
        MmUnmapLockedPages(mappedAddress, mdl);
    }
    if (mdl != NULL) {
        if (pagesLocked) {
            MmUnlockPages(mdl);
        }
        IoFreeMdl(mdl);
    }
    return status;
}

VOID
kswordArkPlatformAuditInitialize(
    VOID
    )
{
    RtlZeroMemory(
        &gKswPlatformEditState,
        sizeof(gKswPlatformEditState));
    if (!NT_SUCCESS(ExInitializeResourceLite(&gKswPlatformEditState.lock))) {
        // When the lock is unavailable, the edit entry remains closed while the query path is unaffected.
        return;
    }
    InterlockedExchange(&gKswPlatformEditState.initialized, 1L);
}

VOID
kswordArkPlatformAuditUninitialize(
    VOID
    )
{
    ULONG index = 0UL;

    if (InterlockedCompareExchange(
            &gKswPlatformEditState.initialized,
            0L,
            0L) == 0L ||
        KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }

    KeEnterCriticalRegion();
    (VOID)ExAcquireResourceExclusiveLite(&gKswPlatformEditState.lock, TRUE);
    // Flip the flag inside the lock: any submission already queued on the lock will see 0 after acquiring
    // it and exit immediately, preventing it from writing back a stale value after recovery completes.
    InterlockedExchange(&gKswPlatformEditState.initialized, 0L);
    for (index = 0UL; index < KSW_PLATFORM_EDIT_RECORD_LIMIT; ++index) {
        KswPlatformEditRecord* record =
            &gKswPlatformEditState.records[index];
        PVOID previousValue = NULL;
        if (!record->inUse || record->slotAddress == NULL) {
            continue;
        }
        // Unloading recovery only overwrites the last published value for this feature; inaccessible states, alias
        // privilege escalation rejections, or third-party values remain unchanged, so ignore the return status here.
        (VOID)kswPlatformExchangeSlotPointer(
            record->slotAddress,
            record->requiresWritableAlias,
            record->appliedValue,
            record->originalValue,
            &previousValue);
        RtlZeroMemory(record, sizeof(*record));
    }
    ExReleaseResourceLite(&gKswPlatformEditState.lock);
    KeLeaveCriticalRegion();
    ExDeleteResourceLite(&gKswPlatformEditState.lock);
    RtlZeroMemory(
        &gKswPlatformEditState,
        sizeof(gKswPlatformEditState));
}

static NTSTATUS
kswPlatformCommitEdit(
    _In_ ULONG scope,
    _In_ ULONG entryIndex,
    _In_ const KswPlatformEditSlot* slot,
    _In_ PVOID expectedValue,
    _In_ PVOID newValue,
    _Out_ PVOID* previousValueOut
    )
{
    KswPlatformEditRecord* record = NULL;
    KswPlatformEditRecord* freeRecord = NULL;
    PVOID previousValue = NULL;
    ULONG index = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (slot == NULL || slot->tableAddress == NULL ||
        slot->slotAddress == NULL || newValue == NULL ||
        previousValueOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *previousValueOut = NULL;
    if (InterlockedCompareExchange(
            &gKswPlatformEditState.initialized,
            0L,
            0L) == 0L) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    KeEnterCriticalRegion();
    (VOID)ExAcquireResourceExclusiveLite(&gKswPlatformEditState.lock, TRUE);
    // Unloading flips the flag to 0 within the lock; submissions queued on the lock must be rechecked, otherwise they will write after recovery.
    if (InterlockedCompareExchange(
            &gKswPlatformEditState.initialized,
            0L,
            0L) == 0L) {
        status = STATUS_DEVICE_NOT_READY;
        goto Exit;
    }
    for (index = 0UL; index < KSW_PLATFORM_EDIT_RECORD_LIMIT; ++index) {
        KswPlatformEditRecord* candidate =
            &gKswPlatformEditState.records[index];
        if (!candidate->inUse) {
            if (freeRecord == NULL) {
                freeRecord = candidate;
            }
            continue;
        }
        if (candidate->scope == scope &&
            candidate->entryIndex == entryIndex &&
            candidate->tableAddress == slot->tableAddress) {
            record = candidate;
            break;
        }
        // A single physical slot cannot establish a second recovery record with a different logical identity; otherwise, during
        // unloading, the original value chains of the two CAS operations may mask each other, leaving intermediate values behind.
        if (candidate->slotAddress == slot->slotAddress) {
            status = STATUS_CONFLICTING_ADDRESSES;
            goto Exit;
        }
    }
    if (record != NULL &&
        (record->slotAddress != slot->slotAddress ||
         record->appliedValue != expectedValue)) {
        status = STATUS_CONFLICTING_ADDRESSES;
        goto Exit;
    }
    if (record == NULL && freeRecord == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    status = kswPlatformExchangeSlotPointer(
        slot->slotAddress,
        slot->requiresWritableAlias,
        expectedValue,
        newValue,
        &previousValue);
    *previousValueOut = previousValue;
    if (!NT_SUCCESS(status) || previousValue != expectedValue) {
        if (NT_SUCCESS(status)) {
            status = STATUS_REVISION_MISMATCH;
        }
        goto Exit;
    }

    if (record == NULL) {
        record = freeRecord;
        RtlZeroMemory(record, sizeof(*record));
        record->inUse = TRUE;
        record->requiresWritableAlias = slot->requiresWritableAlias;
        record->scope = scope;
        record->entryIndex = entryIndex;
        record->tableAddress = slot->tableAddress;
        record->slotAddress = slot->slotAddress;
        record->originalValue = expectedValue;
    }
    record->appliedValue = newValue;
    if (record->appliedValue == record->originalValue) {
        RtlZeroMemory(record, sizeof(*record));
    }

Exit:
    ExReleaseResourceLite(&gKswPlatformEditState.lock);
    KeLeaveCriticalRegion();
    return status;
}

static NTSTATUS
kswPlatformResolveHalDispatchEditSlot(
    _In_ const KswHookSystemModuleInformation* moduleInfo,
    _In_ ULONG entryIndex,
    _Out_ KswPlatformEditSlot* slotOut
    )
{
    PVOID tableAddress = kswPlatformGetRoutine(L"HalDispatchTable");
    const KswHookSystemModuleEntry* tableOwner = NULL;
    const KswPlatformSlotDescriptor* descriptor = NULL;
    ULONG version = 0UL;
    ULONG slotCount = 0UL;
    ULONG tableBytes = 0UL;

    if (moduleInfo == NULL || slotOut == NULL || tableAddress == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    tableOwner = kswordArkHookFindModuleForAddress(
        moduleInfo,
        (ULONG_PTR)tableAddress);
    if (!kswPlatformIsExpectedHalOwner(tableOwner) ||
        !kswPlatformRangeInSection(
            tableOwner,
            (ULONG_PTR)tableAddress,
            sizeof(version),
            FALSE,
            FALSE) ||
        !kswordArkHookReadMemorySafe(
            tableAddress,
            &version,
            sizeof(version))) {
        return STATUS_DATA_ERROR;
    }
    slotCount = kswPlatformHalDispatchSlotCount(version);
    if (slotCount == 0UL || entryIndex >= slotCount) {
        return STATUS_REVISION_MISMATCH;
    }
    tableBytes = kGKswHalDispatchSlots[slotCount - 1UL].offset +
        kGKswHalDispatchSlots[slotCount - 1UL].width;
    if (!kswPlatformRangeInSection(
            tableOwner,
            (ULONG_PTR)tableAddress,
            tableBytes,
            FALSE,
            FALSE)) {
        return STATUS_DATA_ERROR;
    }
    descriptor = &kGKswHalDispatchSlots[entryIndex];
    if (descriptor->slotKind != KSWORD_ARK_PLATFORM_SLOT_FUNCTION ||
        descriptor->width != sizeof(PVOID)) {
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    slotOut->tableAddress = tableAddress;
    slotOut->slotAddress = (PVOID volatile*)(
        (UCHAR*)tableAddress + descriptor->offset);
    if (!kswordArkHookReadMemorySafe(
            (const VOID*)slotOut->slotAddress,
            &slotOut->currentValue,
            sizeof(slotOut->currentValue))) {
        RtlZeroMemory(slotOut, sizeof(*slotOut));
        return STATUS_PARTIAL_COPY;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS
kswPlatformResolveHalPrivateEditSlot(
    _In_ const KswHookSystemModuleInformation* moduleInfo,
    _In_ ULONG buildNumber,
    _In_ ULONG entryIndex,
    _Out_ KswPlatformEditSlot* slotOut
    )
{
    const KswPlatformPrivateBuildDescriptor* build =
        kswPlatformFindPrivateBuild(buildNumber);
    const KswPlatformSlotDescriptor* descriptor = NULL;
    const KswHookSystemModuleEntry* tableOwner = NULL;
    PVOID tableAddress = kswPlatformGetRoutine(L"HalPrivateDispatchTable");
    ULONG version = 0UL;
    NTSTATUS status = STATUS_NOT_SUPPORTED;

    if (moduleInfo == NULL || slotOut == NULL || entryIndex == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    tableOwner = kswordArkHookFindModuleForAddress(
        moduleInfo,
        (ULONG_PTR)tableAddress);
    if (tableAddress != NULL &&
        kswPlatformIsExpectedHalOwner(tableOwner) &&
        kswPlatformRangeInSection(
            tableOwner,
            (ULONG_PTR)tableAddress,
            sizeof(version),
            FALSE,
            FALSE) &&
        kswordArkHookReadMemorySafe(
            tableAddress,
            &version,
            sizeof(version))) {
        const KswPlatformPrivateBuildDescriptor* versionBuild =
            kswPlatformFindPrivateVersion(version);
        if (versionBuild == NULL) {
            return STATUS_REVISION_MISMATCH;
        }
        if (!kswPlatformRangeInSection(
                tableOwner,
                (ULONG_PTR)tableAddress,
                versionBuild->byteSize,
                FALSE,
                FALSE)) {
            return STATUS_DATA_ERROR;
        }
        build = versionBuild;
        status = STATUS_SUCCESS;
    }
    else if (build != NULL) {
        status = kswPlatformLocateHalPrivateBySignature(
            moduleInfo,
            buildNumber,
            build,
            &tableAddress,
            &version);
    }
    if (!NT_SUCCESS(status) || build == NULL || version != build->version) {
        return NT_SUCCESS(status) ? STATUS_REVISION_MISMATCH : status;
    }
    if (entryIndex - 1UL >= RTL_NUMBER_OF(kGKswHalPrivateSlots)) {
        return STATUS_INVALID_PARAMETER;
    }
    descriptor = &kGKswHalPrivateSlots[entryIndex - 1UL];
    if (descriptor->offset + descriptor->width > build->byteSize ||
        descriptor->slotKind != KSWORD_ARK_PLATFORM_SLOT_FUNCTION ||
        descriptor->width != sizeof(PVOID)) {
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    slotOut->tableAddress = tableAddress;
    slotOut->slotAddress = (PVOID volatile*)(
        (UCHAR*)tableAddress + descriptor->offset);
    if (!kswordArkHookReadMemorySafe(
            (const VOID*)slotOut->slotAddress,
            &slotOut->currentValue,
            sizeof(slotOut->currentValue))) {
        RtlZeroMemory(slotOut, sizeof(*slotOut));
        return STATUS_PARTIAL_COPY;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS
kswPlatformResolveHalAcpiEditSlot(
    _In_ const KswHookSystemModuleInformation* moduleInfo,
    _In_ ULONG buildNumber,
    _In_ ULONG entryIndex,
    _Out_ KswPlatformEditSlot* slotOut
    )
{
    const KswPlatformRipLocatorDescriptor* locator =
        kswPlatformFindRipLocator(
            kGKswHalAcpiLocators,
            RTL_NUMBER_OF(kGKswHalAcpiLocators),
            buildNumber);
    KswPlatformHalAcpiView view;
    PVOID anchor = NULL;
    PVOID tableAddress = NULL;
    ULONG functionCount = 0UL;
    ULONG byteSize = 0UL;
    NTSTATUS status = STATUS_NOT_SUPPORTED;

    if (moduleInfo == NULL || slotOut == NULL || locator == NULL ||
        !kswPlatformGetHalPowerAnchor(moduleInfo, &anchor)) {
        return STATUS_NOT_SUPPORTED;
    }
    status = kswPlatformLocateRipTable(
        moduleInfo,
        anchor,
        locator,
        kswPlatformValidateHalAcpiCandidate,
        &tableAddress);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    RtlZeroMemory(&view, sizeof(view));
    if (!kswordArkHookReadMemorySafe(
            tableAddress,
            &view,
            FIELD_OFFSET(KswPlatformHalAcpiView, functions)) ||
        !kswPlatformHalAcpiIdentityMatches(
            &view,
            &functionCount,
            &byteSize) ||
        entryIndex >= functionCount ||
        byteSize > sizeof(view) ||
        !kswordArkHookReadMemorySafe(tableAddress, &view, byteSize) ||
        !kswPlatformHalAcpiIdentityMatches(&view, NULL, NULL)) {
        return STATUS_REVISION_MISMATCH;
    }

    slotOut->tableAddress = tableAddress;
    slotOut->slotAddress = (PVOID volatile*)(
        (UCHAR*)tableAddress +
        FIELD_OFFSET(KswPlatformHalAcpiView, functions) +
        (entryIndex * sizeof(PVOID)));
    slotOut->currentValue = view.functions[entryIndex];
    return STATUS_SUCCESS;
}

static NTSTATUS
kswPlatformResolveHalSubcomponentEditSlot(
    _In_ const KswHookSystemModuleInformation* moduleInfo,
    _In_ ULONG buildNumber,
    _In_ ULONG entryIndex,
    _Out_ KswPlatformEditSlot* slotOut
    )
{
    const KswPlatformRipLocatorDescriptor* locator =
        kswPlatformFindRipLocator(
            kGKswHalSubcomponentLocators,
            RTL_NUMBER_OF(kGKswHalSubcomponentLocators),
            buildNumber);
    KswPlatformHalSubcomponent
        entries[KSW_PLATFORM_HAL_SUBCOMPONENT_MAX_COUNT];
    PVOID anchor = NULL;
    PVOID tableAddress = NULL;
    ULONG entryCount = 0UL;
    NTSTATUS status = STATUS_NOT_SUPPORTED;

    if (moduleInfo == NULL || slotOut == NULL || locator == NULL) {
        return STATUS_NOT_SUPPORTED;
    }
    entryCount = locator->expectedVersion;
    anchor = locator->anchorName != NULL ?
        kswPlatformGetRoutine(locator->anchorName) :
        NULL;
    status = kswPlatformLocateRipTable(
        moduleInfo,
        anchor,
        locator,
        kswPlatformValidateHalSubcomponentCandidate,
        &tableAddress);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (entryCount > RTL_NUMBER_OF(entries) || entryIndex >= entryCount) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(entries, sizeof(entries));
    if (!kswordArkHookReadMemorySafe(
            tableAddress,
            entries,
            locator->tableByteSize) ||
        !kswPlatformHalSubcomponentIdentityMatches(
            moduleInfo,
            entries,
            entryCount)) {
        return STATUS_REVISION_MISMATCH;
    }

    slotOut->tableAddress = tableAddress;
    slotOut->slotAddress = (PVOID volatile*)(
        (UCHAR*)tableAddress +
        (entryIndex * sizeof(KswPlatformHalSubcomponent)) +
        FIELD_OFFSET(KswPlatformHalSubcomponent, function));
    slotOut->currentValue = entries[entryIndex].function;
    return STATUS_SUCCESS;
}

static NTSTATUS
kswPlatformResolveWdfFunctionEditSlot(
    _In_ const KswHookSystemModuleInformation* moduleInfo,
    _In_ ULONG entryIndex,
    _Out_ KswPlatformEditSlot* slotOut
    )
/*++

Routine Description:

    Re-locate a function slot in the complete KMDF binding table. The criteria match the query path item-by-item: the table pointer must
    belong to Wdf01000.sys, the entire table must reside within the same non-executable section, and the index must be within the number of
    table entries. The tableAddress passed from R3 is used only for post-hoc comparison and does not participate in address calculation.

    This table is owned by the framework itself; all KMDF drivers on the system (including this driver) share the same
    instance. Therefore, a modification to a single slot is global—the caller must have obtained explicit user confirmation.

--*/
{
    // WdfFunctions is declared as const. Since the CAS operation on the edit path must occur at the same address, the const qualifier is explicitly
    // removed when retrieving the slot address. Write permissions are determined by the subsequent module and section criteria, not the type.
    const WDFFUNC* functionTable = WdfFunctions;
    const KswHookSystemModuleEntry* tableOwner = NULL;
    ULONG functionCount = (ULONG)WdfFunctionTableNumEntries;
    WDFFUNC currentValue = NULL;

    if (moduleInfo == NULL || slotOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (functionTable == NULL ||
        functionCount == 0UL ||
        functionCount > KSWORD_ARK_PLATFORM_HARD_MAX_ROWS) {
        return STATUS_NOT_SUPPORTED;
    }
    if (entryIndex >= functionCount) {
        return STATUS_INVALID_PARAMETER;
    }
    tableOwner = kswordArkHookFindModuleForAddress(
        moduleInfo,
        (ULONG_PTR)functionTable);
    if (!kswPlatformModuleNameEquals(tableOwner, "Wdf01000.sys") ||
        !kswPlatformRangeInSection(
            tableOwner,
            (ULONG_PTR)functionTable,
            (SIZE_T)functionCount * sizeof(WDFFUNC),
            FALSE,
            FALSE)) {
        return STATUS_DATA_ERROR;
    }
    if (!kswordArkHookReadMemorySafe(
            &functionTable[entryIndex],
            &currentValue,
            sizeof(currentValue))) {
        return STATUS_PARTIAL_COPY;
    }

    slotOut->tableAddress = (PVOID)(ULONG_PTR)functionTable;
    slotOut->slotAddress =
        (PVOID volatile*)(ULONG_PTR)&functionTable[entryIndex];
    slotOut->currentValue = (PVOID)(ULONG_PTR)currentValue;
    return STATUS_SUCCESS;
}

static NTSTATUS
kswPlatformResolveEditableSlot(
    _In_ const KswHookSystemModuleInformation* moduleInfo,
    _In_ ULONG buildNumber,
    _In_ ULONG scope,
    _In_ ULONG entryIndex,
    _Out_ KswPlatformEditSlot* slotOut
    )
{
    const KswHookSystemModuleEntry* slotOwner = NULL;
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (slotOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(slotOut, sizeof(*slotOut));
    switch (scope) {
    case KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_DISPATCH:
        status = kswPlatformResolveHalDispatchEditSlot(
            moduleInfo,
            entryIndex,
            slotOut);
        break;
    case KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_PRIVATE:
        status = kswPlatformResolveHalPrivateEditSlot(
            moduleInfo,
            buildNumber,
            entryIndex,
            slotOut);
        break;
    case KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_ACPI:
        status = kswPlatformResolveHalAcpiEditSlot(
            moduleInfo,
            buildNumber,
            entryIndex,
            slotOut);
        break;
    case KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_SUBCOMPONENTS:
        status = kswPlatformResolveHalSubcomponentEditSlot(
            moduleInfo,
            buildNumber,
            entryIndex,
            slotOut);
        break;
    case KSWORD_ARK_PLATFORM_AUDIT_SCOPE_WDF_FUNCTIONS:
        status = kswPlatformResolveWdfFunctionEditSlot(
            moduleInfo,
            entryIndex,
            slotOut);
        break;
    default:
        // WDF_CALLBACKS describes compile-time addresses within the driver's .text section, which has no writable slots.
        return STATUS_INVALID_PARAMETER;
    }
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (slotOut->slotAddress == NULL) {
        RtlZeroMemory(slotOut, sizeof(*slotOut));
        return STATUS_INVALID_ADDRESS;
    }

    // If the section containing the slot lacks IMAGE_SCN_MEM_WRITE (e.g., the KMDF binding table resides in a read-only section), a direct CAS
    // will trigger bug check 0xBE. The submission path must instead use a writable MDL alias. If ownership cannot be determined, use the alias
    // path: the alias path is valid for writable pages, and if the address is truly invalid, the probe will throw an exception that gets caught.
    slotOwner = kswordArkHookFindModuleForAddress(
        moduleInfo,
        (ULONG_PTR)slotOut->slotAddress);
    slotOut->requiresWritableAlias = (BOOLEAN)(
        slotOwner == NULL ||
        !kswPlatformRangeInWritableDataSection(
            slotOwner,
            (ULONG_PTR)slotOut->slotAddress,
            sizeof(PVOID)));
    return STATUS_SUCCESS;
}

static VOID
kswPlatformLogControlResult(
    _In_ WDFDEVICE device,
    _In_ const KSWORD_ARK_CONTROL_PLATFORM_AUDIT_RESPONSE* response
    )
{
    CHAR message[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
    NTSTATUS status = STATUS_SUCCESS;

    if (response == NULL) {
        return;
    }
    status = RtlStringCbPrintfA(
        message,
        sizeof(message),
        "R0 platform slot edit: scope=0x%08lX index=%lu status=%lu nt=0x%08X "
        "table=0x%I64X slot=0x%I64X previous=0x%I64X "
        "requested=0x%I64X current=0x%I64X flags=0x%08lX.",
        response->scope,
        response->entryIndex,
        response->status,
        (unsigned int)response->lastStatus,
        response->tableAddress,
        response->slotAddress,
        response->previousValue,
        response->requestedValue,
        response->currentValue,
        response->responseFlags);
    if (NT_SUCCESS(status)) {
        (VOID)kswordArkDriverEnqueueLogFrame(
            device,
            response->status == KSWORD_ARK_PLATFORM_CONTROL_STATUS_OK ?
                "Warn" : "Error",
            message);
    }
}

NTSTATUS
kswordArkPlatformAuditIoctlControl(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
    const KSWORD_ARK_CONTROL_PLATFORM_AUDIT_REQUEST* input = NULL;
    KSWORD_ARK_CONTROL_PLATFORM_AUDIT_REQUEST requestSnapshot;
    KSWORD_ARK_CONTROL_PLATFORM_AUDIT_RESPONSE* response = NULL;
    KswHookSystemModuleInformation* moduleInfo = NULL;
    const KswHookSystemModuleEntry* targetOwner = NULL;
    KswPlatformEditSlot slot;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    PVOID previousValue = NULL;
    ULONG moduleInfoBytes = 0UL;
    ULONG majorVersion = 0UL;
    ULONG minorVersion = 0UL;
    ULONG buildNumber = 0UL;
    size_t actualInputBytes = 0U;
    size_t actualOutputBytes = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(requestSnapshot),
        &inputBuffer,
        &actualInputBytes);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    RtlCopyMemory(&requestSnapshot, inputBuffer, sizeof(requestSnapshot));
    input = &requestSnapshot;
    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(*response),
        &outputBuffer,
        &actualOutputBytes);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    UNREFERENCED_PARAMETER(actualInputBytes);
    UNREFERENCED_PARAMETER(actualOutputBytes);
    response = (KSWORD_ARK_CONTROL_PLATFORM_AUDIT_RESPONSE*)outputBuffer;
    RtlZeroMemory(response, sizeof(*response));
    response->size = sizeof(*response);
    response->version = KSWORD_ARK_PLATFORM_AUDIT_PROTOCOL_VERSION;
    response->scope = input->scope;
    response->entryIndex = input->entryIndex;
    response->requestedValue = input->newValue;
    response->status = KSWORD_ARK_PLATFORM_CONTROL_STATUS_INVALID_REQUEST;
    response->lastStatus = STATUS_INVALID_PARAMETER;
    *bytesReturned = sizeof(*response);

    if (input->size != sizeof(*input) ||
        input->version != KSWORD_ARK_PLATFORM_AUDIT_PROTOCOL_VERSION ||
        input->tableAddress == 0ULL ||
        input->newValue == 0ULL ||
        input->reserved0 != 0UL ||
        input->reserved1 != 0UL ||
        (input->flags & ~KSWORD_ARK_PLATFORM_CONTROL_FLAG_UI_CONFIRMED) != 0UL) {
        kswPlatformLogControlResult(device, response);
        return STATUS_SUCCESS;
    }
    if ((input->flags & KSWORD_ARK_PLATFORM_CONTROL_FLAG_UI_CONFIRMED) == 0UL ||
        input->confirmationToken !=
            KSWORD_ARK_PLATFORM_CONTROL_CONFIRMATION_TOKEN) {
        response->status =
            KSWORD_ARK_PLATFORM_CONTROL_STATUS_CONFIRMATION_REQUIRED;
        response->lastStatus = STATUS_REQUEST_NOT_ACCEPTED;
        kswPlatformLogControlResult(device, response);
        return STATUS_SUCCESS;
    }

    {
        KswordArkSafetyContext safetyContext = { 0 };
        safetyContext.operation = KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH;
        safetyContext.contextFlags =
            KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
        if (input->scope == KSWORD_ARK_PLATFORM_AUDIT_SCOPE_WDF_FUNCTIONS) {
            safetyContext.targetText = L"Validated KMDF binding table slot";
            safetyContext.targetTextChars = (USHORT)(
                RTL_NUMBER_OF(L"Validated KMDF binding table slot") - 1U);
        }
        else {
            safetyContext.targetText = L"Validated HAL function table slot";
            safetyContext.targetTextChars = (USHORT)(
                RTL_NUMBER_OF(L"Validated HAL function table slot") - 1U);
        }
        status = kswordArkSafetyEvaluate(device, &safetyContext);
        if (!NT_SUCCESS(status)) {
            response->status =
                KSWORD_ARK_PLATFORM_CONTROL_STATUS_SAFETY_DENIED;
            response->lastStatus = status;
            kswPlatformLogControlResult(device, response);
            return STATUS_SUCCESS;
        }
    }

    (VOID)PsGetVersion(&majorVersion, &minorVersion, &buildNumber, NULL);
    UNREFERENCED_PARAMETER(majorVersion);
    UNREFERENCED_PARAMETER(minorVersion);
    status = kswordArkHookBuildModuleSnapshot(&moduleInfo, &moduleInfoBytes);
    if (!NT_SUCCESS(status) || moduleInfo == NULL || moduleInfoBytes == 0UL) {
        response->status = KSWORD_ARK_PLATFORM_CONTROL_STATUS_UNSUPPORTED;
        response->lastStatus = NT_SUCCESS(status) ?
            STATUS_UNSUCCESSFUL : status;
        if (moduleInfo != NULL) {
            ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
        }
        kswPlatformLogControlResult(device, response);
        return STATUS_SUCCESS;
    }

    status = kswPlatformResolveEditableSlot(
        moduleInfo,
        buildNumber,
        input->scope,
        input->entryIndex,
        &slot);
    if (!NT_SUCCESS(status)) {
        response->status =
            status == STATUS_INVALID_PARAMETER ||
            status == STATUS_OBJECT_TYPE_MISMATCH ?
                KSWORD_ARK_PLATFORM_CONTROL_STATUS_INVALID_REQUEST :
                KSWORD_ARK_PLATFORM_CONTROL_STATUS_UNSUPPORTED;
        response->lastStatus = status;
        ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
        kswPlatformLogControlResult(device, response);
        return STATUS_SUCCESS;
    }
    response->tableAddress = (ULONGLONG)(ULONG_PTR)slot.tableAddress;
    response->slotAddress = (ULONGLONG)(ULONG_PTR)slot.slotAddress;
    response->previousValue = (ULONGLONG)(ULONG_PTR)slot.currentValue;
    response->currentValue = response->previousValue;
    response->responseFlags |=
        KSWORD_ARK_PLATFORM_CONTROL_RESPONSE_TABLE_REVALIDATED;

    if ((ULONGLONG)(ULONG_PTR)slot.tableAddress != input->tableAddress ||
        (ULONGLONG)(ULONG_PTR)slot.currentValue != input->expectedValue) {
        response->status =
            KSWORD_ARK_PLATFORM_CONTROL_STATUS_STALE_SNAPSHOT;
        response->lastStatus = STATUS_REVISION_MISMATCH;
        ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
        kswPlatformLogControlResult(device, response);
        return STATUS_SUCCESS;
    }

    targetOwner = kswordArkHookFindModuleForAddress(
        moduleInfo,
        (ULONG_PTR)input->newValue);
    if (targetOwner == NULL ||
        !kswPlatformAddressSectionMatches(
            targetOwner,
            (ULONG_PTR)input->newValue,
            TRUE)) {
        response->status =
            KSWORD_ARK_PLATFORM_CONTROL_STATUS_TARGET_INVALID;
        response->lastStatus = STATUS_INVALID_ADDRESS;
        ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
        kswPlatformLogControlResult(device, response);
        return STATUS_SUCCESS;
    }
    response->responseFlags |=
        KSWORD_ARK_PLATFORM_CONTROL_RESPONSE_TARGET_EXECUTABLE;

    if (input->newValue == input->expectedValue) {
        response->status = KSWORD_ARK_PLATFORM_CONTROL_STATUS_OK;
        response->lastStatus = STATUS_SUCCESS;
        ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
        kswPlatformLogControlResult(device, response);
        return STATUS_SUCCESS;
    }

    status = kswPlatformCommitEdit(
        input->scope,
        input->entryIndex,
        &slot,
        (PVOID)(ULONG_PTR)input->expectedValue,
        (PVOID)(ULONG_PTR)input->newValue,
        &previousValue);
    response->previousValue = (ULONGLONG)(ULONG_PTR)previousValue;
    response->currentValue = response->previousValue;
    if (status == STATUS_REVISION_MISMATCH ||
        status == STATUS_CONFLICTING_ADDRESSES) {
        response->status =
            KSWORD_ARK_PLATFORM_CONTROL_STATUS_STALE_SNAPSHOT;
        response->lastStatus = status;
    }
    else if (!NT_SUCCESS(status)) {
        response->status =
            KSWORD_ARK_PLATFORM_CONTROL_STATUS_WRITE_FAILED;
        response->lastStatus = status;
    }
    else {
        response->status = KSWORD_ARK_PLATFORM_CONTROL_STATUS_OK;
        response->lastStatus = STATUS_SUCCESS;
        response->currentValue = input->newValue;
        response->responseFlags |=
            KSWORD_ARK_PLATFORM_CONTROL_RESPONSE_CHANGED;
        if (slot.requiresWritableAlias) {
            response->responseFlags |=
                KSWORD_ARK_PLATFORM_CONTROL_RESPONSE_ALIAS_WRITE;
        }
    }

    ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
    kswPlatformLogControlResult(device, response);
    return STATUS_SUCCESS;
}
