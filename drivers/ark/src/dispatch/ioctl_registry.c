/*++

Module Name:

    ioctl_registry.c

Abstract:

    Static IOCTL registry for the KswordARK dispatch path.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ioctl_registry.h"
#include "ark/ark_ioctl.h"
#include "driver/KswordArkMutationIoctl.h"
#include "driver/KswordArkDeviceAuditIoctl.h"
#include "driver/KswordArkPlatformAuditIoctl.h"
#include "driver/KswordArkI8042AuditIoctl.h"
#include "driver/KswordArkHwidIoctl.h"
#include "driver/KswordArkProcessProtectIoctl.h"
#include "driver/KswordArkCallbackMonitorIoctl.h"
#include "driver/KswordArkHvmMetricsIoctl.h"
#include "driver/KswordArkDdmaIoctl.h"

// Feature handler declarations live here instead of in the central dispatch file.
NTSTATUS kswordArkKernelIoctlControlDriverDispatch(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkKernelIoctlControlDriverImage(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkProcessIoctlTerminate(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkProcessIoctlSuspend(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkProcessIoctlResume(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkProcessIoctlSetPplLevel(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkProcessIoctlSetIntegrity(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkProcessIoctlTokenPrivileges(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkProcessIoctlQueryTokenPrivileges(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkProcessIoctlAdjustTokenPrivilege(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkProcessIoctlEnumProcess(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkProcessIoctlSetVisibility(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkProcessIoctlSetSpecialFlags(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkProcessIoctlDkomProcess(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkProcessIoctlInjectProcess(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkThreadIoctlSetSuspended(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkThreadIoctlControlDriverThread(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkWorkQueueIoctlEnum(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkMemoryIoctlQueryVirtualMemory(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkMemoryIoctlReadVirtualMemory(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkMemoryIoctlWriteVirtualMemory(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkMemoryIoctlReadPhysicalMemory(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkMemoryIoctlWritePhysicalMemory(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkMemoryIoctlTranslateVirtualAddress(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkMemoryIoctlQueryPageTableEntry(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkMemoryIoctlScanKernelExecutableMemory(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkMemoryIoctlScanKernelMemoryEvidence(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkMemoryIoctlDdmaQueryCapability(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkMemoryIoctlDdmaReadPhysical(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkMemoryIoctlDdmaWritePhysical(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkFileIoctlDeletePath(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkFileIoctlQueryFileInfo(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkFileIoctlEnumDirectory(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkFileIoctlSetIntegrity(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkFileIrpIoctlEnumDirectory(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkFileIrpIoctlSubmit(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkFileMonitorIoctlControl(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkFileMonitorIoctlDrain(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkFileMonitorIoctlQueryStatus(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkKernelIoctlEnumSsdt(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkKernelIoctlQueryDriverObject(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkKernelIoctlControlIoTimer(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkKernelIoctlEnumShadowSsdt(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkKernelIoctlScanInlineHooks(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkKernelIoctlPatchInlineHook(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkKernelIoctlRestoreIdtBaseline(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkKernelIoctlQueryPiDdb(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkKernelIoctlDeletePiDdb(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkHvmIoctlQuery(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkHvmIoctlControl(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkKernelIoctlQuerySlatIommuAudit(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkSystemTimeIoctlQuery(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkSystemTimeIoctlControl(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkHvmIoctlEptRule(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkHvmIoctlMemory(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkHvmIoctlView(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkHvmIoctlMsrPolicy(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkHvmIoctlCrPolicy(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkHvmIoctlDomain(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkHvmIoctlPlatform(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkHvmIoctlProcess(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkHvmIoctlInject(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkHvmIoctlNestedProbe(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkHvmIoctlNestedPage(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkHvmIoctlMetrics(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkHvmIoctlEvents(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkKernelIoctlEnumIatEatHooks(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkKernelIoctlForceUnloadDriver(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkKernelIoctlControlDriverCommunication(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkKernelIoctlQueryDriverIntegrity(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkKernelIoctlQueryCpuHardware(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkKernelIoctlQueryPhysicalMemoryLayout(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkKernelIoctlQueryIoctlRegistry(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkKernelIoctlEnumTimerDpc(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkKernelIoctlExperimentalReturnToFirmware(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkKernelIoctlQueryUnloadedDrivers(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkCallbackIoctlSetRulesHandler(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkCallbackIoctlGetRuntimeStateHandler(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkCallbackIoctlWaitEventHandler(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkCallbackIoctlAnswerEventHandler(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkCallbackIoctlCancelAllPendingHandler(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkCallbackIoctlRemoveExternalCallbackHandler(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkBugcheckIoctlConfigureDiagnostics(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkCallbackIoctlRemoveExternalCallbackExHandler(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkCallbackIoctlEnumCallbacksHandler(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkCallbackIoctlSetMinifilterBypassPidsHandler(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkCallbackIoctlQueryMinifilterBypassPidsHandler(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkCallbackMonitorIoctlControl(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkCallbackMonitorIoctlQuery(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkCallbackMonitorIoctlRead(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkProcessProtectIoctlSetConfigHandler(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkProcessProtectIoctlQueryStateHandler(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkDynDataIoctlQueryStatus(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkDynDataIoctlQueryFields(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkDynDataIoctlQueryCapabilities(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkDynDataIoctlApplyProfile(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkDynDataIoctlApplyProfileEx(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkDynDataIoctlApplyProfileV4(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkDynDataIoctlQueryV4Modules(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkDynDataIoctlQueryV4CapabilityGroups(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkDynDataIoctlQueryV4MissingItems(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkDynDataIoctlQueryV4Items(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkCapabilityIoctlQueryDriverCapabilities(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkThreadIoctlEnumThread(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkThreadIoctlTerminate(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkProcessIoctlQueryCrossView(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkThreadIoctlQueryCrossView(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkProcessIoctlQueryDetail(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkProcessIoctlQueryRuntimeFields(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkThreadIoctlQueryDetail(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkThreadIoctlQueryRuntimeFields(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkHandleIoctlEnumProcessHandles(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkHandleIoctlQueryHandleObject(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkAlpcIoctlQueryAlpcPort(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkSectionIoctlQueryProcessSection(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkInjectionIoctlEnumerateProcessVad(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkInjectionIoctlScanExecutablePte(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkInjectionIoctlReadImageSectionPages(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkSectionIoctlQueryFileSectionMappings(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkWslSiloIoctlQuery(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkTrustIoctlQueryImageTrust(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkTrustIoctlQueryImageSignature(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkSafetyIoctlQueryPolicy(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkSafetyIoctlSetPolicy(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkPreflightIoctlQuery(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkRegistryIoctlReadValue(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkRegistryIoctlEnumKey(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkRegistryIoctlSetValue(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkRegistryIoctlDeleteValue(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkRegistryIoctlCreateKey(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkRegistryIoctlDeleteKey(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkRegistryIoctlRenameValue(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkRegistryIoctlRenameKey(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkRedirectIoctlSetRules(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkRedirectIoctlQueryStatus(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkNetworkIoctlSetRules(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkNetworkIoctlQueryStatus(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkNetworkIoctlQueryTcpEndpoints(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkNetworkIoctlQueryUdpEndpoints(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkNetworkIoctlQueryWfpInventory(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkNetworkIoctlQueryWfpEvents(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkNetworkIoctlQueryTrafficPackets(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkNetworkIoctlControlTrafficCapture(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkNetworkIoctlQueryNdisChain(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkKeyboardIoctlEnumHotkeys(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkKeyboardIoctlEnumHooks(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkKeyboardIoctlMutateHotkey(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkMutationIoctlPrepare(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkMutationIoctlCommit(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkMutationIoctlRollback(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkMutationIoctlQueryAudit(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkMinifilterIoctlQueryInventory(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkKernelObjectIoctlEnumCidTable(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkKernelObjectIoctlQueryObjectSummary(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkKernelObjectIoctlEnumTypeTable(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkKernelObjectIoctlQueryIpcSummary(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkStorageIoctlQueryVolumeStackAudit(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkStorageIoctlQueryBitLockerFveAudit(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkStorageIoctlQueryMountMgrMappingAudit(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkStorageIoctlQueryFileSystemIntegrityAudit(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkStorageIoctlQueryRawDiskBackend(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkStorageIoctlReadRawDisk(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkStorageIoctlWriteRawDisk(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkSecurityAuditIoctlQuerySecurityStatus(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkSecurityAuditIoctlQueryDriverTrustView(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkSecurityAuditIoctlQueryHyperVSummary(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkSecurityAuditIoctlQueryAppControlStatus(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkWin32kIoctlQueryProfileStatus(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkWindowBandIoctl(WDFDEVICE device, WDFREQUEST request, size_t inputBufferLength, size_t outputBufferLength, size_t* bytesReturned);
NTSTATUS kswordArkWin32kIoctlQueryWindows(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkWin32kIoctlQueryGuiThreads(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkWin32kIoctlQueryHotkeysPdb(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkWin32kIoctlQueryHooksPdb(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkWin32kIoctlQueryWindowDetail(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkWin32kIoctlQueryTimers(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkWin32kIoctlQueryEventHooks(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkDeviceAuditIoctlQueryDeviceStack(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkDeviceAuditIoctlQueryInputStack(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkDeviceAuditIoctlQueryUsbTopology(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkDeviceAuditIoctlQueryGpuDisplayWatchdog(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkPlatformAuditIoctlQuery(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkPlatformAuditIoctlControl(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkI8042AuditIoctlQuery(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkHwidIoctlQueryDispatch(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkHwidIoctlControlDispatch(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkCpuPowerIoctlQuery(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkCpuPowerIoctlControl(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkResearchIoctlQueryTopic(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkDebugOutputIoctlControl(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkDebugOutputIoctlDrain(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkBugcheckIoctlSetBitmap(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkBugcheckIoctlSetVerdictResources(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkBugcheckGuardIoctlConfigure(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS kswordArkBugcheckShieldIoctlConfigure(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS KswordARKRxpfIoctlQuerySupport(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS KswordARKRxpfIoctlRegisterPage(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS KswordARKRxpfIoctlChangePage(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS KswordARKRxpfIoctlQueryPage(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS KswordARKRxpfIoctlWritePage(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS KswordARKRxpfIoctlSetEmulation(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS KswordARKRxpfIoctlQueryStats(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS KswordARKRxpfIoctlDrainEvents(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS KswordARKRxpfIoctlUnregisterPage(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);
NTSTATUS KswordARKRxpfIoctlRunSelfTest(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned);

static const KswordArkIoctlEntry kGKswordArkIoctlTable[] = {
    { IOCTL_KSWORD_ARK_TERMINATE_PROCESS, kswordArkProcessIoctlTerminate, "IOCTL_KSWORD_ARK_TERMINATE_PROCESS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_SUSPEND_PROCESS, kswordArkProcessIoctlSuspend, "IOCTL_KSWORD_ARK_SUSPEND_PROCESS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_RESUME_PROCESS, kswordArkProcessIoctlResume, "IOCTL_KSWORD_ARK_RESUME_PROCESS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_SET_PPL_LEVEL, kswordArkProcessIoctlSetPplLevel, "IOCTL_KSWORD_ARK_SET_PPL_LEVEL", KSW_CAP_PROCESS_PROTECTION_PATCH, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_SET_PROCESS_INTEGRITY, kswordArkProcessIoctlSetIntegrity, "IOCTL_KSWORD_ARK_SET_PROCESS_INTEGRITY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_PROCESS_TOKEN_PRIVILEGES, kswordArkProcessIoctlTokenPrivileges, "IOCTL_KSWORD_ARK_PROCESS_TOKEN_PRIVILEGES", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_PROCESS_TOKEN_PRIVILEGES, kswordArkProcessIoctlQueryTokenPrivileges, "IOCTL_KSWORD_ARK_QUERY_PROCESS_TOKEN_PRIVILEGES", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    { IOCTL_KSWORD_ARK_ADJUST_PROCESS_TOKEN_PRIVILEGE, kswordArkProcessIoctlAdjustTokenPrivilege, "IOCTL_KSWORD_ARK_ADJUST_PROCESS_TOKEN_PRIVILEGE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_ENUM_PROCESS, kswordArkProcessIoctlEnumProcess, "IOCTL_KSWORD_ARK_ENUM_PROCESS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_SET_PROCESS_VISIBILITY, kswordArkProcessIoctlSetVisibility, "IOCTL_KSWORD_ARK_SET_PROCESS_VISIBILITY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_SET_PROCESS_SPECIAL_FLAGS, kswordArkProcessIoctlSetSpecialFlags, "IOCTL_KSWORD_ARK_SET_PROCESS_SPECIAL_FLAGS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_DKOM_PROCESS, kswordArkProcessIoctlDkomProcess, "IOCTL_KSWORD_ARK_DKOM_PROCESS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_INJECT_PROCESS, kswordArkProcessIoctlInjectProcess, "IOCTL_KSWORD_ARK_INJECT_PROCESS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_VIRTUAL_MEMORY, kswordArkMemoryIoctlQueryVirtualMemory, "IOCTL_KSWORD_ARK_QUERY_VIRTUAL_MEMORY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_READ_VIRTUAL_MEMORY, kswordArkMemoryIoctlReadVirtualMemory, "IOCTL_KSWORD_ARK_READ_VIRTUAL_MEMORY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_WRITE_VIRTUAL_MEMORY, kswordArkMemoryIoctlWriteVirtualMemory, "IOCTL_KSWORD_ARK_WRITE_VIRTUAL_MEMORY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_READ_PHYSICAL_MEMORY, kswordArkMemoryIoctlReadPhysicalMemory, "IOCTL_KSWORD_ARK_READ_PHYSICAL_MEMORY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_WRITE_PHYSICAL_MEMORY, kswordArkMemoryIoctlWritePhysicalMemory, "IOCTL_KSWORD_ARK_WRITE_PHYSICAL_MEMORY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS, kswordArkMemoryIoctlTranslateVirtualAddress, "IOCTL_KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY, kswordArkMemoryIoctlQueryPageTableEntry, "IOCTL_KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY, kswordArkMemoryIoctlScanKernelExecutableMemory, "IOCTL_KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE, kswordArkMemoryIoctlScanKernelMemoryEvidence, "IOCTL_KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_DDMA_QUERY_CAPABILITY, kswordArkMemoryIoctlDdmaQueryCapability, "IOCTL_KSWORD_ARK_DDMA_QUERY_CAPABILITY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_DDMA_READ_PHYSICAL, kswordArkMemoryIoctlDdmaReadPhysical, "IOCTL_KSWORD_ARK_DDMA_READ_PHYSICAL", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_DDMA_WRITE_PHYSICAL, kswordArkMemoryIoctlDdmaWritePhysical, "IOCTL_KSWORD_ARK_DDMA_WRITE_PHYSICAL", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_DELETE_PATH, kswordArkFileIoctlDeletePath, "IOCTL_KSWORD_ARK_DELETE_PATH", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_FILE_INFO, kswordArkFileIoctlQueryFileInfo, "IOCTL_KSWORD_ARK_QUERY_FILE_INFO", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_ENUM_DIRECTORY, kswordArkFileIoctlEnumDirectory, "IOCTL_KSWORD_ARK_ENUM_DIRECTORY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    { IOCTL_KSWORD_ARK_SET_FILE_INTEGRITY, kswordArkFileIoctlSetIntegrity, "IOCTL_KSWORD_ARK_SET_FILE_INTEGRITY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY, kswordArkFileIrpIoctlEnumDirectory, "IOCTL_KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    { IOCTL_KSWORD_ARK_FILE_IRP_SUBMIT, kswordArkFileIrpIoctlSubmit, "IOCTL_KSWORD_ARK_FILE_IRP_SUBMIT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_FILE_MONITOR_CONTROL, kswordArkFileMonitorIoctlControl, "IOCTL_KSWORD_ARK_FILE_MONITOR_CONTROL", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_FILE_MONITOR_DRAIN, kswordArkFileMonitorIoctlDrain, "IOCTL_KSWORD_ARK_FILE_MONITOR_DRAIN", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_FILE_MONITOR_QUERY_STATUS, kswordArkFileMonitorIoctlQueryStatus, "IOCTL_KSWORD_ARK_FILE_MONITOR_QUERY_STATUS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_ENUM_SSDT, kswordArkKernelIoctlEnumSsdt, "IOCTL_KSWORD_ARK_ENUM_SSDT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_DRIVER_OBJECT, kswordArkKernelIoctlQueryDriverObject, "IOCTL_KSWORD_ARK_QUERY_DRIVER_OBJECT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    { IOCTL_KSWORD_ARK_CONTROL_IO_TIMER, kswordArkKernelIoctlControlIoTimer, "IOCTL_KSWORD_ARK_CONTROL_IO_TIMER", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_ENUM_SHADOW_SSDT, kswordArkKernelIoctlEnumShadowSsdt, "IOCTL_KSWORD_ARK_ENUM_SHADOW_SSDT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_SCAN_INLINE_HOOKS, kswordArkKernelIoctlScanInlineHooks, "IOCTL_KSWORD_ARK_SCAN_INLINE_HOOKS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_PATCH_INLINE_HOOK, kswordArkKernelIoctlPatchInlineHook, "IOCTL_KSWORD_ARK_PATCH_INLINE_HOOK", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_RESTORE_IDT_BASELINE, kswordArkKernelIoctlRestoreIdtBaseline, "IOCTL_KSWORD_ARK_RESTORE_IDT_BASELINE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_PIDDB, kswordArkKernelIoctlQueryPiDdb, "IOCTL_KSWORD_ARK_QUERY_PIDDB", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_DELETE_PIDDB, kswordArkKernelIoctlDeletePiDdb, "IOCTL_KSWORD_ARK_DELETE_PIDDB", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_HVM, kswordArkHvmIoctlQuery, "IOCTL_KSWORD_ARK_QUERY_HVM", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_CONTROL_HVM, kswordArkHvmIoctlControl, "IOCTL_KSWORD_ARK_CONTROL_HVM", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT, kswordArkKernelIoctlQuerySlatIommuAudit, "IOCTL_KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    { IOCTL_KSWORD_ARK_QUERY_SYSTEM_TIME, kswordArkSystemTimeIoctlQuery, "IOCTL_KSWORD_ARK_QUERY_SYSTEM_TIME", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    { IOCTL_KSWORD_ARK_CONTROL_SYSTEM_TIME, kswordArkSystemTimeIoctlControl, "IOCTL_KSWORD_ARK_CONTROL_SYSTEM_TIME", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_HVM_EPT_RULE, kswordArkHvmIoctlEptRule, "IOCTL_KSWORD_ARK_HVM_EPT_RULE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_HVM_MEMORY, kswordArkHvmIoctlMemory, "IOCTL_KSWORD_ARK_HVM_MEMORY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_HVM_VIEW, kswordArkHvmIoctlView, "IOCTL_KSWORD_ARK_HVM_VIEW", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_HVM_MSR_POLICY, kswordArkHvmIoctlMsrPolicy, "IOCTL_KSWORD_ARK_HVM_MSR_POLICY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_HVM_CR_POLICY, kswordArkHvmIoctlCrPolicy, "IOCTL_KSWORD_ARK_HVM_CR_POLICY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_HVM_DOMAIN, kswordArkHvmIoctlDomain, "IOCTL_KSWORD_ARK_HVM_DOMAIN", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_HVM_PLATFORM, kswordArkHvmIoctlPlatform, "IOCTL_KSWORD_ARK_HVM_PLATFORM", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_HVM_PROCESS, kswordArkHvmIoctlProcess, "IOCTL_KSWORD_ARK_HVM_PROCESS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_HVM_INJECT, kswordArkHvmIoctlInject, "IOCTL_KSWORD_ARK_HVM_INJECT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_HVM_NESTED_PROBE, kswordArkHvmIoctlNestedProbe, "IOCTL_KSWORD_ARK_HVM_NESTED_PROBE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_HVM_NESTED_PAGE, kswordArkHvmIoctlNestedPage, "IOCTL_KSWORD_ARK_HVM_NESTED_PAGE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_HVM_METRICS, kswordArkHvmIoctlMetrics, "IOCTL_KSWORD_ARK_HVM_METRICS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    { IOCTL_KSWORD_ARK_HVM_EVENTS, kswordArkHvmIoctlEvents, "IOCTL_KSWORD_ARK_HVM_EVENTS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_ENUM_IAT_EAT_HOOKS, kswordArkKernelIoctlEnumIatEatHooks, "IOCTL_KSWORD_ARK_ENUM_IAT_EAT_HOOKS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_FORCE_UNLOAD_DRIVER, kswordArkKernelIoctlForceUnloadDriver, "IOCTL_KSWORD_ARK_FORCE_UNLOAD_DRIVER", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_CONTROL_DRIVER_COMMUNICATION, kswordArkKernelIoctlControlDriverCommunication, "IOCTL_KSWORD_ARK_CONTROL_DRIVER_COMMUNICATION", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    { IOCTL_KSWORD_ARK_CONTROL_DRIVER_DISPATCH, kswordArkKernelIoctlControlDriverDispatch, "IOCTL_KSWORD_ARK_CONTROL_DRIVER_DISPATCH", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_CONTROL_DRIVER_IMAGE, kswordArkKernelIoctlControlDriverImage, "IOCTL_KSWORD_ARK_CONTROL_DRIVER_IMAGE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_DRIVER_INTEGRITY, kswordArkKernelIoctlQueryDriverIntegrity, "IOCTL_KSWORD_ARK_QUERY_DRIVER_INTEGRITY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_CPU_HARDWARE, kswordArkKernelIoctlQueryCpuHardware, "IOCTL_KSWORD_ARK_QUERY_CPU_HARDWARE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    { IOCTL_KSWORD_ARK_QUERY_PHYSICAL_MEMORY_LAYOUT, kswordArkKernelIoctlQueryPhysicalMemoryLayout, "IOCTL_KSWORD_ARK_QUERY_PHYSICAL_MEMORY_LAYOUT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    { IOCTL_KSWORD_ARK_QUERY_IOCTL_REGISTRY, kswordArkKernelIoctlQueryIoctlRegistry, "IOCTL_KSWORD_ARK_QUERY_IOCTL_REGISTRY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    { IOCTL_KSWORD_ARK_ENUM_TIMER_DPC, kswordArkKernelIoctlEnumTimerDpc, "IOCTL_KSWORD_ARK_ENUM_TIMER_DPC", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    { IOCTL_KSWORD_ARK_EXPERIMENTAL_RETURN_TO_FIRMWARE, kswordArkKernelIoctlExperimentalReturnToFirmware, "IOCTL_KSWORD_ARK_EXPERIMENTAL_RETURN_TO_FIRMWARE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    // All three sources report DynData/PDB gaps, so the registry layer allows a degraded response to pass.
    { IOCTL_KSWORD_ARK_QUERY_UNLOADED_DRIVERS, kswordArkKernelIoctlQueryUnloadedDrivers, "IOCTL_KSWORD_ARK_QUERY_UNLOADED_DRIVERS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    { IOCTL_KSWORD_ARK_SET_CALLBACK_RULES, kswordArkCallbackIoctlSetRulesHandler, "IOCTL_KSWORD_ARK_SET_CALLBACK_RULES", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_GET_CALLBACK_RUNTIME_STATE, kswordArkCallbackIoctlGetRuntimeStateHandler, "IOCTL_KSWORD_ARK_GET_CALLBACK_RUNTIME_STATE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_WAIT_CALLBACK_EVENT, kswordArkCallbackIoctlWaitEventHandler, "IOCTL_KSWORD_ARK_WAIT_CALLBACK_EVENT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_ANSWER_CALLBACK_EVENT, kswordArkCallbackIoctlAnswerEventHandler, "IOCTL_KSWORD_ARK_ANSWER_CALLBACK_EVENT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_CANCEL_ALL_PENDING_DECISIONS, kswordArkCallbackIoctlCancelAllPendingHandler, "IOCTL_KSWORD_ARK_CANCEL_ALL_PENDING_DECISIONS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK, kswordArkCallbackIoctlRemoveExternalCallbackHandler, "IOCTL_KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX, kswordArkCallbackIoctlRemoveExternalCallbackExHandler, "IOCTL_KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_ENUM_CALLBACKS, kswordArkCallbackIoctlEnumCallbacksHandler, "IOCTL_KSWORD_ARK_ENUM_CALLBACKS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_SET_MINIFILTER_BYPASS_PIDS, kswordArkCallbackIoctlSetMinifilterBypassPidsHandler, "IOCTL_KSWORD_ARK_SET_MINIFILTER_BYPASS_PIDS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_MINIFILTER_BYPASS_PIDS, kswordArkCallbackIoctlQueryMinifilterBypassPidsHandler, "IOCTL_KSWORD_ARK_QUERY_MINIFILTER_BYPASS_PIDS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_CALLBACK_MONITOR_CONTROL, kswordArkCallbackMonitorIoctlControl, "IOCTL_KSWORD_ARK_CALLBACK_MONITOR_CONTROL", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_CALLBACK_MONITOR_QUERY, kswordArkCallbackMonitorIoctlQuery, "IOCTL_KSWORD_ARK_CALLBACK_MONITOR_QUERY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    { IOCTL_KSWORD_ARK_CALLBACK_MONITOR_READ, kswordArkCallbackMonitorIoctlRead, "IOCTL_KSWORD_ARK_CALLBACK_MONITOR_READ", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    // Process protection reuses the same object callback; configuration updates are handled as 'callback behavior changes', while queries are read-only.
    { IOCTL_KSWORD_ARK_SET_PROCESS_PROTECT_CONFIG, kswordArkProcessProtectIoctlSetConfigHandler, "IOCTL_KSWORD_ARK_SET_PROCESS_PROTECT_CONFIG", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_PROCESS_PROTECT_STATE, kswordArkProcessProtectIoctlQueryStateHandler, "IOCTL_KSWORD_ARK_QUERY_PROCESS_PROTECT_STATE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    // Knowledge center read-only evidence orchestration: query only the central registry and collect the current WDF/WDM context.
    { IOCTL_KSWORD_ARK_QUERY_RESEARCH_TOPIC, kswordArkResearchIoctlQueryTopic, "IOCTL_KSWORD_ARK_QUERY_RESEARCH_TOPIC", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    { IOCTL_KSWORD_ARK_QUERY_DYN_STATUS, kswordArkDynDataIoctlQueryStatus, "IOCTL_KSWORD_ARK_QUERY_DYN_STATUS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_DYN_FIELDS, kswordArkDynDataIoctlQueryFields, "IOCTL_KSWORD_ARK_QUERY_DYN_FIELDS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_CAPABILITIES, kswordArkDynDataIoctlQueryCapabilities, "IOCTL_KSWORD_ARK_QUERY_CAPABILITIES", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_APPLY_DYN_PROFILE, kswordArkDynDataIoctlApplyProfile, "IOCTL_KSWORD_ARK_APPLY_DYN_PROFILE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_APPLY_DYN_PROFILE_EX, kswordArkDynDataIoctlApplyProfileEx, "IOCTL_KSWORD_ARK_APPLY_DYN_PROFILE_EX", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_APPLY_DYN_PROFILE_V4, kswordArkDynDataIoctlApplyProfileV4, "IOCTL_KSWORD_ARK_APPLY_DYN_PROFILE_V4", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_DYN_V4_MODULES, kswordArkDynDataIoctlQueryV4Modules, "IOCTL_KSWORD_ARK_QUERY_DYN_V4_MODULES", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_DYN_V4_CAPABILITY_GROUPS, kswordArkDynDataIoctlQueryV4CapabilityGroups, "IOCTL_KSWORD_ARK_QUERY_DYN_V4_CAPABILITY_GROUPS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_DYN_V4_MISSING_ITEMS, kswordArkDynDataIoctlQueryV4MissingItems, "IOCTL_KSWORD_ARK_QUERY_DYN_V4_MISSING_ITEMS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_DYN_V4_ITEMS, kswordArkDynDataIoctlQueryV4Items, "IOCTL_KSWORD_ARK_QUERY_DYN_V4_ITEMS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_DRIVER_CAPABILITIES, kswordArkCapabilityIoctlQueryDriverCapabilities, "IOCTL_KSWORD_ARK_QUERY_DRIVER_CAPABILITIES", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_ENUM_THREAD, kswordArkThreadIoctlEnumThread, "IOCTL_KSWORD_ARK_ENUM_THREAD", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_TERMINATE_THREAD, kswordArkThreadIoctlTerminate, "IOCTL_KSWORD_ARK_TERMINATE_THREAD", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_SET_THREAD_SUSPENDED, kswordArkThreadIoctlSetSuspended, "IOCTL_KSWORD_ARK_SET_THREAD_SUSPENDED", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_CONTROL_DRIVER_THREAD, kswordArkThreadIoctlControlDriverThread, "IOCTL_KSWORD_ARK_CONTROL_DRIVER_THREAD", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    // Work-queue enumeration is read-only and reports identity/layout gaps in its fixed response.
    { IOCTL_KSWORD_ARK_ENUM_WORK_QUEUE, kswordArkWorkQueueIoctlEnum, "IOCTL_KSWORD_ARK_ENUM_WORK_QUEUE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    // Process cross-view performs its own per-source capability checks, so dispatch must allow degraded read-only results.
    { IOCTL_KSWORD_ARK_QUERY_PROCESS_CROSSVIEW, kswordArkProcessIoctlQueryCrossView, "IOCTL_KSWORD_ARK_QUERY_PROCESS_CROSSVIEW", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    // Thread cross-view performs its own per-source capability checks, so dispatch must allow degraded read-only results.
    { IOCTL_KSWORD_ARK_QUERY_THREAD_CROSSVIEW, kswordArkThreadIoctlQueryCrossView, "IOCTL_KSWORD_ARK_QUERY_THREAD_CROSSVIEW", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    // Process detail is read-only and reports missing PDB/DynData fields inside the fixed response.
    { IOCTL_KSWORD_ARK_QUERY_PROCESS_DETAIL, kswordArkProcessIoctlQueryDetail, "IOCTL_KSWORD_ARK_QUERY_PROCESS_DETAIL", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    // Process runtime field sample is read-only and samples only bounded fields from PsLookupProcessByProcessId.
    { IOCTL_KSWORD_ARK_QUERY_PROCESS_RUNTIME_FIELDS, kswordArkProcessIoctlQueryRuntimeFields, "IOCTL_KSWORD_ARK_QUERY_PROCESS_RUNTIME_FIELDS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    // Thread detail is read-only and reports missing PDB/DynData fields inside the fixed response.
    { IOCTL_KSWORD_ARK_QUERY_THREAD_DETAIL, kswordArkThreadIoctlQueryDetail, "IOCTL_KSWORD_ARK_QUERY_THREAD_DETAIL", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    // Thread runtime field sample is read-only and samples only bounded fields from PsLookupThreadByThreadId.
    { IOCTL_KSWORD_ARK_QUERY_THREAD_RUNTIME_FIELDS, kswordArkThreadIoctlQueryRuntimeFields, "IOCTL_KSWORD_ARK_QUERY_THREAD_RUNTIME_FIELDS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    // Handle/object/ALPC queries own their public-API and runtime-signature fallback paths.
    // Handle occupancy scans issue these IOCTLs at process/handle granularity.
    // Their handlers keep validation and failure logs; dispatch success records
    // are redundant and can evict the real diagnostic lines from the log ring.
    { IOCTL_KSWORD_ARK_ENUM_PROCESS_HANDLES, kswordArkHandleIoctlEnumProcessHandles, "IOCTL_KSWORD_ARK_ENUM_PROCESS_HANDLES", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS | KSWORD_ARK_IOCTL_FLAG_QUIET_INVALID_CID },
    { IOCTL_KSWORD_ARK_QUERY_HANDLE_OBJECT, kswordArkHandleIoctlQueryHandleObject, "IOCTL_KSWORD_ARK_QUERY_HANDLE_OBJECT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    { IOCTL_KSWORD_ARK_QUERY_ALPC_PORT, kswordArkAlpcIoctlQueryAlpcPort, "IOCTL_KSWORD_ARK_QUERY_ALPC_PORT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    // Section queries return public FILE_OBJECT/ControlArea evidence even when private mapping offsets are absent.
    { IOCTL_KSWORD_ARK_QUERY_PROCESS_SECTION, kswordArkSectionIoctlQueryProcessSection, "IOCTL_KSWORD_ARK_QUERY_PROCESS_SECTION", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_ENUMERATE_PROCESS_VAD, kswordArkInjectionIoctlEnumerateProcessVad, "IOCTL_KSWORD_ARK_ENUMERATE_PROCESS_VAD", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_SCAN_PROCESS_EXECUTABLE_PTE, kswordArkInjectionIoctlScanExecutablePte, "IOCTL_KSWORD_ARK_SCAN_PROCESS_EXECUTABLE_PTE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_READ_IMAGE_SECTION_PAGES, kswordArkInjectionIoctlReadImageSectionPages, "IOCTL_KSWORD_ARK_READ_IMAGE_SECTION_PAGES", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_FILE_SECTION_MAPPINGS, kswordArkSectionIoctlQueryFileSectionMappings, "IOCTL_KSWORD_ARK_QUERY_FILE_SECTION_MAPPINGS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_WSL_SILO, kswordArkWslSiloIoctlQuery, "IOCTL_KSWORD_ARK_QUERY_WSL_SILO", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_IMAGE_TRUST, kswordArkTrustIoctlQueryImageTrust, "IOCTL_KSWORD_ARK_QUERY_IMAGE_TRUST", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_IMAGE_SIGNATURE, kswordArkTrustIoctlQueryImageSignature, "IOCTL_KSWORD_ARK_QUERY_IMAGE_SIGNATURE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_SAFETY_POLICY, kswordArkSafetyIoctlQueryPolicy, "IOCTL_KSWORD_ARK_QUERY_SAFETY_POLICY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_SET_SAFETY_POLICY, kswordArkSafetyIoctlSetPolicy, "IOCTL_KSWORD_ARK_SET_SAFETY_POLICY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_PREFLIGHT, kswordArkPreflightIoctlQuery, "IOCTL_KSWORD_ARK_QUERY_PREFLIGHT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_READ_REGISTRY_VALUE, kswordArkRegistryIoctlReadValue, "IOCTL_KSWORD_ARK_READ_REGISTRY_VALUE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_ENUM_REGISTRY_KEY, kswordArkRegistryIoctlEnumKey, "IOCTL_KSWORD_ARK_ENUM_REGISTRY_KEY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_SET_REGISTRY_VALUE, kswordArkRegistryIoctlSetValue, "IOCTL_KSWORD_ARK_SET_REGISTRY_VALUE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_DELETE_REGISTRY_VALUE, kswordArkRegistryIoctlDeleteValue, "IOCTL_KSWORD_ARK_DELETE_REGISTRY_VALUE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_CREATE_REGISTRY_KEY, kswordArkRegistryIoctlCreateKey, "IOCTL_KSWORD_ARK_CREATE_REGISTRY_KEY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_DELETE_REGISTRY_KEY, kswordArkRegistryIoctlDeleteKey, "IOCTL_KSWORD_ARK_DELETE_REGISTRY_KEY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_RENAME_REGISTRY_VALUE, kswordArkRegistryIoctlRenameValue, "IOCTL_KSWORD_ARK_RENAME_REGISTRY_VALUE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_RENAME_REGISTRY_KEY, kswordArkRegistryIoctlRenameKey, "IOCTL_KSWORD_ARK_RENAME_REGISTRY_KEY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_REDIRECT_SET_RULES, kswordArkRedirectIoctlSetRules, "IOCTL_KSWORD_ARK_REDIRECT_SET_RULES", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_REDIRECT_QUERY_STATUS, kswordArkRedirectIoctlQueryStatus, "IOCTL_KSWORD_ARK_REDIRECT_QUERY_STATUS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_NETWORK_SET_RULES, kswordArkNetworkIoctlSetRules, "IOCTL_KSWORD_ARK_NETWORK_SET_RULES", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_NETWORK_QUERY_STATUS, kswordArkNetworkIoctlQueryStatus, "IOCTL_KSWORD_ARK_NETWORK_QUERY_STATUS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_NETWORK_QUERY_TCP_ENDPOINTS, kswordArkNetworkIoctlQueryTcpEndpoints, "IOCTL_KSWORD_ARK_NETWORK_QUERY_TCP_ENDPOINTS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_NETWORK_QUERY_UDP_ENDPOINTS, kswordArkNetworkIoctlQueryUdpEndpoints, "IOCTL_KSWORD_ARK_NETWORK_QUERY_UDP_ENDPOINTS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_NETWORK_QUERY_WFP_INVENTORY, kswordArkNetworkIoctlQueryWfpInventory, "IOCTL_KSWORD_ARK_NETWORK_QUERY_WFP_INVENTORY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_NETWORK_QUERY_WFP_EVENTS, kswordArkNetworkIoctlQueryWfpEvents, "IOCTL_KSWORD_ARK_NETWORK_QUERY_WFP_EVENTS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_NETWORK_QUERY_TRAFFIC_PACKETS, kswordArkNetworkIoctlQueryTrafficPackets, "IOCTL_KSWORD_ARK_NETWORK_QUERY_TRAFFIC_PACKETS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_NETWORK_CONTROL_TRAFFIC_CAPTURE, kswordArkNetworkIoctlControlTrafficCapture, "IOCTL_KSWORD_ARK_NETWORK_CONTROL_TRAFFIC_CAPTURE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_NETWORK_QUERY_NDIS_CHAIN, kswordArkNetworkIoctlQueryNdisChain, "IOCTL_KSWORD_ARK_NETWORK_QUERY_NDIS_CHAIN", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_ENUM_KEYBOARD_HOTKEYS, kswordArkKeyboardIoctlEnumHotkeys, "IOCTL_KSWORD_ARK_ENUM_KEYBOARD_HOTKEYS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_ENUM_KEYBOARD_HOOKS, kswordArkKeyboardIoctlEnumHooks, "IOCTL_KSWORD_ARK_ENUM_KEYBOARD_HOOKS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_MUTATE_KEYBOARD_HOTKEY, kswordArkKeyboardIoctlMutateHotkey, "IOCTL_KSWORD_ARK_MUTATE_KEYBOARD_HOTKEY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_MUTATION_PREPARE, kswordArkMutationIoctlPrepare, "IOCTL_KSWORD_ARK_MUTATION_PREPARE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_MUTATION_COMMIT, kswordArkMutationIoctlCommit, "IOCTL_KSWORD_ARK_MUTATION_COMMIT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_MUTATION_ROLLBACK, kswordArkMutationIoctlRollback, "IOCTL_KSWORD_ARK_MUTATION_ROLLBACK", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_MUTATION_QUERY_AUDIT, kswordArkMutationIoctlQueryAudit, "IOCTL_KSWORD_ARK_MUTATION_QUERY_AUDIT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_MINIFILTER_INVENTORY, kswordArkMinifilterIoctlQueryInventory, "IOCTL_KSWORD_ARK_QUERY_MINIFILTER_INVENTORY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_ENUM_CID_TABLE, kswordArkKernelObjectIoctlEnumCidTable, "IOCTL_KSWORD_ARK_ENUM_CID_TABLE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_KERNEL_OBJECT_SUMMARY, kswordArkKernelObjectIoctlQueryObjectSummary, "IOCTL_KSWORD_ARK_QUERY_KERNEL_OBJECT_SUMMARY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_ENUM_OBJECT_TYPE_TABLE, kswordArkKernelObjectIoctlEnumTypeTable, "IOCTL_KSWORD_ARK_ENUM_OBJECT_TYPE_TABLE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_IPC_SUMMARY, kswordArkKernelObjectIoctlQueryIpcSummary, "IOCTL_KSWORD_ARK_QUERY_IPC_SUMMARY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_VOLUME_STACK_AUDIT, kswordArkStorageIoctlQueryVolumeStackAudit, "IOCTL_KSWORD_ARK_QUERY_VOLUME_STACK_AUDIT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_BITLOCKER_FVE_AUDIT, kswordArkStorageIoctlQueryBitLockerFveAudit, "IOCTL_KSWORD_ARK_QUERY_BITLOCKER_FVE_AUDIT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_MOUNTMGR_MAPPING_AUDIT, kswordArkStorageIoctlQueryMountMgrMappingAudit, "IOCTL_KSWORD_ARK_QUERY_MOUNTMGR_MAPPING_AUDIT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_FILESYSTEM_INTEGRITY_AUDIT, kswordArkStorageIoctlQueryFileSystemIntegrityAudit, "IOCTL_KSWORD_ARK_QUERY_FILESYSTEM_INTEGRITY_AUDIT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_RAW_DISK_BACKEND, kswordArkStorageIoctlQueryRawDiskBackend, "IOCTL_KSWORD_ARK_QUERY_RAW_DISK_BACKEND", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    { IOCTL_KSWORD_ARK_READ_RAW_DISK, kswordArkStorageIoctlReadRawDisk, "IOCTL_KSWORD_ARK_READ_RAW_DISK", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    { IOCTL_KSWORD_ARK_WRITE_RAW_DISK, kswordArkStorageIoctlWriteRawDisk, "IOCTL_KSWORD_ARK_WRITE_RAW_DISK", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_SECURITY_STATUS, kswordArkSecurityAuditIoctlQuerySecurityStatus, "IOCTL_KSWORD_ARK_QUERY_SECURITY_STATUS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_DRIVER_TRUST_VIEW, kswordArkSecurityAuditIoctlQueryDriverTrustView, "IOCTL_KSWORD_ARK_QUERY_DRIVER_TRUST_VIEW", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_HYPERV_SUMMARY, kswordArkSecurityAuditIoctlQueryHyperVSummary, "IOCTL_KSWORD_ARK_QUERY_HYPERV_SUMMARY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_APP_CONTROL_STATUS, kswordArkSecurityAuditIoctlQueryAppControlStatus, "IOCTL_KSWORD_ARK_QUERY_APP_CONTROL_STATUS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_WIN32K_PROFILE_STATUS, kswordArkWin32kIoctlQueryProfileStatus, "IOCTL_KSWORD_ARK_QUERY_WIN32K_PROFILE_STATUS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_WINDOW_BAND, kswordArkWindowBandIoctl, "IOCTL_KSWORD_ARK_WINDOW_BAND", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_WIN32K_WINDOWS, kswordArkWin32kIoctlQueryWindows, "IOCTL_KSWORD_ARK_QUERY_WIN32K_WINDOWS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_WIN32K_GUI_THREADS, kswordArkWin32kIoctlQueryGuiThreads, "IOCTL_KSWORD_ARK_QUERY_WIN32K_GUI_THREADS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_WIN32K_HOTKEYS_PDB, kswordArkWin32kIoctlQueryHotkeysPdb, "IOCTL_KSWORD_ARK_QUERY_WIN32K_HOTKEYS_PDB", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_WIN32K_HOOKS_PDB, kswordArkWin32kIoctlQueryHooksPdb, "IOCTL_KSWORD_ARK_QUERY_WIN32K_HOOKS_PDB", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_WIN32K_WINDOW_DETAIL, kswordArkWin32kIoctlQueryWindowDetail, "IOCTL_KSWORD_ARK_QUERY_WIN32K_WINDOW_DETAIL", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_WIN32K_TIMERS, kswordArkWin32kIoctlQueryTimers, "IOCTL_KSWORD_ARK_QUERY_WIN32K_TIMERS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_WIN32K_EVENT_HOOKS, kswordArkWin32kIoctlQueryEventHooks, "IOCTL_KSWORD_ARK_QUERY_WIN32K_EVENT_HOOKS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_DEVICE_STACK_AUDIT, kswordArkDeviceAuditIoctlQueryDeviceStack, "IOCTL_KSWORD_ARK_QUERY_DEVICE_STACK_AUDIT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_INPUT_STACK_AUDIT, kswordArkDeviceAuditIoctlQueryInputStack, "IOCTL_KSWORD_ARK_QUERY_INPUT_STACK_AUDIT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_USB_TOPOLOGY_AUDIT, kswordArkDeviceAuditIoctlQueryUsbTopology, "IOCTL_KSWORD_ARK_QUERY_USB_TOPOLOGY_AUDIT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_GPU_DISPLAY_WATCHDOG_AUDIT, kswordArkDeviceAuditIoctlQueryGpuDisplayWatchdog, "IOCTL_KSWORD_ARK_QUERY_GPU_DISPLAY_WATCHDOG_AUDIT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    // HAL/WDF query returns evidence verified via export, boundary, and structural signatures; HAL edits
    // are handled by a separate FILE_WRITE_ACCESS IOCTL to relocate slots and perform snapshot CAS.
    { IOCTL_KSWORD_ARK_QUERY_PLATFORM_AUDIT, kswordArkPlatformAuditIoctlQuery, "IOCTL_KSWORD_ARK_QUERY_PLATFORM_AUDIT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_CONTROL_PLATFORM_AUDIT, kswordArkPlatformAuditIoctlControl, "IOCTL_KSWORD_ARK_CONTROL_PLATFORM_AUDIT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    // i8042prt auditing reads the endpoint address only after an exact image/descriptor match, without reading input data.
    { IOCTL_KSWORD_ARK_QUERY_I8042_AUDIT, kswordArkI8042AuditIoctlQuery, "IOCTL_KSWORD_ARK_QUERY_I8042_AUDIT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    // Debug output polling frequency is high; the success path remains silent to avoid unnecessarily amplifying driver-internal logs.
    { IOCTL_KSWORD_ARK_DEBUG_OUTPUT_CONTROL, kswordArkDebugOutputIoctlControl, "IOCTL_KSWORD_ARK_DEBUG_OUTPUT_CONTROL", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_DEBUG_OUTPUT_DRAIN, kswordArkDebugOutputIoctlDrain, "IOCTL_KSWORD_ARK_DEBUG_OUTPUT_DRAIN", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    { IOCTL_KSWORD_ARK_HWID_DISPATCH_QUERY, kswordArkHwidIoctlQueryDispatch, "IOCTL_KSWORD_ARK_HWID_DISPATCH_QUERY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_HWID_DISPATCH_CONTROL, kswordArkHwidIoctlControlDispatch, "IOCTL_KSWORD_ARK_HWID_DISPATCH_CONTROL", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_CPU_POWER, kswordArkCpuPowerIoctlQuery, "IOCTL_KSWORD_ARK_QUERY_CPU_POWER", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    { IOCTL_KSWORD_ARK_CONTROL_CPU_POWER, kswordArkCpuPowerIoctlControl, "IOCTL_KSWORD_ARK_CONTROL_CPU_POWER", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    // BGP scanning and BugCheck callbacks are installed only upon explicit R3 request to prevent private field probing triggered by ordinary driver startup.
    { IOCTL_KSWORD_ARK_CONFIGURE_BUGCHECK_DIAGNOSTICS, kswordArkBugcheckIoctlConfigureDiagnostics, "IOCTL_KSWORD_ARK_CONFIGURE_BUGCHECK_DIAGNOSTICS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_SET_BUGCHECK_BITMAP, kswordArkBugcheckIoctlSetBitmap, "IOCTL_KSWORD_ARK_SET_BUGCHECK_BITMAP", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_COMPLETION },
    { IOCTL_KSWORD_ARK_SET_BUGCHECK_VERDICT_RESOURCES, kswordArkBugcheckIoctlSetVerdictResources, "IOCTL_KSWORD_ARK_SET_BUGCHECK_VERDICT_RESOURCES", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_COMPLETION },
    { IOCTL_KSWORD_ARK_CONFIGURE_BUGCHECK_GUARD, kswordArkBugcheckGuardIoctlConfigure, "IOCTL_KSWORD_ARK_CONFIGURE_BUGCHECK_GUARD", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    // The Shield only uses the public BugCheck callback and never modifies private kernel state; enabling requires explicit confirmation from the UI.
    { IOCTL_KSWORD_ARK_CONFIGURE_BUGCHECK_SHIELD, kswordArkBugcheckShieldIoctlConfigure, "IOCTL_KSWORD_ARK_CONFIGURE_BUGCHECK_SHIELD", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    // RXPF owns its exact-build, write-access, confirmation-token and safety-policy gates.
    { IOCTL_KSWORD_ARK_RXPF_QUERY_SUPPORT, KswordARKRxpfIoctlQuerySupport, "IOCTL_KSWORD_ARK_RXPF_QUERY_SUPPORT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_RXPF_REGISTER_PAGE, KswordARKRxpfIoctlRegisterPage, "IOCTL_KSWORD_ARK_RXPF_REGISTER_PAGE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_RXPF_CHANGE_PAGE, KswordARKRxpfIoctlChangePage, "IOCTL_KSWORD_ARK_RXPF_CHANGE_PAGE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_RXPF_QUERY_PAGE, KswordARKRxpfIoctlQueryPage, "IOCTL_KSWORD_ARK_RXPF_QUERY_PAGE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_RXPF_WRITE_PAGE, KswordARKRxpfIoctlWritePage, "IOCTL_KSWORD_ARK_RXPF_WRITE_PAGE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_RXPF_SET_EMULATION, KswordARKRxpfIoctlSetEmulation, "IOCTL_KSWORD_ARK_RXPF_SET_EMULATION", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_RXPF_QUERY_STATS, KswordARKRxpfIoctlQueryStats, "IOCTL_KSWORD_ARK_RXPF_QUERY_STATS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    { IOCTL_KSWORD_ARK_RXPF_DRAIN_EVENTS, KswordARKRxpfIoctlDrainEvents, "IOCTL_KSWORD_ARK_RXPF_DRAIN_EVENTS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    { IOCTL_KSWORD_ARK_RXPF_UNREGISTER_PAGE, KswordARKRxpfIoctlUnregisterPage, "IOCTL_KSWORD_ARK_RXPF_UNREGISTER_PAGE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_RXPF_RUN_SELF_TEST, KswordARKRxpfIoctlRunSelfTest, "IOCTL_KSWORD_ARK_RXPF_RUN_SELF_TEST", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE }
};

_Must_inspect_result_
const KswordArkIoctlEntry*
kswordArkLookupIoctlEntry(
    _In_ ULONG ioControlCode
    )
/*++

Routine Description:

    Locate the registered IOCTL entry for the supplied control code. The table is
    exact-match only so unsupported IOCTLs fail closed.

Arguments:

    IoControlCode - Control code received by the queue dispatch callback.

Return Value:

    Pointer to a registry entry when found; NULL when unsupported.

--*/
{
    ULONG entryIndex = 0;

    for (entryIndex = 0; entryIndex < (sizeof(kGKswordArkIoctlTable) / sizeof(kGKswordArkIoctlTable[0])); ++entryIndex) {
        if (kGKswordArkIoctlTable[entryIndex].ioControlCode == ioControlCode) {
            return &kGKswordArkIoctlTable[entryIndex];
        }
    }

    return NULL;
}

ULONG
kswordArkGetRegisteredIoctlCount(
    VOID
    )
/*++

Routine Description:

    Returns the count of current IOCTL registry entries. Note: Phase-16 preflight uses this value to
    verify if the registry is enumerable, avoiding R3 guessing the driver's supported feature set.

Arguments:

    None.

Return Value:

    Number of elements in g_KswordArkIoctlTable.

--*/
{
    return (ULONG)(sizeof(kGKswordArkIoctlTable) / sizeof(kGKswordArkIoctlTable[0]));
}

ULONG
kswordArkGetDuplicateIoctlCount(
    VOID
    )
/*++

Routine Description:

    Check the count of duplicate control codes in the IOCTL registry. Note: Duplicate registration causes subsequent
    handlers to become permanently unreachable, which is a structural issue that must be exposed before release.

Arguments:

    None.

Return Value:

    Duplicate count; 0 indicates no duplicates.

--*/
{
    ULONG duplicateCount = 0UL;
    ULONG outerIndex = 0UL;
    ULONG innerIndex = 0UL;
    const ULONG kTotalCount = kswordArkGetRegisteredIoctlCount();

    for (outerIndex = 0UL; outerIndex < kTotalCount; ++outerIndex) {
        for (innerIndex = outerIndex + 1UL; innerIndex < kTotalCount; ++innerIndex) {
            if (kGKswordArkIoctlTable[outerIndex].ioControlCode ==
                kGKswordArkIoctlTable[innerIndex].ioControlCode) {
                duplicateCount += 1UL;
            }
        }
    }

    return duplicateCount;
}

// Note: Export static registry entries by index; return NULL on out-of-bounds access.
_Must_inspect_result_
const KswordArkIoctlEntry*
kswordArkGetIoctlEntryByIndex(
    _In_ ULONG index
    )
/*++

Routine Description:

    Note: Read-only return of registry entries without copying or modifying the static table.

Arguments:

    Index: registry array index.

Return Value:

    Returns the address of the item at the valid index; returns NULL if out of bounds.

--*/
{
    // Note: Retrieve the fixed array length first to prevent out-of-bounds access by the caller.
    const ULONG kTotalCount = kswordArkGetRegisteredIoctlCount();

    // Note: Reject out-of-bounds indices to keep registry queries as read-only safe operations.
    if (index >= kTotalCount) {
        return NULL;
    }

    // Note: Return address of a read-only item in the static array.
    return &kGKswordArkIoctlTable[index];
}
