#pragma once

#include <ntddk.h>

#include "driver/KswordArkKernelIoctl.h"
#include "driver/KswordArkDriverBlindIoctl.h"
#include "driver/KswordArkDriverDispatchIoctl.h"
#include "driver/KswordArkDriverImageEditorIoctl.h"
#include "driver/KswordArkSlatIommuAuditIoctl.h"

EXTERN_C_START

#define KSW_DRIVER_UNLOAD_DIAG_STAGE_REFERENCE     0x00000001UL
#define KSW_DRIVER_UNLOAD_DIAG_STAGE_PREFLIGHT     0x00000002UL
#define KSW_DRIVER_UNLOAD_DIAG_STAGE_ZW            0x00000004UL
#define KSW_DRIVER_UNLOAD_DIAG_STAGE_ZW_VERIFY     0x00000008UL
#define KSW_DRIVER_UNLOAD_DIAG_STAGE_DIRECT        0x00000010UL
#define KSW_DRIVER_UNLOAD_DIAG_STAGE_DIRECT_VERIFY 0x00000020UL

typedef struct KswDriverUnloadDiagnostics
{
    ULONG stages;
    ULONG requestedFlags;
    ULONG sanitizedFlags;
    ULONG finalFlags;
    NTSTATUS referenceStatus;
    NTSTATUS preflightBuildStatus;
    NTSTATUS preflightStatus;
    NTSTATUS preflightDenyStatus;
    NTSTATUS zwRunStatus;
    NTSTATUS zwWaitStatus;
    NTSTATUS zwUnloadStatus;
    NTSTATUS zwVerifyStatus;
    NTSTATUS directRunStatus;
    NTSTATUS directWaitStatus;
    NTSTATUS directUnloadStatus;
    NTSTATUS directCleanupStatus;
    NTSTATUS directVerifyStatus;
    BOOLEAN allowZwUnload;
    BOOLEAN allowDirectUnload;
    BOOLEAN allowDestructiveCleanup;
    BOOLEAN hasServiceRegistryPath;
    BOOLEAN hasDriverUnload;
    BOOLEAN hasValidDynData;
    BOOLEAN hasPdbBackedDynData;
    BOOLEAN hasValidDriverObjectOffsets;
    BOOLEAN hasValidLoaderEvidence;
    BOOLEAN hasDeviceChain;
    BOOLEAN hasCrossDriverAttach;
    BOOLEAN hasDeviceLoop;
    BOOLEAN hasAttachedDevice;
    BOOLEAN hasBusyDeviceReference;
    BOOLEAN hasThreadScan;
    BOOLEAN hasModuleResidentThreads;
    BOOLEAN hasCallbackScan;
    BOOLEAN hasModuleCallbacks;
    BOOLEAN hasNonRemovableModuleCallbacks;
    BOOLEAN hasLoaderLinkCheck;
    BOOLEAN hasLoaderLinkMismatch;
    BOOLEAN hasImageHeaderCheck;
    BOOLEAN hasInvalidImageHeader;
    BOOLEAN isCoreKernelModule;
    BOOLEAN isSelfModule;
    ULONGLONG driverStart;
    ULONGLONG loaderEntryAddress;
    ULONGLONG loaderDllBase;
    ULONG loaderSizeOfImage;
    ULONG scannedProcessCount;
    ULONG scannedThreadCount;
    ULONG moduleResidentThreadCount;
    NTSTATUS threadScanStatus;
    ULONG callbackEnumeratedCount;
    ULONG moduleCallbackCount;
    ULONG removableModuleCallbackCount;
    ULONG nonRemovableModuleCallbackCount;
    NTSTATUS callbackScanStatus;
    NTSTATUS loaderLinkStatus;
    NTSTATUS imageHeaderStatus;
    ULONG imageHeaderSizeOfImage;
    ULONG imageNtHeaderOffset;
} KswDriverUnloadDiagnostics, *PkswDriverUnloadDiagnostics;

NTSTATUS
kswordArkDriverCommunicationInitialize(
    _In_ PDRIVER_OBJECT driverObject
    );

VOID
kswordArkDriverCommunicationUninitialize(
    VOID
    );

NTSTATUS
kswordArkDriverControlCommunication(
    _In_ const KSWORD_ARK_DRIVER_COMMUNICATION_REQUEST* request,
    _Out_ KSWORD_ARK_DRIVER_COMMUNICATION_RESPONSE* response
    );

BOOLEAN
kswordArkDriverCommunicationHasBlockingRecord(
    _In_ PDRIVER_OBJECT targetDriverObject,
    _In_ ULONGLONG originalRequestModuleBase
    );

NTSTATUS
kswordArkDriverDispatchInitialize(
    _In_ PDRIVER_OBJECT driverObject
    );

VOID
kswordArkDriverDispatchUninitialize(
    VOID
    );

// HAL table edit transactions record the initial value at driver load; on unload, atomically restore only if the slot
// still equals the last published value for this feature, avoiding overwrites from concurrent third-party modifications.
VOID
kswordArkPlatformAuditInitialize(
    VOID
    );

VOID
kswordArkPlatformAuditUninitialize(
    VOID
    );

NTSTATUS
kswordArkDriverControlDispatch(
    _In_ const KSWORD_ARK_DRIVER_DISPATCH_REQUEST* request,
    _Out_ KSWORD_ARK_DRIVER_DISPATCH_RESPONSE* response
    );

NTSTATUS
kswordArkSlatIommuAuditQuery(
    _In_ const KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_REQUEST* request,
    _Out_ KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_RESPONSE* response
    );

BOOLEAN
kswordArkDriverDispatchHasBlockingRecord(
    _In_ PDRIVER_OBJECT targetDriverObject,
    _In_ ULONGLONG originalRequestModuleBase
    );

NTSTATUS
kswordArkKernelIoctlControlDriverDispatch(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    );

NTSTATUS
kswordArkDriverImageInitialize(
    _In_ PDRIVER_OBJECT driverObject
    );

VOID
kswordArkDriverImageUninitialize(
    VOID
    );

NTSTATUS
kswordArkDriverControlImage(
    _In_ const KSWORD_ARK_DRIVER_IMAGE_REQUEST* request,
    _Out_ KSWORD_ARK_DRIVER_IMAGE_RESPONSE* response
    );

BOOLEAN
kswordArkDriverImageHasBlockingRecord(
    _In_ PDRIVER_OBJECT targetDriverObject,
    _In_ ULONGLONG originalRequestModuleBase
    );

NTSTATUS
kswordArkKernelIoctlControlDriverImage(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    );

NTSTATUS
kswordArkDriverReferenceObjectByModuleBase(
    _In_ ULONGLONG targetModuleBase,
    _Outptr_ PDRIVER_OBJECT* driverObjectOut,
    _Out_writes_(nameChars) PWCHAR normalizedNameOut,
    _In_ ULONG nameChars
    );

NTSTATUS
kswordArkKernelIoctlExperimentalReturnToFirmware(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    );

NTSTATUS
kswordArkDriverEnumerateSsdt(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_ENUM_SSDT_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkDriverQueryDriverObject(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_QUERY_DRIVER_OBJECT_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkDriverQueryDriverIntegrity(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_QUERY_DRIVER_INTEGRITY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkDriverQueryCpuHardware(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkDriverQueryPhysicalMemoryLayout(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkDriverEnumerateTimerDpc(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_ENUM_TIMER_DPC_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkDriverEnumerateShadowSsdt(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_ENUM_SSDT_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkDriverScanInlineHooks(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_SCAN_KERNEL_HOOKS_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkDriverPatchInlineHook(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_PATCH_INLINE_HOOK_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkDriverEnumerateIatEatHooks(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_SCAN_KERNEL_HOOKS_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkDriverForceUnloadDriver(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_FORCE_UNLOAD_DRIVER_REQUEST* request,
    _Out_ size_t* bytesWrittenOut,
    _Out_opt_ KswDriverUnloadDiagnostics* diagnostics
    );

EXTERN_C_END
