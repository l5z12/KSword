#pragma once

#include "ark/ark_driver.h"
#include "driver/KswordArkDeviceAuditIoctl.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntstrsafe.h>
#include <stdarg.h>

#define KSW_DEVICE_AUDIT_POOL_TAG 'aDsK'
#define KSW_DEVICE_AUDIT_RESPONSE_HEADER_SIZE \
    (FIELD_OFFSET(KSWORD_ARK_QUERY_DEVICE_AUDIT_RESPONSE, entries))
#define KSW_DEVICE_AUDIT_INTEGRITY_RESPONSE_HEADER_SIZE \
    (FIELD_OFFSET(KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE, entries))
#define KSW_DEVICE_AUDIT_SCRATCH_ROW_LIMIT 1024UL

typedef struct KswDeviceAuditTarget
{
    PCWSTR driverName;
    ULONG roleHint;
} KswDeviceAuditTarget, *PkswDeviceAuditTarget;

typedef struct KswDeviceAuditRequestContext
{
    KSWORD_ARK_QUERY_DEVICE_AUDIT_REQUEST request;
    ULONG effectiveProfile;
    ULONG maxRows;
    ULONG maxAttachedDepth;
    BOOLEAN hasSingleTarget;
} KswDeviceAuditRequestContext, *PkswDeviceAuditRequestContext;

EXTERN_C_START

extern const KswDeviceAuditTarget kGKswDeviceAuditDeviceTargets[];
extern const KswDeviceAuditTarget kGKswDeviceAuditInputTargets[];
extern const KswDeviceAuditTarget kGKswDeviceAuditUsbTargets[];
extern const KswDeviceAuditTarget kGKswDeviceAuditGpuTargets[];
extern const ULONG kGKswDeviceAuditDeviceTargetCount;
extern const ULONG kGKswDeviceAuditInputTargetCount;
extern const ULONG kGKswDeviceAuditUsbTargetCount;
extern const ULONG kGKswDeviceAuditGpuTargetCount;

VOID
kswDeviceAuditLog(_In_ WDFDEVICE device, _In_z_ PCSTR levelText, _In_z_ PCSTR formatText, ...);

VOID
kswDeviceAuditZeroResponse(_Out_writes_bytes_(outputBufferLength) PVOID outputBuffer, _In_ size_t outputBufferLength, _In_ ULONG profileFlags);

ULONG
kswDeviceAuditNormalizeMaxRows(_In_ ULONG requestedRows);

ULONG
kswDeviceAuditNormalizeAttachedDepth(_In_ ULONG requestedDepth);

BOOLEAN
kswDeviceAuditStringPresent(_In_reads_(maxChars) const WCHAR* text, _In_ ULONG maxChars);

VOID
kswDeviceAuditCopyWide(_Out_writes_(destinationChars) WCHAR* destination, _In_ ULONG destinationChars, _In_opt_z_ PCWSTR source);

VOID
kswDeviceAuditCopyServiceName(_Out_writes_(destinationChars) WCHAR* destination, _In_ ULONG destinationChars, _In_z_ PCWSTR driverName);

ULONG
kswDeviceAuditOutputCapacity(_In_ size_t outputBufferLength);

ULONG
kswDeviceAuditMapRiskFlags(_In_ ULONG integrityRiskFlags);

ULONG
kswDeviceAuditMapStatus(_In_ ULONG integrityStatus, _In_ ULONG integrityRiskFlags);

VOID
kswDeviceAuditSetResponsePartial(_Inout_ KSWORD_ARK_QUERY_DEVICE_AUDIT_RESPONSE* response, _In_ NTSTATUS lastStatus);

NTSTATUS
kswDeviceAuditAppendEntry(_Inout_ KSWORD_ARK_QUERY_DEVICE_AUDIT_RESPONSE* response, _In_ ULONG capacity, _In_ ULONG maxRows, _In_ const KSWORD_ARK_DEVICE_AUDIT_ENTRY* sourceEntry);

NTSTATUS
kswDeviceAuditExecute(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned,
    _In_ ULONG handlerProfile,
    _In_z_ PCSTR logName
    );

EXTERN_C_END
