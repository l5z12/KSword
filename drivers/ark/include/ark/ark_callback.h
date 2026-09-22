#pragma once

#include <ntddk.h>
#include <wdf.h>

#include "driver/KswordArkCallbackIoctl.h"
#include "driver/KswordArkCallbackMonitorIoctl.h"

EXTERN_C_START

// The callback hot path uses a lightweight input descriptor; the telemetry runtime is responsible for copying the text into a fixed ring slot.
typedef struct KswordArkCallbackMonitorEventInput
{
    ULONG category;
    ULONG operation;
    ULONG flags;
    NTSTATUS resultStatus;
    ULONG originatingProcessId;
    ULONG originatingThreadId;
    ULONG targetProcessId;
    ULONG targetThreadId;
    ULONG parentProcessId;
    ULONG sessionId;
    ULONG originalAccess;
    ULONG desiredAccess;
    ULONG objectType;
    ULONG detailCode;
    ULONG64 address;
    ULONG64 regionSize;
    PCUNICODE_STRING processName;
    PCUNICODE_STRING path;
} KswordArkCallbackMonitorEventInput;

// Returns STATUS_SUCCESS if all callbacks are registered successfully; returns a failure status if the callback
// layer has degraded. The caller must continue loading the driver and not treat this as a fatal error.
NTSTATUS
kswordArkCallbackInitialize(
    _In_ WDFDEVICE device
    );

// The actual KSWORD_ARK_CALLBACK_REGISTERED_* capability bits successfully registered.
ULONG
kswordArkCallbackGetRegisteredMask(
    VOID
    );

VOID
kswordArkCallbackUninitialize(
    VOID
    );

NTSTATUS
kswordArkCallbackIoctlSetRules(
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _Out_ size_t* completeBytesOut
    );

NTSTATUS
kswordArkCallbackIoctlGetRuntimeState(
    _In_ WDFREQUEST request,
    _In_ size_t outputBufferLength,
    _Out_ size_t* completeBytesOut
    );

NTSTATUS
kswordArkCallbackIoctlWaitEvent(
    _In_ WDFREQUEST request,
    _In_ size_t outputBufferLength,
    _Out_ size_t* completeBytesOut
    );

NTSTATUS
kswordArkCallbackIoctlAnswerEvent(
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _Out_ size_t* completeBytesOut
    );

NTSTATUS
kswordArkCallbackIoctlCancelAllPending(
    _Out_ size_t* completeBytesOut
    );

NTSTATUS
kswordArkCallbackIoctlRemoveExternalCallback(
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* completeBytesOut
    );

NTSTATUS
kswordArkCallbackIoctlRemoveExternalCallbackEx(
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* completeBytesOut
    );

NTSTATUS
kswordArkCallbackIoctlEnumCallbacks(
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* completeBytesOut
    );

NTSTATUS
kswordArkCallbackIoctlSetMinifilterBypassPids(
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _Out_ size_t* completeBytesOut
    );

NTSTATUS
kswordArkCallbackIoctlQueryMinifilterBypassPids(
    _In_ WDFREQUEST request,
    _In_ size_t outputBufferLength,
    _Out_ size_t* completeBytesOut
    );

BOOLEAN
kswordArkCallbackIsMinifilterBypassPid(
    _In_ ULONG processId
    );

// Only check the atomic category mask; callers should return early when the category is disabled to avoid extra path resolution.
BOOLEAN
kswordArkCallbackMonitorIsEnabled(
    _In_ ULONG category
    );

// Submit a structured event to a fixed ring buffer; drop on contention without waiting.
VOID
kswordArkCallbackMonitorPublish(
    _In_ const KswordArkCallbackMonitorEventInput* eventInput
    );

NTSTATUS
kswordArkCallbackMonitorControl(
    _In_ const KSWORD_ARK_CALLBACK_MONITOR_CONTROL_REQUEST* request,
    _Out_ KSWORD_ARK_CALLBACK_MONITOR_STATUS_RESPONSE* response
    );

NTSTATUS
kswordArkCallbackMonitorQuery(
    _Out_ KSWORD_ARK_CALLBACK_MONITOR_STATUS_RESPONSE* response
    );

NTSTATUS
kswordArkCallbackMonitorRead(
    _In_ const KSWORD_ARK_CALLBACK_MONITOR_READ_REQUEST* request,
    _Out_writes_bytes_(outputBufferLength) KSWORD_ARK_CALLBACK_MONITOR_READ_RESPONSE* response,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    );

EXTERN_C_END
