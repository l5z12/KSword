/*++

Module Name:

    rxpf_ioctl.c

Abstract:

    WDF adapters for the administrator-only RXPF research protocol.

Environment:

    Kernel-mode Driver Framework at PASSIVE_LEVEL.

--*/

#include "ark/ark_driver.h"

#include "rxpf_runtime.h"
#include "src/dispatch/ioctl_validation.h"

typedef enum KswRxpfIoctlOperation
{
    kKswRxpfIoctlQuerySupport = 0,
    kKswRxpfIoctlRegisterPage,
    kKswRxpfIoctlChangePage,
    kKswRxpfIoctlQueryPage,
    kKswRxpfIoctlWritePage,
    kKswRxpfIoctlSetEmulation,
    kKswRxpfIoctlQueryStats,
    kKswRxpfIoctlDrainEvents,
    kKswRxpfIoctlUnregisterPage,
    kKswRxpfIoctlRunSelfTest
} KswRxpfIoctlOperation;

typedef union KswRxpfRequestSnapshot
{
    KSWORD_ARK_RXPF_REQUEST_HEADER header;
    KSWORD_ARK_RXPF_REGISTER_PAGE_REQUEST registerPage;
    KSWORD_ARK_RXPF_RECORD_REQUEST record;
    KSWORD_ARK_RXPF_WRITE_PAGE_REQUEST writePage;
    KSWORD_ARK_RXPF_SET_EMULATION_REQUEST setEmulation;
    KSWORD_ARK_RXPF_DRAIN_EVENTS_REQUEST drainEvents;
} KswRxpfRequestSnapshot;

static BOOLEAN
kswRxpfIoctlIsMutation(
    _In_ KswRxpfIoctlOperation operation
    )
{
    /* Queries and event export do not change RXPF or machine state. */
    return operation == kKswRxpfIoctlRegisterPage ||
        operation == kKswRxpfIoctlChangePage ||
        operation == kKswRxpfIoctlWritePage ||
        operation == kKswRxpfIoctlSetEmulation ||
        operation == kKswRxpfIoctlUnregisterPage ||
        operation == kKswRxpfIoctlRunSelfTest;
}

static NTSTATUS
kswRxpfIoctlEvaluateSafety(
    _In_ WDFDEVICE device,
    _In_ KswRxpfIoctlOperation operation,
    _In_ ULONG requestFlags
    )
{
    KswordArkSafetyContext safetyContext = { 0 };

    /* Bind every mutation to the central critical kernel-patch policy class. */
    safetyContext.operation = KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH;
    safetyContext.contextFlags =
        (requestFlags & KSWORD_ARK_RXPF_FLAG_UI_CONFIRMED) != 0UL
        ? KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED
        : 0UL;
    switch (operation) {
    case kKswRxpfIoctlRegisterPage:
        safetyContext.targetText =
            L"Register one driver-owned RXPF research page";
        safetyContext.targetTextChars = (USHORT)(RTL_NUMBER_OF(
            L"Register one driver-owned RXPF research page") - 1U);
        break;
    case kKswRxpfIoctlChangePage:
        safetyContext.targetText =
            L"Transition one RXPF research page to persistent RW/NX";
        safetyContext.targetTextChars = (USHORT)(RTL_NUMBER_OF(
            L"Transition one RXPF research page to persistent RW/NX") - 1U);
        break;
    case kKswRxpfIoctlWritePage:
        safetyContext.targetText =
            L"Write bounded bytes to one RXPF writable alias";
        safetyContext.targetTextChars = (USHORT)(RTL_NUMBER_OF(
            L"Write bounded bytes to one RXPF writable alias") - 1U);
        break;
    case kKswRxpfIoctlSetEmulation:
        safetyContext.targetText =
            L"Install or restore per-processor shadow IDTs for RXPF";
        safetyContext.targetTextChars = (USHORT)(RTL_NUMBER_OF(
            L"Install or restore per-processor shadow IDTs for RXPF") - 1U);
        break;
    case kKswRxpfIoctlUnregisterPage:
        safetyContext.targetText =
            L"Terminate and release one RXPF research page";
        safetyContext.targetTextChars = (USHORT)(RTL_NUMBER_OF(
            L"Terminate and release one RXPF research page") - 1U);
        break;
    default:
        safetyContext.targetText =
            L"Execute an RXPF driver-owned-page instruction self-test";
        safetyContext.targetTextChars = (USHORT)(RTL_NUMBER_OF(
            L"Execute an RXPF driver-owned-page instruction self-test") - 1U);
        break;
    }
    return kswordArkSafetyEvaluate(device, &safetyContext);
}

static NTSTATUS
KswRxpfIoctlDispatchFixed(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned,
    _In_ KswRxpfIoctlOperation operation,
    _In_ size_t requiredInputLength,
    _In_ size_t requiredOutputLength,
    _In_ ULONG allowedFlags
    )
{
    KswRxpfRequestSnapshot snapshot;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    /* Reject malformed completion and fixed-buffer contracts before mutation. */
    if (bytesReturned == NULL || request == NULL ||
        requiredInputLength > sizeof(snapshot)) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;
    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = WdfRequestRetrieveInputBuffer(
        request,
        requiredInputLength,
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status) ||
        inputBufferLength != requiredInputLength ||
        actualInputLength < requiredInputLength) {
        return NT_SUCCESS(status)
            ? STATUS_INFO_LENGTH_MISMATCH
            : status;
    }

    /* METHOD_BUFFERED uses one system buffer, so preserve input before output. */
    RtlZeroMemory(&snapshot, sizeof(snapshot));
    RtlCopyMemory(&snapshot, inputBuffer, requiredInputLength);
    if (snapshot.header.version != KSWORD_ARK_RXPF_PROTOCOL_VERSION ||
        snapshot.header.size != requiredInputLength ||
        snapshot.header.confirmationToken !=
            KSWORD_ARK_RXPF_CONFIRMATION_TOKEN ||
        (snapshot.header.flags & KSWORD_ARK_RXPF_FLAG_UI_CONFIRMED) == 0UL ||
        (snapshot.header.flags & ~allowedFlags) != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    status = WdfRequestRetrieveOutputBuffer(
        request,
        requiredOutputLength,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status) ||
        outputBufferLength < requiredOutputLength ||
        actualOutputLength < requiredOutputLength) {
        return NT_SUCCESS(status)
            ? STATUS_BUFFER_TOO_SMALL
            : status;
    }
    RtlZeroMemory(outputBuffer, requiredOutputLength);

    /* Central safety policy evaluates only operations that change machine state. */
    if (kswRxpfIoctlIsMutation(operation)) {
        status = kswRxpfIoctlEvaluateSafety(
            device,
            operation,
            snapshot.header.flags);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    /* Dispatch the validated snapshot to the type-owning runtime entry point. */
    switch (operation) {
    case kKswRxpfIoctlQuerySupport:
        status = kswRxpfRuntimeQuerySupport(
            (KSWORD_ARK_RXPF_QUERY_SUPPORT_RESPONSE*)outputBuffer);
        break;
    case kKswRxpfIoctlRegisterPage:
        status = kswRxpfRuntimeRegisterPage(
            &snapshot.registerPage,
            (KSWORD_ARK_RXPF_PAGE_RESPONSE*)outputBuffer);
        break;
    case kKswRxpfIoctlChangePage:
        status = kswRxpfRuntimeChangePage(
            &snapshot.record,
            (KSWORD_ARK_RXPF_PAGE_RESPONSE*)outputBuffer);
        break;
    case kKswRxpfIoctlQueryPage:
        status = kswRxpfRuntimeQueryPage(
            &snapshot.record,
            (KSWORD_ARK_RXPF_PAGE_RESPONSE*)outputBuffer);
        break;
    case kKswRxpfIoctlWritePage:
        status = kswRxpfRuntimeWritePage(
            &snapshot.writePage,
            (KSWORD_ARK_RXPF_PAGE_RESPONSE*)outputBuffer);
        break;
    case kKswRxpfIoctlSetEmulation:
        status = kswRxpfRuntimeSetEmulation(
            &snapshot.setEmulation,
            (KSWORD_ARK_RXPF_PAGE_RESPONSE*)outputBuffer);
        break;
    case kKswRxpfIoctlQueryStats:
        status = kswRxpfRuntimeQueryStats(
            (KSWORD_ARK_RXPF_STATS_RESPONSE*)outputBuffer);
        break;
    case kKswRxpfIoctlDrainEvents:
        status = kswRxpfRuntimeDrainEvents(
            &snapshot.drainEvents,
            (KSWORD_ARK_RXPF_DRAIN_EVENTS_RESPONSE*)outputBuffer);
        break;
    case kKswRxpfIoctlUnregisterPage:
        status = kswRxpfRuntimeUnregisterPage(
            &snapshot.record,
            (KSWORD_ARK_RXPF_PAGE_RESPONSE*)outputBuffer);
        break;
    case kKswRxpfIoctlRunSelfTest:
        status = kswRxpfRuntimeRunSelfTest(
            &snapshot.record,
            (KSWORD_ARK_RXPF_SELF_TEST_RESPONSE*)outputBuffer);
        break;
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }
    *bytesReturned = requiredOutputLength;
    return status;
}

#define KSW_RXPF_DEFINE_IOCTL_HANDLER(                                      \
    FunctionName, OperationValue, RequestType, ResponseType, FlagMask)      \
NTSTATUS                                                                     \
FunctionName(                                                                \
    _In_ WDFDEVICE Device,                                                   \
    _In_ WDFREQUEST Request,                                                 \
    _In_ size_t InputBufferLength,                                           \
    _In_ size_t OutputBufferLength,                                          \
    _Out_ size_t* BytesReturned                                              \
    )                                                                        \
{                                                                            \
    return KswRxpfIoctlDispatchFixed(                                        \
        Device,                                                              \
        Request,                                                             \
        InputBufferLength,                                                   \
        OutputBufferLength,                                                  \
        BytesReturned,                                                       \
        OperationValue,                                                      \
        sizeof(RequestType),                                                 \
        sizeof(ResponseType),                                                \
        FlagMask);                                                           \
}

/* Fixed adapters keep protocol sizing in one auditable declaration each. */
KSW_RXPF_DEFINE_IOCTL_HANDLER(
    KswordARKRxpfIoctlQuerySupport,
    kKswRxpfIoctlQuerySupport,
    KSWORD_ARK_RXPF_REQUEST_HEADER,
    KSWORD_ARK_RXPF_QUERY_SUPPORT_RESPONSE,
    KSWORD_ARK_RXPF_FLAG_UI_CONFIRMED)

KSW_RXPF_DEFINE_IOCTL_HANDLER(
    KswordARKRxpfIoctlRegisterPage,
    kKswRxpfIoctlRegisterPage,
    KSWORD_ARK_RXPF_REGISTER_PAGE_REQUEST,
    KSWORD_ARK_RXPF_PAGE_RESPONSE,
    KSWORD_ARK_RXPF_FLAG_UI_CONFIRMED |
        KSWORD_ARK_RXPF_FLAG_CAPTURE_BACKUP)

KSW_RXPF_DEFINE_IOCTL_HANDLER(
    KswordARKRxpfIoctlChangePage,
    kKswRxpfIoctlChangePage,
    KSWORD_ARK_RXPF_RECORD_REQUEST,
    KSWORD_ARK_RXPF_PAGE_RESPONSE,
    KSWORD_ARK_RXPF_FLAG_UI_CONFIRMED)

KSW_RXPF_DEFINE_IOCTL_HANDLER(
    KswordARKRxpfIoctlQueryPage,
    kKswRxpfIoctlQueryPage,
    KSWORD_ARK_RXPF_RECORD_REQUEST,
    KSWORD_ARK_RXPF_PAGE_RESPONSE,
    KSWORD_ARK_RXPF_FLAG_UI_CONFIRMED)

KSW_RXPF_DEFINE_IOCTL_HANDLER(
    KswordARKRxpfIoctlWritePage,
    kKswRxpfIoctlWritePage,
    KSWORD_ARK_RXPF_WRITE_PAGE_REQUEST,
    KSWORD_ARK_RXPF_PAGE_RESPONSE,
    KSWORD_ARK_RXPF_FLAG_UI_CONFIRMED)

KSW_RXPF_DEFINE_IOCTL_HANDLER(
    KswordARKRxpfIoctlSetEmulation,
    kKswRxpfIoctlSetEmulation,
    KSWORD_ARK_RXPF_SET_EMULATION_REQUEST,
    KSWORD_ARK_RXPF_PAGE_RESPONSE,
    KSWORD_ARK_RXPF_FLAG_UI_CONFIRMED)

KSW_RXPF_DEFINE_IOCTL_HANDLER(
    KswordARKRxpfIoctlQueryStats,
    kKswRxpfIoctlQueryStats,
    KSWORD_ARK_RXPF_REQUEST_HEADER,
    KSWORD_ARK_RXPF_STATS_RESPONSE,
    KSWORD_ARK_RXPF_FLAG_UI_CONFIRMED)

KSW_RXPF_DEFINE_IOCTL_HANDLER(
    KswordARKRxpfIoctlDrainEvents,
    kKswRxpfIoctlDrainEvents,
    KSWORD_ARK_RXPF_DRAIN_EVENTS_REQUEST,
    KSWORD_ARK_RXPF_DRAIN_EVENTS_RESPONSE,
    KSWORD_ARK_RXPF_FLAG_UI_CONFIRMED)

KSW_RXPF_DEFINE_IOCTL_HANDLER(
    KswordARKRxpfIoctlUnregisterPage,
    kKswRxpfIoctlUnregisterPage,
    KSWORD_ARK_RXPF_RECORD_REQUEST,
    KSWORD_ARK_RXPF_PAGE_RESPONSE,
    KSWORD_ARK_RXPF_FLAG_UI_CONFIRMED)

KSW_RXPF_DEFINE_IOCTL_HANDLER(
    KswordARKRxpfIoctlRunSelfTest,
    kKswRxpfIoctlRunSelfTest,
    KSWORD_ARK_RXPF_RECORD_REQUEST,
    KSWORD_ARK_RXPF_SELF_TEST_RESPONSE,
    KSWORD_ARK_RXPF_FLAG_UI_CONFIRMED)

#undef KSW_RXPF_DEFINE_IOCTL_HANDLER
