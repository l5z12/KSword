/*++

Module Name:

    hvm_ioctl.c

Abstract:

    WDF adapters for HVM capability queries and safety-gated lifecycle control.

Environment:

    Kernel-mode Driver Framework.

--*/

#include "hvm_runtime.h"
#include "hvm_cr_policy.h"
#include "hvm_ept_domain.h"
#include "hvm_ept_view.h"
#include "hvm_inject.h"
#include "hvm_nested_probe.h"
#include "hvm_nested_ept.h"
#include "hvm_process.h"
#include "hvm_memory.h"
#include "hvm_msr_policy.h"
#include "hvm_metrics.h"
#include "../../dispatch/ioctl_validation.h"
#include "../../platform/pool_compat.h"

/* Tag the bounded request snapshot the shared SystemBuffer forces us to keep. */
#define KSWORD_ARK_HVM_MEMORY_IOCTL_POOL_TAG 'IvHK'
/* Tag the view request snapshot, which carries a full shadow page. */
#define KSWORD_ARK_HVM_VIEW_IOCTL_POOL_TAG 'VvHK'

/* Read-only measurement query; it never performs a VMX transition. */
NTSTATUS kswordArkHvmIoctlMetrics(
    WDFDEVICE device, WDFREQUEST request, size_t inputBufferLength,
    size_t outputBufferLength, size_t* bytesReturned)
{
    /* Validate METHOD_BUFFERED input before overwriting its shared buffer. */
    PVOID input = NULL, output = NULL;
    size_t inputBytes = 0U, outputBytes = 0U;
    KSWORD_ARK_HVM_METRICS_REQUEST* query;
    NTSTATUS status;
    /* This query needs no mutable device context. */
    UNREFERENCED_PARAMETER(device);
    /* Every rejected request reports zero completed bytes. */
    if (bytesReturned == NULL) { return STATUS_INVALID_PARAMETER; }
    /* initialize completion before retrieving buffers. */
    *bytesReturned = 0U;
    /* Retrieve the complete versioned query. */
    status = WdfRequestRetrieveInputBuffer(request, sizeof(*query), &input, &inputBytes);
    /* Reject truncation before reading any query member. */
    if (!NT_SUCCESS(status)) { return status; }
    /* Check both the dispatcher and WDF input lengths. */
    if (inputBufferLength < sizeof(*query) || inputBytes < sizeof(*query)) { return STATUS_INFO_LENGTH_MISMATCH; }
    /* Interpret the validated fixed input. */
    query = (KSWORD_ARK_HVM_METRICS_REQUEST*)input;
    /* Preserve independent protocol-version negotiation. */
    if (query->version != KSWORD_ARK_HVM_METRICS_VERSION || query->size != sizeof(*query)) { return STATUS_REVISION_MISMATCH; }
    /* Refuse unknown flags before producing output. */
    if (query->flags != 0UL || query->reserved != 0UL) { return STATUS_INVALID_PARAMETER; }
    /* Retrieve fixed-capacity output without using the kernel stack. */
    status = WdfRequestRetrieveOutputBuffer(request, sizeof(KSWORD_ARK_HVM_METRICS_RESPONSE), &output, &outputBytes);
    /* Propagate retrieval failure without touching output. */
    if (!NT_SUCCESS(status)) { return status; }
    /* Partial per-processor timing is not an authoritative response. */
    if (outputBufferLength < sizeof(KSWORD_ARK_HVM_METRICS_RESPONSE) || outputBytes < sizeof(KSWORD_ARK_HVM_METRICS_RESPONSE)) { return STATUS_BUFFER_TOO_SMALL; }
    /* Copy observations without resetting counters or changing residency. */
    status = kswordArkHvmMetricsQuery((KSWORD_ARK_HVM_METRICS_RESPONSE*)output);
    /* Report completed bytes only on success. */
    if (NT_SUCCESS(status)) { *bytesReturned = sizeof(KSWORD_ARK_HVM_METRICS_RESPONSE); }
    /* Return the authoritative query result. */
    return status;
}

NTSTATUS
kswordArkHvmIoctlPlatform(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;
    const KSWORD_ARK_HVM_PLATFORM_REQUEST* probeRequest = NULL;

    /* The dispatcher requires an explicit completion size on every path. */
    UNREFERENCED_PARAMETER(device);
    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    /* Retrieve and validate the versioned fixed probe request. */
    status = WdfRequestRetrieveInputBuffer(
        request,
        sizeof(KSWORD_ARK_HVM_PLATFORM_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status) ||
        inputBufferLength < sizeof(KSWORD_ARK_HVM_PLATFORM_REQUEST) ||
        actualInputLength < sizeof(KSWORD_ARK_HVM_PLATFORM_REQUEST)) {
        return NT_SUCCESS(status)
            ? STATUS_INFO_LENGTH_MISMATCH
            : status;
    }
    probeRequest =
        (const KSWORD_ARK_HVM_PLATFORM_REQUEST*)inputBuffer;
    if (probeRequest->version !=
            KSWORD_ARK_HVM_PLATFORM_PROTOCOL_VERSION ||
        probeRequest->size != sizeof(*probeRequest)) {
        return STATUS_REVISION_MISMATCH;
    }
    /* Reject unknown flags and reserved fields in this protocol version. */
    if (probeRequest->flags != 0UL ||
        probeRequest->reserved != 0UL) {
        /* Return the exact fixed-field contract failure. */
        return STATUS_INVALID_PARAMETER;
    }

    /* Retrieve the complete fixed probe response. */
    status = WdfRequestRetrieveOutputBuffer(
        request,
        sizeof(KSWORD_ARK_HVM_PLATFORM_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status) ||
        outputBufferLength < sizeof(KSWORD_ARK_HVM_PLATFORM_RESPONSE) ||
        actualOutputLength < sizeof(KSWORD_ARK_HVM_PLATFORM_RESPONSE)) {
        return NT_SUCCESS(status)
            ? STATUS_BUFFER_TOO_SMALL
            : status;
    }

    /*
     * METHOD_BUFFERED shares one SystemBuffer between input and output, and
     * the probe zeroes the response before reading anything - but every field
     * it needs was already validated out of the request above, so there is
     * nothing left to snapshot.
     */
    status = kswordArkHvmPlatformProbe(
        (KSWORD_ARK_HVM_PLATFORM_RESPONSE*)outputBuffer);
    if (NT_SUCCESS(status)) {
        *bytesReturned = sizeof(KSWORD_ARK_HVM_PLATFORM_RESPONSE);
    }
    return status;
}

NTSTATUS
kswordArkHvmIoctlQuery(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;
    const KSWORD_ARK_QUERY_HVM_REQUEST* queryRequest = NULL;

    /* The dispatcher requires an explicit completion size on every path. */
    UNREFERENCED_PARAMETER(device);
    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    /* Retrieve and validate the versioned fixed query request. */
    status = WdfRequestRetrieveInputBuffer(
        request,
        sizeof(KSWORD_ARK_QUERY_HVM_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status) ||
        inputBufferLength < sizeof(KSWORD_ARK_QUERY_HVM_REQUEST) ||
        actualInputLength < sizeof(KSWORD_ARK_QUERY_HVM_REQUEST)) {
        return NT_SUCCESS(status)
            ? STATUS_INFO_LENGTH_MISMATCH
            : status;
    }
    queryRequest = (const KSWORD_ARK_QUERY_HVM_REQUEST*)inputBuffer;
    if (queryRequest->version != KSWORD_ARK_HVM_PROTOCOL_VERSION ||
        queryRequest->size != sizeof(*queryRequest)) {
        return STATUS_REVISION_MISMATCH;
    }
    /* Reject unknown query flags and reserved fields in this protocol version. */
    if (queryRequest->flags != 0UL ||
        queryRequest->reserved != 0UL) {
        /* Return the exact fixed-field contract failure. */
        return STATUS_INVALID_PARAMETER;
    }

    /* Retrieve the complete fixed status response. */
    status = WdfRequestRetrieveOutputBuffer(
        request,
        sizeof(KSWORD_ARK_QUERY_HVM_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status) ||
        outputBufferLength < sizeof(KSWORD_ARK_QUERY_HVM_RESPONSE) ||
        actualOutputLength < sizeof(KSWORD_ARK_QUERY_HVM_RESPONSE)) {
        return NT_SUCCESS(status)
            ? STATUS_BUFFER_TOO_SMALL
            : status;
    }

    /* Snapshot the backend without changing VMX or EPT state. */
    status = kswordArkHvmQuery(
        (KSWORD_ARK_QUERY_HVM_RESPONSE*)outputBuffer);
    if (NT_SUCCESS(status)) {
        *bytesReturned = sizeof(KSWORD_ARK_QUERY_HVM_RESPONSE);
    }
    return status;
}

NTSTATUS
kswordArkHvmIoctlControl(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;
    KSWORD_ARK_CONTROL_HVM_REQUEST controlRequestSnapshot = { 0 };
    const KSWORD_ARK_CONTROL_HVM_REQUEST* controlRequest = NULL;
    KSWORD_ARK_CONTROL_HVM_RESPONSE* controlResponse = NULL;

    /* Reject an invalid completion contract before touching request buffers. */
    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    /* Lifecycle mutations require a write-authorized device handle. */
    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* Retrieve both fixed protocol buffers before evaluating policy. */
    status = WdfRequestRetrieveInputBuffer(
        request,
        sizeof(KSWORD_ARK_CONTROL_HVM_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status) ||
        inputBufferLength < sizeof(KSWORD_ARK_CONTROL_HVM_REQUEST) ||
        actualInputLength < sizeof(KSWORD_ARK_CONTROL_HVM_REQUEST)) {
        return NT_SUCCESS(status)
            ? STATUS_INFO_LENGTH_MISMATCH
            : status;
    }
    /* Preserve METHOD_BUFFERED input before output retrieval exposes the same system buffer. */
    RtlCopyMemory(
        &controlRequestSnapshot,
        inputBuffer,
        sizeof(controlRequestSnapshot));
    status = WdfRequestRetrieveOutputBuffer(
        request,
        sizeof(KSWORD_ARK_CONTROL_HVM_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status) ||
        outputBufferLength < sizeof(KSWORD_ARK_CONTROL_HVM_RESPONSE) ||
        actualOutputLength < sizeof(KSWORD_ARK_CONTROL_HVM_RESPONSE)) {
        return NT_SUCCESS(status)
            ? STATUS_BUFFER_TOO_SMALL
            : status;
    }
    controlRequest = &controlRequestSnapshot;
    controlResponse =
        (KSWORD_ARK_CONTROL_HVM_RESPONSE*)outputBuffer;

    /*
     * Preparing VMX pages is reversible allocation work.  VMX transitions and
     * guest entry both receive the central critical kernel-patch policy gate.
     */
    if (controlRequest->command ==
            KSWORD_ARK_HVM_CONTROL_SELF_TEST ||
        controlRequest->command ==
            KSWORD_ARK_HVM_CONTROL_LAUNCH_TEST_GUEST ||
        controlRequest->command ==
            KSWORD_ARK_HVM_CONTROL_START_RESIDENT ||
        controlRequest->command ==
            KSWORD_ARK_HVM_CONTROL_VALIDATE_NESTED ||
        controlRequest->command ==
            KSWORD_ARK_HVM_CONTROL_RESET_FAULT) {
        KswordArkSafetyContext safetyContext = { 0 };

        /* Bind policy auditing to the exact high-risk operation class. */
        safetyContext.operation =
            KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH;
        safetyContext.contextFlags =
            (controlRequest->flags &
                KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED) != 0UL
            ? KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED
            : 0UL;
        /* Describe the exact privileged transition in the central audit gate. */
        if (controlRequest->command ==
                KSWORD_ARK_HVM_CONTROL_LAUNCH_TEST_GUEST) {
            safetyContext.targetText =
                L"One-shot VT-x VMLAUNCH and VMCALL VM-exit test";
            safetyContext.targetTextChars =
                (USHORT)(RTL_NUMBER_OF(
                    L"One-shot VT-x VMLAUNCH and VMCALL VM-exit test") - 1U);
        } else if (controlRequest->command ==
            KSWORD_ARK_HVM_CONTROL_SELF_TEST) {
            safetyContext.targetText =
                L"Per-processor VT-x VMXON and VMXOFF self-test";
            safetyContext.targetTextChars =
                (USHORT)(RTL_NUMBER_OF(
                    L"Per-processor VT-x VMXON and VMXOFF self-test") - 1U);
        } else if (controlRequest->command ==
            KSWORD_ARK_HVM_CONTROL_START_RESIDENT) {
            /* Describe all-processor resident VMX entry and rollback. */
            safetyContext.targetText =
                L"Resident all-processor VT-x VMM and EPT activation";
            /* Publish the exact bounded target text length. */
            safetyContext.targetTextChars =
                (USHORT)(RTL_NUMBER_OF(
                    L"Resident all-processor VT-x VMM and EPT activation") -
                    1U);
        } else if (controlRequest->command ==
            KSWORD_ARK_HVM_CONTROL_VALIDATE_NESTED) {
            /* Describe partial nested-VMX and eVMCS validation explicitly. */
            safetyContext.targetText =
                L"Partial nested VMX dispatch and Hyper-V eVMCS validation";
            /* Publish the exact bounded target text length. */
            safetyContext.targetTextChars =
                (USHORT)(RTL_NUMBER_OF(
                    L"Partial nested VMX dispatch and Hyper-V eVMCS validation") -
                    1U);
        } else {
            /* Describe recoverable HVM fault-state reset explicitly. */
            safetyContext.targetText =
                L"Reset stopped HVM fault and rollback state";
            /* Publish the exact bounded target text length. */
            safetyContext.targetTextChars =
                (USHORT)(RTL_NUMBER_OF(
                    L"Reset stopped HVM fault and rollback state") - 1U);
        }
        status = kswordArkSafetyEvaluate(device, &safetyContext);
        if (!NT_SUCCESS(status)) {
            RtlZeroMemory(controlResponse, sizeof(*controlResponse));
            controlResponse->version =
                KSWORD_ARK_HVM_PROTOCOL_VERSION;
            controlResponse->size = sizeof(*controlResponse);
            controlResponse->status =
                KSWORD_ARK_HVM_CONTROL_STATUS_CONFIRMATION_REQUIRED;
            controlResponse->lastStatus = status;
            *bytesReturned = sizeof(*controlResponse);
            return status;
        }
    }

    /* Execute the versioned lifecycle command and return its stable summary. */
    status = kswordArkHvmControl(controlRequest, controlResponse);
    *bytesReturned = sizeof(*controlResponse);
    return status;
}

NTSTATUS
kswordArkHvmIoctlEptRule(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;
    const KSWORD_ARK_HVM_EPT_RULE_REQUEST* ruleRequest = NULL;
    /* requestSnapshot: Save the complete request before the shared SystemBuffer is cleared at runtime. */
    KSWORD_ARK_HVM_EPT_RULE_REQUEST requestSnapshot;
    KSWORD_ARK_HVM_EPT_RULE_RESPONSE* ruleResponse = NULL;

    /* Reject an invalid completion contract before touching request buffers. */
    if (bytesReturned == NULL) {
        /* Return the exact dispatcher-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* initialize the completion size on every path. */
    *bytesReturned = 0U;
    /* EPT rule control requires a write-authorized device handle. */
    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    /* Stop before buffer access when handle authorization fails. */
    if (!NT_SUCCESS(status)) {
        /* Return the exact authorization failure. */
        return status;
    }
    /* Retrieve the complete fixed EPT rule request. */
    status = WdfRequestRetrieveInputBuffer(
        request,
        sizeof(KSWORD_ARK_HVM_EPT_RULE_REQUEST),
        &inputBuffer,
        &actualInputLength);
    /* Reject truncated or unavailable input buffers. */
    if (!NT_SUCCESS(status) ||
        inputBufferLength <
            sizeof(KSWORD_ARK_HVM_EPT_RULE_REQUEST) ||
        actualInputLength <
            sizeof(KSWORD_ARK_HVM_EPT_RULE_REQUEST)) {
        /* Return the exact WDF or fixed-size failure. */
        return NT_SUCCESS(status)
            ? STATUS_INFO_LENGTH_MISMATCH
            : status;
    }
    /* Retrieve the complete fixed EPT rule response. */
    status = WdfRequestRetrieveOutputBuffer(
        request,
        sizeof(KSWORD_ARK_HVM_EPT_RULE_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    /* Reject truncated or unavailable output buffers. */
    if (!NT_SUCCESS(status) ||
        outputBufferLength <
            sizeof(KSWORD_ARK_HVM_EPT_RULE_RESPONSE) ||
        actualOutputLength <
            sizeof(KSWORD_ARK_HVM_EPT_RULE_RESPONSE)) {
        /* Return the exact WDF or fixed-size failure. */
        return NT_SUCCESS(status)
            ? STATUS_BUFFER_TOO_SMALL
            : status;
    }
    /*
     * For METHOD_BUFFERED, input and output share the same SystemBuffer; kswordArkHvmEptRuleControl first
     * zero-fills the response via RtlZeroMemory before reading operation/GPA/permission bits. Without a
     * snapshot, it would modify an entirely unrelated EPT rule based on the response header bytes.
     */
    RtlCopyMemory(
        &requestSnapshot,
        inputBuffer,
        sizeof(requestSnapshot));
    /* Bind fixed protocol views after both buffers are validated. */
    ruleRequest = &requestSnapshot;
    /* Bind the fixed protocol output view. */
    ruleResponse =
        (KSWORD_ARK_HVM_EPT_RULE_RESPONSE*)outputBuffer;
    /*
     * Apply central high-risk policy to every mutating EPT rule operation.
     *
     * Both query forms are exempt: they read rule records and publish nothing.
     * Auditing a read as KERNEL_PATCH would record a mutation that never
     * happened, and a stricter policy configuration would then deny the one
     * operation a user needs most - reading back what a watch caught.
     */
    if (ruleRequest->operation !=
            KSWORD_ARK_HVM_EPT_RULE_QUERY &&
        ruleRequest->operation !=
            KSWORD_ARK_HVM_EPT_RULE_WATCH_QUERY) {
        KswordArkSafetyContext safetyContext = { 0 };

        /* Bind policy auditing to the kernel-patch operation class. */
        safetyContext.operation =
            KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH;
        /* Preserve explicit UI confirmation in central policy evidence. */
        safetyContext.contextFlags =
            (ruleRequest->flags &
                KSWORD_ARK_HVM_EPT_RULE_FLAG_UI_CONFIRMED) != 0UL
            ? KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED
            : 0UL;
        /* Describe the exact EPT permission mutation class. */
        safetyContext.targetText =
            L"Resident EPT R/W/X rule and cross-processor invalidation";
        /* Publish the exact bounded target text length. */
        safetyContext.targetTextChars =
            (USHORT)(RTL_NUMBER_OF(
                L"Resident EPT R/W/X rule and cross-processor invalidation") -
                1U);
        /* Evaluate central policy without weakening protocol confirmation. */
        status = kswordArkSafetyEvaluate(
            device,
            &safetyContext);
        /* Return a complete confirmation-required response on denial. */
        if (!NT_SUCCESS(status)) {
            /* initialize the complete fixed response. */
            RtlZeroMemory(
                ruleResponse,
                sizeof(*ruleResponse));
            /* Publish the response protocol identity. */
            ruleResponse->version =
                KSWORD_ARK_HVM_PROTOCOL_VERSION;
            /* Publish the complete response size. */
            ruleResponse->size =
                sizeof(*ruleResponse);
            /* Publish stable confirmation-required status. */
            ruleResponse->status =
                KSWORD_ARK_HVM_EPT_RULE_STATUS_CONFIRMATION_REQUIRED;
            /* Publish the authoritative policy failure. */
            ruleResponse->lastStatus = status;
            /* Publish the fixed completion size. */
            *bytesReturned =
                sizeof(*ruleResponse);
            /* Return the authoritative policy failure. */
            return status;
        }
    }
    /* Execute the serialized EPT rule operation. */
    status = kswordArkHvmEptRuleControl(
        ruleRequest,
        ruleResponse);
    /* Publish the fixed completion size on protocol-level results. */
    *bytesReturned = sizeof(*ruleResponse);
    /* Return the complete EPT rule operation result. */
    return status;
}

NTSTATUS
kswordArkHvmIoctlEvents(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;
    /*
     * METHOD_BUFFERED shares one SystemBuffer between input and output, and
     * kswordArkHvmEventControl zeroes the response before it reads maxRows and
     * afterSequence.  Without this snapshot the cursor is always read back as
     * zero, so every query restarts from the oldest retained event and the
     * consumer sees the same rows forever.
     */
    KSWORD_ARK_HVM_EVENT_QUERY_REQUEST requestSnapshot = { 0 };
    const KSWORD_ARK_HVM_EVENT_QUERY_REQUEST* eventRequest = NULL;

    /* Event queries do not use the device object directly. */
    UNREFERENCED_PARAMETER(device);
    /* Reject an invalid completion contract before touching request buffers. */
    if (bytesReturned == NULL) {
        /* Return the exact dispatcher-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* initialize the completion size on every path. */
    *bytesReturned = 0U;
    /* Retrieve the complete fixed event query request. */
    status = WdfRequestRetrieveInputBuffer(
        request,
        sizeof(KSWORD_ARK_HVM_EVENT_QUERY_REQUEST),
        &inputBuffer,
        &actualInputLength);
    /* Reject truncated or unavailable input buffers. */
    if (!NT_SUCCESS(status) ||
        inputBufferLength <
            sizeof(KSWORD_ARK_HVM_EVENT_QUERY_REQUEST) ||
        actualInputLength <
            sizeof(KSWORD_ARK_HVM_EVENT_QUERY_REQUEST)) {
        /* Return the exact WDF or fixed-size failure. */
        return NT_SUCCESS(status)
            ? STATUS_INFO_LENGTH_MISMATCH
            : status;
    }
    /* Bind the fixed protocol request after length validation. */
    /* Preserve the request before the shared buffer is used as a response. */
    RtlCopyMemory(
        &requestSnapshot,
        inputBuffer,
        sizeof(requestSnapshot));
    eventRequest = &requestSnapshot;
    /* Require write authorization before clearing retained events. */
    if (eventRequest->operation ==
        KSWORD_ARK_HVM_EVENT_QUERY_CLEAR) {
        /* Validate write access on the current device handle. */
        status = kswordArkValidateDeviceIoControlWriteAccess(
            request);
        /* Stop before response access when authorization fails. */
        if (!NT_SUCCESS(status)) {
            /* Return the exact authorization failure. */
            return status;
        }
    }
    /* Retrieve the complete fixed event query response. */
    status = WdfRequestRetrieveOutputBuffer(
        request,
        sizeof(KSWORD_ARK_HVM_EVENT_QUERY_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    /* Reject truncated or unavailable output buffers. */
    if (!NT_SUCCESS(status) ||
        outputBufferLength <
            sizeof(KSWORD_ARK_HVM_EVENT_QUERY_RESPONSE) ||
        actualOutputLength <
            sizeof(KSWORD_ARK_HVM_EVENT_QUERY_RESPONSE)) {
        /* Return the exact WDF or fixed-size failure. */
        return NT_SUCCESS(status)
            ? STATUS_BUFFER_TOO_SMALL
            : status;
    }
    /* Execute the read or stopped clear operation. */
    status = kswordArkHvmEventControl(
        eventRequest,
        (KSWORD_ARK_HVM_EVENT_QUERY_RESPONSE*)outputBuffer);
    /* Publish the fixed completion size only on success. */
    if (NT_SUCCESS(status)) {
        /* Publish the complete fixed response size. */
        *bytesReturned =
            sizeof(KSWORD_ARK_HVM_EVENT_QUERY_RESPONSE);
    }
    /* Return the complete event operation result. */
    return status;
}

NTSTATUS
kswordArkHvmIoctlMemory(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;
    /*
     * The request carries a full payload page, which is too large to snapshot
     * on the kernel stack, so it is copied into its own allocation instead.
     */
    KSWORD_ARK_HVM_MEMORY_REQUEST* requestSnapshot = NULL;
    KSWORD_ARK_HVM_MEMORY_RESPONSE* memoryResponse = NULL;

    /* Reject an invalid completion contract before touching request buffers. */
    if (bytesReturned == NULL) {
        /* Return the exact dispatcher-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* initialize the completion size on every path. */
    *bytesReturned = 0U;
    /* Every ring -1 memory operation requires a write-authorized handle. */
    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    /* Stop before buffer access when handle authorization fails. */
    if (!NT_SUCCESS(status)) {
        /* Return the exact authorization failure. */
        return status;
    }
    /* Retrieve the complete fixed memory request. */
    status = WdfRequestRetrieveInputBuffer(
        request,
        sizeof(KSWORD_ARK_HVM_MEMORY_REQUEST),
        &inputBuffer,
        &actualInputLength);
    /* Reject truncated or unavailable input buffers. */
    if (!NT_SUCCESS(status) ||
        inputBufferLength < sizeof(KSWORD_ARK_HVM_MEMORY_REQUEST) ||
        actualInputLength < sizeof(KSWORD_ARK_HVM_MEMORY_REQUEST)) {
        /* Return the exact WDF or fixed-size failure. */
        return NT_SUCCESS(status)
            ? STATUS_INFO_LENGTH_MISMATCH
            : status;
    }
    /* Retrieve the complete fixed memory response. */
    status = WdfRequestRetrieveOutputBuffer(
        request,
        sizeof(KSWORD_ARK_HVM_MEMORY_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    /* Reject truncated or unavailable output buffers. */
    if (!NT_SUCCESS(status) ||
        outputBufferLength < sizeof(KSWORD_ARK_HVM_MEMORY_RESPONSE) ||
        actualOutputLength < sizeof(KSWORD_ARK_HVM_MEMORY_RESPONSE)) {
        /* Return the exact WDF or fixed-size failure. */
        return NT_SUCCESS(status)
            ? STATUS_BUFFER_TOO_SMALL
            : status;
    }
    /* Reserve the snapshot before the shared buffer is written. */
    requestSnapshot = (KSWORD_ARK_HVM_MEMORY_REQUEST*)
        kswordArkAllocateNonPagedPool(
            sizeof(KSWORD_ARK_HVM_MEMORY_REQUEST),
            KSWORD_ARK_HVM_MEMORY_IOCTL_POOL_TAG);
    /* Fail before any buffer mutation when the snapshot cannot be reserved. */
    if (requestSnapshot == NULL) {
        /* Return the exact allocation failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /*
     * METHOD_BUFFERED shares one SystemBuffer between input and output, and
     * the executor zeroes the response before reading the operation, address
     * and payload.  Without this snapshot it would act on response header
     * bytes instead of the caller's request.
     */
    RtlCopyMemory(
        requestSnapshot,
        inputBuffer,
        sizeof(*requestSnapshot));
    /* Bind the fixed protocol output view. */
    memoryResponse = (KSWORD_ARK_HVM_MEMORY_RESPONSE*)outputBuffer;
    /* Apply central high-risk policy to every operation that writes memory. */
    if (requestSnapshot->operation ==
            KSWORD_ARK_HVM_MEMORY_OP_WRITE_PHYSICAL ||
        requestSnapshot->operation ==
            KSWORD_ARK_HVM_MEMORY_OP_WRITE_VIRTUAL) {
        KswordArkSafetyContext safetyContext = { 0 };

        /* Bind policy auditing to the kernel-patch operation class. */
        safetyContext.operation =
            KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH;
        /* Preserve explicit UI confirmation in central policy evidence. */
        safetyContext.contextFlags =
            (requestSnapshot->flags &
                KSWORD_ARK_HVM_MEMORY_FLAG_UI_CONFIRMED) != 0UL
            ? KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED
            : 0UL;
        /* Describe the exact memory mutation class. */
        safetyContext.targetText =
            L"Ring -1 physical memory write through a private page-table window";
        /* Publish the exact bounded target text length. */
        safetyContext.targetTextChars =
            (USHORT)(RTL_NUMBER_OF(
                L"Ring -1 physical memory write through a private page-table window") -
                1U);
        /* Evaluate central policy without weakening protocol confirmation. */
        status = kswordArkSafetyEvaluate(
            device,
            &safetyContext);
        /* Return a complete confirmation-required response on denial. */
        if (!NT_SUCCESS(status)) {
            /* initialize the complete fixed response. */
            RtlZeroMemory(
                memoryResponse,
                sizeof(*memoryResponse));
            /* Publish the response protocol identity. */
            memoryResponse->version =
                KSWORD_ARK_HVM_MEMORY_PROTOCOL_VERSION;
            /* Publish the complete response size. */
            memoryResponse->size = sizeof(*memoryResponse);
            /* Publish stable confirmation-required status. */
            memoryResponse->status =
                KSWORD_ARK_HVM_MEMORY_STATUS_CONFIRMATION_REQUIRED;
            /* Publish the authoritative policy failure. */
            memoryResponse->ntStatus = status;
            /* Publish the fixed completion size. */
            *bytesReturned = sizeof(*memoryResponse);
            /* Release the snapshot before returning the policy failure. */
            ExFreePoolWithTag(
                requestSnapshot,
                KSWORD_ARK_HVM_MEMORY_IOCTL_POOL_TAG);
            /* Return the authoritative policy failure. */
            return status;
        }
    }
    /* Execute the versioned ring -1 memory operation. */
    status = kswordArkHvmMemoryExecute(
        requestSnapshot,
        memoryResponse);
    /* Release the snapshot as soon as the operation no longer needs it. */
    ExFreePoolWithTag(
        requestSnapshot,
        KSWORD_ARK_HVM_MEMORY_IOCTL_POOL_TAG);
    /* Publish the fixed completion size on protocol-level results. */
    *bytesReturned = sizeof(*memoryResponse);
    /* Return the complete ring -1 memory operation result. */
    return status;
}

NTSTATUS kswordArkHvmIoctlNestedPage(
    WDFDEVICE device, WDFREQUEST request, size_t inputBufferLength,
    size_t outputBufferLength, size_t* bytesReturned)
{
    PVOID input = NULL, output = NULL;
    KSWORD_ARK_HVM_NESTED_PAGE_REQUEST* snapshot;
    size_t inputBytes = 0U, outputBytes = 0U;
    NTSTATUS status;
    if (bytesReturned == NULL) { return STATUS_INVALID_PARAMETER; }
    *bytesReturned = 0U;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_INVALID_DEVICE_STATE; }
    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    if (!NT_SUCCESS(status)) { return status; }
    status = WdfRequestRetrieveInputBuffer(request,
        sizeof(KSWORD_ARK_HVM_NESTED_PAGE_REQUEST), &input, &inputBytes);
    if (!NT_SUCCESS(status)) { return status; }
    status = WdfRequestRetrieveOutputBuffer(request,
        sizeof(KSWORD_ARK_HVM_NESTED_PAGE_RESPONSE), &output, &outputBytes);
    if (!NT_SUCCESS(status)) { return status; }
    if (inputBufferLength < sizeof(*snapshot) || inputBytes < sizeof(*snapshot) ||
        outputBufferLength < sizeof(KSWORD_ARK_HVM_NESTED_PAGE_RESPONSE) ||
        outputBytes < sizeof(KSWORD_ARK_HVM_NESTED_PAGE_RESPONSE)) {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    snapshot = (KSWORD_ARK_HVM_NESTED_PAGE_REQUEST*)kswordArkAllocateNonPagedPool(
        sizeof(*snapshot), KSWORD_ARK_HVM_VIEW_IOCTL_POOL_TAG);
    if (snapshot == NULL) { return STATUS_INSUFFICIENT_RESOURCES; }
    RtlCopyMemory(snapshot, input, sizeof(*snapshot));
    if (snapshot->operation != KSWORD_ARK_HVM_NESTED_PAGE_QUERY) {
        KswordArkSafetyContext safety = { 0 };
        safety.operation = KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH;
        safety.contextFlags =
            (snapshot->flags & KSWORD_ARK_HVM_NESTED_PAGE_CONFIRMED) != 0UL
                ? KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED : 0UL;
        safety.targetText = L"Replace one nested guest EPT page";
        safety.targetTextChars = (USHORT)(RTL_NUMBER_OF(L"Replace one nested guest EPT page") - 1U);
        status = kswordArkSafetyEvaluate(device, &safety);
    }
    if (NT_SUCCESS(status)) {
        status = kswordArkHvmNestedPageControl(snapshot,
            (KSWORD_ARK_HVM_NESTED_PAGE_RESPONSE*)output);
        *bytesReturned = sizeof(KSWORD_ARK_HVM_NESTED_PAGE_RESPONSE);
    }
    ExFreePoolWithTag(snapshot, KSWORD_ARK_HVM_VIEW_IOCTL_POOL_TAG);
    return status;
}

NTSTATUS
kswordArkHvmIoctlView(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;
    /* The request carries a full shadow page, too large for the kernel stack. */
    KSWORD_ARK_HVM_VIEW_REQUEST* requestSnapshot = NULL;
    KSWORD_ARK_HVM_VIEW_RESPONSE* viewResponse = NULL;

    /* Reject an invalid completion contract before touching request buffers. */
    if (bytesReturned == NULL) {
        /* Return the exact dispatcher-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* initialize the completion size on every path. */
    *bytesReturned = 0U;
    /* Redirecting real memory accesses requires a write-authorized handle. */
    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    /* Stop before buffer access when handle authorization fails. */
    if (!NT_SUCCESS(status)) {
        /* Return the exact authorization failure. */
        return status;
    }
    /* Retrieve the complete fixed view request. */
    status = WdfRequestRetrieveInputBuffer(
        request,
        sizeof(KSWORD_ARK_HVM_VIEW_REQUEST),
        &inputBuffer,
        &actualInputLength);
    /* Reject truncated or unavailable input buffers. */
    if (!NT_SUCCESS(status) ||
        inputBufferLength < sizeof(KSWORD_ARK_HVM_VIEW_REQUEST) ||
        actualInputLength < sizeof(KSWORD_ARK_HVM_VIEW_REQUEST)) {
        /* Return the exact WDF or fixed-size failure. */
        return NT_SUCCESS(status)
            ? STATUS_INFO_LENGTH_MISMATCH
            : status;
    }
    /* Retrieve the complete fixed view response. */
    status = WdfRequestRetrieveOutputBuffer(
        request,
        sizeof(KSWORD_ARK_HVM_VIEW_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    /* Reject truncated or unavailable output buffers. */
    if (!NT_SUCCESS(status) ||
        outputBufferLength < sizeof(KSWORD_ARK_HVM_VIEW_RESPONSE) ||
        actualOutputLength < sizeof(KSWORD_ARK_HVM_VIEW_RESPONSE)) {
        /* Return the exact WDF or fixed-size failure. */
        return NT_SUCCESS(status)
            ? STATUS_BUFFER_TOO_SMALL
            : status;
    }
    /* Reserve the snapshot before the shared buffer is written. */
    requestSnapshot = (KSWORD_ARK_HVM_VIEW_REQUEST*)
        kswordArkAllocateNonPagedPool(
            sizeof(KSWORD_ARK_HVM_VIEW_REQUEST),
            KSWORD_ARK_HVM_VIEW_IOCTL_POOL_TAG);
    /* Fail before any buffer mutation when the snapshot cannot be reserved. */
    if (requestSnapshot == NULL) {
        /* Return the exact allocation failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /*
     * METHOD_BUFFERED shares one SystemBuffer between input and output, and the
     * view backend zeroes the response before reading the operation, kind,
     * target page and shadow payload.  Without this snapshot it would install a
     * view described by response header bytes.
     */
    RtlCopyMemory(
        requestSnapshot,
        inputBuffer,
        sizeof(*requestSnapshot));
    /* Bind the fixed protocol output view. */
    viewResponse = (KSWORD_ARK_HVM_VIEW_RESPONSE*)outputBuffer;
    /* Apply central high-risk policy to every operation that installs a view. */
    if (requestSnapshot->operation != KSWORD_ARK_HVM_VIEW_OP_QUERY) {
        KswordArkSafetyContext safetyContext = { 0 };

        /* Bind policy auditing to the kernel-patch operation class. */
        safetyContext.operation =
            KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH;
        /* Preserve explicit UI confirmation in central policy evidence. */
        safetyContext.contextFlags =
            (requestSnapshot->flags &
                KSWORD_ARK_HVM_VIEW_FLAG_UI_CONFIRMED) != 0UL
            ? KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED
            : 0UL;
        /* Describe the exact memory redirection class. */
        safetyContext.targetText =
            L"EPT split view redirecting execution or reads to a shadow page";
        /* Publish the exact bounded target text length. */
        safetyContext.targetTextChars =
            (USHORT)(RTL_NUMBER_OF(
                L"EPT split view redirecting execution or reads to a shadow page") -
                1U);
        /* Evaluate central policy without weakening protocol confirmation. */
        status = kswordArkSafetyEvaluate(
            device,
            &safetyContext);
        /* Return a complete confirmation-required response on denial. */
        if (!NT_SUCCESS(status)) {
            /* initialize the complete fixed response. */
            RtlZeroMemory(
                viewResponse,
                sizeof(*viewResponse));
            /* Publish the response protocol identity. */
            viewResponse->version =
                KSWORD_ARK_HVM_VIEW_PROTOCOL_VERSION;
            /* Publish the complete response size. */
            viewResponse->size = sizeof(*viewResponse);
            /* Publish stable confirmation-required status. */
            viewResponse->status =
                KSWORD_ARK_HVM_VIEW_STATUS_CONFIRMATION_REQUIRED;
            /* Publish the authoritative policy failure. */
            viewResponse->lastStatus = status;
            /* Publish the fixed completion size. */
            *bytesReturned = sizeof(*viewResponse);
            /* Release the snapshot before returning the policy failure. */
            ExFreePoolWithTag(
                requestSnapshot,
                KSWORD_ARK_HVM_VIEW_IOCTL_POOL_TAG);
            /* Return the authoritative policy failure. */
            return status;
        }
    }
    /* Execute the versioned EPT view operation. */
    status = kswordArkHvmEptViewControl(
        requestSnapshot,
        viewResponse);
    /* Release the snapshot as soon as the operation no longer needs it. */
    ExFreePoolWithTag(
        requestSnapshot,
        KSWORD_ARK_HVM_VIEW_IOCTL_POOL_TAG);
    /* Publish the fixed completion size on protocol-level results. */
    *bytesReturned = sizeof(*viewResponse);
    /* Return the complete EPT view operation result. */
    return status;
}

NTSTATUS
kswordArkHvmIoctlMsrPolicy(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;
    /* The request is small enough to snapshot on the stack. */
    KSWORD_ARK_HVM_MSR_POLICY_REQUEST requestSnapshot = { 0 };
    KSWORD_ARK_HVM_MSR_POLICY_RESPONSE* policyResponse = NULL;

    /* Reject an invalid completion contract before touching request buffers. */
    if (bytesReturned == NULL) {
        /* Return the exact dispatcher-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* initialize the completion size on every path. */
    *bytesReturned = 0U;
    /* Changing what the guest sees in an MSR needs a write-authorized handle. */
    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    /* Stop before buffer access when handle authorization fails. */
    if (!NT_SUCCESS(status)) {
        /* Return the exact authorization failure. */
        return status;
    }
    /* Retrieve the complete fixed policy request. */
    status = WdfRequestRetrieveInputBuffer(
        request,
        sizeof(KSWORD_ARK_HVM_MSR_POLICY_REQUEST),
        &inputBuffer,
        &actualInputLength);
    /* Reject truncated or unavailable input buffers. */
    if (!NT_SUCCESS(status) ||
        inputBufferLength <
            sizeof(KSWORD_ARK_HVM_MSR_POLICY_REQUEST) ||
        actualInputLength <
            sizeof(KSWORD_ARK_HVM_MSR_POLICY_REQUEST)) {
        /* Return the exact WDF or fixed-size failure. */
        return NT_SUCCESS(status)
            ? STATUS_INFO_LENGTH_MISMATCH
            : status;
    }
    /*
     * METHOD_BUFFERED shares one SystemBuffer between input and output, and the
     * policy backend zeroes the response before reading the operation, index
     * and action.  Snapshot the request before that happens.
     */
    RtlCopyMemory(
        &requestSnapshot,
        inputBuffer,
        sizeof(requestSnapshot));
    /* Retrieve the complete fixed policy response. */
    status = WdfRequestRetrieveOutputBuffer(
        request,
        sizeof(KSWORD_ARK_HVM_MSR_POLICY_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    /* Reject truncated or unavailable output buffers. */
    if (!NT_SUCCESS(status) ||
        outputBufferLength <
            sizeof(KSWORD_ARK_HVM_MSR_POLICY_RESPONSE) ||
        actualOutputLength <
            sizeof(KSWORD_ARK_HVM_MSR_POLICY_RESPONSE)) {
        /* Return the exact WDF or fixed-size failure. */
        return NT_SUCCESS(status)
            ? STATUS_BUFFER_TOO_SMALL
            : status;
    }
    /* Bind the fixed protocol output view. */
    policyResponse =
        (KSWORD_ARK_HVM_MSR_POLICY_RESPONSE*)outputBuffer;
    /* Apply central high-risk policy to every mutating operation. */
    if (requestSnapshot.operation !=
        KSWORD_ARK_HVM_MSR_POLICY_OP_QUERY) {
        KswordArkSafetyContext safetyContext = { 0 };

        /* Bind policy auditing to the kernel-patch operation class. */
        safetyContext.operation =
            KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH;
        /* Preserve explicit UI confirmation in central policy evidence. */
        safetyContext.contextFlags =
            (requestSnapshot.flags &
                KSWORD_ARK_HVM_MSR_POLICY_FLAG_UI_CONFIRMED) != 0UL
            ? KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED
            : 0UL;
        /* Describe the exact interception class. */
        safetyContext.targetText =
            L"Model-specific register interception with denial or faked values";
        /* Publish the exact bounded target text length. */
        safetyContext.targetTextChars =
            (USHORT)(RTL_NUMBER_OF(
                L"Model-specific register interception with denial or faked values") -
                1U);
        /* Evaluate central policy without weakening protocol confirmation. */
        status = kswordArkSafetyEvaluate(
            device,
            &safetyContext);
        /* Return a complete confirmation-required response on denial. */
        if (!NT_SUCCESS(status)) {
            /* initialize the complete fixed response. */
            RtlZeroMemory(
                policyResponse,
                sizeof(*policyResponse));
            /* Publish the response protocol identity. */
            policyResponse->version =
                KSWORD_ARK_HVM_MSR_POLICY_PROTOCOL_VERSION;
            /* Publish the complete response size. */
            policyResponse->size = sizeof(*policyResponse);
            /* Publish stable confirmation-required status. */
            policyResponse->status =
                KSWORD_ARK_HVM_MSR_POLICY_STATUS_CONFIRMATION_REQUIRED;
            /* Publish the authoritative policy failure. */
            policyResponse->lastStatus = status;
            /* Publish the fixed completion size. */
            *bytesReturned = sizeof(*policyResponse);
            /* Return the authoritative policy failure. */
            return status;
        }
    }
    /* Execute the versioned MSR policy operation. */
    status = kswordArkHvmMsrPolicyControl(
        &requestSnapshot,
        policyResponse);
    /* Publish the fixed completion size on protocol-level results. */
    *bytesReturned = sizeof(*policyResponse);
    /* Return the complete MSR policy operation result. */
    return status;
}

NTSTATUS
kswordArkHvmIoctlCrPolicy(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;
    /* The request is small enough to snapshot on the stack. */
    KSWORD_ARK_HVM_CR_POLICY_REQUEST requestSnapshot = { 0 };
    KSWORD_ARK_HVM_CR_POLICY_RESPONSE* policyResponse = NULL;

    /* Reject an invalid completion contract before touching request buffers. */
    if (bytesReturned == NULL) {
        /* Return the exact dispatcher-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* initialize the completion size on every path. */
    *bytesReturned = 0U;
    /* Pinning control-register bits needs a write-authorized handle. */
    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    /* Stop before buffer access when handle authorization fails. */
    if (!NT_SUCCESS(status)) {
        /* Return the exact authorization failure. */
        return status;
    }
    /* Retrieve the complete fixed policy request. */
    status = WdfRequestRetrieveInputBuffer(
        request,
        sizeof(KSWORD_ARK_HVM_CR_POLICY_REQUEST),
        &inputBuffer,
        &actualInputLength);
    /* Reject truncated or unavailable input buffers. */
    if (!NT_SUCCESS(status) ||
        inputBufferLength <
            sizeof(KSWORD_ARK_HVM_CR_POLICY_REQUEST) ||
        actualInputLength <
            sizeof(KSWORD_ARK_HVM_CR_POLICY_REQUEST)) {
        /* Return the exact WDF or fixed-size failure. */
        return NT_SUCCESS(status)
            ? STATUS_INFO_LENGTH_MISMATCH
            : status;
    }
    /*
     * METHOD_BUFFERED shares one SystemBuffer between input and output, and the
     * policy backend zeroes the response before reading the masks.  Snapshot
     * the request before that happens.
     */
    RtlCopyMemory(
        &requestSnapshot,
        inputBuffer,
        sizeof(requestSnapshot));
    /* Retrieve the complete fixed policy response. */
    status = WdfRequestRetrieveOutputBuffer(
        request,
        sizeof(KSWORD_ARK_HVM_CR_POLICY_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    /* Reject truncated or unavailable output buffers. */
    if (!NT_SUCCESS(status) ||
        outputBufferLength <
            sizeof(KSWORD_ARK_HVM_CR_POLICY_RESPONSE) ||
        actualOutputLength <
            sizeof(KSWORD_ARK_HVM_CR_POLICY_RESPONSE)) {
        /* Return the exact WDF or fixed-size failure. */
        return NT_SUCCESS(status)
            ? STATUS_BUFFER_TOO_SMALL
            : status;
    }
    /* Bind the fixed protocol output view. */
    policyResponse =
        (KSWORD_ARK_HVM_CR_POLICY_RESPONSE*)outputBuffer;
    /* Apply central high-risk policy to every mutating operation. */
    if (requestSnapshot.operation !=
        KSWORD_ARK_HVM_CR_POLICY_OP_QUERY) {
        KswordArkSafetyContext safetyContext = { 0 };

        /* Bind policy auditing to the kernel-patch operation class. */
        safetyContext.operation =
            KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH;
        /* Preserve explicit UI confirmation in central policy evidence. */
        safetyContext.contextFlags =
            (requestSnapshot.flags &
                KSWORD_ARK_HVM_CR_POLICY_FLAG_UI_CONFIRMED) != 0UL
            ? KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED
            : 0UL;
        /* Describe the exact interception class. */
        safetyContext.targetText =
            L"Control-register pinning and address-space switch interception";
        /* Publish the exact bounded target text length. */
        safetyContext.targetTextChars =
            (USHORT)(RTL_NUMBER_OF(
                L"Control-register pinning and address-space switch interception") -
                1U);
        /* Evaluate central policy without weakening protocol confirmation. */
        status = kswordArkSafetyEvaluate(
            device,
            &safetyContext);
        /* Return a complete confirmation-required response on denial. */
        if (!NT_SUCCESS(status)) {
            /* initialize the complete fixed response. */
            RtlZeroMemory(
                policyResponse,
                sizeof(*policyResponse));
            /* Publish the response protocol identity. */
            policyResponse->version =
                KSWORD_ARK_HVM_CR_POLICY_PROTOCOL_VERSION;
            /* Publish the complete response size. */
            policyResponse->size = sizeof(*policyResponse);
            /* Publish stable confirmation-required status. */
            policyResponse->status =
                KSWORD_ARK_HVM_CR_POLICY_STATUS_CONFIRMATION_REQUIRED;
            /* Publish the authoritative policy failure. */
            policyResponse->lastStatus = status;
            /* Publish the fixed completion size. */
            *bytesReturned = sizeof(*policyResponse);
            /* Return the authoritative policy failure. */
            return status;
        }
    }
    /* Execute the versioned control-register policy operation. */
    status = kswordArkHvmCrPolicyControl(
        &requestSnapshot,
        policyResponse);
    /* Publish the fixed completion size on protocol-level results. */
    *bytesReturned = sizeof(*policyResponse);
    /* Return the complete control-register policy operation result. */
    return status;
}

NTSTATUS
kswordArkHvmIoctlDomain(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;
    /* The request is small enough to snapshot on the stack. */
    KSWORD_ARK_HVM_DOMAIN_REQUEST requestSnapshot = { 0 };
    KSWORD_ARK_HVM_DOMAIN_RESPONSE* domainResponse = NULL;

    /* Reject an invalid completion contract before touching request buffers. */
    if (bytesReturned == NULL) {
        /* Return the exact dispatcher-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* initialize the completion size on every path. */
    *bytesReturned = 0U;
    /* Publishing a switchable view to guest code needs write authorization. */
    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    /* Stop before buffer access when handle authorization fails. */
    if (!NT_SUCCESS(status)) {
        /* Return the exact authorization failure. */
        return status;
    }
    /* Retrieve the complete fixed domain request. */
    status = WdfRequestRetrieveInputBuffer(
        request,
        sizeof(KSWORD_ARK_HVM_DOMAIN_REQUEST),
        &inputBuffer,
        &actualInputLength);
    /* Reject truncated or unavailable input buffers. */
    if (!NT_SUCCESS(status) ||
        inputBufferLength < sizeof(KSWORD_ARK_HVM_DOMAIN_REQUEST) ||
        actualInputLength < sizeof(KSWORD_ARK_HVM_DOMAIN_REQUEST)) {
        /* Return the exact WDF or fixed-size failure. */
        return NT_SUCCESS(status)
            ? STATUS_INFO_LENGTH_MISMATCH
            : status;
    }
    /*
     * METHOD_BUFFERED shares one SystemBuffer between input and output, and
     * the domain backend zeroes the response before reading the operation,
     * target index and range.  Snapshot the request before that happens.
     */
    RtlCopyMemory(
        &requestSnapshot,
        inputBuffer,
        sizeof(requestSnapshot));
    /* Retrieve the complete fixed domain response. */
    status = WdfRequestRetrieveOutputBuffer(
        request,
        sizeof(KSWORD_ARK_HVM_DOMAIN_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    /* Reject truncated or unavailable output buffers. */
    if (!NT_SUCCESS(status) ||
        outputBufferLength < sizeof(KSWORD_ARK_HVM_DOMAIN_RESPONSE) ||
        actualOutputLength < sizeof(KSWORD_ARK_HVM_DOMAIN_RESPONSE)) {
        /* Return the exact WDF or fixed-size failure. */
        return NT_SUCCESS(status)
            ? STATUS_BUFFER_TOO_SMALL
            : status;
    }
    /* Bind the fixed protocol output view. */
    domainResponse = (KSWORD_ARK_HVM_DOMAIN_RESPONSE*)outputBuffer;
    /* Apply central high-risk policy to every mutating operation. */
    if (requestSnapshot.operation != KSWORD_ARK_HVM_DOMAIN_OP_QUERY) {
        KswordArkSafetyContext safetyContext = { 0 };

        /* Bind policy auditing to the kernel-patch operation class. */
        safetyContext.operation =
            KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH;
        /* Preserve explicit UI confirmation in central policy evidence. */
        safetyContext.contextFlags =
            (requestSnapshot.flags &
                KSWORD_ARK_HVM_DOMAIN_FLAG_UI_CONFIRMED) != 0UL
            ? KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED
            : 0UL;
        /* Describe what makes this class of change consequential. */
        safetyContext.targetText =
            L"EPT domain published to unprivileged guest code through VMFUNC";
        /* Publish the exact bounded target text length. */
        safetyContext.targetTextChars =
            (USHORT)(RTL_NUMBER_OF(
                L"EPT domain published to unprivileged guest code through VMFUNC") -
                1U);
        /* Evaluate central policy without weakening protocol confirmation. */
        status = kswordArkSafetyEvaluate(
            device,
            &safetyContext);
        /* Return a complete confirmation-required response on denial. */
        if (!NT_SUCCESS(status)) {
            /* initialize the complete fixed response. */
            RtlZeroMemory(
                domainResponse,
                sizeof(*domainResponse));
            /* Publish the response protocol identity. */
            domainResponse->version =
                KSWORD_ARK_HVM_DOMAIN_PROTOCOL_VERSION;
            /* Publish the complete response size. */
            domainResponse->size = sizeof(*domainResponse);
            /* Publish stable confirmation-required status. */
            domainResponse->status =
                KSWORD_ARK_HVM_DOMAIN_STATUS_CONFIRMATION_REQUIRED;
            /* Publish the authoritative policy failure. */
            domainResponse->lastStatus = status;
            /* Publish the fixed completion size. */
            *bytesReturned = sizeof(*domainResponse);
            /* Return the authoritative policy failure. */
            return status;
        }
    }
    /* Execute the versioned EPT domain operation. */
    status = kswordArkHvmEptDomainControl(
        &requestSnapshot,
        domainResponse);
    /* Publish the fixed completion size on protocol-level results. */
    *bytesReturned = sizeof(*domainResponse);
    /* Return the complete EPT domain operation result. */
    return status;
}

NTSTATUS
kswordArkHvmIoctlProcess(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;
    /* The request is small enough for the snapshot to be placed on the stack. */
    KSWORD_ARK_HVM_PROCESS_REQUEST requestSnapshot = { 0 };
    KSWORD_ARK_HVM_PROCESS_RESPONSE* processResponse = NULL;

    /* Reject incomplete dispatch contracts before touching any request buffer. */
    if (bytesReturned == NULL) {
        /* Return explicit dispatch contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* initialize the completion length on every path first. */
    *bytesReturned = 0U;
    /* Freezing or terminating a process requires write authorization. */
    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    /* Stop before touching the buffer if handle authorization fails. */
    if (!NT_SUCCESS(status)) {
        /* Return explicit authorization failure. */
        return status;
    }
    /* Retrieve complete fixed-length request. */
    status = WdfRequestRetrieveInputBuffer(
        request,
        sizeof(KSWORD_ARK_HVM_PROCESS_REQUEST),
        &inputBuffer,
        &actualInputLength);
    /* Reject truncated or unavailable input buffers. */
    if (!NT_SUCCESS(status) ||
        inputBufferLength < sizeof(KSWORD_ARK_HVM_PROCESS_REQUEST) ||
        actualInputLength < sizeof(KSWORD_ARK_HVM_PROCESS_REQUEST)) {
        /* Return explicit WDF or fixed-length failure. */
        return NT_SUCCESS(status)
            ? STATUS_INFO_LENGTH_MISMATCH
            : status;
    }
    /*
     * METHOD_BUFFERED causes input and output to share the same SystemBuffer, and the backend clears the response
     * before reading the opcode, PID, and linear address. Therefore, the request snapshot must be captured first.
     */
    RtlCopyMemory(
        &requestSnapshot,
        inputBuffer,
        sizeof(requestSnapshot));
    /* Retrieve complete fixed-length response. */
    status = WdfRequestRetrieveOutputBuffer(
        request,
        sizeof(KSWORD_ARK_HVM_PROCESS_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    /* Reject truncated or unavailable output buffers. */
    if (!NT_SUCCESS(status) ||
        outputBufferLength < sizeof(KSWORD_ARK_HVM_PROCESS_RESPONSE) ||
        actualOutputLength < sizeof(KSWORD_ARK_HVM_PROCESS_RESPONSE)) {
        /* Return explicit WDF or fixed-length failure. */
        return NT_SUCCESS(status)
            ? STATUS_BUFFER_TOO_SMALL
            : status;
    }
    /* Bind fixed-length protocol output view. */
    processResponse =
        (KSWORD_ARK_HVM_PROCESS_RESPONSE*)outputBuffer;
    /*
     * Every operation that changes state must pass through the central high-risk policy.
     *
     * Two read-only operations are handled outside. QUERY and RESOLVE_CR3 do not modify any state. This policy treats
     * all non-FREEZE operations as process termination. Missing a single read-only operation does not incur the cost of
     * an extra confirmation, but rather causes a table lookup to be recorded as a process termination in the evidence.
     */
    if (requestSnapshot.operation !=
            KSWORD_ARK_HVM_PROCESS_OP_QUERY &&
        requestSnapshot.operation !=
            KSWORD_ARK_HVM_PROCESS_OP_RESOLVE_CR3) {
        KswordArkSafetyContext safetyContext = { 0 };

        /*
         * Classify by operation type, rather than grouping everything as 'terminate process'.
         *
         * Central policy is configured by operation category. Reporting a freeze as termination would let a termination-only
         * rule block freezing, or vice versa. Either mistake makes the policy behave differently from its configuration.
         */
        safetyContext.operation =
            (requestSnapshot.operation ==
                KSWORD_ARK_HVM_PROCESS_OP_FREEZE)
            ? KSWORD_ARK_SAFETY_OPERATION_PROCESS_SUSPEND
            : KSWORD_ARK_SAFETY_OPERATION_PROCESS_TERMINATE;
        /* Persist explicit UI confirmation into central policy evidence. */
        safetyContext.contextFlags =
            (requestSnapshot.flags &
                KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED) != 0UL
            ? KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED
            : 0UL;
        /* Clarify why this class of changes has consequences. */
        safetyContext.targetText =
            L"R-1 execution denial scoped to one guest address space";
        /* Publish the exact fixed-length target text length. */
        safetyContext.targetTextChars =
            (USHORT)(RTL_NUMBER_OF(
                L"R-1 execution denial scoped to one guest address space") -
                1U);
        /* Evaluate central policy without weakening protocol confirmation. */
        status = kswordArkSafetyEvaluate(
            device,
            &safetyContext);
        /* Return a complete 'needs confirmation' response when rejected. */
        if (!NT_SUCCESS(status)) {
            /* initialize the complete fixed-length response. */
            RtlZeroMemory(
                processResponse,
                sizeof(*processResponse));
            /* Publish response protocol identity. */
            processResponse->version =
                KSWORD_ARK_HVM_PROCESS_PROTOCOL_VERSION;
            /* Publish the full response length. */
            processResponse->size = sizeof(*processResponse);
            /* Publish the stable 'confirmation required' status. */
            processResponse->status =
                KSWORD_ARK_HVM_PROCESS_STATUS_CONFIRMATION_REQUIRED;
            /* Failed to publish authoritative policy status code. */
            processResponse->lastStatus = status;
            /* Publish fixed-length completion size. */
            *bytesReturned = sizeof(*processResponse);
            /* Return authoritative policy failure. */
            return status;
        }
    }
    /* Execute a versioned process handling operation. */
    status = kswordArkHvmProcessControl(
        &requestSnapshot,
        processResponse);
    /* Protocol layer results always report a fixed-length completion size. */
    *bytesReturned = sizeof(*processResponse);
    /*
     * Semantic-layer denials must complete with a protocol-layer success; otherwise, the response will not be returned.
     *
     * The backend returns a genuine NTSTATUS failure code for cases like 'target protected' or 'prerequisites not met'.
     * Pass through unchanged so the I/O manager does not copy back the output buffer—the
     * caller receives returned=0 plus a generic Win32 code, while the protocol status code
     * that actually explains the reason resides in the buffer that was not copied back.
     *
     * The response is already populated with its own conclusion, so this always returns success. Failures occurring before the protocol
     * layer, such as buffer retrieval failure or authorization failure, are returned as-is since no response exists in those cases.
     */
    UNREFERENCED_PARAMETER(status);
    /* Returns the complete result of the process disposal operation. */
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkHvmIoctlInject(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;
    /*
     * The request carries a full page of payload and is too large for the stack; allocate a separate snapshot.
     *
     * The snapshot remains mandatory: METHOD_BUFFERED causes input and output to share the same
     * SystemBuffer, and the backend clears the response before reading the opcode and payload.
     * Without an initial snapshot, the payload read would be the zeroed-out data just cleared.
     */
    KSWORD_ARK_HVM_INJECT_REQUEST* requestSnapshot = NULL;
    KSWORD_ARK_HVM_INJECT_RESPONSE* injectResponse = NULL;

    if (bytesReturned == NULL) {
        /* Return explicit dispatch contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;
    /* Writing executable code into another process requires write authorization. */
    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    if (!NT_SUCCESS(status)) {
        /* Return explicit authorization failure. */
        return status;
    }
    status = WdfRequestRetrieveInputBuffer(
        request,
        sizeof(KSWORD_ARK_HVM_INJECT_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status) ||
        inputBufferLength < sizeof(KSWORD_ARK_HVM_INJECT_REQUEST) ||
        actualInputLength < sizeof(KSWORD_ARK_HVM_INJECT_REQUEST)) {
        /* Return explicit WDF or fixed-length failure. */
        return NT_SUCCESS(status)
            ? STATUS_INFO_LENGTH_MISMATCH
            : status;
    }
    requestSnapshot = (KSWORD_ARK_HVM_INJECT_REQUEST*)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(KSWORD_ARK_HVM_INJECT_REQUEST),
        'qnIK');
    if (requestSnapshot == NULL) {
        /* Return explicit resource failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(
        requestSnapshot,
        inputBuffer,
        sizeof(*requestSnapshot));
    status = WdfRequestRetrieveOutputBuffer(
        request,
        sizeof(KSWORD_ARK_HVM_INJECT_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status) ||
        outputBufferLength < sizeof(KSWORD_ARK_HVM_INJECT_RESPONSE) ||
        actualOutputLength < sizeof(KSWORD_ARK_HVM_INJECT_RESPONSE)) {
        ExFreePool(requestSnapshot);
        /* Return explicit WDF or fixed-length failure. */
        return NT_SUCCESS(status)
            ? STATUS_BUFFER_TOO_SMALL
            : status;
    }
    injectResponse =
        (KSWORD_ARK_HVM_INJECT_RESPONSE*)outputBuffer;
    /* Every operation that changes state must pass through the central high-risk policy. */
    if (requestSnapshot->operation !=
            KSWORD_ARK_HVM_INJECT_OP_QUERY) {
        KswordArkSafetyContext safetyContext = { 0 };

        safetyContext.operation =
            KSWORD_ARK_SAFETY_OPERATION_PROCESS_INJECT;
        safetyContext.contextFlags =
            (requestSnapshot->flags &
                KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED) != 0UL
            ? KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED
            : 0UL;
        safetyContext.targetText =
            L"R-1 code injection into one guest address space";
        safetyContext.targetTextChars =
            (USHORT)(RTL_NUMBER_OF(
                L"R-1 code injection into one guest address space") -
                1U);
        status = kswordArkSafetyEvaluate(
            device,
            &safetyContext);
        if (!NT_SUCCESS(status)) {
            RtlZeroMemory(
                injectResponse,
                sizeof(*injectResponse));
            injectResponse->version =
                KSWORD_ARK_HVM_INJECT_PROTOCOL_VERSION;
            injectResponse->size = sizeof(*injectResponse);
            injectResponse->status =
                KSWORD_ARK_HVM_INJECT_STATUS_INVALID_REQUEST;
            injectResponse->lastStatus = status;
            *bytesReturned = sizeof(*injectResponse);
            ExFreePool(requestSnapshot);
            /* Return authoritative policy failure. */
            return status;
        }
    }
    status = kswordArkHvmInjectControl(
        requestSnapshot,
        injectResponse);
    ExFreePool(requestSnapshot);
    *bytesReturned = sizeof(*injectResponse);
    /* Align with the process handling rule: the semantic layer rejects completion via the protocol layer, so the response can only be returned. */
    UNREFERENCED_PARAMETER(status);
    /* Return: Complete injection operation result. */
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkHvmIoctlNestedProbe(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;
    /*
     * METHOD_BUFFERED causes input and output to share a single SystemBuffer, and the backend's first action is to zero the response.
     * Without a prior snapshot, the read request is the zeroed-out data just cleared. The request is small, so it is placed on the stack.
     */
    KSWORD_ARK_HVM_NESTED_PROBE_REQUEST requestSnapshot = { 0 };
    KSWORD_ARK_HVM_NESTED_PROBE_RESPONSE* probeResponse = NULL;

    UNREFERENCED_PARAMETER(device);
    if (bytesReturned == NULL) {
        /* Return explicit dispatch contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;
    /* Self-test executes VMX instructions and temporarily modifies CR4 within the guest, so it is guarded by write access checks. */
    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    if (!NT_SUCCESS(status)) {
        /* Return explicit authorization failure. */
        return status;
    }
    status = WdfRequestRetrieveInputBuffer(
        request,
        sizeof(requestSnapshot),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status) ||
        inputBufferLength < sizeof(requestSnapshot) ||
        actualInputLength < sizeof(requestSnapshot)) {
        /* Return explicit WDF or fixed-length failure. */
        return NT_SUCCESS(status)
            ? STATUS_INFO_LENGTH_MISMATCH
            : status;
    }
    RtlCopyMemory(
        &requestSnapshot,
        inputBuffer,
        sizeof(requestSnapshot));
    status = WdfRequestRetrieveOutputBuffer(
        request,
        sizeof(KSWORD_ARK_HVM_NESTED_PROBE_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status) ||
        outputBufferLength <
            sizeof(KSWORD_ARK_HVM_NESTED_PROBE_RESPONSE) ||
        actualOutputLength <
            sizeof(KSWORD_ARK_HVM_NESTED_PROBE_RESPONSE)) {
        /* Return explicit WDF or fixed-length failure. */
        return NT_SUCCESS(status)
            ? STATUS_BUFFER_TOO_SMALL
            : status;
    }
    probeResponse =
        (KSWORD_ARK_HVM_NESTED_PROBE_RESPONSE*)outputBuffer;
    (void)kswordArkHvmNestedProbeRun(
        &requestSnapshot,
        probeResponse);
    *bytesReturned = sizeof(*probeResponse);
    /*
     * Semantic result delivered successfully at the protocol layer.
     *
     * Returning a failure NTSTATUS causes the I/O manager to skip copying the output buffer, resulting in the loss of all incremental
     * results; the caller receives only a generic Win32 error code. The entire value of this command lies in those incremental results.
     */
    return STATUS_SUCCESS;
}
