/*++

Module Name:

    safety_policy.c

Abstract:

    Phase-15 centralized dangerous-operation safety policy.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"

#include <ntstrsafe.h>

#ifndef STATUS_REQUEST_NOT_ACCEPTED
#define STATUS_REQUEST_NOT_ACCEPTED ((NTSTATUS)0xC00000D0L)
#endif

#define KSWORD_ARK_SAFETY_MAX_USER_PID 0xFFFFFFF0UL

typedef struct KswordArkSafetyState
{
    EX_PUSH_LOCK lock;
    ULONG policyFlags;
    ULONG generation;
    ULONG lastOperation;
    ULONG lastDecision;
    ULONG lastReason;
    ULONG lastRiskLevel;
    ULONG lastTargetProcessId;
    NTSTATUS lastStatus;
    ULONGLONG allowedCount;
    ULONGLONG deniedCount;
    ULONGLONG auditOnlyCount;
    WCHAR lastTargetText[KSWORD_ARK_SAFETY_TEXT_MAX_CHARS];
} KswordArkSafetyState;

static KswordArkSafetyState gKswordArkSafetyState;

static VOID
kswordArkSafetyCopyWideText(
    _Out_writes_(destinationChars) PWSTR destination,
    _In_ USHORT destinationChars,
    _In_reads_opt_(sourceChars) PCWSTR source,
    _In_ USHORT sourceChars
    )
/*++

Routine Description:

    Copy safety target text. Note: All audit text has a fixed length and is
    forced to be NUL-terminated to prevent log/response parsing buffer overruns.

Arguments:

    Destination - Target buffer.
    DestinationChars: Target character capacity.
    Source - source text, may be null.
    SourceChars - Number of source characters.

Return Value:

    None. This function has no return value.

--*/
{
    USHORT copyChars = 0U;

    if (destination == NULL || destinationChars == 0U) {
        return;
    }

    destination[0] = L'\0';
    if (source == NULL || sourceChars == 0U) {
        return;
    }

    copyChars = sourceChars;
    if (copyChars >= destinationChars) {
        copyChars = destinationChars - 1U;
    }
    RtlCopyMemory(destination, source, (SIZE_T)copyChars * sizeof(WCHAR));
    destination[copyChars] = L'\0';
}

static ULONG
kswordArkSafetyRequiredPolicyFlagForOperation(
    _In_ ULONG operation
    )
/*++

Routine Description:

    Map dangerous operations to policy-allowed bits. Note: All features must obtain
    unified switch semantics through here instead of judging policies independently.

Arguments:

    Operation - KSWORD_ARK_SAFETY_OPERATION_*。

Return Value:

    Corresponds to KSWORD_ARK_SAFETY_POLICY_FLAG_*; unknown operations return 0.

--*/
{
    switch (operation) {
    case KSWORD_ARK_SAFETY_OPERATION_PROCESS_TERMINATE:
        return KSWORD_ARK_SAFETY_POLICY_FLAG_ALLOW_PROCESS_TERMINATE;
    case KSWORD_ARK_SAFETY_OPERATION_PROCESS_SUSPEND:
        return KSWORD_ARK_SAFETY_POLICY_FLAG_ALLOW_PROCESS_SUSPEND;
    case KSWORD_ARK_SAFETY_OPERATION_PROCESS_SET_PROTECTION:
        return KSWORD_ARK_SAFETY_POLICY_FLAG_ALLOW_PROCESS_PROTECTION;
    case KSWORD_ARK_SAFETY_OPERATION_FILE_DELETE:
        return KSWORD_ARK_SAFETY_POLICY_FLAG_ALLOW_FILE_DELETE;
    case KSWORD_ARK_SAFETY_OPERATION_CALLBACK_SET_RULES:
    case KSWORD_ARK_SAFETY_OPERATION_CALLBACK_REMOVE_EXTERNAL:
    case KSWORD_ARK_SAFETY_OPERATION_CALLBACK_CANCEL_PENDING:
        return KSWORD_ARK_SAFETY_POLICY_FLAG_ALLOW_CALLBACK_CONTROL;
    case KSWORD_ARK_SAFETY_OPERATION_MEMORY_WRITE:
        return KSWORD_ARK_SAFETY_POLICY_FLAG_ALLOW_MEMORY_WRITE;
    case KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH:
        return KSWORD_ARK_SAFETY_POLICY_FLAG_ALLOW_KERNEL_PATCH;
    case KSWORD_ARK_SAFETY_OPERATION_DRIVER_UNLOAD:
        return KSWORD_ARK_SAFETY_POLICY_FLAG_ALLOW_DRIVER_UNLOAD;
    case KSWORD_ARK_SAFETY_OPERATION_PROCESS_INJECT:
        return KSWORD_ARK_SAFETY_POLICY_FLAG_ALLOW_PROCESS_INJECT;
    case KSWORD_ARK_SAFETY_OPERATION_DRIVER_THREAD_CONTROL:
        return KSWORD_ARK_SAFETY_POLICY_FLAG_ALLOW_DRIVER_THREAD_CONTROL;
    case KSWORD_ARK_SAFETY_OPERATION_FIRMWARE_RETURN:
        return KSWORD_ARK_SAFETY_POLICY_FLAG_ALLOW_FIRMWARE_RETURN;
    case KSWORD_ARK_SAFETY_OPERATION_RAW_DISK_WRITE:
        return KSWORD_ARK_SAFETY_POLICY_FLAG_ALLOW_RAW_DISK_WRITE;
    default:
        return 0UL;
    }
}

static ULONG
kswordArkSafetyRiskForOperation(
    _In_ ULONG operation
    )
/*++

Routine Description:

    Assign a default risk level to dangerous operations. Note: High-risk operations require UI confirmation or a legacy
    compatibility confirmation bit; after R3 supports explicit confirmation, legacy compatibility can be disabled.

Arguments:

    Operation - KSWORD_ARK_SAFETY_OPERATION_*。

Return Value:

    KSWORD_ARK_SAFETY_RISK_*。

--*/
{
    switch (operation) {
    case KSWORD_ARK_SAFETY_OPERATION_PROCESS_TERMINATE:
    case KSWORD_ARK_SAFETY_OPERATION_PROCESS_SET_PROTECTION:
    case KSWORD_ARK_SAFETY_OPERATION_CALLBACK_REMOVE_EXTERNAL:
    case KSWORD_ARK_SAFETY_OPERATION_MEMORY_WRITE:
    case KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH:
    case KSWORD_ARK_SAFETY_OPERATION_DRIVER_UNLOAD:
    case KSWORD_ARK_SAFETY_OPERATION_PROCESS_INJECT:
        return KSWORD_ARK_SAFETY_RISK_HIGH;
    case KSWORD_ARK_SAFETY_OPERATION_FILE_DELETE:
    case KSWORD_ARK_SAFETY_OPERATION_PROCESS_SUSPEND:
    case KSWORD_ARK_SAFETY_OPERATION_CALLBACK_SET_RULES:
        return KSWORD_ARK_SAFETY_RISK_MEDIUM;
    case KSWORD_ARK_SAFETY_OPERATION_CALLBACK_CANCEL_PENDING:
        return KSWORD_ARK_SAFETY_RISK_LOW;
    case KSWORD_ARK_SAFETY_OPERATION_DRIVER_THREAD_CONTROL:
    case KSWORD_ARK_SAFETY_OPERATION_FIRMWARE_RETURN:
    case KSWORD_ARK_SAFETY_OPERATION_RAW_DISK_WRITE:
        return KSWORD_ARK_SAFETY_RISK_CRITICAL;
    default:
        return KSWORD_ARK_SAFETY_RISK_CRITICAL;
    }
}

static BOOLEAN
kswordArkSafetyIsCriticalProcessId(
    _In_ ULONG processId
    )
/*++

Routine Description:

    Check if the target PID belongs to the default prohibited critical range. Note: The first version uses stable
    system PIDs for protection to avoid mistakenly terminating core processes like Idle, System, or session management.

Arguments:

    ProcessId - target PID.

Return Value:

    TRUE indicates default denial.

--*/
{
    if (processId == 0UL || processId == 4UL) {
        return TRUE;
    }
    if (processId > KSWORD_ARK_SAFETY_MAX_USER_PID) {
        return TRUE;
    }
    return FALSE;
}

static VOID
kswordArkSafetyRecordDecisionLocked(
    _In_ const KswordArkSafetyContext* context,
    _In_ ULONG decision,
    _In_ ULONG reason,
    _In_ ULONG riskLevel,
    _In_ NTSTATUS status
    )
/*++

Routine Description:

    Record the most recent safety decision. Note: The caller already holds the write
    lock, so this function performs only structure updates without re-acquiring the lock.

Arguments:

    Context - Operation context.
    Decision - allow/deny/audit-only。
    Reason - unified reason code.
    RiskLevel - Risk level.
    Status - Status code returned to the caller.

Return Value:

    None. This function has no return value.

--*/
{
    gKswordArkSafetyState.lastOperation = context->operation;
    gKswordArkSafetyState.lastDecision = decision;
    gKswordArkSafetyState.lastReason = reason;
    gKswordArkSafetyState.lastRiskLevel = riskLevel;
    gKswordArkSafetyState.lastTargetProcessId = context->targetProcessId;
    gKswordArkSafetyState.lastStatus = status;
    kswordArkSafetyCopyWideText(
        gKswordArkSafetyState.lastTargetText,
        KSWORD_ARK_SAFETY_TEXT_MAX_CHARS,
        context->targetText,
        context->targetTextChars);

    if (decision == KSWORD_ARK_SAFETY_DECISION_DENY) {
        gKswordArkSafetyState.deniedCount += 1ULL;
    }
    else if (decision == KSWORD_ARK_SAFETY_DECISION_AUDIT_ONLY_ALLOW) {
        gKswordArkSafetyState.auditOnlyCount += 1ULL;
    }
    else {
        gKswordArkSafetyState.allowedCount += 1ULL;
    }
}

static VOID
kswordArkSafetyLogDecision(
    _In_opt_ WDFDEVICE device,
    _In_ const KswordArkSafetyContext* context,
    _In_ ULONG decision,
    _In_ ULONG reason,
    _In_ ULONG riskLevel,
    _In_ NTSTATUS status
    )
/*++

Routine Description:

    Output safety decision audit log. Note: Logs are generated centrally in the policy
    module; the feature layer no longer concatenates policy reasons individually.

Arguments:

    Device - The WDF device object.
    Context - Operation context.
    Decision - The decision result.
    Reason - Reason code.
    RiskLevel - Risk level.
    Status - Return status.

Return Value:

    None. This function has no return value.

--*/
{
    CHAR logMessage[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
    PCSTR levelText = (decision == KSWORD_ARK_SAFETY_DECISION_DENY) ? "Warn" : "Info";

    (VOID)RtlStringCbPrintfA(
        logMessage,
        sizeof(logMessage),
        "Safety decision: op=%lu, pid=%lu, risk=%lu, decision=%lu, reason=%lu, status=0x%08X.",
        (unsigned long)context->operation,
        (unsigned long)context->targetProcessId,
        (unsigned long)riskLevel,
        (unsigned long)decision,
        (unsigned long)reason,
        (unsigned int)status);
    if (device != WDF_NO_HANDLE) {
        (VOID)kswordArkDriverEnqueueLogFrame(device, levelText, logMessage);
    }
}

VOID
kswordArkSafetyInitialize(
    VOID
    )
/*++

Routine Description:

    initialize the central safety policy. Note: Advanced mode is enabled by default, and legacy compatibility is not explicitly
    confirmed to ensure existing R3 workflows are not disrupted before completion, while all operations still enter audit.

Arguments:

    None.

Return Value:

    None. This function has no return value.

--*/
{
    RtlZeroMemory(&gKswordArkSafetyState, sizeof(gKswordArkSafetyState));
    ExInitializePushLock(&gKswordArkSafetyState.lock);
    gKswordArkSafetyState.policyFlags = KSWORD_ARK_SAFETY_POLICY_FLAG_DEFAULT;
    gKswordArkSafetyState.generation = 1UL;
    gKswordArkSafetyState.lastStatus = STATUS_SUCCESS;
}

NTSTATUS
kswordArkSafetyEvaluate(
    _In_opt_ WDFDEVICE device,
    _In_ const KswordArkSafetyContext* context
    )
/*++

Routine Description:

    Unified evaluation of whether dangerous operations are permitted. Note: All mutating IOCTL handlers must call
    this function before performing actual actions; on rejection, return a failure status and write to the audit log.

Arguments:

    Device: WDF device object, used for logging.
    Context - Dangerous operation context.

Return Value:

    STATUS_SUCCESS indicates allowed; failure indicates policy denial.

--*/
{
    ULONG policyFlags = 0UL;
    ULONG requiredFlag = 0UL;
    ULONG decision = KSWORD_ARK_SAFETY_DECISION_ALLOW;
    ULONG reason = KSWORD_ARK_SAFETY_REASON_NONE;
    ULONG riskLevel = KSWORD_ARK_SAFETY_RISK_CRITICAL;
    NTSTATUS status = STATUS_SUCCESS;

    if (context == NULL || context->operation == KSWORD_ARK_SAFETY_OPERATION_NONE) {
        return STATUS_INVALID_PARAMETER;
    }

    kswordArkAcquirePushLockExclusive(&gKswordArkSafetyState.lock);
    policyFlags = gKswordArkSafetyState.policyFlags;
    requiredFlag = kswordArkSafetyRequiredPolicyFlagForOperation(context->operation);
    riskLevel = kswordArkSafetyRiskForOperation(context->operation);

    if ((policyFlags & KSWORD_ARK_SAFETY_POLICY_FLAG_ACTIVE) == 0UL) {
        decision = KSWORD_ARK_SAFETY_DECISION_DENY;
        reason = KSWORD_ARK_SAFETY_REASON_POLICY_INACTIVE;
        status = STATUS_ACCESS_DENIED;
    }
    else if (requiredFlag == 0UL || (policyFlags & requiredFlag) == 0UL) {
        decision = KSWORD_ARK_SAFETY_DECISION_DENY;
        reason = KSWORD_ARK_SAFETY_REASON_OPERATION_DISABLED;
        status = STATUS_ACCESS_DENIED;
    }
    else if ((policyFlags & KSWORD_ARK_SAFETY_POLICY_FLAG_ADVANCED_MODE) == 0UL) {
        decision = KSWORD_ARK_SAFETY_DECISION_DENY;
        reason = KSWORD_ARK_SAFETY_REASON_ADVANCED_MODE_REQUIRED;
        status = STATUS_ACCESS_DENIED;
    }
    else if ((policyFlags & KSWORD_ARK_SAFETY_POLICY_FLAG_DENY_CRITICAL_PROCESS) != 0UL &&
        context->targetProcessId != 0UL &&
        kswordArkSafetyIsCriticalProcessId(context->targetProcessId)) {
        decision = KSWORD_ARK_SAFETY_DECISION_DENY;
        reason = KSWORD_ARK_SAFETY_REASON_CRITICAL_PROCESS_DENIED;
        status = STATUS_ACCESS_DENIED;
    }
    else if ((policyFlags & KSWORD_ARK_SAFETY_POLICY_FLAG_REQUIRE_CONFIRMATION_HIGH_RISK) != 0UL &&
        riskLevel >= KSWORD_ARK_SAFETY_RISK_HIGH &&
        (context->contextFlags & KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED) == 0UL &&
        (policyFlags & KSWORD_ARK_SAFETY_POLICY_FLAG_ALLOW_LEGACY_UNCONFIRMED_R3) == 0UL) {
        decision = KSWORD_ARK_SAFETY_DECISION_DENY;
        reason = KSWORD_ARK_SAFETY_REASON_CONFIRMATION_REQUIRED;
        status = STATUS_REQUEST_NOT_ACCEPTED;
    }
    else if ((policyFlags & KSWORD_ARK_SAFETY_POLICY_FLAG_AUDIT_ONLY) != 0UL) {
        decision = KSWORD_ARK_SAFETY_DECISION_AUDIT_ONLY_ALLOW;
        reason = KSWORD_ARK_SAFETY_REASON_NONE;
        status = STATUS_SUCCESS;
    }

    kswordArkSafetyRecordDecisionLocked(context, decision, reason, riskLevel, status);
    kswordArkReleasePushLockExclusive(&gKswordArkSafetyState.lock);

    kswordArkSafetyLogDecision(device, context, decision, reason, riskLevel, status);
    return status;
}

NTSTATUS
kswordArkSafetyQueryPolicy(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Generate the current safety policy response. Note: This query is used by the R3 status
    page to display advanced mode, the most recent dangerous operation, and allow/deny counts.

Arguments:

    OutputBuffer - Output buffer.
    OutputBufferLength - Output buffer length.
    BytesWrittenOut - Number of bytes written.

Return Value:

    STATUS_SUCCESS or buffer validation status.

--*/
{
    KSWORD_ARK_QUERY_SAFETY_POLICY_RESPONSE* response = NULL;

    if (outputBuffer == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < sizeof(KSWORD_ARK_QUERY_SAFETY_POLICY_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_QUERY_SAFETY_POLICY_RESPONSE*)outputBuffer;
    response->size = sizeof(*response);
    response->version = KSWORD_ARK_SAFETY_PROTOCOL_VERSION;
    response->defaultPolicyFlags = KSWORD_ARK_SAFETY_POLICY_FLAG_DEFAULT;

    kswordArkAcquirePushLockShared(&gKswordArkSafetyState.lock);
    response->policyFlags = gKswordArkSafetyState.policyFlags;
    response->policyGeneration = gKswordArkSafetyState.generation;
    response->lastOperation = gKswordArkSafetyState.lastOperation;
    response->lastDecision = gKswordArkSafetyState.lastDecision;
    response->lastReason = gKswordArkSafetyState.lastReason;
    response->lastRiskLevel = gKswordArkSafetyState.lastRiskLevel;
    response->lastTargetProcessId = gKswordArkSafetyState.lastTargetProcessId;
    response->lastStatus = gKswordArkSafetyState.lastStatus;
    response->allowedCount = gKswordArkSafetyState.allowedCount;
    response->deniedCount = gKswordArkSafetyState.deniedCount;
    response->auditOnlyCount = gKswordArkSafetyState.auditOnlyCount;
    RtlCopyMemory(
        response->lastTargetText,
        gKswordArkSafetyState.lastTargetText,
        sizeof(response->lastTargetText));
    kswordArkReleasePushLockShared(&gKswordArkSafetyState.lock);

    response->lastTargetText[KSWORD_ARK_SAFETY_TEXT_MAX_CHARS - 1U] = L'\0';
    *bytesWrittenOut = sizeof(*response);
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkSafetySetPolicy(
    _In_ const KSWORD_ARK_SET_SAFETY_POLICY_REQUEST* request,
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Atomic update of the safety policy bit. Note: R3 can only set/clear specific
    bits; expectedGeneration is non-zero to prevent overwriting concurrent updates.

Arguments:

    Request - Set request.
    OutputBuffer - Response buffer.
    OutputBufferLength - Response buffer length.
    BytesWrittenOut - Number of bytes written.

Return Value:

    STATUS_SUCCESS or validation/concurrency status.

--*/
{
    KSWORD_ARK_SET_SAFETY_POLICY_RESPONSE* response = NULL;
    ULONG oldFlags = 0UL;
    ULONG oldGeneration = 0UL;
    ULONG allowedMask =
        KSWORD_ARK_SAFETY_POLICY_FLAG_ACTIVE |
        KSWORD_ARK_SAFETY_POLICY_FLAG_ADVANCED_MODE |
        KSWORD_ARK_SAFETY_POLICY_FLAG_REQUIRE_CONFIRMATION_HIGH_RISK |
        KSWORD_ARK_SAFETY_POLICY_FLAG_ALLOW_LEGACY_UNCONFIRMED_R3 |
        KSWORD_ARK_SAFETY_POLICY_FLAG_DENY_CRITICAL_PROCESS |
        KSWORD_ARK_SAFETY_POLICY_FLAG_MUTATING_DEFAULTS |
        KSWORD_ARK_SAFETY_POLICY_FLAG_ALLOW_MEMORY_WRITE |
        KSWORD_ARK_SAFETY_POLICY_FLAG_ALLOW_KERNEL_PATCH |
        KSWORD_ARK_SAFETY_POLICY_FLAG_ALLOW_DRIVER_UNLOAD |
        KSWORD_ARK_SAFETY_POLICY_FLAG_ALLOW_PROCESS_INJECT |
        KSWORD_ARK_SAFETY_POLICY_FLAG_ALLOW_DRIVER_THREAD_CONTROL |
        KSWORD_ARK_SAFETY_POLICY_FLAG_ALLOW_FIRMWARE_RETURN |
        KSWORD_ARK_SAFETY_POLICY_FLAG_AUDIT_ONLY;
    NTSTATUS status = STATUS_SUCCESS;

    if (request == NULL || outputBuffer == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < sizeof(KSWORD_ARK_SET_SAFETY_POLICY_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (request->size < sizeof(KSWORD_ARK_SET_SAFETY_POLICY_REQUEST) ||
        request->version != KSWORD_ARK_SAFETY_PROTOCOL_VERSION ||
        ((request->setFlags | request->clearFlags) & ~allowedMask) != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_SET_SAFETY_POLICY_RESPONSE*)outputBuffer;
    response->size = sizeof(*response);
    response->version = KSWORD_ARK_SAFETY_PROTOCOL_VERSION;

    kswordArkAcquirePushLockExclusive(&gKswordArkSafetyState.lock);
    oldFlags = gKswordArkSafetyState.policyFlags;
    oldGeneration = gKswordArkSafetyState.generation;
    if (request->expectedGeneration != 0UL &&
        request->expectedGeneration != oldGeneration) {
        status = STATUS_REVISION_MISMATCH;
    }
    else {
        gKswordArkSafetyState.policyFlags |= (request->setFlags & allowedMask);
        gKswordArkSafetyState.policyFlags &= ~(request->clearFlags & allowedMask);
        gKswordArkSafetyState.generation += 1UL;
    }
    response->oldPolicyFlags = oldFlags;
    response->newPolicyFlags = gKswordArkSafetyState.policyFlags;
    response->oldGeneration = oldGeneration;
    response->newGeneration = gKswordArkSafetyState.generation;
    response->status = status;
    kswordArkReleasePushLockExclusive(&gKswordArkSafetyState.lock);

    *bytesWrittenOut = sizeof(*response);
    return STATUS_SUCCESS;
}
