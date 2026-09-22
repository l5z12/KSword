/*++

Module Name:

    device_audit_query.c

Abstract:

    Read-only adapter from existing DriverObject integrity evidence to device audit rows.

Environment:

    Kernel-mode Driver Framework

--*/

#include "device_audit_internal.h"
#include "../../platform/pool_compat.h"

/*
 * A device-audit row is large, and the integrity backend has its own sizable
 * stack frame.  Keep the per-target conversion state adjacent to the dynamic
 * backend response so the complete synchronous query chain remains bounded.
 */
typedef struct KswDeviceAuditQueryWorkspace
{
    KSWORD_ARK_QUERY_DRIVER_INTEGRITY_REQUEST integrityRequest;
    KSWORD_ARK_DEVICE_AUDIT_ENTRY auditEntry;
} KswDeviceAuditQueryWorkspace, *PkswDeviceAuditQueryWorkspace;

static VOID
kswDeviceAuditFillSummaryEntry(
    _Out_ KSWORD_ARK_DEVICE_AUDIT_ENTRY* entry,
    _In_ ULONG profileFlags,
    _In_ ULONG roleHint,
    _In_z_ PCWSTR driverName,
    _In_ const KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE* integrityResponse
    )
/*++

Routine Description:

    Build a driver-summary row from the integrity response header.  This row is
    emitted even when the DriverObject was absent so R3 can show a clean
    not-found/partial diagnostic instead of silently hiding the target.

Arguments:

    Entry - Output row to initialize.
    ProfileFlags - Audit profile represented by this target.
    RoleHint - Expected role for the target driver in the selected profile.
    DriverName - DriverObject name queried by the backend.
    IntegrityResponse - Response header returned by the existing integrity code.

Return Value:

    None.  Entry is fully initialized in-place.

--*/
{
    ULONG rowStatus = KSWORD_ARK_DEVICE_AUDIT_STATUS_OK;
    ULONG riskFlags = KSWORD_ARK_DEVICE_AUDIT_RISK_NONE;

    RtlZeroMemory(entry, sizeof(*entry));
    entry->size = sizeof(*entry);
    entry->profileFlags = profileFlags;
    entry->rowKind = KSWORD_ARK_DEVICE_AUDIT_ROW_KIND_DRIVER_SUMMARY;
    entry->roleHint = roleHint;
    entry->confidence = 70UL;
    entry->lastStatus = STATUS_SUCCESS;
    kswDeviceAuditCopyWide(entry->driverName, RTL_NUMBER_OF(entry->driverName), driverName);
    kswDeviceAuditCopyServiceName(entry->serviceName, RTL_NUMBER_OF(entry->serviceName), driverName);
    entry->fieldFlags = KSWORD_ARK_DEVICE_AUDIT_FIELD_DRIVER_NAME_PRESENT |
        KSWORD_ARK_DEVICE_AUDIT_FIELD_SERVICE_NAME_PRESENT |
        KSWORD_ARK_DEVICE_AUDIT_FIELD_DETAIL_PRESENT;

    if (integrityResponse == NULL) {
        entry->status = KSWORD_ARK_DEVICE_AUDIT_STATUS_QUERY_FAILED;
        entry->riskFlags = KSWORD_ARK_DEVICE_AUDIT_RISK_QUERY_FAILED;
        entry->lastStatus = STATUS_UNSUCCESSFUL;
        kswDeviceAuditCopyWide(entry->detail, RTL_NUMBER_OF(entry->detail), L"Driver integrity backend returned no response header.");
        return;
    }

    if (integrityResponse->queryStatus == KSWORD_ARK_DRIVER_INTEGRITY_STATUS_OK &&
        (integrityResponse->statusFlags & KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PARTIAL) == 0UL) {
        rowStatus = KSWORD_ARK_DEVICE_AUDIT_STATUS_OK;
    }
    else if (integrityResponse->queryStatus == KSWORD_ARK_DRIVER_INTEGRITY_STATUS_NOT_FOUND) {
        rowStatus = KSWORD_ARK_DEVICE_AUDIT_STATUS_NOT_FOUND;
        riskFlags |= KSWORD_ARK_DEVICE_AUDIT_RISK_UNAVAILABLE;
    }
    else if (integrityResponse->queryStatus == KSWORD_ARK_DRIVER_INTEGRITY_STATUS_QUERY_FAILED) {
        rowStatus = KSWORD_ARK_DEVICE_AUDIT_STATUS_QUERY_FAILED;
        riskFlags |= KSWORD_ARK_DEVICE_AUDIT_RISK_QUERY_FAILED;
    }
    else {
        rowStatus = KSWORD_ARK_DEVICE_AUDIT_STATUS_PARTIAL;
        riskFlags |= KSWORD_ARK_DEVICE_AUDIT_RISK_INTEGRITY_PARTIAL;
    }

    if ((integrityResponse->statusFlags & KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_TRUNCATED) != 0UL) {
        riskFlags |= KSWORD_ARK_DEVICE_AUDIT_RISK_STACK_TRUNCATED;
    }
    entry->status = rowStatus;
    entry->riskFlags = riskFlags;
    entry->lastStatus = integrityResponse->lastStatus;
    (VOID)RtlStringCchPrintfW(
        entry->detail,
        RTL_NUMBER_OF(entry->detail),
        L"Driver integrity status=%lu rows=%lu/%lu modules=%lu statusFlags=0x%08lX.",
        integrityResponse->queryStatus,
        integrityResponse->returnedCount,
        integrityResponse->totalCount,
        integrityResponse->moduleCount,
        integrityResponse->statusFlags);
}

static VOID
kswDeviceAuditFillDeviceEntry(
    _Out_ KSWORD_ARK_DEVICE_AUDIT_ENTRY* entry,
    _In_ ULONG profileFlags,
    _In_ ULONG roleHint,
    _In_z_ PCWSTR driverName,
    _In_ const KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE* evidence
    )
/*++

Routine Description:

    Convert one integrity device-chain evidence row into the new audit row shape.
    The conversion is read-only and copies only addresses, flags, names, and
    textual diagnostics already produced by the integrity backend.

Arguments:

    Entry - Output row to initialize.
    ProfileFlags - Audit profile represented by this target.
    RoleHint - Expected role for the target driver.
    DriverName - DriverObject name queried by the backend.
    Evidence - Integrity evidence row to convert.

Return Value:

    None.  Entry is fully initialized in-place.

--*/
{
    RtlZeroMemory(entry, sizeof(*entry));
    entry->size = sizeof(*entry);
    entry->profileFlags = profileFlags;
    entry->rowKind = KSWORD_ARK_DEVICE_AUDIT_ROW_KIND_DEVICE_ROW;
    entry->roleHint = roleHint;
    entry->status = kswDeviceAuditMapStatus(evidence->entryStatus, evidence->riskFlags);
    entry->riskFlags = kswDeviceAuditMapRiskFlags(evidence->riskFlags);
    entry->fieldFlags = KSWORD_ARK_DEVICE_AUDIT_FIELD_DRIVER_NAME_PRESENT |
        KSWORD_ARK_DEVICE_AUDIT_FIELD_SERVICE_NAME_PRESENT |
        KSWORD_ARK_DEVICE_AUDIT_FIELD_DETAIL_PRESENT;
    entry->confidence = evidence->confidence;
    entry->relationDepth = evidence->ordinal;
    entry->attachedDepth = evidence->ordinal;
    entry->deviceType = evidence->deviceType;
    entry->characteristics = evidence->deviceFlags;
    entry->lastStatus = STATUS_SUCCESS;
    entry->driverObjectAddress = evidence->driverObjectAddress;
    entry->deviceObjectAddress = evidence->deviceObjectAddress;
    entry->attachedDeviceAddress = evidence->attachedDeviceObjectAddress;
    entry->nextDeviceObjectAddress = evidence->nextDeviceObjectAddress;
    kswDeviceAuditCopyWide(entry->driverName, RTL_NUMBER_OF(entry->driverName), driverName);
    kswDeviceAuditCopyServiceName(entry->serviceName, RTL_NUMBER_OF(entry->serviceName), driverName);
    kswDeviceAuditCopyWide(entry->detail, RTL_NUMBER_OF(entry->detail), evidence->detail);

    if (evidence->deviceObjectAddress != 0ULL) {
        entry->fieldFlags |= KSWORD_ARK_DEVICE_AUDIT_FIELD_DEVICE_NAME_PRESENT;
        (VOID)RtlStringCchPrintfW(entry->deviceName, RTL_NUMBER_OF(entry->deviceName), L"DeviceObject 0x%llX", evidence->deviceObjectAddress);
    }
    if (evidence->attachedDeviceObjectAddress != 0ULL) {
        entry->fieldFlags |= KSWORD_ARK_DEVICE_AUDIT_FIELD_ATTACHED_PRESENT;
    }
    if (evidence->nextDeviceObjectAddress != 0ULL) {
        entry->fieldFlags |= KSWORD_ARK_DEVICE_AUDIT_FIELD_NEXT_PRESENT;
    }
}

static NTSTATUS
kswDeviceAuditQueryOneTarget(
    _Inout_ KSWORD_ARK_QUERY_DEVICE_AUDIT_RESPONSE* response,
    _In_ ULONG capacity,
    _In_ const KswDeviceAuditRequestContext* context,
    _In_z_ PCWSTR driverName,
    _In_ ULONG profileFlags,
    _In_ ULONG roleHint
    )
/*++

Routine Description:

    Query one target DriverObject through the existing integrity backend and
    append a summary row plus each returned device-chain row to the audit
    response.  The function does not dereference device links itself.

Arguments:

    Response - Initialized caller response that receives converted rows.
    Capacity - Physical row capacity of Response.
    Context - Validated request context containing row and depth limits.
    DriverName - DriverObject namespace name to query.
    ProfileFlags - Audit profile represented by DriverName.
    RoleHint - Expected role to attach to emitted rows.

Return Value:

    STATUS_SUCCESS when the target was queried and any rows were appended.
    Non-success status only represents local allocation/backend transport errors;
    missing drivers are converted to partial evidence rows.

--*/
{
    KswDeviceAuditQueryWorkspace* workspace = NULL;
    KSWORD_ARK_QUERY_DRIVER_INTEGRITY_REQUEST* integrityRequest = NULL;
    KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE* integrityResponse = NULL;
    KSWORD_ARK_DEVICE_AUDIT_ENTRY* auditEntry = NULL;
    ULONG scratchRows = KSW_DEVICE_AUDIT_SCRATCH_ROW_LIMIT;
    size_t workspaceBytes = 0U;
    size_t scratchBytes = 0U;
    size_t allocationBytes = 0U;
    size_t bytesWritten = 0U;
    ULONG index = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (response == NULL || context == NULL || driverName == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (context->maxRows != 0UL && context->maxRows < scratchRows) {
        scratchRows = context->maxRows;
    }
    if (scratchRows == 0UL) {
        scratchRows = 1UL;
    }

    scratchBytes = KSW_DEVICE_AUDIT_INTEGRITY_RESPONSE_HEADER_SIZE +
        ((size_t)scratchRows * sizeof(KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE));
    workspaceBytes = ALIGN_UP_BY(
        sizeof(*workspace),
        MEMORY_ALLOCATION_ALIGNMENT);
    if (scratchBytes > MAXULONG_PTR - workspaceBytes) {
        return STATUS_INTEGER_OVERFLOW;
    }
    allocationBytes = workspaceBytes + scratchBytes;
    workspace = (KswDeviceAuditQueryWorkspace*)kswordArkAllocateNonPagedPool(
        allocationBytes,
        KSW_DEVICE_AUDIT_POOL_TAG);
    if (workspace == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(workspace, allocationBytes);
    integrityRequest = &workspace->integrityRequest;
    auditEntry = &workspace->auditEntry;
    integrityResponse = (KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE*)(
        (PUCHAR)workspace + workspaceBytes);

    integrityRequest->version = KSWORD_ARK_DRIVER_INTEGRITY_PROTOCOL_VERSION;
    integrityRequest->flags = KSWORD_ARK_DRIVER_INTEGRITY_FLAG_DRIVER_OBJECT | KSWORD_ARK_DRIVER_INTEGRITY_FLAG_SERVICE;
    integrityRequest->maxRows = scratchRows;
    integrityRequest->maxDevices = context->maxRows;
    integrityRequest->maxAttachedDevices = context->maxAttachedDepth;
    integrityRequest->requestSize = sizeof(*integrityRequest);
    kswDeviceAuditCopyWide(
        integrityRequest->driverName,
        RTL_NUMBER_OF(integrityRequest->driverName),
        driverName);

    status = kswordArkDriverQueryDriverIntegrity(
        integrityResponse,
        scratchBytes,
        integrityRequest,
        &bytesWritten);
    if (!NT_SUCCESS(status)) {
        kswDeviceAuditSetResponsePartial(response, status);
        RtlZeroMemory(auditEntry, sizeof(*auditEntry));
        auditEntry->size = sizeof(*auditEntry);
        auditEntry->profileFlags = profileFlags;
        auditEntry->rowKind = KSWORD_ARK_DEVICE_AUDIT_ROW_KIND_DRIVER_SUMMARY;
        auditEntry->roleHint = roleHint;
        auditEntry->status = KSWORD_ARK_DEVICE_AUDIT_STATUS_QUERY_FAILED;
        auditEntry->riskFlags = KSWORD_ARK_DEVICE_AUDIT_RISK_QUERY_FAILED;
        auditEntry->confidence = 20UL;
        auditEntry->lastStatus = status;
        auditEntry->fieldFlags = KSWORD_ARK_DEVICE_AUDIT_FIELD_DRIVER_NAME_PRESENT |
            KSWORD_ARK_DEVICE_AUDIT_FIELD_SERVICE_NAME_PRESENT |
            KSWORD_ARK_DEVICE_AUDIT_FIELD_DETAIL_PRESENT;
        kswDeviceAuditCopyWide(
            auditEntry->driverName,
            RTL_NUMBER_OF(auditEntry->driverName),
            driverName);
        kswDeviceAuditCopyServiceName(
            auditEntry->serviceName,
            RTL_NUMBER_OF(auditEntry->serviceName),
            driverName);
        (VOID)RtlStringCchPrintfW(
            auditEntry->detail,
            RTL_NUMBER_OF(auditEntry->detail),
            L"Driver integrity backend failed, status=0x%08lX.",
            (ULONG)status);
        (VOID)kswDeviceAuditAppendEntry(
            response,
            capacity,
            context->maxRows,
            auditEntry);
        ExFreePoolWithTag(workspace, KSW_DEVICE_AUDIT_POOL_TAG);
        return STATUS_SUCCESS;
    }

    UNREFERENCED_PARAMETER(bytesWritten);

    kswDeviceAuditFillSummaryEntry(
        auditEntry,
        profileFlags,
        roleHint,
        driverName,
        integrityResponse);
    status = kswDeviceAuditAppendEntry(
        response,
        capacity,
        context->maxRows,
        auditEntry);
    if (!NT_SUCCESS(status)) {
        kswDeviceAuditSetResponsePartial(response, status);
    }
    else {
        response->driverCount += 1UL;
    }

    if (integrityResponse->queryStatus != KSWORD_ARK_DRIVER_INTEGRITY_STATUS_OK ||
        (integrityResponse->statusFlags & KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PARTIAL) != 0UL) {
        kswDeviceAuditSetResponsePartial(response, integrityResponse->lastStatus);
    }

    for (index = 0UL; index < integrityResponse->returnedCount; ++index) {
        const KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE* evidence = &integrityResponse->entries[index];
        if (evidence->evidenceClass != KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DEVICE_CHAIN) {
            continue;
        }
        kswDeviceAuditFillDeviceEntry(
            auditEntry,
            profileFlags,
            roleHint,
            driverName,
            evidence);
        status = kswDeviceAuditAppendEntry(
            response,
            capacity,
            context->maxRows,
            auditEntry);
        if (!NT_SUCCESS(status)) {
            kswDeviceAuditSetResponsePartial(response, status);
            break;
        }
        response->deviceCount += 1UL;
    }

    ExFreePoolWithTag(workspace, KSW_DEVICE_AUDIT_POOL_TAG);
    return STATUS_SUCCESS;
}

static NTSTATUS
kswDeviceAuditQueryTargets(
    _Inout_ KSWORD_ARK_QUERY_DEVICE_AUDIT_RESPONSE* response,
    _In_ ULONG capacity,
    _In_ const KswDeviceAuditRequestContext* context,
    _In_reads_(targetCount) const KswDeviceAuditTarget* targets,
    _In_ ULONG targetCount,
    _In_ ULONG profileFlags
    )
/*++

Routine Description:

    Query a static list of target drivers for one profile.  Each target is
    isolated so one absent Windows component does not fail the whole IOCTL.

Arguments:

    Response - Initialized output response.
    Capacity - Physical row capacity of Response.
    Context - Validated request context.
    Targets - Static target table for the selected profile.
    TargetCount - Number of entries in Targets.
    ProfileFlags - Profile bit attached to emitted rows.

Return Value:

    STATUS_SUCCESS after all targets are attempted.  Local allocation failures
    are represented as partial response state and do not stop later targets.

--*/
{
    ULONG index = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (response == NULL || context == NULL || targets == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    for (index = 0UL; index < targetCount; ++index) {
        NTSTATUS targetStatus = kswDeviceAuditQueryOneTarget(
            response,
            capacity,
            context,
            targets[index].driverName,
            profileFlags,
            targets[index].roleHint);
        response->targetCount += 1UL;
        if (!NT_SUCCESS(targetStatus)) {
            status = targetStatus;
            kswDeviceAuditSetResponsePartial(response, targetStatus);
        }
    }
    return status;
}

static ULONG
kswDeviceAuditKnownProfileForHandler(
    _In_ ULONG handlerProfile,
    _In_ ULONG requestedProfile
    )
/*++

Routine Description:

    Select the profile flags to execute for one public IOCTL.  A zero request
    means the handler default; otherwise only the handler-owned bit is honored.

Arguments:

    HandlerProfile - Profile bit implied by the IOCTL control code.
    RequestedProfile - Caller supplied profile mask.

Return Value:

    Effective profile mask or zero when the caller requested an unsupported mask.

--*/
{
    if (requestedProfile == 0UL) {
        return handlerProfile;
    }
    if ((requestedProfile & ~KSWORD_ARK_DEVICE_AUDIT_PROFILE_ALL) != 0UL) {
        return 0UL;
    }
    return requestedProfile & handlerProfile;
}

static NTSTATUS
kswDeviceAuditCaptureRequest(
    _In_opt_ const KSWORD_ARK_QUERY_DEVICE_AUDIT_REQUEST* userRequest,
    _In_ ULONG handlerProfile,
    _Out_ KswDeviceAuditRequestContext* context
    )
/*++

Routine Description:

    Validate and normalize the optional IOCTL request.  The function accepts a
    NULL request to support legacy callers that only provide an output buffer.

Arguments:

    UserRequest - Optional caller request already retrieved from WDF.
    HandlerProfile - Profile bit implied by the IOCTL handler.
    Context - Normalized request context returned to the handler.

Return Value:

    STATUS_SUCCESS on a usable request; STATUS_INVALID_PARAMETER when version,
    size, profile, or target string validation fails.

--*/
{
    if (context == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(context, sizeof(*context));
    context->request.size = sizeof(context->request);
    context->request.version = KSWORD_ARK_DEVICE_AUDIT_PROTOCOL_VERSION;
    context->effectiveProfile = handlerProfile;
    context->maxRows = KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ROWS;
    context->maxAttachedDepth = KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ATTACHED_DEPTH;

    if (userRequest != NULL) {
        RtlCopyMemory(&context->request, userRequest, sizeof(context->request));
        if (context->request.size < sizeof(context->request) ||
            context->request.version > KSWORD_ARK_DEVICE_AUDIT_PROTOCOL_VERSION) {
            return STATUS_INVALID_PARAMETER;
        }
        context->effectiveProfile = kswDeviceAuditKnownProfileForHandler(handlerProfile, context->request.profileFlags);
        if (context->effectiveProfile == 0UL) {
            return STATUS_INVALID_PARAMETER;
        }
        context->maxRows = kswDeviceAuditNormalizeMaxRows(context->request.maxRows);
        context->maxAttachedDepth = kswDeviceAuditNormalizeAttachedDepth(context->request.maxAttachedDepth);
        context->hasSingleTarget = kswDeviceAuditStringPresent(context->request.targetName, RTL_NUMBER_OF(context->request.targetName));
        if (context->request.targetName[RTL_NUMBER_OF(context->request.targetName) - 1UL] != L'\0') {
            return STATUS_INVALID_PARAMETER;
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS
kswDeviceAuditExecute(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned,
    _In_ ULONG handlerProfile,
    _In_z_ PCSTR logName
    )
/*++

Routine Description:

    Shared implementation for the four read-only audit IOCTL handlers.  The
    routine validates buffers, normalizes the optional request, runs either a
    caller-specified target or the handler's static target list, and finalizes
    the response byte count.

Arguments:

    Device - WDF device used only for logging.
    Request - Current IOCTL request.
    InputBufferLength - Caller input byte count.
    OutputBufferLength - Caller output byte count; WDF performs concrete buffer validation.
    BytesReturned - Receives the number of bytes written to the output buffer.
    HandlerProfile - Profile bit represented by the public IOCTL.
    Targets - Static fallback target list for this handler.
    TargetCount - Number of entries in Targets.
    LogName - Short ANSI name used in diagnostic logs.

Return Value:

    STATUS_SUCCESS when a syntactically valid response is returned, even if the
    response contains per-target partial/not-found diagnostics.  Buffer or
    request validation failures are returned directly.

--*/
{
    const KSWORD_ARK_QUERY_DEVICE_AUDIT_REQUEST* userRequest = NULL;
    KswDeviceAuditRequestContext context;
    KSWORD_ARK_QUERY_DEVICE_AUDIT_RESPONSE* response = NULL;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    ULONG capacity = 0UL;
    const KswDeviceAuditTarget* targets = NULL;
    ULONG targetCount = 0UL;
    BOOLEAN hasInput = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkRetrieveOptionalInputBuffer(
        request,
        inputBufferLength,
        sizeof(KSWORD_ARK_QUERY_DEVICE_AUDIT_REQUEST),
        &inputBuffer,
        &actualInputLength,
        &hasInput);
    if (!NT_SUCCESS(status)) {
        kswDeviceAuditLog(device, "Error", "%s input invalid: 0x%08X.", logName, (unsigned int)status);
        return status;
    }
    UNREFERENCED_PARAMETER(actualInputLength);
    userRequest = hasInput ? (const KSWORD_ARK_QUERY_DEVICE_AUDIT_REQUEST*)inputBuffer : NULL;

    if (handlerProfile == KSWORD_ARK_DEVICE_AUDIT_PROFILE_DEVICE_STACK) {
        targets = kGKswDeviceAuditDeviceTargets;
        targetCount = kGKswDeviceAuditDeviceTargetCount;
    }
    else if (handlerProfile == KSWORD_ARK_DEVICE_AUDIT_PROFILE_INPUT_STACK) {
        targets = kGKswDeviceAuditInputTargets;
        targetCount = kGKswDeviceAuditInputTargetCount;
    }
    else if (handlerProfile == KSWORD_ARK_DEVICE_AUDIT_PROFILE_USB_TOPOLOGY) {
        targets = kGKswDeviceAuditUsbTargets;
        targetCount = kGKswDeviceAuditUsbTargetCount;
    }
    else if (handlerProfile == KSWORD_ARK_DEVICE_AUDIT_PROFILE_GPU_DISPLAY_WATCHDOG) {
        targets = kGKswDeviceAuditGpuTargets;
        targetCount = kGKswDeviceAuditGpuTargetCount;
    }
    else {
        return STATUS_INVALID_PARAMETER;
    }

    status = kswDeviceAuditCaptureRequest(userRequest, handlerProfile, &context);
    if (!NT_SUCCESS(status)) {
        kswDeviceAuditLog(device, "Error", "%s request invalid: 0x%08X.", logName, (unsigned int)status);
        return status;
    }

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        KSW_DEVICE_AUDIT_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswDeviceAuditLog(device, "Error", "%s output invalid: 0x%08X.", logName, (unsigned int)status);
        return status;
    }

    capacity = kswDeviceAuditOutputCapacity(actualOutputLength);
    kswDeviceAuditZeroResponse(outputBuffer, actualOutputLength, context.effectiveProfile);
    response = (KSWORD_ARK_QUERY_DEVICE_AUDIT_RESPONSE*)outputBuffer;

    if (context.hasSingleTarget) {
        status = kswDeviceAuditQueryOneTarget(
            response,
            capacity,
            &context,
            context.request.targetName,
            context.effectiveProfile,
            KSWORD_ARK_DEVICE_AUDIT_ROLE_UNKNOWN);
        response->targetCount += 1UL;
        if (!NT_SUCCESS(status)) {
            kswDeviceAuditSetResponsePartial(response, status);
        }
    }
    else {
        status = kswDeviceAuditQueryTargets(response, capacity, &context, targets, targetCount, handlerProfile);
        if (!NT_SUCCESS(status)) {
            kswDeviceAuditSetResponsePartial(response, status);
        }
    }

    if (response->totalCount == 0UL) {
        response->responseFlags |= KSWORD_ARK_DEVICE_AUDIT_RESPONSE_FLAG_EMPTY;
        response->queryStatus = KSWORD_ARK_DEVICE_AUDIT_STATUS_NOT_FOUND;
    }
    if ((response->responseFlags & KSWORD_ARK_DEVICE_AUDIT_RESPONSE_FLAG_TRUNCATED) != 0UL) {
        response->queryStatus = KSWORD_ARK_DEVICE_AUDIT_STATUS_PARTIAL;
    }

    *bytesReturned = KSW_DEVICE_AUDIT_RESPONSE_HEADER_SIZE +
        ((size_t)response->returnedCount * sizeof(KSWORD_ARK_DEVICE_AUDIT_ENTRY));
    kswDeviceAuditLog(
        device,
        (response->queryStatus == KSWORD_ARK_DEVICE_AUDIT_STATUS_QUERY_FAILED) ? "Warn" : "Info",
        "%s completed: q=%lu flags=0x%08lX total=%lu returned=%lu devices=%lu targets=%lu bytes=%Iu.",
        logName,
        response->queryStatus,
        response->responseFlags,
        response->totalCount,
        response->returnedCount,
        response->deviceCount,
        response->targetCount,
        *bytesReturned);
    return STATUS_SUCCESS;
}
