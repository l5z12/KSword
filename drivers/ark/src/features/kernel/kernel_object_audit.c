/*++
Module Name:
    kernel_object_audit.c
Abstract:
    Read-only CID table, kernel object summary, and IPC summary IOCTLs.
Environment:
    Kernel-mode Driver Framework
--*/
#include "kernel_object_audit.h"
#include "object_header_fallback.h"
#include "ark/ark_driver.h"
#include "../process/process_crossview.h"
#include "../../dispatch/ioctl_validation.h"
#include "../../platform/pool_compat.h"
#include <ntstrsafe.h>
#include <stdarg.h>
#define KSW_KERNEL_OBJECT_CID_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_ENUM_CID_TABLE_RESPONSE) - sizeof(KSWORD_ARK_CID_TABLE_ENTRY))
#define KSW_KERNEL_OBJECT_DEFAULT_CID_VISIT_BUDGET 65536UL
#define KSW_KERNEL_OBJECT_HARD_CID_VISIT_BUDGET    262144UL
#define KSW_KERNEL_OBJECT_HARD_RETURN_COUNT        4096UL
#define KSW_KERNEL_OBJECT_TYPE_NAME_POOL_TAG        'nOsK'
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif
#ifndef STATUS_BUFFER_OVERFLOW
#define STATUS_BUFFER_OVERFLOW ((NTSTATUS)0x80000005L)
#endif
#ifndef STATUS_NOT_FOUND
#define STATUS_NOT_FOUND ((NTSTATUS)0xC0000225L)
#endif
extern POBJECT_TYPE* PsProcessType;
extern POBJECT_TYPE* PsThreadType;
NTSYSAPI
NTSTATUS
NTAPI
PsLookupProcessByProcessId(
    _In_ HANDLE processId,
    _Outptr_ PEPROCESS* process
    );
NTSYSAPI
NTSTATUS
NTAPI
PsLookupThreadByThreadId(
    _In_ HANDLE threadId,
    _Outptr_ PETHREAD* thread
    );
NTKERNELAPI
POBJECT_TYPE
NTAPI
ObGetObjectType(
    _In_ PVOID object
    );

NTKERNELAPI
NTSTATUS
ObQueryNameString(
    _In_ PVOID object,
    _Out_writes_bytes_opt_(length) POBJECT_NAME_INFORMATION objectNameInfo,
    _In_ ULONG length,
    _Out_ PULONG returnLength
    );

static VOID
kswordArkKernelObjectIoctlLog(
    _In_ WDFDEVICE device,
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR formatText,
    ...
    )
/*++
Routine Description:
    Format and enqueue one kernel-object audit log line. Note: Logs record only read-only
    query status and counts, excluding any credentials that could be used to modify objects.
Arguments:
    Device - WDF device that owns the log channel.
    levelText - Log level text.
    FormatText - printf-style format string.
    ... - Format arguments.
Return Value:
    None. Log formatting failures are ignored.
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
static ULONG
kswordArkKernelObjectNormalizeOffset(
    _In_ ULONG offset
    )
/*++
Routine Description:
    Convert DynData unavailable sentinels into the protocol's display sentinel.
Arguments:
    Offset - Raw DynData offset.
Return Value:
    Usable offset or KSWORD_ARK_KERNEL_OBJECT_OFFSET_UNAVAILABLE.
--*/
{
    if (!kswordArkCrossViewOffsetPresent(offset)) {
        return KSWORD_ARK_KERNEL_OBJECT_OFFSET_UNAVAILABLE;
    }
    return offset;
}
static ULONG
kswordArkKernelObjectClampVisitBudget(
    _In_ ULONG requestedBudget
    )
/*++
Routine Description:
    Clamp caller CID traversal budget to a nonzero, bounded value.
Arguments:
    RequestedBudget - Caller-provided budget, zero selects default.
Return Value:
    Safe traversal budget never exceeding the hard limit.
--*/
{
    ULONG budget = requestedBudget;
    if (budget == 0UL) {
        budget = KSW_KERNEL_OBJECT_DEFAULT_CID_VISIT_BUDGET;
    }
    if (budget > KSW_KERNEL_OBJECT_HARD_CID_VISIT_BUDGET) {
        budget = KSW_KERNEL_OBJECT_HARD_CID_VISIT_BUDGET;
    }
    return budget;
}
static ULONG
kswordArkKernelObjectSanitizeCidFlags(
    _In_ ULONG requestFlags
    )
/*++
Routine Description:
    Keep only supported CID enumeration selector bits and provide a safe default.
Arguments:
    RequestFlags - Caller flags from the request packet.
Return Value:
    Process/thread selector flags.
--*/
{
    ULONG flags = requestFlags & KSWORD_ARK_CID_ENUM_FLAG_INCLUDE_ALL;
    if (flags == 0UL) {
        flags = KSWORD_ARK_CID_ENUM_FLAG_INCLUDE_ALL;
    }
    return flags;
}
typedef struct KswKernelObjectCidContext
{
    KSWORD_ARK_ENUM_CID_TABLE_RESPONSE* response;
    KSWORD_ARK_CID_TABLE_ENTRY* rows;
    ULONG rowCapacity;
    ULONG expectedObjectKind;
    ULONG startCid;
    ULONG endCid;
    BOOLEAN hasStartCid;
    BOOLEAN hasEndCid;
    BOOLEAN truncated;
} KswKernelObjectCidContext, *PkswKernelObjectCidContext;
static BOOLEAN
kswordArkKernelObjectCidInRange(
    _In_ const KswKernelObjectCidContext* context,
    _In_ ULONG cidValue
    )
/*++
Routine Description:
    Apply optional CID start/end filters without changing the underlying walker.
Arguments:
    Context - CID response builder state.
    CidValue - Candidate CID value from PspCidTable.
Return Value:
    TRUE when the candidate should be emitted or counted.
--*/
{
    if (context == NULL) {
        return FALSE;
    }
    if (context->hasStartCid && cidValue < context->startCid) {
        return FALSE;
    }
    if (context->hasEndCid && cidValue > context->endCid) {
        return FALSE;
    }
    return TRUE;
}
static VOID
kswordArkKernelObjectCidCallback(
    _In_ const KswCrossviewCidEntry* entry,
    _Inout_opt_ PVOID context
    )
/*++
Routine Description:
    Convert one read-only CID walker callback into the public response row.
Arguments:
    Entry - Type-matched CID walker payload.
    Context - KswKernelObjectCidContext response builder.
Return Value:
    None. Rows beyond capacity are counted and marked as truncated.
--*/
{
    KswKernelObjectCidContext* cidContext = (KswKernelObjectCidContext*)context;
    KSWORD_ARK_CID_TABLE_ENTRY* row = NULL;
    if (entry == NULL || cidContext == NULL || cidContext->response == NULL) {
        return;
    }
    if (!kswordArkKernelObjectCidInRange(cidContext, entry->cidValue)) {
        return;
    }
    cidContext->response->totalCount += 1UL;
    if (cidContext->response->returnedCount >= cidContext->rowCapacity) {
        cidContext->truncated = TRUE;
        return;
    }
    row = &cidContext->rows[cidContext->response->returnedCount];
    RtlZeroMemory(row, sizeof(*row));
    row->cidValue = entry->cidValue;
    row->handleIndex = entry->cidValue / 4UL;
    row->expectedObjectKind = cidContext->expectedObjectKind;
    row->lookupStatus = entry->referenced ?
        KSWORD_ARK_CID_ENUM_STATUS_OK :
        KSWORD_ARK_CID_ENUM_STATUS_PARTIAL;
    row->referenceStatus = entry->referenceStatus;
    row->objectAddress = entry->objectAddress;
    if (entry->referenced) {
        row->flags |= KSWORD_ARK_CID_ENTRY_FLAG_REFERENCED;
    }
    else {
        row->flags |= KSWORD_ARK_CID_ENTRY_FLAG_DANGLING;
    }
    cidContext->response->returnedCount += 1UL;
}
static NTSTATUS
kswordArkKernelObjectWalkExpectedCidKind(
    _In_ const KswDynState* dynState,
    _In_ PVOID pspCidTableAddress,
    _In_ ULONG expectedObjectKind,
    _In_ ULONG maxVisitCount,
    _Inout_ KswKernelObjectCidContext* context,
    _Out_ ULONG* visitedCountOut
    )
/*++
Routine Description:
    Select the Process or Thread object type and invoke the existing read-only
    CID table walker. Note: Do not replicate walker logic here to avoid introducing a second decoding path.
Arguments:
    DynState - Current DynData snapshot.
    PspCidTableAddress - Address of the PspCidTable global variable.
    ExpectedObjectKind - Process or Thread selector.
    MaxVisitCount - Bounded leaf-entry visit budget.
    Context - Mutable response builder.
    VisitedCountOut - Receives visited leaf entries for this pass.
Return Value:
    STATUS_SUCCESS, STATUS_BUFFER_OVERFLOW, or the walker failure status.
--*/
{
    POBJECT_TYPE expectedType = NULL;
    if (visitedCountOut != NULL) {
        *visitedCountOut = 0UL;
    }
    if (dynState == NULL || pspCidTableAddress == NULL || context == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (expectedObjectKind == KSWORD_ARK_CID_OBJECT_KIND_PROCESS) {
        expectedType = (PsProcessType != NULL) ? *PsProcessType : NULL;
    }
    else if (expectedObjectKind == KSWORD_ARK_CID_OBJECT_KIND_THREAD) {
        expectedType = (PsThreadType != NULL) ? *PsThreadType : NULL;
    }
    else {
        return STATUS_INVALID_PARAMETER;
    }
    if (expectedType == NULL) {
        return STATUS_NOT_FOUND;
    }
    context->expectedObjectKind = expectedObjectKind;
    return kswordArkCrossViewWalkCidTable(
        dynState,
        pspCidTableAddress,
        expectedType,
        maxVisitCount,
        kswordArkKernelObjectCidCallback,
        context,
        visitedCountOut);
}
NTSTATUS
kswordArkDriverEnumerateCidTable(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_ENUM_CID_TABLE_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++
Routine Description:
    enumerate process/thread objects observed through PspCidTable in read-only
    Note: All traversals are controlled by maxVisitCount, and the output may be truncated.
Arguments:
    OutputBuffer - METHOD_BUFFERED output buffer.
    OutputBufferLength - Output buffer size in bytes.
    Request - Optional request; NULL selects process+thread default.
    BytesWrittenOut - Receives bytes written.
Return Value:
    STATUS_SUCCESS when a response header was produced; hard buffer failures
    return an NTSTATUS error before touching private fields.
--*/
{
    KSWORD_ARK_ENUM_CID_TABLE_RESPONSE* response = (KSWORD_ARK_ENUM_CID_TABLE_RESPONSE*)outputBuffer;
    KswKernelObjectCidContext context;
    KswDynState dynState;
    KSWORD_ARK_CROSSVIEW_FIELD_OFFSETS fieldOffsets;
    PVOID pspCidTableAddress = NULL;
    ULONG64 missingCapabilityMask = 0ULL;
    ULONG flags = KSWORD_ARK_CID_ENUM_FLAG_INCLUDE_ALL;
    ULONG maxVisitCount = KSW_KERNEL_OBJECT_DEFAULT_CID_VISIT_BUDGET;
    ULONG availableRows = 0UL;
    ULONG totalVisited = 0UL;
    BOOLEAN usedDynDataGlobal = FALSE;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS passStatus = STATUS_SUCCESS;
    if (bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBuffer == NULL || outputBufferLength < KSW_KERNEL_OBJECT_CID_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    RtlZeroMemory(response, outputBufferLength);
    response->version = KSWORD_ARK_KERNEL_OBJECT_PROTOCOL_VERSION;
    response->status = KSWORD_ARK_CID_ENUM_STATUS_UNAVAILABLE;
    response->entrySize = sizeof(KSWORD_ARK_CID_TABLE_ENTRY);
    kswordArkDynDataSnapshot(&dynState);
    response->dynDataCapabilityMask = dynState.capabilityMask;
    response->htTableCodeOffset = kswordArkKernelObjectNormalizeOffset(dynState.kernel.htTableCode);
    response->hteLowValueOffset = kswordArkKernelObjectNormalizeOffset(dynState.kernel.hteLowValue);
    if (request != NULL) {
        flags = kswordArkKernelObjectSanitizeCidFlags(request->flags);
        maxVisitCount = kswordArkKernelObjectClampVisitBudget(request->maxVisitCount);
    }
    response->flags = flags;
    response->maxVisitCount = maxVisitCount;
    if (outputBufferLength > KSW_KERNEL_OBJECT_CID_RESPONSE_HEADER_SIZE) {
        availableRows = (ULONG)((outputBufferLength - KSW_KERNEL_OBJECT_CID_RESPONSE_HEADER_SIZE) / sizeof(KSWORD_ARK_CID_TABLE_ENTRY));
    }
    if (request != NULL && request->maxEntries != 0UL && availableRows > request->maxEntries) {
        availableRows = request->maxEntries;
    }
    if (availableRows > KSW_KERNEL_OBJECT_HARD_RETURN_COUNT) {
        availableRows = KSW_KERNEL_OBJECT_HARD_RETURN_COUNT;
    }
    RtlZeroMemory(&fieldOffsets, sizeof(fieldOffsets));
    RtlZeroMemory(&context, sizeof(context));
    context.response = response;
    context.rows = response->entries;
    context.rowCapacity = availableRows;
    if (request != NULL) {
        context.startCid = request->startCid;
        context.endCid = request->endCid;
        context.hasStartCid = (request->startCid != 0UL) ? TRUE : FALSE;
        context.hasEndCid = (request->endCid != 0UL) ? TRUE : FALSE;
    }
    kswordArkCrossViewFillFieldOffsets(&dynState, &fieldOffsets);
    status = kswordArkCrossViewResolvePspCidTableAddress(
        &dynState,
        &fieldOffsets,
        &pspCidTableAddress,
        &missingCapabilityMask,
        &usedDynDataGlobal);
    UNREFERENCED_PARAMETER(usedDynDataGlobal);
    if (!NT_SUCCESS(status) || pspCidTableAddress == NULL) {
        response->lastStatus = status;
        response->status = (missingCapabilityMask != 0ULL) ?
            KSWORD_ARK_CID_ENUM_STATUS_DYNDATA_MISSING :
            KSWORD_ARK_CID_ENUM_STATUS_PSPCID_UNAVAILABLE;
        *bytesWrittenOut = KSW_KERNEL_OBJECT_CID_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }
    response->pspCidTableAddress = (ULONG64)(ULONG_PTR)pspCidTableAddress;
    if ((flags & KSWORD_ARK_CID_ENUM_FLAG_INCLUDE_PROCESS) != 0UL) {
        ULONG visitedThisPass = 0UL;
        passStatus = kswordArkKernelObjectWalkExpectedCidKind(
            &dynState,
            pspCidTableAddress,
            KSWORD_ARK_CID_OBJECT_KIND_PROCESS,
            maxVisitCount,
            &context,
            &visitedThisPass);
        totalVisited += visitedThisPass;
        if (!NT_SUCCESS(passStatus) && NT_SUCCESS(status)) {
            status = passStatus;
        }
    }
    if ((flags & KSWORD_ARK_CID_ENUM_FLAG_INCLUDE_THREAD) != 0UL) {
        ULONG visitedThisPass = 0UL;
        passStatus = kswordArkKernelObjectWalkExpectedCidKind(
            &dynState,
            pspCidTableAddress,
            KSWORD_ARK_CID_OBJECT_KIND_THREAD,
            maxVisitCount,
            &context,
            &visitedThisPass);
        totalVisited += visitedThisPass;
        if (!NT_SUCCESS(passStatus) && NT_SUCCESS(status)) {
            status = passStatus;
        }
    }
    response->visitedCount = totalVisited;
    response->lastStatus = status;
    if (context.truncated) {
        response->status = KSWORD_ARK_CID_ENUM_STATUS_BUFFER_TRUNCATED;
    }
    else if (status == STATUS_BUFFER_OVERFLOW) {
        response->status = KSWORD_ARK_CID_ENUM_STATUS_BUDGET_EXHAUSTED;
    }
    else if (!NT_SUCCESS(status)) {
        response->status = (response->returnedCount != 0UL) ?
            KSWORD_ARK_CID_ENUM_STATUS_PARTIAL :
            KSWORD_ARK_CID_ENUM_STATUS_TYPE_UNAVAILABLE;
    }
    else {
        response->status = KSWORD_ARK_CID_ENUM_STATUS_OK;
    }
    *bytesWrittenOut = KSW_KERNEL_OBJECT_CID_RESPONSE_HEADER_SIZE +
        ((size_t)response->returnedCount * sizeof(KSWORD_ARK_CID_TABLE_ENTRY));
    return STATUS_SUCCESS;
}
static VOID
kswordArkKernelObjectCopyUnicodeStringToFixed(
    _Out_writes_(destinationChars) WCHAR* destination,
    _In_ ULONG destinationChars,
    _In_opt_ const UNICODE_STRING* source
    )
/*++
Routine Description:
    Copy a counted Unicode string into a fixed protocol field.
Arguments:
    Destination - Destination WCHAR array.
    DestinationChars - Destination capacity in characters.
    Source - Optional counted source string.
Return Value:
    None. The destination is always NUL-terminated when capacity is nonzero.
--*/
{
    ULONG copyChars = 0UL;
    if (destination == NULL || destinationChars == 0UL) {
        return;
    }
    destination[0] = L'\0';
    if (source == NULL || source->Buffer == NULL || source->Length == 0U) {
        return;
    }
    copyChars = (ULONG)(source->Length / sizeof(WCHAR));
    if (copyChars >= destinationChars) {
        copyChars = destinationChars - 1UL;
    }
    RtlCopyMemory(destination, source->Buffer, (SIZE_T)copyChars * sizeof(WCHAR));
    destination[copyChars] = L'\0';
}
static NTSTATUS
kswordArkKernelObjectReadNamespaceTypeName(
    _In_ POBJECT_TYPE objectType,
    _Out_writes_(destinationChars) WCHAR* destination,
    _In_ ULONG destinationChars
    )
/*++
Routine Description:
    Query the stable Object Manager name of an OBJECT_TYPE object and retain
    its final path component. This avoids the private _OBJECT_TYPE.Name offset.
Return Value:
    STATUS_SUCCESS when a bounded non-empty name was copied.
--*/
{
    POBJECT_NAME_INFORMATION nameInfo = NULL;
    ULONG requiredBytes = 0UL;
    ULONG allocationBytes = 0UL;
    ULONG sourceChars = 0UL;
    ULONG startChar = 0UL;
    ULONG copyChars = 0UL;
    ULONG index = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (objectType == NULL || destination == NULL || destinationChars < 2UL) {
        return STATUS_INVALID_PARAMETER;
    }
    destination[0] = L'\0';
    status = ObQueryNameString(objectType, NULL, 0UL, &requiredBytes);
    if (status != STATUS_INFO_LENGTH_MISMATCH &&
        status != STATUS_BUFFER_TOO_SMALL &&
        status != STATUS_BUFFER_OVERFLOW) {
        return status;
    }
    allocationBytes = requiredBytes;
    if (allocationBytes < sizeof(OBJECT_NAME_INFORMATION) + sizeof(WCHAR)) {
        allocationBytes = sizeof(OBJECT_NAME_INFORMATION) + sizeof(WCHAR);
    }
    if (allocationBytes > 64UL * 1024UL) {
        return STATUS_NAME_TOO_LONG;
    }
    nameInfo = (POBJECT_NAME_INFORMATION)kswordArkAllocateNonPagedPool(
        allocationBytes,
        KSW_KERNEL_OBJECT_TYPE_NAME_POOL_TAG);
    if (nameInfo == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(nameInfo, allocationBytes);
    status = ObQueryNameString(
        objectType,
        nameInfo,
        allocationBytes,
        &requiredBytes);
    if (NT_SUCCESS(status) && nameInfo->Name.Buffer != NULL &&
        nameInfo->Name.Length != 0U &&
        nameInfo->Name.Length <= nameInfo->Name.MaximumLength &&
        (nameInfo->Name.Length & (sizeof(WCHAR) - 1U)) == 0U) {
        sourceChars = nameInfo->Name.Length / sizeof(WCHAR);
        for (index = 0UL; index < sourceChars; ++index) {
            if (nameInfo->Name.Buffer[index] == L'\\') {
                startChar = index + 1UL;
            }
        }
        if (startChar < sourceChars) {
            copyChars = min(sourceChars - startChar, destinationChars - 1UL);
            RtlCopyMemory(
                destination,
                &nameInfo->Name.Buffer[startChar],
                (SIZE_T)copyChars * sizeof(WCHAR));
            destination[copyChars] = L'\0';
        }
    }
    ExFreePoolWithTag(nameInfo, KSW_KERNEL_OBJECT_TYPE_NAME_POOL_TAG);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    return (copyChars != 0UL) ? STATUS_SUCCESS : STATUS_OBJECT_NAME_NOT_FOUND;
}

static NTSTATUS
kswordArkKernelObjectReadTypeInfo(
    _In_ POBJECT_TYPE objectType,
    _In_ const KswDynState* dynState,
    _Inout_ KSWORD_ARK_QUERY_KERNEL_OBJECT_SUMMARY_RESPONSE* response
    )
/*++
Routine Description:
    Read OBJECT_TYPE name/index using DynData-gated offsets only.
Arguments:
    ObjectType - Object type returned by ObGetObjectType.
    DynState - DynData snapshot containing OtName/OtIndex.
    Response - Mutable object summary response.
Return Value:
    STATUS_SUCCESS when at least one requested type field was decoded.
--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN decodedAny = FALSE;
    if (objectType == NULL || dynState == NULL || response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    response->objectTypeAddress = (ULONG64)(ULONG_PTR)objectType;
    response->fieldFlags |= KSWORD_ARK_OBJECT_SUMMARY_FIELD_TYPE_PRESENT;

    status = kswordArkKernelObjectReadNamespaceTypeName(
        objectType,
        response->typeName,
        KSWORD_ARK_KERNEL_OBJECT_TYPE_NAME_CHARS);
    if (NT_SUCCESS(status)) {
        response->fieldFlags |= KSWORD_ARK_OBJECT_SUMMARY_FIELD_TYPE_NAME_PRESENT;
        decodedAny = TRUE;
    }

    status = STATUS_SUCCESS;
    __try {
        if (!decodedAny &&
            kswordArkCrossViewOffsetPresent(dynState->kernel.otName)) {
            UNICODE_STRING typeName;
            RtlZeroMemory(&typeName, sizeof(typeName));
            RtlCopyMemory(&typeName, (PUCHAR)objectType + dynState->kernel.otName, sizeof(typeName));
            kswordArkKernelObjectCopyUnicodeStringToFixed(
                response->typeName,
                KSWORD_ARK_KERNEL_OBJECT_TYPE_NAME_CHARS,
                &typeName);
            response->fieldFlags |= KSWORD_ARK_OBJECT_SUMMARY_FIELD_TYPE_NAME_PRESENT;
            decodedAny = TRUE;
        }
        if (kswordArkCrossViewOffsetPresent(dynState->kernel.otIndex)) {
            RtlCopyMemory(&response->typeIndex, (PUCHAR)objectType + dynState->kernel.otIndex, sizeof(response->typeIndex));
            response->fieldFlags |= KSWORD_ARK_OBJECT_SUMMARY_FIELD_TYPE_INDEX_PRESENT;
            decodedAny = TRUE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    if (!decodedAny && NT_SUCCESS(status)) {
        status = STATUS_NOT_SUPPORTED;
    }
    return status;
}
static NTSTATUS
kswordArkKernelObjectReferenceByCid(
    _In_ ULONG targetKind,
    _In_ ULONG cidValue,
    _Outptr_result_nullonfailure_ PVOID* objectOut
    )
/*++
Routine Description:
    Safely obtain a referenced process or thread object from a CID value.
Arguments:
    TargetKind - Process or Thread selector.
    CidValue - PID/TID value.
    ObjectOut - Receives a referenced object on success.
Return Value:
    NTSTATUS from PsLookupProcessByProcessId or PsLookupThreadByThreadId.
--*/
{
    if (objectOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *objectOut = NULL;
    if (cidValue == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (targetKind == KSWORD_ARK_CID_OBJECT_KIND_PROCESS) {
        return PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)cidValue, (PEPROCESS*)objectOut);
    }
    if (targetKind == KSWORD_ARK_CID_OBJECT_KIND_THREAD) {
        return PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)cidValue, (PETHREAD*)objectOut);
    }
    return STATUS_NOT_SUPPORTED;
}
NTSTATUS
kswordArkDriverQueryKernelObjectSummary(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_QUERY_KERNEL_OBJECT_SUMMARY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++
Routine Description:
    Query a kernel object summary through a safe PID/TID lookup path.
Arguments:
    OutputBuffer - METHOD_BUFFERED response buffer.
    OutputBufferLength - Output buffer length.
    Request - Query request. The object address is diagnostic-only.
    BytesWrittenOut - Receives fixed response size.
Return Value:
    STATUS_SUCCESS when a response was produced.
--*/
{
    KSWORD_ARK_QUERY_KERNEL_OBJECT_SUMMARY_RESPONSE* response =
        (KSWORD_ARK_QUERY_KERNEL_OBJECT_SUMMARY_RESPONSE*)outputBuffer;
    KswDynState dynState;
    PVOID object = NULL;
    POBJECT_TYPE objectType = NULL;
    KswObjectHeaderFallbackResult counterResult;
    NTSTATUS status = STATUS_SUCCESS;
    if (bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBuffer == NULL || outputBufferLength < sizeof(*response) || request == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    RtlZeroMemory(response, sizeof(*response));
    response->version = KSWORD_ARK_KERNEL_OBJECT_PROTOCOL_VERSION;
    response->size = sizeof(*response);
    response->targetKind = request->targetKind;
    response->cidValue = request->cidValue;
    response->expectedObjectAddress = request->expectedObjectAddress;
    response->status = KSWORD_ARK_OBJECT_SUMMARY_STATUS_UNAVAILABLE;
    response->objectHeaderStatus = KSWORD_ARK_OBJECT_HEADER_STATUS_PROFILE_MISSING;
    kswordArkDynDataSnapshot(&dynState);
    response->dynDataCapabilityMask = dynState.capabilityMask;
    response->otNameOffset = kswordArkKernelObjectNormalizeOffset(dynState.kernel.otName);
    response->otIndexOffset = kswordArkKernelObjectNormalizeOffset(dynState.kernel.otIndex);
    status = kswordArkKernelObjectReferenceByCid(request->targetKind, request->cidValue, &object);
    response->lookupStatus = status;
    if (!NT_SUCCESS(status) || object == NULL) {
        response->status = KSWORD_ARK_OBJECT_SUMMARY_STATUS_LOOKUP_FAILED;
        (VOID)RtlStringCchPrintfW(
            response->detail,
            KSWORD_ARK_KERNEL_OBJECT_DETAIL_CHARS,
            L"CID lookup failed; targetKind=%lu, cid=%lu, status=0x%08X.",
            request->targetKind,
            request->cidValue,
            (unsigned int)status);
        *bytesWrittenOut = sizeof(*response);
        return STATUS_SUCCESS;
    }
    response->objectAddress = (ULONG64)(ULONG_PTR)object;
    response->fieldFlags |= KSWORD_ARK_OBJECT_SUMMARY_FIELD_OBJECT_PRESENT;
    __try {
        objectType = ObGetObjectType(object);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        objectType = NULL;
    }
    if (objectType != NULL) {
        status = kswordArkKernelObjectReadTypeInfo(objectType, &dynState, response);
        response->typeStatus = status;
        response->status = NT_SUCCESS(status) ?
            KSWORD_ARK_OBJECT_SUMMARY_STATUS_OK :
            KSWORD_ARK_OBJECT_SUMMARY_STATUS_PARTIAL;
    }
    else {
        response->typeStatus = status;
        response->status = KSWORD_ARK_OBJECT_SUMMARY_STATUS_TYPE_QUERY_FAILED;
    }
    response->counterStatus = STATUS_NOT_SUPPORTED;
    response->objectHeaderStatus = KSWORD_ARK_OBJECT_HEADER_STATUS_UNAVAILABLE;
    RtlZeroMemory(&counterResult, sizeof(counterResult));
    if ((request->flags & KSWORD_ARK_OBJECT_SUMMARY_FLAG_INCLUDE_COUNTERS) != 0UL) {
        response->counterStatus = kswordArkObjectHeaderQueryFallback(
            object,
            &counterResult);
        if (NT_SUCCESS(response->counterStatus)) {
            response->pointerCount = counterResult.pointerCount;
            response->fieldFlags |=
                KSWORD_ARK_OBJECT_SUMMARY_FIELD_POINTER_COUNT_PRESENT;
            if ((counterResult.validFields &
                    KSW_OBJECT_HEADER_FALLBACK_FIELD_HANDLE_COUNT) != 0UL) {
                response->handleCount = counterResult.handleCount;
                response->fieldFlags |=
                    KSWORD_ARK_OBJECT_SUMMARY_FIELD_HANDLE_COUNT_PRESENT;
            }
            response->objectHeaderStatus = KSWORD_ARK_OBJECT_HEADER_STATUS_AVAILABLE;
        }
        else {
            response->objectHeaderStatus = KSWORD_ARK_OBJECT_HEADER_STATUS_PROFILE_MISSING;
            if (response->status == KSWORD_ARK_OBJECT_SUMMARY_STATUS_OK) {
                response->status = KSWORD_ARK_OBJECT_SUMMARY_STATUS_PARTIAL;
            }
        }
    }
    (VOID)RtlStringCchPrintfW(
        response->detail,
        KSWORD_ARK_KERNEL_OBJECT_DETAIL_CHARS,
        (request->flags & KSWORD_ARK_OBJECT_SUMMARY_FLAG_INCLUDE_COUNTERS) == 0UL
            ? L"Summary is CID-backed; ObjectHeader counters were not requested."
            : (NT_SUCCESS(response->counterStatus)
                ? ((response->fieldFlags &
                        KSWORD_ARK_OBJECT_SUMMARY_FIELD_HANDLE_COUNT_PRESENT) != 0UL
                    ? L"Summary is CID-backed; ObjectHeader PointerCount and HandleCount passed independent export-signature and balanced-reference validation."
                    : L"Summary is CID-backed; ObjectHeader PointerCount passed independent export-signature and balanced-reference validation; HandleCount was not published without a unique secondary pattern.")
                : L"Summary is CID-backed; the ObjectHeader signature candidate was unavailable or failed live validation."));
    ObDereferenceObject(object);
    *bytesWrittenOut = sizeof(*response);
    return STATUS_SUCCESS;
}
NTSTATUS
kswordArkKernelObjectIoctlEnumCidTable(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++
Routine Description:
    IOCTL wrapper for read-only CID table enumeration.
Arguments:
    Device - WDF device used for diagnostics.
    Request - Current WDF request.
    InputBufferLength - Optional input length.
    OutputBufferLength - Output length supplied by caller.
    BytesReturned - Receives response bytes.
Return Value:
    NTSTATUS from buffer validation or backend enumeration.
--*/
{
    KSWORD_ARK_ENUM_CID_TABLE_REQUEST* enumRequest = NULL;
    KSWORD_ARK_ENUM_CID_TABLE_REQUEST defaultRequest = { 0 };
    // requestSnapshot: Saves the complete request before zeroing the shared SystemBuffer in the backend.
    KSWORD_ARK_ENUM_CID_TABLE_REQUEST requestSnapshot;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
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
        sizeof(KSWORD_ARK_ENUM_CID_TABLE_REQUEST),
        &inputBuffer,
        &actualInputLength,
        &hasInput);
    if (!NT_SUCCESS(status)) {
        kswordArkKernelObjectIoctlLog(device, "Error", "R0 enum-cid ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }
    if (hasInput) {
        /*
         * For METHOD_BUFFERED, input and output share the same SystemBuffer; the backend
         * writes the response header first, then reads flags/maxVisitCount as the traversal
         * budget. Without a snapshot, response bytes are incorrectly used as the budget.
         */
        RtlCopyMemory(&requestSnapshot, inputBuffer, sizeof(requestSnapshot));
        enumRequest = &requestSnapshot;
    }
    else {
        enumRequest = &defaultRequest;
        enumRequest->version = KSWORD_ARK_KERNEL_OBJECT_PROTOCOL_VERSION;
        enumRequest->flags = KSWORD_ARK_CID_ENUM_FLAG_INCLUDE_ALL;
        enumRequest->maxVisitCount = KSW_KERNEL_OBJECT_DEFAULT_CID_VISIT_BUDGET;
    }
    status = kswordArkRetrieveRequiredOutputBuffer(request, KSW_KERNEL_OBJECT_CID_RESPONSE_HEADER_SIZE, &outputBuffer, &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkKernelObjectIoctlLog(device, "Error", "R0 enum-cid ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }
    status = kswordArkDriverEnumerateCidTable(outputBuffer, actualOutputLength, enumRequest, bytesReturned);
    if (NT_SUCCESS(status) && *bytesReturned >= KSW_KERNEL_OBJECT_CID_RESPONSE_HEADER_SIZE) {
        KSWORD_ARK_ENUM_CID_TABLE_RESPONSE* response = (KSWORD_ARK_ENUM_CID_TABLE_RESPONSE*)outputBuffer;
        kswordArkKernelObjectIoctlLog(
            device,
            "Info",
            "R0 enum-cid success: status=%lu, total=%lu, returned=%lu, visited=%lu.",
            (unsigned long)response->status,
            (unsigned long)response->totalCount,
            (unsigned long)response->returnedCount,
            (unsigned long)response->visitedCount);
    }
    return status;
}
NTSTATUS
kswordArkKernelObjectIoctlQueryObjectSummary(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++
Routine Description:
    IOCTL wrapper for CID-backed kernel object summary queries.
Arguments:
    Device - WDF device used for diagnostics.
    Request - Current WDF request.
    InputBufferLength - Required input length.
    OutputBufferLength - Required output length.
    BytesReturned - Receives fixed response size.
Return Value:
    NTSTATUS from validation or backend query.
--*/
{
    KSWORD_ARK_QUERY_KERNEL_OBJECT_SUMMARY_REQUEST* queryRequest = NULL;
    // requestSnapshot: Saves the complete request before zeroing the shared SystemBuffer in the backend.
    KSWORD_ARK_QUERY_KERNEL_OBJECT_SUMMARY_REQUEST requestSnapshot;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;
    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);
    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;
    status = kswordArkRetrieveRequiredInputBuffer(request, sizeof(*queryRequest), (PVOID*)&queryRequest, &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkKernelObjectIoctlLog(device, "Error", "R0 query-object-summary ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }
    /*
     * For METHOD_BUFFERED, input and output share the same SystemBuffer; the backend writes the response header
     * before reading targetKind/targetId. Without a snapshot, it would count an incorrect object category.
     */
    RtlCopyMemory(&requestSnapshot, queryRequest, sizeof(requestSnapshot));
    queryRequest = &requestSnapshot;
    status = kswordArkRetrieveRequiredOutputBuffer(request, sizeof(KSWORD_ARK_QUERY_KERNEL_OBJECT_SUMMARY_RESPONSE), &outputBuffer, &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkKernelObjectIoctlLog(device, "Error", "R0 query-object-summary ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }
    status = kswordArkDriverQueryKernelObjectSummary(outputBuffer, actualOutputLength, queryRequest, bytesReturned);
    if (NT_SUCCESS(status)) {
        kswordArkKernelObjectIoctlLog(device, "Info", "R0 query-object-summary completed: bytes=%Iu.", *bytesReturned);
    }
    return status;
}
NTSTATUS
kswordArkKernelObjectIoctlQueryIpcSummary(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++
Routine Description:
    IOCTL wrapper for read-only IPC summary queries.
Arguments:
    Device - WDF device used for diagnostics.
    Request - Current WDF request.
    InputBufferLength - Required input length.
    OutputBufferLength - Required output length.
    BytesReturned - Receives fixed response size.
Return Value:
    NTSTATUS from validation or backend query.
--*/
{
    KSWORD_ARK_QUERY_IPC_SUMMARY_REQUEST* queryRequest = NULL;
    // requestSnapshot: Saves the complete request before zeroing the shared SystemBuffer in the backend.
    KSWORD_ARK_QUERY_IPC_SUMMARY_REQUEST requestSnapshot;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;
    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);
    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;
    status = kswordArkRetrieveRequiredInputBuffer(request, sizeof(*queryRequest), (PVOID*)&queryRequest, &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkKernelObjectIoctlLog(device, "Error", "R0 query-ipc-summary ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }
    /*
     * For METHOD_BUFFERED, input and output share the same SystemBuffer. The processId is read only after the backend writes
     * the response header; otherwise, a snapshot is not taken, leading to statistics on an incorrect process's IPC objects.
     */
    RtlCopyMemory(&requestSnapshot, queryRequest, sizeof(requestSnapshot));
    queryRequest = &requestSnapshot;
    status = kswordArkRetrieveRequiredOutputBuffer(request, sizeof(KSWORD_ARK_QUERY_IPC_SUMMARY_RESPONSE), &outputBuffer, &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkKernelObjectIoctlLog(device, "Error", "R0 query-ipc-summary ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }
    status = kswordArkDriverQueryIpcSummary(outputBuffer, actualOutputLength, queryRequest, bytesReturned);
    if (NT_SUCCESS(status)) {
        kswordArkKernelObjectIoctlLog(device, "Info", "R0 query-ipc-summary completed: bytes=%Iu.", *bytesReturned);
    }
    return status;
}
