/*++

Module Name:

    process_detail.c

Abstract:

    Read-only PDB/DynData-backed process runtime detail query.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "process_crossview.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntstrsafe.h>

NTSYSAPI
NTSTATUS
NTAPI
PsLookupProcessByProcessId(
    _In_ HANDLE processId,
    _Outptr_ PEPROCESS* process
    );

NTSYSAPI
PCHAR
NTAPI
PsGetProcessImageFileName(
    _In_ PEPROCESS process
    );

static BOOLEAN
kswordArkProcessDetailOffsetPresent(
    _In_ ULONG offset
    )
/*++

Routine Description:

    Check if a DynData/PDB offset is usable for read-only sampling.

Arguments:

    Offset - Field offset from KswDynState.

Return Value:

    TRUE indicates the offset is readable; FALSE indicates it is missing or a placeholder sentinel.

--*/
{
    return (offset != KSW_DYN_OFFSET_UNAVAILABLE && offset != 0x0000FFFFUL) ? TRUE : FALSE;
}

static ULONG
kswordArkProcessDetailProtocolOffset(
    _In_ ULONG offset
    )
/*++

Routine Description:

    Convert the driver-internal offset sentinel to the process shared protocol sentinel.

Arguments:

    Offset - Original DynData/PDB offset.

Return Value:

    Returns a valid offset or KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE.

--*/
{
    if (!kswordArkProcessDetailOffsetPresent(offset)) {
        return KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
    }

    return offset;
}

static VOID
kswordArkProcessDetailFillOffsets(
    _In_ const KswDynState* dynState,
    _Out_ KSWORD_ARK_PROCESS_DETAIL_OFFSETS* offsets
    )
/*++

Routine Description:

    Copy the current kernel DynData offset snapshot to the shared response structure.

Arguments:

    DynState - Output of kswordArkDynDataSnapshot.
    Offsets: Shared R3/R0 response field for process detail offsets.

Return Value:

    None.

--*/
{
    RtlZeroMemory(offsets, sizeof(*offsets));
    offsets->epUniqueProcessId = kswordArkProcessDetailProtocolOffset(dynState->kernel.epUniqueProcessId);
    offsets->epActiveProcessLinks = kswordArkProcessDetailProtocolOffset(dynState->kernel.epActiveProcessLinks);
    offsets->epThreadListHead = kswordArkProcessDetailProtocolOffset(dynState->kernel.epThreadListHead);
    offsets->epImageFileName = kswordArkProcessDetailProtocolOffset(dynState->kernel.epImageFileName);
    offsets->epToken = kswordArkProcessDetailProtocolOffset(dynState->kernel.epToken);
    offsets->epObjectTable = kswordArkProcessDetailProtocolOffset(dynState->kernel.epObjectTable);
    offsets->epSectionObject = kswordArkProcessDetailProtocolOffset(dynState->kernel.epSectionObject);
    offsets->epProtection = kswordArkProcessDetailProtocolOffset(dynState->kernel.epProtection);
    offsets->epSignatureLevel = kswordArkProcessDetailProtocolOffset(dynState->kernel.epSignatureLevel);
    offsets->epSectionSignatureLevel = kswordArkProcessDetailProtocolOffset(dynState->kernel.epSectionSignatureLevel);
}

static BOOLEAN
kswordArkProcessDetailSourcePresent(
    _In_ ULONG source
    )
/*++

Routine Description:

    Check if the DynData field source is displayable. Note: When the source is
    unavailable, the UI must not treat it as valid PDB or System Informer evidence.

Arguments:

    Source - KSW_DYN_FIELD_SOURCE_* source value.

Return Value:

    TRUE indicates a valid source; FALSE indicates missing data.

--*/
{
    return (source != KSW_DYN_FIELD_SOURCE_UNAVAILABLE) ? TRUE : FALSE;
}

static BOOLEAN
kswordArkProcessDetailFillSources(
    _In_ const KswDynState* dynState,
    _Out_ KSWORD_ARK_PROCESS_DETAIL_SOURCES* sources
    )
/*++

Routine Description:

    Copy each EPROCESS offset source used for process detail into the shared response.

Arguments:

    DynState - Output of kswordArkDynDataSnapshot.
    Sources: R3/R0 shared response field for process details.

Return Value:

    TRUE indicates at least one source is available for display; FALSE indicates all sources are missing.

--*/
{
    BOOLEAN anySourcePresent = FALSE;

    RtlZeroMemory(sources, sizeof(*sources));
    sources->epUniqueProcessId = dynState->kernelSources.epUniqueProcessId;
    sources->epActiveProcessLinks = dynState->kernelSources.epActiveProcessLinks;
    sources->epThreadListHead = dynState->kernelSources.epThreadListHead;
    sources->epImageFileName = dynState->kernelSources.epImageFileName;
    sources->epToken = dynState->kernelSources.epToken;
    sources->epObjectTable = dynState->kernelSources.epObjectTable;
    sources->epSectionObject = dynState->kernelSources.epSectionObject;
    sources->epProtection = dynState->kernelSources.epProtection;
    sources->epSignatureLevel = dynState->kernelSources.epSignatureLevel;
    sources->epSectionSignatureLevel = dynState->kernelSources.epSectionSignatureLevel;

    anySourcePresent = kswordArkProcessDetailSourcePresent(sources->epUniqueProcessId) ? TRUE : anySourcePresent;
    anySourcePresent = kswordArkProcessDetailSourcePresent(sources->epActiveProcessLinks) ? TRUE : anySourcePresent;
    anySourcePresent = kswordArkProcessDetailSourcePresent(sources->epThreadListHead) ? TRUE : anySourcePresent;
    anySourcePresent = kswordArkProcessDetailSourcePresent(sources->epImageFileName) ? TRUE : anySourcePresent;
    anySourcePresent = kswordArkProcessDetailSourcePresent(sources->epToken) ? TRUE : anySourcePresent;
    anySourcePresent = kswordArkProcessDetailSourcePresent(sources->epObjectTable) ? TRUE : anySourcePresent;
    anySourcePresent = kswordArkProcessDetailSourcePresent(sources->epSectionObject) ? TRUE : anySourcePresent;
    anySourcePresent = kswordArkProcessDetailSourcePresent(sources->epProtection) ? TRUE : anySourcePresent;
    anySourcePresent = kswordArkProcessDetailSourcePresent(sources->epSignatureLevel) ? TRUE : anySourcePresent;
    anySourcePresent = kswordArkProcessDetailSourcePresent(sources->epSectionSignatureLevel) ? TRUE : anySourcePresent;

    return anySourcePresent;
}

static ULONG64
kswordArkProcessDetailKernelGlobalAddress(
    _In_ const KswDynState* dynState,
    _In_ ULONG rva
    )
/*++

Routine Description:

    Convert global RVA from the ntoskrnl PDB profile to the current boot session kernel address.

Arguments:

    DynState: The current DynData snapshot, providing ntoskrnl identity and imageBase.
    Rva - The RVA of the verified global symbol.

Return Value:

    Current kernel VA for display; returns 0 if missing.

--*/
{
    if (!dynState->ntosActive || dynState->ntoskrnl.imageBase == 0ULL) {
        return 0ULL;
    }
    if (!kswordArkProcessDetailOffsetPresent(rva)) {
        return 0ULL;
    }

    return dynState->ntoskrnl.imageBase + (ULONG64)rva;
}

static BOOLEAN
kswordArkProcessDetailFillKernelGlobals(
    _In_ const KswDynState* dynState,
    _Out_ KSWORD_ARK_RUNTIME_KERNEL_GLOBALS* globals
    )
/*++

Routine Description:

    Copy key ntoskrnl global RVAs and sources provided by the PDB profile EX.

Arguments:

    DynState - Current DynData snapshot.
    Globals: Global RVA, source, and runtime address package in the shared response.

Return Value:

    TRUE indicates at least one global RVA is displayable; FALSE indicates all are missing.

--*/
{
    BOOLEAN anyGlobalPresent = FALSE;

    RtlZeroMemory(globals, sizeof(*globals));
    globals->pspCidTableRva = kswordArkProcessDetailProtocolOffset(dynState->kernelGlobals.pspCidTable);
    globals->psLoadedModuleListRva = kswordArkProcessDetailProtocolOffset(dynState->kernelGlobals.psLoadedModuleList);
    globals->mmUnloadedDriversRva = kswordArkProcessDetailProtocolOffset(dynState->kernelGlobals.mmUnloadedDrivers);
    globals->piDdbCacheTableRva = kswordArkProcessDetailProtocolOffset(dynState->kernelGlobals.piDdbCacheTable);
    globals->keServiceDescriptorTableShadowRva = kswordArkProcessDetailProtocolOffset(dynState->kernelGlobals.keServiceDescriptorTableShadow);
    globals->mmLastUnloadedDriverRva = kswordArkProcessDetailProtocolOffset(dynState->kernelGlobals.mmLastUnloadedDriver);
    globals->pspCidTableSource = dynState->kernelGlobalSources.pspCidTable;
    globals->psLoadedModuleListSource = dynState->kernelGlobalSources.psLoadedModuleList;
    globals->mmUnloadedDriversSource = dynState->kernelGlobalSources.mmUnloadedDrivers;
    globals->piDdbCacheTableSource = dynState->kernelGlobalSources.piDdbCacheTable;
    globals->keServiceDescriptorTableShadowSource = dynState->kernelGlobalSources.keServiceDescriptorTableShadow;
    globals->mmLastUnloadedDriverSource = dynState->kernelGlobalSources.mmLastUnloadedDriver;
    globals->pspCidTableAddress = kswordArkProcessDetailKernelGlobalAddress(dynState, dynState->kernelGlobals.pspCidTable);
    globals->psLoadedModuleListAddress = kswordArkProcessDetailKernelGlobalAddress(dynState, dynState->kernelGlobals.psLoadedModuleList);
    globals->mmUnloadedDriversAddress = kswordArkProcessDetailKernelGlobalAddress(dynState, dynState->kernelGlobals.mmUnloadedDrivers);
    globals->piDdbCacheTableAddress = kswordArkProcessDetailKernelGlobalAddress(dynState, dynState->kernelGlobals.piDdbCacheTable);
    globals->keServiceDescriptorTableShadowAddress = kswordArkProcessDetailKernelGlobalAddress(dynState, dynState->kernelGlobals.keServiceDescriptorTableShadow);
    globals->mmLastUnloadedDriverAddress = kswordArkProcessDetailKernelGlobalAddress(dynState, dynState->kernelGlobals.mmLastUnloadedDriver);

    anyGlobalPresent = kswordArkProcessDetailOffsetPresent(dynState->kernelGlobals.pspCidTable) ? TRUE : anyGlobalPresent;
    anyGlobalPresent = kswordArkProcessDetailOffsetPresent(dynState->kernelGlobals.psLoadedModuleList) ? TRUE : anyGlobalPresent;
    anyGlobalPresent = kswordArkProcessDetailOffsetPresent(dynState->kernelGlobals.mmUnloadedDrivers) ? TRUE : anyGlobalPresent;
    anyGlobalPresent = kswordArkProcessDetailOffsetPresent(dynState->kernelGlobals.piDdbCacheTable) ? TRUE : anyGlobalPresent;
    anyGlobalPresent = kswordArkProcessDetailOffsetPresent(dynState->kernelGlobals.keServiceDescriptorTableShadow) ? TRUE : anyGlobalPresent;
    anyGlobalPresent = kswordArkProcessDetailOffsetPresent(dynState->kernelGlobals.mmLastUnloadedDriver) ? TRUE : anyGlobalPresent;

    return anyGlobalPresent;
}

static VOID
kswordArkProcessDetailCopyImageName(
    _Out_writes_bytes_(KSWORD_ARK_RUNTIME_IMAGE_NAME_CHARS) CHAR* destination,
    _In_opt_z_ const CHAR* source
    )
/*++

Routine Description:

    Copy the short name returned by PsGetProcessImageFileName into a fixed protocol buffer.

Arguments:

    Destination: 16-byte ANSI short name buffer within the response packet.
    Source - The short process name returned by the kernel, which may be NULL.

Return Value:

    None.

--*/
{
    SIZE_T index = 0U;

    RtlZeroMemory(destination, KSWORD_ARK_RUNTIME_IMAGE_NAME_CHARS);
    if (source == NULL) {
        return;
    }

    while (index + 1U < KSWORD_ARK_RUNTIME_IMAGE_NAME_CHARS && source[index] != '\0') {
        destination[index] = source[index];
        ++index;
    }
}

static NTSTATUS
kswordArkProcessDetailReadUcharField(
    _In_ const VOID* object,
    _In_ ULONG offset,
    _Out_ UCHAR* valueOut
    )
/*++

Routine Description:

    Read a UCHAR field from EPROCESS via a cross-view safe read helper.

Arguments:

    Object - EPROCESS address.
    Offset - Field offset.
    ValueOut - Output bytes.

Return Value:

    STATUS_SUCCESS or secure read failure status.

--*/
{
    if (valueOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!kswordArkProcessDetailOffsetPresent(offset)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    return kswordArkCrossViewReadMemory((const UCHAR*)object + offset, valueOut, sizeof(*valueOut));
}

static NTSTATUS
kswordArkProcessDetailReadListEntryField(
    _In_ const VOID* object,
    _In_ ULONG offset,
    _Out_ ULONG64* flinkOut,
    _Out_ ULONG64* blinkOut
    )
/*++

Routine Description:

    Read the embedded LIST_ENTRY within EPROCESS for displaying ActiveProcessLinks/ThreadListHead.

Arguments:

    Object - EPROCESS address.
    Offset - Offset of the LIST_ENTRY field.
    FlinkOut: output Flink address.
    BlinkOut - Output the Blink address.

Return Value:

    STATUS_SUCCESS or secure read failure status.

--*/
{
    LIST_ENTRY listEntry;
    NTSTATUS status;

    if (flinkOut == NULL || blinkOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!kswordArkProcessDetailOffsetPresent(offset)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    RtlZeroMemory(&listEntry, sizeof(listEntry));
    status = kswordArkCrossViewReadMemory((const UCHAR*)object + offset, &listEntry, sizeof(listEntry));
    if (NT_SUCCESS(status)) {
        *flinkOut = (ULONG64)(ULONG_PTR)listEntry.Flink;
        *blinkOut = (ULONG64)(ULONG_PTR)listEntry.Blink;
    }

    return status;
}

static VOID
kswordArkProcessDetailNoteFailure(
    _In_ NTSTATUS readStatus,
    _Inout_ ULONG* failureCount,
    _Inout_ NTSTATUS* lastStatus
    )
/*++

Routine Description:

    Record a field read failure for the final status/detail summary.

Arguments:

    ReadStatus - Single-field read status.
    FailureCount: cumulative failure count field.
    LastStatus - Most recent failed NTSTATUS.

Return Value:

    None.

--*/
{
    if (!NT_SUCCESS(readStatus)) {
        ++(*failureCount);
        *lastStatus = readStatus;
    }
}

NTSTATUS
kswordArkDriverQueryProcessDetail(
    _Out_writes_bytes_(outputBufferLength) KSWORD_ARK_PROCESS_DETAIL_RESPONSE* response,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_PROCESS_DETAIL_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Query read-only runtime details for a single process. Note: This function retrieves the EPROCESS solely by PID,
    then reads fields using applied PDB/DynData offsets without modifying the target process or any kernel lists.

Arguments:

    Response - METHOD_BUFFERED output response.
    OutputBufferLength - Length of the output buffer.
    Request - optional fixed request; returns STATUS_INVALID_PARAMETER if NULL.
    BytesWrittenOut - Bytes written returned.

Return Value:

    STATUS_SUCCESS indicates a valid response packet; field-level missing data is expressed via response.status/detail.

--*/
{
    KswDynState dynState;
    PEPROCESS processObject = NULL;
    ULONG requestFlags = KSWORD_ARK_PROCESS_DETAIL_FLAG_INCLUDE_ALL;
    ULONG failureCount = 0UL;
    ULONG missingRequired = 0UL;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS lastStatus = STATUS_SUCCESS;

    if (response == NULL || request == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (outputBufferLength < sizeof(*response)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    *bytesWrittenOut = sizeof(*response);
    RtlZeroMemory(response, sizeof(*response));
    response->version = KSWORD_ARK_RUNTIME_DETAIL_PROTOCOL_VERSION;
    response->status = KSWORD_ARK_DETAIL_STATUS_UNKNOWN;
    response->processId = request->processId;
    response->requestedFlags = request->flags;

    if (request->version != KSWORD_ARK_RUNTIME_DETAIL_PROTOCOL_VERSION) {
        response->status = KSWORD_ARK_DETAIL_STATUS_UNSUPPORTED;
        response->lastStatus = STATUS_REVISION_MISMATCH;
        (VOID)RtlStringCchCopyW(response->detail, KSWORD_ARK_RUNTIME_DETAIL_TEXT_CHARS, L"Process detail request version mismatch.");
        return STATUS_SUCCESS;
    }

    if (request->processId == 0UL) {
        response->status = KSWORD_ARK_DETAIL_STATUS_LOOKUP_FAILED;
        response->lastStatus = STATUS_INVALID_PARAMETER;
        (VOID)RtlStringCchCopyW(response->detail, KSWORD_ARK_RUNTIME_DETAIL_TEXT_CHARS, L"Process detail requires a non-zero PID.");
        return STATUS_SUCCESS;
    }

    if (request->flags != 0UL) {
        requestFlags = request->flags;
    }

    kswordArkDynDataSnapshot(&dynState);
    response->dynDataCapabilityMask = dynState.capabilityMask;
    kswordArkProcessDetailFillOffsets(&dynState, &response->offsets);
    if (kswordArkProcessDetailFillSources(&dynState, &response->sources)) {
        response->fieldFlags |= KSWORD_ARK_PROCESS_DETAIL_FIELD_OFFSET_SOURCES;
    }
    if (kswordArkProcessDetailFillKernelGlobals(&dynState, &response->kernelGlobals)) {
        response->fieldFlags |= KSWORD_ARK_PROCESS_DETAIL_FIELD_KERNEL_GLOBALS;
    }

    status = PsLookupProcessByProcessId(ULongToHandle(request->processId), &processObject);
    if (!NT_SUCCESS(status)) {
        response->status = KSWORD_ARK_DETAIL_STATUS_LOOKUP_FAILED;
        response->lastStatus = status;
        (VOID)RtlStringCchPrintfW(response->detail, KSWORD_ARK_RUNTIME_DETAIL_TEXT_CHARS, L"PsLookupProcessByProcessId failed for PID %lu: 0x%08X.", request->processId, (unsigned int)status);
        return STATUS_SUCCESS;
    }

    response->processObjectAddress = (ULONG64)(ULONG_PTR)processObject;
    response->fieldFlags |= KSWORD_ARK_PROCESS_DETAIL_FIELD_OBJECT_ADDRESS;
    response->fieldFlags |= KSWORD_ARK_PROCESS_DETAIL_FIELD_PUBLIC_IDENTITY;
    kswordArkProcessDetailCopyImageName(response->imageName, PsGetProcessImageFileName(processObject));

    if ((requestFlags & KSWORD_ARK_PROCESS_DETAIL_FLAG_INCLUDE_PUBLIC_IDENTITY) != 0UL) {
        response->uniqueProcessIdValue = (ULONG64)(ULONG_PTR)PsGetProcessId(processObject);
        response->fieldFlags |= KSWORD_ARK_PROCESS_DETAIL_FIELD_UNIQUE_PROCESS_ID;
        /* Verify that the PDB/DynData offset is available first to avoid misinterpreting an unavailable sentinel as an EPROCESS offset. */
        if (kswordArkProcessDetailOffsetPresent(dynState.kernel.epImageFileName)) {
            status = kswordArkCrossViewReadMemory(
                (const UCHAR*)processObject + dynState.kernel.epImageFileName,
                response->imageName,
                KSWORD_ARK_RUNTIME_IMAGE_NAME_CHARS - 1U);
        }
        else {
            status = STATUS_PROCEDURE_NOT_FOUND;
        }
        if (NT_SUCCESS(status)) {
            response->imageName[KSWORD_ARK_RUNTIME_IMAGE_NAME_CHARS - 1U] = '\0';
            response->fieldFlags |= KSWORD_ARK_PROCESS_DETAIL_FIELD_IMAGE_FILE_NAME;
        }
        else {
            response->missingCapabilityMask |= KSW_CAP_PROCESS_LIST_FIELDS;
        }
        kswordArkProcessDetailNoteFailure(status, &failureCount, &lastStatus);
    }

    if ((requestFlags & KSWORD_ARK_PROCESS_DETAIL_FLAG_INCLUDE_LIST_LINKS) != 0UL) {
        status = kswordArkProcessDetailReadListEntryField(processObject, dynState.kernel.epActiveProcessLinks, &response->activeProcessLinksFlink, &response->activeProcessLinksBlink);
        if (NT_SUCCESS(status)) {
            response->fieldFlags |= KSWORD_ARK_PROCESS_DETAIL_FIELD_ACTIVE_PROCESS_LINKS;
        }
        else {
            response->missingCapabilityMask |= KSW_CAP_PROCESS_LIST_FIELDS;
            ++missingRequired;
        }
        kswordArkProcessDetailNoteFailure(status, &failureCount, &lastStatus);

        status = kswordArkProcessDetailReadListEntryField(processObject, dynState.kernel.epThreadListHead, &response->threadListHeadFlink, &response->threadListHeadBlink);
        if (NT_SUCCESS(status)) {
            response->fieldFlags |= KSWORD_ARK_PROCESS_DETAIL_FIELD_THREAD_LIST_HEAD;
        }
        else {
            response->missingCapabilityMask |= KSW_CAP_PROCESS_LIST_FIELDS;
            ++missingRequired;
        }
        kswordArkProcessDetailNoteFailure(status, &failureCount, &lastStatus);
    }

    if ((requestFlags & KSWORD_ARK_PROCESS_DETAIL_FLAG_INCLUDE_TOKEN_FASTREF) != 0UL) {
        PVOID tokenFastRef = NULL;
        status = kswordArkCrossViewReadPointerField(processObject, dynState.kernel.epToken, &tokenFastRef);
        if (NT_SUCCESS(status)) {
            response->tokenFastRef = (ULONG64)(ULONG_PTR)tokenFastRef;
            response->tokenObjectAddress = response->tokenFastRef & ~0xFULL;
            response->fieldFlags |= KSWORD_ARK_PROCESS_DETAIL_FIELD_TOKEN_FASTREF;
        }
        else {
            response->missingCapabilityMask |= KSW_CAP_PROCESS_LIST_FIELDS;
        }
        kswordArkProcessDetailNoteFailure(status, &failureCount, &lastStatus);
    }

    if ((requestFlags & KSWORD_ARK_PROCESS_DETAIL_FLAG_INCLUDE_OBJECT_POINTERS) != 0UL) {
        PVOID objectTable = NULL;
        PVOID sectionObject = NULL;
        status = kswordArkCrossViewReadPointerField(processObject, dynState.kernel.epObjectTable, &objectTable);
        if (NT_SUCCESS(status)) {
            response->objectTableAddress = (ULONG64)(ULONG_PTR)objectTable;
            response->fieldFlags |= KSWORD_ARK_PROCESS_DETAIL_FIELD_OBJECT_TABLE;
        }
        else {
            response->missingCapabilityMask |= KSW_CAP_PROCESS_OBJECT_TABLE;
        }
        kswordArkProcessDetailNoteFailure(status, &failureCount, &lastStatus);

        status = kswordArkCrossViewReadPointerField(processObject, dynState.kernel.epSectionObject, &sectionObject);
        if (NT_SUCCESS(status)) {
            response->sectionObjectAddress = (ULONG64)(ULONG_PTR)sectionObject;
            response->fieldFlags |= KSWORD_ARK_PROCESS_DETAIL_FIELD_SECTION_OBJECT;
        }
        else {
            response->missingCapabilityMask |= KSW_CAP_SECTION_CONTROL_AREA;
        }
        kswordArkProcessDetailNoteFailure(status, &failureCount, &lastStatus);
    }

    if ((requestFlags & KSWORD_ARK_PROCESS_DETAIL_FLAG_INCLUDE_PROTECTION) != 0UL) {
        status = kswordArkProcessDetailReadUcharField(processObject, dynState.kernel.epProtection, &response->protection);
        if (NT_SUCCESS(status)) {
            response->fieldFlags |= KSWORD_ARK_PROCESS_DETAIL_FIELD_PROTECTION;
        }
        else {
            response->missingCapabilityMask |= KSW_CAP_PROCESS_PROTECTION_PATCH;
        }
        kswordArkProcessDetailNoteFailure(status, &failureCount, &lastStatus);

        status = kswordArkProcessDetailReadUcharField(processObject, dynState.kernel.epSignatureLevel, &response->signatureLevel);
        if (NT_SUCCESS(status)) {
            response->fieldFlags |= KSWORD_ARK_PROCESS_DETAIL_FIELD_SIGNATURE_LEVEL;
        }
        else {
            response->missingCapabilityMask |= KSW_CAP_PROCESS_PROTECTION_PATCH;
        }
        kswordArkProcessDetailNoteFailure(status, &failureCount, &lastStatus);

        status = kswordArkProcessDetailReadUcharField(processObject, dynState.kernel.epSectionSignatureLevel, &response->sectionSignatureLevel);
        if (NT_SUCCESS(status)) {
            response->fieldFlags |= KSWORD_ARK_PROCESS_DETAIL_FIELD_SECTION_SIGNATURE;
        }
        else {
            response->missingCapabilityMask |= KSW_CAP_PROCESS_PROTECTION_PATCH;
        }
        kswordArkProcessDetailNoteFailure(status, &failureCount, &lastStatus);
    }

    if (processObject != NULL) {
        ObDereferenceObject(processObject);
        processObject = NULL;
    }

    if (missingRequired != 0UL) {
        response->status = KSWORD_ARK_DETAIL_STATUS_CAPABILITY_MISSING;
    }
    else if (failureCount != 0UL) {
        response->status = KSWORD_ARK_DETAIL_STATUS_PARTIAL;
    }
    else {
        response->status = KSWORD_ARK_DETAIL_STATUS_OK;
    }

    response->lastStatus = lastStatus;
    (VOID)RtlStringCchPrintfW(
        response->detail,
        KSWORD_ARK_RUNTIME_DETAIL_TEXT_CHARS,
        L"Process detail sampled by PID. fields=0x%08lX missingCaps=0x%I64X failures=%lu.",
        (unsigned long)response->fieldFlags,
        response->missingCapabilityMask,
        (unsigned long)failureCount);
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkProcessIoctlQueryDetail(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_QUERY_PROCESS_DETAIL. Note: The handler performs only
    fixed buffer validation and copies the request to the stack; actual sampling
    of read-only fields is completed in kswordArkDriverQueryProcessDetail.

Arguments:

    Device - WDF device object; currently used only for signature consistency, not directly accessing device extension.
    Request - Current IOCTL request.
    InputBufferLength - Input length; must include KSWORD_ARK_PROCESS_DETAIL_REQUEST.
    OutputBufferLength: Output length; must accommodate KSWORD_ARK_PROCESS_DETAIL_RESPONSE.
    BytesReturned - Returns the number of response bytes.

Return Value:

    NTSTATUS from WDF buffer retrieval or process detail backend.

--*/
{
    KSWORD_ARK_PROCESS_DETAIL_REQUEST requestCopy;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(device);
    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(KSWORD_ARK_PROCESS_DETAIL_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(&requestCopy, sizeof(requestCopy));
    RtlCopyMemory(&requestCopy, inputBuffer, sizeof(requestCopy));

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(KSWORD_ARK_PROCESS_DETAIL_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return kswordArkDriverQueryProcessDetail(
        (KSWORD_ARK_PROCESS_DETAIL_RESPONSE*)outputBuffer,
        actualOutputLength,
        &requestCopy,
        bytesReturned);
}


/*
 * KswProcessRuntimeFieldRequestSnapshot
 * Stack layout for a METHOD_BUFFERED snapshot request. Note: The shared protocol uses items[1] as a
 * variable-length placeholder; here, the remaining MAX_ITEMS-1 items are padded so the handler can
 * save the entire request in an aligned stack local without allocating pool memory for each query.
 */
typedef struct KswProcessRuntimeFieldRequestSnapshot
{
    KSWORD_ARK_PROCESS_RUNTIME_FIELD_SAMPLE_REQUEST header;
    KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ITEM_REQUEST extraItems[
        KSWORD_ARK_RUNTIME_FIELD_SAMPLE_MAX_ITEMS - 1U];
} KswProcessRuntimeFieldRequestSnapshot;

static size_t
kswordArkProcessRuntimeFieldRequestHeaderSize(VOID)
/*++

Routine Description:

    Calculate the variable-length request header length for the process runtime field sample. Note: entries[1]
    is a variable-length placeholder in the shared protocol; the actual input length must exclude this item.

Arguments:

    None.

Return Value:

    Request header byte count excluding the placeholder for the first item.

--*/
{
    return sizeof(KSWORD_ARK_PROCESS_RUNTIME_FIELD_SAMPLE_REQUEST) -
        sizeof(KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ITEM_REQUEST);
}

static size_t
kswordArkRuntimeFieldSampleResponseHeaderSize(VOID)
/*++

Routine Description:

    Calculate the variable-length header size of the runtime field sample response. Note: The
    caller uses this value to determine the maximum number of rows the output buffer can hold.

Arguments:

    None.

Return Value:

    Response header byte count excluding the space occupied by the first row.

--*/
{
    return sizeof(KSWORD_ARK_RUNTIME_FIELD_SAMPLE_RESPONSE) -
        sizeof(KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW);
}

static BOOLEAN
kswordArkRuntimeFieldSampleRequestLengthValid(
    _In_ size_t headerSize,
    _In_ ULONG itemCount,
    _In_ size_t inputBufferLength
    )
/*++

Routine Description:

    Verify that the runtime field sample input buffer covers all declared items.

Arguments:

    HeaderSize: Length of the variable-length request header excluding items[1].
    ItemCount: Number of sample items declared in R3.
    InputBufferLength - Actual WDF input buffer length.

Return Value:

    TRUE indicates length consistency; FALSE indicates input truncation or count overflow.

--*/
{
    const size_t kItemSize = sizeof(KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ITEM_REQUEST);
    size_t requiredLength = headerSize;

    if (inputBufferLength < headerSize) {
        return FALSE;
    }
    if (itemCount > ((((size_t)-1) - headerSize) / kItemSize)) {
        return FALSE;
    }

    requiredLength = headerSize + ((size_t)itemCount * kItemSize);
    return (inputBufferLength >= requiredLength) ? TRUE : FALSE;
}

static ULONG
kswordArkRuntimeFieldSampleReturnedCount(
    _In_ ULONG itemCount,
    _In_ size_t outputBufferLength
    )
/*++

Routine Description:

    Calculate the maximum number of runtime sample rows that can be returned in this batch based on the output buffer capacity.

Arguments:

    ItemCount - Number of requested items.
    OutputBufferLength: WDF output buffer length.

Return Value:

    returnedCount after being limited by both the protocol maximum and the output buffer.

--*/
{
    const size_t kHeaderSize = kswordArkRuntimeFieldSampleResponseHeaderSize();
    const ULONG kCappedItemCount = itemCount > KSWORD_ARK_RUNTIME_FIELD_SAMPLE_MAX_ITEMS ?
        KSWORD_ARK_RUNTIME_FIELD_SAMPLE_MAX_ITEMS : itemCount;
    size_t outputRowCapacity = 0U;

    if (outputBufferLength <= kHeaderSize) {
        return 0UL;
    }

    outputRowCapacity = (outputBufferLength - kHeaderSize) /
        sizeof(KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW);
    if (outputRowCapacity > (size_t)kCappedItemCount) {
        return kCappedItemCount;
    }

    return (ULONG)outputRowCapacity;
}

static VOID
kswordArkRuntimeFieldSampleOne(
    _In_ const VOID* object,
    _In_ const KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ITEM_REQUEST* item,
    _Out_ KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW* row
    )
/*++

Routine Description:

    Read-only sample a small field from a kernel object already obtained via R0 lookup/reference.

Arguments:

    Object: base address of EPROCESS or ETHREAD; never derived from R3 input.
    Item: Runtime metadata (runtimeItemId/offset/size) passed from R3.
    Row - Output row containing status, raw bytes, and U64 summary.

Return Value:

    None. Field-level failure writes to Row->status and Row->lastStatus.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;

    RtlZeroMemory(row, sizeof(*row));
    row->runtimeItemId = item->runtimeItemId;
    row->offset = item->offset;
    row->size = item->size;
    row->flags = item->flags;
    row->status = KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW_STATUS_UNKNOWN;
    row->lastStatus = STATUS_SUCCESS;

    if (item->size == 0UL || item->size > KSWORD_ARK_RUNTIME_FIELD_SAMPLE_MAX_VALUE_BYTES) {
        row->status = KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW_STATUS_SIZE_REJECTED;
        row->lastStatus = STATUS_INVALID_PARAMETER;
        return;
    }
    if (item->offset == KSW_DYN_OFFSET_UNAVAILABLE || item->offset == 0x0000FFFFUL) {
        row->status = KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW_STATUS_OFFSET_REJECTED;
        row->lastStatus = STATUS_PROCEDURE_NOT_FOUND;
        return;
    }
    if (item->offset > (KSWORD_ARK_RUNTIME_FIELD_SAMPLE_MAX_OFFSET - item->size)) {
        row->status = KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW_STATUS_OFFSET_REJECTED;
        row->lastStatus = STATUS_INVALID_PARAMETER;
        return;
    }

    status = kswordArkCrossViewReadMemory(
        (const UCHAR*)object + item->offset,
        row->sampleBytes,
        item->size);
    row->lastStatus = status;
    if (!NT_SUCCESS(status)) {
        row->status = KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW_STATUS_READ_FAILED;
        return;
    }

    row->status = KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW_STATUS_OK;
    row->bytesRead = item->size;
    if (item->size <= sizeof(row->valueU64)) {
        RtlCopyMemory(&row->valueU64, row->sampleBytes, item->size);
    }
}

NTSTATUS
kswordArkDriverQueryProcessRuntimeFields(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) KSWORD_ARK_RUNTIME_FIELD_SAMPLE_RESPONSE* response,
    _In_ size_t outputBufferLength,
    _In_reads_bytes_(inputBufferLength) const KSWORD_ARK_PROCESS_RUNTIME_FIELD_SAMPLE_REQUEST* request,
    _In_ size_t inputBufferLength,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Performs generic deep PDB runtime field sampling on EPROCESS by PID.

Arguments:

    Response - variable-length METHOD_BUFFERED response buffer.
    OutputBufferLength - Length of the output buffer.
    Request - Variable-length request containing PID and field sampling items.
    InputBufferLength: Actual length of the input buffer.
    BytesWrittenOut - Actual bytes written.

Return Value:

    STATUS_SUCCESS indicates a valid response header; row-level failures are expressed via entries[].status.

--*/
{
    KswDynState dynState;
    PEPROCESS processObject = NULL;
    ULONG returnedCount = 0UL;
    ULONG rowIndex = 0UL;
    NTSTATUS status = STATUS_SUCCESS;
    const size_t kRequestHeaderSize = kswordArkProcessRuntimeFieldRequestHeaderSize();
    const size_t kResponseHeaderSize = kswordArkRuntimeFieldSampleResponseHeaderSize();

    if (response == NULL || request == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (outputBufferLength < kResponseHeaderSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    *bytesWrittenOut = kResponseHeaderSize;
    RtlZeroMemory(response, outputBufferLength);
    response->version = KSWORD_ARK_RUNTIME_FIELD_SAMPLE_PROTOCOL_VERSION;
    response->entrySize = sizeof(KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW);
    response->status = KSWORD_ARK_RUNTIME_FIELD_SAMPLE_STATUS_UNKNOWN;

    if (request->version != KSWORD_ARK_RUNTIME_FIELD_SAMPLE_PROTOCOL_VERSION ||
        !kswordArkRuntimeFieldSampleRequestLengthValid(kRequestHeaderSize, request->itemCount, inputBufferLength)) {
        response->status = KSWORD_ARK_RUNTIME_FIELD_SAMPLE_STATUS_INVALID_REQUEST;
        response->lastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }

    response->totalCount = request->itemCount;
    response->flags = request->flags;
    returnedCount = kswordArkRuntimeFieldSampleReturnedCount(request->itemCount, outputBufferLength);
    response->returnedCount = returnedCount;
    *bytesWrittenOut = kResponseHeaderSize + ((size_t)returnedCount * sizeof(KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW));
    if (returnedCount < request->itemCount || request->itemCount > KSWORD_ARK_RUNTIME_FIELD_SAMPLE_MAX_ITEMS) {
        response->status = KSWORD_ARK_RUNTIME_FIELD_SAMPLE_STATUS_TRUNCATED;
    }

    kswordArkDynDataSnapshot(&dynState);
    response->dynDataCapabilityMask = dynState.capabilityMask;

    if (request->processId == 0UL) {
        response->status = KSWORD_ARK_RUNTIME_FIELD_SAMPLE_STATUS_LOOKUP_FAILED;
        response->lastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }

    status = PsLookupProcessByProcessId(ULongToHandle(request->processId), &processObject);
    if (!NT_SUCCESS(status)) {
        response->status = KSWORD_ARK_RUNTIME_FIELD_SAMPLE_STATUS_LOOKUP_FAILED;
        response->lastStatus = status;
        return STATUS_SUCCESS;
    }

    response->objectAddress = (ULONG64)(ULONG_PTR)processObject;
    for (rowIndex = 0UL; rowIndex < returnedCount; ++rowIndex) {
        kswordArkRuntimeFieldSampleOne(processObject, &request->items[rowIndex], &response->entries[rowIndex]);
        if (!NT_SUCCESS(response->entries[rowIndex].lastStatus) && response->lastStatus == STATUS_SUCCESS) {
            response->lastStatus = response->entries[rowIndex].lastStatus;
        }
    }

    if (response->status == KSWORD_ARK_RUNTIME_FIELD_SAMPLE_STATUS_UNKNOWN) {
        response->status = (response->lastStatus == STATUS_SUCCESS) ?
            KSWORD_ARK_RUNTIME_FIELD_SAMPLE_STATUS_OK :
            KSWORD_ARK_RUNTIME_FIELD_SAMPLE_STATUS_PARTIAL;
    }

    ObDereferenceObject(processObject);
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkProcessIoctlQueryRuntimeFields(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_QUERY_PROCESS_RUNTIME_FIELDS. Note: The handler only retrieves
    the WDF input/output buffer; actual read-only sampling is performed by the backend.

Arguments:

    Device - WDF device object; currently only maintains handler signature compatibility.
    Request - Current IOCTL request.
    InputBufferLength - WDF-provided input length hint.
    OutputBufferLength: Output length hint passed by WDF.
    BytesReturned - Actual response bytes returned.

Return Value:

    NTSTATUS from WDF buffer retrieval or process runtime sampler backend.

--*/
{
    // requestSnapshot covers the protocol limit (header + MAX_ITEMS samples); any valid request fits within this limit.
    KswProcessRuntimeFieldRequestSnapshot requestSnapshot;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    size_t snapshotLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(device);
    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        kswordArkProcessRuntimeFieldRequestHeaderSize(),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /*
     * For METHOD_BUFFERED, input and output share the same SystemBuffer. The backend first clears
     * the output with RtlZeroMemory, then reads itemCount and items[]. Without a snapshot, response
     * bytes are treated as sample items, corrupting the item count and offsets. Data exceeding
     * MAX_ITEMS is not copied; the backend's length check will then flag this as INVALID_REQUEST.
     */
    snapshotLength = min(actualInputLength, sizeof(requestSnapshot));
    RtlZeroMemory(&requestSnapshot, sizeof(requestSnapshot));
    RtlCopyMemory(&requestSnapshot, inputBuffer, snapshotLength);

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        kswordArkRuntimeFieldSampleResponseHeaderSize(),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return kswordArkDriverQueryProcessRuntimeFields(
        (KSWORD_ARK_RUNTIME_FIELD_SAMPLE_RESPONSE*)outputBuffer,
        actualOutputLength,
        &requestSnapshot.header,
        snapshotLength,
        bytesReturned);
}
