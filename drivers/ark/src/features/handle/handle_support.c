/*++

Module Name:

    handle_support.c

Abstract:

    Shared helpers for handle table and object detail queries.

Environment:

    Kernel-mode Driver Framework

--*/

#include "handle_support.h"
#include "../kernel/object_header_fallback.h"

BOOLEAN
kswordArkHandleIsOffsetPresent(
    _In_ ULONG offset
    )
/*++

Routine Description:

    normalize DynData offset availability before touching a private kernel field.
    Note: System Informer missing values and Ksword missing values are uniformly
    validated here to avoid scattered, duplicate checks in subsequent read paths.

Arguments:

    Offset - Candidate offset or shift value from the active DynData state.

Return Value:

    TRUE when the value can be used; otherwise FALSE.

--*/
{
    return (offset != KSW_DYN_OFFSET_UNAVAILABLE && offset != 0x0000FFFFUL) ? TRUE : FALSE;
}

ULONG
kswordArkHandleNormalizeOffset(
    _In_ ULONG offset
    )
/*++

Routine Description:

    Convert internal unavailable sentinels into the handle protocol sentinel.
    Note: UI relies on this raw offset for diagnostic display; it is not used in any subsequent operations.

Arguments:

    Offset - Raw DynData value.

Return Value:

    Usable offset/shift or KSWORD_ARK_HANDLE_OFFSET_UNAVAILABLE.

--*/
{
    if (!kswordArkHandleIsOffsetPresent(offset)) {
        return KSWORD_ARK_HANDLE_OFFSET_UNAVAILABLE;
    }

    return offset;
}

VOID
kswordArkHandlePrepareObjectDynData(
    _Inout_ KSWORD_ARK_QUERY_HANDLE_OBJECT_RESPONSE* response,
    _In_ const KswDynState* dynState
    )
/*++

Routine Description:

    Copy object-query DynData diagnostics into the response. Note: Only output OBJECT_TYPE-related
    offsets and capabilities; do not leak reusable kernel operation credentials.

Arguments:

    Response - Mutable object query response.
    DynState - Active DynData snapshot.

Return Value:

    None.

--*/
{
    if (response == NULL || dynState == NULL) {
        return;
    }

    response->dynDataCapabilityMask = dynState->capabilityMask;
    response->otNameOffset = kswordArkHandleNormalizeOffset(dynState->kernel.otName);
    response->otIndexOffset = kswordArkHandleNormalizeOffset(dynState->kernel.otIndex);
}

PVOID
kswordArkHandleGetObjectBodyFromHeader(
    _In_opt_ PVOID objectHeader
    )
/*++

Routine Description:

    Convert an OBJECT_HEADER pointer into its body pointer. Note: The caller uses the result solely for read-only
    display or query input, never as a credential to perform arbitrary object operations on that address.

Arguments:

    ObjectHeader - Optional decoded object header pointer.

Return Value:

    Object body pointer when ObjectHeader is non-NULL; otherwise NULL.

--*/
{
    ULONG bodyOffset = 0UL;

    if (objectHeader == NULL) {
        return NULL;
    }
    if (!NT_SUCCESS(kswordArkObjectHeaderResolveBodyOffsetFallback(&bodyOffset))) {
        return NULL;
    }
    return (PUCHAR)objectHeader + bodyOffset;
}

PVOID
kswordArkHandleGetObjectHeaderFromBody(
    _In_opt_ PVOID objectBody
    )
/*++

Routine Description:

    Convert an object body pointer back to its OBJECT_HEADER. Note: This conversion is only valid when the object has
    already been successfully referenced via ObReferenceObjectByHandle; a read failure will still occur otherwise.
    Per-entry/per-query state absorption.

Arguments:

    ObjectBody - Optional object body pointer.

Return Value:

    Object header pointer when ObjectBody is non-NULL; otherwise NULL.

--*/
{
    ULONG bodyOffset = 0UL;

    if (objectBody == NULL) {
        return NULL;
    }
    if (!NT_SUCCESS(kswordArkObjectHeaderResolveBodyOffsetFallback(&bodyOffset)) ||
        (ULONG_PTR)objectBody < bodyOffset) {
        return NULL;
    }
    return (PUCHAR)objectBody - bodyOffset;
}

NTSTATUS
kswordArkHandleReadObjectTypeIndex(
    _In_opt_ POBJECT_TYPE objectType,
    _In_ const KswDynState* dynState,
    _Out_ ULONG* objectTypeIndexOut
    )
/*++

Routine Description:

    Read OBJECT_TYPE.Index through the DynData OtIndex offset. Note: This does not rely on the
    compile-time OBJECT_TYPE layout; if the offset is missing, return STATUS_NOT_SUPPORTED.

Arguments:

    ObjectType - Object type pointer from ObGetObjectType.
    DynState - Active DynData snapshot containing OtIndex.
    ObjectTypeIndexOut - Receives the decoded type index.

Return Value:

    STATUS_SUCCESS when the index is decoded; otherwise an NTSTATUS failure.

--*/
{
    if (objectTypeIndexOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *objectTypeIndexOut = 0UL;

    if (objectType == NULL || dynState == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!kswordArkHandleIsOffsetPresent(dynState->kernel.otIndex)) {
        return STATUS_NOT_SUPPORTED;
    }

    __try {
        *objectTypeIndexOut = (ULONG)(*(PUCHAR)((PUCHAR)objectType + dynState->kernel.otIndex));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    return STATUS_SUCCESS;
}

ULONG
kswordArkHandleMergeTypeIndexSource(
    _In_ BOOLEAN objectTypeIndexPresent,
    _In_ ULONG objectTypeIndex,
    _In_ BOOLEAN headerTypeIndexPresent,
    _In_ ULONG headerTypeIndex
    )
/*++

Routine Description:

    Describe where the final type index came from. Note: When OBJECT_TYPE.Index and
    OBJECT_HEADER.TypeIndex are both readable but inconsistent, R3 can directly display the mismatch.

Arguments:

    ObjectTypeIndexPresent - TRUE when OBJECT_TYPE.Index was decoded.
    ObjectTypeIndex - Index from OBJECT_TYPE.
    HeaderTypeIndexPresent - TRUE when OBJECT_HEADER.TypeIndex was decoded.
    HeaderTypeIndex - Index from OBJECT_HEADER.

Return Value:

    KSWORD_ARK_OBJECT_TYPE_SOURCE_* value.

--*/
{
    if (objectTypeIndexPresent && headerTypeIndexPresent) {
        return (objectTypeIndex == headerTypeIndex) ?
            KSWORD_ARK_OBJECT_TYPE_SOURCE_BOTH_MATCH :
            KSWORD_ARK_OBJECT_TYPE_SOURCE_BOTH_MISMATCH;
    }

    if (objectTypeIndexPresent) {
        return KSWORD_ARK_OBJECT_TYPE_SOURCE_OBJECT_TYPE_INDEX;
    }

    if (headerTypeIndexPresent) {
        return KSWORD_ARK_OBJECT_TYPE_SOURCE_OBJECT_HEADER;
    }

    return KSWORD_ARK_OBJECT_TYPE_SOURCE_NONE;
}

static VOID
kswordArkHandleReadHeaderValues(
    _In_opt_ PVOID objectHeader,
    _In_opt_ PVOID objectBody,
    _In_opt_ POBJECT_TYPE objectType,
    _In_ const KswDynState* dynState,
    _Out_ ULONG* fieldFlagsOut,
    _Out_ ULONG* decodeStatusOut,
    _Out_ NTSTATUS* readStatusOut,
    _Out_ ULONG* headerTypeIndexOut,
    _Out_ ULONG* infoMaskOut,
    _Out_ ULONG* headerFlagsOut,
    _Out_ ULONG* traceFlagsOut,
    _Out_ LONG64* pointerCountOut,
    _Out_ ULONG64* handleCountOut,
    _Out_ ULONG64* headerAddressOut,
    _Out_ ULONG64* typeAddressOut,
    _Out_ ULONG* typeIndexSourceOut,
    _Out_ ULONG* nameInfoStatusOut
    )
/*++

Routine Description:

    Safely read common OBJECT_HEADER fields into scalar outputs. Note: All pointer dereferences
    occur within __try blocks; exceptions affect only the current line or current query.

Arguments:

    ObjectHeader - Optional header pointer; derived from ObjectBody when absent.
    ObjectBody - Optional body pointer used to derive the header.
    ObjectType - Optional object type pointer used for source comparison.
    DynState - Active DynData snapshot used for capability and OtIndex reads.
    FieldFlagsOut - Receives protocol field flags.
    DecodeStatusOut - Receives protocol decode status.
    ReadStatusOut - Receives NTSTATUS read status.
    HeaderTypeIndexOut - Receives OBJECT_HEADER.TypeIndex.
    InfoMaskOut - Receives OBJECT_HEADER.InfoMask.
    HeaderFlagsOut - Receives OBJECT_HEADER.Flags.
    TraceFlagsOut - Receives OBJECT_HEADER.TraceFlags.
    PointerCountOut - Receives OBJECT_HEADER.PointerCount.
    HandleCountOut - Receives OBJECT_HEADER.HandleCount.
    HeaderAddressOut - Receives OBJECT_HEADER address.
    TypeAddressOut - Receives OBJECT_TYPE address.
    TypeIndexSourceOut - Receives source/mismatch classification.
    NameInfoStatusOut - Receives conservative name-info availability status.

Return Value:

    None.

--*/
{
    KswObjectHeaderFallbackResult fallback;
    PVOID header = NULL;
    ULONG objectTypeIndex = 0UL;
    NTSTATUS fallbackStatus = STATUS_NOT_SUPPORTED;
    NTSTATUS typeIndexStatus = STATUS_UNSUCCESSFUL;
    BOOLEAN objectTypeIndexPresent = FALSE;

    *fieldFlagsOut = 0UL;
    *decodeStatusOut = KSWORD_ARK_HANDLE_DECODE_STATUS_UNAVAILABLE;
    *readStatusOut = STATUS_SUCCESS;
    *headerTypeIndexOut = 0UL;
    *infoMaskOut = 0UL;
    *headerFlagsOut = 0UL;
    *traceFlagsOut = 0UL;
    *pointerCountOut = 0LL;
    *handleCountOut = 0ULL;
    *headerAddressOut = 0ULL;
    *typeAddressOut = 0ULL;
    *typeIndexSourceOut = KSWORD_ARK_OBJECT_TYPE_SOURCE_NONE;
    *nameInfoStatusOut = KSWORD_ARK_OBJECT_NAME_INFO_STATUS_UNKNOWN;

    UNREFERENCED_PARAMETER(objectHeader);
    RtlZeroMemory(&fallback, sizeof(fallback));
    if (objectBody == NULL) {
        *decodeStatusOut = KSWORD_ARK_HANDLE_DECODE_STATUS_OBJECT_DECODE_FAILED;
        *readStatusOut = STATUS_INVALID_PARAMETER;
        return;
    }
    fallbackStatus = kswordArkObjectHeaderQueryFallback(objectBody, &fallback);
    *readStatusOut = fallbackStatus;
    if (!NT_SUCCESS(fallbackStatus) ||
        (ULONG_PTR)objectBody < fallback.bodyOffset) {
        *decodeStatusOut = KSWORD_ARK_HANDLE_DECODE_STATUS_HEADER_DYNDATA_MISSING;
        return;
    }

    header = (PUCHAR)objectBody - fallback.bodyOffset;
    *headerAddressOut = (ULONG64)(ULONG_PTR)header;
    *pointerCountOut = (LONG64)fallback.pointerCount;
    *fieldFlagsOut |=
        KSWORD_ARK_HANDLE_FIELD_OBJECT_HEADER_PRESENT |
        KSWORD_ARK_HANDLE_FIELD_POINTER_COUNT_PRESENT;
    if ((fallback.validFields &
            KSW_OBJECT_HEADER_FALLBACK_FIELD_HANDLE_COUNT) != 0UL) {
        *handleCountOut = (ULONG64)fallback.handleCount;
        *fieldFlagsOut |= KSWORD_ARK_HANDLE_FIELD_HANDLE_COUNT_PRESENT;
    }

    if (objectBody != NULL) {
        *fieldFlagsOut |= KSWORD_ARK_HANDLE_FIELD_OBJECT_HEADER_BODY_PRESENT;
    }
    if (objectType != NULL) {
        *fieldFlagsOut |= KSWORD_ARK_HANDLE_FIELD_OBJECT_TYPE_PRESENT;
        *typeAddressOut = (ULONG64)(ULONG_PTR)objectType;
        typeIndexStatus = kswordArkHandleReadObjectTypeIndex(objectType, dynState, &objectTypeIndex);
        objectTypeIndexPresent = NT_SUCCESS(typeIndexStatus) ? TRUE : FALSE;
    }

    *typeIndexSourceOut = kswordArkHandleMergeTypeIndexSource(
        objectTypeIndexPresent,
        objectTypeIndex,
        FALSE,
        *headerTypeIndexOut);
    *decodeStatusOut = KSWORD_ARK_HANDLE_DECODE_STATUS_PARTIAL;
}

VOID
kswordArkHandleFillEntryObjectHeaderAudit(
    _Inout_ KSWORD_ARK_HANDLE_ENTRY* entry,
    _In_opt_ PVOID objectHeader,
    _In_opt_ PVOID objectBody,
    _In_opt_ POBJECT_TYPE objectType,
    _In_ const KswDynState* dynState
    )
/*++

Routine Description:

    Copy OBJECT_HEADER audit fields into one enumeration entry. Note: On failure, only write to
    Entry->objectHeaderDecodeStatus without overwriting successfully decoded base handle fields.

Arguments:

    Entry - Mutable handle enumeration row.
    ObjectHeader - Optional decoded OBJECT_HEADER pointer.
    ObjectBody - Optional object body pointer.
    ObjectType - Optional object type pointer.
    DynState - Active DynData snapshot.

Return Value:

    None.

--*/
{
    ULONG headerFieldFlags = 0UL;

    if (entry == NULL) {
        return;
    }

    kswordArkHandleReadHeaderValues(
        objectHeader,
        objectBody,
        objectType,
        dynState,
        &headerFieldFlags,
        &entry->objectHeaderDecodeStatus,
        &entry->objectHeaderReadStatus,
        &entry->objectHeaderTypeIndex,
        &entry->objectHeaderInfoMask,
        &entry->objectHeaderFlags,
        &entry->objectHeaderTraceFlags,
        &entry->pointerCount,
        &entry->handleCount,
        &entry->objectHeaderAddress,
        &entry->objectTypeAddress,
        &entry->objectTypeIndexSource,
        &entry->nameInfoStatus);
    entry->fieldFlags |= headerFieldFlags;
}

VOID
kswordArkHandleFillQueryObjectHeaderAudit(
    _Inout_ KSWORD_ARK_QUERY_HANDLE_OBJECT_RESPONSE* response,
    _In_opt_ PVOID objectHeader,
    _In_opt_ PVOID objectBody,
    _In_opt_ POBJECT_TYPE objectType,
    _In_ const KswDynState* dynState
    )
/*++

Routine Description:

    Copy OBJECT_HEADER audit fields into the queryHandleObject response.
    Note: This helper shares the read logic with the enumeration path, ensuring consistent failure state semantics.

Arguments:

    Response - Mutable object query response.
    ObjectHeader - Optional object header pointer.
    ObjectBody - Optional referenced object body pointer.
    ObjectType - Optional object type pointer.
    DynState - Active DynData snapshot.

Return Value:

    None.

--*/
{
    ULONG headerFieldFlags = 0UL;

    if (response == NULL) {
        return;
    }

    kswordArkHandleReadHeaderValues(
        objectHeader,
        objectBody,
        objectType,
        dynState,
        &headerFieldFlags,
        &response->objectHeaderDecodeStatus,
        &response->objectHeaderReadStatus,
        &response->objectHeaderTypeIndex,
        &response->objectHeaderInfoMask,
        &response->objectHeaderFlags,
        &response->objectHeaderTraceFlags,
        &response->pointerCount,
        &response->handleCount,
        &response->objectHeaderAddress,
        &response->objectTypeAddress,
        &response->objectTypeIndexSource,
        &response->nameInfoStatus);
    if ((headerFieldFlags & KSWORD_ARK_HANDLE_FIELD_OBJECT_HEADER_PRESENT) != 0UL) {
        response->fieldFlags |= KSWORD_ARK_OBJECT_INFO_FIELD_OBJECT_HEADER_PRESENT;
    }
    if ((headerFieldFlags & KSWORD_ARK_HANDLE_FIELD_OBJECT_HEADER_BODY_PRESENT) != 0UL) {
        response->fieldFlags |= KSWORD_ARK_OBJECT_INFO_FIELD_OBJECT_HEADER_BODY_PRESENT;
    }
    if ((headerFieldFlags & KSWORD_ARK_HANDLE_FIELD_POINTER_COUNT_PRESENT) != 0UL) {
        response->fieldFlags |= KSWORD_ARK_OBJECT_INFO_FIELD_POINTER_COUNT_PRESENT;
    }
    if ((headerFieldFlags & KSWORD_ARK_HANDLE_FIELD_HANDLE_COUNT_PRESENT) != 0UL) {
        response->fieldFlags |= KSWORD_ARK_OBJECT_INFO_FIELD_HANDLE_COUNT_PRESENT;
    }
    if ((headerFieldFlags & KSWORD_ARK_HANDLE_FIELD_HEADER_TYPE_INDEX_PRESENT) != 0UL) {
        response->fieldFlags |= KSWORD_ARK_OBJECT_INFO_FIELD_HEADER_TYPE_INDEX_PRESENT;
    }
    if ((headerFieldFlags & KSWORD_ARK_HANDLE_FIELD_INFO_MASK_PRESENT) != 0UL) {
        response->fieldFlags |= KSWORD_ARK_OBJECT_INFO_FIELD_INFO_MASK_PRESENT;
    }
    if ((headerFieldFlags & KSWORD_ARK_HANDLE_FIELD_OBJECT_TYPE_PRESENT) != 0UL) {
        response->fieldFlags |= KSWORD_ARK_OBJECT_INFO_FIELD_OBJECT_TYPE_PRESENT;
    }
}
