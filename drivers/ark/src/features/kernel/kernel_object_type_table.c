/*++

Module Name:

    kernel_object_type_table.c

Abstract:

    Enumerates the live ObTypeIndexTable as read-only R0 evidence. The table is
    recovered from bounded references rooted at Object Manager exports and is
    accepted only when several exported POBJECT_TYPE identities agree with the
    table slots. Optional DynData offsets add name and index cross-validation.

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL read-only query path.

--*/

#include "kernel_object_type_table.h"
#include "ark/ark_dyndata.h"
#include "../../dispatch/ioctl_validation.h"
#include "../../platform/pool_compat.h"
#include "../../platform/runtime_signature_scan.h"

#define KSW_OBJECT_TYPE_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_ENUM_OBJECT_TYPE_TABLE_RESPONSE) - \
        sizeof(KSWORD_ARK_OBJECT_TYPE_TABLE_ENTRY))
#define KSW_OBJECT_TYPE_MAX_REFERENCES 96UL
#define KSW_OBJECT_TYPE_SCAN_BYTES 0x500UL
#define KSW_OBJECT_TYPE_MAX_CALL_DEPTH 2UL
#define KSW_OBJECT_TYPE_MAX_STRUCT_OFFSET 0x1000UL
#define KSW_OBJECT_TYPE_FNV_OFFSET_BASIS 1469598103934665603ULL
#define KSW_OBJECT_TYPE_FNV_PRIME 1099511628211ULL
#define KSW_OBJECT_TYPE_NAME_POOL_TAG 'nTsK'
#define KSW_OBJECT_TYPE_WORKSPACE_POOL_TAG 'wOsK'

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

extern POBJECT_TYPE* PsProcessType;
extern POBJECT_TYPE* PsThreadType;
extern POBJECT_TYPE* IoDriverObjectType;
extern POBJECT_TYPE* IoFileObjectType;

NTKERNELAPI
NTSTATUS
ObQueryNameString(
    _In_ PVOID object,
    _Out_writes_bytes_opt_(length) POBJECT_NAME_INFORMATION objectNameInfo,
    _In_ ULONG length,
    _Out_ PULONG returnLength
    );

typedef struct KswObjectTypeTableCandidate
{
    ULONG_PTR address;
    ULONG knownMatchCount;
    ULONG nonNullCount;
    BOOLEAN valid;
} KswObjectTypeTableCandidate, *PkswObjectTypeTableCandidate;

/*
 * DynData state, the parsed PE view, and signature references are all sizable.
 * They are live together while the nested scanner runs, so keep the complete
 * query workspace in bounded nonpaged pool instead of the kernel stack.
 */
typedef struct KswObjectTypeWorkspace
{
    KswDynState dynState;
    KswRuntimeImageView ntosView;
    KswRuntimeDataReference references[KSW_OBJECT_TYPE_MAX_REFERENCES];
} KswObjectTypeWorkspace, *PkswObjectTypeWorkspace;

static BOOLEAN
kswordArkObjectTypeIsKernelPointer(
    _In_ ULONG_PTR address
    )
/*++

Routine Description:

    Validates one aligned canonical kernel pointer.

Return Value:

    TRUE only for system-range aligned addresses.

--*/
{
#if defined(_M_AMD64) || defined(_M_X64)
    return address >= (ULONG_PTR)MmSystemRangeStart &&
        (address >> 48U) == 0xFFFFU &&
        (address & (sizeof(PVOID) - 1U)) == 0U;
#else
    return Address >= (ULONG_PTR)MmSystemRangeStart &&
        (Address & (sizeof(PVOID) - 1U)) == 0U;
#endif
}

static BOOLEAN
kswordArkObjectTypeOffsetPresent(
    _In_ ULONG offset
    )
/*++

Routine Description:

    Rejects missing or implausibly large private structure offsets.

Return Value:

    TRUE for a bounded non-sentinel offset.

--*/
{
    return offset != 0UL && offset != 0xFFFFFFFFUL &&
        offset < KSW_OBJECT_TYPE_MAX_STRUCT_OFFSET;
}

static ULONG64
kswordArkObjectTypeHashBytes(
    _In_ ULONG64 hash,
    _In_reads_bytes_(byteCount) const VOID* data,
    _In_ SIZE_T byteCount
    )
/*++

Routine Description:

    Extends a deterministic FNV-1a snapshot or row identity.

Return Value:

    Updated 64-bit hash.

--*/
{
    const UCHAR* bytes = (const UCHAR*)data;
    SIZE_T index = 0U;

    for (index = 0U; index < byteCount; ++index) {
        hash ^= bytes[index];
        hash *= KSW_OBJECT_TYPE_FNV_PRIME;
    }
    return hash;
}

static BOOLEAN
kswordArkObjectTypeReadPointerSlot(
    _In_ ULONG_PTR tableAddress,
    _In_ ULONG slotIndex,
    _Out_ ULONG_PTR* objectTypeAddressOut
    )
/*++

Routine Description:

    Reads one fixed ObTypeIndexTable pointer without dereferencing the object.

Return Value:

    TRUE when the slot was readable.

--*/
{
    if (objectTypeAddressOut == NULL ||
        slotIndex >= KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS) {
        return FALSE;
    }
    *objectTypeAddressOut = 0U;
    return kswordArkRuntimeReadMemory(
        (const VOID*)(tableAddress + ((ULONG_PTR)slotIndex * sizeof(PVOID))),
        objectTypeAddressOut,
        sizeof(*objectTypeAddressOut));
}

static ULONG
kswordArkObjectTypeKnownPointers(
    _Out_writes_(capacity) ULONG_PTR* pointers,
    _In_ ULONG capacity
    )
/*++

Routine Description:

    Captures exported Object Manager type identities used only to authenticate
    a candidate table.

Return Value:

    Number of distinct non-null known POBJECT_TYPE values.

--*/
{
    POBJECT_TYPE* sources[] = {
        PsProcessType,
        PsThreadType,
        IoDriverObjectType,
        IoFileObjectType
    };
    ULONG sourceIndex = 0UL;
    ULONG count = 0UL;

    if (pointers == NULL || capacity == 0UL) {
        return 0UL;
    }
    for (sourceIndex = 0UL; sourceIndex < RTL_NUMBER_OF(sources); ++sourceIndex) {
        ULONG_PTR value = 0U;
        ULONG existingIndex = 0UL;
        BOOLEAN duplicate = FALSE;

        if (sources[sourceIndex] == NULL ||
            !kswordArkRuntimeReadMemory(
                sources[sourceIndex],
                &value,
                sizeof(value)) ||
            !kswordArkObjectTypeIsKernelPointer(value)) {
            continue;
        }
        for (existingIndex = 0UL; existingIndex < count; ++existingIndex) {
            if (pointers[existingIndex] == value) {
                duplicate = TRUE;
                break;
            }
        }
        if (!duplicate && count < capacity) {
            pointers[count] = value;
            count += 1UL;
        }
    }
    return count;
}

static BOOLEAN
kswordArkObjectTypeValidateCandidate(
    _In_ const KswRuntimeImageView* ntosView,
    _In_ ULONG_PTR candidateAddress,
    _In_reads_(knownCount) const ULONG_PTR* knownPointers,
    _In_ ULONG knownCount,
    _Out_ KswObjectTypeTableCandidate* candidateOut
    )
/*++

Routine Description:

    Requires a complete writable 256-slot array, canonical non-null entries,
    and at least three exported type identities present in the same table.

Return Value:

    TRUE only for a strongly authenticated table candidate.

--*/
{
    ULONG slot = 0UL;
    ULONG knownIndex = 0UL;
    ULONG knownMatches = 0UL;
    ULONG nonNullCount = 0UL;
    BOOLEAN knownSeen[4];

    if (candidateOut == NULL || knownPointers == NULL || knownCount < 3UL ||
        knownCount > RTL_NUMBER_OF(knownSeen) ||
        !kswordArkRuntimeAddressIsWritableData(
            ntosView,
            candidateAddress,
            KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS * sizeof(PVOID))) {
        return FALSE;
    }
    RtlZeroMemory(knownSeen, sizeof(knownSeen));
    for (slot = 0UL; slot < KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS; ++slot) {
        ULONG_PTR objectTypeAddress = 0U;

        if (!kswordArkObjectTypeReadPointerSlot(
                candidateAddress,
                slot,
                &objectTypeAddress)) {
            return FALSE;
        }
        if (objectTypeAddress == 0U) {
            continue;
        }
        if (!kswordArkObjectTypeIsKernelPointer(objectTypeAddress)) {
            return FALSE;
        }
        nonNullCount += 1UL;
        for (knownIndex = 0UL; knownIndex < knownCount; ++knownIndex) {
            if (!knownSeen[knownIndex] &&
                knownPointers[knownIndex] == objectTypeAddress) {
                knownSeen[knownIndex] = TRUE;
                knownMatches += 1UL;
            }
        }
    }
    if (knownMatches < 3UL || nonNullCount < knownMatches) {
        return FALSE;
    }
    candidateOut->address = candidateAddress;
    candidateOut->knownMatchCount = knownMatches;
    candidateOut->nonNullCount = nonNullCount;
    candidateOut->valid = TRUE;
    return TRUE;
}

static NTSTATUS
kswordArkObjectTypeLocateTable(
    _In_ const KswRuntimeImageView* ntosView,
    _Out_writes_(referenceCapacity) KswRuntimeDataReference* references,
    _In_ ULONG referenceCapacity,
    _Out_ ULONG_PTR* tableAddressOut
    )
/*++

Routine Description:

    Locates ObTypeIndexTable from bounded RIP-relative references rooted at
    Object Manager exports and rejects tied strongest candidates.

Return Value:

    STATUS_SUCCESS for one unique table, STATUS_OBJECT_NAME_COLLISION for an
    ambiguity, or STATUS_NOT_FOUND when no candidate validates.

--*/
{
    static PCSTR const kAnchors[] = {
        "ObGetObjectType",
        "ObReferenceObjectByHandle",
        "ObOpenObjectByPointer"
    };
    ULONG_PTR knownPointers[4];
    ULONG knownCount = 0UL;
    ULONG referenceCount = 0UL;
    ULONG referenceIndex = 0UL;
    KswObjectTypeTableCandidate best;
    BOOLEAN ambiguous = FALSE;

    if (ntosView == NULL || references == NULL || referenceCapacity == 0UL ||
        referenceCapacity > KSW_OBJECT_TYPE_MAX_REFERENCES ||
        tableAddressOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *tableAddressOut = 0U;
    RtlZeroMemory(
        references,
        (SIZE_T)referenceCapacity * sizeof(*references));
    RtlZeroMemory(knownPointers, sizeof(knownPointers));
    RtlZeroMemory(&best, sizeof(best));
    knownCount = kswordArkObjectTypeKnownPointers(
        knownPointers,
        RTL_NUMBER_OF(knownPointers));
    if (knownCount < 3UL) {
        return STATUS_NOT_SUPPORTED;
    }
    referenceCount = kswordArkRuntimeCollectAnchoredDataReferences(
        ntosView,
        kAnchors,
        RTL_NUMBER_OF(kAnchors),
        KSW_OBJECT_TYPE_MAX_CALL_DEPTH,
        KSW_OBJECT_TYPE_SCAN_BYTES,
        references,
        referenceCapacity);
    for (referenceIndex = 0UL; referenceIndex < referenceCount; ++referenceIndex) {
        KswObjectTypeTableCandidate candidate;

        RtlZeroMemory(&candidate, sizeof(candidate));
        if (!kswordArkObjectTypeValidateCandidate(
                ntosView,
                references[referenceIndex].address,
                knownPointers,
                knownCount,
                &candidate)) {
            continue;
        }
        if (!best.valid ||
            candidate.knownMatchCount > best.knownMatchCount) {
            best = candidate;
            ambiguous = FALSE;
        }
        else if (candidate.knownMatchCount == best.knownMatchCount &&
            candidate.address != best.address) {
            ambiguous = TRUE;
        }
    }
    if (!best.valid) {
        return STATUS_NOT_FOUND;
    }
    if (ambiguous) {
        return STATUS_OBJECT_NAME_COLLISION;
    }
    *tableAddressOut = best.address;
    return STATUS_SUCCESS;
}

static BOOLEAN
kswordArkObjectTypeReadName(
    _In_ ULONG_PTR objectTypeAddress,
    _In_ ULONG nameOffset,
    _Out_writes_(destinationChars) PWCHAR destination,
    _In_ ULONG destinationChars
    )
/*++

Routine Description:

    Copies a DynData-gated _OBJECT_TYPE.Name into a fixed response buffer.

Return Value:

    TRUE only when the UNICODE_STRING and complete bounded payload are valid.

--*/
{
    UNICODE_STRING name;
    USHORT copyBytes = 0U;

    if (destination == NULL || destinationChars < 2UL ||
        !kswordArkObjectTypeOffsetPresent(nameOffset)) {
        return FALSE;
    }
    RtlZeroMemory(destination, (SIZE_T)destinationChars * sizeof(WCHAR));
    RtlZeroMemory(&name, sizeof(name));
    if (!kswordArkRuntimeReadMemory(
            (const VOID*)(objectTypeAddress + nameOffset),
            &name,
            sizeof(name)) ||
        name.Buffer == NULL || name.Length == 0U ||
        name.Length > name.MaximumLength ||
        (name.Length & (sizeof(WCHAR) - 1U)) != 0U ||
        !kswordArkObjectTypeIsKernelPointer((ULONG_PTR)name.Buffer)) {
        return FALSE;
    }
    copyBytes = (USHORT)min(
        name.Length,
        (USHORT)((destinationChars - 1UL) * sizeof(WCHAR)));
    if (!kswordArkRuntimeReadMemory(name.Buffer, destination, copyBytes)) {
        RtlZeroMemory(destination, (SIZE_T)destinationChars * sizeof(WCHAR));
        return FALSE;
    }
    destination[copyBytes / sizeof(WCHAR)] = L'\0';
    return TRUE;
}

static BOOLEAN
kswordArkObjectTypeReadNamespaceName(
    _In_ ULONG_PTR objectTypeAddress,
    _Out_writes_(destinationChars) PWCHAR destination,
    _In_ ULONG destinationChars
    )
/*++

Routine Description:

    Query the Object Manager name of an OBJECT_TYPE object and retain the last
    path component (for example, "Process" from "\ObjectTypes\Process").
    This provides names without the private _OBJECT_TYPE.Name member offset.

Return Value:

    TRUE only when a complete bounded name was copied.

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

    if (objectTypeAddress == 0U || destination == NULL ||
        destinationChars < 2UL) {
        return FALSE;
    }
    RtlZeroMemory(destination, (SIZE_T)destinationChars * sizeof(WCHAR));
    status = ObQueryNameString(
        (PVOID)objectTypeAddress,
        NULL,
        0UL,
        &requiredBytes);
    if (status != STATUS_INFO_LENGTH_MISMATCH &&
        status != STATUS_BUFFER_TOO_SMALL &&
        status != STATUS_BUFFER_OVERFLOW) {
        return FALSE;
    }
    allocationBytes = max(
        requiredBytes,
        (ULONG)(sizeof(OBJECT_NAME_INFORMATION) + sizeof(WCHAR)));
    if (allocationBytes > 64UL * 1024UL) {
        return FALSE;
    }
    nameInfo = (POBJECT_NAME_INFORMATION)kswordArkAllocateNonPagedPool(
        allocationBytes,
        KSW_OBJECT_TYPE_NAME_POOL_TAG);
    if (nameInfo == NULL) {
        return FALSE;
    }
    RtlZeroMemory(nameInfo, allocationBytes);
    status = ObQueryNameString(
        (PVOID)objectTypeAddress,
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
    ExFreePoolWithTag(nameInfo, KSW_OBJECT_TYPE_NAME_POOL_TAG);
    return copyChars != 0UL;
}

static BOOLEAN
kswordArkObjectTypeReadIndex(
    _In_ ULONG_PTR objectTypeAddress,
    _In_ ULONG indexOffset,
    _Out_ UCHAR* typeIndexOut
    )
/*++

Routine Description:

    Reads the DynData-gated _OBJECT_TYPE.Index byte.

Return Value:

    TRUE when the member is available and readable.

--*/
{
    if (typeIndexOut == NULL ||
        !kswordArkObjectTypeOffsetPresent(indexOffset)) {
        return FALSE;
    }
    *typeIndexOut = 0U;
    return kswordArkRuntimeReadMemory(
        (const VOID*)(objectTypeAddress + indexOffset),
        typeIndexOut,
        sizeof(*typeIndexOut));
}

static BOOLEAN
kswordArkObjectTypeIsKnown(
    _In_ ULONG_PTR objectTypeAddress
    )
/*++

Routine Description:

    Compares one row against exported process/thread/driver/file type objects.

Return Value:

    TRUE for an exported known identity.

--*/
{
    ULONG_PTR knownPointers[4];
    ULONG knownCount = 0UL;
    ULONG index = 0UL;

    RtlZeroMemory(knownPointers, sizeof(knownPointers));
    knownCount = kswordArkObjectTypeKnownPointers(
        knownPointers,
        RTL_NUMBER_OF(knownPointers));
    for (index = 0UL; index < knownCount; ++index) {
        if (knownPointers[index] == objectTypeAddress) {
            return TRUE;
        }
    }
    return FALSE;
}

static NTSTATUS
kswordArkObjectTypeBuildResponse(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_ENUM_OBJECT_TYPE_TABLE_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Builds one paged, read-only Object Type Table response.

Return Value:

    STATUS_SUCCESS for a semantic response; malformed buffers return an error.

--*/
{
    KSWORD_ARK_ENUM_OBJECT_TYPE_TABLE_RESPONSE* response =
        (KSWORD_ARK_ENUM_OBJECT_TYPE_TABLE_RESPONSE*)outputBuffer;
    KSWORD_ARK_OBJECT_TYPE_TABLE_ENTRY* rows = NULL;
    KswObjectTypeWorkspace* workspace = NULL;
    KswDynState* dynState = NULL;
    KswRuntimeImageView* ntosView = NULL;
    ULONG_PTR tableAddress = 0U;
    NTSTATUS locateStatus = STATUS_SUCCESS;
    ULONG capacity = 0UL;
    ULONG requestedMax = 0UL;
    ULONG startIndex = 0UL;
    ULONG slot = 0UL;
    ULONG nextIndex = KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS;
    BOOLEAN dynName = FALSE;
    BOOLEAN dynIndex = FALSE;
    BOOLEAN partial = FALSE;
    ULONG64 snapshotHash = KSW_OBJECT_TYPE_FNV_OFFSET_BASIS;

    if (outputBuffer == NULL || request == NULL || bytesWrittenOut == NULL ||
        outputBufferLength < KSW_OBJECT_TYPE_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    *bytesWrittenOut = 0U;
    RtlZeroMemory(outputBuffer, outputBufferLength);
    response->version = KSWORD_ARK_KERNEL_OBJECT_PROTOCOL_VERSION;
    response->entrySize = sizeof(KSWORD_ARK_OBJECT_TYPE_TABLE_ENTRY);
    response->status = KSWORD_ARK_OBJECT_TYPE_TABLE_STATUS_UNAVAILABLE;
    response->nextIndex = KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS;

    workspace = (KswObjectTypeWorkspace*)kswordArkAllocateNonPagedPool(
        sizeof(*workspace),
        KSW_OBJECT_TYPE_WORKSPACE_POOL_TAG);
    if (workspace == NULL) {
        response->lastStatus = STATUS_INSUFFICIENT_RESOURCES;
        *bytesWrittenOut = KSW_OBJECT_TYPE_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }
    RtlZeroMemory(workspace, sizeof(*workspace));
    dynState = &workspace->dynState;
    ntosView = &workspace->ntosView;

    capacity = (ULONG)((outputBufferLength - KSW_OBJECT_TYPE_RESPONSE_HEADER_SIZE) /
        sizeof(KSWORD_ARK_OBJECT_TYPE_TABLE_ENTRY));
    requestedMax = request->maxEntries == 0UL
        ? KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS
        : min(request->maxEntries, KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS);
    capacity = min(capacity, requestedMax);
    startIndex = min(request->startIndex, KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS);
    rows = response->entries;

    kswordArkDynDataSnapshot(dynState);
    response->dynDataCapabilityMask = dynState->capabilityMask;
    response->otNameOffset = dynState->kernel.otName;
    response->otIndexOffset = dynState->kernel.otIndex;
    dynName = kswordArkObjectTypeOffsetPresent(dynState->kernel.otName);
    dynIndex = kswordArkObjectTypeOffsetPresent(dynState->kernel.otIndex);
    if (dynName || dynIndex) {
        response->flags |=
            KSWORD_ARK_OBJECT_TYPE_TABLE_RESPONSE_FLAG_DYNDATA_ACTIVE;
    }
    if (dynState->ntoskrnl.present == 0UL ||
        !kswordArkRuntimeInitializeImageView(
            (PVOID)(ULONG_PTR)dynState->ntoskrnl.imageBase,
            dynState->ntoskrnl.sizeOfImage,
            ntosView)) {
        response->status = KSWORD_ARK_OBJECT_TYPE_TABLE_STATUS_TABLE_NOT_FOUND;
        response->lastStatus = STATUS_NOT_SUPPORTED;
        *bytesWrittenOut = KSW_OBJECT_TYPE_RESPONSE_HEADER_SIZE;
        ExFreePoolWithTag(workspace, KSW_OBJECT_TYPE_WORKSPACE_POOL_TAG);
        workspace = NULL;
        return STATUS_SUCCESS;
    }
    locateStatus = kswordArkObjectTypeLocateTable(
        ntosView,
        workspace->references,
        RTL_NUMBER_OF(workspace->references),
        &tableAddress);
    if (!NT_SUCCESS(locateStatus)) {
        response->status = (locateStatus == STATUS_OBJECT_NAME_COLLISION)
            ? KSWORD_ARK_OBJECT_TYPE_TABLE_STATUS_TABLE_AMBIGUOUS
            : KSWORD_ARK_OBJECT_TYPE_TABLE_STATUS_TABLE_NOT_FOUND;
        response->lastStatus = locateStatus;
        *bytesWrittenOut = KSW_OBJECT_TYPE_RESPONSE_HEADER_SIZE;
        ExFreePoolWithTag(workspace, KSW_OBJECT_TYPE_WORKSPACE_POOL_TAG);
        workspace = NULL;
        return STATUS_SUCCESS;
    }
    response->tableAddress = (ULONG64)tableAddress;
    response->flags |=
        KSWORD_ARK_OBJECT_TYPE_TABLE_RESPONSE_FLAG_TABLE_VALIDATED;

    for (slot = 0UL; slot < KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS; ++slot) {
        ULONG_PTR objectTypeAddress = 0U;

        if (!kswordArkObjectTypeReadPointerSlot(
                tableAddress,
                slot,
                &objectTypeAddress)) {
            partial = TRUE;
            continue;
        }
        if (objectTypeAddress == 0U) {
            continue;
        }
        response->totalCount += 1UL;
        snapshotHash = kswordArkObjectTypeHashBytes(
            snapshotHash,
            &slot,
            sizeof(slot));
        snapshotHash = kswordArkObjectTypeHashBytes(
            snapshotHash,
            &objectTypeAddress,
            sizeof(objectTypeAddress));
        if (slot < startIndex || response->returnedCount >= capacity) {
            if (slot >= startIndex && nextIndex == KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS) {
                nextIndex = slot;
            }
            continue;
        }
        {
            KSWORD_ARK_OBJECT_TYPE_TABLE_ENTRY* entry =
                &rows[response->returnedCount];
            UCHAR observedIndex = 0U;
            BOOLEAN nameRead = FALSE;
            BOOLEAN indexRead = FALSE;

            entry->size = sizeof(*entry);
            entry->typeIndex = slot;
            entry->status = KSWORD_ARK_OBJECT_TYPE_ENTRY_STATUS_OK;
            entry->fieldFlags = KSWORD_ARK_OBJECT_TYPE_ENTRY_FIELD_ADDRESS;
            entry->objectTypeAddress = (ULONG64)objectTypeAddress;
            if (kswordArkObjectTypeIsKnown(objectTypeAddress)) {
                entry->fieldFlags |=
                    KSWORD_ARK_OBJECT_TYPE_ENTRY_FIELD_KNOWN_TYPE;
            }
            if ((request->flags &
                    KSWORD_ARK_OBJECT_TYPE_TABLE_FLAG_INCLUDE_NAMES) != 0UL &&
                dynName) {
                nameRead = kswordArkObjectTypeReadName(
                    objectTypeAddress,
                    dynState->kernel.otName,
                    entry->typeName,
                    RTL_NUMBER_OF(entry->typeName));
                if (nameRead) {
                    entry->fieldFlags |=
                        KSWORD_ARK_OBJECT_TYPE_ENTRY_FIELD_NAME;
                }
            }
            if ((request->flags &
                    KSWORD_ARK_OBJECT_TYPE_TABLE_FLAG_INCLUDE_NAMES) != 0UL &&
                !nameRead) {
                nameRead = kswordArkObjectTypeReadNamespaceName(
                    objectTypeAddress,
                    entry->typeName,
                    RTL_NUMBER_OF(entry->typeName));
                if (nameRead) {
                    entry->fieldFlags |=
                        KSWORD_ARK_OBJECT_TYPE_ENTRY_FIELD_NAME;
                    response->flags |=
                        KSWORD_ARK_OBJECT_TYPE_TABLE_RESPONSE_FLAG_NAMESPACE_NAMES;
                }
            }
            if ((request->flags &
                    KSWORD_ARK_OBJECT_TYPE_TABLE_FLAG_VALIDATE_INDEX) != 0UL &&
                dynIndex) {
                indexRead = kswordArkObjectTypeReadIndex(
                    objectTypeAddress,
                    dynState->kernel.otIndex,
                    &observedIndex);
                if (indexRead) {
                    entry->fieldFlags |=
                        KSWORD_ARK_OBJECT_TYPE_ENTRY_FIELD_INDEX;
                    if ((ULONG)observedIndex == slot) {
                        entry->fieldFlags |=
                            KSWORD_ARK_OBJECT_TYPE_ENTRY_FIELD_INDEX_MATCH;
                    }
                    else {
                        entry->status =
                            KSWORD_ARK_OBJECT_TYPE_ENTRY_STATUS_INDEX_MISMATCH;
                        entry->lastStatus = STATUS_DATA_ERROR;
                        partial = TRUE;
                    }
                }
            }
            if (((request->flags &
                    KSWORD_ARK_OBJECT_TYPE_TABLE_FLAG_INCLUDE_NAMES) != 0UL &&
                    !nameRead) ||
                ((request->flags &
                    KSWORD_ARK_OBJECT_TYPE_TABLE_FLAG_VALIDATE_INDEX) != 0UL &&
                    !indexRead)) {
                if (entry->status == KSWORD_ARK_OBJECT_TYPE_ENTRY_STATUS_OK) {
                    entry->status = KSWORD_ARK_OBJECT_TYPE_ENTRY_STATUS_PARTIAL;
                }
                partial = TRUE;
            }
            entry->identityHash = kswordArkObjectTypeHashBytes(
                KSW_OBJECT_TYPE_FNV_OFFSET_BASIS,
                &entry->typeIndex,
                sizeof(entry->typeIndex));
            entry->identityHash = kswordArkObjectTypeHashBytes(
                entry->identityHash,
                &entry->objectTypeAddress,
                sizeof(entry->objectTypeAddress));
            entry->fieldFlags |=
                KSWORD_ARK_OBJECT_TYPE_ENTRY_FIELD_IDENTITY_HASH;
            response->returnedCount += 1UL;
        }
    }
    response->snapshotHash = snapshotHash;
    response->flags |=
        KSWORD_ARK_OBJECT_TYPE_TABLE_RESPONSE_FLAG_SNAPSHOT_HASH_VALID;
    response->nextIndex = nextIndex;
    if (nextIndex < KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS) {
        response->flags |=
            KSWORD_ARK_OBJECT_TYPE_TABLE_RESPONSE_FLAG_TRUNCATED;
        response->status =
            KSWORD_ARK_OBJECT_TYPE_TABLE_STATUS_BUFFER_TRUNCATED;
        response->lastStatus = STATUS_BUFFER_OVERFLOW;
    }
    else if (partial ||
        (((request->flags &
            KSWORD_ARK_OBJECT_TYPE_TABLE_FLAG_VALIDATE_INDEX) != 0UL) &&
            !dynIndex)) {
        response->status = KSWORD_ARK_OBJECT_TYPE_TABLE_STATUS_PARTIAL;
        response->lastStatus = partial ? STATUS_PARTIAL_COPY : STATUS_NOT_SUPPORTED;
    }
    else {
        response->status = KSWORD_ARK_OBJECT_TYPE_TABLE_STATUS_OK;
        response->lastStatus = STATUS_SUCCESS;
    }
    *bytesWrittenOut = KSW_OBJECT_TYPE_RESPONSE_HEADER_SIZE +
        ((size_t)response->returnedCount *
            sizeof(KSWORD_ARK_OBJECT_TYPE_TABLE_ENTRY));
    ExFreePoolWithTag(workspace, KSW_OBJECT_TYPE_WORKSPACE_POOL_TAG);
    workspace = NULL;
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkKernelObjectIoctlEnumTypeTable(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Validates and dispatches IOCTL_KSWORD_ARK_ENUM_OBJECT_TYPE_TABLE.

Return Value:

    WDF buffer validation or response-builder status.

--*/
{
    KSWORD_ARK_ENUM_OBJECT_TYPE_TABLE_REQUEST* queryRequest = NULL;
    // requestSnapshot: Saves the complete request before zeroing the shared SystemBuffer in the backend.
    KSWORD_ARK_ENUM_OBJECT_TYPE_TABLE_REQUEST requestSnapshot;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(device);
    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;
    if (inputBufferLength < sizeof(*queryRequest) ||
        outputBufferLength < KSW_OBJECT_TYPE_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = WdfRequestRetrieveInputBuffer(
        request,
        sizeof(*queryRequest),
        (PVOID*)&queryRequest,
        &actualInputLength);
    if (!NT_SUCCESS(status) || actualInputLength < sizeof(*queryRequest)) {
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }
    /*
     * METHOD_BUFFERED shares one SystemBuffer for input and output. The backend calls
     * RtlZeroMemory on the output before reading maxEntries as the enumeration limit. Without
     * an input snapshot, it would interpret response-header bytes as the entry count.
     */
    RtlCopyMemory(&requestSnapshot, queryRequest, sizeof(requestSnapshot));
    queryRequest = &requestSnapshot;

    if (queryRequest->version != KSWORD_ARK_KERNEL_OBJECT_PROTOCOL_VERSION ||
        (queryRequest->flags &
            (~KSWORD_ARK_OBJECT_TYPE_TABLE_FLAG_INCLUDE_ALL)) != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        KSW_OBJECT_TYPE_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    return kswordArkObjectTypeBuildResponse(
        outputBuffer,
        actualOutputLength,
        queryRequest,
        bytesReturned);
}
