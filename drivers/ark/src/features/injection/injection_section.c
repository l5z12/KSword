/*++

Module Name:

    injection_section.c

Abstract:

    Image section object reference page (issue #196 §V, third layer).

    Use the **second source** for "what this image should look like": not the file on disk, but the
    section object held by the memory manager itself. Even if the disk file is locked, unreadable, or
    modified by an attacker, this copy remains the content as it was when the mapping was established.

    Deliberately minimize version risk in design with three measures:

    1. **Do not walk the Subsection chain.** A ControlArea can have multiple Subsection objects (one per PE
       section), and locating a page through StartingSector/PtesInSubsection requires four offsets. MMVAD already
       provides FirstPrototypePte and LastContiguousPte: the prototype PTE entries between them are **contiguous**,
       with index (va - vadStart) / PAGE_SIZE. Report pages outside that range as unresolved; do not guess where a
       second range begins. This module already reads both fields, so no new DynData offsets are needed.

    2. Do not decode software PTEs. Prototype PTEs have four states: valid, transition, pagefile,
       and demand-zero. Only the 'valid' state has an architecture-defined bit layout (bit 0 = Present,
       bits 12..51 = PFN). The encoding for 'transition' and 'pagefile' is Windows-specific and
       version-dependent; this is precisely the boundary defined by kLimitKernelVadFlagsUnverified. All
       other states are reported as NOT_RESIDENT and recorded as coverage gaps by the upper layer.

    3. **Never page in the page.** Reading a referenced page that is not in memory triggers a page fault, which changes
       the target state and causes a deadlock on this call path. "This page is currently unavailable" is an honest answer.

--*/

#include "ark/ark_driver.h"
#include "ark/ark_injection_scan.h"
#include "ark/ark_dyndata.h"
#include "../../platform/kernel_object_probe.h"

// PsLookupProcessByProcessId is declared in ntifs.h; this driver only includes ntddk.h.
// Follow the same approach as injection_vad.c / memory_pagetable.c: declare manually.
NTSYSAPI
NTSTATUS
NTAPI
PsLookupProcessByProcessId(
    _In_ HANDLE processId,
    _Outptr_ PEPROCESS* process
    );

// MMVAD layout is consistent with injection_vad.c; see that file for full details.
// Only the Core range field and the two prototype PTE pointers of the long VAD are needed here.
typedef struct KswSecMmvadShort
{
    union
    {
        struct
        {
            PVOID nextVad;
            PVOID extraCreateInfo;
        } nodeFields;
        RTL_BALANCED_NODE vadNode;
    } nodeUnion;
    ULONG startingVpn;
    ULONG endingVpn;
    UCHAR startingVpnHigh;
    UCHAR endingVpnHigh;
    UCHAR commitChargeHigh;
    union
    {
        UCHAR spareNT64VadUChar;
        struct
        {
            UCHAR endingVpnHigher : 4;
            UCHAR commitChargeHigher : 4;
        } higherFields;
    } higherUnion;
    LONG referenceCount;
    EX_PUSH_LOCK pushLock;
    ULONG longFlags;
    ULONG longFlags1;
    union
    {
        ULONG_PTR eventListULongPtr;
        UCHAR startingVpnHigher : 4;
    } u5;
} KswSecMmvadShort, *PkswSecMmvadShort;

typedef struct KswSecMmvad
{
    KswSecMmvadShort core;
    ULONG longFlags2;
    PVOID subsection;
    PVOID firstPrototypePte;
    PVOID lastContiguousPte;
} KswSecMmvad, *PkswSecMmvad;

#define KSW_SEC_VAD_FLAGS_PRIVATE_MEMORY_BIT (1UL << 20)

// x64 hardware PTE. Only these two fields are architecture-defined; do not touch others.
#define KSW_SEC_PTE_VALID_BIT   0x1ULL
#define KSW_SEC_PTE_PFN_SHIFT   12U
#define KSW_SEC_PTE_PFN_MASK    0xFFFFFFFFFULL   // bits 12..51

#define KSW_SEC_PAGE_BYTES 4096U
#define KSW_SEC_POOL_TAG   'cSsK'

static BOOLEAN
kswordArkSectionReadKernel(
    _In_ const VOID* address,
    _Out_writes_bytes_(size) VOID* buffer,
    _In_ SIZE_T size
    )
{
    MM_COPY_ADDRESS copyAddress;
    SIZE_T copied = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (address == NULL || buffer == NULL || size == 0U) {
        return FALSE;
    }
    if (!kswordArkKernelProbeRangeIsResident(address, size)) {
        return FALSE;
    }
    RtlZeroMemory(&copyAddress, sizeof(copyAddress));
    copyAddress.VirtualAddress = (PVOID)(ULONG_PTR)address;
    __try {
        status = MmCopyMemory(buffer, copyAddress, size, MM_COPY_MEMORY_VIRTUAL, &copied);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        copied = 0U;
    }
    return NT_SUCCESS(status) && copied == size;
}

static BOOLEAN
kswordArkSectionReadPhysicalPage(
    _In_ ULONG64 physicalAddress,
    _Out_writes_bytes_(KSW_SEC_PAGE_BYTES) VOID* buffer
    )
{
    MM_COPY_ADDRESS copyAddress;
    SIZE_T copied = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    RtlZeroMemory(&copyAddress, sizeof(copyAddress));
    copyAddress.PhysicalAddress.QuadPart = (LONGLONG)physicalAddress;
    __try {
        status = MmCopyMemory(
            buffer, copyAddress, KSW_SEC_PAGE_BYTES, MM_COPY_MEMORY_PHYSICAL, &copied);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        copied = 0U;
    }
    return NT_SUCCESS(status) && copied == KSW_SEC_PAGE_BYTES;
}

static ULONG64
kswordArkSectionVadStartVa(
    _In_ const KswSecMmvadShort* core
    )
{
    ULONG_PTR higher = core->u5.startingVpnHigher;
    ULONG_PTR high = core->startingVpnHigh;
    ULONG_PTR low = core->startingVpn;
    return (ULONG64)((low | ((high | (higher << 8)) << 32)) << PAGE_SHIFT);
}

static ULONG64
kswordArkSectionVadEndVaExclusive(
    _In_ const KswSecMmvadShort* core
    )
{
    ULONG_PTR higher = core->higherUnion.higherFields.endingVpnHigher;
    ULONG_PTR high = core->endingVpnHigh;
    ULONG_PTR low = core->endingVpn;
    return (ULONG64)(((low + 1U) | ((high | (higher << 8)) << 32)) << PAGE_SHIFT);
}

static NTSTATUS
kswordArkSectionFindVad(
    _In_ PEPROCESS processObject,
    _In_ const KswDynState* dynState,
    _In_ ULONG64 targetVa,
    _Out_ KswSecMmvad* vadOut,
    _Out_ ULONG64* vadStartOut,
    _Out_ ULONG64* vadEndOut
    )
/*++

Routine Description:

    Find the VAD tree node containing TargetVa. Note: This is a value-based descent search, not an
    in-order traversal. Once the target node is reached, the entire tree need not be visited. Each step
    tolerates read failures; a failed read is treated as a miss, avoiding dereferencing wild pointers.

    Depth limit matches the constant in injection_vad.c: the modified 'tree' must not cause traversal failure here.

--*/
{
    ULONG offset = 0U;
    PVOID node = NULL;
    ULONG depth = 0U;

    RtlZeroMemory(vadOut, sizeof(*vadOut));
    *vadStartOut = 0ULL;
    *vadEndOut = 0ULL;

    offset = dynState->kernel.epVadRoot;
    if (offset == KSW_DYN_OFFSET_UNAVAILABLE || offset == 0U) {
        return STATUS_NOT_SUPPORTED;
    }
    if (!kswordArkSectionReadKernel(
            (const UCHAR*)processObject + offset, &node, sizeof(node))) {
        return STATUS_ACCESS_VIOLATION;
    }

    while (node != NULL && depth < KSWORD_ARK_INJECTION_VAD_MAX_DEPTH) {
        KswSecMmvadShort core;
        ULONG64 startVa = 0ULL;
        ULONG64 endVa = 0ULL;

        ++depth;
        if (!kswordArkSectionReadKernel(node, &core, sizeof(core))) {
            return STATUS_ACCESS_VIOLATION;
        }
        startVa = kswordArkSectionVadStartVa(&core);
        endVa = kswordArkSectionVadEndVaExclusive(&core);
        if (endVa <= startVa) {
            return STATUS_DATA_ERROR;
        }

        if (targetVa < startVa) {
            node = core.nodeUnion.vadNode.Children[0];
            continue;
        }
        if (targetVa >= endVa) {
            node = core.nodeUnion.vadNode.Children[1];
            continue;
        }

        // Match found. Private memory uses MmvadShort, where Subsection and FirstPrototypePte do not exist; reading the long VAD directly
        // would cross the allocation boundary. Therefore, first check Core to confirm it is not private before reading the long fields.
        vadOut->core = core;
        *vadStartOut = startVa;
        *vadEndOut = endVa;
        if ((core.longFlags & KSW_SEC_VAD_FLAGS_PRIVATE_MEMORY_BIT) != 0UL) {
            return STATUS_NOT_FOUND;   // Private memory has no section object reference; this is not an error.
        }
        if (!kswordArkSectionReadKernel(
                (const UCHAR*)node + FIELD_OFFSET(KswSecMmvad, subsection),
                &vadOut->subsection,
                sizeof(PVOID) * 3U)) {
            return STATUS_ACCESS_VIOLATION;
        }
        return STATUS_SUCCESS;
    }
    return (depth >= KSWORD_ARK_INJECTION_VAD_MAX_DEPTH) ? STATUS_DATA_ERROR : STATUS_NOT_FOUND;
}

NTSTATUS
kswordArkDriverReadImageSectionPages(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_READ_IMAGE_SECTION_PAGES_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
{
    KSWORD_ARK_READ_IMAGE_SECTION_PAGES_RESPONSE* response = NULL;
    KswDynState dynState;
    KswSecMmvad vad;
    PEPROCESS processObject = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS findStatus = STATUS_SUCCESS;
    ULONG64 vadStart = 0ULL;
    ULONG64 vadEnd = 0ULL;
    ULONG64 rangeStart = 0ULL;
    ULONG64 rangeEnd = 0ULL;
    ULONG64 va = 0ULL;
    ULONG maxPages = 0UL;
    size_t entryCapacity = 0U;
    size_t headerSize = KSWORD_ARK_INJECTION_SECTION_RESPONSE_HEADER_SIZE;
    size_t perPageBytes = 0U;
    UCHAR* byteArea = NULL;
    BOOLEAN includeBytes = FALSE;
    BOOLEAN truncated = FALSE;

    if (bytesWrittenOut == NULL || outputBuffer == NULL || request == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < headerSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    response = (KSWORD_ARK_READ_IMAGE_SECTION_PAGES_RESPONSE*)outputBuffer;
    RtlZeroMemory(response, headerSize);
    response->version = KSWORD_ARK_INJECTION_SCAN_PROTOCOL_VERSION;
    response->processId = request->processId;
    response->entrySize = (ULONG)sizeof(KSWORD_ARK_IMAGE_SECTION_PAGE_ENTRY);
    response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_UNAVAILABLE;

    includeBytes =
        (request->flags & KSWORD_ARK_INJECTION_SECTION_FLAG_INCLUDE_BYTES) != 0UL;
    perPageBytes = includeBytes ? KSW_SEC_PAGE_BYTES : 0U;
    response->bytesPerPage = (ULONG)perPageBytes;

    maxPages = request->maxPages != 0UL
        ? request->maxPages
        : KSWORD_ARK_INJECTION_SECTION_PAGES_DEFAULT;
    if (includeBytes && maxPages > KSWORD_ARK_INJECTION_SECTION_BYTES_PAGES_MAX) {
        maxPages = KSWORD_ARK_INJECTION_SECTION_BYTES_PAGES_MAX;
    }
    if (maxPages > KSWORD_ARK_INJECTION_SECTION_PAGES_MAX) {
        maxPages = KSWORD_ARK_INJECTION_SECTION_PAGES_MAX;
    }

    // Each entry occupies sizeof(entry) + optional 4096 bytes. The buffer holds as many entries as it can fit.
    entryCapacity = (outputBufferLength - headerSize) /
                    (sizeof(KSWORD_ARK_IMAGE_SECTION_PAGE_ENTRY) + perPageBytes);
    if (entryCapacity == 0U) {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_BUFFER_TOO_SMALL;
        *bytesWrittenOut = headerSize;
        response->size = (ULONG)headerSize;
        return STATUS_SUCCESS;
    }
    if (entryCapacity > maxPages) {
        entryCapacity = maxPages;
    }

    rangeStart = request->cursorVa != 0ULL ? request->cursorVa : request->rangeStart;
    rangeEnd = request->rangeEnd;
    rangeStart &= ~((ULONG64)PAGE_SIZE - 1ULL);
    if (rangeEnd <= rangeStart) {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_INVALID_RANGE;
        response->lastStatus = (LONG)STATUS_INVALID_PARAMETER;
        *bytesWrittenOut = headerSize;
        response->size = (ULONG)headerSize;
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&dynState, sizeof(dynState));
    kswordArkDynDataSnapshot(&dynState);

    status = PsLookupProcessByProcessId(ULongToHandle(request->processId), &processObject);
    if (!NT_SUCCESS(status)) {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_PROCESS_LOOKUP_FAILED;
        response->lastStatus = (LONG)status;
        *bytesWrittenOut = headerSize;
        response->size = (ULONG)headerSize;
        return STATUS_SUCCESS;
    }

    findStatus = kswordArkSectionFindVad(
        processObject, &dynState, rangeStart, &vad, &vadStart, &vadEnd);
    if (findStatus == STATUS_NOT_SUPPORTED) {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_DYNDATA_MISSING;
        response->lastStatus = (LONG)findStatus;
        ObDereferenceObject(processObject);
        *bytesWrittenOut = headerSize;
        response->size = (ULONG)headerSize;
        return STATUS_SUCCESS;
    }
    if (!NT_SUCCESS(findStatus) || vad.firstPrototypePte == NULL) {
        // Private memory / VAD not found / unable to read long fields: these are not 'reference is empty' but 'this
        // range has no section object reference'. Report statuses separately so callers can distinguish them.
        response->status = (findStatus == STATUS_NOT_FOUND)
            ? KSWORD_ARK_INJECTION_SCAN_STATUS_OK
            : KSWORD_ARK_INJECTION_SCAN_STATUS_WALK_FAILED;
        response->lastStatus = (LONG)findStatus;
        ObDereferenceObject(processObject);
        *bytesWrittenOut = headerSize;
        response->size = (ULONG)headerSize;
        return STATUS_SUCCESS;
    }

    // ControlArea = *(PVOID*)Subsection，Segment = *(PVOID*)ControlArea。
    // Both are at offset 0, representing the two most stable hops in this chain. A dereference failure only loses diagnostic
    // info and does not affect reading the reference page, as the index points to FirstPrototypePte, bypassing them.
    {
        PVOID controlArea = NULL;
        PVOID segment = NULL;
        if (vad.subsection != NULL &&
            kswordArkSectionReadKernel(vad.subsection, &controlArea, sizeof(controlArea))) {
            response->controlArea = (ULONG64)(ULONG_PTR)controlArea;
            if (controlArea != NULL &&
                kswordArkSectionReadKernel(controlArea, &segment, sizeof(segment))) {
                response->segment = (ULONG64)(ULONG_PTR)segment;
            }
        }
        response->prototypePteArray = (ULONG64)(ULONG_PTR)vad.firstPrototypePte;
    }

    if (rangeEnd > vadEnd) {
        rangeEnd = vadEnd;   // Process one VAD at a time; cross-VAD handling is done by the caller using the cursor.
    }
    if (includeBytes) {
        // The byte area offset must be communicated to the caller: it depends on entryCapacity, which is simultaneously
        // constrained by buffer size and maxPages, making it impossible for the caller to calculate independently.
        response->byteAreaOffset =
            (ULONG64)(headerSize +
                      (entryCapacity * sizeof(KSWORD_ARK_IMAGE_SECTION_PAGE_ENTRY)));
        byteArea = (UCHAR*)outputBuffer + response->byteAreaOffset;
    } else {
        byteArea = NULL;
    }

    for (va = rangeStart; va < rangeEnd; va += PAGE_SIZE) {
        KSWORD_ARK_IMAGE_SECTION_PAGE_ENTRY* entry = NULL;
        ULONG64 index = 0ULL;
        const UCHAR* ptePointer = NULL;
        ULONG64 pteValue = 0ULL;

        if ((size_t)response->returnedCount >= entryCapacity) {
            truncated = TRUE;
            response->nextCursorVa = va;
            response->fieldFlags |= KSWORD_ARK_INJECTION_FIELD_CURSOR_PRESENT;
            break;
        }

        entry = &response->entries[response->returnedCount];
        RtlZeroMemory(entry, sizeof(*entry));
        entry->va = va;

        index = (va - vadStart) / PAGE_SIZE;
        ptePointer = (const UCHAR*)vad.firstPrototypePte + (index * sizeof(ULONG64));
        // Hard boundary of the contiguous segment. Pages beyond LastContiguousPte require traversing the Subsection chain to be found; this version
        // does not do so. It reports "parsing failed" instead of continuing the calculation, as proceeding would involve reading someone else's memory.
        if (vad.lastContiguousPte != NULL &&
            (const UCHAR*)ptePointer > (const UCHAR*)vad.lastContiguousPte) {
            entry->entryFlags |= KSWORD_ARK_INJECTION_SECTION_ENTRY_FLAG_PTE_UNREADABLE;
            ++response->unreadablePteCount;
            ++response->returnedCount;
            continue;
        }
        entry->prototypePteAddress = (ULONG64)(ULONG_PTR)ptePointer;

        if (!kswordArkSectionReadKernel(ptePointer, &pteValue, sizeof(pteValue))) {
            entry->entryFlags |= KSWORD_ARK_INJECTION_SECTION_ENTRY_FLAG_PTE_UNREADABLE;
            ++response->unreadablePteCount;
            ++response->returnedCount;
            continue;
        }
        entry->prototypePteValue = pteValue;

        if ((pteValue & KSW_SEC_PTE_VALID_BIT) == 0ULL) {
            // transition / page file / zero page. Bit layout varies by version; do not decode.
            // Note: Do not bring it in either. This page currently has no reference; report it as-is.
            entry->entryFlags |= KSWORD_ARK_INJECTION_SECTION_ENTRY_FLAG_NOT_RESIDENT;
            ++response->notResidentPageCount;
            ++response->returnedCount;
            continue;
        }

        entry->physicalAddress =
            ((pteValue >> KSW_SEC_PTE_PFN_SHIFT) & KSW_SEC_PTE_PFN_MASK) << KSW_SEC_PTE_PFN_SHIFT;
        entry->entryFlags |= KSWORD_ARK_INJECTION_SECTION_ENTRY_FLAG_VALID;
        ++response->validPageCount;

        if (includeBytes && byteArea != NULL) {
            UCHAR* target = byteArea + ((size_t)response->validPageCount - 1U) * KSW_SEC_PAGE_BYTES;
            if (kswordArkSectionReadPhysicalPage(entry->physicalAddress, target)) {
                entry->entryFlags |= KSWORD_ARK_INJECTION_SECTION_ENTRY_FLAG_BYTES_PRESENT;
            }
        }
        ++response->returnedCount;
    }

    if (response->returnedCount != 0U) {
        response->fieldFlags |= KSWORD_ARK_INJECTION_FIELD_ENTRIES_PRESENT;
    }
    if (truncated) {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_TRUNCATED;
    } else if (response->unreadablePteCount != 0U) {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_PARTIAL;
    } else {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_OK;
    }

    *bytesWrittenOut = headerSize +
                       ((size_t)response->returnedCount *
                        sizeof(KSWORD_ARK_IMAGE_SECTION_PAGE_ENTRY));
    if (includeBytes) {
        // The byte region is laid out aligned to entryCapacity; the returned length must cover up to the last page.
        *bytesWrittenOut = headerSize +
                           (entryCapacity * sizeof(KSWORD_ARK_IMAGE_SECTION_PAGE_ENTRY)) +
                           ((size_t)response->validPageCount * KSW_SEC_PAGE_BYTES);
    }
    response->size = (ULONG)*bytesWrittenOut;
    ObDereferenceObject(processObject);
    return STATUS_SUCCESS;
}
