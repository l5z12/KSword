/*++

Module Name:

    kernel_cache_fallback.c

Abstract:

    Runtime fallback for MmUnloadedDrivers and PiDDBCacheTable.  Candidate
    globals are recovered from bounded call graphs rooted at stable ntoskrnl
    exports.  No address is published until PE-section checks, uniqueness, and
    live semantic validation agree.  Ambiguous or empty structures fail closed.

    Field-shape heuristics alone never authorize a kernel API call here.  A
    candidate PiDDB lock must be proven to sit on the global resource list
    before it reaches ExAcquireResourceSharedLite, and the cache table is
    walked through bounded fault-tolerant reads instead of the Rtl generic
    table API, which dereferences and mutates its argument unconditionally.

Environment:

    Kernel mode, PASSIVE_LEVEL during DynData initialization.

--*/

#include <ntifs.h>
#include "kernel_cache_fallback.h"
#include "kernel_object_probe.h"
#include "runtime_signature_scan.h"
#include "pool_compat.h"

#define KSW_KERNEL_CACHE_TAG 'cCsK'
#define KSW_KERNEL_CACHE_MAX_REFERENCES 512UL
#define KSW_KERNEL_CACHE_ROUTINE_SCAN_BYTES 0x0800UL
#define KSW_KERNEL_CACHE_MAX_UNLOADED_RECORDS 50UL
#define KSW_KERNEL_CACHE_MIN_UNLOADED_STRIDE 0x20UL
#define KSW_KERNEL_CACHE_MAX_UNLOADED_STRIDE 0x80UL
#define KSW_KERNEL_CACHE_MAX_PRIVATE_ENTRY 0x100UL
#define KSW_KERNEL_CACHE_MAX_SAMPLE_ENTRIES 16UL
#define KSW_KERNEL_CACHE_MAX_NAME_BYTES 520U
#define KSW_KERNEL_CACHE_MAX_AVL_ELEMENTS 0x10000UL
#define KSW_KERNEL_CACHE_MAX_AVL_DEPTH 64UL

typedef struct KswUnloadedLayoutCandidate
{
    ULONG_PTR pointerGlobal;
    ULONG_PTR records;
    ULONG nameOffset;
    ULONG startAddressOffset;
    ULONG endAddressOffset;
    ULONG currentTimeOffset;
    ULONG recordSize;
    ULONG validRecordCount;
    ULONG_PTR referenceRoutine;
} KswUnloadedLayoutCandidate, *PkswUnloadedLayoutCandidate;

typedef struct KswPiddbLayoutCandidate
{
    PRTL_AVL_TABLE table;
    PERESOURCE lock;
    ULONG driverNameOffset;
    ULONG timeDateStampOffset;
    ULONG loadStatusOffset;
    ULONG entrySize;
} KswPiddbLayoutCandidate, *PkswPiddbLayoutCandidate;

static BOOLEAN
kswordArkKernelCacheIsKernelPointer(
    _In_ ULONG_PTR address
    )
{
#if defined(_M_AMD64) || defined(_M_X64)
    return address >= (ULONG_PTR)MmSystemRangeStart &&
        (address >> 48U) == 0xFFFFU;
#else
    return Address >= (ULONG_PTR)MmSystemRangeStart;
#endif
}

static BOOLEAN
kswordArkKernelCacheUnicodeSuffixMatches(
    _In_ const UNICODE_STRING* string,
    _In_z_ PCWSTR suffix
    )
/*++

Routine Description:

    Compare a bounded private UNICODE_STRING suffix without trusting its buffer.

Return Value:

    TRUE only for a readable, even-sized, bounded kernel string with the suffix.

--*/
{
    WCHAR tail[5];
    SIZE_T suffixBytes = 0U;
    UNICODE_STRING tailString;
    UNICODE_STRING expectedString;

    if (string == NULL || suffix == NULL || string->Buffer == NULL ||
        !kswordArkKernelCacheIsKernelPointer((ULONG_PTR)string->Buffer) ||
        string->Length == 0U || string->Length > KSW_KERNEL_CACHE_MAX_NAME_BYTES ||
        string->Length > string->MaximumLength ||
        (string->Length & (sizeof(WCHAR) - 1U)) != 0U) {
        return FALSE;
    }
    RtlInitUnicodeString(&expectedString, suffix);
    suffixBytes = expectedString.Length;
    if (suffixBytes == 0U ||
        suffixBytes >= sizeof(tail) ||
        string->Length < suffixBytes) {
        return FALSE;
    }
    RtlZeroMemory(tail, sizeof(tail));
    if (!kswordArkRuntimeReadMemory(
            (const UCHAR*)string->Buffer + string->Length - suffixBytes,
            tail,
            suffixBytes)) {
        return FALSE;
    }
    tailString.Buffer = tail;
    tailString.Length = (USHORT)suffixBytes;
    tailString.MaximumLength = (USHORT)suffixBytes;
    return RtlEqualUnicodeString(&tailString, &expectedString, TRUE);
}

static BOOLEAN
kswordArkKernelCacheReadDriverName(
    _In_ const UCHAR* object,
    _In_ ULONG offset,
    _Out_opt_ UNICODE_STRING* nameOut
    )
{
    UNICODE_STRING name;

    if (object == NULL) {
        return FALSE;
    }
    RtlZeroMemory(&name, sizeof(name));
    if (!kswordArkRuntimeReadMemory(
            object + offset,
            &name,
            sizeof(name)) ||
        (!kswordArkKernelCacheUnicodeSuffixMatches(&name, L".sys") &&
         !kswordArkKernelCacheUnicodeSuffixMatches(&name, L".dll"))) {
        return FALSE;
    }
    if (nameOut != NULL) {
        *nameOut = name;
    }
    return TRUE;
}

static BOOLEAN
kswordArkKernelCacheTimeIsPlausible(
    _In_ LONGLONG value,
    _In_ LONGLONG currentSystemTime
    )
{
    const LONGLONG kEarliestSupportedTime = 129067776000000000LL;
    const LONGLONG kOneDay = 24LL * 60LL * 60LL * 10000000LL;

    return value >= kEarliestSupportedTime &&
        currentSystemTime > 0LL && value <= currentSystemTime + kOneDay;
}

static ULONG
kswordArkKernelCacheCountUnloadedLayoutMatches(
    _In_ ULONG_PTR records,
    _In_ ULONG recordSize,
    _In_ ULONG nameOffset,
    _In_ ULONG startOffset,
    _In_ ULONG endOffset,
    _In_ ULONG timeOffset,
    _In_ LONGLONG currentSystemTime
    )
{
    ULONG index = 0UL;
    ULONG matches = 0UL;

    for (index = 0UL; index < KSW_KERNEL_CACHE_MAX_UNLOADED_RECORDS; ++index) {
        const UCHAR* record = (const UCHAR*)records +
            ((SIZE_T)index * recordSize);
        ULONG_PTR startAddress = 0U;
        ULONG_PTR endAddress = 0U;
        LARGE_INTEGER currentTime;

        RtlZeroMemory(&currentTime, sizeof(currentTime));
        if (!kswordArkKernelCacheReadDriverName(record, nameOffset, NULL) ||
            !kswordArkRuntimeReadMemory(
                record + startOffset,
                &startAddress,
                sizeof(startAddress)) ||
            !kswordArkRuntimeReadMemory(
                record + endOffset,
                &endAddress,
                sizeof(endAddress)) ||
            !kswordArkRuntimeReadMemory(
                record + timeOffset,
                &currentTime,
                sizeof(currentTime)) ||
            !kswordArkKernelCacheIsKernelPointer(startAddress) ||
            !kswordArkKernelCacheIsKernelPointer(endAddress) ||
            endAddress <= startAddress ||
            endAddress - startAddress > 0x40000000U ||
            !kswordArkKernelCacheTimeIsPlausible(
                currentTime.QuadPart,
                currentSystemTime)) {
            continue;
        }
        matches += 1UL;
    }
    return matches;
}

static BOOLEAN
kswordArkKernelCacheInferUnloadedLayout(
    _In_ ULONG_PTR pointerGlobal,
    _In_ ULONG_PTR referenceRoutine,
    _Out_ KswUnloadedLayoutCandidate* candidateOut
    )
/*++

Routine Description:

    Infer the fixed 50-entry unloaded-driver record layout by requiring at
    least two rows with a driver suffix, ordered kernel range, and plausible
    system unload time.  A tied best layout is rejected.

Return Value:

    TRUE only for one strongest live layout.

--*/
{
    ULONG_PTR records = 0U;
    LARGE_INTEGER now;
    ULONG stride = 0UL;
    ULONG nameOffset = 0UL;
    ULONG bestMatches = 0UL;
    BOOLEAN tied = FALSE;
    KswUnloadedLayoutCandidate best;

    if (candidateOut == NULL ||
        !kswordArkRuntimeReadMemory(
            (const VOID*)pointerGlobal,
            &records,
            sizeof(records)) ||
        !kswordArkKernelCacheIsKernelPointer(records) ||
        (records & (sizeof(PVOID) - 1U)) != 0U) {
        return FALSE;
    }
    RtlZeroMemory(&best, sizeof(best));
    KeQuerySystemTime(&now);

    for (stride = KSW_KERNEL_CACHE_MIN_UNLOADED_STRIDE;
         stride <= KSW_KERNEL_CACHE_MAX_UNLOADED_STRIDE;
         stride += sizeof(PVOID)) {
        for (nameOffset = 0UL;
             nameOffset + sizeof(UNICODE_STRING) +
                 (3UL * sizeof(ULONG_PTR)) <= stride;
             nameOffset += sizeof(PVOID)) {
            ULONG startOffset = nameOffset + sizeof(UNICODE_STRING);
            ULONG endOffset = startOffset + sizeof(PVOID);
            ULONG timeOffset = endOffset + sizeof(PVOID);
            ULONG matches = kswordArkKernelCacheCountUnloadedLayoutMatches(
                records,
                stride,
                nameOffset,
                startOffset,
                endOffset,
                timeOffset,
                now.QuadPart);

            if (matches < 2UL || matches < bestMatches) {
                continue;
            }
            if (matches == bestMatches && bestMatches != 0UL) {
                tied = TRUE;
                continue;
            }
            bestMatches = matches;
            tied = FALSE;
            best.pointerGlobal = pointerGlobal;
            best.records = records;
            best.nameOffset = nameOffset;
            best.startAddressOffset = startOffset;
            best.endAddressOffset = endOffset;
            best.currentTimeOffset = timeOffset;
            best.recordSize = stride;
            best.validRecordCount = matches;
            best.referenceRoutine = referenceRoutine;
        }
    }
    if (bestMatches < 2UL || tied) {
        return FALSE;
    }
    *candidateOut = best;
    return TRUE;
}

static VOID
kswordArkKernelCacheResolveUnloadedDrivers(
    _In_ const KswRuntimeImageView* view,
    _In_reads_(referenceCount) const KswRuntimeDataReference* references,
    _In_ ULONG referenceCount,
    _Inout_ PkswRuntimeKernelLayout layout
    )
{
    KswUnloadedLayoutCandidate best;
    ULONG bestScore = 0UL;
    BOOLEAN ambiguous = FALSE;
    ULONG index = 0UL;
    LONG lastIndexRva = -1;

    if (view == NULL || references == NULL || layout == NULL) {
        return;
    }
    RtlZeroMemory(&best, sizeof(best));
    for (index = 0UL; index < referenceCount; ++index) {
        KswUnloadedLayoutCandidate candidate;

        RtlZeroMemory(&candidate, sizeof(candidate));
        if (!kswordArkRuntimeAddressIsWritableData(
                view,
                references[index].address,
                sizeof(PVOID)) ||
            !kswordArkKernelCacheInferUnloadedLayout(
                references[index].address,
                references[index].routineAddress,
                &candidate) ||
            candidate.validRecordCount < bestScore) {
            continue;
        }
        if (candidate.validRecordCount == bestScore && bestScore != 0UL) {
            ambiguous = TRUE;
            continue;
        }
        best = candidate;
        bestScore = candidate.validRecordCount;
        ambiguous = FALSE;
    }
    if (bestScore < 2UL || ambiguous || best.pointerGlobal < view->base ||
        best.pointerGlobal - view->base > MAXLONG) {
        return;
    }

    for (index = 0UL; index < referenceCount; ++index) {
        ULONG value = 0UL;
        ULONG_PTR address = references[index].address;

        if (references[index].routineAddress != best.referenceRoutine ||
            address == best.pointerGlobal ||
            !kswordArkRuntimeAddressIsWritableData(view, address, sizeof(value)) ||
            !kswordArkRuntimeReadMemory((const VOID*)address, &value, sizeof(value)) ||
            value > KSW_KERNEL_CACHE_MAX_UNLOADED_RECORDS ||
            address < view->base || address - view->base > MAXLONG) {
            continue;
        }
        if (lastIndexRva >= 0) {
            lastIndexRva = -1;
            break;
        }
        lastIndexRva = (LONG)(address - view->base);
    }

    layout->mmUnloadedDriversRva = (LONG)(best.pointerGlobal - view->base);
    layout->mmLastUnloadedDriverRva = lastIndexRva;
    layout->uldName = (LONG)best.nameOffset;
    layout->uldStartAddress = (LONG)best.startAddressOffset;
    layout->uldEndAddress = (LONG)best.endAddressOffset;
    layout->uldCurrentTime = (LONG)best.currentTimeOffset;
    layout->uldTypeSize = (LONG)best.recordSize;
}

static BOOLEAN
kswordArkKernelCacheAvlTableIsPlausible(
    _In_ const KswRuntimeImageView* view,
    _In_ ULONG_PTR address,
    _Out_opt_ RTL_AVL_TABLE* snapshotOut
    )
{
    RTL_AVL_TABLE table;
    ULONG_PTR childPointers[3];
    ULONG index = 0UL;

    RtlZeroMemory(&table, sizeof(table));
    if (view == NULL || (address & (sizeof(PVOID) - 1U)) != 0U ||
        !kswordArkRuntimeAddressIsWritableData(view, address, sizeof(table)) ||
        !kswordArkRuntimeReadMemory((const VOID*)address, &table, sizeof(table)) ||
        table.NumberGenericTableElements == 0UL ||
        table.NumberGenericTableElements > 0x10000UL ||
        table.DepthOfTree == 0UL || table.DepthOfTree > 64UL ||
        table.WhichOrderedElement > table.NumberGenericTableElements ||
        !kswordArkRuntimeAddressIsExecutable(
            view,
            (ULONG_PTR)table.CompareRoutine,
            1U) ||
        !kswordArkRuntimeAddressIsExecutable(
            view,
            (ULONG_PTR)table.AllocateRoutine,
            1U) ||
        !kswordArkRuntimeAddressIsExecutable(
            view,
            (ULONG_PTR)table.FreeRoutine,
            1U)) {
        return FALSE;
    }
    childPointers[0] = (ULONG_PTR)table.BalancedRoot.Parent;
    childPointers[1] = (ULONG_PTR)table.BalancedRoot.LeftChild;
    childPointers[2] = (ULONG_PTR)table.BalancedRoot.RightChild;
    for (index = 0UL; index < RTL_NUMBER_OF(childPointers); ++index) {
        if (childPointers[index] != 0U &&
            !kswordArkKernelCacheIsKernelPointer(childPointers[index])) {
            return FALSE;
        }
    }
    if (table.OrderedPointer != NULL &&
        !kswordArkKernelCacheIsKernelPointer((ULONG_PTR)table.OrderedPointer)) {
        return FALSE;
    }
    if (table.RestartKey != NULL &&
        !kswordArkKernelCacheIsKernelPointer((ULONG_PTR)table.RestartKey)) {
        return FALSE;
    }
    if (snapshotOut != NULL) {
        *snapshotOut = table;
    }
    return TRUE;
}

static BOOLEAN
kswordArkKernelCacheOptionalPointerIsSane(
    _In_opt_ const VOID* pointer
    )
{
    return pointer == NULL ||
        kswordArkKernelCacheIsKernelPointer((ULONG_PTR)pointer);
}

static BOOLEAN
kswordArkKernelCacheResourceIsPlausible(
    _In_ const KswRuntimeImageView* view,
    _In_ ULONG_PTR address
    )
/*++

Routine Description:

    Cheap shape filter used while pairing candidates.  It narrows the search
    space only; it can never establish that the address is a real ERESOURCE,
    because every self-consistent LIST_ENTRY in a writable ntoskrnl section
    satisfies these conditions.  Identity is settled later by
    kswordArkKernelProbeResourceIsSystemResource.

Return Value:

    TRUE when the candidate is shaped like a resource.

--*/
{
    ERESOURCE resource;
    LIST_ENTRY forward;
    LIST_ENTRY backward;

    RtlZeroMemory(&resource, sizeof(resource));
    RtlZeroMemory(&forward, sizeof(forward));
    RtlZeroMemory(&backward, sizeof(backward));
    if (view == NULL || (address & (sizeof(PVOID) - 1U)) != 0U ||
        !kswordArkRuntimeAddressIsWritableData(view, address, sizeof(resource)) ||
        !kswordArkRuntimeReadMemory((const VOID*)address, &resource, sizeof(resource)) ||
        !kswordArkKernelCacheIsKernelPointer(
            (ULONG_PTR)resource.SystemResourcesList.Flink) ||
        !kswordArkKernelCacheIsKernelPointer(
            (ULONG_PTR)resource.SystemResourcesList.Blink) ||
        (((ULONG_PTR)resource.SystemResourcesList.Flink |
          (ULONG_PTR)resource.SystemResourcesList.Blink) &
         (sizeof(PVOID) - 1U)) != 0U ||
        resource.ActiveCount < 0 ||
        !kswordArkKernelCacheOptionalPointerIsSane(resource.OwnerTable) ||
        !kswordArkKernelCacheOptionalPointerIsSane(resource.SharedWaiters) ||
        !kswordArkKernelCacheOptionalPointerIsSane(resource.ExclusiveWaiters) ||
        !kswordArkRuntimeReadMemory(
            resource.SystemResourcesList.Flink,
            &forward,
            sizeof(forward)) ||
        !kswordArkRuntimeReadMemory(
            resource.SystemResourcesList.Blink,
            &backward,
            sizeof(backward)) ||
        forward.Blink != (PLIST_ENTRY)address ||
        backward.Flink != (PLIST_ENTRY)address) {
        return FALSE;
    }
    return TRUE;
}

static BOOLEAN
kswordArkKernelCacheCollectAvlEntries(
    _In_ const RTL_AVL_TABLE* snapshot,
    _In_ ULONG_PTR tableAddress,
    _Out_writes_to_(capacity, *countOut) PVOID* entries,
    _In_ ULONG capacity,
    _Out_ ULONG* countOut
    )
/*++

Routine Description:

    Walk the balanced tree with bounded fault-tolerant reads and collect user
    data pointers.  This replaces RtlGetElementGenericTableAvl, which follows
    every link without validation and additionally mutates OrderedPointer and
    WhichOrderedElement inside a table that is only held shared.  Parent back
    pointers, balance factors, and the element count must all agree, so a
    structure that merely resembles a table fails here instead of inside the
    Rtl walker.

Return Value:

    TRUE when the whole tree is intact and at least one element was collected.

--*/
{
    ULONG_PTR nodeStack[KSW_KERNEL_CACHE_MAX_AVL_DEPTH];
    ULONG_PTR parentStack[KSW_KERNEL_CACHE_MAX_AVL_DEPTH];
    ULONG depth = 0UL;
    ULONG visited = 0UL;
    ULONG collected = 0UL;
    ULONG_PTR sentinel = 0U;

    if (snapshot == NULL || tableAddress == 0U || entries == NULL ||
        capacity == 0UL || countOut == NULL) {
        return FALSE;
    }
    *countOut = 0UL;
    if (snapshot->NumberGenericTableElements == 0UL ||
        snapshot->NumberGenericTableElements > KSW_KERNEL_CACHE_MAX_AVL_ELEMENTS ||
        snapshot->BalancedRoot.LeftChild != NULL ||
        snapshot->BalancedRoot.RightChild == NULL) {
        return FALSE;
    }
    RtlZeroMemory(nodeStack, sizeof(nodeStack));
    RtlZeroMemory(parentStack, sizeof(parentStack));
    sentinel = tableAddress + FIELD_OFFSET(RTL_AVL_TABLE, BalancedRoot);
    nodeStack[0] = (ULONG_PTR)snapshot->BalancedRoot.RightChild;
    parentStack[0] = sentinel;
    depth = 1UL;

    while (depth != 0UL) {
        RTL_BALANCED_LINKS links;
        ULONG_PTR node = 0U;
        ULONG_PTR expectedParent = 0U;
        ULONG child = 0UL;
        ULONG_PTR children[2];

        depth -= 1UL;
        node = nodeStack[depth];
        expectedParent = parentStack[depth];
        if ((node & (sizeof(PVOID) - 1U)) != 0U ||
            !kswordArkKernelCacheIsKernelPointer(node)) {
            return FALSE;
        }
        RtlZeroMemory(&links, sizeof(links));
        if (!kswordArkRuntimeReadMemory((const VOID*)node, &links, sizeof(links)) ||
            (ULONG_PTR)links.Parent != expectedParent ||
            links.Balance < -1 || links.Balance > 1) {
            return FALSE;
        }
        visited += 1UL;
        if (visited > snapshot->NumberGenericTableElements) {
            return FALSE;
        }
        if (collected < capacity) {
            entries[collected] = (PVOID)(node + sizeof(RTL_BALANCED_LINKS));
            collected += 1UL;
        }
        children[0] = (ULONG_PTR)links.LeftChild;
        children[1] = (ULONG_PTR)links.RightChild;
        for (child = 0UL; child < RTL_NUMBER_OF(children); ++child) {
            if (children[child] == 0U) {
                continue;
            }
            if (depth >= KSW_KERNEL_CACHE_MAX_AVL_DEPTH) {
                return FALSE;
            }
            nodeStack[depth] = children[child];
            parentStack[depth] = node;
            depth += 1UL;
        }
    }
    if (visited != snapshot->NumberGenericTableElements) {
        return FALSE;
    }
    *countOut = collected;
    return collected != 0UL;
}

static ULONG
kswordArkKernelCachePairScore(
    _In_ const KswRuntimeDataReference* tableReference,
    _In_ const KswRuntimeDataReference* lockReference
    )
{
    ULONG_PTR distance = 0U;
    ULONG score = 0UL;

    if (tableReference->routineAddress == lockReference->routineAddress) {
        score += 8UL;
    }
    distance = tableReference->instructionAddress > lockReference->instructionAddress
        ? tableReference->instructionAddress - lockReference->instructionAddress
        : lockReference->instructionAddress - tableReference->instructionAddress;
    if (distance <= 0x100UL) {
        score += 4UL;
    }
    else if (distance <= 0x800UL) {
        score += 2UL;
    }
    else if (distance <= 0x2000UL) {
        score += 1UL;
    }
    return score;
}

static BOOLEAN
kswordArkKernelCacheInferPiDdbEntryLayout(
    _In_reads_(sampleCount) PVOID const* entries,
    _In_ ULONG sampleCountArg,
    _Out_ KswPiddbLayoutCandidate* layout
    )
/*++

Routine Description:

    Infer PiDDB element fields while its validated resource is held.  Driver
    names must agree across multiple AVL elements; timestamp and status fields
    must form one unique adjacent semantic pair after the name descriptor.

Return Value:

    TRUE only for a unique bounded layout.

--*/
{
    ULONG sampleCount = 0UL;
    ULONG index = 0UL;
    ULONG nameOffset = 0UL;
    ULONG bestNameMatches = 0UL;
    LONG bestNameOffset = -1;
    BOOLEAN nameTied = FALSE;
    ULONG pairOffset = 0UL;
    ULONG bestPairMatches = 0UL;
    LONG bestPairOffset = -1;
    BOOLEAN pairTied = FALSE;

    if (entries == NULL || layout == NULL) {
        return FALSE;
    }
    sampleCount = min(sampleCountArg, KSW_KERNEL_CACHE_MAX_SAMPLE_ENTRIES);
    if (sampleCount < 2UL) {
        return FALSE;
    }
    for (index = 0UL; index < sampleCount; ++index) {
        if (entries[index] == NULL ||
            !kswordArkKernelCacheIsKernelPointer((ULONG_PTR)entries[index])) {
            return FALSE;
        }
    }

    for (nameOffset = 0UL;
         nameOffset + sizeof(UNICODE_STRING) <= KSW_KERNEL_CACHE_MAX_PRIVATE_ENTRY;
         nameOffset += sizeof(PVOID)) {
        ULONG matches = 0UL;

        for (index = 0UL; index < sampleCount; ++index) {
            if (kswordArkKernelCacheReadDriverName(
                    (const UCHAR*)entries[index],
                    nameOffset,
                    NULL)) {
                matches += 1UL;
            }
        }
        if (matches < 2UL || matches < bestNameMatches) {
            continue;
        }
        if (matches == bestNameMatches && bestNameMatches != 0UL) {
            nameTied = TRUE;
            continue;
        }
        bestNameMatches = matches;
        bestNameOffset = (LONG)nameOffset;
        nameTied = FALSE;
    }
    if (bestNameOffset < 0 || nameTied) {
        return FALSE;
    }

    for (pairOffset = (ULONG)bestNameOffset + sizeof(UNICODE_STRING);
         pairOffset + (2UL * sizeof(ULONG)) <=
             min(KSW_KERNEL_CACHE_MAX_PRIVATE_ENTRY,
                 (ULONG)bestNameOffset + sizeof(UNICODE_STRING) + 0x20UL);
         pairOffset += sizeof(ULONG)) {
        ULONG matches = 0UL;

        for (index = 0UL; index < sampleCount; ++index) {
            ULONG timeDateStamp = 0UL;
            NTSTATUS loadStatus = STATUS_SUCCESS;

            if (!kswordArkRuntimeReadMemory(
                    (const UCHAR*)entries[index] + pairOffset,
                    &timeDateStamp,
                    sizeof(timeDateStamp)) ||
                !kswordArkRuntimeReadMemory(
                    (const UCHAR*)entries[index] + pairOffset + sizeof(ULONG),
                    &loadStatus,
                    sizeof(loadStatus)) ||
                timeDateStamp < 0x20000000UL ||
                !((loadStatus == STATUS_SUCCESS) ||
                  (((ULONG)loadStatus & 0xC0000000UL) == 0xC0000000UL) ||
                  (((ULONG)loadStatus & 0xC0000000UL) == 0x80000000UL))) {
                continue;
            }
            matches += 1UL;
        }
        if (matches < 2UL || matches < bestPairMatches) {
            continue;
        }
        if (matches == bestPairMatches && bestPairMatches != 0UL) {
            pairTied = TRUE;
            continue;
        }
        bestPairMatches = matches;
        bestPairOffset = (LONG)pairOffset;
        pairTied = FALSE;
    }
    if (bestPairOffset < 0 || pairTied) {
        return FALSE;
    }

    layout->driverNameOffset = (ULONG)bestNameOffset;
    layout->timeDateStampOffset = (ULONG)bestPairOffset;
    layout->loadStatusOffset = (ULONG)bestPairOffset + sizeof(ULONG);
    layout->entrySize = (layout->loadStatusOffset + sizeof(NTSTATUS) +
        (sizeof(PVOID) - 1UL)) & ~(sizeof(PVOID) - 1UL);
    return TRUE;
}

static VOID
kswordArkKernelCacheResolvePiDdb(
    _In_ const KswRuntimeImageView* view,
    _In_reads_(referenceCount) const KswRuntimeDataReference* references,
    _In_ ULONG referenceCount,
    _Inout_ PkswRuntimeKernelLayout layout
    )
{
    ULONG tableIndex = 0UL;
    ULONG bestScore = 0UL;
    BOOLEAN ambiguous = FALSE;
    const KswRuntimeDataReference* bestTableReference = NULL;
    const KswRuntimeDataReference* bestLockReference = NULL;
    KswPiddbLayoutCandidate candidate;
    BOOLEAN acquired = FALSE;

    if (view == NULL || references == NULL || layout == NULL ||
        KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }
    RtlZeroMemory(&candidate, sizeof(candidate));
    for (tableIndex = 0UL; tableIndex < referenceCount; ++tableIndex) {
        ULONG lockIndex = 0UL;

        if (!kswordArkKernelCacheAvlTableIsPlausible(
                view,
                references[tableIndex].address,
                NULL)) {
            continue;
        }
        for (lockIndex = 0UL; lockIndex < referenceCount; ++lockIndex) {
            ULONG score = 0UL;

            if (lockIndex == tableIndex ||
                !kswordArkKernelCacheResourceIsPlausible(
                    view,
                    references[lockIndex].address)) {
                continue;
            }
            score = kswordArkKernelCachePairScore(
                &references[tableIndex],
                &references[lockIndex]);
            if (score == 0UL || score < bestScore) {
                continue;
            }
            if (score == bestScore && bestScore != 0UL &&
                (bestTableReference->address != references[tableIndex].address ||
                 bestLockReference->address != references[lockIndex].address)) {
                ambiguous = TRUE;
                continue;
            }
            bestScore = score;
            ambiguous = FALSE;
            bestTableReference = &references[tableIndex];
            bestLockReference = &references[lockIndex];
        }
    }
    if (bestScore < 2UL || ambiguous || bestTableReference == NULL ||
        bestLockReference == NULL) {
        return;
    }

    candidate.table = (PRTL_AVL_TABLE)bestTableReference->address;
    candidate.lock = (PERESOURCE)bestLockReference->address;
    if (!kswordArkKernelProbeResourceIsSystemResource(
            (ULONG_PTR)candidate.lock)) {
        return;
    }

    KeEnterCriticalRegion();
    acquired = ExAcquireResourceSharedLite(candidate.lock, FALSE);
    if (acquired) {
        RTL_AVL_TABLE snapshot;
        PVOID entries[KSW_KERNEL_CACHE_MAX_SAMPLE_ENTRIES];
        ULONG entryCount = 0UL;

        RtlZeroMemory(&snapshot, sizeof(snapshot));
        RtlZeroMemory(entries, sizeof(entries));
        if (kswordArkKernelCacheAvlTableIsPlausible(
                view,
                (ULONG_PTR)candidate.table,
                &snapshot) &&
            kswordArkKernelCacheCollectAvlEntries(
                &snapshot,
                (ULONG_PTR)candidate.table,
                entries,
                RTL_NUMBER_OF(entries),
                &entryCount) &&
            kswordArkKernelCacheInferPiDdbEntryLayout(
                entries,
                entryCount,
                &candidate)) {
            if ((ULONG_PTR)candidate.table >= view->base &&
                (ULONG_PTR)candidate.lock >= view->base &&
                (ULONG_PTR)candidate.table - view->base <= MAXLONG &&
                (ULONG_PTR)candidate.lock - view->base <= MAXLONG) {
                layout->piDdbCacheTableRva =
                    (LONG)((ULONG_PTR)candidate.table - view->base);
                layout->piDdbLockRva =
                    (LONG)((ULONG_PTR)candidate.lock - view->base);
                layout->piDdbDriverName = (LONG)candidate.driverNameOffset;
                layout->piDdbTimeDateStamp =
                    (LONG)candidate.timeDateStampOffset;
                layout->piDdbLoadStatus = (LONG)candidate.loadStatusOffset;
                layout->piDdbTypeSize = (LONG)candidate.entrySize;
            }
        }
        ExReleaseResourceLite(candidate.lock);
    }
    KeLeaveCriticalRegion();
}

VOID
kswordArkDriverResolveKernelCacheFallback(
    _In_ const KSW_DYN_MODULE_IDENTITY_PACKET* ntoskrnlIdentity,
    _Inout_ PkswRuntimeKernelLayout layout
    )
/*++

Routine Description:

    Resolve both ntoskrnl caches from stable exported call graphs.  The two
    features are independent: one may remain unavailable without weakening the
    other feature's validation.

Return Value:

    None.  Unresolved signed members retain the caller's -1 sentinel.

--*/
{
    static PCSTR const kAnchors[] = {
        "MmUnloadSystemImage",
        "MmLoadSystemImage",
        "NtLoadDriver",
        "NtUnloadDriver"
    };
    KswRuntimeImageView view;
    KswRuntimeDataReference* references = NULL;
    ULONG referenceCount = 0UL;

    if (ntoskrnlIdentity == NULL || layout == NULL ||
        ntoskrnlIdentity->present == 0UL ||
        ntoskrnlIdentity->imageBase == 0ULL ||
        ntoskrnlIdentity->sizeOfImage == 0UL ||
        KeGetCurrentIrql() > APC_LEVEL) {
        return;
    }
    RtlZeroMemory(&view, sizeof(view));
    if (!kswordArkRuntimeInitializeImageView(
            (PVOID)(ULONG_PTR)ntoskrnlIdentity->imageBase,
            ntoskrnlIdentity->sizeOfImage,
            &view)) {
        return;
    }
    references = (KswRuntimeDataReference*)kswordArkAllocateNonPagedPool(
        KSW_KERNEL_CACHE_MAX_REFERENCES * sizeof(*references),
        KSW_KERNEL_CACHE_TAG);
    if (references == NULL) {
        return;
    }
    referenceCount = kswordArkRuntimeCollectAnchoredDataReferences(
        &view,
        kAnchors,
        RTL_NUMBER_OF(kAnchors),
        4UL,
        KSW_KERNEL_CACHE_ROUTINE_SCAN_BYTES,
        references,
        KSW_KERNEL_CACHE_MAX_REFERENCES);
    if (referenceCount != 0UL) {
        kswordArkKernelCacheResolveUnloadedDrivers(
            &view,
            references,
            referenceCount,
            layout);
        kswordArkKernelCacheResolvePiDdb(
            &view,
            references,
            referenceCount,
            layout);
    }
    ExFreePoolWithTag(references, KSW_KERNEL_CACHE_TAG);
}
