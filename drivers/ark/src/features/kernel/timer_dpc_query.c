/*++

Module Name:

    timer_dpc_query.c

Abstract:

    Read-only, DynData v4-backed KTIMER/KDPC enumeration.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "../dyndata/dyndata_v4_internal.h"
#include "../../platform/pool_compat.h"

#define KSW_TIMER_DPC_POOL_TAG 'pDTK'

#if defined(_M_AMD64) || defined(_M_X64)
#define KSW_TIMER_DPC_RUNTIME_PRCB_BYTES 0x00010000UL
#define KSW_TIMER_DPC_RUNTIME_LIST_BUDGET 4096UL
#define KSW_TIMER_DPC_RUNTIME_MIN_BUCKETS 64UL
#define KSW_TIMER_DPC_RUNTIME_MAX_ENTRY_BYTES 0x80UL
#endif

typedef struct KswTimerDpcBuilder
{
    KSWORD_ARK_ENUM_TIMER_DPC_RESPONSE* response;
    SIZE_T outputBufferLength;
    ULONG capacity;
    ULONG maxEntries;
    ULONG maxEntriesPerBucket;
    ULONG64* seenTimers;
    ULONG seenCount;
    KswDynV4TimerDpcLayout layout;
} KswTimerDpcBuilder;

static BOOLEAN
kswordArkTimerDpcIsKernelAddress(
    _In_ ULONG64 address
    )
{
#if defined(_M_AMD64) || defined(_M_X64)
    return address >= (ULONG64)(ULONG_PTR)MmSystemRangeStart &&
        (address >> 48U) == 0xFFFFULL;
#else
    return Address >= (ULONG64)(ULONG_PTR)MmSystemRangeStart;
#endif
}

static BOOLEAN
kswordArkTimerDpcAddAddress(
    _In_ ULONG64 base,
    _In_ ULONG offset,
    _Out_ ULONG64* addressOut
    )
{
    if (addressOut == NULL || base > MAXULONGLONG - (ULONG64)offset) {
        return FALSE;
    }
    *addressOut = base + (ULONG64)offset;
    return kswordArkTimerDpcIsKernelAddress(*addressOut);
}

static BOOLEAN
kswordArkTimerDpcReadMemory(
    _In_ ULONG64 address,
    _Out_writes_bytes_(bytesToRead) PVOID destination,
    _In_ SIZE_T bytesToRead
    )
{
    MM_COPY_ADDRESS sourceAddress;
    SIZE_T copiedBytes = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (destination == NULL || bytesToRead == 0U ||
        !kswordArkTimerDpcIsKernelAddress(address) ||
        address > MAXULONGLONG - (ULONG64)(bytesToRead - 1U) ||
        !kswordArkTimerDpcIsKernelAddress(address + (ULONG64)(bytesToRead - 1U)) ||
        KeGetCurrentIrql() > APC_LEVEL) {
        return FALSE;
    }

    RtlZeroMemory(&sourceAddress, sizeof(sourceAddress));
    sourceAddress.VirtualAddress = (PVOID)(ULONG_PTR)address;
    __try {
        status = MmCopyMemory(
            destination,
            sourceAddress,
            bytesToRead,
            MM_COPY_MEMORY_VIRTUAL,
            &copiedBytes);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        RtlZeroMemory(destination, bytesToRead);
        return FALSE;
    }

    if (!NT_SUCCESS(status) || copiedBytes != bytesToRead) {
        RtlZeroMemory(destination, bytesToRead);
        return FALSE;
    }
    return TRUE;
}

#if defined(_M_AMD64) || defined(_M_X64)
static BOOLEAN
kswordArkTimerDpcAddressInsidePrcb(
    _In_ ULONG64 address,
    _In_ ULONG64 prcbAddress,
    _In_ SIZE_T bytes
    )
/*++

Routine Description:

    Bound one candidate range to the current processor's conservative KPRCB
    window.  The private KPRCB type size is deliberately not assumed.

Return Value:

    TRUE when the entire range is contained by the non-wrapping window.

--*/
{
    ULONG64 prcbEnd = 0ULL;

    if (!kswordArkTimerDpcIsKernelAddress(prcbAddress) ||
        prcbAddress > MAXULONGLONG - KSW_TIMER_DPC_RUNTIME_PRCB_BYTES) {
        return FALSE;
    }
    prcbEnd = prcbAddress + KSW_TIMER_DPC_RUNTIME_PRCB_BYTES;
    return address >= prcbAddress && address < prcbEnd &&
        bytes <= (SIZE_T)(prcbEnd - address);
}

static BOOLEAN
kswordArkTimerDpcListHeadValid(
    _In_ ULONG64 headAddress
    )
/*++

Routine Description:

    Validate an empty or populated LIST_ENTRY head with reciprocal first/last
    links.  This is the semantic gate used after the probe reaches KPRCB data.

Return Value:

    TRUE for a reciprocal bounded list head; otherwise FALSE.

--*/
{
    LIST_ENTRY head;
    LIST_ENTRY first;
    LIST_ENTRY last;
    ULONG64 forward = 0ULL;
    ULONG64 backward = 0ULL;

    RtlZeroMemory(&head, sizeof(head));
    RtlZeroMemory(&first, sizeof(first));
    RtlZeroMemory(&last, sizeof(last));
    if (!kswordArkTimerDpcReadMemory(headAddress, &head, sizeof(head))) {
        return FALSE;
    }
    forward = (ULONG64)(ULONG_PTR)head.Flink;
    backward = (ULONG64)(ULONG_PTR)head.Blink;
    if (forward == headAddress || backward == headAddress) {
        return (forward == headAddress && backward == headAddress) ? TRUE : FALSE;
    }
    if (!kswordArkTimerDpcIsKernelAddress(forward) ||
        !kswordArkTimerDpcIsKernelAddress(backward) ||
        !kswordArkTimerDpcReadMemory(forward, &first, sizeof(first)) ||
        !kswordArkTimerDpcReadMemory(backward, &last, sizeof(last))) {
        return FALSE;
    }
    return ((ULONG64)(ULONG_PTR)first.Blink == headAddress &&
            (ULONG64)(ULONG_PTR)last.Flink == headAddress)
        ? TRUE
        : FALSE;
}

static ULONG64
kswordArkTimerDpcWalkProbeToPrcb(
    _In_ ULONG64 probeLinkAddress,
    _In_ ULONG64 prcbAddress,
    _In_ BOOLEAN walkForward
    )
/*++

Routine Description:

    Follow one direction of a live probe timer's reciprocal list until the
    walk reaches the embedded bucket head inside the current KPRCB.

Return Value:

    Candidate bucket-head address, or zero on corruption/budget exhaustion.

--*/
{
    ULONG64 currentAddress = probeLinkAddress;
    ULONG step = 0UL;

    for (step = 0UL; step < KSW_TIMER_DPC_RUNTIME_LIST_BUDGET; ++step) {
        LIST_ENTRY current;
        LIST_ENTRY next;
        ULONG64 nextAddress = 0ULL;

        RtlZeroMemory(&current, sizeof(current));
        RtlZeroMemory(&next, sizeof(next));
        if (!kswordArkTimerDpcReadMemory(currentAddress, &current, sizeof(current))) {
            return 0ULL;
        }
        nextAddress = walkForward
            ? (ULONG64)(ULONG_PTR)current.Flink
            : (ULONG64)(ULONG_PTR)current.Blink;
        if (nextAddress == 0ULL || nextAddress == probeLinkAddress ||
            !kswordArkTimerDpcIsKernelAddress(nextAddress) ||
            !kswordArkTimerDpcReadMemory(nextAddress, &next, sizeof(next))) {
            return 0ULL;
        }
        if (walkForward) {
            if ((ULONG64)(ULONG_PTR)next.Blink != currentAddress) {
                return 0ULL;
            }
        }
        else if ((ULONG64)(ULONG_PTR)next.Flink != currentAddress) {
            return 0ULL;
        }

        if (kswordArkTimerDpcAddressInsidePrcb(
                nextAddress,
                prcbAddress,
                sizeof(LIST_ENTRY))) {
            return kswordArkTimerDpcListHeadValid(nextAddress)
                ? nextAddress
                : 0ULL;
        }
        currentAddress = nextAddress;
    }
    return 0ULL;
}

static ULONG
kswordArkTimerDpcCountBucketRun(
    _In_ ULONG64 knownHeadAddress,
    _In_ ULONG64 prcbAddress,
    _In_ ULONG entryBytes,
    _Out_ ULONG64* firstHeadAddressOut
    )
/*++

Routine Description:

    Expand from one proven bucket head across a regular KPRCB list-head array.
    Only reciprocal heads count, and both directions are bounded by the KPRCB
    window and the public protocol's hard bucket limit.

Return Value:

    Number of contiguous heads for this stride; zero for invalid input.

--*/
{
    ULONG64 firstAddress = knownHeadAddress;
    ULONG64 cursorAddress = knownHeadAddress;
    ULONG beforeCount = 0UL;
    ULONG afterCount = 0UL;

    if (firstHeadAddressOut == NULL || entryBytes < sizeof(LIST_ENTRY) ||
        (entryBytes & (sizeof(PVOID) - 1UL)) != 0UL) {
        return 0UL;
    }
    *firstHeadAddressOut = 0ULL;

    while (beforeCount < KSWORD_ARK_TIMER_DPC_MAX_BUCKETS - 1UL &&
           cursorAddress >= prcbAddress + entryBytes) {
        const ULONG64 kPreviousAddress = cursorAddress - entryBytes;

        if (!kswordArkTimerDpcAddressInsidePrcb(
                kPreviousAddress,
                prcbAddress,
                sizeof(LIST_ENTRY)) ||
            !kswordArkTimerDpcListHeadValid(kPreviousAddress)) {
            break;
        }
        firstAddress = kPreviousAddress;
        cursorAddress = kPreviousAddress;
        beforeCount += 1UL;
    }

    cursorAddress = knownHeadAddress;
    while (beforeCount + afterCount < KSWORD_ARK_TIMER_DPC_MAX_BUCKETS - 1UL &&
           cursorAddress <= MAXULONGLONG - entryBytes) {
        const ULONG64 kNextAddress = cursorAddress + entryBytes;

        if (!kswordArkTimerDpcAddressInsidePrcb(
                kNextAddress,
                prcbAddress,
                sizeof(LIST_ENTRY)) ||
            !kswordArkTimerDpcListHeadValid(kNextAddress)) {
            break;
        }
        cursorAddress = kNextAddress;
        afterCount += 1UL;
    }

    *firstHeadAddressOut = firstAddress;
    return beforeCount + afterCount + 1UL;
}

static BOOLEAN
kswordArkTimerDpcResolveBucketArray(
    _In_ ULONG64 knownHeadAddress,
    _In_ ULONG64 prcbAddress,
    _Out_ ULONG64* firstHeadAddressOut,
    _Out_ ULONG* entryBytesOut,
    _Out_ ULONG* bucketCountOut
    )
/*++

Routine Description:

    Select the unique regular bucket-array stride with the strongest live
    structural evidence.  A power-of-two run of at least 64 heads is required;
    ties fail closed instead of choosing a version guess.

Return Value:

    TRUE when one unique strongest layout was recovered.

--*/
{
    ULONG entryBytes = 0UL;
    ULONG bestCount = 0UL;
    ULONG bestEntryBytes = 0UL;
    ULONG64 bestFirstAddress = 0ULL;
    BOOLEAN ambiguous = FALSE;

    if (firstHeadAddressOut == NULL || entryBytesOut == NULL ||
        bucketCountOut == NULL) {
        return FALSE;
    }
    *firstHeadAddressOut = 0ULL;
    *entryBytesOut = 0UL;
    *bucketCountOut = 0UL;

    for (entryBytes = (ULONG)sizeof(LIST_ENTRY);
         entryBytes <= KSW_TIMER_DPC_RUNTIME_MAX_ENTRY_BYTES;
         entryBytes += (ULONG)sizeof(PVOID)) {
        ULONG64 firstAddress = 0ULL;
        const ULONG kCount = kswordArkTimerDpcCountBucketRun(
            knownHeadAddress,
            prcbAddress,
            entryBytes,
            &firstAddress);

        if (kCount < KSW_TIMER_DPC_RUNTIME_MIN_BUCKETS ||
            kCount > KSWORD_ARK_TIMER_DPC_MAX_BUCKETS ||
            (kCount & (kCount - 1UL)) != 0UL) {
            continue;
        }
        if (kCount > bestCount) {
            bestCount = kCount;
            bestEntryBytes = entryBytes;
            bestFirstAddress = firstAddress;
            ambiguous = FALSE;
        }
        else if (kCount == bestCount &&
                 (entryBytes != bestEntryBytes || firstAddress != bestFirstAddress)) {
            ambiguous = TRUE;
        }
    }

    if (bestCount == 0UL || ambiguous || bestFirstAddress < prcbAddress ||
        bestFirstAddress - prcbAddress > MAXULONG ||
        bestCount > MAXULONG / bestEntryBytes) {
        return FALSE;
    }
    *firstHeadAddressOut = bestFirstAddress;
    *entryBytesOut = bestEntryBytes;
    *bucketCountOut = bestCount;
    return TRUE;
}

static NTSTATUS
kswordArkTimerDpcResolveRuntimeLayout(
    _Out_ KswDynV4TimerDpcLayout* layoutOut
    )
/*++

Routine Description:

    Recover a normalized Timer/DPC enumeration layout without PDB data.  A
    long-due probe KTIMER is inserted on the affinity-pinned current processor,
    both reciprocal list directions must reach the same KPRCB bucket head, and
    the surrounding regular bucket array must have a unique strongest stride.
    Public WDK KTIMER/KDPC member offsets complete the read-only layout.

Return Value:

    STATUS_SUCCESS for a fully validated runtime layout; otherwise a fail-closed
    capability or data status.  The probe is cancelled on every exit path.

--*/
{
    KTIMER probeTimer;
    LARGE_INTEGER dueTime;
    PROCESSOR_NUMBER processorNumber;
    GROUP_AFFINITY targetAffinity;
    GROUP_AFFINITY previousAffinity;
    ULONG64 prcbAddress = 0ULL;
    ULONG64 probeLinkAddress = 0ULL;
    ULONG64 forwardHead = 0ULL;
    ULONG64 backwardHead = 0ULL;
    ULONG64 firstHead = 0ULL;
    ULONG entryBytes = 0UL;
    ULONG bucketCount = 0UL;
    BOOLEAN affinitySet = FALSE;
    BOOLEAN timerSet = FALSE;
    NTSTATUS status = STATUS_NOT_SUPPORTED;

    if (layoutOut == NULL || KeGetCurrentIrql() > APC_LEVEL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(layoutOut, sizeof(*layoutOut));
    RtlZeroMemory(&probeTimer, sizeof(probeTimer));
    RtlZeroMemory(&processorNumber, sizeof(processorNumber));
    RtlZeroMemory(&targetAffinity, sizeof(targetAffinity));
    RtlZeroMemory(&previousAffinity, sizeof(previousAffinity));

    KeGetCurrentProcessorNumberEx(&processorNumber);
    if (processorNumber.Number >= sizeof(KAFFINITY) * 8UL) {
        return STATUS_NOT_SUPPORTED;
    }
    targetAffinity.Group = processorNumber.Group;
    targetAffinity.Mask = ((KAFFINITY)1) << processorNumber.Number;
    KeSetSystemGroupAffinityThread(&targetAffinity, &previousAffinity);
    affinitySet = TRUE;

    __try {
        prcbAddress = (ULONG64)(ULONG_PTR)KeGetPcr()->CurrentPrcb;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        goto Exit;
    }
    if (!kswordArkTimerDpcIsKernelAddress(prcbAddress)) {
        status = STATUS_DATA_ERROR;
        goto Exit;
    }

    KeInitializeTimerEx(&probeTimer, NotificationTimer);
    dueTime.QuadPart = -6000000000LL;
    (VOID)KeSetTimerEx(&probeTimer, dueTime, 0L, NULL);
    timerSet = TRUE;
    probeLinkAddress = (ULONG64)(ULONG_PTR)&probeTimer.TimerListEntry;

    forwardHead = kswordArkTimerDpcWalkProbeToPrcb(
        probeLinkAddress,
        prcbAddress,
        TRUE);
    backwardHead = kswordArkTimerDpcWalkProbeToPrcb(
        probeLinkAddress,
        prcbAddress,
        FALSE);
    if (forwardHead == 0ULL || forwardHead != backwardHead ||
        !kswordArkTimerDpcResolveBucketArray(
            forwardHead,
            prcbAddress,
            &firstHead,
            &entryBytes,
            &bucketCount)) {
        status = STATUS_NOT_FOUND;
        goto Exit;
    }

    layoutOut->kprcbTimerTable = (ULONG)(firstHead - prcbAddress);
    layoutOut->timerTableTimerEntries = 0UL;
    layoutOut->timerTableEntryLock = 0UL;
    layoutOut->timerTableEntryEntry = 0UL;
    layoutOut->timerTableEntryTime = 0UL;
    layoutOut->timerTimerListEntry = (ULONG)FIELD_OFFSET(KTIMER, TimerListEntry);
    layoutOut->timerDueTime = (ULONG)FIELD_OFFSET(KTIMER, DueTime);
    layoutOut->timerDpc = (ULONG)FIELD_OFFSET(KTIMER, Dpc);
    layoutOut->timerType = (ULONG)FIELD_OFFSET(KTIMER, Header.Type);
    layoutOut->timerPeriod = (ULONG)FIELD_OFFSET(KTIMER, Period);
    layoutOut->dpcDeferredRoutine = (ULONG)FIELD_OFFSET(KDPC, DeferredRoutine);
    layoutOut->dpcDeferredContext = (ULONG)FIELD_OFFSET(KDPC, DeferredContext);
    layoutOut->timerTableTypeSize = bucketCount * entryBytes;
    layoutOut->timerTableEntryTypeSize = entryBytes;
    layoutOut->timerTypeSize = (ULONG)sizeof(KTIMER);
    layoutOut->dpcTypeSize = (ULONG)sizeof(KDPC);
    status = STATUS_SUCCESS;

Exit:
    if (timerSet) {
        (VOID)KeCancelTimer(&probeTimer);
    }
    if (affinitySet) {
        KeRevertToUserGroupAffinityThread(&previousAffinity);
    }
    if (!NT_SUCCESS(status)) {
        RtlZeroMemory(layoutOut, sizeof(*layoutOut));
    }
    return status;
}
#endif

static BOOLEAN
kswordArkTimerDpcLayoutValid(
    _In_ const KswDynV4TimerDpcLayout* layout,
    _Out_ ULONG* bucketCountOut
    )
{
    ULONG remainingBytes = 0UL;
    ULONG bucketCount = 0UL;

    if (layout == NULL || bucketCountOut == NULL) {
        return FALSE;
    }
    *bucketCountOut = 0UL;

    if (layout->kprcbTimerTable == 0UL ||
        layout->timerTableTypeSize == 0UL ||
        layout->timerTableEntryTypeSize < sizeof(LIST_ENTRY) ||
        layout->timerTableEntryTypeSize > 0x100UL ||
        layout->timerTableTimerEntries >= layout->timerTableTypeSize ||
        layout->timerTableEntryEntry > layout->timerTableEntryTypeSize - sizeof(LIST_ENTRY) ||
        layout->timerTypeSize < sizeof(LIST_ENTRY) ||
        layout->timerTimerListEntry > layout->timerTypeSize - sizeof(LIST_ENTRY) ||
        layout->timerDueTime > layout->timerTypeSize - sizeof(LONGLONG) ||
        layout->timerDpc > layout->timerTypeSize - sizeof(PVOID) ||
        layout->timerType >= layout->timerTypeSize ||
        layout->timerPeriod > layout->timerTypeSize - sizeof(LONG) ||
        layout->dpcTypeSize < sizeof(PVOID) ||
        layout->dpcDeferredRoutine > layout->dpcTypeSize - sizeof(PVOID) ||
        layout->dpcDeferredContext > layout->dpcTypeSize - sizeof(PVOID)) {
        return FALSE;
    }

    remainingBytes = layout->timerTableTypeSize - layout->timerTableTimerEntries;
    bucketCount = remainingBytes / layout->timerTableEntryTypeSize;
    if (bucketCount == 0UL || bucketCount > KSWORD_ARK_TIMER_DPC_MAX_BUCKETS) {
        return FALSE;
    }

    *bucketCountOut = bucketCount;
    return TRUE;
}

static BOOLEAN
kswordArkTimerDpcAlreadySeen(
    _Inout_ KswTimerDpcBuilder* builder,
    _In_ ULONG64 timerAddress
    )
{
    ULONG index = 0UL;
    for (index = 0UL; index < builder->seenCount; ++index) {
        if (builder->seenTimers[index] == timerAddress) {
            builder->response->duplicateCount += 1UL;
            builder->response->statusFlags |= KSWORD_ARK_TIMER_DPC_STATUS_DUPLICATE_SKIPPED;
            return TRUE;
        }
    }
    if (builder->seenCount < builder->maxEntries) {
        builder->seenTimers[builder->seenCount] = timerAddress;
        builder->seenCount += 1UL;
    }
    return FALSE;
}

static VOID
kswordArkTimerDpcMarkReadFailure(
    _Inout_ KswTimerDpcBuilder* builder,
    _In_ BOOLEAN corruptChain
    )
{
    builder->response->readFailureCount += 1UL;
    builder->response->statusFlags |=
        KSWORD_ARK_TIMER_DPC_STATUS_PARTIAL |
        KSWORD_ARK_TIMER_DPC_STATUS_READ_FAILED;
    if (corruptChain) {
        builder->response->corruptBucketCount += 1UL;
        builder->response->statusFlags |= KSWORD_ARK_TIMER_DPC_STATUS_CORRUPT_CHAIN;
    }
}

static VOID
kswordArkTimerDpcEmitTimer(
    _Inout_ KswTimerDpcBuilder* builder,
    _In_ USHORT processorGroup,
    _In_ UCHAR processorNumber,
    _In_ ULONG bucketIndex,
    _In_ ULONG64 timerAddress
    )
{
    KSWORD_ARK_TIMER_DPC_ENTRY row;
    ULONG64 fieldAddress = 0ULL;
    ULONG64 dpcAddress = 0ULL;
    UCHAR timerType = 0U;
    BOOLEAN timerFieldsComplete = TRUE;

    RtlZeroMemory(&row, sizeof(row));
    row.processorGroup = processorGroup;
    row.processorNumber = processorNumber;
    row.bucketIndex = bucketIndex;
    row.timerAddress = timerAddress;

    if (!kswordArkTimerDpcAddAddress(timerAddress, builder->layout.timerDueTime, &fieldAddress) ||
        !kswordArkTimerDpcReadMemory(fieldAddress, &row.dueTime, sizeof(row.dueTime))) {
        timerFieldsComplete = FALSE;
    }
    if (!kswordArkTimerDpcAddAddress(timerAddress, builder->layout.timerPeriod, &fieldAddress) ||
        !kswordArkTimerDpcReadMemory(fieldAddress, &row.period, sizeof(row.period))) {
        timerFieldsComplete = FALSE;
    }
    if (!kswordArkTimerDpcAddAddress(timerAddress, builder->layout.timerType, &fieldAddress) ||
        !kswordArkTimerDpcReadMemory(fieldAddress, &timerType, sizeof(timerType))) {
        timerFieldsComplete = FALSE;
    }
    row.timerType = timerType;
    if (row.period != 0) {
        row.flags |= KSWORD_ARK_TIMER_DPC_ENTRY_PERIODIC;
    }

    if (kswordArkTimerDpcAddAddress(timerAddress, builder->layout.timerDpc, &fieldAddress) &&
        kswordArkTimerDpcReadMemory(fieldAddress, &dpcAddress, sizeof(dpcAddress))) {
        row.dpcAddress = dpcAddress;
        if (dpcAddress != 0ULL) {
            row.flags |= KSWORD_ARK_TIMER_DPC_ENTRY_DPC_PRESENT;
            if (kswordArkTimerDpcIsKernelAddress(dpcAddress) &&
                kswordArkTimerDpcAddAddress(dpcAddress, builder->layout.dpcDeferredRoutine, &fieldAddress) &&
                kswordArkTimerDpcReadMemory(fieldAddress, &row.deferredRoutine, sizeof(row.deferredRoutine)) &&
                kswordArkTimerDpcAddAddress(dpcAddress, builder->layout.dpcDeferredContext, &fieldAddress) &&
                kswordArkTimerDpcReadMemory(fieldAddress, &row.deferredContext, sizeof(row.deferredContext))) {
                row.flags |= KSWORD_ARK_TIMER_DPC_ENTRY_DPC_FIELDS_PRESENT;
            }
            else {
                timerFieldsComplete = FALSE;
            }
        }
    }
    else {
        timerFieldsComplete = FALSE;
    }

    if (!timerFieldsComplete) {
        row.flags |= KSWORD_ARK_TIMER_DPC_ENTRY_READ_PARTIAL;
        builder->response->readFailureCount += 1UL;
        builder->response->statusFlags |=
            KSWORD_ARK_TIMER_DPC_STATUS_PARTIAL |
            KSWORD_ARK_TIMER_DPC_STATUS_READ_FAILED;
    }

    builder->response->totalCount += 1UL;
    if (builder->response->returnedCount < builder->capacity) {
        builder->response->entries[builder->response->returnedCount] = row;
        builder->response->returnedCount += 1UL;
    }
    else {
        builder->response->statusFlags |=
            KSWORD_ARK_TIMER_DPC_STATUS_PARTIAL |
            KSWORD_ARK_TIMER_DPC_STATUS_TRUNCATED;
    }
}

static BOOLEAN
kswordArkTimerDpcEnumerateBucket(
    _Inout_ KswTimerDpcBuilder* builder,
    _In_ USHORT processorGroup,
    _In_ UCHAR processorNumber,
    _In_ ULONG bucketIndex,
    _In_ ULONG64 listHeadAddress
    )
{
    LIST_ENTRY headLinks;
    ULONG64 currentAddress = 0ULL;
    ULONG64 expectedBackLink = listHeadAddress;
    ULONG traversalCount = 0UL;

    RtlZeroMemory(&headLinks, sizeof(headLinks));
    if (!kswordArkTimerDpcReadMemory(listHeadAddress, &headLinks, sizeof(headLinks))) {
        kswordArkTimerDpcMarkReadFailure(builder, TRUE);
        return TRUE;
    }

    currentAddress = (ULONG64)(ULONG_PTR)headLinks.Flink;
    if (currentAddress == listHeadAddress) {
        return TRUE;
    }
    if (!kswordArkTimerDpcIsKernelAddress(currentAddress)) {
        kswordArkTimerDpcMarkReadFailure(builder, TRUE);
        return TRUE;
    }

    while (currentAddress != listHeadAddress) {
        LIST_ENTRY currentLinks;
        ULONG64 timerAddress = 0ULL;
        ULONG64 nextAddress = 0ULL;

        if (builder->seenCount >= builder->maxEntries) {
            builder->response->statusFlags |=
                KSWORD_ARK_TIMER_DPC_STATUS_PARTIAL |
                KSWORD_ARK_TIMER_DPC_STATUS_TRUNCATED;
            return FALSE;
        }
        if (traversalCount >= builder->maxEntriesPerBucket) {
            builder->response->corruptBucketCount += 1UL;
            builder->response->statusFlags |=
                KSWORD_ARK_TIMER_DPC_STATUS_PARTIAL |
                KSWORD_ARK_TIMER_DPC_STATUS_TRUNCATED |
                KSWORD_ARK_TIMER_DPC_STATUS_CORRUPT_CHAIN;
            return TRUE;
        }

        RtlZeroMemory(&currentLinks, sizeof(currentLinks));
        if (!kswordArkTimerDpcReadMemory(currentAddress, &currentLinks, sizeof(currentLinks))) {
            kswordArkTimerDpcMarkReadFailure(builder, TRUE);
            return TRUE;
        }
        if ((ULONG64)(ULONG_PTR)currentLinks.Blink != expectedBackLink ||
            currentAddress < (ULONG64)builder->layout.timerTimerListEntry) {
            kswordArkTimerDpcMarkReadFailure(builder, TRUE);
            return TRUE;
        }

        timerAddress = currentAddress - (ULONG64)builder->layout.timerTimerListEntry;
        if (!kswordArkTimerDpcIsKernelAddress(timerAddress)) {
            kswordArkTimerDpcMarkReadFailure(builder, TRUE);
            return TRUE;
        }
        if (!kswordArkTimerDpcAlreadySeen(builder, timerAddress)) {
            kswordArkTimerDpcEmitTimer(
                builder,
                processorGroup,
                processorNumber,
                bucketIndex,
                timerAddress);
        }

        nextAddress = (ULONG64)(ULONG_PTR)currentLinks.Flink;
        if (nextAddress != listHeadAddress &&
            (!kswordArkTimerDpcIsKernelAddress(nextAddress) || nextAddress == currentAddress)) {
            kswordArkTimerDpcMarkReadFailure(builder, TRUE);
            return TRUE;
        }
        expectedBackLink = currentAddress;
        currentAddress = nextAddress;
        traversalCount += 1UL;
    }
    return TRUE;
}

NTSTATUS
kswordArkDriverEnumerateTimerDpc(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_ENUM_TIMER_DPC_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
{
    KSWORD_ARK_ENUM_TIMER_DPC_REQUEST requestCopy;
    KswTimerDpcBuilder builder;
    ULONG bucketCount = 0UL;
    ULONG activeProcessorCount = 0UL;
    ULONG processorIndex = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (outputBuffer == NULL || bytesWrittenOut == NULL ||
        outputBufferLength < KSWORD_ARK_ENUM_TIMER_DPC_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    *bytesWrittenOut = 0U;
    RtlZeroMemory(&requestCopy, sizeof(requestCopy));
    requestCopy.version = KSWORD_ARK_TIMER_DPC_PROTOCOL_VERSION;
    requestCopy.maxEntries = KSWORD_ARK_TIMER_DPC_DEFAULT_MAX_ENTRIES;
    requestCopy.maxEntriesPerBucket = KSWORD_ARK_TIMER_DPC_DEFAULT_BUCKET_BUDGET;
    if (request != NULL) {
        requestCopy = *request;
    }
    if (requestCopy.version != KSWORD_ARK_TIMER_DPC_PROTOCOL_VERSION) {
        return STATUS_REVISION_MISMATCH;
    }
    if (requestCopy.maxEntries == 0UL || requestCopy.maxEntries > KSWORD_ARK_TIMER_DPC_MAX_ENTRIES) {
        requestCopy.maxEntries = KSWORD_ARK_TIMER_DPC_DEFAULT_MAX_ENTRIES;
    }
    if (requestCopy.maxEntriesPerBucket == 0UL ||
        requestCopy.maxEntriesPerBucket > KSWORD_ARK_TIMER_DPC_MAX_BUCKET_BUDGET) {
        requestCopy.maxEntriesPerBucket = KSWORD_ARK_TIMER_DPC_DEFAULT_BUCKET_BUDGET;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    RtlZeroMemory(&builder, sizeof(builder));
    builder.response = (KSWORD_ARK_ENUM_TIMER_DPC_RESPONSE*)outputBuffer;
    builder.outputBufferLength = outputBufferLength;
    builder.capacity = (ULONG)((outputBufferLength - KSWORD_ARK_ENUM_TIMER_DPC_RESPONSE_HEADER_SIZE) /
        sizeof(KSWORD_ARK_TIMER_DPC_ENTRY));
    builder.maxEntries = requestCopy.maxEntries;
    builder.maxEntriesPerBucket = requestCopy.maxEntriesPerBucket;
    builder.response->version = KSWORD_ARK_TIMER_DPC_PROTOCOL_VERSION;
    builder.response->queryStatus = KSWORD_ARK_TIMER_DPC_QUERY_STATUS_OK;
    builder.response->entrySize = sizeof(KSWORD_ARK_TIMER_DPC_ENTRY);

#if !defined(_M_AMD64) && !defined(_M_X64)
    builder.Response->queryStatus = KSWORD_ARK_TIMER_DPC_QUERY_STATUS_NOT_SUPPORTED;
    builder.Response->lastStatus = STATUS_NOT_SUPPORTED;
    *BytesWrittenOut = KSWORD_ARK_ENUM_TIMER_DPC_RESPONSE_HEADER_SIZE;
    return STATUS_SUCCESS;
#else
    status = kswordArkDynDataV4SnapshotTimerDpcLayout(&builder.layout);
    if (!NT_SUCCESS(status)) {
        status = kswordArkTimerDpcResolveRuntimeLayout(&builder.layout);
    }
    if (!NT_SUCCESS(status)) {
        builder.response->queryStatus = KSWORD_ARK_TIMER_DPC_QUERY_STATUS_DYNDATA_MISSING;
        builder.response->statusFlags = KSWORD_ARK_TIMER_DPC_STATUS_DYNDATA_MISSING;
        builder.response->lastStatus = status;
        *bytesWrittenOut = KSWORD_ARK_ENUM_TIMER_DPC_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }
    if (!kswordArkTimerDpcLayoutValid(&builder.layout, &bucketCount)) {
        builder.response->queryStatus = KSWORD_ARK_TIMER_DPC_QUERY_STATUS_INVALID_LAYOUT;
        builder.response->lastStatus = STATUS_DATA_ERROR;
        *bytesWrittenOut = KSWORD_ARK_ENUM_TIMER_DPC_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }
    builder.response->bucketCount = bucketCount;

    builder.seenTimers = (ULONG64*)kswordArkAllocateNonPagedPool(
        (SIZE_T)builder.maxEntries * sizeof(ULONG64),
        KSW_TIMER_DPC_POOL_TAG);
    if (builder.seenTimers == NULL) {
        builder.response->queryStatus = KSWORD_ARK_TIMER_DPC_QUERY_STATUS_PARTIAL;
        builder.response->statusFlags = KSWORD_ARK_TIMER_DPC_STATUS_PARTIAL;
        builder.response->lastStatus = STATUS_INSUFFICIENT_RESOURCES;
        *bytesWrittenOut = KSWORD_ARK_ENUM_TIMER_DPC_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }
    RtlZeroMemory(builder.seenTimers, (SIZE_T)builder.maxEntries * sizeof(ULONG64));

    activeProcessorCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    for (processorIndex = 0UL; processorIndex < activeProcessorCount; ++processorIndex) {
        PROCESSOR_NUMBER processorNumber;
        GROUP_AFFINITY targetAffinity;
        GROUP_AFFINITY previousAffinity;
        ULONG64 prcbAddress = 0ULL;
        ULONG64 timerTableAddress = 0ULL;
        ULONG bucketIndex = 0UL;
        BOOLEAN continueProcessors = TRUE;

        RtlZeroMemory(&processorNumber, sizeof(processorNumber));
        if (!NT_SUCCESS(KeGetProcessorNumberFromIndex(processorIndex, &processorNumber)) ||
            processorNumber.Number >= (sizeof(KAFFINITY) * 8UL)) {
            kswordArkTimerDpcMarkReadFailure(&builder, FALSE);
            continue;
        }

        RtlZeroMemory(&targetAffinity, sizeof(targetAffinity));
        RtlZeroMemory(&previousAffinity, sizeof(previousAffinity));
        targetAffinity.Group = processorNumber.Group;
        targetAffinity.Mask = ((KAFFINITY)1) << processorNumber.Number;
        KeSetSystemGroupAffinityThread(&targetAffinity, &previousAffinity);
        __try {
            prcbAddress = (ULONG64)(ULONG_PTR)KeGetPcr()->CurrentPrcb;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            prcbAddress = 0ULL;
        }

        if (!kswordArkTimerDpcIsKernelAddress(prcbAddress) ||
            !kswordArkTimerDpcAddAddress(prcbAddress, builder.layout.kprcbTimerTable, &timerTableAddress)) {
            kswordArkTimerDpcMarkReadFailure(&builder, FALSE);
        }
        else {
            builder.response->processorCount += 1UL;
            for (bucketIndex = 0UL; bucketIndex < bucketCount; ++bucketIndex) {
                ULONG64 bucketOffset =
                    (ULONG64)builder.layout.timerTableTimerEntries +
                    ((ULONG64)bucketIndex * (ULONG64)builder.layout.timerTableEntryTypeSize) +
                    (ULONG64)builder.layout.timerTableEntryEntry;
                ULONG64 listHeadAddress = 0ULL;

                if (bucketOffset > MAXULONG ||
                    !kswordArkTimerDpcAddAddress(timerTableAddress, (ULONG)bucketOffset, &listHeadAddress)) {
                    kswordArkTimerDpcMarkReadFailure(&builder, TRUE);
                    break;
                }
                builder.response->bucketsVisited += 1UL;
                continueProcessors = kswordArkTimerDpcEnumerateBucket(
                    &builder,
                    processorNumber.Group,
                    processorNumber.Number,
                    bucketIndex,
                    listHeadAddress);
                if (!continueProcessors) {
                    break;
                }
            }
        }
        KeRevertToUserGroupAffinityThread(&previousAffinity);
        if (!continueProcessors) {
            break;
        }
    }

    ExFreePoolWithTag(builder.seenTimers, KSW_TIMER_DPC_POOL_TAG);
    builder.seenTimers = NULL;
    if (builder.response->statusFlags != 0UL) {
        builder.response->queryStatus = KSWORD_ARK_TIMER_DPC_QUERY_STATUS_PARTIAL;
    }
    builder.response->lastStatus = STATUS_SUCCESS;
    *bytesWrittenOut = KSWORD_ARK_ENUM_TIMER_DPC_RESPONSE_HEADER_SIZE +
        ((SIZE_T)builder.response->returnedCount * sizeof(KSWORD_ARK_TIMER_DPC_ENTRY));
    return STATUS_SUCCESS;
#endif
}
