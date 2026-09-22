/*++

Module Name:

    work_queue_fallback.c

Abstract:

    Runtime-signature fallback for Ex worker queues.  ExQueueWorkItem is the
    stable entry anchor.  The resolver validates the partition pointer chain,
    every live node queue, all priority list heads, public WORK_QUEUE_ITEM
    fields, the ETHREAD queue pointer and the ETHREAD start address across
    referenced System threads.  No fixed private Windows offsets are used and
    no PDB profile is required.

Environment:

    Kernel mode, PASSIVE_LEVEL read-only query path.

--*/

#include "ark/ark_dyndata.h"
#include "work_queue_fallback.h"
#include "../../platform/runtime_signature_scan.h"
#include "../../platform/pool_compat.h"

#define KSW_WORK_QUEUE_FALLBACK_TAG 'qWsK'
#define KSW_WORK_QUEUE_FALLBACK_MAX_REFERENCES 256UL
#define KSW_WORK_QUEUE_FALLBACK_SCAN_BYTES 0x0800UL
#define KSW_WORK_QUEUE_FALLBACK_PARTITION_SCAN 0x0100UL
#define KSW_WORK_QUEUE_FALLBACK_QUEUE_SCAN 0x0100UL
#define KSW_WORK_QUEUE_FALLBACK_MAX_POOL_INDEX 8UL
// Self-descriptive field window after the priority-linked list array: the queue's own partition back-reference and queue index both reside here.
#define KSW_WORK_QUEUE_FALLBACK_TAIL_SCAN 0x0180UL
#define KSW_WORK_QUEUE_FALLBACK_MAX_NODES 64UL
#define KSW_WORK_QUEUE_FALLBACK_PRIORITY_COUNT 32UL
#define KSW_WORK_QUEUE_FALLBACK_THREAD_SCAN 0x0800UL
#define KSW_WORK_QUEUE_FALLBACK_MAX_THREADS 512UL
#define KSW_WORK_QUEUE_FALLBACK_WORKER_SAMPLES 8UL
#define KSW_WORK_QUEUE_FALLBACK_SYSTEM_PROCESS_ID 4UL
#define KSW_WORK_QUEUE_FALLBACK_PROCESS_INFORMATION_CLASS 5UL
#define KSW_WORK_QUEUE_FALLBACK_SNAPSHOT_SLACK (64UL * 1024UL)
#define KSW_WORK_QUEUE_FALLBACK_SNAPSHOT_LIMIT (32UL * 1024UL * 1024UL)
// Criteria for the starting address offset: All worker threads must obtain the same value at this offset, which must fall within
// the ntoskrnl executable section (i.e., ExpWorkerThread). Additionally, the offset must exhibit sufficient variance across the
// entire sample set to exclude scenarios where all System threads share a single constant or various pool pointer fields.
#define KSW_WORK_QUEUE_FALLBACK_START_MIN_SAMPLES 8UL
#define KSW_WORK_QUEUE_FALLBACK_START_MIN_DISTINCT 3UL
#define KSW_WORK_QUEUE_FALLBACK_START_MIN_WORKERS 2UL
#define KSW_WORK_QUEUE_FALLBACK_START_DISTINCT_SLOTS 4UL

typedef PETHREAD(NTAPI* KswWorkQueueFallbackNextThreadFn)(
    _In_ PEPROCESS process,
    _In_opt_ PETHREAD thread
    );

typedef struct KswWorkQueueFallbackThreadInformation
{
    LARGE_INTEGER kernelTime;
    LARGE_INTEGER userTime;
    LARGE_INTEGER createTime;
    ULONG waitTime;
    PVOID startAddress;
    CLIENT_ID clientId;
    KPRIORITY priority;
    LONG basePriority;
    ULONG contextSwitches;
    ULONG threadState;
    ULONG waitReason;
} KswWorkQueueFallbackThreadInformation;

typedef struct KswWorkQueueFallbackProcessInformation
{
    ULONG nextEntryOffset;
    ULONG numberOfThreads;
    UCHAR reserved1[48];
    UNICODE_STRING imageName;
    KPRIORITY basePriority;
    HANDLE uniqueProcessId;
    PVOID reserved2;
    ULONG handleCount;
    ULONG sessionId;
    PVOID reserved3;
    SIZE_T peakVirtualSize;
    SIZE_T virtualSize;
    ULONG reserved4;
    SIZE_T peakWorkingSetSize;
    SIZE_T workingSetSize;
    PVOID reserved5;
    SIZE_T quotaPagedPoolUsage;
    PVOID reserved6;
    SIZE_T quotaNonPagedPoolUsage;
    SIZE_T pagefileUsage;
    SIZE_T peakPagefileUsage;
    SIZE_T privatePageCount;
    LARGE_INTEGER reserved7[6];
    KswWorkQueueFallbackThreadInformation threads[1];
} KswWorkQueueFallbackProcessInformation;

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ ULONG systemInformationClass,
    _Out_writes_bytes_opt_(systemInformationLength) PVOID systemInformation,
    _In_ ULONG systemInformationLength,
    _Out_opt_ PULONG returnLength
    );

NTKERNELAPI
NTSTATUS
PsLookupThreadByThreadId(
    _In_ HANDLE threadId,
    _Outptr_ PETHREAD* thread
    );

// Accumulator for evidence of each candidate offset. One slot per pointer width within the ETHREAD scan window.
typedef struct KswWorkQueueFallbackSlotStats
{
    ULONG queueMatches;
    ULONG zeroValues;
    ULONG startMatches;
    ULONG startMismatches;
    ULONG workerSamples;
    ULONG distinctCount;
    BOOLEAN workerConflict;
    ULONG64 workerValue;
    ULONG64 distinctValues[KSW_WORK_QUEUE_FALLBACK_START_DISTINCT_SLOTS];
} KswWorkQueueFallbackSlotStats;

typedef struct KswWorkQueueChain
{
    ULONG_PTR partitionGlobal;
    ULONG partitionExPartition;
    ULONG exPartitionWorkQueues;
    ULONG poolIndex;
    ULONG priQueueOffset;
    ULONG partitionBackOffset;
    ULONG queueIndexOffset;
    ULONG nodeCount;
    ULONG validationScore;
    ULONG_PTR queueAddresses[KSW_WORK_QUEUE_FALLBACK_MAX_NODES];
} KswWorkQueueChain, *PkswWorkQueueChain;

extern NTKERNELAPI PEPROCESS PsInitialSystemProcess;

static KswWorkQueueFallbackNextThreadFn
KswordARKWorkQueueFallbackResolveNextThread(
    VOID
    )
/*++

Routine Description:

    Probe the public process-thread walker.  Current kernels do not export it,
    so callers must treat NULL as "use the TID snapshot path" instead of as a
    hard failure.

--*/
{
    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, L"PsGetNextProcessThread");
    return (KswWorkQueueFallbackNextThreadFn)
        MmGetSystemRoutineAddress(&routineName);
}

static NTSTATUS
kswordArkWorkQueueFallbackCaptureProcessSnapshot(
    _Outptr_result_maybenull_ PVOID* snapshotOut,
    _Out_ ULONG* snapshotBytesOut
    )
/*++

Routine Description:

    Capture one SystemProcessInformation snapshot with a bounded grow-retry.

Return Value:

    STATUS_SUCCESS with a pool block the caller frees, otherwise a query status.

--*/
{
    ULONG requiredBytes = 0UL;
    ULONG attempt = 0UL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    if (snapshotOut == NULL || snapshotBytesOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *snapshotOut = NULL;
    *snapshotBytesOut = 0UL;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    status = ZwQuerySystemInformation(
        KSW_WORK_QUEUE_FALLBACK_PROCESS_INFORMATION_CLASS,
        NULL,
        0UL,
        &requiredBytes);
    if (requiredBytes < sizeof(KswWorkQueueFallbackProcessInformation)) {
        requiredBytes = sizeof(KswWorkQueueFallbackProcessInformation);
    }

    for (attempt = 0UL; attempt < 4UL; ++attempt) {
        PVOID snapshot = NULL;
        ULONG allocationBytes = 0UL;
        ULONG returnedBytes = 0UL;

        if (requiredBytes >
            KSW_WORK_QUEUE_FALLBACK_SNAPSHOT_LIMIT -
                KSW_WORK_QUEUE_FALLBACK_SNAPSHOT_SLACK) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        allocationBytes = requiredBytes + KSW_WORK_QUEUE_FALLBACK_SNAPSHOT_SLACK;
        snapshot = kswordArkAllocateNonPagedPool(
            allocationBytes,
            KSW_WORK_QUEUE_FALLBACK_TAG);
        if (snapshot == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(snapshot, allocationBytes);

        status = ZwQuerySystemInformation(
            KSW_WORK_QUEUE_FALLBACK_PROCESS_INFORMATION_CLASS,
            snapshot,
            allocationBytes,
            &returnedBytes);
        if (NT_SUCCESS(status)) {
            if (returnedBytes == 0UL || returnedBytes > allocationBytes) {
                returnedBytes = allocationBytes;
            }
            *snapshotOut = snapshot;
            *snapshotBytesOut = returnedBytes;
            return STATUS_SUCCESS;
        }

        ExFreePoolWithTag(snapshot, KSW_WORK_QUEUE_FALLBACK_TAG);
        if (status != STATUS_INFO_LENGTH_MISMATCH &&
            status != STATUS_BUFFER_TOO_SMALL) {
            return status;
        }
        requiredBytes = returnedBytes > allocationBytes
            ? returnedBytes
            : allocationBytes;
    }
    return status;
}

NTSTATUS
kswordArkWorkQueueCaptureSystemThreads(
    _Out_ KswWorkQueueSystemThreadSnapshot* snapshotOut
    )
/*++

Routine Description:

    Build the bounded System(PID 4) TID / StartAddress table.  The kernel does
    not export a process-thread walker, so this table is what lets the work
    queue path reach Object Manager referenced ETHREADs without a PDB profile.

Return Value:

    STATUS_SUCCESS with at least one row, otherwise a fail-closed status.

--*/
{
    PVOID processSnapshot = NULL;
    ULONG processSnapshotBytes = 0UL;
    ULONG processOffset = 0UL;
    KswWorkQueueSystemThread* entries = NULL;
    ULONG count = 0UL;
    BOOLEAN truncated = FALSE;
    BOOLEAN found = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (snapshotOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(snapshotOut, sizeof(*snapshotOut));

    status = kswordArkWorkQueueFallbackCaptureProcessSnapshot(
        &processSnapshot,
        &processSnapshotBytes);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    entries = (KswWorkQueueSystemThread*)kswordArkAllocateNonPagedPool(
        KSW_WORK_QUEUE_SYSTEM_THREAD_MAX * sizeof(*entries),
        KSW_WORK_QUEUE_FALLBACK_TAG);
    if (entries == NULL) {
        ExFreePoolWithTag(processSnapshot, KSW_WORK_QUEUE_FALLBACK_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(entries, KSW_WORK_QUEUE_SYSTEM_THREAD_MAX * sizeof(*entries));

    while (processOffset < processSnapshotBytes && !found) {
        const KswWorkQueueFallbackProcessInformation* processInfo =
            (const KswWorkQueueFallbackProcessInformation*)
                ((const UCHAR*)processSnapshot + processOffset);
        ULONG remainingBytes = processSnapshotBytes - processOffset;
        ULONG entryBytes = 0UL;
        ULONG threadCapacity = 0UL;
        ULONG threadCount = 0UL;
        ULONG threadIndex = 0UL;

        if (remainingBytes <
            (ULONG)FIELD_OFFSET(
                KswWorkQueueFallbackProcessInformation,
                threads)) {
            break;
        }
        entryBytes = processInfo->nextEntryOffset != 0UL
            ? processInfo->nextEntryOffset
            : remainingBytes;
        if (entryBytes >
                remainingBytes ||
            entryBytes <
                (ULONG)FIELD_OFFSET(
                    KswWorkQueueFallbackProcessInformation,
                    threads)) {
            break;
        }
        if (HandleToULong(processInfo->uniqueProcessId) !=
            KSW_WORK_QUEUE_FALLBACK_SYSTEM_PROCESS_ID) {
            if (processInfo->nextEntryOffset == 0UL) {
                break;
            }
            processOffset += processInfo->nextEntryOffset;
            continue;
        }

        found = TRUE;
        threadCapacity = (entryBytes -
            (ULONG)FIELD_OFFSET(
                KswWorkQueueFallbackProcessInformation,
                threads)) /
            (ULONG)sizeof(KswWorkQueueFallbackThreadInformation);
        threadCount = processInfo->numberOfThreads;
        if (threadCount > threadCapacity) {
            threadCount = threadCapacity;
            truncated = TRUE;
        }
        for (threadIndex = 0UL; threadIndex < threadCount; ++threadIndex) {
            const KswWorkQueueFallbackThreadInformation* threadInfo =
                &processInfo->threads[threadIndex];
            ULONG threadId = HandleToULong(threadInfo->clientId.UniqueThread);

            if (threadId == 0UL ||
                HandleToULong(threadInfo->clientId.UniqueProcess) !=
                    KSW_WORK_QUEUE_FALLBACK_SYSTEM_PROCESS_ID) {
                continue;
            }
            if (count >= KSW_WORK_QUEUE_SYSTEM_THREAD_MAX) {
                truncated = TRUE;
                break;
            }
            entries[count].threadId = threadId;
            entries[count].startAddress =
                (ULONG64)(ULONG_PTR)threadInfo->startAddress;
            count += 1UL;
        }
    }

    ExFreePoolWithTag(processSnapshot, KSW_WORK_QUEUE_FALLBACK_TAG);
    if (count == 0UL) {
        ExFreePoolWithTag(entries, KSW_WORK_QUEUE_FALLBACK_TAG);
        return STATUS_NOT_FOUND;
    }
    snapshotOut->entries = entries;
    snapshotOut->count = count;
    snapshotOut->truncated = truncated;
    return STATUS_SUCCESS;
}

VOID
kswordArkWorkQueueReleaseSystemThreads(
    _Inout_ KswWorkQueueSystemThreadSnapshot* snapshot
    )
{
    if (snapshot == NULL) {
        return;
    }
    if (snapshot->entries != NULL) {
        ExFreePoolWithTag(snapshot->entries, KSW_WORK_QUEUE_FALLBACK_TAG);
    }
    RtlZeroMemory(snapshot, sizeof(*snapshot));
}

VOID
kswordArkWorkQueueInitializeThreadWalker(
    _Out_ KswWorkQueueThreadWalker* walker,
    _In_opt_ const KswWorkQueueSystemThreadSnapshot* snapshot
    )
{
    if (walker == NULL) {
        return;
    }
    RtlZeroMemory(walker, sizeof(*walker));
    if (PsInitialSystemProcess != NULL) {
        walker->nextProcessThread =
            KswordARKWorkQueueFallbackResolveNextThread();
    }
    if (snapshot != NULL && snapshot->entries != NULL && snapshot->count != 0UL) {
        walker->snapshot = snapshot;
    }
}

BOOLEAN
kswordArkWorkQueueThreadWalkerUsable(
    _In_ const KswWorkQueueThreadWalker* walker
    )
{
    return walker != NULL &&
        (walker->nextProcessThread != NULL || walker->snapshot != NULL);
}

PETHREAD
kswordArkWorkQueueThreadWalkerNext(
    _Inout_ KswWorkQueueThreadWalker* walker
    )
/*++

Routine Description:

    Advance to the next referenced System thread.  The walker owns the returned
    reference and releases it on the next advance or on close.

Return Value:

    Referenced ETHREAD, or NULL when the walk is finished.

--*/
{
    PETHREAD previous = NULL;
    PETHREAD next = NULL;

    if (walker == NULL || walker->finished) {
        return NULL;
    }
    previous = walker->current;

    if (walker->nextProcessThread != NULL) {
        next = walker->nextProcessThread(PsInitialSystemProcess, previous);
        if (previous != NULL) {
            ObDereferenceObject(previous);
        }
    }
    else {
        if (previous != NULL) {
            ObDereferenceObject(previous);
        }
        while (walker->snapshot != NULL &&
               walker->nextIndex < walker->snapshot->count) {
            PETHREAD candidate = NULL;
            ULONG threadId = walker->snapshot->entries[walker->nextIndex].threadId;

            walker->nextIndex += 1UL;
            if (threadId == 0UL) {
                continue;
            }
            // The thread may exit between snapshot and lookup; simply skip it. Rows still in the table remain unaffected.
            if (NT_SUCCESS(PsLookupThreadByThreadId(
                    ULongToHandle(threadId),
                    &candidate)) &&
                candidate != NULL) {
                next = candidate;
                break;
            }
        }
    }

    walker->current = next;
    if (next == NULL) {
        walker->finished = TRUE;
    }
    return next;
}

VOID
kswordArkWorkQueueThreadWalkerClose(
    _Inout_ KswWorkQueueThreadWalker* walker
    )
{
    if (walker == NULL) {
        return;
    }
    if (walker->current != NULL) {
        ObDereferenceObject(walker->current);
        walker->current = NULL;
    }
    walker->finished = TRUE;
}

static ULONG64
kswordArkWorkQueueFallbackLookupStartAddress(
    _In_opt_ const KswWorkQueueSystemThreadSnapshot* snapshot,
    _In_ ULONG threadId
    )
{
    ULONG index = 0UL;

    if (snapshot == NULL || snapshot->entries == NULL || threadId == 0UL) {
        return 0ULL;
    }
    for (index = 0UL; index < snapshot->count; ++index) {
        if (snapshot->entries[index].threadId == threadId) {
            return snapshot->entries[index].startAddress;
        }
    }
    return 0ULL;
}

static BOOLEAN
kswordArkWorkQueueFallbackIsKernelAddress(
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
kswordArkWorkQueueFallbackReadPointer(
    _In_ ULONG_PTR address,
    _Out_ ULONG_PTR* valueOut
    )
{
    return valueOut != NULL &&
        kswordArkRuntimeReadMemory(
            (const VOID*)address,
            valueOut,
            sizeof(*valueOut));
}

static BOOLEAN
kswordArkWorkQueueFallbackValidateListHead(
    _In_ ULONG_PTR headAddress,
    _Out_opt_ BOOLEAN* nonEmptyOut
    )
{
    LIST_ENTRY head;
    LIST_ENTRY first;
    LIST_ENTRY last;

    if (nonEmptyOut != NULL) {
        *nonEmptyOut = FALSE;
    }
    RtlZeroMemory(&head, sizeof(head));
    RtlZeroMemory(&first, sizeof(first));
    RtlZeroMemory(&last, sizeof(last));
    if (!kswordArkWorkQueueFallbackIsKernelAddress(headAddress) ||
        !kswordArkRuntimeReadMemory(
            (const VOID*)headAddress,
            &head,
            sizeof(head)) ||
        head.Flink == NULL || head.Blink == NULL) {
        return FALSE;
    }
    if ((ULONG_PTR)head.Flink == headAddress ||
        (ULONG_PTR)head.Blink == headAddress) {
        return (ULONG_PTR)head.Flink == headAddress &&
            (ULONG_PTR)head.Blink == headAddress;
    }
    if (!kswordArkWorkQueueFallbackIsKernelAddress((ULONG_PTR)head.Flink) ||
        !kswordArkWorkQueueFallbackIsKernelAddress((ULONG_PTR)head.Blink) ||
        !kswordArkRuntimeReadMemory(head.Flink, &first, sizeof(first)) ||
        !kswordArkRuntimeReadMemory(head.Blink, &last, sizeof(last)) ||
        (ULONG_PTR)first.Blink != headAddress ||
        (ULONG_PTR)last.Flink != headAddress) {
        return FALSE;
    }
    if (nonEmptyOut != NULL) {
        *nonEmptyOut = TRUE;
    }
    return TRUE;
}

static BOOLEAN
kswordArkWorkQueueFallbackFindPriQueueOffset(
    _In_ ULONG_PTR queueAddress,
    _Out_ ULONG* offsetOut,
    _Out_ ULONG* scoreOut
    )
/*++

Routine Description:

    Locate the one array of 32 reciprocal priority list heads inside a live
    queue.

    The scan steps by one pointer while the array strides by one LIST_ENTRY,
    so a shape-only test always accepts two windows: the real EntryListHead
    array, and the window starting one pointer earlier, which pairs the
    preceding dispatcher-header wait list with the first 31 real heads. Both
    contain 32 reciprocal heads, so neither occupancy scoring nor a tie-break
    can separate them - the earlier window is not weaker evidence, it is an
    equally well-formed alias sitting exactly one pointer before the truth.

    The discriminator is the right edge: the real array must END. Probing one
    element past the window must fail, which is true only for the genuine
    array (whose successor field is a counter, not a list head). The aliased
    window's 33rd probe lands on the array's own last element and stays valid,
    so it is rejected. The left edge must never be used for this: the element
    before the real array is a valid list head, so a left-edge test would
    select the alias instead.

Return Value:

    TRUE only when exactly one window survives the right-edge test.

--*/
{
    ULONG candidateOffset = 0UL;
    ULONG bestOffset = 0UL;
    ULONG bestScore = 0UL;
    ULONG survivors = 0UL;

    if (offsetOut == NULL || scoreOut == NULL ||
        !kswordArkWorkQueueFallbackIsKernelAddress(queueAddress)) {
        return FALSE;
    }
    for (candidateOffset = 0UL;
         candidateOffset < KSW_WORK_QUEUE_FALLBACK_QUEUE_SCAN;
         candidateOffset += sizeof(PVOID)) {
        ULONG priorityIndex = 0UL;
        ULONG score = 0UL;
        ULONG_PTR tailAddress = 0U;
        BOOLEAN valid = TRUE;

        for (priorityIndex = 0UL;
             priorityIndex < KSW_WORK_QUEUE_FALLBACK_PRIORITY_COUNT;
             ++priorityIndex) {
            ULONG_PTR headAddress = queueAddress + candidateOffset +
                ((ULONG_PTR)priorityIndex * sizeof(LIST_ENTRY));
            BOOLEAN nonEmpty = FALSE;

            if (headAddress < queueAddress ||
                !kswordArkWorkQueueFallbackValidateListHead(
                    headAddress,
                    &nonEmpty)) {
                valid = FALSE;
                break;
            }
            score += nonEmpty ? 2UL : 1UL;
        }
        if (!valid) {
            continue;
        }
        tailAddress = queueAddress + candidateOffset +
            ((ULONG_PTR)KSW_WORK_QUEUE_FALLBACK_PRIORITY_COUNT *
             sizeof(LIST_ENTRY));
        if (tailAddress < queueAddress ||
            kswordArkWorkQueueFallbackValidateListHead(tailAddress, NULL)) {
            // Item 33 is still a valid list head, indicating this window does not end at the true end of the array.
            continue;
        }
        survivors += 1UL;
        bestOffset = candidateOffset;
        bestScore = score;
    }
    if (survivors != 1UL ||
        bestScore < KSW_WORK_QUEUE_FALLBACK_PRIORITY_COUNT) {
        return FALSE;
    }
    *offsetOut = bestOffset;
    *scoreOut = bestScore;
    return TRUE;
}

static BOOLEAN
kswordArkWorkQueueFallbackFindPartitionBackOffset(
    _In_ ULONG_PTR queueAddress,
    _In_ ULONG priQueueOffset,
    _In_ ULONG_PTR exPartition,
    _Out_ ULONG* offsetOut
    )
/*++

Routine Description:

    Find where the queue names its owning partition. Walking
    partition -> work queues -> queue only proves the forward direction; a
    lookalike global that happens to hold a plausible pointer chain would pass
    it. Requiring the queue to point back at the same partition object closes
    the loop, and the offset is discovered at runtime rather than assumed.

Return Value:

    TRUE when exactly one slot past the priority array holds ExPartition.

--*/
{
    ULONG offset = 0UL;
    ULONG found = 0UL;
    ULONG foundOffset = 0UL;
    const ULONG kArrayEnd = priQueueOffset +
        (KSW_WORK_QUEUE_FALLBACK_PRIORITY_COUNT * (ULONG)sizeof(LIST_ENTRY));

    if (offsetOut == NULL) {
        return FALSE;
    }
    *offsetOut = 0UL;
    for (offset = kArrayEnd;
         offset < kArrayEnd + KSW_WORK_QUEUE_FALLBACK_TAIL_SCAN;
         offset += sizeof(PVOID)) {
        ULONG_PTR value = 0U;

        if (!kswordArkWorkQueueFallbackReadPointer(
                queueAddress + offset,
                &value)) {
            continue;
        }
        if (value == exPartition) {
            found += 1UL;
            foundOffset = offset;
        }
    }
    if (found != 1UL) {
        return FALSE;
    }
    *offsetOut = foundOffset;
    return TRUE;
}

static BOOLEAN
kswordArkWorkQueueFallbackFindQueueIndexOffset(
    _In_ ULONG_PTR firstQueue,
    _In_ ULONG_PTR secondQueue,
    _In_ ULONG priQueueOffset,
    _Out_ ULONG* offsetOut
    )
/*++

Routine Description:

    Find where a queue records its own slot number, by requiring slot 0 to read
    back 0 and slot 1 to read back 1 at the same offset. Optional evidence: it
    lets the consumer re-check on live memory that it is walking the slot it
    thinks it is.

Return Value:

    TRUE when exactly one offset satisfies both queues.

--*/
{
    ULONG offset = 0UL;
    ULONG found = 0UL;
    ULONG foundOffset = 0UL;
    const ULONG kArrayEnd = priQueueOffset +
        (KSW_WORK_QUEUE_FALLBACK_PRIORITY_COUNT * (ULONG)sizeof(LIST_ENTRY));

    if (offsetOut == NULL) {
        return FALSE;
    }
    *offsetOut = 0UL;
    for (offset = kArrayEnd;
         offset < kArrayEnd + KSW_WORK_QUEUE_FALLBACK_TAIL_SCAN;
         offset += sizeof(ULONG)) {
        ULONG firstValue = 0UL;
        ULONG secondValue = 0UL;

        if (!kswordArkRuntimeReadMemory(
                (const VOID*)(firstQueue + offset),
                &firstValue,
                sizeof(firstValue)) ||
            !kswordArkRuntimeReadMemory(
                (const VOID*)(secondQueue + offset),
                &secondValue,
                sizeof(secondValue))) {
            continue;
        }
        if (firstValue == 0UL && secondValue == 1UL) {
            found += 1UL;
            foundOffset = offset;
        }
    }
    if (found != 1UL) {
        return FALSE;
    }
    *offsetOut = foundOffset;
    return TRUE;
}

static BOOLEAN
kswordArkWorkQueueFallbackValidateChainCandidate(
    _In_ ULONG_PTR partitionGlobal,
    _In_ ULONG partitionOffset,
    _In_ ULONG workQueuesOffset,
    _In_ ULONG poolIndex,
    _Out_ KswWorkQueueChain* chainOut
    )
{
    ULONG_PTR partition = 0U;
    ULONG_PTR exPartition = 0U;
    ULONG_PTR workQueues = 0U;
    ULONG nodeCount = (ULONG)KeQueryHighestNodeNumber() + 1UL;
    ULONG nodeIndex = 0UL;
    ULONG sharedPriQueueOffset = MAXULONG;
    ULONG sharedBackOffset = MAXULONG;
    ULONG queueIndexOffset = 0UL;
    ULONG totalScore = 0UL;
    KswWorkQueueChain candidate;

    if (chainOut == NULL || nodeCount == 0UL ||
        nodeCount > KSW_WORK_QUEUE_FALLBACK_MAX_NODES ||
        !kswordArkWorkQueueFallbackReadPointer(
            partitionGlobal,
            &partition) ||
        !kswordArkWorkQueueFallbackIsKernelAddress(partition) ||
        !kswordArkWorkQueueFallbackReadPointer(
            partition + partitionOffset,
            &exPartition) ||
        !kswordArkWorkQueueFallbackIsKernelAddress(exPartition) ||
        !kswordArkWorkQueueFallbackReadPointer(
            exPartition + workQueuesOffset,
            &workQueues) ||
        !kswordArkWorkQueueFallbackIsKernelAddress(workQueues)) {
        return FALSE;
    }
    RtlZeroMemory(&candidate, sizeof(candidate));
    for (nodeIndex = 0UL; nodeIndex < nodeCount; ++nodeIndex) {
        ULONG_PTR nodeQueueArray = 0U;
        ULONG_PTR queueAddress = 0U;
        ULONG priQueueOffset = 0UL;
        ULONG backOffset = 0UL;
        ULONG queueScore = 0UL;

        if (!kswordArkWorkQueueFallbackReadPointer(
                workQueues + ((ULONG_PTR)nodeIndex * sizeof(PVOID)),
                &nodeQueueArray) ||
            !kswordArkWorkQueueFallbackIsKernelAddress(nodeQueueArray) ||
            !kswordArkWorkQueueFallbackReadPointer(
                nodeQueueArray + ((ULONG_PTR)poolIndex * sizeof(PVOID)),
                &queueAddress) ||
            !kswordArkWorkQueueFallbackIsKernelAddress(queueAddress) ||
            !kswordArkWorkQueueFallbackFindPriQueueOffset(
                queueAddress,
                &priQueueOffset,
                &queueScore) ||
            (sharedPriQueueOffset != MAXULONG &&
             priQueueOffset != sharedPriQueueOffset) ||
            !kswordArkWorkQueueFallbackFindPartitionBackOffset(
                queueAddress,
                priQueueOffset,
                exPartition,
                &backOffset) ||
            (sharedBackOffset != MAXULONG && backOffset != sharedBackOffset)) {
            return FALSE;
        }
        sharedPriQueueOffset = priQueueOffset;
        sharedBackOffset = backOffset;
        candidate.queueAddresses[nodeIndex] = queueAddress;
        totalScore += queueScore;

        if (nodeIndex == 0UL &&
            poolIndex + 1UL < KSW_WORK_QUEUE_FALLBACK_MAX_POOL_INDEX) {
            ULONG_PTR siblingQueue = 0U;

            // The queue index is an optional additional piece of evidence; failure to resolve it does not block the link determination.
            if (kswordArkWorkQueueFallbackReadPointer(
                    nodeQueueArray +
                        ((ULONG_PTR)(poolIndex + 1UL) * sizeof(PVOID)),
                    &siblingQueue) &&
                kswordArkWorkQueueFallbackIsKernelAddress(siblingQueue)) {
                (VOID)kswordArkWorkQueueFallbackFindQueueIndexOffset(
                    queueAddress,
                    siblingQueue,
                    priQueueOffset,
                    &queueIndexOffset);
            }
        }
    }

    candidate.partitionGlobal = partitionGlobal;
    candidate.partitionExPartition = partitionOffset;
    candidate.exPartitionWorkQueues = workQueuesOffset;
    candidate.poolIndex = poolIndex;
    candidate.priQueueOffset = sharedPriQueueOffset;
    candidate.partitionBackOffset = sharedBackOffset;
    candidate.queueIndexOffset = queueIndexOffset;
    candidate.nodeCount = nodeCount;
    candidate.validationScore = totalScore;
    *chainOut = candidate;
    return TRUE;
}

static BOOLEAN
kswordArkWorkQueueFallbackChainsEqual(
    _In_ const KswWorkQueueChain* left,
    _In_ const KswWorkQueueChain* right
    )
/*++

Routine Description:

    Decide whether two candidates describe the same queues. Identity is the
    resolved result, not the description that produced it: two distinct globals
    both holding the same partition pointer reach the identical queue set and
    must not count as a contradiction, while candidates that reach different
    queues still do.

--*/
{
    ULONG nodeIndex = 0UL;

    if (left->nodeCount != right->nodeCount) {
        return FALSE;
    }
    for (nodeIndex = 0UL; nodeIndex < left->nodeCount; ++nodeIndex) {
        if (left->queueAddresses[nodeIndex] != right->queueAddresses[nodeIndex]) {
            return FALSE;
        }
    }
    return left->poolIndex == right->poolIndex &&
        left->priQueueOffset == right->priQueueOffset;
}

static BOOLEAN
kswordArkWorkQueueFallbackFindChain(
    _In_ const KswRuntimeImageView* view,
    _In_reads_(referenceCount) const KswRuntimeDataReference* references,
    _In_ ULONG referenceCount,
    _Out_ KswWorkQueueChain* chainOut,
    _Out_ BOOLEAN* ambiguousOut
    )
{
    KswWorkQueueChain best;
    ULONG bestScore = 0UL;
    BOOLEAN ambiguous = FALSE;
    ULONG referenceIndex = 0UL;

    if (ambiguousOut != NULL) {
        *ambiguousOut = FALSE;
    }
    if (view == NULL || references == NULL || chainOut == NULL) {
        return FALSE;
    }
    RtlZeroMemory(&best, sizeof(best));
    for (referenceIndex = 0UL; referenceIndex < referenceCount; ++referenceIndex) {
        ULONG_PTR partition = 0U;
        ULONG partitionOffset = 0UL;

        // The partition pointer is an invariant across the entire reference; read it once before entering the inner scan.
        if (!kswordArkRuntimeAddressIsWritableData(
                view,
                references[referenceIndex].address,
                sizeof(PVOID)) ||
            !kswordArkWorkQueueFallbackReadPointer(
                references[referenceIndex].address,
                &partition) ||
            !kswordArkWorkQueueFallbackIsKernelAddress(partition)) {
            continue;
        }
        for (partitionOffset = 0UL;
             partitionOffset < KSW_WORK_QUEUE_FALLBACK_PARTITION_SCAN;
             partitionOffset += sizeof(PVOID)) {
            ULONG_PTR exPartition = 0U;
            ULONG workQueuesOffset = 0UL;

            if (!kswordArkWorkQueueFallbackReadPointer(
                    partition + partitionOffset,
                    &exPartition) ||
                !kswordArkWorkQueueFallbackIsKernelAddress(exPartition)) {
                continue;
            }
            for (workQueuesOffset = 0UL;
                 workQueuesOffset < KSW_WORK_QUEUE_FALLBACK_PARTITION_SCAN;
                 workQueuesOffset += sizeof(PVOID)) {
                ULONG_PTR workQueues = 0U;
                KswWorkQueueChain candidate;

                if (!kswordArkWorkQueueFallbackReadPointer(
                        exPartition + workQueuesOffset,
                        &workQueues) ||
                    !kswordArkWorkQueueFallbackIsKernelAddress(workQueues)) {
                    continue;
                }

                /*
                 * Pool indices are excluded from the search. ExPoolUntrusted corresponds to index 0 of _EXQUEUEINDEX; it represents an
                 * array subscript semantics rather than a private offset requiring inference. Including it in the same scoring logic would
                 * cause two already-allocated queues to be misidentified as ambiguous, while the scoring itself provides zero information
                 * regarding 'which slot is correct'. Selecting the wrong slot would silently produce evidence with incorrect labels;
                 * therefore, index 0 is fixed here. If validation fails, the operation is fail-closed without attempting alternative slots.
                 */
                RtlZeroMemory(&candidate, sizeof(candidate));
                if (!kswordArkWorkQueueFallbackValidateChainCandidate(
                        references[referenceIndex].address,
                        partitionOffset,
                        workQueuesOffset,
                        0UL,
                        &candidate) ||
                    candidate.validationScore < bestScore) {
                    continue;
                }
                if (candidate.validationScore == bestScore &&
                    bestScore != 0UL &&
                    !kswordArkWorkQueueFallbackChainsEqual(
                        &candidate,
                        &best)) {
                    ambiguous = TRUE;
                    continue;
                }
                /*
                 * The ambiguity flag must remain set; only a candidate with a strictly higher score may clear it.
                 * ChainsEqual only compares parsed results; the same batch of queues can be hit repeatedly by
                 * multiple candidates. If tied candidates also clear the score, the previously recorded 'another tied
                 * contradictory chain' is erased, causing the fail-closed gate for uniqueness validation to fail.
                 */
                if (candidate.validationScore > bestScore) {
                    ambiguous = FALSE;
                }
                best = candidate;
                bestScore = candidate.validationScore;
            }
        }
    }
    if (ambiguousOut != NULL) {
        *ambiguousOut = ambiguous;
    }
    if (bestScore == 0UL || ambiguous) {
        return FALSE;
    }
    *chainOut = best;
    return TRUE;
}

static BOOLEAN
kswordArkWorkQueueFallbackFindPriorityIndexes(
    _In_ const KswRuntimeImageView* view,
    _Out_writes_(3) ULONG* priorityIndexesOut
    )
/*++

Routine Description:

    Recover ExpBuiltinPriorities from an RVA displacement embedded in the
    bounded ExQueueWorkItem code.  The array must contain seven bounded values
    and the three supported built-in queues must map to distinct priorities.

Return Value:

    TRUE only for one matching array.

--*/
{
    ULONG_PTR routine = 0U;
    ULONG offset = 0UL;
    ULONG_PTR foundAddress = 0U;
    ULONG foundValues[3] = { 0UL, 0UL, 0UL };

    if (view == NULL || priorityIndexesOut == NULL) {
        return FALSE;
    }
    routine = (ULONG_PTR)kswordArkRuntimeFindExport(view, "ExQueueWorkItem");
    if (routine == 0U) {
        return FALSE;
    }
    for (offset = 0UL; offset + sizeof(ULONG) <=
             KSW_WORK_QUEUE_FALLBACK_SCAN_BYTES; ++offset) {
        ULONG candidateRva = 0UL;
        ULONG values[7];
        ULONG index = 0UL;
        ULONG_PTR candidateAddress = 0U;
        BOOLEAN valid = TRUE;

        RtlZeroMemory(values, sizeof(values));
        if (!kswordArkRuntimeAddressIsExecutable(
                view,
                routine + offset,
                sizeof(candidateRva)) ||
            !kswordArkRuntimeReadMemory(
                (const VOID*)(routine + offset),
                &candidateRva,
                sizeof(candidateRva)) ||
            candidateRva >= view->size ||
            view->base > MAXULONG_PTR - candidateRva) {
            continue;
        }
        candidateAddress = view->base + candidateRva;
        if ((candidateAddress & (sizeof(ULONG) - 1U)) != 0U ||
            !kswordArkRuntimeAddressInImage(
                view,
                candidateAddress,
                sizeof(values)) ||
            kswordArkRuntimeAddressIsExecutable(view, candidateAddress, 1U) ||
            !kswordArkRuntimeReadMemory(
                (const VOID*)candidateAddress,
                values,
                sizeof(values))) {
            continue;
        }
        for (index = 0UL; index < RTL_NUMBER_OF(values); ++index) {
            if (values[index] >= KSW_WORK_QUEUE_FALLBACK_PRIORITY_COUNT) {
                valid = FALSE;
                break;
            }
        }
        if (!valid || values[0] == values[1] || values[0] == values[2] ||
            values[1] == values[2]) {
            continue;
        }
        if (foundAddress != 0U && foundAddress != candidateAddress) {
            return FALSE;
        }
        foundAddress = candidateAddress;
        foundValues[0] = values[0];
        foundValues[1] = values[1];
        foundValues[2] = values[2];
    }
    if (foundAddress == 0U) {
        return FALSE;
    }
    priorityIndexesOut[0] = foundValues[0];
    priorityIndexesOut[1] = foundValues[1];
    priorityIndexesOut[2] = foundValues[2];
    return TRUE;
}

static BOOLEAN
kswordArkWorkQueueFallbackQueueAddressMatches(
    _In_ ULONG_PTR value,
    _In_ const KswWorkQueueChain* chain
    )
{
    ULONG nodeIndex = 0UL;

    for (nodeIndex = 0UL; nodeIndex < chain->nodeCount; ++nodeIndex) {
        if (value == chain->queueAddresses[nodeIndex]) {
            return TRUE;
        }
    }
    return FALSE;
}

static VOID
kswordArkWorkQueueFallbackAccumulateSlot(
    _Inout_ KswWorkQueueFallbackSlotStats* slot,
    _In_ ULONG64 value,
    _In_ BOOLEAN workerLike,
    _In_ ULONG64 expectedStart
    )
/*++

Routine Description:

    Fold one thread's value at one candidate offset into that offset's evidence.

Return Value:

    None.

--*/
{
    ULONG index = 0UL;

    if (value == 0ULL) {
        slot->zeroValues += 1UL;
    }
    if (slot->distinctCount < KSW_WORK_QUEUE_FALLBACK_START_DISTINCT_SLOTS) {
        for (index = 0UL; index < slot->distinctCount; ++index) {
            if (slot->distinctValues[index] == value) {
                break;
            }
        }
        if (index == slot->distinctCount) {
            slot->distinctValues[slot->distinctCount] = value;
            slot->distinctCount += 1UL;
        }
    }
    if (workerLike) {
        if (slot->workerSamples == 0UL) {
            slot->workerValue = value;
        }
        else if (slot->workerValue != value) {
            slot->workerConflict = TRUE;
        }
        slot->workerSamples += 1UL;
    }
    if (expectedStart != 0ULL) {
        if (value == expectedStart) {
            slot->startMatches += 1UL;
        }
        else {
            slot->startMismatches += 1UL;
        }
    }
}

static BOOLEAN
kswordArkWorkQueueFallbackInferThreadOffsets(
    _In_ const KswWorkQueueChain* chain,
    _In_ const KswRuntimeImageView* view,
    _In_opt_ const KswWorkQueueSystemThreadSnapshot* snapshot,
    _Out_ ULONG* queueOffsetOut,
    _Out_ ULONG* startAddressOffsetOut,
    _Out_ BOOLEAN* startAddressResolvedOut
    )
/*++

Routine Description:

    Infer _KTHREAD.Queue and _ETHREAD.StartAddress from live System threads in
    one walk.  Queue wins by unique strongest match against the queues the
    pointer chain already validated.

    StartAddress is derived without any stored description: at the real offset
    every Ex worker thread holds one identical value - ExpWorkerThread - which
    must land inside ntoskrnl's executable range, while the same offset must
    still vary across ordinary System threads.  Pool pointers (Queue, WaitBlock
    objects, EPROCESS), data-section pointers and per-process constants all
    fail one of those three tests, and ambiguity fails closed.

    SystemProcessInformation start addresses are folded in as an extra
    constraint when the kernel hands them out; they are only a strengthener
    because unprivileged-caller hardening can zero that field.

Return Value:

    TRUE when the queue offset resolved; StartAddressResolvedOut reports the
    start-address offset separately because it is only needed for thread rows.

--*/
{
    const ULONG kSlotCount =
        KSW_WORK_QUEUE_FALLBACK_THREAD_SCAN / (ULONG)sizeof(PVOID);
    KswWorkQueueThreadWalker walker;
    KswWorkQueueFallbackSlotStats* slots = NULL;
    ULONG_PTR* values = NULL;
    BOOLEAN* readable = NULL;
    UCHAR* block = NULL;
    SIZE_T blockBytes = 0U;
    PETHREAD thread = NULL;
    ULONG threadCount = 0UL;
    ULONG expectedStartSamples = 0UL;
    ULONG slot = 0UL;
    ULONG bestQueueCount = 0UL;
    ULONG bestQueueZeros = 0UL;
    LONG bestQueueOffset = -1;
    BOOLEAN queueTied = FALSE;
    LONG startOffset = -1;
    BOOLEAN startTied = FALSE;

    if (chain == NULL || view == NULL || queueOffsetOut == NULL ||
        startAddressOffsetOut == NULL || startAddressResolvedOut == NULL) {
        return FALSE;
    }
    *queueOffsetOut = 0UL;
    *startAddressOffsetOut = 0UL;
    *startAddressResolvedOut = FALSE;

    RtlZeroMemory(&walker, sizeof(walker));
    kswordArkWorkQueueInitializeThreadWalker(&walker, snapshot);
    if (!kswordArkWorkQueueThreadWalkerUsable(&walker)) {
        return FALSE;
    }

    blockBytes = ((SIZE_T)kSlotCount * sizeof(*slots)) +
        ((SIZE_T)kSlotCount * sizeof(*values)) +
        ((SIZE_T)kSlotCount * sizeof(*readable));
    block = (UCHAR*)kswordArkAllocateNonPagedPool(
        blockBytes,
        KSW_WORK_QUEUE_FALLBACK_TAG);
    if (block == NULL) {
        kswordArkWorkQueueThreadWalkerClose(&walker);
        return FALSE;
    }
    RtlZeroMemory(block, blockBytes);
    slots = (KswWorkQueueFallbackSlotStats*)block;
    values = (ULONG_PTR*)(block + ((SIZE_T)kSlotCount * sizeof(*slots)));
    readable = (BOOLEAN*)(((UCHAR*)values) +
        ((SIZE_T)kSlotCount * sizeof(*values)));

    thread = kswordArkWorkQueueThreadWalkerNext(&walker);
    while (thread != NULL && threadCount < KSW_WORK_QUEUE_FALLBACK_MAX_THREADS) {
        ULONG64 expectedStart = kswordArkWorkQueueFallbackLookupStartAddress(
            snapshot,
            HandleToULong(PsGetThreadId(thread)));
        BOOLEAN workerLike = FALSE;

        if (expectedStart != 0ULL &&
            !kswordArkWorkQueueFallbackIsKernelAddress(
                (ULONG_PTR)expectedStart)) {
            expectedStart = 0ULL;
        }
        if (expectedStart != 0ULL) {
            expectedStartSamples += 1UL;
        }

        for (slot = 0UL; slot < kSlotCount; ++slot) {
            readable[slot] = kswordArkRuntimeReadMemory(
                (const UCHAR*)thread + (slot * sizeof(PVOID)),
                &values[slot],
                sizeof(values[slot]));
            if (readable[slot] &&
                kswordArkWorkQueueFallbackQueueAddressMatches(
                    values[slot],
                    chain)) {
                slots[slot].queueMatches += 1UL;
                workerLike = TRUE;
            }
        }
        for (slot = 0UL; slot < kSlotCount; ++slot) {
            if (!readable[slot]) {
                continue;
            }
            kswordArkWorkQueueFallbackAccumulateSlot(
                &slots[slot],
                (ULONG64)values[slot],
                workerLike,
                expectedStart);
        }

        threadCount += 1UL;
        thread = kswordArkWorkQueueThreadWalkerNext(&walker);
    }
    kswordArkWorkQueueThreadWalkerClose(&walker);

    /*
     * _KTHREAD.Queue and the wait block object of a thread parked in
     * KeRemoveQueue can both hold the queue address, so a raw match count can
     * tie. The queue field is NULL on every System thread that never touched a
     * queue, while a wait block object is populated for anything that ever
     * waited, so the tie breaks on how often the slot reads back as NULL.
     */
    for (slot = 0UL; slot < kSlotCount; ++slot) {
        const KswWorkQueueFallbackSlotStats* stats = &slots[slot];

        if (stats->queueMatches >= 2UL && stats->queueMatches > bestQueueCount) {
            bestQueueCount = stats->queueMatches;
        }
    }
    for (slot = 0UL; bestQueueCount != 0UL && slot < kSlotCount; ++slot) {
        const KswWorkQueueFallbackSlotStats* stats = &slots[slot];

        if (stats->queueMatches != bestQueueCount) {
            continue;
        }
        if (bestQueueOffset < 0 || stats->zeroValues > bestQueueZeros) {
            bestQueueOffset = (LONG)(slot * (ULONG)sizeof(PVOID));
            bestQueueZeros = stats->zeroValues;
            queueTied = FALSE;
        }
        else if (stats->zeroValues == bestQueueZeros) {
            queueTied = TRUE;
        }
    }

    for (slot = 0UL; slot < kSlotCount; ++slot) {
        const KswWorkQueueFallbackSlotStats* stats = &slots[slot];
        const ULONG kOffset = slot * (ULONG)sizeof(PVOID);
        BOOLEAN startCandidate = FALSE;

        if (expectedStartSamples >= KSW_WORK_QUEUE_FALLBACK_START_MIN_SAMPLES) {
            // The kernel provided the real start address; use zero-counterexample per-thread comparison to locate the offset.
            startCandidate =
                stats->startMismatches == 0UL &&
                stats->startMatches >=
                    KSW_WORK_QUEUE_FALLBACK_START_MIN_SAMPLES;
        }
        else {
            // When the starting address is zeroed out by caller hardening, switch to structural criteria.
            startCandidate =
                stats->workerSamples >=
                    KSW_WORK_QUEUE_FALLBACK_START_MIN_WORKERS &&
                !stats->workerConflict &&
                stats->distinctCount >=
                    KSW_WORK_QUEUE_FALLBACK_START_MIN_DISTINCT &&
                kswordArkWorkQueueFallbackIsKernelAddress(
                    (ULONG_PTR)stats->workerValue) &&
                kswordArkRuntimeAddressIsExecutable(
                    view,
                    (ULONG_PTR)stats->workerValue,
                    1U);
        }
        if (startCandidate) {
            if (startOffset >= 0) {
                startTied = TRUE;
            }
            else {
                startOffset = (LONG)kOffset;
            }
        }
    }
    ExFreePoolWithTag(block, KSW_WORK_QUEUE_FALLBACK_TAG);

    if (startOffset >= 0 && !startTied) {
        *startAddressOffsetOut = (ULONG)startOffset;
        *startAddressResolvedOut = TRUE;
    }
    if (bestQueueOffset < 0 || queueTied) {
        return FALSE;
    }
    *queueOffsetOut = (ULONG)bestQueueOffset;
    return TRUE;
}

NTSTATUS
kswordArkWorkQueueResolveRuntimeLayout(
    _Out_ KswDynV4WorkQueueLayout* layoutOut
    )
{
    static PCSTR const kAnchors[] = { "ExQueueWorkItem" };
    KswDynState state;
    KswRuntimeImageView view;
    KswRuntimeDataReference* references = NULL;
    KswWorkQueueChain chain;
    KswWorkQueueSystemThreadSnapshot systemThreads;
    ULONG referenceCount = 0UL;
    ULONG threadQueueOffset = 0UL;
    ULONG threadStartOffset = 0UL;
    BOOLEAN threadStartResolved = FALSE;
    BOOLEAN chainAmbiguous = FALSE;
    NTSTATUS status = STATUS_NOT_SUPPORTED;

    if (layoutOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(layoutOut, sizeof(*layoutOut));
    RtlZeroMemory(&state, sizeof(state));
    RtlZeroMemory(&view, sizeof(view));
    RtlZeroMemory(&chain, sizeof(chain));
    RtlZeroMemory(&systemThreads, sizeof(systemThreads));
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    /*
     * Signature fallback only requires the ntoskrnl image range, and image identity is unconditionally
     * collected from the loaded module table. NtosActive indicates 'System Informer / PDB profile
     * applied'; using it as a threshold would rebind this fallback (which has no profile available) to
     * PDB, causing the entire path to exit with STATUS_DEVICE_NOT_READY when no profile exists.
     */
    kswordArkDynDataSnapshot(&state);
    if (state.ntoskrnl.imageBase == 0ULL ||
        state.ntoskrnl.sizeOfImage == 0UL ||
        !kswordArkRuntimeInitializeImageView(
            (PVOID)(ULONG_PTR)state.ntoskrnl.imageBase,
            state.ntoskrnl.sizeOfImage,
            &view)) {
        return STATUS_DEVICE_NOT_READY;
    }

    references = (KswRuntimeDataReference*)kswordArkAllocateNonPagedPool(
        KSW_WORK_QUEUE_FALLBACK_MAX_REFERENCES * sizeof(*references),
        KSW_WORK_QUEUE_FALLBACK_TAG);
    if (references == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    referenceCount = kswordArkRuntimeCollectAnchoredDataReferences(
        &view,
        kAnchors,
        RTL_NUMBER_OF(kAnchors),
        2UL,
        KSW_WORK_QUEUE_FALLBACK_SCAN_BYTES,
        references,
        KSW_WORK_QUEUE_FALLBACK_MAX_REFERENCES);
    /*
     * The four failure points return distinct NTSTATUS codes. When they all share a generic NOT_SUPPORTED, R3 can only
     * see 'fallback failed' and cannot determine whether the anchor failed to produce a reference, the pointer chain
     * failed to converge, the built-in priority table failed to locate, or a global variable fell outside the image.
     */
    if (referenceCount == 0UL) {
        // Anchor routine found no RIP-relative data references.
        status = STATUS_NOT_FOUND;
        goto Exit;
    }
    if (!kswordArkWorkQueueFallbackFindChain(
            &view,
            references,
            referenceCount,
            &chain,
            &chainAmbiguous)) {
        // The pointer chain from Partition -> ExPartition -> WorkQueues has no unique solution:
        // No candidate passes through multiple mutually contradictory chains; these are two distinct failure modes and must be reported separately.
        status = chainAmbiguous
            ? STATUS_OBJECT_NAME_COLLISION
            : STATUS_OBJECT_PATH_NOT_FOUND;
        goto Exit;
    }
    if (!kswordArkWorkQueueFallbackFindPriorityIndexes(
            &view,
            layoutOut->runtimePriorityIndexes)) {
        // ExpBuiltinPriorities failed to restore from the anchor code's RVA offset.
        status = STATUS_OBJECT_NAME_NOT_FOUND;
        goto Exit;
    }
    if (chain.partitionGlobal < view.base ||
        chain.partitionGlobal - view.base > MAXULONG) {
        // The hit global variable is outside the ntoskrnl image range.
        status = STATUS_INTEGER_OVERFLOW;
        goto Exit;
    }

    layoutOut->moduleBase = view.base;
    layoutOut->moduleSize = view.size;
    layoutOut->pspSystemPartitionRva =
        (ULONG)(chain.partitionGlobal - view.base);
    layoutOut->epartitionExPartition = chain.partitionExPartition;
    layoutOut->exPartitionWorkQueues = chain.exPartitionWorkQueues;
    layoutOut->exWorkQueueWorkPriQueue = 0UL;
    layoutOut->kpriQueueEntryListHead = chain.priQueueOffset;
    layoutOut->workItemList = (ULONG)FIELD_OFFSET(WORK_QUEUE_ITEM, List);
    layoutOut->workItemRoutine =
        (ULONG)FIELD_OFFSET(WORK_QUEUE_ITEM, WorkerRoutine);
    layoutOut->workItemParameter =
        (ULONG)FIELD_OFFSET(WORK_QUEUE_ITEM, Parameter);
    layoutOut->exWorkQueueQueueIndex = chain.queueIndexOffset;
    layoutOut->exPoolUntrusted = chain.poolIndex;
    layoutOut->epartitionTypeSize = chain.partitionExPartition + sizeof(PVOID);
    layoutOut->exPartitionTypeSize =
        chain.exPartitionWorkQueues + sizeof(PVOID);
    layoutOut->kpriQueueTypeSize = chain.priQueueOffset +
        (KSW_WORK_QUEUE_FALLBACK_PRIORITY_COUNT * sizeof(LIST_ENTRY));
    /*
     * The queue type size takes the upper bound of all validated fields. Reusing KpriQueueTypeSize would push the
     * partition back-reference and queue index outside the structure, causing the downstream FieldFits check to
     * degenerate into "using an offset-derived size to validate the same offset," effectively nullifying the check.
     */
    layoutOut->exWorkQueueTypeSize = layoutOut->kpriQueueTypeSize;
    if (chain.partitionBackOffset + sizeof(PVOID) >
        layoutOut->exWorkQueueTypeSize) {
        layoutOut->exWorkQueueTypeSize =
            chain.partitionBackOffset + (ULONG)sizeof(PVOID);
    }
    if (chain.queueIndexOffset != 0UL &&
        chain.queueIndexOffset + sizeof(ULONG) >
            layoutOut->exWorkQueueTypeSize) {
        layoutOut->exWorkQueueTypeSize =
            chain.queueIndexOffset + (ULONG)sizeof(ULONG);
    }
    layoutOut->workItemTypeSize = sizeof(WORK_QUEUE_ITEM);
    layoutOut->runtimeFlags =
        KSW_DYN_V4_WORK_QUEUE_RUNTIME_SIGNATURE |
        KSW_DYN_V4_WORK_QUEUE_RUNTIME_ITEMS;

    /*
     * Worker-thread rows need _KTHREAD.Queue and _ETHREAD.StartAddress. Both
     * are inferred from live System threads here, so the thread half of this
     * page no longer depends on an applied PDB profile. A profile-supplied
     * offset is still accepted, but only when the live walk could not produce
     * its own evidence: live evidence outranks a stored description.
     */
    (VOID)kswordArkWorkQueueCaptureSystemThreads(&systemThreads);
    if (kswordArkWorkQueueFallbackInferThreadOffsets(
            &chain,
            &view,
            &systemThreads,
            &threadQueueOffset,
            &threadStartOffset,
            &threadStartResolved)) {
        if (!threadStartResolved &&
            state.kernel.etStartAddress != KSW_DYN_OFFSET_UNAVAILABLE &&
            (state.kernelSources.etStartAddress ==
                 KSW_DYN_FIELD_SOURCE_PDB_PROFILE ||
             state.kernelSources.etStartAddress ==
                 KSW_DYN_FIELD_SOURCE_RUNTIME_PATTERN)) {
            threadStartOffset = state.kernel.etStartAddress;
            threadStartResolved = TRUE;
        }
        if (threadStartResolved) {
            layoutOut->ethreadTcb = 0UL;
            layoutOut->kthreadQueue = threadQueueOffset;
            layoutOut->ethreadStartAddress = threadStartOffset;
            layoutOut->kthreadTypeSize = threadQueueOffset + sizeof(PVOID);
            layoutOut->ethreadTypeSize = max(
                layoutOut->kthreadTypeSize,
                layoutOut->ethreadStartAddress + (ULONG)sizeof(PVOID));
            layoutOut->runtimeFlags |= KSW_DYN_V4_WORK_QUEUE_RUNTIME_THREADS;
        }
    }
    status = STATUS_SUCCESS;

Exit:
    kswordArkWorkQueueReleaseSystemThreads(&systemThreads);
    ExFreePoolWithTag(references, KSW_WORK_QUEUE_FALLBACK_TAG);
    if (!NT_SUCCESS(status)) {
        RtlZeroMemory(layoutOut, sizeof(*layoutOut));
    }
    return status;
}

NTSTATUS
kswordArkWorkQueueResolveActiveExWorkerField(
    _Out_ KswDynV4BitFieldLayout* fieldOut
    )
/*++

Routine Description:

    Infer ActiveExWorker from System threads whose queue pointer matches the
    independently signature-resolved Ex queues. Worker and non-worker samples
    must produce exactly one distinguishing set bit; ambiguity fails closed.

Return Value:

    STATUS_SUCCESS for one live-validated bit, otherwise a fail-closed status.

--*/
{
    KswDynV4WorkQueueLayout layout;
    KswWorkQueueChain chain;
    KswRuntimeImageView view;
    KswWorkQueueSystemThreadSnapshot systemThreads;
    KswWorkQueueThreadWalker walker;
    UCHAR* samples = NULL;
    UCHAR* workerSamples = NULL;
    UCHAR* otherSamples = NULL;
    ULONG workerCount = 0UL;
    ULONG otherCount = 0UL;
    ULONG threadQueueOffset = 0UL;
    ULONG threadStartOffset = 0UL;
    BOOLEAN threadStartResolved = FALSE;
    ULONG_PTR partitionGlobal = 0U;
    ULONG offset = 0UL;
    ULONG bit = 0UL;
    LONG foundOffset = -1;
    LONG foundBit = -1;
    PETHREAD thread = NULL;
    NTSTATUS status = STATUS_NOT_SUPPORTED;

    if (fieldOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(fieldOut, sizeof(*fieldOut));
    RtlZeroMemory(&layout, sizeof(layout));
    RtlZeroMemory(&chain, sizeof(chain));
    RtlZeroMemory(&view, sizeof(view));
    RtlZeroMemory(&systemThreads, sizeof(systemThreads));
    RtlZeroMemory(&walker, sizeof(walker));
    status = kswordArkWorkQueueResolveRuntimeLayout(&layout);
    if (!NT_SUCCESS(status) ||
        (layout.runtimeFlags & KSW_DYN_V4_WORK_QUEUE_RUNTIME_THREADS) == 0UL ||
        layout.moduleBase > MAXULONG_PTR - layout.pspSystemPartitionRva ||
        !kswordArkRuntimeInitializeImageView(
            (PVOID)(ULONG_PTR)layout.moduleBase,
            layout.moduleSize,
            &view)) {
        return STATUS_NOT_SUPPORTED;
    }
    partitionGlobal = (ULONG_PTR)layout.moduleBase +
        layout.pspSystemPartitionRva;
    (VOID)kswordArkWorkQueueCaptureSystemThreads(&systemThreads);
    if (!kswordArkWorkQueueFallbackValidateChainCandidate(
            partitionGlobal,
            layout.epartitionExPartition,
            layout.exPartitionWorkQueues,
            layout.exPoolUntrusted,
            &chain) ||
        !kswordArkWorkQueueFallbackInferThreadOffsets(
            &chain,
            &view,
            &systemThreads,
            &threadQueueOffset,
            &threadStartOffset,
            &threadStartResolved) ||
        threadQueueOffset != layout.kthreadQueue) {
        kswordArkWorkQueueReleaseSystemThreads(&systemThreads);
        return STATUS_NOT_SUPPORTED;
    }

    samples = (UCHAR*)kswordArkAllocateNonPagedPool(
        (2UL * KSW_WORK_QUEUE_FALLBACK_WORKER_SAMPLES) *
            KSW_WORK_QUEUE_FALLBACK_THREAD_SCAN,
        KSW_WORK_QUEUE_FALLBACK_TAG);
    if (samples == NULL) {
        kswordArkWorkQueueReleaseSystemThreads(&systemThreads);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(
        samples,
        (2UL * KSW_WORK_QUEUE_FALLBACK_WORKER_SAMPLES) *
            KSW_WORK_QUEUE_FALLBACK_THREAD_SCAN);
    workerSamples = samples;
    otherSamples = samples +
        (KSW_WORK_QUEUE_FALLBACK_WORKER_SAMPLES *
         KSW_WORK_QUEUE_FALLBACK_THREAD_SCAN);

    kswordArkWorkQueueInitializeThreadWalker(&walker, &systemThreads);
    if (!kswordArkWorkQueueThreadWalkerUsable(&walker)) {
        status = STATUS_PROCEDURE_NOT_FOUND;
        goto Exit;
    }
    thread = kswordArkWorkQueueThreadWalkerNext(&walker);
    while (thread != NULL &&
           (workerCount < KSW_WORK_QUEUE_FALLBACK_WORKER_SAMPLES ||
            otherCount < KSW_WORK_QUEUE_FALLBACK_WORKER_SAMPLES)) {
        ULONG_PTR queueAddress = 0U;
        BOOLEAN worker = FALSE;
        UCHAR* destination = NULL;

        if (kswordArkRuntimeReadMemory(
                (const UCHAR*)thread + threadQueueOffset,
                &queueAddress,
                sizeof(queueAddress))) {
            worker = kswordArkWorkQueueFallbackQueueAddressMatches(
                queueAddress,
                &chain);
            if (worker && workerCount < KSW_WORK_QUEUE_FALLBACK_WORKER_SAMPLES) {
                destination = workerSamples +
                    (workerCount * KSW_WORK_QUEUE_FALLBACK_THREAD_SCAN);
            }
            else if (!worker &&
                     otherCount < KSW_WORK_QUEUE_FALLBACK_WORKER_SAMPLES) {
                destination = otherSamples +
                    (otherCount * KSW_WORK_QUEUE_FALLBACK_THREAD_SCAN);
            }
            if (destination != NULL &&
                kswordArkRuntimeReadMemory(
                    thread,
                    destination,
                    KSW_WORK_QUEUE_FALLBACK_THREAD_SCAN)) {
                if (worker) {
                    workerCount += 1UL;
                }
                else {
                    otherCount += 1UL;
                }
            }
        }
        thread = kswordArkWorkQueueThreadWalkerNext(&walker);
    }
    kswordArkWorkQueueThreadWalkerClose(&walker);
    if (workerCount < 2UL || otherCount < 2UL) {
        status = STATUS_NOT_FOUND;
        goto Exit;
    }

    for (offset = sizeof(DISPATCHER_HEADER);
         offset < KSW_WORK_QUEUE_FALLBACK_THREAD_SCAN;
         ++offset) {
        for (bit = 0UL; bit < 8UL; ++bit) {
            UCHAR mask = (UCHAR)(1U << bit);
            ULONG sampleIndex = 0UL;
            BOOLEAN distinguishes = TRUE;

            for (sampleIndex = 0UL; sampleIndex < workerCount; ++sampleIndex) {
                if ((workerSamples[
                         sampleIndex * KSW_WORK_QUEUE_FALLBACK_THREAD_SCAN +
                         offset] & mask) == 0U) {
                    distinguishes = FALSE;
                    break;
                }
            }
            for (sampleIndex = 0UL;
                 distinguishes && sampleIndex < otherCount;
                 ++sampleIndex) {
                if ((otherSamples[
                         sampleIndex * KSW_WORK_QUEUE_FALLBACK_THREAD_SCAN +
                         offset] & mask) != 0U) {
                    distinguishes = FALSE;
                }
            }
            if (!distinguishes) {
                continue;
            }
            if (foundOffset >= 0) {
                status = STATUS_OBJECT_NAME_COLLISION;
                goto Exit;
            }
            foundOffset = (LONG)offset;
            foundBit = (LONG)bit;
        }
    }
    if (foundOffset < 0 || foundBit < 0) {
        status = STATUS_NOT_FOUND;
        goto Exit;
    }
    fieldOut->offset = (ULONG)foundOffset;
    fieldOut->bitOffset = (ULONG)foundBit;
    fieldOut->bitCount = 1UL;
    fieldOut->storageBytes = 1UL;
    status = STATUS_SUCCESS;

Exit:
    kswordArkWorkQueueThreadWalkerClose(&walker);
    kswordArkWorkQueueReleaseSystemThreads(&systemThreads);
    ExFreePoolWithTag(samples, KSW_WORK_QUEUE_FALLBACK_TAG);
    if (!NT_SUCCESS(status)) {
        RtlZeroMemory(fieldOut, sizeof(*fieldOut));
    }
    return status;
}
