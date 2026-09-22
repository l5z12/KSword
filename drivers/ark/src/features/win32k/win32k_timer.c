/*++

Module Name:

    win32k_timer.c

Abstract:

    Read-only enumeration of win32k tagTIMER objects through the exported
    gTimerHashTable. The collector prefers exact PE identity and can fall back
    to the nearest previous Windows layout. It never unlinks or modifies a timer.

Environment:

    Kernel-mode Driver Framework

--*/

#include "win32k_query.h"
#include "win32k_support.h"
#include "../../platform/pool_compat.h"

#include <ntimage.h>
#include <ntstrsafe.h>

#define KSWORD_ARK_WIN32K_TIMER_POOL_TAG 'mTkW'
#define KSWORD_ARK_WIN32K_TIMER_OBJECT_SIZE 0x88UL
#define KSWORD_ARK_WIN32K_TIMER_BUCKET_COUNT 64UL
#define KSWORD_ARK_WIN32K_TIMER_BUCKET_STRIDE sizeof(LIST_ENTRY)
#define KSWORD_ARK_WIN32K_TIMER_MAX_THREAD_MAP 8192UL
#define KSWORD_ARK_WIN32K_TIMER_MAX_SEEN 8192UL
#define KSWORD_ARK_WIN32K_TIMER_MAX_NODES 32768UL
#define KSWORD_ARK_WIN32K_TIMER_MAX_NODES_PER_BUCKET 8192UL

typedef struct KswordArkWiN32KTimerProfile
{
    KswordArkWiN32KLayoutProfileIdentity identity;
    KSWORD_ARK_WIN32K_TIMER_LAYOUT layout;
} KswordArkWiN32KTimerProfile;

// Maintained from older to newer Windows versions. Precise PE identity takes precedence; on a miss, the
// common selector uses the most recent table entry with a Windows version not higher than the current one.
static const KswordArkWiN32KTimerProfile kGKswordArkWin32kTimerProfiles[] =
{
    {
        // 22H2 19045 is an enablement-package version. Private win32k
        // binaries remain on the 19041 servicing branch; use that branch for
        // nearest-previous ordering so PsGetVersion/NtBuildNumber cannot make
        // the verified profile look newer than the running kernel.
        { 10UL, 0UL, 19041UL, 6456UL,
          0x8FC48444UL, 0x002D6000UL, 0x83C73BE4UL, 0x003B4000UL },
        { KSWORD_ARK_WIN32K_TIMER_OBJECT_SIZE,
          0x18UL, 0x20UL, 0x28UL, 0x2CUL, 0x30UL, 0x34UL, 0x48UL,
          0x58UL, 0x60UL, 0x68UL, 0x70UL, 0x80UL,
          KSWORD_ARK_WIN32K_TIMER_BUCKET_COUNT,
          KSWORD_ARK_WIN32K_TIMER_BUCKET_STRIDE,
          KSWORD_ARK_WIN32K_TIMER_LAYOUT_SOURCE_UNKNOWN,
          0x83C73BE4UL, 0x003B4000UL }
    }
};

typedef KswordArkWiN32KGuiThreadMapEntry
    KswordArkWiN32KTimerThreadMapEntry;

typedef struct KswordArkWiN32KTimerWalkContext
{
    KSWORD_ARK_WIN32K_TIMER_SNAPSHOT_RESPONSE* response;
    const KSWORD_ARK_WIN32K_TIMER_LAYOUT* layout;
    const KSWORD_ARK_WIN32K_QUERY_REQUEST* request;
    const KswordArkWiN32KTimerThreadMapEntry* threadMap;
    ULONG threadMapCount;
    ULONG requestedSessionId;
    ULONG maxEntries;
    ULONG64* seenTimers;
    ULONG seenCount;
    ULONG traversalCount;
    ULONG unresolvedOwnerCount;
    BOOLEAN stop;
} KswordArkWiN32KTimerWalkContext;

NTSYSAPI
PVOID
NTAPI
RtlFindExportedRoutineByName(
    _In_ PVOID imageBase,
    _In_z_ PCSTR routineName
    );

NTKERNELAPI
VOID
KeStackAttachProcess(
    _Inout_ PVOID process,
    _Out_ PVOID apcState
    );

NTKERNELAPI
VOID
KeUnstackDetachProcess(
    _In_ PVOID apcState
    );

NTKERNELAPI
NTSTATUS
PsLookupProcessByProcessId(
    _In_ HANDLE processId,
    _Outptr_ PEPROCESS* process
    );

static BOOLEAN
KswordARKWin32kTimerIsKernelAddress(
    _In_ ULONG64 address
    )
/*++

Routine Description:

    Validate that a pointer belongs to the canonical kernel virtual address
    range before passing it to MmCopyMemory.

Arguments:

    Address - Candidate pointer value.

Return Value:

    TRUE when the value is a canonical kernel address.

--*/
{
#if defined(_M_AMD64) || defined(_M_X64)
    return address >= (ULONG64)(ULONG_PTR)MmSystemRangeStart &&
        (address >> 48U) == 0xFFFFULL;
#else
    return Address >= (ULONG64)(ULONG_PTR)MmSystemRangeStart;
#endif
}

static BOOLEAN
kswordArkWin32kTimerReadMemory(
    _In_ ULONG64 address,
    _Out_writes_bytes_(bytesToRead) PVOID destination,
    _In_ SIZE_T bytesToRead
    )
/*++

Routine Description:

    Read one timer or list fragment with the shared safe kernel-memory helper.

Arguments:

    Address - Kernel virtual address to read.
    Destination - Destination buffer.
    BytesToRead - Number of bytes to read.

Return Value:

    TRUE when the complete range was copied.

--*/
{
    ULONG64 lastAddress = 0ULL;

    if (destination == NULL || bytesToRead == 0U ||
        bytesToRead > (SIZE_T)MAXULONG ||
        !KswordARKWin32kTimerIsKernelAddress(address) ||
        address > MAXULONGLONG - (ULONG64)(bytesToRead - 1U)) {
        return FALSE;
    }

    lastAddress = address + (ULONG64)(bytesToRead - 1U);
    if (!KswordARKWin32kTimerIsKernelAddress(lastAddress)) {
        return FALSE;
    }

    return kswordArkHookReadMemorySafe(
        (const VOID*)(ULONG_PTR)address,
        destination,
        bytesToRead);
}

static ULONG64
kswordArkWin32kTimerReadU64(
    _In_reads_bytes_(KSWORD_ARK_WIN32K_TIMER_OBJECT_SIZE) const UCHAR* timerBytes,
    _In_ ULONG offset
    )
/*++

Routine Description:

    Read a pointer-sized tagTIMER field from a validated local copy.

Arguments:

    TimerBytes - Local timer object copy.
    Offset - Field offset.

Return Value:

    Field value, or zero when the offset is outside the known object.

--*/
{
    ULONG64 value = 0ULL;

    if (timerBytes == NULL || offset > KSWORD_ARK_WIN32K_TIMER_OBJECT_SIZE ||
        sizeof(value) > KSWORD_ARK_WIN32K_TIMER_OBJECT_SIZE - offset) {
        return 0ULL;
    }
    RtlCopyMemory(&value, timerBytes + offset, sizeof(value));
    return value;
}

static ULONG
kswordArkWin32kTimerReadU32(
    _In_reads_bytes_(KSWORD_ARK_WIN32K_TIMER_OBJECT_SIZE) const UCHAR* timerBytes,
    _In_ ULONG offset
    )
/*++

Routine Description:

    Read a 32-bit tagTIMER field from a validated local copy.

Arguments:

    TimerBytes - Local timer object copy.
    Offset - Field offset.

Return Value:

    Field value, or zero when the offset is outside the known object.

--*/
{
    ULONG value = 0UL;

    if (timerBytes == NULL || offset > KSWORD_ARK_WIN32K_TIMER_OBJECT_SIZE ||
        sizeof(value) > KSWORD_ARK_WIN32K_TIMER_OBJECT_SIZE - offset) {
        return 0UL;
    }
    RtlCopyMemory(&value, timerBytes + offset, sizeof(value));
    return value;
}

static VOID
kswordArkWin32kTimerSetDetail(
    _Out_writes_(KSWORD_ARK_WIN32K_DETAIL_CHARS) PWCHAR destination,
    _In_z_ PCWSTR text
    )
/*++

Routine Description:

    Copy a bounded timer diagnostic detail string.

Arguments:

    Destination - Fixed protocol text field.
    Text - Constant diagnostic text.

Return Value:

    None.

--*/
{
    kswordArkWin32kCopyWideText(
        destination,
        KSWORD_ARK_WIN32K_DETAIL_CHARS,
        text);
}

static VOID
kswordArkWin32kTimerInitializeLayout(
    _Out_ KSWORD_ARK_WIN32K_TIMER_LAYOUT* layout,
    _In_ const KswordArkWiN32KTimerProfile* profile,
    _In_ ULONG source
    )
/*++

Routine Description:

    initialize the exact tagTIMER offsets verified for the supported PE pair.

Arguments:

    Layout - Receives the timer layout packet.
    Profile - Selected exact or nearest-previous layout profile.
    Source - Layout selection source.

Return Value:

    None.

--*/
{
    if (layout == NULL || profile == NULL) {
        return;
    }
    *layout = profile->layout;
    layout->source = source == KSWORD_ARK_WIN32K_LAYOUT_SELECTION_EXACT_IDENTITY
        ? KSWORD_ARK_WIN32K_TIMER_LAYOUT_SOURCE_VALIDATED_DISASSEMBLY
        : KSWORD_ARK_WIN32K_TIMER_LAYOUT_SOURCE_NEAREST_PREVIOUS;
}

static NTSTATUS
kswordArkWin32kTimerBuildThreadMap(
    _Outptr_result_buffer_(*countOut) KswordArkWiN32KTimerThreadMapEntry** mapOut,
    _Out_ ULONG* countOut,
    _Out_ BOOLEAN* truncatedOut
    )
/*++

Routine Description:

    Build a bounded map from public PsGetThreadWin32Thread values to PID/TID.
    This avoids depending on private tagTHREADINFO fields for ownership.

Arguments:

    MapOut - Receives the allocated map.
    CountOut - Receives the number of valid entries.
    TruncatedOut - Receives TRUE if the hard map limit was reached.

Return Value:

    STATUS_SUCCESS or the first missing public routine/allocation failure.

--*/
{
    return kswordArkWin32kBuildGuiThreadMap(
        KSWORD_ARK_WIN32K_TIMER_MAX_THREAD_MAP,
        KSWORD_ARK_WIN32K_TIMER_POOL_TAG,
        mapOut,
        countOut,
        truncatedOut);
}

static NTSTATUS
kswordArkWin32kTimerReferenceSessionProcess(
    _In_reads_(threadMapCount) const KswordArkWiN32KTimerThreadMapEntry* threadMap,
    _In_ ULONG threadMapCount,
    _In_opt_ const KSWORD_ARK_WIN32K_QUERY_REQUEST* request,
    _Inout_ ULONG* requestedSessionId,
    _Outptr_ PEPROCESS* processOut
    )
{
    ULONG preferredProcessId = request != NULL ? request->processId : 0UL;
    ULONG pass = 0UL;

    if (threadMap == NULL || threadMapCount == 0UL ||
        requestedSessionId == NULL || processOut == NULL) {
        return STATUS_NOT_FOUND;
    }
    *processOut = NULL;

    for (pass = 0UL; pass < 4UL; ++pass) {
        ULONG index = 0UL;

        for (index = 0UL; index < threadMapCount; ++index) {
            const KswordArkWiN32KTimerThreadMapEntry* entry = &threadMap[index];
            BOOLEAN candidate = FALSE;
            PEPROCESS process = NULL;
            NTSTATUS status = STATUS_SUCCESS;

            switch (pass) {
            case 0UL:
                candidate = preferredProcessId != 0UL &&
                    entry->processId == preferredProcessId &&
                    (*requestedSessionId == 0UL || entry->sessionId == *requestedSessionId);
                break;
            case 1UL:
                candidate = *requestedSessionId != 0UL &&
                    entry->sessionId == *requestedSessionId;
                break;
            case 2UL:
                candidate = *requestedSessionId == 0UL && entry->sessionId != 0UL;
                break;
            default:
                candidate = *requestedSessionId == 0UL;
                break;
            }
            if (!candidate) {
                continue;
            }

            status = PsLookupProcessByProcessId(
                ULongToHandle(entry->processId),
                &process);
            if (NT_SUCCESS(status) && process != NULL) {
                KswordWiN32KPsGetProcessSessionIdFn psGetProcessSessionId =
                    kswordArkWin32kResolvePsGetProcessSessionId();

                if (psGetProcessSessionId == NULL ||
                    psGetProcessSessionId(process) == entry->sessionId) {
                    *requestedSessionId = entry->sessionId;
                    *processOut = process;
                    return STATUS_SUCCESS;
                }
                ObDereferenceObject(process);
            }
        }
    }

    return STATUS_NOT_FOUND;
}

static BOOLEAN
kswordArkWin32kTimerLookupThread(
    _In_reads_(threadMapCount) const KswordArkWiN32KTimerThreadMapEntry* threadMap,
    _In_ ULONG threadMapCount,
    _In_ ULONG64 threadInfo,
    _In_ ULONG preferredSessionId,
    _Out_ ULONG* processIdOut,
    _Out_ ULONG* threadIdOut,
    _Out_ ULONG* sessionIdOut
    )
/*++

Routine Description:

    Resolve one private tagTHREADINFO pointer through the public thread map.

Arguments:

    ThreadMap - Bounded map produced by the process/thread walker.
    ThreadMapCount - Number of valid map rows.
    ThreadInfo - tagTHREADINFO pointer stored in tagTIMER.
    ProcessIdOut - Receives PID.
    ThreadIdOut - Receives TID.
    SessionIdOut - Receives session id.

Return Value:

    TRUE when the pointer was matched.

--*/
{
    ULONG index = 0UL;

    if (processIdOut == NULL || threadIdOut == NULL || sessionIdOut == NULL) {
        return FALSE;
    }
    *processIdOut = 0UL;
    *threadIdOut = 0UL;
    *sessionIdOut = 0UL;
    if (threadMap == NULL || threadInfo == 0ULL) {
        return FALSE;
    }

    for (index = 0UL; index < threadMapCount; ++index) {
        if (threadMap[index].threadInfo == threadInfo &&
            (preferredSessionId == 0UL ||
                threadMap[index].sessionId == preferredSessionId)) {
            *processIdOut = threadMap[index].processId;
            *threadIdOut = threadMap[index].threadId;
            *sessionIdOut = threadMap[index].sessionId;
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN
kswordArkWin32kTimerAlreadySeen(
    _In_reads_(seenCount) const ULONG64* seenTimers,
    _In_ ULONG seenCount,
    _In_ ULONG64 timerAddress
    )
/*++

Routine Description:

    Check the bounded duplicate set used while hash buckets are traversed.

Arguments:

    SeenTimers - Previously emitted timer addresses.
    SeenCount - Number of valid addresses.
    TimerAddress - Candidate timer address.

Return Value:

    TRUE if the address was already observed.

--*/
{
    ULONG index = 0UL;

    if (seenTimers == NULL || timerAddress == 0ULL) {
        return FALSE;
    }
    for (index = 0UL; index < seenCount; ++index) {
        if (seenTimers[index] == timerAddress) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN
kswordArkWin32kTimerMatchesRequest(
    _In_ const KswordArkWiN32KTimerWalkContext* context,
    _In_ ULONG processId,
    _In_ ULONG threadId,
    _In_ BOOLEAN ownerResolved
    )
/*++

Routine Description:

    Apply the user supplied session/PID/TID filters to one resolved timer owner.

Arguments:

    Context - Timer traversal context.
    ProcessId - Resolved owner PID.
    ThreadId - Resolved owner TID.
    SessionId - Resolved owner session.

Return Value:

    TRUE when the row belongs in the response.

--*/
{
    if (context == NULL) {
        return FALSE;
    }
    if (context->request != NULL && context->request->processId != 0UL &&
        (!ownerResolved || context->request->processId != processId)) {
        return FALSE;
    }
    if (context->request != NULL && context->request->threadId != 0UL &&
        (!ownerResolved || context->request->threadId != threadId)) {
        return FALSE;
    }
    return TRUE;
}

static VOID
kswordArkWin32kTimerAppend(
    _Inout_ KswordArkWiN32KTimerWalkContext* context,
    _In_ ULONG64 timerAddress,
    _In_ ULONG64 hashLinkAddress
    )
/*++

Routine Description:

    Read one tagTIMER object, resolve its owner, apply filters, and append a row.

Arguments:

    Context - Mutable traversal context and response.
    TimerAddress - Container address derived from the hash LIST_ENTRY.
    HashLinkAddress - Address of the hash LIST_ENTRY node.

Return Value:

    None. Read failures are counted and do not abort other buckets.

--*/
{
    UCHAR timerBytes[KSWORD_ARK_WIN32K_TIMER_OBJECT_SIZE];
    ULONG64 primaryThreadInfo = 0ULL;
    ULONG64 alternateThreadInfo = 0ULL;
    ULONG processId = 0UL;
    ULONG threadId = 0UL;
    ULONG sessionId = 0UL;
    BOOLEAN ownerResolved = FALSE;
    KSWORD_ARK_WIN32K_TIMER_ENTRY* entry = NULL;

    if (context == NULL || context->response == NULL || context->layout == NULL ||
        timerAddress == 0ULL) {
        return;
    }
    context->response->visitedNodeCount += 1UL;
    context->traversalCount += 1UL;
    if (context->traversalCount > KSWORD_ARK_WIN32K_TIMER_MAX_NODES) {
        context->response->status = KSWORD_ARK_WIN32K_STATUS_BUFFER_TRUNCATED;
        context->response->lastStatus = STATUS_BUFFER_OVERFLOW;
        context->stop = TRUE;
        return;
    }

    if (!KswordARKWin32kTimerIsKernelAddress(timerAddress) ||
        !kswordArkWin32kTimerReadMemory(
            timerAddress,
            timerBytes,
            sizeof(timerBytes))) {
        context->response->readFailureCount += 1UL;
        context->response->status = KSWORD_ARK_WIN32K_STATUS_PARTIAL;
        context->response->lastStatus = STATUS_PARTIAL_COPY;
        return;
    }

    primaryThreadInfo = kswordArkWin32kTimerReadU64(
        timerBytes,
        context->layout->primaryThreadInfo);
    alternateThreadInfo = kswordArkWin32kTimerReadU64(
        timerBytes,
        context->layout->alternateThreadInfo);
    ownerResolved = kswordArkWin32kTimerLookupThread(
        context->threadMap,
        context->threadMapCount,
        primaryThreadInfo,
        context->requestedSessionId,
        &processId,
        &threadId,
        &sessionId);
    if (!ownerResolved) {
        ownerResolved = kswordArkWin32kTimerLookupThread(
            context->threadMap,
            context->threadMapCount,
            alternateThreadInfo,
            context->requestedSessionId,
            &processId,
            &threadId,
            &sessionId);
    }
    if (!ownerResolved) {
        context->unresolvedOwnerCount += 1UL;
        processId = 0UL;
        threadId = 0UL;
        // gTimerHashTable was read while attached to RequestedSessionId. Keep
        // the object visible even when a nearest-previous private pti offset
        // cannot be joined to the public PsGetThreadWin32Thread map.
        sessionId = context->requestedSessionId;
    }

    if (!kswordArkWin32kTimerMatchesRequest(
            context,
            processId,
            threadId,
            ownerResolved)) {
        return;
    }
    context->response->totalCount += 1UL;
    if (context->response->returnedCount >= context->maxEntries) {
        context->response->status = KSWORD_ARK_WIN32K_STATUS_BUFFER_TRUNCATED;
        context->response->lastStatus = STATUS_BUFFER_OVERFLOW;
        context->stop = TRUE;
        return;
    }

    entry = &context->response->entries[context->response->returnedCount];
    RtlZeroMemory(entry, sizeof(*entry));
    entry->fieldFlags = KSWORD_ARK_WIN32K_TIMER_FIELD_OBJECT |
        KSWORD_ARK_WIN32K_TIMER_FIELD_CALLBACK |
        KSWORD_ARK_WIN32K_TIMER_FIELD_INTERVAL |
        KSWORD_ARK_WIN32K_TIMER_FIELD_FLAGS |
        KSWORD_ARK_WIN32K_TIMER_FIELD_WINDOW |
        KSWORD_ARK_WIN32K_TIMER_FIELD_ID |
        KSWORD_ARK_WIN32K_TIMER_FIELD_HASH_LINK;
    if (ownerResolved) {
        entry->fieldFlags |= KSWORD_ARK_WIN32K_TIMER_FIELD_THREAD;
    }
    if (alternateThreadInfo != 0ULL) {
        entry->fieldFlags |= KSWORD_ARK_WIN32K_TIMER_FIELD_ALTERNATE_THREAD;
    }
    entry->status = ownerResolved
        ? KSWORD_ARK_WIN32K_STATUS_OK
        : KSWORD_ARK_WIN32K_STATUS_PARTIAL;
    entry->processId = processId;
    entry->threadId = threadId;
    entry->sessionId = sessionId;
    entry->flags = kswordArkWin32kTimerReadU32(timerBytes, context->layout->flags);
    entry->intervalMs = kswordArkWin32kTimerReadU32(timerBytes, context->layout->interval);
    entry->countdownMs = kswordArkWin32kTimerReadU32(timerBytes, context->layout->countdown);
    entry->toleranceMs = kswordArkWin32kTimerReadU32(timerBytes, context->layout->tolerance);
    entry->lastStatus = STATUS_SUCCESS;
    entry->timerObject = timerAddress;
    entry->callbackAddress = kswordArkWin32kTimerReadU64(timerBytes, context->layout->callback);
    entry->primaryThreadInfo = primaryThreadInfo;
    entry->alternateThreadInfo = alternateThreadInfo;
    entry->windowObject = kswordArkWin32kTimerReadU64(timerBytes, context->layout->window);
    entry->timerId = kswordArkWin32kTimerReadU64(timerBytes, context->layout->timerId);
    entry->hashLink = hashLinkAddress;
    if (ownerResolved) {
        kswordArkWin32kTimerSetDetail(
            entry->detail,
            L"tagTIMER via gTimerHashTable; owner mapped through PsGetThreadWin32Thread.");
    }
    else {
        kswordArkWin32kTimerSetDetail(
            entry->detail,
            L"tagTIMER read succeeded; tagTHREADINFO owner was not present in the public thread map.");
    }
    context->response->returnedCount += 1UL;
}

static VOID
kswordArkWin32kTimerWalkBucket(
    _Inout_ KswordArkWiN32KTimerWalkContext* context,
    _In_ ULONG64 listHeadAddress
    )
/*++

Routine Description:

    Traverse one gTimerHashTable LIST_ENTRY bucket with bounded integrity checks.

Arguments:

    Context - Mutable timer traversal context.
    ListHeadAddress - Address of the bucket LIST_ENTRY head.

Return Value:

    None. The response records partial/corrupt/read-failure evidence.

--*/
{
    LIST_ENTRY headLinks;
    ULONG64 currentAddress = 0ULL;
    ULONG64 expectedBackLink = listHeadAddress;
    ULONG traversalCount = 0UL;

    if (context == NULL || context->response == NULL ||
        !kswordArkWin32kTimerReadMemory(
            listHeadAddress,
            &headLinks,
            sizeof(headLinks))) {
        if (context != NULL && context->response != NULL) {
            context->response->readFailureCount += 1UL;
            context->response->status = KSWORD_ARK_WIN32K_STATUS_PARTIAL;
            context->response->lastStatus = STATUS_PARTIAL_COPY;
        }
        return;
    }

    currentAddress = (ULONG64)(ULONG_PTR)headLinks.Flink;
    if (currentAddress == listHeadAddress) {
        return;
    }
    if (!KswordARKWin32kTimerIsKernelAddress(currentAddress)) {
        context->response->corruptBucketCount += 1UL;
        context->response->status = KSWORD_ARK_WIN32K_STATUS_PARTIAL;
        context->response->lastStatus = STATUS_DATA_ERROR;
        return;
    }

    while (currentAddress != listHeadAddress && !context->stop) {
        LIST_ENTRY currentLinks;
        ULONG64 timerAddress = 0ULL;
        ULONG64 nextAddress = 0ULL;

        if (traversalCount >= KSWORD_ARK_WIN32K_TIMER_MAX_NODES_PER_BUCKET) {
            context->response->corruptBucketCount += 1UL;
            context->response->status = KSWORD_ARK_WIN32K_STATUS_BUFFER_TRUNCATED;
            context->response->lastStatus = STATUS_BUFFER_OVERFLOW;
            break;
        }
        if (!KswordARKWin32kTimerIsKernelAddress(currentAddress) ||
            currentAddress < (ULONG64)context->layout->hashListEntry) {
            context->response->corruptBucketCount += 1UL;
            context->response->status = KSWORD_ARK_WIN32K_STATUS_PARTIAL;
            context->response->lastStatus = STATUS_DATA_ERROR;
            break;
        }
        timerAddress = currentAddress - (ULONG64)context->layout->hashListEntry;
        RtlZeroMemory(&currentLinks, sizeof(currentLinks));
        if (!kswordArkWin32kTimerReadMemory(
                currentAddress,
                &currentLinks,
                sizeof(currentLinks))) {
            context->response->readFailureCount += 1UL;
            context->response->status = KSWORD_ARK_WIN32K_STATUS_PARTIAL;
            context->response->lastStatus = STATUS_PARTIAL_COPY;
            break;
        }
        if ((ULONG64)(ULONG_PTR)currentLinks.Blink != expectedBackLink) {
            context->response->corruptBucketCount += 1UL;
            context->response->status = KSWORD_ARK_WIN32K_STATUS_PARTIAL;
            context->response->lastStatus = STATUS_DATA_ERROR;
            break;
        }
        if (kswordArkWin32kTimerAlreadySeen(
                context->seenTimers,
                context->seenCount,
                timerAddress)) {
            context->response->duplicateCount += 1UL;
        }
        else {
            if (context->seenCount < KSWORD_ARK_WIN32K_TIMER_MAX_SEEN) {
                context->seenTimers[context->seenCount] = timerAddress;
                context->seenCount += 1UL;
            }
            else {
                context->response->status = KSWORD_ARK_WIN32K_STATUS_BUFFER_TRUNCATED;
                context->response->lastStatus = STATUS_BUFFER_OVERFLOW;
                context->stop = TRUE;
            }
            if (!context->stop) {
                kswordArkWin32kTimerAppend(context, timerAddress, currentAddress);
            }
        }
        if (context->stop) {
            break;
        }
        nextAddress = (ULONG64)(ULONG_PTR)currentLinks.Flink;
        if (nextAddress != listHeadAddress &&
            (!KswordARKWin32kTimerIsKernelAddress(nextAddress) ||
             nextAddress == currentAddress)) {
            context->response->corruptBucketCount += 1UL;
            context->response->status = KSWORD_ARK_WIN32K_STATUS_PARTIAL;
            context->response->lastStatus = STATUS_DATA_ERROR;
            break;
        }
        expectedBackLink = currentAddress;
        currentAddress = nextAddress;
        traversalCount += 1UL;
    }
    if (!context->stop && currentAddress == listHeadAddress &&
        (ULONG64)(ULONG_PTR)headLinks.Blink != expectedBackLink) {
        context->response->corruptBucketCount += 1UL;
        context->response->status = KSWORD_ARK_WIN32K_STATUS_PARTIAL;
        context->response->lastStatus = STATUS_DATA_ERROR;
    }
}

NTSTATUS
kswordArkWin32kQueryTimerSnapshot(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_WIN32K_QUERY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    enumerate current USER window timers from the win32k hash table.

Arguments:

    OutputBuffer - METHOD_BUFFERED output packet.
    OutputBufferLength - Writable output size.
    Request - Optional session/PID/TID filters and row budget.
    BytesWrittenOut - Receives the variable response size.

Return Value:

    STATUS_SUCCESS with an explicit response status for unsupported or partial
    runtime conditions.

--*/
{
    KswHookSystemModuleInformation* moduleInfo = NULL;
    KswHookSystemModuleEntry baseEntry;
    KswHookSystemModuleEntry fullEntry;
    IMAGE_NT_HEADERS baseHeaders;
    IMAGE_NT_HEADERS fullHeaders;
    KswordArkWiN32KLayoutSelection layoutSelection;
    const KswordArkWiN32KTimerProfile* layoutProfile = NULL;
    KSWORD_ARK_WIN32K_TIMER_SNAPSHOT_RESPONSE* response = NULL;
    KswordArkWiN32KTimerThreadMapEntry* threadMap = NULL;
    ULONG64* seenTimers = NULL;
    PEPROCESS sessionProcess = NULL;
    PVOID timerHashTable = NULL;
    ULONG moduleInfoBytes = 0UL;
    ULONG threadMapCount = 0UL;
    ULONG maxEntries = KSWORD_ARK_WIN32K_DEFAULT_MAX_ENTRIES;
    ULONG requestedSessionId = 0UL;
    ULONG bucketIndex = 0UL;
    size_t headerSize = 0U;
    size_t entryCapacity = 0U;
    BOOLEAN threadMapTruncated = FALSE;
    BOOLEAN attached = FALSE;
    DECLSPEC_ALIGN(16) UCHAR attachState[128];
    NTSTATUS status = STATUS_SUCCESS;

    if (bytesWrittenOut == NULL || outputBuffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    headerSize = sizeof(KSWORD_ARK_WIN32K_TIMER_SNAPSHOT_RESPONSE) -
        sizeof(KSWORD_ARK_WIN32K_TIMER_ENTRY);
    if (outputBufferLength < headerSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_WIN32K_TIMER_SNAPSHOT_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_WIN32K_PROTOCOL_VERSION;
    response->status = KSWORD_ARK_WIN32K_STATUS_UNKNOWN;
    response->entrySize = sizeof(KSWORD_ARK_WIN32K_TIMER_ENTRY);
    response->flags = request != NULL ? request->flags : 0UL;
    response->lastStatus = STATUS_SUCCESS;
    entryCapacity = (outputBufferLength - headerSize) / sizeof(KSWORD_ARK_WIN32K_TIMER_ENTRY);
    maxEntries = request != NULL
        ? kswordArkWin32kNormalizeMaxEntries(request->maxEntries)
        : KSWORD_ARK_WIN32K_DEFAULT_MAX_ENTRIES;
    if (entryCapacity < (size_t)maxEntries) {
        maxEntries = (ULONG)entryCapacity;
    }
    if (maxEntries == 0UL) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = kswordArkHookBuildModuleSnapshot(&moduleInfo, &moduleInfoBytes);
    response->lastStatus = status;
    if (!NT_SUCCESS(status) ||
        !kswordArkWin32kFindModuleByName(moduleInfo, "win32kbase.sys", &baseEntry) ||
        !kswordArkWin32kFindModuleByName(moduleInfo, "win32kfull.sys", &fullEntry)) {
        response->status = KSWORD_ARK_WIN32K_STATUS_WIN32K_NOT_FOUND;
        response->missingCapabilityMask = KSWORD_ARK_WIN32K_CAP_TIMER_HASH_EXPORT |
            KSWORD_ARK_WIN32K_CAP_TIMER_LAYOUT | KSWORD_ARK_WIN32K_CAP_TIMER_ENUM;
        response->lastStatus = NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
        goto Cleanup;
    }

    RtlZeroMemory(&baseHeaders, sizeof(baseHeaders));
    RtlZeroMemory(&fullHeaders, sizeof(fullHeaders));
    if (!kswordArkHookReadImageNtHeaders(&baseEntry, &baseHeaders) ||
        !kswordArkHookReadImageNtHeaders(&fullEntry, &fullHeaders)) {
        response->status = KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED;
        response->missingCapabilityMask = KSWORD_ARK_WIN32K_CAP_TIMER_LAYOUT |
            KSWORD_ARK_WIN32K_CAP_TIMER_ENUM;
        response->lastStatus = STATUS_INVALID_IMAGE_FORMAT;
        kswordArkWin32kTimerSetDetail(
            response->detail,
            L"win32k PE header could not be read; timer layout was not guessed.");
        goto Cleanup;
    }

    response->win32kbaseTimeDateStamp = baseHeaders.FileHeader.TimeDateStamp;
    response->win32kbaseImageSize = baseHeaders.OptionalHeader.SizeOfImage;
    response->win32kfullTimeDateStamp = fullHeaders.FileHeader.TimeDateStamp;
    response->win32kfullImageSize = fullHeaders.OptionalHeader.SizeOfImage;
    if (!kswordArkWin32kSelectLayoutProfile(
            kGKswordArkWin32kTimerProfiles,
            RTL_NUMBER_OF(kGKswordArkWin32kTimerProfiles),
            sizeof(kGKswordArkWin32kTimerProfiles[0]),
            response->win32kbaseTimeDateStamp,
            response->win32kbaseImageSize,
            response->win32kfullTimeDateStamp,
            response->win32kfullImageSize,
            &layoutSelection)) {
        response->status = KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED;
        response->missingCapabilityMask = KSWORD_ARK_WIN32K_CAP_TIMER_LAYOUT |
            KSWORD_ARK_WIN32K_CAP_TIMER_ENUM;
        response->lastStatus = STATUS_REVISION_MISMATCH;
        kswordArkWin32kTimerSetDetail(
            response->detail,
            L"No exact or nearest-previous Windows tagTIMER profile is available.");
        goto Cleanup;
    }
    layoutProfile = &kGKswordArkWin32kTimerProfiles[layoutSelection.profileIndex];

    kswordArkWin32kTimerInitializeLayout(
        &response->layout,
        layoutProfile,
        layoutSelection.source);
    if (response->layout.objectSize == 0UL ||
        response->layout.objectSize > KSWORD_ARK_WIN32K_TIMER_OBJECT_SIZE ||
        response->layout.bucketCount == 0UL ||
        response->layout.bucketCount > 256UL ||
        response->layout.bucketStride < sizeof(LIST_ENTRY)) {
        response->status = KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED;
        response->missingCapabilityMask = KSWORD_ARK_WIN32K_CAP_TIMER_LAYOUT |
            KSWORD_ARK_WIN32K_CAP_TIMER_ENUM;
        response->lastStatus = STATUS_INVALID_PARAMETER;
        kswordArkWin32kTimerSetDetail(
            response->detail,
            L"Selected tagTIMER profile failed local size and bucket validation.");
        goto Cleanup;
    }
    status = kswordArkWin32kTimerBuildThreadMap(
        &threadMap,
        &threadMapCount,
        &threadMapTruncated);
    if (!NT_SUCCESS(status)) {
        response->status = KSWORD_ARK_WIN32K_STATUS_READ_FAILED;
        response->lastStatus = status;
        response->missingCapabilityMask |= KSWORD_ARK_WIN32K_CAP_THREADINFO_PUBLIC;
        kswordArkWin32kTimerSetDetail(
            response->detail,
            L"GUI thread mapping failed before the target win32k session could be attached.");
        goto Cleanup;
    }

    if (request != NULL && request->sessionId != 0UL) {
        requestedSessionId = request->sessionId;
    }
    else if (request != NULL &&
        (request->flags & KSWORD_ARK_WIN32K_QUERY_FLAG_CURRENT_SESSION_ONLY) != 0UL) {
        KswordWiN32KPsGetProcessSessionIdFn psGetProcessSessionId =
            kswordArkWin32kResolvePsGetProcessSessionId();
        if (psGetProcessSessionId != NULL) {
            requestedSessionId = psGetProcessSessionId(PsGetCurrentProcess());
        }
    }

    status = kswordArkWin32kTimerReferenceSessionProcess(
        threadMap,
        threadMapCount,
        request,
        &requestedSessionId,
        &sessionProcess);
    if (!NT_SUCCESS(status) || sessionProcess == NULL) {
        response->status = KSWORD_ARK_WIN32K_STATUS_READ_FAILED;
        response->lastStatus = NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
        response->missingCapabilityMask |= KSWORD_ARK_WIN32K_CAP_TIMER_HASH_EXPORT |
            KSWORD_ARK_WIN32K_CAP_TIMER_ENUM;
        kswordArkWin32kTimerSetDetail(
            response->detail,
            L"No live GUI process was available for the requested win32k session.");
        goto Cleanup;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        response->status = KSWORD_ARK_WIN32K_STATUS_READ_FAILED;
        response->lastStatus = STATUS_INVALID_DEVICE_STATE;
        goto Cleanup;
    }

    RtlZeroMemory(attachState, sizeof(attachState));
    KeStackAttachProcess((PVOID)sessionProcess, attachState);
    attached = TRUE;

    timerHashTable = RtlFindExportedRoutineByName(
        baseEntry.imageBase,
        "gTimerHashTable");
    if (timerHashTable == NULL ||
        !KswordARKWin32kTimerIsKernelAddress((ULONG64)(ULONG_PTR)timerHashTable)) {
        response->status = KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED;
        response->missingCapabilityMask = KSWORD_ARK_WIN32K_CAP_TIMER_HASH_EXPORT |
            KSWORD_ARK_WIN32K_CAP_TIMER_ENUM;
        response->lastStatus = STATUS_PROCEDURE_NOT_FOUND;
        kswordArkWin32kTimerSetDetail(
            response->detail,
            L"win32kbase does not expose a readable gTimerHashTable export.");
        goto Cleanup;
    }

    response->timerHashTable = (ULONG64)(ULONG_PTR)timerHashTable;
    response->capabilityMask = KSWORD_ARK_WIN32K_CAP_WIN32KBASE_LOADED |
        KSWORD_ARK_WIN32K_CAP_WIN32KFULL_LOADED |
        KSWORD_ARK_WIN32K_CAP_THREADINFO_PUBLIC |
        KSWORD_ARK_WIN32K_CAP_TIMER_HASH_EXPORT |
        KSWORD_ARK_WIN32K_CAP_TIMER_LAYOUT |
        KSWORD_ARK_WIN32K_CAP_TIMER_ENUM;
    response->status = threadMapTruncated
        ? KSWORD_ARK_WIN32K_STATUS_PARTIAL
        : KSWORD_ARK_WIN32K_STATUS_OK;
    response->lastStatus = threadMapTruncated
        ? STATUS_BUFFER_OVERFLOW
        : STATUS_SUCCESS;
    kswordArkWin32kTimerSetDetail(
        response->detail,
        layoutSelection.source == KSWORD_ARK_WIN32K_LAYOUT_SELECTION_EXACT_IDENTITY
            ? L"tagTIMER layout matched the exact PE identity; gTimerHashTable is being read in the requested GUI session."
            : L"The nearest previous tagTIMER layout and the current gTimerHashTable export are active in the requested GUI session; results may be partial.");

    seenTimers = (ULONG64*)kswordArkAllocateNonPagedPool(
        sizeof(*seenTimers) * KSWORD_ARK_WIN32K_TIMER_MAX_SEEN,
        KSWORD_ARK_WIN32K_TIMER_POOL_TAG);
    if (seenTimers == NULL) {
        response->status = KSWORD_ARK_WIN32K_STATUS_PARTIAL;
        response->lastStatus = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }
    RtlZeroMemory(seenTimers, sizeof(*seenTimers) * KSWORD_ARK_WIN32K_TIMER_MAX_SEEN);

    {
        KswordArkWiN32KTimerWalkContext context;
        RtlZeroMemory(&context, sizeof(context));
        context.response = response;
        context.layout = &response->layout;
        context.request = request;
        context.threadMap = threadMap;
        context.threadMapCount = threadMapCount;
        context.requestedSessionId = requestedSessionId;
        context.maxEntries = maxEntries;
        context.seenTimers = seenTimers;

        for (bucketIndex = 0UL;
            bucketIndex < response->layout.bucketCount && !context.stop;
            ++bucketIndex) {
            ULONG64 listHeadAddress = (ULONG64)(ULONG_PTR)timerHashTable +
                ((ULONG64)bucketIndex * (ULONG64)response->layout.bucketStride);
            kswordArkWin32kTimerWalkBucket(&context, listHeadAddress);
        }
        (VOID)RtlStringCchPrintfW(
            response->detail,
            KSWORD_ARK_WIN32K_DETAIL_CHARS,
            L"collector=session-filter-v2; session=%lu, requestPid=%lu, requestTid=%lu, threadMap=%lu, visited=%lu, accepted=%lu, unresolved=%lu.",
            requestedSessionId,
            request != NULL ? request->processId : 0UL,
            request != NULL ? request->threadId : 0UL,
            threadMapCount,
            response->visitedNodeCount,
            response->totalCount,
            context.unresolvedOwnerCount);
    }

Cleanup:
    if (attached) {
        KeUnstackDetachProcess(attachState);
        attached = FALSE;
    }
    if (sessionProcess != NULL) {
        ObDereferenceObject(sessionProcess);
        sessionProcess = NULL;
    }
    if (seenTimers != NULL) {
        ExFreePoolWithTag(seenTimers, KSWORD_ARK_WIN32K_TIMER_POOL_TAG);
    }
    if (threadMap != NULL) {
        ExFreePoolWithTag(threadMap, KSWORD_ARK_WIN32K_TIMER_POOL_TAG);
    }
    if (moduleInfo != NULL) {
        ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
    }
    UNREFERENCED_PARAMETER(moduleInfoBytes);
    *bytesWrittenOut = headerSize +
        ((size_t)response->returnedCount * sizeof(KSWORD_ARK_WIN32K_TIMER_ENTRY));
    return STATUS_SUCCESS;
}
