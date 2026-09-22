/*++

Module Name:

    win32k_message_hook.c

Abstract:

    Read-only enumeration of classic Win32 message hook chains. The collector
    walks tagTHREADINFO/DESKTOPINFO aphkStart arrays and tagHOOK nodes using an
    exact PE layout when possible, otherwise the nearest previous Windows
    profile. It never removes, unlinks, or changes a hook.

Environment:

    Kernel-mode Driver Framework

--*/

#include "win32k_query.h"
#include "win32k_support.h"
#include "../../platform/pool_compat.h"

#include <ntimage.h>

#define KSWORD_ARK_WIN32K_MESSAGE_POOL_TAG 'mWkW'
#define KSWORD_ARK_WIN32K_MESSAGE_OBJECT_SIZE 0x60UL
#define KSWORD_ARK_WIN32K_MESSAGE_HOOK_TYPE_COUNT 16UL
#define KSWORD_ARK_WIN32K_MESSAGE_MAX_THREAD_MAP 8192UL
#define KSWORD_ARK_WIN32K_MESSAGE_MAX_SEEN 8192UL
#define KSWORD_ARK_WIN32K_MESSAGE_MAX_CHAIN_DEPTH 1024UL
#define KSWORD_ARK_WIN32K_MESSAGE_MAX_PROCESS_WALK 4096UL
#define KSWORD_ARK_WIN32K_MESSAGE_MAX_THREAD_WALK 65536UL

#define KSWORD_ARK_WIN32K_MESSAGE_MODULE_ATOM_TABLE_RVA 0x003391D0UL
#define KSWORD_ARK_WIN32K_MESSAGE_MODULE_ATOM_COUNT_RVA 0x00339310UL

typedef struct KswordArkWiN32KMessageProfile
{
    KswordArkWiN32KLayoutProfileIdentity identity;
    KSWORD_ARK_WIN32K_MESSAGE_HOOK_LAYOUT layout;
} KswordArkWiN32KMessageProfile;

// Maintained from older to newer Windows versions; selects the most recent previous version when an exact identity is missing.
static const KswordArkWiN32KMessageProfile kGKswordArkWin32kMessageProfiles[] =
{
    {
        // Windows 10 22H2 reports 19045 through the enablement package while
        // win32k stays on the 19041 servicing branch.
        { 10UL, 0UL, 19041UL, 6456UL,
          0x8FC48444UL, 0x002D6000UL, 0x83C73BE4UL, 0x003B4000UL },
        { KSWORD_ARK_WIN32K_MESSAGE_OBJECT_SIZE,
          0x00UL, 0x10UL, 0x18UL, 0x28UL, 0x30UL, 0x38UL, 0x40UL,
          0x44UL, 0x48UL, 0x390UL, 0x1D0UL, 0x28UL,
          KSWORD_ARK_WIN32K_MESSAGE_MODULE_ATOM_TABLE_RVA,
          KSWORD_ARK_WIN32K_MESSAGE_MODULE_ATOM_COUNT_RVA,
          KSWORD_ARK_WIN32K_MESSAGE_HOOK_LAYOUT_SOURCE_UNKNOWN,
          0x83C73BE4UL, 0x003B4000UL }
    }
};

typedef struct KswordArkWiN32KMessageThreadMapEntry
{
    ULONG64 threadInfo;
    ULONG processId;
    ULONG threadId;
    ULONG sessionId;
} KswordArkWiN32KMessageThreadMapEntry;

typedef struct KswordArkWiN32KMessageSeenEntry
{
    ULONG64 hookObject;
    ULONG sessionId;
} KswordArkWiN32KMessageSeenEntry;

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

static BOOLEAN
KswordARKWin32kMessageIsKernelAddress(
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
kswordArkWin32kMessageReadMemory(
    _In_ ULONG64 address,
    _Out_writes_bytes_(bytesToRead) PVOID destination,
    _In_ SIZE_T bytesToRead
    )
{
    ULONG64 lastAddress = 0ULL;

    if (destination == NULL || bytesToRead == 0U ||
        bytesToRead > (SIZE_T)MAXULONG ||
        !KswordARKWin32kMessageIsKernelAddress(address) ||
        address > MAXULONGLONG - (ULONG64)(bytesToRead - 1U)) {
        return FALSE;
    }
    lastAddress = address + (ULONG64)(bytesToRead - 1U);
    if (!KswordARKWin32kMessageIsKernelAddress(lastAddress)) {
        return FALSE;
    }
    return kswordArkHookReadMemorySafe(
        (const VOID*)(ULONG_PTR)address,
        destination,
        bytesToRead);
}

static ULONG64
kswordArkWin32kMessageReadU64(
    _In_reads_bytes_(KSWORD_ARK_WIN32K_MESSAGE_OBJECT_SIZE) const UCHAR* objectBytes,
    _In_ ULONG offset
    )
{
    ULONG64 value = 0ULL;

    if (objectBytes == NULL || offset > KSWORD_ARK_WIN32K_MESSAGE_OBJECT_SIZE ||
        sizeof(value) > KSWORD_ARK_WIN32K_MESSAGE_OBJECT_SIZE - offset) {
        return 0ULL;
    }
    RtlCopyMemory(&value, objectBytes + offset, sizeof(value));
    return value;
}

static ULONG
kswordArkWin32kMessageReadU32(
    _In_reads_bytes_(KSWORD_ARK_WIN32K_MESSAGE_OBJECT_SIZE) const UCHAR* objectBytes,
    _In_ ULONG offset
    )
{
    ULONG value = 0UL;

    if (objectBytes == NULL || offset > KSWORD_ARK_WIN32K_MESSAGE_OBJECT_SIZE ||
        sizeof(value) > KSWORD_ARK_WIN32K_MESSAGE_OBJECT_SIZE - offset) {
        return 0UL;
    }
    RtlCopyMemory(&value, objectBytes + offset, sizeof(value));
    return value;
}

static VOID
kswordArkWin32kMessageSetDetail(
    _Out_writes_(KSWORD_ARK_WIN32K_DETAIL_CHARS) PWCHAR destination,
    _In_z_ PCWSTR text
    )
{
    kswordArkWin32kCopyWideText(
        destination,
        KSWORD_ARK_WIN32K_DETAIL_CHARS,
        text);
}

static VOID
kswordArkWin32kMessageInitializeLayout(
    _Out_ KSWORD_ARK_WIN32K_MESSAGE_HOOK_LAYOUT* layout,
    _In_ const KswordArkWiN32KMessageProfile* profile,
    _In_ ULONG source
    )
{
    if (layout == NULL || profile == NULL) {
        return;
    }
    *layout = profile->layout;
    layout->source = source == KSWORD_ARK_WIN32K_LAYOUT_SELECTION_EXACT_IDENTITY
        ? KSWORD_ARK_WIN32K_MESSAGE_HOOK_LAYOUT_SOURCE_VALIDATED_DISASSEMBLY
        : KSWORD_ARK_WIN32K_MESSAGE_HOOK_LAYOUT_SOURCE_NEAREST_PREVIOUS;
}

static NTSTATUS
kswordArkWin32kMessageBuildThreadMap(
    _Outptr_result_buffer_(*countOut) KswordArkWiN32KMessageThreadMapEntry** mapOut,
    _Out_ ULONG* countOut,
    _Out_ BOOLEAN* truncatedOut
    )
{
    KswordWiN32KPsGetNextProcessFn psGetNextProcess = NULL;
    KswordWiN32KPsGetNextProcessThreadFn psGetNextProcessThread = NULL;
    KswordWiN32KPsGetThreadWiN32ThreadFn psGetThreadWin32Thread = NULL;
    KswordWiN32KPsGetProcessSessionIdFn psGetProcessSessionId = NULL;
    KswordArkWiN32KMessageThreadMapEntry* map = NULL;
    PEPROCESS processCursor = NULL;
    ULONG processWalkCount = 0UL;
    ULONG count = 0UL;
    BOOLEAN truncated = FALSE;

    if (mapOut == NULL || countOut == NULL || truncatedOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *mapOut = NULL;
    *countOut = 0UL;
    *truncatedOut = FALSE;

    map = (KswordArkWiN32KMessageThreadMapEntry*)kswordArkAllocateNonPagedPool(
        sizeof(*map) * KSWORD_ARK_WIN32K_MESSAGE_MAX_THREAD_MAP,
        KSWORD_ARK_WIN32K_MESSAGE_POOL_TAG);
    if (map == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(map, sizeof(*map) * KSWORD_ARK_WIN32K_MESSAGE_MAX_THREAD_MAP);

    psGetNextProcess = kswordArkWin32kResolvePsGetNextProcess();
    psGetNextProcessThread = kswordArkWin32kResolvePsGetNextProcessThread();
    psGetThreadWin32Thread = kswordArkWin32kResolvePsGetThreadWin32Thread();
    psGetProcessSessionId = kswordArkWin32kResolvePsGetProcessSessionId();
    if (psGetNextProcess == NULL || psGetNextProcessThread == NULL ||
        psGetThreadWin32Thread == NULL) {
        ExFreePoolWithTag(map, KSWORD_ARK_WIN32K_MESSAGE_POOL_TAG);
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    processCursor = psGetNextProcess(NULL);
    while (processCursor != NULL &&
        processWalkCount < KSWORD_ARK_WIN32K_MESSAGE_MAX_PROCESS_WALK) {
        PEPROCESS nextProcess = psGetNextProcess(processCursor);
        PETHREAD threadCursor = NULL;
        ULONG threadWalkCount = 0UL;
        ULONG processId = HandleToULong(PsGetProcessId(processCursor));
        ULONG sessionId = psGetProcessSessionId != NULL
            ? psGetProcessSessionId(processCursor)
            : 0UL;

        threadCursor = psGetNextProcessThread(processCursor, NULL);
        while (threadCursor != NULL &&
            threadWalkCount < KSWORD_ARK_WIN32K_MESSAGE_MAX_THREAD_WALK) {
            PETHREAD nextThread = psGetNextProcessThread(processCursor, threadCursor);
            PVOID threadInfo = psGetThreadWin32Thread(threadCursor);

            if (threadInfo != NULL) {
                if (count >= KSWORD_ARK_WIN32K_MESSAGE_MAX_THREAD_MAP) {
                    truncated = TRUE;
                }
                else {
                    map[count].threadInfo = (ULONG64)(ULONG_PTR)threadInfo;
                    map[count].processId = processId;
                    map[count].threadId = HandleToULong(PsGetThreadId(threadCursor));
                    map[count].sessionId = sessionId;
                    count += 1UL;
                }
            }
            ObDereferenceObject(threadCursor);
            threadCursor = nextThread;
            threadWalkCount += 1UL;
        }
        if (threadCursor != NULL) {
            ObDereferenceObject(threadCursor);
            truncated = TRUE;
        }
        ObDereferenceObject(processCursor);
        processCursor = nextProcess;
        processWalkCount += 1UL;
    }
    if (processCursor != NULL) {
        ObDereferenceObject(processCursor);
        truncated = TRUE;
    }

    *mapOut = map;
    *countOut = count;
    *truncatedOut = truncated;
    return STATUS_SUCCESS;
}

static BOOLEAN
kswordArkWin32kMessageLookupThread(
    _In_reads_(threadMapCount) const KswordArkWiN32KMessageThreadMapEntry* threadMap,
    _In_ ULONG threadMapCount,
    _In_ ULONG64 threadInfo,
    _In_ ULONG preferredSessionId,
    _Out_ ULONG* processIdOut,
    _Out_ ULONG* threadIdOut,
    _Out_ ULONG* sessionIdOut
    )
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
            (preferredSessionId == 0UL || threadMap[index].sessionId == preferredSessionId)) {
            *processIdOut = threadMap[index].processId;
            *threadIdOut = threadMap[index].threadId;
            *sessionIdOut = threadMap[index].sessionId;
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN
kswordArkWin32kMessageAlreadySeen(
    _In_reads_(seenCount) const KswordArkWiN32KMessageSeenEntry* seenHooks,
    _In_ ULONG seenCount,
    _In_ ULONG64 hookObject,
    _In_ ULONG sessionId
    )
{
    ULONG index = 0UL;

    if (seenHooks == NULL || hookObject == 0ULL) {
        return FALSE;
    }
    for (index = 0UL; index < seenCount; ++index) {
        if (seenHooks[index].hookObject == hookObject &&
            seenHooks[index].sessionId == sessionId) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN
kswordArkWin32kMessageMatchesSide(
    _In_opt_ const KSWORD_ARK_WIN32K_QUERY_REQUEST* request,
    _In_ ULONG requestedSessionId,
    _In_ ULONG processId,
    _In_ ULONG threadId,
    _In_ ULONG sessionId
    )
{
    if (requestedSessionId != 0UL && sessionId != requestedSessionId) {
        return FALSE;
    }
    if (request != NULL &&
        request->processId != 0UL &&
        processId != request->processId) {
        return FALSE;
    }
    if (request != NULL &&
        request->threadId != 0UL &&
        threadId != request->threadId) {
        return FALSE;
    }
    return TRUE;
}

static BOOLEAN
kswordArkWin32kMessageMatchesRequest(
    _In_opt_ const KSWORD_ARK_WIN32K_QUERY_REQUEST* request,
    _In_ ULONG requestedSessionId,
    _In_ ULONG ownerProcessId,
    _In_ ULONG ownerThreadId,
    _In_ ULONG ownerSessionId,
    _In_ ULONG targetProcessId,
    _In_ ULONG targetThreadId,
    _In_ ULONG targetSessionId
    )
{
    ULONG matchFlags = 0UL;
    BOOLEAN matchOwner = TRUE;
    BOOLEAN matchTarget = TRUE;

    if (request != NULL) {
        matchFlags = request->flags &
            KSWORD_ARK_WIN32K_MESSAGE_HOOK_QUERY_FLAG_MATCH_MASK;
    }
    if (matchFlags != 0UL) {
        matchOwner = (matchFlags &
            KSWORD_ARK_WIN32K_MESSAGE_HOOK_QUERY_FLAG_MATCH_OWNER) != 0UL;
        matchTarget = (matchFlags &
            KSWORD_ARK_WIN32K_MESSAGE_HOOK_QUERY_FLAG_MATCH_TARGET) != 0UL;
    }

    // Treat Session/PID/TID as one predicate per side. Evaluating each field
    // independently would allow a request to pass when, for example, Session
    // matched the owner while PID matched the target even though neither side
    // satisfied the complete filter.
    return (matchOwner &&
            kswordArkWin32kMessageMatchesSide(
                request,
                requestedSessionId,
                ownerProcessId,
                ownerThreadId,
                ownerSessionId)) ||
        (matchTarget &&
            kswordArkWin32kMessageMatchesSide(
                request,
                requestedSessionId,
                targetProcessId,
                targetThreadId,
                targetSessionId));
}

static VOID
kswordArkWin32kMessageMarkPartial(
    _Inout_ KSWORD_ARK_WIN32K_HOOK_SNAPSHOT_RESPONSE* response,
    _In_ NTSTATUS status
    )
{
    if (response == NULL) {
        return;
    }
    if (response->status == KSWORD_ARK_WIN32K_STATUS_OK) {
        response->status = KSWORD_ARK_WIN32K_STATUS_PARTIAL;
    }
    if (!NT_SUCCESS(status)) {
        response->lastStatus = status;
    }
}

static VOID
kswordArkWin32kMessageWalkChain(
    _Inout_ KSWORD_ARK_WIN32K_HOOK_SNAPSHOT_RESPONSE* response,
    _In_ ULONG maxEntries,
    _Inout_updates_(KSWORD_ARK_WIN32K_MESSAGE_MAX_SEEN) KswordArkWiN32KMessageSeenEntry* seenHooks,
    _Inout_ ULONG* seenCount,
    _In_reads_(threadMapCount) const KswordArkWiN32KMessageThreadMapEntry* threadMap,
    _In_ ULONG threadMapCount,
    _In_opt_ const KSWORD_ARK_WIN32K_QUERY_REQUEST* request,
    _In_ ULONG requestedSessionId,
    _In_ ULONG discoveryProcessId,
    _In_ ULONG discoveryThreadId,
    _In_ ULONG discoverySessionId,
    _In_ ULONG64 discoveryThreadInfo,
    _In_ ULONG source,
    _In_ ULONG scope,
    _In_ LONG expectedHookType,
    _In_ ULONG64 chainHead,
    _In_ ULONG64 win32kfullBase
    )
{
    ULONG64 currentHook = 0ULL;
    ULONG depth = 0UL;

    if (response == NULL || seenHooks == NULL || seenCount == NULL ||
        chainHead == 0ULL) {
        return;
    }
    if (!kswordArkWin32kMessageReadMemory(
            chainHead,
            &currentHook,
            sizeof(currentHook)) ||
        currentHook == 0ULL) {
        return;
    }
    response->discoveredChainCount += 1UL;

    while (currentHook != 0ULL && depth < KSWORD_ARK_WIN32K_MESSAGE_MAX_CHAIN_DEPTH) {
        UCHAR objectBytes[KSWORD_ARK_WIN32K_MESSAGE_OBJECT_SIZE];
        ULONG64 nextHook = 0ULL;
        ULONG64 ownerThreadInfo = 0ULL;
        ULONG64 targetThreadInfo = 0ULL;
        ULONG ownerProcessId = 0UL;
        ULONG ownerThreadId = 0UL;
        ULONG ownerSessionId = 0UL;
        ULONG targetProcessId = 0UL;
        ULONG targetThreadId = 0UL;
        ULONG targetSessionId = 0UL;
        ULONG hookFlags = 0UL;
        ULONG hookTypeRaw = 0UL;
        ULONG moduleId = 0UL;
        ULONG moduleAtom = 0UL;
        ULONG moduleCount = 0UL;
        ULONG64 procedureOffset = 0ULL;
        BOOLEAN ownerResolved = FALSE;
        BOOLEAN targetResolved = FALSE;

        response->visitedNodeCount += 1UL;
        if (*seenCount >= KSWORD_ARK_WIN32K_MESSAGE_MAX_SEEN) {
            response->status = KSWORD_ARK_WIN32K_STATUS_BUFFER_TRUNCATED;
            response->lastStatus = STATUS_BUFFER_OVERFLOW;
            return;
        }
        if (!KswordARKWin32kMessageIsKernelAddress(currentHook)) {
            response->corruptLinkCount += 1UL;
            kswordArkWin32kMessageMarkPartial(response, STATUS_INVALID_ADDRESS);
            return;
        }
        if (kswordArkWin32kMessageAlreadySeen(
                seenHooks,
                *seenCount,
                currentHook,
                discoverySessionId)) {
            response->duplicateCount += 1UL;
            return;
        }
        seenHooks[*seenCount].hookObject = currentHook;
        seenHooks[*seenCount].sessionId = discoverySessionId;
        *seenCount += 1UL;

        if (!kswordArkWin32kMessageReadMemory(
                currentHook,
                objectBytes,
                sizeof(objectBytes))) {
            response->readFailureCount += 1UL;
            kswordArkWin32kMessageMarkPartial(response, STATUS_PARTIAL_COPY);
            return;
        }

        nextHook = kswordArkWin32kMessageReadU64(
            objectBytes,
            response->layout.nextHook);
        ownerThreadInfo = kswordArkWin32kMessageReadU64(
            objectBytes,
            response->layout.ownerThreadInfo);
        targetThreadInfo = kswordArkWin32kMessageReadU64(
            objectBytes,
            response->layout.targetThreadInfo);
        hookTypeRaw = kswordArkWin32kMessageReadU32(
            objectBytes,
            response->layout.hookType);
        hookFlags = kswordArkWin32kMessageReadU32(
            objectBytes,
            response->layout.flags);
        moduleId = kswordArkWin32kMessageReadU32(
            objectBytes,
            response->layout.moduleId);
        procedureOffset = kswordArkWin32kMessageReadU64(
            objectBytes,
            response->layout.procedureOffset);

        ownerResolved = kswordArkWin32kMessageLookupThread(
            threadMap,
            threadMapCount,
            ownerThreadInfo,
            discoverySessionId,
            &ownerProcessId,
            &ownerThreadId,
            &ownerSessionId);
        targetResolved = kswordArkWin32kMessageLookupThread(
            threadMap,
            threadMapCount,
            targetThreadInfo,
            discoverySessionId,
            &targetProcessId,
            &targetThreadId,
            &targetSessionId);
        if (!ownerResolved && ownerThreadInfo == discoveryThreadInfo) {
            ownerProcessId = discoveryProcessId;
            ownerThreadId = discoveryThreadId;
            ownerSessionId = discoverySessionId;
            ownerResolved = TRUE;
        }
        if (!targetResolved && scope == KSWORD_ARK_WIN32K_MESSAGE_HOOK_SCOPE_THREAD) {
            targetProcessId = discoveryProcessId;
            targetThreadId = discoveryThreadId;
            targetSessionId = discoverySessionId;
        }

        if ((LONG)hookTypeRaw != expectedHookType) {
            response->corruptLinkCount += 1UL;
            kswordArkWin32kMessageMarkPartial(response, STATUS_DATA_ERROR);
        }

        if ((LONG)moduleId >= 0 &&
            kswordArkWin32kMessageReadMemory(
                win32kfullBase + response->layout.moduleAtomCountRva,
                &moduleCount,
                sizeof(moduleCount)) &&
            moduleCount <= 0x1000UL &&
            moduleId < moduleCount) {
            USHORT atomValue = 0U;
            if (kswordArkWin32kMessageReadMemory(
                    win32kfullBase + response->layout.moduleAtomTableRva +
                        ((ULONG64)moduleId * sizeof(atomValue)),
                    &atomValue,
                    sizeof(atomValue))) {
                moduleAtom = atomValue;
            }
        }

        if (kswordArkWin32kMessageMatchesRequest(
                request,
                requestedSessionId,
                ownerProcessId,
                ownerThreadId,
                ownerSessionId,
                targetProcessId,
                targetThreadId,
                targetSessionId)) {
            KSWORD_ARK_WIN32K_HOOK_ENTRY* entry = NULL;

            response->totalCount += 1UL;
            if (response->returnedCount >= maxEntries) {
                response->status = KSWORD_ARK_WIN32K_STATUS_BUFFER_TRUNCATED;
                response->lastStatus = STATUS_BUFFER_OVERFLOW;
                return;
            }

            entry = &response->entries[response->returnedCount++];
            RtlZeroMemory(entry, sizeof(*entry));
            entry->source = source;
            entry->status = ownerResolved
                ? KSWORD_ARK_WIN32K_STATUS_OK
                : KSWORD_ARK_WIN32K_STATUS_PARTIAL;
            entry->flags = hookFlags;
            entry->sessionId = ownerSessionId != 0UL
                ? ownerSessionId
                : discoverySessionId;
            entry->processId = ownerProcessId;
            entry->threadId = ownerThreadId;
            entry->hookType = hookTypeRaw;
            entry->hookScope = scope;
            entry->lastStatus = ownerResolved ? STATUS_SUCCESS : STATUS_NOT_FOUND;
            entry->fieldFlags = KSWORD_ARK_WIN32K_MESSAGE_HOOK_FIELD_HANDLE |
                KSWORD_ARK_WIN32K_MESSAGE_HOOK_FIELD_OWNER |
                KSWORD_ARK_WIN32K_MESSAGE_HOOK_FIELD_DESKTOP |
                KSWORD_ARK_WIN32K_MESSAGE_HOOK_FIELD_NEXT |
                KSWORD_ARK_WIN32K_MESSAGE_HOOK_FIELD_TYPE |
                KSWORD_ARK_WIN32K_MESSAGE_HOOK_FIELD_PROCEDURE |
                KSWORD_ARK_WIN32K_MESSAGE_HOOK_FIELD_FLAGS |
                KSWORD_ARK_WIN32K_MESSAGE_HOOK_FIELD_MODULE |
                KSWORD_ARK_WIN32K_MESSAGE_HOOK_FIELD_TARGET |
                KSWORD_ARK_WIN32K_MESSAGE_HOOK_FIELD_CHAIN;
            entry->hookObject = currentHook;
            entry->chainHead = chainHead;
            entry->nextHookObject = nextHook;
            entry->threadInfo = ownerThreadInfo;
            entry->targetThreadInfo = targetThreadInfo;
            entry->desktopObject = kswordArkWin32kMessageReadU64(
                objectBytes,
                response->layout.desktopObject);
            entry->procedureAddress = (LONG)moduleId < 0
                ? procedureOffset
                : 0ULL;
            entry->moduleBase = 0ULL;
            entry->hookHandle = kswordArkWin32kMessageReadU64(
                objectBytes,
                response->layout.handle);
            entry->procedureOffset = procedureOffset;
            entry->moduleId = moduleId;
            entry->moduleAtom = moduleAtom;
            entry->targetProcessId = targetProcessId;
            entry->targetThreadId = targetThreadId;
            entry->targetSessionId = targetSessionId;
            kswordArkWin32kMessageSetDetail(
                entry->detail,
                ownerResolved
                    ? L"tagHOOK owner mapped through PsGetThreadWin32Thread; chain was read only."
                    : L"tagHOOK fields read; owner ThreadInfo was not found in the public thread map.");
        }

        if (nextHook != 0ULL &&
            (!KswordARKWin32kMessageIsKernelAddress(nextHook) ||
                nextHook == currentHook)) {
            response->corruptLinkCount += 1UL;
            kswordArkWin32kMessageMarkPartial(response, STATUS_DATA_ERROR);
            return;
        }
        currentHook = nextHook;
        depth += 1UL;
    }

    if (currentHook != 0ULL) {
        response->status = KSWORD_ARK_WIN32K_STATUS_BUFFER_TRUNCATED;
        response->lastStatus = STATUS_BUFFER_OVERFLOW;
    }
}

NTSTATUS
kswordArkWin32kQueryHookSnapshot(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_WIN32K_QUERY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
{
    KswHookSystemModuleInformation* moduleInfo = NULL;
    KswHookSystemModuleEntry baseEntry;
    KswHookSystemModuleEntry fullEntry;
    IMAGE_NT_HEADERS baseHeaders;
    IMAGE_NT_HEADERS fullHeaders;
    KswordArkWiN32KLayoutSelection layoutSelection;
    const KswordArkWiN32KMessageProfile* layoutProfile = NULL;
    KSWORD_ARK_WIN32K_HOOK_SNAPSHOT_RESPONSE* response = NULL;
    KswordArkWiN32KMessageThreadMapEntry* threadMap = NULL;
    KswordArkWiN32KMessageSeenEntry* seenHooks = NULL;
    KswordWiN32KPsGetNextProcessFn psGetNextProcess = NULL;
    KswordWiN32KPsGetNextProcessThreadFn psGetNextProcessThread = NULL;
    KswordWiN32KPsGetThreadWiN32ThreadFn psGetThreadWin32Thread = NULL;
    KswordWiN32KPsGetProcessSessionIdFn psGetProcessSessionId = NULL;
    PEPROCESS processCursor = NULL;
    ULONG moduleInfoBytes = 0UL;
    ULONG threadMapCount = 0UL;
    ULONG seenCount = 0UL;
    ULONG maxEntries = KSWORD_ARK_WIN32K_MESSAGE_HOOK_DEFAULT_MAX_ENTRIES;
    ULONG requestedSessionId = 0UL;
    ULONG processWalkCount = 0UL;
    size_t headerSize = 0U;
    size_t entryCapacity = 0U;
    BOOLEAN threadMapTruncated = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (bytesWrittenOut == NULL || outputBuffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    headerSize = sizeof(KSWORD_ARK_WIN32K_HOOK_SNAPSHOT_RESPONSE) -
        sizeof(KSWORD_ARK_WIN32K_HOOK_ENTRY);
    if (outputBufferLength < headerSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_WIN32K_HOOK_SNAPSHOT_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_WIN32K_PROTOCOL_VERSION;
    response->status = KSWORD_ARK_WIN32K_STATUS_UNKNOWN;
    response->entrySize = sizeof(KSWORD_ARK_WIN32K_HOOK_ENTRY);
    response->flags = request != NULL ? request->flags : 0UL;
    response->lastStatus = STATUS_SUCCESS;
    kswordArkWin32kInitializeOffsets(&response->fieldOffsets);

    entryCapacity = (outputBufferLength - headerSize) /
        sizeof(KSWORD_ARK_WIN32K_HOOK_ENTRY);
    maxEntries = request != NULL && request->maxEntries != 0UL
        ? kswordArkWin32kNormalizeMaxEntries(request->maxEntries)
        : KSWORD_ARK_WIN32K_MESSAGE_HOOK_DEFAULT_MAX_ENTRIES;
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
        response->missingCapabilityMask = KSWORD_ARK_WIN32K_CAP_MESSAGE_HOOK_LAYOUT |
            KSWORD_ARK_WIN32K_CAP_MESSAGE_HOOK_ENUM |
            KSWORD_ARK_WIN32K_CAP_MESSAGE_HOOK_MODULE_TABLE;
        response->lastStatus = NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
        kswordArkWin32kMessageSetDetail(
            response->detail,
            L"win32kbase/win32kfull could not be located; message hooks were not read.");
        goto Cleanup;
    }

    RtlZeroMemory(&baseHeaders, sizeof(baseHeaders));
    RtlZeroMemory(&fullHeaders, sizeof(fullHeaders));
    if (!kswordArkHookReadImageNtHeaders(&baseEntry, &baseHeaders) ||
        !kswordArkHookReadImageNtHeaders(&fullEntry, &fullHeaders)) {
        response->status = KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED;
        response->missingCapabilityMask = KSWORD_ARK_WIN32K_CAP_MESSAGE_HOOK_LAYOUT |
            KSWORD_ARK_WIN32K_CAP_MESSAGE_HOOK_ENUM;
        response->lastStatus = STATUS_INVALID_IMAGE_FORMAT;
        kswordArkWin32kMessageSetDetail(
            response->detail,
            L"win32k PE headers could not be read; tagHOOK layout was not guessed.");
        goto Cleanup;
    }

    response->win32kbaseTimeDateStamp = baseHeaders.FileHeader.TimeDateStamp;
    response->win32kbaseImageSize = baseHeaders.OptionalHeader.SizeOfImage;
    response->win32kfullTimeDateStamp = fullHeaders.FileHeader.TimeDateStamp;
    response->win32kfullImageSize = fullHeaders.OptionalHeader.SizeOfImage;
    if (!kswordArkWin32kSelectLayoutProfile(
            kGKswordArkWin32kMessageProfiles,
            RTL_NUMBER_OF(kGKswordArkWin32kMessageProfiles),
            sizeof(kGKswordArkWin32kMessageProfiles[0]),
            response->win32kbaseTimeDateStamp,
            response->win32kbaseImageSize,
            response->win32kfullTimeDateStamp,
            response->win32kfullImageSize,
            &layoutSelection)) {
        response->status = KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED;
        response->missingCapabilityMask = KSWORD_ARK_WIN32K_CAP_MESSAGE_HOOK_LAYOUT |
            KSWORD_ARK_WIN32K_CAP_MESSAGE_HOOK_ENUM;
        response->lastStatus = STATUS_REVISION_MISMATCH;
        kswordArkWin32kMessageSetDetail(
            response->detail,
            L"No exact or nearest-previous Windows tagHOOK profile is available.");
        goto Cleanup;
    }
    layoutProfile = &kGKswordArkWin32kMessageProfiles[layoutSelection.profileIndex];

    kswordArkWin32kMessageInitializeLayout(
        &response->layout,
        layoutProfile,
        layoutSelection.source);
    if (response->layout.objectSize == 0UL ||
        response->layout.objectSize > KSWORD_ARK_WIN32K_MESSAGE_OBJECT_SIZE ||
        response->layout.threadHookArray > 0x1000UL ||
        response->layout.threadDesktopInfo > 0x1000UL ||
        response->layout.desktopHookArray > 0x1000UL) {
        response->status = KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED;
        response->missingCapabilityMask = KSWORD_ARK_WIN32K_CAP_MESSAGE_HOOK_LAYOUT |
            KSWORD_ARK_WIN32K_CAP_MESSAGE_HOOK_ENUM;
        response->lastStatus = STATUS_INVALID_PARAMETER;
        kswordArkWin32kMessageSetDetail(
            response->detail,
            L"Selected tagHOOK profile failed local object and owner-layout validation.");
        goto Cleanup;
    }
    response->fieldOffsets.tagHookNext = response->layout.nextHook;
    response->fieldOffsets.tagHookType = response->layout.hookType;
    response->fieldOffsets.tagHookProcedure = response->layout.procedureOffset;
    response->fieldOffsets.tagHookTargetThreadInfo = response->layout.targetThreadInfo;
    if ((ULONG64)response->layout.moduleAtomTableRva + sizeof(USHORT) >
            (ULONG64)response->win32kfullImageSize ||
        (ULONG64)response->layout.moduleAtomCountRva + sizeof(ULONG) >
            (ULONG64)response->win32kfullImageSize) {
        response->status = KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED;
        response->missingCapabilityMask = KSWORD_ARK_WIN32K_CAP_MESSAGE_HOOK_MODULE_TABLE |
            KSWORD_ARK_WIN32K_CAP_MESSAGE_HOOK_ENUM;
        response->lastStatus = STATUS_INVALID_ADDRESS;
        kswordArkWin32kMessageSetDetail(
            response->detail,
            L"Message hook module atom globals are outside the verified win32kfull image.");
        goto Cleanup;
    }

    status = kswordArkWin32kMessageBuildThreadMap(
        &threadMap,
        &threadMapCount,
        &threadMapTruncated);
    if (!NT_SUCCESS(status)) {
        response->status = KSWORD_ARK_WIN32K_STATUS_READ_FAILED;
        response->missingCapabilityMask = KSWORD_ARK_WIN32K_CAP_MESSAGE_HOOK_ENUM;
        response->lastStatus = status;
        kswordArkWin32kMessageSetDetail(
            response->detail,
            L"GUI thread map could not be built; message hook chains were not read.");
        goto Cleanup;
    }

    seenHooks = (KswordArkWiN32KMessageSeenEntry*)kswordArkAllocateNonPagedPool(
        sizeof(*seenHooks) * KSWORD_ARK_WIN32K_MESSAGE_MAX_SEEN,
        KSWORD_ARK_WIN32K_MESSAGE_POOL_TAG);
    if (seenHooks == NULL) {
        response->status = KSWORD_ARK_WIN32K_STATUS_READ_FAILED;
        response->lastStatus = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }
    RtlZeroMemory(
        seenHooks,
        sizeof(*seenHooks) * KSWORD_ARK_WIN32K_MESSAGE_MAX_SEEN);

    psGetNextProcess = kswordArkWin32kResolvePsGetNextProcess();
    psGetNextProcessThread = kswordArkWin32kResolvePsGetNextProcessThread();
    psGetThreadWin32Thread = kswordArkWin32kResolvePsGetThreadWin32Thread();
    psGetProcessSessionId = kswordArkWin32kResolvePsGetProcessSessionId();
    if (psGetNextProcess == NULL || psGetNextProcessThread == NULL ||
        psGetThreadWin32Thread == NULL) {
        response->status = KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED;
        response->missingCapabilityMask = KSWORD_ARK_WIN32K_CAP_MESSAGE_HOOK_ENUM;
        response->lastStatus = STATUS_PROCEDURE_NOT_FOUND;
        goto Cleanup;
    }

    if (request != NULL && request->sessionId != 0UL) {
        requestedSessionId = request->sessionId;
    }
    else if (request != NULL &&
        (request->flags & KSWORD_ARK_WIN32K_QUERY_FLAG_CURRENT_SESSION_ONLY) != 0UL &&
        psGetProcessSessionId != NULL) {
        requestedSessionId = psGetProcessSessionId(PsGetCurrentProcess());
    }

    response->capabilityMask = KSWORD_ARK_WIN32K_CAP_WIN32KBASE_LOADED |
        KSWORD_ARK_WIN32K_CAP_WIN32KFULL_LOADED |
        KSWORD_ARK_WIN32K_CAP_THREADINFO_PUBLIC |
        KSWORD_ARK_WIN32K_CAP_HOOK_PROFILE |
        KSWORD_ARK_WIN32K_CAP_MESSAGE_HOOK_LAYOUT |
        KSWORD_ARK_WIN32K_CAP_MESSAGE_HOOK_ENUM |
        KSWORD_ARK_WIN32K_CAP_MESSAGE_HOOK_MODULE_TABLE;
    response->status = threadMapTruncated
        ? KSWORD_ARK_WIN32K_STATUS_PARTIAL
        : KSWORD_ARK_WIN32K_STATUS_OK;
    response->lastStatus = threadMapTruncated
        ? STATUS_BUFFER_OVERFLOW
        : STATUS_SUCCESS;
    kswordArkWin32kMessageSetDetail(
        response->detail,
        layoutSelection.source == KSWORD_ARK_WIN32K_LAYOUT_SELECTION_EXACT_IDENTITY
            ? L"tagHOOK layout matched the exact PE identity; thread and desktop chains are read only and bounded."
            : L"Exact tagHOOK identity was missing; the nearest previous Windows layout is active. Results are read only, bounded, and may be partial.");

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        response->status = KSWORD_ARK_WIN32K_STATUS_READ_FAILED;
        response->lastStatus = STATUS_INVALID_DEVICE_STATE;
        goto Cleanup;
    }

    processCursor = psGetNextProcess(NULL);
    while (processCursor != NULL &&
        processWalkCount < KSWORD_ARK_WIN32K_MESSAGE_MAX_PROCESS_WALK &&
        response->status != KSWORD_ARK_WIN32K_STATUS_BUFFER_TRUNCATED) {
        PEPROCESS nextProcess = psGetNextProcess(processCursor);
        PETHREAD threadCursor = NULL;
        ULONG threadWalkCount = 0UL;
        ULONG processId = HandleToULong(PsGetProcessId(processCursor));
        ULONG sessionId = psGetProcessSessionId != NULL
            ? psGetProcessSessionId(processCursor)
            : 0UL;
        DECLSPEC_ALIGN(16) UCHAR attachState[128];
        BOOLEAN attached = FALSE;

        if (requestedSessionId == 0UL || sessionId == requestedSessionId) {
            RtlZeroMemory(attachState, sizeof(attachState));
            KeStackAttachProcess((PVOID)processCursor, attachState);
            attached = TRUE;

            threadCursor = psGetNextProcessThread(processCursor, NULL);
            while (threadCursor != NULL &&
                threadWalkCount < KSWORD_ARK_WIN32K_MESSAGE_MAX_THREAD_WALK &&
                response->status != KSWORD_ARK_WIN32K_STATUS_BUFFER_TRUNCATED) {
                PETHREAD nextThread = psGetNextProcessThread(processCursor, threadCursor);
                ULONG threadId = HandleToULong(PsGetThreadId(threadCursor));
                ULONG64 threadInfo = (ULONG64)(ULONG_PTR)psGetThreadWin32Thread(threadCursor);
                ULONG64 desktopInfo = 0ULL;
                ULONG hookIndex = 0UL;

                if (threadInfo != 0ULL &&
                    KswordARKWin32kMessageIsKernelAddress(threadInfo)) {
                    (VOID)kswordArkWin32kMessageReadMemory(
                        threadInfo + response->layout.threadDesktopInfo,
                        &desktopInfo,
                        sizeof(desktopInfo));

                    for (hookIndex = 0UL;
                        hookIndex < KSWORD_ARK_WIN32K_MESSAGE_HOOK_TYPE_COUNT &&
                        response->status != KSWORD_ARK_WIN32K_STATUS_BUFFER_TRUNCATED;
                        ++hookIndex) {
                        LONG hookType = (LONG)hookIndex - 1L;
                        ULONG64 threadChainHead = threadInfo +
                            response->layout.threadHookArray +
                            ((ULONG64)hookIndex * sizeof(ULONG64));

                        kswordArkWin32kMessageWalkChain(
                            response,
                            maxEntries,
                            seenHooks,
                            &seenCount,
                            threadMap,
                            threadMapCount,
                            request,
                            requestedSessionId,
                            processId,
                            threadId,
                            sessionId,
                            threadInfo,
                            KSWORD_ARK_WIN32K_MESSAGE_HOOK_SOURCE_THREAD,
                            KSWORD_ARK_WIN32K_MESSAGE_HOOK_SCOPE_THREAD,
                            hookType,
                            threadChainHead,
                            (ULONG64)(ULONG_PTR)fullEntry.imageBase);

                        if (desktopInfo != 0ULL &&
                            KswordARKWin32kMessageIsKernelAddress(desktopInfo)) {
                            ULONG64 desktopChainHead = desktopInfo +
                                response->layout.desktopHookArray +
                                ((ULONG64)hookIndex * sizeof(ULONG64));
                            kswordArkWin32kMessageWalkChain(
                                response,
                                maxEntries,
                                seenHooks,
                                &seenCount,
                                threadMap,
                                threadMapCount,
                                request,
                                requestedSessionId,
                                processId,
                                threadId,
                                sessionId,
                                threadInfo,
                                KSWORD_ARK_WIN32K_MESSAGE_HOOK_SOURCE_GLOBAL,
                                KSWORD_ARK_WIN32K_MESSAGE_HOOK_SCOPE_GLOBAL,
                                hookType,
                                desktopChainHead,
                                (ULONG64)(ULONG_PTR)fullEntry.imageBase);
                        }
                    }
                }

                ObDereferenceObject(threadCursor);
                threadCursor = nextThread;
                threadWalkCount += 1UL;
            }
            if (threadCursor != NULL) {
                ObDereferenceObject(threadCursor);
                kswordArkWin32kMessageMarkPartial(response, STATUS_BUFFER_OVERFLOW);
            }
        }

        if (attached) {
            KeUnstackDetachProcess(attachState);
        }
        ObDereferenceObject(processCursor);
        processCursor = nextProcess;
        processWalkCount += 1UL;
    }
    if (processCursor != NULL) {
        ObDereferenceObject(processCursor);
        if (response->status != KSWORD_ARK_WIN32K_STATUS_BUFFER_TRUNCATED) {
            kswordArkWin32kMessageMarkPartial(response, STATUS_BUFFER_OVERFLOW);
        }
    }

Cleanup:
    if (seenHooks != NULL) {
        ExFreePoolWithTag(seenHooks, KSWORD_ARK_WIN32K_MESSAGE_POOL_TAG);
    }
    if (threadMap != NULL) {
        ExFreePoolWithTag(threadMap, KSWORD_ARK_WIN32K_MESSAGE_POOL_TAG);
    }
    if (moduleInfo != NULL) {
        ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
    }
    UNREFERENCED_PARAMETER(moduleInfoBytes);
    *bytesWrittenOut = headerSize +
        ((size_t)response->returnedCount * sizeof(KSWORD_ARK_WIN32K_HOOK_ENTRY));
    return STATUS_SUCCESS;
}
