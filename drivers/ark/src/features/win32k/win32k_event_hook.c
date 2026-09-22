/*++

Module Name:

    win32k_event_hook.c

Abstract:

    Read-only enumeration of tagEVENTHOOK objects through
    win32kbase!gpWinEventHooks. The collector prefers exact PE identity and can
    fall back to the nearest previous Windows layout. It never changes a node.

Environment:

    Kernel-mode Driver Framework

--*/

#include "win32k_query.h"
#include "win32k_support.h"
#include "../../platform/pool_compat.h"

#include <ntimage.h>
#include <ntstrsafe.h>

#define KSWORD_ARK_WIN32K_EVENT_POOL_TAG 'eWkW'
#define KSWORD_ARK_WIN32K_EVENT_OBJECT_SIZE 0x60UL
#define KSWORD_ARK_WIN32K_EVENT_GLOBAL_RVA 0x00257EE8UL
#define KSWORD_ARK_WIN32K_EVENT_MAX_THREAD_MAP 8192UL
#define KSWORD_ARK_WIN32K_EVENT_MAX_SEEN 8192UL
#define KSWORD_ARK_WIN32K_EVENT_INTERNAL_PUBLIC_MASK 0x0000001EUL
#define KSWORD_ARK_WIN32K_EVENT_INTERNAL_IN_CONTEXT 0x00000008UL

typedef struct KswordArkWiN32KEventProfile
{
    KswordArkWiN32KLayoutProfileIdentity identity;
    KSWORD_ARK_WIN32K_EVENT_HOOK_LAYOUT layout;
} KswordArkWiN32KEventProfile;

// Maintained from older to newer Windows versions; selects the most recent previous version when an exact identity is missing.
static const KswordArkWiN32KEventProfile kGKswordArkWin32kEventProfiles[] =
{
    {
        // Windows 10 22H2 reports 19045 through the enablement package while
        // win32k stays on the 19041 servicing branch.
        { 10UL, 0UL, 19041UL, 6456UL,
          0x8FC48444UL, 0x002D6000UL, 0x83C73BE4UL, 0x003B4000UL },
        { KSWORD_ARK_WIN32K_EVENT_OBJECT_SIZE,
          0x00UL, 0x10UL, 0x18UL, 0x20UL, 0x24UL, 0x28UL,
          0x30UL, 0x38UL, 0x40UL, 0x48UL, 0x58UL,
          KSWORD_ARK_WIN32K_EVENT_GLOBAL_RVA,
          KSWORD_ARK_WIN32K_EVENT_HOOK_LAYOUT_SOURCE_UNKNOWN,
          0x83C73BE4UL, 0x003B4000UL }
    }
};

typedef KswordArkWiN32KGuiThreadMapEntry
    KswordArkWiN32KEventThreadMapEntry;

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

NTSYSAPI
PVOID
NTAPI
RtlFindExportedRoutineByName(
    _In_ PVOID imageBase,
    _In_z_ PCSTR routineName
    );

static BOOLEAN
kswordArkWin32kEventIsKernelAddress(
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
kswordArkWin32kEventReadMemory(
    _In_ ULONG64 address,
    _Out_writes_bytes_(bytesToRead) PVOID destination,
    _In_ SIZE_T bytesToRead
    )
{
    ULONG64 lastAddress = 0ULL;

    if (destination == NULL || bytesToRead == 0U ||
        bytesToRead > (SIZE_T)MAXULONG ||
        !kswordArkWin32kEventIsKernelAddress(address) ||
        address > MAXULONGLONG - (ULONG64)(bytesToRead - 1U)) {
        return FALSE;
    }
    lastAddress = address + (ULONG64)(bytesToRead - 1U);
    if (!kswordArkWin32kEventIsKernelAddress(lastAddress)) {
        return FALSE;
    }
    return kswordArkHookReadMemorySafe(
        (const VOID*)(ULONG_PTR)address,
        destination,
        bytesToRead);
}

static ULONG64
kswordArkWin32kEventReadU64(
    _In_reads_bytes_(KSWORD_ARK_WIN32K_EVENT_OBJECT_SIZE) const UCHAR* objectBytes,
    _In_ ULONG offset
    )
{
    ULONG64 value = 0ULL;

    if (objectBytes == NULL || offset > KSWORD_ARK_WIN32K_EVENT_OBJECT_SIZE ||
        sizeof(value) > KSWORD_ARK_WIN32K_EVENT_OBJECT_SIZE - offset) {
        return 0ULL;
    }
    RtlCopyMemory(&value, objectBytes + offset, sizeof(value));
    return value;
}

static ULONG
kswordArkWin32kEventReadU32(
    _In_reads_bytes_(KSWORD_ARK_WIN32K_EVENT_OBJECT_SIZE) const UCHAR* objectBytes,
    _In_ ULONG offset
    )
{
    ULONG value = 0UL;

    if (objectBytes == NULL || offset > KSWORD_ARK_WIN32K_EVENT_OBJECT_SIZE ||
        sizeof(value) > KSWORD_ARK_WIN32K_EVENT_OBJECT_SIZE - offset) {
        return 0UL;
    }
    RtlCopyMemory(&value, objectBytes + offset, sizeof(value));
    return value;
}

static VOID
kswordArkWin32kEventSetDetail(
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
kswordArkWin32kEventInitializeLayout(
    _Out_ KSWORD_ARK_WIN32K_EVENT_HOOK_LAYOUT* layout,
    _In_ const KswordArkWiN32KEventProfile* profile,
    _In_ ULONG source
    )
{
    if (layout == NULL || profile == NULL) {
        return;
    }
    *layout = profile->layout;
    layout->source = source == KSWORD_ARK_WIN32K_LAYOUT_SELECTION_EXACT_IDENTITY
        ? KSWORD_ARK_WIN32K_EVENT_HOOK_LAYOUT_SOURCE_VALIDATED_DISASSEMBLY
        : KSWORD_ARK_WIN32K_EVENT_HOOK_LAYOUT_SOURCE_NEAREST_PREVIOUS;
}

static NTSTATUS
kswordArkWin32kEventBuildThreadMap(
    _Outptr_result_buffer_(*countOut) KswordArkWiN32KEventThreadMapEntry** mapOut,
    _Out_ ULONG* countOut,
    _Out_ BOOLEAN* truncatedOut
    )
{
    return kswordArkWin32kBuildGuiThreadMap(
        KSWORD_ARK_WIN32K_EVENT_MAX_THREAD_MAP,
        KSWORD_ARK_WIN32K_EVENT_POOL_TAG,
        mapOut,
        countOut,
        truncatedOut);
}

static NTSTATUS
kswordArkWin32kEventReferenceSessionProcess(
    _In_reads_(threadMapCount) const KswordArkWiN32KEventThreadMapEntry* threadMap,
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
            const KswordArkWiN32KEventThreadMapEntry* entry = &threadMap[index];
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
kswordArkWin32kEventLookupThread(
    _In_reads_(threadMapCount) const KswordArkWiN32KEventThreadMapEntry* threadMap,
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
kswordArkWin32kEventAlreadySeen(
    _In_reads_(seenCount) const ULONG64* seenHooks,
    _In_ ULONG seenCount,
    _In_ ULONG64 hookAddress
    )
{
    ULONG index = 0UL;

    if (seenHooks == NULL || hookAddress == 0ULL) {
        return FALSE;
    }
    for (index = 0UL; index < seenCount; ++index) {
        if (seenHooks[index] == hookAddress) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN
kswordArkWin32kEventMatchesRequest(
    _In_opt_ const KSWORD_ARK_WIN32K_QUERY_REQUEST* request,
    _In_ ULONG processId,
    _In_ ULONG threadId,
    _In_ BOOLEAN ownerResolved
    )
{
    if (request != NULL && request->processId != 0UL &&
        (!ownerResolved || request->processId != processId)) {
        return FALSE;
    }
    if (request != NULL && request->threadId != 0UL &&
        (!ownerResolved || request->threadId != threadId)) {
        return FALSE;
    }
    return TRUE;
}

NTSTATUS
kswordArkWin32kQueryEventHookSnapshot(
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
    const KswordArkWiN32KEventProfile* layoutProfile = NULL;
    KSWORD_ARK_WIN32K_EVENT_HOOK_SNAPSHOT_RESPONSE* response = NULL;
    KswordArkWiN32KEventThreadMapEntry* threadMap = NULL;
    ULONG64* seenHooks = NULL;
    PEPROCESS sessionProcess = NULL;
    PVOID hookListExport = NULL;
    ULONG64 hookListPointer = 0ULL;
    ULONG64 currentHook = 0ULL;
    ULONG moduleInfoBytes = 0UL;
    ULONG threadMapCount = 0UL;
    ULONG seenCount = 0UL;
    ULONG maxEntries = KSWORD_ARK_WIN32K_DEFAULT_MAX_ENTRIES;
    ULONG requestedSessionId = 0UL;
    ULONG unresolvedOwnerCount = 0UL;
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
    headerSize = sizeof(KSWORD_ARK_WIN32K_EVENT_HOOK_SNAPSHOT_RESPONSE) -
        sizeof(KSWORD_ARK_WIN32K_EVENT_HOOK_ENTRY);
    if (outputBufferLength < headerSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_WIN32K_EVENT_HOOK_SNAPSHOT_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_WIN32K_PROTOCOL_VERSION;
    response->status = KSWORD_ARK_WIN32K_STATUS_UNKNOWN;
    response->entrySize = sizeof(KSWORD_ARK_WIN32K_EVENT_HOOK_ENTRY);
    response->flags = request != NULL ? request->flags : 0UL;
    response->lastStatus = STATUS_SUCCESS;
    entryCapacity = (outputBufferLength - headerSize) /
        sizeof(KSWORD_ARK_WIN32K_EVENT_HOOK_ENTRY);
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
        response->missingCapabilityMask = KSWORD_ARK_WIN32K_CAP_EVENT_HOOK_GLOBAL |
            KSWORD_ARK_WIN32K_CAP_EVENT_HOOK_LAYOUT |
            KSWORD_ARK_WIN32K_CAP_EVENT_HOOK_ENUM;
        response->lastStatus = NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
        goto Cleanup;
    }

    RtlZeroMemory(&baseHeaders, sizeof(baseHeaders));
    RtlZeroMemory(&fullHeaders, sizeof(fullHeaders));
    if (!kswordArkHookReadImageNtHeaders(&baseEntry, &baseHeaders) ||
        !kswordArkHookReadImageNtHeaders(&fullEntry, &fullHeaders)) {
        response->status = KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED;
        response->missingCapabilityMask = KSWORD_ARK_WIN32K_CAP_EVENT_HOOK_LAYOUT |
            KSWORD_ARK_WIN32K_CAP_EVENT_HOOK_ENUM;
        response->lastStatus = STATUS_INVALID_IMAGE_FORMAT;
        kswordArkWin32kEventSetDetail(
            response->detail,
            L"win32k PE header could not be read; tagEVENTHOOK layout was not guessed.");
        goto Cleanup;
    }

    response->win32kbaseTimeDateStamp = baseHeaders.FileHeader.TimeDateStamp;
    response->win32kbaseImageSize = baseHeaders.OptionalHeader.SizeOfImage;
    response->win32kfullTimeDateStamp = fullHeaders.FileHeader.TimeDateStamp;
    response->win32kfullImageSize = fullHeaders.OptionalHeader.SizeOfImage;
    if (!kswordArkWin32kSelectLayoutProfile(
            kGKswordArkWin32kEventProfiles,
            RTL_NUMBER_OF(kGKswordArkWin32kEventProfiles),
            sizeof(kGKswordArkWin32kEventProfiles[0]),
            response->win32kbaseTimeDateStamp,
            response->win32kbaseImageSize,
            response->win32kfullTimeDateStamp,
            response->win32kfullImageSize,
            &layoutSelection)) {
        response->status = KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED;
        response->missingCapabilityMask = KSWORD_ARK_WIN32K_CAP_EVENT_HOOK_LAYOUT |
            KSWORD_ARK_WIN32K_CAP_EVENT_HOOK_ENUM;
        response->lastStatus = STATUS_REVISION_MISMATCH;
        kswordArkWin32kEventSetDetail(
            response->detail,
            L"No exact or nearest-previous Windows tagEVENTHOOK profile is available.");
        goto Cleanup;
    }
    layoutProfile = &kGKswordArkWin32kEventProfiles[layoutSelection.profileIndex];

    kswordArkWin32kEventInitializeLayout(
        &response->layout,
        layoutProfile,
        layoutSelection.source);
    if (response->layout.objectSize == 0UL ||
        response->layout.objectSize > KSWORD_ARK_WIN32K_EVENT_OBJECT_SIZE) {
        response->status = KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED;
        response->missingCapabilityMask = KSWORD_ARK_WIN32K_CAP_EVENT_HOOK_GLOBAL |
            KSWORD_ARK_WIN32K_CAP_EVENT_HOOK_ENUM;
        response->lastStatus = STATUS_INVALID_PARAMETER;
        kswordArkWin32kEventSetDetail(
            response->detail,
            L"Selected tagEVENTHOOK profile failed local object-size validation.");
        goto Cleanup;
    }

    status = kswordArkWin32kEventBuildThreadMap(
        &threadMap,
        &threadMapCount,
        &threadMapTruncated);
    if (!NT_SUCCESS(status)) {
        response->status = KSWORD_ARK_WIN32K_STATUS_READ_FAILED;
        response->lastStatus = status;
        response->missingCapabilityMask |= KSWORD_ARK_WIN32K_CAP_THREADINFO_PUBLIC;
        kswordArkWin32kEventSetDetail(
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

    status = kswordArkWin32kEventReferenceSessionProcess(
        threadMap,
        threadMapCount,
        request,
        &requestedSessionId,
        &sessionProcess);
    if (!NT_SUCCESS(status) || sessionProcess == NULL) {
        response->status = KSWORD_ARK_WIN32K_STATUS_READ_FAILED;
        response->lastStatus = NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
        response->missingCapabilityMask |= KSWORD_ARK_WIN32K_CAP_EVENT_HOOK_GLOBAL |
            KSWORD_ARK_WIN32K_CAP_EVENT_HOOK_ENUM;
        kswordArkWin32kEventSetDetail(
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

    hookListExport = RtlFindExportedRoutineByName(
        baseEntry.imageBase,
        "gpWinEventHooks");
    hookListPointer = (ULONG64)(ULONG_PTR)hookListExport;
    if (hookListExport == NULL ||
        !kswordArkWin32kEventIsKernelAddress(hookListPointer) ||
        hookListPointer < (ULONG64)(ULONG_PTR)baseEntry.imageBase ||
        hookListPointer - (ULONG64)(ULONG_PTR)baseEntry.imageBase > MAXULONG ||
        hookListPointer - (ULONG64)(ULONG_PTR)baseEntry.imageBase + sizeof(ULONG64) >
            (ULONG64)response->win32kbaseImageSize) {
        response->status = KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED;
        response->missingCapabilityMask = KSWORD_ARK_WIN32K_CAP_EVENT_HOOK_GLOBAL |
            KSWORD_ARK_WIN32K_CAP_EVENT_HOOK_ENUM;
        response->lastStatus = STATUS_PROCEDURE_NOT_FOUND;
        kswordArkWin32kEventSetDetail(
            response->detail,
            L"win32kbase does not expose a valid gpWinEventHooks data export.");
        goto Cleanup;
    }
    response->layout.globalRva = (ULONG)(hookListPointer -
        (ULONG64)(ULONG_PTR)baseEntry.imageBase);
    response->hookListPointer = hookListPointer;
    if (!kswordArkWin32kEventReadMemory(
            hookListPointer,
            &currentHook,
            sizeof(currentHook))) {
        response->status = KSWORD_ARK_WIN32K_STATUS_READ_FAILED;
        response->missingCapabilityMask = KSWORD_ARK_WIN32K_CAP_EVENT_HOOK_GLOBAL |
            KSWORD_ARK_WIN32K_CAP_EVENT_HOOK_ENUM;
        response->lastStatus = STATUS_PARTIAL_COPY;
        kswordArkWin32kEventSetDetail(
            response->detail,
            L"gpWinEventHooks could not be read after attaching the requested GUI session.");
        goto Cleanup;
    }

    response->hookListHead = currentHook;
    response->capabilityMask = KSWORD_ARK_WIN32K_CAP_WIN32KBASE_LOADED |
        KSWORD_ARK_WIN32K_CAP_WIN32KFULL_LOADED |
        KSWORD_ARK_WIN32K_CAP_THREADINFO_PUBLIC |
        KSWORD_ARK_WIN32K_CAP_EVENT_HOOK_GLOBAL |
        KSWORD_ARK_WIN32K_CAP_EVENT_HOOK_LAYOUT |
        KSWORD_ARK_WIN32K_CAP_EVENT_HOOK_ENUM;
    response->status = threadMapTruncated
        ? KSWORD_ARK_WIN32K_STATUS_PARTIAL
        : KSWORD_ARK_WIN32K_STATUS_OK;
    response->lastStatus = threadMapTruncated
        ? STATUS_BUFFER_OVERFLOW
        : STATUS_SUCCESS;
    kswordArkWin32kEventSetDetail(
        response->detail,
        layoutSelection.source == KSWORD_ARK_WIN32K_LAYOUT_SELECTION_EXACT_IDENTITY
            ? L"tagEVENTHOOK layout matched the exact PE identity; gpWinEventHooks is being read in the requested GUI session."
            : L"The nearest previous tagEVENTHOOK layout and the current gpWinEventHooks export are active in the requested GUI session; results may be partial.");

    seenHooks = (ULONG64*)kswordArkAllocateNonPagedPool(
        sizeof(*seenHooks) * KSWORD_ARK_WIN32K_EVENT_MAX_SEEN,
        KSWORD_ARK_WIN32K_EVENT_POOL_TAG);
    if (seenHooks == NULL) {
        response->status = KSWORD_ARK_WIN32K_STATUS_PARTIAL;
        response->lastStatus = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }
    RtlZeroMemory(seenHooks, sizeof(*seenHooks) * KSWORD_ARK_WIN32K_EVENT_MAX_SEEN);

    while (currentHook != 0ULL) {
        UCHAR objectBytes[KSWORD_ARK_WIN32K_EVENT_OBJECT_SIZE];
        ULONG64 nextHook = 0ULL;
        ULONG64 ownerThreadInfo = 0ULL;
        ULONG processId = 0UL;
        ULONG threadId = 0UL;
        ULONG sessionId = 0UL;
        BOOLEAN ownerResolved = FALSE;

        response->visitedNodeCount += 1UL;
        if (seenCount >= KSWORD_ARK_WIN32K_EVENT_MAX_SEEN) {
            response->status = KSWORD_ARK_WIN32K_STATUS_BUFFER_TRUNCATED;
            response->lastStatus = STATUS_BUFFER_OVERFLOW;
            break;
        }
        if (!kswordArkWin32kEventIsKernelAddress(currentHook)) {
            response->corruptLinkCount += 1UL;
            response->status = KSWORD_ARK_WIN32K_STATUS_PARTIAL;
            response->lastStatus = STATUS_INVALID_ADDRESS;
            break;
        }
        if (kswordArkWin32kEventAlreadySeen(seenHooks, seenCount, currentHook)) {
            response->duplicateCount += 1UL;
            response->corruptLinkCount += 1UL;
            response->status = KSWORD_ARK_WIN32K_STATUS_PARTIAL;
            response->lastStatus = STATUS_DATA_ERROR;
            break;
        }
        seenHooks[seenCount++] = currentHook;
        if (!kswordArkWin32kEventReadMemory(
                currentHook,
                objectBytes,
                sizeof(objectBytes))) {
            response->readFailureCount += 1UL;
            response->status = KSWORD_ARK_WIN32K_STATUS_PARTIAL;
            response->lastStatus = STATUS_PARTIAL_COPY;
            break;
        }

        nextHook = kswordArkWin32kEventReadU64(
            objectBytes,
            response->layout.nextHook);
        ownerThreadInfo = kswordArkWin32kEventReadU64(
            objectBytes,
            response->layout.ownerThreadInfo);
        ownerResolved = kswordArkWin32kEventLookupThread(
            threadMap,
            threadMapCount,
            ownerThreadInfo,
            requestedSessionId,
            &processId,
            &threadId,
            &sessionId);
        if (!ownerResolved) {
            unresolvedOwnerCount += 1UL;
            // gpWinEventHooks is session-local. Preserve the attached session
            // so an unresolved private pti field does not discard the node.
            processId = 0UL;
            threadId = 0UL;
            sessionId = requestedSessionId;
        }

        if (kswordArkWin32kEventMatchesRequest(
                request,
                processId,
                threadId,
                ownerResolved)) {
            KSWORD_ARK_WIN32K_EVENT_HOOK_ENTRY* entry = NULL;
            ULONG internalFlags = kswordArkWin32kEventReadU32(
                objectBytes,
                response->layout.internalFlags);
            ULONG64 callbackOffset = kswordArkWin32kEventReadU64(
                objectBytes,
                response->layout.callbackOffset);

            response->totalCount += 1UL;
            if (response->returnedCount >= maxEntries) {
                response->status = KSWORD_ARK_WIN32K_STATUS_BUFFER_TRUNCATED;
                response->lastStatus = STATUS_BUFFER_OVERFLOW;
                break;
            }
            entry = &response->entries[response->returnedCount++];
            RtlZeroMemory(entry, sizeof(*entry));
            entry->fieldFlags = KSWORD_ARK_WIN32K_EVENT_HOOK_FIELD_HANDLE |
                KSWORD_ARK_WIN32K_EVENT_HOOK_FIELD_OWNER |
                KSWORD_ARK_WIN32K_EVENT_HOOK_FIELD_RANGE |
                KSWORD_ARK_WIN32K_EVENT_HOOK_FIELD_FLAGS |
                KSWORD_ARK_WIN32K_EVENT_HOOK_FIELD_TARGET |
                KSWORD_ARK_WIN32K_EVENT_HOOK_FIELD_CALLBACK |
                KSWORD_ARK_WIN32K_EVENT_HOOK_FIELD_MODULE_ATOM |
                KSWORD_ARK_WIN32K_EVENT_HOOK_FIELD_NEXT |
                KSWORD_ARK_WIN32K_EVENT_HOOK_FIELD_TIMESTAMP;
            entry->status = ownerResolved
                ? KSWORD_ARK_WIN32K_STATUS_OK
                : KSWORD_ARK_WIN32K_STATUS_PARTIAL;
            entry->processId = processId;
            entry->threadId = threadId;
            entry->sessionId = sessionId;
            entry->flags = (internalFlags & KSWORD_ARK_WIN32K_EVENT_INTERNAL_PUBLIC_MASK) >> 1U;
            entry->internalFlags = internalFlags;
            entry->eventMin = kswordArkWin32kEventReadU32(
                objectBytes,
                response->layout.eventMin);
            entry->eventMax = kswordArkWin32kEventReadU32(
                objectBytes,
                response->layout.eventMax);
            entry->targetProcessId = (ULONG)kswordArkWin32kEventReadU64(
                objectBytes,
                response->layout.targetProcessId);
            entry->targetThreadId = kswordArkWin32kEventReadU32(
                objectBytes,
                response->layout.targetThreadId);
            entry->moduleAtom = kswordArkWin32kEventReadU32(
                objectBytes,
                response->layout.moduleAtom);
            entry->installTime = kswordArkWin32kEventReadU32(
                objectBytes,
                response->layout.timestamp);
            entry->lastStatus = ownerResolved ? STATUS_SUCCESS : STATUS_NOT_FOUND;
            entry->hookHandle = kswordArkWin32kEventReadU64(
                objectBytes,
                response->layout.handle);
            entry->hookObject = currentHook;
            entry->nextHookObject = nextHook;
            entry->ownerThreadInfo = ownerThreadInfo;
            entry->callbackOffset = callbackOffset;
            if ((internalFlags & KSWORD_ARK_WIN32K_EVENT_INTERNAL_IN_CONTEXT) == 0UL) {
                entry->callbackAddress = callbackOffset;
            }
            kswordArkWin32kEventSetDetail(
                entry->detail,
                ownerResolved
                    ? L"tagEVENTHOOK owner mapped through PsGetThreadWin32Thread."
                    : L"tagEVENTHOOK fields read; owner ThreadInfo was not found in the public thread map.");
        }

        if (nextHook != 0ULL &&
            (!kswordArkWin32kEventIsKernelAddress(nextHook) || nextHook == currentHook)) {
            response->corruptLinkCount += 1UL;
            response->status = KSWORD_ARK_WIN32K_STATUS_PARTIAL;
            response->lastStatus = STATUS_DATA_ERROR;
            break;
        }
        currentHook = nextHook;
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
        unresolvedOwnerCount);

Cleanup:
    if (attached) {
        KeUnstackDetachProcess(attachState);
        attached = FALSE;
    }
    if (sessionProcess != NULL) {
        ObDereferenceObject(sessionProcess);
        sessionProcess = NULL;
    }
    if (seenHooks != NULL) {
        ExFreePoolWithTag(seenHooks, KSWORD_ARK_WIN32K_EVENT_POOL_TAG);
    }
    if (threadMap != NULL) {
        ExFreePoolWithTag(threadMap, KSWORD_ARK_WIN32K_EVENT_POOL_TAG);
    }
    if (moduleInfo != NULL) {
        ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
    }
    UNREFERENCED_PARAMETER(moduleInfoBytes);
    *bytesWrittenOut = headerSize +
        ((size_t)response->returnedCount * sizeof(KSWORD_ARK_WIN32K_EVENT_HOOK_ENTRY));
    return STATUS_SUCCESS;
}
