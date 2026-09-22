/*++

Module Name:

    win32k_runtime_query.c

Abstract:

    Protocol adapters for the validated Win32k signature fallback.  Only
    identity fields whose live relationships were proved are returned;
    PDB-only text, class, desktop, style, and rectangle fields remain marked
    unavailable instead of being guessed.

Environment:

    Kernel mode, PASSIVE_LEVEL IOCTL query paths.

--*/

#include "win32k_fallback.h"
#include "win32k_query.h"
#include "../../platform/pool_compat.h"

#include <ntstrsafe.h>

#define KSW_WIN32K_WINDOW_HEADER_SIZE \
    (sizeof(KSWORD_ARK_WIN32K_WINDOW_SNAPSHOT_RESPONSE) - \
        sizeof(KSWORD_ARK_WIN32K_WINDOW_ENTRY))
#define KSW_WIN32K_GUI_THREAD_HEADER_SIZE \
    (sizeof(KSWORD_ARK_WIN32K_GUI_THREAD_SNAPSHOT_RESPONSE) - \
        sizeof(KSWORD_ARK_WIN32K_GUI_THREAD_ENTRY))

#ifndef STATUS_NOT_FOUND
#define STATUS_NOT_FOUND ((NTSTATUS)0xC0000225L)
#endif

NTKERNELAPI
NTSTATUS
PsLookupThreadByThreadId(
    _In_ HANDLE threadId,
    _Outptr_ PETHREAD* thread
    );

typedef struct KswWiN32KProfileOneEntryResponse
{
    KSWORD_ARK_WIN32K_PROFILE_STATUS_RESPONSE header;
    KSWORD_ARK_WIN32K_SESSION_ENTRY extraEntry;
} KswWiN32KProfileOneEntryResponse, *PkswWiN32KProfileOneEntryResponse;

static ULONG64
kswordArkWin32kFallbackCapabilityMask(
    _In_ const KswWiN32KFallbackContext* context,
    _In_ BOOLEAN enumerationValidated
    )
{
    ULONG64 mask = KSWORD_ARK_WIN32K_CAP_WIN32KBASE_LOADED |
        KSWORD_ARK_WIN32K_CAP_WIN32KFULL_LOADED |
        KSWORD_ARK_WIN32K_CAP_THREADINFO_PUBLIC;

    if (context == NULL) {
        return 0ULL;
    }
    if (context->userGetSiloGlobals != 0U) {
        mask |= KSWORD_ARK_WIN32K_CAP_USER_GET_SILO_GLOBALS;
    }
    if (context->handleLayoutResolved) {
        mask |= KSWORD_ARK_WIN32K_CAP_TAGWND_SIGNATURE;
    }
    if (context->queueLayoutResolved) {
        mask |= KSWORD_ARK_WIN32K_CAP_TAGQ_SIGNATURE;
    }
    if (enumerationValidated) {
        mask |= KSWORD_ARK_WIN32K_CAP_WINDOW_ENUM;
    }
    return mask;
}

static ULONG
kswordArkWin32kFallbackEntryCapacity(
    _In_ size_t outputLength,
    _In_ size_t headerLength,
    _In_ size_t entryLength,
    _In_opt_ const KSWORD_ARK_WIN32K_QUERY_REQUEST* request
    )
{
    size_t capacity = 0U;
    ULONG maximum = KSWORD_ARK_WIN32K_DEFAULT_MAX_ENTRIES;

    if (outputLength < headerLength || entryLength == 0U) {
        return 0UL;
    }
    capacity = (outputLength - headerLength) / entryLength;
    if (request != NULL) {
        maximum = kswordArkWin32kNormalizeMaxEntries(request->maxEntries);
    }
    if (capacity > (size_t)maximum) {
        capacity = maximum;
    }
    if (capacity > KSWORD_ARK_WIN32K_HARD_MAX_ENTRIES) {
        capacity = KSWORD_ARK_WIN32K_HARD_MAX_ENTRIES;
    }
    return (ULONG)capacity;
}

static VOID
kswordArkWin32kFallbackSetWindowFailure(
    _Inout_ KSWORD_ARK_WIN32K_WINDOW_SNAPSHOT_RESPONSE* response,
    _In_ NTSTATUS status
    )
{
    response->status = (status == STATUS_NOT_FOUND)
        ? KSWORD_ARK_WIN32K_STATUS_PROFILE_MISSING
        : KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED;
    response->lastStatus = status;
    response->missingCapabilityMask =
        KSWORD_ARK_WIN32K_CAP_WIN32KBASE_PROFILE |
        KSWORD_ARK_WIN32K_CAP_WIN32KFULL_PROFILE |
        KSWORD_ARK_WIN32K_CAP_TAGWND_PROFILE;
}

NTSTATUS
kswordArkWin32kFallbackQueryWindowSnapshot(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_WIN32K_QUERY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
{
    KSWORD_ARK_WIN32K_WINDOW_SNAPSHOT_RESPONSE* response =
        (KSWORD_ARK_WIN32K_WINDOW_SNAPSHOT_RESPONSE*)outputBuffer;
    KswWiN32KFallbackContext context;
    KswWiN32KFallbackWindow* windows = NULL;
    ULONG capacity = 0UL;
    ULONG count = 0UL;
    ULONG total = 0UL;
    ULONG index = 0UL;
    BOOLEAN truncated = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBuffer == NULL || outputBufferLength < KSW_WIN32K_WINDOW_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    RtlZeroMemory(outputBuffer, outputBufferLength);
    response->version = KSWORD_ARK_WIN32K_PROTOCOL_VERSION;
    response->entrySize = sizeof(KSWORD_ARK_WIN32K_WINDOW_ENTRY);
    response->flags = request != NULL ? request->flags : 0UL;
    response->status = KSWORD_ARK_WIN32K_STATUS_PROFILE_MISSING;
    response->lastStatus = STATUS_NOT_FOUND;
    response->missingCapabilityMask =
        KSWORD_ARK_WIN32K_CAP_WIN32KBASE_PROFILE |
        KSWORD_ARK_WIN32K_CAP_WIN32KFULL_PROFILE |
        KSWORD_ARK_WIN32K_CAP_TAGWND_PROFILE;
    kswordArkWin32kInitializeOffsets(&response->fieldOffsets);
    *bytesWrittenOut = KSW_WIN32K_WINDOW_HEADER_SIZE;

    if (request != NULL && request->version != KSWORD_ARK_WIN32K_PROTOCOL_VERSION) {
        response->status = KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED;
        response->lastStatus = STATUS_REVISION_MISMATCH;
        return STATUS_SUCCESS;
    }
    capacity = kswordArkWin32kFallbackEntryCapacity(
        outputBufferLength,
        KSW_WIN32K_WINDOW_HEADER_SIZE,
        sizeof(KSWORD_ARK_WIN32K_WINDOW_ENTRY),
        request);
    if (capacity == 0UL) {
        response->status = KSWORD_ARK_WIN32K_STATUS_BUFFER_TRUNCATED;
        response->lastStatus = STATUS_BUFFER_OVERFLOW;
        return STATUS_SUCCESS;
    }
    status = kswordArkWin32kFallbackInitialize(&context);
    if (!NT_SUCCESS(status)) {
        kswordArkWin32kFallbackSetWindowFailure(response, status);
        return STATUS_SUCCESS;
    }
    windows = (KswWiN32KFallbackWindow*)kswordArkAllocateNonPagedPool(
        sizeof(*windows) * capacity,
        KSW_WIN32K_FALLBACK_POOL_TAG);
    if (windows == NULL) {
        response->status = KSWORD_ARK_WIN32K_STATUS_ENUM_FAILED;
        response->lastStatus = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }
    status = kswordArkWin32kFallbackEnumerateWindows(
        &context,
        request,
        windows,
        capacity,
        &count,
        &total,
        &truncated);
    if (!NT_SUCCESS(status)) {
        kswordArkWin32kFallbackSetWindowFailure(response, status);
        goto Cleanup;
    }

    response->capabilityMask = kswordArkWin32kFallbackCapabilityMask(
        &context,
        TRUE);
    response->missingCapabilityMask =
        KSWORD_ARK_WIN32K_CAP_WIN32KBASE_PROFILE |
        KSWORD_ARK_WIN32K_CAP_WIN32KFULL_PROFILE |
        KSWORD_ARK_WIN32K_CAP_TAGWND_PROFILE;
    response->status = truncated
        ? KSWORD_ARK_WIN32K_STATUS_BUFFER_TRUNCATED
        : KSWORD_ARK_WIN32K_STATUS_PARTIAL;
    response->lastStatus = truncated ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
    response->totalCount = total;
    response->returnedCount = count;
    kswordArkWin32kFallbackPublishOffsets(&context, &response->fieldOffsets);

    for (index = 0UL; index < count; ++index) {
        KSWORD_ARK_WIN32K_WINDOW_ENTRY* entry = &response->entries[index];

        entry->fieldFlags = KSWORD_ARK_WIN32K_FIELD_HWND_PRESENT |
            KSWORD_ARK_WIN32K_FIELD_TAGWND_PRESENT |
            KSWORD_ARK_WIN32K_FIELD_THREADINFO_PRESENT;
        entry->status = KSWORD_ARK_WIN32K_STATUS_PARTIAL;
        entry->processId = windows[index].processId;
        entry->threadId = windows[index].threadId;
        entry->sessionId = windows[index].sessionId;
        entry->titleStatus = KSWORD_ARK_WIN32K_READ_STATUS_PROFILE_MISSING;
        entry->classStatus = KSWORD_ARK_WIN32K_READ_STATUS_PROFILE_MISSING;
        entry->lastStatus = STATUS_SUCCESS;
        entry->hwnd = windows[index].hwnd;
        entry->tagWnd = windows[index].tagWnd;
        entry->threadInfo = windows[index].threadInfo;
        kswordArkWin32kCopyWideText(
            entry->detail,
            KSWORD_ARK_WIN32K_DETAIL_CHARS,
            L"HWND identity was recovered by a validated ValidateHwnd signature; PDB-only text and geometry fields remain unavailable.");
    }
    *bytesWrittenOut = KSW_WIN32K_WINDOW_HEADER_SIZE +
        ((size_t)count * sizeof(KSWORD_ARK_WIN32K_WINDOW_ENTRY));

Cleanup:
    if (windows != NULL) {
        ExFreePoolWithTag(windows, KSW_WIN32K_FALLBACK_POOL_TAG);
    }
    kswordArkWin32kFallbackCleanup(&context);
    return STATUS_SUCCESS;
}

static BOOLEAN
kswordArkWin32kFallbackThreadMatchesRequest(
    _In_ const KswordArkWiN32KGuiThreadMapEntry* entry,
    _In_opt_ const KSWORD_ARK_WIN32K_QUERY_REQUEST* request
    )
{
    KswordWiN32KPsGetProcessSessionIdFn getSessionId = NULL;

    if (entry == NULL) {
        return FALSE;
    }
    if (request != NULL && request->sessionId == 0UL &&
        (request->flags & KSWORD_ARK_WIN32K_QUERY_FLAG_CURRENT_SESSION_ONLY) != 0UL) {
        getSessionId = kswordArkWin32kResolvePsGetProcessSessionId();
        if (getSessionId == NULL ||
            getSessionId(PsGetCurrentProcess()) != entry->sessionId) {
            return FALSE;
        }
    }
    return request == NULL ||
        ((request->sessionId == 0UL || request->sessionId == entry->sessionId) &&
         (request->processId == 0UL || request->processId == entry->processId) &&
         (request->threadId == 0UL || request->threadId == entry->threadId));
}

NTSTATUS
kswordArkWin32kFallbackQueryGuiThreadSnapshot(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_WIN32K_QUERY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
{
    KSWORD_ARK_WIN32K_GUI_THREAD_SNAPSHOT_RESPONSE* response =
        (KSWORD_ARK_WIN32K_GUI_THREAD_SNAPSHOT_RESPONSE*)outputBuffer;
    KswWiN32KFallbackContext context;
    KswWiN32KFallbackWindow* windows = NULL;
    KSWORD_ARK_WIN32K_QUERY_REQUEST windowRequest;
    ULONG capacity = 0UL;
    ULONG windowCount = 0UL;
    ULONG windowTotal = 0UL;
    ULONG mapIndex = 0UL;
    BOOLEAN windowsTruncated = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBuffer == NULL || outputBufferLength < KSW_WIN32K_GUI_THREAD_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    RtlZeroMemory(outputBuffer, outputBufferLength);
    response->version = KSWORD_ARK_WIN32K_PROTOCOL_VERSION;
    response->entrySize = sizeof(KSWORD_ARK_WIN32K_GUI_THREAD_ENTRY);
    response->flags = request != NULL ? request->flags : 0UL;
    response->status = KSWORD_ARK_WIN32K_STATUS_PROFILE_MISSING;
    response->lastStatus = STATUS_NOT_FOUND;
    response->missingCapabilityMask =
        KSWORD_ARK_WIN32K_CAP_TAGTHREADINFO_PROFILE |
        KSWORD_ARK_WIN32K_CAP_TAGQ_PROFILE;
    kswordArkWin32kInitializeOffsets(&response->fieldOffsets);
    *bytesWrittenOut = KSW_WIN32K_GUI_THREAD_HEADER_SIZE;

    if (request != NULL && request->version != KSWORD_ARK_WIN32K_PROTOCOL_VERSION) {
        response->status = KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED;
        response->lastStatus = STATUS_REVISION_MISMATCH;
        return STATUS_SUCCESS;
    }
    capacity = kswordArkWin32kFallbackEntryCapacity(
        outputBufferLength,
        KSW_WIN32K_GUI_THREAD_HEADER_SIZE,
        sizeof(KSWORD_ARK_WIN32K_GUI_THREAD_ENTRY),
        request);
    if (capacity == 0UL) {
        response->status = KSWORD_ARK_WIN32K_STATUS_BUFFER_TRUNCATED;
        response->lastStatus = STATUS_BUFFER_OVERFLOW;
        return STATUS_SUCCESS;
    }
    status = kswordArkWin32kFallbackInitialize(&context);
    if (!NT_SUCCESS(status) || !context.handleLayoutResolved ||
        !context.queueLayoutResolved) {
        response->status = KSWORD_ARK_WIN32K_STATUS_PROFILE_MISSING;
        response->lastStatus = NT_SUCCESS(status) ? STATUS_NOT_SUPPORTED : status;
        if (NT_SUCCESS(status)) {
            kswordArkWin32kFallbackCleanup(&context);
        }
        return STATUS_SUCCESS;
    }
    windows = (KswWiN32KFallbackWindow*)kswordArkAllocateNonPagedPool(
        sizeof(*windows) * KSW_WIN32K_FALLBACK_WINDOW_LIMIT,
        KSW_WIN32K_FALLBACK_POOL_TAG);
    if (windows == NULL) {
        response->status = KSWORD_ARK_WIN32K_STATUS_ENUM_FAILED;
        response->lastStatus = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }
    RtlZeroMemory(&windowRequest, sizeof(windowRequest));
    windowRequest.version = KSWORD_ARK_WIN32K_PROTOCOL_VERSION;
    if (request != NULL) {
        windowRequest.flags = request->flags;
        windowRequest.sessionId = request->sessionId;
    }
    windowRequest.maxEntries = KSW_WIN32K_FALLBACK_WINDOW_LIMIT;
    status = kswordArkWin32kFallbackEnumerateWindows(
        &context,
        &windowRequest,
        windows,
        KSW_WIN32K_FALLBACK_WINDOW_LIMIT,
        &windowCount,
        &windowTotal,
        &windowsTruncated);
    if (!NT_SUCCESS(status)) {
        response->status = KSWORD_ARK_WIN32K_STATUS_PROFILE_MISSING;
        response->lastStatus = status;
        goto Cleanup;
    }

    response->capabilityMask = kswordArkWin32kFallbackCapabilityMask(
        &context,
        TRUE);
    response->missingCapabilityMask =
        KSWORD_ARK_WIN32K_CAP_TAGTHREADINFO_PROFILE |
        KSWORD_ARK_WIN32K_CAP_TAGQ_PROFILE;
    response->status = KSWORD_ARK_WIN32K_STATUS_PARTIAL;
    response->lastStatus = windowsTruncated ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
    kswordArkWin32kFallbackPublishOffsets(&context, &response->fieldOffsets);

    for (mapIndex = 0UL; mapIndex < context.threadMapCount; ++mapIndex) {
        const KswordArkWiN32KGuiThreadMapEntry* thread =
            &context.threadMap[mapIndex];
        KSWORD_ARK_WIN32K_GUI_THREAD_ENTRY* entry = NULL;
        KswWiN32KFallbackQueue queue;
        PETHREAD threadObject = NULL;

        if (!kswordArkWin32kFallbackThreadMatchesRequest(thread, request)) {
            continue;
        }
        response->totalCount += 1UL;
        if (response->returnedCount >= capacity) {
            response->status = KSWORD_ARK_WIN32K_STATUS_BUFFER_TRUNCATED;
            response->lastStatus = STATUS_BUFFER_OVERFLOW;
            continue;
        }
        entry = &response->entries[response->returnedCount];
        RtlZeroMemory(entry, sizeof(*entry));
        entry->fieldFlags = KSWORD_ARK_WIN32K_FIELD_THREADINFO_PRESENT;
        entry->status = KSWORD_ARK_WIN32K_STATUS_PARTIAL;
        entry->processId = thread->processId;
        entry->threadId = thread->threadId;
        entry->sessionId = thread->sessionId;
        entry->threadInfo = thread->threadInfo;
        entry->lastStatus = STATUS_SUCCESS;
        if (NT_SUCCESS(PsLookupThreadByThreadId(
                (HANDLE)(ULONG_PTR)thread->threadId,
                &threadObject)) && threadObject != NULL) {
            entry->ethread = (ULONG64)(ULONG_PTR)threadObject;
            ObDereferenceObject(threadObject);
        }

        RtlZeroMemory(&queue, sizeof(queue));
        if (kswordArkWin32kFallbackReadQueue(
                &context,
                thread,
                windows,
                windowCount,
                &queue)) {
            entry->fieldFlags |= KSWORD_ARK_WIN32K_FIELD_QUEUE_PRESENT;
            entry->queueStatus = KSWORD_ARK_WIN32K_READ_STATUS_OK;
            entry->queueObject = queue.queueObject;
            entry->activeHwnd = queue.activeHwnd;
            entry->focusHwnd = queue.focusHwnd;
            entry->captureHwnd = queue.captureHwnd;
            entry->caretHwnd = queue.caretHwnd;
            kswordArkWin32kCopyWideText(
                entry->detail,
                KSWORD_ARK_WIN32K_DETAIL_CHARS,
                L"tagQ core window fields were decoded from a validated NtUserGetGUIThreadInfo signature.");
        }
        else {
            entry->queueStatus = windowsTruncated
                ? KSWORD_ARK_WIN32K_READ_STATUS_TRUNCATED
                : KSWORD_ARK_WIN32K_READ_STATUS_READ_FAILED;
            entry->lastStatus = windowsTruncated
                ? STATUS_BUFFER_OVERFLOW
                : STATUS_PARTIAL_COPY;
            kswordArkWin32kCopyWideText(
                entry->detail,
                KSWORD_ARK_WIN32K_DETAIL_CHARS,
                L"The tagQ signature candidate failed live window-pointer validation and was not published.");
        }
        response->returnedCount += 1UL;
    }
    *bytesWrittenOut = KSW_WIN32K_GUI_THREAD_HEADER_SIZE +
        ((size_t)response->returnedCount * sizeof(KSWORD_ARK_WIN32K_GUI_THREAD_ENTRY));
    UNREFERENCED_PARAMETER(windowTotal);

Cleanup:
    if (windows != NULL) {
        ExFreePoolWithTag(windows, KSW_WIN32K_FALLBACK_POOL_TAG);
    }
    kswordArkWin32kFallbackCleanup(&context);
    return STATUS_SUCCESS;
}

static const KswordArkWiN32KGuiThreadMapEntry*
kswordArkWin32kFallbackFindDetailThread(
    _In_ const KswWiN32KFallbackContext* context,
    _In_ const KswWiN32KFallbackWindow* window
    )
{
    ULONG index = 0UL;

    for (index = 0UL; index < context->threadMapCount; ++index) {
        if (context->threadMap[index].threadInfo == window->threadInfo &&
            context->threadMap[index].sessionId == window->sessionId) {
            return &context->threadMap[index];
        }
    }
    return NULL;
}

NTSTATUS
kswordArkWin32kFallbackQueryWindowDetail(
    _Out_writes_bytes_(outputBufferLength) KSWORD_ARK_WIN32K_WINDOW_DETAIL_RESPONSE* response,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_WIN32K_WINDOW_DETAIL_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
{
    KswWiN32KProfileOneEntryResponse profileResponse;
    KSWORD_ARK_WIN32K_QUERY_REQUEST profileRequest;
    KswWiN32KFallbackContext context;
    KswWiN32KFallbackWindow* windows = NULL;
    KSWORD_ARK_WIN32K_QUERY_REQUEST windowRequest;
    const KswWiN32KFallbackWindow* match = NULL;
    const KswordArkWiN32KGuiThreadMapEntry* thread = NULL;
    KswWiN32KFallbackQueue queue;
    size_t profileBytes = 0U;
    ULONG windowCount = 0UL;
    ULONG windowTotal = 0UL;
    ULONG index = 0UL;
    ULONG targetSession = 0UL;
    BOOLEAN targetSessionFound = FALSE;
    BOOLEAN truncated = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (response == NULL || request == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (outputBufferLength < sizeof(*response)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    *bytesWrittenOut = sizeof(*response);
    RtlZeroMemory(response, sizeof(*response));
    response->version = KSWORD_ARK_WIN32K_PROTOCOL_VERSION;
    response->status = KSWORD_ARK_WIN32K_STATUS_PROFILE_MISSING;
    response->processId = request->processId;
    response->threadId = request->threadId;
    response->flags = request->flags;
    response->hwnd = request->hwnd;
    response->lastStatus = STATUS_NOT_FOUND;
    response->missingCapabilityMask = KSWORD_ARK_WIN32K_CAP_TAGWND_PROFILE |
        KSWORD_ARK_WIN32K_CAP_TAGTHREADINFO_PROFILE |
        KSWORD_ARK_WIN32K_CAP_TAGQ_PROFILE;
    kswordArkWin32kInitializeOffsets(&response->fieldOffsets);

    if (request->version != KSWORD_ARK_WIN32K_PROTOCOL_VERSION ||
        request->hwnd == 0ULL) {
        response->status = KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED;
        response->lastStatus = request->version != KSWORD_ARK_WIN32K_PROTOCOL_VERSION
            ? STATUS_REVISION_MISMATCH
            : STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&profileRequest, sizeof(profileRequest));
    profileRequest.version = KSWORD_ARK_WIN32K_PROTOCOL_VERSION;
    profileRequest.maxEntries = 1UL;
    RtlZeroMemory(&profileResponse, sizeof(profileResponse));
    status = kswordArkWin32kQueryProfileStatus(
        &profileResponse,
        sizeof(profileResponse),
        &profileRequest,
        &profileBytes);
    if (NT_SUCCESS(status)) {
        response->win32k = profileResponse.header.win32k;
        response->win32kbase = profileResponse.header.win32kbase;
        response->win32kfull = profileResponse.header.win32kfull;
    }

    status = kswordArkWin32kFallbackInitialize(&context);
    if (!NT_SUCCESS(status) || !context.handleLayoutResolved) {
        response->lastStatus = NT_SUCCESS(status) ? STATUS_NOT_SUPPORTED : status;
        if (NT_SUCCESS(status)) {
            kswordArkWin32kFallbackCleanup(&context);
        }
        return STATUS_SUCCESS;
    }
    for (index = 0UL; index < context.threadMapCount; ++index) {
        const KswordArkWiN32KGuiThreadMapEntry* candidate =
            &context.threadMap[index];
        if ((request->processId == 0UL || request->processId == candidate->processId) &&
            (request->threadId == 0UL || request->threadId == candidate->threadId)) {
            if (targetSessionFound && targetSession != candidate->sessionId) {
                response->status = KSWORD_ARK_WIN32K_STATUS_ENUM_FAILED;
                response->lastStatus = STATUS_OBJECT_NAME_COLLISION;
                goto Cleanup;
            }
            targetSession = candidate->sessionId;
            targetSessionFound = TRUE;
        }
    }
    if (!targetSessionFound &&
        (request->processId != 0UL || request->threadId != 0UL)) {
        response->lastStatus = STATUS_NOT_FOUND;
        goto Cleanup;
    }
    windows = (KswWiN32KFallbackWindow*)kswordArkAllocateNonPagedPool(
        sizeof(*windows) * KSW_WIN32K_FALLBACK_WINDOW_LIMIT,
        KSW_WIN32K_FALLBACK_POOL_TAG);
    if (windows == NULL) {
        response->status = KSWORD_ARK_WIN32K_STATUS_ENUM_FAILED;
        response->lastStatus = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }
    RtlZeroMemory(&windowRequest, sizeof(windowRequest));
    windowRequest.version = KSWORD_ARK_WIN32K_PROTOCOL_VERSION;
    windowRequest.sessionId = targetSession;
    windowRequest.maxEntries = KSW_WIN32K_FALLBACK_WINDOW_LIMIT;
    status = kswordArkWin32kFallbackEnumerateWindows(
        &context,
        &windowRequest,
        windows,
        KSW_WIN32K_FALLBACK_WINDOW_LIMIT,
        &windowCount,
        &windowTotal,
        &truncated);
    if (!NT_SUCCESS(status)) {
        response->lastStatus = status;
        goto Cleanup;
    }
    for (index = 0UL; index < windowCount; ++index) {
        if (windows[index].hwnd == request->hwnd &&
            (request->processId == 0UL || request->processId == windows[index].processId) &&
            (request->threadId == 0UL || request->threadId == windows[index].threadId)) {
            if (match != NULL) {
                response->status = KSWORD_ARK_WIN32K_STATUS_ENUM_FAILED;
                response->lastStatus = STATUS_OBJECT_NAME_COLLISION;
                goto Cleanup;
            }
            match = &windows[index];
        }
    }
    if (match == NULL) {
        response->lastStatus = truncated ? STATUS_BUFFER_OVERFLOW : STATUS_NOT_FOUND;
        goto Cleanup;
    }

    response->processId = match->processId;
    response->threadId = match->threadId;
    response->hwnd = match->hwnd;
    response->tagWnd = match->tagWnd;
    response->threadInfo = match->threadInfo;
    response->fieldFlags = KSWORD_ARK_WIN32K_FIELD_HWND_PRESENT |
        KSWORD_ARK_WIN32K_FIELD_TAGWND_PRESENT |
        KSWORD_ARK_WIN32K_FIELD_THREADINFO_PRESENT |
        KSWORD_ARK_WIN32K_FIELD_DETAIL_IDENTITY |
        KSWORD_ARK_WIN32K_FIELD_DETAIL_OFFSETS;
    response->capabilityMask = kswordArkWin32kFallbackCapabilityMask(
        &context,
        TRUE);
    kswordArkWin32kFallbackPublishOffsets(&context, &response->fieldOffsets);
    response->status = KSWORD_ARK_WIN32K_STATUS_PARTIAL;
    response->lastStatus = truncated ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;

    thread = kswordArkWin32kFallbackFindDetailThread(&context, match);
    RtlZeroMemory(&queue, sizeof(queue));
    if (thread != NULL && kswordArkWin32kFallbackReadQueue(
            &context,
            thread,
            windows,
            windowCount,
            &queue)) {
        response->fieldFlags |= KSWORD_ARK_WIN32K_FIELD_QUEUE_PRESENT;
        response->queueObject = queue.queueObject;
    }
    kswordArkWin32kCopyWideText(
        response->detail,
        KSWORD_ARK_RUNTIME_DETAIL_TEXT_CHARS,
        L"The HWND, tagWND, tagTHREADINFO, and optional tagQ identity passed signature and live relationship validation; PDB-only text and class fields remain unavailable.");
    UNREFERENCED_PARAMETER(windowTotal);
    UNREFERENCED_PARAMETER(profileBytes);

Cleanup:
    if (windows != NULL) {
        ExFreePoolWithTag(windows, KSW_WIN32K_FALLBACK_POOL_TAG);
    }
    kswordArkWin32kFallbackCleanup(&context);
    return STATUS_SUCCESS;
}
