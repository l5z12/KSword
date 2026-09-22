/*++

Module Name:

    win32k_query.c

Abstract:

    Read-only win32k GUI audit collectors.

Environment:

    Kernel-mode Driver Framework

--*/

#include "win32k_query.h"
#include "win32k_support.h"
#include "win32k_fallback.h"
#include "../../platform/pool_compat.h"
#include "ark/ark_keyboard.h"

#include <ntstrsafe.h>

#define KSWORD_ARK_WIN32K_PROFILE_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_WIN32K_PROFILE_STATUS_RESPONSE) - sizeof(KSWORD_ARK_WIN32K_SESSION_ENTRY))

#define KSWORD_ARK_WIN32K_WINDOW_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_WIN32K_WINDOW_SNAPSHOT_RESPONSE) - sizeof(KSWORD_ARK_WIN32K_WINDOW_ENTRY))

#define KSWORD_ARK_WIN32K_GUI_THREAD_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_WIN32K_GUI_THREAD_SNAPSHOT_RESPONSE) - sizeof(KSWORD_ARK_WIN32K_GUI_THREAD_ENTRY))

#define KSWORD_ARK_WIN32K_HOTKEY_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_WIN32K_HOTKEY_SNAPSHOT_RESPONSE) - sizeof(KSWORD_ARK_WIN32K_HOTKEY_ENTRY))

#define KSWORD_ARK_WIN32K_HOOK_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_WIN32K_HOOK_SNAPSHOT_RESPONSE) - sizeof(KSWORD_ARK_WIN32K_HOOK_ENTRY))

#ifndef STATUS_NOT_FOUND
#define STATUS_NOT_FOUND ((NTSTATUS)0xC0000225L)
#endif

#define KSWORD_ARK_WIN32K_BRIDGE_TAG 'B3WK'

static NTSTATUS
kswordArkWin32kPrepareProfileHeader(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Outptr_ KSWORD_ARK_WIN32K_PROFILE_STATUS_RESPONSE** responseOut,
    _Out_ size_t* entryCapacityOut
    )
/*++

Routine Description:

    Validate and initialize a Win32k profile/status response header.

Arguments:

    OutputBuffer - METHOD_BUFFERED output.
    OutputBufferLength - Writable output bytes.
    ResponseOut - Receives the response pointer.
    EntryCapacityOut - Receives variable session-entry capacity.

Return Value:

    STATUS_SUCCESS or a buffer validation failure.

--*/
{
    if (outputBuffer == NULL || responseOut == NULL || entryCapacityOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (outputBufferLength < KSWORD_ARK_WIN32K_PROFILE_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    *responseOut = (KSWORD_ARK_WIN32K_PROFILE_STATUS_RESPONSE*)outputBuffer;
    *entryCapacityOut =
        (outputBufferLength - KSWORD_ARK_WIN32K_PROFILE_RESPONSE_HEADER_SIZE) /
        sizeof(KSWORD_ARK_WIN32K_SESSION_ENTRY);
    (*responseOut)->version = KSWORD_ARK_WIN32K_PROTOCOL_VERSION;
    (*responseOut)->status = KSWORD_ARK_WIN32K_STATUS_PROFILE_MISSING;
    (*responseOut)->entrySize = sizeof(KSWORD_ARK_WIN32K_SESSION_ENTRY);
    (*responseOut)->lastStatus = STATUS_SUCCESS;
    kswordArkWin32kInitializeOffsets(&(*responseOut)->fieldOffsets);
    return STATUS_SUCCESS;
}
static ULONG
kswordArkWin32kMapKeyboardStatus(
    _In_ ULONG keyboardStatus
    )
/*++

Routine Description:

    Map the legacy keyboard hotkey/hook status space to the Win32k audit status space.

Arguments:

    KeyboardStatus - Status returned by the keyboard enumeration backend.

Return Value:

    A KSWORD_ARK_WIN32K_STATUS_* value that preserves the backend failure meaning.

--*/
{
    switch (keyboardStatus) {
    case KSWORD_ARK_KEYBOARD_ENUM_STATUS_OK:
        return KSWORD_ARK_WIN32K_STATUS_OK;
    case KSWORD_ARK_KEYBOARD_ENUM_STATUS_PARTIAL:
        return KSWORD_ARK_WIN32K_STATUS_PARTIAL;
    case KSWORD_ARK_KEYBOARD_ENUM_STATUS_UNSUPPORTED:
        return KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED;
    case KSWORD_ARK_KEYBOARD_ENUM_STATUS_WIN32K_NOT_FOUND:
        return KSWORD_ARK_WIN32K_STATUS_WIN32K_NOT_FOUND;
    case KSWORD_ARK_KEYBOARD_ENUM_STATUS_PATTERN_NOT_FOUND:
    case KSWORD_ARK_KEYBOARD_ENUM_STATUS_SESSION_UNAVAILABLE:
        return KSWORD_ARK_WIN32K_STATUS_ENUM_FAILED;
    case KSWORD_ARK_KEYBOARD_ENUM_STATUS_BUFFER_TRUNCATED:
        return KSWORD_ARK_WIN32K_STATUS_BUFFER_TRUNCATED;
    case KSWORD_ARK_KEYBOARD_ENUM_STATUS_READ_FAILED:
        return KSWORD_ARK_WIN32K_STATUS_READ_FAILED;
    default:
        return KSWORD_ARK_WIN32K_STATUS_PROFILE_MISSING;
    }
}

static VOID
kswordArkWin32kFillKeyboardBridgeRequest(
    _Out_ KSWORD_ARK_ENUM_KEYBOARD_REQUEST* keyboardRequest,
    _In_opt_ const KSWORD_ARK_WIN32K_QUERY_REQUEST* request,
    _In_ ULONG defaultFlags
    )
/*++

Routine Description:

    Convert a Win32k audit request into the existing read-only keyboard request shape.

Arguments:

    KeyboardRequest - Receives the keyboard request packet.
    Request - Optional Win32k request from user mode.
    DefaultFlags - Keyboard enumeration defaults for hotkey or hook mode.

Return Value:

    None. Invalid inputs are ignored by leaving a zeroed request.

--*/
{
    if (keyboardRequest == NULL) {
        return;
    }

    RtlZeroMemory(keyboardRequest, sizeof(*keyboardRequest));
    keyboardRequest->version = KSWORD_ARK_KEYBOARD_PROTOCOL_VERSION;
    keyboardRequest->flags = defaultFlags;
    keyboardRequest->maxEntries = KSWORD_ARK_WIN32K_DEFAULT_MAX_ENTRIES;
    if (request != NULL) {
        keyboardRequest->processId = request->processId;
        if (request->maxEntries != 0UL) {
            keyboardRequest->maxEntries = kswordArkWin32kNormalizeMaxEntries(request->maxEntries);
        }
    }
}

static VOID
kswordArkWin32kCopyKeyboardDetail(
    _Out_writes_(destinationChars) PWCHAR destination,
    _In_ ULONG destinationChars,
    _In_reads_(sourceChars) const WCHAR* source,
    _In_ ULONG sourceChars,
    _In_z_ PCWSTR prefix
    )
/*++

Routine Description:

    Build a bounded detail string for a Win32k row converted from keyboard audit data.

Arguments:

    Destination - Win32k protocol detail field.
    DestinationChars - Destination WCHAR capacity.
    Source - Keyboard backend detail field.
    SourceChars - Source WCHAR capacity.
    Prefix - Short conversion prefix.

Return Value:

    None. The destination is always terminated when capacity is nonzero.

--*/
{
    WCHAR sourceBuffer[KSWORD_ARK_KEYBOARD_DETAIL_CHARS];
    ULONG sourceIndex = 0UL;

    if (destination == NULL || destinationChars == 0UL) {
        return;
    }

    destination[0] = L'\0';
    RtlZeroMemory(sourceBuffer, sizeof(sourceBuffer));
    if (source != NULL && sourceChars != 0UL) {
        for (sourceIndex = 0UL;
            sourceIndex + 1UL < RTL_NUMBER_OF(sourceBuffer) &&
            sourceIndex < sourceChars &&
            source[sourceIndex] != L'\0';
            ++sourceIndex) {
            sourceBuffer[sourceIndex] = source[sourceIndex];
        }
    }

    (VOID)RtlStringCchPrintfW(
        destination,
        destinationChars,
        L"%ws%ws",
        (prefix != NULL) ? prefix : L"",
        sourceBuffer);
    destination[destinationChars - 1UL] = L'\0';
}

NTSTATUS
kswordArkWin32kQueryProfileStatus(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_WIN32K_QUERY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Query loaded win32k module state and currently observable GUI sessions.

Arguments:

    OutputBuffer - METHOD_BUFFERED output packet.
    OutputBufferLength - Writable output size.
    Request - Optional filter and budget packet.
    BytesWrittenOut - Receives bytes written.

Return Value:

    STATUS_SUCCESS on a completed diagnostic response.

--*/
{
    KswHookSystemModuleInformation* moduleInfo = NULL;
    ULONG moduleInfoBytes = 0UL;
    KswHookSystemModuleEntry win32kEntry;
    KswHookSystemModuleEntry win32kbaseEntry;
    KswHookSystemModuleEntry win32kfullEntry;
    BOOLEAN win32kLoaded = FALSE;
    BOOLEAN win32kbaseLoaded = FALSE;
    BOOLEAN win32kfullLoaded = FALSE;
    ULONG64 runtimeCapabilityMask = 0ULL;
    KSWORD_ARK_WIN32K_PROFILE_STATUS_RESPONSE* response = NULL;
    size_t entryCapacity = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;

    status = kswordArkWin32kPrepareProfileHeader(
        outputBuffer,
        outputBufferLength,
        &response,
        &entryCapacity);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = kswordArkHookBuildModuleSnapshot(&moduleInfo, &moduleInfoBytes);
    response->lastStatus = status;
    if (NT_SUCCESS(status)) {
        win32kLoaded = kswordArkWin32kFindModuleByName(moduleInfo, "win32k.sys", &win32kEntry);
        win32kbaseLoaded = kswordArkWin32kFindModuleByName(moduleInfo, "win32kbase.sys", &win32kbaseEntry);
        win32kfullLoaded = kswordArkWin32kFindModuleByName(moduleInfo, "win32kfull.sys", &win32kfullEntry);
    }

    kswordArkWin32kFillModuleState(
        &response->win32k,
        L"win32k.sys",
        win32kLoaded,
        win32kLoaded ? &win32kEntry : NULL);
    kswordArkWin32kFillModuleState(
        &response->win32kbase,
        L"win32kbase.sys",
        win32kbaseLoaded,
        win32kbaseLoaded ? &win32kbaseEntry : NULL);
    kswordArkWin32kFillModuleState(
        &response->win32kfull,
        L"win32kfull.sys",
        win32kfullLoaded,
        win32kfullLoaded ? &win32kfullEntry : NULL);

    response->capabilityMask = kswordArkWin32kModuleCapabilityMask(
        win32kLoaded,
        win32kbaseLoaded,
        win32kfullLoaded,
        win32kbaseLoaded ? &win32kbaseEntry : NULL,
        &response->missingCapabilityMask,
        &response->userGetSiloGlobals);
    runtimeCapabilityMask = kswordArkWin32kFallbackProbeCapabilityMask();
    response->capabilityMask |= runtimeCapabilityMask;

    if (!win32kbaseLoaded || !win32kfullLoaded) {
        response->status = KSWORD_ARK_WIN32K_STATUS_WIN32K_NOT_FOUND;
    }
    else if (runtimeCapabilityMask != 0ULL) {
        response->status = KSWORD_ARK_WIN32K_STATUS_PARTIAL;
    }
    else {
        response->status = KSWORD_ARK_WIN32K_STATUS_PROFILE_MISSING;
    }

    kswordArkWin32kCollectSessionSummary(response, entryCapacity, request);

    if (moduleInfo != NULL) {
        ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
    }

    *bytesWrittenOut =
        KSWORD_ARK_WIN32K_PROFILE_RESPONSE_HEADER_SIZE +
        ((size_t)response->returnedCount * sizeof(KSWORD_ARK_WIN32K_SESSION_ENTRY));
    UNREFERENCED_PARAMETER(moduleInfoBytes);
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkWin32kQueryWindowSnapshot(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_WIN32K_QUERY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Query windows through the validated runtime-signature fallback when no
    private-symbol profile is available.

--*/
{
    return kswordArkWin32kFallbackQueryWindowSnapshot(
        outputBuffer,
        outputBufferLength,
        request,
        bytesWrittenOut);
}

NTSTATUS
kswordArkWin32kQueryGuiThreadSnapshot(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_WIN32K_QUERY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    enumerate public GUI-thread identities and enrich tagQ fields only after
    the NtUserGetGUIThreadInfo-derived layout passes live window validation.

--*/
{
    return kswordArkWin32kFallbackQueryGuiThreadSnapshot(
        outputBuffer,
        outputBufferLength,
        request,
        bytesWrittenOut);
}
NTSTATUS
kswordArkWin32kQueryHotkeySnapshot(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_WIN32K_QUERY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Return a PDB-gated hotkey snapshot header that coexists with keyboard IOCTLs.

Arguments:

    OutputBuffer - METHOD_BUFFERED output packet.
    OutputBufferLength - Writable output size.
    Request - Optional request; currently used only for flags.
    BytesWrittenOut - Receives bytes written.

Return Value:

    STATUS_SUCCESS with PROFILE_MISSING until hotkey PDB fields are supplied.

--*/
{
    KSWORD_ARK_WIN32K_HOTKEY_SNAPSHOT_RESPONSE* response = NULL;
    KSWORD_ARK_ENUM_KEYBOARD_REQUEST keyboardRequest;
    KSWORD_ARK_ENUM_KEYBOARD_HOTKEYS_RESPONSE* keyboardResponse = NULL;
    ULONG entryCapacity = 0UL;
    ULONG copyCount = 0UL;
    ULONG index = 0UL;
    size_t keyboardBufferLength = 0U;
    size_t keyboardBytesWritten = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBuffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (outputBufferLength < KSWORD_ARK_WIN32K_HOTKEY_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_WIN32K_HOTKEY_SNAPSHOT_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_WIN32K_PROTOCOL_VERSION;
    response->status = KSWORD_ARK_WIN32K_STATUS_UNKNOWN;
    response->entrySize = sizeof(KSWORD_ARK_WIN32K_HOTKEY_ENTRY);
    response->flags = (request != NULL) ? request->flags : 0UL;
    response->lastStatus = STATUS_SUCCESS;
    response->capabilityMask = KSWORD_ARK_WIN32K_CAP_HOTKEY_PROFILE;
    kswordArkWin32kInitializeOffsets(&response->fieldOffsets);

    entryCapacity = (ULONG)((outputBufferLength - KSWORD_ARK_WIN32K_HOTKEY_RESPONSE_HEADER_SIZE) /
        sizeof(KSWORD_ARK_WIN32K_HOTKEY_ENTRY));
    kswordArkWin32kFillKeyboardBridgeRequest(
        &keyboardRequest,
        request,
        KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_SYSTEM |
        KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_DIAGNOSTICS);

    keyboardBufferLength = sizeof(KSWORD_ARK_ENUM_KEYBOARD_HOTKEYS_RESPONSE) +
        ((size_t)keyboardRequest.maxEntries * sizeof(KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY));
    keyboardResponse = (KSWORD_ARK_ENUM_KEYBOARD_HOTKEYS_RESPONSE*)kswordArkAllocateNonPagedPool(
        keyboardBufferLength,
        KSWORD_ARK_WIN32K_BRIDGE_TAG);
    if (keyboardResponse == NULL) {
        response->status = KSWORD_ARK_WIN32K_STATUS_READ_FAILED;
        response->lastStatus = STATUS_INSUFFICIENT_RESOURCES;
        *bytesWrittenOut = KSWORD_ARK_WIN32K_HOTKEY_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }

    status = kswordArkDriverEnumerateKeyboardHotkeys(
        keyboardResponse,
        keyboardBufferLength,
        &keyboardRequest,
        &keyboardBytesWritten);
    response->lastStatus = status;
    if (!NT_SUCCESS(status) ||
        keyboardBytesWritten < (sizeof(KSWORD_ARK_ENUM_KEYBOARD_HOTKEYS_RESPONSE) - sizeof(KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY))) {
        response->status = KSWORD_ARK_WIN32K_STATUS_READ_FAILED;
        if (NT_SUCCESS(status)) {
            response->lastStatus = STATUS_BUFFER_TOO_SMALL;
        }
        ExFreePoolWithTag(keyboardResponse, KSWORD_ARK_WIN32K_BRIDGE_TAG);
        *bytesWrittenOut = KSWORD_ARK_WIN32K_HOTKEY_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }

    response->totalCount = keyboardResponse->totalCount;
    response->returnedCount = 0UL;
    response->status = kswordArkWin32kMapKeyboardStatus(keyboardResponse->status);
    response->lastStatus = keyboardResponse->lastStatus;
    response->fieldOffsets.hotkeyNext = keyboardResponse->hotkeyNextOffset;
    response->fieldOffsets.hotkeyModifiers = keyboardResponse->hotkeyModifiersOffset;
    response->fieldOffsets.hotkeyVirtualKey = keyboardResponse->hotkeyVkOffset;
    response->fieldOffsets.hotkeyId = keyboardResponse->hotkeyIdOffset;

    copyCount = keyboardResponse->returnedCount;
    if (copyCount > entryCapacity) {
        copyCount = entryCapacity;
        response->status = KSWORD_ARK_WIN32K_STATUS_BUFFER_TRUNCATED;
        response->missingCapabilityMask |= KSWORD_ARK_WIN32K_CAP_HOTKEY_PROFILE;
    }

    for (index = 0UL; index < copyCount; ++index) {
        const KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY* sourceEntry = &keyboardResponse->entries[index];
        KSWORD_ARK_WIN32K_HOTKEY_ENTRY* targetEntry = &response->entries[index];

        RtlZeroMemory(targetEntry, sizeof(*targetEntry));
        targetEntry->source = sourceEntry->source;
        targetEntry->status = kswordArkWin32kMapKeyboardStatus(sourceEntry->status);
        targetEntry->flags = sourceEntry->flags;
        targetEntry->processId = sourceEntry->processId;
        targetEntry->threadId = sourceEntry->threadId;
        targetEntry->modifiers = sourceEntry->modifiers;
        targetEntry->virtualKey = sourceEntry->virtualKey;
        targetEntry->hotkeyId = sourceEntry->hotkeyId;
        targetEntry->depth = sourceEntry->depth;
        targetEntry->lastStatus = sourceEntry->lastStatus;
        targetEntry->hotkeyObject = sourceEntry->hotkeyObject;
        targetEntry->nextHotkeyObject = sourceEntry->nextHotkeyObject;
        targetEntry->hwnd = sourceEntry->windowObject;
        targetEntry->tagWnd = sourceEntry->windowObject;
        targetEntry->threadInfo = sourceEntry->threadInfo;
        kswordArkWin32kCopyKeyboardDetail(
            targetEntry->detail,
            KSWORD_ARK_WIN32K_DETAIL_CHARS,
            sourceEntry->detail,
            KSWORD_ARK_KEYBOARD_DETAIL_CHARS,
            L"keyboard bridge: ");
    }
    response->returnedCount = copyCount;

    ExFreePoolWithTag(keyboardResponse, KSWORD_ARK_WIN32K_BRIDGE_TAG);
    *bytesWrittenOut = KSWORD_ARK_WIN32K_HOTKEY_RESPONSE_HEADER_SIZE +
        ((size_t)response->returnedCount * sizeof(KSWORD_ARK_WIN32K_HOTKEY_ENTRY));
    return STATUS_SUCCESS;
}
