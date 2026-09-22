/*++

Module Name:

    keyboard_ioctl.c

Abstract:

    IOCTL handlers for read-only win32k keyboard hotkey/hook inspection.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntstrsafe.h>
#include <stdarg.h>

#define KSWORD_ARK_KEYBOARD_HOTKEY_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_ENUM_KEYBOARD_HOTKEYS_RESPONSE) - sizeof(KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY))

#define KSWORD_ARK_KEYBOARD_HOOK_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_ENUM_KEYBOARD_HOOKS_RESPONSE) - sizeof(KSWORD_ARK_KEYBOARD_HOOK_ENTRY))

static VOID
kswordArkKeyboardIoctlLog(
    _In_ WDFDEVICE device,
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR formatText,
    ...
    )
{
    CHAR logMessage[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
    va_list arguments;

    va_start(arguments, formatText);
    if (NT_SUCCESS(RtlStringCbVPrintfA(logMessage, sizeof(logMessage), formatText, arguments))) {
        (VOID)kswordArkDriverEnqueueLogFrame(device, levelText, logMessage);
    }
    va_end(arguments);
}

static VOID
kswordArkKeyboardFillDefaultRequest(
    _Out_ KSWORD_ARK_ENUM_KEYBOARD_REQUEST* request,
    _In_ ULONG defaultFlags
    )
{
    RtlZeroMemory(request, sizeof(*request));
    request->version = KSWORD_ARK_KEYBOARD_PROTOCOL_VERSION;
    request->flags = defaultFlags;
    request->processId = 0UL;
    request->maxEntries = 1024UL;
}

static NTSTATUS
kswordArkKeyboardRetrieveRequest(
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ ULONG defaultFlags,
    _Out_ KSWORD_ARK_ENUM_KEYBOARD_REQUEST** requestOut,
    _Out_ KSWORD_ARK_ENUM_KEYBOARD_REQUEST* defaultRequest
    )
{
    PVOID inputBuffer = NULL;
    size_t actualInputLength = 0;
    BOOLEAN hasInput = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (requestOut == NULL || defaultRequest == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *requestOut = NULL;
    status = kswordArkRetrieveOptionalInputBuffer(
        request,
        inputBufferLength,
        sizeof(KSWORD_ARK_ENUM_KEYBOARD_REQUEST),
        &inputBuffer,
        &actualInputLength,
        &hasInput);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (hasInput) {
        *requestOut = (KSWORD_ARK_ENUM_KEYBOARD_REQUEST*)inputBuffer;
    }
    else {
        kswordArkKeyboardFillDefaultRequest(defaultRequest, defaultFlags);
        *requestOut = defaultRequest;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkKeyboardIoctlEnumHotkeys(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
    KSWORD_ARK_ENUM_KEYBOARD_REQUEST* enumRequest = NULL;
    KSWORD_ARK_ENUM_KEYBOARD_REQUEST defaultRequest;
    PVOID outputBuffer = NULL;
    size_t actualOutputLength = 0;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0;

    status = kswordArkKeyboardRetrieveRequest(
        request,
        inputBufferLength,
        KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_SYSTEM | KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_DIAGNOSTICS,
        &enumRequest,
        &defaultRequest);
    if (!NT_SUCCESS(status)) {
        kswordArkKeyboardIoctlLog(device, "Error", "R0 enum-keyboard-hotkeys ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        KSWORD_ARK_KEYBOARD_HOTKEY_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkKeyboardIoctlLog(device, "Error", "R0 enum-keyboard-hotkeys ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkDriverEnumerateKeyboardHotkeys(outputBuffer, actualOutputLength, enumRequest, bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkKeyboardIoctlLog(device, "Error", "R0 enum-keyboard-hotkeys failed: status=0x%08X, outBytes=%Iu.", (unsigned int)status, *bytesReturned);
        return status;
    }

    if (*bytesReturned >= KSWORD_ARK_KEYBOARD_HOTKEY_RESPONSE_HEADER_SIZE) {
        const KSWORD_ARK_ENUM_KEYBOARD_HOTKEYS_RESPONSE* response =
            (const KSWORD_ARK_ENUM_KEYBOARD_HOTKEYS_RESPONSE*)outputBuffer;
        kswordArkKeyboardIoctlLog(
            device,
            "Info",
            "R0 enum-keyboard-hotkeys success: status=%lu, total=%lu, returned=%lu.",
            (unsigned long)response->status,
            (unsigned long)response->totalCount,
            (unsigned long)response->returnedCount);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkKeyboardIoctlEnumHooks(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
    KSWORD_ARK_ENUM_KEYBOARD_REQUEST* enumRequest = NULL;
    KSWORD_ARK_ENUM_KEYBOARD_REQUEST defaultRequest;
    PVOID outputBuffer = NULL;
    size_t actualOutputLength = 0;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0;

    status = kswordArkKeyboardRetrieveRequest(
        request,
        inputBufferLength,
        KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_THREAD_HOOKS |
            KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_GLOBAL_HOOKS |
            KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_DIAGNOSTICS,
        &enumRequest,
        &defaultRequest);
    if (!NT_SUCCESS(status)) {
        kswordArkKeyboardIoctlLog(device, "Error", "R0 enum-keyboard-hooks ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        KSWORD_ARK_KEYBOARD_HOOK_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkKeyboardIoctlLog(device, "Error", "R0 enum-keyboard-hooks ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkDriverEnumerateKeyboardHooks(outputBuffer, actualOutputLength, enumRequest, bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkKeyboardIoctlLog(device, "Error", "R0 enum-keyboard-hooks failed: status=0x%08X, outBytes=%Iu.", (unsigned int)status, *bytesReturned);
        return status;
    }

    if (*bytesReturned >= KSWORD_ARK_KEYBOARD_HOOK_RESPONSE_HEADER_SIZE) {
        const KSWORD_ARK_ENUM_KEYBOARD_HOOKS_RESPONSE* response =
            (const KSWORD_ARK_ENUM_KEYBOARD_HOOKS_RESPONSE*)outputBuffer;
        kswordArkKeyboardIoctlLog(
            device,
            "Info",
            "R0 enum-keyboard-hooks success: status=%lu, total=%lu, returned=%lu.",
            (unsigned long)response->status,
            (unsigned long)response->totalCount,
            (unsigned long)response->returnedCount);
    }

    return STATUS_SUCCESS;
}
