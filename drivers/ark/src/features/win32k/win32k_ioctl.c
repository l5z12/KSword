/*++

Module Name:

    win32k_ioctl.c

Abstract:

    IOCTL handlers for read-only win32k GUI audit queries.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_validation.h"
#include "win32k_query.h"

#include <ntstrsafe.h>
#include <stdarg.h>

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

#define KSWORD_ARK_WIN32K_TIMER_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_WIN32K_TIMER_SNAPSHOT_RESPONSE) - sizeof(KSWORD_ARK_WIN32K_TIMER_ENTRY))

#define KSWORD_ARK_WIN32K_EVENT_HOOK_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_WIN32K_EVENT_HOOK_SNAPSHOT_RESPONSE) - sizeof(KSWORD_ARK_WIN32K_EVENT_HOOK_ENTRY))

#define KSWORD_ARK_WIN32K_WINDOW_DETAIL_RESPONSE_SIZE \
    sizeof(KSWORD_ARK_WIN32K_WINDOW_DETAIL_RESPONSE)

typedef NTSTATUS(*KswordArkWiN32KQueryCollector)(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_WIN32K_QUERY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

static VOID
kswordArkWin32kIoctlLog(
    _In_ WDFDEVICE device,
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR formatText,
    ...
    )
/*++

Routine Description:

    Format a bounded Win32k IOCTL log message and enqueue it through the shared
    driver log channel.

Arguments:

    Device - Current framework device object.
    levelText - Existing textual log severity label.
    FormatText - printf-style ASCII format string.
    ... - Format arguments consumed only by this routine.

Return Value:

    None. Formatting failures are intentionally dropped because logging must not
    change IOCTL completion status.

--*/
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
kswordArkWin32kFillDefaultRequest(
    _Out_ KSWORD_ARK_WIN32K_QUERY_REQUEST* queryRequest,
    _In_ ULONG defaultMaxEntries
    )
/*++

Routine Description:

    Fill the default read-only Win32k query request used when R3 sends no input
    packet with a METHOD_BUFFERED query.

Arguments:

    QueryRequest - Receives the default version, diagnostic flag, and traversal
    budget.
    DefaultMaxEntries - Operation-specific default traversal budget.

Return Value:

    None. The caller supplies a stack request object.

--*/
{
    RtlZeroMemory(queryRequest, sizeof(*queryRequest));
    queryRequest->version = KSWORD_ARK_WIN32K_PROTOCOL_VERSION;
    queryRequest->flags = KSWORD_ARK_WIN32K_QUERY_FLAG_INCLUDE_DIAGNOSTICS;
    queryRequest->maxEntries = defaultMaxEntries != 0UL
        ? defaultMaxEntries
        : KSWORD_ARK_WIN32K_DEFAULT_MAX_ENTRIES;
}

static NTSTATUS
kswordArkWin32kRetrieveRequest(
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _Outptr_ KSWORD_ARK_WIN32K_QUERY_REQUEST** queryRequestOut,
    _Out_ KSWORD_ARK_WIN32K_QUERY_REQUEST* defaultRequest,
    _In_ ULONG defaultMaxEntries
    )
/*++

Routine Description:

    Retrieve an optional Win32k query packet or synthesize a bounded default
    request for legacy callers that provide output-only METHOD_BUFFERED IOCTLs.

Arguments:

    Request - Current framework request.
    InputBufferLength - Input length reported by the central dispatch callback.
    QueryRequestOut - Receives the caller packet or DefaultRequest.
    DefaultRequest - Stack storage for a synthesized request.
    DefaultMaxEntries - Operation-specific default traversal budget.

Return Value:

    STATUS_SUCCESS when a usable request is available; otherwise a buffer or
    protocol validation status.

--*/
{
    PVOID inputBuffer = NULL;
    size_t actualInputLength = 0U;
    BOOLEAN hasInput = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (queryRequestOut == NULL || defaultRequest == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *queryRequestOut = NULL;
    status = kswordArkRetrieveOptionalInputBuffer(
        request,
        inputBufferLength,
        sizeof(KSWORD_ARK_WIN32K_QUERY_REQUEST),
        &inputBuffer,
        &actualInputLength,
        &hasInput);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (hasInput) {
        *queryRequestOut = (KSWORD_ARK_WIN32K_QUERY_REQUEST*)inputBuffer;
        if ((*queryRequestOut)->version != KSWORD_ARK_WIN32K_PROTOCOL_VERSION) {
            return STATUS_REVISION_MISMATCH;
        }
        UNREFERENCED_PARAMETER(actualInputLength);
        return STATUS_SUCCESS;
    }

    kswordArkWin32kFillDefaultRequest(defaultRequest, defaultMaxEntries);
    *queryRequestOut = defaultRequest;
    UNREFERENCED_PARAMETER(actualInputLength);
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkWin32kIoctlQueryCommon(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t requiredOutputLength,
    _In_ ULONG defaultMaxEntries,
    _In_z_ PCSTR operationName,
    _In_ KswordArkWiN32KQueryCollector collector,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Common adapter for read-only Win32k IOCTLs. It performs WDF buffer retrieval,
    optional request handling, collector dispatch, and compact success/error
    logging while leaving all audit logic inside src/features/win32k.

Arguments:

    Device - Current framework device object.
    Request - Current framework request.
    InputBufferLength - Input length reported by dispatch.
    RequiredOutputLength - Fixed response header size required by the collector.
    DefaultMaxEntries - Operation-specific budget used by output-only callers.
    OperationName - Short ASCII operation name for logs.
    Collector - Feature collector routine that fills the response packet.
    BytesReturned - Receives bytes written by the collector.

Return Value:

    STATUS_SUCCESS when the collector produced a response; otherwise the first
    validation or collector failure status.

--*/
{
    KSWORD_ARK_WIN32K_QUERY_REQUEST* queryRequest = NULL;
    KSWORD_ARK_WIN32K_QUERY_REQUEST defaultRequest;
    KSWORD_ARK_WIN32K_QUERY_REQUEST requestCopy;
    PVOID outputBuffer = NULL;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (bytesReturned == NULL || operationName == NULL || collector == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkWin32kRetrieveRequest(
        request,
        inputBufferLength,
        &queryRequest,
        &defaultRequest,
        defaultMaxEntries);
    if (!NT_SUCCESS(status)) {
        kswordArkWin32kIoctlLog(device, "Error", "R0 win32k-%s ioctl: input invalid, status=0x%08X.", operationName, (unsigned int)status);
        return status;
    }

    // METHOD_BUFFERED uses one system buffer for both input and output. Keep a
    // private copy before the collector initializes its response header, or
    // response fields at the same offsets are observed as PID/TID filters.
    requestCopy = *queryRequest;
    queryRequest = &requestCopy;

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        requiredOutputLength,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkWin32kIoctlLog(device, "Error", "R0 win32k-%s ioctl: output invalid, status=0x%08X.", operationName, (unsigned int)status);
        return status;
    }

    status = collector(outputBuffer, actualOutputLength, queryRequest, bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkWin32kIoctlLog(device, "Error", "R0 win32k-%s query failed: status=0x%08X, outBytes=%Iu.", operationName, (unsigned int)status, *bytesReturned);
        return status;
    }

    kswordArkWin32kIoctlLog(device, "Info", "R0 win32k-%s query success: outBytes=%Iu.", operationName, *bytesReturned);
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkWin32kIoctlQueryProfileStatus(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle the read-only win32k profile/status IOCTL.

Arguments:

    Device - Current framework device object.
    Request - Current framework request.
    InputBufferLength - Optional query request size.
    OutputBufferLength - Dispatch-supplied output length; WDF performs the final
    buffer retrieval in the common adapter.
    BytesReturned - Receives response bytes.

Return Value:

    NTSTATUS from the common Win32k IOCTL adapter.

--*/
{
    UNREFERENCED_PARAMETER(outputBufferLength);
    return kswordArkWin32kIoctlQueryCommon(
        device,
        request,
        inputBufferLength,
        KSWORD_ARK_WIN32K_PROFILE_RESPONSE_HEADER_SIZE,
        KSWORD_ARK_WIN32K_DEFAULT_MAX_ENTRIES,
        "profile-status",
        kswordArkWin32kQueryProfileStatus,
        bytesReturned);
}

NTSTATUS
kswordArkWin32kIoctlQueryWindows(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle the read-only HWND/tagWND snapshot IOCTL.

Arguments:

    Device - Current framework device object.
    Request - Current framework request.
    InputBufferLength - Optional query request size.
    OutputBufferLength - Dispatch-supplied output length, referenced only by the
    common WDF output buffer retrieval path.
    BytesReturned - Receives response bytes.

Return Value:

    NTSTATUS from the common Win32k IOCTL adapter.

--*/
{
    UNREFERENCED_PARAMETER(outputBufferLength);
    return kswordArkWin32kIoctlQueryCommon(
        device,
        request,
        inputBufferLength,
        KSWORD_ARK_WIN32K_WINDOW_RESPONSE_HEADER_SIZE,
        KSWORD_ARK_WIN32K_DEFAULT_MAX_ENTRIES,
        "windows",
        kswordArkWin32kQueryWindowSnapshot,
        bytesReturned);
}

NTSTATUS
kswordArkWin32kIoctlQueryGuiThreads(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle the read-only GUI thread/tagQ snapshot IOCTL.

Arguments:

    Device - Current framework device object.
    Request - Current framework request.
    InputBufferLength - Optional query request size.
    OutputBufferLength - Dispatch-supplied output length, referenced only by the
    common WDF output buffer retrieval path.
    BytesReturned - Receives response bytes.

Return Value:

    NTSTATUS from the common Win32k IOCTL adapter.

--*/
{
    UNREFERENCED_PARAMETER(outputBufferLength);
    return kswordArkWin32kIoctlQueryCommon(
        device,
        request,
        inputBufferLength,
        KSWORD_ARK_WIN32K_GUI_THREAD_RESPONSE_HEADER_SIZE,
        KSWORD_ARK_WIN32K_DEFAULT_MAX_ENTRIES,
        "gui-threads",
        kswordArkWin32kQueryGuiThreadSnapshot,
        bytesReturned);
}

NTSTATUS
kswordArkWin32kIoctlQueryHotkeysPdb(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle the read-only PDB-backed hotkey snapshot skeleton IOCTL.

Arguments:

    Device - Current framework device object.
    Request - Current framework request.
    InputBufferLength - Optional query request size.
    OutputBufferLength - Dispatch-supplied output length, referenced only by the
    common WDF output buffer retrieval path.
    BytesReturned - Receives response bytes.

Return Value:

    NTSTATUS from the common Win32k IOCTL adapter.

--*/
{
    UNREFERENCED_PARAMETER(outputBufferLength);
    return kswordArkWin32kIoctlQueryCommon(
        device,
        request,
        inputBufferLength,
        KSWORD_ARK_WIN32K_HOTKEY_RESPONSE_HEADER_SIZE,
        KSWORD_ARK_WIN32K_DEFAULT_MAX_ENTRIES,
        "hotkeys-pdb",
        kswordArkWin32kQueryHotkeySnapshot,
        bytesReturned);
}

NTSTATUS
kswordArkWin32kIoctlQueryHooksPdb(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle the read-only PDB-backed hook snapshot skeleton IOCTL.

Arguments:

    Device - Current framework device object.
    Request - Current framework request.
    InputBufferLength - Optional query request size.
    OutputBufferLength - Dispatch-supplied output length, referenced only by the
    common WDF output buffer retrieval path.
    BytesReturned - Receives response bytes.

Return Value:

    NTSTATUS from the common Win32k IOCTL adapter.

--*/
{
    UNREFERENCED_PARAMETER(outputBufferLength);
    return kswordArkWin32kIoctlQueryCommon(
        device,
        request,
        inputBufferLength,
        KSWORD_ARK_WIN32K_HOOK_RESPONSE_HEADER_SIZE,
        KSWORD_ARK_WIN32K_MESSAGE_HOOK_DEFAULT_MAX_ENTRIES,
        "hooks-pdb",
        kswordArkWin32kQueryHookSnapshot,
        bytesReturned);
}

NTSTATUS
kswordArkWin32kIoctlQueryTimers(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle the read-only gTimerHashTable/tagTIMER snapshot IOCTL.

Arguments:

    Device - Current framework device object.
    Request - Current framework request.
    InputBufferLength - Optional query request size.
    OutputBufferLength - Dispatch-supplied output length, referenced by the
    common WDF output buffer retrieval path.
    BytesReturned - Receives response bytes.

Return Value:

    NTSTATUS from the common Win32k IOCTL adapter.

--*/
{
    UNREFERENCED_PARAMETER(outputBufferLength);
    return kswordArkWin32kIoctlQueryCommon(
        device,
        request,
        inputBufferLength,
        KSWORD_ARK_WIN32K_TIMER_RESPONSE_HEADER_SIZE,
        KSWORD_ARK_WIN32K_DEFAULT_MAX_ENTRIES,
        "timers",
        kswordArkWin32kQueryTimerSnapshot,
        bytesReturned);
}

NTSTATUS
kswordArkWin32kIoctlQueryEventHooks(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle the read-only gpWinEventHooks/tagEVENTHOOK snapshot IOCTL.

--*/
{
    UNREFERENCED_PARAMETER(outputBufferLength);
    return kswordArkWin32kIoctlQueryCommon(
        device,
        request,
        inputBufferLength,
        KSWORD_ARK_WIN32K_EVENT_HOOK_RESPONSE_HEADER_SIZE,
        KSWORD_ARK_WIN32K_DEFAULT_MAX_ENTRIES,
        "event-hooks",
        kswordArkWin32kQueryEventHookSnapshot,
        bytesReturned);
}

NTSTATUS
kswordArkWin32kIoctlQueryWindowDetail(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle the fixed-size read-only single-window detail readiness IOCTL.

Arguments:

    Device - Current framework device object, used for compact diagnostics.
    Request - Current framework request.
    InputBufferLength - Input length; must contain the fixed detail request.
    OutputBufferLength - Output length; must contain the fixed detail response.
    BytesReturned - Receives response bytes.

Return Value:

    NTSTATUS from buffer validation or the win32k detail backend.

--*/
{
    KSWORD_ARK_WIN32K_WINDOW_DETAIL_REQUEST requestCopy;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(KSWORD_ARK_WIN32K_WINDOW_DETAIL_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkWin32kIoctlLog(device, "Error", "R0 win32k-window-detail ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    RtlZeroMemory(&requestCopy, sizeof(requestCopy));
    RtlCopyMemory(&requestCopy, inputBuffer, sizeof(requestCopy));

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        KSWORD_ARK_WIN32K_WINDOW_DETAIL_RESPONSE_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkWin32kIoctlLog(device, "Error", "R0 win32k-window-detail ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkWin32kQueryWindowDetail(
        (KSWORD_ARK_WIN32K_WINDOW_DETAIL_RESPONSE*)outputBuffer,
        actualOutputLength,
        &requestCopy,
        bytesReturned);
    kswordArkWin32kIoctlLog(
        device,
        NT_SUCCESS(status) ? "Info" : "Error",
        "R0 win32k-window-detail query completed: status=0x%08X, outBytes=%Iu.",
        (unsigned int)status,
        *bytesReturned);
    return status;
}
