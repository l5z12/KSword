/*++

Module Name:

    thread_ioctl.c

Abstract:

    IOCTL handlers for KswordARK thread inspection operations.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "../kernel/hook_scan_support.h"
#include "../../dispatch/ioctl_validation.h"
#include "../../platform/pool_compat.h"

#include <ntstrsafe.h>
#include <stdarg.h>

#define KSWORD_ARK_THREAD_ENUM_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_ENUM_THREAD_RESPONSE) - sizeof(KSWORD_ARK_THREAD_ENTRY))

#ifndef THREAD_SUSPEND_RESUME
#define THREAD_SUSPEND_RESUME (0x0002)
#endif

typedef NTSTATUS(NTAPI* KswordZwOrNtThreadSuspendFn)(
    _In_ HANDLE threadHandle,
    _Out_opt_ PULONG previousSuspendCount
    );

NTSYSAPI
NTSTATUS
NTAPI
PsLookupThreadByThreadId(
    _In_ HANDLE threadId,
    _Outptr_ PETHREAD* thread
    );

NTKERNELAPI
NTSTATUS
ObOpenObjectByPointer(
    _In_ PVOID object,
    _In_ ULONG handleAttributes,
    _In_opt_ PACCESS_STATE passedAccessState,
    _In_opt_ ACCESS_MASK desiredAccess,
    _In_opt_ POBJECT_TYPE objectType,
    _In_ KPROCESSOR_MODE accessMode,
    _Out_ PHANDLE handle
    );

static VOID
kswordArkThreadIoctlLog(
    _In_ WDFDEVICE device,
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR formatText,
    ...
    )
/*++

Routine Description:

    Format and enqueue one thread-handler diagnostic message. This centralizes log formatting
    to avoid embedding repeated RtlStringCbVPrintfA calls within the handler enumeration.

Arguments:

    Device - WDF device that owns the log channel.
    levelText - Log level string.
    FormatText - printf-style ANSI message template.
    ... - Template arguments.

Return Value:

    None. Log failure does not affect the main IOCTL path.

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

NTSTATUS
kswordArkThreadIoctlEnumThread(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_ENUM_THREAD. The input packet is optional; if omitted,
    enumerate all threads and request all Phase-3 extended fields. The output packet
    allows partial filling; R3 uses totalCount to determine if a larger buffer is needed.

Arguments:

    Device - WDF device used for logging.
    Request - Current IOCTL request.
    InputBufferLength - Supplied input bytes; shorter input selects defaults.
    OutputBufferLength - Supplied output bytes; checked by WDF output retrieval.
    BytesReturned - Receives the feature-written response byte count.

Return Value:

    NTSTATUS from buffer retrieval or kswordArkDriverEnumerateThreads.

--*/
{
    KSWORD_ARK_ENUM_THREAD_REQUEST* enumRequest = NULL;
    KSWORD_ARK_ENUM_THREAD_REQUEST defaultRequest = { 0 };
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0;
    size_t actualOutputLength = 0;
    BOOLEAN hasInput = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0;

    status = kswordArkRetrieveOptionalInputBuffer(
        request,
        inputBufferLength,
        sizeof(KSWORD_ARK_ENUM_THREAD_REQUEST),
        &inputBuffer,
        &actualInputLength,
        &hasInput);
    if (!NT_SUCCESS(status)) {
        kswordArkThreadIoctlLog(device, "Error", "R0 enum-thread ioctl: input buffer invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    if (hasInput) {
        enumRequest = (KSWORD_ARK_ENUM_THREAD_REQUEST*)inputBuffer;
    }
    else {
        enumRequest = &defaultRequest;
        enumRequest->flags = KSWORD_ARK_ENUM_THREAD_FLAG_INCLUDE_ALL;
        enumRequest->processId = 0UL;
        enumRequest->reserved0 = 0UL;
        enumRequest->reserved1 = 0UL;
    }

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        KSWORD_ARK_THREAD_ENUM_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkThreadIoctlLog(device, "Error", "R0 enum-thread ioctl: output buffer invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkDriverEnumerateThreads(outputBuffer, actualOutputLength, enumRequest, bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkThreadIoctlLog(device, "Error", "R0 enum-thread failed: status=0x%08X, outBytes=%Iu.", (unsigned int)status, *bytesReturned);
        return status;
    }

    if (*bytesReturned >= KSWORD_ARK_THREAD_ENUM_RESPONSE_HEADER_SIZE) {
        KSWORD_ARK_ENUM_THREAD_RESPONSE* responseHeader = (KSWORD_ARK_ENUM_THREAD_RESPONSE*)outputBuffer;
        kswordArkThreadIoctlLog(
            device,
            "Info",
            "R0 enum-thread success: total=%lu, returned=%lu, outBytes=%Iu.",
            (unsigned long)responseHeader->totalCount,
            (unsigned long)responseHeader->returnedCount,
            *bytesReturned);
    }
    else {
        kswordArkThreadIoctlLog(device, "Warn", "R0 enum-thread success: outBytes=%Iu (header partial).", *bytesReturned);
    }

    return status;
}

NTSTATUS
kswordArkThreadIoctlTerminate(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_TERMINATE_THREAD. The handler validates the fixed
    PID/TID request, applies the existing destructive-process safety policy, and
    terminates only the referenced target thread.

Arguments:

    Device - WDF device used for logging and safety-policy evaluation.
    Request - Current IOCTL request.
    InputBufferLength - Caller-supplied input length; used by WDF retrieval.
    OutputBufferLength - Caller-supplied output length; unused for this IOCTL.
    BytesReturned - Receives sizeof(request) on success and zero on failure.

Return Value:

    NTSTATUS from validation, safety policy, or the specified-thread backend.

--*/
{
    KSWORD_ARK_TERMINATE_THREAD_REQUEST* terminateRequest = NULL;
    PVOID inputBuffer = NULL;
    size_t actualInputLength = 0;
    NTSTATUS status = STATUS_SUCCESS;

    // This IOCTL only reads a fixed input packet and does not require an output buffer.
    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    // Caller must provide a storage location for the returned byte count.
    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0;

    // Retrieve the complete shared thread termination request from a METHOD_BUFFERED request.
    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(KSWORD_ARK_TERMINATE_THREAD_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkThreadIoctlLog(device, "Error", "R0 terminate-thread ioctl: input buffer invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    // Input packets with validated length can be safely cast to the request structure.
    terminateRequest = (KSWORD_ARK_TERMINATE_THREAD_REQUEST*)inputBuffer;
    status = kswordArkValidateUserPid((ULONG)terminateRequest->processId);
    if (!NT_SUCCESS(status) || terminateRequest->threadId == 0UL) {
        kswordArkThreadIoctlLog(
            device,
            "Warn",
            "R0 terminate-thread ioctl: pid=%lu, tid=%lu rejected, status=0x%08X.",
            (unsigned long)terminateRequest->processId,
            (unsigned long)terminateRequest->threadId,
            (unsigned int)(NT_SUCCESS(status) ? STATUS_INVALID_PARAMETER : status));
        return NT_SUCCESS(status) ? STATUS_INVALID_PARAMETER : status;
    }

    // Specifying thread termination is a destructive process operation; reuse the existing process safety policy.
    {
        KswordArkSafetyContext safetyContext;
        RtlZeroMemory(&safetyContext, sizeof(safetyContext));
        safetyContext.operation = KSWORD_ARK_SAFETY_OPERATION_PROCESS_TERMINATE;
        safetyContext.targetProcessId = (ULONG)terminateRequest->processId;
        safetyContext.contextFlags = KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
        status = kswordArkSafetyEvaluate(device, &safetyContext);
        if (!NT_SUCCESS(status)) {
            kswordArkThreadIoctlLog(
                device,
                "Warn",
                "R0 terminate-thread denied by safety policy: pid=%lu, tid=%lu, status=0x%08X.",
                (unsigned long)terminateRequest->processId,
                (unsigned long)terminateRequest->threadId,
                (unsigned int)status);
            return status;
        }
    }

    // The backend will re-reference and validate the process owning the ETHREAD; it does not trust any object addresses passed from R3.
    status = kswordArkDriverTerminateThreadById(
        device,
        (ULONG)terminateRequest->processId,
        (ULONG)terminateRequest->threadId,
        (NTSTATUS)terminateRequest->exitStatus);
    if (NT_SUCCESS(status)) {
        kswordArkThreadIoctlLog(
            device,
            "Info",
            "R0 terminate-thread success: pid=%lu, tid=%lu.",
            (unsigned long)terminateRequest->processId,
            (unsigned long)terminateRequest->threadId);
        *bytesReturned = sizeof(KSWORD_ARK_TERMINATE_THREAD_REQUEST);
    }
    else {
        kswordArkThreadIoctlLog(
            device,
            "Error",
            "R0 terminate-thread failed: pid=%lu, tid=%lu, status=0x%08X.",
            (unsigned long)terminateRequest->processId,
            (unsigned long)terminateRequest->threadId,
            (unsigned int)status);
    }

    return status;
}

static KswordZwOrNtThreadSuspendFn
kswordArkResolveThreadSuspendRoutine(
    _In_ BOOLEAN suspend
    )
{
    UNICODE_STRING routineName;
    KswordZwOrNtThreadSuspendFn routine = NULL;

    RtlInitUnicodeString(&routineName, suspend ? L"ZwSuspendThread" : L"ZwResumeThread");
    routine = (KswordZwOrNtThreadSuspendFn)MmGetSystemRoutineAddress(&routineName);
    if (routine != NULL) {
        return routine;
    }

    RtlInitUnicodeString(&routineName, suspend ? L"NtSuspendThread" : L"NtResumeThread");
    return (KswordZwOrNtThreadSuspendFn)MmGetSystemRoutineAddress(&routineName);
}

static NTSTATUS
kswordArkDriverSetThreadSuspendedById(
    _In_ WDFDEVICE device,
    _In_ ULONG processId,
    _In_ ULONG threadId,
    _In_ BOOLEAN suspend
    )
/*++

Routine Description:

    Reference one ETHREAD by TID, verify that it still belongs to the requested
    user process, then suspend or resume it through a kernel thread handle.

Arguments:

    Device - WDF device used for diagnostics.
    ProcessId - Expected owner PID.
    ThreadId - Target TID.
    Suspend - TRUE to increment the suspend count, FALSE to decrement it.

Return Value:

    NTSTATUS from validation, ownership checking, handle creation, or the
    resolved Zw/Nt thread control routine.

--*/
{
    KswordZwOrNtThreadSuspendFn controlRoutine = NULL;
    PETHREAD threadObject = NULL;
    HANDLE threadHandle = NULL;
    ULONG actualProcessId = 0UL;
    ULONG previousSuspendCount = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (processId <= 4UL || threadId == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = PsLookupThreadByThreadId(ULongToHandle(threadId), &threadObject);
    if (!NT_SUCCESS(status)) {
        kswordArkThreadIoctlLog(
            device,
            "Warn",
            "R0 thread-control lookup failed: pid=%lu, tid=%lu, status=0x%08X.",
            (unsigned long)processId,
            (unsigned long)threadId,
            (unsigned int)status);
        return status;
    }

    actualProcessId = HandleToULong(PsGetThreadProcessId(threadObject));
    if (actualProcessId != processId) {
        status = STATUS_NOT_FOUND;
        kswordArkThreadIoctlLog(
            device,
            "Warn",
            "R0 thread-control ownership mismatch: requestPid=%lu, actualPid=%lu, tid=%lu.",
            (unsigned long)processId,
            (unsigned long)actualProcessId,
            (unsigned long)threadId);
        goto Exit;
    }

    // Suspending the thread currently processing this IOCTL would cause the request to hang indefinitely, so it is explicitly rejected.
    if (suspend && threadObject == PsGetCurrentThread()) {
        status = STATUS_INVALID_DEVICE_STATE;
        kswordArkThreadIoctlLog(
            device,
            "Warn",
            "R0 suspend-thread rejected current request thread: pid=%lu, tid=%lu.",
            (unsigned long)processId,
            (unsigned long)threadId);
        goto Exit;
    }

    controlRoutine = kswordArkResolveThreadSuspendRoutine(suspend);
    if (controlRoutine == NULL) {
        status = STATUS_PROCEDURE_NOT_FOUND;
        goto Exit;
    }

    status = ObOpenObjectByPointer(
        threadObject,
        OBJ_KERNEL_HANDLE,
        NULL,
        THREAD_SUSPEND_RESUME,
        *PsThreadType,
        KernelMode,
        &threadHandle);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    status = controlRoutine(threadHandle, &previousSuspendCount);
    kswordArkThreadIoctlLog(
        device,
        NT_SUCCESS(status) ? "Info" : "Warn",
        "R0 %s-thread result: pid=%lu, tid=%lu, previousSuspendCount=%lu, status=0x%08X.",
        suspend ? "suspend" : "resume",
        (unsigned long)processId,
        (unsigned long)threadId,
        (unsigned long)previousSuspendCount,
        (unsigned int)status);

Exit:
    if (threadHandle != NULL) {
        ZwClose(threadHandle);
        threadHandle = NULL;
    }
    if (threadObject != NULL) {
        ObDereferenceObject(threadObject);
        threadObject = NULL;
    }
    return status;
}

NTSTATUS
kswordArkThreadIoctlSetSuspended(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_SET_THREAD_SUSPENDED. Suspend requests reuse the
    destructive suspend safety policy; resume remains available as recovery.

Arguments:

    Device - WDF device used for logging and safety-policy evaluation.
    Request - Current IOCTL request.
    InputBufferLength - Caller input length; validated through WDF retrieval.
    OutputBufferLength - Caller output length; unused.
    BytesReturned - Receives request size on success and zero on failure.

Return Value:

    NTSTATUS from validation, safety policy, or the thread-control backend.

--*/
{
    KSWORD_ARK_SET_THREAD_SUSPENDED_REQUEST* controlRequest = NULL;
    PVOID inputBuffer = NULL;
    size_t actualInputLength = 0;
    BOOLEAN suspend = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0;

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(KSWORD_ARK_SET_THREAD_SUSPENDED_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkThreadIoctlLog(
            device,
            "Error",
            "R0 thread-control ioctl: input buffer invalid, status=0x%08X.",
            (unsigned int)status);
        return status;
    }

    controlRequest = (KSWORD_ARK_SET_THREAD_SUSPENDED_REQUEST*)inputBuffer;
    status = kswordArkValidateUserPid((ULONG)controlRequest->processId);
    if (!NT_SUCCESS(status) || controlRequest->threadId == 0UL) {
        return NT_SUCCESS(status) ? STATUS_INVALID_PARAMETER : status;
    }
    if (controlRequest->action == KSWORD_ARK_THREAD_SUSPEND_ACTION_SUSPEND) {
        suspend = TRUE;
    }
    else if (controlRequest->action != KSWORD_ARK_THREAD_SUSPEND_ACTION_RESUME) {
        return STATUS_INVALID_PARAMETER;
    }

    if (suspend) {
        KswordArkSafetyContext safetyContext;
        RtlZeroMemory(&safetyContext, sizeof(safetyContext));
        safetyContext.operation = KSWORD_ARK_SAFETY_OPERATION_PROCESS_SUSPEND;
        safetyContext.targetProcessId = (ULONG)controlRequest->processId;
        safetyContext.contextFlags = KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
        status = kswordArkSafetyEvaluate(device, &safetyContext);
        if (!NT_SUCCESS(status)) {
            kswordArkThreadIoctlLog(
                device,
                "Warn",
                "R0 suspend-thread denied by safety policy: pid=%lu, tid=%lu, status=0x%08X.",
                (unsigned long)controlRequest->processId,
                (unsigned long)controlRequest->threadId,
                (unsigned int)status);
            return status;
        }
    }

    status = kswordArkDriverSetThreadSuspendedById(
        device,
        (ULONG)controlRequest->processId,
        (ULONG)controlRequest->threadId,
        suspend);
    if (NT_SUCCESS(status)) {
        *bytesReturned = sizeof(KSWORD_ARK_SET_THREAD_SUSPENDED_REQUEST);
    }
    return status;
}

static NTSTATUS
kswordArkDriverThreadVerifyLiveIdentity(
    _In_ PETHREAD threadObject,
    _In_ const KSWORD_ARK_CONTROL_DRIVER_THREAD_REQUEST* controlRequest,
    _Out_opt_ ULONG64* actualStartAddressOut
    )
{
    KSWORD_ARK_THREAD_DETAIL_REQUEST detailRequest;
    KSWORD_ARK_THREAD_DETAIL_RESPONSE detailResponse;
    ULONG64 actualStartAddress = 0ULL;
    size_t detailBytes = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (actualStartAddressOut != NULL) {
        *actualStartAddressOut = 0ULL;
    }
    if (threadObject == NULL || controlRequest == NULL ||
        controlRequest->threadId == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Even referenced objects must verify PS public identity to prevent misrouting to other ETHREADs in the call chain.
    if (HandleToULong(PsGetThreadId(threadObject)) != controlRequest->threadId ||
        HandleToULong(PsGetThreadProcessId(threadObject)) != 4UL) {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

#if (NTDDI_VERSION >= NTDDI_WINTHRESHOLD)
    if (controlRequest->expectedCreateTime100ns != 0ULL) {
        const LONGLONG kCreateTime = PsGetThreadCreateTime(threadObject);
        if (kCreateTime <= 0 ||
            (ULONG64)kCreateTime != controlRequest->expectedCreateTime100ns) {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
    }
#else
    // Old WDK only rejected when the caller actually provided a creation time; missing time no longer closes the control entry.
    if (ControlRequest->expectedCreateTime100ns != 0ULL) {
        return STATUS_NOT_SUPPORTED;
    }
#endif

    RtlZeroMemory(&detailRequest, sizeof(detailRequest));
    RtlZeroMemory(&detailResponse, sizeof(detailResponse));
    detailRequest.version = KSWORD_ARK_THREAD_PROTOCOL_VERSION;
    detailRequest.flags = KSWORD_ARK_THREAD_DETAIL_FLAG_INCLUDE_START;
    detailRequest.threadId = controlRequest->threadId;
    detailRequest.processId = 4UL;
    status = kswordArkDriverQueryThreadDetail(
        &detailResponse,
        sizeof(detailResponse),
        &detailRequest,
        &detailBytes);
    if (!NT_SUCCESS(status) ||
        detailResponse.processId != 4UL) {
        return NT_SUCCESS(status) ? STATUS_OBJECT_NAME_NOT_FOUND : status;
    }

    if ((detailResponse.fieldFlags & KSWORD_ARK_THREAD_DETAIL_FIELD_WIN32_START_ADDRESS) != 0UL) {
        actualStartAddress = detailResponse.win32StartAddress;
    }
    else if ((detailResponse.fieldFlags & KSWORD_ARK_THREAD_DETAIL_FIELD_START_ADDRESS) != 0UL) {
        actualStartAddress = detailResponse.startAddress;
    }
    if (controlRequest->expectedStartAddress != 0ULL &&
        !(((detailResponse.fieldFlags & KSWORD_ARK_THREAD_DETAIL_FIELD_START_ADDRESS) != 0UL &&
           controlRequest->expectedStartAddress == detailResponse.startAddress) ||
          ((detailResponse.fieldFlags & KSWORD_ARK_THREAD_DETAIL_FIELD_WIN32_START_ADDRESS) != 0UL &&
           controlRequest->expectedStartAddress == detailResponse.win32StartAddress))) {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    if (actualStartAddressOut != NULL) {
        *actualStartAddressOut = actualStartAddress;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkDriverControlDriverThread(
    _In_ WDFDEVICE device,
    _In_ const KSWORD_ARK_CONTROL_DRIVER_THREAD_REQUEST* controlRequest
    )
/*++

Routine Description:

    Validate one PID 4 system thread against all identity fields supplied by R3,
    then suspend, resume, or terminate it.  Missing optional fields do not
    disable the control entry.

Arguments:

    Device - WDF device used for diagnostics and safety evaluation.
    ControlRequest - Fixed request containing TID, action, confirmation, and
    the R3-observed start address used as an anti-stale consistency check.

Return Value:

    NTSTATUS from identity/module validation, safety policy, or thread control.

--*/
{
    KswHookSystemModuleInformation* moduleInfo = NULL;
    const KswHookSystemModuleEntry* ownerModule = NULL;
    const UCHAR* moduleFileName = NULL;
    ULONG moduleFileNameBytes = 0UL;
    ULONG moduleInfoBytes = 0UL;
    WCHAR moduleNameWide[128] = L"<unresolved>";
    USHORT moduleNameChars = 0U;
    PETHREAD threadObject = NULL;
    PETHREAD actionThreadObject = NULL;
    HANDLE threadHandle = NULL;
    ULONG previousSuspendCount = 0UL;
    ULONG64 actualStartAddress = 0ULL;
    KswordZwOrNtThreadSuspendFn suspendRoutine = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (controlRequest == NULL ||
        controlRequest->size != sizeof(*controlRequest) ||
        controlRequest->version != KSWORD_ARK_DRIVER_THREAD_CONTROL_PROTOCOL_VERSION ||
        controlRequest->threadId == 0UL ||
        (controlRequest->flags & ~KSWORD_ARK_DRIVER_THREAD_CONTROL_FLAG_VALID_MASK) != 0UL ||
        controlRequest->reserved0 != 0UL ||
        controlRequest->reserved1 != 0UL ||
        (controlRequest->action != KSWORD_ARK_DRIVER_THREAD_ACTION_SUSPEND &&
         controlRequest->action != KSWORD_ARK_DRIVER_THREAD_ACTION_RESUME &&
         controlRequest->action != KSWORD_ARK_DRIVER_THREAD_ACTION_TERMINATE)) {
        return STATUS_INVALID_PARAMETER;
    }
    if ((controlRequest->action == KSWORD_ARK_DRIVER_THREAD_ACTION_SUSPEND ||
         controlRequest->action == KSWORD_ARK_DRIVER_THREAD_ACTION_TERMINATE) &&
        (controlRequest->flags & KSWORD_ARK_DRIVER_THREAD_CONTROL_FLAG_UI_CONFIRMED) == 0UL) {
        return STATUS_ACCESS_DENIED;
    }
    if (controlRequest->action == KSWORD_ARK_DRIVER_THREAD_ACTION_RESUME &&
        controlRequest->flags != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (controlRequest->action == KSWORD_ARK_DRIVER_THREAD_ACTION_TERMINATE) {
        if (controlRequest->terminateMethod <
                KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_PSP_BY_POINTER ||
            controlRequest->terminateMethod >
                KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_SPECIAL_TO_NORMAL_APC) {
            return STATUS_INVALID_PARAMETER;
        }
    }
    else if (controlRequest->terminateMethod !=
             KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_NONE) {
        return STATUS_INVALID_PARAMETER;
    }

    // Hold the target ETHREAD until all address/module checksum actions complete to prevent TID reuse races.
    status = PsLookupThreadByThreadId(
        ULongToHandle(controlRequest->threadId),
        &threadObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (threadObject == PsGetCurrentThread() &&
        controlRequest->action != KSWORD_ARK_DRIVER_THREAD_ACTION_RESUME) {
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }

    status = kswordArkDriverThreadVerifyLiveIdentity(
        threadObject,
        controlRequest,
        &actualStartAddress);
    if (!NT_SUCCESS(status)) {
        kswordArkThreadIoctlLog(
            device,
            "Warn",
            "Driver-thread control identity rejected: tid=%lu, expectedStart=0x%I64X, expectedCreateTime100ns=%I64u, status=0x%08X.",
            (unsigned long)controlRequest->threadId,
            controlRequest->expectedStartAddress,
            controlRequest->expectedCreateTime100ns,
            (unsigned int)status);
        goto Exit;
    }

    // The module snapshot is used only for audit text; ntoskrnl, the driver itself, unknown modules, or missing start addresses
    // are no longer treated as control protection conditions. If the snapshot fails, continue using the <unresolved> target text.
    status = kswordArkHookBuildModuleSnapshot(&moduleInfo, &moduleInfoBytes);
    if (NT_SUCCESS(status) && actualStartAddress != 0ULL) {
        ownerModule = kswordArkHookFindModuleForAddress(
            moduleInfo,
            (ULONG_PTR)actualStartAddress);
        if (ownerModule != NULL) {
            kswordArkHookGetModuleFileName(
                ownerModule,
                &moduleFileName,
                &moduleFileNameBytes);
            kswordArkHookCopyBoundedAnsiToWide(
                moduleFileName,
                moduleFileNameBytes,
                moduleNameWide,
                RTL_NUMBER_OF(moduleNameWide));
        }
    }
    status = STATUS_SUCCESS;
    while (moduleNameChars + 1U < RTL_NUMBER_OF(moduleNameWide) &&
           moduleNameWide[moduleNameChars] != L'\0') {
        ++moduleNameChars;
    }

    if (controlRequest->action != KSWORD_ARK_DRIVER_THREAD_ACTION_RESUME) {
        KswordArkSafetyContext safetyContext;
        RtlZeroMemory(&safetyContext, sizeof(safetyContext));
        safetyContext.operation = KSWORD_ARK_SAFETY_OPERATION_DRIVER_THREAD_CONTROL;
        safetyContext.contextFlags =
            (controlRequest->flags & KSWORD_ARK_DRIVER_THREAD_CONTROL_FLAG_UI_CONFIRMED) != 0UL
            ? KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED
            : 0UL;
        safetyContext.targetText = moduleNameWide;
        safetyContext.targetTextChars = moduleNameChars;
        status = kswordArkSafetyEvaluate(device, &safetyContext);
        if (!NT_SUCCESS(status)) {
            goto Exit;
        }
    }

    // Re-reference the ETHREAD by TID at the action entry point and verify it remains the same object originally held.
    // Subsequently verify the TID and the StartAddress/CreateTime actually provided in the request against the new reference.
    status = PsLookupThreadByThreadId(
        ULongToHandle(controlRequest->threadId),
        &actionThreadObject);
    if (!NT_SUCCESS(status) || actionThreadObject != threadObject) {
        if (NT_SUCCESS(status)) {
            status = STATUS_OBJECT_NAME_NOT_FOUND;
        }
        goto Exit;
    }
    status = kswordArkDriverThreadVerifyLiveIdentity(
        actionThreadObject,
        controlRequest,
        &actualStartAddress);
    if (!NT_SUCCESS(status)) {
        kswordArkThreadIoctlLog(
            device,
            "Warn",
            "Driver-thread control final identity check failed: tid=%lu, expectedStart=0x%I64X, expectedCreateTime100ns=%I64u, status=0x%08X.",
            (unsigned long)controlRequest->threadId,
            controlRequest->expectedStartAddress,
            controlRequest->expectedCreateTime100ns,
            (unsigned int)status);
        goto Exit;
    }

    if (controlRequest->action == KSWORD_ARK_DRIVER_THREAD_ACTION_TERMINATE) {
        switch (controlRequest->terminateMethod) {
        case KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_PSP_BY_POINTER:
            status = kswordArkDriverTerminateReferencedThreadPsp(
                actionThreadObject,
                STATUS_CANCELLED);
            break;
        case KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_ZW_OR_NT:
            status = kswordArkDriverTerminateReferencedThreadZwOrNt(
                actionThreadObject,
                STATUS_CANCELLED);
            break;
        case KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_NORMAL_APC:
            status = kswordArkDriverQueueTerminateSystemThreadApc(
                actionThreadObject,
                FALSE);
            break;
        case KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_SPECIAL_TO_NORMAL_APC:
            status = kswordArkDriverQueueTerminateSystemThreadApc(
                actionThreadObject,
                TRUE);
            break;
        default:
            status = STATUS_INVALID_PARAMETER;
            break;
        }
    }
    else {
        status = ObOpenObjectByPointer(
            actionThreadObject,
            OBJ_KERNEL_HANDLE,
            NULL,
            THREAD_SUSPEND_RESUME,
            *PsThreadType,
            KernelMode,
            &threadHandle);
        if (!NT_SUCCESS(status)) {
            goto Exit;
        }
        suspendRoutine = kswordArkResolveThreadSuspendRoutine(
            controlRequest->action == KSWORD_ARK_DRIVER_THREAD_ACTION_SUSPEND);
        status = suspendRoutine != NULL
            ? suspendRoutine(threadHandle, &previousSuspendCount)
            : STATUS_PROCEDURE_NOT_FOUND;
    }

    kswordArkThreadIoctlLog(
        device,
        NT_SUCCESS(status) ? "Info" : "Warn",
        "Driver-thread control result: tid=%lu, createTime100ns=%I64u, action=%lu, terminateMethod=%lu, module=%ws, start=0x%I64X, previousSuspendCount=%lu, status=0x%08X.",
        (unsigned long)controlRequest->threadId,
        controlRequest->expectedCreateTime100ns,
        (unsigned long)controlRequest->action,
        (unsigned long)controlRequest->terminateMethod,
        moduleNameWide,
        actualStartAddress,
        (unsigned long)previousSuspendCount,
        (unsigned int)status);

Exit:
    if (threadHandle != NULL) {
        ZwClose(threadHandle);
        threadHandle = NULL;
    }
    if (actionThreadObject != NULL) {
        ObDereferenceObject(actionThreadObject);
        actionThreadObject = NULL;
    }
    if (threadObject != NULL) {
        ObDereferenceObject(threadObject);
        threadObject = NULL;
    }
    if (moduleInfo != NULL) {
        ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
        moduleInfo = NULL;
    }
    return status;
}

NTSTATUS
kswordArkThreadIoctlControlDriverThread(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
    KSWORD_ARK_CONTROL_DRIVER_THREAD_REQUEST* controlRequest = NULL;
    PVOID inputBuffer = NULL;
    size_t actualInputLength = 0;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0;

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(KSWORD_ARK_CONTROL_DRIVER_THREAD_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    controlRequest = (KSWORD_ARK_CONTROL_DRIVER_THREAD_REQUEST*)inputBuffer;
    if (inputBufferLength != sizeof(*controlRequest) ||
        actualInputLength != sizeof(*controlRequest)) {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    status = kswordArkDriverControlDriverThread(device, controlRequest);
    if (NT_SUCCESS(status)) {
        *bytesReturned = sizeof(KSWORD_ARK_CONTROL_DRIVER_THREAD_REQUEST);
    }
    return status;
}
