/*++

Module Name:

    ioctl_validation.c

Abstract:

    Shared IOCTL validation helpers for KswordARK handler modules.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ioctl_validation.h"

#include <wdm.h>

NTSTATUS
kswordArkRetrieveRequiredInputBuffer(
    _In_ WDFREQUEST request,
    _In_ size_t requiredLength,
    _Outptr_result_bytebuffer_(*actualLengthOut) PVOID* bufferOut,
    _Out_ size_t* actualLengthOut
    )
/*++

Routine Description:

    Retrieve a required METHOD_BUFFERED input buffer from a WDF request. The
    helper clears output parameters before WDF is called.

Arguments:

    Request - Current WDF request.
    RequiredLength - Minimum accepted input length in bytes.
    BufferOut - Receives the input buffer pointer.
    ActualLengthOut - Receives the full input buffer length supplied by WDF.

Return Value:

    NTSTATUS from parameter validation or WdfRequestRetrieveInputBuffer.

--*/
{
    if (bufferOut == NULL || actualLengthOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *bufferOut = NULL;
    *actualLengthOut = 0;
    return WdfRequestRetrieveInputBuffer(
        request,
        requiredLength,
        bufferOut,
        actualLengthOut);
}

NTSTATUS
kswordArkRetrieveOptionalInputBuffer(
    _In_ WDFREQUEST request,
    _In_ size_t suppliedInputLength,
    _In_ size_t requiredLength,
    _Outptr_result_bytebuffer_(*actualLengthOut) PVOID* bufferOut,
    _Out_ size_t* actualLengthOut,
    _Out_ BOOLEAN* presentOut
    )
/*++

Routine Description:

    Retrieve an optional input buffer only when the caller supplied enough bytes.
    This preserves legacy IOCTL behavior where missing request packets select a
    handler-specific default request.

Arguments:

    Request - Current WDF request.
    SuppliedInputLength - InputBufferLength from the dispatch callback.
    RequiredLength - Minimum length that makes the optional buffer present.
    BufferOut - Receives the input buffer when present; NULL otherwise.
    ActualLengthOut - Receives the WDF buffer length when present; zero otherwise.
    PresentOut - Receives TRUE when a buffer was retrieved.

Return Value:

    STATUS_SUCCESS for absent optional input, or WDF retrieval status when present.

--*/
{
    if (bufferOut == NULL || actualLengthOut == NULL || presentOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *bufferOut = NULL;
    *actualLengthOut = 0;
    *presentOut = FALSE;
    if (suppliedInputLength < requiredLength) {
        return STATUS_SUCCESS;
    }

    *presentOut = TRUE;
    return WdfRequestRetrieveInputBuffer(
        request,
        requiredLength,
        bufferOut,
        actualLengthOut);
}

NTSTATUS
kswordArkRetrieveRequiredOutputBuffer(
    _In_ WDFREQUEST request,
    _In_ size_t requiredLength,
    _Outptr_result_bytebuffer_(*actualLengthOut) PVOID* bufferOut,
    _Out_ size_t* actualLengthOut
    )
/*++

Routine Description:

    Retrieve a required METHOD_BUFFERED output buffer from a WDF request before a
    handler writes its fixed or variable-size response.

Arguments:

    Request - Current WDF request.
    RequiredLength - Minimum accepted output length in bytes.
    BufferOut - Receives the output buffer pointer.
    ActualLengthOut - Receives the full output buffer length supplied by WDF.

Return Value:

    NTSTATUS from parameter validation or WdfRequestRetrieveOutputBuffer.

--*/
{
    if (bufferOut == NULL || actualLengthOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *bufferOut = NULL;
    *actualLengthOut = 0;
    return WdfRequestRetrieveOutputBuffer(
        request,
        requiredLength,
        bufferOut,
        actualLengthOut);
}

NTSTATUS
kswordArkValidateUserPid(
    _In_ ULONG processId
    )
/*++

Routine Description:

    Apply the existing user-action PID guard. PID 0 and core system pseudo/system
    PIDs up to 4 are rejected before feature code runs.

Arguments:

    ProcessId - Target process identifier supplied by user mode.

Return Value:

    STATUS_SUCCESS when accepted; STATUS_INVALID_PARAMETER when rejected.

--*/
{
    if (processId == 0UL || processId <= 4UL) {
        return STATUS_INVALID_PARAMETER;
    }
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkValidateDeviceIoControlWriteAccess(
    _In_ WDFREQUEST request
    )
/*++

Routine Description:

    Validate that the caller opened the device handle with FILE_WRITE_ACCESS for
    high-risk IOCTL paths.

Arguments:

    Request - Current WDF request whose underlying IRP carries access state.

Return Value:

    STATUS_SUCCESS when the IRP has write access, or the access-check status.

--*/
{
    return IoValidateDeviceIoControlAccess(
        WdfRequestWdmGetIrp(request),
        FILE_WRITE_ACCESS);
}
