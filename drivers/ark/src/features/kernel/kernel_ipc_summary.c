/*++
Module Name:
    kernel_ipc_summary.c
Abstract:
    Read-only IPC summary implementation for ALPC, Named Pipe, and Mailslot handles.
Environment:
    Kernel-mode Driver Framework
--*/
#include "kernel_ipc_summary.h"
#include "ark/ark_alpc.h"
#include "ark/ark_dyndata.h"
#include <ntstrsafe.h>
#define KSW_KERNEL_IPC_NAME_CHARS 160UL
#define KSW_KERNEL_IPC_POOL_TAG   'iKsK'
#ifndef STATUS_BUFFER_OVERFLOW
#define STATUS_BUFFER_OVERFLOW ((NTSTATUS)0x80000005L)
#endif
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif
typedef PVOID
(NTAPI* KswKernelIpcExAllocatePooL2Fn)(
    _In_ POOL_FLAGS flags,
    _In_ SIZE_T numberOfBytes,
    _In_ ULONG tag
    );
NTSYSAPI
NTSTATUS
NTAPI
PsLookupProcessByProcessId(
    _In_ HANDLE processId,
    _Outptr_ PEPROCESS* process
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
ObReferenceObjectByHandle(
    _In_ HANDLE handle,
    _In_ ACCESS_MASK desiredAccess,
    _In_opt_ POBJECT_TYPE objectType,
    _In_ KPROCESSOR_MODE accessMode,
    _Out_ PVOID* object,
    _Out_opt_ POBJECT_HANDLE_INFORMATION handleInformation
    );
NTKERNELAPI
NTSTATUS
ObQueryNameString(
    _In_ PVOID object,
    _Out_writes_bytes_opt_(length) POBJECT_NAME_INFORMATION objectNameInfo,
    _In_ ULONG length,
    _Out_ PULONG returnLength
    );
static PVOID
kswordArkKernelIpcAllocateNonPaged(
    _In_ SIZE_T bufferBytes
    )
/*++
Routine Description:
    Allocate transient nonpaged memory for IPC object-name queries.
Arguments:
    BufferBytes - Number of bytes requested.
Return Value:
    Allocation pointer or NULL. Caller frees with ExFreePoolWithTag.
--*/
{
    UNICODE_STRING routineName;
    static KswKernelIpcExAllocatePooL2Fn allocatePool2 = NULL;
    if (bufferBytes == 0U) {
        return NULL;
    }
    if (allocatePool2 == NULL) {
        RtlInitUnicodeString(&routineName, L"ExAllocatePool2");
        allocatePool2 = (KswKernelIpcExAllocatePooL2Fn)MmGetSystemRoutineAddress(&routineName);
    }
    if (allocatePool2 != NULL) {
        return allocatePool2(POOL_FLAG_NON_PAGED, bufferBytes, KSW_KERNEL_IPC_POOL_TAG);
    }
#pragma warning(push)
#pragma warning(disable:4996)
    return ExAllocatePoolWithTag(NonPagedPoolNx, bufferBytes, KSW_KERNEL_IPC_POOL_TAG);
#pragma warning(pop)
}
static VOID
kswordArkKernelIpcCopyUnicodeStringToFixed(
    _Out_writes_(destinationChars) WCHAR* destination,
    _In_ ULONG destinationChars,
    _In_opt_ PCUNICODE_STRING source
    )
/*++
Routine Description:
    Copy a counted UNICODE_STRING into a fixed NUL-terminated WCHAR buffer.
Arguments:
    Destination - Fixed output buffer.
    DestinationChars - Destination capacity in WCHARs.
    Source - Optional counted source string.
Return Value:
    None. Destination is always NUL-terminated when capacity is nonzero.
--*/
{
    ULONG copyChars = 0UL;
    if (destination == NULL || destinationChars == 0UL) {
        return;
    }
    destination[0] = L'\0';
    if (source == NULL || source->Buffer == NULL || source->Length == 0U) {
        return;
    }
    copyChars = (ULONG)(source->Length / sizeof(WCHAR));
    if (copyChars >= destinationChars) {
        copyChars = destinationChars - 1UL;
    }
    RtlCopyMemory(destination, source->Buffer, (SIZE_T)copyChars * sizeof(WCHAR));
    destination[copyChars] = L'\0';
}
static HANDLE
kswordArkKernelIpcMakeKernelHandle(
    _In_ HANDLE handleValue
    )
/*++
Routine Description:
    Convert a System-process handle value to the kernel-handle namespace.
Arguments:
    HandleValue - Raw handle value from the IPC summary request.
Return Value:
    Handle value with the architecture-specific kernel-handle bit set.
--*/
{
#ifdef _X86_
    return (HANDLE)((ULONG_PTR)HandleValue | (ULONG_PTR)0x80000000UL);
#else
    return (HANDLE)((ULONG_PTR)handleValue | (ULONG_PTR)0xFFFFFFFF80000000ULL);
#endif
}
static NTSTATUS
kswordArkKernelIpcReferenceHandleObject(
    _In_ PEPROCESS processObject,
    _In_ ULONG64 handleValue,
    _Outptr_result_nullonfailure_ PVOID* objectOut
    )
/*++
Routine Description:
    Reference the object identified by a PID-owned handle.
Arguments:
    ProcessObject - Referenced process object from PsLookupProcessByProcessId.
    HandleValue - Handle value in that process.
    ObjectOut - Receives referenced object body on success.
Return Value:
    STATUS_SUCCESS or ObReferenceObjectByHandle failure status.
--*/
{
    DECLSPEC_ALIGN(16) UCHAR attachState[128];
    HANDLE targetHandle = (HANDLE)(ULONG_PTR)handleValue;
    BOOLEAN attached = FALSE;
    NTSTATUS status = STATUS_SUCCESS;
    if (objectOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *objectOut = NULL;
    if (processObject == NULL || handleValue == 0ULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (processObject == PsInitialSystemProcess) {
        targetHandle = kswordArkKernelIpcMakeKernelHandle(targetHandle);
    }
    RtlZeroMemory(attachState, sizeof(attachState));
    __try {
        KeStackAttachProcess((PVOID)processObject, attachState);
        attached = TRUE;
        status = ObReferenceObjectByHandle(
            targetHandle,
            0,
            NULL,
            (processObject == PsInitialSystemProcess) ? KernelMode : UserMode,
            objectOut,
            NULL);
        KeUnstackDetachProcess(attachState);
        attached = FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        if (attached) {
            KeUnstackDetachProcess(attachState);
            attached = FALSE;
        }
    }
    return status;
}
static NTSTATUS
kswordArkKernelIpcQueryObjectName(
    _In_ PVOID object,
    _Out_writes_(destinationChars) WCHAR* destination,
    _In_ ULONG destinationChars
    )
/*++
Routine Description:
    Query a referenced object's object-manager name into a fixed buffer.
Arguments:
    Object - Referenced object body.
    Destination - Fixed WCHAR output buffer.
    DestinationChars - Destination capacity in WCHARs.
Return Value:
    STATUS_SUCCESS when ObQueryNameString completed, otherwise NTSTATUS.
--*/
{
    POBJECT_NAME_INFORMATION nameInfo = NULL;
    ULONG requiredBytes = 0UL;
    ULONG allocationBytes = 0UL;
    NTSTATUS status = STATUS_SUCCESS;
    if (object == NULL || destination == NULL || destinationChars == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    destination[0] = L'\0';
    status = ObQueryNameString(object, NULL, 0UL, &requiredBytes);
    if (status != STATUS_INFO_LENGTH_MISMATCH &&
        status != STATUS_BUFFER_TOO_SMALL &&
        status != STATUS_BUFFER_OVERFLOW) {
        return NT_SUCCESS(status) ? STATUS_SUCCESS : status;
    }
    allocationBytes = requiredBytes;
    if (allocationBytes < sizeof(OBJECT_NAME_INFORMATION) + sizeof(WCHAR)) {
        allocationBytes = sizeof(OBJECT_NAME_INFORMATION) + sizeof(WCHAR);
    }
    if (allocationBytes > (64UL * 1024UL)) {
        allocationBytes = 64UL * 1024UL;
    }
    nameInfo = (POBJECT_NAME_INFORMATION)kswordArkKernelIpcAllocateNonPaged(allocationBytes);
    if (nameInfo == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(nameInfo, allocationBytes);
    status = ObQueryNameString(object, nameInfo, allocationBytes, &requiredBytes);
    if (NT_SUCCESS(status)) {
        kswordArkKernelIpcCopyUnicodeStringToFixed(destination, destinationChars, &nameInfo->Name);
    }
    ExFreePoolWithTag(nameInfo, KSW_KERNEL_IPC_POOL_TAG);
    return status;
}
static BOOLEAN
kswordArkKernelIpcNameStartsWith(
    _In_reads_(objectNameChars) const WCHAR* objectName,
    _In_ ULONG objectNameChars,
    _In_z_ PCWSTR prefixText
    )
/*++
Routine Description:
    Check whether an object name starts with a known IPC device prefix.
Arguments:
    ObjectName - Fixed object-manager name buffer.
    ObjectNameChars - Capacity of ObjectName in WCHARs.
    PrefixText - NUL-terminated prefix such as \Device\NamedPipe.
Return Value:
    TRUE when ObjectName begins with PrefixText, case-insensitively.
--*/
{
    UNICODE_STRING actualName;
    UNICODE_STRING prefixName;
    SIZE_T actualChars = 0U;
    SIZE_T prefixChars = 0U;
    if (objectName == NULL || objectNameChars == 0UL || prefixText == NULL) {
        return FALSE;
    }
    while (actualChars < (SIZE_T)objectNameChars && objectName[actualChars] != L'\0') {
        actualChars += 1U;
    }
    if (actualChars == 0U) {
        return FALSE;
    }
    RtlInitUnicodeString(&prefixName, prefixText);
    prefixChars = (SIZE_T)(prefixName.Length / sizeof(WCHAR));
    if (actualChars < prefixChars) {
        return FALSE;
    }
    actualName.Buffer = (PWCHAR)objectName;
    actualName.Length = prefixName.Length;
    actualName.MaximumLength = prefixName.Length;
    return RtlEqualUnicodeString(&actualName, &prefixName, TRUE) ? TRUE : FALSE;
}
static VOID
kswordArkKernelIpcClassifyObjectName(
    _In_reads_(objectNameChars) const WCHAR* objectName,
    _In_ ULONG objectNameChars,
    _In_ ULONG flags,
    _Inout_ KSWORD_ARK_QUERY_IPC_SUMMARY_RESPONSE* response
    )
/*++
Routine Description:
    Classify the referenced handle name as NamedPipe or Mailslot evidence.
Arguments:
    ObjectName - Object-manager name queried from the referenced object.
    ObjectNameChars - Capacity of ObjectName in WCHARs.
    Flags - Sanitized IPC selector flags.
    Response - Mutable IPC summary response.
Return Value:
    None. Status fields are updated in Response.
--*/
{
    if (response == NULL) {
        return;
    }
    if ((flags & KSWORD_ARK_IPC_QUERY_FLAG_INCLUDE_PIPE) != 0UL) {
        response->namedPipeStatus = kswordArkKernelIpcNameStartsWith(
            objectName,
            objectNameChars,
            L"\\Device\\NamedPipe") ?
            KSWORD_ARK_IPC_SUMMARY_STATUS_OK :
            KSWORD_ARK_IPC_SUMMARY_STATUS_UNAVAILABLE;
    }
    if ((flags & KSWORD_ARK_IPC_QUERY_FLAG_INCLUDE_MAILSLOT) != 0UL) {
        response->mailslotStatus = kswordArkKernelIpcNameStartsWith(
            objectName,
            objectNameChars,
            L"\\Device\\Mailslot") ?
            KSWORD_ARK_IPC_SUMMARY_STATUS_OK :
            KSWORD_ARK_IPC_SUMMARY_STATUS_UNAVAILABLE;
    }
}
static VOID
kswordArkKernelIpcApplyNameFailure(
    _In_ ULONG flags,
    _Inout_ KSWORD_ARK_QUERY_IPC_SUMMARY_RESPONSE* response
    )
/*++
Routine Description:
    Mark handle-backed pipe/mailslot checks as failed after lookup/name failure.
Arguments:
    Flags - Sanitized IPC selector flags.
    Response - Mutable IPC summary response.
Return Value:
    None.
--*/
{
    if (response == NULL) {
        return;
    }
    if ((flags & KSWORD_ARK_IPC_QUERY_FLAG_INCLUDE_PIPE) != 0UL) {
        response->namedPipeStatus = KSWORD_ARK_IPC_SUMMARY_STATUS_FAILED;
    }
    if ((flags & KSWORD_ARK_IPC_QUERY_FLAG_INCLUDE_MAILSLOT) != 0UL) {
        response->mailslotStatus = KSWORD_ARK_IPC_SUMMARY_STATUS_FAILED;
    }
}
static VOID
kswordArkKernelIpcFinalizeStatus(
    _Inout_ KSWORD_ARK_QUERY_IPC_SUMMARY_RESPONSE* response
    )
/*++
Routine Description:
    Collapse per-family IPC statuses into the response-level status.
Arguments:
    Response - Mutable IPC summary response.
Return Value:
    None.
--*/
{
    if (response == NULL) {
        return;
    }
    if (response->alpcStatus == KSWORD_ARK_ALPC_QUERY_STATUS_OK ||
        response->namedPipeStatus == KSWORD_ARK_IPC_SUMMARY_STATUS_OK ||
        response->mailslotStatus == KSWORD_ARK_IPC_SUMMARY_STATUS_OK) {
        response->status = KSWORD_ARK_IPC_SUMMARY_STATUS_OK;
        return;
    }
    if (response->alpcStatus == KSWORD_ARK_ALPC_QUERY_STATUS_PARTIAL ||
        response->namedPipeStatus == KSWORD_ARK_IPC_SUMMARY_STATUS_FAILED ||
        response->mailslotStatus == KSWORD_ARK_IPC_SUMMARY_STATUS_FAILED) {
        response->status = KSWORD_ARK_IPC_SUMMARY_STATUS_PARTIAL;
        return;
    }
    response->status = KSWORD_ARK_IPC_SUMMARY_STATUS_UNAVAILABLE;
}
NTSTATUS
kswordArkDriverQueryIpcSummary(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_QUERY_IPC_SUMMARY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++
Routine Description:
    Build a read-only IPC summary from caller-supplied PID+handle evidence.
Arguments:
    OutputBuffer - METHOD_BUFFERED response buffer.
    OutputBufferLength - Output buffer length.
    Request - Query selector.
    BytesWrittenOut - Receives sizeof(response).
Return Value:
    STATUS_SUCCESS when a response packet was produced.
--*/
{
    KSWORD_ARK_QUERY_IPC_SUMMARY_RESPONSE* response = (KSWORD_ARK_QUERY_IPC_SUMMARY_RESPONSE*)outputBuffer;
    KswDynState dynState;
    ULONG flags = KSWORD_ARK_IPC_QUERY_FLAG_INCLUDE_ALL;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS nameStatus = STATUS_SUCCESS;
    PEPROCESS processObject = NULL;
    PVOID ipcObject = NULL;
    WCHAR objectName[KSW_KERNEL_IPC_NAME_CHARS];
    BOOLEAN hasHandleInput = FALSE;
    if (bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBuffer == NULL || outputBufferLength < sizeof(*response) || request == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    RtlZeroMemory(response, sizeof(*response));
    RtlZeroMemory(objectName, sizeof(objectName));
    response->version = KSWORD_ARK_KERNEL_OBJECT_PROTOCOL_VERSION;
    response->size = sizeof(*response);
    response->processId = request->processId;
    response->handleValue = request->handleValue;
    response->status = KSWORD_ARK_IPC_SUMMARY_STATUS_UNAVAILABLE;
    response->alpcStatus = KSWORD_ARK_IPC_SUMMARY_STATUS_UNAVAILABLE;
    response->namedPipeStatus = KSWORD_ARK_IPC_SUMMARY_STATUS_UNAVAILABLE;
    response->mailslotStatus = KSWORD_ARK_IPC_SUMMARY_STATUS_UNAVAILABLE;
    kswordArkDynDataSnapshot(&dynState);
    response->dynDataCapabilityMask = dynState.capabilityMask;
    flags = request->flags & KSWORD_ARK_IPC_QUERY_FLAG_INCLUDE_ALL;
    if (flags == 0UL) {
        flags = KSWORD_ARK_IPC_QUERY_FLAG_INCLUDE_ALL;
    }
    hasHandleInput = (request->processId != 0UL && request->handleValue != 0ULL) ? TRUE : FALSE;
    if ((flags & KSWORD_ARK_IPC_QUERY_FLAG_INCLUDE_ALPC) != 0UL && hasHandleInput) {
        KSWORD_ARK_QUERY_ALPC_PORT_REQUEST alpcRequest;
        KSWORD_ARK_QUERY_ALPC_PORT_RESPONSE alpcResponse;
        size_t alpcBytes = 0U;
        RtlZeroMemory(&alpcRequest, sizeof(alpcRequest));
        RtlZeroMemory(&alpcResponse, sizeof(alpcResponse));
        alpcRequest.flags = KSWORD_ARK_ALPC_QUERY_FLAG_INCLUDE_BASIC | KSWORD_ARK_ALPC_QUERY_FLAG_INCLUDE_NAMES;
        alpcRequest.processId = request->processId;
        alpcRequest.handleValue = request->handleValue;
        status = kswordArkDriverQueryAlpcPort(&alpcResponse, sizeof(alpcResponse), &alpcRequest, &alpcBytes);
        response->lastStatus = status;
        response->alpcStatus = NT_SUCCESS(status) ? alpcResponse.queryStatus : KSWORD_ARK_IPC_SUMMARY_STATUS_FAILED;
        if (NT_SUCCESS(status)) {
            response->alpcObjectAddress = alpcResponse.queryPort.objectAddress;
            response->dynDataCapabilityMask = alpcResponse.dynDataCapabilityMask;
            RtlCopyMemory(response->alpcTypeName, alpcResponse.typeName, sizeof(response->alpcTypeName));
        }
    }
    if (((flags & (KSWORD_ARK_IPC_QUERY_FLAG_INCLUDE_PIPE | KSWORD_ARK_IPC_QUERY_FLAG_INCLUDE_MAILSLOT)) != 0UL) &&
        hasHandleInput) {
        status = PsLookupProcessByProcessId(ULongToHandle(request->processId), &processObject);
        response->lastStatus = status;
        if (NT_SUCCESS(status)) {
            status = kswordArkKernelIpcReferenceHandleObject(processObject, request->handleValue, &ipcObject);
            response->lastStatus = status;
        }
        if (NT_SUCCESS(status) && ipcObject != NULL) {
            nameStatus = kswordArkKernelIpcQueryObjectName(ipcObject, objectName, KSW_KERNEL_IPC_NAME_CHARS);
            response->lastStatus = nameStatus;
            if (NT_SUCCESS(nameStatus)) {
                kswordArkKernelIpcClassifyObjectName(objectName, KSW_KERNEL_IPC_NAME_CHARS, flags, response);
            }
            else {
                kswordArkKernelIpcApplyNameFailure(flags, response);
            }
        }
        else {
            kswordArkKernelIpcApplyNameFailure(flags, response);
        }
        if (ipcObject != NULL) {
            ObDereferenceObject(ipcObject);
        }
        if (processObject != NULL) {
            ObDereferenceObject(processObject);
        }
    }
    kswordArkKernelIpcFinalizeStatus(response);
    (VOID)RtlStringCchPrintfW(
        response->detail,
        KSWORD_ARK_KERNEL_OBJECT_DETAIL_CHARS,
        L"IPC summary is read-only and handle-backed; objectName=%ws.",
        objectName[0] != L'\0' ? objectName : L"<unavailable>");
    *bytesWrittenOut = sizeof(*response);
    return STATUS_SUCCESS;
}
