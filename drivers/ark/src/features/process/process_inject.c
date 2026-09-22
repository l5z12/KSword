/*++

Module Name:

    process_inject.c

Abstract:

    R0-backed user-process injection helpers for KswordARK.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"

NTSYSAPI
NTSTATUS
NTAPI
PsLookupProcessByProcessId(
    _In_ HANDLE processId,
    _Outptr_ PEPROCESS* process
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

NTKERNELAPI
NTSTATUS
MmCopyVirtualMemory(
    _In_ PEPROCESS fromProcess,
    _In_reads_bytes_(bufferSize) PVOID fromAddress,
    _In_ PEPROCESS toProcess,
    _Out_writes_bytes_(bufferSize) PVOID toAddress,
    _In_ SIZE_T bufferSize,
    _In_ KPROCESSOR_MODE previousMode,
    _Out_ PSIZE_T numberOfBytesCopied
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwAllocateVirtualMemory(
    _In_ HANDLE processHandle,
    _Inout_ PVOID* baseAddress,
    _In_ ULONG_PTR zeroBits,
    _Inout_ PSIZE_T regionSize,
    _In_ ULONG allocationType,
    _In_ ULONG protect
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwFreeVirtualMemory(
    _In_ HANDLE processHandle,
    _Inout_ PVOID* baseAddress,
    _Inout_ PSIZE_T regionSize,
    _In_ ULONG freeType
    );

/*
 * KswordZwCreateThreadExFn:
 * - Inputs: the target process handle, user entry point, optional argument, and stack options.
 * - Processing: matches the kernel ZwCreateThreadEx routine signature used to create the remote thread.
 * - Returns: NTSTATUS and optionally writes the created thread handle.
 */
typedef
NTSTATUS
(NTAPI* KswordZwCreateThreadExFn)(
    _Out_ PHANDLE threadHandle,
    _In_ ACCESS_MASK desiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES objectAttributes,
    _In_ HANDLE processHandle,
    _In_ PVOID startRoutine,
    _In_opt_ PVOID argument,
    _In_ ULONG createFlags,
    _In_ SIZE_T zeroBits,
    _In_ SIZE_T stackSize,
    _In_ SIZE_T maximumStackSize,
    _In_opt_ PVOID attributeList
    );

/*
 * ZwWaitForSingleObject:
 * - Inputs: a kernel handle, alertable-wait flag, and optional relative timeout.
 * - Processing: waits for the remote thread handle created by ZwCreateThreadEx.
 * - Returns: NTSTATUS from the kernel wait operation.
 */
NTSYSAPI
NTSTATUS
NTAPI
ZwWaitForSingleObject(
    _In_ HANDLE handle,
    _In_ BOOLEAN alertable,
    _In_opt_ PLARGE_INTEGER timeout
    );

#ifndef OBJ_KERNEL_HANDLE
#define OBJ_KERNEL_HANDLE 0x00000200L
#endif

#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD (0x0002)
#endif

#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION (0x0400)
#endif

#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION (0x0008)
#endif

#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE (0x0020)
#endif

#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ (0x0010)
#endif

#ifndef THREAD_ALL_ACCESS
#define THREAD_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF)
#endif

#ifndef MEM_COMMIT
#define MEM_COMMIT 0x00001000UL
#endif

#ifndef MEM_RESERVE
#define MEM_RESERVE 0x00002000UL
#endif

#ifndef MEM_RELEASE
#define MEM_RELEASE 0x00008000UL
#endif

#ifndef PAGE_READWRITE
#define PAGE_READWRITE 0x04UL
#endif

#ifndef PAGE_EXECUTE_READWRITE
#define PAGE_EXECUTE_READWRITE 0x40UL
#endif

#define KSWORD_ARK_INJECT_REQUEST_HEADER_SIZE \
    FIELD_OFFSET(KSWORD_ARK_INJECT_PROCESS_REQUEST, payload)

static BOOLEAN
kswordArkInjectIsUserAddress(
    _In_ ULONG64 address
    )
{
    return address != 0ULL &&
        address <= (ULONG64)(ULONG_PTR)MmHighestUserAddress;
}

/*
 * kswordArkInjectResolveZwCreateThreadEx:
 * - Inputs: none.
 * - Processing: resolves ZwCreateThreadEx at runtime because some WDK import libraries do not expose it.
 * - Returns: callable routine pointer, or NULL when the running kernel does not export the routine.
 */
static KswordZwCreateThreadExFn
kswordArkInjectResolveZwCreateThreadEx(
    VOID
    )
{
    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, L"ZwCreateThreadEx");
    return (KswordZwCreateThreadExFn)MmGetSystemRoutineAddress(&routineName);
}

static NTSTATUS
kswordArkInjectOpenProcess(
    _In_ ULONG processId,
    _Out_ HANDLE* processHandleOut,
    _Outptr_ PEPROCESS* processObjectOut
    )
{
    HANDLE processHandle = NULL;
    PEPROCESS processObject = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    const ACCESS_MASK kDesiredAccess =
        PROCESS_CREATE_THREAD |
        PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE |
        PROCESS_VM_READ;

    if (processHandleOut == NULL || processObjectOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *processHandleOut = NULL;
    *processObjectOut = NULL;

    status = PsLookupProcessByProcessId(ULongToHandle(processId), &processObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /*
     * Open the exact object returned by PsLookupProcessByProcessId. Reopening by
     * numeric PID can select a different process if the target exits and the PID
     * is reused between lookup and handle creation.
     */
    status = ObOpenObjectByPointer(
        processObject,
        OBJ_KERNEL_HANDLE,
        NULL,
        kDesiredAccess,
        *PsProcessType,
        KernelMode,
        &processHandle);

    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(processObject);
        return status;
    }

    *processHandleOut = processHandle;
    *processObjectOut = processObject;
    return STATUS_SUCCESS;
}

static ULONG
kswordArkInjectStatusFromNtStatus(
    _In_ ULONG phaseStatus,
    _In_ NTSTATUS status
    )
{
    UNREFERENCED_PARAMETER(status);
    return phaseStatus;
}

NTSTATUS
kswordArkDriverInjectProcess(
    _Out_writes_bytes_(outputBufferLength) KSWORD_ARK_INJECT_PROCESS_RESPONSE* response,
    _In_ size_t outputBufferLength,
    _In_reads_bytes_(inputBufferLength) const KSWORD_ARK_INJECT_PROCESS_REQUEST* request,
    _In_ size_t inputBufferLength,
    _Out_ size_t* bytesWrittenOut
    )
{
    HANDLE processHandle = NULL;
    HANDLE threadHandle = NULL;
    PEPROCESS processObject = NULL;
    PVOID remoteBase = NULL;
    SIZE_T remoteRegionSize = 0U;
    SIZE_T bytesCopied = 0U;
    PVOID entryPoint = NULL;
    PVOID parameterAddress = NULL;
    ULONG allocationProtect = PAGE_READWRITE;
    BOOLEAN freeRemoteRegionOnFailure = FALSE;
    KswordZwCreateThreadExFn createThreadEx = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (response == NULL || request == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < sizeof(KSWORD_ARK_INJECT_PROCESS_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(response, outputBufferLength);
    response->version = KSWORD_ARK_PROCESS_INJECT_PROTOCOL_VERSION;
    response->processId = request->processId;
    response->injectType = request->injectType;
    response->status = KSWORD_ARK_PROCESS_INJECT_STATUS_UNKNOWN;
    response->flags = request->flags;
    response->lastStatus = STATUS_SUCCESS;
    response->waitStatus = STATUS_SUCCESS;
    response->entryPointAddress = request->entryPointAddress;
    response->parameterAddress = request->parameterAddress;
    *bytesWrittenOut = sizeof(*response);

    if (KeGetCurrentIrql() != PASSIVE_LEVEL ||
        request->version != KSWORD_ARK_PROCESS_INJECT_PROTOCOL_VERSION ||
        request->processId <= 4UL ||
        request->payloadBytes == 0UL ||
        request->payloadBytes > KSWORD_ARK_PROCESS_INJECT_MAX_PAYLOAD_BYTES ||
        inputBufferLength < KSWORD_ARK_INJECT_REQUEST_HEADER_SIZE ||
        (SIZE_T)request->payloadBytes >
            (inputBufferLength - KSWORD_ARK_INJECT_REQUEST_HEADER_SIZE)) {
        response->status = KSWORD_ARK_PROCESS_INJECT_STATUS_INVALID_REQUEST;
        response->lastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }

    if (request->injectType == KSWORD_ARK_PROCESS_INJECT_TYPE_DLL_PATH) {
        if ((request->payloadBytes % sizeof(WCHAR)) != 0U ||
            ((const WCHAR*)request->payload)[(request->payloadBytes / sizeof(WCHAR)) - 1U] != L'\0' ||
            !kswordArkInjectIsUserAddress(request->entryPointAddress)) {
            response->status = KSWORD_ARK_PROCESS_INJECT_STATUS_INVALID_REQUEST;
            response->lastStatus = STATUS_INVALID_PARAMETER;
            return STATUS_SUCCESS;
        }
        entryPoint = (PVOID)(ULONG_PTR)request->entryPointAddress;
        allocationProtect = PAGE_READWRITE;
    }
    else if (request->injectType == KSWORD_ARK_PROCESS_INJECT_TYPE_SHELLCODE) {
        allocationProtect = PAGE_EXECUTE_READWRITE;
    }
    else {
        response->status = KSWORD_ARK_PROCESS_INJECT_STATUS_INVALID_REQUEST;
        response->lastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }

    status = kswordArkInjectOpenProcess(request->processId, &processHandle, &processObject);
    if (!NT_SUCCESS(status)) {
        response->status = KSWORD_ARK_PROCESS_INJECT_STATUS_PROCESS_OPEN_FAILED;
        response->lastStatus = status;
        return STATUS_SUCCESS;
    }

    remoteRegionSize = (SIZE_T)request->payloadBytes;
    status = ZwAllocateVirtualMemory(
        processHandle,
        &remoteBase,
        0,
        &remoteRegionSize,
        MEM_COMMIT | MEM_RESERVE,
        allocationProtect);
    response->remoteBaseAddress = (ULONG64)(ULONG_PTR)remoteBase;
    response->remoteRegionSize = (ULONG64)remoteRegionSize;
    if (!NT_SUCCESS(status) || remoteBase == NULL) {
        response->status = KSWORD_ARK_PROCESS_INJECT_STATUS_ALLOC_FAILED;
        response->lastStatus = status;
        goto Exit;
    }
    freeRemoteRegionOnFailure = TRUE;

    status = MmCopyVirtualMemory(
        PsGetCurrentProcess(),
        (PVOID)request->payload,
        processObject,
        remoteBase,
        (SIZE_T)request->payloadBytes,
        KernelMode,
        &bytesCopied);
    response->bytesWritten = (ULONG)bytesCopied;
    if (!NT_SUCCESS(status) || bytesCopied != (SIZE_T)request->payloadBytes) {
        response->status = kswordArkInjectStatusFromNtStatus(
            KSWORD_ARK_PROCESS_INJECT_STATUS_WRITE_FAILED,
            status);
        response->lastStatus = status;
        goto Exit;
    }

    if (request->injectType == KSWORD_ARK_PROCESS_INJECT_TYPE_SHELLCODE) {
        entryPoint = remoteBase;
        parameterAddress = (PVOID)(ULONG_PTR)request->parameterAddress;
    }
    else {
        parameterAddress = remoteBase;
    }
    response->entryPointAddress = (ULONG64)(ULONG_PTR)entryPoint;
    response->parameterAddress = (ULONG64)(ULONG_PTR)parameterAddress;

    if (!kswordArkInjectIsUserAddress((ULONG64)(ULONG_PTR)entryPoint)) {
        response->status = KSWORD_ARK_PROCESS_INJECT_STATUS_INVALID_REQUEST;
        response->lastStatus = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    createThreadEx = kswordArkInjectResolveZwCreateThreadEx();
    if (createThreadEx == NULL) {
        response->status = KSWORD_ARK_PROCESS_INJECT_STATUS_THREAD_FAILED;
        response->lastStatus = STATUS_NOT_SUPPORTED;
        goto Exit;
    }

    status = createThreadEx(
        &threadHandle,
        THREAD_ALL_ACCESS,
        NULL,
        processHandle,
        entryPoint,
        parameterAddress,
        0,
        0,
        0,
        0,
        NULL);
    if (!NT_SUCCESS(status)) {
        response->status = KSWORD_ARK_PROCESS_INJECT_STATUS_THREAD_FAILED;
        response->lastStatus = status;
        goto Exit;
    }
    freeRemoteRegionOnFailure = FALSE;

    if ((request->flags & KSWORD_ARK_PROCESS_INJECT_FLAG_WAIT_THREAD) != 0UL) {
        LARGE_INTEGER timeout;
        timeout.QuadPart = -10LL * 1000LL * 1000LL * 10LL;
        status = ZwWaitForSingleObject(threadHandle, FALSE, &timeout);
        response->waitStatus = status;
        if (!NT_SUCCESS(status)) {
            response->status = KSWORD_ARK_PROCESS_INJECT_STATUS_WAIT_FAILED;
            response->lastStatus = status;
            goto Exit;
        }
    }

    response->status = KSWORD_ARK_PROCESS_INJECT_STATUS_INJECTED;
    response->lastStatus = STATUS_SUCCESS;

Exit:
    if (threadHandle != NULL) {
        ZwClose(threadHandle);
        threadHandle = NULL;
    }
    if (freeRemoteRegionOnFailure && remoteBase != NULL && processHandle != NULL) {
        PVOID freeBase = remoteBase;
        SIZE_T freeRegionSize = 0U;
        (void)ZwFreeVirtualMemory(
            processHandle,
            &freeBase,
            &freeRegionSize,
            MEM_RELEASE);
    }
    if (processHandle != NULL) {
        ZwClose(processHandle);
        processHandle = NULL;
    }
    if (processObject != NULL) {
        ObDereferenceObject(processObject);
        processObject = NULL;
    }
    return STATUS_SUCCESS;
}
