/*++

Module Name:

    process_terminate_memory.c

Abstract:

    Memory-zero fallback stage used by the KswordARK process termination pipeline.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"

// Note: This file only carries the memory zeroing fallback stage for process termination.
// Note: Exported entry point to process_terminate.c to prevent a single file from exceeding the collaboration limit.

NTSYSAPI
NTSTATUS
NTAPI
PsLookupProcessByProcessId(
    _In_ HANDLE processId,
    _Outptr_ PEPROCESS* process
    );

NTKERNELAPI
PVOID
NTAPI
PsGetProcessSectionBaseAddress(
    _In_ PEPROCESS process
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
ZwQueryVirtualMemory(
    _In_ HANDLE processHandle,
    _In_opt_ PVOID baseAddress,
    _In_ ULONG memoryInformationClass,
    _Out_writes_bytes_(memoryInformationLength) PVOID memoryInformation,
    _In_ SIZE_T memoryInformationLength,
    _Out_opt_ PSIZE_T returnLength
    );

#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION (0x0400)
#endif

#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION (0x0008)
#endif

#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE (0x0020)
#endif

#define KSWORD_ARK_MEMORY_ZERO_CHUNK_BYTES 0x1000UL
#define KSWORD_ARK_MEMORY_SCAN_LOW_ADDRESS 0x10000ULL

typedef PVOID(NTAPI* KswordPsGetProcessSectionBaseAddressFn)(
    _In_ PEPROCESS process
    );

typedef struct KswordArkMemoryBasicInformation
{
    PVOID baseAddress;
    PVOID allocationBase;
    ULONG allocationProtect;
    SIZE_T regionSize;
    ULONG state;
    ULONG protect;
    ULONG type;
} KswordArkMemoryBasicInformation;

VOID
kswordArkDriverLogTerminateMessage(
    _In_opt_ WDFDEVICE device,
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR formatText,
    ...
    );

static KswordPsGetProcessSectionBaseAddressFn
kswordArkDriverResolvePsGetProcessSectionBaseAddress(
    VOID
    )
{
    UNICODE_STRING routineName;
    RtlInitUnicodeString(&routineName, L"PsGetProcessSectionBaseAddress");
    return (KswordPsGetProcessSectionBaseAddressFn)MmGetSystemRoutineAddress(&routineName);
}

static NTSTATUS
kswordArkDriverOpenProcessHandleForMemoryZeroByObject(
    _In_ PEPROCESS processObject,
    _Out_ HANDLE* processHandleOut
    )
/*++

Routine Description:

    Open a process handle for the memory-zero fallback from an already resolved
    EPROCESS object. Note: The UniqueProcessId of a hidden process may be
    untrustworthy, so the fallback stage no longer re-opens the process by PID.

Arguments:

    processObject - Referenced target EPROCESS.
    processHandleOut - Receives a kernel handle with query/write access.

Return Value:

    STATUS_SUCCESS or ObOpenObjectByPointer status.

--*/
{
    HANDLE processHandle = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    const ACCESS_MASK kDesiredAccess =
        PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE;

    if (processObject == NULL || processHandleOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *processHandleOut = NULL;

    status = ObOpenObjectByPointer(
        processObject,
        OBJ_KERNEL_HANDLE,
        NULL,
        kDesiredAccess,
        *PsProcessType,
        KernelMode,
        &processHandle);

    if (NT_SUCCESS(status)) {
        *processHandleOut = processHandle;
    }
    return status;
}

static BOOLEAN
kswordArkDriverIsWritableProtection(
    _In_ ULONG protectionFlags
    )
{
    const ULONG kBaseProtect = protectionFlags & 0xFFUL;

    switch (kBaseProtect) {
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return TRUE;
    default:
        return FALSE;
    }
}

NTSTATUS
kswordArkDriverZeroProcessUserMemoryByObject(
    _In_opt_ WDFDEVICE device,
    _In_ ULONG processId,
    _In_ PEPROCESS processObject
    )
/*++

Routine Description:

    Zero writable user-mode memory regions for an already resolved process.
    Note: processId is used for logging only; actual queries/writes revolve around
    ProcessObject to prevent the third-stage fallback from failing due to a rewritten PID.

Arguments:

    device - Optional WDF device used for logs.
    processId - Display/request PID used in diagnostic messages.
    processObject - Referenced target EPROCESS.

Return Value:

    STATUS_SUCCESS when at least one writable chunk was zeroed; otherwise the
    best failure status.

--*/
{
    KswordPsGetProcessSectionBaseAddressFn psGetSectionBaseAddress = NULL;
    HANDLE processHandle = NULL;
    PUCHAR zeroChunkBuffer = NULL;
    ULONG_PTR queryAddress = KSWORD_ARK_MEMORY_SCAN_LOW_ADDRESS;
    ULONG_PTR upperUserAddress = 0;
    ULONG_PTR sectionBase = 0;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS finalStatus = STATUS_UNSUCCESSFUL;
    NTSTATUS firstFailureStatus = STATUS_UNSUCCESSFUL;
    BOOLEAN anyWriteSucceeded = FALSE;
    ULONG scannedRegionCount = 0UL;
    ULONG writableRegionCount = 0UL;
    ULONG successfulWriteCount = 0UL;
    SIZE_T totalBytesZeroed = 0U;

    if (processObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = kswordArkDriverOpenProcessHandleForMemoryZeroByObject(
        processObject,
        &processHandle);
    if (!NT_SUCCESS(status)) {
        kswordArkDriverLogTerminateMessage(
            device,
            "Warn",
            "R0 terminate fallback#3 open failed: pid=%lu, status=0x%08X.",
            (unsigned long)processId,
            (unsigned int)status);
        return status;
    }

    psGetSectionBaseAddress = kswordArkDriverResolvePsGetProcessSectionBaseAddress();
    if (psGetSectionBaseAddress != NULL) {
        sectionBase = (ULONG_PTR)psGetSectionBaseAddress(processObject);
        if (sectionBase >= KSWORD_ARK_MEMORY_SCAN_LOW_ADDRESS) {
            queryAddress = sectionBase;
        }
    }

    kswordArkDriverLogTerminateMessage(
        device,
        "Info",
        "R0 terminate fallback#3 resolver: pid=%lu, PsGetProcessSectionBaseAddress=%p, sectionBase=0x%p.",
        (unsigned long)processId,
        psGetSectionBaseAddress,
        (PVOID)sectionBase);

    upperUserAddress = (ULONG_PTR)MmUserProbeAddress;
    if (upperUserAddress <= queryAddress) {
        queryAddress = KSWORD_ARK_MEMORY_SCAN_LOW_ADDRESS;
    }

#pragma warning(push)
#pragma warning(disable:4996)
    zeroChunkBuffer = (PUCHAR)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        KSWORD_ARK_MEMORY_ZERO_CHUNK_BYTES,
        'zKsK');
#pragma warning(pop)
    if (zeroChunkBuffer == NULL) {
        finalStatus = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }
    RtlZeroMemory(zeroChunkBuffer, KSWORD_ARK_MEMORY_ZERO_CHUNK_BYTES);

    while (queryAddress < upperUserAddress) {
        KswordArkMemoryBasicInformation memoryInfo;
        SIZE_T returnedBytes = 0;
        ULONG_PTR regionBase = 0;
        SIZE_T regionSize = 0;
        ULONG_PTR nextAddress = 0;
        scannedRegionCount += 1UL;

        RtlZeroMemory(&memoryInfo, sizeof(memoryInfo));
        status = ZwQueryVirtualMemory(
            processHandle,
            (PVOID)queryAddress,
            0UL,
            &memoryInfo,
            sizeof(memoryInfo),
            &returnedBytes);
        if (!NT_SUCCESS(status)) {
            if (status == STATUS_INVALID_PARAMETER || status == STATUS_ACCESS_DENIED) {
                queryAddress += PAGE_SIZE;
                continue;
            }
            if (firstFailureStatus == STATUS_UNSUCCESSFUL) {
                firstFailureStatus = status;
            }
            break;
        }

        regionBase = (ULONG_PTR)memoryInfo.baseAddress;
        regionSize = (SIZE_T)memoryInfo.regionSize;
        if (regionSize == 0U) {
            queryAddress += PAGE_SIZE;
            continue;
        }

        nextAddress = regionBase + regionSize;
        if (nextAddress <= queryAddress) {
            break;
        }

        if (memoryInfo.state == MEM_COMMIT &&
            (memoryInfo.protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0UL &&
            kswordArkDriverIsWritableProtection(memoryInfo.protect)) {
            ULONG_PTR writeAddress = regionBase;
            const ULONG_PTR kRegionEndAddress = regionBase + regionSize;
            writableRegionCount += 1UL;

            while (writeAddress < kRegionEndAddress) {
                SIZE_T bytesToWrite = (SIZE_T)(kRegionEndAddress - writeAddress);
                SIZE_T bytesCopied = 0;
                NTSTATUS copyStatus = STATUS_UNSUCCESSFUL;

                if (bytesToWrite > KSWORD_ARK_MEMORY_ZERO_CHUNK_BYTES) {
                    bytesToWrite = KSWORD_ARK_MEMORY_ZERO_CHUNK_BYTES;
                }

                copyStatus = MmCopyVirtualMemory(
                    PsGetCurrentProcess(),
                    zeroChunkBuffer,
                    processObject,
                    (PVOID)writeAddress,
                    bytesToWrite,
                    KernelMode,
                    &bytesCopied);
                if (!NT_SUCCESS(copyStatus) || bytesCopied == 0U) {
                    if (firstFailureStatus == STATUS_UNSUCCESSFUL) {
                        firstFailureStatus = copyStatus;
                    }
                    break;
                }

                anyWriteSucceeded = TRUE;
                successfulWriteCount += 1UL;
                totalBytesZeroed += bytesCopied;
                writeAddress += bytesCopied;
            }
        }

        queryAddress = nextAddress;
    }

    if (anyWriteSucceeded) {
        finalStatus = STATUS_SUCCESS;
    }
    else if (firstFailureStatus != STATUS_UNSUCCESSFUL) {
        finalStatus = firstFailureStatus;
    }
    else {
        finalStatus = STATUS_NOT_FOUND;
    }

    kswordArkDriverLogTerminateMessage(
        device,
        NT_SUCCESS(finalStatus) ? "Info" : "Warn",
        "R0 terminate fallback#3 result: pid=%lu, status=0x%08X, scannedRegions=%lu, writableRegions=%lu, successfulWrites=%lu, bytesZeroed=%Iu.",
        (unsigned long)processId,
        (unsigned int)finalStatus,
        (unsigned long)scannedRegionCount,
        (unsigned long)writableRegionCount,
        (unsigned long)successfulWriteCount,
        totalBytesZeroed);

Exit:
    if (zeroChunkBuffer != NULL) {
        ExFreePoolWithTag(zeroChunkBuffer, 'zKsK');
        zeroChunkBuffer = NULL;
    }
    if (processHandle != NULL) {
        ZwClose(processHandle);
        processHandle = NULL;
    }
    return finalStatus;
}

NTSTATUS
kswordArkDriverZeroProcessUserMemoryByPid(
    _In_opt_ WDFDEVICE device,
    _In_ ULONG processId
    )
/*++

Routine Description:

    Compatibility wrapper that resolves a process by PID, then runs the object
    based memory-zero fallback.

Arguments:

    device - Optional WDF device used for logs.
    processId - Target process ID.

Return Value:

    STATUS_SUCCESS or lookup/fallback status.

--*/
{
    PEPROCESS processObject = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    status = PsLookupProcessByProcessId(ULongToHandle(processId), &processObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = kswordArkDriverZeroProcessUserMemoryByObject(
        device,
        processId,
        processObject);
    ObDereferenceObject(processObject);
    return status;
}
