/*++

Module Name:

    process_token_privilege.c

Abstract:

    Stable process-token privilege query and adjustment backends.

Environment:

    Kernel-mode Driver Framework

--*/

#include <ntifs.h>
#include "ark/ark_driver.h"
#include "../../platform/pool_compat.h"

#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION (0x0400)
#endif

NTKERNELAPI
LONGLONG
NTAPI
PsGetProcessCreateTimeQuadPart(
    _In_ PEPROCESS process
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwAdjustPrivilegesToken(
    _In_ HANDLE tokenHandle,
    _In_ BOOLEAN disableAllPrivileges,
    _In_opt_ PTOKEN_PRIVILEGES newState,
    _In_ ULONG bufferLength,
    _Out_opt_ PTOKEN_PRIVILEGES previousState,
    _Out_opt_ PULONG returnLength
    );

#define KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_POOL_TAG 'vPsK'
#define KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_QUERY_MAX_BYTES (64UL * 1024UL)

static NTSTATUS
kswordArkDriverOpenStableProcessToken(
    _In_ ULONG processId,
    _In_ ULONG64 expectedCreateTime100ns,
    _In_ ACCESS_MASK tokenDesiredAccess,
    _Out_ HANDLE* tokenHandleOut,
    _Out_ ULONG64* processCreateTime100nsOut
    )
/*++

Routine Description:

    Reference one process by PID, bind it to the expected creation timestamp,
    and open its primary token through kernel handles.

Arguments:

    ProcessId - Target process ID.
    ExpectedCreateTime100ns - Optional FILETIME-compatible identity timestamp.
    TokenDesiredAccess - Access requested for the primary token.
    TokenHandleOut - Receives the kernel token handle.
    ProcessCreateTime100nsOut - Receives the observed process creation time.

Return Value:

    NTSTATUS from PID lookup, identity validation, process handle creation, or
    primary-token open.

--*/
{
    PEPROCESS processObject = NULL;
    HANDLE processHandle = NULL;
    HANDLE tokenHandle = NULL;
    ULONG64 processCreateTime100ns = 0ULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (tokenHandleOut == NULL || processCreateTime100nsOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *tokenHandleOut = NULL;
    *processCreateTime100nsOut = 0ULL;

    if (processId == 0UL || processId <= 4UL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = PsLookupProcessByProcessId(ULongToHandle(processId), &processObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    processCreateTime100ns = (ULONG64)PsGetProcessCreateTimeQuadPart(processObject);
    if (expectedCreateTime100ns != 0ULL &&
        processCreateTime100ns != expectedCreateTime100ns) {
        ObDereferenceObject(processObject);
        return STATUS_INVALID_CID;
    }

    status = ObOpenObjectByPointer(
        processObject,
        OBJ_KERNEL_HANDLE,
        NULL,
        PROCESS_QUERY_INFORMATION,
        *PsProcessType,
        KernelMode,
        &processHandle);
    ObDereferenceObject(processObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = ZwOpenProcessTokenEx(
        processHandle,
        tokenDesiredAccess,
        OBJ_KERNEL_HANDLE,
        &tokenHandle);
    ZwClose(processHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *tokenHandleOut = tokenHandle;
    *processCreateTime100nsOut = processCreateTime100ns;
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkDriverQueryProcessTokenPrivileges(
    _In_ ULONG processId,
    _In_ ULONG64 expectedCreateTime100ns,
    _Out_ KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_RESPONSE* response
    )
/*++

Routine Description:

    Query a target primary token and copy its privilege LUID/attribute rows into
    the bounded shared response.

Arguments:

    ProcessId - Target process ID.
    ExpectedCreateTime100ns - Optional stable process identity timestamp.
    Response - Fixed response initialized by the IOCTL handler.

Return Value:

    STATUS_SUCCESS, STATUS_BUFFER_OVERFLOW for truncation, or a token query
    failure status.

--*/
{
    HANDLE tokenHandle = NULL;
    PTOKEN_PRIVILEGES tokenPrivileges = NULL;
    ULONG tokenInformationBytes = 0UL;
    ULONG tokenInformationCapacity = 0UL;
    ULONG returnedCount = 0UL;
    ULONG entryIndex = 0UL;
    ULONG64 processCreateTime100ns = 0ULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = kswordArkDriverOpenStableProcessToken(
        processId,
        expectedCreateTime100ns,
        TOKEN_QUERY,
        &tokenHandle,
        &processCreateTime100ns);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    response->processCreateTime100ns = processCreateTime100ns;

    status = ZwQueryInformationToken(
        tokenHandle,
        TokenPrivileges,
        NULL,
        0UL,
        &tokenInformationBytes);
    if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW) {
        ZwClose(tokenHandle);
        return status;
    }
    if (tokenInformationBytes < (ULONG)FIELD_OFFSET(TOKEN_PRIVILEGES, Privileges) ||
        tokenInformationBytes > KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_QUERY_MAX_BYTES) {
        ZwClose(tokenHandle);
        return STATUS_INVALID_BUFFER_SIZE;
    }

    tokenInformationCapacity = tokenInformationBytes;
    tokenPrivileges = (PTOKEN_PRIVILEGES)kswordArkAllocateNonPagedPool(
        tokenInformationCapacity,
        KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_POOL_TAG);
    if (tokenPrivileges == NULL) {
        ZwClose(tokenHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(tokenPrivileges, tokenInformationCapacity);

    status = ZwQueryInformationToken(
        tokenHandle,
        TokenPrivileges,
        tokenPrivileges,
        tokenInformationCapacity,
        &tokenInformationBytes);
    ZwClose(tokenHandle);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(tokenPrivileges, KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_POOL_TAG);
        return status;
    }

    if (tokenInformationBytes < (ULONG)FIELD_OFFSET(TOKEN_PRIVILEGES, Privileges) ||
        tokenInformationBytes > tokenInformationCapacity ||
        tokenPrivileges->PrivilegeCount >
            ((tokenInformationBytes -
              (ULONG)FIELD_OFFSET(TOKEN_PRIVILEGES, Privileges)) /
             sizeof(LUID_AND_ATTRIBUTES))) {
        ExFreePoolWithTag(tokenPrivileges, KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_POOL_TAG);
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    returnedCount = tokenPrivileges->PrivilegeCount;
    if (returnedCount > KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_MAX_ENTRIES) {
        returnedCount = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_MAX_ENTRIES;
    }
    for (entryIndex = 0UL; entryIndex < returnedCount; ++entryIndex) {
        response->entries[entryIndex].luidLowPart =
            tokenPrivileges->Privileges[entryIndex].Luid.LowPart;
        response->entries[entryIndex].luidHighPart =
            tokenPrivileges->Privileges[entryIndex].Luid.HighPart;
        response->entries[entryIndex].attributes =
            tokenPrivileges->Privileges[entryIndex].Attributes;
        response->entries[entryIndex].action =
            KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_KEEP;
    }
    response->entryCount = returnedCount;

    status = tokenPrivileges->PrivilegeCount > returnedCount
        ? STATUS_BUFFER_OVERFLOW
        : STATUS_SUCCESS;
    ExFreePoolWithTag(tokenPrivileges, KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_POOL_TAG);
    return status;
}

NTSTATUS
kswordArkDriverAdjustProcessTokenPrivileges(
    _In_ ULONG processId,
    _In_ ULONG64 expectedCreateTime100ns,
    _In_reads_(entryCount) const KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ENTRY* entries,
    _In_ ULONG entryCount,
    _Out_ ULONG* appliedCountOut,
    _Out_ ULONG* failedIndexOut,
    _Out_ ULONG64* processCreateTime100nsOut
    )
/*++

Routine Description:

    Apply a validated ordered privilege edit list through
    ZwAdjustPrivilegesToken.

Arguments:

    ProcessId - Target process ID.
    ExpectedCreateTime100ns - Stable identity timestamp from the UI snapshot.
    Entries - LUID/action rows validated by the IOCTL handler.
    EntryCount - Number of requested rows.
    AppliedCountOut - Receives the successfully committed prefix length.
    FailedIndexOut - Receives the first failed row or the shared NONE sentinel.
    ProcessCreateTime100nsOut - Receives the observed process creation time.

Return Value:

    STATUS_SUCCESS only when every row was applied; otherwise the first failing
    token API status is returned after preserving partial-progress outputs.

--*/
{
    HANDLE tokenHandle = NULL;
    ULONG entryIndex = 0UL;
    ULONG64 processCreateTime100ns = 0ULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (expectedCreateTime100ns == 0ULL ||
        entries == NULL || entryCount == 0UL ||
        entryCount > KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_MAX_ENTRIES ||
        appliedCountOut == NULL || failedIndexOut == NULL ||
        processCreateTime100nsOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *appliedCountOut = 0UL;
    *failedIndexOut = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_FAILED_INDEX_NONE;
    *processCreateTime100nsOut = 0ULL;

    status = kswordArkDriverOpenStableProcessToken(
        processId,
        expectedCreateTime100ns,
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &tokenHandle,
        &processCreateTime100ns);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    *processCreateTime100nsOut = processCreateTime100ns;

    for (entryIndex = 0UL; entryIndex < entryCount; ++entryIndex) {
        TOKEN_PRIVILEGES tokenPrivileges;
        RtlZeroMemory(&tokenPrivileges, sizeof(tokenPrivileges));
        tokenPrivileges.PrivilegeCount = 1UL;
        tokenPrivileges.Privileges[0].Luid.LowPart = entries[entryIndex].luidLowPart;
        tokenPrivileges.Privileges[0].Luid.HighPart = entries[entryIndex].luidHighPart;

        switch (entries[entryIndex].action) {
        case KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_ENABLE:
            tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            break;
        case KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_DISABLE:
            tokenPrivileges.Privileges[0].Attributes = 0UL;
            break;
        case KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_REMOVE:
            tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;
            break;
        default:
            status = STATUS_INVALID_PARAMETER;
            *failedIndexOut = entryIndex;
            ZwClose(tokenHandle);
            return status;
        }

        status = ZwAdjustPrivilegesToken(
            tokenHandle,
            FALSE,
            &tokenPrivileges,
            (ULONG)sizeof(tokenPrivileges),
            NULL,
            NULL);
        if (status != STATUS_SUCCESS) {
            *failedIndexOut = entryIndex;
            ZwClose(tokenHandle);
            return status;
        }
        *appliedCountOut = entryIndex + 1UL;
    }

    ZwClose(tokenHandle);
    return STATUS_SUCCESS;
}
