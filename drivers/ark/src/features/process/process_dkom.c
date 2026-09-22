/*++

Module Name:

    process_dkom.c

Abstract:

    PspCidTable-backed process DKOM operations.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"

/* Note: PspCidTable location relies on the stable reference of PsLookupProcessByProcessId in ntoskrnl. */
#define KSWORD_ARK_DKOM_SCAN_BYTES 0x180UL
/* Note: The lower two bits of HandleTable.TableCode indicate the table level. */
#define KSWORD_ARK_DKOM_TABLE_LEVEL_MASK 0x3ULL
/* Note: The first-level table supports a maximum of 256 HandleTableEntry entries. */
#define KSWORD_ARK_DKOM_LEVEL0_ENTRY_COUNT 256UL
/* Note: Level 2 and Level 3 tables each support up to 512 pointer slots. */
#define KSWORD_ARK_DKOM_POINTER_ENTRY_COUNT 512UL
/* Note: The removal operation cleans up at most the matched entries to prevent abnormal loops. */
#define KSWORD_ARK_DKOM_REMOVE_MAX_ENTRIES 4UL

/* Note: PsLookupProcessByProcessId is used to reference the target object and locate PspCidTable. */
NTSYSAPI
NTSTATUS
NTAPI
PsLookupProcessByProcessId(
    _In_ HANDLE processId,
    _Outptr_ PEPROCESS* process
    );

/* Note: ObGetObjectType is used to confirm whether the decoded object is of the Process type. */
NTKERNELAPI
POBJECT_TYPE
NTAPI
ObGetObjectType(
    _In_ PVOID object
    );

/* Note: PsProcessType serves as the baseline for validating the target EPROCESS object type. */
extern POBJECT_TYPE* PsProcessType;

/* Note: Read kernel pointer with unified SEH protection. */
static NTSTATUS
kswordArkDkomReadPointer(
    _In_ PVOID address,
    _Out_ PVOID* pointerOut
    )
{
    PVOID pointerValue = NULL;

    if (address == NULL || pointerOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *pointerOut = NULL;

    __try {
        RtlCopyMemory(&pointerValue, address, sizeof(pointerValue));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    *pointerOut = pointerValue;
    return STATUS_SUCCESS;
}

/* Note: Write 64-bit entry; encapsulate separately for exception isolation. */
static NTSTATUS
kswordArkDkomWriteUlong64(
    _In_ PVOID address,
    _In_ ULONGLONG value
    )
{
    if (address == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    __try {
        *((volatile ULONGLONG*)address) = value;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    return STATUS_SUCCESS;
}

/* Note: Read a 64-bit entry; return an error status on failure. */
static NTSTATUS
kswordArkDkomReadUlong64(
    _In_ PVOID address,
    _Out_ ULONGLONG* valueOut
    )
{
    ULONGLONG value = 0ULL;

    if (address == NULL || valueOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *valueOut = 0ULL;

    __try {
        value = *((volatile ULONGLONG*)address);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    *valueOut = value;
    return STATUS_SUCCESS;
}

/* Note: Resolves global variable addresses from x64 RIP-relative instructions. */
static NTSTATUS
kswordArkDkomResolveRelativeAddress(
    _In_reads_bytes_(instructionLength) const UCHAR* instructionAddress,
    _In_ ULONG displacementOffset,
    _In_ ULONG instructionLength,
    _Out_ PVOID* addressOut
    )
{
    LONG relativeOffset = 0;
    ULONG_PTR resolvedAddress = 0UL;

    if (instructionAddress == NULL || addressOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *addressOut = NULL;

    __try {
        RtlCopyMemory(
            &relativeOffset,
            instructionAddress + displacementOffset,
            sizeof(relativeOffset));
        resolvedAddress =
            (ULONG_PTR)instructionAddress +
            (ULONG_PTR)instructionLength +
            (ULONG_PTR)relativeOffset;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    if (resolvedAddress == 0UL) {
        return STATUS_NOT_FOUND;
    }
    *addressOut = (PVOID)resolvedAddress;
    return STATUS_SUCCESS;
}

/* Note: Match the 'mov rax/qword ptr [rip+disp32]' pattern. */
static NTSTATUS
kswordArkDkomTryResolveMovRaxRip(
    _In_reads_bytes_(KSWORD_ARK_DKOM_SCAN_BYTES) const UCHAR* scanBase,
    _In_ ULONG offset,
    _Out_ PVOID* pspCidTableAddressOut
    )
{
    if (scanBase == NULL || pspCidTableAddressOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *pspCidTableAddressOut = NULL;

    if ((offset + 7UL) > KSWORD_ARK_DKOM_SCAN_BYTES) {
        return STATUS_NOT_FOUND;
    }

    __try {
        if (scanBase[offset] == 0x48U &&
            scanBase[offset + 1UL] == 0x8BU &&
            scanBase[offset + 2UL] == 0x05U) {
            return kswordArkDkomResolveRelativeAddress(
                scanBase + offset,
                3UL,
                7UL,
                pspCidTableAddressOut);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    return STATUS_NOT_FOUND;
}

/* Note: Match 'mov rcx/qword ptr [rip+disp32]' form. */
static NTSTATUS
kswordArkDkomTryResolveMovRcxRip(
    _In_reads_bytes_(KSWORD_ARK_DKOM_SCAN_BYTES) const UCHAR* scanBase,
    _In_ ULONG offset,
    _Out_ PVOID* pspCidTableAddressOut
    )
{
    if (scanBase == NULL || pspCidTableAddressOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *pspCidTableAddressOut = NULL;

    if ((offset + 7UL) > KSWORD_ARK_DKOM_SCAN_BYTES) {
        return STATUS_NOT_FOUND;
    }

    __try {
        if (scanBase[offset] == 0x48U &&
            scanBase[offset + 1UL] == 0x8BU &&
            scanBase[offset + 2UL] == 0x0DU) {
            return kswordArkDkomResolveRelativeAddress(
                scanBase + offset,
                3UL,
                7UL,
                pspCidTableAddressOut);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    return STATUS_NOT_FOUND;
}

/* Note: Parse small-range MOV instructions following the call to PspReferenceCidTableEntry. */
static NTSTATUS
kswordArkDkomTryResolveThroughCallTarget(
    _In_reads_bytes_(KSWORD_ARK_DKOM_SCAN_BYTES) const UCHAR* scanBase,
    _In_ ULONG offset,
    _Out_ PVOID* pspCidTableAddressOut
    )
{
    PVOID callTarget = NULL;
    const UCHAR* targetBytes = NULL;
    ULONG targetOffset = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (scanBase == NULL || pspCidTableAddressOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *pspCidTableAddressOut = NULL;

    if ((offset + 5UL) > KSWORD_ARK_DKOM_SCAN_BYTES) {
        return STATUS_NOT_FOUND;
    }

    __try {
        if (scanBase[offset] != 0xE8U) {
            return STATUS_NOT_FOUND;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    status = kswordArkDkomResolveRelativeAddress(
        scanBase + offset,
        1UL,
        5UL,
        &callTarget);
    if (!NT_SUCCESS(status) || callTarget == NULL) {
        return status;
    }

    targetBytes = (const UCHAR*)callTarget;
    for (targetOffset = 0UL; targetOffset < 0x40UL; ++targetOffset) {
        PVOID resolvedAddress = NULL;
        NTSTATUS movStatus = STATUS_SUCCESS;

        movStatus = kswordArkDkomTryResolveMovRaxRip(
            targetBytes,
            targetOffset,
            &resolvedAddress);
        if (NT_SUCCESS(movStatus) && resolvedAddress != NULL) {
            *pspCidTableAddressOut = resolvedAddress;
            return STATUS_SUCCESS;
        }

        movStatus = kswordArkDkomTryResolveMovRcxRip(
            targetBytes,
            targetOffset,
            &resolvedAddress);
        if (NT_SUCCESS(movStatus) && resolvedAddress != NULL) {
            *pspCidTableAddressOut = resolvedAddress;
            return STATUS_SUCCESS;
        }
    }

    return STATUS_NOT_FOUND;
}

/* Note: Locate the PspCidTable global variable address; return STATUS_NOT_FOUND on failure. */
static NTSTATUS
kswordArkDkomResolvePspCidTableAddress(
    _Out_ PVOID* pspCidTableAddressOut
    )
{
    const UCHAR* lookupBytes = (const UCHAR*)PsLookupProcessByProcessId;
    ULONG offset = 0UL;
    NTSTATUS lastStatus = STATUS_NOT_FOUND;

    if (pspCidTableAddressOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *pspCidTableAddressOut = NULL;

    if (lookupBytes == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    for (offset = 0UL; offset < KSWORD_ARK_DKOM_SCAN_BYTES; ++offset) {
        PVOID resolvedAddress = NULL;
        NTSTATUS status = STATUS_SUCCESS;

        status = kswordArkDkomTryResolveMovRaxRip(
            lookupBytes,
            offset,
            &resolvedAddress);
        if (NT_SUCCESS(status) && resolvedAddress != NULL) {
            *pspCidTableAddressOut = resolvedAddress;
            return STATUS_SUCCESS;
        }
        if (status != STATUS_NOT_FOUND) {
            lastStatus = status;
        }

        status = kswordArkDkomTryResolveMovRcxRip(
            lookupBytes,
            offset,
            &resolvedAddress);
        if (NT_SUCCESS(status) && resolvedAddress != NULL) {
            *pspCidTableAddressOut = resolvedAddress;
            return STATUS_SUCCESS;
        }
        if (status != STATUS_NOT_FOUND) {
            lastStatus = status;
        }

        status = kswordArkDkomTryResolveThroughCallTarget(
            lookupBytes,
            offset,
            &resolvedAddress);
        if (NT_SUCCESS(status) && resolvedAddress != NULL) {
            *pspCidTableAddressOut = resolvedAddress;
            return STATUS_SUCCESS;
        }
        if (status != STATUS_NOT_FOUND) {
            lastStatus = status;
        }
    }

    return lastStatus;
}

/* Note: Read TableCode from HandleTable and extract the root table address. */
static NTSTATUS
kswordArkDkomReadCidTableRoot(
    _In_ PVOID pspCidTableAddress,
    _Out_ ULONGLONG* tableRootOut,
    _Out_ ULONG* tableLevelOut
    )
{
    PVOID handleTable = NULL;
    ULONGLONG tableCode = 0ULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (pspCidTableAddress == NULL || tableRootOut == NULL || tableLevelOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *tableRootOut = 0ULL;
    *tableLevelOut = 0UL;

    status = kswordArkDkomReadPointer(pspCidTableAddress, &handleTable);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (handleTable == NULL) {
        return STATUS_NOT_FOUND;
    }

    status = kswordArkDkomReadUlong64((PUCHAR)handleTable + sizeof(PVOID), &tableCode);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *tableLevelOut = (ULONG)(tableCode & KSWORD_ARK_DKOM_TABLE_LEVEL_MASK);
    *tableRootOut = tableCode & ~KSWORD_ARK_DKOM_TABLE_LEVEL_MASK;
    return (*tableRootOut == 0ULL) ? STATUS_NOT_FOUND : STATUS_SUCCESS;
}

/* Note: Decode the object body pointer from HandleTableEntry.LowValue. */
static PVOID
kswordArkDkomDecodeCidEntryObject(
    _In_ ULONGLONG entryValue
    )
{
    ULONGLONG objectValue = 0ULL;

    if (entryValue == 0ULL) {
        return NULL;
    }

#if defined(_WIN64)
    /* Note: Modern x64 HandleTableEntry uses object pointer encoding with a right shift of 0x10. */
    objectValue = (ULONGLONG)(((LONGLONG)entryValue) >> 0x10);
    objectValue &= 0xFFFFFFFFFFFFFFF0ULL;
#else
    objectValue = EntryValue & ~(ULONGLONG)0x7U;
#endif

    return (PVOID)(ULONG_PTR)objectValue;
}

/* Note: Verify whether the candidate object is the target EPROCESS. */
static BOOLEAN
kswordArkDkomEntryMatchesProcess(
    _In_ ULONGLONG entryValue,
    _In_ PEPROCESS processObject
    )
{
    PVOID objectBody = NULL;
    POBJECT_TYPE objectType = NULL;
    BOOLEAN matches = FALSE;

    if (entryValue == 0ULL || processObject == NULL) {
        return FALSE;
    }

    objectBody = kswordArkDkomDecodeCidEntryObject(entryValue);
    if (objectBody != (PVOID)processObject) {
        return FALSE;
    }

    __try {
        objectType = ObGetObjectType(objectBody);
        matches = (PsProcessType != NULL && objectType == *PsProcessType) ? TRUE : FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        matches = FALSE;
    }

    return matches;
}

/* Note: Search within a single-level entry table and zero out the target process object. */
static NTSTATUS
kswordArkDkomRemoveFromLevel0Table(
    _In_ ULONGLONG tableAddress,
    _In_ PEPROCESS processObject,
    _Inout_ ULONG* removedEntries
    )
{
    ULONG entryIndex = 0UL;
    NTSTATUS lastStatus = STATUS_NOT_FOUND;

    if (tableAddress == 0ULL || processObject == NULL || removedEntries == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    for (entryIndex = 0UL; entryIndex < KSWORD_ARK_DKOM_LEVEL0_ENTRY_COUNT; ++entryIndex) {
        PVOID entryAddress = (PVOID)(ULONG_PTR)(tableAddress + ((ULONGLONG)entryIndex * 16ULL));
        ULONGLONG entryValue = 0ULL;
        NTSTATUS status = STATUS_SUCCESS;

        status = kswordArkDkomReadUlong64(entryAddress, &entryValue);
        if (!NT_SUCCESS(status)) {
            lastStatus = status;
            continue;
        }

        if (!kswordArkDkomEntryMatchesProcess(entryValue, processObject)) {
            continue;
        }

        status = kswordArkDkomWriteUlong64(entryAddress, 0ULL);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (*removedEntries != MAXULONG) {
            *removedEntries += 1UL;
        }
        lastStatus = STATUS_SUCCESS;
        if (*removedEntries >= KSWORD_ARK_DKOM_REMOVE_MAX_ENTRIES) {
            break;
        }
    }

    return lastStatus;
}

/* Note: Iterate the level-2 table and invoke level-1 cleanup. */
static NTSTATUS
kswordArkDkomRemoveFromLevel1Table(
    _In_ ULONGLONG tableAddress,
    _In_ PEPROCESS processObject,
    _Inout_ ULONG* removedEntries
    )
{
    ULONG pointerIndex = 0UL;
    NTSTATUS lastStatus = STATUS_NOT_FOUND;

    if (tableAddress == 0ULL || processObject == NULL || removedEntries == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    for (pointerIndex = 0UL; pointerIndex < KSWORD_ARK_DKOM_POINTER_ENTRY_COUNT; ++pointerIndex) {
        ULONGLONG childTable = 0ULL;
        NTSTATUS status = STATUS_SUCCESS;

        status = kswordArkDkomReadUlong64(
            (PVOID)(ULONG_PTR)(tableAddress + ((ULONGLONG)pointerIndex * sizeof(PVOID))),
            &childTable);
        if (!NT_SUCCESS(status) || childTable == 0ULL) {
            if (!NT_SUCCESS(status)) {
                lastStatus = status;
            }
            continue;
        }

        status = kswordArkDkomRemoveFromLevel0Table(
            childTable,
            processObject,
            removedEntries);
        if (NT_SUCCESS(status)) {
            lastStatus = STATUS_SUCCESS;
            if (*removedEntries >= KSWORD_ARK_DKOM_REMOVE_MAX_ENTRIES) {
                break;
            }
        }
        else if (status != STATUS_NOT_FOUND) {
            lastStatus = status;
        }
    }

    return lastStatus;
}

/* Note: Traverse the three-level table and invoke level-2 cleanup. */
static NTSTATUS
kswordArkDkomRemoveFromLevel2Table(
    _In_ ULONGLONG tableAddress,
    _In_ PEPROCESS processObject,
    _Inout_ ULONG* removedEntries
    )
{
    ULONG pointerIndex = 0UL;
    NTSTATUS lastStatus = STATUS_NOT_FOUND;

    if (tableAddress == 0ULL || processObject == NULL || removedEntries == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    for (pointerIndex = 0UL; pointerIndex < KSWORD_ARK_DKOM_POINTER_ENTRY_COUNT; ++pointerIndex) {
        ULONGLONG childTable = 0ULL;
        NTSTATUS status = STATUS_SUCCESS;

        status = kswordArkDkomReadUlong64(
            (PVOID)(ULONG_PTR)(tableAddress + ((ULONGLONG)pointerIndex * sizeof(PVOID))),
            &childTable);
        if (!NT_SUCCESS(status) || childTable == 0ULL) {
            if (!NT_SUCCESS(status)) {
                lastStatus = status;
            }
            continue;
        }

        status = kswordArkDkomRemoveFromLevel1Table(
            childTable,
            processObject,
            removedEntries);
        if (NT_SUCCESS(status)) {
            lastStatus = STATUS_SUCCESS;
            if (*removedEntries >= KSWORD_ARK_DKOM_REMOVE_MAX_ENTRIES) {
                break;
            }
        }
        else if (status != STATUS_NOT_FOUND) {
            lastStatus = status;
        }
    }

    return lastStatus;
}

/* Note: Dispatch cleanup logic based on the HandleTable.TableCode level. */
static NTSTATUS
kswordArkDkomRemoveProcessFromPspCidTable(
    _In_ PEPROCESS processObject,
    _In_ PVOID pspCidTableAddress,
    _Out_ ULONG* removedEntriesOut
    )
{
    ULONGLONG tableRoot = 0ULL;
    ULONG tableLevel = 0UL;
    ULONG removedEntries = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (processObject == NULL || pspCidTableAddress == NULL || removedEntriesOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *removedEntriesOut = 0UL;

    status = kswordArkDkomReadCidTableRoot(
        pspCidTableAddress,
        &tableRoot,
        &tableLevel);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (tableLevel == 0UL) {
        status = kswordArkDkomRemoveFromLevel0Table(
            tableRoot,
            processObject,
            &removedEntries);
    }
    else if (tableLevel == 1UL) {
        status = kswordArkDkomRemoveFromLevel1Table(
            tableRoot,
            processObject,
            &removedEntries);
    }
    else if (tableLevel == 2UL) {
        status = kswordArkDkomRemoveFromLevel2Table(
            tableRoot,
            processObject,
            &removedEntries);
    }
    else {
        status = STATUS_NOT_SUPPORTED;
    }

    *removedEntriesOut = removedEntries;
    if (removedEntries != 0UL) {
        return STATUS_SUCCESS;
    }
    return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
}

NTSTATUS
kswordArkDriverDkomProcess(
    _In_ ULONG processId,
    _In_ ULONG action,
    _In_ ULONG flags,
    _Out_ ULONG* operationStatusOut,
    _Out_ ULONG* removedEntriesOut,
    _Out_ ULONG64* pspCidTableAddressOut,
    _Out_ ULONG64* processObjectAddressOut
    )
/*++

Routine Description:

    Execute process DKOM actions. Note: The current implementation removes entries from PspCidTable; the target
    object is resolved in the kernel by PID, and arbitrary EPROCESS addresses passed from R3 are not accepted.

Arguments:

    ProcessId - target PID.
    Action - KSWORD_ARK_PROCESS_DKOM_ACTION_*。
    Flags - Reserved policy bits.
    OperationStatusOut - Returned protocol status.
    RemovedEntriesOut - Number of CID entries cleaned up.
    PspCidTableAddressOut - Returns the address of the PspCidTable variable for diagnostics.
    ProcessObjectAddressOut: Returns the EPROCESS address for diagnostics.

Return Value:

    STATUS_SUCCESS or locate/write failure status.

--*/
{
    PEPROCESS processObject = NULL;
    PVOID pspCidTableAddress = NULL;
    ULONG removedEntries = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(flags);

    if (operationStatusOut == NULL ||
        removedEntriesOut == NULL ||
        pspCidTableAddressOut == NULL ||
        processObjectAddressOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *operationStatusOut = KSWORD_ARK_PROCESS_DKOM_STATUS_UNKNOWN;
    *removedEntriesOut = 0UL;
    *pspCidTableAddressOut = 0ULL;
    *processObjectAddressOut = 0ULL;

    if (processId == 0UL || processId <= 4UL) {
        *operationStatusOut = KSWORD_ARK_PROCESS_DKOM_STATUS_LOOKUP_FAILED;
        return STATUS_INVALID_PARAMETER;
    }
    if (action != KSWORD_ARK_PROCESS_DKOM_ACTION_REMOVE_FROM_PSP_CID_TABLE) {
        *operationStatusOut = KSWORD_ARK_PROCESS_DKOM_STATUS_OPERATION_FAILED;
        return STATUS_INVALID_PARAMETER;
    }

    status = PsLookupProcessByProcessId(ULongToHandle(processId), &processObject);
    if (!NT_SUCCESS(status)) {
        *operationStatusOut = KSWORD_ARK_PROCESS_DKOM_STATUS_LOOKUP_FAILED;
        return status;
    }
    *processObjectAddressOut = (ULONG64)(ULONG_PTR)processObject;

    status = kswordArkDkomResolvePspCidTableAddress(&pspCidTableAddress);
    if (!NT_SUCCESS(status) || pspCidTableAddress == NULL) {
        *operationStatusOut = KSWORD_ARK_PROCESS_DKOM_STATUS_UNSUPPORTED;
        ObDereferenceObject(processObject);
        return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
    }
    *pspCidTableAddressOut = (ULONG64)(ULONG_PTR)pspCidTableAddress;

    status = kswordArkDkomRemoveProcessFromPspCidTable(
        processObject,
        pspCidTableAddress,
        &removedEntries);
    *removedEntriesOut = removedEntries;

    if (NT_SUCCESS(status)) {
        *operationStatusOut = KSWORD_ARK_PROCESS_DKOM_STATUS_REMOVED;
    }
    else if (status == STATUS_NOT_FOUND) {
        *operationStatusOut = KSWORD_ARK_PROCESS_DKOM_STATUS_NOT_FOUND;
    }
    else if (status == STATUS_NOT_SUPPORTED || status == STATUS_PROCEDURE_NOT_FOUND) {
        *operationStatusOut = KSWORD_ARK_PROCESS_DKOM_STATUS_UNSUPPORTED;
    }
    else {
        *operationStatusOut = KSWORD_ARK_PROCESS_DKOM_STATUS_OPERATION_FAILED;
    }

    ObDereferenceObject(processObject);
    return status;
}
