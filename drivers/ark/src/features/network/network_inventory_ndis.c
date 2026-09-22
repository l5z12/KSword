/*++

Module Name:

    network_inventory_ndis.c

Abstract:

    Read-only NDIS LAN interface device-stack inventory.

Environment:

    Kernel mode, PASSIVE_LEVEL only

--*/

#include <ntifs.h>
#include "network_inventory_internal.h"

#define KSWORD_ARK_NDIS_STACK_MAX_DEPTH 64UL
#define KSWORD_ARK_NDIS_ENUM_MAX_ROWS 8192UL

// {AD498944-762F-11D0-8DCB-00C04FC3358C}, which is the WDK GUID_NDIS_LAN_CLASS.
static const GUID kKswordArkNdisLanInterfaceClass =
{ 0xad498944, 0x762f, 0x11d0, { 0x8d, 0xcb, 0x00, 0xc0, 0x4f, 0xc3, 0x35, 0x8c } };

static VOID
kswordArkNetworkNdisAppendDevice(
    _In_ PCWSTR interfaceName,
    _In_reads_(stackCount) PDEVICE_OBJECT const* stack,
    _In_ ULONG stackCount,
    _In_ ULONG stackIndex,
    _In_ ULONG objectKind,
    _Out_writes_opt_(rowCapacity) KSWORD_ARK_NETWORK_NDIS_CHAIN_ROW* rows,
    _In_ ULONG rowCapacity,
    _Inout_ ULONG* totalRows,
    _Inout_ ULONG* returnedRows
    )
{
    PDEVICE_OBJECT deviceObject = stack[stackIndex];
    PDRIVER_OBJECT driverObject = (deviceObject != NULL) ? deviceObject->DriverObject : NULL;
    KSWORD_ARK_NETWORK_NDIS_CHAIN_ROW* row = NULL;

    if (*totalRows >= KSWORD_ARK_NDIS_ENUM_MAX_ROWS) {
        return;
    }

    *totalRows += 1UL;
    if (rows == NULL || *returnedRows >= rowCapacity) {
        return;
    }

    row = &rows[*returnedRows];
    RtlZeroMemory(row, sizeof(*row));
    row->rowId = *returnedRows;
    row->objectKind = objectKind;
    row->flags =
        KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_PDB_UNAVAILABLE |
        KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_FIELD_MISSING;
    row->filterOrder = stackIndex;
    row->objectAddress = (ULONG64)(ULONG_PTR)deviceObject;
    row->parentObjectAddress =
        (stackIndex + 1UL < stackCount) ?
        (ULONG64)(ULONG_PTR)stack[stackIndex + 1UL] :
        0ULL;

    if (driverObject != NULL) {
        row->driverObject = (ULONG64)(ULONG_PTR)driverObject;
        row->imageBase = (ULONG64)(ULONG_PTR)driverObject->DriverStart;
        kswordArkNetworkInventoryCopyUnicodeString(row->ownerModule, &driverObject->DriverName);
    }
    else {
        row->flags |=
            KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_OWNER_UNKNOWN |
            KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_MODULE_UNKNOWN;
    }

    if (objectKind == KSWORD_ARK_NETWORK_NDIS_OBJECT_MINIPORT ||
        objectKind == KSWORD_ARK_NETWORK_NDIS_OBJECT_UNKNOWN) {
        kswordArkNetworkInventoryCopyWideText(row->componentName, interfaceName);
    }
    else if (driverObject != NULL) {
        kswordArkNetworkInventoryCopyUnicodeString(row->componentName, &driverObject->DriverName);
    }

    *returnedRows += 1UL;
}

NTSTATUS
kswordArkNetworkCollectNdisDeviceStacks(
    _Out_writes_opt_(rowCapacity) KSWORD_ARK_NETWORK_NDIS_CHAIN_ROW* rows,
    _In_ ULONG rowCapacity,
    _Out_ ULONG* totalRowsOut,
    _Out_ ULONG* returnedRowsOut
    )
/*++

Routine Description:

    enumerate enabled interfaces for GUID_NDIS_LAN_CLASS and obtain the read-only device stack following
    the reference rules of IoGetAttachedDeviceReference / IoGetLowerDeviceObject. Select the deepest
    FILE_DEVICE_PHYSICAL_NETCARD in the stack as the unique provable miniport device boundary. Objects
    above this boundary can only prove attachment; objectKind remains UNKNOWN. If no boundary is found,
    the top-level object also remains UNKNOWN; do not fabricate NDIS private LWF, protocol, or binding.

Return Value:

    STATUS_SUCCESS indicates all interfaces were fully traversed; STATUS_BUFFER_OVERFLOW indicates a hard limit
    on depth or total count; STATUS_PARTIAL_COPY indicates some interfaces succeeded while others failed to open.

--*/
{
    PWSTR symbolicLinks = NULL;
    PWSTR currentLink = NULL;
    ULONG totalRows = 0UL;
    ULONG returnedRows = 0UL;
    ULONG successfulInterfaces = 0UL;
    NTSTATUS firstFailure = STATUS_SUCCESS;
    NTSTATUS status = STATUS_SUCCESS;

    if (totalRowsOut == NULL || returnedRowsOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *totalRowsOut = 0UL;
    *returnedRowsOut = 0UL;
    if (rows == NULL && rowCapacity != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    status = IoGetDeviceInterfaces(
        &kKswordArkNdisLanInterfaceClass,
        NULL,
        0UL,
        &symbolicLinks);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (symbolicLinks == NULL) {
        return STATUS_DATA_ERROR;
    }

    currentLink = symbolicLinks;
    while (currentLink != NULL && *currentLink != L'\0') {
        UNICODE_STRING interfaceName;
        PFILE_OBJECT fileObject = NULL;
        PDEVICE_OBJECT deviceObject = NULL;
        PDEVICE_OBJECT stack[KSWORD_ARK_NDIS_STACK_MAX_DEPTH];
        ULONG stackCount = 0UL;
        ULONG miniportIndex = MAXULONG;
        ULONG includedCount = 0UL;
        ULONG index = 0UL;

        RtlZeroMemory(stack, sizeof(stack));
        RtlInitUnicodeString(&interfaceName, currentLink);
        status = IoGetDeviceObjectPointer(
            &interfaceName,
            FILE_READ_ATTRIBUTES,
            &fileObject,
            &deviceObject);
        if (!NT_SUCCESS(status)) {
            if (NT_SUCCESS(firstFailure)) {
                firstFailure = status;
            }
            currentLink += (interfaceName.Length / sizeof(WCHAR)) + 1UL;
            continue;
        }

        stack[0] = IoGetAttachedDeviceReference(deviceObject);
        if (stack[0] == NULL) {
            if (NT_SUCCESS(firstFailure)) {
                firstFailure = STATUS_NOT_FOUND;
            }
            ObDereferenceObject(fileObject);
            currentLink += (interfaceName.Length / sizeof(WCHAR)) + 1UL;
            continue;
        }
        stackCount = 1UL;

        while (stackCount < KSWORD_ARK_NDIS_STACK_MAX_DEPTH) {
            PDEVICE_OBJECT lowerObject = IoGetLowerDeviceObject(stack[stackCount - 1UL]);
            if (lowerObject == NULL) {
                break;
            }
            stack[stackCount] = lowerObject;
            stackCount += 1UL;
        }

        if (stackCount == KSWORD_ARK_NDIS_STACK_MAX_DEPTH) {
            PDEVICE_OBJECT extraObject = IoGetLowerDeviceObject(stack[stackCount - 1UL]);
            if (extraObject != NULL) {
                ObDereferenceObject(extraObject);
                if (NT_SUCCESS(firstFailure)) {
                    firstFailure = STATUS_BUFFER_OVERFLOW;
                }
            }
        }

        for (index = 0UL; index < stackCount; ++index) {
            if (stack[index]->DeviceType == FILE_DEVICE_PHYSICAL_NETCARD) {
                // Take the deepest match as the only provable miniport boundary; objects above it only prove attachment.
                miniportIndex = index;
            }
        }

        if (miniportIndex != MAXULONG) {
            includedCount = miniportIndex + 1UL;
            for (index = 0UL; index < includedCount; ++index) {
                const ULONG kKind = (index == miniportIndex) ?
                    KSWORD_ARK_NETWORK_NDIS_OBJECT_MINIPORT :
                    KSWORD_ARK_NETWORK_NDIS_OBJECT_UNKNOWN;
                kswordArkNetworkNdisAppendDevice(
                    currentLink,
                    stack,
                    includedCount,
                    index,
                    kKind,
                    rows,
                    rowCapacity,
                    &totalRows,
                    &returnedRows);
            }
        }
        else {
            kswordArkNetworkNdisAppendDevice(
                currentLink,
                stack,
                1UL,
                0UL,
                KSWORD_ARK_NETWORK_NDIS_OBJECT_UNKNOWN,
                rows,
                rowCapacity,
                &totalRows,
                &returnedRows);
        }

        for (index = 0UL; index < stackCount; ++index) {
            ObDereferenceObject(stack[index]);
        }
        ObDereferenceObject(fileObject);
        successfulInterfaces += 1UL;

        if (totalRows >= KSWORD_ARK_NDIS_ENUM_MAX_ROWS) {
            firstFailure = STATUS_BUFFER_OVERFLOW;
            break;
        }
        currentLink += (interfaceName.Length / sizeof(WCHAR)) + 1UL;
    }

    ExFreePool(symbolicLinks);

    if (totalRows > returnedRows && rows != NULL) {
        ULONG index = 0UL;
        for (index = 0UL; index < returnedRows; ++index) {
            rows[index].flags |= KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_BUDGET_LIMITED;
        }
    }

    *totalRowsOut = totalRows;
    *returnedRowsOut = returnedRows;
    if (NT_SUCCESS(firstFailure)) {
        return STATUS_SUCCESS;
    }
    if (successfulInterfaces == 0UL) {
        return firstFailure;
    }
    return (firstFailure == STATUS_BUFFER_OVERFLOW) ?
        STATUS_BUFFER_OVERFLOW :
        STATUS_PARTIAL_COPY;
}
