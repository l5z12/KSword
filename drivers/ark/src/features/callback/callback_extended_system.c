/*++

Module Name:

    callback_extended_system.c

Abstract:

    Enumerates file system registration changes, logon session termination, and driver shutdown callbacks.

Environment:

    Kernel-mode Driver Framework

--*/

#include "callback_extended_internal.h"
#include "callback_extended_kernel.h"

#define KSWORD_ARK_CALLBACK_SYSTEM_CODE_SCAN_BYTES 0x300UL
#define KSWORD_ARK_CALLBACK_SYSTEM_WALK_LIMIT 512UL
#define KSWORD_ARK_CALLBACK_SYSTEM_DIRECTORY_BYTES (16UL * 1024UL)
#define KSWORD_ARK_CALLBACK_SYSTEM_DIRECTORY_LIMIT 4096UL
#define KSWORD_ARK_CALLBACK_SYSTEM_DEVICE_LIMIT 4096UL
#define KSWORD_ARK_CALLBACK_SYSTEM_TAG 'sCbK'

#ifndef DIRECTORY_QUERY
#define DIRECTORY_QUERY 0x0001
#endif

#ifndef STATUS_NO_MORE_ENTRIES
#define STATUS_NO_MORE_ENTRIES ((NTSTATUS)0x8000001AL)
#endif

typedef struct KswordArkCallbackSystemDirectoryInformation
{
    UNICODE_STRING name;
    UNICODE_STRING typeName;
} KswordArkCallbackSystemDirectoryInformation;

typedef struct KswordArkCallbackFsRegistration
{
    LIST_ENTRY link;
    PDRIVER_OBJECT driverObject;
    PVOID notificationRoutine;
} KswordArkCallbackFsRegistration;

typedef struct KswordArkCallbackLogonRegistration
{
    PVOID next;
    PVOID callbackRoutine;
} KswordArkCallbackLogonRegistration;

typedef struct KswordArkCallbackLogonExRegistration
{
    PVOID next;
    PVOID callbackRoutine;
    PVOID callbackContext;
} KswordArkCallbackLogonExRegistration;

NTSYSAPI
NTSTATUS
NTAPI
ZwOpenDirectoryObject(
    _Out_ PHANDLE directoryHandle,
    _In_ ACCESS_MASK desiredAccess,
    _In_ POBJECT_ATTRIBUTES objectAttributes
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryDirectoryObject(
    _In_ HANDLE directoryHandle,
    _Out_writes_bytes_opt_(length) PVOID buffer,
    _In_ ULONG length,
    _In_ BOOLEAN returnSingleEntry,
    _In_ BOOLEAN restartScan,
    _Inout_ PULONG context,
    _Out_opt_ PULONG returnLength
    );

NTSYSAPI
NTSTATUS
NTAPI
ObReferenceObjectByName(
    _In_ PUNICODE_STRING objectName,
    _In_ ULONG attributes,
    _In_opt_ PACCESS_STATE passedAccessState,
    _In_opt_ ACCESS_MASK desiredAccess,
    _In_ POBJECT_TYPE objectType,
    _In_ KPROCESSOR_MODE accessMode,
    _Inout_opt_ PVOID parseContext,
    _Out_ PVOID* object
    );

extern POBJECT_TYPE* IoDriverObjectType;

static NTSTATUS
kswordArkCallbackExtendedLocateFsListHead(
    _Out_ ULONG64* listHeadAddressOut
    )
/*++

Routine Description:

    Locate IopFsNotifyChangeQueueHead from IoRegisterFsRegistrationChangeMountAware.
    Note: Requires adjacent LEA/CMP two RIP-relative instructions to resolve to the same
    address, to avoid misidentifying locks, events, or other globals as linked list heads.

Arguments:

    ListHeadAddressOut - Output LIST_ENTRY address.

Return Value:

    Returns STATUS_SUCCESS on success; returns the corresponding status if export or signature is unavailable.

--*/
{
    UCHAR codeBytes[KSWORD_ARK_CALLBACK_SYSTEM_CODE_SCAN_BYTES];
    ULONG offset = 0UL;
    ULONG64 routineAddress = (ULONG64)(ULONG_PTR)
        kswordArkCallbackExtendedGetSystemRoutine(L"IoRegisterFsRegistrationChangeMountAware");

    if (listHeadAddressOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *listHeadAddressOut = 0ULL;
    if (routineAddress == 0ULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    RtlZeroMemory(codeBytes, sizeof(codeBytes));
    if (!kswordArkCallbackEnumReadMemory(
            (const VOID*)(ULONG_PTR)routineAddress,
            codeBytes,
            sizeof(codeBytes))) {
        return STATUS_ACCESS_VIOLATION;
    }

    for (offset = 0UL; offset + 14UL <= sizeof(codeBytes); ++offset) {
        ULONG64 leaTarget = 0ULL;
        ULONG64 compareTarget = 0ULL;

        if (codeBytes[offset] != 0x4CU ||
            codeBytes[offset + 1UL] != 0x8DU ||
            codeBytes[offset + 2UL] != 0x3DU ||
            codeBytes[offset + 7UL] != 0x4CU ||
            codeBytes[offset + 8UL] != 0x39U ||
            codeBytes[offset + 9UL] != 0x3DU) {
            continue;
        }
        if (!kswordArkCallbackExtendedResolveRipRelative(
                routineAddress + offset,
                3UL,
                7UL,
                &leaTarget) ||
            !kswordArkCallbackExtendedResolveRipRelative(
                routineAddress + offset + 7UL,
                3UL,
                7UL,
                &compareTarget)) {
            continue;
        }
        if (leaTarget == compareTarget && leaTarget != 0ULL) {
            *listHeadAddressOut = leaTarget;
            return STATUS_SUCCESS;
        }
    }

    return STATUS_NOT_FOUND;
}

static VOID
kswordArkCallbackExtendedAddFsRegistrationCallbacks(
    _Inout_ KswordArkCallbackEnumBuilder* builder,
    _Inout_ KswordArkCallbackModuleCache* moduleCache
    )
/*++

Routine Description:

    Iterate over IopFsNotifyChangeQueueHead to display file system registration change callbacks.

Arguments:

    Builder: Response builder.
    ModuleCache - Module cache.

Return Value:

    No return value.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG index = 0UL;
    ULONG addedCount = 0UL;
    ULONG64 listHeadAddress = 0ULL;
    ULONG64 currentAddress = 0ULL;
    LIST_ENTRY listHead;

    status = kswordArkCallbackExtendedLocateFsListHead(&listHeadAddress);
    if (!NT_SUCCESS(status)) {
        kswordArkCallbackExtendedAddRow(
            builder,
            moduleCache,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_FILE_SYSTEM,
            KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_FILESYSTEM_LIST,
            KSWORD_ARK_CALLBACK_ENUM_STATUS_QUERY_FAILED,
            status,
            KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_FILE_SYSTEM_CHANGE,
            0UL,
            0UL,
            0ULL,
            0ULL,
            0ULL,
            0UL,
            L"IopFsNotifyChangeQueueHead",
            L"未能从 IoRegisterFsRegistrationChangeMountAware 公开入口定位文件系统注册变化链。");
        return;
    }

    RtlZeroMemory(&listHead, sizeof(listHead));
    if (!kswordArkCallbackExtendedReadListEntry(listHeadAddress, &listHead)) {
        return;
    }

    currentAddress = (ULONG64)(ULONG_PTR)listHead.Flink;
    while (currentAddress != 0ULL &&
        currentAddress != listHeadAddress &&
        index < KSWORD_ARK_CALLBACK_SYSTEM_WALK_LIMIT) {
        KswordArkCallbackFsRegistration registration;
        ULONG64 nextAddress = 0ULL;

        RtlZeroMemory(&registration, sizeof(registration));
        if (!kswordArkCallbackEnumReadMemory(
                (const VOID*)(ULONG_PTR)currentAddress,
                &registration,
                sizeof(registration))) {
            break;
        }
        nextAddress = (ULONG64)(ULONG_PTR)registration.link.Flink;

        if (registration.notificationRoutine != NULL &&
            kswordArkCallbackEnumIsKernelModuleAddress(
                moduleCache,
                (ULONG64)(ULONG_PTR)registration.notificationRoutine)) {
            WCHAR nameText[KSWORD_ARK_CALLBACK_ENUM_NAME_CHARS];
            WCHAR detailText[KSWORD_ARK_CALLBACK_ENUM_DETAIL_CHARS];

            RtlZeroMemory(nameText, sizeof(nameText));
            RtlZeroMemory(detailText, sizeof(detailText));
            (VOID)RtlStringCbPrintfW(
                nameText,
                sizeof(nameText),
                L"IoFsRegistrationChange[%lu]",
                (unsigned long)index);
            (VOID)RtlStringCbPrintfW(
                detailText,
                sizeof(detailText),
                L"IopFsNotifyChangeQueueHead 私有链只读项；Node=0x%p，DriverObject=0x%p，NotificationRoutine=0x%p。",
                (PVOID)(ULONG_PTR)currentAddress,
                registration.driverObject,
                registration.notificationRoutine);
            kswordArkCallbackExtendedAddRow(
                builder,
                moduleCache,
                KSWORD_ARK_CALLBACK_ENUM_CLASS_FILE_SYSTEM,
                KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_FILESYSTEM_LIST,
                KSWORD_ARK_CALLBACK_ENUM_STATUS_OK,
                STATUS_SUCCESS,
                KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_FILE_SYSTEM_CHANGE,
                0UL,
                0UL,
                (ULONG64)(ULONG_PTR)registration.notificationRoutine,
                (ULONG64)(ULONG_PTR)registration.driverObject,
                currentAddress,
                0UL,
                nameText,
                detailText);
            ++addedCount;
        }

        if (nextAddress == currentAddress) {
            break;
        }
        currentAddress = nextAddress;
        ++index;
    }

    if (addedCount == 0UL) {
        kswordArkCallbackExtendedAddRow(
            builder,
            moduleCache,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_FILE_SYSTEM,
            KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_FILESYSTEM_LIST,
            KSWORD_ARK_CALLBACK_ENUM_STATUS_NOT_REGISTERED,
            STATUS_SUCCESS,
            KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_FILE_SYSTEM_CHANGE,
            0UL,
            0UL,
            0ULL,
            0ULL,
            listHeadAddress,
            0UL,
            L"IopFsNotifyChangeQueueHead empty",
            L"已定位文件系统注册变化链，但当前未发现可验证到已加载模块的回调。");
    }
}

static NTSTATUS
kswordArkCallbackExtendedLocatePairedPointerGlobal(
    _In_z_ PCWSTR routineName,
    _Out_ ULONG64* globalAddressOut
    )
/*++

Routine Description:

    Locate the single-linked global variable for 'read old head pointer then write back new head pointer'.

Arguments:

    RoutineName - Exported name of the routine.
    GlobalAddressOut - Address of the output global pointer variable.

Return Value:

    Returns STATUS_SUCCESS on success, or STATUS_NOT_FOUND if no match is found.

--*/
{
    UCHAR codeBytes[0x100];
    ULONG readOffset = 0UL;
    ULONG64 routineAddress = (ULONG64)(ULONG_PTR)
        kswordArkCallbackExtendedGetSystemRoutine(routineName);

    if (globalAddressOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *globalAddressOut = 0ULL;
    if (routineAddress == 0ULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    RtlZeroMemory(codeBytes, sizeof(codeBytes));
    if (!kswordArkCallbackEnumReadMemory(
            (const VOID*)(ULONG_PTR)routineAddress,
            codeBytes,
            sizeof(codeBytes))) {
        return STATUS_ACCESS_VIOLATION;
    }

    for (readOffset = 0UL; readOffset + 7UL <= sizeof(codeBytes); ++readOffset) {
        ULONG writeOffset = 0UL;
        ULONG64 readTarget = 0ULL;

        if (codeBytes[readOffset] != 0x48U ||
            codeBytes[readOffset + 1UL] != 0x8BU ||
            codeBytes[readOffset + 2UL] != 0x05U) {
            continue;
        }
        if (!kswordArkCallbackExtendedResolveRipRelative(
                routineAddress + readOffset,
                3UL,
                7UL,
                &readTarget)) {
            continue;
        }

        for (writeOffset = readOffset + 7UL;
            writeOffset + 7UL <= sizeof(codeBytes) &&
                writeOffset <= readOffset + 40UL;
            ++writeOffset) {
            ULONG64 writeTarget = 0ULL;

            if (codeBytes[writeOffset] != 0x48U ||
                codeBytes[writeOffset + 1UL] != 0x89U ||
                codeBytes[writeOffset + 2UL] != 0x1DU) {
                continue;
            }
            if (kswordArkCallbackExtendedResolveRipRelative(
                    routineAddress + writeOffset,
                    3UL,
                    7UL,
                    &writeTarget) &&
                writeTarget == readTarget) {
                *globalAddressOut = readTarget;
                return STATUS_SUCCESS;
            }
        }
    }

    return STATUS_NOT_FOUND;
}

static ULONG
kswordArkCallbackExtendedWalkLogonList(
    _Inout_ KswordArkCallbackEnumBuilder* builder,
    _Inout_ KswordArkCallbackModuleCache* moduleCache,
    _In_ ULONG64 globalAddress,
    _In_ BOOLEAN extendedList
    )
/*++

Routine Description:

    Traverse the linked list of Legacy or Ex logon session termination entries.

Arguments:

    Builder: Response builder.
    ModuleCache - Module cache.
    GlobalAddress - address of the single-linked list head pointer variable.
    ExtendedList - TRUE indicates the node contains Context.

Return Value:

    Return: Number of successfully verified callbacks.

--*/
{
    ULONG index = 0UL;
    ULONG addedCount = 0UL;
    ULONG64 currentAddress = 0ULL;

    if (!kswordArkCallbackExtendedReadPointer(
            globalAddress,
            &currentAddress)) {
        return 0UL;
    }

    while (currentAddress != 0ULL &&
        index < KSWORD_ARK_CALLBACK_SYSTEM_WALK_LIMIT) {
        ULONG64 nextAddress = 0ULL;
        ULONG64 callbackAddress = 0ULL;
        ULONG64 contextAddress = 0ULL;

        if (extendedList) {
            KswordArkCallbackLogonExRegistration registration;

            RtlZeroMemory(&registration, sizeof(registration));
            if (!kswordArkCallbackEnumReadMemory(
                    (const VOID*)(ULONG_PTR)currentAddress,
                    &registration,
                    sizeof(registration))) {
                break;
            }
            nextAddress = (ULONG64)(ULONG_PTR)registration.next;
            callbackAddress = (ULONG64)(ULONG_PTR)registration.callbackRoutine;
            contextAddress = (ULONG64)(ULONG_PTR)registration.callbackContext;
        }
        else {
            KswordArkCallbackLogonRegistration registration;

            RtlZeroMemory(&registration, sizeof(registration));
            if (!kswordArkCallbackEnumReadMemory(
                    (const VOID*)(ULONG_PTR)currentAddress,
                    &registration,
                    sizeof(registration))) {
                break;
            }
            nextAddress = (ULONG64)(ULONG_PTR)registration.next;
            callbackAddress = (ULONG64)(ULONG_PTR)registration.callbackRoutine;
        }

        if (callbackAddress != 0ULL &&
            kswordArkCallbackEnumIsKernelModuleAddress(
                moduleCache,
                callbackAddress)) {
            WCHAR nameText[KSWORD_ARK_CALLBACK_ENUM_NAME_CHARS];
            WCHAR detailText[KSWORD_ARK_CALLBACK_ENUM_DETAIL_CHARS];

            RtlZeroMemory(nameText, sizeof(nameText));
            RtlZeroMemory(detailText, sizeof(detailText));
            (VOID)RtlStringCbPrintfW(
                nameText,
                sizeof(nameText),
                extendedList
                    ? L"SeLogonSessionTerminatedEx[%lu]"
                    : L"SeLogonSessionTerminated[%lu]",
                (unsigned long)index);
            (VOID)RtlStringCbPrintfW(
                detailText,
                sizeof(detailText),
                extendedList
                    ? L"SeRegisterLogonSessionTerminatedRoutineEx 私有单链项；Node=0x%p，Function=0x%p，Context=0x%p。"
                    : L"SeRegisterLogonSessionTerminatedRoutine 私有单链项；Node=0x%p，Function=0x%p。",
                (PVOID)(ULONG_PTR)currentAddress,
                (PVOID)(ULONG_PTR)callbackAddress,
                (PVOID)(ULONG_PTR)contextAddress);
            kswordArkCallbackExtendedAddRow(
                builder,
                moduleCache,
                KSWORD_ARK_CALLBACK_ENUM_CLASS_LOGON_SESSION,
                KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_LOGON_LIST,
                KSWORD_ARK_CALLBACK_ENUM_STATUS_OK,
                STATUS_SUCCESS,
                extendedList
                    ? KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_LOGON_EX
                    : KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_LOGON_LEGACY,
                0UL,
                0UL,
                callbackAddress,
                contextAddress,
                currentAddress,
                0UL,
                nameText,
                detailText);
            ++addedCount;
        }

        if (nextAddress == currentAddress) {
            break;
        }
        currentAddress = nextAddress;
        ++index;
    }

    return addedCount;
}

static VOID
kswordArkCallbackExtendedAddLogonCallbacks(
    _Inout_ KswordArkCallbackEnumBuilder* builder,
    _Inout_ KswordArkCallbackModuleCache* moduleCache
    )
/*++

Routine Description:

    Locate and traverse the Legacy and Ex login session termination callback chains.

Arguments:

    Builder: Response builder.
    ModuleCache - Module cache.

Return Value:

    No return value.

--*/
{
    NTSTATUS legacyStatus = STATUS_SUCCESS;
    NTSTATUS extendedStatus = STATUS_SUCCESS;
    ULONG addedCount = 0UL;
    ULONG64 legacyGlobal = 0ULL;
    ULONG64 extendedGlobal = 0ULL;

    legacyStatus = kswordArkCallbackExtendedLocatePairedPointerGlobal(
        L"SeRegisterLogonSessionTerminatedRoutine",
        &legacyGlobal);
    if (NT_SUCCESS(legacyStatus)) {
        addedCount += kswordArkCallbackExtendedWalkLogonList(
            builder,
            moduleCache,
            legacyGlobal,
            FALSE);
    }

    extendedStatus = kswordArkCallbackExtendedLocatePairedPointerGlobal(
        L"SeRegisterLogonSessionTerminatedRoutineEx",
        &extendedGlobal);
    if (NT_SUCCESS(extendedStatus)) {
        addedCount += kswordArkCallbackExtendedWalkLogonList(
            builder,
            moduleCache,
            extendedGlobal,
            TRUE);
    }

    if (addedCount == 0UL) {
        const NTSTATUS kCombinedStatus = !NT_SUCCESS(legacyStatus)
            ? legacyStatus
            : (!NT_SUCCESS(extendedStatus) ? extendedStatus : STATUS_SUCCESS);
        kswordArkCallbackExtendedAddRow(
            builder,
            moduleCache,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_LOGON_SESSION,
            KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_LOGON_LIST,
            NT_SUCCESS(kCombinedStatus)
                ? KSWORD_ARK_CALLBACK_ENUM_STATUS_NOT_REGISTERED
                : KSWORD_ARK_CALLBACK_ENUM_STATUS_QUERY_FAILED,
            kCombinedStatus,
            KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_UNKNOWN,
            0UL,
            0UL,
            0ULL,
            0ULL,
            NT_SUCCESS(legacyStatus) ? legacyGlobal : extendedGlobal,
            0UL,
            L"Se logon-session callback lists",
            NT_SUCCESS(kCombinedStatus)
                ? L"已定位 Legacy/Ex 登录会话终止链，但当前没有可验证回调。"
                : L"未能从 SeRegisterLogonSessionTerminatedRoutine/Ex 公开入口定位回调链。");
    }
}

static NTSTATUS
kswordArkCallbackExtendedOpenObjectDirectory(
    _In_z_ PCWSTR directoryNameArg,
    _Out_ HANDLE* directoryHandleOut
    )
/*++

Routine Description:

    Open the \Driver or \FileSystem object directory.

Arguments:

    DirectoryName: Full directory path.
    DirectoryHandleOut - Output kernel handle.

Return Value:

    Returns the NTSTATUS from ZwOpenDirectoryObject.

--*/
{
    UNICODE_STRING directoryName;
    OBJECT_ATTRIBUTES objectAttributes;

    if (directoryNameArg == NULL || directoryHandleOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *directoryHandleOut = NULL;
    RtlInitUnicodeString(&directoryName, directoryNameArg);
    InitializeObjectAttributes(
        &objectAttributes,
        &directoryName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);
    return ZwOpenDirectoryObject(
        directoryHandleOut,
        DIRECTORY_QUERY,
        &objectAttributes);
}

static BOOLEAN
kswordArkCallbackExtendedBuildObjectName(
    _In_z_ PCWSTR directoryName,
    _In_ PCUNICODE_STRING leafName,
    _Out_writes_(destinationChars) PWCHAR destination,
    _In_ ULONG destinationChars
    )
/*++

Routine Description:

    Concatenate the object directory and leaf name.

Arguments:

    DirectoryName - Directory path.
    LeafName - Object leaf name.
    Destination - Output full path.
    DestinationChars - Output character capacity.

Return Value:

    Return TRUE on success; return FALSE if parameters are invalid or the string is out of bounds.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;

    if (directoryName == NULL ||
        leafName == NULL ||
        leafName->Buffer == NULL ||
        leafName->Length == 0U ||
        destination == NULL ||
        destinationChars == 0UL) {
        return FALSE;
    }

    destination[0] = L'\0';
    status = RtlStringCchPrintfW(
        destination,
        destinationChars,
        L"%ws\\",
        directoryName);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }
    status = RtlStringCchCatNW(
        destination,
        destinationChars,
        leafName->Buffer,
        leafName->Length / sizeof(WCHAR));
    return NT_SUCCESS(status);
}

static VOID
kswordArkCallbackExtendedAddDriverShutdownRows(
    _Inout_ KswordArkCallbackEnumBuilder* builder,
    _Inout_ KswordArkCallbackModuleCache* moduleCache,
    _In_ PDRIVER_OBJECT driverObject,
    _In_z_ PCWSTR driverName
    )
/*++

Routine Description:

    Enumerates the DO_SHUTDOWN_REGISTERED device objects of a DriverObject.

Arguments:

    Builder: Response builder.
    ModuleCache - Module cache.
    DriverObject - Driver object already referenced.
    DriverName - Full object name.

Return Value:

    No return value.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG index = 0UL;
    ULONG deviceCount = 0UL;
    ULONG actualCount = 0UL;
    PDEVICE_OBJECT* deviceObjects = NULL;

    if (driverObject == NULL || driverName == NULL) {
        return;
    }

    status = IoEnumerateDeviceObjectList(
        driverObject,
        NULL,
        0UL,
        &deviceCount);
    if (deviceCount == 0UL ||
        deviceCount > KSWORD_ARK_CALLBACK_SYSTEM_DEVICE_LIMIT) {
        return;
    }

    deviceObjects = (PDEVICE_OBJECT*)kswordArkAllocateNonPaged(
        (SIZE_T)deviceCount * sizeof(PDEVICE_OBJECT),
        KSWORD_ARK_CALLBACK_SYSTEM_TAG);
    if (deviceObjects == NULL) {
        return;
    }
    RtlZeroMemory(
        deviceObjects,
        (SIZE_T)deviceCount * sizeof(PDEVICE_OBJECT));

    status = IoEnumerateDeviceObjectList(
        driverObject,
        deviceObjects,
        deviceCount * sizeof(PDEVICE_OBJECT),
        &actualCount);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(deviceObjects, KSWORD_ARK_CALLBACK_SYSTEM_TAG);
        return;
    }
    if (actualCount > deviceCount) {
        actualCount = deviceCount;
    }

    for (index = 0UL; index < actualCount; ++index) {
        PDEVICE_OBJECT deviceObject = deviceObjects[index];

        if (deviceObject != NULL &&
            (deviceObject->Flags & DO_SHUTDOWN_REGISTERED) != 0UL &&
            driverObject->MajorFunction[IRP_MJ_SHUTDOWN] != NULL) {
            WCHAR nameText[KSWORD_ARK_CALLBACK_ENUM_NAME_CHARS];
            WCHAR detailText[KSWORD_ARK_CALLBACK_ENUM_DETAIL_CHARS];

            RtlZeroMemory(nameText, sizeof(nameText));
            RtlZeroMemory(detailText, sizeof(detailText));
            (VOID)RtlStringCbPrintfW(
                nameText,
                sizeof(nameText),
                L"%ws/Device[%lu]",
                driverName,
                (unsigned long)index);
            (VOID)RtlStringCbPrintfW(
                detailText,
                sizeof(detailText),
                L"IoRegisterShutdownNotification/LastChance 的公开 DeviceObject 标志证据；DriverObject=0x%p，DeviceObject=0x%p。公开结构不区分常规与 LastChance 队列。",
                driverObject,
                deviceObject);
            kswordArkCallbackExtendedAddRow(
                builder,
                moduleCache,
                KSWORD_ARK_CALLBACK_ENUM_CLASS_SHUTDOWN,
                KSWORD_ARK_CALLBACK_ENUM_SOURCE_DRIVER_OBJECT_SCAN,
                KSWORD_ARK_CALLBACK_ENUM_STATUS_OK,
                STATUS_SUCCESS,
                KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_SHUTDOWN,
                0UL,
                0UL,
                (ULONG64)(ULONG_PTR)driverObject->MajorFunction[IRP_MJ_SHUTDOWN],
                (ULONG64)(ULONG_PTR)driverObject,
                (ULONG64)(ULONG_PTR)deviceObject,
                0UL,
                nameText,
                detailText);
        }

        if (deviceObject != NULL) {
            ObDereferenceObject(deviceObject);
        }
    }

    ExFreePoolWithTag(deviceObjects, KSWORD_ARK_CALLBACK_SYSTEM_TAG);
}

static VOID
kswordArkCallbackExtendedScanShutdownDirectory(
    _Inout_ KswordArkCallbackEnumBuilder* builder,
    _Inout_ KswordArkCallbackModuleCache* moduleCache,
    _In_z_ PCWSTR directoryName
    )
/*++

Routine Description:

    Scan a driver object directory and check for Shutdown-registered devices.

Arguments:

    Builder: Response builder.
    ModuleCache - Module cache.
    DirectoryName - \Driver or \FileSystem.

Return Value:

    No return value.

--*/
{
    HANDLE directoryHandle = NULL;
    KswordArkCallbackSystemDirectoryInformation* entry = NULL;
    ULONG queryContext = 0UL;
    ULONG returnLength = 0UL;
    ULONG scannedEntries = 0UL;
    BOOLEAN restartScan = TRUE;
    NTSTATUS status = STATUS_SUCCESS;

    status = kswordArkCallbackExtendedOpenObjectDirectory(
        directoryName,
        &directoryHandle);
    if (!NT_SUCCESS(status)) {
        return;
    }
    if (IoDriverObjectType == NULL || *IoDriverObjectType == NULL) {
        ZwClose(directoryHandle);
        return;
    }

    entry = (KswordArkCallbackSystemDirectoryInformation*)kswordArkAllocateNonPaged(
        KSWORD_ARK_CALLBACK_SYSTEM_DIRECTORY_BYTES,
        KSWORD_ARK_CALLBACK_SYSTEM_TAG);
    if (entry == NULL) {
        ZwClose(directoryHandle);
        return;
    }

    while (scannedEntries < KSWORD_ARK_CALLBACK_SYSTEM_DIRECTORY_LIMIT) {
        WCHAR objectName[KSWORD_ARK_CALLBACK_ENUM_MODULE_PATH_CHARS];
        UNICODE_STRING objectNameString;
        PDRIVER_OBJECT driverObject = NULL;

        RtlZeroMemory(entry, KSWORD_ARK_CALLBACK_SYSTEM_DIRECTORY_BYTES);
        status = ZwQueryDirectoryObject(
            directoryHandle,
            entry,
            KSWORD_ARK_CALLBACK_SYSTEM_DIRECTORY_BYTES,
            TRUE,
            restartScan,
            &queryContext,
            &returnLength);
        restartScan = FALSE;
        if (status == STATUS_NO_MORE_ENTRIES) {
            break;
        }
        if (!NT_SUCCESS(status)) {
            break;
        }

        ++scannedEntries;
        RtlZeroMemory(objectName, sizeof(objectName));
        if (!kswordArkCallbackExtendedBuildObjectName(
                directoryName,
                &entry->name,
                objectName,
                RTL_NUMBER_OF(objectName))) {
            continue;
        }

        RtlInitUnicodeString(&objectNameString, objectName);
        status = ObReferenceObjectByName(
            &objectNameString,
            OBJ_CASE_INSENSITIVE,
            NULL,
            0,
            *IoDriverObjectType,
            KernelMode,
            NULL,
            (PVOID*)&driverObject);
        if (!NT_SUCCESS(status) || driverObject == NULL) {
            continue;
        }

        kswordArkCallbackExtendedAddDriverShutdownRows(
            builder,
            moduleCache,
            driverObject,
            objectName);
        ObDereferenceObject(driverObject);
    }

    ExFreePoolWithTag(entry, KSWORD_ARK_CALLBACK_SYSTEM_TAG);
    ZwClose(directoryHandle);
}

static VOID
kswordArkCallbackExtendedAddShutdownCallbacks(
    _Inout_ KswordArkCallbackEnumBuilder* builder,
    _Inout_ KswordArkCallbackModuleCache* moduleCache
    )
/*++

Routine Description:

    Scan the Shutdown registered devices in the \Driver and \FileSystem directories.

Arguments:

    Builder: Response builder.
    ModuleCache - Module cache.

Return Value:

    No return value.

--*/
{
    kswordArkCallbackExtendedScanShutdownDirectory(
        builder,
        moduleCache,
        L"\\Driver");
    kswordArkCallbackExtendedScanShutdownDirectory(
        builder,
        moduleCache,
        L"\\FileSystem");
}

typedef struct KswordArkLegacyFsClassInitMatch
{
    ULONG extensionOffset;
    ULONG64 classInitAddress;
    FS_FILTER_CALLBACKS callbacks;
    ULONG callbackCount;
} KswordArkLegacyFsClassInitMatch;

static const PCWSTR kGKswordArkLegacyFsCallbackNames[] = {
    L"PreAcquireForSectionSynchronization",
    L"PostAcquireForSectionSynchronization",
    L"PreReleaseForSectionSynchronization",
    L"PostReleaseForSectionSynchronization",
    L"PreAcquireForCcFlush",
    L"PostAcquireForCcFlush",
    L"PreReleaseForCcFlush",
    L"PostReleaseForCcFlush",
    L"PreAcquireForModifiedPageWriter",
    L"PostAcquireForModifiedPageWriter",
    L"PreReleaseForModifiedPageWriter",
    L"PostReleaseForModifiedPageWriter",
    L"PreQueryOpen",
    L"PostQueryOpen"
};

static VOID
kswordArkCallbackLegacyFsBuildSlots(
    _In_ const FS_FILTER_CALLBACKS* callbacks,
    _Out_writes_(14) PVOID* slots
    )
{
    if (callbacks == NULL || slots == NULL) {
        return;
    }

    slots[0] = (PVOID)callbacks->PreAcquireForSectionSynchronization;
    slots[1] = (PVOID)callbacks->PostAcquireForSectionSynchronization;
    slots[2] = (PVOID)callbacks->PreReleaseForSectionSynchronization;
    slots[3] = (PVOID)callbacks->PostReleaseForSectionSynchronization;
    slots[4] = (PVOID)callbacks->PreAcquireForCcFlush;
    slots[5] = (PVOID)callbacks->PostAcquireForCcFlush;
    slots[6] = (PVOID)callbacks->PreReleaseForCcFlush;
    slots[7] = (PVOID)callbacks->PostReleaseForCcFlush;
    slots[8] = (PVOID)callbacks->PreAcquireForModifiedPageWriter;
    slots[9] = (PVOID)callbacks->PostAcquireForModifiedPageWriter;
    slots[10] = (PVOID)callbacks->PreReleaseForModifiedPageWriter;
    slots[11] = (PVOID)callbacks->PostReleaseForModifiedPageWriter;
    slots[12] = (PVOID)callbacks->PreQueryOpen;
    slots[13] = (PVOID)callbacks->PostQueryOpen;
}

static BOOLEAN
kswordArkCallbackLegacyFsValidateCandidate(
    _In_ ULONG64 candidateAddress,
    _Out_ FS_FILTER_CALLBACKS* callbacksOut,
    _Out_ ULONG* callbackCountOut
    )
{
    FS_FILTER_CALLBACKS callbacks;
    PVOID slots[14];
    ULONG index = 0UL;
    ULONG callbackCount = 0UL;

    if (candidateAddress == 0ULL ||
        callbacksOut == NULL ||
        callbackCountOut == NULL ||
        candidateAddress < (ULONG64)(ULONG_PTR)MmUserProbeAddress ||
        (candidateAddress & (sizeof(PVOID) - 1ULL)) != 0ULL) {
        return FALSE;
    }

    RtlZeroMemory(&callbacks, sizeof(callbacks));
    RtlZeroMemory(slots, sizeof(slots));
    if (!kswordArkCallbackEnumReadMemory(
            (const VOID*)(ULONG_PTR)candidateAddress,
            &callbacks,
            sizeof(callbacks)) ||
        callbacks.SizeOfFsFilterCallbacks != (ULONG)sizeof(FS_FILTER_CALLBACKS) ||
        callbacks.Reserved != 0UL) {
        return FALSE;
    }

    kswordArkCallbackLegacyFsBuildSlots(&callbacks, slots);
    for (index = 0UL; index < RTL_NUMBER_OF(slots); ++index) {
        if (slots[index] != NULL) {
            callbackCount += 1UL;
        }
    }

    // Note: Candidate signatures rely solely on the structure's own public version evidence (Size, Reserved) and at least one
    // registered slot. Whether a slot address resides in a module, whether the module is resolvable, and whether the owner
    // matches are all per-slot diagnostics; they cannot retroactively invalidate an already established ClassInitData candidate.
    if (callbackCount == 0UL) {
        return FALSE;
    }

    *callbacksOut = callbacks;
    *callbackCountOut = callbackCount;
    return TRUE;
}

static NTSTATUS
kswordArkCallbackLegacyFsLocateClassInitData(
    _In_ PDRIVER_OBJECT driverObject,
    _Out_ KswordArkLegacyFsClassInitMatch* matchOut
    )
{
    DRIVER_OBJECT driverView;
    ULONG offset = 0UL;
    ULONG matchCount = 0UL;
    const ULONG kStartOffset = (ULONG)sizeof(DRIVER_EXTENSION);
    const ULONG kEndOffset = kStartOffset + 0x60UL;

    if (driverObject == NULL || matchOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(matchOut, sizeof(*matchOut));
    RtlZeroMemory(&driverView, sizeof(driverView));
    if (!kswordArkCallbackEnumReadMemory(driverObject, &driverView, sizeof(driverView)) ||
        driverView.DriverExtension == NULL ||
        driverView.DriverStart == NULL ||
        driverView.DriverSize == 0UL) {
        return STATUS_DATA_ERROR;
    }

    // Note: After exposing DRIVER_EXTENSION, only check the 0x60-byte aligned pointer slot.
    // Each candidate forms independent structure/version evidence solely based on the full FS_FILTER_CALLBACKS
    // size, Reserved, and non-empty slot count; each pre/post address and owner are then determined item-by-item.
    for (offset = kStartOffset; offset < kEndOffset; offset += (ULONG)sizeof(PVOID)) {
        ULONG64 candidateAddress = 0ULL;
        FS_FILTER_CALLBACKS callbacks;
        ULONG callbackCount = 0UL;

        if (!kswordArkCallbackEnumReadMemory(
                (const UCHAR*)driverView.DriverExtension + offset,
                &candidateAddress,
                sizeof(candidateAddress)) ||
            candidateAddress == 0ULL) {
            continue;
        }
        RtlZeroMemory(&callbacks, sizeof(callbacks));
        if (!kswordArkCallbackLegacyFsValidateCandidate(
                candidateAddress,
                &callbacks,
                &callbackCount)) {
            continue;
        }

        matchCount += 1UL;
        if (matchCount == 1UL) {
            matchOut->extensionOffset = offset;
            matchOut->classInitAddress = candidateAddress;
            matchOut->callbacks = callbacks;
            matchOut->callbackCount = callbackCount;
        }
    }

    if (matchCount == 0UL) {
        return STATUS_NOT_FOUND;
    }
    if (matchCount != 1UL) {
        RtlZeroMemory(matchOut, sizeof(*matchOut));
        return STATUS_OBJECT_NAME_COLLISION;
    }
    return STATUS_SUCCESS;
}

static BOOLEAN
kswordArkCallbackLegacyFsCopyDriverName(
    _Out_writes_(destinationChars) PWCHAR destination,
    _In_ ULONG destinationChars,
    _In_ const UNICODE_STRING* source
    )
{
    const USHORT kHardLimitBytes =
        (USHORT)(KSWORD_ARK_CALLBACK_ENUM_NAME_CHARS * sizeof(WCHAR));
    USHORT copyBytes = 0U;

    if (destination == NULL || destinationChars < 2UL) {
        return FALSE;
    }
    destination[0] = L'\0';
    if (source == NULL ||
        source->Buffer == NULL ||
        source->Length == 0U ||
        source->MaximumLength == 0U ||
        source->Length > source->MaximumLength ||
        (ULONG_PTR)source->Buffer < (ULONG_PTR)MmUserProbeAddress ||
        ((ULONG_PTR)source->Buffer & (sizeof(WCHAR) - 1U)) != 0U ||
        (source->Length & (sizeof(WCHAR) - 1U)) != 0U ||
        (source->MaximumLength & (sizeof(WCHAR) - 1U)) != 0U ||
        source->Length > kHardLimitBytes ||
        source->MaximumLength > kHardLimitBytes) {
        return FALSE;
    }

    copyBytes = source->Length;
    if (copyBytes > (USHORT)((destinationChars - 1UL) * sizeof(WCHAR))) {
        copyBytes = (USHORT)((destinationChars - 1UL) * sizeof(WCHAR));
    }
    if (copyBytes == 0U ||
        !kswordArkCallbackEnumReadMemory(
            source->Buffer,
            destination,
            copyBytes)) {
        destination[0] = L'\0';
        return FALSE;
    }

    destination[copyBytes / sizeof(WCHAR)] = L'\0';
    return TRUE;
}

static VOID
kswordArkCallbackLegacyFsSetDetail(
    _Inout_ KswordArkCallbackEnumBuilder* builder,
    _In_ ULONG detailCode,
    _In_ ULONG64 arg0,
    _In_ ULONG64 arg1,
    _In_ ULONG64 arg2,
    _In_ ULONG64 arg3
    )
{
    KSWORD_ARK_CALLBACK_ENUM_ENTRY* entry = NULL;

    if (builder == NULL || detailCode == KSWORD_ARK_CALLBACK_ENUM_DETAIL_NONE) {
        return;
    }
    entry = builder->pendingEntry;
    if (entry == NULL) {
        return;
    }

    entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_DETAIL_ARGS;
    entry->detailCode = detailCode;
    entry->detailArgs[0] = arg0;
    entry->detailArgs[1] = arg1;
    entry->detailArgs[2] = arg2;
    entry->detailArgs[3] = arg3;
}

static VOID
kswordArkCallbackLegacyFsAddDriver(
    _Inout_ KswordArkCallbackEnumBuilder* builder,
    _Inout_ KswordArkCallbackModuleCache* moduleCache,
    _In_ PDRIVER_OBJECT driverObject
    )
{
    DRIVER_OBJECT driverView;
    KswordArkLegacyFsClassInitMatch match;
    PVOID slots[14];
    WCHAR driverName[KSWORD_ARK_CALLBACK_ENUM_NAME_CHARS];
    WCHAR nameText[KSWORD_ARK_CALLBACK_ENUM_NAME_CHARS];
    NTSTATUS status = STATUS_SUCCESS;
    ULONG index = 0UL;

    RtlZeroMemory(&driverView, sizeof(driverView));
    RtlZeroMemory(&match, sizeof(match));
    RtlZeroMemory(slots, sizeof(slots));
    RtlZeroMemory(driverName, sizeof(driverName));
    if (!kswordArkCallbackEnumReadMemory(driverObject, &driverView, sizeof(driverView))) {
        return;
    }
    (VOID)kswordArkCallbackLegacyFsCopyDriverName(
        driverName,
        RTL_NUMBER_OF(driverName),
        &driverView.DriverName);
    if (driverName[0] == L'\0') {
        kswordArkCallbackEnumCopyWide(
            driverName,
            RTL_NUMBER_OF(driverName),
            L"<legacy-fs-filter>");
    }

    status = kswordArkCallbackLegacyFsLocateClassInitData(
        driverObject,
        &match);
    if (!NT_SUCCESS(status)) {
        kswordArkCallbackExtendedAddRow(
            builder,
            moduleCache,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_LEGACY_FS_FILTER,
            KSWORD_ARK_CALLBACK_ENUM_SOURCE_LEGACY_FS_PUBLIC_AND_STRUCTURAL,
            status == STATUS_NOT_FOUND
                ? KSWORD_ARK_CALLBACK_ENUM_STATUS_NOT_REGISTERED
                : KSWORD_ARK_CALLBACK_ENUM_STATUS_QUERY_FAILED,
            status,
            KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_LEGACY_FS_CLASS_INIT,
            0UL,
            0UL,
            0ULL,
            (ULONG64)(ULONG_PTR)driverObject,
            0ULL,
            0UL,
            driverName,
            NULL);
        kswordArkCallbackLegacyFsSetDetail(
            builder,
            status == STATUS_OBJECT_NAME_COLLISION
                ? KSWORD_ARK_CALLBACK_ENUM_DETAIL_LEGACY_FS_CLASS_INIT_AMBIGUOUS
                : KSWORD_ARK_CALLBACK_ENUM_DETAIL_LEGACY_FS_CLASS_INIT_NOT_FOUND,
            (ULONG64)(ULONG_PTR)driverObject,
            (ULONG64)sizeof(DRIVER_EXTENSION),
            (ULONG64)sizeof(DRIVER_EXTENSION) + 0x60ULL,
            (ULONG64)(ULONG)status);
        return;
    }

    RtlZeroMemory(nameText, sizeof(nameText));
    (VOID)RtlStringCchPrintfW(
        nameText,
        RTL_NUMBER_OF(nameText),
        L"%ws!ClassInitData",
        driverName);
    kswordArkCallbackExtendedAddRow(
        builder,
        moduleCache,
        KSWORD_ARK_CALLBACK_ENUM_CLASS_LEGACY_FS_FILTER,
        KSWORD_ARK_CALLBACK_ENUM_SOURCE_LEGACY_FS_PUBLIC_AND_STRUCTURAL,
        KSWORD_ARK_CALLBACK_ENUM_STATUS_OK,
        STATUS_SUCCESS,
        KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_LEGACY_FS_CLASS_INIT,
        0UL,
        0UL,
        0ULL,
        (ULONG64)(ULONG_PTR)driverObject,
        match.classInitAddress,
        KSWORD_ARK_CALLBACK_ENUM_FIELD_CLASS_INIT_DATA_VALIDATED,
        nameText,
        NULL);
    kswordArkCallbackLegacyFsSetDetail(
        builder,
        KSWORD_ARK_CALLBACK_ENUM_DETAIL_LEGACY_FS_CLASS_INIT_VALIDATED,
        match.classInitAddress,
        match.extensionOffset,
        match.callbacks.SizeOfFsFilterCallbacks,
        match.callbackCount);

    kswordArkCallbackLegacyFsBuildSlots(&match.callbacks, slots);
    for (index = 0UL; index < RTL_NUMBER_OF(slots); ++index) {
        WCHAR ownerModulePath[KSWORD_ARK_CALLBACK_ENUM_MODULE_PATH_CHARS];
        ULONG64 ownerModuleBase = 0ULL;
        ULONG ownerModuleSize = 0UL;
        NTSTATUS ownerStatus = STATUS_SUCCESS;
        BOOLEAN ownerMatched = FALSE;
        ULONG rowStatus = KSWORD_ARK_CALLBACK_ENUM_STATUS_UNKNOWN;
        NTSTATUS rowLastStatus = STATUS_NOT_FOUND;
        ULONG fieldFlags = 0UL;
        const ULONG kPairBase = index & ~1UL;
        ULONG64 pairEvidence = 0ULL;

        if (slots[index] == NULL) {
            continue;
        }

        RtlZeroMemory(ownerModulePath, sizeof(ownerModulePath));
        ownerStatus = kswordArkCallbackEnumResolveModuleByAddressCached(
            moduleCache,
            (ULONG64)(ULONG_PTR)slots[index],
            ownerModulePath,
            RTL_NUMBER_OF(ownerModulePath),
            &ownerModuleBase,
            &ownerModuleSize);
        if (NT_SUCCESS(ownerStatus)) {
            ownerMatched =
                ownerModuleBase == (ULONG64)(ULONG_PTR)driverView.DriverStart;
            if (ownerMatched) {
                fieldFlags |=
                    KSWORD_ARK_CALLBACK_ENUM_FIELD_CALLBACK_OWNER_MATCH;
                rowStatus = KSWORD_ARK_CALLBACK_ENUM_STATUS_OK;
                rowLastStatus = STATUS_SUCCESS;
            }
            else {
                rowStatus = KSWORD_ARK_CALLBACK_ENUM_STATUS_SUSPICIOUS;
                rowLastStatus = STATUS_OBJECT_TYPE_MISMATCH;
            }
        }
        else {
            rowLastStatus = ownerStatus;
        }

        if (slots[kPairBase] != NULL && slots[kPairBase + 1UL] != NULL) {
            fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_PRE_POST_PAIR;
        }
        pairEvidence = (ULONG64)(index / 2UL);
        if ((fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_PRE_POST_PAIR) != 0UL) {
            pairEvidence |= 1ULL << 32;
        }
        RtlZeroMemory(nameText, sizeof(nameText));
        (VOID)RtlStringCchPrintfW(
            nameText,
            RTL_NUMBER_OF(nameText),
            L"%ws!%ws",
            driverName,
            kGKswordArkLegacyFsCallbackNames[index]);
        kswordArkCallbackExtendedAddRow(
            builder,
            moduleCache,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_LEGACY_FS_FILTER,
            KSWORD_ARK_CALLBACK_ENUM_SOURCE_LEGACY_FS_PUBLIC_AND_STRUCTURAL,
            rowStatus,
            rowLastStatus,
            (index & 1UL) == 0UL
                ? KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_LEGACY_FS_PRE
                : KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_LEGACY_FS_POST,
            1UL << (index / 2UL),
            0UL,
            (ULONG64)(ULONG_PTR)slots[index],
            (ULONG64)(ULONG_PTR)driverObject,
            match.classInitAddress,
            fieldFlags,
            nameText,
            NULL);
        kswordArkCallbackLegacyFsSetDetail(
            builder,
            ownerMatched
                ? KSWORD_ARK_CALLBACK_ENUM_DETAIL_LEGACY_FS_OWNER_MATCH
                : (NT_SUCCESS(ownerStatus)
                    ? KSWORD_ARK_CALLBACK_ENUM_DETAIL_LEGACY_FS_OWNER_MISMATCH
                    : KSWORD_ARK_CALLBACK_ENUM_DETAIL_LEGACY_FS_OWNER_UNRESOLVED),
            match.classInitAddress,
            match.extensionOffset,
            pairEvidence,
            (ULONG64)(ULONG_PTR)driverView.DriverStart);
        UNREFERENCED_PARAMETER(ownerModuleSize);
    }
}

static VOID
kswordArkCallbackExtendedAddLegacyFsFilterCallbacks(
    _Inout_ KswordArkCallbackEnumBuilder* builder,
    _Inout_ KswordArkCallbackModuleCache* moduleCache
    )
{
    PDRIVER_OBJECT* driverObjects = NULL;
    ULONG actualCount = 0UL;
    ULONG allocatedCount = 0UL;
    ULONG index = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    status = IoEnumerateRegisteredFiltersList(NULL, 0UL, &actualCount);
    if (actualCount == 0UL) {
        kswordArkCallbackExtendedAddRow(
            builder,
            moduleCache,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_LEGACY_FS_FILTER,
            KSWORD_ARK_CALLBACK_ENUM_SOURCE_LEGACY_FS_PUBLIC_AND_STRUCTURAL,
            NT_SUCCESS(status)
                ? KSWORD_ARK_CALLBACK_ENUM_STATUS_NOT_REGISTERED
                : KSWORD_ARK_CALLBACK_ENUM_STATUS_QUERY_FAILED,
            status,
            KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_LEGACY_FS_CLASS_INIT,
            0UL, 0UL, 0ULL, 0ULL, 0ULL, 0UL,
            L"IoEnumerateRegisteredFiltersList",
            NULL);
        kswordArkCallbackLegacyFsSetDetail(
            builder,
            KSWORD_ARK_CALLBACK_ENUM_DETAIL_LEGACY_FS_PUBLIC_EMPTY,
            (ULONG64)(ULONG)status,
            0ULL,
            0ULL,
            0ULL);
        return;
    }
    if (actualCount > KSWORD_ARK_CALLBACK_SYSTEM_WALK_LIMIT) {
        kswordArkCallbackExtendedAddRow(
            builder,
            moduleCache,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_LEGACY_FS_FILTER,
            KSWORD_ARK_CALLBACK_ENUM_SOURCE_LEGACY_FS_PUBLIC_AND_STRUCTURAL,
            KSWORD_ARK_CALLBACK_ENUM_STATUS_BUFFER_TRUNCATED,
            STATUS_BUFFER_OVERFLOW,
            KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_LEGACY_FS_CLASS_INIT,
            0UL, 0UL, 0ULL, 0ULL, 0ULL, 0UL,
            L"IoEnumerateRegisteredFiltersList",
            NULL);
        kswordArkCallbackLegacyFsSetDetail(
            builder,
            KSWORD_ARK_CALLBACK_ENUM_DETAIL_LEGACY_FS_COUNT_LIMIT,
            actualCount,
            KSWORD_ARK_CALLBACK_SYSTEM_WALK_LIMIT,
            0ULL,
            0ULL);
        return;
    }

#pragma warning(push)
#pragma warning(disable:4996)
    allocatedCount = actualCount;
    driverObjects = (PDRIVER_OBJECT*)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        (SIZE_T)allocatedCount * sizeof(PDRIVER_OBJECT),
        KSWORD_ARK_CALLBACK_SYSTEM_TAG);
#pragma warning(pop)
    if (driverObjects == NULL) {
        kswordArkCallbackExtendedAddRow(
            builder,
            moduleCache,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_LEGACY_FS_FILTER,
            KSWORD_ARK_CALLBACK_ENUM_SOURCE_LEGACY_FS_PUBLIC_AND_STRUCTURAL,
            KSWORD_ARK_CALLBACK_ENUM_STATUS_QUERY_FAILED,
            STATUS_INSUFFICIENT_RESOURCES,
            KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_LEGACY_FS_CLASS_INIT,
            0UL, 0UL, 0ULL, 0ULL, 0ULL, 0UL,
            L"IoEnumerateRegisteredFiltersList",
            NULL);
        kswordArkCallbackLegacyFsSetDetail(
            builder,
            KSWORD_ARK_CALLBACK_ENUM_DETAIL_LEGACY_FS_PUBLIC_ENUM_FAILED,
            (ULONG64)(ULONG)STATUS_INSUFFICIENT_RESOURCES,
            actualCount,
            allocatedCount,
            0ULL);
        return;
    }
    RtlZeroMemory(driverObjects, (SIZE_T)allocatedCount * sizeof(PDRIVER_OBJECT));
    status = IoEnumerateRegisteredFiltersList(
        driverObjects,
        allocatedCount * sizeof(PDRIVER_OBJECT),
        &actualCount);
    if (NT_SUCCESS(status) && actualCount <= allocatedCount) {
        for (index = 0UL; index < actualCount; ++index) {
            if (driverObjects[index] != NULL) {
                kswordArkCallbackLegacyFsAddDriver(
                    builder,
                    moduleCache,
                    driverObjects[index]);
            }
        }
    }
    else {
        kswordArkCallbackExtendedAddRow(
            builder,
            moduleCache,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_LEGACY_FS_FILTER,
            KSWORD_ARK_CALLBACK_ENUM_SOURCE_LEGACY_FS_PUBLIC_AND_STRUCTURAL,
            KSWORD_ARK_CALLBACK_ENUM_STATUS_QUERY_FAILED,
            status,
            KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_LEGACY_FS_CLASS_INIT,
            0UL, 0UL, 0ULL, 0ULL, 0ULL, 0UL,
            L"IoEnumerateRegisteredFiltersList",
            NULL);
        kswordArkCallbackLegacyFsSetDetail(
            builder,
            KSWORD_ARK_CALLBACK_ENUM_DETAIL_LEGACY_FS_PUBLIC_ENUM_FAILED,
            (ULONG64)(ULONG)status,
            actualCount,
            allocatedCount,
            0ULL);
    }

    // Note: IoEnumerateRegisteredFiltersList increments the reference count for each returned object; regardless
    // of whether subsequent structure parsing succeeds, each must be released before the current snapshot ends.
    for (index = 0UL; index < allocatedCount; ++index) {
        if (driverObjects[index] != NULL) {
            ObDereferenceObject(driverObjects[index]);
        }
    }
    ExFreePoolWithTag(driverObjects, KSWORD_ARK_CALLBACK_SYSTEM_TAG);
}

VOID
kswordArkCallbackExtendedAddSystemCallbacks(
    _Inout_ KswordArkCallbackEnumBuilder* builder
    )
/*++

Routine Description:

    Aggregate the three missing callbacks: FS, LogonSession, and Shutdown.

Arguments:

    Builder: Response builder.

Return Value:

    No return value.

--*/
{
    KswordArkCallbackModuleCache moduleCache;

    if (builder == NULL) {
        return;
    }

    kswordArkCallbackEnumInitModuleCache(&moduleCache);
    if (!NT_SUCCESS(kswordArkCallbackEnumEnsureModuleCache(&moduleCache))) {
        kswordArkCallbackEnumFreeModuleCache(&moduleCache);
        return;
    }

    kswordArkCallbackExtendedAddFsRegistrationCallbacks(builder, &moduleCache);
    kswordArkCallbackExtendedAddLegacyFsFilterCallbacks(builder, &moduleCache);
    kswordArkCallbackExtendedAddLogonCallbacks(builder, &moduleCache);
    kswordArkCallbackExtendedAddShutdownCallbacks(builder, &moduleCache);
    kswordArkCallbackEnumFreeModuleCache(&moduleCache);
}
