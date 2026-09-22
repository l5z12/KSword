/*++

Module Name:

    callback_extended_object.c

Abstract:

    Enum naming for CallbackObject registration items and Image Verification callback objects.

Environment:

    Kernel-mode Driver Framework

--*/

#include "callback_extended_internal.h"
#include "callback_extended_kernel.h"

#define KSWORD_ARK_CALLBACK_OBJECT_DIRECTORY_BYTES (16UL * 1024UL)
#define KSWORD_ARK_CALLBACK_OBJECT_DIRECTORY_LIMIT 4096UL
#define KSWORD_ARK_CALLBACK_OBJECT_REGISTRATION_LIMIT 512UL
#define KSWORD_ARK_CALLBACK_OBJECT_CODE_SCAN_BYTES 0x80UL
#define KSWORD_ARK_CALLBACK_OBJECT_TAG 'oCbK'
#define KSWORD_ARK_CALLBACK_OBJECT_SIGNATURE 0x6C6C6143UL

#ifndef DIRECTORY_QUERY
#define DIRECTORY_QUERY 0x0001
#endif

#ifndef STATUS_NO_MORE_ENTRIES
#define STATUS_NO_MORE_ENTRIES ((NTSTATUS)0x8000001AL)
#endif

typedef struct KswordArkCallbackObjectDirectoryInformation
{
    UNICODE_STRING name;
    UNICODE_STRING typeName;
} KswordArkCallbackObjectDirectoryInformation;

typedef struct KswordArkCallbackObjectRegistration
{
    LIST_ENTRY link;
    PVOID callbackObject;
    PVOID callbackFunction;
    PVOID callbackContext;
} KswordArkCallbackObjectRegistration;

typedef struct KswordArkCallbackObjectSnapshot
{
    ULONG traversalIndex;
    ULONG64 registrationAddress;
    ULONG64 callbackFunction;
    ULONG64 callbackContext;
} KswordArkCallbackObjectSnapshot;

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

static NTSTATUS
kswordArkCallbackExtendedOpenCallbackDirectory(
    _Out_ HANDLE* directoryHandleOut
    )
/*++

Routine Description:

    Open the \Callback object directory.

Arguments:

    DirectoryHandleOut - Output kernel handle.

Return Value:

    Returns the NTSTATUS from ZwOpenDirectoryObject.

--*/
{
    UNICODE_STRING directoryName;
    OBJECT_ATTRIBUTES objectAttributes;

    if (directoryHandleOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *directoryHandleOut = NULL;
    RtlInitUnicodeString(&directoryName, L"\\Callback");
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
kswordArkCallbackExtendedBuildCallbackObjectName(
    _In_ PCUNICODE_STRING leafName,
    _Out_writes_(destinationChars) PWCHAR destination,
    _In_ ULONG destinationChars
    )
/*++

Routine Description:

    Concatenate the \Callback\ leaf name.

Arguments:

    LeafName - The leaf name returned by the object directory.
    Destination - Output full NT object path.
    DestinationChars - Number of output buffer characters.

Return Value:

    Return TRUE on success; return FALSE if parameters are invalid or the string is out of bounds.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;

    if (leafName == NULL ||
        leafName->Buffer == NULL ||
        leafName->Length == 0U ||
        destination == NULL ||
        destinationChars == 0UL) {
        return FALSE;
    }

    destination[0] = L'\0';
    status = RtlStringCchCopyW(
        destination,
        destinationChars,
        L"\\Callback\\");
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

static ULONG
kswordArkCallbackExtendedEnumerateCallbackObject(
    _Inout_ KswordArkCallbackEnumBuilder* builder,
    _Inout_ KswordArkCallbackModuleCache* moduleCache,
    _In_ ULONG64 callbackObjectAddress,
    _In_ ULONG callbackClass,
    _In_ ULONG source,
    _In_ ULONG registrationType,
    _In_z_ PCWSTR objectName
    )
/*++

Routine Description:

    Traverse the registration chain inside a CallbackObject. Note: The current structure is restored from the object layout exposed by
    the ExRegisterCallback entry point; it holds the object's spinlock to copy scalar snapshots, preventing concurrent unregistration
    and node release, and completes module checks, string formatting, and response construction only after releasing the spinlock.

Arguments:

    Builder: Response builder.
    ModuleCache - Module cache.
    CallbackObjectAddress: Address of the CallbackObject body.
    CallbackClass - General or Image Verification category.
    Source - Enumeration source.
    RegistrationType - Registered sub-type.
    ObjectName - Display name.

Return Value:

    Returns the count of registered nodes that passed validation.

--*/
{
    ULONG index = 0UL;
    ULONG addedCount = 0UL;
    ULONG snapshotCount = 0UL;
    ULONG snapshotIndex = 0UL;
    ULONG objectSignature = 0UL;
    ULONG64 listHeadAddress = 0ULL;
    ULONG64 currentAddress = 0ULL;
    LIST_ENTRY listHead;
    PKSPIN_LOCK objectLock = NULL;
    KIRQL oldIrql = PASSIVE_LEVEL;
    KswordArkCallbackObjectSnapshot* snapshots = NULL;

    // Validate the caller-provided response builder, module cache, object address, and display name.
    if (builder == NULL ||
        moduleCache == NULL ||
        callbackObjectAddress == 0ULL ||
        objectName == NULL) {
        return 0UL;
    }
    // Verify the object signature before acquiring a private lock, to avoid treating an unrelated address as a CallbackObject.
    if (!kswordArkCallbackEnumReadMemory(
            (const VOID*)(ULONG_PTR)callbackObjectAddress,
            &objectSignature,
            sizeof(objectSignature)) ||
        objectSignature != KSWORD_ARK_CALLBACK_OBJECT_SIGNATURE) {
        return 0UL;
    }

    // Calculate the registered list head address; on x64, the CALLBACK_OBJECT lock is at +0x08 and the list is at +0x10.
    listHeadAddress = callbackObjectAddress + (2ULL * sizeof(ULONG_PTR));
    // Allocate non-paged snapshots before entering the spinlock; perform no memory allocation or string processing inside the lock.
    snapshots = (KswordArkCallbackObjectSnapshot*)kswordArkAllocateNonPaged(
        sizeof(*snapshots) * KSWORD_ARK_CALLBACK_OBJECT_REGISTRATION_LIMIT,
        KSWORD_ARK_CALLBACK_OBJECT_TAG);
    // Safely abandon the object on out-of-memory to avoid entering a failure recovery path while holding a lock.
    if (snapshots == NULL) {
        return 0UL;
    }
    // Zero out the snapshots array to ensure no uninitialized fields are exposed in any early-exit path.
    RtlZeroMemory(
        snapshots,
        sizeof(*snapshots) * KSWORD_ARK_CALLBACK_OBJECT_REGISTRATION_LIMIT);

    // The +0x08 field of CALLBACK_OBJECT is protected as a KSPIN_LOCK by ExRegisterCallback.
    objectLock = (PKSPIN_LOCK)(ULONG_PTR)(callbackObjectAddress + sizeof(ULONG_PTR));
    // Acquire the object spin lock and save the original IRQL to prevent concurrent unregistration and release of the current registration node.
    KeAcquireSpinLock(objectLock, &oldIrql);
    // Read the list head within the lock to ensure the first node originates from the same consistency window.
    RtlZeroMemory(&listHead, sizeof(listHead));
    if (!kswordArkCallbackExtendedReadListEntry(listHeadAddress, &listHead)) {
        // On read failure, restore IRQL first, then free the pre-allocated snapshot.
        KeReleaseSpinLock(objectLock, oldIrql);
        // Snapshots are allocated from non-paged pool in this function; failure paths must symmetrically free them.
        ExFreePoolWithTag(snapshots, KSWORD_ARK_CALLBACK_OBJECT_TAG);
        return 0UL;
    }

    // Traverse from the first node under lock protection, copying up to a fixed number of scalar snapshots.
    currentAddress = (ULONG64)(ULONG_PTR)listHead.Flink;
    while (currentAddress != 0ULL &&
        currentAddress != listHeadAddress &&
        index < KSWORD_ARK_CALLBACK_OBJECT_REGISTRATION_LIMIT) {
        KswordArkCallbackObjectRegistration registration;
        ULONG64 nextAddress = 0ULL;

        // Clear the local structure before reading each node to prevent stack residue from causing abnormal reads.
        RtlZeroMemory(&registration, sizeof(registration));
        // Copy the registration node under object lock protection; the unregistration path cannot release this node concurrently.
        if (!kswordArkCallbackEnumReadMemory(
                (const VOID*)(ULONG_PTR)currentAddress,
                &registration,
                sizeof(registration))) {
            break;
        }
        // Saves the next node address for use only within the current lock protection window.
        nextAddress = (ULONG64)(ULONG_PTR)registration.link.Flink;

        // Accept only registration nodes belonging to the current object with a non-null callback function.
        if ((ULONG64)(ULONG_PTR)registration.callbackObject == callbackObjectAddress &&
            registration.callbackFunction != NULL) {
            // Snapshots only store scalars required to build responses outside the lock, excluding node pointers that may become invalid.
            snapshots[snapshotCount].traversalIndex = index;
            snapshots[snapshotCount].registrationAddress = currentAddress;
            snapshots[snapshotCount].callbackFunction =
                (ULONG64)(ULONG_PTR)registration.callbackFunction;
            snapshots[snapshotCount].callbackContext =
                (ULONG64)(ULONG_PTR)registration.callbackContext;
            // Record the number of filled snapshots; capacity matches the traversal limit exactly.
            ++snapshotCount;
        }

        // A self-loop indicates a corrupted list; continuing traversal would cause an infinite loop while holding the lock.
        if (nextAddress == currentAddress) {
            break;
        }
        // Advance to the next node and record the original traversal index.
        currentAddress = nextAddress;
        ++index;
    }

    // Release the object spinlock and restore the caller's IRQL immediately after node copying is completed.
    KeReleaseSpinLock(objectLock, oldIrql);

    // Verify module ownership and build the response item-by-item outside the lock to avoid complex logic at DISPATCH_LEVEL.
    for (snapshotIndex = 0UL; snapshotIndex < snapshotCount; ++snapshotIndex) {
        WCHAR nameText[KSWORD_ARK_CALLBACK_ENUM_NAME_CHARS];
        WCHAR detailText[KSWORD_ARK_CALLBACK_ENUM_DETAIL_CHARS];
        const KswordArkCallbackObjectSnapshot* snapshot = &snapshots[snapshotIndex];

        // Non-module addresses are excluded from the result set, but this does not affect other stable snapshots.
        if (!kswordArkCallbackEnumIsKernelModuleAddress(
                moduleCache,
                snapshot->callbackFunction)) {
            continue;
        }

        // Pre-zero display buffers to ensure deterministic content even if formatting fails.
        RtlZeroMemory(nameText, sizeof(nameText));
        RtlZeroMemory(detailText, sizeof(detailText));
        // Maintain existing name semantics using the traversal sequence number recorded within the lock.
        (VOID)RtlStringCbPrintfW(
            nameText,
            sizeof(nameText),
            L"%ws[%lu]",
            objectName,
            (unsigned long)snapshot->traversalIndex);
        // Details use only scalar address values and do not dereference registration nodes that have already been unregistered.
        (VOID)RtlStringCbPrintfW(
            detailText,
            sizeof(detailText),
            L"CallbackObject 注册项；Object=0x%p，Registration=0x%p，Function=0x%p，Context=0x%p。",
            (PVOID)(ULONG_PTR)callbackObjectAddress,
            (PVOID)(ULONG_PTR)snapshot->registrationAddress,
            (PVOID)(ULONG_PTR)snapshot->callbackFunction,
            (PVOID)(ULONG_PTR)snapshot->callbackContext);
        // Write the verified snapshot to the unified callback enumeration response.
        kswordArkCallbackExtendedAddRow(
            builder,
            moduleCache,
            callbackClass,
            source,
            KSWORD_ARK_CALLBACK_ENUM_STATUS_OK,
            STATUS_SUCCESS,
            registrationType,
            0UL,
            0UL,
            snapshot->callbackFunction,
            snapshot->callbackContext,
            snapshot->registrationAddress,
            0UL,
            nameText,
            detailText);
        // Count the number of registered items successfully added to the result set.
        ++addedCount;
    }

    // Free the non-paged snapshot array allocated by this function.
    ExFreePoolWithTag(snapshots, KSWORD_ARK_CALLBACK_OBJECT_TAG);
    return addedCount;
}

static VOID
kswordArkCallbackExtendedAddNamedCallbackObjects(
    _Inout_ KswordArkCallbackEnumBuilder* builder,
    _Inout_ KswordArkCallbackModuleCache* moduleCache
    )
/*++

Routine Description:

    enumerate named CallbackObject instances and their registered functions in the \Callback directory.

Arguments:

    Builder: Response builder.
    ModuleCache - Module cache.

Return Value:

    No return value.

--*/
{
    HANDLE directoryHandle = NULL;
    KswordArkCallbackObjectDirectoryInformation* entry = NULL;
    ULONG queryContext = 0UL;
    ULONG returnLength = 0UL;
    ULONG scannedEntries = 0UL;
    BOOLEAN restartScan = TRUE;
    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING callbackTypeName;

    status = kswordArkCallbackExtendedOpenCallbackDirectory(&directoryHandle);
    if (!NT_SUCCESS(status)) {
        kswordArkCallbackExtendedAddRow(
            builder,
            moduleCache,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_GENERIC_KERNEL,
            KSWORD_ARK_CALLBACK_ENUM_SOURCE_OBJECT_DIRECTORY,
            KSWORD_ARK_CALLBACK_ENUM_STATUS_QUERY_FAILED,
            status,
            KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_GENERIC_CALLBACK_OBJECT,
            0UL,
            0UL,
            0ULL,
            0ULL,
            0ULL,
            0UL,
            L"\\Callback directory",
            L"打开命名 CallbackObject 目录失败。");
        return;
    }

    entry = (KswordArkCallbackObjectDirectoryInformation*)kswordArkAllocateNonPaged(
        KSWORD_ARK_CALLBACK_OBJECT_DIRECTORY_BYTES,
        KSWORD_ARK_CALLBACK_OBJECT_TAG);
    if (entry == NULL) {
        ZwClose(directoryHandle);
        return;
    }

    RtlInitUnicodeString(&callbackTypeName, L"Callback");
    while (scannedEntries < KSWORD_ARK_CALLBACK_OBJECT_DIRECTORY_LIMIT) {
        WCHAR objectName[KSWORD_ARK_CALLBACK_ENUM_NAME_CHARS];
        UNICODE_STRING fullObjectName;
        OBJECT_ATTRIBUTES callbackObjectAttributes;
        PCALLBACK_OBJECT callbackObject = NULL;

        RtlZeroMemory(entry, KSWORD_ARK_CALLBACK_OBJECT_DIRECTORY_BYTES);
        status = ZwQueryDirectoryObject(
            directoryHandle,
            entry,
            KSWORD_ARK_CALLBACK_OBJECT_DIRECTORY_BYTES,
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
        if (!RtlEqualUnicodeString(
                &entry->typeName,
                &callbackTypeName,
                TRUE)) {
            continue;
        }

        RtlZeroMemory(objectName, sizeof(objectName));
        if (!kswordArkCallbackExtendedBuildCallbackObjectName(
                &entry->name,
                objectName,
                RTL_NUMBER_OF(objectName))) {
            continue;
        }

        RtlInitUnicodeString(&fullObjectName, objectName);
        // Open an existing object using the public CallbackObject DDI; the entry point passes the actual object type internally within the kernel.
        InitializeObjectAttributes(
            &callbackObjectAttributes,
            &fullObjectName,
            OBJ_CASE_INSENSITIVE,
            NULL,
            NULL);
        // Create=FALSE ensures enumeration is read-only; AllowMultipleCallbacks is ignored by the system when opening an existing object only.
        status = ExCreateCallback(
            &callbackObject,
            &callbackObjectAttributes,
            FALSE,
            FALSE);
        if (!NT_SUCCESS(status) || callbackObject == NULL) {
            continue;
        }

        (VOID)kswordArkCallbackExtendedEnumerateCallbackObject(
            builder,
            moduleCache,
            (ULONG64)(ULONG_PTR)callbackObject,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_GENERIC_KERNEL,
            KSWORD_ARK_CALLBACK_ENUM_SOURCE_OBJECT_DIRECTORY,
            KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_GENERIC_CALLBACK_OBJECT,
            objectName);
        ObDereferenceObject(callbackObject);
    }

    ExFreePoolWithTag(entry, KSWORD_ARK_CALLBACK_OBJECT_TAG);
    ZwClose(directoryHandle);
}

static ULONG
kswordArkCallbackExtendedLocateImageCallbackGlobals(
    _Out_writes_(globalCapacity) ULONG64* globalAddresses,
    _In_ ULONG globalCapacity
    )
/*++

Routine Description:

    Extract two CallbackObject global pointers from SeRegisterImageVerificationCallback.

Arguments:

    GlobalAddresses - Output address of the global pointer variable.
    GlobalCapacity - Output slot capacity.

Return Value:

    Return the count of deduplicated global addresses.

--*/
{
    UCHAR codeBytes[KSWORD_ARK_CALLBACK_OBJECT_CODE_SCAN_BYTES];
    ULONG offset = 0UL;
    ULONG foundCount = 0UL;
    ULONG64 routineAddress = (ULONG64)(ULONG_PTR)
        kswordArkCallbackExtendedGetSystemRoutine(L"SeRegisterImageVerificationCallback");

    if (globalAddresses == NULL || globalCapacity == 0UL || routineAddress == 0ULL) {
        return 0UL;
    }

    RtlZeroMemory(globalAddresses, sizeof(ULONG64) * globalCapacity);
    RtlZeroMemory(codeBytes, sizeof(codeBytes));
    if (!kswordArkCallbackEnumReadMemory(
            (const VOID*)(ULONG_PTR)routineAddress,
            codeBytes,
            sizeof(codeBytes))) {
        return 0UL;
    }

    for (offset = 0UL;
        offset + 7UL <= sizeof(codeBytes) && foundCount < globalCapacity;
        ++offset) {
        ULONG64 globalAddress = 0ULL;
        ULONG existingIndex = 0UL;
        BOOLEAN duplicate = FALSE;

        if (codeBytes[offset] != 0x48U ||
            codeBytes[offset + 1UL] != 0x8BU ||
            codeBytes[offset + 2UL] != 0x0DU) {
            continue;
        }
        if (!kswordArkCallbackExtendedResolveRipRelative(
                routineAddress + offset,
                3UL,
                7UL,
                &globalAddress)) {
            continue;
        }

        for (existingIndex = 0UL; existingIndex < foundCount; ++existingIndex) {
            if (globalAddresses[existingIndex] == globalAddress) {
                duplicate = TRUE;
                break;
            }
        }
        if (!duplicate) {
            globalAddresses[foundCount] = globalAddress;
            ++foundCount;
        }
    }

    return foundCount;
}

static VOID
kswordArkCallbackExtendedAddImageVerificationCallbacks(
    _Inout_ KswordArkCallbackEnumBuilder* builder,
    _Inout_ KswordArkCallbackModuleCache* moduleCache
    )
/*++

Routine Description:

    enumerate the Informational and Block Image Verification CallbackObject instances.

Arguments:

    Builder: Response builder.
    ModuleCache - Module cache.

Return Value:

    No return value.

--*/
{
    ULONG index = 0UL;
    ULONG globalCount = 0UL;
    ULONG64 globalAddresses[2] = { 0ULL, 0ULL };

    globalCount = kswordArkCallbackExtendedLocateImageCallbackGlobals(
        globalAddresses,
        RTL_NUMBER_OF(globalAddresses));
    if (globalCount == 0UL) {
        kswordArkCallbackExtendedAddRow(
            builder,
            moduleCache,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_IMAGE_VERIFICATION,
            KSWORD_ARK_CALLBACK_ENUM_SOURCE_CALLBACK_OBJECT,
            KSWORD_ARK_CALLBACK_ENUM_STATUS_QUERY_FAILED,
            STATUS_NOT_FOUND,
            KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_UNKNOWN,
            0UL,
            0UL,
            0ULL,
            0ULL,
            0ULL,
            0UL,
            L"SeImageVerification callback objects",
            L"未能从 SeRegisterImageVerificationCallback 公开入口恢复 CallbackObject 全局指针。");
        return;
    }

    for (index = 0UL; index < globalCount; ++index) {
        ULONG64 callbackObject = 0ULL;
        const ULONG kRegistrationType = (index == 0UL)
            ? KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_IMAGE_VERIFY_INFORMATIONAL
            : KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_IMAGE_VERIFY_BLOCK;
        PCWSTR objectName = (index == 0UL)
            ? L"SeImageVerification/Informational"
            : L"SeImageVerification/Block";

        if (!kswordArkCallbackExtendedReadPointer(
                globalAddresses[index],
                &callbackObject) ||
            callbackObject == 0ULL) {
            continue;
        }

        (VOID)kswordArkCallbackExtendedEnumerateCallbackObject(
            builder,
            moduleCache,
            callbackObject,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_IMAGE_VERIFICATION,
            KSWORD_ARK_CALLBACK_ENUM_SOURCE_CALLBACK_OBJECT,
            kRegistrationType,
            objectName);
    }
}

VOID
kswordArkCallbackExtendedAddObjectCallbacks(
    _Inout_ KswordArkCallbackEnumBuilder* builder
    )
/*++

Routine Description:

    Aggregates the CallbackObject naming with the Image Verification callback enumeration.

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

    kswordArkCallbackExtendedAddNamedCallbackObjects(builder, &moduleCache);
    kswordArkCallbackExtendedAddImageVerificationCallbacks(builder, &moduleCache);
    kswordArkCallbackEnumFreeModuleCache(&moduleCache);
}
