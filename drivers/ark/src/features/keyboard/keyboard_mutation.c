/*++

Module Name:

    keyboard_mutation.c

Abstract:

    Exact-build, snapshot-guarded editing and deletion of ordinary win32k
    RegisterHotKey entries.

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL, original caller context.

--*/

#include "ark/ark_driver.h"
#include "keyboard_internal.h"
#include "../../dispatch/ioctl_validation.h"
#include "../kernel/hook_scan_support.h"

#include <ntimage.h>

#define KSW_HOTKEY_BUCKET_COUNT 0x80UL
#define KSW_HOTKEY_CHAIN_LIMIT 512UL
#define KSW_HOTKEY_OBJECT_SIZE 0x48UL
#define KSW_HOTKEY_OWNER_OFFSET 0x00UL
#define KSW_HOTKEY_CALLBACK_OFFSET 0x08UL
#define KSW_HOTKEY_WINDOW_OFFSET 0x10UL
#define KSW_HOTKEY_DESTINATION_OFFSET 0x18UL
#define KSW_HOTKEY_MODIFIERS_OFFSET 0x20UL
#define KSW_HOTKEY_FLAGS_OFFSET 0x22UL
#define KSW_HOTKEY_VK_OFFSET 0x24UL
#define KSW_HOTKEY_ID_OFFSET 0x28UL
#define KSW_HOTKEY_NEXT_OFFSET 0x30UL
#define KSW_HOTKEY_CHILD_OFFSET 0x38UL
#define KSW_HOTKEY_TABLE_OFFSET 0x3290UL
#define KSW_HOTKEY_SESSION_CACHE_OFFSET 0x36A8UL
#define KSW_HOTKEY_REMOVE_MATCHING_RVA 0x1C8108UL
#define KSW_HOTKEY_EXPECTED_TIMESTAMP 0x5CD0A4AFUL
#define KSW_HOTKEY_EXPECTED_IMAGE_SIZE 0x00428000UL
#define KSW_HOTKEY_EXPECTED_PDB_AGE 1UL
#define KSW_HOTKEY_RSDS_SIGNATURE 0x53445352UL
#define KSW_HOTKEY_QUERY_OWNER_WINDOW_ID 3UL
#define KSW_HOTKEY_ALLOWED_MODIFIERS 0x0000400FUL

typedef VOID(NTAPI* KswEnterCritFn)(VOID);
typedef VOID(NTAPI* KswLeaveCritFn)(VOID);
typedef PVOID(NTAPI* KswValidateHwndFn)(_In_ PVOID windowHandle);
typedef PVOID(NTAPI* KswPsGetThreadWiN32ThreadFn)(_In_ PETHREAD thread);
typedef BOOLEAN(*KswRemoveMatchingHotkeysFn)(
    _In_ PVOID threadInfo,
    _In_opt_ PVOID windowObject,
    _In_ ULONG hotkeyId,
    _In_ ULONG queryType
    );

typedef struct KswHotkeyRsdsHeader
{
    ULONG signature;
    GUID guid;
    ULONG age;
} KswHotkeyRsdsHeader;

typedef struct KswHotkeyView
{
    UCHAR bytes[KSW_HOTKEY_OBJECT_SIZE];
    ULONG_PTR ownerThreadInfo;
    ULONG_PTR callbackAddress;
    ULONG_PTR windowHandle;
    ULONG_PTR destinationHandle;
    USHORT modifiers;
    USHORT flags;
    ULONG virtualKey;
    ULONG hotkeyId;
    ULONG_PTR nextHotkey;
    ULONG_PTR childFlink;
    ULONG_PTR childBlink;
    ULONG64 snapshotHash;
} KswHotkeyView;

typedef struct KswHotkeyExactRuntime
{
    KswKeyboardHotkeyRuntime layout;
    KswEnterCritFn enterCrit;
    KswLeaveCritFn leaveCrit;
    KswValidateHwndFn validateHwnd;
    KswRemoveMatchingHotkeysFn removeMatchingHotkeys;
    KswPsGetThreadWiN32ThreadFn psGetThreadWin32Thread;
    ULONG timeDateStamp;
    ULONG imageSize;
    ULONG pdbAge;
} KswHotkeyExactRuntime;

static const GUID kGKswHotkeyExpectedPdbGuid = {
    0x80DB0813UL,
    0x4711U,
    0x330DU,
    { 0xD7U, 0x06U, 0x8DU, 0x82U, 0x6FU, 0xF8U, 0xE1U, 0xB0U }
};

static const UCHAR kGKswHotkeyRemoveMatchingPrologue[] = {
    0x48U, 0x89U, 0x5CU, 0x24U, 0x08U, 0x48U, 0x89U, 0x6CU,
    0x24U, 0x10U, 0x48U, 0x89U, 0x74U, 0x24U, 0x18U, 0x57U,
    0x41U, 0x54U, 0x41U, 0x55U, 0x41U, 0x56U, 0x41U, 0x57U,
    0x48U, 0x83U, 0xECU, 0x30U, 0x40U, 0x32U, 0xEDU, 0x45U
};

NTSYSAPI
PVOID
NTAPI
RtlFindExportedRoutineByName(
    _In_ PVOID imageBase,
    _In_z_ PCSTR routineName
    );

static BOOLEAN
kswHotkeyPointerInImage(
    _In_ PVOID address,
    _In_ PVOID imageBase,
    _In_ ULONG imageSize
    )
{
    const ULONG_PTR kAddressValue = (ULONG_PTR)address;
    const ULONG_PTR kImageBaseValue = (ULONG_PTR)imageBase;

    return address != NULL && imageBase != NULL && imageSize != 0UL &&
        kAddressValue >= kImageBaseValue &&
        kAddressValue < (kImageBaseValue + (ULONG_PTR)imageSize);
}

static BOOLEAN
kswHotkeyReadLoadedRsds(
    _In_ PVOID imageBase,
    _In_ ULONG imageSize,
    _Out_ ULONG* timeDateStampOut,
    _Out_ ULONG* sizeOfImageOut,
    _Out_ GUID* pdbGuidOut,
    _Out_ ULONG* pdbAgeOut
    )
{
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS64 ntHeaders;
    IMAGE_DATA_DIRECTORY debugDirectory;
    ULONG debugIndex = 0UL;
    ULONG debugCount = 0UL;

    if (imageBase == NULL || timeDateStampOut == NULL || sizeOfImageOut == NULL ||
        pdbGuidOut == NULL || pdbAgeOut == NULL || imageSize < sizeof(ntHeaders)) {
        return FALSE;
    }
    *timeDateStampOut = 0UL;
    *sizeOfImageOut = 0UL;
    RtlZeroMemory(pdbGuidOut, sizeof(*pdbGuidOut));
    *pdbAgeOut = 0UL;
    if (!kswordArkHookReadMemorySafe(imageBase, &dosHeader, sizeof(dosHeader)) ||
        dosHeader.e_magic != IMAGE_DOS_SIGNATURE || dosHeader.e_lfanew <= 0 ||
        (ULONG)dosHeader.e_lfanew > imageSize - sizeof(ntHeaders) ||
        !kswordArkHookReadMemorySafe(
            (const UCHAR*)imageBase + (ULONG)dosHeader.e_lfanew,
            &ntHeaders,
            sizeof(ntHeaders)) ||
        ntHeaders.Signature != IMAGE_NT_SIGNATURE ||
        ntHeaders.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        ntHeaders.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        ntHeaders.OptionalHeader.SizeOfImage != imageSize) {
        return FALSE;
    }

    *timeDateStampOut = ntHeaders.FileHeader.TimeDateStamp;
    *sizeOfImageOut = ntHeaders.OptionalHeader.SizeOfImage;
    debugDirectory = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    if (debugDirectory.VirtualAddress == 0UL ||
        debugDirectory.Size < sizeof(IMAGE_DEBUG_DIRECTORY) ||
        debugDirectory.VirtualAddress > imageSize ||
        debugDirectory.Size > imageSize - debugDirectory.VirtualAddress) {
        return FALSE;
    }
    debugCount = debugDirectory.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
    if (debugCount == 0UL || debugCount > 64UL) {
        return FALSE;
    }

    for (debugIndex = 0UL; debugIndex < debugCount; ++debugIndex) {
        IMAGE_DEBUG_DIRECTORY debugEntry;
        KswHotkeyRsdsHeader rsdsHeader;
        const ULONG kDebugEntryRva = debugDirectory.VirtualAddress +
            (debugIndex * sizeof(IMAGE_DEBUG_DIRECTORY));

        if (!kswordArkHookReadMemorySafe(
                (const UCHAR*)imageBase + kDebugEntryRva,
                &debugEntry,
                sizeof(debugEntry)) ||
            debugEntry.Type != IMAGE_DEBUG_TYPE_CODEVIEW ||
            debugEntry.AddressOfRawData == 0UL ||
            debugEntry.SizeOfData < sizeof(rsdsHeader) ||
            debugEntry.AddressOfRawData > imageSize ||
            sizeof(rsdsHeader) > imageSize - debugEntry.AddressOfRawData ||
            !kswordArkHookReadMemorySafe(
                (const UCHAR*)imageBase + debugEntry.AddressOfRawData,
                &rsdsHeader,
                sizeof(rsdsHeader)) ||
            rsdsHeader.signature != KSW_HOTKEY_RSDS_SIGNATURE) {
            continue;
        }
        *pdbGuidOut = rsdsHeader.guid;
        *pdbAgeOut = rsdsHeader.age;
        return TRUE;
    }
    return FALSE;
}

static NTSTATUS
kswHotkeyResolveExactRuntime(
    _Out_ KswHotkeyExactRuntime* runtimeOut
    )
{
    GUID pdbGuid;
    UCHAR prologue[sizeof(kGKswHotkeyRemoveMatchingPrologue)] = { 0 };
    UNICODE_STRING routineName;
    NTSTATUS status = STATUS_SUCCESS;

    if (runtimeOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(runtimeOut, sizeof(*runtimeOut));
    RtlZeroMemory(&pdbGuid, sizeof(pdbGuid));
    status = kswordArkKeyboardResolveHotkeyRuntime(&runtimeOut->layout);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (runtimeOut->layout.tableBase != 0U ||
        runtimeOut->layout.tableOffset != KSW_HOTKEY_TABLE_OFFSET ||
        runtimeOut->layout.nextOffset != KSW_HOTKEY_NEXT_OFFSET ||
        runtimeOut->layout.modifiersOffset != KSW_HOTKEY_MODIFIERS_OFFSET ||
        runtimeOut->layout.vkOffset != KSW_HOTKEY_VK_OFFSET ||
        runtimeOut->layout.idOffset != KSW_HOTKEY_ID_OFFSET ||
        !kswHotkeyReadLoadedRsds(
            runtimeOut->layout.win32kfullBase,
            runtimeOut->layout.win32kfullSize,
            &runtimeOut->timeDateStamp,
            &runtimeOut->imageSize,
            &pdbGuid,
            &runtimeOut->pdbAge) ||
        runtimeOut->timeDateStamp != KSW_HOTKEY_EXPECTED_TIMESTAMP ||
        runtimeOut->imageSize != KSW_HOTKEY_EXPECTED_IMAGE_SIZE ||
        runtimeOut->pdbAge != KSW_HOTKEY_EXPECTED_PDB_AGE ||
        RtlCompareMemory(&pdbGuid, &kGKswHotkeyExpectedPdbGuid, sizeof(GUID)) != sizeof(GUID)) {
        return STATUS_REVISION_MISMATCH;
    }

    runtimeOut->enterCrit = (KswEnterCritFn)RtlFindExportedRoutineByName(
        runtimeOut->layout.win32kbaseBase,
        "EnterCrit");
    runtimeOut->leaveCrit = (KswLeaveCritFn)RtlFindExportedRoutineByName(
        runtimeOut->layout.win32kbaseBase,
        "UserSessionSwitchLeaveCrit");
    runtimeOut->validateHwnd = (KswValidateHwndFn)RtlFindExportedRoutineByName(
        runtimeOut->layout.win32kbaseBase,
        "ValidateHwnd");
    runtimeOut->removeMatchingHotkeys = (KswRemoveMatchingHotkeysFn)(
        (UCHAR*)runtimeOut->layout.win32kfullBase + KSW_HOTKEY_REMOVE_MATCHING_RVA);
    RtlInitUnicodeString(&routineName, L"PsGetThreadWin32Thread");
    runtimeOut->psGetThreadWin32Thread =
        (KswPsGetThreadWiN32ThreadFn)MmGetSystemRoutineAddress(&routineName);
    if (!kswHotkeyPointerInImage(
            (PVOID)runtimeOut->enterCrit,
            runtimeOut->layout.win32kbaseBase,
            runtimeOut->layout.win32kbaseSize) ||
        !kswHotkeyPointerInImage(
            (PVOID)runtimeOut->leaveCrit,
            runtimeOut->layout.win32kbaseBase,
            runtimeOut->layout.win32kbaseSize) ||
        !kswHotkeyPointerInImage(
            (PVOID)runtimeOut->validateHwnd,
            runtimeOut->layout.win32kbaseBase,
            runtimeOut->layout.win32kbaseSize) ||
        runtimeOut->psGetThreadWin32Thread == NULL ||
        !kswHotkeyPointerInImage(
            (PVOID)runtimeOut->removeMatchingHotkeys,
            runtimeOut->layout.win32kfullBase,
            runtimeOut->layout.win32kfullSize) ||
        !kswordArkHookReadMemorySafe(
            (const VOID*)runtimeOut->removeMatchingHotkeys,
            prologue,
            sizeof(prologue)) ||
        RtlCompareMemory(
            prologue,
            kGKswHotkeyRemoveMatchingPrologue,
            sizeof(prologue)) != sizeof(prologue)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    return STATUS_SUCCESS;
}

static BOOLEAN
kswHotkeyReadView(
    _In_ ULONG_PTR hotkeyObject,
    _Out_ KswHotkeyView* viewOut
    )
{
    if (hotkeyObject == 0U || viewOut == NULL) {
        return FALSE;
    }
    RtlZeroMemory(viewOut, sizeof(*viewOut));
    if (!kswordArkHookReadMemorySafe(
            (const VOID*)hotkeyObject,
            viewOut->bytes,
            sizeof(viewOut->bytes))) {
        return FALSE;
    }
    RtlCopyMemory(&viewOut->ownerThreadInfo, viewOut->bytes + KSW_HOTKEY_OWNER_OFFSET, sizeof(PVOID));
    RtlCopyMemory(&viewOut->callbackAddress, viewOut->bytes + KSW_HOTKEY_CALLBACK_OFFSET, sizeof(PVOID));
    RtlCopyMemory(&viewOut->windowHandle, viewOut->bytes + KSW_HOTKEY_WINDOW_OFFSET, sizeof(PVOID));
    RtlCopyMemory(&viewOut->destinationHandle, viewOut->bytes + KSW_HOTKEY_DESTINATION_OFFSET, sizeof(PVOID));
    RtlCopyMemory(&viewOut->modifiers, viewOut->bytes + KSW_HOTKEY_MODIFIERS_OFFSET, sizeof(USHORT));
    RtlCopyMemory(&viewOut->flags, viewOut->bytes + KSW_HOTKEY_FLAGS_OFFSET, sizeof(USHORT));
    RtlCopyMemory(&viewOut->virtualKey, viewOut->bytes + KSW_HOTKEY_VK_OFFSET, sizeof(ULONG));
    RtlCopyMemory(&viewOut->hotkeyId, viewOut->bytes + KSW_HOTKEY_ID_OFFSET, sizeof(ULONG));
    RtlCopyMemory(&viewOut->nextHotkey, viewOut->bytes + KSW_HOTKEY_NEXT_OFFSET, sizeof(PVOID));
    RtlCopyMemory(&viewOut->childFlink, viewOut->bytes + KSW_HOTKEY_CHILD_OFFSET, sizeof(PVOID));
    RtlCopyMemory(&viewOut->childBlink, viewOut->bytes + KSW_HOTKEY_CHILD_OFFSET + sizeof(PVOID), sizeof(PVOID));
    viewOut->snapshotHash = kswordArkKeyboardHashHotkeyObject(viewOut->bytes, sizeof(viewOut->bytes));
    return TRUE;
}

static BOOLEAN
kswHotkeyViewMatchesRequest(
    _In_ const KswHotkeyView* view,
    _In_ const KSWORD_ARK_MUTATE_KEYBOARD_HOTKEY_REQUEST* request
    )
{
    return view != NULL && request != NULL &&
        view->ownerThreadInfo == (ULONG_PTR)request->expectedThreadInfo &&
        view->windowHandle == (ULONG_PTR)request->expectedWindowHandle &&
        view->destinationHandle == (ULONG_PTR)request->expectedDestinationHandle &&
        view->callbackAddress == (ULONG_PTR)request->expectedCallbackAddress &&
        view->nextHotkey == (ULONG_PTR)request->expectedNextHotkeyObject &&
        view->childFlink == (ULONG_PTR)request->expectedChildListFlink &&
        view->childBlink == (ULONG_PTR)request->expectedChildListBlink &&
        view->modifiers == (USHORT)request->expectedModifiers &&
        view->flags == (USHORT)request->expectedModifierFlags2 &&
        view->virtualKey == request->expectedVirtualKey &&
        view->hotkeyId == request->expectedHotkeyId &&
        view->snapshotHash == request->expectedSnapshotHash;
}

static BOOLEAN
kswHotkeyViewIsOrdinaryStandalone(
    _In_ ULONG_PTR hotkeyObject,
    _In_ const KswHotkeyView* view
    )
{
    const ULONG_PTR kChildHead = hotkeyObject + KSW_HOTKEY_CHILD_OFFSET;

    return view != NULL && view->ownerThreadInfo != 0U &&
        view->callbackAddress == 0U && view->flags == 0U &&
        view->virtualKey != 0UL && view->virtualKey <= 0xFFUL &&
        view->childFlink == kChildHead && view->childBlink == kChildHead;
}

static NTSTATUS
kswHotkeyFindObjectLink(
    _In_ ULONG_PTR tableAddress,
    _In_ ULONG bucketIndex,
    _In_ ULONG_PTR hotkeyObject,
    _Out_ ULONG_PTR* linkAddressOut,
    _Out_ ULONG_PTR* nextHotkeyOut
    )
{
    ULONG_PTR linkAddress = tableAddress + ((ULONG_PTR)bucketIndex * sizeof(PVOID));
    ULONG_PTR currentObject = 0U;
    ULONG depth = 0UL;

    if (linkAddressOut == NULL || nextHotkeyOut == NULL || bucketIndex >= KSW_HOTKEY_BUCKET_COUNT) {
        return STATUS_INVALID_PARAMETER;
    }
    *linkAddressOut = 0U;
    *nextHotkeyOut = 0U;
    while (depth < KSW_HOTKEY_CHAIN_LIMIT) {
        if (!kswordArkHookReadMemorySafe((const VOID*)linkAddress, &currentObject, sizeof(currentObject))) {
            return STATUS_PARTIAL_COPY;
        }
        if (currentObject == 0U) {
            return STATUS_NOT_FOUND;
        }
        if (currentObject == hotkeyObject) {
            KswHotkeyView view;

            if (!kswHotkeyReadView(currentObject, &view)) {
                return STATUS_PARTIAL_COPY;
            }
            *linkAddressOut = linkAddress;
            *nextHotkeyOut = view.nextHotkey;
            return STATUS_SUCCESS;
        }
        linkAddress = currentObject + KSW_HOTKEY_NEXT_OFFSET;
        ++depth;
    }
    return STATUS_DATA_ERROR;
}

static NTSTATUS
kswHotkeyFindConflict(
    _In_ ULONG_PTR tableAddress,
    _In_ ULONG_PTR targetObject,
    _In_ USHORT modifiers,
    _In_ ULONG virtualKey
    )
{
    ULONG bucketIndex = 0UL;

    for (bucketIndex = 0UL; bucketIndex < KSW_HOTKEY_BUCKET_COUNT; ++bucketIndex) {
        ULONG_PTR currentObject = 0U;
        ULONG depth = 0UL;
        const ULONG_PTR kHeadAddress = tableAddress + ((ULONG_PTR)bucketIndex * sizeof(PVOID));

        if (!kswordArkHookReadMemorySafe((const VOID*)kHeadAddress, &currentObject, sizeof(currentObject))) {
            return STATUS_PARTIAL_COPY;
        }
        while (currentObject != 0U && depth < KSW_HOTKEY_CHAIN_LIMIT) {
            KswHotkeyView view;

            if (!kswHotkeyReadView(currentObject, &view)) {
                return STATUS_PARTIAL_COPY;
            }
            if (currentObject != targetObject &&
                view.modifiers == modifiers && view.virtualKey == virtualKey) {
                return STATUS_OBJECT_NAME_COLLISION;
            }
            if (view.nextHotkey == currentObject) {
                return STATUS_DATA_ERROR;
            }
            currentObject = view.nextHotkey;
            ++depth;
        }
        if (currentObject != 0U) {
            return STATUS_DATA_ERROR;
        }
    }
    return STATUS_SUCCESS;
}

static BOOLEAN
kswHotkeyOtherBytesUnchanged(
    _In_ const KswHotkeyView* before,
    _In_ const KswHotkeyView* after
    )
{
    ULONG byteIndex = 0UL;

    if (before == NULL || after == NULL) {
        return FALSE;
    }
    for (byteIndex = 0UL; byteIndex < KSW_HOTKEY_OBJECT_SIZE; ++byteIndex) {
        const BOOLEAN kMutableByte =
            (byteIndex >= KSW_HOTKEY_MODIFIERS_OFFSET && byteIndex < KSW_HOTKEY_FLAGS_OFFSET) ||
            (byteIndex >= KSW_HOTKEY_VK_OFFSET && byteIndex < KSW_HOTKEY_VK_OFFSET + sizeof(ULONG)) ||
            (byteIndex >= KSW_HOTKEY_NEXT_OFFSET && byteIndex < KSW_HOTKEY_NEXT_OFFSET + sizeof(PVOID));

        if (!kMutableByte && before->bytes[byteIndex] != after->bytes[byteIndex]) {
            return FALSE;
        }
    }
    return TRUE;
}

static NTSTATUS
kswHotkeyWriteEdit(
    _In_ ULONG_PTR tableAddress,
    _In_ ULONG_PTR oldLinkAddress,
    _In_ ULONG oldBucketIndex,
    _In_ ULONG newBucketIndex,
    _In_ ULONG_PTR hotkeyObject,
    _In_ const KswHotkeyView* before,
    _In_ USHORT newModifiers,
    _In_ ULONG newVirtualKey,
    _Out_ KswHotkeyView* afterOut,
    _Out_ BOOLEAN* rolledBackOut
    )
{
    ULONG_PTR newHeadAddress = 0U;
    ULONG_PTR newHeadObject = 0U;
    ULONG_PTR verifyPointer = 0U;
    BOOLEAN rebucket = FALSE;
    BOOLEAN writeStarted = FALSE;
    BOOLEAN validPostState = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (before == NULL || afterOut == NULL || rolledBackOut == NULL ||
        oldBucketIndex >= KSW_HOTKEY_BUCKET_COUNT || newBucketIndex >= KSW_HOTKEY_BUCKET_COUNT) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(afterOut, sizeof(*afterOut));
    *rolledBackOut = FALSE;
    rebucket = oldBucketIndex != newBucketIndex;
    newHeadAddress = tableAddress + ((ULONG_PTR)newBucketIndex * sizeof(PVOID));
    if (rebucket && !kswordArkHookReadMemorySafe(
            (const VOID*)newHeadAddress,
            &newHeadObject,
            sizeof(newHeadObject))) {
        return STATUS_PARTIAL_COPY;
    }

    __try {
        writeStarted = TRUE;
        if (rebucket) {
            *(volatile ULONG_PTR*)oldLinkAddress = before->nextHotkey;
            *(volatile ULONG_PTR*)(hotkeyObject + KSW_HOTKEY_NEXT_OFFSET) = newHeadObject;
            *(volatile ULONG_PTR*)newHeadAddress = hotkeyObject;
        }
        *(volatile USHORT*)(hotkeyObject + KSW_HOTKEY_MODIFIERS_OFFSET) = newModifiers;
        *(volatile ULONG*)(hotkeyObject + KSW_HOTKEY_VK_OFFSET) = newVirtualKey;
        KeMemoryBarrier();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    if (NT_SUCCESS(status) && kswHotkeyReadView(hotkeyObject, afterOut)) {
        validPostState = afterOut->modifiers == newModifiers &&
            afterOut->virtualKey == newVirtualKey &&
            afterOut->nextHotkey == (rebucket ? newHeadObject : before->nextHotkey) &&
            kswHotkeyOtherBytesUnchanged(before, afterOut);
        if (validPostState && kswordArkHookReadMemorySafe(
                (const VOID*)(rebucket ? newHeadAddress : oldLinkAddress),
                &verifyPointer,
                sizeof(verifyPointer))) {
            validPostState = verifyPointer == hotkeyObject;
        }
        else {
            validPostState = FALSE;
        }
        if (validPostState && rebucket && kswordArkHookReadMemorySafe(
                (const VOID*)oldLinkAddress,
                &verifyPointer,
                sizeof(verifyPointer))) {
            validPostState = verifyPointer == before->nextHotkey;
        }
        else if (validPostState && rebucket) {
            validPostState = FALSE;
        }
    }
    if (validPostState) {
        return STATUS_SUCCESS;
    }
    if (NT_SUCCESS(status)) {
        status = STATUS_DATA_ERROR;
    }

    if (writeStarted) {
        KswHotkeyView rollbackView;
        BOOLEAN rollbackValid = FALSE;

        RtlZeroMemory(&rollbackView, sizeof(rollbackView));
        __try {
            *(volatile USHORT*)(hotkeyObject + KSW_HOTKEY_MODIFIERS_OFFSET) = before->modifiers;
            *(volatile ULONG*)(hotkeyObject + KSW_HOTKEY_VK_OFFSET) = before->virtualKey;
            if (rebucket) {
                *(volatile ULONG_PTR*)newHeadAddress = newHeadObject;
                *(volatile ULONG_PTR*)(hotkeyObject + KSW_HOTKEY_NEXT_OFFSET) = before->nextHotkey;
                *(volatile ULONG_PTR*)oldLinkAddress = hotkeyObject;
            }
            KeMemoryBarrier();
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            rollbackValid = FALSE;
        }
        if (kswHotkeyReadView(hotkeyObject, &rollbackView) &&
            rollbackView.snapshotHash == before->snapshotHash &&
            kswordArkHookReadMemorySafe(
                (const VOID*)oldLinkAddress,
                &verifyPointer,
                sizeof(verifyPointer)) &&
            verifyPointer == hotkeyObject) {
            rollbackValid = TRUE;
            if (rebucket && (!kswordArkHookReadMemorySafe(
                    (const VOID*)newHeadAddress,
                    &verifyPointer,
                    sizeof(verifyPointer)) || verifyPointer != newHeadObject)) {
                rollbackValid = FALSE;
            }
        }
        *rolledBackOut = rollbackValid;
    }
    return status;
}

static VOID
kswHotkeyInitializeResponse(
    _Out_ KSWORD_ARK_MUTATE_KEYBOARD_HOTKEY_RESPONSE* response,
    _In_opt_ const KSWORD_ARK_MUTATE_KEYBOARD_HOTKEY_REQUEST* request
    )
{
    RtlZeroMemory(response, sizeof(*response));
    response->size = sizeof(*response);
    response->version = KSWORD_ARK_KEYBOARD_PROTOCOL_VERSION;
    response->status = KSWORD_ARK_KEYBOARD_MUTATION_STATUS_INVALID_REQUEST;
    if (request != NULL) {
        response->operation = request->operation;
        response->previousBucketIndex = request->expectedBucketIndex;
        response->currentBucketIndex = request->expectedBucketIndex;
        response->previousModifiers = request->expectedModifiers;
        response->currentModifiers = request->expectedModifiers;
        response->previousVirtualKey = request->expectedVirtualKey;
        response->currentVirtualKey = request->expectedVirtualKey;
        response->hotkeyObject = request->hotkeyObject;
        response->sessionGlobals = request->sessionGlobals;
        response->previousSnapshotHash = request->expectedSnapshotHash;
        response->currentSnapshotHash = request->expectedSnapshotHash;
    }
}

static BOOLEAN
kswHotkeyRequestShapeValid(
    _In_ const KSWORD_ARK_MUTATE_KEYBOARD_HOTKEY_REQUEST* request
    )
{
    if (request == NULL || request->size != sizeof(*request) ||
        request->version != KSWORD_ARK_KEYBOARD_PROTOCOL_VERSION ||
        (request->flags & ~KSWORD_ARK_KEYBOARD_MUTATION_FLAG_UI_CONFIRMED) != 0UL ||
        (request->flags & KSWORD_ARK_KEYBOARD_MUTATION_FLAG_UI_CONFIRMED) == 0UL ||
        request->confirmationToken != KSWORD_ARK_KEYBOARD_MUTATION_CONFIRMATION_TOKEN ||
        request->hotkeyObject == 0ULL || request->sessionGlobals == 0ULL ||
        request->expectedThreadInfo == 0ULL || request->expectedSnapshotHash == 0ULL ||
        request->expectedBucketIndex >= KSW_HOTKEY_BUCKET_COUNT ||
        request->expectedModifiers > 0xFFFFUL || request->expectedModifierFlags2 > 0xFFFFUL ||
        request->expectedVirtualKey == 0UL || request->expectedVirtualKey > 0xFFUL ||
        request->expectedBucketIndex != (request->expectedVirtualKey & (KSW_HOTKEY_BUCKET_COUNT - 1UL))) {
        return FALSE;
    }
    if (request->operation == KSWORD_ARK_KEYBOARD_MUTATION_OPERATION_EDIT) {
        return request->newModifiers <= 0xFFFFUL &&
            (request->newModifiers & ~KSW_HOTKEY_ALLOWED_MODIFIERS) == 0UL &&
            request->newVirtualKey != 0UL && request->newVirtualKey <= 0xFFUL;
    }
    if (request->operation == KSWORD_ARK_KEYBOARD_MUTATION_OPERATION_DELETE) {
        return request->newModifiers == 0UL && request->newVirtualKey == 0UL;
    }
    return FALSE;
}

static NTSTATUS
kswHotkeyCountOwnerWindowIdMatches(
    _In_ ULONG_PTR tableAddress,
    _In_ const KswHotkeyView* targetView,
    _Out_ ULONG* matchCountOut
    )
{
    ULONG bucketIndex = 0UL;
    ULONG matchCount = 0UL;

    if (targetView == NULL || matchCountOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *matchCountOut = 0UL;
    for (bucketIndex = 0UL; bucketIndex < KSW_HOTKEY_BUCKET_COUNT; ++bucketIndex) {
        ULONG_PTR currentObject = 0U;
        ULONG depth = 0UL;
        const ULONG_PTR kHeadAddress = tableAddress + ((ULONG_PTR)bucketIndex * sizeof(PVOID));

        if (!kswordArkHookReadMemorySafe((const VOID*)kHeadAddress, &currentObject, sizeof(currentObject))) {
            return STATUS_PARTIAL_COPY;
        }
        while (currentObject != 0U && depth < KSW_HOTKEY_CHAIN_LIMIT) {
            KswHotkeyView view;

            if (!kswHotkeyReadView(currentObject, &view)) {
                return STATUS_PARTIAL_COPY;
            }
            if (view.ownerThreadInfo == targetView->ownerThreadInfo &&
                view.windowHandle == targetView->windowHandle &&
                view.hotkeyId == targetView->hotkeyId) {
                ++matchCount;
                if (matchCount > 1UL) {
                    *matchCountOut = matchCount;
                    return STATUS_SUCCESS;
                }
            }
            if (view.nextHotkey == currentObject) {
                return STATUS_DATA_ERROR;
            }
            currentObject = view.nextHotkey;
            ++depth;
        }
        if (currentObject != 0U) {
            return STATUS_DATA_ERROR;
        }
    }
    *matchCountOut = matchCount;
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkKeyboardIoctlMutateHotkey(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
    KSWORD_ARK_MUTATE_KEYBOARD_HOTKEY_REQUEST* inputBuffer = NULL;
    KSWORD_ARK_MUTATE_KEYBOARD_HOTKEY_RESPONSE* outputBuffer = NULL;
    KSWORD_ARK_MUTATE_KEYBOARD_HOTKEY_REQUEST requestSnapshot;
    KswordArkSafetyContext safetyContext;
    KswHotkeyExactRuntime runtime;
    KswHotkeyView beforeView;
    KswHotkeyView afterView;
    PVOID windowObject = NULL;
    PVOID callerThreadInfo = NULL;
    ULONG_PTR tableAddress = 0U;
    ULONG_PTR oldLinkAddress = 0U;
    ULONG_PTR oldNextObject = 0U;
    ULONG matchCount = 0UL;
    ULONG newBucketIndex = 0UL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN critEntered = FALSE;
    BOOLEAN operationChanged = FALSE;
    BOOLEAN rolledBack = FALSE;
    static const WCHAR kTargetText[] = L"win32k RegisterHotKey table";

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(requestSnapshot),
        (PVOID*)&inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    RtlCopyMemory(&requestSnapshot, inputBuffer, sizeof(requestSnapshot));
    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(*outputBuffer),
        (PVOID*)&outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    kswHotkeyInitializeResponse(outputBuffer, &requestSnapshot);
    *bytesReturned = sizeof(*outputBuffer);
    if (!kswHotkeyRequestShapeValid(&requestSnapshot)) {
        outputBuffer->lastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&safetyContext, sizeof(safetyContext));
    safetyContext.operation = KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH;
    safetyContext.contextFlags = KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
    safetyContext.targetText = kTargetText;
    safetyContext.targetTextChars = (USHORT)(RTL_NUMBER_OF(kTargetText) - 1U);
    status = kswordArkSafetyEvaluate(device, &safetyContext);
    if (!NT_SUCCESS(status)) {
        outputBuffer->status = KSWORD_ARK_KEYBOARD_MUTATION_STATUS_SAFETY_DENIED;
        outputBuffer->lastStatus = status;
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&runtime, sizeof(runtime));
    status = kswHotkeyResolveExactRuntime(&runtime);
    if (!NT_SUCCESS(status)) {
        outputBuffer->status = KSWORD_ARK_KEYBOARD_MUTATION_STATUS_UNSUPPORTED_BUILD;
        outputBuffer->lastStatus = status;
        return STATUS_SUCCESS;
    }
    outputBuffer->responseFlags |= KSWORD_ARK_KEYBOARD_MUTATION_RESPONSE_IDENTITY_VALIDATED;
    outputBuffer->imageTimeDateStamp = runtime.timeDateStamp;
    outputBuffer->imageSize = runtime.imageSize;
    outputBuffer->pdbAge = runtime.pdbAge;

    callerThreadInfo = runtime.psGetThreadWin32Thread(PsGetCurrentThread());
    if (callerThreadInfo == NULL || runtime.layout.sessionGlobals == 0U ||
        runtime.layout.sessionGlobals != (ULONG_PTR)requestSnapshot.sessionGlobals) {
        outputBuffer->status = KSWORD_ARK_KEYBOARD_MUTATION_STATUS_CALLER_CONTEXT_REQUIRED;
        outputBuffer->lastStatus = STATUS_INVALID_DEVICE_STATE;
        return STATUS_SUCCESS;
    }
    outputBuffer->responseFlags |= KSWORD_ARK_KEYBOARD_MUTATION_RESPONSE_CALLER_VALIDATED;
    tableAddress = runtime.layout.sessionGlobals + KSW_HOTKEY_TABLE_OFFSET;

    __try {
        runtime.enterCrit();
        critEntered = TRUE;
        if (runtime.layout.sessionGlobals != (ULONG_PTR)requestSnapshot.sessionGlobals) {
            status = STATUS_REVISION_MISMATCH;
            outputBuffer->status = KSWORD_ARK_KEYBOARD_MUTATION_STATUS_STALE_SNAPSHOT;
            __leave;
        }
        status = kswHotkeyFindObjectLink(
            tableAddress,
            requestSnapshot.expectedBucketIndex,
            (ULONG_PTR)requestSnapshot.hotkeyObject,
            &oldLinkAddress,
            &oldNextObject);
        if (!NT_SUCCESS(status) || !kswHotkeyReadView(
                (ULONG_PTR)requestSnapshot.hotkeyObject,
                &beforeView) ||
            oldNextObject != beforeView.nextHotkey ||
            !kswHotkeyViewMatchesRequest(&beforeView, &requestSnapshot)) {
            if (NT_SUCCESS(status)) {
                status = STATUS_REVISION_MISMATCH;
            }
            outputBuffer->status = KSWORD_ARK_KEYBOARD_MUTATION_STATUS_STALE_SNAPSHOT;
            __leave;
        }
        if (!kswHotkeyViewIsOrdinaryStandalone(
                (ULONG_PTR)requestSnapshot.hotkeyObject,
                &beforeView)) {
            status = STATUS_NOT_SUPPORTED;
            outputBuffer->status = KSWORD_ARK_KEYBOARD_MUTATION_STATUS_UNSAFE_TARGET;
            __leave;
        }
        outputBuffer->responseFlags |= KSWORD_ARK_KEYBOARD_MUTATION_RESPONSE_SNAPSHOT_VALIDATED;
        outputBuffer->previousSnapshotHash = beforeView.snapshotHash;
        outputBuffer->currentSnapshotHash = beforeView.snapshotHash;

        if (beforeView.windowHandle != 0U) {
            windowObject = runtime.validateHwnd((PVOID)beforeView.windowHandle);
            if (windowObject == NULL) {
                status = STATUS_INVALID_HANDLE;
                outputBuffer->status = KSWORD_ARK_KEYBOARD_MUTATION_STATUS_STALE_SNAPSHOT;
                __leave;
            }
        }

        if (requestSnapshot.operation == KSWORD_ARK_KEYBOARD_MUTATION_OPERATION_DELETE) {
            BOOLEAN removed = FALSE;
            NTSTATUS verifyStatus = STATUS_SUCCESS;

            status = kswHotkeyCountOwnerWindowIdMatches(tableAddress, &beforeView, &matchCount);
            if (!NT_SUCCESS(status) || matchCount != 1UL) {
                if (NT_SUCCESS(status)) {
                    status = STATUS_OBJECT_NAME_COLLISION;
                }
                outputBuffer->status = KSWORD_ARK_KEYBOARD_MUTATION_STATUS_UNSAFE_TARGET;
                __leave;
            }
            removed = runtime.removeMatchingHotkeys(
                (PVOID)beforeView.ownerThreadInfo,
                windowObject,
                beforeView.hotkeyId,
                KSW_HOTKEY_QUERY_OWNER_WINDOW_ID);
            verifyStatus = kswHotkeyFindObjectLink(
                tableAddress,
                requestSnapshot.expectedBucketIndex,
                (ULONG_PTR)requestSnapshot.hotkeyObject,
                &oldLinkAddress,
                &oldNextObject);
            if (!removed || verifyStatus != STATUS_NOT_FOUND) {
                status = !removed ? STATUS_UNSUCCESSFUL : verifyStatus;
                outputBuffer->status = KSWORD_ARK_KEYBOARD_MUTATION_STATUS_OPERATION_FAILED;
                __leave;
            }
            *(volatile ULONG_PTR*)(runtime.layout.sessionGlobals + KSW_HOTKEY_SESSION_CACHE_OFFSET) = 0U;
            KeMemoryBarrier();
            outputBuffer->status = KSWORD_ARK_KEYBOARD_MUTATION_STATUS_OK;
            outputBuffer->responseFlags |= KSWORD_ARK_KEYBOARD_MUTATION_RESPONSE_CHANGED;
            outputBuffer->currentModifiers = 0UL;
            outputBuffer->currentVirtualKey = 0UL;
            outputBuffer->currentSnapshotHash = 0ULL;
            operationChanged = TRUE;
            status = STATUS_SUCCESS;
            __leave;
        }

        newBucketIndex = requestSnapshot.newVirtualKey & (KSW_HOTKEY_BUCKET_COUNT - 1UL);
        status = kswHotkeyFindConflict(
            tableAddress,
            (ULONG_PTR)requestSnapshot.hotkeyObject,
            (USHORT)requestSnapshot.newModifiers,
            requestSnapshot.newVirtualKey);
        if (!NT_SUCCESS(status)) {
            outputBuffer->status = status == STATUS_OBJECT_NAME_COLLISION ?
                KSWORD_ARK_KEYBOARD_MUTATION_STATUS_CONFLICT :
                KSWORD_ARK_KEYBOARD_MUTATION_STATUS_OPERATION_FAILED;
            __leave;
        }
        if (beforeView.modifiers == (USHORT)requestSnapshot.newModifiers &&
            beforeView.virtualKey == requestSnapshot.newVirtualKey) {
            outputBuffer->status = KSWORD_ARK_KEYBOARD_MUTATION_STATUS_OK;
            outputBuffer->responseFlags |= KSWORD_ARK_KEYBOARD_MUTATION_RESPONSE_OTHER_BYTES_SAME;
            status = STATUS_SUCCESS;
            __leave;
        }

        RtlZeroMemory(&afterView, sizeof(afterView));
        status = kswHotkeyWriteEdit(
            tableAddress,
            oldLinkAddress,
            requestSnapshot.expectedBucketIndex,
            newBucketIndex,
            (ULONG_PTR)requestSnapshot.hotkeyObject,
            &beforeView,
            (USHORT)requestSnapshot.newModifiers,
            requestSnapshot.newVirtualKey,
            &afterView,
            &rolledBack);
        if (!NT_SUCCESS(status)) {
            outputBuffer->status = KSWORD_ARK_KEYBOARD_MUTATION_STATUS_OPERATION_FAILED;
            if (rolledBack) {
                outputBuffer->responseFlags |= KSWORD_ARK_KEYBOARD_MUTATION_RESPONSE_ROLLED_BACK;
            }
            __leave;
        }
        *(volatile ULONG_PTR*)(runtime.layout.sessionGlobals + KSW_HOTKEY_SESSION_CACHE_OFFSET) = 0U;
        KeMemoryBarrier();
        outputBuffer->status = KSWORD_ARK_KEYBOARD_MUTATION_STATUS_OK;
        outputBuffer->responseFlags |=
            KSWORD_ARK_KEYBOARD_MUTATION_RESPONSE_CHANGED |
            KSWORD_ARK_KEYBOARD_MUTATION_RESPONSE_OTHER_BYTES_SAME;
        if (newBucketIndex != requestSnapshot.expectedBucketIndex) {
            outputBuffer->responseFlags |= KSWORD_ARK_KEYBOARD_MUTATION_RESPONSE_REBUCKETED;
        }
        outputBuffer->currentBucketIndex = newBucketIndex;
        outputBuffer->currentModifiers = afterView.modifiers;
        outputBuffer->currentVirtualKey = afterView.virtualKey;
        outputBuffer->currentSnapshotHash = afterView.snapshotHash;
        operationChanged = TRUE;
        status = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        outputBuffer->status = KSWORD_ARK_KEYBOARD_MUTATION_STATUS_OPERATION_FAILED;
    }

    if (critEntered) {
        __try {
            runtime.leaveCrit();
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
            outputBuffer->status = KSWORD_ARK_KEYBOARD_MUTATION_STATUS_OPERATION_FAILED;
        }
    }
    if (!operationChanged && outputBuffer->status == KSWORD_ARK_KEYBOARD_MUTATION_STATUS_OK) {
        outputBuffer->currentBucketIndex = requestSnapshot.expectedBucketIndex;
    }
    outputBuffer->lastStatus = status;
    return STATUS_SUCCESS;
}
