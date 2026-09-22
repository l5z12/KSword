/*++

Module Name:

    keyboard_query.c

Abstract:

    Read-only win32k keyboard hotkey and keyboard hook enumeration helpers.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_keyboard.h"
#include "../kernel/hook_scan_support.h"
#include "keyboard_internal.h"

#include <ntstrsafe.h>

#ifndef STATUS_NOT_FOUND
#define STATUS_NOT_FOUND ((NTSTATUS)0xC0000225L)
#endif

#define KSWORD_ARK_KEYBOARD_HOTKEY_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_ENUM_KEYBOARD_HOTKEYS_RESPONSE) - sizeof(KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY))

#define KSWORD_ARK_KEYBOARD_HOOK_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_ENUM_KEYBOARD_HOOKS_RESPONSE) - sizeof(KSWORD_ARK_KEYBOARD_HOOK_ENTRY))

#define KSWORD_ARK_KEYBOARD_HOTKEY_BUCKETS 0x80UL
#define KSWORD_ARK_KEYBOARD_CHAIN_WALK_LIMIT 512UL
#define KSWORD_ARK_KEYBOARD_PROCESS_WALK_LIMIT 4096UL
#define KSWORD_ARK_KEYBOARD_THREAD_WALK_LIMIT 65536UL

// Conservative default offsets for the current win32kfull!NtUserSetWindowsHookEx/IsHotKey form.
#define KSWORD_ARK_KEYBOARD_HOTKEY_THREADINFO_OFFSET 0x00UL
#define KSWORD_ARK_KEYBOARD_HOTKEY_WINDOW_OFFSET     0x10UL
#define KSWORD_ARK_KEYBOARD_HOTKEY_FLAGS2_OFFSET     0x22UL
#define KSWORD_ARK_KEYBOARD_HOTKEY_CALLBACK_OFFSET   0x08UL
#define KSWORD_ARK_KEYBOARD_HOTKEY_DESTINATION_OFFSET 0x18UL
#define KSWORD_ARK_KEYBOARD_HOTKEY_CHILD_LIST_OFFSET 0x38UL
#define KSWORD_ARK_KEYBOARD_HOTKEY_OBJECT_SIZE       0x48UL
#define KSWORD_ARK_KEYBOARD_HOTKEY_NEXT_V26100_OFFSET 0x30UL
#define KSWORD_ARK_KEYBOARD_HOTKEY_MODIFIERS_V26100_OFFSET 0x20UL
#define KSWORD_ARK_KEYBOARD_HOTKEY_VK_V26100_OFFSET  0x24UL
#define KSWORD_ARK_KEYBOARD_HOTKEY_PLACEHOLDER_FLAG  0x0100U

#define KSWORD_ARK_HOOK_THREAD_ARRAY_OFFSET        0x3C0UL
#define KSWORD_ARK_HOOK_DESKTOP_INFO_OFFSET        0x1F8UL
#define KSWORD_ARK_HOOK_DESKTOP_ARRAY_OFFSET       0x28UL
#define KSWORD_ARK_HOOK_NEXT_OFFSET                0x28UL
#define KSWORD_ARK_HOOK_TYPE_OFFSET                0x30UL
#define KSWORD_ARK_HOOK_PROCEDURE_OFFSET           0x38UL
#define KSWORD_ARK_HOOK_FLAGS_OFFSET               0x40UL
#define KSWORD_ARK_HOOK_MODULE_ID_OFFSET           0x44UL
#define KSWORD_ARK_HOOK_TARGET_THREAD_INFO_OFFSET  0x48UL

typedef PVOID(NTAPI* KswordUserGetSiloGlobalsFn)(VOID);

typedef PEPROCESS(NTAPI* KswordPsGetNextProcessFn)(
    _In_opt_ PEPROCESS process
    );

typedef PETHREAD(NTAPI* KswordPsGetNextProcessThreadFn)(
    _In_ PEPROCESS process,
    _In_opt_ PETHREAD thread
    );

typedef PVOID(NTAPI* KswordPsGetThreadWiN32ThreadFn)(
    _In_ PETHREAD thread
    );

NTSYSAPI
PVOID
NTAPI
RtlFindExportedRoutineByName(
    _In_ PVOID imageBase,
    _In_z_ PCSTR routineName
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

static BOOLEAN
KswordARKKeyboardLooksLikeKernelPointer(
    _In_ ULONG_PTR value
    )
{
#if defined(_M_AMD64)
    return value >= 0xFFFF000000000000ULL ? TRUE : FALSE;
#else
    return Value >= 0x80000000UL ? TRUE : FALSE;
#endif
}

ULONG64
kswordArkKeyboardHashHotkeyObject(
    _In_reads_bytes_(objectBytes) const UCHAR* object,
    _In_ SIZE_T objectBytes
    )
{
    ULONG64 hashValue = 14695981039346656037ULL;
    SIZE_T byteIndex = 0U;

    if (object == NULL || objectBytes == 0U) {
        return 0ULL;
    }

    for (byteIndex = 0U; byteIndex < objectBytes; ++byteIndex) {
        hashValue ^= (ULONG64)object[byteIndex];
        hashValue *= 1099511628211ULL;
    }

    return hashValue;
}

static BOOLEAN
kswordArkKeyboardReadPointer(
    _In_ ULONG_PTR address,
    _Out_ ULONG_PTR* valueOut
    )
{
    PVOID pointerValue = NULL;

    if (valueOut == NULL) {
        return FALSE;
    }
    *valueOut = 0U;
    if (address == 0U) {
        return FALSE;
    }

    if (!kswordArkHookReadMemorySafe((const VOID*)address, &pointerValue, sizeof(pointerValue))) {
        return FALSE;
    }

    *valueOut = (ULONG_PTR)pointerValue;
    return TRUE;
}

static BOOLEAN
kswordArkKeyboardReadUlong(
    _In_ ULONG_PTR address,
    _Out_ ULONG* valueOut
    )
{
    if (valueOut == NULL) {
        return FALSE;
    }
    *valueOut = 0UL;
    if (address == 0U) {
        return FALSE;
    }
    return kswordArkHookReadMemorySafe((const VOID*)address, valueOut, sizeof(*valueOut));
}

static BOOLEAN
kswordArkKeyboardReadUshort(
    _In_ ULONG_PTR address,
    _Out_ USHORT* valueOut
    )
{
    if (valueOut == NULL) {
        return FALSE;
    }
    *valueOut = 0U;
    if (address == 0U) {
        return FALSE;
    }
    return kswordArkHookReadMemorySafe((const VOID*)address, valueOut, sizeof(*valueOut));
}

static BOOLEAN
kswordArkKeyboardFindModuleByName(
    _In_ const KswHookSystemModuleInformation* moduleInfo,
    _In_z_ PCSTR moduleName,
    _Out_ KswHookSystemModuleEntry* moduleEntryOut
    )
{
    ULONG moduleIndex = 0UL;

    if (moduleInfo == NULL || moduleName == NULL || moduleEntryOut == NULL) {
        return FALSE;
    }
    RtlZeroMemory(moduleEntryOut, sizeof(*moduleEntryOut));

    for (moduleIndex = 0UL; moduleIndex < moduleInfo->numberOfModules; ++moduleIndex) {
        const KswHookSystemModuleEntry* moduleEntry = &moduleInfo->modules[moduleIndex];
        const UCHAR* fileName = NULL;
        ULONG fileNameBytes = 0UL;

        kswordArkHookGetModuleFileName(moduleEntry, &fileName, &fileNameBytes);
        if (kswordArkHookBoundedAnsiEqualsInsensitive(fileName, fileNameBytes, moduleName)) {
            RtlCopyMemory(moduleEntryOut, moduleEntry, sizeof(*moduleEntryOut));
            return TRUE;
        }
    }

    return FALSE;
}

static KswordPsGetNextProcessThreadFn
kswordArkKeyboardResolvePsGetNextProcessThread(
    VOID
    )
{
    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, L"PsGetNextProcessThread");
    return (KswordPsGetNextProcessThreadFn)MmGetSystemRoutineAddress(&routineName);
}

static KswordPsGetNextProcessFn
kswordArkKeyboardResolvePsGetNextProcess(
    VOID
    )
{
    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, L"PsGetNextProcess");
    return (KswordPsGetNextProcessFn)MmGetSystemRoutineAddress(&routineName);
}

static KswordPsGetThreadWiN32ThreadFn
kswordArkKeyboardResolvePsGetThreadWin32Thread(
    VOID
    )
{
    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, L"PsGetThreadWin32Thread");
    return (KswordPsGetThreadWiN32ThreadFn)MmGetSystemRoutineAddress(&routineName);
}

static KswordUserGetSiloGlobalsFn
kswordArkKeyboardResolveUserGetSiloGlobals(
    _In_ const KswHookSystemModuleEntry* win32kbaseEntry
    )
{
    if (win32kbaseEntry == NULL || win32kbaseEntry->imageBase == NULL) {
        return NULL;
    }

    return (KswordUserGetSiloGlobalsFn)RtlFindExportedRoutineByName(
        win32kbaseEntry->imageBase,
        "UserGetSiloGlobals");
}

static BOOLEAN
kswordArkKeyboardResolveIsHotKeyBody(
    _In_ const KswHookSystemModuleEntry* win32kfullEntry,
    _Out_ ULONG_PTR* isHotKeyAddressOut
    )
{
    ULONG_PTR editionAddress = 0U;
    UCHAR bytes[32] = { 0 };
    ULONG byteIndex = 0UL;

    if (win32kfullEntry == NULL || isHotKeyAddressOut == NULL) {
        return FALSE;
    }
    *isHotKeyAddressOut = 0U;

    editionAddress = (ULONG_PTR)RtlFindExportedRoutineByName(
        win32kfullEntry->imageBase,
        "EditionIsHotKey");
    if (editionAddress == 0U ||
        editionAddress < (ULONG_PTR)win32kfullEntry->imageBase ||
        editionAddress >= ((ULONG_PTR)win32kfullEntry->imageBase + win32kfullEntry->imageSize)) {
        return FALSE;
    }

    if (!kswordArkHookReadMemorySafe((const VOID*)editionAddress, bytes, sizeof(bytes))) {
        return FALSE;
    }

    for (byteIndex = 0UL; byteIndex + 5UL <= sizeof(bytes); ++byteIndex) {
        if (bytes[byteIndex] == 0xE8U) {
            LONG relativeOffset = 0;
            ULONG_PTR targetAddress = 0U;

            RtlCopyMemory(&relativeOffset, bytes + byteIndex + 1UL, sizeof(relativeOffset));
            targetAddress = editionAddress + byteIndex + 5UL + (LONG_PTR)relativeOffset;
            if (targetAddress >= (ULONG_PTR)win32kfullEntry->imageBase &&
                targetAddress < ((ULONG_PTR)win32kfullEntry->imageBase + win32kfullEntry->imageSize)) {
                *isHotKeyAddressOut = targetAddress;
                return TRUE;
            }
        }
    }

    return FALSE;
}

static BOOLEAN
kswordArkKeyboardResolveHotkeyLayout(
    _In_ ULONG_PTR isHotKeyAddress,
    _Out_ ULONG* tableOffsetOut,
    _Out_ ULONG_PTR* tableBaseOut,
    _Out_ ULONG* nextOffsetOut,
    _Out_ ULONG* modifiersOffsetOut,
    _Out_ ULONG* vkOffsetOut,
    _Out_ ULONG* idOffsetOut
    )
{
    UCHAR bytes[192] = { 0 };
    ULONG index = 0UL;
    ULONG tableOffset = 0UL;
    ULONG_PTR tableBase = 0U;
    ULONG nextOffset = 0UL;
    ULONG modifiersOffset = 0UL;
    ULONG vkOffset = 0UL;

    if (isHotKeyAddress == 0U ||
        tableOffsetOut == NULL ||
        tableBaseOut == NULL ||
        nextOffsetOut == NULL ||
        modifiersOffsetOut == NULL ||
        vkOffsetOut == NULL ||
        idOffsetOut == NULL) {
        return FALSE;
    }

    *tableOffsetOut = 0UL;
    *tableBaseOut = 0U;
    *nextOffsetOut = 0UL;
    *modifiersOffsetOut = 0UL;
    *vkOffsetOut = 0UL;
    *idOffsetOut = 0UL;

    if (!kswordArkHookReadMemorySafe((const VOID*)isHotKeyAddress, bytes, sizeof(bytes))) {
        return FALSE;
    }

    for (index = 0UL; index + 8UL <= sizeof(bytes); ++index) {
        if (bytes[index] == 0x4AU &&
            bytes[index + 1UL] == 0x8BU &&
            bytes[index + 2UL] == 0xBCU &&
            bytes[index + 3UL] == 0xC0U) {
            RtlCopyMemory(&tableOffset, bytes + index + 4UL, sizeof(tableOffset));
        }
        if (bytes[index] == 0x48U &&
            bytes[index + 1UL] == 0x8DU &&
            bytes[index + 2UL] == 0x1DU) {
            LONG relativeOffset = 0;

            RtlCopyMemory(&relativeOffset, bytes + index + 3UL, sizeof(relativeOffset));
            tableBase = isHotKeyAddress + index + 7UL + (LONG_PTR)relativeOffset;
        }
        if (bytes[index] == 0x0FU &&
            bytes[index + 1UL] == 0xB7U &&
            bytes[index + 2UL] == 0x47U) {
            modifiersOffset = (ULONG)bytes[index + 3UL];
        }
        if (bytes[index] == 0x0FU &&
            bytes[index + 1UL] == 0xB7U &&
            bytes[index + 2UL] == 0x43U) {
            modifiersOffset = (ULONG)bytes[index + 3UL];
        }
        if (bytes[index] == 0x39U &&
            bytes[index + 1UL] == 0x77U) {
            vkOffset = (ULONG)bytes[index + 2UL];
        }
        if (bytes[index] == 0x39U &&
            bytes[index + 1UL] == 0x7BU) {
            vkOffset = (ULONG)bytes[index + 2UL];
        }
        if (bytes[index] == 0x48U &&
            bytes[index + 1UL] == 0x8BU &&
            bytes[index + 2UL] == 0x7FU) {
            nextOffset = (ULONG)bytes[index + 3UL];
        }
        if (bytes[index] == 0x48U &&
            bytes[index + 1UL] == 0x8BU &&
            bytes[index + 2UL] == 0x5BU) {
            nextOffset = (ULONG)bytes[index + 3UL];
        }
    }

    if ((tableOffset == 0UL && tableBase == 0U) ||
        nextOffset == 0UL ||
        modifiersOffset == 0UL ||
        vkOffset == 0UL) {
        return FALSE;
    }

    *tableOffsetOut = tableOffset;
    *tableBaseOut = tableBase;
    *nextOffsetOut = nextOffset;
    *modifiersOffsetOut = modifiersOffset;
    *vkOffsetOut = vkOffset;
    *idOffsetOut = vkOffset + sizeof(ULONG);
    return TRUE;
}

NTSTATUS
kswordArkKeyboardResolveHotkeyRuntime(
    _Out_ KswKeyboardHotkeyRuntime* runtimeOut
    )
{
    KswHookSystemModuleInformation* moduleInfo = NULL;
    ULONG moduleInfoBytes = 0UL;
    KswHookSystemModuleEntry win32kfullEntry;
    KswHookSystemModuleEntry win32kbaseEntry;
    KswordUserGetSiloGlobalsFn userGetSiloGlobals = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (runtimeOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(runtimeOut, sizeof(*runtimeOut));

    status = kswordArkHookBuildModuleSnapshot(&moduleInfo, &moduleInfoBytes);
    if (!NT_SUCCESS(status) || moduleInfo == NULL || moduleInfoBytes == 0UL) {
        return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
    }

    if (!kswordArkKeyboardFindModuleByName(moduleInfo, "win32kfull.sys", &win32kfullEntry) ||
        !kswordArkKeyboardFindModuleByName(moduleInfo, "win32kbase.sys", &win32kbaseEntry)) {
        status = STATUS_NOT_FOUND;
        goto Cleanup;
    }

    runtimeOut->win32kfullBase = win32kfullEntry.imageBase;
    runtimeOut->win32kfullSize = win32kfullEntry.imageSize;
    runtimeOut->win32kbaseBase = win32kbaseEntry.imageBase;
    runtimeOut->win32kbaseSize = win32kbaseEntry.imageSize;
    if (!kswordArkKeyboardResolveIsHotKeyBody(
            &win32kfullEntry,
            &runtimeOut->isHotKeyAddress) ||
        !kswordArkKeyboardResolveHotkeyLayout(
            runtimeOut->isHotKeyAddress,
            &runtimeOut->tableOffset,
            &runtimeOut->tableBase,
            &runtimeOut->nextOffset,
            &runtimeOut->modifiersOffset,
            &runtimeOut->vkOffset,
            &runtimeOut->idOffset)) {
        status = STATUS_NOT_FOUND;
        goto Cleanup;
    }

    userGetSiloGlobals = kswordArkKeyboardResolveUserGetSiloGlobals(&win32kbaseEntry);
    if (userGetSiloGlobals != NULL) {
        __try {
            runtimeOut->sessionGlobals = (ULONG_PTR)userGetSiloGlobals();
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
            runtimeOut->sessionGlobals = 0U;
            goto Cleanup;
        }
    }

    if (runtimeOut->tableBase == 0U && runtimeOut->sessionGlobals == 0U) {
        status = STATUS_INVALID_DEVICE_STATE;
        goto Cleanup;
    }
    status = STATUS_SUCCESS;

Cleanup:
    ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
    if (!NT_SUCCESS(status)) {
        RtlZeroMemory(runtimeOut, sizeof(*runtimeOut));
    }
    return status;
}

static VOID
kswordArkKeyboardFillHotkeyThreadIdentity(
    _In_ ULONG_PTR threadInfo,
    _Out_ ULONG_PTR* threadObjectOut,
    _Out_ ULONG* processIdOut,
    _Out_ ULONG* threadIdOut
    )
{
    ULONG_PTR threadObject = 0U;

    if (threadObjectOut != NULL) {
        *threadObjectOut = 0U;
    }
    if (processIdOut != NULL) {
        *processIdOut = 0UL;
    }
    if (threadIdOut != NULL) {
        *threadIdOut = 0UL;
    }

    if (threadInfo == 0U ||
        !kswordArkKeyboardReadPointer(threadInfo, &threadObject) ||
        !KswordARKKeyboardLooksLikeKernelPointer(threadObject)) {
        return;
    }

    if (threadObjectOut != NULL) {
        *threadObjectOut = threadObject;
    }

    __try {
        if (processIdOut != NULL) {
            *processIdOut = HandleToULong(PsGetThreadProcessId((PETHREAD)threadObject));
        }
        if (threadIdOut != NULL) {
            *threadIdOut = HandleToULong(PsGetThreadId((PETHREAD)threadObject));
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        if (processIdOut != NULL) {
            *processIdOut = 0UL;
        }
        if (threadIdOut != NULL) {
            *threadIdOut = 0UL;
        }
    }
}

static VOID
kswordArkKeyboardAppendHotkeyEntry(
    _Inout_ KSWORD_ARK_ENUM_KEYBOARD_HOTKEYS_RESPONSE* response,
    _In_ ULONG entryCapacity,
    _In_ ULONG maxEntries,
    _In_ ULONG_PTR sessionGlobals,
    _In_ ULONG bucketIndex,
    _In_ ULONG depth,
    _In_ ULONG_PTR hotkeyObject,
    _In_ ULONG nextOffset,
    _In_ ULONG modifiersOffset,
    _In_ ULONG vkOffset,
    _In_ ULONG idOffset,
    _In_ ULONG requestFlags,
    _In_ ULONG filterProcessId
    )
{
    KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY tempEntry;
    USHORT modifiers = 0U;
    USHORT flags2 = 0U;
    ULONG_PTR nextHotkey = 0U;
    ULONG_PTR threadInfo = 0U;
    ULONG_PTR threadObject = 0U;
    ULONG_PTR windowObject = 0U;
    UCHAR objectBytes[KSWORD_ARK_KEYBOARD_HOTKEY_OBJECT_SIZE] = { 0 };
    ULONG_PTR callbackAddress = 0U;
    ULONG_PTR destinationHandle = 0U;
    ULONG_PTR childListFlink = 0U;
    ULONG_PTR childListBlink = 0U;

    if (response == NULL || hotkeyObject == 0U) {
        return;
    }

    RtlZeroMemory(&tempEntry, sizeof(tempEntry));
    tempEntry.source = KSWORD_ARK_KEYBOARD_SOURCE_WIN32K_HOTKEY_TABLE;
    tempEntry.status = KSWORD_ARK_KEYBOARD_ENUM_STATUS_OK;
    tempEntry.bucketIndex = bucketIndex;
    tempEntry.depth = depth;
    tempEntry.hotkeyObject = (ULONG64)hotkeyObject;
    tempEntry.sessionGlobals = (ULONG64)sessionGlobals;

    if (!kswordArkKeyboardReadPointer(hotkeyObject + nextOffset, &nextHotkey)) {
        tempEntry.status = KSWORD_ARK_KEYBOARD_ENUM_STATUS_PARTIAL;
    }
    if (!kswordArkKeyboardReadPointer(hotkeyObject + KSWORD_ARK_KEYBOARD_HOTKEY_THREADINFO_OFFSET, &threadInfo)) {
        tempEntry.status = KSWORD_ARK_KEYBOARD_ENUM_STATUS_PARTIAL;
    }
    (VOID)kswordArkKeyboardReadPointer(hotkeyObject + KSWORD_ARK_KEYBOARD_HOTKEY_WINDOW_OFFSET, &windowObject);
    if (!kswordArkKeyboardReadUshort(hotkeyObject + modifiersOffset, &modifiers)) {
        tempEntry.status = KSWORD_ARK_KEYBOARD_ENUM_STATUS_READ_FAILED;
    }
    if (!kswordArkKeyboardReadUshort(hotkeyObject + KSWORD_ARK_KEYBOARD_HOTKEY_FLAGS2_OFFSET, &flags2)) {
        flags2 = 0U;
    }
    if (!kswordArkKeyboardReadUlong(hotkeyObject + vkOffset, &tempEntry.virtualKey)) {
        tempEntry.status = KSWORD_ARK_KEYBOARD_ENUM_STATUS_READ_FAILED;
    }
    if (!kswordArkKeyboardReadUlong(hotkeyObject + idOffset, &tempEntry.hotkeyId)) {
        tempEntry.hotkeyId = 0UL;
    }

    tempEntry.nextHotkeyObject = (ULONG64)nextHotkey;
    tempEntry.threadInfo = (ULONG64)threadInfo;
    tempEntry.windowObject = (ULONG64)windowObject;
    tempEntry.modifiers = (ULONG)modifiers;
    tempEntry.modifierFlags2 = (ULONG)flags2;
    tempEntry.windowHandle = (ULONG64)windowObject;
    tempEntry.entryFlags = KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY_FLAG_MAIN;
    if (nextOffset == KSWORD_ARK_KEYBOARD_HOTKEY_NEXT_V26100_OFFSET &&
        modifiersOffset == KSWORD_ARK_KEYBOARD_HOTKEY_MODIFIERS_V26100_OFFSET &&
        vkOffset == KSWORD_ARK_KEYBOARD_HOTKEY_VK_V26100_OFFSET &&
        idOffset == (KSWORD_ARK_KEYBOARD_HOTKEY_VK_V26100_OFFSET + sizeof(ULONG)) &&
        kswordArkHookReadMemorySafe(
            (const VOID*)hotkeyObject,
            objectBytes,
            sizeof(objectBytes))) {
        RtlCopyMemory(
            &callbackAddress,
            objectBytes + KSWORD_ARK_KEYBOARD_HOTKEY_CALLBACK_OFFSET,
            sizeof(callbackAddress));
        RtlCopyMemory(
            &destinationHandle,
            objectBytes + KSWORD_ARK_KEYBOARD_HOTKEY_DESTINATION_OFFSET,
            sizeof(destinationHandle));
        RtlCopyMemory(
            &childListFlink,
            objectBytes + KSWORD_ARK_KEYBOARD_HOTKEY_CHILD_LIST_OFFSET,
            sizeof(childListFlink));
        RtlCopyMemory(
            &childListBlink,
            objectBytes + KSWORD_ARK_KEYBOARD_HOTKEY_CHILD_LIST_OFFSET + sizeof(PVOID),
            sizeof(childListBlink));
        tempEntry.callbackAddress = (ULONG64)callbackAddress;
        tempEntry.destinationHandle = (ULONG64)destinationHandle;
        tempEntry.childListFlink = (ULONG64)childListFlink;
        tempEntry.childListBlink = (ULONG64)childListBlink;
        tempEntry.objectSize = (ULONG)sizeof(objectBytes);
        tempEntry.snapshotHash = kswordArkKeyboardHashHotkeyObject(objectBytes, sizeof(objectBytes));
        if (childListFlink != (hotkeyObject + KSWORD_ARK_KEYBOARD_HOTKEY_CHILD_LIST_OFFSET) ||
            childListBlink != (hotkeyObject + KSWORD_ARK_KEYBOARD_HOTKEY_CHILD_LIST_OFFSET)) {
            tempEntry.entryFlags |= KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY_FLAG_HAS_CHILDREN;
        }
        if ((flags2 & KSWORD_ARK_KEYBOARD_HOTKEY_PLACEHOLDER_FLAG) != 0U) {
            tempEntry.entryFlags |= KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY_FLAG_PLACEHOLDER;
        }
        if (callbackAddress != 0U) {
            tempEntry.entryFlags |= KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY_FLAG_CALLBACK;
        }
        if (threadInfo != 0U && callbackAddress == 0U && flags2 == 0U &&
            tempEntry.virtualKey != 0UL && tempEntry.virtualKey <= 0xFFUL &&
            (tempEntry.modifiers & ~0x0000400FUL) == 0UL &&
            childListFlink == (hotkeyObject + KSWORD_ARK_KEYBOARD_HOTKEY_CHILD_LIST_OFFSET) &&
            childListBlink == (hotkeyObject + KSWORD_ARK_KEYBOARD_HOTKEY_CHILD_LIST_OFFSET) &&
            bucketIndex == (tempEntry.virtualKey & (KSWORD_ARK_KEYBOARD_HOTKEY_BUCKETS - 1UL))) {
            tempEntry.entryFlags |= KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY_FLAG_MUTABLE;
        }
    }
    kswordArkKeyboardFillHotkeyThreadIdentity(
        threadInfo,
        &threadObject,
        &tempEntry.processId,
        &tempEntry.threadId);
    tempEntry.threadObject = (ULONG64)threadObject;
    if ((requestFlags & KSWORD_ARK_KEYBOARD_ENUM_FLAG_FILTER_PROCESS) != 0UL &&
        filterProcessId != 0UL &&
        tempEntry.processId != 0UL &&
        tempEntry.processId != filterProcessId) {
        return;
    }

    if (response->totalCount < maxEntries) {
        response->totalCount += 1UL;
    }

    if (response->returnedCount >= entryCapacity) {
        response->status = KSWORD_ARK_KEYBOARD_ENUM_STATUS_BUFFER_TRUNCATED;
        return;
    }

    (VOID)RtlStringCchPrintfW(
        tempEntry.detail,
        KSWORD_ARK_KEYBOARD_DETAIL_CHARS,
        L"bucket=%lu depth=%lu",
        bucketIndex,
        depth);

    RtlCopyMemory(
        &response->entries[response->returnedCount],
        &tempEntry,
        sizeof(tempEntry));
    response->returnedCount += 1UL;
}

static BOOLEAN
kswordArkKeyboardHookAlreadySeen(
    _In_ const KSWORD_ARK_ENUM_KEYBOARD_HOOKS_RESPONSE* response,
    _In_ ULONG_PTR hookObject
    )
{
    ULONG index = 0UL;

    if (response == NULL || hookObject == 0U) {
        return FALSE;
    }

    for (index = 0UL; index < response->returnedCount; ++index) {
        if ((ULONG_PTR)response->entries[index].hookObject == hookObject) {
            return TRUE;
        }
    }

    return FALSE;
}

static VOID
kswordArkKeyboardAppendHookEntry(
    _Inout_ KSWORD_ARK_ENUM_KEYBOARD_HOOKS_RESPONSE* response,
    _In_ ULONG entryCapacity,
    _In_ ULONG maxEntries,
    _In_ ULONG source,
    _In_ ULONG hookScope,
    _In_ ULONG_PTR chainHead,
    _In_ ULONG_PTR hookObject,
    _In_ ULONG processId,
    _In_ ULONG threadId
    )
{
    KSWORD_ARK_KEYBOARD_HOOK_ENTRY tempEntry;
    ULONG hookType = 0UL;
    ULONG hookFlags = 0UL;
    ULONG moduleId = 0UL;
    ULONG_PTR nextHook = 0U;
    ULONG_PTR procedureOffset = 0U;
    ULONG_PTR targetThreadInfo = 0U;

    if (response == NULL || hookObject == 0U) {
        return;
    }

    if (kswordArkKeyboardHookAlreadySeen(response, hookObject)) {
        return;
    }

    RtlZeroMemory(&tempEntry, sizeof(tempEntry));
    tempEntry.source = source;
    tempEntry.status = KSWORD_ARK_KEYBOARD_ENUM_STATUS_OK;
    tempEntry.hookScope = hookScope;
    tempEntry.processId = processId;
    tempEntry.threadId = threadId;
    tempEntry.hookObject = (ULONG64)hookObject;
    tempEntry.chainHead = (ULONG64)chainHead;

    if (!kswordArkKeyboardReadUlong(hookObject + KSWORD_ARK_HOOK_TYPE_OFFSET, &hookType)) {
        tempEntry.status = KSWORD_ARK_KEYBOARD_ENUM_STATUS_READ_FAILED;
    }
    if (hookType != KSWORD_ARK_KEYBOARD_HOOK_TYPE_KEYBOARD &&
        hookType != KSWORD_ARK_KEYBOARD_HOOK_TYPE_KEYBOARD_LL) {
        return;
    }

    if (response->totalCount < maxEntries) {
        response->totalCount += 1UL;
    }

    if (response->returnedCount >= entryCapacity) {
        response->status = KSWORD_ARK_KEYBOARD_ENUM_STATUS_BUFFER_TRUNCATED;
        return;
    }

    (VOID)kswordArkKeyboardReadPointer(hookObject + KSWORD_ARK_HOOK_NEXT_OFFSET, &nextHook);
    (VOID)kswordArkKeyboardReadUlong(hookObject + KSWORD_ARK_HOOK_FLAGS_OFFSET, &hookFlags);
    (VOID)kswordArkKeyboardReadUlong(hookObject + KSWORD_ARK_HOOK_MODULE_ID_OFFSET, &moduleId);
    (VOID)kswordArkKeyboardReadPointer(hookObject + KSWORD_ARK_HOOK_PROCEDURE_OFFSET, &procedureOffset);
    (VOID)kswordArkKeyboardReadPointer(hookObject + KSWORD_ARK_HOOK_TARGET_THREAD_INFO_OFFSET, &targetThreadInfo);

    tempEntry.hookType = hookType;
    tempEntry.flags = hookFlags;
    tempEntry.moduleId = moduleId;
    tempEntry.nextHookObject = (ULONG64)nextHook;
    tempEntry.procedureOffset = (ULONG64)procedureOffset;
    tempEntry.targetThreadInfo = (ULONG64)targetThreadInfo;
    (VOID)RtlStringCchPrintfW(
        tempEntry.detail,
        KSWORD_ARK_KEYBOARD_DETAIL_CHARS,
        L"scope=%lu chain=0x%p",
        hookScope,
        (PVOID)chainHead);

    RtlCopyMemory(
        &response->entries[response->returnedCount],
        &tempEntry,
        sizeof(tempEntry));
    response->returnedCount += 1UL;
}

static VOID
kswordArkKeyboardWalkHookChain(
    _Inout_ KSWORD_ARK_ENUM_KEYBOARD_HOOKS_RESPONSE* response,
    _In_ ULONG entryCapacity,
    _In_ ULONG maxEntries,
    _In_ ULONG source,
    _In_ ULONG hookScope,
    _In_ ULONG_PTR chainHead,
    _In_ ULONG processId,
    _In_ ULONG threadId
    )
{
    ULONG_PTR hookObject = 0U;
    ULONG depth = 0UL;

    if (response == NULL || chainHead == 0U) {
        return;
    }

    if (!kswordArkKeyboardReadPointer(chainHead, &hookObject)) {
        return;
    }

    while (hookObject != 0U && depth < KSWORD_ARK_KEYBOARD_CHAIN_WALK_LIMIT) {
        ULONG_PTR nextHook = 0U;

        kswordArkKeyboardAppendHookEntry(
            response,
            entryCapacity,
            maxEntries,
            source,
            hookScope,
            chainHead,
            hookObject,
            processId,
            threadId);

        if (!kswordArkKeyboardReadPointer(hookObject + KSWORD_ARK_HOOK_NEXT_OFFSET, &nextHook)) {
            break;
        }
        if (nextHook == hookObject) {
            break;
        }
        hookObject = nextHook;
        ++depth;
    }
}

static VOID
kswordArkKeyboardEnumerateHookChainsForThread(
    _Inout_ KSWORD_ARK_ENUM_KEYBOARD_HOOKS_RESPONSE* response,
    _In_ ULONG entryCapacity,
    _In_ ULONG maxEntries,
    _In_ PETHREAD threadObject,
    _In_ ULONG processId,
    _In_ KswordPsGetThreadWiN32ThreadFn psGetThreadWin32Thread,
    _In_ ULONG flags
    )
{
    static const ULONG kHookTypes[] = {
        KSWORD_ARK_KEYBOARD_HOOK_TYPE_KEYBOARD,
        KSWORD_ARK_KEYBOARD_HOOK_TYPE_KEYBOARD_LL
    };
    PVOID threadInfoPointer = NULL;
    ULONG_PTR threadInfo = 0U;
    ULONG threadId = 0UL;
    ULONG index = 0UL;

    if (response == NULL || threadObject == NULL || psGetThreadWin32Thread == NULL) {
        return;
    }

    __try {
        threadInfoPointer = psGetThreadWin32Thread(threadObject);
        threadId = HandleToULong(PsGetThreadId(threadObject));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        threadInfoPointer = NULL;
    }

    threadInfo = (ULONG_PTR)threadInfoPointer;
    if (threadInfo == 0U) {
        return;
    }

    for (index = 0UL; index < RTL_NUMBER_OF(kHookTypes); ++index) {
        ULONG hookType = kHookTypes[index];
        ULONG_PTR chainHead = 0U;

        if ((flags & KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_THREAD_HOOKS) != 0UL) {
            chainHead = threadInfo +
                KSWORD_ARK_HOOK_THREAD_ARRAY_OFFSET +
                ((ULONG_PTR)(hookType + 1UL) * sizeof(PVOID));
            kswordArkKeyboardWalkHookChain(
                response,
                entryCapacity,
                maxEntries,
                KSWORD_ARK_KEYBOARD_SOURCE_WIN32K_THREAD_HOOK_CHAIN,
                KSWORD_ARK_KEYBOARD_HOOK_SCOPE_THREAD,
                chainHead,
                processId,
                threadId);
        }

        if ((flags & KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_GLOBAL_HOOKS) != 0UL) {
            ULONG_PTR desktopInfo = 0U;

            if (kswordArkKeyboardReadPointer(threadInfo + KSWORD_ARK_HOOK_DESKTOP_INFO_OFFSET, &desktopInfo) &&
                desktopInfo != 0U) {
                chainHead = desktopInfo +
                    KSWORD_ARK_HOOK_DESKTOP_ARRAY_OFFSET +
                    ((ULONG_PTR)(hookType + 1UL) * sizeof(PVOID));
                kswordArkKeyboardWalkHookChain(
                    response,
                    entryCapacity,
                    maxEntries,
                    KSWORD_ARK_KEYBOARD_SOURCE_WIN32K_GLOBAL_HOOK_CHAIN,
                    KSWORD_ARK_KEYBOARD_HOOK_SCOPE_GLOBAL,
                    chainHead,
                    processId,
                    threadId);
            }
        }
    }
}

static VOID
kswordArkKeyboardEnumerateHookChainsForProcess(
    _Inout_ KSWORD_ARK_ENUM_KEYBOARD_HOOKS_RESPONSE* response,
    _In_ ULONG entryCapacity,
    _In_ ULONG maxEntries,
    _In_ PEPROCESS processObject,
    _In_ KswordPsGetNextProcessThreadFn PsGetNextProcessThread,
    _In_ KswordPsGetThreadWiN32ThreadFn psGetThreadWin32Thread,
    _In_ ULONG flags
    )
{
    DECLSPEC_ALIGN(16) UCHAR attachState[128];
    BOOLEAN attached = FALSE;
    PETHREAD threadCursor = NULL;
    ULONG processId = 0UL;
    ULONG threadWalkCount = 0UL;

    if (response == NULL ||
        processObject == NULL ||
        PsGetNextProcessThread == NULL ||
        psGetThreadWin32Thread == NULL) {
        return;
    }

    processId = HandleToULong(PsGetProcessId(processObject));
    if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
        RtlZeroMemory(attachState, sizeof(attachState));
        KeStackAttachProcess((PVOID)processObject, attachState);
        attached = TRUE;
    }

    threadCursor = PsGetNextProcessThread(processObject, NULL);
    while (threadCursor != NULL &&
        threadWalkCount < KSWORD_ARK_KEYBOARD_THREAD_WALK_LIMIT &&
        response->status != KSWORD_ARK_KEYBOARD_ENUM_STATUS_BUFFER_TRUNCATED) {
        PETHREAD nextThread = PsGetNextProcessThread(processObject, threadCursor);

        kswordArkKeyboardEnumerateHookChainsForThread(
            response,
            entryCapacity,
            maxEntries,
            threadCursor,
            processId,
            psGetThreadWin32Thread,
            flags);

        ObDereferenceObject(threadCursor);
        threadCursor = nextThread;
        threadWalkCount += 1UL;
    }

    if (threadCursor != NULL) {
        ObDereferenceObject(threadCursor);
        threadCursor = NULL;
        if (response->status != KSWORD_ARK_KEYBOARD_ENUM_STATUS_BUFFER_TRUNCATED) {
            response->status = KSWORD_ARK_KEYBOARD_ENUM_STATUS_PARTIAL;
            response->lastStatus = STATUS_BUFFER_OVERFLOW;
        }
    }

    if (attached) {
        KeUnstackDetachProcess(attachState);
    }
}

NTSTATUS
kswordArkDriverEnumerateKeyboardHotkeys(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_ENUM_KEYBOARD_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
{
    KSWORD_ARK_ENUM_KEYBOARD_HOTKEYS_RESPONSE* response = NULL;
    KswHookSystemModuleInformation* moduleInfo = NULL;
    ULONG moduleInfoBytes = 0UL;
    KswHookSystemModuleEntry win32kfullEntry;
    KswHookSystemModuleEntry win32kbaseEntry;
    KswordUserGetSiloGlobalsFn userGetSiloGlobals = NULL;
    ULONG requestFlags = KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_SYSTEM;
    ULONG maxEntries = 1024UL;
    ULONG entryCapacity = 0UL;
    ULONG_PTR isHotKeyAddress = 0U;
    ULONG_PTR sessionGlobals = 0U;
    ULONG_PTR tableBase = 0U;
    ULONG tableOffset = 0UL;
    ULONG nextOffset = 0UL;
    ULONG modifiersOffset = 0UL;
    ULONG vkOffset = 0UL;
    ULONG idOffset = 0UL;
    PEPROCESS attachProcess = NULL;
    DECLSPEC_ALIGN(16) UCHAR attachState[128];
    BOOLEAN attached = FALSE;
    BOOLEAN referencedProcess = FALSE;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bucketIndex = 0UL;

    if (outputBuffer == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < KSWORD_ARK_KEYBOARD_HOTKEY_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (request != NULL) {
        requestFlags = request->flags;
        if (request->maxEntries != 0UL) {
            maxEntries = request->maxEntries;
        }
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_ENUM_KEYBOARD_HOTKEYS_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_KEYBOARD_PROTOCOL_VERSION;
    response->entrySize = sizeof(KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY);
    response->status = KSWORD_ARK_KEYBOARD_ENUM_STATUS_UNKNOWN;
    response->flags = requestFlags;
    entryCapacity = (ULONG)((outputBufferLength - KSWORD_ARK_KEYBOARD_HOTKEY_RESPONSE_HEADER_SIZE) / sizeof(KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY));
    if (entryCapacity > maxEntries) {
        entryCapacity = maxEntries;
    }

    status = kswordArkHookBuildModuleSnapshot(&moduleInfo, &moduleInfoBytes);
    response->lastStatus = status;
    if (!NT_SUCCESS(status) || moduleInfo == NULL) {
        response->status = KSWORD_ARK_KEYBOARD_ENUM_STATUS_WIN32K_NOT_FOUND;
        *bytesWrittenOut = KSWORD_ARK_KEYBOARD_HOTKEY_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }

    if (!kswordArkKeyboardFindModuleByName(moduleInfo, "win32kfull.sys", &win32kfullEntry) ||
        !kswordArkKeyboardFindModuleByName(moduleInfo, "win32kbase.sys", &win32kbaseEntry)) {
        response->status = KSWORD_ARK_KEYBOARD_ENUM_STATUS_WIN32K_NOT_FOUND;
        goto Cleanup;
    }

    response->win32kBase = (ULONG64)(ULONG_PTR)win32kfullEntry.imageBase;
    userGetSiloGlobals = kswordArkKeyboardResolveUserGetSiloGlobals(&win32kbaseEntry);
    if (!kswordArkKeyboardResolveIsHotKeyBody(&win32kfullEntry, &isHotKeyAddress) ||
        !kswordArkKeyboardResolveHotkeyLayout(
            isHotKeyAddress,
            &tableOffset,
            &tableBase,
            &nextOffset,
            &modifiersOffset,
            &vkOffset,
            &idOffset)) {
        response->status = KSWORD_ARK_KEYBOARD_ENUM_STATUS_PATTERN_NOT_FOUND;
        response->lastStatus = STATUS_NOT_FOUND;
        goto Cleanup;
    }

    if (tableBase == 0U && userGetSiloGlobals == NULL) {
        response->status = KSWORD_ARK_KEYBOARD_ENUM_STATUS_SESSION_UNAVAILABLE;
        response->lastStatus = STATUS_PROCEDURE_NOT_FOUND;
        goto Cleanup;
    }

    response->tableOffset = tableOffset;
    response->hotkeyNextOffset = nextOffset;
    response->hotkeyModifiersOffset = modifiersOffset;
    response->hotkeyVkOffset = vkOffset;
    response->hotkeyIdOffset = idOffset;

    if (request != NULL && request->processId != 0UL) {
        status = PsLookupProcessByProcessId(ULongToHandle(request->processId), &attachProcess);
        response->lastStatus = status;
        if (!NT_SUCCESS(status)) {
            attachProcess = NULL;
        }
        else {
            referencedProcess = TRUE;
        }
    }

    if (attachProcess != NULL && KeGetCurrentIrql() == PASSIVE_LEVEL) {
        RtlZeroMemory(attachState, sizeof(attachState));
        KeStackAttachProcess((PVOID)attachProcess, attachState);
        attached = TRUE;
    }

    if (userGetSiloGlobals != NULL) {
        __try {
            sessionGlobals = (ULONG_PTR)userGetSiloGlobals();
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            sessionGlobals = 0U;
            response->lastStatus = GetExceptionCode();
        }
    }

    if (tableBase == 0U && sessionGlobals == 0U) {
        response->status = KSWORD_ARK_KEYBOARD_ENUM_STATUS_SESSION_UNAVAILABLE;
        goto Cleanup;
    }
    response->sessionGlobals = (ULONG64)sessionGlobals;

    for (bucketIndex = 0UL; bucketIndex < KSWORD_ARK_KEYBOARD_HOTKEY_BUCKETS; ++bucketIndex) {
        ULONG_PTR listHeadAddress = ((tableBase != 0U) ? tableBase : (sessionGlobals + tableOffset)) +
            ((ULONG_PTR)bucketIndex * sizeof(PVOID));
        ULONG_PTR hotkeyObject = 0U;
        ULONG depth = 0UL;

        if (!kswordArkKeyboardReadPointer(listHeadAddress, &hotkeyObject)) {
            continue;
        }

        while (hotkeyObject != 0U && depth < KSWORD_ARK_KEYBOARD_CHAIN_WALK_LIMIT) {
            ULONG_PTR nextHotkey = 0U;

            kswordArkKeyboardAppendHotkeyEntry(
                response,
                entryCapacity,
                maxEntries,
                sessionGlobals,
                bucketIndex,
                depth,
                hotkeyObject,
                nextOffset,
                modifiersOffset,
                vkOffset,
                idOffset,
                requestFlags,
                (request != NULL) ? request->processId : 0UL);

            if (!kswordArkKeyboardReadPointer(hotkeyObject + nextOffset, &nextHotkey)) {
                break;
            }
            if (nextHotkey == hotkeyObject) {
                break;
            }
            hotkeyObject = nextHotkey;
            ++depth;
        }
    }

    if (response->status != KSWORD_ARK_KEYBOARD_ENUM_STATUS_BUFFER_TRUNCATED) {
        response->status = KSWORD_ARK_KEYBOARD_ENUM_STATUS_OK;
    }

Cleanup:
    if (attached) {
        KeUnstackDetachProcess(attachState);
    }
    if (referencedProcess && attachProcess != NULL) {
        ObDereferenceObject(attachProcess);
    }
    if (moduleInfo != NULL) {
        ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
    }

    *bytesWrittenOut = KSWORD_ARK_KEYBOARD_HOTKEY_RESPONSE_HEADER_SIZE +
        ((size_t)response->returnedCount * sizeof(KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY));
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkDriverEnumerateKeyboardHooks(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_ENUM_KEYBOARD_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
{
    KSWORD_ARK_ENUM_KEYBOARD_HOOKS_RESPONSE* response = NULL;
    KswHookSystemModuleInformation* moduleInfo = NULL;
    ULONG moduleInfoBytes = 0UL;
    KswHookSystemModuleEntry win32kfullEntry;
    KswordPsGetNextProcessFn psGetNextProcess = NULL;
    KswordPsGetNextProcessThreadFn psGetNextProcessThread = NULL;
    KswordPsGetThreadWiN32ThreadFn psGetThreadWin32Thread = NULL;
    ULONG requestFlags = KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_THREAD_HOOKS |
        KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_GLOBAL_HOOKS;
    ULONG maxEntries = 1024UL;
    ULONG entryCapacity = 0UL;
    PEPROCESS processObject = NULL;
    PEPROCESS processCursor = NULL;
    BOOLEAN referencedProcess = FALSE;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG processWalkCount = 0UL;

    if (outputBuffer == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < KSWORD_ARK_KEYBOARD_HOOK_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (request != NULL) {
        requestFlags = request->flags;
        if (request->maxEntries != 0UL) {
            maxEntries = request->maxEntries;
        }
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_ENUM_KEYBOARD_HOOKS_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_KEYBOARD_PROTOCOL_VERSION;
    response->entrySize = sizeof(KSWORD_ARK_KEYBOARD_HOOK_ENTRY);
    response->status = KSWORD_ARK_KEYBOARD_ENUM_STATUS_UNKNOWN;
    response->flags = requestFlags;
    response->threadHookArrayOffset = KSWORD_ARK_HOOK_THREAD_ARRAY_OFFSET;
    response->desktopInfoOffset = KSWORD_ARK_HOOK_DESKTOP_INFO_OFFSET;
    response->desktopHookArrayOffset = KSWORD_ARK_HOOK_DESKTOP_ARRAY_OFFSET;
    response->hookNextOffset = KSWORD_ARK_HOOK_NEXT_OFFSET;
    response->hookTypeOffset = KSWORD_ARK_HOOK_TYPE_OFFSET;
    response->hookProcedureOffset = KSWORD_ARK_HOOK_PROCEDURE_OFFSET;
    response->hookFlagsOffset = KSWORD_ARK_HOOK_FLAGS_OFFSET;
    response->hookModuleIdOffset = KSWORD_ARK_HOOK_MODULE_ID_OFFSET;
    response->hookTargetThreadInfoOffset = KSWORD_ARK_HOOK_TARGET_THREAD_INFO_OFFSET;
    entryCapacity = (ULONG)((outputBufferLength - KSWORD_ARK_KEYBOARD_HOOK_RESPONSE_HEADER_SIZE) / sizeof(KSWORD_ARK_KEYBOARD_HOOK_ENTRY));
    if (entryCapacity > maxEntries) {
        entryCapacity = maxEntries;
    }

    psGetNextProcess = kswordArkKeyboardResolvePsGetNextProcess();
    psGetNextProcessThread = kswordArkKeyboardResolvePsGetNextProcessThread();
    psGetThreadWin32Thread = kswordArkKeyboardResolvePsGetThreadWin32Thread();
    if (psGetNextProcessThread == NULL || psGetThreadWin32Thread == NULL) {
        response->status = KSWORD_ARK_KEYBOARD_ENUM_STATUS_UNSUPPORTED;
        response->lastStatus = STATUS_PROCEDURE_NOT_FOUND;
        goto Cleanup;
    }

    status = kswordArkHookBuildModuleSnapshot(&moduleInfo, &moduleInfoBytes);
    response->lastStatus = status;
    if (NT_SUCCESS(status) && moduleInfo != NULL &&
        kswordArkKeyboardFindModuleByName(moduleInfo, "win32kfull.sys", &win32kfullEntry)) {
        response->win32kBase = (ULONG64)(ULONG_PTR)win32kfullEntry.imageBase;
    }

    if (request != NULL && request->processId != 0UL) {
        status = PsLookupProcessByProcessId(ULongToHandle(request->processId), &processObject);
        response->lastStatus = status;
        if (!NT_SUCCESS(status)) {
            response->status = KSWORD_ARK_KEYBOARD_ENUM_STATUS_READ_FAILED;
            goto Cleanup;
        }
        referencedProcess = TRUE;

        kswordArkKeyboardEnumerateHookChainsForProcess(
            response,
            entryCapacity,
            maxEntries,
            processObject,
            psGetNextProcessThread,
            psGetThreadWin32Thread,
            requestFlags);
    }
    else {
        if (psGetNextProcess == NULL) {
            response->status = KSWORD_ARK_KEYBOARD_ENUM_STATUS_UNSUPPORTED;
            response->lastStatus = STATUS_PROCEDURE_NOT_FOUND;
            goto Cleanup;
        }

        processCursor = psGetNextProcess(NULL);
        while (processCursor != NULL &&
            processWalkCount < KSWORD_ARK_KEYBOARD_PROCESS_WALK_LIMIT &&
            response->status != KSWORD_ARK_KEYBOARD_ENUM_STATUS_BUFFER_TRUNCATED) {
            PEPROCESS nextProcess = psGetNextProcess(processCursor);

            kswordArkKeyboardEnumerateHookChainsForProcess(
                response,
                entryCapacity,
                maxEntries,
                processCursor,
                psGetNextProcessThread,
                psGetThreadWin32Thread,
                requestFlags);

            ObDereferenceObject(processCursor);
            processCursor = nextProcess;
            processWalkCount += 1UL;
        }

        if (processCursor != NULL) {
            ObDereferenceObject(processCursor);
            processCursor = NULL;
            if (response->status != KSWORD_ARK_KEYBOARD_ENUM_STATUS_BUFFER_TRUNCATED) {
                response->status = KSWORD_ARK_KEYBOARD_ENUM_STATUS_PARTIAL;
                response->lastStatus = STATUS_BUFFER_OVERFLOW;
            }
        }
    }

    if (response->status == KSWORD_ARK_KEYBOARD_ENUM_STATUS_UNKNOWN) {
        response->status = KSWORD_ARK_KEYBOARD_ENUM_STATUS_OK;
    }

Cleanup:
    if (referencedProcess && processObject != NULL) {
        ObDereferenceObject(processObject);
    }
    if (moduleInfo != NULL) {
        ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
    }

    *bytesWrittenOut = KSWORD_ARK_KEYBOARD_HOOK_RESPONSE_HEADER_SIZE +
        ((size_t)response->returnedCount * sizeof(KSWORD_ARK_KEYBOARD_HOOK_ENTRY));
    return STATUS_SUCCESS;
}
