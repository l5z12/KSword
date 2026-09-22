/*++

Module Name:

    callback_extended_bugcheck.c

Abstract:

    enumerate classic BugCheck and BugCheckReason callbacks, and explicitly display Ksword's own records.

Environment:

    Kernel-mode Driver Framework

--*/

#include "callback_extended_internal.h"
#include "callback_extended_kernel.h"
#include "../bugcheck/bugcheck_internal.h"

#define KSWORD_ARK_CALLBACK_BUGCHECK_WALK_LIMIT 512UL

static ULONG
kswordArkCallbackExtendedBugcheckReasonType(
    _In_ KBUGCHECK_CALLBACK_REASON reason
    )
/*++

Routine Description:

    Map the WDK BugCheckReason enum to the shared protocol's sub-type registration.

Arguments:

    Reason - KBUGCHECK_CALLBACK_REASON。

Return Value:

    Returns stable KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_* values.

--*/
{
    switch (reason) {
    case KbCallbackSecondaryDumpData:
    case KbCallbackSecondaryMultiPartDumpData:
        return KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_BUGCHECK_SECONDARY_DUMP;

    case KbCallbackDumpIo:
        return KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_BUGCHECK_DUMP_IO;

    case KbCallbackTriageDumpData:
        return KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_BUGCHECK_TRIAGE_DUMP;

    default:
        return KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_BUGCHECK_REASON_OTHER;
    }
}

static VOID
kswordArkCallbackExtendedAddSelfBugcheckRow(
    _Inout_ KswordArkCallbackEnumBuilder* builder,
    _Inout_ KswordArkCallbackModuleCache* moduleCache,
    _In_ BOOLEAN registered,
    _In_ ULONG callbackClass,
    _In_ ULONG registrationType,
    _In_ ULONG64 callbackAddress,
    _In_ ULONG64 contextAddress,
    _In_ ULONG64 recordAddress,
    _In_z_ PCWSTR nameText,
    _In_z_ PCWSTR detailText
    )
/*++

Routine Description:

    Write a Ksword-specific BugCheck registration record.

Arguments:

    Builder: Response builder.
    ModuleCache - Module cache.
    Registered - Indicates whether the current record is already registered.
    CallbackClass - Classic or Reason category.
    RegistrationType - specific BugCheck registration type.
    CallbackAddress - Address of the callback function.
    ContextAddress: Reason value or buffer address.
    RecordAddress - Address of the KBUGCHECK_*_RECORD.
    NameText - Row name.
    DetailText - The detailed text.

Return Value:

    No return value.

--*/
{
    kswordArkCallbackExtendedAddRow(
        builder,
        moduleCache,
        callbackClass,
        KSWORD_ARK_CALLBACK_ENUM_SOURCE_KSWORD_SELF,
        registered
            ? KSWORD_ARK_CALLBACK_ENUM_STATUS_OK
            : KSWORD_ARK_CALLBACK_ENUM_STATUS_NOT_REGISTERED,
        registered ? STATUS_SUCCESS : STATUS_NOT_FOUND,
        registrationType,
        0UL,
        0UL,
        callbackAddress,
        contextAddress,
        recordAddress,
        0UL,
        nameText,
        detailText);
}

VOID
kswordArkCallbackExtendedAddSelfBugcheckCallbacks(
    _Inout_ KswordArkCallbackEnumBuilder* builder
    )
/*++

Routine Description:

    Demonstrate a classic BugCheck and three BugCheckReason callbacks actually registered by the driver.

Arguments:

    Builder: Response builder.

Return Value:

    No return value.

--*/
{
    KswordArkCallbackModuleCache moduleCache;
    KswordArkBugcheckState* state = &gKswordArkBugcheckState;

    if (builder == NULL) {
        return;
    }

    kswordArkCallbackEnumInitModuleCache(&moduleCache);
    kswordArkCallbackExtendedAddSelfBugcheckRow(
        builder,
        &moduleCache,
        state->classicRegistered,
        KSWORD_ARK_CALLBACK_ENUM_CLASS_BUGCHECK,
        KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_BUGCHECK_CLASSIC,
        (ULONG64)(ULONG_PTR)state->classicRecord.CallbackRoutine,
        (ULONG64)(ULONG_PTR)state->classicRecord.Buffer,
        (ULONG64)(ULONG_PTR)&state->classicRecord,
        L"KswordARK BugCheck callback",
        L"KeRegisterBugCheckCallback 注册的经典蓝屏回调；该行直接来自本驱动运行时记录。");
    kswordArkCallbackExtendedAddSelfBugcheckRow(
        builder,
        &moduleCache,
        state->secondaryRegistered,
        KSWORD_ARK_CALLBACK_ENUM_CLASS_BUGCHECK_REASON,
        KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_BUGCHECK_SECONDARY_DUMP,
        (ULONG64)(ULONG_PTR)state->secondaryRecord.CallbackRoutine,
        (ULONG64)state->secondaryRecord.Reason,
        (ULONG64)(ULONG_PTR)&state->secondaryRecord,
        L"KswordARK SecondaryDumpData callback",
        L"KeRegisterBugCheckReasonCallback 注册的 SecondaryDumpData 回调。");
    kswordArkCallbackExtendedAddSelfBugcheckRow(
        builder,
        &moduleCache,
        state->dumpIoRegistered,
        KSWORD_ARK_CALLBACK_ENUM_CLASS_BUGCHECK_REASON,
        KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_BUGCHECK_DUMP_IO,
        (ULONG64)(ULONG_PTR)state->dumpIoRecord.CallbackRoutine,
        (ULONG64)state->dumpIoRecord.Reason,
        (ULONG64)(ULONG_PTR)&state->dumpIoRecord,
        L"KswordARK DumpIo callback",
        L"KeRegisterBugCheckReasonCallback 注册的 DumpIo 回调。");
    kswordArkCallbackExtendedAddSelfBugcheckRow(
        builder,
        &moduleCache,
        state->triageRegistered,
        KSWORD_ARK_CALLBACK_ENUM_CLASS_BUGCHECK_REASON,
        KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_BUGCHECK_TRIAGE_DUMP,
        (ULONG64)(ULONG_PTR)state->triageRecord.CallbackRoutine,
        (ULONG64)state->triageRecord.Reason,
        (ULONG64)(ULONG_PTR)&state->triageRecord,
        L"KswordARK TriageDumpData callback",
        L"KeRegisterBugCheckReasonCallback 注册的 TriageDumpData 回调。");
    kswordArkCallbackEnumFreeModuleCache(&moduleCache);
}

static BOOLEAN
kswordArkCallbackExtendedIsOwnBugcheckRecord(
    _In_ ULONG64 recordAddress
    )
/*++

Routine Description:

    Check if the linked list node belongs to the Ksword internal records already displayed above.

Arguments:

    RecordAddress: Offset from KBUGCHECK_*_RECORD base address.

Return Value:

    Return TRUE if the record belongs to one of the four self-records; otherwise return FALSE.

--*/
{
    return recordAddress == (ULONG64)(ULONG_PTR)&gKswordArkBugcheckState.classicRecord ||
        recordAddress == (ULONG64)(ULONG_PTR)&gKswordArkBugcheckState.secondaryRecord ||
        recordAddress == (ULONG64)(ULONG_PTR)&gKswordArkBugcheckState.dumpIoRecord ||
        recordAddress == (ULONG64)(ULONG_PTR)&gKswordArkBugcheckState.triageRecord;
}

static VOID
kswordArkCallbackExtendedWalkClassicBugcheckList(
    _Inout_ KswordArkCallbackEnumBuilder* builder,
    _Inout_ KswordArkCallbackModuleCache* moduleCache
    )
/*++

Routine Description:

    Traverse the classic BugCheck chain using this driver's registered records as a security anchor.

Arguments:

    Builder: Response builder.
    ModuleCache - Module cache.

Return Value:

    No return value.

--*/
{
    ULONG index = 0UL;
    ULONG64 anchorAddress = 0ULL;
    ULONG64 currentAddress = 0ULL;
    KBUGCHECK_CALLBACK_RECORD anchorRecord;

    if (!gKswordArkBugcheckState.classicRegistered) {
        kswordArkCallbackExtendedAddRow(
            builder,
            moduleCache,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_BUGCHECK,
            KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_BUGCHECK_LIST,
            KSWORD_ARK_CALLBACK_ENUM_STATUS_QUERY_FAILED,
            STATUS_NOT_FOUND,
            KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_BUGCHECK_CLASSIC,
            0UL,
            0UL,
            0ULL,
            0ULL,
            0ULL,
            0UL,
            L"KeBugCheckCallbackListHead anchor unavailable",
            L"Ksword 自身经典 BugCheck 记录未注册，无法在不全局盲扫的情况下取得链表锚点。");
        return;
    }

    anchorAddress = (ULONG64)(ULONG_PTR)&gKswordArkBugcheckState.classicRecord;
    RtlZeroMemory(&anchorRecord, sizeof(anchorRecord));
    if (!kswordArkCallbackEnumReadMemory(
            (const VOID*)(ULONG_PTR)anchorAddress,
            &anchorRecord,
            sizeof(anchorRecord))) {
        return;
    }

    currentAddress = (ULONG64)(ULONG_PTR)anchorRecord.Entry.Flink;
    while (currentAddress != 0ULL &&
        currentAddress != anchorAddress &&
        index < KSWORD_ARK_CALLBACK_BUGCHECK_WALK_LIMIT) {
        KBUGCHECK_CALLBACK_RECORD record;
        ULONG64 nextAddress = 0ULL;

        RtlZeroMemory(&record, sizeof(record));
        if (!kswordArkCallbackEnumReadMemory(
                (const VOID*)(ULONG_PTR)currentAddress,
                &record,
                sizeof(record))) {
            break;
        }
        nextAddress = (ULONG64)(ULONG_PTR)record.Entry.Flink;

        if (!kswordArkCallbackExtendedIsOwnBugcheckRecord(currentAddress) &&
            record.State == BufferInserted &&
            record.CallbackRoutine != NULL &&
            kswordArkCallbackEnumIsKernelModuleAddress(
                moduleCache,
                (ULONG64)(ULONG_PTR)record.CallbackRoutine)) {
            WCHAR nameText[KSWORD_ARK_CALLBACK_ENUM_NAME_CHARS];
            WCHAR detailText[KSWORD_ARK_CALLBACK_ENUM_DETAIL_CHARS];

            RtlZeroMemory(nameText, sizeof(nameText));
            RtlZeroMemory(detailText, sizeof(detailText));
            (VOID)RtlStringCbPrintfW(
                nameText,
                sizeof(nameText),
                L"KeBugCheckCallback[%lu]",
                (unsigned long)index);
            (VOID)RtlStringCbPrintfW(
                detailText,
                sizeof(detailText),
                L"经典 BugCheck 公共记录链只读项；Record=0x%p，Buffer=0x%p，Length=%lu，Component=0x%p。",
                (PVOID)(ULONG_PTR)currentAddress,
                record.Buffer,
                (unsigned long)record.Length,
                record.Component);
            kswordArkCallbackExtendedAddRow(
                builder,
                moduleCache,
                KSWORD_ARK_CALLBACK_ENUM_CLASS_BUGCHECK,
                KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_BUGCHECK_LIST,
                KSWORD_ARK_CALLBACK_ENUM_STATUS_OK,
                STATUS_SUCCESS,
                KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_BUGCHECK_CLASSIC,
                0UL,
                0UL,
                (ULONG64)(ULONG_PTR)record.CallbackRoutine,
                (ULONG64)(ULONG_PTR)record.Buffer,
                currentAddress,
                0UL,
                nameText,
                detailText);
        }

        if (nextAddress == currentAddress) {
            break;
        }
        currentAddress = nextAddress;
        ++index;
    }
}

static PKBUGCHECK_REASON_CALLBACK_RECORD
kswordArkCallbackExtendedReasonAnchor(
    VOID
    )
/*++

Routine Description:

    Select a registered BugCheckReason record as the global chain anchor.

Arguments:

    None.

Return Value:

    Returns the registered record; returns NULL if all are unregistered.

--*/
{
    if (gKswordArkBugcheckState.secondaryRegistered) {
        return &gKswordArkBugcheckState.secondaryRecord;
    }
    if (gKswordArkBugcheckState.dumpIoRegistered) {
        return &gKswordArkBugcheckState.dumpIoRecord;
    }
    if (gKswordArkBugcheckState.triageRegistered) {
        return &gKswordArkBugcheckState.triageRecord;
    }
    return NULL;
}

static VOID
kswordArkCallbackExtendedWalkReasonBugcheckList(
    _Inout_ KswordArkCallbackEnumBuilder* builder,
    _Inout_ KswordArkCallbackModuleCache* moduleCache
    )
/*++

Routine Description:

    Traverse the BugCheckReason global chain anchored by a registered Reason record.

Arguments:

    Builder: Response builder.
    ModuleCache - Module cache.

Return Value:

    No return value.

--*/
{
    ULONG index = 0UL;
    PKBUGCHECK_REASON_CALLBACK_RECORD anchor = NULL;
    ULONG64 anchorAddress = 0ULL;
    ULONG64 currentAddress = 0ULL;
    KBUGCHECK_REASON_CALLBACK_RECORD anchorRecord;

    anchor = kswordArkCallbackExtendedReasonAnchor();
    if (anchor == NULL) {
        kswordArkCallbackExtendedAddRow(
            builder,
            moduleCache,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_BUGCHECK_REASON,
            KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_BUGCHECK_LIST,
            KSWORD_ARK_CALLBACK_ENUM_STATUS_QUERY_FAILED,
            STATUS_NOT_FOUND,
            KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_BUGCHECK_REASON_OTHER,
            0UL,
            0UL,
            0ULL,
            0ULL,
            0ULL,
            0UL,
            L"KeBugCheckReasonCallbackListHead anchor unavailable",
            L"Ksword 自身三个 BugCheckReason 记录均未注册，无法取得安全链表锚点。");
        return;
    }

    anchorAddress = (ULONG64)(ULONG_PTR)anchor;
    RtlZeroMemory(&anchorRecord, sizeof(anchorRecord));
    if (!kswordArkCallbackEnumReadMemory(
            (const VOID*)(ULONG_PTR)anchorAddress,
            &anchorRecord,
            sizeof(anchorRecord))) {
        return;
    }

    currentAddress = (ULONG64)(ULONG_PTR)anchorRecord.Entry.Flink;
    while (currentAddress != 0ULL &&
        currentAddress != anchorAddress &&
        index < KSWORD_ARK_CALLBACK_BUGCHECK_WALK_LIMIT) {
        KBUGCHECK_REASON_CALLBACK_RECORD record;
        ULONG64 nextAddress = 0ULL;

        RtlZeroMemory(&record, sizeof(record));
        if (!kswordArkCallbackEnumReadMemory(
                (const VOID*)(ULONG_PTR)currentAddress,
                &record,
                sizeof(record))) {
            break;
        }
        nextAddress = (ULONG64)(ULONG_PTR)record.Entry.Flink;

        if (!kswordArkCallbackExtendedIsOwnBugcheckRecord(currentAddress) &&
            record.State == BufferInserted &&
            record.CallbackRoutine != NULL &&
            kswordArkCallbackEnumIsKernelModuleAddress(
                moduleCache,
                (ULONG64)(ULONG_PTR)record.CallbackRoutine)) {
            WCHAR nameText[KSWORD_ARK_CALLBACK_ENUM_NAME_CHARS];
            WCHAR detailText[KSWORD_ARK_CALLBACK_ENUM_DETAIL_CHARS];

            RtlZeroMemory(nameText, sizeof(nameText));
            RtlZeroMemory(detailText, sizeof(detailText));
            (VOID)RtlStringCbPrintfW(
                nameText,
                sizeof(nameText),
                L"KeBugCheckReasonCallback[%lu]",
                (unsigned long)index);
            (VOID)RtlStringCbPrintfW(
                detailText,
                sizeof(detailText),
                L"BugCheckReason 公共记录链只读项；Record=0x%p，Reason=%lu，Component=0x%p。",
                (PVOID)(ULONG_PTR)currentAddress,
                (unsigned long)record.Reason,
                record.Component);
            kswordArkCallbackExtendedAddRow(
                builder,
                moduleCache,
                KSWORD_ARK_CALLBACK_ENUM_CLASS_BUGCHECK_REASON,
                KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_BUGCHECK_LIST,
                KSWORD_ARK_CALLBACK_ENUM_STATUS_OK,
                STATUS_SUCCESS,
                kswordArkCallbackExtendedBugcheckReasonType(record.Reason),
                0UL,
                0UL,
                (ULONG64)(ULONG_PTR)record.CallbackRoutine,
                (ULONG64)record.Reason,
                currentAddress,
                0UL,
                nameText,
                detailText);
        }

        if (nextAddress == currentAddress) {
            break;
        }
        currentAddress = nextAddress;
        ++index;
    }
}

VOID
kswordArkCallbackExtendedAddBugcheckCallbacks(
    _Inout_ KswordArkCallbackEnumBuilder* builder
    )
/*++

Routine Description:

    enumerate external callbacks in the system's classic BugCheck and BugCheckReason chains.

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

    kswordArkCallbackExtendedWalkClassicBugcheckList(builder, &moduleCache);
    kswordArkCallbackExtendedWalkReasonBugcheckList(builder, &moduleCache);
    kswordArkCallbackEnumFreeModuleCache(&moduleCache);
}
