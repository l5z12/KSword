/*++

Module Name:

    driver_dispatch_editor.c

Abstract:

    Unrestricted, transactional DriverObject MajorFunction editor.

    This component intentionally applies no target class, module owner, PnP,
    file-system, security-product, or pointer-range policy.  Mutation safety is
    limited to stable object identity, an exact expected-current value, a
    mandatory mutation generation, and InterlockedCompareExchangePointer.

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL control path.

--*/

#include <ntifs.h>

#include "ark/ark_driver.h"

#include <ntstrsafe.h>

#define KSW_DRIVER_DISPATCH_RECORD_LIMIT 128UL

typedef struct KswDriverDispatchRecord
{
    BOOLEAN inUse;
    BOOLEAN owned;
    BOOLEAN conflict;
    UCHAR majorFunction;
    ULONG generation;
    ULONGLONG targetModuleBase;
    PDRIVER_OBJECT driverObject;
    PDRIVER_DISPATCH originalDispatch;
    PDRIVER_DISPATCH appliedDispatch;
    WCHAR canonicalName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS];
} KswDriverDispatchRecord, *PkswDriverDispatchRecord;

typedef struct KswDriverDispatchState
{
    FAST_MUTEX lock;
    volatile LONG initialized;
    BOOLEAN shuttingDown;
    UCHAR padding[3];
    ULONG generation;
    PDRIVER_OBJECT selfDriverObject;
    KswDriverDispatchRecord records[KSW_DRIVER_DISPATCH_RECORD_LIMIT];
} KswDriverDispatchState, *PkswDriverDispatchState;

static KswDriverDispatchState gKswordArkDriverDispatchState;

C_ASSERT(sizeof(KSWORD_ARK_DRIVER_DISPATCH_REQUEST) == 584U);
C_ASSERT(sizeof(KSWORD_ARK_DRIVER_DISPATCH_RESPONSE) == 608U);
C_ASSERT(IRP_MJ_MAXIMUM_FUNCTION <= 0xFFU);

static PDRIVER_DISPATCH
kswordArkDriverDispatchRead(
    _In_ PDRIVER_OBJECT driverObject,
    _In_ UCHAR majorFunction
    )
{
    return (PDRIVER_DISPATCH)InterlockedCompareExchangePointer(
        (PVOID volatile*)&driverObject->MajorFunction[majorFunction],
        NULL,
        NULL);
}

static PDRIVER_DISPATCH
kswordArkDriverDispatchCompareExchange(
    _In_ PDRIVER_OBJECT driverObject,
    _In_ UCHAR majorFunction,
    _In_ PDRIVER_DISPATCH exchange,
    _In_ PDRIVER_DISPATCH expected
    )
{
    return (PDRIVER_DISPATCH)InterlockedCompareExchangePointer(
        (PVOID volatile*)&driverObject->MajorFunction[majorFunction],
        (PVOID)exchange,
        (PVOID)expected);
}

static ULONG
kswordArkDriverDispatchAdvanceGenerationLocked(
    _Inout_opt_ KswDriverDispatchRecord* record
    )
{
    ++gKswordArkDriverDispatchState.generation;
    if (gKswordArkDriverDispatchState.generation == 0UL) {
        ++gKswordArkDriverDispatchState.generation;
    }
    if (record != NULL) {
        record->generation = gKswordArkDriverDispatchState.generation;
    }
    return gKswordArkDriverDispatchState.generation;
}

static KswDriverDispatchRecord*
kswordArkDriverDispatchFindRecordLocked(
    _In_ ULONGLONG targetModuleBase,
    _In_ UCHAR majorFunction
    )
{
    ULONG index = 0UL;

    for (index = 0UL; index < KSW_DRIVER_DISPATCH_RECORD_LIMIT; ++index) {
        KswDriverDispatchRecord* record =
            &gKswordArkDriverDispatchState.records[index];
        if (record->inUse != FALSE &&
            record->targetModuleBase == targetModuleBase &&
            record->majorFunction == majorFunction) {
            return record;
        }
    }
    return NULL;
}

static KswDriverDispatchRecord*
kswordArkDriverDispatchAllocateRecordLocked(
    VOID
    )
{
    ULONG index = 0UL;

    for (index = 0UL; index < KSW_DRIVER_DISPATCH_RECORD_LIMIT; ++index) {
        KswDriverDispatchRecord* record =
            &gKswordArkDriverDispatchState.records[index];
        if (record->inUse == FALSE) {
            RtlZeroMemory(record, sizeof(*record));
            return record;
        }
    }
    return NULL;
}

static BOOLEAN
kswordArkDriverDispatchHasTerminatedName(
    _In_reads_(KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) const WCHAR* driverName
    )
{
    ULONG index = 0UL;

    if (driverName == NULL) {
        return FALSE;
    }
    for (index = 0UL; index < KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS; ++index) {
        if (driverName[index] == L'\0') {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN
kswordArkDriverDispatchNamesEqual(
    _In_z_ const WCHAR* left,
    _In_z_ const WCHAR* right
    )
{
    UNICODE_STRING leftName;
    UNICODE_STRING rightName;

    if (left == NULL || right == NULL || left[0] == L'\0' || right[0] == L'\0') {
        return FALSE;
    }
    RtlInitUnicodeString(&leftName, left);
    RtlInitUnicodeString(&rightName, right);
    return RtlEqualUnicodeString(&leftName, &rightName, TRUE);
}

static BOOLEAN
kswordArkDriverDispatchRecordMatchesRequest(
    _In_ const KswDriverDispatchRecord* record,
    _In_ const KSWORD_ARK_DRIVER_DISPATCH_REQUEST* request
    )
{
    if (record == NULL || request == NULL || record->inUse == FALSE) {
        return FALSE;
    }
    if ((request->flags &
        KSWORD_ARK_DRIVER_DISPATCH_FLAG_EXPECTED_DRIVER_OBJECT_PRESENT) != 0UL &&
        request->expectedDriverObjectAddress !=
            (ULONGLONG)(ULONG_PTR)record->driverObject) {
        return FALSE;
    }
    if (request->driverName[0] != L'\0' &&
        !kswordArkDriverDispatchNamesEqual(
            request->driverName,
            record->canonicalName)) {
        return FALSE;
    }
    return TRUE;
}

static VOID
kswordArkDriverDispatchRefreshRecordLocked(
    _Inout_ KswDriverDispatchRecord* record
    )
{
    PDRIVER_DISPATCH current = NULL;
    BOOLEAN oldOwned = FALSE;
    BOOLEAN oldConflict = FALSE;

    if (record == NULL || record->inUse == FALSE || record->driverObject == NULL) {
        return;
    }

    oldOwned = record->owned;
    oldConflict = record->conflict;
    current = kswordArkDriverDispatchRead(
        record->driverObject,
        record->majorFunction);

    if (record->owned != FALSE) {
        if (current == record->appliedDispatch) {
            /* Still exactly owned by this transaction. */
        }
        else if (current == record->originalDispatch) {
            record->owned = FALSE;
        }
        else {
            record->owned = FALSE;
            record->conflict = TRUE;
        }
    }
    else if (current != record->originalDispatch) {
        record->conflict = TRUE;
    }

    if (oldOwned != record->owned || oldConflict != record->conflict) {
        (VOID)kswordArkDriverDispatchAdvanceGenerationLocked(record);
    }
}

static VOID
kswordArkDriverDispatchFillResponse(
    _Out_ KSWORD_ARK_DRIVER_DISPATCH_RESPONSE* response,
    _In_ ULONG action,
    _In_ UCHAR majorFunction,
    _In_ NTSTATUS lastStatus,
    _In_ ULONGLONG requestedDispatch,
    _In_opt_ const KswDriverDispatchRecord* record,
    _In_opt_ PDRIVER_OBJECT driverObject,
    _In_ ULONGLONG targetModuleBase,
    _In_opt_z_ const WCHAR* canonicalName,
    _In_ BOOLEAN changed
    )
{
    PDRIVER_DISPATCH current = NULL;

    RtlZeroMemory(response, sizeof(*response));
    response->version = KSWORD_ARK_DRIVER_DISPATCH_PROTOCOL_VERSION;
    response->action = action;
    response->majorFunction = majorFunction;
    response->lastStatus = lastStatus;
    response->requestedDispatchAddress = requestedDispatch;
    response->targetModuleBase = targetModuleBase;
    response->selfDriverObjectAddress = (ULONGLONG)(ULONG_PTR)
        gKswordArkDriverDispatchState.selfDriverObject;
    response->responseFlags =
        KSWORD_ARK_DRIVER_DISPATCH_RESPONSE_FLAG_WARN_ONLY_POLICY;
    if (changed != FALSE) {
        response->responseFlags |=
            KSWORD_ARK_DRIVER_DISPATCH_RESPONSE_FLAG_CHANGED;
    }

    if (record != NULL && record->inUse != FALSE) {
        driverObject = record->driverObject;
        targetModuleBase = record->targetModuleBase;
        canonicalName = record->canonicalName;
        current = kswordArkDriverDispatchRead(
            record->driverObject,
            record->majorFunction);
        response->responseFlags |=
            KSWORD_ARK_DRIVER_DISPATCH_RESPONSE_FLAG_RECORD_PRESENT;
        if (record->owned != FALSE) {
            response->responseFlags |=
                KSWORD_ARK_DRIVER_DISPATCH_RESPONSE_FLAG_OWNED;
        }
        if (record->conflict != FALSE) {
            response->responseFlags |=
                KSWORD_ARK_DRIVER_DISPATCH_RESPONSE_FLAG_FOREIGN_CHANGE;
        }
        response->state = record->conflict != FALSE
            ? KSWORD_ARK_DRIVER_DISPATCH_STATE_CONFLICT
            : (record->owned != FALSE
                ? KSWORD_ARK_DRIVER_DISPATCH_STATE_ACTIVE
                : KSWORD_ARK_DRIVER_DISPATCH_STATE_INACTIVE);
        response->generation = record->generation;
        response->originalDispatchAddress =
            (ULONGLONG)(ULONG_PTR)record->originalDispatch;
        response->appliedDispatchAddress =
            (ULONGLONG)(ULONG_PTR)record->appliedDispatch;
    }
    else {
        response->state = KSWORD_ARK_DRIVER_DISPATCH_STATE_INACTIVE;
        response->generation = gKswordArkDriverDispatchState.generation;
        if (driverObject != NULL) {
            current = kswordArkDriverDispatchRead(driverObject, majorFunction);
        }
    }

    response->targetModuleBase = targetModuleBase;
    response->driverObjectAddress = (ULONGLONG)(ULONG_PTR)driverObject;
    response->currentDispatchAddress = (ULONGLONG)(ULONG_PTR)current;
    if (current == (PDRIVER_DISPATCH)(ULONG_PTR)response->originalDispatchAddress &&
        (record != NULL && record->inUse != FALSE)) {
        response->responseFlags |=
            KSWORD_ARK_DRIVER_DISPATCH_RESPONSE_FLAG_CURRENT_IS_ORIGINAL;
    }
    if (current == (PDRIVER_DISPATCH)(ULONG_PTR)response->appliedDispatchAddress &&
        (record != NULL && record->inUse != FALSE)) {
        response->responseFlags |=
            KSWORD_ARK_DRIVER_DISPATCH_RESPONSE_FLAG_CURRENT_IS_APPLIED;
    }
    if (driverObject != NULL &&
        driverObject == gKswordArkDriverDispatchState.selfDriverObject) {
        response->responseFlags |=
            KSWORD_ARK_DRIVER_DISPATCH_RESPONSE_FLAG_SELF_TARGET;
        if (majorFunction == IRP_MJ_DEVICE_CONTROL) {
            response->responseFlags |=
                KSWORD_ARK_DRIVER_DISPATCH_RESPONSE_FLAG_SELF_CONTROL_CHANNEL;
        }
    }
    if (canonicalName != NULL) {
        (VOID)RtlStringCchCopyW(
            response->driverName,
            RTL_NUMBER_OF(response->driverName),
            canonicalName);
    }
}

static VOID
kswordArkDriverDispatchFillRetiredResponse(
    _Out_ KSWORD_ARK_DRIVER_DISPATCH_RESPONSE* response,
    _In_ ULONG action,
    _In_ UCHAR majorFunction,
    _In_ NTSTATUS lastStatus,
    _In_ ULONGLONG requestedDispatch,
    _In_ const KswDriverDispatchRecord* snapshot,
    _In_ PDRIVER_DISPATCH currentDispatch,
    _In_ BOOLEAN changed
    )
{
    kswordArkDriverDispatchFillResponse(
        response,
        action,
        majorFunction,
        lastStatus,
        requestedDispatch,
        NULL,
        snapshot->driverObject,
        snapshot->targetModuleBase,
        snapshot->canonicalName,
        changed);
    response->generation = gKswordArkDriverDispatchState.generation;
    response->currentDispatchAddress = (ULONGLONG)(ULONG_PTR)currentDispatch;
    response->originalDispatchAddress =
        (ULONGLONG)(ULONG_PTR)snapshot->originalDispatch;
    response->appliedDispatchAddress =
        (ULONGLONG)(ULONG_PTR)snapshot->appliedDispatch;
    if (currentDispatch == snapshot->originalDispatch) {
        response->responseFlags |=
            KSWORD_ARK_DRIVER_DISPATCH_RESPONSE_FLAG_CURRENT_IS_ORIGINAL;
    }
}

static NTSTATUS
kswordArkDriverDispatchResolveTarget(
    _In_ const KSWORD_ARK_DRIVER_DISPATCH_REQUEST* request,
    _Outptr_ PDRIVER_OBJECT* driverObjectOut,
    _Out_writes_(nameChars) PWCHAR canonicalNameOut,
    _In_ ULONG nameChars
    )
{
    PDRIVER_OBJECT driverObject = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    status = kswordArkDriverReferenceObjectByModuleBase(
        request->targetModuleBase,
        &driverObject,
        canonicalNameOut,
        nameChars);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if ((ULONGLONG)(ULONG_PTR)driverObject->DriverStart !=
        request->targetModuleBase) {
        ObDereferenceObject(driverObject);
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    if ((request->flags &
        KSWORD_ARK_DRIVER_DISPATCH_FLAG_EXPECTED_DRIVER_OBJECT_PRESENT) != 0UL &&
        request->expectedDriverObjectAddress !=
            (ULONGLONG)(ULONG_PTR)driverObject) {
        ObDereferenceObject(driverObject);
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    if (request->driverName[0] != L'\0' &&
        !kswordArkDriverDispatchNamesEqual(
            request->driverName,
            canonicalNameOut)) {
        ObDereferenceObject(driverObject);
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    *driverObjectOut = driverObject;
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkDriverDispatchQuery(
    _In_ const KSWORD_ARK_DRIVER_DISPATCH_REQUEST* request,
    _Out_ KSWORD_ARK_DRIVER_DISPATCH_RESPONSE* response
    )
{
    KswDriverDispatchRecord* record = NULL;
    PDRIVER_OBJECT driverObject = NULL;
    WCHAR canonicalName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
    NTSTATUS status = STATUS_SUCCESS;

    ExAcquireFastMutex(&gKswordArkDriverDispatchState.lock);
    record = kswordArkDriverDispatchFindRecordLocked(
        request->targetModuleBase,
        (UCHAR)request->majorFunction);
    if (record != NULL) {
        if (!kswordArkDriverDispatchRecordMatchesRequest(record, request)) {
            kswordArkDriverDispatchFillResponse(
                response,
                request->action,
                (UCHAR)request->majorFunction,
                STATUS_OBJECT_TYPE_MISMATCH,
                request->desiredDispatchAddress,
                record,
                NULL,
                0ULL,
                NULL,
                FALSE);
            ExReleaseFastMutex(&gKswordArkDriverDispatchState.lock);
            return STATUS_OBJECT_TYPE_MISMATCH;
        }
        kswordArkDriverDispatchRefreshRecordLocked(record);
        kswordArkDriverDispatchFillResponse(
            response,
            request->action,
            (UCHAR)request->majorFunction,
            STATUS_SUCCESS,
            request->desiredDispatchAddress,
            record,
            NULL,
            0ULL,
            NULL,
            FALSE);
        ExReleaseFastMutex(&gKswordArkDriverDispatchState.lock);
        return STATUS_SUCCESS;
    }
    ExReleaseFastMutex(&gKswordArkDriverDispatchState.lock);

    status = kswordArkDriverDispatchResolveTarget(
        request,
        &driverObject,
        canonicalName,
        RTL_NUMBER_OF(canonicalName));
    if (!NT_SUCCESS(status)) {
        kswordArkDriverDispatchFillResponse(
            response,
            request->action,
            (UCHAR)request->majorFunction,
            status,
            request->desiredDispatchAddress,
            NULL,
            NULL,
            request->targetModuleBase,
            canonicalName,
            FALSE);
        return status;
    }
    kswordArkDriverDispatchFillResponse(
        response,
        request->action,
        (UCHAR)request->majorFunction,
        STATUS_SUCCESS,
        request->desiredDispatchAddress,
        NULL,
        driverObject,
        request->targetModuleBase,
        canonicalName,
        FALSE);
    ObDereferenceObject(driverObject);
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkDriverDispatchApply(
    _In_ const KSWORD_ARK_DRIVER_DISPATCH_REQUEST* request,
    _Out_ KSWORD_ARK_DRIVER_DISPATCH_RESPONSE* response
    )
{
    KswDriverDispatchRecord* record = NULL;
    PDRIVER_OBJECT driverObject = NULL;
    PDRIVER_OBJECT releaseObject = NULL;
    PDRIVER_DISPATCH current = NULL;
    PDRIVER_DISPATCH previous = NULL;
    PDRIVER_DISPATCH desired =
        (PDRIVER_DISPATCH)(ULONG_PTR)request->desiredDispatchAddress;
    KswDriverDispatchRecord retiredSnapshot;
    WCHAR canonicalName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
    BOOLEAN newRecord = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    RtlZeroMemory(&retiredSnapshot, sizeof(retiredSnapshot));
    status = kswordArkDriverDispatchResolveTarget(
        request,
        &driverObject,
        canonicalName,
        RTL_NUMBER_OF(canonicalName));
    if (!NT_SUCCESS(status)) {
        kswordArkDriverDispatchFillResponse(
            response,
            request->action,
            (UCHAR)request->majorFunction,
            status,
            request->desiredDispatchAddress,
            NULL,
            NULL,
            request->targetModuleBase,
            canonicalName,
            FALSE);
        return status;
    }

    ExAcquireFastMutex(&gKswordArkDriverDispatchState.lock);
    if (gKswordArkDriverDispatchState.shuttingDown != FALSE) {
        status = STATUS_DELETE_PENDING;
        goto ApplyFailureLocked;
    }
    record = kswordArkDriverDispatchFindRecordLocked(
        request->targetModuleBase,
        (UCHAR)request->majorFunction);
    if (record != NULL) {
        if (record->driverObject != driverObject ||
            !kswordArkDriverDispatchNamesEqual(
                record->canonicalName,
                canonicalName)) {
            status = STATUS_OBJECT_TYPE_MISMATCH;
            goto ApplyFailureLocked;
        }
        kswordArkDriverDispatchRefreshRecordLocked(record);
        if ((request->flags &
            KSWORD_ARK_DRIVER_DISPATCH_FLAG_EXPECTED_GENERATION_PRESENT) != 0UL &&
            request->expectedGeneration != record->generation) {
            status = STATUS_RETRY;
            goto ApplyFailureLocked;
        }
        if (record->conflict != FALSE) {
            status = STATUS_DEVICE_BUSY;
            goto ApplyFailureLocked;
        }
    }

    current = kswordArkDriverDispatchRead(
        driverObject,
        (UCHAR)request->majorFunction);
    if (current != (PDRIVER_DISPATCH)(ULONG_PTR)
        request->expectedCurrentDispatchAddress) {
        status = STATUS_RETRY;
        goto ApplyFailureLocked;
    }
    if (current == desired) {
        kswordArkDriverDispatchFillResponse(
            response,
            request->action,
            (UCHAR)request->majorFunction,
            STATUS_SUCCESS,
            request->desiredDispatchAddress,
            record,
            driverObject,
            request->targetModuleBase,
            canonicalName,
            FALSE);
        ExReleaseFastMutex(&gKswordArkDriverDispatchState.lock);
        ObDereferenceObject(driverObject);
        return STATUS_SUCCESS;
    }

    if (record == NULL) {
        record = kswordArkDriverDispatchAllocateRecordLocked();
        if (record == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto ApplyFailureLocked;
        }
        newRecord = TRUE;
    }

    previous = kswordArkDriverDispatchCompareExchange(
        driverObject,
        (UCHAR)request->majorFunction,
        desired,
        current);
    if (previous != current) {
        if (newRecord != FALSE) {
            RtlZeroMemory(record, sizeof(*record));
            record = NULL;
        }
        else {
            kswordArkDriverDispatchRefreshRecordLocked(record);
        }
        status = STATUS_RETRY;
        goto ApplyFailureLocked;
    }

    if (newRecord != FALSE) {
        record->inUse = TRUE;
        record->owned = TRUE;
        record->conflict = FALSE;
        record->majorFunction = (UCHAR)request->majorFunction;
        record->targetModuleBase = request->targetModuleBase;
        record->driverObject = driverObject;
        record->originalDispatch = current;
        record->appliedDispatch = desired;
        (VOID)RtlStringCchCopyW(
            record->canonicalName,
            RTL_NUMBER_OF(record->canonicalName),
            canonicalName);
        (VOID)kswordArkDriverDispatchAdvanceGenerationLocked(record);
        driverObject = NULL;
    }
    else {
        record->owned = TRUE;
        record->appliedDispatch = desired;
        (VOID)kswordArkDriverDispatchAdvanceGenerationLocked(record);
    }

    if (record->appliedDispatch == record->originalDispatch) {
        retiredSnapshot = *record;
        releaseObject = record->driverObject;
        current = record->originalDispatch;
        RtlZeroMemory(record, sizeof(*record));
        (VOID)kswordArkDriverDispatchAdvanceGenerationLocked(NULL);
        kswordArkDriverDispatchFillRetiredResponse(
            response,
            request->action,
            (UCHAR)request->majorFunction,
            STATUS_SUCCESS,
            request->desiredDispatchAddress,
            &retiredSnapshot,
            current,
            TRUE);
    }
    else {
        kswordArkDriverDispatchFillResponse(
            response,
            request->action,
            (UCHAR)request->majorFunction,
            STATUS_SUCCESS,
            request->desiredDispatchAddress,
            record,
            NULL,
            0ULL,
            NULL,
            TRUE);
    }
    ExReleaseFastMutex(&gKswordArkDriverDispatchState.lock);
    if (driverObject != NULL) {
        ObDereferenceObject(driverObject);
    }
    if (releaseObject != NULL) {
        ObDereferenceObject(releaseObject);
    }
    return STATUS_SUCCESS;

ApplyFailureLocked:
    kswordArkDriverDispatchFillResponse(
        response,
        request->action,
        (UCHAR)request->majorFunction,
        status,
        request->desiredDispatchAddress,
        record,
        driverObject,
        request->targetModuleBase,
        canonicalName,
        FALSE);
    ExReleaseFastMutex(&gKswordArkDriverDispatchState.lock);
    ObDereferenceObject(driverObject);
    return status;
}

static NTSTATUS
kswordArkDriverDispatchRestoreOrAbandon(
    _In_ const KSWORD_ARK_DRIVER_DISPATCH_REQUEST* request,
    _Out_ KSWORD_ARK_DRIVER_DISPATCH_RESPONSE* response
    )
{
    KswDriverDispatchRecord* record = NULL;
    KswDriverDispatchRecord retiredSnapshot;
    PDRIVER_OBJECT releaseObject = NULL;
    PDRIVER_DISPATCH current = NULL;
    PDRIVER_DISPATCH previous = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN changed = FALSE;

    RtlZeroMemory(&retiredSnapshot, sizeof(retiredSnapshot));
    ExAcquireFastMutex(&gKswordArkDriverDispatchState.lock);
    record = kswordArkDriverDispatchFindRecordLocked(
        request->targetModuleBase,
        (UCHAR)request->majorFunction);
    if (record == NULL) {
        kswordArkDriverDispatchFillResponse(
            response,
            request->action,
            (UCHAR)request->majorFunction,
            STATUS_NOT_FOUND,
            request->desiredDispatchAddress,
            NULL,
            NULL,
            request->targetModuleBase,
            NULL,
            FALSE);
        ExReleaseFastMutex(&gKswordArkDriverDispatchState.lock);
        return STATUS_NOT_FOUND;
    }
    if (!kswordArkDriverDispatchRecordMatchesRequest(record, request)) {
        kswordArkDriverDispatchFillResponse(
            response,
            request->action,
            (UCHAR)request->majorFunction,
            STATUS_OBJECT_TYPE_MISMATCH,
            request->desiredDispatchAddress,
            record,
            NULL,
            0ULL,
            NULL,
            FALSE);
        ExReleaseFastMutex(&gKswordArkDriverDispatchState.lock);
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    kswordArkDriverDispatchRefreshRecordLocked(record);
    if ((request->flags &
        KSWORD_ARK_DRIVER_DISPATCH_FLAG_EXPECTED_GENERATION_PRESENT) != 0UL &&
        request->expectedGeneration != record->generation) {
        kswordArkDriverDispatchFillResponse(
            response,
            request->action,
            (UCHAR)request->majorFunction,
            STATUS_RETRY,
            request->desiredDispatchAddress,
            record,
            NULL,
            0ULL,
            NULL,
            FALSE);
        ExReleaseFastMutex(&gKswordArkDriverDispatchState.lock);
        return STATUS_RETRY;
    }

    current = kswordArkDriverDispatchRead(
        record->driverObject,
        record->majorFunction);
    if (request->action == KSWORD_ARK_DRIVER_DISPATCH_ACTION_RESTORE) {
        if (current == record->originalDispatch) {
            status = STATUS_SUCCESS;
        }
        else if (record->owned != FALSE &&
            current == record->appliedDispatch) {
            previous = kswordArkDriverDispatchCompareExchange(
                record->driverObject,
                record->majorFunction,
                record->originalDispatch,
                record->appliedDispatch);
            if (previous == record->appliedDispatch) {
                current = record->originalDispatch;
                changed = TRUE;
                status = STATUS_SUCCESS;
            }
            else {
                kswordArkDriverDispatchRefreshRecordLocked(record);
                status = STATUS_RETRY;
            }
        }
        else {
            record->owned = FALSE;
            record->conflict = TRUE;
            (VOID)kswordArkDriverDispatchAdvanceGenerationLocked(record);
            status = STATUS_OBJECT_TYPE_MISMATCH;
        }
    }

    if (request->action == KSWORD_ARK_DRIVER_DISPATCH_ACTION_ABANDON ||
        (request->action == KSWORD_ARK_DRIVER_DISPATCH_ACTION_RESTORE &&
        NT_SUCCESS(status) && current == record->originalDispatch)) {
        retiredSnapshot = *record;
        releaseObject = record->driverObject;
        RtlZeroMemory(record, sizeof(*record));
        (VOID)kswordArkDriverDispatchAdvanceGenerationLocked(NULL);
        kswordArkDriverDispatchFillRetiredResponse(
            response,
            request->action,
            (UCHAR)request->majorFunction,
            STATUS_SUCCESS,
            request->desiredDispatchAddress,
            &retiredSnapshot,
            current,
            changed);
        ExReleaseFastMutex(&gKswordArkDriverDispatchState.lock);
        ObDereferenceObject(releaseObject);
        return STATUS_SUCCESS;
    }

    kswordArkDriverDispatchFillResponse(
        response,
        request->action,
        (UCHAR)request->majorFunction,
        status,
        request->desiredDispatchAddress,
        record,
        NULL,
        0ULL,
        NULL,
        changed);
    ExReleaseFastMutex(&gKswordArkDriverDispatchState.lock);
    return status;
}

NTSTATUS
kswordArkDriverDispatchInitialize(
    _In_ PDRIVER_OBJECT driverObject
    )
{
    if (driverObject == NULL || KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (InterlockedCompareExchange(
        &gKswordArkDriverDispatchState.initialized,
        0L,
        0L) != 0L) {
        return gKswordArkDriverDispatchState.selfDriverObject == driverObject
            ? STATUS_SUCCESS
            : STATUS_INVALID_DEVICE_STATE;
    }
    RtlZeroMemory(
        &gKswordArkDriverDispatchState,
        sizeof(gKswordArkDriverDispatchState));
    ExInitializeFastMutex(&gKswordArkDriverDispatchState.lock);
    gKswordArkDriverDispatchState.generation = 1UL;
    gKswordArkDriverDispatchState.selfDriverObject = driverObject;
    InterlockedExchange(&gKswordArkDriverDispatchState.initialized, 1L);
    return STATUS_SUCCESS;
}

VOID
kswordArkDriverDispatchUninitialize(
    VOID
    )
{
    PDRIVER_OBJECT releaseObjects[KSW_DRIVER_DISPATCH_RECORD_LIMIT] = { 0 };
    ULONG releaseCount = 0UL;
    ULONG index = 0UL;

    if (InterlockedCompareExchange(
        &gKswordArkDriverDispatchState.initialized,
        0L,
        0L) == 0L) {
        return;
    }
    ExAcquireFastMutex(&gKswordArkDriverDispatchState.lock);
    gKswordArkDriverDispatchState.shuttingDown = TRUE;
    for (index = 0UL; index < KSW_DRIVER_DISPATCH_RECORD_LIMIT; ++index) {
        KswDriverDispatchRecord* record =
            &gKswordArkDriverDispatchState.records[index];
        if (record->inUse == FALSE || record->driverObject == NULL) {
            continue;
        }
        kswordArkDriverDispatchRefreshRecordLocked(record);
        if (record->owned != FALSE &&
            kswordArkDriverDispatchRead(
                record->driverObject,
                record->majorFunction) == record->appliedDispatch) {
            (VOID)kswordArkDriverDispatchCompareExchange(
                record->driverObject,
                record->majorFunction,
                record->originalDispatch,
                record->appliedDispatch);
        }
        releaseObjects[releaseCount++] = record->driverObject;
        RtlZeroMemory(record, sizeof(*record));
    }
    ExReleaseFastMutex(&gKswordArkDriverDispatchState.lock);
    InterlockedExchange(&gKswordArkDriverDispatchState.initialized, 0L);
    for (index = 0UL; index < releaseCount; ++index) {
        ObDereferenceObject(releaseObjects[index]);
    }
    RtlZeroMemory(
        &gKswordArkDriverDispatchState,
        sizeof(gKswordArkDriverDispatchState));
}

NTSTATUS
kswordArkDriverControlDispatch(
    _In_ const KSWORD_ARK_DRIVER_DISPATCH_REQUEST* request,
    _Out_ KSWORD_ARK_DRIVER_DISPATCH_RESPONSE* response
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    if (request == NULL || response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(response, sizeof(*response));
    response->version = KSWORD_ARK_DRIVER_DISPATCH_PROTOCOL_VERSION;
    response->action = request->action;
    response->majorFunction = request->majorFunction;
    response->requestedDispatchAddress = request->desiredDispatchAddress;
    response->targetModuleBase = request->targetModuleBase;
    response->driverObjectAddress = request->expectedDriverObjectAddress;
    response->responseFlags =
        KSWORD_ARK_DRIVER_DISPATCH_RESPONSE_FLAG_WARN_ONLY_POLICY;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL ||
        InterlockedCompareExchange(
            &gKswordArkDriverDispatchState.initialized,
            0L,
            0L) == 0L) {
        status = STATUS_DEVICE_NOT_READY;
    }
    else if (request->version != KSWORD_ARK_DRIVER_DISPATCH_PROTOCOL_VERSION ||
        request->majorFunction > IRP_MJ_MAXIMUM_FUNCTION ||
        (request->flags &
            KSWORD_ARK_DRIVER_DISPATCH_FLAG_TARGET_MODULE_BASE_PRESENT) == 0UL ||
        request->targetModuleBase == 0ULL ||
        !kswordArkDriverDispatchHasTerminatedName(request->driverName)) {
        status = STATUS_INVALID_PARAMETER;
    }
    else if (request->action > KSWORD_ARK_DRIVER_DISPATCH_ACTION_ABANDON) {
        status = STATUS_INVALID_PARAMETER;
    }
    else if (request->action != KSWORD_ARK_DRIVER_DISPATCH_ACTION_QUERY &&
        (((request->flags &
            KSWORD_ARK_DRIVER_DISPATCH_FLAG_EXPECTED_DRIVER_OBJECT_PRESENT) == 0UL) ||
         ((request->flags &
            KSWORD_ARK_DRIVER_DISPATCH_FLAG_EXPECTED_GENERATION_PRESENT) == 0UL) ||
         request->expectedDriverObjectAddress == 0ULL ||
         request->expectedGeneration == 0UL ||
         request->driverName[0] == L'\0')) {
        status = STATUS_INVALID_PARAMETER;
    }
    else if (request->action == KSWORD_ARK_DRIVER_DISPATCH_ACTION_APPLY &&
        (((request->flags &
            KSWORD_ARK_DRIVER_DISPATCH_FLAG_EXPECTED_CURRENT_PRESENT) == 0UL) ||
         ((request->flags &
            KSWORD_ARK_DRIVER_DISPATCH_FLAG_UI_CONFIRMED) == 0UL) ||
         request->confirmationToken !=
            KSWORD_ARK_DRIVER_DISPATCH_CONFIRMATION_TOKEN)) {
        status = STATUS_INVALID_PARAMETER;
    }
    else if (request->action == KSWORD_ARK_DRIVER_DISPATCH_ACTION_ABANDON &&
        (((request->flags &
            KSWORD_ARK_DRIVER_DISPATCH_FLAG_UI_CONFIRMED) == 0UL) ||
         request->confirmationToken !=
            KSWORD_ARK_DRIVER_DISPATCH_CONFIRMATION_TOKEN)) {
        status = STATUS_INVALID_PARAMETER;
    }
    else {
        switch (request->action) {
        case KSWORD_ARK_DRIVER_DISPATCH_ACTION_QUERY:
            return kswordArkDriverDispatchQuery(request, response);
        case KSWORD_ARK_DRIVER_DISPATCH_ACTION_APPLY:
            return kswordArkDriverDispatchApply(request, response);
        case KSWORD_ARK_DRIVER_DISPATCH_ACTION_RESTORE:
        case KSWORD_ARK_DRIVER_DISPATCH_ACTION_ABANDON:
            return kswordArkDriverDispatchRestoreOrAbandon(request, response);
        default:
            status = STATUS_INVALID_PARAMETER;
            break;
        }
    }

    response->lastStatus = status;
    return status;
}

BOOLEAN
kswordArkDriverDispatchHasBlockingRecord(
    _In_ PDRIVER_OBJECT targetDriverObject,
    _In_ ULONGLONG originalRequestModuleBase
    )
{
    ULONG index = 0UL;
    BOOLEAN blocked = FALSE;

    if (targetDriverObject == NULL) {
        return TRUE;
    }
    if (InterlockedCompareExchange(
        &gKswordArkDriverDispatchState.initialized,
        0L,
        0L) == 0L) {
        return FALSE;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return TRUE;
    }

    ExAcquireFastMutex(&gKswordArkDriverDispatchState.lock);
    for (index = 0UL; index < KSW_DRIVER_DISPATCH_RECORD_LIMIT; ++index) {
        const KswDriverDispatchRecord* record =
            &gKswordArkDriverDispatchState.records[index];
        if (record->inUse != FALSE &&
            (record->driverObject == targetDriverObject ||
             (originalRequestModuleBase != 0ULL &&
              record->targetModuleBase == originalRequestModuleBase))) {
            blocked = TRUE;
            break;
        }
    }
    ExReleaseFastMutex(&gKswordArkDriverDispatchState.lock);
    return blocked;
}
