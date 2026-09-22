/*++

Module Name:

    driver_image_editor.c

Abstract:

    Unrestricted transactional controller for DriverObject image metadata and
    PsLoadedModuleList membership.

    No driver class, product, owner, PnP, file-system, security role, self
    identity, or requested pointer-value policy is applied. Mutations require
    exact object identity, a transaction generation, expected-current values or
    links, explicit confirmation, CAS, and the real loader resource.

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL control path.

--*/

#include "driver_image_editor_internal.h"

#include <ntstrsafe.h>

// Note: The global table stores only a limited number of active/conflicting transactions and their corresponding DriverObject references.
static KswDriverImageState gKswordArkDriverImageState;

// Note: Generation zero is reserved for 'not queried'; any observable state change jumps to a new non-zero value.
static ULONG
kswordArkDriverImageAdvanceGenerationLocked(
    _Inout_opt_ KswDriverImageRecord* record
    )
{
    ++gKswordArkDriverImageState.generation;
    if (gKswordArkDriverImageState.generation == 0UL) {
        ++gKswordArkDriverImageState.generation;
    }
    if (record != NULL) {
        record->generation = gKswordArkDriverImageState.generation;
    }
    return gKswordArkDriverImageState.generation;
}

// Note: Lookup prioritizes the exact object address, followed by the frozen module base address or object name.
static KswDriverImageRecord*
kswordArkDriverImageFindRecordLocked(
    _In_ const KSWORD_ARK_DRIVER_IMAGE_REQUEST* request
    )
{
    ULONG index = 0UL;

    if (request == NULL) {
        return NULL;
    }
    for (index = 0UL; index < KSW_DRIVER_IMAGE_RECORD_LIMIT; ++index) {
        KswDriverImageRecord* record =
            &gKswordArkDriverImageState.records[index];
        BOOLEAN candidate = FALSE;

        if (record->inUse == FALSE) {
            continue;
        }
        if ((request->flags &
            KSWORD_ARK_DRIVER_IMAGE_FLAG_EXPECTED_DRIVER_OBJECT_PRESENT) != 0UL) {
            candidate = request->expectedDriverObjectAddress ==
                (ULONGLONG)(ULONG_PTR)record->driverObject;
        }
        else if ((request->flags &
            KSWORD_ARK_DRIVER_IMAGE_FLAG_TARGET_MODULE_BASE_PRESENT) != 0UL) {
            candidate = request->targetModuleBase ==
                record->targetModuleBase;
        }
        else if (request->driverName[0] != L'\0') {
            candidate = kswordArkDriverImageNamesEqual(
                request->driverName,
                record->canonicalName);
        }
        if (candidate != FALSE) {
            return record;
        }
    }
    return NULL;
}

// Note: The allocator does not immediately publish InUse; the record becomes valid only after the target reference and canonical name are written.
static KswDriverImageRecord*
kswordArkDriverImageAllocateRecordLocked(
    VOID
    )
{
    ULONG index = 0UL;

    for (index = 0UL; index < KSW_DRIVER_IMAGE_RECORD_LIMIT; ++index) {
        KswDriverImageRecord* record =
            &gKswordArkDriverImageState.records[index];
        if (record->inUse == FALSE) {
            RtlZeroMemory(record, sizeof(*record));
            return record;
        }
    }
    return NULL;
}

// Note: An existing record must satisfy every identity field present in the request, not just one.
static BOOLEAN
kswordArkDriverImageRecordMatchesRequest(
    _In_ const KswDriverImageRecord* record,
    _In_ const KSWORD_ARK_DRIVER_IMAGE_REQUEST* request
    )
{
    if (record == NULL || request == NULL || record->inUse == FALSE) {
        return FALSE;
    }
    if ((request->flags &
        KSWORD_ARK_DRIVER_IMAGE_FLAG_EXPECTED_DRIVER_OBJECT_PRESENT) != 0UL &&
        request->expectedDriverObjectAddress !=
            (ULONGLONG)(ULONG_PTR)record->driverObject) {
        return FALSE;
    }
    if ((request->flags &
        KSWORD_ARK_DRIVER_IMAGE_FLAG_TARGET_MODULE_BASE_PRESENT) != 0UL &&
        request->targetModuleBase != record->targetModuleBase) {
        return FALSE;
    }
    if (request->driverName[0] != L'\0' &&
        !kswordArkDriverImageNamesEqual(
            request->driverName,
            record->canonicalName)) {
        return FALSE;
    }
    return TRUE;
}

// Note: The record can be safely retired when there are no managed fields, field conflicts, chain management issues, or chain conflicts.
static BOOLEAN
kswordArkDriverImageRecordIsClean(
    _In_ const KswDriverImageRecord* record
    )
{
    return record != NULL &&
        record->managedFieldMask == 0UL &&
        record->ownedFieldMask == 0UL &&
        record->conflictFieldMask == 0UL &&
        record->linkManaged == FALSE &&
        record->linkOwned == FALSE &&
        record->linkConflict == FALSE;
}

// Note: The new record takes ownership of one object reference from the caller and freezes the module base address obtained from the initial resolution.
static NTSTATUS
kswordArkDriverImageInitializeRecordLocked(
    _Inout_ KswDriverImageRecord* record,
    _In_ PDRIVER_OBJECT driverObject,
    _In_ ULONGLONG targetModuleBase,
    _In_z_ const WCHAR* canonicalName
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    if (record == NULL || driverObject == NULL ||
        canonicalName == NULL || canonicalName[0] == L'\0') {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(record, sizeof(*record));
    record->driverObject = driverObject;
    record->targetModuleBase = targetModuleBase;
    record->generation = gKswordArkDriverImageState.generation;
    status = RtlStringCchCopyW(
        record->canonicalName,
        RTL_NUMBER_OF(record->canonicalName),
        canonicalName);
    if (!NT_SUCCESS(status)) {
        RtlZeroMemory(record, sizeof(*record));
        return status;
    }
    record->inUse = TRUE;
    return STATUS_SUCCESS;
}

// Note: Runtime failures do not prevent pure DriverObject field operations, but explicitly return loaderStatus.
static NTSTATUS
kswordArkDriverImagePrepareRuntimeLocked(
    _Inout_ KswDriverImageRecord* record,
    _In_ BOOLEAN exclusive,
    _Out_ KswDriverImageRuntime* runtime,
    _Out_ NTSTATUS* loaderStatus,
    _Out_ BOOLEAN* stateChanged
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    if (record == NULL || runtime == NULL ||
        loaderStatus == NULL || stateChanged == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *stateChanged = FALSE;
    *loaderStatus = STATUS_NOT_SUPPORTED;
    RtlZeroMemory(runtime, sizeof(*runtime));

    status = kswordArkDriverImageOpenRuntime(runtime, exclusive);
    if (!NT_SUCCESS(status)) {
        *loaderStatus = status;
        return status;
    }
    status = kswordArkDriverImageAttachLoaderLocked(
        runtime,
        record,
        stateChanged);
    *loaderStatus = status;
    return status;
}

// Note: Only release based on actual acquisition flags; Runtime objects that parsed successfully but failed to acquire will not cause erroneous release of system resources.
static VOID
kswordArkDriverImageCloseRuntime(
    _Inout_ KswDriverImageRuntime* runtime
    )
{
    if (runtime != NULL && runtime->resourceAcquired != FALSE) {
        kswordArkDriverImageReleaseRuntime(runtime);
    }
}

// Note: Construct minimal failure response when no referenceable object exists; never treat an R3 address as a readable DriverObject.
static VOID
kswordArkDriverImageFillBasicResponse(
    _In_ const KSWORD_ARK_DRIVER_IMAGE_REQUEST* request,
    _In_ NTSTATUS status,
    _Out_ KSWORD_ARK_DRIVER_IMAGE_RESPONSE* response
    )
{
    RtlZeroMemory(response, sizeof(*response));
    response->version = KSWORD_ARK_DRIVER_IMAGE_PROTOCOL_VERSION;
    response->action = request->action;
    response->state = KSWORD_ARK_DRIVER_IMAGE_STATE_INACTIVE;
    response->responseFlags =
        KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_WARN_ONLY_POLICY |
        KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_PARTIAL_VIEW;
    response->lastStatus = status;
    response->loaderStatus = STATUS_NOT_SUPPORTED;
    response->generation = gKswordArkDriverImageState.generation;
    response->targetModuleBase = request->targetModuleBase;
    response->driverObjectAddress =
        request->expectedDriverObjectAddress;
    response->selfDriverObjectAddress = (ULONGLONG)(ULONG_PTR)
        gKswordArkDriverImageState.selfDriverObject;
    response->requestedValues = request->desiredValues;
    if (kswordArkDriverImageHasTerminatedName(request->driverName)) {
        (VOID)RtlStringCchCopyW(
            response->driverName,
            RTL_NUMBER_OF(response->driverName),
            request->driverName);
    }
}

// Note: Retire a complete snapshot copy for this response and transfer object ownership to be released outside the lock.
static PDRIVER_OBJECT
kswordArkDriverImageRetireRecordLocked(
    _Inout_ KswDriverImageRecord* record,
    _Out_ KswDriverImageRecord* snapshot,
    _In_ BOOLEAN advanceGeneration
    )
{
    PDRIVER_OBJECT releaseObject = NULL;

    *snapshot = *record;
    releaseObject = record->driverObject;
    RtlZeroMemory(record, sizeof(*record));
    if (advanceGeneration != FALSE) {
        (VOID)kswordArkDriverImageAdvanceGenerationLocked(NULL);
    }
    return releaseObject;
}

// Note: QUERY parses live objects and prioritizes reusing records to return an atomic consistent snapshot of fields/links.
static NTSTATUS
kswordArkDriverImageQuery(
    _In_ const KSWORD_ARK_DRIVER_IMAGE_REQUEST* request,
    _Out_ KSWORD_ARK_DRIVER_IMAGE_RESPONSE* response
    )
{
    KswDriverImageRuntime runtime;
    KswDriverImageRecord temporaryRecord;
    KswDriverImageRecord retiredSnapshot;
    KswDriverImageResponseContext context;
    KswDriverImageRecord* record = NULL;
    PDRIVER_OBJECT resolvedObject = NULL;
    PDRIVER_OBJECT retiredObject = NULL;
    WCHAR canonicalName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
    ULONGLONG targetModuleBase = 0ULL;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS loaderStatus = STATUS_NOT_SUPPORTED;
    BOOLEAN attachChanged = FALSE;
    BOOLEAN refreshChanged = FALSE;

    RtlZeroMemory(&runtime, sizeof(runtime));
    RtlZeroMemory(&temporaryRecord, sizeof(temporaryRecord));
    RtlZeroMemory(&retiredSnapshot, sizeof(retiredSnapshot));
    RtlZeroMemory(&context, sizeof(context));

    status = kswordArkDriverImageResolveTarget(
        request,
        &resolvedObject,
        canonicalName,
        RTL_NUMBER_OF(canonicalName),
        &targetModuleBase);
    if (!NT_SUCCESS(status)) {
        kswordArkDriverImageFillBasicResponse(request, status, response);
        return status;
    }

    ExAcquireFastMutex(&gKswordArkDriverImageState.lock);
    record = kswordArkDriverImageFindRecordLocked(request);
    if (record != NULL &&
        (record->driverObject != resolvedObject ||
         !kswordArkDriverImageRecordMatchesRequest(record, request))) {
        status = STATUS_OBJECT_TYPE_MISMATCH;
        kswordArkDriverImageFillBasicResponse(request, status, response);
        ExReleaseFastMutex(&gKswordArkDriverImageState.lock);
        ObDereferenceObject(resolvedObject);
        return status;
    }
    if (record == NULL) {
        temporaryRecord.driverObject = resolvedObject;
        temporaryRecord.targetModuleBase = targetModuleBase;
        (VOID)RtlStringCchCopyW(
            temporaryRecord.canonicalName,
            RTL_NUMBER_OF(temporaryRecord.canonicalName),
            canonicalName);
        record = &temporaryRecord;
    }

    (VOID)kswordArkDriverImagePrepareRuntimeLocked(
        record,
        FALSE,
        &runtime,
        &loaderStatus,
        &attachChanged);
    if (record != &temporaryRecord) {
        (VOID)kswordArkDriverImageRefreshRecordLocked(
            runtime.resourceAcquired != FALSE ? &runtime : NULL,
            record,
            &refreshChanged);
        if (attachChanged != FALSE || refreshChanged != FALSE) {
            (VOID)kswordArkDriverImageAdvanceGenerationLocked(record);
        }
    }

    context.request = request;
    context.record = record;
    context.runtime = &runtime;
    context.lastStatus = STATUS_SUCCESS;
    context.loaderStatus = loaderStatus;
    context.recordPresent = record != &temporaryRecord;

    if (record != &temporaryRecord &&
        kswordArkDriverImageRecordIsClean(record)) {
        retiredObject = kswordArkDriverImageRetireRecordLocked(
            record,
            &retiredSnapshot,
            TRUE);
        context.record = &retiredSnapshot;
        context.recordPresent = FALSE;
    }
    kswordArkDriverImageFillResponseLocked(
        &gKswordArkDriverImageState,
        &context,
        response);
    kswordArkDriverImageCloseRuntime(&runtime);
    ExReleaseFastMutex(&gKswordArkDriverImageState.lock);

    ObDereferenceObject(resolvedObject);
    if (retiredObject != NULL) {
        ObDereferenceObject(retiredObject);
    }
    return STATUS_SUCCESS;
}

// Note: APPLY_FIELDS and HIDE share identity, generation, resources, and record lifecycle, branching only at the final primitive.
static NTSTATUS
kswordArkDriverImageApplyOrHide(
    _In_ const KSWORD_ARK_DRIVER_IMAGE_REQUEST* request,
    _Out_ KSWORD_ARK_DRIVER_IMAGE_RESPONSE* response
    )
{
    KswDriverImageRuntime runtime;
    KswDriverImageRecord retiredSnapshot;
    KswDriverImageRecord beforeAction;
    KswDriverImageResponseContext context;
    KswDriverImageRecord* record = NULL;
    PDRIVER_OBJECT resolvedObject = NULL;
    PDRIVER_OBJECT retiredObject = NULL;
    WCHAR canonicalName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
    ULONGLONG targetModuleBase = 0ULL;
    ULONG changedFieldMask = 0UL;
    ULONG rollbackConflictMask = 0UL;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS loaderStatus = STATUS_NOT_SUPPORTED;
    BOOLEAN newRecord = FALSE;
    BOOLEAN attachChanged = FALSE;
    BOOLEAN refreshChanged = FALSE;
    BOOLEAN linkChanged = FALSE;
    BOOLEAN recordChanged = FALSE;

    RtlZeroMemory(&runtime, sizeof(runtime));
    RtlZeroMemory(&retiredSnapshot, sizeof(retiredSnapshot));
    RtlZeroMemory(&beforeAction, sizeof(beforeAction));
    RtlZeroMemory(&context, sizeof(context));

    status = kswordArkDriverImageResolveTarget(
        request,
        &resolvedObject,
        canonicalName,
        RTL_NUMBER_OF(canonicalName),
        &targetModuleBase);
    if (!NT_SUCCESS(status)) {
        kswordArkDriverImageFillBasicResponse(request, status, response);
        return status;
    }

    ExAcquireFastMutex(&gKswordArkDriverImageState.lock);
    if (gKswordArkDriverImageState.shuttingDown != FALSE) {
        status = STATUS_DELETE_PENDING;
        goto ApplyOrHideFailure;
    }

    record = kswordArkDriverImageFindRecordLocked(request);
    if (record != NULL) {
        if (record->driverObject != resolvedObject ||
            !kswordArkDriverImageRecordMatchesRequest(record, request)) {
            status = STATUS_OBJECT_TYPE_MISMATCH;
            goto ApplyOrHideFailure;
        }
    }
    else {
        record = kswordArkDriverImageAllocateRecordLocked();
        if (record == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto ApplyOrHideFailure;
        }
        status = kswordArkDriverImageInitializeRecordLocked(
            record,
            resolvedObject,
            targetModuleBase,
            canonicalName);
        if (!NT_SUCCESS(status)) {
            record = NULL;
            goto ApplyOrHideFailure;
        }
        resolvedObject = NULL;
        newRecord = TRUE;
    }

    (VOID)kswordArkDriverImagePrepareRuntimeLocked(
        record,
        TRUE,
        &runtime,
        &loaderStatus,
        &attachChanged);
    if (newRecord == FALSE) {
        (VOID)kswordArkDriverImageRefreshRecordLocked(
            runtime.resourceAcquired != FALSE ? &runtime : NULL,
            record,
            &refreshChanged);
        if (attachChanged != FALSE || refreshChanged != FALSE) {
            (VOID)kswordArkDriverImageAdvanceGenerationLocked(record);
        }
        if (request->expectedGeneration != record->generation) {
            status = STATUS_RETRY;
            goto ApplyOrHideRespond;
        }
    }

    beforeAction = *record;
    if (request->action ==
        KSWORD_ARK_DRIVER_IMAGE_ACTION_APPLY_FIELDS) {
        if ((request->fieldMask &
            (KSWORD_ARK_DRIVER_IMAGE_FIELD_KLDR_DLL_BASE |
             KSWORD_ARK_DRIVER_IMAGE_FIELD_KLDR_SIZE_OF_IMAGE)) != 0UL &&
            (runtime.resourceAcquired == FALSE ||
             !NT_SUCCESS(loaderStatus))) {
            status = NT_SUCCESS(loaderStatus)
                ? STATUS_NOT_SUPPORTED
                : loaderStatus;
        }
        else {
            status = kswordArkDriverImageApplyFieldsLocked(
                runtime.resourceAcquired != FALSE ? &runtime : NULL,
                record,
                request->fieldMask,
                &request->expectedValues,
                &request->desiredValues,
                &changedFieldMask,
                &rollbackConflictMask);
        }
    }
    else {
        if (runtime.resourceAcquired == FALSE ||
            !NT_SUCCESS(loaderStatus)) {
            status = NT_SUCCESS(loaderStatus)
                ? STATUS_NOT_SUPPORTED
                : loaderStatus;
        }
        else {
            status = kswordArkDriverImageHideLinkLocked(
                &runtime,
                record,
                (PLIST_ENTRY)(ULONG_PTR)request->expectedLinkFlink,
                (PLIST_ENTRY)(ULONG_PTR)request->expectedLinkBlink,
                &linkChanged);
        }
    }

    recordChanged =
        changedFieldMask != 0UL ||
        rollbackConflictMask != 0UL ||
        linkChanged != FALSE ||
        beforeAction.managedFieldMask != record->managedFieldMask ||
        beforeAction.ownedFieldMask != record->ownedFieldMask ||
        beforeAction.conflictFieldMask != record->conflictFieldMask ||
        beforeAction.linkManaged != record->linkManaged ||
        beforeAction.linkOwned != record->linkOwned ||
        beforeAction.linkConflict != record->linkConflict;
    if (recordChanged != FALSE) {
        (VOID)kswordArkDriverImageAdvanceGenerationLocked(record);
    }

ApplyOrHideRespond:
    context.request = request;
    context.record = record;
    context.runtime = &runtime;
    context.lastStatus = status;
    context.loaderStatus = loaderStatus;
    context.changedFieldMask = changedFieldMask;
    context.linkChanged = linkChanged;
    context.recordPresent = TRUE;

    if (kswordArkDriverImageRecordIsClean(record)) {
        retiredObject = kswordArkDriverImageRetireRecordLocked(
            record,
            &retiredSnapshot,
            newRecord == FALSE || recordChanged != FALSE);
        context.record = &retiredSnapshot;
        context.recordPresent = FALSE;
    }
    kswordArkDriverImageFillResponseLocked(
        &gKswordArkDriverImageState,
        &context,
        response);
    kswordArkDriverImageCloseRuntime(&runtime);
    ExReleaseFastMutex(&gKswordArkDriverImageState.lock);

    if (resolvedObject != NULL) {
        ObDereferenceObject(resolvedObject);
    }
    if (retiredObject != NULL) {
        ObDereferenceObject(retiredObject);
    }
    return status;

ApplyOrHideFailure:
    kswordArkDriverImageFillBasicResponse(request, status, response);
    kswordArkDriverImageCloseRuntime(&runtime);
    ExReleaseFastMutex(&gKswordArkDriverImageState.lock);
    if (resolvedObject != NULL) {
        ObDereferenceObject(resolvedObject);
    }
    return status;
}

// Note: RESTORE can restore fields and chain segments partially; ABANDON explicitly retains all current hazardous values and discards the record.
static NTSTATUS
kswordArkDriverImageRestoreOrAbandon(
    _In_ const KSWORD_ARK_DRIVER_IMAGE_REQUEST* request,
    _Out_ KSWORD_ARK_DRIVER_IMAGE_RESPONSE* response
    )
{
    KswDriverImageRuntime runtime;
    KswDriverImageRecord retiredSnapshot;
    KswDriverImageRecord beforeAction;
    KswDriverImageResponseContext context;
    KswDriverImageRecord* record = NULL;
    PDRIVER_OBJECT retiredObject = NULL;
    ULONG changedFieldMask = 0UL;
    ULONG failedFieldMask = 0UL;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS fieldStatus = STATUS_SUCCESS;
    NTSTATUS linkStatus = STATUS_SUCCESS;
    NTSTATUS loaderStatus = STATUS_NOT_SUPPORTED;
    BOOLEAN attachChanged = FALSE;
    BOOLEAN refreshChanged = FALSE;
    BOOLEAN linkChanged = FALSE;
    BOOLEAN originalPosition = FALSE;
    BOOLEAN recordChanged = FALSE;

    RtlZeroMemory(&runtime, sizeof(runtime));
    RtlZeroMemory(&retiredSnapshot, sizeof(retiredSnapshot));
    RtlZeroMemory(&beforeAction, sizeof(beforeAction));
    RtlZeroMemory(&context, sizeof(context));

    ExAcquireFastMutex(&gKswordArkDriverImageState.lock);
    record = kswordArkDriverImageFindRecordLocked(request);
    if (record == NULL) {
        status = STATUS_NOT_FOUND;
        kswordArkDriverImageFillBasicResponse(request, status, response);
        ExReleaseFastMutex(&gKswordArkDriverImageState.lock);
        return status;
    }
    if (!kswordArkDriverImageRecordMatchesRequest(record, request)) {
        status = STATUS_OBJECT_TYPE_MISMATCH;
        goto RestoreRespond;
    }

    if (request->action == KSWORD_ARK_DRIVER_IMAGE_ACTION_ABANDON) {
        if (request->expectedGeneration != record->generation) {
            status = STATUS_RETRY;
            goto RestoreRespond;
        }
        (VOID)kswordArkDriverImagePrepareRuntimeLocked(
            record,
            FALSE,
            &runtime,
            &loaderStatus,
            &attachChanged);
        retiredObject = kswordArkDriverImageRetireRecordLocked(
            record,
            &retiredSnapshot,
            TRUE);
        context.request = request;
        context.record = &retiredSnapshot;
        context.runtime = &runtime;
        context.lastStatus = STATUS_SUCCESS;
        context.loaderStatus = loaderStatus;
        context.recordPresent = FALSE;
        kswordArkDriverImageFillResponseLocked(
            &gKswordArkDriverImageState,
            &context,
            response);
        kswordArkDriverImageCloseRuntime(&runtime);
        ExReleaseFastMutex(&gKswordArkDriverImageState.lock);
        ObDereferenceObject(retiredObject);
        return STATUS_SUCCESS;
    }

    (VOID)kswordArkDriverImagePrepareRuntimeLocked(
        record,
        TRUE,
        &runtime,
        &loaderStatus,
        &attachChanged);
    (VOID)kswordArkDriverImageRefreshRecordLocked(
        runtime.resourceAcquired != FALSE ? &runtime : NULL,
        record,
        &refreshChanged);
    if (attachChanged != FALSE || refreshChanged != FALSE) {
        (VOID)kswordArkDriverImageAdvanceGenerationLocked(record);
    }
    if (request->expectedGeneration != record->generation) {
        status = STATUS_RETRY;
        goto RestoreRespond;
    }

    beforeAction = *record;
    fieldStatus = kswordArkDriverImageRestoreFieldsLocked(
        runtime.resourceAcquired != FALSE ? &runtime : NULL,
        record,
        request->fieldMask,
        &changedFieldMask,
        &failedFieldMask);
    status = fieldStatus;

    if ((request->flags &
        KSWORD_ARK_DRIVER_IMAGE_FLAG_RESTORE_LINK) != 0UL) {
        if (runtime.resourceAcquired == FALSE ||
            !NT_SUCCESS(loaderStatus)) {
            linkStatus = NT_SUCCESS(loaderStatus)
                ? STATUS_NOT_SUPPORTED
                : loaderStatus;
        }
        else {
            linkStatus = kswordArkDriverImageRestoreLinkLocked(
                &runtime,
                record,
                &linkChanged,
                &originalPosition);
        }
        if (NT_SUCCESS(status) && !NT_SUCCESS(linkStatus)) {
            status = linkStatus;
        }
    }

    recordChanged =
        changedFieldMask != 0UL ||
        failedFieldMask != 0UL ||
        linkChanged != FALSE ||
        beforeAction.managedFieldMask != record->managedFieldMask ||
        beforeAction.ownedFieldMask != record->ownedFieldMask ||
        beforeAction.conflictFieldMask != record->conflictFieldMask ||
        beforeAction.linkManaged != record->linkManaged ||
        beforeAction.linkOwned != record->linkOwned ||
        beforeAction.linkConflict != record->linkConflict;
    if (recordChanged != FALSE) {
        (VOID)kswordArkDriverImageAdvanceGenerationLocked(record);
    }

RestoreRespond:
    context.request = request;
    context.record = record;
    context.runtime = &runtime;
    context.lastStatus = status;
    context.loaderStatus = loaderStatus;
    context.changedFieldMask = changedFieldMask;
    context.linkChanged = linkChanged;
    context.restoredOriginalPosition =
        linkChanged != FALSE && originalPosition != FALSE;
    context.restoredListTail =
        linkChanged != FALSE && originalPosition == FALSE;
    context.recordPresent = TRUE;

    if (NT_SUCCESS(status) && kswordArkDriverImageRecordIsClean(record)) {
        retiredObject = kswordArkDriverImageRetireRecordLocked(
            record,
            &retiredSnapshot,
            TRUE);
        context.record = &retiredSnapshot;
        context.recordPresent = FALSE;
    }
    kswordArkDriverImageFillResponseLocked(
        &gKswordArkDriverImageState,
        &context,
        response);
    kswordArkDriverImageCloseRuntime(&runtime);
    ExReleaseFastMutex(&gKswordArkDriverImageState.lock);
    if (retiredObject != NULL) {
        ObDereferenceObject(retiredObject);
    }
    return status;
}

// Note: initialize without referencing the DriverObject itself; its lifecycle naturally covers the entire WDF driver instance.
NTSTATUS
kswordArkDriverImageInitialize(
    _In_ PDRIVER_OBJECT driverObject
    )
{
    if (driverObject == NULL || KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (InterlockedCompareExchange(
        &gKswordArkDriverImageState.initialized,
        0L,
        0L) != 0L) {
        return gKswordArkDriverImageState.selfDriverObject == driverObject
            ? STATUS_SUCCESS
            : STATUS_INVALID_DEVICE_STATE;
    }

    RtlZeroMemory(
        &gKswordArkDriverImageState,
        sizeof(gKswordArkDriverImageState));
    ExInitializeFastMutex(&gKswordArkDriverImageState.lock);
    gKswordArkDriverImageState.generation = 1UL;
    gKswordArkDriverImageState.selfDriverObject = driverObject;
    InterlockedExchange(
        &gKswordArkDriverImageState.initialized,
        1L);
    return STATUS_SUCCESS;
}

// Note: On normal unload, attempt to restore fields and self-loops still owned by the transaction; release the record after leaving race values unchanged.
VOID
kswordArkDriverImageUninitialize(
    VOID
    )
{
    KswDriverImageRuntime runtime;
    PDRIVER_OBJECT releaseObjects[KSW_DRIVER_IMAGE_RECORD_LIMIT] = { 0 };
    ULONG releaseCount = 0UL;
    ULONG index = 0UL;
    BOOLEAN runtimeOpened = FALSE;

    if (InterlockedCompareExchange(
        &gKswordArkDriverImageState.initialized,
        0L,
        0L) == 0L) {
        return;
    }
    RtlZeroMemory(&runtime, sizeof(runtime));

    ExAcquireFastMutex(&gKswordArkDriverImageState.lock);
    gKswordArkDriverImageState.shuttingDown = TRUE;
    if (NT_SUCCESS(kswordArkDriverImageOpenRuntime(&runtime, TRUE))) {
        runtimeOpened = TRUE;
    }

    for (index = 0UL; index < KSW_DRIVER_IMAGE_RECORD_LIMIT; ++index) {
        KswDriverImageRecord* record =
            &gKswordArkDriverImageState.records[index];
        ULONG changedMask = 0UL;
        ULONG failedMask = 0UL;
        BOOLEAN linkChanged = FALSE;
        BOOLEAN originalPosition = FALSE;
        BOOLEAN refreshChanged = FALSE;

        if (record->inUse == FALSE || record->driverObject == NULL) {
            continue;
        }
        (VOID)kswordArkDriverImageRefreshRecordLocked(
            runtimeOpened != FALSE ? &runtime : NULL,
            record,
            &refreshChanged);
        (VOID)kswordArkDriverImageRestoreFieldsLocked(
            runtimeOpened != FALSE ? &runtime : NULL,
            record,
            record->managedFieldMask,
            &changedMask,
            &failedMask);
        if (record->linkManaged != FALSE &&
            record->linkOwned != FALSE &&
            runtimeOpened != FALSE) {
            (VOID)kswordArkDriverImageRestoreLinkLocked(
                &runtime,
                record,
                &linkChanged,
                &originalPosition);
        }
        releaseObjects[releaseCount++] = record->driverObject;
        RtlZeroMemory(record, sizeof(*record));
    }

    kswordArkDriverImageCloseRuntime(&runtime);
    ExReleaseFastMutex(&gKswordArkDriverImageState.lock);
    InterlockedExchange(
        &gKswordArkDriverImageState.initialized,
        0L);

    for (index = 0UL; index < releaseCount; ++index) {
        ObDereferenceObject(releaseObjects[index]);
    }
    RtlZeroMemory(
        &gKswordArkDriverImageState,
        sizeof(gKswordArkDriverImageState));
}

// Note: The protocol entry performs only structure/confirmation/concurrency precondition checks, without adding target categories or value range policies.
NTSTATUS
kswordArkDriverControlImage(
    _In_ const KSWORD_ARK_DRIVER_IMAGE_REQUEST* request,
    _Out_ KSWORD_ARK_DRIVER_IMAGE_RESPONSE* response
    )
{
    const ULONG kAllowedFlags =
        KSWORD_ARK_DRIVER_IMAGE_FLAG_TARGET_MODULE_BASE_PRESENT |
        KSWORD_ARK_DRIVER_IMAGE_FLAG_EXPECTED_DRIVER_OBJECT_PRESENT |
        KSWORD_ARK_DRIVER_IMAGE_FLAG_EXPECTED_GENERATION_PRESENT |
        KSWORD_ARK_DRIVER_IMAGE_FLAG_EXPECTED_VALUES_PRESENT |
        KSWORD_ARK_DRIVER_IMAGE_FLAG_EXPECTED_LINKS_PRESENT |
        KSWORD_ARK_DRIVER_IMAGE_FLAG_UI_CONFIRMED |
        KSWORD_ARK_DRIVER_IMAGE_FLAG_RESTORE_LINK;
    NTSTATUS status = STATUS_SUCCESS;

    if (request == NULL || response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    kswordArkDriverImageFillBasicResponse(
        request,
        STATUS_INVALID_PARAMETER,
        response);

    if (KeGetCurrentIrql() != PASSIVE_LEVEL ||
        InterlockedCompareExchange(
            &gKswordArkDriverImageState.initialized,
            0L,
            0L) == 0L) {
        status = STATUS_DEVICE_NOT_READY;
    }
    else if (request->version !=
        KSWORD_ARK_DRIVER_IMAGE_PROTOCOL_VERSION ||
        request->action > KSWORD_ARK_DRIVER_IMAGE_ACTION_ABANDON ||
        (request->flags & ~kAllowedFlags) != 0UL ||
        request->reserved0 != 0UL || request->reserved1 != 0UL ||
        !kswordArkDriverImageHasTerminatedName(request->driverName) ||
        (request->fieldMask &
         ~KSWORD_ARK_DRIVER_IMAGE_FIELD_ALL) != 0UL) {
        status = STATUS_INVALID_PARAMETER;
    }
    else if (request->driverName[0] == L'\0' &&
        (((request->flags &
           KSWORD_ARK_DRIVER_IMAGE_FLAG_TARGET_MODULE_BASE_PRESENT) == 0UL) ||
         request->targetModuleBase == 0ULL)) {
        status = STATUS_INVALID_PARAMETER;
    }
    else if (request->action != KSWORD_ARK_DRIVER_IMAGE_ACTION_QUERY &&
        (((request->flags &
           KSWORD_ARK_DRIVER_IMAGE_FLAG_EXPECTED_DRIVER_OBJECT_PRESENT) == 0UL) ||
         ((request->flags &
           KSWORD_ARK_DRIVER_IMAGE_FLAG_EXPECTED_GENERATION_PRESENT) == 0UL) ||
         ((request->flags &
           KSWORD_ARK_DRIVER_IMAGE_FLAG_UI_CONFIRMED) == 0UL) ||
         request->expectedDriverObjectAddress == 0ULL ||
         request->expectedGeneration == 0UL ||
         request->driverName[0] == L'\0' ||
         request->confirmationToken !=
            KSWORD_ARK_DRIVER_IMAGE_CONFIRMATION_TOKEN)) {
        status = STATUS_INVALID_PARAMETER;
    }
    else if (request->action ==
        KSWORD_ARK_DRIVER_IMAGE_ACTION_APPLY_FIELDS &&
        (request->fieldMask == 0UL ||
         (request->flags &
          KSWORD_ARK_DRIVER_IMAGE_FLAG_EXPECTED_VALUES_PRESENT) == 0UL)) {
        status = STATUS_INVALID_PARAMETER;
    }
    else if (request->action == KSWORD_ARK_DRIVER_IMAGE_ACTION_HIDE &&
        (request->flags &
         KSWORD_ARK_DRIVER_IMAGE_FLAG_EXPECTED_LINKS_PRESENT) == 0UL) {
        status = STATUS_INVALID_PARAMETER;
    }
    else {
        switch (request->action) {
        case KSWORD_ARK_DRIVER_IMAGE_ACTION_QUERY:
            return kswordArkDriverImageQuery(request, response);
        case KSWORD_ARK_DRIVER_IMAGE_ACTION_APPLY_FIELDS:
        case KSWORD_ARK_DRIVER_IMAGE_ACTION_HIDE:
            return kswordArkDriverImageApplyOrHide(request, response);
        case KSWORD_ARK_DRIVER_IMAGE_ACTION_RESTORE:
        case KSWORD_ARK_DRIVER_IMAGE_ACTION_ABANDON:
            return kswordArkDriverImageRestoreOrAbandon(request, response);
        default:
            status = STATUS_INVALID_PARAMETER;
            break;
        }
    }

    response->lastStatus = status;
    return status;
}

// Note: Any active or conflicting record blocks KSword's own forced unload path; it is only released after abandonment.
BOOLEAN
kswordArkDriverImageHasBlockingRecord(
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
        &gKswordArkDriverImageState.initialized,
        0L,
        0L) == 0L) {
        return FALSE;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return TRUE;
    }

    ExAcquireFastMutex(&gKswordArkDriverImageState.lock);
    for (index = 0UL; index < KSW_DRIVER_IMAGE_RECORD_LIMIT; ++index) {
        const KswDriverImageRecord* record =
            &gKswordArkDriverImageState.records[index];
        if (record->inUse != FALSE &&
            (record->driverObject == targetDriverObject ||
             (originalRequestModuleBase != 0ULL &&
              record->targetModuleBase == originalRequestModuleBase))) {
            blocked = TRUE;
            break;
        }
    }
    ExReleaseFastMutex(&gKswordArkDriverImageState.lock);
    return blocked;
}
