/*++

Module Name:

    driver_image_editor_state.c

Abstract:

    Target identity resolution, live loader binding, transaction-state refresh,
    and response serialization for the unrestricted driver image editor.

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL control path.

--*/

#include "driver_image_editor_internal.h"

#include <ntstrsafe.h>

// Note: IoDriverObjectType restricts object-manager resolution to genuine DriverObject instances.
extern POBJECT_TYPE* IoDriverObjectType;

// Note: WDK headers do not declare this Object Manager entry point; signature is consistent with other DriverObject parsers in the repository.
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

// Note: Protocol size is fixed for x64 alignment and 260 WCHAR object names to prevent silent R0/R3 drift.
C_ASSERT(sizeof(KSWORD_ARK_DRIVER_IMAGE_REQUEST) == 664U);
C_ASSERT(sizeof(KSWORD_ARK_DRIVER_IMAGE_RESPONSE) == 816U);

// Note: The fixed array must contain a terminator before UNICODE_STRING initialization is allowed.
BOOLEAN
kswordArkDriverImageHasTerminatedName(
    _In_reads_(KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) const WCHAR* driverName
    )
{
    ULONG index = 0UL;

    if (driverName == NULL) {
        return FALSE;
    }
    for (index = 0UL;
        index < KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS;
        ++index) {
        if (driverName[index] == L'\0') {
            return TRUE;
        }
    }
    return FALSE;
}

// Note: Object name comparison ignores case, consistent with ObReferenceObjectByName.
BOOLEAN
kswordArkDriverImageNamesEqual(
    _In_z_ const WCHAR* left,
    _In_z_ const WCHAR* right
    )
{
    UNICODE_STRING leftName;
    UNICODE_STRING rightName;

    if (left == NULL || right == NULL ||
        left[0] == L'\0' || right[0] == L'\0') {
        return FALSE;
    }
    RtlInitUnicodeString(&leftName, left);
    RtlInitUnicodeString(&rightName, right);
    return RtlEqualUnicodeString(&leftName, &rightName, TRUE);
}

// Note: Prioritizes stable object names for resolution, allowing continued query and recovery even after DriverStart is edited.
NTSTATUS
kswordArkDriverImageResolveTarget(
    _In_ const KSWORD_ARK_DRIVER_IMAGE_REQUEST* request,
    _Outptr_ PDRIVER_OBJECT* driverObjectOut,
    _Out_writes_(nameChars) PWCHAR canonicalNameOut,
    _In_ ULONG nameChars,
    _Out_ ULONGLONG* targetModuleBaseOut
    )
{
    PDRIVER_OBJECT driverObject = NULL;
    UNICODE_STRING objectName;
    KswDriverImageRecord temporaryRecord;
    KSWORD_ARK_DRIVER_IMAGE_VALUES currentValues;
    ULONG availableMask = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (request == NULL || driverObjectOut == NULL ||
        canonicalNameOut == NULL || nameChars == 0UL ||
        targetModuleBaseOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *driverObjectOut = NULL;
    *targetModuleBaseOut = 0ULL;
    canonicalNameOut[0] = L'\0';
    RtlZeroMemory(&temporaryRecord, sizeof(temporaryRecord));
    RtlZeroMemory(&currentValues, sizeof(currentValues));

    if (request->driverName[0] != L'\0') {
        // Note: No filtering by driver category, product, or name directory; the only type constraint is DriverObject.
        if (IoDriverObjectType == NULL || *IoDriverObjectType == NULL) {
            return STATUS_NOT_SUPPORTED;
        }
        RtlInitUnicodeString(&objectName, request->driverName);
        status = ObReferenceObjectByName(
            &objectName,
            OBJ_CASE_INSENSITIVE,
            NULL,
            0UL,
            *IoDriverObjectType,
            KernelMode,
            NULL,
            (PVOID*)&driverObject);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = RtlStringCchCopyW(
            canonicalNameOut,
            nameChars,
            request->driverName);
        if (!NT_SUCCESS(status)) {
            ObDereferenceObject(driverObject);
            return status;
        }
    }
    else {
        // Note: Read-only first lookup without an object name can reuse the repository's existing module base address to DriverObject resolver.
        if ((request->flags &
            KSWORD_ARK_DRIVER_IMAGE_FLAG_TARGET_MODULE_BASE_PRESENT) == 0UL ||
            request->targetModuleBase == 0ULL) {
            return STATUS_INVALID_PARAMETER;
        }
        status = kswordArkDriverReferenceObjectByModuleBase(
            request->targetModuleBase,
            &driverObject,
            canonicalNameOut,
            nameChars);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    // Note: The object address in the change request must exactly match the object currently returned by the object manager.
    if ((request->flags &
        KSWORD_ARK_DRIVER_IMAGE_FLAG_EXPECTED_DRIVER_OBJECT_PRESENT) != 0UL &&
        request->expectedDriverObjectAddress !=
            (ULONGLONG)(ULONG_PTR)driverObject) {
        ObDereferenceObject(driverObject);
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    if ((request->flags &
        KSWORD_ARK_DRIVER_IMAGE_FLAG_TARGET_MODULE_BASE_PRESENT) != 0UL) {
        *targetModuleBaseOut = request->targetModuleBase;
    }
    else {
        // Note: When no explicit base address is provided, atomically sample the current DriverStart as a record hint without restricting its value.
        temporaryRecord.driverObject = driverObject;
        status = kswordArkDriverImageReadValuesLocked(
            NULL,
            &temporaryRecord,
            &currentValues,
            &availableMask);
        if (!NT_SUCCESS(status) ||
            (availableMask &
             KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_START) == 0UL) {
            ObDereferenceObject(driverObject);
            return NT_SUCCESS(status) ? STATUS_NOT_SUPPORTED : status;
        }
        *targetModuleBaseOut = currentValues.driverStart;
    }

    *driverObjectOut = driverObject;
    return STATUS_SUCCESS;
}

// Note: Uniformly open actual module resources; on failure, Runtime retains the parsed layout for partial diagnostic response.
NTSTATUS
kswordArkDriverImageOpenRuntime(
    _Out_ KswDriverImageRuntime* runtime,
    _In_ BOOLEAN exclusive
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    if (runtime == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    status = kswordArkDriverImageResolveRuntime(runtime);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    return kswordArkDriverImageAcquireRuntime(runtime, exclusive);
}

// Note: On the first binding, precisely lock the DllBase entry; existing bindings must be re-validated via active layout and chain checks.
NTSTATUS
kswordArkDriverImageAttachLoaderLocked(
    _In_ const KswDriverImageRuntime* runtime,
    _Inout_ KswDriverImageRecord* record,
    _Out_ BOOLEAN* stateChanged
    )
{
    KswDriverImageLinkView view;
    KSWORD_ARK_DRIVER_IMAGE_VALUES currentValues;
    ULONG availableMask = 0UL;
    ULONGLONG lookupBase = 0ULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (runtime == NULL || record == NULL || stateChanged == NULL ||
        runtime->resourceAcquired == FALSE) {
        return STATUS_INVALID_PARAMETER;
    }
    *stateChanged = FALSE;
    RtlZeroMemory(&view, sizeof(view));
    RtlZeroMemory(&currentValues, sizeof(currentValues));

    if (record->loaderEntry != NULL && record->loaderLink != NULL) {
        return kswordArkDriverImageInspectRecordLinkLocked(
            runtime,
            record,
            &view);
    }

    // Note: On the first binding, sample the public DriverObject identity; subsequently, require at least one field to match the KLDR exactly.
    status = kswordArkDriverImageReadValuesLocked(
        runtime,
        record,
        &currentValues,
        &availableMask);
    if (!NT_SUCCESS(status) ||
        (availableMask &
         (KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_START |
          KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_SECTION)) !=
        (KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_START |
         KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_SECTION)) {
        return NT_SUCCESS(status) ? STATUS_NOT_SUPPORTED : status;
    }
    lookupBase = record->targetModuleBase;
    if (lookupBase == 0ULL) {
        // Note: Without a frozen base address, use the current DriverStart for precise DllBase lookup only, without interval fuzzy matching.
        lookupBase = currentValues.driverStart;
    }

    status = kswordArkDriverImageLocateLoaderLocked(
        runtime,
        lookupBase,
        &view);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    // Note: If the target base address comes from stale UI rows, do not incorrectly associate this DriverObject with another module's KLDR.
    if (currentValues.driverStart != view.dllBase &&
        currentValues.driverSection != view.entryAddress) {
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    record->loaderEntry = (PVOID)(ULONG_PTR)view.entryAddress;
    record->loaderLink = (PLIST_ENTRY)(ULONG_PTR)view.linkAddress;
    // Note: R0 normalizes and freezes the identity using the actually matched DllBase; subsequent DriverStart modifications do not affect recovery.
    record->targetModuleBase = view.dllBase;
    *stateChanged = TRUE;
    return STATUS_SUCCESS;
}

// Note: Chain refresh follows conservative ownership rules; external restoration to the main chain may retire objects, while unknown dangling states are only marked as conflicts.
NTSTATUS
kswordArkDriverImageRefreshRecordLocked(
    _In_opt_ const KswDriverImageRuntime* runtime,
    _Inout_ KswDriverImageRecord* record,
    _Out_ BOOLEAN* stateChanged
    )
{
    KswDriverImageLinkView view;
    BOOLEAN fieldChanged = FALSE;
    BOOLEAN oldLinkManaged = FALSE;
    BOOLEAN oldLinkOwned = FALSE;
    BOOLEAN oldLinkConflict = FALSE;
    NTSTATUS fieldStatus = STATUS_SUCCESS;
    NTSTATUS linkStatus = STATUS_SUCCESS;

    if (record == NULL || stateChanged == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *stateChanged = FALSE;
    RtlZeroMemory(&view, sizeof(view));
    oldLinkManaged = record->linkManaged;
    oldLinkOwned = record->linkOwned;
    oldLinkConflict = record->linkConflict;

    fieldStatus = kswordArkDriverImageRefreshFieldsLocked(
        runtime,
        record,
        &fieldChanged);

    if (record->linkManaged != FALSE || record->linkConflict != FALSE) {
        if (runtime == NULL || runtime->resourceAcquired == FALSE ||
            record->loaderEntry == NULL || record->loaderLink == NULL) {
            // Note: Resources temporarily unavailable; return capability status only without losing ownership required to restore the self-loop chain later.
            linkStatus = STATUS_NOT_SUPPORTED;
        }
        else {
            linkStatus = kswordArkDriverImageInspectRecordLinkLocked(
                runtime,
                record,
                &view);
            if (!NT_SUCCESS(linkStatus)) {
                record->linkOwned = FALSE;
                record->linkConflict = TRUE;
            }
            else if (view.inList != FALSE) {
                // Note: Valid entries within the main chain are considered recovered; they no longer block unloading regardless of whether they return to their original neighbors.
                record->linkManaged = FALSE;
                record->linkOwned = FALSE;
                record->linkConflict = FALSE;
            }
            else if (view.selfLinked != FALSE &&
                record->linkOwned != FALSE) {
                record->linkConflict = FALSE;
            }
            else {
                record->linkOwned = FALSE;
                record->linkConflict = TRUE;
            }
        }
    }

    *stateChanged = fieldChanged ||
        oldLinkManaged != record->linkManaged ||
        oldLinkOwned != record->linkOwned ||
        oldLinkConflict != record->linkConflict;
    if (!NT_SUCCESS(fieldStatus)) {
        return fieldStatus;
    }
    return linkStatus;
}

// Note: The response includes four sets of values (current/original/applied/requested) and chain/lock addresses, enabling R3 to clearly assess risks.
VOID
kswordArkDriverImageFillResponseLocked(
    _In_ const KswDriverImageState* state,
    _In_ const KswDriverImageResponseContext* context,
    _Out_ KSWORD_ARK_DRIVER_IMAGE_RESPONSE* response
    )
{
    const KswDriverImageRecord* record = NULL;
    KswDriverImageLinkView linkView;
    KSWORD_ARK_DRIVER_IMAGE_VALUES currentValues;
    ULONG availableMask = 0UL;
    NTSTATUS valueStatus = STATUS_SUCCESS;
    NTSTATUS loaderStatus = STATUS_NOT_SUPPORTED;
    BOOLEAN loaderAvailable = FALSE;

    if (state == NULL || context == NULL || context->request == NULL ||
        context->record == NULL || response == NULL) {
        return;
    }
    record = context->record;
    loaderStatus = context->loaderStatus;
    RtlZeroMemory(response, sizeof(*response));
    RtlZeroMemory(&linkView, sizeof(linkView));
    RtlZeroMemory(&currentValues, sizeof(currentValues));

    response->version = KSWORD_ARK_DRIVER_IMAGE_PROTOCOL_VERSION;
    response->action = context->request->action;
    response->lastStatus = context->lastStatus;
    response->generation = context->recordPresent != FALSE
        ? record->generation
        : state->generation;
    response->managedFieldMask = record->managedFieldMask;
    response->ownedFieldMask = record->ownedFieldMask;
    response->conflictFieldMask = record->conflictFieldMask;
    response->changedFieldMask = context->changedFieldMask;
    response->targetModuleBase = record->targetModuleBase;
    response->driverObjectAddress =
        (ULONGLONG)(ULONG_PTR)record->driverObject;
    response->selfDriverObjectAddress =
        (ULONGLONG)(ULONG_PTR)state->selfDriverObject;
    response->loaderEntryAddress =
        (ULONGLONG)(ULONG_PTR)record->loaderEntry;
    response->loaderLinkAddress =
        (ULONGLONG)(ULONG_PTR)record->loaderLink;
    response->originalLinkFlink =
        (ULONGLONG)(ULONG_PTR)record->originalLinkFlink;
    response->originalLinkBlink =
        (ULONGLONG)(ULONG_PTR)record->originalLinkBlink;
    response->originalValues = record->originalValues;
    response->appliedValues = record->appliedValues;
    response->requestedValues = context->request->desiredValues;
    response->responseFlags =
        KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_WARN_ONLY_POLICY;

    if (context->runtime != NULL) {
        response->layoutFlags = context->runtime->layoutFlags;
        response->listHeadAddress =
            (ULONGLONG)(ULONG_PTR)context->runtime->listHead;
        response->listResourceAddress =
            (ULONGLONG)(ULONG_PTR)context->runtime->listResource;
        if (context->runtime->layoutFlags != 0UL) {
            response->responseFlags |=
                KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_LAYOUT_AVAILABLE;
        }
        if (context->runtime->listResource != NULL) {
            response->responseFlags |=
                KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_LIST_LOCK_AVAILABLE;
        }
    }

    valueStatus = kswordArkDriverImageReadValuesLocked(
        context->runtime,
        record,
        &currentValues,
        &availableMask);
    if (NT_SUCCESS(valueStatus)) {
        response->currentValues = currentValues;
    }

    if (context->runtime != NULL &&
        context->runtime->resourceAcquired != FALSE &&
        record->loaderEntry != NULL && record->loaderLink != NULL) {
        loaderStatus = kswordArkDriverImageInspectRecordLinkLocked(
            context->runtime,
            record,
            &linkView);
        if (NT_SUCCESS(loaderStatus)) {
            loaderAvailable = TRUE;
            response->currentLinkFlink =
                (ULONGLONG)(ULONG_PTR)linkView.flink;
            response->currentLinkBlink =
                (ULONGLONG)(ULONG_PTR)linkView.blink;
        }
    }
    response->loaderStatus = loaderStatus;

    if (context->recordPresent != FALSE) {
        response->responseFlags |=
            KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_RECORD_PRESENT;
    }
    if (record->driverObject == state->selfDriverObject) {
        response->responseFlags |=
            KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_SELF_TARGET;
    }
    if (record->ownedFieldMask != 0UL) {
        response->responseFlags |=
            KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_FIELDS_OWNED;
    }
    if (record->conflictFieldMask != 0UL) {
        response->responseFlags |=
            KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_FIELDS_CONFLICT;
    }
    if (record->linkOwned != FALSE) {
        response->responseFlags |=
            KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_LINK_OWNED;
    }
    if (record->linkConflict != FALSE) {
        response->responseFlags |=
            KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_LINK_CONFLICT;
    }
    if (context->changedFieldMask != 0UL ||
        context->linkChanged != FALSE) {
        response->responseFlags |=
            KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_CHANGED;
    }
    if (context->restoredOriginalPosition != FALSE) {
        response->responseFlags |=
            KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_RESTORED_ORIGINAL_POSITION;
    }
    if (context->restoredListTail != FALSE) {
        response->responseFlags |=
            KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_RESTORED_LIST_TAIL;
    }

    if (loaderAvailable != FALSE) {
        response->responseFlags |=
            KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_LOADER_AVAILABLE;
        if (linkView.inList != FALSE) {
            response->responseFlags |=
                KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_LINK_VISIBLE;
        }
        if (linkView.selfLinked != FALSE) {
            response->responseFlags |=
                KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_LINK_HIDDEN;
        }
        if ((availableMask &
            KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_SECTION) != 0UL &&
            currentValues.driverSection ==
                (ULONGLONG)(ULONG_PTR)record->loaderEntry) {
            response->responseFlags |=
                KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_DRIVER_SECTION_MATCH;
        }
        if ((availableMask &
            (KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_START |
             KSWORD_ARK_DRIVER_IMAGE_FIELD_KLDR_DLL_BASE)) ==
            (KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_START |
             KSWORD_ARK_DRIVER_IMAGE_FIELD_KLDR_DLL_BASE) &&
            currentValues.driverStart == currentValues.kldrDllBase) {
            response->responseFlags |=
                KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_DRIVER_START_MATCH;
        }
    }

    if (!NT_SUCCESS(valueStatus) ||
        availableMask != KSWORD_ARK_DRIVER_IMAGE_FIELD_ALL ||
        loaderAvailable == FALSE) {
        response->responseFlags |=
            KSWORD_ARK_DRIVER_IMAGE_RESPONSE_FLAG_PARTIAL_VIEW;
    }

    if (record->conflictFieldMask != 0UL ||
        record->linkConflict != FALSE) {
        response->state = KSWORD_ARK_DRIVER_IMAGE_STATE_CONFLICT;
    }
    else if (record->managedFieldMask != 0UL ||
        record->linkManaged != FALSE) {
        response->state = KSWORD_ARK_DRIVER_IMAGE_STATE_ACTIVE;
    }
    else {
        response->state = KSWORD_ARK_DRIVER_IMAGE_STATE_INACTIVE;
    }

    (VOID)RtlStringCchCopyW(
        response->driverName,
        RTL_NUMBER_OF(response->driverName),
        record->canonicalName);
}
