/*++

Module Name:

    driver_image_editor_fields.c

Abstract:

    Atomic DriverObject/KLDR field transaction helpers with multi-field
    compare-and-swap, reverse rollback, conservative ownership refresh, and
    restore-to-original semantics.

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL control path.

--*/

#include "driver_image_editor_internal.h"

// Note: Fields are applied in a fixed order; during rollback, strictly traverse in reverse to avoid uncertain partial transaction ordering.
static const ULONG kGKswordArkDriverImageFields[] = {
    KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_START,
    KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_SIZE,
    KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_SECTION,
    KSWORD_ARK_DRIVER_IMAGE_FIELD_KLDR_DLL_BASE,
    KSWORD_ARK_DRIVER_IMAGE_FIELD_KLDR_SIZE_OF_IMAGE
};

C_ASSERT(sizeof(PVOID) == sizeof(ULONGLONG));

// Note: The two KLDR fields depend on the active layout and PsLoadedModuleResource, while the three DriverObject fields do not.
static BOOLEAN
kswordArkDriverImageIsLoaderField(
    _In_ ULONG field
    )
{
    return field == KSWORD_ARK_DRIVER_IMAGE_FIELD_KLDR_DLL_BASE ||
        field == KSWORD_ARK_DRIVER_IMAGE_FIELD_KLDR_SIZE_OF_IMAGE;
}

// Note: Both size fields have a physical width of ULONG; high bits in the protocol must not be silently truncated.
static BOOLEAN
kswordArkDriverImageValuesFitFieldWidths(
    _In_ ULONG fieldMask,
    _In_ const KSWORD_ARK_DRIVER_IMAGE_VALUES* values
    )
{
    if (values == NULL) {
        return FALSE;
    }
    if ((fieldMask & KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_SIZE) != 0UL &&
        values->driverSize > MAXULONG) {
        return FALSE;
    }
    if ((fieldMask & KSWORD_ARK_DRIVER_IMAGE_FIELD_KLDR_SIZE_OF_IMAGE) != 0UL &&
        values->kldrSizeOfImage > MAXULONG) {
        return FALSE;
    }
    return TRUE;
}

// Note: Protocol values are extracted as single-bit fields; the caller passes only five valid single-bit constants.
static ULONGLONG
kswordArkDriverImageGetValue(
    _In_ const KSWORD_ARK_DRIVER_IMAGE_VALUES* values,
    _In_ ULONG field
    )
{
    switch (field) {
    case KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_START:
        return values->driverStart;
    case KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_SIZE:
        return values->driverSize;
    case KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_SECTION:
        return values->driverSection;
    case KSWORD_ARK_DRIVER_IMAGE_FIELD_KLDR_DLL_BASE:
        return values->kldrDllBase;
    case KSWORD_ARK_DRIVER_IMAGE_FIELD_KLDR_SIZE_OF_IMAGE:
        return values->kldrSizeOfImage;
    default:
        return 0ULL;
    }
}

// Note: Preserve original bit patterns when writing field write transaction snapshots; do not interpret arbitrary pointer values.
static VOID
kswordArkDriverImageSetValue(
    _Inout_ KSWORD_ARK_DRIVER_IMAGE_VALUES* values,
    _In_ ULONG field,
    _In_ ULONGLONG value
    )
{
    switch (field) {
    case KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_START:
        values->driverStart = value;
        break;
    case KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_SIZE:
        values->driverSize = value;
        break;
    case KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_SECTION:
        values->driverSection = value;
        break;
    case KSWORD_ARK_DRIVER_IMAGE_FIELD_KLDR_DLL_BASE:
        values->kldrDllBase = value;
        break;
    case KSWORD_ARK_DRIVER_IMAGE_FIELD_KLDR_SIZE_OF_IMAGE:
        values->kldrSizeOfImage = value;
        break;
    default:
        break;
    }
}

// Note: When resolving real field addresses, use only the WDK DriverObject member or KLDR offsets that have been verified in real time.
static NTSTATUS
kswordArkDriverImageResolveFieldAddress(
    _In_opt_ const KswDriverImageRuntime* runtime,
    _In_ const KswDriverImageRecord* record,
    _In_ ULONG field,
    _Outptr_ PVOID* address,
    _Out_ BOOLEAN* pointerSized
    )
{
    ULONG_PTR loaderBase = 0U;
    ULONG offset = 0UL;

    if (record == NULL || record->driverObject == NULL ||
        address == NULL || pointerSized == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *address = NULL;
    *pointerSized = FALSE;

    // Note: The DRIVER_OBJECT field is exposed directly via WDK layout and does not accept R3 offsets.
    switch (field) {
    case KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_START:
        *address = &record->driverObject->DriverStart;
        *pointerSized = TRUE;
        break;
    case KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_SIZE:
        *address = &record->driverObject->DriverSize;
        break;
    case KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_SECTION:
        *address = &record->driverObject->DriverSection;
        *pointerSized = TRUE;
        break;
    case KSWORD_ARK_DRIVER_IMAGE_FIELD_KLDR_DLL_BASE:
    case KSWORD_ARK_DRIVER_IMAGE_FIELD_KLDR_SIZE_OF_IMAGE:
        // Note: KLDR addresses are only valid during the actual resource acquisition period and while the loader identity is preserved.
        if (runtime == NULL || runtime->resourceAcquired == FALSE ||
            record->loaderEntry == NULL) {
            return STATUS_NOT_SUPPORTED;
        }
        offset = field == KSWORD_ARK_DRIVER_IMAGE_FIELD_KLDR_DLL_BASE
            ? runtime->dynState.kernel.kldrDllBase
            : runtime->dynState.kernel.kldrSizeOfImage;
        if (!kswordArkDriverIntegrityOffsetPresent(offset)) {
            return STATUS_NOT_SUPPORTED;
        }
        loaderBase = (ULONG_PTR)record->loaderEntry;
        if (loaderBase > MAXULONG_PTR - offset) {
            return STATUS_INTEGER_OVERFLOW;
        }
        *address = (PVOID)(loaderBase + offset);
        *pointerSized =
            field == KSWORD_ARK_DRIVER_IMAGE_FIELD_KLDR_DLL_BASE;
        break;
    default:
        return STATUS_INVALID_PARAMETER;
    }

    // Note: Interlocked primitives require natural alignment; reject layout anomalies to prevent unpredictable bus accesses.
    if (*address == NULL ||
        (*pointerSized != FALSE &&
         ((ULONG_PTR)*address % TYPE_ALIGNMENT(PVOID)) != 0U) ||
        (*pointerSized == FALSE &&
         ((ULONG_PTR)*address % TYPE_ALIGNMENT(ULONG)) != 0U)) {
        return STATUS_DATATYPE_MISALIGNMENT;
    }
    return STATUS_SUCCESS;
}

// Note: Atomic reads add SEH boundaries for invalid/freed addresses; failures do not proceed to adjacent writes.
static NTSTATUS
kswordArkDriverImageReadField(
    _In_opt_ const KswDriverImageRuntime* runtime,
    _In_ const KswDriverImageRecord* record,
    _In_ ULONG field,
    _Out_ ULONGLONG* value
    )
{
    PVOID address = NULL;
    BOOLEAN pointerSized = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (value == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *value = 0ULL;
    status = kswordArkDriverImageResolveFieldAddress(
        runtime,
        record,
        field,
        &address,
        &pointerSized);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    __try {
        if (pointerSized != FALSE) {
            PVOID current = InterlockedCompareExchangePointer(
                (PVOID volatile*)address,
                NULL,
                NULL);
            *value = (ULONGLONG)(ULONG_PTR)current;
        }
        else {
            LONG current = InterlockedCompareExchange(
                (volatile LONG*)address,
                0L,
                0L);
            *value = (ULONGLONG)(ULONG)current;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return (NTSTATUS)GetExceptionCode();
    }
    return STATUS_SUCCESS;
}

// Note: Single-field CAS returns the observed value; the caller uses this to distinguish success, contention, and exceptions.
static NTSTATUS
kswordArkDriverImageCompareExchangeField(
    _In_opt_ const KswDriverImageRuntime* runtime,
    _In_ const KswDriverImageRecord* record,
    _In_ ULONG field,
    _In_ ULONGLONG desired,
    _In_ ULONGLONG expected,
    _Out_ ULONGLONG* observed
    )
{
    PVOID address = NULL;
    BOOLEAN pointerSized = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (observed == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *observed = 0ULL;
    status = kswordArkDriverImageResolveFieldAddress(
        runtime,
        record,
        field,
        &address,
        &pointerSized);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (pointerSized == FALSE &&
        (desired > MAXULONG || expected > MAXULONG)) {
        return STATUS_INVALID_PARAMETER;
    }

    __try {
        if (pointerSized != FALSE) {
            PVOID previous = InterlockedCompareExchangePointer(
                (PVOID volatile*)address,
                (PVOID)(ULONG_PTR)desired,
                (PVOID)(ULONG_PTR)expected);
            *observed = (ULONGLONG)(ULONG_PTR)previous;
        }
        else {
            LONG previous = InterlockedCompareExchange(
                (volatile LONG*)address,
                (LONG)(ULONG)desired,
                (LONG)(ULONG)expected);
            *observed = (ULONGLONG)(ULONG)previous;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return (NTSTATUS)GetExceptionCode();
    }
    return STATUS_SUCCESS;
}

// Note: The sampling function always returns three DriverObject fields; KLDR availability is explicitly expressed via a bit mask.
NTSTATUS
kswordArkDriverImageReadValuesLocked(
    _In_opt_ const KswDriverImageRuntime* runtime,
    _In_ const KswDriverImageRecord* record,
    _Out_ KSWORD_ARK_DRIVER_IMAGE_VALUES* values,
    _Out_ ULONG* availableFieldMask
    )
{
    ULONG index = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (record == NULL || values == NULL || availableFieldMask == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(values, sizeof(*values));
    *availableFieldMask = 0UL;

    for (index = 0UL;
        index < RTL_NUMBER_OF(kGKswordArkDriverImageFields);
        ++index) {
        ULONG field = kGKswordArkDriverImageFields[index];
        ULONGLONG value = 0ULL;

        status = kswordArkDriverImageReadField(
            runtime,
            record,
            field,
            &value);
        if (!NT_SUCCESS(status)) {
            // Note: Failure of the DriverObject field indicates the object is no longer reliable; missing KLDR results in only a partial view.
            if (kswordArkDriverImageIsLoaderField(field) == FALSE) {
                return status;
            }
            continue;
        }
        kswordArkDriverImageSetValue(values, field, value);
        *availableFieldMask |= field;
    }
    return STATUS_SUCCESS;
}

// Note: Applies any combination of the five fields; any mid-operation race condition rolls back successfully CAS'd fields.
NTSTATUS
kswordArkDriverImageApplyFieldsLocked(
    _In_opt_ const KswDriverImageRuntime* runtime,
    _Inout_ KswDriverImageRecord* record,
    _In_ ULONG fieldMask,
    _In_ const KSWORD_ARK_DRIVER_IMAGE_VALUES* expectedValues,
    _In_ const KSWORD_ARK_DRIVER_IMAGE_VALUES* desiredValues,
    _Out_ ULONG* changedFieldMask,
    _Out_ ULONG* rollbackConflictMask
    )
{
    KSWORD_ARK_DRIVER_IMAGE_VALUES currentValues;
    ULONG availableMask = 0UL;
    ULONG appliedMask = 0UL;
    ULONG index = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (record == NULL || expectedValues == NULL || desiredValues == NULL ||
        changedFieldMask == NULL || rollbackConflictMask == NULL ||
        fieldMask == 0UL ||
        (fieldMask & ~KSWORD_ARK_DRIVER_IMAGE_FIELD_ALL) != 0UL ||
        !kswordArkDriverImageValuesFitFieldWidths(fieldMask, expectedValues) ||
        !kswordArkDriverImageValuesFitFieldWidths(fieldMask, desiredValues)) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(&currentValues, sizeof(currentValues));
    *changedFieldMask = 0UL;
    *rollbackConflictMask = 0UL;

    status = kswordArkDriverImageReadValuesLocked(
        runtime,
        record,
        &currentValues,
        &availableMask);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if ((availableMask & fieldMask) != fieldMask) {
        return STATUS_NOT_SUPPORTED;
    }

    // Note: Validate the complete expected snapshot first, then perform the first write to avoid partial modifications from known stale requests.
    for (index = 0UL;
        index < RTL_NUMBER_OF(kGKswordArkDriverImageFields);
        ++index) {
        ULONG field = kGKswordArkDriverImageFields[index];

        if ((fieldMask & field) != 0UL &&
            kswordArkDriverImageGetValue(&currentValues, field) !=
                kswordArkDriverImageGetValue(expectedValues, field)) {
            return STATUS_RETRY;
        }
    }

    // Note: Each field independently freezes its original value upon first entering the transaction; subsequent edits do not alter the restoration baseline.
    for (index = 0UL;
        index < RTL_NUMBER_OF(kGKswordArkDriverImageFields);
        ++index) {
        ULONG field = kGKswordArkDriverImageFields[index];

        if ((fieldMask & field) != 0UL &&
            (record->originalFieldMask & field) == 0UL) {
            kswordArkDriverImageSetValue(
                &record->originalValues,
                field,
                kswordArkDriverImageGetValue(expectedValues, field));
            record->originalFieldMask |= field;
        }
    }

    // Note: Perform a same-value CAS even if desired equals expected to establish ownership evidence at the same moment.
    for (index = 0UL;
        index < RTL_NUMBER_OF(kGKswordArkDriverImageFields);
        ++index) {
        ULONG field = kGKswordArkDriverImageFields[index];
        ULONGLONG expected = 0ULL;
        ULONGLONG desired = 0ULL;
        ULONGLONG observed = 0ULL;

        if ((fieldMask & field) == 0UL) {
            continue;
        }
        expected = kswordArkDriverImageGetValue(expectedValues, field);
        desired = kswordArkDriverImageGetValue(desiredValues, field);
        status = kswordArkDriverImageCompareExchangeField(
            runtime,
            record,
            field,
            desired,
            expected,
            &observed);
        if (!NT_SUCCESS(status) || observed != expected) {
            if (NT_SUCCESS(status)) {
                status = STATUS_RETRY;
            }
            break;
        }
        appliedMask |= field;
        if (desired != expected) {
            *changedFieldMask |= field;
        }
    }

    if (!NT_SUCCESS(status)) {
        // Note: Reverse rollback writes back expected only if the current value still equals the current round's desired, never overwriting competitors.
        while (index > 0UL) {
            ULONG rollbackField = 0UL;
            ULONGLONG expected = 0ULL;
            ULONGLONG desired = 0ULL;
            ULONGLONG observed = 0ULL;
            NTSTATUS rollbackStatus = STATUS_SUCCESS;

            --index;
            rollbackField = kGKswordArkDriverImageFields[index];
            if ((appliedMask & rollbackField) == 0UL) {
                continue;
            }
            expected = kswordArkDriverImageGetValue(
                expectedValues,
                rollbackField);
            desired = kswordArkDriverImageGetValue(
                desiredValues,
                rollbackField);
            rollbackStatus = kswordArkDriverImageCompareExchangeField(
                runtime,
                record,
                rollbackField,
                expected,
                desired,
                &observed);
            if (!NT_SUCCESS(rollbackStatus) || observed != desired) {
                *rollbackConflictMask |= rollbackField;
                record->managedFieldMask |= rollbackField;
                record->ownedFieldMask &= ~rollbackField;
                record->conflictFieldMask |= rollbackField;
                kswordArkDriverImageSetValue(
                    &record->appliedValues,
                    rollbackField,
                    desired);
            }
        }
        // Note: Fields successfully rolled back have no net change; conflict bits separately report potential leftover writes from this round.
        *changedFieldMask &= *rollbackConflictMask;
        return status;
    }

    // Note: Publish transaction metadata only after all CAS operations succeed; fields restored to original are then removed from management.
    for (index = 0UL;
        index < RTL_NUMBER_OF(kGKswordArkDriverImageFields);
        ++index) {
        ULONG field = kGKswordArkDriverImageFields[index];
        ULONGLONG desired = 0ULL;
        ULONGLONG original = 0ULL;

        if ((fieldMask & field) == 0UL) {
            continue;
        }
        desired = kswordArkDriverImageGetValue(desiredValues, field);
        original = kswordArkDriverImageGetValue(
            &record->originalValues,
            field);
        kswordArkDriverImageSetValue(
            &record->appliedValues,
            field,
            desired);
        if (desired == original) {
            record->managedFieldMask &= ~field;
            record->ownedFieldMask &= ~field;
            record->conflictFieldMask &= ~field;
        }
        else {
            record->managedFieldMask |= field;
            record->ownedFieldMask |= field;
            record->conflictFieldMask &= ~field;
        }
    }
    return STATUS_SUCCESS;
}

// Note: Restoration can be partially successful; a zero mask indicates restoring only the chain, without implicitly expanding to all fields.
// Retain records and conflict information for each failed field to facilitate subsequent queries or abandonment.
NTSTATUS
kswordArkDriverImageRestoreFieldsLocked(
    _In_opt_ const KswDriverImageRuntime* runtime,
    _Inout_ KswDriverImageRecord* record,
    _In_ ULONG fieldMask,
    _Out_ ULONG* changedFieldMask,
    _Out_ ULONG* failedFieldMask
    )
{
    KSWORD_ARK_DRIVER_IMAGE_VALUES currentValues;
    ULONG availableMask = 0UL;
    ULONG selectedMask = 0UL;
    ULONG index = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (record == NULL || changedFieldMask == NULL ||
        failedFieldMask == NULL ||
        (fieldMask & ~KSWORD_ARK_DRIVER_IMAGE_FIELD_ALL) != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(&currentValues, sizeof(currentValues));
    *changedFieldMask = 0UL;
    *failedFieldMask = 0UL;
    selectedMask = fieldMask & record->managedFieldMask;
    if (selectedMask == 0UL) {
        return STATUS_SUCCESS;
    }

    status = kswordArkDriverImageReadValuesLocked(
        runtime,
        record,
        &currentValues,
        &availableMask);
    if (!NT_SUCCESS(status)) {
        *failedFieldMask = selectedMask;
        return status;
    }

    for (index = 0UL;
        index < RTL_NUMBER_OF(kGKswordArkDriverImageFields);
        ++index) {
        ULONG field = kGKswordArkDriverImageFields[index];
        ULONGLONG current = 0ULL;
        ULONGLONG original = 0ULL;
        ULONGLONG applied = 0ULL;

        if ((selectedMask & field) == 0UL) {
            continue;
        }
        if ((availableMask & field) == 0UL) {
            // Note: Retain 'owned' when layout is temporarily unavailable to avoid misjudging 'unknown' as a third-party race.
            *failedFieldMask |= field;
            continue;
        }
        if ((record->originalFieldMask & field) == 0UL) {
            record->ownedFieldMask &= ~field;
            record->conflictFieldMask |= field;
            *failedFieldMask |= field;
            continue;
        }

        current = kswordArkDriverImageGetValue(&currentValues, field);
        original = kswordArkDriverImageGetValue(
            &record->originalValues,
            field);
        applied = kswordArkDriverImageGetValue(
            &record->appliedValues,
            field);
        if (current == original) {
            // Note: If the external state has already reverted to the original value, retire the field directly to avoid redundant writes.
            record->managedFieldMask &= ~field;
            record->ownedFieldMask &= ~field;
            record->conflictFieldMask &= ~field;
            continue;
        }
        if ((record->ownedFieldMask & field) != 0UL &&
            current == applied) {
            ULONGLONG observed = 0ULL;
            NTSTATUS restoreStatus =
                kswordArkDriverImageCompareExchangeField(
                    runtime,
                    record,
                    field,
                    original,
                    applied,
                    &observed);

            if (NT_SUCCESS(restoreStatus) && observed == applied) {
                record->managedFieldMask &= ~field;
                record->ownedFieldMask &= ~field;
                record->conflictFieldMask &= ~field;
                if (original != applied) {
                    *changedFieldMask |= field;
                }
                continue;
            }
        }

        // Note: Any current third-party values are preserved as-is; only the field is marked as conflicted for the user to decide whether to abandon.
        record->ownedFieldMask &= ~field;
        record->conflictFieldMask |= field;
        *failedFieldMask |= field;
    }

    if (*failedFieldMask != 0UL) {
        return (availableMask & *failedFieldMask) == *failedFieldMask
            ? STATUS_OBJECT_TYPE_MISMATCH
            : STATUS_NOT_SUPPORTED;
    }
    return STATUS_SUCCESS;
}

// Note: Refresh all managed fields to generate a conservative owned/conflict view without performing any writes.
NTSTATUS
kswordArkDriverImageRefreshFieldsLocked(
    _In_opt_ const KswDriverImageRuntime* runtime,
    _Inout_ KswDriverImageRecord* record,
    _Out_ BOOLEAN* stateChanged
    )
{
    KSWORD_ARK_DRIVER_IMAGE_VALUES currentValues;
    ULONG oldManagedMask = 0UL;
    ULONG oldOwnedMask = 0UL;
    ULONG oldConflictMask = 0UL;
    ULONG availableMask = 0UL;
    ULONG unavailableMask = 0UL;
    ULONG index = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (record == NULL || stateChanged == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *stateChanged = FALSE;
    oldManagedMask = record->managedFieldMask;
    oldOwnedMask = record->ownedFieldMask;
    oldConflictMask = record->conflictFieldMask;
    if (record->managedFieldMask == 0UL) {
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&currentValues, sizeof(currentValues));
    status = kswordArkDriverImageReadValuesLocked(
        runtime,
        record,
        &currentValues,
        &availableMask);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    for (index = 0UL;
        index < RTL_NUMBER_OF(kGKswordArkDriverImageFields);
        ++index) {
        ULONG field = kGKswordArkDriverImageFields[index];
        ULONGLONG current = 0ULL;
        ULONGLONG original = 0ULL;
        ULONGLONG applied = 0ULL;

        if ((record->managedFieldMask & field) == 0UL) {
            continue;
        }
        if ((availableMask & field) == 0UL) {
            unavailableMask |= field;
            continue;
        }
        if ((record->originalFieldMask & field) == 0UL) {
            record->ownedFieldMask &= ~field;
            record->conflictFieldMask |= field;
            continue;
        }
        current = kswordArkDriverImageGetValue(&currentValues, field);
        original = kswordArkDriverImageGetValue(
            &record->originalValues,
            field);
        applied = kswordArkDriverImageGetValue(
            &record->appliedValues,
            field);

        if (current == original) {
            record->managedFieldMask &= ~field;
            record->ownedFieldMask &= ~field;
            record->conflictFieldMask &= ~field;
        }
        else if ((record->ownedFieldMask & field) != 0UL &&
            current == applied) {
            record->conflictFieldMask &= ~field;
        }
        else {
            record->ownedFieldMask &= ~field;
            record->conflictFieldMask |= field;
        }
    }

    *stateChanged =
        oldManagedMask != record->managedFieldMask ||
        oldOwnedMask != record->ownedFieldMask ||
        oldConflictMask != record->conflictFieldMask;
    return unavailableMask != 0UL
        ? STATUS_NOT_SUPPORTED
        : STATUS_SUCCESS;
}
