/*++

Module Name:

    driver_blind_actions.c

Abstract:

    QUERY, BLIND, and RESTORE actions for DriverObject communication control.

Environment:

    Kernel-mode Driver Framework

--*/

#include "driver_blind_internal.h"

#include <ntstrsafe.h>

/* Note: BLIND binds the canonical object name confirmed during UI pre-check to the base address resolution of this module. */
static BOOLEAN
kswordArkDriverCommunicationMatchesCanonicalName(
    _In_reads_(KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) const WCHAR* requestName,
    _In_z_ const WCHAR* canonicalName
    )
{
    SIZE_T requestLength = 0U;
    UNICODE_STRING requestString;
    UNICODE_STRING canonicalString;
    NTSTATUS status = STATUS_SUCCESS;

    /* Note: An empty display name cannot prove that UI evidence still corresponds to the current DriverObject. */
    if (requestName == NULL || canonicalName == NULL || requestName[0] == L'\0') {
        /* Note: BLIND fails to close on missing evidence identity. */
        return FALSE;
    }
    /* Note: Fixed arrays must be terminated within the ABI boundary to prohibit out-of-bounds string scanning. */
    status = RtlStringCchLengthW(
        requestName,
        KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS,
        &requestLength);
    /* Note: Reject un-terminated or empty specification names. */
    if (!NT_SUCCESS(status) || requestLength == 0U) {
        /* Note: Invalid names do not enter unsafe wide-string APIs. */
        return FALSE;
    }

    /* Note: Two terminated short strings can be safely constructed into a UNICODE_STRING. */
    RtlInitUnicodeString(&requestString, requestName);
    /* Note: The canonical \Driver\ name returned by the resolver is the current kernel identity. */
    RtlInitUnicodeString(&canonicalString, canonicalName);
    /* Note: Object directory matching is case-insensitive, but length and all characters must match exactly. */
    return RtlEqualUnicodeString(&requestString, &canonicalString, TRUE);
}

/* Note: Explicit RESTORE is only performed when retiring the record after all taint slots have been restored to the captured original entry by external means. */
static BOOLEAN
kswordArkDriverCommunicationTaintedSlotsMatchOriginalLocked(
    _In_ const KswDriverCommunicationRecord* record
    )
{
    ULONG slotIndex = 0UL;

    /* Note: Without a record, it cannot be proven that taint has been resolved externally. */
    if (record == NULL || record->inUse == FALSE || record->driverObject == NULL) {
        /* Note: On failure, close and retain any existing diagnostic records. */
        return FALSE;
    }

    /* Note: Read-only validation of permanently tainted slots; never attempt to write back old entries. */
    for (slotIndex = 0UL;
        slotIndex < KSW_DRIVER_COMMUNICATION_SLOT_COUNT;
        ++slotIndex) {
        const KswDriverCommunicationSlot* slot =
            &kGKswordArkDriverCommunicationSlots[slotIndex];
        PDRIVER_DISPATCH currentDispatch = NULL;

        /* Note: Untainted slots do not participate in explicit conflict confirmation. */
        if ((record->conflictMask & slot->mask) == 0UL) {
            /* Note: Continue checking the next permanent taint bit. */
            continue;
        }
        /* Note: Atomic read avoids semantic inconsistency between normal loads and CAS control paths. */
        currentDispatch = kswordArkDriverCommunicationReadDispatch(
            record->driverObject,
            slot->majorFunction);
        /* Note: Only allow retiring the record if the third-party dispatch has been restored to its pre-transaction original entry. */
        if (currentDispatch != record->originalDispatch[slotIndex]) {
            /* Note: Foreign or returning to reject must maintain the conflict state. */
            return FALSE;
        }
    }

    /* Note: All permanent taint slots have been restored externally; RESTORE only clears records without writing to slots. */
    return TRUE;
}

/* Note: The query only reads persistent records; if no record exists, return inactive directly. */
NTSTATUS
kswordArkDriverCommunicationQuery(
    _In_ const KSWORD_ARK_DRIVER_COMMUNICATION_REQUEST* request,
    _Out_ KSWORD_ARK_DRIVER_COMMUNICATION_RESPONSE* response
    )
{
    KswDriverCommunicationRecord* record = NULL;
    PDRIVER_OBJECT driverObject = NULL;
    PDRIVER_OBJECT releasedObject = NULL;
    WCHAR canonicalName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
    ULONGLONG targetModuleBase = 0ULL;

    /* Note: First search the persistent table by module base address to support states where the object name has already disappeared from the directory. */
    ExAcquireFastMutex(&gKswordArkDriverCommunicationState.lock);
    /* Note: The module base address is the unique identity of the record. */
    record = kswordArkDriverCommunicationFindRecordLocked(request->targetModuleBase);
    /* Note: Refresh foreign changes upon hitting a record, then return immediately. */
    if (record != NULL) {
        /* Note: Querying five real-time slots without modifying the target entry. */
        kswordArkDriverCommunicationRefreshRecordLocked(record);
        /* Note: Release the record if external restoration is complete and it is no longer needed. */
        if (record->ownedMask == 0UL && record->conflictMask == 0UL) {
            /* Note: Temporarily store object references; perform dereference only after unlocking. */
            releasedObject = record->driverObject;
            /* Note: The response still uses the target address and name from the record. */
            driverObject = record->driverObject;
            /* Note: Save immutable record key; prohibit responding to re-derivations from the current DriverStart. */
            targetModuleBase = record->targetModuleBase;
            /* Note: Save the canonical name for later restoration after zeroing the record. */
            (VOID)RtlStringCchCopyW(
                canonicalName,
                RTL_NUMBER_OF(canonicalName),
                record->canonicalName);
            /* Note: Clearing the record indicates that blind ownership has ended. */
            RtlZeroMemory(record, sizeof(*record));
            /* Note: Recording removal is also an observable state change. */
            kswordArkDriverCommunicationAdvanceGenerationLocked(NULL);
            /* Note: Report external recovery with an inactive result. */
            kswordArkDriverCommunicationFillResponse(
                response,
                request->action,
                STATUS_SUCCESS,
                0UL,
                NULL,
                driverObject,
                canonicalName);
            /* Note: inactive responses still return the original module base address locked by the record. */
            response->driverStart = targetModuleBase;
        }
        else {
            /* Note: Return active or conflicting records according to the real-time mask. */
            kswordArkDriverCommunicationFillResponse(
                response,
                request->action,
                STATUS_SUCCESS,
                0UL,
                record,
                NULL,
                NULL);
        }
        /* Note: Release the global serial lock after completing the record read. */
        ExReleaseFastMutex(&gKswordArkDriverCommunicationState.lock);
        /* Note: Release the original reference only when the record is cleared. */
        if (releasedObject != NULL) {
            /* Note: Address and name have been copied; object fields are no longer accessed. */
            ObDereferenceObject(releasedObject);
        }
        /* Note: The query protocol succeeded; the operation status is in the response. */
        return STATUS_SUCCESS;
    }
    /* Note: Immediately release the lock when no record is found, without scanning the object directory or re-validating the target. */
    ExReleaseFastMutex(&gKswordArkDriverCommunicationState.lock);
    /* Note: inactive QUERY does not touch targets, enabling safe polling for per-module evidence scanning. */
    kswordArkDriverCommunicationFillResponse(
        response,
        request->action,
        STATUS_SUCCESS,
        0UL,
        NULL,
        NULL,
        NULL);
    /* Note: No-record queries are protocol-successful, with status explicitly set to inactive. */
    return STATUS_SUCCESS;
}

/* Note: Execute an all-or-nothing blind CAS transaction across all five slots. */
NTSTATUS
kswordArkDriverCommunicationBlind(
    _In_ const KSWORD_ARK_DRIVER_COMMUNICATION_REQUEST* request,
    _Out_ KSWORD_ARK_DRIVER_COMMUNICATION_RESPONSE* response
    )
{
    KswDriverCommunicationRecord* record = NULL;
    PDRIVER_OBJECT driverObject = NULL;
    PDRIVER_DISPATCH originalDispatch[KSW_DRIVER_COMMUNICATION_SLOT_COUNT] = { 0 };
    WCHAR canonicalName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
    ULONG slotIndex = 0UL;
    ULONG changedMask = 0UL;
    ULONG captureInvalidMask = 0UL;
    ULONG externalDispatchMask = 0UL;
    ULONG forwardConflictMask = 0UL;
    ULONG rollbackTaintMask = 0UL;
    ULONG targetImageSize = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    /* Note: Object directory resolution is completed before acquiring the FAST_MUTEX to preserve the PASSIVE_LEVEL contract. */
    status = kswordArkDriverReferenceObjectByModuleBase(
        request->targetModuleBase,
        &driverObject,
        canonicalName,
        RTL_NUMBER_OF(canonicalName));
    /* Note: Returns a deterministic inactive response upon parsing failure. */
    if (!NT_SUCCESS(status)) {
        /* Note: Do not treat unverified display names as canonical object names. */
        kswordArkDriverCommunicationFillResponse(
            response,
            request->action,
            status,
            0UL,
            NULL,
            NULL,
            canonicalName);
        /* Note: Propagate object directory failure to IOCTL handler. */
        return status;
    }

    /* Note: BLIND must carry the DriverObject address observed by the UI evidence scan. */
    if ((request->flags &
        KSWORD_ARK_DRIVER_COMMUNICATION_FLAG_EXPECTED_DRIVER_OBJECT_PRESENT) == 0UL ||
        request->expectedDriverObjectAddress == 0ULL) {
        /* Note: Returns a structurally complete business failure response when object address evidence is missing. */
        kswordArkDriverCommunicationFillResponse(
            response,
            request->action,
            STATUS_INVALID_PARAMETER,
            0UL,
            NULL,
            driverObject,
            canonicalName);
        /* Note: The temporary resolver reference is not recorded in the persistent log. */
        ObDereferenceObject(driverObject);
        /* Note: BLIND is not allowed using only potentially reusable module base addresses. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Note: The resolver's current object address must be bitwise identical to the UI evidence. */
    if (request->expectedDriverObjectAddress !=
        (ULONGLONG)(ULONG_PTR)driverObject) {
        /* Note: Return current resolver result for re-validation when address identity drifts. */
        kswordArkDriverCommunicationFillResponse(
            response,
            request->action,
            STATUS_OBJECT_TYPE_MISMATCH,
            0UL,
            NULL,
            driverObject,
            canonicalName);
        /* Note: Prevent blind Y after X unloads and Y reuses the base address. */
        ObDereferenceObject(driverObject);
        /* Note: Object address mismatch indicates a stable identity conflict. */
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    /* Note: Bind UI pre-check canonical name to prevent old evidence from reusing the same module base address for a new driver. */
    if (!kswordArkDriverCommunicationMatchesCanonicalName(
        request->driverName,
        canonicalName)) {
        /* Note: Return the current resolver identity to R3 for re-executing evidence pre-check. */
        kswordArkDriverCommunicationFillResponse(
            response,
            request->action,
            STATUS_OBJECT_TYPE_MISMATCH,
            0UL,
            NULL,
            driverObject,
            canonicalName);
        /* Note: Never enter target preflight or dispatch write when the canonical name does not match. */
        ObDereferenceObject(driverObject);
        /* Note: Reject stale BLIND requests with a stable identity error. */
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    /* Note: Reject \FileSystem, empty DriverStart, and KSword itself. */
    status = kswordArkDriverCommunicationValidateTarget(driverObject, canonicalName);
    /* Note: On validation failure, do not retain the just-acquired target reference. */
    if (!NT_SUCCESS(status)) {
        /* Note: Failure responses include the validated target diagnostic field for reads. */
        kswordArkDriverCommunicationFillResponse(
            response,
            request->action,
            status,
            0UL,
            NULL,
            driverObject,
            canonicalName);
        /* Note: Since the transaction has not started, the target reference can be released directly. */
        ObDereferenceObject(driverObject);
        /* Note: Return self-protection or directory denial status to the upper layer. */
        return status;
    }

    /* Note: Before acquiring the lock, recheck that the resolver object's current DriverStart still equals the immutable request base address. */
    if ((ULONGLONG)(ULONG_PTR)driverObject->DriverStart !=
        request->targetModuleBase) {
        /* Note: Form a no-write failure response when the target identity drifts during pre-check. */
        kswordArkDriverCommunicationFillResponse(
            response,
            request->action,
            STATUS_OBJECT_TYPE_MISMATCH,
            0UL,
            NULL,
            driverObject,
            canonicalName);
        /* Note: Drifted object references have not entered the state table. */
        ObDereferenceObject(driverObject);
        /* Note: Deriving or updating the record key from the target's currently writable field is not allowed. */
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    /* Note: All blind/restore state transitions are serialized by a FAST_MUTEX. */
    ExAcquireFastMutex(&gKswordArkDriverCommunicationState.lock);
    /* Note: Prohibit creating any new records after unloading begins. */
    if (gKswordArkDriverCommunicationState.shuttingDown != FALSE) {
        /* Note: Release the temporary target reference after unlocking. */
        ExReleaseFastMutex(&gKswordArkDriverCommunicationState.lock);
        /* Note: The target state is no longer mutable during driver unloading. */
        kswordArkDriverCommunicationFillResponse(
            response,
            request->action,
            STATUS_DELETE_PENDING,
            0UL,
            NULL,
            driverObject,
            canonicalName);
        /* Note: temporary reference not yet in the state table. */
        ObDereferenceObject(driverObject);
        /* Note: Return stable unloading status. */
        return STATUS_DELETE_PENDING;
    }

    /* Note: Re-reads DriverStart before starting the transaction with the lock to narrow the identity drift race window. */
    if ((ULONGLONG)(ULONG_PTR)driverObject->DriverStart !=
        request->targetModuleBase) {
        /* Note: Keep all dispatch slots unchanged if identity verification fails within the lock. */
        kswordArkDriverCommunicationFillResponse(
            response,
            request->action,
            STATUS_OBJECT_TYPE_MISMATCH,
            0UL,
            NULL,
            driverObject,
            canonicalName);
        /* Note: Release the state lock before releasing the temporary object reference. */
        ExReleaseFastMutex(&gKswordArkDriverCommunicationState.lock);
        /* Note: Request has not been created or matched any record. */
        ObDereferenceObject(driverObject);
        /* Note: Return stable identity drift error. */
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    /* Note: For repeated blind operations, first check the existing module base address record. */
    record = kswordArkDriverCommunicationFindRecordLocked(request->targetModuleBase);
    /* Note: Verify object identity and refresh the real-time mask upon record hit. */
    if (record != NULL) {
        /* Note: Close on identity conflict when the same module base address resolves to different objects. */
        if (record->driverObject != driverObject ||
            record->targetModuleBase != request->targetModuleBase) {
            /* Note: Retain old records to avoid erroneously overwriting newly loaded objects. */
            kswordArkDriverCommunicationFillResponse(
                response,
                request->action,
                STATUS_OBJECT_TYPE_MISMATCH,
                0UL,
                record,
                NULL,
                NULL);
            /* Note: Release the serial lock after completing the response. */
            ExReleaseFastMutex(&gKswordArkDriverCommunicationState.lock);
            /* Note: Release the extra parse reference for this instance; the old record reference remains. */
            ObDereferenceObject(driverObject);
            /* Note: Module identity conflict requires resolving the old record first. */
            return STATUS_OBJECT_TYPE_MISMATCH;
        }

        /* Note: Account for real-time changes caused by third parties during read. */
        kswordArkDriverCommunicationRefreshRecordLocked(record);
        /* Note: Idempotent success occurs only when all five slots are actually held by this feature, active, and untainted. */
        if (record->ownedMask == KSWORD_ARK_DRIVER_COMMUNICATION_MAJOR_MASK_ALL &&
            record->activeMask == KSWORD_ARK_DRIVER_COMMUNICATION_MAJOR_MASK_ALL &&
            record->conflictMask == 0UL) {
            /* Note: A changedMask of zero explicitly indicates no secondary rewrite. */
            kswordArkDriverCommunicationFillResponse(
                response,
                request->action,
                STATUS_SUCCESS,
                0UL,
                record,
                NULL,
                NULL);
            /* Note: Release the serial lock after completing the idempotent query. */
            ExReleaseFastMutex(&gKswordArkDriverCommunicationState.lock);
            /* Note: The newly acquired extra reference does not replace the record's held reference. */
            ObDereferenceObject(driverObject);
            /* Note: Repeatedly return success for blind actions. */
            return STATUS_SUCCESS;
        }

        /* Note: Prohibit overwriting and require restoration first when in partial/foreign state. */
        kswordArkDriverCommunicationFillResponse(
            response,
            request->action,
            STATUS_DEVICE_BUSY,
            0UL,
            record,
            NULL,
            NULL);
        /* Note: Retain the conflict record and release the serial lock. */
        ExReleaseFastMutex(&gKswordArkDriverCommunicationState.lock);
        /* Note: Release this additional parse reference. */
        ObDereferenceObject(driverObject);
        /* Note: Explicitly return busy status to prevent blind stacking. */
        return STATUS_DEVICE_BUSY;
    }

    /* Note: Reserve an empty record but keep InUse=FALSE before submission. */
    record = kswordArkDriverCommunicationAllocateRecordLocked();
    /* Note: Do not initiate any target writes when capacity is exhausted. */
    if (record == NULL) {
        /* Note: Release the temporary object reference after releasing the serial lock. */
        ExReleaseFastMutex(&gKswordArkDriverCommunicationState.lock);
        /* Note: Form a capacity failure response without records. */
        kswordArkDriverCommunicationFillResponse(
            response,
            request->action,
            STATUS_INSUFFICIENT_RESOURCES,
            0UL,
            NULL,
            driverObject,
            canonicalName);
        /* Note: The temporary reference was not transferred to the state table. */
        ObDereferenceObject(driverObject);
        /* Note: Return status for fixed capacity exhaustion. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Note: Snapshot the target image size within the lock; subsequent original entries can only fall within this immutable range. */
    targetImageSize = driverObject->DriverSize;
    /* Note: A zero image size cannot prove the owner lifecycle of any recoverable entry. */
    if (targetImageSize == 0UL) {
        /* Note: Clear uncommitted reserved records. */
        RtlZeroMemory(record, sizeof(*record));
        /* Note: Form a failure response for the target state with no writes. */
        kswordArkDriverCommunicationFillResponse(
            response,
            request->action,
            STATUS_INVALID_DEVICE_STATE,
            0UL,
            NULL,
            driverObject,
            canonicalName);
        /* Note: Release the control lock before releasing the temporary resolver reference. */
        ExReleaseFastMutex(&gKswordArkDriverCommunicationState.lock);
        /* Note: The failure path does not persistently record the takeover reference. */
        ObDereferenceObject(driverObject);
        /* Reject targets lacking a stable image range. */
        return STATUS_INVALID_DEVICE_STATE;
    }

    /* Note: Capture all five expected original entry points once before the transaction. */
    for (slotIndex = 0UL;
        slotIndex < KSW_DRIVER_COMMUNICATION_SLOT_COUNT;
        ++slotIndex) {
        const KswDriverCommunicationSlot* slot =
            &kGKswordArkDriverCommunicationSlots[slotIndex];
        ULONGLONG originalAddress = 0ULL;

        /* Note: Atomic read ensures subsequent CAS can detect third-party changes after capture. */
        originalDispatch[slotIndex] =
            kswordArkDriverCommunicationReadDispatch(
                driverObject,
                slot->majorFunction);
        /* Note: Public MajorFunction slots must not be null; invalid objects are closed upon failure. */
        if (originalDispatch[slotIndex] == NULL) {
            /* Note: Mark the corresponding slot as failed and skip all write transactions. */
            captureInvalidMask |= slot->mask;
            /* Note: An empty entry has no executable owner address to verify. */
            continue;
        }
        /* Note: The kernel reject is the only allowed original entry point located outside the target image. */
        if (originalDispatch[slotIndex] ==
            gKswordArkDriverCommunicationState.rejectDispatch) {
            /* Note: This precise entry point is proven during initialization to belong to ntos/HAL. */
            continue;
        }
        /* Note: Cast function pointer to integer for validated image range comparison only. */
        originalAddress = (ULONGLONG)(ULONG_PTR)originalDispatch[slotIndex];
        /* Note: Subtraction range check prevents base+size overflow. */
        if (originalAddress < request->targetModuleBase ||
            (originalAddress - request->targetModuleBase) >=
                (ULONGLONG)targetImageSize) {
            /* Note: External hook owner not pinned by target reference; disallow saving as recovery entry. */
            externalDispatchMask |= slot->mask;
        }
    }

    /* Note: Do not perform any CAS or persistent record writes when an entry outside the target image is detected. */
    if (externalDispatchMask != 0UL) {
        /* Note: Clear reserved record contents before submission. */
        RtlZeroMemory(record, sizeof(*record));
        /* Note: After releasing the control lock, construct the rejection response for an external owner. */
        ExReleaseFastMutex(&gKswordArkDriverCommunicationState.lock);
        /* Note: External hooks cannot serve as a stable entry point for future RESTORE operations. */
        kswordArkDriverCommunicationFillResponse(
            response,
            request->action,
            STATUS_OBJECT_TYPE_MISMATCH,
            0UL,
            NULL,
            driverObject,
            canonicalName);
        /* Note: The failure path does not record the takeover of the target reference. */
        ObDereferenceObject(driverObject);
        /* Note: Return a stable owner mismatch status. */
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    /* Note: Do not perform any CAS when an empty entry is detected during the capture phase. */
    if (captureInvalidMask != 0UL) {
        /* Note: Clear temporary record contents before submission. */
        RtlZeroMemory(record, sizeof(*record));
        /* Note: Form a failure response after releasing the serial lock. */
        ExReleaseFastMutex(&gKswordArkDriverCommunicationState.lock);
        /* Note: An empty entry indicates the target object state is invalid. */
        kswordArkDriverCommunicationFillResponse(
            response,
            request->action,
            STATUS_INVALID_DEVICE_STATE,
            0UL,
            NULL,
            driverObject,
            canonicalName);
        /* Note: Release untransferred object reference. */
        ObDereferenceObject(driverObject);
        /* Note: Return an exception for the target dispatch table. */
        return STATUS_INVALID_DEVICE_STATE;
    }

    /* Note: CAS pre-check of target image identity and size did not drift during capture. */
    if ((ULONGLONG)(ULONG_PTR)driverObject->DriverStart !=
        request->targetModuleBase ||
        driverObject->DriverSize != targetImageSize) {
        /* Note: Clear the reserved record during identity drift while keeping all slots unchanged. */
        RtlZeroMemory(record, sizeof(*record));
        /* Note: Form the final no-write identity failure response. */
        kswordArkDriverCommunicationFillResponse(
            response,
            request->action,
            STATUS_OBJECT_TYPE_MISMATCH,
            0UL,
            NULL,
            driverObject,
            canonicalName);
        /* Note: Release the control lock first. */
        ExReleaseFastMutex(&gKswordArkDriverCommunicationState.lock);
        /* Note: No record takes over the resolver reference. */
        ObDereferenceObject(driverObject);
        /* Note: Caller must re-collect target evidence. */
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    /* Note: Per-slot CAS; enter reverse rollback upon any failure. */
    for (slotIndex = 0UL;
        slotIndex < KSW_DRIVER_COMMUNICATION_SLOT_COUNT;
        ++slotIndex) {
        const KswDriverCommunicationSlot* slot =
            &kGKswordArkDriverCommunicationSlots[slotIndex];
        PDRIVER_DISPATCH previousDispatch = NULL;

        /* Note: No need to write or retrieve ownership recovery when the original entry is already rejected by the kernel. */
        if (originalDispatch[slotIndex] ==
            gKswordArkDriverCommunicationState.rejectDispatch) {
            /* Note: This slot preserves the existing external state and continues processing other slots. */
            continue;
        }

        /* Note: Only publish kernel reject if the captured value has not changed. */
        previousDispatch = kswordArkDriverCommunicationCompareExchangeDispatch(
            driverObject,
            slot->majorFunction,
            gKswordArkDriverCommunicationState.rejectDispatch,
            originalDispatch[slotIndex]);
        /* Note: CAS mismatch indicates a third-party modification within the transaction window. */
        if (previousDispatch != originalDispatch[slotIndex]) {
            /* Note: Record only one-time forward conflicts; do not persistently taint unwritten slots. */
            forwardConflictMask |= slot->mask;
            /* Note: Later, uniformly reverse-restore the replaced slots. */
            break;
        }

        /* Record the slots successfully written in this operation. */
        changedMask |= slot->mask;
    }

    /* Note: On transaction conflict, restore only the modified slots that still equal reject. */
    if (forwardConflictMask != 0UL) {
        ULONG rollbackIndex = 0UL;

        /* Note: Reverse order reduces the observed time window for partial commits. */
        for (rollbackIndex = slotIndex;
            rollbackIndex > 0UL;
            --rollbackIndex) {
            const ULONG kCompletedIndex = rollbackIndex - 1UL;
            const KswDriverCommunicationSlot* completedSlot =
                &kGKswordArkDriverCommunicationSlots[kCompletedIndex];
            PDRIVER_DISPATCH rollbackPrevious = NULL;

            /* Note: Roll back only the slots actually written by this transaction. */
            if ((changedMask & completedSlot->mask) == 0UL) {
                /* Note: No rollback needed for natively rejected or unhandled slots. */
                continue;
            }

            /* Note: foreign changes take precedence; rollbacks never overwrite them. */
            rollbackPrevious = kswordArkDriverCommunicationCompareExchangeDispatch(
                driverObject,
                completedSlot->majorFunction,
                originalDispatch[kCompletedIndex],
                gKswordArkDriverCommunicationState.rejectDispatch);
            /* Note: No longer owned by this transaction upon successful rollback or if a third party has restored the original entry. */
            if (rollbackPrevious ==
                gKswordArkDriverCommunicationState.rejectDispatch) {
                /* Note: CAS has restored the reject for this feature to the original entry point. */
            }
            else if (rollbackPrevious == originalDispatch[kCompletedIndex]) {
                /* Note: The third party has already been safely restored; no further write is needed. */
            }
            /* Note: Permanently latch taint if other entry points appear during rollback. */
            else if (rollbackPrevious != originalDispatch[kCompletedIndex]) {
                /* Note: Foreign changes are not overwritten and never acquire recovery ownership. */
                rollbackTaintMask |= completedSlot->mask;
            }
            /* Note: After rollback, the slot no longer belongs to net changed regardless of its current value. */
            changedMask &= ~completedSlot->mask;
        }

        /* Note: Only create sticky records if foreign observation occurs during rollback for slots that have been written. */
        if (rollbackTaintMask != 0UL) {
            /* Note: Record long-term ownership of the resolver DriverObject reference obtained in this session. */
            record->driverObject = driverObject;
            /* Note: Latch the validated, immutable module base address from the request. */
            record->targetModuleBase = request->targetModuleBase;
            /* Note: After rollback, no slot retains automatic recovery ownership. */
            record->ownedMask = 0UL;
            /* Note: Zero-initialize the active reject visibility before refresh. */
            record->activeMask = 0UL;
            /* Note: persistent conflict only includes foreign entries observed in rolled-back write slots. */
            record->conflictMask = rollbackTaintMask;
            /* Note: Only track slots where rollback taint occurs after a real install, excluding slots where forward failed. */
            record->installedMask = rollbackTaintMask;
            /* Note: Copy the original entry point before the five transactions for read-only conflict resolution confirmation. */
            RtlCopyMemory(
                record->originalDispatch,
                originalDispatch,
                sizeof(record->originalDispatch));
            /* Note: Save canonical \Driver\ name for subsequent directory-less restoration. */
            (VOID)RtlStringCchCopyW(
                record->canonicalName,
                RTL_NUMBER_OF(record->canonicalName),
                canonicalName);
            /* Note: Publish InUse last to prevent queries on partially initialized records. */
            record->inUse = TRUE;
            /* Note: Publish the creation generation of the rollback taint record. */
            kswordArkDriverCommunicationAdvanceGenerationLocked(record);
            /* Note: Refresh runtime reject visibility without absorbing forward failure slots. */
            kswordArkDriverCommunicationRefreshRecordLocked(record);
            /* Note: The response exposes only the actual rollback taint. */
            kswordArkDriverCommunicationFillResponse(
                response,
                request->action,
                STATUS_OBJECT_TYPE_MISMATCH,
                0UL,
                record,
                NULL,
                NULL);
            /* Note: Release the global lock after completing the sticky record submission. */
            ExReleaseFastMutex(&gKswordArkDriverCommunicationState.lock);
            /* Note: The record continues to hold a reference to the DriverObject until explicitly resolved safely. */
            return STATUS_OBJECT_TYPE_MISMATCH;
        }

        /* Note: If all written slots are safely rolled back, forward conflicts do not form a persistent record. */
        RtlZeroMemory(record, sizeof(*record));
        /* Note: A single STATUS_RETRY response remains inactive with no persistent conflict. */
        kswordArkDriverCommunicationFillResponse(
            response,
            request->action,
            STATUS_RETRY,
            0UL,
            NULL,
            driverObject,
            canonicalName);
        /* Note: The transaction has been fully rolled back; release the state lock. */
        ExReleaseFastMutex(&gKswordArkDriverCommunicationState.lock);
        /* Note: No record takes over this resolver reference. */
        ObDereferenceObject(driverObject);
        /* Note: The caller may retry after re-scanning for evidence. */
        return STATUS_RETRY;
    }

    /* Note: If all five slots were originally reject, no actual installation occurred, and no fake active record is ever created. */
    if (changedMask == 0UL) {
        /* Note: Clear uncommitted reserved slots to maintain the purity of the OwnedMask semantics. */
        RtlZeroMemory(record, sizeof(*record));
        /* Note: Forms inactive success, explicitly indicating no communicable entry points can be modified this time. */
        kswordArkDriverCommunicationFillResponse(
            response,
            request->action,
            STATUS_SUCCESS,
            0UL,
            NULL,
            driverObject,
            canonicalName);
        /* Note: Release the control lock first when there is no persistent record. */
        ExReleaseFastMutex(&gKswordArkDriverCommunicationState.lock);
        /* Note: The resolver reference from this operation is not transferred to the state table. */
        ObDereferenceObject(driverObject);
        /* Note: Business logic succeeded, but state remains inactive. */
        return STATUS_SUCCESS;
    }

    /* Note: Commit the complete recoverable record after the five-slot transaction succeeds. */
    record->driverObject = driverObject;
    /* Note: Latch the validated, immutable module base address from the request. */
    record->targetModuleBase = request->targetModuleBase;
    /* Note: Only the slot where the current CAS is successfully installed and not rolled back acquires restored ownership. */
    record->ownedMask = changedMask;
    /* Note: After the transaction completes, all five slots equal the kernel reject. */
    record->activeMask = KSWORD_ARK_DRIVER_COMMUNICATION_MAJOR_MASK_ALL;
    /* Note: Successful transactions have no foreign changes. */
    record->conflictMask = 0UL;
    /* Note: Latch the current real installation slot for ABA monitoring after ownership release. */
    record->installedMask = changedMask;
    /* Note: Saves original function address for each slot. */
    RtlCopyMemory(
        record->originalDispatch,
        originalDispatch,
        sizeof(record->originalDispatch));
    /* Note: Save the canonical object name resolved from the module. */
    (VOID)RtlStringCchCopyW(
        record->canonicalName,
        RTL_NUMBER_OF(record->canonicalName),
        canonicalName);
    /* Note: Publish the record within the atomic control domain only after all fields are ready. */
    record->inUse = TRUE;
    /* Note: Successfully advanced the target generation for blind. */
    kswordArkDriverCommunicationAdvanceGenerationLocked(record);
    /* Note: Generate an active response containing the changed mask for this operation. */
    kswordArkDriverCommunicationFillResponse(
        response,
        request->action,
        STATUS_SUCCESS,
        changedMask,
        record,
        NULL,
        NULL);
    /* Note: Release the serial lock after submission; continue holding object references. */
    ExReleaseFastMutex(&gKswordArkDriverCommunicationState.lock);
    /* Note: blind transaction succeeded. */
    return STATUS_SUCCESS;
}

/* Note: Restore the five slots based on the original record entries, replacing only those entries that still equal reject. */
NTSTATUS
kswordArkDriverCommunicationRestore(
    _In_ const KSWORD_ARK_DRIVER_COMMUNICATION_REQUEST* request,
    _Out_ KSWORD_ARK_DRIVER_COMMUNICATION_RESPONSE* response
    )
{
    KswDriverCommunicationRecord* record = NULL;
    PDRIVER_OBJECT releasedObject = NULL;
    WCHAR canonicalName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
    ULONG slotIndex = 0UL;
    ULONG changedMask = 0UL;
    ULONGLONG targetModuleBase = 0ULL;
    NTSTATUS status = STATUS_SUCCESS;

    /* Note: Restore reliance on persistent module base address records only, avoiding re-parsing object names that may have already disappeared. */
    ExAcquireFastMutex(&gKswordArkDriverCommunicationState.lock);
    /* Note: Module base address is the unique lookup key for restoring actions. */
    record = kswordArkDriverCommunicationFindRecordLocked(request->targetModuleBase);
    /* Note: No record indicates there is no state recoverable by this feature. */
    if (record == NULL) {
        /* Note: Form a stable inactive/not-found response. */
        kswordArkDriverCommunicationFillResponse(
            response,
            request->action,
            STATUS_NOT_FOUND,
            0UL,
            NULL,
            NULL,
            NULL);
        /* Note: Release lock immediately when no record path exists. */
        ExReleaseFastMutex(&gKswordArkDriverCommunicationState.lock);
        /* Note: Explicitly report to R3 that no recovery record exists. */
        return STATUS_NOT_FOUND;
    }

    /* Note: Observe and permanently latch foreign first to prevent overwriting the old entry after B->reject ABA. */
    kswordArkDriverCommunicationRefreshRecordLocked(record);
    /* Note: Restore entries per slot that are still actually owned and have never been tainted. */
    for (slotIndex = 0UL;
        slotIndex < KSW_DRIVER_COMMUNICATION_SLOT_COUNT;
        ++slotIndex) {
        const KswDriverCommunicationSlot* slot =
            &kGKswordArkDriverCommunicationSlots[slotIndex];
        PDRIVER_DISPATCH previousDispatch = NULL;

        /* Note: Slots that are not owned or permanently tainted are excluded from any recovery writes. */
        if ((record->ownedMask & slot->mask) == 0UL ||
            (record->conflictMask & slot->mask) != 0UL) {
            /* Note: A tainted slot that re-equals reject remains read-only for diagnostics only. */
            continue;
        }

        /* Note: Only write back the captured original entry if it is still kernel-rejected. */
        previousDispatch = kswordArkDriverCommunicationCompareExchangeDispatch(
            record->driverObject,
            slot->majorFunction,
            record->originalDispatch[slotIndex],
            gKswordArkDriverCommunicationState.rejectDispatch);
        /* Note: A CAS hit indicates that this slot was indeed restored in this operation. */
        if (previousDispatch ==
            gKswordArkDriverCommunicationState.rejectDispatch) {
            /* Record the protocol bits successfully restored in this operation. */
            changedMask |= slot->mask;
            /* Note: This slot no longer requires the record to hold recovery responsibility. */
            record->ownedMask &= ~slot->mask;
        }
        /* Note: Considered a safe completion when the third party has restored to the same original entry point. */
        else if (previousDispatch == record->originalDispatch[slotIndex]) {
            /* Note: No overwrite needed; directly release ownership of this slot. */
            record->ownedMask &= ~slot->mask;
        }
        else {
            /* Note: Foreign changes are not overwritten and permanently lock the taint. */
            record->conflictMask |= slot->mask;
            /* Note: After observing foreign, permanently revoke the slot's automatic recovery eligibility. */
            record->ownedMask &= ~slot->mask;
        }
    }

    /* Note: Perform a second read-only refresh to capture foreign changes that occur within the recovery CAS window. */
    kswordArkDriverCommunicationRefreshRecordLocked(record);
    /* Note: The explicit RESTORE attempt itself advances the observable generation. */
    kswordArkDriverCommunicationAdvanceGenerationLocked(record);

    /* Note: Can retire directly when there is no owned state and no taint; taint must be explicitly confirmed after external recovery. */
    if (record->ownedMask == 0UL &&
        (record->conflictMask == 0UL ||
        kswordArkDriverCommunicationTaintedSlotsMatchOriginalLocked(record))) {
        /* Note: Temporarily store the object and name; after clearing the record, form a complete inactive response. */
        releasedObject = record->driverObject;
        /* Note: Save immutable record key; prohibit responding to reads of the current DriverStart for retired targets. */
        targetModuleBase = record->targetModuleBase;
        /* Note: Save the canonical name for use after the record is zeroed. */
        (VOID)RtlStringCchCopyW(
            canonicalName,
            RTL_NUMBER_OF(canonicalName),
            record->canonicalName);
        /* Note: Record deletion is the sole permanent point to clear taint, without writing to any taint slots. */
        RtlZeroMemory(record, sizeof(*record));
        /* Note: Publish the global generation after record retirement. */
        kswordArkDriverCommunicationAdvanceGenerationLocked(NULL);
        /* Note: Explicitly confirm completion and return success as inactive, rather than leaving a foreign flag. */
        status = STATUS_SUCCESS;
        /* Note: Fill the diagnostic address using the object that still holds a reference before unlocking and releasing. */
        kswordArkDriverCommunicationFillResponse(
            response,
            request->action,
            status,
            changedMask,
            NULL,
            releasedObject,
            canonicalName);
        /* Note: inactive responses still populate the module base address captured at record creation time. */
        response->driverStart = targetModuleBase;
    }
    else {
        /* Note: Any permanent taint remains in conflict and blocks force-unload. */
        status = record->conflictMask != 0UL
            ? STATUS_OBJECT_TYPE_MISMATCH
            : STATUS_SUCCESS;
        /* Note: Return the real-time active and permanent conflict mask for non-retired records. */
        kswordArkDriverCommunicationFillResponse(
            response,
            request->action,
            status,
            changedMask,
            record,
            NULL,
            NULL);
    }

    /* Note: Release the serial lock after completing the status commit. */
    ExReleaseFastMutex(&gKswordArkDriverCommunicationState.lock);
    /* Note: Release the target DriverObject reference after full restoration. */
    if (releasedObject != NULL) {
        /* Note: No slots depend on the object's lifetime. */
        ObDereferenceObject(releasedObject);
    }
    /* Note: Return success or a foreign-change status. */
    return status;
}
