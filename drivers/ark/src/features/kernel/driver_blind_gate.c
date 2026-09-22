/*++

Module Name:

    driver_blind_gate.c

Abstract:

    Force-unload identity gate for DriverObject communication records.

Environment:

    Kernel-mode Driver Framework

--*/

#include "driver_blind_internal.h"

BOOLEAN
kswordArkDriverCommunicationHasBlockingRecord(
    _In_ PDRIVER_OBJECT targetDriverObject,
    _In_ ULONGLONG originalRequestModuleBase
    )
{
    PDRIVER_OBJECT releaseObjects[KSW_DRIVER_COMMUNICATION_RECORD_LIMIT] = { 0 };
    ULONG releaseCount = 0UL;
    ULONG recordIndex = 0UL;
    BOOLEAN blocked = FALSE;

    /* Note: The actual DriverObject already held by force-unload is the mandatory primary identity and cannot be omitted. */
    if (targetDriverObject == NULL) {
        /* Note: Without a reference object, it cannot be proven that no blocking records exist; close as failure. */
        return TRUE;
    }
    /* Note: Records created by it do not exist when the feature is uninitialized. */
    if (InterlockedCompareExchange(
        &gKswordArkDriverCommunicationState.initialized,
        0L,
        0L) == 0L) {
        /* Note: An uninitialized state will not block other unload logic. */
        return FALSE;
    }
    /* Note: FAST_MUTEX requires the caller to be at PASSIVE_LEVEL IRQL. */
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        /* Note: An incorrect IRQL cannot prove safety; treat it as having a blocking record. */
        return TRUE;
    }

    /* Note: Scan all records serially to avoid using a single field as a key, which might be rewritten by the target. */
    ExAcquireFastMutex(&gKswordArkDriverCommunicationState.lock);
    /* Note: A full scan of the small fixed table finds identity matches by either pointer or immutable request base address. */
    for (recordIndex = 0UL;
        recordIndex < KSW_DRIVER_COMMUNICATION_RECORD_LIMIT;
        ++recordIndex) {
        KswDriverCommunicationRecord* record =
            &gKswordArkDriverCommunicationState.records[recordIndex];
        BOOLEAN identityMatch = FALSE;

        /* Note: An empty record holds no target identity or reference. */
        if (record->inUse == FALSE) {
            /* Continue checking other records. */
            continue;
        }
        /* Note: Do not trust the target's current DriverStart when the DriverObject pointer is matched via reference. */
        if (record->driverObject == targetDriverObject) {
            /* Note: Object identity match implies inclusion in the access control gate. */
            identityMatch = TRUE;
        }
        /* Note: The original force-unload request base address provides a second immutable identity clue. */
        else if (originalRequestModuleBase != 0ULL &&
            record->targetModuleBase == originalRequestModuleBase) {
            /* Note: any identity record must be resolved first and cannot be bypassed by current field drift. */
            identityMatch = TRUE;
        }
        /* Note: A record with no matching identity is unrelated to this unloading. */
        if (identityMatch == FALSE) {
            /* Note: Continue full scan. */
            continue;
        }

        /* Note: Perform the final access control check after refreshing the real-time owned and permanent taint states. */
        kswordArkDriverCommunicationRefreshRecordLocked(record);
        /* Note: Any owned or sticky taint bit requires executing RESTORE first. */
        if (record->ownedMask != 0UL || record->conflictMask != 0UL) {
            /* Note: After detecting a blocked record, retain it along with its DriverObject reference. */
            blocked = TRUE;
            /* Note: Still need to release the reference to the previously cleaned-up expired record after unlocking. */
            break;
        }

        /* Note: Identity records without owned/taint status are safely expired and can be retired within the gate. */
        if (record->driverObject != NULL) {
            /* Note: Temporarily store record references to avoid triggering object deletion paths within a FAST_MUTEX. */
            releaseObjects[releaseCount] = record->driverObject;
            /* Note: Fixed table capacity ensures the release array does not overflow. */
            ++releaseCount;
        }
        /* Note: Clear expired security records without retaining variable target fields. */
        RtlZeroMemory(record, sizeof(*record));
        /* Note: Record retirement to advance the global generation. */
        kswordArkDriverCommunicationAdvanceGenerationLocked(NULL);
    }
    /* Note: Release the global state lock after identity scanning is complete. */
    ExReleaseFastMutex(&gKswordArkDriverCommunicationState.lock);

    /* Note: Release all DriverObject references held by security-expired records outside the lock. */
    for (recordIndex = 0UL; recordIndex < releaseCount; ++recordIndex) {
        /* Note: The array stores only non-null record references. */
        ObDereferenceObject(releaseObjects[recordIndex]);
    }
    /* Note: Returns the failed gate closure result obtained from dual-identity scanning. */
    return blocked;
}
