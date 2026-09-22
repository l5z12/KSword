/*++

Module Name:

    driver_blind.c

Abstract:

    Reversible DriverObject MajorFunction communication blocking.

Environment:

    Kernel-mode Driver Framework

--*/

#include <ntifs.h>

#include "ark/ark_driver.h"
#include "driver_blind_internal.h"
#include "driver_integrity.h"
#include "../../platform/pool_compat.h"

#include <ntstrsafe.h>

/* Note: The five protocol slots maintain a stable order to facilitate transaction rollback and R3 mask display. */
const KswDriverCommunicationSlot kGKswordArkDriverCommunicationSlots[
    KSW_DRIVER_COMMUNICATION_SLOT_COUNT] = {
    { KSWORD_ARK_DRIVER_COMMUNICATION_MAJOR_MASK_CREATE, IRP_MJ_CREATE },
    { KSWORD_ARK_DRIVER_COMMUNICATION_MAJOR_MASK_READ, IRP_MJ_READ },
    { KSWORD_ARK_DRIVER_COMMUNICATION_MAJOR_MASK_WRITE, IRP_MJ_WRITE },
    { KSWORD_ARK_DRIVER_COMMUNICATION_MAJOR_MASK_DEVICE_CONTROL, IRP_MJ_DEVICE_CONTROL },
    { KSWORD_ARK_DRIVER_COMMUNICATION_MAJOR_MASK_INTERNAL_DEVICE_CONTROL, IRP_MJ_INTERNAL_DEVICE_CONTROL }
};

/* Note: Static state resides in non-paged driver image; IOCTL usage is prohibited before initialization completes. */
KswDriverCommunicationState gKswordArkDriverCommunicationState;

/* Note: Compile-time verification ensures protocol slot count and WDK MajorFunction array boundaries are consistent. */
C_ASSERT(KSW_DRIVER_COMMUNICATION_SLOT_COUNT == 5U);
/* Note: Compile-time assertion that the highest target major function index falls within the DRIVER_OBJECT public array. */
C_ASSERT(IRP_MJ_INTERNAL_DEVICE_CONTROL <= IRP_MJ_MAXIMUM_FUNCTION);
/* Note: Lock the v1 x64 ABI sizes to prevent R0/R3 compilation option drift. */
C_ASSERT(sizeof(KSWORD_ARK_DRIVER_COMMUNICATION_REQUEST) == 552U);
C_ASSERT(sizeof(KSWORD_ARK_DRIVER_COMMUNICATION_RESPONSE) == 592U);
/* Note: Lock fixed offsets for request base address, pre-check object address, and response reject address. */
C_ASSERT(FIELD_OFFSET(
    KSWORD_ARK_DRIVER_COMMUNICATION_REQUEST,
    targetModuleBase) == 16U);
C_ASSERT(FIELD_OFFSET(
    KSWORD_ARK_DRIVER_COMMUNICATION_REQUEST,
    expectedDriverObjectAddress) == 24U);
C_ASSERT(FIELD_OFFSET(
    KSWORD_ARK_DRIVER_COMMUNICATION_RESPONSE,
    driverObjectAddress) == 48U);
C_ASSERT(FIELD_OFFSET(
    KSWORD_ARK_DRIVER_COMMUNICATION_RESPONSE,
    rejectDispatchAddress) == 64U);

/* Note: Bound device snapshots so a malicious or pathological DriverObject cannot consume unbounded pool memory. */
#define KSW_DRIVER_COMMUNICATION_DEVICE_LIMIT 64UL
/* Note: The device count retries at most three times in enumeration race conditions. */
#define KSW_DRIVER_COMMUNICATION_DEVICE_ENUM_RETRY_LIMIT 3UL
/* Note: Non-paged device pointer array uses an independent, identifiable pool tag. */
#define KSW_DRIVER_COMMUNICATION_DEVICE_LIST_TAG 'lBcK'

/* Note: Use pointer CAS to atomically read the current dispatch without modifying the target content. */
PDRIVER_DISPATCH
kswordArkDriverCommunicationReadDispatch(
    _In_ PDRIVER_OBJECT driverObject,
    _In_ UCHAR majorFunction
    )
{
    PVOID currentDispatch = NULL;

    /* Note: Use NULL/NULL compare-exchange to obtain an atomic snapshot consistent with the write path. */
    currentDispatch = InterlockedCompareExchangePointer(
        (PVOID volatile*)&driverObject->MajorFunction[majorFunction],
        NULL,
        NULL);
    /* Note: Restore the public function pointer type and pass it to the caller for comparison. */
    return (PDRIVER_DISPATCH)currentDispatch;
}

/* Note: Replace only if the slot still equals expected; never overwrite concurrent third-party modifications. */
PDRIVER_DISPATCH
kswordArkDriverCommunicationCompareExchangeDispatch(
    _In_ PDRIVER_OBJECT driverObject,
    _In_ UCHAR majorFunction,
    _In_ PDRIVER_DISPATCH exchange,
    _In_ PDRIVER_DISPATCH expected
    )
{
    PVOID previousDispatch = NULL;

    /* Note: Pointer CAS provides both atomic conditional update and cross-processor memory ordering. */
    previousDispatch = InterlockedCompareExchangePointer(
        (PVOID volatile*)&driverObject->MajorFunction[majorFunction],
        (PVOID)exchange,
        (PVOID)expected);
    /* Note: Return the actual entry before writing, for the transaction to determine success or foreign change. */
    return (PDRIVER_DISPATCH)previousDispatch;
}

/* Note: Canonical object names must reside under \Driver\; file system objects explicitly reject others. */
static BOOLEAN
kswordArkDriverCommunicationIsCanonicalDriverName(
    _In_z_ const WCHAR* canonicalName
    )
{
    UNICODE_STRING candidateName;
    UNICODE_STRING requiredPrefix;

    /* Note: An empty string cannot serve as the identity for a modifiable DriverObject. */
    if (canonicalName == NULL || canonicalName[0] == L'\0') {
        /* Note: Close on failure if canonical name is missing. */
        return FALSE;
    }

    /* Note: Construct a read-only UNICODE_STRING for case-insensitive prefix comparison. */
    RtlInitUnicodeString(&candidateName, canonicalName);
    /* Note: The trailing backslash prevents \DriverLike from being misidentified as \Driver. */
    RtlInitUnicodeString(&requiredPrefix, L"\\Driver\\");
    /* Note: Only objects truly located in the \Driver\ directory can enter the replacement transaction. */
    return RtlPrefixUnicodeString(&requiredPrefix, &candidateName, TRUE);
}

/* Note: Verify that the captured default I/O manager dispatch is owned by the ntos/HAL image. */
static NTSTATUS
kswordArkDriverCommunicationValidateKernelReject(
    _In_ PDRIVER_DISPATCH rejectDispatch
    )
{
    KswHookSystemModuleInformation* moduleInfo = NULL;
    const KswHookSystemModuleEntry* ownerModule = NULL;
    ULONG moduleInfoBytes = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    /* Note: A null entry can never serve as a cross-driver reject function. */
    if (rejectDispatch == NULL) {
        /* Note: Use a stable state to indicate that the DriverEntry initial table does not match expectations. */
        return STATUS_INVALID_DEVICE_STATE;
    }

    /* Note: Reads a system module snapshot once and verifies entry ownership using public module ownership tools. */
    status = kswordArkHookBuildModuleSnapshot(&moduleInfo, &moduleInfoBytes);
    /* Note: Reject enabling the feature if the entry cannot be proven to belong to the kernel. */
    if (!NT_SUCCESS(status) || moduleInfo == NULL) {
        /* Note: An anomalous success with an empty result is also normalized to unavailable. */
        return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
    }

    /* Note: Find the unique loaded module that covers the entry point address. */
    ownerModule = kswordArkDriverIntegrityFindModuleForAddress(
        moduleInfo,
        (ULONGLONG)(ULONG_PTR)rejectDispatch);
    /* Note: Only accept stable kernel images: ntoskrnl, ntkrnl, or HAL. */
    if (ownerModule == NULL ||
        !kswordArkDriverIntegrityIsCoreKernelModule(ownerModule)) {
        /* Note: Return explicit owner mismatch after releasing module snapshot. */
        ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
        /* Note: Non-kernel entry points must not cross the KSword self-unloading lifecycle. */
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    /* Note: Release the temporary module snapshot after validation is complete. */
    ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
    /* Note: Both ownership and null-check conditions are satisfied. */
    return STATUS_SUCCESS;
}

/* Note: Generate a non-zero monotonically increasing generation and write the record of state changes. */
VOID
kswordArkDriverCommunicationAdvanceGenerationLocked(
    _Inout_opt_ KswDriverCommunicationRecord* record
    )
{
    /* Note: Advance the global generation only once per observable state change. */
    ++gKswordArkDriverCommunicationState.generation;
    /* Note: Zero values are reserved for responses to records that have not yet been created. */
    if (gKswordArkDriverCommunicationState.generation == 0UL) {
        /* Note: Skip reserved zero value on natural wraparound. */
        ++gKswordArkDriverCommunicationState.generation;
    }
    /* Note: Synchronize the last change generation of the target record if it exists. */
    if (record != NULL) {
        /* Note: Record generation for R3 to determine if query results have been refreshed. */
        record->generation = gKswordArkDriverCommunicationState.generation;
    }
}

/* Note: Look up the state record holding the reference by the unique module base address. */
KswDriverCommunicationRecord*
kswordArkDriverCommunicationFindRecordLocked(
    _In_ ULONGLONG targetModuleBase
    )
{
    ULONG recordIndex = 0UL;

    /* Note: Linearly scan a fixed small table to avoid dynamic containers and paging dependencies. */
    for (recordIndex = 0UL;
        recordIndex < KSW_DRIVER_COMMUNICATION_RECORD_LIMIT;
        ++recordIndex) {
        KswDriverCommunicationRecord* record =
            &gKswordArkDriverCommunicationState.records[recordIndex];

        /* Note: Only compare the immutable request module base address locked at record creation time. */
        if (record->inUse != FALSE &&
            record->targetModuleBase == targetModuleBase) {
            /* Note: Return the unique record upon a module base address match. */
            return record;
        }
    }

    /* Note: A miss indicates the target currently has no KSword blind status. */
    return NULL;
}

/* Note: Retrieve a zeroed empty record from the fixed table. */
KswDriverCommunicationRecord*
kswordArkDriverCommunicationAllocateRecordLocked(
    VOID
    )
{
    ULONG recordIndex = 0UL;

    /* Note: Select the first empty slot in a fixed order to ensure reproducible behavior. */
    for (recordIndex = 0UL;
        recordIndex < KSW_DRIVER_COMMUNICATION_RECORD_LIMIT;
        ++recordIndex) {
        KswDriverCommunicationRecord* record =
            &gKswordArkDriverCommunicationState.records[recordIndex];

        /* Note: An empty slot can be safely reset and handed to the current transaction. */
        if (record->inUse == FALSE) {
            /* Note: Clear residual addresses and masks from the previous generation. */
            RtlZeroMemory(record, sizeof(*record));
            /* Note: The caller sets InUse to TRUE only after submitting the transaction. */
            return record;
        }
    }

    /* Note: Do not overwrite existing recoverable states when fixed capacity is exhausted. */
    return NULL;
}

/* Note: Refresh the active/conflict mask for the currently owned slot without writing to the target table. */
VOID
kswordArkDriverCommunicationRefreshRecordLocked(
    _Inout_ KswDriverCommunicationRecord* record
    )
{
    ULONG slotIndex = 0UL;
    ULONG activeMask = 0UL;
    ULONG taintedMask = 0UL;
    ULONG previousOwnedMask = 0UL;
    ULONG previousActiveMask = 0UL;
    ULONG previousTaintedMask = 0UL;

    /* Note: Empty records have no refreshable state. */
    if (record == NULL || record->inUse == FALSE || record->driverObject == NULL) {
        /* Note: Return immediately for invalid records. */
        return;
    }
    /* Note: Save old masks; only advance generation when ownership or externally observable state changes. */
    previousOwnedMask = record->ownedMask;
    previousActiveMask = record->activeMask;
    previousTaintedMask = record->conflictMask;
    /* Note: Refreshing only allows increasing taint; it never clears historical conflicts based on the current pointer. */
    taintedMask = record->conflictMask;
    /* Note: Atomically read each slot to avoid mixing ordinary reads with this module's CAS writes. */
    for (slotIndex = 0UL;
        slotIndex < KSW_DRIVER_COMMUNICATION_SLOT_COUNT;
        ++slotIndex) {
        const KswDriverCommunicationSlot* slot =
            &kGKswordArkDriverCommunicationSlots[slotIndex];
        PDRIVER_DISPATCH currentDispatch = NULL;
        /* Note: Obtain a real-time atomic snapshot of the target slot. */
        currentDispatch = kswordArkDriverCommunicationReadDispatch(
            record->driverObject,
            slot->majorFunction);
        /* Note: active only describes whether current communication is rejected, not granting recovery ownership. */
        if (currentDispatch == gKswordArkDriverCommunicationState.rejectDispatch) {
            activeMask |= slot->mask;
        }
        /* Note: Slots not actually installed by this feature never qualify for automatic recovery. */
        if ((record->ownedMask & slot->mask) == 0UL) {
            /* Note: Only monitor slots that were successfully installed; forward CAS failures do not persist taint to those slots. */
            if ((record->installedMask & slot->mask) != 0UL &&
                currentDispatch != record->originalDispatch[slotIndex]) {
                /* Note: Cover the secondary ABA of A->reject/foreign after safe external recovery. */
                taintedMask |= slot->mask;
            }
            continue;
        }
        /* Note: Immediately revoke ownership of tainted slots to prevent B->reject ABA. */
        if ((taintedMask & slot->mask) != 0UL) {
            record->ownedMask &= ~slot->mask;
            continue;
        }
        /* Note: retains actual ownership when still the reject installed for this feature. */
        if (currentDispatch == gKswordArkDriverCommunicationState.rejectDispatch) {
            continue;
        }
        /* Note: Release ownership directly if a third party safely restores the captured original entry point. */
        if (currentDispatch == record->originalDispatch[slotIndex]) {
            record->ownedMask &= ~slot->mask;
            continue;
        }
        /* Note: Permanently taint and revoke auto-recovery eligibility upon observing other entries. */
        taintedMask |= slot->mask;
        record->ownedMask &= ~slot->mask;
    }
    /* Note: Submit real-time reject visibility for all five slots. */
    record->activeMask = activeMask;
    /* Note: Commits can only monotonically increase permanent foreign/ABA taint. */
    record->conflictMask = taintedMask;
    /* Note: Update the query generation number only when ownership or visible masks actually change. */
    if (previousOwnedMask != record->ownedMask ||
        previousActiveMask != record->activeMask ||
        previousTaintedMask != record->conflictMask) {
        /* Note: Expose state changes caused by external modifications to R3. */
        kswordArkDriverCommunicationAdvanceGenerationLocked(record);
    }
}

/* Note: Convert the current record or no-record state into a stable protocol response. */
VOID
kswordArkDriverCommunicationFillResponse(
    _Out_ KSWORD_ARK_DRIVER_COMMUNICATION_RESPONSE* response,
    _In_ ULONG action,
    _In_ NTSTATUS lastStatus,
    _In_ ULONG changedMask,
    _In_opt_ const KswDriverCommunicationRecord* record,
    _In_opt_ PDRIVER_OBJECT driverObject,
    _In_opt_z_ const WCHAR* canonicalName
    )
{
    /* Note: Fixed responses must be fully initialized to avoid leaking kernel stack contents. */
    RtlZeroMemory(response, sizeof(*response));
    /* Note: Fill back the protocol version for R3 to reject incompatible layouts. */
    response->version = KSWORD_ARK_DRIVER_COMMUNICATION_PROTOCOL_VERSION;
    /* Note: Echo the actual action performed. */
    response->action = action;
    /* Note: The five fixed communication slots always represent the target set for this feature. */
    response->targetedMask = KSWORD_ARK_DRIVER_COMMUNICATION_MAJOR_MASK_ALL;
    /* Note: changedMask only indicates the slots actually changed by this CAS. */
    response->changedMask = changedMask;
    /* Note: The underlying state maintains precise information via lastStatus. */
    response->lastStatus = lastStatus;
    /* Note: Return verified ntos/HAL reject entry points to R3 for precise evidence comparison. */
    response->rejectDispatchAddress = (ULONGLONG)(ULONG_PTR)
        gKswordArkDriverCommunicationState.rejectDispatch;

    /* Note: Prefer populating active and conflict states from persistent records. */
    if (record != NULL && record->inUse != FALSE) {
        /* Note: The active mask represents the set of the five target slots currently pointing to kernel rejects. */
        response->activeMask = record->activeMask;
        /* Note: The owned mask only indicates slots that are actually installed by this feature and still have recovery eligibility. */
        response->ownedMask = record->ownedMask;
        /* Note: conflict mask indicates the permanently locked foreign taint throughout the record's lifecycle. */
        response->conflictMask = record->conflictMask;
        /* Note: The record generation is updated during blind operations, restores, or external changes. */
        response->generation = record->generation;
        /* Note: Conflict takes precedence over the active state display. */
        response->state = record->conflictMask != 0UL
            ? KSWORD_ARK_DRIVER_COMMUNICATION_STATE_CONFLICT
            : KSWORD_ARK_DRIVER_COMMUNICATION_STATE_ACTIVE;
        /* Note: Set the stable response flag when a foreign change exists. */
        if (record->conflictMask != 0UL) {
            /* Note: R3 does not need to infer conflict semantics from NTSTATUS. */
            response->responseFlags |=
                KSWORD_ARK_DRIVER_COMMUNICATION_RESPONSE_FLAG_FOREIGN_CHANGE;
        }
        /* Note: Return the address of the DriverObject protected by a held reference for diagnostics. */
        response->driverObjectAddress =
            (ULONGLONG)(ULONG_PTR)record->driverObject;
        /* Note: Return the immutable module base-address identity validated and latched when the record was created. */
        response->driverStart = record->targetModuleBase;
        /* Note: Returns the parsed \Driver\ canonical name. */
        (VOID)RtlStringCchCopyW(
            response->driverName,
            RTL_NUMBER_OF(response->driverName),
            record->canonicalName);
        /* Record that the path has been fully populated in the response. */
        return;
    }

    /* Note: No record indicates the target is not taken over by this feature. */
    response->state = KSWORD_ARK_DRIVER_COMMUNICATION_STATE_INACTIVE;
    /* Note: Unrecorded queries still return the current global generation. */
    response->generation = gKswordArkDriverCommunicationState.generation;
    /* Note: Returns the diagnostic address corresponding to the temporary reference upon successful parsing. */
    if (driverObject != NULL) {
        /* Note: The address is for response display only; R3 cannot use it as subsequent input. */
        response->driverObjectAddress = (ULONGLONG)(ULONG_PTR)driverObject;
        /* Note: DriverStart is the sole identity for subsequent control actions. */
        response->driverStart = (ULONGLONG)(ULONG_PTR)driverObject->DriverStart;
    }
    /* Return the canonical object name on successful parsing. */
    if (canonicalName != NULL) {
        /* Note: Bounded copy ensures the fixed array always ends with NUL. */
        (VOID)RtlStringCchCopyW(
            response->driverName,
            RTL_NUMBER_OF(response->driverName),
            canonicalName);
    }
}

/* Note: Release the references acquired by IoEnumerateDeviceObjectList for each non-null entry. */
static VOID
kswordArkDriverCommunicationReleaseDeviceSnapshot(
    _Inout_updates_(capacity) PDEVICE_OBJECT* deviceObjects,
    _In_ ULONG capacity
    )
{
    ULONG deviceIndex = 0UL;

    /* Note: An empty array contains no DeviceObject references to release. */
    if (deviceObjects == NULL) {
        /* Note: Allow all failure cleanup paths to be idempotent. */
        return;
    }
    /* Note: Iterates over allocated capacity rather than returning the total count, compatible with partial fills for BUFFER_TOO_SMALL. */
    for (deviceIndex = 0UL; deviceIndex < capacity; ++deviceIndex) {
        /* Note: Empty slots in the zero-initialized array have no references. */
        if (deviceObjects[deviceIndex] == NULL) {
            /* Note: Skip entries not populated by enumeration APIs. */
            continue;
        }
        /* Note: Each populated entry has been reference-counted by IoEnumerateDeviceObjectList. */
        ObDereferenceObject(deviceObjects[deviceIndex]);
        /* Note: Clear the slot to prevent duplicate dereference during retry cleanup. */
        deviceObjects[deviceIndex] = NULL;
    }
}

/* Note: Use a referenced DeviceObject snapshot to verify the target is an independent legacy control driver. */
static NTSTATUS
kswordArkDriverCommunicationValidateDeviceSnapshot(
    _In_ PDRIVER_OBJECT driverObject
    )
{
    PDEVICE_OBJECT* deviceObjects = NULL;
    ULONG requestedCount = 0UL;
    ULONG actualCount = 0UL;
    ULONG attemptIndex = 0UL;
    NTSTATUS status = STATUS_SUCCESS;
    /* Note: First query the current device object count using the official two-call pattern. */
    status = IoEnumerateDeviceObjectList(
        driverObject,
        NULL,
        0UL,
        &requestedCount);
    /* Note: Zero-length probes typically return BUFFER_TOO_SMALL; other failures immediately disable the feature. */
    if (status != STATUS_BUFFER_TOO_SMALL && !NT_SUCCESS(status)) {
        /* Note: Preserve the exact failure status of the kernel API. */
        return status;
    }
    /* Note: Without a device object, there is no verifiable communication surface. */
    if (requestedCount == 0UL) {
        /* Note: Do not modify MajorFunction directly without device evidence. */
        return STATUS_NOT_SUPPORTED;
    }
    /* Note: Device creation race conditions may cause insufficient capacity on the second enumeration, so bounded retries are used. */
    for (attemptIndex = 0UL;
        attemptIndex < KSW_DRIVER_COMMUNICATION_DEVICE_ENUM_RETRY_LIMIT;
        ++attemptIndex) {
        ULONG deviceIndex = 0UL;
        NTSTATUS validationStatus = STATUS_SUCCESS;
        /* Note: Complex drivers exceeding the fixed device limit are out of scope for this feature. */
        if (requestedCount > KSW_DRIVER_COMMUNICATION_DEVICE_LIMIT) {
            /* Note: Complex device topologies must use a dedicated stack for management. */
            return STATUS_NOT_SUPPORTED;
        }
        /* Note: Allocate a non-paged pointer array based on the current required count. */
        deviceObjects = (PDEVICE_OBJECT*)kswordArkAllocateNonPagedPool(
            (SIZE_T)requestedCount * sizeof(*deviceObjects),
            KSW_DRIVER_COMMUNICATION_DEVICE_LIST_TAG);
        /* Note: Do not touch the target if snapshot storage cannot be obtained. */
        if (deviceObjects == NULL) {
            /* Note: Report pool allocation failure to R3. */
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        /* Note: Zero-initialization allows all enumeration results to release references uniformly from non-empty slots. */
        RtlZeroMemory(
            deviceObjects,
            (SIZE_T)requestedCount * sizeof(*deviceObjects));
        /* Note: Obtain the actual total count returned by the API from zero on each retry. */
        actualCount = 0UL;
        /* Note: Obtain a snapshot of stable DeviceObject pointers with references. */
        status = IoEnumerateDeviceObjectList(
            driverObject,
            deviceObjects,
            requestedCount * (ULONG)sizeof(*deviceObjects),
            &actualCount);
        /* Note: On capacity race, the API fills available entries and increments their references. */
        if (status == STATUS_BUFFER_TOO_SMALL) {
            /* Note: Release all references in the partial snapshot first. */
            kswordArkDriverCommunicationReleaseDeviceSnapshot(
                deviceObjects,
                requestedCount);
            /* Note: Release the old capacity array and retry with the new count. */
            ExFreePoolWithTag(
                deviceObjects,
                KSW_DRIVER_COMMUNICATION_DEVICE_LIST_TAG);
            /* Note: Clear local pointers to avoid double-free on failure paths. */
            deviceObjects = NULL;
            /* Note: A retry is justified only if the actual total returned by the API increases. */
            if (actualCount <= requestedCount) {
                /* Note: inconsistency indicates the target device chain is changing abnormally. */
                return STATUS_INVALID_DEVICE_STATE;
            }
            /* Note: Use the new capacity returned by the API in the next iteration. */
            requestedCount = actualCount;
            /* Note: Continue bounded retries without checking incomplete snapshots. */
            continue;
        }
        /* Note: Other enumeration failures do not include an acceptable complete snapshot. */
        if (!NT_SUCCESS(status)) {
            /* Note: Defensive release of any non-null entries with references that the API might write. */
            kswordArkDriverCommunicationReleaseDeviceSnapshot(
                deviceObjects,
                requestedCount);
            /* Note: Free the current non-paged array. */
            ExFreePoolWithTag(
                deviceObjects,
                KSW_DRIVER_COMMUNICATION_DEVICE_LIST_TAG);
            /* Note: Return precise enumeration failure status. */
            return status;
        }
        /* Note: The success count must not exceed the capacity provided by the caller. */
        if (actualCount > requestedCount) {
            /* Note: First release all visible references obtained from successful calls. */
            kswordArkDriverCommunicationReleaseDeviceSnapshot(
                deviceObjects,
                requestedCount);
            /* Note: Free exception snapshot array. */
            ExFreePoolWithTag(
                deviceObjects,
                KSW_DRIVER_COMMUNICATION_DEVICE_LIST_TAG);
            /* Note: Reject inconsistent API results. */
            return STATUS_INVALID_DEVICE_STATE;
        }
        /* Note: A successful but empty snapshot indicates the device disappeared between calls. */
        if (actualCount == 0UL) {
            /* Note: An empty array has no DeviceObject references, but pool memory must still be freed. */
            ExFreePoolWithTag(
                deviceObjects,
                KSW_DRIVER_COMMUNICATION_DEVICE_LIST_TAG);
            /* Note: Treat as not supported when no stable communication interface exists. */
            return STATUS_NOT_SUPPORTED;
        }
        /* Note: Check public device attributes in the reference snapshot one by one. */
        for (deviceIndex = 0UL; deviceIndex < actualCount; ++deviceIndex) {
            PDEVICE_OBJECT deviceObject = deviceObjects[deviceIndex];
            PDEVICE_OBJECT topDevice = NULL;
            /* Note: A null entry in a successful snapshot indicates an inconsistent kernel return. */
            if (deviceObject == NULL) {
                /* Note: After recording the failure, unified cleanup releases other references. */
                validationStatus = STATUS_INVALID_DEVICE_STATE;
                /* Note: No need to continue reading an incomplete snapshot. */
                break;
            }
            /* Note: Each enumerated object must still belong to the target DriverObject. */
            if (deviceObject->DriverObject != driverObject) {
                /* Note: Cross-driver object identity mismatch. */
                validationStatus = STATUS_OBJECT_TYPE_MISMATCH;
                /* Note: Stop further device attribute checks. */
                break;
            }
            /* Note: This feature only supports standalone control devices with FILE_DEVICE_UNKNOWN. */
            if (deviceObject->DeviceType != FILE_DEVICE_UNKNOWN) {
                /* Note: All dedicated device types are handled exclusively by their dedicated governance path. */
                validationStatus = STATUS_NOT_SUPPORTED;
                /* Note: Stop further device attribute checks. */
                break;
            }
            /* Note: Devices still initializing cannot accept global dispatch switches. */
            if ((deviceObject->Flags & DO_DEVICE_INITIALIZING) != 0UL) {
                /* Note: Require target device to complete initialization. */
                validationStatus = STATUS_DEVICE_NOT_READY;
                /* Note: Stop further device attribute checks. */
                break;
            }
            /* Note: StackSize not equal to 1 indicates a lower stack relationship or an abnormal object state. */
            if (deviceObject->StackSize != 1U) {
                /* Note: Reject creating communication breakpoints across driver stacks. */
                validationStatus = STATUS_DEVICE_BUSY;
                /* Note: Stop further device attribute checks. */
                break;
            }
            /* Note: Obtain a reference to the current stack-top object and perform a safety check on the upper attachment chain. */
            topDevice = IoGetAttachedDeviceReference(deviceObject);
            /* Note: Public APIs should normally return at least the input object itself. */
            if (topDevice == NULL) {
                /* Note: Handle empty stack top as target state exception. */
                validationStatus = STATUS_INVALID_DEVICE_STATE;
                /* Note: No additional references require release. */
                break;
            }
            /* Note: A different stack top indicates the presence of an upper attached device. */
            if (topDevice != deviceObject) {
                /* Note: Record BUSY first, then uniformly release the current stack-top reference. */
                validationStatus = STATUS_DEVICE_BUSY;
            }
            /* Note: Paired release of the stack top reference from IoGetAttachedDeviceReference. */
            ObDereferenceObject(topDevice);
            /* Note: Stop checking other devices once an additional stack is found. */
            if (!NT_SUCCESS(validationStatus)) {
                /* Note: Unified snapshot cleanup will be performed outside the loop. */
                break;
            }
        }
        /* Note: Every non-null entry successfully enumerated is uniformly dereferenced here. */
        kswordArkDriverCommunicationReleaseDeviceSnapshot(
            deviceObjects,
            requestedCount);
        /* Note: Free the non-paged pointer array. */
        ExFreePoolWithTag(
            deviceObjects,
            KSW_DRIVER_COMMUNICATION_DEVICE_LIST_TAG);
        /* Note: Clear local pointers after array release. */
        deviceObjects = NULL;
        /* Note: Returns the status of the first failure in the complete snapshot or success if all checks pass. */
        return validationStatus;
    }
    /* Note: When continuous device growth exhausts the retry budget, require the caller to retry later. */
    return STATUS_RETRY;
}

/* Note: Validate that the target reference belongs to \Driver\ and is never KSword itself. */
NTSTATUS
kswordArkDriverCommunicationValidateTarget(
    _In_ PDRIVER_OBJECT driverObject,
    _In_z_ const WCHAR* canonicalName
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    /* Note: Module base address resolution must return the actual DriverObject. */
    if (driverObject == NULL) {
        /* Note: A null object cannot enter any CAS path. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Note: File system directory objects are outside the scope allowed for this feature. */
    if (!kswordArkDriverCommunicationIsCanonicalDriverName(canonicalName)) {
        /* Note: Stable rejection of \FileSystem and other object directories. */
        return STATUS_NOT_SUPPORTED;
    }
    /* Note: Prevent blinding KSword itself, otherwise R3 loses the recovery control channel. */
    if (driverObject == gKswordArkDriverCommunicationState.selfDriverObject ||
        (gKswordArkDriverCommunicationState.selfDriverObject != NULL &&
        driverObject->DriverStart ==
            gKswordArkDriverCommunicationState.selfDriverObject->DriverStart)) {
        /* Note: Using core driver rejection status highlights non-bypassable self-protection. */
        return STATUS_DRIVER_BLOCKED_CRITICAL;
    }
    /* Note: After resolving the module base address, DriverStart must still be non-null. */
    if (driverObject->DriverStart == NULL) {
        /* Note: Treat as an invalid object when load identity is missing. */
        return STATUS_INVALID_DEVICE_STATE;
    }
    /* Note: Exposing AddDevice indicates PnP lifecycle; modifying only communication slots is prohibited as it breaks the PnP mental model. */
    if (driverObject->DriverExtension != NULL &&
        driverObject->DriverExtension->AddDevice != NULL) {
        /* Note: PnP drivers must be managed through the complete device stack; this feature is disabled upon failure. */
        return STATUS_NOT_SUPPORTED;
    }
    /* Note: StartIo drivers have an independent queue lifecycle; replacing only the five dispatch slots is insufficient. */
    if (driverObject->DriverStartIo != NULL) {
        /* Note: Prevent queued IRPs from entering a half-switched state with new rejected entry points. */
        return STATUS_NOT_SUPPORTED;
    }
    /* Note: Obtain a stable device snapshot via kernel reference enumeration and perform stack pre-check. */
    status = kswordArkDriverCommunicationValidateDeviceSnapshot(driverObject);
    /* Note: Preserve the precise failure reason of the snapshot pre-check. */
    if (!NT_SUCCESS(status)) {
        /* Note: Fail and close on any device lifecycle or stack risk. */
        return status;
    }
    /* Note: The target must satisfy directory, self, stable legacy control device, and loaded identity constraints. */
    return status;
}

NTSTATUS
kswordArkDriverCommunicationInitialize(
    _In_ PDRIVER_OBJECT driverObject
    )
{
    PDRIVER_DISPATCH rejectDispatch = NULL;
    ULONG majorIndex = 0UL;
    ULONG_PTR selfStart = 0U;
    ULONG_PTR rejectAddress = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    /* Note: This initialization must occur before WdfDriverCreate rewrites the dispatch table. */
    if (driverObject == NULL || KeGetCurrentIrql() != PASSIVE_LEVEL) {
        /* Note: The initial DriverObject cannot be safely validated during an erroneous call phase. */
        return STATUS_INVALID_PARAMETER;
    }

    /* Note: Re-initialization is idempotent and succeeds only for the same driver object. */
    if (InterlockedCompareExchange(
        &gKswordArkDriverCommunicationState.initialized,
        0L,
        0L) != 0L) {
        /* Note: Repeated calls with different objects indicate an initialization order error. */
        return gKswordArkDriverCommunicationState.selfDriverObject == driverObject
            ? STATUS_SUCCESS
            : STATUS_INVALID_DEVICE_STATE;
    }

    /* Note: The I/O manager pre-fills all slots with the same invalid dispatch before DriverEntry. */
    rejectDispatch = driverObject->MajorFunction[0];
    /* Note: Verify item-by-item that the initial table is fully consistent and non-empty. */
    for (majorIndex = 0UL;
        majorIndex <= IRP_MJ_MAXIMUM_FUNCTION;
        ++majorIndex) {
        /* Note: Any discrepancy indicates the call occurred after the framework dispatch installation. */
        if (rejectDispatch == NULL ||
            driverObject->MajorFunction[majorIndex] != rejectDispatch) {
            /* Note: Do not capture uncertain entry points; the feature shuts down on failure. */
            return STATUS_INVALID_DEVICE_STATE;
        }
    }

    /* Note: Reject additional entries falling within the KSword self-image range. */
    selfStart = (ULONG_PTR)driverObject->DriverStart;
    /* Note: Convert the function entry point to an integer address for range comparison only. */
    rejectAddress = (ULONG_PTR)rejectDispatch;
    /* Note: Use subtraction-based comparison to avoid overflow when computing selfStart + DriverSize. */
    if (driverObject->DriverSize != 0UL &&
        rejectAddress >= selfStart &&
        (rejectAddress - selfStart) < (ULONG_PTR)driverObject->DriverSize) {
        /* Note: A function in this driver cannot serve as a rejection entry point that survives KSword unloading. */
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    /* Note: Prove the entry truly belongs to ntos/HAL via the loaded module snapshot. */
    status = kswordArkDriverCommunicationValidateKernelReject(rejectDispatch);
    /* Note: Reject enabling the feature if kernel ownership verification cannot be completed. */
    if (!NT_SUCCESS(status)) {
        /* Note: Return precise verification failure to DriverEntry. */
        return status;
    }

    /* Note: Clear and initialize global state after successful validation. */
    RtlZeroMemory(
        &gKswordArkDriverCommunicationState,
        sizeof(gKswordArkDriverCommunicationState));
    /* Note: FAST_MUTEX protects only the control path and the record table. */
    ExInitializeFastMutex(&gKswordArkDriverCommunicationState.lock);
    /* Note: Save the self object for permanent self-target rejection. */
    gKswordArkDriverCommunicationState.selfDriverObject = driverObject;
    /* Note: Save the kernel-owned default invalid dispatch. */
    gKswordArkDriverCommunicationState.rejectDispatch = rejectDispatch;
    /* Note: generation starts at 1; zero is reserved for uninitialized. */
    gKswordArkDriverCommunicationState.generation = 1UL;
    /* Note: Publish 'Initialized' only after all state fields are ready. */
    InterlockedExchange(
        &gKswordArkDriverCommunicationState.initialized,
        1L);
    /* Note: Communication blocking backend can accept IOCTLs. */
    return STATUS_SUCCESS;
}

VOID
kswordArkDriverCommunicationUninitialize(
    VOID
    )
{
    PDRIVER_OBJECT releaseObjects[KSW_DRIVER_COMMUNICATION_RECORD_LIMIT] = { 0 };
    ULONG releaseCount = 0UL;
    ULONG recordIndex = 0UL;

    /* Note: In the uninitialized state, there are no target references or replacements to restore. */
    if (InterlockedCompareExchange(
        &gKswordArkDriverCommunicationState.initialized,
        0L,
        0L) == 0L) {
        /* Note: Return immediately for idempotent repeated cleanup. */
        return;
    }

    /* Note: Serially wait for ongoing control operations to complete. */
    ExAcquireFastMutex(&gKswordArkDriverCommunicationState.lock);
    /* Note: First block any subsequent blind requests from creating new records. */
    gKswordArkDriverCommunicationState.shuttingDown = TRUE;

    /* Note: Per-record recovery still holds and is uncorrupted by this feature. */
    for (recordIndex = 0UL;
        recordIndex < KSW_DRIVER_COMMUNICATION_RECORD_LIMIT;
        ++recordIndex) {
        KswDriverCommunicationRecord* record =
            &gKswordArkDriverCommunicationState.records[recordIndex];
        ULONG slotIndex = 0UL;

        /* Note: Empty records contain no object references. */
        if (record->inUse == FALSE || record->driverObject == NULL) {
            /* Note: Skip unused slots. */
            continue;
        }

        /* Note: First lock foreign observation and revoke ownership of the taint slot recovery. */
        kswordArkDriverCommunicationRefreshRecordLocked(record);
        /* Note: Unload recovery still insists on compare-exchange and does not overwrite foreign changes. */
        for (slotIndex = 0UL;
            slotIndex < KSW_DRIVER_COMMUNICATION_SLOT_COUNT;
            ++slotIndex) {
            const KswDriverCommunicationSlot* slot =
                &kGKswordArkDriverCommunicationSlots[slotIndex];

            /* Note: Only process slots that are actually installed and have never been tainted. */
            if ((record->ownedMask & slot->mask) == 0UL ||
                (record->conflictMask & slot->mask) != 0UL) {
                /* Note: If ownership is not held or the slot is tainted, never write even if it returns to reject. */
                continue;
            }

            /* Note: Restore the captured original entry point while the kernel is still in reject state. */
            (VOID)kswordArkDriverCommunicationCompareExchangeDispatch(
                record->driverObject,
                slot->majorFunction,
                record->originalDispatch[slotIndex],
                gKswordArkDriverCommunicationState.rejectDispatch);
        }

        /* Note: Temporarily hold references; perform unified dereference after unlocking. */
        releaseObjects[releaseCount] = record->driverObject;
        /* Note: Fixed capacity ensures releaseCount never overflows. */
        ++releaseCount;
        /* Note: Clear the record to prevent queries during driver unloading. */
        RtlZeroMemory(record, sizeof(*record));
    }

    /* Note: Revoke the initialization publication status only after all records have been removed. */
    InterlockedExchange(
        &gKswordArkDriverCommunicationState.initialized,
        0L);
    /* Note: The target table does not reference KSword code; object references can be released after unlocking. */
    ExReleaseFastMutex(&gKswordArkDriverCommunicationState.lock);

    /* Note: Release all target DriverObject references outside the lock. */
    for (recordIndex = 0UL; recordIndex < releaseCount; ++recordIndex) {
        /* Note: The array stores only non-null references from the actual records. */
        ObDereferenceObject(releaseObjects[recordIndex]);
    }
}

NTSTATUS
kswordArkDriverControlCommunication(
    _In_ const KSWORD_ARK_DRIVER_COMMUNICATION_REQUEST* request,
    _Out_ KSWORD_ARK_DRIVER_COMMUNICATION_RESPONSE* response
    )
{
    const ULONG kAllowedFlags =
        KSWORD_ARK_DRIVER_COMMUNICATION_FLAG_TARGET_MODULE_BASE_PRESENT |
        KSWORD_ARK_DRIVER_COMMUNICATION_FLAG_UI_CONFIRMED |
        KSWORD_ARK_DRIVER_COMMUNICATION_FLAG_EXPECTED_DRIVER_OBJECT_PRESENT;

    /* Note: The backend accepts only complete, fixed request and response pointers. */
    if (request == NULL || response == NULL) {
        /* Note: A protocol response cannot be formed without a fixed buffer. */
        return STATUS_INVALID_PARAMETER;
    }

    /* Note: Zero the response first to ensure no data leakage on any failure path. */
    RtlZeroMemory(response, sizeof(*response));
    /* Note: Fill in the protocol version that must be returned even on the failure path. */
    response->version = KSWORD_ARK_DRIVER_COMMUNICATION_PROTOCOL_VERSION;
    /* Note: Echo the request action to facilitate R3 correlation of concurrent tasks. */
    response->action = request->action;
    /* Note: Keep the target mask consistent across all results. */
    response->targetedMask = KSWORD_ARK_DRIVER_COMMUNICATION_MAJOR_MASK_ALL;

    /* Note: All object directory and FAST_MUTEX operations require PASSIVE_LEVEL. */
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        /* Note: Record non-executable state for R3 display. */
        response->lastStatus = STATUS_INVALID_DEVICE_STATE;
        /* Note: Do not enter any shared state on invalid IRQL. */
        return STATUS_INVALID_DEVICE_STATE;
    }
    /* Note: Control is disallowed if DriverEntry initialization fails or after unloading. */
    if (InterlockedCompareExchange(
        &gKswordArkDriverCommunicationState.initialized,
        0L,
        0L) == 0L) {
        /* Note: In the uninitialized state, explicitly report that the device backend is unavailable. */
        response->lastStatus = STATUS_DEVICE_NOT_READY;
        /* Note: Caller can use this to disable UI actions. */
        return STATUS_DEVICE_NOT_READY;
    }
    /* Note: Protocol version must match the fixed v1 layout exactly. */
    if (request->version != KSWORD_ARK_DRIVER_COMMUNICATION_PROTOCOL_VERSION) {
        /* Note: Do not attempt compatibility guessing for version mismatches. */
        response->lastStatus = STATUS_REVISION_MISMATCH;
        /* Note: Return a stable version mismatch error to the caller. */
        return STATUS_REVISION_MISMATCH;
    }
    /* Note: reserved and unknown flags must be zero. */
    if (request->reserved != 0UL || (request->flags & ~kAllowedFlags) != 0UL) {
        /* Note: Prevent future fields from being misinterpreted by old R0. */
        response->lastStatus = STATUS_INVALID_PARAMETER;
        /* Note: Invalid flags do not enter the object directory. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Note: All three actions use the explicit module base address as the sole identifier. */
    if ((request->flags &
        KSWORD_ARK_DRIVER_COMMUNICATION_FLAG_TARGET_MODULE_BASE_PRESENT) == 0UL ||
        request->targetModuleBase == 0ULL) {
        /* Note: Display name must never replace module base address identity. */
        response->lastStatus = STATUS_INVALID_PARAMETER;
        /* Note: Fail immediately if identity is missing. */
        return STATUS_INVALID_PARAMETER;
    }

    /* Note: Route to independent, auditable state transitions based on the action. */
    switch (request->action) {
    case KSWORD_ARK_DRIVER_COMMUNICATION_ACTION_QUERY:
        /* Note: Query only reads status and is not blocked by dangerous policies. */
        return kswordArkDriverCommunicationQuery(request, response);
    case KSWORD_ARK_DRIVER_COMMUNICATION_ACTION_BLIND:
        /* Note: The handler has completed the safety gate; the backend executes only the transaction. */
        return kswordArkDriverCommunicationBlind(request, response);
    case KSWORD_ARK_DRIVER_COMMUNICATION_ACTION_RESTORE:
        /* Note: Restoration is a risk-reduction action and is not blocked by dangerous policies. */
        return kswordArkDriverCommunicationRestore(request, response);
    default:
        /* Note: Unknown action does not guess execution semantics. */
        response->lastStatus = STATUS_INVALID_PARAMETER;
        /* Note: Return invalid parameter error. */
        return STATUS_INVALID_PARAMETER;
    }
}
