/*++

Module Name:

    hvm_process.c

Abstract:

    R-1 layer process handling. Semantics defined in hvm_process.h and protocol headers.

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL control, VMX root dispatch.

--*/

#include "hvm_process.h"
#include "hvm_ept.h"
#include "hvm_ept_switch.h"
#include "hvm_memory.h"

#include "../../platform/pool_compat.h"

#if defined(_M_AMD64)

/* Hierarchical physical page frame mask. CR3 lower bits contain PCID and flags; these must be masked before comparison. */
#define KSW_HVM_PROCESS_CR3_FRAME_MASK 0x000FFFFFFFFFF000ULL
/* Page-aligned mask. */
#define KSW_HVM_PROCESS_PAGE_MASK 0xFFFFFFFFFFFFF000ULL

/*
 * Refuse to act on these PIDs.
 *
 * 0 is Idle, 4 is System. Freezing or terminating either of these does not constitute
 * 'handling a process'; it halts the machine in VMX root mode in a way that is unrecoverable.
 */
#define KSW_HVM_PROCESS_PID_IDLE 0UL
#define KSW_HVM_PROCESS_PID_SYSTEM 4UL

/* Pool tag and snapshot limit for CR3 attribution. */
#define KSW_HVM_PROCESS_RESOLVE_POOL_TAG 'RvHK'
/* Class number for SystemProcessInformation. */
#define KSW_HVM_PROCESS_INFORMATION_CLASS 5UL
/*
 * Snapshot limit is 16 MiB.
 *
 * On a machine running hundreds of processes, this snapshot is a few hundred KiB; the 16 MiB limit prevents silent
 * failures on machines with an abnormally high number of processes while still enforcing an upper bound. Attribution is an
 * optional convenience feature; it is not entitled to request arbitrary non-paged memory from the kernel just to complete.
 */
#define KSW_HVM_PROCESS_RESOLVE_SNAPSHOT_LIMIT (16UL * 1024UL * 1024UL)

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ ULONG systemInformationClass,
    _Out_writes_bytes_opt_(systemInformationLength) PVOID systemInformation,
    _In_ ULONG systemInformationLength,
    _Out_opt_ PULONG returnLength
    );

/*
 * Prefix of SystemProcessInformation.
 *
 * Declare only up to UniqueProcessId: no subsequent fields are read here. Declaring
 * extra fields introduces offsets that drift across Windows versions. Traversal requires
 * only two things: the offset to the next entry and the identity of the current entry.
 */
typedef struct KswHvmProcessInformationPrefix
{
    ULONG nextEntryOffset;
    ULONG numberOfThreads;
    UCHAR reserved1[48];
    UNICODE_STRING imageName;
    KPRIORITY basePriority;
    HANDLE uniqueProcessId;
} KswHvmProcessInformationPrefix;

/*
 * Take a process snapshot with a bounded retry.
 *
 * The process count may change between two queries, so the length obtained in the first query might already be insufficient. Retry up to
 * four times, increasing the buffer margin each time. If retries are exhausted, fail honestly rather than proceeding with a potentially
 * truncated snapshot. A truncation leads to 'scanned but not found', which yields the same result as 'this address space no longer exists'.
 */
static NTSTATUS
kswordArkHvmProcessCaptureSnapshot(
    _Outptr_result_maybenull_ PVOID* snapshotOut,
    _Out_ ULONG* snapshotBytesOut
    )
{
    ULONG requiredBytes = 0UL;
    ULONG attempt = 0UL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    /* Reject incomplete call contracts. */
    if (snapshotOut == NULL || snapshotBytesOut == NULL) {
        /* Return explicit contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    *snapshotOut = NULL;
    *snapshotBytesOut = 0UL;
    /* ZwQuerySystemInformation can only be called at PASSIVE_LEVEL. */
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        /* Return explicit runtime level failure. */
        return STATUS_INVALID_DEVICE_STATE;
    }
    (void)ZwQuerySystemInformation(
        KSW_HVM_PROCESS_INFORMATION_CLASS,
        NULL,
        0UL,
        &requiredBytes);
    /* Must be large enough to hold at least one record. */
    if (requiredBytes < sizeof(KswHvmProcessInformationPrefix)) {
        requiredBytes = sizeof(KswHvmProcessInformationPrefix);
    }
    for (attempt = 0UL; attempt < 4UL; ++attempt) {
        PVOID snapshot = NULL;
        ULONG allocationBytes = 0UL;
        ULONG returnedBytes = 0UL;

        /* Reserve space for new processes between two queries. */
        if (requiredBytes > KSW_HVM_PROCESS_RESOLVE_SNAPSHOT_LIMIT - 65536UL) {
            /* Return explicit resource limit failure. */
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        allocationBytes = requiredBytes + 65536UL;
        snapshot = kswordArkAllocateNonPagedPool(
            allocationBytes,
            KSW_HVM_PROCESS_RESOLVE_POOL_TAG);
        if (snapshot == NULL) {
            /* Return explicit allocation failure. */
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(snapshot, allocationBytes);
        status = ZwQuerySystemInformation(
            KSW_HVM_PROCESS_INFORMATION_CLASS,
            snapshot,
            allocationBytes,
            &returnedBytes);
        if (NT_SUCCESS(status)) {
            /* Clamp the returned length to the actual allocated range to prevent out-of-bounds traversal. */
            if (returnedBytes == 0UL || returnedBytes > allocationBytes) {
                returnedBytes = allocationBytes;
            }
            *snapshotOut = snapshot;
            *snapshotBytesOut = returnedBytes;
            /* Complete a full snapshot. */
            return STATUS_SUCCESS;
        }
        ExFreePoolWithTag(snapshot, KSW_HVM_PROCESS_RESOLVE_POOL_TAG);
        /* Retry only on "buffer too small"; return other failures as-is. */
        if (status != STATUS_INFO_LENGTH_MISMATCH &&
            status != STATUS_BUFFER_TOO_SMALL) {
            /* Return query self failure. */
            return status;
        }
        requiredBytes = returnedBytes > allocationBytes
            ? returnedBytes
            : allocationBytes;
    }
    /* Retry exhausted; report the last failure status as-is. */
    return status;
}

/*
 * Map an observed CR3 to a PID.
 *
 * There is only one criterion: attach to that process, read back the CR3 actually in use by the processor, and compare it against the given value page-frame by page-frame.
 * Do not read any fields from EPROCESS. Windows does not expose a stable offset for DirectoryTableBase; reading the wrong field
 * does not cause a crash but yields an incorrect value that still allows page table traversal and physical address resolution.
 *
 * ScannedOut is reported separately because 'scanned but not found' and 'failed to scan anything' require opposite actions from the user.
 */
static NTSTATUS
kswordArkHvmProcessResolveDirectoryBase(
    _In_ ULONGLONG directoryBase,
    _Out_ ULONG* processIdOut,
    _Out_ ULONG* scannedOut
    )
{
    PVOID snapshot = NULL;
    ULONG snapshotBytes = 0UL;
    ULONG offset = 0UL;
    ULONG scanned = 0UL;
    ULONGLONG target = directoryBase & KSW_HVM_PROCESS_CR3_FRAME_MASK;
    NTSTATUS status = STATUS_SUCCESS;

    /* Reject incomplete call contracts. */
    if (processIdOut == NULL || scannedOut == NULL) {
        /* Return explicit contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    *processIdOut = 0UL;
    *scannedOut = 0UL;
    /* Zero is not a valid page directory base address for any process; no need to scan it. */
    if (target == 0ULL) {
        /* Return explicit parameter failure. */
        return STATUS_INVALID_PARAMETER;
    }
    status = kswordArkHvmProcessCaptureSnapshot(&snapshot, &snapshotBytes);
    /* If the snapshot cannot be retrieved, fail as expected and keep the scan count at 0. */
    if (!NT_SUCCESS(status)) {
        /* Return failure of the snapshot itself. */
        return status;
    }
    while (offset + sizeof(KswHvmProcessInformationPrefix) <= snapshotBytes) {
        const KswHvmProcessInformationPrefix* entry =
            (const KswHvmProcessInformationPrefix*)
                ((PUCHAR)snapshot + offset);
        ULONG processId = (ULONG)(ULONG_PTR)entry->uniqueProcessId;
        ULONG entryBytes = entry->nextEntryOffset;
        ULONGLONG candidate = 0ULL;

        /* Idle has no attachable address space; skip rather than letting the attach fail. */
        if (processId != KSW_HVM_PROCESS_PID_IDLE) {
            if (NT_SUCCESS(kswordArkHvmMemoryResolveProcessDirectoryBase(
                    processId,
                    &candidate))) {
                ++scanned;
                if ((candidate & KSW_HVM_PROCESS_CR3_FRAME_MASK) == target) {
                    *processIdOut = processId;
                    *scannedOut = scanned;
                    ExFreePoolWithTag(
                        snapshot,
                        KSW_HVM_PROCESS_RESOLVE_POOL_TAG);
                    /* Complete a successful attribution. */
                    return STATUS_SUCCESS;
                }
            }
        }
        /* Offset zero indicates the end of the linked list; not advancing would cause an infinite loop. */
        if (entryBytes == 0UL || entryBytes > snapshotBytes - offset) {
            break;
        }
        offset += entryBytes;
    }
    ExFreePoolWithTag(snapshot, KSW_HVM_PROCESS_RESOLVE_POOL_TAG);
    *scannedOut = scanned;
    /* No match found. This is not an error; it is a definitive answer. */
    return STATUS_NOT_FOUND;
}

/* Find a slot matching the given directory base. Exit path and control path are shared. */
static KswHvmProcessSlot*
kswordArkHvmProcessFindByDirectoryBase(
    _In_ KswHvmRuntime* runtime,
    _In_ ULONGLONG directoryBase
    )
{
    ULONG index = 0UL;

    /* A masked zero value is not a real address space; it does not match. */
    if (directoryBase == 0ULL) {
        /* Return miss. */
        return NULL;
    }
    for (index = 0UL;
         index < KSWORD_ARK_HVM_MAX_PROCESS_DISPOSITIONS;
         ++index) {
        KswHvmProcessSlot* slot =
            &runtime->processDispositions[index];

        /* Compare only hierarchical physical page frames; both sides were masked during write. */
        if (slot->inUse &&
            slot->directoryBase == directoryBase) {
            /* Return the matching entry. */
            return slot;
        }
    }
    /* Return miss. */
    return NULL;
}

/* Find a disposition record by PID. Used for revocation and duplicate detection. */
static KswHvmProcessSlot*
kswordArkHvmProcessFindByProcessId(
    _In_ KswHvmRuntime* runtime,
    _In_ ULONG processId
    )
{
    ULONG index = 0UL;

    for (index = 0UL;
         index < KSWORD_ARK_HVM_MAX_PROCESS_DISPOSITIONS;
         ++index) {
        KswHvmProcessSlot* slot =
            &runtime->processDispositions[index];

        if (slot->inUse && slot->processId == processId) {
            /* Return the matching entry. */
            return slot;
        }
    }
    /* Return miss. */
    return NULL;
}

/* Retrieve an empty slot; return NULL if full. */
static KswHvmProcessSlot*
kswordArkHvmProcessAllocateSlot(
    _In_ KswHvmRuntime* runtime
    )
{
    ULONG index = 0UL;

    for (index = 0UL;
         index < KSWORD_ARK_HVM_MAX_PROCESS_DISPOSITIONS;
         ++index) {
        if (!runtime->processDispositions[index].inUse) {
            /* Return the first available slot. */
            return &runtime->processDispositions[index];
        }
    }
    /* Return capacity exhausted. */
    return NULL;
}

/* Release a slot along with its associated hierarchy. Caller holds the runtime lock. */
static VOID
kswordArkHvmProcessReleaseSlotLocked(
    _Inout_ KswHvmRuntime* runtime,
    _Inout_ KswHvmProcessSlot* slot
    )
{
    /* Release the hierarchy ledger first, then clear the record; reversing this order loses the hierarchy index and leaks a hierarchy set. */
    if (slot->hierarchyIndex != 0UL) {
        kswordArkHvmEptSwitchReleaseLeaf(
            runtime,
            slot->hierarchyIndex);
    }
    RtlZeroMemory(slot, sizeof(*slot));
    /* The count changes only here and at the installation site; both sides hold the lock. */
    if (runtime->processDispositionCount != 0UL) {
        runtime->processDispositionCount -= 1UL;
    }
}

/* Fill protocol row with driver-side records. */
static VOID
kswordArkHvmProcessFillRow(
    _In_ const KswHvmProcessSlot* slot,
    _Out_ KSWORD_ARK_HVM_PROCESS_ROW* row
    )
{
    RtlZeroMemory(row, sizeof(*row));
    row->processId = slot->processId;
    row->disposition = slot->disposition;
    row->directoryBase = slot->directoryBase;
    row->guestPhysicalAddress = slot->guestPhysicalAddress;
    row->guestLinearAddress = slot->guestLinearAddress;
    row->interceptCount = (ULONGLONG)InterlockedCompareExchange64(
        (volatile LONG64*)&slot->interceptCount,
        0LL,
        0LL);
    row->hierarchyIndex = slot->hierarchyIndex;
}

/* Write the entire table into the response. */
static VOID
kswordArkHvmProcessPublishTable(
    _In_ const KswHvmRuntime* runtime,
    _Out_ KSWORD_ARK_HVM_PROCESS_RESPONSE* response
    )
{
    ULONG index = 0UL;

    for (index = 0UL;
         index < KSWORD_ARK_HVM_MAX_PROCESS_DISPOSITIONS;
         ++index) {
        const KswHvmProcessSlot* slot =
            &runtime->processDispositions[index];

        if (!slot->inUse) {
            /* Skip empty slots instead of leaving a row of zeros, otherwise the caller cannot distinguish empty slots from zero counts. */
            continue;
        }
        kswordArkHvmProcessFillRow(
            slot,
            &response->rows[response->returnedRows]);
        response->returnedRows += 1UL;
    }
    response->rowCount = runtime->processDispositionCount;
}

/*
 * Install one disposition. The caller holds the runtime lock and has verified that the resident hypervisor is stopped.
 *
 * The sequence is: calculate the target page, build the hierarchy, and finally publish the record. If any step fails, no
 * intermediate state is left where a record exists in the table but the hierarchy is incomplete. Such an intermediate
 * state would be read as a valid hierarchy index during the exit path, causing a switch to a non-existent hierarchy.
 */
static NTSTATUS
kswordArkHvmProcessArmLocked(
    _Inout_ KswHvmRuntime* runtime,
    _In_ const KSWORD_ARK_HVM_PROCESS_REQUEST* request,
    _Out_ KSWORD_ARK_HVM_PROCESS_RESPONSE* response
    )
{
    KswHvmProcessSlot* slot = NULL;
    KswHvmEptSplit* split = NULL;
    volatile ULONGLONG* entry = NULL;
    ULONGLONG directoryBase = 0ULL;
    ULONGLONG guestPhysical = 0ULL;
    ULONGLONG physicalPage = 0ULL;
    ULONGLONG originalEntry = 0ULL;
    ULONGLONG deniedEntry = 0ULL;
    ULONG hierarchyIndex = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    /* Refuse to operate on Idle and System processes. */
    if (request->processId == KSW_HVM_PROCESS_PID_IDLE ||
        request->processId == KSW_HVM_PROCESS_PID_SYSTEM) {
        response->status =
            KSWORD_ARK_HVM_PROCESS_STATUS_PROTECTED_TARGET;
        /* Return explicit target denial. */
        return STATUS_ACCESS_DENIED;
    }
    /*
     * Reject self-modification attempts.
     *
     * When the action takes effect, injecting #PF or #UD onto the process that initiated
     * this call severs the control path itself—afterward, no one can issue a revocation.
     */
    if (request->processId ==
            (ULONG)(ULONG_PTR)PsGetCurrentProcessId()) {
        response->status =
            KSWORD_ARK_HVM_PROCESS_STATUS_PROTECTED_TARGET;
        /* Return explicit target denial. */
        return STATUS_ACCESS_DENIED;
    }
    /* Scope relies entirely on CR3-load exits; without it, the policy is rejected rather than downgraded to machine-wide enforcement. */
    if ((runtime->crPolicyFlags &
            KSWORD_ARK_HVM_CR_POLICY_FLAG_TRACK_CR3) == 0UL) {
        response->status =
            KSWORD_ARK_HVM_PROCESS_STATUS_CR3_TRACKING_REQUIRED;
        /* Return explicit precondition missing. */
        return STATUS_NOT_SUPPORTED;
    }
    /* No 'restricted' option without a second tier. */
    if (!runtime->eptpSwitchArmed) {
        response->status =
            KSWORD_ARK_HVM_PROCESS_STATUS_EPTP_SWITCH_REQUIRED;
        /* Return explicit precondition missing. */
        return STATUS_NOT_SUPPORTED;
    }
    /* Only one disposition is allowed per process; otherwise, the second one will never be selected due to hierarchy constraints. */
    if (kswordArkHvmProcessFindByProcessId(
            runtime,
            request->processId) != NULL) {
        response->status =
            KSWORD_ARK_HVM_PROCESS_STATUS_ALREADY_ARMED;
        /* Return explicit duplicate installation rejection. */
        return STATUS_OBJECT_NAME_COLLISION;
    }
    /* Allocate a slot; reject before any allocation if the table is full. */
    slot = kswordArkHvmProcessAllocateSlot(runtime);
    if (slot == NULL) {
        response->status = KSWORD_ARK_HVM_PROCESS_STATUS_TABLE_FULL;
        /* Return explicit capacity exhaustion. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* Resolve the actual hierarchical base address used by the target process. */
    status = kswordArkHvmMemoryResolveProcessDirectoryBase(
        request->processId,
        &directoryBase);
    if (!NT_SUCCESS(status)) {
        response->status =
            KSWORD_ARK_HVM_PROCESS_STATUS_PROCESS_LOOKUP_FAILED;
        response->lastStatus = status;
        /* Return explicit process resolution failure. */
        return status;
    }
    /* Retain only hierarchical physical page frames; this form is used for comparisons on the exit path. */
    directoryBase &= KSW_HVM_PROCESS_CR3_FRAME_MASK;
    /*
     * Translate the page whose execution is to be denied to a guest physical address.
     *
     * If the caller provides no linear address, there is no starting point: the driver has no 'cheap' answer like 'the main
     * image entry of this process'. Guessing a page risks rejecting an address that will never be executed—effectively
     * doing nothing while appearing successful from the outside. Therefore, missing this parameter results in rejection.
     */
    if (request->guestLinearAddress == 0ULL) {
        response->status =
            KSWORD_ARK_HVM_PROCESS_STATUS_INVALID_REQUEST;
        /* Return explicit parameter missing. */
        return STATUS_INVALID_PARAMETER;
    }
    status = kswordArkHvmMemoryTranslate(
        directoryBase,
        request->guestLinearAddress,
        &guestPhysical,
        NULL);
    if (!NT_SUCCESS(status)) {
        response->status =
            KSWORD_ARK_HVM_PROCESS_STATUS_TRANSLATION_FAILED;
        response->lastStatus = status;
        /* Return explicit translation failure. */
        return status;
    }
    /* The granularity of the EPT leaf is a page, landing on page boundaries. */
    physicalPage = guestPhysical & KSW_HVM_PROCESS_PAGE_MASK;
    /* Split the 2 MiB leaf covering this page to obtain 4 KiB granularity. */
    status = kswordArkHvmEptEnsureSplitLocked(
        runtime,
        physicalPage,
        &split);
    if (!NT_SUCCESS(status)) {
        response->status =
            KSWORD_ARK_HVM_PROCESS_STATUS_TRANSLATION_FAILED;
        response->lastStatus = status;
        /* Return explicit split failure. */
        return status;
    }
    /* Retrieve the leaf entry for this page in the base; use it as the restricted hierarchy's foundation. */
    entry = kswordArkHvmEptFindLeafEntry(runtime, physicalPage);
    if (entry == NULL) {
        response->status =
            KSWORD_ARK_HVM_PROCESS_STATUS_TRANSLATION_FAILED;
        response->lastStatus = STATUS_NOT_FOUND;
        /* Return explicit leaf lookup failure. */
        return STATUS_NOT_FOUND;
    }
    originalEntry = *entry;
    /*
     * Restricted levels only clear the execute bit; read/write remain unchanged.
     *
     * Preserving read/write is not permissive: a process's code pages are also read by the kernel as data (for
     * paging, image verification, debugging). Denying read access would cause unrelated paths to trigger violations
     * even though they are not in the target address space, giving this mechanism no valid reason to touch them.
     */
    deniedEntry = originalEntry & ~KSW_EPT_EXECUTE;
    /*
     * Construct this custom restricted hierarchy and immediately verify it against the processor's walk table.
     *
     * Verify no tautology: the write path uses the leaf level, while the verification path starts from the root and traverses down through the modified parent nodes.
     * An off-by-one error in the index calculation or a re-pointed parent results in a structurally
     * valid hierarchy that the processor will use without issue, leaving no other symptoms to detect it.
     */
    status = kswordArkHvmEptSwitchBuildLeaf(
        runtime,
        physicalPage,
        originalEntry,
        deniedEntry,
        (const volatile ULONGLONG*)split->pageTable,
        &hierarchyIndex);
    if (NT_SUCCESS(status)) {
        status = kswordArkHvmEptSwitchVerifyLeaf(
            runtime,
            hierarchyIndex);
        /* If validation fails, release the newly created hierarchy to avoid leaving a half-initialized record. */
        if (!NT_SUCCESS(status)) {
            kswordArkHvmEptSwitchReleaseLeaf(
                runtime,
                hierarchyIndex);
        }
    }
    if (!NT_SUCCESS(status)) {
        response->status =
            KSWORD_ARK_HVM_PROCESS_STATUS_EPTP_SWITCH_REQUIRED;
        response->lastStatus = status;
        /* Return explicit hierarchy construction failure. */
        return status;
    }
    /* Publish the record only after all data is ready. */
    slot->processId = request->processId;
    slot->disposition = request->operation;
    slot->hierarchyIndex = hierarchyIndex;
    slot->directoryBase = directoryBase;
    slot->guestPhysicalAddress = physicalPage;
    slot->guestLinearAddress = request->guestLinearAddress;
    slot->interceptCount = 0LL;
    /* InUse is set last: the exit path uses it to determine if this entry is available. */
    slot->inUse = TRUE;
    runtime->processDispositionCount += 1UL;
    response->status = KSWORD_ARK_HVM_PROCESS_STATUS_OK;
    /* Return full installation success. */
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkHvmProcessControlLocked(
    _Inout_ KswHvmRuntime* runtime,
    _In_ const KSWORD_ARK_HVM_PROCESS_REQUEST* request,
    _Out_ KSWORD_ARK_HVM_PROCESS_RESPONSE* response
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    /* Write the complete response identity first; ensure no return path leaves a partial response. */
    RtlZeroMemory(response, sizeof(*response));
    response->version = KSWORD_ARK_HVM_PROCESS_PROTOCOL_VERSION;
    response->size = sizeof(*response);
    response->generation = runtime->generation;
    response->stateFlags = (ULONGLONG)runtime->stateFlags;
    /*
     * Validate complete versioned request contract.
     *
     * directoryBase belongs exclusively to RESOLVE_CR3, which is handled outside this
     * function. Thus, it must be zero here: a non-zero value indicates the caller confused
     * the two operation types. This confusion is silent because the field is never read.
     */
    if (request->version != KSWORD_ARK_HVM_PROCESS_PROTOCOL_VERSION ||
        request->size != sizeof(*request) ||
        request->directoryBase != 0ULL) {
        response->status =
            KSWORD_ARK_HVM_PROCESS_STATUS_INVALID_REQUEST;
        /* Return explicit contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    switch (request->operation) {
    case KSWORD_ARK_HVM_PROCESS_OP_QUERY:
        kswordArkHvmProcessPublishTable(runtime, response);
        response->status = KSWORD_ARK_HVM_PROCESS_STATUS_OK;
        /* Read-only operations end here. */
        break;
    case KSWORD_ARK_HVM_PROCESS_OP_FREEZE:
    case KSWORD_ARK_HVM_PROCESS_OP_TERMINATE:
        status = kswordArkHvmProcessArmLocked(
            runtime,
            request,
            response);
        /* Publish the current table regardless of success or failure, allowing the caller to see the landing point with a single call. */
        kswordArkHvmProcessPublishTable(runtime, response);
        break;
    case KSWORD_ARK_HVM_PROCESS_OP_RELEASE: {
        KswHvmProcessSlot* slot =
            kswordArkHvmProcessFindByProcessId(
                runtime,
                request->processId);

        if (slot == NULL) {
            response->status =
                KSWORD_ARK_HVM_PROCESS_STATUS_NOT_FOUND;
            status = STATUS_NOT_FOUND;
        } else if (InterlockedCompareExchange(
                &runtime->residentProcessorCount,
                0L,
                0L) != 0L) {
            /*
             * Mark only during residency; do not reclaim.
             *
             * The page slot might currently be in use by a core; releasing it now would cause silent memory corruption,
             * while merely clearing the record would cause the spinning core to hang indefinitely. After marking: cores
             * that haven't entered yet will no longer select it, and cores stuck in the spin loop will switch back to
             * the base upon their next violation. Actual reclamation is deferred to the resident Reset upon stop.
             */
            slot->disposition =
                KSWORD_ARK_HVM_PROCESS_DISPOSITION_RELEASED;
            response->status = KSWORD_ARK_HVM_PROCESS_STATUS_OK;
        } else {
            kswordArkHvmProcessReleaseSlotLocked(runtime, slot);
            response->status = KSWORD_ARK_HVM_PROCESS_STATUS_OK;
        }
        kswordArkHvmProcessPublishTable(runtime, response);
        break;
    }
    case KSWORD_ARK_HVM_PROCESS_OP_RELEASE_ALL:
        if (InterlockedCompareExchange(
                &runtime->residentProcessorCount,
                0L,
                0L) != 0L) {
            ULONG index = 0UL;

            /* Mark entries one by one during residency; the rationale is identical to that of a single entry revocation. */
            for (index = 0UL;
                 index < KSWORD_ARK_HVM_MAX_PROCESS_DISPOSITIONS;
                 ++index) {
                KswHvmProcessSlot* slot =
                    &runtime->processDispositions[index];

                if (slot->inUse) {
                    slot->disposition =
                        KSWORD_ARK_HVM_PROCESS_DISPOSITION_RELEASED;
                }
            }
        } else {
            kswordArkHvmProcessResetLocked(runtime);
        }
        response->status = KSWORD_ARK_HVM_PROCESS_STATUS_OK;
        kswordArkHvmProcessPublishTable(runtime, response);
        break;
    default:
        response->status =
            KSWORD_ARK_HVM_PROCESS_STATUS_INVALID_REQUEST;
        status = STATUS_INVALID_PARAMETER;
        break;
    }
    /* Report the final table size and generation. */
    response->generation = runtime->generation;
    /* Return the full operation result. */
    return status;
}

NTSTATUS
kswordArkHvmProcessControl(
    _In_ const KSWORD_ARK_HVM_PROCESS_REQUEST* request,
    _Out_ KSWORD_ARK_HVM_PROCESS_RESPONSE* response
    )
{
    KswHvmRuntime* runtime = kswordArkHvmGetRuntime();
    BOOLEAN mutating = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    /* Reject incomplete call contracts before acquiring the lock. */
    if (request == NULL || response == NULL || runtime == NULL) {
        /* Return explicit contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /*
     * CR3 attribution occurs outside the lock and before the Initialized check.
     *
     * Two reasons, neither is an optimization. It touches not a single byte of HVM state. Putting it in a critical
     * section means holding the lock shared with the exit path for the entire duration of an attach traversal involving
     * hundreds of processes. Moreover, 'must prepare before attributing' gets the logic backwards: the moment most
     * needing attribution is precisely when the resident process has stopped and the user is viewing hit records.
     */
    if (request->operation == KSWORD_ARK_HVM_PROCESS_OP_RESOLVE_CR3) {
        ULONG resolvedProcessId = 0UL;
        ULONG scanned = 0UL;

        RtlZeroMemory(response, sizeof(*response));
        response->version = KSWORD_ARK_HVM_PROCESS_PROTOCOL_VERSION;
        response->size = sizeof(*response);
        /*
         * This path bypasses ControlLocked, so version and field contracts must be validated here independently.
         * The bypassed branch produces no symptoms—it still returns a correctly formatted response.
         */
        if (request->version != KSWORD_ARK_HVM_PROCESS_PROTOCOL_VERSION ||
            request->size != sizeof(*request) ||
            request->processId != 0UL ||
            request->guestLinearAddress != 0ULL) {
            response->status =
                KSWORD_ARK_HVM_PROCESS_STATUS_INVALID_REQUEST;
            response->lastStatus = STATUS_INVALID_PARAMETER;
            /* Protocol layer success, semantic layer rejection. */
            return STATUS_SUCCESS;
        }
        status = kswordArkHvmProcessResolveDirectoryBase(
            request->directoryBase,
            &resolvedProcessId,
            &scanned);
        response->resolvedProcessId = resolvedProcessId;
        response->resolvedScannedProcesses = scanned;
        response->lastStatus = status;
        if (NT_SUCCESS(status)) {
            response->status = KSWORD_ARK_HVM_PROCESS_STATUS_OK;
        } else if (status == STATUS_NOT_FOUND) {
            /* Scanned but no match found. 'scanned' is the evidence for this. */
            response->status = KSWORD_ARK_HVM_PROCESS_STATUS_NOT_FOUND;
        } else if (status == STATUS_INVALID_PARAMETER) {
            response->status = KSWORD_ARK_HVM_PROCESS_STATUS_INVALID_REQUEST;
        } else {
            /* Failed to retrieve the snapshot. Keep scanned at 0 to distinguish this case. */
            response->status =
                KSWORD_ARK_HVM_PROCESS_STATUS_PROCESS_LOOKUP_FAILED;
        }
        /* The protocol layer always succeeds; the semantic result resides entirely in the status and the two counters. */
        return STATUS_SUCCESS;
    }
    /*
     * Only **installation** requires the resident hypervisor to be stopped.
     *
     * Installation involves paging, leaf creation, and hierarchy construction; those are read-only operations that do not hold locks on the exit path. Reversion does not touch these.
     * During its lifetime, it modifies only one field in an existing record, marking it as 'not selected;
     * switch back to base upon encounter'. By also blocking rollback, it enforces that 'unfreezing
     * requires shutting down the entire hypervisor'—otherwise, freezing is only half a feature.
     */
    mutating =
        request->operation == KSWORD_ARK_HVM_PROCESS_OP_FREEZE ||
        request->operation == KSWORD_ARK_HVM_PROCESS_OP_TERMINATE;
    /* Serialized with other lifecycle and EPT operations. */
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&runtime->lock);
    if (!runtime->initialized) {
        RtlZeroMemory(response, sizeof(*response));
        response->version = KSWORD_ARK_HVM_PROCESS_PROTOCOL_VERSION;
        response->size = sizeof(*response);
        response->status =
            KSWORD_ARK_HVM_PROCESS_STATUS_NOT_PREPARED;
        response->lastStatus = STATUS_DEVICE_NOT_READY;
        /* Protocol layer success, semantic layer rejection. */
        status = STATUS_SUCCESS;
    } else if (mutating &&
        InterlockedCompareExchange(
            &runtime->residentProcessorCount,
            0L,
            0L) != 0L) {
        /*
         * While resident, the exit path reads this table and its hierarchy without
         * holding the PASSIVE_LEVEL lock. Neither may change until every VCPU has
         * returned to the guest stack. This is the same rule used for EPT rules and split
         * views, for the same reason: readers of these tables cannot wait for a lock.
         */
        RtlZeroMemory(response, sizeof(*response));
        response->version = KSWORD_ARK_HVM_PROCESS_PROTOCOL_VERSION;
        response->size = sizeof(*response);
        response->status =
            KSWORD_ARK_HVM_PROCESS_STATUS_REQUIRES_RESIDENT_STOPPED;
        response->lastStatus = STATUS_DEVICE_BUSY;
        /* No record or hierarchy was modified. */
        status = STATUS_SUCCESS;
    } else {
        status = kswordArkHvmProcessControlLocked(
            runtime,
            request,
            response);
    }
    ExReleasePushLockExclusive(&runtime->lock);
    KeLeaveCriticalRegion();
    /* Return the full operation result. */
    return status;
}

BOOLEAN
kswordArkHvmProcessSelectHierarchy(
    _In_ const KswHvmRuntime* runtime,
    _In_ ULONGLONG guestCr3,
    _Out_ ULONGLONG* targetEptp
    )
{
    ULONGLONG frame = guestCr3 & KSW_HVM_PROCESS_CR3_FRAME_MASK;
    ULONG index = 0UL;

    /* Reject incomplete call contracts; do not accept partial results on the exit path. */
    if (runtime == NULL || targetEptp == NULL) {
        /* Return miss. */
        return FALSE;
    }
    *targetEptp = 0ULL;
    /* Return immediately if the table is empty, avoiding a scan during every address space switch while resident. */
    if (runtime->processDispositionCount == 0UL) {
        /* Return miss. */
        return FALSE;
    }
    for (index = 0UL;
         index < KSWORD_ARK_HVM_MAX_PROCESS_DISPOSITIONS;
         ++index) {
        const KswHvmProcessSlot* slot =
            &runtime->processDispositions[index];

        if (!slot->inUse ||
            slot->disposition ==
                KSWORD_ARK_HVM_PROCESS_DISPOSITION_RELEASED ||
            slot->directoryBase != frame ||
            slot->hierarchyIndex == 0UL ||
            slot->hierarchyIndex >
                (KSWORD_ARK_HVM_MAX_VIEWS + 1UL)) {
            /* Skip empty slots, address spaces that do not match, and out-of-bounds hierarchy indices. */
            continue;
        }
        /* Treat a missing hierarchy as a miss: switching to 0 is equivalent to switching to a non-existent hierarchy. */
        if (runtime->eptSwitch.eptp[slot->hierarchyIndex] == 0ULL) {
            /* Skip unconstructed hierarchies. */
            continue;
        }
        *targetEptp =
            runtime->eptSwitch.eptp[slot->hierarchyIndex];
        /* Return the matched restricted layer. */
        return TRUE;
    }
    /* Return miss. */
    return FALSE;
}

KswHvmProcessAction
kswordArkHvmProcessHandleViolation(
    _Inout_ KswHvmRuntime* runtime,
    _In_ ULONGLONG guestPhysicalAddress,
    _In_ ULONG access
    )
{
    ULONGLONG page = guestPhysicalAddress & KSW_HVM_PROCESS_PAGE_MASK;
    ULONG index = 0UL;

    /* Reject incomplete call contracts. */
    if (runtime == NULL) {
        /* Return if not managed by this module. */
        return kKswHvmProcessActionNone;
    }
    /*
     * Recognize only instruction violations.
     *
     * The restricted level only removes the execute bit, so read/write operations behave exactly like the base
     * level under this hierarchy and will not generate violations. If a read/write violation does occur, it is the
     * responsibility of other mechanisms (rules, views); claiming it here would only consume their handling logic.
     */
    if ((access & KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE) == 0UL) {
        /* Return if not managed by this module. */
        return kKswHvmProcessActionNone;
    }
    if (runtime->processDispositionCount == 0UL) {
        /* Return if not managed by this module. */
        return kKswHvmProcessActionNone;
    }
    for (index = 0UL;
         index < KSWORD_ARK_HVM_MAX_PROCESS_DISPOSITIONS;
         ++index) {
        KswHvmProcessSlot* slot =
            &runtime->processDispositions[index];

        if (!slot->inUse ||
            slot->guestPhysicalAddress != page) {
            /* Skip empty slots and records not belonging to this page. */
            continue;
        }
        /*
         * Records that have been released are no longer intercepted: switch this core back to the base and continue in place.
         *
         * This entry must precede the count. Continuing to accumulate interception counts after release causes the sole external
         * reading for 'has it been released?' to keep increasing, making it appear identical to not having been released.
         */
        if (slot->disposition ==
                KSWORD_ARK_HVM_PROCESS_DISPOSITION_RELEASED) {
            /* Return resume action. */
            return kKswHvmProcessActionResume;
        }
        /* Record one interception. If this count keeps rising, it is evidence of spinning. */
        InterlockedIncrement64(&slot->interceptCount);
        if (slot->disposition ==
                KSWORD_ARK_HVM_PROCESS_OP_TERMINATE) {
            /* Return terminate action. */
            return kKswHvmProcessActionTerminate;
        }
        /* Return freeze action. */
        return kKswHvmProcessActionFreeze;
    }
    /* Return if not managed by this module. */
    return kKswHvmProcessActionNone;
}

VOID
kswordArkHvmProcessResetLocked(
    _Inout_ KswHvmRuntime* runtime
    )
{
    ULONG index = 0UL;

    /* Tolerate a null runtime so that every failure path and teardown path need not add extra guards. */
    if (runtime == NULL) {
        /* Nothing to do. */
        return;
    }
    for (index = 0UL;
         index < KSWORD_ARK_HVM_MAX_PROCESS_DISPOSITIONS;
         ++index) {
        KswHvmProcessSlot* slot =
            &runtime->processDispositions[index];

        if (slot->inUse) {
            kswordArkHvmProcessReleaseSlotLocked(runtime, slot);
        }
    }
    /* Reset count to zero; items are released one by one as their counts reach zero; this line just ensures consistency. */
    runtime->processDispositionCount = 0UL;
}

#endif /* _M_AMD64 */
