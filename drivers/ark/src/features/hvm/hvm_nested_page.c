/* Transactional control of a single composed-EPT page override. */
#include "hvm_nested_ept.h"
#include "hvm_resident.h"
#include "hvm_metrics.h"
#include "hvm_event.h"
#include "../../platform/pool_compat.h"

#if defined(_M_AMD64)
/* Use one tag for the allocation and every rejection/reclamation path. */
#define KSW_HVM_PAGE_POOL_TAG 'PvHK'
/* Permit only page-aligned architectural physical addresses. */
#define KSW_HVM_PAGE_FRAME_MASK 0x000FFFFFFFFFF000ULL
/* Operation ids survive resource teardown and reset only at driver load. */
static volatile LONG gPageOperationSequence;
/* Serialize process-object publication against the process-exit callback. */
static KSPIN_LOCK gPageOwnerLock;
/* Unregistration drains callbacks before driver resources are released. */
static BOOLEAN gPageOwnerNotifyRegistered;
/* This documented process identity is independent of private EPROCESS offsets. */
NTSYSAPI LONGLONG NTAPI PsGetProcessCreateTimeQuadPart(_In_ PEPROCESS process);
/* ntddk does not declare the documented ntifs process lookup export. */
NTSYSAPI NTSTATUS NTAPI PsLookupProcessByProcessId(_In_ HANDLE processId, _Outptr_ PEPROCESS* process);

static VOID kswordArkHvmPageRevoke(KswHvmRuntime* runtime, ULONG reason)
{
    /* Only the first observer changes this lease's policy generation. */
    if (InterlockedCompareExchange(&runtime->nestedPageRevocationReason,
            (LONG)reason, (LONG)KSWORD_ARK_HVM_PAGE_LEASE_VALID) == 0L) {
        /* Future entries must discard translations composed under the old policy. */
        InterlockedIncrement((volatile LONG*)&runtime->nestedPageGeneration);
    }
}

static int kswordArkHvmPageReadSource(void* context, KswLeaseU64 address,
    KswLeaseU64* value)
{
    MM_COPY_ADDRESS source;
    SIZE_T copied = 0U;
    NTSTATUS status;
    /* Admission runs below APC_LEVEL; no mapping-manager call occurs in VMX root. */
    UNREFERENCED_PARAMETER(context);
    /* Only ordinary physical RAM is accepted by this checked kernel copy. */
    source.PhysicalAddress.QuadPart = (LONGLONG)address;
    /* Reject a partial read rather than interpreting uninitialized entry bits. */
    status = MmCopyMemory(value, source, sizeof(*value), MM_COPY_MEMORY_PHYSICAL, &copied);
    /* Both status and copied length must establish a complete source word. */
    return NT_SUCCESS(status) && copied == sizeof(*value);
}

static int kswordArkHvmPageReadSourceRoot(void* context, KswLeaseU64 address,
    KswLeaseU64* value)
{
    /* The per-CPU window performs no allocation or operating-system memory call. */
    return NT_SUCCESS(kswordArkHvmPhysWindowReadQword(
        (KswHvmPhysWindow*)context, address, value));
}

BOOLEAN kswordArkHvmNestedPageValidateTranslation(KswHvmRuntime* runtime,
    KswHvmPhysWindow* window, ULONGLONG eptPointer)
{
    KswHvmNestedPage* page;
    int result;
    /* The all-CPU retirement barrier pins any pointer a root reader observes. */
    page = (KswHvmNestedPage*)ReadPointerAcquire((PVOID volatile*)&runtime->nestedPage);
    /* Unrelated roots need no page-policy work. */
    if (page == NULL || page->ept12Pointer != eptPointer) { return TRUE; }
    /* Revocation is sticky until an explicit drain and a new map operation. */
    if (ReadAcquire(&runtime->nestedPageRevocationReason) != 0L) { return FALSE; }
    /* Compare all captured path entries, never just a recycled root pointer. */
    result = kswordHvmLeaseValidate(&page->translation, kswordArkHvmPageReadSourceRoot, window);
    /* A mismatch and an inaccessible source are separately observable rejections. */
    if (result != 1) {
        /* Retain backing; this callback is not a global invalidation acknowledgement. */
        kswordArkHvmPageRevoke(runtime, result == 0 ?
            KSWORD_ARK_HVM_PAGE_LEASE_TRANSLATION_CHANGED : KSWORD_ARK_HVM_PAGE_LEASE_SOURCE_UNREADABLE);
    }
    /* Re-read after validation to notice another CPU's simultaneous revocation. */
    return ReadAcquire(&runtime->nestedPageRevocationReason) == 0L;
}

/*
 * Recheck one page of a scan-admitted region, from the exit path.
 *
 * Admission by scanning reads all 512 source leaves once and admits on their
 * agreement. That agreement is not stable: the intermediate VMM rewrites its
 * per-page permissions while the guest runs, and a region admitted at one moment
 * has been measured to disagree a few seconds later. Rechecking all 512 at every
 * composition is not affordable - compositions run on the order of 1e5 per
 * second - so one page is checked per call and the cursor advances, which covers
 * the region in as many calls as it has pages.
 *
 * The consequence is stated rather than hidden: detection is eventual, so a
 * region can serve for a bounded interval after its condition stops holding.
 * That is still the difference between a condition nobody rechecks and one that
 * expires; a lease that is never rechecked cannot expire at all.
 */
VOID kswordArkHvmNestedPageSampleRegion(KswHvmRuntime* runtime,
    KswHvmPhysWindow* window)
{
    KswHvmNestedPage* page;
    LONG cursor;

    page = (KswHvmNestedPage*)ReadPointerAcquire(
        (PVOID volatile*)&runtime->nestedPage);
    /* Nothing to recheck for an absent, ordinary, or already revoked lease. */
    if (page == NULL || !page->scanAdmitted ||
        ReadAcquire(&runtime->nestedPageRevocationReason) != 0L) {
        return;
    }
    /* One page per sample, from a cursor the planner folds into the region. */
    cursor = InterlockedIncrement(&page->scanCursor) - 1L;
    /*
     * The decision lives in the planner, beside the scan whose conclusion it
     * rechecks, so the two cannot disagree about which bits matter and so it
     * can be tested without a machine. An unreadable entry is not a proven
     * change: UNKNOWN leaves the lease alone and lets the ordinary path report
     * an unreadable source if it sees one.
     */
    if (kswordHvmLeafPlanRecheckPage(page->ept12Pointer, &page->plan,
            (KswPlanU64)(ULONG)cursor, page->scanSharedBits,
            kswordArkHvmPageReadSourceRoot, window) ==
        KSW_PLAN_RECHECK_DRIFTED) {
        kswordArkHvmPageRevoke(runtime,
            KSWORD_ARK_HVM_PAGE_LEASE_REGION_DRIFTED);
    }
}

static VOID kswordArkHvmPageOwnerNotify(PEPROCESS process, HANDLE processId,
    PPS_CREATE_NOTIFY_INFO createInfo)
{
    KswHvmRuntime* runtime = kswordArkHvmGetRuntime();
    KIRQL oldIrql;
    /* Only object identity is needed; PID reuse cannot revive an expired lease. */
    UNREFERENCED_PARAMETER(processId);
    /* Process creation cannot invalidate an existing owner's mapping. */
    if (createInfo != NULL) { return; }
    /* Match and revoke in one bounded critical section; never wait for VM exits here. */
    KeAcquireSpinLock(&gPageOwnerLock, &oldIrql);
    /* A rule remains referenced until explicit all-CPU reclamation completes. */
    if (runtime->nestedPageOwner == process && runtime->nestedPageOwnerExited == 0L) {
        /* Stop new compositions from using the replacement. */
        InterlockedExchange(&runtime->nestedPageOwnerExited, 1L);
        /* Expire both process and translation policy without freeing backing. */
        kswordArkHvmPageRevoke(runtime, KSWORD_ARK_HVM_PAGE_LEASE_OWNER_EXITED);
    }
    /* Release before returning to process teardown. */
    KeReleaseSpinLock(&gPageOwnerLock, oldIrql);
}

NTSTATUS kswordArkHvmNestedPageGuardInitialize(VOID)
{
    NTSTATUS status;
    /* initialize once before any page rule can be published. */
    KeInitializeSpinLock(&gPageOwnerLock);
    /* Use a documented notification, without patching or injecting into the VMM. */
    status = PsSetCreateProcessNotifyRoutineEx(kswordArkHvmPageOwnerNotify, FALSE);
    /* Record only a registration the OS actually accepted. */
    gPageOwnerNotifyRegistered = NT_SUCCESS(status);
    /* Resident admission is denied if its owner-lifetime guard is unavailable. */
    return status;
}

VOID kswordArkHvmNestedPageGuardShutdown(VOID)
{
    /* Failed initialization has no callback to remove. */
    if (gPageOwnerNotifyRegistered) {
        /* The OS waits for in-flight callbacks before this routine returns. */
        (void)PsSetCreateProcessNotifyRoutineEx(kswordArkHvmPageOwnerNotify, TRUE);
        /* Prevent a second unregistration on a partial-start cleanup path. */
        gPageOwnerNotifyRegistered = FALSE;
    }
}

static NTSTATUS kswordArkHvmPageBindOwner(KswHvmRuntime* runtime,
    KswHvmNestedPage* page, const KSWORD_ARK_HVM_NESTED_PAGE_REQUEST* request)
{
    PEPROCESS process = NULL;
    KIRQL oldIrql;
    NTSTATUS status;
    /* A caller must identify a live owner; an EPT address is not a lifetime. */
    if (request->ownerProcessId <= 4UL || request->ownerCreationTime == 0ULL) { return STATUS_INVALID_PARAMETER; }
    /* Take the reference before exposing its pointer to the exit callback. */
    status = PsLookupProcessByProcessId(ULongToHandle(request->ownerProcessId), &process);
    /* Failed lookup owns no reference. */
    if (!NT_SUCCESS(status)) { return status; }
    /* A reused PID must never be mistaken for the selected VMM. */
    if ((ULONGLONG)PsGetProcessCreateTimeQuadPart(process) != request->ownerCreationTime) {
        /* Release the unadmitted process reference. */
        ObDereferenceObject(process);
        /* Distinguish identity drift from a resource failure. */
        return STATUS_REVISION_MISMATCH;
    }
    /* The page record owns this reference even if subsequent admission fails. */
    page->ownerProcess = process;
    /* Retain exactly the identity validated above. */
    page->ownerCreationTime = request->ownerCreationTime;
    /* Close the callback/publication race before checking termination status. */
    KeAcquireSpinLock(&gPageOwnerLock, &oldIrql);
    /* A previous retired rule must already have been drained before mapping again. */
    runtime->nestedPageOwnerExited = 0L;
    /* A prior lease must have been drained before a new owner can be published. */
    runtime->nestedPageRevocationReason = 0L;
    /* Publish the referenced object, not only its recyclable numeric PID. */
    runtime->nestedPageOwner = process;
    /* Process exit after publication now marks the rule expired. */
    KeReleaseSpinLock(&gPageOwnerLock, oldIrql);
    /* Exit before publication is caught here; exit after this check hits the callback. */
    return PsGetProcessExitStatus(process) == STATUS_PENDING ? STATUS_SUCCESS : STATUS_PROCESS_IS_TERMINATING;
}

/* Fixed local metadata remains valid after its backing allocation is freed. */
typedef struct KswHvmPageTrace {
    ULONG id, operation, flags;
    ULONGLONG eptPointer, guestPage, backingPage;
} KswHvmPageTrace;

static VOID kswordArkHvmPageTrace(const KswHvmPageTrace* trace, ULONG stage, NTSTATUS status)
{
    /* Retain the existing event ABI and give its new type explicit semantics. */
    KSWORD_ARK_HVM_EVENT_ROW row = { 0 };
    PROCESSOR_NUMBER processor;
    /* Queries do not advance the transaction trace or generate events. */
    if (trace->id == 0UL) { return; }
    /* Record the control caller, not a claim of per-CPU invalidation timing. */
    (void)KeGetCurrentProcessorNumberEx(&processor);
    /* Select the separately decoded page transaction event type. */
    row.type = KSWORD_ARK_HVM_EVENT_TYPE_NESTED_PAGE;
    /* Distinguish this transaction from older events in the same ring. */
    row.ruleId = trace->id;
    /* Stage and operation occupy fields otherwise used for VM-exit metadata. */
    row.exitReason = stage;
    /* Preserve map/remove identity, including fault-injection requests. */
    row.access = trace->operation;
    /* Keep the exact explicit fault mode in the trace. */
    row.qualification = trace->flags;
    /* Record the target descendant GPA. */
    row.guestPhysicalAddress = trace->guestPage;
    /* For this event type, this field is the EPT12 root, not a linear address. */
    row.guestLinearAddress = trace->eptPointer;
    /* For this event type, this field is backing PA, not an instruction pointer. */
    row.guestRip = trace->backingPage;
    /* Record the complete operation result at this boundary. */
    row.status = status;
    /* Preserve the observing processor group. */
    row.processorGroup = processor.Group;
    /* Preserve the observing processor number. */
    row.processorNumber = processor.Number;
    /* The event publisher stamps QPC and reports ring overwrite/drop counts. */
    kswordArkHvmEventPublish(&row);
}

/*
 * FNV-1a over a region, read one page at a time.
 *
 * Page at a time because the source is physical memory we do not own: a single
 * unreadable page then names itself instead of failing a 2 MiB copy with no
 * indication of where. A page that cannot be read makes the whole digest
 * unavailable rather than silently contributing zeroes, since a digest that
 * quietly skips part of the region would compare equal to one that did not.
 */
static BOOLEAN kswordArkHvmPageDigestPhysical(ULONGLONG base, ULONGLONG bytes,
    ULONGLONG* digest)
{
    ULONGLONG hash = 0xCBF29CE484222325ULL;
    ULONGLONG offset;
    /* A page-sized staging buffer, from the pool rather than the kernel stack:
       4 KiB is a large fraction of one, and this runs under the runtime lock
       where an overflow would be a bugcheck rather than a failed request. */
    UCHAR* page = (UCHAR*)kswordArkAllocateNonPagedPool(PAGE_SIZE,
        KSW_HVM_PAGE_POOL_TAG);

    *digest = 0ULL;
    if (page == NULL) { return FALSE; }
    for (offset = 0ULL; offset < bytes; offset += PAGE_SIZE) {
        MM_COPY_ADDRESS source;
        SIZE_T copied = 0U;
        ULONG index;

        source.PhysicalAddress.QuadPart = (LONGLONG)(base + offset);
        if (!NT_SUCCESS(MmCopyMemory(page, source, PAGE_SIZE,
                MM_COPY_MEMORY_PHYSICAL, &copied)) || copied != PAGE_SIZE) {
            ExFreePoolWithTag(page, KSW_HVM_PAGE_POOL_TAG);
            return FALSE;
        }
        for (index = 0UL; index < PAGE_SIZE; ++index) {
            hash = (hash ^ (ULONGLONG)page[index]) * 0x100000001B3ULL;
        }
    }
    ExFreePoolWithTag(page, KSW_HVM_PAGE_POOL_TAG);
    *digest = hash;
    return TRUE;
}

static VOID kswordArkHvmNestedPageFree(KswHvmNestedPage* page)
{
    /* Failed allocation and empty removal both permit an empty record. */
    if (page == NULL) { return; }
    /* Owner references remain pinned for the same lifetime as replacement backing. */
    if (page->ownerProcess != NULL) {
        KswHvmRuntime* runtime = kswordArkHvmGetRuntime();
        KIRQL oldIrql;
        /* Unpublish the object before releasing its final rule reference. */
        KeAcquireSpinLock(&gPageOwnerLock, &oldIrql);
        /* A single slot cannot replace another live lease. */
        if (runtime->nestedPageOwner == page->ownerProcess) { runtime->nestedPageOwner = NULL; }
        /* Finish the callback barrier before invoking the object manager. */
        KeReleaseSpinLock(&gPageOwnerLock, oldIrql);
        /* No owner identity is dereferenced from VMX root. */
        ObDereferenceObject(page->ownerProcess);
    }
    /* Backing may be absent after an allocation failure. */
    if (page->shadowVirtual != NULL) {
        /* Caller has either never published it or drained all possible readers. */
        MmFreeContiguousMemory(page->shadowVirtual);
        /* Count actual frees independently of mapping-slot occupancy. */
        kswordArkHvmMetricsAllocation(TRUE, TRUE);
    }
    /* Pair the rule's exact tagged allocation. */
    ExFreePoolWithTag(page, KSW_HVM_PAGE_POOL_TAG);
    /* Keep failed preparations visible in the object ledger. */
    kswordArkHvmMetricsAllocation(FALSE, TRUE);
}

VOID kswordArkHvmNestedPageResetLocked(KswHvmRuntime* runtime)
{
    /* VMXOFF on every CPU is required for teardown without another rendezvous. */
    if (runtime->residentProcessorCount != 0L) { return; }
    /* Resource teardown owns the runtime lock and cannot race a publication. */
    kswordArkHvmNestedPageFree((KswHvmNestedPage*)InterlockedExchangePointer(
        (PVOID volatile*)&runtime->nestedPage, NULL));
    /* Reclaim a retained page only after the stopped lifecycle is proven. */
    kswordArkHvmNestedPageFree(runtime->nestedPageRetired);
    /* Publish the empty retention slot. */
    runtime->nestedPageRetired = NULL;
    /* Invalidate stale generation-bound user requests. */
    InterlockedIncrement((volatile LONG*)&runtime->nestedPageGeneration);
}

static NTSTATUS kswordArkHvmPageRetire(KswHvmRuntime* runtime,
    KswHvmPageTrace* trace, BOOLEAN failFlush)
{
    NTSTATUS status;
    KswHvmNestedPage* page;
    BOOLEAN unpublished = FALSE;
    /* A failed earlier attempt is retried without losing its pinned backing. */
    if (runtime->nestedPageRetired == NULL) {
        /* Stop new root readers from discovering the override. */
        runtime->nestedPageRetired = (KswHvmNestedPage*)InterlockedExchangePointer(
            (PVOID volatile*)&runtime->nestedPage, NULL);
        /* The logical mapping changes even if subsequent invalidation fails. */
        InterlockedIncrement((volatile LONG*)&runtime->nestedPageGeneration);
        /* Delay the event until its retained allocation identity is available. */
        unpublished = TRUE;
    }
    /* Copy identities before any possible free. */
    page = runtime->nestedPageRetired;
    /* Empty removes still validate the invalidation path. */
    if (page != NULL) {
        /* Preserve the actual retained allocation's EPT identity on retries. */
        trace->eptPointer = page->ept12Pointer;
        /* Preserve its target GPA for removal requests without an address. */
        trace->guestPage = page->guestPhysicalPage;
        /* Preserve its backing PA beyond reclamation. */
        trace->backingPage = page->shadowPhysicalPage;
    }
    /* Unpublication is distinct from successful hardware invalidation. */
    if (unpublished) { kswordArkHvmPageTrace(trace, KSW_HVM_PAGE_UNPUBLISHED, STATUS_SUCCESS); }
    /* Bound the all-CPU drain independently of the user-mode command. */
    kswordArkHvmPageTrace(trace, KSW_HVM_PAGE_ROLLBACK_BEGIN, STATUS_SUCCESS);
    /* Fault injection omits this drain; it never reports an unexecuted INVEPT. */
    status = failFlush ? STATUS_HV_OPERATION_FAILED : kswordArkHvmResidentInvalidateEpt(runtime->eptPointer);
    /* A failed drain leaves all possibly referenced allocations pinned. */
    kswordArkHvmPageTrace(trace, KSW_HVM_PAGE_ROLLBACK_END, status);
    /* Reclamation is permitted only after every participant acknowledged. */
    if (NT_SUCCESS(status) && page != NULL) {
        /* Both the object and backing are now unreachable by resident readers. */
        kswordArkHvmNestedPageFree(page);
        /* Publish successful retirement after actual reclamation. */
        runtime->nestedPageRetired = NULL;
        /* timestamp after free, retaining identities in the local trace. */
        kswordArkHvmPageTrace(trace, KSW_HVM_PAGE_RECLAIMED, STATUS_SUCCESS);
    }
    /* Return actual drain status; slot occupancy alone is not success. */
    return status;
}

NTSTATUS kswordArkHvmNestedPageControl(const KSWORD_ARK_HVM_NESTED_PAGE_REQUEST* request,
    KSWORD_ARK_HVM_NESTED_PAGE_RESPONSE* response)
{
    KswHvmRuntime* runtime = kswordArkHvmGetRuntime();
    KswHvmNestedPage* page;
    KswHvmPageTrace trace = { 0 };
    NTSTATUS status = STATUS_SUCCESS;
    ULONG index, fault;
    /* Set only when the caller asked for the scan and it proved uniformity. */
    int sourceUniform = 0;
    /* Validate fixed input/output pointers before any state access. */
    if (request == NULL || response == NULL || runtime == NULL) { return STATUS_INVALID_PARAMETER; }
    /* Clear every response field, including inactive-page identities. */
    RtlZeroMemory(response, sizeof(*response));
    /* Preserve the existing wire layout and version. */
    response->version = KSWORD_ARK_HVM_NESTED_PAGE_VERSION;
    /* Report the exact compatible fixed buffer length. */
    response->size = sizeof(*response);
    /* Prevent asynchronous kernel APCs while owning the push lock. */
    KeEnterCriticalRegion();
    /* Serialize publication, retirement, lifecycle changes, and retries. */
    ExAcquirePushLockExclusive(&runtime->lock);
    /* enumerate roots under the same control serialization. */
    kswordArkHvmResidentNestedRoots(response);
    /* Decode a request-local fault; no global fault switch remains armed. */
    fault = (request->flags & KSWORD_ARK_HVM_NESTED_PAGE_FAULT_MASK) >> KSWORD_ARK_HVM_NESTED_PAGE_FAULT_SHIFT;
    /* Reject unknown versions, reserved bits and unsupported fault combinations. */
    if (request->version != KSWORD_ARK_HVM_NESTED_PAGE_VERSION ||
        request->size != sizeof(*request) ||
        request->operation > KSWORD_ARK_HVM_NESTED_PAGE_STAGE ||
        /* Granularity is meaningful only when creating the region. */
        (request->operation != KSWORD_ARK_HVM_NESTED_PAGE_MAP &&
         request->leafShift != 0UL) ||
        /* A page index is meaningful only when staging one page of it. */
        (request->operation != KSWORD_ARK_HVM_NESTED_PAGE_STAGE &&
         request->stagePageIndex != 0UL) ||
        /* Staging edits published backing; it takes no lab fault injection. */
        (request->operation == KSWORD_ARK_HVM_NESTED_PAGE_STAGE && fault != 0UL) ||
        (request->flags & ~(KSWORD_ARK_HVM_NESTED_PAGE_CONFIRMED |
                            KSWORD_ARK_HVM_NESTED_PAGE_SCAN_SOURCE |
                            KSWORD_ARK_HVM_NESTED_PAGE_DIGEST |
                            KSWORD_ARK_HVM_NESTED_PAGE_FAULT_MASK)) != 0UL ||
        /* Scanning the source only means anything while creating a region. */
        ((request->flags & KSWORD_ARK_HVM_NESTED_PAGE_SCAN_SOURCE) != 0UL &&
         request->operation != KSWORD_ARK_HVM_NESTED_PAGE_MAP) ||
        fault > KSWORD_ARK_HVM_NESTED_PAGE_FAULT_REMOVE_FLUSH ||
        (fault != 0UL && ((request->operation == KSWORD_ARK_HVM_NESTED_PAGE_QUERY) ||
         (request->operation == KSWORD_ARK_HVM_NESTED_PAGE_MAP && fault == KSWORD_ARK_HVM_NESTED_PAGE_FAULT_REMOVE_FLUSH) ||
         (request->operation == KSWORD_ARK_HVM_NESTED_PAGE_REMOVE && fault != KSWORD_ARK_HVM_NESTED_PAGE_FAULT_REMOVE_FLUSH)))) {
        /* Return a semantic rejection without changing mappings or generations. */
        status = STATUS_INVALID_PARAMETER;
        /* Fill the complete query-compatible response below. */
        goto complete;
    }
    /* A query never emits operation events or mutates the page policy. */
    if (request->operation == KSWORD_ARK_HVM_NESTED_PAGE_QUERY) { goto complete; }
    /* Preserve explicit confirmation on every mutation, including lab faults. */
    if (request->confirmationToken != KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN ||
        (request->flags & KSWORD_ARK_HVM_NESTED_PAGE_CONFIRMED) == 0UL) {
        /* Deny a request that lacks the existing write contract. */
        status = STATUS_ACCESS_DENIED;
        /* No allocation or publication has occurred. */
        goto complete;
    }
    /* Allocate a durable correlation id for an authorized operation. */
    trace.id = (ULONG)InterlockedIncrement(&gPageOperationSequence);
    /* Preserve the requested operation. */
    trace.operation = request->operation;
    /* Preserve confirmation and fault flags for attribution. */
    trace.flags = request->flags;
    /* Preserve the requested root. */
    trace.eptPointer = request->ept12Pointer;
    /* Preserve the requested descendant physical page. */
    trace.guestPage = request->guestPhysicalPage;
    /* timestamp the start before lifecycle and generation validation. */
    kswordArkHvmPageTrace(&trace, KSW_HVM_PAGE_BEGIN, STATUS_SUCCESS);
    /* Reject overlap with an incomplete lifecycle operation. */
    if (!runtime->initialized || runtime->busy) { status = STATUS_DEVICE_BUSY; goto complete; }
    /* Do not mutate a runtime whose CPU ownership is already uncertain. */
    if ((runtime->stateFlags & (KSWORD_ARK_HVM_STATE_FAULTED | KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED)) != 0UL) {
        /* Keep any outstanding backing pinned for stopped resource teardown. */
        status = STATUS_INVALID_DEVICE_STATE;
        /* Report the fault without starting another rendezvous. */
        goto complete;
    }
    /* Stale requests cannot remove or replace another transaction's mapping. */
    if (request->expectedGeneration != runtime->nestedPageGeneration) { status = STATUS_REVISION_MISMATCH; goto complete; }
    /* Removal and retry share the same drain-before-free implementation. */
    if (request->operation == KSWORD_ARK_HVM_NESTED_PAGE_REMOVE) {
        /* Only the explicit removal test is permitted to omit this drain. */
        status = kswordArkHvmPageRetire(runtime, &trace, fault == KSWORD_ARK_HVM_NESTED_PAGE_FAULT_REMOVE_FLUSH);
        /* Return active/retired occupancy as observed after the attempt. */
        goto complete;
    }
    /*
     * Overwrite one 4-KiB page of the live region's replacement backing.
     *
     * This edits memory the descendant may be reading right now. It is not an
     * atomic page update and is not presented as one: a reader concurrent with
     * the copy can observe a mix of old and new bytes, exactly as the manuscript
     * states for the override path generally. What it does guarantee is that no
     * write lands outside the published region, because the index is resolved
     * through the same plan the composition path uses.
     */
    if (request->operation == KSWORD_ARK_HVM_NESTED_PAGE_STAGE) {
        KswHvmNestedPage* const kLive = runtime->nestedPage;

        /* Staging has nothing to edit before a region is published. */
        if (kLive == NULL) { status = STATUS_NOT_FOUND; goto complete; }
        /* A revoked lease must not accept further edits to retained backing. */
        if (ReadAcquire(&runtime->nestedPageRevocationReason) != 0L) {
            status = STATUS_INVALID_DEVICE_STATE;
            goto complete;
        }
        /* Refuse an index the plan does not own rather than clamping it. */
        if (kswordHvmLeafPlanPageFrame(&kLive->plan,
                (KswPlanU64)request->stagePageIndex) == 0ULL) {
            status = STATUS_INVALID_PARAMETER;
            goto complete;
        }
        /* Backing is one contiguous block, so the index is a direct offset. */
        RtlCopyMemory((PUCHAR)kLive->shadowVirtual +
                ((SIZE_T)request->stagePageIndex * (SIZE_T)PAGE_SIZE),
            request->shadow, PAGE_SIZE);
        /* Count applied edits for evidence; the region itself is unchanged. */
        (void)InterlockedIncrement64(&kLive->stagedPageCount);
        /* No mapping, generation or CPU state changed, so no drain is owed. */
        goto complete;
    }
    /* A map needs a running nested monitor and exclusive ownership of the slot. */
    if (runtime->residentProcessorCount == 0L || runtime->nestedPage != NULL || runtime->nestedPageRetired != NULL) {
        /* Never overwrite an allocation that may remain visible in a CPU cache. */
        status = STATUS_DEVICE_BUSY;
        /* Keep the existing mapping intact. */
        goto complete;
    }
    /* Reject alignment errors and addresses wider than the architectural field. */
    if ((request->guestPhysicalPage & ~KSW_HVM_PAGE_FRAME_MASK) != 0ULL) { status = STATUS_INVALID_PARAMETER; goto complete; }
    /* Require a root actually observed by the resident nested runtime. */
    for (index = 0UL; index < response->rootCount; ++index) {
        /* Exact EPTP matching preserves its translation configuration bits. */
        if (response->ept12Roots[index] == request->ept12Pointer) { break; }
    }
    /* Unknown roots never allocate replacement memory. */
    if (index == response->rootCount) { status = STATUS_NOT_FOUND; goto complete; }
    /* timestamp before either allocation. */
    kswordArkHvmPageTrace(&trace, KSW_HVM_PAGE_ALLOCATE_BEGIN, STATUS_SUCCESS);
    /* Allocate the rule independently of its contiguous backing. */
    page = (KswHvmNestedPage*)kswordArkAllocateNonPagedPool(sizeof(*page), KSW_HVM_PAGE_POOL_TAG);
    /* An object allocation failure never publishes a partial record. */
    if (page == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto complete; }
    /* Count actual object allocation. */
    kswordArkHvmMetricsAllocation(FALSE, FALSE);
    /* initialize the optional backing before any cleanup can inspect it. */
    RtlZeroMemory(page, sizeof(*page));
    /* Capture a specific ordinary-RAM translation before allocating its replacement. */
    if (!kswordHvmLeaseCapture(request->ept12Pointer, request->guestPhysicalPage,
            kswordArkHvmPageReadSource, NULL, &page->translation) ||
        kswordHvmLeaseValidate(&page->translation, kswordArkHvmPageReadSource, NULL) != 1) {
        /* Failed or already changed captures cannot create a live mapping. */
        kswordArkHvmNestedPageFree(page);
        /* Preserve a precise admission failure independent of allocation injection. */
        status = STATUS_INVALID_ADDRESS;
        /* Return without changing the published page policy. */
        goto complete;
    }
    /*
     * Decide the region before allocating it, using the planner's own rules.
     *
     * The probe passes a synthetic backing address chosen to satisfy every
     * backing test, so this call answers exactly one question: is the requested
     * granularity admissible for this guest address and this source path?
     * Duplicating those rules here to avoid the synthetic argument would give
     * two places that must agree about what a legal region is.
     */
    {
        const ULONG kRequestedShift = (request->leafShift != 0UL)
            ? request->leafShift : KSWORD_ARK_HVM_NESTED_PAGE_SHIFT_4K;
        KswHvmLeafPlan probe;

        /*
         * Read the source only when the caller asked for that rule.
         *
         * The scan is what lets a region be published over a source that maps it
         * one page at a time, and it costs a weaker lease; see the flag's
         * definition. Running it unasked would hand that trade to callers who
         * never chose it, so an unset flag leaves sourceUniform zero and the
         * coarse-source rule decides alone.
         */
        if ((request->flags & KSWORD_ARK_HVM_NESTED_PAGE_SCAN_SOURCE) != 0UL) {
            KswHvmLeafSourceScan scan;

            if (kswordHvmLeafPlanScanSource(request->ept12Pointer,
                    request->guestPhysicalPage, kRequestedShift,
                    kswordArkHvmPageReadSource, NULL, &scan)) {
                sourceUniform = (scan.uniform != 0 && scan.complete != 0) ? 1 : 0;
                response->scannedLeafCount = scan.leafCount;
                response->scannedSharedBits = scan.sharedBits;
            }
        }
        if (!kswordHvmLeafPlanCreate(kRequestedShift, request->guestPhysicalPage,
                page->translation.entryCount, sourceUniform,
                (KswPlanU64)1ULL << kRequestedShift,
                (KswPlanU64)1ULL << kRequestedShift, &probe)) {
            /* Reclaim the never-published rule. */
            kswordArkHvmNestedPageFree(page);
            /*
             * Name the refusal rather than reporting one generic error.
             *
             * A caller that asked for 2 MiB over 512 separately mapped source
             * pages and one that mis-aligned its address have to be told apart:
             * the first is a property of the descendant's own tables and will
             * not change by retrying, the second is the caller's bug.
             */
            status = (probe.refusal == KSW_PLAN_REFUSE_SOURCE_GRANULARITY ||
                      probe.refusal == KSW_PLAN_REFUSE_SOURCE_UNKNOWN)
                ? STATUS_NOT_SUPPORTED : STATUS_INVALID_PARAMETER;
            /* Publish the refused geometry so the caller can read why. */
            response->leafShift = kRequestedShift;
            response->sourceLeafShift =
                kswordHvmLeafSourceShift(page->translation.entryCount);
            goto complete;
        }
        page->backingBytes = probe.regionBytes;
    }
    /* Allocation injection deliberately exercises cleanup of the allocated object. */
    if (fault != KSWORD_ARK_HVM_NESTED_PAGE_FAULT_ALLOCATE) {
        PHYSICAL_ADDRESS low = { 0 }, high, boundary = { 0 };
        /* Accept any allocatable backing PA supported by the current system. */
        high.QuadPart = MAXLONGLONG;
        /*
         * Force the block onto its own granularity by forbidding it to cross one.
         *
         * A leaf carries a single frame and hardware ignores the address bits
         * below its granularity, so an unaligned 2-MiB block would be read as
         * its own aligned base and serve the wrong bytes with no error anywhere.
         * A request of exactly N bytes that may not cross an N-aligned boundary
         * can only start on one. Left at zero for an ordinary page, which is
         * inherently aligned, so the single-page path is unchanged.
         */
        if (page->backingBytes > PAGE_SIZE) {
            boundary.QuadPart = (LONGLONG)page->backingBytes;
        }
        /* Allocate ordinary WB RAM for the whole replacement region. */
        page->shadowVirtual = MmAllocateContiguousMemorySpecifyCache(
            (SIZE_T)page->backingBytes, low, high, boundary, MmCached);
    }
    /* An absent backing takes the same cleanup branch as a real allocation failure. */
    if (page->shadowVirtual == NULL) {
        /* Reclaim the never-published rule. */
        kswordArkHvmNestedPageFree(page);
        /* Preserve an allocation-specific error. */
        status = STATUS_INSUFFICIENT_RESOURCES;
        /* Record the failure boundary without inventing an allocated page. */
        kswordArkHvmPageTrace(&trace, KSW_HVM_PAGE_ALLOCATE_END, status);
        /* Return with generations and active mappings unchanged. */
        goto complete;
    }
    /* Account for backing as soon as allocation succeeds. */
    kswordArkHvmMetricsAllocation(TRUE, FALSE);
    /*
     * initialize all content before root readers can discover it.
     *
     * The two granularities mean different things and are initialized
     * differently. A 4-KiB override replaces one page outright, so it takes the
     * caller's inline page and that path is byte-for-byte what it was. A region
     * is a clone: every page including the first is copied from the source, so
     * publishing it changes nothing the descendant can observe, and STAGE then
     * changes the parts that should differ. The inline page is ignored there,
     * because a region that started as one repeated page, or as zeroes, would
     * be an immediate whole-region corruption - the opposite of a control
     * primitive you can arm first and fire later.
     */
    {
        /* The capture folds the guest offset in, and the request is aligned to
           the region, so this is already the region's source base. */
        const ULONGLONG kSourceBase = page->translation.sourcePage;
        const ULONGLONG kFirstCopied =
            (page->backingBytes > PAGE_SIZE) ? 0ULL : PAGE_SIZE;
        ULONGLONG offset;

        if (kFirstCopied != 0ULL) {
            RtlCopyMemory(page->shadowVirtual, request->shadow, PAGE_SIZE);
        }
        for (offset = kFirstCopied; offset < page->backingBytes; offset += PAGE_SIZE) {
            MM_COPY_ADDRESS source;
            SIZE_T copied = 0U;

            source.PhysicalAddress.QuadPart = (LONGLONG)(kSourceBase + offset);
            /* Copy one page at a time so an unreadable page names itself. */
            if (!NT_SUCCESS(MmCopyMemory((PUCHAR)page->shadowVirtual + offset,
                    source, PAGE_SIZE, MM_COPY_MEMORY_PHYSICAL, &copied)) ||
                copied != PAGE_SIZE) {
                /* Never publish a region holding uninitialized bytes. */
                kswordArkHvmNestedPageFree(page);
                status = STATUS_INVALID_ADDRESS;
                kswordArkHvmPageTrace(&trace, KSW_HVM_PAGE_ALLOCATE_END, status);
                goto complete;
            }
        }
    }
    /* Bind lifetime before publication; cleanup also releases failed admission. */
    status = kswordArkHvmPageBindOwner(runtime, page, request);
    /* A dead or reused owner must not leave any allocated replacement behind. */
    if (!NT_SUCCESS(status)) { kswordArkHvmNestedPageFree(page); goto complete; }
    /* Resolve the actual backing PA for EPT and evidence. */
    page->shadowPhysicalPage = (ULONGLONG)MmGetPhysicalAddress(page->shadowVirtual).QuadPart;
    /*
     * Build the published plan from the address actually allocated.
     *
     * The probe above proved the geometry was admissible; this proves the
     * allocator honoured it. The boundary argument is a request, not a
     * guarantee, and an unaligned block would otherwise be published as a leaf
     * that serves the wrong bytes without failing anywhere. A refusal here is a
     * clean rejection, not a downgrade to a smaller leaf.
     */
    if (!kswordHvmLeafPlanCreate(
            (request->leafShift != 0UL) ? request->leafShift
                                        : KSWORD_ARK_HVM_NESTED_PAGE_SHIFT_4K,
            request->guestPhysicalPage, page->translation.entryCount,
            sourceUniform, page->shadowPhysicalPage, page->backingBytes,
            &page->plan)) {
        /* Reclaim backing whose address the plan cannot accept. */
        kswordArkHvmNestedPageFree(page);
        status = STATUS_INSUFFICIENT_RESOURCES;
        kswordArkHvmPageTrace(&trace, KSW_HVM_PAGE_ALLOCATE_END, status);
        goto complete;
    }
    /*
     * Keep the scan's conclusion so the sampler can recheck it.
     *
     * Only for regions the scan admitted: one whose source leaf already covered
     * the region cannot disagree with itself, and its single captured path is
     * already revalidated at every composition.
     */
    page->scanAdmitted = (page->plan.leafShift > KSW_PLAN_SHIFT_4K &&
        kswordHvmLeafSourceShift(page->translation.entryCount) <
            page->plan.leafShift) ? TRUE : FALSE;
    page->scanSharedBits = response->scannedSharedBits;
    page->scanCursor = 0L;
    /* Store the root identity used by the composition path. */
    page->ept12Pointer = request->ept12Pointer;
    /* Store the target page used by the composition path. */
    page->guestPhysicalPage = request->guestPhysicalPage;
    /* Retain backing identity independently of object lifetime. */
    trace.backingPage = page->shadowPhysicalPage;
    /* Close allocation and initialization timing. */
    kswordArkHvmPageTrace(&trace, KSW_HVM_PAGE_ALLOCATE_END, STATUS_SUCCESS);
    /* Cancellation before publication requires no remote invalidation. */
    if (fault == KSWORD_ARK_HVM_NESTED_PAGE_FAULT_CANCEL) {
        /* Reclaim both allocations while no CPU can reference the rule. */
        kswordArkHvmNestedPageFree(page);
        /* Record completed reclamation with the retained backing identity. */
        kswordArkHvmPageTrace(&trace, KSW_HVM_PAGE_RECLAIMED, STATUS_SUCCESS);
        /* Distinguish a requested cancellation from normal mapping success. */
        status = STATUS_CANCELLED;
        /* Preserve the original generation. */
        goto complete;
    }
    /* Publish only a fully initialized rule with one release-ordered pointer swap. */
    (void)InterlockedExchangePointer((PVOID volatile*)&runtime->nestedPage, page);
    /* Invalidate stale control requests once publication occurs. */
    InterlockedIncrement((volatile LONG*)&runtime->nestedPageGeneration);
    /* Record publication separately from eventual cache coherence. */
    kswordArkHvmPageTrace(&trace, KSW_HVM_PAGE_PUBLISHED, STATUS_SUCCESS);
    /* Bound the commit invalidation operation. */
    kswordArkHvmPageTrace(&trace, KSW_HVM_PAGE_FLUSH_BEGIN, STATUS_SUCCESS);
    /* Simulate a failed call boundary without reporting an actual INVEPT failure. */
    status = fault == KSWORD_ARK_HVM_NESTED_PAGE_FAULT_COMMIT_FLUSH ?
        STATUS_HV_OPERATION_FAILED : kswordArkHvmResidentInvalidateEpt(runtime->eptPointer);
    /* Record real or explicitly injected commit status. */
    kswordArkHvmPageTrace(&trace, KSW_HVM_PAGE_FLUSH_END, status);
    /* Post-commit cancellation follows successful publication and invalidation. */
    if (NT_SUCCESS(status) && fault == KSWORD_ARK_HVM_NESTED_PAGE_FAULT_ROLLBACK) { status = STATUS_CANCELLED; }
    /* Owner exit during commit is a failed transaction, not a successful mapping. */
    if (NT_SUCCESS(status) && ReadAcquire(&runtime->nestedPageOwnerExited) != 0L) { status = STATUS_PROCESS_IS_TERMINATING; }
    /* Source drift observed during commit is not a successful page transaction. */
    if (NT_SUCCESS(status) && ReadAcquire(&runtime->nestedPageRevocationReason) != 0L) { status = STATUS_REVISION_MISMATCH; }
    /* A failed commit must withdraw the override instead of silently leaving it active. */
    if (!NT_SUCCESS(status)) {
        /* Keep the original error; failed rollback remains visible as retired backing. */
        (void)kswordArkHvmPageRetire(runtime, &trace, FALSE);
    }
complete:
    /* A query reports the newest id; an operation reports its own correlation id. */
    response->operationId = trace.id != 0UL ? trace.id : (ULONG)InterlockedCompareExchange(&gPageOperationSequence, 0L, 0L);
    /* Retained memory is reported even when logical publication has ended. */
    page = runtime->nestedPage != NULL ? runtime->nestedPage : runtime->nestedPageRetired;
    /* Keep semantic operation failures independent from IOCTL transport success. */
    response->status = NT_SUCCESS(status) ? 0UL : 1UL;
    /* Preserve the precise original operation status. */
    response->lastStatus = (ULONG)status;
    /* Return the current control generation. */
    response->generation = runtime->nestedPageGeneration;
    /* Report logical mapping occupancy. */
    response->active = runtime->nestedPage != NULL && ReadAcquire(&runtime->nestedPageRevocationReason) == 0L;
    /* Report potentially referenced, unreclaimed backing. */
    response->retired = runtime->nestedPageRetired != NULL || (runtime->nestedPage != NULL && ReadAcquire(&runtime->nestedPageRevocationReason) != 0L);
    /* Preserve resident participant count for the caller's preconditions. */
    response->residentProcessors = (ULONG)runtime->residentProcessorCount;
    /* Only dereference an allocation still owned by the runtime. */
    if (page != NULL) {
        /* Report the stable owner and the reason backing may still be retained. */
        response->ownerProcessId = HandleToULong(PsGetProcessId(page->ownerProcess));
        /* Preserve the process creation identity for both live and expired leases. */
        response->ownerCreationTime = page->ownerCreationTime;
        /* This flag does not claim that retained backing has already been freed. */
        response->ownerExited = ReadAcquire(&runtime->nestedPageOwnerExited) != 0L;
        /* Report the first reason this translation lease ceased to authorize remapping. */
        response->leaseRevocationReason = (ULONG)ReadAcquire(&runtime->nestedPageRevocationReason);
        /* Preserve admission-time source identity after automatic revocation. */
        response->sourcePhysicalPage = page->translation.sourcePage;
        /* Expose only the bounded captured path for machine-readable evidence. */
        response->sourceEntryCount = page->translation.entryCount;
        /* The arrays are immutable from publication until reclamation. */
        RtlCopyMemory(response->sourceEntryAddress, page->translation.entryAddress, sizeof(response->sourceEntryAddress));
        /* Keep normalized values alongside their exact physical entry addresses. */
        RtlCopyMemory(response->sourceEntryValue, page->translation.entryValue, sizeof(response->sourceEntryValue));
        /* Return its exact translation identity. */
        response->ept12Pointer = page->ept12Pointer;
        /* Return its exact descendant page. */
        response->guestPhysicalPage = page->guestPhysicalPage;
        /* Return its replacement backing. */
        response->shadowPhysicalPage = page->shadowPhysicalPage;
        /* Sample the original backing discovered during composition. */
        response->originalPhysicalPage = (ULONGLONG)InterlockedCompareExchange64(&page->originalPhysicalPage, 0LL, 0LL);
        /* Sample actual composition hits independently. */
        response->composedCount = (ULONGLONG)InterlockedCompareExchange64(&page->composedCount, 0LL, 0LL);
        /* Report the granularity actually published and the region it owns. */
        response->leafShift = page->plan.leafShift;
        response->regionBytes = page->plan.regionBytes;
        response->regionPageCount = page->plan.pageCount;
        /* Report what limited that granularity, so a refusal reads without a walk. */
        response->sourceLeafShift =
            kswordHvmLeafSourceShift(page->translation.entryCount);
        /* A published region whose source is finer was admitted by scanning. */
        response->admittedByScan =
            (page->plan.leafShift > KSW_PLAN_SHIFT_4K &&
             kswordHvmLeafSourceShift(page->translation.entryCount) <
                 page->plan.leafShift) ? 1UL : 0UL;
        /*
         * Digests are computed only on request: each one reads the whole region.
         * Both sides or neither, so that "equal" is never an artefact of one
         * side having been skipped.
         */
        if ((request->flags & KSWORD_ARK_HVM_NESTED_PAGE_DIGEST) != 0UL &&
            page->plan.refusal == KSW_PLAN_OK && page->shadowVirtual != NULL) {
            ULONGLONG sourceDigest = 0ULL, backingDigest = 0ULL;

            if (kswordArkHvmPageDigestPhysical(page->translation.sourcePage,
                    page->backingBytes, &sourceDigest) &&
                kswordArkHvmPageDigestPhysical(page->shadowPhysicalPage,
                    page->backingBytes, &backingDigest)) {
                response->sourceDigest = sourceDigest;
                response->backingDigest = backingDigest;
                response->digestBytes = page->backingBytes;
            }
        }
        /* Report applied staged edits; publication alone leaves this zero. */
        response->stagedPageCount =
            (ULONGLONG)InterlockedCompareExchange64(&page->stagedPageCount, 0LL, 0LL);
    }
    /* Finish the correlated trace before releasing the control lock. */
    kswordArkHvmPageTrace(&trace, KSW_HVM_PAGE_END, status);
    /* Release mutation serialization. */
    ExReleasePushLockExclusive(&runtime->lock);
    /* Restore normal kernel APC delivery. */
    KeLeaveCriticalRegion();
    /* A complete semantic response was produced even when the request failed. */
    return STATUS_SUCCESS;
}
#else
/* HVM has no resident implementation on other architectures. */
NTSTATUS KswordARKHvmNestedPageGuardInitialize(VOID) { return STATUS_NOT_SUPPORTED; }
/* No notification was registered on an unsupported architecture. */
VOID KswordARKHvmNestedPageGuardShutdown(VOID) { }
#endif
