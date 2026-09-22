/*++

Module Name:

    thread_apc.c

Abstract:

    Manage the lifecycle of Kernel APCs used to terminate system threads, canceling and draining them before driver unloading.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "../../platform/pool_compat.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text (PAGE, kswordArkThreadApcUninitialize)
#endif

#define KSWORD_ARK_THREAD_APC_POOL_TAG 'pAsK'
#define KSWORD_ARK_APC_ENVIRONMENT_ORIGINAL 0L

typedef VOID(NTAPI* KswordApcNormalRoutine)(
    _In_opt_ PVOID normalContext,
    _In_opt_ PVOID systemArgument1,
    _In_opt_ PVOID systemArgument2
    );

typedef VOID(NTAPI* KswordApcKernelRoutine)(
    _In_ PKAPC apc,
    _Inout_ KswordApcNormalRoutine* normalRoutine,
    _Inout_ PVOID* normalContext,
    _Inout_ PVOID* systemArgument1,
    _Inout_ PVOID* systemArgument2
    );

typedef VOID(NTAPI* KswordApcRundownRoutine)(
    _In_ PKAPC apc
    );

typedef VOID(NTAPI* KswordKeInitializeApcFn)(
    _Out_ PKAPC apc,
    _In_ PKTHREAD thread,
    _In_ LONG environment,
    _In_ KswordApcKernelRoutine kernelRoutine,
    _In_opt_ KswordApcRundownRoutine rundownRoutine,
    _In_opt_ KswordApcNormalRoutine normalRoutine,
    _In_ KPROCESSOR_MODE apcMode,
    _In_opt_ PVOID normalContext
    );

typedef BOOLEAN(NTAPI* KswordKeInsertQueueApcFn)(
    _Inout_ PKAPC apc,
    _In_opt_ PVOID systemArgument1,
    _In_opt_ PVOID systemArgument2,
    _In_ KPRIORITY increment
    );

typedef BOOLEAN(NTAPI* KswordKeRemoveQueueApcFn)(
    _Inout_ PKAPC apc
    );

typedef struct KswordArkThreadTerminateApcContext
{
    LIST_ENTRY registryLink;
    KAPC specialApc;
    KAPC normalApc;
    WORK_QUEUE_ITEM reaperWorkItem;
    KEVENT normalRoutineCompletedEvent;
    PETHREAD threadObject;
    KswordKeInitializeApcFn keInitializeApc;
    KswordKeInsertQueueApcFn keInsertQueueApc;
    KswordKeRemoveQueueApcFn keRemoveQueueApc;
    PVOID volatile activeApc;
    volatile LONG referenceCount;
    volatile LONG registered;
    volatile LONG released;
    volatile LONG cancelVisited;
} KswordArkThreadTerminateApcContext;

// Registry spinlock protects the APC context list, count, and stop-receiving flag.
static KSPIN_LOCK gKswordArkThreadApcRegistryLock;
// The registry list stores all APC contexts that may callback to this driver image.
static LIST_ENTRY gKswordArkThreadApcRegistry;
// The drain event remains signaled when the registry is empty; the unload path waits for all callbacks to exit based on this.
static KEVENT gKswordArkThreadApcDrainEvent;
// Unfinished context count is read/written only under the registry spinlock.
static ULONG gKswordArkThreadApcOutstandingCount = 0UL;
// The stop flag prevents new APCs from being queued after unloading begins.
static volatile LONG gKswordArkThreadApcStopping = 1L;

static KswordKeInitializeApcFn
kswordArkResolveKeInitializeApc(
    VOID
    )
/*++

Routine Description:

    Parse KeInitializeApc to avoid direct dependency on import declarations across different WDK versions.

Arguments:

    None.

Return Value:

    Returns the function address on success; returns NULL if unavailable.

--*/
{
    UNICODE_STRING routineName;

    // initialize the query string using the public system routine name.
    RtlInitUnicodeString(&routineName, L"KeInitializeApc");
    // Returns the address of the kernel-exported routine; the caller is responsible for checking for NULL.
    return (KswordKeInitializeApcFn)MmGetSystemRoutineAddress(&routineName);
}

static KswordKeInsertQueueApcFn
kswordArkResolveKeInsertQueueApc(
    VOID
    )
/*++

Routine Description:

    Parses KeInsertQueueApc for use by queueing functions protected by registry.

Arguments:

    None.

Return Value:

    Returns the function address on success; returns NULL if unavailable.

--*/
{
    UNICODE_STRING routineName;

    // initialize the query string using the public system routine name.
    RtlInitUnicodeString(&routineName, L"KeInsertQueueApc");
    // Returns the address of the kernel-exported routine; the caller is responsible for checking for NULL.
    return (KswordKeInsertQueueApcFn)MmGetSystemRoutineAddress(&routineName);
}

static KswordKeRemoveQueueApcFn
kswordArkResolveKeRemoveQueueApc(
    VOID
    )
/*++

Routine Description:

    Parse KeRemoveQueueApc; use it to cancel pending APCs during the unload path.

Arguments:

    None.

Return Value:

    Returns the function address on success; returns NULL if unavailable.

--*/
{
    UNICODE_STRING routineName;

    // initialize the system routine query string using the publicly exported name.
    RtlInitUnicodeString(&routineName, L"KeRemoveQueueApc");
    // Returns the address of the kernel-exported APC routine; must verify availability before creating the context.
    return (KswordKeRemoveQueueApcFn)MmGetSystemRoutineAddress(&routineName);
}

static VOID
kswordArkReferenceThreadTerminateApcContext(
    _In_ KswordArkThreadTerminateApcContext* context
    )
/*++

Routine Description:

    Temporarily increment the APC context reference count for the unload cancellation path.

Arguments:

    Context - APC context to keep alive.

Return Value:

    No return value.

--*/
{
    // Caller references the context only while the registry lock protects it being in the list.
    (VOID)InterlockedIncrement(&context->referenceCount);
}

static VOID
kswordArkDereferenceThreadTerminateApcContext(
    _In_ KswordArkThreadTerminateApcContext* context
    )
/*++

Routine Description:

    Release the APC context reference and free non-paged memory when the last reference is released.

Arguments:

    Context - APC context to release the reference from.

Return Value:

    No return value.

--*/
{
    // Only the last reference is responsible for freeing the context to prevent double-free due to concurrent cancellation and callbacks.
    if (InterlockedDecrement(&context->referenceCount) == 0L) {
        // The context comes from a non-paged pool with a fixed tag and must be freed using the same tag.
        ExFreePoolWithTag(context, KSWORD_ARK_THREAD_APC_POOL_TAG);
    }
}

static BOOLEAN
kswordArkRegisterThreadTerminateApcContext(
    _Inout_ KswordArkThreadTerminateApcContext* context
    )
/*++

Routine Description:

    Add APC context to global registry while stop flag is still off.

Arguments:

    Context: APC context that has completed basic initialization but is not yet queued.

Return Value:

    Returns TRUE on successful registration; returns FALSE if the driver is unloading.

--*/
{
    KIRQL oldIrql = PASSIVE_LEVEL;
    BOOLEAN registered = FALSE;

    // Acquire the global spin lock to make the stop flag check and list insertion an atomic transaction.
    KeAcquireSpinLock(&gKswordArkThreadApcRegistryLock, &oldIrql);
    // Registration allowed only if unloading has not started and the context is not released.
    if (gKswordArkThreadApcStopping == 0L &&
        context->released == 0L) {
        // Clear the drain event on the first context entry to prevent premature unloading completion.
        if (gKswordArkThreadApcOutstandingCount == 0UL) {
            KeClearEvent(&gKswordArkThreadApcDrainEvent);
        }
        // The list holds the initial reference to the context until the unified release function removes the node.
        InsertTailList(&gKswordArkThreadApcRegistry, &context->registryLink);
        // Mark the node as registered; the release function performs a symmetric removal based on this.
        context->registered = 1L;
        // Record the total number of contexts that may currently callback to the driver image.
        ++gKswordArkThreadApcOutstandingCount;
        // Return value confirms to the caller that initialization and APC queuing can proceed.
        registered = TRUE;
    }
    // Release the registry lock and restore the caller's original IRQL.
    KeReleaseSpinLock(&gKswordArkThreadApcRegistryLock, oldIrql);
    // Returns the final result of the atomic registration operation.
    return registered;
}

static VOID
kswordArkClearActiveThreadTerminateApc(
    _Inout_ KswordArkThreadTerminateApcContext* context,
    _In_ PKAPC apc
    )
/*++

Routine Description:

    Clear the active pointer only if the given APC is still the currently queued instance.

Arguments:

    Context - Context belonging to the APC.
    Apc - APC currently executing, being rundown, or cancelled.

Return Value:

    No return value.

--*/
{
    // Compare-exchange prevents old-stage callbacks from erroneously clearing the new APC after the Special-to-Normal transition.
    (VOID)InterlockedCompareExchangePointer(
        &context->activeApc,
        NULL,
        apc);
}

static VOID
kswordArkReleaseThreadTerminateApcContext(
    _In_opt_ KswordArkThreadTerminateApcContext* context
    )
/*++

Routine Description:

    Remove APC context from the global registry, release the thread reference, and decrement the base reference count.

Arguments:

    Context - Registered APC context, which may be NULL.

Return Value:

    No return value.

--*/
{
    KIRQL oldIrql = PASSIVE_LEVEL;
    PETHREAD threadObject = NULL;

    // Context is not processed again if it is NULL or already released by another concurrent path.
    if (context == NULL ||
        InterlockedCompareExchange(&context->released, 1L, 0L) != 0L) {
        return;
    }

    // Acquire the registry lock to ensure consistency between list removal, counter updates, and the emptying event setup.
    KeAcquireSpinLock(&gKswordArkThreadApcRegistryLock, &oldIrql);
    // Only successfully registered contexts possess list nodes and base registration references.
    if (context->registered != 0L) {
        // Remove the node from the global list so it won't be selected again during subsequent unloading traversal.
        RemoveEntryList(&context->registryLink);
        // Restore the node to a self-loop to allow the debugger to recognize it has left the registry.
        InitializeListHead(&context->registryLink);
        // Clear the registration flag to prevent any exceptions from repeatedly freeing and re-operating on the linked list.
        context->registered = 0L;
        // Defensive check on the count to prevent unsigned underflow in a corrupted state.
        if (gKswordArkThreadApcOutstandingCount != 0UL) {
            // Symmetrically decrement the outstanding context count incremented during registration.
            --gKswordArkThreadApcOutstandingCount;
        }
        // Wake the unloading thread waiting for drain when the last context leaves.
        if (gKswordArkThreadApcOutstandingCount == 0UL) {
            (VOID)KeSetEvent(
                &gKswordArkThreadApcDrainEvent,
                IO_NO_INCREMENT,
                FALSE);
        }
    }
    // Retrieve the thread object and clear the field to ensure no further dereferencing occurs.
    threadObject = context->threadObject;
    context->threadObject = NULL;
    // Release the registry lock and restore the caller's original IRQL.
    KeReleaseSpinLock(&gKswordArkThreadApcRegistryLock, oldIrql);

    // Release the reference after the thread object is detached from the shared structure.
    if (threadObject != NULL) {
        // ETHREAD references obtained via PsLookup/ObReference must be symmetrically released in the final release path.
        ObDereferenceObject(threadObject);
    }
    // Release the base reference held by the registry; a temporary dereference may keep memory alive.
    kswordArkDereferenceThreadTerminateApcContext(context);
}

static BOOLEAN
kswordArkQueueTrackedThreadTerminateApc(
    _Inout_ KswordArkThreadTerminateApcContext* context,
    _Inout_ PKAPC apc
    )
/*++

Routine Description:

    Check the unload status, publish the active APC pointer, and perform queuing under registry lock protection.

Arguments:

    Context - Registered context holding a reference to the target thread.
    APC: Special or Normal APC already initialized by KeInitializeApc.

Return Value:

    Returns TRUE on successful queuing; returns FALSE when unloading begins, context is released, or the kernel rejects queuing.

--*/
{
    KIRQL oldIrql = PASSIVE_LEVEL;
    BOOLEAN inserted = FALSE;

    // The registry lock keeps the stop flag and the invariant that an active pointer corresponds to a queued APC atomic.
    KeAcquireSpinLock(&gKswordArkThreadApcRegistryLock, &oldIrql);
    // Invoke the kernel queued routine only when the context is still registered and the driver has not stopped accepting APCs.
    if (gKswordArkThreadApcStopping == 0L &&
        context->registered != 0L &&
        context->released == 0L) {
        // Publish the active APC first; even if the callback executes immediately, it can safely clear the same pointer.
        (VOID)InterlockedExchangePointer(&context->activeApc, apc);
        // Perform the actual enqueue operation under the same lock that prevents insertion while stopped.
        inserted = context->keInsertQueueApc(apc, NULL, NULL, 0);
        // On queue failure, clear the active pointer; the caller subsequently releases the entire context.
        if (!inserted) {
            kswordArkClearActiveThreadTerminateApc(context, apc);
        }
    }
    // After releasing the registry lock, the unload path can cancel the APC that was just confirmed as queued.
    KeReleaseSpinLock(&gKswordArkThreadApcRegistryLock, oldIrql);
    // Returns the final result of the kernel queued operation.
    return inserted;
}

static VOID
NTAPI
kswordArkTerminateSystemThreadReaperWorker(
    _In_ PVOID parameter
    )
/*++

Routine Description:

    Wait for the target thread to terminate or the NormalRoutine to return before releasing the APC context.

Arguments:

    Parameter: Pointer to KswordArkThreadTerminateApcContext.

Return Value:

    No return value.

--*/
{
    KswordArkThreadTerminateApcContext* context =
        (KswordArkThreadTerminateApcContext*)parameter;
    PVOID waitObjects[2];

    // The first wait object is an ETHREAD, which the kernel sets to signaled when the thread fully exits.
    waitObjects[0] = context->threadObject;
    // The second wait object covers the failure path unexpectedly returned by PsTerminateSystemThread.
    waitObjects[1] = &context->normalRoutineCompletedEvent;
    // A signal on any object indicates that the target thread is no longer executing the NormalRoutine body of this driver.
    (VOID)KeWaitForMultipleObjects(
        RTL_NUMBER_OF(waitObjects),
        waitObjects,
        WaitAny,
        Executive,
        KernelMode,
        FALSE,
        NULL,
        NULL);
    // Release action must be at the end of the worker to ensure unloading waits for the entire execution window.
    kswordArkReleaseThreadTerminateApcContext(context);
}

static VOID
NTAPI
kswordArkTerminateSystemThreadNormalRoutine(
    _In_opt_ PVOID normalContext,
    _In_opt_ PVOID systemArgument1,
    _In_opt_ PVOID systemArgument2
    )
/*++

Routine Description:

    Queue a cleanup worker at PASSIVE_LEVEL on the target system thread, then terminate the current thread.

Arguments:

    NormalContext - pointer to KswordArkThreadTerminateApcContext.
    SystemArgument1 - Unused APC system parameter.
    SystemArgument2 - Unused APC system parameter.

Return Value:

    On normal success, PsTerminateSystemThread does not return; on failure, it returns to wake and recycle the worker.

--*/
{
    KswordArkThreadTerminateApcContext* context =
        (KswordArkThreadTerminateApcContext*)normalContext;

    // Both system arguments are fixed to NULL by the queuing side; this implementation does not read them.
    UNREFERENCED_PARAMETER(systemArgument1);
    UNREFERENCED_PARAMETER(systemArgument2);

    // KeInitializeApc permits a NULL NormalContext, but this callback cannot
    // safely schedule its reaper or terminate the target thread without its
    // tracked lifetime context.  Treat a broken callback contract as a no-op.
    if (context == NULL) {
        return;
    }

    // Prepare a wait-type worker before terminating the current thread to ensure the context is released after the thread exits.
    ExInitializeWorkItem(
        &context->reaperWorkItem,
        kswordArkTerminateSystemThreadReaperWorker,
        context);
    // The system worker waits for the ETHREAD to signal, preventing premature release of contexts still executing.
    ExQueueWorkItem(&context->reaperWorkItem, DelayedWorkQueue);
    // The public API terminates only the current system thread; the success path never returns to this driver code.
    (VOID)PsTerminateSystemThread(STATUS_CANCELLED);
    // If the API returns an error, notify the worker that the NormalRoutine has completed and the context can be released.
    (VOID)KeSetEvent(
        &context->normalRoutineCompletedEvent,
        IO_NO_INCREMENT,
        FALSE);
}

static VOID
NTAPI
kswordArkTerminateSystemThreadNormalKernelRoutine(
    _In_ PKAPC apc,
    _Inout_ KswordApcNormalRoutine* normalRoutine,
    _Inout_ PVOID* normalContext,
    _Inout_ PVOID* systemArgument1,
    _Inout_ PVOID* systemArgument2
    )
/*++

Routine Description:

    Marks the Normal APC as removed from the queue; suppresses NormalRoutine during unloading and releases the context.

Arguments:

    Apc - The Normal APC currently being dispatched.
    NormalRoutine - function pointer slot that can cancel subsequent NormalRoutine calls.
    NormalContext: Context slot for NormalRoutine.
    SystemArgument1 - Unused system parameter slot.
    SystemArgument2 - Unused system parameter slot.

Return Value:

    No return value.

--*/
{
    KswordArkThreadTerminateApcContext* context =
        CONTAINING_RECORD(apc, KswordArkThreadTerminateApcContext, normalApc);

    // Both system arguments are always NULL; this routine does not modify them.
    UNREFERENCED_PARAMETER(systemArgument1);
    UNREFERENCED_PARAMETER(systemArgument2);
    // The APC has already been dequeued by the kernel; the cancellation path should not call KeRemoveQueueApc again.
    kswordArkClearActiveThreadTerminateApc(context, apc);
    // No new driver NormalRoutine will be entered after unloading begins.
    if (InterlockedCompareExchange(&gKswordArkThreadApcStopping, 0L, 0L) != 0L) {
        // Clear the function pointer to prevent the APC dispatcher from calling this driver's NormalRoutine.
        *normalRoutine = NULL;
        // Clear the context slot to prevent downstream code from retaining the address of a released context.
        *normalContext = NULL;
        // The release action is at the end of the kernel routine; unloading waits to overwrite all prior logic.
        kswordArkReleaseThreadTerminateApcContext(context);
    }
}

static VOID
NTAPI
kswordArkTerminateSystemThreadNormalRundownRoutine(
    _In_ PKAPC apc
    )
/*++

Routine Description:

    Clear the active pointer and free the context when a thread exits before the Normal APC is delivered.

Arguments:

    Apc - Normal APC being rundown by the kernel.

Return Value:

    No return value.

--*/
{
    KswordArkThreadTerminateApcContext* context =
        CONTAINING_RECORD(apc, KswordArkThreadTerminateApcContext, normalApc);

    // The APC is no longer in the target thread queue; first revoke the cancellable pointer.
    kswordArkClearActiveThreadTerminateApc(context, apc);
    // Rundown tail: Release registered context and wake up any unloaded threads waiting.
    kswordArkReleaseThreadTerminateApcContext(context);
}

static VOID
NTAPI
kswordArkTerminateSystemThreadSpecialRundownRoutine(
    _In_ PKAPC apc
    )
/*++

Routine Description:

    Release the registration context when the thread termination causes the Special APC to remain undelivered.

Arguments:

    Apc: Special APC being rundown by the kernel.

Return Value:

    No return value.

--*/
{
    KswordArkThreadTerminateApcContext* context =
        CONTAINING_RECORD(apc, KswordArkThreadTerminateApcContext, specialApc);

    // The APC has left the target thread queue; clear the current active pointer first.
    kswordArkClearActiveThreadTerminateApc(context, apc);
    // Rundown tail: Release registered context and wake up any unloaded threads waiting.
    kswordArkReleaseThreadTerminateApcContext(context);
}

static VOID
NTAPI
kswordArkTerminateSystemThreadSpecialKernelRoutine(
    _In_ PKAPC apc,
    _Inout_ KswordApcNormalRoutine* normalRoutine,
    _Inout_ PVOID* normalContext,
    _Inout_ PVOID* systemArgument1,
    _Inout_ PVOID* systemArgument2
    )
/*++

Routine Description:

    Convert the dispatched Special APC to a Normal APC tracked by the same registry.

Arguments:

    Apc - Special APC being dispatched.
    NormalRoutine - Special APC does not configure NormalRoutine; parameters are for signature compatibility only.
    NormalContext - Special APC does not configure NormalContext; parameters are for signature compatibility only.
    SystemArgument1 - Unused system parameter slot.
    SystemArgument2 - Unused system parameter slot.

Return Value:

    No return value.

--*/
{
    KswordArkThreadTerminateApcContext* context =
        CONTAINING_RECORD(apc, KswordArkThreadTerminateApcContext, specialApc);

    // Special APCs lack a NormalRoutine; these two slots are excluded from the conversion logic.
    UNREFERENCED_PARAMETER(normalRoutine);
    UNREFERENCED_PARAMETER(normalContext);
    // Both system arguments are fixed to NULL by the queuing side; this routine does not read them.
    UNREFERENCED_PARAMETER(systemArgument1);
    UNREFERENCED_PARAMETER(systemArgument2);
    // Special APC has been dequeued by the kernel; clear its active pointer.
    kswordArkClearActiveThreadTerminateApc(context, apc);
    // Prevent entry into the second phase at driver unloading and release the context at the end of the kernel routine.
    if (InterlockedCompareExchange(&gKswordArkThreadApcStopping, 0L, 0L) != 0L) {
        // The unified release function removes the context from the registry and wakes the unload thread.
        kswordArkReleaseThreadTerminateApcContext(context);
        return;
    }

    // initialize the second-stage Normal APC so that PsTerminateSystemThread executes at PASSIVE_LEVEL.
    context->keInitializeApc(
        &context->normalApc,
        (PKTHREAD)context->threadObject,
        KSWORD_ARK_APC_ENVIRONMENT_ORIGINAL,
        kswordArkTerminateSystemThreadNormalKernelRoutine,
        kswordArkTerminateSystemThreadNormalRundownRoutine,
        kswordArkTerminateSystemThreadNormalRoutine,
        KernelMode,
        context);
    // Atomically check the stop flag and publish a new active APC via the unified queue function.
    if (!kswordArkQueueTrackedThreadTerminateApc(context, &context->normalApc)) {
        // Release the context immediately if queuing fails or unloading has started.
        kswordArkReleaseThreadTerminateApcContext(context);
    }
}

VOID
kswordArkThreadApcInitialize(
    VOID
    )
/*++

Routine Description:

    initialize the APC registry, drain events, and set the receive state; called once by DriverEntry.

Arguments:

    None.

Return Value:

    No return value.

--*/
{
    // initialize the spin lock protecting the global APC registry.
    KeInitializeSpinLock(&gKswordArkThreadApcRegistryLock);
    // initialize an empty list; all subsequent contexts enter via the unified registration function.
    InitializeListHead(&gKswordArkThreadApcRegistry);
    // An empty registry corresponds to a signaled state, allowing unloading without pending APCs to proceed without waiting.
    KeInitializeEvent(
        &gKswordArkThreadApcDrainEvent,
        NotificationEvent,
        TRUE);
    // initialize the count to zero, consistent with an empty list and a signaled event.
    gKswordArkThreadApcOutstandingCount = 0UL;
    // Only allow APC queuing after all shared objects are fully initialized.
    (VOID)InterlockedExchange(&gKswordArkThreadApcStopping, 0L);
}

VOID
kswordArkThreadApcUninitialize(
    VOID
    )
/*++

Routine Description:

    Stop accepting new APCs, cancel all APCs still in the queue, and wait for executing callbacks to drain.

Arguments:

    None.

Return Value:

    No return value; upon return, no thread terminating APC capable of calling this driver code remains.

--*/
{
    KIRQL oldIrql = PASSIVE_LEVEL;

    // The unload callback runs at PASSIVE_LEVEL; explicitly verify the execution context before waiting for APCs to drain.
    PAGED_CODE();
    // Publish the stop state within the registry lock to prevent further registration and phase transition queuing.
    KeAcquireSpinLock(&gKswordArkThreadApcRegistryLock, &oldIrql);
    // Once set, the stop flag is never cleared for the lifetime of this driver instance.
    (VOID)InterlockedExchange(&gKswordArkThreadApcStopping, 1L);
    // Release the registry lock so the callback tail can continue completion and remove itself.
    KeReleaseSpinLock(&gKswordArkThreadApcRegistryLock, oldIrql);

    // Select an unvisited context in each round to avoid holding invalid pointers during cancellation outside the lock.
    for (;;) {
        KswordArkThreadTerminateApcContext* context = NULL;
        PVOID activeApc = NULL;
        PLIST_ENTRY entry = NULL;

        // Select the context under the list lock and increment the temporary reference.
        KeAcquireSpinLock(&gKswordArkThreadApcRegistryLock, &oldIrql);
        // Traverse from the head through still-registered contexts to find nodes that have not yet requested cancellation in this round.
        for (entry = gKswordArkThreadApcRegistry.Flink;
             entry != &gKswordArkThreadApcRegistry;
             entry = entry->Flink) {
            KswordArkThreadTerminateApcContext* candidate =
                CONTAINING_RECORD(
                    entry,
                    KswordArkThreadTerminateApcContext,
                    registryLink);

            // Released or visited nodes are handled by their existing callback/cancel paths; do not process them again.
            if (candidate->released != 0L ||
                candidate->cancelVisited != 0L) {
                continue;
            }
            // Mark this context as processed in the current round; subsequent iterations will advance to other nodes.
            candidate->cancelVisited = 1L;
            // Temporary reference ensures context memory remains valid when calling KeRemoveQueueApc outside the lock.
            kswordArkReferenceThreadTerminateApcContext(candidate);
            // Atomic read of the current actual queuing phase; NULL indicates the callback is executing or has not yet been queued.
            activeApc = InterlockedCompareExchangePointer(
                &candidate->activeApc,
                NULL,
                NULL);
            // Save candidate pointer then exit lock-internal traversal.
            context = candidate;
            break;
        }
        // Release the registry lock before acquiring the APC queue lock of the target thread to avoid lock order inversion.
        KeReleaseSpinLock(&gKswordArkThreadApcRegistryLock, oldIrql);

        // No unvisited nodes indicate that the cancellation request has overridden the current registration.
        if (context == NULL) {
            break;
        }
        // Attempt atomic removal while the active APC is still in the queue; if successful, the kernel will not invoke rundown.
        if (activeApc != NULL &&
            context->keRemoveQueueApc((PKAPC)activeApc)) {
            // Revoke the active pointer to prevent the diagnostic status from still showing the removed APC.
            kswordArkClearActiveThreadTerminateApc(
                context,
                (PKAPC)activeApc);
            // The success path of cancellation must release the context itself, as the kernel will not callback.
            kswordArkReleaseThreadTerminateApcContext(context);
        }
        // Release the temporary reference acquired within the lock; the base registration reference is held by the callback or cancellation path.
        kswordArkDereferenceThreadTerminateApcContext(context);
    }

    // Wait until all kernel/normal/rundown/worker paths have exited from the registry.
    (VOID)KeWaitForSingleObject(
        &gKswordArkThreadApcDrainEvent,
        Executive,
        KernelMode,
        FALSE,
        NULL);
}

NTSTATUS
kswordArkDriverQueueTerminateSystemThreadApc(
    _In_ PETHREAD threadObject,
    _In_ BOOLEAN specialToNormal
    )
/*++

Routine Description:

    Create a thread termination APC tracked by the global lifecycle registry and queue it to the target system thread.

Arguments:

    ThreadObject: The target ETHREAD already referenced by the caller; this function adds an independent reference.
    SpecialToNormal - when TRUE, Special APCs are processed first, then converted to Normal APCs.

Return Value:

    Return parameters, system routine parsing, memory, unload status, or actual queueing result.

--*/
{
    KswordArkThreadTerminateApcContext* context = NULL;
    KswordKeInitializeApcFn keInitializeApc = NULL;
    KswordKeInsertQueueApcFn keInsertQueueApc = NULL;
    KswordKeRemoveQueueApcFn keRemoveQueueApc = NULL;
    PKAPC firstApc = NULL;

    // The thread object cannot be null; the caller remains responsible for prior target identity and security policy checks.
    if (threadObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Resolve the APC initialization routine exported by the current kernel.
    keInitializeApc = kswordArkResolveKeInitializeApc();
    // Resolve the currently exported kernel APC queue routines.
    keInsertQueueApc = kswordArkResolveKeInsertQueueApc();
    // Resolve kernel routines required to cancel pending APCs during unloading.
    keRemoveQueueApc = kswordArkResolveKeRemoveQueueApc();
    // Do not create unmanageable partial contexts if any routine is unavailable.
    if (keInitializeApc == NULL ||
        keInsertQueueApc == NULL ||
        keRemoveQueueApc == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    // APC, registration nodes, events, and workers must reside in non-paged pool.
    context = (KswordArkThreadTerminateApcContext*)kswordArkAllocateNonPagedPool(
        sizeof(*context),
        KSWORD_ARK_THREAD_APC_POOL_TAG);
    // Return the standard insufficient resources status to the caller upon allocation failure.
    if (context == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    // Zero out the entire context to ensure all concurrency flags start from a defined state.
    RtlZeroMemory(context, sizeof(*context));
    // initialize the independent list node to maintain a self-loop state before registration.
    InitializeListHead(&context->registryLink);
    // NormalRoutine returns an initially non-signaled event; only covers the unexpected return path of PsTerminate.
    KeInitializeEvent(
        &context->normalRoutineCompletedEvent,
        NotificationEvent,
        FALSE);
    // Initial reference is held by the global registry; the release function eventually returns it.
    context->referenceCount = 1L;
    // Increment the reference count on the target thread object to ensure the address remains valid during APC, worker, and unload operations.
    ObReferenceObject(threadObject);
    // Save the target thread object for APC initialization and for the cleanup worker to wait on.
    context->threadObject = threadObject;
    // Save the parsed initialization routine for continued use during the Special-to-Normal phase transition.
    context->keInitializeApc = keInitializeApc;
    // Save the parsed queue routines; all stages are invoked via a unified atomic queue function.
    context->keInsertQueueApc = keInsertQueueApc;
    // Save the resolved unhook routine; unload traversal no longer requires querying system exports.
    context->keRemoveQueueApc = keRemoveQueueApc;

    // Register globally before initializing the callback object to ensure the context can be discovered during unloading.
    if (!kswordArkRegisterThreadTerminateApcContext(context)) {
        // Return the independent thread object reference when unloading begins.
        ObDereferenceObject(context->threadObject);
        // Clear the field to prevent the debugger from mistakenly assuming an unregistered context still holds the object.
        context->threadObject = NULL;
        // Return the initial reference not yet handed to the registry and free memory.
        kswordArkDereferenceThreadTerminateApcContext(context);
        return STATUS_DELETE_PENDING;
    }

    // initialize the first-stage Special or Normal APC based on user selection.
    if (specialToNormal) {
        // The first phase of Special mode is initialized only at APC_LEVEL; the second phase follows.
        firstApc = &context->specialApc;
        // initialize the Special APC and provide a rundown release path when the thread exits.
        keInitializeApc(
            firstApc,
            (PKTHREAD)threadObject,
            KSWORD_ARK_APC_ENVIRONMENT_ORIGINAL,
            kswordArkTerminateSystemThreadSpecialKernelRoutine,
            kswordArkTerminateSystemThreadSpecialRundownRoutine,
            NULL,
            KernelMode,
            NULL);
    }
    else {
        // Normal mode executes the termination routine directly on the target thread at PASSIVE_LEVEL.
        firstApc = &context->normalApc;
        // initialize a Normal APC and provide complete paths for kernel, rundown, and normal execution.
        keInitializeApc(
            firstApc,
            (PKTHREAD)threadObject,
            KSWORD_ARK_APC_ENVIRONMENT_ORIGINAL,
            kswordArkTerminateSystemThreadNormalKernelRoutine,
            kswordArkTerminateSystemThreadNormalRundownRoutine,
            kswordArkTerminateSystemThreadNormalRoutine,
            KernelMode,
            context);
    }

    // On atomic queue failure, release the context uniformly from the registry.
    if (!kswordArkQueueTrackedThreadTerminateApc(context, firstApc)) {
        // Symmetrically remove the registered node, thread reference, and base memory reference in the release function.
        kswordArkReleaseThreadTerminateApcContext(context);
        return STATUS_UNSUCCESSFUL;
    }

    // Queue success indicates the APC has entered the globally cancellable and drainable lifecycle management.
    return STATUS_SUCCESS;
}
