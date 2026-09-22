/*++

Module Name:

    bugcheck_control.c

Abstract:

    Install the control layer for blue screen diagnostics on demand. During driver load, only the synchronization state in this file
    is initialized; ntoskrnl is not scanned, BGP private functions are not resolved, and BugCheck callbacks are not registered.

Environment:

    Kernel-mode Driver Framework

--*/

#include "bugcheck_internal.h"
#include "bugcheck_bgp.h"

// Lifecycle state may only be modified by the control lock holder to avoid concurrent IOCTLs queuing or cleaning up repeatedly.
#define KSWORD_ARK_BUGCHECK_CONTROL_INACTIVE     0L
#define KSWORD_ARK_BUGCHECK_CONTROL_INSTALLING   1L
#define KSWORD_ARK_BUGCHECK_CONTROL_INSTALLED    2L
#define KSWORD_ARK_BUGCHECK_CONTROL_UNINSTALLING 3L

// BGP private function parsing and rectangle pre-generation must have hard budgets on the kernel side. R3 timeouts cannot abort synchronous IOCTLs that have
// already entered the kernel; therefore, the budget and cancellation status must be owned by the R0 controller that actually performs the preparation work.
#define KSWORD_ARK_BUGCHECK_INSTALL_TIMEOUT_100NS (30ULL * 1000ULL * 10000ULL)

// The control lock is established during DriverEntry and is not placed in the diagnostic state structure that gets zeroed by the full initialization routine.
// The lock protects only queuing and final state publication; it never covers time-consuming BGP initialization or resource destruction.
static FAST_MUTEX gKswordArkBugcheckControlLock;
static volatile LONG gKswordArkBugcheckControlReady = 0L;
static volatile LONG gKswordArkBugcheckControlLifecycle =
    KSWORD_ARK_BUGCHECK_CONTROL_INACTIVE;
static volatile LONG gKswordArkBugcheckControlCancelRequested = 0L;
static volatile LONG gKswordArkBugcheckControlLastStatus = STATUS_SUCCESS;
static volatile LONG gKswordArkBugcheckControlProtocolStatus =
    KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATUS_INACTIVE;
static volatile LONG64 gKswordArkBugcheckControlDeadline = 0LL;
static PDRIVER_OBJECT gKswordArkBugcheckControlDriverObject = NULL;
static WDFDEVICE gKswordArkBugcheckControlDevice = WDF_NO_HANDLE;
static WDFWORKITEM gKswordArkBugcheckControlWorkItem = WDF_NO_HANDLE;

static VOID
kswordArkBugcheckControlInstallWorker(
    _In_ WDFWORKITEM workItem
    );

static ULONG
kswordArkBugcheckControlCallbackMask(
    VOID
    )
{
    ULONG callbackMask = 0UL;

    // Only report to R3 that the full callback set is available after all four Windows BugCheck callbacks have been registered.
    if (gKswordArkBugcheckState.classicRegistered) {
        callbackMask |= 0x00000001UL;
    }
    if (gKswordArkBugcheckState.secondaryRegistered) {
        callbackMask |= 0x00000002UL;
    }
    if (gKswordArkBugcheckState.dumpIoRegistered) {
        callbackMask |= 0x00000004UL;
    }
    if (gKswordArkBugcheckState.triageRegistered) {
        callbackMask |= 0x00000008UL;
    }
    return callbackMask;
}

NTSTATUS
kswordArkBugcheckControlCheckAbort(
    VOID
    )
{
#if !KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED
    return STATUS_NOT_SUPPORTED;
#else
    ULONGLONG deadline;

    if (InterlockedCompareExchange(
            &gKswordArkBugcheckControlCancelRequested,
            0L,
            0L) != 0L ||
        InterlockedCompareExchange(
            &gKswordArkBugcheckControlReady,
            0L,
            0L) == 0L) {
        return STATUS_CANCELLED;
    }

    deadline = (ULONGLONG)InterlockedCompareExchange64(
        &gKswordArkBugcheckControlDeadline,
        0LL,
        0LL);
    if (deadline != 0ULL && KeQueryInterruptTime() >= deadline) {
        return STATUS_IO_TIMEOUT;
    }
    return STATUS_SUCCESS;
#endif
}

static VOID
kswordArkBugcheckControlFillResponse(
    _Out_ KSWORD_ARK_BUGCHECK_DIAGNOSTICS_RESPONSE* response,
    _In_ ULONG protocolStatus,
    _In_ NTSTATUS lastStatus
    )
{
    KswordArkBgpDumpState bgpSnapshot;
    ULONG callbackMask = 0UL;
    LONG lifecycle = KSWORD_ARK_BUGCHECK_CONTROL_INACTIVE;

    // Zero all response fields first to prevent uninitialized kernel stack content from leaking to R3 on failure paths.
    RtlZeroMemory(response, sizeof(*response));
    response->size = sizeof(*response);
    response->version = KSWORD_ARK_BUGCHECK_DIAGNOSTICS_PROTOCOL_VERSION;
    response->status = protocolStatus;
    response->lastStatus = (LONG)lastStatus;

    // BGP snapshot reads only published non-paged states; installation work items can be polled during the preparation phase.
    RtlZeroMemory(&bgpSnapshot, sizeof(bgpSnapshot));
    kswordArkBugcheckBgpSnapshot(&bgpSnapshot);
    response->bgpState = bgpSnapshot.state;
    response->bgpPreparationStage = bgpSnapshot.preparationStage;
    response->bgpPreparationStatus = (LONG)bgpSnapshot.preparationStatus;
    response->panelStatus = (LONG)bgpSnapshot.preparationStatus;

    lifecycle = InterlockedCompareExchange(
        &gKswordArkBugcheckControlLifecycle,
        KSWORD_ARK_BUGCHECK_CONTROL_INACTIVE,
        KSWORD_ARK_BUGCHECK_CONTROL_INACTIVE);
    callbackMask = kswordArkBugcheckControlCallbackMask();
    response->callbackMask = callbackMask;
    if (lifecycle == KSWORD_ARK_BUGCHECK_CONTROL_INSTALLED) {
        response->stateFlags |= KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATE_INSTALLED;
    }
    if (callbackMask == 0x0000000FUL) {
        response->stateFlags |= KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATE_CALLBACKS_READY;
    }
    if (bgpSnapshot.state == kKswordArkBgpStateReady ||
        bgpSnapshot.state == kKswordArkBgpStateArmed ||
        bgpSnapshot.state == kKswordArkBgpStateDrawn) {
        response->stateFlags |= KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATE_BGP_BACKEND_READY;
    }
    if (bgpSnapshot.state == kKswordArkBgpStateArmed ||
        bgpSnapshot.state == kKswordArkBgpStateDrawn) {
        response->stateFlags |= KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATE_PANEL_READY;
    }
}

static VOID
kswordArkBugcheckControlInstallWorker(
    _In_ WDFWORKITEM workItem
    )
{
    NTSTATUS installStatus;
    NTSTATUS abortStatus;

    UNREFERENCED_PARAMETER(workItem);
    installStatus = kswordArkBugcheckControlCheckAbort();
    if (NT_SUCCESS(installStatus)) {
        installStatus = kswordArkBugcheckInitialize(
            gKswordArkBugcheckControlDriverObject,
            gKswordArkBugcheckControlDevice);
    }

    // Unloading or budget expiration may occur simultaneously with initialization; re-check before final state publication.
    abortStatus = kswordArkBugcheckControlCheckAbort();
    if (NT_SUCCESS(installStatus) && !NT_SUCCESS(abortStatus)) {
        installStatus = abortStatus;
    }

    // Publish the success terminal state within the lock. If unloading has already revoked 'ready', this work item is responsible for cleaning up the just-completed installation.
    if (NT_SUCCESS(installStatus)) {
        ExAcquireFastMutex(&gKswordArkBugcheckControlLock);
        if (InterlockedCompareExchange(
                &gKswordArkBugcheckControlReady,
                0L,
                0L) != 0L &&
            InterlockedCompareExchange(
                &gKswordArkBugcheckControlCancelRequested,
                0L,
                0L) == 0L) {
            InterlockedExchange64(&gKswordArkBugcheckControlDeadline, 0LL);
            InterlockedExchange(
                &gKswordArkBugcheckControlLastStatus,
                STATUS_SUCCESS);
            InterlockedExchange(
                &gKswordArkBugcheckControlLifecycle,
                KSWORD_ARK_BUGCHECK_CONTROL_INSTALLED);
            InterlockedExchange(
                &gKswordArkBugcheckControlProtocolStatus,
                KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATUS_OK);
            ExReleaseFastMutex(&gKswordArkBugcheckControlLock);
            return;
        }
        ExReleaseFastMutex(&gKswordArkBugcheckControlLock);
        installStatus = STATUS_CANCELLED;
    }

    // On initialization failure or cancellation paths, uniformly clean up all callbacks and rectangles created by the current work item.
    kswordArkBugcheckUninitialize();
    ExAcquireFastMutex(&gKswordArkBugcheckControlLock);
    InterlockedExchange64(&gKswordArkBugcheckControlDeadline, 0LL);
    InterlockedExchange(
        &gKswordArkBugcheckControlLastStatus,
        (LONG)installStatus);
    // The unloader performs the final state reset after Flush returns; ordinary failures allow subsequent reinstallation.
    InterlockedExchange(
        &gKswordArkBugcheckControlLifecycle,
        KSWORD_ARK_BUGCHECK_CONTROL_INACTIVE);
    InterlockedExchange(
        &gKswordArkBugcheckControlProtocolStatus,
        KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATUS_PREPARATION_FAILED);
    ExReleaseFastMutex(&gKswordArkBugcheckControlLock);
}

NTSTATUS
kswordArkBugcheckControlInitialize(
    _In_ PDRIVER_OBJECT driverObject,
    _In_ WDFDEVICE controlDevice
    )
{
#if !KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(ControlDevice);
    return STATUS_NOT_SUPPORTED;
#else
    WDF_OBJECT_ATTRIBUTES attributes;
    WDF_WORKITEM_CONFIG workItemConfig;
    NTSTATUS status;

    // DriverEntry is called only once; reject invalid objects to prevent subsequent installation actions from holding null device pointers.
    if (driverObject == NULL || controlDevice == WDF_NO_HANDLE) {
        return STATUS_INVALID_PARAMETER;
    }

    // The work item uses the control device as its parent; the unload path explicitly flushes before allowing the device and driver image to disappear.
    ExInitializeFastMutex(&gKswordArkBugcheckControlLock);
    WDF_WORKITEM_CONFIG_INIT(
        &workItemConfig,
        kswordArkBugcheckControlInstallWorker);
    // The controller uses its own FAST_MUTEX; work items cannot inherit device-level automatic serialization and must not block IOCTLs in reverse.
    workItemConfig.AutomaticSerialization = FALSE;
    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.ParentObject = controlDevice;
    // WDFWORKITEM callbacks naturally run at PASSIVE_LEVEL; this object type does not allow specifying
    // ExecutionLevel/SynchronizationScope in object attributes, so InheritFromParent must be retained.
    // Explicitly writing Passive/None causes WdfWorkItemCreate to return an invalid WDF attribute status, leaving the
    // controller in a not-ready state and causing R3 to incorrectly assume the driver lacks installation capabilities.
    status = WdfWorkItemCreate(
        &workItemConfig,
        &attributes,
        &gKswordArkBugcheckControlWorkItem);
    if (!NT_SUCCESS(status)) {
        gKswordArkBugcheckControlWorkItem = WDF_NO_HANDLE;
        InterlockedExchange(
            &gKswordArkBugcheckControlLastStatus,
            (LONG)status);
        InterlockedExchange(
            &gKswordArkBugcheckControlProtocolStatus,
            KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATUS_PREPARATION_FAILED);
        return status;
    }

    gKswordArkBugcheckControlDriverObject = driverObject;
    gKswordArkBugcheckControlDevice = controlDevice;
    InterlockedExchange(
        &gKswordArkBugcheckControlLifecycle,
        KSWORD_ARK_BUGCHECK_CONTROL_INACTIVE);
    InterlockedExchange(
        &gKswordArkBugcheckControlProtocolStatus,
        KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATUS_INACTIVE);
    InterlockedExchange(
        &gKswordArkBugcheckControlLastStatus,
        STATUS_SUCCESS);
    InterlockedExchange(
        &gKswordArkBugcheckControlCancelRequested,
        0L);
    InterlockedExchange64(&gKswordArkBugcheckControlDeadline, 0LL);
    InterlockedExchange(&gKswordArkBugcheckControlReady, 1L);
    return STATUS_SUCCESS;
#endif
}

VOID
kswordArkBugcheckControlUninitialize(
    VOID
    )
{
#if !KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED
    return;
#else
    WDFWORKITEM workItem;
    LONG lifecycle;

    // Revoke ready and broadcast cancellation; new configuration IOCTLs will no longer queue. The control lock is used only for handover during the queuing moment.
    if (InterlockedExchange(&gKswordArkBugcheckControlReady, 0L) == 0L) {
        return;
    }
    InterlockedExchange(&gKswordArkBugcheckControlCancelRequested, 1L);
    ExAcquireFastMutex(&gKswordArkBugcheckControlLock);
    workItem = gKswordArkBugcheckControlWorkItem;
    ExReleaseFastMutex(&gKswordArkBugcheckControlLock);

    // Flush waits only for already queued work items; work items respond to cancellation between scan blocks and each private bitmap parse.
    if (workItem != WDF_NO_HANDLE) {
        WdfWorkItemFlush(workItem);
    }

    ExAcquireFastMutex(&gKswordArkBugcheckControlLock);
    lifecycle = InterlockedCompareExchange(
        &gKswordArkBugcheckControlLifecycle,
        KSWORD_ARK_BUGCHECK_CONTROL_INACTIVE,
        KSWORD_ARK_BUGCHECK_CONTROL_INACTIVE);
    if (lifecycle == KSWORD_ARK_BUGCHECK_CONTROL_INSTALLED) {
        InterlockedExchange(
            &gKswordArkBugcheckControlLifecycle,
            KSWORD_ARK_BUGCHECK_CONTROL_UNINSTALLING);
    }
    ExReleaseFastMutex(&gKswordArkBugcheckControlLock);

    // The ready state has been revoked and the work item has been drained; resource destruction does not require holding the control lock.
    if (lifecycle == KSWORD_ARK_BUGCHECK_CONTROL_INSTALLED) {
        kswordArkBugcheckUninitialize();
    }

    ExAcquireFastMutex(&gKswordArkBugcheckControlLock);
    gKswordArkBugcheckControlDriverObject = NULL;
    gKswordArkBugcheckControlDevice = WDF_NO_HANDLE;
    gKswordArkBugcheckControlWorkItem = WDF_NO_HANDLE;
    InterlockedExchange64(&gKswordArkBugcheckControlDeadline, 0LL);
    InterlockedExchange(
        &gKswordArkBugcheckControlLifecycle,
        KSWORD_ARK_BUGCHECK_CONTROL_INACTIVE);
    InterlockedExchange(
        &gKswordArkBugcheckControlProtocolStatus,
        KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATUS_INACTIVE);
    ExReleaseFastMutex(&gKswordArkBugcheckControlLock);

    if (workItem != WDF_NO_HANDLE) {
        WdfObjectDelete(workItem);
    }
#endif
}

NTSTATUS
kswordArkBugcheckControlConfigure(
    _In_ const KSWORD_ARK_BUGCHECK_DIAGNOSTICS_REQUEST* request,
    _Out_ KSWORD_ARK_BUGCHECK_DIAGNOSTICS_RESPONSE* response
    )
{
#if !KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED
    UNREFERENCED_PARAMETER(Request);
    if (Response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    KswordARKBugcheckControlFillResponse(
        Response,
        KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATUS_UNSUPPORTED,
        STATUS_NOT_SUPPORTED);
    return STATUS_SUCCESS;
#else
    NTSTATUS lastStatus;
    ULONG protocolStatus;
    LONG lifecycle;

    if (response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // The handler has already performed the WDF buffer length check; here we strictly validate version, action, and reserved bits.
    if (request == NULL ||
        request->size != sizeof(*request) ||
        request->version != KSWORD_ARK_BUGCHECK_DIAGNOSTICS_PROTOCOL_VERSION ||
        request->flags != 0UL ||
        request->reserved0 != 0UL ||
        request->reserved1 != 0UL ||
        (request->action != KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ACTION_QUERY &&
         request->action != KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ACTION_INSTALL)) {
        kswordArkBugcheckControlFillResponse(
            response,
            KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATUS_INVALID_REQUEST,
            STATUS_INVALID_PARAMETER);
        return STATUS_SUCCESS;
    }

    if (InterlockedCompareExchange(
            &gKswordArkBugcheckControlReady,
            0L,
            0L) == 0L) {
        protocolStatus = (ULONG)InterlockedCompareExchange(
            &gKswordArkBugcheckControlProtocolStatus,
            0L,
            0L);
        lastStatus = (NTSTATUS)InterlockedCompareExchange(
            &gKswordArkBugcheckControlLastStatus,
            0L,
            0L);
        if (protocolStatus == KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATUS_INACTIVE) {
            protocolStatus = KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATUS_PREPARATION_FAILED;
            lastStatus = STATUS_DEVICE_NOT_READY;
        }
        kswordArkBugcheckControlFillResponse(
            response,
            protocolStatus,
            lastStatus);
        return STATUS_SUCCESS;
    }

    ExAcquireFastMutex(&gKswordArkBugcheckControlLock);
    lifecycle = InterlockedCompareExchange(
        &gKswordArkBugcheckControlLifecycle,
        KSWORD_ARK_BUGCHECK_CONTROL_INACTIVE,
        KSWORD_ARK_BUGCHECK_CONTROL_INACTIVE);
    protocolStatus = (ULONG)InterlockedCompareExchange(
        &gKswordArkBugcheckControlProtocolStatus,
        0L,
        0L);
    lastStatus = (NTSTATUS)InterlockedCompareExchange(
        &gKswordArkBugcheckControlLastStatus,
        0L,
        0L);

    if (request->action == KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ACTION_QUERY) {
        if (lifecycle == KSWORD_ARK_BUGCHECK_CONTROL_INSTALLING ||
            lifecycle == KSWORD_ARK_BUGCHECK_CONTROL_UNINSTALLING) {
            protocolStatus = KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATUS_BUSY;
            lastStatus = STATUS_PENDING;
        } else if (lifecycle == KSWORD_ARK_BUGCHECK_CONTROL_INSTALLED) {
            protocolStatus = KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATUS_OK;
            lastStatus = STATUS_SUCCESS;
        }
    } else if (lifecycle == KSWORD_ARK_BUGCHECK_CONTROL_INSTALLED) {
        protocolStatus = KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATUS_OK;
        lastStatus = STATUS_SUCCESS;
    } else if (lifecycle != KSWORD_ARK_BUGCHECK_CONTROL_INACTIVE) {
        protocolStatus = KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATUS_BUSY;
        lastStatus = STATUS_DEVICE_BUSY;
    } else if (gKswordArkBugcheckControlDriverObject == NULL ||
               gKswordArkBugcheckControlDevice == WDF_NO_HANDLE ||
               gKswordArkBugcheckControlWorkItem == WDF_NO_HANDLE) {
        protocolStatus = KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATUS_UNSUPPORTED;
        lastStatus = STATUS_DEVICE_NOT_READY;
    } else {
        ULONGLONG deadline;

        // IOCTL is only responsible for atomic state publication and queuing. Time-consuming preparation does not hold the control lock and does not occupy R3 requests.
        deadline = KeQueryInterruptTime() +
            KSWORD_ARK_BUGCHECK_INSTALL_TIMEOUT_100NS;
        InterlockedExchange(
            &gKswordArkBugcheckControlCancelRequested,
            0L);
        InterlockedExchange64(
            &gKswordArkBugcheckControlDeadline,
            (LONG64)deadline);
        InterlockedExchange(
            &gKswordArkBugcheckControlLastStatus,
            STATUS_PENDING);
        InterlockedExchange(
            &gKswordArkBugcheckControlProtocolStatus,
            KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATUS_BUSY);
        InterlockedExchange(
            &gKswordArkBugcheckControlLifecycle,
            KSWORD_ARK_BUGCHECK_CONTROL_INSTALLING);
        WdfWorkItemEnqueue(gKswordArkBugcheckControlWorkItem);
        protocolStatus = KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATUS_BUSY;
        lastStatus = STATUS_PENDING;
    }

    kswordArkBugcheckControlFillResponse(
        response,
        protocolStatus,
        lastStatus);
    ExReleaseFastMutex(&gKswordArkBugcheckControlLock);
    return STATUS_SUCCESS;
#endif
}
