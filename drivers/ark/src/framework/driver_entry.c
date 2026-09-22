/*++

Module Name:

    driver_entry.c

Abstract:

    This file contains the driver entry points and callbacks.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "ark/ark_mutation.h"
#include "src/features/kernel/kernel_idt_baseline.h"
#include "src/features/hvm/hvm_runtime.h"
#include "src/features/rxpf/rxpf_runtime.h"
#include "driver_entry.tmh"

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, kswordArkDriverEvtDriverUnload)
#pragma alloc_text (PAGE, kswordArkDriverEvtDriverContextCleanup)
#endif

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  driverObject,
    _In_ PUNICODE_STRING registryPath
    )
/*++

Routine Description:

    DriverEntry initializes the driver and is the first routine called by the
    system after the driver is loaded.

Arguments:

    DriverObject - represents the instance of the function driver that is loaded
    into memory.
    RegistryPath - represents the driver specific path in the Registry.

Return Value:

    NTSTATUS

--*/
{
    WDF_DRIVER_CONFIG config;
    NTSTATUS status;
    WDF_OBJECT_ATTRIBUTES attributes;
    WDFDRIVER driverHandle = WDF_NO_HANDLE;
    WDFDEVICE controlDevice = WDF_NO_HANDLE;
    ULONG osBuildNumber = 0UL;

    // initialize WPP tracing as soon as possible.
    WPP_INIT_TRACING(driverObject, registryPath);
    // The first breadcrumb must precede any initialization that might fail; otherwise, it is impossible to distinguish between
    // "the driver never entered DriverEntry (signature/CI/import/KMDF binding)" and "failed at some step after entering".
    kswordArkStartupBreadcrumbInitialize(driverObject, registryPath);

    // The INF declares a minimum OS of 10.0.16299; systems below this return a definitive unsupported status immediately
    // rather than letting subsequent kernel callback registrations produce an unexplained generic failure code.
    kswordArkStartupStage(kKswordArkStartStageOsVersionCheck);
    osBuildNumber = kswordArkStartupGetOsBuildNumber();
    if (osBuildNumber != 0UL && osBuildNumber < KSWORD_ARK_MINIMUM_SUPPORTED_OS_BUILD) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER,
            "Unsupported OS build %lu, KswordARK requires 16299 or newer", osBuildNumber);
        WPP_CLEANUP(driverObject);
        return kswordArkStartupFailure(kKswordArkStartStageOsVersionCheck, STATUS_NOT_SUPPORTED);
    }

    kswordArkCapabilityInitialize();
    kswordArkTrustInitialize();
    kswordArkSafetyInitialize();
    // HAL edit transactions only initialize locks and empty record tables; no function slots are modified during the loading phase.
    kswordArkPlatformAuditInitialize();
    // System variable-speed load phase prepares only synchronization and DPC; it does not modify the system time source before user confirmation.
    kswordArkSystemTimeInitialize();
    // Capture the immutable IDT baseline per CPU before making the device visible; failure only disables this diagnostic feature.
    status = kswordArkIdtBaselineInitialize();
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER, "KswordARKIdtBaselineInitialize unavailable %!STATUS!", status);
    }
    /*
     * HVM startup is read-only: capture CPU/MSR capability state now, while
     * all VMX/EPT allocations and tests remain explicit UI lifecycle actions.
     */
    status = kswordArkHvmInitialize();
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER, "KswordARKHvmInitialize unavailable %!STATUS!", status);
    }
    // initialize APC registration and unload drain event before the thread control IOCTL becomes visible.
    kswordArkThreadApcInitialize();

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    // Note: Must capture the I/O manager's kernel rejection entry point before the WdfDriverCreate framework dispatch is installed.
    status = kswordArkDriverCommunicationInitialize(driverObject);
    // Note: Communication control is optional; it cannot be proven that the kernel rejects the entry point by only disabling this feature.
    if (!NT_SUCCESS(status)) {
        // Note: Preserve other KSword capabilities while making new IOCTLs return DEVICE_NOT_READY.
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER, "KswordARKDriverCommunicationInitialize unavailable %!STATUS!", status);
    }

    // The generic IRP editor does not rely on blind target policies; it only initializes the transaction table and its own identity.
    status = kswordArkDriverDispatchInitialize(driverObject);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER, "KswordARKDriverDispatchInitialize unavailable %!STATUS!", status);
    }

    // The driver image editor saves its own identity; DynData/loader capabilities are resolved in real-time on each request.
    status = kswordArkDriverImageInitialize(driverObject);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER, "KswordARKDriverImageInitialize unavailable %!STATUS!", status);
    }
    /* Preallocate RXPF state; exact-build ABI mismatch remains a safe feature gate. */
    status = kswRxpfRuntimeInitialize(driverObject);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER,
            "KswRxpfRuntimeInitialize unavailable %!STATUS!", status);
    }


    // Register cleanup callback for WPP_CLEANUP during framework teardown.
    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.EvtCleanupCallback = kswordArkDriverEvtDriverContextCleanup;

    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.DriverInitFlags = WdfDriverInitNonPnpDriver;
    config.EvtDriverUnload = kswordArkDriverEvtDriverUnload;

    kswordArkStartupStage(kKswordArkStartStageWdfDriverCreate);
    status = WdfDriverCreate(
        driverObject,
        registryPath,
        &attributes,
        &config,
        &driverHandle);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "WdfDriverCreate failed %!STATUS!", status);
        // Symmetrically revert system speed state on framework failure to ensure DPC maintenance does not leave residues.
        /* No RXPF exception-visible allocation may survive DriverEntry failure. */
        kswRxpfRuntimeUninitialize();
        kswordArkPlatformAuditUninitialize();
        kswordArkSystemTimeUninitialize();
        // Note: On framework creation failure, revoke communication control state and all potential references.
        // First restore image fields and loader chain, then restore IRP/communication slots.
        kswordArkDriverImageUninitialize();
        kswordArkDriverDispatchUninitialize();
        kswordArkDriverCommunicationUninitialize();
        // Release the optional HVM capability state on early framework failure.
        kswordArkHvmUninitialize();
        // Release the boot-captured IDT table when framework creation fails.
        kswordArkIdtBaselineUninitialize();
        // On DriverEntry failure, close the APC receive state to maintain symmetry between initialization and exit paths.
        kswordArkThreadApcUninitialize();
        WPP_CLEANUP(driverObject);
        return kswordArkStartupFailure(kKswordArkStartStageWdfDriverCreate, status);
    }

    /*
     * Bind resident-HVM lifecycle guards only after KMDF installs the final
     * DriverUnload entry.  Failure keeps resident VMX disabled without taking
     * down the rest of the driver.
     */
    status = kswordArkHvmEnableResidentLifecycle(driverObject);
    if (!NT_SUCCESS(status)) {
        TraceEvents(
            TRACE_LEVEL_WARNING,
            TRACE_DRIVER,
            "Resident HVM lifecycle unavailable %!STATUS!",
            status);
    }

    // The internal phase of the control device is registered by kswordArkDriverCreateControlDevice itself.
    // On failure, it has already written the breadcrumb; this step only performs resource rollback.
    status = kswordArkDriverCreateControlDevice(driverHandle, &controlDevice);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "KswordARKDriverCreateControlDevice failed %!STATUS!", status);
        // When the device is hidden, no valid speed-change requests will occur; release its runtime state immediately.
        /* Restore any RXPF shadow IDT before the driver image can be discarded. */
        kswRxpfRuntimeUninitialize();
        kswordArkPlatformAuditUninitialize();
        kswordArkSystemTimeUninitialize();
        // Note: Do not retain communication control global state when device creation fails.
        // Image transactions may hold other DriverObject references; they must be released before returning on failure.
        kswordArkDriverImageUninitialize();
        kswordArkDriverDispatchUninitialize();
        kswordArkDriverCommunicationUninitialize();
        // Release the optional HVM capability state on early device failure.
        kswordArkHvmUninitialize();
        // Release the boot-captured IDT table when the control device is absent.
        kswordArkIdtBaselineUninitialize();
        // When the control device is unavailable, thread requests are rejected; immediately terminate the APC lifecycle management.
        kswordArkThreadApcUninitialize();
        WPP_CLEANUP(driverObject);
        return status;
    }

    // Process protection is attached to the pre-callback of object callbacks. The state must be initialized before registering the callback;
    // otherwise, the callback might read uninitialized configuration upon attachment. Allocation failure only disables the protection capability.
    status = kswordArkProcessProtectInitialize(controlDevice);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER,
            "KswordARKProcessProtectInitialize degraded %!STATUS!", status);
    }

    // Kernel callbacks are an optional capability and no longer a hard requirement for driver loading: altitude
    // conflicts, exhausted callback slots, or resource shortages on a specific machine will only disable that capability;
    // other KSword functions (driver, process, thread, memory, handle, kernel auditing, etc.) remain available.
    status = kswordArkCallbackInitialize(controlDevice);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER,
            "KswordARKCallbackInitialize degraded %!STATUS!", status);
    }
    // Write the actual registered callback capabilities into the breadcrumb so users can directly compare when reporting missing features.
    kswordArkStartupNoteCallbackMask(kswordArkCallbackGetRegisteredMask());

    status = kswordArkRedirectInitialize(driverObject, controlDevice);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER, "KswordARKRedirectInitialize recorded failure %!STATUS!", status);
    }

    status = kswordArkNetworkInitialize(driverObject, controlDevice);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER, "KswordARKNetworkInitialize recorded failure %!STATUS!", status);
    }

    status = kswordArkFileMonitorInitialize(driverObject, registryPath, controlDevice);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER, "KswordARKFileMonitorInitialize recorded failure %!STATUS!", status);
    }

#if KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED
    // DriverEntry prepares controllers only on demand to avoid scanning private BGP fields or registering bugcheck callbacks during normal loading.
    status = kswordArkBugcheckControlInitialize(driverObject, controlDevice);
    if (!NT_SUCCESS(status)) {
        TraceEvents(
            TRACE_LEVEL_WARNING,
            TRACE_DRIVER,
            "KswordARKBugcheckControlInitialize degraded %!STATUS!",
            status);
    }
    // Guard remains an independent, one-time debugging capability; initialization itself does not install a KeBugCheckEx hook.
    kswordArkBugcheckGuardInitialize();
    // Shield only prepares synchronization primitives and registers no BugCheck callbacks; R3 enables it explicitly via IOCTL.
    kswordArkBugcheckShieldInitialize();
#else
    // Fail closed while the crash-time renderer and guard are disabled.
    TraceEvents(
        TRACE_LEVEL_INFORMATION,
        TRACE_DRIVER,
        "KswordARK: driver-side bugcheck diagnostics disabled at build time");
#endif

    // Make the control device visible to user mode only after all runtime components are established.
    kswordArkStartupStage(kKswordArkStartStageControlDevicePublish);
    kswordArkDriverPublishControlDevice(controlDevice);

    // The final state record overwrites any failure record left by the previous startup.
    kswordArkStartupReady();
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit");
    return STATUS_SUCCESS;
}

VOID
kswordArkDriverEvtDriverUnload(
    _In_ WDFDRIVER driver
    )
/*++

Routine Description:

    Called when SCM requests to unload the non-PnP control driver.

Arguments:

    Driver - Handle to a WDF Driver object.

Return Value:

    VOID

--*/
{
    UNREFERENCED_PARAMETER(driver);

    PAGED_CODE();

    /* Restore every RXPF shadow IDTR and drain #PF readers before other teardown. */
    kswRxpfRuntimeUninitialize();

    // First restore the controlled HAL table edit records, then stop system time hooks; both only overwrite their respective last published values.
    kswordArkPlatformAuditUninitialize();
    kswordArkSystemTimeUninitialize();
    // Note: First restore MajorFunction entries still owned by this feature, then release the target DriverObject reference.
    // First, revoke any slot edits, then restore the five-slot communication blind that may be located underneath.
    // The image field or loader chain may contain self-identity; this must be restored before the driver image is unloaded.
    kswordArkDriverImageUninitialize();
    kswordArkDriverDispatchUninitialize();
    kswordArkDriverCommunicationUninitialize();
    // Release all VMX/VMCS/EPT pages before the driver image can leave memory.
    kswordArkHvmUninitialize();
    // Release the read-only IDT baseline after IOCTLs stop to avoid retaining driver-allocated resources after unloading.
    kswordArkIdtBaselineUninitialize();
    // Release the reference to the request process object held by the dangerous write transaction to prevent PID reuse.
    kswordArkMutationUninitialize();
    // Subsequently stop and flush all thread termination APCs that might callback to this driver image.
    kswordArkThreadApcUninitialize();
    // Directory enumeration may cache a directory handle for resuming the scan; it must be closed before driver unloading.
    kswordArkDriverResetDirectoryScanCache();

#if KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED
    // Restore Guard entry and Shield callbacks first, then release BGP resources.
    kswordArkBugcheckGuardUninitialize();
    kswordArkBugcheckShieldUninitialize();
    kswordArkBugcheckControlUninitialize();
#endif

    // Must unregister kernel debug callbacks first to prevent re-entering this driver code during subsequent unloading phases.
    kswordArkDebugOutputUninitialize();
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");
    kswordArkNetworkUninitialize();
    kswordArkRedirectUninitialize();
    // First, unregister to enter the minifilter at the callback rule layer and wait for all its post-operation callbacks to exit.
    kswordArkFileMonitorUninitialize();
    // Destroy the callback runtime only after the minifilter has stopped to prevent post-operation paths from accessing freed state.
    kswordArkCallbackUninitialize();
    // Object callbacks have already been unregistered in the previous step; no pre-call routines will read the protection configuration anymore, so it is safe to release.
    kswordArkProcessProtectUninitialize();
    kswordArkDynDataUninitialize();
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit");
}

VOID
kswordArkDriverEvtDriverContextCleanup(
    _In_ WDFOBJECT driverObject
    )
/*++

Routine Description:

    Free all the resources allocated in DriverEntry.

Arguments:

    DriverObject - handle to a WDF Driver object.

Return Value:

    VOID.

--*/
{
    UNREFERENCED_PARAMETER(driverObject);

    PAGED_CODE();

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    // Stop WPP tracing.
    WPP_CLEANUP(WdfDriverWdmGetDriverObject((WDFDRIVER)driverObject));
}
