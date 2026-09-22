/*++

Module Name:

    device_control.c

Abstract:

    This file contains control-device creation and compatibility PnP path.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "device_control.tmh"

#include <wdmsec.h>

#include "KswordArkLogProtocol.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text (PAGE, kswordArkDriverCreateDevice)
#pragma alloc_text (PAGE, kswordArkDriverCreateControlDevice)
#pragma alloc_text (PAGE, kswordArkDriverPublishControlDevice)
#pragma alloc_text (PAGE, kswordArkDriverEvtDevicePrepareHardware)
#endif

/*
 * Control device security: SYSTEM full, Administrators read/write/execute.
 * Nobody else can open it at all.
 *
 * World and Restricted used to hold GENERIC_READ here, on the reasoning that
 * reading the log stream is harmless.  That reasoning does not survive contact
 * with how the IOCTLs are declared: FILE_ANY_ACCESS tells the I/O manager to
 * perform no access check on the request, so a read-only handle can issue any
 * IOCTL declared that way.  101 of them still are.  The effect was that every
 * user on the machine could reach a hundred kernel entry points through a
 * handle the descriptor described as read-only.
 *
 * Removing the two ACEs costs nothing in this repository.  Every consumer -
 * including the one that opens with GENERIC_READ alone to read the log stream -
 * also performs read/write operations elsewhere, so all of them already require
 * Administrators, and Administrators keep GENERIC_READ through the BA entry.
 * What changes is that a non-administrator can no longer open the device, which
 * is the whole of the unprivileged reach.
 *
 * This narrows who may knock.  It does not make the 101 FILE_ANY_ACCESS
 * declarations correct - an IOCTL that mutates state should say so in its
 * control code, so that a read-only handle held by an administrator is refused
 * too.  That work is separate and still open.
 */
static const WCHAR kGKswordArkControlDeviceSddl[] =
    L"D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)";

NTSTATUS
kswordArkDriverCreateControlDevice(
    _In_ WDFDRIVER driver,
    _Out_opt_ WDFDEVICE* deviceOut
    )
/*++

Routine Description:

    Create a control device used by R3 to read driver log stream. The device is
    fully built here but stays unpublished: kswordArkDriverPublishControlDevice
    must be called once every dependent runtime is up, so R3 can never open the
    device while callback state is still being assembled.

Arguments:

    Driver - WDF driver handle created in DriverEntry.
    DeviceOut - Receives the created (still unpublished) control device.

Return Value:

    NTSTATUS

--*/
{
    PWDFDEVICE_INIT deviceInit = NULL;
    WDFDEVICE device = WDF_NO_HANDLE;
    WDF_OBJECT_ATTRIBUTES deviceAttributes;
    UNICODE_STRING sddlText;
    NTSTATUS status = STATUS_SUCCESS;

    DECLARE_CONST_UNICODE_STRING(deviceName, KSWORD_ARK_LOG_DEVICE_NT_NAME);
    DECLARE_CONST_UNICODE_STRING(symbolicName, KSWORD_ARK_LOG_DOS_NAME);

    PAGED_CODE();

    if (deviceOut != NULL) {
        *deviceOut = WDF_NO_HANDLE;
    }

    RtlInitUnicodeString(&sddlText, kGKswordArkControlDeviceSddl);
    kswordArkStartupStage(kKswordArkStartStageControlInitAllocate);
    deviceInit = WdfControlDeviceInitAllocate(driver, &sddlText);
    if (deviceInit == NULL) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DEVICE, "WdfControlDeviceInitAllocate failed");
        return kswordArkStartupFailure(
            kKswordArkStartStageControlInitAllocate,
            STATUS_INSUFFICIENT_RESOURCES);
    }

    kswordArkStartupStage(kKswordArkStartStageDeviceAssignName);
    status = WdfDeviceInitAssignName(deviceInit, &deviceName);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DEVICE, "WdfDeviceInitAssignName failed %!STATUS!", status);
        WdfDeviceInitFree(deviceInit);
        return kswordArkStartupFailure(kKswordArkStartStageDeviceAssignName, status);
    }

    WdfDeviceInitSetDeviceType(deviceInit, FILE_DEVICE_UNKNOWN);
    WdfDeviceInitSetExclusive(deviceInit, FALSE);
    WdfDeviceInitSetIoType(deviceInit, WdfDeviceIoBuffered);
    WdfDeviceInitSetIoInCallerContextCallback(deviceInit, kswordArkDriverEvtIoInCallerContext);

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, DeviceContext);
    kswordArkStartupStage(kKswordArkStartStageDeviceCreate);
    status = WdfDeviceCreate(&deviceInit, &deviceAttributes, &device);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DEVICE, "WdfDeviceCreate(control) failed %!STATUS!", status);
        if (deviceInit != NULL) {
            WdfDeviceInitFree(deviceInit);
        }
        // Fixed device name conflicts (e.g., from an old instance not fully unloaded) are logged here as a locatable stage.
        return kswordArkStartupFailure(kKswordArkStartStageDeviceCreate, status);
    }

    kswordArkStartupStage(kKswordArkStartStageLogChannel);
    status = kswordArkDriverInitializeLogChannel(device);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DEVICE, "KswordARKDriverInitializeLogChannel failed %!STATUS!", status);
        WdfObjectDelete(device);
        return kswordArkStartupFailure(kKswordArkStartStageLogChannel, status);
    }

    // initialize the kernel debug output circular buffer; register system callbacks only when the user explicitly starts capturing.
    kswordArkStartupStage(kKswordArkStartStageDebugOutput);
    status = kswordArkDebugOutputInitialize(device);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DEVICE, "KswordARKDebugOutputInitialize failed %!STATUS!", status);
        WdfObjectDelete(device);
        return kswordArkStartupFailure(kKswordArkStartStageDebugOutput, status);
    }

    kswordArkStartupStage(kKswordArkStartStageSymbolicLink);
    status = WdfDeviceCreateSymbolicLink(device, &symbolicName);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DEVICE, "WdfDeviceCreateSymbolicLink failed %!STATUS!", status);
        WdfObjectDelete(device);
        // A symbolic link conflict also points to another existing KswordARK instance on the machine.
        return kswordArkStartupFailure(kKswordArkStartStageSymbolicLink, status);
    }

    kswordArkStartupStage(kKswordArkStartStageDefaultQueue);
    status = kswordArkDriverQueueInitialize(device, FALSE);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DEVICE, "KswordARKDriverQueueInitialize(control) failed %!STATUS!", status);
        WdfObjectDelete(device);
        // When WdfIoQueueCreate returns STATUS_UNSUCCESSFUL, this is the only place to record the original status.
        return kswordArkStartupFailure(kKswordArkStartStageDefaultQueue, status);
    }

    status = kswordArkDynDataInitialize(device);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_DEVICE, "KswordARKDynDataInitialize recorded failure %!STATUS!", status);
    }

    status = kswordArkDriverEnqueueLogFrame(device, "Info", "KswordARK driver started.");
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DEVICE, "KswordARKDriverEnqueueLogFrame(startup) failed %!STATUS!", status);
    }

    if (deviceOut != NULL) {
        *deviceOut = device;
    }
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DEVICE, "Control log device created successfully");
    return STATUS_SUCCESS;
}

VOID
kswordArkDriverPublishControlDevice(
    _In_ WDFDEVICE device
    )
/*++

Routine Description:

    Make the control device visible to user mode. Creating and publishing are
    kept apart on purpose: WdfControlFinishInitializing used to run before the
    callback runtime existed, which let R3 reach IOCTL handlers whose backing
    state was still being built.

Arguments:

    Device - Control device returned by kswordArkDriverCreateControlDevice.

Return Value:

    VOID

--*/
{
    PAGED_CODE();

    // All runtime dependencies are ready; only then are I/O manager dispatch requests allowed.
    WdfControlFinishInitializing(device);
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DEVICE, "Control log device published");
}

NTSTATUS
kswordArkDriverCreateDevice(
    _Inout_ PWDFDEVICE_INIT deviceInit
    )
/*++

Routine Description:

    Keep a minimal PnP path for compatibility; primary path is control device.

Arguments:

    DeviceInit - Framework-allocated init structure.

Return Value:

    NTSTATUS

--*/
{
    WDF_PNPPOWER_EVENT_CALLBACKS pnpPowerCallbacks;
    WDF_OBJECT_ATTRIBUTES deviceAttributes;
    WDFDEVICE device = WDF_NO_HANDLE;
    PdeviceContext deviceContext = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    PAGED_CODE();

    WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnpPowerCallbacks);
    pnpPowerCallbacks.EvtDevicePrepareHardware = kswordArkDriverEvtDevicePrepareHardware;
    WdfDeviceInitSetPnpPowerEventCallbacks(deviceInit, &pnpPowerCallbacks);
    WdfDeviceInitSetIoInCallerContextCallback(deviceInit, kswordArkDriverEvtIoInCallerContext);

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, DeviceContext);
    status = WdfDeviceCreate(&deviceInit, &deviceAttributes, &device);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DEVICE, "WdfDeviceCreate(PnP) failed %!STATUS!", status);
        return status;
    }

    deviceContext = DeviceGetContext(device);
    deviceContext->usbDevice = WDF_NO_HANDLE;
    deviceContext->privateDeviceData = 0U;

    status = kswordArkDriverInitializeLogChannel(device);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // PnP device paths must also have a complete debug output context to avoid IOCTL access to uninitialized states.
    status = kswordArkDebugOutputInitialize(device);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = WdfDeviceCreateDeviceInterface(
        device,
        &GUID_DEVINTERFACE_KswordARKDriver,
        NULL);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DEVICE, "WdfDeviceCreateDeviceInterface failed %!STATUS!", status);
        return status;
    }

    // Compatible with PnP devices participating in power management, so the queue retains power management semantics and EvtIoStop by default.
    status = kswordArkDriverQueueInitialize(device, TRUE);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = kswordArkDynDataInitialize(device);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_DEVICE, "KswordARKDynDataInitialize(PnP) recorded failure %!STATUS!", status);
    }

    (void)kswordArkDriverEnqueueLogFrame(device, "Info", "KswordARK PnP device initialized.");
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkDriverEvtDevicePrepareHardware(
    _In_ WDFDEVICE device,
    _In_ WDFCMRESLIST resourceList,
    _In_ WDFCMRESLIST resourceListTranslated
    )
/*++

Routine Description:

    Placeholder callback retained for compatibility.

Arguments:

    Device - Framework device handle.
    ResourceList - Raw resource list.
    ResourceListTranslated - Translated resource list.

Return Value:

    NTSTATUS

--*/
{
    UNREFERENCED_PARAMETER(device);
    UNREFERENCED_PARAMETER(resourceList);
    UNREFERENCED_PARAMETER(resourceListTranslated);

    PAGED_CODE();

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DEVICE, "%!FUNC! Entry");
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DEVICE, "%!FUNC! Exit");
    return STATUS_SUCCESS;
}
