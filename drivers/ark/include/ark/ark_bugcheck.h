#pragma once

#include <ntddk.h>
#include <wdf.h>

#include "driver/KswordArkBugcheckIoctl.h"

EXTERN_C_START

// Build gate for the complete driver-side blue screen diagnostic path. The
// default development image enables it; this does not affect the rest of the
// driver, Windows' native blue screen, dump creation, or user-mode dump UI.
#ifndef KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED
#define KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED 1
#endif

#if KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED != 0 && \
    KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED != 1
#error KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED must be 0 or 1
#endif

// The lightweight controller only stores the driver object and initializes synchronization primitives; it does not parse ntoskrnl or register bugcheck callbacks.
// DriverEntry calls initialize; Uninitialize is called before driver unloading. Actual diagnostics are installed on-demand via configuration IOCTLs.
NTSTATUS
kswordArkBugcheckControlInitialize(
    _In_ PDRIVER_OBJECT driverObject,
    _In_ WDFDEVICE controlDevice
    );

VOID
kswordArkBugcheckControlUninitialize(
    VOID
    );

// Resolve the physical-machine BGP backend, prepare every crash-time rectangle
// at PASSIVE_LEVEL, and register dump-preserving bugcheck callbacks. Missing
// private features leave the renderer fail-closed without blocking diagnostics.
NTSTATUS
kswordArkBugcheckInitialize(
    _In_ PDRIVER_OBJECT driverObject,
    _In_ WDFDEVICE controlDevice
    );

// Deregister callbacks before destroying the prebuilt BGP rectangles.
VOID
kswordArkBugcheckUninitialize(
    VOID
    );

// Feed the crash-safe process/module identity caches from the driver's existing
// notify callbacks. Writers run before a crash; the bugcheck path only reads
// fixed nonpaged snapshots and never dereferences an arbitrary crash parameter.
VOID
kswordArkBugcheckTrackProcess(
    _In_ PEPROCESS process,
    _In_ HANDLE processId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO createInfo
    );

VOID
kswordArkBugcheckTrackLoadedImage(
    _In_opt_ PUNICODE_STRING fullImageName,
    _In_ HANDLE processId,
    _In_ PIMAGE_INFO imageInfo
    );

NTSTATUS
kswordArkBugcheckIoctlConfigureDiagnostics(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    );

// Optional bitmap upload adapter registered through ioctl_registry.c.
NTSTATUS
kswordArkBugcheckIoctlSetBitmap(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    );

NTSTATUS
kswordArkBugcheckIoctlSetVerdictResources(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    );


// initialize and tear down the independent BugCheck guard with persistent ignore mode.
// HVCI systems use a delay-only callback; other systems may use the exported
// KeBugCheckEx entry hook and must restore it before driver unload. The guard
// is intentionally not coupled to the optional VMware panel.
VOID
kswordArkBugcheckGuardInitialize(
    VOID
    );

VOID
kswordArkBugcheckGuardUninitialize(
    VOID
    );

NTSTATUS
kswordArkBugcheckGuardIoctlConfigure(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    );

// Bugcheck Shield is a PatchGuard-safe buffer backend. Unlike the guard, it
// never patches KeBugCheckEx and never writes any private ntoskrnl state; it
// only registers up to four documented BugCheck reason callbacks and stalls
// each callback for a configurable, bounded window. Enabling and disabling
// stay fully R3-controlled, and DriverEntry only prepares the synchronization
// primitives — nothing observable happens until an IOCTL explicitly enables it.
VOID
kswordArkBugcheckShieldInitialize(
    VOID
    );

VOID
kswordArkBugcheckShieldUninitialize(
    VOID
    );

NTSTATUS
kswordArkBugcheckShieldIoctlConfigure(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    );

EXTERN_C_END
