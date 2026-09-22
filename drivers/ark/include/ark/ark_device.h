#pragma once

#include <wdf.h>
#include <wdfusb.h>

#include "ark_log.h"
#include "ark_debug_output.h"
#include "public.h"

EXTERN_C_START

// The device context performs the same job as a WDM device extension.
typedef struct DeviceContext {

    WDFUSBDEVICE usbDevice;
    ULONG privateDeviceData;
    WDFSPINLOCK logQueueLock;
    ULONG logQueueHeadIndex;
    ULONG logQueueTailIndex;
    ULONG logQueueCount;
    ULONG logEntryLength[KSWORD_ARK_LOG_RING_CAPACITY];
    CHAR logEntryText[KSWORD_ARK_LOG_RING_CAPACITY][KSWORD_ARK_LOG_ENTRY_MAX_BYTES];
    volatile LONG debugOutputCaptureEnabled;
    volatile LONG debugOutputWriterLock;
    volatile LONG64 debugOutputLatestSequence;
    volatile LONG64 debugOutputDroppedCount;
    NTSTATUS debugOutputRegistrationStatus;
    NTSTATUS debugOutputLastStatus;
    KswordArkDebugOutputSlot debugOutputSlots[KSWORD_ARK_DEBUG_OUTPUT_RING_CAPACITY];

} DeviceContext, *PdeviceContext;

// This macro will generate an inline function called DeviceGetContext
// which will be used to get a pointer to the device context memory
// in a type safe manner.
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DeviceContext, DeviceGetContext)

NTSTATUS
kswordArkDriverCreateDevice(
    _Inout_ PWDFDEVICE_INIT deviceInit
    );

NTSTATUS
kswordArkDriverCreateControlDevice(
    _In_ WDFDRIVER driver,
    _Out_opt_ WDFDEVICE* deviceOut
    );

// Control device creation and publication are separated: user-mode access is only allowed after all runtime initialization is complete.
VOID
kswordArkDriverPublishControlDevice(
    _In_ WDFDEVICE device
    );

// Function to select the device's USB configuration and get a WDFUSBDEVICE
// handle.
EVT_WDF_DEVICE_PREPARE_HARDWARE kswordArkDriverEvtDevicePrepareHardware;

EXTERN_C_END
