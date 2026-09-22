#pragma once

#include "ark/ark_driver.h"
#include "driver/KswordArkUnloadedDriverIoctl.h"

EXTERN_C_START

// Only enumerate a specified source and write unsupported source or missing layout into the protocol business status.
NTSTATUS
kswordArkQueryUnloadedDrivers(
    _In_ const KSWORD_ARK_QUERY_UNLOADED_DRIVERS_REQUEST* request,
    _Out_writes_bytes_to_(outputBufferLength, *bytesWritten)
        KSWORD_ARK_QUERY_UNLOADED_DRIVERS_RESPONSE* response,
    _In_ SIZE_T outputBufferLength,
    _Out_ SIZE_T* bytesWritten
    );

// The WDF adapter is only responsible for retrieving the METHOD_BUFFERED buffer and invoking the function implementation.
NTSTATUS
kswordArkKernelIoctlQueryUnloadedDrivers(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    );

EXTERN_C_END
