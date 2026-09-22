#pragma once

#include <wdf.h>

// Maximum bytes per single log frame (including trailing NUL room).
#define KSWORD_ARK_LOG_ENTRY_MAX_BYTES 512

// Ring queue capacity in log-frame units.
#define KSWORD_ARK_LOG_RING_CAPACITY 64

EXTERN_C_START

NTSTATUS
kswordArkDriverInitializeLogChannel(
    _In_ WDFDEVICE device
    );

NTSTATUS
kswordArkDriverEnqueueLogLine(
    _In_ WDFDEVICE device,
    _In_z_ PCSTR formattedLogLine
    );

NTSTATUS
kswordArkDriverEnqueueLogFrame(
    _In_ WDFDEVICE device,
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR messageText
    );

NTSTATUS
kswordArkDriverReadNextLogLine(
    _In_ WDFDEVICE device,
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    );

EXTERN_C_END
