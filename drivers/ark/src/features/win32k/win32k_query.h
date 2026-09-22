#pragma once

#include "ark/ark_driver.h"
#include "ark/ark_ioctl.h"

EXTERN_C_START

NTSTATUS
kswordArkWin32kQueryProfileStatus(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_WIN32K_QUERY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkWin32kQueryWindowSnapshot(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_WIN32K_QUERY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkWin32kQueryGuiThreadSnapshot(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_WIN32K_QUERY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkWin32kQueryHotkeySnapshot(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_WIN32K_QUERY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkWin32kQueryHookSnapshot(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_WIN32K_QUERY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkWin32kQueryTimerSnapshot(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_WIN32K_QUERY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkWin32kQueryEventHookSnapshot(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_WIN32K_QUERY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkWin32kQueryWindowDetail(
    _Out_writes_bytes_(outputBufferLength) KSWORD_ARK_WIN32K_WINDOW_DETAIL_RESPONSE* response,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_WIN32K_WINDOW_DETAIL_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

EXTERN_C_END
