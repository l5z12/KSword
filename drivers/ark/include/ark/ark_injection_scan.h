#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "driver/KswordArkInjectionScanIoctl.h"

EXTERN_C_START

NTSTATUS
kswordArkDriverEnumerateProcessVad(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_ENUMERATE_PROCESS_VAD_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkDriverScanProcessExecutablePte(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_SCAN_PROCESS_EXECUTABLE_PTE_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkDriverReadImageSectionPages(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_READ_IMAGE_SECTION_PAGES_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

EXTERN_C_END
