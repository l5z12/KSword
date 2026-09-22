#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "driver/KswordArkSectionIoctl.h"

EXTERN_C_START

NTSTATUS
kswordArkDriverQueryProcessSection(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_QUERY_PROCESS_SECTION_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkDriverQueryFileSectionMappings(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_QUERY_FILE_SECTION_MAPPINGS_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

EXTERN_C_END
