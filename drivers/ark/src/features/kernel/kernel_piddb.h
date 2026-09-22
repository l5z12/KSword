#pragma once

#include "ark/ark_driver.h"
#include "driver/KswordArkPiDdbIoctl.h"

EXTERN_C_START

NTSTATUS
kswordArkPiDdbQuery(
    _In_ const KSWORD_ARK_QUERY_PIDDB_REQUEST* request,
    _Out_writes_bytes_to_(outputBufferLength, *bytesWritten)
        KSWORD_ARK_QUERY_PIDDB_RESPONSE* response,
    _In_ SIZE_T outputBufferLength,
    _Out_ SIZE_T* bytesWritten
    );

NTSTATUS
kswordArkPiDdbDelete(
    _In_ const KSWORD_ARK_DELETE_PIDDB_REQUEST* request,
    _Out_ KSWORD_ARK_DELETE_PIDDB_RESPONSE* response
    );

EXTERN_C_END
