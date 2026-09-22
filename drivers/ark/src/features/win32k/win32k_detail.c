/*++

Module Name:

    win32k_detail.c

Abstract:

    Read-only single-window detail adapter.

Environment:

    Kernel-mode Driver Framework

--*/

#include "win32k_query.h"
#include "win32k_fallback.h"

NTSTATUS
kswordArkWin32kQueryWindowDetail(
    _Out_writes_bytes_(outputBufferLength) KSWORD_ARK_WIN32K_WINDOW_DETAIL_RESPONSE* response,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_WIN32K_WINDOW_DETAIL_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Resolve one HWND through the validated runtime-signature fallback.  The
    backend rejects ambiguous identities and never trusts a caller-supplied
    tagWND address.

--*/
{
    if (request == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    return kswordArkWin32kFallbackQueryWindowDetail(
        response,
        outputBufferLength,
        request,
        bytesWrittenOut);
}
