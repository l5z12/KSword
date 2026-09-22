/*++

Module Name:

    minifilter_runtime_link.c

Abstract:

    Links the callback-rule runtime to the shared file-monitor minifilter.

Environment:

    Kernel-mode Driver Framework

--*/

#include "callback_internal.h"

VOID
kswordArkMinifilterCallbackUpdateState(
    _In_opt_ PFLT_FILTER filterHandle,
    _In_ NTSTATUS registerStatus,
    _In_ NTSTATUS startStatus,
    _In_ BOOLEAN started
    )
{
    KswordArkCallbackRuntime* runtime = kswordArkCallbackGetRuntime();

    if (runtime == NULL) {
        return;
    }

    if (runtime->miniFilterHandle == NULL && filterHandle != NULL) {
        kswordArkCallbackLogFrame("Info", "Minifilter custom callback linked to file-monitor runtime.");
    }

    runtime->miniFilterHandle = filterHandle;
    runtime->miniFilterRegisterStatus = registerStatus;
    runtime->miniFilterStartStatus = startStatus;
    runtime->miniFilterStarted = started;

    if (filterHandle != NULL && NT_SUCCESS(registerStatus)) {
        runtime->registeredCallbacksMask |= KSWORD_ARK_CALLBACK_REGISTERED_MINIFILTER;
    }
    else {
        runtime->registeredCallbacksMask &= ~KSWORD_ARK_CALLBACK_REGISTERED_MINIFILTER;
    }
}

VOID
kswordArkMinifilterCallbackUnregister(
    _In_ KswordArkCallbackRuntime* runtime
    )
{
    if (runtime == NULL) {
        return;
    }

    runtime->miniFilterHandle = NULL;
    runtime->miniFilterStarted = FALSE;
    runtime->miniFilterRegisterStatus = STATUS_NOT_SUPPORTED;
    runtime->miniFilterStartStatus = STATUS_NOT_SUPPORTED;
    runtime->registeredCallbacksMask &= ~KSWORD_ARK_CALLBACK_REGISTERED_MINIFILTER;
    kswordArkCallbackLogFrame("Info", "Minifilter custom callback unlinked from callback runtime.");
}
