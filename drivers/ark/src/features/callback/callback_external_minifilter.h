#pragma once

#include "callback_internal.h"

EXTERN_C_START

VOID
kswordArkCallbackExternalMinifilterAddCallbacks(
    _Inout_ KswordArkCallbackEnumBuilder* builder
    );

NTSTATUS
kswordArkCallbackExternalMinifilterRemove(
    _In_ const KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_REQUEST* requestPacket,
    _Inout_ KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_RESPONSE* responsePacket
    );

EXTERN_C_END
