#pragma once

#include "ark/ark_dyndata.h"

EXTERN_C_START

LONG
kswordArkDriverResolveShadowSsdtRva(
    _In_ const KSW_DYN_MODULE_IDENTITY_PACKET* ntoskrnlIdentity
    );

EXTERN_C_END
