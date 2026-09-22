#pragma once

#include "callback_internal.h"

EXTERN_C_START

VOID
kswordArkCallbackExtendedAddSelfBugcheckCallbacks(
    _Inout_ KswordArkCallbackEnumBuilder* builder
    );

VOID
kswordArkCallbackExtendedAddBugcheckCallbacks(
    _Inout_ KswordArkCallbackEnumBuilder* builder
    );

VOID
kswordArkCallbackExtendedAddObjectCallbacks(
    _Inout_ KswordArkCallbackEnumBuilder* builder
    );

VOID
kswordArkCallbackExtendedAddSystemCallbacks(
    _Inout_ KswordArkCallbackEnumBuilder* builder
    );

VOID
kswordArkCallbackExtendedAddNmiCallbacks(
    _Inout_ KswordArkCallbackEnumBuilder* builder
    );

VOID
kswordArkCallbackExtendedAddSpecialCallbacks(
    _Inout_ KswordArkCallbackEnumBuilder* builder
    );

EXTERN_C_END
