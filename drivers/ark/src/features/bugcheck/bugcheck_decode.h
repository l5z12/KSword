#pragma once

#include "bugcheck_internal.h"

// Decode only stop-code parameters that Microsoft documents as a direct
// instruction/module address. Object pointers, reserved fields, and subtype-
// dependent data must not be promoted into a faulting-module claim.
BOOLEAN
kswordArkBugcheckDecodePrimaryAddress(
    _Inout_ PkswordArkBugcheckDiagnostics diagnostics,
    _Out_ PULONG_PTR address,
    _Out_ PULONG parameterIndex,
    _Out_ PULONG confidence
    );

// Return the documented semantic role of one raw stop-code parameter.  The
// returned labels are deliberately short enough for the crash-safe panel.
PCSTR
kswordArkBugcheckDecodeParameterRole(
    _In_ const KswordArkBugcheckDiagnostics* diagnostics,
    _In_ ULONG parameterIndex
    );
