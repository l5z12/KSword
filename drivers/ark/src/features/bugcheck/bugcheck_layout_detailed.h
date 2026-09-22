#pragma once

#include "bugcheck_layout.h"

NTSTATUS
kswordArkBugcheckLayoutDrawDetailed(
    _In_ const KswordArkBugcheckLayoutCanvas* canvas,
    _In_ const KswordArkBugcheckDiagnostics* diagnostics,
    _In_ ULONG callbackMask,
    _In_ ULONG moduleCount
    );
