/*++

Module Name:

    hvm_mtrr.h

Abstract:

    Captures Intel MTRR state and resolves conservative EPT memory types.

Environment:

    Kernel-mode Driver Framework.

--*/

#pragma once

#include "hvm_internal.h"

EXTERN_C_START

/* Capture one immutable MTRR snapshot on the preparing processor. */
NTSTATUS
kswordArkHvmMtrrCapture(
    _Out_ KswHvmMtrrState* state
    );

/* Resolve one range to a uniform EPT memory type or conservative UC. */
UCHAR
kswordArkHvmMtrrResolveRangeType(
    _In_ const KswHvmMtrrState* state,
    _In_ ULONGLONG physicalAddress,
    _In_ ULONGLONG byteCount
    );

EXTERN_C_END
