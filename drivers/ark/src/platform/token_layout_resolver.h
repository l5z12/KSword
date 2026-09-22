#pragma once

#include <ntifs.h>

EXTERN_C_START

LONG
kswordArkDriverResolveProcessTokenOffset(
    _In_ PEPROCESS process,
    _In_ PACCESS_TOKEN token
    );

VOID
kswordArkDriverResolveTokenLayoutOffsets(
    _In_ PACCESS_TOKEN token,
    _Out_ LONG* userAndGroupCountOffsetOut,
    _Out_ LONG* userAndGroupsOffsetOut,
    _Out_ LONG* integrityLevelIndexOffsetOut,
    _Out_ LONG* mandatoryPolicyOffsetOut
    );

EXTERN_C_END
