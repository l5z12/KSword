#pragma once

#include "ark/ark_dyndata.h"

EXTERN_C_START

// One accepted loaded-module filename and the DynData class assigned to it.
typedef struct KswKernelModuleNameMatch
{
    PCSTR fileName;
    ULONG classId;
} KswKernelModuleNameMatch, *PkswKernelModuleNameMatch;

NTSTATUS
kswordArkQueryKernelModuleIdentity(
    _In_reads_(nameMatchCount) const KswKernelModuleNameMatch* nameMatches,
    _In_ ULONG nameMatchCount,
    _Out_ KSW_DYN_MODULE_IDENTITY_PACKET* identityOut
    );

EXTERN_C_END
