#pragma once

#include "ark/ark_driver.h"

EXTERN_C_START

typedef struct KswAlpcRuntimeBasicInfo
{
    ULONG flags;
    ULONG sequenceNo;
    PVOID portContext;
} KswAlpcRuntimeBasicInfo, *PkswAlpcRuntimeBasicInfo;

NTSTATUS
kswordArkAlpcQueryRuntimeBasicInfo(
    _In_ PEPROCESS processObject,
    _In_ ULONG64 handleValue,
    _Out_ KswAlpcRuntimeBasicInfo* basicInfoOut
    );

EXTERN_C_END
