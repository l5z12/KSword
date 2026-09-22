#pragma once

#include "driver_integrity.h"

EXTERN_C_START

NTSTATUS
kswordArkCpuIntegrityCollect(
    _Inout_ KswDriverIntegrityBuilder* builder,
    _In_opt_ const KswHookSystemModuleInformation* moduleInfo,
    _In_ ULONG flags,
    _In_ ULONG maxIdtVectorsPerCpu,
    _Out_ ULONG* cpuCountOut
    );

EXTERN_C_END
