#pragma once

#include <ntddk.h>
#include "driver/KswordArkCpuPowerIoctl.h"

EXTERN_C_START

// kswordArkCpuPowerQuerySnapshot: Read CPUID and whitelisted Intel power MSRs, then generate a fixed response.
NTSTATUS
kswordArkCpuPowerQuerySnapshot(
    _Out_ KSWORD_ARK_CPU_POWER_RESPONSE* response
    );

// kswordArkCpuPowerApply: Validates the request, modifies whitelist fields across logical processors, and performs a write-back read.
NTSTATUS
kswordArkCpuPowerApply(
    _In_ const KSWORD_ARK_CPU_POWER_CONTROL_REQUEST* request,
    _Out_ KSWORD_ARK_CPU_POWER_RESPONSE* response
    );

EXTERN_C_END
