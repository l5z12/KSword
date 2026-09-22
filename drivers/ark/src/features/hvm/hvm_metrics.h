#pragma once

#include "ark/ark_driver.h"
#include "driver/KswordArkHvmMetricsIoctl.h"

/* Lifecycle serialization belongs to the existing HVM control lock. */
VOID kswordArkHvmMetricsBegin(ULONG command);
VOID kswordArkHvmMetricsEnd(NTSTATUS status);
VOID kswordArkHvmMetricsStamp(ULONG stage);
VOID kswordArkHvmMetricsCpuStamp(ULONG index, ULONG stage);
VOID kswordArkHvmMetricsAllocation(BOOLEAN replacement, BOOLEAN free);
NTSTATUS kswordArkHvmMetricsQuery(KSWORD_ARK_HVM_METRICS_RESPONSE* response);

/* Caller holds the runtime resource lock; values remain observational. */
VOID kswordArkHvmResidentMetrics(KSWORD_ARK_HVM_METRICS_RESPONSE* response);
