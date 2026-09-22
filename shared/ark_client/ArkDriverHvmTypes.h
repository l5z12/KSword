#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>

#include "ArkDriverIoTypes.h"
#include "../driver/KswordArkHvmIoctl.h"
#include "../driver/KswordArkHvmMetricsIoctl.h"
#include "../driver/KswordArkSlatIommuAuditIoctl.h"

namespace ksword::ark
{
    // HvmStatusResult preserves the complete VT-x/EPT capability and lifecycle
    // snapshot. A prepared or self-tested response is not an active hypervisor.
    struct HvmStatusResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_QUERY_HVM_RESPONSE response{};
    };

    // Metrics are independently versioned; validity flags define usable intervals.
    struct HvmMetricsResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_HVM_METRICS_RESPONSE response{};
    };

    // HvmControlResult carries one generation-bound prepare, self-test, or
    // teardown result. The UI owns all persistent warnings and typed consent.
    struct HvmControlResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_CONTROL_HVM_RESPONSE response{};
    };

    // HvmViewResult carries one EPT split-view operation. rows is only filled
    // by QUERY; every other operation leaves it empty.
    struct HvmViewResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_HVM_VIEW_RESPONSE response{};
    };

    // HvmProcessResult carries a single R-1 process disposition. Every operation fills the entire table because the caller
    // issuing the disposition immediately needs to know which layer it fell into and how many times it was intercepted.
    struct HvmProcessResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_HVM_PROCESS_RESPONSE response{};
    };

    // HvmInjectResult carries a single R-1 process injection. The table reports the address of the **gap page** and the padding bytes used in
    // that gap—these two values (where the shellcode lands and which padding scheme is used) are the only useful data for troubleshooting. The
    // shadow page and the real page for the trigger page are byte-for-byte identical; reporting them would falsely suggest the page was modified.
    struct HvmInjectResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_HVM_INJECT_RESPONSE response{};
    };

    // HvmDomainResult carries one EPT execution-domain operation. rows are
    // filled on every operation, because a caller that just created or
    // restricted a domain needs to see the resulting shape immediately.
    struct HvmDomainResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_HVM_DOMAIN_RESPONSE response{};
    };

    // HvmMsrPolicyResult carries one MSR policy operation. rows is only
    // filled by QUERY; every other operation leaves it empty.
    struct HvmMsrPolicyResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_HVM_MSR_POLICY_RESPONSE response{};
    };

    // HvmCrPolicyResult carries one control-register policy operation.
    struct HvmCrPolicyResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_HVM_CR_POLICY_RESPONSE response{};
    };

    // HvmMemoryResult carries one ring -1 memory access. usedDirectWindow
    // distinguishes the hook-free private-window path from the documented
    // MmCopyMemory fallback, so a caller can tell which one actually ran.
    struct HvmMemoryResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_HVM_MEMORY_RESPONSE response{};
    };

    // HvmPlatformResult carries one read-only platform calibration.
    //
    // This probe **does not enter VMX, does not allocate, and does not lock**, so it can
    // run in any state, including 'nothing is ready yet' and 'resident and running'.
    //
    // When validating, first check response.validMask: each field has its own independent valid bit, because 0
    // is a **legal value** for many quantities. Treating a failed read as 0 is worse than not reading at all.
    // If the 8-bit value is incomplete, it means 'this round of calibration is not finished'; do not draw conclusions from it.
    struct HvmPlatformResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_HVM_PLATFORM_RESPONSE response{};
    };

    // Read-only EPT/NPT cross-view and IOMMU firmware/runtime evidence.
    // A clean guest-visible result cannot prove an opaque outer SLAT is clean.
    struct SlatIommuAuditResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_RESPONSE response{};
    };

    // HvmEptRuleResult preserves one generation-bound EPT rule mutation or
    // query. The response exposes explicit implementation maturity and never
    // treats a prepared table as an active resident monitor.
    struct HvmEptRuleResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_HVM_EPT_RULE_RESPONSE response{};
    };

    // HvmEventResult carries a bounded event-ring page. Clearing the ring is a
    // separate explicit operation and does not alter EPT rules or VMX state.
    struct HvmEventResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_HVM_EVENT_QUERY_RESPONSE response{};
    };
}
