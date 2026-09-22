#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>

#include "ArkDriverIoTypes.h"
#include "../driver/KswordArkSecurityAuditIoctl.h"

namespace ksword::ark
{
    // SecurityStatusAuditResult carries CI/SecureBoot/VBS/SKCI/debug-mode fixed responses.
    // Input: return value of querySecurityStatus.
    // Handling: the response directly retains the shared protocol's fixed structure to facilitate UI display of all fields.
    // Return behavior: "unsupported" indicates the old driver lacks a security audit entry.
    struct SecurityStatusAuditResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_QUERY_SECURITY_STATUS_RESPONSE response{};
    };

    // DriverTrustViewAuditResult carries cross-view rows for loaded driver signatures and modules.
    // Input: Return value from queryDriverTrustView.
    // Handling: entries store the module name, imageBase, signingLevel, and conflictFlags.
    // Return behavior: Does not modify signature policies or bypass CI.
    struct DriverTrustViewAuditResult : VariableAuditResultBase
    {
        std::uint32_t fieldFlags = 0;
        std::uint32_t sourceMask = 0;
        std::uint32_t maxEntriesAccepted = 0;
        std::uint32_t truncated = 0;
        long moduleQueryStatus = 0;
        long signingResolverStatus = 0;
        std::vector<KSWORD_ARK_DRIVER_TRUST_VIEW_ENTRY> entries;
    };

    // HyperVSummaryAuditResult: Carries summaries of Hyper-V/VBS-related modules and CPUID fixes.
    // Input: Return value of queryHyperVSummary.
    // Note: response preserves vendor, module status, and sourceMask.
    // Return behavior: Read-only display; do not close Hyper-V or VBS.
    struct HyperVSummaryAuditResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_QUERY_HYPERV_SUMMARY_RESPONSE response{};
    };

    // AppControlStatusAuditResult carries read-only status for AppID, AppLocker, mssecflt, and BAM.
    // Input: Return value of queryAppControlStatus.
    // Handling: response preserves the callback owner module and module status.
    // Return behavior: Does not modify AppLocker/WDAC/CI policies.
    struct AppControlStatusAuditResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_QUERY_APP_CONTROL_STATUS_RESPONSE response{};
    };
}
