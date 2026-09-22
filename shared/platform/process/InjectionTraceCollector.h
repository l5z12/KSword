#pragma once

// Collector for process injection trace inspection (Issue #196 Phase 1).
//
// Responsibility: This layer only handles "reading the scene"; all criteria are in shared/evidence/InjectionSurvey.h.
// The collector does not generate conclusions, and rules must not be added here — rules belong in the pure criteria layer, which has offline testing.
//
// Boundary (placed here so that anyone making changes sees it first):
//   * Start with minimal permissions: first PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ; only fall
//     back to PROCESS_QUERY_INFORMATION | PROCESS_VM_READ on failure. Never request PROCESS_ALL_ACCESS. When
//     access to a protected process is denied, output "Access Restricted" instead of "No Injection Found".
//   * Hold the same handle throughout. Verify PID + creation time at both start and end. If identity changes,
//     invalidate the entire record—otherwise evidence may be attributed to a different process instance.
//   * Fast mode does not suspend the target, does not modify the target page protection attributes, and does not capture the context of running threads.
//   * Any read failure, budget overrun, or path query failure is carried
//     into the SurveyReport gap as-is, without folding into "clean".

#include "../../evidence/InjectionSurvey.h"
// Protocol constants for the R0 scanning backend (entries/table read limits). The protocol is defined
// only in shared/driver; this file references it rather than duplicating the numeric values locally.
#include "../../driver/KswordArkInjectionScanIoctl.h"

#include <QString>

#include <cstdint>

namespace ks::process
{
    // Collection budget. Does not promise "fast scan takes a few hundred milliseconds"; only promises that the report will show the hit limit when reached.
    struct InjectionTraceOptions
    {
        bool deepMode = false;                      // Deep mode: all executable image ranges.
        std::uint32_t maxRegionCount = 262144U;     // Maximum number of entries for VirtualQueryEx.
        std::uint32_t maxImageComparisons = 4096U;  // Compare target limit
        std::uint64_t maxReadBytes = 64ULL * 1024ULL * 1024ULL;
        std::uint64_t maxDurationMs = 30000ULL;
        std::uint32_t maxThreads = 4096U;
        std::uint32_t maxPayloadProbeBytes = 4096U; // Number of bytes to read from each candidate region for structure validation.

        // R0 scanning backend (VAD tree + user-mode executable page table leaves). Capability gating:
        // automatically degrade to R3 if the driver is unloaded, lacks permissions, or DynData
        // offsets haven't been verified for the current build; R3 results are still produced.
        bool useKernelBackend = true;
        std::uint32_t kernelVadMaxEntries = 8192U;
        // Set protocol limit: testing shows explorer.exe requires 7266 segments; completing the process in
        // a single run prevents ending with Partial each time, thereby avoiding a permanent coverage gap.
        std::uint32_t kernelPteMaxEntries = KSWORD_ARK_INJECTION_PTE_LIMIT_MAX;
        std::uint32_t kernelPteMaxTableReads = 65536U;
    };

    enum class InjectionTraceStatus : std::uint8_t
    {
        kCompleted = 0,
        kProcessIdentityUnavailable,  // Creation time unavailable: identity cannot be confirmed.
        kProcessIdentityMismatch,     // PID reused
        kProcessOpenDenied,           // Insufficient permissions (e.g., protected process).
        kProcessOpenFailed,
    };

    // Collection result: report is the output from the policy layer; other fields are for display and diagnostic statistics.
    struct InjectionTraceResult
    {
        InjectionTraceStatus status = InjectionTraceStatus::kProcessIdentityUnavailable;
        QString diagnosticText;

        ksword::evidence::SurveyReport report;

        // The **requested** mode for this operation. report.mode is only assigned when the criteria layer actually executes; if the process
        // cannot be opened, it remains the default value. Using it to display the title would incorrectly label a deep scan as a fast scan.
        ksword::evidence::SurveyMode requestedMode =
            ksword::evidence::SurveyMode::kFast;

        std::uint32_t pid = 0;
        std::uint64_t creationTime100ns = 0;
        QString imagePath;
        QString architectureText;

        std::uint32_t regionCount = 0;
        std::uint32_t loaderModuleCount = 0;
        std::uint32_t imageMappingCount = 0;
        std::uint32_t threadCount = 0;
        std::uint32_t comparedModuleCount = 0;
        std::uint32_t comparedRangeCount = 0;
        std::uint32_t workingSetPagesQueried = 0;
        std::uint64_t bytesRead = 0;
        std::uint64_t elapsedMs = 0;

        // Stack backtrace context counters (non-zero only in deep mode). It is normal for walked to be much smaller than considered:
        // Only take context for threads stopped in the waiting state.
        std::uint32_t stackThreadsConsidered = 0;
        std::uint32_t stackThreadsWaiting = 0;
        std::uint32_t stackThreadsWalked = 0;

        // In deep mode, the number of non-executable regions in the first page checked for "dormant payloads". 0 indicates this tier was not performed.
        std::uint32_t dormantRegionsScanned = 0;

        // Accounting for the second reference source of section objects (non-zero only in deep mode with a driver).
        std::uint32_t sectionModulesChecked = 0;
        std::uint32_t sectionPagesCompared = 0;
        std::uint32_t sectionPagesDiffering = 0;

        // R0 backend context sampling. A state of NotRequested indicates it is not intended for use.
        // DriverUnavailable indicates the driver is desired but missing (capability degradation, not a defect).
        ksword::evidence::KernelBackendState kernelVadState =
            ksword::evidence::KernelBackendState::kNotRequested;
        ksword::evidence::KernelBackendState kernelPteState =
            ksword::evidence::KernelBackendState::kNotRequested;
        std::uint32_t kernelVadRegionCount = 0;
        std::uint32_t kernelVadUnreadableNodes = 0;
        std::uint32_t kernelExecutableExtentCount = 0;
        std::uint32_t kernelExecutablePageCount = 0;
        std::uint32_t kernelPteTableReads = 0;
        QString kernelDiagnosticText;

        bool completed() const { return status == InjectionTraceStatus::kCompleted; }
    };

    // screenProcessInjectionSurface: a **low-cost filter** used for the process list column.
    //
    // Performs only address space enumeration and region classification; **does not** touch module lists, PE normalization, working sets, threads, or drivers.
    // Measured (2026-09-12, 496 processes on this machine): median 2.52 ms/process, p95 9.5 ms, total 1073 ms.
    // In contrast, the full scanProcessInjectionTrace takes 4.6 s for a cold start on Explorer.
    //
    // It produces **counts, not conclusions**: in a single sample, 284 out of 310 openable processes contain dynamic code,
    // so a simple 'present/absent' distinction lacks discriminative power; what matters is the degree of outlier behavior.
    // For inaccessible processes, AccessDenied is returned, and the caller must display 'unknown' rather than 0.
    ksword::evidence::ProcessSurfaceScreen screenProcessInjectionSurface(
        std::uint32_t pid,
        std::uint64_t expectedCreationTime100ns);

    // Collect and evaluate injection traces for a process.
    // - pid / expectedCreationTime100ns: Process instance identity. If expectedCreationTime100ns is 0, the caller
    //   has no known baseline, so only a self-validation of 'consistency before and after scanning' is performed.
    // - fallbackImagePath: display fallback when kernel path query fails; not part of criteria.
    InjectionTraceResult scanProcessInjectionTrace(
        std::uint32_t pid,
        std::uint64_t expectedCreationTime100ns,
        const QString& fallbackImagePath,
        const InjectionTraceOptions& options = InjectionTraceOptions{});
}
