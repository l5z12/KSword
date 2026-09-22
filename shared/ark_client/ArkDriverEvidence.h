#pragma once

// F-05 collection status normalization layer: translate ArkDriverClient's IoResult and each
// protocol's own PARTIAL/TRUNCATED/UNSUPPORTED status bits into a unified CollectionOutcome.
//
// Why this layer is needed: Currently, 'unsupported' is a bool, 'denied' is only reflected via
// win32Error == ERROR_ACCESS_DENIED, and 'timeout' has no independent expression. 'Not collected' and
// 'correct empty set' both appear as empty tables in the UI. There are 40+ *_STATUS_PARTIAL / _TRUNCATED
// / _UNSUPPORTED macros under shared/driver with inconsistent naming, and R3 lacks a unified standard.
//
// This header is inline-only: the Qt main application, Light, CLI, and plugins all compile ArkDriverClient directly.
// Adding a .cpp file would affect five project files; this file performs pure translation only and contains no state.

#include "ArkDriverTypes.h"

#include "../evidence/EvidenceEnvelope.h"

#include <cstdint>
#include <string>
#include <utility>

namespace ksword::ark
{
    // DriverCallShape: a few things known to the caller that IoResult cannot express.
    struct DriverCallShape
    {
        // The protocol returns "this driver does not provide this capability" (the unsupported
        // bit in each Result, or the *_STATUS_UNSUPPORTED_* flag in the response).
        bool unsupported = false;
        // The response includes flags like PARTIAL / TRUNCATED: the call succeeded but did not cover the requested scope.
        bool partial = false;
        // The protocol's lastStatus/queryStatus fields represent the result of the R0-side operation (default behavior for most
        // IOCTLs). If a protocol uses this field purely as informational (e.g., returning the status of an unrelated previous
        // operation), it must explicitly set false; otherwise, it will be incorrectly treated as a collection failure.
        bool ntStatusIsAuthoritative = true;
    };

    // toCollectionOutcome: The sole translation entry point.
    //
    // The order is deliberately set as follows:
    //   1. unsupported takes precedence over everything — old drivers report unknown IOCTLs as ERROR_INVALID_FUNCTION,
    //      which means "unsupported" rather than "error"; the two have completely different semantics in the UI and reports.
    //   2. NTSTATUS dispatch: The most common failure mode is when DeviceIoControl round-trip succeeds
    //      (io.ok = true) but the R0-side operation fails. Over 40 locations set `result.io.ntStatus =
    //      response->lastStatus/queryStatus/status`. Relying solely on io.ok would misclassify
    //      STATUS_ACCESS_DENIED as Success, store it in the envelope, and have deriveConclusion(false)
    //      immediately return "No differences found" (F-05 explicitly forbids this).
    //   3. On failure, route to AccessDenied / Timeout / Error based on the Win32 error code, while preserving the original error code.
    //   4. On success, 'partial' determines whether the outcome is Success or Partial; an empty collection on success is still considered Success.
    //
    // No branch produces a "normal" conclusion; the conclusion is derived separately by EvidenceEnvelope::deriveConclusion.
    inline ksword::evidence::CollectionOutcome toCollectionOutcome(
        const IoResult& io,
        const DriverCallShape& shape = DriverCallShape{})
    {
        using ksword::evidence::CollectionOutcome;
        using ksword::evidence::CollectionStatus;
        using ksword::evidence::OptionalU64;

        CollectionOutcome outcome;
        outcome.message = io.message;

        // Prefer NTSTATUS as the raw code: if the driver supplies it, the failure occurred in R0.
        if (io.ntStatus != 0)
        {
            outcome.nativeCodeDomain = "NTSTATUS";
            outcome.nativeCode = OptionalU64::of(static_cast<std::uint64_t>(
                static_cast<std::uint32_t>(io.ntStatus)));
        }
        else if (io.win32Error != ERROR_SUCCESS)
        {
            outcome.nativeCodeDomain = "WIN32";
            outcome.nativeCode = OptionalU64::of(static_cast<std::uint64_t>(io.win32Error));
        }

        if (shape.unsupported ||
            io.win32Error == ERROR_INVALID_FUNCTION ||
            io.win32Error == ERROR_NOT_SUPPORTED)
        {
            outcome.status = CollectionStatus::kUnsupported;
            return outcome;
        }

        // NTSTATUS dispatching. Strictly classify by NTSTATUS severity; do not write `ntStatus < 0`,
        // as that would also mark NT_WARNING (0x8xxxxxxx, "data present but incomplete") as a failure.
        //   severity 3 (0xC.......) = NT_ERROR       -> failure
        //   severity 2 (0x8.......) = NT_WARNING     -> Partial (e.g. BUFFER_OVERFLOW)
        //   severity 1 (0x4.......) = NT_INFORMATION -> no change to the result
        //   severity 0 (0x0.......) = NT_SUCCESS     -> no change to the result (except STATUS_TIMEOUT)
        if (shape.ntStatusIsAuthoritative && io.ntStatus != 0)
        {
            const std::uint32_t kStatus = static_cast<std::uint32_t>(io.ntStatus);
            switch (kStatus)
            {
            case 0xC0000022UL:  // STATUS_ACCESS_DENIED
            case 0xC0000061UL:  // STATUS_PRIVILEGE_NOT_HELD
                outcome.status = CollectionStatus::kAccessDenied;
                return outcome;
            case 0xC0000034UL:  // STATUS_OBJECT_NAME_NOT_FOUND
            case 0xC00000BBUL:  // STATUS_NOT_SUPPORTED
            case 0xC0000002UL:  // STATUS_NOT_IMPLEMENTED
            case 0xC0000010UL:  // STATUS_INVALID_DEVICE_REQUEST
                outcome.status = CollectionStatus::kUnsupported;
                return outcome;
            case 0x00000102UL:  // STATUS_TIMEOUT: severity is 0, but the wait indeed timed out.
            case 0xC0000102UL:  // STATUS_FILE_CORRUPT_ERROR or timeout-related error codes.
                outcome.status = CollectionStatus::kTimeout;
                return outcome;
            default:
                break;
            }

            const std::uint32_t kSeverity = kStatus >> 30U;
            if (kSeverity == 3U)
            {
                outcome.status = CollectionStatus::kError;
                return outcome;
            }
            if (kSeverity == 2U)
            {
                // For example, STATUS_BUFFER_OVERFLOW (0x80000005): data was retrieved, but not completely.
                // This is Partial, not Error—the retrieved portion remains a valid observation.
                outcome.status = CollectionStatus::kPartial;
                return outcome;
            }
            // NT_SUCCESS / NT_INFORMATION: Continue with the standard checks below.
        }

        if (!io.ok)
        {
            switch (io.win32Error)
            {
            case ERROR_ACCESS_DENIED:
            case ERROR_PRIVILEGE_NOT_HELD:
                outcome.status = CollectionStatus::kAccessDenied;
                break;
            case ERROR_SEM_TIMEOUT:
            case WAIT_TIMEOUT:
            case ERROR_TIMEOUT:
                outcome.status = CollectionStatus::kTimeout;
                break;
            default:
                outcome.status = CollectionStatus::kError;
                break;
            }
            return outcome;
        }

        outcome.status = shape.partial ? CollectionStatus::kPartial : CollectionStatus::kSuccess;
        return outcome;
    }

    // notCollected: The call was never initiated (no driver, capability disabled, or user did not click refresh).
    // This is distinct from 'initiated but returned empty'; they cannot share the same empty table.
    inline ksword::evidence::CollectionOutcome driverNotCollected(std::string reason)
    {
        ksword::evidence::CollectionOutcome outcome;
        outcome.status = ksword::evidence::CollectionStatus::kNotCollected;
        outcome.message = std::move(reason);
        return outcome;
    }

    // makeDriverSource: the unified entry point for filling SourceRef, ensuring sourceGroup is taken based on
    // "underlying evidence source" rather than UI wrapping — otherwise, two layers of wrapping for the same
    // collector would be treated by X-01 as two independent sources, artificially inflating trustworthiness.
    inline ksword::evidence::SourceRef makeDriverSource(std::string collectorId,
                                                        std::uint32_t collectorVersion,
                                                        std::string sourceGroup,
                                                        std::string ioctlName)
    {
        ksword::evidence::SourceRef source;
        source.collectorId = std::move(collectorId);
        source.collectorVersion = collectorVersion;
        source.sourceGroup = std::move(sourceGroup);
        source.origin = ksword::evidence::SourceOrigin::kLiveKernel;
        source.dependsOn = "ArkDriverClient/" + ioctlName;
        return source;
    }
}
