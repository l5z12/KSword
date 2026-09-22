#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>

#include "ArkDriverIoTypes.h"
#include "../driver/KswordArkCallbackIoctl.h"
#include "../driver/KswordArkProcessProtectIoctl.h"

namespace ksword::ark
{
    // CallbackMonitorStatusResult is a fixed state snapshot for kernel callback telemetry.
    struct CallbackMonitorStatusResult
    {
        IoResult io;                              // io: DeviceIoControl and protocol validation status.
        bool unsupported = false;                 // unsupported: The old driver has not registered the monitoring IOCTL.
        std::uint32_t version = 0;                // version: Shared protocol version.
        std::uint32_t runtimeFlags = 0;           // runtimeFlags：CAPTURING/DROPPED/STOPPING。
        std::uint32_t categoryMask = 0;           // categoryMask: Currently collected categories.
        std::uint32_t registeredCategoryMask = 0; // registeredCategoryMask: Registered callback capabilities.
        std::uint32_t ringCapacity = 0;           // ringCapacity: fixed R0 ring capacity.
        std::uint32_t queuedCount = 0;            // queuedCount: The number of records currently available for reading.
        std::uint64_t latestSequence = 0;         // latestSequence: Most recently submitted sequence number.
        std::uint64_t droppedCount = 0;           // droppedCount: Cumulative count of dropped items due to try-lock contention.
        long lastStatus = 0;                      // lastStatus: Most recent control action NTSTATUS.
        long minifilterStartStatus = 0;           // minifilterStartStatus: FltStartFiltering status.
    };

    // CallbackMonitorEventRow is a single callback event that has been safely copied from the shared ABI.
    struct CallbackMonitorEventRow
    {
        std::uint64_t sequence = 0;
        std::int64_t timeUtc100ns = 0;
        std::uint32_t category = 0;
        std::uint32_t operation = 0;
        std::uint32_t flags = 0;
        long resultStatus = 0;
        std::uint32_t originatingProcessId = 0;
        std::uint32_t originatingThreadId = 0;
        std::uint32_t targetProcessId = 0;
        std::uint32_t targetThreadId = 0;
        std::uint32_t parentProcessId = 0;
        std::uint32_t sessionId = 0;
        std::uint32_t originalAccess = 0;
        std::uint32_t desiredAccess = 0;
        std::uint32_t objectType = 0;
        std::uint32_t detailCode = 0;
        std::uint64_t address = 0;
        std::uint64_t regionSize = 0;
        std::wstring processName;
        std::wstring path;
    };

    // CallbackMonitorReadResult stores the result of a single independent cursor read along with coverage/competition diagnostics.
    struct CallbackMonitorReadResult
    {
        IoResult io;
        bool unsupported = false;
        std::uint32_t runtimeFlags = 0;
        std::uint32_t categoryMask = 0;
        std::uint32_t responseFlags = 0;
        std::uint32_t ringCapacity = 0;
        std::uint64_t firstAvailableSequence = 0;
        std::uint64_t latestSequence = 0;
        std::uint64_t nextSequence = 0;
        std::uint64_t droppedCount = 0;
        std::uint64_t lostBeforeFirst = 0;
        std::vector<CallbackMonitorEventRow> records;
    };

    // CallbackRuntimeResult wraps the runtime-state response packet.
    struct CallbackRuntimeResult
    {
        IoResult io;
        KSWORD_ARK_CALLBACK_RUNTIME_STATE state{};
    };

    // MinifilterBypassPidResult wraps the fixed PID whitelist response.
    // Input: none; DriverClient::queryMinifilterBypassPids fills this struct.
    // Processing: io reports transport/protocol success and response carries
    // the full R0 whitelist snapshot.
    // Return behavior: the struct itself has no methods; callers inspect io.ok.
    struct MinifilterBypassPidResult
    {
        IoResult io;
        KSWORD_ARK_MINIFILTER_BYPASS_PID_RESPONSE response{};
    };

    // ProcessProtectStateResult wraps the handle-callback process protection state.
    // Input: None; DriverClient::queryProcessProtectState is responsible for populating this.
    // Handling: io records the transport/protocol result; response contains the currently effective full protection configuration and counters in R0.
    // Return: The structure itself has no methods; the caller first checks io.ok, then uses response.capabilityStatus
    //       to distinguish between 'no rules configured' and 'handle callbacks failed to attach on this machine'.
    struct ProcessProtectStateResult
    {
        IoResult io;
        KSWORD_ARK_PROCESS_PROTECT_STATE_RESPONSE response{};
    };

    // CallbackRemoveResult wraps the legacy external-callback removal response packet.
    struct CallbackRemoveResult
    {
        IoResult io;
        KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_RESPONSE response{};
    };

    // CallbackRemoveExResult wraps the extended removal response.
    // Input: none; it is returned by DriverClient::removeExternalCallbackEx.
    // Processing: keeps public-API and experimental-unlink diagnostics together.
    // Return behavior: io.ok reports transport/protocol success; response.ntstatus
    // reports the kernel operation result.
    struct CallbackRemoveExResult
    {
        IoResult io;
        KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_RESPONSE response{};
    };

    // CallbackEnumEntry is an R3 model row for R0 callback traversal.
    struct CallbackEnumEntry
    {
        std::uint32_t callbackClass = 0;
        std::uint32_t source = 0;
        std::uint32_t status = 0;
        std::uint32_t fieldFlags = 0;
        std::uint32_t trustFlags = 0;        // trustFlags: PDB/public/fallback/revalidated trust bits.
        std::uint32_t removeBehavior = 0;    // removeBehavior: R0-recommended public API/experimental unlink behavior.
        std::uint32_t removeFlags = 0;       // removeFlags: Compatible with legacy UI naming; always mirrors removeBehavior.
        std::uint32_t operationMask = 0;
        std::uint32_t objectTypeMask = 0;
        std::uint32_t registrationType = 0; // registrationType: Specific registration API types such as Legacy, Ex, or Ex2.
        std::uint64_t generation = 0;        // generation: R0 enumeration generation, used for re-verification before EX removal.
        long lastStatus = 0;
        std::uint64_t callbackAddress = 0;
        std::uint64_t contextAddress = 0;
        std::uint64_t registrationAddress = 0;
        std::uint64_t identityHash = 0;      // identityHash: stable line-by-line identity hash for protocol v3; remains 0 for older protocols.
        std::uint64_t rawStorageValue = 0;   // rawStorageValue: R0 raw registry slot value; 0 if the old protocol does not provide it.
        std::uint64_t moduleBase = 0;
        std::uint32_t moduleSize = 0;
        std::uint32_t detailCode = KSWORD_ARK_CALLBACK_ENUM_DETAIL_NONE;
        std::uint64_t detailArgs[KSWORD_ARK_CALLBACK_ENUM_DETAIL_ARG_COUNT]{};
        std::wstring name;
        std::wstring altitude;
        std::wstring modulePath;
        std::wstring detail;
    };

    // CallbackEnumResult carries the response for R0 callback traversal.
    struct CallbackEnumResult
    {
        IoResult io;
        std::uint32_t version = 0;
        std::uint32_t totalCount = 0;
        std::uint32_t returnedCount = 0;
        std::uint32_t flags = 0;
        long lastStatus = 0;
        std::uint64_t snapshotGeneration = 0; // snapshotGeneration: Token for the current stable snapshot.
        std::uint64_t snapshotHash = 0;       // snapshotHash: Hash of the complete ordered callback set.
        std::uint32_t pageCount = 0;          // pageCount: Number of pages successfully received.
        std::uint32_t snapshotRetryCount = 0; // snapshotRetryCount: Retry count after detecting concurrent changes.
        bool snapshotConsistent = false;      // snapshotConsistent: v3 final consistency check probe confirmed consistent.
        std::vector<CallbackEnumEntry> entries;
    };
}
