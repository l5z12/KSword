#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>

#include "ArkDriverIoTypes.h"
#include "../driver/KswordArkMutationIoctl.h"

namespace ksword::ark
{
    // MutationPrepareInput is the safe R3-side representation of a mutation prepare request.
    // Input: UI/future repair paths populate target kind, address, bytes and expected-before bytes.
    // Processing: DriverClient packs the fields into KSWORD_ARK_MUTATION_PREPARE_REQUEST.
    // Return behavior: used as input to prepareMutation; no member function return.
    struct MutationPrepareInput
    {
        std::uint32_t flags = KSWORD_ARK_MUTATION_FLAG_DRY_RUN;
        std::uint32_t targetKind = KSWORD_ARK_MUTATION_TARGET_UNKNOWN;
        std::uint32_t processId = 0;
        std::uint32_t bytes = 0;
        std::uint64_t targetAddress = 0;
        std::uint64_t targetContext = 0;
        std::vector<std::uint8_t> afterBytes;
        std::vector<std::uint8_t> expectedBeforeBytes;
    };

    // MutationResponseResult carries PREPARE/COMMIT/ROLLBACK response metadata.
    // Input: returned by mutation DriverClient methods.
    // Processing: before/after byte arrays are bounded by the shared protocol max.
    // Return behavior: io.ok reports transport and fixed-response parse success.
    struct MutationResponseResult
    {
        IoResult io;
        bool unsupported = false;
        std::uint32_t version = 0;
        std::uint32_t status = KSWORD_ARK_MUTATION_STATUS_UNKNOWN;
        std::uint32_t targetKind = KSWORD_ARK_MUTATION_TARGET_UNKNOWN;
        std::uint32_t processId = 0;
        std::uint32_t bytes = 0;
        std::uint32_t riskFlags = 0;
        long lastStatus = 0;
        std::uint64_t transactionId = 0;
        std::uint64_t targetAddress = 0;
        std::uint64_t targetContext = 0;
        std::uint64_t beforeHash = 0;
        std::uint64_t afterHash = 0;
        std::uint64_t timestampTick = 0;
        std::vector<std::uint8_t> beforeBytes;
        std::vector<std::uint8_t> afterBytes;
    };

    // MutationAuditEntry is one read-only transaction audit row.
    // Input: copied from KSWORD_ARK_MUTATION_AUDIT_ENTRY.
    // Processing: UI displays audit/dry-run/rollback status only; no arbitrary-write button is exposed.
    // Return behavior: data-only row.
    struct MutationAuditEntry
    {
        std::uint32_t operation = KSWORD_ARK_MUTATION_OPERATION_UNKNOWN;
        std::uint32_t status = KSWORD_ARK_MUTATION_STATUS_UNKNOWN;
        long lastStatus = 0;
        std::uint32_t targetKind = KSWORD_ARK_MUTATION_TARGET_UNKNOWN;
        std::uint32_t riskFlags = 0;
        std::uint32_t flags = 0;
        std::uint32_t processId = 0;
        std::uint32_t bytes = 0;
        std::uint64_t transactionId = 0;
        std::uint64_t sequence = 0;
        std::uint64_t targetAddress = 0;
        std::uint64_t targetContext = 0;
        std::uint64_t beforeHash = 0;
        std::uint64_t afterHash = 0;
        std::uint64_t timestampTick = 0;
        std::vector<std::uint8_t> byteData;
    };

    // MutationAuditResult carries the bounded R0 audit ring snapshot.
    // Input: produced by DriverClient::queryMutationAudit.
    // Processing: unsupported distinguishes missing transaction IOCTL from empty audit rings.
    // Return behavior: returned by value; entries contains parsed audit rows.
    struct MutationAuditResult
    {
        IoResult io;
        bool unsupported = false;
        std::uint32_t version = 0;
        std::uint32_t totalCount = 0;
        std::uint32_t returnedCount = 0;
        std::uint32_t lostCount = 0;
        std::uint64_t oldestSequence = 0;
        std::uint64_t nextSequence = 0;
        std::vector<MutationAuditEntry> entries;
    };
}
