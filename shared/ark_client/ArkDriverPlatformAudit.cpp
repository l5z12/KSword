#include "ArkDriverClient.h"
#include "ArkDriverAuditSupport.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <iterator>
#include <limits>
#include <sstream>
#include <string>
#include <type_traits>
#include <vector>

namespace ksword::ark
{
    using namespace detail::audit;
    PlatformAuditResult DriverClient::queryPlatformAudit(const unsigned long scopeMask, const unsigned long maxRows) const
    {
        constexpr const char* kOperationName = "IOCTL_KSWORD_ARK_QUERY_PLATFORM_AUDIT";
        constexpr std::size_t kHeaderSize =
            offsetof(KSWORD_ARK_QUERY_PLATFORM_AUDIT_RESPONSE, entries);
        constexpr std::uint32_t kKnownResponseFlags =
            KSWORD_ARK_PLATFORM_RESPONSE_TRUNCATED |
            KSWORD_ARK_PLATFORM_RESPONSE_PARTIAL |
            KSWORD_ARK_PLATFORM_RESPONSE_FAIL_CLOSED |
            KSWORD_ARK_PLATFORM_RESPONSE_NO_PDB;
        constexpr std::uint32_t kKnownFieldFlags =
            KSWORD_ARK_PLATFORM_FIELD_LIVE_ADDRESS |
            KSWORD_ARK_PLATFORM_FIELD_ORIGINAL_ADDRESS |
            KSWORD_ARK_PLATFORM_FIELD_TABLE_ADDRESS |
            KSWORD_ARK_PLATFORM_FIELD_MODULE |
            KSWORD_ARK_PLATFORM_FIELD_PROLOGUE_FORMAT |
            KSWORD_ARK_PLATFORM_FIELD_OWNER_VALIDATED |
            KSWORD_ARK_PLATFORM_FIELD_STRUCTURE_VALIDATED |
            KSWORD_ARK_PLATFORM_FIELD_EXACT_EXPORT |
            KSWORD_ARK_PLATFORM_FIELD_EXECUTABLE_VALIDATED |
            KSWORD_ARK_PLATFORM_FIELD_READ_ONLY_RANGE |
            KSWORD_ARK_PLATFORM_FIELD_DETAIL_ARGS |
            KSWORD_ARK_PLATFORM_FIELD_BASELINE_VALIDATED |
            KSWORD_ARK_PLATFORM_FIELD_LOCATOR_VALIDATED;
        constexpr std::uint32_t kExpectedSignaturePolicyFlags =
            KSWORD_ARK_PLATFORM_FIELD_EXACT_EXPORT |
            KSWORD_ARK_PLATFORM_FIELD_STRUCTURE_VALIDATED |
            KSWORD_ARK_PLATFORM_FIELD_OWNER_VALIDATED |
            KSWORD_ARK_PLATFORM_FIELD_PROLOGUE_FORMAT |
            KSWORD_ARK_PLATFORM_FIELD_LOCATOR_VALIDATED;
        PlatformAuditResult result{};
        KSWORD_ARK_QUERY_PLATFORM_AUDIT_REQUEST request{};
        request.size = sizeof(request);
        request.version = KSWORD_ARK_PLATFORM_AUDIT_PROTOCOL_VERSION;
        request.scopeMask = scopeMask;
        request.maxRows = maxRows;
        request.flags = 0UL;
        request.reserved0 = 0UL;

        constexpr std::size_t kResponseBufferBytes =
            kHeaderSize +
            (static_cast<std::size_t>(KSWORD_ARK_PLATFORM_HARD_MAX_ROWS) *
             sizeof(KSWORD_ARK_PLATFORM_AUDIT_ENTRY));
        static_assert(
            kResponseBufferBytes <= std::numeric_limits<unsigned long>::max(),
            "platform audit buffer must fit DeviceIoControl");
        std::vector<std::uint8_t> responseBuffer(kResponseBufferBytes, 0U);
        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_PLATFORM_AUDIT,
            &request,
            sizeof(request),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        if (!result.io.ok)
        {
            markUnsupportedIfNeeded(result, kOperationName);
            return result;
        }

        const auto kFailProtocol = [&result, kOperationName](const std::string& reason)
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_DATA;
            result.io.message = std::string(kOperationName) + " invalid response: " + reason;
            result.entries.clear();
        };
        if (result.io.bytesReturned < kHeaderSize ||
            result.io.bytesReturned > responseBuffer.size())
        {
            kFailProtocol("header/bytesReturned out of range");
            return result;
        }

        KSWORD_ARK_QUERY_PLATFORM_AUDIT_RESPONSE response{};
        std::memcpy(&response, responseBuffer.data(), kHeaderSize);
        const unsigned long kExpectedScope =
            scopeMask == 0UL ? KSWORD_ARK_PLATFORM_AUDIT_SCOPE_ALL : scopeMask;
        const unsigned long kRequestedRows =
            maxRows == 0UL
                ? KSWORD_ARK_PLATFORM_DEFAULT_MAX_ROWS
                : std::min(maxRows, KSWORD_ARK_PLATFORM_HARD_MAX_ROWS);
        const auto kValidStatus = [](const unsigned long value)
        {
            return value <= KSWORD_ARK_PLATFORM_AUDIT_STATUS_BUFFER_TRUNCATED;
        };
        const auto kValidSignature = [](const unsigned long value)
        {
            return value == KSWORD_ARK_PLATFORM_SIGNATURE_NONE ||
                value == KSWORD_ARK_PLATFORM_SIGNATURE_PUBLIC_HAL_V6 ||
                value == KSWORD_ARK_PLATFORM_SIGNATURE_PUBLIC_HAL_V4_V5 ||
                (value >= KSWORD_ARK_PLATFORM_SIGNATURE_WDF_BINDING_TABLE &&
                 value <= KSWORD_ARK_PLATFORM_SIGNATURE_MAX);
        };
        const bool kHeaderValid =
            response.size == kHeaderSize &&
            response.version == KSWORD_ARK_PLATFORM_AUDIT_PROTOCOL_VERSION &&
            response.reserved0 == 0UL &&
            response.scopeMask == kExpectedScope &&
            kValidStatus(response.queryStatus) &&
            (response.responseFlags & ~kKnownResponseFlags) == 0UL &&
            (response.responseFlags & KSWORD_ARK_PLATFORM_RESPONSE_NO_PDB) != 0UL &&
            response.totalCount >= response.returnedCount &&
            response.totalCount <= KSWORD_ARK_PLATFORM_HARD_MAX_ROWS &&
            response.returnedCount <= kRequestedRows &&
            response.returnedCount <= KSWORD_ARK_PLATFORM_HARD_MAX_ROWS &&
            response.entrySize == sizeof(KSWORD_ARK_PLATFORM_AUDIT_ENTRY) &&
            response.signaturePolicyFlags == kExpectedSignaturePolicyFlags &&
            (((response.responseFlags & KSWORD_ARK_PLATFORM_RESPONSE_TRUNCATED) != 0UL) ==
             (response.returnedCount < response.totalCount));
        if (!kHeaderValid)
        {
            kFailProtocol("header fields rejected");
            return result;
        }
        if (response.returnedCount >
            (std::numeric_limits<std::size_t>::max() - kHeaderSize) /
                sizeof(KSWORD_ARK_PLATFORM_AUDIT_ENTRY))
        {
            kFailProtocol("row byte count overflow");
            return result;
        }
        const std::size_t kRequiredBytes =
            kHeaderSize +
            (static_cast<std::size_t>(response.returnedCount) *
             sizeof(KSWORD_ARK_PLATFORM_AUDIT_ENTRY));
        if (kRequiredBytes != result.io.bytesReturned)
        {
            kFailProtocol("returnedCount/bytesReturned mismatch");
            return result;
        }

        result.entries.reserve(response.returnedCount);
        for (std::size_t index = 0U; index < response.returnedCount; ++index)
        {
            KSWORD_ARK_PLATFORM_AUDIT_ENTRY entry{};
            const std::size_t kOffset =
                kHeaderSize + (index * sizeof(KSWORD_ARK_PLATFORM_AUDIT_ENTRY));
            std::memcpy(&entry, responseBuffer.data() + kOffset, sizeof(entry));

            const bool kScopeValid =
                entry.scope != 0UL &&
                (entry.scope & ~KSWORD_ARK_PLATFORM_AUDIT_SCOPE_ALL) == 0UL &&
                (entry.scope & ~response.scopeMask) == 0UL;
            const bool kRowKindValid =
                entry.rowKind >= KSWORD_ARK_PLATFORM_AUDIT_ROW_TABLE &&
                entry.rowKind <= KSWORD_ARK_PLATFORM_AUDIT_ROW_DIAGNOSTIC;
            const bool kHookValid =
                entry.hookStatus == KSWORD_ARK_PLATFORM_HOOK_UNKNOWN ||
                entry.hookStatus == KSWORD_ARK_PLATFORM_HOOK_SUSPICIOUS ||
                entry.hookStatus == KSWORD_ARK_PLATFORM_HOOK_UNSUPPORTED;
            const bool kConfidenceValid =
                entry.confidence == KSWORD_ARK_PLATFORM_CONFIDENCE_NONE ||
                entry.confidence == KSWORD_ARK_PLATFORM_CONFIDENCE_LOW ||
                entry.confidence == KSWORD_ARK_PLATFORM_CONFIDENCE_MEDIUM ||
                entry.confidence == KSWORD_ARK_PLATFORM_CONFIDENCE_HIGH;
            const bool kStringsValid =
                std::find(
                    std::begin(entry.name),
                    std::end(entry.name),
                    L'\0') != std::end(entry.name) &&
                std::find(
                    std::begin(entry.modulePath),
                    std::end(entry.modulePath),
                    L'\0') != std::end(entry.modulePath);
            const bool kEntryValid =
                entry.size == sizeof(entry) &&
                entry.reserved0 == 0UL &&
                entry.reserved1 == 0UL &&
                kScopeValid &&
                kRowKindValid &&
                kValidStatus(entry.status) &&
                kHookValid &&
                kConfidenceValid &&
                (entry.fieldFlags & ~kKnownFieldFlags) == 0UL &&
                kValidSignature(entry.signatureId) &&
                entry.slotKind <= KSWORD_ARK_PLATFORM_SLOT_DUMMY &&
                entry.ownerPolicy <= KSWORD_ARK_PLATFORM_OWNER_KSWORD &&
                entry.originalAddressSource ==
                    KSWORD_ARK_PLATFORM_ORIGINAL_SOURCE_NONE &&
                entry.detailCode <=
                    KSWORD_ARK_PLATFORM_DETAIL_SUBCOMPONENT_VALIDATED &&
                entry.prologueSignatureId <= 8UL &&
                kStringsValid &&
                (entry.fieldFlags &
                 (KSWORD_ARK_PLATFORM_FIELD_ORIGINAL_ADDRESS |
                  KSWORD_ARK_PLATFORM_FIELD_BASELINE_VALIDATED)) == 0UL &&
                entry.originalAddress == 0ULL &&
                (((entry.fieldFlags & KSWORD_ARK_PLATFORM_FIELD_DETAIL_ARGS) != 0UL) ==
                 (entry.detailCode != KSWORD_ARK_PLATFORM_DETAIL_NONE)) &&
                (((entry.fieldFlags & KSWORD_ARK_PLATFORM_FIELD_LIVE_ADDRESS) != 0UL) ==
                 (entry.liveAddress != 0ULL)) &&
                (((entry.fieldFlags & KSWORD_ARK_PLATFORM_FIELD_TABLE_ADDRESS) != 0UL) ==
                 (entry.tableAddress != 0ULL)) &&
                (((entry.fieldFlags & KSWORD_ARK_PLATFORM_FIELD_MODULE) != 0UL) ==
                 (entry.moduleBase != 0ULL)) &&
                (((entry.fieldFlags & KSWORD_ARK_PLATFORM_FIELD_MODULE) != 0UL) ==
                 (entry.moduleSize != 0UL)) &&
                (((entry.fieldFlags & KSWORD_ARK_PLATFORM_FIELD_PROLOGUE_FORMAT) != 0UL) ==
                 (entry.prologueSignatureId != 0UL));
            if (!kEntryValid)
            {
                kFailProtocol("entry[" + std::to_string(index) + "] rejected");
                return result;
            }
            result.entries.push_back(entry);
        }

        result.version = response.version;
        result.status = response.queryStatus;
        result.scopeMask = response.scopeMask;
        result.responseFlags = response.responseFlags;
        result.totalCount = response.totalCount;
        result.returnedCount = response.returnedCount;
        result.entrySize = response.entrySize;
        result.buildNumber = response.buildNumber;
        result.signaturePolicyFlags = response.signaturePolicyFlags;
        result.lastStatus = response.lastStatus;
        result.io.ntStatus = response.lastStatus;
        result.io.message = appendAuditSummary(
            kOperationName,
            result.totalCount,
            result.returnedCount,
            result.entries.size(),
            result.io.bytesReturned);
        return result;
    }

    PlatformAuditControlResult DriverClient::editPlatformAuditEntry(
        const unsigned long scope,
        const unsigned long entryIndex,
        const std::uint64_t tableAddress,
        const std::uint64_t expectedValue,
        const std::uint64_t newValue,
        const bool uiConfirmed) const
    {
        constexpr const char* kOperationName =
            "IOCTL_KSWORD_ARK_CONTROL_PLATFORM_AUDIT";
        constexpr std::uint32_t kKnownResponseFlags =
            KSWORD_ARK_PLATFORM_CONTROL_RESPONSE_CHANGED |
            KSWORD_ARK_PLATFORM_CONTROL_RESPONSE_TARGET_EXECUTABLE |
            KSWORD_ARK_PLATFORM_CONTROL_RESPONSE_TABLE_REVALIDATED |
            KSWORD_ARK_PLATFORM_CONTROL_RESPONSE_ALIAS_WRITE;
        PlatformAuditControlResult result{};
        KSWORD_ARK_CONTROL_PLATFORM_AUDIT_REQUEST request{};
        request.size = sizeof(request);
        request.version = KSWORD_ARK_PLATFORM_AUDIT_PROTOCOL_VERSION;
        request.scope = scope;
        request.entryIndex = entryIndex;
        request.flags = uiConfirmed
            ? KSWORD_ARK_PLATFORM_CONTROL_FLAG_UI_CONFIRMED
            : 0UL;
        request.confirmationToken = uiConfirmed
            ? KSWORD_ARK_PLATFORM_CONTROL_CONFIRMATION_TOKEN
            : 0UL;
        request.tableAddress = tableAddress;
        request.expectedValue = expectedValue;
        request.newValue = newValue;

        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_CONTROL_PLATFORM_AUDIT,
            &request,
            sizeof(request),
            &result.response,
            sizeof(result.response));
        if (!result.io.ok)
        {
            markUnsupportedIfNeeded(result, kOperationName);
            return result;
        }

        // WDF_CALLBACKS are excluded: those lines are compile-time addresses within the driver's .text
        // section; R0 has no corresponding writable slot, so requests are rejected during the resolve phase.
        const bool kValidScope =
            result.response.scope ==
                KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_DISPATCH ||
            result.response.scope ==
                KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_PRIVATE ||
            result.response.scope ==
                KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_ACPI ||
            result.response.scope ==
                KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_SUBCOMPONENTS ||
            result.response.scope ==
                KSWORD_ARK_PLATFORM_AUDIT_SCOPE_WDF_FUNCTIONS;
        const bool kResponseValid =
            result.io.bytesReturned == sizeof(result.response) &&
            result.response.size == sizeof(result.response) &&
            result.response.version ==
                KSWORD_ARK_PLATFORM_AUDIT_PROTOCOL_VERSION &&
            result.response.status <=
                KSWORD_ARK_PLATFORM_CONTROL_STATUS_SAFETY_DENIED &&
            kValidScope &&
            result.response.scope == scope &&
            result.response.entryIndex == entryIndex &&
            result.response.reserved0 == 0UL &&
            (result.response.responseFlags & ~kKnownResponseFlags) == 0UL &&
            result.response.requestedValue == newValue &&
            (((result.response.responseFlags &
               KSWORD_ARK_PLATFORM_CONTROL_RESPONSE_CHANGED) != 0UL) ==
             (result.response.status ==
                  KSWORD_ARK_PLATFORM_CONTROL_STATUS_OK &&
              expectedValue != newValue));
        if (!kResponseValid)
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_DATA;
            result.io.message =
                std::string(kOperationName) + " invalid response";
            std::memset(&result.response, 0, sizeof(result.response));
            return result;
        }

        result.io.ntStatus = result.response.lastStatus;
        result.io.message = std::string(kOperationName) +
            " status=" + std::to_string(result.response.status) +
            ", ntstatus=" +
            std::to_string(
                static_cast<std::uint32_t>(result.response.lastStatus));
        return result;
    }
}
