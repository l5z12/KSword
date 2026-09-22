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
    I8042AuditResult DriverClient::queryI8042Audit(const unsigned long maxRows) const
    {
        constexpr const char* kOperationName = "IOCTL_KSWORD_ARK_QUERY_I8042_AUDIT";
        constexpr std::size_t kHeaderSize =
            offsetof(KSWORD_ARK_QUERY_I8042_AUDIT_RESPONSE, entries);
        constexpr std::uint32_t kKnownResponseFlags =
            KSWORD_ARK_I8042_RESPONSE_TRUNCATED |
            KSWORD_ARK_I8042_RESPONSE_PARTIAL |
            KSWORD_ARK_I8042_RESPONSE_FAIL_CLOSED |
            KSWORD_ARK_I8042_RESPONSE_IMAGE_VALIDATED |
            KSWORD_ARK_I8042_RESPONSE_DESCRIPTOR_VALIDATED;
        constexpr std::uint32_t kKnownFieldFlags =
            KSWORD_ARK_I8042_FIELD_DEVICE_OBJECT |
            KSWORD_ARK_I8042_FIELD_PNP_ID |
            KSWORD_ARK_I8042_FIELD_CLASS_DEVICE_OBJECT |
            KSWORD_ARK_I8042_FIELD_CALLBACK_ADDRESS |
            KSWORD_ARK_I8042_FIELD_CONTEXT_ADDRESS |
            KSWORD_ARK_I8042_FIELD_OWNER_MODULE |
            KSWORD_ARK_I8042_FIELD_EXECUTABLE |
            KSWORD_ARK_I8042_FIELD_SAME_DEVICE_STACK |
            KSWORD_ARK_I8042_FIELD_IMAGE_VALIDATED |
            KSWORD_ARK_I8042_FIELD_DESCRIPTOR_VALIDATED |
            KSWORD_ARK_I8042_FIELD_DETAIL_ARGS;
        constexpr std::uint8_t kExpectedPdbGuid[KSWORD_ARK_I8042_PDB_GUID_BYTES] = {
            0x63U, 0x4CU, 0x70U, 0xECU,
            0x2FU, 0x3FU, 0xE7U, 0xA4U,
            0xBEU, 0xF7U, 0x86U, 0xF7U,
            0x55U, 0xDCU, 0xB5U, 0x2CU
        };
        I8042AuditResult result{};
        KSWORD_ARK_QUERY_I8042_AUDIT_REQUEST request{};
        request.size = sizeof(request);
        request.version = KSWORD_ARK_I8042_AUDIT_PROTOCOL_VERSION;
        request.maxRows = maxRows;
        request.flags = 0UL;
        request.reserved0 = 0UL;
        request.reserved1 = 0UL;

        constexpr std::size_t kResponseBufferBytes =
            kHeaderSize +
            (static_cast<std::size_t>(KSWORD_ARK_I8042_HARD_MAX_ROWS) *
             sizeof(KSWORD_ARK_I8042_AUDIT_ENTRY));
        static_assert(
            kResponseBufferBytes <= std::numeric_limits<unsigned long>::max(),
            "i8042 audit buffer must fit DeviceIoControl");
        std::vector<std::uint8_t> responseBuffer(kResponseBufferBytes, 0U);
        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_I8042_AUDIT,
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
            result.io.message = std::string(kOperationName) +
                " invalid response: " + reason;
            result.entries.clear();
        };
        if (result.io.bytesReturned < kHeaderSize ||
            result.io.bytesReturned > responseBuffer.size())
        {
            kFailProtocol("header/bytesReturned out of range");
            return result;
        }

        KSWORD_ARK_QUERY_I8042_AUDIT_RESPONSE response{};
        std::memcpy(&response, responseBuffer.data(), kHeaderSize);
        const unsigned long kRequestedRows =
            maxRows == 0UL
                ? KSWORD_ARK_I8042_DEFAULT_MAX_ROWS
                : std::min(maxRows, KSWORD_ARK_I8042_HARD_MAX_ROWS);
        const auto kValidStatus = [](const unsigned long value)
        {
            return value <= KSWORD_ARK_I8042_AUDIT_STATUS_BUFFER_TRUNCATED;
        };
        const bool kImageValidated =
            (response.responseFlags &
             KSWORD_ARK_I8042_RESPONSE_IMAGE_VALIDATED) != 0UL;
        const bool kDescriptorValidated =
            (response.responseFlags &
             KSWORD_ARK_I8042_RESPONSE_DESCRIPTOR_VALIDATED) != 0UL;
        const bool kTruncated =
            (response.responseFlags &
             KSWORD_ARK_I8042_RESPONSE_TRUNCATED) != 0UL;
        const bool kPartial =
            (response.responseFlags &
             KSWORD_ARK_I8042_RESPONSE_PARTIAL) != 0UL;
        const bool kFailClosed =
            (response.responseFlags &
             KSWORD_ARK_I8042_RESPONSE_FAIL_CLOSED) != 0UL;
        const bool kExactIdentity =
            response.imageTimeDateStamp == 0xFD7548DDUL &&
            response.imageSize == 0x00026000UL &&
            response.imageChecksum == 0x0002637EUL &&
            response.pdbAge == 1UL &&
            std::equal(
                std::begin(response.pdbGuid),
                std::end(response.pdbGuid),
                std::begin(kExpectedPdbGuid));
        const bool kHeaderValid =
            response.size == kHeaderSize &&
            response.version == KSWORD_ARK_I8042_AUDIT_PROTOCOL_VERSION &&
            response.reserved0 == 0UL &&
            kValidStatus(response.queryStatus) &&
            (response.responseFlags & ~kKnownResponseFlags) == 0UL &&
            response.totalCount >= response.returnedCount &&
            response.returnedCount <= kRequestedRows &&
            response.returnedCount <= KSWORD_ARK_I8042_HARD_MAX_ROWS &&
            (kTruncated
                ? response.totalCount > response.returnedCount
                : response.totalCount == response.returnedCount) &&
            response.entrySize == sizeof(KSWORD_ARK_I8042_AUDIT_ENTRY) &&
            response.descriptorId ==
                KSWORD_ARK_I8042_DESCRIPTOR_WIN11_26100_7934 &&
            (kPartial ==
                (response.queryStatus !=
                 KSWORD_ARK_I8042_AUDIT_STATUS_AVAILABLE)) &&
            (response.queryStatus !=
                    KSWORD_ARK_I8042_AUDIT_STATUS_AVAILABLE ||
             response.totalCount != 0UL) &&
            (kTruncated ==
                (response.queryStatus ==
                 KSWORD_ARK_I8042_AUDIT_STATUS_BUFFER_TRUNCATED)) &&
            (!kFailClosed || (kPartial && !kDescriptorValidated)) &&
            response.queryStatus !=
                KSWORD_ARK_I8042_AUDIT_STATUS_SIGNATURE_MISMATCH &&
            (!kImageValidated || (response.imageBase != 0ULL && kExactIdentity)) &&
            (!kDescriptorValidated || kImageValidated);
        if (!kHeaderValid)
        {
            kFailProtocol("header fields rejected");
            return result;
        }
        if (response.returnedCount >
            (std::numeric_limits<std::size_t>::max() - kHeaderSize) /
                sizeof(KSWORD_ARK_I8042_AUDIT_ENTRY))
        {
            kFailProtocol("row byte count overflow");
            return result;
        }
        const std::size_t kRequiredBytes =
            kHeaderSize +
            (static_cast<std::size_t>(response.returnedCount) *
             sizeof(KSWORD_ARK_I8042_AUDIT_ENTRY));
        if (kRequiredBytes != result.io.bytesReturned)
        {
            kFailProtocol("returnedCount/bytesReturned mismatch");
            return result;
        }

        result.entries.reserve(response.returnedCount);
        for (std::size_t index = 0U; index < response.returnedCount; ++index)
        {
            KSWORD_ARK_I8042_AUDIT_ENTRY entry{};
            const std::size_t kOffset =
                kHeaderSize + (index * sizeof(KSWORD_ARK_I8042_AUDIT_ENTRY));
            std::memcpy(
                &entry,
                responseBuffer.data() + kOffset,
                sizeof(entry));

            const bool kStringsValid =
                std::find(
                    std::begin(entry.pnpId),
                    std::end(entry.pnpId),
                    L'\0') != std::end(entry.pnpId) &&
                std::find(
                    std::begin(entry.ownerModulePath),
                    std::end(entry.ownerModulePath),
                    L'\0') != std::end(entry.ownerModulePath);
            const bool kPnpPresent =
                entry.pnpId[0] != L'\0';
            const bool kOwnerPathPresent =
                entry.ownerModulePath[0] != L'\0';
            const bool kPnpFlag =
                (entry.fieldFlags &
                 KSWORD_ARK_I8042_FIELD_PNP_ID) != 0UL;
            const bool kOwnerFlag =
                (entry.fieldFlags &
                 KSWORD_ARK_I8042_FIELD_OWNER_MODULE) != 0UL;
            const bool kCallbackFlag =
                (entry.fieldFlags &
                 KSWORD_ARK_I8042_FIELD_CALLBACK_ADDRESS) != 0UL;
            const bool kClassDeviceFlag =
                (entry.fieldFlags &
                 KSWORD_ARK_I8042_FIELD_CLASS_DEVICE_OBJECT) != 0UL;
            const bool kExecutableFlag =
                (entry.fieldFlags &
                 KSWORD_ARK_I8042_FIELD_EXECUTABLE) != 0UL;
            const bool kSameStackFlag =
                (entry.fieldFlags &
                 KSWORD_ARK_I8042_FIELD_SAME_DEVICE_STACK) != 0UL;
            const bool kEntryImageFlag =
                (entry.fieldFlags &
                 KSWORD_ARK_I8042_FIELD_IMAGE_VALIDATED) != 0UL;
            const bool kEntryDescriptorFlag =
                (entry.fieldFlags &
                 KSWORD_ARK_I8042_FIELD_DESCRIPTOR_VALIDATED) != 0UL;
            const bool kEndpointMatchesDevice =
                (entry.deviceKind == KSWORD_ARK_I8042_DEVICE_KEYBOARD &&
                 entry.endpointKind >=
                    KSWORD_ARK_I8042_ENDPOINT_KEYBOARD_CLASS_SERVICE &&
                 entry.endpointKind <=
                    KSWORD_ARK_I8042_ENDPOINT_KEYBOARD_ISR) ||
                (entry.deviceKind == KSWORD_ARK_I8042_DEVICE_MOUSE &&
                 entry.endpointKind >=
                    KSWORD_ARK_I8042_ENDPOINT_MOUSE_CLASS_SERVICE &&
                 entry.endpointKind <=
                    KSWORD_ARK_I8042_ENDPOINT_MOUSE_ISR);
            const bool kOwnerRangeValid =
                !kOwnerFlag ||
                (kCallbackFlag &&
                 entry.moduleBase != 0ULL &&
                 entry.moduleSize != 0UL &&
                 entry.callbackAddress >= entry.moduleBase &&
                 entry.callbackAddress - entry.moduleBase <
                    entry.moduleSize);
            const std::uint32_t kDeviceAllowedFields =
                KSWORD_ARK_I8042_FIELD_DEVICE_OBJECT |
                KSWORD_ARK_I8042_FIELD_PNP_ID |
                KSWORD_ARK_I8042_FIELD_IMAGE_VALIDATED |
                KSWORD_ARK_I8042_FIELD_DESCRIPTOR_VALIDATED |
                KSWORD_ARK_I8042_FIELD_DETAIL_ARGS;
            const bool kAvailableDevice =
                entry.status == KSWORD_ARK_I8042_AUDIT_STATUS_AVAILABLE &&
                entry.verdict == KSWORD_ARK_I8042_VERDICT_AVAILABLE &&
                entry.deviceKind != KSWORD_ARK_I8042_DEVICE_UNKNOWN &&
                (entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_DESCRIPTOR_VALIDATED ||
                 entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_GENERIC_DEVICE_AVAILABLE) &&
                entry.lastStatus == 0L;
            const bool kPartialDevice =
                entry.status == KSWORD_ARK_I8042_AUDIT_STATUS_PARTIAL &&
                entry.verdict == KSWORD_ARK_I8042_VERDICT_UNKNOWN &&
                entry.deviceKind == KSWORD_ARK_I8042_DEVICE_UNKNOWN &&
                entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_PNP_CLASS_UNKNOWN &&
                entry.lastStatus != 0L;
            const bool kFailedDevice =
                entry.status == KSWORD_ARK_I8042_AUDIT_STATUS_QUERY_FAILED &&
                entry.verdict == KSWORD_ARK_I8042_VERDICT_UNKNOWN &&
                entry.deviceKind == KSWORD_ARK_I8042_DEVICE_UNKNOWN &&
                entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_DRIVER_LAYOUT_MISMATCH &&
                entry.lastStatus != 0L;
            const bool kDeviceShape =
                entry.rowKind != KSWORD_ARK_I8042_AUDIT_ROW_DEVICE ||
                (entry.endpointKind == KSWORD_ARK_I8042_ENDPOINT_NONE &&
                 (entry.fieldFlags & ~kDeviceAllowedFields) == 0UL &&
                 (kAvailableDevice || kPartialDevice || kFailedDevice) &&
                 (entry.detailCode !=
                        KSWORD_ARK_I8042_DETAIL_DESCRIPTOR_VALIDATED ||
                  (kEntryImageFlag && kEntryDescriptorFlag)) &&
                 (entry.detailCode !=
                        KSWORD_ARK_I8042_DETAIL_GENERIC_DEVICE_AVAILABLE ||
                  !kEntryDescriptorFlag));
            const bool kAvailableEndpoint =
                entry.status == KSWORD_ARK_I8042_AUDIT_STATUS_AVAILABLE &&
                entry.verdict == KSWORD_ARK_I8042_VERDICT_AVAILABLE &&
                entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_ENDPOINT_AVAILABLE &&
                entry.lastStatus == 0L &&
                kCallbackFlag &&
                kClassDeviceFlag &&
                kOwnerFlag &&
                kExecutableFlag &&
                kSameStackFlag;
            const bool kNullEndpoint =
                entry.status == KSWORD_ARK_I8042_AUDIT_STATUS_UNAVAILABLE &&
                entry.verdict == KSWORD_ARK_I8042_VERDICT_UNKNOWN &&
                entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_ENDPOINT_NULL &&
                entry.lastStatus == 0L &&
                !kCallbackFlag &&
                !kOwnerFlag &&
                !kExecutableFlag &&
                !kSameStackFlag;
            const bool kSuspiciousEndpoint =
                entry.status ==
                    KSWORD_ARK_I8042_AUDIT_STATUS_SIGNATURE_MISMATCH &&
                entry.verdict == KSWORD_ARK_I8042_VERDICT_SUSPICIOUS &&
                entry.lastStatus != 0L &&
                kCallbackFlag &&
                (entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_OWNER_MISMATCH ||
                 entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_NON_EXECUTABLE ||
                 entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_CLASS_DO_OUTSIDE_STACK);
            const bool kEndpointShape =
                entry.rowKind != KSWORD_ARK_I8042_AUDIT_ROW_ENDPOINT ||
                (kEndpointMatchesDevice &&
                 kEntryImageFlag &&
                 kEntryDescriptorFlag &&
                 (kAvailableEndpoint ||
                  kNullEndpoint ||
                  kSuspiciousEndpoint));
            const bool kUnavailableDiagnostic =
                entry.status == KSWORD_ARK_I8042_AUDIT_STATUS_UNAVAILABLE &&
                entry.verdict == KSWORD_ARK_I8042_VERDICT_UNKNOWN &&
                entry.detailCode == KSWORD_ARK_I8042_DETAIL_NO_DEVICES;
            const bool kUnsupportedDiagnostic =
                entry.status == KSWORD_ARK_I8042_AUDIT_STATUS_UNSUPPORTED &&
                entry.verdict == KSWORD_ARK_I8042_VERDICT_UNSUPPORTED &&
                (entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_MODULE_NOT_FOUND ||
                 entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_DRIVER_NOT_FOUND ||
                 entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_IMAGE_MISMATCH ||
                 entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_RSDS_MISMATCH ||
                 entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_OPCODE_MISMATCH ||
                 entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_DRIVER_LAYOUT_MISMATCH);
            const bool kPartialDiagnostic =
                entry.status == KSWORD_ARK_I8042_AUDIT_STATUS_PARTIAL &&
                entry.verdict == KSWORD_ARK_I8042_VERDICT_UNKNOWN &&
                (entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_MODULE_NOT_FOUND ||
                 entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_IMAGE_MISMATCH ||
                 entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_RSDS_MISMATCH ||
                 entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_OPCODE_MISMATCH ||
                 entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_DRIVER_LAYOUT_MISMATCH);
            const bool kFailedDiagnostic =
                entry.status == KSWORD_ARK_I8042_AUDIT_STATUS_QUERY_FAILED &&
                (entry.verdict == KSWORD_ARK_I8042_VERDICT_UNKNOWN ||
                 (kFailClosed &&
                  entry.verdict ==
                    KSWORD_ARK_I8042_VERDICT_UNSUPPORTED)) &&
                (entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_MODULE_NOT_FOUND ||
                 entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_DRIVER_NOT_FOUND ||
                 entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_DEVICE_ENUM_FAILED ||
                 entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_EXTENSION_READ_FAILED);
            const bool kDiagnosticShape =
                entry.rowKind !=
                    KSWORD_ARK_I8042_AUDIT_ROW_DIAGNOSTIC ||
                (entry.deviceKind == KSWORD_ARK_I8042_DEVICE_UNKNOWN &&
                 entry.endpointKind == KSWORD_ARK_I8042_ENDPOINT_NONE &&
                 entry.fieldFlags ==
                    KSWORD_ARK_I8042_FIELD_DETAIL_ARGS &&
                 entry.lastStatus != 0L &&
                 (kUnavailableDiagnostic ||
                  kUnsupportedDiagnostic ||
                  kPartialDiagnostic ||
                  kFailedDiagnostic));
            const bool kRowShapeValid =
                (entry.rowKind == KSWORD_ARK_I8042_AUDIT_ROW_DEVICE &&
                 entry.endpointKind == KSWORD_ARK_I8042_ENDPOINT_NONE) ||
                (entry.rowKind == KSWORD_ARK_I8042_AUDIT_ROW_ENDPOINT &&
                 entry.deviceKind != KSWORD_ARK_I8042_DEVICE_UNKNOWN &&
                 entry.endpointKind >=
                    KSWORD_ARK_I8042_ENDPOINT_KEYBOARD_CLASS_SERVICE &&
                 entry.endpointKind <= KSWORD_ARK_I8042_ENDPOINT_MOUSE_ISR) ||
                (entry.rowKind == KSWORD_ARK_I8042_AUDIT_ROW_DIAGNOSTIC &&
                 entry.endpointKind == KSWORD_ARK_I8042_ENDPOINT_NONE);
            const bool kEntryValid =
                entry.size == sizeof(entry) &&
                entry.reserved0 == 0UL &&
                entry.reserved1 == 0UL &&
                kRowShapeValid &&
                entry.deviceKind <= KSWORD_ARK_I8042_DEVICE_MOUSE &&
                kValidStatus(entry.status) &&
                entry.verdict <= KSWORD_ARK_I8042_VERDICT_UNSUPPORTED &&
                (entry.fieldFlags & ~kKnownFieldFlags) == 0UL &&
                entry.detailCode <=
                    KSWORD_ARK_I8042_DETAIL_GENERIC_DEVICE_AVAILABLE &&
                kStringsValid &&
                kPnpFlag == kPnpPresent &&
                kOwnerFlag == kOwnerPathPresent &&
                kOwnerRangeValid &&
                kDeviceShape &&
                kEndpointShape &&
                kDiagnosticShape &&
                (((entry.fieldFlags &
                   KSWORD_ARK_I8042_FIELD_DETAIL_ARGS) != 0UL) ==
                 (entry.detailCode != KSWORD_ARK_I8042_DETAIL_NONE)) &&
                (((entry.fieldFlags &
                   KSWORD_ARK_I8042_FIELD_DEVICE_OBJECT) != 0UL) ==
                 (entry.deviceObject != 0ULL)) &&
                (((entry.fieldFlags &
                   KSWORD_ARK_I8042_FIELD_CLASS_DEVICE_OBJECT) != 0UL) ==
                 (entry.classDeviceObject != 0ULL)) &&
                (((entry.fieldFlags &
                   KSWORD_ARK_I8042_FIELD_CALLBACK_ADDRESS) != 0UL) ==
                 (entry.callbackAddress != 0ULL)) &&
                (((entry.fieldFlags &
                   KSWORD_ARK_I8042_FIELD_CONTEXT_ADDRESS) != 0UL) ==
                 (entry.contextAddress != 0ULL)) &&
                (((entry.fieldFlags &
                   KSWORD_ARK_I8042_FIELD_OWNER_MODULE) != 0UL) ==
                 (entry.moduleBase != 0ULL && entry.moduleSize != 0UL)) &&
                ((entry.fieldFlags &
                  KSWORD_ARK_I8042_FIELD_EXECUTABLE) == 0UL ||
                 (entry.fieldFlags &
                  (KSWORD_ARK_I8042_FIELD_CALLBACK_ADDRESS |
                   KSWORD_ARK_I8042_FIELD_OWNER_MODULE)) ==
                    (KSWORD_ARK_I8042_FIELD_CALLBACK_ADDRESS |
                     KSWORD_ARK_I8042_FIELD_OWNER_MODULE)) &&
                ((entry.fieldFlags &
                  KSWORD_ARK_I8042_FIELD_SAME_DEVICE_STACK) == 0UL ||
                 (entry.fieldFlags &
                  KSWORD_ARK_I8042_FIELD_CLASS_DEVICE_OBJECT) != 0UL) &&
                ((entry.fieldFlags &
                  KSWORD_ARK_I8042_FIELD_IMAGE_VALIDATED) == 0UL ||
                 kImageValidated) &&
                ((entry.fieldFlags &
                  KSWORD_ARK_I8042_FIELD_DESCRIPTOR_VALIDATED) == 0UL ||
                 kDescriptorValidated);
            if (!kEntryValid)
            {
                kFailProtocol(
                    "entry[" + std::to_string(index) + "] rejected");
                return result;
            }
            result.entries.push_back(entry);
        }

        const bool kAggregateValid =
            (response.queryStatus != KSWORD_ARK_I8042_AUDIT_STATUS_AVAILABLE ||
             std::all_of(
                 result.entries.begin(),
                 result.entries.end(),
                 [](const KSWORD_ARK_I8042_AUDIT_ENTRY& entry)
                 {
                     return entry.status ==
                         KSWORD_ARK_I8042_AUDIT_STATUS_AVAILABLE;
                 })) &&
            (!kFailClosed ||
             std::any_of(
                 result.entries.begin(),
                 result.entries.end(),
                 [](const KSWORD_ARK_I8042_AUDIT_ENTRY& entry)
                 {
                     return entry.rowKind ==
                            KSWORD_ARK_I8042_AUDIT_ROW_DIAGNOSTIC &&
                         entry.verdict ==
                            KSWORD_ARK_I8042_VERDICT_UNSUPPORTED;
                 }));
        if (!kAggregateValid)
        {
            kFailProtocol("entry aggregate rejected");
            return result;
        }

        result.version = response.version;
        result.status = response.queryStatus;
        result.responseFlags = response.responseFlags;
        result.totalCount = response.totalCount;
        result.returnedCount = response.returnedCount;
        result.entrySize = response.entrySize;
        result.descriptorId = response.descriptorId;
        result.imageTimeDateStamp = response.imageTimeDateStamp;
        result.imageSize = response.imageSize;
        result.imageChecksum = response.imageChecksum;
        result.pdbAge = response.pdbAge;
        result.imageBase = response.imageBase;
        std::copy(
            std::begin(response.pdbGuid),
            std::end(response.pdbGuid),
            std::begin(result.pdbGuid));
        result.lastStatus = response.lastStatus;
        result.io.ntStatus = response.lastStatus;
        result.unsupported =
            response.queryStatus ==
                KSWORD_ARK_I8042_AUDIT_STATUS_UNSUPPORTED ||
            (response.responseFlags &
             KSWORD_ARK_I8042_RESPONSE_FAIL_CLOSED) != 0UL;
        result.io.message = appendAuditSummary(
            kOperationName,
            result.totalCount,
            result.returnedCount,
            result.entries.size(),
            result.io.bytesReturned);
        return result;
    }
}
