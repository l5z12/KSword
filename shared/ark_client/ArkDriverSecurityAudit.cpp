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
    SecurityStatusAuditResult DriverClient::querySecurityStatus(const unsigned long flags) const
    {
        SecurityStatusAuditResult result{};
        KSWORD_ARK_QUERY_SECURITY_STATUS_REQUEST request{};
        request.size = sizeof(request);
        request.version = KSWORD_ARK_SECURITY_AUDIT_PROTOCOL_VERSION;
        request.flags = flags;
        result.io = queryFixedAudit(*this, IOCTL_KSWORD_ARK_QUERY_SECURITY_STATUS, &request, result.response, "IOCTL_KSWORD_ARK_QUERY_SECURITY_STATUS");
        markUnsupportedIfNeeded(result, "IOCTL_KSWORD_ARK_QUERY_SECURITY_STATUS");
        result.io.ntStatus = result.response.queryStatus;
        return result;
    }

    DriverTrustViewAuditResult DriverClient::queryDriverTrustView(const unsigned long flags, const unsigned long maxEntries) const
    {
        constexpr const char* kOperationName = "IOCTL_KSWORD_ARK_QUERY_DRIVER_TRUST_VIEW";
        DriverTrustViewAuditResult result{};
        KSWORD_ARK_QUERY_DRIVER_TRUST_VIEW_REQUEST request{};
        request.size = sizeof(request);
        request.version = KSWORD_ARK_SECURITY_AUDIT_PROTOCOL_VERSION;
        request.flags = flags;
        request.maxEntries = maxEntries;
        std::vector<std::uint8_t> responseBuffer(kDefaultAuditBufferBytes, 0U);
        result.io = deviceIoControl(IOCTL_KSWORD_ARK_QUERY_DRIVER_TRUST_VIEW, &request, sizeof(request), responseBuffer.data(), static_cast<unsigned long>(responseBuffer.size()));
        if (!result.io.ok)
        {
            markUnsupportedIfNeeded(result, kOperationName);
            return result;
        }

        constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_QUERY_DRIVER_TRUST_VIEW_RESPONSE) - sizeof(KSWORD_ARK_DRIVER_TRUST_VIEW_ENTRY);
        const auto* response = reinterpret_cast<const KSWORD_ARK_QUERY_DRIVER_TRUST_VIEW_RESPONSE*>(responseBuffer.data());
        const std::size_t kParsedCount = validateAuditRows(result.io, kHeaderSize, sizeof(KSWORD_ARK_DRIVER_TRUST_VIEW_ENTRY), sizeof(KSWORD_ARK_DRIVER_TRUST_VIEW_ENTRY), response->entryCount, kOperationName);
        if (!result.io.ok)
        {
            return result;
        }

        result.version = response->version;
        result.status = static_cast<std::uint32_t>(response->queryStatus);
        result.fieldFlags = response->fieldFlags;
        result.sourceMask = response->sourceMask;
        result.totalCount = response->totalModuleCount;
        result.returnedCount = response->entryCount;
        result.entrySize = sizeof(KSWORD_ARK_DRIVER_TRUST_VIEW_ENTRY);
        result.maxEntriesAccepted = response->maxEntriesAccepted;
        result.truncated = response->truncated;
        result.moduleQueryStatus = response->moduleQueryStatus;
        result.signingResolverStatus = response->signingResolverStatus;
        result.lastStatus = response->queryStatus;
        result.io.ntStatus = response->queryStatus;
        result.entries = parseVariableRows<KSWORD_ARK_DRIVER_TRUST_VIEW_ENTRY>(responseBuffer, kHeaderSize, sizeof(KSWORD_ARK_DRIVER_TRUST_VIEW_ENTRY), kParsedCount);
        result.io.message = appendAuditSummary(kOperationName, result.totalCount, result.returnedCount, result.entries.size(), result.io.bytesReturned);
        return result;
    }

    HyperVSummaryAuditResult DriverClient::queryHyperVSummary() const
    {
        HyperVSummaryAuditResult result{};
        result.io = queryNoInputFixedAudit(*this, IOCTL_KSWORD_ARK_QUERY_HYPERV_SUMMARY, result.response, "IOCTL_KSWORD_ARK_QUERY_HYPERV_SUMMARY");
        markUnsupportedIfNeeded(result, "IOCTL_KSWORD_ARK_QUERY_HYPERV_SUMMARY");
        result.io.ntStatus = result.response.queryStatus;
        return result;
    }

    AppControlStatusAuditResult DriverClient::queryAppControlStatus() const
    {
        AppControlStatusAuditResult result{};
        result.io = queryNoInputFixedAudit(*this, IOCTL_KSWORD_ARK_QUERY_APP_CONTROL_STATUS, result.response, "IOCTL_KSWORD_ARK_QUERY_APP_CONTROL_STATUS");
        markUnsupportedIfNeeded(result, "IOCTL_KSWORD_ARK_QUERY_APP_CONTROL_STATUS");
        result.io.ntStatus = result.response.queryStatus;
        return result;
    }
}
