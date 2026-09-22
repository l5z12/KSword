#include "ArkDriverClient.h"
#include "ArkDriverResponseSupport.h"

#include <algorithm>
#include <cstddef>
#include <sstream>

namespace ksword::ark
{
    namespace
    {
        constexpr std::size_t kMutationResponseHeaderSize =
            sizeof(KSWORD_ARK_MUTATION_RESPONSE);
        const std::size_t kMutationAuditResponseHeaderSize =
            KSWORD_ARK_MUTATION_AUDIT_RESPONSE_HEADER_SIZE;


        void copyBytesToVector(
            const unsigned char* bytes,
            const std::size_t maxBytes,
            std::vector<std::uint8_t>& bytesOut)
        {
            // Input: fixed-length byte array and length from the shared protocol.
            // Processing: Copy to the R3 vector while preserving the original order for UI/audit display.
            // Return: No return value; output is written to bytesOut.
            if (bytes == nullptr || maxBytes == 0U)
            {
                bytesOut.clear();
                return;
            }

            bytesOut.assign(bytes, bytes + maxBytes);
        }

        void copyVectorToFixedBytes(
            unsigned char* destination,
            const std::size_t destinationBytes,
            const std::vector<std::uint8_t>& sourceBytes)
        {
            // Input: Target fixed-length byte array and R3 vector.
            // Processing: Truncate copy and zero remaining space to ensure shared protocol field determinism.
            // Returns: Nothing.
            if (destination == nullptr || destinationBytes == 0U)
            {
                return;
            }

            std::fill(destination, destination + destinationBytes, std::uint8_t{0});
            const std::size_t kCopyBytes = std::min<std::size_t>(destinationBytes, sourceBytes.size());
            if (kCopyBytes != 0U)
            {
                std::copy(sourceBytes.begin(), sourceBytes.begin() + static_cast<std::ptrdiff_t>(kCopyBytes), destination);
            }
        }
    }

    MutationResponseResult DriverClient::prepareMutation(const MutationPrepareInput& input) const
    {
        // Input: Pre-preparation information for dry-run / audit / rollback.
        // Processing: Encapsulate PREPARE IOCTL; performs only protocol packaging and response parsing, without exposing arbitrary write UI.
        // Returns: MutationResponseResult; if unsupported=true, the UI can prompt that the driver is outdated.
        MutationResponseResult responseResult{};
        KSWORD_ARK_MUTATION_PREPARE_REQUEST request{};
        KSWORD_ARK_MUTATION_RESPONSE response{};
        request.size = static_cast<unsigned long>(sizeof(request));
        request.version = KSWORD_ARK_MUTATION_PROTOCOL_VERSION;
        request.flags = input.flags;
        request.targetKind = input.targetKind;
        request.processId = input.processId;
        request.bytes = input.bytes;
        request.targetAddress = input.targetAddress;
        request.targetContext = input.targetContext;
        copyVectorToFixedBytes(request.afterBytes, KSWORD_ARK_MUTATION_MAX_BYTES, input.afterBytes);
        copyVectorToFixedBytes(request.expectedBeforeBytes, KSWORD_ARK_MUTATION_MAX_BYTES, input.expectedBeforeBytes);

        responseResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_MUTATION_PREPARE,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &response,
            static_cast<unsigned long>(sizeof(response)));
        if (!responseResult.io.ok)
        {
            responseResult.unsupported = detail::isUnsupportedIoctlError(responseResult.io.win32Error);
            responseResult.io.message = responseResult.unsupported
                ? "IOCTL_KSWORD_ARK_MUTATION_PREPARE unsupported or driver version is too old"
                : "DeviceIoControl(IOCTL_KSWORD_ARK_MUTATION_PREPARE) failed, error=" +
                    std::to_string(responseResult.io.win32Error);
            return responseResult;
        }
        if (responseResult.io.bytesReturned < kMutationResponseHeaderSize)
        {
            responseResult.io.ok = false;
            responseResult.io.message =
                "mutation prepare response too small, bytesReturned=" +
                std::to_string(responseResult.io.bytesReturned);
            return responseResult;
        }

        responseResult.version = static_cast<std::uint32_t>(response.version);
        responseResult.status = static_cast<std::uint32_t>(response.status);
        responseResult.targetKind = static_cast<std::uint32_t>(response.targetKind);
        responseResult.processId = static_cast<std::uint32_t>(response.processId);
        responseResult.bytes = static_cast<std::uint32_t>(response.bytes);
        responseResult.riskFlags = static_cast<std::uint32_t>(response.riskFlags);
        responseResult.lastStatus = static_cast<long>(response.lastStatus);
        responseResult.transactionId = static_cast<std::uint64_t>(response.transactionId);
        responseResult.targetAddress = static_cast<std::uint64_t>(response.targetAddress);
        responseResult.targetContext = static_cast<std::uint64_t>(response.targetContext);
        responseResult.beforeHash = static_cast<std::uint64_t>(response.beforeHash);
        responseResult.afterHash = static_cast<std::uint64_t>(response.afterHash);
        responseResult.timestampTick = static_cast<std::uint64_t>(response.timestampTick);
        copyBytesToVector(response.beforeBytes, KSWORD_ARK_MUTATION_MAX_BYTES, responseResult.beforeBytes);
        copyBytesToVector(response.afterBytes, KSWORD_ARK_MUTATION_MAX_BYTES, responseResult.afterBytes);

        std::ostringstream stream;
        stream << "tx=" << responseResult.transactionId
            << ", status=" << responseResult.status
            << ", kind=" << responseResult.targetKind
            << ", bytes=" << responseResult.bytes
            << ", risk=0x" << std::hex << std::uppercase << responseResult.riskFlags
            << ", lastStatus=0x" << static_cast<unsigned long>(responseResult.lastStatus);
        responseResult.io.message = stream.str();
        return responseResult;
    }

    MutationResponseResult DriverClient::commitMutation(
        const std::uint64_t transactionId,
        const unsigned long flags) const
    {
        // Input: transactionId and commit flags.
        // Processing: Wrap COMMIT IOCTL, allow only controlled transactions, and do not provide arbitrary write parameters.
        // Return: MutationResponseResult. UI may display only dry-run, rejected, or committed states.
        MutationResponseResult responseResult{};
        KSWORD_ARK_MUTATION_TRANSACTION_REQUEST request{};
        KSWORD_ARK_MUTATION_RESPONSE response{};
        request.size = static_cast<unsigned long>(sizeof(request));
        request.version = KSWORD_ARK_MUTATION_PROTOCOL_VERSION;
        request.flags = flags;
        request.transactionId = transactionId;

        responseResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_MUTATION_COMMIT,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &response,
            static_cast<unsigned long>(sizeof(response)));
        if (!responseResult.io.ok)
        {
            responseResult.unsupported = detail::isUnsupportedIoctlError(responseResult.io.win32Error);
            responseResult.io.message = responseResult.unsupported
                ? "IOCTL_KSWORD_ARK_MUTATION_COMMIT unsupported or driver version is too old"
                : "DeviceIoControl(IOCTL_KSWORD_ARK_MUTATION_COMMIT) failed, error=" +
                    std::to_string(responseResult.io.win32Error);
            return responseResult;
        }
        if (responseResult.io.bytesReturned < kMutationResponseHeaderSize)
        {
            responseResult.io.ok = false;
            responseResult.io.message =
                "mutation commit response too small, bytesReturned=" +
                std::to_string(responseResult.io.bytesReturned);
            return responseResult;
        }

        responseResult.version = static_cast<std::uint32_t>(response.version);
        responseResult.status = static_cast<std::uint32_t>(response.status);
        responseResult.targetKind = static_cast<std::uint32_t>(response.targetKind);
        responseResult.processId = static_cast<std::uint32_t>(response.processId);
        responseResult.bytes = static_cast<std::uint32_t>(response.bytes);
        responseResult.riskFlags = static_cast<std::uint32_t>(response.riskFlags);
        responseResult.lastStatus = static_cast<long>(response.lastStatus);
        responseResult.transactionId = static_cast<std::uint64_t>(response.transactionId);
        responseResult.targetAddress = static_cast<std::uint64_t>(response.targetAddress);
        responseResult.targetContext = static_cast<std::uint64_t>(response.targetContext);
        responseResult.beforeHash = static_cast<std::uint64_t>(response.beforeHash);
        responseResult.afterHash = static_cast<std::uint64_t>(response.afterHash);
        responseResult.timestampTick = static_cast<std::uint64_t>(response.timestampTick);
        copyBytesToVector(response.beforeBytes, KSWORD_ARK_MUTATION_MAX_BYTES, responseResult.beforeBytes);
        copyBytesToVector(response.afterBytes, KSWORD_ARK_MUTATION_MAX_BYTES, responseResult.afterBytes);

        std::ostringstream stream;
        stream << "tx=" << responseResult.transactionId
            << ", status=" << responseResult.status
            << ", bytes=" << responseResult.bytes
            << ", risk=0x" << std::hex << std::uppercase << responseResult.riskFlags
            << ", lastStatus=0x" << static_cast<unsigned long>(responseResult.lastStatus);
        responseResult.io.message = stream.str();
        return responseResult;
    }

    MutationResponseResult DriverClient::rollbackMutation(
        const std::uint64_t transactionId,
        const unsigned long flags) const
    {
        // Input: transactionId and rollback flags.
        // Processing: Wrap ROLLBACK IOCTL, returning only transaction status without any direct write parameters.
        // Returns: MutationResponseResult; R3 can only display rollback / dry-run / rejected.
        MutationResponseResult responseResult{};
        KSWORD_ARK_MUTATION_TRANSACTION_REQUEST request{};
        KSWORD_ARK_MUTATION_RESPONSE response{};
        request.size = static_cast<unsigned long>(sizeof(request));
        request.version = KSWORD_ARK_MUTATION_PROTOCOL_VERSION;
        request.flags = flags;
        request.transactionId = transactionId;

        responseResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_MUTATION_ROLLBACK,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &response,
            static_cast<unsigned long>(sizeof(response)));
        if (!responseResult.io.ok)
        {
            responseResult.unsupported = detail::isUnsupportedIoctlError(responseResult.io.win32Error);
            responseResult.io.message = responseResult.unsupported
                ? "IOCTL_KSWORD_ARK_MUTATION_ROLLBACK unsupported or driver version is too old"
                : "DeviceIoControl(IOCTL_KSWORD_ARK_MUTATION_ROLLBACK) failed, error=" +
                    std::to_string(responseResult.io.win32Error);
            return responseResult;
        }
        if (responseResult.io.bytesReturned < kMutationResponseHeaderSize)
        {
            responseResult.io.ok = false;
            responseResult.io.message =
                "mutation rollback response too small, bytesReturned=" +
                std::to_string(responseResult.io.bytesReturned);
            return responseResult;
        }

        responseResult.version = static_cast<std::uint32_t>(response.version);
        responseResult.status = static_cast<std::uint32_t>(response.status);
        responseResult.targetKind = static_cast<std::uint32_t>(response.targetKind);
        responseResult.processId = static_cast<std::uint32_t>(response.processId);
        responseResult.bytes = static_cast<std::uint32_t>(response.bytes);
        responseResult.riskFlags = static_cast<std::uint32_t>(response.riskFlags);
        responseResult.lastStatus = static_cast<long>(response.lastStatus);
        responseResult.transactionId = static_cast<std::uint64_t>(response.transactionId);
        responseResult.targetAddress = static_cast<std::uint64_t>(response.targetAddress);
        responseResult.targetContext = static_cast<std::uint64_t>(response.targetContext);
        responseResult.beforeHash = static_cast<std::uint64_t>(response.beforeHash);
        responseResult.afterHash = static_cast<std::uint64_t>(response.afterHash);
        responseResult.timestampTick = static_cast<std::uint64_t>(response.timestampTick);
        copyBytesToVector(response.beforeBytes, KSWORD_ARK_MUTATION_MAX_BYTES, responseResult.beforeBytes);
        copyBytesToVector(response.afterBytes, KSWORD_ARK_MUTATION_MAX_BYTES, responseResult.afterBytes);

        std::ostringstream stream;
        stream << "tx=" << responseResult.transactionId
            << ", status=" << responseResult.status
            << ", bytes=" << responseResult.bytes
            << ", risk=0x" << std::hex << std::uppercase << responseResult.riskFlags
            << ", lastStatus=0x" << static_cast<unsigned long>(responseResult.lastStatus);
        responseResult.io.message = stream.str();
        return responseResult;
    }

    MutationAuditResult DriverClient::queryMutationAudit(
        const unsigned long flags,
        const unsigned long maxEntries,
        const std::uint64_t startSequence) const
    {
        // Input: audit flags, maximum count, and starting sequence.
        // Processing: Read the R0 mutation audit ring; read-only decode transaction metadata and optional byte snapshots.
        // Return: MutationAuditResult; unsupported=true for old drivers or unregistered IOCTLs.
        MutationAuditResult auditResult{};
        KSWORD_ARK_MUTATION_QUERY_AUDIT_REQUEST request{};
        request.size = static_cast<unsigned long>(sizeof(request));
        request.version = KSWORD_ARK_MUTATION_PROTOCOL_VERSION;
        request.flags = flags;
        request.maxEntries = maxEntries;
        request.startSequence = startSequence;

        std::vector<std::uint8_t> responseBuffer(2U * 1024U * 1024U, 0U);
        auditResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_MUTATION_QUERY_AUDIT,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        if (!auditResult.io.ok)
        {
            auditResult.unsupported = detail::isUnsupportedIoctlError(auditResult.io.win32Error);
            auditResult.io.message = auditResult.unsupported
                ? "IOCTL_KSWORD_ARK_MUTATION_QUERY_AUDIT unsupported or driver version is too old"
                : "DeviceIoControl(IOCTL_KSWORD_ARK_MUTATION_QUERY_AUDIT) failed, error=" +
                    std::to_string(auditResult.io.win32Error);
            return auditResult;
        }
        if (auditResult.io.bytesReturned < kMutationAuditResponseHeaderSize)
        {
            auditResult.io.ok = false;
            auditResult.io.message =
                "mutation audit response too small, bytesReturned=" +
                std::to_string(auditResult.io.bytesReturned);
            return auditResult;
        }

        const auto* responseHeader =
            reinterpret_cast<const KSWORD_ARK_MUTATION_QUERY_AUDIT_RESPONSE*>(responseBuffer.data());
        if (responseHeader->entrySize < sizeof(KSWORD_ARK_MUTATION_AUDIT_ENTRY))
        {
            auditResult.io.ok = false;
            auditResult.io.message =
                "mutation audit entrySize invalid, entrySize=" +
                std::to_string(responseHeader->entrySize);
            return auditResult;
        }

        auditResult.version = static_cast<std::uint32_t>(responseHeader->version);
        auditResult.totalCount = static_cast<std::uint32_t>(responseHeader->totalCount);
        auditResult.returnedCount = static_cast<std::uint32_t>(responseHeader->returnedCount);
        auditResult.lostCount = static_cast<std::uint32_t>(responseHeader->lostCount);
        auditResult.oldestSequence = static_cast<std::uint64_t>(responseHeader->oldestSequence);
        auditResult.nextSequence = static_cast<std::uint64_t>(responseHeader->nextSequence);

        const std::size_t kAvailableCount =
            (static_cast<std::size_t>(auditResult.io.bytesReturned) - kMutationAuditResponseHeaderSize) /
            static_cast<std::size_t>(responseHeader->entrySize);
        const std::size_t kParsedCount = std::min<std::size_t>(
            static_cast<std::size_t>(responseHeader->returnedCount),
            kAvailableCount);
        auditResult.entries.reserve(kParsedCount);
        for (std::size_t index = 0U; index < kParsedCount; ++index)
        {
            const std::size_t kEntryOffset =
                kMutationAuditResponseHeaderSize +
                (index * static_cast<std::size_t>(responseHeader->entrySize));
            if (kEntryOffset + sizeof(KSWORD_ARK_MUTATION_AUDIT_ENTRY) > responseBuffer.size())
            {
                break;
            }

            const auto* sourceEntry =
                reinterpret_cast<const KSWORD_ARK_MUTATION_AUDIT_ENTRY*>(responseBuffer.data() + kEntryOffset);
            MutationAuditEntry row{};
            row.operation = static_cast<std::uint32_t>(sourceEntry->operation);
            row.status = static_cast<std::uint32_t>(sourceEntry->status);
            row.lastStatus = static_cast<long>(sourceEntry->lastStatus);
            row.targetKind = static_cast<std::uint32_t>(sourceEntry->targetKind);
            row.riskFlags = static_cast<std::uint32_t>(sourceEntry->riskFlags);
            row.flags = static_cast<std::uint32_t>(sourceEntry->flags);
            row.processId = static_cast<std::uint32_t>(sourceEntry->processId);
            row.bytes = static_cast<std::uint32_t>(sourceEntry->bytes);
            row.transactionId = static_cast<std::uint64_t>(sourceEntry->transactionId);
            row.sequence = static_cast<std::uint64_t>(sourceEntry->sequence);
            row.targetAddress = static_cast<std::uint64_t>(sourceEntry->targetAddress);
            row.targetContext = static_cast<std::uint64_t>(sourceEntry->targetContext);
            row.beforeHash = static_cast<std::uint64_t>(sourceEntry->beforeHash);
            row.afterHash = static_cast<std::uint64_t>(sourceEntry->afterHash);
            row.timestampTick = static_cast<std::uint64_t>(sourceEntry->timestampTick);
            copyBytesToVector(sourceEntry->byteData, KSWORD_ARK_MUTATION_MAX_BYTES, row.byteData);
            auditResult.entries.push_back(std::move(row));
        }

        std::ostringstream stream;
        stream << "version=" << auditResult.version
            << ", total=" << auditResult.totalCount
            << ", returned=" << auditResult.returnedCount
            << ", parsed=" << auditResult.entries.size()
            << ", lost=" << auditResult.lostCount
            << ", nextSequence=" << auditResult.nextSequence;
        auditResult.io.message = stream.str();
        return auditResult;
    }
}
