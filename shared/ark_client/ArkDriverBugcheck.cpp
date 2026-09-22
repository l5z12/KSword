#include "ArkDriverClient.h"

#include <chrono>
#include <cstring>
#include <limits>
#include <thread>

namespace ksword::ark
{
    IoResult DriverClient::setBugcheckBitmap(
        const std::uint32_t width,
        const std::uint32_t height,
        const std::uint32_t stride,
        const std::uint32_t brandColorRgb,
        const std::vector<std::uint8_t>& bgraPixels) const
    {
        IoResult result{};
        const std::uint64_t kExpectedStride = static_cast<std::uint64_t>(width) * 4ULL;
        const std::uint64_t kExpectedBytes = kExpectedStride * static_cast<std::uint64_t>(height);

        if (width == 0 || height == 0 ||
            width > KSWORD_ARK_BUGCHECK_BITMAP_MAX_WIDTH ||
            height > KSWORD_ARK_BUGCHECK_BITMAP_MAX_HEIGHT ||
            stride != kExpectedStride ||
            kExpectedBytes == 0 ||
            kExpectedBytes > KSWORD_ARK_BUGCHECK_BITMAP_MAX_BYTES ||
            bgraPixels.size() != static_cast<std::size_t>(kExpectedBytes))
        {
            result.win32Error = ERROR_INVALID_PARAMETER;
            return result;
        }

        const std::size_t kPayloadBytes = sizeof(KSWORD_ARK_BUGCHECK_BITMAP_HEADER) + bgraPixels.size();
        if (kPayloadBytes > std::numeric_limits<unsigned long>::max())
        {
            result.win32Error = ERROR_ARITHMETIC_OVERFLOW;
            return result;
        }

        KSWORD_ARK_BUGCHECK_BITMAP_HEADER header{};
        header.version = KSWORD_ARK_BUGCHECK_BITMAP_PROTOCOL_VERSION;
        header.size = sizeof(header);
        header.magic = KSWORD_ARK_BUGCHECK_BITMAP_MAGIC;
        header.width = width;
        header.height = height;
        header.stride = stride;
        header.format = KSWORD_ARK_BUGCHECK_BITMAP_FORMAT_BGRA32;
        header.brandColorRgb = brandColorRgb & 0x00FFFFFFUL;
        header.dataLength = static_cast<unsigned long>(bgraPixels.size());

        std::vector<std::uint8_t> payload(kPayloadBytes);
        std::memcpy(payload.data(), &header, sizeof(header));
        std::memcpy(payload.data() + sizeof(header), bgraPixels.data(), bgraPixels.size());

        return deviceIoControl(
            IOCTL_KSWORD_ARK_SET_BUGCHECK_BITMAP,
            payload.data(),
            static_cast<unsigned long>(payload.size()),
            nullptr,
            0);
    }

    IoResult DriverClient::setBugcheckVerdictResources(
        const std::vector<BugcheckVerdictBitmap>& resources) const
    {
        IoResult result{};
        std::uint32_t seenMask = 0;
        std::uint64_t dataBytes = 0;

        if (resources.size() != KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_COUNT)
        {
            result.win32Error = ERROR_INVALID_PARAMETER;
            return result;
        }

        for (const BugcheckVerdictBitmap& resource : resources)
        {
            const std::uint64_t kExpectedStride =
                static_cast<std::uint64_t>(resource.width) * 4ULL;
            const std::uint64_t kExpectedBytes =
                kExpectedStride * static_cast<std::uint64_t>(resource.height);
            if (resource.language >= KSWORD_ARK_BUGCHECK_VERDICT_LANGUAGE_COUNT ||
                resource.classification >= KSWORD_ARK_BUGCHECK_VERDICT_CLASS_COUNT ||
                resource.width == 0 || resource.height == 0 ||
                resource.width > KSWORD_ARK_BUGCHECK_VERDICT_MAX_WIDTH ||
                resource.height > KSWORD_ARK_BUGCHECK_VERDICT_MAX_HEIGHT ||
                resource.stride != kExpectedStride ||
                kExpectedBytes == 0 ||
                kExpectedBytes != resource.bgraPixels.size())
            {
                result.win32Error = ERROR_INVALID_PARAMETER;
                return result;
            }

            const std::uint32_t kBitIndex =
                resource.language * KSWORD_ARK_BUGCHECK_VERDICT_CLASS_COUNT +
                resource.classification;
            const std::uint32_t kBit = 1UL << kBitIndex;
            if ((seenMask & kBit) != 0)
            {
                result.win32Error = ERROR_INVALID_PARAMETER;
                return result;
            }
            seenMask |= kBit;
            dataBytes += kExpectedBytes;
        }

        const std::uint64_t kEntriesBytes =
            sizeof(KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_ENTRY) *
            KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_COUNT;
        const std::uint64_t kPacketBytes64 =
            sizeof(KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_HEADER) +
            kEntriesBytes + dataBytes;
        if (dataBytes > KSWORD_ARK_BUGCHECK_VERDICT_MAX_DATA_BYTES ||
            kPacketBytes64 > std::numeric_limits<unsigned long>::max())
        {
            result.win32Error = ERROR_ARITHMETIC_OVERFLOW;
            return result;
        }

        std::vector<std::uint8_t> packet(
            static_cast<std::size_t>(kPacketBytes64));
        auto* header = reinterpret_cast<
            KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_HEADER*>(packet.data());
        auto* entries = reinterpret_cast<
            KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_ENTRY*>(
                packet.data() + sizeof(*header));
        header->version = KSWORD_ARK_BUGCHECK_VERDICT_PROTOCOL_VERSION;
        header->size = sizeof(*header);
        header->magic = KSWORD_ARK_BUGCHECK_VERDICT_MAGIC;
        header->resourceCount =
            KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_COUNT;
        header->entriesOffset = sizeof(*header);
        header->totalSize = static_cast<unsigned long>(packet.size());

        std::size_t dataOffset = sizeof(*header) +
            static_cast<std::size_t>(kEntriesBytes);
        for (std::size_t index = 0; index < resources.size(); ++index)
        {
            const BugcheckVerdictBitmap& resource = resources[index];
            KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_ENTRY& entry = entries[index];
            entry.language = resource.language;
            entry.classification = resource.classification;
            entry.width = resource.width;
            entry.height = resource.height;
            entry.stride = resource.stride;
            entry.format = KSWORD_ARK_BUGCHECK_VERDICT_FORMAT_BGRA32;
            entry.dataOffset = static_cast<unsigned long>(dataOffset);
            entry.dataLength = static_cast<unsigned long>(
                resource.bgraPixels.size());
            std::memcpy(
                packet.data() + dataOffset,
                resource.bgraPixels.data(),
                resource.bgraPixels.size());
            dataOffset += resource.bgraPixels.size();
        }

        return deviceIoControl(
            IOCTL_KSWORD_ARK_SET_BUGCHECK_VERDICT_RESOURCES,
            packet.data(),
            static_cast<unsigned long>(packet.size()),
            nullptr,
            0);
    }

    BugcheckDiagnosticsResult DriverClient::configureBugcheckDiagnostics(
        const unsigned long action) const
    {
        const auto kSendRequest = [this](const unsigned long requestAction)
        {
            BugcheckDiagnosticsResult current{};
            KSWORD_ARK_BUGCHECK_DIAGNOSTICS_REQUEST request{};

            // Reserved fields must remain zero to match strict R0 validation; INSTALL only queues, QUERY reads the final state and phase.
            request.size = sizeof(request);
            request.version = KSWORD_ARK_BUGCHECK_DIAGNOSTICS_PROTOCOL_VERSION;
            request.action = requestAction;
            current.io = deviceIoControl(
                IOCTL_KSWORD_ARK_CONFIGURE_BUGCHECK_DIAGNOSTICS,
                &request,
                static_cast<unsigned long>(sizeof(request)),
                &current.response,
                static_cast<unsigned long>(sizeof(current.response)));
            current.unsupported = !current.io.ok &&
                (current.io.win32Error == ERROR_INVALID_FUNCTION ||
                 current.io.win32Error == ERROR_NOT_SUPPORTED);
            if (current.io.ok &&
                (current.io.bytesReturned < sizeof(current.response) ||
                 current.response.version !=
                     KSWORD_ARK_BUGCHECK_DIAGNOSTICS_PROTOCOL_VERSION ||
                 current.response.size != sizeof(current.response)))
            {
                current.io.ok = false;
                current.io.win32Error = ERROR_INVALID_DATA;
            }
            current.io.ntStatus = current.response.lastStatus;
            return current;
        };

        BugcheckDiagnosticsResult result = kSendRequest(action);
        if (action != KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ACTION_INSTALL ||
            !result.io.ok ||
            result.response.status != KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATUS_BUSY)
        {
            return result;
        }

        // The new protocol's installation IOCTL no longer holds a device handle waiting for R0. Background calls use short QUERY polling to reach the
        // final state; during driver unloading, the next query fails quickly, preventing the thread from blocking the SCM from stopping the service.
        const auto kPollDeadline = std::chrono::steady_clock::now() +
            std::chrono::seconds(35);
        do
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            result = kSendRequest(KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ACTION_QUERY);
            if (!result.io.ok ||
                result.response.status != KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATUS_BUSY)
            {
                return result;
            }
        } while (std::chrono::steady_clock::now() < kPollDeadline);

        // Restricts only the R3 polling thread; actual R0 work items have their own 30-second budget and unload cancellation protocol.
        return result;
    }

    BugcheckGuardResult DriverClient::configureBugcheckGuard(
        const unsigned long action,
        const unsigned long delaySeconds,
        const bool uiConfirmed,
        const bool tryIgnoreError,
        DriverHandle* const existingHandle) const
    {
        BugcheckGuardResult result{};
        KSWORD_ARK_BUGCHECK_GUARD_REQUEST request{};

        request.size = sizeof(request);
        request.version = KSWORD_ARK_BUGCHECK_GUARD_PROTOCOL_VERSION;
        request.action = action;
        request.delaySeconds = delaySeconds;
        if (uiConfirmed) {
            request.flags = KSWORD_ARK_BUGCHECK_GUARD_FLAG_UI_CONFIRMED;
            request.confirmationToken =
                KSWORD_ARK_BUGCHECK_GUARD_CONFIRMATION_TOKEN;
        }
        if (tryIgnoreError) {
            request.flags |= KSWORD_ARK_BUGCHECK_GUARD_FLAG_TRY_IGNORE_ERROR;
        }
        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_CONFIGURE_BUGCHECK_GUARD,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &result.response,
            static_cast<unsigned long>(sizeof(result.response)),
            existingHandle);
        result.unsupported = !result.io.ok &&
            (result.io.win32Error == ERROR_INVALID_FUNCTION ||
             result.io.win32Error == ERROR_NOT_SUPPORTED);
        if (result.io.ok &&
            (result.io.bytesReturned < sizeof(result.response) ||
             result.response.version != KSWORD_ARK_BUGCHECK_GUARD_PROTOCOL_VERSION ||
             result.response.size != sizeof(result.response))) {
            result.unsupported = result.io.bytesReturned >= sizeof(result.response) &&
                result.response.version != KSWORD_ARK_BUGCHECK_GUARD_PROTOCOL_VERSION;
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_DATA;
        }
        result.io.ntStatus = result.response.lastStatus;
        return result;
    }
}
