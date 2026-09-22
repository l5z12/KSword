#include "ArkDriverClient.h"
#include "ArkDriverResponseSupport.h"

#include <cstddef>
#include <sstream>
#include <string>

static_assert(
    sizeof(KSWORD_ARK_DRIVER_IMAGE_REQUEST) == 664U,
    "Driver image request ABI drifted");
static_assert(
    sizeof(KSWORD_ARK_DRIVER_IMAGE_RESPONSE) == 816U,
    "Driver image response ABI drifted");

namespace
{
    // Copy canonical object name to fixed protocol array; truncate with null terminator if input is too long.
    void copyImageDriverName(
        wchar_t* destination,
        const std::size_t destinationChars,
        const std::wstring& source)
    {
        if (destination == nullptr || destinationChars == 0U)
        {
            return;
        }
        const std::size_t kCopyChars =
            source.size() < (destinationChars - 1U)
            ? source.size()
            : (destinationChars - 1U);
        for (std::size_t index = 0U; index < kCopyChars; ++index)
        {
            destination[index] = source[index];
        }
        destination[kCopyChars] = L'\0';
    }


    // R3-friendly value model to shared protocol structure; all fields are retained as 64-bit without address policy checks.
    KSWORD_ARK_DRIVER_IMAGE_VALUES toWireValues(
        const ksword::ark::DriverImageValues& source)
    {
        KSWORD_ARK_DRIVER_IMAGE_VALUES values{};
        values.driverStart = source.driverStart;
        values.driverSize = source.driverSize;
        values.driverSection = source.driverSection;
        values.kldrDllBase = source.kldrDllBase;
        values.kldrSizeOfImage = source.kldrSizeOfImage;
        return values;
    }

    // Convert shared protocol structure to R3 model for unified table and detail usage.
    ksword::ark::DriverImageValues fromWireValues(
        const KSWORD_ARK_DRIVER_IMAGE_VALUES& source)
    {
        ksword::ark::DriverImageValues values{};
        values.driverStart = source.driverStart;
        values.driverSize = source.driverSize;
        values.driverSection = source.driverSection;
        values.kldrDllBase = source.kldrDllBase;
        values.kldrSizeOfImage = source.kldrSizeOfImage;
        return values;
    }

}

namespace ksword::ark
{
    // Unify Driver image transaction transmission. All targets and value policies are determined by the caller; R3 only encodes and validates the protocol.
    DriverImageControlResult DriverClient::controlDriverImage(
        const std::uint64_t moduleBase,
        const std::wstring& canonicalDriverName,
        const unsigned long action,
        const unsigned long fieldMask,
        const std::uint64_t expectedDriverObjectAddress,
        const std::uint32_t expectedGeneration,
        const DriverImageValues& expectedValues,
        const DriverImageValues& desiredValues,
        const std::uint64_t expectedLinkFlink,
        const std::uint64_t expectedLinkBlink,
        const bool restoreLink,
        const bool uiConfirmed) const
    {
        DriverImageControlResult result{};
        KSWORD_ARK_DRIVER_IMAGE_REQUEST request{};
        KSWORD_ARK_DRIVER_IMAGE_RESPONSE response{};

        request.version = KSWORD_ARK_DRIVER_IMAGE_PROTOCOL_VERSION;
        request.action = action;
        request.flags = 0U;
        request.fieldMask = fieldMask;
        // A module base address of zero indicates querying existing records by exact DriverObject/name.
        // R0 derives identity from the real-time DriverStart for new targets and returns the frozen base address for old targets.
        if (moduleBase != 0U)
        {
            request.flags |= KSWORD_ARK_DRIVER_IMAGE_FLAG_TARGET_MODULE_BASE_PRESENT;
            request.targetModuleBase = moduleBase;
        }
        request.expectedDriverObjectAddress =
            expectedDriverObjectAddress;
        request.expectedGeneration = expectedGeneration;
        request.expectedLinkFlink = expectedLinkFlink;
        request.expectedLinkBlink = expectedLinkBlink;
        request.expectedValues = toWireValues(expectedValues);
        request.desiredValues = toWireValues(desiredValues);

        if (expectedDriverObjectAddress != 0U)
        {
            request.flags |=
                KSWORD_ARK_DRIVER_IMAGE_FLAG_EXPECTED_DRIVER_OBJECT_PRESENT;
        }
        if (expectedGeneration != 0U)
        {
            request.flags |=
                KSWORD_ARK_DRIVER_IMAGE_FLAG_EXPECTED_GENERATION_PRESENT;
        }
        if (action == KSWORD_ARK_DRIVER_IMAGE_ACTION_APPLY_FIELDS)
        {
            request.flags |=
                KSWORD_ARK_DRIVER_IMAGE_FLAG_EXPECTED_VALUES_PRESENT;
        }
        if (action == KSWORD_ARK_DRIVER_IMAGE_ACTION_HIDE)
        {
            request.flags |=
                KSWORD_ARK_DRIVER_IMAGE_FLAG_EXPECTED_LINKS_PRESENT;
        }
        if (restoreLink)
        {
            request.flags |= KSWORD_ARK_DRIVER_IMAGE_FLAG_RESTORE_LINK;
        }
        if (uiConfirmed)
        {
            request.flags |= KSWORD_ARK_DRIVER_IMAGE_FLAG_UI_CONFIRMED;
            request.confirmationToken =
                KSWORD_ARK_DRIVER_IMAGE_CONFIRMATION_TOKEN;
        }
        copyImageDriverName(
            request.driverName,
            KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS,
            canonicalDriverName);

        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_CONTROL_DRIVER_IMAGE,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &response,
            static_cast<unsigned long>(sizeof(response)));
        if (!result.io.ok)
        {
            result.unsupported =
                detail::isUnsupportedIoctlError(result.io.win32Error);
            result.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_CONTROL_DRIVER_IMAGE) failed, error=" +
                std::to_string(result.io.win32Error);
            return result;
        }
        if (result.io.bytesReturned < sizeof(response))
        {
            result.io.ok = false;
            result.io.message =
                "driver-image response too small, bytesReturned=" +
                std::to_string(result.io.bytesReturned);
            return result;
        }
        if (response.version != KSWORD_ARK_DRIVER_IMAGE_PROTOCOL_VERSION ||
            response.action != action ||
            (moduleBase != 0U &&
             expectedDriverObjectAddress == 0U &&
             response.targetModuleBase != moduleBase) ||
            (response.lastStatus >= 0 &&
             expectedDriverObjectAddress != 0U &&
             response.driverObjectAddress != expectedDriverObjectAddress))
        {
            result.io.ok = false;
            result.io.message = "driver-image response protocol mismatch";
            return result;
        }

        result.version = response.version;
        result.action = response.action;
        result.state = response.state;
        result.responseFlags = response.responseFlags;
        result.lastStatus = response.lastStatus;
        result.loaderStatus = response.loaderStatus;
        result.generation = response.generation;
        result.managedFieldMask = response.managedFieldMask;
        result.ownedFieldMask = response.ownedFieldMask;
        result.conflictFieldMask = response.conflictFieldMask;
        result.changedFieldMask = response.changedFieldMask;
        result.layoutFlags = response.layoutFlags;
        result.targetModuleBase = response.targetModuleBase;
        result.driverObjectAddress = response.driverObjectAddress;
        result.selfDriverObjectAddress = response.selfDriverObjectAddress;
        result.loaderEntryAddress = response.loaderEntryAddress;
        result.listHeadAddress = response.listHeadAddress;
        result.listResourceAddress = response.listResourceAddress;
        result.loaderLinkAddress = response.loaderLinkAddress;
        result.currentLinkFlink = response.currentLinkFlink;
        result.currentLinkBlink = response.currentLinkBlink;
        result.originalLinkFlink = response.originalLinkFlink;
        result.originalLinkBlink = response.originalLinkBlink;
        result.currentValues = fromWireValues(response.currentValues);
        result.originalValues = fromWireValues(response.originalValues);
        result.appliedValues = fromWireValues(response.appliedValues);
        result.requestedValues = fromWireValues(response.requestedValues);
        result.driverName = detail::readFixedString(
            response.driverName,
            KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS);
        result.io.ntStatus = result.lastStatus;

        std::ostringstream stream;
        stream << "action=" << result.action
            << ", status=0x" << std::hex
            << static_cast<unsigned long>(result.lastStatus)
            << ", loader=0x"
            << static_cast<unsigned long>(result.loaderStatus)
            << ", fields=0x" << result.managedFieldMask
            << ", flags=0x" << result.responseFlags
            << std::dec << ", generation=" << result.generation;
        result.io.message = stream.str();
        return result;
    }

    // Query only carries stable identity; R0 returns real-time fields, chains, and potentially transaction records.
    DriverImageControlResult DriverClient::queryDriverImage(
        const std::uint64_t moduleBase,
        const std::wstring& canonicalDriverName,
        const std::uint64_t expectedDriverObjectAddress) const
    {
        return controlDriverImage(
            moduleBase,
            canonicalDriverName,
            KSWORD_ARK_DRIVER_IMAGE_ACTION_QUERY,
            0U,
            expectedDriverObjectAddress,
            0U,
            DriverImageValues{},
            DriverImageValues{});
    }

    // Batch field modifications carry the same query snapshot and generation, achieving an all-or-nothing semantics across the five fields.
    DriverImageControlResult DriverClient::applyDriverImageFields(
        const std::uint64_t moduleBase,
        const std::wstring& canonicalDriverName,
        const unsigned long fieldMask,
        const std::uint64_t expectedDriverObjectAddress,
        const std::uint32_t expectedGeneration,
        const DriverImageValues& expectedValues,
        const DriverImageValues& desiredValues) const
    {
        return controlDriverImage(
            moduleBase,
            canonicalDriverName,
            KSWORD_ARK_DRIVER_IMAGE_ACTION_APPLY_FIELDS,
            fieldMask,
            expectedDriverObjectAddress,
            expectedGeneration,
            expectedValues,
            desiredValues,
            0U,
            0U,
            false,
            true);
    }

    // Unlinking must return the exact adjacent pointer just queried to avoid overwriting concurrent load/unload changes.
    DriverImageControlResult DriverClient::hideDriverImage(
        const std::uint64_t moduleBase,
        const std::wstring& canonicalDriverName,
        const std::uint64_t expectedDriverObjectAddress,
        const std::uint32_t expectedGeneration,
        const std::uint64_t expectedLinkFlink,
        const std::uint64_t expectedLinkBlink) const
    {
        return controlDriverImage(
            moduleBase,
            canonicalDriverName,
            KSWORD_ARK_DRIVER_IMAGE_ACTION_HIDE,
            0U,
            expectedDriverObjectAddress,
            expectedGeneration,
            DriverImageValues{},
            DriverImageValues{},
            expectedLinkFlink,
            expectedLinkBlink,
            false,
            true);
    }

    // Restoration can select both fields and the load chain; a zero fieldMask indicates processing only the load chain.
    DriverImageControlResult DriverClient::restoreDriverImage(
        const std::uint64_t moduleBase,
        const std::wstring& canonicalDriverName,
        const unsigned long fieldMask,
        const bool restoreLink,
        const std::uint64_t expectedDriverObjectAddress,
        const std::uint32_t expectedGeneration) const
    {
        return controlDriverImage(
            moduleBase,
            canonicalDriverName,
            KSWORD_ARK_DRIVER_IMAGE_ACTION_RESTORE,
            fieldMask,
            expectedDriverObjectAddress,
            expectedGeneration,
            DriverImageValues{},
            DriverImageValues{},
            0U,
            0U,
            restoreLink,
            true);
    }

    // Abandonment only removes R0 recovery records and avoids touching any current fields or load chains.
    DriverImageControlResult DriverClient::abandonDriverImage(
        const std::uint64_t moduleBase,
        const std::wstring& canonicalDriverName,
        const std::uint64_t expectedDriverObjectAddress,
        const std::uint32_t expectedGeneration) const
    {
        return controlDriverImage(
            moduleBase,
            canonicalDriverName,
            KSWORD_ARK_DRIVER_IMAGE_ACTION_ABANDON,
            0U,
            expectedDriverObjectAddress,
            expectedGeneration,
            DriverImageValues{},
            DriverImageValues{},
            0U,
            0U,
            false,
            true);
    }
}
