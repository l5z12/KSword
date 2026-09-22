#include "ArkDriverClient.h"
#include "ArkDriverResponseSupport.h"

#include <cstddef>
#include <string>

namespace
{
    // copyDriverCommunicationName：
    // - Input: R3 DriverObject name and shared protocol fixed buffer;
    // - Processing: Copy by character boundary and ensure NUL termination.
    // - Return: None. In BLIND mode, this name is part of the end-to-end target identity.
    void copyDriverCommunicationName(
        wchar_t* destination,
        const std::size_t destinationChars,
        const std::wstring& source)
    {
        if (destination == nullptr || destinationChars == 0U)
        {
            return;
        }

        const std::size_t kSourceChars = source.size();
        const std::size_t kCopyChars =
            kSourceChars < (destinationChars - 1U)
            ? kSourceChars
            : (destinationChars - 1U);
        for (std::size_t charIndex = 0U; charIndex < kCopyChars; ++charIndex)
        {
            destination[charIndex] = source[charIndex];
        }
        destination[kCopyChars] = L'\0';
    }

}

namespace ksword::ark
{
    DriverCommunicationControlResult DriverClient::controlDriverCommunication(
        const std::uint64_t moduleBase,
        const std::wstring& canonicalDriverName,
        const unsigned long action,
        const std::uint64_t expectedDriverObjectAddress) const
    {
        // Input: Precise base address of the loaded module, canonical DriverObject name, object address, and control action.
        // Handling: BLIND uses a three-element identity to verify the target; the original MajorFunction pointer remains in R0.
        // Return: Fixed response; lastStatus indicates the business result, while io indicates the transport/protocol result.
        DriverCommunicationControlResult result{};
        result.action = action;
        result.targetedMask = KSWORD_ARK_DRIVER_COMMUNICATION_MAJOR_MASK_ALL;
        KSWORD_ARK_DRIVER_COMMUNICATION_REQUEST request{};
        KSWORD_ARK_DRIVER_COMMUNICATION_RESPONSE response{};
        request.version = KSWORD_ARK_DRIVER_COMMUNICATION_PROTOCOL_VERSION;
        request.action = action;
        request.flags =
            KSWORD_ARK_DRIVER_COMMUNICATION_FLAG_TARGET_MODULE_BASE_PRESENT |
            KSWORD_ARK_DRIVER_COMMUNICATION_FLAG_UI_CONFIRMED;
        if (expectedDriverObjectAddress != 0U)
        {
            request.flags |=
                KSWORD_ARK_DRIVER_COMMUNICATION_FLAG_EXPECTED_DRIVER_OBJECT_PRESENT;
        }
        request.targetModuleBase = static_cast<unsigned long long>(moduleBase);
        request.expectedDriverObjectAddress =
            static_cast<unsigned long long>(expectedDriverObjectAddress);
        copyDriverCommunicationName(
            request.driverName,
            KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS,
            canonicalDriverName);

        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_CONTROL_DRIVER_COMMUNICATION,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &response,
            static_cast<unsigned long>(sizeof(response)));
        if (!result.io.ok)
        {
            result.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_CONTROL_DRIVER_COMMUNICATION) failed, error=" +
                std::to_string(result.io.win32Error);
            return result;
        }
        if (result.io.bytesReturned < sizeof(response))
        {
            result.io.ok = false;
            result.io.message =
                "driver-communication response too small, bytesReturned=" +
                std::to_string(result.io.bytesReturned);
            return result;
        }
        if (response.version != KSWORD_ARK_DRIVER_COMMUNICATION_PROTOCOL_VERSION)
        {
            result.io.ok = false;
            result.io.message =
                "driver-communication protocol mismatch, version=" +
                std::to_string(response.version);
            return result;
        }

        // Response copy: all fields are read-only diagnostic information; addresses are not used as credentials for subsequent requests.
        result.version = response.version;
        result.action = response.action;
        result.state = response.state;
        result.responseFlags = response.responseFlags;
        result.lastStatus = response.lastStatus;
        result.targetedMask = response.targetedMask;
        result.changedMask = response.changedMask;
        result.activeMask = response.activeMask;
        result.ownedMask = response.ownedMask;
        result.conflictMask = response.conflictMask;
        result.generation = response.generation;
        result.driverObjectAddress = response.driverObjectAddress;
        result.driverStart = response.driverStart;
        result.rejectDispatchAddress = response.rejectDispatchAddress;
        result.driverName = detail::readFixedString(
            response.driverName,
            KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS);
        result.io.ntStatus = result.lastStatus;
        result.io.message = "driver-communication control completed";
        return result;
    }

    DriverCommunicationControlResult DriverClient::queryDriverCommunication(
        const std::uint64_t moduleBase,
        const std::wstring& displayName) const
    {
        // QUERY does not modify R0 state; it only returns whether the specified module has active/conflict records.
        return controlDriverCommunication(
            moduleBase,
            displayName,
            KSWORD_ARK_DRIVER_COMMUNICATION_ACTION_QUERY,
            0U);
    }

    DriverCommunicationControlResult DriverClient::blindDriverCommunication(
        const std::uint64_t moduleBase,
        const std::wstring& canonicalDriverName,
        const std::uint64_t expectedDriverObjectAddress) const
    {
        // BLIND replaces the five communication slots with a transaction after R0 safety policy reviews UI_CONFIRMED.
        return controlDriverCommunication(
            moduleBase,
            canonicalDriverName,
            KSWORD_ARK_DRIVER_COMMUNICATION_ACTION_BLIND,
            expectedDriverObjectAddress);
    }

    DriverCommunicationControlResult DriverClient::restoreDriverCommunication(
        const std::uint64_t moduleBase,
        const std::wstring& displayName) const
    {
        // RESTORE is an escape path independent of dangerous policy switches; R0 restores only slots still managed by this feature.
        return controlDriverCommunication(
            moduleBase,
            displayName,
            KSWORD_ARK_DRIVER_COMMUNICATION_ACTION_RESTORE,
            0U);
    }
}
