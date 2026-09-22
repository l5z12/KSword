#include "ArkDriverClient.h"
#include "ArkDriverResponseSupport.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <sstream>
#include <utility>
#include <vector>

namespace ksword::ark
{
    using detail::isUnsupportedIoctlError;
    IoResult DriverClient::terminateProcess(
        const std::uint32_t processId,
        const long exitStatus,
        const std::uint64_t expectedCreateTime100ns) const
    {
        DriverHandle handle = open();
        return terminateProcess(handle, processId, exitStatus, expectedCreateTime100ns);
    }

    IoResult DriverClient::terminateProcess(
        DriverHandle& handle,
        const std::uint32_t processId,
        const long exitStatus,
        const std::uint64_t expectedCreateTime100ns) const
    {
        KSWORD_ARK_TERMINATE_PROCESS_REQUEST request{};
        request.processId = processId;
        request.exitStatus = exitStatus;
        request.expectedCreateTime100ns = expectedCreateTime100ns;
        IoResult result = deviceIoControl(
            IOCTL_KSWORD_ARK_TERMINATE_PROCESS,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            nullptr,
            0,
            &handle);

        std::ostringstream stream;
        stream << "pid=" << processId
            << ", createTime100ns=" << expectedCreateTime100ns
            << ", bytesReturned=" << result.bytesReturned;
        if (result.ok)
        {
            stream << ", ioctl=ok";
        }
        else
        {
            stream << ", ioctl=fail, error=" << result.win32Error;
            if (result.win32Error == ERROR_ACCESS_DENIED)
            {
                stream << " (driver returned failing NTSTATUS, check R0 log for status)";
            }
        }
        result.message = stream.str();
        return result;
    }

    IoResult DriverClient::suspendProcess(const std::uint32_t processId) const
    {
        KSWORD_ARK_SUSPEND_PROCESS_REQUEST request{};
        request.processId = processId;
        IoResult result = deviceIoControl(
            IOCTL_KSWORD_ARK_SUSPEND_PROCESS,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            nullptr,
            0);

        std::ostringstream stream;
        stream << "pid=" << processId << ", bytesReturned=" << result.bytesReturned;
        stream << (result.ok ? ", ioctl=ok" : ", ioctl=fail, error=" + std::to_string(result.win32Error));
        result.message = stream.str();
        return result;
    }

    IoResult DriverClient::resumeProcess(const std::uint32_t processId) const
    {
        KSWORD_ARK_RESUME_PROCESS_REQUEST request{};
        request.processId = processId;
        IoResult result = deviceIoControl(
            IOCTL_KSWORD_ARK_RESUME_PROCESS,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            nullptr,
            0);

        std::ostringstream stream;
        stream << "pid=" << processId << ", bytesReturned=" << result.bytesReturned;
        stream << (result.ok ? ", ioctl=ok" : ", ioctl=fail, error=" + std::to_string(result.win32Error));
        result.message = stream.str();
        return result;
    }

    IoResult DriverClient::setProcessProtection(const std::uint32_t processId, const std::uint8_t protectionLevel) const
    {
        KSWORD_ARK_SET_PPL_LEVEL_REQUEST request{};
        request.processId = processId;
        request.protectionLevel = protectionLevel;
        IoResult result = deviceIoControl(
            IOCTL_KSWORD_ARK_SET_PPL_LEVEL,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            nullptr,
            0);

        std::ostringstream stream;
        stream << "pid=" << processId
            << ", protectionLevel=0x" << std::hex << std::uppercase << static_cast<unsigned int>(protectionLevel)
            << std::dec << ", bytesReturned=" << result.bytesReturned;
        stream << (result.ok ? ", ioctl=ok" : ", ioctl=fail, error=" + std::to_string(result.win32Error));
        result.message = stream.str();
        return result;
    }

    ProcessVisibilityResult DriverClient::setProcessVisibility(
        const std::uint32_t processId,
    const unsigned long action,
    const unsigned long flags) const
    {
        // Purpose: Request R0 to execute a process visibility action (real unlinking or restoration).
        // Return: parsed response; if IOCTL fails, io.ok=false and message contains the Win32 error.
        ProcessVisibilityResult visibilityResult{};
        KSWORD_ARK_SET_PROCESS_VISIBILITY_REQUEST request{};
        KSWORD_ARK_SET_PROCESS_VISIBILITY_RESPONSE response{};
        request.processId = processId;
        request.action = action;
        request.flags = flags;

        visibilityResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_SET_PROCESS_VISIBILITY,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &response,
            static_cast<unsigned long>(sizeof(response)));
        if (!visibilityResult.io.ok)
        {
            visibilityResult.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_SET_PROCESS_VISIBILITY) failed, error=" +
                std::to_string(visibilityResult.io.win32Error);
            return visibilityResult;
        }
        if (visibilityResult.io.bytesReturned < sizeof(response))
        {
            visibilityResult.io.ok = false;
            visibilityResult.io.message =
                "process visibility response too small, bytesReturned=" +
                std::to_string(visibilityResult.io.bytesReturned);
            return visibilityResult;
        }

        visibilityResult.version = static_cast<std::uint32_t>(response.version);
        visibilityResult.processId = static_cast<std::uint32_t>(response.processId);
        visibilityResult.status = static_cast<std::uint32_t>(response.status);
        visibilityResult.hiddenCount = static_cast<std::uint32_t>(response.hiddenCount);
        visibilityResult.lastStatus = static_cast<long>(response.lastStatus);
        visibilityResult.io.ntStatus = visibilityResult.lastStatus;

        std::ostringstream stream;
        stream << "pid=" << visibilityResult.processId
            << ", action=" << action
            << ", flags=0x" << std::hex << std::uppercase << flags << std::dec
            << ", status=" << visibilityResult.status
            << ", hiddenCount=" << visibilityResult.hiddenCount
            << ", lastStatus=0x" << std::hex << static_cast<unsigned long>(visibilityResult.lastStatus);
        visibilityResult.io.message = stream.str();
        return visibilityResult;
    }

    ProcessSpecialFlagsResult DriverClient::setProcessSpecialFlags(
        const std::uint32_t processId,
        const unsigned long action,
        const unsigned long flags,
        const std::uint64_t expectedCreateTime100ns) const
    {
        // Purpose: Request R0 to set BreakOnTermination or disable APC injection into the target process's threads.
        // Return: Parsed fixed response; if IOCTL fails, io.ok=false.
        ProcessSpecialFlagsResult specialResult{};
        KSWORD_ARK_SET_PROCESS_SPECIAL_FLAGS_REQUEST request{};
        KSWORD_ARK_SET_PROCESS_SPECIAL_FLAGS_RESPONSE response{};
        request.version = KSWORD_ARK_ENUM_PROCESS_PROTOCOL_VERSION;
        request.processId = processId;
        request.action = action;
        request.flags = flags;
        request.expectedCreateTime100ns = expectedCreateTime100ns;

        specialResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_SET_PROCESS_SPECIAL_FLAGS,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &response,
            static_cast<unsigned long>(sizeof(response)));
        if (!specialResult.io.ok)
        {
            specialResult.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_SET_PROCESS_SPECIAL_FLAGS) failed, error=" +
                std::to_string(specialResult.io.win32Error);
            return specialResult;
        }
        if (specialResult.io.bytesReturned < sizeof(response))
        {
            specialResult.io.ok = false;
            specialResult.io.message =
                "process-special response too small, bytesReturned=" +
                std::to_string(specialResult.io.bytesReturned);
            return specialResult;
        }

        specialResult.version = static_cast<std::uint32_t>(response.version);
        specialResult.processId = static_cast<std::uint32_t>(response.processId);
        specialResult.action = static_cast<std::uint32_t>(response.action);
        specialResult.status = static_cast<std::uint32_t>(response.status);
        specialResult.appliedFlags = static_cast<std::uint32_t>(response.appliedFlags);
        specialResult.touchedThreadCount = static_cast<std::uint32_t>(response.touchedThreadCount);
        specialResult.lastStatus = static_cast<long>(response.lastStatus);
        specialResult.io.ntStatus = specialResult.lastStatus;

        std::ostringstream stream;
        stream << "pid=" << specialResult.processId
            << ", action=" << specialResult.action
            << ", createTime100ns=" << expectedCreateTime100ns
            << ", status=" << specialResult.status
            << ", applied=0x" << std::hex << specialResult.appliedFlags
            << ", touchedThreads=" << std::dec << specialResult.touchedThreadCount
            << ", lastStatus=0x" << std::hex << static_cast<unsigned long>(specialResult.lastStatus);
        specialResult.io.message = stream.str();
        return specialResult;
    }

    ProcessDkomResult DriverClient::dkomProcess(
        const std::uint32_t processId,
        const unsigned long action,
        const unsigned long flags) const
    {
        // Purpose: Requests R0 to perform a process DKOM operation, currently used to remove the PID from PspCidTable.
        // Returns: Parsed fixed response; the diagnostic address is for display only and is not used as subsequent credentials.
        ProcessDkomResult dkomResult{};
        KSWORD_ARK_DKOM_PROCESS_REQUEST request{};
        KSWORD_ARK_DKOM_PROCESS_RESPONSE response{};
        request.version = KSWORD_ARK_ENUM_PROCESS_PROTOCOL_VERSION;
        request.processId = processId;
        request.action = action;
        request.flags = flags;

        dkomResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_DKOM_PROCESS,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &response,
            static_cast<unsigned long>(sizeof(response)));
        if (!dkomResult.io.ok)
        {
            dkomResult.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_DKOM_PROCESS) failed, error=" +
                std::to_string(dkomResult.io.win32Error);
            return dkomResult;
        }
        if (dkomResult.io.bytesReturned < sizeof(response))
        {
            dkomResult.io.ok = false;
            dkomResult.io.message =
                "process-dkom response too small, bytesReturned=" +
                std::to_string(dkomResult.io.bytesReturned);
            return dkomResult;
        }

        dkomResult.version = static_cast<std::uint32_t>(response.version);
        dkomResult.processId = static_cast<std::uint32_t>(response.processId);
        dkomResult.action = static_cast<std::uint32_t>(response.action);
        dkomResult.status = static_cast<std::uint32_t>(response.status);
        dkomResult.removedEntries = static_cast<std::uint32_t>(response.removedEntries);
        dkomResult.lastStatus = static_cast<long>(response.lastStatus);
        dkomResult.pspCidTableAddress = static_cast<std::uint64_t>(response.pspCidTableAddress);
        dkomResult.processObjectAddress = static_cast<std::uint64_t>(response.processObjectAddress);
        dkomResult.io.ntStatus = dkomResult.lastStatus;

        std::ostringstream stream;
        stream << "pid=" << dkomResult.processId
            << ", action=" << dkomResult.action
            << ", status=" << dkomResult.status
            << ", removed=" << dkomResult.removedEntries
            << ", pspCidTable=0x" << std::hex << dkomResult.pspCidTableAddress
            << ", eprocess=0x" << dkomResult.processObjectAddress
            << ", lastStatus=0x" << static_cast<unsigned long>(dkomResult.lastStatus);
        dkomResult.io.message = stream.str();
        return dkomResult;
    }
}
