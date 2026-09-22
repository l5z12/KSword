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
    IoResult DriverClient::terminateThread(
        const std::uint32_t threadId,
        const std::uint32_t processId,
        const long exitStatus) const
    {
        DriverHandle handle = open();
        return terminateThread(handle, threadId, processId, exitStatus);
    }

    IoResult DriverClient::terminateThread(
        DriverHandle& handle,
        const std::uint32_t threadId,
        const std::uint32_t processId,
        const long exitStatus) const
    {
        KSWORD_ARK_TERMINATE_THREAD_REQUEST request{};
        request.threadId = threadId;
        request.processId = processId;
        request.exitStatus = exitStatus;
        IoResult result = deviceIoControl(
            IOCTL_KSWORD_ARK_TERMINATE_THREAD,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            nullptr,
            0,
            &handle);

        std::ostringstream stream;
        stream << "tid=" << threadId << ", pid=" << processId << ", bytesReturned=" << result.bytesReturned;
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

    IoResult DriverClient::setThreadSuspended(
        const std::uint32_t threadId,
        const std::uint32_t processId,
        const bool suspended) const
    {
        DriverHandle handle = open();
        return setThreadSuspended(handle, threadId, processId, suspended);
    }

    IoResult DriverClient::setThreadSuspended(
        DriverHandle& handle,
        const std::uint32_t threadId,
        const std::uint32_t processId,
        const bool suspended) const
    {
        KSWORD_ARK_SET_THREAD_SUSPENDED_REQUEST request{};
        request.threadId = threadId;
        request.processId = processId;
        request.action = suspended
            ? KSWORD_ARK_THREAD_SUSPEND_ACTION_SUSPEND
            : KSWORD_ARK_THREAD_SUSPEND_ACTION_RESUME;
        IoResult result = deviceIoControl(
            IOCTL_KSWORD_ARK_SET_THREAD_SUSPENDED,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            nullptr,
            0,
            &handle);

        std::ostringstream stream;
        stream << "tid=" << threadId
            << ", pid=" << processId
            << ", action=" << (suspended ? "suspend" : "resume")
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

    IoResult DriverClient::controlDriverThread(
        const std::uint32_t threadId,
        const std::uint64_t expectedStartAddress,
        const std::uint64_t expectedCreateTime100ns,
        const unsigned long action,
        const unsigned long terminateMethod,
        const bool uiConfirmed) const
    {
        DriverHandle handle = open();
        return controlDriverThread(
            handle,
            threadId,
            expectedStartAddress,
            expectedCreateTime100ns,
            action,
            terminateMethod,
            uiConfirmed);
    }

    IoResult DriverClient::controlDriverThread(
        DriverHandle& handle,
        const std::uint32_t threadId,
        const std::uint64_t expectedStartAddress,
        const std::uint64_t expectedCreateTime100ns,
        const unsigned long action,
        const unsigned long terminateMethod,
        const bool uiConfirmed) const
    {
        KSWORD_ARK_CONTROL_DRIVER_THREAD_REQUEST request{};
        request.size = static_cast<unsigned long>(sizeof(request));
        request.version = KSWORD_ARK_DRIVER_THREAD_CONTROL_PROTOCOL_VERSION;
        request.threadId = threadId;
        request.action = action;
        request.flags = uiConfirmed
            ? KSWORD_ARK_DRIVER_THREAD_CONTROL_FLAG_UI_CONFIRMED
            : 0UL;
        request.terminateMethod = terminateMethod;
        request.expectedStartAddress = expectedStartAddress;
        request.expectedCreateTime100ns = expectedCreateTime100ns;
        IoResult result = deviceIoControl(
            IOCTL_KSWORD_ARK_CONTROL_DRIVER_THREAD,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            nullptr,
            0,
            &handle);

        const char* actionText = action == KSWORD_ARK_DRIVER_THREAD_ACTION_SUSPEND
            ? "suspend"
            : (action == KSWORD_ARK_DRIVER_THREAD_ACTION_RESUME ? "resume" : "terminate");
        const char* rawApiText = "none";
        switch (terminateMethod)
        {
        case KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_PSP_BY_POINTER:
            rawApiText = "PspTerminateThreadByPointer";
            break;
        case KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_ZW_OR_NT:
            rawApiText = "ZwTerminateThread/NtTerminateThread";
            break;
        case KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_NORMAL_APC:
            rawApiText = "KeInsertQueueApc(Normal Kernel APC)->PsTerminateSystemThread";
            break;
        case KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_SPECIAL_TO_NORMAL_APC:
            rawApiText = "KeInsertQueueApc(Special Kernel APC)->KeInsertQueueApc(Normal Kernel APC)->PsTerminateSystemThread";
            break;
        default:
            break;
        }
        std::ostringstream stream;
        stream << "tid=" << threadId
            << ", pid=4"
            << ", start=0x" << std::hex << expectedStartAddress << std::dec
            << ", createTime100ns=" << expectedCreateTime100ns
            << ", action=" << actionText
            << ", terminateMethod=" << terminateMethod
            << ", rawApi=" << rawApiText
            << ", bytesReturned=" << result.bytesReturned;
        if (result.ok)
        {
            stream << ", ioctl=ok";
            if (terminateMethod == KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_NORMAL_APC ||
                terminateMethod == KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_SPECIAL_TO_NORMAL_APC)
            {
                stream << ", apc=queued (delivery/termination is asynchronous and not guaranteed)";
            }
        }
        else
        {
            stream << ", ioctl=fail, error=" << result.win32Error;
            if (result.win32Error == ERROR_ACCESS_DENIED)
            {
                stream << " (driver safety/module validation denied the request; check R0 log)";
            }
        }
        result.message = stream.str();
        return result;
    }
}
