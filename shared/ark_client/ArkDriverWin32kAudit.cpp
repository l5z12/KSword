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
    namespace
    {
        // buildWin32kRequest:
        // - Input: flags/session/pid/tid/maxEntries;
        // - Processing: normalize Win32K shared query requests.
        // - Return: KSWORD_ARK_WIN32K_QUERY_REQUEST.
        KSWORD_ARK_WIN32K_QUERY_REQUEST buildWin32kRequest(
            const unsigned long flags,
            const unsigned long sessionId,
            const unsigned long processId,
            const unsigned long threadId,
            const unsigned long maxEntries)
        {
            KSWORD_ARK_WIN32K_QUERY_REQUEST request{};
            unsigned long effectiveSessionId = sessionId;
            if (effectiveSessionId == 0UL &&
                (flags & KSWORD_ARK_WIN32K_QUERY_FLAG_CURRENT_SESSION_ONLY) != 0UL)
            {
                DWORD currentSessionId = 0U;
                if (::ProcessIdToSessionId(::GetCurrentProcessId(), &currentSessionId) != FALSE)
                {
                    effectiveSessionId = currentSessionId;
                }
            }
            request.version = KSWORD_ARK_WIN32K_PROTOCOL_VERSION;
            request.flags = flags;
            request.sessionId = effectiveSessionId;
            request.processId = processId;
            request.threadId = threadId;
            request.maxEntries = maxEntries;
            return request;
        }

    // queryWin32kRows:
    // - Input: Win32K variable-length response/row type, IOCTL, and filter parameters;
    // - Processing: Send the request and parse capability, offset, and entries.
    // - Returns: The specific Win32K result type.
    template <typename TResult, typename TResponse, typename TEntry>
    TResult queryWin32kRows(
        const DriverClient& client,
        const unsigned long ioctlCode,
        const KSWORD_ARK_WIN32K_QUERY_REQUEST& request,
        const char* const operationName)
    {
        TResult result{};
        std::vector<std::uint8_t> responseBuffer(kDefaultAuditBufferBytes, 0U);
        result.io = client.deviceIoControl(ioctlCode, const_cast<KSWORD_ARK_WIN32K_QUERY_REQUEST*>(&request), sizeof(request), responseBuffer.data(), static_cast<unsigned long>(responseBuffer.size()));
        if (!result.io.ok)
        {
            markUnsupportedIfNeeded(result, operationName);
            return result;
        }

        constexpr std::size_t kHeaderSize = sizeof(TResponse) - sizeof(TEntry);
        const auto* response = reinterpret_cast<const TResponse*>(responseBuffer.data());
        const std::size_t kParsedCount = validateAuditRows(result.io, kHeaderSize, response->entrySize, sizeof(TEntry), response->returnedCount, operationName);
        if (!result.io.ok)
        {
            return result;
        }

        result.version = response->version;
        result.status = response->status;
        result.totalCount = response->totalCount;
        result.returnedCount = response->returnedCount;
        result.entrySize = response->entrySize;
        result.flags = response->flags;
        result.lastStatus = response->lastStatus;
        result.capabilityMask = response->capabilityMask;
        result.missingCapabilityMask = response->missingCapabilityMask;
        result.fieldOffsets = response->fieldOffsets;
        result.io.ntStatus = response->lastStatus;
        result.entries = parseVariableRows<TEntry>(responseBuffer, kHeaderSize, response->entrySize, kParsedCount);
        result.io.message = appendAuditSummary(operationName, result.totalCount, result.returnedCount, result.entries.size(), result.io.bytesReturned);
        return result;
    }
    }

    Win32kProfileStatusResult DriverClient::queryWin32kProfileStatus(const unsigned long flags, const unsigned long sessionId, const unsigned long maxEntries) const
    {
        constexpr const char* kOperationName = "IOCTL_KSWORD_ARK_QUERY_WIN32K_PROFILE_STATUS";
        Win32kProfileStatusResult result{};
        KSWORD_ARK_WIN32K_QUERY_REQUEST request = buildWin32kRequest(flags, sessionId, 0UL, 0UL, maxEntries);
        std::vector<std::uint8_t> responseBuffer(kDefaultAuditBufferBytes, 0U);
        result.io = deviceIoControl(IOCTL_KSWORD_ARK_QUERY_WIN32K_PROFILE_STATUS, &request, sizeof(request), responseBuffer.data(), static_cast<unsigned long>(responseBuffer.size()));
        if (!result.io.ok)
        {
            markUnsupportedIfNeeded(result, kOperationName);
            return result;
        }

        constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_WIN32K_PROFILE_STATUS_RESPONSE) - sizeof(KSWORD_ARK_WIN32K_SESSION_ENTRY);
        const auto* response = reinterpret_cast<const KSWORD_ARK_WIN32K_PROFILE_STATUS_RESPONSE*>(responseBuffer.data());
        const std::size_t kParsedCount = validateAuditRows(result.io, kHeaderSize, response->entrySize, sizeof(KSWORD_ARK_WIN32K_SESSION_ENTRY), response->returnedCount, kOperationName);
        if (!result.io.ok)
        {
            return result;
        }

        result.version = response->version;
        result.status = response->status;
        result.totalCount = response->totalCount;
        result.returnedCount = response->returnedCount;
        result.entrySize = response->entrySize;
        result.flags = response->flags;
        result.lastStatus = response->lastStatus;
        result.capabilityMask = response->capabilityMask;
        result.missingCapabilityMask = response->missingCapabilityMask;
        result.userGetSiloGlobals = response->userGetSiloGlobals;
        result.win32k = response->win32k;
        result.win32kbase = response->win32kbase;
        result.win32kfull = response->win32kfull;
        result.fieldOffsets = response->fieldOffsets;
        result.io.ntStatus = response->lastStatus;
        result.entries = parseVariableRows<KSWORD_ARK_WIN32K_SESSION_ENTRY>(responseBuffer, kHeaderSize, response->entrySize, kParsedCount);
        result.io.message = appendAuditSummary(kOperationName, result.totalCount, result.returnedCount, result.entries.size(), result.io.bytesReturned);
        return result;
    }

    Win32kWindowsResult DriverClient::queryWin32kWindows(const unsigned long flags, const unsigned long sessionId, const unsigned long processId, const unsigned long threadId, const unsigned long maxEntries) const
    {
        const KSWORD_ARK_WIN32K_QUERY_REQUEST kRequest = buildWin32kRequest(flags, sessionId, processId, threadId, maxEntries);
        return queryWin32kRows<Win32kWindowsResult, KSWORD_ARK_WIN32K_WINDOW_SNAPSHOT_RESPONSE, KSWORD_ARK_WIN32K_WINDOW_ENTRY>(*this, IOCTL_KSWORD_ARK_QUERY_WIN32K_WINDOWS, kRequest, "IOCTL_KSWORD_ARK_QUERY_WIN32K_WINDOWS");
    }

    Win32kGuiThreadsResult DriverClient::queryWin32kGuiThreads(const unsigned long flags, const unsigned long sessionId, const unsigned long processId, const unsigned long threadId, const unsigned long maxEntries) const
    {
        const KSWORD_ARK_WIN32K_QUERY_REQUEST kRequest = buildWin32kRequest(flags, sessionId, processId, threadId, maxEntries);
        return queryWin32kRows<Win32kGuiThreadsResult, KSWORD_ARK_WIN32K_GUI_THREAD_SNAPSHOT_RESPONSE, KSWORD_ARK_WIN32K_GUI_THREAD_ENTRY>(*this, IOCTL_KSWORD_ARK_QUERY_WIN32K_GUI_THREADS, kRequest, "IOCTL_KSWORD_ARK_QUERY_WIN32K_GUI_THREADS");
    }

    Win32kHotkeysPdbResult DriverClient::queryWin32kHotkeysPdb(const unsigned long flags, const unsigned long sessionId, const unsigned long processId, const unsigned long threadId, const unsigned long maxEntries) const
    {
        const KSWORD_ARK_WIN32K_QUERY_REQUEST kRequest = buildWin32kRequest(flags, sessionId, processId, threadId, maxEntries);
        return queryWin32kRows<Win32kHotkeysPdbResult, KSWORD_ARK_WIN32K_HOTKEY_SNAPSHOT_RESPONSE, KSWORD_ARK_WIN32K_HOTKEY_ENTRY>(*this, IOCTL_KSWORD_ARK_QUERY_WIN32K_HOTKEYS_PDB, kRequest, "IOCTL_KSWORD_ARK_QUERY_WIN32K_HOTKEYS_PDB");
    }

    Win32kHooksPdbResult DriverClient::queryWin32kHooksPdb(const unsigned long flags, const unsigned long sessionId, const unsigned long processId, const unsigned long threadId, const unsigned long maxEntries) const
    {
        constexpr const char* kOperationName = "IOCTL_KSWORD_ARK_QUERY_WIN32K_HOOKS_PDB";
        Win32kHooksPdbResult result{};
        const KSWORD_ARK_WIN32K_QUERY_REQUEST kRequest = buildWin32kRequest(flags, sessionId, processId, threadId, maxEntries);
        std::vector<std::uint8_t> responseBuffer(kDefaultAuditBufferBytes, 0U);
        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_WIN32K_HOOKS_PDB,
            const_cast<KSWORD_ARK_WIN32K_QUERY_REQUEST*>(&kRequest),
            sizeof(kRequest),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        if (!result.io.ok)
        {
            markUnsupportedIfNeeded(result, kOperationName);
            return result;
        }

        constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_WIN32K_HOOK_SNAPSHOT_RESPONSE) - sizeof(KSWORD_ARK_WIN32K_HOOK_ENTRY);
        const auto* response = reinterpret_cast<const KSWORD_ARK_WIN32K_HOOK_SNAPSHOT_RESPONSE*>(responseBuffer.data());
        const std::size_t kParsedCount = validateAuditRows(
            result.io,
            kHeaderSize,
            response->entrySize,
            sizeof(KSWORD_ARK_WIN32K_HOOK_ENTRY),
            response->returnedCount,
            kOperationName);
        if (!result.io.ok)
        {
            return result;
        }

        result.version = response->version;
        result.status = response->status;
        result.totalCount = response->totalCount;
        result.returnedCount = response->returnedCount;
        result.entrySize = response->entrySize;
        result.flags = response->flags;
        result.lastStatus = response->lastStatus;
        result.capabilityMask = response->capabilityMask;
        result.missingCapabilityMask = response->missingCapabilityMask;
        result.fieldOffsets = response->fieldOffsets;
        result.layout = response->layout;
        result.discoveredChainCount = response->discoveredChainCount;
        result.visitedNodeCount = response->visitedNodeCount;
        result.readFailureCount = response->readFailureCount;
        result.corruptLinkCount = response->corruptLinkCount;
        result.duplicateCount = response->duplicateCount;
        result.win32kbaseTimeDateStamp = response->win32kbaseTimeDateStamp;
        result.win32kbaseImageSize = response->win32kbaseImageSize;
        result.win32kfullTimeDateStamp = response->win32kfullTimeDateStamp;
        result.win32kfullImageSize = response->win32kfullImageSize;
        result.detail = detail::readFixedString(response->detail, KSWORD_ARK_WIN32K_DETAIL_CHARS);
        result.io.ntStatus = response->lastStatus;
        result.unsupported = response->status == KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED ||
            static_cast<unsigned long>(response->lastStatus) == 0xC0000059UL;
        result.entries = parseVariableRows<KSWORD_ARK_WIN32K_HOOK_ENTRY>(
            responseBuffer,
            kHeaderSize,
            response->entrySize,
            kParsedCount);
        result.io.message = appendAuditSummary(
            kOperationName,
            result.totalCount,
            result.returnedCount,
            result.entries.size(),
            result.io.bytesReturned);
        return result;
    }

    Win32kTimersResult DriverClient::queryWin32kTimers(const unsigned long flags, const unsigned long sessionId, const unsigned long processId, const unsigned long threadId, const unsigned long maxEntries) const
    {
        constexpr const char* kOperationName = "IOCTL_KSWORD_ARK_QUERY_WIN32K_TIMERS";
        Win32kTimersResult result{};
        const KSWORD_ARK_WIN32K_QUERY_REQUEST kRequest = buildWin32kRequest(flags, sessionId, processId, threadId, maxEntries);
        std::vector<std::uint8_t> responseBuffer(kDefaultAuditBufferBytes, 0U);
        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_WIN32K_TIMERS,
            const_cast<KSWORD_ARK_WIN32K_QUERY_REQUEST*>(&kRequest),
            sizeof(kRequest),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        if (!result.io.ok)
        {
            markUnsupportedIfNeeded(result, kOperationName);
            return result;
        }

        constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_WIN32K_TIMER_SNAPSHOT_RESPONSE) - sizeof(KSWORD_ARK_WIN32K_TIMER_ENTRY);
        const auto* response = reinterpret_cast<const KSWORD_ARK_WIN32K_TIMER_SNAPSHOT_RESPONSE*>(responseBuffer.data());
        const std::size_t kParsedCount = validateAuditRows(
            result.io,
            kHeaderSize,
            response->entrySize,
            sizeof(KSWORD_ARK_WIN32K_TIMER_ENTRY),
            response->returnedCount,
            kOperationName);
        if (!result.io.ok)
        {
            return result;
        }

        result.version = response->version;
        result.status = response->status;
        result.totalCount = response->totalCount;
        result.returnedCount = response->returnedCount;
        result.entrySize = response->entrySize;
        result.flags = response->flags;
        result.lastStatus = response->lastStatus;
        result.capabilityMask = response->capabilityMask;
        result.missingCapabilityMask = response->missingCapabilityMask;
        result.timerHashTable = response->timerHashTable;
        result.visitedNodeCount = response->visitedNodeCount;
        result.readFailureCount = response->readFailureCount;
        result.corruptBucketCount = response->corruptBucketCount;
        result.duplicateCount = response->duplicateCount;
        result.win32kbaseTimeDateStamp = response->win32kbaseTimeDateStamp;
        result.win32kbaseImageSize = response->win32kbaseImageSize;
        result.win32kfullTimeDateStamp = response->win32kfullTimeDateStamp;
        result.win32kfullImageSize = response->win32kfullImageSize;
        result.layout = response->layout;
        result.detail = std::wstring(response->detail);
        result.io.ntStatus = response->lastStatus;
        result.unsupported = response->status == KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED ||
            static_cast<unsigned long>(response->lastStatus) == 0xC0000059UL;
        result.entries = parseVariableRows<KSWORD_ARK_WIN32K_TIMER_ENTRY>(
            responseBuffer,
            kHeaderSize,
            response->entrySize,
            kParsedCount);
        result.io.message = appendAuditSummary(
            kOperationName,
            result.totalCount,
            result.returnedCount,
            result.entries.size(),
            result.io.bytesReturned);
        return result;
    }

    Win32kEventHooksResult DriverClient::queryWin32kEventHooks(const unsigned long flags, const unsigned long sessionId, const unsigned long processId, const unsigned long threadId, const unsigned long maxEntries) const
    {
        constexpr const char* kOperationName = "IOCTL_KSWORD_ARK_QUERY_WIN32K_EVENT_HOOKS";
        Win32kEventHooksResult result{};
        const KSWORD_ARK_WIN32K_QUERY_REQUEST kRequest = buildWin32kRequest(flags, sessionId, processId, threadId, maxEntries);
        std::vector<std::uint8_t> responseBuffer(kDefaultAuditBufferBytes, 0U);
        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_WIN32K_EVENT_HOOKS,
            const_cast<KSWORD_ARK_WIN32K_QUERY_REQUEST*>(&kRequest),
            sizeof(kRequest),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        if (!result.io.ok)
        {
            markUnsupportedIfNeeded(result, kOperationName);
            return result;
        }

        constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_WIN32K_EVENT_HOOK_SNAPSHOT_RESPONSE) - sizeof(KSWORD_ARK_WIN32K_EVENT_HOOK_ENTRY);
        const auto* response = reinterpret_cast<const KSWORD_ARK_WIN32K_EVENT_HOOK_SNAPSHOT_RESPONSE*>(responseBuffer.data());
        const std::size_t kParsedCount = validateAuditRows(
            result.io,
            kHeaderSize,
            response->entrySize,
            sizeof(KSWORD_ARK_WIN32K_EVENT_HOOK_ENTRY),
            response->returnedCount,
            kOperationName);
        if (!result.io.ok)
        {
            return result;
        }

        result.version = response->version;
        result.status = response->status;
        result.totalCount = response->totalCount;
        result.returnedCount = response->returnedCount;
        result.entrySize = response->entrySize;
        result.flags = response->flags;
        result.lastStatus = response->lastStatus;
        result.capabilityMask = response->capabilityMask;
        result.missingCapabilityMask = response->missingCapabilityMask;
        result.hookListPointer = response->hookListPointer;
        result.hookListHead = response->hookListHead;
        result.visitedNodeCount = response->visitedNodeCount;
        result.readFailureCount = response->readFailureCount;
        result.corruptLinkCount = response->corruptLinkCount;
        result.duplicateCount = response->duplicateCount;
        result.win32kbaseTimeDateStamp = response->win32kbaseTimeDateStamp;
        result.win32kbaseImageSize = response->win32kbaseImageSize;
        result.win32kfullTimeDateStamp = response->win32kfullTimeDateStamp;
        result.win32kfullImageSize = response->win32kfullImageSize;
        result.layout = response->layout;
        result.detail = std::wstring(response->detail);
        result.io.ntStatus = response->lastStatus;
        result.unsupported = response->status == KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED ||
            static_cast<unsigned long>(response->lastStatus) == 0xC0000059UL;
        result.entries = parseVariableRows<KSWORD_ARK_WIN32K_EVENT_HOOK_ENTRY>(
            responseBuffer,
            kHeaderSize,
            response->entrySize,
            kParsedCount);
        result.io.message = appendAuditSummary(
            kOperationName,
            result.totalCount,
            result.returnedCount,
            result.entries.size(),
            result.io.bytesReturned);
        return result;
    }

    Win32kWindowRuntimeDetailResult DriverClient::queryWin32kWindowDetail(
        const std::uint64_t hwnd,
        const unsigned long processId,
        const unsigned long threadId,
        const unsigned long flags) const
    {
        // Input: HWND and optional PID/TID constraints; flags control whether to return diagnostic text.
        // Processing: Invokes the win32k single-window detail IOCTL; R0 currently only handles profile/capability readiness.
        // Returns: fixed response; unsupported indicates the old driver lacks the entry or R0 explicitly does not implement tagWND reading.
        constexpr const char* kOperationName = "IOCTL_KSWORD_ARK_QUERY_WIN32K_WINDOW_DETAIL";
        Win32kWindowRuntimeDetailResult result{};
        KSWORD_ARK_WIN32K_WINDOW_DETAIL_REQUEST request{};
        request.version = KSWORD_ARK_WIN32K_PROTOCOL_VERSION;
        request.flags = flags;
        request.processId = processId;
        request.threadId = threadId;
        request.hwnd = hwnd;

        result.io = queryFixedAudit(
            *this,
            IOCTL_KSWORD_ARK_QUERY_WIN32K_WINDOW_DETAIL,
            &request,
            result.response,
            kOperationName);
        markUnsupportedIfNeeded(result, kOperationName);
        result.io.ntStatus = result.response.lastStatus;
        if (result.io.ok)
        {
            result.unsupported = result.response.status == KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED ||
                static_cast<unsigned long>(result.response.lastStatus) == 0xC00000BBUL ||
                static_cast<unsigned long>(result.response.lastStatus) == 0xC0000010UL;
            std::ostringstream stream;
            stream << kOperationName
                << " status=" << result.response.status
                << ", fields=0x" << std::hex << std::uppercase << result.response.fieldFlags
                << ", missingCaps=0x" << result.response.missingCapabilityMask
                << ", lastStatus=0x" << static_cast<unsigned long>(result.response.lastStatus)
                << std::dec << ", bytesReturned=" << result.io.bytesReturned;
            result.io.message = stream.str();
        }
        return result;
    }
}
