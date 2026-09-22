#include "pch.h"
#include "MonitorPipe.h"
#include "../MonitorAgent.h"
#include "../hook/HookEngine.h"

namespace apimon
{
    std::uint32_t flushPendingMonitorEvents(const std::uint32_t maxPacketsToFlush);

    namespace
    {
        SRWLOCK gPipeLock = SRWLOCK_INIT;              // g_pipeLock: Protects read/write operations and send sequence of g_pipeHandle.
        HANDLE gPipeHandle = INVALID_HANDLE_VALUE;     // g_pipeHandle: Currently connected named pipe handle.
        // g_pipeHandleValue: a lock-free handle snapshot used by hooks to quickly determine if a pipe handle is being monitored, avoiding re-entrant locks in WriteFile hooks that could cause deadlocks.
        std::atomic_uintptr_t gPipeHandleValue{ 0 };
        SRWLOCK gQueueLock = SRWLOCK_INIT;             // g_queueLock: Protects the pending event queue.
        constexpr std::size_t kMaxPendingPacketCount = 4096; // kMaxPendingPacketCount: Fixed ring buffer capacity to avoid dynamic allocation in the Hook hot path.
        constexpr std::uint32_t kMaxFlushBatchCount = 256;   // kMaxFlushBatchCount: Maximum number of events transferred in a single pipe write; controls stack buffer size.
        std::array<ks::winapi_monitor::ApiMonitorEventPacket, kMaxPendingPacketCount> gPendingPacketRing{}; // Fixed-size event ring buffer.
        std::size_t gPendingPacketHead = 0;                 // g_pendingPacketHead: Slot index for the next event to be sent.
        std::size_t gPendingPacketCount = 0;                // g_pendingPacketCount: Number of valid events currently in the ring buffer.
        std::atomic_bool gSenderStopFlag{ false };    // g_senderStopFlag: Stop signal for the background sender thread.
        HANDLE gQueueWakeEvent = nullptr;             // g_queueWakeEvent: Event to wake up for pending sends.
        HANDLE gSenderStopEvent = nullptr;            // g_senderStopEvent: Manual-reset stop event to interrupt pending OVERLAPPED WriteFile operations.
        constexpr DWORD kPipeConnectPollMs = 200;       // kPipeConnectPollMs: Polling interval while waiting for a client connection.
        constexpr DWORD kPipeConnectTimeoutMs = 45000;  // kPipeConnectTimeoutMs: Maximum duration to wait for the UI side to connect.

        // senderThreadSlot:
        // - Inputs: None;
        // - Processing: Return the unique slot held by the background send thread; the slot is intentionally leaked until process termination.
        // - Returns: a reference to std::unique_ptr<std::thread>; stopMonitorPipeServer will still join/reset normally.
        // - Reason: When the target process exits, DLL static destructors may run before worker threads complete; if a static std::thread remains joinable, the MSVC
        //   CRT calls std::terminate, manifesting as 0xC0000409. Leaking the slot lets explicit Stop handle cleanup, while abnormal exits are reclaimed by the OS.
        std::unique_ptr<std::thread>& senderThreadSlot()
        {
            static auto* const kSenderThreadPointer = new std::unique_ptr<std::thread>();
            return *kSenderThreadPointer;
        }

        // copyWideTextRaw:
        // - Input: sourceText is a nullable wide string; targetBuffer/charCount is a fixed-length target buffer.
        // - Processing: Copy up to maxChars and always append NUL without heap allocation.
        // - Return: No return value; caller uses targetBuffer directly.
        void copyWideTextRaw(
            const wchar_t* const sourceText,
            wchar_t* const targetBuffer,
            const std::size_t charCount,
            const std::size_t maxChars)
        {
            if (targetBuffer == nullptr || charCount == 0)
            {
                return;
            }

            const std::size_t kCopyLimit = std::min<std::size_t>(charCount - 1, maxChars);
            std::size_t copyLength = 0;
            if (sourceText != nullptr)
            {
                while (copyLength < kCopyLimit && sourceText[copyLength] != L'\0')
                {
                    targetBuffer[copyLength] = sourceText[copyLength];
                    ++copyLength;
                }
            }
            targetBuffer[copyLength] = L'\0';
        }

        // copyWideText:
        // - Input: sourceText is std::wstring; targetBuffer/charCount are protocol packet fields;
        // - Processing: Reuse the Raw version to perform truncated copying.
        // - Returns: Nothing; writes only to the target buffer.
        void copyWideText(const std::wstring& sourceText, wchar_t* const targetBuffer, const std::size_t charCount)
        {
            copyWideTextRaw(sourceText.c_str(), targetBuffer, charCount, sourceText.size());
        }

        std::uint64_t queryNow100ns()
        {
            FILETIME fileTimeValue{};
            ::GetSystemTimeAsFileTime(&fileTimeValue);

            ULARGE_INTEGER largeValue{};
            largeValue.LowPart = fileTimeValue.dwLowDateTime;
            largeValue.HighPart = fileTimeValue.dwHighDateTime;
            return static_cast<std::uint64_t>(largeValue.QuadPart);
        }

        void closePipeLocked()
        {
            // First, clear the lock-free snapshot to ensure the Hook side does not continue treating this handle as an available monitoring pipe during the shutdown phase.
            gPipeHandleValue.store(0);
            if (gPipeHandle != INVALID_HANDLE_VALUE)
            {
                // Skip FlushFileBuffers during shutdown to avoid deadlocking the target thread if the UI has disconnected or stopped reading.
                (void)::CancelIoEx(gPipeHandle, nullptr);
                (void)::DisconnectNamedPipe(gPipeHandle);
                ::CloseHandle(gPipeHandle);
                gPipeHandle = INVALID_HANDLE_VALUE;
            }
        }

        // writePendingPacketLocked:
        // - Input: packetValue is a fixed-size protocol event packet; the caller holds exclusive ownership of g_pipeLock;
        // - Handling: Use a dedicated OVERLAPPED structure and a stop event to wait for write completion; on stop, the sending thread cancels the current I/O.
        // - Return: true if a packet is fully written; false on disconnect, cancellation, or any I/O error.
        bool writePendingPacketLocked(const ks::winapi_monitor::ApiMonitorEventPacket& packetValue)
        {
            if (gPipeHandle == INVALID_HANDLE_VALUE || gSenderStopFlag.load())
            {
                return false;
            }

            HANDLE writeEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
            if (writeEvent == nullptr)
            {
                return false;
            }

            OVERLAPPED overlappedValue{};
            overlappedValue.hEvent = writeEvent;
            DWORD bytesWritten = 0;
            bool writeComplete = false;
            const BOOL kWriteStarted = ::WriteFile(
                gPipeHandle,
                &packetValue,
                static_cast<DWORD>(sizeof(packetValue)),
                nullptr,
                &overlappedValue);
            if (kWriteStarted != FALSE)
            {
                writeComplete = ::GetOverlappedResult(
                    gPipeHandle,
                    &overlappedValue,
                    &bytesWritten,
                    FALSE) != FALSE;
            }
            else if (::GetLastError() == ERROR_IO_PENDING)
            {
                HANDLE waitHandles[] = { writeEvent, gSenderStopEvent };
                const DWORD kWaitResult = ::WaitForMultipleObjects(
                    static_cast<DWORD>(std::size(waitHandles)),
                    waitHandles,
                    FALSE,
                    INFINITE);
                if (kWaitResult == WAIT_OBJECT_0)
                {
                    writeComplete = ::GetOverlappedResult(
                        gPipeHandle,
                        &overlappedValue,
                        &bytesWritten,
                        FALSE) != FALSE;
                }
                else
                {
                    // On stop signal or wait exception, cancellation must be completed and actual completion waited for first;
                    // otherwise, the stack-local OVERLAPPED/packetValue may still be accessed by the kernel after leaving its scope.
                    (void)::CancelIoEx(gPipeHandle, &overlappedValue);
                    (void)::WaitForSingleObject(writeEvent, INFINITE);
                    (void)::GetOverlappedResult(
                        gPipeHandle,
                        &overlappedValue,
                        &bytesWritten,
                        FALSE);
                }
            }

            ::CloseHandle(writeEvent);
            return writeComplete && bytesWritten == sizeof(packetValue);
        }

        // ensureSenderThreadStarted:
        // - Input: errorTextOut receives diagnostics for failed stop event creation or sender thread start; may be null.
        // - Processing: Prepare queue wake/stop events and create a unique sender thread if none exists in the current session.
        // - Return: true if sender thread is available; false if creating any required synchronization objects fails.
        bool ensureSenderThreadStarted(std::wstring* errorTextOut)
        {
            if (gQueueWakeEvent == nullptr)
            {
                gQueueWakeEvent = ::CreateEventW(nullptr, FALSE, FALSE, nullptr);
                if (gQueueWakeEvent == nullptr)
                {
                    if (errorTextOut != nullptr)
                    {
                        *errorTextOut = L"CreateEventW for monitor queue wake failed. error=" + std::to_wstring(::GetLastError());
                    }
                    return false;
                }
            }
            if (gSenderStopEvent == nullptr)
            {
                gSenderStopEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
                if (gSenderStopEvent == nullptr)
                {
                    if (errorTextOut != nullptr)
                    {
                        *errorTextOut = L"CreateEventW for monitor sender stop failed. error=" + std::to_wstring(::GetLastError());
                    }
                    return false;
                }
            }

            std::unique_ptr<std::thread>& senderThread = senderThreadSlot();
            if (senderThread != nullptr && senderThread->joinable())
            {
                return true;
            }

            gSenderStopFlag.store(false);
            (void)::ResetEvent(gSenderStopEvent);
            senderThread = std::make_unique<std::thread>([]() {
                // senderBypassScope：
                // - Inputs: None;
                // - Processing: Basic APIs like WaitForSingleObject/WriteFile/CloseHandle used by the background pipe sender thread do not enter the monitoring event stream.
                // - Return: No return value; the scope covers the entire thread lifecycle.
                // - Reason: If the Agent's internal sending thread is monitored by its own hooks, it can trigger an event storm (e.g., NtWaitForSingleObject), potentially crashing the target process.
                ScopedInlineHookInternalBypass senderBypassScope;
                while (!gSenderStopFlag.load())
                {
                    (void)flushPendingMonitorEvents(256);
                    if (gSenderStopFlag.load())
                    {
                        break;
                    }

                    const DWORD kWaitResult = (gQueueWakeEvent != nullptr)
                        ? ::WaitForSingleObject(gQueueWakeEvent, 25)
                        : WAIT_TIMEOUT;
                    if (kWaitResult != WAIT_OBJECT_0 && kWaitResult != WAIT_TIMEOUT)
                    {
                        ::Sleep(25);
                    }
                }
            });
            return true;
        }

        bool waitForClientConnection(const HANDLE pipeHandle, const MonitorConfig& configValue, std::wstring* errorTextOut)
        {
            HANDLE connectEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
            if (connectEvent == nullptr)
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = L"CreateEventW for ConnectNamedPipe failed. error=" + std::to_wstring(::GetLastError());
                }
                return false;
            }

            OVERLAPPED overlappedValue{};
            overlappedValue.hEvent = connectEvent;

            const auto kCancelAndDrainPendingConnect = [&]() {
                DWORD ignoredTransferredBytes = 0;
                (void)::CancelIoEx(pipeHandle, &overlappedValue);
                (void)::GetOverlappedResult(pipeHandle, &overlappedValue, &ignoredTransferredBytes, TRUE);
            };

            bool connected = false;
            const BOOL kConnectOk = ::ConnectNamedPipe(pipeHandle, &overlappedValue);
            if (kConnectOk != FALSE)
            {
                connected = true;
            }
            else
            {
                DWORD lastError = ::GetLastError();
                if (lastError == ERROR_PIPE_CONNECTED)
                {
                    connected = true;
                    ::SetEvent(connectEvent);
                }
                else if (lastError == ERROR_IO_PENDING)
                {
                    DWORD waitedMs = 0;
                    while (waitedMs < kPipeConnectTimeoutMs)
                    {
                        if (stopRequested() || isStopFlagPresent(configValue))
                        {
                            kCancelAndDrainPendingConnect();
                            if (errorTextOut != nullptr)
                            {
                                *errorTextOut = L"ConnectNamedPipe canceled because stop was requested before UI connected.";
                            }
                            ::CloseHandle(connectEvent);
                            return false;
                        }

                        const DWORD kWaitResult = ::WaitForSingleObject(connectEvent, kPipeConnectPollMs);
                        if (kWaitResult == WAIT_OBJECT_0)
                        {
                            DWORD transferredBytes = 0;
                            if (::GetOverlappedResult(pipeHandle, &overlappedValue, &transferredBytes, FALSE) != FALSE
                                || ::GetLastError() == ERROR_PIPE_CONNECTED)
                            {
                                connected = true;
                                break;
                            }

                            lastError = ::GetLastError();
                            if (errorTextOut != nullptr)
                            {
                                *errorTextOut = L"ConnectNamedPipe overlapped completion failed. error=" + std::to_wstring(lastError);
                            }
                            ::CloseHandle(connectEvent);
                            return false;
                        }
                        if (kWaitResult != WAIT_TIMEOUT)
                        {
                            kCancelAndDrainPendingConnect();
                            if (errorTextOut != nullptr)
                            {
                                *errorTextOut = L"WaitForSingleObject for ConnectNamedPipe failed. error=" + std::to_wstring(::GetLastError());
                            }
                            ::CloseHandle(connectEvent);
                            return false;
                        }

                        waitedMs += kPipeConnectPollMs;
                    }

                    if (!connected)
                    {
                        kCancelAndDrainPendingConnect();
                        if (errorTextOut != nullptr)
                        {
                            *errorTextOut = L"ConnectNamedPipe timed out waiting for WinAPIDock client.";
                        }
                        ::CloseHandle(connectEvent);
                        return false;
                    }
                }
                else
                {
                    if (errorTextOut != nullptr)
                    {
                        *errorTextOut = L"ConnectNamedPipe start failed. error=" + std::to_wstring(lastError);
                    }
                    ::CloseHandle(connectEvent);
                    return false;
                }
            }

            ::CloseHandle(connectEvent);
            return connected;
        }
    }

    bool startMonitorPipeServer(const MonitorConfig& configValue, std::wstring* errorTextOut)
    {
        if (errorTextOut != nullptr)
        {
            errorTextOut->clear();
        }

        DWORD pipeMode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT;
#ifdef PIPE_REJECT_REMOTE_CLIENTS
        pipeMode |= PIPE_REJECT_REMOTE_CLIENTS;
#endif

        HANDLE pipeHandle = ::CreateNamedPipeW(
            configValue.pipeName.c_str(),
            PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED,
            pipeMode,
            1,
            64 * 1024,
            64 * 1024,
            0,
            nullptr);
        if (pipeHandle == INVALID_HANDLE_VALUE)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = L"CreateNamedPipeW failed. error=" + std::to_wstring(::GetLastError());
            }
            return false;
        }

        if (!waitForClientConnection(pipeHandle, configValue, errorTextOut))
        {
            ::CloseHandle(pipeHandle);
            return false;
        }

        ::AcquireSRWLockExclusive(&gPipeLock);
        closePipeLocked();
        gPipeHandle = pipeHandle;
        gPipeHandleValue.store(reinterpret_cast<std::uintptr_t>(pipeHandle));
        ::ReleaseSRWLockExclusive(&gPipeLock);
        if (!ensureSenderThreadStarted(errorTextOut))
        {
            ::AcquireSRWLockExclusive(&gPipeLock);
            closePipeLocked();
            ::ReleaseSRWLockExclusive(&gPipeLock);
            return false;
        }
        return true;
    }

    void stopMonitorPipeServer()
    {
        gSenderStopFlag.store(true);
        if (gSenderStopEvent != nullptr)
        {
            // When the sending thread is waiting for an asynchronous WriteFile, it will cancel the I/O via CancelIoEx and reclaim the OVERLAPPED structure.
            // Do not close g_pipeHandle first here, or the sender thread might attempt to retrieve completion status on an invalid handle.
            ::SetEvent(gSenderStopEvent);
        }
        if (gQueueWakeEvent != nullptr)
        {
            ::SetEvent(gQueueWakeEvent);
        }
        std::unique_ptr<std::thread>& senderThread = senderThreadSlot();
        if (senderThread != nullptr && senderThread->joinable())
        {
            senderThread->join();
        }
        senderThread.reset();

        ::AcquireSRWLockExclusive(&gPipeLock);
        closePipeLocked();
        ::ReleaseSRWLockExclusive(&gPipeLock);

        ::AcquireSRWLockExclusive(&gQueueLock);
        gPendingPacketHead = 0;
        gPendingPacketCount = 0;
        ::ReleaseSRWLockExclusive(&gQueueLock);
    }

    bool sendMonitorEvent(
        const ks::winapi_monitor::EventCategory categoryValue,
        const wchar_t* moduleName,
        const wchar_t* apiName,
        const std::int32_t resultCode,
        const std::wstring& detailText)
    {
        return sendMonitorEventRaw(
            categoryValue,
            moduleName,
            apiName,
            resultCode,
            detailText.c_str());
    }

    bool sendMonitorEventRaw(
        const ks::winapi_monitor::EventCategory categoryValue,
        const wchar_t* moduleName,
        const wchar_t* apiName,
        const std::int32_t resultCode,
        const wchar_t* detailText)
    {
        ks::winapi_monitor::ApiMonitorEventPacket packetValue{};
        packetValue.pid = static_cast<std::uint32_t>(::GetCurrentProcessId());
        packetValue.tid = static_cast<std::uint32_t>(::GetCurrentThreadId());
        packetValue.timestamp100ns = queryNow100ns();
        packetValue.category = static_cast<std::uint32_t>(categoryValue);
        packetValue.resultCode = resultCode;

        const std::size_t kDetailLimit = std::min<std::size_t>(
            activeConfig().detailLimitChars,
            ks::winapi_monitor::kMaxDetailChars - 1);
        copyWideTextRaw(moduleName, packetValue.moduleName, std::size(packetValue.moduleName), ks::winapi_monitor::kMaxModuleNameChars - 1);
        copyWideTextRaw(apiName, packetValue.apiName, std::size(packetValue.apiName), ks::winapi_monitor::kMaxApiNameChars - 1);
        copyWideTextRaw(detailText, packetValue.detailText, std::size(packetValue.detailText), kDetailLimit);

        ::AcquireSRWLockExclusive(&gQueueLock);
        if (gPendingPacketCount >= kMaxPendingPacketCount)
        {
            ::ReleaseSRWLockExclusive(&gQueueLock);
            return false;
        }

        const std::size_t kTailIndex = (gPendingPacketHead + gPendingPacketCount) % kMaxPendingPacketCount;
        gPendingPacketRing[kTailIndex] = packetValue;
        ++gPendingPacketCount;
        ::ReleaseSRWLockExclusive(&gQueueLock);
        if (gQueueWakeEvent != nullptr)
        {
            ::SetEvent(gQueueWakeEvent);
        }
        return true;
    }

    std::uint32_t flushPendingMonitorEvents(const std::uint32_t maxPacketsToFlush)
    {
        if (maxPacketsToFlush == 0)
        {
            return 0;
        }

        std::array<ks::winapi_monitor::ApiMonitorEventPacket, kMaxFlushBatchCount> packetBatch{};
        std::size_t flushCount = 0;

        ::AcquireSRWLockExclusive(&gQueueLock);
        flushCount = std::min<std::size_t>(
            std::min<std::size_t>(maxPacketsToFlush, kMaxFlushBatchCount),
            gPendingPacketCount);
        for (std::size_t indexValue = 0; indexValue < flushCount; ++indexValue)
        {
            packetBatch[indexValue] = gPendingPacketRing[gPendingPacketHead];
            gPendingPacketHead = (gPendingPacketHead + 1) % kMaxPendingPacketCount;
            --gPendingPacketCount;
        }
        ::ReleaseSRWLockExclusive(&gQueueLock);

        if (flushCount == 0)
        {
            return 0;
        }

        ::AcquireSRWLockExclusive(&gPipeLock);
        if (gPipeHandle == INVALID_HANDLE_VALUE)
        {
            ::ReleaseSRWLockExclusive(&gPipeLock);
            return 0;
        }

        std::uint32_t flushedCount = 0;
        for (std::size_t indexValue = 0; indexValue < flushCount; ++indexValue)
        {
            const auto& packetValue = packetBatch[indexValue];
            if (!writePendingPacketLocked(packetValue))
            {
                closePipeLocked();
                break;
            }
            ++flushedCount;
        }

        ::ReleaseSRWLockExclusive(&gPipeLock);
        return flushedCount;
    }

    bool isMonitorPipeHandle(const HANDLE handleValue)
    {
        if (handleValue == nullptr || handleValue == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        const std::uintptr_t kMonitorPipeHandleValue = gPipeHandleValue.load();
        if (kMonitorPipeHandleValue == 0)
        {
            return false;
        }

        // Use a lock-free snapshot comparison of handle values to prevent a same-thread reentrancy deadlock
        // where WriteFile Hook attempts to acquire g_pipeLock while flushPendingMonitorEvents already holds it.
        return reinterpret_cast<std::uintptr_t>(handleValue) == kMonitorPipeHandleValue;
    }
}
