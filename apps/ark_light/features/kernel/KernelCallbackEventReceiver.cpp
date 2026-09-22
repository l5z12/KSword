#include "KernelCallbackEventReceiver.h"

#include "../../../../shared/ark_client/ArkDriverClient.h"

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>

namespace ksword::features::kernel {
namespace {

constexpr DWORD kReceiverPollMilliseconds = 100;
constexpr DWORD kReceiverRetryMilliseconds = 250;

bool isReceiverRunning(const std::shared_ptr<CallbackEventReceiver::State>& state, const std::uint64_t generation);
void runReceiver(const std::shared_ptr<CallbackEventReceiver::State>& state, std::uint64_t generation);

} // namespace

struct CallbackEventReceiver::State final {
    State(const HWND initialOwner, const UINT completionMessage)
        : owner(initialOwner), eventMessage(completionMessage) {
    }

    mutable std::mutex mutex;
    HWND owner = nullptr;
    UINT eventMessage = 0;
    std::atomic_uint64_t generation = 0;
    std::atomic_bool active = false;
    std::atomic_bool workerRunning = false;
    ksword::ark::DriverHandle handle;
};

namespace {

bool isReceiverRunning(const std::shared_ptr<CallbackEventReceiver::State>& state, const std::uint64_t generation) {
    return state && state->active.load(std::memory_order_acquire) && state->generation.load(std::memory_order_acquire) == generation;
}

void resetHandle(const std::shared_ptr<CallbackEventReceiver::State>& state) {
    std::scoped_lock lock(state->mutex);
    state->handle.reset();
}

void postEvent(
    const std::shared_ptr<CallbackEventReceiver::State>& state,
    const std::uint64_t generation,
    const KSWORD_ARK_CALLBACK_EVENT_PACKET& event) {
    HWND owner = nullptr;
    UINT message = 0;
    {
        std::scoped_lock lock(state->mutex);
        if (!isReceiverRunning(state, generation) || state->owner == nullptr) {
            return;
        }
        owner = state->owner;
        message = state->eventMessage;
    }

    auto snapshot = std::make_unique<CallbackEventSnapshot>();
    snapshot->generation = generation;
    snapshot->event = event;
    if (::PostMessageW(owner, message, 0, reinterpret_cast<LPARAM>(snapshot.get()))) {
        snapshot.release();
    }
}

void runReceiver(const std::shared_ptr<CallbackEventReceiver::State>& state, const std::uint64_t generation) {
    const ksword::ark::DriverClient kClient;
    while (isReceiverRunning(state, generation)) {
        HANDLE nativeHandle = INVALID_HANDLE_VALUE;
        {
            std::scoped_lock lock(state->mutex);
            nativeHandle = state->handle.native();
        }
        if (nativeHandle == nullptr || nativeHandle == INVALID_HANDLE_VALUE) {
            ksword::ark::DriverHandle opened = kClient.openOverlapped();
            if (!opened.isValid()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(kReceiverRetryMilliseconds));
                continue;
            }
            {
                std::scoped_lock lock(state->mutex);
                if (!isReceiverRunning(state, generation)) {
                    break;
                }
                state->handle = std::move(opened);
                nativeHandle = state->handle.native();
            }
        }

        KSWORD_ARK_CALLBACK_WAIT_REQUEST request{};
        request.size = sizeof(request);
        request.version = KSWORD_ARK_CALLBACK_PROTOCOL_VERSION;
        request.waiterTag = static_cast<unsigned long>(generation & 0xFFFFFFFFULL);
        KSWORD_ARK_CALLBACK_EVENT_PACKET event{};
        OVERLAPPED overlapped{};
        overlapped.hEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (overlapped.hEvent == nullptr) {
            std::this_thread::sleep_for(std::chrono::milliseconds(kReceiverRetryMilliseconds));
            continue;
        }

        DWORD bytesReturned = 0;
        const ksword::ark::AsyncIoResult kIssued = kClient.waitCallbackEventAsync(state->handle, request, event, &overlapped);
        bytesReturned = kIssued.bytesReturned;
        if (!kIssued.issued) {
            if (kIssued.win32Error == ERROR_IO_PENDING) {
                while (isReceiverRunning(state, generation)) {
                    const DWORD kWait = ::WaitForSingleObject(overlapped.hEvent, kReceiverPollMilliseconds);
                    if (kWait == WAIT_OBJECT_0 || kWait == WAIT_FAILED) {
                        break;
                    }
                }
                BOOL completionOk = FALSE;
                if (!isReceiverRunning(state, generation)) {
                    (void)::CancelIoEx(nativeHandle, &overlapped);
                    // Cancellation is asynchronous: wait for the current I/O to complete before closing the event or leaving the stack scope.
                    completionOk = ::GetOverlappedResult(nativeHandle, &overlapped, &bytesReturned, TRUE);
                } else {
                    completionOk = ::GetOverlappedResult(nativeHandle, &overlapped, &bytesReturned, FALSE);
                }
                if (completionOk == FALSE) {
                    const DWORD kError = ::GetLastError();
                    ::CloseHandle(overlapped.hEvent);
                    if (kError == ERROR_OPERATION_ABORTED || kError == ERROR_INVALID_HANDLE ||
                        kError == ERROR_DEVICE_NOT_CONNECTED || kError == ERROR_FILE_NOT_FOUND) {
                        resetHandle(state);
                    }
                    if (isReceiverRunning(state, generation)) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(kReceiverRetryMilliseconds));
                    }
                    continue;
                }
            } else {
                ::CloseHandle(overlapped.hEvent);
                if (kIssued.win32Error == ERROR_INVALID_HANDLE || kIssued.win32Error == ERROR_DEVICE_NOT_CONNECTED ||
                    kIssued.win32Error == ERROR_FILE_NOT_FOUND) {
                    resetHandle(state);
                }
                if (isReceiverRunning(state, generation)) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(kReceiverRetryMilliseconds));
                }
                continue;
            }
        }
        ::CloseHandle(overlapped.hEvent);

        if (!isReceiverRunning(state, generation)) {
            break;
        }
        if (bytesReturned >= sizeof(event) && event.size >= sizeof(event) &&
            event.version == KSWORD_ARK_CALLBACK_PROTOCOL_VERSION) {
            postEvent(state, generation, event);
        }
    }
    resetHandle(state);
    state->workerRunning.store(false, std::memory_order_release);
}

} // namespace

CallbackEventReceiver::CallbackEventReceiver(const HWND owner, const UINT eventMessage)
    : state_(std::make_shared<State>(owner, eventMessage)) {
}

CallbackEventReceiver::~CallbackEventReceiver() {
    shutdown();
}

bool CallbackEventReceiver::start() {
    const std::shared_ptr<State> kState = state_;
    if (!kState) {
        return false;
    }
    std::uint64_t generation = 0;
    {
        std::scoped_lock lock(kState->mutex);
        if (kState->owner == nullptr || kState->active.load(std::memory_order_acquire) ||
            kState->workerRunning.load(std::memory_order_acquire)) {
            return false;
        }
        generation = kState->generation.fetch_add(1, std::memory_order_acq_rel) + 1U;
        kState->active.store(true, std::memory_order_release);
        kState->workerRunning.store(true, std::memory_order_release);
    }
    std::thread([kState, generation] { runReceiver(kState, generation); }).detach();
    return true;
}

void CallbackEventReceiver::stop() noexcept {
    const std::shared_ptr<State> kState = state_;
    if (!kState) {
        return;
    }
    HANDLE nativeHandle = INVALID_HANDLE_VALUE;
    {
        std::scoped_lock lock(kState->mutex);
        kState->active.store(false, std::memory_order_release);
        kState->generation.fetch_add(1, std::memory_order_acq_rel);
        nativeHandle = kState->handle.native();
    }
    if (nativeHandle != nullptr && nativeHandle != INVALID_HANDLE_VALUE) {
        (void)::CancelIoEx(nativeHandle, nullptr);
    }
}

void CallbackEventReceiver::shutdown() noexcept {
    stop();
    const std::shared_ptr<State> kState = state_;
    if (kState) {
        std::scoped_lock lock(kState->mutex);
        kState->owner = nullptr;
    }
}

bool CallbackEventReceiver::running() const noexcept {
    const std::shared_ptr<State> kState = state_;
    return kState && kState->active.load(std::memory_order_acquire);
}

bool CallbackEventReceiver::stopping() const noexcept {
    const std::shared_ptr<State> kState = state_;
    return kState && !kState->active.load(std::memory_order_acquire) &&
        kState->workerRunning.load(std::memory_order_acquire);
}

bool CallbackEventReceiver::accepts(const std::uint64_t generation) const noexcept {
    const std::shared_ptr<State> kState = state_;
    return kState && kState->active.load(std::memory_order_acquire) && kState->generation.load(std::memory_order_acquire) == generation;
}

} // namespace Ksword::Features::Kernel
