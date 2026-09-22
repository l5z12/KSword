#pragma once

#include "../core/Win32Lean.h"

#include <atomic>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <utility>

namespace ksword::ui {

// AsyncSnapshotTask runs one value-producing operation away from the UI thread.
// Repeated requests are coalesced: only the newest request is delivered after an
// in-flight operation completes. The owner must call cancel() from WM_NCDESTROY
// and consume() for its configured completion message.
template <typename Result>
class AsyncSnapshotTask final {
public:
    using Work = std::function<Result()>;
    using Deliver = std::function<void(std::uint64_t, std::optional<Result>&&, std::exception_ptr)>;

    explicit AsyncSnapshotTask(HWND owner, UINT completionMessage)
        : state_(std::make_shared<State>(owner, completionMessage)) {
    }

    ~AsyncSnapshotTask() {
        cancel();
    }

    AsyncSnapshotTask(const AsyncSnapshotTask&) = delete;
    AsyncSnapshotTask& operator=(const AsyncSnapshotTask&) = delete;

    void resetOwner(HWND owner) {
        const std::shared_ptr<State> kState = state_;
        if (!kState) {
            return;
        }
        std::scoped_lock lock(kState->mutex);
        kState->owner = owner;
        kState->alive.store(owner != nullptr, std::memory_order_release);
    }

    void request(Work work, Deliver deliver) {
        const std::shared_ptr<State> kState = state_;
        if (!kState || !work || !deliver || !kState->alive.load(std::memory_order_acquire)) {
            return;
        }

        Work startWork;
        std::uint64_t generation = 0;
        bool startNow = false;
        {
            std::scoped_lock lock(kState->mutex);
            if (!kState->alive.load(std::memory_order_acquire)) {
                return;
            }

            kState->work = std::move(work);
            kState->deliver = std::move(deliver);
            generation = ++kState->latestGeneration;
            if (kState->running) {
                kState->pending = true;
                return;
            }

            kState->running = true;
            kState->runningGeneration = generation;
            startWork = kState->work;
            startNow = true;
        }

        if (startNow) {
            startWorker(kState, std::move(startWork), generation);
        }
    }

    // consume takes ownership of lParam when it belongs to this task. Call it
    // only for the completion message supplied to the constructor.
    bool consume(HWND owner, WPARAM, LPARAM lParam) {
        std::unique_ptr<Completion> completion(reinterpret_cast<Completion*>(lParam));
        if (!completion) {
            return false;
        }

        const std::shared_ptr<State> kState = completion->state.lock();
        if (!kState || !kState->alive.load(std::memory_order_acquire)) {
            return true;
        }

        Deliver deliver;
        Work nextWork;
        std::uint64_t nextGeneration = 0;
        bool deliverCurrent = false;
        bool startNext = false;
        {
            std::scoped_lock lock(kState->mutex);
            if (!kState->alive.load(std::memory_order_acquire) || kState->owner != owner) {
                return true;
            }

            deliverCurrent = completion->generation == kState->latestGeneration;
            deliver = kState->deliver;
            if (kState->running && kState->runningGeneration == completion->generation) {
                kState->running = false;
                if (kState->pending && kState->alive.load(std::memory_order_acquire)) {
                    kState->pending = false;
                    kState->running = true;
                    kState->runningGeneration = kState->latestGeneration;
                    nextGeneration = kState->runningGeneration;
                    nextWork = kState->work;
                    startNext = true;
                }
            }
        }

        if (deliverCurrent && deliver) {
            deliver(completion->generation, std::move(completion->result), completion->error);
        }
        if (startNext) {
            startWorker(kState, std::move(nextWork), nextGeneration);
        }
        return true;
    }

    void cancel() noexcept {
        const std::shared_ptr<State> kState = state_;
        if (!kState) {
            return;
        }
        std::scoped_lock lock(kState->mutex);
        kState->alive.store(false, std::memory_order_release);
        kState->owner = nullptr;
        kState->pending = false;
        kState->work = {};
        kState->deliver = {};
    }

    bool running() const noexcept {
        const std::shared_ptr<State> kState = state_;
        if (!kState) {
            return false;
        }
        std::scoped_lock lock(kState->mutex);
        return kState->running || kState->pending;
    }

private:
    struct State final {
        State(HWND target, UINT message)
            : owner(target), completionMessage(message), alive(target != nullptr) {
        }

        std::mutex mutex;
        HWND owner = nullptr;
        UINT completionMessage = 0;
        std::atomic_bool alive = false;
        bool running = false;
        bool pending = false;
        std::uint64_t latestGeneration = 0;
        std::uint64_t runningGeneration = 0;
        Work work;
        Deliver deliver;
    };

    struct Completion final {
        std::weak_ptr<State> state;
        std::uint64_t generation = 0;
        std::optional<Result> result;
        std::exception_ptr error;
    };

    static void startWorker(const std::shared_ptr<State>& state, Work work, const std::uint64_t generation) {
        std::thread([state, work = std::move(work), generation]() mutable {
            auto completion = std::make_unique<Completion>();
            completion->state = state;
            completion->generation = generation;
            try {
                completion->result.emplace(work());
            } catch (...) {
                completion->error = std::current_exception();
            }

            HWND owner = nullptr;
            UINT message = 0;
            bool shouldPost = false;
            {
                std::scoped_lock lock(state->mutex);
                shouldPost = state->alive.load(std::memory_order_acquire);
                owner = state->owner;
                message = state->completionMessage;
            }

            if (shouldPost && owner && ::PostMessageW(owner, message, static_cast<WPARAM>(generation), reinterpret_cast<LPARAM>(completion.get()))) {
                completion.release();
                return;
            }

            finishWithoutDelivery(state, generation);
        }).detach();
    }

    static void finishWithoutDelivery(const std::shared_ptr<State>& state, const std::uint64_t generation) {
        Work nextWork;
        std::uint64_t nextGeneration = 0;
        bool startNext = false;
        {
            std::scoped_lock lock(state->mutex);
            if (state->running && state->runningGeneration == generation) {
                state->running = false;
                if (state->pending && state->alive.load(std::memory_order_acquire)) {
                    state->pending = false;
                    state->running = true;
                    state->runningGeneration = state->latestGeneration;
                    nextGeneration = state->runningGeneration;
                    nextWork = state->work;
                    startNext = true;
                }
            }
        }
        if (startNext) {
            startWorker(state, std::move(nextWork), nextGeneration);
        }
    }

private:
    std::shared_ptr<State> state_;
};

} // namespace Ksword::Ui
