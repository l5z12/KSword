#include "DiskMonitorStorageLeaseCoordinator.h"

#include <QDebug>
#include <QHash>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <limits>
#include <memory>
#include <mutex>
#include <system_error>
#include <thread>
#include <utility>

#include <winioctl.h>

namespace disk_monitor_storage_lease
{
    namespace
    {
        using RetirementClock = std::chrono::steady_clock;

        constexpr std::uint32_t kMaximumBackoffExponent = 7U;
        constexpr std::uint32_t kInitialBackoffMilliseconds = 250U;

        enum class LeaseSlotState
        {
            kActive,
            kRetiring
        };

        // LeaseSlot：
        // - At most one slot exists per normalized volume GUID.
        // - The Active phase uses the lease by the sampling thread;
        // - Retiring phase: serial compensation of references by a unique worker.
        struct LeaseSlot
        {
            LeasePointer lease;               // lease: The sole ownership object shared between active and retired phases.
            LeaseSlotState state = LeaseSlotState::kActive; // state: current ownership phase.
            QString retirementReason;         // retirementReason: Diagnostic reason triggering retirement.
            std::uint32_t failureAttempt = 0U; // failureAttempt: Number of consecutive OFF failures.
            RetirementClock::time_point nextAttemptAt = RetirementClock::now(); // nextAttemptAt: The next time a retry is allowed.
        };

        using LeaseSlotPointer = std::shared_ptr<LeaseSlot>;

        // LeaseCoordinatorState：
        // - slotByVolumeGuid serves both active reservation and retiring quarantine.
        // - workerThread is limited to at most one; no thread is created per volume;
        // - Object intentionally kept until process exit to prevent worker access to invalid state after Qt panel destruction.
        struct LeaseCoordinatorState
        {
            std::mutex mutex;                 // mutex: Protects slot, retry time, and worker ownership.
            std::condition_variable wakeCondition; // wakeCondition: Wake the worker when a new task or an earlier task arrives.
            QHash<QString, LeaseSlotPointer> slotByVolumeGuid; // slotByVolumeGuid: Unique status slot per volume.
            std::unique_ptr<std::thread> workerThread; // workerThread: The unique, non-detached background thread for the process lifetime.
        };

        QString normalizedVolumeGuidName(const QString& volumeGuidName)
        {
            // normalizedName: Normalizes delimiters, case, and whitespace to ensure a single volume occupies only one slot.
            QString normalizedName = volumeGuidName.trimmed();
            normalizedName.replace(QLatin1Char('/'), QLatin1Char('\\'));
            return normalizedName.toUpper();
        }

        LeaseCoordinatorState& coordinatorState()
        {
            // state: The process-scoped ledger must not be destroyed before the background worker, so static destruction is intentionally not registered.
            static auto* state = new LeaseCoordinatorState();
            return *state;
        }

        void logRetiredLeaseDiagnostic(
            const Lease& lease,
            const QString& reason,
            const QString& action,
            const DWORD errorCode,
            const std::uint32_t attempt)
        {
            qWarning().noquote()
                << QStringLiteral(
                    "[DiskMonitorStorage] retired lease %1: guid=%2 refs=%3 "
                    "error=%4 attempt=%5 lastQueryError=%6 "
                    "consecutiveQueryFailures=%7 reason=%8")
                    .arg(action)
                    .arg(lease.volumeGuidName)
                    .arg(lease.ownedEnableReferenceCount)
                    .arg(errorCode)
                    .arg(attempt)
                    .arg(lease.lastQueryError)
                    .arg(lease.consecutiveQueryFailureCount)
                    .arg(reason);
        }

        bool hasRetiringSlotLocked(const LeaseCoordinatorState& state)
        {
            // slot: If any Retiring slot exists, ensure exactly one worker remains active.
            for (auto slotIterator = state.slotByVolumeGuid.constBegin();
                 slotIterator != state.slotByVolumeGuid.constEnd();
                 ++slotIterator)
            {
                const LeaseSlotPointer& slot = slotIterator.value();
                if (slot != nullptr &&
                    slot->state == LeaseSlotState::kRetiring)
                {
                    return true;
                }
            }
            return false;
        }

        void runRetiredLeaseWorker(LeaseCoordinatorState* state)
        {
            if (state == nullptr)
            {
                return;
            }

            for (;;)
            {
                LeaseSlotPointer selectedSlot;
                QString selectedVolumeGuid;
                {
                    std::unique_lock<std::mutex> lock(state->mutex);
                    while (selectedSlot == nullptr)
                    {
                        const RetirementClock::time_point kNow =
                            RetirementClock::now();
                        RetirementClock::time_point earliestAttempt =
                            RetirementClock::time_point::max();

                        // Only one expired volume is selected per round; with a single worker serializing OFF
                        // operations, blocking the driver does not escalate into a permanent thread per volume.
                        for (auto slotIterator =
                                 state->slotByVolumeGuid.constBegin();
                             slotIterator !=
                                 state->slotByVolumeGuid.constEnd();
                             ++slotIterator)
                        {
                            const LeaseSlotPointer& candidateSlot =
                                slotIterator.value();
                            if (candidateSlot == nullptr ||
                                candidateSlot->state !=
                                    LeaseSlotState::kRetiring)
                            {
                                continue;
                            }
                            if (candidateSlot->nextAttemptAt <= kNow)
                            {
                                selectedSlot = candidateSlot;
                                selectedVolumeGuid = slotIterator.key();
                                break;
                            }
                            earliestAttempt = std::min(
                                earliestAttempt,
                                candidateSlot->nextAttemptAt);
                        }

                        if (selectedSlot != nullptr)
                        {
                            break;
                        }
                        if (earliestAttempt ==
                            RetirementClock::time_point::max())
                        {
                            state->wakeCondition.wait(lock);
                        }
                        else
                        {
                            state->wakeCondition.wait_until(
                                lock,
                                earliestAttempt);
                        }
                    }
                }

                Lease& lease = *selectedSlot->lease;
                DWORD releaseError = ERROR_SUCCESS;
                const bool kReleasedReference =
                    turnOffOneReference(&lease, &releaseError);
                const bool kRetirementCompleted =
                    lease.ownedEnableReferenceCount == 0U;

                // CloseHandle is also executed only in the background worker; the slot remains in quarantine until closure
                // completes to prevent the same volume from being reopened while the old handle is still being finalized.
                if (kRetirementCompleted &&
                    lease.volumeHandle != INVALID_HANDLE_VALUE)
                {
                    CloseHandle(lease.volumeHandle);
                    lease.volumeHandle = INVALID_HANDLE_VALUE;
                }

                QString action;
                std::uint32_t diagnosticAttempt = 0U;
                {
                    std::lock_guard<std::mutex> lock(state->mutex);
                    auto slotIterator =
                        state->slotByVolumeGuid.find(selectedVolumeGuid);
                    if (slotIterator ==
                            state->slotByVolumeGuid.end() ||
                        slotIterator.value() != selectedSlot)
                    {
                        continue;
                    }

                    if (kRetirementCompleted)
                    {
                        action = QStringLiteral("closed");
                        diagnosticAttempt =
                            selectedSlot->failureAttempt;
                        state->slotByVolumeGuid.erase(slotIterator);
                    }
                    else if (kReleasedReference)
                    {
                        action = QStringLiteral("released-one");
                        selectedSlot->failureAttempt = 0U;
                        selectedSlot->nextAttemptAt =
                            RetirementClock::now();
                    }
                    else
                    {
                        action = QStringLiteral("retry");
                        if (selectedSlot->failureAttempt <
                            std::numeric_limits<std::uint32_t>::max())
                        {
                            ++selectedSlot->failureAttempt;
                        }
                        diagnosticAttempt =
                            selectedSlot->failureAttempt;
                        const std::uint32_t kBackoffExponent =
                            std::min(
                                selectedSlot->failureAttempt,
                                kMaximumBackoffExponent);
                        const std::uint32_t kBackoffMilliseconds =
                            kInitialBackoffMilliseconds *
                            (1U << kBackoffExponent);
                        selectedSlot->nextAttemptAt =
                            RetirementClock::now() +
                            std::chrono::milliseconds(
                                kBackoffMilliseconds);
                    }
                }

                logRetiredLeaseDiagnostic(
                    lease,
                    selectedSlot->retirementReason,
                    action,
                    kReleasedReference
                        ? ERROR_SUCCESS
                        : releaseError,
                    diagnosticAttempt);
            }
        }

        void ensureWorkerStarted()
        {
            LeaseCoordinatorState& state = coordinatorState();
            QString startErrorText;
            {
                std::lock_guard<std::mutex> lock(state.mutex);
                if (state.workerThread != nullptr ||
                    !hasRetiringSlotLocked(state))
                {
                    return;
                }

                try
                {
                    // workerThread: the coordinator retains a joinable object until process exit; it
                    // is not detached, nor does it depend on the lifetime of any QWidget/QObject.
                    LeaseCoordinatorState* const kStatePointer = &state;
                    state.workerThread =
                        std::make_unique<std::thread>(
                            [kStatePointer]()
                            {
                                runRetiredLeaseWorker(kStatePointer);
                            });
                }
                catch (const std::system_error& error)
                {
                    startErrorText =
                        QString::fromStdString(error.what());
                }
            }

            if (!startErrorText.isEmpty())
            {
                qWarning().noquote()
                    << QStringLiteral(
                        "[DiskMonitorStorage] retirement worker start "
                        "failed; bounded ledger retained for next retry: %1")
                        .arg(startErrorText);
            }
        }
    }

    LeasePointer tryAcquireActiveLease(
        const QString& volumeGuidName)
    {
        const QString kVolumeGuidKey =
            normalizedVolumeGuidName(volumeGuidName);
        if (kVolumeGuidKey.isEmpty())
        {
            return {};
        }

        LeaseCoordinatorState& state = coordinatorState();
        bool blockedByRetirement = false;
        {
            std::lock_guard<std::mutex> lock(state.mutex);
            const auto kExistingIterator =
                state.slotByVolumeGuid.constFind(kVolumeGuidKey);
            if (kExistingIterator !=
                state.slotByVolumeGuid.constEnd())
            {
                const LeaseSlotPointer& existingSlot =
                    kExistingIterator.value();
                blockedByRetirement =
                    existingSlot != nullptr &&
                    existingSlot->state ==
                        LeaseSlotState::kRetiring;
            }
            else
            {
                LeasePointer lease = std::make_shared<Lease>();
                lease->volumeGuidName = kVolumeGuidKey;

                LeaseSlotPointer slot =
                    std::make_shared<LeaseSlot>();
                slot->lease = lease;
                slot->state = LeaseSlotState::kActive;
                state.slotByVolumeGuid.insert(
                    kVolumeGuidKey,
                    std::move(slot));
                return lease;
            }
        }

        // If worker creation fails, the ledger is not lost; subsequent 1 Hz sampling will only retry
        // starting the same worker, without creating new leases, handles, or tasks for that volume.
        if (blockedByRetirement)
        {
            ensureWorkerStarted();
        }
        return {};
    }

    bool releaseUnusedActiveLease(
        const LeasePointer& lease)
    {
        if (lease == nullptr)
        {
            return false;
        }

        const QString kVolumeGuidKey =
            normalizedVolumeGuidName(lease->volumeGuidName);
        LeaseCoordinatorState& state = coordinatorState();
        std::lock_guard<std::mutex> lock(state.mutex);
        auto slotIterator =
            state.slotByVolumeGuid.find(kVolumeGuidKey);
        if (slotIterator ==
                state.slotByVolumeGuid.end() ||
            slotIterator.value() == nullptr ||
            slotIterator.value()->lease != lease ||
            slotIterator.value()->state !=
                LeaseSlotState::kActive)
        {
            return false;
        }

        state.slotByVolumeGuid.erase(slotIterator);
        return true;
    }

    bool retireLeaseAsync(
        const LeasePointer& lease,
        const QString& reason)
    {
        if (lease == nullptr)
        {
            return false;
        }

        const QString kVolumeGuidKey =
            normalizedVolumeGuidName(lease->volumeGuidName);
        LeaseCoordinatorState& state = coordinatorState();
        Lease diagnosticSnapshot;
        bool newlyRetired = false;
        {
            std::lock_guard<std::mutex> lock(state.mutex);
            auto slotIterator =
                state.slotByVolumeGuid.find(kVolumeGuidKey);
            if (slotIterator ==
                    state.slotByVolumeGuid.end() ||
                slotIterator.value() == nullptr ||
                slotIterator.value()->lease != lease)
            {
                return false;
            }

            LeaseSlotPointer& slot = slotIterator.value();
            if (slot->state == LeaseSlotState::kActive)
            {
                // diagnosticSnapshot: Freezes the diagnostic snapshot by value before transitioning to Retiring.
                // Worker modifications to reference counts/handles later will not race with log reads.
                diagnosticSnapshot = *lease;
                slot->state = LeaseSlotState::kRetiring;
                slot->retirementReason = reason;
                slot->failureAttempt = 0U;
                slot->nextAttemptAt = RetirementClock::now();
                newlyRetired = true;
            }
        }

        if (newlyRetired)
        {
            logRetiredLeaseDiagnostic(
                diagnosticSnapshot,
                reason,
                QStringLiteral("queued"),
                ERROR_SUCCESS,
                0U);
        }
        ensureWorkerStarted();
        state.wakeCondition.notify_one();
        return true;
    }

    bool turnOffOneReference(
        Lease* lease,
        DWORD* errorOut)
    {
        if (errorOut != nullptr)
        {
            *errorOut = ERROR_SUCCESS;
        }
        if (lease == nullptr ||
            lease->ownedEnableReferenceCount == 0U)
        {
            return true;
        }
        if (lease->volumeHandle == INVALID_HANDLE_VALUE)
        {
            if (errorOut != nullptr)
            {
                *errorOut = ERROR_INVALID_HANDLE;
            }
            return false;
        }

        DWORD returnedBytes = 0U;
        const BOOL kReleaseOk = DeviceIoControl(
            lease->volumeHandle,
            IOCTL_DISK_PERFORMANCE_OFF,
            nullptr,
            0U,
            nullptr,
            0U,
            &returnedBytes,
            nullptr);
        if (!kReleaseOk)
        {
            if (errorOut != nullptr)
            {
                *errorOut = GetLastError();
            }
            return false;
        }

        --lease->ownedEnableReferenceCount;
        return true;
    }
}
