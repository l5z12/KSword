#include "ProcessDock.Support.h"
#include "ProcessActivityChartWidget.h"
#include "ProcessActivityTimelineSlider.h"

using namespace ksword::ui::process_dock;

void ProcessDock::dispatchProcessActionTargetsInParallel(
    const QString& actionTitle,
    const std::vector<ProcessActionTarget>& actionTargets,
    const std::function<bool(const ProcessActionTarget&, std::string*)>& actionInvoker,
    const bool refreshWhenAnySucceeded,
    const bool forceAsyncWithTimeout,
    const bool requireVerifiedProcessIdentity)
{
    // Parameter check: Log and return immediately if no target or no invoker exists.
    if (actionTargets.empty() || !actionInvoker)
    {
        KLogEvent logEvent;
        warn << logEvent
            << "[ProcessDock] 批量动作被忽略：目标为空或执行体为空, title="
            << actionTitle.toStdString()
            << eol;
        return;
    }

    // For any action targeting a process by PID, first verify the PID and creation time on the same process object, and keep
    // the query handle until actionInvoker returns. This ensures that even if R3 or R0 action implementations still use PID as
    // the entry point, they won't mistakenly target a PID that has been recycled by Windows after the original process exits.
    const auto kInvokeAction = [actionInvoker, requireVerifiedProcessIdentity](
        const ProcessActionTarget& actionTarget,
        std::string* const detailTextOut) -> bool
    {
        if (!requireVerifiedProcessIdentity || actionTarget.isKernelOnly)
        {
            return actionInvoker(actionTarget, detailTextOut);
        }

        HANDLE rawIdentityHandle = nullptr;
        std::string identityDetailText;
        if (!acquireProcessActionIdentityHold(
                actionTarget.record.pid,
                actionTarget.record.creationTime100ns,
                &rawIdentityHandle,
                &identityDetailText))
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = identityDetailText;
            }
            return false;
        }

        ScopedProcessActionHandle identityHandle(rawIdentityHandle);
        return actionInvoker(actionTarget, detailTextOut);
    };

    // R3 process termination includes external debugger and session management fallback; single target must also execute asynchronously.
    // Other actions retain the original single-target synchronous semantics to avoid expanding the scope of this change.
    if (actionTargets.size() == 1U && !forceAsyncWithTimeout)
    {
        std::string detailText;
        const bool kActionOk = kInvokeAction(actionTargets.front(), &detailText);
        KLogEvent actionEvent;
        (kActionOk ? info : err) << actionEvent
            << "[ProcessDock] 单进程动作完成, title=" << actionTitle.toStdString()
            << ", pid=" << actionTargets.front().record.pid
            << ", ok=" << (kActionOk ? "true" : "false")
            << ", detail=" << (detailText.empty() ? "无附加信息" : detailText)
            << eol;
        showActionResultMessage(actionTitle, kActionOk, detailText, actionEvent);
        if (kActionOk && refreshWhenAnySucceeded)
        {
            requestAsyncRefresh(true);
        }
        clearContextActionBinding();
        return;
    }

    // Batch actions: each PID is executed in an independent thread to prevent one target from blocking subsequent targets if it hangs.
    static constexpr int kProcessActionTimeoutMs = 15000;
    QPointer<ProcessDock> guard(this);
    const QString kLocalActionTitle = actionTitle;
    const std::size_t kTargetCount = actionTargets.size();
    const auto kFinishedCounter = std::make_shared<std::atomic_size_t>(0U);
    const auto kAnySucceeded = std::make_shared<std::atomic_bool>(false);
    KLogEvent startEvent;
    info << startEvent
        << "[ProcessDock] 启动批量动作, title=" << kLocalActionTitle.toStdString()
        << ", targetCount=" << kTargetCount
        << eol;

    for (const ProcessActionTarget& actionTarget : actionTargets)
    {
        // resultReported: Ensures only one party (normal completion or timeout watchdog) can report back to the UI.
        // Late results after timeout are still logged and included in refresh statistics, but cannot overwrite an already reported failure.
        std::shared_ptr<std::atomic_bool> resultReported;
        if (forceAsyncWithTimeout)
        {
            resultReported = std::make_shared<std::atomic_bool>(false);
            QTimer::singleShot(
                kProcessActionTimeoutMs,
                this,
                [guard, kLocalActionTitle, actionTarget, resultReported]()
                {
                    bool expected = false;
                    if (!resultReported->compare_exchange_strong(
                        expected,
                        true,
                        std::memory_order_acq_rel))
                    {
                        return;
                    }

                    const std::string kTimeoutDetail =
                        "process action timed out after 15000 ms; target may be PPL-protected or a system API is blocked";
                    KLogEvent timeoutEvent;
                    err << timeoutEvent
                        << "[ProcessDock] 进程动作超时, title="
                        << kLocalActionTitle.toStdString()
                        << ", pid="
                        << actionTarget.record.pid
                        << ", detail="
                        << kTimeoutDetail
                        << eol;

                    if (guard != nullptr)
                    {
                        guard->showActionResultMessage(
                            kLocalActionTitle,
                            false,
                            kTimeoutDetail,
                            timeoutEvent);
                    }
                });
        }

        std::thread([
            guard,
            kLocalActionTitle,
            actionTarget,
            kInvokeAction,
            refreshWhenAnySucceeded,
            kTargetCount,
            kFinishedCounter,
            kAnySucceeded,
            resultReported]()
        {
            std::string detailText;
            const bool kActionOk = kInvokeAction(actionTarget, &detailText);
            const std::string kNormalizedDetailText = detailText.empty() ? "无附加信息" : detailText;
            if (kActionOk)
            {
                kAnySucceeded->store(true, std::memory_order_relaxed);
            }
            const std::size_t kFinishedCount =
                kFinishedCounter->fetch_add(1U, std::memory_order_acq_rel) + 1U;
            const bool kAllTargetsFinished = (kFinishedCount >= kTargetCount);

            KLogEvent threadEvent;
            (kActionOk ? info : err) << threadEvent
                << "[ProcessDock] 批量动作单目标完成, title=" << kLocalActionTitle.toStdString()
                << ", pid=" << actionTarget.record.pid
                << ", identity=" << actionTarget.identityKey
                << ", ok=" << (kActionOk ? "true" : "false")
                << ", detail=" << kNormalizedDetailText
                << eol;

            bool reportCompletion = true;
            if (resultReported != nullptr)
            {
                bool expected = false;
                reportCompletion = resultReported->compare_exchange_strong(
                    expected,
                    true,
                    std::memory_order_acq_rel);
            }
            if (!reportCompletion)
            {
                KLogEvent lateResultEvent;
                warn << lateResultEvent
                    << "[ProcessDock] 进程动作在超时提示后返回, title="
                    << kLocalActionTitle.toStdString()
                    << ", pid="
                    << actionTarget.record.pid
                    << ", ok="
                    << (kActionOk ? "true" : "false")
                    << ", detail="
                    << kNormalizedDetailText
                    << eol;
            }

            if (guard == nullptr)
            {
                return;
            }

            if (reportCompletion)
            {
                QMetaObject::invokeMethod(guard, [guard, kLocalActionTitle, kActionOk, detailText]()
                {
                    if (guard == nullptr)
                    {
                        return;
                    }

                    KLogEvent uiEvent;
                    guard->showActionResultMessage(kLocalActionTitle, kActionOk, detailText, uiEvent);
                }, Qt::QueuedConnection);
            }

            if (!kAllTargetsFinished || guard == nullptr)
            {
                return;
            }

            QMetaObject::invokeMethod(guard, [guard, kLocalActionTitle, refreshWhenAnySucceeded, kAnySucceeded]()
            {
                if (guard == nullptr)
                {
                    return;
                }

                if (refreshWhenAnySucceeded && kAnySucceeded->load(std::memory_order_relaxed))
                {
                    KLogEvent refreshEvent;
                    info << refreshEvent
                        << "[ProcessDock] 批量动作全部完成，触发一次刷新, title="
                        << kLocalActionTitle.toStdString()
                        << eol;
                    guard->requestAsyncRefresh(true);
                }
            }, Qt::QueuedConnection);
        }).detach();
    }

    // Preserve the context cleanup timing for R3 single-target actions to prevent right-click bindings from pointing to stale rows during background execution.
    if (forceAsyncWithTimeout && actionTargets.size() == 1U)
    {
        clearContextActionBinding();
    }
}
