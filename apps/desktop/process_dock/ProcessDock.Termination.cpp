#include "ProcessDock.Support.h"
#include "ProcessActivityChartWidget.h"
#include "ProcessActivityTimelineSlider.h"

using namespace ksword::ui::process_dock;

void ProcessDock::executeScreenInjectionSurfaceAction()
{
    /*
     * Injection surface filtering (issue #196). Execute only on **selected items**, do not follow periodic refresh:
     * Measured across 496 processes: one pass took 1073 ms (median 2.52 ms,
     * p95 9.5 ms). This cannot be part of a once-per-second table refresh.
     *
     * This step enumerates address spaces only; it does not read memory or touch modules, PE, working sets, or threads.
     * It provides a count, not a conclusion.
     */
    const std::vector<ProcessActionTarget> kActionTargets = selectedActionTargets();
    if (kActionTargets.empty())
    {
        KLogEvent logEvent;
        warn << logEvent << "[ProcessDock] 注入面筛选被忽略：当前没有选中进程。" << eol;
        return;
    }

    std::size_t screenedCount = 0;
    std::size_t limitedCount = 0;
    QStringList resultLineList;
    resultLineList.reserve(static_cast<qsizetype>(kActionTargets.size()));

    for (const ProcessActionTarget& actionTarget : kActionTargets)
    {
        auto cacheIt = cacheByIdentity_.find(actionTarget.identityKey);
        if (cacheIt == cacheByIdentity_.end())
        {
            resultLineList.push_back(QStringLiteral("PID %1: cache missing")
                .arg(actionTarget.record.pid));
            continue;
        }

        const ksword::evidence::ProcessSurfaceScreen kScreen =
            ks::process::screenProcessInjectionSurface(
                actionTarget.record.pid,
                actionTarget.record.creationTime100ns);

        cacheIt->second.record.injectionSurfaceState =
            static_cast<std::uint32_t>(kScreen.state);
        cacheIt->second.record.injectionDynamicRegions = kScreen.dynamicCodeRegions;
        cacheIt->second.record.injectionWritableExecRegions =
            kScreen.writableExecutableRegions;
        cacheIt->second.record.injectionDynamicBytes = kScreen.dynamicCodeBytes;

        if (ksword::evidence::surfaceScreenCountsAreMeaningful(kScreen.state))
        {
            ++screenedCount;
        }
        else
        {
            ++limitedCount;
        }
        resultLineList.push_back(QStringLiteral("PID %1: %2 dyn=%3 wx=%4")
            .arg(actionTarget.record.pid)
            .arg(QString::fromLatin1(
                ksword::evidence::surfaceScreenStateName(kScreen.state)))
            .arg(kScreen.dynamicCodeRegions)
            .arg(kScreen.writableExecutableRegions));
    }

    rebuildTable();
    KLogEvent actionEvent;
    info << actionEvent
        << "[ProcessDock] 注入面筛选完成, targets=" << kActionTargets.size()
        << ", screened=" << screenedCount
        << ", limited=" << limitedCount
        << ", detail=" << resultLineList.join(" | ").toStdString()
        << eol;
}

void ProcessDock::executeTerminateProcessAction()
{
    const std::vector<ProcessActionTarget> kActionTargets = selectedActionTargets();
    if (kActionTargets.empty())
    {
        KLogEvent logEvent;
        warn << logEvent << "[ProcessDock] executeTerminateProcessAction 被忽略：当前没有选中进程。" << eol;
        return;
    }

    executeTerminateProcessActions(
        processContextText("process.menu.r3_terminate", QStringLiteral("R3 结束进程")),
        kActionTargets,
        false,
        false);
}

void ProcessDock::executeTerminateAndDeleteImageAction()
{
    const std::vector<ProcessActionTarget> kActionTargets = selectedActionTargets();
    if (kActionTargets.size() != 1U ||
        kActionTargets.front().record.pid == 0U ||
        kActionTargets.front().record.creationTime100ns == 0U ||
        kActionTargets.front().record.imagePath.empty())
    {
        KLogEvent logEvent;
        warn << logEvent
            << "[ProcessDock] executeTerminateAndDeleteImageAction 被拒绝："
            << "目标必须为一个具有创建时间和映像路径的进程。"
            << eol;
        clearContextActionBinding();
        return;
    }

    executeTerminateProcessActions(
        processContextText(
            "process.menu.terminate_delete_image",
            QStringLiteral("结束进程并删除映像文件")),
        kActionTargets,
        true);
}

void ProcessDock::executeTerminateProcessTreeAction()
{
    const std::vector<ProcessActionTarget> kActionTargets = processTreeActionTargets();
    if (kActionTargets.empty())
    {
        KLogEvent logEvent;
        warn << logEvent
            << "[ProcessDock] executeTerminateProcessTreeAction 被忽略：选中进程未包含在当前 R3 快照中。"
            << eol;
        return;
    }

    executeTerminateProcessActions(
        processContextText("process.menu.r3_terminate_tree", QStringLiteral("R3 结束进程树")),
        kActionTargets,
        false,
        false);
}

/*
 * Execute only one method from the combination chain, once.
 *
 * The rationale here is localization, not strength: the combined chain executes fourteen methods in two rounds. On success, it is
 * indistinguishable which method succeeded; on failure, it is indistinguishable which method was closest to success. Here, the result is
 * reported immediately after execution without attempting remaining methods or falling back to R0; otherwise, the result becomes unattributable.
 */
void ProcessDock::executeSingleTerminateMethodAction(const std::size_t methodIndex)
{
    if (methodIndex >= terminateMethodTable().size())
    {
        KLogEvent logEvent;
        warn << logEvent
            << "[ProcessDock] executeSingleTerminateMethodAction 被忽略：方法下标越界, index="
            << static_cast<unsigned long long>(methodIndex)
            << eol;
        return;
    }
    const std::vector<ProcessActionTarget> kActionTargets = selectedActionTargets();
    if (kActionTargets.empty())
    {
        KLogEvent logEvent;
        warn << logEvent
            << "[ProcessDock] executeSingleTerminateMethodAction 被忽略：当前没有选中进程。"
            << eol;
        return;
    }

    const TerminateMethodEntry& entry = terminateMethodTable()[methodIndex];
    const QString kMethodTitle = QString::fromUtf8(entry.methodName);
    dispatchProcessActionTargetsInParallel(
        kMethodTitle,
        kActionTargets,
        [methodIndex](const ProcessActionTarget& actionTarget, std::string* detailTextOut)
        {
            // Re-fetch the table index here instead of capturing a reference: the table is static, but
            // capturing a reference used across threads offers no benefit and introduces lifetime issues.
            return terminateMethodTable()[methodIndex].invokeMethod(
                actionTarget.record.pid, detailTextOut);
        },
        true,
        false,
        false);
}

/*
 * Open the DMA process operation window.
 *
 * Implement as a standalone window rather than a sub-tab of the memory page: this action targets **processes**, which is fundamentally different from memory
 * viewing/searching. Placing it within the memory page could lead users to inadvertently transition from 'viewing memory' to 'modifying another process'.
 */
void ProcessDock::openDmaProcessOpWindow()
{
    const std::vector<ProcessActionTarget> kActionTargets = selectedActionTargets();
    if (kActionTargets.empty())
    {
        KLogEvent logEvent;
        warn << logEvent << "[ProcessDock] openDmaProcessOpWindow 被忽略：当前没有选中进程。" << eol;
        return;
    }

    if (dmaProcessOpDialog_ == nullptr)
    {
        dmaProcessOpDialog_ = new QDialog(this);
        dmaProcessOpDialog_->setWindowTitle(
            processContextText("process.menu.dma_process_op.title",
                               QStringLiteral("DMA 进程操作")));
        dmaProcessOpDialog_->resize(900, 640);
        QVBoxLayout* const kDialogLayout = new QVBoxLayout(dmaProcessOpDialog_);
        kDialogLayout->setContentsMargins(0, 0, 0, 0);
        dmaProcessOpPage_ = new ksword::memory_dock::DmaProcessOpPage(dmaProcessOpDialog_);
        kDialogLayout->addWidget(dmaProcessOpPage_);
    }

    const ProcessActionTarget& target = kActionTargets.front();
    dmaProcessOpPage_->setAttachedProcess(
        target.record.pid,
        QString::fromStdString(target.record.processName));
    dmaProcessOpPage_->refreshChannelAvailability();
    dmaProcessOpDialog_->show();
    dmaProcessOpDialog_->raise();
    dmaProcessOpDialog_->activateWindow();
}

void ProcessDock::executeR0TerminateProcessAction()
{
    const std::vector<ProcessActionTarget> kActionTargets = selectedActionTargets();
    if (kActionTargets.empty())
    {
        KLogEvent logEvent;
        warn << logEvent << "[ProcessDock] executeR0TerminateProcessAction 被忽略：当前没有选中进程。" << eol;
        return;
    }

    executeR0TerminateProcessActions(
        processContextText("process.menu.r0_terminate", QStringLiteral("R0结束进程")),
        kActionTargets);
}

void ProcessDock::executeR0TerminateProcessTreeAction()
{
    const std::vector<ProcessActionTarget> kActionTargets = processTreeActionTargets();
    if (kActionTargets.empty())
    {
        KLogEvent logEvent;
        warn << logEvent
            << "[ProcessDock] executeR0TerminateProcessTreeAction 被忽略：选中进程未包含在当前 R3 快照中。"
            << eol;
        QMessageBox::information(
            this,
            processContextText("process.menu.r0_terminate_tree", QStringLiteral("R0结束进程树")),
            processContextText(
                "process.action.r0_terminate_tree.r3_snapshot_unavailable",
                QStringLiteral("当前选中进程未包含在 R3 进程快照中，无法识别进程树。")));
        return;
    }

    executeR0TerminateProcessActions(
        processContextText("process.menu.r0_terminate_tree", QStringLiteral("R0结束进程树")),
        kActionTargets);
}

/*
 * Route exclusively through the R0 driver path; no R3 methods are used.
 *
 * The 0dbbeaf1 commit on 2026-09-16 folded it into the R3 chain rollback, so "R0 only" can no longer be initiated independently:
 * If any of the 14 R3 methods succeeds, this R0 path is never executed. Attempting to verify the driver path
 * in isolation yields a false positive: it appears 'terminated successfully,' but the driver was never called.
 * Revert to the earlier implementation with separate entry points here, keeping the confirmation dialog as well (the failure surface for R0
 * termination differs from R3; it can kill things R3 cannot, making irreversible consequences more likely if the wrong target is selected).
 */
void ProcessDock::executeR0TerminateProcessActions(
    const QString& actionTitle,
    const std::vector<ProcessActionTarget>& actionTargets)
{
    QStringList targetPidList;
    for (const ProcessActionTarget& actionTarget : actionTargets)
    {
        targetPidList.push_back(QString::number(actionTarget.record.pid));
    }
    const QString kTargetDescription = ks::i18n::sourceText(
        QStringLiteral("%1 个进程；PID：%2"))
        .arg(actionTargets.size())
        .arg(targetPidList.join(QStringLiteral(", ")));
    if (!ks::ui::confirmDestructiveAction(
            this,
            QStringLiteral("process-termination-r0"),
            actionTitle,
            kTargetDescription,
            ks::i18n::sourceText(QStringLiteral(
                "R0 结束操作不可逆，可能造成数据丢失、系统不稳定或蓝屏。请确认目标无误后再继续。"))))
    {
        clearContextActionBinding();
        return;
    }

    dispatchProcessActionTargetsInParallel(
        actionTitle,
        actionTargets,
        [](const ProcessActionTarget& actionTarget, std::string* detailTextOut)
        {
            // Each action target independently invokes ArkDriverClient, creating a separate IOCTL to terminate the process.
            return terminateProcessByR0Driver(
                actionTarget.record.pid,
                r0ActionExpectedCreationTime(actionTarget.record),
                detailTextOut);
        },
        true,
        false,
        true);
}

void ProcessDock::executeTerminateProcessActions(
    const QString& actionTitle,
    const std::vector<ProcessActionTarget>& actionTargets,
    const bool deleteImageAfterExit,
    const bool includeR0Fallback)
{
    if (deleteImageAfterExit && actionTargets.size() != 1U)
    {
        clearContextActionBinding();
        return;
    }

    dispatchProcessActionTargetsInParallel(
        actionTitle,
        actionTargets,
        [deleteImageAfterExit, includeR0Fallback](const ProcessActionTarget& actionTarget, std::string* detailTextOut)
        {
            // targetPid usage: Fixes the target PID for the current action to prevent execution object changes due to row selection shifts.
            const std::uint32_t kTargetPid = actionTarget.record.pid;
            // Single-target actions uniformly reuse actionEvent to ensure consistent log GUIDs within the same call chain.
            KLogEvent actionEvent;
            info << actionEvent
                << "[ProcessDock] 开始执行结束进程组合动作, pid=" << kTargetPid
                << eol;

            // In deletion mode, the exact file object must be locked before any termination method executes; if this fails, termination is
            // skipped to prevent a half-completed state where the process has ended but the deletion target identity cannot be verified.
            ks::process::CapturedProcessImageDeleteTarget capturedImageTarget;
            std::string imageCaptureDetail;
            if (deleteImageAfterExit)
            {
                const std::wstring kExpectedImagePath =
                    QString::fromStdString(actionTarget.record.imagePath).toStdWString();
                const bool kCaptureOk = ks::process::captureProcessImageDeleteTarget(
                    kTargetPid,
                    actionTarget.record.creationTime100ns,
                    kExpectedImagePath,
                    &capturedImageTarget,
                    &imageCaptureDetail);
                if (!kCaptureOk)
                {
                    err << actionEvent
                        << "[ProcessDock] 结束并删除映像前置身份锁定失败, pid="
                        << kTargetPid
                        << ", detail="
                        << imageCaptureDetail
                        << eol;
                    if (detailTextOut != nullptr)
                    {
                        *detailTextOut = "文件身份锁定失败：" + imageCaptureDetail;
                    }
                    return false;
                }
            }

            // Perform an initial process existence check to avoid meaningless operations on an already exited PID.
            bool initialQueryOk = false;
            bool processStillPresent = isProcessPresentBySnapshot(kTargetPid, &initialQueryOk);
            if (!initialQueryOk)
            {
                warn << actionEvent
                    << "[ProcessDock] 结束进程前置存在性检查失败，将按“进程仍存在”继续处理, pid="
                    << kTargetPid
                    << eol;
            }
            if (!processStillPresent)
            {
                info << actionEvent
                    << "[ProcessDock] 目标进程已不存在，结束动作直接判定成功, pid="
                    << kTargetPid
                    << eol;
                if (deleteImageAfterExit)
                {
                    std::string deletionDetail;
                    const bool kDeletionOk = ks::process::deleteCapturedProcessImage(
                        &capturedImageTarget,
                        &deletionDetail);
                    (kDeletionOk ? info : err) << actionEvent
                        << "[ProcessDock] 原进程在文件身份锁定后退出，执行精确映像删除, pid="
                        << kTargetPid
                        << ", ok="
                        << (kDeletionOk ? "true" : "false")
                        << ", detail="
                        << deletionDetail
                        << eol;
                    if (detailTextOut != nullptr)
                    {
                        *detailTextOut = "capture=" + imageCaptureDetail +
                            " | process=already exited | delete=" + deletionDetail;
                    }
                    return kDeletionOk;
                }
                if (detailTextOut != nullptr)
                {
                    *detailTextOut = "目标进程已不存在，无需执行结束动作。";
                }
                return true;
            }

            // kTerminateRoundLimit usage: Limits the number of rounds for the 'full method chain' to prevent infinite UI blocking caused by anomalous targets.
            constexpr int kTerminateRoundLimit = 2;
            // processExited purpose: Record whether the target process has been confirmed to have exited after the combined action.
            bool processExited = false;
            // actionDetailStream usage: Aggregates details from each round and method for unified final output.
            std::ostringstream actionDetailStream;
            actionDetailStream << "pid=" << kTargetPid;
            if (deleteImageAfterExit)
            {
                actionDetailStream << " | capture=" << imageCaptureDetail;
            }

            // The method table is sourced from a single origin (terminateMethodTable), the same one used by the
            // 'Advanced Process Termination' menu. Previously, there was a locally defined copy here; modifying
            // each separately would cause them to diverge, and such inconsistency would not trigger an error.
            const std::vector<TerminateMethodEntry>& terminateMethodList =
                terminateMethodTable();

            for (int roundIndex = 0; roundIndex < kTerminateRoundLimit && !processExited; ++roundIndex)
            {
                // roundNumber: Log round number (1-based for easier manual troubleshooting).
                const int kRoundNumber = roundIndex + 1;

                for (std::size_t methodIndex = 0;
                    methodIndex < terminateMethodList.size() && !processExited;
                    ++methodIndex)
                {
                    const TerminateMethodEntry& methodEntry = terminateMethodList[methodIndex];
                    if (methodEntry.methodName == nullptr || !methodEntry.invokeMethod)
                    {
                        continue;
                    }

                    std::string methodDetailText;
                    const bool kMethodOk = methodEntry.invokeMethod(kTargetPid, &methodDetailText);
                    const std::string kNormalizedMethodDetailText =
                        methodDetailText.empty() ? "无附加信息" : methodDetailText;
                    (kMethodOk ? info : err) << actionEvent
                        << "[ProcessDock] 结束进程组合动作-方法执行, pid="
                        << kTargetPid
                        << ", round="
                        << kRoundNumber
                        << ", method="
                        << methodEntry.methodName
                        << ", ok="
                        << (kMethodOk ? "true" : "false")
                        << ", detail="
                        << kNormalizedMethodDetailText
                        << eol;
                    actionDetailStream
                        << " | round"
                        << kRoundNumber
                        << ":"
                        << methodEntry.methodName
                        << "="
                        << (kMethodOk ? "ok" : "fail")
                        << "("
                        << kNormalizedMethodDetailText
                        << ")";

                    if (!kMethodOk)
                    {
                        warn << actionEvent
                            << "[ProcessDock] 当前方法执行失败，继续尝试下一方法, pid="
                            << kTargetPid
                            << ", round="
                            << kRoundNumber
                            << ", method="
                            << methodEntry.methodName
                            << eol;
                        continue;
                    }

                    std::string exitWaitDetail;
                    processExited = waitForProcessExitAfterSuccessfulTerminate(
                        kTargetPid,
                        &exitWaitDetail);
                    actionDetailStream << " | wait=" << exitWaitDetail;
                    if (processExited)
                    {
                        info << actionEvent
                            << "[ProcessDock] 成功方法等待目标进程退出完成, pid="
                            << kTargetPid
                            << ", round="
                            << kRoundNumber
                            << ", method="
                            << methodEntry.methodName
                            << ", wait="
                            << exitWaitDetail
                            << eol;
                        break;
                    }

                    warn << actionEvent
                        << "[ProcessDock] 成功方法等待 200ms 后目标仍未退出，继续尝试下一方法, pid="
                        << kTargetPid
                        << ", round="
                        << kRoundNumber
                        << ", method="
                        << methodEntry.methodName
                        << ", wait="
                        << exitWaitDetail
                        << eol;
                }

                if (!processExited)
                {
                    warn << actionEvent
                        << "[ProcessDock] 本轮全方法链执行后目标仍存活，将进入下一轮, pid="
                        << kTargetPid
                        << ", round="
                        << kRoundNumber
                        << eol;
                }
            }

            // Execute the R0 driver fallback only once when all R3 methods fail to terminate the target. Do not include it in the
            // two-round R3 method table to avoid sending duplicate termination requests to the same target. For normally visible
            // processes, re-verify existence before fallback to cover the asynchronous exit tail of the previously successful method.
            // When includeR0Fallback is false, this entire block is skipped: the menu item 'End Process (R3)'
            // promises 'R3 only'. A single action behind the scenes that invokes the driver with this name is
            // deceptive and prevents 'isolated verification of the R3 path' from ever obtaining clean readings.
            if (!includeR0Fallback && !processExited)
            {
                actionDetailStream << " | R0 fallback=skipped (R3-only action)";
            }
            if (includeR0Fallback && !processExited && !actionTarget.isKernelOnly)
            {
                bool finalPresenceQueryOk = false;
                const bool kTargetStillPresentBeforeR0 = isProcessPresentBySnapshot(
                    kTargetPid,
                    &finalPresenceQueryOk);
                if (finalPresenceQueryOk && !kTargetStillPresentBeforeR0)
                {
                    processExited = true;
                    actionDetailStream << " | target=exited before R0 fallback";
                    info << actionEvent
                        << "[ProcessDock] 目标进程已退出，跳过 R0 回退, pid="
                        << kTargetPid
                        << eol;
                }
            }
            if (!processExited)
            {
                constexpr const char* kR0TerminateMethodName =
                    "R0 TerminateProcess (KswordARK driver)";
                std::string r0DetailText;
                const bool kR0Ok = terminateProcessByR0Driver(
                    kTargetPid,
                    r0ActionExpectedCreationTime(actionTarget.record),
                    &r0DetailText);
                const std::string kNormalizedR0DetailText =
                    r0DetailText.empty() ? "无附加信息" : r0DetailText;
                (kR0Ok ? info : err) << actionEvent
                    << "[ProcessDock] 结束进程组合动作-方法执行, pid="
                    << kTargetPid
                    << ", round=R0"
                    << ", method="
                    << kR0TerminateMethodName
                    << ", ok="
                    << (kR0Ok ? "true" : "false")
                    << ", detail="
                    << kNormalizedR0DetailText
                    << eol;
                actionDetailStream
                    << " | R0:"
                    << kR0TerminateMethodName
                    << "="
                    << (kR0Ok ? "ok" : "fail")
                    << "("
                    << kNormalizedR0DetailText
                    << ")";
                if (kR0Ok)
                {
                    std::string r0ExitWaitDetail;
                    processExited = waitForProcessExitAfterSuccessfulTerminate(
                        kTargetPid,
                        &r0ExitWaitDetail);
                    actionDetailStream << " | wait=" << r0ExitWaitDetail;
                    if (processExited)
                    {
                        info << actionEvent
                            << "[ProcessDock] 成功方法等待目标进程退出完成, pid="
                            << kTargetPid
                            << ", round=R0"
                            << ", method="
                            << kR0TerminateMethodName
                            << ", wait="
                            << r0ExitWaitDetail
                            << eol;
                    }
                    else
                    {
                        warn << actionEvent
                            << "[ProcessDock] 成功方法等待 200ms 后目标仍未退出，组合链结束, pid="
                            << kTargetPid
                            << ", round=R0"
                            << ", method="
                            << kR0TerminateMethodName
                            << ", wait="
                            << r0ExitWaitDetail
                            << eol;
                    }
                }
                else
                {
                    warn << actionEvent
                        << "[ProcessDock] 当前方法执行失败，组合链结束, pid="
                        << kTargetPid
                        << ", round=R0"
                        << ", method="
                        << kR0TerminateMethodName
                        << eol;
                }
            }

            if (!processExited)
            {
                err << actionEvent
                    << "[ProcessDock] 结束进程组合动作达到上限后目标仍存活, pid="
                    << kTargetPid
                    << ", roundLimit="
                    << kTerminateRoundLimit
                    << eol;
            }

            if (detailTextOut != nullptr)
            {
                *detailTextOut = actionDetailStream.str();
            }
            if (!processExited || !deleteImageAfterExit)
            {
                return processExited;
            }

            std::string deletionDetail;
            const bool kDeletionOk = ks::process::deleteCapturedProcessImage(
                &capturedImageTarget,
                &deletionDetail);
            (kDeletionOk ? info : err) << actionEvent
                << "[ProcessDock] 目标进程退出后执行精确映像删除, pid="
                << kTargetPid
                << ", ok="
                << (kDeletionOk ? "true" : "false")
                << ", detail="
                << deletionDetail
                << eol;
            actionDetailStream << " | delete="
                << (kDeletionOk ? "ok" : "fail")
                << "("
                << deletionDetail
                << ")";
            if (detailTextOut != nullptr)
            {
                *detailTextOut = actionDetailStream.str();
            }
            return kDeletionOk;
        },
        true,
        true,
        true);
}
