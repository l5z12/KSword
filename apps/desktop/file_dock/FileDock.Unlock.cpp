#include "FileDock.Support.h"

using namespace ksword::ui::file_dock;

void FileDock::unlockSelectedItemsByDriver(FilePanelWidgets& panel)
{
    const std::vector<QString> kPaths = selectedPaths(panel);
    if (kPaths.empty())
    {
        return;
    }
    if (kPaths.size() != 1)
    {
        // The current file locker first scans for the source of the lock, then prompts the user to close the handle or terminate the process.
        // Under multiple paths, candidate handle/process relationships can get mixed up; batch operations are not provided to avoid accidentally terminating unrelated processes.
        KLogEvent event;
        info << event
            << "[FileDock] 文件解锁器取消：暂不支持多选, panel="
            << panel.panelNameText.toStdString()
            << ", selectedCount="
            << kPaths.size()
            << eol;
        return;
    }

    unlockPathsByDriver(kPaths, QStringLiteral("panel_context_menu"), &panel);
}

void FileDock::unlockPathsByDriver(
    const std::vector<QString>& targetPaths,
    const QString& triggerTag,
    FilePanelWidgets* panelForRefresh)
{
    std::vector<QString> paths;
    paths.reserve(targetPaths.size());
    for (const QString& path : targetPaths)
    {
        const QString kNormalizedPath = QDir::toNativeSeparators(path.trimmed());
        if (!kNormalizedPath.isEmpty())
        {
            paths.push_back(kNormalizedPath);
        }
    }
    if (paths.empty())
    {
        return;
    }

    // Legacy unlocker entry point directly to the unified lock/unlock page for file properties.
    // When the property window closes, use the shared cancellation flag to safely invalidate the scan callback.
    Q_UNUSED(triggerTag);
    Q_UNUSED(panelForRefresh);
    openHandleUsageScanWindow(paths);
    return;

    enum class RefreshTarget
    {
        kBoth = 0,
        kLeft,
        kRight
    };
    const RefreshTarget kRefreshTarget =
        (panelForRefresh == &leftPanel_) ? RefreshTarget::kLeft :
        (panelForRefresh == &rightPanel_) ? RefreshTarget::kRight :
        RefreshTarget::kBoth;

    struct UnlockJobResult
    {
        bool scanCompleted = false;
        QStringList scanDetailList;
        std::vector<UnlockProcessCandidate> processCandidateList;
        std::vector<UnlockHandleCandidate> handleCandidateList;
        UnlockOperationMode operationMode = UnlockOperationMode::kCloseHandleR3;
        std::vector<std::uint32_t> selectedProcessIdList;
        std::vector<UnlockHandleCandidate> selectedHandleList;
        std::size_t closeHandleSuccessCount = 0U;
        std::size_t terminateSuccessCount = 0U;
        QStringList operationFailList;
        QStringList skippedTargetList;
        QString driverErrorText;
    };

    {
        std::lock_guard<std::mutex> lock(unlockerWorkerMutex_);
        if (unlockerWorkerRunning_.load())
        {
            return;
        }
        if (unlockerWorkerThread_.joinable())
        {
            unlockerWorkerThread_.join();
        }
        unlockerWorkerStopRequested_.store(false);
        unlockerWorkerRunning_.store(true);
    }

    const int kProgressPid = kPro.add(this, "文件", "文件解锁器");
    kPro.set(kProgressPid, "准备扫描占用来源", 0, 5.0f);

    QPointer<FileDock> safeThis(this);
    {
        std::lock_guard<std::mutex> lock(unlockerWorkerMutex_);
        unlockerWorkerThread_ = std::thread([safeThis, paths, triggerTag, kRefreshTarget, kProgressPid, this]() {
        UnlockJobResult jobResult;
        const auto kMarkWorkerStopped = [this]() {
            this->unlockerWorkerRunning_.store(false);
            };
        const auto kStopRequested = [this]()
        {
            return this->unlockerWorkerStopRequested_.load();
        };

        kPro.set(kProgressPid, "扫描占用来源", 0, 35.0f);
        const filedock::handleusage::HandleUsageScanResult kScanResult =
            filedock::handleusage::scanHandleUsageByPaths(
                paths,
                kProgressPid,
                true,
                kStopRequested);
        if (kStopRequested())
        {
            kPro.set(kProgressPid, "用户取消", 0, 100.0f);
            kMarkWorkerStopped();
            return;
        }
        jobResult.scanCompleted = true;
        jobResult.scanDetailList.push_back(
            QStringLiteral("matched=%1, elapsedMs=%2, diagnostic=%3")
            .arg(kScanResult.matchedHandleCount)
            .arg(kScanResult.elapsedMs)
            .arg(kScanResult.diagnosticText.trimmed().isEmpty()
                ? QStringLiteral("-")
                : kScanResult.diagnosticText.simplified()));

        std::map<std::uint32_t, UnlockProcessCandidate> candidateByPid;
        const std::uint32_t kCurrentProcessId = static_cast<std::uint32_t>(::GetCurrentProcessId());
        for (const filedock::handleusage::HandleUsageEntry& entry : kScanResult.entries)
        {
            if (kStopRequested())
            {
                kPro.set(kProgressPid, "用户取消", 0, 100.0f);
                kMarkWorkerStopped();
                return;
            }
            if (entry.processId == 0U)
            {
                continue;
            }

            UnlockProcessCandidate& processCandidate = candidateByPid[entry.processId];
            processCandidate.processId = entry.processId;
            if (processCandidate.matchCount == 0U)
            {
                processCandidate.processCreationTime = entry.processCreationTime;
            }
            else if (processCandidate.processCreationTime != entry.processCreationTime)
            {
                // PID identity mismatch within the same scan round indicates the process has exited or been reused; zeroing ensures subsequent actions fail and close.
                processCandidate.processCreationTime = 0U;
            }
            if (processCandidate.processName.isEmpty() && !entry.processName.trimmed().isEmpty())
            {
                processCandidate.processName = entry.processName.trimmed();
            }
            if (processCandidate.processImagePath.isEmpty() && !entry.processImagePath.trimmed().isEmpty())
            {
                processCandidate.processImagePath = entry.processImagePath.trimmed();
            }
            appendUniqueText(processCandidate.matchedTargetList, entry.matchedTargetPath);
            appendUniqueText(processCandidate.matchRuleList, entry.matchRuleText);
            processCandidate.matchCount += 1U;
            processCandidate.isCurrentProcess = entry.processId == kCurrentProcessId;
            processCandidate.isCriticalProcess = entry.processId <= 4U || isCriticalProcessName(processCandidate.processName);

            UnlockHandleCandidate handleCandidate{};
            handleCandidate.processId = entry.processId;
            handleCandidate.processCreationTime = entry.processCreationTime;
            handleCandidate.processName = entry.processName.trimmed();
            handleCandidate.processImagePath = entry.processImagePath.trimmed();
            handleCandidate.handleValue = entry.handleValue;
            handleCandidate.grantedAccess = entry.grantedAccess;
            handleCandidate.matchedTargetPath = entry.matchedTargetPath;
            handleCandidate.matchedByDirectoryRule = entry.matchedByDirectoryRule;
            handleCandidate.matchRuleText = entry.matchRuleText;
            handleCandidate.objectName = entry.objectName;
            handleCandidate.enumerationSource = entry.enumerationSource;
            handleCandidate.isCurrentProcess = processCandidate.isCurrentProcess;
            handleCandidate.isCriticalProcess = processCandidate.isCriticalProcess;
            jobResult.handleCandidateList.push_back(handleCandidate);
        }

        jobResult.processCandidateList.reserve(candidateByPid.size());
        for (const auto& entry : candidateByPid)
        {
            if (kStopRequested())
            {
                kPro.set(kProgressPid, "用户取消", 0, 100.0f);
                kMarkWorkerStopped();
                return;
            }
            jobResult.processCandidateList.push_back(entry.second);
        }

        if (safeThis.isNull())
        {
            kPro.set(kProgressPid, "界面已关闭", 0, 100.0f);
            kMarkWorkerStopped();
            return;
        }

        UnlockSelectionResult selectionResult;
        const std::shared_ptr<UnlockSelectionSharedState> kSelectionState =
            std::make_shared<UnlockSelectionSharedState>();
        const bool kSelectionInvokeOk = QMetaObject::invokeMethod(
            safeThis.data(),
            [kSelectionState, safeThis, kProgressPid, jobResult]() {
                QWidget* const kUnlockerDialogParent = resolveVisibleDialogParent(safeThis.data());
                UnlockSelectionResult uiSelectionResult;
                if (safeThis.isNull())
                {
                    kPro.set(kProgressPid, "界面已关闭", 0, 100.0f);
                }
                else if (jobResult.processCandidateList.empty() && jobResult.handleCandidateList.empty())
                {
                    kPro.set(kProgressPid, "未发现占用来源", 0, 100.0f);
                }
                else
                {
                    uiSelectionResult = showUnlockSelectionDialog(
                        kUnlockerDialogParent,
                        jobResult.processCandidateList,
                        jobResult.handleCandidateList);
                }

                {
                    std::lock_guard<std::mutex> lock(kSelectionState->mutex);
                    kSelectionState->result = uiSelectionResult;
                    kSelectionState->completed = true;
                }

                kSelectionState->condition.notify_all();
            },
            Qt::QueuedConnection);
        if (!kSelectionInvokeOk)
        {
            kPro.set(kProgressPid, "回调失败", 0, 100.0f);
            kMarkWorkerStopped();
            return;
        }

        {
            std::unique_lock<std::mutex> lock(kSelectionState->mutex);
            while (!kSelectionState->completed)
            {
                if (safeThis.isNull() || this->unlockerWorkerStopRequested_.load())
                {
                    kPro.set(kProgressPid, "界面已关闭", 0, 100.0f);
                    kMarkWorkerStopped();
                    return;
                }

                kSelectionState->condition.wait_for(lock, std::chrono::milliseconds(100));
            }

            selectionResult = kSelectionState->result;
        }

        const bool kNoSelectedHandle = selectionResult.selectedHandleList.empty();
        const bool kNoSelectedProcess = selectionResult.selectedProcessIdList.empty();
        if (!selectionResult.accepted
            || (selectionResult.operationMode == UnlockOperationMode::kCloseHandleR3 && kNoSelectedHandle)
            || (selectionResult.operationMode != UnlockOperationMode::kCloseHandleR3 && kNoSelectedProcess))
        {
            kPro.set(kProgressPid, "用户取消", 0, 100.0f);
            kMarkWorkerStopped();
            return;
        }

        jobResult.operationMode = selectionResult.operationMode;
        jobResult.selectedHandleList = selectionResult.selectedHandleList;
        jobResult.selectedProcessIdList = selectionResult.selectedProcessIdList;
        kPro.set(kProgressPid, unlockOperationModeToText(jobResult.operationMode).toStdString(), 0, 55.0f);

        if (jobResult.operationMode == UnlockOperationMode::kCloseHandleR3)
        {
            const std::size_t kTotalHandleCount = jobResult.selectedHandleList.size();
            for (std::size_t index = 0; index < kTotalHandleCount; ++index)
            {
                if (safeThis.isNull() || this->unlockerWorkerStopRequested_.load())
                {
                    break;
                }

                const UnlockHandleCandidate& handleCandidate = jobResult.selectedHandleList[index];
                if (handleCandidate.processId <= 4U
                    || handleCandidate.handleValue == 0U
                    || handleCandidate.isCurrentProcess
                    || handleCandidate.isCriticalProcess)
                {
                    jobResult.skippedTargetList.push_back(
                        QStringLiteral("pid=%1 | handle=%2 | %3 | 已保护或无效，未关闭")
                        .arg(handleCandidate.processId)
                        .arg(formatHandleValueText(handleCandidate.handleValue))
                        .arg(handleCandidate.processName.isEmpty() ? QStringLiteral("Unknown") : handleCandidate.processName));
                    continue;
                }

                std::string detailText;
                const bool kCloseOk = ks::file::closeRemoteHandle(
                    handleCandidate.processId,
                    handleCandidate.handleValue,
                    handleCandidate.processCreationTime,
                    handleCandidate.matchedTargetPath.toStdWString(),
                    handleCandidate.matchedByDirectoryRule,
                    detailText);
                if (kCloseOk)
                {
                    jobResult.closeHandleSuccessCount += 1U;
                }
                else
                {
                    jobResult.operationFailList.push_back(
                        QStringLiteral("pid=%1 | handle=%2 | %3 | %4")
                        .arg(handleCandidate.processId)
                        .arg(formatHandleValueText(handleCandidate.handleValue))
                        .arg(handleCandidate.processName.isEmpty() ? QStringLiteral("Unknown") : handleCandidate.processName)
                        .arg(QString::fromStdString(detailText)));
                }

                const float kProgress =
                    55.0f + (static_cast<float>(index + 1) / static_cast<float>(kTotalHandleCount)) * 40.0f;
                kPro.set(kProgressPid, "关闭选中句柄", 0, kProgress);
            }
        }
        else
        {
            ksword::ark::DriverHandle driverHandle;
            if (jobResult.operationMode == UnlockOperationMode::kTerminateProcessR0)
            {
                std::string openDriverDetailText;
                driverHandle = openKswordArkDriverHandle(&openDriverDetailText);
                if (!driverHandle.isValid())
                {
                    jobResult.driverErrorText = QString::fromStdString(openDriverDetailText);
                }
            }

            std::map<std::uint32_t, UnlockProcessCandidate> candidateBySelectedPid;
            for (const UnlockProcessCandidate& candidate : jobResult.processCandidateList)
            {
                candidateBySelectedPid[candidate.processId] = candidate;
            }

            if (jobResult.operationMode == UnlockOperationMode::kTerminateProcessR0
                && !driverHandle.isValid())
            {
                jobResult.operationFailList.push_back(
                    QStringLiteral("R0 驱动连接失败：%1")
                    .arg(jobResult.driverErrorText));
            }
            else
            {
                const std::size_t kTotalProcessCount = jobResult.selectedProcessIdList.size();
                for (std::size_t index = 0; index < kTotalProcessCount; ++index)
                {
                    if (safeThis.isNull() || this->unlockerWorkerStopRequested_.load())
                    {
                        break;
                    }

                    const std::uint32_t kProcessId = jobResult.selectedProcessIdList[index];
                    const auto kCandidateIter = candidateBySelectedPid.find(kProcessId);
                    const QString kProcessName = (kCandidateIter != candidateBySelectedPid.end())
                        ? kCandidateIter->second.processName
                        : QString();
                    const std::uint64_t kProcessCreationTime = (kCandidateIter != candidateBySelectedPid.end())
                        ? kCandidateIter->second.processCreationTime
                        : 0U;
                    const bool kProtectedProcess = kCandidateIter != candidateBySelectedPid.end()
                        && (kCandidateIter->second.isCurrentProcess
                            || kCandidateIter->second.isCriticalProcess
                            || kCandidateIter->second.processCreationTime == 0U);
                    if (kProcessId <= 4U
                        || kProcessId == static_cast<std::uint32_t>(::GetCurrentProcessId())
                        || kProtectedProcess
                        || kProcessCreationTime == 0U)
                    {
                        jobResult.skippedTargetList.push_back(
                            QStringLiteral("pid=%1 | %2 | 已保护，未结束")
                            .arg(kProcessId)
                            .arg(kProcessName.isEmpty() ? QStringLiteral("Unknown") : kProcessName));
                        continue;
                    }

                    std::string detailText;
                    bool terminateOk = false;
                    if (jobResult.operationMode == UnlockOperationMode::kTerminateProcessR0)
                    {
                        // Even if terminated by the driver, first hold the R3 process handle verified for creation time;
                        // This ensures that during driver queries by PID, it does not hit another process object that has been reused.
                        HANDLE verifiedProcessHandle = nullptr;
                        if (ks::file::openProcessForVerifiedAction(
                                kProcessId,
                                kProcessCreationTime,
                                SYNCHRONIZE,
                                verifiedProcessHandle,
                                detailText))
                        {
                            terminateOk = terminateProcessByR0Driver(driverHandle, kProcessId, &detailText);
                            ::CloseHandle(verifiedProcessHandle);
                        }
                    }
                    else
                    {
                        terminateOk = terminateProcessByR3(
                            kProcessId,
                            kProcessCreationTime,
                            &detailText);
                    }
                    if (terminateOk)
                    {
                        jobResult.terminateSuccessCount += 1U;
                    }
                    else
                    {
                        jobResult.operationFailList.push_back(
                            QStringLiteral("pid=%1 | %2 | %3")
                            .arg(kProcessId)
                            .arg(kProcessName.isEmpty() ? QStringLiteral("Unknown") : kProcessName)
                            .arg(QString::fromStdString(detailText)));
                    }

                    const float kProgress =
                        55.0f + (static_cast<float>(index + 1) / static_cast<float>(kTotalProcessCount)) * 40.0f;
                    kPro.set(kProgressPid, "结束选中进程", 0, kProgress);
                }
            }

            driverHandle.reset();
        }

        if (safeThis.isNull())
        {
            kPro.set(kProgressPid, "界面已关闭", 0, 100.0f);
            kMarkWorkerStopped();
            return;
        }

        const bool kFinishInvokeOk = QMetaObject::invokeMethod(
            safeThis.data(),
            [safeThis, triggerTag, kRefreshTarget, kProgressPid, jobResult, paths, kMarkWorkerStopped]() {
                if (safeThis.isNull())
                {
                    kPro.set(kProgressPid, "界面已关闭", 0, 100.0f);
                    return;
                }

                QList<QAbstractItemView*> affectedViews;
                if (kRefreshTarget == RefreshTarget::kLeft)
                {
                    affectedViews.push_back(safeThis->leftPanel_.fileView);
                }
                else if (kRefreshTarget == RefreshTarget::kRight)
                {
                    affectedViews.push_back(safeThis->rightPanel_.fileView);
                }
                else
                {
                    affectedViews.push_back(safeThis->leftPanel_.fileView);
                    affectedViews.push_back(safeThis->rightPanel_.fileView);
                }
                const auto kRefreshPanels = [safeThis, kRefreshTarget]()
                {
                    if (safeThis.isNull())
                    {
                        return;
                    }
                    if (kRefreshTarget == RefreshTarget::kLeft)
                    {
                        safeThis->refreshPanel(safeThis->leftPanel_);
                    }
                    else if (kRefreshTarget == RefreshTarget::kRight)
                    {
                        safeThis->refreshPanel(safeThis->rightPanel_);
                    }
                    else
                    {
                        safeThis->refreshPanel(safeThis->leftPanel_);
                        safeThis->refreshPanel(safeThis->rightPanel_);
                    }
                };
                const QString kRefreshKey =
                    kRefreshTarget == RefreshTarget::kLeft
                    ? QStringLiteral("file-unlocker-panel-refresh-left")
                    : (kRefreshTarget == RefreshTarget::kRight
                        ? QStringLiteral("file-unlocker-panel-refresh-right")
                        : QStringLiteral("file-unlocker-panel-refresh-both"));
                if (!ks::ui::deferItemViewUiCommitIfContextMenuOpen(
                    safeThis.data(),
                    kRefreshKey,
                    affectedViews,
                    kRefreshPanels))
                {
                    kRefreshPanels();
                }

                const QString kModeText = unlockOperationModeToText(jobResult.operationMode);
                const std::size_t kSelectedCount = (jobResult.operationMode == UnlockOperationMode::kCloseHandleR3)
                    ? jobResult.selectedHandleList.size()
                    : jobResult.selectedProcessIdList.size();
                const std::size_t kSuccessCount = (jobResult.operationMode == UnlockOperationMode::kCloseHandleR3)
                    ? jobResult.closeHandleSuccessCount
                    : jobResult.terminateSuccessCount;
                KLogEvent event;
                if (!jobResult.operationFailList.isEmpty() || !jobResult.skippedTargetList.isEmpty())
                {
                    warn << event
                        << "[FileDock] 文件解锁器部分失败, panel="
                        << triggerTag.toStdString()
                        << ", mode="
                        << kModeText.toStdString()
                        << ", targetCount="
                        << paths.size()
                        << ", occupyProcessCount="
                        << jobResult.processCandidateList.size()
                        << ", handleRecordCount="
                        << jobResult.handleCandidateList.size()
                        << ", selectedCount="
                        << kSelectedCount
                        << ", successCount="
                        << kSuccessCount
                        << ", failCount="
                        << (jobResult.operationFailList.size() + jobResult.skippedTargetList.size())
                        << ", scanPreview=\n"
                        << buildLogPreviewText(jobResult.scanDetailList).toStdString()
                        << ", failPreview=\n"
                        << buildLogPreviewText(jobResult.operationFailList + jobResult.skippedTargetList).toStdString()
                        << eol;
                }
                else
                {
                    info << event
                        << "[FileDock] 文件解锁器完成, panel="
                        << triggerTag.toStdString()
                        << ", mode="
                        << kModeText.toStdString()
                        << ", targetCount="
                        << paths.size()
                        << ", occupyProcessCount="
                        << jobResult.processCandidateList.size()
                        << ", handleRecordCount="
                        << jobResult.handleCandidateList.size()
                        << ", selectedCount="
                        << kSelectedCount
                        << ", successCount="
                        << kSuccessCount
                        << eol;
                }

                kPro.set(kProgressPid, "文件解锁器完成", 0, 100.0f);
                kMarkWorkerStopped();
            },
            Qt::QueuedConnection);
        if (!kFinishInvokeOk)
        {
            kPro.set(kProgressPid, "回调失败", 0, 100.0f);
            kMarkWorkerStopped();
        }
        });
    }
}

void FileDock::unlockFileByPath(const QString& targetPath)
{
    const QString kNormalizedPath = QDir::toNativeSeparators(targetPath.trimmed());
    if (kNormalizedPath.isEmpty())
    {
        return;
    }

    unlockPathsByDriver(std::vector<QString>{ kNormalizedPath }, QStringLiteral("system_context_menu"), nullptr);
}
