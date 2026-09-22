#include "ProcessDetailWindow.InternalCommon.h"
#include "ProcessAffinityUtils.h"
#include "ProcessAffinityPersistence.h"

using namespace process_detail_window_internal;

namespace
{
    class ScopedDetailProcessIdentityHandle final
    {
    public:
        explicit ScopedDetailProcessIdentityHandle(HANDLE handleValue) : handle_(handleValue) {}
        ~ScopedDetailProcessIdentityHandle()
        {
            if (handle_ != nullptr)
            {
                ::CloseHandle(handle_);
            }
        }
        ScopedDetailProcessIdentityHandle(const ScopedDetailProcessIdentityHandle&) = delete;
        ScopedDetailProcessIdentityHandle& operator=(const ScopedDetailProcessIdentityHandle&) = delete;
    private:
        HANDLE handle_ = nullptr;
    };

    // invokeProcessActionForIdentity keeps a verified query handle open until
    // the synchronous R3 operation returns. Windows does not reuse the PID while
    // that process object is still referenced, so a stale detail window cannot
    // modify a later process instance.
    bool invokeProcessActionForIdentity(
        const std::uint32_t pid,
        const std::uint64_t expectedCreationTime100ns,
        const std::function<bool(std::string*)>& actionInvoker,
        std::string* const detailTextOut)
    {
        if (!actionInvoker)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "process action invoker is unavailable";
            }
            return false;
        }
        if (pid == 0U || expectedCreationTime100ns == 0U)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "process identity is unavailable; action skipped";
            }
            return false;
        }

        HANDLE rawProcessHandle = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (rawProcessHandle == nullptr)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) failed, error=" +
                    std::to_string(::GetLastError());
            }
            return false;
        }
        ScopedDetailProcessIdentityHandle processHandle(rawProcessHandle);

        FILETIME creationTime{};
        FILETIME exitTime{};
        FILETIME kernelTime{};
        FILETIME userTime{};
        if (!::GetProcessTimes(
                rawProcessHandle,
                &creationTime,
                &exitTime,
                &kernelTime,
                &userTime))
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "GetProcessTimes failed, error=" + std::to_string(::GetLastError());
            }
            return false;
        }
        const std::uint64_t kActualCreationTime100ns =
            (static_cast<std::uint64_t>(creationTime.dwHighDateTime) << 32U) |
            static_cast<std::uint64_t>(creationTime.dwLowDateTime);
        if (kActualCreationTime100ns == 0U || kActualCreationTime100ns != expectedCreationTime100ns)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "process identity changed (PID was reused); action skipped";
            }
            return false;
        }

        return actionInvoker(detailTextOut);
    }
}

// ============================================================
// ProcessDetailWindow.ActionAndUtil.cpp
// Purpose:
// - Responsible for action page operations (terminate/suspend/priority/inject) and utility functions.
// - Focus on 'execute action + result feedback + auxiliary formatting/search' logic.
// ============================================================

void ProcessDetailWindow::executeTerminateProcessAction()
{
    // TerminateProcess operation log: Use a single KLogEvent for the same action to ensure the call chain is traceable.
    KLogEvent actionEvent;
    warn << actionEvent
        << "[ProcessDetailWindow] executeTerminateProcessAction: pid="
        << baseRecord_.pid
        << eol;

    std::string detailText;
    const std::uint32_t kTargetPid = baseRecord_.pid;
    const bool kActionOk = invokeProcessActionForIdentity(
        kTargetPid,
        baseRecord_.creationTime100ns,
        [kTargetPid](std::string* detailTextOut)
        {
            return ks::process::terminateProcessByWin32(kTargetPid, detailTextOut);
        },
        &detailText);
    (kActionOk ? info : err) << actionEvent
        << "[ProcessDetailWindow] executeTerminateProcessAction: actionOk="
        << (kActionOk ? "true" : "false")
        << ", detail="
        << detailText
        << eol;
    showActionResultMessage("TerminateProcess", kActionOk, detailText, actionEvent);
}

void ProcessDetailWindow::executeTerminateThreadsAction()
{
    // Terminating all threads log: Use a single KLogEvent for the same action to ensure the call chain is traceable.
    KLogEvent actionEvent;
    warn << actionEvent
        << "[ProcessDetailWindow] executeTerminateThreadsAction: pid="
        << baseRecord_.pid
        << eol;

    std::string detailText;
    const std::uint32_t kTargetPid = baseRecord_.pid;
    const bool kActionOk = invokeProcessActionForIdentity(
        kTargetPid,
        baseRecord_.creationTime100ns,
        [kTargetPid](std::string* detailTextOut)
        {
            return ks::process::terminateAllThreadsByPid(kTargetPid, detailTextOut);
        },
        &detailText);
    (kActionOk ? info : err) << actionEvent
        << "[ProcessDetailWindow] executeTerminateThreadsAction: actionOk="
        << (kActionOk ? "true" : "false")
        << ", detail="
        << detailText
        << eol;
    showActionResultMessage("TerminateThread(全部线程)", kActionOk, detailText, actionEvent);
}

void ProcessDetailWindow::executeR0SuspendSelectedThreadAction()
{
    if (threadInspectTable_ == nullptr)
    {
        return;
    }

    const int kCurrentRow = threadInspectTable_->currentRow();
    const QTableWidgetItem* threadIdItem = kCurrentRow >= 0
        ? threadInspectTable_->item(kCurrentRow, toThreadColumnIndex(ThreadRowColumn::kThreadId))
        : nullptr;
    const std::size_t kCacheIndex = threadIdItem != nullptr
        ? static_cast<std::size_t>(threadIdItem->data(Qt::UserRole).toULongLong())
        : static_cast<std::size_t>(threadInspectRows_.size());
    if (kCacheIndex >= threadInspectRows_.size())
    {
        return;
    }

    const ThreadInspectItem kSelectedThread = threadInspectRows_[kCacheIndex];
    const std::uint32_t kProcessId = kSelectedThread.processId != 0U
        ? kSelectedThread.processId
        : baseRecord_.pid;
    if (kProcessId <= 4U || kSelectedThread.threadId == 0U)
    {
        return;
    }

    const QMessageBox::StandardButton kConfirmation = QMessageBox::warning(
        this,
        ks::i18n::contextText(
            QStringLiteral("process.thread.r0_suspend.confirm.title"),
            QStringLiteral("R0挂起线程")),
        ks::i18n::contextText(
            QStringLiteral("process.thread.r0_suspend.confirm.body"),
            QStringLiteral("将通过 R0 挂起 PID %2 的线程 %1。目标程序可能失去响应，是否继续？"))
            .arg(kSelectedThread.threadId)
            .arg(kProcessId),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kConfirmation != QMessageBox::Yes)
    {
        return;
    }

    KLogEvent actionEvent;
    const ksword::ark::DriverClient kDriverClient;
    const ksword::ark::IoResult kResult = kDriverClient.setThreadSuspended(
        kSelectedThread.threadId,
        kProcessId,
        true);
    (kResult.ok ? info : err) << actionEvent
        << "[ProcessDetailWindow] executeR0SuspendSelectedThreadAction: pid="
        << kProcessId
        << ", tid="
        << kSelectedThread.threadId
        << ", actionOk="
        << (kResult.ok ? "true" : "false")
        << ", detail="
        << kResult.message
        << eol;
    showActionResultMessage(
        ks::i18n::contextText(
            QStringLiteral("process.thread.r0_suspend.result.title"),
            QStringLiteral("R0挂起线程")),
        kResult.ok,
        kResult.message,
        actionEvent);
    requestAsyncThreadInspectRefresh();
}

void ProcessDetailWindow::executeR0ResumeSelectedThreadAction()
{
    if (threadInspectTable_ == nullptr)
    {
        return;
    }

    const int kCurrentRow = threadInspectTable_->currentRow();
    const QTableWidgetItem* threadIdItem = kCurrentRow >= 0
        ? threadInspectTable_->item(kCurrentRow, toThreadColumnIndex(ThreadRowColumn::kThreadId))
        : nullptr;
    const std::size_t kCacheIndex = threadIdItem != nullptr
        ? static_cast<std::size_t>(threadIdItem->data(Qt::UserRole).toULongLong())
        : static_cast<std::size_t>(threadInspectRows_.size());
    if (kCacheIndex >= threadInspectRows_.size())
    {
        return;
    }

    const ThreadInspectItem& selectedThread = threadInspectRows_[kCacheIndex];
    const std::uint32_t kProcessId = selectedThread.processId != 0U
        ? selectedThread.processId
        : baseRecord_.pid;
    if (kProcessId <= 4U || selectedThread.threadId == 0U)
    {
        return;
    }

    KLogEvent actionEvent;
    const ksword::ark::DriverClient kDriverClient;
    const ksword::ark::IoResult kResult = kDriverClient.setThreadSuspended(
        selectedThread.threadId,
        kProcessId,
        false);
    (kResult.ok ? info : err) << actionEvent
        << "[ProcessDetailWindow] executeR0ResumeSelectedThreadAction: pid="
        << kProcessId
        << ", tid="
        << selectedThread.threadId
        << ", actionOk="
        << (kResult.ok ? "true" : "false")
        << ", detail="
        << kResult.message
        << eol;
    showActionResultMessage(
        ks::i18n::contextText(
            QStringLiteral("process.thread.r0_resume.result.title"),
            QStringLiteral("R0恢复线程")),
        kResult.ok,
        kResult.message,
        actionEvent);
    requestAsyncThreadInspectRefresh();
}

void ProcessDetailWindow::executeDriverThreadAction(
    const unsigned long action,
    const unsigned long terminateMethod)
{
    if (threadInspectTable_ == nullptr)
    {
        return;
    }

    const int kCurrentRow = threadInspectTable_->currentRow();
    const QTableWidgetItem* threadIdItem = kCurrentRow >= 0
        ? threadInspectTable_->item(kCurrentRow, toThreadColumnIndex(ThreadRowColumn::kThreadId))
        : nullptr;
    const std::size_t kCacheIndex = threadIdItem != nullptr
        ? static_cast<std::size_t>(threadIdItem->data(Qt::UserRole).toULongLong())
        : static_cast<std::size_t>(threadInspectRows_.size());
    if (kCacheIndex >= threadInspectRows_.size())
    {
        return;
    }

    const ThreadInspectItem& selectedThread = threadInspectRows_[kCacheIndex];
    const std::uint64_t kStartAddress = selectedThread.startAddress != 0ULL
        ? selectedThread.startAddress
        : selectedThread.win32StartAddress;
    if (baseRecord_.pid != 4U || selectedThread.threadId == 0U ||
        kStartAddress == 0ULL || selectedThread.createTime100ns == 0ULL)
    {
        return;
    }

    QString resultTitle;
    if (action == KSWORD_ARK_DRIVER_THREAD_ACTION_SUSPEND)
    {
        resultTitle = ks::i18n::contextText(
            QStringLiteral("process.thread.driver_suspend.result.title"),
            QStringLiteral("挂起驱动线程"));
        const QMessageBox::StandardButton kConfirmation = QMessageBox::critical(
            this,
            ks::i18n::contextText(
                QStringLiteral("process.thread.driver_suspend.confirm.title"),
                QStringLiteral("挂起驱动线程")),
            ks::i18n::contextText(
                QStringLiteral("process.thread.driver_suspend.confirm.body"),
                QStringLiteral("即将挂起 System(PID 4) 的驱动线程 %1。此操作可能冻结磁盘、网络或安全组件，并可能导致系统死锁或蓝屏。仅在已保存工作且可强制重启时继续。"))
                .arg(selectedThread.threadId),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
        if (kConfirmation != QMessageBox::Yes)
        {
            return;
        }
    }
    else if (action == KSWORD_ARK_DRIVER_THREAD_ACTION_RESUME)
    {
        resultTitle = ks::i18n::contextText(
            QStringLiteral("process.thread.driver_resume.result.title"),
            QStringLiteral("恢复驱动线程"));
    }
    else if (action == KSWORD_ARK_DRIVER_THREAD_ACTION_TERMINATE)
    {
        switch (terminateMethod)
        {
        case KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_PSP_BY_POINTER:
        case KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_ZW_OR_NT:
        case KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_NORMAL_APC:
        case KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_SPECIAL_TO_NORMAL_APC:
            break;
        default:
            return;
        }
        resultTitle = ks::i18n::contextText(
            QStringLiteral("process.thread.driver_terminate.result.title"),
            QStringLiteral("强制结束驱动线程"));
    }
    else
    {
        return;
    }

    KLogEvent actionEvent;
    const ksword::ark::DriverClient kDriverClient;
    const ksword::ark::IoResult kResult = kDriverClient.controlDriverThread(
        selectedThread.threadId,
        kStartAddress,
        selectedThread.createTime100ns,
        action,
        terminateMethod,
        action != KSWORD_ARK_DRIVER_THREAD_ACTION_RESUME);
    (kResult.ok ? info : err) << actionEvent
        << "[ProcessDetailWindow] executeDriverThreadAction: tid="
        << selectedThread.threadId
        << ", action="
        << action
        << ", terminateMethod="
        << terminateMethod
        << ", actionOk="
        << (kResult.ok ? "true" : "false")
        << ", detail="
        << kResult.message
        << eol;
    showActionResultMessage(resultTitle, kResult.ok, kResult.message, actionEvent);
    requestAsyncThreadInspectRefresh();
}

void ProcessDetailWindow::executeExperimentalFirmwareRebootAction()
{
    const QMessageBox::StandardButton kFirstConfirmation = QMessageBox::critical(
        this,
        ks::i18n::contextText(
            QStringLiteral("process.thread.hal_return.confirm.title"),
            QStringLiteral("HalReturnToFirmware 实验性整机动作")),
        ks::i18n::contextText(
            QStringLiteral("process.thread.hal_return.confirm.body"),
            QStringLiteral("HalReturnToFirmware(HalRebootRoutine) 不是线程终止 API，而是不受支持的整机固件返回动作。它会绕过所选线程和进程保护，可能立即重启、丢失所有未保存数据，或在当前平台失败/崩溃。是否进入最终确认？")),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kFirstConfirmation != QMessageBox::Yes)
    {
        return;
    }
    const QMessageBox::StandardButton kFinalConfirmation = QMessageBox::critical(
        this,
        ks::i18n::contextText(
            QStringLiteral("process.thread.hal_return.final.title"),
            QStringLiteral("最终确认：立即调用原始 API")),
        ks::i18n::contextText(
            QStringLiteral("process.thread.hal_return.final.body"),
            QStringLiteral("最后确认：立即调用 HalReturnToFirmware(HalRebootRoutine)。成功时系统不会返回本程序。")),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kFinalConfirmation != QMessageBox::Yes)
    {
        return;
    }

    KLogEvent actionEvent;
    const ksword::ark::DriverClient kDriverClient;
    const ksword::ark::IoResult kResult = kDriverClient.experimentalReturnToFirmware();
    (kResult.ok ? warn : err) << actionEvent
        << "[ProcessDetailWindow] executeExperimentalFirmwareRebootAction: actionOk="
        << (kResult.ok ? "true" : "false")
        << ", detail=" << kResult.message
        << eol;
    showActionResultMessage(
        ks::i18n::contextText(
            QStringLiteral("process.thread.hal_return.result.title"),
            QStringLiteral("HalReturnToFirmware 实验性整机动作")),
        kResult.ok,
        kResult.message,
        actionEvent);
}

void ProcessDetailWindow::executeR0TerminateSelectedThreadAction()
{
    if (threadInspectTable_ == nullptr)
    {
        return;
    }

    const int kCurrentRow = threadInspectTable_->currentRow();
    const QTableWidgetItem* threadIdItem = kCurrentRow >= 0
        ? threadInspectTable_->item(kCurrentRow, toThreadColumnIndex(ThreadRowColumn::kThreadId))
        : nullptr;
    const std::size_t kCacheIndex = threadIdItem != nullptr
        ? static_cast<std::size_t>(threadIdItem->data(Qt::UserRole).toULongLong())
        : static_cast<std::size_t>(threadInspectRows_.size());
    if (kCacheIndex >= threadInspectRows_.size())
    {
        return;
    }

    const ThreadInspectItem& selectedThread = threadInspectRows_[kCacheIndex];
    const std::uint32_t kProcessId = selectedThread.processId != 0U
        ? selectedThread.processId
        : baseRecord_.pid;
    if (kProcessId <= 4U || selectedThread.threadId == 0U)
    {
        return;
    }

    KLogEvent actionEvent;
    const ksword::ark::DriverClient kDriverClient;
    const ksword::ark::IoResult kResult = kDriverClient.terminateThread(
        selectedThread.threadId,
        kProcessId,
        static_cast<long>(0xC0000005u));
    (kResult.ok ? info : err) << actionEvent
        << "[ProcessDetailWindow] executeR0TerminateSelectedThreadAction: pid="
        << kProcessId
        << ", tid="
        << selectedThread.threadId
        << ", actionOk="
        << (kResult.ok ? "true" : "false")
        << ", detail="
        << kResult.message
        << eol;
    showActionResultMessage(
        ks::i18n::contextText(
            QStringLiteral("process.thread.r0_terminate.result.title"),
            QStringLiteral("R0结束线程")),
        kResult.ok,
        kResult.message,
        actionEvent);
    requestAsyncThreadInspectRefresh();
}

void ProcessDetailWindow::executeSelectedTerminateAction()
{
    if (terminateActionCombo_ == nullptr)
    {
        KLogEvent terminateComboNullEvent;
        err << terminateComboNullEvent
            << "[ProcessDetailWindow] executeSelectedTerminateAction: m_terminateActionCombo 为空。"
            << eol;
        return;
    }

    // End action dispatch:
    // - The combo box is responsible only for selecting the strategy
    // - The actual execution still reuses existing action functions to ensure the log chain and behavior remain unchanged.
    const int kActionId = terminateActionCombo_->currentData().toInt();
    switch (kActionId)
    {
    case 0:
        executeTerminateProcessAction();
        break;
    case 1:
        executeTerminateThreadsAction();
        break;
    case 2:
        executeTerminateProcessComboAction();
        break;
    default:
    {
        KLogEvent invalidTerminateActionEvent;
        warn << invalidTerminateActionEvent
            << "[ProcessDetailWindow] executeSelectedTerminateAction: 未知 actionId="
            << kActionId
            << eol;
        break;
    }
    }
}

void ProcessDetailWindow::executeSuspendProcessAction()
{
    // Suspend process log: use a single KLogEvent per action to ensure the call chain is traceable.
    KLogEvent actionEvent;
    info << actionEvent
        << "[ProcessDetailWindow] executeSuspendProcessAction: pid="
        << baseRecord_.pid
        << eol;

    std::string detailText;
    const bool kActionOk = ks::process::suspendProcessIfCreationTimeMatches(baseRecord_.pid, baseRecord_.creationTime100ns, &detailText);
    (kActionOk ? info : err) << actionEvent
        << "[ProcessDetailWindow] executeSuspendProcessAction: actionOk="
        << (kActionOk ? "true" : "false")
        << ", detail="
        << detailText
        << eol;
    showActionResultMessage("挂起进程", kActionOk, detailText, actionEvent);
}

void ProcessDetailWindow::executeResumeProcessAction()
{
    // Process resume logging: use a single KLogEvent for the same action to ensure call chain traceability.
    KLogEvent actionEvent;
    info << actionEvent
        << "[ProcessDetailWindow] executeResumeProcessAction: pid="
        << baseRecord_.pid
        << eol;

    std::string detailText;
    const bool kActionOk = ks::process::resumeProcessIfCreationTimeMatches(baseRecord_.pid, baseRecord_.creationTime100ns, &detailText);
    (kActionOk ? info : err) << actionEvent
        << "[ProcessDetailWindow] executeResumeProcessAction: actionOk="
        << (kActionOk ? "true" : "false")
        << ", detail="
        << detailText
        << eol;
    showActionResultMessage("恢复进程", kActionOk, detailText, actionEvent);
}

void ProcessDetailWindow::executeSetCriticalAction(const bool enableCritical)
{
    // Critical process flag change log: a single KLogEvent is used for the same action to ensure call chain traceability.
    KLogEvent actionEvent;
    warn << actionEvent
        << "[ProcessDetailWindow] executeSetCriticalAction: pid="
        << baseRecord_.pid
        << ", enableCritical="
        << (enableCritical ? "true" : "false")
        << eol;

    std::string detailText;
    const std::uint32_t kTargetPid = baseRecord_.pid;
    const bool kActionOk = invokeProcessActionForIdentity(
        kTargetPid,
        baseRecord_.creationTime100ns,
        [kTargetPid, enableCritical](std::string* detailTextOut)
        {
            return ks::process::setProcessCriticalFlag(kTargetPid, enableCritical, detailTextOut);
        },
        &detailText);
    (kActionOk ? info : err) << actionEvent
        << "[ProcessDetailWindow] executeSetCriticalAction: actionOk="
        << (kActionOk ? "true" : "false")
        << ", detail="
        << detailText
        << eol;
    showActionResultMessage(enableCritical ? "设为关键进程" : "取消关键进程", kActionOk, detailText, actionEvent);
}

void ProcessDetailWindow::executeSetPriorityAction()
{
    if (priorityCombo_ == nullptr)
    {
        KLogEvent priorityComboNullEvent;
        err << priorityComboNullEvent
            << "[ProcessDetailWindow] executeSetPriorityAction: m_priorityCombo 为空。"
            << eol;
        return;
    }

    const int kActionId = priorityCombo_->currentData().toInt();
    ks::process::ProcessPriorityLevel priorityLevel = ks::process::ProcessPriorityLevel::kNormal;
    switch (kActionId)
    {
    case 0: priorityLevel = ks::process::ProcessPriorityLevel::kIdle; break;
    case 1: priorityLevel = ks::process::ProcessPriorityLevel::kBelowNormal; break;
    case 2: priorityLevel = ks::process::ProcessPriorityLevel::kNormal; break;
    case 3: priorityLevel = ks::process::ProcessPriorityLevel::kAboveNormal; break;
    case 4: priorityLevel = ks::process::ProcessPriorityLevel::kHigh; break;
    case 5: priorityLevel = ks::process::ProcessPriorityLevel::kRealtime; break;
    default: priorityLevel = ks::process::ProcessPriorityLevel::kNormal; break;
    }

    // Priority setting log: use a single KLogEvent for the same action to ensure the call chain is traceable.
    KLogEvent actionEvent;
    info << actionEvent
        << "[ProcessDetailWindow] executeSetPriorityAction: pid="
        << baseRecord_.pid
        << ", actionId="
        << kActionId
        << eol;

    std::string detailText;
    const std::uint32_t kTargetPid = baseRecord_.pid;
    const bool kActionOk = invokeProcessActionForIdentity(
        kTargetPid,
        baseRecord_.creationTime100ns,
        [kTargetPid, priorityLevel](std::string* detailTextOut)
        {
            return ks::process::setProcessPriority(kTargetPid, priorityLevel, detailTextOut);
        },
        &detailText);
    (kActionOk ? info : err) << actionEvent
        << "[ProcessDetailWindow] executeSetPriorityAction: actionOk="
        << (kActionOk ? "true" : "false")
        << ", detail="
        << detailText
        << eol;
    showActionResultMessage("设置进程优先级", kActionOk, detailText, actionEvent);
}

void ProcessDetailWindow::refreshActionAffinityControls()
{
    // Affinity reading is performed on-demand only on the operation page, using a cross-node CPU set snapshot.
    ks::process::ProcessAffinitySnapshot affinitySnapshot;
    std::string detailText;
    const bool kQueryOk = ks::process::queryProcessAffinityState(
        static_cast<DWORD>(baseRecord_.pid),
        &affinitySnapshot,
        &detailText);
    actionAffinityReadable_ = kQueryOk;
    actionAffinitySnapshot_ = kQueryOk
        ? std::move(affinitySnapshot)
        : ks::process::ProcessAffinitySnapshot{};
    rebuildActionAffinityCoreButtons();
    updateActionAffinityCoreButtons();
    refreshActionAffinityPersistenceControl();

    if (affinityStatusLabel_ == nullptr)
    {
        return;
    }

    if (!kQueryOk)
    {
        KLogEvent queryEvent;
        warn << queryEvent
            << "[ProcessDetailWindow] CPU affinity query failed, pid="
            << baseRecord_.pid
            << ", detail="
            << (detailText.empty() ? "none" : detailText)
            << eol;
        affinityStatusLabel_->setText(
            ks::i18n::text(
                QStringLiteral("process.detail.affinity.status.unavailable"),
                QString()));
        affinityStatusLabel_->setStyleSheet(buildStateLabelStyle(statusWarningColor(), 700));
        return;
    }

    std::size_t availableProcessorCount = 0U;
    std::size_t selectedProcessorCount = 0U;
    std::size_t constrainedProcessorCount = 0U;
    for (const ks::process::LogicalProcessorState& processor :
         actionAffinitySnapshot_.processors)
    {
        if (processor.available)
        {
            ++availableProcessorCount;
            if (processor.selected)
            {
                ++selectedProcessorCount;
            }
        }
        if (processor.constrainedByHardAffinity)
        {
            ++constrainedProcessorCount;
        }
    }
    const QString kModeText = ks::i18n::text(
        actionAffinitySnapshot_.usesCpuSets
            ? QStringLiteral("process.detail.affinity.mode.cpu_sets")
            : QStringLiteral("process.detail.affinity.mode.legacy"),
        QString());
    QString affinityStatusText = ks::i18n::text(
            QStringLiteral("process.detail.affinity.status.current"),
            QString())
            .arg(kModeText)
            .arg(selectedProcessorCount)
            .arg(availableProcessorCount);
    if (constrainedProcessorCount != 0U)
    {
        affinityStatusText += ks::i18n::text(
            QStringLiteral(
                "process.detail.affinity.status.constraint_suffix"),
            QString())
            .arg(constrainedProcessorCount);
    }
    affinityStatusLabel_->setText(affinityStatusText);
    affinityStatusLabel_->setStyleSheet(buildStateLabelStyle(statusIdleColor(), 600));
}

bool ProcessDetailWindow::confirmActionAffinityRisk(
    const bool persistenceSave)
{
    const QMessageBox::StandardButton kConfirmation =
        QMessageBox::warning(
            this,
            ks::i18n::text(
                QStringLiteral("process.affinity.risk.title"),
                QString()),
            ks::i18n::text(
                persistenceSave
                    ? QStringLiteral("process.affinity.risk.save")
                    : QStringLiteral("process.affinity.risk.apply"),
                QString()),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
    return kConfirmation == QMessageBox::Yes;
}

void ProcessDetailWindow::applyActionAffinityRule(
    const ks::process::ProcessAffinityRule& affinityRule)
{
    if (!actionAffinityReadable_ ||
        (!affinityRule.selectAllAvailable &&
            affinityRule.processors.empty()))
    {
        refreshActionAffinityControls();
        return;
    }
    const bool kPersistenceEnabled =
        affinityPersistenceCheckBox_ != nullptr &&
        affinityPersistenceCheckBox_->isChecked();
    if (!confirmActionAffinityRisk(kPersistenceEnabled))
    {
        updateActionAffinityCoreButtons();
        return;
    }

    QStringList requestedProcessorTexts;
    if (affinityRule.selectAllAvailable)
    {
        requestedProcessorTexts <<
            ks::i18n::text(
                QStringLiteral("process.detail.affinity.all_cores"),
                QString());
    }
    else
    {
        for (const ks::process::LogicalProcessorCoordinate& coordinate :
             affinityRule.processors)
        {
            requestedProcessorTexts <<
                QString::fromStdString(
                    ks::process::processorIdentityText(coordinate));
        }
    }

    std::string detailText;
    const std::uint32_t kTargetPid = baseRecord_.pid;
    const bool kSetOk = invokeProcessActionForIdentity(
        kTargetPid,
        baseRecord_.creationTime100ns,
        [kTargetPid, &affinityRule](std::string* detailTextOut)
        {
            return ks::process::setProcessAffinityRuleByPid(
                static_cast<DWORD>(kTargetPid),
                affinityRule,
                detailTextOut);
        },
        &detailText);
    KLogEvent actionEvent;
    (kSetOk ? info : warn) << actionEvent
        << "[ProcessDetailWindow] CPU affinity update, pid="
        << baseRecord_.pid
        << ", requested="
        << requestedProcessorTexts.join(',').toStdString()
        << ", ok="
        << (kSetOk ? "true" : "false")
        << ", detail="
        << (detailText.empty() ? "none" : detailText)
        << eol;

    if (!kSetOk)
    {
        if (affinityStatusLabel_ != nullptr)
        {
            affinityStatusLabel_->setText(
                ks::i18n::text(
                    QStringLiteral("process.detail.affinity.status.update_failed"),
                    QString()));
            affinityStatusLabel_->setStyleSheet(buildStateLabelStyle(statusWarningColor(), 700));
        }
        updateActionAffinityCoreButtons();
        return;
    }

    bool persistenceOk = true;
    std::string persistenceDetailText;
    if (kPersistenceEnabled)
    {
        persistenceOk = ks::process::savePersistedProcessAffinityRule(
                baseRecord_.imagePath,
                affinityRule,
                &persistenceDetailText);
        if (!persistenceOk)
        {
            const QSignalBlocker kSignalBlocker(affinityPersistenceCheckBox_);
            affinityPersistenceCheckBox_->setChecked(false);
            KLogEvent persistenceEvent;
            warn << persistenceEvent
                << "[ProcessDetailWindow] CPU affinity persistence update failed, pid="
                << baseRecord_.pid
                << ", detail=" << persistenceDetailText << eol;
        }
    }
    refreshActionAffinityControls();
    if (affinityStatusLabel_ != nullptr)
    {
        affinityStatusLabel_->setText(
            persistenceOk
                ? ks::i18n::text(
                    QStringLiteral("process.detail.affinity.status.updated"),
                    QString())
                : ks::i18n::text(
                    QStringLiteral(
                        "process.detail.affinity.persistence.save_failed"),
                    QString()));
        affinityStatusLabel_->setStyleSheet(buildStateLabelStyle(
            persistenceOk ? statusIdleColor() : statusWarningColor(),
            persistenceOk ? 600 : 700));
    }
}

void ProcessDetailWindow::refreshActionAffinityPersistenceControl()
{
    if (affinityPersistenceCheckBox_ == nullptr)
    {
        return;
    }

    ks::process::ProcessAffinityRule storedRule;
    bool ruleFound = false;
    std::string detailText;
    const std::uint16_t kLegacyGroupHint =
        actionAffinityReadable_
            ? ks::process::inferLegacyAffinityGroup(
                actionAffinitySnapshot_)
            : 0U;
    const bool kReadOk =
        ks::process::loadPersistedProcessAffinityRule(
        baseRecord_.imagePath,
        &storedRule,
        &ruleFound,
        &detailText,
        kLegacyGroupHint);
    const QSignalBlocker kSignalBlocker(affinityPersistenceCheckBox_);
    affinityPersistenceCheckBox_->setEnabled(
        kReadOk &&
        actionAffinityReadable_ &&
        !baseRecord_.imagePath.empty());
    affinityPersistenceCheckBox_->setChecked(kReadOk && ruleFound);
    affinityPersistenceCheckBox_->setToolTip(
        ks::i18n::text(
            QStringLiteral("process.detail.affinity.persistence.tooltip"),
            QString()));
    if (!kReadOk)
    {
        KLogEvent persistenceReadEvent;
        warn << persistenceReadEvent
            << "[ProcessDetailWindow] CPU affinity persistence query failed, pid="
            << baseRecord_.pid
            << ", detail="
            << (detailText.empty() ? "none" : detailText)
            << eol;
    }
}

void ProcessDetailWindow::toggleActionAffinityCore(
    const ks::process::LogicalProcessorCoordinate& coordinate,
    const bool enabled)
{
    if (!actionAffinityReadable_)
    {
        refreshActionAffinityControls();
        return;
    }

    const auto kTargetProcessorIt = std::find_if(
        actionAffinitySnapshot_.processors.begin(),
        actionAffinitySnapshot_.processors.end(),
        [&coordinate](const ks::process::LogicalProcessorState& processor)
        {
            return processor.coordinate == coordinate &&
                processor.available;
        });
    if (kTargetProcessorIt ==
        actionAffinitySnapshot_.processors.end())
    {
        updateActionAffinityCoreButtons();
        return;
    }

    ks::process::ProcessAffinityRule nextRule;
    if (actionAffinitySnapshot_.unrestricted)
    {
        for (const ks::process::LogicalProcessorState& processor :
             actionAffinitySnapshot_.processors)
        {
            if (processor.available)
            {
                nextRule.processors.push_back(
                    processor.coordinate);
            }
        }
    }
    else
    {
        nextRule = ks::process::affinityRuleFromSnapshot(
            actionAffinitySnapshot_);
    }

    if (enabled)
    {
        nextRule.processors.push_back(coordinate);
    }
    else
    {
        nextRule.processors.erase(
            std::remove(
                nextRule.processors.begin(),
                nextRule.processors.end(),
                coordinate),
            nextRule.processors.end());
    }
    nextRule.selectAllAvailable = false;
    ks::process::normalizeLogicalProcessorCoordinates(
        &nextRule.processors);
    if (nextRule.processors.empty())
    {
        updateActionAffinityCoreButtons();
        if (affinityStatusLabel_ != nullptr)
        {
            affinityStatusLabel_->setText(
                ks::i18n::text(QStringLiteral("process.detail.affinity.status.last_core"), QString()));
            affinityStatusLabel_->setStyleSheet(buildStateLabelStyle(statusWarningColor(), 700));
        }
        return;
    }
    applyActionAffinityRule(nextRule);
}

void ProcessDetailWindow::updateActionAffinityCoreButtons()
{
    const std::size_t kProcessorCount = std::min(
        affinityCoreButtons_.size(),
        actionAffinitySnapshot_.processors.size());
    for (std::size_t processorIndex = 0U;
         processorIndex < kProcessorCount;
         ++processorIndex)
    {
        QToolButton* const kCoreButton =
            affinityCoreButtons_[processorIndex];
        if (kCoreButton == nullptr)
        {
            continue;
        }
        const ks::process::LogicalProcessorState& processor =
            actionAffinitySnapshot_.processors[processorIndex];
        const bool kAvailable =
            actionAffinityReadable_ && processor.available;
        const QSignalBlocker kSignalBlocker(kCoreButton);
        kCoreButton->setEnabled(kAvailable);
        kCoreButton->setChecked(
            kAvailable && processor.selected);
    }
    if (affinityAllCoresButton_ != nullptr)
    {
        const bool kHasAvailableProcessor = std::any_of(
            actionAffinitySnapshot_.processors.begin(),
            actionAffinitySnapshot_.processors.end(),
            [](const ks::process::LogicalProcessorState& processor)
            {
                return processor.available;
            });
        affinityAllCoresButton_->setEnabled(
            actionAffinityReadable_ && kHasAvailableProcessor);
    }
}

void ProcessDetailWindow::executeInjectDllAction()
{
    const QString kDllPath = dllPathLineEdit_->text().trimmed();
    const bool kUseR0Injection =
        injectionModeCombo_ != nullptr &&
        injectionModeCombo_->currentData().toInt() == 1;
    if (kDllPath.isEmpty())
    {
        KLogEvent injectDllEmptyPathEvent;
        warn << injectDllEmptyPathEvent
            << "[ProcessDetailWindow] executeInjectDllAction: DLL 路径为空。"
            << eol;
        QMessageBox::warning(this, "DLL 注入", "请先选择 DLL 文件。");
        return;
    }

    // DLL injection log: A single KLogEvent is used for the same action to ensure the call chain is traceable.
    KLogEvent actionEvent;
    info << actionEvent
        << "[ProcessDetailWindow] executeInjectDllAction: pid="
        << baseRecord_.pid
        << ", mode="
        << (kUseR0Injection ? "R0" : "R3")
        << ", dllPath="
        << kDllPath.toStdString()
        << eol;

    std::string detailText;
    const std::uint32_t kTargetPid = baseRecord_.pid;
    bool actionOk = false;
    if (kUseR0Injection)
    {
        ksword::ark::DriverClient driverClient;
        const ksword::ark::ProcessInjectResult kInjectResult =
            driverClient.injectProcessDll(
                static_cast<std::uint32_t>(baseRecord_.pid),
                kDllPath.toStdWString());
        detailText = kInjectResult.io.message;
        actionOk =
            kInjectResult.io.ok &&
            kInjectResult.status == KSWORD_ARK_PROCESS_INJECT_STATUS_INJECTED;
    }
    else
    {
        const std::string kDllPathUtf8 = kDllPath.toStdString();
        actionOk = invokeProcessActionForIdentity(
            kTargetPid,
            baseRecord_.creationTime100ns,
            [kTargetPid, kDllPathUtf8](std::string* detailTextOut)
            {
                return ks::process::injectDllByPath(kTargetPid, kDllPathUtf8, detailTextOut);
            },
            &detailText);
    }
    (actionOk ? info : err) << actionEvent
        << "[ProcessDetailWindow] executeInjectDllAction: actionOk="
        << (actionOk ? "true" : "false")
        << ", detail="
        << detailText
        << eol;
    showActionResultMessage(kUseR0Injection ? QStringLiteral("DLL 注入(R0)") : QStringLiteral("DLL 注入"), actionOk, detailText, actionEvent);
    if (actionOk)
    {
        requestAsyncModuleRefresh(true);
    }
}

void ProcessDetailWindow::executeInjectShellcodeAction()
{
    const QString kShellcodePath = shellcodePathLineEdit_->text().trimmed();
    const bool kUseR0Injection =
        injectionModeCombo_ != nullptr &&
        injectionModeCombo_->currentData().toInt() == 1;
    if (kShellcodePath.isEmpty())
    {
        KLogEvent injectShellcodeEmptyPathEvent;
        warn << injectShellcodeEmptyPathEvent
            << "[ProcessDetailWindow] executeInjectShellcodeAction: shellcode 路径为空。"
            << eol;
        QMessageBox::warning(this, "Shellcode 注入", "请先选择 shellcode 文件。");
        return;
    }

    // Shellcode injection log: Use a single KLogEvent per action to ensure the call chain is traceable.
    KLogEvent actionEvent;
    info << actionEvent
        << "[ProcessDetailWindow] executeInjectShellcodeAction: pid="
        << baseRecord_.pid
        << ", mode="
        << (kUseR0Injection ? "R0" : "R3")
        << ", filePath="
        << kShellcodePath.toStdString()
        << eol;

    std::vector<std::uint8_t> shellcodeBuffer;
    std::string readErrorText;
    if (!readBinaryFile(kShellcodePath, shellcodeBuffer, readErrorText, actionEvent))
    {
        err << actionEvent
            << "[ProcessDetailWindow] executeInjectShellcodeAction: 读取文件失败, error="
            << readErrorText
            << eol;
        showActionResultMessage("Shellcode 注入", false, readErrorText, actionEvent);
        return;
    }

    std::string detailText;
    const std::uint32_t kTargetPid = baseRecord_.pid;
    bool actionOk = false;
    if (kUseR0Injection)
    {
        ksword::ark::DriverClient driverClient;
        const ksword::ark::ProcessInjectResult kInjectResult =
            driverClient.injectProcessShellcode(
                static_cast<std::uint32_t>(baseRecord_.pid),
                shellcodeBuffer);
        detailText = kInjectResult.io.message;
        actionOk =
            kInjectResult.io.ok &&
            kInjectResult.status == KSWORD_ARK_PROCESS_INJECT_STATUS_INJECTED;
    }
    else
    {
        actionOk = invokeProcessActionForIdentity(
            kTargetPid,
            baseRecord_.creationTime100ns,
            [kTargetPid, &shellcodeBuffer](std::string* detailTextOut)
            {
                return ks::process::injectShellcodeBuffer(kTargetPid, shellcodeBuffer, detailTextOut);
            },
            &detailText);
    }
    (actionOk ? info : err) << actionEvent
        << "[ProcessDetailWindow] executeInjectShellcodeAction: actionOk="
        << (actionOk ? "true" : "false")
        << ", shellcodeSize="
        << shellcodeBuffer.size()
        << ", detail="
        << detailText
        << eol;
    showActionResultMessage(kUseR0Injection ? QStringLiteral("Shellcode 注入(R0)") : QStringLiteral("Shellcode 注入"), actionOk, detailText, actionEvent);
}

QIcon ProcessDetailWindow::resolveProcessIcon(const std::string& processPath, const int iconPixelSize)
{
    Q_UNUSED(iconPixelSize);

    // Prefer the passed-in path; if empty, fall back to querying once using the current PID.
    QString pathText = QString::fromStdString(processPath);
    if (pathText.trimmed().isEmpty() && baseRecord_.pid != 0)
    {
        pathText = QString::fromStdString(ks::process::queryProcessPathByPid(baseRecord_.pid));
    }
    if (pathText.isEmpty())
    {
        KLogEvent resolveIconFallbackEvent;
        dbg << resolveIconFallbackEvent
            << "[ProcessDetailWindow] resolveProcessIcon: 路径为空，返回默认图标。"
            << eol;
        return QIcon(":/Icon/process_main.svg");
    }

    auto iconIt = iconCacheByPath_.find(pathText);
    if (iconIt != iconCacheByPath_.end())
    {
        KLogEvent resolveIconCacheHitEvent;
        dbg << resolveIconCacheHitEvent
            << "[ProcessDetailWindow] resolveProcessIcon: 命中图标缓存, path="
            << pathText.toStdString()
            << eol;
        return iconIt.value();
    }

    // First attempt to load the icon directly from the EXE path; fall back to QFileIconProvider on failure.
    QIcon processIcon(pathText);
    if (processIcon.isNull())
    {
        QFileIconProvider iconProvider;
        processIcon = iconProvider.icon(QFileInfo(pathText));
    }
    if (processIcon.isNull())
    {
        processIcon = QIcon(":/Icon/process_main.svg");
    }
    iconCacheByPath_.insert(pathText, processIcon);
    KLogEvent resolveIconCacheStoreEvent;
    dbg << resolveIconCacheStoreEvent
        << "[ProcessDetailWindow] resolveProcessIcon: 缓存图标, path="
        << pathText.toStdString()
        << eol;
    return processIcon;
}

QString ProcessDetailWindow::formatModuleSizeText(const std::uint32_t moduleSizeBytes) const
{
    const double kSizeKb = static_cast<double>(moduleSizeBytes) / 1024.0;
    if (kSizeKb < 1024.0)
    {
        return QString("%1 KB").arg(QString::number(kSizeKb, 'f', 1));
    }
    const double kSizeMb = kSizeKb / 1024.0;
    return QString("%1 MB").arg(QString::number(kSizeMb, 'f', 2));
}

QString ProcessDetailWindow::formatHexText(const std::uint64_t value) const
{
    std::ostringstream stream;
    stream << "0x" << std::hex << std::uppercase << value;
    return QString::fromStdString(stream.str());
}

bool ProcessDetailWindow::readBinaryFile(
    const QString& filePath,
    std::vector<std::uint8_t>& bufferOut,
    std::string& errorTextOut,
    const KLogEvent& actionEvent) const
{
    // File read entry log: inherit the caller's actionEvent to ensure continuity of the action chain GUID.
    info << actionEvent
        << "[ProcessDetailWindow] readBinaryFile: filePath="
        << filePath.toStdString()
        << eol;

    bufferOut.clear();
    errorTextOut.clear();

    QFile fileObject(filePath);
    if (!fileObject.open(QIODevice::ReadOnly))
    {
        errorTextOut = "Open file failed: " + fileObject.errorString().toStdString();
        err << actionEvent
            << "[ProcessDetailWindow] readBinaryFile: 打开失败, error="
            << errorTextOut
            << eol;
        return false;
    }

    const QByteArray kRawBytes = fileObject.readAll();
    if (kRawBytes.isEmpty())
    {
        errorTextOut = "File is empty.";
        warn << actionEvent
            << "[ProcessDetailWindow] readBinaryFile: 文件为空。"
            << eol;
        return false;
    }

    bufferOut.resize(static_cast<std::size_t>(kRawBytes.size()));
    std::copy(
        reinterpret_cast<const std::uint8_t*>(kRawBytes.constData()),
        reinterpret_cast<const std::uint8_t*>(kRawBytes.constData()) + kRawBytes.size(),
        bufferOut.begin());
    info << actionEvent
        << "[ProcessDetailWindow] readBinaryFile: 读取成功, size="
        << bufferOut.size()
        << eol;
    return true;
}

void ProcessDetailWindow::showActionResultMessage(
    const QString& title,
    const bool actionOk,
    const std::string& detailText,
    const KLogEvent& actionEvent)
{
    if (!actionOk)
    {
        (void)ks::ui::promptForPrivilegeFailure(
            this,
            title,
            QString::fromStdString(detailText));
    }
    // Action feedback log: Per specification, no pop-up is shown; only logs are output to avoid interrupting the user flow.
    const std::string kNormalizedDetailText = detailText.empty() ? "无附加信息" : detailText;
    (actionOk ? info : err) << actionEvent
        << "[ProcessDetailWindow] showActionResultMessage: title="
        << title.toStdString()
        << ", actionOk="
        << (actionOk ? "true" : "false")
        << ", detail="
        << kNormalizedDetailText
        << eol;
}

ks::process::ProcessModuleRecord* ProcessDetailWindow::selectedModuleRecord()
{
    QTreeWidgetItem* currentItem = moduleTable_->currentItem();
    if (currentItem == nullptr)
    {
        KLogEvent selectedModuleNullEvent;
        warn << selectedModuleNullEvent
            << "[ProcessDetailWindow] selectedModuleRecord: 当前无选中行。"
            << eol;
        return nullptr;
    }

    const std::string kPathText = currentItem->data(
        toModuleColumnIndex(ModuleColumn::kPath),
        Qt::UserRole).toString().toStdString();
    const std::uint64_t kBaseAddress = currentItem->data(
        toModuleColumnIndex(ModuleColumn::kPath),
        Qt::UserRole + 1).toULongLong();

    auto foundIt = std::find_if(
        moduleRecords_.begin(),
        moduleRecords_.end(),
        [kBaseAddress, &kPathText](const ks::process::ProcessModuleRecord& moduleRecord)
        {
            return moduleRecord.moduleBaseAddress == kBaseAddress && moduleRecord.modulePath == kPathText;
        });
    if (foundIt == moduleRecords_.end())
    {
        KLogEvent selectedModuleNotFoundEvent;
        warn << selectedModuleNotFoundEvent
            << "[ProcessDetailWindow] selectedModuleRecord: 缓存中未找到对应模块记录。"
            << eol;
        return nullptr;
    }
    KLogEvent selectedModuleFoundEvent;
    dbg << selectedModuleFoundEvent
        << "[ProcessDetailWindow] selectedModuleRecord: 命中模块记录, path="
        << foundIt->modulePath
        << eol;
    return &(*foundIt);
}

void ProcessDetailWindow::openSelectedThreadStackWindow()
{
    // Call stack window entry:
    // - The current table row may have been sorted, so prioritize reading the cached index saved in the ThreadID cell.
    // - On index invalidation, fall back to lookup by TID to avoid failures to open due to sorting/refresh boundary issues.
    if (threadInspectTable_ == nullptr)
    {
        return;
    }

    const int kCurrentRow = threadInspectTable_->currentRow();
    if (kCurrentRow < 0)
    {
        updateThreadInspectStatusLabel(QStringLiteral("● 请先选择一个线程。"), false);
        return;
    }

    QTableWidgetItem* threadIdItem = threadInspectTable_->item(
        kCurrentRow,
        toThreadColumnIndex(ThreadRowColumn::kThreadId));
    if (threadIdItem == nullptr)
    {
        updateThreadInspectStatusLabel(QStringLiteral("● 当前线程行缺少 ThreadID。"), false);
        return;
    }

    const std::size_t kCacheIndex =
        static_cast<std::size_t>(threadIdItem->data(Qt::UserRole).toULongLong());
    const ThreadInspectItem* selectedThread = nullptr;
    if (kCacheIndex < threadInspectRows_.size())
    {
        selectedThread = &threadInspectRows_[kCacheIndex];
    }

    const std::uint32_t kSelectedTid =
        static_cast<std::uint32_t>(threadIdItem->data(Qt::UserRole + 1).toUInt());
    if (selectedThread == nullptr || selectedThread->threadId != kSelectedTid)
    {
        const auto kFoundIt = std::find_if(
            threadInspectRows_.begin(),
            threadInspectRows_.end(),
            [kSelectedTid](const ThreadInspectItem& rowItem)
            {
                return rowItem.threadId == kSelectedTid;
            });
        if (kFoundIt != threadInspectRows_.end())
        {
            selectedThread = &(*kFoundIt);
        }
    }

    if (selectedThread == nullptr)
    {
        updateThreadInspectStatusLabel(QStringLiteral("● 线程缓存已过期，请先刷新线程列表。"), false);
        return;
    }

    ThreadStackTarget target{};
    target.processId = selectedThread->processId != 0 ? selectedThread->processId : baseRecord_.pid;
    target.threadId = selectedThread->threadId;
    target.processName = QString::fromStdString(
        baseRecord_.processName.empty() ? std::string("Unknown") : baseRecord_.processName);
    target.processPath = QString::fromStdString(baseRecord_.imagePath);
    target.startAddress = selectedThread->startAddress;
    target.win32StartAddress = selectedThread->win32StartAddress;
    target.tebBaseAddress = selectedThread->tebAddress;
    target.userStackBase = selectedThread->userStackBase;
    target.userStackLimit = selectedThread->userStackLimit;
    target.r0KernelStack = selectedThread->r0KernelStack;
    target.r0StackBase = selectedThread->r0StackBase;
    target.r0StackLimit = selectedThread->r0StackLimit;
    target.r0InitialStack = selectedThread->r0InitialStack;
    target.r0ThreadStatus = selectedThread->r0ThreadStatus;
    target.r0CapabilityMask = selectedThread->r0CapabilityMask;

    auto* stackWindow = new ThreadStackWindow(target, this);
    stackWindow->setAttribute(Qt::WA_DeleteOnClose, true);
    stackWindow->show();
    stackWindow->raise();
    stackWindow->activateWindow();

    KLogEvent actionEvent;
    info << actionEvent
        << "[ProcessDetailWindow] openSelectedThreadStackWindow: pid="
        << target.processId
        << ", tid="
        << target.threadId
        << eol;
}

QString ProcessDetailWindow::resolveSelectedThreadModulePathForUpload(QString* errorTextOut) const
{
    // Input: Current row of the thread table and the most recent thread/module refresh cache.
    // Note: Retrieve startAddress/win32StartAddress from ThreadInspectItem and perform range matching based on module base address + size.
    // Returns: The path of the matched module; on failure, returns an empty string and populates errorTextOut with the reason for the user.
    if (errorTextOut != nullptr)
    {
        errorTextOut->clear();
    }
    if (threadInspectTable_ == nullptr)
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("线程表尚未初始化。");
        }
        return QString();
    }

    const int kCurrentRow = threadInspectTable_->currentRow();
    if (kCurrentRow < 0)
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("请先选择一个线程。");
        }
        return QString();
    }

    const QTableWidgetItem* threadIdItem = threadInspectTable_->item(
        kCurrentRow,
        toThreadColumnIndex(ThreadRowColumn::kThreadId));
    if (threadIdItem == nullptr)
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("当前线程行缺少 ThreadID。");
        }
        return QString();
    }

    const std::size_t kCacheIndex = static_cast<std::size_t>(threadIdItem->data(Qt::UserRole).toULongLong());
    const std::uint32_t kSelectedTid = static_cast<std::uint32_t>(threadIdItem->data(Qt::UserRole + 1).toUInt());
    const ThreadInspectItem* selectedThread = nullptr;
    if (kCacheIndex < threadInspectRows_.size())
    {
        selectedThread = &threadInspectRows_[kCacheIndex];
    }
    if (selectedThread == nullptr || selectedThread->threadId != kSelectedTid)
    {
        const auto kFoundIt = std::find_if(
            threadInspectRows_.begin(),
            threadInspectRows_.end(),
            [kSelectedTid](const ThreadInspectItem& rowItem)
            {
                return rowItem.threadId == kSelectedTid;
            });
        if (kFoundIt != threadInspectRows_.end())
        {
            selectedThread = &(*kFoundIt);
        }
    }
    if (selectedThread == nullptr)
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("线程缓存已过期，请先刷新线程列表。");
        }
        return QString();
    }
    if (moduleRecords_.empty())
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("模块缓存为空，请先刷新“模块”页后再上传线程模块。");
        }
        return QString();
    }

    const std::uint64_t kAddressCandidates[] =
    {
        selectedThread->win32StartAddress,
        selectedThread->startAddress
    };
    for (const std::uint64_t kAddressValue : kAddressCandidates)
    {
        if (kAddressValue == 0)
        {
            continue;
        }

        for (const ks::process::ProcessModuleRecord& moduleRecord : moduleRecords_)
        {
            if (moduleRecord.moduleBaseAddress == 0 || moduleRecord.moduleSizeBytes == 0)
            {
                continue;
            }

            const std::uint64_t kModuleEnd =
                moduleRecord.moduleBaseAddress + static_cast<std::uint64_t>(moduleRecord.moduleSizeBytes);
            if (kAddressValue >= moduleRecord.moduleBaseAddress && kAddressValue < kModuleEnd)
            {
                const QString kModulePath = QString::fromStdString(moduleRecord.modulePath).trimmed();
                if (!kModulePath.isEmpty())
                {
                    return kModulePath;
                }
            }
        }
    }

    if (errorTextOut != nullptr)
    {
        *errorTextOut = QStringLiteral("无法根据线程起始地址解析所属模块；不会回退上传进程 EXE。");
    }
    return QString();
}
