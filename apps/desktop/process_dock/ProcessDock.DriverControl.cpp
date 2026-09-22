#include "ProcessDock.Support.h"
#include "ProcessActivityChartWidget.h"
#include "ProcessActivityTimelineSlider.h"

using namespace ksword::ui::process_dock;

void ProcessDock::executeR0SuspendProcessAction()
{
    const std::vector<ProcessActionTarget> kActionTargets = selectedActionTargets();
    if (kActionTargets.empty())
    {
        KLogEvent logEvent;
        warn << logEvent << "[ProcessDock] executeR0SuspendProcessAction 被忽略：当前没有选中进程。" << eol;
        return;
    }

    dispatchProcessActionTargetsInParallel(
        QStringLiteral("R0挂起进程"),
        kActionTargets,
        [](const ProcessActionTarget& actionTarget, std::string* detailTextOut)
        {
            return suspendProcessByR0Driver(actionTarget.record.pid, detailTextOut);
        },
        false,
        false,
        true);
}

void ProcessDock::executeR0ResumeProcessAction()
{
    const std::vector<ProcessActionTarget> kActionTargets = selectedActionTargets();
    if (kActionTargets.empty())
    {
        KLogEvent logEvent;
        warn << logEvent << "[ProcessDock] executeR0ResumeProcessAction 被忽略：当前没有选中进程。" << eol;
        return;
    }

    dispatchProcessActionTargetsInParallel(
        processContextText("process.menu.r0_resume", QStringLiteral("R0恢复进程")),
        kActionTargets,
        [](const ProcessActionTarget& actionTarget, std::string* detailTextOut)
        {
            return resumeProcessByR0Driver(actionTarget.record.pid, detailTextOut);
        },
        false,
        false,
        true);
}

void ProcessDock::executeR0SetProcessHiddenAction(
    const bool hidden,
    const unsigned long visibilityFlags)
{
    // Input: hidden indicates hide/show direction; visibilityFlags is used only for hide actions in R0 mode.
    // Processing: Batch call driver IOCTLs, then open kernel comparison and display Ksword hidden items after successful hiding.
    // Return: None; results are fed back to the user via message boxes, logs, and asynchronous refresh.
    const std::vector<ProcessActionTarget> kActionTargets = selectedActionTargets();
    if (kActionTargets.empty())
    {
        KLogEvent logEvent;
        warn << logEvent << "[ProcessDock] executeR0SetProcessHiddenAction 被忽略：当前没有选中进程。" << eol;
        return;
    }

    if (hidden)
    {
        const bool kPatchPid =
            ((visibilityFlags & KSWORD_ARK_PROCESS_VISIBILITY_FLAG_PATCH_UNIQUE_PID) != 0UL);
        const bool kUnlinkList =
            ((visibilityFlags & KSWORD_ARK_PROCESS_VISIBILITY_FLAG_UNLINK_ACTIVE_LIST) != 0UL);
        QString modeText;
        QString riskText;
        if (kPatchPid && kUnlinkList)
        {
            modeText = QStringLiteral("改 PID + 断链（旧版双操作）");
            riskText = QStringLiteral("风险：最高；可能导致按原 PID 查找困难，退出路径也更敏感。");
        }
        else if (kPatchPid)
        {
            modeText = QStringLiteral("只改 PID");
            riskText = QStringLiteral("风险：高；目标仍在活动链表中，但按原 PID 查找可能失效。");
        }
        else
        {
            modeText = QStringLiteral("只断链");
            riskText = QStringLiteral("风险：相对低于改 PID；不改 UniqueProcessId，Ksword 更容易按原 PID 找回。");
        }

        const QMessageBox::StandardButton kChoice = QMessageBox::warning(
            this,
            QStringLiteral("R0进程隐藏(可恢复)"),
            QStringLiteral(
                "将把选中的 %1 个进程写入 Ksword 驱动隐藏表。\n\n"
                "模式：%2\n"
                "%3\n\n"
                "说明：驱动只保存 Ksword 本次修改过的字段；取消隐藏/清空时按记录恢复。")
                .arg(kActionTargets.size())
                .arg(modeText)
                .arg(riskText),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
        if (kChoice != QMessageBox::Yes)
        {
            return;
        }
    }

    std::size_t successCount = 0U;
    std::size_t failureCount = 0U;
    QStringList detailLines;
    const unsigned long kAction = hidden
        ? KSWORD_ARK_PROCESS_VISIBILITY_ACTION_HIDE
        : KSWORD_ARK_PROCESS_VISIBILITY_ACTION_UNHIDE;

    for (const ProcessActionTarget& actionTarget : kActionTargets)
    {
        std::string detailText;
        const bool kActionOk = setProcessVisibilityByR0Driver(
            actionTarget.record.pid,
            kAction,
            hidden ? visibilityFlags : 0UL,
            &detailText);
        if (kActionOk)
        {
            ++successCount;
            if (hidden)
            {
                hiddenProcessPidSet_.insert(actionTarget.record.pid);
            }
            else
            {
                hiddenProcessPidSet_.erase(actionTarget.record.pid);
            }
        }
        else
        {
            ++failureCount;
        }
        detailLines.push_back(QStringLiteral("PID=%1 %2 | %3")
            .arg(actionTarget.record.pid)
            .arg(kActionOk ? QStringLiteral("OK") : QStringLiteral("FAIL"))
            .arg(QString::fromStdString(detailText.empty() ? std::string("无附加信息") : detailText)));
    }

    const QString kTitleText = hidden
        ? QStringLiteral("R0隐藏进程")
        : QStringLiteral("R0取消隐藏进程");
    const QString kSummaryText = QStringLiteral("%1 完成：成功 %2，失败 %3\n\n%4")
        .arg(kTitleText)
        .arg(successCount)
        .arg(failureCount)
        .arg(detailLines.join(QLatin1Char('\n')));

    KLogEvent logEvent;
    (failureCount == 0U ? info : warn) << logEvent
        << "[ProcessDock] " << kTitleText.toStdString()
        << " completed, success=" << successCount
        << ", failure=" << failureCount
        << eol;
    showActionResultMessage(kTitleText, failureCount == 0U, kSummaryText.toStdString(), logEvent);
    if (hidden && successCount > 0U && kernelCompareCheck_ != nullptr && !kernelCompareCheck_->isChecked())
    {
        kernelCompareCheck_->setChecked(true);
    }
    if (hidden && successCount > 0U &&
        showKswordHiddenProcessCheck_ != nullptr &&
        !showKswordHiddenProcessCheck_->isChecked())
    {
        showKswordHiddenProcessCheck_->setChecked(true);
    }
    requestAsyncRefresh(true);
}

void ProcessDock::executeR0ClearProcessHiddenAction()
{
    const QMessageBox::StandardButton kChoice = QMessageBox::question(
        this,
        QStringLiteral("清空R0隐藏标记"),
        QStringLiteral("确定清空 Ksword 驱动内全部可恢复进程隐藏标记吗？"),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kChoice != QMessageBox::Yes)
    {
        return;
    }

    std::string detailText;
    const bool kActionOk = setProcessVisibilityByR0Driver(
        0U,
        KSWORD_ARK_PROCESS_VISIBILITY_ACTION_CLEAR_ALL,
        0UL,
        &detailText);
    if (kActionOk)
    {
        hiddenProcessPidSet_.clear();
    }

    KLogEvent logEvent;
    (kActionOk ? info : warn) << logEvent
        << "[ProcessDock] 清空R0隐藏标记完成, ok="
        << (kActionOk ? "true" : "false")
        << ", detail=" << (detailText.empty() ? "无附加信息" : detailText)
        << eol;
    showActionResultMessage(
        QStringLiteral("清空R0隐藏标记"),
        kActionOk,
        detailText.empty() ? std::string("无附加信息") : detailText,
        logEvent);
    requestAsyncRefresh(true);
}

void ProcessDock::executeR0SetBreakOnTerminationAction(const bool enabled)
{
    // BreakOnTermination：
    // - Use ZwSetInformationProcess on the R0 side; do not directly hardcode EPROCESS.Flags.
    // - Distribute batch targets one by one; write failure details to a unified action log.
    const std::vector<ProcessActionTarget> kActionTargets = selectedActionTargets();
    if (kActionTargets.empty())
    {
        KLogEvent logEvent;
        warn << logEvent << "[ProcessDock] executeR0SetBreakOnTerminationAction 被忽略：当前没有选中进程。" << eol;
        return;
    }

    const QMessageBox::StandardButton kChoice = QMessageBox::warning(
        this,
        enabled ? QStringLiteral("启用 BreakOnTermination") : QStringLiteral("关闭 BreakOnTermination"),
        enabled
        ? QStringLiteral("将把选中的 %1 个进程设为关键进程。目标退出可能触发系统崩溃保护。是否继续？").arg(kActionTargets.size())
        : QStringLiteral("将清除选中 %1 个进程的 BreakOnTermination。是否继续？").arg(kActionTargets.size()),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kChoice != QMessageBox::Yes)
    {
        return;
    }

    const unsigned long kAction = enabled
        ? KSWORD_ARK_PROCESS_SPECIAL_ACTION_ENABLE_BREAK_ON_TERMINATION
        : KSWORD_ARK_PROCESS_SPECIAL_ACTION_DISABLE_BREAK_ON_TERMINATION;
    dispatchProcessActionTargetsInParallel(
        enabled ? QStringLiteral("R0启用BreakOnTermination") : QStringLiteral("R0关闭BreakOnTermination"),
        kActionTargets,
        [kAction](const ProcessActionTarget& actionTarget, std::string* detailTextOut)
        {
            return setProcessSpecialFlagsByR0Driver(
                actionTarget.record.pid,
                kAction,
                r0ActionExpectedCreationTime(actionTarget.record),
                detailTextOut);
        },
        false,
        false,
        true);
}

void ProcessDock::executeR0DisableApcInsertionAction()
{
    // Disable APC insertion:
    // - R0 side only processes the ApcQueueable bit for threads that currently exist.
    // - Newly created threads are outside the current result scope, so the boundary is explicitly noted in the prompt.
    const std::vector<ProcessActionTarget> kActionTargets = selectedActionTargets();
    if (kActionTargets.empty())
    {
        KLogEvent logEvent;
        warn << logEvent << "[ProcessDock] executeR0DisableApcInsertionAction 被忽略：当前没有选中进程。" << eol;
        return;
    }

    const QMessageBox::StandardButton kChoice = QMessageBox::warning(
        this,
        QStringLiteral("禁止APC插入"),
        QStringLiteral(
            "将清除选中 %1 个进程当前线程的 ApcQueueable 位。\n\n"
            "说明：该动作影响现有线程；目标后续新建线程不自动覆盖。错误线程偏移可能导致系统不稳定。是否继续？")
            .arg(kActionTargets.size()),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kChoice != QMessageBox::Yes)
    {
        return;
    }

    dispatchProcessActionTargetsInParallel(
        QStringLiteral("R0禁止APC插入"),
        kActionTargets,
        [](const ProcessActionTarget& actionTarget, std::string* detailTextOut)
        {
            return setProcessSpecialFlagsByR0Driver(
                actionTarget.record.pid,
                KSWORD_ARK_PROCESS_SPECIAL_ACTION_DISABLE_APC_INSERTION,
                r0ActionExpectedCreationTime(actionTarget.record),
                detailTextOut);
        },
        false,
        false,
        true);
}

void ProcessDock::executeR0DkomRemoveFromCidTableAction()
{
    // PspCidTable DKOM：
    // - Target objects are referenced by R0 based on PID.
    // - UI does not pass EPROCESS addresses;
    // - After deletion, PsLookupProcessByProcessId may no longer find the target; refresh the list.
    const std::vector<ProcessActionTarget> kActionTargets = selectedActionTargets();
    if (kActionTargets.empty())
    {
        KLogEvent logEvent;
        warn << logEvent << "[ProcessDock] executeR0DkomRemoveFromCidTableAction 被忽略：当前没有选中进程。" << eol;
        return;
    }

    const QMessageBox::StandardButton kChoice = QMessageBox::critical(
        this,
        QStringLiteral("DKOM从PspCidTable删除"),
        QStringLiteral(
            "将从 PspCidTable 删除选中 %1 个进程的 CID 表项。\n\n"
            "风险：该动作不可通过当前菜单恢复，可能破坏句柄/PID 查询语义，错误系统版本或竞态会导致蓝屏。是否继续？")
            .arg(kActionTargets.size()),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kChoice != QMessageBox::Yes)
    {
        return;
    }

    dispatchProcessActionTargetsInParallel(
        QStringLiteral("R0 DKOM PspCidTable删除"),
        kActionTargets,
        [](const ProcessActionTarget& actionTarget, std::string* detailTextOut)
        {
            return dkomProcessByR0Driver(
                actionTarget.record.pid,
                KSWORD_ARK_PROCESS_DKOM_ACTION_REMOVE_FROM_PSP_CID_TABLE,
                detailTextOut);
        },
        false,
        false,
        true);
    requestAsyncRefresh(true);
}

void ProcessDock::executeR0SetPplProtectionAction(
    const std::uint8_t protectionLevel,
    const QString& levelDisplayText)
{
    const std::vector<ProcessActionTarget> kActionTargets = selectedActionTargets();
    if (kActionTargets.empty())
    {
        KLogEvent logEvent;
        warn << logEvent << "[ProcessDock] executeR0SetPplProtectionAction 被忽略：当前没有选中进程。" << eol;
        return;
    }

    const ks::process::ProcessRecord& primaryRecord = kActionTargets.front().record;
    const std::uint32_t kTargetPid = primaryRecord.pid;
    std::uint8_t targetSignatureLevel = 0U;
    std::uint8_t targetSectionSignatureLevel = 0U;
    const bool kSignaturePredictionOk = resolvePplSignatureLevelsForUi(
        protectionLevel,
        &targetSignatureLevel,
        &targetSectionSignatureLevel);
    const QString kCurrentProtectionText =
        ((primaryRecord.r0FieldFlags & KSWORD_ARK_PROCESS_FIELD_PROTECTION_PRESENT) != 0U)
        ? byteHexText(primaryRecord.r0Protection)
        : QStringLiteral("Unavailable");
    const QString kCurrentSignatureText =
        ((primaryRecord.r0FieldFlags & KSWORD_ARK_PROCESS_FIELD_SIGNATURE_LEVEL_PRESENT) != 0U)
        ? byteHexText(primaryRecord.r0SignatureLevel)
        : QStringLiteral("Unavailable");
    const QString kCurrentSectionSignatureText =
        ((primaryRecord.r0FieldFlags & KSWORD_ARK_PROCESS_FIELD_SECTION_SIGNATURE_LEVEL_PRESENT) != 0U)
        ? byteHexText(primaryRecord.r0SectionSignatureLevel)
        : QStringLiteral("Unavailable");
    const QString kTargetSignatureText = kSignaturePredictionOk
        ? byteHexText(targetSignatureLevel)
        : QStringLiteral("Unknown");
    const QString kTargetSectionSignatureText = kSignaturePredictionOk
        ? byteHexText(targetSectionSignatureLevel)
        : QStringLiteral("Unknown");
    const QString kConfirmationText = QStringLiteral(
        "将通过 R0 驱动修改目标进程 PPL/PP（EPROCESS.Protection）字段。\n\n"
        "进程: %1 (PID %2)%12\n"
        "当前 Protection: %3  来源: %4\n"
        "目标 Protection: %5  菜单: %6\n\n"
        "SignatureLevel 影响:\n"
        "  当前 SignatureLevel: %7 -> 目标: %8\n"
        "  当前 SectionSignatureLevel: %9 -> 目标: %10\n\n"
        "%11\n\n"
        "风险: 该动作会直接写 EPROCESS.Protection/SignatureLevel/SectionSignatureLevel。"
        "错误的 DynData 偏移、系统版本差异或目标进程状态变化可能导致回滚失败、访问异常或系统不稳定。"
        "继续前请确认已保存当前字段值用于手工回滚。")
        .arg(QString::fromStdString(primaryRecord.processName.empty() ? std::string("Unknown") : primaryRecord.processName))
        .arg(kTargetPid)
        .arg(kCurrentProtectionText)
        .arg(processFieldSourceText(primaryRecord.r0ProtectionSource))
        .arg(byteHexText(protectionLevel))
        .arg(levelDisplayText)
        .arg(kCurrentSignatureText)
        .arg(kTargetSignatureText)
        .arg(kCurrentSectionSignatureText)
        .arg(kTargetSectionSignatureText)
        .arg(pplMutationCapabilityText(primaryRecord))
        .arg(kActionTargets.size() > 1U ? QStringLiteral("\n批量目标数: %1，确认后每个进程会独立线程执行。").arg(kActionTargets.size()) : QString());

    const QMessageBox::StandardButton kConfirmationButton = QMessageBox::warning(
        this,
        QStringLiteral("确认 R0 设置 PPL 层级"),
        kConfirmationText,
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kConfirmationButton != QMessageBox::Yes)
    {
        KLogEvent cancelEvent;
        warn << cancelEvent
            << "[ProcessDock] R0 set PPL action cancelled by user, pid="
            << kTargetPid
            << ", protectionLevel=0x"
            << std::hex
            << std::uppercase
            << static_cast<unsigned int>(protectionLevel)
            << std::dec
            << eol;
        return;
    }

    const QString kActionTitle = QStringLiteral("R0设置进程保护层级(%1)").arg(levelDisplayText);
    dispatchProcessActionTargetsInParallel(
        kActionTitle,
        kActionTargets,
        [protectionLevel](const ProcessActionTarget& actionTarget, std::string* detailTextOut)
        {
            return setPplProtectionLevelByR0Driver(actionTarget.record.pid, protectionLevel, detailTextOut);
        },
        false,
        false,
        true);
}

void ProcessDock::executeRefreshPplProtectionLevelAction()
{
    // This action only refreshes the fields of the currently selected snapshot, without triggering a full process enumeration.
    const std::vector<ProcessActionTarget> kActionTargets = selectedActionTargets();
    if (kActionTargets.empty())
    {
        KLogEvent logEvent;
        warn << logEvent << "[ProcessDock] PPL 保护级别刷新被忽略：当前没有选中进程。" << eol;
        return;
    }

    std::size_t successCount = 0;
    std::size_t failureCount = 0;
    QStringList resultLineList;
    resultLineList.reserve(static_cast<qsizetype>(kActionTargets.size()));

    // Each target independently calls GetProcessInformation to avoid relying on stale cache for PPL columns.
    for (const ProcessActionTarget& actionTarget : kActionTargets)
    {
        auto cacheIt = cacheByIdentity_.find(actionTarget.identityKey);
        if (cacheIt == cacheByIdentity_.end())
        {
            ++failureCount;
            resultLineList.push_back(QStringLiteral("PID %1: cache missing")
                .arg(actionTarget.record.pid));
            continue;
        }

        HANDLE processHandle = nullptr;
        std::string identityDetail;
        if (!acquireProcessActionIdentityHold(
                actionTarget.record.pid,
                actionTarget.record.creationTime100ns,
                &processHandle,
                &identityDetail))
        {
            ++failureCount;
            resultLineList.push_back(QStringLiteral("PID %1: %2")
                .arg(actionTarget.record.pid)
                .arg(QString::fromStdString(identityDetail)));
            continue;
        }
        const ScopedProcessActionHandle kIdentityHold(processHandle);

        std::uint32_t protectionLevelValue = 0;
        std::string protectionLevelText;
        std::string errorText;
        const bool kQueryOk = ks::process::queryProcessProtectionLevelByPid(
            actionTarget.record.pid,
            &protectionLevelValue,
            &protectionLevelText,
            &errorText);
        if (kQueryOk)
        {
            cacheIt->second.record.protectionLevelKnown = true;
            cacheIt->second.record.protectionLevel = protectionLevelValue;
            cacheIt->second.record.protectionLevelText = protectionLevelText;
            ++successCount;
            resultLineList.push_back(QStringLiteral("PID %1: %2")
                .arg(actionTarget.record.pid)
                .arg(QString::fromStdString(protectionLevelText)));
        }
        else
        {
            cacheIt->second.record.protectionLevelKnown = true;
            cacheIt->second.record.protectionLevel = 0;
            cacheIt->second.record.protectionLevelText = errorText.empty()
                ? std::string("Query failed")
                : std::string("Query failed: ") + errorText;
            ++failureCount;
            resultLineList.push_back(QStringLiteral("PID %1: %2")
                .arg(actionTarget.record.pid)
                .arg(QString::fromStdString(cacheIt->second.record.protectionLevelText)));
        }
    }

    rebuildTable();
    KLogEvent actionEvent;
    (failureCount == 0 ? info : warn) << actionEvent
        << "[ProcessDock] PPL 保护级别手动刷新完成, targets=" << kActionTargets.size()
        << ", success=" << successCount
        << ", failure=" << failureCount
        << ", detail=" << resultLineList.join(" | ").toStdString()
        << eol;
}
