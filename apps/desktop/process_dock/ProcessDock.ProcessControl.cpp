#include "ProcessDock.Support.h"
#include "ProcessActivityChartWidget.h"
#include "ProcessActivityTimelineSlider.h"

using namespace ksword::ui::process_dock;

void ProcessDock::executeTerminateThreadsAction()
{
    const std::vector<ProcessActionTarget> kActionTargets = selectedActionTargets();
    if (kActionTargets.empty())
    {
        KLogEvent logEvent;
        warn << logEvent << "[ProcessDock] executeTerminateThreadsAction 被忽略：当前没有选中进程。" << eol;
        return;
    }

    dispatchProcessActionTargetsInParallel(
        QStringLiteral("TerminateThread(全部线程)"),
        kActionTargets,
        [](const ProcessActionTarget& actionTarget, std::string* detailTextOut)
        {
            return ks::process::terminateAllThreadsByPid(actionTarget.record.pid, detailTextOut);
        },
        true,
        false,
        true);
}

void ProcessDock::executeSuspendAction()
{
    const std::vector<ProcessActionTarget> kActionTargets = selectedActionTargets();
    if (kActionTargets.empty())
    {
        KLogEvent logEvent;
        warn << logEvent << "[ProcessDock] executeSuspendAction 被忽略：当前没有选中进程。" << eol;
        return;
    }

    dispatchProcessActionTargetsInParallel(
        QStringLiteral("挂起进程"),
        kActionTargets,
        [](const ProcessActionTarget& actionTarget, std::string* detailTextOut)
        {
            return ks::process::suspendProcessIfCreationTimeMatches(actionTarget.record.pid, actionTarget.record.creationTime100ns, detailTextOut);
        },
        false,
        false,
        true);
}

void ProcessDock::executeResumeAction()
{
    const std::vector<ProcessActionTarget> kActionTargets = selectedActionTargets();
    if (kActionTargets.empty())
    {
        KLogEvent logEvent;
        warn << logEvent << "[ProcessDock] executeResumeAction 被忽略：当前没有选中进程。" << eol;
        return;
    }

    dispatchProcessActionTargetsInParallel(
        QStringLiteral("恢复进程"),
        kActionTargets,
        [](const ProcessActionTarget& actionTarget, std::string* detailTextOut)
        {
            return ks::process::resumeProcessIfCreationTimeMatches(actionTarget.record.pid, actionTarget.record.creationTime100ns, detailTextOut);
        },
        false,
        false,
        true);
}

void ProcessDock::executeSetCriticalAction(const bool enableCritical)
{
    const std::vector<ProcessActionTarget> kActionTargets = selectedActionTargets();
    if (kActionTargets.empty())
    {
        KLogEvent logEvent;
        warn << logEvent << "[ProcessDock] executeSetCriticalAction 被忽略：当前没有选中进程。" << eol;
        return;
    }

    dispatchProcessActionTargetsInParallel(
        enableCritical ? QStringLiteral("设为关键进程") : QStringLiteral("取消关键进程"),
        kActionTargets,
        [enableCritical](const ProcessActionTarget& actionTarget, std::string* detailTextOut)
        {
            return ks::process::setProcessCriticalFlag(actionTarget.record.pid, enableCritical, detailTextOut);
        },
        false,
        false,
        true);
}

void ProcessDock::executeSetPriorityAction(const int priorityActionId)
{
    const std::vector<ProcessActionTarget> kActionTargets = selectedActionTargets();
    if (kActionTargets.empty())
    {
        KLogEvent logEvent;
        warn << logEvent << "[ProcessDock] executeSetPriorityAction 被忽略：当前没有选中进程。" << eol;
        return;
    }

    ks::process::ProcessPriorityLevel priorityLevel = ks::process::ProcessPriorityLevel::kNormal;
    switch (priorityActionId)
    {
    case 0: priorityLevel = ks::process::ProcessPriorityLevel::kIdle; break;
    case 1: priorityLevel = ks::process::ProcessPriorityLevel::kBelowNormal; break;
    case 2: priorityLevel = ks::process::ProcessPriorityLevel::kNormal; break;
    case 3: priorityLevel = ks::process::ProcessPriorityLevel::kAboveNormal; break;
    case 4: priorityLevel = ks::process::ProcessPriorityLevel::kHigh; break;
    case 5: priorityLevel = ks::process::ProcessPriorityLevel::kRealtime; break;
    default: break;
    }

    dispatchProcessActionTargetsInParallel(
        QStringLiteral("设置进程优先级"),
        kActionTargets,
        [priorityLevel](const ProcessActionTarget& actionTarget, std::string* detailTextOut)
        {
            return ks::process::setProcessPriority(actionTarget.record.pid, priorityLevel, detailTextOut);
        },
        false,
        false,
        true);
}

void ProcessDock::executeSetProcessIntegrityAction(
    const unsigned long integrityRid,
    const QString& levelDisplayText)
{
    // Input: integrity RID and menu display text.
    // Note: Pass selected process snapshots to the unified batch executor; each target first uses R0 kernel APIs, falling back to R3 if the driver is unavailable or outdated.
    // Return: None; success/failure is logged by dispatchProcessActionTargetsInParallel.
    const std::vector<ProcessActionTarget> kActionTargets = selectedActionTargets();
    if (kActionTargets.empty())
    {
        KLogEvent logEvent;
        warn << logEvent << "[ProcessDock] executeSetProcessIntegrityAction 被忽略：当前没有选中进程。" << eol;
        return;
    }

    const DWORD kTargetIntegrityRid = static_cast<DWORD>(integrityRid);
    const QString kActionTitle = QStringLiteral("设置进程完整性(%1)").arg(levelDisplayText);
    dispatchProcessActionTargetsInParallel(
        kActionTitle,
        kActionTargets,
        [kTargetIntegrityRid](const ProcessActionTarget& actionTarget, std::string* detailTextOut)
        {
            return setProcessIntegrityLevelByR0ThenR3(
                actionTarget.record.pid,
                kTargetIntegrityRid,
                detailTextOut);
        },
        false,
        false,
        true);
}

void ProcessDock::executeSetEfficiencyModeAction(const bool enableEfficiencyMode)
{
    const std::vector<ProcessActionTarget> kActionTargets = selectedActionTargets();
    if (kActionTargets.empty())
    {
        KLogEvent logEvent;
        warn << logEvent << "[ProcessDock] executeSetEfficiencyModeAction 被忽略：当前没有选中进程。" << eol;
        return;
    }

    const QString kActionTitle =
        enableEfficiencyMode ? QStringLiteral("开启效率模式") : QStringLiteral("关闭效率模式");
    dispatchProcessActionTargetsInParallel(
        kActionTitle,
        kActionTargets,
        [enableEfficiencyMode](const ProcessActionTarget& actionTarget, std::string* detailTextOut)
        {
            return ks::process::setProcessEfficiencyMode(
                actionTarget.record.pid,
                enableEfficiencyMode,
                detailTextOut);
        },
        false,
        false,
        true);

    // UI cache updates immediately: thread execution results are still recorded independently; this step only ensures the visual state of selected rows responds quickly.
    for (const ProcessActionTarget& actionTarget : kActionTargets)
    {
        const auto kCacheIt = cacheByIdentity_.find(actionTarget.identityKey);
        if (kCacheIt != cacheByIdentity_.end())
        {
            kCacheIt->second.record.efficiencyModeSupported = true;
            kCacheIt->second.record.efficiencyModeEnabled = enableEfficiencyMode;
        }
    }
    if (processTable_ != nullptr)
    {
        processTable_->viewport()->update();
    }
}
