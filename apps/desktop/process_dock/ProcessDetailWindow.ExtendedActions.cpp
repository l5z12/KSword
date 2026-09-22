#include "ProcessDetailWindow.InternalCommon.h"

using namespace process_detail_window_internal;

// ============================================================
// ProcessDetailWindow.ExtendedActions.cpp
// Purpose:
// - Provides supplementary actions for the "right-click menu synchronization capability" in the detail view.
// - Allow the base operation file to continue focusing on existing terminate/suspend/inject logic;
// - R0 calls go exclusively through ArkDriverClient; UI files do not directly call DeviceIoControl.
// ============================================================

namespace
{
    // detailExtendedProcessStillPresent:
    // - Use a Toolhelp snapshot to check if the target PID still exists;
    // - Input targetPid is the process ID, queryOkOut receives whether the snapshot succeeded;
    // - Returns true if the process still exists; false if not found or the query failed.
    bool detailExtendedProcessStillPresent(const std::uint32_t targetPid, bool* const queryOkOut)
    {
        if (queryOkOut != nullptr)
        {
            *queryOkOut = false;
        }

        const HANDLE kSnapshotHandle = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (kSnapshotHandle == INVALID_HANDLE_VALUE)
        {
            return true;
        }

        PROCESSENTRY32W processEntry{};
        processEntry.dwSize = sizeof(processEntry);
        bool foundTarget = false;
        BOOL walkOk = ::Process32FirstW(kSnapshotHandle, &processEntry);
        while (walkOk != FALSE)
        {
            if (processEntry.th32ProcessID == targetPid)
            {
                foundTarget = true;
                break;
            }
            walkOk = ::Process32NextW(kSnapshotHandle, &processEntry);
        }

        ::CloseHandle(kSnapshotHandle);
        if (queryOkOut != nullptr)
        {
            *queryOkOut = true;
        }
        return foundTarget;
    }

    // appendExtendedIoResultDetail:
    // - Formats the generic ArkDriverClient I/O result into the output stream;
    // - Input: result is the driver client return value; detailStream is the target for appending.
    // - Return value: None.
    void appendExtendedIoResultDetail(
        const ksword::ark::IoResult& result,
        std::ostringstream& detailStream)
    {
        detailStream
            << "io.ok=" << (result.ok ? "true" : "false")
            << ", win32=" << result.win32Error
            << ", nt=0x" << std::hex << static_cast<unsigned long>(result.ntStatus) << std::dec
            << ", bytes=" << result.bytesReturned
            << ", message=" << result.message;
    }

    // DetailProcessIdentityHold:
    // - Hold a process handle validated by creation time during synchronization actions in the detail view.
    // - Prevent old detail windows from operating on or displaying another process instance after PID reuse.
    class DetailProcessIdentityHold final
    {
    public:
        DetailProcessIdentityHold() = default;
        ~DetailProcessIdentityHold()
        {
            if (processHandle_ != nullptr)
            {
                ::CloseHandle(processHandle_);
            }
        }

        DetailProcessIdentityHold(const DetailProcessIdentityHold&) = delete;
        DetailProcessIdentityHold& operator=(const DetailProcessIdentityHold&) = delete;

        bool acquire(
            const std::uint32_t pid,
            const std::uint64_t expectedCreationTime100ns,
            std::string* const detailTextOut)
        {
            if (pid == 0U || expectedCreationTime100ns == 0U)
            {
                if (detailTextOut != nullptr)
                {
                    *detailTextOut = "process identity is unavailable; action skipped";
                }
                return false;
            }

            const HANDLE kRawProcessHandle = ::OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                FALSE,
                pid);
            if (kRawProcessHandle == nullptr)
            {
                if (detailTextOut != nullptr)
                {
                    *detailTextOut = "OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) failed, error=" +
                        std::to_string(::GetLastError());
                }
                return false;
            }

            FILETIME creationTime{};
            FILETIME exitTime{};
            FILETIME kernelTime{};
            FILETIME userTime{};
            if (!::GetProcessTimes(
                    kRawProcessHandle,
                    &creationTime,
                    &exitTime,
                    &kernelTime,
                    &userTime))
            {
                const DWORD kError = ::GetLastError();
                ::CloseHandle(kRawProcessHandle);
                if (detailTextOut != nullptr)
                {
                    *detailTextOut = "GetProcessTimes failed, error=" + std::to_string(kError);
                }
                return false;
            }

            const std::uint64_t kActualCreationTime100ns =
                (static_cast<std::uint64_t>(creationTime.dwHighDateTime) << 32U) |
                static_cast<std::uint64_t>(creationTime.dwLowDateTime);
            if (kActualCreationTime100ns == 0U ||
                kActualCreationTime100ns != expectedCreationTime100ns)
            {
                ::CloseHandle(kRawProcessHandle);
                if (detailTextOut != nullptr)
                {
                    *detailTextOut = "process identity changed (PID was reused); action skipped";
                }
                return false;
            }

            processHandle_ = kRawProcessHandle;
            return true;
        }

    private:
        HANDLE processHandle_ = nullptr;
    };
    // processPriorityLevelFromActionId:
    // - Converts UI menu IDs to ks::process priority enums;
    // - Input priorityActionId is 0~5;
    // - Returns the corresponding priority; returns Normal for invalid values.
    ks::process::ProcessPriorityLevel processPriorityLevelFromActionId(const int priorityActionId)
    {
        switch (priorityActionId)
        {
        case 0:
            return ks::process::ProcessPriorityLevel::kIdle;
        case 1:
            return ks::process::ProcessPriorityLevel::kBelowNormal;
        case 2:
            return ks::process::ProcessPriorityLevel::kNormal;
        case 3:
            return ks::process::ProcessPriorityLevel::kAboveNormal;
        case 4:
            return ks::process::ProcessPriorityLevel::kHigh;
        case 5:
            return ks::process::ProcessPriorityLevel::kRealtime;
        default:
            return ks::process::ProcessPriorityLevel::kNormal;
        }
    }
}

void ProcessDetailWindow::executeTerminateProcessComboAction()
{
    // Combine end action:
    // - Maintains the same method order as the right-click menu in the process list.
    // - Check after each method execution whether the target has exited to avoid meaningless continued disruption of the scene.
    KLogEvent actionEvent;
    const std::uint32_t kTargetPid = baseRecord_.pid;
    warn << actionEvent
        << "[ProcessDetailWindow] executeTerminateProcessComboAction: pid="
        << kTargetPid
        << eol;

    std::string identityDetailText;
    DetailProcessIdentityHold identityHold;
    if (!identityHold.acquire(kTargetPid, baseRecord_.creationTime100ns, &identityDetailText))
    {
        showActionResultMessage(QStringLiteral("结束进程"), false, identityDetailText, actionEvent);
        return;
    }

    struct TerminateMethodEntry
    {
        const char* methodName = nullptr; // methodName: Method name in logs and results.
        std::function<bool(std::string*)> invokeMethod; // invokeMethod: Actual termination method.
    };

    const std::vector<TerminateMethodEntry> kTerminateMethodList =
    {
        { "TerminateProcess(Kernel32)", [kTargetPid](std::string* detailOut)
            { return ks::process::terminateProcessByWin32(kTargetPid, detailOut); } },
        { "NtTerminateProcess/ZwTerminateProcess", [kTargetPid](std::string* detailOut)
            { return ks::process::terminateProcessByNtNative(kTargetPid, detailOut); } },
        { "WTSTerminateProcess(WTS API)", [kTargetPid](std::string* detailOut)
            { return ks::process::terminateProcessByWtsApi(kTargetPid, detailOut); } },
        { "WinStationTerminateProcess(winsta)", [kTargetPid](std::string* detailOut)
            { return ks::process::terminateProcessByWinStationApi(kTargetPid, detailOut); } },
        { "TerminateJobObject(Job)", [kTargetPid](std::string* detailOut)
            { return ks::process::terminateProcessByJobObject(kTargetPid, detailOut); } },
        { "NtTerminateJobObject/ZwTerminateJobObject", [kTargetPid](std::string* detailOut)
            { return ks::process::terminateProcessByNtJobObject(kTargetPid, detailOut); } },
        { "RmShutdown(Restart Manager)", [kTargetPid](std::string* detailOut)
            { return ks::process::terminateProcessByRestartManager(kTargetPid, false, detailOut); } },
        { "RmShutdown(Restart Manager, force)", [kTargetPid](std::string* detailOut)
            { return ks::process::terminateProcessByRestartManager(kTargetPid, true, detailOut); } },
        { "DuplicateHandle(-1)+TerminateProcess", [kTargetPid](std::string* detailOut)
            { return ks::process::terminateProcessByDuplicateHandlePseudo(kTargetPid, detailOut); } },
        { "TerminateThread(全部线程)", [kTargetPid](std::string* detailOut)
            { return ks::process::terminateAllThreadsByPid(kTargetPid, detailOut); } },
        { "NtTerminateThread/ZwTerminateThread(全部线程)", [kTargetPid](std::string* detailOut)
            { return ks::process::terminateAllThreadsByPidNtNative(kTargetPid, detailOut); } },
        { "DebugActiveProcess 调试附加", [kTargetPid](std::string* detailOut)
            { return ks::process::terminateProcessByDebugAttach(kTargetPid, detailOut); } },
        { "ntsd -c q -p <pid>", [kTargetPid](std::string* detailOut)
            { return ks::process::terminateProcessByNtsdCommand(kTargetPid, detailOut); } },
        { "NtUnmapViewOfSection 卸载 ntdll.dll", [kTargetPid](std::string* detailOut)
            { return ks::process::terminateProcessByNtUnmapNtdll(kTargetPid, detailOut); } }
    };

    bool processExited = false;
    std::ostringstream actionDetailStream;
    actionDetailStream << "pid=" << kTargetPid;
    constexpr int kTerminateRoundLimit = 2;
    for (int roundIndex = 0; roundIndex < kTerminateRoundLimit && !processExited; ++roundIndex)
    {
        const int kRoundNumber = roundIndex + 1;
        for (const TerminateMethodEntry& methodEntry : kTerminateMethodList)
        {
            if (methodEntry.methodName == nullptr || !methodEntry.invokeMethod)
            {
                continue;
            }

            std::string methodDetailText;
            const bool kMethodOk = methodEntry.invokeMethod(&methodDetailText);
            const std::string kNormalizedDetail = methodDetailText.empty() ? "无附加信息" : methodDetailText;
            (kMethodOk ? info : warn) << actionEvent
                << "[ProcessDetailWindow] 组合结束方法执行, pid="
                << kTargetPid
                << ", round="
                << kRoundNumber
                << ", method="
                << methodEntry.methodName
                << ", ok="
                << (kMethodOk ? "true" : "false")
                << ", detail="
                << kNormalizedDetail
                << eol;

            actionDetailStream
                << " | round" << kRoundNumber
                << ":" << methodEntry.methodName
                << "=" << (kMethodOk ? "ok" : "fail")
                << "(" << kNormalizedDetail << ")";

            bool queryOk = false;
            processExited = !detailExtendedProcessStillPresent(kTargetPid, &queryOk);
            if (!queryOk)
            {
                warn << actionEvent
                    << "[ProcessDetailWindow] 组合结束后存在性检查失败，继续下一方法, pid="
                    << kTargetPid
                    << eol;
            }
            if (processExited)
            {
                break;
            }
        }
    }

    showActionResultMessage(
        QStringLiteral("结束进程"),
        processExited,
        actionDetailStream.str(),
        actionEvent);
}

void ProcessDetailWindow::executeSetPriorityActionById(const int priorityActionId)
{
    // Priority menu action:
    // - Allow the Add button/menu to directly specify priority without relying on the current state of the dropdown.
    // - Result still reuses the unified action feedback log.
    KLogEvent actionEvent;
    info << actionEvent
        << "[ProcessDetailWindow] executeSetPriorityActionById: pid="
        << baseRecord_.pid
        << ", actionId="
        << priorityActionId
        << eol;

    std::string detailText;
    DetailProcessIdentityHold identityHold;
    if (!identityHold.acquire(baseRecord_.pid, baseRecord_.creationTime100ns, &detailText))
    {
        showActionResultMessage(QStringLiteral("设置进程优先级"), false, detailText, actionEvent);
        return;
    }
    const bool kActionOk = ks::process::setProcessPriority(
        baseRecord_.pid,
        processPriorityLevelFromActionId(priorityActionId),
        &detailText);
    showActionResultMessage(QStringLiteral("设置进程优先级"), kActionOk, detailText, actionEvent);
}

void ProcessDetailWindow::executeSetEfficiencyModeAction(const bool enableEfficiencyMode)
{
    // Efficiency mode action:
    // - Controlled via Windows ProcessPowerThrottling;
    // - On success, only update the detail window cache; the process list will sync in the next refresh cycle.
    KLogEvent actionEvent;
    info << actionEvent
        << "[ProcessDetailWindow] executeSetEfficiencyModeAction: pid="
        << baseRecord_.pid
        << ", enable="
        << (enableEfficiencyMode ? "true" : "false")
        << eol;

    std::string detailText;
    DetailProcessIdentityHold identityHold;
    if (!identityHold.acquire(baseRecord_.pid, baseRecord_.creationTime100ns, &detailText))
    {
        showActionResultMessage(
            enableEfficiencyMode ? QStringLiteral("开启效率模式") : QStringLiteral("关闭效率模式"),
            false,
            detailText,
            actionEvent);
        return;
    }
    const bool kActionOk = ks::process::setProcessEfficiencyMode(
        baseRecord_.pid,
        enableEfficiencyMode,
        &detailText);
    if (kActionOk)
    {
        baseRecord_.efficiencyModeSupported = true;
        baseRecord_.efficiencyModeEnabled = enableEfficiencyMode;
    }
    showActionResultMessage(
        enableEfficiencyMode ? QStringLiteral("开启效率模式") : QStringLiteral("关闭效率模式"),
        kActionOk,
        detailText,
        actionEvent);
}

void ProcessDetailWindow::executeOpenProcessFolderAction()
{
    // Open directory action:
    // - Prefer querying the current image path by PID to avoid empty cached paths in the detail view.
    // - Log results uniformly without showing additional pop-up windows.
    KLogEvent actionEvent;
    info << actionEvent
        << "[ProcessDetailWindow] executeOpenProcessFolderAction: pid="
        << baseRecord_.pid
        << eol;

    std::string detailText;
    DetailProcessIdentityHold identityHold;
    if (!identityHold.acquire(baseRecord_.pid, baseRecord_.creationTime100ns, &detailText))
    {
        showActionResultMessage(QStringLiteral("打开所在目录"), false, detailText, actionEvent);
        return;
    }
    const bool kActionOk = ks::process::openProcessFolder(baseRecord_.pid, &detailText);
    showActionResultMessage(QStringLiteral("打开所在目录"), kActionOk, detailText, actionEvent);
}

void ProcessDetailWindow::executeRefreshPplProtectionLevelAction()
{
    // Manual PPL refresh:
    // - R3 query for ProcessProtectionLevelInfo;
    // - Only update the current detail page record and text; do not write to cross-wheel caches of other docks.
    KLogEvent actionEvent;
    info << actionEvent
        << "[ProcessDetailWindow] executeRefreshPplProtectionLevelAction: pid="
        << baseRecord_.pid
        << eol;

    std::uint32_t protectionLevel = 0;
    std::string displayText;
    std::string errorText;
    DetailProcessIdentityHold identityHold;
    if (!identityHold.acquire(baseRecord_.pid, baseRecord_.creationTime100ns, &errorText))
    {
        showActionResultMessage(
            QStringLiteral("手动刷新PPL保护级别"),
            false,
            errorText,
            actionEvent);
        return;
    }
    const bool kQueryOk = ks::process::queryProcessProtectionLevelByPid(
        baseRecord_.pid,
        &protectionLevel,
        &displayText,
        &errorText);
    if (kQueryOk)
    {
        baseRecord_.protectionLevel = protectionLevel;
        baseRecord_.protectionLevelKnown = true;
        baseRecord_.protectionLevelText = displayText;
        refreshDetailTabTexts();
    }
    showActionResultMessage(
        QStringLiteral("手动刷新PPL保护级别"),
        kQueryOk,
        kQueryOk ? displayText : errorText,
        actionEvent);
}

void ProcessDetailWindow::executeR0TerminateProcessAction()
{
    // R0 terminate process:
    // - Encapsulates device access control via ArkDriverClient.
    // - exitStatus is fixed at 1, consistent with the list context menu entry.
    KLogEvent actionEvent;
    warn << actionEvent
        << "[ProcessDetailWindow] executeR0TerminateProcessAction: pid="
        << baseRecord_.pid
        << eol;

    ksword::ark::DriverClient driverClient;
    const ksword::ark::IoResult kResult = driverClient.terminateProcess(
        baseRecord_.pid,
        1L,
        baseRecord_.creationTime100ns);
    std::ostringstream detailStream;
    appendExtendedIoResultDetail(kResult, detailStream);
    showActionResultMessage(QStringLiteral("R0结束进程"), kResult.ok, detailStream.str(), actionEvent);
}

void ProcessDetailWindow::executeR0SuspendProcessAction()
{
    // R0 suspend process:
    // - Calls the driver via ArkDriverClient::suspendProcess;
    // - The UI is only responsible for displaying results, not for sending IOCTLs directly.
    KLogEvent actionEvent;
    warn << actionEvent
        << "[ProcessDetailWindow] executeR0SuspendProcessAction: pid="
        << baseRecord_.pid
        << eol;

    ksword::ark::DriverClient driverClient;
    const ksword::ark::IoResult kResult = driverClient.suspendProcess(baseRecord_.pid);
    std::ostringstream detailStream;
    appendExtendedIoResultDetail(kResult, detailStream);
    showActionResultMessage(QStringLiteral("R0挂起进程"), kResult.ok, detailStream.str(), actionEvent);
}

void ProcessDetailWindow::executeR0SetPplProtectionAction(
    const std::uint8_t protectionLevel,
    const QString& levelDisplayText)
{
    // R0 process protection level setting:
    // - protectionLevel is the raw byte of PS_PROTECTION; Type=1 is PPL, Type=2 is full PP.
    // - Prompt for confirmation before the action to avoid mistakenly setting a normal process to a high protection level.
    const int kConfirmResult = QMessageBox::question(
        this,
        QStringLiteral("确认 R0 设置进程保护层级"),
        QStringLiteral("将通过 R0 驱动修改当前进程 PPL/PP（EPROCESS.Protection）字段。\n\n进程: %1 (PID %2)\n目标: %3\n\n错误偏移或系统版本差异可能导致系统不稳定。是否继续？")
            .arg(QString::fromStdString(baseRecord_.processName.empty() ? std::string("Unknown") : baseRecord_.processName))
            .arg(baseRecord_.pid)
            .arg(levelDisplayText),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kConfirmResult != QMessageBox::Yes)
    {
        return;
    }

    KLogEvent actionEvent;
    warn << actionEvent
        << "[ProcessDetailWindow] executeR0SetPplProtectionAction: pid="
        << baseRecord_.pid
        << ", protectionLevel="
        << static_cast<unsigned int>(protectionLevel)
        << eol;

    ksword::ark::DriverClient driverClient;
    const ksword::ark::IoResult kResult = driverClient.setProcessProtection(baseRecord_.pid, protectionLevel);
    std::ostringstream detailStream;
    appendExtendedIoResultDetail(kResult, detailStream);
    showActionResultMessage(QStringLiteral("R0设置进程保护层级"), kResult.ok, detailStream.str(), actionEvent);
}

void ProcessDetailWindow::executeR0SetProcessHiddenAction(
    const bool hidden,
    const unsigned long visibilityFlags)
{
    // R0 recoverable hide:
    // - When hidden=true, selects between only unlinking, only modifying the PID, or the legacy dual-operation based on flags.
    // - When hidden=false, the driver restores the current PID based on the record.
    const QString kConfirmTitle = hidden
        ? QStringLiteral("确认 R0 隐藏当前进程")
        : QStringLiteral("确认 R0 取消隐藏当前进程");
    const QString kConfirmText = hidden
        ? QStringLiteral("将修改当前进程可见性，错误偏移或竞态可能导致系统不稳定。是否继续？")
        : QStringLiteral("将按 Ksword 驱动记录恢复当前进程可见性。是否继续？");
    const int kConfirmResult = QMessageBox::question(
        this,
        kConfirmTitle,
        kConfirmText,
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kConfirmResult != QMessageBox::Yes)
    {
        return;
    }

    KLogEvent actionEvent;
    warn << actionEvent
        << "[ProcessDetailWindow] executeR0SetProcessHiddenAction: pid="
        << baseRecord_.pid
        << ", hidden="
        << (hidden ? "true" : "false")
        << ", flags="
        << visibilityFlags
        << eol;

    ksword::ark::DriverClient driverClient;
    const unsigned long kAction = hidden
        ? KSWORD_ARK_PROCESS_VISIBILITY_ACTION_HIDE
        : KSWORD_ARK_PROCESS_VISIBILITY_ACTION_UNHIDE;
    const ksword::ark::ProcessVisibilityResult kResult =
        driverClient.setProcessVisibility(baseRecord_.pid, kAction, visibilityFlags);
    const bool kActionOk = kResult.io.ok &&
        (kResult.status == KSWORD_ARK_PROCESS_VISIBILITY_STATUS_HIDDEN ||
            kResult.status == KSWORD_ARK_PROCESS_VISIBILITY_STATUS_VISIBLE ||
            kResult.status == KSWORD_ARK_PROCESS_VISIBILITY_STATUS_CLEARED);

    std::ostringstream detailStream;
    appendExtendedIoResultDetail(kResult.io, detailStream);
    detailStream
        << ", status=" << kResult.status
        << ", hiddenCount=" << kResult.hiddenCount
        << ", lastStatus=0x" << std::hex << static_cast<unsigned long>(kResult.lastStatus) << std::dec;
    showActionResultMessage(
        hidden ? QStringLiteral("R0隐藏进程") : QStringLiteral("R0取消隐藏进程"),
        kActionOk,
        detailStream.str(),
        actionEvent);
}

void ProcessDetailWindow::executeR0ClearProcessHiddenAction()
{
    // Clear hidden marker:
    // - This is a global driver state operation, affecting not only the current detail view's PID.
    // - Therefore, a secondary confirmation is required.
    const int kConfirmResult = QMessageBox::question(
        this,
        QStringLiteral("确认清空 R0 隐藏标记"),
        QStringLiteral("将恢复并清空 Ksword 驱动内全部可恢复进程隐藏标记。是否继续？"),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kConfirmResult != QMessageBox::Yes)
    {
        return;
    }

    KLogEvent actionEvent;
    warn << actionEvent
        << "[ProcessDetailWindow] executeR0ClearProcessHiddenAction"
        << eol;

    ksword::ark::DriverClient driverClient;
    const ksword::ark::ProcessVisibilityResult kResult =
        driverClient.setProcessVisibility(0, KSWORD_ARK_PROCESS_VISIBILITY_ACTION_CLEAR_ALL, 0UL);
    const bool kActionOk = kResult.io.ok &&
        kResult.status == KSWORD_ARK_PROCESS_VISIBILITY_STATUS_CLEARED;
    std::ostringstream detailStream;
    appendExtendedIoResultDetail(kResult.io, detailStream);
    detailStream
        << ", status=" << kResult.status
        << ", hiddenCount=" << kResult.hiddenCount
        << ", lastStatus=0x" << std::hex << static_cast<unsigned long>(kResult.lastStatus) << std::dec;
    showActionResultMessage(QStringLiteral("R0清空隐藏标记"), kActionOk, detailStream.str(), actionEvent);
}

void ProcessDetailWindow::executeR0SetBreakOnTerminationAction(const bool enabled)
{
    // BreakOnTermination：
    // - Enabling this may trigger system crash protection when the target process exits.
    // - When disabled, the flag is also cleared via the driver path.
    const int kConfirmResult = QMessageBox::question(
        this,
        enabled ? QStringLiteral("确认启用 BreakOnTermination") : QStringLiteral("确认关闭 BreakOnTermination"),
        enabled
            ? QStringLiteral("将把当前进程设为关键进程，目标退出可能触发系统崩溃保护。是否继续？")
            : QStringLiteral("将清除当前进程的 BreakOnTermination。是否继续？"),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kConfirmResult != QMessageBox::Yes)
    {
        return;
    }

    KLogEvent actionEvent;
    warn << actionEvent
        << "[ProcessDetailWindow] executeR0SetBreakOnTerminationAction: pid="
        << baseRecord_.pid
        << ", enabled="
        << (enabled ? "true" : "false")
        << eol;

    const unsigned long kAction = enabled
        ? KSWORD_ARK_PROCESS_SPECIAL_ACTION_ENABLE_BREAK_ON_TERMINATION
        : KSWORD_ARK_PROCESS_SPECIAL_ACTION_DISABLE_BREAK_ON_TERMINATION;
    ksword::ark::DriverClient driverClient;
    const ksword::ark::ProcessSpecialFlagsResult kResult =
        driverClient.setProcessSpecialFlags(
            baseRecord_.pid,
            kAction,
            0UL,
            baseRecord_.creationTime100ns);
    const bool kActionOk = kResult.io.ok &&
        kResult.status == KSWORD_ARK_PROCESS_SPECIAL_STATUS_APPLIED;
    std::ostringstream detailStream;
    appendExtendedIoResultDetail(kResult.io, detailStream);
    detailStream
        << ", status=" << kResult.status
        << ", appliedFlags=" << kResult.appliedFlags
        << ", touchedThreadCount=" << kResult.touchedThreadCount
        << ", lastStatus=0x" << std::hex << static_cast<unsigned long>(kResult.lastStatus) << std::dec;
    showActionResultMessage(
        enabled ? QStringLiteral("R0启用BreakOnTermination") : QStringLiteral("R0关闭BreakOnTermination"),
        kActionOk,
        detailStream.str(),
        actionEvent);
}

void ProcessDetailWindow::executeR0DisableApcInsertionAction()
{
    // Prevent APC insertion:
    // - Only handle the ApcQueueable bit for threads that already exist.
    // - New threads do not automatically inherit this state.
    const int kConfirmResult = QMessageBox::question(
        this,
        QStringLiteral("确认 R0 禁止 APC 插入"),
        QStringLiteral("将清除当前进程现有线程的 ApcQueueable 位。新建线程不自动继承。是否继续？"),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kConfirmResult != QMessageBox::Yes)
    {
        return;
    }

    KLogEvent actionEvent;
    warn << actionEvent
        << "[ProcessDetailWindow] executeR0DisableApcInsertionAction: pid="
        << baseRecord_.pid
        << eol;

    ksword::ark::DriverClient driverClient;
    const ksword::ark::ProcessSpecialFlagsResult kResult =
        driverClient.setProcessSpecialFlags(
            baseRecord_.pid,
            KSWORD_ARK_PROCESS_SPECIAL_ACTION_DISABLE_APC_INSERTION,
            0UL,
            baseRecord_.creationTime100ns);
    const bool kActionOk = kResult.io.ok &&
        kResult.status == KSWORD_ARK_PROCESS_SPECIAL_STATUS_APPLIED;
    std::ostringstream detailStream;
    appendExtendedIoResultDetail(kResult.io, detailStream);
    detailStream
        << ", status=" << kResult.status
        << ", appliedFlags=" << kResult.appliedFlags
        << ", touchedThreadCount=" << kResult.touchedThreadCount
        << ", lastStatus=0x" << std::hex << static_cast<unsigned long>(kResult.lastStatus) << std::dec;
    showActionResultMessage(QStringLiteral("R0禁止APC插入"), kActionOk, detailStream.str(), actionEvent);
}

void ProcessDetailWindow::executeR0DkomRemoveFromCidTableAction()
{
    // DKOM CID deletion:
    // - This action cannot be restored via the current menu;
    // - Forces confirmation before the operation; results are logged only.
    const int kConfirmResult = QMessageBox::question(
        this,
        QStringLiteral("确认 DKOM 删除 PspCidTable"),
        QStringLiteral("将从 PspCidTable 删除当前进程 CID 表项。\n\n该动作不可通过当前菜单恢复，可能破坏句柄/PID 查询语义或导致蓝屏。是否继续？"),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kConfirmResult != QMessageBox::Yes)
    {
        return;
    }

    KLogEvent actionEvent;
    warn << actionEvent
        << "[ProcessDetailWindow] executeR0DkomRemoveFromCidTableAction: pid="
        << baseRecord_.pid
        << eol;

    ksword::ark::DriverClient driverClient;
    const ksword::ark::ProcessDkomResult kResult =
        driverClient.dkomProcess(
            baseRecord_.pid,
            KSWORD_ARK_PROCESS_DKOM_ACTION_REMOVE_FROM_PSP_CID_TABLE);
    const bool kActionOk = kResult.io.ok &&
        kResult.status == KSWORD_ARK_PROCESS_DKOM_STATUS_REMOVED;
    std::ostringstream detailStream;
    appendExtendedIoResultDetail(kResult.io, detailStream);
    detailStream
        << ", status=" << kResult.status
        << ", removedEntries=" << kResult.removedEntries
        << ", lastStatus=0x" << std::hex << static_cast<unsigned long>(kResult.lastStatus) << std::dec
        << ", pspCidTable=0x" << std::hex << kResult.pspCidTableAddress
        << ", eprocess=0x" << kResult.processObjectAddress << std::dec;
    showActionResultMessage(QStringLiteral("R0 DKOM PspCidTable删除"), kActionOk, detailStream.str(), actionEvent);
}
