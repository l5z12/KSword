#include "ProcessDock.Support.h"
#include "ProcessActivityChartWidget.h"
#include "ProcessActivityTimelineSlider.h"

using namespace ksword::ui::process_dock;

void ProcessDock::showTableContextMenu(const QPoint& localPosition)
{
    const QModelIndex kClickedIndex = processTable_->indexAt(localPosition);
    if (!kClickedIndex.isValid())
    {
        clearContextActionBinding();
        return;
    }

    const ProcessTableRow* clickedTableRow = processTableRowForViewIndex(kClickedIndex);
    if (clickedTableRow == nullptr || clickedTableRow->rowKind == ProcessTableRowKind::kGroupHeader)
    {
        clearContextActionBinding();
        return;
    }

    // Right-click behavior:
    // - If the right-click point is within the existing multi-selection set, keep the set unchanged; menu actions apply to all selected rows.
    // - If the right-click occurs on an unselected row, switch selection to that single row to maintain the traditional right-click experience.
    if (QItemSelectionModel* selectionModel = processTable_->selectionModel())
    {
        const bool kClickedRowAlreadySelected = selectionModel->isRowSelected(kClickedIndex.row(), kClickedIndex.parent());
        if (!kClickedRowAlreadySelected)
        {
            selectionModel->clearSelection();
            selectionModel->select(kClickedIndex, QItemSelectionModel::Select | QItemSelectionModel::Rows);
        }
        selectionModel->setCurrentIndex(kClickedIndex, QItemSelectionModel::NoUpdate);
    }

    bindContextActionToIndex(kClickedIndex);
    const std::vector<ProcessActionTarget> kContextActionTargets = selectedActionTargets();
    const bool kHasBatchSelection = kContextActionTargets.size() > 1;
    const ks::process::ProcessRecord* contextProcessRecord =
        kContextActionTargets.empty() ? nullptr : &kContextActionTargets.front().record;
    DWORD contextIntegrityRid = 0;
    std::string contextIntegrityDetailText;
    const bool kContextIntegrityKnown = contextProcessRecord != nullptr &&
        queryProcessIntegrityRid(
            contextProcessRecord->pid,
            &contextIntegrityRid,
            &contextIntegrityDetailText);

    QMenu contextMenu(this);
    // Explicit context menu styling: avoid black background and black text in light mode under transparent parent controls.
    contextMenu.setStyleSheet(buildThreadContextMenuStyle());

    // R0 actions continue to use the corresponding business icons; action text and grouping clearly indicate the R0 source.
    const auto kBuildR0ActionIcon = [this](const char* iconPath) -> QIcon
    {
        return blueTintedIcon(iconPath);
    };

    QAction* copyCellAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_copy_cell.svg"),
        processContextText("process.menu.copy_cell", QStringLiteral("复制单元格")));
    QAction* copyRowAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_copy_row.svg"),
        processContextText("process.menu.copy_row", QStringLiteral("复制行")));
    contextMenu.addSeparator();
    if (kHasBatchSelection)
    {
        QAction* batchHintAction = contextMenu.addAction(
            blueTintedIcon(":/Icon/process_list.svg"),
            processContextText(
                "process.menu.batch_hint",
                QStringLiteral("已选择 %1 个进程，支持批量动作")).arg(kContextActionTargets.size()));
        batchHintAction->setEnabled(false);
        contextMenu.addSeparator();
    }

    // Termination action area:
    // - Removed the 'Terminate Process' submenu and promoted it to a top-level action;
    // - The process tree target is derived solely from the parent PID relationships in the current R3 snapshot; R0 is not involved in identification.
    // - Terminating a process and its process tree both reuse the same R3→R0 combination chain.
    QAction* terminateProcessAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_terminate.svg"),
        processContextText("process.menu.r3_terminate", QStringLiteral("R3 结束进程")));
    terminateProcessAction->setToolTip(processContextText(
        "process.menu.r3_terminate.tooltip",
        QStringLiteral("只走用户态的十四种结束方法（两轮），不调用驱动。全部失败也不会自动退到 R0——要用驱动请选下面那两项。")));
    QAction* terminateAndDeleteImageAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_terminate.svg"),
        processContextText(
            "process.menu.terminate_delete_image",
            QStringLiteral("结束进程并删除映像文件")));
    const bool kCanDeleteSingleImage = kContextActionTargets.size() == 1U &&
        kContextActionTargets.front().record.pid != 0U &&
        kContextActionTargets.front().record.creationTime100ns != 0U &&
        !kContextActionTargets.front().record.imagePath.empty();
    terminateAndDeleteImageAction->setEnabled(kCanDeleteSingleImage);
    terminateAndDeleteImageAction->setToolTip(
        kCanDeleteSingleImage
            ? processContextText(
                "process.menu.terminate_delete_image.tooltip",
                QStringLiteral("绑定当前 PID 创建时间和文件 ID；确认退出后删除同一映像文件对象"))
            : processContextText(
                "process.menu.terminate_delete_image.unavailable",
                QStringLiteral("仅支持单选且必须具有可验证的 PID 创建时间与映像路径")));
    QAction* terminateProcessTreeAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_terminate.svg"),
        processContextText("process.menu.r3_terminate_tree", QStringLiteral("R3 结束进程树")));
    /*
     * The two R0 items were folded into the R3 chain rollback in commit 0dbbeaf1 on 2026-09-16. Here, we restore them as
     * independent entries based on the earlier implementation: if any R3 method succeeds, the folded R0 path is never executed,
     * making it impossible to initiate 'terminate using R0 only' and preventing independent verification of the driver path.
     */
    QAction* r0TerminateAction = contextMenu.addAction(
        kBuildR0ActionIcon(":/Icon/process_terminate.svg"),
        processContextText("process.menu.r0_terminate", QStringLiteral("R0结束进程")));
    r0TerminateAction->setToolTip(processContextText(
        "process.menu.r0_terminate.tooltip",
        QStringLiteral("只下发驱动的结束 IOCTL，不跑任何用户态方法。驱动侧本身是四步：先清 PP/PPL 保护字节，再 ZwTerminateProcess、逐线程终止、清零可写用户内存。注意保护字节清零之后不会还原。")));
    QAction* r0TerminateTreeAction = contextMenu.addAction(
        kBuildR0ActionIcon(":/Icon/process_terminate.svg"),
        processContextText("process.menu.r0_terminate_tree", QStringLiteral("R0结束进程树")));
    /*
     * R-1 items follow the display name in the upper right corner (KVM / HVM / R-1).
     *
     * Read settings fresh each time the menu is built rather than caching: this name can be changed at any time in the settings page. Caching
     * it would cause the menu to display one name while the top-right corner displays another, even though both refer to the same capability.
     */
    const QString kHvmName = ks::settings::hvmDisplayNameLabel(
        ks::settings::loadAppearanceSettings().hvmDisplayName);
    /*
     * R-1 and DMA operations grouped into a single submenu.
     *
     * The difference between these and the R3/R0 items above is not 'stronger', but **completely different
     * mechanisms**, leading to different failure modes and side effects: R-1 relies on EPT to deny execution and
     * inject #PF/#UD, leaving the process state unchanged by a single byte; the guest converts the unhandled
     * exception into process termination. DMA directly modifies real pages, having no trigger point and no
     * process scope. Laying them flat alongside R3/R0 implies they are merely 'a more aggressive button'.
     */
    QMenu* ringMinusOneSubMenu = contextMenu.addMenu(
        kBuildR0ActionIcon(":/Icon/process_terminate.svg"),
        processContextText("process.menu.ring_minus_one_group", QStringLiteral("%1 / DMA 进程操作"))
            .arg(kHvmName));
    QAction* hvmFreezeAction = ringMinusOneSubMenu->addAction(
        kBuildR0ActionIcon(":/Icon/process_suspend.svg"),
        processContextText("process.menu.hvm_freeze", QStringLiteral("%1 冻结进程（可逆）"))
            .arg(kHvmName));
    QAction* hvmTerminateAction = ringMinusOneSubMenu->addAction(
        kBuildR0ActionIcon(":/Icon/process_terminate.svg"),
        processContextText("process.menu.hvm_terminate", QStringLiteral("%1 结束进程"))
            .arg(kHvmName));
    hvmTerminateAction->setToolTip(processContextText(
        "process.menu.hvm_terminate.tooltip",
        QStringLiteral("靠 EPT 拒绝执行并注入 #UD，RIP 不动。我们不杀进程，是客户机自己把这个未处理异常变成了进程终止。")));
    QAction* hvmReleaseAction = ringMinusOneSubMenu->addAction(
        kBuildR0ActionIcon(":/Icon/process_refresh.svg"),
        processContextText("process.menu.hvm_release", QStringLiteral("%1 解除（冻结/结束）"))
            .arg(kHvmName));
    QAction* hvmInjectAction = ringMinusOneSubMenu->addAction(
        kBuildR0ActionIcon(":/Icon/process_terminate.svg"),
        processContextText("process.menu.hvm_inject", QStringLiteral("%1 注入 DLL"))
            .arg(kHvmName));
    QAction* hvmInjectReleaseAction = ringMinusOneSubMenu->addAction(
        kBuildR0ActionIcon(":/Icon/process_refresh.svg"),
        processContextText("process.menu.hvm_inject_release", QStringLiteral("%1 撤销注入"))
            .arg(kHvmName));
    ringMinusOneSubMenu->addSeparator();
    QAction* dmaProcessOpAction = ringMinusOneSubMenu->addAction(
        kBuildR0ActionIcon(":/Icon/process_terminate.svg"),
        processContextText("process.menu.dma_process_op", QStringLiteral("DMA 注入 / 写 UD2…")));
    dmaProcessOpAction->setToolTip(processContextText(
        "process.menu.dma_process_op.tooltip",
        QStringLiteral("打开 DMA 进程操作窗口。DMA 改的是真页、没有触发点、也没有进程作用域——写入前会先证明目标页不被其它进程共享，确认共享的直接拒绝。")));

    /*
     * Advanced terminate: List each method in the combination chain separately.
     *
     * The rationale is **traceability**, not enhanced capability: running all fourteen methods in two
     * batches means success leaves you unaware of which method worked, and failure leaves you unaware
     * of which was closest. Running one method at a time ensures the log entry is a clean reading.
     *
     * Entries are generated directly by terminateMethodTable(); no separate name list is written. Maintaining two lists would inevitably
     * cause them to drift, leading to errors where the menu displays 'A' but actually executes 'B' without raising an exception.
     */
    QMenu* advancedTerminateSubMenu = contextMenu.addMenu(
        blueTintedIcon(":/Icon/process_terminate.svg"),
        processContextText("process.menu.advanced_terminate", QStringLiteral("高级结束进程（逐方法）")));
    advancedTerminateSubMenu->setToolTipsVisible(true);
    std::vector<QAction*> advancedTerminateActions;
    advancedTerminateActions.reserve(terminateMethodTable().size());
    for (std::size_t methodIndex = 0; methodIndex < terminateMethodTable().size(); ++methodIndex)
    {
        const TerminateMethodEntry& entry = terminateMethodTable()[methodIndex];
        QAction* const kMethodAction = advancedTerminateSubMenu->addAction(
            QString::fromUtf8(entry.methodName));
        kMethodAction->setToolTip(processContextText(
            "process.menu.advanced_terminate.item_tooltip",
            QStringLiteral("只执行这一种方法一次，不跑其余方法、也不退到 R0。结果与细节写进日志面板。")));
        advancedTerminateActions.push_back(kMethodAction);
    }
    // The lines below are not R3. These entries bypass the upper loop because they are not in terminateMethodTable():
    // each entry in that table has the signature (pid, detail*), but the R0 entry requires the creation time for PID
    // reuse validation. Including it in the table would force dropping that parameter—validation would be lost,
    // causing no error but potentially terminating the wrong process if the PID is reused.
    //
    // Draws a line only, no text: This menu's stylesheet handles QMenu::separator with a fixed height of 1px.
    // QMenu::addSection text has no rendering location; writing it will not display.
    advancedTerminateSubMenu->addSeparator();
    QAction* advancedR0OnlyAction = advancedTerminateSubMenu->addAction(
        kBuildR0ActionIcon(":/Icon/process_terminate.svg"),
        processContextText("process.menu.advanced_terminate_r0",
                           QStringLiteral("R0 驱动结束（四步：清保护 → ZwTerminate → 逐线程 → 清零内存）")));
    QAction* advancedHvmOnlyAction = advancedTerminateSubMenu->addAction(
        kBuildR0ActionIcon(":/Icon/process_terminate.svg"),
        processContextText("process.menu.advanced_terminate_hvm",
                           QStringLiteral("%1 结束（EPT 拒绝执行 + 注入 #UD）")).arg(kHvmName));
    QAction* advancedDmaAction = advancedTerminateSubMenu->addAction(
        kBuildR0ActionIcon(":/Icon/process_terminate.svg"),
        processContextText("process.menu.advanced_terminate_dma",
                           QStringLiteral("DMA 写 UD2（需指定地址，打开窗口）")));
    QAction* screenInjectionSurfaceAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_details.svg"),
        processContextText("process.menu.screen_injection_surface",
                           QStringLiteral("筛选注入面（填充注入面列）")));
    screenInjectionSurfaceAction->setToolTip(processContextText(
        "process.menu.screen_injection_surface.tooltip",
        QStringLiteral("只读枚举选中进程的地址空间，数出动态/非映像可执行区域。这是计数不是结论——实测绝大多数进程都有动态代码，能看的是数量的离群程度。要完整结论请开进程详情→模块→注入痕迹检查")));
    QAction* refreshPplLevelAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_refresh.svg"),
        processContextText("process.menu.refresh_ppl", QStringLiteral("手动刷新PPL保护级别")));
    refreshPplLevelAction->setToolTip(QStringLiteral("查询 ProcessProtectionLevelInfo；结果只更新当前列表快照，不写入跨轮缓存。"));
    QMenu* r0PplLevelSubMenu = contextMenu.addMenu(
        kBuildR0ActionIcon(":/Icon/process_critical.svg"),
        processContextText("process.menu.set_ppl", QStringLiteral("R0设置进程保护(PPL/PP)")));
    QAction* r0PplNoneAction = r0PplLevelSubMenu->addAction(
        kBuildR0ActionIcon(":/Icon/process_critical.svg"),
        processContextText("process.menu.close_ppl", QStringLiteral("关闭进程保护 (0x00)")));
    r0PplNoneAction->setData(0x00U);
    // Protection presets:
    // - signer naming/values align with PPLcontrol's PsProtectedSigner*.
    // - protectionLevel = (Signer << 4) | Type; Type=1 indicates PPL, Type=2 indicates full PP.
    // - Under the same signer, PP is stronger than PPL: PPL processes cannot obtain high-privilege handles from PP processes.
    struct ProcessProtectionSignerPreset
    {
        int signerValue;         // signerValue: Signer value (1~7).
        const char* signerName;  // signerName: Menu display name.
        const char* meaningText; // meaningText: Menu display explanation.
    };
    const ProcessProtectionSignerPreset kPresetList[] =
    {
        { 1, "Authenticode", "签名代码（Authenticode）" },
        { 2, "CodeGen", "动态代码生成" },
        { 3, "Antimalware", "反恶意软件" },
        { 4, "Lsa", "本地安全机构" },
        { 5, "Windows", "Windows 组件" },
        { 6, "WinTcb", "可信计算基础（最高）" },
        { 7, "WinSystem", "系统 signer（System 进程同级）" }
    };
    struct ProcessProtectionTypePreset
    {
        unsigned int typeValue;     // typeValue: PS_PROTECTION type bits.
        const char* sectionTextUtf8; // sectionTextUtf8: group title.
    };
    const ProcessProtectionTypePreset kTypeList[] =
    {
        { 1U, "PPL 轻量保护（Type=1）" },
        { 2U, "PP 完整保护（Type=2，更强）" }
    };
    for (const ProcessProtectionTypePreset& typeEntry : kTypeList)
    {
        r0PplLevelSubMenu->addSection(QString::fromUtf8(typeEntry.sectionTextUtf8));
        for (const ProcessProtectionSignerPreset& presetEntry : kPresetList)
        {
            const unsigned int kProtectionLevel =
                (static_cast<unsigned int>(presetEntry.signerValue) << 4U) | typeEntry.typeValue;
            const QString kProtectionLevelHexText = QStringLiteral("0x%1")
                .arg(kProtectionLevel, 2, 16, QChar('0'))
                .toUpper();
            QAction* presetAction = r0PplLevelSubMenu->addAction(
                kBuildR0ActionIcon(":/Icon/process_critical.svg"),
                QStringLiteral("%1 (%2) → %3 [%4]")
                .arg(QString::fromLatin1(presetEntry.signerName))
                .arg(presetEntry.signerValue)
                .arg(QString::fromUtf8(presetEntry.meaningText))
                .arg(kProtectionLevelHexText));
            presetAction->setData(kProtectionLevel);
        }
    }
    QMenu* r0VisibilitySubMenu = contextMenu.addMenu(
        kBuildR0ActionIcon(":/Icon/process_details.svg"),
        processContextText("process.menu.hide", QStringLiteral("R0进程隐藏(可恢复)")));
    QAction* r0HideUnlinkOnlyAction = r0VisibilitySubMenu->addAction(
        kBuildR0ActionIcon(":/Icon/process_suspend.svg"),
        processContextText("process.menu.hide_unlink", QStringLiteral("隐藏选中进程：只断链")));
    QAction* r0HidePatchPidOnlyAction = r0VisibilitySubMenu->addAction(
        kBuildR0ActionIcon(":/Icon/process_uncritical.svg"),
        processContextText("process.menu.hide_pid", QStringLiteral("隐藏选中进程：只改PID")));
    QAction* r0HideLegacyBothAction = r0VisibilitySubMenu->addAction(
        kBuildR0ActionIcon(":/Icon/process_critical.svg"),
        processContextText("process.menu.hide_legacy", QStringLiteral("隐藏选中进程：改PID+断链(旧版高风险)")));
    r0VisibilitySubMenu->addSeparator();
    QAction* r0UnhideProcessAction = r0VisibilitySubMenu->addAction(
        kBuildR0ActionIcon(":/Icon/process_resume.svg"),
        processContextText("process.menu.unhide", QStringLiteral("取消隐藏选中进程")));
    QAction* r0ClearHiddenProcessAction = r0VisibilitySubMenu->addAction(
        kBuildR0ActionIcon(":/Icon/log_clear.svg"),
        processContextText("process.menu.clear_hidden", QStringLiteral("清空全部隐藏标记")));
    r0HideUnlinkOnlyAction->setToolTip(QStringLiteral("只摘除 ActiveProcessLinks，不修改 PID；Ksword 更容易按原 PID 找回和恢复。"));
    r0HidePatchPidOnlyAction->setToolTip(QStringLiteral("只修改 UniqueProcessId，不摘链；高风险，可能影响按原 PID 查找目标。"));
    r0HideLegacyBothAction->setToolTip(QStringLiteral("兼容旧版：同时修改 UniqueProcessId 并摘除 ActiveProcessLinks；风险最高，仅用于复现实验。"));
    r0UnhideProcessAction->setToolTip(QStringLiteral("恢复由 Ksword 记录的 UniqueProcessId 和进程链表位置；若原位置不再相邻，则挂回 System 链头后。"));
    r0ClearHiddenProcessAction->setToolTip(QStringLiteral("恢复所有由 Ksword 摘链的进程，并清空驱动内记录。"));
    QMenu* criticalProcessSubMenu = contextMenu.addMenu(
        blueTintedIcon(":/Icon/process_critical.svg"),
        processContextText("process.menu.critical", QStringLiteral("关键进程 / BreakOnTermination")));
    QAction* setCriticalAction = criticalProcessSubMenu->addAction(
        blueTintedIcon(":/Icon/process_critical.svg"),
        processContextText("process.menu.r3_critical", QStringLiteral("R3设为关键进程")));
    QAction* clearCriticalAction = criticalProcessSubMenu->addAction(
        blueTintedIcon(":/Icon/process_uncritical.svg"),
        processContextText("process.menu.r3_uncritical", QStringLiteral("R3取消关键进程")));
    criticalProcessSubMenu->addSeparator();
    QAction* r0EnableBreakAction = criticalProcessSubMenu->addAction(
        kBuildR0ActionIcon(":/Icon/process_critical.svg"),
        processContextText("process.menu.r0_break", QStringLiteral("R0启用 BreakOnTermination")));
    QAction* r0DisableBreakAction = criticalProcessSubMenu->addAction(
        kBuildR0ActionIcon(":/Icon/process_uncritical.svg"),
        processContextText("process.menu.r0_unbreak", QStringLiteral("R0关闭 BreakOnTermination")));
    setCriticalAction->setToolTip(QStringLiteral("将进程标记为关键进程；意外终止可能导致系统崩溃。"));
    clearCriticalAction->setToolTip(QStringLiteral("取消进程的关键标记。"));
    r0EnableBreakAction->setToolTip(QStringLiteral("将进程标记为关键进程；意外终止可能导致系统崩溃。"));
    r0DisableBreakAction->setToolTip(QStringLiteral("取消进程的关键标记。"));
    QMenu* r0DangerSubMenu = contextMenu.addMenu(
        kBuildR0ActionIcon(":/Icon/process_uncritical.svg"),
        processContextText("process.menu.danger", QStringLiteral("R0危险进程标志/DKOM")));
    QAction* r0DisableApcAction = r0DangerSubMenu->addAction(
        kBuildR0ActionIcon(":/Icon/process_suspend.svg"),
        processContextText("process.menu.disable_apc", QStringLiteral("禁止APC插入(现有线程)")));
    QAction* r0DkomCidRemoveAction = r0DangerSubMenu->addAction(
        kBuildR0ActionIcon(":/Icon/process_uncritical.svg"),
        processContextText("process.menu.remove_cid", QStringLiteral("DKOM从PspCidTable删除")));
    r0DisableApcAction->setToolTip(QStringLiteral("清除目标进程现有线程 ETHREAD ApcQueueable 位；新建线程不自动继承。"));
    r0DkomCidRemoveAction->setToolTip(QStringLiteral("从 PspCidTable 清零目标 EPROCESS 的 CID 表项；高风险且不可通过本菜单恢复。"));
    contextMenu.addSeparator();

    /*
     * Suspended and Efficiency Mode are both **switches**, not actions, so each is implemented as a toggleable option:
     * Checked means suspended/started; click to toggle to the other state.
     *
     * The checked state is derived from processStateKnown/processSuspended; these fields are computed directly
     * from the thread array in SystemProcessInformation without opening a process handle or requiring privileges.
     * Thus, the state is known even on protected processes, and the checkbox will not display a fabricated status.
     * Only pathological cases like buffer overflows are considered unknown; in such cases, display as unchecked (i.e., clicking implies suspended).
     *
     * The icon is shown **only when unchecked**. In Qt menu items, the icon and checkmark share the same column: if an icon is set,
     * it is drawn; in the checked state, the selection box below the icon is used instead, and the menu's stylesheet takes over.
     * For QMenu::item, the box may not be drawn at all, hiding the checkmark. Omit icons on checked
     * items to reserve the column for their checkmarks; unchecked items keep their original icons.
     *
     * The menu is rebuilt on every right-click, so the checked state is determined during construction; thus, a
     * single null check here suffices, and no icon update is needed after clicking since the menu closes immediately.
     */
    const bool kContextProcessSuspended =
        contextProcessRecord != nullptr
        && contextProcessRecord->processStateKnown
        && contextProcessRecord->processSuspended;
    QAction* suspendToggleAction = contextMenu.addAction(
        processContextText("process.menu.suspend", QStringLiteral("挂起进程")));
    suspendToggleAction->setCheckable(true);
    suspendToggleAction->setChecked(kContextProcessSuspended);
    if (!kContextProcessSuspended)
    {
        suspendToggleAction->setIcon(blueTintedIcon(":/Icon/process_suspend.svg"));
    }
    /*
     * R0 suspend is grouped with R3 suspend/resume, not with the terminate group.
     *
     * Group menu items by **action** rather than implementation layer: a user wanting to
     * suspend a process looks for "Suspend", not whether it's R3 or R0. Grouping by layer
     * scatters the same action across opposite ends of the menu, leaving each end incomplete.
     */
    QAction* r0SuspendToggleAction = contextMenu.addAction(
        processContextText("process.menu.r0_suspend", QStringLiteral("R0挂起进程")));
    r0SuspendToggleAction->setCheckable(true);
    r0SuspendToggleAction->setChecked(kContextProcessSuspended);
    if (!kContextProcessSuspended)
    {
        r0SuspendToggleAction->setIcon(kBuildR0ActionIcon(":/Icon/process_suspend.svg"));
    }
    r0SuspendToggleAction->setToolTip(processContextText(
        "process.menu.r0_suspend.tooltip",
        QStringLiteral("走驱动的 PsSuspendProcess，取不到则退到 Zw/NtSuspendProcess。取消勾选走 PsResumeProcess。勾选态与上面那条共用同一个读数——它反映的是进程当前是否挂起，不表示是谁挂的。")));
    const bool kContextEfficiencyModeEnabled =
        contextProcessRecord != nullptr
        && contextProcessRecord->efficiencyModeSupported
        && contextProcessRecord->efficiencyModeEnabled;
    QAction* efficiencyToggleAction = contextMenu.addAction(
        processContextText("process.menu.efficiency", QStringLiteral("效率模式（绿叶）")));
    efficiencyToggleAction->setCheckable(true);
    efficiencyToggleAction->setChecked(kContextEfficiencyModeEnabled);
    if (!kContextEfficiencyModeEnabled)
    {
        efficiencyToggleAction->setIcon(blueTintedIcon(":/Icon/process_resume.svg"));
    }
    QAction* openFolderAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_open_folder.svg"),
        processContextText("process.menu.open_folder", QStringLiteral("打开所在目录")));
    QMenu* gotoSubMenu = contextMenu.addMenu(
        blueTintedIcon(":/Icon/process_details.svg"),
        QStringLiteral("转到"));
    QAction* openHandleAction = gotoSubMenu->addAction(
        blueTintedIcon(":/Icon/process_list.svg"), QStringLiteral("句柄"));
    QAction* openMemoryAction = gotoSubMenu->addAction(
        blueTintedIcon(":/Icon/process_details.svg"), QStringLiteral("内存"));
    QAction* openNetworkAction = gotoSubMenu->addAction(
        blueTintedIcon(":/Icon/process_main.svg"), QStringLiteral("网络"));
    QAction* openWindowAction = gotoSubMenu->addAction(
        blueTintedIcon(":/Icon/process_tree.svg"), QStringLiteral("窗口"));
    QAction* openMessageHooksAction = gotoSubMenu->addAction(
        blueTintedIcon(":/Icon/process_list.svg"),
        processContextText("process.menu.message_hooks", QStringLiteral("消息 Hook")));
    openMessageHooksAction->setToolTip(processContextText(
        "process.menu.message_hooks.tooltip",
        QStringLiteral("默认显示作用于该进程线程的非全局 Hook；窗口内可切换为安装者或双侧相关范围。")));
    openMemoryAction->setEnabled(!kHasBatchSelection);
    openMessageHooksAction->setEnabled(
        !kHasBatchSelection &&
        contextProcessRecord != nullptr &&
        contextProcessRecord->pid != 0U);
    if (kHasBatchSelection)
    {
        openMemoryAction->setToolTip(QStringLiteral("内存页一次只能附加一个进程。"));
        openMessageHooksAction->setToolTip(processContextText(
            "process.menu.message_hooks.single.tooltip",
            QStringLiteral("消息 Hook 窗口一次只能绑定一个进程。")));
    }
    QAction* injectionPageAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_priority.svg"),
        processContextText("process.menu.injection", QStringLiteral("DLL/Shellcode 注入")));
    injectionPageAction->setToolTip(QStringLiteral("打开进程详细信息并直达“操作”页的 DLL/Shellcode 注入区域。"));
    injectionPageAction->setEnabled(!kHasBatchSelection);
    QAction* scanHotkeyAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_refresh.svg"),
        processContextText("process.menu.hotkeys", QStringLiteral("扫描进程热键")));
    scanHotkeyAction->setToolTip(QStringLiteral("打开进程详细信息并直达“进程热键”页，扫描窗口热键、菜单快捷键、Accelerator、快捷方式和R0热键表。"));
    scanHotkeyAction->setEnabled(!kHasBatchSelection);

    // Token privileges submenu:
    // - Both queries and adjustments execute in the thread pool to avoid blocking the GUI with OpenProcessToken/AdjustTokenPrivileges.
    // - Each item uses a QWidgetAction to host a borderless QPushButton; a prefix displays the check state, and the menu remains expanded after clicking.
    // - When multiple items are selected, the privilege toggle is allowed only if all targets possess this privilege; a single click immediately submits to all targets.
    QMenu* privilegeSubMenu = contextMenu.addMenu(
        blueTintedIcon(":/Icon/process_critical.svg"),
        processContextText("process.menu.privileges", QStringLiteral("令牌特权")));
    privilegeSubMenu->setStyleSheet(buildThreadContextMenuStyle());
    privilegeSubMenu->setToolTipsVisible(true);
    privilegeSubMenu->setToolTip(processContextText(
        "process.menu.privileges.tooltip",
        QStringLiteral("点击切换全部选中进程的令牌特权；菜单会保持展开，便于连续调整。")));
    QAction* privilegeLoadingAction = privilegeSubMenu->addAction(
        processContextText(
            "process.menu.privileges.querying",
            QStringLiteral("正在查询令牌特权...")));
    privilegeLoadingAction->setEnabled(false);

    struct ContextPrivilegeTargetState
    {
        std::uint32_t processId = 0;
        std::uint64_t creationTime100ns = 0;
        std::string processName;
        bool querySucceeded = false;
        bool usedR0 = false;
        std::vector<ks::process::TokenPrivilegeInfo> privileges;
        std::string detailText;
    };
    struct ContextPrivilegeAdjustResult
    {
        std::size_t targetIndex = 0U;
        bool succeeded = false;
        bool r0Attempted = false;
        std::string detailText;
        std::string r3DetailText;
    };

    const QPointer<ProcessDock> kPrivilegeDockGuard(this);
    const QPointer<QMenu> kPrivilegeMenuGuard(privilegeSubMenu);
    const std::vector<ProcessActionTarget> kPrivilegeTargets = kContextActionTargets;
    QRunnable* privilegeQueryTask = QRunnable::create([
        kPrivilegeDockGuard,
        kPrivilegeMenuGuard,
        kPrivilegeTargets]() mutable
    {
        const auto kTargetStates = std::make_shared<std::vector<ContextPrivilegeTargetState>>();
        kTargetStates->reserve(kPrivilegeTargets.size());
        for (const ProcessActionTarget& actionTarget : kPrivilegeTargets)
        {
            ContextPrivilegeTargetState targetState;
            targetState.processId = actionTarget.record.pid;
            targetState.creationTime100ns = actionTarget.record.creationTime100ns;
            targetState.processName = actionTarget.record.processName;
            std::string r3DetailText;
            HANDLE rawIdentityHandle = nullptr;
            if (!acquireProcessActionIdentityHold(
                    targetState.processId,
                    targetState.creationTime100ns,
                    &rawIdentityHandle,
                    &targetState.detailText))
            {
                kTargetStates->push_back(std::move(targetState));
                continue;
            }
            const ScopedProcessActionHandle kIdentityHandle(rawIdentityHandle);

            targetState.querySucceeded =
                ks::process::queryTokenPrivilegesByProcessHandle(
                    rawIdentityHandle,
                    &targetState.privileges,
                    &r3DetailText);
            if (!targetState.querySucceeded)
            {
                ksword::ark::DriverClient r0Client;
                const ksword::ark::ProcessTokenPrivilegeResult kR0Result =
                    r0Client.queryProcessTokenPrivileges(
                        targetState.processId,
                        targetState.creationTime100ns);
                if (kR0Result.io.ok
                    && (kR0Result.status == KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_OK
                        || kR0Result.status ==
                            KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_PARTIAL))
                {
                    std::vector<ks::process::TokenPrivilegeLuidEntry> r0Entries;
                    r0Entries.reserve(kR0Result.entries.size());
                    for (const ksword::ark::ProcessTokenPrivilegeEntry& r0Entry : kR0Result.entries)
                    {
                        ks::process::TokenPrivilegeLuidEntry entry{};
                        entry.luidLowPart = r0Entry.luidLowPart;
                        entry.luidHighPart = r0Entry.luidHighPart;
                        entry.attributes = r0Entry.attributes;
                        r0Entries.push_back(entry);
                    }
                    targetState.querySucceeded = ks::process::buildKnownTokenPrivilegeSnapshot(
                        r0Entries,
                        &targetState.privileges,
                        &targetState.detailText);
                    targetState.usedR0 = targetState.querySucceeded;
                }

                if (!targetState.querySucceeded)
                {
                    targetState.detailText = r3DetailText;
                    if (!kR0Result.io.message.empty())
                    {
                        targetState.detailText += " | ";
                        targetState.detailText += kR0Result.io.message;
                    }
                }
            }
            kTargetStates->push_back(std::move(targetState));
        }

        if (kPrivilegeDockGuard == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(kPrivilegeDockGuard, [
            kPrivilegeDockGuard,
            kPrivilegeMenuGuard,
            kTargetStates]()
        {
            if (kPrivilegeDockGuard == nullptr || kPrivilegeMenuGuard == nullptr)
            {
                return;
            }

            kPrivilegeMenuGuard->clear();
            if (kTargetStates->empty())
            {
                QAction* unavailableAction = kPrivilegeMenuGuard->addAction(
                    processContextText(
                        "process.menu.privileges.unavailable",
                        QStringLiteral("无法读取全部选中进程的令牌特权。")));
                unavailableAction->setEnabled(false);
                return;
            }

            const QString kPrivilegeButtonStyle = QStringLiteral(
                "QPushButton {"
                "  min-width:300px; min-height:30px; max-height:30px;"
                "  padding:0 12px; text-align:left;"
                "  color:%1; background:transparent;"
                "  border:none; border-bottom:1px solid %4;"
                "}"
                "QPushButton:hover { background:%2; }"
                "QPushButton:pressed { background:%2; }"
                "QPushButton:disabled { color:%3; }")
                .arg(ksword_theme::textPrimaryHex())
                .arg(ksword_theme::surfaceAltHex())
                .arg(ksword_theme::textSecondaryHex())
                .arg(ksword_theme::borderHex());

            const std::size_t kPrivilegeCount = ks::process::knownTokenPrivilegeNames().size();
            std::vector<std::size_t> controllablePrivilegeIndices;
            controllablePrivilegeIndices.reserve(kPrivilegeCount);
            for (std::size_t privilegeIndex = 0U;
                 privilegeIndex < kPrivilegeCount;
                 ++privilegeIndex)
            {
                bool controllableForAll = true;
                for (const ContextPrivilegeTargetState& targetState : *kTargetStates)
                {
                    if (!targetState.querySucceeded
                        || privilegeIndex >= targetState.privileges.size())
                    {
                        controllableForAll = false;
                        break;
                    }
                    const ks::process::TokenPrivilegeState kPrivilegeState =
                        targetState.privileges[privilegeIndex].state;
                    if (kPrivilegeState != ks::process::TokenPrivilegeState::kEnabled
                        && kPrivilegeState != ks::process::TokenPrivilegeState::kDisabled)
                    {
                        controllableForAll = false;
                        break;
                    }
                }
                if (controllableForAll)
                {
                    controllablePrivilegeIndices.push_back(privilegeIndex);
                }
            }

            if (controllablePrivilegeIndices.empty())
            {
                QAction* unavailableAction = kPrivilegeMenuGuard->addAction(
                    processContextText(
                        "process.menu.privileges.none",
                        QStringLiteral("没有可调整的令牌特权。")));
                unavailableAction->setEnabled(false);
                return;
            }

            for (const std::size_t kPrivilegeIndex : controllablePrivilegeIndices)
            {
                QWidgetAction* rowAction = new QWidgetAction(kPrivilegeMenuGuard);
                QPushButton* privilegeButton = new QPushButton(kPrivilegeMenuGuard);
                privilegeButton->setCheckable(true);
                privilegeButton->setFlat(true);
                privilegeButton->setFocusPolicy(Qt::NoFocus);
                privilegeButton->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
                privilegeButton->setStyleSheet(kPrivilegeButtonStyle);
                rowAction->setDefaultWidget(privilegeButton);
                kPrivilegeMenuGuard->addAction(rowAction);

                const QPointer<QPushButton> kPrivilegeButtonGuard(privilegeButton);
                const auto kUpdatePrivilegeButton = [
                    kTargetStates,
                    kPrivilegeButtonGuard,
                    kPrivilegeIndex]()
                {
                    if (kPrivilegeButtonGuard == nullptr)
                    {
                        return;
                    }

                    std::size_t enabledCount = 0U;
                    for (const ContextPrivilegeTargetState& targetState : *kTargetStates)
                    {
                        const ks::process::TokenPrivilegeState kPrivilegeState =
                            targetState.privileges[kPrivilegeIndex].state;
                        if (kPrivilegeState == ks::process::TokenPrivilegeState::kEnabled)
                        {
                            ++enabledCount;
                        }
                    }

                    const bool kEnabledForAll = enabledCount == kTargetStates->size();
                    const bool kMixedState = enabledCount > 0U
                        && enabledCount < kTargetStates->size();

                    const QString kCheckMark = kEnabledForAll
                        ? QStringLiteral("✓")
                        : (kMixedState ? QStringLiteral("—") : QStringLiteral(" "));
                    const QSignalBlocker kSignalBlocker(kPrivilegeButtonGuard);
                    kPrivilegeButtonGuard->setText(
                        QStringLiteral("%1  %2")
                            .arg(
                                kCheckMark,
                                QString::fromLatin1(
                                    ks::process::knownTokenPrivilegeNames().at(kPrivilegeIndex).c_str())));
                    kPrivilegeButtonGuard->setChecked(kEnabledForAll);
                    kPrivilegeButtonGuard->setEnabled(true);
                    kPrivilegeButtonGuard->setToolTip(
                        processContextText(
                            "process.menu.privileges.toggle",
                            QStringLiteral("点击切换全部选中进程的此项令牌特权。")));
                    kPrivilegeButtonGuard->style()->unpolish(kPrivilegeButtonGuard);
                    kPrivilegeButtonGuard->style()->polish(kPrivilegeButtonGuard);
                    kPrivilegeButtonGuard->update();
                };
                kUpdatePrivilegeButton();

                connect(privilegeButton, &QPushButton::clicked, kPrivilegeMenuGuard, [
                    kPrivilegeDockGuard,
                    kPrivilegeMenuGuard,
                    kTargetStates,
                    kPrivilegeButtonGuard,
                    kPrivilegeIndex,
                    kUpdatePrivilegeButton](const bool enablePrivilege)
                {
                    if (kPrivilegeDockGuard == nullptr
                        || kPrivilegeMenuGuard == nullptr
                        || kPrivilegeButtonGuard == nullptr)
                    {
                        return;
                    }

                    kPrivilegeButtonGuard->setEnabled(false);

                    const std::string kPrivilegeName =
                        ks::process::knownTokenPrivilegeNames().at(kPrivilegeIndex);
                    QRunnable* adjustTask = QRunnable::create([
                        kPrivilegeDockGuard,
                        kPrivilegeMenuGuard,
                        kTargetStates,
                        kPrivilegeButtonGuard,
                        kPrivilegeIndex,
                        kPrivilegeName,
                        enablePrivilege,
                        kUpdatePrivilegeButton]()
                    {
                        std::vector<ContextPrivilegeAdjustResult> adjustResults;
                        adjustResults.reserve(kTargetStates->size());
                        for (std::size_t targetIndex = 0U;
                             targetIndex < kTargetStates->size();
                             ++targetIndex)
                        {
                            ContextPrivilegeAdjustResult adjustResult;
                            adjustResult.targetIndex = targetIndex;
                            ks::process::TokenPrivilegeEdit privilegeEdit;
                            privilegeEdit.privilegeName = kPrivilegeName;
                            privilegeEdit.action = enablePrivilege
                                ? ks::process::TokenPrivilegeAction::kEnable
                                : ks::process::TokenPrivilegeAction::kDisable;
                            const ContextPrivilegeTargetState& targetState =
                                (*kTargetStates)[targetIndex];
                            HANDLE rawIdentityHandle = nullptr;
                            if (acquireProcessActionIdentityHold(
                                    targetState.processId,
                                    targetState.creationTime100ns,
                                    &rawIdentityHandle,
                                    &adjustResult.detailText))
                            {
                                const ScopedProcessActionHandle kIdentityHandle(
                                    rawIdentityHandle);
                                adjustResult.succeeded =
                                    ks::process::applyTokenPrivilegeEditsByProcessHandle(
                                        rawIdentityHandle,
                                        TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
                                        false,
                                        std::vector<ks::process::TokenPrivilegeEdit>{
                                            privilegeEdit },
                                        &adjustResult.detailText);
                            }
                            if (!adjustResult.succeeded)
                            {
                                adjustResult.r3DetailText = adjustResult.detailText;
                                const ks::process::TokenPrivilegeInfo& privilegeInfo =
                                    (*kTargetStates)[targetIndex].privileges[kPrivilegeIndex];
                                if (privilegeInfo.luidKnown)
                                {
                                    adjustResult.r0Attempted = true;
                                    ksword::ark::ProcessTokenPrivilegeEntry r0Edit{};
                                    r0Edit.luidLowPart = privilegeInfo.luidLowPart;
                                    r0Edit.luidHighPart = privilegeInfo.luidHighPart;
                                    r0Edit.action = enablePrivilege
                                        ? KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_ENABLE
                                        : KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_DISABLE;
                                    ksword::ark::DriverClient r0Client;
                                    const ksword::ark::ProcessTokenPrivilegeResult kR0Result =
                                        r0Client.adjustProcessTokenPrivileges(
                                            targetState.processId,
                                            targetState.creationTime100ns,
                                            std::vector<ksword::ark::ProcessTokenPrivilegeEntry>{
                                                r0Edit },
                                            false);
                                    adjustResult.succeeded = kR0Result.io.ok
                                        && kR0Result.status ==
                                            KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_OK
                                        && kR0Result.appliedCount == 1U;
                                    adjustResult.detailText = kR0Result.io.message;
                                }
                            }
                            adjustResults.push_back(std::move(adjustResult));
                        }

                        if (kPrivilegeDockGuard == nullptr)
                        {
                            return;
                        }
                        QMetaObject::invokeMethod(kPrivilegeDockGuard, [
                            kPrivilegeDockGuard,
                            kPrivilegeMenuGuard,
                            kTargetStates,
                            kPrivilegeButtonGuard,
                            kPrivilegeIndex,
                            kPrivilegeName,
                            enablePrivilege,
                            kUpdatePrivilegeButton,
                            adjustResults = std::move(adjustResults)]() mutable
                        {
                            if (kPrivilegeDockGuard == nullptr
                                || kPrivilegeMenuGuard == nullptr
                                || kPrivilegeButtonGuard == nullptr)
                            {
                                return;
                            }

                            bool allSucceeded = true;
                            std::size_t r0FallbackCount = 0U;
                            QStringList failureDetails;
                            for (const ContextPrivilegeAdjustResult& adjustResult : adjustResults)
                            {
                                ContextPrivilegeTargetState& targetState =
                                    (*kTargetStates)[adjustResult.targetIndex];
                                if (!adjustResult.r3DetailText.empty())
                                {
                                    if (adjustResult.r0Attempted)
                                    {
                                        ++r0FallbackCount;
                                    }
                                    KLogEvent r3FailureEvent;
                                    warn << r3FailureEvent
                                        << "[ProcessDock]::R3 token privilege adjustment failed, pid="
                                        << targetState.processId
                                        << "::privilege=" << kPrivilegeName
                                        << ", enable=" << (enablePrivilege ? "true" : "false")
                                        << ", detail=" << adjustResult.r3DetailText
                                        << "::r0Attempted=" << (adjustResult.r0Attempted ? "true" : "false")
                                        << "::finalSucceeded=" << (adjustResult.succeeded ? "true" : "false")
                                        << eol;
                                }
                                if (adjustResult.succeeded)
                                {
                                    continue;
                                }

                                allSucceeded = false;
                                failureDetails.push_back(QStringLiteral("PID %1: %2")
                                    .arg(targetState.processId)
                                    .arg(QString::fromStdString(adjustResult.detailText)));
                            }

                            if (allSucceeded)
                            {
                                for (ContextPrivilegeTargetState& targetState : *kTargetStates)
                                {
                                    targetState.privileges[kPrivilegeIndex].state = enablePrivilege
                                        ? ks::process::TokenPrivilegeState::kEnabled
                                        : ks::process::TokenPrivilegeState::kDisabled;
                                }
                            }
                            kUpdatePrivilegeButton();
                            if (!allSucceeded)
                            {
                                kPrivilegeButtonGuard->setToolTip(
                                    failureDetails.join(QStringLiteral("\n")));
                                kPrivilegeMenuGuard->setToolTip(
                                    processContextText(
                                        "process.menu.privileges.adjust_failed",
                                        QStringLiteral("部分进程的令牌特权调整失败。"))
                                    + QStringLiteral("\n")
                                    + failureDetails.join(QStringLiteral("\n")));
                            }

                            KLogEvent actionEvent;
                            (allSucceeded ? info : warn) << actionEvent
                                << "[ProcessDock]::token privilege menu adjustment::privilege="
                                << kPrivilegeName
                                << ", enable=" << (enablePrivilege ? "true" : "false")
                                << ", targetCount=" << kTargetStates->size()
                                << ", r0FallbackCount=" << r0FallbackCount
                                << "::allSucceeded=" << (allSucceeded ? "true" : "false")
                                << eol;
                        }, Qt::QueuedConnection);
                    });
                    adjustTask->setAutoDelete(true);
                    QThreadPool::globalInstance()->start(adjustTask);
                });
            }
        }, Qt::QueuedConnection);
    });
    privilegeQueryTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(privilegeQueryTask);

    // Cross-group CPU affinity matrix:
    // - Use QWidgetAction to host each core button row; button interactions do not trigger QAction::triggered, so
    //   the submenu remains expanded during continuous checks and closes only when the user clicks outside the menu.
    // - Only enable when all selected targets are readable for affinity to avoid opaque writes to partial targets.
    // - Each target retains its own remaining stable coordinates, modifying only the Gx:Ly values corresponding to the user's click.
    QMenu* affinitySubMenu = contextMenu.addMenu(
        blueTintedIcon(":/Icon/process_priority.svg"),
        processContextText("process.menu.affinity", QStringLiteral("CPU 亲和性")));
    affinitySubMenu->setStyleSheet(buildThreadContextMenuStyle());
    affinitySubMenu->setToolTipsVisible(true);

    struct ContextAffinityTargetState
    {
        DWORD processId = 0;
        ks::process::ProcessAffinitySnapshot snapshot;
    };
    const auto kAffinityTargetStates = std::make_shared<std::vector<ContextAffinityTargetState>>();
    kAffinityTargetStates->reserve(kContextActionTargets.size());
    bool affinityReadable = !kContextActionTargets.empty();
    std::vector<ks::process::LogicalProcessorCoordinate>
        commonProcessorCoordinates;
    bool hasHardConstrainedProcessor = false;
    std::string affinityReadDetailText;
    for (const ProcessActionTarget& actionTarget : kContextActionTargets)
    {
        ks::process::ProcessAffinitySnapshot affinitySnapshot;
        std::string detailText;
        if (!ks::process::queryProcessAffinityState(
                static_cast<DWORD>(actionTarget.record.pid),
                &affinitySnapshot,
                &detailText))
        {
            affinityReadable = false;
            affinityReadDetailText = detailText;
            break;
        }
        ContextAffinityTargetState targetState;
        targetState.processId = static_cast<DWORD>(actionTarget.record.pid);
        targetState.snapshot = std::move(affinitySnapshot);
        hasHardConstrainedProcessor =
            hasHardConstrainedProcessor ||
            std::any_of(
                targetState.snapshot.processors.begin(),
                targetState.snapshot.processors.end(),
                [](const ks::process::LogicalProcessorState& processor)
                {
                    return processor.constrainedByHardAffinity;
                });
        if (kAffinityTargetStates->empty())
        {
            for (const ks::process::LogicalProcessorState& processor :
                 targetState.snapshot.processors)
            {
                commonProcessorCoordinates.push_back(
                    processor.coordinate);
            }
        }
        else
        {
            commonProcessorCoordinates.erase(
                std::remove_if(
                    commonProcessorCoordinates.begin(),
                    commonProcessorCoordinates.end(),
                    [&targetState](
                        const ks::process::LogicalProcessorCoordinate&
                            coordinate)
                    {
                        return std::none_of(
                            targetState.snapshot.processors.begin(),
                            targetState.snapshot.processors.end(),
                            [&coordinate](
                                const ks::process::LogicalProcessorState&
                                    processor)
                            {
                                return processor.coordinate == coordinate;
                            });
                    }),
                commonProcessorCoordinates.end());
        }
        kAffinityTargetStates->push_back(targetState);
    }
    ks::process::normalizeLogicalProcessorCoordinates(
        &commonProcessorCoordinates);
    const bool kIncludeProcessorGroup =
        ks::process::logicalProcessorGroupCount(
            commonProcessorCoordinates) > 1U;
    affinitySubMenu->setToolTip(processContextText(
        kIncludeProcessorGroup
            ? "process.menu.affinity.tooltip.multigroup"
            : "process.menu.affinity.tooltip",
        kIncludeProcessorGroup
            ? QStringLiteral(
                "检测到多个 Windows Processor Group；按 Gx:Ly 切换 CPU Set，蓝色按钮表示已启用。")
            : QStringLiteral(
                "按 Lx 切换 CPU Set，蓝色按钮表示已启用。")));
    if (hasHardConstrainedProcessor)
    {
        affinitySubMenu->setToolTip(
            affinitySubMenu->toolTip() +
            QStringLiteral("\n") +
            processContextText(
                "process.menu.affinity.constraint_notice",
                QStringLiteral(
                    "部分处理器受现有 processor group/thread/Job/legacy affinity 约束，当前不可调度；对应按钮已禁用。")));
    }
    if (commonProcessorCoordinates.empty())
    {
        affinityReadable = false;
        if (affinityReadDetailText.empty())
        {
            affinityReadDetailText =
                "selected processes do not share an available logical processor coordinate";
        }
    }

    const auto kAffinityChanged = std::make_shared<bool>(false);
    if (!affinityReadable)
    {
        affinitySubMenu->setEnabled(false);
        affinitySubMenu->setToolTip(
            processContextText(
                "process.menu.affinity.unavailable",
                QStringLiteral("无法读取全部选中进程的 CPU 亲和性。")));
        KLogEvent affinityReadEvent;
        warn << affinityReadEvent
            << "[ProcessDock] context CPU affinity query failed, targetCount="
            << kContextActionTargets.size()
            << ", detail="
            << (affinityReadDetailText.empty()
                ? "none"
                : affinityReadDetailText)
            << eol;
    }
    else
    {
        constexpr int kAffinityMatrixColumnCount = 6;
        const QString kAffinityCoreButtonStyle = QStringLiteral(
            "QToolButton {"
            "  min-width:42px; min-height:28px; padding:2px 6px;"
            "  color:%1; background:transparent; border:1px solid %2; border-radius:4px;"
            "}"
            "QToolButton:hover { border-color:%3; background:%4; }"
            "QToolButton:checked { color:%5; background:%3; border-color:%3; }"
            "QToolButton[affinityMixed=\"true\"] { border-color:%3; border-style:dashed; }")
            .arg(ksword_theme::textPrimaryHex())
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::accentHex(ksword_theme::AccentRole::kBlue))
            .arg(ksword_theme::surfaceAltHex())
            .arg(ksword_theme::onAccentDynamicHex());

        const auto kAffinityCoordinates = std::make_shared<
            std::vector<ks::process::LogicalProcessorCoordinate>>(
                commonProcessorCoordinates);
        const auto kAffinityCoreButtons =
            std::make_shared<std::vector<QToolButton*>>(
                kAffinityCoordinates->size(),
                nullptr);
        const auto kUpdateAffinityCoreButtons =
            [kAffinityTargetStates,
                kAffinityCoordinates,
                kAffinityCoreButtons]()
        {
            for (std::size_t processorIndex = 0U;
                 processorIndex < kAffinityCoreButtons->size();
                 ++processorIndex)
            {
                QToolButton* const kCoreButton =
                    (*kAffinityCoreButtons)[processorIndex];
                if (kCoreButton == nullptr)
                {
                    continue;
                }
                const ks::process::LogicalProcessorCoordinate kCoordinate =
                    (*kAffinityCoordinates)[processorIndex];
                bool availableForAll = !kAffinityTargetStates->empty();
                bool enabledForAll = !kAffinityTargetStates->empty();
                bool enabledForAny = false;
                for (const ContextAffinityTargetState& targetState : *kAffinityTargetStates)
                {
                    const auto kProcessorIt = std::find_if(
                        targetState.snapshot.processors.begin(),
                        targetState.snapshot.processors.end(),
                        [&kCoordinate](
                            const ks::process::LogicalProcessorState&
                                processor)
                        {
                            return processor.coordinate == kCoordinate;
                        });
                    const bool kAvailableForTarget =
                        kProcessorIt != targetState.snapshot.processors.end() &&
                        kProcessorIt->available;
                    const bool kEnabledForTarget =
                        kAvailableForTarget && kProcessorIt->selected;
                    availableForAll =
                        availableForAll && kAvailableForTarget;
                    enabledForAll = enabledForAll && kEnabledForTarget;
                    enabledForAny = enabledForAny || kEnabledForTarget;
                }

                const QSignalBlocker kSignalBlocker(kCoreButton);
                kCoreButton->setEnabled(availableForAll);
                kCoreButton->setChecked(availableForAll && enabledForAll);
                kCoreButton->setProperty(
                    "affinityMixed",
                    availableForAll && enabledForAny && !enabledForAll);
                kCoreButton->style()->unpolish(kCoreButton);
                kCoreButton->style()->polish(kCoreButton);
                kCoreButton->update();
            }
        };

        for (std::size_t rowStart = 0U;
             rowStart < kAffinityCoordinates->size();
             rowStart += kAffinityMatrixColumnCount)
        {
            QWidgetAction* rowAction = new QWidgetAction(affinitySubMenu);
            QWidget* rowWidget = new QWidget(affinitySubMenu);
            QHBoxLayout* rowLayout = new QHBoxLayout(rowWidget);
            rowLayout->setContentsMargins(8, 3, 8, 3);
            rowLayout->setSpacing(6);
            const std::size_t kRowEnd = std::min(
                rowStart + static_cast<std::size_t>(kAffinityMatrixColumnCount),
                kAffinityCoordinates->size());
            for (std::size_t processorIndex = rowStart;
                 processorIndex < kRowEnd;
                 ++processorIndex)
            {
                const ks::process::LogicalProcessorCoordinate kCoordinate =
                    (*kAffinityCoordinates)[processorIndex];
                QToolButton* coreButton = new QToolButton(rowWidget);
                const auto kTopologyIt = std::find_if(
                    kAffinityTargetStates->front().snapshot.processors.begin(),
                    kAffinityTargetStates->front().snapshot.processors.end(),
                    [&kCoordinate](
                        const ks::process::LogicalProcessorState& processor)
                    {
                        return processor.coordinate == kCoordinate;
                    });
                const QString kIdentityText = QString::fromStdString(
                    ks::process::processorDisplayIdentityText(
                        kCoordinate,
                        kIncludeProcessorGroup));
                const QString kTopologyText =
                    kTopologyIt !=
                        kAffinityTargetStates->front().snapshot.processors.end()
                        ? QString::fromStdString(
                            kTopologyIt->topologyLabel)
                        : QString();
                coreButton->setText(
                    kTopologyText.isEmpty()
                        ? kIdentityText
                        : kIdentityText + QStringLiteral("\n") +
                            kTopologyText);
                coreButton->setCheckable(true);
                coreButton->setAutoRaise(false);
                coreButton->setFocusPolicy(Qt::NoFocus);
                QString processorToolTip = processContextText(
                        "process.menu.affinity.core_tooltip",
                        QStringLiteral("%1（%2）；点击切换全部选中进程的 CPU Set。"))
                        .arg(kIdentityText, kTopologyText);
                bool constrainedForAnyTarget = false;
                bool unavailableForAnyTarget = false;
                for (const ContextAffinityTargetState& targetState :
                     *kAffinityTargetStates)
                {
                    const auto kTargetProcessorIt = std::find_if(
                        targetState.snapshot.processors.begin(),
                        targetState.snapshot.processors.end(),
                        [&kCoordinate](
                            const ks::process::LogicalProcessorState&
                                processor)
                        {
                            return processor.coordinate == kCoordinate;
                        });
                    if (kTargetProcessorIt ==
                        targetState.snapshot.processors.end())
                    {
                        unavailableForAnyTarget = true;
                        continue;
                    }
                    constrainedForAnyTarget =
                        constrainedForAnyTarget ||
                        kTargetProcessorIt->constrainedByHardAffinity;
                    unavailableForAnyTarget =
                        unavailableForAnyTarget ||
                        !kTargetProcessorIt->available;
                }
                if (constrainedForAnyTarget)
                {
                    processorToolTip += QStringLiteral("\n") +
                        processContextText(
                            "process.menu.affinity.constraint_tooltip",
                            QStringLiteral(
                                "受现有 processor group/thread/Job/legacy affinity 约束，CPU Sets 无法在当前状态下调度到此处理器。"));
                }
                else if (unavailableForAnyTarget)
                {
                    processorToolTip += QStringLiteral("\n") +
                        processContextText(
                            "process.menu.affinity.allocated_tooltip",
                            QStringLiteral(
                                "此 CPU Set 对至少一个选中进程不可用。"));
                }
                coreButton->setToolTip(processorToolTip);
                coreButton->setStyleSheet(kAffinityCoreButtonStyle);
                rowLayout->addWidget(coreButton);
                (*kAffinityCoreButtons)[processorIndex] = coreButton;
                connect(coreButton, &QToolButton::clicked, affinitySubMenu,
                    [affinitySubMenu,
                        kAffinityTargetStates,
                        kAffinityChanged,
                        kUpdateAffinityCoreButtons,
                        kCoordinate,
                        coreButton](const bool enabled)
                    {
                        std::vector<ks::process::ProcessAffinityRule>
                            nextRules;
                        nextRules.reserve(kAffinityTargetStates->size());
                        for (const ContextAffinityTargetState& targetState :
                             *kAffinityTargetStates)
                        {
                            ks::process::ProcessAffinityRule nextRule;
                            if (targetState.snapshot.unrestricted)
                            {
                                for (const ks::process::LogicalProcessorState&
                                     processor :
                                     targetState.snapshot.processors)
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
                                nextRule =
                                    ks::process::affinityRuleFromSnapshot(
                                        targetState.snapshot);
                            }

                            if (enabled)
                            {
                                nextRule.processors.push_back(kCoordinate);
                            }
                            else
                            {
                                nextRule.processors.erase(
                                    std::remove(
                                        nextRule.processors.begin(),
                                        nextRule.processors.end(),
                                        kCoordinate),
                                    nextRule.processors.end());
                            }
                            nextRule.selectAllAvailable = false;
                            ks::process::
                                normalizeLogicalProcessorCoordinates(
                                    &nextRule.processors);
                            if (nextRule.processors.empty())
                            {
                                const QSignalBlocker kSignalBlocker(
                                    coreButton);
                                coreButton->setChecked(true);
                                affinitySubMenu->setToolTip(
                                    processContextText(
                                        "process.menu.affinity.last_core",
                                        QStringLiteral(
                                            "至少保留一个可用逻辑处理器。")));
                                return;
                            }
                            nextRules.push_back(std::move(nextRule));
                        }

                        const QMessageBox::StandardButton kConfirmation =
                            QMessageBox::warning(
                                affinitySubMenu,
                                processContextText(
                                    "process.affinity.risk.title",
                                    QStringLiteral("CPU 亲和性风险")),
                                processContextText(
                                    "process.affinity.risk.apply",
                                    QStringLiteral(
                                        "跨组/CPU Set 亲和性可能显著降低性能，并与线程或 Job 约束冲突；极端配置可能使进程无法调度、冻结并造成数据丢失。是否继续？")),
                                QMessageBox::Yes | QMessageBox::No,
                                QMessageBox::No);
                        if (kConfirmation != QMessageBox::Yes)
                        {
                            kUpdateAffinityCoreButtons();
                            return;
                        }

                        bool allUpdated = true;
                        QStringList failedProcessDetails;
                        for (std::size_t targetIndex = 0U;
                             targetIndex < kAffinityTargetStates->size();
                             ++targetIndex)
                        {
                            ContextAffinityTargetState& targetState =
                                (*kAffinityTargetStates)[targetIndex];
                            std::string detailText;
                            if (ks::process::setProcessAffinityRuleByPid(
                                    targetState.processId,
                                    nextRules[targetIndex],
                                    &detailText))
                            {
                                ks::process::ProcessAffinitySnapshot
                                    refreshedSnapshot;
                                if (ks::process::queryProcessAffinityState(
                                        targetState.processId,
                                        &refreshedSnapshot,
                                        &detailText))
                                {
                                    targetState.snapshot =
                                        std::move(refreshedSnapshot);
                                    *kAffinityChanged = true;
                                    continue;
                                }
                            }
                            allUpdated = false;
                            failedProcessDetails << QStringLiteral("PID %1: %2")
                                .arg(targetState.processId)
                                .arg(QString::fromStdString(detailText));
                        }
                        if (!allUpdated)
                        {
                            const QString kFailureText = processContextText(
                                "process.menu.affinity.update_failed",
                                QStringLiteral(
                                    "CPU 亲和性更新未完全生效；详细信息已写入日志。"));
                            affinitySubMenu->setToolTip(kFailureText);
                            QMessageBox::warning(
                                affinitySubMenu,
                                processContextText(
                                    "process.menu.affinity",
                                    QStringLiteral("CPU 亲和性")),
                                kFailureText);
                        }
                        kUpdateAffinityCoreButtons();

                        KLogEvent actionEvent;
                        (allUpdated ? info : warn) << actionEvent
                            << "[ProcessDock] 右键 CPU 亲和性更新, processor="
                            << ks::process::processorIdentityText(
                                kCoordinate)
                            << ", enabled="
                            << (enabled ? "true" : "false")
                            << ", targetCount="
                            << kAffinityTargetStates->size()
                            << ", allUpdated="
                            << (allUpdated ? "true" : "false")
                            << ", failed="
                            << (failedProcessDetails.isEmpty()
                                ? "none"
                                : failedProcessDetails
                                    .join(QStringLiteral(" | "))
                                    .toStdString())
                            << eol;
                    });
            }
            rowLayout->addStretch(1);
            rowAction->setDefaultWidget(rowWidget);
            affinitySubMenu->addAction(rowAction);
        }
        kUpdateAffinityCoreButtons();
    }

    // Priority submenu.
    QMenu* prioritySubMenu = contextMenu.addMenu(
        blueTintedIcon(":/Icon/process_priority.svg"),
        processContextText("process.menu.priority", QStringLiteral("设置进程优先级")));
    QAction* idlePriority = prioritySubMenu->addAction(blueTintedIcon(":/Icon/process_priority.svg"), "Idle");
    QAction* belowNormalPriority = prioritySubMenu->addAction(blueTintedIcon(":/Icon/process_priority.svg"), "Below Normal");
    QAction* normalPriority = prioritySubMenu->addAction(blueTintedIcon(":/Icon/process_priority.svg"), "Normal");
    QAction* aboveNormalPriority = prioritySubMenu->addAction(blueTintedIcon(":/Icon/process_priority.svg"), "Above Normal");
    QAction* highPriority = prioritySubMenu->addAction(blueTintedIcon(":/Icon/process_priority.svg"), "High");
    QAction* realtimePriority = prioritySubMenu->addAction(blueTintedIcon(":/Icon/process_priority.svg"), "Realtime");
    idlePriority->setData(0);
    belowNormalPriority->setData(1);
    normalPriority->setData(2);
    aboveNormalPriority->setData(3);
    highPriority->setData(4);
    realtimePriority->setData(5);

    // Integrity submenu:
    // - Read the TokenIntegrityLevel of the right-click target (take the first target in batch mode);
    // - Uses a prefix dot to mark the current RID to avoid Qt platform checkmarks being invisible under different themes;
    // - Batch operations are still supported; all selected processes attempt to write to the same Mandatory Label.
    QMenu* integritySubMenu = contextMenu.addMenu(
        blueTintedIcon(":/Icon/process_critical.svg"),
        processContextText("process.menu.integrity", QStringLiteral("完整性")));
    integritySubMenu->setToolTipsVisible(true);
    if (!kContextIntegrityKnown && contextProcessRecord != nullptr)
    {
        integritySubMenu->setToolTip(QStringLiteral("当前完整性读取失败：%1")
            .arg(QString::fromStdString(contextIntegrityDetailText)));
    }
    for (const ProcessIntegrityLevelPreset& preset : kProcessIntegrityLevelPresets)
    {
        const bool kIsCurrentLevel = kContextIntegrityKnown && contextIntegrityRid == preset.rid;
        QAction* integrityAction = integritySubMenu->addAction(
            blueTintedIcon(":/Icon/process_critical.svg"),
            QStringLiteral("%1 %2 - %3")
                .arg(kIsCurrentLevel ? QStringLiteral("●") : QStringLiteral(" "))
                .arg(QString::fromLatin1(preset.nameText))
                .arg(processContextText(
                    QStringLiteral("process.integrity.") + QString::fromLatin1(preset.nameText),
                    QString::fromUtf8(preset.detailText))));
        integrityAction->setData(static_cast<unsigned int>(preset.rid));
    }

    QAction* detailsAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_details.svg"),
        processContextText("process.menu.details", QStringLiteral("进程详细信息")));
    detailsAction->setEnabled(!kHasBatchSelection);
    contextMenu.addSeparator();
    QAction* uploadVirusTotalAction = ks::online_scan::addVirusTotalSandboxMenu(
        &contextMenu,
        this,
        [kContextActionTargets]() -> ks::online_scan::SandboxUploadTarget
        {
            // Input: Frozen process action targets from the right-click menu.
            // Handling: Prioritize using the cached imagePath; if empty, fall back to PID resolution.
            // Returns: File paths to upload and the source description for the result window.
            ks::online_scan::SandboxUploadTarget uploadTarget;
            if (kContextActionTargets.empty())
            {
                return uploadTarget;
            }

            const ks::process::ProcessRecord& record = kContextActionTargets.front().record;
            uploadTarget.filePath = QString::fromStdString(record.imagePath);
            uploadTarget.sourceText = QStringLiteral("进程列表 PID=%1 %2")
                .arg(record.pid)
                .arg(QString::fromStdString(record.processName));
            if (uploadTarget.filePath.trimmed().isEmpty() && record.pid != 0)
            {
                uploadTarget.filePath = QString::fromStdString(ks::process::queryProcessPathByPid(record.pid));
            }
            return uploadTarget;
        });
    if (uploadVirusTotalAction != nullptr)
    {
        uploadVirusTotalAction->setEnabled(!kContextActionTargets.empty());
    }

    contextMenuVisible_ = true;
    QAction* selectedAction = contextMenu.exec(processTable_->viewport()->mapToGlobal(localPosition));
    contextMenuVisible_ = false;
    if (*kAffinityChanged)
    {
        // The affinity matrix button writes directly while the submenu is active and refreshes the list only after the menu
        // closes, avoiding reconstruction of right-click bindings during refresh or premature collapsing of the expanded matrix.
        requestAsyncRefresh(true);
    }
    {
        if (selectedAction == nullptr)
        {
            clearContextActionBinding();
            return;
        }

        {
            KLogEvent logEvent;
            info << logEvent
                << "[ProcessDock] 右键菜单执行动作: " << selectedAction->text().toStdString()
                << eol;
        }

        if (selectedAction == copyCellAction) { copyCurrentCell(); }
        else if (selectedAction == copyRowAction) { copyCurrentRow(); }
        else if (selectedAction == terminateProcessAction) { executeTerminateProcessAction(); }
        else if (selectedAction == terminateAndDeleteImageAction) { executeTerminateAndDeleteImageAction(); }
        else if (selectedAction == terminateProcessTreeAction) { executeTerminateProcessTreeAction(); }
        else if (selectedAction == r0TerminateAction) { executeR0TerminateProcessAction(); }
        else if (selectedAction == r0TerminateTreeAction) { executeR0TerminateProcessTreeAction(); }
        // Selectable option: When exec() returns, Qt has already flipped the checked state to what the user
        // wants, so isChecked() reflects 'what the user wants it to be', not 'what it was originally'.
        else if (selectedAction == r0SuspendToggleAction)
        {
            if (r0SuspendToggleAction->isChecked()) { executeR0SuspendProcessAction(); }
            else { executeR0ResumeProcessAction(); }
        }
        else if (selectedAction == dmaProcessOpAction || selectedAction == advancedDmaAction)
        {
            openDmaProcessOpWindow();
        }
        else if (selectedAction == advancedR0OnlyAction) { executeR0TerminateProcessAction(); }
        else if (selectedAction == advancedHvmOnlyAction)
        {
            executeHvmProcessDispositionAction(KSWORD_ARK_HVM_PROCESS_OP_TERMINATE);
        }
        // Prefer member check over !empty(): the latter is a tautology that would swallow all subsequent
        // else-if branches (including the HVM ones), leaving menu items unresponsive without any error.
        else if (std::find(advancedTerminateActions.begin(),
                           advancedTerminateActions.end(),
                           selectedAction) != advancedTerminateActions.end())
        {
            // Iterate through each method item: retrieve the corresponding entry by index and execute only that specific method.
            for (std::size_t methodIndex = 0;
                 methodIndex < advancedTerminateActions.size();
                 ++methodIndex)
            {
                if (selectedAction == advancedTerminateActions[methodIndex])
                {
                    executeSingleTerminateMethodAction(methodIndex);
                    break;
                }
            }
        }
        else if (selectedAction == hvmFreezeAction) {
            executeHvmProcessDispositionAction(
                KSWORD_ARK_HVM_PROCESS_OP_FREEZE);
        }
        else if (selectedAction == hvmTerminateAction) {
            executeHvmProcessDispositionAction(
                KSWORD_ARK_HVM_PROCESS_OP_TERMINATE);
        }
        else if (selectedAction == hvmReleaseAction) {
            executeHvmProcessDispositionAction(
                KSWORD_ARK_HVM_PROCESS_OP_RELEASE);
        }
        else if (selectedAction == hvmInjectAction) {
            executeHvmInjectAction(KSWORD_ARK_HVM_INJECT_OP_ARM);
        }
        else if (selectedAction == hvmInjectReleaseAction) {
            executeHvmInjectAction(KSWORD_ARK_HVM_INJECT_OP_RELEASE);
        }
        else if (selectedAction == r0HideUnlinkOnlyAction) {
            executeR0SetProcessHiddenAction(true, KSWORD_ARK_PROCESS_VISIBILITY_FLAG_UNLINK_ACTIVE_LIST);
        }
        else if (selectedAction == r0HidePatchPidOnlyAction) {
            executeR0SetProcessHiddenAction(true, KSWORD_ARK_PROCESS_VISIBILITY_FLAG_PATCH_UNIQUE_PID);
        }
        else if (selectedAction == r0HideLegacyBothAction) {
            executeR0SetProcessHiddenAction(true, KSWORD_ARK_PROCESS_VISIBILITY_FLAG_LEGACY_BOTH);
        }
        else if (selectedAction == r0UnhideProcessAction) { executeR0SetProcessHiddenAction(false); }
        else if (selectedAction == r0ClearHiddenProcessAction) { executeR0ClearProcessHiddenAction(); }
        else if (selectedAction == r0EnableBreakAction) { executeR0SetBreakOnTerminationAction(true); }
        else if (selectedAction == r0DisableBreakAction) { executeR0SetBreakOnTerminationAction(false); }
        else if (selectedAction == r0DisableApcAction) { executeR0DisableApcInsertionAction(); }
        else if (selectedAction == r0DkomCidRemoveAction) { executeR0DkomRemoveFromCidTableAction(); }
        else if (selectedAction == screenInjectionSurfaceAction) { executeScreenInjectionSurfaceAction(); }
        else if (selectedAction == refreshPplLevelAction) { executeRefreshPplProtectionLevelAction(); }
        else if (selectedAction == suspendToggleAction)
        {
            if (suspendToggleAction->isChecked()) { executeSuspendAction(); }
            else { executeResumeAction(); }
        }
        else if (selectedAction == efficiencyToggleAction)
        {
            executeSetEfficiencyModeAction(efficiencyToggleAction->isChecked());
        }
        else if (selectedAction == setCriticalAction) { executeSetCriticalAction(true); }
        else if (selectedAction == clearCriticalAction) { executeSetCriticalAction(false); }
        else if (selectedAction == openFolderAction) { executeOpenFolderAction(); }
        else if (selectedAction == openHandleAction) { executeFocusHandleAction(); }
        else if (selectedAction == openMemoryAction) { executeOpenMemoryOperationAction(); }
        else if (selectedAction == openNetworkAction) { executeFocusNetworkAction(); }
        else if (selectedAction == openWindowAction) { executeFocusWindowAction(); }
        else if (selectedAction == openMessageHooksAction && !kContextActionTargets.empty())
        {
            executeOpenMessageHooksAction(kContextActionTargets.front().record);
        }
        else if (selectedAction == injectionPageAction) { openSelectedProcessInjectionPage(); }
        else if (selectedAction == scanHotkeyAction) { openSelectedProcessHotkeyScanner(); }
        else if (selectedAction == detailsAction) { openProcessDetailsPlaceholder(); }
        else if (selectedAction->parent() == prioritySubMenu)
        {
            executeSetPriorityAction(selectedAction->data().toInt());
        }
        else if (selectedAction->parent() == integritySubMenu)
        {
            const DWORD kIntegrityRid = selectedAction->data().toUInt();
            executeSetProcessIntegrityAction(
                kIntegrityRid,
                processIntegrityNameFromRid(kIntegrityRid));
        }
        else if (selectedAction->parent() == r0PplLevelSubMenu)
        {
            const unsigned int kLevelValue = selectedAction->data().toUInt();
            if (kLevelValue > 0xFFU)
            {
                KLogEvent actionEvent;
                warn << actionEvent
                    << "[ProcessDock] R0 进程保护层级无效: levelValue="
                    << kLevelValue
                    << eol;
                showActionResultMessage(
                    QStringLiteral("R0设置进程保护层级"),
                    false,
                    std::string("invalid PPL level value"),
                    actionEvent);
                clearContextActionBinding();
                return;
            }

            executeR0SetPplProtectionAction(
                static_cast<std::uint8_t>(kLevelValue),
                selectedAction->text());
        }
    }
    clearContextActionBinding();
}
