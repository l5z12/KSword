#include "ProcessDock.Support.h"
#include "ProcessActivityChartWidget.h"
#include "ProcessActivityTimelineSlider.h"

using namespace ksword::ui::process_dock;

QString ProcessDock::hvmDispositionStatusAdvice(const unsigned long status)
{
    /*
     * Translate status code to 'what to do next'.
     *
     * Simply showing status=3 to the user is uninformative: most of these codes indicate **preconditions were not met**,
     * and the required user action differs for each precondition. Two even have opposite directions (one: 'not started
     * yet, prepare first'; the other: 'running, stop first'). hvm_ctl already displays these hints; the UI lacks them.
     * Consequently, the same rejection is actionable via the command line but appears as just a number in the UI.
     */
    switch (status)
    {
    case KSWORD_ARK_HVM_PROCESS_STATUS_REQUIRES_RESIDENT_STOPPED:
        return ks::i18n::sourceText(QStringLiteral("虚拟化常驻正在运行，而安装处置要求它停着——常驻期间退出路径不持锁读这张表。请先用右上角的虚拟化按钮停止常驻，装上处置后再启动。"));
    case KSWORD_ARK_HVM_PROCESS_STATUS_NOT_PREPARED:
        return ks::i18n::sourceText(QStringLiteral("虚拟化运行时还没准备过。请先在内核页完成 prepare，并且要带 EPTP 切换后端。"));
    case KSWORD_ARK_HVM_PROCESS_STATUS_CR3_TRACKING_REQUIRED:
        return ks::i18n::sourceText(QStringLiteral("缺 CR3 追踪。处置的作用范围完全靠它来区分是哪个进程；没有它，拒绝会落到整台机器而不是一个进程上，所以这里是拒绝而不是降级。请先打开 CR3 追踪再启动常驻——这一位在常驻启动时写进 VMCS，起来之后改不了。"));
    case KSWORD_ARK_HVM_PROCESS_STATUS_EPTP_SWITCH_REQUIRED:
        return ks::i18n::sourceText(QStringLiteral("缺 EPTP 切换后端。没有第二套页表层次就没有\"受限\"可选。请在 prepare 时启用它。"));
    case KSWORD_ARK_HVM_PROCESS_STATUS_TRANSLATION_FAILED:
        return ks::i18n::sourceText(QStringLiteral("这个地址在目标进程里翻译不出物理页。请确认它确实落在该进程已映射的代码上。"));
    case KSWORD_ARK_HVM_PROCESS_STATUS_PROTECTED_TARGET:
        return ks::i18n::sourceText(QStringLiteral("拒绝对该目标动手：系统进程与本程序自身不在可处置范围内。"));
    case KSWORD_ARK_HVM_PROCESS_STATUS_ALREADY_ARMED:
        return ks::i18n::sourceText(QStringLiteral("这个进程已经有一条处置了。请先解除再重新下达。"));
    case KSWORD_ARK_HVM_PROCESS_STATUS_TABLE_FULL:
        return ks::i18n::sourceText(QStringLiteral("处置表已满。请先解除一条不再需要的。"));
    case KSWORD_ARK_HVM_PROCESS_STATUS_NOT_FOUND:
        return ks::i18n::sourceText(QStringLiteral("这个进程上没有已安装的处置。"));
    case KSWORD_ARK_HVM_PROCESS_STATUS_PROCESS_LOOKUP_FAILED:
        return ks::i18n::sourceText(QStringLiteral("找不到这个进程，它可能已经退出。"));
    case KSWORD_ARK_HVM_PROCESS_STATUS_CONFIRMATION_REQUIRED:
        return ks::i18n::sourceText(QStringLiteral("被安全策略拦下，需要显式确认。"));
    default:
        return QString();
    }
}

void ProcessDock::showHvmDispositionResult(
    const QString& title,
    const bool actionOk,
    const std::string& detailText,
    const unsigned long status,
    const KLogEvent& actionEvent,
    const QString& successAdvice)
{
    // Both logging and popup: log must include the call stack; popup must show the conclusion immediately.
    // If only logging without a popup, rejections like 'precondition not met' remain completely silent in the UI.
    showActionResultMessage(title, actionOk, detailText, actionEvent);
    const QString kDetail = QString::fromStdString(detailText);
    if (actionOk)
    {
        /*
         * Even on success, provide a message because "success" here means **the payload is installed**, not
         * that the target is dead/stopped. There is an uncertain time gap between these two events: injection
         * only occurs when the target address space actually executes to that page. After installation, the
         * target may remain in the list for a while—without explanation, this period would look like failure.
         */
        QMessageBox::information(
            this,
            title,
            successAdvice.isEmpty()
                ? kDetail
                : (successAdvice + QStringLiteral("\n\n") + kDetail));
        return;
    }
    // State what to do first, then append the original line—both are required: one for human reading, one for troubleshooting.
    const QString kAdvice = hvmDispositionStatusAdvice(status);
    QMessageBox::warning(
        this,
        title,
        kAdvice.isEmpty() ? kDetail : (kAdvice + QStringLiteral("\n\n") + kDetail));
}

/*
 * Complete the three prerequisites of R-1 installation in order. Returns true on success; reports the cause on failure.
 *
 * This block is shared by remediation and injection. It is extracted not to reduce code lines, but because the execution order
 * is strict: CR3 tracking and backend are only read during PREPARE/VMCS creation; installation requires resident suspension;
 * teardown clears EPT, so prepare must follow it. Two copies are kept because one will inevitably be modified first.
 */
/*
 * After installation, restore the resident component. Return true on failure (indicating 'this step failed').
 *
 * This function is separate because its failure must be reported distinct from installation failure: by the
 * time we reach here, the component is **already installed**, just not executing. Merging the message would
 * imply nothing happened, causing the next installation to hit ALREADY_ARMED without understanding why.
 */
bool ProcessDock::stepFailedRestartResident(
    const QString& actionTitle,
    const KLogEvent& actionEvent)
{
    const ksword::kvm::KvmCommandResult kStarted = ksword::kvm::startResident(0UL);

    if (kStarted.ok)
    {
        return false;
    }
    showHvmDispositionResult(
        actionTitle,
        false,
        (ks::i18n::sourceText(QStringLiteral("启动常驻（已经装上了，但常驻没起来）")) +
            QStringLiteral("：") + kStarted.message).toStdString(),
        KSWORD_ARK_HVM_PROCESS_STATUS_OK,
        actionEvent);
    return true;
}

bool ProcessDock::prepareHvmForArming(
    const QString& actionTitle,
    const KLogEvent& actionEvent)
{
    const auto kStepFailed = [&](const QString& stepName,
                                const ksword::kvm::KvmCommandResult& r) {
        if (r.ok)
        {
            return false;
        }
        showHvmDispositionResult(
            actionTitle,
            false,
            (stepName + QStringLiteral("：") + r.message).toStdString(),
            KSWORD_ARK_HVM_PROCESS_STATUS_OK,
            actionEvent);
        return true;
    };
    // Stop resident: returns success if already stopped, no need to check first.
    if (kStepFailed(ks::i18n::sourceText(QStringLiteral("停止常驻")),
                   ksword::kvm::stopResident(0UL)))
    {
        return false;
    }
    /*
     * Release resources. This must be done; do not skip it just because it "looks ready":
     * The backend and CR3 tracking are only read during PREPARE / VMCS creation, and ensurePrepared does not resend
     * PREPARE once resources are ready. Without releasing first, these settings would not take effect in this round.
     */
    if (kStepFailed(ks::i18n::sourceText(QStringLiteral("释放资源")),
                   ksword::kvm::releaseResources(0UL)))
    {
        return false;
    }
    /*
     * CR3 tracking: The scope of the action depends entirely on it, and it is read only when the VMCS is being built.
     *
     * Must read before writing. The CR policy OP_SET operation performs a **full replacement**, not a merge
     * (in hvm_cr_policy.c, it directly sets `CrPolicyFlags = flags` and `Cr0PinnedMask = ...`). Therefore,
     * sending `0, 0, trackCr3=true, false, false` directly would zero out the CR0/CR4 pinned masks
     * configured by the user in the CR policy panel and silently disable DR interception and logging. We
     * only need to modify the CR3 tracking bit; all other bits must be preserved and returned as-is.
     *
     * Uses applyCrPolicy instead of sending an IOCTL directly, because it carries write permission
     * gates: when R-1 write permission is closed, this path should not modify any policy.
     */
    const ksword::kvm::KvmCrPolicyResult kCurrentCrPolicy =
        ksword::kvm::readCrPolicy();
    const ksword::kvm::KvmCrPolicyResult kCrResult = ksword::kvm::applyCrPolicy(
        kCurrentCrPolicy.ok ? kCurrentCrPolicy.cr0PinnedMask : 0ULL,
        kCurrentCrPolicy.ok ? kCurrentCrPolicy.cr4PinnedMask : 0ULL,
        true,
        kCurrentCrPolicy.ok ? kCurrentCrPolicy.interceptDr : false,
        kCurrentCrPolicy.ok ? kCurrentCrPolicy.log : false);
    if (!kCrResult.ok)
    {
        showHvmDispositionResult(
            actionTitle, false,
            kCrResult.message.toStdString(),
            KSWORD_ARK_HVM_PROCESS_STATUS_CR3_TRACKING_REQUIRED,
            actionEvent);
        return false;
    }
    /*
     * The sole source for restricted hierarchy is the EPTP switch backend, which is selected during PREPARE.
     *
     * Must block the mutex before enabling it: private EPT and VMFUNC are both mutually exclusive with
     * this backend, and the driver rejects any allocation before this point. This check exists on the
     * manual switch path; adding it here prevents the final step of starting the resident component
     * from failing with an unrelated status code after the handler has already been installed.
     */
    if (ksword::kvm::isLocalEptEnabled() || ksword::kvm::isVmFuncEnabled())
    {
        showHvmDispositionResult(
            actionTitle, false,
            ks::i18n::sourceText(QStringLiteral("R-1 处置需要 EPTP 切换后端，而它与「每处理器私有 EPT」「VMFUNC」互斥。请先在虚拟化菜单里关掉这两项。")).toStdString(),
            KSWORD_ARK_HVM_PROCESS_STATUS_EPTP_SWITCH_REQUIRED,
            actionEvent);
        return false;
    }
    ksword::kvm::setEptpSwitchEnabled(true);
    if (kStepFailed(ks::i18n::sourceText(QStringLiteral("准备资源")),
                   ksword::kvm::ensurePrepared()))
    {
        return false;
    }
    /* All three prerequisites are met. */
    return true;
}

void ProcessDock::executeHvmProcessDispositionAction(
    const unsigned long operation)
{
    // Input: operation is FREEZE / TERMINATE / RELEASE.
    // Processing: Parse the guest linear address of the target page, then issue a single R-1 disposition upon confirmation.
    // Return: None; results are reported via message box and logs.
    const std::vector<ProcessActionTarget> kActionTargets = selectedActionTargets();
    if (kActionTargets.empty())
    {
        KLogEvent logEvent;
        warn << logEvent
            << "[ProcessDock] executeHvmProcessDispositionAction 被忽略：当前没有选中进程。"
            << eol;
        return;
    }
    const QString kHvmName = ks::settings::hvmDisplayNameLabel(
        ks::settings::loadAppearanceSettings().hvmDisplayName);
    /*
     * Write permission gate. Freezing, terminating, and unfreezing all alter system state and are managed by this gate.
     *
     * This is the second gate within the process, existing alongside the driver-side confirmation token and FILE_WRITE_ACCESS.
     * Omitting it does not merely remove a layer of protection; it turns this link into a bypass path: the menu includes
     * After R-1 is set to read-only observation, the context menu can still change CR policies, freeze processes, and terminate processes.
     */
    if (!ksword::kvm::isWriteAccessEnabled())
    {
        QMessageBox::information(
            this,
            kHvmName,
            ks::i18n::sourceText(QStringLiteral("R-1 写权限当前是关闭的（只读观测）。进程处置会改变系统状态，请先在虚拟化菜单里开启写权限。")));
        return;
    }
    const ProcessActionTarget& target = kActionTargets.front();
    const unsigned long kTargetPid = target.record.pid;

    if (operation == KSWORD_ARK_HVM_PROCESS_OP_RELEASE)
    {
        KLogEvent releaseEvent;
        ksword::ark::DriverClient releaseClient;
        const ksword::ark::HvmProcessResult kReleaseResult =
            releaseClient.controlHvmProcess(
                KSWORD_ARK_HVM_PROCESS_OP_RELEASE,
                kTargetPid,
                0ULL,
                true);
        showHvmDispositionResult(
            ks::i18n::sourceText(QStringLiteral("%1 解除（冻结/结束）")).arg(kHvmName),
            kReleaseResult.io.ok &&
                kReleaseResult.response.status ==
                    KSWORD_ARK_HVM_PROCESS_STATUS_OK,
            kReleaseResult.io.message,
            kReleaseResult.response.status,
            releaseEvent);
        return;
    }

    /*
     * Default to one-click mode: automatically select pages and complete prerequisites, requiring user confirmation only once.
     *
     * The previous workflow required the user to first enable CR3 tracing, then prepare the EPTP backend, stop the resident component,
     * return to right-click, and manually enter a hexadecimal address—omitting any of these five steps resulted only in a rejection code.
     * This isn't about 'high capability'; it's about passing the driver's internal constraints directly to the user.
     *
     * The constraints still apply, including stopping the resident hypervisor before
     * installation. They are ordering requirements the UI can handle, not decisions the user must
     * make. Complete the entire sequence here and explain what will happen before taking action.
     *
     * Hold Shift to use the legacy manual address path—keep this because automatic page selection has a real boundary.
     * It captures the page currently being executed by a thread, which may
     * not be the page you most want to pin for a process stuck elsewhere.
     */
    const bool kManualAddress =
        (QApplication::keyboardModifiers() & Qt::ShiftModifier) != 0;
    /*
     * Auto page selection: prefer the address currently being executed by a thread; fall back to the entry point if unavailable.
     *
     * The order cannot be reversed. The entry point executes only once at startup; pinning a running process there is
     * equivalent to doing nothing, and this silent failure is indistinguishable from success from the outside. Such
     * silent failures are the most expensive failure mode of this mechanism and must not appear in the default path.
     */
    quint64 guestLinearAddress = hvmProcessRunningThreadRip(target.record.pid);
    if (guestLinearAddress == 0ULL)
    {
        guestLinearAddress = hvmProcessEntryPointAddress(target.record.pid);
    }
    if (kManualAddress)
    {
    const QString kDefaultAddress = QStringLiteral("0x%1")
        .arg(guestLinearAddress, 0, 16);
    /*
     * Uses a custom dialog instead of QInputDialog::getText.
     *
     * QInputDialog labels do not auto-wrap; width is calculated based on the longest line. This description spans three lines,
     * causing the dialog to expand wider than the main window, cutting off the right-side button entirely—verified in practice.
     * Users see a dialog without a cancel button. Adding \n for manual line breaks doesn't solve the root issue: any translated
     * text that grows longer will break the layout again, and the author of this description won't return to measure it once more.
     *
     * So explicitly enable auto-wrapping and fix the width to completely decouple 'text length' from 'dialog width'.
     */
    QDialog addressDialog(this);
    addressDialog.setWindowTitle(
        ks::i18n::sourceText(QStringLiteral("%1 进程处置：选择要拒绝执行的页"))
            .arg(kHvmName));
    QVBoxLayout* const kAddressLayout = new QVBoxLayout(&addressDialog);
    QLabel* const kAddressHint = new QLabel(
        // Single line: Multi-line concatenation will cause i18n audits to request terms segment by segment.
        ks::i18n::sourceText(QStringLiteral("输入该进程内一个会被执行到的客户线性地址（十六进制）。\n处置作用在这个地址所在的整页上。若这一页在处置期间从未被执行，拒绝就不会发生——那和成功在外面看不出区别。\n默认值是主模块入口点，对刚启动的进程有效。")),
        &addressDialog);
    kAddressHint->setWordWrap(true);
    kAddressHint->setMaximumWidth(520);
    kAddressLayout->addWidget(kAddressHint);
    QLineEdit* const kAddressEdit = new QLineEdit(kDefaultAddress, &addressDialog);
    kAddressEdit->selectAll();
    kAddressLayout->addWidget(kAddressEdit);
    QDialogButtonBox* const kAddressButtons = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel,
        &addressDialog);
    kAddressLayout->addWidget(kAddressButtons);
    connect(kAddressButtons, &QDialogButtonBox::accepted, &addressDialog, &QDialog::accept);
    connect(kAddressButtons, &QDialogButtonBox::rejected, &addressDialog, &QDialog::reject);
    kAddressEdit->setFocus();
    if (addressDialog.exec() != QDialog::Accepted)
    {
        return;
    }
    const QString kAddressText = kAddressEdit->text();
    bool addressParsed = false;
    guestLinearAddress =
        kAddressText.trimmed().startsWith(QStringLiteral("0x"), Qt::CaseInsensitive)
            ? kAddressText.trimmed().mid(2).toULongLong(&addressParsed, 16)
            : kAddressText.trimmed().toULongLong(&addressParsed, 16);
    if (!addressParsed || guestLinearAddress == 0ULL)
    {
        QMessageBox::warning(
            this,
            ks::i18n::sourceText(QStringLiteral("地址无效")),
            ks::i18n::sourceText(QStringLiteral(
                "要拒绝执行的地址必须是非零的十六进制值。")));
        return;
    }
    }
    if (guestLinearAddress == 0ULL)
    {
        QMessageBox::warning(
            this,
            ks::i18n::sourceText(QStringLiteral("地址无效")),
            ks::i18n::sourceText(QStringLiteral("取不到这个进程正在执行的地址，也读不到它的主模块入口点。按住 Shift 再点这一项可以手动指定要拒绝执行的地址。")));
        return;
    }

    const bool kFreezing = operation == KSWORD_ARK_HVM_PROCESS_OP_FREEZE;
    const QString kActionTitle = kFreezing
        ? ks::i18n::sourceText(QStringLiteral("%1 冻结进程")).arg(kHvmName)
        : ks::i18n::sourceText(QStringLiteral("%1 结束进程")).arg(kHvmName);
    /*
     * The two risk descriptions differ because the operations have different natures: freezing is reversible with the cost of spinning and occupying a core;
     * Termination is irreversible. Merging the descriptions would make one of them incorrect.
     */
    // Two strings, each on a separate line, for the same reason.
    const QString kRiskText = kFreezing
        ? ks::i18n::sourceText(QStringLiteral("冻结在硬件层拒绝该地址空间执行这一页，进程状态不变、可解除。代价是被冻结的线程会在故障上自旋，持续占用一个核。生效时机取决于目标何时再执行到这一页，因此不是即时的。安装过程会自动停止并重新启动虚拟化常驻——这期间全机器的虚拟化监控是断开的。"))
        : ks::i18n::sourceText(QStringLiteral("结束在硬件层向该进程注入未定义指令异常，由系统自身的未处理异常路径拆除进程。不可逆，可能造成数据丢失。生效时机取决于目标何时再执行到这一页，因此进程退出可能有延迟。安装过程会自动停止并重新启动虚拟化常驻——这期间全机器的虚拟化监控是断开的。"));
    if (!ks::ui::confirmDestructiveAction(
            this,
            QStringLiteral("process-disposition-hvm"),
            kActionTitle,
            ks::i18n::sourceText(QStringLiteral("PID %1；页 0x%2"))
                .arg(kTargetPid)
                .arg(guestLinearAddress, 0, 16),
            kRiskText))
    {
        clearContextActionBinding();
        return;
    }

    KLogEvent actionEvent;
    warn << actionEvent
        << "[ProcessDock] executeHvmProcessDispositionAction: op="
        << operation
        << " pid=" << kTargetPid
        << eol;
    ksword::ark::DriverClient driverClient;
    /*
     * Complete the three prerequisites in order, issue the action, then restore the resident state.
     *
     * Order is mandatory, not stylistic:
     *   - CR3 tracking and the EPTP backend are consumed during VMCS creation/preparation. Setting them after the
     *     resident phase is established has no effect, so they must be configured before starting the resident phase.
     *   - Installation requires the resident hypervisor to be stopped because the exit path reads this table without a lock; stop it first;
     *   - teardown clears EPT and the hierarchy pool, so prepare must occur after teardown.
     *
     * Do not check if conditions are already met at each step; always redo the process: check the status
     * once to decide which steps to skip. This requires duplicating the driver's state machine on the UI
     * side. If this copy falls out of sync with the driver, it may skip a prerequisite that was actually
     * not met and misattribute the failure. Redoing is idempotent; the cost is only a few IOCTLs.
     */
    /*
     * Each step goes through the ksword::kvm layer; do not manually construct controlHvm.
     *
     * Directly constructing the flags came at a cost: each command has a different whitelist of allowed bits
     * (stop/teardown only accept UI_CONFIRMED, prepare does not accept FORCE), and the driver checks `(flags &
     * ~allowedFlags) != 0`. Providing even one extra bit makes the entire request INVALID_REQUEST instead of
     * ignoring the extra bit. Manually constructing the flags means re-implementing the driver's rules in a
     * second place; if you get it wrong, you only get back "Invalid Request" without knowing which bit was extra.
     *
     * That layer also handles generation passing, avoids redundant PREPARE when resources are ready, and converts
     * protocol status codes to localized reasons. Re-implementing any of these here would create a third copy.
     */
    if (!prepareHvmForArming(kActionTitle, actionEvent))
    {
        return;
    }
    // Issue the disposal. The current resident state is stopped, which is exactly the required installation state.
    const ksword::ark::HvmProcessResult kResult = driverClient.controlHvmProcess(
        operation,
        kTargetPid,
        static_cast<std::uint64_t>(guestLinearAddress),
        true);
    const bool kArmed = kResult.io.ok &&
        kResult.response.status == KSWORD_ARK_HVM_PROCESS_STATUS_OK;
    if (kArmed)
    {
        /*
         * Restart the resident hypervisor; the disposition takes effect only once it is running.
         * startResident performs self-checks on demand internally, so no separate trigger is needed here.
         *
         * This step failed and must be reported separately: the action is already installed but not
         * currently executing. If this is merged with installation failure messages, it implies nothing
         * happened, causing the next installation attempt to hit ALREADY_ARMED without understanding why.
         */
        if (stepFailedRestartResident(kActionTitle, actionEvent))
        {
            return;
        }
    }
    /*
     * The effective timing must be stated separately because it is not immediate.
     *
     * Rejection occurs at the moment the target address space executes to that page. If the target
     * is stuck in a wait, sleep, or another code path, the action will wait—the process remains in
     * the list. Without this note, the waiting period would appear identical to "not yet effective,"
     * yet the required actions are opposite: one waits, the other reissues on a different page.
     */
    const QString kSuccessAdvice = kFreezing
        ? ks::i18n::sourceText(QStringLiteral("处置已装上。它在目标下一次执行到这一页时才生效，所以进程可能不会立刻停住——正卡在等待或睡眠中的进程要等它再次运行到那里。若长时间没有反应，多半是这一页没被执行到：按住 Shift 重新下达可以换一个地址。"))
        : ks::i18n::sourceText(QStringLiteral("处置已装上。它在目标下一次执行到这一页时才生效，所以进程退出可能有延迟——正卡在等待或睡眠中的进程要等它再次运行到那里，期间它会继续留在列表里。若长时间没有退出，多半是这一页没被执行到：按住 Shift 重新下达可以换一个地址。"));
    showHvmDispositionResult(
        kActionTitle,
        kArmed,
        kResult.io.message,
        kResult.response.status,
        actionEvent,
        kSuccessAdvice);
}

void ProcessDock::executeHvmInjectAction(const unsigned long operation)
{
    // Input: operation is ARM (inject DLL) or RELEASE (revoke).
    // Processing: Validate prerequisites, select DLL, issue injection, then restore resident state.
    // Return: None; results are reported via message box and logs.
    const std::vector<ProcessActionTarget> kActionTargets = selectedActionTargets();
    if (kActionTargets.empty())
    {
        KLogEvent logEvent;
        warn << logEvent
            << "[ProcessDock] executeHvmInjectAction 被忽略：当前没有选中进程。"
            << eol;
        return;
    }
    const QString kHvmName = ks::settings::hvmDisplayNameLabel(
        ks::settings::loadAppearanceSettings().hvmDisplayName);
    // Injecting executable code into other processes requires stricter write access checks than handling; this cannot be omitted.
    if (!ksword::kvm::isWriteAccessEnabled())
    {
        QMessageBox::information(
            this,
            kHvmName,
            ks::i18n::sourceText(QStringLiteral("R-1 写权限当前是关闭的（只读观测）。注入会改变系统状态，请先在虚拟化菜单里开启写权限。")));
        return;
    }
    const ProcessActionTarget& target = kActionTargets.front();
    const unsigned long kTargetPid = target.record.pid;

    if (operation == KSWORD_ARK_HVM_INJECT_OP_RELEASE)
    {
        KLogEvent releaseEvent;
        ksword::ark::DriverClient releaseClient;
        const ksword::ark::HvmInjectResult kReleaseResult =
            releaseClient.controlHvmInject(
                KSWORD_ARK_HVM_INJECT_OP_RELEASE,
                kTargetPid, 0UL, 0ULL, 0ULL, nullptr, 0UL, true);
        showHvmDispositionResult(
            ks::i18n::sourceText(QStringLiteral("%1 撤销注入")).arg(kHvmName),
            kReleaseResult.io.ok &&
                kReleaseResult.response.status ==
                    KSWORD_ARK_HVM_INJECT_STATUS_OK,
            kReleaseResult.io.message,
            KSWORD_ARK_HVM_PROCESS_STATUS_OK,
            releaseEvent);
        return;
    }

    const QString kDllPath = QFileDialog::getOpenFileName(
        this,
        ks::i18n::sourceText(QStringLiteral("%1 注入：选择要加载的 DLL")).arg(kHvmName),
        QString(),
        ks::i18n::sourceText(QStringLiteral("动态链接库 (*.dll)")));
    if (kDllPath.isEmpty())
    {
        return;
    }
    /*
     * Trigger address is the location the target thread is currently executing.
     *
     * The driver searches backward from the page containing this address for a gap, so it must lie within code that
     * **will be executed**. The entry point is insufficient: it executes only once at startup, so for a running
     * process it effectively never triggers, which is indistinguishable from a successful external operation.
     */
    const quint64 kTriggerAddress = hvmProcessRunningThreadRip(kTargetPid);
    if (kTriggerAddress == 0ULL)
    {
        QMessageBox::warning(
            this,
            kHvmName,
            ks::i18n::sourceText(QStringLiteral("取不到这个进程正在执行的地址，无法确定从哪一页开始找空隙。")));
        return;
    }
    /*
     * Resolve LoadLibraryW within this process.
     *
     * kernel32 has the same base address for all processes within a single boot (system DLL ASLR is
     * re-randomized per boot, not per process), so the resolved value here holds for the target as well.
     */
    const HMODULE kKernel32 = ::GetModuleHandleW(L"kernel32.dll");
    const FARPROC kLoadLibrary = (kKernel32 != nullptr)
        ? ::GetProcAddress(kKernel32, "LoadLibraryW")
        : nullptr;
    if (kLoadLibrary == nullptr)
    {
        QMessageBox::warning(
            this,
            kHvmName,
            ks::i18n::sourceText(QStringLiteral("解析 LoadLibraryW 失败，无法构造注入外壳。")));
        return;
    }

    const QString kActionTitle =
        ks::i18n::sourceText(QStringLiteral("%1 注入 DLL")).arg(kHvmName);
    if (!ks::ui::confirmDestructiveAction(
            this,
            QStringLiteral("process-inject-hvm"),
            kActionTitle,
            ks::i18n::sourceText(QStringLiteral("PID %1；%2")).arg(kTargetPid).arg(kDllPath),
            ks::i18n::sourceText(QStringLiteral("注入不调用任何内核 API：载荷只存在于该页的执行视图里，读这一页的人看到的仍是原始字节。它跑在目标一个正在运行的线程上——不是新线程，而是把那个线程借用一小段，因此可能与目标当前正在做的事相互干扰。生效时机取决于目标何时再执行到那一页，所以不是即时的。安装过程会自动停止并重新启动虚拟化常驻——这期间全机器的虚拟化监控是断开的。"))))
    {
        clearContextActionBinding();
        return;
    }

    KLogEvent actionEvent;
    warn << actionEvent
        << "[ProcessDock] executeHvmInjectAction: pid=" << kTargetPid
        << eol;
    if (!prepareHvmForArming(kActionTitle, actionEvent))
    {
        return;
    }
    /*
     * Path is passed as UTF-16 (LoadLibraryW); length excludes the trailing null.
     * The driver pads excess bytes with zeros, making the trailing null redundant.
     */
    const std::wstring kWidePath = kDllPath.toStdWString();
    const unsigned long kPayloadBytes = static_cast<unsigned long>(
        kWidePath.size() * sizeof(wchar_t));
    ksword::ark::DriverClient driverClient;
    const ksword::ark::HvmInjectResult kResult = driverClient.controlHvmInject(
        KSWORD_ARK_HVM_INJECT_OP_ARM,
        kTargetPid,
        KSWORD_ARK_HVM_INJECT_TYPE_DLL_PATH,
        static_cast<std::uint64_t>(kTriggerAddress),
        static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(kLoadLibrary)),
        reinterpret_cast<const unsigned char*>(kWidePath.c_str()),
        kPayloadBytes,
        true);
    const bool kArmed = kResult.io.ok &&
        kResult.response.status == KSWORD_ARK_HVM_INJECT_STATUS_OK;
    if (kArmed)
    {
        // Injection only takes effect after becoming resident. If this step fails, report
        // it separately: injection is **already installed**, but no one is executing it.
        if (stepFailedRestartResident(kActionTitle, actionEvent))
        {
            return;
        }
    }
    /*
     * Installation does not equal execution, so we must read the execution count here.
     *
     * The return code only indicates that the shellcode and payload have been written to the shadow page; it provides no information on whether that page will be executed.
     * An injection that never triggers returns the exact same code as a successful injection. The execution
     * count is the only metric that distinguishes these two cases, so it must be read and reported to the user.
     *
     * Give the target one more chance to continue execution when the execution count is zero:
     * a frozen process/thread is entirely stuck in waiting, so that page may never be reached.
     */
    QString injectDetail = ks::i18n::sourceText(QStringLiteral("注入已装上。它在目标下一次执行到那一页时才生效，所以可能不会立刻看到效果。若长时间没有反应，多半是那一页没被执行到，或这一带找不到足够长的空隙。"));
    if (kArmed)
    {
        unsigned long long executionCount =
            hvmInjectWaitForExecution(kTargetPid, kHvmInjectSettleMilliseconds);
        std::size_t wakenedWindows = 0U;
        if (executionCount == 0ULL)
        {
            wakenedWindows = hvmProcessWakeMessageLoops(kTargetPid);
            if (wakenedWindows != 0U)
            {
                executionCount = hvmInjectWaitForExecution(
                    kTargetPid, kHvmInjectSettleMilliseconds);
            }
        }
        warn << actionEvent
            << "[ProcessDock] executeHvmInjectAction: executionCount="
            << executionCount
            << " wakenedWindows=" << static_cast<unsigned long long>(wakenedWindows)
            << eol;
        if (executionCount != 0ULL)
        {
            injectDetail = ks::i18n::sourceText(QStringLiteral("载荷已经在目标里执行过 %1 次，注入确实生效了。")).arg(executionCount);
        }
        else if (wakenedWindows != 0U)
        {
            injectDetail = ks::i18n::sourceText(QStringLiteral("注入已装上，但目标还没有执行到那一页。已向它的 %1 个窗口各投递一条空消息把消息循环唤醒（不写目标内存、不建线程），仍未触发。载荷会一直挂着，目标下次执行到那一页时自然生效。")).arg(wakenedWindows);
        }
        else
        {
            injectDetail = ks::i18n::sourceText(QStringLiteral("注入已装上，但目标当前是静止的：它的线程都停在等待里，那一页还没有被执行到，而且它没有可唤醒的顶层窗口。载荷会一直挂着，等目标自己再次运行才生效——对长期空闲的后台进程，这可能一直不发生。"));
        }
    }
    showHvmDispositionResult(
        kActionTitle,
        kArmed,
        kResult.io.message,
        KSWORD_ARK_HVM_PROCESS_STATUS_OK,
        actionEvent,
        injectDetail);
}
