#include "KvmDock.h"

#include "../internationalization/LanguageManager.h"
#include "../kernel_dock/KernelHvmTab.h"
#include "../ui/FlowLayout.h"
#include "../ui/KvmControl.h"
#include "../ui/KvmGuestVmPanel.h"
#include "../ui/KvmWatchPanel.h"
#include "../Theme.h"

#include <QGroupBox>
#include <QHideEvent>
#include <QLabel>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QScrollArea>
#include <QShowEvent>
#include <QTabWidget>
#include <QTimer>
#include <QVBoxLayout>
#include <QVariant>

#include <thread>
#include <utility>

namespace
{
    // Polling interval. Status queries are blocking IOCTLs. While a single read is cheap, the driver-side status lock is held
    // exclusively during resident switching, causing queries to queue indefinitely; thus, the interval cannot be shortened further.
    constexpr int kStatePollIntervalMilliseconds = 2000;

    enum class StepPhase
    {
        kDone,
        kActive,
        kPending
    };

    // All three states are expressed using QSS dynamic palette roles. Static *ColorHex() can display here,
    // but it won't update automatically after a theme switch, and this page has no rebuild entry point.
    void applyStepStyle(QLabel* const label, const StepPhase phase)
    {
        if (label == nullptr)
        {
            return;
        }
        QString backgroundColor = QStringLiteral("transparent");
        QString textColor = ksword_theme::textSecondaryHex();
        QString borderColor = ksword_theme::borderHex();
        if (phase == StepPhase::kActive)
        {
            backgroundColor = ksword_theme::kPrimaryBlueHex;
            textColor = ksword_theme::onAccentDynamicHex();
            borderColor = ksword_theme::kPrimaryBlueHex;
        }
        else if (phase == StepPhase::kDone)
        {
            textColor = ksword_theme::textPrimaryHex();
            borderColor = ksword_theme::borderStrongHex();
        }
        label->setStyleSheet(
            QStringLiteral(
                "QLabel{"
                "  background:%1;"
                "  color:%2;"
                "  border:1px solid %3;"
                "  border-radius:%4px;"
                "  padding:3px 10px;"
                "  font-weight:600;"
                "}")
                .arg(backgroundColor)
                .arg(textColor)
                .arg(borderColor)
                .arg(ksword_theme::kControlCornerRadius));
    }

    // The 'why gray' reason must follow the button: the call site can determine the disable condition, but the
    // user only sees a gray button. On the first call, store the static explanation in a dynamic property; on
    // subsequent calls, rebuild based on it. Otherwise, repeated disables would stack reasons into a long string.
    void setGatedTooltip(QPushButton* const button, const QString& gateReason)
    {
        if (button == nullptr)
        {
            return;
        }
        const QVariant kStoredBaseTooltip = button->property("ks_base_tooltip");
        const QString kBaseTooltip = kStoredBaseTooltip.isValid()
            ? kStoredBaseTooltip.toString()
            : button->toolTip();
        if (!kStoredBaseTooltip.isValid())
        {
            button->setProperty("ks_base_tooltip", kBaseTooltip);
        }
        if (gateReason.isEmpty())
        {
            button->setToolTip(kBaseTooltip);
            return;
        }
        button->setToolTip(kBaseTooltip.isEmpty()
            ? gateReason
            : kBaseTooltip + QLatin1Char('\n') + gateReason);
    }
}

KvmDock::KvmDock(QWidget* const parent)
    : QWidget(parent)
{
    initializeUi();
    updateLifecycleView();
}

void KvmDock::setActionHandler(ActionHandler handler)
{
    actionHandler_ = std::move(handler);
}

void KvmDock::setCommandOperationHandler(std::function<void(bool)> handler)
{
    commandOperationHandler_ = std::move(handler);
}

void KvmDock::setOperationRunning(const bool running)
{
    if (operationRunning_ == running)
    {
        return;
    }
    operationRunning_ = running;
    hvmTab_->setEnabled(!running);
    // Memory monitoring sends the same EPT rule IOCTL as other entry points, sharing the driver-side state lock.
    watchPanel_->setEnabled(!running);
    // The 'Run Third-Party VMs' page sends the same set of control commands and must be serialized together with other entry points:
    // If omitted, users can still press 'Complete all five steps in one click' while commands are in flight,
    // causing two IOCTL paths to simultaneously contend for the driver-side state lock. When initiated by itself,
    // it first disables its own button via setBusy, then gets disabled along with the entire page by this line.
    guestVmPanel_->setEnabled(!running);
    updateLifecycleView();
    if (!running)
    {
        // The command just finished and the state lock is already released: immediately perform a query refresh
        // to avoid waiting for the next polling cycle, otherwise the user will see stale steps for two seconds.
        refreshStateAsync();
    }
}

void KvmDock::showEvent(QShowEvent* const event)
{
    QWidget::showEvent(event);
    refreshStateAsync();
    if (pollTimer_ != nullptr)
    {
        pollTimer_->start();
    }
}

void KvmDock::hideEvent(QHideEvent* const event)
{
    QWidget::hideEvent(event);
    // Stop the timer when the page is not visible: this page is not part of resident monitoring, so there is no need for the background to keep sending IOCTLs.
    if (pollTimer_ != nullptr)
    {
        pollTimer_->stop();
    }
}

void KvmDock::initializeUi()
{
    auto* const kRootLayout = new QVBoxLayout(this);
    kRootLayout->setContentsMargins(6, 6, 6, 6);
    kRootLayout->setSpacing(6);

    // Persistent header: displays only the current step.
    //
    // These two lines are the only elements that must remain visible on any sub-page. After switching to the Evidence
    // page, users must still know their current step; otherwise, the sub-tabs would sever the main lifecycle thread.
    auto* const kHeaderPanel = new QWidget(this);
    auto* const kHeaderLayout = new QVBoxLayout(kHeaderPanel);
    kHeaderLayout->setContentsMargins(0, 0, 0, 0);
    kHeaderLayout->setSpacing(4);

    // Breadcrumb uses a line-break layout: at 1024 width, three segments plus two arrows fill the space exactly; if
    // narrower, QHBoxLayout would truncate the labels, whereas a line-break layout wraps them to the second line.
    auto* const kStepRow = new ks::ui::FlowLayout(nullptr, 0, 6, 4);
    stepOneLabel_ = new QLabel(
        ks::i18n::sourceText(QStringLiteral("第 1 步 · 准备资源")),
        kHeaderPanel);
    stepTwoLabel_ = new QLabel(
        ks::i18n::sourceText(QStringLiteral("第 2 步 · 安装视图 / 策略 / 域")),
        kHeaderPanel);
    stepThreeLabel_ = new QLabel(
        ks::i18n::sourceText(QStringLiteral("第 3 步 · 启动常驻")),
        kHeaderPanel);
    kStepRow->addWidget(stepOneLabel_);
    kStepRow->addWidget(new QLabel(QStringLiteral("→"), kHeaderPanel));
    kStepRow->addWidget(stepTwoLabel_);
    kStepRow->addWidget(new QLabel(QStringLiteral("→"), kHeaderPanel));
    kStepRow->addWidget(stepThreeLabel_);
    kHeaderLayout->addLayout(kStepRow);

    stateLabel_ = new QLabel(kHeaderPanel);
    stateLabel_->setWordWrap(true);
    stateLabel_->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;")
            .arg(ksword_theme::textPrimaryHex()));
    kHeaderLayout->addWidget(stateLabel_);
    kRootLayout->addWidget(kHeaderPanel);

    // Sub-tabs: Split the previously vertically stacked five-section control panel.
    //
    // Stacking vertically on a 1024×768 screen is a disaster: three groups plus two lines of explanatory text consume two-thirds of
    // the height, leaving only two or three lines for per-CPU tables; meanwhile, buttons within each group are horizontally clipped.
    // After splitting into sub-pages, each page handles only one task, eliminating simultaneous expansion in both directions.
    auto* const kTabs = new QTabWidget(this);
    tabs_ = kTabs;
    kTabs->setDocumentMode(true);

    auto* const kControlPanel = new QWidget(kTabs);
    auto* const kControlLayout = new QVBoxLayout(kControlPanel);
    kControlLayout->setContentsMargins(6, 6, 6, 6);
    kControlLayout->setSpacing(6);

    // Step 1: Preparation and release. Neither enters resident mode; together they define the window for Step 2.
    auto* const kPrepareGroup = new QGroupBox(
        ks::i18n::sourceText(QStringLiteral("第 1 步 · 资源（不进入常驻）")),
        kControlPanel);
    auto* const kPrepareRow = new ks::ui::FlowLayout(kPrepareGroup, 6, 6, 4);
    prepareButton_ = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("准备资源（不进入常驻）")),
        kPrepareGroup);
    // The note explicitly names both backends: the structure on AMD machines remains unchanged, though some entries will be grayed out.
    // Hard-coding Intel terminology here forces AMD users to see an irrelevant message when clicking the button.
    prepareButton_->setToolTip(ks::i18n::sourceText(QStringLiteral("按当前后端分配每处理器资源并建立 EPT 或 NPT，但不进入常驻。分离视图、MSR 策略、CR 策略与执行域都必须在这一步之后、启动常驻之前安装 —— 常驻期间这几张表都是不可变的。")));
    releaseButton_ = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("释放资源")),
        kPrepareGroup);
    releaseButton_->setToolTip(ks::i18n::sourceText(QStringLiteral("释放全部可逆资源，回到未准备状态。改过分离视图后端或每处理器私有 EPT 之后必须走这一步 —— 那两个选择只在准备资源时被消费，已准备的运行时改开关不会生效。")));
    // "Hardware Virtualization Evidence" was previously only accessible by navigating to the last sub-tab. It is now
    // placed in Step 1 because it answers the prerequisite question for this step: what backend is this machine using, and
    // how far has per-core preparation progressed? It is read-only and does not change state when clicked at any time.
    evidenceButton_ = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("硬件虚拟化证据")),
        kPrepareGroup);
    evidenceButton_->setToolTip(ks::i18n::sourceText(QStringLiteral("切到证据页：完整能力、逐处理器状态与退出计数。只读，不改变任何状态。")));
    kPrepareRow->addWidget(prepareButton_);
    kPrepareRow->addWidget(releaseButton_);
    kPrepareRow->addWidget(evidenceButton_);
    kControlLayout->addWidget(kPrepareGroup);

    // Step 2: A guided entry plus seven R-1 panels. They do not change state themselves; the installation actions inside
    // do. Those actions require resources to be prepared and not resident—exactly what the group box title states.
    auto* const kInstallGroup = new QGroupBox(
        ks::i18n::sourceText(QStringLiteral("第 2 步 · 安装（要求资源已准备且未常驻）")),
        kControlPanel);
    auto* const kInstallRow = new ks::ui::FlowLayout(kInstallGroup, 6, 6, 4);
    // Wizard entry placed first: It is the only one in this group that does not require the user to calculate the physical page address beforehand.
    // Keep the following seven panels unchanged for experts—they offer more capabilities at the cost of requiring manual preparation for every value.
    hookWizardButton_ = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("添加 Hook（引导式）...")),
        kInstallGroup);
    hookWizardButton_->setToolTip(ks::i18n::sourceText(QStringLiteral("按模块加偏移或虚拟地址指定目标，自动翻译成页对齐的物理地址；影子页默认与目标页逐字节相同，只改你指定的那几个字节。装前逐条预检，装后把 EPT 叶读回来核对。")));
    viewButton_ = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("EPT 分离视图（隐蔽 Hook / 内存隐藏）...")),
        kInstallGroup);
    domainButton_ = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("EPT 执行域（VMFUNC 可切换）...")),
        kInstallGroup);
    msrButton_ = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("MSR 策略...")),
        kInstallGroup);
    crButton_ = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("控制寄存器策略...")),
        kInstallGroup);
    memoryButton_ = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("R-1 内存操作...")),
        kInstallGroup);
    eventButton_ = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("事件流...")),
        kInstallGroup);
    processButton_ = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("R-1 进程处置与注入...")),
        kInstallGroup);
    processButton_->setToolTip(ks::i18n::sourceText(QStringLiteral("在 R0 之外冻结或结束一个进程，或用分离视图加线程劫持在目标里加载 DLL。要求先开启 CR3 追踪、用 EPTP 切换后端准备资源，且常驻停着。这不是安全边界：目标换掉自己那一页的物理页就不在被拒绝的页上了。")));
    for (QPushButton* const kButton :
         { hookWizardButton_, viewButton_, domainButton_, msrButton_, crButton_,
           memoryButton_, eventButton_, processButton_ })
    {
        kInstallRow->addWidget(kButton);
    }
    kControlLayout->addWidget(kInstallGroup);

    // Step 3: Entering and exiting resident mode, plus the unique exit point: 'do this first if stuck'.
    auto* const kResidentGroup = new QGroupBox(
        ks::i18n::sourceText(QStringLiteral("第 3 步 · 常驻与故障")),
        kControlPanel);
    auto* const kResidentRow = new ks::ui::FlowLayout(kResidentGroup, 6, 6, 4);
    residentButton_ = new QPushButton(kResidentGroup);
    soakButton_ = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("常驻保持自检（5 秒）")),
        kResidentGroup);
    soakButton_->setToolTip(ks::i18n::sourceText(QStringLiteral("全部逻辑处理器会用当前后端进入来宾态并保持数秒后自动退出。期间任何未被处理的退出都会被记录为掉核，与已有 Hypervisor 冲突时可能导致系统不稳定。")));
    resetFaultButton_ = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("重置故障状态")),
        kResidentGroup);
    kResidentRow->addWidget(residentButton_);
    kResidentRow->addWidget(soakButton_);
    kResidentRow->addWidget(resetFaultButton_);
    kControlLayout->addWidget(kResidentGroup);

    // Place the explanatory text at the bottom of the control page rather than the top: it explains that the right-click
    // menu remains unchanged. Since this is a one-time read, occupying the top would push all three groups down.
    hintLabel_ = new QLabel(
        ks::i18n::sourceText(QStringLiteral("标题栏 KVM 按钮的右键菜单原样保留，能力与这一页一致；这一页额外把生命周期顺序和每一步的前置条件写出来。")),
        kControlPanel);
    hintLabel_->setWordWrap(true);
    hintLabel_->setStyleSheet(
        QStringLiteral("color:%1;").arg(ksword_theme::textSecondaryHex()));
    kControlLayout->addWidget(hintLabel_);
    kControlLayout->addStretch(1);

    for (QPushButton* const kButton :
         { prepareButton_,
           releaseButton_,
           evidenceButton_,
           hookWizardButton_,
           viewButton_,
           domainButton_,
           msrButton_,
           crButton_,
           memoryButton_,
           eventButton_,
           processButton_,
           residentButton_,
           soakButton_,
           resetFaultButton_ })
    {
        kButton->setStyleSheet(ksword_theme::themedButtonStyle());
    }

    connect(prepareButton_, &QPushButton::clicked, this, [this]() {
        requestAction(Action::kPrepareResources);
    });
    connect(releaseButton_, &QPushButton::clicked, this, [this]() {
        requestAction(Action::kReleaseResources);
    });
    // Note: The Evidence tab does not go through ActionHandler; it is not a control command, but simply switches to this tab's sub-tab.
    // Using dispatch adds an unnecessary no-op branch to mainWindow.
    connect(evidenceButton_, &QPushButton::clicked, this, [this]() {
        tabs_->setCurrentWidget(hvmTab_);
    });
    connect(hookWizardButton_, &QPushButton::clicked, this, [this]() {
        requestAction(Action::kOpenHookWizard);
    });
    connect(viewButton_, &QPushButton::clicked, this, [this]() {
        requestAction(Action::kOpenViewDialog);
    });
    connect(domainButton_, &QPushButton::clicked, this, [this]() {
        requestAction(Action::kOpenDomainDialog);
    });
    connect(msrButton_, &QPushButton::clicked, this, [this]() {
        requestAction(Action::kOpenMsrPolicyDialog);
    });
    connect(crButton_, &QPushButton::clicked, this, [this]() {
        requestAction(Action::kOpenCrPolicyDialog);
    });
    connect(memoryButton_, &QPushButton::clicked, this, [this]() {
        requestAction(Action::kOpenMemoryDialog);
    });
    connect(eventButton_, &QPushButton::clicked, this, [this]() {
        requestAction(Action::kOpenEventDialog);
    });
    connect(processButton_, &QPushButton::clicked, this, [this]() {
        requestAction(Action::kOpenProcessDialog);
    });
    connect(residentButton_, &QPushButton::clicked, this, [this]() {
        requestAction(Action::kToggleResident);
    });
    connect(soakButton_, &QPushButton::clicked, this, [this]() {
        requestAction(Action::kSoak);
    });
    connect(resetFaultButton_, &QPushButton::clicked, this, [this]() {
        requestAction(Action::kResetFault);
    });

    // Status detail page: snapshot original text.
    //
    // Placed on a separate page instead of crowded with buttons because its row count is uncontrolled—each additional backend,
    // nested item, write access, or self-check entry adds a row, and button positions should not drift up and down with it.
    // Wrap in a scroll area: allow scrolling when row count exceeds page height to prevent text from being squeezed out.
    auto* const kDetailPage = new QScrollArea(kTabs);
    kDetailPage->setWidgetResizable(true);
    kDetailPage->setFrameShape(QFrame::NoFrame);
    auto* const kDetailHost = new QWidget(kDetailPage);
    auto* const kDetailLayout = new QVBoxLayout(kDetailHost);
    kDetailLayout->setContentsMargins(6, 6, 6, 6);
    kDetailLayout->setSpacing(6);
    detailLabel_ = new QLabel(kDetailHost);
    detailLabel_->setWordWrap(true);
    detailLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    detailLabel_->setAlignment(Qt::AlignTop | Qt::AlignLeft);
    detailLabel_->setStyleSheet(
        QStringLiteral("color:%1;").arg(ksword_theme::textSecondaryHex()));
    kDetailLayout->addWidget(detailLabel_);
    kDetailLayout->addStretch(1);
    kDetailPage->setWidget(kDetailHost);

    // Hardware virtualization page moved wholesale from the 'Kernel' tab. It carries PREPARE /
    // SELF_TEST / one-time guest / TEARDOWN and EPT rules. Since EPT rules are reachable only
    // through this path, they must be moved along rather than replaced by the buttons above.
    //
    // It includes its own per-CPU table and a details panel, requiring a dedicated page to be visible: previously, when
    // sharing a splitter with the Control Panel, the default split allocated only two or three rows of the table to it.
    hvmTab_ = new KernelHvmTab(kTabs);

    // Third-party virtual machines are listed first.
    //
    // This is the only page designed for users unfamiliar with virtualization: the other three pages assume the reader knows what PREPARE,
    // resident mode, and EPT are. The issue 'VMware won't launch after installing KSwordVM' is exactly what ordinary users encounter most
    // frequently and are least likely to diagnose themselves—VMware reports 'incompatible with Hyper-V,' which points nowhere near us.
    // Placing this on the first page ensures users can find the solution without needing to know what to search for first.
    guestVmPanel_ = new KvmGuestVmPanel(kTabs);
    guestVmPanel_->onBusyChanged = [this](bool running) {
        setOperationRunning(running);
        if (commandOperationHandler_) { commandOperationHandler_(running); }
    };
    kTabs->addTab(guestVmPanel_,
                 ks::i18n::sourceText(QStringLiteral("跑第三方虚拟机")));

    kTabs->addTab(kControlPanel, ks::i18n::sourceText(QStringLiteral("控制")));

    // Memory monitoring is placed after controls and before status details.
    //
    // This is the only feature on this page that produces evidence rather than changing state: the other pages
    // answer 'what is installed now, where did we get to', while this page answers 'who will touch it next'. It is
    // placed right next to the Control page because it has a hard prerequisite—the resident process must be running;
    // otherwise, the installed monitoring will never trigger, and that condition is managed by the Control page.
    watchPanel_ = new KvmWatchPanel(kTabs);
    watchPanel_->onBusyChanged = [this](bool running) {
        setOperationRunning(running);
        if (commandOperationHandler_) { commandOperationHandler_(running); }
    };
    kTabs->addTab(watchPanel_, ks::i18n::sourceText(QStringLiteral("内存监视")));

    kTabs->addTab(kDetailPage, ks::i18n::sourceText(QStringLiteral("状态详情")));
    // The tab name no longer specifies VT-x/EPT: the same tab displays SVM/NPT readings on AMD machines. Hardcoding the tab
    // name to a single architecture would lead users of the other architecture to assume this tab is irrelevant to them.
    kTabs->addTab(hvmTab_, ks::i18n::sourceText(QStringLiteral("硬件虚拟化证据")));
    // Default to the 'Control' tab instead of the first page: 'Run third-party VMs' is an exit path for users encountering
    // issues, not the main flow. The main flow is the three-step lifecycle, which resides on the 'Control' tab.
    kTabs->setCurrentWidget(kControlPanel);
    kRootLayout->addWidget(kTabs, 1);

    pollTimer_ = new QTimer(this);
    pollTimer_->setInterval(kStatePollIntervalMilliseconds);
    connect(pollTimer_, &QTimer::timeout, this, [this]() {
        refreshStateAsync();
    });
}

void KvmDock::refreshStateAsync()
{
    // Merge concurrent queries: polling is periodic; accumulated requests only slow down the driver.
    // Also skip queries during command execution: the state lock is exclusively held, so a query would just hang waiting.
    if (queryInFlight_ || operationRunning_)
    {
        return;
    }
    queryInFlight_ = true;
    QPointer<KvmDock> safeThis(this);
    std::thread([safeThis]() {
        const ksword::kvm::KvmState kState = ksword::kvm::queryState();
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, kState]() {
                if (safeThis == nullptr)
                {
                    return;
                }
                safeThis->queryInFlight_ = false;
                safeThis->applyState(kState);
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmDock::applyState(const ksword::kvm::KvmState& state)
{
    driverRunning_ =
        state.availability != ksword::kvm::KvmAvailability::kDriverNotRunning;
    hardwareAvailable_ =
        state.availability == ksword::kvm::KvmAvailability::kAvailable ||
        state.availability == ksword::kvm::KvmAvailability::kNotPrepared;
    // Read the bit returned directly by the driver to determine if resources are ready, instead of inferring from availability.
    //
    // Reverse engineering reveals that on AMD, the answer is inverted: 'availability' reports 'whether resident is
    // possible', but the AMD backend may still not land in 'Available' after preparation completes due to other conditions.
    // In this scenario, the Step 2 window is open, yet the progress bar remains stuck at Step 1. 'resourcesReady' is the
    // driver's direct feedback indicating PREPARE has executed and TEARDOWN has not, eliminating this ambiguity.
    resourcesReady_ = state.resourcesReady;
    amdBackend_ = state.backend == KSWORD_ARK_HVM_BACKEND_SVM;
    residentActive_ = state.residentActive;
    faulted_ = state.faulted;
    availabilityText_ = ksword::kvm::describeAvailability(state.availability);
    detailText_ = state.detail;
    updateLifecycleView();
}

void KvmDock::updateLifecycleView()
{
    // The three step labels only indicate "where we are"; button availability is calculated separately:
    // In fault state, all buttons are disabled, but the step indicator must still show whether resources have been prepared.
    StepPhase stepOnePhase = StepPhase::kPending;
    StepPhase stepTwoPhase = StepPhase::kPending;
    StepPhase stepThreePhase = StepPhase::kPending;
    if (residentActive_)
    {
        stepOnePhase = StepPhase::kDone;
        stepTwoPhase = StepPhase::kDone;
        stepThreePhase = StepPhase::kActive;
    }
    else if (resourcesReady_)
    {
        stepOnePhase = StepPhase::kDone;
        stepTwoPhase = StepPhase::kActive;
    }
    else if (driverRunning_ && hardwareAvailable_)
    {
        stepOnePhase = StepPhase::kActive;
    }
    applyStepStyle(stepOneLabel_, stepOnePhase);
    applyStepStyle(stepTwoLabel_, stepTwoPhase);
    applyStepStyle(stepThreeLabel_, stepThreePhase);

    QString stateText;
    if (operationRunning_)
    {
        stateText = ks::i18n::sourceText(QStringLiteral("当前：正在执行一项 KVM 操作，等它结束。"));
    }
    else if (!driverRunning_)
    {
        stateText = ks::i18n::sourceText(QStringLiteral("当前：KswordARK 驱动未运行。先用标题栏的 R0 按钮启动驱动服务，这一页的入口在那之前都不会生效。"));
    }
    else if (faulted_)
    {
        stateText = ks::i18n::sourceText(QStringLiteral("当前：故障或待回滚。先执行“重置故障状态”，其余入口在那之前都不会生效。"));
    }
    else if (!hardwareAvailable_)
    {
        stateText = ks::i18n::sourceText(QStringLiteral("当前：不可用。%1")).arg(availabilityText_);
    }
    else if (residentActive_)
    {
        stateText = ks::i18n::sourceText(QStringLiteral("当前：第 3 步。常驻运行中；分离视图、MSR 策略、CR 策略与执行域这几张表在常驻期间不可改，要改先停止常驻。"));
    }
    else if (resourcesReady_ && amdBackend_)
    {
        // Step 2 is empty on AMD: none of the installation entry points have SVM implementations yet. Copying the
        // Intel phrasing would lead users to look for a non-clickable window, so this state is explained separately.
        stateText = ks::i18n::sourceText(QStringLiteral("当前：第 2 步。资源已按 AMD SVM/NPT 准备好且未常驻。第 2 步的安装类入口尚无 SVM 实现，AMD 上可以直接进入第 3 步启动常驻。"));
    }
    else if (resourcesReady_)
    {
        stateText = ks::i18n::sourceText(QStringLiteral("当前：第 2 步。资源已准备且未常驻，这是安装分离视图、MSR 策略、CR 策略与执行域的唯一窗口期。"));
    }
    else
    {
        stateText = ks::i18n::sourceText(QStringLiteral("当前：第 1 步。资源尚未准备，先点“准备资源（不进入常驻）”。"));
    }
    stateLabel_->setText(stateText);
    detailLabel_->setText(detailText_);
    detailLabel_->setVisible(!detailText_.isEmpty());

    residentButton_->setText(residentActive_
        ? ks::i18n::sourceText(QStringLiteral("停止常驻"))
        : ks::i18n::sourceText(QStringLiteral("启动常驻")));

    // Each button's gate matches the right-click menu item-by-item; here we simply state the reason for being grayed out.
    const QString kDriverGate =
        ks::i18n::sourceText(QStringLiteral("灰掉的原因：KswordARK 驱动未运行。"));
    const QString kBusyGate =
        ks::i18n::sourceText(QStringLiteral("灰掉的原因：正在执行另一项 KVM 操作。"));
    const QString kResidentGate =
        ks::i18n::sourceText(QStringLiteral("灰掉的原因：常驻运行中，这一步只能在未常驻时做。"));
    const QString kHardwareGate =
        ks::i18n::sourceText(QStringLiteral("灰掉的原因：当前硬件或系统状态不满足 KVM 常驻条件。"));

    const auto kResourceStageReason = [&]() -> QString {
        if (operationRunning_) { return kBusyGate; }
        if (!driverRunning_) { return kDriverGate; }
        if (residentActive_) { return kResidentGate; }
        if (!hardwareAvailable_) { return kHardwareGate; }
        return QString();
    };
    const QString kResourceGateReason = kResourceStageReason();
    prepareButton_->setEnabled(kResourceGateReason.isEmpty());
    setGatedTooltip(prepareButton_, kResourceGateReason);
    // Resource release does not depend on the hardware gate: the hardware gate answers "can it remain resident", whereas the
    // release operation does the opposite—reclaiming already allocated resources. Using the "ready" gate for judgment alongside it
    // would leave no exit for the state where "hardware conditions changed but resources are still held", forcing a machine reboot.
    const QString kReleaseReason = operationRunning_ ? kBusyGate
        : !driverRunning_ ? kDriverGate
        : residentActive_ ? kResidentGate
        : QString();
    releaseButton_->setEnabled(kReleaseReason.isEmpty());
    setGatedTooltip(releaseButton_, kReleaseReason);
    // Evidence pages are read-only; accessible if the driver is running.
    const QString kEvidenceReason = operationRunning_ ? kBusyGate
        : !driverRunning_ ? kDriverGate
        : QString();
    evidenceButton_->setEnabled(kEvidenceReason.isEmpty());
    setGatedTooltip(evidenceButton_, kEvidenceReason);

    // These eight entries are accessible as long as the driver is running: each has its own gate for reading status and performing writable actions.
    // It remains accessible while resident; otherwise, users cannot even see 'what is currently installed'.
    const QString kPanelGateReason = driverRunning_ ? QString() : kDriverGate;
    for (QPushButton* const kButton :
         { hookWizardButton_, viewButton_, domainButton_, msrButton_, crButton_,
           memoryButton_, eventButton_, processButton_ })
    {
        kButton->setEnabled(driverRunning_);
        setGatedTooltip(kButton, kPanelGateReason);
    }

    // AMD backend: Keep the structure unchanged, gray out entries without corresponding implementations, and explain the reason.
    //
    // The commonality among these disabled items is not that "AMD cannot do it," but rather that they all rely on the EPT
    // split-view mechanism (concealed hooks, views, execution domains, R-1 process handling, and injection all require
    // EPTP switching). The SVM/NPT backend currently only supports resource preparation, per-core VMRUN self-checks, and
    // residency. MSR and CR policies are similar; they consume VMCS fields rather than corresponding bits in VMCB.
    //
    // We keep the buttons visible instead of hiding them to distinguish between 'this feature is unavailable on this machine' and 'this feature is
    // not yet implemented in this version': hidden entries cannot express the latter, leading users to believe they are looking in the wrong place.
    // Memory operations and event flows are not included: they use the physical memory window and event loop, independent of the backend.
    if (amdBackend_)
    {
        const QString kAmdGate = ks::i18n::sourceText(QStringLiteral("灰掉的原因：这一项建立在 EPT 分离视图或 VMCS 字段上，当前的 AMD SVM/NPT 后端还没有对应实现。AMD 上可用的是资源准备、逐核自检与常驻。"));
        for (QPushButton* const kButton :
             { hookWizardButton_, viewButton_, domainButton_, msrButton_,
               crButton_, processButton_ })
        {
            kButton->setEnabled(false);
            setGatedTooltip(kButton, kAmdGate);
        }
    }

    const auto kResidentToggleReason = [&]() -> QString {
        if (operationRunning_) { return kBusyGate; }
        if (!driverRunning_) { return kDriverGate; }
        if (residentActive_) { return QString(); }
        if (!hardwareAvailable_) { return kHardwareGate; }
        return QString();
    };
    const QString kResidentReason = kResidentToggleReason();
    residentButton_->setEnabled(kResidentReason.isEmpty());
    setGatedTooltip(residentButton_, kResidentReason);

    const QString kSoakReason = kResourceGateReason;
    soakButton_->setEnabled(kSoakReason.isEmpty());
    setGatedTooltip(soakButton_, kSoakReason);

    const auto kFaultResetReason = [&]() -> QString {
        if (operationRunning_) { return kBusyGate; }
        if (!driverRunning_) { return kDriverGate; }
        if (!faulted_)
        {
            return ks::i18n::sourceText(QStringLiteral("灰掉的原因：当前没有记录到故障或待回滚标记。"));
        }
        return QString();
    };
    const QString kFaultReason = kFaultResetReason();
    resetFaultButton_->setEnabled(kFaultReason.isEmpty());
    setGatedTooltip(resetFaultButton_, kFaultReason);
}

void KvmDock::requestAction(const Action action)
{
    if (!actionHandler_)
    {
        return;
    }
    actionHandler_(action);
    // Control commands immediately advance mainWindow to setOperationRunning(true); that path
    // performs its own query. Opening the panel changes nothing, so adding a query here is harmless.
    refreshStateAsync();
}
