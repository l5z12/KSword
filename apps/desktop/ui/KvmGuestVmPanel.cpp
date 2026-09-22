#include "KvmGuestVmPanel.h"

#include "../internationalization/LanguageManager.h"
#include "../../../shared/platform/service/Service.h"
#include "../Theme.h"
#include "KvmControl.h"

#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QScrollArea>
#include <QShowEvent>
#include <QVBoxLayout>

#include <thread>

// Every long sentence in this file intended for users is written on a **single line**, not split into adjacent literals.
// Splitting this line would cause the term extraction tool to treat each fragment as an independent entry in the language
// pack, while at runtime `sourceText` receives the concatenated string. This results in a language pack filled with fragments
// that never match, while the actual entry remains missing. Existing long tooltips in the repository are all single-line.

namespace
{
    // VMware VMX driver service name. It queries CPU capabilities only once upon its own startup
    // and caches the result, so after the preceding steps, it must be forced to query again.
    const wchar_t* const kVmwareDriverService = L"vmx86";

    // Win32 SERVICE_STOPPED / SERVICE_RUNNING; avoid including winsvc.h just for these two constants.
    constexpr std::uint32_t kServiceStopped = 1U;
    constexpr std::uint32_t kServiceRunning = 4U;

    QString doneMark()
    {
        return ks::i18n::sourceText(QStringLiteral("已完成"));
    }

    QString todoMark()
    {
        return ks::i18n::sourceText(QStringLiteral("还没做"));
    }

    void paintStatus(QLabel* label, const QString& text, bool done)
    {
        if (label == nullptr) { return; }
        label->setText(text);
        label->setStyleSheet(QStringLiteral("color:%1;").arg(
            done ? ksword_theme::successHex() : ksword_theme::warningHex()));
    }
}

KvmGuestVmPanel::KvmGuestVmPanel(QWidget* parent)
    : QWidget(parent)
{
    auto* const kOuter = new QVBoxLayout(this);
    kOuter->setContentsMargins(0, 0, 0, 0);

    auto* const kScroll = new QScrollArea(this);
    kScroll->setWidgetResizable(true);
    kScroll->setFrameShape(QFrame::NoFrame);
    auto* const kHost = new QWidget(kScroll);
    auto* const kLayout = new QVBoxLayout(kHost);
    kLayout->setContentsMargins(14, 14, 14, 14);
    kLayout->setSpacing(10);

    intro_ = new QLabel(kHost);
    intro_->setWordWrap(true);
    intro_->setText(ks::i18n::sourceText(QStringLiteral("本机启用 KSwordVM 之后，它会占住 CPU 的虚拟化功能。VMware、VirtualBox、WSL2、Docker Desktop 要用的是同一套功能，因此必须由 KSwordVM 主动让出来，并且对它们隐藏自己的存在。下面五步全部完成之后，这些软件就能照常打开虚拟机。顺序是有讲究的：前三步是设置，第四步才把 KSwordVM 真正跑起来，第五步让 VMware 重新去问一次 CPU 能力。少做任何一步虚拟机软件都会打不开，而且它给出的错误提示不会提到 KSwordVM。")));
    kLayout->addWidget(intro_);

    auto* const kButtonRow = new QHBoxLayout();
    doAll_ = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("一键完成全部五步")), kHost);
    doAll_->setToolTip(ks::i18n::sourceText(QStringLiteral("按顺序执行：打开三个设置，准备并启动 KSwordVM，最后重启 VMware 的驱动服务。每一步的结果都会显示在下面的清单里。")));
    connect(doAll_, &QPushButton::clicked, this, [this]() {
        runInBackground([this]() -> QString {
            enableAllSwitches();
            startMonitor();
            restartVmwareDriver();
            return ks::i18n::sourceText(QStringLiteral("五步已执行完，请看下面每一步的状态。"));
        });
    });
    kButtonRow->addWidget(doAll_);

    refresh_ = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("刷新状态")), kHost);
    connect(refresh_, &QPushButton::clicked, this, [this]() { refreshAsync(); });
    kButtonRow->addWidget(refresh_);
    kButtonRow->addStretch(1);
    kLayout->addLayout(kButtonRow);

    stepAllowNested_ = addStep(kLayout, 1,
        ks::i18n::sourceText(QStringLiteral("允许 KSwordVM 运行在虚拟机里")),
        ks::i18n::sourceText(QStringLiteral("如果这台电脑本身就是一台虚拟机，或者系统开着「内存完整性」，那么 KSwordVM 只能以这种方式运行。代价是每一条虚拟化指令都要由外面那层软件代为处理，速度会明显变慢。不确定要不要开就开着，它不改动系统任何设置。")),
        ks::i18n::sourceText(QStringLiteral("打开")),
        [this]() {
            runInBackground([this]() -> QString {
                markConfigurationChanged();
                ksword::kvm::setNestedAllowed(true);
                return ks::i18n::sourceText(QStringLiteral("第 1 步已打开。"));
            });
        });

    stepHostGuests_ = addStep(kLayout, 2,
        ks::i18n::sourceText(QStringLiteral("允许别的虚拟机运行在 KSwordVM 下面")),
        ks::i18n::sourceText(QStringLiteral("这一项和上一项方向相反：上一项是让 KSwordVM 跑在别人下面，这一项是让别人跑在 KSwordVM 下面。不打开的话，VMware 一按「开启此虚拟机」就会失败。它有两个前提：需要先打开「允许 R-1 写操作」，并且关掉「每处理器私有 EPT」，后者和这一项不能同时开，同时开会被整条拒绝。")),
        ks::i18n::sourceText(QStringLiteral("打开")),
        [this]() {
            runInBackground([this]() -> QString {
                if (ksword::kvm::isLocalEptEnabled())
                {
                    return ks::i18n::sourceText(QStringLiteral("打不开：「每处理器私有 EPT」正开着，它和这一项不能同时开，请先关掉它。"));
                }
                if (!ksword::kvm::isWriteAccessEnabled())
                {
                    return ks::i18n::sourceText(QStringLiteral("打不开：需要先打开「允许 R-1 写操作」。"));
                }
                markConfigurationChanged();
                ksword::kvm::setNestedDispatchEnabled(true);
                return ks::i18n::sourceText(QStringLiteral("第 2 步已打开。"));
            });
        });

    stepHideIdentity_ = addStep(kLayout, 3,
        ks::i18n::sourceText(QStringLiteral("对虚拟机软件隐藏 KSwordVM 的身份")),
        ks::i18n::sourceText(QStringLiteral("这一步不能省。VMware 启动时会先检查 CPU 上有没有别的虚拟化软件，一旦发现就直接弹「与 Hyper-V 不兼容」并退出，它连能力都不会去问，所以前两步做得再对也救不回来。打开之后虚拟机软件就看不到 KSwordVM 了。")),
        ks::i18n::sourceText(QStringLiteral("打开")),
        [this]() {
            runInBackground([this]() -> QString {
                markConfigurationChanged();
                ksword::kvm::setHypervisorHidden(true);
                return ks::i18n::sourceText(QStringLiteral("第 3 步已打开。"));
            });
        });

    stepStartMonitor_ = addStep(kLayout, 4,
        ks::i18n::sourceText(QStringLiteral("启动 KSwordVM")),
        ks::i18n::sourceText(QStringLiteral("分配资源、做一次自检，然后正式接管 CPU 的虚拟化功能。前三步是设置，只有走完这一步它们才真正生效：设置是在启动的那一刻被读取的，启动之后再改开关不会影响已经跑起来的这一份。")),
        ks::i18n::sourceText(QStringLiteral("启动")),
        [this]() {
            runInBackground([this]() -> QString {
                startMonitor();
                return QString();
            });
        });

    stepRestartVmware_ = addStep(kLayout, 5,
        ks::i18n::sourceText(QStringLiteral("让 VMware 重新识别 CPU 能力")),
        ks::i18n::sourceText(QStringLiteral("VMware 的驱动只在它自己启动的时候问一次 CPU 支持哪些虚拟化能力，问完就记住了。前面几步改完之后它手里还是旧答案，所以必须让它重启一次重新问。这一步动的是 VMware 自己的服务，不是 KSwordVM；重启前请先关掉所有正在运行的虚拟机。")),
        ks::i18n::sourceText(QStringLiteral("重启 VMware 驱动服务")),
        [this]() {
            runInBackground([this]() -> QString {
                restartVmwareDriver();
                return QString();
            });
        });

    auto* const kLine = new QFrame(kHost);
    kLine->setFrameShape(QFrame::HLine);
    kLine->setFrameShadow(QFrame::Sunken);
    kLayout->addWidget(kLine);

    verdict_ = new QLabel(kHost);
    verdict_->setWordWrap(true);
    kLayout->addWidget(verdict_);

    lastMessage_ = new QLabel(kHost);
    lastMessage_->setWordWrap(true);
    lastMessage_->setStyleSheet(
        QStringLiteral("color:%1;").arg(ksword_theme::textSecondaryHex()));
    kLayout->addWidget(lastMessage_);

    kLayout->addStretch(1);
    kScroll->setWidget(kHost);
    kOuter->addWidget(kScroll);
}

KvmGuestVmPanel::StepRow KvmGuestVmPanel::addStep(
    QVBoxLayout* parentLayout,
    const int number,
    const QString& title,
    const QString& explanation,
    const QString& actionText,
    const std::function<void()>& onClicked)
{
    StepRow row;

    auto* const kBox = new QFrame(parentLayout->parentWidget());
    kBox->setFrameShape(QFrame::StyledPanel);
    auto* const kBoxLayout = new QVBoxLayout(kBox);
    kBoxLayout->setContentsMargins(12, 10, 12, 10);
    kBoxLayout->setSpacing(6);

    auto* const kHeaderRow = new QHBoxLayout();
    auto* const kTitleLabel = new QLabel(
        QStringLiteral("%1. %2").arg(number).arg(title), kBox);
    kTitleLabel->setStyleSheet(QStringLiteral("font-weight:600;"));
    kTitleLabel->setWordWrap(true);
    kHeaderRow->addWidget(kTitleLabel, 1);

    row.status = new QLabel(kBox);
    kHeaderRow->addWidget(row.status);

    row.action = new QPushButton(actionText, kBox);
    connect(row.action, &QPushButton::clicked, this, onClicked);
    kHeaderRow->addWidget(row.action);
    kBoxLayout->addLayout(kHeaderRow);

    auto* const kWhy = new QLabel(explanation, kBox);
    kWhy->setWordWrap(true);
    kWhy->setStyleSheet(
        QStringLiteral("color:%1;").arg(ksword_theme::textSecondaryHex()));
    kBoxLayout->addWidget(kWhy);

    parentLayout->addWidget(kBox);
    return row;
}

void KvmGuestVmPanel::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    refreshAsync();
}

void KvmGuestVmPanel::setBusy(const bool busy)
{
    busy_ = busy;
    // The "Refresh" action does not depend on the backend: reading the status once is valid on any machine, and it is precisely
    // the only button still clickable for users on AMD. Disabling it along with others would leave this page with no exit.
    if (refresh_ != nullptr) { refresh_->setEnabled(!busy); }
    const bool kActionsEnabled = !busy && backendSupported_;
    if (doAll_ != nullptr) { doAll_->setEnabled(kActionsEnabled); }
    for (StepRow* const kRow : { &stepAllowNested_, &stepHostGuests_,
                                &stepHideIdentity_, &stepStartMonitor_,
                                &stepRestartVmware_ })
    {
        if (kRow->action != nullptr) { kRow->action->setEnabled(kActionsEnabled); }
    }
    if (onBusyChanged) { onBusyChanged(busy); }
}

void KvmGuestVmPanel::runInBackground(const std::function<QString()>& work)
{
    if (busy_) { return; }
    setBusy(true);
    QPointer<KvmGuestVmPanel> safeThis(this);
    std::thread([safeThis, work]() {
        QString message;
        if (work) { message = work(); }
        const ksword::kvm::KvmState kState = ksword::kvm::queryState();
        if (safeThis == nullptr) { return; }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, kState, message]() {
                if (safeThis == nullptr) { return; }
                safeThis->setBusy(false);
                if (!message.isEmpty() && safeThis->lastMessage_ != nullptr)
                {
                    safeThis->lastMessage_->setText(message);
                }
                safeThis->applyState(kState);
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmGuestVmPanel::refreshAsync()
{
    if (busy_ || queryInFlight_) { return; }
    queryInFlight_ = true;
    QPointer<KvmGuestVmPanel> safeThis(this);
    std::thread([safeThis]() {
        const ksword::kvm::KvmState kState = ksword::kvm::queryState();
        if (safeThis == nullptr) { return; }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, kState]() {
                if (safeThis == nullptr) { return; }
                safeThis->queryInFlight_ = false;
                safeThis->applyState(kState);
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmGuestVmPanel::markConfigurationChanged()
{
    vmwareDriverRestarted_ = false;
}

void KvmGuestVmPanel::enableAllSwitches()
{
    markConfigurationChanged();
    ksword::kvm::setNestedAllowed(true);
    if (!ksword::kvm::isLocalEptEnabled() && ksword::kvm::isWriteAccessEnabled())
    {
        ksword::kvm::setNestedDispatchEnabled(true);
    }
    ksword::kvm::setHypervisorHidden(true);
}

void KvmGuestVmPanel::startMonitor()
{
    const ksword::kvm::KvmState kBefore = ksword::kvm::queryState();
    if (kBefore.residentActive) { return; }
    // Restarting KSwordVM is equivalent to reloading the capability filter; the answer
    // obtained from vmx86 in the previous session is now invalid, so Step 5 must be redone.
    markConfigurationChanged();
    const ksword::kvm::KvmCommandResult kPrepared = ksword::kvm::ensurePrepared();
    if (!kPrepared.ok) { return; }
    const ksword::kvm::KvmState kPrepState = ksword::kvm::queryState();
    (void)ksword::kvm::startResident(kPrepState.generation);
}

void KvmGuestVmPanel::restartVmwareDriver()
{
    ks::service::ServiceStatus status{};
    if (!ks::service::queryServiceStatus(kVmwareDriverService, &status))
    {
        // If VMware is not installed, this service does not exist; this is not an error.
        return;
    }
    (void)ks::service::stopServiceByName(
        kVmwareDriverService, 15000U, kServiceStopped);
    if (ks::service::startServiceByName(
            kVmwareDriverService, 15000U, kServiceRunning))
    {
        vmwareDriverRestarted_ = true;
    }
}

void KvmGuestVmPanel::applyState(const ksword::kvm::KvmState& state)
{
    // Evaluate the backend criterion first: the following five steps all rely on Intel nested VMX dispatch.
    // setBusy does not change the busy flag; it simply refreshes the button using the new m_backendSupported value.
    backendSupported_ = state.backend == KSWORD_ARK_HVM_BACKEND_VMX;
    setBusy(busy_);
    if (!backendSupported_)
    {
        // Mark all five steps as "Not Applicable" instead of "To Do": "To Do" implies a click will advance
        // the process, but here clicking does nothing—this is the most deceptive display on this page.
        const QString kReason = state.backend == KSWORD_ARK_HVM_BACKEND_SVM
            ? ks::i18n::sourceText(QStringLiteral("这一页只对 Intel 嵌套 VMX 成立。当前是 AMD SVM/NPT 后端：它不提供把第三方虚拟机跑在 KSwordVM 之下的能力，上面五步在这里按下去不会有任何效果。"))
            : ks::i18n::sourceText(QStringLiteral("还读不到虚拟化后端。请先用标题栏的 R0 按钮启动 KswordARK 驱动服务，再回到这一页。"));
        for (StepRow* const kRow : { &stepAllowNested_, &stepHostGuests_,
                                    &stepHideIdentity_, &stepStartMonitor_,
                                    &stepRestartVmware_ })
        {
            paintStatus(kRow->status,
                        ks::i18n::sourceText(QStringLiteral("不适用")), false);
        }
        if (verdict_ != nullptr)
        {
            verdict_->setText(kReason);
            verdict_->setStyleSheet(QStringLiteral("font-weight:600;"));
        }
        return;
    }
    const bool kAllowNested = ksword::kvm::isNestedAllowed();
    const bool kHostGuests = ksword::kvm::isNestedDispatchEnabled();
    const bool kHideIdentity = ksword::kvm::isHypervisorHidden();
    const bool kRunning = state.residentActive;

    paintStatus(stepAllowNested_.status,
                kAllowNested ? doneMark() : todoMark(), kAllowNested);
    paintStatus(stepHostGuests_.status,
                kHostGuests ? doneMark() : todoMark(), kHostGuests);
    paintStatus(stepHideIdentity_.status,
                kHideIdentity ? doneMark() : todoMark(), kHideIdentity);
    paintStatus(stepStartMonitor_.status,
                kRunning
                    ? doneMark()
                    : ks::i18n::sourceText(QStringLiteral("没在运行")),
                kRunning);

    ks::service::ServiceStatus vmwareStatus{};
    const bool kVmwareInstalled =
        ks::service::queryServiceStatus(kVmwareDriverService, &vmwareStatus);
    QString vmwareText;
    bool vmwareDone = false;
    if (!kVmwareInstalled)
    {
        vmwareText = ks::i18n::sourceText(QStringLiteral("没装 VMware"));
        vmwareDone = true; // Skip this step if not installed.
    }
    else if (vmwareDriverRestarted_)
    {
        vmwareText = doneMark();
        vmwareDone = true;
    }
    else
    {
        vmwareText = ks::i18n::sourceText(QStringLiteral("还需重启一次"));
    }
    paintStatus(stepRestartVmware_.status, vmwareText, vmwareDone);

    // Provide a one-sentence conclusion in plain language, and only state 'ready' when all conditions are truly met.
    QString verdict;
    if (kAllowNested && kHostGuests && kHideIdentity && kRunning && vmwareDone)
    {
        verdict = ks::i18n::sourceText(QStringLiteral("现在可以打开 VMware、VirtualBox 或 WSL2 了。如果仍然打不开，请先把已经开着的虚拟机全部关掉，再重启一次 VMware 的驱动服务。"));
    }
    else if (!kRunning)
    {
        verdict = ks::i18n::sourceText(QStringLiteral("还不行：KSwordVM 没在运行。请先把上面的设置打开，再执行第 4 步。"));
    }
    else if (!kHideIdentity)
    {
        verdict = ks::i18n::sourceText(QStringLiteral("还不行：没有隐藏身份，VMware 会直接报「与 Hyper-V 不兼容」并退出。这一项要在启动 KSwordVM 之前设好，改完需要重新启动 KSwordVM 才生效。"));
    }
    else if (!kHostGuests)
    {
        verdict = ks::i18n::sourceText(QStringLiteral("还不行：没有允许别的虚拟机跑在 KSwordVM 下面，VMware 一开虚拟机就会失败。"));
    }
    else if (!vmwareDone)
    {
        verdict = ks::i18n::sourceText(QStringLiteral("就差最后一步：VMware 的驱动手里还是旧的 CPU 能力答案，重启一次它的服务即可。"));
    }
    else
    {
        verdict = ks::i18n::sourceText(QStringLiteral("还有步骤没完成，请看上面的清单。"));
    }
    if (verdict_ != nullptr)
    {
        verdict_->setText(verdict);
        verdict_->setStyleSheet(QStringLiteral("font-weight:600;"));
    }
}
