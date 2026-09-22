// mainWindow.Kvm.cpp
//
// The title bar permission button overrides all behavior of the KVM (KSwordVM, R-1 layer) button.
//
// Rationale for splitting consistent with KernelHvmTab sharding: mainWindow.cpp already handles multiple
// main threads including windows, docks, permissions, and driver services. KVM's state machine, menus,
// and background queries form a self-contained unit; mixing them would make both sides harder to read.
//
// Three hard constraints:
// - Status queries and all control commands are blocking IOCTLs; always execute on a background thread, with the UI thread handling only display.
// - Entering VMX non-root mode alters the CPU state of the entire machine, constituting a high-risk operation that must go through a unified confirmation step.
// - Write access is disabled by default. When disabled, KVM operates in observation-only mode; no R-1 write entry points appear in the menu.

#include "MainWindow.h"
#include "kernel_dock/KernelDock.h"
#include "kvm_dock/KvmDock.h"

#include "framework/DestructiveActionConfirmation.h"
#include "internationalization/LanguageManager.h"
#include "ui/KvmControl.h"
#include "ui/KvmCrPolicyDialog.h"
#include "ui/KvmEventDialog.h"
#include "ui/KvmMemoryDialog.h"
#include "ui/KvmMsrPolicyDialog.h"
#include "ui/KvmDomainDialog.h"
#include "ui/KvmHookWizard.h"
#include "ui/KvmProcessDialog.h"
#include "ui/KvmViewDialog.h"
#include "ui/KvmWriteAccessGate.h"
#include "Theme.h"

#include <QAction>
#include <QDialog>
#include <QMenu>
#include <QMessageBox>
#include <QPointer>
#include <QPushButton>

#include <thread>
#include <utility>

namespace
{
    /*
     * Display state of the KVM button: **one** ordered state, not two independent booleans.
     *
     * Originally, the background color encoded 'active status' and the border/text color encoded 'capability status'. Since these two channels
     * were independently sampled, it was possible to render contradictory combinations: during a fault, the background might say 'running'
     * while the border says 'unavailable'. Worse, NotPrepared was treated as 'available', causing a driver that wasn't ready to appear capable,
     * while the hint text simultaneously claimed it wasn't ready. The observer was forced to choose one of the two conflicting signals.
     *
     * After changing to a single state, 'what the button looks like' and 'whether it can be clicked now and what
     * happens when clicked' are just two ways of saying the same thing, so they cannot contradict each other.
     */
    enum class KvmButtonState
    {
        kUnavailable,   // Hardware gate failed, driver not started, or outer hypervisor is occupying.
        kFaulted,       // Faulted or pending rollback; must be reset before proceeding.
        kNotPrepared,   // Capabilities are ready but resources are not prepared; clicking will prepare them first before becoming resident.
        kReady,         // Ready but not resident; click to start residency.
        kResident       // Currently resident; click to stop.
    };

    /*
     * The priority is deliberate: first answer whether it is usable, then identify its current step.
     *
     * Fault state is prioritized over resident state because, even if processors remain resident during a fault, the
     * user's first action is reset, not stop. Depicting it as a normal 'running' state would obscure this critical step.
     */
    KvmButtonState resolveKvmButtonState(
        const ksword::kvm::KvmAvailability availability,
        const bool residentActive,
        const bool faulted)
    {
        if (availability != ksword::kvm::KvmAvailability::kAvailable &&
            availability != ksword::kvm::KvmAvailability::kNotPrepared &&
            availability != ksword::kvm::KvmAvailability::kFaulted)
        {
            return KvmButtonState::kUnavailable;
        }
        if (faulted || availability == ksword::kvm::KvmAvailability::kFaulted)
        {
            return KvmButtonState::kFaulted;
        }
        if (residentActive)
        {
            return KvmButtonState::kResident;
        }
        if (availability == ksword::kvm::KvmAvailability::kNotPrepared)
        {
            return KvmButtonState::kNotPrepared;
        }
        return KvmButtonState::kReady;
    }

    QString buildKvmButtonStyle(const KvmButtonState state)
    {
        const bool kResidentActive = state == KvmButtonState::kResident;
        // Only Ready and Resident mean "truly operational as expected at this moment".
        // NotPrepared is rendered as weakly available: clickable, but requires a preparatory step upon activation.
        const bool kAvailable = state == KvmButtonState::kReady ||
            state == KvmButtonState::kResident ||
            state == KvmButtonState::kNotPrepared;
        const QString kBackgroundColor = kResidentActive
            ? ksword_theme::kPrimaryBlueHex
            : ksword_theme::surfaceHex();
        /*
         * Faulted state uses a distinct color, separate from 'unavailable'.
         *
         * The two scenarios require completely different human actions: a fault is resolved by a single reset click to
         * continue, whereas unavailability means the machine or configuration is fundamentally unusable. Rendering both as the
         * same gray causes a recoverable fault to be misread as 'switch machines,' which is the most costly misinterpretation.
         */
        const bool kFaulted = state == KvmButtonState::kFaulted;
        // Non-active accent text must be calibrated against the Surface first; otherwise, high-brightness accent colors will blur onto the background.
        const QString kTextColor = kResidentActive
            ? ksword_theme::onAccentHex()
            : (kFaulted
                ? ksword_theme::warningHex()
                : (kAvailable
                    ? ksword_theme::accentButtonTextHex()
                    : ksword_theme::textSecondaryHex()));
        const QString kBorderColor = kFaulted
            ? ksword_theme::warningHex()
            : (kAvailable
                ? ksword_theme::kPrimaryBlueBorderHex
                : ksword_theme::borderHex());
        const QString kHoverColor = kResidentActive
            ? ksword_theme::primaryBlueSolidHoverHex()
            : ksword_theme::primaryBlueSubtleHex();
        const QString kHoverTextColor = kResidentActive
            ? ksword_theme::onAccentHex()
            : ksword_theme::textPrimaryColorHex();
        return QStringLiteral(
            "QPushButton {"
            "  background:%1;"
            "  color:%2;"
            "  border:1px solid %3;"
            "  border-radius:3px;"
            "  padding:2px 8px;"
            "  font-weight:600;"
            "}"
            "QPushButton:hover {"
            "  background:%4;"
            "  color:%5;"
            "  border:1px solid %4;"
            "}"
            "QPushButton:pressed {"
            "  background:%6;"
            "  color:%5;"
            "}"
            "QPushButton:disabled {"
            "  color:%7;"
            "}")
            .arg(kBackgroundColor)
            .arg(kTextColor)
            .arg(kBorderColor)
            .arg(kHoverColor)
            .arg(kHoverTextColor)
            .arg(ksword_theme::kPrimaryBluePressedHex)
            .arg(ksword_theme::textSecondaryHex());
    }
}

KvmDock* MainWindow::createKvmDockContent()
{
    auto* const kDockContent = new KvmDock(this);
    kDockContent->setActionHandler([this](const KvmDock::Action action) {
        handleKvmDockAction(action);
    });
    kDockContent->setCommandOperationHandler([this](bool running) {
        kvmOperationRunning_ = running;
        applyKvmButtonState();
        if (!running) { refreshKvmStatusAsync(); }
    });
    return kDockContent;
}

void MainWindow::handleKvmDockAction(const KvmDock::Action action)
{
    // This layer performs only dispatch. Every item falls to the same implementation used for the right-click menu, including the
    // high-risk confirmDestructiveAction confirmations; therefore, the two entry points cannot produce inconsistent behaviors.
    const auto kShowKvmDialog = [](QDialog* const dialog) {
        // Non-modal without parent: The R-1 panel must be usable side-by-side with the main interface, consistent with the right-click menu.
        dialog->setAttribute(Qt::WA_DeleteOnClose);
        dialog->show();
    };

    switch (action)
    {
    case KvmDock::Action::kToggleResident:
        handleKvmStatusButtonClicked();
        return;
    case KvmDock::Action::kSoak:
        runKvmSoak(5000);
        return;
    case KvmDock::Action::kPrepareResources:
        runKvmPrepare();
        return;
    case KvmDock::Action::kReleaseResources:
        runKvmRelease();
        return;
    case KvmDock::Action::kResetFault:
        runKvmFaultReset();
        return;
    case KvmDock::Action::kOpenHookWizard:
        // The wizard manages its own non-modal lifecycle and WA_DeleteOnClose (the contract of openWizard), so this
        // case bypasses showKvmDialog; invoking it would redundantly set attributes and add an extra show layer.
        ks::ui::KvmHookWizard::openWizard(this);
        return;
    case KvmDock::Action::kOpenViewDialog:
        kShowKvmDialog(new KvmViewDialog(this));
        return;
    case KvmDock::Action::kOpenDomainDialog:
        kShowKvmDialog(new KvmDomainDialog(this));
        return;
    case KvmDock::Action::kOpenMsrPolicyDialog:
        kShowKvmDialog(new KvmMsrPolicyDialog(this));
        return;
    case KvmDock::Action::kOpenCrPolicyDialog:
        kShowKvmDialog(new KvmCrPolicyDialog(this));
        return;
    case KvmDock::Action::kOpenMemoryDialog:
        kShowKvmDialog(new KvmMemoryDialog(this));
        return;
    case KvmDock::Action::kOpenEventDialog:
        kShowKvmDialog(new KvmEventDialog(this));
        return;
    case KvmDock::Action::kOpenProcessDialog:
        kShowKvmDialog(new KvmProcessDialog(this));
        return;
    }
}

void MainWindow::applyKvmButtonState()
{
    // KVM page status polling cannot detect that a command is running: during the command, the driver-side status lock is
    // exclusively held, so queries are queued behind it. Only the side initiating the command can push this state forward.
    if (kvmWidget_ != nullptr)
    {
        kvmWidget_->setOperationRunning(kvmOperationRunning_);
    }
    if (kvmStatusButton_ == nullptr)
    {
        return;
    }
    kvmStatusButton_->setStyleSheet(
        buildKvmButtonStyle(resolveKvmButtonState(
            kvmAvailability_,
            kvmResidentActive_,
            kvmFaulted_)));
    // Disable buttons during operations: both resident-mode switching and the hold self-test exclusively acquire the driver's state lock.
    kvmStatusButton_->setEnabled(!kvmOperationRunning_);
    /*
     * Hint text follows the display name.
     *
     * Originally, "KVM" was hardcoded. After changing the display name in settings to HVM or R-1, the button text updated
     * while the tooltip still referred to KVM, causing the two text fields of the same control to display conflicting names.
     */
    const QString kHvmName = ks::settings::hvmDisplayNameLabel(
        currentAppearanceSettings_.hvmDisplayName);
    if (kvmOperationRunning_)
    {
        kvmStatusButton_->setToolTip(
            ks::i18n::sourceText(QStringLiteral("%1 操作进行中...")).arg(kHvmName));
        return;
    }
    kvmStatusButton_->setToolTip(kvmTooltip_.isEmpty()
        ? ks::i18n::sourceText(QStringLiteral("%1：KSwordVM 硬件虚拟化（R-1）常驻状态。左键启动或停止常驻，右键打开 R-1 能力菜单。")).arg(kHvmName)
        : kvmTooltip_);
}

void MainWindow::refreshKvmStatusAsync()
{
    // Merge concurrent queries: permission button refresh is periodic; piling up requests only slows down the driver.
    if (kvmQueryInFlight_ || kvmOperationRunning_)
    {
        return;
    }
    kvmQueryInFlight_ = true;
    QPointer<MainWindow> safeThis(this);
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
                safeThis->kvmQueryInFlight_ = false;
                safeThis->kvmResidentActive_ = kState.residentActive;
                /*
                 * Preserve the full availability value instead of compressing it into a boolean.
                 *
                 * Flattening is the source of contradictions: NotPrepared is merged into 'Available', causing
                 * unprepared drivers to appear capable; Faulted is merged into 'Unavailable', making a resettable fault
                 * indistinguishable from 'machine unsupported'. Button states are now calculated from this raw value.
                 */
                safeThis->kvmAvailability_ = kState.availability;
                safeThis->kvmAvailable_ =
                    kState.availability == ksword::kvm::KvmAvailability::kAvailable ||
                    kState.availability == ksword::kvm::KvmAvailability::kNotPrepared;
                safeThis->kvmFaulted_ = kState.faulted;
                safeThis->kvmGeneration_ = kState.generation;
                safeThis->kvmBackend_ = kState.backend;
                safeThis->kvmTooltip_ = kState.detail;
                safeThis->applyKvmButtonState();
            },
            Qt::QueuedConnection);
    }).detach();
}

void MainWindow::handleKvmStatusButtonClicked()
{
    if (kvmOperationRunning_)
    {
        return;
    }
    if (!r0DriverServiceRunning_)
    {
        QMessageBox::information(
            this,
            QStringLiteral("KVM"),
            ks::i18n::sourceText(QStringLiteral(
                "KswordARK 驱动未运行。请先点击 R0 启动驱动服务。")));
        return;
    }
    if (kvmFaulted_)
    {
        QMessageBox::warning(
            this,
            QStringLiteral("KVM"),
            ks::i18n::sourceText(QStringLiteral(
                "KVM 处于故障或待回滚状态。请先在右键菜单中执行“重置故障状态”。")));
        return;
    }
    if (!kvmResidentActive_ && !kvmAvailable_)
    {
        // The background snapshot puts the specific reason for unavailability in the tooltip; display it unchanged instead of substituting a generic message.
        QMessageBox::information(
            this,
            QStringLiteral("KVM"),
            kvmTooltip_.isEmpty()
                ? ks::i18n::sourceText(QStringLiteral("当前硬件或系统状态不支持 KVM 常驻。"))
                : kvmTooltip_);
        return;
    }

    const bool kStopping = kvmResidentActive_;
    if (!kStopping)
    {
        // Entering VMX non-root mode changes the execution mode of all logical processors; require a unified high-risk confirmation.
        const bool kConfirmed = ks::ui::confirmDestructiveAction(
            this,
            QStringLiteral("KvmStartResident"),
            ks::i18n::sourceText(QStringLiteral("启动 KSwordVM 常驻")),
            ks::i18n::sourceText(QStringLiteral("本机全部逻辑处理器")),
            ks::i18n::sourceText(QStringLiteral("所有逻辑处理器将进入 VMX non-root 运行。与 Hyper-V/VBS 冲突、驱动异常或电源转换失败都可能导致系统不稳定或蓝屏。首次使用建议先执行“常驻保持自检”。")));
        if (!kConfirmed)
        {
            return;
        }
    }

    kvmOperationRunning_ = true;
    applyKvmButtonState();
    QPointer<MainWindow> safeThis(this);
    const unsigned long kGeneration = kvmGeneration_;
    std::thread([safeThis, kStopping, kGeneration]() {
        const ksword::kvm::KvmCommandResult kResult = kStopping
            ? ksword::kvm::stopResident(kGeneration)
            : ksword::kvm::startResident(kGeneration);
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, kResult]() {
                if (safeThis == nullptr)
                {
                    return;
                }
                safeThis->kvmOperationRunning_ = false;
                safeThis->applyKvmButtonState();
                if (!kResult.ok)
                {
                    QMessageBox::warning(
                        safeThis,
                        QStringLiteral("KVM"),
                        kResult.message);
                }
                safeThis->refreshKvmStatusAsync();
            },
            Qt::QueuedConnection);
    }).detach();
}

void MainWindow::runKvmSoak(const unsigned long milliseconds)
{
    if (kvmOperationRunning_)
    {
        return;
    }
    // The self-test also puts every processor into non-root mode and carries the same risks as starting the resident hypervisor directly.
    const bool kConfirmed = ks::ui::confirmDestructiveAction(
        this,
        QStringLiteral("KvmSoak"),
        ks::i18n::sourceText(QStringLiteral("KSwordVM 常驻保持自检")),
        ks::i18n::sourceText(QStringLiteral("本机全部逻辑处理器")),
        ks::i18n::sourceText(QStringLiteral("全部逻辑处理器会进入 VMX non-root 并保持数秒后自动退出。期间任何未被处理的 VM-exit 都会被记录为掉核，与 Hyper-V/VBS 冲突时可能导致系统不稳定。")));
    if (!kConfirmed)
    {
        return;
    }

    kvmOperationRunning_ = true;
    applyKvmButtonState();
    QPointer<MainWindow> safeThis(this);
    const unsigned long kGeneration = kvmGeneration_;
    std::thread([safeThis, kGeneration, milliseconds]() {
        const ksword::kvm::KvmCommandResult kResult =
            ksword::kvm::runSoak(kGeneration, milliseconds);
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, kResult]() {
                if (safeThis == nullptr)
                {
                    return;
                }
                safeThis->kvmOperationRunning_ = false;
                safeThis->applyKvmButtonState();
                // Display the self-test result whether it passed or failed; it is the only direct evidence of resident-mode availability.
                if (kResult.ok)
                {
                    QMessageBox::information(
                        safeThis,
                        QStringLiteral("KVM"),
                        kResult.message);
                }
                else
                {
                    QMessageBox::warning(
                        safeThis,
                        QStringLiteral("KVM"),
                        kResult.message);
                }
                safeThis->refreshKvmStatusAsync();
            },
            Qt::QueuedConnection);
    }).detach();
}

void MainWindow::runKvmPrepare()
{
    if (kvmOperationRunning_)
    {
        return;
    }
    kvmOperationRunning_ = true;
    applyKvmButtonState();
    QPointer<MainWindow> safeThis(this);
    std::thread([safeThis]() {
        // ensurePrepared performs PREPARE + SELF_TEST as needed; returns success immediately if already prepared.
        // It **does not** become resident—that is precisely the reason this entry point exists.
        const ksword::kvm::KvmCommandResult kResult =
            ksword::kvm::ensurePrepared();
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, kResult]() {
                if (safeThis == nullptr)
                {
                    return;
                }
                safeThis->kvmOperationRunning_ = false;
                safeThis->applyKvmButtonState();
                if (!kResult.ok)
                {
                    QMessageBox::warning(
                        safeThis,
                        QStringLiteral("KVM"),
                        kResult.message);
                }
                else
                {
                    QMessageBox::information(
                        safeThis,
                        QStringLiteral("KVM"),
                        ks::i18n::sourceText(QStringLiteral("资源已准备，尚未进入常驻。现在是安装分离视图 / MSR 策略 / CR 策略 / 执行域的窗口期 —— 启动常驻之后这几张表就不可变了。")));
                }
                safeThis->refreshKvmStatusAsync();
            },
            Qt::QueuedConnection);
    }).detach();
}

void MainWindow::runKvmRelease()
{
    if (kvmOperationRunning_)
    {
        return;
    }
    // Releasing resources discards installed views, policies, and domains, so a high-risk confirmation is required.
    const bool kConfirmed = ks::ui::confirmDestructiveAction(
        this,
        QStringLiteral("KvmReleaseResources"),
        ks::i18n::sourceText(QStringLiteral("释放 KVM 资源")),
        ks::i18n::sourceText(QStringLiteral("本机全部逻辑处理器")),
        ks::i18n::sourceText(QStringLiteral("将释放全部每处理器资源与 EPT 层次。已安装的分离视图、MSR 策略、CR 策略与执行域会一并消失，叶项与权限恢复原状。改过后端选择或每处理器私有 EPT 时需要这一步：那些选择只在准备资源时被消费。")));
    if (!kConfirmed)
    {
        return;
    }
    kvmOperationRunning_ = true;
    applyKvmButtonState();
    QPointer<MainWindow> safeThis(this);
    const unsigned long kGeneration = kvmGeneration_;
    std::thread([safeThis, kGeneration]() {
        const ksword::kvm::KvmCommandResult kResult =
            ksword::kvm::releaseResources(kGeneration);
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, kResult]() {
                if (safeThis == nullptr)
                {
                    return;
                }
                safeThis->kvmOperationRunning_ = false;
                safeThis->applyKvmButtonState();
                if (!kResult.ok)
                {
                    QMessageBox::warning(
                        safeThis,
                        QStringLiteral("KVM"),
                        kResult.message);
                }
                safeThis->refreshKvmStatusAsync();
            },
            Qt::QueuedConnection);
    }).detach();
}

void MainWindow::runKvmFaultReset()
{
    if (kvmOperationRunning_)
    {
        return;
    }
    kvmOperationRunning_ = true;
    applyKvmButtonState();
    QPointer<MainWindow> safeThis(this);
    const unsigned long kGeneration = kvmGeneration_;
    std::thread([safeThis, kGeneration]() {
        const ksword::kvm::KvmCommandResult kResult =
            ksword::kvm::resetFault(kGeneration);
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, kResult]() {
                if (safeThis == nullptr)
                {
                    return;
                }
                safeThis->kvmOperationRunning_ = false;
                safeThis->applyKvmButtonState();
                if (!kResult.ok)
                {
                    QMessageBox::warning(
                        safeThis,
                        QStringLiteral("KVM"),
                        kResult.message);
                }
                safeThis->refreshKvmStatusAsync();
            },
            Qt::QueuedConnection);
    }).detach();
}

void MainWindow::showKvmMenu(const QPoint& globalPosition)
{
    QMenu menu(this);

    // The resident toggle matches the left-click behavior; added to the menu solely to make the capability visibly centralized.
    QAction* const kToggleAction = menu.addAction(kvmResidentActive_
        ? ks::i18n::sourceText(QStringLiteral("停止常驻"))
        : ks::i18n::sourceText(QStringLiteral("启动常驻")));
    kToggleAction->setEnabled(!kvmOperationRunning_ &&
        (kvmResidentActive_ || kvmAvailable_));
    connect(kToggleAction, &QAction::triggered, this, [this]() {
        handleKvmStatusButtonClicked();
    });

    // The hold self-test is the only way to prove that resident operation can survive; a single entry/exit only verifies the transition itself.
    QAction* const kSoakAction = menu.addAction(
        ks::i18n::sourceText(QStringLiteral("常驻保持自检（5 秒）")));
    kSoakAction->setEnabled(!kvmOperationRunning_ &&
        !kvmResidentActive_ &&
        kvmAvailable_);
    connect(kSoakAction, &QAction::triggered, this, [this]() {
        runKvmSoak(5000);
    });

    menu.addSeparator();

    // "Prepare Resources" and "Release Resources" must be here; otherwise, this menu contains an unavoidable dead path.
    //
    // The View, MSR, CR, and Domain panels all require resources to be prepared. This menu originally
    // only supported 'Start Resident', which prepares resources and immediately enters the resident
    // state in the same call, causing all four panels to transition from 'Not Prepared' to 'Unmodifiable
    // During Resident'. The only available window in between cannot be triggered here; users must find
    // it in a different page of another Dock, with no cross-references between the two sides.
    //
    // 「Release Resources」is the only way to activate backend switches: the backend selects
    // during PREPARE, and ensurePrepared does not resend PREPARE once resources are ready.
    QAction* const kPrepareAction = menu.addAction(
        ks::i18n::sourceText(QStringLiteral("准备资源（不进入常驻）")));
    kPrepareAction->setEnabled(!kvmOperationRunning_ &&
        !kvmResidentActive_ &&
        kvmAvailable_);
    // A sourceText must be a single non-wrapped literal: adjacent string concatenation causes the i18n extractor to
    // treat them as multiple independent entries, resulting in orphaned fragments in the language pack that never match.
    kPrepareAction->setToolTip(ks::i18n::sourceText(QStringLiteral("分配每处理器资源并建立 EPT，但不进入常驻。分离视图、MSR 策略、CR 策略与执行域都必须在这一步之后、启动常驻之前安装 —— 常驻期间这几张表都是不可变的。")));
    connect(kPrepareAction, &QAction::triggered, this, [this]() {
        runKvmPrepare();
    });

    QAction* const kReleaseAction = menu.addAction(
        ks::i18n::sourceText(QStringLiteral("释放资源")));
    kReleaseAction->setEnabled(!kvmOperationRunning_ &&
        !kvmResidentActive_ &&
        kvmAvailable_);
    kReleaseAction->setToolTip(ks::i18n::sourceText(QStringLiteral("释放全部可逆资源，回到未准备状态。改过分离视图后端或每处理器私有 EPT 之后必须走这一步 —— 那两个选择只在准备资源时被消费，已准备的运行时改开关不会生效。")));
    connect(kReleaseAction, &QAction::triggered, this, [this]() {
        runKvmRelease();
    });

    menu.addSeparator();

    // Nested mode: The only way to run when an outer hypervisor exists (inside a VM, or bare metal with VBS/HVCI enabled).
    // It does not modify any system state, so it bypasses high-risk confirmation, but the trade-offs must be clearly stated.
    QAction* const kNestedAction = menu.addAction(
        ks::i18n::sourceText(QStringLiteral("允许嵌套运行（作为 L1）")));
    kNestedAction->setCheckable(true);
    kNestedAction->setChecked(ksword::kvm::isNestedAllowed());
    kNestedAction->setToolTip(ks::i18n::sourceText(QStringLiteral("在虚拟机内或开着 VBS/HVCI 的机器上，KSwordVM 只能作为 L1 运行：每条 VMX 操作都由外层 hypervisor 模拟，性能明显下降，可用能力也只剩外层愿意暴露的那部分。")));
    connect(kNestedAction, &QAction::triggered, this, [this](const bool checked) {
        ksword::kvm::setNestedAllowed(checked);
        applyKvmButtonState();
        refreshKvmStatusAsync();
    });

    /*
     * Nested dispatch: opposite in direction to the item above, so place it immediately next to it.
     *
     * The former says 'allow us to run underneath others' (we are the guest); this one says 'allow others to run underneath
     * us' (we are the host). Both are called 'nesting', but enabling them activates completely different features.
     *
     * Before this option existed, nested dispatch was only accessible via the Nested page in KernelDock, which was hard-bound
     * to 'which feature page is currently active'—meaning there was no toggle: visiting that page always enabled it, and not
     * visiting it always disabled it. A capability already end-to-end validated was absent from the main interface.
     */
    QAction* const kNestedDispatchAction = menu.addAction(
        ks::i18n::sourceText(QStringLiteral("允许来宾嵌套（我们作为宿主）")));
    kNestedDispatchAction->setCheckable(true);
    kNestedDispatchAction->setChecked(ksword::kvm::isNestedDispatchEnabled());
    kNestedDispatchAction->setToolTip(ks::i18n::sourceText(QStringLiteral("与上一项方向相反：上一项是让我们跑在别人底下，这一项是让别人跑在我们底下。打开后，来宾里的 ring 0 代码可以真的 VMXON、维护自己的 vmcs12、把 L2 跑起来；退出先落到我们手上，L1 要 EPT 时由影子层次按需合成。关着时 VMX 指令被注 #UD——对已经在跑的 VMware / VirtualBox / WSL2 来说就是「虚拟机打不开了」。与每处理器私有 EPT 互斥。本开关不持久化。")));
    connect(kNestedDispatchAction, &QAction::triggered, this,
            [this, kNestedDispatchAction](const bool checked) {
        if (!checked)
        {
            ksword::kvm::setNestedDispatchEnabled(false);
            applyKvmButtonState();
            refreshKvmStatusAsync();
            return;
        }
        // Mutual exclusion is a hard rejection by the driver: nesting requires combining the guest's EPT hierarchy with our composite
        // into a single pointer, but a private root makes this composite processor-specific. Simultaneously, the request will be rejected
        // with STATUS_INVALID_PARAMETER, and the response only states 'invalid request' without specifying the offending parameter.
        if (ksword::kvm::isLocalEptEnabled())
        {
            kNestedDispatchAction->setChecked(false);
            QMessageBox::warning(
                this,
                ks::i18n::sourceText(QStringLiteral("嵌套派发与私有 EPT 互斥")),
                ks::i18n::sourceText(QStringLiteral("嵌套要把来宾的 EPT 层次和我们的合成成一个 EPT 指针，而私有 EPT 要给每个处理器各自一份层次，那会让这个合成变成处理器相关的。驱动会拒绝同时请求。请先关掉「每处理器私有 EPT」。")));
            return;
        }
        // Write permission prerequisite: expose a guest-visible capability
        // to modify its own execution environment, similar to VMFUNC.
        if (!ksword::kvm::isWriteAccessEnabled())
        {
            kNestedDispatchAction->setChecked(false);
            QMessageBox::warning(
                this,
                ks::i18n::sourceText(QStringLiteral("嵌套派发需要先开启写权限")),
                ks::i18n::sourceText(QStringLiteral("打开嵌套派发会让来宾获得一整套它原本拿不到的 VMX 能力，属于写权限门管辖的范围。请先打开「允许 R-1 写操作」。")));
            return;
        }
        const bool kConfirmed = ks::ui::confirmDestructiveAction(
            this,
            QStringLiteral("KvmEnableNestedDispatch"),
            ks::i18n::sourceText(QStringLiteral("允许来宾嵌套")),
            ks::i18n::sourceText(QStringLiteral("本机全部 ring 0 代码")),
            ks::i18n::sourceText(QStringLiteral("打开后，这台机器上任何 ring 0 代码都能在我们底下起一台虚拟机，而我们只看得到它产生的退出，看不到它在里面跑什么。影子 EPT 层次按需合成，MSR 与 I/O 位图按 L1 自己的那份合并，每核要额外占用若干页。位图在每次进入 L2 时重算一遍、不缓存，所以来宾越频繁地进出 L2 越贵。")));
        if (!kConfirmed)
        {
            kNestedDispatchAction->setChecked(false);
            return;
        }
        ksword::kvm::setNestedDispatchEnabled(true);
        applyKvmButtonState();
        refreshKvmStatusAsync();
    });

    menu.addSeparator();

    auto* hideHypervisorAction = menu.addAction(ks::i18n::sourceText(QStringLiteral("对来宾用户态隐藏 Hypervisor 身份")));
    hideHypervisorAction->setCheckable(true);
    hideHypervisorAction->setChecked(ksword::kvm::isHypervisorHidden());
    hideHypervisorAction->setEnabled(!kvmResidentActive_ && !kvmOperationRunning_ && ksword::kvm::isNestedDispatchEnabled());
    connect(hideHypervisorAction, &QAction::toggled, this, [](bool enabled) {
        ksword::kvm::setHypervisorHidden(enabled);
    });

    // Private EPT does not expose capabilities; it only ensures safety of existing views/authorizations across multiple cores. Therefore,
    // it bypasses high-risk confirmation—the real danger lies in the views themselves, which are controlled by write permission gates.
    QAction* const kLocalEptAction = menu.addAction(
        ks::i18n::sourceText(QStringLiteral("每处理器私有 EPT（多核可用视图）")));
    kLocalEptAction->setCheckable(true);
    kLocalEptAction->setChecked(ksword::kvm::isLocalEptEnabled());
    kLocalEptAction->setToolTip(ks::i18n::sourceText(QStringLiteral("给每个处理器一份私有 EPT 层次，翻转只落在取到 exit 的那个处理器上。打开后才能在多核机器上安装 EPT 视图；关着时视图仍然只能在单核拓扑安装。与 VMFUNC、嵌套 VMX 互斥，且每核要多花若干页。")));
    connect(kLocalEptAction, &QAction::triggered, this, [this, kLocalEptAction](const bool checked) {
        // Mutual exclusion is not a preference but a hard rejection by the driver: requesting simultaneously with the EPTP
        // switching backend results in an INVALID_REQUEST before any allocation. Intercepting here with an explanation is
        // superior to letting the user accumulate a guaranteed-failing combination and then guessing the protocol status code.
        if (checked && ksword::kvm::isEptpSwitchEnabled())
        {
            kLocalEptAction->setChecked(false);
            QMessageBox::warning(
                this,
                ks::i18n::sourceText(QStringLiteral("私有 EPT 与 EPTP 切换后端互斥")),
                ks::i18n::sourceText(QStringLiteral("EPTP 切换后端靠在多份 EPT 层次之间换 EPTP 来做视图，私有 EPT 则要给每个处理器各自一份层次，两者对层次的用法冲突，驱动会在分配任何资源之前拒绝同时请求。请先关掉「EPT 分离视图用 EPTP 切换后端」。")));
            return;
        }
        /*
         * Mutually exclusive with VMFUNC; this case was previously missing on both sides.
         *
         * The consequence of this omission is worse than 'missing one prompt': the driver will indeed reject this
         * combination, but its returned STATUS_INVALID_PARAMETER has no corresponding status mapping in
         * START_RESIDENT, causing it to fall through to the fallback branch and report RENDEZVOUS_FAILED—a name
         * unrelated to the true cause that misleads debugging toward multi-core synchronization issues. The option's
         * own documentation states it is 'mutually exclusive with VMFUNC', but the code does not enforce this.
         */
        if (checked && ksword::kvm::isVmFuncEnabled())
        {
            kLocalEptAction->setChecked(false);
            QMessageBox::warning(
                this,
                ks::i18n::sourceText(QStringLiteral("私有 EPT 与 VMFUNC 互斥")),
                ks::i18n::sourceText(QStringLiteral("VMFUNC 要求所有处理器共享同一份 EPTP list，而私有 EPT 要给每个处理器各自一份层次，驱动会拒绝同时请求。请先关掉「武装 VMFUNC / EPTP 切换」。")));
            return;
        }
        /*
         * Mutually exclusive with nested dispatch; direction must be completed.
         *
         * This item's own description explicitly states it is mutually exclusive with VMFUNC and nested VMX, but the nested half
         * never had corresponding code—because this combination could not be formed before the nested dispatch switch existed.
         * Now that the other half is available, the missing half must be filled in; otherwise, callers entering from
         * this side will still hit the ambiguous 'Invalid Request' message that doesn't specify which party is at fault.
         */
        if (checked && ksword::kvm::isNestedDispatchEnabled())
        {
            kLocalEptAction->setChecked(false);
            QMessageBox::warning(
                this,
                ks::i18n::sourceText(QStringLiteral("私有 EPT 与嵌套派发互斥")),
                ks::i18n::sourceText(QStringLiteral("嵌套要把来宾的 EPT 层次和我们的合成成一个 EPT 指针，而私有 EPT 要给每个处理器各自一份层次，那会让这个合成变成处理器相关的。驱动会拒绝同时请求。请先关掉「允许来宾嵌套（我们作为宿主）」。")));
            return;
        }
        ksword::kvm::setLocalEptEnabled(checked);
        applyKvmButtonState();
        refreshKvmStatusAsync();
    });

    // EPTP switching backend: This option selects which machine set is used for the view, not whether a capability is needed.
    // Behavior when disabled matches the default backend byte-for-byte, so no high-risk confirmation is needed. The only reason
    // to select it is that the default backend requires Monitor Trap Flag (MTF), which nested Hyper-V guests cannot access.
    QAction* const kEptpSwitchAction = menu.addAction(
        ks::i18n::sourceText(QStringLiteral("EPT 分离视图用 EPTP 切换后端")));
    kEptpSwitchAction->setCheckable(true);
    kEptpSwitchAction->setChecked(ksword::kvm::isEptpSwitchEnabled());
    kEptpSwitchAction->setToolTip(ks::i18n::sourceText(QStringLiteral("默认后端是「写 EPT 叶 + 用 Monitor Trap Flag 单步一条指令 + 写回去」，它要求处理器提供 Monitor Trap Flag。EPTP 切换后端换成在两份层次之间切 EPTP，只要 execute-only EPT 叶，既不要 MTF 也不要 VMFUNC。差别不是性能而是能力：嵌套 Hyper-V 客户机拿不到 MTF，那种机器上只有这套后端能装上视图。与私有 EPT、VMFUNC 互斥。这一位只随准备资源发出，改完要重新准备才生效。")));
    connect(kEptpSwitchAction, &QAction::triggered, this, [this, kEptpSwitchAction](const bool checked) {
        if (!checked)
        {
            ksword::kvm::setEptpSwitchEnabled(false);
            applyKvmButtonState();
            refreshKvmStatusAsync();
            return;
        }
        if (ksword::kvm::isLocalEptEnabled() || ksword::kvm::isVmFuncEnabled())
        {
            kEptpSwitchAction->setChecked(false);
            QMessageBox::warning(
                this,
                ks::i18n::sourceText(QStringLiteral("EPTP 切换后端与私有 EPT、VMFUNC 互斥")),
                ks::i18n::sourceText(QStringLiteral("EPTP 切换后端要在多份 EPT 层次之间换 EPTP：私有 EPT 要给每个处理器各自一份层次，VMFUNC 又要所有处理器共享同一份 EPTP list，两者都与它冲突。驱动会在分配任何资源之前拒绝同时请求。请先关掉「每处理器私有 EPT」与「武装 VMFUNC 视图切换」。")));
            return;
        }
        ksword::kvm::setEptpSwitchEnabled(true);
        applyKvmButtonState();
        refreshKvmStatusAsync();
    });

    // Write-access gate: when closed, KVM operates in observation-only mode; all R-1 write capabilities are disabled.
    QAction* const kWriteAction = menu.addAction(
        ks::i18n::sourceText(QStringLiteral("允许 R-1 写操作")));
    kWriteAction->setCheckable(true);
    kWriteAction->setChecked(ksword::kvm::isWriteAccessEnabled());
    connect(kWriteAction, &QAction::triggered, this, [this](const bool checked) {
        if (!checked)
        {
            ksword::kvm::setWriteAccessEnabled(false);
            applyKvmButtonState();
            refreshKvmStatusAsync();
            return;
        }
        // Opening write access unlocks a whole class of capabilities to modify system state; explicit confirmation is required.
        //
        // Ensure the confirmation text and suppressionKey exist only in KvmWriteAccessGate: The wizard's pre-check must also enable it in-place.
        // If both entry points construct the prompt separately, users who checked 'Do not show again' in one entry will be prompted again in the
        // other. Moreover, if the text differs by even a single character, it becomes impossible to determine what the user actually agreed to.
        (void)ks::ui::requestKvmWriteAccess(this);
        applyKvmButtonState();
        refreshKvmStatusAsync();
    });

    // #VE Reflection: The only switch in this module where a misconfiguration causes an immediate BSOD, so access control is stricter than write permissions.
    // The guest is the running Windows instance; its IDT[20] lacks a #VE handler.
    QAction* const kVeAction = menu.addAction(
        ks::i18n::sourceText(QStringLiteral("武装 #VE 反射（危险）")));
    kVeAction->setCheckable(true);
    kVeAction->setChecked(ksword::kvm::isVeEnabled());
    kVeAction->setToolTip(ks::i18n::sourceText(QStringLiteral("把 EPT violation 反射成 guest 的 #VE（向量 20）。驱动侧有两道独立保险：所有 EPT 叶项都带 suppress-#VE，每 CPU 的信息区分配时即锁 busy。两道都在时，控制位开着也投递不出 #VE。本开关不持久化，重启客户端即回到关闭。")));
    connect(kVeAction, &QAction::triggered, this, [this, kVeAction](const bool checked) {
        if (!checked)
        {
            ksword::kvm::setVeEnabled(false);
            applyKvmButtonState();
            refreshKvmStatusAsync();
            return;
        }
        // Gate 1: Disable on bare-metal hosts. The cost of a misconfigured #VE is an immediate
        // system reboot; the only place that can tolerate this cost is inside a virtual machine.
        if (!ksword::kvm::isNestedAllowed())
        {
            kVeAction->setChecked(false);
            QMessageBox::warning(
                this,
                ks::i18n::sourceText(QStringLiteral("#VE 需要先进入嵌套模式")),
                ks::i18n::sourceText(QStringLiteral("#VE 只能在嵌套模式下武装，也就是只能在虚拟机里。配错的代价是整台机器立刻 triple fault 重启，这个代价只有虚拟机承受得起。请先打开「允许嵌套运行（作为 L1）」。")));
            return;
        }
        // Gate 2: Write access is a prerequisite; #VE is a capability that alters guest-visible behavior.
        if (!ksword::kvm::isWriteAccessEnabled())
        {
            kVeAction->setChecked(false);
            QMessageBox::warning(
                this,
                ks::i18n::sourceText(QStringLiteral("#VE 需要先开启写权限")),
                ks::i18n::sourceText(QStringLiteral("武装 #VE 会改变 guest 可见的异常行为，属于写权限门管辖的范围。请先打开「允许 R-1 写操作」。")));
            return;
        }
        // Access control gate 3: Standard high-risk confirmation.
        const bool kConfirmed = ks::ui::confirmDestructiveAction(
            this,
            QStringLiteral("KvmEnableVe"),
            ks::i18n::sourceText(QStringLiteral("武装 #VE 反射")),
            ks::i18n::sourceText(QStringLiteral("当前虚拟机的运行中内核")),
            ks::i18n::sourceText(QStringLiteral("#VE 把 EPT violation 变成 guest 内部的 20 号异常。这里的 guest 就是正在跑的这个 Windows，它没有 #VE 处理程序，真投递一次就是 #GP 转 #DF 转 triple fault，虚拟机当场重启且不会留下崩溃转储。")));
        if (!kConfirmed)
        {
            kVeAction->setChecked(false);
            return;
        }
        // Access control rule 4: final attempt, defaulting to Cancel.
        const auto kAnswer = QMessageBox::warning(
            this,
            ks::i18n::sourceText(QStringLiteral("确认武装 #VE")),
            ks::i18n::sourceText(QStringLiteral("武装后驱动仍有两道保险挡着实际投递：所有 EPT 叶项都带 suppress-#VE，每 CPU 的信息区出厂即锁 busy。因此这一步得到的是「控制位已武装」，不是「#VE 已生效」。要真的收到 #VE，还需要在 guest 里装好处理程序、清掉 busy、再把目标页显式设为可转换——那三步本客户端不提供。确定要武装吗？")),
            QMessageBox::Yes | QMessageBox::Cancel,
            QMessageBox::Cancel);
        const bool kArmed = kAnswer == QMessageBox::Yes;
        kVeAction->setChecked(kArmed);
        ksword::kvm::setVeEnabled(kArmed);
        applyKvmButtonState();
        refreshKvmStatusAsync();
    });

    // VMFUNC: Does not cause a BSOD, but publishes every domain in the EPTP list to any Ring 3 thread.
    QAction* const kVmFuncAction = menu.addAction(
        ks::i18n::sourceText(QStringLiteral("武装 VMFUNC 视图切换")));
    kVmFuncAction->setCheckable(true);
    kVmFuncAction->setChecked(ksword::kvm::isVmFuncEnabled());
    kVmFuncAction->setToolTip(ks::i18n::sourceText(QStringLiteral("武装后 guest 用一条 VMFUNC 就能在 EPTP list 的域之间切换，不产生 VM exit，驱动也收不到通知。VMFUNC 不做 CPL 检查，所以任意进程的任意 ring 3 线程都能切。这不是提权路径（域只能被拿掉权限），但确实是驱动观测不到的状态切换。本开关不持久化。")));
    connect(kVmFuncAction, &QAction::triggered, this, [this, kVmFuncAction](const bool checked) {
        if (!checked)
        {
            ksword::kvm::setVmFuncEnabled(false);
            applyKvmButtonState();
            refreshKvmStatusAsync();
            return;
        }
        // Same mutual exclusion as private EPT: VMFUNC requires all processors to share a single EPTP list, while EPTP
        // switching backends need to switch EPTPs across multiple layers; the driver will directly reject this combination.
        if (ksword::kvm::isEptpSwitchEnabled())
        {
            kVmFuncAction->setChecked(false);
            QMessageBox::warning(
                this,
                ks::i18n::sourceText(QStringLiteral("VMFUNC 与 EPTP 切换后端互斥")),
                ks::i18n::sourceText(QStringLiteral("VMFUNC 要求所有处理器共享同一份 EPTP list，而 EPTP 切换后端要在多份 EPT 层次之间换 EPTP，驱动会在分配任何资源之前拒绝同时请求。请先关掉「EPT 分离视图用 EPTP 切换后端」。")));
            return;
        }
        // Also mutually exclusive with private EPT. The reason is the same as for the private EPT option: the driver's rejection
        // will manifest as RENDEZVOUS_FAILED, a name unrelated to the true cause, so intercepting it here is more efficient.
        if (ksword::kvm::isLocalEptEnabled())
        {
            kVmFuncAction->setChecked(false);
            QMessageBox::warning(
                this,
                ks::i18n::sourceText(QStringLiteral("VMFUNC 与私有 EPT 互斥")),
                ks::i18n::sourceText(QStringLiteral("VMFUNC 要求所有处理器共享同一份 EPTP list，而私有 EPT 要给每个处理器各自一份层次，驱动会拒绝同时请求。请先关掉「每处理器私有 EPT」。")));
            return;
        }
        // Write permission prerequisite: exposing a switchable interface visible to the guest constitutes a change in system behavior.
        if (!ksword::kvm::isWriteAccessEnabled())
        {
            kVmFuncAction->setChecked(false);
            QMessageBox::warning(
                this,
                ks::i18n::sourceText(QStringLiteral("VMFUNC 需要先开启写权限")),
                ks::i18n::sourceText(QStringLiteral("武装 VMFUNC 会让 guest 获得一个驱动观测不到的视图切换能力，属于写权限门管辖的范围。请先打开「允许 R-1 写操作」。")));
            return;
        }
        const bool kConfirmed = ks::ui::confirmDestructiveAction(
            this,
            QStringLiteral("KvmEnableVmFunc"),
            ks::i18n::sourceText(QStringLiteral("武装 VMFUNC 视图切换")),
            ks::i18n::sourceText(QStringLiteral("EPTP list 中的全部执行域")),
            ks::i18n::sourceText(QStringLiteral("VMFUNC 不做 CPL 检查：武装之后，任意进程里的任意用户态线程都能用一条指令切换当前使用的 EPT 视图，不产生 VM exit，驱动也不会被通知。域只能被拿掉权限，所以切过去拿不到新的访问权，但这仍然是一个你观测不到的状态变化。")));
        kVmFuncAction->setChecked(kConfirmed);
        ksword::kvm::setVmFuncEnabled(kConfirmed);
        applyKvmButtonState();
        refreshKvmStatusAsync();
    });

    menu.addSeparator();

    // The R-1 memory panel does not require resident mode; the private page-table window is created when the driver loads.
    QAction* const kMemoryAction = menu.addAction(
        ks::i18n::sourceText(QStringLiteral("R-1 内存操作...")));
    kMemoryAction->setEnabled(r0DriverServiceRunning_);
    connect(kMemoryAction, &QAction::triggered, this, [this]() {
        // Modeless without parent: memory panel must be usable side-by-side with the main window.
        KvmMemoryDialog* const kDialog = new KvmMemoryDialog(this);
        kDialog->setAttribute(Qt::WA_DeleteOnClose);
        kDialog->show();
    });

    // EPT view also does not require residency: it is installed on EPT, and residency actually prevents modification.
    QAction* const kViewAction = menu.addAction(
        ks::i18n::sourceText(QStringLiteral("EPT 分离视图（隐蔽 Hook / 内存隐藏）...")));
    kViewAction->setEnabled(r0DriverServiceRunning_);
    connect(kViewAction, &QAction::triggered, this, [this]() {
        KvmViewDialog* const kDialog = new KvmViewDialog(this);
        kDialog->setAttribute(Qt::WA_DeleteOnClose);
        kDialog->show();
    });

    // Execution domain panel: domains are forks of the default view; permissions can only be revoked, not added.
    QAction* const kDomainAction = menu.addAction(
        ks::i18n::sourceText(QStringLiteral("EPT 执行域（VMFUNC 可切换）...")));
    kDomainAction->setEnabled(r0DriverServiceRunning_);
    connect(kDomainAction, &QAction::triggered, this, [this]() {
        KvmDomainDialog* const kDialog = new KvmDomainDialog(this);
        kDialog->setAttribute(Qt::WA_DeleteOnClose);
        kDialog->show();
    });

    // MSR policies are also configured when not resident: the bitmap reflects live hardware state and cannot be modified while resident.
    QAction* const kMsrAction = menu.addAction(
        ks::i18n::sourceText(QStringLiteral("MSR 策略...")));
    kMsrAction->setEnabled(r0DriverServiceRunning_);
    connect(kMsrAction, &QAction::triggered, this, [this]() {
        KvmMsrPolicyDialog* const kDialog = new KvmMsrPolicyDialog(this);
        kDialog->setAttribute(Qt::WA_DeleteOnClose);
        kDialog->show();
    });

    // The control-register policy is also consumed when building the VMCS and must be configured before the resident hypervisor starts.
    QAction* const kCrAction = menu.addAction(
        ks::i18n::sourceText(QStringLiteral("控制寄存器策略...")));
    kCrAction->setEnabled(r0DriverServiceRunning_);
    connect(kCrAction, &QAction::triggered, this, [this]() {
        KvmCrPolicyDialog* const kDialog = new KvmCrPolicyDialog(this);
        kDialog->setAttribute(Qt::WA_DeleteOnClose);
        kDialog->show();
    });

    // Event streams are read-only and always viewable—they are the sole real-time evidence of the capabilities listed above.
    QAction* const kEventAction = menu.addAction(
        ks::i18n::sourceText(QStringLiteral("事件流...")));
    kEventAction->setEnabled(r0DriverServiceRunning_);
    connect(kEventAction, &QAction::triggered, this, [this]() {
        KvmEventDialog* const kDialog = new KvmEventDialog(this);
        kDialog->setAttribute(Qt::WA_DeleteOnClose);
        kDialog->show();
    });

    // R-1 Process handling and injection. This option was previously only accessible via the 'full command panel',
    // which used a probe path launching the main program as an hvm_ctl subprocess; that entire path has been removed.
    // Since the capability has its own dedicated IOCTL, a new entry with the same shape as other panels is added here.
    QAction* const kProcessAction = menu.addAction(
        ks::i18n::sourceText(QStringLiteral("R-1 进程处置与注入...")));
    kProcessAction->setEnabled(r0DriverServiceRunning_);
    connect(kProcessAction, &QAction::triggered, this, [this]() {
        KvmProcessDialog* const kDialog = new KvmProcessDialog(this);
        kDialog->setAttribute(Qt::WA_DeleteOnClose);
        kDialog->show();
    });

    menu.addSeparator();

    // Fault reset clears only recoverable flags; the driver rejects it while the resident hypervisor is running.
    QAction* const kResetAction = menu.addAction(
        ks::i18n::sourceText(QStringLiteral("重置故障状态")));
    kResetAction->setEnabled(!kvmOperationRunning_ && kvmFaulted_);
    connect(kResetAction, &QAction::triggered, this, [this]() {
        runKvmFaultReset();
    });

    // AMD backend: Gray out entries based on EPT split view or VMCS fields.
    //
    // Uses the same criteria and explanation as the set of gates in KvmDock. Since these two locations are
    // checked independently, users may find a button unresponsive in one entry point while it works in another.
    //
    // The switches above do not follow the gray state: some are persistent (private EPT, EPTP switching). The user
    // may have opened them on a different Intel machine, and on AMD they would block resource preparation if left on.
    // Disabling them together also disables the only exit point, creating a dead end.
    if (kvmBackend_ == KSWORD_ARK_HVM_BACKEND_SVM)
    {
        const QString kAmdReason = ks::i18n::sourceText(QStringLiteral("这一项建立在 Intel VMX 的 VMCS 字段或 EPT 分离视图上，当前的 AMD SVM/NPT 后端还没有对应实现。"));
        for (QAction* const kAction : { kViewAction, kDomainAction, kMsrAction, kCrAction, kProcessAction })
        {
            kAction->setEnabled(false);
            kAction->setToolTip(kAmdReason);
        }
    }

    menu.exec(globalPosition);
}
