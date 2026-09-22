// NOMINMAX must be defined before any include: several project headers cascade-include Windows.h. Defining it
// later is too late; once the min/max macros are included, they will break std:: templates with the same names.
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "KvmHookWizard.h"

#include "KvmControl.h"
#include "ThemeStatusRole.h"
#include "../framework/DestructiveActionConfirmation.h"
#include "../internationalization/LanguageManager.h"
#include "../kernel_dock/KernelThreadAuditTab.h"

#include <QComboBox>
#include <QFontDatabase>
#include <QFormLayout>
#include <QFrame>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QSignalBlocker>
#include <QStackedWidget>
#include <QStringList>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>

// The rehearsal page requires VirtualAlloc / VirtualLock / VirtualFree.
#include <Windows.h>

#include <thread>
#include <vector>

// This implementation handles the wizard skeleton, Step 1 (select target), and Step 4 (installation).
// Step 2 is in KvmHookWizard.Patch.cpp, Steps 3/5 are in KvmHookWizard.Verify.cpp; see
// the contract section in the KvmHookWizard.h header for division of responsibilities.

namespace
{
    // Upper bound for target physical address. The driver only checks for 'page-aligned' and 'less than
    // this value' (see hvm_ept_view.c:288-295, which compares against KSW_HVM_MAX_MAPPED_PHYSICAL =)
    //  KSW_HVM_ONE_512_GIB * KSW_HVM_MAX_PML4_ENTRIES = 0x8000000000 * 16）。
    // The client performs this check first to clarify the rejection reason, not to make the determination for the driver.
    constexpr quint64 kMaxTargetPhysical = 0x80000000000ULL;

    // Bytes per page. Using the arithmetic layer's constant instead of hard-coding 4096 ensures the two values are always equal.
    constexpr qsizetype kPageBytes =
        static_cast<qsizetype>(ksword::evidence::kPatchPageBytes);

    // Marker byte written in the rehearsal page. Since pages from VirtualAlloc are zeroed, the entire page contains only
    // this single non-zero byte; after reading the baseline, it is immediately recognizable whether this page was read.
    constexpr unsigned char kRehearsalMarkerByte = 0xA5U;

    // hexText: Unified hexadecimal display format shared by four read-only value labels.
    QString hexText(const quint64 value)
    {
        return QStringLiteral("0x%1").arg(value, 0, 16);
    }

    // parseHexQuint64: Parse a hexadecimal number from the input field, tolerating the 0x prefix and leading/trailing whitespace.
    // An empty string is not an error but indicates 'not yet filled', so the caller must check for null first.
    bool parseHexQuint64(const QString& text, quint64* const valueOut)
    {
        QString compact = text.trimmed();
        if (compact.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
        {
            compact = compact.mid(2);
        }
        if (compact.isEmpty())
        {
            return false;
        }
        bool converted = false;
        const qulonglong kValue = compact.toULongLong(&converted, 16);
        if (!converted)
        {
            return false;
        }
        *valueOut = static_cast<quint64>(kValue);
        return true;
    }

    // makeMonospace: Renders read-only byte/address echo controls in monospace font.
    // The address must be compared bit-by-bit, which is impossible with proportional fonts.
    void makeMonospace(QWidget* const widget)
    {
        if (widget == nullptr)
        {
            return;
        }
        widget->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    }
}

namespace ks::ui
{
    QString describeHookTargetSource(const KvmHookTargetSource source)
    {
        switch (source)
        {
        case KvmHookTargetSource::kModuleOffset:
            return ks::i18n::sourceText(
                QStringLiteral("模块 + 偏移"));
        case KvmHookTargetSource::kKernelVa:
            return ks::i18n::sourceText(
                QStringLiteral("裸内核虚拟地址"));
        case KvmHookTargetSource::kRawPa:
            return ks::i18n::sourceText(
                QStringLiteral("裸物理地址"));
        case KvmHookTargetSource::kRehearsal:
            return ks::i18n::sourceText(
                QStringLiteral("排练（本进程自有页）"));
        default:
            break;
        }
        return ks::i18n::sourceText(QStringLiteral("未知入口"));
    }

    // =====================================================================
    // Lifecycle
    // =====================================================================

    KvmHookWizard::KvmHookWizard(QWidget* const parent)
        : QDialog(parent)
    {
        setWindowTitle(ks::i18n::sourceText(
            QStringLiteral("KVM HOOK 视图安装向导")));
        setObjectName(QStringLiteral("KvmHookWizard"));
        buildUi();
        goToStep(Step::kTarget);
    }

    KvmHookWizard::~KvmHookWizard()
    {
        // Order is critical: once a rehearsal page's physical frame is returned to the system, it may be reused by something
        // else while the view still points to that frame. At that point, execution redirected to the shadow page would run
        // code unrelated to us. Therefore, remove the view first; if removal fails, it is preferable to leak the page.
        bool viewRemoved = true;
        if (plan_.installed
            && plan_.installedViewId != 0
            && plan_.targetSource == KvmHookTargetSource::kRehearsal)
        {
            // This is the only place in this file where an IOCTL is dispatched on the UI thread. The
            // dialog is being destroyed, no other thread can perform this task for it, and returning
            // memory with a still-attached view to the system is far worse than blocking here once.
            const ksword::kvm::KvmViewResult kRemoval =
                ksword::kvm::removeView(plan_.installedViewId);
            viewRemoved = kRemoval.ok;
        }
        if (viewRemoved)
        {
            releaseRehearsalPage();
        }
    }

    void KvmHookWizard::openWizard(QWidget* const parent)
    {
        // Keep only one instance. Having two wizards open simultaneously causes each to allocate a separate rehearsal page and hold a separate
        // view; the destruction order determines which view is removed and page returned first—a race condition that is unnecessary to risk.
        // Use QPointer instead of a raw pointer: the window calls WA_DeleteOnClose, so this must still be visible afterward.
        static QPointer<KvmHookWizard> openedWizard;
        if (!openedWizard.isNull())
        {
            openedWizard->show();
            openedWizard->raise();
            openedWizard->activateWindow();
            return;
        }

        KvmHookWizard* const kWizard = new KvmHookWizard(parent);
        // Non-modal: The pre-check screen often requires looking at the wizard while modifying state in other panels
        // (enabling write permissions, stopping resident processes). A modal dialog would block this workflow.
        kWizard->setAttribute(Qt::WA_DeleteOnClose, true);
        openedWizard = kWizard;
        kWizard->show();
        kWizard->raise();
        kWizard->activateWindow();
    }

    // =====================================================================
    // Skeleton and navigation.
    // =====================================================================

    void KvmHookWizard::buildUi()
    {
        QVBoxLayout* const kRootLayout = new QVBoxLayout(this);

        stepTitleLabel_ = new QLabel(QString(), this);
        stepTitleLabel_->setWordWrap(true);
        kRootLayout->addWidget(stepTitleLabel_);

        stepHintLabel_ = new QLabel(QString(), this);
        stepHintLabel_->setWordWrap(true);
        kRootLayout->addWidget(stepHintLabel_);

        pageStack_ = new QStackedWidget(this);
        // The five pages are added in Step order, with indices corresponding one-to-one to Steps: Step 2 controls
        // are built by KvmHookWizard.Patch.cpp, while Steps 3 and 5 are built by KvmHookWizard.Verify.cpp.
        pageStack_->addWidget(buildTargetPage());
        pageStack_->addWidget(buildPatchPage());
        pageStack_->addWidget(buildPreflightPage());
        pageStack_->addWidget(buildInstallPage());
        pageStack_->addWidget(buildVerifyPage());
        kRootLayout->addWidget(pageStack_, 1);

        QFrame* const kSeparator = new QFrame(this);
        kSeparator->setFrameShape(QFrame::HLine);
        kSeparator->setFrameShadow(QFrame::Sunken);
        kRootLayout->addWidget(kSeparator);

        statusLabel_ = new QLabel(QString(), this);
        statusLabel_->setWordWrap(true);
        kRootLayout->addWidget(statusLabel_);

        QHBoxLayout* const kNavigationLayout = new QHBoxLayout();
        backButton_ = new QPushButton(
            ks::i18n::sourceText(QStringLiteral("上一步")), this);
        nextButton_ = new QPushButton(
            ks::i18n::sourceText(QStringLiteral("下一步")), this);
        closeButton_ = new QPushButton(
            ks::i18n::sourceText(QStringLiteral("关闭")), this);
        kNavigationLayout->addWidget(backButton_);
        kNavigationLayout->addWidget(nextButton_);
        kNavigationLayout->addStretch(1);
        kNavigationLayout->addWidget(closeButton_);
        kRootLayout->addLayout(kNavigationLayout);

        connect(backButton_, &QPushButton::clicked, this, [this]() {
            const int kPrevious = static_cast<int>(currentStep_) - 1;
            if (kPrevious >= 0)
            {
                goToStep(static_cast<Step>(kPrevious));
            }
        });
        connect(nextButton_, &QPushButton::clicked, this, [this]() {
            QString reason;
            if (!canLeaveStep(currentStep_, &reason))
            {
                setStatusText(reason, KvmCheckVerdict::kFail);
                return;
            }
            const int kNext = static_cast<int>(currentStep_) + 1;
            if (kNext < static_cast<int>(Step::kCount))
            {
                goToStep(static_cast<Step>(kNext));
            }
        });
        connect(closeButton_, &QPushButton::clicked, this, [this]() {
            close();
        });

        resize(940, 720);
    }

    void KvmHookWizard::goToStep(const Step step)
    {
        const int kIndex = static_cast<int>(step);
        if (kIndex < 0 || kIndex >= static_cast<int>(Step::kCount))
        {
            return;
        }
        currentStep_ = step;
        if (pageStack_ != nullptr)
        {
            pageStack_->setCurrentIndex(kIndex);
        }

        QString title;
        QString hint;
        switch (step)
        {
        case Step::kTarget:
            title = ks::i18n::sourceText(
                QStringLiteral("第 1 步 / 共 5 步：指定目标页"));
            hint = ks::i18n::sourceText(
                QStringLiteral("四个入口最终都收敛到同一条归一化管线：先算出虚拟地址，再翻译成物理地址，最后拆成页基址与页内偏移。以前这三步在用户脑子里，算错了驱动也不会报错。"));
            break;
        case Step::kPatch:
            title = ks::i18n::sourceText(
                QStringLiteral("第 2 步 / 共 5 步：编补丁"));
            hint = ks::i18n::sourceText(
                QStringLiteral("HOOK 的影子页才是被执行的那一份，所以它必须是「原页 4096 字节 + 你的改动」，补丁区间以外每个字节都要与原页逐位相同。"));
            break;
        case Step::kPreflight:
            title = ks::i18n::sourceText(
                QStringLiteral("第 3 步 / 共 5 步：预检"));
            hint = ks::i18n::sourceText(
                QStringLiteral("这一屏只转述驱动侧的前置条件与本层的几何检查，它不放宽任何一条，也不替驱动发明新的检查。"));
            break;
        case Step::kInstall:
            title = ks::i18n::sourceText(
                QStringLiteral("第 4 步 / 共 5 步：安装"));
            hint = ks::i18n::sourceText(
                QStringLiteral("安装前会重读一次目标页并与第 2 步冻结的基线逐字节比对，比对不过就中止，不是提示一下继续装。"));
            break;
        case Step::kVerify:
            title = ks::i18n::sourceText(
                QStringLiteral("第 5 步 / 共 5 步：校验"));
            hint = ks::i18n::sourceText(
                QStringLiteral("装上了与生效了是两件事。这一屏把能读回来的读数原样摆出来，读不到的如实写成「没有读数」，不涂成通过也不涂成失败。"));
            break;
        default:
            break;
        }
        if (stepTitleLabel_ != nullptr)
        {
            stepTitleLabel_->setText(title);
        }
        if (stepHintLabel_ != nullptr)
        {
            stepHintLabel_->setText(hint);
        }

        updateNavigationState();
        // "What to do when entering this step" has only this single dispatch point.
        enterStep(step);
    }

    void KvmHookWizard::enterStep(const Step step)
    {
        switch (step)
        {
        case Step::kTarget:
            // The module list is enumerated only on the first entry: it uses R3's NtQuerySystemInformation,
            // which is expensive and won't change during the few minutes the wizard is open.
            if (modules_.isEmpty() && !moduleQueryInFlight_)
            {
                refreshModuleList();
            }
            updateTargetReadout();
            break;
        case Step::kPatch:
            // Capture a baseline if it is incomplete. When the target changes, applyTargetResolve
            // clears the baselinePage, so 'target changed' manifests here as an incomplete baseline.
            if (!plan_.baselineIsComplete())
            {
                startBaselineCapture();
            }
            else
            {
                updatePatchEnabledState();
            }
            break;
        case Step::kPreflight:
            startPreflightRefresh();
            break;
        case Step::kInstall:
            if (installSummaryView_ != nullptr)
            {
                installSummaryView_->setPlainText(buildInstallSummaryText());
            }
            break;
        case Step::kVerify:
            startVerifyStatic();
            break;
        default:
            break;
        }
    }

    bool KvmHookWizard::canLeaveStep(
        const Step step,
        QString* const reasonOut) const
    {
        const auto kRefuse = [reasonOut](const QString& reason) {
            if (reasonOut != nullptr)
            {
                *reasonOut = reason;
            }
            return false;
        };

        switch (step)
        {
        case Step::kTarget:
            if (!plan_.resolved)
            {
                return kRefuse(ks::i18n::sourceText(
                    QStringLiteral("目标还没有归一化成功：下一步要用的是页基址，没有它就没有可装的东西。")));
            }
            return true;
        case Step::kPatch:
            if (!plan_.baselineIsComplete())
            {
                return kRefuse(ks::i18n::sourceText(
                    QStringLiteral("基线页不是完整的 4096 字节：残缺的基线拼出来的影子页会在被执行的那一页里留一段零。")));
            }
            if (plan_.patchIsEmpty())
            {
                return kRefuse(ks::i18n::sourceText(
                    QStringLiteral("补丁为空：空补丁产出的影子页与原页逐位相同，装上去什么都不改变却会让人以为补丁生效了。")));
            }
            if (plan_.classifyPatchGeometry()
                != ksword::evidence::CrossPageClassification::kInPage)
            {
                return kRefuse(ks::i18n::sourceText(
                    QStringLiteral("补丁跨过了页尾：一条视图恰好覆盖一页，协议里没有页数，跨页在两种后端下都必须直接拒绝。")));
            }
            return true;
        case Step::kPreflight:
            if (preflightRows_.isEmpty())
            {
                return kRefuse(ks::i18n::sourceText(
                    QStringLiteral("预检还没有读到任何读数：先刷新一次再往下走。")));
            }
            if (hasBlockingPreflightFailure())
            {
                return kRefuse(ks::i18n::sourceText(
                    QStringLiteral("预检里还有拦截性的判据没有通过：「不知道」同样挡住下一步，因为它不等于「可以装」。")));
            }
            return true;
        case Step::kInstall:
            if (!plan_.installed)
            {
                return kRefuse(ks::i18n::sourceText(
                    QStringLiteral("还没有安装成功：第 5 步校验的是这一条已安装视图，没装上就没有可校验的对象。")));
            }
            return true;
        case Step::kVerify:
            return kRefuse(ks::i18n::sourceText(
                QStringLiteral("这已经是最后一步。")));
        default:
            break;
        }
        return true;
    }

    void KvmHookWizard::updateNavigationState()
    {
        if (backButton_ != nullptr)
        {
            backButton_->setEnabled(
                !busy_ && currentStep_ != Step::kTarget);
        }
        if (nextButton_ != nullptr)
        {
            QString reason;
            const bool kAllowed =
                !busy_
                && currentStep_ != Step::kVerify
                && canLeaveStep(currentStep_, &reason);
            nextButton_->setEnabled(kAllowed);
            nextButton_->setToolTip(kAllowed ? QString() : reason);
        }
        if (closeButton_ != nullptr)
        {
            closeButton_->setEnabled(true);
        }
    }

    void KvmHookWizard::setBusy(const bool busy)
    {
        busy_ = busy;
        updateNavigationState();
        if (moduleReloadButton_ != nullptr)
        {
            moduleReloadButton_->setEnabled(!busy && !moduleQueryInFlight_);
        }
        if (rehearsalAllocButton_ != nullptr)
        {
            rehearsalAllocButton_->setEnabled(
                !busy && rehearsalPage_ == nullptr);
        }
        if (installButton_ != nullptr)
        {
            installButton_->setEnabled(!busy && !installInFlight_);
        }
        if (preflightRefreshButton_ != nullptr)
        {
            preflightRefreshButton_->setEnabled(!busy);
        }
        if (verifyRefreshButton_ != nullptr)
        {
            verifyRefreshButton_->setEnabled(!busy);
        }
        if (verifyResidentButton_ != nullptr)
        {
            verifyResidentButton_->setEnabled(!busy);
        }
        // The availability rules for Step 2 include more than just 'busy' status, so delegate the calculation back to it.
        if (shadowEditor_ != nullptr)
        {
            updatePatchEnabledState();
        }
    }

    void KvmHookWizard::setStatusText(
        const QString& text,
        const KvmCheckVerdict verdict)
    {
        if (statusLabel_ == nullptr)
        {
            return;
        }
        statusLabel_->setText(text);
        applyStatusRole(statusLabel_, checkVerdictStatusRole(verdict));
    }

    void KvmHookWizard::failBackTo(
        const Step step,
        const QString& reason,
        const unsigned long protocolStatus,
        const long lastStatus)
    {
        // Append the two-level failure codes verbatim to the message. Once the message becomes a sentence, it loses the information
        // about 'which step failed'. Since the same protocolStatus can be generated by multiple branches, only pairing it with
        // lastStatus allows differentiation. Only with these two values can one trace back to the specific branch in the driver.
        const QString kDetail = ks::i18n::sourceText(
            QStringLiteral("%1（协议状态 %2，NTSTATUS 0x%3）"))
            .arg(reason)
            .arg(protocolStatus)
            .arg(static_cast<quint32>(lastStatus), 8, 16, QLatin1Char('0'));
        if (installStatusLabel_ != nullptr)
        {
            installStatusLabel_->setText(kDetail);
            applyStatusRole(installStatusLabel_, StatusRole::kError);
        }
        // Switch pages before writing the status line: goToStep dispatches the refresh for the target step, which also writes this line.
        // If written in reverse, this failure reason would be immediately overwritten by the target step's 'Refreshing...' status.
        goToStep(step);
        setStatusText(kDetail, KvmCheckVerdict::kFail);
    }

    KvmHookWizard::Step KvmHookWizard::stepForViewFailure(
        const unsigned long protocolStatus,
        const long lastStatus)
    {
        // lastStatus is not used here for step selection: the two sources it distinguishes (currently resident vs.
        // topology/capability mismatch) appear on the same screen. It is passed through unchanged by failBackTo, allowing that
        // screen to identify the specific row—this is precisely why the two-level failure codes must be transmitted together.
        (void)lastStatus;
        switch (protocolStatus)
        {
        case KSWORD_ARK_HVM_VIEW_STATUS_OK:
            // Zero means both 'success' and 'the client rejected it without sending an IOCTL'. Only the latter can reach
            // this point (the caller guarantees ok is false), and there are only two rejection reasons on the client side:
            // Write permissions are closed and shadow page length is incorrect. The former is the first line of preflight.
            return Step::kPreflight;
        case KSWORD_ARK_HVM_VIEW_STATUS_INVALID_REQUEST:
            // The driver checks only two conditions: page alignment and the 8 TiB upper bound; both belong to target geometry.
            return Step::kTarget;
        case KSWORD_ARK_HVM_VIEW_STATUS_CONFIRMATION_REQUIRED:
            // Unrelated to security policy: this is a shape issue with the FORCE/confirmation bit; retrying once is sufficient.
            return Step::kInstall;
        case KSWORD_ARK_HVM_VIEW_STATUS_NOT_PREPARED:
        case KSWORD_ARK_HVM_VIEW_STATUS_TABLE_FULL:
        case KSWORD_ARK_HVM_VIEW_STATUS_SPLIT_FAILED:
        case KSWORD_ARK_HVM_VIEW_STATUS_EXECUTE_ONLY_UNSUPPORTED:
        case KSWORD_ARK_HVM_VIEW_STATUS_RESOURCE_FAILED:
            return Step::kPreflight;
        case KSWORD_ARK_HVM_VIEW_STATUS_NOT_FOUND:
            // If NOT_FOUND is encountered on the ADD path, it indicates that this page has no mapping at
            // the base layer, meaning the target was selected incorrectly rather than a prerequisite issue.
            return Step::kTarget;
        case KSWORD_ARK_HVM_VIEW_STATUS_LEAF_CONFLICT:
            // Another view already exists on this page. Either switch pages or clear
            // space in the view panel; both paths require reselecting the target.
            return Step::kTarget;
        case KSWORD_ARK_HVM_VIEW_STATUS_MULTIPROCESSOR_UNSAFE:
            // This protocol state has two sources: resident (lastStatus = STATUS_DEVICE_BUSY
            // 0x80000011) or topology/capability mismatch (STATUS_NOT_SUPPORTED 0xC00000BB).
            // Both have their own row in the preflight screen (NotResident and Topology), so we
            // return to the same step; they are distinguished by lastStatus, which is passed to
            // that screen unchanged by failBackTo, rather than being inferred from a string here.
            return Step::kPreflight;
        default:
            break;
        }
        return Step::kPreflight;
    }

    // =====================================================================
    // Step 1: Select target
    // =====================================================================

    QWidget* KvmHookWizard::buildTargetPage()
    {
        QWidget* const kPage = new QWidget(this);
        QVBoxLayout* const kPageLayout = new QVBoxLayout(kPage);

        QFormLayout* const kSourceForm = new QFormLayout();
        sourceBox_ = new QComboBox(kPage);
        sourceBox_->addItem(
            describeHookTargetSource(KvmHookTargetSource::kModuleOffset),
            static_cast<int>(KvmHookTargetSource::kModuleOffset));
        sourceBox_->addItem(
            describeHookTargetSource(KvmHookTargetSource::kKernelVa),
            static_cast<int>(KvmHookTargetSource::kKernelVa));
        sourceBox_->addItem(
            describeHookTargetSource(KvmHookTargetSource::kRawPa),
            static_cast<int>(KvmHookTargetSource::kRawPa));
        sourceBox_->addItem(
            describeHookTargetSource(KvmHookTargetSource::kRehearsal),
            static_cast<int>(KvmHookTargetSource::kRehearsal));
        kSourceForm->addRow(
            ks::i18n::sourceText(QStringLiteral("目标入口")),
            sourceBox_);
        kPageLayout->addLayout(kSourceForm);

        sourceStack_ = new QStackedWidget(kPage);

        // ---- Entry 1: Module + Offset ----
        QWidget* const kModulePage = new QWidget(sourceStack_);
        QVBoxLayout* const kModuleLayout = new QVBoxLayout(kModulePage);
        QFormLayout* const kModuleForm = new QFormLayout();
        QWidget* const kModuleRow = new QWidget(kModulePage);
        QHBoxLayout* const kModuleRowLayout = new QHBoxLayout(kModuleRow);
        kModuleRowLayout->setContentsMargins(0, 0, 0, 0);
        moduleBox_ = new QComboBox(kModuleRow);
        moduleReloadButton_ = new QPushButton(
            ks::i18n::sourceText(QStringLiteral("重新枚举")), kModuleRow);
        kModuleRowLayout->addWidget(moduleBox_, 1);
        kModuleRowLayout->addWidget(moduleReloadButton_);
        kModuleForm->addRow(
            ks::i18n::sourceText(QStringLiteral("内核模块")),
            kModuleRow);
        moduleOffsetEdit_ = new QLineEdit(kModulePage);
        moduleOffsetEdit_->setPlaceholderText(QStringLiteral("0x1234"));
        makeMonospace(moduleOffsetEdit_);
        kModuleForm->addRow(
            ks::i18n::sourceText(QStringLiteral("模块内偏移（十六进制）")),
            moduleOffsetEdit_);
        kModuleLayout->addLayout(kModuleForm);

        moduleRangeLabel_ = new QLabel(QString(), kModulePage);
        moduleRangeLabel_->setWordWrap(true);
        kModuleLayout->addWidget(moduleRangeLabel_);

        QLabel* const kModuleNoteLabel = new QLabel(
            ks::i18n::sourceText(QStringLiteral("模块表走 R3 的 NtQuerySystemInformation，不依赖驱动，因此被摘链的驱动不会出现在这个下拉里 —— 这里选不到某个模块，不等于系统里没有它。")),
            kModulePage);
        kModuleNoteLabel->setWordWrap(true);
        applyStatusRole(kModuleNoteLabel, StatusRole::kInfo);
        kModuleLayout->addWidget(kModuleNoteLabel);
        kModuleLayout->addStretch(1);
        sourceStack_->addWidget(kModulePage);

        // ---- Entry 2: Raw Kernel Virtual Address ----
        QWidget* const kKernelVaPage = new QWidget(sourceStack_);
        QVBoxLayout* const kKernelVaLayout = new QVBoxLayout(kKernelVaPage);
        QFormLayout* const kKernelVaForm = new QFormLayout();
        kernelVaEdit_ = new QLineEdit(kKernelVaPage);
        kernelVaEdit_->setPlaceholderText(QStringLiteral("0xFFFFF80000000000"));
        makeMonospace(kernelVaEdit_);
        kKernelVaForm->addRow(
            ks::i18n::sourceText(QStringLiteral("内核虚拟地址（十六进制）")),
            kernelVaEdit_);
        kKernelVaLayout->addLayout(kKernelVaForm);
        QLabel* const kKernelVaNoteLabel = new QLabel(
            ks::i18n::sourceText(QStringLiteral("这条入口不做归属校验，只做翻译：地址抄错一位仍然会翻译成功，只是翻到了别的一页。")),
            kKernelVaPage);
        kKernelVaNoteLabel->setWordWrap(true);
        applyStatusRole(kKernelVaNoteLabel, StatusRole::kWarning);
        kKernelVaLayout->addWidget(kKernelVaNoteLabel);
        kKernelVaLayout->addStretch(1);
        sourceStack_->addWidget(kKernelVaPage);

        // ---- Entry 3: Raw Physical Address ----
        QWidget* const kRawPaPage = new QWidget(sourceStack_);
        QVBoxLayout* const kRawPaLayout = new QVBoxLayout(kRawPaPage);
        QFormLayout* const kRawPaForm = new QFormLayout();
        rawPaEdit_ = new QLineEdit(kRawPaPage);
        rawPaEdit_->setPlaceholderText(QStringLiteral("0x1000"));
        makeMonospace(rawPaEdit_);
        kRawPaForm->addRow(
            ks::i18n::sourceText(QStringLiteral("物理地址（十六进制，跳过翻译）")),
            rawPaEdit_);
        kRawPaLayout->addLayout(kRawPaForm);
        QLabel* const kRawPaWarningLabel = new QLabel(
            ks::i18n::sourceText(QStringLiteral("驱动对这条路径只校验页对齐与小于 8 TiB 两条，既不校验目标页是不是 RAM，也不校验它归谁。填错的结果是视图静默安装成功，然后对一页毫不相干的物理内存做执行重定向。")),
            kRawPaPage);
        kRawPaWarningLabel->setWordWrap(true);
        applyStatusRole(kRawPaWarningLabel, StatusRole::kError);
        kRawPaLayout->addWidget(kRawPaWarningLabel);
        QLabel* const kRawPaJumpLabel = new QLabel(
            ks::i18n::sourceText(QStringLiteral("这条入口拿不到虚拟地址，所以第 2 步的近跳与绝对跳模板在这里没有可信的源地址，会被停用。")),
            kRawPaPage);
        kRawPaJumpLabel->setWordWrap(true);
        applyStatusRole(kRawPaJumpLabel, StatusRole::kInfo);
        kRawPaLayout->addWidget(kRawPaJumpLabel);
        kRawPaLayout->addStretch(1);
        sourceStack_->addWidget(kRawPaPage);

        // ---- Entry 4: Rehearsal ----
        QWidget* const kRehearsalPage = new QWidget(sourceStack_);
        QVBoxLayout* const kRehearsalLayout = new QVBoxLayout(kRehearsalPage);
        QLabel* const kRehearsalIntroLabel = new QLabel(
            ks::i18n::sourceText(QStringLiteral("排练把目标换成本进程自己分配并锁住的一页，后面四步与真实目标逐条一致。它回答的是一个别处回答不了的问题：这一趟走完没生效，到底是整条编排有 bug，还是装上了但没生效 —— 在动内核之前把这两件事分开。")),
            kRehearsalPage);
        kRehearsalIntroLabel->setWordWrap(true);
        kRehearsalLayout->addWidget(kRehearsalIntroLabel);

        rehearsalAllocButton_ = new QPushButton(
            ks::i18n::sourceText(QStringLiteral("分配并锁住一页排练页")),
            kRehearsalPage);
        kRehearsalLayout->addWidget(rehearsalAllocButton_);

        rehearsalLabel_ = new QLabel(QString(), kRehearsalPage);
        rehearsalLabel_->setWordWrap(true);
        makeMonospace(rehearsalLabel_);
        kRehearsalLayout->addWidget(rehearsalLabel_);

        QLabel* const kRehearsalNoteLabel = new QLabel(
            ks::i18n::sourceText(QStringLiteral("分配之后会先写一个标记字节再 VirtualLock：没有驻留的页翻译出来的帧随时会换人，而接下来要往那个帧上挂视图。这一页在向导关闭时释放，且必须在移除视图之后。")),
            kRehearsalPage);
        kRehearsalNoteLabel->setWordWrap(true);
        applyStatusRole(kRehearsalNoteLabel, StatusRole::kInfo);
        kRehearsalLayout->addWidget(kRehearsalNoteLabel);
        kRehearsalLayout->addStretch(1);
        sourceStack_->addWidget(kRehearsalPage);

        kPageLayout->addWidget(sourceStack_);

        // ---- Four Products of the Normalization Pipeline ----
        QGroupBox* const kReadoutGroup = new QGroupBox(
            ks::i18n::sourceText(QStringLiteral("归一化结果")), kPage);
        QFormLayout* const kReadoutForm = new QFormLayout(kReadoutGroup);
        readoutVaLabel_ = new QLabel(QString(), kReadoutGroup);
        readoutFullPaLabel_ = new QLabel(QString(), kReadoutGroup);
        readoutPageBaseLabel_ = new QLabel(QString(), kReadoutGroup);
        readoutPageOffsetLabel_ = new QLabel(QString(), kReadoutGroup);
        makeMonospace(readoutVaLabel_);
        makeMonospace(readoutFullPaLabel_);
        makeMonospace(readoutPageBaseLabel_);
        makeMonospace(readoutPageOffsetLabel_);
        kReadoutForm->addRow(
            ks::i18n::sourceText(QStringLiteral("虚拟地址")),
            readoutVaLabel_);
        kReadoutForm->addRow(
            ks::i18n::sourceText(QStringLiteral("完整物理地址（含页内偏移）")),
            readoutFullPaLabel_);
        kReadoutForm->addRow(
            ks::i18n::sourceText(QStringLiteral("页基址（安装用的就是它）")),
            readoutPageBaseLabel_);
        kReadoutForm->addRow(
            ks::i18n::sourceText(QStringLiteral("页内偏移")),
            readoutPageOffsetLabel_);
        kPageLayout->addWidget(kReadoutGroup);

        QLabel* const kCr3NoteLabel = new QLabel(
            ks::i18n::sourceText(QStringLiteral("这里不需要填 CR3：翻译时页目录基址恒传 0，表示驱动用 __readcr3()，而内核地址在任何进程的页表里都能解析；排练页的目标就在本进程用户空间里，调用线程正好也在这个进程。")),
            kPage);
        kCr3NoteLabel->setWordWrap(true);
        applyStatusRole(kCr3NoteLabel, StatusRole::kInfo);
        kPageLayout->addWidget(kCr3NoteLabel);

        targetStatusLabel_ = new QLabel(QString(), kPage);
        targetStatusLabel_->setWordWrap(true);
        kPageLayout->addWidget(targetStatusLabel_);
        kPageLayout->addStretch(1);

        // The debounce timer belongs to Step 1, so create it in the Step 1 build.
        targetDebounce_ = new QTimer(this);
        targetDebounce_->setSingleShot(true);
        targetDebounce_->setInterval(kInputDebounceMilliseconds);
        connect(targetDebounce_, &QTimer::timeout, this, [this]() {
            startTargetResolve();
        });

        connect(
            sourceBox_,
            &QComboBox::currentIndexChanged,
            this,
            [this](int) { onTargetSourceChanged(); });
        connect(
            moduleBox_,
            &QComboBox::currentIndexChanged,
            this,
            [this](int) { scheduleTargetResolve(); });
        connect(moduleReloadButton_, &QPushButton::clicked, this, [this]() {
            refreshModuleList();
        });
        connect(moduleOffsetEdit_, &QLineEdit::textChanged, this, [this]() {
            scheduleTargetResolve();
        });
        connect(kernelVaEdit_, &QLineEdit::textChanged, this, [this]() {
            scheduleTargetResolve();
        });
        connect(rawPaEdit_, &QLineEdit::textChanged, this, [this]() {
            scheduleTargetResolve();
        });
        connect(rehearsalAllocButton_, &QPushButton::clicked, this, [this]() {
            if (allocateRehearsalPage())
            {
                scheduleTargetResolve();
            }
        });

        // Default to Rehearsal: It is the only entry point that allows completing all five steps
        // without risk, and it aligns with the default value of KvmHookPlan::targetSource.
        sourceBox_->setCurrentIndex(
            static_cast<int>(KvmHookTargetSource::kRehearsal));
        sourceStack_->setCurrentIndex(
            static_cast<int>(KvmHookTargetSource::kRehearsal));
        return kPage;
    }

    void KvmHookWizard::onTargetSourceChanged()
    {
        if (sourceBox_ == nullptr)
        {
            return;
        }
        const int kIndex = sourceBox_->currentIndex();
        if (kIndex < 0)
        {
            return;
        }
        const KvmHookTargetSource kSource =
            static_cast<KvmHookTargetSource>(kIndex);
        if (sourceStack_ != nullptr)
        {
            sourceStack_->setCurrentIndex(kIndex);
        }

        // Clear all fields belonging to the old entry: leaving old values would cause Step 4's summary to show a
        // target the user no longer selected, and the summary is the only chance to verify before installation.
        plan_.targetSource = kSource;
        plan_.moduleName.clear();
        plan_.moduleBase = 0;
        plan_.imageSize = 0;
        plan_.offset = 0;
        plan_.virtualAddress = 0;
        plan_.fullPhysicalAddress = 0;
        plan_.pageBasePhysical = 0;
        plan_.pageOffset = 0;
        plan_.resolved = false;
        // The baseline and patch bytes belong to the previous target page; changing the target invalidates them as any baseline.
        plan_.baselinePage.clear();
        plan_.patchBytes.clear();
        // The sequence number is invalidated here: between switching the entry point and the debounce
        // point, there is a gap. If the previous entry's translation returns during this gap with an
        // equal sequence number, it would write the old entry's page geometry into the new entry's plan.
        ++targetResolveSequence_;

        updateTargetReadout();
        updateNavigationState();
        scheduleTargetResolve();
    }

    void KvmHookWizard::scheduleTargetResolve()
    {
        if (targetDebounce_ == nullptr)
        {
            startTargetResolve();
            return;
        }
        // Sending a blocking IOCTL for every keystroke would freeze the UI, so we batch them first.
        targetDebounce_->start();
    }

    void KvmHookWizard::startTargetResolve()
    {
        if (targetResolveInFlight_)
        {
            // Single-flight: when the active thread returns, debounce is re-scheduled to prevent dispatching duplicates.
            if (targetDebounce_ != nullptr)
            {
                targetDebounce_->start();
            }
            return;
        }

        const KvmHookTargetSource kSource = plan_.targetSource;
        quint64 virtualAddress = 0;
        quint64 rawPhysicalAddress = 0;

        switch (kSource)
        {
        case KvmHookTargetSource::kModuleOffset:
        {
            const int kModuleIndex =
                (moduleBox_ != nullptr) ? moduleBox_->currentIndex() : -1;
            if (kModuleIndex < 0 || kModuleIndex >= modules_.size())
            {
                plan_.resolved = false;
                updateTargetReadout();
                if (targetStatusLabel_ != nullptr)
                {
                    targetStatusLabel_->setText(ks::i18n::sourceText(
                        QStringLiteral("还没有选择模块。")));
                    applyStatusRole(targetStatusLabel_, StatusRole::kIdle);
                }
                updateNavigationState();
                return;
            }
            const KvmHookModuleChoice& choice = modules_.at(kModuleIndex);
            quint64 offset = 0;
            const QString kOffsetText = (moduleOffsetEdit_ != nullptr)
                ? moduleOffsetEdit_->text()
                : QString();
            if (!parseHexQuint64(kOffsetText, &offset))
            {
                plan_.resolved = false;
                updateTargetReadout();
                if (targetStatusLabel_ != nullptr)
                {
                    targetStatusLabel_->setText(ks::i18n::sourceText(
                        QStringLiteral("模块内偏移不是合法的十六进制数。")));
                    applyStatusRole(targetStatusLabel_, StatusRole::kError);
                }
                updateNavigationState();
                return;
            }
            // Locally clamp the upper bound; if it fails, reject immediately without sending an IOCTL. This is the only one of the
            // four entry points capable of preventing 'off-by-one address copy' errors; if it fails to clamp, the selection is futile.
            if (choice.imageSize == 0 || offset >= choice.imageSize)
            {
                plan_.resolved = false;
                plan_.offset = offset;
                updateTargetReadout();
                if (targetStatusLabel_ != nullptr)
                {
                    targetStatusLabel_->setText(ks::i18n::sourceText(
                        QStringLiteral("偏移 %1 超出了模块 %2 的映像大小 %3，已在本地拒绝，没有发起翻译。"))
                        .arg(hexText(offset))
                        .arg(choice.name)
                        .arg(hexText(choice.imageSize)));
                    applyStatusRole(targetStatusLabel_, StatusRole::kError);
                }
                updateNavigationState();
                return;
            }
            plan_.moduleName = choice.name;
            plan_.moduleBase = choice.baseAddress;
            plan_.imageSize = choice.imageSize;
            plan_.offset = offset;
            virtualAddress = choice.baseAddress + offset;
            break;
        }
        case KvmHookTargetSource::kKernelVa:
        {
            const QString kText =
                (kernelVaEdit_ != nullptr) ? kernelVaEdit_->text() : QString();
            if (!parseHexQuint64(kText, &virtualAddress))
            {
                plan_.resolved = false;
                updateTargetReadout();
                if (targetStatusLabel_ != nullptr)
                {
                    targetStatusLabel_->setText(ks::i18n::sourceText(
                        QStringLiteral("内核虚拟地址不是合法的十六进制数。")));
                    applyStatusRole(targetStatusLabel_, StatusRole::kError);
                }
                updateNavigationState();
                return;
            }
            break;
        }
        case KvmHookTargetSource::kRawPa:
        {
            const QString kText =
                (rawPaEdit_ != nullptr) ? rawPaEdit_->text() : QString();
            if (!parseHexQuint64(kText, &rawPhysicalAddress))
            {
                plan_.resolved = false;
                updateTargetReadout();
                if (targetStatusLabel_ != nullptr)
                {
                    targetStatusLabel_->setText(ks::i18n::sourceText(
                        QStringLiteral("物理地址不是合法的十六进制数。")));
                    applyStatusRole(targetStatusLabel_, StatusRole::kError);
                }
                updateNavigationState();
                return;
            }
            break;
        }
        case KvmHookTargetSource::kRehearsal:
        {
            if (rehearsalPage_ == nullptr)
            {
                plan_.resolved = false;
                updateTargetReadout();
                if (targetStatusLabel_ != nullptr)
                {
                    targetStatusLabel_->setText(ks::i18n::sourceText(
                        QStringLiteral("还没有分配排练页。")));
                    applyStatusRole(targetStatusLabel_, StatusRole::kIdle);
                }
                updateNavigationState();
                return;
            }
            virtualAddress =
                static_cast<quint64>(reinterpret_cast<quintptr>(rehearsalPage_));
            break;
        }
        default:
            break;
        }

        plan_.virtualAddress = virtualAddress;
        targetResolveInFlight_ = true;
        ++targetResolveSequence_;
        const quint64 kSequence = targetResolveSequence_;
        if (targetStatusLabel_ != nullptr)
        {
            // Ensure a usable UI frame is available during the wait: only update the text without
            // disabling input fields; otherwise, users will lose focus repeatedly while typing.
            targetStatusLabel_->setText(ks::i18n::sourceText(
                QStringLiteral("正在翻译目标地址...")));
            applyStatusRole(targetStatusLabel_, StatusRole::kInfo);
        }

        QPointer<KvmHookWizard> safeThis(this);
        std::thread([safeThis, kSequence, kSource, virtualAddress,
                     rawPhysicalAddress]() {
            const KvmHookTargetResolution kResolution = resolveTargetBlocking(
                kSource, virtualAddress, rawPhysicalAddress);
            if (safeThis == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                safeThis,
                [safeThis, kSequence, kResolution]() {
                    if (safeThis == nullptr)
                    {
                        return;
                    }
                    safeThis->applyTargetResolve(kSequence, kResolution);
                },
                Qt::QueuedConnection);
        }).detach();
    }

    void KvmHookWizard::applyTargetResolve(
        const quint64 sequence,
        const KvmHookTargetResolution& resolution)
    {
        // The in-flight flag must be cleared first: at most one request is in flight at any time, so any return corresponds to it.
        // Clearing this flag after the sequence check would leave the flag permanently true for
        // a single invalidated result, preventing all subsequent translations from being sent.
        targetResolveInFlight_ = false;
        if (sequence != targetResolveSequence_)
        {
            // An old address invalidated by subsequent input. Applying it would cause a mismatch between page
            // geometry and the input field, which is precisely the error type this flow aims to eliminate.
            return;
        }

        const quint64 kPreviousPageBase = plan_.pageBasePhysical;
        plan_.virtualAddress = resolution.virtualAddress;
        plan_.fullPhysicalAddress = resolution.fullPhysicalAddress;
        plan_.pageBasePhysical = resolution.pageBasePhysical;
        plan_.pageOffset = resolution.pageOffset;
        plan_.resolved = resolution.ok;
        if (plan_.pageBasePhysical != kPreviousPageBase)
        {
            // Changing the page changes the baseline. Keeping the previous page's bytes means step 2 uses them
            // as a draft to construct the shadow page, which is exactly the version executed by the processor.
            plan_.baselinePage.clear();
            plan_.patchBytes.clear();
        }

        updateTargetReadout();
        if (targetStatusLabel_ != nullptr)
        {
            targetStatusLabel_->setText(resolution.message);
            applyStatusRole(
                targetStatusLabel_,
                resolution.ok ? StatusRole::kSuccess : StatusRole::kError);
        }
        updateNavigationState();
    }

    KvmHookTargetResolution KvmHookWizard::resolveTargetBlocking(
        const KvmHookTargetSource source,
        const quint64 virtualAddress,
        const quint64 rawPhysicalAddress)
    {
        KvmHookTargetResolution resolution;

        if (source == KvmHookTargetSource::kRawPa)
        {
            // This path has no virtual address and no translation step: the user provides the physical address directly.
            resolution.virtualAddress = 0;
            resolution.fullPhysicalAddress = rawPhysicalAddress;
            resolution.pageBasePhysical = rawPhysicalAddress & ~0xFFFULL;
            resolution.pageOffset =
                static_cast<quint32>(rawPhysicalAddress & 0xFFFULL);
            if (resolution.pageBasePhysical >= kMaxTargetPhysical)
            {
                resolution.ok = false;
                resolution.message = ks::i18n::sourceText(
                    QStringLiteral("页基址 %1 不小于 8 TiB，驱动会直接拒绝这一条。"))
                    .arg(hexText(resolution.pageBasePhysical));
                return resolution;
            }
            resolution.ok = true;
            resolution.message = ks::i18n::sourceText(
                QStringLiteral("已按裸物理地址取页几何，没有做任何翻译，也没有校验这一页是不是 RAM、归谁。"));
            return resolution;
        }

        if (virtualAddress == 0ULL)
        {
            resolution.ok = false;
            resolution.message = ks::i18n::sourceText(
                QStringLiteral("还没有得到有效的虚拟地址。"));
            return resolution;
        }

        // Page directory base address is always passed as 0: the driver uses __readcr3(), so kernel addresses can be
        // resolved in any process page table, and the page being paged out is already in the calling thread's process.
        const ksword::kvm::KvmMemoryResult kTranslated =
            ksword::kvm::translate(0ULL, virtualAddress);
        resolution.virtualAddress = virtualAddress;
        resolution.usedDirectWindow = kTranslated.usedDirectWindow;
        if (!kTranslated.ok)
        {
            resolution.ok = false;
            resolution.message = kTranslated.message;
            return resolution;
        }

        resolution.fullPhysicalAddress = kTranslated.physicalAddress;
        resolution.pageBasePhysical = kTranslated.physicalAddress & ~0xFFFULL;
        resolution.pageOffset =
            static_cast<quint32>(kTranslated.physicalAddress & 0xFFFULL);

        // Consistency check: the page offset must remain consistent before and after translation. Inconsistency indicates a contradictory
        // translation; the page base address obtained is untrustworthy, so it is better to reject immediately rather than proceed.
        const quint32 kVirtualPageOffset =
            static_cast<quint32>(virtualAddress & 0xFFFULL);
        if (resolution.pageOffset != kVirtualPageOffset)
        {
            resolution.ok = false;
            resolution.message = ks::i18n::sourceText(
                QStringLiteral("翻译自相矛盾：虚拟地址的页内偏移是 %1，返回的物理地址的页内偏移却是 %2，这一条已拒绝。"))
                .arg(hexText(kVirtualPageOffset))
                .arg(hexText(resolution.pageOffset));
            return resolution;
        }
        if (resolution.pageBasePhysical >= kMaxTargetPhysical)
        {
            resolution.ok = false;
            resolution.message = ks::i18n::sourceText(
                QStringLiteral("页基址 %1 不小于 8 TiB，驱动会直接拒绝这一条。"))
                .arg(hexText(resolution.pageBasePhysical));
            return resolution;
        }

        resolution.ok = true;
        resolution.message = resolution.usedDirectWindow
            ? ks::i18n::sourceText(
                QStringLiteral("翻译成功，走的是私有页表窗口。"))
            : ks::i18n::sourceText(
                QStringLiteral("翻译成功，但退化到了 MmCopyMemory 路径：仍然能翻译，只是不再规避内核层 Hook。这是一个读数，不是失败。"));
        return resolution;
    }

    void KvmHookWizard::refreshModuleList()
    {
        if (moduleQueryInFlight_)
        {
            return;
        }
        moduleQueryInFlight_ = true;
        ++moduleQuerySequence_;
        const quint64 kSequence = moduleQuerySequence_;
        if (moduleReloadButton_ != nullptr)
        {
            moduleReloadButton_->setEnabled(false);
        }

        QPointer<KvmHookWizard> safeThis(this);
        std::thread([safeThis, kSequence]() {
            // Uses R3 NtQuerySystemInformation; does not depend on the driver and can be called from any thread.
            KernelThreadAuditTab::ModuleQueryStatus status =
                KernelThreadAuditTab::ModuleQueryStatus::kOk;
            long nativeStatus = 0;
            unsigned long requiredBytes = 0;
            const std::vector<KernelThreadAuditTab::ModuleRecord> kRecords =
                KernelThreadAuditTab::queryKernelModules(
                    &status, &nativeStatus, &requiredBytes);

            // Project to value-layer structures in the background thread; the UI thread only copies a single set of copyable data.
            QVector<KvmHookModuleChoice> choices;
            choices.reserve(static_cast<qsizetype>(kRecords.size()));
            for (const auto& record : kRecords)
            {
                if (record.baseAddress == 0)
                {
                    continue;
                }
                KvmHookModuleChoice choice;
                choice.name = record.name;
                choice.path = record.path;
                choice.baseAddress = static_cast<quint64>(record.baseAddress);
                // imageSize is promoted to 64-bit here: using 32-bit for 'base + offset'
                // comparison would cause an out-of-bounds offset to appear as a valid address.
                choice.imageSize = static_cast<quint64>(record.imageSize);
                choice.kernelImage = record.kernelImage;
                choices.append(choice);
            }
            const bool kOk =
                status == KernelThreadAuditTab::ModuleQueryStatus::kOk;

            if (safeThis == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                safeThis,
                [safeThis, kSequence, choices, kOk]() {
                    if (safeThis == nullptr)
                    {
                        return;
                    }
                    // Same as above: clear the in-flight flag first; otherwise, a single invalidated enumeration would lock it to true.
                    safeThis->moduleQueryInFlight_ = false;
                    if (kSequence != safeThis->moduleQuerySequence_)
                    {
                        return;
                    }
                    if (safeThis->moduleReloadButton_ != nullptr)
                    {
                        safeThis->moduleReloadButton_->setEnabled(
                            !safeThis->busy_);
                    }
                    safeThis->modules_ = choices;
                    if (safeThis->moduleBox_ != nullptr)
                    {
                        const QSignalBlocker kBlocker(safeThis->moduleBox_);
                        safeThis->moduleBox_->clear();
                        for (const auto& choice : safeThis->modules_)
                        {
                            safeThis->moduleBox_->addItem(
                                QStringLiteral("%1  %2")
                                    .arg(choice.name)
                                    .arg(hexText(choice.baseAddress)));
                        }
                    }
                    if (safeThis->moduleRangeLabel_ != nullptr)
                    {
                        safeThis->moduleRangeLabel_->setText(kOk
                            ? ks::i18n::sourceText(
                                QStringLiteral("已枚举 %1 个内核模块。"))
                                .arg(choices.size())
                            : ks::i18n::sourceText(
                                QStringLiteral("内核模块枚举失败：这一屏拿不到模块表，不代表系统里没有模块。")));
                        applyStatusRole(
                            safeThis->moduleRangeLabel_,
                            kOk ? StatusRole::kInfo : StatusRole::kError);
                    }
                    if (safeThis->plan_.targetSource
                        == KvmHookTargetSource::kModuleOffset)
                    {
                        safeThis->scheduleTargetResolve();
                    }
                },
                Qt::QueuedConnection);
        }).detach();
    }

    void KvmHookWizard::updateTargetReadout()
    {
        if (readoutVaLabel_ != nullptr)
        {
            readoutVaLabel_->setText(
                plan_.targetSource == KvmHookTargetSource::kRawPa
                    ? ks::i18n::sourceText(
                        QStringLiteral("本入口没有虚拟地址"))
                    : hexText(plan_.virtualAddress));
        }
        if (readoutFullPaLabel_ != nullptr)
        {
            readoutFullPaLabel_->setText(hexText(plan_.fullPhysicalAddress));
        }
        if (readoutPageBaseLabel_ != nullptr)
        {
            readoutPageBaseLabel_->setText(hexText(plan_.pageBasePhysical));
        }
        if (readoutPageOffsetLabel_ != nullptr)
        {
            readoutPageOffsetLabel_->setText(
                QStringLiteral("%1 (%2)")
                    .arg(hexText(plan_.pageOffset))
                    .arg(plan_.pageOffset));
        }
        if (moduleRangeLabel_ != nullptr
            && plan_.targetSource == KvmHookTargetSource::kModuleOffset
            && plan_.imageSize != 0)
        {
            moduleRangeLabel_->setText(ks::i18n::sourceText(
                QStringLiteral("模块 %1 的地址区间是 %2 .. %3，偏移必须小于 %4。"))
                .arg(plan_.moduleName)
                .arg(hexText(plan_.moduleBase))
                .arg(hexText(plan_.moduleBase + plan_.imageSize))
                .arg(hexText(plan_.imageSize)));
            applyStatusRole(moduleRangeLabel_, StatusRole::kInfo);
        }
    }

    bool KvmHookWizard::allocateRehearsalPage()
    {
        if (rehearsalPage_ != nullptr)
        {
            return true;
        }
        // Addresses returned by VirtualAlloc are naturally 4 KiB aligned, so the rehearsal entry does not require additional page alignment.
        void* const kPage = ::VirtualAlloc(
            nullptr,
            static_cast<SIZE_T>(kPageBytes),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE);
        if (kPage == nullptr)
        {
            if (rehearsalLabel_ != nullptr)
            {
                rehearsalLabel_->setText(ks::i18n::sourceText(
                    QStringLiteral("排练页分配失败：Win32 错误 %1。"))
                    .arg(::GetLastError()));
                applyStatusRole(rehearsalLabel_, StatusRole::kError);
            }
            return false;
        }

        // Do not reverse this order: write a byte to give the page a physical backing frame,
        // then pin it with VirtualLock. An unpinned page's backing frame can be reassigned.
        // Attaching an EPT view after reassignment would target someone else's memory.
        static_cast<volatile unsigned char*>(kPage)[0] = kRehearsalMarkerByte;
        const BOOL kLocked =
            ::VirtualLock(kPage, static_cast<SIZE_T>(kPageBytes));
        rehearsalPage_ = kPage;

        if (rehearsalLabel_ != nullptr)
        {
            const quint64 kAddress =
                static_cast<quint64>(reinterpret_cast<quintptr>(kPage));
            rehearsalLabel_->setText(kLocked
                ? ks::i18n::sourceText(
                    QStringLiteral("排练页已分配并锁定：虚拟地址 %1，偏移 0 处写入了标记字节 0xA5，其余字节由 VirtualAlloc 清零。"))
                    .arg(hexText(kAddress))
                : ks::i18n::sourceText(
                    QStringLiteral("排练页已分配，但 VirtualLock 失败（Win32 错误 %1）：这一页的物理帧随时可能换人，翻译到的页基址不可信。"))
                    .arg(::GetLastError()));
            applyStatusRole(
                rehearsalLabel_,
                kLocked ? StatusRole::kSuccess : StatusRole::kWarning);
        }
        if (rehearsalAllocButton_ != nullptr)
        {
            rehearsalAllocButton_->setEnabled(false);
        }
        return true;
    }

    void KvmHookWizard::releaseRehearsalPage()
    {
        if (rehearsalPage_ == nullptr)
        {
            return;
        }
        (void)::VirtualUnlock(rehearsalPage_, static_cast<SIZE_T>(kPageBytes));
        (void)::VirtualFree(rehearsalPage_, 0, MEM_RELEASE);
        rehearsalPage_ = nullptr;
    }

    // =====================================================================
    // Step 4: Install
    // =====================================================================

    QWidget* KvmHookWizard::buildInstallPage()
    {
        QWidget* const kPage = new QWidget(this);
        QVBoxLayout* const kPageLayout = new QVBoxLayout(kPage);

        installSummaryView_ = new QPlainTextEdit(kPage);
        installSummaryView_->setReadOnly(true);
        makeMonospace(installSummaryView_);
        kPageLayout->addWidget(installSummaryView_, 1);

        QLabel* const kRiskLabel = new QLabel(
            ks::i18n::sourceText(QStringLiteral("HOOK 不是安全边界。稳态下对这一页的读写走真实页且被显式授予，不会触发任何事件。能把 hypervisor 打退的是：落进单指令翻转窗口内的访问、与已有翻转重叠、以及同一条指令取指跨两张视图页。")),
            kPage);
        kRiskLabel->setWordWrap(true);
        applyStatusRole(kRiskLabel, StatusRole::kError);
        kPageLayout->addWidget(kRiskLabel);

        QLabel* const kWindowLabel = new QLabel(
            ks::i18n::sourceText(QStringLiteral("安装前会重读一次目标页做 TOCTOU 比对，这把窗口收窄到了一次 IOCTL，但不为零 —— 对一页活着的内核代码，这个窗口关不掉。")),
            kPage);
        kWindowLabel->setWordWrap(true);
        applyStatusRole(kWindowLabel, StatusRole::kWarning);
        kPageLayout->addWidget(kWindowLabel);

        installButton_ = new QPushButton(
            ks::i18n::sourceText(QStringLiteral("确认并安装这条 HOOK 视图")),
            kPage);
        kPageLayout->addWidget(installButton_);

        installStatusLabel_ = new QLabel(QString(), kPage);
        installStatusLabel_->setWordWrap(true);
        kPageLayout->addWidget(installStatusLabel_);

        connect(installButton_, &QPushButton::clicked, this, [this]() {
            startInstall();
        });
        return kPage;
    }

    QString KvmHookWizard::buildInstallSummaryText() const
    {
        QStringList lines;
        lines << ks::i18n::sourceText(
            QStringLiteral("视图类型：HOOK（协议值 2）—— 读写走真实页，执行走影子页。"));
        lines << ks::i18n::sourceText(QStringLiteral("目标入口：%1"))
            .arg(describeHookTargetSource(plan_.targetSource));
        if (plan_.targetSource == KvmHookTargetSource::kModuleOffset)
        {
            lines << ks::i18n::sourceText(
                QStringLiteral("模块：%1，基址 %2，映像大小 %3，模块内偏移 %4"))
                .arg(plan_.moduleName)
                .arg(hexText(plan_.moduleBase))
                .arg(hexText(plan_.imageSize))
                .arg(hexText(plan_.offset));
        }
        lines << ks::i18n::sourceText(QStringLiteral("虚拟地址：%1"))
            .arg(plan_.targetSource == KvmHookTargetSource::kRawPa
                ? ks::i18n::sourceText(QStringLiteral("本入口没有虚拟地址"))
                : hexText(plan_.virtualAddress));
        lines << ks::i18n::sourceText(
            QStringLiteral("完整物理地址（含页内偏移）：%1"))
            .arg(hexText(plan_.fullPhysicalAddress));
        lines << ks::i18n::sourceText(QStringLiteral("目标物理页（安装用的就是它）：%1"))
            .arg(hexText(plan_.pageBasePhysical));
        lines << ks::i18n::sourceText(QStringLiteral("页内偏移：%1"))
            .arg(hexText(plan_.pageOffset));
        lines << ks::i18n::sourceText(
            QStringLiteral("影子来源：调用方提供的整页内容（Explicit，恰好 %1 字节）"))
            .arg(kPageBytes);
        lines << ks::i18n::sourceText(
            QStringLiteral("补丁：从页内偏移 %1 起，共 %2 字节，止于偏移 %3"))
            .arg(hexText(plan_.pageOffset))
            .arg(plan_.patchLength())
            .arg(hexText(plan_.patchEndOffset()));
        lines << ks::i18n::sourceText(
            QStringLiteral("稳态叶权限：真页 | 读 | 写，不给执行 —— 所以稳态下对这一页的读写不产生任何 violation。"));
        lines << ks::i18n::sourceText(
            QStringLiteral("翻转态叶权限：影子页 | 执行；处理器缺 execute-only 能力时驱动会静默补上读权限。"));
        lines << ks::i18n::sourceText(
            QStringLiteral("补丁几何：%1"))
            .arg(plan_.classifyPatchGeometry()
                    == ksword::evidence::CrossPageClassification::kInPage
                ? ks::i18n::sourceText(QStringLiteral("完全落在这一页内"))
                : ks::i18n::sourceText(QStringLiteral("越过了页尾，必须拒绝")));
        lines << ks::i18n::sourceText(
            QStringLiteral("HOOK 不是安全边界，失败即放行：翻转窗口里指令长度为 0 时处理器会重执行并读到真页。"));
        return lines.join(QStringLiteral("\n"));
    }

    void KvmHookWizard::startInstall()
    {
        if (busy_ || installInFlight_)
        {
            return;
        }
        if (!plan_.resolved)
        {
            failBackTo(
                Step::kTarget,
                ks::i18n::sourceText(
                    QStringLiteral("目标还没有归一化成功，没有可装的页基址。")),
                0,
                0);
            return;
        }
        if (!plan_.baselineIsComplete() || plan_.patchIsEmpty())
        {
            failBackTo(
                Step::kPatch,
                ks::i18n::sourceText(
                    QStringLiteral("基线不完整或补丁为空，成品影子页拼不出来。")),
                0,
                0);
            return;
        }

        QString composeFailure;
        const QByteArray kShadowPage =
            plan_.composedShadowPage(&composeFailure);
        if (kShadowPage.size() != kPageBytes)
        {
            // Cannot proceed from a work-in-progress page: the seed is Explicit, and the driver
            // copies the entire page into the shadow frame, which is the exact copy being executed.
            failBackTo(
                Step::kPatch,
                composeFailure.isEmpty()
                    ? ks::i18n::sourceText(
                        QStringLiteral("成品影子页拼不出完整的一页，已中止安装。"))
                    : composeFailure,
                0,
                0);
            return;
        }

        // Ensure the UI thread triggers the popup; only start the background thread after the popup completes.
        const QString kActionTitle = ks::i18n::sourceText(
            QStringLiteral("安装一条 HOOK EPT 分离视图"));
        const QString kTargetDescription = ks::i18n::sourceText(
            QStringLiteral("目标物理页 %1（入口：%2），影子页由基线页 %3 字节加上 %4 字节补丁现拼，补丁从页内偏移 %5 起。"))
            .arg(hexText(plan_.pageBasePhysical))
            .arg(describeHookTargetSource(plan_.targetSource))
            .arg(kPageBytes)
            .arg(plan_.patchLength())
            .arg(hexText(plan_.pageOffset));
        const QString kRiskDescription = ks::i18n::sourceText(
            QStringLiteral("这是 UI 上补的一道要人来点的门，它不是协议确认：客户端仍然无条件替你置上 UI_CONFIRMED 与确认令牌，驱动侧那道协议门在这条路径上本来就是自动满足的。HOOK 也不是安全边界 —— 稳态下对这一页的读写走真实页并被显式授予，不产生任何事件。"));
        if (!ks::ui::confirmDestructiveAction(
                this,
                QStringLiteral("KvmHookInstall"),
                kActionTitle,
                kTargetDescription,
                kRiskDescription))
        {
            setStatusText(
                ks::i18n::sourceText(QStringLiteral("已取消，没有发起安装。")),
                KvmCheckVerdict::kNoReading);
            return;
        }

        installInFlight_ = true;
        setBusy(true);
        if (installStatusLabel_ != nullptr)
        {
            installStatusLabel_->setText(ks::i18n::sourceText(
                QStringLiteral("正在重读目标页并比对基线...")));
            applyStatusRole(installStatusLabel_, StatusRole::kInfo);
        }

        const quint64 kPageBase = plan_.pageBasePhysical;
        const QByteArray kBaseline = plan_.baselinePage;
        QPointer<KvmHookWizard> safeThis(this);
        std::thread([safeThis, kPageBase, kBaseline, kShadowPage]() {
            const InstallOutcome kOutcome =
                performInstallBlocking(kPageBase, kBaseline, kShadowPage);
            if (safeThis == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                safeThis,
                [safeThis, kOutcome]() {
                    if (safeThis == nullptr)
                    {
                        return;
                    }
                    safeThis->applyInstallOutcome(kOutcome);
                },
                Qt::QueuedConnection);
        }).detach();
    }

    KvmHookWizard::InstallOutcome KvmHookWizard::performInstallBlocking(
        const quint64 pageBasePhysical,
        const QByteArray& baselinePage,
        const QByteArray& shadowPage)
    {
        InstallOutcome outcome;

        // 1) Re-read the target page. Several minutes may have passed from capturing the baseline in step 2 to here.
        outcome.freshPage = readTargetPage(pageBasePhysical, &outcome.rereadFailure);
        outcome.rereadOk =
            outcome.freshPage.size() == kPageBytes;
        if (!outcome.rereadOk)
        {
            return outcome;
        }

        // 2) Compare byte-by-byte with the frozen baseline. If they differ, stop immediately—the shadow
        //    page we constructed contains stale original bytes, yet the shadow page is the one being executed.
        outcome.baselineMatches = (outcome.freshPage == baselinePage);
        if (!outcome.baselineMatches)
        {
            return outcome;
        }

        // 3) A match implies the re-read bytes are bitwise identical to the baseline. Thus, applying the patch
        //    to the re-read bytes yields the same page passed by the caller, requiring no further stitching.
        outcome.addAttempted = true;
        outcome.addResult = ksword::kvm::addView(
            KSWORD_ARK_HVM_VIEW_KIND_HOOK,
            pageBasePhysical,
            ksword::kvm::KvmViewShadowSeed::kExplicit,
            shadowPage);
        if (!outcome.addResult.ok)
        {
            return outcome;
        }

        // 4) Immediately re-read once: the ADD response does not contain shadowPhysicalAddress.
        outcome.listAfter = ksword::kvm::listViews();
        return outcome;
    }

    void KvmHookWizard::applyInstallOutcome(const InstallOutcome& outcome)
    {
        installInFlight_ = false;
        setBusy(false);

        if (!outcome.rereadOk)
        {
            failBackTo(
                Step::kPatch,
                ks::i18n::sourceText(
                    QStringLiteral("安装前重读目标页失败，没有发起安装：%1"))
                    .arg(outcome.rereadFailure),
                0,
                0);
            return;
        }

        if (!outcome.baselineMatches)
        {
            // List the changed offsets. Stating only 'changed' forces the user to check again.
            QStringList changed;
            // Use qMin instead of std::min: Windows.h can introduce the min macro depending
            // on include order, which would expand std::min into syntactically invalid code.
            const qsizetype kLength =
                qMin(outcome.freshPage.size(), plan_.baselinePage.size());
            for (qsizetype index = 0; index < kLength; ++index)
            {
                if (outcome.freshPage.at(index) != plan_.baselinePage.at(index))
                {
                    if (changed.size() >= 32)
                    {
                        changed << ks::i18n::sourceText(
                            QStringLiteral("...（还有更多，只列前 32 处）"));
                        break;
                    }
                    const uint kOldByte = static_cast<uint>(
                        static_cast<quint8>(plan_.baselinePage.at(index)));
                    const uint kNewByte = static_cast<uint>(
                        static_cast<quint8>(outcome.freshPage.at(index)));
                    changed << QStringLiteral("+0x%1: %2 -> %3")
                        .arg(static_cast<quint64>(index), 3, 16,
                             QLatin1Char('0'))
                        .arg(kOldByte, 2, 16, QLatin1Char('0'))
                        .arg(kNewByte, 2, 16, QLatin1Char('0'));
                }
            }
            if (installSummaryView_ != nullptr)
            {
                installSummaryView_->setPlainText(
                    ks::i18n::sourceText(
                        QStringLiteral("目标页在抓基线之后被改过，已中止安装。变化的页内偏移："))
                    + QStringLiteral("\n")
                    + changed.join(QStringLiteral("\n")));
            }
            // Use the re-read page as the new baseline; the user can return to Step 2 to
            // recompile the patch without restarting from Step 1 or re-reading the data.
            plan_.baselinePage = outcome.freshPage;
            if (shadowEditor_ != nullptr)
            {
                revertPatch();
            }
            failBackTo(
                Step::kPatch,
                ks::i18n::sourceText(
                    QStringLiteral("目标页在抓基线之后被改过，已中止安装：影子页里含的会是过期的原字节，而影子页正是被执行的那一份。")),
                0,
                0);
            return;
        }

        if (!outcome.addAttempted)
        {
            failBackTo(
                Step::kPreflight,
                ks::i18n::sourceText(
                    QStringLiteral("安装请求没有发出，卡在重读或比对这一步。")),
                0,
                0);
            return;
        }

        if (!outcome.addResult.ok)
        {
            const Step kTarget = stepForViewFailure(
                outcome.addResult.protocolStatus,
                outcome.addResult.lastStatus);
            failBackTo(
                kTarget,
                outcome.addResult.message,
                outcome.addResult.protocolStatus,
                outcome.addResult.lastStatus);
            return;
        }

        plan_.installedViewId = outcome.addResult.viewId;
        plan_.installed = true;
        plan_.shadowPhysicalAddress = 0;
        for (const auto& entry : outcome.listAfter.views)
        {
            if (entry.viewId == plan_.installedViewId)
            {
                plan_.shadowPhysicalAddress = entry.shadowPhysicalAddress;
                break;
            }
        }

        const QString kSummary = ks::i18n::sourceText(
            QStringLiteral("已安装视图 %1：目标物理页 %2，影子物理页 %3。注意这只说明驱动接受了请求，那张叶到底改了没有要看第 5 步的读数。"))
            .arg(plan_.installedViewId)
            .arg(hexText(plan_.pageBasePhysical))
            .arg(plan_.shadowPhysicalAddress != 0
                ? hexText(plan_.shadowPhysicalAddress)
                : ks::i18n::sourceText(QStringLiteral("回读没拿到")));
        if (installStatusLabel_ != nullptr)
        {
            installStatusLabel_->setText(kSummary);
            applyStatusRole(installStatusLabel_, StatusRole::kSuccess);
        }
        // Same reason as failBackTo: switch pages before writing the status line;
        // otherwise, the data retrieval in step 5 will overwrite this summary immediately.
        goToStep(Step::kVerify);
        setStatusText(kSummary, KvmCheckVerdict::kPass);
    }
}
