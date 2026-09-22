#include "KvmCrPolicyDialog.h"

#include "KvmControl.h"
#include "../framework/DestructiveActionConfirmation.h"
#include "../internationalization/LanguageManager.h"

#include <QCheckBox>
#include <QFormLayout>
#include <QGridLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPointer>
#include <QPushButton>
#include <QVBoxLayout>

#include <thread>

namespace
{
    // Common pinned targets, provided as bitmasks to avoid manual mask calculation by users.
    constexpr unsigned long long kCr0WriteProtect = 1ull << 16;
    constexpr unsigned long long kCr4Smep = 1ull << 20;
    constexpr unsigned long long kCr4Smap = 1ull << 21;
    constexpr unsigned long long kCr4Umip = 1ull << 11;

    // parseHexOrZero: Treats empty input as zero; parses other inputs as hexadecimal.
    bool parseHexOrZero(const QString& text, unsigned long long* valueOut)
    {
        QString compact = text.trimmed();
        if (compact.isEmpty())
        {
            *valueOut = 0;
            return true;
        }
        if (compact.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
        {
            compact = compact.mid(2);
        }
        bool converted = false;
        const unsigned long long kValue = compact.toULongLong(&converted, 16);
        if (!converted)
        {
            return false;
        }
        *valueOut = kValue;
        return true;
    }
}

KvmCrPolicyDialog::KvmCrPolicyDialog(QWidget* const parent)
    : QDialog(parent)
{
    setWindowTitle(
        ks::i18n::sourceText(QStringLiteral("KVM 控制寄存器策略")));
    setObjectName(QStringLiteral("KvmCrPolicyDialog"));
    buildUi();
    updateEnabledState();
    refreshPolicy();
}

void KvmCrPolicyDialog::buildUi()
{
    QVBoxLayout* const kRootLayout = new QVBoxLayout(this);

    QLabel* const kHintLabel = new QLabel(
        ks::i18n::sourceText(QStringLiteral("被钉住的位由 hypervisor 持有：guest 改它会被驳回，但影子仍回报改成功。掩码在建 VMCS 时消费，必须在常驻启动前配置。")),
        this);
    kHintLabel->setWordWrap(true);
    kRootLayout->addWidget(kHintLabel);

    QFormLayout* const kFormLayout = new QFormLayout();
    pinWpCheck_ = new QCheckBox(
        ks::i18n::sourceText(QStringLiteral("钉住 CR0.WP（内核写保护）")), this);
    pinSmepCheck_ = new QCheckBox(
        ks::i18n::sourceText(QStringLiteral("钉住 CR4.SMEP")), this);
    pinSmapCheck_ = new QCheckBox(
        ks::i18n::sourceText(QStringLiteral("钉住 CR4.SMAP")), this);
    pinUmipCheck_ = new QCheckBox(
        ks::i18n::sourceText(QStringLiteral("钉住 CR4.UMIP")), this);
    kFormLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("常用钉住位")),
        pinWpCheck_);
    kFormLayout->addRow(QString(), pinSmepCheck_);
    kFormLayout->addRow(QString(), pinSmapCheck_);
    kFormLayout->addRow(QString(), pinUmipCheck_);

    cr0MaskEdit_ = new QLineEdit(this);
    cr0MaskEdit_->setPlaceholderText(
        ks::i18n::sourceText(QStringLiteral("额外的 CR0 掩码位，十六进制")));
    kFormLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("CR0 附加掩码")),
        cr0MaskEdit_);

    cr4MaskEdit_ = new QLineEdit(this);
    cr4MaskEdit_->setPlaceholderText(
        ks::i18n::sourceText(QStringLiteral("额外的 CR4 掩码位，十六进制")));
    kFormLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("CR4 附加掩码")),
        cr4MaskEdit_);

    trackCr3Check_ = new QCheckBox(
        ks::i18n::sourceText(QStringLiteral("跟踪地址空间切换（每次切换一次 VM-exit，非常昂贵）")),
        this);
    interceptDrCheck_ = new QCheckBox(
        ks::i18n::sourceText(QStringLiteral("拦截调试寄存器访问（只记录，不改变行为）")),
        this);
    logCheck_ = new QCheckBox(
        ks::i18n::sourceText(QStringLiteral("把拦截写进事件环")), this);
    kFormLayout->addRow(QString(), trackCr3Check_);
    kFormLayout->addRow(QString(), interceptDrCheck_);
    kFormLayout->addRow(QString(), logCheck_);
    kRootLayout->addLayout(kFormLayout);

    currentLabel_ = new QLabel(QString(), this);
    currentLabel_->setWordWrap(true);
    currentLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    kRootLayout->addWidget(currentLabel_, 1);

    QGridLayout* const kButtonLayout = new QGridLayout();
    applyButton_ = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("应用配置")), this);
    clearButton_ = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("清除配置")), this);
    refreshButton_ = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("刷新")), this);
    kButtonLayout->addWidget(applyButton_, 0, 0);
    kButtonLayout->addWidget(clearButton_, 0, 1);
    kButtonLayout->addWidget(refreshButton_, 0, 2);
    kRootLayout->addLayout(kButtonLayout);

    statusLabel_ = new QLabel(QString(), this);
    statusLabel_->setWordWrap(true);
    kRootLayout->addWidget(statusLabel_);

    connect(applyButton_, &QPushButton::clicked, this, [this]() {
        startApply();
    });
    connect(clearButton_, &QPushButton::clicked, this, [this]() {
        startClear();
    });
    connect(refreshButton_, &QPushButton::clicked, this, [this]() {
        refreshPolicy();
    });
    resize(640, 520);
}

void KvmCrPolicyDialog::updateEnabledState()
{
    const bool kWriteAllowed = ksword::kvm::isWriteAccessEnabled();
    const QString kWriteHint = kWriteAllowed
        ? QString()
        : ks::i18n::sourceText(QStringLiteral(
            "R-1 写权限未开启：在 KVM 按钮右键菜单中开启后才能配置策略"));
    if (applyButton_ != nullptr)
    {
        applyButton_->setEnabled(kWriteAllowed && !busy_);
        applyButton_->setToolTip(kWriteHint);
    }
    if (clearButton_ != nullptr)
    {
        clearButton_->setEnabled(kWriteAllowed && !busy_);
        clearButton_->setToolTip(kWriteHint);
    }
    if (refreshButton_ != nullptr)
    {
        refreshButton_->setEnabled(!busy_);
    }
}

void KvmCrPolicyDialog::setBusy(const bool busy)
{
    busy_ = busy;
    updateEnabledState();
}

bool KvmCrPolicyDialog::collectMasks(
    unsigned long long* const cr0Out,
    unsigned long long* const cr4Out)
{
    unsigned long long cr0Extra = 0;
    unsigned long long cr4Extra = 0;
    if (!parseHexOrZero(cr0MaskEdit_->text(), &cr0Extra))
    {
        statusLabel_->setText(ks::i18n::sourceText(
            QStringLiteral("CR0 附加掩码不是合法的十六进制数。")));
        return false;
    }
    if (!parseHexOrZero(cr4MaskEdit_->text(), &cr4Extra))
    {
        statusLabel_->setText(ks::i18n::sourceText(
            QStringLiteral("CR4 附加掩码不是合法的十六进制数。")));
        return false;
    }
    // Quick check and manual input are additive, not mutually exclusive.
    *cr0Out = cr0Extra |
        (pinWpCheck_->isChecked() ? kCr0WriteProtect : 0ull);
    *cr4Out = cr4Extra |
        (pinSmepCheck_->isChecked() ? kCr4Smep : 0ull) |
        (pinSmapCheck_->isChecked() ? kCr4Smap : 0ull) |
        (pinUmipCheck_->isChecked() ? kCr4Umip : 0ull);
    return true;
}

void KvmCrPolicyDialog::refreshPolicy()
{
    if (busy_)
    {
        return;
    }
    setBusy(true);
    QPointer<KvmCrPolicyDialog> safeThis(this);
    std::thread([safeThis]() {
        const ksword::kvm::KvmCrPolicyResult kResult =
            ksword::kvm::readCrPolicy();
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
                safeThis->setBusy(false);
                if (!kResult.ok)
                {
                    safeThis->statusLabel_->setText(kResult.message);
                    return;
                }
                safeThis->currentLabel_->setText(
                    ks::i18n::sourceText(QStringLiteral("当前配置：CR0 掩码 0x%1（捕获值 0x%2），CR4 掩码 0x%3（捕获值 0x%4）；驳回写入 %5 次，地址空间切换 %6 次，调试寄存器访问 %7 次。"))
                        .arg(kResult.cr0PinnedMask, 0, 16)
                        .arg(kResult.cr0PinnedValue, 0, 16)
                        .arg(kResult.cr4PinnedMask, 0, 16)
                        .arg(kResult.cr4PinnedValue, 0, 16)
                        .arg(kResult.refusedWriteCount)
                        .arg(kResult.cr3SwitchCount)
                        .arg(kResult.debugAccessCount));
                // Sync UI switches to the actual driver-side configuration to prevent display from diverging from reality.
                safeThis->trackCr3Check_->setChecked(kResult.trackCr3);
                safeThis->interceptDrCheck_->setChecked(kResult.interceptDr);
                safeThis->logCheck_->setChecked(kResult.log);
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmCrPolicyDialog::startApply()
{
    unsigned long long cr0Mask = 0;
    unsigned long long cr4Mask = 0;
    if (!collectMasks(&cr0Mask, &cr4Mask))
    {
        return;
    }
    // Tracking CR3 is too costly to be lumped into the general write permission check; it requires a separate confirmation.
    if (trackCr3Check_->isChecked())
    {
        const bool kConfirmed = ks::ui::confirmDestructiveAction(
            this,
            QStringLiteral("KvmTrackCr3"),
            ks::i18n::sourceText(QStringLiteral("开启地址空间切换跟踪")),
            ks::i18n::sourceText(QStringLiteral("本机全部逻辑处理器")),
            ks::i18n::sourceText(QStringLiteral("每次 CR3 加载都会变成一次 VM-exit。Windows 每秒切换地址空间数千次，整机会明显变慢，事件环也会迅速被填满并开始丢弃。")));
        if (!kConfirmed)
        {
            return;
        }
    }

    const bool kTrackCr3 = trackCr3Check_->isChecked();
    const bool kInterceptDr = interceptDrCheck_->isChecked();
    const bool kLog = logCheck_->isChecked();

    setBusy(true);
    statusLabel_->setText(
        ks::i18n::sourceText(QStringLiteral("正在应用配置...")));
    QPointer<KvmCrPolicyDialog> safeThis(this);
    std::thread([safeThis, cr0Mask, cr4Mask, kTrackCr3, kInterceptDr, kLog]() {
        const ksword::kvm::KvmCrPolicyResult kResult =
            ksword::kvm::applyCrPolicy(
                cr0Mask, cr4Mask, kTrackCr3, kInterceptDr, kLog);
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
                safeThis->setBusy(false);
                safeThis->statusLabel_->setText(kResult.message);
                safeThis->refreshPolicy();
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmCrPolicyDialog::startClear()
{
    setBusy(true);
    statusLabel_->setText(
        ks::i18n::sourceText(QStringLiteral("正在清除配置...")));
    QPointer<KvmCrPolicyDialog> safeThis(this);
    std::thread([safeThis]() {
        const ksword::kvm::KvmCrPolicyResult kResult =
            ksword::kvm::clearCrPolicy();
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
                safeThis->setBusy(false);
                safeThis->statusLabel_->setText(kResult.message);
                safeThis->refreshPolicy();
            },
            Qt::QueuedConnection);
    }).detach();
}
