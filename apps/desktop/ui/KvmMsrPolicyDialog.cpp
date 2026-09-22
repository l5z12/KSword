#include "KvmMsrPolicyDialog.h"

#include "KvmControl.h"
#include "../internationalization/LanguageManager.h"

#include <QComboBox>
#include <QFormLayout>
#include <QGridLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPointer>
#include <QPushButton>
#include <QTableWidget>
#include <QVBoxLayout>

#include <thread>

namespace
{
    // describeAccess: Translate the interception direction into a sentence.
    QString describeAccess(const unsigned long access)
    {
        const bool kRead =
            (access & KSWORD_ARK_HVM_MSR_ACCESS_READ) != 0;
        const bool kWrite =
            (access & KSWORD_ARK_HVM_MSR_ACCESS_WRITE) != 0;
        if (kRead && kWrite)
        {
            return ks::i18n::sourceText(QStringLiteral("读+写"));
        }
        return kRead
            ? ks::i18n::sourceText(QStringLiteral("读"))
            : ks::i18n::sourceText(QStringLiteral("写"));
    }

    // describeAction: Translate the action into a sentence.
    QString describeAction(const unsigned long action)
    {
        switch (action)
        {
        case KSWORD_ARK_HVM_MSR_ACTION_LOG:
            return ks::i18n::sourceText(QStringLiteral("记录后放行"));
        case KSWORD_ARK_HVM_MSR_ACTION_DENY:
            return ks::i18n::sourceText(QStringLiteral("拒绝（注入 #GP）"));
        case KSWORD_ARK_HVM_MSR_ACTION_FAKE:
            return ks::i18n::sourceText(QStringLiteral("伪造读值 / 吞掉写"));
        default:
            break;
        }
        return ks::i18n::sourceText(QStringLiteral("未知动作"));
    }

    // parseHex: Parse hexadecimal input optionally prefixed with 0x.
    bool parseHex(const QString& text, unsigned long long* valueOut)
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
        const unsigned long long kValue = compact.toULongLong(&converted, 16);
        if (!converted)
        {
            return false;
        }
        *valueOut = kValue;
        return true;
    }
}

KvmMsrPolicyDialog::KvmMsrPolicyDialog(QWidget* const parent)
    : QDialog(parent)
{
    setWindowTitle(ks::i18n::sourceText(QStringLiteral("KVM MSR 策略")));
    setObjectName(QStringLiteral("KvmMsrPolicyDialog"));
    buildUi();
    updateEnabledState();
    refreshPolicies();
}

void KvmMsrPolicyDialog::buildUi()
{
    QVBoxLayout* const kRootLayout = new QVBoxLayout(this);

    QLabel* const kHintLabel = new QLabel(
        ks::i18n::sourceText(QStringLiteral("只有位图覆盖的两段索引可以设策略：0x00000000-0x00001FFF 与 0xC0000000-0xC0001FFF。常驻期间不能改动策略。")),
        this);
    kHintLabel->setWordWrap(true);
    kRootLayout->addWidget(kHintLabel);

    QFormLayout* const kFormLayout = new QFormLayout();
    msrEdit_ = new QLineEdit(this);
    msrEdit_->setPlaceholderText(QStringLiteral("0xC0000082"));
    kFormLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("MSR 索引（十六进制）")),
        msrEdit_);

    accessBox_ = new QComboBox(this);
    accessBox_->addItem(
        ks::i18n::sourceText(QStringLiteral("读")),
        static_cast<unsigned int>(KSWORD_ARK_HVM_MSR_ACCESS_READ));
    accessBox_->addItem(
        ks::i18n::sourceText(QStringLiteral("写")),
        static_cast<unsigned int>(KSWORD_ARK_HVM_MSR_ACCESS_WRITE));
    accessBox_->addItem(
        ks::i18n::sourceText(QStringLiteral("读+写")),
        static_cast<unsigned int>(
            KSWORD_ARK_HVM_MSR_ACCESS_READ |
            KSWORD_ARK_HVM_MSR_ACCESS_WRITE));
    kFormLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("拦截方向")),
        accessBox_);

    actionBox_ = new QComboBox(this);
    actionBox_->addItem(
        ks::i18n::sourceText(QStringLiteral("记录后放行（仅读）")),
        static_cast<unsigned int>(KSWORD_ARK_HVM_MSR_ACTION_LOG));
    actionBox_->addItem(
        ks::i18n::sourceText(QStringLiteral("拒绝（注入 #GP）")),
        static_cast<unsigned int>(KSWORD_ARK_HVM_MSR_ACTION_DENY));
    actionBox_->addItem(
        ks::i18n::sourceText(QStringLiteral("伪造读值 / 吞掉写")),
        static_cast<unsigned int>(KSWORD_ARK_HVM_MSR_ACTION_FAKE));
    kFormLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("处置动作")),
        actionBox_);

    fakeValueEdit_ = new QLineEdit(this);
    fakeValueEdit_->setPlaceholderText(QStringLiteral("0"));
    kFormLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("伪造值（十六进制）")),
        fakeValueEdit_);
    kRootLayout->addLayout(kFormLayout);

    policyTable_ = new QTableWidget(0, 6, this);
    policyTable_->setHorizontalHeaderLabels(QStringList()
        << ks::i18n::sourceText(QStringLiteral("编号"))
        << ks::i18n::sourceText(QStringLiteral("MSR"))
        << ks::i18n::sourceText(QStringLiteral("方向"))
        << ks::i18n::sourceText(QStringLiteral("动作"))
        << ks::i18n::sourceText(QStringLiteral("伪造值"))
        << ks::i18n::sourceText(QStringLiteral("命中次数")));
    policyTable_->horizontalHeader()->setStretchLastSection(true);
    policyTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    policyTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    policyTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    kRootLayout->addWidget(policyTable_, 1);

    QGridLayout* const kButtonLayout = new QGridLayout();
    addButton_ = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("安装策略")), this);
    removeButton_ = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("移除选中")), this);
    clearButton_ = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("全部移除")), this);
    refreshButton_ = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("刷新")), this);
    kButtonLayout->addWidget(addButton_, 0, 0);
    kButtonLayout->addWidget(removeButton_, 0, 1);
    kButtonLayout->addWidget(clearButton_, 0, 2);
    kButtonLayout->addWidget(refreshButton_, 0, 3);
    kRootLayout->addLayout(kButtonLayout);

    statusLabel_ = new QLabel(QString(), this);
    statusLabel_->setWordWrap(true);
    kRootLayout->addWidget(statusLabel_);

    connect(actionBox_, &QComboBox::currentIndexChanged, this, [this](int) {
        updateEnabledState();
    });
    connect(addButton_, &QPushButton::clicked, this, [this]() {
        startAdd();
    });
    connect(removeButton_, &QPushButton::clicked, this, [this]() {
        startRemove();
    });
    connect(clearButton_, &QPushButton::clicked, this, [this]() {
        startClear();
    });
    connect(refreshButton_, &QPushButton::clicked, this, [this]() {
        refreshPolicies();
    });
    resize(720, 500);
}

void KvmMsrPolicyDialog::updateEnabledState()
{
    const bool kWriteAllowed = ksword::kvm::isWriteAccessEnabled();
    const QString kWriteHint = kWriteAllowed
        ? QString()
        : ks::i18n::sourceText(QStringLiteral(
            "R-1 写权限未开启：在 KVM 按钮右键菜单中开启后才能安装或移除策略"));
    if (addButton_ != nullptr)
    {
        addButton_->setEnabled(kWriteAllowed && !busy_);
        addButton_->setToolTip(kWriteHint);
    }
    if (removeButton_ != nullptr)
    {
        removeButton_->setEnabled(kWriteAllowed && !busy_);
        removeButton_->setToolTip(kWriteHint);
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
    // The fake value is only meaningful for the FAKE action.
    if (fakeValueEdit_ != nullptr && actionBox_ != nullptr)
    {
        fakeValueEdit_->setEnabled(
            actionBox_->currentData().toUInt() ==
                KSWORD_ARK_HVM_MSR_ACTION_FAKE &&
            !busy_);
    }
}

void KvmMsrPolicyDialog::setBusy(const bool busy)
{
    busy_ = busy;
    updateEnabledState();
}

void KvmMsrPolicyDialog::refreshPolicies()
{
    if (busy_)
    {
        return;
    }
    setBusy(true);
    QPointer<KvmMsrPolicyDialog> safeThis(this);
    std::thread([safeThis]() {
        const ksword::kvm::KvmMsrPolicyResult kResult =
            ksword::kvm::listMsrPolicies();
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
                QTableWidget* const kTable = safeThis->policyTable_;
                kTable->setRowCount(kResult.policies.size());
                for (int row = 0; row < kResult.policies.size(); ++row)
                {
                    const auto& entry = kResult.policies.at(row);
                    kTable->setItem(row, 0, new QTableWidgetItem(
                        QString::number(entry.policyId)));
                    kTable->setItem(row, 1, new QTableWidgetItem(
                        QStringLiteral("0x%1")
                            .arg(entry.msrIndex, 8, 16, QLatin1Char('0'))));
                    kTable->setItem(row, 2, new QTableWidgetItem(
                        describeAccess(entry.access)));
                    kTable->setItem(row, 3, new QTableWidgetItem(
                        describeAction(entry.action)));
                    kTable->setItem(row, 4, new QTableWidgetItem(
                        QStringLiteral("0x%1")
                            .arg(entry.fakeValue, 0, 16)));
                    kTable->setItem(row, 5, new QTableWidgetItem(
                        QString::number(entry.hitCount)));
                }
                safeThis->statusLabel_->setText(
                    ks::i18n::sourceText(QStringLiteral("已安装 %1 条策略。"))
                        .arg(kResult.policyCount));
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmMsrPolicyDialog::startAdd()
{
    unsigned long long msrIndex = 0;
    if (!parseHex(msrEdit_->text(), &msrIndex) ||
        msrIndex > 0xFFFFFFFFull)
    {
        statusLabel_->setText(ks::i18n::sourceText(
            QStringLiteral("MSR 索引不是合法的三十二位十六进制数。")));
        return;
    }
    unsigned long long fakeValue = 0;
    const unsigned long kAction = actionBox_->currentData().toUInt();
    if (kAction == KSWORD_ARK_HVM_MSR_ACTION_FAKE &&
        !fakeValueEdit_->text().trimmed().isEmpty() &&
        !parseHex(fakeValueEdit_->text(), &fakeValue))
    {
        statusLabel_->setText(ks::i18n::sourceText(
            QStringLiteral("伪造值不是合法的十六进制数。")));
        return;
    }
    const unsigned long kAccess = accessBox_->currentData().toUInt();

    setBusy(true);
    statusLabel_->setText(
        ks::i18n::sourceText(QStringLiteral("正在安装策略...")));
    QPointer<KvmMsrPolicyDialog> safeThis(this);
    std::thread([safeThis, msrIndex, kAccess, kAction, fakeValue]() {
        const ksword::kvm::KvmMsrPolicyResult kResult =
            ksword::kvm::addMsrPolicy(
                static_cast<unsigned long>(msrIndex),
                kAccess,
                kAction,
                fakeValue);
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
                safeThis->statusLabel_->setText(kResult.ok
                    ? ks::i18n::sourceText(
                        QStringLiteral("已安装策略，编号 %1。"))
                        .arg(kResult.policyId)
                    : kResult.message);
                safeThis->refreshPolicies();
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmMsrPolicyDialog::startRemove()
{
    const int kRow = policyTable_->currentRow();
    if (kRow < 0 || policyTable_->item(kRow, 0) == nullptr)
    {
        statusLabel_->setText(
            ks::i18n::sourceText(QStringLiteral("请先在表中选择一条策略。")));
        return;
    }
    const unsigned long kPolicyId =
        policyTable_->item(kRow, 0)->text().toULong();

    setBusy(true);
    statusLabel_->setText(
        ks::i18n::sourceText(QStringLiteral("正在移除策略...")));
    QPointer<KvmMsrPolicyDialog> safeThis(this);
    std::thread([safeThis, kPolicyId]() {
        const ksword::kvm::KvmMsrPolicyResult kResult =
            ksword::kvm::removeMsrPolicy(kPolicyId);
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
                safeThis->refreshPolicies();
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmMsrPolicyDialog::startClear()
{
    setBusy(true);
    statusLabel_->setText(
        ks::i18n::sourceText(QStringLiteral("正在移除全部策略...")));
    QPointer<KvmMsrPolicyDialog> safeThis(this);
    std::thread([safeThis]() {
        const ksword::kvm::KvmMsrPolicyResult kResult =
            ksword::kvm::clearMsrPolicies();
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
                safeThis->refreshPolicies();
            },
            Qt::QueuedConnection);
    }).detach();
}
