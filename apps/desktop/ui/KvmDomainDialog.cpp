#include "KvmDomainDialog.h"

#include "KvmControl.h"
#include "../internationalization/LanguageManager.h"

#include <QCheckBox>
#include <QFormLayout>
#include <QGridLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPointer>
#include <QPushButton>
#include <QTableWidget>
#include <QVBoxLayout>

#include <thread>

namespace
{
    // parseHex: Parse hexadecimal number optionally prefixed with 0x.
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

KvmDomainDialog::KvmDomainDialog(QWidget* const parent)
    : QDialog(parent)
{
    setWindowTitle(ks::i18n::sourceText(QStringLiteral("KVM EPT 执行域")));
    setObjectName(QStringLiteral("KvmDomainDialog"));
    buildUi();
    updateEnabledState();
    refreshDomains();
}

void KvmDomainDialog::buildUi()
{
    QVBoxLayout* const kRootLayout = new QVBoxLayout(this);

    QLabel* const kHintLabel = new QLabel(
        ks::i18n::sourceText(QStringLiteral("域发布在 EPTP list 里，guest 用一条 VMFUNC 就能切过去，而 VMFUNC 不做 CPL 检查。所以这里只能给域【拿掉】权限，不能给权限：域建出来时与默认视图完全一致，切进去的线程拿不到它原本没有的访问权。")),
        this);
    kHintLabel->setWordWrap(true);
    kRootLayout->addWidget(kHintLabel);

    QLabel* const kArmLabel = new QLabel(
        ks::i18n::sourceText(QStringLiteral("建域本身不改变任何行为。要让 VMFUNC 真的能切，还得用带「武装 VMFUNC」的常驻启动。")),
        this);
    kArmLabel->setWordWrap(true);
    kRootLayout->addWidget(kArmLabel);

    domainTable_ = new QTableWidget(0, 4, this);
    domainTable_->setHorizontalHeaderLabels(QStringList()
        << ks::i18n::sourceText(QStringLiteral("槽位"))
        << ks::i18n::sourceText(QStringLiteral("状态"))
        << ks::i18n::sourceText(QStringLiteral("已分叉页表"))
        << ks::i18n::sourceText(QStringLiteral("EPT 指针")));
    domainTable_->horizontalHeader()->setStretchLastSection(true);
    domainTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    domainTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    domainTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    kRootLayout->addWidget(domainTable_, 1);

    QFormLayout* const kFormLayout = new QFormLayout();
    domainEdit_ = new QLineEdit(this);
    domainEdit_->setPlaceholderText(QStringLiteral("1"));
    kFormLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("目标域槽位（十进制，0 号是默认视图）")),
        domainEdit_);

    addressEdit_ = new QLineEdit(this);
    addressEdit_->setPlaceholderText(QStringLiteral("0x100000"));
    kFormLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("物理起始地址（十六进制）")),
        addressEdit_);

    lengthEdit_ = new QLineEdit(this);
    lengthEdit_->setPlaceholderText(QStringLiteral("0x200000"));
    kFormLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("长度（十六进制，按 2MiB 叶项向外取整）")),
        lengthEdit_);
    kRootLayout->addLayout(kFormLayout);

    QHBoxLayout* const kDenyLayout = new QHBoxLayout();
    QLabel* const kDenyLabel = new QLabel(
        ks::i18n::sourceText(QStringLiteral("拿掉的权限")),
        this);
    denyReadBox_ = new QCheckBox(
        ks::i18n::sourceText(QStringLiteral("读")), this);
    denyReadBox_->setToolTip(ks::i18n::sourceText(QStringLiteral("拿掉读权限需要处理器支持仅执行的 EPT 叶项，否则驱动会拒绝——那样的叶项会让 VM entry 直接失败。")));
    denyWriteBox_ = new QCheckBox(
        ks::i18n::sourceText(QStringLiteral("写")), this);
    denyExecuteBox_ = new QCheckBox(
        ks::i18n::sourceText(QStringLiteral("执行")), this);
    kDenyLayout->addWidget(kDenyLabel);
    kDenyLayout->addWidget(denyReadBox_);
    kDenyLayout->addWidget(denyWriteBox_);
    kDenyLayout->addWidget(denyExecuteBox_);
    kDenyLayout->addStretch(1);
    kRootLayout->addLayout(kDenyLayout);

    QGridLayout* const kButtonLayout = new QGridLayout();
    createButton_ = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("新建域")), this);
    createButton_->setToolTip(ks::i18n::sourceText(QStringLiteral("分叉一份与默认视图完全一致的域。只花一页，因为下层页表全部共享。")));
    restrictButton_ = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("收紧权限")), this);
    resetButton_ = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("清空全部域")), this);
    refreshButton_ = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("刷新")), this);
    kButtonLayout->addWidget(createButton_, 0, 0);
    kButtonLayout->addWidget(restrictButton_, 0, 1);
    kButtonLayout->addWidget(resetButton_, 0, 2);
    kButtonLayout->addWidget(refreshButton_, 0, 3);
    kRootLayout->addLayout(kButtonLayout);

    statusLabel_ = new QLabel(QString(), this);
    statusLabel_->setWordWrap(true);
    kRootLayout->addWidget(statusLabel_);

    connect(createButton_, &QPushButton::clicked, this, [this]() {
        startCreate();
    });
    connect(restrictButton_, &QPushButton::clicked, this, [this]() {
        startRestrict();
    });
    connect(resetButton_, &QPushButton::clicked, this, [this]() {
        startReset();
    });
    connect(refreshButton_, &QPushButton::clicked, this, [this]() {
        refreshDomains();
    });
    // When a row is selected, populate the input fields with the slot data to avoid manual entry.
    connect(domainTable_, &QTableWidget::itemSelectionChanged, this, [this]() {
        const auto kSelected = domainTable_->selectedItems();
        if (kSelected.isEmpty())
        {
            return;
        }
        const int kRow = kSelected.first()->row();
        QTableWidgetItem* const kItem = domainTable_->item(kRow, 0);
        if (kItem != nullptr)
        {
            domainEdit_->setText(kItem->text());
        }
    });
    resize(720, 540);
}

void KvmDomainDialog::updateEnabledState()
{
    const bool kWriteAllowed = ksword::kvm::isWriteAccessEnabled();
    const QString kWriteHint = kWriteAllowed
        ? QString()
        : ks::i18n::sourceText(QStringLiteral("R-1 写权限未开启：在 KVM 按钮右键菜单中开启后才能建域或收紧权限"));
    if (createButton_ != nullptr)
    {
        createButton_->setEnabled(kWriteAllowed && !busy_);
        if (!kWriteAllowed)
        {
            createButton_->setToolTip(kWriteHint);
        }
    }
    if (restrictButton_ != nullptr)
    {
        restrictButton_->setEnabled(kWriteAllowed && !busy_);
        restrictButton_->setToolTip(kWriteHint);
    }
    if (resetButton_ != nullptr)
    {
        resetButton_->setEnabled(kWriteAllowed && !busy_);
        resetButton_->setToolTip(kWriteHint);
    }
    if (refreshButton_ != nullptr)
    {
        refreshButton_->setEnabled(!busy_);
    }
}

void KvmDomainDialog::setBusy(const bool busy)
{
    busy_ = busy;
    updateEnabledState();
}

void KvmDomainDialog::refreshDomains()
{
    if (busy_)
    {
        return;
    }
    setBusy(true);
    QPointer<KvmDomainDialog> safeThis(this);
    std::thread([safeThis]() {
        const ksword::kvm::KvmDomainResult kResult =
            ksword::kvm::listDomains();
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
                QTableWidget* const kTable = safeThis->domainTable_;
                kTable->setRowCount(kResult.domains.size());
                for (int row = 0; row < kResult.domains.size(); ++row)
                {
                    const auto& entry = kResult.domains.at(row);
                    kTable->setItem(row, 0, new QTableWidgetItem(
                        QString::number(entry.domainIndex)));
                    // Slot 0 is always the default view; mark it to avoid treating it as a collapsible replica.
                    const QString kState = entry.domainIndex == 0
                        ? ks::i18n::sourceText(QStringLiteral("默认视图"))
                        : (entry.active
                            ? ks::i18n::sourceText(QStringLiteral("已建立"))
                            : ks::i18n::sourceText(QStringLiteral("空闲")));
                    kTable->setItem(row, 1, new QTableWidgetItem(kState));
                    kTable->setItem(row, 2, new QTableWidgetItem(
                        QString::number(entry.privateTableCount)));
                    kTable->setItem(row, 3, new QTableWidgetItem(
                        entry.eptPointer == 0
                            ? QStringLiteral("-")
                            : QStringLiteral("0x%1")
                                .arg(entry.eptPointer, 0, 16)));
                }
                safeThis->statusLabel_->setText(
                    ks::i18n::sourceText(QStringLiteral("当前有 %1 个域（含默认视图）。"))
                        .arg(kResult.domainCount));
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmDomainDialog::startCreate()
{
    if (busy_)
    {
        return;
    }
    setBusy(true);
    QPointer<KvmDomainDialog> safeThis(this);
    std::thread([safeThis]() {
        const ksword::kvm::KvmDomainResult kResult =
            ksword::kvm::createDomain();
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
                    ? ks::i18n::sourceText(QStringLiteral("已建立 %1 号域，内容与默认视图一致。"))
                        .arg(kResult.domainIndex)
                    : kResult.message);
                safeThis->refreshDomains();
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmDomainDialog::startRestrict()
{
    if (busy_)
    {
        return;
    }
    bool converted = false;
    const unsigned long kDomainIndex =
        domainEdit_->text().trimmed().toULong(&converted, 10);
    if (!converted)
    {
        statusLabel_->setText(ks::i18n::sourceText(
            QStringLiteral("目标域槽位不是合法的十进制数。")));
        return;
    }
    unsigned long long address = 0;
    if (!parseHex(addressEdit_->text(), &address))
    {
        statusLabel_->setText(ks::i18n::sourceText(
            QStringLiteral("物理起始地址不是合法的十六进制数。")));
        return;
    }
    unsigned long long length = 0;
    if (!parseHex(lengthEdit_->text(), &length) || length == 0)
    {
        statusLabel_->setText(ks::i18n::sourceText(
            QStringLiteral("长度不是合法的非零十六进制数。")));
        return;
    }
    unsigned long denied = 0;
    if (denyReadBox_->isChecked())
    {
        denied |= KSWORD_ARK_HVM_EPT_ACCESS_READ;
    }
    if (denyWriteBox_->isChecked())
    {
        denied |= KSWORD_ARK_HVM_EPT_ACCESS_WRITE;
    }
    if (denyExecuteBox_->isChecked())
    {
        denied |= KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE;
    }
    if (denied == 0)
    {
        statusLabel_->setText(ks::i18n::sourceText(
            QStringLiteral("至少要勾选一项要拿掉的权限。")));
        return;
    }

    setBusy(true);
    QPointer<KvmDomainDialog> safeThis(this);
    std::thread([safeThis, kDomainIndex, address, length, denied]() {
        const ksword::kvm::KvmDomainResult kResult =
            ksword::kvm::restrictDomain(
                kDomainIndex,
                address,
                length,
                denied);
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
                safeThis->refreshDomains();
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmDomainDialog::startReset()
{
    if (busy_)
    {
        return;
    }
    setBusy(true);
    QPointer<KvmDomainDialog> safeThis(this);
    std::thread([safeThis]() {
        const ksword::kvm::KvmDomainResult kResult =
            ksword::kvm::resetDomains();
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
                safeThis->refreshDomains();
            },
            Qt::QueuedConnection);
    }).detach();
}
