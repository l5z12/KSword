#include "KvmViewDialog.h"

#include "KvmControl.h"
#include "../internationalization/LanguageManager.h"

#include <QComboBox>
#include <QFontDatabase>
#include <QFormLayout>
#include <QGridLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QTableWidget>
#include <QVBoxLayout>

#include <thread>

namespace
{
    // A shadow page is exactly one page; explicit content must fill it completely.
    constexpr int kShadowPageBytes =
        static_cast<int>(KSWORD_ARK_HVM_VIEW_PAGE_BYTES);

    // parseHexPage: Parses hexadecimal text into bytes not exceeding one page, padding with zeros on the right to a full page.
    bool parseHexPage(const QString& text, QByteArray* pageOut)
    {
        QString compact;
        compact.reserve(text.size());
        for (const QChar kCharacter : text)
        {
            if (kCharacter.isSpace())
            {
                continue;
            }
            if (!isxdigit(kCharacter.toLatin1()))
            {
                return false;
            }
            compact.append(kCharacter);
        }
        if (compact.isEmpty() || (compact.size() % 2) != 0)
        {
            return false;
        }
        if (compact.size() / 2 > kShadowPageBytes)
        {
            return false;
        }
        QByteArray bytes;
        bytes.reserve(compact.size() / 2);
        for (int index = 0; index < compact.size(); index += 2)
        {
            bool converted = false;
            const unsigned int kValue =
                compact.mid(index, 2).toUInt(&converted, 16);
            if (!converted)
            {
                return false;
            }
            bytes.append(static_cast<char>(kValue & 0xFFu));
        }
        // The driver copies data in full pages; pad the remainder with zeros instead of allowing reads of uninitialized data.
        bytes.append(kShadowPageBytes - bytes.size(), '\0');
        *pageOut = bytes;
        return true;
    }

    // describeKind: Translate the view type into a sentence.
    QString describeKind(const unsigned long kind)
    {
        return kind == KSWORD_ARK_HVM_VIEW_KIND_CLOAK
            ? ks::i18n::sourceText(QStringLiteral("隐藏：执行走真实页，读写走影子"))
            : ks::i18n::sourceText(QStringLiteral("Hook：读写走真实页，执行走影子"));
    }
}

KvmViewDialog::KvmViewDialog(QWidget* const parent)
    : QDialog(parent)
{
    setWindowTitle(ks::i18n::sourceText(QStringLiteral("KVM EPT 分离视图")));
    setObjectName(QStringLiteral("KvmViewDialog"));
    buildUi();
    updateEnabledState();
    refreshViews();
}

void KvmViewDialog::buildUi()
{
    QVBoxLayout* const kRootLayout = new QVBoxLayout(this);

    QLabel* const kHintLabel = new QLabel(
        ks::i18n::sourceText(QStringLiteral(
            "视图靠翻转共享 EPT 叶项实现，只能在单处理器拓扑且未常驻时安装或移除。")),
        this);
    kHintLabel->setWordWrap(true);
    kRootLayout->addWidget(kHintLabel);

    QFormLayout* const kFormLayout = new QFormLayout();
    kindBox_ = new QComboBox(this);
    kindBox_->addItem(
        ks::i18n::sourceText(QStringLiteral("隐藏（读写看影子）")),
        static_cast<unsigned int>(KSWORD_ARK_HVM_VIEW_KIND_CLOAK));
    kindBox_->addItem(
        ks::i18n::sourceText(QStringLiteral("Hook（执行看影子）")),
        static_cast<unsigned int>(KSWORD_ARK_HVM_VIEW_KIND_HOOK));
    kFormLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("视图类型")),
        kindBox_);

    addressEdit_ = new QLineEdit(this);
    addressEdit_->setPlaceholderText(QStringLiteral("0x1000"));
    kFormLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("目标物理页（十六进制，页对齐）")),
        addressEdit_);

    seedBox_ = new QComboBox(this);
    seedBox_->addItem(
        ks::i18n::sourceText(QStringLiteral("影子填零")), 0);
    seedBox_->addItem(
        ks::i18n::sourceText(QStringLiteral("冻结目标页当前内容")), 1);
    seedBox_->addItem(
        ks::i18n::sourceText(QStringLiteral("使用下方十六进制内容")), 2);
    kFormLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("影子来源")),
        seedBox_);
    kRootLayout->addLayout(kFormLayout);

    shadowEdit_ = new QPlainTextEdit(this);
    shadowEdit_->setFont(
        QFontDatabase::systemFont(QFontDatabase::FixedFont));
    shadowEdit_->setPlaceholderText(
        ks::i18n::sourceText(QStringLiteral(
            "影子页内容，十六进制字节；不足一页的部分自动补零")));
    shadowEdit_->setMaximumHeight(110);
    kRootLayout->addWidget(shadowEdit_);

    viewTable_ = new QTableWidget(0, 5, this);
    viewTable_->setHorizontalHeaderLabels(QStringList()
        << ks::i18n::sourceText(QStringLiteral("编号"))
        << ks::i18n::sourceText(QStringLiteral("类型"))
        << ks::i18n::sourceText(QStringLiteral("目标物理页"))
        << ks::i18n::sourceText(QStringLiteral("影子物理页"))
        << ks::i18n::sourceText(QStringLiteral("翻转次数")));
    viewTable_->horizontalHeader()->setStretchLastSection(true);
    viewTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    viewTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    viewTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    kRootLayout->addWidget(viewTable_, 1);

    QGridLayout* const kButtonLayout = new QGridLayout();
    addButton_ = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("安装视图")), this);
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
        refreshViews();
    });
    resize(720, 520);
}

void KvmViewDialog::updateEnabledState()
{
    const bool kWriteAllowed = ksword::kvm::isWriteAccessEnabled();
    const QString kWriteHint = kWriteAllowed
        ? QString()
        : ks::i18n::sourceText(QStringLiteral(
            "R-1 写权限未开启：在 KVM 按钮右键菜单中开启后才能安装或移除视图"));
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
}

void KvmViewDialog::setBusy(const bool busy)
{
    busy_ = busy;
    updateEnabledState();
}

void KvmViewDialog::refreshViews()
{
    if (busy_)
    {
        return;
    }
    setBusy(true);
    QPointer<KvmViewDialog> safeThis(this);
    std::thread([safeThis]() {
        const ksword::kvm::KvmViewResult kResult = ksword::kvm::listViews();
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
                QTableWidget* const kTable = safeThis->viewTable_;
                kTable->setRowCount(kResult.views.size());
                for (int row = 0; row < kResult.views.size(); ++row)
                {
                    const auto& entry = kResult.views.at(row);
                    kTable->setItem(row, 0, new QTableWidgetItem(
                        QString::number(entry.viewId)));
                    kTable->setItem(row, 1, new QTableWidgetItem(
                        describeKind(entry.kind)));
                    kTable->setItem(row, 2, new QTableWidgetItem(
                        QStringLiteral("0x%1")
                            .arg(entry.physicalAddress, 0, 16)));
                    kTable->setItem(row, 3, new QTableWidgetItem(
                        QStringLiteral("0x%1")
                            .arg(entry.shadowPhysicalAddress, 0, 16)));
                    kTable->setItem(row, 4, new QTableWidgetItem(
                        QString::number(entry.flipCount)));
                }
                safeThis->statusLabel_->setText(
                    ks::i18n::sourceText(QStringLiteral("已安装 %1 条视图。"))
                        .arg(kResult.viewCount));
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmViewDialog::startAdd()
{
    QString addressText = addressEdit_->text().trimmed();
    if (addressText.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
    {
        addressText = addressText.mid(2);
    }
    bool converted = false;
    const unsigned long long kAddress =
        addressText.toULongLong(&converted, 16);
    if (!converted)
    {
        statusLabel_->setText(ks::i18n::sourceText(
            QStringLiteral("目标物理页不是合法的十六进制数。")));
        return;
    }

    const unsigned long kKind =
        kindBox_->currentData().toUInt();
    const int kSeedIndex = seedBox_->currentIndex();
    ksword::kvm::KvmViewShadowSeed seed =
        ksword::kvm::KvmViewShadowSeed::kZero;
    QByteArray shadow;
    if (kSeedIndex == 1)
    {
        seed = ksword::kvm::KvmViewShadowSeed::kFromTarget;
    }
    else if (kSeedIndex == 2)
    {
        seed = ksword::kvm::KvmViewShadowSeed::kExplicit;
        if (!parseHexPage(shadowEdit_->toPlainText(), &shadow))
        {
            statusLabel_->setText(ks::i18n::sourceText(QStringLiteral(
                "影子内容必须是成对的十六进制字节，且不超过一页。")));
            return;
        }
    }

    setBusy(true);
    statusLabel_->setText(
        ks::i18n::sourceText(QStringLiteral("正在安装视图...")));
    QPointer<KvmViewDialog> safeThis(this);
    std::thread([safeThis, kKind, kAddress, seed, shadow]() {
        const ksword::kvm::KvmViewResult kResult =
            ksword::kvm::addView(kKind, kAddress, seed, shadow);
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
                        QStringLiteral("已安装视图，编号 %1。"))
                        .arg(kResult.viewId)
                    : kResult.message);
                safeThis->refreshViews();
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmViewDialog::startRemove()
{
    const int kRow = viewTable_->currentRow();
    if (kRow < 0 || viewTable_->item(kRow, 0) == nullptr)
    {
        statusLabel_->setText(
            ks::i18n::sourceText(QStringLiteral("请先在表中选择一条视图。")));
        return;
    }
    const unsigned long kViewId =
        viewTable_->item(kRow, 0)->text().toULong();

    setBusy(true);
    statusLabel_->setText(
        ks::i18n::sourceText(QStringLiteral("正在移除视图...")));
    QPointer<KvmViewDialog> safeThis(this);
    std::thread([safeThis, kViewId]() {
        const ksword::kvm::KvmViewResult kResult =
            ksword::kvm::removeView(kViewId);
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
                safeThis->refreshViews();
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmViewDialog::startClear()
{
    setBusy(true);
    statusLabel_->setText(
        ks::i18n::sourceText(QStringLiteral("正在移除全部视图...")));
    QPointer<KvmViewDialog> safeThis(this);
    std::thread([safeThis]() {
        const ksword::kvm::KvmViewResult kResult = ksword::kvm::clearViews();
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
                safeThis->refreshViews();
            },
            Qt::QueuedConnection);
    }).detach();
}
