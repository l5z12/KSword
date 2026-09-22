#include "KvmWatchDialog.h"

#include "KvmControl.h"
#include "../internationalization/LanguageManager.h"
#include "../Theme.h"

#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QGridLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QVBoxLayout>

#include <thread>

namespace
{
    QString text(const QString& source)
    {
        return ks::i18n::sourceText(source);
    }

    /* Parses hexadecimal values with an optional 0x prefix. */
    bool parseHex(const QString& input, unsigned long long* valueOut)
    {
        QString compact = input.trimmed();
        if (compact.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
        {
            compact = compact.mid(2);
        }
        // Allows backticks as separators: both the debugger and this program use them to
        // display 64-bit addresses, and addresses copied from elsewhere often include them.
        compact.remove(QLatin1Char('`'));
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

KvmWatchAddDialog::KvmWatchAddDialog(QWidget* const parent)
    : QDialog(parent)
{
    setWindowTitle(text(QStringLiteral("添加内存监视")));
    setObjectName(QStringLiteral("KvmWatchAddDialog"));
    auto* const kRootLayout = new QVBoxLayout(this);

    targetLabel_ = new QLabel(this);
    targetLabel_->setWordWrap(true);
    targetLabel_->setVisible(false);
    targetLabel_->setStyleSheet(QStringLiteral("font-weight:600;"));
    kRootLayout->addWidget(targetLabel_);

    auto* const kForm = new QFormLayout();
    addressKind_ = new QComboBox(this);
    addressKind_->addItem(text(QStringLiteral("内核虚拟地址")), true);
    addressKind_->addItem(text(QStringLiteral("物理地址")), false);
    kForm->addRow(text(QStringLiteral("地址类型")), addressKind_);

    address_ = new QLineEdit(this);
    address_->setPlaceholderText(QStringLiteral("FFFFF80112345678"));
    kForm->addRow(text(QStringLiteral("地址（十六进制）")), address_);

    length_ = new QLineEdit(this);
    length_->setPlaceholderText(QStringLiteral("8"));
    length_->setToolTip(text(QStringLiteral("你真正关心的字节数。它不改变硬件监视的范围（那永远是整页），只决定命中后能不能判断这次访问落在你关心的那几个字节上。留空表示整页。")));
    kForm->addRow(text(QStringLiteral("关心的长度（十进制字节）")), length_);
    kRootLayout->addLayout(kForm);

    auto* const kAccessRow = new QGridLayout();
    read_ = new QCheckBox(text(QStringLiteral("读")), this);
    write_ = new QCheckBox(text(QStringLiteral("写")), this);
    execute_ = new QCheckBox(text(QStringLiteral("执行")), this);
    write_->setChecked(true);
    kAccessRow->addWidget(
        new QLabel(text(QStringLiteral("监视的访问类型")), this), 0, 0);
    kAccessRow->addWidget(read_, 0, 1);
    kAccessRow->addWidget(write_, 0, 2);
    kAccessRow->addWidget(execute_, 0, 3);
    kRootLayout->addLayout(kAccessRow);

    kRootLayout->addWidget(new QLabel(
        text(QStringLiteral("模式：首次访问（当前唯一支持）")), this));

    granularity_ = new QLabel(this);
    granularity_->setWordWrap(true);
    granularity_->setStyleSheet(
        QStringLiteral("color:%1;").arg(ksword_theme::textSecondaryHex()));
    kRootLayout->addWidget(granularity_);

    auto* const kButtons = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    kButtons->button(QDialogButtonBox::Ok)->setText(text(QStringLiteral("武装")));
    kRootLayout->addWidget(kButtons);
    connect(kButtons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(kButtons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    connect(length_, &QLineEdit::textChanged, this, [this](const QString&) {
        updateGranularity();
    });
    connect(read_, &QCheckBox::toggled, this, [this](bool) {
        updateGranularity();
    });
    updateGranularity();
    resize(560, 360);
}

void KvmWatchAddDialog::prefill(const ks::ui::HvmWatchRequest& request)
{
    addressKind_->setCurrentIndex(request.virtualAddress ? 0 : 1);
    address_->setText(QStringLiteral("%1")
        .arg(request.address, 16, 16, QLatin1Char('0')).toUpper());
    if (request.length != 0)
    {
        length_->setText(QString::number(request.length));
    }
    read_->setChecked(
        (request.access & KSWORD_ARK_HVM_EPT_ACCESS_READ) != 0UL);
    write_->setChecked(
        (request.access & KSWORD_ARK_HVM_EPT_ACCESS_WRITE) != 0UL);
    execute_->setChecked(
        (request.access & KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE) != 0UL);
    if (!request.label.isEmpty())
    {
        targetLabel_->setText(
            text(QStringLiteral("正在监视：%1")).arg(request.label));
        targetLabel_->setVisible(true);
        /*
         * Address field is read-only.
         *
         * The caller has already calculated "where this item is", and the line above describes exactly that target.
         * Allowing users to edit the address here would cause the on-screen description to mismatch
         * the actual monitored content, causing every piece of evidence to be attached to an incorrect
         * title. To monitor a different address, manually add it from the Memory Monitor page.
         */
        address_->setReadOnly(true);
        addressKind_->setEnabled(false);
    }
    updateGranularity();
}

void KvmWatchAddDialog::updateGranularity()
{
    bool converted = false;
    const unsigned long long kLength =
        length_->text().trimmed().toULongLong(&converted, 10);
    const unsigned long long kRequested =
        converted && kLength != 0ULL ? kLength : 4096ULL;
    QString note = text(QStringLiteral("EPT 的监视单位是页：你请求 %1 字节，实际装到硬件上的是它所在的整个 4096 字节页。命中后如果 CPU 报告了有效的客户线性地址，界面会另外告诉你这次访问是否落在你请求的那一段里。"))
        .arg(kRequested);
    if (read_->isChecked())
    {
        // This message must appear when "Read" is checked, not discovered later in the table after installation:
        // At this point, the user decides whether to accept monitoring writes as well.
        note += QLatin1Char('\n');
        note += text(QStringLiteral("已勾选“读”：EPT 不允许可写而不可读，所以实际生效的监视一定同时包含写；处理器不支持仅执行叶项时还会连带包含执行。表格里的“实际访问”一栏显示归一化后的结果。"));
    }
    granularity_->setText(note);
}

ksword::kvm::KvmWatchTarget KvmWatchAddDialog::target() const
{
    ksword::kvm::KvmWatchTarget result;
    result.virtualAddress = addressKind_->currentData().toBool();
    unsigned long long address = 0;
    if (parseHex(address_->text(), &address))
    {
        result.address = address;
    }
    bool converted = false;
    const unsigned long long kLength =
        length_->text().trimmed().toULongLong(&converted, 10);
    result.length = converted ? kLength : 0ULL;
    result.access =
        (read_->isChecked() ? KSWORD_ARK_HVM_EPT_ACCESS_READ : 0UL) |
        (write_->isChecked() ? KSWORD_ARK_HVM_EPT_ACCESS_WRITE : 0UL) |
        (execute_->isChecked() ? KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE : 0UL);
    return result;
}

bool KvmWatchAddDialog::addressValid() const
{
    unsigned long long address = 0;
    return parseHex(address_->text(), &address) && address != 0;
}

namespace ks::ui
{
    void openHvmWatch(QWidget* const parent, const HvmWatchRequest& request)
    {
        /*
         * Write access gate is checked first.
         *
         * It is an in-process switch that can be checked without sending any IOCTL, and it is the most common
         * reason for rejection. Checking it first prevents users from filling out a form only to be rejected.
         */
        if (!ksword::kvm::isWriteAccessEnabled())
        {
            QMessageBox::warning(
                parent,
                text(QStringLiteral("添加内存监视")),
                text(QStringLiteral("R-1 写权限未开启：请先在标题栏 KVM 按钮的右键菜单里打开它，再安装内存监视。")));
            return;
        }
        KvmWatchAddDialog dialog(parent);
        dialog.prefill(request);
        if (dialog.exec() != QDialog::Accepted)
        {
            return;
        }
        if (!dialog.addressValid())
        {
            QMessageBox::warning(
                parent,
                text(QStringLiteral("添加内存监视")),
                text(QStringLiteral("地址不是合法的非零十六进制数。")));
            return;
        }
        const ksword::kvm::KvmWatchTarget kWatchTarget = dialog.target();
        if (kWatchTarget.access == 0UL)
        {
            QMessageBox::warning(
                parent,
                text(QStringLiteral("添加内存监视")),
                text(QStringLiteral("请至少选择一种要监视的访问类型。")));
            return;
        }
        /*
         * Installation is a blocking IOCTL; must leave the UI thread.
         *
         * QPointer guards parent: During installation, the user can close the page entirely.
         * Sending a message box to a destroyed window when the result returns causes a crash.
         */
        QPointer<QWidget> safeParent(parent);
        const QString kLabel = request.label;
        std::thread([safeParent, kWatchTarget, kLabel]() {
            const ksword::kvm::KvmWatchResult kResult =
                ksword::kvm::addWatch(kWatchTarget);
            QMetaObject::invokeMethod(
                qApp,
                [safeParent, kResult, kLabel]() {
                    const QString kTitle =
                        text(QStringLiteral("添加内存监视"));
                    // On success, clearly explain what happens next: this does not take effect immediately,
                    // and the user's most likely next action is to start the resident process.
                    const QString kBody = kResult.ok
                        ? text(QStringLiteral("已为 %1 安装内存监视。\n\n监视在启动常驻之后才开始生效；命中一次后会自动解除，届时可在“虚拟化 (KVM) → 内存监视”页查看现场并重新武装。"))
                            .arg(kLabel.isEmpty()
                                ? text(QStringLiteral("该目标"))
                                : kLabel)
                        : kResult.message;
                    if (safeParent != nullptr)
                    {
                        kResult.ok
                            ? QMessageBox::information(safeParent, kTitle, kBody)
                            : QMessageBox::warning(safeParent, kTitle, kBody);
                    }
                },
                Qt::QueuedConnection);
        }).detach();
    }
}
