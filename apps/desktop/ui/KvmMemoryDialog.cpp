#include "KvmMemoryDialog.h"

#include "KvmControl.h"
#include "../framework/DestructiveActionConfirmation.h"
#include "../internationalization/LanguageManager.h"

#include <QComboBox>
#include <QFontDatabase>
#include <QFormLayout>
#include <QGridLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QSpinBox>
#include <QVBoxLayout>

#include <thread>

namespace
{
    // The byte limit for a single transfer is determined by the driver protocol; the UI cannot offer a larger option.
    constexpr int kMaxTransferBytes =
        static_cast<int>(KSWORD_ARK_HVM_MEMORY_MAX_BYTES);
    // Number of bytes displayed per line in the hex view.
    constexpr int kHexBytesPerLine = 16;

    // parseHexBytes: Parse "41 42 43" or "414243" into a byte sequence.
    // Returns false if illegal characters are present or the number of hexadecimal digits is odd.
    bool parseHexBytes(const QString& text, QByteArray* bytesOut)
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
        bytesOut->clear();
        bytesOut->reserve(compact.size() / 2);
        for (int index = 0; index < compact.size(); index += 2)
        {
            bool converted = false;
            const unsigned int kValue =
                compact.mid(index, 2).toUInt(&converted, 16);
            if (!converted)
            {
                return false;
            }
            bytesOut->append(static_cast<char>(kValue & 0xFFu));
        }
        return true;
    }
}

KvmMemoryDialog::KvmMemoryDialog(QWidget* const parent)
    : QDialog(parent)
{
    setWindowTitle(ks::i18n::sourceText(QStringLiteral("KVM R-1 内存操作")));
    setObjectName(QStringLiteral("KvmMemoryDialog"));
    // The dialog's appearance is uniformly managed by the global style installed by installGlobalDialogTheme;
    // no separate styles are set here to avoid desynchronization with theme switching.
    buildUi();
    updateEnabledState();

    // Query the window status immediately on opening; this panel's value depends on whether it can operate without Mm*.
    QPointer<KvmMemoryDialog> safeThis(this);
    std::thread([safeThis]() {
        const ksword::kvm::KvmMemoryResult kResult =
            ksword::kvm::queryMemoryWindow();
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, kResult]() {
                if (safeThis == nullptr || safeThis->windowLabel_ == nullptr)
                {
                    return;
                }
                safeThis->windowLabel_->setText(kResult.windowReady
                    ? ks::i18n::sourceText(QStringLiteral(
                        "私有页表窗口：可用（读写均绕开内存管理器导出例程）"))
                    : ks::i18n::sourceText(QStringLiteral(
                        "私有页表窗口：不可用（读退化为 MmCopyMemory，写不可用）")));
            },
            Qt::QueuedConnection);
    }).detach();
}

bool KvmMemoryDialog::isVirtualMode() const
{
    return modeBox_ != nullptr && modeBox_->currentIndex() == 1;
}

void KvmMemoryDialog::buildUi()
{
    QVBoxLayout* const kRootLayout = new QVBoxLayout(this);

    windowLabel_ = new QLabel(
        ks::i18n::sourceText(QStringLiteral("私有页表窗口：正在查询...")),
        this);
    windowLabel_->setWordWrap(true);
    kRootLayout->addWidget(windowLabel_);

    QFormLayout* const kFormLayout = new QFormLayout();
    modeBox_ = new QComboBox(this);
    modeBox_->addItem(ks::i18n::sourceText(QStringLiteral("物理地址")));
    modeBox_->addItem(ks::i18n::sourceText(QStringLiteral("虚拟地址")));
    kFormLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("地址类型")),
        modeBox_);

    addressEdit_ = new QLineEdit(this);
    addressEdit_->setPlaceholderText(QStringLiteral("0x1000"));
    kFormLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("地址（十六进制）")),
        addressEdit_);

    directoryBaseEdit_ = new QLineEdit(this);
    directoryBaseEdit_->setPlaceholderText(
        ks::i18n::sourceText(QStringLiteral("留空表示当前进程页表")));
    kFormLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("页目录基址（CR3）")),
        directoryBaseEdit_);

    lengthBox_ = new QSpinBox(this);
    lengthBox_->setRange(1, kMaxTransferBytes);
    lengthBox_->setValue(64);
    kFormLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("读取长度（字节）")),
        lengthBox_);

    writeEdit_ = new QLineEdit(this);
    writeEdit_->setPlaceholderText(
        ks::i18n::sourceText(QStringLiteral("要写入的十六进制字节，例如 90 90 90")));
    kFormLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("写入内容")),
        writeEdit_);
    kRootLayout->addLayout(kFormLayout);

    dataView_ = new QPlainTextEdit(this);
    dataView_->setReadOnly(true);
    dataView_->setFont(
        QFontDatabase::systemFont(QFontDatabase::FixedFont));
    dataView_->setMinimumHeight(220);
    kRootLayout->addWidget(dataView_, 1);

    QGridLayout* const kButtonLayout = new QGridLayout();
    readButton_ = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("读取")), this);
    writeButton_ = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("写入")), this);
    translateButton_ = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("翻译为物理地址")), this);
    kButtonLayout->addWidget(readButton_, 0, 0);
    kButtonLayout->addWidget(writeButton_, 0, 1);
    kButtonLayout->addWidget(translateButton_, 0, 2);
    kRootLayout->addLayout(kButtonLayout);

    statusLabel_ = new QLabel(QString(), this);
    statusLabel_->setWordWrap(true);
    kRootLayout->addWidget(statusLabel_);

    connect(modeBox_, &QComboBox::currentIndexChanged, this, [this](int) {
        updateEnabledState();
    });
    connect(readButton_, &QPushButton::clicked, this, [this]() {
        startRead();
    });
    connect(writeButton_, &QPushButton::clicked, this, [this]() {
        startWrite();
    });
    connect(translateButton_, &QPushButton::clicked, this, [this]() {
        startTranslate();
    });
    resize(640, 520);
}

void KvmMemoryDialog::updateEnabledState()
{
    const bool kVirtualMode = isVirtualMode();
    const bool kWriteAllowed = ksword::kvm::isWriteAccessEnabled();
    if (directoryBaseEdit_ != nullptr)
    {
        // Page directory base is only meaningful in virtual address mode.
        directoryBaseEdit_->setEnabled(kVirtualMode && !busy_);
    }
    if (translateButton_ != nullptr)
    {
        translateButton_->setEnabled(kVirtualMode && !busy_);
    }
    if (readButton_ != nullptr)
    {
        readButton_->setEnabled(!busy_);
    }
    if (writeButton_ != nullptr)
    {
        writeButton_->setEnabled(kWriteAllowed && !busy_);
        writeButton_->setToolTip(kWriteAllowed
            ? ks::i18n::sourceText(QStringLiteral("按十六进制字节写入目标地址"))
            : ks::i18n::sourceText(QStringLiteral(
                "R-1 写权限未开启：在 KVM 按钮右键菜单中开启后才能写入")));
    }
    if (writeEdit_ != nullptr)
    {
        writeEdit_->setEnabled(kWriteAllowed && !busy_);
    }
}

void KvmMemoryDialog::setBusy(const bool busy)
{
    busy_ = busy;
    updateEnabledState();
}

bool KvmMemoryDialog::parseAddress(
    const QLineEdit* const field,
    unsigned long long* const valueOut,
    const QString& fieldName)
{
    QString text = field != nullptr ? field->text().trimmed() : QString();
    if (text.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
    {
        text = text.mid(2);
    }
    bool converted = false;
    const unsigned long long kValue = text.toULongLong(&converted, 16);
    if (!converted)
    {
        statusLabel_->setText(
            ks::i18n::sourceText(QStringLiteral("%1 不是合法的十六进制数。"))
                .arg(fieldName));
        return false;
    }
    *valueOut = kValue;
    return true;
}

void KvmMemoryDialog::showHexDump(
    const unsigned long long baseAddress,
    const QByteArray& data)
{
    QStringList lines;
    for (int offset = 0; offset < data.size(); offset += kHexBytesPerLine)
    {
        const int kLineLength =
            qMin(kHexBytesPerLine, data.size() - offset);
        QString hexPart;
        QString asciiPart;
        for (int index = 0; index < kLineLength; ++index)
        {
            const unsigned char kValue =
                static_cast<unsigned char>(data.at(offset + index));
            hexPart += QStringLiteral("%1 ")
                .arg(kValue, 2, 16, QLatin1Char('0')).toUpper();
            // Display all non-printable bytes as dots to prevent control characters from breaking alignment.
            asciiPart += (kValue >= 0x20 && kValue < 0x7F)
                ? QChar(static_cast<char>(kValue))
                : QChar(QLatin1Char('.'));
        }
        lines << QStringLiteral("%1  %2 %3")
            .arg(baseAddress + static_cast<unsigned long long>(offset),
                16, 16, QLatin1Char('0'))
            .arg(hexPart, -(kHexBytesPerLine * 3))
            .arg(asciiPart);
    }
    dataView_->setPlainText(lines.join(QStringLiteral("\n")));
}

void KvmMemoryDialog::startRead()
{
    unsigned long long address = 0;
    if (!parseAddress(addressEdit_, &address,
            ks::i18n::sourceText(QStringLiteral("地址"))))
    {
        return;
    }
    unsigned long long directoryBase = 0;
    const bool kVirtualMode = isVirtualMode();
    if (kVirtualMode && !directoryBaseEdit_->text().trimmed().isEmpty() &&
        !parseAddress(directoryBaseEdit_, &directoryBase,
            ks::i18n::sourceText(QStringLiteral("页目录基址"))))
    {
        return;
    }
    const unsigned long kLength =
        static_cast<unsigned long>(lengthBox_->value());

    setBusy(true);
    statusLabel_->setText(
        ks::i18n::sourceText(QStringLiteral("正在读取...")));
    QPointer<KvmMemoryDialog> safeThis(this);
    std::thread([safeThis, kVirtualMode, address, directoryBase, kLength]() {
        const ksword::kvm::KvmMemoryResult kResult = kVirtualMode
            ? ksword::kvm::readVirtual(directoryBase, address, kLength)
            : ksword::kvm::readPhysical(address, kLength);
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, kResult, address]() {
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
                safeThis->showHexDump(address, kResult.data);
                // Whether the private window path was taken is part of the read's trustworthiness and must be included in the status.
                safeThis->statusLabel_->setText(
                    ks::i18n::sourceText(QStringLiteral(
                        "已读取 %1 字节，物理地址 0x%2，路径：%3"))
                        .arg(kResult.data.size())
                        .arg(kResult.physicalAddress, 0, 16)
                        .arg(kResult.usedDirectWindow
                            ? ks::i18n::sourceText(QStringLiteral("私有页表窗口"))
                            : ks::i18n::sourceText(QStringLiteral("MmCopyMemory 回退"))));
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmMemoryDialog::startWrite()
{
    unsigned long long address = 0;
    if (!parseAddress(addressEdit_, &address,
            ks::i18n::sourceText(QStringLiteral("地址"))))
    {
        return;
    }
    unsigned long long directoryBase = 0;
    const bool kVirtualMode = isVirtualMode();
    if (kVirtualMode && !directoryBaseEdit_->text().trimmed().isEmpty() &&
        !parseAddress(directoryBaseEdit_, &directoryBase,
            ks::i18n::sourceText(QStringLiteral("页目录基址"))))
    {
        return;
    }
    QByteArray payload;
    if (!parseHexBytes(writeEdit_->text(), &payload))
    {
        statusLabel_->setText(ks::i18n::sourceText(
            QStringLiteral("写入内容必须是成对的十六进制字节。")));
        return;
    }
    if (payload.size() > kMaxTransferBytes)
    {
        statusLabel_->setText(
            ks::i18n::sourceText(QStringLiteral("单次写入最多 %1 字节。"))
                .arg(kMaxTransferBytes));
        return;
    }

    // R-1 direct write is the only operation in this module that can instantly corrupt a running system and relies solely on a
    // single global write-permission switch for protection. All six actions in the same batch—startup resident, SOAK, enabling
    // write permissions, arming #VE, arming VMFUNC, and tracking CR3—require separate confirmation, but this one was missed.
    //
    // Target write confirmation text must specify the target rather than just saying 'memory': physical writes and virtual
    // writes have vastly different blast radii, and the user is currently staring at a hexadecimal address they just typed in.
    {
        const QString kTarget = kVirtualMode
            ? ks::i18n::sourceText(QStringLiteral("虚拟地址 0x%1（按页目录 0x%2 解析）"))
                  .arg(address, 0, 16).arg(directoryBase, 0, 16)
            : ks::i18n::sourceText(QStringLiteral("**物理**地址 0x%1"))
                  .arg(address, 0, 16);
        const bool kConfirmed = ks::ui::confirmDestructiveAction(
            this,
            QStringLiteral("KvmMemoryWrite"),
            ks::i18n::sourceText(QStringLiteral("从 R-1 直接写入内存")),
            kTarget,
            ks::i18n::sourceText(QStringLiteral("将写入 %1 字节，绕过页保护、只读段与内核写保护。写错地址不会有任何提示：受害的可能是内核代码、页表或另一个进程的数据，症状往往在很久之后才以看不出关联的方式出现。物理地址写入没有任何归属检查 —— 这个地址属于谁，只有你知道。"))
                .arg(payload.size()));
        if (!kConfirmed)
        {
            return;
        }
    }

    setBusy(true);
    statusLabel_->setText(
        ks::i18n::sourceText(QStringLiteral("正在写入...")));
    QPointer<KvmMemoryDialog> safeThis(this);
    std::thread([safeThis, kVirtualMode, address, directoryBase, payload]() {
        const ksword::kvm::KvmMemoryResult kResult = kVirtualMode
            ? ksword::kvm::writeVirtual(directoryBase, address, payload)
            : ksword::kvm::writePhysical(address, payload);
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, kResult, size = payload.size()]() {
                if (safeThis == nullptr)
                {
                    return;
                }
                safeThis->setBusy(false);
                safeThis->statusLabel_->setText(kResult.ok
                    ? ks::i18n::sourceText(
                        QStringLiteral("已写入 %1 字节，物理地址 0x%2。"))
                        .arg(size)
                        .arg(kResult.physicalAddress, 0, 16)
                    : kResult.message);
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmMemoryDialog::startTranslate()
{
    unsigned long long address = 0;
    if (!parseAddress(addressEdit_, &address,
            ks::i18n::sourceText(QStringLiteral("地址"))))
    {
        return;
    }
    unsigned long long directoryBase = 0;
    if (!directoryBaseEdit_->text().trimmed().isEmpty() &&
        !parseAddress(directoryBaseEdit_, &directoryBase,
            ks::i18n::sourceText(QStringLiteral("页目录基址"))))
    {
        return;
    }

    setBusy(true);
    statusLabel_->setText(
        ks::i18n::sourceText(QStringLiteral("正在翻译...")));
    QPointer<KvmMemoryDialog> safeThis(this);
    std::thread([safeThis, address, directoryBase]() {
        const ksword::kvm::KvmMemoryResult kResult =
            ksword::kvm::translate(directoryBase, address);
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
                    ? ks::i18n::sourceText(QStringLiteral("物理地址：0x%1"))
                        .arg(kResult.physicalAddress, 0, 16)
                    : kResult.message);
            },
            Qt::QueuedConnection);
    }).detach();
}
