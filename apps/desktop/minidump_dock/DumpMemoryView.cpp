// ============================================================
// DumpMemoryView.cpp
// Purpose: Implement safe address resolution, file reopening, and paging for the dump virtual memory viewer.
// ============================================================

#include "DumpMemoryView.h"

#include "internationalization/LanguageManager.h"
#include "MinidumpFormat.h"
#include "ui/HexEditorWidget.h"
#include "Theme.h"

#include <QApplication>
#include <QClipboard>
#include <QComboBox>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QPushButton>
#include <QRegularExpression>
#include <QTextBrowser>
#include <QVBoxLayout>

#include <algorithm>
#include <limits>

namespace
{
    // kMaximumReadBytes: Hard upper limit for a single read to prevent large allocations triggered by user input or malformed directories.
    constexpr std::uint64_t kMaximumReadBytes = 64ull * 1024ull;
    // kInitialContentProbeBytes: Read-only sampling window per range when first opened. It is used only to avoid the
    // default page being exactly a zero block, without affecting the user's ability to view any captured range by address.
    constexpr std::uint64_t kInitialContentProbeBytes = 512;

    QString inputStyle()
    {
        return QStringLiteral(
            "QLineEdit,QComboBox{"
            "  border:1px solid %2;"
            "  border-radius:4px;"
            "  background:%3;"
            "  color:%4;"
            "  padding:2px 6px;"
            "}"
            "QLineEdit:focus,QComboBox:focus{ border:1px solid %1; }")
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::textPrimaryHex());
    }

    QString buttonStyle()
    {
        return ksword_theme::themedButtonStyle();
    }

    bool parseUnsignedAddress(const QString& text, std::uint64_t* const valueOut)
    {
        if (valueOut == nullptr)
        {
            return false;
        }
        QString normalized = text.trimmed();
        if (normalized.isEmpty())
        {
            return false;
        }
        int base = 10;
        if (normalized.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
        {
            normalized = normalized.mid(2);
            base = 16;
        }
        else if (normalized.contains(QRegularExpression(QStringLiteral("[A-Fa-f]"))))
        {
            // Raw hexadecimal addresses are common in debugging scenarios, e.g., FFFFF8058282A8E0.
            base = 16;
        }
        bool ok = false;
        const qulonglong kValue = normalized.toULongLong(&ok, base);
        if (!ok)
        {
            return false;
        }
        *valueOut = static_cast<std::uint64_t>(kValue);
        return true;
    }
}

DumpMemoryView::DumpMemoryView(QWidget* parent)
    : QWidget(parent)
{
    auto* const kRootLayout = new QVBoxLayout(this);
    kRootLayout->setContentsMargins(8, 8, 8, 8);
    kRootLayout->setSpacing(8);

    auto* const kToolbarLayout = new QHBoxLayout();
    kToolbarLayout->setContentsMargins(0, 0, 0, 0);
    kToolbarLayout->setSpacing(6);
    addressLabel_ = new QLabel(this);
    addressEdit_ = new QLineEdit(this);
    addressEdit_->setClearButtonEnabled(true);
    readSizeLabel_ = new QLabel(this);
    readSizeCombo_ = new QComboBox(this);
    readSizeCombo_->addItem(QStringLiteral("256 B"), 256);
    readSizeCombo_->addItem(QStringLiteral("1 KiB"), 1024);
    readSizeCombo_->addItem(QStringLiteral("4 KiB"), 4 * 1024);
    readSizeCombo_->addItem(QStringLiteral("16 KiB"), 16 * 1024);
    readSizeCombo_->addItem(QStringLiteral("64 KiB"), 64 * 1024);
    readSizeCombo_->setCurrentIndex(2);
    readButton_ = new QPushButton(this);
    previousButton_ = new QPushButton(this);
    nextButton_ = new QPushButton(this);
    addressEdit_->setStyleSheet(inputStyle());
    readSizeCombo_->setStyleSheet(inputStyle());
    for (QPushButton* const kButton : { readButton_, previousButton_, nextButton_ })
    {
        kButton->setStyleSheet(buttonStyle());
    }

    kToolbarLayout->addWidget(addressLabel_);
    kToolbarLayout->addWidget(addressEdit_, 1);
    kToolbarLayout->addWidget(readSizeLabel_);
    kToolbarLayout->addWidget(readSizeCombo_);
    kToolbarLayout->addWidget(readButton_);
    kToolbarLayout->addWidget(previousButton_);
    kToolbarLayout->addWidget(nextButton_);
    kRootLayout->addLayout(kToolbarLayout);

    // Status descriptions are structured evidence mappings; use a text browser to support line wrapping, selection, and right-click copy.
    messageView_ = new QTextBrowser(this);
    messageView_->setOpenExternalLinks(false);
    messageView_->setOpenLinks(false);
    messageView_->setMaximumHeight(145);
    messageView_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    messageView_->setStyleSheet(QStringLiteral(
        "QTextBrowser{background:%1;color:%2;border:1px solid %3;border-radius:4px;padding:5px;}")
        .arg(ksword_theme::surfaceAltHex())
        .arg(ksword_theme::textPrimaryHex())
        .arg(ksword_theme::borderHex()));
    messageView_->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(
        messageView_,
        &QTextBrowser::customContextMenuRequested,
        this,
        [this](const QPoint& point)
        {
            QMenu menu(messageView_);
            menu.setStyleSheet(QStringLiteral(
                "QMenu{background:%1;color:%2;border:1px solid %3;}"
                "QMenu::item{padding:5px 20px;}"
                "QMenu::item:selected{background:%4;color:%5;}")
                .arg(
                    ksword_theme::surfaceHex(),
                    ksword_theme::textPrimaryHex(),
                    ksword_theme::borderHex(),
                    ksword_theme::accentHex(ksword_theme::AccentRole::kBlue),
                    ksword_theme::onAccentDynamicHex()));
            QAction* const kCopyAction = menu.addAction(
                ks::i18n::text(
                    QStringLiteral("minidump.memory_view.action.copy_details"),
                    QStringLiteral("复制说明")));
            kCopyAction->setEnabled(!messageView_->toPlainText().isEmpty());
            connect(kCopyAction, &QAction::triggered, &menu, [this]()
                {
                    if (QClipboard* const kClipboard = QApplication::clipboard())
                    {
                        kClipboard->setText(messageView_->toPlainText());
                    }
                });
            menu.exec(messageView_->mapToGlobal(point));
        });
    kRootLayout->addWidget(messageView_);

    hexEditor_ = new HexEditorWidget(this);
    hexEditor_->setEditable(false);
    hexEditor_->setBytesPerRow(16);
    kRootLayout->addWidget(hexEditor_, 1);

    connect(readButton_, &QPushButton::clicked, this, [this]() { loadCurrentInput(); });
    connect(addressEdit_, &QLineEdit::returnPressed, this, [this]() { loadCurrentInput(); });
    connect(previousButton_, &QPushButton::clicked, this, [this]() { goPreviousPage(); });
    connect(nextButton_, &QPushButton::clicked, this, [this]() { goNextPage(); });
    connect(readSizeCombo_, &QComboBox::currentIndexChanged, this, [this](const int)
        {
            if (currentRangeIndex_ >= 0)
            {
                loadAddress(currentAddress_);
            }
        });
    retranslateUi();
    clearData();
}

void DumpMemoryView::setDumpData(const ks::minidump::DumpParseResult& result)
{
    filePath_ = result.filePath;
    expectedFileSize_ = result.fileSize;
    expectedFileLastModifiedUtcMs_ = result.fileLastModifiedUtcMs;
    ranges_ = result.capturedMemoryRanges;
    modules_ = result.modules;
    memoryRegions_ = result.memoryRegions;
    currentAddress_ = 0;
    currentReadBytes_ = 0;
    currentRangeIndex_ = -1;
    retranslateUi();

    if (ranges_.empty())
    {
        hexEditor_->clearData();
        setMessage(ks::i18n::text(
            QStringLiteral("minidump.memory_view.status.no_ranges"),
            QStringLiteral("转储中没有可直接读取的虚拟内存范围。")));
        return;
    }

    const int kFaultingRange = result.faultingAddress != 0
        ? findRangeIndex(result.faultingAddress)
        : -1;
    const std::uint64_t kInitialAddress = kFaultingRange >= 0
        ? result.faultingAddress
        : findPreferredInitialAddress();
    addressEdit_->setText(formatHex(kInitialAddress));
    loadAddress(kInitialAddress);
}

void DumpMemoryView::clearData()
{
    filePath_.clear();
    expectedFileSize_ = 0;
    expectedFileLastModifiedUtcMs_ = -1;
    ranges_.clear();
    modules_.clear();
    memoryRegions_.clear();
    currentAddress_ = 0;
    currentReadBytes_ = 0;
    currentRangeIndex_ = -1;
    if (hexEditor_ != nullptr)
    {
        hexEditor_->clearData();
    }
    if (addressEdit_ != nullptr)
    {
        addressEdit_->clear();
    }
    setMessage(ks::i18n::text(
        QStringLiteral("minidump.memory_view.status.idle"),
        QStringLiteral("请选择一个已捕获的虚拟地址。")));
}

void DumpMemoryView::retranslateUi()
{
    if (addressLabel_ == nullptr)
    {
        return;
    }
    addressLabel_->setText(ks::i18n::text(
        QStringLiteral("minidump.memory_view.address_label"), QStringLiteral("虚拟地址")));
    addressEdit_->setPlaceholderText(ks::i18n::text(
        QStringLiteral("minidump.memory_view.address_placeholder"),
        QStringLiteral("输入虚拟地址，或 模块名+偏移")));
    addressEdit_->setToolTip(ks::i18n::text(
        QStringLiteral("minidump.memory_view.address_tooltip"),
        QStringLiteral("支持 0x 地址、裸十六进制地址，以及 模块名+偏移。")));
    readSizeLabel_->setText(ks::i18n::text(
        QStringLiteral("minidump.memory_view.read_size_label"), QStringLiteral("读取大小")));
    const QVariant kPreviousSize = readSizeCombo_->currentData();
    readSizeCombo_->setItemText(0, ks::i18n::text(
        QStringLiteral("minidump.memory_view.size.256b"), QStringLiteral("256 字节")));
    readSizeCombo_->setItemText(1, ks::i18n::text(
        QStringLiteral("minidump.memory_view.size.1k"), QStringLiteral("1 KiB")));
    readSizeCombo_->setItemText(2, ks::i18n::text(
        QStringLiteral("minidump.memory_view.size.4k"), QStringLiteral("4 KiB")));
    readSizeCombo_->setItemText(3, ks::i18n::text(
        QStringLiteral("minidump.memory_view.size.16k"), QStringLiteral("16 KiB")));
    readSizeCombo_->setItemText(4, ks::i18n::text(
        QStringLiteral("minidump.memory_view.size.64k"), QStringLiteral("64 KiB")));
    const int kPreviousSizeIndex = readSizeCombo_->findData(kPreviousSize);
    if (kPreviousSizeIndex >= 0)
    {
        readSizeCombo_->setCurrentIndex(kPreviousSizeIndex);
    }
    readButton_->setText(ks::i18n::text(
        QStringLiteral("minidump.memory_view.action.read"), QStringLiteral("读取")));
    previousButton_->setText(ks::i18n::text(
        QStringLiteral("minidump.memory_view.action.previous"), QStringLiteral("上一页")));
    nextButton_->setText(ks::i18n::text(
        QStringLiteral("minidump.memory_view.action.next"), QStringLiteral("下一页")));
}

bool DumpMemoryView::readAddressText(const QString& text, std::uint64_t* const addressOut) const
{
    if (parseUnsignedAddress(text, addressOut))
    {
        return true;
    }
    const int kPlusIndex = text.lastIndexOf(QLatin1Char('+'));
    if (kPlusIndex <= 0 || kPlusIndex == text.size() - 1)
    {
        return false;
    }
    std::uint64_t offset = 0;
    if (!parseUnsignedAddress(text.mid(kPlusIndex + 1), &offset))
    {
        return false;
    }
    const QString kModuleText = text.left(kPlusIndex).trimmed();
    for (const ks::minidump::ModuleEntry& module : modules_)
    {
        const QString kFileName = QFileInfo(module.name).fileName();
        const QString kNativeModulePath = QDir::toNativeSeparators(module.name);
        const QString kNativeModuleText = QDir::toNativeSeparators(kModuleText);
        if (module.name.compare(kModuleText, Qt::CaseInsensitive) != 0 &&
            kNativeModulePath.compare(kNativeModuleText, Qt::CaseInsensitive) != 0 &&
            kFileName.compare(kModuleText, Qt::CaseInsensitive) != 0)
        {
            continue;
        }
        if (module.base > std::numeric_limits<std::uint64_t>::max() - offset)
        {
            return false;
        }
        *addressOut = module.base + offset;
        return true;
    }
    return false;
}

int DumpMemoryView::findRangeIndex(const std::uint64_t address) const
{
    const auto kUpper = std::upper_bound(
        ranges_.begin(),
        ranges_.end(),
        address,
        [](const std::uint64_t value, const ks::minidump::DumpMemoryRange& range)
        {
            return value < range.virtualAddress;
        });
    const int kUpperIndex = static_cast<int>(kUpper - ranges_.begin());
    constexpr int kOverlapProbeDepth = 8;
    for (int index = kUpperIndex - 1, probes = 0;
         index >= 0 && probes < kOverlapProbeDepth;
         --index, ++probes)
    {
        const ks::minidump::DumpMemoryRange& range =
            ranges_[static_cast<std::size_t>(index)];
        if (address < range.virtualAddress)
        {
            continue;
        }
        const std::uint64_t kOffset = address - range.virtualAddress;
        if (kOffset < range.bytes)
        {
            return index;
        }
    }
    return -1;
}

std::uint64_t DumpMemoryView::findPreferredInitialAddress() const
{
    if (ranges_.empty() || filePath_.isEmpty())
    {
        return ranges_.empty() ? 0 : ranges_.front().virtualAddress;
    }

    QFile dumpFile(filePath_);
    if (!dumpFile.open(QIODevice::ReadOnly))
    {
        return ranges_.front().virtualAddress;
    }

    for (const ks::minidump::DumpMemoryRange& range : ranges_)
    {
        const std::uint64_t kProbeBytes = std::min(range.bytes, kInitialContentProbeBytes);
        if (kProbeBytes == 0 ||
            range.fileOffset > static_cast<std::uint64_t>(std::numeric_limits<qint64>::max()) ||
            kProbeBytes > static_cast<std::uint64_t>(std::numeric_limits<qint64>::max()) ||
            !dumpFile.seek(static_cast<qint64>(range.fileOffset)))
        {
            continue;
        }
        const QByteArray kBytes = dumpFile.read(static_cast<qint64>(kProbeBytes));
        if (kBytes.size() != static_cast<qsizetype>(kProbeBytes))
        {
            continue;
        }
        const bool kHasNonZeroByte = std::any_of(
            kBytes.cbegin(),
            kBytes.cend(),
            [](const char byte) { return static_cast<unsigned char>(byte) != 0; });
        if (kHasNonZeroByte)
        {
            return range.virtualAddress;
        }
    }
    return ranges_.front().virtualAddress;
}

void DumpMemoryView::loadCurrentInput()
{
    std::uint64_t address = 0;
    if (!readAddressText(addressEdit_->text(), &address))
    {
        hexEditor_->clearData();
        setMessage(ks::i18n::text(
            QStringLiteral("minidump.memory_view.status.invalid_address"),
            QStringLiteral("请输入有效的虚拟地址，或“模块名+偏移”。")));
        return;
    }
    loadAddress(address);
}

bool DumpMemoryView::loadAddress(const std::uint64_t address)
{
    const int kRangeIndex = findRangeIndex(address);
    if (kRangeIndex < 0)
    {
        hexEditor_->clearData();
        setMessage(ks::i18n::text(
            QStringLiteral("minidump.memory_view.status.not_captured"),
            QStringLiteral("地址 %1 不在当前转储捕获的虚拟内存范围内。"))
            .arg(formatHex(address)));
        return false;
    }
    if (filePath_.isEmpty())
    {
        hexEditor_->clearData();
        setMessage(ks::i18n::text(
            QStringLiteral("minidump.memory_view.status.no_file"),
            QStringLiteral("没有与当前内存范围关联的转储文件。")));
        return false;
    }

    const QFileInfo kFileInfo(filePath_);
    const bool kChanged = !kFileInfo.exists() || !kFileInfo.isFile() ||
        static_cast<std::uint64_t>(kFileInfo.size()) != expectedFileSize_ ||
        (expectedFileLastModifiedUtcMs_ >= 0 &&
            kFileInfo.lastModified().toUTC().toMSecsSinceEpoch() !=
                expectedFileLastModifiedUtcMs_);
    if (kChanged)
    {
        hexEditor_->clearData();
        setMessage(ks::i18n::text(
            QStringLiteral("minidump.memory_view.status.file_changed"),
            QStringLiteral("转储文件已变更，请重新解析后再读取内存。")));
        return false;
    }

    const ks::minidump::DumpMemoryRange& range =
        ranges_[static_cast<std::size_t>(kRangeIndex)];
    const std::uint64_t kOffsetInRange = address - range.virtualAddress;
    const std::uint64_t kRemaining = range.bytes - kOffsetInRange;
    const std::uint64_t kRequestedBytes = std::min(kRemaining, selectedReadBytes());
    if (kRequestedBytes == 0 || range.fileOffset > std::numeric_limits<std::uint64_t>::max() - kOffsetInRange)
    {
        hexEditor_->clearData();
        setMessage(ks::i18n::text(
            QStringLiteral("minidump.memory_view.status.offset_invalid"),
            QStringLiteral("文件偏移超出可读取范围。")));
        return false;
    }
    const std::uint64_t kFileOffset = range.fileOffset + kOffsetInRange;
    if (kFileOffset > static_cast<std::uint64_t>(std::numeric_limits<qint64>::max()) ||
        kRequestedBytes > static_cast<std::uint64_t>(std::numeric_limits<qint64>::max()) ||
        kFileOffset > expectedFileSize_ || kRequestedBytes > expectedFileSize_ - kFileOffset)
    {
        hexEditor_->clearData();
        setMessage(ks::i18n::text(
            QStringLiteral("minidump.memory_view.status.offset_invalid"),
            QStringLiteral("文件偏移超出可读取范围。")));
        return false;
    }

    QFile dumpFile(filePath_);
    if (!dumpFile.open(QIODevice::ReadOnly))
    {
        hexEditor_->clearData();
        setMessage(ks::i18n::text(
            QStringLiteral("minidump.memory_view.status.open_failed"),
            QStringLiteral("无法打开转储文件：%1"))
            .arg(dumpFile.errorString()));
        return false;
    }
    if (!dumpFile.seek(static_cast<qint64>(kFileOffset)))
    {
        hexEditor_->clearData();
        setMessage(ks::i18n::text(
            QStringLiteral("minidump.memory_view.status.read_failed"),
            QStringLiteral("读取失败或文件内容不足。")));
        return false;
    }
    const QByteArray kBytes = dumpFile.read(static_cast<qint64>(kRequestedBytes));
    if (kBytes.size() != static_cast<qsizetype>(kRequestedBytes))
    {
        hexEditor_->clearData();
        setMessage(ks::i18n::text(
            QStringLiteral("minidump.memory_view.status.read_failed"),
            QStringLiteral("读取失败或文件内容不足。")));
        return false;
    }

    currentAddress_ = address;
    currentReadBytes_ = kRequestedBytes;
    currentRangeIndex_ = kRangeIndex;
    addressEdit_->setText(formatHex(address));
    hexEditor_->setByteArray(kBytes, address);

    QStringList details;
    details.append(ks::i18n::text(
        QStringLiteral("minidump.memory_view.detail.address"),
        QStringLiteral("虚拟地址：%1")).arg(formatHex(address)));
    const std::uint64_t kRangeEnd = range.bytes <= std::numeric_limits<std::uint64_t>::max() - range.virtualAddress
        ? range.virtualAddress + range.bytes - 1
        : std::numeric_limits<std::uint64_t>::max();
    details.append(ks::i18n::text(
        QStringLiteral("minidump.memory_view.detail.range"),
        QStringLiteral("捕获范围：%1 - %2（%3 字节）"))
        .arg(formatHex(range.virtualAddress))
        .arg(formatHex(kRangeEnd))
        .arg(range.bytes));
    details.append(ks::i18n::text(
        QStringLiteral("minidump.memory_view.detail.file_offset"),
        QStringLiteral("文件偏移：%1")).arg(formatHex(kFileOffset)));
    details.append(ks::i18n::text(
        QStringLiteral("minidump.memory_view.detail.source"),
        QStringLiteral("来源：%1")).arg(ks::i18n::sourceText(range.source)));
    for (const ks::minidump::ModuleEntry& module : modules_)
    {
        if (module.size == 0 || address < module.base || address - module.base >= module.size)
        {
            continue;
        }
        details.append(ks::i18n::text(
            QStringLiteral("minidump.memory_view.detail.module"),
            QStringLiteral("所属模块：%1+0x%2"))
            .arg(module.name)
            .arg(QString::number(address - module.base, 16).toUpper()));
        break;
    }
    for (const ks::minidump::MemoryRegionEntry& region : memoryRegions_)
    {
        if (region.size == 0 || address < region.base || address - region.base >= region.size)
        {
            continue;
        }
        details.append(ks::i18n::text(
            QStringLiteral("minidump.memory_view.detail.memory_region"),
            QStringLiteral("内存区域：%1（%2，%3，%4）"))
            .arg(formatHex(region.base))
            .arg(ks::i18n::sourceText(region.state))
            .arg(ks::i18n::sourceText(region.protect))
            .arg(ks::i18n::sourceText(region.type)));
        break;
    }
    details.append(ks::i18n::text(
        QStringLiteral("minidump.memory_view.detail.read_size"),
        QStringLiteral("本次读取：%1 字节"))
        .arg(kRequestedBytes));
    setMessage(details.join(QLatin1Char('\n')));
    return true;
}

void DumpMemoryView::goPreviousPage()
{
    if (currentRangeIndex_ < 0)
    {
        loadCurrentInput();
        return;
    }
    const ks::minidump::DumpMemoryRange& current =
        ranges_[static_cast<std::size_t>(currentRangeIndex_)];
    if (currentAddress_ > current.virtualAddress)
    {
        const std::uint64_t kPrevious = currentAddress_ - current.virtualAddress >= selectedReadBytes()
            ? currentAddress_ - selectedReadBytes()
            : current.virtualAddress;
        loadAddress(kPrevious);
        return;
    }
    for (int index = currentRangeIndex_ - 1; index >= 0; --index)
    {
        const ks::minidump::DumpMemoryRange& previous =
            ranges_[static_cast<std::size_t>(index)];
        if (previous.bytes == 0)
        {
            continue;
        }
        const std::uint64_t kPageBytes = std::min(previous.bytes, selectedReadBytes());
        loadAddress(previous.virtualAddress + previous.bytes - kPageBytes);
        return;
    }
}

void DumpMemoryView::goNextPage()
{
    if (currentRangeIndex_ < 0)
    {
        loadCurrentInput();
        return;
    }
    const ks::minidump::DumpMemoryRange& current =
        ranges_[static_cast<std::size_t>(currentRangeIndex_)];
    const std::uint64_t kConsumed = currentAddress_ - current.virtualAddress;
    if (currentReadBytes_ != 0 && kConsumed <= current.bytes - currentReadBytes_)
    {
        const std::uint64_t kNext = currentAddress_ + currentReadBytes_;
        if (kNext > currentAddress_ && kNext - current.virtualAddress < current.bytes)
        {
            loadAddress(kNext);
            return;
        }
    }
    for (std::size_t index = static_cast<std::size_t>(currentRangeIndex_) + 1;
         index < ranges_.size(); ++index)
    {
        if (ranges_[index].bytes != 0)
        {
            loadAddress(ranges_[index].virtualAddress);
            return;
        }
    }
}

std::uint64_t DumpMemoryView::selectedReadBytes() const
{
    const QVariant kData = readSizeCombo_->currentData();
    bool ok = false;
    const qulonglong kSelected = kData.toULongLong(&ok);
    return ok ? std::clamp<std::uint64_t>(kSelected, 1, kMaximumReadBytes) : 4ull * 1024ull;
}

void DumpMemoryView::setMessage(const QString& text)
{
    if (messageView_ != nullptr)
    {
        messageView_->setPlainText(text);
    }
}

QString DumpMemoryView::formatHex(const std::uint64_t value)
{
    return QStringLiteral("0x%1").arg(QString::number(value, 16).toUpper());
}
