#include "HexEditorWidget.h"

// ============================================================
// HexEditorWidget.Selection.cpp
// Purpose:
// - Hosts the creation of the "Selection Inspector" panel and selection interpretation logic.
// - Decouple from main UI/tool logic to reduce maintenance costs.
// - Handles display only; does not touch the core search and edit logic.
// ============================================================

#include "../Theme.h"

#include <QFontDatabase>
#include <QGridLayout>
#include <QLabel>

#include <algorithm>
#include <cstring>
#include <string>

namespace
{
    // byteToHexTextLocal：
    // - Convert a single byte to a two-character uppercase HEX string.
    // - The selection checker is a separate compilation unit to avoid dependencies on anonymous functions in the main .cpp.
    QString byteToHexTextLocal(const std::uint8_t byteValue)
    {
        return QStringLiteral("%1").arg(byteValue, 2, 16, QChar('0')).toUpper();
    }

    // buildSelectionInspectorPanelStyle：
    // - Uniformly set the border and background styles for the selection inspector panel;
    // - Keeps the theme consistent with the main hex editor panel.
    QString buildSelectionInspectorPanelStyle()
    {
        return QStringLiteral(
            "#ksHexSelectionInspectorPanel{"
            "  border:1px solid %1;"
            "  border-radius:4px;"
            "  background:transparent;"
            "  background-color:transparent;"
            "}"
            "#ksHexSelectionInspectorPanel QLabel{"
            "  border:none;"
            "  background:transparent;"
            "  background-color:transparent;"
            "  color:%3;"
            "}")
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::textPrimaryHex());
    }

    // buildFixedPreviewFont：
    // - Provide a unified monospace font for HEX/ASCII/UTF-16/numeric interpretation;
    // - Facilitates user alignment when reading byte previews.
    QFont buildFixedPreviewFont()
    {
        QFont fixedFont = QFontDatabase::systemFont(QFontDatabase::FixedFont);
        // When the system monospace font lacks Chinese glyphs, Windows falls back to SimSun. Explicitly specifying Microsoft YaHei handles Chinese (UTF-16 preview will display Chinese).
        fixedFont.setFamilies(QStringList{ fixedFont.family(), QStringLiteral("Microsoft YaHei UI") });
        fixedFont.setPointSize(std::max(fixedFont.pointSize(), 10));
        return fixedFont;
    }
}

void HexEditorWidget::initializeSelectionInspector()
{
    selectionInspectorPanel_ = new QWidget(this);
    selectionInspectorPanel_->setObjectName(QStringLiteral("ksHexSelectionInspectorPanel"));
    selectionInspectorPanel_->setAutoFillBackground(false);
    selectionInspectorPanel_->setAttribute(Qt::WA_StyledBackground, true);
    selectionInspectorLayout_ = new QGridLayout(selectionInspectorPanel_);
    selectionInspectorLayout_->setContentsMargins(8, 8, 8, 8);
    selectionInspectorLayout_->setHorizontalSpacing(8);
    selectionInspectorLayout_->setVerticalSpacing(4);
    selectionInspectorPanel_->setStyleSheet(buildSelectionInspectorPanelStyle());

    auto buildValueLabel = [this]() -> QLabel*
        {
            QLabel* valueLabel = new QLabel(selectionInspectorPanel_);
            valueLabel->setWordWrap(true);
            valueLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
            valueLabel->setAlignment(Qt::AlignLeft | Qt::AlignTop);
            return valueLabel;
        };

    const QFont kFixedFont = buildFixedPreviewFont();
    selectionSummaryLabel_ = buildValueLabel();
    selectionHexPreviewLabel_ = buildValueLabel();
    selectionAsciiPreviewLabel_ = buildValueLabel();
    selectionUtf16PreviewLabel_ = buildValueLabel();
    selectionIntegerPreviewLabel_ = buildValueLabel();

    selectionHexPreviewLabel_->setFont(kFixedFont);
    selectionAsciiPreviewLabel_->setFont(kFixedFont);
    selectionUtf16PreviewLabel_->setFont(kFixedFont);
    selectionIntegerPreviewLabel_->setFont(kFixedFont);

    selectionInspectorLayout_->addWidget(new QLabel(QStringLiteral("选区"), selectionInspectorPanel_), 0, 0);
    selectionInspectorLayout_->addWidget(selectionSummaryLabel_, 0, 1);
    selectionInspectorLayout_->addWidget(new QLabel(QStringLiteral("HEX"), selectionInspectorPanel_), 1, 0);
    selectionInspectorLayout_->addWidget(selectionHexPreviewLabel_, 1, 1);
    selectionInspectorLayout_->addWidget(new QLabel(QStringLiteral("ASCII"), selectionInspectorPanel_), 2, 0);
    selectionInspectorLayout_->addWidget(selectionAsciiPreviewLabel_, 2, 1);
    selectionInspectorLayout_->addWidget(new QLabel(QStringLiteral("UTF-16"), selectionInspectorPanel_), 3, 0);
    selectionInspectorLayout_->addWidget(selectionUtf16PreviewLabel_, 3, 1);
    selectionInspectorLayout_->addWidget(new QLabel(QStringLiteral("数值"), selectionInspectorPanel_), 4, 0);
    selectionInspectorLayout_->addWidget(selectionIntegerPreviewLabel_, 4, 1);
    selectionInspectorLayout_->setColumnStretch(1, 1);
}

void HexEditorWidget::updateSelectionInspector()
{
    // The selection checker is the unified aggregation point for all selection changes, so external broadcasts are also placed here to
    // ensure that when external parties receive notifications, selectedBytes() and selectionRange() already reflect the latest state.
    std::uint64_t notifyStartOffset = 0;
    std::uint64_t notifyEndOffset = 0;
    const bool kNotifyHasSelection = selectionRange(notifyStartOffset, notifyEndOffset);
    emit selectionChanged(notifyStartOffset, notifyEndOffset, kNotifyHasSelection);

    if (selectionSummaryLabel_ == nullptr ||
        selectionHexPreviewLabel_ == nullptr ||
        selectionAsciiPreviewLabel_ == nullptr ||
        selectionUtf16PreviewLabel_ == nullptr ||
        selectionIntegerPreviewLabel_ == nullptr)
    {
        return;
    }

    if (buffer_.isEmpty())
    {
        selectionSummaryLabel_->setText(QStringLiteral("当前无数据。"));
        selectionHexPreviewLabel_->setText(QStringLiteral("-"));
        selectionAsciiPreviewLabel_->setText(QStringLiteral("-"));
        selectionUtf16PreviewLabel_->setText(QStringLiteral("-"));
        selectionIntegerPreviewLabel_->setText(QStringLiteral("-"));
        return;
    }

    const std::vector<std::uint64_t> kOffsetList = collectSelectedOffsets();
    if (kOffsetList.empty())
    {
        selectionSummaryLabel_->setText(QStringLiteral("当前未选中有效字节。"));
        selectionHexPreviewLabel_->setText(QStringLiteral("-"));
        selectionAsciiPreviewLabel_->setText(QStringLiteral("-"));
        selectionUtf16PreviewLabel_->setText(QStringLiteral("-"));
        selectionIntegerPreviewLabel_->setText(QStringLiteral("-"));
        return;
    }

    const QByteArray kSelectedBytes = buildSelectedByteArray();
    const std::uint64_t kFirstOffset = kOffsetList.front();
    const std::uint64_t kLastOffset = kOffsetList.back();
    const bool kContiguous = (kLastOffset - kFirstOffset + 1) == static_cast<std::uint64_t>(kOffsetList.size());

    selectionSummaryLabel_->setText(
        QStringLiteral("起始=%1 | 结束=%2 | 长度=%3 字节 | 模式=%4")
        .arg(QStringLiteral("0x%1").arg(static_cast<qulonglong>(baseAddress_ + kFirstOffset), 16, 16, QChar('0')).toUpper())
        .arg(QStringLiteral("0x%1").arg(static_cast<qulonglong>(baseAddress_ + kLastOffset), 16, 16, QChar('0')).toUpper())
        .arg(static_cast<qulonglong>(kSelectedBytes.size()))
        .arg(kContiguous ? QStringLiteral("连续") : QStringLiteral("非连续")));
    selectionHexPreviewLabel_->setText(formatSelectionHexPreview(kSelectedBytes));
    selectionAsciiPreviewLabel_->setText(formatSelectionAsciiPreview(kSelectedBytes));
    selectionUtf16PreviewLabel_->setText(formatSelectionUtf16Preview(kSelectedBytes));
    selectionIntegerPreviewLabel_->setText(formatSelectionIntegerPreview(kSelectedBytes));
}

QByteArray HexEditorWidget::buildSelectedByteArray() const
{
    QByteArray selectedBytes;
    const std::vector<std::uint64_t> kOffsetList = collectSelectedOffsets();
    selectedBytes.reserve(static_cast<int>(kOffsetList.size()));

    for (const std::uint64_t kOffset : kOffsetList)
    {
        if (kOffset >= static_cast<std::uint64_t>(buffer_.size()))
        {
            continue;
        }
        selectedBytes.push_back(buffer_.at(static_cast<int>(kOffset)));
    }
    return selectedBytes;
}

QByteArray HexEditorWidget::selectedBytes() const
{
    // Directly delegate to existing internal implementation to avoid a second definition of selection semantics.
    return buildSelectedByteArray();
}

bool HexEditorWidget::selectionRange(
    std::uint64_t& startOffsetOut,
    std::uint64_t& endOffsetOut) const
{
    // collectSelectedOffsets is guaranteed to be sorted and deduplicated; taking the first and last elements restores the intervals.
    const std::vector<std::uint64_t> kOffsetList = collectSelectedOffsets();
    if (kOffsetList.empty())
    {
        return false;
    }

    startOffsetOut = kOffsetList.front();
    endOffsetOut = kOffsetList.back() + 1U;
    return true;
}

QString HexEditorWidget::formatSelectionHexPreview(const QByteArray& selectedBytes) const
{
    if (selectedBytes.isEmpty())
    {
        return QStringLiteral("-");
    }

    constexpr int kPreviewBytes = 64;
    QStringList hexTextList;
    const int kDisplayCount = std::min<int>(selectedBytes.size(), kPreviewBytes);
    hexTextList.reserve(kDisplayCount);
    for (int index = 0; index < kDisplayCount; ++index)
    {
        hexTextList.push_back(byteToHexTextLocal(static_cast<std::uint8_t>(selectedBytes.at(index))));
    }

    QString previewText = hexTextList.join(' ');
    if (selectedBytes.size() > kPreviewBytes)
    {
        previewText += QStringLiteral(" ...（共 %1 字节）").arg(selectedBytes.size());
    }
    return previewText;
}

QString HexEditorWidget::formatSelectionAsciiPreview(const QByteArray& selectedBytes) const
{
    if (selectedBytes.isEmpty())
    {
        return QStringLiteral("-");
    }

    QString asciiText;
    asciiText.reserve(selectedBytes.size());
    for (int index = 0; index < selectedBytes.size(); ++index)
    {
        const std::uint8_t kByteValue = static_cast<std::uint8_t>(selectedBytes.at(index));
        asciiText.push_back((kByteValue >= 32 && kByteValue <= 126) ? QChar(kByteValue) : QChar('.'));
    }
    return asciiText;
}

QString HexEditorWidget::formatSelectionUtf16Preview(const QByteArray& selectedBytes) const
{
    if (selectedBytes.size() < static_cast<int>(sizeof(char16_t)))
    {
        return QStringLiteral("-");
    }

    constexpr int kPreviewCodeUnits = 32;
    const int kCodeUnitCount = std::min<int>(
        selectedBytes.size() / static_cast<int>(sizeof(char16_t)),
        kPreviewCodeUnits);
    std::u16string utf16Buffer(static_cast<std::size_t>(kCodeUnitCount), u'\0');
    std::memcpy(
        utf16Buffer.data(),
        selectedBytes.constData(),
        static_cast<std::size_t>(kCodeUnitCount) * sizeof(char16_t));

    QString utf16Text = QString::fromUtf16(
        reinterpret_cast<const char16_t*>(utf16Buffer.data()),
        kCodeUnitCount);
    utf16Text.replace(QChar(u'\0'), QChar('.'));
    if ((selectedBytes.size() / static_cast<int>(sizeof(char16_t))) > kPreviewCodeUnits)
    {
        utf16Text += QStringLiteral(" ...");
    }
    return utf16Text;
}

QString HexEditorWidget::formatSelectionIntegerPreview(const QByteArray& selectedBytes) const
{
    if (selectedBytes.isEmpty())
    {
        return QStringLiteral("-");
    }

    const auto kByteAt = [&selectedBytes](const int index) -> std::uint8_t
        {
            return static_cast<std::uint8_t>(selectedBytes.at(index));
        };
    const auto kReadLe = [&kByteAt](const int count) -> std::uint64_t
        {
            std::uint64_t value = 0;
            for (int index = 0; index < count; ++index)
            {
                value |= (static_cast<std::uint64_t>(kByteAt(index)) << (index * 8));
            }
            return value;
        };
    const auto kReadBe = [&kByteAt](const int count) -> std::uint64_t
        {
            std::uint64_t value = 0;
            for (int index = 0; index < count; ++index)
            {
                value = (value << 8) | static_cast<std::uint64_t>(kByteAt(index));
            }
            return value;
        };

    QStringList valueTextList;
    valueTextList.push_back(QStringLiteral("u8=%1").arg(kByteAt(0)));
    valueTextList.push_back(QStringLiteral("s8=%1").arg(static_cast<qint8>(kByteAt(0))));

    if (selectedBytes.size() >= 2)
    {
        valueTextList.push_back(QStringLiteral("u16le=%1").arg(kReadLe(2)));
        valueTextList.push_back(QStringLiteral("u16be=%1").arg(kReadBe(2)));
    }
    if (selectedBytes.size() >= 4)
    {
        const std::uint32_t kU32le = static_cast<std::uint32_t>(kReadLe(4));
        const std::uint32_t kU32be = static_cast<std::uint32_t>(kReadBe(4));
        float f32le = 0.0f;
        std::memcpy(&f32le, &kU32le, sizeof(f32le));
        valueTextList.push_back(QStringLiteral("u32le=%1").arg(kU32le));
        valueTextList.push_back(QStringLiteral("u32be=%1").arg(kU32be));
        valueTextList.push_back(QStringLiteral("f32le=%1").arg(QString::number(f32le, 'g', 8)));
    }
    if (selectedBytes.size() >= 8)
    {
        const std::uint64_t kU64le = kReadLe(8);
        const std::uint64_t kU64be = kReadBe(8);
        double f64le = 0.0;
        std::memcpy(&f64le, &kU64le, sizeof(f64le));
        valueTextList.push_back(QStringLiteral("u64le=%1").arg(QString::number(static_cast<qulonglong>(kU64le))));
        valueTextList.push_back(QStringLiteral("u64be=%1").arg(QString::number(static_cast<qulonglong>(kU64be))));
        valueTextList.push_back(QStringLiteral("f64le=%1").arg(QString::number(f64le, 'g', 12)));
    }

    return valueTextList.join(QStringLiteral(" | "));
}
