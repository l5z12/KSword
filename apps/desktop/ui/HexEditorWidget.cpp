#include "HexEditorWidget.Internal.h"

namespace ksword::ui::hex_editor_internal
{
    // kMinBytesPerRow：
    // - Minimum bytes per row limit;
    // - Prevent layout anomalies caused by 0 or values that are too small.
    constexpr int kMinBytesPerRow = 4;

    // kMaxBytesPerRow：
    // - Maximum bytes per row limit;
    // - Limit excessive column count to prevent table performance degradation.
    constexpr int kMaxBytesPerRow = 64;

    // buildToolbarButtonStyle：
    // - Unify toolbar button styles.
    // - Reads theme colors for both light and dark themes.
    QString buildToolbarButtonStyle()
    {
        return QStringLiteral(
            "QToolButton {"
            "  border:1px solid %1;"
            "  border-radius:3px;"
            "  padding:2px 6px;"
            "  background:%2;"
            "  color:%3;"
            "}"
            "QToolButton:hover {"
            "  border:1px solid %4;"
            "  background:%5;"
            "  color:%7;"
            "}"
            "QToolButton:pressed {"
            "  background:%6;"
            "  color:%7;"
            "}")
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::textPrimaryHex())
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::kPrimaryBlueHoverHex)
            .arg(ksword_theme::kPrimaryBluePressedHex)
            .arg(QStringLiteral("palette(highlighted-text)"));
    }

    // buildInputStyle：
    // - Unify the style for the find/jump input box and the dropdown box.
    QString buildInputStyle()
    {
        return QStringLiteral(
            "QLineEdit {"
            "  border:1px solid %1;"
            "  border-radius:3px;"
            "  padding:2px 6px;"
            "  background:%2;"
            "  color:%3;"
            "}"
            "QLineEdit:focus {"
            "  border:1px solid %4;"
            "}")
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::textPrimaryHex())
            .arg(ksword_theme::kPrimaryBlueHex)
            + ksword_theme::themedComboBoxStyle();
    }

    // buildHeaderStyle：
    // - Unified header theme style to ensure visual consistency in both light and dark modes.
    QString buildHeaderStyle()
    {
        return QStringLiteral(
            "QHeaderView::section {"
            "  color:%1;"
            "  background:transparent; /* %2 */"
            "  border:none;"
            "  padding:4px;"
            "  font-weight:600;"
            "}")
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::surfaceHex());
    }

    // buildMenuStyle：
    // - Generate independent theme styles for HexEditor's internal right-click menu and export menu;
    // - Fix the issue where menus still have a white background in dark mode.
    QString buildMenuStyle()
    {
        return QStringLiteral(
            "QMenu{"
            "  background:%1;"
            "  color:%2;"
            "  border:1px solid %3;"
            "}"
            "QMenu::item{"
            "  padding:6px 18px;"
            "  background:transparent;"
            "}"
            "QMenu::item:selected{"
            "  background:%4;"
            "  color:%5;"
            "}"
            "QMenu::separator{"
            "  height:1px;"
            "  background:%3;"
            "  margin:4px 8px;"
            "}")
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::textPrimaryHex())
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::accentHex(ksword_theme::AccentRole::kBlue))
            .arg(ksword_theme::onAccentDynamicHex());
    }

    // buildMatchColor：
    // - Return the background color for a regular matched byte.
    // - Use dark green for dark mode and pale yellow for light mode.
    QColor buildMatchColor()
    {
        if (ksword_theme::isDarkModeEnabled())
        {
            return ksword_theme::editorMatchColor();
        }
        return ksword_theme::editorMatchColor();
    }

    // buildCurrentMatchColor：
    // - Return the background color for the current matched byte.
    // - Slightly stronger color for quick location.
    QColor buildCurrentMatchColor()
    {
        if (ksword_theme::isDarkModeEnabled())
        {
            return ksword_theme::editorCurrentMatchColor();
        }
        return ksword_theme::editorCurrentMatchColor();
    }

    // buildSelectionColor：
    // - Returns the highlight color for the current user selection.
    // - Prioritize making the drag selection more prominent than the search highlight.
    QColor buildSelectionColor()
    {
        if (ksword_theme::isDarkModeEnabled())
        {
            return ksword_theme::editorSelectionColor();
        }
        return ksword_theme::editorSelectionColor();
    }

    // byteToHexText：
    // - Convert a single byte to a two-digit uppercase HEX text.
    QString byteToHexText(const std::uint8_t byteValue)
    {
        return QStringLiteral("%1").arg(byteValue, 2, 16, QChar('0')).toUpper();
    }

    // normalizeBytesPerRow：
    // - Safely clamp bytes per row.
    // - Prevents invalid values from affecting the layout.
    int normalizeBytesPerRow(const int requestedBytesPerRow)
    {
        return std::clamp(requestedBytesPerRow, kMinBytesPerRow, kMaxBytesPerRow);
    }
}


using namespace ksword::ui::hex_editor_internal;

HexEditorWidget::HexEditorWidget(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
    initializeConnections();

    // initialize to an empty data view.
    clearData();
}

HexEditorWidget::~HexEditorWidget() = default;

void HexEditorWidget::setRegionData(
    const void* regionPointer,
    const std::size_t regionSize,
    const std::uint64_t baseAddress)
{
    // Treat a null pointer or 0 length as a clear operation.
    if (regionPointer == nullptr || regionSize == 0)
    {
        baseAddress_ = baseAddress;
        buffer_.clear();
        ++bufferRevision_;
        clearSearchState();
        selectionRangeValid_ = false;
        selectionRangeStartOffset_ = 0;
        selectionRangeEndOffset_ = 0;
        selectionVisualAsciiColumn_ = false;
        rebuildTable();
        updateSummaryLabel();
        updateSelectionInspector();
        updateStatusLabel(QStringLiteral("当前区域为空。"));
        return;
    }

    // Copy the input memory region to avoid external buffer lifetime affecting the control.
    const QByteArray kIncomingBytes(
        static_cast<const char*>(regionPointer),
        static_cast<int>(regionSize));
    setByteArray(kIncomingBytes, baseAddress);
}

void HexEditorWidget::setByteArray(const QByteArray& bytes, const std::uint64_t baseAddress)
{
    // Overwrite the current buffer, update the base address and version number.
    buffer_ = bytes;
    baseAddress_ = baseAddress;
    ++bufferRevision_;

    // Clear old search results upon new data arrival to prevent highlight misalignment.
    clearSearchState();
    selectionRangeValid_ = false;
    selectionRangeStartOffset_ = 0;
    selectionRangeEndOffset_ = 0;
    selectionVisualAsciiColumn_ = false;
    rebuildTable();
    updateSummaryLabel();
    updateSelectionInspector();

    updateStatusLabel(
        QStringLiteral("加载完成：%1 字节。")
        .arg(static_cast<qulonglong>(buffer_.size())));
}

void HexEditorWidget::clearData()
{
    // clearData directly reuses setByteArray to maintain consistent behavior.
    setByteArray(QByteArray(), baseAddress_);
}

void HexEditorWidget::setEditable(const bool editable)
{
    if (editable_ == editable)
    {
        return;
    }

    editable_ = editable;
    rebuildTable();
    updateSummaryLabel();
    updateSelectionInspector();
}

bool HexEditorWidget::isEditable() const
{
    return editable_;
}

void HexEditorWidget::setBytesPerRow(const int bytesPerRow)
{
    const int kNormalizedBytesPerRow = normalizeBytesPerRow(bytesPerRow);
    if (kNormalizedBytesPerRow == bytesPerRow_)
    {
        return;
    }

    bytesPerRow_ = kNormalizedBytesPerRow;
    if (bytesPerRowCombo_ != nullptr)
    {
        const int kComboIndex = bytesPerRowCombo_->findData(bytesPerRow_);
        if (kComboIndex >= 0)
        {
            bytesPerRowCombo_->setCurrentIndex(kComboIndex);
        }
    }

    rebuildTable();
    updateSummaryLabel();
    updateSelectionInspector();
}

int HexEditorWidget::bytesPerRow() const
{
    return bytesPerRow_;
}

bool HexEditorWidget::jumpToAbsoluteAddress(const std::uint64_t absoluteAddress)
{
    if (absoluteAddress < baseAddress_)
    {
        updateStatusLabel(QStringLiteral("跳转失败：地址小于基址。"));
        return false;
    }

    const std::uint64_t kOffset = absoluteAddress - baseAddress_;
    return jumpToOffset(kOffset);
}

bool HexEditorWidget::jumpToOffset(const std::uint64_t offset)
{
    if (buffer_.isEmpty())
    {
        updateStatusLabel(QStringLiteral("跳转失败：当前无可显示数据。"));
        return false;
    }

    if (offset >= static_cast<std::uint64_t>(buffer_.size()))
    {
        updateStatusLabel(QStringLiteral("跳转失败：偏移超出范围。"));
        return false;
    }

    int row = -1;
    int column = -1;
    if (!offsetToRowColumn(offset, row, column))
    {
        updateStatusLabel(QStringLiteral("跳转失败：目标单元格不可用。"));
        return false;
    }

    hexTable_->setCurrentCell(row, column);
    hexTable_->scrollToItem(hexTable_->item(row, column), QAbstractItemView::PositionAtCenter);

    updateStatusLabel(
        QStringLiteral("已跳转到地址 %1。")
        .arg(QStringLiteral("0x%1").arg(static_cast<qulonglong>(baseAddress_ + offset), 16, 16, QChar('0')).toUpper()));
    return true;
}

bool HexEditorWidget::jumpToRow(const std::uint64_t rowIndex)
{
    if (buffer_.isEmpty())
    {
        updateStatusLabel(QStringLiteral("跳转失败：当前无可显示数据。"));
        return false;
    }

    const std::uint64_t kOffset = rowIndex * static_cast<std::uint64_t>(bytesPerRow_);
    if (kOffset >= static_cast<std::uint64_t>(buffer_.size()))
    {
        updateStatusLabel(QStringLiteral("跳转失败：行号超出范围。"));
        return false;
    }

    return jumpToOffset(kOffset);
}

void HexEditorWidget::openFindPanel()
{
    if (findPanel_ == nullptr)
    {
        return;
    }

    findPanel_->setVisible(true);
    if (findEdit_ != nullptr)
    {
        findEdit_->setFocus(Qt::ShortcutFocusReason);
        findEdit_->selectAll();
    }
}

void HexEditorWidget::openJumpPanel()
{
    if (jumpPanel_ == nullptr)
    {
        return;
    }

    jumpPanel_->setVisible(true);
    if (jumpEdit_ != nullptr)
    {
        jumpEdit_->setFocus(Qt::ShortcutFocusReason);
        jumpEdit_->selectAll();
    }
}

bool HexEditorWidget::setByteAtAbsoluteAddress(
    const std::uint64_t absoluteAddress,
    const std::uint8_t byteValue,
    const bool keepSelection)
{
    if (absoluteAddress < baseAddress_)
    {
        return false;
    }

    const std::uint64_t kOffset = absoluteAddress - baseAddress_;
    if (kOffset >= static_cast<std::uint64_t>(buffer_.size()))
    {
        return false;
    }

    buffer_[static_cast<int>(kOffset)] = static_cast<char>(byteValue);
    ++bufferRevision_;

    int row = -1;
    int column = -1;
    if (!offsetToRowColumn(kOffset, row, column))
    {
        return false;
    }

    // Suppress itemChanged during backfill to avoid triggering edit signals.
    ignoreItemChanged_ = true;
    QTableWidgetItem* byteItem = hexTable_->item(row, column);
    if (byteItem != nullptr)
    {
        byteItem->setText(byteToHexText(byteValue));
    }
    updateAsciiCellByRow(row);
    refreshAsciiTabText();
    updateRowHighlightByRow(row);
    ignoreItemChanged_ = false;
    updateSelectionInspector();

    if (keepSelection)
    {
        hexTable_->setCurrentCell(row, column);
    }
    return true;
}

QByteArray HexEditorWidget::data() const
{
    return buffer_;
}

std::size_t HexEditorWidget::regionSize() const
{
    return static_cast<std::size_t>(buffer_.size());
}

std::uint64_t HexEditorWidget::baseAddress() const
{
    return baseAddress_;
}

std::uint64_t HexEditorWidget::selectedAbsoluteAddress() const
{
    return baseAddress_ + selectedOffset();
}

std::uint64_t HexEditorWidget::selectedOffset() const
{
    if (hexTable_ == nullptr || hexTable_->currentItem() == nullptr)
    {
        return 0;
    }

    const int kCurrentRow = hexTable_->currentItem()->row();
    const int kCurrentColumn = hexTable_->currentItem()->column();

    std::uint64_t offset = 0;
    if (!rowColumnToOffset(kCurrentRow, kCurrentColumn, offset))
    {
        return 0;
    }
    return offset;
}

bool HexEditorWidget::eventFilter(QObject* watched, QEvent* event)
{
    if (hexTable_ == nullptr || event == nullptr)
    {
        return QWidget::eventFilter(watched, event);
    }

    // Intercept only the hex table viewport; delegate other objects to the base class.
    if (watched != hexTable_->viewport())
    {
        return QWidget::eventFilter(watched, event);
    }

    if (buffer_.isEmpty())
    {
        return QWidget::eventFilter(watched, event);
    }

    // Mouse press: record anchor point and enter linear drag mode.
    if (event->type() == QEvent::MouseButtonPress)
    {
        QMouseEvent* mouseEvent = static_cast<QMouseEvent*>(event);
        if (mouseEvent->button() != Qt::LeftButton)
        {
            return QWidget::eventFilter(watched, event);
        }

        std::uint64_t clickedOffset = 0;
        if (!viewportPosToOffset(mouseEvent->pos(), clickedOffset))
        {
            return true;
        }

        if (!(mouseEvent->modifiers() & Qt::ShiftModifier) || !linearSelectAnchorValid_)
        {
            linearSelectAnchorOffset_ = clickedOffset;
            linearSelectAnchorValid_ = true;
        }

        // Record whether the current drag start is in the ASCII column:
        // - true: visual highlight remains in the ASCII column;
        // - false: visual highlight remains in the hex byte column
        const int kPressedColumnIndex = hexTable_->columnAt(mouseEvent->pos().x());
        selectionVisualAsciiColumn_ = (kPressedColumnIndex == (bytesPerRow_ + 1));

        linearSelectDragging_ = true;
        selectLinearRange(linearSelectAnchorOffset_, clickedOffset, false);
        hexTable_->setFocus(Qt::MouseFocusReason);
        return true;
    }

    // Mouse drag: update the selection based on 'text-style continuous byte ranges'.
    if (event->type() == QEvent::MouseMove)
    {
        QMouseEvent* mouseEvent = static_cast<QMouseEvent*>(event);
        if (!linearSelectDragging_ || !(mouseEvent->buttons() & Qt::LeftButton))
        {
            return QWidget::eventFilter(watched, event);
        }

        std::uint64_t hoverOffset = 0;
        if (!viewportPosToOffset(mouseEvent->pos(), hoverOffset))
        {
            return true;
        }

        selectLinearRange(linearSelectAnchorOffset_, hoverOffset, true);
        return true;
    }

    // Mouse release: end drag state.
    if (event->type() == QEvent::MouseButtonRelease)
    {
        QMouseEvent* mouseEvent = static_cast<QMouseEvent*>(event);
        if (mouseEvent->button() == Qt::LeftButton)
        {
            linearSelectDragging_ = false;
            return true;
        }
    }

    return QWidget::eventFilter(watched, event);
}
