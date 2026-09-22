#include "HexEditorWidget.Internal.h"

// Note: Migrated from the original aggregated implementation to a standalone .cpp file; member function implementations remain unchanged.
using namespace ksword::ui::hex_editor_internal;

// ============================================================
// HexEditorWidget.Tools.cpp
// Purpose: Provide capabilities for find/parse, asynchronous search, copy, and export.
// ============================================================

bool HexEditorWidget::parseAddressNumber(const QString& text, std::uint64_t& valueOut) const
{
    const QString kTrimmedText = text.trimmed();
    if (kTrimmedText.isEmpty())
    {
        return false;
    }

    bool parseOk = false;
    qulonglong parsedValue = 0;

    if (kTrimmedText.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
    {
        parsedValue = kTrimmedText.mid(2).toULongLong(&parseOk, 16);
        if (!parseOk)
        {
            return false;
        }
        valueOut = static_cast<std::uint64_t>(parsedValue);
        return true;
    }

    parsedValue = kTrimmedText.toULongLong(&parseOk, 10);
    if (!parseOk)
    {
        parsedValue = kTrimmedText.toULongLong(&parseOk, 16);
        if (!parseOk)
        {
            return false;
        }
    }

    valueOut = static_cast<std::uint64_t>(parsedValue);
    return true;
}

bool HexEditorWidget::parseSearchPattern(
    const SearchMode mode,
    const QString& text,
    SearchPattern& patternOut,
    QString& errorTextOut) const
{
    if (mode == SearchMode::kHexBytes)
    {
        return parseHexPattern(text, patternOut, errorTextOut);
    }
    return parseAsciiPattern(mode, text, patternOut, errorTextOut);
}

bool HexEditorWidget::parseHexPattern(
    const QString& text,
    SearchPattern& patternOut,
    QString& errorTextOut) const
{
    const QString kNormalizedText = text.trimmed().toUpper();
    if (kNormalizedText.isEmpty())
    {
        errorTextOut = QStringLiteral("HEX 查找输入为空。");
        return false;
    }

    const QStringList kTokenList = kNormalizedText.split(QRegularExpression(QStringLiteral("\\s+")), Qt::SkipEmptyParts);
    if (kTokenList.isEmpty())
    {
        errorTextOut = QStringLiteral("HEX 查找输入为空。");
        return false;
    }

    QByteArray patternBytes;
    QByteArray maskBytes;
    patternBytes.reserve(kTokenList.size());
    maskBytes.reserve(kTokenList.size());

    for (const QString& token : kTokenList)
    {
        if (token == QStringLiteral("?") || token == QStringLiteral("??"))
        {
            patternBytes.push_back('\0');
            maskBytes.push_back('\0');
            continue;
        }

        bool parseOk = false;
        const int kByteValue = token.toInt(&parseOk, 16);
        if (!parseOk || kByteValue < 0 || kByteValue > 0xFF)
        {
            errorTextOut = QStringLiteral("HEX token 无效: %1").arg(token);
            return false;
        }

        patternBytes.push_back(static_cast<char>(kByteValue));
        maskBytes.push_back('\1');
    }

    patternOut.patternBytes = patternBytes;
    patternOut.maskBytes = maskBytes;
    patternOut.normalizeText = kTokenList.join(' ');
    return true;
}

bool HexEditorWidget::parseAsciiPattern(
    const SearchMode mode,
    const QString& text,
    SearchPattern& patternOut,
    QString& errorTextOut) const
{
    const QString kNormalizedText = text;
    if (kNormalizedText.isEmpty())
    {
        errorTextOut = QStringLiteral("文本查找输入为空。");
        return false;
    }

    QByteArray patternBytes;
    if (mode == SearchMode::kAsciiText)
    {
        patternBytes = kNormalizedText.toUtf8();
    }
    else
    {
        patternBytes.resize(kNormalizedText.size() * static_cast<int>(sizeof(char16_t)));
        std::memcpy(patternBytes.data(), kNormalizedText.utf16(), static_cast<std::size_t>(patternBytes.size()));
    }

    if (patternBytes.isEmpty())
    {
        errorTextOut = QStringLiteral("文本查找输入为空。");
        return false;
    }

    QByteArray maskBytes(patternBytes.size(), '\1');
    patternOut.patternBytes = patternBytes;
    patternOut.maskBytes = maskBytes;
    patternOut.normalizeText = kNormalizedText;
    return true;
}

bool HexEditorWidget::ensureSearchResultReady(
    const NavigateDirection direction,
    const std::uint64_t startOffset)
{
    if (findEdit_ == nullptr || findModeCombo_ == nullptr)
    {
        return false;
    }

    if (buffer_.isEmpty())
    {
        updateStatusLabel(QStringLiteral("查找失败：当前无数据。"));
        return false;
    }

    const SearchMode kMode = static_cast<SearchMode>(findModeCombo_->currentData().toInt());
    const QString kSearchText = findEdit_->text();

    SearchPattern searchPattern;
    QString errorText;
    if (!parseSearchPattern(kMode, kSearchText, searchPattern, errorText))
    {
        updateStatusLabel(QStringLiteral("查找失败：%1").arg(errorText));
        return false;
    }

    const bool kSamePattern =
        (kMode == lastSearchMode_) &&
        (kSearchText == lastSearchText_) &&
        (searchReadyRevision_ == bufferRevision_);

    if (kSamePattern)
    {
        return true;
    }

    startSearchAsync(searchPattern, kMode, kSearchText, direction, startOffset);
    return false;
}

void HexEditorWidget::startSearchAsync(
    const SearchPattern& pattern,
    const SearchMode mode,
    const QString& searchText,
    const NavigateDirection direction,
    const std::uint64_t startOffset)
{
    if (pattern.patternBytes.isEmpty())
    {
        updateStatusLabel(QStringLiteral("查找失败：查找模板为空。"));
        return;
    }

    const QByteArray kDataSnapshot = buffer_;
    const QByteArray kPatternSnapshot = pattern.patternBytes;
    const QByteArray kMaskSnapshot = pattern.maskBytes;
    const QString kNormalizedText = pattern.normalizeText;
    const std::uint64_t kTicket = ++searchTicket_;
    const std::uint64_t kDataRevision = bufferRevision_;

    searchRunning_ = true;
    pendingDirection_ = direction;
    pendingStartOffset_ = startOffset;

    findResultLabel_->setText(QStringLiteral("命中: 搜索中..."));
    updateStatusLabel(QStringLiteral("查找中：正在后台扫描，不阻塞界面。"));

    // Asynchronous scan: copy the snapshot, search in a thread, then submit results back to the main thread upon completion.
    QPointer<HexEditorWidget> guardThis(this);
    std::thread([guardThis,
        kTicket,
        kDataSnapshot,
        kPatternSnapshot,
        kMaskSnapshot,
        mode,
        searchText,
        kNormalizedText,
        kDataRevision]()
        {
            std::vector<std::uint64_t> matchOffsets;
            const int kPatternLength = kPatternSnapshot.size();

            if (kPatternLength > 0 && kDataSnapshot.size() >= kPatternLength)
            {
                const std::size_t kMaxStart =
                    static_cast<std::size_t>(kDataSnapshot.size() - kPatternLength);

                for (std::size_t startIndex = 0; startIndex <= kMaxStart; ++startIndex)
                {
                    bool matched = true;
                    for (int patternIndex = 0; patternIndex < kPatternLength; ++patternIndex)
                    {
                        if (kMaskSnapshot.at(patternIndex) == '\0')
                        {
                            continue;
                        }

                        const char kDataByte = kDataSnapshot.at(static_cast<int>(startIndex) + patternIndex);
                        const char kPatternByte = kPatternSnapshot.at(patternIndex);
                        if (kDataByte != kPatternByte)
                        {
                            matched = false;
                            break;
                        }
                    }

                    if (matched)
                    {
                        matchOffsets.push_back(static_cast<std::uint64_t>(startIndex));
                    }
                }
            }

            if (guardThis == nullptr)
            {
                return;
            }

            QMetaObject::invokeMethod(
                guardThis.data(),
                [guardThis,
                    kTicket,
                    matchOffsets,
                    kPatternLength,
                    mode,
                    searchText,
                    kNormalizedText,
                    kDataRevision]() mutable
                {
                    if (guardThis == nullptr)
                    {
                        return;
                    }

                    guardThis->applySearchResult(
                        kTicket,
                        matchOffsets,
                        kPatternLength,
                        mode,
                        searchText,
                        kNormalizedText,
                        kDataRevision);
                },
                Qt::QueuedConnection);
        }).detach();
}

void HexEditorWidget::applySearchResult(
    const std::uint64_t ticket,
    const std::vector<std::uint64_t>& matchOffsets,
    const int matchLength,
    const SearchMode mode,
    const QString& searchText,
    const QString& normalizedText,
    const std::uint64_t dataRevision)
{
    // Accept only the latest ticket results to prevent old threads from overwriting the new state upon write-back.
    if (ticket != searchTicket_.load())
    {
        return;
    }

    searchRunning_ = false;
    matchOffsets_ = matchOffsets;
    currentMatchLength_ = std::max(1, matchLength);
    currentMatchIndex_ = matchOffsets_.empty() ? -1 : 0;

    lastSearchMode_ = mode;
    lastSearchText_ = searchText;
    lastSearchNormalizeText_ = normalizedText;
    searchReadyRevision_ = dataRevision;

    // Build hit mask to accelerate cell highlight judgment.
    matchMask_ = QByteArray(buffer_.size(), '\0');
    for (const std::uint64_t kMatchOffset : matchOffsets_)
    {
        for (int index = 0; index < currentMatchLength_; ++index)
        {
            const std::uint64_t kByteOffset = kMatchOffset + static_cast<std::uint64_t>(index);
            if (kByteOffset >= static_cast<std::uint64_t>(matchMask_.size()))
            {
                break;
            }
            matchMask_[static_cast<int>(kByteOffset)] = '\1';
        }
    }

    // Redraw highlights and execute pending jumps.
    rebuildTable();

    findResultLabel_->setText(
        QStringLiteral("命中: %1").arg(static_cast<qulonglong>(matchOffsets_.size())));

    if (matchOffsets_.empty())
    {
        updateStatusLabel(QStringLiteral("查找完成：未找到匹配项。"));
        return;
    }

    gotoMatchByDirection(pendingDirection_, pendingStartOffset_);
}

void HexEditorWidget::clearSearchState()
{
    matchMask_ = QByteArray(buffer_.size(), '\0');
    matchOffsets_.clear();
    currentMatchIndex_ = -1;
    currentMatchLength_ = 0;

    lastSearchText_.clear();
    lastSearchNormalizeText_.clear();
    lastSearchMode_ = SearchMode::kHexBytes;
    searchReadyRevision_ = 0;

    pendingDirection_ = NavigateDirection::kNone;
    pendingStartOffset_ = 0;

    if (findResultLabel_ != nullptr)
    {
        findResultLabel_->setText(QStringLiteral("命中: -"));
    }
}

void HexEditorWidget::gotoMatchByDirection(
    const NavigateDirection direction,
    const std::uint64_t startOffset)
{
    if (matchOffsets_.empty())
    {
        return;
    }

    pendingDirection_ = NavigateDirection::kNone;

    int targetIndex = 0;
    if (direction == NavigateDirection::kPrevious)
    {
        targetIndex = static_cast<int>(matchOffsets_.size()) - 1;
        for (int index = static_cast<int>(matchOffsets_.size()) - 1; index >= 0; --index)
        {
            if (matchOffsets_[static_cast<std::size_t>(index)] <= startOffset)
            {
                targetIndex = index;
                break;
            }
        }
    }
    else
    {
        targetIndex = 0;
        for (int index = 0; index < static_cast<int>(matchOffsets_.size()); ++index)
        {
            if (matchOffsets_[static_cast<std::size_t>(index)] >= startOffset)
            {
                targetIndex = index;
                break;
            }
        }
    }

    setCurrentMatchIndex(targetIndex);
}

void HexEditorWidget::setCurrentMatchIndex(const int matchIndex)
{
    if (matchIndex < 0 || matchIndex >= static_cast<int>(matchOffsets_.size()))
    {
        return;
    }

    currentMatchIndex_ = matchIndex;

    const std::uint64_t kMatchOffset = matchOffsets_[static_cast<std::size_t>(currentMatchIndex_)];
    selectRangeByOffset(kMatchOffset, std::max(1, currentMatchLength_), true);

    // Refresh current match highlight color.
    const int kRowIndex = static_cast<int>(kMatchOffset / static_cast<std::uint64_t>(bytesPerRow_));
    updateRowHighlightByRow(kRowIndex);

    findResultLabel_->setText(
        QStringLiteral("命中: %1 / %2")
        .arg(currentMatchIndex_ + 1)
        .arg(static_cast<int>(matchOffsets_.size())));

    updateStatusLabel(
        QStringLiteral("已定位命中 %1/%2，地址=%3")
        .arg(currentMatchIndex_ + 1)
        .arg(static_cast<int>(matchOffsets_.size()))
        .arg(QStringLiteral("0x%1").arg(static_cast<qulonglong>(baseAddress_ + kMatchOffset), 16, 16, QChar('0')).toUpper()));
}

void HexEditorWidget::selectRangeByOffset(
    const std::uint64_t offset,
    const int length,
    const bool scrollToCenter)
{
    if (hexTable_ == nullptr || length <= 0)
    {
        return;
    }

    const bool kOldRangeValid = selectionRangeValid_;
    const std::uint64_t kOldStartOffset = selectionRangeStartOffset_;
    const std::uint64_t kOldEndOffset = selectionRangeEndOffset_;

    // Non-mouse-drag paths (e.g., jump from search hit) uniformly use hex column highlighting.
    if (!linearSelectDragging_)
    {
        selectionVisualAsciiColumn_ = false;
    }
    // selectAsciiColumn: records whether the current visible selection is drawn in the ASCII column.
    const bool kSelectAsciiColumn = selectionVisualAsciiColumn_;

    hexTable_->clearSelection();

    bool firstCell = true;
    std::uint64_t newEndOffset = offset;
    // lastSelectedAsciiRow: Prevents duplicate setSelected calls for the same ASCII cell row.
    int lastSelectedAsciiRow = -1;
    for (int index = 0; index < length; ++index)
    {
        // currentOffset: The target byte offset currently being processed in the loop.
        const std::uint64_t kCurrentOffset = offset + static_cast<std::uint64_t>(index);
        // row: Output parameter for the row number of the current byte in the table.
        int row = 0;
        // column: Output parameter for the column number of the current byte in the table (hexadecimal column).
        int column = 0;
        if (!offsetToRowColumn(kCurrentOffset, row, column))
        {
            break;
        }

        newEndOffset = kCurrentOffset;

        // hexItem: Hexadecimal byte cell corresponding to the current offset.
        QTableWidgetItem* hexItem = hexTable_->item(row, column);
        // asciiItem: The ASCII column cell for the current row, used for visual feedback during multi-row ASCII selection.
        QTableWidgetItem* asciiItem = hexTable_->item(row, bytesPerRow_ + 1);

        if (kSelectAsciiColumn)
        {
            if (asciiItem != nullptr && lastSelectedAsciiRow != row)
            {
                asciiItem->setSelected(true);
                lastSelectedAsciiRow = row;
            }
        }
        else if (hexItem != nullptr)
        {
            // Explicitly set to selected state to ensure the blue highlight is always visible during drag selection.
            hexItem->setSelected(true);
        }

        if (firstCell)
        {
            // The current cell is used only for focus/scroll positioning and should not clear the already built selection.
            if (kSelectAsciiColumn)
            {
                hexTable_->setCurrentCell(row, bytesPerRow_ + 1, QItemSelectionModel::NoUpdate);
            }
            else
            {
                hexTable_->setCurrentCell(row, column, QItemSelectionModel::NoUpdate);
            }
            if (scrollToCenter)
            {
                QTableWidgetItem* scrollItem = kSelectAsciiColumn ? asciiItem : hexItem;
                if (scrollItem != nullptr)
                {
                    hexTable_->scrollToItem(scrollItem, QAbstractItemView::PositionAtCenter);
                }
            }
            firstCell = false;
        }
    }

    selectionRangeValid_ = true;
    selectionRangeStartOffset_ = offset;
    selectionRangeEndOffset_ = newEndOffset;
    updateSelectionHighlightRange(
        kOldRangeValid,
        kOldStartOffset,
        kOldEndOffset,
        selectionRangeValid_,
        selectionRangeStartOffset_,
        selectionRangeEndOffset_);
    // Force viewport refresh to avoid delayed selection highlight display under certain styles or platforms.
    hexTable_->viewport()->update();

    // Record the anchor for extending text selection via Shift + mouse.
    linearSelectAnchorOffset_ = offset;
    linearSelectAnchorValid_ = true;
}

void HexEditorWidget::selectLinearRange(
    const std::uint64_t anchorOffset,
    const std::uint64_t currentOffset,
    const bool scrollToCurrent)
{
    if (hexTable_ == nullptr || buffer_.isEmpty())
    {
        return;
    }

    const std::uint64_t kMaxOffset = static_cast<std::uint64_t>(buffer_.size() - 1);
    const std::uint64_t kSafeAnchorOffset = std::min(anchorOffset, kMaxOffset);
    const std::uint64_t kSafeCurrentOffset = std::min(currentOffset, kMaxOffset);
    const std::uint64_t kRangeStartOffset = std::min(kSafeAnchorOffset, kSafeCurrentOffset);
    const std::uint64_t kRangeEndOffset = std::max(kSafeAnchorOffset, kSafeCurrentOffset);
    const bool kOldRangeValid = selectionRangeValid_;
    const std::uint64_t kOldStartOffset = selectionRangeStartOffset_;
    const std::uint64_t kOldEndOffset = selectionRangeEndOffset_;
    // selectAsciiColumn: records whether the current drag operation requires the visible selection to be drawn in the ASCII column.
    const bool kSelectAsciiColumn = selectionVisualAsciiColumn_;

    hexTable_->clearSelection();
    // lastSelectedAsciiRow: Prevents selecting the same ASCII cell in the same row multiple times during the loop.
    int lastSelectedAsciiRow = -1;

    for (std::uint64_t byteOffset = kRangeStartOffset; byteOffset <= kRangeEndOffset; ++byteOffset)
    {
        // rowIndex: Row index mapped from the current byte offset.
        int rowIndex = 0;
        // columnIndex: Hexadecimal column index mapped from the current byte offset.
        int columnIndex = 0;
        if (!offsetToRowColumn(byteOffset, rowIndex, columnIndex))
        {
            continue;
        }

        // byteItem: The byte cell corresponding to the current offset, responsible for displaying the selected highlight.
        QTableWidgetItem* byteItem = hexTable_->item(rowIndex, columnIndex);
        // asciiItem: The ASCII column cell for the current row, used for ASCII cross-row selection.
        QTableWidgetItem* asciiItem = hexTable_->item(rowIndex, bytesPerRow_ + 1);
        if (kSelectAsciiColumn)
        {
            if (asciiItem != nullptr && lastSelectedAsciiRow != rowIndex)
            {
                asciiItem->setSelected(true);
                lastSelectedAsciiRow = rowIndex;
            }
        }
        else if (byteItem != nullptr)
        {
            // Select all bytes along the drag path to ensure continuous visual highlighting.
            byteItem->setSelected(true);
        }

        if (byteOffset == kSafeCurrentOffset)
        {
            // The current cell is used only for cursor position and should not trigger ClearAndSelect to override the entire selection.
            if (kSelectAsciiColumn)
            {
                hexTable_->setCurrentCell(rowIndex, bytesPerRow_ + 1, QItemSelectionModel::NoUpdate);
            }
            else
            {
                hexTable_->setCurrentCell(rowIndex, columnIndex, QItemSelectionModel::NoUpdate);
            }
            if (scrollToCurrent)
            {
                QTableWidgetItem* scrollItem = kSelectAsciiColumn ? asciiItem : byteItem;
                if (scrollItem != nullptr)
                {
                    hexTable_->scrollToItem(scrollItem, QAbstractItemView::EnsureVisible);
                }
            }
        }
    }

    selectionRangeValid_ = true;
    selectionRangeStartOffset_ = kRangeStartOffset;
    selectionRangeEndOffset_ = kRangeEndOffset;
    updateSelectionHighlightRange(
        kOldRangeValid,
        kOldStartOffset,
        kOldEndOffset,
        selectionRangeValid_,
        selectionRangeStartOffset_,
        selectionRangeEndOffset_);
    // Force viewport refresh to prevent highlight state from not redrawing immediately during mouse drag.
    hexTable_->viewport()->update();

    linearSelectAnchorOffset_ = kSafeAnchorOffset;
    linearSelectAnchorValid_ = true;
}

void HexEditorWidget::updateSelectionHighlightRange(
    const bool oldRangeValid,
    const std::uint64_t oldStartOffset,
    const std::uint64_t oldEndOffset,
    const bool newRangeValid,
    const std::uint64_t newStartOffset,
    const std::uint64_t newEndOffset)
{
    if (hexTable_ == nullptr || buffer_.isEmpty())
    {
        return;
    }

    bool hasAnyRange = false;
    std::uint64_t affectedStartOffset = 0;
    std::uint64_t affectedEndOffset = 0;

    if (oldRangeValid)
    {
        hasAnyRange = true;
        affectedStartOffset = oldStartOffset;
        affectedEndOffset = oldEndOffset;
    }
    if (newRangeValid)
    {
        if (!hasAnyRange)
        {
            hasAnyRange = true;
            affectedStartOffset = newStartOffset;
            affectedEndOffset = newEndOffset;
        }
        else
        {
            affectedStartOffset = std::min(affectedStartOffset, newStartOffset);
            affectedEndOffset = std::max(affectedEndOffset, newEndOffset);
        }
    }

    if (!hasAnyRange)
    {
        return;
    }

    const int kStartRowIndex = static_cast<int>(affectedStartOffset / static_cast<std::uint64_t>(bytesPerRow_));
    const int kEndRowIndex = static_cast<int>(affectedEndOffset / static_cast<std::uint64_t>(bytesPerRow_));
    for (int rowIndex = kStartRowIndex; rowIndex <= kEndRowIndex; ++rowIndex)
    {
        updateRowHighlightByRow(rowIndex);
    }
}

bool HexEditorWidget::rowColumnToOffset(
    const int row,
    const int column,
    std::uint64_t& offsetOut) const
{
    if (row < 0 || column <= 0)
    {
        return false;
    }

    // Map ASCII columns uniformly to 'the first byte of the row' to prevent failures when right-clicking or selecting the current cell in an ASCII column.
    int normalizedColumn = column;
    if (normalizedColumn == bytesPerRow_ + 1)
    {
        normalizedColumn = 1;
    }
    if (normalizedColumn > bytesPerRow_)
    {
        return false;
    }

    const std::uint64_t kOffset =
        static_cast<std::uint64_t>(row) * static_cast<std::uint64_t>(bytesPerRow_) +
        static_cast<std::uint64_t>(normalizedColumn - 1);

    if (kOffset >= static_cast<std::uint64_t>(buffer_.size()))
    {
        return false;
    }

    offsetOut = kOffset;
    return true;
}

bool HexEditorWidget::offsetToRowColumn(
    const std::uint64_t offset,
    int& rowOut,
    int& columnOut) const
{
    if (offset >= static_cast<std::uint64_t>(buffer_.size()))
    {
        return false;
    }

    rowOut = static_cast<int>(offset / static_cast<std::uint64_t>(bytesPerRow_));
    columnOut = static_cast<int>(offset % static_cast<std::uint64_t>(bytesPerRow_)) + 1;
    return true;
}

bool HexEditorWidget::viewportPosToOffset(
    const QPoint& viewportPos,
    std::uint64_t& offsetOut) const
{
    if (hexTable_ == nullptr || buffer_.isEmpty())
    {
        return false;
    }

    const int kRowCount = hexTable_->rowCount();
    if (kRowCount <= 0)
    {
        return false;
    }

    int rowIndex = hexTable_->rowAt(viewportPos.y());
    if (rowIndex < 0)
    {
        rowIndex = (viewportPos.y() < 0) ? 0 : (kRowCount - 1);
    }
    rowIndex = std::clamp(rowIndex, 0, kRowCount - 1);

    int columnIndex = hexTable_->columnAt(viewportPos.x());
    if (columnIndex < 1)
    {
        columnIndex = 1;
    }

    // Map the ASCII column to specific bytes by character position to fix 'ASCII region cannot be selected continuously across rows'.
    if (columnIndex == bytesPerRow_ + 1)
    {
        const std::uint64_t kRowStartOffset =
            static_cast<std::uint64_t>(rowIndex) * static_cast<std::uint64_t>(bytesPerRow_);
        const std::uint64_t kRemainBytes =
            static_cast<std::uint64_t>(buffer_.size()) > kRowStartOffset
            ? static_cast<std::uint64_t>(buffer_.size()) - kRowStartOffset
            : 0;
        const int kValidBytesInRow = static_cast<int>(
            std::min<std::uint64_t>(static_cast<std::uint64_t>(bytesPerRow_), kRemainBytes));
        if (kValidBytesInRow <= 0)
        {
            return false;
        }

        const QModelIndex kAsciiModelIndex = hexTable_->model()->index(rowIndex, bytesPerRow_ + 1);
        const QRect kAsciiRect = hexTable_->visualRect(kAsciiModelIndex);
        const QFontMetrics kFontMetrics(hexTable_->font());
        const int kCharWidth = std::max(1, kFontMetrics.horizontalAdvance(QChar('M')));
        const int kRelativeX = std::max(0, viewportPos.x() - kAsciiRect.left());
        int charIndex = kRelativeX / kCharWidth;
        charIndex = std::clamp(charIndex, 0, kValidBytesInRow - 1);

        offsetOut = kRowStartOffset + static_cast<std::uint64_t>(charIndex);
        return true;
    }

    if (columnIndex > bytesPerRow_)
    {
        columnIndex = bytesPerRow_;
    }

    const std::uint64_t kRawOffset =
        static_cast<std::uint64_t>(rowIndex) * static_cast<std::uint64_t>(bytesPerRow_)
        + static_cast<std::uint64_t>(columnIndex - 1);
    const std::uint64_t kMaxOffset = static_cast<std::uint64_t>(buffer_.size() - 1);
    offsetOut = std::min(kRawOffset, kMaxOffset);
    return true;
}

std::vector<std::uint64_t> HexEditorWidget::collectSelectedOffsets() const
{
    std::vector<std::uint64_t> offsetList;
    if (selectionRangeValid_)
    {
        const std::uint64_t kRangeStartOffset = std::min(selectionRangeStartOffset_, selectionRangeEndOffset_);
        const std::uint64_t kRangeEndOffset = std::max(selectionRangeStartOffset_, selectionRangeEndOffset_);
        for (std::uint64_t offset = kRangeStartOffset; offset <= kRangeEndOffset; ++offset)
        {
            if (offset >= static_cast<std::uint64_t>(buffer_.size()))
            {
                break;
            }
            offsetList.push_back(offset);
        }
        return offsetList;
    }

    if (hexTable_ == nullptr)
    {
        return offsetList;
    }

    // Read selectedIndexes directly to avoid extra bytes from rectangular merging in selectedRanges.
    const QModelIndexList kSelectedIndexList = hexTable_->selectionModel()->selectedIndexes();
    for (const QModelIndex& modelIndex : kSelectedIndexList)
    {
        if (!modelIndex.isValid())
        {
            continue;
        }

        std::uint64_t offset = 0;
        if (!rowColumnToOffset(modelIndex.row(), modelIndex.column(), offset))
        {
            continue;
        }
        offsetList.push_back(offset);
    }

    std::sort(offsetList.begin(), offsetList.end());
    offsetList.erase(std::unique(offsetList.begin(), offsetList.end()), offsetList.end());
    return offsetList;
}

void HexEditorWidget::copySelectedAsHex()
{
    const std::vector<std::uint64_t> kOffsetList = collectSelectedOffsets();
    if (kOffsetList.empty())
    {
        updateStatusLabel(QStringLiteral("复制失败：未选中有效字节。"));
        return;
    }

    QStringList byteTextList;
    byteTextList.reserve(static_cast<int>(kOffsetList.size()));
    for (const std::uint64_t kOffset : kOffsetList)
    {
        const std::uint8_t kByteValue = static_cast<std::uint8_t>(buffer_.at(static_cast<int>(kOffset)));
        byteTextList.push_back(byteToHexText(kByteValue));
    }

    if (QApplication::clipboard() != nullptr)
    {
        QApplication::clipboard()->setText(byteTextList.join(' '));
    }

    updateStatusLabel(
        QStringLiteral("已复制 %1 字节 HEX。")
        .arg(static_cast<qulonglong>(kOffsetList.size())));
}

void HexEditorWidget::copySelectedAsAscii()
{
    const std::vector<std::uint64_t> kOffsetList = collectSelectedOffsets();
    if (kOffsetList.empty())
    {
        updateStatusLabel(QStringLiteral("复制失败：未选中有效字节。"));
        return;
    }

    QString asciiText;
    asciiText.reserve(static_cast<int>(kOffsetList.size()));
    for (const std::uint64_t kOffset : kOffsetList)
    {
        const std::uint8_t kByteValue = static_cast<std::uint8_t>(buffer_.at(static_cast<int>(kOffset)));
        const bool kPrintable = (kByteValue >= 32 && kByteValue <= 126);
        asciiText.push_back(kPrintable ? QChar(kByteValue) : QChar('.'));
    }

    if (QApplication::clipboard() != nullptr)
    {
        QApplication::clipboard()->setText(asciiText);
    }

    updateStatusLabel(
        QStringLiteral("已复制 %1 字节 ASCII。")
        .arg(static_cast<qulonglong>(kOffsetList.size())));
}

void HexEditorWidget::copyCurrentAddress()
{
    const std::uint64_t kAbsoluteAddress = selectedAbsoluteAddress();
    const QString kAddressText = QStringLiteral("0x%1")
        .arg(static_cast<qulonglong>(kAbsoluteAddress), 16, 16, QChar('0')).toUpper();

    if (QApplication::clipboard() != nullptr)
    {
        QApplication::clipboard()->setText(kAddressText);
    }

    updateStatusLabel(QStringLiteral("已复制地址：%1").arg(kAddressText));
}

void HexEditorWidget::copyCurrentRowDump()
{
    if (hexTable_ == nullptr)
    {
        return;
    }

    const int kCurrentRow = hexTable_->currentRow();
    if (kCurrentRow < 0)
    {
        updateStatusLabel(QStringLiteral("复制失败：未定位到当前行。"));
        return;
    }

    const QString kRowDumpText = buildRowDumpText(kCurrentRow);
    if (QApplication::clipboard() != nullptr)
    {
        QApplication::clipboard()->setText(kRowDumpText);
    }

    updateStatusLabel(QStringLiteral("已复制当前行转储文本。"));
}

void HexEditorWidget::exportBinaryFile()
{
    if (buffer_.isEmpty())
    {
        updateStatusLabel(QStringLiteral("导出失败：当前无数据。"));
        return;
    }

    const QString kFilePath = QFileDialog::getSaveFileName(
        this,
        QStringLiteral("导出二进制"),
        QStringLiteral("hex_export.bin"),
        QStringLiteral("Binary Files (*.bin);;All Files (*.*)"));
    if (kFilePath.trimmed().isEmpty())
    {
        return;
    }

    QFile outputFile(kFilePath);
    if (!outputFile.open(QIODevice::WriteOnly | QIODevice::Truncate))
    {
        QMessageBox::warning(this, QStringLiteral("导出失败"), QStringLiteral("无法写入文件：%1").arg(kFilePath));
        return;
    }

    outputFile.write(buffer_);
    outputFile.close();

    updateStatusLabel(
        QStringLiteral("导出完成：%1 字节 -> %2")
        .arg(static_cast<qulonglong>(buffer_.size()))
        .arg(kFilePath));
}

void HexEditorWidget::exportHexTextFile()
{
    if (buffer_.isEmpty())
    {
        updateStatusLabel(QStringLiteral("导出失败：当前无数据。"));
        return;
    }

    const QString kFilePath = QFileDialog::getSaveFileName(
        this,
        QStringLiteral("导出 HEX 文本"),
        QStringLiteral("hex_export.txt"),
        QStringLiteral("Text Files (*.txt);;All Files (*.*)"));
    if (kFilePath.trimmed().isEmpty())
    {
        return;
    }

    QFile outputFile(kFilePath);
    if (!outputFile.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text))
    {
        QMessageBox::warning(this, QStringLiteral("导出失败"), QStringLiteral("无法写入文件：%1").arg(kFilePath));
        return;
    }

    QTextStream outputStream(&outputFile);
    outputStream.setEncoding(QStringConverter::Utf8);
    outputStream << buildFullDumpText();
    outputFile.close();

    updateStatusLabel(
        QStringLiteral("导出完成：HEX 文本 -> %1").arg(kFilePath));
}

void HexEditorWidget::exportSelectedHexDataFile()
{
    const std::vector<std::uint64_t> kOffsetList = collectSelectedOffsets();
    if (kOffsetList.empty())
    {
        updateStatusLabel(QStringLiteral("导出失败：未选中有效字节。"));
        return;
    }

    const QString kFilePath = QFileDialog::getSaveFileName(
        this,
        QStringLiteral("导出选中 HEX 数据"),
        QStringLiteral("hex_selected.txt"),
        QStringLiteral("Text Files (*.txt);;All Files (*.*)"));
    if (kFilePath.trimmed().isEmpty())
    {
        return;
    }

    QFile outputFile(kFilePath);
    if (!outputFile.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text))
    {
        QMessageBox::warning(this, QStringLiteral("导出失败"), QStringLiteral("无法写入文件：%1").arg(kFilePath));
        return;
    }

    QTextStream outputStream(&outputFile);
    outputStream.setEncoding(QStringConverter::Utf8);

    bool firstByte = true;
    for (const std::uint64_t kOffset : kOffsetList)
    {
        if (!firstByte)
        {
            outputStream << ' ';
        }
        firstByte = false;
        const std::uint8_t kByteValue = static_cast<std::uint8_t>(buffer_.at(static_cast<int>(kOffset)));
        outputStream << byteToHexText(kByteValue);
    }
    outputFile.close();

    updateStatusLabel(
        QStringLiteral("导出完成：%1 字节 HEX 数据 -> %2")
        .arg(static_cast<qulonglong>(kOffsetList.size()))
        .arg(kFilePath));
}

QString HexEditorWidget::buildRowDumpText(const int rowIndex) const
{
    if (rowIndex < 0)
    {
        return QString();
    }

    const std::uint64_t kRowOffset = static_cast<std::uint64_t>(rowIndex) * static_cast<std::uint64_t>(bytesPerRow_);
    QStringList byteList;
    byteList.reserve(bytesPerRow_);

    QString asciiText;
    asciiText.reserve(bytesPerRow_);

    for (int byteColumn = 0; byteColumn < bytesPerRow_; ++byteColumn)
    {
        const std::uint64_t kByteOffset = kRowOffset + static_cast<std::uint64_t>(byteColumn);
        if (kByteOffset < static_cast<std::uint64_t>(buffer_.size()))
        {
            const std::uint8_t kByteValue = static_cast<std::uint8_t>(buffer_.at(static_cast<int>(kByteOffset)));
            byteList.push_back(byteToHexText(kByteValue));
            const bool kPrintable = (kByteValue >= 32 && kByteValue <= 126);
            asciiText.push_back(kPrintable ? QChar(kByteValue) : QChar('.'));
        }
        else
        {
            byteList.push_back(QStringLiteral("--"));
            asciiText.push_back(' ');
        }
    }

    return QStringLiteral("%1  %2  |%3|")
        .arg(QStringLiteral("0x%1").arg(static_cast<qulonglong>(baseAddress_ + kRowOffset), 16, 16, QChar('0')).toUpper())
        .arg(byteList.join(' '))
        .arg(asciiText);
}

QString HexEditorWidget::buildFullDumpText() const
{
    if (buffer_.isEmpty())
    {
        return QStringLiteral("<empty>");
    }

    QStringList rowTextList;
    const int kRowCount = (buffer_.size() + bytesPerRow_ - 1) / bytesPerRow_;
    rowTextList.reserve(kRowCount);

    for (int rowIndex = 0; rowIndex < kRowCount; ++rowIndex)
    {
        rowTextList.push_back(buildRowDumpText(rowIndex));
    }
    return rowTextList.join('\n');
}
