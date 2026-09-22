#include "HexEditorWidget.Internal.h"
#include "VisibleTableWidget.h"

// Note: Migrated from the original aggregated implementation to a standalone .cpp file; member function implementations remain unchanged.
using namespace ksword::ui::hex_editor_internal;

// ============================================================
// HexEditorWidget.Ui.cpp
// Purpose: Handle UI creation, signal connections, table reconstruction, and highlight refresh logic.
// ============================================================

void HexEditorWidget::initializeUi()
{
    rootLayout_ = new QVBoxLayout(this);
    rootLayout_->setContentsMargins(0, 0, 0, 0);
    rootLayout_->setSpacing(6);

    // Top toolbar: summary + line width + find/jump/export.
    QWidget* toolbarWidget = new QWidget(this);
    toolbarLayout_ = new QHBoxLayout(toolbarWidget);
    toolbarLayout_->setContentsMargins(0, 0, 0, 0);
    toolbarLayout_->setSpacing(6);

    summaryLabel_ = new QLabel(toolbarWidget);
    summaryLabel_->setText(QStringLiteral("长度: 0 字节 | 基址: 0x0000000000000000"));

    bytesPerRowCombo_ = new QComboBox(toolbarWidget);
    bytesPerRowCombo_->addItem(QStringLiteral("8/行"), 8);
    bytesPerRowCombo_->addItem(QStringLiteral("16/行"), 16);
    bytesPerRowCombo_->addItem(QStringLiteral("32/行"), 32);
    bytesPerRowCombo_->addItem(QStringLiteral("48/行"), 48);
    bytesPerRowCombo_->addItem(QStringLiteral("64/行"), 64);
    bytesPerRowCombo_->setToolTip(QStringLiteral("设置每行显示字节数"));

    findButton_ = new QToolButton(toolbarWidget);
    findButton_->setText(QStringLiteral("查找"));
    findButton_->setToolTip(QStringLiteral("打开查找面板（Ctrl+F）"));

    jumpButton_ = new QToolButton(toolbarWidget);
    jumpButton_->setText(QStringLiteral("跳转"));
    jumpButton_->setToolTip(QStringLiteral("打开跳转面板（Ctrl+G）"));

    exportButton_ = new QToolButton(toolbarWidget);
    exportButton_->setText(QStringLiteral("导出"));
    exportButton_->setToolTip(QStringLiteral("导出当前缓冲区"));

    const QString kToolbarButtonStyle = buildToolbarButtonStyle();
    findButton_->setStyleSheet(kToolbarButtonStyle);
    jumpButton_->setStyleSheet(kToolbarButtonStyle);
    exportButton_->setStyleSheet(kToolbarButtonStyle);
    bytesPerRowCombo_->setStyleSheet(buildInputStyle());

    toolbarLayout_->addWidget(summaryLabel_, 1);
    toolbarLayout_->addWidget(new QLabel(QStringLiteral("行宽"), toolbarWidget));
    toolbarLayout_->addWidget(bytesPerRowCombo_);
    toolbarLayout_->addWidget(findButton_);
    toolbarLayout_->addWidget(jumpButton_);
    toolbarLayout_->addWidget(exportButton_);

    rootLayout_->addWidget(toolbarWidget);

    // Find panel: hidden by default, shown on demand.
    findPanel_ = new QWidget(this);
    findLayout_ = new QHBoxLayout(findPanel_);
    findLayout_->setContentsMargins(0, 0, 0, 0);
    findLayout_->setSpacing(6);

    findModeCombo_ = new QComboBox(findPanel_);
    findModeCombo_->addItem(QStringLiteral("HEX字节"), static_cast<int>(SearchMode::kHexBytes));
    findModeCombo_->addItem(QStringLiteral("ASCII文本"), static_cast<int>(SearchMode::kAsciiText));
    findModeCombo_->addItem(QStringLiteral("UTF-16文本"), static_cast<int>(SearchMode::kUtf16Text));
    findModeCombo_->setToolTip(QStringLiteral("查找模式"));

    findEdit_ = new QLineEdit(findPanel_);
    findEdit_->setPlaceholderText(QStringLiteral("HEX模式示例：4D 5A ?? 90；ASCII模式示例：HTTP"));
    findEdit_->setToolTip(QStringLiteral("输入查找内容，回车查找下一个"));

    findPrevButton_ = new QToolButton(findPanel_);
    findPrevButton_->setText(QStringLiteral("上一个"));
    findPrevButton_->setToolTip(QStringLiteral("跳转到上一个命中（Shift+F3）"));

    findNextButton_ = new QToolButton(findPanel_);
    findNextButton_->setText(QStringLiteral("下一个"));
    findNextButton_->setToolTip(QStringLiteral("跳转到下一个命中（F3）"));

    findCloseButton_ = new QToolButton(findPanel_);
    findCloseButton_->setText(QStringLiteral("关闭"));
    findCloseButton_->setToolTip(QStringLiteral("关闭查找面板"));

    findResultLabel_ = new QLabel(QStringLiteral("命中: -"), findPanel_);

    findModeCombo_->setStyleSheet(buildInputStyle());
    findEdit_->setStyleSheet(buildInputStyle());
    findPrevButton_->setStyleSheet(kToolbarButtonStyle);
    findNextButton_->setStyleSheet(kToolbarButtonStyle);
    findCloseButton_->setStyleSheet(kToolbarButtonStyle);

    findLayout_->addWidget(new QLabel(QStringLiteral("查找"), findPanel_));
    findLayout_->addWidget(findModeCombo_);
    findLayout_->addWidget(findEdit_, 1);
    findLayout_->addWidget(findPrevButton_);
    findLayout_->addWidget(findNextButton_);
    findLayout_->addWidget(findResultLabel_);
    findLayout_->addWidget(findCloseButton_);

    findPanel_->setVisible(false);
    rootLayout_->addWidget(findPanel_);

    // Jump panel: hidden by default, supports address/offset/line number.
    jumpPanel_ = new QWidget(this);
    jumpLayout_ = new QHBoxLayout(jumpPanel_);
    jumpLayout_->setContentsMargins(0, 0, 0, 0);
    jumpLayout_->setSpacing(6);

    jumpModeCombo_ = new QComboBox(jumpPanel_);
    jumpModeCombo_->addItem(QStringLiteral("绝对地址"), 0);
    jumpModeCombo_->addItem(QStringLiteral("相对偏移"), 1);
    jumpModeCombo_->addItem(QStringLiteral("行号"), 2);
    jumpModeCombo_->setToolTip(QStringLiteral("跳转模式"));

    jumpEdit_ = new QLineEdit(jumpPanel_);
    jumpEdit_->setPlaceholderText(QStringLiteral("输入十进制或 0x 十六进制数值"));
    jumpEdit_->setToolTip(QStringLiteral("例如：0x401000 / 256 / 0x20"));

    jumpApplyButton_ = new QToolButton(jumpPanel_);
    jumpApplyButton_->setText(QStringLiteral("执行"));
    jumpApplyButton_->setToolTip(QStringLiteral("执行跳转"));

    jumpCloseButton_ = new QToolButton(jumpPanel_);
    jumpCloseButton_->setText(QStringLiteral("关闭"));
    jumpCloseButton_->setToolTip(QStringLiteral("关闭跳转面板"));

    jumpModeCombo_->setStyleSheet(buildInputStyle());
    jumpEdit_->setStyleSheet(buildInputStyle());
    jumpApplyButton_->setStyleSheet(kToolbarButtonStyle);
    jumpCloseButton_->setStyleSheet(kToolbarButtonStyle);

    jumpLayout_->addWidget(new QLabel(QStringLiteral("跳转"), jumpPanel_));
    jumpLayout_->addWidget(jumpModeCombo_);
    jumpLayout_->addWidget(jumpEdit_, 1);
    jumpLayout_->addWidget(jumpApplyButton_);
    jumpLayout_->addWidget(jumpCloseButton_);

    jumpPanel_->setVisible(false);
    rootLayout_->addWidget(jumpPanel_);

    // Main view area: HEX and ASCII pages.
    viewTabWidget_ = new QTabWidget(this);
    viewTabWidget_->setDocumentMode(true);
    hexViewPage_ = new QWidget(viewTabWidget_);
    QVBoxLayout* hexPageLayout = new QVBoxLayout(hexViewPage_);
    hexPageLayout->setContentsMargins(0, 0, 0, 0);
    hexPageLayout->setSpacing(0);

    // HEX page main table: Address column + Byte column + ASCII column.
    hexTable_ = new ks::ui::VisibleTableWidget(hexViewPage_);
    ks::ui::setPreserveCustomTableHeaderStyle(hexTable_, true);
    hexTable_->setColumnCount(bytesPerRow_ + 2);
    hexTable_->setRowCount(1);
    // Use ExtendedSelection:
    // - Linear multi-row selection in a 2D table is not strictly rectangular.
    // - ContiguousSelection actively constrains and consumes certain selection states, causing visual highlighting anomalies.
    hexTable_->setSelectionMode(QAbstractItemView::ExtendedSelection);
    hexTable_->setSelectionBehavior(QAbstractItemView::SelectItems);
    hexTable_->setEditTriggers(
        QAbstractItemView::AnyKeyPressed
        | QAbstractItemView::EditKeyPressed
        | QAbstractItemView::SelectedClicked
        | QAbstractItemView::DoubleClicked);
    hexTable_->setAlternatingRowColors(true);
    hexTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    hexTable_->verticalHeader()->setVisible(false);
    hexTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    hexTable_->horizontalHeader()->setStretchLastSection(true);
    hexTable_->horizontalHeader()->setStyleSheet(buildHeaderStyle());
    hexTable_->setShowGrid(false);
    hexTable_->setFrameShape(QFrame::NoFrame);
    hexTable_->setStyleSheet(
        QStringLiteral(
            "QTableView{"
            "  border:none;"
            "  gridline-color:transparent;"
            "  outline:none;"
            "  background:%1;"
            "  alternate-background-color:%2;"
            "  color:%3;"
            "}"
            "QTableView::item{"
            "  border:none;"
            "  color:%3;"
            "}"
        "QTableCornerButton::section{"
            "  background:transparent; /* %1 */"
            "  border:none;"
            "}")
        .arg(ksword_theme::surfaceHex())
        .arg(ksword_theme::surfaceAltHex())
        .arg(ksword_theme::textPrimaryHex()));

    // Increase table font size and fix it to monospace for easier hexadecimal content editing.
    QFont fixedFont = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    // When the system monospace font lacks Chinese glyphs, Windows falls back to SimSun; explicitly specify Microsoft YaHei for Chinese text.
    fixedFont.setFamilies(QStringList{ fixedFont.family(), QStringLiteral("Microsoft YaHei UI") });
    fixedFont.setPointSize(std::max(fixedFont.pointSize(), 12));
    // ksword_preserve_custom_font: Prevents global table font refresh from overwriting the monospace font required for HEX alignment.
    hexTable_->setProperty("ksword_preserve_custom_font", true);
    hexTable_->horizontalHeader()->setProperty("ksword_preserve_custom_font", true);
    hexTable_->verticalHeader()->setProperty("ksword_preserve_custom_font", true);
    hexTable_->setFont(fixedFont);
    hexTable_->horizontalHeader()->setFont(fixedFont);
    hexTable_->verticalHeader()->setFont(fixedFont);

    // Show I-beam cursor on mouse hover to emphasize the 'direct input' editing experience.
    hexTable_->viewport()->setCursor(Qt::IBeamCursor);
    hexTable_->setCursor(Qt::IBeamCursor);
    hexTable_->viewport()->installEventFilter(this);
    hexPageLayout->addWidget(hexTable_, 1);
    viewTabWidget_->addTab(hexViewPage_, QStringLiteral("HEX"));

    asciiViewPage_ = new QWidget(viewTabWidget_);
    QVBoxLayout* asciiPageLayout = new QVBoxLayout(asciiViewPage_);
    asciiPageLayout->setContentsMargins(0, 0, 0, 0);
    asciiPageLayout->setSpacing(0);
    asciiEditor_ = new CodeEditorWidget(asciiViewPage_);
    asciiEditor_->setReadOnly(true);
    asciiEditor_->setLocalizedText(QStringLiteral("当前无数据。"));
    asciiPageLayout->addWidget(asciiEditor_, 1);
    viewTabWidget_->addTab(asciiViewPage_, QStringLiteral("ASCII"));

    rootLayout_->addWidget(viewTabWidget_, 1);

    // Selection inspector: displays multiple interpretations of the currently selected bytes.
    initializeSelectionInspector();
    rootLayout_->addWidget(selectionInspectorPanel_);

    // Bottom status text: reports operation success or failure.
    statusLabel_ = new QLabel(QStringLiteral("就绪。"), this);
    rootLayout_->addWidget(statusLabel_);

    // Shortcuts: Find, Jump, Navigate to Hit, Copy.
    findShortcut_ = new QShortcut(QKeySequence::Find, this);
    jumpShortcut_ = new QShortcut(QKeySequence(QStringLiteral("Ctrl+G")), this);
    findNextShortcut_ = new QShortcut(QKeySequence::FindNext, this);
    findPrevShortcut_ = new QShortcut(QKeySequence::FindPrevious, this);
    copyHexShortcut_ = new QShortcut(QKeySequence::Copy, this);
    copyAsciiShortcut_ = new QShortcut(QKeySequence(QStringLiteral("Ctrl+Shift+C")), this);

    updateHeaderText();
    updateSummaryLabel();
    updateSelectionInspector();
    refreshAsciiTabText();
}

void HexEditorWidget::initializeConnections()
{
    connect(bytesPerRowCombo_, &QComboBox::currentIndexChanged, this, [this](const int indexValue)
        {
            if (indexValue < 0)
            {
                return;
            }
            const int kBytesPerRowValue = bytesPerRowCombo_->itemData(indexValue).toInt();
            setBytesPerRow(kBytesPerRowValue);
        });

    connect(findButton_, &QToolButton::clicked, this, [this]()
        {
            openFindPanel();
        });
    connect(jumpButton_, &QToolButton::clicked, this, [this]()
        {
            openJumpPanel();
        });
    connect(exportButton_, &QToolButton::clicked, this, [this]()
        {
            QMenu exportMenu(this);
            exportMenu.setStyleSheet(buildMenuStyle());
            QAction* binaryAction = exportMenu.addAction(QStringLiteral("导出二进制"));
            QAction* textAction = exportMenu.addAction(QStringLiteral("导出HEX文本"));
            QAction* selectedHexAction = exportMenu.addAction(QStringLiteral("导出选中HEX数据"));
            selectedHexAction->setEnabled(!collectSelectedOffsets().empty());
            QAction* selectedAction = exportMenu.exec(exportButton_->mapToGlobal(QPoint(0, exportButton_->height())));
            if (selectedAction == binaryAction)
            {
                exportBinaryFile();
                return;
            }
            if (selectedAction == textAction)
            {
                exportHexTextFile();
                return;
            }
            if (selectedAction == selectedHexAction)
            {
                exportSelectedHexDataFile();
            }
        });

    connect(findCloseButton_, &QToolButton::clicked, this, [this]()
        {
            findPanel_->setVisible(false);
        });
    connect(jumpCloseButton_, &QToolButton::clicked, this, [this]()
        {
            jumpPanel_->setVisible(false);
        });

    connect(findEdit_, &QLineEdit::returnPressed, this, [this]()
        {
            const std::uint64_t kCurrentOffset = selectedOffset();
            const std::uint64_t kStartOffset =
                (buffer_.isEmpty() || kCurrentOffset + 1 >= static_cast<std::uint64_t>(buffer_.size()))
                ? 0
                : (kCurrentOffset + 1);
            if (!ensureSearchResultReady(NavigateDirection::kNext, kStartOffset))
            {
                return;
            }
            gotoMatchByDirection(NavigateDirection::kNext, kStartOffset);
        });

    connect(findNextButton_, &QToolButton::clicked, this, [this]()
        {
            const std::uint64_t kCurrentOffset = selectedOffset();
            const std::uint64_t kStartOffset =
                (buffer_.isEmpty() || kCurrentOffset + 1 >= static_cast<std::uint64_t>(buffer_.size()))
                ? 0
                : (kCurrentOffset + 1);
            if (!ensureSearchResultReady(NavigateDirection::kNext, kStartOffset))
            {
                return;
            }
            gotoMatchByDirection(NavigateDirection::kNext, kStartOffset);
        });

    connect(findPrevButton_, &QToolButton::clicked, this, [this]()
        {
            const std::uint64_t kCurrentOffset = selectedOffset();
            const std::uint64_t kStartOffset =
                (buffer_.isEmpty())
                ? 0
                : ((kCurrentOffset == 0) ? static_cast<std::uint64_t>(buffer_.size() - 1) : (kCurrentOffset - 1));
            if (!ensureSearchResultReady(NavigateDirection::kPrevious, kStartOffset))
            {
                return;
            }
            gotoMatchByDirection(NavigateDirection::kPrevious, kStartOffset);
        });

    connect(jumpApplyButton_, &QToolButton::clicked, this, [this]()
        {
            if (jumpEdit_ == nullptr || jumpModeCombo_ == nullptr)
            {
                return;
            }

            std::uint64_t targetValue = 0;
            if (!parseAddressNumber(jumpEdit_->text(), targetValue))
            {
                updateStatusLabel(QStringLiteral("跳转失败：输入格式无效。"));
                return;
            }

            const int kJumpMode = jumpModeCombo_->currentData().toInt();
            bool jumpOk = false;
            if (kJumpMode == 0)
            {
                jumpOk = jumpToAbsoluteAddress(targetValue);
            }
            else if (kJumpMode == 1)
            {
                jumpOk = jumpToOffset(targetValue);
            }
            else
            {
                jumpOk = jumpToRow(targetValue);
            }

            if (jumpOk)
            {
                jumpPanel_->setVisible(false);
            }
        });

    connect(jumpEdit_, &QLineEdit::returnPressed, this, [this]()
        {
            jumpApplyButton_->click();
        });

    connect(hexTable_, &QTableWidget::itemChanged, this, [this](QTableWidgetItem* changedItem)
        {
            if (ignoreItemChanged_ || changedItem == nullptr)
            {
                return;
            }

            const int kRowIndex = changedItem->row();
            const int kColumnIndex = changedItem->column();

            std::uint64_t offset = 0;
            if (!rowColumnToOffset(kRowIndex, kColumnIndex, offset))
            {
                return;
            }

            bool parseOk = false;
            const int kParsedValue = changedItem->text().trimmed().toInt(&parseOk, 16);
            if (!parseOk || kParsedValue < 0 || kParsedValue > 0xFF)
            {
                updateStatusLabel(QStringLiteral("编辑失败：请输入两位十六进制字节。"));
                ignoreItemChanged_ = true;
                const std::uint8_t kOldByte = static_cast<std::uint8_t>(buffer_.at(static_cast<int>(offset)));
                changedItem->setText(byteToHexText(kOldByte));
                ignoreItemChanged_ = false;
                return;
            }

            const std::uint8_t kOldValue = static_cast<std::uint8_t>(buffer_.at(static_cast<int>(offset)));
            const std::uint8_t kNewValue = static_cast<std::uint8_t>(kParsedValue);
            if (kOldValue == kNewValue)
            {
                changedItem->setText(byteToHexText(kNewValue));
                return;
            }

            // Notify external components after updating the local buffer.
            buffer_[static_cast<int>(offset)] = static_cast<char>(kNewValue);
            ++bufferRevision_;

            // Uniformly rewrite input format to two-digit uppercase HEX.
            ignoreItemChanged_ = true;
            changedItem->setText(byteToHexText(kNewValue));
            updateAsciiCellByRow(kRowIndex);
            refreshAsciiTabText();
            updateRowHighlightByRow(kRowIndex);
            ignoreItemChanged_ = false;

            emit byteEdited(baseAddress_ + offset, kOldValue, kNewValue);

            // Automatically move to the next byte cell after a successful edit to improve continuous editing efficiency.
            const std::uint64_t kNextOffset = offset + 1;
            if (kNextOffset < static_cast<std::uint64_t>(buffer_.size()))
            {
                int nextRow = 0;
                int nextColumn = 0;
                if (offsetToRowColumn(kNextOffset, nextRow, nextColumn))
                {
                    hexTable_->setCurrentCell(nextRow, nextColumn);
                    hexTable_->setFocus(Qt::OtherFocusReason);
                }
            }
        });

    connect(hexTable_, &QTableWidget::currentCellChanged, this,
        [this](int currentRow, int currentColumn, int previousRow, int previousColumn)
        {
            Q_UNUSED(previousRow);
            Q_UNUSED(previousColumn);

            std::uint64_t offset = 0;
            if (!rowColumnToOffset(currentRow, currentColumn, offset))
            {
                updateSelectionInspector();
                return;
            }
            emit currentAddressChanged(baseAddress_ + offset);
            updateSelectionInspector();
        });

    connect(hexTable_, &QTableWidget::itemSelectionChanged, this, [this]()
        {
            updateSelectionInspector();
        });

    connect(hexTable_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& localPosition)
        {
            QTableWidgetItem* clickedItem = hexTable_->itemAt(localPosition);

            std::uint64_t clickedOffset = 0;
            bool hasByte = false;
            if (clickedItem != nullptr)
            {
                hasByte = rowColumnToOffset(clickedItem->row(), clickedItem->column(), clickedOffset);
                // When right-clicking an unselected cell, set that byte as the current selection first to ensure copying strictly targets the current item.
                if (hasByte && !clickedItem->isSelected())
                {
                    selectionVisualAsciiColumn_ = (clickedItem->column() == (bytesPerRow_ + 1));
                    selectRangeByOffset(clickedOffset, 1, false);
                }
            }

            const std::uint64_t kAbsoluteAddress = baseAddress_ + clickedOffset;
            const bool kHasSelection = !collectSelectedOffsets().empty();

            QMenu menu(this);
            menu.setStyleSheet(buildMenuStyle());
            QAction* copyHexAction = menu.addAction(QStringLiteral("复制 HEX"));
            QAction* copyAsciiAction = menu.addAction(QStringLiteral("复制 ASCII"));
            QAction* copyAddressAction = menu.addAction(QStringLiteral("复制地址"));
            QAction* copyRowAction = menu.addAction(QStringLiteral("复制当前行"));
            menu.addSeparator();
            QAction* findAction = menu.addAction(QStringLiteral("查找（Ctrl+F）"));
            QAction* jumpAction = menu.addAction(QStringLiteral("跳转（Ctrl+G）"));
            menu.addSeparator();
            QAction* exportBinaryAction = menu.addAction(QStringLiteral("导出二进制"));
            QAction* exportTextAction = menu.addAction(QStringLiteral("导出 HEX 文本"));
            QAction* exportSelectedHexAction = menu.addAction(QStringLiteral("导出选中 HEX 数据"));

            if (!kHasSelection)
            {
                copyHexAction->setEnabled(false);
                copyAsciiAction->setEnabled(false);
                exportSelectedHexAction->setEnabled(false);
            }

            if (!hasByte)
            {
                copyAddressAction->setEnabled(false);
                copyRowAction->setEnabled(false);
            }

            emit aboutToShowContextMenu(&menu, kAbsoluteAddress, hasByte);

            QAction* selectedAction = menu.exec(hexTable_->viewport()->mapToGlobal(localPosition));
            if (selectedAction == nullptr)
            {
                return;
            }

            if (selectedAction == copyHexAction)
            {
                copySelectedAsHex();
                return;
            }
            if (selectedAction == copyAsciiAction)
            {
                copySelectedAsAscii();
                return;
            }
            if (selectedAction == copyAddressAction)
            {
                copyCurrentAddress();
                return;
            }
            if (selectedAction == copyRowAction)
            {
                copyCurrentRowDump();
                return;
            }
            if (selectedAction == findAction)
            {
                openFindPanel();
                return;
            }
            if (selectedAction == jumpAction)
            {
                openJumpPanel();
                return;
            }
            if (selectedAction == exportBinaryAction)
            {
                exportBinaryFile();
                return;
            }
            if (selectedAction == exportTextAction)
            {
                exportHexTextFile();
                return;
            }
            if (selectedAction == exportSelectedHexAction)
            {
                exportSelectedHexDataFile();
            }
        });

    connect(findShortcut_, &QShortcut::activated, this, [this]()
        {
            openFindPanel();
        });
    connect(jumpShortcut_, &QShortcut::activated, this, [this]()
        {
            openJumpPanel();
        });
    connect(findNextShortcut_, &QShortcut::activated, this, [this]()
        {
            findNextButton_->click();
        });
    connect(findPrevShortcut_, &QShortcut::activated, this, [this]()
        {
            findPrevButton_->click();
        });
    connect(copyHexShortcut_, &QShortcut::activated, this, [this]()
        {
            copySelectedAsHex();
        });
    connect(copyAsciiShortcut_, &QShortcut::activated, this, [this]()
        {
            copySelectedAsAscii();
        });

    connect(viewTabWidget_, &QTabWidget::currentChanged, this, [this](const int indexValue)
        {
            const bool kHexPageActive = (indexValue == 0);
            if (selectionInspectorPanel_ != nullptr)
            {
                selectionInspectorPanel_->setVisible(kHexPageActive);
            }
            if (!kHexPageActive)
            {
                refreshAsciiTabText();
            }
        });
}

void HexEditorWidget::rebuildTable()
{
    if (hexTable_ == nullptr)
    {
        return;
    }

    // Update the header before rebuilding to ensure column count syncs with m_bytesPerRow.
    updateHeaderText();

    const int kRowCount = buffer_.isEmpty()
        ? 1
        : ((buffer_.size() + bytesPerRow_ - 1) / bytesPerRow_);

    ignoreItemChanged_ = true;
    hexTable_->clearContents();
    hexTable_->setRowCount(kRowCount);

    const QColor kMatchColor = buildMatchColor();
    const QColor kCurrentMatchColor = buildCurrentMatchColor();

    for (int rowIndex = 0; rowIndex < kRowCount; ++rowIndex)
    {
        const std::uint64_t kRowOffset = static_cast<std::uint64_t>(rowIndex) * static_cast<std::uint64_t>(bytesPerRow_);

        QTableWidgetItem* addressItem = new QTableWidgetItem(
            QStringLiteral("0x%1").arg(
                static_cast<qulonglong>(baseAddress_ + kRowOffset),
                16,
                16,
                QChar('0')).toUpper());
        addressItem->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
        hexTable_->setItem(rowIndex, 0, addressItem);

        QString asciiText;
        asciiText.reserve(bytesPerRow_);

        for (int byteColumn = 0; byteColumn < bytesPerRow_; ++byteColumn)
        {
            const std::uint64_t kByteOffset = kRowOffset + static_cast<std::uint64_t>(byteColumn);
            QTableWidgetItem* byteItem = nullptr;

            if (kByteOffset < static_cast<std::uint64_t>(buffer_.size()))
            {
                const std::uint8_t kByteValue = static_cast<std::uint8_t>(buffer_.at(static_cast<int>(kByteOffset)));
                byteItem = new QTableWidgetItem(byteToHexText(kByteValue));

                Qt::ItemFlags flags = Qt::ItemIsEnabled | Qt::ItemIsSelectable;
                if (editable_)
                {
                    flags |= Qt::ItemIsEditable;
                }
                byteItem->setFlags(flags);

                const bool kPrintable = (kByteValue >= 32 && kByteValue <= 126);
                asciiText.push_back(kPrintable ? QChar(kByteValue) : QChar('.'));

                // Normal match highlight.
                if (kByteOffset < static_cast<std::uint64_t>(matchMask_.size()) && matchMask_.at(static_cast<int>(kByteOffset)) != 0)
                {
                    byteItem->setBackground(kMatchColor);
                }

                // Current match has higher highlight priority.
                if (currentMatchIndex_ >= 0 &&
                    currentMatchIndex_ < static_cast<int>(matchOffsets_.size()) &&
                    kByteOffset >= matchOffsets_[static_cast<std::size_t>(currentMatchIndex_)] &&
                    kByteOffset < matchOffsets_[static_cast<std::size_t>(currentMatchIndex_)] +
                    static_cast<std::uint64_t>(std::max(1, currentMatchLength_)))
                {
                    byteItem->setBackground(kCurrentMatchColor);
                }
            }
            else
            {
                byteItem = new QTableWidgetItem(QStringLiteral("--"));
                byteItem->setFlags(Qt::ItemIsEnabled);
                asciiText.push_back(' ');
            }

            hexTable_->setItem(rowIndex, byteColumn + 1, byteItem);
        }

        QTableWidgetItem* asciiItem = new QTableWidgetItem(asciiText);
        // The ASCII column is selectable to satisfy the interaction requirement of 'cross-row highlighting in the ASCII column'.
        asciiItem->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
        hexTable_->setItem(rowIndex, bytesPerRow_ + 1, asciiItem);
    }

    ignoreItemChanged_ = false;

    if (buffer_.isEmpty())
    {
        linearSelectDragging_ = false;
        linearSelectAnchorValid_ = false;
        linearSelectAnchorOffset_ = 0;
        selectionVisualAsciiColumn_ = false;
    }

    refreshAsciiTabText();
}

void HexEditorWidget::updateHeaderText()
{
    if (hexTable_ == nullptr)
    {
        return;
    }

    hexTable_->setColumnCount(bytesPerRow_ + 2);

    QStringList headerList;
    headerList.reserve(bytesPerRow_ + 2);
    headerList.push_back(QStringLiteral("地址"));

    for (int columnIndex = 0; columnIndex < bytesPerRow_; ++columnIndex)
    {
        headerList.push_back(QStringLiteral("%1").arg(columnIndex, 2, 16, QChar('0')).toUpper());
    }
    headerList.push_back(QStringLiteral("ASCII"));
    hexTable_->setHorizontalHeaderLabels(headerList);
}

void HexEditorWidget::updateSummaryLabel()
{
    if (summaryLabel_ == nullptr)
    {
        return;
    }

    summaryLabel_->setText(
        QStringLiteral("长度: %1 字节 | 基址: %2 | 行宽: %3 | 模式: %4")
        .arg(static_cast<qulonglong>(buffer_.size()))
        .arg(QStringLiteral("0x%1").arg(static_cast<qulonglong>(baseAddress_), 16, 16, QChar('0')).toUpper())
        .arg(bytesPerRow_)
        .arg(editable_ ? QStringLiteral("可编辑") : QStringLiteral("只读")));
}

void HexEditorWidget::updateStatusLabel(const QString& statusText)
{
    if (statusLabel_ != nullptr)
    {
        statusLabel_->setText(statusText);
    }
}

void HexEditorWidget::refreshAsciiTabText()
{
    if (asciiEditor_ == nullptr)
    {
        return;
    }

    if (buffer_.isEmpty())
    {
        asciiEditor_->setLocalizedText(QStringLiteral("当前无数据。"));
        return;
    }

    const int kSafeBytesPerRow = std::max(1, bytesPerRow_);
    QString asciiText;
    asciiText.reserve(buffer_.size() + (buffer_.size() / kSafeBytesPerRow) + 8);

    for (int index = 0; index < buffer_.size(); ++index)
    {
        const std::uint8_t kByteValue = static_cast<std::uint8_t>(buffer_.at(index));
        const bool kPrintable = (kByteValue >= 32 && kByteValue <= 126);
        asciiText.push_back(kPrintable ? QChar(kByteValue) : QChar('.'));

        if (((index + 1) % kSafeBytesPerRow) == 0 && (index + 1) < buffer_.size())
        {
            asciiText.push_back(QChar('\n'));
        }
    }

    asciiEditor_->setRawText(asciiText);
}

void HexEditorWidget::updateAsciiCellByRow(const int rowIndex)
{
    if (rowIndex < 0 || rowIndex >= hexTable_->rowCount())
    {
        return;
    }

    const std::uint64_t kRowOffset = static_cast<std::uint64_t>(rowIndex) * static_cast<std::uint64_t>(bytesPerRow_);
    QString asciiText;
    asciiText.reserve(bytesPerRow_);

    for (int byteColumn = 0; byteColumn < bytesPerRow_; ++byteColumn)
    {
        const std::uint64_t kByteOffset = kRowOffset + static_cast<std::uint64_t>(byteColumn);
        if (kByteOffset < static_cast<std::uint64_t>(buffer_.size()))
        {
            const std::uint8_t kByteValue = static_cast<std::uint8_t>(buffer_.at(static_cast<int>(kByteOffset)));
            const bool kPrintable = (kByteValue >= 32 && kByteValue <= 126);
            asciiText.push_back(kPrintable ? QChar(kByteValue) : QChar('.'));
        }
        else
        {
            asciiText.push_back(' ');
        }
    }

    QTableWidgetItem* asciiItem = hexTable_->item(rowIndex, bytesPerRow_ + 1);
    if (asciiItem == nullptr)
    {
        asciiItem = new QTableWidgetItem();
        // Maintain selectable attribute for ASCII column to avoid losing cross-row selection visual feedback after reconstruction.
        asciiItem->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
        hexTable_->setItem(rowIndex, bytesPerRow_ + 1, asciiItem);
    }
    asciiItem->setText(asciiText);
}

void HexEditorWidget::updateRowHighlightByRow(const int rowIndex)
{
    if (rowIndex < 0 || rowIndex >= hexTable_->rowCount())
    {
        return;
    }

    const std::uint64_t kRowOffset = static_cast<std::uint64_t>(rowIndex) * static_cast<std::uint64_t>(bytesPerRow_);
    const QColor kMatchColor = buildMatchColor();
    const QColor kCurrentMatchColor = buildCurrentMatchColor();
    const QColor kSelectionColor = buildSelectionColor();

    for (int byteColumn = 0; byteColumn < bytesPerRow_; ++byteColumn)
    {
        const std::uint64_t kByteOffset = kRowOffset + static_cast<std::uint64_t>(byteColumn);
        QTableWidgetItem* byteItem = hexTable_->item(rowIndex, byteColumn + 1);
        if (byteItem == nullptr)
        {
            continue;
        }

        byteItem->setBackground(QBrush());
        if (kByteOffset >= static_cast<std::uint64_t>(buffer_.size()))
        {
            continue;
        }

        if (!selectionVisualAsciiColumn_ &&
            selectionRangeValid_ &&
            kByteOffset >= std::min(selectionRangeStartOffset_, selectionRangeEndOffset_) &&
            kByteOffset <= std::max(selectionRangeStartOffset_, selectionRangeEndOffset_))
        {
            byteItem->setBackground(kSelectionColor);
            continue;
        }

        if (kByteOffset < static_cast<std::uint64_t>(matchMask_.size()) && matchMask_.at(static_cast<int>(kByteOffset)) != 0)
        {
            byteItem->setBackground(kMatchColor);
        }

        if (currentMatchIndex_ >= 0 &&
            currentMatchIndex_ < static_cast<int>(matchOffsets_.size()) &&
            kByteOffset >= matchOffsets_[static_cast<std::size_t>(currentMatchIndex_)] &&
            kByteOffset < matchOffsets_[static_cast<std::size_t>(currentMatchIndex_)] +
            static_cast<std::uint64_t>(std::max(1, currentMatchLength_)))
        {
            byteItem->setBackground(kCurrentMatchColor);
        }
    }
}
