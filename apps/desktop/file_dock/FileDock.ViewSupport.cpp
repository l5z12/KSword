#include "FileDock.Support.h"

namespace ksword::ui::file_dock
{
    bool gPreferPlainTextReportView = false;

    // manualFsTypeToText purpose: Convert manually parsed result types to readable text.
    QString manualFsTypeToText(const ks::file::ManualFsType fsType)
    {
        switch (fsType)
        {
        case ks::file::ManualFsType::kNtfs:
            return QStringLiteral("NTFS");
        case ks::file::ManualFsType::kFat32:
            return QStringLiteral("FAT32");
        case ks::file::ManualFsType::kExFat:
            return QStringLiteral("exFAT");
        default:
            return QStringLiteral("Unknown");
        }
    }

    // markSuspiciousRowIfNeeded:
    // - Input: Newly constructed row, row entry name, and set of suspected hidden item names (case-folded);
    // - Processing: apply prominent background color and explanatory tooltip to the entire row on match;
    // - Note: This list is the difference set between 'bypass path visible, regular path invisible', representing the core output of
    //   MFT and IRP parsing methods. Only reporting a single number in the status bar leaves the user unable to locate the specific rows.
    void markSuspiciousRowIfNeeded(
        const QList<QStandardItem*>& rowItems,
        const QString& entryName,
        const QSet<QString>& suspiciousNameSet)
    {
        if (suspiciousNameSet.isEmpty() ||
            !suspiciousNameSet.contains(entryName.toCaseFolded()))
        {
            return;
        }

        // Use a low-opacity alert color as the background: visible at a glance, but not obscuring the selected state or alternating row colors.
        QColor highlightColor(
            ksword_theme::accentHex(ksword_theme::AccentRole::kOrange));
        highlightColor.setAlpha(72);
        const QString kTipText = QStringLiteral(
            "该条目只有绕过过滤层或直读 $MFT 才能看到，常规目录枚举视图中不存在。");
        for (QStandardItem* rowItem : rowItems)
        {
            if (rowItem == nullptr)
            {
                continue;
            }
            rowItem->setBackground(highlightColor);
            rowItem->setToolTip(kTipText);
        }
    }

    // buildSuspiciousNameSet purpose: Fold case-insensitive suspicious hidden item
    // names into a set to avoid O(n) linear lookups during line-by-line backfilling.
    QSet<QString> buildSuspiciousNameSet(const QStringList& names)
    {
        QSet<QString> nameSet;
        nameSet.reserve(names.size() + 8);
        for (const QString& nameText : names)
        {
            nameSet.insert(nameText.toCaseFolded());
        }
        return nameSet;
    }

    // Unify button styles to maintain consistency with the main interface's blue theme.
    QString buildBlueButtonStyle()
    {
        return ksword_theme::themedButtonStyle();
    }

    // Unified input control style.
    QString buildBlueInputStyle()
    {
        return QStringLiteral(
            "QLineEdit,QPlainTextEdit,QTextEdit{"
            "  border:1px solid %2;"
            "  border-radius:3px;"
            "  background:%3;"
            "  color:%4;"
            "  padding:2px 6px;"
            "}"
            "QLineEdit:focus,QPlainTextEdit:focus,QTextEdit:focus{"
            "  border:1px solid %1;}")
            .arg(ksword_theme::accentHex(ksword_theme::AccentRole::kBlue))
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::textPrimaryHex())
            + ksword_theme::themedComboBoxStyle();
    }

    // buildContextMenuStyle:
    // - Generates independent theme styles for the FileDock file list context menu;
    // - Fix the menu background incorrectly remaining black in the light theme, which makes the text unreadable.
    QString buildContextMenuStyle()
    {
        const QString kDisabledTextColor = ksword_theme::textDisabledColorHex();

        return QStringLiteral(
            "QMenu{"
            "  background:%1;"
            "  color:%2;"
            "  border:1px solid %3;"
            "}"
            "QMenu::item{"
            "  padding:3px 16px 3px 12px;"
            "  background:transparent;"
            "}"
            "QMenu::item:selected{"
            "  background:%4;"
            "  color:%6;"
            "}"
            "QMenu::item:disabled{"
            "  color:%5;"
            "  background:transparent;"
            "}"
            "QMenu::separator{"
            "  height:1px;"
            "  background:%3;"
            "  margin:2px 6px;"
            "}")
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::textPrimaryHex())
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::accentHex(ksword_theme::AccentRole::kBlue))
            .arg(kDisabledTextColor)
            .arg(ksword_theme::onAccentDynamicHex());
    }

    void installFileTableCopyMenu(QTableWidget* tableWidget, const int processIdColumn)
    {
        // installFileTableCopyMenu：
        // - Input: Temporary popup or tool page table within FileDock;
        // - Processing: Right-click to select the current row and copy all columns of that row to the clipboard as TSV.
        // - Returns: None. Read-only copy; does not trigger delete, restore, or close handle actions.
        if (tableWidget == nullptr)
        {
            return;
        }

        tableWidget->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(tableWidget, &QTableWidget::customContextMenuRequested, tableWidget, [tableWidget, processIdColumn](const QPoint& localPosition)
        {
            const auto kClickedIndex = tableWidget->indexAt(localPosition);
            if (kClickedIndex.isValid())
            {
                tableWidget->setCurrentCell(kClickedIndex.row(), kClickedIndex.column());
            }

            QMenu menu(tableWidget);
            menu.setStyleSheet(buildContextMenuStyle());
            QAction* copyRowAction = menu.addAction(
                QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
                QStringLiteral("复制当前行"));
            copyRowAction->setEnabled(tableWidget->currentRow() >= 0);
            const QTableWidgetItem* processIdItem =
                processIdColumn >= 0 && processIdColumn < tableWidget->columnCount() && tableWidget->currentRow() >= 0
                ? tableWidget->item(tableWidget->currentRow(), processIdColumn)
                : nullptr;
            bool processIdOk = false;
            const quint32 kProcessId = processIdItem != nullptr
                ? processIdItem->text().trimmed().toUInt(&processIdOk, 10)
                : 0U;
            QAction* openProcessAction = nullptr;
            if (processIdColumn >= 0)
            {
                openProcessAction = menu.addAction(
                    QIcon(QStringLiteral(":/Icon/process_details.svg")),
                    QStringLiteral("转到进程详细信息"));
                openProcessAction->setEnabled(processIdOk && kProcessId != 0U);
            }

            QAction* selectedAction = menu.exec(tableWidget->viewport()->mapToGlobal(localPosition));
            if (selectedAction == openProcessAction)
            {
                ks::ui::openProcessDetailByPid(kProcessId);
                return;
            }
            if (selectedAction != copyRowAction)
            {
                return;
            }

            QClipboard* clipboardObject = QApplication::clipboard();
            const int kRowIndex = tableWidget->currentRow();
            if (clipboardObject == nullptr || kRowIndex < 0 || kRowIndex >= tableWidget->rowCount())
            {
                return;
            }

            QStringList fields;
            fields.reserve(tableWidget->columnCount());
            for (int columnIndex = 0; columnIndex < tableWidget->columnCount(); ++columnIndex)
            {
                const QTableWidgetItem* item = tableWidget->item(kRowIndex, columnIndex);
                fields.push_back(item != nullptr ? item->text() : QString());
            }
            clipboardObject->setText(fields.join(QLatin1Char('\t')));
        });
    }

    // installFileTreeCopyMenu:
    // - Input treeWidget: read-only result displayed as tree table in FileDock;
    // - Processing: Right-click to select the current row and copy all columns of that row to the clipboard as TSV.
    // - Return: None. Read-only copy; no unlock, handle close, or file deletion actions are performed.
    void installFileTreeCopyMenu(QTreeWidget* treeWidget, const int processIdColumn)
    {
        if (treeWidget == nullptr)
        {
            return;
        }

        treeWidget->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(treeWidget, &QTreeWidget::customContextMenuRequested, treeWidget, [treeWidget, processIdColumn](const QPoint& localPosition)
        {
            QTreeWidgetItem* clickedItem = treeWidget->itemAt(localPosition);
            if (clickedItem != nullptr)
            {
                treeWidget->setCurrentItem(clickedItem);
            }

            QMenu menu(treeWidget);
            menu.setStyleSheet(buildContextMenuStyle());
            QAction* copyRowAction = menu.addAction(
                QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
                QStringLiteral("复制当前行"));
            copyRowAction->setEnabled(treeWidget->currentItem() != nullptr);
            QTreeWidgetItem* const kProcessIdItem = treeWidget->currentItem();
            bool processIdOk = false;
            const quint32 kProcessId =
                kProcessIdItem != nullptr && processIdColumn >= 0 && processIdColumn < treeWidget->columnCount()
                ? kProcessIdItem->text(processIdColumn).trimmed().toUInt(&processIdOk, 10)
                : 0U;
            QAction* openProcessAction = menu.addAction(
                QIcon(QStringLiteral(":/Icon/process_details.svg")),
                QStringLiteral("转到进程详细信息"));
            openProcessAction->setEnabled(processIdOk && kProcessId != 0U);

            QAction* selectedAction = menu.exec(treeWidget->viewport()->mapToGlobal(localPosition));
            if (selectedAction == openProcessAction)
            {
                ks::ui::openProcessDetailByPid(kProcessId);
                return;
            }
            if (selectedAction != copyRowAction)
            {
                return;
            }

            QClipboard* clipboardObject = QApplication::clipboard();
            QTreeWidgetItem* currentItem = treeWidget->currentItem();
            if (clipboardObject == nullptr || currentItem == nullptr)
            {
                return;
            }

            QStringList fields;
            fields.reserve(treeWidget->columnCount());
            for (int columnIndex = 0; columnIndex < treeWidget->columnCount(); ++columnIndex)
            {
                fields.push_back(currentItem->text(columnIndex));
            }
            clipboardObject->setText(fields.join(QLatin1Char('\t')));
        });
    }

    // propertyTreeToPlainText:
    // - Export the entire 'Name/Value' two-column property tree as indented text;
    // After changing the property page from a plain text block to a property tree, this replaces the original 'select all text box then copy'.
    // Input treeWidget: target property tree; returns empty string if null.
    // Return: Multi-line text with groups on separate lines enclosed in brackets and attributes as 'Name: Value'.
    QString propertyTreeToPlainText(const QTreeWidget* treeWidget)
    {
        if (treeWidget == nullptr)
        {
            return {};
        }

        QString exportedText;
        for (int groupIndex = 0; groupIndex < treeWidget->topLevelItemCount(); ++groupIndex)
        {
            const QTreeWidgetItem* groupItem = treeWidget->topLevelItem(groupIndex);
            if (groupItem == nullptr)
            {
                continue;
            }

            exportedText += groupItem->text(1).isEmpty()
                ? QStringLiteral("[%1]\n").arg(groupItem->text(0))
                : QStringLiteral("[%1] %2\n").arg(groupItem->text(0), groupItem->text(1));
            for (int rowIndex = 0; rowIndex < groupItem->childCount(); ++rowIndex)
            {
                const QTreeWidgetItem* rowItem = groupItem->child(rowIndex);
                if (rowItem == nullptr)
                {
                    continue;
                }
                exportedText += QStringLiteral("  %1: %2\n").arg(rowItem->text(0), rowItem->text(1));
            }
            exportedText += QStringLiteral("\n");
        }
        return exportedText;
    }

    // installPropertyTreeCopyMenu:
    // - Add a right-click copy menu to the 'Name/Value' two-column property tree.
    // - Provide three granularities: 'copy value only', 'copy entire row', and 'copy all'. In read-only text boxes, retrieving a single path previously
    //   required manual selection; after converting each attribute in the property tree into an independent row, it should be directly selectable.
    // Input treeWidget: Target property tree; ignored if null.
    // Returns: Nothing.
    void installPropertyTreeCopyMenu(QTreeWidget* treeWidget)
    {
        if (treeWidget == nullptr)
        {
            return;
        }

        treeWidget->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(
            treeWidget,
            &QTreeWidget::customContextMenuRequested,
            treeWidget,
            [treeWidget](const QPoint& localPosition)
            {
                QTreeWidgetItem* clickedItem = treeWidget->itemAt(localPosition);
                if (clickedItem != nullptr)
                {
                    treeWidget->setCurrentItem(clickedItem);
                }

                QMenu menu(treeWidget);
                menu.setStyleSheet(buildContextMenuStyle());
                QAction* copyValueAction = menu.addAction(
                    QIcon(QStringLiteral(":/Icon/process_copy_cell.svg")),
                    QStringLiteral("复制值"));
                QAction* copyRowAction = menu.addAction(
                    QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
                    QStringLiteral("复制当前行"));
                QAction* copyAllAction = menu.addAction(
                    QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
                    QStringLiteral("复制全部"));
                copyValueAction->setEnabled(clickedItem != nullptr && !clickedItem->text(1).isEmpty());
                copyRowAction->setEnabled(clickedItem != nullptr);

                QAction* selectedAction = menu.exec(treeWidget->viewport()->mapToGlobal(localPosition));
                if (selectedAction == nullptr)
                {
                    return;
                }

                QString clipboardText;
                if (selectedAction == copyValueAction && clickedItem != nullptr)
                {
                    clipboardText = clickedItem->text(1);
                }
                else if (selectedAction == copyRowAction && clickedItem != nullptr)
                {
                    clipboardText = clickedItem->text(1).isEmpty()
                        ? clickedItem->text(0)
                        : QStringLiteral("%1: %2").arg(clickedItem->text(0), clickedItem->text(1));
                }
                else if (selectedAction == copyAllAction)
                {
                    clipboardText = propertyTreeToPlainText(treeWidget);
                }

                QClipboard* clipboardObject = QApplication::clipboard();
                if (clipboardObject != nullptr && !clipboardText.isEmpty())
                {
                    clipboardObject->setText(clipboardText);
                }
            });
    }

    // appendPropertyGroup:
    // - Create a top-level group in the property tree that is expanded by default.
    // - Make group rows bold and unselectable to prevent them from being copied as a property.
    // Input parameters tree: Target property tree; titleText: Translated group title.
    // Returns: A newly created group node, whose lifetime is managed by the tree.
    QTreeWidgetItem* appendPropertyGroup(QTreeWidget* tree, const QString& titleText)
    {
        QTreeWidgetItem* groupItem = new QTreeWidgetItem(tree);
        groupItem->setText(0, titleText);
        QFont groupFont = groupItem->font(0);
        groupFont.setBold(true);
        groupItem->setFont(0, groupFont);
        groupItem->setFlags(groupItem->flags() & ~Qt::ItemIsSelectable);
        groupItem->setExpanded(true);
        return groupItem;
    }

    // appendPropertyRow:
    // - Append a row with 'attribute name + value' under the group;
    // - Write the value to ToolTip simultaneously; when a long path is truncated by column width, the full path remains visible on hover.
    // Parameters groupItem: parent group; nameText/valueText: translated name and value.
    // Returns: a newly created row node; the tree manages its lifetime.
    QTreeWidgetItem* appendPropertyRow(
        QTreeWidgetItem* groupItem,
        const QString& nameText,
        const QString& valueText)
    {
        QTreeWidgetItem* rowItem = new QTreeWidgetItem(groupItem);
        rowItem->setText(0, nameText);
        rowItem->setText(1, valueText);
        rowItem->setToolTip(1, valueText);
        return rowItem;
    }

    // configurePropertyTree:
    // - Standardize property tree appearance and interaction: two columns, collapsible, non-editable, unsorted, with a copy menu;
    // - Shared between the regular page and all audit pages to avoid having two inconsistent property views in the same window.
    // Input treeWidget: Target property tree; ignored if null.
    // Returns: Nothing.
    void configurePropertyTree(QTreeWidget* treeWidget)
    {
        if (treeWidget == nullptr)
        {
            return;
        }

        treeWidget->setColumnCount(2);
        // Font size matches the structure view in unified report controls: two structured views in the same window must not have different font sizes.
        // Mark the font as self-managed simultaneously: mainWindow refreshes all item views to the application font after
        // appearance settings change. Without this mark, changing the font setting here would revert it to the default.
        treeWidget->setProperty("ksword_preserve_custom_font", true);
        treeWidget->setFont(ks::ui::scaledReportFont(treeWidget->font()));
        treeWidget->setRootIsDecorated(true);
        treeWidget->setAlternatingRowColors(true);
        treeWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
        treeWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
        treeWidget->setUniformRowHeights(true);
        // The row order carries meaning (reports are written in collection order), so sorting is disabled.
        treeWidget->setSortingEnabled(false);
        if (treeWidget->header() != nullptr)
        {
            treeWidget->header()->setStretchLastSection(true);
        }
        installPropertyTreeCopyMenu(treeWidget);
    }

    // buildSwitchableView:
    // - Input parent, pre-filled property tree, and read-only text view of the same content.
    // - Handling: Stack both views in a QStackedWidget and place a view-switching dropdown in the top-right corner.
    //   The structured view displays fields on separate lines, suitable for reviewing and copying item by item; the original
    //   text preserves the complete report, suitable for Ctrl+F full-text search and pasting entire sections into tickets. Both
    //   have irreplaceable use cases, so we do not force the user to choose one; instead, switching is available on the spot.
    // - Returns: A container widget ready to be placed directly into a page layout.
    QWidget* buildSwitchableView(
        QWidget* parent,
        QTreeWidget* propertyTree,
        CodeEditorWidget* textEditor)
    {
        QWidget* container = new QWidget(parent);
        QVBoxLayout* containerLayout = new QVBoxLayout(container);
        containerLayout->setContentsMargins(0, 0, 0, 0);
        containerLayout->setSpacing(4);

        auto& languageManager = ks::i18n::LanguageManager::instance();
        QComboBox* viewModeCombo = new QComboBox(container);
        viewModeCombo->addItem(QStringLiteral("结构视图"));
        viewModeCombo->addItem(QStringLiteral("原始文本"));
        languageManager.bindComboBoxItem(
            viewModeCombo, 0, QStringLiteral("file.detail.view.structured"), QStringLiteral("结构视图"));
        languageManager.bindComboBoxItem(
            viewModeCombo, 1, QStringLiteral("file.detail.view.plain_text"), QStringLiteral("原始文本"));
        viewModeCombo->setToolTip(
            QStringLiteral("结构视图按字段分行，便于逐条查看和复制；原始文本保留完整报告，便于全文检索和整段复制"));
        languageManager.bindToolTip(
            viewModeCombo,
            QStringLiteral("file.detail.view.tooltip"),
            QStringLiteral("结构视图按字段分行，便于逐条查看和复制；原始文本保留完整报告，便于全文检索和整段复制"));

        QHBoxLayout* headerLayout = new QHBoxLayout();
        headerLayout->setContentsMargins(0, 0, 0, 0);
        headerLayout->addStretch(1);
        headerLayout->addWidget(viewModeCombo, 0);
        containerLayout->addLayout(headerLayout, 0);

        QStackedWidget* viewStack = new QStackedWidget(container);
        viewStack->addWidget(propertyTree);
        viewStack->addWidget(textEditor);
        containerLayout->addWidget(viewStack, 1);

        const int kInitialViewIndex = gPreferPlainTextReportView ? 1 : 0;
        viewModeCombo->setCurrentIndex(kInitialViewIndex);
        viewStack->setCurrentIndex(kInitialViewIndex);
        QObject::connect(
            viewModeCombo,
            QOverload<int>::of(&QComboBox::currentIndexChanged),
            viewStack,
            [viewStack](const int viewIndex)
            {
                viewStack->setCurrentIndex(viewIndex);
                gPreferPlainTextReportView = viewIndex == 1;
            });
        return container;
    }

    // buildReportView:
    // - Input parent and the original report text generated by the audit page;
    // - Handling: Delegate to a unified read-only report control that determines structured presentation based
    //   on content type, and provides a toolbar button to toggle between 'Structured View' and 'Raw Text'.
    // - Rationale: This file originally contained a parsing implementation that only recognized attribute trees grouped by [Group] with dropdown switching.
    //   With the global report control online, having both versions coexist creates two entry points and two parsing interpretations on the same page. Since
    //   the local version only parses property trees (not aligned tables or machine code blocks), the entire system is replaced with a unified control.
    // - Returns: a widget that can be directly placed into a page layout.
    QWidget* buildReportView(QWidget* parent, const QString& reportText)
    {
        CodeEditorWidget* textEditor = new CodeEditorWidget(parent);
        textEditor->setReadOnly(true);
        textEditor->setLocalizedText(reportText);
        return textEditor;
    }

    // buildOpaqueStandaloneDialogStyle:
    // - Overrides the parent Dock transparent style for 'standalone dialogs' to prevent black backgrounds under light themes.
    // - Force the edit area and table area to use palette(base) as the opaque background.
    QString buildOpaqueStandaloneDialogStyle(const QString& dialogObjectName)
    {
        return QStringLiteral(
            "QDialog#%1{"
            "  background-color:palette(window) !important;"
            "  color:palette(text) !important;"
            "}"
            "QDialog#%1 QTabWidget::pane{"
            "  background-color:palette(window) !important;"
            "  border:1px solid palette(mid) !important;"
            "}"
            "QDialog#%1 QPlainTextEdit,"
            "QDialog#%1 QTextEdit,"
            "QDialog#%1 QTreeWidget,"
            "QDialog#%1 QTableWidget,"
            "QDialog#%1 QAbstractScrollArea,"
            "QDialog#%1 QAbstractScrollArea::viewport{"
            "  background-color:palette(base) !important;"
            "  color:palette(text) !important;"
            "}"
            "QDialog#%1 QHeaderView::section{"
            "  background-color:palette(base) !important;"
            "  color:palette(text) !important;"
            "}")
            .arg(dialogObjectName);
    }

    // buildFileDetailDialogPalette：
    // - Establishes the same Window/Surface/Base layering for the file properties window as used in the process properties window.
    // - Explicitly sets the Base to prevent CodeEditor and tables from falling back to system colors independently under different themes.
    QPalette buildFileDetailDialogPalette(const QWidget* const fallbackWidget)
    {
        QPalette palette = qApp != nullptr
            ? qApp->palette()
            : (fallbackWidget != nullptr ? fallbackWidget->palette() : QPalette());
        palette.setColor(QPalette::Window, ksword_theme::windowColor());
        palette.setColor(QPalette::WindowText, ksword_theme::textPrimaryColor());
        palette.setColor(QPalette::Base, ksword_theme::surfaceColor());
        palette.setColor(QPalette::AlternateBase, ksword_theme::surfaceAltColor());
        palette.setColor(QPalette::Text, ksword_theme::textPrimaryColor());
        palette.setColor(QPalette::Button, ksword_theme::surfaceColor());
        palette.setColor(QPalette::ButtonText, ksword_theme::textPrimaryColor());
        palette.setColor(QPalette::Mid, ksword_theme::borderColor());
        palette.setColor(QPalette::Highlight, ksword_theme::controlAccentColor());
        palette.setColor(
            QPalette::HighlightedText,
            ksword_theme::maximumContrastMonochromeColor(ksword_theme::controlAccentColor()));
        palette.setColor(QPalette::Disabled, QPalette::WindowText, ksword_theme::textDisabledColor());
        palette.setColor(QPalette::Disabled, QPalette::Text, ksword_theme::textDisabledColor());
        palette.setColor(QPalette::Disabled, QPalette::ButtonText, ksword_theme::textDisabledColor());
        return palette;
    }

    // applyFileDetailSurfacePalette：
    // - Force opaque surfaces for independent windows and their pages;
    // - Prevent transparent sub-pages from exposing windowColor, while editors/tables use Base, causing a background color discontinuity.
    void applyFileDetailSurfacePalette(QWidget* const widget, const QPalette& palette)
    {
        if (widget == nullptr)
        {
            return;
        }
        widget->setPalette(palette);
        widget->setAutoFillBackground(true);
        widget->setAttribute(Qt::WA_StyledBackground, true);
    }

    // buildFileDetailDialogStyle：
    // - The file properties window reuses the process properties' visual hierarchy: 'Window outer layer + Surface content page + Left navigation';
    // - All readable text containers, headers, and scroll areas explicitly use Surface to avoid inconsistent text background colors within the same window.
    QString buildFileDetailDialogStyle()
    {
        return QStringLiteral(
            "QDialog#FileDetailDialogRoot{"
            "  background:%1;"
            "  color:%2;"
            "}"
            "QDialog#FileDetailDialogRoot QGroupBox{"
            "  border:1px solid %3;"
            "  border-radius:4px;"
            "  margin-top:8px;"
            "  padding-top:8px;"
            "  background:%4;"
            "  color:%2;"
            "}"
            "QDialog#FileDetailDialogRoot QGroupBox::title{"
            "  subcontrol-origin:margin;"
            "  left:8px;"
            "  padding:0 4px;"
            "  color:%2;"
            "}"
            "QDialog#FileDetailDialogRoot QLineEdit,"
            "QDialog#FileDetailDialogRoot QPlainTextEdit,"
            "QDialog#FileDetailDialogRoot QTextEdit{"
            "  background:%4;"
            "  color:%2;"
            "  border:1px solid %3;"
            "  border-radius:3px;"
            "  padding:3px 6px;"
            "  selection-background-color:%5;"
            "  selection-color:%7;"
            "}"
            "QDialog#FileDetailDialogRoot QTableWidget,"
            "QDialog#FileDetailDialogRoot QTreeWidget{"
            "  background:%4;"
            "  alternate-background-color:%6;"
            "  color:%2;"
            "  border:1px solid %3;"
            "  gridline-color:%3;"
            "}"
            "QDialog#FileDetailDialogRoot QAbstractScrollArea::viewport{"
            "  background:%4;"
            "  color:%2;"
            "}"
            "QDialog#FileDetailDialogRoot QTableCornerButton::section,"
            "QDialog#FileDetailDialogRoot QHeaderView::section{"
            "  background:%4;"
            "  color:%2;"
            "  border:1px solid %3;"
            "  padding:4px;"
            "  font-weight:600;"
            "}"
            "QDialog#FileDetailDialogRoot QTabWidget::pane{"
            "  border:1px solid %3;"
            "  background:%4;"
            "}"
            "QWidget#FileDetailTabNavigation{"
            "  background:%4;"
            "  border:1px solid %3;"
            "  border-radius:4px;"
            "}"
            "QWidget#FileDetailTabNavigation QToolButton{"
            "  background:%4;"
            "  color:%2;"
            "  border:1px solid %3;"
            "  border-radius:3px;"
            "  padding:5px 8px;"
            "}"
            "QWidget#FileDetailTabNavigation QToolButton:checked{"
            "  background:%5;"
            "  color:%7;"
            "  border-color:%5;"
            "}"
            "QWidget#FileDetailTabNavigation QToolButton:hover:!checked{"
            "  background:%6;"
            "}"
            "QDialog#FileDetailDialogRoot QPushButton{"
            "  background:%4;"
            "  color:%2;"
            "  border:1px solid %3;"
            "  border-radius:3px;"
            "  padding:4px 10px;"
            "}"
            "QDialog#FileDetailDialogRoot QPushButton:hover{"
            "  background:%6;"
            "  border-color:%5;"
            "}"
            "QDialog#FileDetailDialogRoot QPushButton:pressed{"
            "  background:%5;"
            "  color:%7;"
            "  border-color:%5;"
            "}"
            "QDialog#FileDetailDialogRoot QProgressBar{"
            "  background:%6;"
            "  color:%2;"
            "  border:1px solid %3;"
            "  border-radius:3px;"
            "  text-align:center;"
            "}"
            "QDialog#FileDetailDialogRoot QProgressBar::chunk{"
            "  background:%5;"
            "  border-radius:2px;"
            "}"
            "QDialog#FileDetailDialogRoot QScrollBar:vertical{"
            "  background:%4;"
            "  width:12px;"
            "  margin:0;"
            "}"
            "QDialog#FileDetailDialogRoot QScrollBar:horizontal{"
            "  background:%4;"
            "  height:12px;"
            "  margin:0;"
            "}"
            "QDialog#FileDetailDialogRoot QScrollBar::handle:vertical,"
            "QDialog#FileDetailDialogRoot QScrollBar::handle:horizontal{"
            "  background:%5;"
            "  min-height:20px;"
            "  min-width:20px;"
            "  border-radius:4px;"
            "}"
            "QDialog#FileDetailDialogRoot QScrollBar::handle:vertical:hover,"
            "QDialog#FileDetailDialogRoot QScrollBar::handle:horizontal:hover{"
            "  background:%1;"
            "}"
            "QDialog#FileDetailDialogRoot QScrollBar::add-line,"
            "QDialog#FileDetailDialogRoot QScrollBar::sub-line,"
            "QDialog#FileDetailDialogRoot QScrollBar::add-page,"
            "QDialog#FileDetailDialogRoot QScrollBar::sub-page{"
            "  background:%4;"
            "  border:none;"
            "}")
            .arg(ksword_theme::mainBackgroundHex())
            .arg(ksword_theme::textPrimaryHex())
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::controlAccentHex())
            .arg(ksword_theme::surfaceAltHex())
            .arg(ksword_theme::onAccentDynamicHex());
    }

    // buildLogPreviewText:
    // - Compresses multi-line results into a single log preview text to prevent the log panel from being flooded by batch errors.
    // - Parameter sourceLines: original detailed text collection; Parameter maxLineCount: maximum number of lines to retain;
    // - Returns: A QString suitable for direct writing to a log.
    QString buildLogPreviewText(const QStringList& sourceLines, const int maxLineCount )
    {
        if (sourceLines.isEmpty())
        {
            return QStringLiteral("(空)");
        }

        QStringList previewLines;
        const int kSourceLineCount = static_cast<int>(sourceLines.size());
        const int kPreviewCount = kSourceLineCount < maxLineCount
            ? kSourceLineCount
            : maxLineCount;
        previewLines.reserve(kPreviewCount + 1);
        for (int index = 0; index < kPreviewCount; ++index)
        {
            previewLines.push_back(sourceLines[index]);
        }
        if (sourceLines.size() > kPreviewCount)
        {
            previewLines.push_back(
                QStringLiteral("... 其余 %1 行省略").arg(sourceLines.size() - kPreviewCount));
        }
        return previewLines.join(QStringLiteral("\n"));
    }

    // Breadcrumb button style: visually 'embedded' in the input box, with a lightweight hover tooltip retained.
    QString buildBreadcrumbButtonStyle()
    {
        return QStringLiteral(
            "QToolButton{"
            "  color:%1;"
            "  background:transparent;"
            "  border:none;"
            "  padding:0 4px;"
            "}"
            "QToolButton:hover{"
            "  background:%2;"
            "  color:%1;"
            "  border-radius:3px;"
            "}"
            "QToolButton:pressed{"
            "  background:%3;"
            "  color:%4;"
            "}")
            .arg(ksword_theme::textPrimaryHex())
            .arg(ksword_theme::surfaceAltHex())
            .arg(ksword_theme::accentHex(ksword_theme::AccentRole::kBlue, -14, -40))
            .arg(ksword_theme::onAccentDynamicHex());
    }
}
