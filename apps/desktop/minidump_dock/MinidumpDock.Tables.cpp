// ============================================================
// MinidumpDock.Tables.cpp
// Purpose:
// - Implement all rendering logic for dump parsing results.
//   Diagnostic conclusion, culprit module, overview, exception, call stack, registers, stream directory,
//   module, thread, memory, handle, unloaded modules: 12 tables total, plus a full-text report.
// - The table control is pre-created in MinidumpDock.cpp; this file only handles clearing, repopulating,
//   and mounting tabs. Language switching triggers a re-entry into this file to complete re-translation.
// - The wide table provides complementary A/B/C column group presets via createStructuredTablePage and allows
//   column-by-column show/hide via header right-click (adhering to the project's A/B column group specification).
// ============================================================

#include "MinidumpDock.h"

#include "DumpAnalyzer.h"
#include "DumpByteView.h"
#include "DumpMemoryView.h"
#include "DumpSymbolResolver.h"
#include "internationalization/LanguageManager.h"
#include "MinidumpFormat.h"
#include "ui/CodeEditorWidget.h"
#include "ui/TableHeaderSortingSupport.h"
#include "Theme.h"

#include <QAction>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QMenu>
#include <QPointer>
#include <QPushButton>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTextBrowser>
#include <QVBoxLayout>

#include <algorithm>
#include <memory>
#include <vector>

namespace
{
    // kReportMemoryRowLimit: Maximum number of rows to list for memory regions in the full report.
    constexpr std::size_t kReportMemoryRowLimit = 2000;

    // hexText purpose: Formats values as uppercase hexadecimal with 0x prefix (common for rendering layer).
    QString hexText(const std::uint64_t value)
    {
        return QStringLiteral("0x%1").arg(QString::number(value, 16).toUpper());
    }

    // makeItem purpose: Creates a read-only table cell.
    // Pass text as the cell text; return the newly created QTableWidgetItem.
    QTableWidgetItem* makeItem(const QString& text)
    {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }

    // beginFill: Disables refresh and sorting, then clears content before batch filling.
    // Note: endFill only restores refresh; it does not re-enable sorting. All tables on this page are presented in the
    // original order produced by parsing (the frame order of call stacks and the load order of modules are themselves
    // meaningful information). Allowing users to disrupt this order by clicking table headers is pointless.
    void beginFill(QTableWidget* const table)
    {
        table->setUpdatesEnabled(false);
        table->setSortingEnabled(false);
        table->clearContents();
        table->setRowCount(0);
    }

    // endFill purpose: After batch filling, restore refresh and auto-adjust column widths (with a maximum width limit).
    void endFill(QTableWidget* const table)
    {
        table->resizeColumnsToContents();
        // Column width limit: do not allow an excessively long path column to push other columns out of the viewport.
        for (int column = 0; column < table->columnCount(); ++column)
        {
            // Hidden columns return 0 for columnWidth(); clamping then sets their width to 0. When the
            // user later displays them via A/B/C or the header menu, they become zero-width columns.
            if (table->isColumnHidden(column))
            {
                continue;
            }
            table->setColumnWidth(
                column,
                std::min(table->columnWidth(column), 420));
        }
        table->setUpdatesEnabled(true);
    }
}

QTableWidget* MinidumpDock::createReadOnlyTable(QWidget* parent) const
{
    // table: Unified-style read-only table; interaction settings consistent with ScannerDock.
    auto* table = new QTableWidget(parent);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setSelectionMode(QAbstractItemView::ExtendedSelection);
    table->setAlternatingRowColors(true);
    table->setWordWrap(false);
    table->setTextElideMode(Qt::ElideMiddle);
    table->verticalHeader()->setVisible(false);
    table->horizontalHeader()->setSectionsMovable(true);
    table->horizontalHeader()->setStretchLastSection(true);
    // Header left-aligned: when the last column is stretched, it becomes very wide, causing centered header text to drift
    // to the column center and misalign with left-aligned data. The convention for data tables is also left alignment.
    table->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    // Frame order, load order, and collection order in the dump analysis table are themselves evidence; disable generic header sorting.
    ks::ui::setTableHeaderClickSortingEnabled(table, false);
    return table;
}

void MinidumpDock::clearResultTabs()
{
    // Detach the tab without destroying the control: all tables and editors are pre-created reusable members.
    // removeTab does not change parent-child relationships; the detached control remains a child of m_resultTabs.
    // If not explicitly hidden, it floats as a regular child control above the current page, appearing as "table overlap".
    while (resultTabs_->count() > 0)
    {
        QWidget* const kDetachedPage = resultTabs_->widget(0);
        resultTabs_->removeTab(0);
        if (kDetachedPage != nullptr)
        {
            kDetachedPage->hide();
        }
    }
}

QWidget* MinidumpDock::createStructuredTablePage(
    QTableWidget* table,
    const int columnCount) const
{
    // No grouping is needed for tables with five or fewer columns; returning the original table avoids adding meaningless control bars.
    if (table == nullptr || columnCount <= 5)
    {
        return table;
    }

    // page/pageLayout: Wide table page consists of tightly packed A/B/C controls and the original read-only table.
    auto* page = new QWidget(resultTabs_); // page: Outer page of this structure table.
    auto* pageLayout = new QVBoxLayout(page); // pageLayout: Arranges column group buttons and data tables vertically.
    pageLayout->setContentsMargins(0, 0, 0, 0);
    pageLayout->setSpacing(4);
    auto* buttonLayout = new QHBoxLayout(); // buttonLayout: Arrange A/B/C buttons with no spacing.
    buttonLayout->setContentsMargins(0, 0, 0, 0);
    buttonLayout->setSpacing(0);

    // groupCount: At most three groups; the first column serves as the identifier key and is retained in each group, while remaining columns are distributed evenly.
    const int kRemainingColumns = columnCount - 1; // remainingColumns: Number of fields excluding the identifier column.
    const int kGroupCount = std::clamp((kRemainingColumns + 3) / 4, 2, 3); // groupCount: actual number of column groups.
    const int kColumnsPerGroup = (kRemainingColumns + kGroupCount - 1) / kGroupCount; // columnsPerGroup: Maximum number of fields per group.
    auto groups = std::make_shared<std::vector<std::vector<int>>>(); // groups: Column indices displayed for each preset.
    auto buttons = std::make_shared<std::vector<QPointer<QPushButton>>>(); // buttons: Column group buttons that can be safely invalidated.

    // activeStyle/inactiveStyle: Currently use theme accent colors for presets; disable all coloring when customizing visibility.
    // Both strings are captured by value by applyGroup and the header's right-click menu, so every subsequent re-transmission uses the same
    // text instance—therefore, colors must all be taken from palette dynamic tokens. Once baked into static color values, theme switching
    // makes them unreachable from the outside. Active text uses highlighted-text, which pairs perfectly with palette(highlight) background.
    const QString kActiveStyle = QStringLiteral(
        "QPushButton { background:%1; color:palette(highlighted-text); "
        "border:1px solid %1; padding:3px 10px; }")
        .arg(ksword_theme::kPrimaryBlueHex); // activeStyle: Activates the preset style.
    const QString kInactiveStyle = QStringLiteral(
        "QPushButton { background:%1; color:%2; border:1px solid %3; padding:3px 10px; }"
        "QPushButton:hover { background:%4; }")
        .arg(
            ksword_theme::surfaceHex(),
            ksword_theme::textPrimaryHex(),
            ksword_theme::borderHex(),
            ksword_theme::surfaceAltHex()); // inactiveStyle: Unselected or custom layout style.

    for (int groupIndex = 0; groupIndex < kGroupCount; ++groupIndex)
    {
        // columns: Each group retains column 0 and adds its complementary fields.
        std::vector<int> columns{ 0 }; // columns: Currently visible columns for the A/B/C preset.
        const int kFirstColumn = 1 + groupIndex * kColumnsPerGroup; // firstColumn: first column of the current group.
        const int kEndColumn = std::min(columnCount, kFirstColumn + kColumnsPerGroup); // endColumn: The column immediately after the current group's end.
        for (int column = kFirstColumn; column < kEndColumn; ++column)
        {
            columns.push_back(column);
        }
        groups->push_back(std::move(columns));

        // groupButton: A/B/C use tight layout with hover tooltips indicating current behavior.
        const char16_t kGroupLetter = static_cast<char16_t>(u'A' + groupIndex); // groupLetter: Letter identifier for the current group.
        auto* groupButton = new QPushButton(
            QString(QChar(kGroupLetter)),
            page); // groupButton: Switch to the current complementary field group.
        groupButton->setMinimumWidth(36);
        groupButton->setToolTip(
            translated(
                "minidump.column_view.tooltip",
                "列组 %1：显示一组互补字段；可在表头右键自定义列。")
                .arg(groupButton->text()));
        groupButton->setStyleSheet(groupIndex == 0 ? kActiveStyle : kInactiveStyle);
        buttons->push_back(groupButton);
        buttonLayout->addWidget(groupButton);
    }
    buttonLayout->addStretch(1);
    pageLayout->addLayout(buttonLayout);
    pageLayout->addWidget(table, 1);

    // currentGroup: Index of the currently active preset. This function is called during the buildUi phase, at which
    // point the table has no columns yet. Consequently, all setColumnHidden calls within applyGroup are no-ops (Qt
    //ignores out-of-bounds sections). As a result, button A is highlighted as the "current view," but the table renders
    // with all columns visible after rendering, causing a mismatch between the highlight state and the actual view.
    // Record the current index and replay once the column count is finalized.
    auto currentGroup = std::make_shared<int>(0);

    // applyGroup: Hides all columns first, then displays only the target group and updates the button theme when switching presets.
    const auto kApplyGroup =
        [table, groups, buttons, kActiveStyle, kInactiveStyle, currentGroup](const int groupIndex)
        {
            *currentGroup = groupIndex;
            for (int column = 0; column < table->columnCount(); ++column)
            {
                table->setColumnHidden(column, true);
            }
            for (const int kColumn : groups->at(static_cast<std::size_t>(groupIndex)))
            {
                table->setColumnHidden(kColumn, false);
            }
            for (int buttonIndex = 0; buttonIndex < static_cast<int>(buttons->size()); ++buttonIndex)
            {
                if (buttons->at(static_cast<std::size_t>(buttonIndex)))
                {
                    buttons->at(static_cast<std::size_t>(buttonIndex))->setStyleSheet(
                        buttonIndex == groupIndex ? kActiveStyle : kInactiveStyle);
                }
            }
        };

    for (int groupIndex = 0; groupIndex < static_cast<int>(buttons->size()); ++groupIndex)
    {
        // groupButton: The current button is connected to its preset index; clicking it does not change the table data.
        QPushButton* groupButton = buttons->at(static_cast<std::size_t>(groupIndex)); // groupButton: Connect button.
        connect(
            groupButton,
            &QPushButton::clicked,
            page,
            [kApplyGroup, groupIndex]() { kApplyGroup(groupIndex); });
    }
    kApplyGroup(0);

    // Replay current presets when the column count changes from 0 to the actual value (setColumnCount in renderResult).
    // setColumnHidden only takes effect at this point; otherwise, button highlighting and table content will remain inconsistent long-term.
    // During subsequent re-parsing, the column count remains unchanged and the signal is not emitted, preserving the user's manually selected column groups.
    connect(
        table->horizontalHeader(),
        &QHeaderView::sectionCountChanged,
        page,
        [kApplyGroup, currentGroup](const int oldCount, const int newCount)
        {
            if (oldCount == 0 && newCount > 0)
            {
                kApplyGroup(*currentGroup);
            }
        });

    // Table header right-click menu allows per-column show/hide; each manual adjustment clears A/B/C activation colors to indicate a custom layout.
    // QMenu explicitly sets background/text/selection/disabled states per project specifications to avoid black text on black background caused by transparent inheritance.
    QHeaderView* tableHeader = table->horizontalHeader(); // tableHeader: table header carrying the column menu.
    tableHeader->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(
        tableHeader,
        &QHeaderView::customContextMenuRequested,
        page,
        [this, table, tableHeader, buttons, kInactiveStyle](const QPoint& position)
        {
            QMenu menu(tableHeader); // menu: Column visibility toggle menu existing only during the current right-click operation.
            menu.setStyleSheet(QStringLiteral(
                "QMenu { background:%1; color:%2; border:1px solid %3; }"
                "QMenu::item { padding:5px 22px; }"
                "QMenu::item:selected { background:%4; color:%5; }"
                "QMenu::item:disabled { color:%6; }")
                .arg(
                    ksword_theme::surfaceHex(),
                    ksword_theme::textPrimaryHex(),
                    ksword_theme::borderHex(),
                    ksword_theme::accentHex(ksword_theme::AccentRole::kBlue),
                    ksword_theme::onAccentDynamicHex(),
                    ksword_theme::textDisabledColorHex()));

            // columnAction: Check state directly reflects current column visibility.
            for (int column = 0; column < table->columnCount(); ++column)
            {
                QAction* columnAction = menu.addAction( // columnAction: Menu item controlling the visibility of a single column.
                    table->horizontalHeaderItem(column) != nullptr
                        ? table->horizontalHeaderItem(column)->text()
                        : translated("minidump.column.unnamed", "未命名列"));
                columnAction->setCheckable(true);
                columnAction->setChecked(!table->isColumnHidden(column));
                connect(
                    columnAction,
                    &QAction::toggled,
                    &menu,
                    [table, column, buttons, kInactiveStyle](const bool visible)
                    {
                        table->setColumnHidden(column, !visible);
                        for (const QPointer<QPushButton>& button : *buttons)
                        {
                            if (button)
                            {
                                button->setStyleSheet(kInactiveStyle);
                            }
                        }
                    });
            }
            menu.exec(tableHeader->mapToGlobal(position));
        });
    return page;
}

void MinidumpDock::renderResult(const ks::minidump::DumpParseResult& result)
{
    clearResultTabs();

    // ===================== Diagnostic Conclusion Page (placed first, the main output of this page) =====================
    const ks::minidump::DumpAnalysis& analysis = result.analysis;
    // Display this page whenever a conclusion text exists. Cases with 'None' confidence (e.g., snapshots without exception records) actually need
    // the clearest explanation that 'this is not a crash scene'; hiding them would only cause users to search fruitlessly for a crash point.
    if (result.success && !analysis.headline.isEmpty())
    {
        // The conclusion page is formatted in the order: 'state the conclusion first, then provide evidence, and finally present the action.'
        // Trust level must be indicated by a badge with a background color, not plain text: it determines how seriously
        // this conclusion should be treated, must be immediately visible, and cannot be mixed with other attributes.
        const QString kAccentHex = ksword_theme::accentHex(ksword_theme::AccentRole::kBlue);
        const QString kTextHex = ksword_theme::textPrimaryHex();
        const QString kMutedHex = ksword_theme::textDisabledColorHex();
        const QString kBorderHex = ksword_theme::borderHex();
        const QString kSurfaceAltHex = ksword_theme::surfaceAltHex();

        // confidenceColor: Lower confidence should be visually de-emphasized to avoid low-confidence conclusions being mistaken for facts.
        QColor confidenceColor = ksword_theme::textDisabledColor();
        switch (analysis.confidence)
        {
        case ks::minidump::AnalysisConfidence::kHigh:
            confidenceColor = ksword_theme::accentColor(ksword_theme::AccentRole::kRed);
            break;
        case ks::minidump::AnalysisConfidence::kMedium:
            confidenceColor = ksword_theme::accentColor(ksword_theme::AccentRole::kOrange);
            break;
        case ks::minidump::AnalysisConfidence::kLow:
            confidenceColor = ksword_theme::accentColor(ksword_theme::AccentRole::kYellow);
            break;
        case ks::minidump::AnalysisConfidence::kNone:
        default:
            break;
        }
        const QString kConfidenceHex = ksword_theme::themeColorName(confidenceColor);
        // confidenceTextHex: The badge foreground is calculated inversely based on the badge's own background color. Do not use onAccentHex(), as it only
        // performs contrast correction for the primary blue accent. When overlaid on Yellow (amber) or None (gray-blue), the white text achieves only a
        // 2:1 contrast ratio, yet these two states are precisely where users most need to clearly see "Do not treat this conclusion as definitive."
        const QString kConfidenceTextHex = ksword_theme::themeColorName(
            ksword_theme::ensureTextContrast(
                ksword_theme::textPrimaryColor(),
                confidenceColor));

        // escape: the conclusion text may contain <, >, or &; they must be escaped before being concatenated into HTML.
        const auto kEscape = [](const QString& text) { return text.toHtmlEscaped(); };

        QString html;
        html.reserve(2048);
        html += QStringLiteral("<div style='color:%1;'>").arg(kTextHex);

        // One-sentence conclusion: Maximum font size for the entire page, displayed in a separate block.
        html += QStringLiteral(
            "<div style='font-size:15pt; font-weight:600; line-height:150%%; margin:2px 0 10px 0;'>%1</div>")
            .arg(kEscape(ks::i18n::sourceText(analysis.headline)));

        // Badge row: trust level + fault classification.
        html += QStringLiteral("<div style='margin-bottom:14px;'>");
        html += QStringLiteral(
            "<span style='background:%1; color:%2; padding:3px 10px; "
            "border-radius:4px; font-weight:600;'>%3 %4</span>")
            .arg(kConfidenceHex)
            .arg(kConfidenceTextHex)
            .arg(translated("minidump.analysis.confidence", "可信度"))
            .arg(kEscape(ks::i18n::sourceText(
                ks::minidump::analysisConfidenceText(analysis.confidence))));
        if (!analysis.category.isEmpty())
        {
            html += QStringLiteral(
                "&nbsp;&nbsp;<span style='background:%1; color:%2; padding:3px 10px; "
                "border-radius:4px; border:1px solid %3;'>%4</span>")
                .arg(kSurfaceAltHex)
                .arg(kTextHex)
                .arg(kBorderHex)
                .arg(kEscape(ks::i18n::sourceText(analysis.category)));
        }
        html += QStringLiteral("</div>");

        // sectionHtml: Unified rendering of 'subtitle + item list'.
        const auto kSectionHtml =
            [&kEscape, &kAccentHex, &kTextHex](const QString& title, const QStringList& items)
            {
                if (items.isEmpty())
                {
                    return QString();
                }
                QString block = QStringLiteral(
                    "<div style='color:%1; font-weight:600; font-size:11pt; "
                    "margin:0 0 6px 0;'>%2</div>")
                    .arg(kAccentHex)
                    .arg(kEscape(title));
                block += QStringLiteral("<div style='margin:0 0 16px 0;'>");
                for (const QString& item : items)
                {
                    // Use hanging indented lines instead of <ul>: Qt rich text has limited control over list margins.
                    // Long entries wrapping will bump into the bullet points below, making the text harder to read.
                    block += QStringLiteral(
                        "<div style='color:%1; line-height:160%%; margin-bottom:5px;'>"
                        "<span style='color:%2;'>▸</span>&nbsp;%3</div>")
                        .arg(kTextHex)
                        .arg(kAccentHex)
                        .arg(kEscape(item));
                }
                block += QStringLiteral("</div>");
                return block;
            };

        QStringList localizedFindings;
        for (const QString& finding : analysis.findings)
        {
            localizedFindings.append(ks::i18n::sourceText(finding));
        }
        QStringList localizedSuggestions;
        for (const QString& suggestion : analysis.suggestions)
        {
            localizedSuggestions.append(ks::i18n::sourceText(suggestion));
        }

        // Crash point: the single most critical address in the entire report, isolated in its own block
        // with monospace font to prevent it from blending with other text in the evidence entries.
        if (result.faultingAddress != 0)
        {
            // faultSymbol: prefer the entry from the culprit candidates that belongs to the same module as the crash address, yielding "module+offset".
            QString faultSymbol;
            for (const ks::minidump::BlameEntry& blame : analysis.blame)
            {
                if (blame.address == result.faultingAddress && !blame.moduleName.isEmpty())
                {
                    faultSymbol = QStringLiteral("%1+0x%2")
                        .arg(blame.moduleName)
                        .arg(QString::number(blame.offset, 16).toUpper());
                    break;
                }
            }
            html += QStringLiteral(
                "<div style='background:%1; border:1px solid %2; border-radius:6px; "
                "padding:8px 12px; margin-bottom:16px;'>"
                "<span style='color:%3;'>%4</span>&nbsp;&nbsp;"
                "<span style='font-family:Consolas,monospace; font-size:11pt; color:%5;'>%6</span>")
                .arg(kSurfaceAltHex)
                .arg(kBorderHex)
                .arg(kMutedHex)
                .arg(translated("minidump.analysis.fault_address", "崩溃点"))
                .arg(kTextHex)
                .arg(hexText(result.faultingAddress));
            if (!faultSymbol.isEmpty())
            {
                html += QStringLiteral(
                    "&nbsp;&nbsp;<span style='color:%1; font-weight:600;'>%2</span>")
                    .arg(kAccentHex)
                    .arg(kEscape(faultSymbol));
            }
            html += QStringLiteral("</div>");
        }

        // Embed candidate blame modules directly on this page: they are the direct basis for the conclusion. It makes no sense to make users
        // jump to another tab just to view the top suspect. Render weights as bars for immediate visual comparison of relative magnitudes.
        if (!analysis.blame.empty())
        {
            html += QStringLiteral(
                "<div style='color:%1; font-weight:600; font-size:11pt; margin:0 0 8px 0;'>%2</div>")
                .arg(kAccentHex)
                .arg(kEscape(translated("minidump.analysis.blame_title", "肇事模块候选")));

            // maxWeight: Baseline for bar length. When all weights are 0, it degrades to equal lengths to avoid division by zero.
            int maxWeight = 1;
            for (const ks::minidump::BlameEntry& blame : analysis.blame)
            {
                maxWeight = std::max(maxWeight, blame.weight);
            }

            // List only the first few entries: the end of the candidate table is usually low-weight noise; the full list is on a dedicated page.
            constexpr std::size_t kInlineBlameLimit = 5;
            const std::size_t kShownCount =
                std::min(kInlineBlameLimit, analysis.blame.size());
            html += QStringLiteral("<table cellspacing='0' cellpadding='0' width='100%'>");
            for (std::size_t blameIndex = 0; blameIndex < kShownCount; ++blameIndex)
            {
                const ks::minidump::BlameEntry& blame = analysis.blame[blameIndex];
                const int kBarPercent =
                    std::clamp(blame.weight * 100 / maxWeight, 3, 100);
                // The top rank uses an emphasis color, while others use neutral colors: the sorting order already
                // conveys precedence; coloring everything would diminish the significance of the 'first place'.
                const QString kBarColor = (blameIndex == 0) ? kConfidenceHex : kBorderHex;
                const QString kNameText = blame.unloadedModule
                    ? QStringLiteral("%1 [%2]")
                        .arg(blame.moduleName, translated("minidump.blame.unloaded", "已卸载"))
                    : blame.moduleName;
                html += QStringLiteral(
                    "<tr>"
                    "<td width='34%%' style='padding:3px 8px 3px 0; color:%1;'>%2</td>"
                    "<td width='50%%' style='padding:3px 0;'>"
                    "<table cellspacing='0' cellpadding='0' width='100%%'><tr>"
                    "<td width='%3%%' style='background:%4;'>&nbsp;</td>"
                    "<td>&nbsp;</td></tr></table></td>"
                    "<td width='16%%' style='padding:3px 0 3px 8px; color:%5;'>%6 %7</td>"
                    "</tr>")
                    .arg(kTextHex)
                    .arg(kEscape(kNameText))
                    .arg(kBarPercent)
                    .arg(kBarColor)
                    .arg(kMutedHex)
                    .arg(translated("minidump.column.weight", "证据权重"))
                    .arg(blame.weight);
            }
            html += QStringLiteral("</table>");
            if (analysis.blame.size() > kShownCount)
            {
                html += QStringLiteral(
                    "<div style='color:%1; margin:4px 0 0 0;'>%2</div>")
                    .arg(kMutedHex)
                    .arg(kEscape(translated(
                        "minidump.analysis.blame_more",
                        "更多候选与逐条证据见“肇事模块”页。")));
            }
            html += QStringLiteral("<div style='margin-bottom:16px;'></div>");
        }

        html += kSectionHtml(
            translated("minidump.analysis.findings_title", "证据"),
            localizedFindings);
        html += kSectionHtml(
            translated("minidump.analysis.suggestions_title", "接下来怎么做"),
            localizedSuggestions);

        html += QStringLiteral("</div>");
        analysisView_->setHtml(html);
        resultTabs_->addTab(analysisView_,
            translated("minidump.tab.analysis", "诊断结论"));
    }

    // ===================== Blame Module Candidate Page =====================
    if (!analysis.blame.empty())
    {
        beginFill(blameTable_);
        blameTable_->setColumnCount(6);
        blameTable_->setHorizontalHeaderLabels({
            translated("minidump.column.suspect_module", "模块"),
            translated("minidump.column.suspect_function", "函数"),
            translated("minidump.column.hit_address", "命中地址"),
            translated("minidump.column.module_offset", "模块内偏移"),
            translated("minidump.column.weight", "证据权重"),
            translated("minidump.column.evidence", "证据") });
        blameTable_->setRowCount(static_cast<int>(analysis.blame.size()));
        int blameRow = 0;
        for (const ks::minidump::BlameEntry& blame : analysis.blame)
        {
            // moduleText: Unloaded modules are marked separately; this is the strongest single piece of evidence.
            const QString kModuleText = blame.unloadedModule
                ? QStringLiteral("%1 [%2]")
                    .arg(blame.moduleName,
                         translated("minidump.blame.unloaded", "已卸载"))
                : blame.moduleName;
            blameTable_->setItem(blameRow, 0, makeItem(kModuleText));
            // For signed entries, list function names separately: attributing to a module only indicates 'which driver',
            // while attributing to a function pinpoints the exact code; this is the most valuable column on this page.
            blameTable_->setItem(blameRow, 1, makeItem(blame.functionText));
            blameTable_->setItem(blameRow, 2, makeItem(hexText(blame.address)));
            blameTable_->setItem(blameRow, 3, makeItem(hexText(blame.offset)));
            blameTable_->setItem(blameRow, 4, makeItem(QString::number(blame.weight)));
            // evidence: Multiple evidence items are combined into a single line, separated by semicolons, to prevent line explosion.
            QStringList localizedEvidence;
            for (const QString& evidence : blame.evidence)
            {
                localizedEvidence.append(ks::i18n::sourceText(evidence));
            }
            blameTable_->setItem(blameRow, 5,
                makeItem(localizedEvidence.join(QStringLiteral("；"))));
            ++blameRow;
        }
        endFill(blameTable_);
        resultTabs_->addTab(blameTable_,
            translated("minidump.tab.blame", "肇事模块"));
    }

    // ===================== Overview Page (Always Present) =====================
    beginFill(overviewTable_);
    overviewTable_->setColumnCount(2);
    overviewTable_->setHorizontalHeaderLabels({
        translated("minidump.column.property", "属性"),
        translated("minidump.column.value", "值") });
    // overviewRows: Combine overview attributes and parsing alerts for display; set row count in one operation.
    const int kOverviewRowCount =
        static_cast<int>(result.overview.size()) +
        static_cast<int>(result.diagnostics.size()) +
        (result.memoryRegionShown < result.memoryRegionTotal ? 1 : 0);
    overviewTable_->setRowCount(kOverviewRowCount);
    int overviewRow = 0;
    for (const ks::minidump::DumpProperty& property : result.overview)
    {
        overviewTable_->setItem(overviewRow, 0,
            makeItem(ks::i18n::sourceText(property.name)));
        overviewTable_->setItem(overviewRow, 1,
            makeItem(ks::i18n::sourceText(property.value)));
        ++overviewRow;
    }
    // Memory truncation notes and parsing warnings are both listed as 'Parsing Warning' attribute rows/columns.
    if (result.memoryRegionShown < result.memoryRegionTotal)
    {
        overviewTable_->setItem(overviewRow, 0,
            makeItem(translated("minidump.overview.warning", "解析告警")));
        overviewTable_->setItem(overviewRow, 1,
            makeItem(translated(
                "minidump.overview.memory_truncated",
                "内存区域过多，仅展示前 %1 / %2 条。")
                .arg(result.memoryRegionShown)
                .arg(result.memoryRegionTotal)));
        ++overviewRow;
    }
    for (const QString& diagnostic : result.diagnostics)
    {
        overviewTable_->setItem(overviewRow, 0,
            makeItem(translated("minidump.overview.warning", "解析告警")));
        overviewTable_->setItem(overviewRow, 1,
            makeItem(ks::i18n::sourceText(diagnostic)));
        ++overviewRow;
    }
    endFill(overviewTable_);
    resultTabs_->addTab(overviewTable_, translated("minidump.tab.overview", "概览"));

    // ===================== Exception/Stop Code Page =====================
    if (!result.exceptionInfo.empty())
    {
        beginFill(exceptionTable_);
        exceptionTable_->setColumnCount(2);
        exceptionTable_->setHorizontalHeaderLabels({
            translated("minidump.column.property", "属性"),
            translated("minidump.column.value", "值") });
        exceptionTable_->setRowCount(static_cast<int>(result.exceptionInfo.size()));
        int exceptionRow = 0;
        for (const ks::minidump::DumpProperty& property : result.exceptionInfo)
        {
            exceptionTable_->setItem(exceptionRow, 0,
                makeItem(ks::i18n::sourceText(property.name)));
            exceptionTable_->setItem(exceptionRow, 1,
                makeItem(ks::i18n::sourceText(property.value)));
            ++exceptionRow;
        }
        endFill(exceptionTable_);
        // Multi-line 'Parameter Meaning' allows line wrapping for display.
        exceptionTable_->setWordWrap(true);
        exceptionTable_->resizeRowsToContents();
        resultTabs_->addTab(exceptionTable_,
            translated("minidump.tab.exception", "异常信息"));
    }

    // ===================== Crash Context Page ===================== TRIAGE small
    // kernel dumps save a local snapshot of the current CPU, KTHREAD, and EPROCESS.
    // They differ from user-mode MINIDUMP_THREAD on the 'thread' page and cannot be displayed together.
    if (!result.executionContext.empty())
    {
        beginFill(executionContextTable_);
        executionContextTable_->setColumnCount(2);
        executionContextTable_->setHorizontalHeaderLabels({
            translated("minidump.column.property", "属性"),
            translated("minidump.column.value", "值") });
        executionContextTable_->setRowCount(
            static_cast<int>(result.executionContext.size()));
        int contextRow = 0;
        for (const ks::minidump::DumpProperty& property : result.executionContext)
        {
            executionContextTable_->setItem(contextRow, 0,
                makeItem(ks::i18n::sourceText(property.name)));
            executionContextTable_->setItem(contextRow, 1,
                makeItem(ks::i18n::sourceText(property.value)));
            ++contextRow;
        }
        endFill(executionContextTable_);
        resultTabs_->addTab(executionContextTable_,
            translated("minidump.tab.execution_context", "崩溃现场"));
    }

    // ===================== Call Stack Page =====================
    if (!result.stackFrames.empty())
    {
        beginFill(stackTable_);
        stackTable_->setColumnCount(7);
        stackTable_->setHorizontalHeaderLabels({
            translated("minidump.column.thread_id", "线程 ID"),
            translated("minidump.column.frame_index", "帧"),
            translated("minidump.column.symbol", "符号"),
            translated("minidump.column.source_location", "源码位置"),
            translated("minidump.column.frame_address", "返回地址"),
            translated("minidump.column.stack_address", "栈地址"),
            translated("minidump.column.frame_source", "来源") });
        stackTable_->setRowCount(static_cast<int>(result.stackFrames.size()));
        int stackRow = 0;
        for (const ks::minidump::StackFrameEntry& frame : result.stackFrames)
        {
            stackTable_->setItem(stackRow, 0,
                makeItem(frame.threadId != 0
                    ? QString::number(frame.threadId)
                    : translated("minidump.stack.crash_thread", "崩溃线程")));
            stackTable_->setItem(stackRow, 1, makeItem(QString::number(frame.index)));
            // The symbol column prioritizes 'Module!Function+Offset'; if unavailable, it falls back to 'Module+Offset'.
            // Synthesizing a single column instead of adding a new one prevents the table from becoming so wide that column groups are
            // required. Once grouped, the 'Source' column might be hidden, leaving no place to display the false-positive warning.
            const QString kBaseSymbol = frame.functionText.isEmpty()
                ? frame.symbolText
                : frame.functionText;
            const QString kSymbolText = frame.unloadedModule
                ? QStringLiteral("%1 [%2]")
                    .arg(kBaseSymbol,
                         translated("minidump.blame.unloaded", "已卸载"))
                : kBaseSymbol;
            stackTable_->setItem(stackRow, 2, makeItem(kSymbolText));
            // Source location is only valid when both the image and PDB match; the parser has already filtered out untrusted data.
            stackTable_->setItem(stackRow, 3, makeItem(frame.sourceText));
            stackTable_->setItem(stackRow, 4, makeItem(hexText(frame.address)));
            stackTable_->setItem(stackRow, 5,
                makeItem(frame.stackAddress != 0 ? hexText(frame.stackAddress) : QString()));
            // Source must be accurately labeled: only frame 0 is from CONTEXT; the rest are scan-based guesses.
            stackTable_->setItem(stackRow, 6,
                makeItem(frame.fromContext
                    ? translated("minidump.stack.from_context", "上下文（可信）")
                    : translated("minidump.stack.from_scan", "栈扫描（可能误报）")));
            ++stackRow;
        }
        endFill(stackTable_);
        resultTabs_->addTab(stackPage_,
            translated("minidump.tab.stack", "调用栈"));
    }

    // ===================== Crash History Page ===================== A single dump cannot answer two things:
    // whether this was a BSOD or a "hard hang without a dump," and which driver build was running at the
    // time of the crash. The former determines whether to search for dump files; the latter determines
    // whether the fix took effect. Both judgments rely solely on the system event log for answers.
    if (!result.crashHistory.empty())
    {
        beginFill(crashHistoryTable_);
        crashHistoryTable_->setColumnCount(4);
        crashHistoryTable_->setHorizontalHeaderLabels({
            translated("minidump.column.event_time", "时间"),
            translated("minidump.column.event_kind", "性质"),
            translated("minidump.column.event_summary", "摘要"),
            translated("minidump.column.detail", "说明") });
        crashHistoryTable_->setRowCount(
            static_cast<int>(result.crashHistory.size()));
        int historyRow = 0;
        for (const ks::minidump::CrashHistoryEntry& entry : result.crashHistory)
        {
            crashHistoryTable_->setItem(historyRow, 0,
                makeItem(entry.time.toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"))));
            crashHistoryTable_->setItem(historyRow, 1,
                makeItem(ks::i18n::sourceText(entry.kindText)));
            crashHistoryTable_->setItem(historyRow, 2,
                makeItem(ks::i18n::sourceText(entry.summary)));
            crashHistoryTable_->setItem(historyRow, 3,
                makeItem(ks::i18n::sourceText(entry.detail)));
            ++historyRow;
        }
        endFill(crashHistoryTable_);
        resultTabs_->addTab(crashHistoryTable_,
            translated("minidump.tab.crash_history", "崩溃历史"));
    }

    // ===================== Pool Tag Page ===================== In pool corruption stop codes
    // (0x13A / 0xC2 / 0x19...), identifying "who owns the corrupted memory" is more indicative of
    // the culprit than the call stack: the stack often only shows the next module that allocated
    // memory and thus hit the bad list; two crashes can be caused by two unrelated modules.
    if (!result.poolTags.empty())
    {
        beginFill(poolTagTable_);
        poolTagTable_->setColumnCount(4);
        poolTagTable_->setHorizontalHeaderLabels({
            translated("minidump.column.pool_tag", "池标记"),
            translated("minidump.column.pool_tag_source", "来源"),
            translated("minidump.column.pool_tag_owner", "映像中出现该标记的模块"),
            translated("minidump.column.pool_tag_purpose", "已知用途") });
        poolTagTable_->setRowCount(static_cast<int>(result.poolTags.size()));
        int poolRow = 0;
        for (const ks::minidump::PoolTagCandidate& candidate : result.poolTags)
        {
            poolTagTable_->setItem(poolRow, 0, makeItem(candidate.tagText));
            poolTagTable_->setItem(poolRow, 1,
                makeItem(ks::i18n::sourceText(candidate.source)));
            poolTagTable_->setItem(poolRow, 2,
                makeItem(candidate.ownerModules.join(QStringLiteral("、"))));
            poolTagTable_->setItem(poolRow, 3, makeItem(candidate.knownPurpose));
            ++poolRow;
        }
        endFill(poolTagTable_);
        resultTabs_->addTab(poolTagTable_,
            translated("minidump.tab.pool_tags", "池标记"));
    }

    // ===================== Symbol Status Page ===================== The sole reason for this page's
    // existence is to make "whether function names and line numbers are trustworthy" a visible
    // conclusion for users. The most dangerous failure mode of symbolication is not an error, but
    // silently providing globally misaligned line numbers after the image has been recompiled.
    if (!result.symbolStatus.empty())
    {
        beginFill(symbolTable_);
        symbolTable_->setColumnCount(5);
        symbolTable_->setHorizontalHeaderLabels({
            translated("minidump.column.module", "模块"),
            translated("minidump.column.symbol_state", "符号状态"),
            translated("minidump.column.image_path", "映像路径"),
            translated("minidump.column.pdb_path", "PDB 路径"),
            translated("minidump.column.detail", "说明") });
        symbolTable_->setRowCount(static_cast<int>(result.symbolStatus.size()));
        int symbolRow = 0;
        for (const ks::minidump::ModuleSymbolStatus& status : result.symbolStatus)
        {
            symbolTable_->setItem(symbolRow, 0, makeItem(status.moduleName));
            symbolTable_->setItem(symbolRow, 1,
                makeItem(ks::i18n::sourceText(
                    ks::minidump::symbolMatchStateText(status.state))));
            symbolTable_->setItem(symbolRow, 2, makeItem(status.imagePath));
            symbolTable_->setItem(symbolRow, 3, makeItem(status.pdbPath));
            symbolTable_->setItem(symbolRow, 4,
                makeItem(ks::i18n::sourceText(status.detail)));
            ++symbolRow;
        }
        endFill(symbolTable_);
        resultTabs_->addTab(symbolTable_,
            translated("minidump.tab.symbols", "符号"));
    }

    // ===================== Register page =====================
    if (!result.registers.empty())
    {
        beginFill(registerTable_);
        registerTable_->setColumnCount(3);
        registerTable_->setHorizontalHeaderLabels({
            translated("minidump.column.register", "寄存器"),
            translated("minidump.column.value", "值"),
            translated("minidump.column.interpretation", "解读") });
        registerTable_->setRowCount(static_cast<int>(result.registers.size()));
        int registerRow = 0;
        for (const ks::minidump::RegisterEntry& registerEntry : result.registers)
        {
            registerTable_->setItem(registerRow, 0, makeItem(registerEntry.name));
            registerTable_->setItem(registerRow, 1, makeItem(hexText(registerEntry.value)));
            registerTable_->setItem(registerRow, 2,
                makeItem(ks::i18n::sourceText(registerEntry.note)));
            ++registerRow;
        }
        endFill(registerTable_);
        resultTabs_->addTab(registerTable_,
            translated("minidump.tab.registers", "寄存器"));
    }

    // ===================== Stream directory / data layout page =====================
    if (!result.streams.empty())
    {
        beginFill(streamTable_);
        streamTable_->setColumnCount(5);
        streamTable_->setHorizontalHeaderLabels({
            translated("minidump.column.stream_type", "类型编号"),
            translated("minidump.column.stream_name", "类型名"),
            translated("minidump.column.offset", "文件偏移"),
            translated("minidump.column.size", "大小"),
            translated("minidump.column.note", "说明") });
        streamTable_->setRowCount(static_cast<int>(result.streams.size()));
        int streamRow = 0;
        for (const ks::minidump::StreamEntry& stream : result.streams)
        {
            streamTable_->setItem(streamRow, 0, makeItem(QString::number(stream.type)));
            streamTable_->setItem(streamRow, 1, makeItem(stream.typeName));
            streamTable_->setItem(streamRow, 2, makeItem(hexText(stream.rva)));
            streamTable_->setItem(streamRow, 3, makeItem(QString::number(stream.size)));
            streamTable_->setItem(streamRow, 4,
                makeItem(ks::i18n::sourceText(stream.note)));
            ++streamRow;
        }
        endFill(streamTable_);
        resultTabs_->addTab(streamTable_,
            result.kind == ks::minidump::DumpKind::kUserMinidump
                ? translated("minidump.tab.streams", "流目录")
                : translated("minidump.tab.layout", "数据布局"));
    }

    // ===================== Modules/Drivers Page =====================
    if (!result.modules.empty())
    {
        beginFill(moduleTable_);
        moduleTable_->setColumnCount(8);
        moduleTable_->setHorizontalHeaderLabels({
            translated("minidump.column.module_name", "名称"),
            translated("minidump.column.base", "基址"),
            translated("minidump.column.size", "大小"),
            translated("minidump.column.timestamp", "时间戳"),
            translated("minidump.column.version", "版本"),
            translated("minidump.column.pdb_file", "PDB 文件"),
            translated("minidump.column.pdb_guid", "PDB GUID/Age"),
            translated("minidump.column.checksum", "校验和") });
        moduleTable_->setRowCount(static_cast<int>(result.modules.size()));
        int moduleRow = 0;
        for (const ks::minidump::ModuleEntry& module : result.modules)
        {
            moduleTable_->setItem(moduleRow, 0, makeItem(module.name));
            moduleTable_->setItem(moduleRow, 1, makeItem(hexText(module.base)));
            moduleTable_->setItem(moduleRow, 2, makeItem(hexText(module.size)));
            moduleTable_->setItem(moduleRow, 3, makeItem(module.timestampText));
            moduleTable_->setItem(moduleRow, 4, makeItem(module.version));
            moduleTable_->setItem(moduleRow, 5, makeItem(module.pdbName));
            moduleTable_->setItem(moduleRow, 6, makeItem(module.pdbGuidAge));
            moduleTable_->setItem(moduleRow, 7,
                makeItem(module.checksum != 0 ? hexText(module.checksum) : QString()));
            ++moduleRow;
        }
        endFill(moduleTable_);
        resultTabs_->addTab(modulePage_,
            result.kind == ks::minidump::DumpKind::kUserMinidump
                ? translated("minidump.tab.modules", "模块")
                : translated("minidump.tab.drivers", "驱动"));
    }

    // ===================== Threads Page =====================
    if (!result.threads.empty())
    {
        beginFill(threadTable_);
        threadTable_->setColumnCount(13);
        threadTable_->setHorizontalHeaderLabels({
            translated("minidump.column.thread_id", "线程 ID"),
            translated("minidump.column.thread_state", "状态"),
            translated("minidump.column.thread_name", "名称"),
            translated("minidump.column.instruction_pointer", "指令指针"),
            translated("minidump.column.ip_module", "指令指针所属模块"),
            translated("minidump.column.start_address", "起始地址"),
            translated("minidump.column.start_module", "起始地址所属模块"),
            translated("minidump.column.cpu_time", "CPU 时间(用户/内核)"),
            translated("minidump.column.teb", "TEB"),
            translated("minidump.column.stack_base", "栈基址"),
            translated("minidump.column.stack_size", "栈大小"),
            translated("minidump.column.suspend_count", "挂起计数"),
            translated("minidump.column.priority", "优先级") });
        threadTable_->setRowCount(static_cast<int>(result.threads.size()));
        int threadRow = 0;
        for (const ks::minidump::ThreadEntry& thread : result.threads)
        {
            threadTable_->setItem(threadRow, 0, makeItem(QString::number(thread.threadId)));
            threadTable_->setItem(threadRow, 1,
                makeItem(thread.faulting
                    ? translated("minidump.thread.faulting", "崩溃线程")
                    : QString()));
            threadTable_->setItem(threadRow, 2, makeItem(thread.name));
            threadTable_->setItem(threadRow, 3,
                makeItem(thread.instructionPointer != 0
                    ? hexText(thread.instructionPointer)
                    : QString()));
            threadTable_->setItem(threadRow, 4, makeItem(thread.ipSymbolText));
            threadTable_->setItem(threadRow, 5,
                makeItem(thread.startAddress != 0 ? hexText(thread.startAddress) : QString()));
            threadTable_->setItem(threadRow, 6, makeItem(thread.startSymbolText));
            threadTable_->setItem(threadRow, 7, makeItem(thread.cpuTimeText));
            threadTable_->setItem(threadRow, 8, makeItem(hexText(thread.teb)));
            threadTable_->setItem(threadRow, 9, makeItem(hexText(thread.stackBase)));
            threadTable_->setItem(threadRow, 10, makeItem(QString::number(thread.stackSize)));
            threadTable_->setItem(threadRow, 11, makeItem(QString::number(thread.suspendCount)));
            threadTable_->setItem(threadRow, 12,
                makeItem(QStringLiteral("%1 / %2")
                    .arg(thread.priorityClass)
                    .arg(thread.priority)));
            ++threadRow;
        }
        endFill(threadTable_);
        resultTabs_->addTab(threadPage_, translated("minidump.tab.threads", "线程"));
    }

    // ===================== Memory Region Pages =====================
    if (!result.memoryRegions.empty())
    {
        beginFill(memoryTable_);
        memoryTable_->setColumnCount(6);
        memoryTable_->setHorizontalHeaderLabels({
            translated("minidump.column.base", "基址"),
            translated("minidump.column.size", "大小"),
            translated("minidump.column.mem_state", "状态"),
            translated("minidump.column.mem_protect", "保护"),
            translated("minidump.column.mem_type", "类型"),
            translated("minidump.column.mem_source", "来源") });
        memoryTable_->setRowCount(static_cast<int>(result.memoryRegions.size()));
        int memoryRow = 0;
        for (const ks::minidump::MemoryRegionEntry& region : result.memoryRegions)
        {
            memoryTable_->setItem(memoryRow, 0, makeItem(hexText(region.base)));
            memoryTable_->setItem(memoryRow, 1, makeItem(hexText(region.size)));
            memoryTable_->setItem(memoryRow, 2, makeItem(region.state));
            memoryTable_->setItem(memoryRow, 3, makeItem(region.protect));
            memoryTable_->setItem(memoryRow, 4, makeItem(region.type));
            memoryTable_->setItem(memoryRow, 5,
                makeItem(ks::i18n::sourceText(region.source)));
            ++memoryRow;
        }
        endFill(memoryTable_);
        resultTabs_->addTab(memoryPage_,
            translated("minidump.tab.memory", "内存区域"));
    }

    // ===================== Original Memory Preview Page ===================== TRIAGE data
    // blocks and Secondary Dump Data are raw bytes saved alongside small kernel dumps.
    // This displays a limited preview copied by the parser after boundary checks are complete. Never let the
    // UI re-read the file, and never mislabel auxiliary data without virtual addresses as complete memory.
    if (!result.byteBlocks.empty())
    {
        QString rawText;
        rawText.reserve(static_cast<qsizetype>(result.byteBlocks.size() * 2000));
        for (std::size_t index = 0; index < result.byteBlocks.size(); ++index)
        {
            const ks::minidump::DumpByteBlock& block = result.byteBlocks[index];
            if (index != 0)
            {
                rawText += QLatin1Char('\n');
            }
            const std::uint64_t kPreviewBytes = block.previewBytes.size();
            const std::uint64_t kOmittedBytes = block.capturedBytes > kPreviewBytes
                ? block.capturedBytes - kPreviewBytes
                : 0;
            rawText += QStringLiteral("[%1 %2]\n%3: %4\n%5: %6\n%7: %8\n%9: %10 %11\n%12: %13 %14\n\n")
                .arg(translated("minidump.raw.block", "数据块"))
                .arg(index + 1)
                .arg(translated("minidump.raw.source", "来源"))
                .arg(block.source)
                .arg(translated("minidump.raw.address", "虚拟地址"))
                .arg(block.hasVirtualAddress
                    ? hexText(block.address)
                    : translated("minidump.raw.not_applicable", "不适用"))
                .arg(translated("minidump.raw.file_offset", "文件偏移"))
                .arg(hexText(block.fileOffset))
                .arg(translated("minidump.raw.captured_size", "完整捕获大小"))
                .arg(block.capturedBytes)
                .arg(translated("minidump.raw.bytes", "字节"))
                .arg(translated("minidump.raw.preview_size", "预览大小"))
                .arg(kPreviewBytes)
                .arg(translated("minidump.raw.bytes", "字节"));
            rawText += ks::minidump::formatDumpBytes(
                block.hasVirtualAddress ? block.address : block.fileOffset,
                block.previewBytes.empty() ? nullptr : block.previewBytes.data(),
                kPreviewBytes,
                kOmittedBytes);
        }
        rawMemoryEditor_->setRawText(rawText);
        resultTabs_->addTab(rawMemoryEditor_,
            translated("minidump.tab.raw_memory", "原始内存"));
    }

    // ===================== Memory Viewer Tab ===================== The preview tab retains only the leading bytes
    // of a few TRIAGE blocks; the viewer reopens the DMP file based on address mappings validated during the parsing
    // phase, supports paging to read complete blocks, and covers both MDMP memory streams and thread stacks.
    if (!result.capturedMemoryRanges.empty())
    {
        memoryView_->setDumpData(result);
        resultTabs_->addTab(memoryView_,
            translated("minidump.tab.memory_view", "内存查看器"));
    }
    else
    {
        memoryView_->clearData();
    }

    // ===================== Handles Page =====================
    if (!result.handles.empty())
    {
        beginFill(handleTable_);
        handleTable_->setColumnCount(7);
        handleTable_->setHorizontalHeaderLabels({
            translated("minidump.column.handle_value", "句柄值"),
            translated("minidump.column.handle_type", "类型"),
            translated("minidump.column.object_name", "对象名"),
            translated("minidump.column.attributes", "属性"),
            translated("minidump.column.granted_access", "访问掩码"),
            translated("minidump.column.handle_count", "句柄计数"),
            translated("minidump.column.pointer_count", "指针计数") });
        handleTable_->setRowCount(static_cast<int>(result.handles.size()));
        int handleRow = 0;
        for (const ks::minidump::HandleEntry& handle : result.handles)
        {
            handleTable_->setItem(handleRow, 0, makeItem(hexText(handle.handleValue)));
            handleTable_->setItem(handleRow, 1, makeItem(handle.typeName));
            handleTable_->setItem(handleRow, 2, makeItem(handle.objectName));
            handleTable_->setItem(handleRow, 3, makeItem(hexText(handle.attributes)));
            handleTable_->setItem(handleRow, 4, makeItem(hexText(handle.grantedAccess)));
            handleTable_->setItem(handleRow, 5, makeItem(QString::number(handle.handleCount)));
            handleTable_->setItem(handleRow, 6, makeItem(QString::number(handle.pointerCount)));
            ++handleRow;
        }
        endFill(handleTable_);
        resultTabs_->addTab(handlePage_, translated("minidump.tab.handles", "句柄"));
    }

    // ===================== Unloaded Modules Page =====================
    if (!result.unloadedModules.empty())
    {
        beginFill(unloadedTable_);
        unloadedTable_->setColumnCount(5);
        unloadedTable_->setHorizontalHeaderLabels({
            translated("minidump.column.module_name", "名称"),
            translated("minidump.column.base", "基址"),
            translated("minidump.column.size", "大小"),
            translated("minidump.column.timestamp", "时间戳"),
            translated("minidump.column.checksum", "校验和") });
        unloadedTable_->setRowCount(static_cast<int>(result.unloadedModules.size()));
        int unloadedRow = 0;
        for (const ks::minidump::UnloadedModuleEntry& module : result.unloadedModules)
        {
            unloadedTable_->setItem(unloadedRow, 0, makeItem(module.name));
            unloadedTable_->setItem(unloadedRow, 1, makeItem(hexText(module.base)));
            unloadedTable_->setItem(unloadedRow, 2, makeItem(hexText(module.size)));
            unloadedTable_->setItem(unloadedRow, 3, makeItem(module.timestampText));
            unloadedTable_->setItem(unloadedRow, 4,
                makeItem(module.checksum != 0 ? hexText(module.checksum) : QString()));
            ++unloadedRow;
        }
        endFill(unloadedTable_);
        resultTabs_->addTab(unloadedTable_,
            translated("minidump.tab.unloaded", "已卸载模块"));
    }

    // ===================== Full Report Page =====================
    if (result.success)
    {
        // Reports are generated using standardized Chinese text; the read-only editor renders content in real-time according to the current language.
        reportEditor_->setLocalizedText(buildReportText(result));
        resultTabs_->addTab(reportEditor_, translated("minidump.tab.report", "报告"));
    }
}

QString MinidumpDock::buildReportText(const ks::minidump::DumpParseResult& result) const
{
    // lines: Chinese-formatted report constructed line-by-line; shared text for export and read-only pages.
    QStringList lines;
    lines.append(QStringLiteral("KSword 转储解析报告"));
    lines.append(QStringLiteral("文件: %1").arg(result.filePath));
    lines.append(QStringLiteral("================================================"));

    // Place the diagnostic conclusion at the beginning of the report: the reader should see the conclusion first, not the raw fields.
    const ks::minidump::DumpAnalysis& analysis = result.analysis;
    if (!analysis.headline.isEmpty())
    {
        lines.append(QStringLiteral("[诊断结论]"));
        lines.append(QStringLiteral("结论: %1").arg(analysis.headline));
        lines.append(QStringLiteral("可信度: %1")
            .arg(ks::minidump::analysisConfidenceText(analysis.confidence)));
        if (!analysis.category.isEmpty())
        {
            lines.append(QStringLiteral("故障归类: %1").arg(analysis.category));
        }
        for (const QString& finding : analysis.findings)
        {
            lines.append(QStringLiteral("发现: %1").arg(finding));
        }
        for (const QString& suggestion : analysis.suggestions)
        {
            lines.append(QStringLiteral("建议: %1").arg(suggestion));
        }
        lines.append(QString());
    }

    if (!analysis.blame.empty())
    {
        lines.append(QStringLiteral("[肇事模块候选] 按证据权重降序"));
        for (const ks::minidump::BlameEntry& blame : analysis.blame)
        {
            QString blameLine = QStringLiteral("%1\t权重 %2\t命中 %3 (+%4)")
                .arg(blame.moduleName)
                .arg(blame.weight)
                .arg(hexText(blame.address))
                .arg(hexText(blame.offset));
            if (blame.unloadedModule)
            {
                blameLine += QStringLiteral("\t[已卸载模块]");
            }
            lines.append(blameLine);
            for (const QString& evidence : blame.evidence)
            {
                lines.append(QStringLiteral("    证据: %1").arg(evidence));
            }
        }
        lines.append(QString());
    }

    // Output overview properties line by line in a unified format of 'Property: Value'.
    lines.append(QStringLiteral("[概览]"));
    for (const ks::minidump::DumpProperty& property : result.overview)
    {
        lines.append(QStringLiteral("%1: %2").arg(property.name, property.value));
    }
    lines.append(QString());

    if (!result.exceptionInfo.empty())
    {
        lines.append(QStringLiteral("[异常信息]"));
        for (const ks::minidump::DumpProperty& property : result.exceptionInfo)
        {
            lines.append(QStringLiteral("%1: %2").arg(property.name, property.value));
        }
        lines.append(QString());
    }

    if (!result.executionContext.empty())
    {
        lines.append(QStringLiteral("[崩溃现场]"));
        for (const ks::minidump::DumpProperty& property : result.executionContext)
        {
            lines.append(QStringLiteral("%1: %2")
                .arg(property.name, property.value));
        }
        lines.append(QString());
    }

    if (!result.registers.empty())
    {
        lines.append(QStringLiteral("[崩溃点寄存器]"));
        for (const ks::minidump::RegisterEntry& registerEntry : result.registers)
        {
            QString registerLine = QStringLiteral("%1 = %2")
                .arg(registerEntry.name, hexText(registerEntry.value));
            if (!registerEntry.note.isEmpty())
            {
                registerLine += QStringLiteral("\t%1").arg(registerEntry.note);
            }
            lines.append(registerLine);
        }
        lines.append(QString());
    }

    if (!result.stackFrames.empty())
    {
        // This limitation note must be repeated in the report: it must be visible even when the report is viewed outside the UI.
        lines.append(QStringLiteral(
            "[疑似调用栈] 由栈内存扫描重建，无符号；顺序为近似值，可能含残留帧"));
        // lastThreadId: Inserts a separator line on thread switch to ensure multi-threaded stack traces are readable.
        std::uint32_t lastThreadId = 0xFFFFFFFFu;
        for (const ks::minidump::StackFrameEntry& frame : result.stackFrames)
        {
            if (frame.threadId != lastThreadId)
            {
                lines.append(QStringLiteral("-- 线程 %1 --").arg(frame.threadId));
                lastThreadId = frame.threadId;
            }
            lines.append(QStringLiteral("%1\t%2\t%3\t%4")
                .arg(frame.index, 2)
                .arg(hexText(frame.address))
                .arg(frame.symbolText)
                .arg(frame.fromContext
                    ? QStringLiteral("上下文")
                    : QStringLiteral("栈扫描")));
        }
        lines.append(QString());
    }

    if (!result.streams.empty())
    {
        lines.append(QStringLiteral("[数据流]"));
        for (const ks::minidump::StreamEntry& stream : result.streams)
        {
            lines.append(QStringLiteral("%1\t%2\t偏移 %3\t大小 %4")
                .arg(stream.type)
                .arg(stream.typeName)
                .arg(hexText(stream.rva))
                .arg(stream.size));
        }
        lines.append(QString());
    }

    if (!result.modules.empty())
    {
        lines.append(QStringLiteral("[模块] 共 %1 个").arg(result.modules.size()));
        for (const ks::minidump::ModuleEntry& module : result.modules)
        {
            // moduleLine: single-line module summary; optional fields are appended only if present.
            QString moduleLine = QStringLiteral("%1\t基址 %2\t大小 %3")
                .arg(module.name)
                .arg(hexText(module.base))
                .arg(hexText(module.size));
            if (!module.version.isEmpty())
            {
                moduleLine += QStringLiteral("\t版本 %1").arg(module.version);
            }
            if (!module.timestampText.isEmpty())
            {
                moduleLine += QStringLiteral("\t时间戳 %1").arg(module.timestampText);
            }
            if (!module.pdbName.isEmpty())
            {
                moduleLine += QStringLiteral("\tPDB %1").arg(module.pdbName);
            }
            lines.append(moduleLine);
        }
        lines.append(QString());
    }

    if (!result.threads.empty())
    {
        lines.append(QStringLiteral("[线程] 共 %1 个").arg(result.threads.size()));
        for (const ks::minidump::ThreadEntry& thread : result.threads)
        {
            QString threadLine = QStringLiteral("TID %1").arg(thread.threadId);
            if (thread.faulting)
            {
                threadLine += QStringLiteral("\t[崩溃线程]");
            }
            if (!thread.name.isEmpty())
            {
                threadLine += QStringLiteral("\t名称 %1").arg(thread.name);
            }
            if (thread.instructionPointer != 0)
            {
                threadLine += QStringLiteral("\tIP %1").arg(hexText(thread.instructionPointer));
            }
            threadLine += QStringLiteral("\tTEB %1\t栈 %2 (%3 字节)")
                .arg(hexText(thread.teb))
                .arg(hexText(thread.stackBase))
                .arg(thread.stackSize);
            lines.append(threadLine);
        }
        lines.append(QString());
    }

    if (!result.memoryRegions.empty())
    {
        lines.append(QStringLiteral("[内存区域] 共 %1 条").arg(result.memoryRegionTotal));
        // reportRows: Upper limit on memory rows in the report to prevent the report text from becoming too large.
        const std::size_t kReportRows =
            std::min(result.memoryRegions.size(), kReportMemoryRowLimit);
        for (std::size_t index = 0; index < kReportRows; ++index)
        {
            const ks::minidump::MemoryRegionEntry& region = result.memoryRegions[index];
            QString regionLine = QStringLiteral("%1\t大小 %2")
                .arg(hexText(region.base))
                .arg(hexText(region.size));
            if (!region.state.isEmpty())
            {
                regionLine += QStringLiteral("\t%1").arg(region.state);
            }
            if (!region.protect.isEmpty())
            {
                regionLine += QStringLiteral("\t%1").arg(region.protect);
            }
            if (!region.type.isEmpty())
            {
                regionLine += QStringLiteral("\t%1").arg(region.type);
            }
            lines.append(regionLine);
        }
        if (result.memoryRegions.size() > kReportRows)
        {
            lines.append(QStringLiteral("(其余 %1 条内存区域未列入报告)")
                .arg(result.memoryRegions.size() - kReportRows));
        }
        lines.append(QString());
    }

    if (!result.handles.empty())
    {
        lines.append(QStringLiteral("[句柄] 共 %1 个").arg(result.handles.size()));
        for (const ks::minidump::HandleEntry& handle : result.handles)
        {
            QString handleLine = QStringLiteral("%1\t%2")
                .arg(hexText(handle.handleValue))
                .arg(handle.typeName);
            if (!handle.objectName.isEmpty())
            {
                handleLine += QStringLiteral("\t%1").arg(handle.objectName);
            }
            lines.append(handleLine);
        }
        lines.append(QString());
    }

    if (!result.unloadedModules.empty())
    {
        lines.append(QStringLiteral("[已卸载模块] 共 %1 个").arg(result.unloadedModules.size()));
        for (const ks::minidump::UnloadedModuleEntry& module : result.unloadedModules)
        {
            lines.append(QStringLiteral("%1\t基址 %2\t大小 %3")
                .arg(module.name)
                .arg(hexText(module.base))
                .arg(hexText(module.size)));
        }
        lines.append(QString());
    }

    if (!result.diagnostics.isEmpty())
    {
        lines.append(QStringLiteral("[解析告警]"));
        for (const QString& diagnostic : result.diagnostics)
        {
            lines.append(diagnostic);
        }
    }
    return lines.join(QStringLiteral("\n"));
}
