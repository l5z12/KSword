#include "TableColumnAutoFit.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <iterator>
#include <vector>

#include <QAbstractItemView>
#include <QAbstractItemModel>
#include <QApplication>
#include <QEvent>
#include <QFontMetrics>
#include <QHeaderView>
#include <QModelIndex>
#include <QMouseEvent>
#include <QPointer>
#include <QSignalBlocker>
#include <QSize>
#include <QTableView>
#include <QTimer>
#include <QTreeView>
#include <QVariant>
#include <QWidget>

namespace
{
    // Centralize property names to avoid conflicts with business control properties.
    constexpr const char* kAutoFitInstalledProperty = "_ksword_table_column_auto_fit_installed";
    constexpr const char* kAutoFitScheduledProperty = "_ksword_table_column_auto_fit_scheduled";
    constexpr const char* kAutoFitApplyingProperty = "_ksword_table_column_auto_fit_applying";
    constexpr const char* kAutoFitUserAdjustedProperty = "_ksword_table_column_auto_fit_user_adjusted";
    constexpr const char* kAutoFitDisabledProperty = "_ksword_table_column_auto_fit_disabled";
    constexpr const char* kAutoFitHeaderHookedProperty = "_ksword_table_column_auto_fit_header_hooked";
    constexpr const char* kAutoFitResizePendingProperty = "_ksword_table_column_auto_fit_resize_pending";
    constexpr const char* kAutoFitResizePressPositionProperty = "_ksword_table_column_auto_fit_resize_press_position";
    constexpr const char* kAutoFitStretchSectionsProperty = "_ksword_table_column_auto_fit_stretch_sections";

    // kViewportPadding:
    // Reserves a few pixels on the right side of the viewport to avoid 1px horizontal scrollbars caused by rounding of style borders or grid lines.
    // - Do not change the scrollbar policy; only ensure the sum of column widths is slightly less than the viewport width.
    constexpr int kViewportPadding = 2;

    // kPreferredMinimumSectionWidth/kAbsoluteMinimumSectionWidth purpose:
    // - In normal cases, columns retain at least 24px to prevent content from becoming completely invisible.
    // - These two values are just the absolute lower bounds; the actual compression limit is determined by the 'readable lower bound' below.
    constexpr int kPreferredMinimumSectionWidth = 24;
    constexpr int kAbsoluteMinimumSectionWidth = 8;

    // kReadableSectionWidthCap:
    // - The upper bound of the 'readable minimum' for column width compression: if a column is compressed to the point where neither the header nor the first word is readable,
    //   the table displays only a row of ellipses, forcing the user to widen the window to view content—this is not adaptive behavior but shifting the problem to the user.
    // - The readable lower bound per column is min(preferred width, this constant): short columns (PID, CPU) cap at their own preferred
    //   width and won't be expanded by this value; only long-content columns (path, command line, endpoint) stop at this value.
    // - When the sum of all columns' minimum readable widths still exceeds the viewport, automatic fitting stops compressing further.
    //   The total column width naturally exceeds the viewport, and Qt displays a horizontal scrollbar according to ScrollBarAsNeeded.
    //   This file never modifies scroll bar policies, so horizontal scrolling is always available.
    constexpr int kReadableSectionWidthCap = 96;

    // kHeaderHorizontalPadding/kCellHorizontalPadding purpose:
    // - Compensate for item margins, grid lines, sort arrows, and icon whitespace when estimating column width using font metrics.
    // - Only affects the auto-calculated default width, not the actual rendering style.
    constexpr int kHeaderHorizontalPadding = 30;
    constexpr int kCellHorizontalPadding = 22;

    // kContentSampleRowLimit:
    // - Auto column width samples only a few rows to avoid full resizeToContents scanning on the UI thread for large tables.
    // - The header and the first few visible/root rows are typically sufficient to identify short columns like 'PID/CPU/Status' and long columns like 'Path/Command Line'.
    constexpr int kContentSampleRowLimit = 48;

    // kMeasuredTextCharacterLimit:
    // - For extremely long paths/command lines, only takes a prefix segment for estimation to prevent a single column's weight from scaling infinitely;
    // - Columns are still recognized as long columns and receive higher weight during compression or allocation of remaining space.
    constexpr int kMeasuredTextCharacterLimit = 180;

    // kLongColumnExpansionThreshold:
    // - Only columns whose preferred width reaches this threshold participate in 'filling the remaining width'.
    // - Short text columns will not be evenly expanded to a very wide column even if the table is wide.
    constexpr int kLongColumnExpansionThreshold = 120;

    // kResizeGripMargin:
    // - Detect if the user clicked near the header column boundary.
    // - Only such actions are treated as manual column width adjustments; ordinary click sorting does not disable auto-fit.
    constexpr int kResizeGripMargin = 6;

    // kCellWidgetHorizontalPadding:
    // - Reserve cell padding for the actual widgets created by setCellWidget/indexWidget.
    // - Prevents dropdowns, checkboxes, and buttons from being compressed to incorrect positions by the column width algorithm when first entering the table;
    // - This value serves only as a minimum width or preferred width compensation for automatic column fitting; it does not alter the control's own style.
    constexpr int kCellWidgetHorizontalPadding = 10;

    struct VisibleSection
    {
        int logicalIndex = -1;  // logicalIndex: Logical column index for QHeaderView.
        int currentWidth = 0;   // currentWidth: Snapshot of the current column width before auto-fit, retained for debugging and future extension.
        int minimumWidth = 0;   // minimumWidth: The minimum column width that should not be compressed in this round; control columns include the actual control width in this value.
        int preferredWidth = 0; // preferredWidth: Estimated preferred column width based on headers and sample content.
        int fittedWidth = 0;    // fittedWidth: The target column width after compression/expansion.
        bool prefersViewportExpansion = false; // prefersViewportExpansion: Candidate columns originally declared as Stretch at the business layer.
    };

    struct SectionWidthHints
    {
        int minimumWidth = 0;   // minimumWidth: The minimum column width that must be preserved.
        int preferredWidth = 0; // preferredWidth: The target width for comfortable content display.
    };

    // horizontalHeaderForView:
    // - Unified retrieval of the horizontal header from QTableView/QTreeView;
    // - QTableWidget and QTreeWidget inherit from these two classes, so no separate branch is needed.
    // Parameter view: Candidate table view.
    // Returns: valid horizontal header; nullptr for unsupported views.
    QHeaderView* horizontalHeaderForView(QAbstractItemView* view)
    {
        if (view == nullptr || qobject_cast<QHeaderView*>(view) != nullptr)
        {
            return nullptr;
        }

        if (QTableView* tableView = qobject_cast<QTableView*>(view))
        {
            return tableView->horizontalHeader();
        }

        if (QTreeView* treeView = qobject_cast<QTreeView*>(view))
        {
            return treeView->header();
        }

        return nullptr;
    }

    // viewForHorizontalHeader:
    // - Retrieve the associated table/tree from the header in reverse.
    // - Used to mark that the column width has been manually taken over by the user when dragging the header boundary.
    // Parameter header: Horizontal header.
    // Return value: The owning QAbstractItemView; nullptr if resolution fails.
    QAbstractItemView* viewForHorizontalHeader(QHeaderView* header)
    {
        if (header == nullptr || header->orientation() != Qt::Horizontal)
        {
            return nullptr;
        }

        return qobject_cast<QAbstractItemView*>(header->parentWidget());
    }

    // eventObjectToHorizontalHeader:
    // - Map QObject received by global event filter to QHeaderView;
    // - Mouse events usually reach the header viewport, so check parentWidget.
    // Parameter watchedObject: Event source object.
    // Return value: Horizontal QHeaderView; nullptr for unrelated objects.
    QHeaderView* eventObjectToHorizontalHeader(QObject* watchedObject)
    {
        if (QHeaderView* header = qobject_cast<QHeaderView*>(watchedObject))
        {
            return header->orientation() == Qt::Horizontal ? header : nullptr;
        }

        QWidget* watchedWidget = qobject_cast<QWidget*>(watchedObject);
        if (watchedWidget == nullptr)
        {
            return nullptr;
        }

        QHeaderView* parentHeader = qobject_cast<QHeaderView*>(watchedWidget->parentWidget());
        if (parentHeader == nullptr || parentHeader->orientation() != Qt::Horizontal)
        {
            return nullptr;
        }
        return parentHeader;
    }

    // isSupportedTableView:
    // - Check if the object is a table/tree view that this feature should handle.
    // - Exclude QHeaderView itself, as it also inherits from QAbstractItemView.
    // Parameter view: candidate view.
    // Return value: true = auto column width supported; false = ignored.
    bool isSupportedTableView(QAbstractItemView* view)
    {
        if (view == nullptr || qobject_cast<QHeaderView*>(view) != nullptr)
        {
            return false;
        }
        return qobject_cast<QTableView*>(view) != nullptr || qobject_cast<QTreeView*>(view) != nullptr;
    }

    // isAutoFitEnabled:
    // - Input: candidate table/tree view
    // - Processing: Read the business-layer configurable disable property, allowing views that manage their own column widths (e.g., file managers) to exit global column width logic.
    // - Return: true indicates global auto-fit can handle the view; false indicates it must be skipped.
    bool isAutoFitEnabled(QAbstractItemView* view)
    {
        return isSupportedTableView(view) && !view->property(kAutoFitDisabledProperty).toBool();
    }

    // eventObjectToSupportedView:
    // - Input: QObject received by global event filter;
    // - Processing: Recognize both the QTableView/QTreeView instances themselves and their viewport child controls.
    // - Returns: the view requiring column width auto-fit; returns nullptr for non-table objects.
    QAbstractItemView* eventObjectToSupportedView(QObject* watchedObject)
    {
        if (QAbstractItemView* directView = qobject_cast<QAbstractItemView*>(watchedObject))
        {
            return isAutoFitEnabled(directView) ? directView : nullptr;
        }

        QWidget* watchedWidget = qobject_cast<QWidget*>(watchedObject);
        if (watchedWidget == nullptr)
        {
            return nullptr;
        }

        QAbstractItemView* parentView = qobject_cast<QAbstractItemView*>(watchedWidget->parentWidget());
        if (!isAutoFitEnabled(parentView) || parentView->viewport() != watchedWidget)
        {
            return nullptr;
        }
        return parentView;
    }

    // measuredTextWidth:
    // - Measures the width required to display a given text using the specified font.
    // - Take the prefix of the single-line version of wrapped text to prevent excessively long content from infinitely inflating the weight of a specific column;
    // - Return value contains only the text pixel width, excluding item/header padding.
    int measuredTextWidth(const QFontMetrics& fontMetrics, const QString& sourceText)
    {
        QString measuredText = sourceText.simplified();
        if (measuredText.isEmpty())
        {
            return 0;
        }

        if (measuredText.size() > kMeasuredTextCharacterLimit)
        {
            measuredText = measuredText.left(kMeasuredTextCharacterLimit);
        }

        return std::max(0, fontMetrics.horizontalAdvance(measuredText));
    }

    // headerPreferredWidth:
    // - Estimate the required width for a specific table header based on the model's horizontal header text.
    // If the column displays a sort arrow, compensate for the arrow's placeholder width.
    // - Return value includes header padding and can be used directly in preferred column width calculations.
    int headerPreferredWidth(
        QAbstractItemView* view,
        QHeaderView* header,
        const int logicalIndex)
    {
        if (view == nullptr || header == nullptr || logicalIndex < 0)
        {
            return 0;
        }

        QAbstractItemModel* model = view->model();
        const QVariant kHeaderValue = model != nullptr
            ? model->headerData(logicalIndex, Qt::Horizontal, Qt::DisplayRole)
            : QVariant();
        const int kTextWidth = measuredTextWidth(header->fontMetrics(), kHeaderValue.toString());
        const int kSortIndicatorReserve = header->isSortIndicatorShown()
            && header->sortIndicatorSection() == logicalIndex
            ? 18
            : 0;
        return kTextWidth + kHeaderHorizontalPadding + kSortIndicatorReserve;
    }

    // widgetWidthHint:
    // - Input: the actual control placed in the cell via setCellWidget/indexWidget;
    // - Processing: Reads minimumWidth, minimumSizeHint, and optional sizeHint to determine the widget's non-compressible or comfortably displayable width.
    // - Returns: Widget width plus cell margins; returns 0 if there is no widget or the widget has no valid width.
    int widgetWidthHint(QWidget* cellWidget, const bool includePreferredSize)
    {
        if (cellWidget == nullptr)
        {
            return 0;
        }

        int widthValue = std::max(0, cellWidget->minimumWidth());
        const QSize kMinimumHint = cellWidget->minimumSizeHint();
        if (kMinimumHint.isValid() && kMinimumHint.width() > 0)
        {
            widthValue = std::max(widthValue, kMinimumHint.width());
        }
        if (includePreferredSize)
        {
            const QSize kPreferredHint = cellWidget->sizeHint();
            if (kPreferredHint.isValid() && kPreferredHint.width() > 0)
            {
                widthValue = std::max(widthValue, kPreferredHint.width());
            }
        }

        return widthValue > 0 ? widthValue + kCellWidgetHorizontalPadding : 0;
    }

    // sampleIndexWidthHints:
    // - Input: Target view, model index, font metrics, tree indentation, and current round's base minimum width;
    // - Processing: Combine DisplayRole, DecorationRole, CheckStateRole, SizeHintRole, and indexWidget control dimensions.
    // - Returns: The minimum/preferred width contributed by the cell to the column; the control column will not be compressed below the control's own width.
    SectionWidthHints sampleIndexWidthHints(
        QAbstractItemView* view,
        const QModelIndex& index,
        const QFontMetrics& fontMetrics,
        const int treeIndentWidth,
        const int minimumWidth)
    {
        SectionWidthHints hints;
        hints.minimumWidth = std::max(0, minimumWidth);
        hints.preferredWidth = hints.minimumWidth;

        if (!index.isValid())
        {
            return hints;
        }

        int widthValue = measuredTextWidth(fontMetrics, index.data(Qt::DisplayRole).toString());
        if (index.data(Qt::DecorationRole).isValid())
        {
            widthValue += 20;
        }
        if (index.data(Qt::CheckStateRole).isValid())
        {
            widthValue += 18;
        }

        if (widthValue > 0)
        {
            hints.preferredWidth = std::max(
                hints.preferredWidth,
                widthValue + treeIndentWidth + kCellHorizontalPadding);
        }

        const QSize kItemSizeHint = index.data(Qt::SizeHintRole).toSize();
        if (kItemSizeHint.isValid() && kItemSizeHint.width() > 0)
        {
            const int kItemHintWidth = kItemSizeHint.width() + treeIndentWidth;
            hints.minimumWidth = std::max(hints.minimumWidth, kItemHintWidth);
            hints.preferredWidth = std::max(hints.preferredWidth, kItemHintWidth);
        }

        QWidget* cellWidget = view == nullptr ? nullptr : view->indexWidget(index);
        const int kWidgetMinimumWidth = widgetWidthHint(cellWidget, false);
        if (kWidgetMinimumWidth > 0)
        {
            hints.minimumWidth = std::max(
                hints.minimumWidth,
                kWidgetMinimumWidth + treeIndentWidth);
        }

        const int kWidgetPreferredWidth = widgetWidthHint(cellWidget, true);
        if (kWidgetPreferredWidth > 0)
        {
            hints.preferredWidth = std::max(
                hints.preferredWidth,
                kWidgetPreferredWidth + treeIndentWidth);
        }

        hints.preferredWidth = std::max(hints.preferredWidth, hints.minimumWidth);
        return hints;
    }

    // contentWidthHints:
    // - Input: Target view, logical column index, and current base minimum width;
    // - Processing: Sample the first few rows of the model while considering the minimumSizeHint/sizeHint of actual cell controls.
    // - Return: The minimum/preferred width contributed by the column content; returns the base minimum width when no sampleable content exists.
    SectionWidthHints contentWidthHints(
        QAbstractItemView* view,
        const int logicalIndex,
        const int minimumWidth)
    {
        SectionWidthHints hints;
        hints.minimumWidth = std::max(0, minimumWidth);
        hints.preferredWidth = hints.minimumWidth;

        if (view == nullptr || logicalIndex < 0 || view->model() == nullptr)
        {
            return hints;
        }

        QAbstractItemModel* model = view->model();
        QTreeView* treeView = qobject_cast<QTreeView*>(view);
        const QFontMetrics kCellFontMetrics(view->font());
        const QModelIndex kRootIndex = view->rootIndex();
        int sampledRowCount = 0;

        // sampleParent:
        // - Sample several rows sequentially under parentIndex;
        // - Recursively sample expanded tree nodes until the global sampling limit is reached;
        // - Return behavior: No return value; accumulates results via sampledRowCount/hints.
        auto sampleParent =
            [&](const QModelIndex& parentIndex, const int depthValue, auto&& sampleParentRef) -> void
            {
                if (sampledRowCount >= kContentSampleRowLimit)
                {
                    return;
                }

                const int kRowCount = model->rowCount(parentIndex);
                for (int rowIndex = 0;
                    rowIndex < kRowCount && sampledRowCount < kContentSampleRowLimit;
                    ++rowIndex)
                {
                    const QModelIndex kCellIndex = model->index(rowIndex, logicalIndex, parentIndex);
                    if (kCellIndex.isValid())
                    {
                        const int kTreeIndentWidth =
                            treeView != nullptr && logicalIndex == 0
                            ? std::max(0, depthValue) * treeView->indentation()
                            : 0;
                        const SectionWidthHints kCellHints = sampleIndexWidthHints(
                            view,
                            kCellIndex,
                            kCellFontMetrics,
                            kTreeIndentWidth,
                            minimumWidth);
                        hints.minimumWidth = std::max(hints.minimumWidth, kCellHints.minimumWidth);
                        hints.preferredWidth = std::max(hints.preferredWidth, kCellHints.preferredWidth);
                        ++sampledRowCount;
                    }

                    if (treeView == nullptr || sampledRowCount >= kContentSampleRowLimit)
                    {
                        continue;
                    }

                    const QModelIndex kTreeIndex = model->index(rowIndex, 0, parentIndex);
                    if (kTreeIndex.isValid() && treeView->isExpanded(kTreeIndex))
                    {
                        sampleParentRef(kTreeIndex, depthValue + 1, sampleParentRef);
                    }
                }
            };

        sampleParent(kRootIndex, 0, sampleParent);
        hints.preferredWidth = std::max(hints.preferredWidth, hints.minimumWidth);
        return hints;
    }

    // sectionWidthHints:
    // - Input: Target view, header, logical column index, and current base minimum width;
    // - Processing: Synthesize header text, sampled content, SizeHintRole, actual cell controls, and current widths of fixed columns.
    // - Returns: The minimum/preferred width for this column; subsequent compression will not go below minimumWidth.
    SectionWidthHints sectionWidthHints(
        QAbstractItemView* view,
        QHeaderView* header,
        const int logicalIndex,
        const int minimumWidth)
    {
        SectionWidthHints hints = contentWidthHints(view, logicalIndex, minimumWidth);
        hints.minimumWidth = std::max(hints.minimumWidth, minimumWidth);

        if (header != nullptr &&
            logicalIndex >= 0 &&
            logicalIndex < header->count() &&
            header->sectionResizeMode(logicalIndex) == QHeaderView::Fixed)
        {
            hints.minimumWidth = std::max(
                hints.minimumWidth,
                std::max(0, header->sectionSize(logicalIndex)));
        }

        hints.preferredWidth = std::max(
            hints.minimumWidth,
            std::max(headerPreferredWidth(view, header, logicalIndex), hints.preferredWidth));
        return hints;
    }

    // sectionHasRememberedStretchIntent:
    // - Check if a logical column was previously set to QHeaderView::Stretch by business logic;
    // - After a global auto-fit, the column mode is switched to Interactive to allow user dragging; therefore, the original Stretch intent must be preserved via properties.
    // - Only reads the current header's properties; does not change column width or resize mode.
    // Parameter header: target horizontal header; logicalIndex: logical column index to check.
    // Return value: true = this column is a priority candidate for 'fill remaining width when no long content'; false = normal column.
    bool sectionHasRememberedStretchIntent(QHeaderView* header, const int logicalIndex)
    {
        if (header == nullptr || logicalIndex < 0 || logicalIndex >= header->count())
        {
            return false;
        }

        const QVariantList kStretchSections =
            header->property(kAutoFitStretchSectionsProperty).toList();
        for (const QVariant& stretchSection : kStretchSections)
        {
            if (stretchSection.toInt() == logicalIndex)
            {
                return true;
            }
        }
        return false;
    }

    // rememberStretchIntentIfNeeded:
    // - Record columns declared as QHeaderView::Stretch by the business layer before auto-fit takes over column mode.
    // - Even if the column mode is later changed to Interactive, still allocate remaining width to these columns according to business intent.
    // - Repeated calls deduplicate entries, preventing the property list from growing indefinitely.
    // Parameters: header - target horizontal header; logicalIndex - logical column index to record.
    // Return value: None; results are stored in the header's QObject property.
    void rememberStretchIntentIfNeeded(QHeaderView* header, const int logicalIndex)
    {
        if (header == nullptr ||
            logicalIndex < 0 ||
            logicalIndex >= header->count() ||
            header->sectionResizeMode(logicalIndex) != QHeaderView::Stretch ||
            sectionHasRememberedStretchIntent(header, logicalIndex))
        {
            return;
        }

        QVariantList stretchSections =
            header->property(kAutoFitStretchSectionsProperty).toList();
        stretchSections.append(logicalIndex);
        header->setProperty(kAutoFitStretchSectionsProperty, stretchSections);
    }

    // sectionPrefersViewportExpansion:
    // - Combine 'currently Stretch' and 'historically Stretch' cases to determine if the column should prefer consuming remaining viewport width.
    // - Remember the intent when currently in Stretch mode to avoid losing business-layer layout intent after the first auto-fit.
    // - Does not directly adjust any column widths; actual allocation is performed in fitWidthsToAvailableSpace.
    // Parameter header: target horizontal header; logicalIndex: logical column index to check.
    // Return value: true=prefer filling this column when no long-content columns exist; false=normal column.
    bool sectionPrefersViewportExpansion(QHeaderView* header, const int logicalIndex)
    {
        rememberStretchIntentIfNeeded(header, logicalIndex);
        return sectionHasRememberedStretchIntent(header, logicalIndex);
    }

    // collectVisibleSections:
    // - Collect visible columns in the current visual order without hidden columns.
    // - Reads both the current column width and content-aware preferred width simultaneously, then pushes them as a whole into the viewport later.
    // Parameter view: target table/tree view.
    // Parameter header: target horizontal header.
    // Parameter minimumWidth: minimum column width used for this fit iteration.
    // Return value: Set of visible columns; returns an empty array if no columns exist.
    std::vector<VisibleSection> collectVisibleSections(
        QAbstractItemView* view,
        QHeaderView* header,
        const int minimumWidth)
    {
        std::vector<VisibleSection> visibleSections;
        if (header == nullptr)
        {
            return visibleSections;
        }

        const int kSectionCount = header->count();
        visibleSections.reserve(static_cast<std::size_t>(std::max(0, kSectionCount)));
        for (int visualIndex = 0; visualIndex < kSectionCount; ++visualIndex)
        {
            const int kLogicalIndex = header->logicalIndex(visualIndex);
            if (kLogicalIndex < 0 || header->isSectionHidden(kLogicalIndex))
            {
                continue;
            }

            const int kSectionWidth = std::max(header->sectionSize(kLogicalIndex), minimumWidth);
            const SectionWidthHints kWidthHints = sectionWidthHints(
                view,
                header,
                kLogicalIndex,
                minimumWidth);
            visibleSections.push_back({
                kLogicalIndex,
                kSectionWidth,
                kWidthHints.minimumWidth,
                kWidthHints.preferredWidth,
                kWidthHints.preferredWidth,
                sectionPrefersViewportExpansion(header, kLogicalIndex) });
        }

        return visibleSections;
    }

    // countVisibleSections:
    // - Count only currently visible horizontal columns.
    // - Used to calculate the minimum column width for this round based on the 'actual number of visible columns', preventing tables with many hidden columns (like the process table) from being overly compressed.
    // Parameter header: target horizontal header.
    // Return value: The count of visible columns; returns 0 if the header is invalid.
    int countVisibleSections(QHeaderView* header)
    {
        if (header == nullptr)
        {
            return 0;
        }

        int visibleSectionCount = 0;
        const int kSectionCount = header->count();
        for (int visualIndex = 0; visualIndex < kSectionCount; ++visualIndex)
        {
            const int kLogicalIndex = header->logicalIndex(visualIndex);
            if (kLogicalIndex >= 0 && !header->isSectionHidden(kLogicalIndex))
            {
                ++visibleSectionCount;
            }
        }
        return visibleSectionCount;
    }

    // fitWidthsToAvailableSpace:
    // - First arrange column widths using the content-aware preferredWidth;
    // - If the total width exceeds the viewport, compress columns to fit within availableWidth based on the weight of (preferred width - minimum width per column).
    // - Compression will not break the minimum readable width per column; if the sum of minimum readable widths exceeds available space, keep original widths and show the horizontal scrollbar.
    // - If total width is less than the viewport, distribute remaining space only to columns with long content; short fields are not forcibly expanded to equal widths.
    // - The minimumWidth of control columns comes from the actual control size; prefer horizontal scrollbars over distorting the controls.
    // - Do not hide columns or change the scroll bar policy.
    // Parameter sections: the set of visible columns, written in-place to fittedWidth.
    // Parameter availableWidth: The available width of the current viewport.
    // Return value: None.
    void fitWidthsToAvailableSpace(
        std::vector<VisibleSection>& sections,
        const int availableWidth)
    {
        if (sections.empty() || availableWidth <= 0)
        {
            return;
        }

        const int kSectionCount = static_cast<int>(sections.size());
        for (VisibleSection& section : sections)
        {
            section.minimumWidth = std::max(1, section.minimumWidth);
            // Readable lower bound: short columns cap at their own preferred width, while long-content columns cap at kReadableSectionWidthCap.
            // preferredWidth is already guaranteed to be >= minimumWidth in sectionWidthHints; therefore, the
            // raised minimumWidth will still not exceed preferredWidth, leaving the wide-table branch unaffected.
            section.minimumWidth = std::max(
                section.minimumWidth,
                std::min(section.preferredWidth, kReadableSectionWidthCap));
            section.fittedWidth = std::max(section.minimumWidth, section.preferredWidth);
        }

        const auto kTotalFittedWidth =
            [&sections]() -> int
            {
                int totalWidth = 0;
                for (const VisibleSection& section : sections)
                {
                    totalWidth += section.fittedWidth;
                }
                return totalWidth;
            };

        int fittedTotalWidth = kTotalFittedWidth();
        if (fittedTotalWidth == availableWidth)
        {
            return;
        }

        if (fittedTotalWidth < availableWidth)
        {
            int remainingWidth = availableWidth - fittedTotalWidth;
            std::vector<int> expansionIndexes;
            std::vector<int> expansionWeights;

            // addExpansionTarget:
            // - Record the target columns and weights that can obtain remaining width in this round.
            // - Check bounds before using a vector index outside the logical upper limit.
            // - Return value: None; results are written to expansionIndexes/expansionWeights.
            const auto kAddExpansionTarget =
                [&](const int sectionIndex, const int expansionWeight) -> void
                {
                    if (sectionIndex < 0 || sectionIndex >= kSectionCount)
                    {
                        return;
                    }
                    expansionIndexes.push_back(sectionIndex);
                    expansionWeights.push_back(std::max(1, expansionWeight));
                };

            // First priority: still allocate space to columns with obviously long content (e.g., paths, command lines, logs) according to the original strategy.
            for (int sectionIndex = 0; sectionIndex < kSectionCount; ++sectionIndex)
            {
                const VisibleSection& section = sections[static_cast<std::size_t>(sectionIndex)];
                if (section.preferredWidth >= kLongColumnExpansionThreshold)
                {
                    kAddExpansionTarget(
                        sectionIndex,
                        section.preferredWidth - kLongColumnExpansionThreshold);
                }
            }

            // Second priority: When no column has obviously long content, respect the business layer's original Stretch setting to fill the viewport.
            if (expansionIndexes.empty())
            {
                for (int sectionIndex = 0; sectionIndex < kSectionCount; ++sectionIndex)
                {
                    const VisibleSection& section = sections[static_cast<std::size_t>(sectionIndex)];
                    if (section.prefersViewportExpansion)
                    {
                        kAddExpansionTarget(sectionIndex, section.preferredWidth);
                    }
                }
            }

            // Third priority: When there is no Stretch intent, allocate remaining space to the visible column with the largest preferred width.
            if (expansionIndexes.empty())
            {
                const auto kLargestPreferredIt = std::max_element(
                    sections.begin(),
                    sections.end(),
                    [](const VisibleSection& leftSection, const VisibleSection& rightSection)
                    {
                        return leftSection.preferredWidth < rightSection.preferredWidth;
                    });
                if (kLargestPreferredIt != sections.end())
                {
                    kAddExpansionTarget(
                        static_cast<int>(std::distance(sections.begin(), kLargestPreferredIt)),
                        kLargestPreferredIt->preferredWidth);
                }
            }

            // Fallback: sections should theoretically be non-empty when reaching this point; still retains the last visible column to ensure the default total width closely matches the viewport.
            if (expansionIndexes.empty())
            {
                kAddExpansionTarget(kSectionCount - 1, 1);
            }

            int totalExpansionWeight = 0;
            for (const int kExpansionWeight : expansionWeights)
            {
                totalExpansionWeight += std::max(1, kExpansionWeight);
            }
            if (totalExpansionWeight <= 0)
            {
                return;
            }

            for (std::size_t targetIndex = 0; targetIndex < expansionIndexes.size(); ++targetIndex)
            {
                const int kSectionIndex = expansionIndexes[targetIndex];
                const int kExtraWidth =
                    remainingWidth * expansionWeights[targetIndex] / totalExpansionWeight;
                sections[static_cast<std::size_t>(kSectionIndex)].fittedWidth += kExtraWidth;
            }

            int finalTotalWidth = kTotalFittedWidth();
            std::size_t roundRobinIndex = 0;
            while (finalTotalWidth < availableWidth && !expansionIndexes.empty())
            {
                const int kSectionIndex =
                    expansionIndexes[roundRobinIndex % expansionIndexes.size()];
                ++sections[static_cast<std::size_t>(kSectionIndex)].fittedWidth;
                ++finalTotalWidth;
                ++roundRobinIndex;
            }
            return;
        }

        int minimumTotalWidth = 0;
        for (const VisibleSection& section : sections)
        {
            minimumTotalWidth += section.minimumWidth;
        }
        if (minimumTotalWidth >= availableWidth)
        {
            for (VisibleSection& section : sections)
            {
                section.fittedWidth = section.minimumWidth;
            }
            return;
        }

        int remainingAssignableWidth = availableWidth - minimumTotalWidth;
        int totalContentWeight = 0;
        for (const VisibleSection& section : sections)
        {
            totalContentWeight += std::max(0, section.preferredWidth - section.minimumWidth);
        }

        for (VisibleSection& section : sections)
        {
            section.fittedWidth = section.minimumWidth;
        }

        if (totalContentWeight <= 0)
        {
            for (VisibleSection& section : sections)
            {
                if (remainingAssignableWidth <= 0)
                {
                    break;
                }
                ++section.fittedWidth;
                --remainingAssignableWidth;
            }
            return;
        }

        for (VisibleSection& section : sections)
        {
            const int kContentWeight = std::max(0, section.preferredWidth - section.minimumWidth);
            const int kExtraWidth =
                remainingAssignableWidth * kContentWeight / totalContentWeight;
            section.fittedWidth += kExtraWidth;
        }

        int finalTotalWidth = kTotalFittedWidth();
        while (finalTotalWidth < availableWidth)
        {
            auto targetIt = std::max_element(
                sections.begin(),
                sections.end(),
                [](const VisibleSection& leftSection, const VisibleSection& rightSection)
                {
                    return (leftSection.preferredWidth - leftSection.fittedWidth)
                        < (rightSection.preferredWidth - rightSection.fittedWidth);
                });
            if (targetIt == sections.end())
            {
                break;
            }
            ++targetIt->fittedWidth;
            ++finalTotalWidth;
        }

        while (finalTotalWidth > availableWidth)
        {
            auto targetIt = std::max_element(
                sections.begin(),
                sections.end(),
                [](const VisibleSection& leftSection, const VisibleSection& rightSection)
                {
                    return leftSection.fittedWidth < rightSection.fittedWidth;
                });
            if (targetIt == sections.end() || targetIt->fittedWidth <= targetIt->minimumWidth)
            {
                break;
            }
            --targetIt->fittedWidth;
            --finalTotalWidth;
        }
    }

    // refreshViewGeometryAfterFit:
    // - Input: Table/tree with adjusted column widths and horizontal header.
    // - Processing: Trigger QAbstractItemView relayout for indexWidget/setCellWidget control geometry, and refresh viewport/header.
    // - Return: None. This function only fixes display geometry; it does not modify model data or selection state.
    void refreshViewGeometryAfterFit(QAbstractItemView* view, QHeaderView* header)
    {
        if (view == nullptr)
        {
            return;
        }

        view->doItemsLayout();
        view->updateGeometry();
        if (view->viewport() != nullptr)
        {
            view->viewport()->updateGeometry();
            view->viewport()->update();
        }
        if (header != nullptr)
        {
            header->updateGeometry();
            if (header->viewport() != nullptr)
            {
                header->viewport()->update();
            }
        }
    }

    // fitViewColumnsToViewport:
    // - Adjust all currently visible columns of the target table to fit within the viewport width at once;
    // - Uniformly set the column resize mode to Interactive to ensure users can drag and adjust columns later.
    // - Does not set or hide any scrollbars.
    // Parameter view: target table/tree view.
    // Return value: true if a valid fit was performed; false if the current view cannot be processed at this time.
    bool fitViewColumnsToViewport(QAbstractItemView* view)
    {
        if (!isAutoFitEnabled(view) ||
            !view->isVisible() ||
            view->property(kAutoFitUserAdjustedProperty).toBool())
        {
            return false;
        }

        QHeaderView* header = horizontalHeaderForView(view);
        if (header == nullptr || header->count() <= 0 || view->viewport() == nullptr)
        {
            return false;
        }
        if (!view->viewport()->isVisible())
        {
            return false;
        }

        const int kAvailableWidth = view->viewport()->width() - kViewportPadding;
        if (kAvailableWidth <= 0)
        {
            return false;
        }

        const int kVisibleSectionCount = countVisibleSections(header);
        if (kVisibleSectionCount <= 0)
        {
            return false;
        }

        const int kDynamicMinimumWidth = std::max(
            kAbsoluteMinimumSectionWidth,
            std::min(kPreferredMinimumSectionWidth, kAvailableWidth / kVisibleSectionCount));
        bool geometryRefreshRequired = false;
        if (header->minimumSectionSize() > kDynamicMinimumWidth)
        {
            header->setMinimumSectionSize(kDynamicMinimumWidth);
            geometryRefreshRequired = true;
        }

        std::vector<VisibleSection> visibleSections =
            collectVisibleSections(view, header, kDynamicMinimumWidth);
        if (visibleSections.empty())
        {
            return false;
        }

        fitWidthsToAvailableSpace(visibleSections, kAvailableWidth);

        geometryRefreshRequired = geometryRefreshRequired || header->stretchLastSection();
        for (const VisibleSection& section : visibleSections)
        {
            if (header->sectionResizeMode(section.logicalIndex) != QHeaderView::Interactive ||
                header->sectionSize(section.logicalIndex) != section.fittedWidth)
            {
                geometryRefreshRequired = true;
                break;
            }
        }

        // LayoutRequest is asynchronously sent back to the global filter by doItemsLayout()/updateGeometry().
        // Do not refresh geometry again when the current column width already matches, as this would create a singleShot(0) idle re-layout loop.
        if (!geometryRefreshRequired)
        {
            return true;
        }

        view->setProperty(kAutoFitApplyingProperty, true);

        {
            const QSignalBlocker kHeaderSignalBlocker(header);
            header->setStretchLastSection(false);
            for (const VisibleSection& section : visibleSections)
            {
                header->setSectionResizeMode(section.logicalIndex, QHeaderView::Interactive);
            }
            for (const VisibleSection& section : visibleSections)
            {
                header->resizeSection(section.logicalIndex, section.fittedWidth);
            }
        }

        refreshViewGeometryAfterFit(view, header);
        view->setProperty(kAutoFitApplyingProperty, false);
        return true;
    }

    // scheduleColumnFit:
    // - Merge multiple show/resize/layout/viewport resize events into a single fit at the end of the queue.
    // - Viewport resize event: dimensions are already updated; singleShot(0) is used only to wait for the current Qt event processing to complete.
    // - User drag-and-drop column width adjustments are skipped by AutoFitUserAdjustedProperty to avoid overwriting the user's layout.
    // Parameter view: target table/tree view.
    // Return value: None.
    void scheduleColumnFit(QAbstractItemView* view)
    {
        if (!isAutoFitEnabled(view) ||
            view->property(kAutoFitApplyingProperty).toBool() ||
            view->property(kAutoFitScheduledProperty).toBool() ||
            view->property(kAutoFitUserAdjustedProperty).toBool())
        {
            return;
        }

        view->setProperty(kAutoFitScheduledProperty, true);
        const QPointer<QAbstractItemView> kGuardedView(view);
        QTimer::singleShot(0, view, [kGuardedView]()
            {
                if (kGuardedView.isNull())
                {
                    return;
                }

                kGuardedView->setProperty(kAutoFitScheduledProperty, false);
                fitViewColumnsToViewport(kGuardedView.data());
            });
    }

    // installHeaderAutoFitHooks:
    // - Install lightweight signal hooks once for the table's horizontal header.
    // - Business logic can trigger a re-fit even after show() if setColumnWidth, column hide/show, or model replacement causes column structure changes.
    // - Tables where the user has manually adjusted column widths are excluded by AutoFitUserAdjustedProperty and will not be re-compressed by hooks.
    // Parameter view: target table/tree view.
    // Returns: None. Repeated calls are deduplicated by the property.
    void installHeaderAutoFitHooks(QAbstractItemView* view)
    {
        if (!isAutoFitEnabled(view))
        {
            return;
        }

        QHeaderView* header = horizontalHeaderForView(view);
        if (header == nullptr || header->property(kAutoFitHeaderHookedProperty).toBool())
        {
            return;
        }

        header->setProperty(kAutoFitHeaderHookedProperty, true);
        const QPointer<QAbstractItemView> kGuardedView(view);

        // sectionResized overrides business logic for setColumnWidth/resizeSection and also overrides model column width recalculation.
        QObject::connect(
            header,
            &QHeaderView::sectionResized,
            header,
            [kGuardedView](int, int, int)
            {
                if (!kGuardedView.isNull())
                {
                    scheduleColumnFit(kGuardedView.data());
                }
            });

        // sectionCountChanged: Covers structural changes such as model replacement and column addition/deletion.
        QObject::connect(
            header,
            &QHeaderView::sectionCountChanged,
            header,
            [kGuardedView](int, int)
            {
                if (!kGuardedView.isNull())
                {
                    scheduleColumnFit(kGuardedView.data());
                }
            });

        // geometriesChanged covers scenarios without sectionResized, such as hiding/showing columns and refreshing header layout.
        QObject::connect(
            header,
            &QHeaderView::geometriesChanged,
            header,
            [kGuardedView]()
            {
                if (!kGuardedView.isNull())
                {
                    scheduleColumnFit(kGuardedView.data());
                }
            });
    }

    // isNearHeaderResizeBoundary:
    // - Check if the mouse position is near any visible column boundary.
    // - Only this press is considered as 'user preparing to drag column width'.
    // Parameter header: target horizontal header.
    // Parameter localPosition: the mouse position in the header/viewport coordinate system.
    // Returns: true if near column boundary; false if clicking a normal header.
    bool isNearHeaderResizeBoundary(QHeaderView* header, const QPoint& localPosition)
    {
        if (header == nullptr || header->count() <= 0)
        {
            return false;
        }

        const int kSectionCount = header->count();
        for (int visualIndex = 0; visualIndex < kSectionCount; ++visualIndex)
        {
            const int kLogicalIndex = header->logicalIndex(visualIndex);
            if (kLogicalIndex < 0 || header->isSectionHidden(kLogicalIndex))
            {
                continue;
            }

            const int kSectionLeft = header->sectionViewportPosition(kLogicalIndex);
            const int kSectionRight = kSectionLeft + header->sectionSize(kLogicalIndex);
            if (std::abs(localPosition.x() - kSectionRight) <= kResizeGripMargin)
            {
                return true;
            }
        }

        return false;
    }

    // updateUserColumnResizeState:
    // - Capture the user's mouse press-and-drag action near the table header column boundary.
    // - Only if the drag distance exceeds QApplication's drag threshold is it considered a user-initiated column width adjustment.
    // - once the user starts manually adjusting column widths, the table is no longer subject to global auto-fit intervention.
    // Parameter watchedObject: Global event source object.
    // Parameter eventObject: the current event.
    // Return value: None.
    void updateUserColumnResizeState(QObject* watchedObject, QEvent* eventObject)
    {
        if (eventObject == nullptr)
        {
            return;
        }

        QHeaderView* header = eventObjectToHorizontalHeader(watchedObject);
        if (header == nullptr)
        {
            return;
        }

        if (eventObject->type() == QEvent::MouseButtonPress)
        {
            QMouseEvent* mouseEvent = static_cast<QMouseEvent*>(eventObject);
            if (mouseEvent->button() != Qt::LeftButton)
            {
                return;
            }

            const QPoint kHeaderPosition = header->viewport() == watchedObject
                ? mouseEvent->position().toPoint()
                : header->mapFromGlobal(mouseEvent->globalPosition().toPoint());
            if (!isNearHeaderResizeBoundary(header, kHeaderPosition))
            {
                return;
            }

            header->setProperty(kAutoFitResizePendingProperty, true);
            header->setProperty(kAutoFitResizePressPositionProperty, kHeaderPosition);
            return;
        }

        if (eventObject->type() == QEvent::MouseMove)
        {
            if (!header->property(kAutoFitResizePendingProperty).toBool())
            {
                return;
            }

            QMouseEvent* mouseEvent = static_cast<QMouseEvent*>(eventObject);
            if ((mouseEvent->buttons() & Qt::LeftButton) == 0)
            {
                header->setProperty(kAutoFitResizePendingProperty, false);
                return;
            }

            const QPoint kHeaderPosition = header->viewport() == watchedObject
                ? mouseEvent->position().toPoint()
                : header->mapFromGlobal(mouseEvent->globalPosition().toPoint());
            const QPoint kPressPosition =
                header->property(kAutoFitResizePressPositionProperty).toPoint();
            if ((kHeaderPosition - kPressPosition).manhattanLength() < QApplication::startDragDistance())
            {
                return;
            }

            header->setProperty(kAutoFitResizePendingProperty, false);
            if (QAbstractItemView* view = viewForHorizontalHeader(header))
            {
                view->setProperty(kAutoFitUserAdjustedProperty, true);
            }
            return;
        }

        if (eventObject->type() == QEvent::MouseButtonRelease)
        {
            QMouseEvent* mouseEvent = static_cast<QMouseEvent*>(eventObject);
            if (mouseEvent->button() == Qt::LeftButton)
            {
                header->setProperty(kAutoFitResizePendingProperty, false);
            }
        }
    }

    class GlobalTableColumnAutoFitFilter final : public QObject
    {
    public:
        // Constructor purpose:
        // - Bind QApplication as the parent object.
        // - Lifecycle follows the application process; no manual release required.
        // Parameter parentObject: Typically QApplication.
        explicit GlobalTableColumnAutoFitFilter(QObject* parentObject)
            : QObject(parentObject)
        {
        }

    protected:
        // eventFilter:
        // - Globally capture table show/resize/layout events and defer column width fitting.
        // - Globally capture header boundary mouse presses and mark user takeover of column width.
        // - Returns false to avoid consuming business events.
        // Parameter watchedObject: Event source object.
        // Parameter eventObject: the current event.
        // Return value: Always continue Qt's default event dispatch.
        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override
        {
            updateUserColumnResizeState(watchedObject, eventObject);

            QAbstractItemView* view = eventObjectToSupportedView(watchedObject);
            if (view != nullptr && eventObject != nullptr)
            {
                installHeaderAutoFitHooks(view);

                const QEvent::Type kEventType = eventObject->type();
                if (kEventType == QEvent::Show ||
                    kEventType == QEvent::Resize ||
                    kEventType == QEvent::Polish ||
                    kEventType == QEvent::LayoutRequest ||
                    kEventType == QEvent::StyleChange)
                {
                    scheduleColumnFit(view);
                }
            }

            return QObject::eventFilter(watchedObject, eventObject);
        }
    };
}

namespace ks::ui
{
    void installGlobalTableColumnAutoFit(QApplication* appInstance)
    {
        if (appInstance == nullptr ||
            appInstance->property(kAutoFitInstalledProperty).toBool())
        {
            return;
        }

        auto* filter = new GlobalTableColumnAutoFitFilter(appInstance);
        appInstance->installEventFilter(filter);
        appInstance->setProperty(kAutoFitInstalledProperty, true);
    }

    void requestTableColumnAutoFit(QAbstractItemView* view)
    {
        scheduleColumnFit(view);
    }

    // setTableColumnAutoFitEnabled:
    // - Input: target table/tree view and enabled state;
    // - Processing: Use QObject dynamic properties to make specific views exit or restore global column width auto-fit.
    // - Return: None; enables immediate single fit queue on enable, clears pending requests on disable.
    void setTableColumnAutoFitEnabled(QAbstractItemView* view, const bool enabled)
    {
        if (!isSupportedTableView(view))
        {
            return;
        }

        view->setProperty(kAutoFitDisabledProperty, !enabled);
        if (!enabled)
        {
            view->setProperty(kAutoFitScheduledProperty, false);
            return;
        }

        scheduleColumnFit(view);
    }
}
