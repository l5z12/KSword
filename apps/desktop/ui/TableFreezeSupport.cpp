#include "TableFreezeSupport.h"

#include "VisibleTableWidget.h"

#include <QAbstractItemDelegate>
#include <QAbstractItemView>
#include <QCoreApplication>
#include <QEvent>
#include <QHash>
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QMouseEvent>
#include <QPalette>
#include <QScrollBar>
#include <QSet>
#include <QSize>
#include <QTableView>
#include <QTimer>
#include <QVariant>
#include <QWheelEvent>

#include <algorithm>
#include <utility>

namespace
{
    constexpr char kFrozenPaneAuxiliaryProperty[] =
        "KSWORD_TABLE_INTERACTION_FROZEN_PANE_AUXILIARY";
    constexpr char kFrozenPaneSourceProperty[] =
        "KSWORD_TABLE_INTERACTION_FROZEN_PANE_SOURCE";

    /*
     * Freezing rows/columns moves them from the main table using setRowHidden/setColumnHidden, which is the same state as
     * 'filtered out' in QTableView. Copy, export, and snapshot comparison all retrieve data based on 'visible rows/columns'.
     * Without distinction, rows/columns the user explicitly pinned would be excluded from export results. Here, the frozen
     * set is published to table properties so the retrieval logic excludes only truly filtered rows/columns.
     */
    constexpr char kFrozenHiddenRowsProperty[] =
        "KSWORD_TABLE_INTERACTION_FROZEN_HIDDEN_ROWS";
    constexpr char kFrozenHiddenColumnsProperty[] =
        "KSWORD_TABLE_INTERACTION_FROZEN_HIDDEN_COLUMNS";

    // The frozen area consumes at most half of the available size. Without this upper limit, freezing a large number of rows at once
    // would freeze the entire screen, reduce the scrollable area height to zero, and make the table appear completely unresponsive.
    constexpr int kFrozenBandBudgetDivisor = 2;

    // When the main table's scroll position jitters due to refreshes of visible row heights, mirror extra rows to prevent white space from appearing at the bottom of the frozen column pane.
    constexpr int kMirrorRowMargin = 3;

    // FrozenPaneTableView:
    // - Read-only auxiliary view for the frozen pane, sharing the model and selection model with the main table.
    // - Does not accept wheel events or scrolling itself; all scrolling is delegated to the main table, which the controller then uses to realign the pane.
    class FrozenPaneTableView final : public QTableView
    {
    public:
        explicit FrozenPaneTableView(QTableView* sourceTable, QWidget* parent)
            : QTableView(parent)
            , sourceTable_(sourceTable)
        {
        }

    protected:
        void wheelEvent(QWheelEvent* eventObject) override
        {
            if (eventObject == nullptr || sourceTable_.isNull() ||
                sourceTable_->viewport() == nullptr)
            {
                QTableView::wheelEvent(eventObject);
                return;
            }

            // The frozen region does not scroll; wheel input is passed to the main table, then synchronized by the controller.
            QCoreApplication::sendEvent(sourceTable_->viewport(), eventObject);
        }

        void mousePressEvent(QMouseEvent* eventObject) override
        {
            const QPoint kRestorePoint = sourceScrollPoint();
            QTableView::mousePressEvent(eventObject);
            restoreSourceScroll(kRestorePoint);
        }

        void mouseDoubleClickEvent(QMouseEvent* eventObject) override
        {
            const QPoint kRestorePoint = sourceScrollPoint();
            QTableView::mouseDoubleClickEvent(eventObject);
            restoreSourceScroll(kRestorePoint);
        }

    private:
        // sourceScrollPoint / restoreSourceScroll purpose:
        // - The frozen area and the main table share the same selection model; the selected row is hidden in the main table.
        // - QAbstractItemView calls scrollTo(current) in currentChanged; without restoring, the entire table jumps erratically.
        QPoint sourceScrollPoint() const
        {
            if (sourceTable_.isNull())
            {
                return QPoint(-1, -1);
            }
            return QPoint(
                sourceTable_->horizontalScrollBar()->value(),
                sourceTable_->verticalScrollBar()->value());
        }

        void restoreSourceScroll(const QPoint& restorePoint)
        {
            if (sourceTable_.isNull() || restorePoint.x() < 0)
            {
                return;
            }
            if (sourceTable_->horizontalScrollBar()->value() != restorePoint.x())
            {
                sourceTable_->horizontalScrollBar()->setValue(restorePoint.x());
            }
            if (sourceTable_->verticalScrollBar()->value() != restorePoint.y())
            {
                sourceTable_->verticalScrollBar()->setValue(restorePoint.y());
            }
        }

        QPointer<QTableView> sourceTable_;
    };

    int headerBandHeight(const QTableView* tableView)
    {
        const QHeaderView* header = tableView != nullptr ? tableView->horizontalHeader() : nullptr;
        return header != nullptr && !header->isHidden() ? header->height() : 0;
    }

    int headerBandWidth(const QTableView* tableView)
    {
        const QHeaderView* header = tableView != nullptr ? tableView->verticalHeader() : nullptr;
        return header != nullptr && !header->isHidden() ? header->width() : 0;
    }

    // setPaneScrollValue:
    // - The pane scroll bar is fully driven by the controller; the range calculated by QTableView itself may not cover the target offset.
    // - Expand the range first before assigning to avoid being clamped to a misaligned single cell.
    void setPaneScrollValue(QScrollBar* scrollBar, const int value)
    {
        if (scrollBar == nullptr)
        {
            return;
        }
        if (scrollBar->minimum() > value)
        {
            scrollBar->setMinimum(value);
        }
        if (scrollBar->maximum() < value)
        {
            scrollBar->setMaximum(value);
        }
        if (scrollBar->value() != value)
        {
            scrollBar->setValue(value);
        }
    }
}

namespace ks::ui
{
    TablePausedSnapshotModel::TablePausedSnapshotModel(
        TableSnapshot snapshot,
        QObject* parent)
        : QAbstractTableModel(parent)
        , snapshot_(std::move(snapshot))
    {
    }

    const TableSnapshot& TablePausedSnapshotModel::snapshot() const
    {
        return snapshot_;
    }

    int TablePausedSnapshotModel::rowCount(const QModelIndex& parent) const
    {
        return parent.isValid() ? 0 : snapshot_.rows.size();
    }

    int TablePausedSnapshotModel::columnCount(const QModelIndex& parent) const
    {
        return parent.isValid() ? 0 : snapshot_.visibleColumns.size();
    }

    QVariant TablePausedSnapshotModel::data(const QModelIndex& index, const int role) const
    {
        if (!index.isValid() ||
            index.row() < 0 ||
            index.row() >= snapshot_.rows.size() ||
            index.column() < 0 ||
            index.column() >= snapshot_.visibleColumns.size())
        {
            return QVariant();
        }

        const TableSnapshotRow& row = snapshot_.rows.at(index.row());
        if (index.column() >= row.values.size())
        {
            return QVariant();
        }
        if (role == Qt::DisplayRole || role == Qt::EditRole || role == Qt::ToolTipRole)
        {
            return row.values.at(index.column());
        }
        return QVariant();
    }

    QVariant TablePausedSnapshotModel::headerData(
        const int section,
        const Qt::Orientation orientation,
        const int role) const
    {
        if (role != Qt::DisplayRole || section < 0)
        {
            return QVariant();
        }
        if (orientation == Qt::Horizontal)
        {
            return section < snapshot_.visibleColumns.size()
                ? snapshot_.visibleColumns.at(section).headerText
                : QVariant();
        }
        if (section >= snapshot_.rows.size())
        {
            return QVariant();
        }
        const int kSourceRow = snapshot_.rows.at(section).sourceRow;
        return kSourceRow >= 0 ? QVariant(kSourceRow + 1) : QVariant(section + 1);
    }

    Qt::ItemFlags TablePausedSnapshotModel::flags(const QModelIndex& index) const
    {
        return index.isValid()
            ? Qt::ItemIsEnabled | Qt::ItemIsSelectable
            : Qt::NoItemFlags;
    }

    TableFrozenPaneController::TableFrozenPaneController(QObject* parent)
        : QObject(parent)
    {
    }

    TableFrozenPaneController::~TableFrozenPaneController()
    {
        // The production controller is owned by TableActionBar, which in turn is a
        // direct child of the target table. QWidget destroys its children while the
        // target table's most-derived C++ object is already gone, but QPointer is not
        // cleared until QObject's destructor runs. Calling releaseTarget() here can
        // therefore dispatch virtual table methods through a partially destroyed
        // object. QObject already disconnects every connection owned by this
        // controller, and the target table owns the auxiliary panes, so destruction
        // only needs to let the guarded members tear down locally. Explicit target
        // changes still use setTargetTable()/releaseTarget() while both objects live.
    }

    void TableFrozenPaneController::setTargetTable(QTableView* tableView)
    {
        if (targetTable_ == tableView)
        {
            refreshGeometry();
            return;
        }

        // When changing the target table, first restore the frozen rows and columns of the old table to visible, then clear the state.
        releaseTarget();
        targetTable_ = tableView;
        targetModel_ = tableView != nullptr ? tableView->model() : nullptr;
        connectTarget();
        refreshGeometry();
    }

    QTableView* TableFrozenPaneController::targetTable() const
    {
        return targetTable_.data();
    }

    bool TableFrozenPaneController::canFreeze() const
    {
        return !targetTable_.isNull() &&
            targetTable_->model() != nullptr &&
            targetTable_->viewport() != nullptr &&
            tableActionBarHostFor(targetTable_.data()) != nullptr;
    }

    int TableFrozenPaneController::freezeRows(const QList<int>& logicalRows)
    {
        if (!canFreeze() || targetTable_->verticalHeader() == nullptr)
        {
            return 0;
        }

        QTableView* tableView = targetTable_.data();
        QHeaderView* header = tableView->verticalHeader();
        QAbstractItemModel* model = tableView->model();
        const int kRowCount = model->rowCount();

        QSet<int> alreadyFrozen;
        for (const FrozenLine& line : frozenRowLines_)
        {
            if (line.index.isValid())
            {
                alreadyFrozen.insert(line.index.row());
            }
        }

        // Candidates are sorted by visible order: when selecting multiple non-contiguous rows, their relative order on screen is preserved within the frozen region.
        QList<QPair<int, int>> candidateList; // (visible row, logical row)
        QSet<int> seenRows;
        for (const int kLogicalRow : logicalRows)
        {
            if (kLogicalRow < 0 || kLogicalRow >= kRowCount ||
                seenRows.contains(kLogicalRow) ||
                alreadyFrozen.contains(kLogicalRow) ||
                tableView->isRowHidden(kLogicalRow))
            {
                continue;
            }
            seenRows.insert(kLogicalRow);
            const int kVisualRow = header->visualIndex(kLogicalRow);
            if (kVisualRow >= 0)
            {
                candidateList.push_back({ kVisualRow, kLogicalRow });
            }
        }
        std::sort(candidateList.begin(), candidateList.end());

        const int kBudget = frozenRowsBudget();
        int usedHeight = totalFrozenRowsHeight();
        int addedCount = 0;
        for (const auto& [visualRow, logicalRow] : candidateList)
        {
            const int kRowHeight = header->sectionSize(logicalRow);
            if (kRowHeight <= 0)
            {
                continue;
            }
            if (usedHeight + kRowHeight > kBudget)
            {
                break;
            }
            frozenRowLines_.push_back(
                { QPersistentModelIndex(model->index(logicalRow, 0)), kRowHeight, logicalRow });
            tableView->setRowHidden(logicalRow, true);
            usedHeight += kRowHeight;
            ++addedCount;
        }

        if (addedCount > 0)
        {
            refreshGeometry();
        }
        return addedCount;
    }

    int TableFrozenPaneController::freezeColumns(const QList<int>& logicalColumns)
    {
        if (!canFreeze() || targetTable_->horizontalHeader() == nullptr)
        {
            return 0;
        }

        QTableView* tableView = targetTable_.data();
        QHeaderView* header = tableView->horizontalHeader();
        QAbstractItemModel* model = tableView->model();
        const int kColumnCount = model->columnCount();

        QSet<int> alreadyFrozen;
        for (const FrozenLine& line : frozenColumnLines_)
        {
            if (line.index.isValid())
            {
                alreadyFrozen.insert(line.index.column());
            }
        }

        QList<QPair<int, int>> candidateList; // (visible column, logical column)
        QSet<int> seenColumns;
        for (const int kLogicalColumn : logicalColumns)
        {
            if (kLogicalColumn < 0 || kLogicalColumn >= kColumnCount ||
                seenColumns.contains(kLogicalColumn) ||
                alreadyFrozen.contains(kLogicalColumn) ||
                tableView->isColumnHidden(kLogicalColumn))
            {
                continue;
            }
            seenColumns.insert(kLogicalColumn);
            const int kVisualColumn = header->visualIndex(kLogicalColumn);
            if (kVisualColumn >= 0)
            {
                candidateList.push_back({ kVisualColumn, kLogicalColumn });
            }
        }
        std::sort(candidateList.begin(), candidateList.end());

        const int kBudget = frozenColumnsBudget();
        int usedWidth = totalFrozenColumnsWidth();
        int addedCount = 0;
        for (const auto& [visualColumn, logicalColumn] : candidateList)
        {
            const int kColumnWidth = header->sectionSize(logicalColumn);
            if (kColumnWidth <= 0)
            {
                continue;
            }
            if (usedWidth + kColumnWidth > kBudget)
            {
                break;
            }
            frozenColumnLines_.push_back(
                { QPersistentModelIndex(model->index(0, logicalColumn)), kColumnWidth, logicalColumn });
            tableView->setColumnHidden(logicalColumn, true);
            usedWidth += kColumnWidth;
            ++addedCount;
        }

        if (addedCount > 0)
        {
            refreshGeometry();
        }
        return addedCount;
    }

    void TableFrozenPaneController::clearFrozenRows()
    {
        if (frozenRowLines_.isEmpty())
        {
            return;
        }
        unfreezeAllRows();
        refreshGeometry();
    }

    void TableFrozenPaneController::clearFrozenColumns()
    {
        if (frozenColumnLines_.isEmpty())
        {
            return;
        }
        unfreezeAllColumns();
        refreshGeometry();
    }

    void TableFrozenPaneController::clearFrozenPanes()
    {
        if (frozenRowLines_.isEmpty() && frozenColumnLines_.isEmpty())
        {
            return;
        }
        unfreezeAllRows();
        unfreezeAllColumns();
        refreshGeometry();
    }

    int TableFrozenPaneController::frozenRowCount() const
    {
        return frozenRowLines_.size();
    }

    int TableFrozenPaneController::frozenColumnCount() const
    {
        return frozenColumnLines_.size();
    }

    void TableFrozenPaneController::unfreezeAllRows()
    {
        if (!targetTable_.isNull() && targetTable_->model() != nullptr)
        {
            for (const FrozenLine& line : frozenRowLines_)
            {
                if (line.index.isValid())
                {
                    targetTable_->setRowHidden(line.index.row(), false);
                }
            }
        }
        frozenRowLines_.clear();
        publishFrozenSections();
    }

    void TableFrozenPaneController::unfreezeAllColumns()
    {
        if (!targetTable_.isNull() && targetTable_->model() != nullptr)
        {
            const int kColumnCount = targetTable_->model()->columnCount();
            for (const FrozenLine& line : frozenColumnLines_)
            {
                // When the index is invalid, restore using the section; otherwise, 'Unfreeze All' cannot recover hidden columns.
                const int kColumn = line.index.isValid() ? line.index.column() : line.section;
                if (kColumn >= 0 && kColumn < kColumnCount)
                {
                    targetTable_->setColumnHidden(kColumn, false);
                }
            }
        }
        frozenColumnLines_.clear();
        publishFrozenSections();
    }

    bool TableFrozenPaneController::eventFilter(QObject* watchedObject, QEvent* eventObject)
    {
        if (eventObject != nullptr &&
            (eventObject->type() == QEvent::Resize ||
                eventObject->type() == QEvent::Show ||
                eventObject->type() == QEvent::LayoutRequest ||
                eventObject->type() == QEvent::StyleChange))
        {
            scheduleRefresh();
        }
        return QObject::eventFilter(watchedObject, eventObject);
    }

    void TableFrozenPaneController::disconnectTarget()
    {
        if (!targetTable_.isNull())
        {
            QObject::disconnect(targetTable_, nullptr, this, nullptr);
            if (QHeaderView* header = targetTable_->horizontalHeader())
            {
                QObject::disconnect(header, nullptr, this, nullptr);
            }
            if (QHeaderView* header = targetTable_->verticalHeader())
            {
                QObject::disconnect(header, nullptr, this, nullptr);
            }
            if (QScrollBar* scrollBar = targetTable_->horizontalScrollBar())
            {
                QObject::disconnect(scrollBar, nullptr, this, nullptr);
            }
            if (QScrollBar* scrollBar = targetTable_->verticalScrollBar())
            {
                QObject::disconnect(scrollBar, nullptr, this, nullptr);
            }
            targetTable_->removeEventFilter(this);
            if (targetTable_->viewport() != nullptr)
            {
                targetTable_->viewport()->removeEventFilter(this);
            }
        }
        if (!targetModel_.isNull())
        {
            QObject::disconnect(targetModel_, nullptr, this, nullptr);
        }
    }

    void TableFrozenPaneController::connectTarget()
    {
        if (targetTable_.isNull())
        {
            return;
        }

        const auto kOnScrolled = [this]()
        {
            if (refreshing_)
            {
                return;
            }
            refreshing_ = true;
            syncPanes();
            refreshing_ = false;
        };
        const auto kOnSectionChanged = [this]()
        {
            if (!mirroringSections_ && !refreshing_)
            {
                scheduleRefresh();
            }
        };

        connect(targetTable_->horizontalScrollBar(), &QScrollBar::valueChanged, this, kOnScrolled);
        connect(targetTable_->verticalScrollBar(), &QScrollBar::valueChanged, this, kOnScrolled);
        connect(targetTable_->horizontalScrollBar(), &QScrollBar::rangeChanged, this, kOnScrolled);
        connect(targetTable_->verticalScrollBar(), &QScrollBar::rangeChanged, this, kOnScrolled);
        connect(
            targetTable_->horizontalHeader(),
            &QHeaderView::sectionResized,
            this,
            kOnSectionChanged);
        connect(
            targetTable_->verticalHeader(),
            &QHeaderView::sectionResized,
            this,
            kOnSectionChanged);
        connect(
            targetTable_->horizontalHeader(),
            &QHeaderView::sectionMoved,
            this,
            kOnSectionChanged);
        connect(
            targetTable_->horizontalHeader(),
            &QHeaderView::sortIndicatorChanged,
            this,
            kOnSectionChanged);
        targetTable_->installEventFilter(this);
        if (targetTable_->viewport() != nullptr)
        {
            targetTable_->viewport()->installEventFilter(this);
        }

        if (!targetModel_.isNull())
        {
            // Row/column insertions, deletions, and sorting are automatically translated by the persistent index in FrozenLine; here, we only
            // need to trigger a single delayed refresh so that enforceFrozenState discards stale items and re-corrects the hidden state.
            const auto kOnModelChanged = [this]() { scheduleRefresh(); };
            connect(targetModel_, &QAbstractItemModel::modelReset, this, kOnModelChanged);
            connect(targetModel_, &QAbstractItemModel::rowsInserted, this, kOnModelChanged);
            connect(targetModel_, &QAbstractItemModel::rowsRemoved, this, kOnModelChanged);
            connect(targetModel_, &QAbstractItemModel::columnsInserted, this, kOnModelChanged);
            connect(targetModel_, &QAbstractItemModel::columnsRemoved, this, kOnModelChanged);
            connect(targetModel_, &QAbstractItemModel::layoutChanged, this, kOnModelChanged);
        }
    }

    void TableFrozenPaneController::scheduleRefresh()
    {
        if (refreshScheduled_)
        {
            return;
        }
        // If nothing is frozen, there is nothing to do. Tables like the process table, which rebuild content
        // every second, hold many such signals; while running an extra iteration is cheap, it is unnecessary.
        if (frozenRowLines_.isEmpty() &&
            frozenColumnLines_.isEmpty() &&
            topPane_.isNull() &&
            leftPane_.isNull() &&
            cornerPane_.isNull() &&
            appliedFrozenWidth_ == 0 &&
            appliedFrozenHeight_ == 0)
        {
            return;
        }
        refreshScheduled_ = true;
        QTimer::singleShot(0, this, [this]()
            {
                refreshScheduled_ = false;
                refreshGeometry();
            });
    }

    void TableFrozenPaneController::releaseTarget()
    {
        unfreezeAllRows();
        unfreezeAllColumns();
        destroyPanes();
        if (!targetTable_.isNull())
        {
            if (TableActionBarHost* host = tableActionBarHostFor(targetTable_.data()))
            {
                host->setFrozenPaneReservation(0, 0);
            }
        }
        disconnectTarget();
        targetTable_.clear();
        targetModel_.clear();
        appliedFrozenWidth_ = 0;
        appliedFrozenHeight_ = 0;
    }

    void TableFrozenPaneController::destroyPanes()
    {
        for (QPointer<QTableView>* guardedPane : { &topPane_, &leftPane_, &cornerPane_ })
        {
            if (!guardedPane->isNull())
            {
                guardedPane->data()->hide();
                guardedPane->data()->deleteLater();
                guardedPane->clear();
            }
        }
    }

    QTableView* TableFrozenPaneController::createPane(QPointer<QTableView>& guardedPane)
    {
        if (guardedPane.isNull())
        {
            guardedPane = new FrozenPaneTableView(targetTable_.data(), targetTable_.data());
        }
        return guardedPane.data();
    }

    void TableFrozenPaneController::ensurePanes()
    {
        const bool kRowsFrozen = !frozenRowLines_.isEmpty() && appliedFrozenHeight_ > 0;
        const bool kColumnsFrozen = !frozenColumnLines_.isEmpty() && appliedFrozenWidth_ > 0;
        if (!kRowsFrozen && !kColumnsFrozen)
        {
            destroyPanes();
            return;
        }

        QTableView* tableView = targetTable_.data();
        const int kHeaderHeight = headerBandHeight(tableView);
        const int kHeaderWidth = headerBandWidth(tableView);
        // The intersecting pane serves three purposes simultaneously: row headers for frozen rows, column headers for frozen columns, and the cell at their intersection.
        const bool kCornerNeeded =
            (appliedFrozenWidth_ + kHeaderWidth) > 0 &&
            (appliedFrozenHeight_ + kHeaderHeight) > 0;

        if (kRowsFrozen)
        {
            configurePane(createPane(topPane_), false, false);
        }
        else if (!topPane_.isNull())
        {
            topPane_->hide();
            topPane_->deleteLater();
            topPane_.clear();
        }

        if (kColumnsFrozen)
        {
            configurePane(createPane(leftPane_), false, false);
        }
        else if (!leftPane_.isNull())
        {
            leftPane_->hide();
            leftPane_->deleteLater();
            leftPane_.clear();
        }

        if (kCornerNeeded)
        {
            configurePane(createPane(cornerPane_), kHeaderHeight > 0, kHeaderWidth > 0);
        }
        else if (!cornerPane_.isNull())
        {
            cornerPane_->hide();
            cornerPane_->deleteLater();
            cornerPane_.clear();
        }
    }

    void TableFrozenPaneController::configurePane(
        QTableView* pane,
        const bool showHorizontalHeader,
        const bool showVerticalHeader)
    {
        if (pane == nullptr || targetTable_.isNull() || targetTable_->model() == nullptr)
        {
            return;
        }

        QTableView* sourceTable = targetTable_.data();
        pane->setProperty(kFrozenPaneAuxiliaryProperty, true);
        pane->setProperty(
            kFrozenPaneSourceProperty,
            QVariant::fromValue(static_cast<QObject*>(sourceTable)));

        // setModel rebuilds column widths and the selection model; only perform this when the model actually changes.
        if (pane->model() != sourceTable->model())
        {
            pane->setModel(sourceTable->model());
        }
        if (sourceTable->selectionModel() != nullptr &&
            pane->selectionModel() != sourceTable->selectionModel())
        {
            pane->setSelectionModel(sourceTable->selectionModel());
        }
        if (pane->itemDelegate() != sourceTable->itemDelegate())
        {
            pane->setItemDelegate(sourceTable->itemDelegate());
        }
        const int kColumnCount = sourceTable->model()->columnCount();
        for (int column = 0; column < kColumnCount; ++column)
        {
            QAbstractItemDelegate* columnDelegate = sourceTable->itemDelegateForColumn(column);
            if (columnDelegate != pane->itemDelegateForColumn(column))
            {
                pane->setItemDelegateForColumn(column, columnDelegate);
            }
        }

        pane->setSelectionMode(sourceTable->selectionMode());
        pane->setSelectionBehavior(sourceTable->selectionBehavior());
        pane->setEditTriggers(QAbstractItemView::NoEditTriggers);
        // Offsets are calculated entirely by the controller in pixels; the pane must be fixed to pixel-scroll mode.
        pane->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
        pane->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
        pane->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        pane->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        pane->setAlternatingRowColors(sourceTable->alternatingRowColors());
        pane->setShowGrid(sourceTable->showGrid());
        pane->setGridStyle(sourceTable->gridStyle());
        pane->setTextElideMode(sourceTable->textElideMode());
        pane->setWordWrap(sourceTable->wordWrap());
        pane->setSortingEnabled(false);
        pane->setFrameShape(QFrame::NoFrame);
        // Keep keyboard focus on the main table; otherwise, arrow keys would move the current item within the frozen area.
        pane->setFocusPolicy(Qt::NoFocus);
        pane->setFont(sourceTable->font());
        pane->setPalette(sourceTable->palette());
        pane->setAutoFillBackground(true);
        pane->viewport()->setAutoFillBackground(true);
        pane->viewport()->setPalette(sourceTable->viewport()->palette());
        pane->setCornerButtonEnabled(
            showHorizontalHeader && showVerticalHeader && sourceTable->isCornerButtonEnabled());

        QHeaderView* sourceHorizontalHeader = sourceTable->horizontalHeader();
        QHeaderView* paneHorizontalHeader = pane->horizontalHeader();
        paneHorizontalHeader->setVisible(showHorizontalHeader);
        if (showHorizontalHeader && sourceHorizontalHeader != nullptr)
        {
            paneHorizontalHeader->setFixedHeight(sourceHorizontalHeader->height());
            paneHorizontalHeader->setDefaultAlignment(
                sourceHorizontalHeader->defaultAlignment());
            paneHorizontalHeader->setHighlightSections(
                sourceHorizontalHeader->highlightSections());
            paneHorizontalHeader->setSectionsClickable(
                sourceHorizontalHeader->sectionsClickable());
            paneHorizontalHeader->setSectionsMovable(false);
            paneHorizontalHeader->setStretchLastSection(false);
            paneHorizontalHeader->setSortIndicatorShown(
                sourceHorizontalHeader->isSortIndicatorShown());
            paneHorizontalHeader->setFont(sourceHorizontalHeader->font());
            paneHorizontalHeader->setPalette(sourceHorizontalHeader->palette());
            if (!pane->property("kswordFrozenHeaderBridged").toBool())
            {
                pane->setProperty("kswordFrozenHeaderBridged", true);
                bridgeFrozenHeader(pane);
            }
        }

        QHeaderView* sourceVerticalHeader = sourceTable->verticalHeader();
        QHeaderView* paneVerticalHeader = pane->verticalHeader();
        paneVerticalHeader->setVisible(showVerticalHeader);
        if (showVerticalHeader && sourceVerticalHeader != nullptr)
        {
            paneVerticalHeader->setFixedWidth(sourceVerticalHeader->width());
            paneVerticalHeader->setDefaultAlignment(sourceVerticalHeader->defaultAlignment());
            paneVerticalHeader->setSectionsClickable(false);
            paneVerticalHeader->setFont(sourceVerticalHeader->font());
            paneVerticalHeader->setPalette(sourceVerticalHeader->palette());
        }
    }

    void TableFrozenPaneController::bridgeFrozenHeader(QTableView* pane)
    {
        if (pane == nullptr || pane->horizontalHeader() == nullptr)
        {
            return;
        }

        QHeaderView* paneHeader = pane->horizontalHeader();
        // Frozen column headers are drawn by the cross-pane. Click-to-sort and drag-to-resize must be delegated
        // to the main table; otherwise, the headers of these columns become dead zones after freezing.
        connect(
            paneHeader,
            &QHeaderView::sectionClicked,
            this,
            [this](const int logicalIndex)
            {
                if (targetTable_.isNull() ||
                    !targetTable_->isSortingEnabled() ||
                    targetTable_->horizontalHeader() == nullptr)
                {
                    return;
                }
                QHeaderView* sourceHeader = targetTable_->horizontalHeader();
                const Qt::SortOrder kNextOrder =
                    sourceHeader->sortIndicatorSection() == logicalIndex &&
                        sourceHeader->sortIndicatorOrder() == Qt::AscendingOrder
                    ? Qt::DescendingOrder
                    : Qt::AscendingOrder;
                targetTable_->sortByColumn(logicalIndex, kNextOrder);
            });
        connect(
            paneHeader,
            &QHeaderView::sectionResized,
            this,
            [this](const int logicalIndex, int, const int newSize)
            {
                if (mirroringSections_ || targetTable_.isNull())
                {
                    return;
                }
                targetTable_->setColumnWidth(logicalIndex, newSize);
            });
    }

    void TableFrozenPaneController::mirrorColumnLayout(QTableView* pane)
    {
        if (pane == nullptr || targetTable_.isNull())
        {
            return;
        }

        QHeaderView* sourceHeader = targetTable_->horizontalHeader();
        QHeaderView* paneHeader = pane->horizontalHeader();
        if (sourceHeader == nullptr || paneHeader == nullptr)
        {
            return;
        }

        mirroringSections_ = true;
        paneHeader->setDefaultSectionSize(sourceHeader->defaultSectionSize());
        const int kSectionCount = std::min(sourceHeader->count(), paneHeader->count());
        for (int visualIndex = 0; visualIndex < kSectionCount; ++visualIndex)
        {
            const int kLogicalIndex = sourceHeader->logicalIndex(visualIndex);
            if (kLogicalIndex < 0)
            {
                continue;
            }
            const int kPaneVisualIndex = paneHeader->visualIndex(kLogicalIndex);
            if (kPaneVisualIndex >= 0 && kPaneVisualIndex != visualIndex)
            {
                paneHeader->moveSection(kPaneVisualIndex, visualIndex);
            }
        }
        for (int logicalIndex = 0; logicalIndex < kSectionCount; ++logicalIndex)
        {
            const bool kHidden = sourceHeader->isSectionHidden(logicalIndex);
            if (paneHeader->isSectionHidden(logicalIndex) != kHidden)
            {
                paneHeader->setSectionHidden(logicalIndex, kHidden);
            }
            if (!kHidden)
            {
                paneHeader->resizeSection(logicalIndex, sourceHeader->sectionSize(logicalIndex));
            }
        }
        if (paneHeader->isSortIndicatorShown())
        {
            paneHeader->setSortIndicator(
                sourceHeader->sortIndicatorSection(),
                sourceHeader->sortIndicatorOrder());
        }
        mirroringSections_ = false;
    }

    void TableFrozenPaneController::mirrorRowLayout(
        QTableView* pane,
        const int firstLogicalRow,
        const int lastLogicalRow)
    {
        if (pane == nullptr || targetTable_.isNull())
        {
            return;
        }

        QHeaderView* sourceHeader = targetTable_->verticalHeader();
        QHeaderView* paneHeader = pane->verticalHeader();
        if (sourceHeader == nullptr || paneHeader == nullptr)
        {
            return;
        }

        mirroringSections_ = true;
        paneHeader->setDefaultSectionSize(sourceHeader->defaultSectionSize());
        const int kSectionCount = std::min(sourceHeader->count(), paneHeader->count());
        const int kFirstRow = std::max(0, firstLogicalRow);
        const int kLastRow = std::min(kSectionCount - 1, lastLogicalRow);
        for (int logicalRow = kFirstRow; logicalRow <= kLastRow; ++logicalRow)
        {
            const bool kHidden = sourceHeader->isSectionHidden(logicalRow);
            if (paneHeader->isSectionHidden(logicalRow) != kHidden)
            {
                paneHeader->setSectionHidden(logicalRow, kHidden);
            }
            if (!kHidden)
            {
                paneHeader->resizeSection(logicalRow, sourceHeader->sectionSize(logicalRow));
            }
        }
        mirroringSections_ = false;
    }

    void TableFrozenPaneController::mirrorVisibleRowLayout(QTableView* pane)
    {
        QTableView* tableView = targetTable_.data();
        if (pane == nullptr || tableView == nullptr || tableView->model() == nullptr)
        {
            return;
        }

        const int kRowCount = tableView->model()->rowCount();
        if (kRowCount <= 0)
        {
            return;
        }

        int firstRow = tableView->rowAt(0);
        if (firstRow < 0)
        {
            firstRow = 0;
        }
        int lastRow = tableView->rowAt(std::max(0, tableView->viewport()->height() - 1));
        if (lastRow < 0)
        {
            lastRow = kRowCount - 1;
        }
        if (lastRow < firstRow)
        {
            std::swap(firstRow, lastRow);
        }
        mirrorRowLayout(
            pane,
            std::max(0, firstRow - 1),
            std::min(kRowCount - 1, lastRow + kMirrorRowMargin));
    }

    void TableFrozenPaneController::applyFrozenRowFilter(QTableView* pane)
    {
        QTableView* tableView = targetTable_.data();
        if (pane == nullptr || tableView == nullptr || tableView->model() == nullptr)
        {
            return;
        }

        QHash<int, int> frozenRowHeights;
        for (const FrozenLine& line : frozenRowLines_)
        {
            if (line.index.isValid())
            {
                frozenRowHeights.insert(line.index.row(), line.extent);
            }
        }

        mirroringSections_ = true;
        const int kRowCount = tableView->model()->rowCount();
        for (int row = 0; row < kRowCount; ++row)
        {
            const auto kHeightIterator = frozenRowHeights.constFind(row);
            const bool kFrozen = kHeightIterator != frozenRowHeights.cend();
            if (pane->isRowHidden(row) == kFrozen)
            {
                pane->setRowHidden(row, !kFrozen);
            }
            if (kFrozen && pane->rowHeight(row) != kHeightIterator.value())
            {
                pane->setRowHeight(row, kHeightIterator.value());
            }
        }
        mirroringSections_ = false;
    }

    void TableFrozenPaneController::applyFrozenColumnFilter(QTableView* pane)
    {
        QTableView* tableView = targetTable_.data();
        if (pane == nullptr || tableView == nullptr || tableView->model() == nullptr)
        {
            return;
        }

        QHash<int, int> frozenColumnWidths;
        for (const FrozenLine& line : frozenColumnLines_)
        {
            if (line.index.isValid())
            {
                frozenColumnWidths.insert(line.index.column(), line.extent);
            }
        }

        mirroringSections_ = true;
        const int kColumnCount = tableView->model()->columnCount();
        for (int column = 0; column < kColumnCount; ++column)
        {
            const auto kWidthIterator = frozenColumnWidths.constFind(column);
            const bool kFrozen = kWidthIterator != frozenColumnWidths.cend();
            if (pane->isColumnHidden(column) == kFrozen)
            {
                pane->setColumnHidden(column, !kFrozen);
            }
            if (kFrozen && pane->columnWidth(column) != kWidthIterator.value())
            {
                pane->setColumnWidth(column, kWidthIterator.value());
            }
        }
        mirroringSections_ = false;
    }

    // enforceFrozenState:
    // - Discard frozen items deleted by the model (persistent indices invalidated);
    // - When business refresh re-displays rows and columns we hid, re-capture dimensions and hide them again.
    // - When the viewport shrinks and the frozen area exceeds the budget, unfreeze from the end until back within budget.
    void TableFrozenPaneController::enforceFrozenState()
    {
        QTableView* tableView = targetTable_.data();
        if (tableView == nullptr || tableView->model() == nullptr)
        {
            frozenRowLines_.clear();
            frozenColumnLines_.clear();
            return;
        }

        for (int i = frozenRowLines_.size() - 1; i >= 0; --i)
        {
            FrozenLine& line = frozenRowLines_[i];
            if (!line.index.isValid())
            {
                frozenRowLines_.removeAt(i);
                continue;
            }
            const int kRow = line.index.row();
            if (!tableView->isRowHidden(kRow))
            {
                const int kRowHeight = tableView->verticalHeader() != nullptr
                    ? tableView->verticalHeader()->sectionSize(kRow)
                    : 0;
                if (kRowHeight > 0)
                {
                    line.extent = kRowHeight;
                }
                tableView->setRowHidden(kRow, true);
            }
        }
        const int kRowBudget = frozenRowsBudget();
        while (!frozenRowLines_.isEmpty() && totalFrozenRowsHeight() > kRowBudget)
        {
            const FrozenLine kLine = frozenRowLines_.takeLast();
            if (kLine.index.isValid())
            {
                tableView->setRowHidden(kLine.index.row(), false);
            }
        }

        const int kColumnCount = tableView->model()->columnCount();
        const int kRowCount = tableView->model()->rowCount();
        for (int i = frozenColumnLines_.size() - 1; i >= 0; --i)
        {
            FrozenLine& line = frozenColumnLines_[i];
            if (!line.index.isValid())
            {
                /*
                 * The persistent index anchor is on the cell of row 0. Common business refreshes using setRowCount(0) will invalidate it,
                 * while the column's hidden bit does not clear with section. If entries are discarded directly here, the column becomes
                 * permanently hidden and the UI cannot recover—the Unfreeze button will become disabled due to the count dropping to zero.
                 */
                if (line.section < 0 || line.section >= kColumnCount)
                {
                    // If the column no longer exists: restore visibility before discarding to avoid leaving an unrecoverable hidden column.
                    if (line.section >= 0)
                    {
                        tableView->setColumnHidden(line.section, false);
                    }
                    frozenColumnLines_.removeAt(i);
                    continue;
                }
                if (kRowCount <= 0)
                {
                    // Table is being repopulated (rows cleared, not yet refilled). Preserve the frozen
                    // state as-is; re-anchor the persistent index in the next round after repopulation.
                    continue;
                }
                line.index = QPersistentModelIndex(tableView->model()->index(0, line.section));
                if (!line.index.isValid())
                {
                    tableView->setColumnHidden(line.section, false);
                    frozenColumnLines_.removeAt(i);
                    continue;
                }
            }
            const int kColumn = line.index.column();
            line.section = kColumn;
            if (!tableView->isColumnHidden(kColumn))
            {
                const int kColumnWidth = tableView->horizontalHeader() != nullptr
                    ? tableView->horizontalHeader()->sectionSize(kColumn)
                    : 0;
                if (kColumnWidth > 0)
                {
                    line.extent = kColumnWidth;
                }
                tableView->setColumnHidden(kColumn, true);
            }
        }
        const int kColumnBudget = frozenColumnsBudget();
        while (!frozenColumnLines_.isEmpty() && totalFrozenColumnsWidth() > kColumnBudget)
        {
            const FrozenLine kLine = frozenColumnLines_.takeLast();
            // The persistent index may be invalid; in this case, only the section can locate the column to restore.
            const int kColumn = kLine.index.isValid() ? kLine.index.column() : kLine.section;
            if (kColumn >= 0 && kColumn < kColumnCount)
            {
                tableView->setColumnHidden(kColumn, false);
            }
        }

        // The frozen set may have been re-anchored or cropped in this round; publish it to allow the data-fetching side to distinguish between frozen and filtered states.
        publishFrozenSections();
    }

    void TableFrozenPaneController::layoutPanes()
    {
        QTableView* tableView = targetTable_.data();
        if (tableView == nullptr || tableView->viewport() == nullptr)
        {
            return;
        }

        const QRect kViewportGeometry = tableView->viewport()->geometry();
        const int kFrozenWidth = appliedFrozenWidth_;
        const int kFrozenHeight = appliedFrozenHeight_;
        const int kHeaderHeight = headerBandHeight(tableView);
        const int kHeaderWidth = headerBandWidth(tableView);
        const bool kRightToLeft = tableView->isRightToLeft();
        const int kBandLeft = kRightToLeft
            ? kViewportGeometry.right() + 1
            : kViewportGeometry.left() - kFrozenWidth;
        const int kCornerLeft = kRightToLeft ? kBandLeft : kBandLeft - kHeaderWidth;

        if (!topPane_.isNull())
        {
            mirrorColumnLayout(topPane_.data());
            applyFrozenRowFilter(topPane_.data());
            topPane_->setGeometry(
                kViewportGeometry.left(),
                kViewportGeometry.top() - kFrozenHeight,
                kViewportGeometry.width(),
                kFrozenHeight);
            topPane_->setVisible(kFrozenHeight > 0 && kViewportGeometry.width() > 0);
            topPane_->raise();
        }
        if (!leftPane_.isNull())
        {
            applyFrozenColumnFilter(leftPane_.data());
            mirrorVisibleRowLayout(leftPane_.data());
            leftPane_->setGeometry(
                kBandLeft,
                kViewportGeometry.top(),
                kFrozenWidth,
                kViewportGeometry.height());
            leftPane_->setVisible(kFrozenWidth > 0 && kViewportGeometry.height() > 0);
            leftPane_->raise();
        }
        if (!cornerPane_.isNull())
        {
            applyFrozenRowFilter(cornerPane_.data());
            applyFrozenColumnFilter(cornerPane_.data());
            cornerPane_->setGeometry(
                kCornerLeft,
                kViewportGeometry.top() - kFrozenHeight - kHeaderHeight,
                kFrozenWidth + kHeaderWidth,
                kFrozenHeight + kHeaderHeight);
            cornerPane_->setVisible(
                (kFrozenWidth + kHeaderWidth) > 0 && (kFrozenHeight + kHeaderHeight) > 0);
            cornerPane_->raise();
        }
    }

    void TableFrozenPaneController::syncPanes()
    {
        QTableView* tableView = targetTable_.data();
        if (tableView == nullptr || tableView->model() == nullptr)
        {
            return;
        }

        if (!topPane_.isNull())
        {
            // All non-frozen rows are hidden; the content top is the first frozen row, vertically locked at 0.
            setPaneScrollValue(topPane_->verticalScrollBar(), 0);
            setPaneHorizontalToSource(topPane_.data());
        }
        if (!leftPane_.isNull())
        {
            mirrorVisibleRowLayout(leftPane_.data());
            setPaneVerticalToSource(leftPane_.data());
            setPaneScrollValue(leftPane_->horizontalScrollBar(), 0);
        }
        if (!cornerPane_.isNull())
        {
            setPaneScrollValue(cornerPane_->verticalScrollBar(), 0);
            setPaneScrollValue(cornerPane_->horizontalScrollBar(), 0);
        }
    }

    void TableFrozenPaneController::setPaneVerticalToSource(QTableView* pane)
    {
        QTableView* tableView = targetTable_.data();
        if (pane == nullptr || tableView == nullptr || pane->verticalHeader() == nullptr)
        {
            return;
        }

        // The main table may scroll by whole rows, and scrollbar values are not in pixels. Align uniformly by the pixel position
        // of the top row in the viewport so that frozen columns remain aligned with the main table in both scrolling modes.
        const int kFirstRow = tableView->rowAt(0);
        if (kFirstRow < 0)
        {
            setPaneScrollValue(pane->verticalScrollBar(), 0);
            return;
        }
        const int kSectionPosition = pane->verticalHeader()->sectionPosition(kFirstRow);
        if (kSectionPosition < 0)
        {
            return;
        }
        setPaneScrollValue(
            pane->verticalScrollBar(),
            std::max(0, kSectionPosition - tableView->rowViewportPosition(kFirstRow)));
    }

    void TableFrozenPaneController::setPaneHorizontalToSource(QTableView* pane)
    {
        QTableView* tableView = targetTable_.data();
        if (pane == nullptr || tableView == nullptr || pane->horizontalHeader() == nullptr)
        {
            return;
        }

        const int kFirstColumn = tableView->columnAt(0);
        if (kFirstColumn < 0)
        {
            setPaneScrollValue(pane->horizontalScrollBar(), 0);
            return;
        }
        const int kSectionPosition = pane->horizontalHeader()->sectionPosition(kFirstColumn);
        if (kSectionPosition < 0)
        {
            return;
        }
        setPaneScrollValue(
            pane->horizontalScrollBar(),
            std::max(0, kSectionPosition - tableView->columnViewportPosition(kFirstColumn)));
    }

    void TableFrozenPaneController::refreshGeometry()
    {
        if (refreshing_)
        {
            return;
        }
        if (targetTable_.isNull() ||
            targetTable_->viewport() == nullptr ||
            targetTable_->model() == nullptr)
        {
            destroyPanes();
            appliedFrozenWidth_ = 0;
            appliedFrozenHeight_ = 0;
            return;
        }

        // Fast path when nothing is frozen: updatePosition is called directly on high-frequency paths like Resize/Show.
        if (frozenRowLines_.isEmpty() &&
            frozenColumnLines_.isEmpty() &&
            topPane_.isNull() &&
            leftPane_.isNull() &&
            cornerPane_.isNull() &&
            appliedFrozenWidth_ == 0 &&
            appliedFrozenHeight_ == 0 &&
            targetModel_ == targetTable_->model())
        {
            return;
        }

        refreshing_ = true;

        if (targetModel_ != targetTable_->model())
        {
            // After the business code completely replaces the model, persistent indices on the old model are invalid; directly unfreeze all rows.
            disconnectTarget();
            destroyPanes();
            frozenRowLines_.clear();
            frozenColumnLines_.clear();
            targetModel_ = targetTable_->model();
            connectTarget();
        }

        enforceFrozenState();

        if (TableActionBarHost* host = tableActionBarHostFor(targetTable_.data()))
        {
            host->setFrozenPaneReservation(
                totalFrozenColumnsWidth(),
                totalFrozenRowsHeight());
            const QSize kReservation = host->frozenPaneReservation();
            appliedFrozenWidth_ = kReservation.width();
            appliedFrozenHeight_ = kReservation.height();
        }
        else
        {
            // Standard QTableView cannot reserve a viewport; forcibly overlaying it only obscures data, so freezing is abandoned here.
            unfreezeAllRows();
            unfreezeAllColumns();
            appliedFrozenWidth_ = 0;
            appliedFrozenHeight_ = 0;
        }

        ensurePanes();
        layoutPanes();
        syncPanes();
        refreshing_ = false;
    }

    int TableFrozenPaneController::totalFrozenRowsHeight() const
    {
        int height = 0;
        for (const FrozenLine& line : frozenRowLines_)
        {
            if (line.index.isValid())
            {
                height += line.extent;
            }
        }
        return height;
    }

    int TableFrozenPaneController::totalFrozenColumnsWidth() const
    {
        int width = 0;
        for (const FrozenLine& line : frozenColumnLines_)
        {
            if (line.index.isValid())
            {
                width += line.extent;
            }
        }
        return width;
    }

    int TableFrozenPaneController::frozenRowsBudget() const
    {
        if (targetTable_.isNull() || targetTable_->viewport() == nullptr)
        {
            return 0;
        }
        return std::max(
            0,
            (targetTable_->viewport()->height() + appliedFrozenHeight_) /
                kFrozenBandBudgetDivisor);
    }

    int TableFrozenPaneController::frozenColumnsBudget() const
    {
        if (targetTable_.isNull() || targetTable_->viewport() == nullptr)
        {
            return 0;
        }
        return std::max(
            0,
            (targetTable_->viewport()->width() + appliedFrozenWidth_) /
                kFrozenBandBudgetDivisor);
    }

    void TableFrozenPaneController::publishFrozenSections()
    {
        QTableView* tableView = targetTable_.data();
        if (tableView == nullptr)
        {
            return;
        }

        QVariantList frozenRows;
        frozenRows.reserve(frozenRowLines_.size());
        for (const FrozenLine& line : frozenRowLines_)
        {
            const int kRow = line.index.isValid() ? line.index.row() : line.section;
            if (kRow >= 0)
            {
                frozenRows.push_back(kRow);
            }
        }

        QVariantList frozenColumns;
        frozenColumns.reserve(frozenColumnLines_.size());
        for (const FrozenLine& line : frozenColumnLines_)
        {
            const int kColumn = line.index.isValid() ? line.index.column() : line.section;
            if (kColumn >= 0)
            {
                frozenColumns.push_back(kColumn);
            }
        }

        tableView->setProperty(kFrozenHiddenRowsProperty, frozenRows);
        tableView->setProperty(kFrozenHiddenColumnsProperty, frozenColumns);
    }

    namespace
    {
        bool sectionListContains(
            const QTableView* tableView,
            const char* propertyName,
            const int section)
        {
            if (tableView == nullptr || section < 0)
            {
                return false;
            }
            const QVariant kStored = tableView->property(propertyName);
            if (!kStored.isValid())
            {
                return false;
            }
            const QVariantList kSectionList = kStored.toList();
            for (const QVariant& entry : kSectionList)
            {
                bool converted = false;
                if (entry.toInt(&converted) == section && converted)
                {
                    return true;
                }
            }
            return false;
        }
    }

    bool isRowHiddenByFreeze(const QTableView* tableView, const int row)
    {
        return sectionListContains(tableView, kFrozenHiddenRowsProperty, row);
    }

    bool isColumnHiddenByFreeze(const QTableView* tableView, const int column)
    {
        return sectionListContains(tableView, kFrozenHiddenColumnsProperty, column);
    }
}
