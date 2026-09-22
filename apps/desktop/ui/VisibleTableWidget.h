#pragma once

#include <QAbstractButton>
#include <QAbstractItemModel>
#include <QHeaderView>
#include <QList>
#include <QMargins>
#include <QModelIndex>
#include <QPaintEvent>
#include <QPointer>
#include <QRect>
#include <QScrollBar>
#include <QSignalBlocker>
#include <QSize>
#include <QTableView>
#include <QTableWidget>
#include <QTimer>
#include <QVariant>

#include <algorithm>
#include <utility>

namespace ks::ui
{
    enum class TableActionBarMode
    {
        kNone = 0,
        kCompact = 1,
        kFull = 2
    };

    inline constexpr char kTableActionBarModeProperty[] =
        "KSWORD_TABLE_INTERACTION_ACTION_BAR_MODE";
    inline constexpr char kPreserveCustomTableHeaderStyleProperty[] =
        "KSWORD_TABLE_INTERACTION_PRESERVE_CUSTOM_HEADER_STYLE";

    inline void setPreserveCustomTableHeaderStyle(QTableView* tableView, const bool preserve)
    {
        if (tableView != nullptr)
        {
            tableView->setProperty(kPreserveCustomTableHeaderStyleProperty, preserve);
        }
    }

    inline bool preservesCustomTableHeaderStyle(const QTableView* tableView)
    {
        return tableView != nullptr
            && tableView->property(kPreserveCustomTableHeaderStyleProperty).toBool();
    }

    // Implemented by table subclasses that can reserve a strip immediately above the column
    // header. The action widget remains owned by its caller; this interface only manages the
    // table's layout reservation and supplies the matching geometry for that widget.
    //
    // The same mechanism carries the Excel-style frozen panes: a frozen band is not painted on
    // top of the scrollable viewport, it is carved out of it. Reserving the band shrinks the
    // viewport so the scrollable rows/columns start below/right of the frozen ones, which is
    // what keeps a frozen row genuinely pinned instead of merely covering live content.
    class TableActionBarHost
    {
    public:
        virtual ~TableActionBarHost() = default;

        virtual void setTopActionBarHeight(int height) = 0;
        virtual int topActionBarHeight() const = 0;
        virtual QRect topActionBarGeometry() const = 0;

        // frozenColumnsWidth is reserved between the row header and the viewport;
        // frozenRowsHeight is reserved between the column header and the viewport.
        virtual void setFrozenPaneReservation(int frozenColumnsWidth, int frozenRowsHeight) = 0;
        virtual QSize frozenPaneReservation() const = 0;
    };

    namespace visible_table_detail
    {
        inline constexpr char kComparisonSourceActiveProperty[] =
            "KSWORD_TABLE_INTERACTION_COMPARISON_SOURCE_ACTIVE";

        // QTableView owns its viewport margins and recalculates them whenever its geometry is
        // updated. Keep the action-bar adjustment in a small reusable helper so QTableWidget and
        // plain QTableView hosts receive exactly the same table/header/scrollbar layout.
        class TableActionBarLayout final
        {
        public:
            bool setHeight(const int height)
            {
                const int kNormalizedHeight = std::max(0, height);
                if (height_ == kNormalizedHeight)
                {
                    return false;
                }

                height_ = kNormalizedHeight;
                return true;
            }

            int height() const
            {
                return height_;
            }

            bool setFrozenPaneReservation(const int frozenColumnsWidth, const int frozenRowsHeight)
            {
                const int kNormalizedWidth = std::max(0, frozenColumnsWidth);
                const int kNormalizedHeight = std::max(0, frozenRowsHeight);
                if (frozenColumnsWidth_ == kNormalizedWidth && frozenRowsHeight_ == kNormalizedHeight)
                {
                    return false;
                }

                frozenColumnsWidth_ = kNormalizedWidth;
                frozenRowsHeight_ = kNormalizedHeight;
                return true;
            }

            int frozenColumnsWidth() const
            {
                return frozenColumnsWidth_;
            }

            int frozenRowsHeight() const
            {
                return frozenRowsHeight_;
            }

            bool hasReservation() const
            {
                return height_ > 0 || frozenColumnsWidth_ > 0 || frozenRowsHeight_ > 0;
            }

            QRect geometry(const QTableView* tableView) const
            {
                if (tableView == nullptr || tableView->viewport() == nullptr || height_ <= 0)
                {
                    return {};
                }

                const QRect kViewportGeometry = tableView->viewport()->geometry();
                const bool kRightToLeft = tableView->isRightToLeft();
                int left = kRightToLeft
                    ? kViewportGeometry.left()
                    : kViewportGeometry.left() - frozenColumnsWidth_;
                int right = kRightToLeft
                    ? kViewportGeometry.right() + frozenColumnsWidth_
                    : kViewportGeometry.right();
                if (const QHeaderView* verticalHeader = tableView->verticalHeader();
                    verticalHeader != nullptr && !verticalHeader->isHidden())
                {
                    left = std::min(left, verticalHeader->geometry().left());
                    right = std::max(right, verticalHeader->geometry().right());
                }

                const QHeaderView* horizontalHeader = tableView->horizontalHeader();
                const int kHeaderHeight = horizontalHeader != nullptr && !horizontalHeader->isHidden()
                    ? horizontalHeader->height()
                    : 0;
                const int kTop = kViewportGeometry.top() - frozenRowsHeight_ - kHeaderHeight - height_;
                return QRect(left, kTop, std::max(0, right - left + 1), height_);
            }

            // Capture this directly after QTableView::updateGeometries().  QTableView owns the
            // normal header margins and resets them on every geometry pass.  Keeping that value
            // separate prevents the action-bar height from being added repeatedly.
            void captureBaseViewportMargins(const QMargins& baseMargins)
            {
                baseViewportMargins_ = baseMargins;
            }

            // Must be called after captureBaseViewportMargins().
            QMargins adjustedViewportMargins(const QTableView* tableView) const
            {
                if (!hasReservation())
                {
                    return baseViewportMargins_;
                }

                const bool kRightToLeft = tableView != nullptr && tableView->isRightToLeft();
                return QMargins(
                    baseViewportMargins_.left() + (kRightToLeft ? 0 : frozenColumnsWidth_),
                    baseViewportMargins_.top() + height_ + frozenRowsHeight_,
                    baseViewportMargins_.right() + (kRightToLeft ? frozenColumnsWidth_ : 0),
                    baseViewportMargins_.bottom());
            }

            // Call this after the owning table subclass applies adjustedViewportMargins().
            // QAbstractScrollArea::setViewportMargins is protected, so its invocation must stay
            // in that subclass rather than in this generic helper.
            void applyTableChrome(QTableView* tableView) const
            {
                if (tableView == nullptr || tableView->viewport() == nullptr || !hasReservation())
                {
                    return;
                }

                const QRect kViewportGeometry = tableView->viewport()->geometry();
                QHeaderView* horizontalHeader = tableView->horizontalHeader();
                QHeaderView* verticalHeader = tableView->verticalHeader();
                const int kHorizontalHeaderHeight = horizontalHeader != nullptr && !horizontalHeader->isHidden()
                    ? horizontalHeader->height()
                    : 0;
                const int kVerticalHeaderWidth = verticalHeader != nullptr && !verticalHeader->isHidden()
                    ? verticalHeader->width()
                    : 0;

                // Both headers stay glued to the table edge; the frozen bands live between them
                // and the viewport, so the header offsets skip over the reserved bands.
                const int kVerticalHeaderLeft = tableView->isRightToLeft()
                    ? kViewportGeometry.right() + 1 + frozenColumnsWidth_
                    : kViewportGeometry.left() - frozenColumnsWidth_ - kVerticalHeaderWidth;
                const int kHorizontalHeaderTop =
                    kViewportGeometry.top() - frozenRowsHeight_ - kHorizontalHeaderHeight;

                // QTableView connects each header's geometriesChanged signal directly back to
                // updateGeometries(). At this point QTableView's own recursion guard has already
                // been released, so the required second header placement must not emit that
                // signal again or it loops through geometry updates until the viewport disappears.
                const QSignalBlocker kHorizontalHeaderSignalBlocker(horizontalHeader);
                const QSignalBlocker kVerticalHeaderSignalBlocker(verticalHeader);
                if (horizontalHeader != nullptr)
                {
                    horizontalHeader->setGeometry(
                        kViewportGeometry.left(),
                        kHorizontalHeaderTop,
                        kViewportGeometry.width(),
                        kHorizontalHeaderHeight);
                }
                if (verticalHeader != nullptr)
                {
                    verticalHeader->setGeometry(
                        kVerticalHeaderLeft,
                        kViewportGeometry.top(),
                        kVerticalHeaderWidth,
                        kViewportGeometry.height());
                }

                // QTableView's private corner widget is a direct QAbstractButton child. It is
                // the intersection of the two headers, so it must follow the shifted header
                // row. Table action bars are hosted in their own container rather than as a
                // direct button child.
                const QList<QAbstractButton*> kDirectButtons = tableView->findChildren<QAbstractButton*>(
                    QString(),
                    Qt::FindDirectChildrenOnly);
                for (QAbstractButton* button : kDirectButtons)
                {
                    if (button != nullptr)
                    {
                        button->setGeometry(
                            kVerticalHeaderLeft,
                            kHorizontalHeaderTop,
                            kVerticalHeaderWidth,
                            kHorizontalHeaderHeight);
                    }
                }
            }

        private:
            QMargins baseViewportMargins_;
            int height_ = 0;
            int frozenColumnsWidth_ = 0;
            int frozenRowsHeight_ = 0;
        };

        // TableChromeHostView:
        // - Consolidate top action bar and frozen pane viewport reservation with header reordering into a single implementation.
        // - BaseTableView must be QTableView or one of its subclasses (e.g., QTableWidget).
        template <typename BaseTableView>
        class TableChromeHostView : public BaseTableView, public TableActionBarHost
        {
        public:
            using BaseTableView::BaseTableView;

            void setTopActionBarHeight(const int height) override
            {
                if (!chromeLayout_.setHeight(height))
                {
                    return;
                }

                this->updateGeometries();
                this->update();
            }

            int topActionBarHeight() const override
            {
                return chromeLayout_.height();
            }

            QRect topActionBarGeometry() const override
            {
                return chromeLayout_.geometry(this);
            }

            void setFrozenPaneReservation(
                const int frozenColumnsWidth,
                const int frozenRowsHeight) override
            {
                if (!chromeLayout_.setFrozenPaneReservation(frozenColumnsWidth, frozenRowsHeight))
                {
                    return;
                }

                this->updateGeometries();
                this->update();
            }

            QSize frozenPaneReservation() const override
            {
                return QSize(
                    chromeLayout_.frozenColumnsWidth(),
                    chromeLayout_.frozenRowsHeight());
            }

        protected:
            void updateGeometries() override
            {
                if (updatingChromeGeometry_)
                {
                    return;
                }

                updatingChromeGeometry_ = true;
                BaseTableView::updateGeometries();
                chromeLayout_.captureBaseViewportMargins(this->viewportMargins());
                this->setViewportMargins(chromeLayout_.adjustedViewportMargins(this));
                chromeLayout_.applyTableChrome(this);
                updatingChromeGeometry_ = false;
            }

        private:
            TableActionBarLayout chromeLayout_;
            bool updatingChromeGeometry_ = false;
        };

        inline std::pair<int, int> visibleRowRange(const QTableView* tableView)
        {
            if (tableView == nullptr ||
                tableView->model() == nullptr ||
                tableView->viewport() == nullptr ||
                tableView->verticalHeader() == nullptr ||
                tableView->viewport()->height() <= 0)
            {
                return { -1, -1 };
            }

            const int kRowCount = tableView->model()->rowCount();
            if (kRowCount <= 0)
            {
                return { -1, -1 };
            }

            const QHeaderView* verticalHeader = tableView->verticalHeader();
            int firstRow = verticalHeader->logicalIndexAt(0);
            if (firstRow < 0)
            {
                firstRow = verticalHeader->logicalIndexAt(1);
            }
            if (firstRow < 0)
            {
                return { -1, -1 };
            }

            int lastRow = verticalHeader->logicalIndexAt(tableView->viewport()->height() - 1);
            if (lastRow < 0)
            {
                // The table is shorter than its viewport. In that case the final model row is
                // visible even though the pixel at the bottom of the viewport is empty.
                const int kFinalContentPixel = std::min(
                    tableView->viewport()->height() - 1,
                    verticalHeader->length() - 1);
                lastRow = verticalHeader->logicalIndexAt(kFinalContentPixel);
            }
            if (lastRow < 0)
            {
                lastRow = firstRow;
            }

            if (firstRow > lastRow)
            {
                std::swap(firstRow, lastRow);
            }
            return {
                std::clamp(firstRow, 0, kRowCount - 1),
                std::clamp(lastRow, 0, kRowCount - 1)
            };
        }

        inline void scheduleVisibleRowHeightRefresh(QTableView* tableView)
        {
            if (tableView == nullptr || tableView->property("kswordVisibleRowHeightRefreshPending").toBool())
            {
                return;
            }

            tableView->setProperty("kswordVisibleRowHeightRefreshPending", true);
            const QPointer<QTableView> kGuardedTable(tableView);
            QTimer::singleShot(0, tableView, [kGuardedTable]()
                {
                    if (kGuardedTable.isNull())
                    {
                        return;
                    }

                    QTableView* table = kGuardedTable.data();
                    table->setProperty("kswordVisibleRowHeightRefreshPending", false);
                    const auto [firstRow, lastRow] = visibleRowRange(table);
                    if (firstRow < 0 || lastRow < firstRow)
                    {
                        return;
                    }

                    for (int row = firstRow; row <= lastRow; ++row)
                    {
                        if (!table->isRowHidden(row))
                        {
                            table->resizeRowToContents(row);
                        }
                    }
                });
        }
    }

    // VisibleTableWidget keeps the complete QTableWidget model intact. In particular, every
    // off-screen item and sort role still participates in QTableWidget's normal full-data sort.
    // Only QAbstractItemView's repaint notification is clipped to rows intersecting the viewport.
    class VisibleTableWidget final
        : public visible_table_detail::TableChromeHostView<QTableWidget>
    {
    public:
        using TableChromeHostView<QTableWidget>::TableChromeHostView;

        static constexpr int kLongTableRowThreshold = 64;

    protected:
        void paintEvent(QPaintEvent* eventObject) override
        {
            if (property(visible_table_detail::kComparisonSourceActiveProperty).toBool())
            {
                return;
            }
            QTableWidget::paintEvent(eventObject);
        }

        void dataChanged(
            const QModelIndex& topLeft,
            const QModelIndex& bottomRight,
            const QList<int>& roles = QList<int>()) override
        {
            if (!topLeft.isValid() ||
                !bottomRight.isValid() ||
                topLeft.parent() != bottomRight.parent() ||
                model() == nullptr ||
                model()->rowCount(topLeft.parent()) < kLongTableRowThreshold ||
                property("kswordDisableVisibleRefresh").toBool())
            {
                QTableView::dataChanged(topLeft, bottomRight, roles);
                return;
            }

            // Hidden tabs need no repaint. Qt will paint their current model contents normally
            // when they become visible, so skipping this notification cannot leave stale data.
            if (viewport() == nullptr || !viewport()->isVisible())
            {
                return;
            }

            const auto [firstVisibleRow, lastVisibleRow] =
                visible_table_detail::visibleRowRange(this);
            if (firstVisibleRow < 0 ||
                lastVisibleRow < topLeft.row() ||
                firstVisibleRow > bottomRight.row())
            {
                return;
            }

            const int kFirstChangedVisibleRow = std::max(firstVisibleRow, topLeft.row());
            const int kLastChangedVisibleRow = std::min(lastVisibleRow, bottomRight.row());
            const QModelIndex kClippedTopLeft = model()->index(
                kFirstChangedVisibleRow,
                topLeft.column(),
                topLeft.parent());
            const QModelIndex kClippedBottomRight = model()->index(
                kLastChangedVisibleRow,
                bottomRight.column(),
                bottomRight.parent());
            QTableView::dataChanged(kClippedTopLeft, kClippedBottomRight, roles);
        }
    };

    // Use this for flat QTableView-based pages that need the same top action-bar reservation as
    // VisibleTableWidget. Its data/model behavior is otherwise identical to QTableView.
    class TableActionTableView final
        : public visible_table_detail::TableChromeHostView<QTableView>
    {
    public:
        using TableChromeHostView<QTableView>::TableChromeHostView;

    protected:
        void paintEvent(QPaintEvent* eventObject) override
        {
            if (property(visible_table_detail::kComparisonSourceActiveProperty).toBool())
            {
                return;
            }
            QTableView::paintEvent(eventObject);
        }
    };

    // All table chrome hosts default to the complete snapshot/freeze workflow.
    // Tiny or purely presentational tables can explicitly select Compact or None.
    inline TableActionBarMode effectiveTableActionBarMode(const QTableView* tableView)
    {
        if (tableView == nullptr)
        {
            return TableActionBarMode::kNone;
        }

        const QVariant kConfiguredMode = tableView->property(kTableActionBarModeProperty);
        if (kConfiguredMode.isValid())
        {
            switch (kConfiguredMode.toInt())
            {
            case static_cast<int>(TableActionBarMode::kNone):
                return TableActionBarMode::kNone;
            case static_cast<int>(TableActionBarMode::kFull):
                return TableActionBarMode::kFull;
            default:
                return TableActionBarMode::kCompact;
            }
        }

        return TableActionBarMode::kFull;
    }

    inline void setTableActionBarMode(QTableView* tableView, const TableActionBarMode mode)
    {
        if (tableView != nullptr)
        {
            tableView->setProperty(kTableActionBarModeProperty, static_cast<int>(mode));
        }
    }

    inline TableActionBarHost* tableActionBarHostFor(QTableView* tableView)
    {
        return dynamic_cast<TableActionBarHost*>(tableView);
    }

    inline const TableActionBarHost* tableActionBarHostFor(const QTableView* tableView)
    {
        return dynamic_cast<const TableActionBarHost*>(tableView);
    }

    // Enables on-demand row-height measurement for variable-height long tables. The model still
    // contains every row; scrolling only measures the rows that have entered the viewport.
    inline void installVisibleRowHeightRefresh(QTableView* tableView)
    {
        if (tableView == nullptr || tableView->property("kswordVisibleRowHeightRefreshInstalled").toBool())
        {
            return;
        }

        tableView->setProperty("kswordVisibleRowHeightRefreshInstalled", true);
        if (tableView->verticalHeader() != nullptr)
        {
            tableView->verticalHeader()->setSectionResizeMode(QHeaderView::Interactive);
        }

        QObject::connect(
            tableView->verticalScrollBar(),
            &QScrollBar::valueChanged,
            tableView,
            [tableView](int)
            {
                visible_table_detail::scheduleVisibleRowHeightRefresh(tableView);
            });
        visible_table_detail::scheduleVisibleRowHeightRefresh(tableView);
    }

    inline void refreshVisibleRowHeights(QTableView* tableView)
    {
        visible_table_detail::scheduleVisibleRowHeightRefresh(tableView);
    }
}
