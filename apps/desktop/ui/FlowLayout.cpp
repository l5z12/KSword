#include "FlowLayout.h"

#include <QLayoutItem>
#include <QStyle>
#include <QWidget>

namespace ks::ui
{
    FlowLayout::FlowLayout(
        QWidget* const parent,
        const int margin,
        const int horizontalSpacing,
        const int verticalSpacing)
        : QLayout(parent)
        , horizontalSpacing_(horizontalSpacing)
        , verticalSpacing_(verticalSpacing)
    {
        if (margin >= 0)
        {
            setContentsMargins(margin, margin, margin, margin);
        }
    }

    FlowLayout::~FlowLayout()
    {
        // QLayout does not reclaim items for derived classes. takeAt is the only ownership-transfer
        // path; drain it in the destructor or every UI rebuild will leak QWidgetItem objects.
        while (QLayoutItem* const kItem = takeAt(0))
        {
            delete kItem;
        }
    }

    void FlowLayout::addItem(QLayoutItem* const item)
    {
        if (item == nullptr)
        {
            return;
        }
        items_.append(item);
    }

    int FlowLayout::horizontalSpacing() const
    {
        if (horizontalSpacing_ >= 0)
        {
            return horizontalSpacing_;
        }
        return smartSpacing(QStyle::PM_LayoutHorizontalSpacing);
    }

    int FlowLayout::verticalSpacing() const
    {
        if (verticalSpacing_ >= 0)
        {
            return verticalSpacing_;
        }
        return smartSpacing(QStyle::PM_LayoutVerticalSpacing);
    }

    Qt::Orientations FlowLayout::expandingDirections() const
    {
        // No extended directions are declared: these buttons should stick to the top, leaving extra vertical space
        // for the table below. Declaring Vertical would cause the button row to grow with the window height.
        return Qt::Orientations();
    }

    bool FlowLayout::hasHeightForWidth() const
    {
        return true;
    }

    int FlowLayout::heightForWidth(const int width) const
    {
        return doLayout(QRect(0, 0, width, 0), true);
    }

    int FlowLayout::count() const
    {
        return static_cast<int>(items_.size());
    }

    QLayoutItem* FlowLayout::itemAt(const int index) const
    {
        return items_.value(index);
    }

    QLayoutItem* FlowLayout::takeAt(const int index)
    {
        if (index < 0 || index >= static_cast<int>(items_.size()))
        {
            return nullptr;
        }
        return items_.takeAt(index);
    }

    QSize FlowLayout::minimumSize() const
    {
        QSize size;
        for (const QLayoutItem* const kItem : items_)
        {
            size = size.expandedTo(kItem->minimumSize());
        }
        const QMargins kMargins = contentsMargins();
        // Minimum width is calculated based only on the **widest single control**, not the sum of all controls: This is precisely the
        // purpose of a flow layout with wrapping—ensuring a window narrow enough to fit only one button can still display it completely.
        size += QSize(kMargins.left() + kMargins.right(), kMargins.top() + kMargins.bottom());
        return size;
    }

    void FlowLayout::setGeometry(const QRect& rect)
    {
        QLayout::setGeometry(rect);
        doLayout(rect, false);
    }

    QSize FlowLayout::sizeHint() const
    {
        return minimumSize();
    }

    int FlowLayout::doLayout(const QRect& rect, const bool testOnly) const
    {
        int left = 0;
        int top = 0;
        int right = 0;
        int bottom = 0;
        getContentsMargins(&left, &top, &right, &bottom);
        const QRect kEffective = rect.adjusted(left, top, -right, -bottom);

        int x = kEffective.x();
        int y = kEffective.y();
        int lineHeight = 0;

        for (QLayoutItem* const kItem : items_)
        {
            const QWidget* const kWidget = kItem->widget();
            int spaceX = horizontalSpacing();
            int spaceY = verticalSpacing();
            if (kWidget != nullptr)
            {
                // Fetch spacing from widget style when not explicitly specified: button spacing
                // varies by theme; hardcoding it causes crowding or excessive gaps in some themes.
                if (spaceX < 0)
                {
                    spaceX = kWidget->style()->layoutSpacing(
                        QSizePolicy::PushButton,
                        QSizePolicy::PushButton,
                        Qt::Horizontal);
                }
                if (spaceY < 0)
                {
                    spaceY = kWidget->style()->layoutSpacing(
                        QSizePolicy::PushButton,
                        QSizePolicy::PushButton,
                        Qt::Vertical);
                }
            }
            if (spaceX < 0)
            {
                spaceX = 0;
            }
            if (spaceY < 0)
            {
                spaceY = 0;
            }

            const QSize kItemHint = kItem->sizeHint();
            int next = x + kItemHint.width() + spaceX;
            if (next - spaceX > kEffective.right() + 1 && lineHeight > 0)
            {
                // Line overflow: wrap. The lineHeight > 0 condition ensures a control wider than the
                // line isn't pushed down infinitely—it takes a full line with its width preserved.
                x = kEffective.x();
                y = y + lineHeight + spaceY;
                next = x + kItemHint.width() + spaceX;
                lineHeight = 0;
            }

            if (!testOnly)
            {
                kItem->setGeometry(QRect(QPoint(x, y), kItemHint));
            }

            x = next;
            lineHeight = qMax(lineHeight, kItemHint.height());
        }
        return y + lineHeight - rect.y() + bottom;
    }

    int FlowLayout::smartSpacing(const int pixelMetric) const
    {
        QObject* const kParentObject = parent();
        if (kParentObject == nullptr)
        {
            return -1;
        }
        if (kParentObject->isWidgetType())
        {
            auto* const kParentWidget = static_cast<QWidget*>(kParentObject);
            return kParentWidget->style()->pixelMetric(
                static_cast<QStyle::PixelMetric>(pixelMetric),
                nullptr,
                kParentWidget);
        }
        return static_cast<QLayout*>(kParentObject)->spacing();
    }
}
