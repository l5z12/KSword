#pragma once

// FlowLayout: layout that wraps to the next line when a row is full.
//
// Why it's needed: QHBoxLayout does not wrap or truncate with ellipsis when width is insufficient; instead, it
// compresses all child controls below their sizeHint, causing QPushButton text to be **directly clipped**. On a 1024×768
// display, the two rows of buttons on the KVM page became 'efresh Capabilitie' and ''repare VMX/EP' exactly this way:
// The layout itself is not reporting errors, and buttons remain clickable, but the labels cannot be read.
//
// Using QGridLayout with a fixed column count does not solve the problem: the column count is fixed at construction,
// wasting half the layout on wide windows and still truncating content on narrow windows. FlowLayout is the only approach
// here that adapts to the window size by determining the number of items per row based on the **actual available width**.
//
// Key implementation point: heightForWidth. Layout height depends on width (number of wrapped
// lines). Qt only queries this if hasHeightForWidth() returns true; both conditions are required.

#include <QLayout>
#include <QList>
#include <QRect>
#include <QSize>

class QLayoutItem;
class QWidget;

namespace ks::ui
{
    class FlowLayout final : public QLayout
    {
    public:
        explicit FlowLayout(
            QWidget* parent = nullptr,
            int margin = -1,
            int horizontalSpacing = -1,
            int verticalSpacing = -1);
        ~FlowLayout() override;

        FlowLayout(const FlowLayout&) = delete;
        FlowLayout& operator=(const FlowLayout&) = delete;

        void addItem(QLayoutItem* item) override;

        int horizontalSpacing() const;
        int verticalSpacing() const;

        Qt::Orientations expandingDirections() const override;
        bool hasHeightForWidth() const override;
        int heightForWidth(int width) const override;
        int count() const override;
        QLayoutItem* itemAt(int index) const override;
        QLayoutItem* takeAt(int index) override;
        QSize minimumSize() const override;
        void setGeometry(const QRect& rect) override;
        QSize sizeHint() const override;

    private:
        // doLayout: The actual layout logic. When testOnly is true, only the height is calculated without moving
        // controls; heightForWidth follows this path—moving controls during layout calculation would cause reentrancy.
        int doLayout(const QRect& rect, bool testOnly) const;
        int smartSpacing(int pixelMetric) const;

        QList<QLayoutItem*> items_;
        int horizontalSpacing_;
        int verticalSpacing_;
    };
}
