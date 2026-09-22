#pragma once

// ============================================================
// EmbeddedRowDelegate.h
// Purpose:
// - When expanding row details, constrain the source cell's drawing area to the original row height before expansion.
// - Preserve the original item delegate's painting, editing, and tooltip behaviors for the page.
// - Do not modify the business model; only correct the source row drawing geometry at the view layer.
// ============================================================

#include <QAbstractItemDelegate>
#include <QModelIndex>
#include <QPointer>
#include <QStyleOptionViewItem>

#include <functional>

class QAbstractItemModel;
class QAbstractItemView;
class QHelpEvent;
class QPainter;
class QWidget;

namespace ks::ui
{
    // EmbeddedRowDelegate: wraps the page's original delegate and trims the draw area for expanded source rows.
    // Usage: Created and installed into the data view by DetailLayoutHost when the row detail is first expanded.
    // sourceDelegate: The page's original delegate; the wrapper borrows it without taking ownership.
    // originalHeightProvider: Returns the original row height before expansion by model index; returns <= 0 for non-detail rows.
    class EmbeddedRowDelegate final : public QAbstractItemDelegate
    {
    public:
        using OriginalHeightProvider = std::function<int(const QModelIndex&)>;

        // Constructor: Saves the original delegate and row height query function, and forwards the original delegate's editing signals.
        // parent: Host of the data view or detail layout, responsible for the wrapper's lifecycle.
        EmbeddedRowDelegate(
            QAbstractItemDelegate* sourceDelegate,
            OriginalHeightProvider originalHeightProvider,
            QObject* parent = nullptr);

        // paint: When the detail row is expanded, draw source cells only within the original row height.
        // painter/option/index: Qt view-provided drawing context, options, and model index.
        void paint(
            QPainter* painter,
            const QStyleOptionViewItem& option,
            const QModelIndex& index) const override;

        // sizeHint: Retain the original delegate's size hint to avoid altering the layout of collapsed pages.
        QSize sizeHint(
            const QStyleOptionViewItem& option,
            const QModelIndex& index) const override;

        // The following interfaces forward editing, hints, and event handling to avoid altering the page's existing interaction behavior via wrappers.
        QWidget* createEditor(
            QWidget* parent,
            const QStyleOptionViewItem& option,
            const QModelIndex& index) const override;
        void destroyEditor(QWidget* editor, const QModelIndex& index) const override;
        void setEditorData(QWidget* editor, const QModelIndex& index) const override;
        void setModelData(
            QWidget* editor,
            QAbstractItemModel* model,
            const QModelIndex& index) const override;
        void updateEditorGeometry(
            QWidget* editor,
            const QStyleOptionViewItem& option,
            const QModelIndex& index) const override;
        bool editorEvent(
            QEvent* event,
            QAbstractItemModel* model,
            const QStyleOptionViewItem& option,
            const QModelIndex& index) override;
        bool helpEvent(
            QHelpEvent* event,
            QAbstractItemView* view,
            const QStyleOptionViewItem& option,
            const QModelIndex& index) override;

    private:
        // sourceDelegate: weak reference to the page's original delegate; actual ownership remains with the data view.
        QPointer<QAbstractItemDelegate> sourceDelegate_;

        // originalHeightProvider: Queries whether the current index belongs to an expanded row and retrieves its original row height.
        OriginalHeightProvider originalHeightProvider_;
    };
}
