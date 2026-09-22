#include "EmbeddedRowDelegate.h"

#include <QAbstractItemModel>
#include <QAbstractItemView>
#include <QEvent>
#include <QHelpEvent>
#include <QPainter>

namespace ks::ui
{
    EmbeddedRowDelegate::EmbeddedRowDelegate(
        QAbstractItemDelegate* sourceDelegate,
        OriginalHeightProvider originalHeightProvider,
        QObject* parent)
        : QAbstractItemDelegate(parent),
          sourceDelegate_(sourceDelegate),
          originalHeightProvider_(std::move(originalHeightProvider))
    {
        // Wrapper reuses the original delegate's editor signals to ensure page behaviors like double-click editing remain unchanged.
        if (sourceDelegate_ != nullptr)
        {
            connect(
                sourceDelegate_.data(),
                &QAbstractItemDelegate::closeEditor,
                this,
                &QAbstractItemDelegate::closeEditor);
            connect(
                sourceDelegate_.data(),
                &QAbstractItemDelegate::commitData,
                this,
                &QAbstractItemDelegate::commitData);
            connect(
                sourceDelegate_.data(),
                &QAbstractItemDelegate::sizeHintChanged,
                this,
                &QAbstractItemDelegate::sizeHintChanged);
        }
    }

    void EmbeddedRowDelegate::paint(
        QPainter* painter,
        const QStyleOptionViewItem& option,
        const QModelIndex& index) const
    {
        // Do not paint when sourceDelegate is invalid to avoid accessing a destroyed page delegate.
        if (painter == nullptr || sourceDelegate_.isNull())
        {
            return;
        }

        // For non-unfolded source rows, fully reuse the original delegate to ensure visual and interaction consistency for standard pages.
        const int kOriginalHeight = originalHeightProvider_
            ? originalHeightProvider_(index)
            : -1;
        if (kOriginalHeight <= 0)
        {
            sourceDelegate_->paint(painter, option, index);
            return;
        }

        // The itemRect for an expanded row still includes the detail area; source content must be constrained to the original row height.
        QStyleOptionViewItem clippedOption(option);
        clippedOption.rect.setHeight(qMin(kOriginalHeight, option.rect.height()));
        if (clippedOption.rect.height() <= 0)
        {
            return;
        }

        // Only clip the source delegate's paint calls; the detail editor's lower area is still covered by DetailLayoutHost.
        painter->save();
        painter->setClipRect(clippedOption.rect, Qt::IntersectClip);
        sourceDelegate_->paint(painter, clippedOption, index);
        painter->restore();
    }

    QSize EmbeddedRowDelegate::sizeHint(
        const QStyleOptionViewItem& option,
        const QModelIndex& index) const
    {
        // Size calculation is forwarded directly; expanded row height is controlled by the original QTableWidget/QTreeWidget interfaces.
        return sourceDelegate_.isNull()
            ? QSize()
            : sourceDelegate_->sizeHint(option, index);
    }

    QWidget* EmbeddedRowDelegate::createEditor(
        QWidget* parent,
        const QStyleOptionViewItem& option,
        const QModelIndex& index) const
    {
        return sourceDelegate_.isNull()
            ? nullptr
            : sourceDelegate_->createEditor(parent, option, index);
    }

    void EmbeddedRowDelegate::destroyEditor(QWidget* editor, const QModelIndex& index) const
    {
        if (!sourceDelegate_.isNull())
        {
            sourceDelegate_->destroyEditor(editor, index);
        }
    }

    void EmbeddedRowDelegate::setEditorData(QWidget* editor, const QModelIndex& index) const
    {
        if (!sourceDelegate_.isNull())
        {
            sourceDelegate_->setEditorData(editor, index);
        }
    }

    void EmbeddedRowDelegate::setModelData(
        QWidget* editor,
        QAbstractItemModel* model,
        const QModelIndex& index) const
    {
        if (!sourceDelegate_.isNull())
        {
            sourceDelegate_->setModelData(editor, model, index);
        }
    }

    void EmbeddedRowDelegate::updateEditorGeometry(
        QWidget* editor,
        const QStyleOptionViewItem& option,
        const QModelIndex& index) const
    {
        if (!sourceDelegate_.isNull())
        {
            sourceDelegate_->updateEditorGeometry(editor, option, index);
        }
    }

    bool EmbeddedRowDelegate::editorEvent(
        QEvent* event,
        QAbstractItemModel* model,
        const QStyleOptionViewItem& option,
        const QModelIndex& index)
    {
        // Pass the event area to the original delegate to avoid altering interactions like checkboxes after reusing the delegate.
        return !sourceDelegate_.isNull()
            && sourceDelegate_->editorEvent(event, model, option, index);
    }

    bool EmbeddedRowDelegate::helpEvent(
        QHelpEvent* event,
        QAbstractItemView* view,
        const QStyleOptionViewItem& option,
        const QModelIndex& index)
    {
        // Tooltips must remain consistent with the original delegate; inline mode affects only the drawing geometry.
        return !sourceDelegate_.isNull()
            && sourceDelegate_->helpEvent(event, view, option, index);
    }
}
