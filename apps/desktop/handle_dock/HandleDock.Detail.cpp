#include "HandleDock.h"
#include "../ui/TableInteractionSupport.h"
#include "../../../shared/platform/log/Log.h"
#include "../Theme.h"

// ============================================================
// HandleDock.Detail.cpp
// Purpose:
// - Handle asynchronous refresh of handle details and detail table population logic;
// - Manage the column menu for the handle table header;
// - Decouple from the main UI file to control single-file size.
// ============================================================

#include <QHeaderView>
#include <QLabel>
#include <QMenu>
#include <QMetaObject>
#include <QPointer>
#include <QRunnable>
#include <QThreadPool>
#include <QTreeWidget>
#include <QTreeWidgetItem>

#include <memory>

void HandleDock::requestHandleDetailRefresh(const bool forceRefresh)
{
    if (handleDetailRefreshInProgress_)
    {
        if (forceRefresh)
        {
            handleDetailRefreshPending_ = true;
        }
        return;
    }

    HandleRow* row = selectedHandleRow();
    if (row == nullptr)
    {
        showHandleDetailPlaceholder(QStringLiteral("请选择一个句柄查看详情。"));
        return;
    }

    const HandleRow kRowSnapshot = *row;
    const std::uint64_t kCurrentTicket = ++handleDetailRefreshTicket_;
    handleDetailRefreshInProgress_ = true;
    if (handleDetailStatusLabel_ != nullptr)
    {
        handleDetailStatusLabel_->setText(QStringLiteral("● 正在刷新句柄详情..."));
    }

    if (handleDetailRefreshProgressPid_ <= 0)
    {
        handleDetailRefreshProgressPid_ = kPro.addReusable(this, "句柄详情", "准备读取句柄详情");
    }
    kPro.set(handleDetailRefreshProgressPid_, "后台查询句柄详情", 0, 20.0f);

    QPointer<HandleDock> guardThis(this);
    auto* refreshTask = QRunnable::create([guardThis, kCurrentTicket, kRowSnapshot]()
        {
            const HandleDetailRefreshResult kRefreshResult =
                buildHandleDetailRefreshResult(kRowSnapshot);
            if (guardThis == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                guardThis,
                [guardThis, kCurrentTicket, kRefreshResult]()
                {
                    if (guardThis == nullptr)
                    {
                        return;
                    }
                    guardThis->applyHandleDetailRefreshResult(kCurrentTicket, kRefreshResult);
                },
                Qt::QueuedConnection);
        });
    refreshTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(refreshTask);
}

void HandleDock::applyHandleDetailRefreshResult(
    const std::uint64_t refreshTicket,
    const HandleDetailRefreshResult& refreshResult)
{
    if (refreshTicket < handleDetailRefreshTicket_)
    {
        return;
    }

    if (ks::ui::isItemViewUiCommitBlockedByContextMenu({ handleDetailTable_ }))
    {
        const auto kRefreshSnapshot = std::make_shared<HandleDetailRefreshResult>(refreshResult);
        const QPointer<HandleDock> kSafeThis(this);
        if (ks::ui::deferItemViewUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("handle-dock-detail-snapshot"),
            { handleDetailTable_ },
            [kSafeThis, refreshTicket, kRefreshSnapshot]()
            {
                if (!kSafeThis.isNull())
                {
                    kSafeThis->applyHandleDetailRefreshResult(refreshTicket, *kRefreshSnapshot);
                }
            }))
        {
            return;
        }
    }

    handleDetailRefreshInProgress_ = false;
    kPro.set(handleDetailRefreshProgressPid_, "句柄详情刷新完成", 0, 100.0f);

    if (handleDetailTable_ == nullptr)
    {
        return;
    }
    handleDetailTable_->clear();

    for (const HandleDetailField& field : refreshResult.fields)
    {
        auto* item = new QTreeWidgetItem();
        item->setText(0, field.keyText);
        item->setText(1, field.valueText);
        handleDetailTable_->addTopLevelItem(item);
    }

    QString statusText = QStringLiteral("● 详情刷新完成 %1 ms").arg(refreshResult.elapsedMs);
    if (!refreshResult.diagnosticText.trimmed().isEmpty())
    {
        statusText += QStringLiteral(" | 存在诊断；详情已写入日志。");
        KLogEvent diagnosticEvent;
        warn << diagnosticEvent
            << "[HandleDock] detail refresh completed with diagnostics, fieldCount="
            << refreshResult.fields.size()
            << ", detail=" << refreshResult.diagnosticText.toStdString()
            << eol;
    }
    if (handleDetailStatusLabel_ != nullptr)
    {
        handleDetailStatusLabel_->setText(statusText);
    }

    if (handleDetailRefreshPending_)
    {
        handleDetailRefreshPending_ = false;
        QMetaObject::invokeMethod(this, [this]()
            {
                requestHandleDetailRefresh(true);
            }, Qt::QueuedConnection);
    }
}

void HandleDock::showHandleHeaderContextMenu(const QPoint& localPosition)
{
    if (tableWidget_ == nullptr || tableWidget_->header() == nullptr)
    {
        return;
    }

    QHeaderView* header = tableWidget_->header();
    QMenu menu(this);
    // Explicitly fill the menu background to avoid a black background caused by inheriting a transparent style in light mode.
    menu.setStyleSheet(ksword_theme::contextMenuStyle());
    for (int columnIndex = 0; columnIndex < static_cast<int>(HandleTableColumn::kCount); ++columnIndex)
    {
        const QString kColumnTitle = tableWidget_->headerItem()->text(columnIndex);
        QAction* columnAction = menu.addAction(kColumnTitle);
        columnAction->setCheckable(true);
        columnAction->setChecked(!header->isSectionHidden(columnIndex));
        connect(columnAction, &QAction::toggled, this, [header, columnIndex](const bool checked)
            {
                header->setSectionHidden(columnIndex, !checked);
            });
    }
    menu.exec(header->viewport()->mapToGlobal(localPosition));
}

void HandleDock::showHandleDetailPlaceholder(const QString& messageText)
{
    if (handleDetailStatusLabel_ != nullptr)
    {
        handleDetailStatusLabel_->setText(messageText);
    }
    if (handleDetailTable_ == nullptr)
    {
        return;
    }
    handleDetailTable_->clear();
}
