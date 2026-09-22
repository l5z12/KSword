#include "KernelNamedPipeTab.h"
#include "KernelDock.h"
#include "../ui/TableInteractionSupport.h"

#include <memory>

// ============================================================
// KernelNamedPipeTab.cpp
// Purpose:
// 1) Display R3 Named Pipe NPFS directory enumeration results;
// 2) Support refresh, filtering, copying the current row, and viewing details;
// 3) This file is not responsible for attaching to KernelDock; project files and Tab registration are handled by the integration session.
// ============================================================

#include "../Theme.h"
#include "../ui/CodeEditorWidget.h"
#include "../ui/DetailLayoutRegistry.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QRunnable>
#include <QResizeEvent>
#include <QSize>
#include <QStringList>
#include <QThreadPool>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QVariant>
#include <QVBoxLayout>

#include <algorithm>

using ksword::kernel_dock_internal::kernelText;

namespace
{
    QString tableColumnText(const KernelNamedPipeEntry& row, const KernelNamedPipeTab::TableColumn column)
    {
        switch (column)
        {
        case KernelNamedPipeTab::TableColumn::kPipeName:
            return row.pipeName;
        case KernelNamedPipeTab::TableColumn::kNtPath:
            return row.ntPath;
        case KernelNamedPipeTab::TableColumn::kAttributes:
            return row.attributesText;
        case KernelNamedPipeTab::TableColumn::kLastWriteTime:
            return row.lastWriteTimeText;
        case KernelNamedPipeTab::TableColumn::kStatus:
            return row.statusText;
        case KernelNamedPipeTab::TableColumn::kSourceDirectory:
            return row.sourceDirectory;
        default:
            return QString();
        }
    }

    QString buildDirectoryStatusText(const KernelNamedPipeSnapshot& snapshot)
    {
        QStringList lines;
        lines << kernelText("kernel.named_pipe.detail.directory_status_heading", QStringLiteral("[路径候选状态]"));
        for (const KernelNamedPipeDirectoryStatus& status : snapshot.directories)
        {
            lines << QStringLiteral("- %1 | open=%2 | query=%3 | rows=%4 | status=%5")
                .arg(status.candidatePath)
                .arg(status.openSucceeded ? QStringLiteral("yes") : QStringLiteral("no"))
                .arg(status.querySucceeded ? QStringLiteral("yes") : QStringLiteral("no"))
                .arg(static_cast<qulonglong>(status.returnedRows))
                .arg(status.statusText);
        }
        return lines.join('\n');
    }

    QString buildSelectedRowDetailText(const KernelNamedPipeEntry* row)
    {
        if (row == nullptr)
        {
            return kernelText("kernel.named_pipe.detail.no_selection", QStringLiteral("[当前行]\n<未选择>"));
        }

        QStringList lines;
        lines << kernelText("kernel.named_pipe.detail.current_row_heading", QStringLiteral("[当前行]"));
        lines << QStringLiteral("Pipe Name: %1").arg(row->pipeName);
        lines << QStringLiteral("NT Path: %1").arg(row->ntPath);
        lines << QStringLiteral("Source Directory: %1").arg(row->sourceDirectory);
        lines << QStringLiteral("Query Succeeded: %1").arg(row->querySucceeded ? QStringLiteral("true") : QStringLiteral("false"));
        lines << QStringLiteral("Attributes: %1").arg(row->attributesText);
        lines << QStringLiteral("LastWriteTime: %1").arg(row->lastWriteTimeText);
        lines << QStringLiteral("LastWriteTimeRaw: %1").arg(static_cast<qlonglong>(row->lastWriteTime));
        lines << QStringLiteral("Status: %1").arg(row->statusText);
        return lines.join('\n');
    }
}

KernelNamedPipeTab::KernelNamedPipeTab(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
    initializeConnections();

    QMetaObject::invokeMethod(
        this,
        [this]()
        {
            requestRefresh(false);
        },
        Qt::QueuedConnection);
}

void KernelNamedPipeTab::initializeUi()
{
    rootLayout_ = new QVBoxLayout(this);
    rootLayout_->setContentsMargins(8, 8, 8, 8);
    rootLayout_->setSpacing(6);

    toolbarLayout_ = new QHBoxLayout();
    toolbarLayout_->setContentsMargins(0, 0, 0, 0);
    toolbarLayout_->setSpacing(6);

    refreshButton_ = new QPushButton(this);
    refreshButton_->setIcon(QIcon(":/Icon/handle_refresh.svg"));
    ksword_theme::applyCompactIconButtonMetrics(refreshButton_);
    refreshButton_->setToolTip(kernelText("kernel.named_pipe.toolbar.refresh.tooltip", QStringLiteral("刷新命名管道列表")));
    refreshButton_->setStyleSheet(ksword_theme::themedButtonStyle());

    copyButton_ = new QPushButton(this);
    copyButton_->setIcon(QIcon(":/Icon/handle_copy_row.svg"));
    ksword_theme::applyCompactIconButtonMetrics(copyButton_);
    copyButton_->setToolTip(kernelText("kernel.named_pipe.toolbar.copy.tooltip", QStringLiteral("复制当前行")));
    copyButton_->setStyleSheet(ksword_theme::themedButtonStyle());

    detailButton_ = new QPushButton(this);
    detailButton_->setIcon(QIcon(":/Icon/process_details.svg"));
    ksword_theme::applyCompactIconButtonMetrics(detailButton_);
    detailButton_->setToolTip(kernelText("kernel.named_pipe.toolbar.detail.tooltip", QStringLiteral("刷新详情面板")));
    detailButton_->setStyleSheet(ksword_theme::themedButtonStyle());

    filterEdit_ = new QLineEdit(this);
    filterEdit_->setPlaceholderText(kernelText("kernel.named_pipe.toolbar.filter.placeholder", QStringLiteral("过滤管道名、NT路径、状态")));
    filterEdit_->setClearButtonEnabled(true);

    statusLabel_ = new QLabel(kernelText("kernel.named_pipe.status.waiting", QStringLiteral("● 等待刷新")), this);
    statusLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    statusLabel_->setStyleSheet(QStringLiteral("color:%1;font-weight:600;").arg(ksword_theme::textSecondaryHex()));

    toolbarLayout_->addWidget(refreshButton_);
    toolbarLayout_->addWidget(copyButton_);
    toolbarLayout_->addWidget(detailButton_);
    toolbarLayout_->addWidget(filterEdit_, 1);
    rootLayout_->addLayout(toolbarLayout_);
    rootLayout_->addWidget(statusLabel_);

    resultTable_ = new QTreeWidget(this);
    resultTable_->setColumnCount(static_cast<int>(TableColumn::kCount));
    resultTable_->setHeaderLabels(QStringList{
        QStringLiteral("Pipe Name"),
        QStringLiteral("NT Path"),
        QStringLiteral("Attributes"),
        QStringLiteral("LastWriteTime"),
        QStringLiteral("Status"),
        QStringLiteral("Source")
        });
    resultTable_->setRootIsDecorated(false);
    resultTable_->setItemsExpandable(false);
    resultTable_->setAlternatingRowColors(true);
    resultTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    resultTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    resultTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    resultTable_->setSortingEnabled(true);
    resultTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    if (resultTable_->header() != nullptr)
    {
        resultTable_->header()->setSectionResizeMode(QHeaderView::Interactive);
        resultTable_->header()->setStretchLastSection(false);
    }

    // m_detailEdit uses the project's built-in CodeEditorWidget:
    // - Input: NPFS enumeration description, candidate path status, and current row details;
    // - Handling: display multi-line text in a read-only code/log view;
    // - Return: None. The control is released via Qt's parent-child relationship.
    detailEdit_ = new CodeEditorWidget(this);
    detailEdit_->setReadOnly(true);
    detailEdit_->setMinimumHeight(150);
    detailEdit_->setText(kernelText(
        "kernel.named_pipe.detail.intro",
        QStringLiteral(
            "说明：命名管道属于 NPFS 文件系统目录枚举，本页使用 NtOpenFile + NtQueryDirectoryFile 读取 \\Device\\NamedPipe。"
            "\n这不是 NtQueryDirectoryObject 下钻，也不是系统句柄表枚举。")));

    rootLayout_->addWidget(resultTable_, 1);
    rootLayout_->addWidget(detailEdit_, 0);

    ks::ui::DetailLayoutRegistry::registerHost(resultTable_, detailEdit_, this);
    applyAdaptiveColumnWidths();
}

void KernelNamedPipeTab::initializeConnections()
{
    connect(refreshButton_, &QPushButton::clicked, this, [this]()
        {
            requestRefresh(true);
        });
    connect(copyButton_, &QPushButton::clicked, this, [this]()
        {
            copyCurrentRow();
        });
    connect(detailButton_, &QPushButton::clicked, this, [this]()
        {
            updateDetailPanel();
        });
    connect(filterEdit_, &QLineEdit::textChanged, this, [this]()
        {
            applyFilter();
        });
    connect(resultTable_, &QTreeWidget::itemSelectionChanged, this, [this]()
        {
            updateDetailPanel();
        });
    connect(resultTable_, &QTreeWidget::customContextMenuRequested, this, [this](const QPoint& localPosition)
        {
            showContextMenu(localPosition);
        });
}

void KernelNamedPipeTab::requestRefresh(const bool forceRefresh)
{
    if (refreshInProgress_)
    {
        if (forceRefresh)
        {
            refreshPending_ = true;
        }
        return;
    }

    const std::uint64_t kCurrentTicket = ++refreshTicket_;
    refreshInProgress_ = true;
    refreshButton_->setEnabled(false);
    statusLabel_->setText(kernelText("kernel.named_pipe.status.enumerating", QStringLiteral("● 正在枚举 NPFS Named Pipe 目录...")));
    statusLabel_->setStyleSheet(QStringLiteral("color:%1;font-weight:700;").arg(ksword_theme::kPrimaryBlueHex));

    QPointer<KernelNamedPipeTab> guardThis(this);
    auto* refreshTask = QRunnable::create([guardThis, kCurrentTicket]()
        {
            const KernelNamedPipeSnapshot kSnapshot = runKernelNamedPipeSnapshotTask();
            if (guardThis == nullptr)
            {
                return;
            }

            QMetaObject::invokeMethod(
                guardThis,
                [guardThis, kCurrentTicket, kSnapshot]()
                {
                    if (guardThis == nullptr)
                    {
                        return;
                    }
                    guardThis->applySnapshot(kCurrentTicket, kSnapshot);
                },
                Qt::QueuedConnection);
        });
    refreshTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(refreshTask);
}

void KernelNamedPipeTab::applySnapshot(
    const std::uint64_t refreshTicket,
    const KernelNamedPipeSnapshot& snapshot)
{
    if (refreshTicket < refreshTicket_)
    {
        return;
    }

    const QPointer<KernelNamedPipeTab> kGuardThis(this);
    const auto kDeferredSnapshot =
        std::make_shared<KernelNamedPipeSnapshot>(snapshot);
    if (ks::ui::deferItemViewUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("kernel-named-pipe-snapshot-apply"),
        { resultTable_ },
        [kGuardThis, refreshTicket, kDeferredSnapshot]()
        {
            if (!kGuardThis.isNull())
            {
                kGuardThis->applySnapshot(refreshTicket, *kDeferredSnapshot);
            }
        }))
    {
        return;
    }

    lastSnapshot_ = snapshot;
    rows_ = snapshot.rows;
    rebuildTable();
    applyFilter();
    updateDetailPanel();

    refreshInProgress_ = false;
    refreshButton_->setEnabled(true);

    QString statusText = snapshot.taskSucceeded
        ? kernelText("kernel.named_pipe.status.completed", QStringLiteral("● 刷新完成 | %1")).arg(snapshot.summaryText)
        : kernelText("kernel.named_pipe.status.failed", QStringLiteral("● 刷新失败 | %1")).arg(snapshot.errorText);
    if (!snapshot.errorText.trimmed().isEmpty() && snapshot.taskSucceeded)
    {
        statusText += kernelText("kernel.named_pipe.status.additional_error", QStringLiteral(" | %1")).arg(snapshot.errorText);
    }
    statusLabel_->setText(statusText);
    statusLabel_->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;")
        .arg(snapshot.anyQuerySucceeded ? ksword_theme::successHex() : ksword_theme::warningHex()));

    if (refreshPending_)
    {
        refreshPending_ = false;
        QMetaObject::invokeMethod(
            this,
            [this]()
            {
                requestRefresh(true);
            },
            Qt::QueuedConnection);
    }
}

void KernelNamedPipeTab::rebuildTable()
{
    if (resultTable_ == nullptr)
    {
        return;
    }

    ks::ui::DetailLayoutRegistry::prepareDataRebuild(detailEdit_);

    resultTable_->setSortingEnabled(false);
    resultTable_->clear();

    for (std::size_t rowIndex = 0; rowIndex < rows_.size(); ++rowIndex)
    {
        const KernelNamedPipeEntry& row = rows_[rowIndex];
        auto* item = new QTreeWidgetItem();
        for (int column = 0; column < static_cast<int>(TableColumn::kCount); ++column)
        {
            item->setText(column, tableColumnText(row, static_cast<TableColumn>(column)));
        }
        item->setData(static_cast<int>(TableColumn::kPipeName), Qt::UserRole, static_cast<qulonglong>(rowIndex));
        resultTable_->addTopLevelItem(item);
    }

    if (resultTable_->topLevelItemCount() > 0)
    {
        resultTable_->setCurrentItem(resultTable_->topLevelItem(0));
    }

    applyAdaptiveColumnWidths();
    resultTable_->setSortingEnabled(true);
}

void KernelNamedPipeTab::applyFilter()
{
    if (resultTable_ == nullptr || filterEdit_ == nullptr)
    {
        return;
    }

    ks::ui::DetailLayoutRegistry::prepareDataRebuild(detailEdit_);

    const QString kFilterText = filterEdit_->text().trimmed().toCaseFolded();
    for (int rowIndex = 0; rowIndex < resultTable_->topLevelItemCount(); ++rowIndex)
    {
        QTreeWidgetItem* item = resultTable_->topLevelItem(rowIndex);
        if (item == nullptr)
        {
            continue;
        }

        bool matched = kFilterText.isEmpty();
        for (int column = 0; !matched && column < static_cast<int>(TableColumn::kCount); ++column)
        {
            matched = item->text(column).toCaseFolded().contains(kFilterText);
        }
        item->setHidden(!matched);
    }
}

void KernelNamedPipeTab::updateDetailPanel()
{
    if (detailEdit_ == nullptr)
    {
        return;
    }

    QStringList detailLines;
    detailLines << kernelText("kernel.named_pipe.detail.explanation_heading", QStringLiteral("[说明]"));
    detailLines << kernelText("kernel.named_pipe.detail.explanation.enumeration", QStringLiteral("命名管道属于 NPFS 文件系统目录枚举，本页使用 NtOpenFile + NtQueryDirectoryFile 读取 \\Device\\NamedPipe 或等价路径。"));
    detailLines << kernelText("kernel.named_pipe.detail.explanation.scope", QStringLiteral("这不是 NtQueryDirectoryObject 下钻，也不是系统句柄表枚举；因此不会列出持有管道句柄的进程。"));
    detailLines << QString();
    detailLines << buildDirectoryStatusText(lastSnapshot_);
    detailLines << QString();
    detailLines << buildSelectedRowDetailText(selectedRow());
    detailEdit_->setText(detailLines.join('\n'));
}

void KernelNamedPipeTab::copyCurrentRow()
{
    if (resultTable_ == nullptr || resultTable_->currentItem() == nullptr)
    {
        return;
    }

    QStringList fields;
    for (int column = 0; column < static_cast<int>(TableColumn::kCount); ++column)
    {
        fields.push_back(resultTable_->currentItem()->text(column));
    }
    QApplication::clipboard()->setText(fields.join('\t'));
}

void KernelNamedPipeTab::showContextMenu(const QPoint& localPosition)
{
    if (resultTable_ == nullptr)
    {
        return;
    }

    QTreeWidgetItem* clickedItem = resultTable_->itemAt(localPosition);
    if (clickedItem == nullptr)
    {
        return;
    }
    resultTable_->setCurrentItem(clickedItem);

    QMenu menu(this);
    menu.setStyleSheet(ksword_theme::contextMenuStyle());
    QAction* copyRowAction = menu.addAction(QIcon(":/Icon/handle_copy_row.svg"), kernelText("kernel.named_pipe.menu.copy_row", QStringLiteral("复制当前行")));
    QAction* detailAction = menu.addAction(QIcon(":/Icon/process_details.svg"), kernelText("kernel.named_pipe.menu.refresh_detail", QStringLiteral("刷新详情")));

    QAction* selectedAction = menu.exec(resultTable_->viewport()->mapToGlobal(localPosition));
    if (selectedAction == nullptr)
    {
        return;
    }
    if (selectedAction == copyRowAction)
    {
        copyCurrentRow();
        return;
    }
    if (selectedAction == detailAction)
    {
        updateDetailPanel();
    }
}

const KernelNamedPipeEntry* KernelNamedPipeTab::selectedRow() const
{
    if (resultTable_ == nullptr || resultTable_->currentItem() == nullptr)
    {
        return nullptr;
    }

    const QVariant kRowIndexValue =
        resultTable_->currentItem()->data(static_cast<int>(TableColumn::kPipeName), Qt::UserRole);
    if (!kRowIndexValue.isValid())
    {
        return nullptr;
    }

    const std::size_t kRowIndex = static_cast<std::size_t>(kRowIndexValue.toULongLong());
    if (kRowIndex >= rows_.size())
    {
        return nullptr;
    }
    return &rows_[kRowIndex];
}

void KernelNamedPipeTab::applyAdaptiveColumnWidths()
{
    if (resultTable_ == nullptr || resultTable_->header() == nullptr)
    {
        return;
    }

    QHeaderView* header = resultTable_->header();
    header->setSectionResizeMode(QHeaderView::Interactive);

    const int kViewportWidth = resultTable_->viewport()->width();
    if (kViewportWidth <= 0)
    {
        return;
    }

    const int kNameWidth = 220;
    const int kAttributesWidth = 180;
    const int kTimeWidth = 190;
    const int kStatusWidth = 220;
    const int kSourceWidth = 160;
    const int kPathWidth = std::max(320, kViewportWidth - kNameWidth - kAttributesWidth - kTimeWidth - kStatusWidth - kSourceWidth - 24);

    resultTable_->setColumnWidth(static_cast<int>(TableColumn::kPipeName), kNameWidth);
    resultTable_->setColumnWidth(static_cast<int>(TableColumn::kNtPath), kPathWidth);
    resultTable_->setColumnWidth(static_cast<int>(TableColumn::kAttributes), kAttributesWidth);
    resultTable_->setColumnWidth(static_cast<int>(TableColumn::kLastWriteTime), kTimeWidth);
    resultTable_->setColumnWidth(static_cast<int>(TableColumn::kStatus), kStatusWidth);
    resultTable_->setColumnWidth(static_cast<int>(TableColumn::kSourceDirectory), kSourceWidth);
}

void KernelNamedPipeTab::resizeEvent(QResizeEvent* event)
{
    QWidget::resizeEvent(event);
    applyAdaptiveColumnWidths();
}
