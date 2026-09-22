#include "KernelSymbolicLinkTab.h"
#include "KernelDock.h"
#include "../ui/TableInteractionSupport.h"
#include "../ui/VisibleTableWidget.h"

// ============================================================
// KernelSymbolicLinkTab.cpp
// Purpose:
// 1) Build the symbolic link specific view.
// 2) Perform R3 SymbolicLink enumeration in the background while the main thread refreshes the table;
// 3) Provide filtering by object field/target path and copy operations.
// ============================================================

#include "../Theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMetaObject>
#include <QModelIndex>
#include <QPointer>
#include <QPushButton>
#include <QRunnable>
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QThreadPool>
#include <QVBoxLayout>

#include <algorithm>
#include <utility>

using ksword::kernel_dock_internal::kernelText;

namespace
{
    QString buttonStyle()
    {
        return ksword_theme::themedButtonStyle();
    }

    QString inputStyle()
    {
        return QStringLiteral(
            "QLineEdit{border:1px solid %1;border-radius:3px;background:transparent;color:%2;padding:3px 6px;}"
            "QLineEdit:focus{border:1px solid %3;}")
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::textPrimaryHex())
            .arg(ksword_theme::kPrimaryBlueHex);
    }
}

KernelSymbolicLinkTab::KernelSymbolicLinkTab(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
    initializeConnections();
}

void KernelSymbolicLinkTab::initializeUi()
{
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(6, 6, 6, 6);
    rootLayout->setSpacing(6);

    auto* toolLayout = new QHBoxLayout();
    toolLayout->setContentsMargins(0, 0, 0, 0);
    toolLayout->setSpacing(6);

    refreshButton_ = new QPushButton(this);
    refreshButton_->setText(kernelText("kernel.symbolic_link.toolbar.refresh", QStringLiteral("刷新")));
    // The parsing boundary for this page is merged into the refresh button tooltip; the page no longer reserves a line for a static description.
    refreshButton_->setToolTip(kernelText("kernel.symbolic_link.toolbar.refresh.tooltip", QStringLiteral("枚举常见对象目录中的 SymbolicLink。本页只解析目标，不递归展开；目标指向 Directory 时由「目录递归」页处理。")));
    refreshButton_->setStyleSheet(buttonStyle());

    copyTargetButton_ = new QPushButton(this);
    copyTargetButton_->setText(kernelText("kernel.symbolic_link.toolbar.copy_target", QStringLiteral("复制目标")));
    copyTargetButton_->setToolTip(kernelText("kernel.symbolic_link.toolbar.copy_target.tooltip", QStringLiteral("复制当前选中符号链接的 targetPath。")));
    copyTargetButton_->setStyleSheet(buttonStyle());

    filterEdit_ = new QLineEdit(this);
    filterEdit_->setPlaceholderText(kernelText("kernel.symbolic_link.toolbar.filter.placeholder", QStringLiteral("过滤目录 / 名称 / 完整路径 / 状态")));
    filterEdit_->setClearButtonEnabled(true);
    filterEdit_->setStyleSheet(inputStyle());

    targetFilterEdit_ = new QLineEdit(this);
    targetFilterEdit_->setPlaceholderText(kernelText("kernel.symbolic_link.toolbar.target_filter.placeholder", QStringLiteral("按目标路径 / DOS 候选过滤")));
    targetFilterEdit_->setClearButtonEnabled(true);
    targetFilterEdit_->setStyleSheet(inputStyle());

    statusLabel_ = new QLabel(kernelText("kernel.symbolic_link.status.waiting", QStringLiteral("状态：等待刷新")), this);
    statusLabel_->setStyleSheet(QStringLiteral("color:%1;font-weight:600;").arg(ksword_theme::textSecondaryHex()));

    toolLayout->addWidget(refreshButton_, 0);
    toolLayout->addWidget(copyTargetButton_, 0);
    toolLayout->addWidget(filterEdit_, 1);
    toolLayout->addWidget(targetFilterEdit_, 1);
    toolLayout->addWidget(statusLabel_, 0);
    rootLayout->addLayout(toolLayout);

    table_ = new ks::ui::VisibleTableWidget(this);
    table_->setColumnCount(static_cast<int>(Column::kCount));
    table_->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("sourceDirectory"),
        QStringLiteral("linkName"),
        QStringLiteral("fullPath"),
        QStringLiteral("targetPath"),
        QStringLiteral("dosCandidate"),
        QStringLiteral("statusText")
    });
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setAlternatingRowColors(true);
    table_->setContextMenuPolicy(Qt::CustomContextMenu);
    table_->horizontalHeader()->setSectionResizeMode(static_cast<int>(Column::kSourceDirectory), QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(static_cast<int>(Column::kLinkName), QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(static_cast<int>(Column::kFullPath), QHeaderView::Stretch);
    table_->horizontalHeader()->setSectionResizeMode(static_cast<int>(Column::kTargetPath), QHeaderView::Stretch);
    table_->horizontalHeader()->setSectionResizeMode(static_cast<int>(Column::kDosCandidate), QHeaderView::Stretch);
    table_->horizontalHeader()->setSectionResizeMode(static_cast<int>(Column::kStatusText), QHeaderView::ResizeToContents);
    rootLayout->addWidget(table_, 1);
}

void KernelSymbolicLinkTab::initializeConnections()
{
    connect(refreshButton_, &QPushButton::clicked, this, [this]() {
        refreshAsync();
    });
    connect(copyTargetButton_, &QPushButton::clicked, this, [this]() {
        copyCurrentTarget();
    });
    connect(filterEdit_, &QLineEdit::textChanged, this, [this]() {
        applyFilters();
    });
    connect(targetFilterEdit_, &QLineEdit::textChanged, this, [this]() {
        applyFilters();
    });
    connect(table_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& position) {
        showContextMenu(position);
    });
}

void KernelSymbolicLinkTab::refreshAsync()
{
    if (refreshing_)
    {
        return;
    }

    refreshing_ = true;
    refreshButton_->setEnabled(false);
    statusLabel_->setText(kernelText("kernel.symbolic_link.status.enumerating", QStringLiteral("状态：正在枚举 SymbolicLink...")));

    QPointer<KernelSymbolicLinkTab> guardThis(this);
    auto* task = QRunnable::create([guardThis]() {
        std::vector<KernelSymbolicLinkEntry> rows;
        QString errorText;
        const bool kOk = runKernelSymbolicLinkSnapshotTask(rows, errorText);

        QMetaObject::invokeMethod(qApp, [guardThis, rows = std::move(rows), errorText, kOk]() mutable {
            if (guardThis == nullptr)
            {
                return;
            }
            guardThis->applySnapshotResult(std::move(rows), errorText, kOk);
        }, Qt::QueuedConnection);
    });
    task->setAutoDelete(true);
    QThreadPool::globalInstance()->start(task);
}

void KernelSymbolicLinkTab::applySnapshotResult(
    std::vector<KernelSymbolicLinkEntry> rows,
    const QString& errorText,
    const bool ok)
{
    const QPointer<KernelSymbolicLinkTab> kSafeThis(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("kernel-symbolic-link-snapshot"),
        { table_ },
        [kSafeThis, rows, errorText, ok]() mutable
        {
            if (!kSafeThis.isNull())
            {
                kSafeThis->applySnapshotResult(std::move(rows), errorText, ok);
            }
        }))
    {
        return;
    }

    refreshing_ = false;
    refreshButton_->setEnabled(true);

    if (!ok)
    {
        allRows_.clear();
        visibleRows_.clear();
        rebuildTable();
        statusLabel_->setText(kernelText("kernel.symbolic_link.status.failed", QStringLiteral("状态：失败 | %1")).arg(errorText));
        return;
    }

    allRows_ = std::move(rows);
    applyFilters();
}

void KernelSymbolicLinkTab::applyFilters()
{
    const QString kKeywordText = filterEdit_ != nullptr ? filterEdit_->text().trimmed() : QString();
    const QString kTargetKeywordText = targetFilterEdit_ != nullptr ? targetFilterEdit_->text().trimmed() : QString();
    visibleRows_.clear();
    visibleRows_.reserve(allRows_.size());

    for (const KernelSymbolicLinkEntry& row : allRows_)
    {
        const QString kMergedText = QStringList{
            row.sourceDirectory,
            row.linkName,
            row.fullPath,
            row.statusText
        }.join(QStringLiteral(" | "));
        const QString kTargetMergedText = QStringList{
            row.targetPath,
            row.dosCandidate
        }.join(QStringLiteral(" | "));

        const bool kKeywordMatched = kKeywordText.isEmpty()
            || kMergedText.contains(kKeywordText, Qt::CaseInsensitive)
            || kTargetMergedText.contains(kKeywordText, Qt::CaseInsensitive);
        const bool kTargetMatched = kTargetKeywordText.isEmpty()
            || kTargetMergedText.contains(kTargetKeywordText, Qt::CaseInsensitive);
        if (kKeywordMatched && kTargetMatched)
        {
            visibleRows_.push_back(row);
        }
    }

    rebuildTable();
    statusLabel_->setText(
        kernelText("kernel.symbolic_link.status.summary", QStringLiteral("状态：显示 %1 / %2"))
        .arg(visibleRows_.size())
        .arg(allRows_.size()));
}

void KernelSymbolicLinkTab::rebuildTable()
{
    table_->setSortingEnabled(false);
    table_->clearContents();
    table_->setRowCount(static_cast<int>(visibleRows_.size()));

    for (int rowIndex = 0; rowIndex < static_cast<int>(visibleRows_.size()); ++rowIndex)
    {
        const KernelSymbolicLinkEntry& row = visibleRows_[static_cast<std::size_t>(rowIndex)];
        table_->setItem(rowIndex, static_cast<int>(Column::kSourceDirectory), createReadOnlyItem(row.sourceDirectory));
        table_->setItem(rowIndex, static_cast<int>(Column::kLinkName), createReadOnlyItem(row.linkName));
        table_->setItem(rowIndex, static_cast<int>(Column::kFullPath), createReadOnlyItem(row.fullPath));
        table_->setItem(rowIndex, static_cast<int>(Column::kTargetPath), createReadOnlyItem(row.targetPath));
        table_->setItem(rowIndex, static_cast<int>(Column::kDosCandidate), createReadOnlyItem(row.dosCandidate));
        table_->setItem(rowIndex, static_cast<int>(Column::kStatusText), createReadOnlyItem(row.statusText));
    }
}

void KernelSymbolicLinkTab::copyCurrentTarget() const
{
    if (table_ == nullptr || table_->currentRow() < 0)
    {
        return;
    }
    const int kRowIndex = table_->currentRow();
    if (kRowIndex >= static_cast<int>(visibleRows_.size()))
    {
        return;
    }
    QApplication::clipboard()->setText(visibleRows_[static_cast<std::size_t>(kRowIndex)].targetPath);
}

void KernelSymbolicLinkTab::copyCurrentRow() const
{
    if (table_ == nullptr || table_->currentRow() < 0)
    {
        return;
    }
    const int kRowIndex = table_->currentRow();
    if (kRowIndex >= static_cast<int>(visibleRows_.size()))
    {
        return;
    }
    QApplication::clipboard()->setText(rowToTsv(visibleRows_[static_cast<std::size_t>(kRowIndex)]));
}

void KernelSymbolicLinkTab::showContextMenu(const QPoint& position)
{
    const QModelIndex kIndex = table_->indexAt(position);
    if (!kIndex.isValid())
    {
        return;
    }
    table_->setCurrentCell(kIndex.row(), kIndex.column());

    QMenu menu(this);
    menu.setStyleSheet(ksword_theme::contextMenuStyle());
    QAction* copyCellAction = menu.addAction(kernelText("kernel.symbolic_link.menu.copy_cell", QStringLiteral("复制单元格")));
    QAction* copyTargetAction = menu.addAction(kernelText("kernel.symbolic_link.menu.copy_target", QStringLiteral("复制 targetPath")));
    QAction* copyDosAction = menu.addAction(kernelText("kernel.symbolic_link.menu.copy_dos_candidate", QStringLiteral("复制 dosCandidate")));
    QAction* copyRowAction = menu.addAction(kernelText("kernel.symbolic_link.menu.copy_row", QStringLiteral("复制整行")));
    QAction* filterTargetAction = menu.addAction(kernelText("kernel.symbolic_link.menu.filter_target", QStringLiteral("按此目标路径过滤")));

    const QAction* selectedAction = menu.exec(table_->viewport()->mapToGlobal(position));
    if (selectedAction == nullptr)
    {
        return;
    }

    const int kRowIndex = kIndex.row();
    if (kRowIndex < 0 || kRowIndex >= static_cast<int>(visibleRows_.size()))
    {
        return;
    }
    const KernelSymbolicLinkEntry& row = visibleRows_[static_cast<std::size_t>(kRowIndex)];

    if (selectedAction == copyCellAction)
    {
        QTableWidgetItem* item = table_->item(kIndex.row(), kIndex.column());
        QApplication::clipboard()->setText(item != nullptr ? item->text() : QString());
    }
    else if (selectedAction == copyTargetAction)
    {
        QApplication::clipboard()->setText(row.targetPath);
    }
    else if (selectedAction == copyDosAction)
    {
        QApplication::clipboard()->setText(row.dosCandidate);
    }
    else if (selectedAction == copyRowAction)
    {
        copyCurrentRow();
    }
    else if (selectedAction == filterTargetAction)
    {
        targetFilterEdit_->setText(row.targetPath);
    }
}

QTableWidgetItem* KernelSymbolicLinkTab::createReadOnlyItem(const QString& text)
{
    auto* item = new QTableWidgetItem(text);
    item->setFlags(item->flags() & ~Qt::ItemIsEditable);
    item->setToolTip(text);
    return item;
}

QString KernelSymbolicLinkTab::rowToTsv(const KernelSymbolicLinkEntry& row)
{
    return QStringList{
        row.sourceDirectory,
        row.linkName,
        row.fullPath,
        row.targetPath,
        row.dosCandidate,
        row.statusText
    }.join('\t');
}
