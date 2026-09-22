#include "KernelCommunicationEndpointTab.h"
#include "KernelDock.h"
#include "../ui/TableInteractionSupport.h"
#include "../ui/VisibleTableWidget.h"

// ============================================================
// KernelCommunicationEndpointTab.cpp
// Purpose:
// 1) Aggregates communication endpoint objects under the root ALPC/Port and \RPC Control directories.
// 2) Use Object Manager directory enumeration results for read-only display.
// 3) The page does not enumerate any process handles and does not call the KswordARK driver.
// ============================================================

#include "../Theme.h"

#include <QAbstractItemView>
#include <QApplication>
#include <QClipboard>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMetaObject>
#include <QModelIndex>
#include <QPointer>
#include <QPushButton>
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

#include <algorithm>
#include <thread>
#include <utility>

using ksword::kernel_dock_internal::kernelText;

namespace
{
    enum class CommunicationEndpointColumn : int
    {
        kSource = 0,
        kName,
        kType,
        kFullPath,
        kStatus,
        kCount
    };

    QString statusLabelStyle(const QString& colorHex)
    {
        return QStringLiteral("color:%1;font-weight:600;").arg(colorHex);
    }

    KernelObjectDirectoryDeepResult queryEndpointRoot(const QString& rootPath)
    {
        KernelObjectDirectoryDeepOptions options;
        options.rootPath = rootPath;
        options.maxDepth = 0;
        options.maxEntriesPerDirectory = 8192;
        options.maxTotalEntries = 8192;
        return runKernelObjectDirectoryDeepSnapshotTask(options);
    }
}

KernelCommunicationEndpointTab::KernelCommunicationEndpointTab(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
    initializeConnections();

    QMetaObject::invokeMethod(this, [this]() {
        refreshAsync();
    }, Qt::QueuedConnection);
}

void KernelCommunicationEndpointTab::initializeUi()
{
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(8, 8, 8, 8);
    rootLayout->setSpacing(6);

    auto* toolbarLayout = new QHBoxLayout();
    toolbarLayout->setContentsMargins(0, 0, 0, 0);
    toolbarLayout->setSpacing(6);

    refreshButton_ = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), this);
    ksword_theme::applyCompactIconButtonMetrics(refreshButton_);
    refreshButton_->setToolTip(kernelText("kernel.communication_endpoint.toolbar.refresh.tooltip", QStringLiteral("刷新通信端点对象")));
    refreshButton_->setStyleSheet(ksword_theme::themedButtonStyle());

    filterEdit_ = new QLineEdit(this);
    filterEdit_->setPlaceholderText(kernelText("kernel.communication_endpoint.toolbar.filter.placeholder", QStringLiteral("按名称、类型、路径筛选")));
    filterEdit_->setClearButtonEnabled(true);

    statusLabel_ = new QLabel(kernelText("kernel.communication_endpoint.status.waiting", QStringLiteral("状态：等待刷新")), this);
    statusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::textSecondaryHex()));

    toolbarLayout->addWidget(refreshButton_, 0);
    toolbarLayout->addWidget(filterEdit_, 1);
    toolbarLayout->addWidget(statusLabel_, 0);
    rootLayout->addLayout(toolbarLayout);

    table_ = new ks::ui::VisibleTableWidget(this);
    table_->setColumnCount(static_cast<int>(CommunicationEndpointColumn::kCount));
    table_->setHorizontalHeaderLabels(QStringList{
        kernelText("kernel.communication_endpoint.header.source", QStringLiteral("来源目录")),
        kernelText("kernel.communication_endpoint.header.name", QStringLiteral("名称")),
        kernelText("kernel.communication_endpoint.header.type", QStringLiteral("类型")),
        kernelText("kernel.communication_endpoint.header.full_path", QStringLiteral("完整路径")),
        kernelText("kernel.communication_endpoint.header.status", QStringLiteral("状态"))
        });
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setAlternatingRowColors(true);
    table_->setContextMenuPolicy(Qt::CustomContextMenu);
    table_->verticalHeader()->setVisible(false);
    table_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(static_cast<int>(CommunicationEndpointColumn::kFullPath), QHeaderView::Stretch);
    rootLayout->addWidget(table_, 1);
}

void KernelCommunicationEndpointTab::initializeConnections()
{
    connect(refreshButton_, &QPushButton::clicked, this, [this]() {
        refreshAsync();
    });
    connect(filterEdit_, &QLineEdit::textChanged, this, [this]() {
        rebuildTable();
    });
    connect(table_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& localPosition) {
        showContextMenu(localPosition);
    });
}

void KernelCommunicationEndpointTab::refreshAsync()
{
    if (refreshing_.exchange(true))
    {
        return;
    }

    refreshButton_->setEnabled(false);
    statusLabel_->setText(kernelText("kernel.communication_endpoint.status.refreshing", QStringLiteral("状态：刷新中...")));
    statusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::kPrimaryBlueHex));

    QPointer<KernelCommunicationEndpointTab> guardThis(this);
    std::thread([guardThis]() {
        QString errorText;
        std::vector<KernelObjectDirectoryDeepEntry> rows;

        const KernelObjectDirectoryDeepResult kRootResult = queryEndpointRoot(QStringLiteral("\\"));
        const KernelObjectDirectoryDeepResult kRpcResult = queryEndpointRoot(QStringLiteral("\\RPC Control"));
        const bool kSuccess = kRootResult.success || kRpcResult.success;

        if (!kRootResult.success)
        {
            errorText += kernelText("kernel.communication_endpoint.error.root_failed", QStringLiteral("\\ 枚举失败：%1\n")).arg(kRootResult.errorText);
        }
        if (!kRpcResult.success)
        {
            errorText += kernelText("kernel.communication_endpoint.error.rpc_failed", QStringLiteral("\\RPC Control 枚举失败：%1\n")).arg(kRpcResult.errorText);
        }

        for (const KernelObjectDirectoryDeepEntry& row : kRootResult.rows)
        {
            if (isCommunicationEndpoint(row))
            {
                rows.push_back(row);
            }
        }
        for (const KernelObjectDirectoryDeepEntry& row : kRpcResult.rows)
        {
            if (row.querySucceeded)
            {
                rows.push_back(row);
            }
        }

        std::sort(rows.begin(), rows.end(), [](const KernelObjectDirectoryDeepEntry& left, const KernelObjectDirectoryDeepEntry& right) {
            const int kSourceCompare = QString::compare(left.directoryPath, right.directoryPath, Qt::CaseInsensitive);
            if (kSourceCompare != 0)
            {
                return kSourceCompare < 0;
            }
            return QString::compare(left.objectName, right.objectName, Qt::CaseInsensitive) < 0;
        });

        KernelCommunicationEndpointTab* const kContextObject = guardThis.data();
        if (kContextObject == nullptr)
        {
            return;
        }

        QMetaObject::invokeMethod(kContextObject, [guardThis, rows = std::move(rows), errorText, kSuccess]() mutable {
            if (guardThis == nullptr)
            {
                return;
            }
            guardThis->applyRefreshResult(std::move(rows), errorText.trimmed(), kSuccess);
        }, Qt::QueuedConnection);
    }).detach();
}

void KernelCommunicationEndpointTab::applyRefreshResult(
    std::vector<KernelObjectDirectoryDeepEntry> rows,
    const QString& errorText,
    const bool success)
{
    const QPointer<KernelCommunicationEndpointTab> kSafeThis(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("kernel-communication-endpoint-snapshot"),
        { table_ },
        [kSafeThis, rows, errorText, success]() mutable
        {
            if (!kSafeThis.isNull())
            {
                kSafeThis->applyRefreshResult(std::move(rows), errorText, success);
            }
        }))
    {
        return;
    }

    refreshing_.store(false);
    refreshButton_->setEnabled(true);
    rows_ = std::move(rows);
    rebuildTable();

    if (!success)
    {
        statusLabel_->setText(kernelText("kernel.communication_endpoint.status.failed", QStringLiteral("状态：刷新失败 - %1")).arg(errorText));
        statusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::errorHex()));
        insertDiagnosticRow(
            kernelText("kernel.communication_endpoint.placeholder.refresh_failed", QStringLiteral("<刷新失败>")),
            buildDiagnosticText(kernelText("kernel.communication_endpoint.diagnostic.refresh_failed", QStringLiteral("通信对象枚举失败：%1")).arg(errorText)));
    }
}

void KernelCommunicationEndpointTab::rebuildTable()
{
    if (table_ == nullptr)
    {
        return;
    }

    table_->setSortingEnabled(false);
    table_->setRowCount(0);

    std::size_t visibleCount = 0;
    for (const KernelObjectDirectoryDeepEntry& entry : rows_)
    {
        if (!rowMatchesFilter(entry))
        {
            continue;
        }

        const int kRowIndex = table_->rowCount();
        table_->insertRow(kRowIndex);
        table_->setItem(kRowIndex, static_cast<int>(CommunicationEndpointColumn::kSource), readOnlyItem(entry.directoryPath));
        table_->setItem(kRowIndex, static_cast<int>(CommunicationEndpointColumn::kName), readOnlyItem(entry.objectName));
        table_->setItem(kRowIndex, static_cast<int>(CommunicationEndpointColumn::kType), readOnlyItem(entry.objectType));
        table_->setItem(kRowIndex, static_cast<int>(CommunicationEndpointColumn::kFullPath), readOnlyItem(entry.fullPath));
        table_->setItem(kRowIndex, static_cast<int>(CommunicationEndpointColumn::kStatus), readOnlyItem(entry.statusText));
        ++visibleCount;
    }

    table_->setSortingEnabled(true);
    statusLabel_->setText(kernelText("kernel.communication_endpoint.status.summary", QStringLiteral("状态：已加载 %1 项，显示 %2 项"))
        .arg(static_cast<qulonglong>(rows_.size()))
        .arg(static_cast<qulonglong>(visibleCount)));
    statusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::successHex()));

    if (visibleCount == 0U)
    {
        // Diagnostic for empty communication endpoint results:
        // - Input: Source data count and current filter.
        // - Processing: Insert a copyable diagnostic row to avoid the new page appearing empty.
        // - Returns: No return value; updates the table only.
        const QString kReasonText = rows_.empty()
            ? kernelText("kernel.communication_endpoint.diagnostic.no_records", QStringLiteral("\\ 和 \\RPC Control 未返回可显示通信端点。"))
            : kernelText("kernel.communication_endpoint.diagnostic.filter_empty", QStringLiteral("当前筛选条件没有命中通信端点。"));
        insertDiagnosticRow(
            rows_.empty()
                ? kernelText("kernel.communication_endpoint.placeholder.no_records", QStringLiteral("<无通信对象>"))
                : kernelText("kernel.communication_endpoint.placeholder.filter_empty", QStringLiteral("<筛选无结果>")),
            buildDiagnosticText(kReasonText));
        table_->setCurrentCell(0, static_cast<int>(CommunicationEndpointColumn::kName));
    }
}

void KernelCommunicationEndpointTab::showContextMenu(const QPoint& localPosition)
{
    if (table_ == nullptr)
    {
        return;
    }

    const QModelIndex kClickedIndex = table_->indexAt(localPosition);
    if (kClickedIndex.isValid())
    {
        table_->setCurrentCell(kClickedIndex.row(), kClickedIndex.column());
    }

    QMenu menu(this);
    menu.setStyleSheet(ksword_theme::contextMenuStyle());
    QAction* copyRowAction = menu.addAction(kernelText("kernel.communication_endpoint.menu.copy_row", QStringLiteral("复制当前行")));
    copyRowAction->setEnabled(table_->currentRow() >= 0);
    const QAction* selectedAction = menu.exec(table_->viewport()->mapToGlobal(localPosition));
    if (selectedAction == copyRowAction)
    {
        copyCurrentRow();
    }
}

void KernelCommunicationEndpointTab::copyCurrentRow() const
{
    if (table_ == nullptr || QApplication::clipboard() == nullptr)
    {
        return;
    }

    const int kRowIndex = table_->currentRow();
    if (kRowIndex < 0)
    {
        return;
    }

    QStringList fields;
    for (int columnIndex = 0; columnIndex < table_->columnCount(); ++columnIndex)
    {
        const QTableWidgetItem* item = table_->item(kRowIndex, columnIndex);
        fields.push_back(item != nullptr ? item->text() : QString());
    }
    QApplication::clipboard()->setText(fields.join('\t'));
}

QString KernelCommunicationEndpointTab::buildDiagnosticText(const QString& reasonText) const
{
    // buildDiagnosticText：
    // - Input: empty table or failure reason;
    // - Processing: Supplement current filters, data sources, and troubleshooting suggestions.
    // - Returns: Diagnostic explanation suitable for table status columns and copied text.
    QStringList lines;
    lines << kernelText("kernel.communication_endpoint.diagnostic.reason", QStringLiteral("原因：%1")).arg(reasonText.trimmed().isEmpty()
        ? kernelText("kernel.communication_endpoint.placeholder.not_provided", QStringLiteral("<未提供>"))
        : reasonText.trimmed());
    lines << kernelText("kernel.communication_endpoint.diagnostic.current_filter", QStringLiteral("当前筛选：%1")).arg(filterEdit_ != nullptr && !filterEdit_->text().trimmed().isEmpty()
        ? filterEdit_->text().trimmed()
        : kernelText("kernel.communication_endpoint.placeholder.no_filter", QStringLiteral("<无筛选>")));
    lines << kernelText("kernel.communication_endpoint.diagnostic.source_count", QStringLiteral("源记录总数：%1")).arg(static_cast<qulonglong>(rows_.size()));
    lines << kernelText("kernel.communication_endpoint.diagnostic.source", QStringLiteral("数据来源：Object Manager 目录枚举根目录与 \\RPC Control，只读聚合 ALPC/Port/RPC 相关对象。"));
    lines << kernelText("kernel.communication_endpoint.diagnostic.next_step", QStringLiteral("建议：清空筛选，或切换到 Object Directory Deep / ALPC 页查看更具体的目录与端口关系。"));
    return lines.join(QStringLiteral(" | "));
}

void KernelCommunicationEndpointTab::insertDiagnosticRow(const QString& titleText, const QString& detailText)
{
    // insertDiagnosticRow：
    // - Input: title and diagnostic text;
    // - Processing: Write a single read-only placeholder row to ensure right-click copy retrieves diagnostic data.
    // - Returns: Nothing.
    if (table_ == nullptr)
    {
        return;
    }

    table_->setSortingEnabled(false);
    table_->setRowCount(1);
    table_->setItem(0, static_cast<int>(CommunicationEndpointColumn::kSource), readOnlyItem(kernelText("kernel.communication_endpoint.placeholder.diagnostic", QStringLiteral("<诊断>"))));
    table_->setItem(0, static_cast<int>(CommunicationEndpointColumn::kName), readOnlyItem(titleText));
    table_->setItem(0, static_cast<int>(CommunicationEndpointColumn::kType), readOnlyItem(QStringLiteral("Diagnostic")));
    table_->setItem(0, static_cast<int>(CommunicationEndpointColumn::kFullPath), readOnlyItem(kernelText("kernel.communication_endpoint.placeholder.no_path", QStringLiteral("<无路径>"))));
    table_->setItem(0, static_cast<int>(CommunicationEndpointColumn::kStatus), readOnlyItem(detailText));
    table_->setSortingEnabled(true);
    table_->setCurrentCell(0, static_cast<int>(CommunicationEndpointColumn::kName));
}

bool KernelCommunicationEndpointTab::rowMatchesFilter(const KernelObjectDirectoryDeepEntry& entry) const
{
    const QString kKeyword = filterEdit_ != nullptr ? filterEdit_->text().trimmed() : QString();
    if (kKeyword.isEmpty())
    {
        return true;
    }

    return entry.directoryPath.contains(kKeyword, Qt::CaseInsensitive)
        || entry.objectName.contains(kKeyword, Qt::CaseInsensitive)
        || entry.objectType.contains(kKeyword, Qt::CaseInsensitive)
        || entry.fullPath.contains(kKeyword, Qt::CaseInsensitive)
        || entry.statusText.contains(kKeyword, Qt::CaseInsensitive);
}

bool KernelCommunicationEndpointTab::isCommunicationEndpoint(const KernelObjectDirectoryDeepEntry& entry)
{
    return entry.objectType.compare(QStringLiteral("ALPC Port"), Qt::CaseInsensitive) == 0
        || entry.objectType.compare(QStringLiteral("Port"), Qt::CaseInsensitive) == 0
        || entry.objectType.contains(QStringLiteral("Port"), Qt::CaseInsensitive);
}

QTableWidgetItem* KernelCommunicationEndpointTab::readOnlyItem(const QString& text)
{
    auto* item = new QTableWidgetItem(text);
    item->setFlags(item->flags() & ~Qt::ItemIsEditable);
    return item;
}
