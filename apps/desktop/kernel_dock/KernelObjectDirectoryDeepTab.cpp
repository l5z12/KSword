
#include "KernelObjectDirectoryDeepTab.h"
#include "KernelDock.h"
#include "../ui/TableInteractionSupport.h"

#include <memory>

// ============================================================
// KernelObjectDirectoryDeepTab.cpp
// Purpose:
// 1) Provide an independent QWidget with directory recursion capabilities;
// 2) Invoke KernelObjectDirectoryDeepWorker in the background;
// 3) Display results in tree and detail panels.
// ============================================================

#include "../ui/CodeEditorWidget.h"
#include "../ui/DetailLayoutRegistry.h"
#include "../Theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QMap>
#include <QMenu>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QSpinBox>
#include <QSplitter>
#include <QStringList>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QVBoxLayout>

#include <algorithm>
#include <limits>
#include <thread>

using ksword::kernel_dock_internal::kernelText;

namespace
{
    enum class DirectoryDeepColumn : int
    {
        kName = 0,
        kType,
        kFullPath,
        kDepth,
        kStatus,
        kCount
    };

    constexpr int kSourceIndexRole = Qt::UserRole + 1;
    constexpr qulonglong kInvalidSourceIndex = std::numeric_limits<qulonglong>::max();

    QString normalizeObjectPathForUi(const QString& rawPath)
    {
        // Input: user input or object path returned by Worker.
        // Processing: Compress slashes and ensure the path starts with '\', unifying tree node keys.
        // Returns: normalized path; empty input returns "\".
        QString path = rawPath.trimmed();
        path.replace('/', '\\');
        while (path.contains(QStringLiteral("\\\\")))
        {
            path.replace(QStringLiteral("\\\\"), QStringLiteral("\\"));
        }
        if (path.isEmpty())
        {
            return QStringLiteral("\\");
        }
        if (!path.startsWith('\\'))
        {
            path.prepend('\\');
        }
        while (path.size() > 1 && path.endsWith('\\'))
        {
            path.chop(1);
        }
        return path;
    }

    QString leafNameFromObjectPathForUi(const QString& objectPath)
    {
        // Input: Full object path.
        // Handling: Extract last segment name; root path returns "\".
        // Returns: Tree node name.
        const QString kNormalizedPath = normalizeObjectPathForUi(objectPath);
        if (kNormalizedPath == QStringLiteral("\\"))
        {
            return QStringLiteral("\\");
        }
        const int kSlashIndex = kNormalizedPath.lastIndexOf('\\');
        return kSlashIndex >= 0 ? kNormalizedPath.mid(kSlashIndex + 1) : kNormalizedPath;
    }

    QString parentPathFromObjectPathForUi(const QString& objectPath)
    {
        // Input: Full object path.
        // Handling: retrieve the parent path; the parent path for a top-level object is "\".
        // Returns: Parent directory path.
        const QString kNormalizedPath = normalizeObjectPathForUi(objectPath);
        if (kNormalizedPath == QStringLiteral("\\"))
        {
            return QStringLiteral("\\");
        }
        const int kSlashIndex = kNormalizedPath.lastIndexOf('\\');
        if (kSlashIndex <= 0)
        {
            return QStringLiteral("\\");
        }
        return kNormalizedPath.left(kSlashIndex);
    }

    QString statusLabelStyle(const QString& colorHex)
    {
        // Input: color hex string.
        // Return: Status label style string.
        return QStringLiteral("color:%1;font-weight:600;").arg(colorHex);
    }

    QTreeWidgetItem* ensurePathItem(
        QTreeWidget* treeWidget,
        QMap<QString, QTreeWidgetItem*>& itemByPath,
        const QString& objectPath)
    {
        // Input: Tree control, cache for path to node, and object path to ensure exists.
        // Processing: Recursively ensure parent node exists, then create the current path node.
        // Returns: the tree node corresponding to the path; returns nullptr if treeWidget is null.
        if (treeWidget == nullptr)
        {
            return nullptr;
        }

        const QString kNormalizedPath = normalizeObjectPathForUi(objectPath);
        QTreeWidgetItem* existingItem = itemByPath.value(kNormalizedPath, nullptr);
        if (existingItem != nullptr)
        {
            return existingItem;
        }

        QTreeWidgetItem* newItem = nullptr;
        if (kNormalizedPath == QStringLiteral("\\"))
        {
            newItem = new QTreeWidgetItem(treeWidget);
            newItem->setText(static_cast<int>(DirectoryDeepColumn::kName), QStringLiteral("\\"));
            newItem->setText(static_cast<int>(DirectoryDeepColumn::kType), QStringLiteral("Directory"));
            newItem->setText(static_cast<int>(DirectoryDeepColumn::kFullPath), QStringLiteral("\\"));
            newItem->setText(static_cast<int>(DirectoryDeepColumn::kDepth), QStringLiteral("0"));
            newItem->setText(static_cast<int>(DirectoryDeepColumn::kStatus), kernelText("kernel.object_directory.tree.root_status", QStringLiteral("根目录")));
        }
        else
        {
            QTreeWidgetItem* parentItem = ensurePathItem(
                treeWidget,
                itemByPath,
                parentPathFromObjectPathForUi(kNormalizedPath));
            newItem = new QTreeWidgetItem(parentItem != nullptr ? parentItem : treeWidget->invisibleRootItem());
            newItem->setText(static_cast<int>(DirectoryDeepColumn::kName), leafNameFromObjectPathForUi(kNormalizedPath));
            newItem->setText(static_cast<int>(DirectoryDeepColumn::kType), QStringLiteral("Directory"));
            newItem->setText(static_cast<int>(DirectoryDeepColumn::kFullPath), kNormalizedPath);
            newItem->setText(static_cast<int>(DirectoryDeepColumn::kDepth), QStringLiteral("-"));
            newItem->setText(static_cast<int>(DirectoryDeepColumn::kStatus), kernelText("kernel.object_directory.tree.parent_placeholder", QStringLiteral("父目录占位")));
        }
        newItem->setData(0, kSourceIndexRole, kInvalidSourceIndex);
        itemByPath.insert(kNormalizedPath, newItem);
        return newItem;
    }

    QString treeItemAsTsv(const QTreeWidget* treeWidget, const QTreeWidgetItem* treeItem)
    {
        // Input: Directory recursive result tree and current node.
        // Processing: Read text in current column order, tab-separated, for easy copying to spreadsheet tools.
        // Returns: TSV text; returns an empty string if the input is null.
        if (treeWidget == nullptr || treeItem == nullptr)
        {
            return QString();
        }

        QStringList fieldList;
        fieldList.reserve(treeWidget->columnCount());
        for (int columnIndex = 0; columnIndex < treeWidget->columnCount(); ++columnIndex)
        {
            const QString kCellText = treeItem->text(columnIndex).trimmed();
            fieldList.push_back(kCellText.isEmpty() ? kernelText("kernel.object_directory.placeholder.empty", QStringLiteral("<空>")) : kCellText);
        }
        return fieldList.join('\t');
    }

    void showTreeCopyRowMenu(QTreeWidget* treeWidget, const QPoint& localPosition)
    {
        // Input: Result tree and right-click position.
        // Processing: Synchronize the clicked node as the current node, display the explicit style menu, and copy the current row.
        // Return: None; silently returns if there are no nodes or the clipboard is unavailable.
        if (treeWidget == nullptr)
        {
            return;
        }

        QTreeWidgetItem* clickedItem = treeWidget->itemAt(localPosition);
        if (clickedItem != nullptr)
        {
            const int kClickedColumn = treeWidget->columnAt(localPosition.x());
            treeWidget->setCurrentItem(clickedItem, kClickedColumn >= 0 ? kClickedColumn : 0);
        }

        QTreeWidgetItem* currentItem = treeWidget->currentItem();
        QMenu contextMenu(treeWidget);
        contextMenu.setStyleSheet(ksword_theme::contextMenuStyle());

        QAction* copyRowAction = contextMenu.addAction(
            QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
            kernelText("kernel.object_directory.menu.copy_row", QStringLiteral("复制当前行")));
        copyRowAction->setEnabled(currentItem != nullptr);

        const QAction* selectedAction = contextMenu.exec(treeWidget->viewport()->mapToGlobal(localPosition));
        if (selectedAction != copyRowAction || currentItem == nullptr)
        {
            return;
        }

        QClipboard* clipboard = QApplication::clipboard();
        const QString kRowText = treeItemAsTsv(treeWidget, currentItem);
        if (clipboard != nullptr && !kRowText.isEmpty())
        {
            clipboard->setText(kRowText);
        }
    }
}

KernelObjectDirectoryDeepTab::KernelObjectDirectoryDeepTab(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
}

void KernelObjectDirectoryDeepTab::initializeUi()
{
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(4, 4, 4, 4);
    rootLayout->setSpacing(6);

    auto* toolLayout = new QHBoxLayout();
    toolLayout->setContentsMargins(0, 0, 0, 0);
    toolLayout->setSpacing(6);

    auto* rootPathLabel = new QLabel(kernelText("kernel.object_directory.toolbar.root_path.label", QStringLiteral("根路径:")), this);
    rootPathEdit_ = new QLineEdit(this);
    rootPathEdit_->setText(QStringLiteral("\\"));
    rootPathEdit_->setPlaceholderText(kernelText("kernel.object_directory.toolbar.root_path.placeholder", QStringLiteral("\\、\\Device、\\BaseNamedObjects、\\Sessions")));
    rootPathEdit_->setToolTip(kernelText("kernel.object_directory.toolbar.root_path.tooltip", QStringLiteral("Object Manager Directory 根路径，必须是 Directory 对象。")));

    auto* depthLabel = new QLabel(kernelText("kernel.object_directory.toolbar.max_depth.label", QStringLiteral("最大深度:")), this);
    maxDepthSpinBox_ = new QSpinBox(this);
    maxDepthSpinBox_->setRange(0, 32);
    maxDepthSpinBox_->setValue(4);
    maxDepthSpinBox_->setToolTip(kernelText("kernel.object_directory.toolbar.max_depth.tooltip", QStringLiteral("只对 TypeName == Directory 的对象继续下钻，达到深度后停止。")));

    refreshButton_ = new QPushButton(kernelText("kernel.object_directory.toolbar.refresh", QStringLiteral("刷新")), this);
    refreshButton_->setToolTip(kernelText("kernel.object_directory.toolbar.refresh.tooltip", QStringLiteral("后台递归枚举指定 Object Manager Directory。")));

    statusLabel_ = new QLabel(kernelText("kernel.object_directory.status.waiting", QStringLiteral("状态：等待刷新")), this);
    statusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::textSecondaryHex()));

    toolLayout->addWidget(rootPathLabel, 0);
    toolLayout->addWidget(rootPathEdit_, 1);
    toolLayout->addWidget(depthLabel, 0);
    toolLayout->addWidget(maxDepthSpinBox_, 0);
    toolLayout->addWidget(refreshButton_, 0);
    toolLayout->addWidget(statusLabel_, 0);
    rootLayout->addLayout(toolLayout);

    auto* splitter = new QSplitter(Qt::Vertical, this);
    rootLayout->addWidget(splitter, 1);

    resultTree_ = new QTreeWidget(splitter);
    resultTree_->setColumnCount(static_cast<int>(DirectoryDeepColumn::kCount));
    resultTree_->setHeaderLabels(QStringList{
        kernelText("kernel.object_directory.header.name", QStringLiteral("名称")),
        kernelText("kernel.object_directory.header.type", QStringLiteral("类型")),
        kernelText("kernel.object_directory.header.full_path", QStringLiteral("完整路径")),
        kernelText("kernel.object_directory.header.depth", QStringLiteral("深度")),
        kernelText("kernel.object_directory.header.status", QStringLiteral("状态"))
        });
    resultTree_->setAlternatingRowColors(true);
    resultTree_->setSelectionMode(QAbstractItemView::SingleSelection);
    resultTree_->setRootIsDecorated(true);
    resultTree_->setContextMenuPolicy(Qt::CustomContextMenu);
    if (resultTree_->header() != nullptr)
    {
        resultTree_->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
        resultTree_->header()->setSectionResizeMode(static_cast<int>(DirectoryDeepColumn::kFullPath), QHeaderView::Stretch);
    }

    detailEditor_ = new CodeEditorWidget(splitter);
    detailEditor_->setReadOnly(true);
    detailEditor_->setText(kernelText("kernel.object_directory.detail.initial", QStringLiteral("输入根路径后点击刷新。")));

    splitter->setStretchFactor(0, 4);
    splitter->setStretchFactor(1, 2);

    ks::ui::DetailLayoutRegistry::registerHost(resultTree_, detailEditor_, this);

    connect(refreshButton_, &QPushButton::clicked, this, [this]() {
        startRefresh();
    });
    connect(rootPathEdit_, &QLineEdit::returnPressed, this, [this]() {
        startRefresh();
    });
    connect(resultTree_, &QTreeWidget::currentItemChanged, this, [this](QTreeWidgetItem*, QTreeWidgetItem*) {
        showCurrentItemDetail();
    });
    connect(resultTree_, &QTreeWidget::customContextMenuRequested, this, [this](const QPoint& localPosition) {
        showTreeCopyRowMenu(resultTree_, localPosition);
    });
}

void KernelObjectDirectoryDeepTab::setRefreshRunning(const bool running)
{
    if (refreshButton_ != nullptr)
    {
        refreshButton_->setEnabled(!running);
    }
    if (rootPathEdit_ != nullptr)
    {
        rootPathEdit_->setEnabled(!running);
    }
    if (maxDepthSpinBox_ != nullptr)
    {
        maxDepthSpinBox_->setEnabled(!running);
    }
    if (statusLabel_ != nullptr)
    {
        statusLabel_->setText(running
            ? kernelText("kernel.object_directory.status.enumerating", QStringLiteral("状态：递归枚举中..."))
            : kernelText("kernel.object_directory.status.idle", QStringLiteral("状态：空闲")));
        statusLabel_->setStyleSheet(statusLabelStyle(running ? ksword_theme::infoHex() : ksword_theme::textSecondaryHex()));
    }
}

void KernelObjectDirectoryDeepTab::startRefresh()
{
    const QPointer<KernelObjectDirectoryDeepTab> kDeferredGuard(this);
    if (ks::ui::deferItemViewUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("kernel-object-directory-refresh-start"),
        { resultTree_ },
        [kDeferredGuard]()
        {
            if (!kDeferredGuard.isNull())
            {
                kDeferredGuard->startRefresh();
            }
        }))
    {
        return;
    }

    if (refreshRunning_.exchange(true))
    {
        return;
    }

    KernelObjectDirectoryDeepOptions options;
    options.rootPath = rootPathEdit_ != nullptr ? rootPathEdit_->text().trimmed() : QStringLiteral("\\");
    options.maxDepth = maxDepthSpinBox_ != nullptr ? maxDepthSpinBox_->value() : 4;
    options.maxEntriesPerDirectory = 4096;
    options.maxTotalEntries = 50000;

    setRefreshRunning(true);
    if (resultTree_ != nullptr)
    {
        ks::ui::DetailLayoutRegistry::prepareDataRebuild(detailEditor_);
        resultTree_->clear();
    }
    if (detailEditor_ != nullptr)
    {
        detailEditor_->setText(kernelText("kernel.object_directory.detail.background", QStringLiteral("正在后台递归枚举：%1")).arg(options.rootPath));
    }

    QPointer<KernelObjectDirectoryDeepTab> guardThis(this);
    std::thread([guardThis, options]() {
        KernelObjectDirectoryDeepResult result =
            runKernelObjectDirectoryDeepSnapshotTask(options);

        QMetaObject::invokeMethod(guardThis, [guardThis, result = std::move(result)]() mutable {
            const auto kDeferredResult =
                std::make_shared<KernelObjectDirectoryDeepResult>(std::move(result));
            auto commitResult = [guardThis, kDeferredResult]() mutable
            {
            KernelObjectDirectoryDeepResult& result = *kDeferredResult;
            if (guardThis == nullptr)
            {
                return;
            }

            guardThis->refreshRunning_.store(false);
            guardThis->setRefreshRunning(false);

            if (!result.success)
            {
                guardThis->rows_.clear();
                if (guardThis->statusLabel_ != nullptr)
                {
                    guardThis->statusLabel_->setText(kernelText("kernel.object_directory.status.failed", QStringLiteral("状态：刷新失败")));
                    guardThis->statusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::errorHex()));
                }
                if (guardThis->detailEditor_ != nullptr)
                {
                    guardThis->detailEditor_->setText(result.errorText);
                }
                return;
            }

            guardThis->rows_ = std::move(result.rows);
            guardThis->rebuildTree();

            QString statusText = kernelText("kernel.object_directory.status.summary", QStringLiteral("状态：已枚举 %1 项，目录 %2 个，失败目录 %3 个"))
                .arg(guardThis->rows_.size())
                .arg(result.visitedDirectoryCount)
                .arg(result.failedDirectoryCount);
            if (result.depthLimitReached)
            {
                statusText += kernelText("kernel.object_directory.status.depth_limit", QStringLiteral("，触达深度上限"));
            }
            if (result.perDirectoryLimitReached)
            {
                statusText += kernelText("kernel.object_directory.status.per_directory_limit", QStringLiteral("，触达单目录上限"));
            }
            if (result.totalLimitReached)
            {
                statusText += kernelText("kernel.object_directory.status.total_limit", QStringLiteral("，触达总上限"));
            }

            if (guardThis->statusLabel_ != nullptr)
            {
                guardThis->statusLabel_->setText(statusText);
                guardThis->statusLabel_->setStyleSheet(
                    statusLabelStyle(result.failedDirectoryCount == 0 ? ksword_theme::successHex() : ksword_theme::warningHex()));
            }
            if (guardThis->resultTree_ != nullptr && guardThis->resultTree_->topLevelItemCount() > 0)
            {
                guardThis->resultTree_->expandToDepth(1);
                guardThis->resultTree_->setCurrentItem(guardThis->resultTree_->topLevelItem(0), 0);
            }
            else if (guardThis->detailEditor_ != nullptr)
            {
                guardThis->detailEditor_->setText(kernelText("kernel.object_directory.detail.no_records", QStringLiteral("当前根路径没有返回可显示记录。")));
            }
            };

            if (guardThis == nullptr)
            {
                return;
            }
            if (ks::ui::deferItemViewUiCommitIfContextMenuOpen(
                guardThis.data(),
                QStringLiteral("kernel-object-directory-snapshot-apply"),
                { guardThis->resultTree_ },
                commitResult))
            {
                return;
            }
            commitResult();
        }, Qt::QueuedConnection);
    }).detach();
}

void KernelObjectDirectoryDeepTab::rebuildTree()
{
    if (resultTree_ == nullptr)
    {
        return;
    }

    ks::ui::DetailLayoutRegistry::prepareDataRebuild(detailEditor_);

    resultTree_->setUpdatesEnabled(false);
    resultTree_->clear();

    QMap<QString, QTreeWidgetItem*> itemByPath;
    for (std::size_t rowIndex = 0; rowIndex < rows_.size(); ++rowIndex)
    {
        const KernelObjectDirectoryDeepEntry& entry = rows_[rowIndex];
        QTreeWidgetItem* parentItem = ensurePathItem(resultTree_, itemByPath, entry.directoryPath);
        QTreeWidgetItem* item = itemByPath.value(normalizeObjectPathForUi(entry.fullPath), nullptr);
        if (item == nullptr || item->data(0, kSourceIndexRole).toULongLong() != kInvalidSourceIndex)
        {
            item = new QTreeWidgetItem(parentItem != nullptr ? parentItem : resultTree_->invisibleRootItem());
            itemByPath.insert(normalizeObjectPathForUi(entry.fullPath), item);
        }

        item->setText(static_cast<int>(DirectoryDeepColumn::kName), entry.objectName);
        item->setText(static_cast<int>(DirectoryDeepColumn::kType), entry.objectType);
        item->setText(static_cast<int>(DirectoryDeepColumn::kFullPath), entry.fullPath);
        item->setText(static_cast<int>(DirectoryDeepColumn::kDepth), QString::number(entry.depth));
        item->setText(static_cast<int>(DirectoryDeepColumn::kStatus), entry.statusText);
        item->setData(0, kSourceIndexRole, static_cast<qulonglong>(rowIndex));
    }

    resultTree_->setUpdatesEnabled(true);
}

void KernelObjectDirectoryDeepTab::showCurrentItemDetail()
{
    if (resultTree_ == nullptr || detailEditor_ == nullptr)
    {
        return;
    }

    QTreeWidgetItem* currentItem = resultTree_->currentItem();
    if (currentItem == nullptr)
    {
        detailEditor_->setText(kernelText("kernel.object_directory.detail.select_hint", QStringLiteral("请选择目录递归结果节点。")));
        return;
    }

    bool convertOk = false;
    const qulonglong kSourceIndex = currentItem->data(0, kSourceIndexRole).toULongLong(&convertOk);
    if (!convertOk || kSourceIndex == kInvalidSourceIndex || kSourceIndex >= rows_.size())
    {
        QString detailText;
        detailText += kernelText("kernel.object_directory.detail.parent_node.name", QStringLiteral("节点名称: %1\n")).arg(currentItem->text(static_cast<int>(DirectoryDeepColumn::kName)));
        detailText += kernelText("kernel.object_directory.detail.parent_node.type", QStringLiteral("节点类型: %1\n")).arg(currentItem->text(static_cast<int>(DirectoryDeepColumn::kType)));
        detailText += kernelText("kernel.object_directory.detail.parent_node.full_path", QStringLiteral("完整路径: %1\n")).arg(currentItem->text(static_cast<int>(DirectoryDeepColumn::kFullPath)));
        detailText += kernelText("kernel.object_directory.detail.parent_node.explanation", QStringLiteral("说明: 该节点为 UI 父目录占位，未直接绑定 Worker 返回记录。\n"));
        detailEditor_->setText(detailText);
        return;
    }

    detailEditor_->setText(formatEntryDetail(rows_[static_cast<std::size_t>(kSourceIndex)]));
}

QString KernelObjectDirectoryDeepTab::formatEntryDetail(const KernelObjectDirectoryDeepEntry& entry)
{
    QString detailText;
    detailText += QStringLiteral("[Object Manager Directory Recursive Entry]\n");
    detailText += QStringLiteral("RootPath: %1\n").arg(entry.rootPath);
    detailText += QStringLiteral("DirectoryPath: %1\n").arg(entry.directoryPath);
    detailText += QStringLiteral("ObjectName: %1\n").arg(entry.objectName);
    detailText += QStringLiteral("ObjectType: %1\n").arg(entry.objectType);
    detailText += QStringLiteral("FullPath: %1\n").arg(entry.fullPath);
    detailText += QStringLiteral("Depth: %1\n").arg(entry.depth);
    detailText += QStringLiteral("IsDirectory: %1\n").arg(entry.isDirectory ? QStringLiteral("true") : QStringLiteral("false"));
    detailText += QStringLiteral("QuerySucceeded: %1\n").arg(entry.querySucceeded ? QStringLiteral("true") : QStringLiteral("false"));
    detailText += QStringLiteral("Status: %1\n").arg(entry.statusText);
    return detailText;
}
