
#include "KernelDeviceDriverObjectsTab.h"
#include "KernelDriverDispatchEditorDialog.h"
#include "KernelDriverImageEditorDialog.h"
#include "KernelDock.h"
#include "../ui/TableInteractionSupport.h"
#include "../ui/VisibleTableWidget.h"

// ============================================================
// KernelDeviceDriverObjectsTab.cpp
// Purpose:
// 1) Build the 'Devices and Drivers' specialized view UI.
// 2) Trigger R3 enumeration tasks asynchronously in the background to avoid blocking the UI.
// 3) Provides directory/type/keyword filtering, copy, and TSV export.
// ============================================================

#include "../Theme.h"

#include <QAction>
#include <QAbstractItemView>
#include <QApplication>
#include <QClipboard>
#include <QComboBox>
#include <QFile>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QSignalBlocker>
#include <QSizePolicy>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QStringList>
#include <QTimer>
#include <QVBoxLayout>

#include <algorithm> // std::find/std::sort/std::unique: filtering and sorting.
#include <utility>   // std::move: Move background results.
#include <thread>    // std::thread: Background enumeration thread.

using ksword::kernel_dock_internal::kernelText;

namespace
{
    // ============================================================
    // Directory specification:
    // - Consistent with the enumerated directories in the worker.
    // - This is responsible only for UI dropdown display and carries no enumeration logic.
    // ============================================================
    struct RootDirectorySpec
    {
        QString pathText;      // pathText: Object manager directory path.
        QString displayText;   // displayText: Text displayed in the dropdown.
    };

    // kRootDirectorySpecs：
    // - Purpose: Provides fixed directory options for filters.
    // - Returns: A static array with a fixed, read-only order.
    const std::vector<RootDirectorySpec> kRootDirectorySpecs{
        { QStringLiteral("\\Device"), QStringLiteral("\\Device") },
        { QStringLiteral("\\Driver"), QStringLiteral("\\Driver") },
        { QStringLiteral("\\FileSystem"), QStringLiteral("\\FileSystem") },
        { QStringLiteral("\\FileSystem\\Filters"), QStringLiteral("\\FileSystem\\Filters") },
    };

    // blueButtonStyle：
    // - Purpose: Generate unified primary button style.
    // - Returns: Style text ready to be used directly with setStyleSheet.
    QString blueButtonStyle()
    {
        return ksword_theme::themedButtonStyle();
    }

    // blueInputStyle：
    // - Purpose: Generate unified input box style.
    // - Returns: Style text ready to be used directly with setStyleSheet.
    QString blueInputStyle()
    {
        return QStringLiteral(
            "QLineEdit{border:1px solid %2;border-radius:2px;background:transparent;/* %3 */color:%4;padding:2px 6px;}"
            "QLineEdit:focus{border:1px solid %1;}")
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::textPrimaryHex());
    }

    // headerStyle：
    // - Purpose: Generate header style;
    // - Returns text directly usable for horizontalHeader()->setStyleSheet.
    QString headerStyle()
    {
        return QStringLiteral(
            "QHeaderView::section{color:%1;background:transparent;/* %2 */border:1px solid %3;font-weight:600;}")
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::borderHex());
    }

    // statusLabelStyle：
    // - Purpose: Generate status label color style.
    // - Returns: Text ready for setStyleSheet.
    QString statusLabelStyle(const QString& colorHex)
    {
        return QStringLiteral("color:%1;font-weight:600;").arg(colorHex);
    }

    // makeLabel：
    // - Input text: Label text;
    // - Processing: create a description label and unify the theme;
    // - Returns: A QLabel directly insertable into a layout.
    QLabel* makeLabel(const QString& text, QWidget* parentWidget)
    {
        auto* label = new QLabel(text, parentWidget);
        label->setStyleSheet(statusLabelStyle(ksword_theme::textSecondaryHex()));
        return label;
    }

    // setColumnWidthIfPresent：
    // - Input table, column, and width;
    // - Handling: set width only if the column exists to facilitate reuse.
    // - Returns: Nothing.
    void setColumnWidthIfPresent(QTableWidget* table, const int column, const int width)
    {
        if (table != nullptr && column >= 0 && column < table->columnCount())
        {
            table->setColumnWidth(column, width);
        }
    }
}

// KernelDeviceDriverObjectsTab：
// - Input parent: Qt parent widget;
// - Processing: Set up UI and trigger initial asynchronous refresh;
// - Returns: Nothing.
KernelDeviceDriverObjectsTab::KernelDeviceDriverObjectsTab(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
    initializeConnections();

    // Defer refresh trigger on first open to avoid blocking UI during construction.
    QTimer::singleShot(0, this, [this]() {
        refreshAsync();
    });
}

// initializeUi：
// - Processing: Build top toolbar, filters, and results table;
// - Returns: Nothing.
void KernelDeviceDriverObjectsTab::initializeUi()
{
    rootLayout_ = new QVBoxLayout(this);
    rootLayout_->setContentsMargins(6, 6, 6, 6);
    rootLayout_->setSpacing(4);

    toolbarWidget_ = new QWidget(this);
    auto* toolbarLayout = new QHBoxLayout(toolbarWidget_);
    toolbarLayout->setContentsMargins(0, 0, 0, 0);
    toolbarLayout->setSpacing(6);

    refreshButton_ = new QPushButton(kernelText("kernel.device_driver.toolbar.refresh", QStringLiteral("刷新")), toolbarWidget_);
    refreshButton_->setStyleSheet(blueButtonStyle());
    refreshButton_->setToolTip(kernelText("kernel.device_driver.toolbar.refresh.tooltip", QStringLiteral("重新枚举 \\Device、\\Driver、\\FileSystem 等对象目录")));
    exportButton_ = new QPushButton(kernelText("kernel.device_driver.toolbar.export", QStringLiteral("导出 TSV")), toolbarWidget_);
    exportButton_->setStyleSheet(blueButtonStyle());
    exportButton_->setToolTip(kernelText("kernel.device_driver.toolbar.export.tooltip", QStringLiteral("把当前可见结果导出为 TSV")));
    statusLabel_ = new QLabel(kernelText("kernel.device_driver.status.initial", QStringLiteral("状态：首次打开后正在加载设备与驱动对象...")), toolbarWidget_);
    statusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::textSecondaryHex()));
    statusLabel_->setWordWrap(true);
    statusLabel_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

    toolbarLayout->addWidget(refreshButton_, 0);
    toolbarLayout->addWidget(exportButton_, 0);
    toolbarLayout->addWidget(statusLabel_, 1);
    rootLayout_->addWidget(toolbarWidget_, 0);

    filterWidget_ = new QWidget(this);
    auto* filterLayout = new QHBoxLayout(filterWidget_);
    filterLayout->setContentsMargins(0, 0, 0, 0);
    filterLayout->setSpacing(6);

    directoryFilterCombo_ = new QComboBox(filterWidget_);
    directoryFilterCombo_->setEditable(false);
    directoryFilterCombo_->setMinimumWidth(190);
    directoryFilterCombo_->setToolTip(kernelText("kernel.device_driver.filter.directory.tooltip", QStringLiteral("按对象目录过滤")));
    typeFilterCombo_ = new QComboBox(filterWidget_);
    typeFilterCombo_->setEditable(false);
    typeFilterCombo_->setMinimumWidth(160);
    typeFilterCombo_->setToolTip(kernelText("kernel.device_driver.filter.type.tooltip", QStringLiteral("按对象类型过滤")));
    keywordEdit_ = new QLineEdit(filterWidget_);
    keywordEdit_->setPlaceholderText(kernelText("kernel.device_driver.filter.keyword.placeholder", QStringLiteral("关键字过滤：名称 / 类型 / 路径 / 目标 / 提示")));
    keywordEdit_->setClearButtonEnabled(true);
    keywordEdit_->setStyleSheet(blueInputStyle());

    filterLayout->addWidget(makeLabel(kernelText("kernel.device_driver.filter.directory.label", QStringLiteral("目录：")), filterWidget_), 0);
    filterLayout->addWidget(directoryFilterCombo_, 0);
    filterLayout->addWidget(makeLabel(kernelText("kernel.device_driver.filter.type.label", QStringLiteral("类型：")), filterWidget_), 0);
    filterLayout->addWidget(typeFilterCombo_, 0);
    filterLayout->addWidget(makeLabel(kernelText("kernel.device_driver.filter.keyword.label", QStringLiteral("关键字：")), filterWidget_), 0);
    filterLayout->addWidget(keywordEdit_, 1);
    rootLayout_->addWidget(filterWidget_, 0);

    tableWidget_ = new ks::ui::VisibleTableWidget(this);
    tableWidget_->setColumnCount(7);
    tableWidget_->setHorizontalHeaderLabels({
        kernelText("kernel.device_driver.header.directory", QStringLiteral("目录路径")),
        kernelText("kernel.device_driver.header.object_name", QStringLiteral("对象名称")),
        kernelText("kernel.device_driver.header.object_type", QStringLiteral("对象类型")),
        kernelText("kernel.device_driver.header.full_path", QStringLiteral("完整路径")),
        kernelText("kernel.device_driver.header.target_path", QStringLiteral("目标路径")),
        kernelText("kernel.device_driver.header.status", QStringLiteral("状态")),
        kernelText("kernel.device_driver.header.capability", QStringLiteral("能力提示")),
    });
    tableWidget_->setSelectionBehavior(QAbstractItemView::SelectRows);
    tableWidget_->setSelectionMode(QAbstractItemView::SingleSelection);
    tableWidget_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    tableWidget_->setContextMenuPolicy(Qt::CustomContextMenu);
    tableWidget_->setAlternatingRowColors(true);
    tableWidget_->setWordWrap(false);
    tableWidget_->verticalHeader()->setVisible(false);
    tableWidget_->horizontalHeader()->setStyleSheet(headerStyle());
    tableWidget_->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    tableWidget_->horizontalHeader()->setStretchLastSection(true);
    setColumnWidthIfPresent(tableWidget_, 0, 190);
    setColumnWidthIfPresent(tableWidget_, 1, 180);
    setColumnWidthIfPresent(tableWidget_, 2, 130);
    setColumnWidthIfPresent(tableWidget_, 3, 320);
    setColumnWidthIfPresent(tableWidget_, 4, 320);
    setColumnWidthIfPresent(tableWidget_, 5, 260);
    rootLayout_->addWidget(tableWidget_, 1);
}

// initializeConnections：
// - Processing: Connect refresh, export, filter, and right-click menu behaviors.
// - Returns: Nothing.
void KernelDeviceDriverObjectsTab::initializeConnections()
{
    connect(refreshButton_, &QPushButton::clicked, this, [this]() {
        refreshAsync();
    });

    connect(exportButton_, &QPushButton::clicked, this, [this]() {
        exportVisibleRowsAsTsv();
    });

    connect(directoryFilterCombo_, &QComboBox::currentTextChanged, this, [this](const QString&) {
        rebuildVisibleRows();
    });

    connect(typeFilterCombo_, &QComboBox::currentTextChanged, this, [this](const QString&) {
        rebuildVisibleRows();
    });

    connect(keywordEdit_, &QLineEdit::textChanged, this, [this](const QString&) {
        rebuildVisibleRows();
    });

    connect(tableWidget_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& localPosition) {
        showTableContextMenu(localPosition);
    });
}

// refreshAsync：
// - Processing: enumerate object directory in background, then dispatch results to UI upon completion.
// - Returns: Nothing.
void KernelDeviceDriverObjectsTab::refreshAsync()
{
    if (refreshRunning_.exchange(true))
    {
        if (statusLabel_ != nullptr)
        {
            statusLabel_->setText(kernelText("kernel.device_driver.status.already_refreshing", QStringLiteral("状态：刷新进行中，重复请求已忽略。")));
            statusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::kPrimaryBlueHex));
        }
        return;
    }

    if (refreshButton_ != nullptr)
    {
        refreshButton_->setEnabled(false);
    }
    updateStatusText();

    QPointer<KernelDeviceDriverObjectsTab> guardThis(this);
    std::thread([guardThis]() {
        std::vector<KernelDeviceDriverObjectEntry> resultRows;
        QString errorText;
        const bool kSuccess = runKernelDeviceDriverObjectsSnapshotTask(resultRows, errorText);

        KernelDeviceDriverObjectsTab* const kContextObject = guardThis.data();
        if (kContextObject == nullptr)
        {
            return;
        }

        QMetaObject::invokeMethod(kContextObject, [guardThis, kSuccess, errorText, resultRows = std::move(resultRows)]() mutable {
            if (guardThis == nullptr)
            {
                return;
            }

            guardThis->refreshRunning_.store(false);
            if (guardThis->refreshButton_ != nullptr)
            {
                guardThis->refreshButton_->setEnabled(true);
            }

            if (!kSuccess)
            {
                guardThis->applyRefreshResult(std::vector<KernelDeviceDriverObjectEntry>(), errorText);
                return;
            }

            guardThis->applyRefreshResult(std::move(resultRows), QString());
        }, Qt::QueuedConnection);
    }).detach();
}

// applyRefreshResult：
// - Input rows: background enumeration results; input errorText: fatal error text;
// - Processing: refresh cache, filters, and table.
// - Returns: Nothing.
void KernelDeviceDriverObjectsTab::applyRefreshResult(
    std::vector<KernelDeviceDriverObjectEntry> rows,
    const QString& errorText)
{
    const QPointer<KernelDeviceDriverObjectsTab> kSafeThis(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("kernel-device-driver-objects-snapshot"),
        { tableWidget_ },
        [kSafeThis, rows, errorText]() mutable
        {
            if (!kSafeThis.isNull())
            {
                kSafeThis->applyRefreshResult(std::move(rows), errorText);
            }
        }))
    {
        return;
    }

    if (!errorText.isEmpty())
    {
        updateStatusText(errorText);
        return;
    }

    allRows_ = std::move(rows);
    populateFilterCombos(allRows_);
    rebuildVisibleRows();
}

// populateFilterCombos：
// - Input rows: current full enumeration results;
// - Processing: Repopulate the directory and type dropdowns, preserving values that can be retained from the current selection.
// - Returns: Nothing.
void KernelDeviceDriverObjectsTab::populateFilterCombos(const std::vector<KernelDeviceDriverObjectEntry>& rows)
{
    const QString kCurrentDirectoryText = directoryFilterCombo_ != nullptr ? directoryFilterCombo_->currentText() : QString();
    const QString kCurrentTypeText = typeFilterCombo_ != nullptr ? typeFilterCombo_->currentText() : QString();

    if (directoryFilterCombo_ != nullptr)
    {
        QSignalBlocker blocker(directoryFilterCombo_);
        directoryFilterCombo_->clear();
        directoryFilterCombo_->addItem(kernelText("kernel.device_driver.filter.all_directories", QStringLiteral("全部目录")), QStringLiteral("*"));
        for (const RootDirectorySpec& spec : kRootDirectorySpecs)
        {
            directoryFilterCombo_->addItem(spec.displayText, spec.pathText);
        }

        const int kMatchIndex = directoryFilterCombo_->findText(kCurrentDirectoryText);
        directoryFilterCombo_->setCurrentIndex(kMatchIndex >= 0 ? kMatchIndex : 0);
    }

    if (typeFilterCombo_ != nullptr)
    {
        QSignalBlocker blocker(typeFilterCombo_);
        typeFilterCombo_->clear();
        typeFilterCombo_->addItem(kernelText("kernel.device_driver.filter.all_types", QStringLiteral("全部类型")), QStringLiteral("*"));

        QStringList uniqueTypes;
        uniqueTypes.reserve(static_cast<int>(rows.size()));
        for (const KernelDeviceDriverObjectEntry& entry : rows)
        {
            const QString kTypeText = entry.objectTypeText.trimmed();
            if (!kTypeText.isEmpty() && !uniqueTypes.contains(kTypeText, Qt::CaseInsensitive))
            {
                uniqueTypes.push_back(kTypeText);
            }
        }
        std::sort(uniqueTypes.begin(), uniqueTypes.end(), [](const QString& left, const QString& right) {
            return QString::compare(left, right, Qt::CaseInsensitive) < 0;
        });

        for (const QString& typeText : uniqueTypes)
        {
            typeFilterCombo_->addItem(typeText, typeText);
        }

        const int kMatchIndex = typeFilterCombo_->findText(kCurrentTypeText);
        typeFilterCombo_->setCurrentIndex(kMatchIndex >= 0 ? kMatchIndex : 0);
    }
}

// matchesCurrentFilters：
// - Input entry: The row to be evaluated.
// - Processing: Perform read-only filtering by directory, type, and keyword;
// - Returns: true if this row should be retained for display.
bool KernelDeviceDriverObjectsTab::matchesCurrentFilters(const KernelDeviceDriverObjectEntry& entry) const
{
    const QString kDirectoryFilterText = directoryFilterCombo_ != nullptr
        ? directoryFilterCombo_->currentData().toString().trimmed()
        : QString();
    const QString kTypeFilterText = typeFilterCombo_ != nullptr
        ? typeFilterCombo_->currentData().toString().trimmed()
        : QString();
    const QString kKeywordText = keywordEdit_ != nullptr ? keywordEdit_->text().trimmed() : QString();

    if (!kDirectoryFilterText.isEmpty() && kDirectoryFilterText != QStringLiteral("*"))
    {
        if (entry.directoryPathText.compare(kDirectoryFilterText, Qt::CaseInsensitive) != 0)
        {
            return false;
        }
    }

    if (!kTypeFilterText.isEmpty() && kTypeFilterText != QStringLiteral("*"))
    {
        if (entry.objectTypeText.compare(kTypeFilterText, Qt::CaseInsensitive) != 0)
        {
            return false;
        }
    }

    if (!kKeywordText.isEmpty())
    {
        const auto kContainsKeyword = [&kKeywordText](const QString& textValue) {
            return textValue.contains(kKeywordText, Qt::CaseInsensitive);
        };

        if (!kContainsKeyword(entry.directoryPathText)
            && !kContainsKeyword(entry.objectNameText)
            && !kContainsKeyword(entry.objectTypeText)
            && !kContainsKeyword(entry.fullPathText)
            && !kContainsKeyword(entry.targetPathText)
            && !kContainsKeyword(entry.statusText)
            && !kContainsKeyword(entry.capabilityHintText)
            && !kContainsKeyword(entry.detailText))
        {
            return false;
        }
    }

    return true;
}

// rebuildVisibleRows：
// - Processing: Build visible rows based on current filter conditions and refresh the table;
// - Returns: Nothing.
void KernelDeviceDriverObjectsTab::rebuildVisibleRows()
{
    visibleRows_.clear();
    for (const KernelDeviceDriverObjectEntry& entry : allRows_)
    {
        if (matchesCurrentFilters(entry))
        {
            visibleRows_.push_back(entry);
        }
    }

    rebuildTableWidget();
    updateStatusText();
}

// rebuildTableWidget：
// - Processing: Populate the table widget with currently visible rows;
// - Returns: Nothing.
void KernelDeviceDriverObjectsTab::rebuildTableWidget()
{
    if (tableWidget_ == nullptr)
    {
        return;
    }

    tableWidget_->setSortingEnabled(false);
    tableWidget_->setUpdatesEnabled(false);
    tableWidget_->clearContents();
    tableWidget_->setRowCount(0);
    tableWidget_->setRowCount(static_cast<int>(visibleRows_.size()));

    for (int rowIndex = 0; rowIndex < static_cast<int>(visibleRows_.size()); ++rowIndex)
    {
        const KernelDeviceDriverObjectEntry& entry = visibleRows_[static_cast<std::size_t>(rowIndex)];
        const QString kTargetText = entry.targetPathText.isEmpty()
            ? kernelText("kernel.device_driver.placeholder.no_target", QStringLiteral("<无>"))
            : entry.targetPathText;

        tableWidget_->setItem(rowIndex, 0, makeReadOnlyItem(entry.directoryPathText));
        tableWidget_->setItem(rowIndex, 1, makeReadOnlyItem(entry.objectNameText));
        tableWidget_->setItem(rowIndex, 2, makeReadOnlyItem(entry.objectTypeText));
        tableWidget_->setItem(rowIndex, 3, makeReadOnlyItem(entry.fullPathText));
        tableWidget_->setItem(rowIndex, 4, makeReadOnlyItem(kTargetText));
        tableWidget_->setItem(rowIndex, 5, makeReadOnlyItem(entry.statusText));
        tableWidget_->setItem(rowIndex, 6, makeReadOnlyItem(entry.capabilityHintText));
    }

    tableWidget_->setUpdatesEnabled(true);
}

// updateStatusText：
// - Input errorText: Optional error description;
// - Processing: Update the status label based on current total/visible counts and error state.
// - Returns: Nothing.
void KernelDeviceDriverObjectsTab::updateStatusText(const QString& errorText)
{
    if (statusLabel_ == nullptr)
    {
        return;
    }

    if (!errorText.isEmpty())
    {
        statusLabel_->setText(kernelText("kernel.device_driver.status.failed", QStringLiteral("状态：刷新失败 - %1")).arg(errorText));
        statusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::errorHex()));
        return;
    }

    if (refreshRunning_.load())
    {
        statusLabel_->setText(kernelText("kernel.device_driver.status.refreshing", QStringLiteral("状态：刷新中...")));
        statusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::kPrimaryBlueHex));
        return;
    }

    if (allRows_.empty())
    {
        statusLabel_->setText(kernelText("kernel.device_driver.status.no_results", QStringLiteral("状态：暂无结果，点击刷新开始枚举对象目录。")));
        statusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::textSecondaryHex()));
        return;
    }

    if (visibleRows_.empty())
    {
        statusLabel_->setText(kernelText("kernel.device_driver.status.filter_empty", QStringLiteral("状态：已加载 %1 条，当前过滤后无可见结果。")).arg(allRows_.size()));
        statusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::warningHex()));
        return;
    }

    statusLabel_->setText(
        kernelText("kernel.device_driver.status.summary", QStringLiteral("状态：已加载 %1 条，当前显示 %2 条。"))
        .arg(allRows_.size())
        .arg(visibleRows_.size()));
    statusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::successHex()));
}

// showTableContextMenu：
// - Input localPosition: Table viewport coordinates;
// - Processing: Provide copy and export operations based on the clicked cell.
// - Returns: Nothing.
void KernelDeviceDriverObjectsTab::showTableContextMenu(const QPoint& localPosition)
{
    if (tableWidget_ == nullptr)
    {
        return;
    }

    QTableWidgetItem* clickedItem = tableWidget_->itemAt(localPosition);
    if (clickedItem != nullptr)
    {
        tableWidget_->setCurrentItem(clickedItem);
    }

    const int kRow = clickedItem != nullptr ? clickedItem->row() : -1;
    const int kColumn = clickedItem != nullptr ? clickedItem->column() : -1;

    QMenu menu(this);
    menu.setStyleSheet(ksword_theme::contextMenuStyle());
    QAction* copyCellAction = menu.addAction(kernelText("kernel.device_driver.menu.copy_cell", QStringLiteral("复制单元格")));
    QAction* copyRowAction = menu.addAction(kernelText("kernel.device_driver.menu.copy_row", QStringLiteral("复制当前行")));
    QAction* copyTsvAction = menu.addAction(kernelText("kernel.device_driver.menu.copy_visible_tsv", QStringLiteral("复制可见结果 TSV")));
    QAction* exportAction = menu.addAction(kernelText("kernel.device_driver.menu.export_tsv", QStringLiteral("导出 TSV")));
    menu.addSeparator();
    QAction* dispatchEditorAction = menu.addAction(
        kernelText(
            "kernel.device_driver.menu.dispatch_editor",
            QStringLiteral("打开 IRP / MajorFunction 编辑器")));
    QAction* imageEditorAction = menu.addAction(
        kernelText(
            "kernel.device_driver.menu.image_editor",
            QStringLiteral("打开 DriverObject / KLDR 镜像编辑器")));

    const bool kEditableDriverObject = kRow >= 0 &&
        kRow < static_cast<int>(visibleRows_.size()) &&
        !visibleRows_[static_cast<std::size_t>(kRow)].isScopeEntry &&
        !visibleRows_[static_cast<std::size_t>(kRow)].isDirectory &&
        (visibleRows_[static_cast<std::size_t>(kRow)].fullPathText.startsWith(
            QStringLiteral("\\Driver\\"), Qt::CaseInsensitive) ||
         visibleRows_[static_cast<std::size_t>(kRow)].fullPathText.startsWith(
            QStringLiteral("\\FileSystem\\"), Qt::CaseInsensitive));

    copyCellAction->setEnabled(kRow >= 0 && kColumn >= 0);
    copyRowAction->setEnabled(kRow >= 0);
    copyTsvAction->setEnabled(!visibleRows_.empty());
    exportAction->setEnabled(!visibleRows_.empty());
    dispatchEditorAction->setEnabled(kEditableDriverObject);
    imageEditorAction->setEnabled(kEditableDriverObject);

    QAction* selectedAction = menu.exec(tableWidget_->viewport()->mapToGlobal(localPosition));
    if (selectedAction == copyCellAction)
    {
        copyCellAt(kRow, kColumn);
    }
    else if (selectedAction == copyRowAction)
    {
        copyRowAt(kRow);
    }
    else if (selectedAction == copyTsvAction)
    {
        copyVisibleRowsAsTsv();
    }
    else if (selectedAction == exportAction)
    {
        exportVisibleRowsAsTsv();
    }
    else if (selectedAction == dispatchEditorAction && kEditableDriverObject)
    {
        const KernelDeviceDriverObjectEntry& entry =
            visibleRows_[static_cast<std::size_t>(kRow)];
        KernelDriverDispatchEditorDialog dialog(entry.fullPathText, this);
        dialog.exec();
    }
    else if (selectedAction == imageEditorAction && kEditableDriverObject)
    {
        const KernelDeviceDriverObjectEntry& entry =
            visibleRows_[static_cast<std::size_t>(kRow)];
        KernelDriverImageEditorDialog dialog(entry.fullPathText, this);
        dialog.exec();
    }
}

// copyCellAt：
// - Input row/column: Table cell position;
// - Processing: Write cell text to the system clipboard;
// - Returns: Nothing.
void KernelDeviceDriverObjectsTab::copyCellAt(const int row, const int column) const
{
    if (tableWidget_ == nullptr || row < 0 || column < 0)
    {
        return;
    }

    const QTableWidgetItem* item = tableWidget_->item(row, column);
    if (QApplication::clipboard() != nullptr)
    {
        QApplication::clipboard()->setText(item != nullptr ? item->text() : QString());
    }
}

// copyRowAt：
// - Input row: target row.
// - Processing: Write the entire row to the clipboard according to TSV rules.
// - Returns: Nothing.
void KernelDeviceDriverObjectsTab::copyRowAt(const int row) const
{
    if (tableWidget_ == nullptr || row < 0)
    {
        return;
    }

    QStringList values;
    values.reserve(tableWidget_->columnCount());
    for (int column = 0; column < tableWidget_->columnCount(); ++column)
    {
        const QTableWidgetItem* item = tableWidget_->item(row, column);
        values.push_back(sanitizeTsvField(item != nullptr ? item->text() : QString()));
    }

    if (QApplication::clipboard() != nullptr)
    {
        QApplication::clipboard()->setText(values.join(QStringLiteral("\t")));
    }
}

// copyVisibleRowsAsTsv：
// - Processing: Write current visible results to clipboard as TSV;
// - Returns: Nothing.
void KernelDeviceDriverObjectsTab::copyVisibleRowsAsTsv() const
{
    if (QApplication::clipboard() != nullptr)
    {
        QApplication::clipboard()->setText(rowsToTsv(true));
    }
}

// exportVisibleRowsAsTsv：
// - Processing: Export current visible results to a user-selected file.
// - Returns: Nothing.
void KernelDeviceDriverObjectsTab::exportVisibleRowsAsTsv()
{
    if (visibleRows_.empty())
    {
        QMessageBox::information(this, kernelText("kernel.device_driver.export.title", QStringLiteral("导出 TSV")), kernelText("kernel.device_driver.export.no_rows", QStringLiteral("当前没有可导出的可见结果。")));
        return;
    }

    const QString kOutputPath = QFileDialog::getSaveFileName(
        this,
        kernelText("kernel.device_driver.export.title", QStringLiteral("导出 TSV")),
        QStringLiteral("kernel_device_driver_objects.tsv"),
        kernelText("kernel.device_driver.export.file_filter", QStringLiteral("TSV 文件 (*.tsv)")));
    if (kOutputPath.isEmpty())
    {
        return;
    }

    QFile outputFile(kOutputPath);
    if (!outputFile.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text))
    {
        QMessageBox::warning(this, kernelText("kernel.device_driver.export.title", QStringLiteral("导出 TSV")), kernelText("kernel.device_driver.export.write_failed", QStringLiteral("无法写入：%1")).arg(kOutputPath));
        return;
    }

    outputFile.write(rowsToTsv(true).toUtf8());
    outputFile.close();
    QMessageBox::information(this, kernelText("kernel.device_driver.export.title", QStringLiteral("导出 TSV")), kernelText("kernel.device_driver.export.completed", QStringLiteral("已导出：%1")).arg(kOutputPath));
}

// rowsToTsv：
// - Input includeHeader: Include Chinese headers when true;
// - Processing: Flatten current visible results into TSV text.
// - Returns: Text suitable for copying or exporting.
QString KernelDeviceDriverObjectsTab::rowsToTsv(const bool includeHeader) const
{
    QStringList lines;
    if (includeHeader)
    {
        lines.push_back(QStringList{
            kernelText("kernel.device_driver.header.directory", QStringLiteral("目录路径")),
            kernelText("kernel.device_driver.header.object_name", QStringLiteral("对象名称")),
            kernelText("kernel.device_driver.header.object_type", QStringLiteral("对象类型")),
            kernelText("kernel.device_driver.header.full_path", QStringLiteral("完整路径")),
            kernelText("kernel.device_driver.header.target_path", QStringLiteral("目标路径")),
            kernelText("kernel.device_driver.header.status", QStringLiteral("状态")),
            kernelText("kernel.device_driver.header.capability", QStringLiteral("能力提示")),
        }.join(QStringLiteral("\t")));
    }

    for (const KernelDeviceDriverObjectEntry& entry : visibleRows_)
    {
        lines.push_back(QStringList{
            sanitizeTsvField(entry.directoryPathText),
            sanitizeTsvField(entry.objectNameText),
            sanitizeTsvField(entry.objectTypeText),
            sanitizeTsvField(entry.fullPathText),
            sanitizeTsvField(entry.targetPathText.isEmpty()
                ? kernelText("kernel.device_driver.placeholder.no_target", QStringLiteral("<无>"))
                : entry.targetPathText),
            sanitizeTsvField(entry.statusText),
            sanitizeTsvField(entry.capabilityHintText),
        }.join(QStringLiteral("\t")));
    }

    return lines.join(QStringLiteral("\n"));
}

// sanitizeTsvField：
// - Input text: Original cell text;
// - Processing: Flatten newlines and tabs to prevent TSV column misalignment.
// - Returns: field text that is safe to write to a TSV.
QString KernelDeviceDriverObjectsTab::sanitizeTsvField(const QString& text)
{
    QString sanitizedText = text;
    sanitizedText.replace(QStringLiteral("\r"), QStringLiteral(" "));
    sanitizedText.replace(QStringLiteral("\n"), QStringLiteral(" "));
    sanitizedText.replace(QStringLiteral("\t"), QStringLiteral(" "));
    return sanitizedText;
}

// makeReadOnlyItem：
// - Input text: cell text;
// - Processing: Create a read-only item, uniformly preserving original text with a tooltip;
// - Returns: QTableWidgetItem objects ready to be inserted directly into the table.
QTableWidgetItem* KernelDeviceDriverObjectsTab::makeReadOnlyItem(const QString& text)
{
    auto* item = new QTableWidgetItem(text);
    item->setFlags(item->flags() & ~Qt::ItemIsEditable);
    item->setToolTip(text);
    return item;
}
