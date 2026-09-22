#include "MemoryDock.Internal.h"
#include "SystemMemoryAuditPage.h"

// Note: Migrated from the original aggregated implementation to a standalone .cpp file; member function implementations remain unchanged.
using namespace ksword::memory_dock_internal;

// ============================================================
// MemoryDock.UiWireAndStatus.cpp
// Purpose: Holds signal-slot connections and status bar/timer initialization code.
// ============================================================

namespace
{
    // memoryTableRowText:
    // - Input: A standard table in MemoryDock and the target row index;
    // - Processing: Read text in the current column order and concatenate using TSV.
    // - Return: full row text ready for clipboard paste.
    QString memoryTableRowText(QTableWidget* table, const int rowIndex)
    {
        if (table == nullptr || rowIndex < 0 || rowIndex >= table->rowCount())
        {
            return QString();
        }

        QStringList fields;
        fields.reserve(table->columnCount());
        for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
        {
            const QTableWidgetItem* item = table->item(rowIndex, columnIndex);
            fields.push_back(item != nullptr ? item->text() : QString());
        }
        return fields.join(QLatin1Char('\t'));
    }

    // copyMemoryTableRow:
    // - Input: MemoryDock table and target row index.
    // - Processing: Copy all columns of the current row, including hidden ones, to preserve context such as PID and session for auditing.
    // - Return: None; silently return if clipboard is unavailable or the row is invalid.
    void copyMemoryTableRow(QTableWidget* table, const int rowIndex)
    {
        if (table == nullptr || QApplication::clipboard() == nullptr)
        {
            return;
        }

        const QString kRowText = memoryTableRowText(table, rowIndex);
        if (!kRowText.isEmpty())
        {
            QApplication::clipboard()->setText(kRowText);
        }
    }

    // copyMemoryTreeRow:
    // - Input: Module tree and current node;
    // - Processing: Copy all columns of the current node, keeping them consistent with the visible fields of the module table.
    // - Returns: void; returns immediately if the clipboard is unavailable or the node is null.
    void copyMemoryTreeRow(QTreeWidget* tree, QTreeWidgetItem* item)
    {
        if (tree == nullptr || item == nullptr || QApplication::clipboard() == nullptr)
        {
            return;
        }

        QStringList fields;
        fields.reserve(tree->columnCount());
        for (int columnIndex = 0; columnIndex < tree->columnCount(); ++columnIndex)
        {
            fields.push_back(item->text(columnIndex));
        }
        QApplication::clipboard()->setText(fields.join(QLatin1Char('\t')));
    }
}

void MemoryDock::initializeConnections()
{
    // Signal-slot connection log: used to confirm all interaction channels are connected.
    KLogEvent connectInitEvent;
    info << connectInitEvent
        << "[MemoryDock] initializeConnections: 开始连接全部信号槽。"
        << eol;

    // ========================================================
    // Toolbar logic
    // ========================================================

    connect(refreshButton_, &QPushButton::clicked, this, [this]() {
        // Route the refresh action based on the current tab to reduce overhead from refreshing unrelated pages.
        const int kTabIndex = tabWidget_->currentIndex();
        KLogEvent refreshClickEvent;
        info << refreshClickEvent
            << "[MemoryDock] 点击刷新按钮, 当前Tab索引="
            << kTabIndex
            << ", attachedPid="
            << attachedPid_
            << eol;
        if (tabWidget_->currentWidget() == systemMemoryAuditPage_)
        {
            systemMemoryAuditPage_->refreshSnapshot();
            return;
        }
        if (kTabIndex == 0)
        {
            refreshProcessList(true);
            if (attachedPid_ != 0)
            {
                refreshModuleListForPid(attachedPid_);
            }
            return;
        }
        if (kTabIndex == 1)
        {
            refreshMemoryRegionList(true);
            return;
        }
        if (kTabIndex == 2)
        {
            refreshMemoryRegionList(true);
            return;
        }
        if (kTabIndex == 3)
        {
            reloadMemoryViewerPage();
            return;
        }
        if (kTabIndex == 4)
        {
            refreshBookmarkValues();
            return;
        }
        if (kTabIndex == 5)
        {
            driverReadMemoryFromUi();
            return;
        }
        if (kTabIndex == 6)
        {
            refreshKernelExecutableMemoryScanAsync();
            return;
        }
        if (kTabIndex == 7)
        {
            refreshKernelMemoryEvidenceAsync();
            return;
        }
        if (kTabIndex == 8)
        {
            refreshProcessPteTranslateAsync();
            return;
        }
        if (kTabIndex == 9)
        {
            refreshProcessMemoryEvidenceAsync();
        }
        });

    connect(tabWidget_, &QTabWidget::currentChanged, this, [this](int) {
        if (tabWidget_->currentWidget() == systemMemoryAuditPage_)
        {
            systemMemoryAuditPage_->refreshSnapshot();
        }
        });

    // Scrolling the wheel on the combo box triggers currentIndexChanged events for each item sequentially. If each item directly initiates a module enumeration,
    // dozens of background tasks would be spawned instantly, overwhelming the main thread with callbacks; this implements a unified debounce mechanism.
    processComboChangeTimer_ = new QTimer(this);
    processComboChangeTimer_->setSingleShot(true);
    processComboChangeTimer_->setInterval(200);
    connect(processComboChangeTimer_, &QTimer::timeout, this, [this]() {
        refreshModuleListForPid(pendingModuleRefreshPid_);
        });

    connect(processCombo_, &QComboBox::currentIndexChanged, this, [this](int indexValue) {
        // When switching top-level processes, refresh only the module preview; do not auto-attach.
        if (indexValue < 0)
        {
            return;
        }
        const std::uint32_t kPid = static_cast<std::uint32_t>(
            processCombo_->itemData(indexValue, Qt::UserRole).toUInt());
        KLogEvent processComboEvent;
        dbg << processComboEvent
            << "[MemoryDock] 进程下拉框切换, index="
            << indexValue
            << ", pid="
            << kPid
            << eol;
        pendingModuleRefreshPid_ = kPid;
        processComboChangeTimer_->start();

        // When the selected process has a sibling with the same name, navigate the user to Tab1 and filter by that name.
        // Reason: The dropdown for processes with the same name only shows a single line of text, making it impossible to decide which one to select. In contrast, the Tab1
        // process table displays icons, working set size, CPU usage, and session ID, and supports column sorting—all the information needed to make an informed choice is there.
        // Trigger only when same-name count > 1: a unique process has no alternative, so stealing the current page is purely disruptive.
        const QString kSelectedName =
            processCombo_->itemData(indexValue, Qt::UserRole + 1).toString();
        int sameNameCount = 0;
        for (const ProcessEntry& entry : processCache_)
        {
            if (entry.processName.compare(kSelectedName, Qt::CaseInsensitive) == 0)
            {
                ++sameNameCount;
            }
        }
        if (sameNameCount > 1
            && processFilterEdit_ != nullptr
            && tabWidget_ != nullptr
            && processTable_ != nullptr)
        {
            // setText triggers textChanged; filtering is handled by that connection, so do not call it again here.
            processFilterEdit_->setText(kSelectedName);
            tabWidget_->setCurrentWidget(tabProcessModule_);

            // Select the same item in the table as the one selected in the dropdown and scroll it into view to keep both sides consistent.
            // Users can then compare rows with the same name up and down; double-clicking any row attaches to it.
            const QString kPidText = QString::number(kPid);
            for (int row = 0; row < processTable_->rowCount(); ++row)
            {
                const QTableWidgetItem* const kPidItem = processTable_->item(row, 1);
                if (kPidItem != nullptr && kPidItem->text() == kPidText)
                {
                    processTable_->selectRow(row);
                    processTable_->scrollToItem(
                        processTable_->item(row, 0), QAbstractItemView::PositionAtCenter);
                    break;
                }
            }
        }
        });

    // Crosshair pick: drag to the target window and release to attach directly using the PID associated with that window.
    // The picked result bypasses the dropdown's current selection: the dropdown content is a potentially stale
    // snapshot, while window ownership is queried in real-time. In case of inconsistency, the latter takes
    // precedence. After successful attachment, align the dropdown to match the actual target displayed on the UI.
    connect(processPickerButton_, &ks::ui::WindowPickerButton::processPicked, this,
        [this](const quint32 pickedPid, const QString& pickedName) {
            if (pickedPid == 0)
            {
                processPickerHintLabel_->setText(
                    QStringLiteral("没拾到窗口：落点上没有其它程序的窗口。"));
                return;
            }
            KLogEvent pickEvent;
            info << pickEvent
                << "[MemoryDock] 窗口拾取附加, pid="
                << pickedPid
                << ", name="
                << pickedName.toStdString()
                << eol;
            processPickerHintLabel_->setText(
                QStringLiteral("已拾取 %1 [PID:%2]").arg(pickedName).arg(pickedPid));
            // The picked process might not yet be in the dropdown snapshot (e.g., a freshly started program), so refresh first,
            // then attach by PID. Attachment relies solely on PID and does not depend on the item existing in the dropdown.
            attachToProcess(static_cast<std::uint32_t>(pickedPid), pickedName, true);
            refreshProcessList(true);
        });

    connect(processPickerButton_, &ks::ui::WindowPickerButton::hoverPreview, this,
        [this](const quint32 hoverPid, const QString& hoverName) {
            if (hoverPid == 0)
            {
                processPickerHintLabel_->setText(QStringLiteral("拖到目标窗口上…"));
                return;
            }
            processPickerHintLabel_->setText(
                QStringLiteral("%1 [PID:%2]").arg(hoverName).arg(hoverPid));
        });

    connect(processPickerButton_, &ks::ui::WindowPickerButton::pickingChanged, this,
        [this](const bool picking) {
            processPickerHintLabel_->setVisible(picking);
            if (picking)
            {
                processPickerHintLabel_->setText(QStringLiteral("拖到目标窗口上…"));
            }
        });

    // Process table filtering: display the row if either the process name or PID matches. Only hide rows without
    // rebuilding the table, so refresh and filtering do not interfere and the current selection is not lost.
    connect(processFilterEdit_, &QLineEdit::textChanged, this, [this](const QString&) {
        applyProcessTableFilter();
        });

    connect(attachButton_, &QPushButton::clicked, this, [this]() {
        const int kComboIndex = processCombo_->currentIndex();
        if (kComboIndex < 0)
        {
            KLogEvent noSelectionEvent;
            warn << noSelectionEvent
                << "[MemoryDock] 点击附加但未选择进程。"
                << eol;
            QMessageBox::warning(this, "附加进程", "请先选择进程。");
            return;
        }
        const std::uint32_t kPid = static_cast<std::uint32_t>(
            processCombo_->itemData(kComboIndex, Qt::UserRole).toUInt());
        const QString kProcessName = processCombo_->itemData(kComboIndex, Qt::UserRole + 1).toString();
        KLogEvent attachClickEvent;
        info << attachClickEvent
            << "[MemoryDock] 点击附加按钮, pid="
            << kPid
            << ", processName="
            << kProcessName.toStdString()
            << eol;
        attachToProcess(kPid, kProcessName, true);
        });

    connect(detachButton_, &QPushButton::clicked, this, [this]() {
        KLogEvent detachClickEvent;
        info << detachClickEvent
            << "[MemoryDock] 点击分离按钮, currentPid="
            << attachedPid_
            << eol;
        detachProcess();
        QMessageBox::information(this, "分离进程", "已分离当前进程。");
        });

    connect(settingsButton_, &QPushButton::clicked, this, [this]() {
        KLogEvent settingsOpenEvent;
        info << settingsOpenEvent
            << "[MemoryDock] 打开扫描设置对话框, 当前线程数="
            << scanThreadCount_
            << ", 当前块大小KB="
            << scanChunkSizeKB_
            << eol;

        // Settings page: allows adjusting the number of scan threads and block size (cache size is approximate).
        QDialog dialog(this);
        dialog.setWindowTitle("内存扫描设置");
        QFormLayout* formLayout = new QFormLayout(&dialog);

        QSpinBox* threadSpin = new QSpinBox(&dialog);
        threadSpin->setRange(1, 32);
        threadSpin->setValue(static_cast<int>(scanThreadCount_));

        QSpinBox* chunkSpin = new QSpinBox(&dialog);
        chunkSpin->setRange(64, 16384);
        chunkSpin->setValue(static_cast<int>(scanChunkSizeKB_));
        chunkSpin->setSuffix(" KB");

        QPushButton* okButton = new QPushButton("确定", &dialog);
        QPushButton* cancelButton = new QPushButton("取消", &dialog);
        okButton->setStyleSheet(buildBlueButtonStyle());
        cancelButton->setStyleSheet(buildBlueButtonStyle());
        QHBoxLayout* buttonLayout = new QHBoxLayout();
        buttonLayout->addWidget(okButton);
        buttonLayout->addWidget(cancelButton);

        formLayout->addRow("扫描线程数", threadSpin);
        formLayout->addRow("读取块大小", chunkSpin);
        formLayout->addRow(buttonLayout);

        connect(okButton, &QPushButton::clicked, &dialog, &QDialog::accept);
        connect(cancelButton, &QPushButton::clicked, &dialog, &QDialog::reject);

        if (dialog.exec() == QDialog::Accepted)
        {
            scanThreadCount_ = static_cast<std::uint32_t>(threadSpin->value());
            scanChunkSizeKB_ = static_cast<std::uint32_t>(chunkSpin->value());
            scanStatusLabel_->setText(
                QString("设置已更新：线程=%1, 块=%2KB")
                .arg(scanThreadCount_)
                .arg(scanChunkSizeKB_));

            KLogEvent settingsApplyEvent;
            info << settingsApplyEvent
                << "[MemoryDock] 扫描设置已更新, 线程数="
                << scanThreadCount_
                << ", 块大小KB="
                << scanChunkSizeKB_
                << eol;
        }
        else
        {
            KLogEvent settingsCancelEvent;
            dbg << settingsCancelEvent
                << "[MemoryDock] 扫描设置对话框取消。"
                << eol;
        }
        });

    // ========================================================
    // Tab1: Processes and modules
    // ========================================================

    connect(processTable_, &QTableWidget::cellClicked, this, [this](int row, int column) {
        Q_UNUSED(column);
        if (row < 0)
        {
            return;
        }

        // Note: The table allows sorting, so 'row' may no longer correspond to the original index in m_processCache.
        // Therefore, this is changed to 'resolve PID and process name from cell text/data' to ensure accurate binding.
        const QTableWidgetItem* pidItem = processTable_->item(row, 1);
        const QTableWidgetItem* nameItem = processTable_->item(row, 0);
        if (pidItem == nullptr || nameItem == nullptr)
        {
            return;
        }

        bool pidOk = false;
        const std::uint32_t kPid = pidItem->text().toUInt(&pidOk);
        if (!pidOk || kPid == 0)
        {
            KLogEvent processClickParseFailEvent;
            warn << processClickParseFailEvent
                << "[MemoryDock] 进程表单击后 PID 解析失败, row="
                << row
                << eol;
            return;
        }

        KLogEvent processClickEvent;
        dbg << processClickEvent
            << "[MemoryDock] 进程表单击, row="
            << row
            << ", pid="
            << kPid
            << eol;

        for (int index = 0; index < processCombo_->count(); ++index)
        {
            if (processCombo_->itemData(index, Qt::UserRole).toUInt() == kPid)
            {
                processCombo_->setCurrentIndex(index);
                break;
            }
        }
        refreshModuleListForPid(kPid);
        });

    connect(processTable_, &QTableWidget::cellDoubleClicked, this, [this](int row, int column) {
        Q_UNUSED(column);
        if (row < 0)
        {
            return;
        }
        // Double-clicking to attach also cannot directly use the row index cache; values must be retrieved dynamically from the current table row.
        const QTableWidgetItem* pidItem = processTable_->item(row, 1);
        const QTableWidgetItem* nameItem = processTable_->item(row, 0);
        if (pidItem == nullptr || nameItem == nullptr)
        {
            return;
        }
        bool pidOk = false;
        const std::uint32_t kPid = pidItem->text().toUInt(&pidOk);
        if (!pidOk || kPid == 0)
        {
            KLogEvent processDoubleClickParseFailEvent;
            warn << processDoubleClickParseFailEvent
                << "[MemoryDock] 进程表双击后 PID 解析失败, row="
                << row
                << eol;
            return;
        }
        KLogEvent processDoubleClickEvent;
        info << processDoubleClickEvent
            << "[MemoryDock] 进程表双击触发附加, row="
            << row
            << ", pid="
            << kPid
            << ", processName="
            << nameItem->text().toStdString()
            << eol;
        attachToProcess(kPid, nameItem->text(), true);
        });

    connect(processTable_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& localPosition) {
        showProcessTableContextMenu(localPosition);
        });

    connect(moduleRefreshButton_, &QPushButton::clicked, this, [this]() {
        // Module refresh button: triggers module reload based on the currently selected PID from the dropdown.
        const int kComboIndex = processCombo_->currentIndex();
        if (kComboIndex < 0)
        {
            return;
        }
        const std::uint32_t kPid = static_cast<std::uint32_t>(
            processCombo_->itemData(kComboIndex, Qt::UserRole).toUInt());
        KLogEvent moduleRefreshClickEvent;
        info << moduleRefreshClickEvent
            << "[MemoryDock] 点击模块刷新按钮, pid="
            << kPid
            << eol;
        refreshModuleListForPid(kPid);
        });

    connect(moduleSignatureCheck_, &QCheckBox::toggled, this, [this](bool checked) {
        // Immediately refresh after switching signature verification to ensure the list state matches the selected option.
        const int kComboIndex = processCombo_->currentIndex();
        if (kComboIndex < 0)
        {
            return;
        }
        const std::uint32_t kPid = static_cast<std::uint32_t>(
            processCombo_->itemData(kComboIndex, Qt::UserRole).toUInt());
        KLogEvent moduleSignatureToggleEvent;
        info << moduleSignatureToggleEvent
            << "[MemoryDock] 模块签名校验选项变更, checked="
            << (checked ? "true" : "false")
            << ", pid="
            << kPid
            << eol;
        refreshModuleListForPid(kPid);
        });

    connect(moduleFilterEdit_, &QLineEdit::textChanged, this, [this](const QString&) {
        // Changed filter input to 'redraw cache only' to avoid re-enumerating modules and verifying signatures on every keystroke.
        KLogEvent moduleFilterEvent;
        dbg << moduleFilterEvent
            << "[MemoryDock] 模块过滤条件变化, filter="
            << moduleFilterEdit_->text().trimmed().toStdString()
            << ", cacheCount="
            << moduleCache_.size()
            << eol;

        rebuildModuleTableFromCache();
        if (moduleStatusLabel_ != nullptr)
        {
            moduleStatusLabel_->setText(
                QString("● 模块:%1 显示:%2 (过滤)")
                .arg(moduleCache_.size())
                .arg(moduleTable_->topLevelItemCount()));
            if (!moduleRefreshInProgress_.load())
            {
                moduleStatusLabel_->setStyleSheet(
                    QStringLiteral("color:%1; font-weight:600;")
                        .arg(ksword_theme::successColor().name(QColor::HexRgb)));
            }
        }
        });

    connect(moduleTable_, &QTreeWidget::itemDoubleClicked, this, [this](QTreeWidgetItem* item, int column) {
        // On double-clicking any column of a module, jump to the memory viewer by the module base address.
        Q_UNUSED(column);
        if (item == nullptr)
        {
            return;
        }
        const std::uint64_t kBaseAddress = item->data(
            toModuleTreeColumnIndex(ModuleTreeColumn::kPath),
            Qt::UserRole).toULongLong();
        KLogEvent moduleJumpEvent;
        info << moduleJumpEvent
            << "[MemoryDock] 模块表双击跳转查看器, address="
            << formatAddress(kBaseAddress).toStdString()
            << eol;
        jumpToAddress(kBaseAddress);
        });

    connect(moduleTable_, &QTreeWidget::customContextMenuRequested, this, [this](const QPoint& localPosition) {
        QTreeWidgetItem* clickedItem = moduleTable_->itemAt(localPosition);
        if (clickedItem == nullptr)
        {
            return;
        }
        moduleTable_->setCurrentItem(clickedItem);

        const std::uint64_t kBaseAddress = clickedItem->data(
            toModuleTreeColumnIndex(ModuleTreeColumn::kPath),
            Qt::UserRole).toULongLong();
        const QString kBaseText = formatAddress(kBaseAddress);

        QMenu menu(this);
        menu.setStyleSheet(ksword_theme::contextMenuStyle());
        QAction* copyBaseAction = menu.addAction("复制基址");
        QAction* copyRowAction = menu.addAction("复制当前行");
        QAction* jumpViewerAction = menu.addAction("跳转到内存查看器");
        QAction* selectedAction = menu.exec(moduleTable_->viewport()->mapToGlobal(localPosition));
        if (selectedAction == nullptr)
        {
            return;
        }

        if (selectedAction == copyBaseAction)
        {
            QApplication::clipboard()->setText(kBaseText);
            KLogEvent copyBaseEvent;
            dbg << copyBaseEvent
                << "[MemoryDock] 模块表右键复制基址, text="
                << kBaseText.toStdString()
                << eol;
            return;
        }
        if (selectedAction == copyRowAction)
        {
            copyMemoryTreeRow(moduleTable_, clickedItem);
            KLogEvent copyRowEvent;
            dbg << copyRowEvent
                << "[MemoryDock] 模块表右键复制当前行, base="
                << kBaseText.toStdString()
                << eol;
            return;
        }
        if (selectedAction == jumpViewerAction)
        {
            KLogEvent contextJumpEvent;
            info << contextJumpEvent
                << "[MemoryDock] 模块表右键跳转查看器, address="
                << kBaseText.toStdString()
                << eol;
            jumpToAddress(kBaseAddress);
        }
        });

    // ========================================================
    // Tab2: Memory Regions
    // ========================================================

    const auto kApplyRegionFilter = [this]() {
        KLogEvent regionFilterToggleEvent;
        dbg << regionFilterToggleEvent
            << "[MemoryDock] 区域过滤条件变化, committedOnly="
            << (regionCommittedOnlyCheck_->isChecked() ? "true" : "false")
            << ", imageOnly="
            << (regionImageOnlyCheck_->isChecked() ? "true" : "false")
            << ", readableOnly="
            << (regionReadableOnlyCheck_->isChecked() ? "true" : "false")
            << eol;
        applyRegionFilterAndRebuildTable();
        };
    connect(regionCommittedOnlyCheck_, &QCheckBox::toggled, this, kApplyRegionFilter);
    connect(regionImageOnlyCheck_, &QCheckBox::toggled, this, kApplyRegionFilter);
    connect(regionReadableOnlyCheck_, &QCheckBox::toggled, this, kApplyRegionFilter);

    // Keyword filtering only reorders existing cache without re-enumerating; changes take effect immediately during input.
    connect(regionFilterEdit_, &QLineEdit::textChanged, this, [this](const QString&) {
        applyRegionFilterAndRebuildTable();
        });

    // Manual refresh forces a re-enumeration of regions, used when the target process has just allocated memory.
    connect(regionRefreshButton_, &QPushButton::clicked, this, [this]() {
        KLogEvent regionRefreshClickEvent;
        info << regionRefreshClickEvent
            << "[MemoryDock] 内存区域页点击刷新。"
            << eol;
        refreshMemoryRegionList(true);
        });

    connect(regionTable_, &QTableWidget::cellDoubleClicked, this, [this](int row, int column) {
        Q_UNUSED(column);
        if (row < 0)
        {
            return;
        }
        const QString kBaseText = regionTable_->item(row, 0) != nullptr
            ? regionTable_->item(row, 0)->text()
            : QString();
        std::uint64_t baseAddress = 0;
        if (parseAddressText(kBaseText, baseAddress))
        {
            KLogEvent regionDoubleClickEvent;
            info << regionDoubleClickEvent
                << "[MemoryDock] 区域表双击跳转查看器, base="
                << formatAddress(baseAddress).toStdString()
                << eol;
            jumpToAddress(baseAddress);
        }
        });

    connect(regionTable_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& localPosition) {
        QTableWidgetItem* clickedItem = regionTable_->itemAt(localPosition);
        if (clickedItem == nullptr)
        {
            return;
        }

        const int kRow = clickedItem->row();
        const QString kBaseText = regionTable_->item(kRow, 0) != nullptr
            ? regionTable_->item(kRow, 0)->text()
            : QString();

        regionTable_->setCurrentCell(kRow, clickedItem->column());

        QMenu menu(this);
        menu.setStyleSheet(ksword_theme::contextMenuStyle());
        QAction* viewAction = menu.addAction("查看此区域");
        QAction* r0ReadAction = menu.addAction("R0读取此区域");
        QAction* copyAction = menu.addAction("复制基址");
        QAction* copyRowAction = menu.addAction("复制当前行");
        QAction* searchAction = menu.addAction("搜索此区域");
        QAction* selectedAction = menu.exec(regionTable_->viewport()->mapToGlobal(localPosition));
        if (selectedAction == nullptr)
        {
            return;
        }

        if (selectedAction == copyAction)
        {
            QApplication::clipboard()->setText(kBaseText);
            KLogEvent regionCopyEvent;
            dbg << regionCopyEvent
                << "[MemoryDock] 区域表右键复制基址, text="
                << kBaseText.toStdString()
                << eol;
            return;
        }
        if (selectedAction == copyRowAction)
        {
            copyMemoryTableRow(regionTable_, kRow);
            KLogEvent regionCopyRowEvent;
            dbg << regionCopyRowEvent
                << "[MemoryDock] 区域表右键复制当前行, row="
                << kRow
                << eol;
            return;
        }

        std::uint64_t baseAddress = 0;
        if (!parseAddressText(kBaseText, baseAddress))
        {
            return;
        }

        if (selectedAction == viewAction)
        {
            KLogEvent regionViewEvent;
            info << regionViewEvent
                << "[MemoryDock] 区域表右键查看区域, base="
                << formatAddress(baseAddress).toStdString()
                << eol;
            jumpToAddress(baseAddress);
            return;
        }
        if (selectedAction == r0ReadAction)
        {
            // Read this region through R0:
            // - Input: Base/size UserRole for the current row in the region table;
            // - Processing: Fill driver read/write pages with 'read from region base address forward', max 4KB per read.
            // - Return: No return value; the read result is displayed by the driver's read/write page status bar and HexEditor.
            const QTableWidgetItem* baseItem = regionTable_->item(kRow, 0);
            const QTableWidgetItem* sizeItem = regionTable_->item(kRow, 1);
            if (baseItem != nullptr && sizeItem != nullptr)
            {
                const std::uint64_t kRegionBase = baseItem->data(Qt::UserRole).toULongLong();
                const std::uint64_t kRegionSize = sizeItem->data(Qt::UserRole).toULongLong();
                const std::uint64_t kBytesToRead = std::min<std::uint64_t>(
                    kRegionSize == 0ULL ? 4096ULL : kRegionSize,
                    4096ULL);
                KLogEvent regionR0ReadEvent;
                info << regionR0ReadEvent
                    << "[MemoryDock] 区域表右键R0读取区域, base="
                    << formatAddress(kRegionBase).toStdString()
                    << ", bytes="
                    << kBytesToRead
                    << eol;
                prepareDriverMemoryReadAtAddress(kRegionBase, kBytesToRead, true);
            }
            return;
        }
        if (selectedAction == searchAction)
        {
            // Search this region: switch to Tab3 and populate start/end addresses.
            // Note: The region table is sorted, so row no longer corresponds to the m_regionCache index.
            // Therefore, calculations are performed using the base/size cached in the UserRole of the table items.
            const QTableWidgetItem* baseItem = regionTable_->item(kRow, 0);
            const QTableWidgetItem* sizeItem = regionTable_->item(kRow, 1);
            if (baseItem != nullptr && sizeItem != nullptr)
            {
                const std::uint64_t kRegionBase = baseItem->data(Qt::UserRole).toULongLong();
                const std::uint64_t kRegionSize = sizeItem->data(Qt::UserRole).toULongLong();
                if (kRegionSize > 0)
                {
                    const std::uint64_t kRegionEnd = kRegionBase + kRegionSize - 1;
                    KLogEvent regionSearchEvent;
                    info << regionSearchEvent
                        << "[MemoryDock] 区域表右键搜索区域, start="
                        << formatAddress(kRegionBase).toStdString()
                        << ", end="
                        << formatAddress(kRegionEnd).toStdString()
                        << eol;
                    searchRangeCombo_->setCurrentIndex(1);
                    searchRangeStartEdit_->setText(formatAddress(kRegionBase));
                    searchRangeEndEdit_->setText(formatAddress(kRegionEnd));
                    tabWidget_->setCurrentWidget(tabSearch_);
                }
            }
        }
        });

    // ========================================================
    // Tab3: Search
    // ========================================================

    connect(searchRangeCombo_, &QComboBox::currentIndexChanged, this, [this](int indexValue) {
        const bool kCustomRange = (indexValue == 1);
        searchRangeStartEdit_->setEnabled(kCustomRange);
        searchRangeEndEdit_->setEnabled(kCustomRange);
        KLogEvent rangeModeEvent;
        dbg << rangeModeEvent
            << "[MemoryDock] 搜索范围模式切换, index="
            << indexValue
            << ", customRange="
            << (kCustomRange ? "true" : "false")
            << eol;
        });

    connect(nextScanCompareCombo_, &QComboBox::currentIndexChanged, this, [this](int indexValue) {
        const auto kCompareMode = static_cast<SearchCompareMode>(
            nextScanCompareCombo_->itemData(indexValue).toInt());
        const bool kNeedValueInput = !(
            kCompareMode == SearchCompareMode::kChanged ||
            kCompareMode == SearchCompareMode::kUnchanged ||
            kCompareMode == SearchCompareMode::kIncreased ||
            kCompareMode == SearchCompareMode::kDecreased);
        const bool kNeedSecondValue = (kCompareMode == SearchCompareMode::kBetween);
        nextScanValueEdit_->setEnabled(kNeedValueInput);
        nextScanValueBEdit_->setVisible(kNeedSecondValue);
        KLogEvent compareModeEvent;
        dbg << compareModeEvent
            << "[MemoryDock] 再次扫描条件切换, mode="
            << static_cast<int>(kCompareMode)
            << ", needValue="
            << (kNeedValueInput ? "true" : "false")
            << ", needValueB="
            << (kNeedSecondValue ? "true" : "false")
            << eol;
        });

    connect(firstScanButton_, &QPushButton::clicked, this, [this]() {
        KLogEvent firstScanClickEvent;
        info << firstScanClickEvent
            << "[MemoryDock] 点击首次扫描按钮。"
            << eol;
        startFirstScan();
        });
    connect(nextScanButton_, &QPushButton::clicked, this, [this]() {
        KLogEvent nextScanClickEvent;
        info << nextScanClickEvent
            << "[MemoryDock] 点击再次扫描按钮。"
            << eol;
        startNextScan();
        });
    connect(resetScanButton_, &QPushButton::clicked, this, [this]() {
        KLogEvent resetScanClickEvent;
        info << resetScanClickEvent
            << "[MemoryDock] 点击重置扫描按钮。"
            << eol;
        resetScanState();
        });
    connect(cancelScanButton_, &QPushButton::clicked, this, [this]() {
        KLogEvent cancelScanClickEvent;
        warn << cancelScanClickEvent
            << "[MemoryDock] 点击取消扫描按钮。"
            << eol;
        cancelCurrentScan();
        });

    connect(searchResultTable_, &QTableWidget::cellDoubleClicked, this, [this](int row, int column) {
        Q_UNUSED(column);
        if (row < 0 || row >= static_cast<int>(searchResultVisibleCount_))
        {
            return;
        }
        KLogEvent resultDoubleClickEvent;
        info << resultDoubleClickEvent
            << "[MemoryDock] 搜索结果双击跳转, row="
            << row
            << eol;
        jumpToAddress(searchResultCache_[static_cast<std::size_t>(row)].address);
        });

    connect(searchResultTable_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& localPosition) {
        QTableWidgetItem* clickedItem = searchResultTable_->itemAt(localPosition);
        if (clickedItem == nullptr)
        {
            return;
        }

        const int kRow = clickedItem->row();
        if (kRow < 0 || kRow >= static_cast<int>(searchResultVisibleCount_))
        {
            return;
        }

        searchResultTable_->setCurrentCell(kRow, clickedItem->column());

        QMenu menu(this);
        menu.setStyleSheet(ksword_theme::contextMenuStyle());
        QAction* viewAction = menu.addAction("查看此地址");
        QAction* addBookmarkAction = menu.addAction("添加到书签");
        QAction* copyAddressAction = menu.addAction("复制地址");
        QAction* copyValueAction = menu.addAction("复制值");
        QAction* copyRowAction = menu.addAction("复制当前行");
        QAction* selectedAction = menu.exec(searchResultTable_->viewport()->mapToGlobal(localPosition));
        if (selectedAction == nullptr)
        {
            return;
        }

        const SearchResultEntry& entry = searchResultCache_[static_cast<std::size_t>(kRow)];
        if (selectedAction == viewAction)
        {
            KLogEvent resultViewActionEvent;
            info << resultViewActionEvent
                << "[MemoryDock] 搜索结果右键查看地址, address="
                << formatAddress(entry.address).toStdString()
                << eol;
            jumpToAddress(entry.address);
            return;
        }
        if (selectedAction == addBookmarkAction)
        {
            KLogEvent resultBookmarkActionEvent;
            info << resultBookmarkActionEvent
                << "[MemoryDock] 搜索结果右键添加书签, address="
                << formatAddress(entry.address).toStdString()
                << eol;
            addBookmarkByAddress(entry.address, "来自内存搜索结果");
            rebuildBookmarkTable();
            return;
        }
        if (selectedAction == copyAddressAction)
        {
            QApplication::clipboard()->setText(formatAddress(entry.address));
            KLogEvent resultCopyAddressEvent;
            dbg << resultCopyAddressEvent
                << "[MemoryDock] 搜索结果右键复制地址, address="
                << formatAddress(entry.address).toStdString()
                << eol;
            return;
        }
        if (selectedAction == copyValueAction)
        {
            QApplication::clipboard()->setText(
                bytesToDisplayString(entry.currentValueBytes, lastSearchValueType_));
            KLogEvent resultCopyValueEvent;
            dbg << resultCopyValueEvent
                << "[MemoryDock] 搜索结果右键复制值, row="
                << kRow
                << eol;
            return;
        }
        if (selectedAction == copyRowAction)
        {
            copyMemoryTableRow(searchResultTable_, kRow);
            KLogEvent resultCopyRowEvent;
            dbg << resultCopyRowEvent
                << "[MemoryDock] 搜索结果右键复制当前行, row="
                << kRow
                << eol;
        }
        });

    // ========================================================
    // Tab4: Viewer
    // ========================================================

    connect(viewJumpButton_, &QPushButton::clicked, this, [this]() {
        KLogEvent viewerJumpClickEvent;
        info << viewerJumpClickEvent
            << "[MemoryDock] 查看器点击跳转按钮, text="
            << viewAddressEdit_->text().trimmed().toStdString()
            << eol;
        jumpToAddressFromUi();
        });
    connect(viewAddressEdit_, &QLineEdit::returnPressed, this, [this]() {
        KLogEvent viewerEnterJumpEvent;
        info << viewerEnterJumpEvent
            << "[MemoryDock] 查看器地址框回车跳转, text="
            << viewAddressEdit_->text().trimmed().toStdString()
            << eol;
        jumpToAddressFromUi();
        });

    connect(hexEditorWidget_, &HexEditorWidget::byteEdited, this,
        [this](const std::uint64_t absoluteAddress, const std::uint8_t oldValue, const std::uint8_t newValue) {
            QString errorText;
            if (!writeSingleByteAtViewer(absoluteAddress, newValue, errorText))
            {
                KLogEvent viewerWriteFailEvent;
                err << viewerWriteFailEvent
                    << "[MemoryDock] 十六进制编辑写入失败, address="
                    << formatAddress(absoluteAddress).toStdString()
                    << ", error="
                    << errorText.toStdString()
                    << eol;

                // Roll back the control's data to the old value on write failure to ensure display consistency with the target process.
                hexEditorWidget_->setByteAtAbsoluteAddress(absoluteAddress, oldValue, true);
                // privilegePromptHandled: Merges two recovery paths: known lack of write permission and error text.
                bool privilegePromptHandled = false;
                if (attachedProcessHandle_ != nullptr &&
                    !canReadWriteMemory_ &&
                    !ks::ui::isCurrentProcessElevated())
                {
                    (void)ks::ui::requestAdministratorRestartForFeature(
                        this,
                        QStringLiteral("编辑进程内存"));
                    privilegePromptHandled = true;
                }
                if (!privilegePromptHandled)
                {
                    privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
                        this,
                        QStringLiteral("编辑进程内存"),
                        errorText);
                }
                if (!privilegePromptHandled)
                {
                    QMessageBox::warning(this, "内存编辑", errorText);
                }
                return;
            }

            // Synchronize the local cache update to prevent subsequent breakpoint/bookmark logic from reading stale page cache.
            if (absoluteAddress >= currentViewerAddress_)
            {
                const std::uint64_t kOffset = absoluteAddress - currentViewerAddress_;
                if (kOffset < static_cast<std::uint64_t>(currentViewerPageBytes_.size()))
                {
                    currentViewerPageBytes_[static_cast<int>(kOffset)] = static_cast<char>(newValue);
                }
            }

            KLogEvent viewerWriteSuccessEvent;
            info << viewerWriteSuccessEvent
                << "[MemoryDock] 十六进制编辑写入成功, address="
                << formatAddress(absoluteAddress).toStdString()
                << ", value=0x"
                << QString("%1").arg(newValue, 2, 16, QChar('0')).toUpper().toStdString()
                << eol;
        });

    connect(hexEditorWidget_, &HexEditorWidget::aboutToShowContextMenu, this,
        [this](QMenu* menu, const std::uint64_t absoluteAddress, const bool hasByte) {
            if (menu == nullptr || !hasByte)
            {
                return;
            }

            menu->setStyleSheet(ksword_theme::contextMenuStyle());
            menu->addSeparator();
            QAction* addBookmarkAction = menu->addAction("添加书签");
            QAction* addBreakpointAction = menu->addAction("添加断点");

            connect(addBookmarkAction, &QAction::triggered, this, [this, absoluteAddress]() {
                KLogEvent hexAddBookmarkEvent;
                info << hexAddBookmarkEvent
                    << "[MemoryDock] 查看器右键添加书签, address="
                    << formatAddress(absoluteAddress).toStdString()
                    << eol;
                addBookmarkByAddress(absoluteAddress, "来自内存查看器");
                rebuildBookmarkTable();
                });

            connect(addBreakpointAction, &QAction::triggered, this, [this, absoluteAddress]() {
                QString errorText;
                if (!addBreakpointByAddress(absoluteAddress, "来自内存查看器", errorText))
                {
                    KLogEvent hexAddBreakpointFailEvent;
                    err << hexAddBreakpointFailEvent
                        << "[MemoryDock] 查看器右键添加断点失败, address="
                        << formatAddress(absoluteAddress).toStdString()
                        << ", error="
                        << errorText.toStdString()
                        << eol;
                    // privilegePromptHandled: Merges two recovery paths: known lack of write permission and error text.
                    bool privilegePromptHandled = false;
                    if (attachedProcessHandle_ != nullptr &&
                        !canReadWriteMemory_ &&
                        !ks::ui::isCurrentProcessElevated())
                    {
                        (void)ks::ui::requestAdministratorRestartForFeature(
                            this,
                            QStringLiteral("设置进程断点"));
                        privilegePromptHandled = true;
                    }
                    if (!privilegePromptHandled)
                    {
                        privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
                            this,
                            QStringLiteral("设置进程断点"),
                            errorText);
                    }
                    if (!privilegePromptHandled)
                    {
                        QMessageBox::warning(this, "添加断点", errorText);
                    }
                }
                else
                {
                    KLogEvent hexAddBreakpointSuccessEvent;
                    info << hexAddBreakpointSuccessEvent
                        << "[MemoryDock] 查看器右键添加断点成功, address="
                        << formatAddress(absoluteAddress).toStdString()
                        << eol;
                }
                rebuildBreakpointTable();
                });
        });

    // ========================================================
    // Tab5: Breakpoints and Bookmarks
    // ========================================================

    connect(addBreakpointButton_, &QPushButton::clicked, this, [this]() {
        bool inputOk = false;
        const QString kAddressText = QInputDialog::getText(
            this,
            "添加断点",
            "输入断点地址",
            QLineEdit::Normal,
            "0x0",
            &inputOk);
        if (!inputOk)
        {
            KLogEvent addBreakpointCancelEvent;
            dbg << addBreakpointCancelEvent
                << "[MemoryDock] 添加断点操作已取消。"
                << eol;
            return;
        }

        std::uint64_t address = 0;
        if (!parseAddressText(kAddressText, address))
        {
            KLogEvent addBreakpointParseFailEvent;
            warn << addBreakpointParseFailEvent
                << "[MemoryDock] 添加断点地址解析失败, text="
                << kAddressText.toStdString()
                << eol;
            QMessageBox::warning(this, "添加断点", "地址格式无效。");
            return;
        }

        QString errorText;
        if (!addBreakpointByAddress(address, "手动添加", errorText))
        {
            KLogEvent addBreakpointFailEvent;
            err << addBreakpointFailEvent
                << "[MemoryDock] 添加断点失败, address="
                << formatAddress(address).toStdString()
                << ", error="
                << errorText.toStdString()
                << eol;
            // privilegePromptHandled: Merges two recovery paths: known lack of write permission and error text.
            bool privilegePromptHandled = false;
            if (attachedProcessHandle_ != nullptr &&
                !canReadWriteMemory_ &&
                !ks::ui::isCurrentProcessElevated())
            {
                (void)ks::ui::requestAdministratorRestartForFeature(
                    this,
                    QStringLiteral("设置进程断点"));
                privilegePromptHandled = true;
            }
            if (!privilegePromptHandled)
            {
                privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
                    this,
                    QStringLiteral("设置进程断点"),
                    errorText);
            }
            if (!privilegePromptHandled)
            {
                QMessageBox::warning(this, "添加断点", errorText);
            }
            return;
        }
        KLogEvent addBreakpointSuccessEvent;
        info << addBreakpointSuccessEvent
            << "[MemoryDock] 添加断点成功, address="
            << formatAddress(address).toStdString()
            << eol;
        rebuildBreakpointTable();
        });

    connect(removeBreakpointButton_, &QPushButton::clicked, this, [this]() {
        const int kRow = breakpointTable_->currentRow();
        if (kRow < 0)
        {
            return;
        }
        KLogEvent removeBreakpointEvent;
        info << removeBreakpointEvent
            << "[MemoryDock] 删除断点, row="
            << kRow
            << eol;
        removeBreakpointByRow(kRow);
        rebuildBreakpointTable();
        });

    connect(toggleBreakpointButton_, &QPushButton::clicked, this, [this]() {
        const int kRow = breakpointTable_->currentRow();
        if (kRow < 0 || kRow >= static_cast<int>(breakpointCache_.size()))
        {
            return;
        }
        const bool kNextState = !breakpointCache_[static_cast<std::size_t>(kRow)].enabled;
        if (!setBreakpointEnabledByRow(kRow, kNextState))
        {
            KLogEvent toggleBreakpointFailEvent;
            warn << toggleBreakpointFailEvent
                << "[MemoryDock] 断点状态切换失败, row="
                << kRow
                << ", targetEnabled="
                << (kNextState ? "true" : "false")
                << eol;
            if (attachedProcessHandle_ != nullptr && !canReadWriteMemory_)
            {
                (void)ks::ui::requestAdministratorRestartForFeature(
                    this,
                    QStringLiteral("切换进程断点状态"));
            }
            QMessageBox::warning(this, "断点切换", "切换失败，请检查权限或进程状态。");
        }
        else
        {
            KLogEvent toggleBreakpointSuccessEvent;
            info << toggleBreakpointSuccessEvent
                << "[MemoryDock] 断点状态切换成功, row="
                << kRow
                << ", targetEnabled="
                << (kNextState ? "true" : "false")
                << eol;
        }
        rebuildBreakpointTable();
        });

    connect(addBookmarkButton_, &QPushButton::clicked, this, [this]() {
        bool inputOk = false;
        const QString kAddressText = QInputDialog::getText(
            this,
            "添加书签",
            "输入书签地址",
            QLineEdit::Normal,
            "0x0",
            &inputOk);
        if (!inputOk)
        {
            KLogEvent addBookmarkCancelEvent;
            dbg << addBookmarkCancelEvent
                << "[MemoryDock] 添加书签操作已取消。"
                << eol;
            return;
        }
        std::uint64_t address = 0;
        if (!parseAddressText(kAddressText, address))
        {
            KLogEvent addBookmarkParseFailEvent;
            warn << addBookmarkParseFailEvent
                << "[MemoryDock] 添加书签地址解析失败, text="
                << kAddressText.toStdString()
                << eol;
            QMessageBox::warning(this, "添加书签", "地址格式无效。");
            return;
        }
        KLogEvent addBookmarkEvent;
        info << addBookmarkEvent
            << "[MemoryDock] 添加书签, address="
            << formatAddress(address).toStdString()
            << eol;
        addBookmarkByAddress(address, "手动添加");
        rebuildBookmarkTable();
        });

    connect(removeBookmarkButton_, &QPushButton::clicked, this, [this]() {
        const int kRow = bookmarkTable_->currentRow();
        if (kRow < 0 || kRow >= static_cast<int>(bookmarkCache_.size()))
        {
            return;
        }
        KLogEvent removeBookmarkEvent;
        info << removeBookmarkEvent
            << "[MemoryDock] 删除书签, row="
            << kRow
            << ", address="
            << formatAddress(bookmarkCache_[static_cast<std::size_t>(kRow)].address).toStdString()
            << eol;
        bookmarkCache_.erase(bookmarkCache_.begin() + kRow);
        rebuildBookmarkTable();
        });

    connect(refreshBookmarkButton_, &QPushButton::clicked, this, [this]() {
        KLogEvent refreshBookmarkClickEvent;
        dbg << refreshBookmarkClickEvent
            << "[MemoryDock] 点击手动刷新书签值。"
            << eol;
        refreshBookmarkValues();
        });

    connect(jumpBookmarkButton_, &QPushButton::clicked, this, [this]() {
        const int kRow = bookmarkTable_->currentRow();
        if (kRow < 0 || kRow >= static_cast<int>(bookmarkCache_.size()))
        {
            return;
        }
        KLogEvent jumpBookmarkEvent;
        info << jumpBookmarkEvent
            << "[MemoryDock] 跳转书签, row="
            << kRow
            << ", address="
            << formatAddress(bookmarkCache_[static_cast<std::size_t>(kRow)].address).toStdString()
            << eol;
        jumpToAddress(bookmarkCache_[static_cast<std::size_t>(kRow)].address);
        });

    // ========================================================
    // Tab6: Driver memory read/write.
    // ========================================================

    connect(driverMemoryReadButton_, &QPushButton::clicked, this, [this]() {
        KLogEvent driverReadClickEvent;
        info << driverReadClickEvent
            << "[MemoryDock] 驱动内存读写页点击 R0读取。"
            << eol;
        driverReadMemoryFromUi();
        });

    connect(driverMemoryAddressEdit_, &QLineEdit::returnPressed, this, [this]() {
        KLogEvent driverReadEnterEvent;
        info << driverReadEnterEvent
            << "[MemoryDock] 驱动内存读写页地址框回车读取。"
            << eol;
        driverReadMemoryFromUi();
        });

    if (driverMemoryBaseCombo_ != nullptr && driverMemoryBaseCombo_->lineEdit() != nullptr)
    {
        connect(driverMemoryBaseCombo_->lineEdit(), &QLineEdit::returnPressed, this, [this]() {
            KLogEvent driverBaseEnterEvent;
            info << driverBaseEnterEvent
                << "[MemoryDock] 驱动内存读写页偏移基址/进程框回车读取。"
                << eol;
            driverReadMemoryFromUi();
            });
    }

    connect(driverMemoryApplyButton_, &QPushButton::clicked, this, [this]() {
        KLogEvent driverApplyClickEvent;
        info << driverApplyClickEvent
            << "[MemoryDock] 驱动内存读写页点击应用差异。"
            << eol;
        driverApplyMemoryDiffFromUi();
        });

    connect(driverMemoryResetButton_, &QPushButton::clicked, this, [this]() {
        KLogEvent driverResetClickEvent;
        info << driverResetClickEvent
            << "[MemoryDock] 驱动内存读写页点击清空缓存。"
            << eol;
        resetDriverMemoryRwState();
        });

    connect(driverMemoryHexEditor_, &HexEditorWidget::byteEdited, this,
        [this](const std::uint64_t absoluteAddress, const std::uint8_t oldValue, const std::uint8_t newValue) {
            Q_UNUSED(oldValue);
            if (!driverMemoryHasSnapshot_ || absoluteAddress < driverMemoryBaseAddress_)
            {
                return;
            }

            const std::uint64_t kOffset = absoluteAddress - driverMemoryBaseAddress_;
            if (kOffset >= static_cast<std::uint64_t>(driverMemoryEditedBytes_.size()))
            {
                return;
            }

            driverMemoryEditedBytes_[static_cast<int>(kOffset)] = static_cast<char>(newValue);
            std::vector<DriverDiffBlock> diffBlocks;
            collectDriverMemoryDiffBlocks(diffBlocks);
            driverMemoryApplyButton_->setEnabled(!diffBlocks.empty());
            if (driverMemoryStatusLabel_ != nullptr)
            {
                driverMemoryStatusLabel_->setText(
                    QString("缓存已修改：差异块=%1，点击“应用差异到真实内存”后才会写入。")
                    .arg(diffBlocks.size()));
            }

            // Changing a single byte may alter the entire instruction; derived views must be recalculated accordingly.
            refreshDriverMemoryViewsFromSnapshot();
        });

    // Switching the source requires synchronizing available controls: physical memory channels have no concept of target processes or modules.
    connect(driverMemorySourceCombo_, QOverload<int>::of(&QComboBox::currentIndexChanged), this,
        [this](int) {
            const DriverMemorySourceMode kSourceMode = currentDriverMemorySourceMode();
            const bool kPhysicalMode = (kSourceMode == DriverMemorySourceMode::kPhysical);
            if (driverMemoryBaseCombo_ != nullptr)
            {
                driverMemoryBaseCombo_->setEnabled(!kPhysicalMode);
            }
            if (driverMemoryKernelModuleRefreshButton_ != nullptr)
            {
                driverMemoryKernelModuleRefreshButton_->setEnabled(!kPhysicalMode);
            }
            if (driverMemoryAddressEdit_ != nullptr)
            {
                driverMemoryAddressEdit_->setPlaceholderText(kPhysicalMode
                    ? QStringLiteral("物理地址，例如 0x1000；单次读上限 64 KB")
                    : QStringLiteral("用户态有效地址/偏移，或 0xFFFF... 内核虚拟地址，或物理地址"));
            }
            if (driverMemoryStatusLabel_ != nullptr)
            {
                driverMemoryStatusLabel_->setText(kPhysicalMode
                    ? QStringLiteral("已切换到物理内存通道：读上限 64 KB，写上限每块 4 KB 且没有回滚。")
                    : (kSourceMode == DriverMemorySourceMode::kKernelVirtual
                        ? QStringLiteral("已切换到内核虚拟内存通道：可用“模块名+偏移”定位内核模块。")
                        : QStringLiteral("已切换到进程虚拟内存通道。")));
            }
        });

    // Kernel module list is loaded on demand to avoid the cost of full enumeration every time the page is opened.
    connect(driverMemoryKernelModuleRefreshButton_, &QPushButton::clicked, this, [this]() {
        KLogEvent kernelModuleRefreshClickEvent;
        info << kernelModuleRefreshClickEvent
            << "[MemoryDock] 驱动内存读写页点击刷新内核模块。"
            << eol;
        refreshKernelModuleCacheAsync();
        });

    connect(driverMemoryDumpButton_, &QPushButton::clicked, this, [this]() {
        dumpDriverMemorySnapshotToFile();
        });

    connect(driverMemoryWriteStringButton_, &QPushButton::clicked, this, [this]() {
        writeStringIntoDriverMemoryBuffer();
        });

    // The three segment buttons are mutually exclusive; they only switch the view when selected to avoid redundant triggers upon deselection.
    connect(driverMemoryHexViewButton_, &QToolButton::toggled, this, [this](bool checked) {
        if (checked)
        {
            applyDriverMemoryViewMode(DriverMemoryViewMode::kHex);
        }
        });
    connect(driverMemoryDisasmViewButton_, &QToolButton::toggled, this, [this](bool checked) {
        if (checked)
        {
            applyDriverMemoryViewMode(DriverMemoryViewMode::kDisassembly);
        }
        });
    connect(driverMemoryTextViewButton_, &QToolButton::toggled, this, [this](bool checked) {
        if (checked)
        {
            applyDriverMemoryViewMode(DriverMemoryViewMode::kText);
        }
        });

    connect(driverMemoryTextEncodingCombo_, QOverload<int>::of(&QComboBox::currentIndexChanged), this,
        [this](int) {
            // Encoding only affects the text view; other views do not need rebuilding.
            if (driverMemoryViewMode_ == DriverMemoryViewMode::kText)
            {
                rebuildDriverMemoryTextView();
            }
        });

    connect(driverMemoryDisasmTable_, &QTableWidget::customContextMenuRequested, this,
        [this](const QPoint& localPosition) {
            showDriverMemoryDisassemblyContextMenu(localPosition);
        });

    // ========================================================
    // Tab7: Kernel executable page scan
    // ========================================================

    connect(kernelExecutableRefreshButton_, &QPushButton::clicked, this, [this]() {
        KLogEvent refreshKernelExecutableEvent;
        info << refreshKernelExecutableEvent
            << "[MemoryDock] 内核可执行页扫描点击刷新。"
            << eol;
        refreshKernelExecutableMemoryScanAsync();
        });

    connect(kernelExecutableRiskOnlyCheck_, &QCheckBox::toggled, this, [this]() {
        rebuildKernelExecutableMemoryScanTable();
        showKernelExecutableMemoryDetailByCurrentRow();
        });

    connect(kernelExecutableModuleFilterEdit_, &QLineEdit::textChanged, this, [this]() {
        rebuildKernelExecutableMemoryScanTable();
        showKernelExecutableMemoryDetailByCurrentRow();
        });

    connect(kernelExecutableTable_, &QTableWidget::currentCellChanged, this, [this](int, int, int, int) {
        showKernelExecutableMemoryDetailByCurrentRow();
        });

    // ========================================================
    // Tab8: Kernel memory evidence.
    // ========================================================

    connect(kernelMemoryEvidenceRefreshButton_, &QPushButton::clicked, this, [this]() {
        KLogEvent refreshKernelMemoryEvidenceEvent;
        info << refreshKernelMemoryEvidenceEvent
            << "[MemoryDock] 内核内存证据点击刷新。"
            << eol;
        refreshKernelMemoryEvidenceAsync();
        });

    connect(kernelMemoryEvidenceRiskOnlyCheck_, &QCheckBox::toggled, this, [this]() {
        rebuildKernelMemoryEvidenceTable();
        showKernelMemoryEvidenceDetailByCurrentRow();
        });

    connect(kernelMemoryEvidenceIncludeNonModuleCheck_, &QCheckBox::toggled, this, [this]() {
        if (kernelMemoryEvidenceStatusLabel_ != nullptr)
        {
            kernelMemoryEvidenceStatusLabel_->setText(QStringLiteral(
                "状态：非模块执行范围仅在填写起止地址后参与下一次刷新。"));
        }
        });

    connect(kernelMemoryEvidenceFilterEdit_, &QLineEdit::textChanged, this, [this]() {
        rebuildKernelMemoryEvidenceTable();
        showKernelMemoryEvidenceDetailByCurrentRow();
        });

    connect(kernelMemoryEvidenceTable_, &QTableWidget::currentCellChanged, this, [this](int, int, int, int) {
        showKernelMemoryEvidenceDetailByCurrentRow();
        });

    // ========================================================
    // Tab9: PTE / VA translation
    // ========================================================

    connect(processPteTranslateRefreshButton_, &QPushButton::clicked, this, [this]() {
        KLogEvent refreshPteTranslateEvent;
        info << refreshPteTranslateEvent
            << "[MemoryDock] PTE / VA 翻译点击刷新。"
            << eol;
        refreshProcessPteTranslateAsync();
        });

    connect(processPteTranslateRiskOnlyCheck_, &QCheckBox::toggled, this, [this]() {
        rebuildProcessPteTranslateTable();
        showProcessPteTranslateDetailByCurrentRow();
        });

    connect(processPteTranslateAddressEdit_, &QLineEdit::textChanged, this, [this]() {
        rebuildProcessPteTranslateTable();
        showProcessPteTranslateDetailByCurrentRow();
        });

    connect(processPteTranslatePageCountSpin_, QOverload<int>::of(&QSpinBox::valueChanged), this, [this](int) {
        rebuildProcessPteTranslateTable();
        showProcessPteTranslateDetailByCurrentRow();
        });

    connect(processPteTranslateTable_, &QTableWidget::currentCellChanged, this, [this](int, int, int, int) {
        showProcessPteTranslateDetailByCurrentRow();
        });

    // ========================================================
    // Tab10: Process memory evidence
    // ========================================================

    connect(processMemoryEvidenceRefreshButton_, &QPushButton::clicked, this, [this]() {
        KLogEvent refreshProcessMemoryEvidenceEvent;
        info << refreshProcessMemoryEvidenceEvent
            << "[MemoryDock] 进程内存证据点击刷新。"
            << eol;
        refreshProcessMemoryEvidenceAsync();
        });

    connect(processMemoryEvidenceRiskOnlyCheck_, &QCheckBox::toggled, this, [this]() {
        rebuildProcessMemoryEvidenceTable();
        showProcessMemoryEvidenceDetailByCurrentRow();
        });

    connect(processMemoryEvidenceImageOnlyCheck_, &QCheckBox::toggled, this, [this]() {
        rebuildProcessMemoryEvidenceTable();
        showProcessMemoryEvidenceDetailByCurrentRow();
        });

    connect(processMemoryEvidenceStartEdit_, &QLineEdit::textChanged, this, [this]() {
        rebuildProcessMemoryEvidenceTable();
        showProcessMemoryEvidenceDetailByCurrentRow();
        });

    connect(processMemoryEvidenceEndEdit_, &QLineEdit::textChanged, this, [this]() {
        rebuildProcessMemoryEvidenceTable();
        showProcessMemoryEvidenceDetailByCurrentRow();
        });

    connect(processMemoryEvidenceFilterEdit_, &QLineEdit::textChanged, this, [this]() {
        rebuildProcessMemoryEvidenceTable();
        showProcessMemoryEvidenceDetailByCurrentRow();
        });

    connect(processMemoryEvidenceMaxRowsSpin_, QOverload<int>::of(&QSpinBox::valueChanged), this, [this](int) {
        rebuildProcessMemoryEvidenceTable();
        showProcessMemoryEvidenceDetailByCurrentRow();
        });

    connect(processMemoryEvidenceTable_, &QTableWidget::currentCellChanged, this, [this](int, int, int, int) {
        showProcessMemoryEvidenceDetailByCurrentRow();
        });
}

void MemoryDock::initializeStatusBar()
{
    // Log during status bar initialization to confirm successful creation of the bottom status component.
    KLogEvent statusBarInitEvent;
    info << statusBarInitEvent
        << "[MemoryDock] initializeStatusBar: 创建状态栏标签。"
        << eol;

    // Bottom status bar uniformly displays process name, PID, and read/write capability.
    statusBar_ = new QStatusBar(this);
    statusBar_->setSizeGripEnabled(false);

    statusProcessLabel_ = new QLabel("进程: 未附加", statusBar_);
    statusPidLabel_ = new QLabel("PID: -", statusBar_);
    statusMemoryIoLabel_ = new QLabel("读写状态: 未就绪", statusBar_);
    statusBar_->addPermanentWidget(statusProcessLabel_, 1);
    statusBar_->addPermanentWidget(statusPidLabel_);
    statusBar_->addPermanentWidget(statusMemoryIoLabel_, 1);

    rootLayout_->addWidget(statusBar_);
}

void MemoryDock::initializeBookmarkRefreshTimer()
{
    // Log when initializing the bookmark refresh timer to help locate the source of automatic refresh triggers.
    KLogEvent timerInitEvent;
    info << timerInitEvent
        << "[MemoryDock] initializeBookmarkRefreshTimer: 启动 1 秒周期刷新。"
        << eol;

    // Bookmark values refresh once per second by default to facilitate observing variable changes.
    bookmarkRefreshTimer_ = new QTimer(this);
    bookmarkRefreshTimer_->setInterval(1000);
    connect(bookmarkRefreshTimer_, &QTimer::timeout, this, [this]() {
        // Timer logs use Debug level to avoid impacting Info stream readability.
        KLogEvent timerTickEvent;
        dbg << timerTickEvent
            << "[MemoryDock] 书签刷新定时器触发。"
            << eol;
        refreshBookmarkValues();
        });
    bookmarkRefreshTimer_->start();
}
