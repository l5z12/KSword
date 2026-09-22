#include "MemoryDock.Internal.h"
#include "../ui/TableInteractionSupport.h"
#include "../ui/VisibleTableWidget.h"
#include "../ui/DetailLayoutRegistry.h"
#include "../ui/TableColumnAutoFit.h"

#include <memory>

using namespace ksword::memory_dock_internal;

namespace
{
    // Process memory evidence page column definition: used for stable sorting, filtering, and detail location.
    enum class ProcessMemoryEvidenceColumn : int
    {
        kVirtualAddress = 0,
        kRegionBase,
        kRegionSize,
        kProtect,
        kState,
        kType,
        kValid,
        kShared,
        kLocked,
        kLargePage,
        kBad,
        kShareCount,
        kNode,
        kWin32Protection,
        kMappedFile,
        kRisk,
        kCount
    };

    int evidenceColumnIndex(const ProcessMemoryEvidenceColumn column)
    {
        return static_cast<int>(column);
    }

    QString hex64(const std::uint64_t value)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(value), 16, 16, QChar('0'))
            .toUpper();
    }

    QString protectText(const std::uint32_t protect)
    {
        switch (protect & 0xFFU)
        {
        case PAGE_READONLY: return QStringLiteral("R--");
        case PAGE_READWRITE: return QStringLiteral("RW-");
        case PAGE_WRITECOPY: return QStringLiteral("RWC");
        case PAGE_EXECUTE: return QStringLiteral("--X");
        case PAGE_EXECUTE_READ: return QStringLiteral("R-X");
        case PAGE_EXECUTE_READWRITE: return QStringLiteral("RWX");
        case PAGE_EXECUTE_WRITECOPY: return QStringLiteral("RXC");
        default: return QStringLiteral("0x%1").arg(protect, 8, 16, QChar('0')).toUpper();
        }
    }

    QString stateText(const std::uint32_t state)
    {
        switch (state)
        {
        case MEM_COMMIT: return QStringLiteral("COMMIT");
        case MEM_RESERVE: return QStringLiteral("RESERVE");
        case MEM_FREE: return QStringLiteral("FREE");
        default: return QStringLiteral("0x%1").arg(state, 8, 16, QChar('0')).toUpper();
        }
    }

    QString typeText(const std::uint32_t type)
    {
        switch (type)
        {
        case MEM_IMAGE: return QStringLiteral("IMAGE");
        case MEM_MAPPED: return QStringLiteral("MAPPED");
        case MEM_PRIVATE: return QStringLiteral("PRIVATE");
        default: return QStringLiteral("0x%1").arg(type, 8, 16, QChar('0')).toUpper();
        }
    }

    QString buildRiskText(
        const std::uint32_t protect,
        const std::uint32_t state,
        const std::uint32_t type,
        const bool valid,
        const bool largePage,
        const bool bad)
    {
        QStringList parts;
        if (!valid)
        {
            parts << QStringLiteral("无效页");
        }
        if (state != MEM_COMMIT)
        {
            parts << QStringLiteral("非提交");
        }
        if ((protect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE ||
            (protect & PAGE_EXECUTE_WRITECOPY) == PAGE_EXECUTE_WRITECOPY)
        {
            parts << QStringLiteral("可写可执行");
        }
        if (type == MEM_PRIVATE && (protect & PAGE_EXECUTE) != 0U)
        {
            parts << QStringLiteral("私有执行");
        }
        if (largePage)
        {
            parts << QStringLiteral("大页");
        }
        if (bad)
        {
            parts << QStringLiteral("坏页");
        }
        return parts.isEmpty() ? QStringLiteral("正常") : parts.join(QStringLiteral(" | "));
    }

    QString buildDetailText(const MemoryDock::ProcessMemoryEvidenceEntry& entry)
    {
        QString text;
        text += QStringLiteral("进程内存证据详情\n");
        text += QStringLiteral("VA: %1\n").arg(hex64(entry.virtualAddress));
        text += QStringLiteral("RegionBase: %1\n").arg(hex64(entry.regionBaseAddress));
        text += QStringLiteral("RegionSize: %1\n").arg(hex64(entry.regionSize));
        text += QStringLiteral("Protect: %1\n").arg(protectText(entry.protect));
        text += QStringLiteral("State: %1\n").arg(stateText(entry.state));
        text += QStringLiteral("Type: %1\n").arg(typeText(entry.type));
        text += QStringLiteral("Win32Protection: 0x%1\n").arg(entry.win32Protection, 8, 16, QChar('0'));
        text += QStringLiteral("ShareCount: %1\n").arg(entry.shareCount);
        text += QStringLiteral("Node: %1\n").arg(entry.node);
        text += QStringLiteral("Valid: %1\n").arg(entry.valid ? QStringLiteral("true") : QStringLiteral("false"));
        text += QStringLiteral("Shared: %1\n").arg(entry.shared ? QStringLiteral("true") : QStringLiteral("false"));
        text += QStringLiteral("Locked: %1\n").arg(entry.locked ? QStringLiteral("true") : QStringLiteral("false"));
        text += QStringLiteral("LargePage: %1\n").arg(entry.largePage ? QStringLiteral("true") : QStringLiteral("false"));
        text += QStringLiteral("Bad: %1\n").arg(entry.bad ? QStringLiteral("true") : QStringLiteral("false"));
        text += QStringLiteral("MappedFile: %1\n").arg(entry.mappedFilePath.isEmpty() ? QStringLiteral("—") : entry.mappedFilePath);
        text += QStringLiteral("Risk: %1\n").arg(entry.riskText);
        text += QStringLiteral("Detail: %1\n").arg(entry.detailText.isEmpty() ? QStringLiteral("—") : entry.detailText);
        return text;
    }

    QTableWidgetItem* makeItem(const QString& text)
    {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled);
        return item;
    }

    QTableWidgetItem* makeNumericItem(const QString& text, const std::uint64_t value)
    {
        // makeNumericItem：
        // - Input: Cell display text text (hex address or decimal count) and the actual numeric value value used for sorting;
        // - Processing: Construct a globally unified NumericTableItem, read NumericSortRole for sorting, and store the original value.
        //   Qt::UserRole, used by the details panel to look up cache records by virtual address;
        // - Return: Read-only numeric cell; ownership transfers to the table upon setItem.
        auto* item = new ks::ui::NumericTableItem(text, static_cast<qulonglong>(value));
        item->setData(Qt::UserRole, QVariant::fromValue<qulonglong>(static_cast<qulonglong>(value)));
        item->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled);
        return item;
    }

    QString evidenceMenuStyle()
    {
        // evidenceMenuStyle：
        // - Inputs: None;
        // - Processing: Generate an opaque QMenu style using the theme color.
        // - Returns: Right-click menu style to prevent unreadability caused by transparent menus.
        // Right-click menus always use the global theme implementation to avoid each page having its own drifting QSS fragments.
        return ksword_theme::contextMenuStyle();
    }

    void copyEvidenceCurrentRow(QTableWidget* table)
    {
        // copyEvidenceCurrentRow：
        // - Input: current memory evidence table;
        // - Processing: Write the current row to the clipboard as TSV.
        // - Return: None; returns immediately if the clipboard is unavailable or there is no current row.
        if (table == nullptr || QApplication::clipboard() == nullptr)
        {
            return;
        }

        const int kRowIndex = table->currentRow();
        if (kRowIndex < 0 || kRowIndex >= table->rowCount())
        {
            return;
        }

        QStringList fields;
        fields.reserve(table->columnCount());
        for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
        {
            const QTableWidgetItem* item = table->item(kRowIndex, columnIndex);
            fields.push_back(item != nullptr ? item->text() : QString());
        }
        QApplication::clipboard()->setText(fields.join('\t'));
    }

    void installEvidenceCopyMenu(QTableWidget* table)
    {
        // installEvidenceCopyMenu：
        // - Input: process memory evidence table;
        // - Processing: Install read-only copy menu.
        // - Return: None. The target process memory is not modified.
        if (table == nullptr)
        {
            return;
        }

        table->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(table, &QTableWidget::customContextMenuRequested, table, [table](const QPoint& localPosition) {
            const QModelIndex kClickedIndex = table->indexAt(localPosition);
            if (kClickedIndex.isValid())
            {
                table->setCurrentCell(kClickedIndex.row(), kClickedIndex.column());
            }

            QMenu menu(table);
            menu.setStyleSheet(evidenceMenuStyle());
            QAction* copyRowAction = menu.addAction(QIcon(QStringLiteral(":/Icon/process_copy_row.svg")), QStringLiteral("复制当前行"));
            copyRowAction->setEnabled(table->currentRow() >= 0);
            if (menu.exec(table->viewport()->mapToGlobal(localPosition)) == copyRowAction)
            {
                copyEvidenceCurrentRow(table);
            }
        });
    }

    int visibleEvidenceColumnCount(const QTableWidget* table)
    {
        // visibleEvidenceColumnCount：
        // - Input: process memory evidence table;
        // - Processing: Count the number of currently unhidden columns.
        // - Returns: The number of visible columns, ensuring the column selection menu maintains a minimum of one column.
        if (table == nullptr)
        {
            return 0;
        }

        int visibleCount = 0;
        for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
        {
            if (!table->isColumnHidden(columnIndex))
            {
                ++visibleCount;
            }
        }
        return visibleCount;
    }

    void installEvidenceColumnMenu(QTableWidget* table)
    {
        // installEvidenceColumnMenu：
        // - Input: process memory evidence table;
        // - Processing: Add a right-click column selection menu to the header, with a checkable action per column bidirectionally linked to setColumnHidden.
        // - Return: None. The menu is built and destroyed in-place within the callback, introducing no member variables.
        // The evidence table has 16 columns; column entry is disabled, so users must horizontally scroll to find the 'Risk' column.
        if (table == nullptr || table->horizontalHeader() == nullptr)
        {
            return;
        }

        QHeaderView* header = table->horizontalHeader();
        header->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(header, &QHeaderView::customContextMenuRequested, header,
            [table, header](const QPoint& localPosition) {
                QMenu columnMenu(table);
                columnMenu.setStyleSheet(evidenceMenuStyle());

                // The first item is a disabled header, indicating this menu controls column visibility rather than row operations.
                QAction* titleAction = columnMenu.addAction(QStringLiteral("显示的列"));
                titleAction->setEnabled(false);
                columnMenu.addSeparator();

                for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
                {
                    const QTableWidgetItem* headerItem = table->horizontalHeaderItem(columnIndex);
                    const QString kHeaderText = headerItem != nullptr
                        ? headerItem->text()
                        : QString::number(columnIndex);
                    QAction* columnAction = columnMenu.addAction(kHeaderText);
                    columnAction->setCheckable(true);
                    columnAction->setChecked(!table->isColumnHidden(columnIndex));
                    QObject::connect(columnAction, &QAction::toggled, table,
                        [table, columnIndex](const bool columnVisible) {
                            // The last column cannot be hidden: if the table becomes fully hidden, the header becomes unclickable, preventing self-recovery.
                            if (!columnVisible && visibleEvidenceColumnCount(table) <= 1)
                            {
                                return;
                            }
                            table->setColumnHidden(columnIndex, !columnVisible);
                            ks::ui::requestTableColumnAutoFit(table);
                        });
                }

                columnMenu.addSeparator();
                QAction* showAllAction = columnMenu.addAction(
                    QIcon(QStringLiteral(":/Icon/filter_funnel.svg")),
                    QStringLiteral("显示全部列"));
                showAllAction->setToolTip(QStringLiteral("取消所有列隐藏，恢复完整证据视图"));
                QObject::connect(showAllAction, &QAction::triggered, table, [table]() {
                    for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
                    {
                        table->setColumnHidden(columnIndex, false);
                    }
                    ks::ui::requestTableColumnAutoFit(table);
                });

                columnMenu.exec(header->mapToGlobal(localPosition));
            });
    }

    void setProcessEvidenceDiagnosticRow(
        QTableWidget* table,
        const QString& detailText)
    {
        // setProcessEvidenceDiagnosticRow：
        // - Input: target process memory evidence table and diagnostic description;
        // - Processing: Write a copyable diagnostic line; store full text in UserRole+2.
        // - Returns: None. Prevents null table issues during attachment failure, empty cache, or filtered empty results.
        if (table == nullptr)
        {
            return;
        }

        table->setRowCount(1);
        QTableWidgetItem* vaItem = makeItem(QStringLiteral("<无进程内存证据>"));
        vaItem->setData(Qt::UserRole + 2, detailText);
        table->setItem(0, evidenceColumnIndex(ProcessMemoryEvidenceColumn::kVirtualAddress), vaItem);
        table->setItem(0, evidenceColumnIndex(ProcessMemoryEvidenceColumn::kRegionBase), makeItem(QStringLiteral("N/A")));
        table->setItem(0, evidenceColumnIndex(ProcessMemoryEvidenceColumn::kRegionSize), makeItem(QStringLiteral("N/A")));
        table->setItem(0, evidenceColumnIndex(ProcessMemoryEvidenceColumn::kProtect), makeItem(QStringLiteral("N/A")));
        table->setItem(0, evidenceColumnIndex(ProcessMemoryEvidenceColumn::kState), makeItem(QStringLiteral("N/A")));
        table->setItem(0, evidenceColumnIndex(ProcessMemoryEvidenceColumn::kType), makeItem(QStringLiteral("诊断")));
        table->setItem(0, evidenceColumnIndex(ProcessMemoryEvidenceColumn::kValid), makeItem(QStringLiteral("-")));
        table->setItem(0, evidenceColumnIndex(ProcessMemoryEvidenceColumn::kShared), makeItem(QStringLiteral("-")));
        table->setItem(0, evidenceColumnIndex(ProcessMemoryEvidenceColumn::kLocked), makeItem(QStringLiteral("-")));
        table->setItem(0, evidenceColumnIndex(ProcessMemoryEvidenceColumn::kLargePage), makeItem(QStringLiteral("-")));
        table->setItem(0, evidenceColumnIndex(ProcessMemoryEvidenceColumn::kBad), makeItem(QStringLiteral("-")));
        table->setItem(0, evidenceColumnIndex(ProcessMemoryEvidenceColumn::kShareCount), makeItem(QStringLiteral("0")));
        table->setItem(0, evidenceColumnIndex(ProcessMemoryEvidenceColumn::kNode), makeItem(QStringLiteral("-")));
        table->setItem(0, evidenceColumnIndex(ProcessMemoryEvidenceColumn::kWin32Protection), makeItem(QStringLiteral("N/A")));
        table->setItem(0, evidenceColumnIndex(ProcessMemoryEvidenceColumn::kMappedFile), makeItem(QStringLiteral("N/A")));
        table->setItem(0, evidenceColumnIndex(ProcessMemoryEvidenceColumn::kRisk), makeItem(detailText));
        table->setCurrentCell(0, evidenceColumnIndex(ProcessMemoryEvidenceColumn::kVirtualAddress));
    }
}

void MemoryDock::initializeProcessMemoryEvidenceTab()
{
    // Input: None; called by initializeTabs.
    // Handling: Build the read-only process memory evidence page, performing risk projection around VirtualQueryEx / QueryWorkingSetEx.
    // Returns: Nothing.
    KLogEvent initEvent;
    info << initEvent
        << "[MemoryDock] initializeProcessMemoryEvidenceTab: 构建进程内存证据页面。"
        << eol;

    tabProcessMemoryEvidence_ = new QWidget(tabWidget_);
    QVBoxLayout* tabLayout = new QVBoxLayout(tabProcessMemoryEvidence_);
    tabLayout->setContentsMargins(6, 6, 6, 6);
    tabLayout->setSpacing(6);

    // First-level action row: only refresh, two filter toggles, and status label. Previously, eleven controls crammed into one row were unreadable.
    QHBoxLayout* actionLayout = new QHBoxLayout();
    actionLayout->setContentsMargins(0, 0, 0, 0);
    actionLayout->setSpacing(8);

    processMemoryEvidenceRefreshButton_ = new QPushButton(QIcon(QStringLiteral(":/Icon/process_refresh.svg")), QStringLiteral("刷新"), tabProcessMemoryEvidence_);
    processMemoryEvidenceRefreshButton_->setToolTip(QStringLiteral("按当前附加进程采集内存证据"));
    processMemoryEvidenceRefreshButton_->setStyleSheet(buildBlueButtonStyle());

    // The vertical line separator visually divides the action area from the switch area, using the dynamic border color to follow theme changes.
    QFrame* actionSeparator = new QFrame(tabProcessMemoryEvidence_);
    actionSeparator->setFrameShape(QFrame::VLine);
    actionSeparator->setFrameShadow(QFrame::Plain);
    actionSeparator->setFixedWidth(1);
    actionSeparator->setStyleSheet(QStringLiteral("color:%1;").arg(ksword_theme::borderHex()));

    processMemoryEvidenceRiskOnlyCheck_ = new QCheckBox(QStringLiteral("仅显示风险项"), tabProcessMemoryEvidence_);
    processMemoryEvidenceRiskOnlyCheck_->setChecked(true);
    processMemoryEvidenceRiskOnlyCheck_->setToolTip(QStringLiteral("只列出命中风险规则的页，风险为正常的页不进表"));
    processMemoryEvidenceRiskOnlyCheck_->setStyleSheet(QStringLiteral(
        "QCheckBox { color:%1; font-weight:600; }")
        .arg(ksword_theme::textPrimaryHex()));

    processMemoryEvidenceImageOnlyCheck_ = new QCheckBox(QStringLiteral("仅映像区域"), tabProcessMemoryEvidence_);
    processMemoryEvidenceImageOnlyCheck_->setToolTip(QStringLiteral("只采集 MEM_IMAGE 映像区域，跳过私有与映射区域"));

    processMemoryEvidenceStatusLabel_ = new QLabel(QStringLiteral("状态：等待刷新"), tabProcessMemoryEvidence_);
    processMemoryEvidenceStatusLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    processMemoryEvidenceStatusLabel_->setStyleSheet(QStringLiteral("color:%1; font-weight:600;").arg(ksword_theme::textSecondaryHex()));

    actionLayout->addWidget(processMemoryEvidenceRefreshButton_);
    actionLayout->addWidget(actionSeparator);
    actionLayout->addWidget(processMemoryEvidenceRiskOnlyCheck_);
    actionLayout->addWidget(processMemoryEvidenceImageOnlyCheck_);
    actionLayout->addWidget(processMemoryEvidenceStatusLabel_, 1);
    tabLayout->addLayout(actionLayout);

    // Second-level scan scope group: four labeled inputs arranged in a 2x2 grid; field names are no longer bare labels squeezed into the action row.
    QGroupBox* scopeGroup = new QGroupBox(QStringLiteral("扫描范围"), tabProcessMemoryEvidence_);
    QGridLayout* scopeLayout = new QGridLayout(scopeGroup);
    scopeLayout->setContentsMargins(10, 8, 10, 8);
    scopeLayout->setHorizontalSpacing(8);
    scopeLayout->setVerticalSpacing(6);

    processMemoryEvidenceStartEdit_ = new QLineEdit(scopeGroup);
    processMemoryEvidenceStartEdit_->setClearButtonEnabled(true);
    processMemoryEvidenceStartEdit_->setPlaceholderText(QStringLiteral("留空从进程最低地址开始"));
    processMemoryEvidenceStartEdit_->setToolTip(QStringLiteral("采样起始虚拟地址。无前缀按十六进制解释，也可显式写 0x 前缀。"));
    processMemoryEvidenceStartEdit_->setStyleSheet(buildBlueInputStyle());

    processMemoryEvidenceEndEdit_ = new QLineEdit(scopeGroup);
    processMemoryEvidenceEndEdit_->setClearButtonEnabled(true);
    processMemoryEvidenceEndEdit_->setPlaceholderText(QStringLiteral("留空到进程最高地址结束"));
    processMemoryEvidenceEndEdit_->setToolTip(QStringLiteral("采样结束虚拟地址。无前缀按十六进制解释，也可显式写 0x 前缀。"));
    processMemoryEvidenceEndEdit_->setStyleSheet(buildBlueInputStyle());

    processMemoryEvidenceFilterEdit_ = new QLineEdit(scopeGroup);
    processMemoryEvidenceFilterEdit_->setClearButtonEnabled(true);
    processMemoryEvidenceFilterEdit_->setPlaceholderText(QStringLiteral("过滤映射文件 / 风险文本"));
    processMemoryEvidenceFilterEdit_->setToolTip(QStringLiteral("按映射文件路径、风险描述或证据说明实时过滤已采样的行"));
    processMemoryEvidenceFilterEdit_->setStyleSheet(buildBlueInputStyle());

    processMemoryEvidenceMaxRowsSpin_ = new QSpinBox(scopeGroup);
    processMemoryEvidenceMaxRowsSpin_->setRange(32, 8192);
    processMemoryEvidenceMaxRowsSpin_->setValue(512);
    processMemoryEvidenceMaxRowsSpin_->setToolTip(QStringLiteral("单次采样最大页数"));

    // Make the four field names formal labels, unify the secondary text color, and avoid competing with input content for visual focus.
    QLabel* startFieldLabel = new QLabel(QStringLiteral("起始地址"), scopeGroup);
    QLabel* endFieldLabel = new QLabel(QStringLiteral("结束地址"), scopeGroup);
    QLabel* maxRowsFieldLabel = new QLabel(QStringLiteral("最大行数"), scopeGroup);
    QLabel* filterFieldLabel = new QLabel(QStringLiteral("文本过滤"), scopeGroup);
    for (QLabel* fieldLabel : { startFieldLabel, endFieldLabel, maxRowsFieldLabel, filterFieldLabel })
    {
        fieldLabel->setStyleSheet(QStringLiteral("color:%1;").arg(ksword_theme::textSecondaryHex()));
    }

    scopeLayout->addWidget(startFieldLabel, 0, 0);
    scopeLayout->addWidget(processMemoryEvidenceStartEdit_, 0, 1);
    scopeLayout->addWidget(endFieldLabel, 0, 2);
    scopeLayout->addWidget(processMemoryEvidenceEndEdit_, 0, 3);
    scopeLayout->addWidget(maxRowsFieldLabel, 1, 0);
    scopeLayout->addWidget(processMemoryEvidenceMaxRowsSpin_, 1, 1);
    scopeLayout->addWidget(filterFieldLabel, 1, 2);
    scopeLayout->addWidget(processMemoryEvidenceFilterEdit_, 1, 3);
    scopeLayout->setColumnStretch(1, 1);
    scopeLayout->setColumnStretch(3, 2);
    tabLayout->addWidget(scopeGroup);

    QSplitter* splitter = new QSplitter(Qt::Vertical, tabProcessMemoryEvidence_);
    tabLayout->addWidget(splitter, 1);

    processMemoryEvidenceTable_ = new ks::ui::VisibleTableWidget(splitter);
    processMemoryEvidenceTable_->setColumnCount(evidenceColumnIndex(ProcessMemoryEvidenceColumn::kCount));
    processMemoryEvidenceTable_->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("虚拟地址"),
        QStringLiteral("区域基址"),
        QStringLiteral("区域大小"),
        QStringLiteral("保护"),
        QStringLiteral("状态"),
        QStringLiteral("类型"),
        QStringLiteral("有效"),
        QStringLiteral("共享"),
        QStringLiteral("锁定"),
        QStringLiteral("大页"),
        QStringLiteral("坏页"),
        QStringLiteral("共享计数"),
        QStringLiteral("NUMA 节点"),
        QStringLiteral("Win32Prot"),
        QStringLiteral("映射文件"),
        QStringLiteral("风险")
    });
    processMemoryEvidenceTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    processMemoryEvidenceTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    processMemoryEvidenceTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    processMemoryEvidenceTable_->setAlternatingRowColors(true);
    processMemoryEvidenceTable_->setSortingEnabled(true);
    processMemoryEvidenceTable_->verticalHeader()->setVisible(false);
    processMemoryEvidenceTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    processMemoryEvidenceTable_->horizontalHeader()->setSectionResizeMode(evidenceColumnIndex(ProcessMemoryEvidenceColumn::kMappedFile), QHeaderView::Stretch);
    installEvidenceCopyMenu(processMemoryEvidenceTable_);
    // The 16-column table must provide a column collapse entry; otherwise, users can only find their columns of interest via the horizontal scrollbar.
    installEvidenceColumnMenu(processMemoryEvidenceTable_);
    splitter->addWidget(processMemoryEvidenceTable_);

    processMemoryEvidenceDetailEditor_ = new CodeEditorWidget(splitter);
    processMemoryEvidenceDetailEditor_->setReadOnly(true);
    processMemoryEvidenceDetailEditor_->setText(QStringLiteral("请选择一条进程内存证据记录查看详情。"));
    splitter->addWidget(processMemoryEvidenceDetailEditor_);

    ks::ui::DetailLayoutRegistry::registerHost(
        processMemoryEvidenceTable_,
        processMemoryEvidenceDetailEditor_,
        tabProcessMemoryEvidence_);
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);

    tabWidget_->addTab(tabProcessMemoryEvidence_, QStringLiteral("进程内存证据"));
}

void MemoryDock::refreshProcessMemoryEvidenceAsync()
{
    // Input: None; triggered by the refresh button or tab routing.
    // Note: Collect VirtualQueryEx / QueryWorkingSetEx evidence based on the address range of the currently attached process.
    // Returns: Nothing.
    if (processMemoryEvidenceRefreshInProgress_.exchange(true))
    {
        return;
    }

    // Immediately lock the refresh button and update the progress text after acquiring the collection lock: collection must traverse the entire user-mode
    // address space; without feedback, users may think the interface is frozen and click repeatedly, causing duplicate refresh requests to queue up.
    if (processMemoryEvidenceRefreshButton_ != nullptr)
    {
        processMemoryEvidenceRefreshButton_->setEnabled(false);
    }
    if (processMemoryEvidenceStatusLabel_ != nullptr)
    {
        processMemoryEvidenceStatusLabel_->setText(QStringLiteral("状态：正在采集进程内存证据…"));
        processMemoryEvidenceStatusLabel_->setStyleSheet(
            QStringLiteral("color:%1; font-weight:600;").arg(ksword_theme::textSecondaryHex()));
    }

    if (attachedProcessHandle_ == nullptr || attachedPid_ == 0U)
    {
        processMemoryEvidenceRefreshInProgress_.store(false);
        // Unlock the button even on early failure; otherwise, the refresh button will remain permanently disabled if no process is attached.
        if (processMemoryEvidenceRefreshButton_ != nullptr)
        {
            processMemoryEvidenceRefreshButton_->setEnabled(true);
        }
        if (processMemoryEvidenceStatusLabel_ != nullptr)
        {
            processMemoryEvidenceStatusLabel_->setText(QStringLiteral("状态：请先附加进程。"));
            processMemoryEvidenceStatusLabel_->setStyleSheet(
                QStringLiteral("color:%1; font-weight:600;")
                    .arg(ksword_theme::errorColor().name(QColor::HexRgb)));
        }
        return;
    }

    std::uint32_t duplicateError = ERROR_SUCCESS;
    const std::shared_ptr<void> kProcessHandleLease =
        duplicateAttachedProcessHandleForWorker(&duplicateError);
    if (!kProcessHandleLease)
    {
        processMemoryEvidenceRefreshInProgress_.store(false);
        if (processMemoryEvidenceRefreshButton_ != nullptr)
        {
            processMemoryEvidenceRefreshButton_->setEnabled(true);
        }
        if (processMemoryEvidenceStatusLabel_ != nullptr)
        {
            processMemoryEvidenceStatusLabel_->setText(
                QStringLiteral("状态：复制进程句柄失败（Win32=%1）。").arg(duplicateError));
            processMemoryEvidenceStatusLabel_->setStyleSheet(
                QStringLiteral("color:%1; font-weight:600;")
                    .arg(ksword_theme::errorColor().name(QColor::HexRgb)));
        }
        return;
    }

    std::uint64_t startAddress = 0ULL;
    std::uint64_t endAddress = 0ULL;
    if (processMemoryEvidenceStartEdit_ != nullptr)
    {
        parseAddressText(processMemoryEvidenceStartEdit_->text().trimmed(), startAddress);
    }
    if (processMemoryEvidenceEndEdit_ != nullptr)
    {
        parseAddressText(processMemoryEvidenceEndEdit_->text().trimmed(), endAddress);
    }

    const std::uint32_t kMaxRows = processMemoryEvidenceMaxRowsSpin_ != nullptr
        ? static_cast<std::uint32_t>(processMemoryEvidenceMaxRowsSpin_->value())
        : 512U;
    const bool kImageOnly = processMemoryEvidenceImageOnlyCheck_ != nullptr && processMemoryEvidenceImageOnlyCheck_->isChecked();

    const std::uint64_t kTicket = processMemoryEvidenceRefreshTicket_.fetch_add(1U) + 1U;
    const std::uint64_t kAttachmentGeneration = processAttachmentGeneration_.load();
    const QPointer<MemoryDock> kGuardThis(this);

    std::thread([kGuardThis,
                 kProcessHandleLease,
                 kTicket,
                 kAttachmentGeneration,
                 startAddress,
                 endAddress,
                 kMaxRows,
                 kImageOnly]() {
        const HANDLE kWorkerProcessHandle = static_cast<HANDLE>(kProcessHandleLease.get());
        std::vector<ProcessMemoryEvidenceEntry> entries;
        SYSTEM_INFO systemInfo{};
        ::GetSystemInfo(&systemInfo);
        const std::uint64_t kPageSize = static_cast<std::uint64_t>(systemInfo.dwPageSize);
        const std::uint64_t kMinAddress = reinterpret_cast<std::uintptr_t>(systemInfo.lpMinimumApplicationAddress);
        const std::uint64_t kMaxAddress = reinterpret_cast<std::uintptr_t>(systemInfo.lpMaximumApplicationAddress);
        std::uint64_t currentAddress = startAddress != 0ULL ? startAddress : kMinAddress;
        const std::uint64_t kStopAddress = endAddress != 0ULL ? endAddress : kMaxAddress;
        if (kPageSize != 0ULL)
        {
            currentAddress = (currentAddress / kPageSize) * kPageSize;
        }

        while (currentAddress < kStopAddress && entries.size() < kMaxRows)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (::VirtualQueryEx(
                    kWorkerProcessHandle,
                    reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(currentAddress)),
                    &mbi,
                    sizeof(mbi)) != sizeof(mbi))
            {
                break;
            }

            const std::uint64_t kRegionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            const std::uint64_t kRegionSize = static_cast<std::uint64_t>(mbi.RegionSize);
            const bool kRegionIsImage = mbi.Type == MEM_IMAGE;
            if (kImageOnly && !kRegionIsImage)
            {
                const std::uint64_t kNextAddress = kRegionBase + kRegionSize;
                if (kNextAddress <= currentAddress)
                {
                    break;
                }
                currentAddress = kNextAddress;
                continue;
            }

            const std::uint64_t kPageCount = kPageSize == 0ULL ? 1ULL : std::max<std::uint64_t>(1ULL, kRegionSize / kPageSize);
            for (std::uint64_t pageIndex = 0; pageIndex < kPageCount && entries.size() < kMaxRows; ++pageIndex)
            {
                const std::uint64_t kVa = kRegionBase + (pageIndex * kPageSize);
                if (kVa >= kStopAddress)
                {
                    break;
                }

                PSAPI_WORKING_SET_EX_INFORMATION wsInfo{};
                wsInfo.VirtualAddress = reinterpret_cast<PVOID>(static_cast<std::uintptr_t>(kVa));
                const BOOL kQueryOk = ::QueryWorkingSetEx(
                    kWorkerProcessHandle,
                    &wsInfo,
                    static_cast<DWORD>(sizeof(wsInfo)));

                ProcessMemoryEvidenceEntry entry{};
                entry.virtualAddress = kVa;
                entry.regionBaseAddress = kRegionBase;
                entry.regionSize = kRegionSize;
                entry.protect = static_cast<std::uint32_t>(mbi.Protect);
                entry.state = static_cast<std::uint32_t>(mbi.State);
                entry.type = static_cast<std::uint32_t>(mbi.Type);
                entry.mappedFilePath = (mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED) ? QStringLiteral("") : QString();

                if (kQueryOk != FALSE)
                {
                    entry.valid = wsInfo.VirtualAttributes.Valid != 0;
                    entry.shared = wsInfo.VirtualAttributes.Shared != 0;
                    entry.locked = wsInfo.VirtualAttributes.Locked != 0;
                    entry.largePage = wsInfo.VirtualAttributes.LargePage != 0;
                    entry.bad = wsInfo.VirtualAttributes.Bad != 0;
                    entry.shareCount = static_cast<std::uint32_t>(wsInfo.VirtualAttributes.ShareCount);
                    entry.win32Protection = static_cast<std::uint32_t>(wsInfo.VirtualAttributes.Win32Protection);
                    entry.node = static_cast<std::uint32_t>(wsInfo.VirtualAttributes.Node);
                }

                entry.riskText = buildRiskText(entry.protect, entry.state, entry.type, entry.valid, entry.largePage, entry.bad);
                entry.detailText = QStringLiteral("VirtualQueryEx + QueryWorkingSetEx 只读证据");
                entries.push_back(std::move(entry));
            }

            const std::uint64_t kNextAddress = kRegionBase + kRegionSize;
            if (kNextAddress <= currentAddress)
            {
                break;
            }
            currentAddress = kNextAddress;
        }

        QMetaObject::invokeMethod(
            kGuardThis.data(),
            [kGuardThis, kTicket, kAttachmentGeneration, entries = std::move(entries)]() mutable {
                auto entriesSnapshot =
                    std::make_shared<std::vector<ProcessMemoryEvidenceEntry>>(std::move(entries));
                auto commitSnapshot = [kGuardThis, kTicket, kAttachmentGeneration, entriesSnapshot]() mutable
                {
                    if (kGuardThis == nullptr ||
                        kTicket != kGuardThis->processMemoryEvidenceRefreshTicket_.load() ||
                        kAttachmentGeneration != kGuardThis->processAttachmentGeneration_.load())
                    {
                        return;
                    }

                    kGuardThis->processMemoryEvidenceRefreshInProgress_.store(false);
                    if (kGuardThis->processMemoryEvidenceRefreshButton_ != nullptr)
                    {
                        kGuardThis->processMemoryEvidenceRefreshButton_->setEnabled(true);
                    }

                    kGuardThis->processMemoryEvidenceCache_ = std::move(*entriesSnapshot);
                    kGuardThis->rebuildProcessMemoryEvidenceTable();
                    kGuardThis->showProcessMemoryEvidenceDetailByCurrentRow();
                    if (kGuardThis->processMemoryEvidenceStatusLabel_ != nullptr)
                    {
                        kGuardThis->processMemoryEvidenceStatusLabel_->setText(
                            QStringLiteral("状态：采样 %1 行").arg(kGuardThis->processMemoryEvidenceCache_.size()));
                        kGuardThis->processMemoryEvidenceStatusLabel_->setStyleSheet(QStringLiteral(
                            "color:%1; font-weight:600;")
                            .arg(kGuardThis->processMemoryEvidenceCache_.empty()
                                ? ksword_theme::errorColor().name(QColor::HexRgb)
                                : ksword_theme::successColor().name(QColor::HexRgb)));
                    }
                };

                if (ks::ui::deferTableUiCommitIfContextMenuOpen(
                    kGuardThis.data(),
                    QStringLiteral("memory-process-evidence-snapshot"),
                    { kGuardThis->processMemoryEvidenceTable_ },
                    commitSnapshot))
                {
                    return;
                }
                commitSnapshot();
            },
            Qt::QueuedConnection);
    }).detach();
}

void MemoryDock::rebuildProcessMemoryEvidenceTable()
{
    ks::ui::DetailLayoutRegistry::prepareDataRebuild(processMemoryEvidenceDetailEditor_);
    // Input: Reads the current cache and filter options.
    // Processing: Project process memory evidence into a read-only table.
    // Returns: Nothing.
    if (processMemoryEvidenceTable_ == nullptr)
    {
        return;
    }

    const bool kRiskOnly = processMemoryEvidenceRiskOnlyCheck_ != nullptr && processMemoryEvidenceRiskOnlyCheck_->isChecked();
    const QString kFilterText = processMemoryEvidenceFilterEdit_ != nullptr
        ? processMemoryEvidenceFilterEdit_->text().trimmed()
        : QString();

    std::vector<const ProcessMemoryEvidenceEntry*> visibleEntries;
    visibleEntries.reserve(processMemoryEvidenceCache_.size());
    for (const ProcessMemoryEvidenceEntry& entry : processMemoryEvidenceCache_)
    {
        if (kRiskOnly && entry.riskText == QStringLiteral("正常"))
        {
            continue;
        }
        if (!kFilterText.isEmpty())
        {
            const QString kDetailText = entry.detailText;
            const QString kMappedText = entry.mappedFilePath;
            if (!kDetailText.contains(kFilterText, Qt::CaseInsensitive) &&
                !kMappedText.contains(kFilterText, Qt::CaseInsensitive) &&
                !entry.riskText.contains(kFilterText, Qt::CaseInsensitive))
            {
                continue;
            }
        }
        visibleEntries.push_back(&entry);
    }

    processMemoryEvidenceVisibleCount_ = visibleEntries.size();
    const QSignalBlocker kBlocker(processMemoryEvidenceTable_);
    processMemoryEvidenceTable_->setSortingEnabled(false);
    processMemoryEvidenceTable_->setRowCount(static_cast<int>(visibleEntries.size()));
    for (int row = 0; row < static_cast<int>(visibleEntries.size()); ++row)
    {
        const ProcessMemoryEvidenceEntry& entry = *visibleEntries[static_cast<std::size_t>(row)];
        // Address, size, count, and node ID must use numeric-sort cells; otherwise, sorting by display text would degrade to string order.
        processMemoryEvidenceTable_->setItem(row, evidenceColumnIndex(ProcessMemoryEvidenceColumn::kVirtualAddress), makeNumericItem(hex64(entry.virtualAddress), entry.virtualAddress));
        processMemoryEvidenceTable_->setItem(row, evidenceColumnIndex(ProcessMemoryEvidenceColumn::kRegionBase), makeNumericItem(hex64(entry.regionBaseAddress), entry.regionBaseAddress));
        processMemoryEvidenceTable_->setItem(row, evidenceColumnIndex(ProcessMemoryEvidenceColumn::kRegionSize), makeNumericItem(hex64(entry.regionSize), entry.regionSize));
        processMemoryEvidenceTable_->setItem(row, evidenceColumnIndex(ProcessMemoryEvidenceColumn::kProtect), makeItem(protectText(entry.protect)));
        processMemoryEvidenceTable_->setItem(row, evidenceColumnIndex(ProcessMemoryEvidenceColumn::kState), makeItem(stateText(entry.state)));
        processMemoryEvidenceTable_->setItem(row, evidenceColumnIndex(ProcessMemoryEvidenceColumn::kType), makeItem(typeText(entry.type)));
        processMemoryEvidenceTable_->setItem(row, evidenceColumnIndex(ProcessMemoryEvidenceColumn::kValid), makeItem(entry.valid ? QStringLiteral("Yes") : QStringLiteral("No")));
        processMemoryEvidenceTable_->setItem(row, evidenceColumnIndex(ProcessMemoryEvidenceColumn::kShared), makeItem(entry.shared ? QStringLiteral("Yes") : QStringLiteral("No")));
        processMemoryEvidenceTable_->setItem(row, evidenceColumnIndex(ProcessMemoryEvidenceColumn::kLocked), makeItem(entry.locked ? QStringLiteral("Yes") : QStringLiteral("No")));
        processMemoryEvidenceTable_->setItem(row, evidenceColumnIndex(ProcessMemoryEvidenceColumn::kLargePage), makeItem(entry.largePage ? QStringLiteral("Yes") : QStringLiteral("No")));
        processMemoryEvidenceTable_->setItem(row, evidenceColumnIndex(ProcessMemoryEvidenceColumn::kBad), makeItem(entry.bad ? QStringLiteral("Yes") : QStringLiteral("No")));
        processMemoryEvidenceTable_->setItem(row, evidenceColumnIndex(ProcessMemoryEvidenceColumn::kShareCount), makeNumericItem(QString::number(entry.shareCount), entry.shareCount));
        processMemoryEvidenceTable_->setItem(row, evidenceColumnIndex(ProcessMemoryEvidenceColumn::kNode), makeNumericItem(QString::number(entry.node), entry.node));
        processMemoryEvidenceTable_->setItem(row, evidenceColumnIndex(ProcessMemoryEvidenceColumn::kWin32Protection), makeNumericItem(QStringLiteral("0x%1").arg(entry.win32Protection, 8, 16, QChar('0')).toUpper(), entry.win32Protection));
        processMemoryEvidenceTable_->setItem(row, evidenceColumnIndex(ProcessMemoryEvidenceColumn::kMappedFile), makeItem(entry.mappedFilePath.isEmpty() ? QStringLiteral("—") : entry.mappedFilePath));
        processMemoryEvidenceTable_->setItem(row, evidenceColumnIndex(ProcessMemoryEvidenceColumn::kRisk), makeItem(entry.riskText));
    }
    if (visibleEntries.empty())
    {
        const QString kDetailText = processMemoryEvidenceCache_.empty()
            ? QStringLiteral("进程内存证据当前没有缓存行；请先附加进程并刷新，或检查采样范围。")
            : QStringLiteral("当前过滤条件隐藏了全部 %1 条进程内存证据；请清空文本过滤或取消勾选仅显示风险项/仅映像区域。")
                .arg(static_cast<qulonglong>(processMemoryEvidenceCache_.size()));
        setProcessEvidenceDiagnosticRow(processMemoryEvidenceTable_, kDetailText);
    }

    if (processMemoryEvidenceTable_->rowCount() > 0 && processMemoryEvidenceTable_->currentRow() < 0)
    {
        processMemoryEvidenceTable_->setCurrentCell(0, evidenceColumnIndex(ProcessMemoryEvidenceColumn::kVirtualAddress));
    }
    processMemoryEvidenceTable_->setSortingEnabled(true);
    ks::ui::requestTableColumnAutoFit(processMemoryEvidenceTable_);
}

void MemoryDock::showProcessMemoryEvidenceDetailByCurrentRow()
{
    // Input: None. Reads the currently selected row in the table.
    // Processing: expand the current evidence record from cache to the detail editor.
    // Returns: Nothing.
    if (processMemoryEvidenceDetailEditor_ == nullptr || processMemoryEvidenceTable_ == nullptr)
    {
        return;
    }

    const int kRow = processMemoryEvidenceTable_->currentRow();
    if (kRow < 0 || kRow >= processMemoryEvidenceTable_->rowCount())
    {
        processMemoryEvidenceDetailEditor_->setText(QStringLiteral("请选择一条进程内存证据记录查看详情。"));
        return;
    }

    const QTableWidgetItem* addressItem = processMemoryEvidenceTable_->item(kRow, evidenceColumnIndex(ProcessMemoryEvidenceColumn::kVirtualAddress));
    if (addressItem == nullptr)
    {
        return;
    }
    const QString kDiagnosticText = addressItem->data(Qt::UserRole + 2).toString();
    if (!kDiagnosticText.isEmpty())
    {
        processMemoryEvidenceDetailEditor_->setText(QStringLiteral("进程内存证据诊断\n%1").arg(kDiagnosticText));
        return;
    }

    bool ok = false;
    const qulonglong kAddressValue = addressItem->data(Qt::UserRole).toULongLong(&ok);
    if (!ok)
    {
        return;
    }

    for (const ProcessMemoryEvidenceEntry& entry : processMemoryEvidenceCache_)
    {
        if (entry.virtualAddress == static_cast<std::uint64_t>(kAddressValue))
        {
            processMemoryEvidenceDetailEditor_->setText(buildDetailText(entry));
            return;
        }
    }
}
