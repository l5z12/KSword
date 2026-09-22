#include "MemoryDock.Internal.h"
#include "../ui/TableInteractionSupport.h"
#include "../ui/VisibleTableWidget.h"
#include "../ui/DetailLayoutRegistry.h"
/* Unified entry point: this page does not need to know GPA, EPT leaf, or ruleId. */
#include "../ui/KvmWatchDialog.h"

#include <QColor>      // QColor: Used for foreground coloring of risky lines.
#include <QPixmap>
#include <QProgressBar> // QProgressBar: Indeterminate progress bar during scanning.

#include <memory>

using namespace ksword::memory_dock_internal;

namespace
{
    // KernelExecutableColumn:
    // - Input: table column enum used by MemoryDock's kernel executable scan UI.
    // - Processing: keeps column numbers stable when rows are rebuilt or sorted.
    // - Return behavior: enum values are converted to int at call sites.
    enum class KernelExecutableColumn : int
    {
        kVa = 0,
        kRegionSize,
        kPageCount,
        kPageSize,
        kPermissions,
        kOwner,
        kModuleBase,
        kModulePath,
        kRiskFlags,
        kCount
    };

    int kernelExecutableColumnIndex(const KernelExecutableColumn column)
    {
        // Input: KernelExecutableColumn enum value.
        // Processing: Narrow down to the int column index used by QTableWidget.
        // Returns: Corresponding table column index.
        return static_cast<int>(column);
    }

    QString wideToQString(const std::wstring& text)
    {
        // Input: UTF-16 wide string returned by ArkDriverClient.
        // Processing: Uniformly convert to QString; keep empty text as empty.
        // Returns: a QString suitable for Qt UI display and filtering.
        return text.empty() ? QString() : QString::fromStdWString(text);
    }

    QString kernelExecutableIoMessageText(const std::string& messageText)
    {
        // Input: raw io.message returned by ArkDriverClient.
        // Handling: Converts low-level strings such as DeviceIoControl/unsupported/empty messages into user-readable descriptions.
        // Returns: Chinese text suitable for the status bar and details area.
        if (messageText.empty())
        {
            return QStringLiteral("无额外驱动消息");
        }

        const QString kRawText = QString::fromStdString(messageText).trimmed();
        if (kRawText.isEmpty())
        {
            return QStringLiteral("无额外驱动消息");
        }
        if (kRawText.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动接口调用失败或当前驱动版本不支持内核可执行页扫描入口");
        }
        if (kRawText.contains(QStringLiteral("unsupported"), Qt::CaseInsensitive) ||
            kRawText.contains(QStringLiteral("not implemented"), Qt::CaseInsensitive))
        {
            return QStringLiteral("当前驱动版本尚未提供内核可执行页扫描入口");
        }
        if (kRawText.contains(QStringLiteral("too small"), Qt::CaseInsensitive) ||
            kRawText.contains(QStringLiteral("invalid"), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动返回数据格式不完整，当前扫描结果已丢弃");
        }
        return kRawText;
    }

    QString hexValue(const std::uint64_t value)
    {
        // Input: 64-bit diagnostic value.
        // Processing: Format as fixed-width hexadecimal for text display, separate from address column sorting.
        // Return value: Uppercase hexadecimal string with 0x prefix.
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(value), 16, 16, QChar('0'))
            .toUpper();
    }

    QString byteSizeText(const std::uint64_t byteCount)
    {
        // Input: byte count, used for columns requiring volume comparison such as region size.
        // Note: Convert to KB/MB/GB using a 1024 base; retain raw byte counts for values < 1KB to avoid rounding small page ranges to zero.
        // Returns: Human-readable text with units; actual sorting is based on the raw byte count provided by NumericTableItem.
        constexpr double kUnitStep = 1024.0;
        if (byteCount < 1024ULL)
        {
            return QStringLiteral("%1 B").arg(static_cast<qulonglong>(byteCount));
        }

        double scaledValue = static_cast<double>(byteCount) / kUnitStep;
        // The unit table starts at KB and goes up to TB; when the range is exceeded, it stays at the last unit while scaling the value.
        constexpr int kUnitCount = 4;
        const char* const kUnitNames[kUnitCount] = { "KB", "MB", "GB", "TB" };
        int unitIndex = 0;
        while (scaledValue >= kUnitStep && unitIndex + 1 < kUnitCount)
        {
            scaledValue /= kUnitStep;
            ++unitIndex;
        }
        return QStringLiteral("%1 %2")
            .arg(scaledValue, 0, 'f', 2)
            .arg(QString::fromLatin1(kUnitNames[unitIndex]));
    }

    QString permissionText(const std::uint32_t flags)
    {
        // Input: KernelExecutableMemoryPermission* bitset.
        // Processing: Convert to compact permission text, preserving diagnostic bits like NX/Large/User/Global.
        // Returns: a permission display string, e.g., R-X | Large | Global.
        QStringList parts;
        QString rwx;
        rwx += (flags & ksword::ark::kKernelExecutableMemoryPermissionPresent) ? QChar('R') : QChar('-');
        rwx += (flags & ksword::ark::kKernelExecutableMemoryPermissionWritable) ? QChar('W') : QChar('-');
        rwx += (flags & ksword::ark::kKernelExecutableMemoryPermissionNoExecute) ? QChar('-') : QChar('X');
        parts << rwx;
        if (flags & ksword::ark::kKernelExecutableMemoryPermissionNoExecute)
        {
            parts << QStringLiteral("NX");
        }
        if (flags & ksword::ark::kKernelExecutableMemoryPermissionLargePage)
        {
            parts << QStringLiteral("Large");
        }
        if (flags & ksword::ark::kKernelExecutableMemoryPermissionUser)
        {
            parts << QStringLiteral("User");
        }
        if (flags & ksword::ark::kKernelExecutableMemoryPermissionGlobal)
        {
            parts << QStringLiteral("Global");
        }
        return parts.join(QStringLiteral(" | "));
    }

    QString riskFlagsText(const std::uint32_t flags)
    {
        // Input: bitset from KernelExecutableMemoryRisk*.
        // Note: Map risk bits to short labels for analysts.
        // Return: "Normal" if no risk is detected; otherwise, return risk tags separated by pipes.
        if (flags == 0U)
        {
            return QStringLiteral("正常");
        }

        QStringList parts;
        if (flags & ksword::ark::kKernelExecutableMemoryRiskWritableExecutable)
        {
            parts << QStringLiteral("WX");
        }
        if (flags & ksword::ark::kKernelExecutableMemoryRiskModuleNonTextExecutable)
        {
            parts << QStringLiteral("非.text可执行");
        }
        if (flags & ksword::ark::kKernelExecutableMemoryRiskSectionWritable)
        {
            parts << QStringLiteral("节可写");
        }
        if (flags & ksword::ark::kKernelExecutableMemoryRiskLargePage)
        {
            parts << QStringLiteral("大页");
        }
        // The normal state of a code section page is read-only executable; the following two items are traces left after changing RX to RW.
        if (flags & ksword::ark::kKernelExecutableMemoryRiskCodePageNotExecutable)
        {
            parts << QStringLiteral("代码页不可执行");
        }
        if (flags & ksword::ark::kKernelExecutableMemoryRiskCodePageWritable)
        {
            parts << QStringLiteral("代码页可写");
        }
        return parts.join(QStringLiteral(" | "));
    }

    QColor kernelExecutableRiskColor(const std::uint32_t flags)
    {
        // Input: bitset from KernelExecutableMemoryRisk*.
        // Processing: Treat 'writable and executable' risks (suitable for direct shellcode injection) as errors; treat other risk flags as warnings.
        // Return: On no risk, return an invalid QColor (caller skips coloring based on this); otherwise, return the foreground color for this line.
        // Note: We deliberately use snapshot functions errorColor()/warningColor() here—row-by-row coloring occurs during each table
        //       fill. Theme switching triggers a table refresh, so colors naturally follow. This is a valid usage of snapshot tokens.
        if (flags == 0U)
        {
            return QColor();
        }

        constexpr std::uint32_t kSevereRiskMask =
            ksword::ark::kKernelExecutableMemoryRiskWritableExecutable |
            ksword::ark::kKernelExecutableMemoryRiskSectionWritable |
            ksword::ark::kKernelExecutableMemoryRiskCodePageWritable;
        if ((flags & kSevereRiskMask) != 0U)
        {
            return ksword_theme::errorColor();
        }
        return ksword_theme::warningColor();
    }

    QString ownerKindText(const std::uint32_t ownerKind)
    {
        // Input: ownerKind enum value from Prompt-1 response.
        // Note: Only map UI text based on ownerKind defined in the shared protocol, without inferring additional semantics.
        // Returns: Chinese category text directly displayable in the Owner column and detail view.
        switch (ownerKind)
        {
        case KSWORD_ARK_KERNEL_EXEC_OWNER_MODULE_TEXT:
            return QStringLiteral("模块 .text");
        case KSWORD_ARK_KERNEL_EXEC_OWNER_MODULE_NON_TEXT:
            return QStringLiteral("模块非 .text");
        case KSWORD_ARK_KERNEL_EXEC_OWNER_MODULE_WRITABLE_EXECUTABLE:
            return QStringLiteral("模块 WX");
        case KSWORD_ARK_KERNEL_EXEC_OWNER_UNKNOWN:
        default:
            return QStringLiteral("未知(%1)").arg(ownerKind);
        }
    }

    QTableWidgetItem* createTextItem(const QString& text)
    {
        // Input: Cell display text.
        // Processing: Create a read-only table item and set vertical alignment.
        // Returns: a pointer to the item, which is now managed by QTableWidget.
        QTableWidgetItem* item = new QTableWidgetItem(text);
        item->setTextAlignment(Qt::AlignVCenter | Qt::AlignLeft);
        return item;
    }

    QString kernelExecutableCopyMenuStyle()
    {
        // Inputs: None.
        // Processing: Generate opaque context menu style to prevent black background and black text caused by transparent parent containers.
        // Returns: a style string that can be directly set on a QMenu.
        // Right-click menus always use the global theme implementation to avoid each page having its own drifting QSS fragments.
        return ksword_theme::contextMenuStyle();
    }

    QString kernelExecutableRowText(QTableWidget* table, const int rowIndex)
    {
        // Input: Kernel executable page table and target row index.
        // Processing: Read cells in current column order and concatenate as TSV.
        // Returns: single-line text writable to the clipboard.
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

    void installKernelExecutableCopyMenu(QTableWidget* table)
    {
        // Input: Kernel executable page scan table.
        // Processing: Install a read-only 'Copy Current Row' menu.
        // Returns: None; triggers no R0 operations.
        if (table == nullptr)
        {
            return;
        }

        table->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(table, &QTableWidget::customContextMenuRequested, table, [table](const QPoint& localPosition)
        {
            const QModelIndex kClickedIndex = table->indexAt(localPosition);
            const int kRowIndex = kClickedIndex.isValid() ? kClickedIndex.row() : table->currentRow();
            if (kClickedIndex.isValid())
            {
                table->setCurrentCell(kClickedIndex.row(), kClickedIndex.column());
                table->selectRow(kClickedIndex.row());
            }

            QMenu menu(table);
            menu.setStyleSheet(kernelExecutableCopyMenuStyle());
            QAction* copyRowAction = menu.addAction(
                QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
                QStringLiteral("复制当前行"));
            copyRowAction->setEnabled(kRowIndex >= 0 && kRowIndex < table->rowCount());

            /*
             * Provide one item for each of the three access types, rather than a single 'monitor' with a secondary menu.
             *
             * Choosing between them isn't a matter of preference; it asks different questions: Write = who modifies it,
             * Execute = who runs it, Read = who scans it. Merging all three into a single entry forces the user to clarify
             * their intent before proceeding, yet the readers of this page are often precisely those who are still uncertain.
             */
            const quint64 kRowAddress = (kRowIndex >= 0 && table->item(kRowIndex, 0) != nullptr)
                ? table->item(kRowIndex, 0)->data(Qt::UserRole).toULongLong()
                : 0ULL;
            menu.addSeparator();
            QMenu* const kWatchMenu = menu.addMenu(QStringLiteral("HVM 监视这一页的下一次访问"));
            kWatchMenu->setStyleSheet(kernelExecutableCopyMenuStyle());
            QAction* const kWatchWrite = kWatchMenu->addAction(QStringLiteral("写入"));
            QAction* const kWatchExecute = kWatchMenu->addAction(QStringLiteral("执行"));
            QAction* const kWatchRead = kWatchMenu->addAction(QStringLiteral("读取"));
            kWatchMenu->setEnabled(kRowAddress != 0ULL);

            QAction* const kChosen = menu.exec(table->viewport()->mapToGlobal(localPosition));
            if (kChosen == copyRowAction)
            {
                QClipboard* clipboard = QApplication::clipboard();
                if (clipboard != nullptr)
                {
                    clipboard->setText(kernelExecutableRowText(table, kRowIndex));
                }
            }
            else if (kRowAddress != 0ULL &&
                     (kChosen == kWatchWrite || kChosen == kWatchExecute || kChosen == kWatchRead))
            {
                ks::ui::HvmWatchRequest request;
                request.virtualAddress = true;
                request.address = kRowAddress;
                // The selected region on this page is a whole executable area, so there are
                // no finer "user-relevant bytes"; thus the request covers the entire page.
                request.length = 0ULL;
                request.access = kChosen == kWatchWrite
                    ? KSWORD_ARK_HVM_EPT_ACCESS_WRITE
                    : kChosen == kWatchExecute
                        ? KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE
                        : KSWORD_ARK_HVM_EPT_ACCESS_READ;
                request.label = QStringLiteral("可执行内核内存 %1")
                    .arg(kRowAddress, 16, 16, QLatin1Char('0'));
                ks::ui::openHvmWatch(table, request);
            }
        });
    }

    void setKernelExecutableDiagnosticRow(
        QTableWidget* table,
        const QString& detailText)
    {
        // setKernelExecutableDiagnosticRow：
        // - Input: Target table and diagnostic text.
        // - Processing: Write a copyable diagnostic line; store full description in UserRole+2.
        // - Returns: None. Used in R0 to avoid leaving only an empty table when the result is null or filtered.
        if (table == nullptr)
        {
            return;
        }

        table->setRowCount(1);
        QTableWidgetItem* vaItem = createTextItem(QStringLiteral("<无可执行页证据>"));
        vaItem->setData(Qt::UserRole + 2, detailText);
        table->setItem(0, kernelExecutableColumnIndex(KernelExecutableColumn::kVa), vaItem);
        table->setItem(0, kernelExecutableColumnIndex(KernelExecutableColumn::kRegionSize), createTextItem(QStringLiteral("N/A")));
        table->setItem(0, kernelExecutableColumnIndex(KernelExecutableColumn::kPageCount), createTextItem(QStringLiteral("N/A")));
        table->setItem(0, kernelExecutableColumnIndex(KernelExecutableColumn::kPageSize), createTextItem(QStringLiteral("N/A")));
        table->setItem(0, kernelExecutableColumnIndex(KernelExecutableColumn::kPermissions), createTextItem(QStringLiteral("N/A")));
        table->setItem(0, kernelExecutableColumnIndex(KernelExecutableColumn::kOwner), createTextItem(QStringLiteral("诊断")));
        table->setItem(0, kernelExecutableColumnIndex(KernelExecutableColumn::kModuleBase), createTextItem(QStringLiteral("N/A")));
        table->setItem(0, kernelExecutableColumnIndex(KernelExecutableColumn::kModulePath), createTextItem(QStringLiteral("N/A")));
        table->setItem(0, kernelExecutableColumnIndex(KernelExecutableColumn::kRiskFlags), createTextItem(detailText));
        table->setCurrentCell(0, kernelExecutableColumnIndex(KernelExecutableColumn::kVa));
    }

    QTableWidgetItem* createNumericItem(const QString& text, const qulonglong numericValue)
    {
        // Input: display text (hex VA, size with unit, or pure numeric count) and the original numeric value used for sorting.
        // Handling: Uniformly switch to the global ks::ui::NumericTableItem; sort by NumericSortRole, ensuring DisplayRole text is not overwritten.
        //       Additionally, write the original value into Qt::UserRole for the details panel to reverse-lookup cache lines by VA (following the legacy lookup convention).
        // Returns: a pointer to the item, which is now managed by QTableWidget.
        ks::ui::NumericTableItem* item = new ks::ui::NumericTableItem(text, numericValue);
        item->setData(Qt::UserRole, QVariant::fromValue<qulonglong>(numericValue));
        item->setTextAlignment(Qt::AlignVCenter | Qt::AlignLeft);
        return item;
    }

    bool entryMatchesModuleFilter(
        const ksword::ark::KernelExecutableMemoryPageEntry& entry,
        const QString& moduleFilter)
    {
        // Input: R3 scan lines and module path filter text.
        // Note: Performs local inclusion matching only on the module path field; empty filter passes immediately.
        // Returns: true if this row should be displayed.
        if (moduleFilter.isEmpty())
        {
            return true;
        }

        return wideToQString(entry.modulePath).contains(moduleFilter, Qt::CaseInsensitive);
    }

    QString buildKernelExecutableDetailText(
        const ksword::ark::KernelExecutableMemoryPageEntry& entry)
    {
        // Input: currently selected kernel executable page scan row.
        // Processing: Generate multi-line diagnostic text suitable for display in CodeEditorWidget.
        // Return: Detail text; the caller directly calls setText.
        QString detailText;
        detailText += QStringLiteral("内核可执行页扫描详情\n");
        detailText += QStringLiteral("VA: %1\n").arg(hexValue(entry.virtualAddress));
        detailText += QStringLiteral("RegionSize: %1\n").arg(hexValue(entry.regionSize));
        detailText += QStringLiteral("PageCount: %1\n").arg(entry.pageCount);
        detailText += QStringLiteral("PageSize: %1\n").arg(entry.pageSize);
        detailText += QStringLiteral("Permissions: %1 (0x%2)\n")
            .arg(permissionText(entry.permissionFlags))
            .arg(entry.permissionFlags, 8, 16, QChar('0'));
        detailText += QStringLiteral("RiskFlags: %1 (0x%2)\n")
            .arg(riskFlagsText(entry.riskFlags))
            .arg(entry.riskFlags, 8, 16, QChar('0'));
        detailText += QStringLiteral("Status: %1\n").arg(entry.status);
        detailText += QStringLiteral("LastStatus: 0x%1\n")
            .arg(static_cast<qulonglong>(static_cast<unsigned long>(entry.lastStatus)), 8, 16, QChar('0'));
        detailText += QStringLiteral("OwnerKind: %1\n").arg(entry.ownerKind);
        detailText += QStringLiteral("Owner: %1\n").arg(ownerKindText(entry.ownerKind));
        detailText += QStringLiteral("OwnerAddress: %1\n").arg(hexValue(entry.ownerAddress));
        detailText += QStringLiteral("ModuleBase: %1\n").arg(hexValue(entry.moduleBase));
        detailText += QStringLiteral("ModuleSize: %1\n").arg(hexValue(entry.moduleSize));
        detailText += QStringLiteral("ModulePath: %1\n").arg(wideToQString(entry.modulePath));

        const QString kR0Detail = wideToQString(entry.detail).trimmed();
        if (!kR0Detail.isEmpty())
        {
            detailText += QStringLiteral("\nR0 Detail:\n%1\n").arg(kR0Detail);
        }
        return detailText;
    }

    QString kernelExecutableStatusStyle(const QString& colorText)
    {
        // Input: Color string.
        // Processing: Uniformly generate status label styles.
        // Returns: CSS text directly usable with setStyleSheet.
        return QStringLiteral("color:%1; font-weight:700;").arg(colorText);
    }
}

void MemoryDock::initializeKernelExecutableMemoryScanTab()
{
    // Input: None; called by initializeTabs.
    // Processing: Build the kernel executable page scan page, including refresh entry, risk/path filtering, table, and detail editor.
    // Returns: Nothing.
    KLogEvent tab7InitEvent;
    info << tab7InitEvent
        << "[MemoryDock] initializeKernelExecutableMemoryScanTab: 构建内核可执行页扫描页面。"
        << eol;

    tabKernelExecutableMemory_ = new QWidget(tabWidget_);
    QVBoxLayout* tabLayout = new QVBoxLayout(tabKernelExecutableMemory_);
    tabLayout->setContentsMargins(6, 6, 6, 6);
    tabLayout->setSpacing(6);

    QHBoxLayout* toolLayout = new QHBoxLayout();
    toolLayout->setContentsMargins(0, 0, 0, 0);
    toolLayout->setSpacing(8);

    kernelExecutableRefreshButton_ = new QPushButton(QIcon(QStringLiteral(":/Icon/process_refresh.svg")), QStringLiteral("刷新"), tabKernelExecutableMemory_);
    kernelExecutableRefreshButton_->setToolTip(QStringLiteral("扫描内核可执行内存"));
    kernelExecutableRefreshButton_->setStyleSheet(buildBlueButtonStyle());

    // Scan progress bar: R0 scanning returns once with no segmented progress to report; use an indeterminate progress bar here to indicate 'In Progress'.
    // Do not add new member variables; refresh the entry by retrieving it via objectName + findChild to avoid modifying MemoryDock.h.
    QProgressBar* scanProgressBar = new QProgressBar(tabKernelExecutableMemory_);
    scanProgressBar->setObjectName(QStringLiteral("kernelExecutableScanProgress"));
    scanProgressBar->setRange(0, 0);
    scanProgressBar->setTextVisible(false);
    scanProgressBar->setFixedWidth(120);
    scanProgressBar->setToolTip(QStringLiteral("内核可执行页扫描进行中"));
    scanProgressBar->setVisible(false);

    kernelExecutableRiskOnlyCheck_ = new QCheckBox(QStringLiteral("仅风险项"), tabKernelExecutableMemory_);
    kernelExecutableRiskOnlyCheck_->setChecked(true);
    kernelExecutableRiskOnlyCheck_->setToolTip(QStringLiteral("只显示风险标志非零的可执行页，取消勾选可查看全部扫描结果"));
    kernelExecutableRiskOnlyCheck_->setStyleSheet(QStringLiteral(
        "QCheckBox { color:%1; font-weight:600; }")
        .arg(ksword_theme::textPrimaryHex()));

    kernelExecutableModuleFilterEdit_ = new QLineEdit(tabKernelExecutableMemory_);
    kernelExecutableModuleFilterEdit_->setClearButtonEnabled(true);
    kernelExecutableModuleFilterEdit_->setPlaceholderText(QStringLiteral("按模块路径过滤，如 ntoskrnl.exe / drivers\\xxx.sys"));
    kernelExecutableModuleFilterEdit_->setToolTip(QStringLiteral("按模块路径子串过滤扫描结果，不区分大小写；留空显示全部"));
    kernelExecutableModuleFilterEdit_->setStyleSheet(buildBlueInputStyle());

    kernelExecutableStatusLabel_ = new QLabel(QStringLiteral("状态：等待刷新"), tabKernelExecutableMemory_);
    kernelExecutableStatusLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    kernelExecutableStatusLabel_->setToolTip(QStringLiteral("显示最近一次内核可执行页扫描的统计结果"));
    kernelExecutableStatusLabel_->setStyleSheet(kernelExecutableStatusStyle(ksword_theme::textSecondaryHex()));

    toolLayout->addWidget(kernelExecutableRefreshButton_, 0);
    toolLayout->addWidget(scanProgressBar, 0);
    toolLayout->addWidget(kernelExecutableRiskOnlyCheck_, 0);
    toolLayout->addWidget(kernelExecutableModuleFilterEdit_, 1);
    toolLayout->addWidget(kernelExecutableStatusLabel_, 0);
    tabLayout->addLayout(toolLayout);

    QSplitter* splitter = new QSplitter(Qt::Vertical, tabKernelExecutableMemory_);
    tabLayout->addWidget(splitter, 1);

    kernelExecutableTable_ = new ks::ui::VisibleTableWidget(splitter);
    kernelExecutableTable_->setColumnCount(kernelExecutableColumnIndex(KernelExecutableColumn::kCount));
    kernelExecutableTable_->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("VA"),
        QStringLiteral("区域大小"),
        QStringLiteral("页数"),
        QStringLiteral("页大小"),
        QStringLiteral("权限"),
        QStringLiteral("Owner"),
        QStringLiteral("模块基址"),
        QStringLiteral("模块路径"),
        QStringLiteral("风险标志")
        });
    kernelExecutableTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    kernelExecutableTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    kernelExecutableTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    kernelExecutableTable_->setAlternatingRowColors(true);
    kernelExecutableTable_->setSortingEnabled(true);
    kernelExecutableTable_->verticalHeader()->setVisible(false);
    kernelExecutableTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    kernelExecutableTable_->horizontalHeader()->setSectionResizeMode(kernelExecutableColumnIndex(KernelExecutableColumn::kModulePath), QHeaderView::Stretch);
    kernelExecutableTable_->setColumnWidth(kernelExecutableColumnIndex(KernelExecutableColumn::kVa), 170);
    kernelExecutableTable_->setColumnWidth(kernelExecutableColumnIndex(KernelExecutableColumn::kModuleBase), 170);
    kernelExecutableTable_->setColumnWidth(kernelExecutableColumnIndex(KernelExecutableColumn::kOwner), 180);
    kernelExecutableTable_->setColumnWidth(kernelExecutableColumnIndex(KernelExecutableColumn::kRiskFlags), 220);
    installKernelExecutableCopyMenu(kernelExecutableTable_);
    splitter->addWidget(kernelExecutableTable_);

    QWidget* detailPanel = new QWidget(splitter);
    QHBoxLayout* detailLayout = new QHBoxLayout(detailPanel);
    detailLayout->setContentsMargins(0, 0, 0, 0);
    detailLayout->setSpacing(8);

    kernelExecutableDetailEditor_ = new CodeEditorWidget(detailPanel);
    kernelExecutableDetailEditor_->setReadOnly(true);
    kernelExecutableDetailEditor_->setText(QStringLiteral("请选择一条内核可执行页记录查看详情。"));
    detailLayout->addWidget(kernelExecutableDetailEditor_, 1);
    splitter->addWidget(detailPanel);

    ks::ui::DetailLayoutRegistry::registerHost(
        kernelExecutableTable_,
        kernelExecutableDetailEditor_,
        tabKernelExecutableMemory_);

    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);

    tabWidget_->addTab(tabKernelExecutableMemory_, QStringLiteral("内核可执行页"));
}

void MemoryDock::refreshKernelExecutableMemoryScanAsync()
{
    // Input: Triggered by the refresh button or initialization path; no parameters.
    // Handling: Asynchronously call DriverClient::scanKernelExecutableMemory; the main thread is responsible only for persisting results.
    // Returns: Nothing.
    if (kernelExecutableRefreshInProgress_.exchange(true))
    {
        return;
    }

    // Disable the refresh entry during scanning to avoid issuing duplicate IOCTLs; the progress bar and status label simultaneously enter the 'Scanning' state.
    if (kernelExecutableRefreshButton_ != nullptr)
    {
        kernelExecutableRefreshButton_->setEnabled(false);
    }
    if (kernelExecutableStatusLabel_ != nullptr)
    {
        kernelExecutableStatusLabel_->setText(QStringLiteral("状态：正在扫描内核可执行页…"));
        kernelExecutableStatusLabel_->setStyleSheet(kernelExecutableStatusStyle(ksword_theme::kPrimaryBlueHex));
    }
    if (tabKernelExecutableMemory_ != nullptr)
    {
        QProgressBar* busyBar = tabKernelExecutableMemory_->findChild<QProgressBar*>(
            QStringLiteral("kernelExecutableScanProgress"));
        if (busyBar != nullptr)
        {
            busyBar->setVisible(true);
        }
    }

    const std::uint64_t kTicket = kernelExecutableRefreshTicket_.fetch_add(1U) + 1U;
    const QPointer<MemoryDock> kGuardThis(this);

    std::thread([kGuardThis, kTicket]() {
        if (kGuardThis == nullptr)
        {
            return;
        }

        const ksword::ark::DriverClient kDriverClient;
        ksword::ark::KernelExecutableMemoryScanResult scanResult = kDriverClient.scanKernelExecutableMemory(
            KSWORD_ARK_KERNEL_EXEC_SCAN_FLAG_INCLUDE_ALL,
            4096U,
            std::wstring());

        QMetaObject::invokeMethod(
            kGuardThis.data(),
            [kGuardThis, kTicket, scanResult = std::move(scanResult)]() mutable {
                auto resultSnapshot =
                    std::make_shared<ksword::ark::KernelExecutableMemoryScanResult>(
                        std::move(scanResult));
                auto commitSnapshot = [kGuardThis, kTicket, resultSnapshot]()
                {
                    if (kGuardThis == nullptr ||
                        kTicket < kGuardThis->kernelExecutableRefreshTicket_.load())
                    {
                        return;
                    }

                    // Return results to the main thread: first restore the refresh entry and progress bar, then write the status summary according to the io.ok branch.
                    kGuardThis->kernelExecutableRefreshInProgress_.store(false);
                    if (kGuardThis->kernelExecutableRefreshButton_ != nullptr)
                    {
                        kGuardThis->kernelExecutableRefreshButton_->setEnabled(true);
                    }
                    if (kGuardThis->tabKernelExecutableMemory_ != nullptr)
                    {
                        QProgressBar* busyBar = kGuardThis->tabKernelExecutableMemory_->findChild<QProgressBar*>(
                            QStringLiteral("kernelExecutableScanProgress"));
                        if (busyBar != nullptr)
                        {
                            busyBar->setVisible(false);
                        }
                    }

                    const ksword::ark::KernelExecutableMemoryScanResult& snapshot = *resultSnapshot;
                    if (!snapshot.io.ok)
                    {
                        kGuardThis->kernelExecutableCache_.clear();
                        kGuardThis->kernelExecutableVisibleCount_ = 0U;
                        kGuardThis->rebuildKernelExecutableMemoryScanTable();

                        const QString kUnsupportedText = snapshot.unsupported
                            ? QStringLiteral("不支持/驱动版本过旧")
                            : QStringLiteral("扫描失败");
                        if (kGuardThis->kernelExecutableStatusLabel_ != nullptr)
                        {
                            kGuardThis->kernelExecutableStatusLabel_->setText(
                                QStringLiteral("状态：%1").arg(kUnsupportedText));
                            kGuardThis->kernelExecutableStatusLabel_->setStyleSheet(
                                kernelExecutableStatusStyle(
                                    snapshot.unsupported
                                        ? ksword_theme::errorColor().name(QColor::HexRgb)
                                        : ksword_theme::textSecondaryColorHex()));
                        }
                        if (kGuardThis->kernelExecutableDetailEditor_ != nullptr)
                        {
                            kGuardThis->kernelExecutableDetailEditor_->setText(
                                snapshot.unsupported
                                ? QStringLiteral("当前驱动不支持内核可执行内存扫描，请更新为匹配版本。")
                                : QStringLiteral("内核可执行页扫描失败。\n\nWin32: %1\n详情: %2")
                                    .arg(snapshot.io.win32Error)
                                    .arg(kernelExecutableIoMessageText(snapshot.io.message)));
                        }
                        return;
                    }

                    kGuardThis->kernelExecutableCache_ = snapshot.entries;
                    kGuardThis->rebuildKernelExecutableMemoryScanTable();
                    kGuardThis->showKernelExecutableMemoryDetailByCurrentRow();
                    if (kGuardThis->kernelExecutableStatusLabel_ != nullptr)
                    {
                        kGuardThis->kernelExecutableStatusLabel_->setText(
                            QStringLiteral("状态：总计 %1，显示 %2，模块 %3")
                            .arg(snapshot.totalCount)
                            .arg(kGuardThis->kernelExecutableVisibleCount_)
                            .arg(snapshot.moduleCount));
                        kGuardThis->kernelExecutableStatusLabel_->setStyleSheet(
                            kernelExecutableStatusStyle(
                                snapshot.entries.empty()
                                    ? ksword_theme::errorColor().name(QColor::HexRgb)
                                    : ksword_theme::successColor().name(QColor::HexRgb)));
                    }
                };

                if (ks::ui::deferTableUiCommitIfContextMenuOpen(
                    kGuardThis.data(),
                    QStringLiteral("memory-kernel-executable-snapshot"),
                    { kGuardThis->kernelExecutableTable_ },
                    commitSnapshot))
                {
                    return;
                }
                commitSnapshot();
            },
            Qt::QueuedConnection);
    }).detach();
}

void MemoryDock::rebuildKernelExecutableMemoryScanTable()
{
    ks::ui::DetailLayoutRegistry::prepareDataRebuild(kernelExecutableDetailEditor_);
    // Input: None; depends on m_kernelExecutableCache and the current filter control.
    // Handling: Perform projection to the table only; do not re-invoke DriverClient.
    // Returns: Nothing.
    const QString kModuleFilter = kernelExecutableModuleFilterEdit_ != nullptr
        ? kernelExecutableModuleFilterEdit_->text().trimmed()
        : QString();
    const bool kRiskOnly = kernelExecutableRiskOnlyCheck_ != nullptr
        ? kernelExecutableRiskOnlyCheck_->isChecked()
        : false;

    std::vector<const ksword::ark::KernelExecutableMemoryPageEntry*> visibleEntries;
    visibleEntries.reserve(kernelExecutableCache_.size());
    for (const ksword::ark::KernelExecutableMemoryPageEntry& entry : kernelExecutableCache_)
    {
        if (kRiskOnly && entry.riskFlags == 0U)
        {
            continue;
        }
        if (!entryMatchesModuleFilter(entry, kModuleFilter))
        {
            continue;
        }
        visibleEntries.push_back(&entry);
    }

    kernelExecutableVisibleCount_ = visibleEntries.size();
    if (kernelExecutableTable_ == nullptr)
    {
        return;
    }

    kernelExecutableTable_->setSortingEnabled(false);
    const QSignalBlocker kBlocker(kernelExecutableTable_);
    kernelExecutableTable_->setRowCount(static_cast<int>(visibleEntries.size()));
    for (int row = 0; row < static_cast<int>(visibleEntries.size()); ++row)
    {
        const ksword::ark::KernelExecutableMemoryPageEntry& entry = *visibleEntries[static_cast<std::size_t>(row)];
        // All numeric columns use NumericTableItem: VA and module base addresses are displayed in hexadecimal but sorted by actual numeric
        // value; region sizes are displayed in KB/MB but sorted by byte count; page counts and page sizes are sorted by raw counts.
        kernelExecutableTable_->setItem(row, kernelExecutableColumnIndex(KernelExecutableColumn::kVa),
            createNumericItem(hexValue(entry.virtualAddress), entry.virtualAddress));
        kernelExecutableTable_->setItem(row, kernelExecutableColumnIndex(KernelExecutableColumn::kRegionSize),
            createNumericItem(byteSizeText(entry.regionSize), entry.regionSize));
        kernelExecutableTable_->setItem(row, kernelExecutableColumnIndex(KernelExecutableColumn::kPageCount),
            createNumericItem(QString::number(entry.pageCount), entry.pageCount));
        kernelExecutableTable_->setItem(row, kernelExecutableColumnIndex(KernelExecutableColumn::kPageSize),
            createNumericItem(QString::number(entry.pageSize), entry.pageSize));
        kernelExecutableTable_->setItem(row, kernelExecutableColumnIndex(KernelExecutableColumn::kPermissions),
            createTextItem(permissionText(entry.permissionFlags)));
        kernelExecutableTable_->setItem(row, kernelExecutableColumnIndex(KernelExecutableColumn::kOwner),
            createTextItem(ownerKindText(entry.ownerKind)));
        // A module base address of 0 indicates this executable page did not match any loaded module; display N/A here, but retain 0 as the sort value.
        kernelExecutableTable_->setItem(row, kernelExecutableColumnIndex(KernelExecutableColumn::kModuleBase),
            createNumericItem(
                entry.moduleBase != 0ULL ? hexValue(entry.moduleBase) : QStringLiteral("N/A"),
                entry.moduleBase));
        kernelExecutableTable_->setItem(row, kernelExecutableColumnIndex(KernelExecutableColumn::kModulePath),
            createTextItem(wideToQString(entry.modulePath)));
        kernelExecutableTable_->setItem(row, kernelExecutableColumnIndex(KernelExecutableColumn::kRiskFlags),
            createTextItem(riskFlagsText(entry.riskFlags)));

        // Entire risk row colored: writable and executable type uses error color, other risk flags use warning color, and rows with no risk retain the default foreground.
        const QColor kRiskColor = kernelExecutableRiskColor(entry.riskFlags);
        if (kRiskColor.isValid())
        {
            for (int column = 0; column < kernelExecutableTable_->columnCount(); ++column)
            {
                QTableWidgetItem* cellItem = kernelExecutableTable_->item(row, column);
                if (cellItem != nullptr)
                {
                    cellItem->setForeground(kRiskColor);
                }
            }
        }
    }
    if (visibleEntries.empty())
    {
        const QString kDetailText = kernelExecutableCache_.empty()
            ? QStringLiteral("内核可执行页扫描当前没有缓存行；可能是驱动未返回结果、扫描失败或尚未刷新。")
            : QStringLiteral("当前过滤条件隐藏了全部 %1 条内核可执行页记录；请清空模块过滤或关闭“仅风险项”。")
                .arg(static_cast<qulonglong>(kernelExecutableCache_.size()));
        setKernelExecutableDiagnosticRow(kernelExecutableTable_, kDetailText);
    }
    if (kernelExecutableTable_->rowCount() > 0 && kernelExecutableTable_->currentRow() < 0)
    {
        kernelExecutableTable_->setCurrentCell(0, kernelExecutableColumnIndex(KernelExecutableColumn::kVa));
    }
    kernelExecutableTable_->setSortingEnabled(true);
}

void MemoryDock::showKernelExecutableMemoryDetailByCurrentRow()
{
    // Input: None; relies on the currently selected row in the table.
    // Processing: Expand the R3 record corresponding to the current row into the CodeEditorWidget.
    // Returns: Nothing.
    if (kernelExecutableDetailEditor_ == nullptr || kernelExecutableTable_ == nullptr)
    {
        return;
    }

    const int kCurrentRow = kernelExecutableTable_->currentRow();
    if (kCurrentRow < 0 || kCurrentRow >= kernelExecutableTable_->rowCount())
    {
        kernelExecutableDetailEditor_->setText(QStringLiteral("请选择一条内核可执行页记录查看详情。"));
        return;
    }

    const QTableWidgetItem* vaItem = kernelExecutableTable_->item(kCurrentRow, kernelExecutableColumnIndex(KernelExecutableColumn::kVa));
    if (vaItem == nullptr)
    {
        return;
    }
    const QString kDiagnosticText = vaItem->data(Qt::UserRole + 2).toString();
    if (!kDiagnosticText.isEmpty())
    {
        kernelExecutableDetailEditor_->setText(QStringLiteral("内核可执行页诊断\n%1").arg(kDiagnosticText));
        return;
    }

    bool ok = false;
    const qulonglong kVa = vaItem->data(Qt::UserRole).toULongLong(&ok);
    if (!ok)
    {
        return;
    }

    for (const ksword::ark::KernelExecutableMemoryPageEntry& entry : kernelExecutableCache_)
    {
        if (entry.virtualAddress == kVa)
        {
            kernelExecutableDetailEditor_->setText(buildKernelExecutableDetailText(entry));
            return;
        }
    }
}
