#include "DriverDock.Internal.h"
#include "../ui/TableInteractionSupport.h"
#include "../ui/VisibleTableWidget.h"
#include "../ui/TableColumnAutoFit.h"
#include "../ui/DetailLayoutRegistry.h"

#include <QPointer>
#include <QRunnable>

using namespace ksword::driver_dock_internal;

namespace
{
    enum class IntegrityColumn : int
    {
        kClass = 0,
        kObject,
        kTarget,
        kOwner,
        kCpu,
        kRisk,
        kConfidence,
        kDetail,
        kCount
    };

    int integrityColumnIndex(const IntegrityColumn column)
    {
        // Input: Integrity table column enumeration.
        // Processing: Convert to QTableWidget column index.
        // Return: column index.
        return static_cast<int>(column);
    }

    QString hex64(const std::uint64_t value)
    {
        // Input: 64-bit address or mask.
        // Handling: Format as fixed-width hexadecimal.
        // Return: uppercase text with 0x prefix.
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(value), 16, 16, QChar('0'))
            .toUpper();
    }

    QString classText(const std::uint32_t evidenceClass)
    {
        // Input: KSWORD_ARK_DRIVER_INTEGRITY_CLASS_*.
        // Handling: map to DriverDock page group text.
        // Returns: Evidence type name.
        switch (evidenceClass)
        {
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MODULE_VIEW: return QStringLiteral("ModuleView");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_PS_LOADED_MODULES: return QStringLiteral("PsLoadedModules");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DRIVER_OBJECT: return QStringLiteral("DriverObject");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DRIVER_SECTION: return QStringLiteral("DriverSection");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MAJOR_FUNCTION: return QStringLiteral("MajorFunction");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_FAST_IO: return QStringLiteral("FastIo");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DEVICE_CHAIN: return QStringLiteral("DeviceChain");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_SERVICE: return QStringLiteral("Service");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_CPU_CONTROL: return QStringLiteral("CPU");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DESCRIPTOR_TABLE: return QStringLiteral("Descriptor");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MSR_ENTRY: return QStringLiteral("MSR");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_IDT_HANDLER: return QStringLiteral("IDT");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_OPTIONAL_GLOBAL: return QStringLiteral("OptionalGlobal");
        default: return QStringLiteral("Class(%1)").arg(evidenceClass);
        }
    }

    QString riskText(const std::uint32_t flags)
    {
        // Input: KSWORD_ARK_DRIVER_INTEGRITY_RISK_* bitset.
        // Processing: Convert to a compact risk label.
        // Return: No risk, return "Normal".
        if (flags == 0U)
        {
            return driverText("driver.integrity.risk.normal", QStringLiteral("正常"));
        }
        QStringList parts;
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_UNAVAILABLE)
            parts << driverText("driver.integrity.risk.unavailable", QStringLiteral("不可用"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_QUERY_FAILED)
            parts << driverText("driver.integrity.risk.query_failed", QStringLiteral("查询失败"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_MODULE_UNRESOLVED)
            parts << driverText("driver.integrity.risk.module_unresolved", QStringLiteral("模块未解析"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_OWNER_MISMATCH)
            parts << driverText("driver.integrity.risk.owner_mismatch", QStringLiteral("Owner不匹配"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_OUTSIDE_DRIVER_IMAGE)
            parts << driverText("driver.integrity.risk.outside_image", QStringLiteral("外跳"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_SECTION_MISMATCH)
            parts << driverText("driver.integrity.risk.section_mismatch", QStringLiteral("Section不匹配"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_SERVICE_MISSING)
            parts << driverText("driver.integrity.risk.service_missing", QStringLiteral("服务缺失"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_EMPTY_UNLOAD)
            parts << driverText("driver.integrity.risk.empty_unload", QStringLiteral("Unload为空"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_DEVICE_LOOP)
            parts << driverText("driver.integrity.risk.device_loop", QStringLiteral("Device环"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_ATTACHED_LOOP)
            parts << driverText("driver.integrity.risk.attached_loop", QStringLiteral("Attached环"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CROSS_DRIVER_ATTACH)
            parts << driverText("driver.integrity.risk.cross_driver_attach", QStringLiteral("跨驱动挂接"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_NULL_POINTER)
            parts << driverText("driver.integrity.risk.null_pointer", QStringLiteral("空指针"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_NON_CORE_OWNER)
            parts << driverText("driver.integrity.risk.idt_external_owner", QStringLiteral("IDT外部Owner"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_WP_DISABLED)
            parts << driverText("driver.integrity.risk.wp_disabled", QStringLiteral("WP关闭"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_NXE_DISABLED)
            parts << driverText("driver.integrity.risk.nxe_disabled", QStringLiteral("NXE关闭"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_SMEP_DISABLED)
            parts << driverText("driver.integrity.risk.smep_disabled", QStringLiteral("SMEP关闭"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_SMAP_DISABLED)
            parts << driverText("driver.integrity.risk.smap_disabled", QStringLiteral("SMAP关闭"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_DESCRIPTOR_INVALID)
            parts << driverText("driver.integrity.risk.descriptor_invalid", QStringLiteral("描述符异常"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_DYNDATA_UNAVAILABLE)
            parts << driverText("driver.integrity.risk.dyndata_unavailable", QStringLiteral("DynData缺失"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_TRUNCATED)
            parts << driverText("driver.integrity.risk.truncated", QStringLiteral("截断"));
        return parts.join(QStringLiteral(" | "));
    }

    QString entryStatusText(const std::uint32_t statusValue)
    {
        // Input: entryStatus for a single integrity evidence.
        // Processing: Map common protocol statuses to human-readable strings; retain numeric values for unknown states.
        // Returns: Short status for table summary.
        switch (statusValue)
        {
        case KSWORD_ARK_DRIVER_INTEGRITY_STATUS_OK: return QStringLiteral("OK");
        case KSWORD_ARK_DRIVER_INTEGRITY_STATUS_PARTIAL: return QStringLiteral("Partial");
        case KSWORD_ARK_DRIVER_INTEGRITY_STATUS_NOT_FOUND: return QStringLiteral("NotFound");
        case KSWORD_ARK_DRIVER_INTEGRITY_STATUS_BUFFER_TOO_SMALL: return QStringLiteral("BufferTooSmall");
        case KSWORD_ARK_DRIVER_INTEGRITY_STATUS_QUERY_FAILED: return QStringLiteral("QueryFailed");
        case KSWORD_ARK_DRIVER_INTEGRITY_STATUS_UNAVAILABLE: return QStringLiteral("Unavailable");
        default: return QStringLiteral("Status(%1)").arg(statusValue);
        }
    }

    QString integritySourceText(const std::uint32_t sourceMask)
    {
        // Input: KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_* bitset.
        // Processing: Convert to a source summary to aid reading the last column instead of viewing only the hexadecimal mask.
        // Return: Source text.
        if (sourceMask == 0U)
        {
            return driverText("driver.integrity.source.none", QStringLiteral("无来源"));
        }

        QStringList parts;
        if (sourceMask & KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SYSTEM_MODULE) parts << QStringLiteral("SystemModule");
        if (sourceMask & KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_AUXKLIB) parts << QStringLiteral("AuxKlib");
        if (sourceMask & KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_PS_LOADED_MODULES) parts << QStringLiteral("PsLoadedModules");
        if (sourceMask & KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_OBJECT) parts << QStringLiteral("DriverObject");
        if (sourceMask & KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_SECTION) parts << QStringLiteral("DriverSection");
        if (sourceMask & KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SERVICE_REGISTRY) parts << QStringLiteral("ServiceRegistry");
        if (sourceMask & KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_CPU_REGISTER) parts << QStringLiteral("CPU");
        if (sourceMask & KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_IDT) parts << QStringLiteral("IDT");
        if (sourceMask & KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_GDT) parts << QStringLiteral("GDT");
        if (sourceMask & KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_MSR) parts << QStringLiteral("MSR");
        if (sourceMask & KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DYNDATA) parts << QStringLiteral("DynData");
        return parts.join(QStringLiteral(" | "));
    }

    class NumericItem final : public QTableWidgetItem
    {
    public:
        NumericItem(const QString& text, const qulonglong value)
            : QTableWidgetItem(text)
        {
            // Input: display text and sort value.
            // Handling: UserRole stores the numeric value.
            // Returns: Constructor has no return value.
            setData(Qt::UserRole, QVariant::fromValue<qulonglong>(value));
            setTextAlignment(Qt::AlignVCenter | Qt::AlignLeft);
        }

        bool operator<(const QTableWidgetItem& other) const override
        {
            // Input: Another item.
            // Handling: prioritize sorting by UserRole values.
            // Returns: The sort comparison result.
            bool leftOk = false;
            bool rightOk = false;
            const qulonglong kLeftValue = data(Qt::UserRole).toULongLong(&leftOk);
            const qulonglong kRightValue = other.data(Qt::UserRole).toULongLong(&rightOk);
            if (leftOk && rightOk)
            {
                return kLeftValue < kRightValue;
            }
            return QTableWidgetItem::operator<(other);
        }
    };

    QTableWidgetItem* textItem(const QString& value)
    {
        // Input: display text.
        // Processing: Create a read-only item.
        // Returns: an item whose lifecycle is managed by the table.
        QTableWidgetItem* item = new QTableWidgetItem(value);
        item->setTextAlignment(Qt::AlignVCenter | Qt::AlignLeft);
        return item;
    }

    QString tableCellText(QTableWidget* table, const int rowIndex, const int columnIndex)
    {
        // Input: Target table, row index, and column index.
        // Processing: Safely read cell text; normalize null items to empty strings.
        // Returns: Text suitable for TSV or detailed display.
        if (table == nullptr)
        {
            return QString();
        }
        QTableWidgetItem* item = table->item(rowIndex, columnIndex);
        return item != nullptr ? item->text() : QString();
    }

    QString escapeTsvCell(QString value)
    {
        // Input: Original cell text.
        // Processing: normalize newlines and tabs to spaces to prevent column structure corruption after copying.
        // Returns: TSV-safe text.
        value.replace(QLatin1Char('\t'), QLatin1Char(' '));
        value.replace(QLatin1Char('\r'), QLatin1Char(' '));
        value.replace(QLatin1Char('\n'), QLatin1Char(' '));
        return value.trimmed();
    }

    void copyIntegrityTableCurrentRow(QTableWidget* table)
    {
        // copyIntegrityTableCurrentRow：
        // - Input: Integrity evidence table;
        // - Processing: Copy the current row as TSV;
        // - Return: None; no repair, unloading, or cleanup actions are performed.
        if (table == nullptr || QGuiApplication::clipboard() == nullptr)
        {
            return;
        }

        const int kCurrentRow = table->currentRow();
        if (kCurrentRow < 0)
        {
            return;
        }

        QStringList cells;
        for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
        {
            cells << escapeTsvCell(tableCellText(table, kCurrentRow, columnIndex));
        }
        QGuiApplication::clipboard()->setText(cells.join(QLatin1Char('\t')));
    }

    void installIntegrityTableCopyMenu(QTableWidget* table)
    {
        // installIntegrityTableCopyMenu：
        // - Input: Integrity evidence table;
        // - Processing: Install the copy current row menu.
        // - Returns: None. Performs only UI/clipboard operations.
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

            QMenu contextMenu(table);
            contextMenu.setStyleSheet(ksword_theme::contextMenuStyle());
            QAction* copyRowAction = contextMenu.addAction(
                QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
                driverText("driver.menu.copy_row", QStringLiteral("复制当前行")));
            copyRowAction->setEnabled(table->currentRow() >= 0);
            if (contextMenu.exec(table->viewport()->mapToGlobal(localPosition)) == copyRowAction)
            {
                copyIntegrityTableCurrentRow(table);
            }
        });
    }

    QTableWidgetItem* numericItem(const QString& text, const qulonglong value)
    {
        // Input: Display text and sort value.
        // Processing: Create a NumericItem.
        // Returns: an item whose lifecycle is managed by the table.
        return new NumericItem(text, value);
    }

    bool parseAddressText(const QString& text, std::uint64_t& valueOut)
    {
        // Input: user-entered hexadecimal or decimal address.
        // Note: Support 0x prefix; parse empty text as 0.
        // Returns: true if parsing succeeds.
        const QString kTrimmed = text.trimmed();
        if (kTrimmed.isEmpty())
        {
            valueOut = 0;
            return true;
        }
        bool ok = false;
        valueOut = kTrimmed.toULongLong(&ok, kTrimmed.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive) ? 16 : 10);
        return ok;
    }

    QString detailText(const ksword::ark::DriverIntegrityEvidenceEntry& row)
    {
        // Input: Integrity evidence row.
        // Processing: Expand all key fields.
        // Returns: detail text.
        QString text;
        text += driverText("driver.integrity.detail.title", QStringLiteral("驱动完整性证据详情\n"));
        text += QStringLiteral("Class: %1 (%2)\n").arg(classText(row.evidenceClass)).arg(row.evidenceClass);
        text += QStringLiteral("RiskFlags: %1 (0x%2)\n").arg(riskText(row.riskFlags)).arg(row.riskFlags, 8, 16, QChar('0'));
        text += QStringLiteral("SourceMask: 0x%1\n").arg(row.sourceMask, 8, 16, QChar('0'));
        text += QStringLiteral("EntryStatus: %1\n").arg(row.entryStatus);
        text += QStringLiteral("StatusFlags: 0x%1\n").arg(row.statusFlags, 8, 16, QChar('0'));
        text += QStringLiteral("FieldMask: 0x%1\n").arg(row.fieldMask, 8, 16, QChar('0'));
        text += QStringLiteral("RiskScore: %1\n").arg(row.riskScore);
        text += QStringLiteral("Confidence: %1\n").arg(row.confidence);
        text += QStringLiteral("ObjectAddress: %1\n").arg(hex64(row.objectAddress));
        text += QStringLiteral("TargetAddress: %1\n").arg(hex64(row.targetAddress));
        text += QStringLiteral("OwnerModule: %1\n").arg(QString::fromStdWString(row.ownerModule));
        text += QStringLiteral("OwnerModuleBase: %1\n").arg(hex64(row.ownerModuleBase));
        text += QStringLiteral("OwnerModuleSize: %1\n").arg(row.ownerModuleSize);
        text += QStringLiteral("DriverObject: %1 DriverStart: %2 DriverSize: %3\n")
            .arg(hex64(row.driverObjectAddress))
            .arg(hex64(row.driverStart))
            .arg(hex64(row.driverSize));
        text += QStringLiteral("KLDR: entry=%1 listHead=%2 dllBase=%3 size=0x%4\n")
            .arg(hex64(row.kldrEntryAddress))
            .arg(hex64(row.kldrListHeadAddress))
            .arg(hex64(row.kldrDllBase))
            .arg(row.kldrSizeOfImage, 8, 16, QChar('0'));
        text += QStringLiteral("CPU: group=%1 cpu=%2 vector=%3\n")
            .arg(row.processorGroup)
            .arg(row.processorNumber)
            .arg(row.vector);
        text += QStringLiteral("Detail: %1\n").arg(QString::fromStdWString(row.detail));
        return text;
    }

    QString integritySummaryText(const ksword::ark::DriverIntegrityEvidenceEntry& row)
    {
        // Input: Integrity evidence row.
        // Processing: Generate a summary in the last table column to avoid inserting raw R0 detail directly into the table.
        // Returns: a single line of Chinese description; the complete raw detail is preserved in the detail editor/dialog.
        const QString kRawDetailText = QString::fromStdWString(row.detail).trimmed();
        const QString kDetailSummaryText = kRawDetailText.isEmpty()
            ? driverText("driver.integrity.detail.no_extra_detail", QStringLiteral("驱动未返回额外说明"))
            : kRawDetailText.left(160);
        return driverText("driver.integrity.detail.summary", QStringLiteral("%1；状态=%2；来源=%3；%4"))
            .arg(riskText(row.riskFlags))
            .arg(entryStatusText(row.entryStatus))
            .arg(integritySourceText(row.sourceMask))
            .arg(kDetailSummaryText);
    }

    // appendEvidenceRow：
    // - Input: Evidence table and cell text.
    // - Processing: write one row of read-only evidence at once;
    // - Returns: Nothing.
    void appendEvidenceRow(
        QTableWidget* table,
        const int rowIndex,
        const QString& evidenceText,
        const QString& objectText,
        const QString& targetText,
        const QString& riskText,
        const QString& confidenceText,
        const QString& detailTextValue)
    {
        if (table == nullptr)
        {
            return;
        }
        table->setItem(rowIndex, 0, textItem(evidenceText));
        table->setItem(rowIndex, 1, textItem(objectText));
        table->setItem(rowIndex, 2, textItem(targetText));
        table->setItem(rowIndex, 3, textItem(riskText));
        table->setItem(rowIndex, 4, textItem(confidenceText));
        table->setItem(rowIndex, 5, textItem(detailTextValue));
    }
}

void DriverDock::initializeIntegrityTab()
{
    // Input: None; called by initializeUi.
    // Processing: Create a read-only driver integrity page.
    // Returns: Nothing.
    integrityPage_ = new QWidget(tabWidget_);
    integrityLayout_ = new QVBoxLayout(integrityPage_);
    integrityLayout_->setContentsMargins(4, 4, 4, 4);
    integrityLayout_->setSpacing(6);

    QHBoxLayout* toolLayout = new QHBoxLayout();
    toolLayout->setContentsMargins(0, 0, 0, 0);
    toolLayout->setSpacing(6);

    integrityDriverNameEdit_ = new QLineEdit(integrityPage_);
    integrityDriverNameEdit_->setPlaceholderText(
        driverText("driver.integrity.form.driver_name.placeholder", QStringLiteral("\\Driver\\Name（可选）")));
    integrityModuleBaseEdit_ = new QLineEdit(integrityPage_);
    integrityModuleBaseEdit_->setPlaceholderText(
        driverText("driver.integrity.form.module_base.placeholder", QStringLiteral("模块基址（可选）")));
    integrityModuleBaseEdit_->setMaximumWidth(150);

    integrityFillFromSelectionButton_ = new QPushButton(QIcon(QStringLiteral(":/Icon/process_details.svg")), QString(), integrityPage_);
    ksword_theme::applyCompactIconButtonMetrics(integrityFillFromSelectionButton_);
    integrityFillFromSelectionButton_->setToolTip(
        driverText("driver.integrity.form.fill.tooltip", QStringLiteral("从当前服务选择填充 DriverObject 名称")));

    integrityRefreshButton_ = new QPushButton(QIcon(QStringLiteral(":/Icon/process_refresh.svg")), QString(), integrityPage_);
    ksword_theme::applyCompactIconButtonMetrics(integrityRefreshButton_);
    integrityRefreshButton_->setToolTip(
        driverText(
            "driver.integrity.form.refresh.tooltip",
            QStringLiteral("查询 DriverObject/LDR/FastIo/CPU 完整性证据")));

    integrityCpuOnlyButton_ = new QPushButton(QIcon(QStringLiteral(":/Icon/process_threads.svg")), QString(), integrityPage_);
    ksword_theme::applyCompactIconButtonMetrics(integrityCpuOnlyButton_);
    integrityCpuOnlyButton_->setToolTip(
        driverText("driver.integrity.form.cpu_only.tooltip", QStringLiteral("仅查询 CPU entry / IDT / MSR 证据")));

    integrityRiskOnlyCheck_ = new QCheckBox(
        driverText("driver.integrity.form.risk_only", QStringLiteral("仅风险项")),
        integrityPage_);
    integrityRiskOnlyCheck_->setChecked(false);

    integrityMaxRowsSpin_ = new QSpinBox(integrityPage_);
    integrityMaxRowsSpin_->setRange(64, static_cast<int>(KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_MAX_ROWS));
    integrityMaxRowsSpin_->setValue(1024);
    integrityMaxRowsSpin_->setToolTip(
        driverText("driver.integrity.form.max_rows.tooltip", QStringLiteral("最大返回证据行数")));

    integrityStatusLabel_ = new QLabel(
        driverText("driver.integrity.status.waiting", QStringLiteral("状态：等待查询")),
        integrityPage_);
    integrityStatusLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);

    toolLayout->addWidget(new QLabel(QStringLiteral("DriverObject:"), integrityPage_));
    toolLayout->addWidget(integrityDriverNameEdit_, 1);
    toolLayout->addWidget(integrityModuleBaseEdit_);
    toolLayout->addWidget(integrityFillFromSelectionButton_);
    toolLayout->addWidget(integrityRefreshButton_);
    toolLayout->addWidget(integrityCpuOnlyButton_);
    toolLayout->addWidget(integrityRiskOnlyCheck_);
    toolLayout->addWidget(new QLabel(
        driverText("driver.integrity.form.rows_label", QStringLiteral("行数:")),
        integrityPage_));
    toolLayout->addWidget(integrityMaxRowsSpin_);
    toolLayout->addWidget(integrityStatusLabel_, 1);
    integrityLayout_->addLayout(toolLayout);

    QSplitter* splitter = new QSplitter(Qt::Vertical, integrityPage_);
    integrityLayout_->addWidget(splitter, 1);

    integrityTable_ = new ks::ui::VisibleTableWidget(splitter);
    integrityTable_->setColumnCount(integrityColumnIndex(IntegrityColumn::kCount));
    integrityTable_->setHorizontalHeaderLabels(driverIntegrityTableHeaders());
    integrityTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    integrityTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    integrityTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    integrityTable_->setAlternatingRowColors(true);
    integrityTable_->setSortingEnabled(true);
    integrityTable_->verticalHeader()->setVisible(false);
    integrityTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    integrityTable_->horizontalHeader()->setSectionResizeMode(integrityColumnIndex(IntegrityColumn::kDetail), QHeaderView::Stretch);
    installIntegrityTableCopyMenu(integrityTable_);
    splitter->addWidget(integrityTable_);

    // The integrity details area uses the project's unified CodeEditorWidget for easy copying, searching, and viewing multi-line R0 evidence.
    integrityDetailEdit_ = new CodeEditorWidget(splitter);
    integrityDetailEdit_->setReadOnly(true);
    integrityDetailEdit_->setText(driverText(
        "driver.integrity.detail.initial",
        QStringLiteral("选择一条完整性证据查看 DriverObject / MajorFunction / FastIo / LDR / CPU entry 详情。")));
    splitter->addWidget(integrityDetailEdit_);
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);

    ks::ui::DetailLayoutRegistry::registerHost(
        integrityTable_, integrityDetailEdit_, integrityPage_);

    tabWidget_->addTab(
        integrityPage_,
        QIcon(QStringLiteral(":/Icon/process_critical.svg")),
        driverText("driver.tab.integrity", QStringLiteral("驱动完整性")));

    rebuildModuleCrossViewTable();
}

void DriverDock::refreshDriverIntegrityAsync(const bool cpuOnly)
{
    // Input: cpuOnly controls the query scope.
    // Processing: Call ArkDriverClient in the background and fill in integrity evidence on the main thread.
    // Returns: Nothing.
    if (integrityQuerying_)
    {
        return;
    }
    std::uint64_t moduleBase = 0;
    if (!parseAddressText(integrityModuleBaseEdit_ != nullptr ? integrityModuleBaseEdit_->text() : QString(), moduleBase))
    {
        if (integrityStatusLabel_ != nullptr)
        {
            integrityStatusLabel_->setText(
                driverText("driver.integrity.status.module_base_invalid", QStringLiteral("状态：模块基址解析失败")));
        }
        return;
    }

    const std::wstring kDriverName = integrityDriverNameEdit_ != nullptr
        ? integrityDriverNameEdit_->text().trimmed().toStdWString()
        : std::wstring();
    const unsigned long kMaxRows = static_cast<unsigned long>(
        integrityMaxRowsSpin_ != nullptr ? integrityMaxRowsSpin_->value() : 1024);

    integrityQuerying_ = true;
    const std::uint64_t kTicket = ++integrityQueryTicket_;
    if (integrityRefreshButton_ != nullptr) integrityRefreshButton_->setEnabled(false);
    if (integrityCpuOnlyButton_ != nullptr) integrityCpuOnlyButton_->setEnabled(false);
    if (integrityStatusLabel_ != nullptr)
    {
        integrityStatusLabel_->setText(
            driverText("driver.integrity.status.querying", QStringLiteral("状态：查询中...")));
    }

    QPointer<DriverDock> guardThis(this);
    QRunnable* task = QRunnable::create([guardThis, kTicket, kDriverName, moduleBase, kMaxRows, cpuOnly]() {
        const ksword::ark::DriverClient kClient;
        ksword::ark::DriverIntegrityResult result = cpuOnly
            ? kClient.queryKernelCpuIntegrity(
                KSWORD_ARK_DRIVER_INTEGRITY_FLAG_CPU | KSWORD_ARK_DRIVER_INTEGRITY_FLAG_IDT_ENTRIES,
                kMaxRows,
                KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_IDT_VECTORS)
            : kClient.queryDriverIntegrity(
                kDriverName,
                moduleBase,
                KSWORD_ARK_DRIVER_INTEGRITY_FLAG_DEFAULT | KSWORD_ARK_DRIVER_INTEGRITY_FLAG_OPTIONAL_GLOBALS,
                kMaxRows,
                KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_IDT_VECTORS);

        QMetaObject::invokeMethod(guardThis.data(), [guardThis, kTicket, result = std::move(result)]() mutable {
            const auto kDeferredResult =
                std::make_shared<ksword::ark::DriverIntegrityResult>(std::move(result));
            const auto kCommitIntegrity = [guardThis, kTicket, kDeferredResult]()
            {
            const ksword::ark::DriverIntegrityResult& result = *kDeferredResult;
            if (guardThis == nullptr || guardThis->integrityQueryTicket_ != kTicket)
            {
                return;
            }
            guardThis->integrityQuerying_ = false;
            if (guardThis->integrityRefreshButton_ != nullptr) guardThis->integrityRefreshButton_->setEnabled(true);
            if (guardThis->integrityCpuOnlyButton_ != nullptr) guardThis->integrityCpuOnlyButton_->setEnabled(true);

            guardThis->lastDriverIntegrityResult_ = result;
            guardThis->driverIntegrityCache_ = result.entries;
            guardThis->rebuildDriverIntegrityTable();
            guardThis->rebuildModuleCrossViewTable();
            guardThis->showSelectedDriverIntegrityDetail();

            if (guardThis->integrityStatusLabel_ != nullptr)
            {
                if (!result.io.ok)
                {
                    guardThis->integrityStatusLabel_->setText(result.unsupported
                        ? driverText(
                            "driver.integrity.status.not_integrated",
                            QStringLiteral("状态：未集成/驱动过旧，等待 R0 支持"))
                        : driverText(
                            "driver.integrity.status.query_failed",
                            QStringLiteral("状态：查询失败 %1"))
                            .arg(describeDriverCollection(result.io)));
                    guardThis->integrityStatusLabel_->setStyleSheet(
                        QStringLiteral("color:%1; font-weight:700;")
                            .arg(ksword_theme::errorColor().name(QColor::HexRgb)));
                }
                else
                {
                    const bool kDegraded =
                        (result.statusFlags &
                            (KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PARTIAL |
                                KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_UNSUPPORTED |
                                KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_TRUNCATED |
                                KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PDB_REQUIRED)) != 0U;
                    guardThis->integrityStatusLabel_->setText(
                        driverText(
                            "driver.integrity.status.summary",
                            QStringLiteral("状态：%1，返回 %2/%3，CPU %4，模块 %5，FieldFlags=0x%6，StatusFlags=0x%7"))
                        .arg(kDegraded ? QStringLiteral("Partial/Degraded") : QStringLiteral("OK"))
                        .arg(result.entries.size())
                        .arg(result.totalCount)
                        .arg(result.cpuCount)
                        .arg(result.moduleCount)
                        .arg(result.fieldFlags, 8, 16, QChar('0'))
                        .arg(result.statusFlags, 8, 16, QChar('0')));
                    guardThis->integrityStatusLabel_->setStyleSheet(
                        QStringLiteral("color:%1; font-weight:700;")
                            .arg((kDegraded ? ksword_theme::warningColor() : ksword_theme::successColor())
                                .name(QColor::HexRgb)));
                }
            }
            };

            if (guardThis == nullptr || guardThis->integrityQueryTicket_ != kTicket)
            {
                return;
            }
            if (ks::ui::deferTableUiCommitIfContextMenuOpen(
                guardThis.data(),
                QStringLiteral("driver-integrity-cross-view-apply"),
                { guardThis->integrityTable_, guardThis->moduleCrossViewTable_ },
                kCommitIntegrity))
            {
                return;
            }
            kCommitIntegrity();
        }, Qt::QueuedConnection);
    });
    task->setAutoDelete(true);
    QThreadPool::globalInstance()->start(task);
}

void DriverDock::rebuildDriverIntegrityTable()
{
    // Input: None; reads m_driverIntegrityCache and filter controls.
    // Action: Redraw the table only; do not access the driver.
    // Returns: Nothing.
    if (integrityTable_ == nullptr)
    {
        return;
    }

    ks::ui::DetailLayoutRegistry::prepareDataRebuild(integrityDetailEdit_);
    const bool kRiskOnly = integrityRiskOnlyCheck_ != nullptr && integrityRiskOnlyCheck_->isChecked();
    std::vector<std::size_t> visibleIndexes;
    for (std::size_t index = 0; index < driverIntegrityCache_.size(); ++index)
    {
        if (kRiskOnly && driverIntegrityCache_[index].riskFlags == 0U)
        {
            continue;
        }
        visibleIndexes.push_back(index);
    }

    const QSignalBlocker kBlocker(integrityTable_);
    integrityTable_->setSortingEnabled(false);
    integrityTable_->setRowCount(static_cast<int>(visibleIndexes.size()));
    for (int rowIndex = 0; rowIndex < static_cast<int>(visibleIndexes.size()); ++rowIndex)
    {
        const std::size_t kCacheIndex = visibleIndexes[static_cast<std::size_t>(rowIndex)];
        const auto& row = driverIntegrityCache_[kCacheIndex];
        QTableWidgetItem* classItem = textItem(classText(row.evidenceClass));
        classItem->setData(Qt::UserRole + 1, QVariant::fromValue<qulonglong>(static_cast<qulonglong>(kCacheIndex)));
        integrityTable_->setItem(rowIndex, integrityColumnIndex(IntegrityColumn::kClass), classItem);
        integrityTable_->setItem(rowIndex, integrityColumnIndex(IntegrityColumn::kObject), numericItem(hex64(row.objectAddress), row.objectAddress));
        integrityTable_->setItem(rowIndex, integrityColumnIndex(IntegrityColumn::kTarget), numericItem(hex64(row.targetAddress), row.targetAddress));
        integrityTable_->setItem(rowIndex, integrityColumnIndex(IntegrityColumn::kOwner),
            textItem(QStringLiteral("%1 %2").arg(QString::fromStdWString(row.ownerModule), hex64(row.ownerModuleBase))));
        integrityTable_->setItem(rowIndex, integrityColumnIndex(IntegrityColumn::kCpu),
            textItem(QStringLiteral("G%1 CPU%2 V%3").arg(row.processorGroup).arg(row.processorNumber).arg(row.vector)));
        integrityTable_->setItem(rowIndex, integrityColumnIndex(IntegrityColumn::kRisk), textItem(riskText(row.riskFlags)));
        integrityTable_->setItem(rowIndex, integrityColumnIndex(IntegrityColumn::kConfidence), numericItem(QString::number(row.confidence), row.confidence));
        integrityTable_->setItem(rowIndex, integrityColumnIndex(IntegrityColumn::kDetail), textItem(integritySummaryText(row)));
    }
    if (integrityTable_->rowCount() > 0 && integrityTable_->currentRow() < 0)
    {
        integrityTable_->setCurrentCell(0, integrityColumnIndex(IntegrityColumn::kClass));
    }
    integrityTable_->setSortingEnabled(true);
    ks::ui::requestTableColumnAutoFit(integrityTable_);
}

void DriverDock::rebuildModuleCrossViewTable()
{
    // Input: Current integrity cache.
    // Handling: Project readable rows from evidence such as DriverObject, DriverSection, DeviceChain, and Service.
    // Returns: Nothing.
    if (moduleCrossViewTable_ == nullptr)
    {
        return;
    }

    const QSignalBlocker kBlocker(moduleCrossViewTable_);
    moduleCrossViewTable_->setSortingEnabled(false);
    moduleCrossViewTable_->setRowCount(0);

    int visibleRows = 0;
    for (const auto& row : driverIntegrityCache_)
    {
        if (row.evidenceClass != KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MODULE_VIEW &&
            row.evidenceClass != KSWORD_ARK_DRIVER_INTEGRITY_CLASS_PS_LOADED_MODULES &&
            row.evidenceClass != KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DRIVER_OBJECT &&
            row.evidenceClass != KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DRIVER_SECTION &&
            row.evidenceClass != KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DEVICE_CHAIN &&
            row.evidenceClass != KSWORD_ARK_DRIVER_INTEGRITY_CLASS_SERVICE)
        {
            continue;
        }

        const int kRowIndex = moduleCrossViewTable_->rowCount();
        moduleCrossViewTable_->insertRow(kRowIndex);
        appendEvidenceRow(
            moduleCrossViewTable_,
            kRowIndex,
            classText(row.evidenceClass),
            hex64(row.objectAddress),
            hex64(row.targetAddress),
            riskText(row.riskFlags),
            QString::number(row.confidence),
            integritySummaryText(row));
        ++visibleRows;
    }

    if (visibleRows == 0)
    {
        moduleCrossViewTable_->setRowCount(1);
        appendEvidenceRow(
            moduleCrossViewTable_,
            0,
            QStringLiteral("ModuleView"),
            QStringLiteral("Unavailable"),
            QStringLiteral("-"),
            driverText("driver.integrity.risk.normal", QStringLiteral("正常")),
            QStringLiteral("0"),
            driverText(
                "driver.integrity.cross_view.empty",
                QStringLiteral("当前完整性缓存没有可投影的模块交叉视图证据。")));
    }

    if (moduleCrossViewStatusLabel_ != nullptr)
    {
        moduleCrossViewStatusLabel_->setText(
            driverText(
                "driver.integrity.cross_view.updated",
                QStringLiteral("状态：模块 Cross-View 已更新，显示 %1 条。"))
            .arg(moduleCrossViewTable_->rowCount()));
    }
    moduleCrossViewTable_->setSortingEnabled(true);
}

bool DriverDock::selectedPiDdbEntryIdentity(
    ksword::ark::PiDdbEntry* identity) const
{
    // DriverDock.Unloaded.cpp writes the source cache index into the name column's dedicated role.
    constexpr int kUnloadedCacheIndexRole = Qt::UserRole + 57;
    constexpr std::uint32_t kRequiredIdentityFlags =
        KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_NAME |
        KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_TIMESTAMP |
        KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_LOAD_STATUS;

    if (unloadedDriverQuerying_ ||
        unloadedPiddbTable_ == nullptr ||
        unloadedPiddbSourceGroup_ == nullptr ||
        unloadedPiddbSourceGroup_->checkedId() !=
            KSWORD_ARK_UNLOADED_DRIVER_SOURCE_PIDDB_CACHE_TABLE ||
        !lastUnloadedDriverResult_.io.ok ||
        lastUnloadedDriverResult_.source !=
            KSWORD_ARK_UNLOADED_DRIVER_SOURCE_PIDDB_CACHE_TABLE)
    {
        return false;
    }

    const int kCurrentRow = unloadedPiddbTable_->currentRow();
    const QTableWidgetItem* nameItem = kCurrentRow >= 0
        ? unloadedPiddbTable_->item(kCurrentRow, 0)
        : nullptr;
    bool indexOk = false;
    const qulonglong kCacheIndex = nameItem != nullptr
        ? nameItem->data(kUnloadedCacheIndexRole).toULongLong(&indexOk)
        : 0ULL;
    if (!indexOk ||
        kCacheIndex >= static_cast<qulonglong>(unloadedDriverCache_.size()))
    {
        return false;
    }

    const ksword::ark::UnloadedDriverEntry& row =
        unloadedDriverCache_[static_cast<std::size_t>(kCacheIndex)];
    if (row.source != KSWORD_ARK_UNLOADED_DRIVER_SOURCE_PIDDB_CACHE_TABLE ||
        (row.flags & kRequiredIdentityFlags) != kRequiredIdentityFlags ||
        row.entryAddress == 0ULL ||
        row.driverName.empty())
    {
        return false;
    }

    if (identity != nullptr)
    {
        identity->entryAddress = row.entryAddress;
        identity->timeDateStamp = row.timeDateStamp;
        identity->loadStatus = row.loadStatus;
        identity->driverName = row.driverName;
    }
    return true;
}

void DriverDock::deleteSelectedPiDdbEntry()
{
    ksword::ark::PiDdbEntry expected{};
    if (!selectedPiDdbEntryIdentity(&expected))
    {
        return;
    }

    const ksword::ark::DriverClient kClient;
    const ksword::ark::PiDdbDeleteResult kPreflight =
        kClient.deletePiDdbEntry(expected, false, false);
    if (!kPreflight.io.ok ||
        kPreflight.status != KSWORD_ARK_PIDDB_DELETE_STATUS_FORCE_REQUIRED)
    {
        QMessageBox::critical(
            this,
            driverText(
                "driver.piddb.delete.title",
                QStringLiteral("删除 PiDDB 表项")),
            driverText(
                "driver.piddb.delete.preflight_failed",
                QStringLiteral(
                    "R0 精确身份预检失败。状态 %1，NTSTATUS %2。\n%3"))
                .arg(kPreflight.status)
                .arg(formatNtStatusText(kPreflight.lastStatus))
                .arg(describeDriverCollection(kPreflight.io)));
        return;
    }

    QMessageBox::warning(
        this,
        driverText(
            "driver.piddb.delete.warning_title",
            QStringLiteral("高风险：修改内核驱动历史缓存")),
        driverText(
            "driver.piddb.delete.warning",
            QStringLiteral(
                "将从活动 PiDDB AVL 表删除“%1”（时间戳 0x%2，地址 %3）。"
                "这会改变内核驱动加载历史，可能影响诊断、安全产品或系统稳定性；"
                "操作不可由本程序自动撤销。"))
            .arg(QString::fromStdWString(expected.driverName))
            .arg(expected.timeDateStamp, 8, 16, QLatin1Char('0'))
            .arg(hex64(expected.entryAddress)));

    bool accepted = false;
    const QString kConfirmation = QInputDialog::getText(
        this,
        driverText(
            "driver.piddb.delete.confirm_title",
            QStringLiteral("确认删除 PiDDB 表项")),
        driverText(
            "driver.piddb.delete.confirm_prompt",
            QStringLiteral("输入 DELETE PIDDB 继续：")),
        QLineEdit::Normal,
        QString(),
        &accepted);
    if (!accepted || kConfirmation != QStringLiteral("DELETE PIDDB"))
    {
        return;
    }

    const ksword::ark::PiDdbDeleteResult kDeleted =
        kClient.deletePiDdbEntry(expected, true, true);
    if (!kDeleted.io.ok ||
        kDeleted.status != KSWORD_ARK_PIDDB_DELETE_STATUS_OK)
    {
        QMessageBox::critical(
            this,
            driverText(
                "driver.piddb.delete.title",
                QStringLiteral("删除 PiDDB 表项")),
            driverText(
                "driver.piddb.delete.failed",
                QStringLiteral("删除失败。状态 %1，NTSTATUS %2。\n%3"))
                .arg(kDeleted.status)
                .arg(formatNtStatusText(kDeleted.lastStatus))
                .arg(describeDriverCollection(kDeleted.io)));
        return;
    }

    QMessageBox::information(
        this,
        driverText(
            "driver.piddb.delete.title",
            QStringLiteral("删除 PiDDB 表项")),
        driverText(
            "driver.piddb.delete.completed",
            QStringLiteral(
                "精确表项已删除，并在同一内核锁保护下复核为不存在。剩余 %1 项。"))
            .arg(kDeleted.remainingRows));
    refreshUnloadedDriversAsync();
}

void DriverDock::showSelectedDriverIntegrityDetail()
{
    // Input: None; read the selected row from the current integrity table.
    // Processing: Expand details via cached index.
    // Returns: Nothing.
    if (integrityDetailEdit_ == nullptr || integrityTable_ == nullptr)
    {
        return;
    }
    const int kCurrentRow = integrityTable_->currentRow();
    if (kCurrentRow < 0)
    {
        integrityDetailEdit_->setText(
            driverText("driver.integrity.detail.select_row", QStringLiteral("请选择一条驱动完整性证据。")));
        return;
    }
    const QTableWidgetItem* classItem = integrityTable_->item(kCurrentRow, integrityColumnIndex(IntegrityColumn::kClass));
    bool ok = false;
    const qulonglong kCacheIndex = classItem != nullptr ? classItem->data(Qt::UserRole + 1).toULongLong(&ok) : 0ULL;
    if (!ok || kCacheIndex >= static_cast<qulonglong>(driverIntegrityCache_.size()))
    {
        return;
    }
    integrityDetailEdit_->setText(detailText(driverIntegrityCache_[static_cast<std::size_t>(kCacheIndex)]));
}
