#include "DriverDock.Internal.h"
#include "../kernel_dock/KernelThreadAuditTab.h"
#include "../ui/VisibleTableWidget.h"
#include "../ui/DetailLayoutRegistry.h"
/* Unified entry point: this page does not need to know GPA, EPT leaf, or ruleId. */
#include "../ui/KvmWatchDialog.h"

#include <QAction>
#include <QMenu>

// Note: Migrated from the original aggregated implementation to a standalone .cpp file; member function implementations remain unchanged.
using namespace ksword::driver_dock_internal;

namespace ksword::driver_dock_internal
{
    namespace
    {
        // The evidence collection worker thread generates only stable source text; this flag is thread-local and does not alter the GUI thread's language state.
        thread_local bool driverEvidenceSourceTextOnly = false;
    }

    QString driverText(const char* const contextKey, const QString& sourceText)
    {
        if (driverEvidenceSourceTextOnly)
        {
            return sourceText;
        }
        return ks::i18n::contextText(QString::fromLatin1(contextKey), sourceText);
    }

    bool swapDriverEvidenceSourceTextMode(const bool sourceTextOnly)
    {
        const bool kPreviousMode = driverEvidenceSourceTextOnly;
        driverEvidenceSourceTextOnly = sourceTextOnly;
        return kPreviousMode;
    }

    QStringList driverServiceTableHeaders()
    {
        return {
            driverText("driver.header.service_name", QStringLiteral("服务名")),
            driverText("driver.header.display_name", QStringLiteral("显示名")),
            driverText("driver.header.status", QStringLiteral("状态")),
            driverText("driver.header.start_type", QStringLiteral("启动类型")),
            driverText("driver.header.error_control", QStringLiteral("错误控制")),
            driverText("driver.header.image_path", QStringLiteral("映像路径")),
            driverText("driver.header.description", QStringLiteral("描述"))
        };
    }

    QStringList driverModuleTableHeaders()
    {
        return {
            driverText("driver.header.module_name", QStringLiteral("模块名")),
            driverText("driver.header.base_address", QStringLiteral("基址")),
            driverText("driver.header.digital_signature", QStringLiteral("数字签名")),
            driverText("driver.header.driver_object", QStringLiteral("DriverObject")),
            driverText("driver.header.driver_start", QStringLiteral("DriverStart")),
            driverText("driver.header.major_function", QStringLiteral("MajorFunction")),
            driverText("driver.header.iat_eat", QStringLiteral("IAT/EAT")),
            driverText("driver.header.inline_hook", QStringLiteral("Inline Hook")),
            driverText("driver.header.callback", QStringLiteral("Callback")),
            driverText("driver.header.module_image_path", QStringLiteral("映像路径"))
        };
    }

    QStringList driverObjectEvidenceTableHeaders()
    {
        return {
            driverText("driver.header.field", QStringLiteral("字段")),
            driverText("driver.header.value", QStringLiteral("值"))
        };
    }

    QStringList driverDeviceObjectTableHeaders()
    {
        return {
            driverText("driver.header.relationship", QStringLiteral("关系")),
            driverText("driver.header.device_object", QStringLiteral("DeviceObject")),
            driverText("driver.header.device_name", QStringLiteral("设备名")),
            driverText("driver.header.type", QStringLiteral("Type")),
            driverText("driver.header.flags", QStringLiteral("Flags")),
            driverText("driver.header.characteristics", QStringLiteral("Characteristics")),
            driverText("driver.header.stack", QStringLiteral("Stack")),
            driverText("driver.header.next_device", QStringLiteral("NextDevice")),
            driverText("driver.header.attached_device", QStringLiteral("AttachedDevice")),
            driverText("driver.header.driver_object", QStringLiteral("DriverObject"))
        };
    }

    QStringList driverEvidenceTableHeaders()
    {
        return {
            driverText("driver.header.evidence", QStringLiteral("证据")),
            driverText("driver.header.object", QStringLiteral("对象")),
            driverText("driver.header.target", QStringLiteral("目标")),
            driverText("driver.header.risk", QStringLiteral("风险")),
            driverText("driver.header.confidence", QStringLiteral("置信度")),
            driverText("driver.header.detail", QStringLiteral("Detail"))
        };
    }

    QStringList driverIntegrityTableHeaders()
    {
        return {
            driverText("driver.header.class", QStringLiteral("类别")),
            driverText("driver.header.object", QStringLiteral("对象")),
            driverText("driver.header.target", QStringLiteral("目标")),
            driverText("driver.header.owner", QStringLiteral("Owner")),
            driverText("driver.header.cpu_vector", QStringLiteral("CPU/Vector")),
            driverText("driver.header.risk", QStringLiteral("风险")),
            driverText("driver.header.confidence", QStringLiteral("置信度")),
            driverText("driver.header.explanation", QStringLiteral("说明"))
        };
    }

    QStringList driverMajorFunctionTableHeaders()
    {
        return {
            driverText("driver.header.irp_mj", QStringLiteral("IRP_MJ")),
            driverText("driver.header.dispatch", QStringLiteral("Dispatch")),
            driverText("driver.header.module", QStringLiteral("模块")),
            driverText("driver.header.module_base", QStringLiteral("模块基址")),
            driverText("driver.header.location", QStringLiteral("位置"))
        };
    }

    QStringList driverModuleCrossViewTableHeaders()
    {
        return {
            driverText("driver.header.evidence", QStringLiteral("证据")),
            driverText("driver.header.object", QStringLiteral("对象")),
            driverText("driver.header.target", QStringLiteral("目标")),
            driverText("driver.header.risk", QStringLiteral("风险")),
            driverText("driver.header.source", QStringLiteral("来源")),
            driverText("driver.header.confidence", QStringLiteral("置信度")),
            driverText("driver.header.detail", QStringLiteral("Detail"))
        };
    }

    QStringList driverUnloadedDriverTableHeaders()
    {
        // Header order matches the issue screenshot; missing fields from the three sources are displayed as '-' via the HAS_* flags.
        return {
            driverText("driver.unloaded.header.name", QStringLiteral("名称")),
            driverText("driver.unloaded.header.base", QStringLiteral("基址")),
            driverText("driver.unloaded.header.size", QStringLiteral("大小")),
            driverText("driver.unloaded.header.timestamp", QStringLiteral("时间戳")),
            driverText("driver.unloaded.header.load_status", QStringLiteral("加载状态")),
            driverText("driver.unloaded.header.unload_time", QStringLiteral("卸载时间"))
        };
    }
}

namespace
{
    QString driverTableCellText(QTableWidget* table, const int rowIndex, const int columnIndex)
    {
        // driverTableCellText：
        // - Input: Table, row index, and column index;
        // - Processing: Safely read cell text;
        // - Returns: Empty string for empty cells.
        if (table == nullptr)
        {
            return QString();
        }
        const QTableWidgetItem* item = table->item(rowIndex, columnIndex);
        return item != nullptr ? item->text() : QString();
    }

    void copyDriverTableCurrentRow(QTableWidget* table)
    {
        // copyDriverTableCurrentRow：
        // - Input: DriverDock read-only table.
        // - Processing: Copy the current row as TSV;
        // - Return: None; returns immediately if the clipboard is unavailable or no selection exists.
        if (table == nullptr || QGuiApplication::clipboard() == nullptr)
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
            fields.push_back(driverTableCellText(table, kRowIndex, columnIndex));
        }
        QGuiApplication::clipboard()->setText(fields.join(QLatin1Char('\t')));
    }

    void installDriverTableCopyMenu(QTableWidget* table)
    {
        // installDriverTableCopyMenu：
        // - Input: Read-only evidence table for DriverDock without destructive actions.
        // - Processing: Install the copy current row menu.
        // - Return: None; does not trigger R0/R3 modification operations.
        if (table == nullptr)
        {
            return;
        }

        table->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(table, &QTableWidget::customContextMenuRequested, table, [table](const QPoint& localPosition)
        {
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
                copyDriverTableCurrentRow(table);
            }
        });
    }
}

void DriverDock::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event != nullptr && event->type() == QEvent::LanguageChange)
    {
        applyTranslatedHeaders();
        updateDebugCaptureButtonState();
        refreshDebugOutputLines();
        // The signature cache stores only semantics; when switching languages, synchronize the reconstruction of row text, filter results, details, and summaries.
        rebuildLoadedModuleTable();
        updateLoadedModuleEvidenceStatusText();
    }
}

void DriverDock::applyTranslatedHeaders()
{
    if (servicePage_ != nullptr && tabWidget_ != nullptr)
    {
        const int kServiceTabIndex = tabWidget_->indexOf(servicePage_);
        if (kServiceTabIndex >= 0)
        {
            tabWidget_->setTabText(
                kServiceTabIndex,
                driverText("driver.tab.services", QStringLiteral("驱动服务")));
        }
    }
    if (kernelModulePage_ != nullptr && tabWidget_ != nullptr)
    {
        const int kKernelModuleTabIndex = tabWidget_->indexOf(kernelModulePage_);
        if (kKernelModuleTabIndex >= 0)
        {
            tabWidget_->setTabText(
                kKernelModuleTabIndex,
                driverText("driver.tab.kernel_modules", QStringLiteral("内核模块")));
        }
    }
    if (serviceFilterEdit_ != nullptr)
    {
        serviceFilterEdit_->setPlaceholderText(driverText(
            "driver.service.filter.placeholder", QStringLiteral("搜索驱动服务")));
        serviceFilterEdit_->setToolTip(driverText(
            "driver.service.filter.tooltip", QStringLiteral("按服务名、显示名、描述和映像路径过滤")));
    }
    if (moduleFilterEdit_ != nullptr)
    {
        moduleFilterEdit_->setPlaceholderText(driverText(
            "driver.kernel_module.filter.placeholder", QStringLiteral("搜索内核模块")));
        moduleFilterEdit_->setToolTip(driverText(
            "driver.kernel_module.filter.tooltip", QStringLiteral("按模块名、签名状态和映像路径过滤")));
    }
    if (serviceTable_ != nullptr)
    {
        serviceTable_->setHorizontalHeaderLabels(driverServiceTableHeaders());
    }
    if (moduleTable_ != nullptr)
    {
        moduleTable_->setHorizontalHeaderLabels(driverModuleTableHeaders());
    }
    if (driverObjectEvidenceTable_ != nullptr)
    {
        driverObjectEvidenceTable_->setHorizontalHeaderLabels(driverObjectEvidenceTableHeaders());
    }
    if (deviceObjectTable_ != nullptr)
    {
        deviceObjectTable_->setHorizontalHeaderLabels(driverDeviceObjectTableHeaders());
    }
    if (driverExtensionEvidenceTable_ != nullptr)
    {
        driverExtensionEvidenceTable_->setHorizontalHeaderLabels(driverEvidenceTableHeaders());
    }
    if (majorFunctionTable_ != nullptr)
    {
        majorFunctionTable_->setHorizontalHeaderLabels(driverMajorFunctionTableHeaders());
    }
    if (fastIoEvidenceTable_ != nullptr)
    {
        fastIoEvidenceTable_->setHorizontalHeaderLabels(driverEvidenceTableHeaders());
    }
    if (integrityTable_ != nullptr)
    {
        integrityTable_->setHorizontalHeaderLabels(driverIntegrityTableHeaders());
    }
    if (moduleCrossViewTable_ != nullptr)
    {
        moduleCrossViewTable_->setHorizontalHeaderLabels(driverModuleCrossViewTableHeaders());
    }
    if (unloadedPiddbTable_ != nullptr)
    {
        unloadedPiddbTable_->setHorizontalHeaderLabels(driverUnloadedDriverTableHeaders());
    }
    if (unloadedPiddbDeleteButton_ != nullptr)
    {
        unloadedPiddbDeleteButton_->setText(
            driverText(
                "driver.unloaded.delete_exact",
                QStringLiteral("删除选中 PiDDB 表项")));
    }
    if (systemThreadAuditTab_ != nullptr)
    {
        const int kSystemThreadTabIndex = tabWidget_->indexOf(systemThreadAuditTab_);
        if (kSystemThreadTabIndex >= 0)
        {
            tabWidget_->setTabText(
                kSystemThreadTabIndex,
                driverText("driver.tab.system_threads", QStringLiteral("系统线程")));
            tabWidget_->setTabToolTip(
                kSystemThreadTabIndex,
                driverText(
                    "driver.tab.system_threads.tooltip",
                    QStringLiteral("枚举 System(PID 4) 线程并提供受保护的第三方驱动线程管理")));
        }
    }
    if (kswordSelfDriverPage_ != nullptr && kswordSelfDriverTabIndex_ >= 0)
    {
        tabWidget_->setTabText(
            kswordSelfDriverTabIndex_,
            driverText("driver.tab.self_driver", QStringLiteral("Ksword自身驱动")));
        tabWidget_->setTabToolTip(
            kswordSelfDriverTabIndex_,
            driverText(
                "driver.tab.self_driver.tooltip",
                QStringLiteral("KswordARK 动态偏移与驱动状态")));
    }
}

void DriverDock::initializeUi()
{
    rootLayout_ = new QVBoxLayout(this);
    rootLayout_->setContentsMargins(6, 6, 6, 6);
    rootLayout_->setSpacing(6);

    tabWidget_ = new QTabWidget(this);
    rootLayout_->addWidget(tabWidget_, 1);

    initializeServiceTab();
    initializeKernelModuleTab();
    initializeOperateTab();
    initializeDebugOutputTab();
    initializeObjectInfoTab();
    initializeModuleCrossViewTab();
    initializeIntegrityTab();
    initializeUnloadedPiddbTab();
    initializeSystemThreadTab();
}

void DriverDock::initializeSystemThreadTab()
{
    if (tabWidget_ == nullptr || systemThreadAuditTab_ != nullptr)
    {
        return;
    }

    // The System Threads tab is responsible only for display and confirmation; all KswordARK operations are performed by ArkDriverClient within the component.
    systemThreadAuditTab_ = new KernelThreadAuditTab(
        KernelThreadAuditTab::Mode::kSystemThreads,
        tabWidget_);
    const int kTabIndex = tabWidget_->addTab(
        systemThreadAuditTab_,
        QIcon(QStringLiteral(":/Icon/process_threads.svg")),
        driverText("driver.tab.system_threads", QStringLiteral("系统线程")));
    tabWidget_->setTabToolTip(
        kTabIndex,
        driverText(
            "driver.tab.system_threads.tooltip",
            QStringLiteral("枚举 System(PID 4) 线程并提供受保护的第三方驱动线程管理")));
}

void DriverDock::initializeServiceTab()
{
    // Input: none; Processing: create an independent driver service page; Return: none.
    servicePage_ = new QWidget(tabWidget_);
    overviewPage_ = servicePage_;
    serviceLayout_ = new QVBoxLayout(servicePage_);
    overviewLayout_ = serviceLayout_;
    serviceLayout_->setContentsMargins(4, 4, 4, 4);
    serviceLayout_->setSpacing(6);

    overviewToolLayout_ = new QHBoxLayout();
    overviewToolLayout_->setContentsMargins(0, 0, 0, 0);
    overviewToolLayout_->setSpacing(6);

    refreshServiceButton_ = new QPushButton(servicePage_);
    refreshServiceButton_->setIcon(QIcon(":/Icon/process_refresh.svg"));
    refreshServiceButton_->setToolTip(driverText(
        "driver.toolbar.refresh_services.tooltip", QStringLiteral("刷新驱动服务列表")));
    ksword_theme::applyCompactIconButtonMetrics(refreshServiceButton_);

    serviceFilterEdit_ = new QLineEdit(servicePage_);
    serviceFilterEdit_->setPlaceholderText(driverText(
        "driver.service.filter.placeholder", QStringLiteral("搜索驱动服务")));
    serviceFilterEdit_->setToolTip(driverText(
        "driver.service.filter.tooltip", QStringLiteral("按服务名、显示名、描述和映像路径过滤")));

    overviewStatusLabel_ = new QLabel(driverText(
        "driver.status.waiting_refresh", QStringLiteral("状态：等待刷新")), servicePage_);
    overviewStatusLabel_->setWordWrap(true);
    overviewToolLayout_->addWidget(refreshServiceButton_);
    overviewToolLayout_->addWidget(serviceFilterEdit_, 1);
    overviewToolLayout_->addWidget(overviewStatusLabel_);
    serviceLayout_->addLayout(overviewToolLayout_);

    serviceTable_ = new ks::ui::VisibleTableWidget(servicePage_);
    serviceTable_->setColumnCount(7);
    serviceTable_->setHorizontalHeaderLabels(driverServiceTableHeaders());
    serviceTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    serviceTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    serviceTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    serviceTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    serviceTable_->setAlternatingRowColors(true);
    serviceTable_->verticalHeader()->setVisible(false);
    serviceTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    serviceTable_->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Stretch);
    serviceTable_->horizontalHeader()->setSectionResizeMode(6, QHeaderView::Stretch);
    serviceLayout_->addWidget(serviceTable_, 1);

    tabWidget_->addTab(servicePage_, QIcon(":/Icon/process_list.svg"), driverText(
        "driver.tab.services", QStringLiteral("驱动服务")));
}

void DriverDock::initializeKernelModuleTab()
{
    // Input: None; Processing: Build module list and unified details editor; Output: None.
    kernelModulePage_ = new QWidget(tabWidget_);
    kernelModuleLayout_ = new QVBoxLayout(kernelModulePage_);
    kernelModuleLayout_->setContentsMargins(4, 4, 4, 4);
    kernelModuleLayout_->setSpacing(6);
    kernelModuleToolLayout_ = new QHBoxLayout();
    kernelModuleToolLayout_->setContentsMargins(0, 0, 0, 0);
    kernelModuleToolLayout_->setSpacing(6);

    refreshModuleButton_ = new QPushButton(kernelModulePage_);
    refreshModuleButton_->setIcon(QIcon(":/Icon/process_refresh.svg"));
    refreshModuleButton_->setToolTip(driverText(
        "driver.toolbar.refresh_modules.tooltip", QStringLiteral("刷新已加载内核模块")));
    ksword_theme::applyCompactIconButtonMetrics(refreshModuleButton_);
    refreshModuleEvidenceButton_ = new QPushButton(kernelModulePage_);
    refreshModuleEvidenceButton_->setIcon(QIcon(":/Icon/process_refresh.svg"));
    refreshModuleEvidenceButton_->setToolTip(driverText(
        "driver.toolbar.refresh_module_evidence.tooltip", QStringLiteral("刷新内核模块证据")));
    ksword_theme::applyCompactIconButtonMetrics(refreshModuleEvidenceButton_);
    moduleEvidenceStatusLabel_ = new QLabel(driverText(
        "driver.overview.evidence.status.waiting", QStringLiteral("证据：等待刷新")), kernelModulePage_);
    moduleEvidenceStatusLabel_->setWordWrap(true);
    moduleFilterEdit_ = new QLineEdit(kernelModulePage_);
    moduleFilterEdit_->setPlaceholderText(driverText(
        "driver.kernel_module.filter.placeholder", QStringLiteral("搜索内核模块")));
    moduleFilterEdit_->setToolTip(driverText(
        "driver.kernel_module.filter.tooltip", QStringLiteral("按模块名、签名状态和映像路径过滤")));
    kernelModuleToolLayout_->addWidget(refreshModuleButton_);
    kernelModuleToolLayout_->addWidget(refreshModuleEvidenceButton_);
    kernelModuleToolLayout_->addWidget(moduleFilterEdit_, 1);
    kernelModuleToolLayout_->addWidget(moduleEvidenceStatusLabel_);
    kernelModuleLayout_->addLayout(kernelModuleToolLayout_);

    moduleTable_ = new ks::ui::VisibleTableWidget(kernelModulePage_);
    moduleTable_->setColumnCount(kModuleTableColumnCount);
    moduleTable_->setHorizontalHeaderLabels(driverModuleTableHeaders());
    moduleTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    moduleTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    moduleTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    moduleTable_->setAlternatingRowColors(true);
    moduleTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    moduleTable_->verticalHeader()->setVisible(false);
    moduleTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    moduleTable_->horizontalHeader()->setSectionResizeMode(kModuleImagePathColumn, QHeaderView::Stretch);
    kernelModuleLayout_->addWidget(moduleTable_, 3);

    moduleEvidenceDetailEditor_ = new CodeEditorWidget(kernelModulePage_);
    moduleEvidenceDetailEditor_->setReadOnly(true);
    moduleEvidenceDetailEditor_->setText(driverText(
        "driver.overview.evidence.detail.initial", QStringLiteral("请选择一条已加载模块，或点击证据刷新按钮。")));
    kernelModuleLayout_->addWidget(moduleEvidenceDetailEditor_, 2);
    ks::ui::DetailLayoutRegistry::registerHost(
        moduleTable_, moduleEvidenceDetailEditor_, kernelModulePage_);
    tabWidget_->addTab(kernelModulePage_, QIcon(":/Icon/process_list.svg"), driverText(
        "driver.tab.kernel_modules", QStringLiteral("内核模块")));
}

void DriverDock::initializeOperateTab()
{
    operatePage_ = new QWidget(tabWidget_);
    operateLayout_ = new QVBoxLayout(operatePage_);
    operateLayout_->setContentsMargins(4, 4, 4, 4);
    operateLayout_->setSpacing(6);

    QGridLayout* formLayout = new QGridLayout();
    formLayout->setHorizontalSpacing(8);
    formLayout->setVerticalSpacing(6);
    formLayout->setColumnStretch(1, 1);
    formLayout->setColumnStretch(3, 1);

    serviceNameEdit_ = new QLineEdit(operatePage_);
    serviceNameEdit_->setPlaceholderText(
        driverText("driver.form.service_name.placeholder", QStringLiteral("例如 MyDriver")));
    displayNameEdit_ = new QLineEdit(operatePage_);
    displayNameEdit_->setPlaceholderText(
        driverText("driver.form.display_name.placeholder", QStringLiteral("例如 My Driver Service")));
    binaryPathEdit_ = new QLineEdit(operatePage_);
    binaryPathEdit_->setPlaceholderText(
        driverText(
            "driver.form.binary_path.placeholder",
            QStringLiteral("例如 C:\\Windows\\System32\\drivers\\mydrv.sys")));
    descriptionEdit_ = new QLineEdit(operatePage_);
    descriptionEdit_->setPlaceholderText(
        driverText("driver.form.description.placeholder", QStringLiteral("描述（可选）")));

    browsePathButton_ = new QPushButton(operatePage_);
    browsePathButton_->setIcon(QIcon(":/Icon/process_open_folder.svg"));
    browsePathButton_->setToolTip(
        driverText("driver.form.browse_path.tooltip", QStringLiteral("浏览并选择 .sys 文件")));
    ksword_theme::applyCompactIconButtonMetrics(browsePathButton_);

    startTypeCombo_ = new QComboBox(operatePage_);
    startTypeCombo_->addItem(
        driverText("driver.form.start_type.boot", QStringLiteral("引导启动（BOOT）")),
        static_cast<int>(SERVICE_BOOT_START));
    startTypeCombo_->addItem(
        driverText("driver.form.start_type.system", QStringLiteral("系统启动（SYSTEM）")),
        static_cast<int>(SERVICE_SYSTEM_START));
    startTypeCombo_->addItem(
        driverText("driver.form.start_type.auto", QStringLiteral("自动启动（AUTO）")),
        static_cast<int>(SERVICE_AUTO_START));
    startTypeCombo_->addItem(
        driverText("driver.form.start_type.demand", QStringLiteral("手动启动（DEMAND）")),
        static_cast<int>(SERVICE_DEMAND_START));
    startTypeCombo_->addItem(
        driverText("driver.form.start_type.disabled", QStringLiteral("禁用（DISABLED）")),
        static_cast<int>(SERVICE_DISABLED));

    errorControlCombo_ = new QComboBox(operatePage_);
    errorControlCombo_->addItem(
        driverText("driver.form.error_control.ignore", QStringLiteral("忽略（IGNORE）")),
        static_cast<int>(SERVICE_ERROR_IGNORE));
    errorControlCombo_->addItem(
        driverText("driver.form.error_control.normal", QStringLiteral("正常（NORMAL）")),
        static_cast<int>(SERVICE_ERROR_NORMAL));
    errorControlCombo_->addItem(
        driverText("driver.form.error_control.severe", QStringLiteral("严重（SEVERE）")),
        static_cast<int>(SERVICE_ERROR_SEVERE));
    errorControlCombo_->addItem(
        driverText("driver.form.error_control.critical", QStringLiteral("致命（CRITICAL）")),
        static_cast<int>(SERVICE_ERROR_CRITICAL));

    formLayout->addWidget(new QLabel(
        driverText("driver.form.label.service_name", QStringLiteral("服务名:")),
        operatePage_), 0, 0);
    formLayout->addWidget(serviceNameEdit_, 0, 1);
    formLayout->addWidget(new QLabel(
        driverText("driver.form.label.display_name", QStringLiteral("显示名:")),
        operatePage_), 0, 2);
    formLayout->addWidget(displayNameEdit_, 0, 3);
    formLayout->addWidget(new QLabel(
        driverText("driver.form.label.binary_path", QStringLiteral("驱动路径:")),
        operatePage_), 1, 0);
    formLayout->addWidget(binaryPathEdit_, 1, 1, 1, 2);
    formLayout->addWidget(browsePathButton_, 1, 3);
    formLayout->addWidget(new QLabel(
        driverText("driver.form.label.start_type", QStringLiteral("启动类型:")),
        operatePage_), 2, 0);
    formLayout->addWidget(startTypeCombo_, 2, 1);
    formLayout->addWidget(new QLabel(
        driverText("driver.form.label.error_control", QStringLiteral("错误控制:")),
        operatePage_), 2, 2);
    formLayout->addWidget(errorControlCombo_, 2, 3);
    formLayout->addWidget(new QLabel(
        driverText("driver.form.label.description", QStringLiteral("描述:")),
        operatePage_), 3, 0);
    formLayout->addWidget(descriptionEdit_, 3, 1, 1, 3);
    operateLayout_->addLayout(formLayout);

    QHBoxLayout* actionLayout = new QHBoxLayout();
    actionLayout->setContentsMargins(0, 0, 0, 0);
    actionLayout->setSpacing(6);

    registerOrUpdateButton_ = new QPushButton(operatePage_);
    registerOrUpdateButton_->setIcon(QIcon(":/Icon/codeeditor_save.svg"));
    registerOrUpdateButton_->setToolTip(
        driverText("driver.form.register_update.tooltip", QStringLiteral("注册新服务或更新现有服务")));
    ksword_theme::applyCompactIconButtonMetrics(registerOrUpdateButton_);

    loadDriverButton_ = new QPushButton(operatePage_);
    loadDriverButton_->setIcon(QIcon(":/Icon/process_start.svg"));
    loadDriverButton_->setToolTip(
        driverText("driver.form.load.tooltip", QStringLiteral("挂载（启动）驱动服务")));
    ksword_theme::applyCompactIconButtonMetrics(loadDriverButton_);

    unloadDriverButton_ = new QPushButton(operatePage_);
    unloadDriverButton_->setIcon(QIcon(":/Icon/process_pause.svg"));
    unloadDriverButton_->setToolTip(
        driverText("driver.form.unload.tooltip", QStringLiteral("卸载（停止）驱动服务")));
    ksword_theme::applyCompactIconButtonMetrics(unloadDriverButton_);

    deleteServiceButton_ = new QPushButton(operatePage_);
    deleteServiceButton_->setIcon(QIcon(":/Icon/log_clear.svg"));
    deleteServiceButton_->setToolTip(
        driverText("driver.form.delete.tooltip", QStringLiteral("删除驱动服务注册")));
    ksword_theme::applyCompactIconButtonMetrics(deleteServiceButton_);

    refreshStateButton_ = new QPushButton(operatePage_);
    refreshStateButton_->setIcon(QIcon(":/Icon/process_refresh.svg"));
    refreshStateButton_->setToolTip(
        driverText("driver.form.refresh_state.tooltip", QStringLiteral("刷新当前服务状态")));
    ksword_theme::applyCompactIconButtonMetrics(refreshStateButton_);

    actionLayout->addWidget(registerOrUpdateButton_);
    actionLayout->addWidget(loadDriverButton_);
    actionLayout->addWidget(unloadDriverButton_);
    actionLayout->addWidget(deleteServiceButton_);
    actionLayout->addWidget(refreshStateButton_);
    actionLayout->addStretch(1);
    operateLayout_->addLayout(actionLayout);

    operateLogOutput_ = new QPlainTextEdit(operatePage_);
    operateLogOutput_->setReadOnly(true);
    operateLogOutput_->setMaximumBlockCount(1200);
    operateLogOutput_->setPlaceholderText(
        driverText("driver.form.operation_log.placeholder", QStringLiteral("驱动操作日志显示在这里。")));
    operateLayout_->addWidget(operateLogOutput_, 1);

    tabWidget_->addTab(
        operatePage_,
        QIcon(":/Icon/process_main.svg"),
        driverText("driver.tab.operations", QStringLiteral("驱动操作")));
}

void DriverDock::initializeDebugOutputTab()
{
    debugOutputPage_ = new QWidget(tabWidget_);
    debugOutputLayout_ = new QVBoxLayout(debugOutputPage_);
    debugOutputLayout_->setContentsMargins(4, 4, 4, 4);
    debugOutputLayout_->setSpacing(6);

    debugToolLayout_ = new QHBoxLayout();
    debugToolLayout_->setContentsMargins(0, 0, 0, 0);
    debugToolLayout_->setSpacing(6);

    startCaptureButton_ = new QPushButton(debugOutputPage_);
    startCaptureButton_->setIcon(QIcon(":/Icon/process_start.svg"));
    // Capture source and filtering criteria are merged into the start button; no explanatory line remains permanently at the top of the page.
    startCaptureButton_->setToolTip(
        driverText(
            "driver.debug.start.tooltip",
            QStringLiteral("启动调试输出捕获。经 KswordARK R0 回调捕获 DbgPrint/DbgPrintEx/KdPrintEx，只显示通过当前内核调试筛选器的消息。")));
    ksword_theme::applyCompactIconButtonMetrics(startCaptureButton_);

    stopCaptureButton_ = new QPushButton(debugOutputPage_);
    stopCaptureButton_->setIcon(QIcon(":/Icon/process_pause.svg"));
    stopCaptureButton_->setToolTip(
        driverText("driver.debug.stop.tooltip", QStringLiteral("停止调试输出捕获")));
    ksword_theme::applyCompactIconButtonMetrics(stopCaptureButton_);

    clearDebugOutputButton_ = new QPushButton(debugOutputPage_);
    clearDebugOutputButton_->setIcon(QIcon(":/Icon/log_clear.svg"));
    clearDebugOutputButton_->setToolTip(
        driverText("driver.debug.clear.tooltip", QStringLiteral("清空调试输出")));
    ksword_theme::applyCompactIconButtonMetrics(clearDebugOutputButton_);

    copyDebugOutputButton_ = new QPushButton(debugOutputPage_);
    copyDebugOutputButton_->setIcon(QIcon(":/Icon/log_copy.svg"));
    copyDebugOutputButton_->setToolTip(
        driverText("driver.debug.copy.tooltip", QStringLiteral("复制全部调试输出")));
    ksword_theme::applyCompactIconButtonMetrics(copyDebugOutputButton_);

    debugCaptureStatusLabel_ = new QLabel(
        driverText("driver.debug.status.not_started", QStringLiteral("状态：未启动")),
        debugOutputPage_);
    debugCaptureStatusLabel_->setWordWrap(true);

    debugToolLayout_->addWidget(startCaptureButton_);
    debugToolLayout_->addWidget(stopCaptureButton_);
    debugToolLayout_->addWidget(clearDebugOutputButton_);
    debugToolLayout_->addWidget(copyDebugOutputButton_);
    debugToolLayout_->addWidget(debugCaptureStatusLabel_, 1);
    debugOutputLayout_->addLayout(debugToolLayout_);

    debugOutputEdit_ = new QPlainTextEdit(debugOutputPage_);
    debugOutputEdit_->setReadOnly(true);
    debugOutputEdit_->setMaximumBlockCount(2000);
    debugOutputEdit_->setPlaceholderText(
        driverText("driver.debug.output.placeholder", QStringLiteral("调试输出会实时显示在这里。")));
    debugOutputLayout_->addWidget(debugOutputEdit_, 1);

    tabWidget_->addTab(
        debugOutputPage_,
        QIcon(":/Icon/log_track.svg"),
        driverText("driver.tab.debug_output", QStringLiteral("调试输出")));
}

void DriverDock::initializeObjectInfoTab()
{
    // Phase-9 object info page:
    // - Input: DriverObject name; R0 side handles object reference counting.
    // - Split the page into five sub-pages: DriverObject, DeviceObject, DriverExtension, MajorFunction, and FastIo;
    // - All displayed information is read-only diagnostics; no write, patch, or unload operations are provided.
    objectInfoPage_ = new QWidget(tabWidget_);
    objectInfoLayout_ = new QVBoxLayout(objectInfoPage_);
    objectInfoLayout_->setContentsMargins(4, 4, 4, 4);
    objectInfoLayout_->setSpacing(6);

    QHBoxLayout* queryLayout = new QHBoxLayout();
    queryLayout->setContentsMargins(0, 0, 0, 0);
    queryLayout->setSpacing(6);

    objectDriverNameEdit_ = new QLineEdit(objectInfoPage_);
    objectDriverNameEdit_->setPlaceholderText(
        driverText("driver.object.driver_name.placeholder", QStringLiteral("\\Driver\\Null 或 Null")));
    objectDriverNameEdit_->setToolTip(
        driverText(
            "driver.object.driver_name.tooltip",
            QStringLiteral("只接受 DriverObject 名称；不要输入内核地址。")));

    fillObjectDriverNameButton_ = new QPushButton(QIcon(":/Icon/process_details.svg"), QString(), objectInfoPage_);
    ksword_theme::applyCompactIconButtonMetrics(fillObjectDriverNameButton_);
    fillObjectDriverNameButton_->setToolTip(
        driverText(
            "driver.object.fill_driver_name.tooltip",
            QStringLiteral("从驱动服务列表当前选中行填充 \\Driver\\服务名")));

    queryObjectInfoButton_ = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), objectInfoPage_);
    ksword_theme::applyCompactIconButtonMetrics(queryObjectInfoButton_);
    queryObjectInfoButton_->setToolTip(
        driverText(
            "driver.object.query.tooltip",
            QStringLiteral("通过 KswordARK 查询 DriverObject / DeviceObject")));

    objectEvidenceRefreshButton_ = new QPushButton(QIcon(":/Icon/process_details.svg"), QString(), objectInfoPage_);
    ksword_theme::applyCompactIconButtonMetrics(objectEvidenceRefreshButton_);
    objectEvidenceRefreshButton_->setToolTip(
        driverText(
            "driver.object.refresh_evidence.tooltip",
            QStringLiteral("仅重建当前 DriverObject / Integrity 证据投影")));

    objectInfoStatusLabel_ = new QLabel(
        driverText("driver.object.status.waiting", QStringLiteral("状态：等待查询")),
        objectInfoPage_);
    objectInfoStatusLabel_->setWordWrap(true);

    queryLayout->addWidget(new QLabel(QStringLiteral("DriverObject:"), objectInfoPage_));
    queryLayout->addWidget(objectDriverNameEdit_, 1);
    queryLayout->addWidget(fillObjectDriverNameButton_);
    queryLayout->addWidget(queryObjectInfoButton_);
    queryLayout->addWidget(objectEvidenceRefreshButton_);
    queryLayout->addWidget(objectInfoStatusLabel_, 1);
    objectInfoLayout_->addLayout(queryLayout);

    // DriverObject top summary is R0 read-only diagnostic text:
    // - Use the project's unified CodeEditorWidget to ensure consistent dark/light mode appearance and copy/find experience;
    // - A structured table below the summary carries specific fields; a summary-only display is not used.
    objectInfoSummaryEdit_ = new CodeEditorWidget(objectInfoPage_);
    objectInfoSummaryEdit_->setReadOnly(true);
    objectInfoSummaryEdit_->setMaximumHeight(145);
    objectInfoSummaryEdit_->setText(
        driverText("driver.object.summary.initial", QStringLiteral("DriverObject 摘要显示在这里。")));
    objectInfoLayout_->addWidget(objectInfoSummaryEdit_);

    objectDetailTabWidget_ = new QTabWidget(objectInfoPage_);
    objectDetailTabWidget_->setDocumentMode(true);
    objectInfoLayout_->addWidget(objectDetailTabWidget_, 1);

    auto configureReadOnlyTable = [](QTableWidget* table)
    {
        if (table == nullptr)
        {
            return;
        }
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setSelectionMode(QAbstractItemView::SingleSelection);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table->setAlternatingRowColors(true);
        table->verticalHeader()->setVisible(false);
        table->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
        installDriverTableCopyMenu(table);
    };

    // DriverObject diagnostic page: displays only basic fields and brief evidence for the current object query.
    driverObjectPage_ = new QWidget(objectDetailTabWidget_);
    QVBoxLayout* driverObjectLayout = new QVBoxLayout(driverObjectPage_);
    driverObjectLayout->setContentsMargins(0, 0, 0, 0);
    driverObjectLayout->setSpacing(4);
    // DriverObject sub-page summary:
    // - Display only the core fields of the current DriverObject.
    // - Detailed evidence is continued to be displayed by the table below; text controls are uniformly set to CodeEditorWidget.
    driverObjectPageSummaryEdit_ = new CodeEditorWidget(driverObjectPage_);
    driverObjectPageSummaryEdit_->setReadOnly(true);
    driverObjectPageSummaryEdit_->setMaximumHeight(130);
    driverObjectPageSummaryEdit_->setText(
        driverText(
            "driver.object.page_summary.initial",
            QStringLiteral("DriverObject 页摘要显示在这里。")));
    driverObjectLayout->addWidget(driverObjectPageSummaryEdit_);

    driverObjectEvidenceTable_ = new ks::ui::VisibleTableWidget(driverObjectPage_);
    driverObjectEvidenceTable_->setColumnCount(2);
    driverObjectEvidenceTable_->setHorizontalHeaderLabels(driverObjectEvidenceTableHeaders());
    configureReadOnlyTable(driverObjectEvidenceTable_);
    driverObjectEvidenceTable_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    driverObjectLayout->addWidget(driverObjectEvidenceTable_, 1);
    objectDetailTabWidget_->addTab(driverObjectPage_, QIcon(":/Icon/process_details.svg"), QStringLiteral("DriverObject"));

    // DeviceObject diagnostic page: displays the device chain mounted under the DriverObject.
    deviceObjectPage_ = new QWidget(objectDetailTabWidget_);
    QVBoxLayout* deviceLayout = new QVBoxLayout(deviceObjectPage_);
    deviceLayout->setContentsMargins(0, 0, 0, 0);
    deviceLayout->setSpacing(4);
    deviceLayout->addWidget(new QLabel(
        driverText(
            "driver.object.device_chain.title",
            QStringLiteral("DeviceObject / AttachedDevice 链")),
        deviceObjectPage_));

    deviceObjectTable_ = new ks::ui::VisibleTableWidget(deviceObjectPage_);
    deviceObjectTable_->setColumnCount(10);
    deviceObjectTable_->setHorizontalHeaderLabels(driverDeviceObjectTableHeaders());
    configureReadOnlyTable(deviceObjectTable_);
    deviceObjectTable_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    deviceLayout->addWidget(deviceObjectTable_, 1);
    objectDetailTabWidget_->addTab(deviceObjectPage_, QIcon(":/Icon/process_list.svg"), QStringLiteral("DeviceObject"));

    // DriverExtension diagnostic page: The current protocol does not directly expose the DriverExtension pointer, so associated evidence is displayed.
    driverExtensionPage_ = new QWidget(objectDetailTabWidget_);
    QVBoxLayout* driverExtensionLayout = new QVBoxLayout(driverExtensionPage_);
    driverExtensionLayout->setContentsMargins(0, 0, 0, 0);
    driverExtensionLayout->setSpacing(4);
    driverExtensionStatusLabel_ = new QLabel(
        driverText(
            "driver.object.driver_extension.status.waiting",
            QStringLiteral("状态：等待 DriverObject 查询。")),
        driverExtensionPage_);
    driverExtensionStatusLabel_->setWordWrap(true);
    driverExtensionLayout->addWidget(driverExtensionStatusLabel_);
    driverExtensionEvidenceTable_ = new ks::ui::VisibleTableWidget(driverExtensionPage_);
    driverExtensionEvidenceTable_->setColumnCount(6);
    driverExtensionEvidenceTable_->setHorizontalHeaderLabels(driverEvidenceTableHeaders());
    configureReadOnlyTable(driverExtensionEvidenceTable_);
    driverExtensionEvidenceTable_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    driverExtensionEvidenceTable_->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Stretch);
    driverExtensionLayout->addWidget(driverExtensionEvidenceTable_, 1);
    objectDetailTabWidget_->addTab(driverExtensionPage_, QIcon(":/Icon/process_critical.svg"), QStringLiteral("DriverExtension"));

    // MajorFunction diagnostic page: displays IRP dispatch entry points and their module ownership.
    majorFunctionPage_ = new QWidget(objectDetailTabWidget_);
    QVBoxLayout* majorLayout = new QVBoxLayout(majorFunctionPage_);
    majorLayout->setContentsMargins(0, 0, 0, 0);
    majorLayout->setSpacing(4);
    majorLayout->addWidget(new QLabel(
        driverText("driver.object.major_function.title", QStringLiteral("MajorFunction 表")),
        majorFunctionPage_));

    majorFunctionTable_ = new ks::ui::VisibleTableWidget(majorFunctionPage_);
    majorFunctionTable_->setColumnCount(5);
    majorFunctionTable_->setHorizontalHeaderLabels(driverMajorFunctionTableHeaders());
    configureReadOnlyTable(majorFunctionTable_);
    majorFunctionTable_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    /*
     * Right-click to add an R-1 memory monitor.
     *
     * This page can answer 'where this dispatch currently points' but not 'who changed it'—that action
     * has already passed. Monitoring answers the next time: after installation, continue using the
     * system normally, and record the RIP, module, and address space when someone modifies it again.
     *
     * The two items correspond to two distinct issues; do not merge them.
     * - Writing to the page containing DriverObject = who is installing the hook. The MajorFunction slot and
     *   DriverObject reside on the same page; under EPT page granularity, this is inherently the same event.
     * - Execute this dispatch = who is using it.
     */
    majorFunctionTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(
        majorFunctionTable_,
        &QTableWidget::customContextMenuRequested,
        majorFunctionTable_,
        [this](const QPoint& localPosition) {
            QTableWidget* const kTable = majorFunctionTable_;
            if (kTable == nullptr)
            {
                return;
            }
            const QModelIndex kClicked = kTable->indexAt(localPosition);
            if (kClicked.isValid())
            {
                kTable->setCurrentCell(kClicked.row(), kClicked.column());
            }
            const int kRow = kTable->currentRow();
            const quint64 kObjectAddress =
                kTable->property("ks_driver_object_address").toULongLong();
            const QString kDriverName =
                kTable->property("ks_driver_object_name").toString();
            const quint64 kDispatchAddress =
                (kRow >= 0 && kTable->item(kRow, 0) != nullptr)
                    ? kTable->item(kRow, 0)->data(Qt::UserRole).toULongLong()
                    : 0ULL;
            const QString kMajorName =
                (kRow >= 0 && kTable->item(kRow, 0) != nullptr)
                    ? kTable->item(kRow, 0)->text()
                    : QString();

            QMenu menu(kTable);
            menu.setStyleSheet(ksword_theme::contextMenuStyle());
            QAction* const kWatchObject = menu.addAction(driverText(
                "driver.object.major_function.menu.hvm_watch_object",
                QStringLiteral("HVM 监视：下一次写入这个 DriverObject（含 MajorFunction 表）")));
            kWatchObject->setEnabled(kObjectAddress != 0ULL);
            QAction* const kWatchDispatch = menu.addAction(driverText(
                "driver.object.major_function.menu.hvm_watch_dispatch",
                QStringLiteral("HVM 监视：下一次执行这条 dispatch 例程")));
            kWatchDispatch->setEnabled(kDispatchAddress != 0ULL);

            QAction* const kChosen =
                menu.exec(kTable->viewport()->mapToGlobal(localPosition));
            if (kChosen == kWatchObject && kObjectAddress != 0ULL)
            {
                ks::ui::HvmWatchRequest request;
                request.virtualAddress = true;
                request.address = kObjectAddress;
                /*
                 * Request scope is left as 0 (full page) rather than fabricating a size based on DRIVER_OBJECT:
                 * The structure layout is version-dependent; hardcoding an offset will silently
                 * miscalculate the range predicate in a specific version, and an incorrect
                 * range predicate manifests as a seemingly correct but erroneous conclusion.
                 */
                request.length = 0ULL;
                request.access = KSWORD_ARK_HVM_EPT_ACCESS_WRITE;
                request.label = driverText(
                    "driver.object.major_function.menu.hvm_watch_object.label",
                    QStringLiteral("DriverObject %1"))
                    .arg(kDriverName.isEmpty()
                        ? QStringLiteral("0x%1").arg(kObjectAddress, 0, 16)
                        : kDriverName);
                ks::ui::openHvmWatch(this, request);
            }
            else if (kChosen == kWatchDispatch && kDispatchAddress != 0ULL)
            {
                ks::ui::HvmWatchRequest request;
                request.virtualAddress = true;
                request.address = kDispatchAddress;
                request.length = 1ULL;
                request.access = KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE;
                request.label = driverText(
                    "driver.object.major_function.menu.hvm_watch_dispatch.label",
                    QStringLiteral("%1 的 %2 dispatch 例程"))
                    .arg(kDriverName.isEmpty()
                        ? QStringLiteral("DriverObject")
                        : kDriverName)
                    .arg(kMajorName);
                ks::ui::openHvmWatch(this, request);
            }
        });
    majorLayout->addWidget(majorFunctionTable_, 1);
    objectDetailTabWidget_->addTab(majorFunctionPage_, QIcon(":/Icon/process_threads.svg"), QStringLiteral("MajorFunction"));

    // FastIo diagnostic page: The current protocol only backfills integrity-side evidence, so it is displayed as an evidence table.
    fastIoPage_ = new QWidget(objectDetailTabWidget_);
    QVBoxLayout* fastIoLayout = new QVBoxLayout(fastIoPage_);
    fastIoLayout->setContentsMargins(0, 0, 0, 0);
    fastIoLayout->setSpacing(4);
    fastIoStatusLabel_ = new QLabel(
        driverText(
            "driver.object.fast_io.status.waiting",
            QStringLiteral("状态：等待 Driver Integrity 证据。")),
        fastIoPage_);
    fastIoStatusLabel_->setWordWrap(true);
    fastIoLayout->addWidget(fastIoStatusLabel_);
    fastIoEvidenceTable_ = new ks::ui::VisibleTableWidget(fastIoPage_);
    fastIoEvidenceTable_->setColumnCount(6);
    fastIoEvidenceTable_->setHorizontalHeaderLabels(driverEvidenceTableHeaders());
    configureReadOnlyTable(fastIoEvidenceTable_);
    fastIoEvidenceTable_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    fastIoEvidenceTable_->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Stretch);
    fastIoLayout->addWidget(fastIoEvidenceTable_, 1);
    objectDetailTabWidget_->addTab(fastIoPage_, QIcon(":/Icon/process_pause.svg"), QStringLiteral("FastIo"));

    if (objectDetailTabWidget_ != nullptr)
    {
        objectDetailTabWidget_->setCurrentIndex(0);
    }

    rebuildDriverObjectEvidenceViews();

    tabWidget_->addTab(
        objectInfoPage_,
        QIcon(":/Icon/process_details.svg"),
        driverText("driver.tab.object_info", QStringLiteral("对象信息")));
}

void DriverDock::initializeModuleCrossViewTab()
{
    // Module Cross-View page:
    // - Project evidence for ModuleView, PsLoadedModules, DriverObject, and DriverSection solely from cached Driver Integrity results.
    // - Does not initiate additional dangerous operations or introduce new R0 protocols.
    moduleCrossViewPage_ = new QWidget(tabWidget_);
    moduleCrossViewLayout_ = new QVBoxLayout(moduleCrossViewPage_);
    moduleCrossViewLayout_->setContentsMargins(4, 4, 4, 4);
    moduleCrossViewLayout_->setSpacing(6);

    moduleCrossViewToolLayout_ = new QHBoxLayout();
    moduleCrossViewToolLayout_->setContentsMargins(0, 0, 0, 0);
    moduleCrossViewToolLayout_->setSpacing(6);

    moduleCrossViewRefreshButton_ = new QPushButton(moduleCrossViewPage_);
    moduleCrossViewRefreshButton_->setIcon(QIcon(":/Icon/process_refresh.svg"));
    moduleCrossViewRefreshButton_->setToolTip(
        driverText("driver.cross_view.refresh.tooltip", QStringLiteral("刷新 Driver Integrity 并重建模块 Cross-View")));
    ksword_theme::applyCompactIconButtonMetrics(moduleCrossViewRefreshButton_);

    moduleCrossViewStatusLabel_ = new QLabel(
        driverText("driver.cross_view.status.waiting", QStringLiteral("状态：等待刷新")),
        moduleCrossViewPage_);
    moduleCrossViewStatusLabel_->setWordWrap(true);

    moduleCrossViewToolLayout_->addWidget(moduleCrossViewRefreshButton_);
    moduleCrossViewToolLayout_->addWidget(moduleCrossViewStatusLabel_, 1);
    moduleCrossViewLayout_->addLayout(moduleCrossViewToolLayout_);

    moduleCrossViewTable_ = new ks::ui::VisibleTableWidget(moduleCrossViewPage_);
    moduleCrossViewTable_->setColumnCount(7);
    moduleCrossViewTable_->setHorizontalHeaderLabels(driverModuleCrossViewTableHeaders());
    moduleCrossViewTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    moduleCrossViewTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    moduleCrossViewTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    moduleCrossViewTable_->setAlternatingRowColors(true);
    moduleCrossViewTable_->verticalHeader()->setVisible(false);
    moduleCrossViewTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    moduleCrossViewTable_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    moduleCrossViewTable_->horizontalHeader()->setSectionResizeMode(6, QHeaderView::Stretch);
    installDriverTableCopyMenu(moduleCrossViewTable_);
    moduleCrossViewLayout_->addWidget(moduleCrossViewTable_, 1);

    tabWidget_->addTab(
        moduleCrossViewPage_,
        QIcon(":/Icon/process_list.svg"),
        driverText("driver.tab.module_cross_view", QStringLiteral("Module Cross-View")));
    rebuildModuleCrossViewTable();
}

void DriverDock::initializeConnections()
{
    // Overview page: Refresh and filter connections.
    connect(refreshServiceButton_, &QPushButton::clicked, this, [this]()
        {
            refreshDriverServiceRecords();
        });
    connect(refreshModuleButton_, &QPushButton::clicked, this, [this]()
        {
            refreshLoadedKernelModuleRecords();
        });
    connect(refreshModuleEvidenceButton_, &QPushButton::clicked, this, [this]()
        {
            refreshLoadedModuleEvidenceAsync();
        });
    connect(serviceFilterEdit_, &QLineEdit::textChanged, this, [this](const QString&)
        {
            rebuildDriverServiceTableByFilter();
        });
    connect(moduleFilterEdit_, &QLineEdit::textChanged, this, [this](const QString&)
        {
            rebuildLoadedModuleTable();
        });

    // Kernel module page: Refresh, filter, and unify detail layout connections.
    connect(serviceTable_, &QTableWidget::itemSelectionChanged, this, [this]()
        {
            syncOperateFormBySelectedService();
        });
    connect(serviceTable_, &QTableWidget::cellDoubleClicked, this, [this](const int, const int)
        {
            syncOperateFormBySelectedService();
            if (tabWidget_ != nullptr && operatePage_ != nullptr)
            {
                tabWidget_->setCurrentWidget(operatePage_);
            }
        });
    connect(serviceTable_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& localPosition)
        {
            showServiceTableContextMenu(localPosition);
        });
    connect(moduleTable_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& localPosition)
        {
            showModuleTableContextMenu(localPosition);
        });
    connect(moduleTable_, &QTableWidget::itemSelectionChanged, this, [this]()
        {
            showSelectedModuleEvidenceDetail();
        });

    // Operation page: Browse path, register update, mount/unmount, delete, and status query.
    connect(browsePathButton_, &QPushButton::clicked, this, [this]()
        {
            const QString kFilePath = QFileDialog::getOpenFileName(
                this,
                driverText("driver.dialog.select_file.title", QStringLiteral("选择驱动文件")),
                QString(),
                QStringLiteral("Driver Files (*.sys);;All Files (*.*)"));
            if (!kFilePath.isEmpty() && binaryPathEdit_ != nullptr)
            {
                binaryPathEdit_->setText(kFilePath);
            }
        });
    connect(registerOrUpdateButton_, &QPushButton::clicked, this, [this]()
        {
            registerOrUpdateDriverService();
        });
    connect(loadDriverButton_, &QPushButton::clicked, this, [this]()
        {
            loadSelectedDriverService();
        });
    connect(unloadDriverButton_, &QPushButton::clicked, this, [this]()
        {
            unloadSelectedDriverService();
        });
    connect(deleteServiceButton_, &QPushButton::clicked, this, [this]()
        {
            deleteSelectedDriverService();
        });
    connect(refreshStateButton_, &QPushButton::clicked, this, [this]()
        {
            refreshSelectedServiceStateToForm();
        });

    // Debug output: Start, stop, clear, copy.
    connect(startCaptureButton_, &QPushButton::clicked, this, [this]()
        {
            startDebugOutputCapture();
        });
    connect(stopCaptureButton_, &QPushButton::clicked, this, [this]()
        {
            stopDebugOutputCapture();
        });
    connect(clearDebugOutputButton_, &QPushButton::clicked, this, [this]()
        {
            clearDebugOutputLines();
        });
    connect(copyDebugOutputButton_, &QPushButton::clicked, this, [this]()
        {
            if (debugOutputEdit_ == nullptr || QGuiApplication::clipboard() == nullptr)
            {
                return;
            }
            QGuiApplication::clipboard()->setText(debugOutputEdit_->toPlainText());
        });

    // Object Info page: Fill DriverObject name from service name and perform R0 query.
    connect(fillObjectDriverNameButton_, &QPushButton::clicked, this, [this]()
        {
            fillObjectDriverNameFromSelection();
        });
    connect(queryObjectInfoButton_, &QPushButton::clicked, this, [this]()
        {
            querySelectedDriverObjectInfo();
        });
    connect(objectDriverNameEdit_, &QLineEdit::returnPressed, this, [this]()
        {
            querySelectedDriverObjectInfo();
        });
    connect(objectEvidenceRefreshButton_, &QPushButton::clicked, this, [this]()
        {
            rebuildDriverObjectEvidenceViews();
        });
    connect(objectDetailTabWidget_, &QTabWidget::currentChanged, this, [this](int)
        {
            rebuildDriverObjectEvidenceViews();
        });

    // Driver Integrity page: all actions are read-only queries or local filtering; no repair or write buttons are provided.
    connect(integrityRefreshButton_, &QPushButton::clicked, this, [this]()
        {
            refreshDriverIntegrityAsync(false);
        });
    connect(integrityCpuOnlyButton_, &QPushButton::clicked, this, [this]()
        {
            refreshDriverIntegrityAsync(true);
        });
    connect(integrityRiskOnlyCheck_, &QCheckBox::toggled, this, [this]()
        {
            rebuildDriverIntegrityTable();
            showSelectedDriverIntegrityDetail();
        });
    connect(integrityFillFromSelectionButton_, &QPushButton::clicked, this, [this]()
        {
            fillObjectDriverNameFromSelection();
            if (integrityDriverNameEdit_ != nullptr && objectDriverNameEdit_ != nullptr)
            {
                integrityDriverNameEdit_->setText(objectDriverNameEdit_->text());
            }
        });
    connect(integrityTable_, &QTableWidget::currentCellChanged, this, [this](int, int, int, int)
        {
            showSelectedDriverIntegrityDetail();
        });

    // Evidence projection page: read-only refresh and in-table selection; no repair actions are triggered.
    connect(moduleCrossViewRefreshButton_, &QPushButton::clicked, this, [this]()
        {
            refreshDriverIntegrityAsync(false);
        });
    connect(moduleCrossViewTable_, &QTableWidget::currentCellChanged, this, [this](int, int, int, int)
        {
            if (moduleCrossViewStatusLabel_ != nullptr && moduleCrossViewTable_ != nullptr)
            {
                moduleCrossViewStatusLabel_->setText(
                    driverText("driver.cross_view.status.projected", QStringLiteral("状态：当前显示 %1 条投影证据。"))
                    .arg(moduleCrossViewTable_->rowCount()));
            }
        });

    // The unloaded driver page itself is uniquely constructed and linked by DriverDock.Unloaded.cpp.
    // Here, we only attach the remote's existing PiDDB precise management actions, without repeating queries, filtering, details retrieval, or connection copying.
    if (unloadedPiddbPage_ != nullptr &&
        unloadedPiddbSourceLayout_ != nullptr &&
        unloadedPiddbTable_ != nullptr &&
        unloadedPiddbRefreshButton_ != nullptr &&
        unloadedPiddbMmSourceRadio_ != nullptr &&
        unloadedPiddbPiDdbSourceRadio_ != nullptr &&
        unloadedPiddbCiSourceRadio_ != nullptr)
    {
        unloadedPiddbDeleteButton_ = new QPushButton(
            driverText(
                "driver.unloaded.delete_exact",
                QStringLiteral("删除选中 PiDDB 表项")),
            unloadedPiddbPage_);
        unloadedPiddbDeleteButton_->setStyleSheet(
            ksword_theme::themedButtonStyle());
        unloadedPiddbDeleteButton_->setEnabled(false);
        unloadedPiddbSourceLayout_->insertWidget(
            unloadedPiddbSourceLayout_->indexOf(
                unloadedPiddbRefreshButton_),
            unloadedPiddbDeleteButton_);

        connect(
            unloadedPiddbDeleteButton_,
            &QPushButton::clicked,
            this,
            &DriverDock::deleteSelectedPiDdbEntry);
        connect(
            unloadedPiddbTable_,
            &QTableWidget::currentCellChanged,
            this,
            [this](int, int, int, int) {
                if (unloadedPiddbDeleteButton_ != nullptr)
                {
                    unloadedPiddbDeleteButton_->setEnabled(
                        selectedPiDdbEntryIdentity(nullptr));
                }
            });
        connect(
            unloadedPiddbRefreshButton_,
            &QPushButton::clicked,
            this,
            [this]() {
                if (unloadedPiddbDeleteButton_ != nullptr)
                {
                    unloadedPiddbDeleteButton_->setEnabled(false);
                }
            });
        const auto kDisableDeleteOnSourceChange =
            [this](const bool) {
                if (unloadedPiddbDeleteButton_ != nullptr)
                {
                    unloadedPiddbDeleteButton_->setEnabled(false);
                }
            };
        connect(
            unloadedPiddbMmSourceRadio_,
            &QRadioButton::toggled,
            this,
            kDisableDeleteOnSourceChange);
        connect(
            unloadedPiddbPiDdbSourceRadio_,
            &QRadioButton::toggled,
            this,
            kDisableDeleteOnSourceChange);
        connect(
            unloadedPiddbCiSourceRadio_,
            &QRadioButton::toggled,
            this,
            kDisableDeleteOnSourceChange);
    }
}
