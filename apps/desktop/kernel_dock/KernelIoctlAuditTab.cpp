#include "KernelIoctlAuditTab.h"

#include "KernelDeviceDriverObjectsWorker.h"
#include "KernelDock.h"
#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../ui/TableInteractionSupport.h"
#include "../ui/VisibleTableWidget.h"
#include "../Theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMetaObject>
#include <QModelIndex>
#include <QPointer>
#include <QPushButton>
#include <QSet>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTabWidget>
#include <QVBoxLayout>

#include <algorithm>
#include <sstream>
#include <thread>
#include <utility>

using ksword::kernel_dock_internal::kernelText;

namespace
{
    QString buttonStyle()
    {
        return ksword_theme::themedButtonStyle();
    }

    QString headerStyle()
    {
        return QStringLiteral("QHeaderView::section{color:%1;background:transparent;border:1px solid %2;font-weight:600;}")
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::borderHex());
    }

    QTableWidgetItem* readOnlyItem(const QString& text)
    {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }
}

KernelIoctlAuditTab::KernelIoctlAuditTab(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
}

void KernelIoctlAuditTab::requestInitialRefresh()
{
    if (initialRefreshRequested_)
    {
        return;
    }

    initialRefreshRequested_ = true;
    refreshAsync();
}

void KernelIoctlAuditTab::initializeUi()
{
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(6, 6, 6, 6);
    rootLayout->setSpacing(5);

    auto* toolbar = new QHBoxLayout();
    refreshButton_ = new QPushButton(kernelText("kernel.ioctl_audit.refresh", QStringLiteral("刷新派遣表")), this);
    refreshButton_->setStyleSheet(buttonStyle());
    filterEdit_ = new QLineEdit(this);
    filterEdit_->setClearButtonEnabled(true);
    filterEdit_->setPlaceholderText(kernelText(
        "kernel.ioctl_audit.filter.placeholder",
        QStringLiteral("筛选驱动、设备、MajorFunction 或地址...")));
    filterEdit_->setMinimumWidth(280);
    clearFilterButton_ = new QPushButton(
        kernelText("kernel.ioctl_audit.filter.clear", QStringLiteral("清除筛选")),
        this);
    clearFilterButton_->setStyleSheet(buttonStyle());
    statusLabel_ = new QLabel(kernelText("kernel.ioctl_audit.loading", QStringLiteral("正在加载全局 DriverObject 与 KswordARK IOCTL registry...")), this);
    statusLabel_->setStyleSheet(QStringLiteral("color:%1;font-weight:600;").arg(ksword_theme::textSecondaryHex()));
    toolbar->addWidget(refreshButton_);
    toolbar->addWidget(filterEdit_);
    toolbar->addWidget(clearFilterButton_);
    toolbar->addWidget(statusLabel_, 1);
    rootLayout->addLayout(toolbar);

    innerTabs_ = new QTabWidget(this);
    driverPage_ = new QWidget(innerTabs_);
    devicePage_ = new QWidget(innerTabs_);
    dispatchPage_ = new QWidget(innerTabs_);
    registryPage_ = new QWidget(innerTabs_);
    driverTable_ = new ks::ui::VisibleTableWidget(driverPage_);
    deviceTable_ = new ks::ui::VisibleTableWidget(devicePage_);
    dispatchTable_ = new ks::ui::VisibleTableWidget(dispatchPage_);
    registryTable_ = new ks::ui::VisibleTableWidget(registryPage_);
    for (QTableWidget* table : {driverTable_, deviceTable_, dispatchTable_, registryTable_})
    {
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setSelectionMode(QAbstractItemView::ExtendedSelection);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table->setAlternatingRowColors(true);
        table->setContextMenuPolicy(Qt::CustomContextMenu);
        table->setStyleSheet(QStringLiteral("QTableWidget{background:transparent;color:%1;}" ).arg(ksword_theme::textPrimaryHex()));
        table->horizontalHeader()->setStyleSheet(headerStyle());
        table->horizontalHeader()->setStretchLastSection(true);
        table->verticalHeader()->setVisible(false);
    }
    driverTable_->setColumnCount(9);
    driverTable_->setHorizontalHeaderLabels({
        kernelText("kernel.ioctl_audit.header.driver", QStringLiteral("DriverObject")),
        kernelText("kernel.ioctl_audit.header.object_address", QStringLiteral("对象地址")),
        QStringLiteral("DriverStart"),
        kernelText("kernel.ioctl_audit.header.image_size", QStringLiteral("镜像大小")),
        kernelText("kernel.ioctl_audit.header.flags", QStringLiteral("Flags")),
        kernelText("kernel.ioctl_audit.header.devices", QStringLiteral("设备数")),
        kernelText("kernel.ioctl_audit.header.major_count", QStringLiteral("MajorFunction 数")),
        kernelText("kernel.ioctl_audit.header.query_status", QStringLiteral("查询状态")),
        QStringLiteral("NTSTATUS")});
    deviceTable_->setColumnCount(13);
    deviceTable_->setHorizontalHeaderLabels({
        kernelText("kernel.ioctl_audit.header.driver", QStringLiteral("DriverObject")),
        kernelText("kernel.ioctl_audit.header.relation", QStringLiteral("关系")),
        QStringLiteral("DeviceObject"),
        kernelText("kernel.ioctl_audit.header.device_name", QStringLiteral("设备名称")),
        kernelText("kernel.ioctl_audit.header.device_type", QStringLiteral("设备类型")),
        kernelText("kernel.ioctl_audit.header.flags", QStringLiteral("Flags")),
        QStringLiteral("Characteristics"),
        QStringLiteral("StackSize"),
        QStringLiteral("RootDevice"),
        QStringLiteral("NextDevice"),
        QStringLiteral("AttachedDevice"),
        kernelText("kernel.ioctl_audit.header.owner_driver", QStringLiteral("归属 DriverObject")),
        QStringLiteral("NameStatus")});
    dispatchTable_->setColumnCount(9);
    dispatchTable_->setHorizontalHeaderLabels({
        kernelText("kernel.ioctl_audit.header.driver", QStringLiteral("DriverObject")),
        kernelText("kernel.ioctl_audit.header.object_address", QStringLiteral("对象地址")),
        kernelText("kernel.ioctl_audit.header.major", QStringLiteral("MajorFunction")),
        kernelText("kernel.ioctl_audit.header.index", QStringLiteral("编号")),
        kernelText("kernel.ioctl_audit.header.dispatch", QStringLiteral("派遣地址")),
        kernelText("kernel.ioctl_audit.header.module_base", QStringLiteral("模块基址")),
        kernelText("kernel.ioctl_audit.header.module", QStringLiteral("归属模块")),
        kernelText("kernel.ioctl_audit.header.flags", QStringLiteral("Flags")),
        kernelText("kernel.ioctl_audit.header.status", QStringLiteral("状态"))});
    registryTable_->setColumnCount(7);
    registryTable_->setHorizontalHeaderLabels({
        kernelText("kernel.ioctl_audit.header.code", QStringLiteral("控制码")),
        kernelText("kernel.ioctl_audit.header.function", QStringLiteral("Function")),
        kernelText("kernel.ioctl_audit.header.method_access", QStringLiteral("Method/Access")),
        kernelText("kernel.ioctl_audit.header.capability", QStringLiteral("能力门槛")),
        kernelText("kernel.ioctl_audit.header.handler", QStringLiteral("Handler")),
        kernelText("kernel.ioctl_audit.header.name", QStringLiteral("名称")),
        kernelText("kernel.ioctl_audit.header.flags", QStringLiteral("Flags"))});

    auto* driverLayout = new QVBoxLayout(driverPage_);
    driverLayout->setContentsMargins(2, 2, 2, 2);
    driverLayout->addWidget(driverTable_);
    auto* deviceLayout = new QVBoxLayout(devicePage_);
    deviceLayout->setContentsMargins(2, 2, 2, 2);
    deviceLayout->addWidget(deviceTable_);
    auto* dispatchLayout = new QVBoxLayout(dispatchPage_);
    dispatchLayout->setContentsMargins(2, 2, 2, 2);
    dispatchLayout->addWidget(dispatchTable_);
    auto* registryLayout = new QVBoxLayout(registryPage_);
    registryLayout->setContentsMargins(2, 2, 2, 2);
    registryLayout->addWidget(registryTable_);
    innerTabs_->addTab(driverPage_, kernelText("kernel.ioctl_audit.tab.drivers", QStringLiteral("驱动概览")));
    innerTabs_->addTab(devicePage_, kernelText("kernel.ioctl_audit.tab.devices", QStringLiteral("设备对象")));
    innerTabs_->addTab(dispatchPage_, kernelText("kernel.ioctl_audit.tab.dispatch", QStringLiteral("MajorFunction")));
    innerTabs_->addTab(registryPage_, kernelText("kernel.ioctl_audit.tab.registry", QStringLiteral("KswordARK IOCTL 注册表")));
    rootLayout->addWidget(innerTabs_, 1);

    connect(refreshButton_, &QPushButton::clicked, this, [this]() { refreshAsync(); });
    connect(filterEdit_, &QLineEdit::textChanged, this, [this]() { applyFilter(); });
    connect(clearFilterButton_, &QPushButton::clicked, filterEdit_, &QLineEdit::clear);
    connect(driverTable_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& position) {
        showCopyMenu(driverTable_, position);
    });
    connect(deviceTable_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& position) {
        showCopyMenu(deviceTable_, position);
    });
    connect(dispatchTable_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& position) {
        showCopyMenu(dispatchTable_, position);
    });
    connect(registryTable_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& position) {
        showCopyMenu(registryTable_, position);
    });
}

void KernelIoctlAuditTab::refreshAsync()
{
    if (refreshRunning_)
    {
        return;
    }
    refreshRunning_ = true;
    refreshButton_->setEnabled(false);
    statusLabel_->setText(kernelText("kernel.ioctl_audit.refreshing", QStringLiteral("正在枚举 DriverObject 派遣入口并读取 IOCTL registry...")));
    QPointer<KernelIoctlAuditTab> safeThis(this);
    std::thread([safeThis]() {
        Snapshot snapshot;
        std::vector<KernelDeviceDriverObjectEntry> objectRows;
        QString workerError;
        const bool kWorkerOk = runKernelDeviceDriverObjectsSnapshotTask(objectRows, workerError);
        if (!kWorkerOk)
        {
            snapshot.errorText = workerError;
        }

        ksword::ark::DriverClient client;
        if (kWorkerOk)
        {
            QSet<QString> seenDriverNames;
            for (const KernelDeviceDriverObjectEntry& objectRow : objectRows)
            {
                if (objectRow.isScopeEntry || objectRow.objectTypeText.compare(QStringLiteral("Driver"), Qt::CaseInsensitive) != 0)
                {
                    continue;
                }
                const QString kDriverPath = objectRow.fullPathText.trimmed();
                const QString kNormalizedDriverPath = kDriverPath.toCaseFolded();
                if (kDriverPath.isEmpty() || seenDriverNames.contains(kNormalizedDriverPath))
                {
                    continue;
                }
                seenDriverNames.insert(kNormalizedDriverPath);

                DriverRow driverRow;
                driverRow.driverName = kDriverPath;
                const std::wstring kDriverName = kDriverPath.toStdWString();
                const ksword::ark::DriverObjectQueryResult kQuery = client.queryDriverObject(kDriverName);
                if (!kQuery.io.ok)
                {
                    ++snapshot.queryFailureCount;
                    driverRow.lastStatus = static_cast<std::int32_t>(kQuery.lastStatus);
                    driverRow.status = kQuery.io.message.empty()
                        ? QStringLiteral("DriverObject 查询失败")
                        : QString::fromStdString(kQuery.io.message);
                    snapshot.driverRows.push_back(std::move(driverRow));
                    continue;
                }

                driverRow.driverObjectAddress = kQuery.driverObjectAddress;
                driverRow.driverStart = kQuery.driverStart;
                driverRow.driverSize = kQuery.driverSize;
                driverRow.driverFlags = kQuery.driverFlags;
                driverRow.majorFunctionCount = kQuery.majorFunctionCount;
                driverRow.returnedDeviceCount = kQuery.returnedDeviceCount;
                driverRow.totalDeviceCount = kQuery.totalDeviceCount;
                driverRow.queryStatus = kQuery.queryStatus;
                driverRow.lastStatus = static_cast<std::int32_t>(kQuery.lastStatus);
                if (kQuery.queryStatus == KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_PARTIAL)
                {
                    ++snapshot.partialDriverCount;
                }
                snapshot.driverRows.push_back(std::move(driverRow));

                for (const ksword::ark::DriverDeviceEntry& device : kQuery.devices)
                {
                    DeviceRow row;
                    row.driverName = kDriverPath;
                    row.deviceName = QString::fromStdWString(device.deviceName);
                    row.relationDepth = device.relationDepth;
                    row.deviceType = device.deviceType;
                    row.flags = device.flags;
                    row.characteristics = device.characteristics;
                    row.stackSize = device.stackSize;
                    row.nameStatus = static_cast<std::int32_t>(device.nameStatus);
                    row.rootDeviceObjectAddress = device.rootDeviceObjectAddress;
                    row.deviceObjectAddress = device.deviceObjectAddress;
                    row.nextDeviceObjectAddress = device.nextDeviceObjectAddress;
                    row.attachedDeviceObjectAddress = device.attachedDeviceObjectAddress;
                    row.ownerDriverObjectAddress = device.driverObjectAddress;
                    snapshot.deviceRows.push_back(std::move(row));
                }
                for (const ksword::ark::DriverMajorFunctionEntry& major : kQuery.majorFunctions)
                {
                    DispatchRow row;
                    row.driverName = kDriverPath;
                    row.driverObjectAddress = kQuery.driverObjectAddress;
                    row.majorFunction = major.majorFunction;
                    row.dispatchAddress = major.dispatchAddress;
                    row.moduleBase = major.moduleBase;
                    row.moduleName = QString::fromStdWString(major.moduleName);
                    row.flags = major.flags;
                    snapshot.dispatchRows.push_back(std::move(row));
                }
            }
        }

        const ksword::ark::IoctlRegistryQueryResult kRegistry = client.queryIoctlRegistry();
        snapshot.registryOk = kRegistry.io.ok;
        snapshot.registryTotal = kRegistry.totalCount;
        snapshot.registryDuplicate = kRegistry.duplicateCount;
        snapshot.registryRows = kRegistry.entries;
        if (!kRegistry.io.ok && snapshot.errorText.isEmpty())
        {
            snapshot.errorText = kRegistry.io.message.empty()
                ? QStringLiteral("KswordARK IOCTL registry 查询失败")
                : QString::fromStdString(kRegistry.io.message);
        }

        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(safeThis, [safeThis, snapshot = std::move(snapshot)]() mutable {
            if (safeThis != nullptr)
            {
                safeThis->applySnapshot(std::move(snapshot));
            }
        }, Qt::QueuedConnection);
    }).detach();
}

void KernelIoctlAuditTab::applySnapshot(Snapshot snapshot)
{
    const QPointer<KernelIoctlAuditTab> kSafeThis(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("kernel-ioctl-audit-snapshot"),
        { driverTable_, deviceTable_, dispatchTable_, registryTable_ },
        [kSafeThis, snapshot]() mutable
        {
            if (!kSafeThis.isNull())
            {
                kSafeThis->applySnapshot(std::move(snapshot));
            }
        }))
    {
        return;
    }

    refreshRunning_ = false;
    refreshButton_->setEnabled(true);
    driverRows_ = std::move(snapshot.driverRows);
    deviceRows_ = std::move(snapshot.deviceRows);
    dispatchRows_ = std::move(snapshot.dispatchRows);
    registryRows_ = std::move(snapshot.registryRows);
    queryFailureCount_ = snapshot.queryFailureCount;
    partialDriverCount_ = snapshot.partialDriverCount;
    registryTotal_ = snapshot.registryTotal;
    registryDuplicate_ = snapshot.registryDuplicate;
    registryOk_ = snapshot.registryOk;
    errorText_ = std::move(snapshot.errorText);
    populateTables();
}

QString KernelIoctlAuditTab::hex64(const std::uint64_t value)
{
    return QStringLiteral("0x%1").arg(value, 16, 16, QLatin1Char('0'));
}

QString KernelIoctlAuditTab::hex32(const std::uint32_t value)
{
    return QStringLiteral("0x%1").arg(value, 8, 16, QLatin1Char('0'));
}

QString KernelIoctlAuditTab::majorFunctionName(const std::uint32_t value)
{
    switch (value)
    {
    case 0x00: return QStringLiteral("IRP_MJ_CREATE");
    case 0x01: return QStringLiteral("IRP_MJ_CREATE_NAMED_PIPE");
    case 0x02: return QStringLiteral("IRP_MJ_CLOSE");
    case 0x03: return QStringLiteral("IRP_MJ_READ");
    case 0x04: return QStringLiteral("IRP_MJ_WRITE");
    case 0x05: return QStringLiteral("IRP_MJ_QUERY_INFORMATION");
    case 0x06: return QStringLiteral("IRP_MJ_SET_INFORMATION");
    case 0x07: return QStringLiteral("IRP_MJ_QUERY_EA");
    case 0x08: return QStringLiteral("IRP_MJ_SET_EA");
    case 0x09: return QStringLiteral("IRP_MJ_FLUSH_BUFFERS");
    case 0x0A: return QStringLiteral("IRP_MJ_QUERY_VOLUME_INFORMATION");
    case 0x0B: return QStringLiteral("IRP_MJ_SET_VOLUME_INFORMATION");
    case 0x0C: return QStringLiteral("IRP_MJ_DIRECTORY_CONTROL");
    case 0x0D: return QStringLiteral("IRP_MJ_FILE_SYSTEM_CONTROL");
    case 0x0E: return QStringLiteral("IRP_MJ_DEVICE_CONTROL");
    case 0x0F: return QStringLiteral("IRP_MJ_INTERNAL_DEVICE_CONTROL");
    case 0x10: return QStringLiteral("IRP_MJ_SHUTDOWN");
    case 0x11: return QStringLiteral("IRP_MJ_LOCK_CONTROL");
    case 0x12: return QStringLiteral("IRP_MJ_CLEANUP");
    case 0x13: return QStringLiteral("IRP_MJ_CREATE_MAILSLOT");
    case 0x14: return QStringLiteral("IRP_MJ_QUERY_SECURITY");
    case 0x15: return QStringLiteral("IRP_MJ_SET_SECURITY");
    case 0x16: return QStringLiteral("IRP_MJ_POWER");
    case 0x17: return QStringLiteral("IRP_MJ_SYSTEM_CONTROL");
    case 0x18: return QStringLiteral("IRP_MJ_DEVICE_CHANGE");
    case 0x19: return QStringLiteral("IRP_MJ_QUERY_QUOTA");
    case 0x1A: return QStringLiteral("IRP_MJ_SET_QUOTA");
    case 0x1B: return QStringLiteral("IRP_MJ_PNP");
    default: return QStringLiteral("IRP_MJ_%1").arg(value);
    }
}

void KernelIoctlAuditTab::populateTables()
{
    driverTable_->setRowCount(0);
    for (const DriverRow& row : driverRows_)
    {
        const int kTableRow = driverTable_->rowCount();
        driverTable_->insertRow(kTableRow);
        QString statusText;
        if (!row.status.isEmpty())
        {
            statusText = kernelText(
                "kernel.ioctl_audit.query.failed",
                QStringLiteral("查询失败：%1")).arg(row.status);
        }
        else if (row.queryStatus == KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_PARTIAL)
        {
            statusText = kernelText("kernel.ioctl_audit.query.partial", QStringLiteral("部分结果"));
        }
        else if (row.queryStatus == KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_OK)
        {
            statusText = kernelText("kernel.ioctl_audit.query.ok", QStringLiteral("正常"));
        }
        else
        {
            statusText = QStringLiteral("QueryStatus=%1").arg(row.queryStatus);
        }
        driverTable_->setItem(kTableRow, 0, readOnlyItem(row.driverName));
        driverTable_->setItem(kTableRow, 1, readOnlyItem(hex64(row.driverObjectAddress)));
        driverTable_->setItem(kTableRow, 2, readOnlyItem(hex64(row.driverStart)));
        driverTable_->setItem(kTableRow, 3, readOnlyItem(hex32(row.driverSize)));
        driverTable_->setItem(kTableRow, 4, readOnlyItem(hex32(row.driverFlags)));
        driverTable_->setItem(kTableRow, 5, readOnlyItem(
            QStringLiteral("%1/%2").arg(row.returnedDeviceCount).arg(row.totalDeviceCount)));
        driverTable_->setItem(kTableRow, 6, readOnlyItem(QString::number(row.majorFunctionCount)));
        driverTable_->setItem(kTableRow, 7, readOnlyItem(statusText));
        driverTable_->setItem(kTableRow, 8, readOnlyItem(hex32(static_cast<std::uint32_t>(row.lastStatus))));
    }

    deviceTable_->setRowCount(0);
    for (const DeviceRow& row : deviceRows_)
    {
        const int kTableRow = deviceTable_->rowCount();
        deviceTable_->insertRow(kTableRow);
        const QString kRelation = row.relationDepth == 0
            ? kernelText("kernel.ioctl_audit.device.root", QStringLiteral("根设备"))
            : kernelText("kernel.ioctl_audit.device.attached", QStringLiteral("附加 +%1")).arg(row.relationDepth);
        deviceTable_->setItem(kTableRow, 0, readOnlyItem(row.driverName));
        deviceTable_->setItem(kTableRow, 1, readOnlyItem(kRelation));
        deviceTable_->setItem(kTableRow, 2, readOnlyItem(hex64(row.deviceObjectAddress)));
        deviceTable_->setItem(kTableRow, 3, readOnlyItem(row.deviceName.isEmpty()
            ? kernelText("kernel.ioctl_audit.device.unnamed", QStringLiteral("（未命名）"))
            : row.deviceName));
        deviceTable_->setItem(kTableRow, 4, readOnlyItem(hex32(row.deviceType)));
        deviceTable_->setItem(kTableRow, 5, readOnlyItem(hex32(row.flags)));
        deviceTable_->setItem(kTableRow, 6, readOnlyItem(hex32(row.characteristics)));
        deviceTable_->setItem(kTableRow, 7, readOnlyItem(QString::number(row.stackSize)));
        deviceTable_->setItem(kTableRow, 8, readOnlyItem(hex64(row.rootDeviceObjectAddress)));
        deviceTable_->setItem(kTableRow, 9, readOnlyItem(hex64(row.nextDeviceObjectAddress)));
        deviceTable_->setItem(kTableRow, 10, readOnlyItem(hex64(row.attachedDeviceObjectAddress)));
        deviceTable_->setItem(kTableRow, 11, readOnlyItem(hex64(row.ownerDriverObjectAddress)));
        deviceTable_->setItem(kTableRow, 12, readOnlyItem(hex32(static_cast<std::uint32_t>(row.nameStatus))));
    }

    dispatchTable_->setRowCount(0);
    for (const DispatchRow& row : dispatchRows_)
    {
        const int kTableRow = dispatchTable_->rowCount();
        dispatchTable_->insertRow(kTableRow);
        const QString kDispatchStatus = (row.flags & 0x00000002U) != 0U
            ? kernelText("kernel.ioctl_audit.dispatch.own_image", QStringLiteral("本驱动镜像"))
            : ((row.flags & 0x00000001U) != 0U
                ? kernelText("kernel.ioctl_audit.dispatch.external_module", QStringLiteral("外部模块"))
                : kernelText("kernel.ioctl_audit.dispatch.unresolved", QStringLiteral("模块未解析")));
        dispatchTable_->setItem(kTableRow, 0, readOnlyItem(row.driverName));
        dispatchTable_->setItem(kTableRow, 1, readOnlyItem(hex64(row.driverObjectAddress)));
        dispatchTable_->setItem(kTableRow, 2, readOnlyItem(majorFunctionName(row.majorFunction)));
        dispatchTable_->setItem(kTableRow, 3, readOnlyItem(QString::number(row.majorFunction)));
        dispatchTable_->setItem(kTableRow, 4, readOnlyItem(hex64(row.dispatchAddress)));
        dispatchTable_->setItem(kTableRow, 5, readOnlyItem(hex64(row.moduleBase)));
        dispatchTable_->setItem(kTableRow, 6, readOnlyItem(row.moduleName.isEmpty() ? QStringLiteral("-") : row.moduleName));
        dispatchTable_->setItem(kTableRow, 7, readOnlyItem(hex32(row.flags)));
        dispatchTable_->setItem(kTableRow, 8, readOnlyItem(kDispatchStatus));
    }

    registryTable_->setRowCount(0);
    for (const ksword::ark::IoctlRegistryEntry& row : registryRows_)
    {
        const int kTableRow = registryTable_->rowCount();
        registryTable_->insertRow(kTableRow);
        registryTable_->setItem(kTableRow, 0, readOnlyItem(hex32(row.ioControlCode)));
        registryTable_->setItem(kTableRow, 1, readOnlyItem(QString::number(row.functionNumber)));
        registryTable_->setItem(kTableRow, 2, readOnlyItem(QStringLiteral("%1 / %2").arg(row.method).arg(row.access)));
        registryTable_->setItem(kTableRow, 3, readOnlyItem(hex64(row.requiredCapability)));
        registryTable_->setItem(kTableRow, 4, readOnlyItem(hex64(row.handlerAddress)));
        registryTable_->setItem(kTableRow, 5, readOnlyItem(QString::fromStdString(row.name)));
        registryTable_->setItem(kTableRow, 6, readOnlyItem(hex32(row.flags)));
    }
    driverTable_->resizeColumnsToContents();
    deviceTable_->resizeColumnsToContents();
    dispatchTable_->resizeColumnsToContents();
    registryTable_->resizeColumnsToContents();
    applyFilter();
    const QString kSummary = kernelText(
        "kernel.ioctl_audit.summary.detailed",
        QStringLiteral("驱动 %1 个（失败 %2，部分 %3），设备 %4 行，MajorFunction %5 行，KswordARK registry %6/%7 行，重复控制码 %8。"))
        .arg(static_cast<qulonglong>(driverRows_.size()))
        .arg(queryFailureCount_)
        .arg(partialDriverCount_)
        .arg(static_cast<qulonglong>(deviceRows_.size()))
        .arg(static_cast<qulonglong>(dispatchRows_.size()))
        .arg(static_cast<qulonglong>(registryRows_.size()))
        .arg(registryTotal_)
        .arg(registryDuplicate_);
    statusLabel_->setText(errorText_.isEmpty() ? kSummary : kSummary + QStringLiteral(" ") + errorText_);
}

void KernelIoctlAuditTab::applyFilter()
{
    const QString kFilterText = filterEdit_ == nullptr ? QString() : filterEdit_->text().trimmed();
    const bool kHasFilter = !kFilterText.isEmpty();
    for (QTableWidget* table : {driverTable_, deviceTable_, dispatchTable_, registryTable_})
    {
        if (table == nullptr)
        {
            continue;
        }
        for (int row = 0; row < table->rowCount(); ++row)
        {
            bool matched = !kHasFilter;
            for (int column = 0; !matched && column < table->columnCount(); ++column)
            {
                const QTableWidgetItem* item = table->item(row, column);
                matched = item != nullptr && item->text().contains(kFilterText, Qt::CaseInsensitive);
            }
            table->setRowHidden(row, !matched);
        }
    }
    if (clearFilterButton_ != nullptr)
    {
        clearFilterButton_->setEnabled(kHasFilter);
    }
}

QString KernelIoctlAuditTab::tableRowText(QTableWidget* table, const int row, const bool includeHeader)
{
    if (table == nullptr || row < 0 || row >= table->rowCount())
    {
        return {};
    }
    QStringList values;
    if (includeHeader)
    {
        for (int column = 0; column < table->columnCount(); ++column)
        {
            values << table->horizontalHeaderItem(column)->text();
        }
    }
    QStringList rowValues;
    for (int column = 0; column < table->columnCount(); ++column)
    {
        rowValues << (table->item(row, column) == nullptr ? QString() : table->item(row, column)->text());
    }
    values << rowValues.join(QLatin1Char('\t'));
    return values.join(QLatin1Char('\n'));
}

void KernelIoctlAuditTab::showCopyMenu(QTableWidget* table, const QPoint& position)
{
    if (table == nullptr)
    {
        return;
    }
    const QModelIndex kIndex = table->indexAt(position);
    const int kRow = kIndex.isValid() ? kIndex.row() : -1;
    QMenu menu(this);
    QAction* copyRow = menu.addAction(kernelText("kernel.ioctl_audit.copy_row", QStringLiteral("复制当前行")));
    QAction* copyAll = menu.addAction(kernelText("kernel.ioctl_audit.copy_all", QStringLiteral("复制全部行")));
    copyRow->setEnabled(kRow >= 0);
    copyAll->setEnabled(table->rowCount() > 0);
    QAction* selected = menu.exec(table->viewport()->mapToGlobal(position));
    if (selected == copyRow)
    {
        QApplication::clipboard()->setText(tableRowText(table, kRow, true));
    }
    else if (selected == copyAll)
    {
        QStringList lines;
        for (int rowIndex = 0; rowIndex < table->rowCount(); ++rowIndex)
        {
            lines << tableRowText(table, rowIndex, rowIndex == 0);
        }
        QApplication::clipboard()->setText(lines.join(QLatin1Char('\n')));
    }
}
