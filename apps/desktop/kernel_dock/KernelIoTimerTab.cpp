#include "KernelIoTimerTab.h"

#include "KernelDeviceDriverObjectsWorker.h"
#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../internationalization/LanguageManager.h"
#include "../ui/CodeEditorWidget.h"
#include "../ui/DetailLayoutRegistry.h"
#include "../Theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QCoreApplication>
#include <QEvent>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QSplitter>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QThreadPool>
#include <QVBoxLayout>

#include <algorithm>
#include <memory>
#include <set>
#include <utility>

namespace
{
    // ioTimerText: All visible text uses stable context keys; Chinese falls back to source code.
    QString ioTimerText(const char* const key, const QString& fallbackText)
    {
        return ks::i18n::contextText(QString::fromLatin1(key), fallbackText);
    }

    // makeReadOnlyItem: Uniformly creates non-editable table items while preserving full tooltips.
    QTableWidgetItem* makeReadOnlyItem(const QString& text)
    {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        item->setToolTip(text);
        return item;
    }

    // driverObjectQueryStatusText: Converts shared protocol status codes into diagnostic text.
    QString driverObjectQueryStatusText(const std::uint32_t status)
    {
        switch (status)
        {
        case KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_OK:
            return ioTimerText("kernel.iotimer.query.ok", QStringLiteral("完整"));
        case KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_PARTIAL:
            return ioTimerText("kernel.iotimer.query.partial", QStringLiteral("部分结果"));
        case KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_NOT_FOUND:
            return ioTimerText("kernel.iotimer.query.not_found", QStringLiteral("对象已消失"));
        case KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_REFERENCE_FAILED:
            return ioTimerText("kernel.iotimer.query.reference_failed", QStringLiteral("引用失败"));
        default:
            return ioTimerText("kernel.iotimer.query.failed", QStringLiteral("查询失败(%1)"))
                .arg(status);
        }
    }

    // ioTimerControlStatusText: Convert R0 semantic status into actionable diagnostics.
    QString ioTimerControlStatusText(const std::uint32_t status)
    {
        switch (status)
        {
        case KSWORD_ARK_IO_TIMER_CONTROL_STATUS_OK:
            return ioTimerText("kernel.iotimer.control.status.ok", QStringLiteral("已调用公开 WDM API"));
        case KSWORD_ARK_IO_TIMER_CONTROL_STATUS_INVALID_REQUEST:
            return ioTimerText("kernel.iotimer.control.status.invalid_request", QStringLiteral("请求或确认令牌无效"));
        case KSWORD_ARK_IO_TIMER_CONTROL_STATUS_DRIVER_NOT_FOUND:
            return ioTimerText("kernel.iotimer.control.status.driver_not_found", QStringLiteral("DriverObject 已消失"));
        case KSWORD_ARK_IO_TIMER_CONTROL_STATUS_DRIVER_IDENTITY_CHANGED:
            return ioTimerText("kernel.iotimer.control.status.driver_changed", QStringLiteral("DriverObject 身份已变化"));
        case KSWORD_ARK_IO_TIMER_CONTROL_STATUS_DEVICE_NOT_FOUND:
            return ioTimerText("kernel.iotimer.control.status.device_not_found", QStringLiteral("DeviceObject 已消失"));
        case KSWORD_ARK_IO_TIMER_CONTROL_STATUS_DEVICE_IDENTITY_CHANGED:
            return ioTimerText("kernel.iotimer.control.status.device_changed", QStringLiteral("DeviceObject 归属已变化"));
        case KSWORD_ARK_IO_TIMER_CONTROL_STATUS_TIMER_NOT_PRESENT:
            return ioTimerText("kernel.iotimer.control.status.timer_missing", QStringLiteral("DEVICE_OBJECT.Timer 已为空"));
        case KSWORD_ARK_IO_TIMER_CONTROL_STATUS_TIMER_IDENTITY_CHANGED:
            return ioTimerText("kernel.iotimer.control.status.timer_changed", QStringLiteral("PIO_TIMER 身份已变化"));
        case KSWORD_ARK_IO_TIMER_CONTROL_STATUS_ENUMERATION_FAILED:
            return ioTimerText("kernel.iotimer.control.status.enumeration_failed", QStringLiteral("带引用设备快照枚举失败"));
        default:
            return ioTimerText("kernel.iotimer.control.status.unknown", QStringLiteral("未知状态(%1)"))
                .arg(status);
        }
    }

    // isDriverObjectEntry: Selects only real Driver type objects, skipping range descriptions and error placeholders.
    bool isDriverObjectEntry(const KernelDeviceDriverObjectEntry& entry)
    {
        return entry.querySucceeded
            && !entry.isScopeEntry
            && entry.objectTypeText.compare(QStringLiteral("Driver"), Qt::CaseInsensitive) == 0
            && !entry.fullPathText.trimmed().isEmpty();
    }
}

KernelIoTimerTab::KernelIoTimerTab(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
    applyTranslatedText();
}

void KernelIoTimerTab::requestInitialRefresh()
{
    if (initialRefreshRequested_)
    {
        return;
    }
    initialRefreshRequested_ = true;
    refreshAsync();
}

void KernelIoTimerTab::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event != nullptr && event->type() == QEvent::LanguageChange)
    {
        applyTranslatedText();
        rebuildTable();
        updateDetail();
    }
}

void KernelIoTimerTab::initializeUi()
{
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(6, 6, 6, 6);
    rootLayout->setSpacing(6);

    auto* toolbarLayout = new QHBoxLayout();
    toolbarLayout->setContentsMargins(0, 0, 0, 0);
    toolbarLayout->setSpacing(6);

    refreshButton_ = new QPushButton(QIcon(QStringLiteral(":/Icon/process_refresh.svg")), QString(), this);
    ksword_theme::applyCompactIconButtonMetrics(refreshButton_);
    startButton_ = new QPushButton(QIcon(QStringLiteral(":/Icon/process_resume.svg")), QString(), this);
    startButton_->setMinimumHeight(30);
    stopButton_ = new QPushButton(QIcon(QStringLiteral(":/Icon/process_suspend.svg")), QString(), this);
    stopButton_->setMinimumHeight(30);
    filterEdit_ = new QLineEdit(this);
    filterEdit_->setClearButtonEnabled(true);
    statusLabel_ = new QLabel(this);
    statusLabel_->setStyleSheet(
        QStringLiteral("QLabel{color:%1;font-weight:600;}").arg(ksword_theme::textSecondaryHex()));

    toolbarLayout->addWidget(refreshButton_);
    toolbarLayout->addWidget(startButton_);
    toolbarLayout->addWidget(stopButton_);
    toolbarLayout->addWidget(filterEdit_, 1);
    toolbarLayout->addWidget(statusLabel_);
    rootLayout->addLayout(toolbarLayout);

    auto* splitter = new QSplitter(Qt::Vertical, this);
    table_ = new QTableWidget(splitter);
    table_->setColumnCount(static_cast<int>(Column::kCount));
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setAlternatingRowColors(true);
    table_->setSortingEnabled(true);
    table_->setContextMenuPolicy(Qt::CustomContextMenu);
    table_->verticalHeader()->setVisible(false);
    table_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(
        static_cast<int>(Column::kNamespacePath),
        QHeaderView::Stretch);

    detailEditor_ = new CodeEditorWidget(splitter);
    detailEditor_->setReadOnly(true);
    splitter->setStretchFactor(0, 4);
    splitter->setStretchFactor(1, 2);
    rootLayout->addWidget(splitter, 1);

    ks::ui::DetailLayoutRegistry::registerHost(table_, detailEditor_, this);

    connect(refreshButton_, &QPushButton::clicked, this, [this]() {
        initialRefreshRequested_ = true;
        refreshAsync();
    });
    connect(startButton_, &QPushButton::clicked, this, [this]() {
        runControlAction(KSWORD_ARK_IO_TIMER_CONTROL_ACTION_START);
    });
    connect(stopButton_, &QPushButton::clicked, this, [this]() {
        runControlAction(KSWORD_ARK_IO_TIMER_CONTROL_ACTION_STOP);
    });
    connect(filterEdit_, &QLineEdit::textChanged, this, [this]() {
        rebuildTable();
    });
    connect(table_, &QTableWidget::itemSelectionChanged, this, [this]() {
        updateDetail();
        updateControlActions();
    });
    connect(table_, &QTableWidget::customContextMenuRequested, this,
        [this](const QPoint& localPosition) {
            showContextMenu(localPosition);
        });
    updateControlActions();
}

void KernelIoTimerTab::applyTranslatedText()
{
    refreshButton_->setToolTip(
        ioTimerText("kernel.iotimer.refresh.tooltip", QStringLiteral("重新枚举全部 DriverObject 的 IoTimer")));
    startButton_->setText(
        ioTimerText("kernel.iotimer.control.start", QStringLiteral("启动 IoTimer")));
    startButton_->setToolTip(
        ioTimerText(
            "kernel.iotimer.control.start.tooltip",
            QStringLiteral("身份重验后调用 IoStartTimer；已注册回调通常每秒执行一次")));
    stopButton_->setText(
        ioTimerText("kernel.iotimer.control.stop", QStringLiteral("停止 IoTimer")));
    stopButton_->setToolTip(
        ioTimerText(
            "kernel.iotimer.control.stop.tooltip",
            QStringLiteral("身份重验后调用 IoStopTimer；可能破坏目标驱动的超时和状态机")));
    filterEdit_->setPlaceholderText(
        ioTimerText("kernel.iotimer.filter.placeholder", QStringLiteral("按地址、驱动、设备或对象路径筛选")));
    filterEdit_->setToolTip(
        ioTimerText("kernel.iotimer.filter.tooltip", QStringLiteral("只过滤当前快照，不重新访问驱动")));
    table_->setHorizontalHeaderLabels(QStringList{
        ioTimerText("kernel.iotimer.header.timer", QStringLiteral("IoTimer 地址")),
        ioTimerText("kernel.iotimer.header.device_object", QStringLiteral("DeviceObject")),
        ioTimerText("kernel.iotimer.header.driver_object", QStringLiteral("DriverObject")),
        ioTimerText("kernel.iotimer.header.driver", QStringLiteral("驱动名")),
        ioTimerText("kernel.iotimer.header.device", QStringLiteral("设备名")),
        ioTimerText("kernel.iotimer.header.namespace", QStringLiteral("对象路径")),
        ioTimerText("kernel.iotimer.header.status", QStringLiteral("查询状态"))
    });

    if (!initialRefreshRequested_ && !refreshRunning_.load(std::memory_order_relaxed))
    {
        statusLabel_->setText(
            ioTimerText("kernel.iotimer.status.waiting", QStringLiteral("状态：切换到本页后开始查询")));
        detailEditor_->setText(
            ioTimerText(
                "kernel.iotimer.detail.initial",
                QStringLiteral("本页展示 DEVICE_OBJECT.Timer，并提供经三重身份重验的启动/停止。请选择一行查看完整证据。")));
    }
    updateControlActions();
}

void KernelIoTimerTab::refreshAsync()
{
    bool expected = false;
    if (!refreshRunning_.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
    {
        return;
    }

    const std::uint64_t kRefreshTicket = ++refreshTicket_;
    refreshButton_->setEnabled(false);
    updateControlActions();
    statusLabel_->setText(
        ioTimerText("kernel.iotimer.status.refreshing", QStringLiteral("状态：正在枚举 DriverObject / DeviceObject...")));

    QPointer<KernelIoTimerTab> guardThis(this);
    QThreadPool::globalInstance()->start([guardThis, kRefreshTicket]() {
        auto snapshot = std::make_shared<Snapshot>(collectSnapshot());
        QMetaObject::invokeMethod(
            QCoreApplication::instance(),
            [guardThis, kRefreshTicket, snapshot]() {
                if (guardThis == nullptr || kRefreshTicket != guardThis->refreshTicket_)
                {
                    return;
                }
                guardThis->applySnapshot(*snapshot);
            },
            Qt::QueuedConnection);
    });
}

KernelIoTimerTab::Snapshot KernelIoTimerTab::collectSnapshot()
{
    Snapshot snapshot;
    std::vector<KernelDeviceDriverObjectEntry> namespaceRows;
    QString namespaceError;
    if (!runKernelDeviceDriverObjectsSnapshotTask(namespaceRows, namespaceError))
    {
        snapshot.namespaceError = namespaceError;
        return snapshot;
    }
    snapshot.namespaceError = namespaceError;

    std::set<QString, std::less<>> driverObjectPaths;
    for (const KernelDeviceDriverObjectEntry& namespaceRow : namespaceRows)
    {
        if (isDriverObjectEntry(namespaceRow))
        {
            driverObjectPaths.insert(namespaceRow.fullPathText.trimmed());
        }
    }
    snapshot.driverObjectsDiscovered = static_cast<std::uint32_t>(driverObjectPaths.size());

    ksword::ark::DriverClient driverClient;
    std::set<std::uint64_t> seenTimerAddresses;
    for (const QString& driverObjectPath : driverObjectPaths)
    {
        const ksword::ark::DriverObjectQueryResult kQueryResult = driverClient.queryDriverObject(
            driverObjectPath.toStdWString(),
            KSWORD_ARK_DRIVER_OBJECT_QUERY_FLAG_INCLUDE_DEVICES |
                KSWORD_ARK_DRIVER_OBJECT_QUERY_FLAG_INCLUDE_NAMES,
            KSWORD_ARK_DRIVER_DEVICE_LIMIT_DEFAULT,
            0UL);
        ++snapshot.driverObjectsQueried;

        if (!kQueryResult.io.ok)
        {
            ++snapshot.queryFailures;
            continue;
        }
        if (kQueryResult.queryStatus == KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_PARTIAL)
        {
            ++snapshot.partialQueries;
        }
        else if (kQueryResult.queryStatus != KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_OK)
        {
            ++snapshot.queryFailures;
        }

        const QString kDriverDisplayName = kQueryResult.driverName.empty()
            ? driverObjectPath
            : QString::fromStdWString(kQueryResult.driverName);
        const QString kImagePath = QString::fromStdWString(kQueryResult.imagePath);
        const QString kQueryStatus = driverObjectQueryStatusText(kQueryResult.queryStatus);
        for (const ksword::ark::DriverDeviceEntry& deviceEntry : kQueryResult.devices)
        {
            if (deviceEntry.ioTimerAddress == 0U)
            {
                continue;
            }
            if (!seenTimerAddresses.insert(deviceEntry.ioTimerAddress).second)
            {
                ++snapshot.duplicateTimersSkipped;
                continue;
            }

            IoTimerRow row;
            row.timerAddress = deviceEntry.ioTimerAddress;
            row.deviceObjectAddress = deviceEntry.deviceObjectAddress;
            row.driverObjectAddress = deviceEntry.driverObjectAddress;
            row.driverName = kDriverDisplayName;
            row.deviceName = QString::fromStdWString(deviceEntry.deviceName);
            row.namespacePath = driverObjectPath;
            row.imagePath = kImagePath;
            row.queryStatus = kQueryStatus;
            row.queryProtocolVersion = kQueryResult.version;
            row.queryFieldFlags = kQueryResult.fieldFlags;
            snapshot.rows.push_back(std::move(row));
        }
    }

    std::sort(snapshot.rows.begin(), snapshot.rows.end(), [](const IoTimerRow& left, const IoTimerRow& right) {
        if (left.driverName.compare(right.driverName, Qt::CaseInsensitive) != 0)
        {
            return left.driverName.compare(right.driverName, Qt::CaseInsensitive) < 0;
        }
        if (left.deviceObjectAddress != right.deviceObjectAddress)
        {
            return left.deviceObjectAddress < right.deviceObjectAddress;
        }
        return left.timerAddress < right.timerAddress;
    });
    return snapshot;
}

void KernelIoTimerTab::applySnapshot(const Snapshot& snapshot)
{
    rows_ = snapshot.rows;
    lastSnapshot_ = snapshot;
    refreshRunning_.store(false, std::memory_order_release);
    refreshButton_->setEnabled(true);
    rebuildTable();
    updateControlActions();

    if (!snapshot.namespaceError.isEmpty() && snapshot.driverObjectsQueried == 0U)
    {
        statusLabel_->setText(
            ioTimerText("kernel.iotimer.status.failed", QStringLiteral("状态：查询失败；%1"))
                .arg(snapshot.namespaceError));
        return;
    }

    statusLabel_->setText(
        ioTimerText(
            "kernel.iotimer.status.completed",
            QStringLiteral("状态：%1 条；DriverObject=%2/%3；失败=%4；部分=%5；去重=%6"))
            .arg(static_cast<qulonglong>(snapshot.rows.size()))
            .arg(snapshot.driverObjectsQueried)
            .arg(snapshot.driverObjectsDiscovered)
            .arg(snapshot.queryFailures)
            .arg(snapshot.partialQueries)
            .arg(snapshot.duplicateTimersSkipped));
}

void KernelIoTimerTab::rebuildTable()
{
    ks::ui::DetailLayoutRegistry::prepareDataRebuild(detailEditor_);
    const QString kFilterText = filterEdit_ != nullptr ? filterEdit_->text().trimmed() : QString();
    table_->setSortingEnabled(false);
    table_->setRowCount(0);

    for (std::size_t sourceIndex = 0; sourceIndex < rows_.size(); ++sourceIndex)
    {
        const IoTimerRow& row = rows_[sourceIndex];
        const QStringList kSearchableFields{
            pointerText(row.timerAddress),
            pointerText(row.deviceObjectAddress),
            pointerText(row.driverObjectAddress),
            row.driverName,
            row.deviceName,
            row.namespacePath,
            row.imagePath,
            row.queryStatus
        };
        if (!kFilterText.isEmpty() && !kSearchableFields.join(QLatin1Char('\n')).contains(kFilterText, Qt::CaseInsensitive))
        {
            continue;
        }

        const int kTableRow = table_->rowCount();
        table_->insertRow(kTableRow);
        const QStringList kCells{
            pointerText(row.timerAddress),
            pointerText(row.deviceObjectAddress),
            pointerText(row.driverObjectAddress),
            row.driverName,
            row.deviceName.isEmpty()
                ? ioTimerText("kernel.iotimer.value.unnamed", QStringLiteral("<未命名设备>"))
                : row.deviceName,
            row.namespacePath,
            row.queryStatus
        };
        for (int column = 0; column < kCells.size(); ++column)
        {
            QTableWidgetItem* item = makeReadOnlyItem(kCells[column]);
            item->setData(Qt::UserRole, static_cast<qulonglong>(sourceIndex));
            if (column <= static_cast<int>(Column::kDriverObject))
            {
                item->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
            }
            table_->setItem(kTableRow, column, item);
        }
    }

    table_->setSortingEnabled(true);
    if (table_->rowCount() > 0)
    {
        table_->selectRow(0);
    }
    else
    {
        detailEditor_->setText(
            ioTimerText("kernel.iotimer.detail.empty", QStringLiteral("当前筛选条件下没有 IoTimer 记录。")));
    }
    updateControlActions();
}

void KernelIoTimerTab::updateDetail()
{
    const int kCurrentRow = table_->currentRow();
    QTableWidgetItem* sourceItem = kCurrentRow >= 0 ? table_->item(kCurrentRow, 0) : nullptr;
    if (sourceItem == nullptr)
    {
        return;
    }
    const std::size_t kSourceIndex = static_cast<std::size_t>(sourceItem->data(Qt::UserRole).toULongLong());
    if (kSourceIndex >= rows_.size())
    {
        return;
    }

    const IoTimerRow& row = rows_[kSourceIndex];
    const QString kDetailText = ioTimerText(
        "kernel.iotimer.detail.template",
        QStringLiteral(
            "IoTimer 地址：%1\n"
            "DeviceObject：%2\n"
            "DriverObject：%3\n"
            "驱动名：%4\n"
            "设备名：%5\n"
            "对象路径：%6\n"
            "映像路径：%7\n"
            "协议版本：%8\n"
            "字段标志：0x%9\n"
            "查询状态：%10\n\n"
            "安全边界：地址来自 WDK 公开 DEVICE_OBJECT.Timer 字段。启动/停止时，"
            "R0 会按对象名重新引用 DriverObject，通过带引用设备快照核对 DeviceObject，"
            "并比较 PIO_TIMER；只调用 IoStartTimer/IoStopTimer，不解引用或写入私有 IO_TIMER。\n\n"
            "限制：WDM API 返回 VOID，Windows 没有公开查询 IoTimer 当前启停状态的接口；"
            "成功仅表示公开控制 API 已被调用。"))
        .arg(pointerText(row.timerAddress))
        .arg(pointerText(row.deviceObjectAddress))
        .arg(pointerText(row.driverObjectAddress))
        .arg(row.driverName)
        .arg(row.deviceName.isEmpty()
            ? ioTimerText("kernel.iotimer.value.unnamed", QStringLiteral("<未命名设备>"))
            : row.deviceName)
        .arg(row.namespacePath)
        .arg(row.imagePath.isEmpty() ? QStringLiteral("<empty>") : row.imagePath)
        .arg(row.queryProtocolVersion)
        .arg(row.queryFieldFlags, 8, 16, QChar('0'))
        .arg(row.queryStatus);
    detailEditor_->setText(kDetailText);
}

const KernelIoTimerTab::IoTimerRow* KernelIoTimerTab::selectedRow() const
{
    if (table_ == nullptr || table_->currentRow() < 0)
    {
        return nullptr;
    }
    const QTableWidgetItem* sourceItem = table_->item(table_->currentRow(), 0);
    if (sourceItem == nullptr)
    {
        return nullptr;
    }
    const std::size_t kSourceIndex =
        static_cast<std::size_t>(sourceItem->data(Qt::UserRole).toULongLong());
    return kSourceIndex < rows_.size() ? &rows_[kSourceIndex] : nullptr;
}

void KernelIoTimerTab::updateControlActions()
{
    const bool kEnabled =
        !refreshRunning_.load(std::memory_order_relaxed) && selectedRow() != nullptr;
    if (startButton_ != nullptr)
    {
        startButton_->setEnabled(kEnabled);
    }
    if (stopButton_ != nullptr)
    {
        stopButton_->setEnabled(kEnabled);
    }
}

void KernelIoTimerTab::runControlAction(const std::uint32_t action)
{
    const IoTimerRow* selected = selectedRow();
    if (selected == nullptr)
    {
        return;
    }
    const IoTimerRow kRow = *selected;
    const bool kIsStart = action == KSWORD_ARK_IO_TIMER_CONTROL_ACTION_START;
    if (!kIsStart && action != KSWORD_ARK_IO_TIMER_CONTROL_ACTION_STOP)
    {
        return;
    }

    const QString kActionTitle = kIsStart
        ? ioTimerText("kernel.iotimer.control.start", QStringLiteral("启动 IoTimer"))
        : ioTimerText("kernel.iotimer.control.stop", QStringLiteral("停止 IoTimer"));
    const QString kRiskText = kIsStart
        ? ioTimerText(
            "kernel.iotimer.control.start.risk",
            QStringLiteral(
                "IoStartTimer 会启用目标驱动已注册的 IoTimerRoutine，其通常每秒执行一次。"
                "对未预期重复启动的驱动操作，可能导致重入、设备异常或系统崩溃。"))
        : ioTimerText(
            "kernel.iotimer.control.stop.risk",
            QStringLiteral(
                "IoStopTimer 会停止目标驱动的设备计时回调。该回调可能负责超时、轮询、"
                "故障恢复或硬件保活；停止后可能导致设备卡死、数据丢失或系统崩溃。"));
    const QString kTargetText = ioTimerText(
        "kernel.iotimer.control.target",
        QStringLiteral("驱动：%1\n设备：%2\nIoTimer：%3"))
        .arg(kRow.namespacePath)
        .arg(pointerText(kRow.deviceObjectAddress))
        .arg(pointerText(kRow.timerAddress));

    QMessageBox warningBox(this);
    warningBox.setIcon(QMessageBox::Critical);
    warningBox.setWindowTitle(
        ioTimerText("kernel.iotimer.control.warning_title", QStringLiteral("关键风险：控制外部驱动 IoTimer")));
    warningBox.setText(
        ioTimerText(
            "kernel.iotimer.control.warning_text",
            QStringLiteral("即将执行“%1”。KSword 只告知风险，不按高级模式或风险等级限制修改；继续后仍会核验目标身份。"))
            .arg(kActionTitle));
    warningBox.setInformativeText(kTargetText + QStringLiteral("\n\n") + kRiskText);
    warningBox.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    warningBox.setDefaultButton(QMessageBox::No);
    warningBox.setEscapeButton(QMessageBox::No);
    if (warningBox.exec() != QMessageBox::Yes)
    {
        return;
    }

    // Changed the double confirmation to a direct click: the action name matches the button text; no English passphrase is used.
    const QString kConfirmationPhrase = QStringLiteral("%1 %2")
        .arg(kIsStart
            ? ioTimerText("kernel.iotimer.control.start", QStringLiteral("启动定时器"))
            : ioTimerText("kernel.iotimer.control.stop", QStringLiteral("停止定时器")))
        .arg(pointerText(kRow.timerAddress));
    const auto kTypedConfirmation = QMessageBox::warning(
        this,
        ioTimerText("kernel.iotimer.control.confirm_title", QStringLiteral("二次确认 IoTimer 控制")),
        ioTimerText(
            "kernel.iotimer.control.confirm_final",
            QStringLiteral("确认执行 %1？"))
            .arg(kConfirmationPhrase),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kTypedConfirmation != QMessageBox::Yes)
    {
        return;
    }

    ksword::ark::DriverClient driverClient;
    const ksword::ark::IoTimerControlResult kResult = driverClient.controlIoTimer(
        action,
        kRow.namespacePath.toStdWString(),
        kRow.driverObjectAddress,
        kRow.deviceObjectAddress,
        kRow.timerAddress,
        true);
    if (!kResult.io.ok)
    {
        const QString kTransportText = kResult.unsupported
            ? ioTimerText(
                "kernel.iotimer.control.unsupported",
                QStringLiteral("当前 KswordARK 驱动过旧，尚未注册 IoTimer 控制 IOCTL。请更新并重载驱动。"))
            : ioTimerText(
                "kernel.iotimer.control.transport_failed",
                QStringLiteral("IoTimer 控制 IOCTL 失败。\n%1"))
                .arg(QString::fromStdString(kResult.io.message));
        QMessageBox::critical(this, kActionTitle, kTransportText);
        return;
    }

    if (kResult.status != KSWORD_ARK_IO_TIMER_CONTROL_STATUS_OK)
    {
        QMessageBox::critical(
            this,
            kActionTitle,
            ioTimerText(
                "kernel.iotimer.control.failed",
                QStringLiteral(
                    "R0 已拒绝操作：%1\n语义状态：%2\nNTSTATUS：0x%3\n"
                    "重新观察：Driver=%4，Device=%5，Timer=%6\n\n"
                    "对象身份变化或目标无效时请刷新后重新确认。"))
                .arg(ioTimerControlStatusText(kResult.status))
                .arg(kResult.status)
                .arg(static_cast<std::uint32_t>(kResult.lastStatus), 8, 16, QChar('0'))
                .arg(pointerText(kResult.observedDriverObjectAddress))
                .arg(pointerText(kResult.observedDeviceObjectAddress))
                .arg(pointerText(kResult.observedTimerAddress)));
        refreshAsync();
        return;
    }

    QMessageBox::information(
        this,
        kActionTitle,
        ioTimerText(
            "kernel.iotimer.control.completed",
            QStringLiteral(
                "%1 已在三重身份校验后调用。\n\n"
                "Windows 的 IoStartTimer/IoStopTimer 返回 VOID，且没有公开运行状态查询接口；"
                "因此此结果表示 API 已接受调用，不伪造“已验证运行态”。"))
            .arg(kIsStart ? QStringLiteral("IoStartTimer") : QStringLiteral("IoStopTimer")));
    refreshAsync();
}

void KernelIoTimerTab::showContextMenu(const QPoint& localPosition)
{
    const QModelIndex kClickedIndex = table_->indexAt(localPosition);
    if (kClickedIndex.isValid())
    {
        table_->setCurrentCell(kClickedIndex.row(), kClickedIndex.column());
    }

    QMenu menu(table_);
    menu.setStyleSheet(QStringLiteral(
        "QMenu{background:%1;color:%2;border:1px solid %3;}"
        "QMenu::item{padding:5px 22px 5px 8px;}"
        "QMenu::item:selected{background:%4;color:%5;}")
        .arg(ksword_theme::surfaceHex())
        .arg(ksword_theme::textPrimaryHex())
        .arg(ksword_theme::borderHex())
        .arg(ksword_theme::kPrimaryBlueHex)
        .arg(ksword_theme::onAccentHex()));
    QAction* startAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_resume.svg")),
        ioTimerText("kernel.iotimer.control.start", QStringLiteral("启动 IoTimer")));
    QAction* stopAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_suspend.svg")),
        ioTimerText("kernel.iotimer.control.stop", QStringLiteral("停止 IoTimer")));
    menu.addSeparator();
    QAction* copyCellAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_copy_cell.svg")),
        ioTimerText("kernel.iotimer.menu.copy_cell", QStringLiteral("复制单元格")));
    QAction* copyRowAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
        ioTimerText("kernel.iotimer.menu.copy_row", QStringLiteral("复制当前行")));
    const bool kCanControl =
        !refreshRunning_.load(std::memory_order_relaxed) && selectedRow() != nullptr;
    startAction->setEnabled(kCanControl);
    stopAction->setEnabled(kCanControl);
    copyCellAction->setEnabled(kClickedIndex.isValid());
    copyRowAction->setEnabled(table_->currentRow() >= 0);

    const QAction* selectedAction = menu.exec(table_->viewport()->mapToGlobal(localPosition));
    if (selectedAction == nullptr)
    {
        return;
    }
    if (selectedAction == startAction)
    {
        runControlAction(KSWORD_ARK_IO_TIMER_CONTROL_ACTION_START);
        return;
    }
    if (selectedAction == stopAction)
    {
        runControlAction(KSWORD_ARK_IO_TIMER_CONTROL_ACTION_STOP);
        return;
    }

    QString clipboardText;
    if (selectedAction == copyCellAction && kClickedIndex.isValid())
    {
        const QTableWidgetItem* item = table_->item(kClickedIndex.row(), kClickedIndex.column());
        clipboardText = item != nullptr ? item->text() : QString();
    }
    else if (selectedAction == copyRowAction && table_->currentRow() >= 0)
    {
        QStringList fields;
        for (int column = 0; column < table_->columnCount(); ++column)
        {
            const QTableWidgetItem* item = table_->item(table_->currentRow(), column);
            fields.push_back(normalizedCellText(item != nullptr ? item->text() : QString()));
        }
        clipboardText = fields.join(QLatin1Char('\t'));
    }

    if (!clipboardText.isEmpty() && QApplication::clipboard() != nullptr)
    {
        QApplication::clipboard()->setText(clipboardText);
    }
}

QString KernelIoTimerTab::pointerText(const std::uint64_t address)
{
    return QStringLiteral("0x%1").arg(static_cast<qulonglong>(address), 16, 16, QChar('0')).toUpper();
}

QString KernelIoTimerTab::normalizedCellText(const QString& text)
{
    QString normalized = text;
    normalized.replace(QLatin1Char('\t'), QLatin1Char(' '));
    normalized.replace(QLatin1Char('\r'), QLatin1Char(' '));
    normalized.replace(QLatin1Char('\n'), QLatin1Char(' '));
    return normalized;
}
