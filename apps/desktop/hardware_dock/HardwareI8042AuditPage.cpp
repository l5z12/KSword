#include "HardwareI8042AuditPage.h"

#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../internationalization/LanguageManager.h"
#include "../ui/TableInteractionSupport.h"
#include "../ui/VisibleTableWidget.h"
#include "../Theme.h"

#include <QAbstractItemView>
#include <QBrush>
#include <QColor>
#include <QCoreApplication>
#include <QEvent>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QMetaObject>
#include <QPushButton>
#include <QPointer>
#include <QShowEvent>
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

#include <array>
#include <algorithm>
#include <utility>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

namespace
{
    QString i8042Text(const char* const key, const QString& sourceText)
    {
        return ks::i18n::LanguageManager::instance().text(
            QString::fromUtf8(key),
            sourceText);
    }

    enum I8042Column : int
    {
        kColumnDeviceKind = 0,
        kColumnPnpId,
        kColumnEndpoint,
        kColumnAddress,
        kColumnContext,
        kColumnClassDeviceObject,
        kColumnOwner,
        kColumnExecutable,
        kColumnSameStack,
        kColumnVerdict,
        kColumnStatus,
        kColumnEvidence,
        kColumnCount
    };

    QTableWidgetItem* readOnlyI8042Item(const QString& text)
    {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }

    QString i8042ColumnButtonStyle(const bool selected)
    {
        return QStringLiteral(
            "QPushButton{min-width:28px;padding:4px 8px;border:1px solid %1;"
            "background:%2;color:%3;}"
            "QPushButton:hover{background:%4;}")
            .arg(ksword_theme::borderHex())
            .arg(selected
                     ? ksword_theme::kPrimaryBlueHex
                     : ksword_theme::surfaceAltHex())
            .arg(selected
                     ? ksword_theme::onAccentDynamicHex()
                     : ksword_theme::textPrimaryHex())
            .arg(ksword_theme::primaryBlueSolidHoverHex());
    }

    QString hexValue(const std::uint64_t value)
    {
        return QStringLiteral("0x%1")
            .arg(value, 0, 16)
            .toUpper();
    }
}

HardwareI8042AuditPage::HardwareI8042AuditPage(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
}

HardwareI8042AuditPage::~HardwareI8042AuditPage()
{
    {
        const std::lock_guard kLock(refreshMutex_);
        closing_ = true;
        if (refreshThread_.joinable())
        {
            // Cancel only the synchronous DeviceIoControl for this worker. If there is no pending I/O, a failure can be ignored.
            (void)::CancelSynchronousIo(refreshThread_.native_handle());
        }
    }
    if (refreshThread_.joinable())
    {
        refreshThread_.join();
    }
}

void HardwareI8042AuditPage::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    if (!firstRefreshStarted_)
    {
        firstRefreshStarted_ = true;
        QMetaObject::invokeMethod(
            this,
            [this]() { refreshAsync(); },
            Qt::QueuedConnection);
    }
}

void HardwareI8042AuditPage::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event != nullptr && event->type() == QEvent::LanguageChange)
    {
        retranslateUi();
    }
}

void HardwareI8042AuditPage::initializeUi()
{
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(6, 6, 6, 6);
    rootLayout->setSpacing(6);

    auto* toolbar = new QHBoxLayout();
    toolbar->setContentsMargins(0, 0, 0, 0);
    toolbar->setSpacing(0);
    refreshButton_ = new QPushButton(
        QIcon(QStringLiteral(":/Icon/process_refresh.svg")),
        QString(),
        this);
    refreshButton_->setStyleSheet(ksword_theme::themedButtonStyle());
    columnGroupAButton_ = new QPushButton(QStringLiteral("A"), this);
    columnGroupBButton_ = new QPushButton(QStringLiteral("B"), this);
    columnGroupCButton_ = new QPushButton(QStringLiteral("C"), this);
    filterEdit_ = new QLineEdit(this);
    filterEdit_->setClearButtonEnabled(true);
    statusLabel_ = new QLabel(this);
    statusLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    toolbar->addWidget(refreshButton_);
    toolbar->addSpacing(6);
    toolbar->addWidget(columnGroupAButton_);
    toolbar->addWidget(columnGroupBButton_);
    toolbar->addWidget(columnGroupCButton_);
    toolbar->addSpacing(6);
    toolbar->addWidget(filterEdit_, 1);
    toolbar->addWidget(statusLabel_);
    rootLayout->addLayout(toolbar);

    table_ = new ks::ui::VisibleTableWidget(this);
    table_->setColumnCount(kColumnCount);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setAlternatingRowColors(true);
    table_->verticalHeader()->setVisible(false);
    table_->horizontalHeader()->setSectionResizeMode(
        QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setStretchLastSection(true);
    rootLayout->addWidget(table_, 1);

    connect(
        refreshButton_,
        &QPushButton::clicked,
        this,
        [this]() { refreshAsync(); });
    connect(columnGroupAButton_, &QPushButton::clicked, this, [this]() { setColumnGroup(0); });
    connect(columnGroupBButton_, &QPushButton::clicked, this, [this]() { setColumnGroup(1); });
    connect(columnGroupCButton_, &QPushButton::clicked, this, [this]() { setColumnGroup(2); });
    connect(
        filterEdit_,
        &QLineEdit::textChanged,
        this,
        [this]() { applyFilter(); });
    retranslateUi();
    updateColumnGroupButtons();
    applyColumnGroup();
}

void HardwareI8042AuditPage::retranslateUi()
{
    if (refreshButton_ == nullptr ||
        columnGroupAButton_ == nullptr ||
        columnGroupBButton_ == nullptr ||
        columnGroupCButton_ == nullptr ||
        filterEdit_ == nullptr ||
        statusLabel_ == nullptr ||
        table_ == nullptr)
    {
        return;
    }
    if (ks::ui::isTableUiCommitBlockedByContextMenu({ table_ }))
    {
        const QPointer<HardwareI8042AuditPage> kSafeThis(this);
        ks::ui::deferTableUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("hardware-i8042-audit-retranslate"),
            { table_ },
            [kSafeThis]()
            {
                if (!kSafeThis.isNull())
                {
                    kSafeThis->retranslateUi();
                }
            });
        return;
    }

    refreshButton_->setToolTip(i8042Text(
        "hardware.i8042.refresh.tooltip",
        QStringLiteral("重新读取专用 i8042prt 描述符与端点证据")));
    columnGroupAButton_->setToolTip(i8042Text(
        "hardware.i8042.columns.a",
        QStringLiteral("A：端点定位")));
    columnGroupBButton_->setToolTip(i8042Text(
        "hardware.i8042.columns.b",
        QStringLiteral("B：完整性证据")));
    columnGroupCButton_->setToolTip(i8042Text(
        "hardware.i8042.columns.c",
        QStringLiteral("C：全部字段")));
    updateColumnGroupButtons();
    filterEdit_->setPlaceholderText(i8042Text(
        "hardware.i8042.filter.placeholder",
        QStringLiteral("过滤设备 / PnP / 端点 / 模块 / 状态 / 证据")));
    table_->setHorizontalHeaderLabels({
        i8042Text("hardware.i8042.header.device_type", QStringLiteral("设备类型")),
        i8042Text("hardware.i8042.header.pnp", QStringLiteral("PnP / Hardware ID")),
        i8042Text("hardware.i8042.header.endpoint", QStringLiteral("端点")),
        i8042Text("hardware.i8042.header.address", QStringLiteral("地址")),
        i8042Text("hardware.i8042.header.context", QStringLiteral("Context")),
        i8042Text("hardware.i8042.header.class_do", QStringLiteral("ClassDeviceObject")),
        i8042Text("hardware.i8042.header.owner", QStringLiteral("归属模块")),
        i8042Text("hardware.i8042.header.executable", QStringLiteral("执行节")),
        i8042Text("hardware.i8042.header.same_stack", QStringLiteral("同设备栈")),
        i8042Text("hardware.i8042.header.verdict", QStringLiteral("结论")),
        i8042Text("hardware.i8042.header.status", QStringLiteral("状态")),
        i8042Text("hardware.i8042.header.evidence", QStringLiteral("证据"))
    });

    if (refreshRunning_)
    {
        statusLabel_->setText(i8042Text(
            "hardware.i8042.status.refreshing",
            QStringLiteral("状态：正在验证映像描述符并读取只读端点...")));
    }
    else if (hasResult_)
    {
        renderResult(lastResult_);
    }
    else
    {
        statusLabel_->setText(i8042Text(
            "hardware.i8042.status.waiting",
            QStringLiteral("状态：等待刷新")));
    }
}

void HardwareI8042AuditPage::refreshAsync()
{
    if (refreshRunning_)
    {
        return;
    }
    if (refreshThread_.joinable())
    {
        // The previous result enters the GUI queue only after the worker has completed the query and successfully dispatched it.
        refreshThread_.join();
    }
    {
        const std::lock_guard kLock(refreshMutex_);
        if (closing_)
        {
            return;
        }
    }

    refreshRunning_ = true;
    refreshButton_->setEnabled(false);
    statusLabel_->setText(i8042Text(
        "hardware.i8042.status.refreshing",
        QStringLiteral("状态：正在验证映像描述符并读取只读端点...")));

    {
        const std::lock_guard kLock(refreshMutex_);
        if (closing_)
        {
            refreshRunning_ = false;
            refreshButton_->setEnabled(true);
            return;
        }
        QCoreApplication* const kApplication = QCoreApplication::instance();
        const QPointer<HardwareI8042AuditPage> kSafeThis(this);
        refreshThread_ = std::thread([this, kApplication, kSafeThis]()
        {
            ksword::ark::DriverClient client;
            auto result = client.queryI8042Audit();
            const std::lock_guard kWorkerLock(refreshMutex_);
            if (closing_)
            {
                return;
            }
            if (kApplication == nullptr)
            {
                return;
            }
            const bool kPosted = QMetaObject::invokeMethod(
                kApplication,
                [kSafeThis, result = std::move(result)]() mutable
                {
                    if (!kSafeThis.isNull())
                    {
                        kSafeThis->applyResult(std::move(result));
                    }
                },
                Qt::QueuedConnection);
            Q_UNUSED(kPosted);
        });
    }
}

void HardwareI8042AuditPage::applyResult(
    ksword::ark::I8042AuditResult result)
{
    if (ks::ui::isTableUiCommitBlockedByContextMenu({ table_ }))
    {
        const QPointer<HardwareI8042AuditPage> kSafeThis(this);
        ks::ui::deferTableUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("hardware-i8042-audit-apply"),
            { table_ },
            [kSafeThis, result = std::move(result)]() mutable
            {
                if (!kSafeThis.isNull())
                {
                    kSafeThis->applyResult(std::move(result));
                }
            });
        return;
    }

    refreshRunning_ = false;
    refreshButton_->setEnabled(true);
    lastResult_ = result;
    hasResult_ = true;
    renderResult(lastResult_);
}

void HardwareI8042AuditPage::renderResult(
    const ksword::ark::I8042AuditResult& result)
{
    table_->setRowCount(0);
    if (!result.io.ok)
    {
        statusLabel_->setText(i8042Text(
            "hardware.i8042.status.failed",
            QStringLiteral("状态：协议查询失败 - %1"))
            .arg(QString::fromStdString(result.io.message)));
        return;
    }

    for (const KSWORD_ARK_I8042_AUDIT_ENTRY& entry : result.entries)
    {
        appendEntry(entry);
    }
    applyColumnGroup();
    applyFilter();

    const bool kImageValidated =
        (result.responseFlags &
         KSWORD_ARK_I8042_RESPONSE_IMAGE_VALIDATED) != 0UL;
    const bool kDescriptorValidated =
        (result.responseFlags &
         KSWORD_ARK_I8042_RESPONSE_DESCRIPTOR_VALIDATED) != 0UL;
    statusLabel_->setText(i8042Text(
        "hardware.i8042.status.summary",
        QStringLiteral(
            "状态：%1/%2 行；描述符=%3；映像=%4；布局=%5；"
            "TDS=0x%6；Size=0x%7；Flags=0x%8"))
        .arg(result.entries.size())
        .arg(result.totalCount)
        .arg(result.descriptorId)
        .arg(yesNoText(kImageValidated, true))
        .arg(yesNoText(kDescriptorValidated, true))
        .arg(QStringLiteral("%1")
            .arg(result.imageTimeDateStamp, 8, 16, QLatin1Char('0'))
            .toUpper())
        .arg(QString::number(result.imageSize, 16).toUpper())
        .arg(QString::number(result.responseFlags, 16).toUpper()));
}

void HardwareI8042AuditPage::appendEntry(
    const KSWORD_ARK_I8042_AUDIT_ENTRY& entry)
{
    const bool kExecutablePresent =
        (entry.fieldFlags & KSWORD_ARK_I8042_FIELD_CALLBACK_ADDRESS) != 0UL;
    const bool kExecutable =
        (entry.fieldFlags & KSWORD_ARK_I8042_FIELD_EXECUTABLE) != 0UL;
    const bool kClassDoPresent =
        (entry.fieldFlags &
         KSWORD_ARK_I8042_FIELD_CLASS_DEVICE_OBJECT) != 0UL;
    const bool kSameStack =
        (entry.fieldFlags &
         KSWORD_ARK_I8042_FIELD_SAME_DEVICE_STACK) != 0UL;
    const std::array<QString, kColumnCount> kCells = {
        deviceKindText(entry.deviceKind),
        fixedWide(entry.pnpId, KSWORD_ARK_I8042_PNP_ID_CHARS),
        endpointText(entry.endpointKind),
        addressText(entry.callbackAddress != 0ULL
            ? entry.callbackAddress
            : entry.deviceObject),
        addressText(entry.contextAddress),
        addressText(entry.classDeviceObject),
        fixedWide(
            entry.ownerModulePath,
            KSWORD_ARK_I8042_MODULE_PATH_CHARS),
        yesNoText(kExecutable, kExecutablePresent),
        yesNoText(kSameStack, kClassDoPresent),
        verdictText(entry.verdict),
        statusText(entry.status, entry.lastStatus),
        detailText(entry)
    };

    const int kRow = table_->rowCount();
    table_->insertRow(kRow);
    for (int column = 0; column < kColumnCount; ++column)
    {
        auto* item = readOnlyI8042Item(
            kCells[static_cast<std::size_t>(column)]);
        if (entry.verdict == KSWORD_ARK_I8042_VERDICT_SUSPICIOUS)
        {
            item->setBackground(QBrush(QColor(190, 35, 45, 48)));
        }
        table_->setItem(kRow, column, item);
    }
}

void HardwareI8042AuditPage::setColumnGroup(const int groupIndex)
{
    columnGroupIndex_ = std::clamp(groupIndex, 0, 2);
    updateColumnGroupButtons();
    applyColumnGroup();
}

void HardwareI8042AuditPage::applyColumnGroup()
{
    const int kGroup = columnGroupIndex_;
    for (int column = 0; column < kColumnCount; ++column)
    {
        bool visible = kGroup == 2;
        if (kGroup == 0)
        {
            visible =
                column == kColumnDeviceKind ||
                column == kColumnPnpId ||
                column == kColumnEndpoint ||
                column == kColumnAddress ||
                column == kColumnOwner ||
                column == kColumnVerdict;
        }
        else if (kGroup == 1)
        {
            visible =
                column == kColumnEndpoint ||
                column == kColumnAddress ||
                column == kColumnContext ||
                column == kColumnClassDeviceObject ||
                column == kColumnExecutable ||
                column == kColumnSameStack ||
                column == kColumnStatus ||
                column == kColumnEvidence;
        }
        table_->setColumnHidden(column, !visible);
    }
}

void HardwareI8042AuditPage::updateColumnGroupButtons()
{
    const std::array<QPushButton*, 3> kButtons = {
        columnGroupAButton_,
        columnGroupBButton_,
        columnGroupCButton_
    };
    for (std::size_t index = 0U; index < kButtons.size(); ++index)
    {
        if (kButtons[index] != nullptr)
        {
            kButtons[index]->setStyleSheet(
                i8042ColumnButtonStyle(
                    static_cast<int>(index) == columnGroupIndex_));
        }
    }
}

void HardwareI8042AuditPage::applyFilter()
{
    const QString kFilter = filterEdit_ != nullptr
        ? filterEdit_->text().trimmed()
        : QString();
    for (int row = 0; row < table_->rowCount(); ++row)
    {
        bool matched = kFilter.isEmpty();
        for (int column = 0;
             !matched && column < table_->columnCount();
             ++column)
        {
            const QTableWidgetItem* item = table_->item(row, column);
            matched =
                item != nullptr &&
                item->text().contains(kFilter, Qt::CaseInsensitive);
        }
        table_->setRowHidden(row, !matched);
    }
}

QString HardwareI8042AuditPage::fixedWide(
    const wchar_t* text,
    const int capacity)
{
    if (text == nullptr || capacity <= 0)
    {
        return QString();
    }
    int length = 0;
    while (length < capacity && text[length] != L'\0')
    {
        ++length;
    }
    return QString::fromWCharArray(text, length);
}

QString HardwareI8042AuditPage::addressText(
    const std::uint64_t address)
{
    return address == 0ULL
        ? QStringLiteral("-")
        : QStringLiteral("0x%1")
            .arg(address, 16, 16, QLatin1Char('0'))
            .toUpper();
}

QString HardwareI8042AuditPage::deviceKindText(
    const std::uint32_t value)
{
    switch (value)
    {
    case KSWORD_ARK_I8042_DEVICE_KEYBOARD:
        return i8042Text(
            "hardware.i8042.device.keyboard",
            QStringLiteral("键盘"));
    case KSWORD_ARK_I8042_DEVICE_MOUSE:
        return i8042Text(
            "hardware.i8042.device.mouse",
            QStringLiteral("鼠标"));
    default:
        return i8042Text(
            "hardware.i8042.value.unknown",
            QStringLiteral("未知"));
    }
}

QString HardwareI8042AuditPage::endpointText(
    const std::uint32_t value)
{
    switch (value)
    {
    case KSWORD_ARK_I8042_ENDPOINT_KEYBOARD_CLASS_SERVICE:
        return QStringLiteral("Keyboard ClassService");
    case KSWORD_ARK_I8042_ENDPOINT_KEYBOARD_INITIALIZATION:
        return QStringLiteral("Keyboard InitializationRoutine");
    case KSWORD_ARK_I8042_ENDPOINT_KEYBOARD_ISR:
        return QStringLiteral("Keyboard IsrRoutine");
    case KSWORD_ARK_I8042_ENDPOINT_MOUSE_CLASS_SERVICE:
        return QStringLiteral("Mouse ClassService");
    case KSWORD_ARK_I8042_ENDPOINT_MOUSE_ISR:
        return QStringLiteral("Mouse IsrRoutine");
    default:
        return QStringLiteral("-");
    }
}

QString HardwareI8042AuditPage::yesNoText(
    const bool value,
    const bool present)
{
    if (!present)
    {
        return QStringLiteral("-");
    }
    return value
        ? i8042Text("hardware.i8042.value.yes", QStringLiteral("是"))
        : i8042Text("hardware.i8042.value.no", QStringLiteral("否"));
}

QString HardwareI8042AuditPage::verdictText(
    const std::uint32_t value)
{
    switch (value)
    {
    case KSWORD_ARK_I8042_VERDICT_AVAILABLE:
        return i8042Text(
            "hardware.i8042.verdict.available",
            QStringLiteral("证据可用（非 Clean）"));
    case KSWORD_ARK_I8042_VERDICT_SUSPICIOUS:
        return i8042Text(
            "hardware.i8042.verdict.suspicious",
            QStringLiteral("可疑"));
    case KSWORD_ARK_I8042_VERDICT_UNSUPPORTED:
        return i8042Text(
            "hardware.i8042.verdict.unsupported",
            QStringLiteral("不支持 / 失败关闭"));
    default:
        return i8042Text(
            "hardware.i8042.value.unknown",
            QStringLiteral("未知"));
    }
}

QString HardwareI8042AuditPage::statusText(
    const std::uint32_t value,
    const std::int32_t lastStatus)
{
    QString text;
    switch (value)
    {
    case KSWORD_ARK_I8042_AUDIT_STATUS_AVAILABLE:
        text = i8042Text(
            "hardware.i8042.status.available",
            QStringLiteral("已读取"));
        break;
    case KSWORD_ARK_I8042_AUDIT_STATUS_PARTIAL:
        text = i8042Text(
            "hardware.i8042.status.partial",
            QStringLiteral("部分"));
        break;
    case KSWORD_ARK_I8042_AUDIT_STATUS_UNSUPPORTED:
        text = i8042Text(
            "hardware.i8042.status.unsupported",
            QStringLiteral("不支持"));
        break;
    case KSWORD_ARK_I8042_AUDIT_STATUS_SIGNATURE_MISMATCH:
        text = i8042Text(
            "hardware.i8042.status.signature_mismatch",
            QStringLiteral("证据不匹配"));
        break;
    case KSWORD_ARK_I8042_AUDIT_STATUS_QUERY_FAILED:
        text = i8042Text(
            "hardware.i8042.status.query_failed",
            QStringLiteral("查询失败"));
        break;
    case KSWORD_ARK_I8042_AUDIT_STATUS_BUFFER_TRUNCATED:
        text = i8042Text(
            "hardware.i8042.status.truncated",
            QStringLiteral("已截断"));
        break;
    default:
        text = i8042Text(
            "hardware.i8042.status.unavailable",
            QStringLiteral("不可用"));
        break;
    }
    return QStringLiteral("%1 (0x%2)")
        .arg(text)
        .arg(QStringLiteral("%1")
            .arg(
                static_cast<std::uint32_t>(lastStatus),
                8,
                16,
                QLatin1Char('0'))
            .toUpper());
}

QString HardwareI8042AuditPage::detailText(
    const KSWORD_ARK_I8042_AUDIT_ENTRY& entry)
{
    const auto kArg = [&entry](const int index)
    {
        return hexValue(
            entry.detailArgs[static_cast<std::size_t>(index)]);
    };
    switch (entry.detailCode)
    {
    case KSWORD_ARK_I8042_DETAIL_DESCRIPTOR_VALIDATED:
        return i8042Text(
            "hardware.i8042.detail.descriptor_validated",
            QStringLiteral(
                "受支持描述符已验证；extension=%1；deviceKind=%2。"))
            .arg(kArg(0))
            .arg(entry.detailArgs[1]);
    case KSWORD_ARK_I8042_DETAIL_DRIVER_NOT_FOUND:
        return i8042Text(
            "hardware.i8042.detail.driver_not_found",
            QStringLiteral("\\Driver\\i8042prt 不存在或无法引用。"));
    case KSWORD_ARK_I8042_DETAIL_MODULE_NOT_FOUND:
        return i8042Text(
            "hardware.i8042.detail.module_not_found",
            QStringLiteral("未找到唯一的 i8042prt.sys 已加载模块。"));
    case KSWORD_ARK_I8042_DETAIL_IMAGE_MISMATCH:
        return i8042Text(
            "hardware.i8042.detail.image_mismatch",
            QStringLiteral("PE 身份不匹配；仅返回通用设备枚举，不读取私有扩展。"));
    case KSWORD_ARK_I8042_DETAIL_RSDS_MISMATCH:
        return i8042Text(
            "hardware.i8042.detail.rsds_mismatch",
            QStringLiteral("RSDS GUID/Age 不匹配；仅返回通用设备枚举，不读取私有扩展。"));
    case KSWORD_ARK_I8042_DETAIL_OPCODE_MISMATCH:
        return i8042Text(
            "hardware.i8042.detail.opcode_mismatch",
            QStringLiteral("opcode 窗口 %1 不匹配；未使用设备扩展偏移。"))
            .arg(kArg(0));
    case KSWORD_ARK_I8042_DETAIL_DRIVER_LAYOUT_MISMATCH:
        return i8042Text(
            "hardware.i8042.detail.driver_layout_mismatch",
            QStringLiteral(
                "DriverObject 派遣/AddDevice/设备类型不匹配（%1，%2）。"))
            .arg(kArg(0), kArg(1));
    case KSWORD_ARK_I8042_DETAIL_DEVICE_ENUM_FAILED:
        return i8042Text(
            "hardware.i8042.detail.device_enum_failed",
            QStringLiteral("IoEnumerateDeviceObjectList 失败。"));
    case KSWORD_ARK_I8042_DETAIL_NO_DEVICES:
        return i8042Text(
            "hardware.i8042.detail.no_devices",
            QStringLiteral("i8042prt 当前没有设备对象。"));
    case KSWORD_ARK_I8042_DETAIL_PNP_CLASS_UNKNOWN:
        return i8042Text(
            "hardware.i8042.detail.pnp_unknown",
            QStringLiteral("PnP 类别无法安全判定；未读取类型专用偏移。"));
    case KSWORD_ARK_I8042_DETAIL_EXTENSION_READ_FAILED:
        return i8042Text(
            "hardware.i8042.detail.extension_read_failed",
            QStringLiteral("设备扩展端点读取失败；未返回不完整指针。"));
    case KSWORD_ARK_I8042_DETAIL_ENDPOINT_AVAILABLE:
        return i8042Text(
            "hardware.i8042.detail.endpoint_available",
            QStringLiteral(
                "端点=%1；owner=%2；ClassDO=%3；Context=%4；"
                "owner/执行节/同栈证据通过，但没有独立 Clean 基线。"))
            .arg(kArg(0), kArg(1), kArg(2), kArg(3));
    case KSWORD_ARK_I8042_DETAIL_ENDPOINT_NULL:
        return i8042Text(
            "hardware.i8042.detail.endpoint_null",
            QStringLiteral("端点尚未登记；endpointKind=%1。"))
            .arg(entry.detailArgs[0]);
    case KSWORD_ARK_I8042_DETAIL_OWNER_MISMATCH:
        return i8042Text(
            "hardware.i8042.detail.owner_mismatch",
            QStringLiteral("端点 %1 的模块 %2 不在同一设备栈。"))
            .arg(kArg(0), kArg(1));
    case KSWORD_ARK_I8042_DETAIL_NON_EXECUTABLE:
        return i8042Text(
            "hardware.i8042.detail.non_executable",
            QStringLiteral("端点 %1 不位于归属模块的可执行节。"))
            .arg(kArg(0));
    case KSWORD_ARK_I8042_DETAIL_CLASS_DO_OUTSIDE_STACK:
        return i8042Text(
            "hardware.i8042.detail.class_do_outside_stack",
            QStringLiteral("ClassDeviceObject %1 不在设备 %2 的附加栈。"))
            .arg(kArg(0), kArg(1));
    case KSWORD_ARK_I8042_DETAIL_BUFFER_TRUNCATED:
        return i8042Text(
            "hardware.i8042.detail.buffer_truncated",
            QStringLiteral("结果超过行预算，已安全截断。"));
    case KSWORD_ARK_I8042_DETAIL_GENERIC_DEVICE_AVAILABLE:
        return i8042Text(
            "hardware.i8042.detail.generic_device",
            QStringLiteral("已通过 I/O 管理器枚举设备；当前版本无精确私有扩展描述符，因此不读取端点偏移。"));
    default:
        return QStringLiteral("-");
    }
}
