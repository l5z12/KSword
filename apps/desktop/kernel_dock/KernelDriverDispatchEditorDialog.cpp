#include "KernelDriverDispatchEditorDialog.h"

#include "KernelDock.h"
#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../Theme.h"

#include <QAbstractItemView>
#include <QGridLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QSignalBlocker>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTimer>
#include <QVBoxLayout>

using ksword::kernel_dock_internal::kernelText;

namespace
{
    enum Column : int
    {
        kColumnMajor = 0,
        kColumnSymbol,
        kColumnCurrent,
        kColumnOwner,
        kColumnTransaction,
        kColumnOriginal,
        kColumnApplied,
        kColumnCount
    };

    QTableWidgetItem* readOnlyItem(const QString& text)
    {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }

    QString ioMessageText(const std::string& text)
    {
        return QString::fromUtf8(text.c_str(), static_cast<int>(text.size()));
    }
}

KernelDriverDispatchEditorDialog::KernelDriverDispatchEditorDialog(
    const QString& driverObjectName,
    QWidget* parent)
    : QDialog(parent),
      requestedDriverName_(driverObjectName.trimmed())
{
    initializeUi();
    QTimer::singleShot(0, this, [this]() { refreshDriverSnapshot(); });
}

void KernelDriverDispatchEditorDialog::initializeUi()
{
    setWindowTitle(kernelText(
        "kernel.driver_dispatch.title",
        QStringLiteral("IRP / MajorFunction 编辑器")));
    resize(1180, 760);
    setModal(true);

    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(10, 10, 10, 10);
    rootLayout->setSpacing(7);

    riskLabel_ = new QLabel(
        kernelText(
            "kernel.driver_dispatch.risk",
            QStringLiteral("高风险：这里允许把任意 MajorFunction 槽写成任意指针，不校验地址归属或可执行性。错误值可能立即蓝屏、破坏文件系统或安全产品；修改 KSword 自身 IRP_MJ_DEVICE_CONTROL 会切断后续查询与恢复通道。")),
        this);
    riskLabel_->setWordWrap(true);
    riskLabel_->setStyleSheet(
        QStringLiteral("color:%1;font-weight:700;border:1px solid %1;padding:7px;")
            .arg(ksword_theme::errorHex()));
    rootLayout->addWidget(riskLabel_);

    auto* toolbar = new QHBoxLayout();
    refreshButton_ = new QPushButton(
        kernelText("kernel.driver_dispatch.refresh", QStringLiteral("刷新 DriverObject")),
        this);
    querySlotButton_ = new QPushButton(
        kernelText("kernel.driver_dispatch.query_slot", QStringLiteral("查询选中槽事务")),
        this);
    refreshButton_->setStyleSheet(ksword_theme::themedButtonStyle());
    querySlotButton_->setStyleSheet(ksword_theme::themedButtonStyle());
    identityLabel_ = new QLabel(this);
    identityLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    identityLabel_->setWordWrap(true);
    toolbar->addWidget(refreshButton_);
    toolbar->addWidget(querySlotButton_);
    toolbar->addWidget(identityLabel_, 1);
    rootLayout->addLayout(toolbar);

    table_ = new QTableWidget(this);
    table_->setColumnCount(kColumnCount);
    table_->setHorizontalHeaderLabels({
        kernelText("kernel.driver_dispatch.header.major", QStringLiteral("Major")),
        kernelText("kernel.driver_dispatch.header.symbol", QStringLiteral("IRP_MJ_*")),
        kernelText("kernel.driver_dispatch.header.current", QStringLiteral("当前入口")),
        kernelText("kernel.driver_dispatch.header.owner", QStringLiteral("当前归属模块")),
        kernelText("kernel.driver_dispatch.header.transaction", QStringLiteral("事务状态")),
        kernelText("kernel.driver_dispatch.header.original", QStringLiteral("记录原值")),
        kernelText("kernel.driver_dispatch.header.applied", QStringLiteral("已应用值")),
    });
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setAlternatingRowColors(true);
    table_->verticalHeader()->setVisible(false);
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->setStyleSheet(
        QStringLiteral(
            "QTableWidget{background:transparent;color:%1;}"
            "QHeaderView::section{color:%2;background:transparent;border:1px solid %3;font-weight:600;}")
            .arg(ksword_theme::textPrimaryHex())
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::borderHex()));
    table_->setColumnWidth(kColumnMajor, 82);
    table_->setColumnWidth(kColumnSymbol, 230);
    table_->setColumnWidth(kColumnCurrent, 185);
    table_->setColumnWidth(kColumnOwner, 180);
    table_->setColumnWidth(kColumnTransaction, 135);
    table_->setColumnWidth(kColumnOriginal, 185);
    rootLayout->addWidget(table_, 1);

    auto* actionLayout = new QGridLayout();
    auto* desiredLabel = new QLabel(
        kernelText(
            "kernel.driver_dispatch.desired.label",
            QStringLiteral("目标指针（支持 0、十进制或 0x 十六进制）：")),
        this);
    desiredAddressEdit_ = new QLineEdit(this);
    desiredAddressEdit_->setPlaceholderText(QStringLiteral("0xFFFFF80000000000"));
    applyButton_ = new QPushButton(
        kernelText("kernel.driver_dispatch.apply", QStringLiteral("原子应用")),
        this);
    restoreButton_ = new QPushButton(
        kernelText("kernel.driver_dispatch.restore", QStringLiteral("按记录恢复")),
        this);
    abandonButton_ = new QPushButton(
        kernelText("kernel.driver_dispatch.abandon", QStringLiteral("放弃恢复记录")),
        this);
    refreshButton_->setToolTip(
        kernelText(
            "kernel.driver_dispatch.refresh.tooltip",
            QStringLiteral("重新读取该驱动对象当前的各个处理函数入口")));
    querySlotButton_->setToolTip(
        kernelText(
            "kernel.driver_dispatch.query_slot.tooltip",
            QStringLiteral("查看选中项的历史修改记录与当前事务状态")));
    applyButton_->setToolTip(
        kernelText(
            "kernel.driver_dispatch.apply.tooltip",
            QStringLiteral("把上面填写的地址一次性写入选中项（会改变驱动的处理流程，可能导致系统不稳定或蓝屏）")));
    restoreButton_->setToolTip(
        kernelText(
            "kernel.driver_dispatch.restore.tooltip",
            QStringLiteral("按之前保存的记录把该项恢复为原始入口")));
    abandonButton_->setToolTip(
        kernelText(
            "kernel.driver_dispatch.abandon.tooltip",
            QStringLiteral("丢弃保存的恢复记录；丢弃后将无法再自动还原该项")));
    for (QPushButton* button : { applyButton_, restoreButton_, abandonButton_ })
    {
        button->setStyleSheet(ksword_theme::themedButtonStyle());
    }
    actionLayout->addWidget(desiredLabel, 0, 0);
    actionLayout->addWidget(desiredAddressEdit_, 0, 1);
    actionLayout->addWidget(applyButton_, 0, 2);
    actionLayout->addWidget(restoreButton_, 0, 3);
    actionLayout->addWidget(abandonButton_, 0, 4);
    actionLayout->setColumnStretch(1, 1);
    rootLayout->addLayout(actionLayout);

    statusLabel_ = new QLabel(
        kernelText("kernel.driver_dispatch.status.waiting", QStringLiteral("状态：等待查询")),
        this);
    statusLabel_->setWordWrap(true);
    statusLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    rootLayout->addWidget(statusLabel_);

    auto* closeLayout = new QHBoxLayout();
    closeLayout->addStretch(1);
    auto* closeButton = new QPushButton(
        kernelText("kernel.driver_dispatch.close", QStringLiteral("关闭")),
        this);
    closeButton->setStyleSheet(ksword_theme::themedButtonStyle());
    closeLayout->addWidget(closeButton);
    rootLayout->addLayout(closeLayout);

    connect(closeButton, &QPushButton::clicked, this, &QDialog::accept);
    connect(refreshButton_, &QPushButton::clicked, this, [this]() {
        refreshDriverSnapshot();
    });
    connect(querySlotButton_, &QPushButton::clicked, this, [this]() {
        refreshSelectedTransaction();
    });
    connect(applyButton_, &QPushButton::clicked, this, [this]() {
        applySelectedDispatch();
    });
    connect(restoreButton_, &QPushButton::clicked, this, [this]() {
        restoreSelectedDispatch();
    });
    connect(abandonButton_, &QPushButton::clicked, this, [this]() {
        abandonSelectedRecord();
    });
    connect(table_, &QTableWidget::itemSelectionChanged, this, [this]() {
        const int kRow = selectedRow();
        if (kRow >= 0)
        {
            const QTableWidgetItem* currentItem = table_->item(kRow, kColumnCurrent);
            desiredAddressEdit_->setText(currentItem != nullptr
                ? currentItem->text()
                : QString());
            refreshSelectedTransaction();
        }
    });
    setActionsEnabled(false);
}

void KernelDriverDispatchEditorDialog::refreshDriverSnapshot()
{
    setActionsEnabled(false);
    setStatus(
        kernelText("kernel.driver_dispatch.status.querying", QStringLiteral("状态：正在查询 DriverObject...")),
        ksword_theme::kPrimaryBlueHex);

    const ksword::ark::DriverClient kClient;
    const auto kResult = kClient.queryDriverObject(requestedDriverName_.toStdWString());
    if (!kResult.io.ok)
    {
        setStatus(
            kernelText(
                "kernel.driver_dispatch.status.driver_query_failed",
                QStringLiteral("状态：DriverObject 查询失败：%1"))
                .arg(ioMessageText(kResult.io.message)),
            ksword_theme::errorHex());
        return;
    }
    if (kResult.lastStatus < 0 || kResult.driverObjectAddress == 0U || kResult.driverStart == 0U)
    {
        setStatus(
            kernelText(
                "kernel.driver_dispatch.status.driver_unavailable",
                QStringLiteral("状态：R0 未返回可编辑身份，NTSTATUS=%1"))
                .arg(ntStatusText(kResult.lastStatus)),
            ksword_theme::errorHex());
        return;
    }

    canonicalDriverName_ = kResult.driverName.empty()
        ? requestedDriverName_
        : QString::fromStdWString(kResult.driverName);
    moduleBase_ = kResult.driverStart;
    driverObjectAddress_ = kResult.driverObjectAddress;
    identityLabel_->setText(
        kernelText(
            "kernel.driver_dispatch.identity",
            QStringLiteral("对象：%1    DriverObject=%2    ImageBase=%3"))
            .arg(
                canonicalDriverName_,
                pointerText(driverObjectAddress_),
                pointerText(moduleBase_)));

    {
        const QSignalBlocker kBlocker(table_);
        const std::uint32_t kPreviousMajor = selectedMajorFunction();
        table_->setRowCount(0);
        for (const auto& entry : kResult.majorFunctions)
        {
            const int kRow = table_->rowCount();
            table_->insertRow(kRow);
            auto* majorItem = readOnlyItem(
                QStringLiteral("0x%1").arg(entry.majorFunction, 2, 16, QChar('0')).toUpper());
            majorItem->setData(Qt::UserRole, entry.majorFunction);
            table_->setItem(kRow, kColumnMajor, majorItem);
            table_->setItem(kRow, kColumnSymbol, readOnlyItem(majorFunctionName(entry.majorFunction)));
            table_->setItem(kRow, kColumnCurrent, readOnlyItem(pointerText(entry.dispatchAddress)));
            table_->setItem(kRow, kColumnOwner, readOnlyItem(
                entry.moduleName.empty()
                    ? pointerText(entry.moduleBase)
                    : QString::fromStdWString(entry.moduleName)));
            table_->setItem(kRow, kColumnTransaction, readOnlyItem(
                kernelText("kernel.driver_dispatch.state.unqueried", QStringLiteral("未查询"))));
            table_->setItem(kRow, kColumnOriginal, readOnlyItem(QStringLiteral("-")));
            table_->setItem(kRow, kColumnApplied, readOnlyItem(QStringLiteral("-")));
        }

        int selectRow = 0;
        for (int row = 0; row < table_->rowCount(); ++row)
        {
            const QTableWidgetItem* item = table_->item(row, kColumnMajor);
            if (item != nullptr && item->data(Qt::UserRole).toUInt() == kPreviousMajor)
            {
                selectRow = row;
                break;
            }
        }
        if (table_->rowCount() > 0)
        {
            table_->selectRow(selectRow);
        }
    }
    setActionsEnabled(table_->rowCount() > 0);
    setStatus(
        kernelText(
            "kernel.driver_dispatch.status.driver_ready",
            QStringLiteral("状态：已读取 %1 个 MajorFunction 槽；请选择槽位查询事务状态。"))
            .arg(table_->rowCount()),
        ksword_theme::successHex());
    if (table_->rowCount() > 0)
    {
        (void)refreshSelectedTransaction();
    }
}

bool KernelDriverDispatchEditorDialog::refreshSelectedTransaction()
{
    const int kRow = selectedRow();
    if (kRow < 0 || moduleBase_ == 0U || driverObjectAddress_ == 0U)
    {
        return false;
    }

    const std::uint32_t kMajor = selectedMajorFunction();
    const ksword::ark::DriverClient kClient;
    const auto kResult = kClient.queryDriverDispatch(
        moduleBase_,
        canonicalDriverName_.toStdWString(),
        kMajor,
        driverObjectAddress_);
    if (!kResult.io.ok)
    {
        setStatus(
            kernelText(
                "kernel.driver_dispatch.status.slot_query_failed",
                QStringLiteral("状态：槽位事务查询失败：%1"))
                .arg(ioMessageText(kResult.io.message)),
            ksword_theme::errorHex());
        return false;
    }

    currentDispatchAddress_ = kResult.currentDispatchAddress;
    generation_ = kResult.generation;
    responseFlags_ = kResult.responseFlags;
    table_->setItem(kRow, kColumnCurrent, readOnlyItem(pointerText(kResult.currentDispatchAddress)));
    table_->setItem(kRow, kColumnOriginal, readOnlyItem(
        (kResult.responseFlags & KSWORD_ARK_DRIVER_DISPATCH_RESPONSE_FLAG_RECORD_PRESENT) != 0U
            ? pointerText(kResult.originalDispatchAddress)
            : QStringLiteral("-")));
    table_->setItem(kRow, kColumnApplied, readOnlyItem(
        (kResult.responseFlags & KSWORD_ARK_DRIVER_DISPATCH_RESPONSE_FLAG_RECORD_PRESENT) != 0U
            ? pointerText(kResult.appliedDispatchAddress)
            : QStringLiteral("-")));

    QString stateText;
    if (kResult.state == KSWORD_ARK_DRIVER_DISPATCH_STATE_CONFLICT)
    {
        stateText = kernelText("kernel.driver_dispatch.state.conflict", QStringLiteral("外部冲突"));
    }
    else if (kResult.state == KSWORD_ARK_DRIVER_DISPATCH_STATE_ACTIVE)
    {
        stateText = kernelText("kernel.driver_dispatch.state.active", QStringLiteral("已接管"));
    }
    else
    {
        stateText = kernelText("kernel.driver_dispatch.state.inactive", QStringLiteral("无活动修改"));
    }
    table_->setItem(kRow, kColumnTransaction, readOnlyItem(stateText));
    desiredAddressEdit_->setText(pointerText(kResult.currentDispatchAddress));
    setStatus(
        kernelText(
            "kernel.driver_dispatch.status.slot_ready",
            QStringLiteral("状态：Major=0x%1，%2，generation=%3，NTSTATUS=%4"))
            .arg(kMajor, 2, 16, QChar('0'))
            .arg(stateText)
            .arg(kResult.generation)
            .arg(ntStatusText(kResult.lastStatus)),
        kResult.lastStatus < 0 ? ksword_theme::errorHex() : ksword_theme::successHex());
    const bool kQuerySucceeded = kResult.lastStatus >= 0;
    const bool kRecordPresent =
        (kResult.responseFlags &
            KSWORD_ARK_DRIVER_DISPATCH_RESPONSE_FLAG_RECORD_PRESENT) != 0U;
    querySlotButton_->setEnabled(true);
    desiredAddressEdit_->setEnabled(kQuerySucceeded);
    applyButton_->setEnabled(kQuerySucceeded);
    restoreButton_->setEnabled(kQuerySucceeded && kRecordPresent);
    abandonButton_->setEnabled(kQuerySucceeded && kRecordPresent);
    return kQuerySucceeded;
}

void KernelDriverDispatchEditorDialog::applySelectedDispatch()
{
    std::uint64_t desiredAddress = 0;
    const std::uint32_t kMajor = selectedMajorFunction();
    if (selectedRow() < 0 || !parsePointer(desiredAddressEdit_->text(), desiredAddress))
    {
        QMessageBox::warning(
            this,
            windowTitle(),
            kernelText(
                "kernel.driver_dispatch.invalid_pointer",
                QStringLiteral("目标指针格式无效。允许值包括 0、十进制和 0x 十六进制。")));
        return;
    }

    if (!refreshSelectedTransaction())
    {
        return;
    }
    const bool kSelfControlChannel =
        (responseFlags_ &
            KSWORD_ARK_DRIVER_DISPATCH_RESPONSE_FLAG_SELF_CONTROL_CHANNEL) != 0U;
    QString warningText = kernelText(
        "kernel.driver_dispatch.apply.warning",
        QStringLiteral("即将把 %1 的 %2 从 %3 原子替换为 %4。\n\nR0 不会检查目标地址是否映射、可执行、ABI 匹配或属于目标驱动。目标下一次收到该 IRP 时可能立即蓝屏或损坏数据。是否继续？"))
        .arg(
            canonicalDriverName_,
            majorFunctionName(kMajor),
            pointerText(currentDispatchAddress_),
            pointerText(desiredAddress));
    if (kSelfControlChannel)
    {
        warningText += kernelText(
            "kernel.driver_dispatch.apply.self_channel_warning",
            QStringLiteral(
                "\n\n这是 KSword 自身 IRP_MJ_DEVICE_CONTROL：写入成功后当前程序通常无法再发送查询、恢复或放弃请求，只能依赖外部恢复或重新加载驱动。"));
    }
    if (QMessageBox::warning(
        this,
        windowTitle(),
        warningText,
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No) != QMessageBox::Yes)
    {
        return;
    }

    const ksword::ark::DriverClient kClient;
    const auto kResult = kClient.applyDriverDispatch(
        moduleBase_,
        canonicalDriverName_.toStdWString(),
        kMajor,
        driverObjectAddress_,
        currentDispatchAddress_,
        desiredAddress,
        generation_);
    if (!kResult.io.ok)
    {
        setStatus(ioMessageText(kResult.io.message), ksword_theme::errorHex());
        return;
    }
    const QString kResultText = kernelText(
        "kernel.driver_dispatch.status.apply_result",
        QStringLiteral("状态：应用完成，NTSTATUS=%1；current=%2；generation=%3"))
        .arg(ntStatusText(kResult.lastStatus))
        .arg(pointerText(kResult.currentDispatchAddress))
        .arg(kResult.generation);
    if (!kSelfControlChannel && kResult.lastStatus >= 0)
    {
        refreshDriverSnapshot();
    }
    setStatus(
        kResultText,
        kResult.lastStatus >= 0
            ? ksword_theme::warningHex()
            : ksword_theme::errorHex());
}

void KernelDriverDispatchEditorDialog::restoreSelectedDispatch()
{
    if (selectedRow() < 0)
    {
        return;
    }
    if (!refreshSelectedTransaction())
    {
        return;
    }
    const ksword::ark::DriverClient kClient;
    const auto kResult = kClient.restoreDriverDispatch(
        moduleBase_,
        canonicalDriverName_.toStdWString(),
        selectedMajorFunction(),
        driverObjectAddress_,
        generation_);
    if (!kResult.io.ok)
    {
        setStatus(ioMessageText(kResult.io.message), ksword_theme::errorHex());
        return;
    }
    const QString kResultText = kernelText(
        "kernel.driver_dispatch.status.restore_result",
        QStringLiteral("状态：恢复请求完成，NTSTATUS=%1；current=%2；generation=%3"))
        .arg(ntStatusText(kResult.lastStatus))
        .arg(pointerText(kResult.currentDispatchAddress))
        .arg(kResult.generation);
    if (kResult.lastStatus >= 0)
    {
        refreshDriverSnapshot();
    }
    setStatus(
        kResultText,
        kResult.lastStatus >= 0
            ? ksword_theme::successHex()
            : ksword_theme::errorHex());
}

void KernelDriverDispatchEditorDialog::abandonSelectedRecord()
{
    if (selectedRow() < 0)
    {
        return;
    }
    if (!refreshSelectedTransaction())
    {
        return;
    }
    if (QMessageBox::warning(
        this,
        windowTitle(),
        kernelText(
            "kernel.driver_dispatch.abandon.warning",
            QStringLiteral("放弃记录不会修改当前 MajorFunction 指针，但会永久丢弃 KSword 保存的原值和自动恢复资格。仅在外部冲突已由你人工处理，或你明确希望保留当前指针时使用。")),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No) != QMessageBox::Yes)
    {
        return;
    }
    const ksword::ark::DriverClient kClient;
    const auto kResult = kClient.abandonDriverDispatch(
        moduleBase_,
        canonicalDriverName_.toStdWString(),
        selectedMajorFunction(),
        driverObjectAddress_,
        generation_);
    if (!kResult.io.ok)
    {
        setStatus(ioMessageText(kResult.io.message), ksword_theme::errorHex());
        return;
    }
    const QString kResultText = kernelText(
        "kernel.driver_dispatch.status.abandon_result",
        QStringLiteral("状态：放弃记录完成，NTSTATUS=%1；当前指针保持 %2"))
        .arg(ntStatusText(kResult.lastStatus))
        .arg(pointerText(kResult.currentDispatchAddress));
    if (kResult.lastStatus >= 0)
    {
        refreshDriverSnapshot();
    }
    setStatus(
        kResultText,
        kResult.lastStatus >= 0
            ? ksword_theme::warningHex()
            : ksword_theme::errorHex());
}

void KernelDriverDispatchEditorDialog::setActionsEnabled(const bool enabled)
{
    querySlotButton_->setEnabled(enabled);
    applyButton_->setEnabled(enabled);
    restoreButton_->setEnabled(enabled);
    abandonButton_->setEnabled(enabled);
    desiredAddressEdit_->setEnabled(enabled);
}

void KernelDriverDispatchEditorDialog::setStatus(
    const QString& text,
    const QString& colorHex)
{
    statusLabel_->setText(text);
    statusLabel_->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;").arg(colorHex));
}

int KernelDriverDispatchEditorDialog::selectedRow() const
{
    return table_ != nullptr ? table_->currentRow() : -1;
}

std::uint32_t KernelDriverDispatchEditorDialog::selectedMajorFunction() const
{
    const int kRow = selectedRow();
    const QTableWidgetItem* item =
        kRow >= 0 && table_ != nullptr ? table_->item(kRow, kColumnMajor) : nullptr;
    return item != nullptr ? item->data(Qt::UserRole).toUInt() : 0U;
}

QString KernelDriverDispatchEditorDialog::pointerText(const std::uint64_t address)
{
    return QStringLiteral("0x%1")
        .arg(static_cast<qulonglong>(address), 16, 16, QChar('0'))
        .toUpper();
}

QString KernelDriverDispatchEditorDialog::ntStatusText(const long status)
{
    return QStringLiteral("0x%1")
        .arg(static_cast<qulonglong>(static_cast<std::uint32_t>(status)), 8, 16, QChar('0'))
        .toUpper();
}

QString KernelDriverDispatchEditorDialog::majorFunctionName(
    const std::uint32_t majorFunction)
{
    static const char* const kNames[] = {
        "IRP_MJ_CREATE", "IRP_MJ_CREATE_NAMED_PIPE", "IRP_MJ_CLOSE",
        "IRP_MJ_READ", "IRP_MJ_WRITE", "IRP_MJ_QUERY_INFORMATION",
        "IRP_MJ_SET_INFORMATION", "IRP_MJ_QUERY_EA", "IRP_MJ_SET_EA",
        "IRP_MJ_FLUSH_BUFFERS", "IRP_MJ_QUERY_VOLUME_INFORMATION",
        "IRP_MJ_SET_VOLUME_INFORMATION", "IRP_MJ_DIRECTORY_CONTROL",
        "IRP_MJ_FILE_SYSTEM_CONTROL", "IRP_MJ_DEVICE_CONTROL",
        "IRP_MJ_INTERNAL_DEVICE_CONTROL", "IRP_MJ_SHUTDOWN",
        "IRP_MJ_LOCK_CONTROL", "IRP_MJ_CLEANUP", "IRP_MJ_CREATE_MAILSLOT",
        "IRP_MJ_QUERY_SECURITY", "IRP_MJ_SET_SECURITY", "IRP_MJ_POWER",
        "IRP_MJ_SYSTEM_CONTROL", "IRP_MJ_DEVICE_CHANGE", "IRP_MJ_QUERY_QUOTA",
        "IRP_MJ_SET_QUOTA", "IRP_MJ_PNP"
    };
    return majorFunction < (sizeof(kNames) / sizeof(kNames[0]))
        ? QString::fromLatin1(kNames[majorFunction])
        : QStringLiteral("IRP_MJ_0x%1").arg(majorFunction, 2, 16, QChar('0')).toUpper();
}

bool KernelDriverDispatchEditorDialog::parsePointer(
    const QString& text,
    std::uint64_t& addressOut)
{
    bool ok = false;
    const qulonglong kValue = text.trimmed().toULongLong(&ok, 0);
    if (!ok)
    {
        return false;
    }
    addressOut = static_cast<std::uint64_t>(kValue);
    return true;
}
