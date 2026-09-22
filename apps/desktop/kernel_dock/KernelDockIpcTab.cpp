#include "KernelDockIpcTab.h"
#include "KernelDock.h"
#include "../ui/VisibleTableWidget.h"

// ============================================================
// KernelDockIpcTab.cpp
// Purpose:
// 1) Aggregate read-only pages for NamedPipe, ALPC, and communication object enumeration;
// 2) Query the single port relationship via DriverClient::queryAlpcPort for the ALPC page;
// 3) The NamedPipe and communication object pages reuse existing independent read-only components.
// ============================================================

#include "KernelCommunicationEndpointTab.h"
#include "KernelNamedPipeTab.h"
#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../ui/CodeEditorWidget.h"
#include "../ui/TableInteractionSupport.h"
#include "../Theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMetaObject>
#include <QModelIndex>
#include <QPoint>
#include <QPointer>
#include <QPushButton>
#include <QSize>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

#include <thread>

using ksword::kernel_dock_internal::kernelText;

namespace
{
    enum class AlpcColumn : int
    {
        kRole = 0,
        kRelation,
        kOwnerProcessId,
        kFlags,
        kState,
        kSequenceNo,
        kObjectAddress,
        kPortContext,
        kPortName,
        kStatus,
        kCount
    };

    enum class IpcSummaryColumn : int
    {
        kCategory = 0,
        kStatus,
        kCount,
        kSource,
        kDetail,
        kCountColumn
    };

    QString blueButtonStyle()
    {
        return ksword_theme::themedButtonStyle();
    }

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

    QString headerStyle()
    {
        return QStringLiteral(
            "QHeaderView::section{color:%1;background:transparent;/* %2 */border:1px solid %3;font-weight:600;}")
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::borderHex());
    }

    QString itemSelectionStyle()
    {
        return QString();
    }

    QString statusLabelStyle(const QString& colorHex)
    {
        return QStringLiteral("color:%1;font-weight:600;").arg(colorHex);
    }

    QString safeText(const QString& valueText, const QString& fallbackText)
    {
        return valueText.trimmed().isEmpty() ? fallbackText : valueText;
    }

    QString safeText(const QString& valueText)
    {
        return safeText(valueText, kernelText("kernel.ipc.placeholder.empty", QStringLiteral("<空>")));
    }

    QString formatRelationText(std::uint32_t relation)
    {
        switch (relation)
        {
        case KSWORD_ARK_ALPC_PORT_RELATION_QUERY: return QStringLiteral("Query");
        case KSWORD_ARK_ALPC_PORT_RELATION_CONNECTION: return QStringLiteral("Connection");
        case KSWORD_ARK_ALPC_PORT_RELATION_SERVER: return QStringLiteral("Server");
        case KSWORD_ARK_ALPC_PORT_RELATION_CLIENT: return QStringLiteral("Client");
        default: return QStringLiteral("Relation(%1)").arg(relation);
        }
    }

    QString ipcSummaryStatusText(const unsigned long statusValue)
    {
        // ipcSummaryStatusText：
        // - Purpose: Convert IPC summary protocol status to UI-readable text.
        // - Input: KSWORD_ARK_IPC_SUMMARY_STATUS_* values
        // - Return: Status name; unknown values retain the original numeric value to avoid rendering unknown states as normal.
        switch (statusValue)
        {
        case KSWORD_ARK_IPC_SUMMARY_STATUS_UNAVAILABLE: return QStringLiteral("Unavailable");
        case KSWORD_ARK_IPC_SUMMARY_STATUS_OK: return QStringLiteral("OK");
        case KSWORD_ARK_IPC_SUMMARY_STATUS_PARTIAL: return QStringLiteral("Partial");
        case KSWORD_ARK_IPC_SUMMARY_STATUS_STUB: return kernelText("kernel.ipc.status.legacy_stub", QStringLiteral("LegacyStub（旧驱动占位）"));
        case KSWORD_ARK_IPC_SUMMARY_STATUS_FAILED: return QStringLiteral("Failed");
        default: return QStringLiteral("Status(%1)").arg(statusValue);
        }
    }

    QString stdStringToQString(const std::string& valueText)
    {
        // stdStringToQString：
        // - Purpose: Converts ArkDriverClient's UTF-8/narrow diagnostic strings to QString.
        // - Input: io.message and other std::string values;
        // - Returns: A QString directly usable in QLabel/QTableWidget.
        return QString::fromUtf8(valueText.data(), static_cast<int>(valueText.size()));
    }

    QString friendlyIpcIoMessage(const QString& messageText)
    {
        // friendlyIpcIoMessage：
        // - Purpose: Convert low-level ArkDriverClient/IOCTL messages into user-readable prompts;
        // - Input: Original io.message text;
        // - Returns: Short description suitable for the 'Details' column of the table.
        const QString kTrimmedText = messageText.trimmed();
        if (kTrimmedText.isEmpty())
        {
            return kernelText("kernel.ipc.message.no_driver_message", QStringLiteral("无额外驱动消息。"));
        }
        if (kTrimmedText.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive))
        {
            return kernelText("kernel.ipc.message.device_io_failure", QStringLiteral("驱动接口调用失败或当前驱动版本不支持该 IPC 摘要入口。"));
        }
        if (kTrimmedText.contains(QStringLiteral("unsupported"), Qt::CaseInsensitive) ||
            kTrimmedText.contains(QStringLiteral("not supported"), Qt::CaseInsensitive))
        {
            return kernelText("kernel.ipc.message.unsupported", QStringLiteral("当前驱动不支持该 IPC/ALPC 只读查询入口。"));
        }
        if (kTrimmedText.contains(QStringLiteral("capability"), Qt::CaseInsensitive) ||
            kTrimmedText.contains(QStringLiteral("DynData"), Qt::CaseInsensitive))
        {
            return kernelText("kernel.ipc.message.capability", QStringLiteral("动态偏移能力未满足，IPC/ALPC 详情暂不可用。"));
        }
        if (kTrimmedText.contains(QStringLiteral("version mismatch"), Qt::CaseInsensitive) ||
            kTrimmedText.contains(QStringLiteral("invalid parameter"), Qt::CaseInsensitive))
        {
            // Protocol compatibility notice:
            // - Input: R0/R3 parameters or underlying messages with version mismatch;
            // - Processing: Convert to synchronous shared/driver/client operation suggestions.
            // - Returns: Chinese description suitable for direct display in the details column.
            return kernelText("kernel.ipc.message.protocol_mismatch", QStringLiteral("驱动与主程序版本不兼容，请更新为匹配版本。"));
        }
        if (kTrimmedText.contains(QStringLiteral("buffer"), Qt::CaseInsensitive) ||
            kTrimmedText.contains(QStringLiteral("too small"), Qt::CaseInsensitive) ||
            kTrimmedText.contains(QStringLiteral("trunc"), Qt::CaseInsensitive))
        {
            return kernelText("kernel.ipc.message.incomplete_buffer", QStringLiteral("IPC/ALPC 返回缓冲区不完整，当前只展示已解析到的证据。"));
        }
        if (kTrimmedText.contains(QStringLiteral("access denied"), Qt::CaseInsensitive) ||
            kTrimmedText.contains(QStringLiteral("privilege"), Qt::CaseInsensitive))
        {
            return kernelText("kernel.ipc.message.access_denied", QStringLiteral("权限不足，当前进程无法完成 IPC/ALPC 只读查询。"));
        }
        if (kTrimmedText.contains(QStringLiteral("skipped"), Qt::CaseInsensitive))
        {
            return kernelText("kernel.ipc.message.skipped_incomplete_target", QStringLiteral("未输入完整 PID/Handle，因此只显示全局 IPC 摘要。"));
        }
        return kTrimmedText;
    }

    QString fixedWideText(const wchar_t* buffer, const int maxChars)
    {
        // fixedWideText：
        // - Purpose: Read a fixed-width R0 character array, truncating early upon encountering NUL.
        // - Input: Fixed array pointer and maximum character count;
        // - Returns: A QString without trailing NUL padding.
        if (buffer == nullptr || maxChars <= 0)
        {
            return QString();
        }
        int length = 0;
        while (length < maxChars && buffer[length] != L'\0')
        {
            ++length;
        }
        return QString::fromWCharArray(buffer, length);
    }

    QString buildPortDetail(const QString& roleText, const ksword::ark::AlpcPortInfo& portInfo)
    {
        return QStringLiteral(
            "Role: %1\n"
            "Relation: %2\n"
            "OwnerProcessId: %3\n"
            "Flags: 0x%4\n"
            "State: %5\n"
            "SequenceNo: %6\n"
            "BasicStatus: 0x%7\n"
            "NameStatus: 0x%8\n"
            "ObjectAddress: 0x%9\n"
            "PortContext: 0x%10\n"
            "PortName: %11")
            .arg(roleText)
            .arg(formatRelationText(portInfo.relation))
            .arg(portInfo.ownerProcessId)
            .arg(QStringLiteral("%1").arg(portInfo.flags, 8, 16, QChar('0')).toUpper())
            .arg(portInfo.state)
            .arg(portInfo.sequenceNo)
            .arg(QStringLiteral("%1").arg(static_cast<qulonglong>(portInfo.basicStatus), 8, 16, QChar('0')).toUpper())
            .arg(QStringLiteral("%1").arg(static_cast<qulonglong>(portInfo.nameStatus), 8, 16, QChar('0')).toUpper())
            .arg(QStringLiteral("%1").arg(static_cast<qulonglong>(portInfo.objectAddress), 16, 16, QChar('0')).toUpper())
            .arg(QStringLiteral("%1").arg(static_cast<qulonglong>(portInfo.portContext), 16, 16, QChar('0')).toUpper())
            .arg(safeText(QString::fromWCharArray(portInfo.portName.c_str(), static_cast<int>(portInfo.portName.size()))));
    }
}

KernelDockIpcTab::KernelDockIpcTab(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
    initializeConnections();

    QMetaObject::invokeMethod(this, [this]() {
        refreshAlpcQuery();
    }, Qt::QueuedConnection);
}

void KernelDockIpcTab::initializeUi()
{
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(8, 8, 8, 8);
    rootLayout->setSpacing(6);

    innerTabWidget_ = new QTabWidget(this);
    innerTabWidget_->setIconSize(QSize(16, 16));
    rootLayout->addWidget(innerTabWidget_, 1);

    innerTabWidget_->addTab(
        new KernelNamedPipeTab(innerTabWidget_),
        QIcon(QStringLiteral(":/Icon/process_list.svg")),
        QStringLiteral("NamedPipe"));
    innerTabWidget_->setTabToolTip(0, kernelText("kernel.ipc.tab.named_pipe.tooltip", QStringLiteral("只读 NPFS NamedPipe 目录枚举")));

    initializeAlpcPage();
    innerTabWidget_->addTab(
        alpcPage_,
        QIcon(QStringLiteral(":/Icon/process_details.svg")),
        QStringLiteral("ALPC"));
    innerTabWidget_->setTabToolTip(1, kernelText("kernel.ipc.tab.alpc.tooltip", QStringLiteral("只读 ALPC 端口关系查询")));

    innerTabWidget_->addTab(
        new KernelCommunicationEndpointTab(innerTabWidget_),
        QIcon(QStringLiteral(":/Icon/process_critical.svg")),
        kernelText("kernel.ipc.tab.communication.title", QStringLiteral("通信对象")));
    innerTabWidget_->setTabToolTip(2, kernelText("kernel.ipc.tab.communication.tooltip", QStringLiteral("只读 ALPC/RPC 通信端点聚合")));
}

void KernelDockIpcTab::initializeConnections()
{
    if (alpcRefreshButton_ != nullptr)
    {
        connect(alpcRefreshButton_, &QPushButton::clicked, this, [this]() {
            refreshAlpcQuery();
        });
    }
    if (alpcProcessIdEdit_ != nullptr)
    {
        connect(alpcProcessIdEdit_, &QLineEdit::textChanged, this, [this]() {
            alpcProcessId_ = alpcProcessIdEdit_->text().trimmed().toUInt();
        });
    }
    if (alpcHandleEdit_ != nullptr)
    {
        connect(alpcHandleEdit_, &QLineEdit::textChanged, this, [this]() {
            bool ok = false;
            alpcHandleValue_ = alpcHandleEdit_->text().trimmed().toULongLong(&ok, 16);
            if (!ok)
            {
                alpcHandleValue_ = 0;
            }
        });
    }
}

void KernelDockIpcTab::initializeAlpcPage()
{
    if (alpcPage_ != nullptr)
    {
        return;
    }

    alpcPage_ = new QWidget(innerTabWidget_);
    auto* layout = new QVBoxLayout(alpcPage_);
    layout->setContentsMargins(4, 4, 4, 4);
    layout->setSpacing(6);

    alpcToolbarLayout_ = new QHBoxLayout();
    alpcToolbarLayout_->setContentsMargins(0, 0, 0, 0);
    alpcToolbarLayout_->setSpacing(6);

    alpcRefreshButton_ = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), alpcPage_);
    ksword_theme::applyCompactIconButtonMetrics(alpcRefreshButton_);
    alpcRefreshButton_->setToolTip(kernelText("kernel.ipc.toolbar.refresh.tooltip", QStringLiteral("刷新 ALPC 端口查询")));
    alpcRefreshButton_->setStyleSheet(blueButtonStyle());

    alpcProcessIdEdit_ = new QLineEdit(alpcPage_);
    alpcProcessIdEdit_->setPlaceholderText(QStringLiteral("PID"));
    alpcProcessIdEdit_->setClearButtonEnabled(true);
    alpcProcessIdEdit_->setStyleSheet(blueInputStyle());

    alpcHandleEdit_ = new QLineEdit(alpcPage_);
    alpcHandleEdit_->setPlaceholderText(kernelText("kernel.ipc.toolbar.handle.placeholder", QStringLiteral("句柄值（十六进制）")));
    alpcHandleEdit_->setClearButtonEnabled(true);
    alpcHandleEdit_->setStyleSheet(blueInputStyle());

    alpcStatusLabel_ = new QLabel(kernelText("kernel.ipc.status.waiting", QStringLiteral("状态：等待查询")), alpcPage_);
    alpcStatusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::textSecondaryHex()));

    alpcToolbarLayout_->addWidget(alpcRefreshButton_, 0);
    alpcToolbarLayout_->addWidget(alpcProcessIdEdit_, 0);
    alpcToolbarLayout_->addWidget(alpcHandleEdit_, 1);
    alpcToolbarLayout_->addWidget(alpcStatusLabel_, 0);
    layout->addLayout(alpcToolbarLayout_);

    ipcSummaryTable_ = new ks::ui::VisibleTableWidget(alpcPage_);
    ipcSummaryTable_->setColumnCount(static_cast<int>(IpcSummaryColumn::kCountColumn));
    ipcSummaryTable_->setHorizontalHeaderLabels(QStringList{
        kernelText("kernel.ipc.header.category", QStringLiteral("类别")),
        kernelText("kernel.ipc.header.status", QStringLiteral("状态")),
        QStringLiteral("Count"),
        kernelText("kernel.ipc.header.source", QStringLiteral("来源")),
        kernelText("kernel.ipc.header.detail", QStringLiteral("详情"))
        });
    ipcSummaryTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    ipcSummaryTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    ipcSummaryTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ipcSummaryTable_->setAlternatingRowColors(true);
    ipcSummaryTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    ipcSummaryTable_->setStyleSheet(itemSelectionStyle());
    ipcSummaryTable_->verticalHeader()->setVisible(false);
    ipcSummaryTable_->horizontalHeader()->setStyleSheet(headerStyle());
    ipcSummaryTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    ipcSummaryTable_->horizontalHeader()->setSectionResizeMode(static_cast<int>(IpcSummaryColumn::kDetail), QHeaderView::Stretch);
    ipcSummaryTable_->setToolTip(kernelText("kernel.ipc.summary.tooltip", QStringLiteral("只读查询进程或全局 IPC 摘要；可使用上方 PID/句柄筛选。")));
    layout->addWidget(ipcSummaryTable_, 0);

    alpcTable_ = new ks::ui::VisibleTableWidget(alpcPage_);
    alpcTable_->setColumnCount(static_cast<int>(AlpcColumn::kCount));
    alpcTable_->setHorizontalHeaderLabels(QStringList{
        kernelText("kernel.ipc.header.role", QStringLiteral("角色")),
        QStringLiteral("Relation"),
        QStringLiteral("Owner PID"),
        QStringLiteral("Flags"),
        QStringLiteral("State"),
        QStringLiteral("Seq"),
        QStringLiteral("Object"),
        QStringLiteral("Context"),
        QStringLiteral("Port Name"),
        QStringLiteral("Status")
        });
    alpcTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    alpcTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    alpcTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    alpcTable_->setAlternatingRowColors(true);
    alpcTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    alpcTable_->setStyleSheet(itemSelectionStyle());
    alpcTable_->verticalHeader()->setVisible(false);
    alpcTable_->horizontalHeader()->setStyleSheet(headerStyle());
    alpcTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    alpcTable_->horizontalHeader()->setSectionResizeMode(static_cast<int>(AlpcColumn::kPortName), QHeaderView::Stretch);
    alpcTable_->horizontalHeader()->setSectionResizeMode(static_cast<int>(AlpcColumn::kStatus), QHeaderView::Stretch);
    layout->addWidget(alpcTable_, 1);

    alpcDetailEditor_ = new CodeEditorWidget(alpcPage_);
    alpcDetailEditor_->setReadOnly(true);
    alpcDetailEditor_->setText(kernelText("kernel.ipc.detail.initial", QStringLiteral("输入 PID + ALPC 句柄后查询，或刷新后查看结果。")));
    layout->addWidget(alpcDetailEditor_, 1);

    connect(alpcTable_, &QTableWidget::currentCellChanged, this, [this](const int currentRow, int, int, int) {
        // ALPC row selection:
        // - Input: Current ALPC table row index;
        // - Processing: Refresh only the detail text; do not re-query or rebuild the table.
        // - Return: None. Prevents the selected row from triggering recursive repainting.
        updateAlpcDetailForRow(currentRow);
    });
    connect(ipcSummaryTable_, &QTableWidget::currentCellChanged, this, [this](const int currentRow, int, int, int) {
        // IPC summary row selection:
        // - Input: Current table row index; column index is not used for business logic.
        // - Processing: Expand fixed summary responses into detailed text.
        // - Return: None. The detail area is read-only display and triggers no R0 calls.
        updateIpcSummaryDetailForRow(currentRow);
    });
    connect(ipcSummaryTable_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& localPosition) {
        // Right-click menu:
        // - Input: User click position in the IPC summary table;
        // - Processing: Locate the current row and copy TSV.
        // - Return: None. The menu is read-only and triggers no IPC modification actions.
        const QModelIndex kClickedIndex = ipcSummaryTable_->indexAt(localPosition);
        if (kClickedIndex.isValid())
        {
            ipcSummaryTable_->setCurrentCell(kClickedIndex.row(), kClickedIndex.column());
            ipcSummaryTable_->selectRow(kClickedIndex.row());
        }
        QMenu menu(this);
        menu.setStyleSheet(ksword_theme::contextMenuStyle());
        QAction* copyRowAction = menu.addAction(kernelText("kernel.ipc.menu.copy_row", QStringLiteral("复制当前行")));
        copyRowAction->setEnabled(ipcSummaryTable_->currentRow() >= 0);
        if (menu.exec(ipcSummaryTable_->viewport()->mapToGlobal(localPosition)) == copyRowAction)
        {
            copyIpcSummaryCurrentRow();
        }
    });
    connect(alpcTable_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& localPosition) {
        const QModelIndex kClickedIndex = alpcTable_->indexAt(localPosition);
        if (kClickedIndex.isValid())
        {
            alpcTable_->setCurrentCell(kClickedIndex.row(), kClickedIndex.column());
            alpcTable_->selectRow(kClickedIndex.row());
        }
        QMenu menu(this);
        menu.setStyleSheet(ksword_theme::contextMenuStyle());
        QAction* copyRowAction = menu.addAction(kernelText("kernel.ipc.menu.copy_row", QStringLiteral("复制当前行")));
        copyRowAction->setEnabled(alpcTable_->currentRow() >= 0);
        const QTableWidgetItem* ownerProcessIdItem = alpcTable_->currentRow() >= 0
            ? alpcTable_->item(alpcTable_->currentRow(), static_cast<int>(AlpcColumn::kOwnerProcessId))
            : nullptr;
        bool processIdOk = false;
        const quint32 kProcessId = ownerProcessIdItem != nullptr
            ? ownerProcessIdItem->text().trimmed().toUInt(&processIdOk, 10)
            : 0U;
        QAction* openProcessAction = menu.addAction(
            QIcon(QStringLiteral(":/Icon/process_details.svg")),
            QStringLiteral("转到进程详细信息"));
        openProcessAction->setEnabled(processIdOk && kProcessId != 0U);
        QAction* selectedAction = menu.exec(alpcTable_->viewport()->mapToGlobal(localPosition));
        if (selectedAction == copyRowAction)
        {
            copyAlpcCurrentRow();
        }
        else if (selectedAction == openProcessAction)
        {
            ks::ui::openProcessDetailByPid(kProcessId);
        }
    });
}

void KernelDockIpcTab::refreshAlpcQuery()
{
    if (alpcRefreshButton_ == nullptr || alpcPage_ == nullptr)
    {
        return;
    }

    alpcRefreshButton_->setEnabled(false);
    alpcStatusLabel_->setText(kernelText("kernel.ipc.status.querying", QStringLiteral("状态：查询中...")));
    alpcStatusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::kPrimaryBlueHex));

    const std::uint32_t kPid = alpcProcessIdEdit_ != nullptr ? alpcProcessIdEdit_->text().trimmed().toUInt() : 0U;
    const QString kHandleText = alpcHandleEdit_ != nullptr ? alpcHandleEdit_->text().trimmed() : QString();
    bool ok = false;
    const std::uint64_t kHandleValue = kHandleText.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive)
        ? kHandleText.mid(2).toULongLong(&ok, 16)
        : kHandleText.toULongLong(&ok, 16);
    const bool kHasAlpcTarget = ok && kPid != 0U && kHandleValue != 0ULL;
    if (!kHasAlpcTarget)
    {
        alpcStatusLabel_->setText(kernelText("kernel.ipc.status.global_query", QStringLiteral("状态：查询全局 R0 IPC summary；ALPC 详情需输入 PID 与十六进制句柄")));
        alpcStatusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::warningHex()));
    }

    QPointer<KernelDockIpcTab> guardThis(this);
    std::thread([guardThis, kPid, kHandleValue, kHasAlpcTarget]() {
        const ksword::ark::DriverClient kClient;
        const std::uint32_t kSummaryPid = kHasAlpcTarget ? kPid : 0U;
        const std::uint64_t kSummaryHandle = kHasAlpcTarget ? kHandleValue : 0ULL;
        const ksword::ark::IpcSummaryAuditResult kSummaryResult = kClient.queryIpcSummary(kSummaryPid, kSummaryHandle);
        ksword::ark::AlpcPortQueryResult alpcResult{};
        if (kHasAlpcTarget)
        {
            alpcResult = kClient.queryAlpcPort(kPid, kHandleValue);
        }
        else
        {
            alpcResult.io.ok = false;
            alpcResult.io.message = "ALPC detail skipped because PID/handle input is incomplete; IPC summary used global defaults.";
        }
        KernelDockIpcTab* const kContextObject = guardThis.data();
        if (kContextObject == nullptr)
        {
            return;
        }

        QMetaObject::invokeMethod(kContextObject, [guardThis, kSummaryResult, alpcResult, kHasAlpcTarget]() mutable {
            if (guardThis == nullptr)
            {
                return;
            }

            if (ks::ui::deferTableUiCommitIfContextMenuOpen(
                guardThis.data(),
                QStringLiteral("kernel-ipc-alpc-snapshot"),
                { guardThis->ipcSummaryTable_, guardThis->alpcTable_ },
                [guardThis, kSummaryResult, alpcResult, kHasAlpcTarget]() mutable
                {
                    if (guardThis.isNull())
                    {
                        return;
                    }

                    guardThis->lastIpcSummaryResult_ = kSummaryResult;
                    guardThis->lastAlpcResult_ = alpcResult;
                    guardThis->alpcRefreshButton_->setEnabled(true);
                    guardThis->applyIpcSummaryResult();
                    guardThis->applyAlpcQueryResult();
                    if (!kHasAlpcTarget)
                    {
                        guardThis->alpcStatusLabel_->setText(kernelText(
                            "kernel.ipc.status.global_refreshed",
                            QStringLiteral("状态：已刷新 R0 IPC summary；ALPC 详情等待 PID/Handle")));
                        guardThis->alpcStatusLabel_->setStyleSheet(
                            statusLabelStyle(ksword_theme::warningHex()));
                    }
                }))
            {
                return;
            }

            guardThis->lastIpcSummaryResult_ = kSummaryResult;
            guardThis->lastAlpcResult_ = alpcResult;
            guardThis->alpcRefreshButton_->setEnabled(true);
            guardThis->applyIpcSummaryResult();
            guardThis->applyAlpcQueryResult();
            if (!kHasAlpcTarget)
            {
                guardThis->alpcStatusLabel_->setText(kernelText("kernel.ipc.status.global_refreshed", QStringLiteral("状态：已刷新 R0 IPC summary；ALPC 详情等待 PID/Handle")));
                guardThis->alpcStatusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::warningHex()));
            }
        }, Qt::QueuedConnection);
    }).detach();
}

void KernelDockIpcTab::applyIpcSummaryResult()
{
    // applyIpcSummaryResult：
    // - Purpose: Append the fixed response from ArkDriverClient::queryIpcSummary to the ALPC/IPC page;
    // - Input: Member m_lastIpcSummaryResult, sourced from a background thread;
    // - Output: Updates m_ipcSummaryTable; no return value, does not directly access DeviceIoControl.
    if (ipcSummaryTable_ == nullptr)
    {
        return;
    }

    auto setSummaryItem = [this](const int rowIndex, const IpcSummaryColumn column, const QString& valueText) {
        // setSummaryItem：
        // - Purpose: Write to the IPC summary table cell.
        // - Input: Row index, column enum, and value;
        // - Output: The table item is owned by m_ipcSummaryTable.
        auto* item = new QTableWidgetItem(valueText);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        ipcSummaryTable_->setItem(rowIndex, static_cast<int>(column), item);
    };

    auto appendSummaryRow = [&](const QString& categoryText, const QString& statusTextValue, const QString& countText, const QString& sourceText, const QString& detailText) {
        // appendSummaryRow：
        // - Purpose: Append a row for the R0 IPC summary.
        // - Input: category, status, count, source, and details;
        // - Output: Adds a row to the table; no return value.
        const int kRowIndex = ipcSummaryTable_->rowCount();
        ipcSummaryTable_->insertRow(kRowIndex);
        setSummaryItem(kRowIndex, IpcSummaryColumn::kCategory, categoryText);
        setSummaryItem(kRowIndex, IpcSummaryColumn::kStatus, statusTextValue);
        setSummaryItem(kRowIndex, IpcSummaryColumn::kCount, countText);
        setSummaryItem(kRowIndex, IpcSummaryColumn::kSource, sourceText);
        setSummaryItem(kRowIndex, IpcSummaryColumn::kDetail, detailText);
    };

    ipcSummaryTable_->setSortingEnabled(false);
    ipcSummaryTable_->setRowCount(0);

    const QString kIoMessage = stdStringToQString(lastIpcSummaryResult_.io.message);
    const QString kReadableIoMessage = friendlyIpcIoMessage(kIoMessage);
    if (!lastIpcSummaryResult_.io.ok)
    {
        appendSummaryRow(
            QStringLiteral("R0 IPC Summary"),
            lastIpcSummaryResult_.unsupported ? QStringLiteral("Unsupported") : QStringLiteral("Unavailable"),
            QStringLiteral("N/A"),
            QStringLiteral("驱动查询"),
            kernelText("kernel.ipc.summary.error_detail", QStringLiteral("IPC 摘要暂不可用。Win32=%1；驱动返回字节=%2；%3"))
                .arg(lastIpcSummaryResult_.io.win32Error)
                .arg(lastIpcSummaryResult_.io.bytesReturned)
                .arg(kReadableIoMessage));
        ipcSummaryTable_->setSortingEnabled(true);
        if (ipcSummaryTable_->rowCount() > 0)
        {
            ipcSummaryTable_->setCurrentCell(0, 0);
            updateIpcSummaryDetailForRow(0);
        }
        return;
    }

    const auto& response = lastIpcSummaryResult_.response;
    const QString kCountUnavailableText = kernelText("kernel.ipc.summary.count_unavailable", QStringLiteral("未提供"));
    const QString kCommonSourceText = QStringLiteral("内核查询 PID=%1 Handle=%2")
        .arg(response.processId)
        .arg(formatHex64(response.handleValue));
    const QString kResponseDetailText = safeText(
        fixedWideText(response.detail, KSWORD_ARK_KERNEL_OBJECT_DETAIL_CHARS),
        kernelText("kernel.ipc.summary.object_detail_unavailable", QStringLiteral("驱动未提供额外对象详情")));
    const QString kCommonDetailText = kernelText("kernel.ipc.summary.common_detail", QStringLiteral(
        "IPC 摘要状态：%1；字段覆盖：%2；最近状态：%3；驱动返回字节：%4；%5；对象说明：%6")
        .arg(ipcSummaryStatusText(response.status))
        .arg(formatHex32(response.fieldFlags))
        .arg(statusText(response.lastStatus))
        .arg(lastIpcSummaryResult_.io.bytesReturned)
        .arg(kReadableIoMessage)
        .arg(kResponseDetailText));

    appendSummaryRow(
        QStringLiteral("ALPC"),
        ipcSummaryStatusText(response.alpcStatus),
        kCountUnavailableText,
        kCommonSourceText,
        kernelText("kernel.ipc.summary.alpc_detail", QStringLiteral("ALPC 对象地址：%1；对象类型：%2；DynData 能力：%3；%4"))
            .arg(formatHex64(response.alpcObjectAddress))
            .arg(safeText(fixedWideText(response.alpcTypeName, KSWORD_ARK_KERNEL_OBJECT_TYPE_NAME_CHARS)))
            .arg(formatHex64(response.dynDataCapabilityMask))
            .arg(kCommonDetailText));
    appendSummaryRow(
        QStringLiteral("NamedPipe"),
        ipcSummaryStatusText(response.namedPipeStatus),
        kCountUnavailableText,
        kCommonSourceText,
        kCommonDetailText);
    appendSummaryRow(
        QStringLiteral("Mailslot"),
        ipcSummaryStatusText(response.mailslotStatus),
        kCountUnavailableText,
        kCommonSourceText,
        kCommonDetailText);
    appendSummaryRow(
        QStringLiteral("SMB/IPC"),
        kernelText("kernel.ipc.summary.smb_hint_title", QStringLiteral("提示")),
        QStringLiteral("N/A"),
        QStringLiteral("功能限制"),
        kernelText("kernel.ipc.summary.smb_hint", QStringLiteral("当前版本未提供 SMB 命名管道或 IPC$ 的归因详情。")));
    appendSummaryRow(
        QStringLiteral("Transport"),
        QStringLiteral("OK"),
        kernelText("kernel.ipc.summary.transport_count", QStringLiteral("已返回")),
        QStringLiteral("内核驱动"),
        kernelText("kernel.ipc.summary.transport_detail", QStringLiteral("驱动 IPC 摘要调用成功；返回字节=%1；%2"))
            .arg(lastIpcSummaryResult_.io.bytesReturned)
            .arg(kReadableIoMessage));

    ipcSummaryTable_->setSortingEnabled(true);
    if (ipcSummaryTable_->rowCount() > 0)
    {
        const int kTargetRow = ipcSummaryTable_->currentRow() >= 0 ? ipcSummaryTable_->currentRow() : 0;
        ipcSummaryTable_->setCurrentCell(kTargetRow, 0);
        updateIpcSummaryDetailForRow(kTargetRow);
    }
}

void KernelDockIpcTab::applyAlpcQueryResult()
{
    if (alpcTable_ == nullptr || alpcDetailEditor_ == nullptr)
    {
        return;
    }

    alpcTable_->setSortingEnabled(false);
    alpcTable_->setRowCount(0);

    if (!lastAlpcResult_.io.ok)
    {
        const QString kAlpcMessage = stdStringToQString(lastAlpcResult_.io.message);
        const QString kReadableAlpcMessage = friendlyIpcIoMessage(kAlpcMessage);
        const bool kSkippedByInput = kAlpcMessage.contains(QStringLiteral("skipped"), Qt::CaseInsensitive);

        auto setDiagnosticItem = [this](const AlpcColumn column, const QString& valueText) {
            // setDiagnosticItem：
            // - Input: ALPC table column enumeration and diagnostic text.
            // - Processing: Write a single read-only placeholder cell;
            // - Return: None. The cell's lifetime is managed by QTableWidget.
            auto* item = new QTableWidgetItem(valueText);
            item->setFlags(item->flags() & ~Qt::ItemIsEditable);
            alpcTable_->setItem(0, static_cast<int>(column), item);
        };

        // ALPC diagnostic row:
        // - Input: Reason for ALPC query failure or skip.
        // - Processing: Keep one row of copyable table evidence to avoid the IPC page having a completely empty table.
        // - Return: No return value; details area still displays summary/error text.
        alpcTable_->setRowCount(1);
        setDiagnosticItem(AlpcColumn::kRole, kSkippedByInput
            ? kernelText("kernel.ipc.alpc.diagnostic.not_requested", QStringLiteral("ALPC 未请求"))
            : kernelText("kernel.ipc.alpc.diagnostic.query_failed", QStringLiteral("ALPC 查询失败")));
        setDiagnosticItem(AlpcColumn::kRelation, QStringLiteral("Diagnostic"));
        setDiagnosticItem(AlpcColumn::kOwnerProcessId, alpcProcessIdEdit_ != nullptr
            ? safeText(alpcProcessIdEdit_->text().trimmed(), kernelText("kernel.ipc.alpc.placeholder.pid", QStringLiteral("<未输入>")))
            : kernelText("kernel.ipc.alpc.placeholder.unknown", QStringLiteral("<未知>")));
        setDiagnosticItem(AlpcColumn::kFlags, QStringLiteral("-"));
        setDiagnosticItem(AlpcColumn::kState, QStringLiteral("-"));
        setDiagnosticItem(AlpcColumn::kSequenceNo, QStringLiteral("-"));
        setDiagnosticItem(AlpcColumn::kObjectAddress, QStringLiteral("0x0000000000000000"));
        setDiagnosticItem(AlpcColumn::kPortContext, QStringLiteral("0x0000000000000000"));
        setDiagnosticItem(AlpcColumn::kPortName, kSkippedByInput
            ? kernelText("kernel.ipc.alpc.diagnostic.handle_hint", QStringLiteral("请输入 PID + 十六进制 ALPC 句柄"))
            : kernelText("kernel.ipc.alpc.placeholder.unavailable", QStringLiteral("<不可用>")));
        setDiagnosticItem(AlpcColumn::kStatus, kReadableAlpcMessage);
        alpcTable_->setSortingEnabled(true);
        alpcTable_->setCurrentCell(0, static_cast<int>(AlpcColumn::kRole));

        alpcStatusLabel_->setText(kSkippedByInput
            ? kernelText("kernel.ipc.alpc.status.not_requested", QStringLiteral("状态：R0 IPC summary 已刷新；ALPC 详情未请求"))
            : kernelText("kernel.ipc.alpc.status.query_failed", QStringLiteral("状态：ALPC 查询失败 - %1")).arg(kReadableAlpcMessage));
        alpcStatusLabel_->setStyleSheet(statusLabelStyle(kSkippedByInput ? ksword_theme::warningHex() : ksword_theme::errorHex()));
        if (kSkippedByInput)
        {
            // When there is no ALPC target:
            // - Input: Current row of the summary table, defaulting to the first row;
            // - Processing: Continue displaying the structured details of the IPC summary instead of overwriting with a single short hint;
            // - Return: None; ensures the page retains readable audit unwind data.
            const int kSummaryRow = (ipcSummaryTable_ != nullptr && ipcSummaryTable_->currentRow() >= 0)
                ? ipcSummaryTable_->currentRow()
                : 0;
            if (ipcSummaryTable_ != nullptr && ipcSummaryTable_->rowCount() > 0)
            {
                ipcSummaryTable_->setCurrentCell(kSummaryRow, 0);
            }
            updateIpcSummaryDetailForRow(kSummaryRow);
        }
        else
        {
            alpcDetailEditor_->setText(kernelText("kernel.ipc.alpc.detail.query_failed", QStringLiteral("ALPC 查询失败。\n%1")).arg(kReadableAlpcMessage));
        }
        return;
    }

    struct EntryView
    {
        QString role;
        const ksword::ark::AlpcPortInfo* port = nullptr;
    };
    const EntryView kViews[] = {
        { QStringLiteral("Query"), &lastAlpcResult_.queryPort },
        { QStringLiteral("Connection"), &lastAlpcResult_.connectionPort },
        { QStringLiteral("Server"), &lastAlpcResult_.serverPort },
        { QStringLiteral("Client"), &lastAlpcResult_.clientPort },
    };

    for (const EntryView& view : kViews)
    {
        const int kRowIndex = alpcTable_->rowCount();
        alpcTable_->insertRow(kRowIndex);

        auto* roleItem = new QTableWidgetItem(view.role);
        auto* relationItem = new QTableWidgetItem(view.port != nullptr ? formatRelationText(view.port->relation) : kernelText("kernel.ipc.placeholder.empty", QStringLiteral("<空>")));
        auto* ownerItem = new QTableWidgetItem(view.port != nullptr ? QString::number(view.port->ownerProcessId) : QString());
        auto* flagsItem = new QTableWidgetItem(view.port != nullptr ? formatHex32(view.port->flags) : QString());
        auto* stateItem = new QTableWidgetItem(view.port != nullptr ? QString::number(view.port->state) : QString());
        auto* seqItem = new QTableWidgetItem(view.port != nullptr ? QString::number(view.port->sequenceNo) : QString());
        auto* objectItem = new QTableWidgetItem(view.port != nullptr ? formatHex64(view.port->objectAddress) : QString());
        auto* contextItem = new QTableWidgetItem(view.port != nullptr ? formatHex64(view.port->portContext) : QString());
        auto* nameItem = new QTableWidgetItem(view.port != nullptr ? safeText(QString::fromWCharArray(view.port->portName.c_str(), static_cast<int>(view.port->portName.size()))) : QString());
        auto* statusItem = new QTableWidgetItem(view.port != nullptr ? statusText(view.port->basicStatus) : QString());

        roleItem->setFlags(roleItem->flags() & ~Qt::ItemIsEditable);
        relationItem->setFlags(relationItem->flags() & ~Qt::ItemIsEditable);
        ownerItem->setFlags(ownerItem->flags() & ~Qt::ItemIsEditable);
        flagsItem->setFlags(flagsItem->flags() & ~Qt::ItemIsEditable);
        stateItem->setFlags(stateItem->flags() & ~Qt::ItemIsEditable);
        seqItem->setFlags(seqItem->flags() & ~Qt::ItemIsEditable);
        objectItem->setFlags(objectItem->flags() & ~Qt::ItemIsEditable);
        contextItem->setFlags(contextItem->flags() & ~Qt::ItemIsEditable);
        nameItem->setFlags(nameItem->flags() & ~Qt::ItemIsEditable);
        statusItem->setFlags(statusItem->flags() & ~Qt::ItemIsEditable);

        alpcTable_->setItem(kRowIndex, static_cast<int>(AlpcColumn::kRole), roleItem);
        alpcTable_->setItem(kRowIndex, static_cast<int>(AlpcColumn::kRelation), relationItem);
        alpcTable_->setItem(kRowIndex, static_cast<int>(AlpcColumn::kOwnerProcessId), ownerItem);
        alpcTable_->setItem(kRowIndex, static_cast<int>(AlpcColumn::kFlags), flagsItem);
        alpcTable_->setItem(kRowIndex, static_cast<int>(AlpcColumn::kState), stateItem);
        alpcTable_->setItem(kRowIndex, static_cast<int>(AlpcColumn::kSequenceNo), seqItem);
        alpcTable_->setItem(kRowIndex, static_cast<int>(AlpcColumn::kObjectAddress), objectItem);
        alpcTable_->setItem(kRowIndex, static_cast<int>(AlpcColumn::kPortContext), contextItem);
        alpcTable_->setItem(kRowIndex, static_cast<int>(AlpcColumn::kPortName), nameItem);
        alpcTable_->setItem(kRowIndex, static_cast<int>(AlpcColumn::kStatus), statusItem);
    }

    alpcTable_->setSortingEnabled(true);
    alpcStatusLabel_->setText(kernelText("kernel.ipc.alpc.status.success", QStringLiteral("状态：PID=%1 Handle=%2 | Query=%3 Connection=%4 Server=%5 Client=%6"))
        .arg(lastAlpcResult_.processId)
        .arg(formatHex64(lastAlpcResult_.handleValue))
        .arg(statusText(lastAlpcResult_.queryStatus))
        .arg(statusText(lastAlpcResult_.communicationStatus))
        .arg(statusText(lastAlpcResult_.basicStatus))
        .arg(statusText(lastAlpcResult_.nameStatus)));
    alpcStatusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::successHex()));

    const int kCurrentRow = alpcTable_->currentRow();
    const QTableWidgetItem* roleItem = kCurrentRow >= 0 ? alpcTable_->item(kCurrentRow, static_cast<int>(AlpcColumn::kRole)) : nullptr;
    if (roleItem == nullptr && alpcTable_->rowCount() > 0)
    {
        alpcTable_->setCurrentCell(0, 0);
        roleItem = alpcTable_->item(0, static_cast<int>(AlpcColumn::kRole));
    }

    updateAlpcDetailForRow(alpcTable_->currentRow());
}

QString KernelDockIpcTab::buildAlpcDetail(const int rowIndex) const
{
    // buildAlpcDetail：
    // - Purpose: Convert ALPC query results into detail section text.
    // - Input: Currently selected ALPC row number;
    // - Returns: QString, multi-line description of the current port, status, and dynamic offset.
    if (!lastAlpcResult_.io.ok)
    {
        return kernelText("kernel.ipc.alpc.detail.unavailable", QStringLiteral("ALPC 查询暂不可用。\n%1"))
            .arg(friendlyIpcIoMessage(stdStringToQString(lastAlpcResult_.io.message)));
    }

    QString selectedRoleText = kernelText("kernel.ipc.placeholder.unselected", QStringLiteral("<未选择>"));
    QString selectedPortDetailText = kernelText("kernel.ipc.alpc.detail.select_row", QStringLiteral("请在 ALPC 表中选择一行查看端口详情。"));
    if (alpcTable_ != nullptr && rowIndex >= 0 && rowIndex < alpcTable_->rowCount())
    {
        // Current row parsing:
        // - Input: table role column text;
        // - Processing: Map to the four port snapshots returned by ArkDriverClient.
        // - Returns: Single-port details for the current row.
        const QTableWidgetItem* roleItem = alpcTable_->item(rowIndex, static_cast<int>(AlpcColumn::kRole));
        selectedRoleText = roleItem != nullptr ? roleItem->text() : kernelText("kernel.ipc.alpc.placeholder.unknown_role", QStringLiteral("<未知角色>"));
        if (selectedRoleText == QStringLiteral("Query"))
        {
            selectedPortDetailText = buildPortDetail(selectedRoleText, lastAlpcResult_.queryPort);
        }
        else if (selectedRoleText == QStringLiteral("Connection"))
        {
            selectedPortDetailText = buildPortDetail(selectedRoleText, lastAlpcResult_.connectionPort);
        }
        else if (selectedRoleText == QStringLiteral("Server"))
        {
            selectedPortDetailText = buildPortDetail(selectedRoleText, lastAlpcResult_.serverPort);
        }
        else if (selectedRoleText == QStringLiteral("Client"))
        {
            selectedPortDetailText = buildPortDetail(selectedRoleText, lastAlpcResult_.clientPort);
        }
    }

    // Detail text:
    // - Input: Port snapshot, status code, and DynData offset;
    // - Processing: Organize by 'current row + summary status + full port list' to avoid providing only a summary.
    // - Return: Stable text to be displayed in the CodeEditorWidget.
    return kernelText("kernel.ipc.alpc.detail.full", QStringLiteral(
        "ALPC Port Detail\n"
        "当前角色: %1\n\n"
        "[Selected]\n%2\n\n"
        "[Status]\n"
        "QueryStatus: %3\n"
        "ObjectReferenceStatus: %4\n"
        "TypeStatus: %5\n"
        "BasicStatus: %6\n"
        "CommunicationStatus: %7\n"
        "NameStatus: %8\n"
        "DynDataCapabilityMask: %9\n"
        "Offsets: CommunicationInfo=%10 OwnerProcess=%11 ConnectionPort=%12 ServerCommunicationPort=%13 ClientCommunicationPort=%14 HandleTable=%15 HandleTableLock=%16 Attributes=%17 AttributesFlags=%18 PortContext=%19 PortObjectLock=%20 SequenceNo=%21 State=%22\n\n"
        "[All Ports]\n"
        "[Query]\n%23\n\n[Connection]\n%24\n\n[Server]\n%25\n\n[Client]\n%26"))
        .arg(selectedRoleText)
        .arg(selectedPortDetailText)
        .arg(statusText(lastAlpcResult_.queryStatus))
        .arg(statusText(lastAlpcResult_.objectReferenceStatus))
        .arg(statusText(lastAlpcResult_.typeStatus))
        .arg(statusText(lastAlpcResult_.basicStatus))
        .arg(statusText(lastAlpcResult_.communicationStatus))
        .arg(statusText(lastAlpcResult_.nameStatus))
        .arg(formatHex64(lastAlpcResult_.dynDataCapabilityMask))
        .arg(lastAlpcResult_.alpcCommunicationInfoOffset)
        .arg(lastAlpcResult_.alpcOwnerProcessOffset)
        .arg(lastAlpcResult_.alpcConnectionPortOffset)
        .arg(lastAlpcResult_.alpcServerCommunicationPortOffset)
        .arg(lastAlpcResult_.alpcClientCommunicationPortOffset)
        .arg(lastAlpcResult_.alpcHandleTableOffset)
        .arg(lastAlpcResult_.alpcHandleTableLockOffset)
        .arg(lastAlpcResult_.alpcAttributesOffset)
        .arg(lastAlpcResult_.alpcAttributesFlagsOffset)
        .arg(lastAlpcResult_.alpcPortContextOffset)
        .arg(lastAlpcResult_.alpcPortObjectLockOffset)
        .arg(lastAlpcResult_.alpcSequenceNoOffset)
        .arg(lastAlpcResult_.alpcStateOffset)
        .arg(buildPortDetail(QStringLiteral("Query"), lastAlpcResult_.queryPort))
        .arg(buildPortDetail(QStringLiteral("Connection"), lastAlpcResult_.connectionPort))
        .arg(buildPortDetail(QStringLiteral("Server"), lastAlpcResult_.serverPort))
        .arg(buildPortDetail(QStringLiteral("Client"), lastAlpcResult_.clientPort));
}

void KernelDockIpcTab::updateAlpcDetailForRow(const int rowIndex)
{
    // updateAlpcDetailForRow：
    // - Purpose: Respond to ALPC table selection changes by refreshing the CodeEditorWidget;
    // - Input: current row index of the ALPC table;
    // - Output: Updates the read-only details text; no return value.
    if (alpcDetailEditor_ == nullptr || !lastAlpcResult_.io.ok)
    {
        return;
    }

    alpcDetailEditor_->setText(buildAlpcDetail(rowIndex));
}

QString KernelDockIpcTab::buildIpcSummaryDetail(const int rowIndex) const
{
    // buildIpcSummaryDetail：
    // - Purpose: Combine fixed IPC summary response with current table row to form detail area text.
    // - Input: summary is the current row number; if -1 or out of bounds, only response-level information is output
    // - Return: QString, multi-line read-only text, triggering no driver queries.
    QString categoryText = kernelText("kernel.ipc.placeholder.unselected", QStringLiteral("<未选择>"));
    QString statusTextValue = kernelText("kernel.ipc.placeholder.unselected", QStringLiteral("<未选择>"));
    QString countText = kernelText("kernel.ipc.placeholder.unselected", QStringLiteral("<未选择>"));
    QString sourceText = kernelText("kernel.ipc.placeholder.unselected", QStringLiteral("<未选择>"));
    QString rowDetailText = kernelText("kernel.ipc.summary.placeholder.unselected_row", QStringLiteral("<未选择 IPC summary 行>"));

    if (ipcSummaryTable_ != nullptr && rowIndex >= 0 && rowIndex < ipcSummaryTable_->rowCount())
    {
        // Table row snapshot:
        // - Input: five visible columns of the current row
        // - Processing: Convert null pointer cells to empty strings.
        // - Return: Row-level summary field for the detail area.
        const QTableWidgetItem* categoryItem = ipcSummaryTable_->item(rowIndex, static_cast<int>(IpcSummaryColumn::kCategory));
        const QTableWidgetItem* statusItem = ipcSummaryTable_->item(rowIndex, static_cast<int>(IpcSummaryColumn::kStatus));
        const QTableWidgetItem* countItem = ipcSummaryTable_->item(rowIndex, static_cast<int>(IpcSummaryColumn::kCount));
        const QTableWidgetItem* sourceItem = ipcSummaryTable_->item(rowIndex, static_cast<int>(IpcSummaryColumn::kSource));
        const QTableWidgetItem* detailItem = ipcSummaryTable_->item(rowIndex, static_cast<int>(IpcSummaryColumn::kDetail));

        categoryText = categoryItem != nullptr ? categoryItem->text() : QString();
        statusTextValue = statusItem != nullptr ? statusItem->text() : QString();
        countText = countItem != nullptr ? countItem->text() : QString();
        sourceText = sourceItem != nullptr ? sourceItem->text() : QString();
        rowDetailText = detailItem != nullptr ? detailItem->text() : QString();
    }

    const QString kReadableIoMessage = friendlyIpcIoMessage(stdStringToQString(lastIpcSummaryResult_.io.message));
    if (!lastIpcSummaryResult_.io.ok)
    {
        // Failure details:
        // - Input: IO result from ArkDriverClient.
        // - Processing: Convert to user-readable status instead of exposing raw DeviceIoControl noise.
        // - Return: Diagnostic text containing Win32/byte count/unsupported.
        return kernelText("kernel.ipc.summary.detail.failure", QStringLiteral(
            "IPC Summary Detail\n"
            "当前行: %1\n"
            "行状态: %2\n"
            "行计数: %3\n"
            "来源: %4\n"
            "行详情: %5\n\n"
            "查询结果: %6\n"
            "Unsupported: %7\n"
            "Win32Error: %8\n"
            "BytesReturned: %9\n"
            "说明: %10"))
            .arg(categoryText)
            .arg(statusTextValue)
            .arg(countText)
            .arg(sourceText)
            .arg(rowDetailText)
            .arg(lastIpcSummaryResult_.io.ok ? QStringLiteral("OK") : QStringLiteral("Unavailable"))
            .arg(lastIpcSummaryResult_.unsupported
                ? kernelText("kernel.ipc.value.yes", QStringLiteral("是"))
                : kernelText("kernel.ipc.value.no", QStringLiteral("否")))
            .arg(lastIpcSummaryResult_.io.win32Error)
            .arg(lastIpcSummaryResult_.io.bytesReturned)
            .arg(kReadableIoMessage);
    }

    const auto& response = lastIpcSummaryResult_.response;
    const QString kObjectDetailText = safeText(
        fixedWideText(response.detail, KSWORD_ARK_KERNEL_OBJECT_DETAIL_CHARS),
        kernelText("kernel.ipc.summary.object_detail_unavailable", QStringLiteral("驱动未提供额外对象详情")));
    const QString kAlpcTypeText = safeText(
        fixedWideText(response.alpcTypeName, KSWORD_ARK_KERNEL_OBJECT_TYPE_NAME_CHARS),
        kernelText("kernel.ipc.summary.placeholder.type_name", QStringLiteral("<未返回类型名>")));

    // Success details:
    // - Input: R0 fixed summary response, current table row, and user-friendly IO text;
    // - Processing: Expand the summary row into four groups of information: response, status, identity, and dyndata.
    // - Returns: Detail area text to prevent users from seeing only a single-line summary.
    return kernelText("kernel.ipc.summary.detail.success", QStringLiteral(
        "IPC Summary Detail\n"
        "当前行: %1\n"
        "行状态: %2\n"
        "行计数: %3\n"
        "来源: %4\n"
        "行详情: %5\n\n"
        "[Response]\n"
        "SummaryStatus: %6\n"
        "ALPCStatus: %7\n"
        "NamedPipeStatus: %8\n"
        "MailslotStatus: %9\n"
        "FieldFlags: %10\n"
        "LastStatus: %11\n"
        "BytesReturned: %12\n"
        "说明: %13\n\n"
        "[Target]\n"
        "ProcessId: %14\n"
        "HandleValue: %15\n"
        "AlpcObjectAddress: %16\n"
        "AlpcTypeName: %17\n"
        "DynDataCapabilityMask: %18\n\n"
        "[ObjectDetail]\n"
        "%19"))
        .arg(categoryText)
        .arg(statusTextValue)
        .arg(countText)
        .arg(sourceText)
        .arg(rowDetailText)
        .arg(ipcSummaryStatusText(response.status))
        .arg(ipcSummaryStatusText(response.alpcStatus))
        .arg(ipcSummaryStatusText(response.namedPipeStatus))
        .arg(ipcSummaryStatusText(response.mailslotStatus))
        .arg(formatHex32(response.fieldFlags))
        .arg(statusText(response.lastStatus))
        .arg(lastIpcSummaryResult_.io.bytesReturned)
        .arg(kReadableIoMessage)
        .arg(response.processId)
        .arg(formatHex64(response.handleValue))
        .arg(formatHex64(response.alpcObjectAddress))
        .arg(kAlpcTypeText)
        .arg(formatHex64(response.dynDataCapabilityMask))
        .arg(kObjectDetailText);
}

void KernelDockIpcTab::updateIpcSummaryDetailForRow(const int rowIndex)
{
    // updateIpcSummaryDetailForRow：
    // - Purpose: Respond to summary table selection changes by expanding the current row into the CodeEditorWidget.
    // - Input: summary table row index;
    // - Output: Updates m_alpcDetailEditor; no return value, modifies no system objects.
    if (alpcDetailEditor_ == nullptr)
    {
        return;
    }

    alpcDetailEditor_->setText(buildIpcSummaryDetail(rowIndex));
}

void KernelDockIpcTab::copyAlpcCurrentRow() const
{
    if (alpcTable_ == nullptr || QApplication::clipboard() == nullptr)
    {
        return;
    }

    const int kRowIndex = alpcTable_->currentRow();
    if (kRowIndex < 0)
    {
        return;
    }

    QStringList fields;
    for (int columnIndex = 0; columnIndex < alpcTable_->columnCount(); ++columnIndex)
    {
        const QTableWidgetItem* item = alpcTable_->item(kRowIndex, columnIndex);
        fields.push_back(item != nullptr ? item->text() : QString());
    }
    QApplication::clipboard()->setText(fields.join('\t'));
}

void KernelDockIpcTab::copyIpcSummaryCurrentRow() const
{
    // copyIpcSummaryCurrentRow：
    // - Input: Currently selected row in the IPC summary table.
    // - Processing: Join visible columns with tabs and write to clipboard.
    // - Return: None. Returns immediately if the table is empty or the clipboard is unavailable to avoid UI errors.
    if (ipcSummaryTable_ == nullptr || QApplication::clipboard() == nullptr)
    {
        return;
    }

    const int kRowIndex = ipcSummaryTable_->currentRow();
    if (kRowIndex < 0)
    {
        return;
    }

    QStringList fields;
    for (int columnIndex = 0; columnIndex < ipcSummaryTable_->columnCount(); ++columnIndex)
    {
        const QTableWidgetItem* item = ipcSummaryTable_->item(kRowIndex, columnIndex);
        fields.push_back(item != nullptr ? item->text() : QString());
    }
    QApplication::clipboard()->setText(fields.join('\t'));
}

QString KernelDockIpcTab::formatHex32(const std::uint32_t value)
{
    return QStringLiteral("0x%1").arg(value, 8, 16, QChar('0')).toUpper();
}

QString KernelDockIpcTab::formatHex64(const std::uint64_t value)
{
    return QStringLiteral("0x%1").arg(static_cast<qulonglong>(value), 16, 16, QChar('0')).toUpper();
}

QString KernelDockIpcTab::statusText(long statusValue)
{
    return formatHex32(static_cast<std::uint32_t>(statusValue));
}
