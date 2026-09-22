#include "KernelDockCidTab.h"
#include "KernelDock.h"
#include "../ui/VisibleTableWidget.h"

// ============================================================
// KernelDockCidTab.cpp
// Purpose:
// 1) Aggregates process/thread cross-view evidence to form a read-only CID view;
// 2) Query the R0 result via ArkDriverClient; do not perform time-consuming collection on the UI thread;
// 3) Do not expose any patch, unlink, restore, or other write paths.
// ============================================================

#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../ui/CodeEditorWidget.h"
#include "../ui/DetailLayoutRegistry.h"
#include "../ui/TableInteractionSupport.h"
#include "../Theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QBrush>
#include <QClipboard>
#include <QColor>
#include <QCoreApplication>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QModelIndex>
#include <QLineEdit>
#include <QMenu>
#include <QMetaObject>
#include <QPoint>
#include <QPointer>
#include <QPushButton>
#include <QPixmap>
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QThreadPool>
#include <QTimer>
#include <QVBoxLayout>

#include <algorithm>
#include <cstddef>
#include <thread>
#include <utility>

using ksword::kernel_dock_internal::kernelText;

namespace
{
    enum class CidColumn : int
    {
        kKind = 0,
        kCidValue,
        kProcessId,
        kThreadId,
        kImage,
        kObjectAddress,
        kStartAddress,
        kSourceMask,
        kAnomalyFlags,
        kCidEntryFlags,
        kConfidence,
        kDetailStatus,
        kDenoise,
        kStatus,
        kCount
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

    QString menuStyle()
    {
        // CID page right-click menu:
        // - Inputs: None;
        // - Handling: Uniformly reuse the global opaque QMenu style to prevent palette role transparency issues in light/dark Dock themes.
        // - Return: Menu style text ready for setStyleSheet.
        return ksword_theme::contextMenuStyle();
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
        return safeText(valueText, kernelText("kernel.cid.placeholder.empty", QStringLiteral("<空>")));
    }

    QString emptyText()
    {
        return kernelText("kernel.cid.placeholder.empty", QStringLiteral("<空>"));
    }

    QString friendlyIoMessage(const QString& messageText)
    {
        // friendlyIoMessage：
        // - Input: ArkDriverClient::IoResult::message or derived diagnostic text;
        // - Handling: Convert common DeviceIoControl/unsupported/capability text into Chinese-readable explanations.
        // - Return: short text suitable for status bar and detail area display; does not hide structured fields such as status/count.
        const QString kTrimmedText = messageText.trimmed();
        if (kTrimmedText.isEmpty())
        {
            return kernelText("kernel.cid.message.no_driver_message", QStringLiteral("无额外驱动消息"));
        }
        if (kTrimmedText.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive))
        {
            return kernelText("kernel.cid.message.device_io_failure", QStringLiteral("驱动接口调用失败或当前驱动版本不匹配"));
        }
        if (kTrimmedText.contains(QStringLiteral("unsupported"), Qt::CaseInsensitive) ||
            kTrimmedText.contains(QStringLiteral("not supported"), Qt::CaseInsensitive))
        {
            return kernelText("kernel.cid.message.unsupported", QStringLiteral("当前驱动不支持该 CID/cross-view 查询入口"));
        }
        if (kTrimmedText.contains(QStringLiteral("capability"), Qt::CaseInsensitive) ||
            kTrimmedText.contains(QStringLiteral("DynData"), Qt::CaseInsensitive))
        {
            return kernelText("kernel.cid.message.capability", QStringLiteral("动态偏移能力未满足，请先查看 DynData/Capability 状态"));
        }
        return kTrimmedText;
    }

    QString formatAddressText(const std::uint64_t value)
    {
        return QStringLiteral("0x%1").arg(static_cast<qulonglong>(value), 16, 16, QChar('0')).toUpper();
    }

}

KernelDockCidTab::KernelDockCidTab(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
    initializeConnections();

    QMetaObject::invokeMethod(this, [this]() {
        refreshAsync();
    }, Qt::QueuedConnection);
}

void KernelDockCidTab::initializeUi()
{
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(8, 8, 8, 8);
    rootLayout->setSpacing(6);

    toolbarLayout_ = new QHBoxLayout();
    toolbarLayout_->setContentsMargins(0, 0, 0, 0);
    toolbarLayout_->setSpacing(6);

    refreshButton_ = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), this);
    ksword_theme::applyCompactIconButtonMetrics(refreshButton_);
    refreshButton_->setToolTip(kernelText("kernel.cid.toolbar.refresh.tooltip", QStringLiteral("刷新 CID / cross-view 证据")));
    refreshButton_->setStyleSheet(blueButtonStyle());

    filterEdit_ = new QLineEdit(this);
    filterEdit_->setPlaceholderText(kernelText("kernel.cid.toolbar.filter.placeholder", QStringLiteral("按类型/PID/TID/地址/状态/异常/详情筛选")));
    filterEdit_->setClearButtonEnabled(true);
    filterEdit_->setStyleSheet(blueInputStyle());

    statusLabel_ = new QLabel(kernelText("kernel.cid.status.waiting", QStringLiteral("状态：等待刷新")), this);
    statusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::textSecondaryHex()));

    toolbarLayout_->addWidget(refreshButton_, 0);
    toolbarLayout_->addWidget(filterEdit_, 1);
    toolbarLayout_->addWidget(statusLabel_, 0);
    rootLayout->addLayout(toolbarLayout_);

    table_ = new ks::ui::VisibleTableWidget(this);
    table_->setColumnCount(static_cast<int>(CidColumn::kCount));
    table_->setHorizontalHeaderLabels(QStringList{
        kernelText("kernel.cid.header.kind", QStringLiteral("类型")),
        QStringLiteral("CID"),
        QStringLiteral("PID"),
        QStringLiteral("TID"),
        kernelText("kernel.cid.header.image", QStringLiteral("图像")),
        kernelText("kernel.cid.header.object_address", QStringLiteral("对象地址")),
        kernelText("kernel.cid.header.start_address", QStringLiteral("起始地址")),
        QStringLiteral("SourceMask"),
        QStringLiteral("AnomalyFlags"),
        QStringLiteral("CID Flags"),
        QStringLiteral("Confidence"),
        QStringLiteral("DetailStatus"),
        QStringLiteral("Denoise"),
        kernelText("kernel.cid.header.status", QStringLiteral("状态"))
        });
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setAlternatingRowColors(true);
    table_->setContextMenuPolicy(Qt::CustomContextMenu);
    table_->setStyleSheet(itemSelectionStyle());
    table_->verticalHeader()->setVisible(false);
    table_->horizontalHeader()->setStyleSheet(headerStyle());
    table_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(static_cast<int>(CidColumn::kImage), QHeaderView::Stretch);
    table_->horizontalHeader()->setSectionResizeMode(static_cast<int>(CidColumn::kStatus), QHeaderView::Stretch);
    rootLayout->addWidget(table_, 1);

    detailEditor_ = new CodeEditorWidget(this);
    detailEditor_->setReadOnly(true);
    detailEditor_->setText(kernelText("kernel.cid.detail.initial", QStringLiteral("请选择一条 cross-view 记录查看详情。")));
    rootLayout->addWidget(detailEditor_, 1);

    ks::ui::DetailLayoutRegistry::registerHost(table_, detailEditor_, this);
}

void KernelDockCidTab::initializeConnections()
{
    connect(refreshButton_, &QPushButton::clicked, this, [this]() {
        refreshAsync();
    });
    connect(filterEdit_, &QLineEdit::textChanged, this, [this]() {
        rebuildTable();
    });
    // Detail debouncing:
    // - When direction keys are pressed repeatedly or filter terms are typed character by character, the selected row changes based on key press frequency.
    // - Local fields render immediately; R0 object summaries are sent via IOCTL only after the final change.
    detailRequestTimer_ = new QTimer(this);
    detailRequestTimer_->setSingleShot(true);
    detailRequestTimer_->setInterval(150);
    connect(detailRequestTimer_, &QTimer::timeout, this, [this]() {
        requestKernelObjectSummaryAsync();
    });
    connect(table_, &QTableWidget::currentCellChanged, this, [this](int, int, int, int) {
        scheduleDetailRefresh();
    });
    connect(table_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& localPosition) {
        showContextMenu(localPosition);
    });
}

void KernelDockCidTab::refreshAsync()
{
    if (refreshing_.exchange(true))
    {
        return;
    }

    refreshButton_->setEnabled(false);
    statusLabel_->setText(kernelText("kernel.cid.status.refreshing", QStringLiteral("状态：刷新中...")));
    statusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::kPrimaryBlueHex));

    QPointer<KernelDockCidTab> guardThis(this);
    std::thread([guardThis]() {
        std::vector<CidEvidenceRow> rows;
        QString errorText;

        const ksword::ark::DriverClient kClient;
        const ksword::ark::ProcessCrossViewResult kProcessResult = kClient.queryProcessCrossView();
        const ksword::ark::ThreadCrossViewResult kThreadResult = kClient.queryThreadCrossView();
        const ksword::ark::CidTableAuditResult kCidTableResult = kClient.enumCidTable();
        const bool kProcessOk = kProcessResult.io.ok;
        const bool kThreadOk = kThreadResult.io.ok;
        const bool kCidOk = kCidTableResult.io.ok;
        CidTableSummary cidSummary{};
        cidSummary.queried = true;
        cidSummary.ok = kCidTableResult.io.ok;
        cidSummary.unsupported = kCidTableResult.unsupported;
        cidSummary.status = kCidTableResult.status;
        cidSummary.totalCount = kCidTableResult.totalCount;
        cidSummary.returnedCount = kCidTableResult.returnedCount;
        cidSummary.visitedCount = kCidTableResult.visitedCount;
        cidSummary.maxVisitCount = kCidTableResult.maxVisitCount;
        cidSummary.flags = kCidTableResult.flags;
        cidSummary.lastStatus = kCidTableResult.lastStatus;
        cidSummary.pspCidTableAddress = kCidTableResult.pspCidTableAddress;
        cidSummary.dynDataCapabilityMask = kCidTableResult.dynDataCapabilityMask;
        cidSummary.htTableCodeOffset = kCidTableResult.htTableCodeOffset;
        cidSummary.hteLowValueOffset = kCidTableResult.hteLowValueOffset;
        cidSummary.messageText = friendlyIoMessage(QString::fromStdString(kCidTableResult.io.message));

        if (kProcessOk)
        {
            for (const ksword::ark::ProcessCrossViewEntry& entry : kProcessResult.entries)
            {
                CidEvidenceRow row{};
                row.isThread = false;
                row.processId = entry.processId;
                row.parentProcessId = entry.parentProcessId;
                row.objectAddress = entry.objectAddress;
                row.startAddress = entry.startAddress;
                row.sourceMask = entry.sourceMask;
                row.anomalyFlags = entry.anomalyFlags;
                row.dynDataCapabilityMask = entry.dynDataCapabilityMask;
                row.lastStatus = entry.lastStatus;
                row.confidence = entry.confidence;
                row.detailStatus = entry.detailStatus;
                row.denoiseFlags = entry.denoiseFlags;
                row.publicProcessId = entry.publicProcessId;
                row.activeListProcessId = entry.activeListProcessId;
                row.cidTableProcessId = entry.cidTableProcessId;
                row.publicWalkStatus = entry.publicWalkStatus;
                row.activeListStatus = entry.activeListStatus;
                row.cidTableStatus = entry.cidTableStatus;
                row.imageNameText = QString::fromStdString(entry.imageName);
                row.detailText = friendlyIoMessage(QString::fromStdString(entry.detail));
                rows.push_back(std::move(row));
            }
        }
        else
        {
            errorText += kernelText("kernel.cid.error.process", QStringLiteral("进程 cross-view 失败: %1\n"))
                .arg(friendlyIoMessage(QString::fromStdString(kProcessResult.io.message)));
        }

        if (kThreadOk)
        {
            for (const ksword::ark::ThreadCrossViewEntry& entry : kThreadResult.entries)
            {
                CidEvidenceRow row{};
                row.isThread = true;
                row.processId = entry.processId;
                row.threadId = entry.threadId;
                row.processObjectAddress = entry.processObjectAddress;
                row.objectAddress = entry.objectAddress;
                row.startAddress = entry.startAddress;
                row.sourceMask = entry.sourceMask;
                row.anomalyFlags = entry.anomalyFlags;
                row.dynDataCapabilityMask = entry.dynDataCapabilityMask;
                row.lastStatus = entry.lastStatus;
                row.confidence = entry.confidence;
                row.detailStatus = entry.detailStatus;
                row.denoiseFlags = entry.denoiseFlags;
                row.publicThreadId = entry.publicThreadId;
                row.threadListThreadId = entry.threadListThreadId;
                row.cidTableThreadId = entry.cidTableThreadId;
                row.publicProcessId = entry.publicProcessId;
                row.threadListProcessId = entry.threadListProcessId;
                row.cidTableProcessId = entry.cidTableProcessId;
                row.publicWalkStatus = entry.publicWalkStatus;
                row.threadListStatus = entry.threadListStatus;
                row.cidTableStatus = entry.cidTableStatus;
                row.startAddressStatus = entry.startAddressStatus;
                row.imageNameText = QString::fromStdString(entry.imageName);
                row.detailText = friendlyIoMessage(QString::fromStdString(entry.detail));
                rows.push_back(std::move(row));
            }
        }
        else
        {
            errorText += kernelText("kernel.cid.error.thread", QStringLiteral("线程 cross-view 失败: %1\n"))
                .arg(friendlyIoMessage(QString::fromStdString(kThreadResult.io.message)));
        }

        if (kCidOk)
        {
            for (const KSWORD_ARK_CID_TABLE_ENTRY& entry : kCidTableResult.entries)
            {
                CidEvidenceRow row{};
                row.isRawCid = true;
                row.isThread = entry.expectedObjectKind == KSWORD_ARK_CID_OBJECT_KIND_THREAD;
                row.cidValue = entry.cidValue;
                row.cidHandleIndex = entry.handleIndex;
                row.cidExpectedKind = entry.expectedObjectKind;
                row.cidEntryFlags = entry.flags;
                row.cidReferenceStatus = entry.referenceStatus;
                row.objectAddress = entry.objectAddress;
                row.sourceMask = KSWORD_ARK_CROSSVIEW_SOURCE_CID_TABLE;
                row.detailStatus = entry.lookupStatus;
                row.lastStatus = entry.referenceStatus;
                if (entry.expectedObjectKind == KSWORD_ARK_CID_OBJECT_KIND_PROCESS)
                {
                    row.processId = entry.cidValue;
                    row.cidTableProcessId = entry.cidValue;
                }
                else if (entry.expectedObjectKind == KSWORD_ARK_CID_OBJECT_KIND_THREAD)
                {
                    row.threadId = entry.cidValue;
                    row.cidTableThreadId = entry.cidValue;
                }
                if ((entry.flags & KSWORD_ARK_CID_ENTRY_FLAG_DANGLING) != 0U)
                {
                    row.anomalyFlags |= KSWORD_ARK_CROSSVIEW_ANOMALY_DANGLING_OBJECT;
                }
                if ((entry.flags & KSWORD_ARK_CID_ENTRY_FLAG_TYPE_MISMATCH) != 0U)
                {
                    row.anomalyFlags |= KSWORD_ARK_CROSSVIEW_ANOMALY_PID_FIELD_MISMATCH;
                }
                row.imageNameText = cidKindText(entry.expectedObjectKind);
                row.detailText = kernelText("kernel.cid.detail.raw_row", QStringLiteral("R0 CID table row：handleIndex=%1，lookupStatus=%2，referenceStatus=%3，flags=%4"))
                    .arg(entry.handleIndex)
                    .arg(statusLabelText(entry.lookupStatus))
                    .arg(statusLabelText(entry.referenceStatus))
                    .arg(cidEntryFlagsText(entry.flags));
                rows.push_back(std::move(row));
            }
        }
        else
        {
            errorText += kernelText("kernel.cid.error.cid_table", QStringLiteral("R0 CID 表枚举失败: %1\n"))
                .arg(friendlyIoMessage(QString::fromStdString(kCidTableResult.io.message)));
        }

        std::sort(rows.begin(), rows.end(), [](const CidEvidenceRow& left, const CidEvidenceRow& right) {
            if (left.isRawCid != right.isRawCid)
            {
                return left.isRawCid < right.isRawCid;
            }
            if (left.isThread != right.isThread)
            {
                return left.isThread < right.isThread;
            }
            if (left.processId != right.processId)
            {
                return left.processId < right.processId;
            }
            return left.threadId < right.threadId;
        });

        KernelDockCidTab* const kContextObject = guardThis.data();
        if (kContextObject == nullptr)
        {
            return;
        }

        QMetaObject::invokeMethod(kContextObject, [guardThis, rows = std::move(rows), errorText, kProcessOk, kThreadOk, kCidOk, cidSummary]() mutable {
            if (guardThis == nullptr)
            {
                return;
            }

            auto applySnapshot = [
                guardThis,
                rows = std::move(rows),
                errorText = errorText.trimmed(),
                success = kProcessOk || kThreadOk || kCidOk,
                cidSummary]() mutable
            {
                if (guardThis == nullptr)
                {
                    return;
                }
                guardThis->cidSummary_ = cidSummary;
                guardThis->applyRefreshResult(std::move(rows), errorText, success);
            };

            if (ks::ui::deferTableUiCommitIfContextMenuOpen(
                    guardThis.data(),
                    QStringLiteral("kernel-cid-snapshot"),
                    {guardThis->table_},
                    applySnapshot))
            {
                return;
            }
            applySnapshot();
        }, Qt::QueuedConnection);
    }).detach();
}

void KernelDockCidTab::applyRefreshResult(std::vector<CidEvidenceRow> rows, const QString& errorText, const bool success)
{
    refreshing_.store(false);
    refreshButton_->setEnabled(true);
    rows_ = std::move(rows);
    rebuildTable();

    if (!success)
    {
        statusLabel_->setText(kernelText("kernel.cid.status.failed", QStringLiteral("状态：刷新失败 - %1")).arg(errorText));
        statusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::errorHex()));
    }
}

void KernelDockCidTab::rebuildTable()
{
    if (table_ == nullptr)
    {
        return;
    }

    ks::ui::DetailLayoutRegistry::prepareDataRebuild(detailEditor_);

    table_->setSortingEnabled(false);
    table_->setRowCount(0);

    std::size_t visibleCount = 0;
    for (std::size_t index = 0; index < rows_.size(); ++index)
    {
        const CidEvidenceRow& row = rows_[index];
        if (!rowMatchesFilter(row))
        {
            continue;
        }

        const int kRowIndex = table_->rowCount();
        table_->insertRow(kRowIndex);

        auto* kindItem = readOnlyItem(row.isRawCid
            ? QStringLiteral("CID/%1").arg(cidKindText(row.cidExpectedKind))
            : roleText(row.isThread));
        auto* cidValueItem = readOnlyItem(row.cidValue == 0U ? emptyText() : QString::number(row.cidValue));
        auto* pidItem = readOnlyItem(row.processId == 0U ? emptyText() : QString::number(row.processId));
        auto* tidItem = readOnlyItem(row.isThread ? QString::number(row.threadId) : emptyText());
        auto* imageItem = readOnlyItem(safeText(row.imageNameText));
        auto* objectItem = readOnlyItem(formatHex64(row.objectAddress));
        auto* startItem = readOnlyItem(formatHex64(row.startAddress));
        auto* sourceItem = readOnlyItem(sourceMaskText(row.sourceMask));
        auto* anomalyItem = readOnlyItem(anomalyFlagsText(row.anomalyFlags));
        auto* cidFlagsItem = readOnlyItem(cidEntryFlagsText(row.cidEntryFlags));
        auto* confidenceItem = readOnlyItem(QString::number(row.confidence));
        auto* detailStatusItem = readOnlyItem(detailStatusText(row.detailStatus));
        auto* denoiseItem = readOnlyItem(denoiseFlagsText(row.denoiseFlags));
        auto* statusItem = readOnlyItem(statusLabelText(row.lastStatus));

        kindItem->setData(Qt::UserRole, static_cast<qulonglong>(index));
        if ((row.anomalyFlags & KSWORD_ARK_CROSSVIEW_ANOMALY_DANGLING_OBJECT) != 0U ||
            (row.anomalyFlags & KSWORD_ARK_CROSSVIEW_ANOMALY_THREAD_ORPHAN) != 0U)
        {
            anomalyItem->setForeground(QBrush(ksword_theme::warningColor()));
        }
        if ((row.anomalyFlags & KSWORD_ARK_CROSSVIEW_ANOMALY_PID_FIELD_MISMATCH) != 0U ||
            (row.anomalyFlags & KSWORD_ARK_CROSSVIEW_ANOMALY_START_ADDRESS_OUTSIDE_MODULE) != 0U)
        {
            anomalyItem->setForeground(QBrush(ksword_theme::errorColor()));
        }

        table_->setItem(kRowIndex, static_cast<int>(CidColumn::kKind), kindItem);
        table_->setItem(kRowIndex, static_cast<int>(CidColumn::kCidValue), cidValueItem);
        table_->setItem(kRowIndex, static_cast<int>(CidColumn::kProcessId), pidItem);
        table_->setItem(kRowIndex, static_cast<int>(CidColumn::kThreadId), tidItem);
        table_->setItem(kRowIndex, static_cast<int>(CidColumn::kImage), imageItem);
        table_->setItem(kRowIndex, static_cast<int>(CidColumn::kObjectAddress), objectItem);
        table_->setItem(kRowIndex, static_cast<int>(CidColumn::kStartAddress), startItem);
        table_->setItem(kRowIndex, static_cast<int>(CidColumn::kSourceMask), sourceItem);
        table_->setItem(kRowIndex, static_cast<int>(CidColumn::kAnomalyFlags), anomalyItem);
        table_->setItem(kRowIndex, static_cast<int>(CidColumn::kCidEntryFlags), cidFlagsItem);
        table_->setItem(kRowIndex, static_cast<int>(CidColumn::kConfidence), confidenceItem);
        table_->setItem(kRowIndex, static_cast<int>(CidColumn::kDetailStatus), detailStatusItem);
        table_->setItem(kRowIndex, static_cast<int>(CidColumn::kDenoise), denoiseItem);
        table_->setItem(kRowIndex, static_cast<int>(CidColumn::kStatus), statusItem);
        ++visibleCount;
    }

    table_->setSortingEnabled(true);
    const QString kCidSummaryText = cidSummary_.queried
        ? kernelText("kernel.cid.status.summary_detail", QStringLiteral("；PspCidTable=%1；CID returned/total=%2/%3；status=%4；truncated=%5；visited=%6/%7"))
            .arg(formatHex64(cidSummary_.pspCidTableAddress))
            .arg(cidSummary_.returnedCount)
            .arg(cidSummary_.totalCount)
            .arg(cidEnumStatusText(cidSummary_.status))
            .arg(cidSummaryTruncated(cidSummary_)
                ? kernelText("kernel.cid.value.yes", QStringLiteral("是"))
                : kernelText("kernel.cid.value.no", QStringLiteral("否")))
            .arg(cidSummary_.visitedCount)
            .arg(cidSummary_.maxVisitCount)
        : QString();
    statusLabel_->setText(kernelText("kernel.cid.status.loaded", QStringLiteral("状态：已加载 %1 项，显示 %2 项%3"))
        .arg(static_cast<qulonglong>(rows_.size()))
        .arg(static_cast<qulonglong>(visibleCount))
        .arg(kCidSummaryText));
    statusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::successHex()));

    if (visibleCount == 0U)
    {
        // Empty table diagnosis:
        // - Input: Refresh result total count and filter keyword;
        // - Processing: Insert a copyable, selectable diagnostic row to prevent the CID page from appearing as a rendering failure.
        // - Returns: No return value; the details panel reads the unwind text from UserRole + 2.
        const QString kReasonText = rows_.empty()
            ? kernelText("kernel.cid.empty.no_records", QStringLiteral("本轮未返回任何 CID / cross-view 记录。"))
            : kernelText("kernel.cid.empty.no_matches", QStringLiteral("当前筛选条件没有命中 CID / cross-view 记录。"));
        const QString kDetailText = buildDiagnosticDetailText(kReasonText);
        insertDiagnosticRow(
            rows_.empty()
                ? kernelText("kernel.cid.placeholder.no_records", QStringLiteral("<无 CID 记录>"))
                : kernelText("kernel.cid.placeholder.no_matches", QStringLiteral("<筛选无结果>")),
            kReasonText,
            kDetailText);
        table_->setCurrentCell(0, static_cast<int>(CidColumn::kKind));
        scheduleDetailRefresh();
        return;
    }

    const int kTargetRow = table_->currentRow() >= 0 ? table_->currentRow() : 0;
    table_->setCurrentCell(qMin(kTargetRow, table_->rowCount() - 1), static_cast<int>(CidColumn::kKind));
    scheduleDetailRefresh();
}

void KernelDockCidTab::showContextMenu(const QPoint& localPosition)
{
    if (table_ == nullptr)
    {
        return;
    }

    const QModelIndex kClickedIndex = table_->indexAt(localPosition);
    if (kClickedIndex.isValid())
    {
        table_->setCurrentCell(kClickedIndex.row(), kClickedIndex.column());
    }

    QMenu menu(this);
    menu.setStyleSheet(menuStyle());
    QAction* copyRowAction = menu.addAction(kernelText("kernel.cid.menu.copy_row", QStringLiteral("复制当前行")));
    copyRowAction->setEnabled(table_->currentRow() >= 0);
    const CidEvidenceRow* evidenceRow = selectedRow();
    QAction* openProcessAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_details.svg")),
        QStringLiteral("转到进程详细信息"));
    openProcessAction->setEnabled(evidenceRow != nullptr && evidenceRow->processId != 0U);
    const QAction* selectedAction = menu.exec(table_->viewport()->mapToGlobal(localPosition));
    if (selectedAction == copyRowAction)
    {
        copyCurrentRow();
    }
    else if (selectedAction == openProcessAction && evidenceRow != nullptr)
    {
        ks::ui::openProcessDetailByPid(evidenceRow->processId);
    }
}

void KernelDockCidTab::copyCurrentRow() const
{
    if (table_ == nullptr || QApplication::clipboard() == nullptr)
    {
        return;
    }

    const int kRowIndex = table_->currentRow();
    if (kRowIndex < 0)
    {
        return;
    }

    QStringList fields;
    for (int columnIndex = 0; columnIndex < table_->columnCount(); ++columnIndex)
    {
        const QTableWidgetItem* item = table_->item(kRowIndex, columnIndex);
        fields.push_back(item != nullptr ? item->text() : QString());
    }
    QApplication::clipboard()->setText(fields.join('\t'));
}

const KernelDockCidTab::CidEvidenceRow* KernelDockCidTab::selectedRow() const
{
    if (table_ == nullptr || table_->currentRow() < 0)
    {
        return nullptr;
    }

    const QTableWidgetItem* kindItem = table_->item(table_->currentRow(), static_cast<int>(CidColumn::kKind));
    if (kindItem == nullptr)
    {
        return nullptr;
    }
    const QString kDiagnosticText = kindItem->data(Qt::UserRole + 2).toString();
    if (!kDiagnosticText.isEmpty())
    {
        return nullptr;
    }

    const std::size_t kSourceIndex = static_cast<std::size_t>(kindItem->data(Qt::UserRole).toULongLong());
    return kSourceIndex < rows_.size() ? &rows_[kSourceIndex] : nullptr;
}

QString KernelDockCidTab::buildDetailText(const CidEvidenceRow* row) const
{
    if (row == nullptr)
    {
        if (table_ != nullptr && table_->currentRow() >= 0)
        {
            // Diagnostic row details:
            // - Input: Current table row, Kind column, UserRole + 2;
            // - Processing: When the table is empty or filtering yields no matches, prioritize displaying the full diagnostic text.
            // - Returns: If not a diagnostic row, continue providing a regular selection prompt.
            const QTableWidgetItem* kindItem = table_->item(table_->currentRow(), static_cast<int>(CidColumn::kKind));
            const QString kDiagnosticText = kindItem != nullptr
                ? kindItem->data(Qt::UserRole + 2).toString()
                : QString();
            if (!kDiagnosticText.isEmpty())
            {
                return kDiagnosticText;
            }
        }
        return kernelText("kernel.cid.detail.unavailable", QStringLiteral("请选择一条 cross-view 记录查看详情。"));
    }

    QStringList lines;
    lines << QStringLiteral("[CrossView]");
    if (cidSummary_.queried)
    {
        lines << QStringLiteral("[R0 CID Table Summary]");
        lines << QStringLiteral("PspCidTable address：%1").arg(formatHex64(cidSummary_.pspCidTableAddress));
        lines << QStringLiteral("returnedCount / totalCount：%1 / %2").arg(cidSummary_.returnedCount).arg(cidSummary_.totalCount);
        lines << QStringLiteral("status：%1 (%2)").arg(formatHex32(cidSummary_.status), cidEnumStatusText(cidSummary_.status));
        lines << kernelText("kernel.cid.detail.truncated", QStringLiteral("truncated：%1")).arg(cidSummaryTruncated(cidSummary_)
            ? kernelText("kernel.cid.value.yes", QStringLiteral("是"))
            : kernelText("kernel.cid.value.no", QStringLiteral("否")));
        lines << QStringLiteral("visitedCount / maxVisitCount：%1 / %2").arg(cidSummary_.visitedCount).arg(cidSummary_.maxVisitCount);
        lines << QStringLiteral("responseFlags：%1").arg(formatHex32(cidSummary_.flags));
        lines << QStringLiteral("lastStatus：%1").arg(statusLabelText(cidSummary_.lastStatus));
        lines << QStringLiteral("DynDataCapabilityMask：%1").arg(formatHex64(cidSummary_.dynDataCapabilityMask));
        lines << QStringLiteral("HtTableCodeOffset：%1").arg(formatHex32(cidSummary_.htTableCodeOffset));
        lines << QStringLiteral("HteLowValueOffset：%1").arg(formatHex32(cidSummary_.hteLowValueOffset));
        lines << kernelText("kernel.cid.detail.r3r0_note", QStringLiteral("R3/R0 说明：%1")).arg(safeText(cidSummary_.messageText));
        lines << QStringLiteral("");
    }
    lines << kernelText("kernel.cid.detail.kind", QStringLiteral("类型：%1")).arg(roleText(row->isThread));
    lines << kernelText("kernel.cid.detail.source", QStringLiteral("来源：%1")).arg(row->isRawCid ? QStringLiteral("R0 enumCidTable") : QStringLiteral("Process/Thread cross-view"));
    lines << kernelText("kernel.cid.detail.cid", QStringLiteral("CID：%1")).arg(row->cidValue == 0U ? emptyText() : QString::number(row->cidValue));
    lines << kernelText("kernel.cid.detail.cid_handle_index", QStringLiteral("CID HandleIndex：%1")).arg(row->cidHandleIndex);
    lines << kernelText("kernel.cid.detail.cid_entry_kind", QStringLiteral("CID EntryKind：%1 (%2)")).arg(formatHex32(row->cidExpectedKind), cidKindText(row->cidExpectedKind));
    lines << kernelText("kernel.cid.detail.cid_entry_flags", QStringLiteral("CID EntryFlags：%1 (%2)")).arg(formatHex32(row->cidEntryFlags), cidEntryFlagsText(row->cidEntryFlags));
    lines << kernelText("kernel.cid.detail.cid_reference_status", QStringLiteral("CID ReferenceStatus：%1")).arg(statusLabelText(row->cidReferenceStatus));
    lines << QStringLiteral("PID：%1").arg(row->processId);
    lines << kernelText("kernel.cid.detail.tid", QStringLiteral("TID：%1")).arg(row->threadId == 0U ? emptyText() : QString::number(row->threadId));
    lines << kernelText("kernel.cid.detail.parent_pid", QStringLiteral("父 PID：%1")).arg(row->parentProcessId == 0U ? emptyText() : QString::number(row->parentProcessId));
    lines << kernelText("kernel.cid.detail.object_address", QStringLiteral("对象地址：%1")).arg(formatHex64(row->objectAddress));
    lines << kernelText("kernel.cid.detail.process_object_address", QStringLiteral("进程对象地址：%1")).arg(formatHex64(row->processObjectAddress));
    lines << kernelText("kernel.cid.detail.start_address", QStringLiteral("起始地址：%1")).arg(formatHex64(row->startAddress));
    lines << kernelText("kernel.cid.detail.image", QStringLiteral("图像名：%1")).arg(safeText(row->imageNameText));
    lines << QStringLiteral("SourceMask：%1 (%2)").arg(formatHex32(row->sourceMask), sourceMaskText(row->sourceMask));
    lines << QStringLiteral("AnomalyFlags：%1 (%2)").arg(formatHex32(row->anomalyFlags), anomalyFlagsText(row->anomalyFlags));
    lines << QStringLiteral("Confidence：%1").arg(row->confidence);
    lines << QStringLiteral("DetailStatus：%1 (%2)").arg(formatHex32(row->detailStatus), detailStatusText(row->detailStatus));
    lines << QStringLiteral("DenoiseFlags：%1 (%2)").arg(formatHex32(row->denoiseFlags), denoiseFlagsText(row->denoiseFlags));
    lines << QStringLiteral("LastStatus：%1").arg(statusLabelText(row->lastStatus));
    lines << QStringLiteral("DynDataCapabilityMask：%1").arg(formatHex64(row->dynDataCapabilityMask));
    lines << QStringLiteral("PublicProcessId: %1").arg(row->publicProcessId == 0U ? emptyText() : QString::number(row->publicProcessId));
    lines << QStringLiteral("ActiveListProcessId: %1").arg(row->activeListProcessId == 0U ? emptyText() : QString::number(row->activeListProcessId));
    lines << QStringLiteral("CidTableProcessId: %1").arg(row->cidTableProcessId == 0U ? emptyText() : QString::number(row->cidTableProcessId));
    lines << QStringLiteral("PublicThreadId: %1").arg(row->publicThreadId == 0U ? emptyText() : QString::number(row->publicThreadId));
    lines << QStringLiteral("ThreadListThreadId: %1").arg(row->threadListThreadId == 0U ? emptyText() : QString::number(row->threadListThreadId));
    lines << QStringLiteral("CidTableThreadId: %1").arg(row->cidTableThreadId == 0U ? emptyText() : QString::number(row->cidTableThreadId));
    lines << QStringLiteral("ThreadListProcessId: %1").arg(row->threadListProcessId == 0U ? emptyText() : QString::number(row->threadListProcessId));
    lines << QStringLiteral("PublicWalkStatus：%1").arg(statusLabelText(row->publicWalkStatus));
    lines << QStringLiteral("ActiveListStatus：%1").arg(statusLabelText(row->activeListStatus));
    lines << QStringLiteral("ThreadListStatus：%1").arg(statusLabelText(row->threadListStatus));
    lines << QStringLiteral("CidTableStatus：%1").arg(statusLabelText(row->cidTableStatus));
    lines << QStringLiteral("StartAddressStatus：%1").arg(statusLabelText(row->startAddressStatus));
    lines << QStringLiteral("");
    lines << kernelText("kernel.cid.detail.detail_header", QStringLiteral("详情："));
    lines << safeText(row->detailText, kernelText("kernel.cid.placeholder.no_detail", QStringLiteral("<无详情>")));

    // [KernelObjectSummary] The segment requires a driver IOCTL, which has been offloaded to the background task in
    // requestKernelObjectSummaryAsync; this function performs pure formatting and can return immediately upon selection change.
    return lines.join('\n');
}

void KernelDockCidTab::scheduleDetailRefresh()
{
    // scheduleDetailRefresh：
    // - Purpose: Immediately render local details upon row selection or table content change, and push the R0 object summary request into the debounce window.
    // - Input parameters: none, directly read the currently selected row;
    // - Return: None. All pending object summary re-injections are invalidated.
    ++detailGeneration_;

    const CidEvidenceRow* row = selectedRow();
    detailBaseText_ = buildDetailText(row);
    if (detailEditor_ != nullptr)
    {
        detailEditor_->setText(detailBaseText_);
    }

    if (detailRequestTimer_ == nullptr || row == nullptr)
    {
        return;
    }
    const unsigned long kCidValue = row->cidValue != 0U
        ? row->cidValue
        : (row->isThread ? row->threadId : row->processId);
    if (kCidValue == 0U)
    {
        return;
    }
    detailRequestTimer_->start();
}

void KernelDockCidTab::requestKernelObjectSummaryAsync()
{
    // requestKernelObjectSummaryAsync：
    // - Purpose: Move the CreateFileW + synchronous IOCTL calls from queryKernelObjectSummary to the thread pool to prevent UI blocking due to high key press frequency.
    // - Input parameters: none; generate request parameters based on the currently selected row;
    // - Return: No return value; results are dispatched via QMetaObject::invokeMethod and evicted by generation.
    const CidEvidenceRow* row = selectedRow();
    if (row == nullptr)
    {
        return;
    }

    const unsigned long kTargetKind = row->cidExpectedKind != KSWORD_ARK_CID_OBJECT_KIND_UNKNOWN
        ? row->cidExpectedKind
        : (row->isThread ? KSWORD_ARK_CID_OBJECT_KIND_THREAD : KSWORD_ARK_CID_OBJECT_KIND_PROCESS);
    const unsigned long kCidValue = row->cidValue != 0U
        ? row->cidValue
        : (row->isThread ? row->threadId : row->processId);
    if (kCidValue == 0U)
    {
        return;
    }
    const std::uint64_t kObjectAddress = row->objectAddress;

    const QPointer<KernelDockCidTab> kGuardedSelf(this);
    const std::uint64_t kRequestGeneration = detailGeneration_;
    QThreadPool::globalInstance()->start(
        [kGuardedSelf, kRequestGeneration, kTargetKind, kCidValue, kObjectAddress]()
        {
            const ksword::ark::DriverClient kClient;
            const ksword::ark::KernelObjectSummaryAuditResult kSummary =
                kClient.queryKernelObjectSummary(kTargetKind, kCidValue, kObjectAddress);
            const QString kSummaryText = formatKernelObjectSummaryText(kSummary);

            QCoreApplication* const kAppInstance = QCoreApplication::instance();
            if (kAppInstance == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(kAppInstance,
                [kGuardedSelf, kRequestGeneration, kSummaryText]()
                {
                    if (kGuardedSelf == nullptr)
                    {
                        return;
                    }
                    if (kGuardedSelf->detailGeneration_ != kRequestGeneration)
                    {
                        return;
                    }
                    kGuardedSelf->appendKernelObjectSummaryText(kSummaryText);
                });
        });
}

void KernelDockCidTab::appendKernelObjectSummaryText(const QString& summaryText)
{
    // appendKernelObjectSummaryText：
    // - Input parameter summaryText: the [KernelObjectSummary] segment formatted by the background thread;
    // - Processing: Append to the local detail text, ensuring CodeEditorWidget is only accessed on the UI thread;
    // - Returns: Nothing.
    if (detailEditor_ == nullptr)
    {
        return;
    }
    detailEditor_->setText(detailBaseText_ + summaryText);
}

QString KernelDockCidTab::formatKernelObjectSummaryText(const ksword::ark::KernelObjectSummaryAuditResult& summary)
{
    // formatKernelObjectSummaryText：
    // - Input summary: the pure value-type audit result returned by queryKernelObjectSummary;
    // - Handling: Performs only string formatting; safe to execute on a background thread.
    // - Returns: a detail append segment starting with an empty line, ready to be appended directly to local detail text.
    const auto& response = summary.response;
    QStringList lines;
    lines << QStringLiteral("");
    lines << QStringLiteral("");
    lines << QStringLiteral("[KernelObjectSummary]");
    lines << kernelText("kernel.cid.detail.io_summary", QStringLiteral("IO：%1，unsupported=%2，说明=%3"))
        .arg(summary.io.ok ? QStringLiteral("OK") : QStringLiteral("FAIL"))
        .arg(summary.unsupported ? QStringLiteral("true") : QStringLiteral("false"))
        .arg(friendlyIoMessage(QString::fromStdString(summary.io.message)));
    lines << QStringLiteral("Status：%1 (%2)").arg(formatHex32(response.status), objectSummaryStatusText(response.status));
    lines << QStringLiteral("FieldFlags：%1").arg(formatHex32(response.fieldFlags));
    lines << QStringLiteral("TargetKind：%1 (%2)").arg(formatHex32(response.targetKind), cidKindText(response.targetKind));
    lines << QStringLiteral("CidValue：%1").arg(response.cidValue);
    lines << QStringLiteral("LookupStatus：%1").arg(statusLabelText(response.lookupStatus));
    lines << QStringLiteral("TypeStatus：%1").arg(statusLabelText(response.typeStatus));
    lines << QStringLiteral("CounterStatus：%1").arg(statusLabelText(response.counterStatus));
    lines << QStringLiteral("ObjectHeaderStatus：%1 (%2)").arg(formatHex32(response.objectHeaderStatus), objectHeaderStatusText(response.objectHeaderStatus));
    lines << QStringLiteral("ObjectAddress：%1").arg(formatHex64(response.objectAddress));
    lines << QStringLiteral("ExpectedObjectAddress：%1").arg(formatHex64(response.expectedObjectAddress));
    lines << QStringLiteral("ObjectTypeAddress：%1").arg(formatHex64(response.objectTypeAddress));
    lines << QStringLiteral("TypeIndex：%1").arg(response.typeIndex);
    lines << QStringLiteral("PointerCount：%1").arg(response.pointerCount);
    lines << QStringLiteral("HandleCount：%1").arg(response.handleCount);
    lines << QStringLiteral("TypeName：%1").arg(safeText(fixedWideText(response.typeName, KSWORD_ARK_KERNEL_OBJECT_TYPE_NAME_CHARS)));
    lines << QStringLiteral("Detail：%1").arg(safeText(fixedWideText(response.detail, KSWORD_ARK_KERNEL_OBJECT_DETAIL_CHARS)));
    lines << QStringLiteral("DynDataCapabilityMask：%1").arg(formatHex64(response.dynDataCapabilityMask));
    lines << QStringLiteral("OtNameOffset：%1").arg(formatHex32(response.otNameOffset));
    lines << QStringLiteral("OtIndexOffset：%1").arg(formatHex32(response.otIndexOffset));
    return lines.join('\n');
}

QString KernelDockCidTab::buildDiagnosticDetailText(const QString& reasonText) const
{
    // buildDiagnosticDetailText：
    // - Input: empty table or reason for filtering empty hits;
    // - Processing: Supplement CID summary, filter keywords, and actionable troubleshooting directions.
    // - Return: Multi-line text reused for the details panel and diagnostic row.
    QStringList lines;
    lines << QStringLiteral("[CID / CrossView Diagnostic]");
    lines << kernelText("kernel.cid.diagnostic.reason", QStringLiteral("原因：%1")).arg(safeText(reasonText));
    lines << kernelText("kernel.cid.diagnostic.filter", QStringLiteral("当前筛选：%1")).arg(filterEdit_ != nullptr
        ? safeText(filterEdit_->text().trimmed(), kernelText("kernel.cid.placeholder.no_filter", QStringLiteral("<无筛选>")))
        : kernelText("kernel.cid.placeholder.no_filter_widget", QStringLiteral("<无筛选控件>")));
    lines << kernelText("kernel.cid.diagnostic.source_total", QStringLiteral("源记录总数：%1")).arg(static_cast<qulonglong>(rows_.size()));
    if (cidSummary_.queried)
    {
        lines << QStringLiteral("");
        lines << QStringLiteral("[R0 CID Table Summary]");
        lines << QStringLiteral("IO：%1").arg(cidSummary_.ok ? QStringLiteral("OK") : QStringLiteral("Unavailable"));
        lines << kernelText("kernel.cid.diagnostic.unsupported", QStringLiteral("Unsupported：%1")).arg(cidSummary_.unsupported
            ? kernelText("kernel.cid.value.yes", QStringLiteral("是"))
            : kernelText("kernel.cid.value.no", QStringLiteral("否")));
        lines << QStringLiteral("PspCidTable：%1").arg(formatHex64(cidSummary_.pspCidTableAddress));
        lines << QStringLiteral("returnedCount / totalCount：%1 / %2").arg(cidSummary_.returnedCount).arg(cidSummary_.totalCount);
        lines << QStringLiteral("visitedCount / maxVisitCount：%1 / %2").arg(cidSummary_.visitedCount).arg(cidSummary_.maxVisitCount);
        lines << QStringLiteral("status：%1 (%2)").arg(formatHex32(cidSummary_.status), cidEnumStatusText(cidSummary_.status));
        lines << kernelText("kernel.cid.diagnostic.truncated", QStringLiteral("truncated：%1")).arg(cidSummaryTruncated(cidSummary_)
            ? kernelText("kernel.cid.value.yes", QStringLiteral("是"))
            : kernelText("kernel.cid.value.no", QStringLiteral("否")));
        lines << QStringLiteral("lastStatus：%1").arg(statusLabelText(cidSummary_.lastStatus));
        lines << QStringLiteral("DynDataCapabilityMask：%1").arg(formatHex64(cidSummary_.dynDataCapabilityMask));
        lines << kernelText("kernel.cid.detail.r3r0_note", QStringLiteral("R3/R0 说明：%1")).arg(safeText(cidSummary_.messageText));
    }
    lines << QStringLiteral("");
    lines << kernelText("kernel.cid.diagnostic.recommendations", QStringLiteral("[排查建议]"));
    lines << kernelText("kernel.cid.diagnostic.recommendation1", QStringLiteral("1. 若显示 capability/DynData 不足，请先查看 Kernel -> DynData 页确认 Process/Thread/CID 相关能力位。"));
    lines << kernelText("kernel.cid.diagnostic.recommendation2", QStringLiteral("2. 若当前筛选不为空，清空筛选框后再确认是否有源记录。"));
    lines << kernelText("kernel.cid.diagnostic.recommendation3", QStringLiteral("3. 若 returnedCount 为 0 或 PspCidTable 为空，说明当前驱动/动态偏移还没有提供可用 CID 表证据。"));
    return lines.join('\n');
}

void KernelDockCidTab::insertDiagnosticRow(
    const QString& titleText,
    const QString& statusText,
    const QString& detailText)
{
    // insertDiagnosticRow：
    // - Input: Diagnosis title, status column text, and detail text.
    // - Handling: Construct a single read-only placeholder row where all columns are copyable via right-click.
    // - Return: None. UserRole + 2 stores the detail area text.
    if (table_ == nullptr)
    {
        return;
    }

    table_->setSortingEnabled(false);
    table_->setRowCount(1);

    auto* kindItem = readOnlyItem(titleText);
    kindItem->setData(Qt::UserRole + 2, detailText);
    table_->setItem(0, static_cast<int>(CidColumn::kKind), kindItem);
    table_->setItem(0, static_cast<int>(CidColumn::kCidValue), readOnlyItem(kernelText("kernel.cid.placeholder.diagnostic", QStringLiteral("<诊断>"))));
    table_->setItem(0, static_cast<int>(CidColumn::kProcessId), readOnlyItem(emptyText()));
    table_->setItem(0, static_cast<int>(CidColumn::kThreadId), readOnlyItem(emptyText()));
    table_->setItem(0, static_cast<int>(CidColumn::kImage), readOnlyItem(QStringLiteral("CID / CrossView")));
    table_->setItem(0, static_cast<int>(CidColumn::kObjectAddress), readOnlyItem(formatHex64(0)));
    table_->setItem(0, static_cast<int>(CidColumn::kStartAddress), readOnlyItem(formatHex64(0)));
    table_->setItem(0, static_cast<int>(CidColumn::kSourceMask), readOnlyItem(kernelText("kernel.cid.placeholder.no_source", QStringLiteral("<无源>"))));
    table_->setItem(0, static_cast<int>(CidColumn::kAnomalyFlags), readOnlyItem(kernelText("kernel.cid.placeholder.none", QStringLiteral("<无>"))));
    table_->setItem(0, static_cast<int>(CidColumn::kCidEntryFlags), readOnlyItem(kernelText("kernel.cid.placeholder.none", QStringLiteral("<无>"))));
    table_->setItem(0, static_cast<int>(CidColumn::kConfidence), readOnlyItem(QStringLiteral("0")));
    table_->setItem(0, static_cast<int>(CidColumn::kDetailStatus), readOnlyItem(QStringLiteral("Diagnostic")));
    table_->setItem(0, static_cast<int>(CidColumn::kDenoise), readOnlyItem(kernelText("kernel.cid.placeholder.none", QStringLiteral("<无>"))));
    table_->setItem(0, static_cast<int>(CidColumn::kStatus), readOnlyItem(statusText));
    table_->setSortingEnabled(true);
}

bool KernelDockCidTab::rowMatchesFilter(const CidEvidenceRow& row) const
{
    const QString kKeyword = filterEdit_ != nullptr ? filterEdit_->text().trimmed() : QString();
    if (kKeyword.isEmpty())
    {
        return true;
    }

    return roleText(row.isThread).contains(kKeyword, Qt::CaseInsensitive) ||
        QString::number(row.processId).contains(kKeyword, Qt::CaseInsensitive) ||
        QString::number(row.threadId).contains(kKeyword, Qt::CaseInsensitive) ||
        QString::number(row.cidValue).contains(kKeyword, Qt::CaseInsensitive) ||
        cidKindText(row.cidExpectedKind).contains(kKeyword, Qt::CaseInsensitive) ||
        cidEntryFlagsText(row.cidEntryFlags).contains(kKeyword, Qt::CaseInsensitive) ||
        safeText(row.imageNameText).contains(kKeyword, Qt::CaseInsensitive) ||
        formatHex64(row.objectAddress).contains(kKeyword, Qt::CaseInsensitive) ||
        formatHex64(row.startAddress).contains(kKeyword, Qt::CaseInsensitive) ||
        sourceMaskText(row.sourceMask).contains(kKeyword, Qt::CaseInsensitive) ||
        anomalyFlagsText(row.anomalyFlags).contains(kKeyword, Qt::CaseInsensitive) ||
        denoiseFlagsText(row.denoiseFlags).contains(kKeyword, Qt::CaseInsensitive) ||
        detailStatusText(row.detailStatus).contains(kKeyword, Qt::CaseInsensitive) ||
        statusLabelText(row.lastStatus).contains(kKeyword, Qt::CaseInsensitive) ||
        row.detailText.contains(kKeyword, Qt::CaseInsensitive);
}

QTableWidgetItem* KernelDockCidTab::readOnlyItem(const QString& text)
{
    auto* item = new QTableWidgetItem(text);
    item->setFlags(item->flags() & ~Qt::ItemIsEditable);
    return item;
}

QString KernelDockCidTab::formatHex32(const std::uint32_t value)
{
    return QStringLiteral("0x%1").arg(value, 8, 16, QChar('0')).toUpper();
}

QString KernelDockCidTab::formatHex64(const std::uint64_t value)
{
    return QStringLiteral("0x%1").arg(static_cast<qulonglong>(value), 16, 16, QChar('0')).toUpper();
}

QString KernelDockCidTab::statusLabelText(const long statusValue)
{
    return formatHex32(static_cast<std::uint32_t>(statusValue));
}

QString KernelDockCidTab::sourceMaskText(const std::uint32_t mask)
{
    QStringList parts;
    if ((mask & KSWORD_ARK_CROSSVIEW_SOURCE_PUBLIC_WALK) != 0U) { parts << QStringLiteral("PublicWalk"); }
    if ((mask & KSWORD_ARK_CROSSVIEW_SOURCE_ACTIVE_LIST) != 0U) { parts << QStringLiteral("ActiveList"); }
    if ((mask & KSWORD_ARK_CROSSVIEW_SOURCE_CID_TABLE) != 0U) { parts << QStringLiteral("CidTable"); }
    if ((mask & KSWORD_ARK_CROSSVIEW_SOURCE_THREAD_LIST) != 0U) { parts << QStringLiteral("ThreadList"); }
    if (parts.isEmpty()) { parts << emptyText(); }
    return QStringLiteral("%1 [%2]").arg(formatHex32(mask), parts.join(QStringLiteral(", ")));
}

QString KernelDockCidTab::anomalyFlagsText(const std::uint32_t flags)
{
    QStringList parts;
    if ((flags & KSWORD_ARK_CROSSVIEW_ANOMALY_CID_ONLY) != 0U) { parts << QStringLiteral("CID_ONLY"); }
    if ((flags & KSWORD_ARK_CROSSVIEW_ANOMALY_ACTIVE_ONLY) != 0U) { parts << QStringLiteral("ACTIVE_ONLY"); }
    if ((flags & KSWORD_ARK_CROSSVIEW_ANOMALY_MISSING_FROM_ACTIVE_LIST) != 0U) { parts << QStringLiteral("MISSING_FROM_ACTIVE_LIST"); }
    if ((flags & KSWORD_ARK_CROSSVIEW_ANOMALY_MISSING_FROM_CID_TABLE) != 0U) { parts << QStringLiteral("MISSING_FROM_CID_TABLE"); }
    if ((flags & KSWORD_ARK_CROSSVIEW_ANOMALY_THREAD_ORPHAN) != 0U) { parts << QStringLiteral("THREAD_ORPHAN"); }
    if ((flags & KSWORD_ARK_CROSSVIEW_ANOMALY_THREAD_NOT_IN_PROCESS_LIST) != 0U) { parts << QStringLiteral("THREAD_NOT_IN_PROCESS_LIST"); }
    if ((flags & KSWORD_ARK_CROSSVIEW_ANOMALY_START_ADDRESS_OUTSIDE_MODULE) != 0U) { parts << QStringLiteral("START_ADDRESS_OUTSIDE_MODULE"); }
    if ((flags & KSWORD_ARK_CROSSVIEW_ANOMALY_DANGLING_OBJECT) != 0U) { parts << QStringLiteral("DANGLING_OBJECT"); }
    if ((flags & KSWORD_ARK_CROSSVIEW_ANOMALY_PID_FIELD_MISMATCH) != 0U) { parts << QStringLiteral("PID_FIELD_MISMATCH"); }
    if (parts.isEmpty()) { parts << emptyText(); }
    return QStringLiteral("%1 [%2]").arg(formatHex32(flags), parts.join(QStringLiteral(", ")));
}

QString KernelDockCidTab::denoiseFlagsText(const std::uint32_t flags)
{
    QStringList parts;
    if ((flags & KSWORD_ARK_CROSSVIEW_DENOISE_PARTIAL_EVIDENCE) != 0U) { parts << QStringLiteral("PARTIAL_EVIDENCE"); }
    if ((flags & KSWORD_ARK_CROSSVIEW_DENOISE_READ_FAILURE) != 0U) { parts << QStringLiteral("READ_FAILURE"); }
    if ((flags & KSWORD_ARK_CROSSVIEW_DENOISE_REFERENCE_FAILURE) != 0U) { parts << QStringLiteral("REFERENCE_FAILURE"); }
    if ((flags & KSWORD_ARK_CROSSVIEW_DENOISE_POSSIBLE_TERMINATING) != 0U) { parts << QStringLiteral("POSSIBLE_TERMINATING"); }
    if ((flags & KSWORD_ARK_CROSSVIEW_DENOISE_UNSUPPORTED_PDB_FIELD) != 0U) { parts << QStringLiteral("UNSUPPORTED_PDB_FIELD"); }
    if (parts.isEmpty()) { parts << emptyText(); }
    return QStringLiteral("%1 [%2]").arg(formatHex32(flags), parts.join(QStringLiteral(", ")));
}

QString KernelDockCidTab::detailStatusText(const std::uint32_t status)
{
    switch (status)
    {
    case KSWORD_ARK_CROSSVIEW_DETAIL_STATUS_OK: return QStringLiteral("OK");
    case KSWORD_ARK_CROSSVIEW_DETAIL_STATUS_PARTIAL: return QStringLiteral("PARTIAL");
    case KSWORD_ARK_CROSSVIEW_DETAIL_STATUS_UNSUPPORTED: return QStringLiteral("UNSUPPORTED");
    case KSWORD_ARK_CROSSVIEW_DETAIL_STATUS_READ_FAILED: return QStringLiteral("READ_FAILED");
    case KSWORD_ARK_CROSSVIEW_DETAIL_STATUS_DATA_MISMATCH: return QStringLiteral("DATA_MISMATCH");
    default: return QStringLiteral("UNKNOWN(%1)").arg(status);
    }
}

QString KernelDockCidTab::roleText(bool isThread)
{
    return isThread ? QStringLiteral("Thread") : QStringLiteral("Process");
}

QString KernelDockCidTab::cidKindText(const std::uint32_t kind)
{
    switch (kind)
    {
    case KSWORD_ARK_CID_OBJECT_KIND_PROCESS: return QStringLiteral("Process");
    case KSWORD_ARK_CID_OBJECT_KIND_THREAD: return QStringLiteral("Thread");
    case KSWORD_ARK_CID_OBJECT_KIND_UNKNOWN:
    default:
        return QStringLiteral("Unknown");
    }
}

QString KernelDockCidTab::cidEntryFlagsText(const std::uint32_t flags)
{
    QStringList parts;
    if ((flags & KSWORD_ARK_CID_ENTRY_FLAG_DANGLING) != 0U) { parts << QStringLiteral("DANGLING"); }
    if ((flags & KSWORD_ARK_CID_ENTRY_FLAG_TYPE_MISMATCH) != 0U) { parts << QStringLiteral("TYPE_MISMATCH"); }
    if ((flags & KSWORD_ARK_CID_ENTRY_FLAG_REFERENCED) != 0U) { parts << QStringLiteral("REFERENCED"); }
    if (parts.isEmpty()) { parts << emptyText(); }
    return QStringLiteral("%1 [%2]").arg(formatHex32(flags), parts.join(QStringLiteral(", ")));
}

QString KernelDockCidTab::cidEnumStatusText(const std::uint32_t status)
{
    switch (status)
    {
    case KSWORD_ARK_CID_ENUM_STATUS_OK: return QStringLiteral("OK");
    case KSWORD_ARK_CID_ENUM_STATUS_PARTIAL: return QStringLiteral("PARTIAL");
    case KSWORD_ARK_CID_ENUM_STATUS_DYNDATA_MISSING: return QStringLiteral("DYNDATA_MISSING");
    case KSWORD_ARK_CID_ENUM_STATUS_PSPCID_UNAVAILABLE: return QStringLiteral("PSPCID_UNAVAILABLE");
    case KSWORD_ARK_CID_ENUM_STATUS_TYPE_UNAVAILABLE: return QStringLiteral("TYPE_UNAVAILABLE");
    case KSWORD_ARK_CID_ENUM_STATUS_BUFFER_TRUNCATED: return QStringLiteral("BUFFER_TRUNCATED");
    case KSWORD_ARK_CID_ENUM_STATUS_BUDGET_EXHAUSTED: return QStringLiteral("BUDGET_EXHAUSTED");
    case KSWORD_ARK_CID_ENUM_STATUS_UNAVAILABLE:
    default:
        return QStringLiteral("UNAVAILABLE");
    }
}

QString KernelDockCidTab::objectSummaryStatusText(const std::uint32_t status)
{
    switch (status)
    {
    case KSWORD_ARK_OBJECT_SUMMARY_STATUS_OK: return QStringLiteral("OK");
    case KSWORD_ARK_OBJECT_SUMMARY_STATUS_PARTIAL: return QStringLiteral("PARTIAL");
    case KSWORD_ARK_OBJECT_SUMMARY_STATUS_UNSUPPORTED_TARGET: return QStringLiteral("UNSUPPORTED_TARGET");
    case KSWORD_ARK_OBJECT_SUMMARY_STATUS_LOOKUP_FAILED: return QStringLiteral("LOOKUP_FAILED");
    case KSWORD_ARK_OBJECT_SUMMARY_STATUS_TYPE_QUERY_FAILED: return QStringLiteral("TYPE_QUERY_FAILED");
    case KSWORD_ARK_OBJECT_SUMMARY_STATUS_COUNTERS_UNAVAILABLE: return QStringLiteral("COUNTERS_UNAVAILABLE");
    case KSWORD_ARK_OBJECT_SUMMARY_STATUS_UNAVAILABLE:
    default:
        return QStringLiteral("UNAVAILABLE");
    }
}

QString KernelDockCidTab::objectHeaderStatusText(const std::uint32_t status)
{
    switch (status)
    {
    case KSWORD_ARK_OBJECT_HEADER_STATUS_PROFILE_MISSING: return QStringLiteral("PROFILE_MISSING");
    case KSWORD_ARK_OBJECT_HEADER_STATUS_PARTIAL_PROFILE: return QStringLiteral("PARTIAL_PROFILE");
    case KSWORD_ARK_OBJECT_HEADER_STATUS_AVAILABLE: return QStringLiteral("AVAILABLE");
    case KSWORD_ARK_OBJECT_HEADER_STATUS_UNAVAILABLE:
    default:
        return QStringLiteral("UNAVAILABLE");
    }
}

QString KernelDockCidTab::fixedWideText(const wchar_t* text, const std::size_t maxChars)
{
    if (text == nullptr || maxChars == 0U)
    {
        return {};
    }
    std::size_t length = 0U;
    while (length < maxChars && text[length] != L'\0')
    {
        ++length;
    }
    return QString::fromWCharArray(text, static_cast<int>(length));
}

bool KernelDockCidTab::cidSummaryTruncated(const CidTableSummary& summary)
{
    return summary.returnedCount < summary.totalCount ||
        summary.status == KSWORD_ARK_CID_ENUM_STATUS_BUFFER_TRUNCATED ||
        summary.status == KSWORD_ARK_CID_ENUM_STATUS_BUDGET_EXHAUSTED;
}
