#include "KernelObjectTypeMatrixTab.h"
#include "../ui/VisibleTableWidget.h"

// ============================================================
// KernelObjectTypeMatrixTab.cpp
// Purpose:
// 1) Displays object type statistics returned by NtQueryObject(ObjectTypesInformation).
// 2) Adds strategy hints for each object type regarding "whether enumeration can continue" or "which API to use";
// 3) Independent asynchronous page refresh to facilitate insertion into the object namespace's second-level tab.
// ============================================================

#include "KernelDockQueryWorker.h"
#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../ui/CodeEditorWidget.h"
#include "../ui/DetailLayoutRegistry.h"
#include "../ui/TableInteractionSupport.h"
#include "../Theme.h"

#include <QAbstractItemView>
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
#include <QPointer>
#include <QPushButton>
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

#include <thread>
#include <unordered_map>
#include <utility>

using ksword::kernel_dock_internal::kernelText;

namespace
{
    enum class ObjectTypeMatrixColumn : int
    {
        kTypeIndex = 0,
        kTypeName,
        kR0Address,
        kR0Validation,
        kObjectCount,
        kHandleCount,
        kAccessMask,
        kStrategy,
        kCount
    };

    QString statusLabelStyle(const QString& colorHex)
    {
        return QStringLiteral("color:%1;font-weight:600;").arg(colorHex);
    }

    QString formatR0Address(const std::uint64_t address)
    {
        if (address == 0ULL)
        {
            return QStringLiteral("-");
        }
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(address), 16, 16, QChar('0'))
            .toUpper();
    }

    QString fixedR0TypeName(const wchar_t* const text, const std::size_t maxChars)
    {
        if (text == nullptr || maxChars == 0U)
        {
            return QString();
        }

        std::size_t length = 0U;
        while (length < maxChars && text[length] != L'\0')
        {
            ++length;
        }
        return QString::fromWCharArray(text, static_cast<qsizetype>(length));
    }

    QString objectTypeR0ValidationText(const KernelObjectTypeEntry& entry)
    {
        if (!entry.r0ValidationText.isEmpty())
        {
            return entry.r0ValidationText;
        }
        if (!entry.r0Present)
        {
            return kernelText("kernel.object_type.r0.validation.not_returned", QStringLiteral("R0 未返回该槽"));
        }
        if (entry.r0Status == KSWORD_ARK_OBJECT_TYPE_ENTRY_STATUS_INDEX_MISMATCH)
        {
            return kernelText("kernel.object_type.r0.validation.index_mismatch", QStringLiteral("索引不一致"));
        }
        if (entry.r0Status == KSWORD_ARK_OBJECT_TYPE_ENTRY_STATUS_READ_FAILED)
        {
            return kernelText("kernel.object_type.r0.validation.read_failed", QStringLiteral("结构读取失败"));
        }

        const bool kIndexMatched =
            (entry.r0FieldFlags & KSWORD_ARK_OBJECT_TYPE_ENTRY_FIELD_INDEX_MATCH) != 0UL;
        const bool kNameMatched = entry.r3Present && !entry.r0TypeNameText.isEmpty() &&
            entry.typeNameText.compare(entry.r0TypeNameText, Qt::CaseInsensitive) == 0;
        if (kIndexMatched && (!entry.r3Present || entry.r0TypeNameText.isEmpty() || kNameMatched))
        {
            return kernelText("kernel.object_type.r0.validation.matched", QStringLiteral("槽/索引/名称一致"));
        }
        if (!entry.r0TypeNameText.isEmpty() && entry.r3Present && !kNameMatched)
        {
            return kernelText("kernel.object_type.r0.validation.name_mismatch", QStringLiteral("R0/R3 名称不一致"));
        }
        return kernelText("kernel.object_type.r0.validation.partial", QStringLiteral("部分验证"));
    }

    QString cellText(const KernelObjectTypeEntry& entry, const ObjectTypeMatrixColumn column)
    {
        switch (column)
        {
        case ObjectTypeMatrixColumn::kTypeIndex:
            return QString::number(entry.typeIndex);
        case ObjectTypeMatrixColumn::kTypeName:
            return entry.typeNameText;
        case ObjectTypeMatrixColumn::kR0Address:
            return formatR0Address(entry.r0ObjectTypeAddress);
        case ObjectTypeMatrixColumn::kR0Validation:
            return objectTypeR0ValidationText(entry);
        case ObjectTypeMatrixColumn::kObjectCount:
            return QString::number(entry.totalObjectCount);
        case ObjectTypeMatrixColumn::kHandleCount:
            return QString::number(entry.totalHandleCount);
        case ObjectTypeMatrixColumn::kAccessMask:
            return KernelObjectTypeMatrixTab::formatAccessMask(entry.validAccessMask);
        case ObjectTypeMatrixColumn::kStrategy:
            return KernelObjectTypeMatrixTab::strategyForType(entry.typeNameText);
        default:
            return QString();
        }
    }
}

KernelObjectTypeMatrixTab::KernelObjectTypeMatrixTab(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
    initializeConnections();
}

void KernelObjectTypeMatrixTab::requestInitialRefresh()
{
    if (initialRefreshRequested_)
    {
        return;
    }
    initialRefreshRequested_ = true;
    refreshAsync();
}

void KernelObjectTypeMatrixTab::initializeUi()
{
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(8, 8, 8, 8);
    rootLayout->setSpacing(6);

    auto* toolbarLayout = new QHBoxLayout();
    toolbarLayout->setContentsMargins(0, 0, 0, 0);
    toolbarLayout->setSpacing(6);

    refreshButton_ = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), this);
    ksword_theme::applyCompactIconButtonMetrics(refreshButton_);
    refreshButton_->setToolTip(kernelText("kernel.object_type.toolbar.refresh.tooltip", QStringLiteral("刷新对象类型统计")));
    refreshButton_->setStyleSheet(ksword_theme::themedButtonStyle());

    filterEdit_ = new QLineEdit(this);
    filterEdit_->setPlaceholderText(kernelText("kernel.object_type.toolbar.filter.placeholder", QStringLiteral("按类型名、编号、R0 地址或策略筛选")));
    filterEdit_->setClearButtonEnabled(true);

    statusLabel_ = new QLabel(kernelText("kernel.object_type.status.waiting", QStringLiteral("状态：等待刷新")), this);
    statusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::textSecondaryHex()));

    toolbarLayout->addWidget(refreshButton_, 0);
    toolbarLayout->addWidget(filterEdit_, 1);
    toolbarLayout->addWidget(statusLabel_, 0);
    rootLayout->addLayout(toolbarLayout);

    table_ = new ks::ui::VisibleTableWidget(this);
    table_->setColumnCount(static_cast<int>(ObjectTypeMatrixColumn::kCount));
    table_->setHorizontalHeaderLabels(QStringList{
        kernelText("kernel.object_type.header.index", QStringLiteral("类型编号")),
        kernelText("kernel.object_type.header.name", QStringLiteral("类型名")),
        kernelText("kernel.object_type.header.r0_address", QStringLiteral("R0 类型地址")),
        kernelText("kernel.object_type.header.r0_validation", QStringLiteral("R0 交叉验证")),
        kernelText("kernel.object_type.header.object_count", QStringLiteral("对象数")),
        kernelText("kernel.object_type.header.handle_count", QStringLiteral("句柄数")),
        kernelText("kernel.object_type.header.access_mask", QStringLiteral("访问掩码")),
        kernelText("kernel.object_type.header.strategy", QStringLiteral("枚举策略"))
        });
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setAlternatingRowColors(true);
    table_->setContextMenuPolicy(Qt::CustomContextMenu);
    table_->verticalHeader()->setVisible(false);
    table_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(static_cast<int>(ObjectTypeMatrixColumn::kStrategy), QHeaderView::Stretch);
    rootLayout->addWidget(table_, 2);

    // Detail area purpose:
    // - Input: currently selected object type in the table;
    // - Processing: Expand access masks, object/handle counts, enumeration policies, and subsequent drill-down suggestions.
    // - Returns void; writes text to the unified CodeEditorWidget to avoid leaving the new page with only a summary table.
    detailEditor_ = new CodeEditorWidget(this);
    detailEditor_->setReadOnly(true);
    detailEditor_->setText(kernelText("kernel.object_type.detail.select_hint", QStringLiteral("请选择一个对象类型查看枚举策略和下钻建议。")));
    rootLayout->addWidget(detailEditor_, 1);

    ks::ui::DetailLayoutRegistry::registerHost(table_, detailEditor_, this);
}

void KernelObjectTypeMatrixTab::initializeConnections()
{
    connect(refreshButton_, &QPushButton::clicked, this, [this]() {
        initialRefreshRequested_ = true;
        refreshAsync();
    });
    connect(filterEdit_, &QLineEdit::textChanged, this, [this]() {
        rebuildTable();
    });
    connect(table_, &QTableWidget::currentCellChanged, this, [this](const int currentRow, int, int, int) {
        updateDetailForRow(currentRow);
    });
    connect(table_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& localPosition) {
        showContextMenu(localPosition);
    });
}

void KernelObjectTypeMatrixTab::refreshAsync()
{
    if (refreshing_.exchange(true))
    {
        return;
    }

    refreshButton_->setEnabled(false);
    statusLabel_->setText(kernelText("kernel.object_type.status.refreshing", QStringLiteral("状态：刷新中...")));
    statusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::kPrimaryBlueHex));

    QPointer<KernelObjectTypeMatrixTab> guardThis(this);
    std::thread([guardThis]() {
        std::vector<KernelObjectTypeEntry> rows;
        QString errorText;
        const bool kR3Success = runKernelTypeSnapshotTask(rows, errorText);
        R0SnapshotState r0State{};
        r0State.attempted = true;

        const ksword::ark::ObjectTypeTableAuditResult kR0Result =
            ksword::ark::DriverClient().enumObjectTypeTable();
        r0State.transportOk = kR0Result.io.ok;
        r0State.unsupported = kR0Result.unsupported;
        r0State.status = kR0Result.status;
        r0State.flags = kR0Result.flags;
        r0State.lastStatus = kR0Result.lastStatus;
        r0State.tableAddress = kR0Result.tableAddress;
        r0State.snapshotHash = kR0Result.snapshotHash;
        r0State.dynDataCapabilityMask = kR0Result.dynDataCapabilityMask;
        r0State.otNameOffset = kR0Result.otNameOffset;
        r0State.otIndexOffset = kR0Result.otIndexOffset;
        r0State.returnedCount = kR0Result.returnedCount;

        if (!kR0Result.io.ok)
        {
            r0State.diagnosticText = kR0Result.unsupported
                ? kernelText("kernel.object_type.r0.old_driver", QStringLiteral("旧驱动不支持 Object Type Table IOCTL"))
                : kernelText("kernel.object_type.r0.query_failed", QStringLiteral("R0 Object Type Table 查询失败：%1"))
                    .arg(QString::fromStdString(kR0Result.io.message));
        }
        else if (kR0Result.tableAddress == 0ULL)
        {
            r0State.diagnosticText = kernelText(
                "kernel.object_type.r0.table_unavailable",
                QStringLiteral("R0 未能唯一定位 ObTypeIndexTable（status=%1, NTSTATUS=0x%2）"))
                .arg(kR0Result.status)
                .arg(static_cast<qulonglong>(static_cast<std::uint32_t>(kR0Result.lastStatus)), 8, 16, QChar('0'))
                .toUpper();
        }
        else
        {
            r0State.diagnosticText = kernelText(
                "kernel.object_type.r0.table_loaded",
                QStringLiteral("R0 表 0x%1，返回 %2 个有效槽"))
                .arg(static_cast<qulonglong>(kR0Result.tableAddress), 16, 16, QChar('0'))
                .arg(kR0Result.entries.size())
                .toUpper();
        }

        const QString kDefaultValidation = r0State.diagnosticText;
        std::unordered_map<std::uint32_t, std::size_t> rowByTypeIndex;
        rowByTypeIndex.reserve(rows.size());
        for (std::size_t index = 0U; index < rows.size(); ++index)
        {
            rows[index].r3Present = true;
            rows[index].r0ValidationText = kDefaultValidation;
            rowByTypeIndex.emplace(rows[index].typeIndex, index);
        }

        for (const KSWORD_ARK_OBJECT_TYPE_TABLE_ENTRY& r0Entry : kR0Result.entries)
        {
            auto found = rowByTypeIndex.find(r0Entry.typeIndex);
            if (found == rowByTypeIndex.end())
            {
                KernelObjectTypeEntry r0Only{};
                r0Only.typeIndex = r0Entry.typeIndex;
                r0Only.r3Present = false;
                r0Only.typeNameText = fixedR0TypeName(
                    r0Entry.typeName,
                    KSWORD_ARK_KERNEL_OBJECT_TYPE_NAME_CHARS);
                if (r0Only.typeNameText.isEmpty())
                {
                    r0Only.typeNameText = kernelText(
                        "kernel.object_type.r0.name_unavailable",
                        QStringLiteral("<R0 名称不可用>"));
                }
                rows.push_back(std::move(r0Only));
                found = rowByTypeIndex.emplace(
                    r0Entry.typeIndex,
                    rows.size() - 1U).first;
            }

            KernelObjectTypeEntry& target = rows[found->second];
            target.r0Present = r0Entry.objectTypeAddress != 0ULL;
            target.r0Status = r0Entry.status;
            target.r0FieldFlags = r0Entry.fieldFlags;
            target.r0LastStatus = r0Entry.lastStatus;
            target.r0ObjectTypeAddress = r0Entry.objectTypeAddress;
            target.r0IdentityHash = r0Entry.identityHash;
            target.r0TypeNameText = fixedR0TypeName(
                r0Entry.typeName,
                KSWORD_ARK_KERNEL_OBJECT_TYPE_NAME_CHARS);
            target.r0ValidationText.clear();
        }

        const bool kR0HasRows = kR0Result.io.ok && !kR0Result.entries.empty();
        const bool kSuccess = kR3Success || kR0HasRows;

        KernelObjectTypeMatrixTab* const kContextObject = guardThis.data();
        if (kContextObject == nullptr)
        {
            return;
        }

        QMetaObject::invokeMethod(kContextObject, [guardThis, rows = std::move(rows), r0State = std::move(r0State), errorText, kSuccess]() mutable {
            if (guardThis == nullptr)
            {
                return;
            }
            guardThis->applyRefreshResult(std::move(rows), std::move(r0State), errorText, kSuccess);
        }, Qt::QueuedConnection);
    }).detach();
}

void KernelObjectTypeMatrixTab::applyRefreshResult(
    std::vector<KernelObjectTypeEntry> rows,
    R0SnapshotState r0State,
    const QString& errorText,
    const bool success)
{
    const QPointer<KernelObjectTypeMatrixTab> kSafeThis(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("kernel-object-type-matrix-snapshot"),
        { table_ },
        [kSafeThis, rows, r0State, errorText, success]() mutable
        {
            if (!kSafeThis.isNull())
            {
                kSafeThis->applyRefreshResult(std::move(rows), std::move(r0State), errorText, success);
            }
        }))
    {
        return;
    }

    refreshing_.store(false);
    refreshButton_->setEnabled(true);
    r0State_ = std::move(r0State);

    if (!success)
    {
        rows_.clear();
        statusLabel_->setText(kernelText("kernel.object_type.status.refresh_failed", QStringLiteral("状态：刷新失败 - %1")).arg(errorText));
        statusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::errorHex()));
        insertDiagnosticRow(
            kernelText("kernel.object_type.placeholder.refresh_failed", QStringLiteral("<刷新失败>")),
            buildDiagnosticDetailText(kernelText("kernel.object_type.diagnostic.refresh_failed", QStringLiteral("对象类型矩阵刷新失败：%1")).arg(errorText)));
        if (detailEditor_ != nullptr)
        {
            detailEditor_->setText(buildDiagnosticDetailText(kernelText("kernel.object_type.diagnostic.refresh_failed", QStringLiteral("对象类型矩阵刷新失败：%1")).arg(errorText)));
        }
        return;
    }

    rows_ = std::move(rows);
    rebuildTable();
}

void KernelObjectTypeMatrixTab::rebuildTable()
{
    if (table_ == nullptr)
    {
        return;
    }

    ks::ui::DetailLayoutRegistry::prepareDataRebuild(detailEditor_);

    table_->setSortingEnabled(false);
    table_->setRowCount(0);

    std::size_t visibleCount = 0;
    for (const KernelObjectTypeEntry& entry : rows_)
    {
        if (!rowMatchesFilter(entry))
        {
            continue;
        }

        const int kRowIndex = table_->rowCount();
        table_->insertRow(kRowIndex);
        for (int columnIndex = 0; columnIndex < static_cast<int>(ObjectTypeMatrixColumn::kCount); ++columnIndex)
        {
            const auto kColumn = static_cast<ObjectTypeMatrixColumn>(columnIndex);
            auto* item = readOnlyItem(cellText(entry, kColumn));
            item->setData(Qt::UserRole, static_cast<qulonglong>(&entry - rows_.data()));
            table_->setItem(kRowIndex, columnIndex, item);
        }
        ++visibleCount;
    }

    table_->setSortingEnabled(true);
    statusLabel_->setText(kernelText("kernel.object_type.status.summary_with_r0", QStringLiteral("状态：已加载 %1 类，显示 %2 类；%3"))
        .arg(static_cast<qulonglong>(rows_.size()))
        .arg(static_cast<qulonglong>(visibleCount))
        .arg(r0State_.diagnosticText));
    statusLabel_->setStyleSheet(statusLabelStyle(
        r0State_.tableAddress != 0ULL
            ? ksword_theme::successHex()
            : ksword_theme::warningHex()));

    if (table_->rowCount() > 0)
    {
        const int kTargetRow = table_->currentRow() >= 0 ? table_->currentRow() : 0;
        table_->setCurrentCell(qMin(kTargetRow, table_->rowCount() - 1), 0);
        updateDetailForRow(table_->currentRow());
    }
    else if (detailEditor_ != nullptr)
    {
        const QString kReasonText = rows_.empty()
            ? kernelText("kernel.object_type.diagnostic.no_records", QStringLiteral("NtQueryObject(ObjectTypesInformation) 未返回对象类型记录。"))
            : kernelText("kernel.object_type.diagnostic.filter_empty", QStringLiteral("当前筛选条件下没有对象类型记录。"));
        const QString kDetailText = buildDiagnosticDetailText(kReasonText);
        insertDiagnosticRow(
            rows_.empty()
                ? kernelText("kernel.object_type.placeholder.no_records", QStringLiteral("<无对象类型>"))
                : kernelText("kernel.object_type.placeholder.filter_empty", QStringLiteral("<筛选无结果>")),
            kDetailText);
        table_->setCurrentCell(0, static_cast<int>(ObjectTypeMatrixColumn::kTypeName));
        detailEditor_->setText(kDetailText);
    }
}

std::size_t KernelObjectTypeMatrixTab::sourceIndexForTableRow(const int tableRow) const
{
    // sourceIndexForTableRow：
    // - Input: Currently visible table row index;
    // - Processing: Read original indices saved in UserRole for m_rows to support sorting and filtering.
    // - Return: Valid source index; returns size_t(-1) on failure.
    if (table_ == nullptr || tableRow < 0 || tableRow >= table_->rowCount())
    {
        return static_cast<std::size_t>(-1);
    }

    const QTableWidgetItem* item = table_->item(tableRow, 0);
    if (item == nullptr)
    {
        return static_cast<std::size_t>(-1);
    }
    if (!item->data(Qt::UserRole + 2).toString().isEmpty())
    {
        return static_cast<std::size_t>(-1);
    }

    const qulonglong kSourceIndex = item->data(Qt::UserRole).toULongLong();
    if (kSourceIndex >= static_cast<qulonglong>(rows_.size()))
    {
        return static_cast<std::size_t>(-1);
    }
    return static_cast<std::size_t>(kSourceIndex);
}

QString KernelObjectTypeMatrixTab::buildDetailText(const KernelObjectTypeEntry& entry) const
{
    // buildDetailText：
    // - Input: A source record of the object type matrix;
    // - Processing: Expand short summaries in the table into readable audit descriptions.
    // - Return: R3/R0 cross-validation text for display by CodeEditorWidget; does not modify system state.
    QStringList lines;
    lines << QStringLiteral("[Object Type Matrix Detail]");
    lines << QStringLiteral("TypeIndex: %1").arg(entry.typeIndex);
    lines << QStringLiteral("TypeName: %1").arg(entry.typeNameText);
    lines << QStringLiteral("TotalObjectCount: %1").arg(entry.totalObjectCount);
    lines << QStringLiteral("TotalHandleCount: %1").arg(entry.totalHandleCount);
    lines << QStringLiteral("ValidAccessMask: %1").arg(formatAccessMask(entry.validAccessMask));
    lines << QString();
    lines << QStringLiteral("[R0 ObTypeIndexTable Evidence]");
    lines << QStringLiteral("R3Present: %1").arg(entry.r3Present
        ? kernelText("kernel.object_type.value.yes", QStringLiteral("是"))
        : kernelText("kernel.object_type.value.no", QStringLiteral("否")));
    lines << QStringLiteral("R0Present: %1").arg(entry.r0Present
        ? kernelText("kernel.object_type.value.yes", QStringLiteral("是"))
        : kernelText("kernel.object_type.value.no", QStringLiteral("否")));
    lines << QStringLiteral("ObTypeIndexTable: %1").arg(formatR0Address(r0State_.tableAddress));
    lines << QStringLiteral("ObjectTypeAddress: %1").arg(formatR0Address(entry.r0ObjectTypeAddress));
    lines << QStringLiteral("R0TypeName: %1").arg(entry.r0TypeNameText.isEmpty()
        ? kernelText("kernel.object_type.placeholder.not_available", QStringLiteral("<不可用>"))
        : entry.r0TypeNameText);
    lines << QStringLiteral("R0Validation: %1").arg(objectTypeR0ValidationText(entry));
    lines << QStringLiteral("R0EntryStatus: %1").arg(entry.r0Status);
    lines << QStringLiteral("R0FieldFlags: 0x%1").arg(entry.r0FieldFlags, 8, 16, QChar('0')).toUpper();
    lines << QStringLiteral("R0LastStatus: 0x%1")
        .arg(static_cast<qulonglong>(static_cast<std::uint32_t>(entry.r0LastStatus)), 8, 16, QChar('0'))
        .toUpper();
    lines << QStringLiteral("R0IdentityHash: 0x%1")
        .arg(static_cast<qulonglong>(entry.r0IdentityHash), 16, 16, QChar('0'))
        .toUpper();
    lines << QStringLiteral("SnapshotHash: 0x%1")
        .arg(static_cast<qulonglong>(r0State_.snapshotHash), 16, 16, QChar('0'))
        .toUpper();
    lines << QStringLiteral("OtName/OtIndex: 0x%1 / 0x%2")
        .arg(r0State_.otNameOffset, 8, 16, QChar('0'))
        .arg(r0State_.otIndexOffset, 8, 16, QChar('0'))
        .toUpper();
    lines << QString();
    lines << QStringLiteral("[Enumeration Strategy]");
    lines << strategyForType(entry.typeNameText);
    lines << QString();
    lines << QStringLiteral("[Audit Meaning]");
    lines << kernelText("kernel.object_type.detail.audit.object_count", QStringLiteral("对象数用于判断该类型在 Object Manager 命名空间中的总体存在感。"));
    lines << kernelText("kernel.object_type.detail.audit.handle_count", QStringLiteral("句柄数用于判断用户态/内核态是否大量持有该类型对象。"));
    lines << kernelText("kernel.object_type.detail.audit.access_mask", QStringLiteral("访问掩码来自 NtQueryObject(ObjectTypesInformation)，用于解释该类型支持的权限位范围。"));
    lines << QString();
    lines << QStringLiteral("[Next Step]");
    if (entry.typeNameText.compare(QStringLiteral("Directory"), Qt::CaseInsensitive) == 0)
    {
        lines << kernelText("kernel.object_type.detail.next.directory", QStringLiteral("可切换到 Object Directory Deep 页，对目标目录做递归只读枚举。"));
    }
    else if (entry.typeNameText.compare(QStringLiteral("SymbolicLink"), Qt::CaseInsensitive) == 0)
    {
        lines << kernelText("kernel.object_type.detail.next.symbolic_link", QStringLiteral("可在命名对象页查看符号链接目标，重点关注跨命名空间或设备路径跳转。"));
    }
    else if (entry.typeNameText.compare(QStringLiteral("Driver"), Qt::CaseInsensitive) == 0 ||
        entry.typeNameText.compare(QStringLiteral("Device"), Qt::CaseInsensitive) == 0)
    {
        lines << kernelText("kernel.object_type.detail.next.device_driver", QStringLiteral("可切换到 Device/Driver Objects 页查看 DriverObject、DeviceObject 和 Major/FastIo 归属。"));
    }
    else if (entry.typeNameText.contains(QStringLiteral("Port"), Qt::CaseInsensitive))
    {
        lines << kernelText("kernel.object_type.detail.next.ipc", QStringLiteral("可切换到 IPC/ALPC/NamedPipe 页，把通信端点与进程、句柄和命名空间路径关联。"));
    }
    else
    {
        lines << kernelText("kernel.object_type.detail.next.generic", QStringLiteral("该类型通常需要专项页或句柄表交叉验证；当前页只提供类型级只读证据。"));
    }
    return lines.join(QChar('\n'));
}

void KernelObjectTypeMatrixTab::updateDetailForRow(const int tableRow)
{
    // updateDetailForRow：
    // - Input: Currently visible table row index;
    // - Processing: locate the source record and refresh the details area.
    // - Returns: nothing. On failure, provides a clear message instead of leaving it empty.
    if (detailEditor_ == nullptr)
    {
        return;
    }

    const std::size_t kSourceIndex = sourceIndexForTableRow(tableRow);
    if (kSourceIndex == static_cast<std::size_t>(-1))
    {
        if (table_ != nullptr && tableRow >= 0 && tableRow < table_->rowCount())
        {
            const QTableWidgetItem* item = table_->item(tableRow, static_cast<int>(ObjectTypeMatrixColumn::kTypeIndex));
            const QString kDiagnosticText = item != nullptr
                ? item->data(Qt::UserRole + 2).toString()
                : QString();
            if (!kDiagnosticText.isEmpty())
            {
                detailEditor_->setText(kDiagnosticText);
                return;
            }
        }
        detailEditor_->setText(kernelText("kernel.object_type.detail.select_hint", QStringLiteral("请选择一个对象类型查看枚举策略和下钻建议。")));
        return;
    }

    detailEditor_->setText(buildDetailText(rows_[kSourceIndex]));
}

QString KernelObjectTypeMatrixTab::buildDiagnosticDetailText(const QString& reasonText) const
{
    // buildDiagnosticDetailText：
    // - Input: Reason for refresh failure, empty source data, or empty filter match;
    // - Processing: Supplement current filter and page data source explanation;
    // - Return: Used for diagnostic placeholder rows and multi-line text in CodeEditorWidget.
    QStringList lines;
    lines << QStringLiteral("[Object Type Matrix Diagnostic]");
    lines << kernelText("kernel.object_type.diagnostic.reason", QStringLiteral("原因：%1")).arg(reasonText.trimmed().isEmpty()
        ? kernelText("kernel.object_type.placeholder.not_provided", QStringLiteral("<未提供>"))
        : reasonText.trimmed());
    lines << kernelText("kernel.object_type.diagnostic.current_filter", QStringLiteral("当前筛选：%1")).arg(filterEdit_ != nullptr && !filterEdit_->text().trimmed().isEmpty()
        ? filterEdit_->text().trimmed()
        : kernelText("kernel.object_type.placeholder.no_filter", QStringLiteral("<无筛选>")));
    lines << kernelText("kernel.object_type.diagnostic.source_count", QStringLiteral("源记录总数：%1")).arg(static_cast<qulonglong>(rows_.size()));
    lines << QStringLiteral("");
    lines << kernelText("kernel.object_type.diagnostic.source_heading", QStringLiteral("[数据来源]"));
    lines << kernelText("kernel.object_type.diagnostic.source", QStringLiteral("本页合并 NtQueryObject(ObjectTypesInformation) 与 R0 ObTypeIndexTable，只读交叉验证槽地址、类型名和 TypeIndex，不修改系统对象。"));
    lines << kernelText("kernel.object_type.diagnostic.r0_state", QStringLiteral("R0 状态：%1")).arg(r0State_.diagnosticText);
    lines << kernelText("kernel.object_type.diagnostic.no_data_explanation", QStringLiteral("若这里没有记录，通常是 API 查询失败、权限/兼容性问题，或筛选条件过窄。"));
    lines << QStringLiteral("");
    lines << kernelText("kernel.object_type.diagnostic.next_heading", QStringLiteral("[下一步]"));
    lines << kernelText("kernel.object_type.diagnostic.next.clear_filter", QStringLiteral("1. 清空筛选关键字，确认不是过滤导致空表。"));
    lines << kernelText("kernel.object_type.diagnostic.next.specialized_pages", QStringLiteral("2. 切换到 Object Directory Deep / NamedPipe / Device-Driver Objects 等专项页查看具体对象。"));
    lines << kernelText("kernel.object_type.diagnostic.next.record_status", QStringLiteral("3. 如果刷新失败，请记录状态栏错误文本用于定位 NtQueryObject 返回状态。"));
    return lines.join(QChar('\n'));
}

void KernelObjectTypeMatrixTab::insertDiagnosticRow(const QString& titleText, const QString& detailText)
{
    // insertDiagnosticRow：
    // - Input: Table title and detail text.
    // - Processing: Insert a copyable diagnostic placeholder and place details in UserRole + 2.
    // - Returns: No return value; updates the UI table only.
    if (table_ == nullptr)
    {
        return;
    }

    table_->setSortingEnabled(false);
    table_->setRowCount(1);

    auto* indexItem = readOnlyItem(kernelText("kernel.object_type.placeholder.diagnostic", QStringLiteral("<诊断>")));
    indexItem->setData(Qt::UserRole + 2, detailText);
    table_->setItem(0, static_cast<int>(ObjectTypeMatrixColumn::kTypeIndex), indexItem);
    table_->setItem(0, static_cast<int>(ObjectTypeMatrixColumn::kTypeName), readOnlyItem(titleText));
    table_->setItem(0, static_cast<int>(ObjectTypeMatrixColumn::kR0Address), readOnlyItem(QStringLiteral("-")));
    table_->setItem(0, static_cast<int>(ObjectTypeMatrixColumn::kR0Validation), readOnlyItem(r0State_.diagnosticText));
    table_->setItem(0, static_cast<int>(ObjectTypeMatrixColumn::kObjectCount), readOnlyItem(QStringLiteral("0")));
    table_->setItem(0, static_cast<int>(ObjectTypeMatrixColumn::kHandleCount), readOnlyItem(QStringLiteral("0")));
    table_->setItem(0, static_cast<int>(ObjectTypeMatrixColumn::kAccessMask), readOnlyItem(formatAccessMask(0)));
    table_->setItem(0, static_cast<int>(ObjectTypeMatrixColumn::kStrategy), readOnlyItem(kernelText("kernel.object_type.placeholder.view_diagnostic", QStringLiteral("请查看下方诊断详情"))));

    table_->setSortingEnabled(true);
}

void KernelObjectTypeMatrixTab::showContextMenu(const QPoint& localPosition)
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
    menu.setStyleSheet(ksword_theme::contextMenuStyle());
    QAction* copyRowAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
        kernelText("kernel.object_type.menu.copy_row", QStringLiteral("复制当前行")));
    copyRowAction->setEnabled(table_->currentRow() >= 0);
    const QAction* selectedAction = menu.exec(table_->viewport()->mapToGlobal(localPosition));
    if (selectedAction == copyRowAction)
    {
        copyCurrentRow();
    }
}

void KernelObjectTypeMatrixTab::copyCurrentRow() const
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

bool KernelObjectTypeMatrixTab::rowMatchesFilter(const KernelObjectTypeEntry& entry) const
{
    const QString kKeyword = filterEdit_ != nullptr ? filterEdit_->text().trimmed() : QString();
    if (kKeyword.isEmpty())
    {
        return true;
    }

    return QString::number(entry.typeIndex).contains(kKeyword, Qt::CaseInsensitive)
        || entry.typeNameText.contains(kKeyword, Qt::CaseInsensitive)
        || entry.r0TypeNameText.contains(kKeyword, Qt::CaseInsensitive)
        || formatR0Address(entry.r0ObjectTypeAddress).contains(kKeyword, Qt::CaseInsensitive)
        || objectTypeR0ValidationText(entry).contains(kKeyword, Qt::CaseInsensitive)
        || strategyForType(entry.typeNameText).contains(kKeyword, Qt::CaseInsensitive);
}

QString KernelObjectTypeMatrixTab::strategyForType(const QString& typeNameText)
{
    if (typeNameText.compare(QStringLiteral("Directory"), Qt::CaseInsensitive) == 0)
    {
        return kernelText("kernel.object_type.strategy.directory", QStringLiteral("NtQueryDirectoryObject 可递归枚举子对象"));
    }
    if (typeNameText.compare(QStringLiteral("SymbolicLink"), Qt::CaseInsensitive) == 0)
    {
        return kernelText("kernel.object_type.strategy.symbolic_link", QStringLiteral("NtQuerySymbolicLinkObject 可解析目标"));
    }
    if (typeNameText.compare(QStringLiteral("File"), Qt::CaseInsensitive) == 0
        || typeNameText.compare(QStringLiteral("NamedPipe"), Qt::CaseInsensitive) == 0)
    {
        return kernelText("kernel.object_type.strategy.file_pipe", QStringLiteral("文件系统目录枚举，NamedPipe 走 NPFS/NtQueryDirectoryFile"));
    }
    if (typeNameText.contains(QStringLiteral("Port"), Qt::CaseInsensitive))
    {
        return kernelText("kernel.object_type.strategy.port", QStringLiteral("通信端点对象，通常是叶子；可做命名空间聚合"));
    }
    if (typeNameText.compare(QStringLiteral("Device"), Qt::CaseInsensitive) == 0
        || typeNameText.compare(QStringLiteral("Driver"), Qt::CaseInsensitive) == 0)
    {
        return kernelText("kernel.object_type.strategy.device_driver", QStringLiteral("通常是叶子对象；可做专项属性/目录聚合"));
    }
    return kernelText("kernel.object_type.strategy.generic", QStringLiteral("通常不可下钻；按类型查询属性或在专项页聚合"));
}

QString KernelObjectTypeMatrixTab::formatAccessMask(const std::uint32_t accessMask)
{
    return QStringLiteral("0x%1")
        .arg(accessMask, 8, 16, QChar('0'))
        .toUpper();
}

QTableWidgetItem* KernelObjectTypeMatrixTab::readOnlyItem(const QString& text)
{
    auto* item = new QTableWidgetItem(text);
    item->setFlags(item->flags() & ~Qt::ItemIsEditable);
    return item;
}
