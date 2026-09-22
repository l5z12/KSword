#include "KernelDock.h"
#include "../ui/TableInteractionSupport.h"

#include <memory>
#include "../ui/VisibleTableWidget.h"

#include "KernelDockSsdtWorker.h"
#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../ui/CodeEditorWidget.h"
#include "../ui/DetailLayoutRegistry.h"
/* Unified entry point: this page does not need to know GPA, EPT leaf, or ruleId. */
#include "../ui/KvmWatchDialog.h"
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
#include <QInputDialog>
#include <QMessageBox>
#include <QMetaObject>
#include <QMenu>
#include <QModelIndex>
#include <QPointer>
#include <QPushButton>
#include <QStringList>
#include <QSplitter>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

#include <thread>

using ksword::kernel_dock_internal::kernelText;

namespace
{
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

    // ssdtContextMenuStyle：
    // - Input: none; reads menu background, text, border, and selection colors from the global theme;
    // - Processing: Uniformly return non-transparent QMenu styles to ensure right-click menus remain readable under dark or system themes.
    // - Returns: Style text directly passable to QMenu::setStyleSheet.
    QString ssdtContextMenuStyle()
    {
        return ksword_theme::contextMenuStyle();
    }

    QString safeText(const QString& valueText, const QString& fallbackText)
    {
        return valueText.trimmed().isEmpty() ? fallbackText : valueText;
    }

    QString safeText(const QString& valueText)
    {
        return safeText(valueText, kernelText("kernel.ssdt.placeholder.empty", QStringLiteral("<空>")));
    }

    QString emptyText()
    {
        return kernelText("kernel.ssdt.placeholder.empty", QStringLiteral("<空>"));
    }

    QString formatAddressHex(const std::uint64_t addressValue)
    {
        return QStringLiteral("0x%1")
            .arg(addressValue, 16, 16, QChar('0'))
            .toUpper();
    }

    // tableRowAsTsv：
    // - Input: SSDT table pointer and visible row index;
    // - Processing: Read visible text according to the current table column order, using a placeholder for empty cells, with fields separated by tabs.
    // - Return: TSV text suitable for copying to clipboard or spreadsheet software; returns an empty string if input is invalid.
    QString tableRowAsTsv(const QTableWidget* tableWidget, const int rowIndex)
    {
        if (tableWidget == nullptr || rowIndex < 0 || rowIndex >= tableWidget->rowCount())
        {
            return QString();
        }

        QStringList fieldList;
        fieldList.reserve(tableWidget->columnCount());
        for (int columnIndex = 0; columnIndex < tableWidget->columnCount(); ++columnIndex)
        {
            const QTableWidgetItem* cellItem = tableWidget->item(rowIndex, columnIndex);
            fieldList.push_back(cellItem != nullptr ? safeText(cellItem->text()) : emptyText());
        }
        return fieldList.join('\t');
    }

    enum class SsdtColumn : int
    {
        kIndex = 0,
        kServiceName,
        kZwAddress,
        kServiceAddress,
        kSlotAddress,
        kModule,
        kCount
    };
}

void KernelDock::initializeSsdtTab()
{
    if (ssdtPage_ == nullptr || ssdtLayout_ != nullptr)
    {
        return;
    }

    ssdtLayout_ = new QVBoxLayout(ssdtPage_);
    ssdtLayout_->setContentsMargins(4, 4, 4, 4);
    ssdtLayout_->setSpacing(6);

    ssdtToolLayout_ = new QHBoxLayout();
    ssdtToolLayout_->setContentsMargins(0, 0, 0, 0);
    ssdtToolLayout_->setSpacing(6);

    refreshSsdtButton_ = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), ssdtPage_);
    refreshSsdtButton_->setToolTip(kernelText("kernel.ssdt.toolbar.refresh.tooltip", QStringLiteral("刷新 SSDT 遍历结果")));
    refreshSsdtButton_->setStyleSheet(blueButtonStyle());
    ksword_theme::applyCompactIconButtonMetrics(refreshSsdtButton_);

    restoreSsdtButton_ = new QPushButton(
        QIcon(QStringLiteral(":/Icon/process_terminate.svg")),
        kernelText(
            "kernel.ssdt.toolbar.restore",
            QStringLiteral("恢复选中槽位")),
        ssdtPage_);
    restoreSsdtButton_->setToolTip(kernelText(
        "kernel.ssdt.toolbar.restore.tooltip",
        QStringLiteral(
            "仅当磁盘映像身份完全匹配且槽值存在差异时，按当前值比较后恢复")));
    restoreSsdtButton_->setStyleSheet(blueButtonStyle());
    restoreSsdtButton_->setEnabled(false);

    ssdtFilterEdit_ = new QLineEdit(ssdtPage_);
    ssdtFilterEdit_->setPlaceholderText(kernelText("kernel.ssdt.toolbar.filter.placeholder", QStringLiteral("按索引/服务名/地址/模块筛选")));
    ssdtFilterEdit_->setToolTip(kernelText("kernel.ssdt.toolbar.filter.tooltip", QStringLiteral("输入关键字后实时过滤 SSDT 结果")));
    ssdtFilterEdit_->setClearButtonEnabled(true);
    ssdtFilterEdit_->setStyleSheet(blueInputStyle());

    ssdtStatusLabel_ = new QLabel(kernelText("kernel.ssdt.status.waiting", QStringLiteral("状态：等待刷新")), ssdtPage_);
    ssdtStatusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::textSecondaryHex()));

    ssdtToolLayout_->addWidget(refreshSsdtButton_, 0);
    ssdtToolLayout_->addWidget(restoreSsdtButton_, 0);
    ssdtToolLayout_->addWidget(ssdtFilterEdit_, 1);
    ssdtToolLayout_->addWidget(ssdtStatusLabel_, 0);
    ssdtLayout_->addLayout(ssdtToolLayout_);

    QSplitter* splitter = new QSplitter(Qt::Vertical, ssdtPage_);
    ssdtLayout_->addWidget(splitter, 1);

    ssdtTable_ = new ks::ui::VisibleTableWidget(splitter);
    ssdtTable_->setColumnCount(static_cast<int>(SsdtColumn::kCount));
    ssdtTable_->setHorizontalHeaderLabels(QStringList{
        kernelText("kernel.ssdt.header.index", QStringLiteral("索引")),
        kernelText("kernel.ssdt.header.service_name", QStringLiteral("服务名")),
        kernelText("kernel.ssdt.header.zw_address", QStringLiteral("Zw导出地址")),
        kernelText("kernel.ssdt.header.service_address", QStringLiteral("服务例程")),
        kernelText("kernel.ssdt.header.slot_address", QStringLiteral("槽位地址")),
        kernelText("kernel.ssdt.header.module", QStringLiteral("模块"))
        });
    ssdtTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    ssdtTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    ssdtTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ssdtTable_->setAlternatingRowColors(true);
    ssdtTable_->setStyleSheet(itemSelectionStyle());
    ssdtTable_->setCornerButtonEnabled(false);
    ssdtTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    ssdtTable_->verticalHeader()->setVisible(false);
    ssdtTable_->horizontalHeader()->setStyleSheet(headerStyle());
    ssdtTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    ssdtTable_->horizontalHeader()->setSectionResizeMode(static_cast<int>(SsdtColumn::kServiceName), QHeaderView::Stretch);
    ssdtTable_->setColumnWidth(static_cast<int>(SsdtColumn::kIndex), 90);
    ssdtTable_->setColumnWidth(static_cast<int>(SsdtColumn::kZwAddress), 180);
    ssdtTable_->setColumnWidth(static_cast<int>(SsdtColumn::kServiceAddress), 180);
    ssdtTable_->setColumnWidth(static_cast<int>(SsdtColumn::kSlotAddress), 180);
    ssdtTable_->setColumnWidth(static_cast<int>(SsdtColumn::kModule), 150);

    ssdtDetailEditor_ = new CodeEditorWidget(splitter);
    ssdtDetailEditor_->setReadOnly(true);
    ssdtDetailEditor_->setText(kernelText("kernel.ssdt.detail.initial", QStringLiteral("请选择一条 SSDT 记录查看详情。")));

    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);

    ks::ui::DetailLayoutRegistry::registerHost(
        ssdtTable_, ssdtDetailEditor_, ssdtPage_);

    connect(refreshSsdtButton_, &QPushButton::clicked, this, [this]() {
        refreshSsdtAsync();
    });
    connect(restoreSsdtButton_, &QPushButton::clicked, this, [this]() {
        restoreSelectedSsdtBaseline();
    });
    connect(ssdtFilterEdit_, &QLineEdit::textChanged, this, [this](const QString& filterText) {
        rebuildSsdtTable(filterText.trimmed());
    });
    connect(ssdtTable_, &QTableWidget::currentCellChanged, this, [this](int, int, int, int) {
        showSsdtDetailByCurrentRow();
        const KernelSsdtEntry* entry = currentSsdtEntry();
        restoreSsdtButton_->setEnabled(
            entry != nullptr
            && entry->cleanBaselineAvailable
            && entry->cleanBaselineDiffers
            && entry->tableEntryAddress != 0U
            && !ssdtRefreshRunning_.load());
    });
    connect(ssdtTable_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& localPosition) {
        if (ssdtTable_ == nullptr)
        {
            return;
        }

        const QModelIndex kClickedIndex = ssdtTable_->indexAt(localPosition);
        if (kClickedIndex.isValid())
        {
            ssdtTable_->setCurrentCell(kClickedIndex.row(), kClickedIndex.column());
        }

        const int kCurrentRow = ssdtTable_->currentRow();
        QMenu contextMenu(ssdtTable_);
        contextMenu.setStyleSheet(ssdtContextMenuStyle());

        QAction* copyRowAction = contextMenu.addAction(
            QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
            kernelText("kernel.ssdt.menu.copy_row", QStringLiteral("复制当前行")));
        copyRowAction->setEnabled(kCurrentRow >= 0);

        /*
         * Monitor writes to this **slot itself**, not the service routine it points to.
         *
         * Modifying the SSDT means modifying the encoded value in the slot; modifying the routine is a separate matter (that is an inline hook, which
         * should be monitored on the disassembly page). The consequence of monitoring the wrong object is not an error, but never hitting the target.
         */
        const KernelSsdtEntry* const kWatchEntry = currentSsdtEntry();
        QAction* watchAction = contextMenu.addAction(
            kernelText("kernel.ssdt.menu.hvm_watch",
                       QStringLiteral("HVM 监视：下一次写入这一槽位")));
        watchAction->setEnabled(
            kWatchEntry != nullptr && kWatchEntry->tableEntryAddress != 0U);
        watchAction->setToolTip(kernelText(
            "kernel.ssdt.menu.hvm_watch.tip",
            QStringLiteral("装一条首次访问监视，等下一次有人写这一槽位时记下访问者的 RIP、模块与地址空间。命中不阻止写入，也不会让常驻退出。")));

        QAction* selectedAction = contextMenu.exec(ssdtTable_->viewport()->mapToGlobal(localPosition));
        if (selectedAction == watchAction && kWatchEntry != nullptr)
        {
            ks::ui::HvmWatchRequest request;
            request.virtualAddress = true;
            request.address = kWatchEntry->tableEntryAddress;
            // Slot width is reported by the driver (a 4-byte encoded offset on x64); do not hardcode it.
            request.length = kWatchEntry->tableEntrySize != 0U
                ? kWatchEntry->tableEntrySize
                : sizeof(std::uint32_t);
            request.access = KSWORD_ARK_HVM_EPT_ACCESS_WRITE;
            request.label = kernelText(
                "kernel.ssdt.menu.hvm_watch.label",
                QStringLiteral("SSDT 槽位 #%1 %2"))
                .arg(kWatchEntry->serviceIndex)
                .arg(kWatchEntry->serviceNameText);
            ks::ui::openHvmWatch(this, request);
            return;
        }
        if (selectedAction != copyRowAction || kCurrentRow < 0)
        {
            return;
        }

        const QString kRowText = tableRowAsTsv(ssdtTable_, kCurrentRow);
        QClipboard* clipboard = QApplication::clipboard();
        if (clipboard != nullptr && !kRowText.isEmpty())
        {
            clipboard->setText(kRowText);
        }
    });
}

void KernelDock::refreshSsdtAsync()
{
    if (ssdtRefreshRunning_.exchange(true))
    {
        KLogEvent skipEvent;
        dbg << skipEvent << "[KernelDock] SSDT 刷新被忽略：已有任务运行。" << eol;
        return;
    }

    refreshSsdtButton_->setEnabled(false);
    ssdtStatusLabel_->setText(kernelText("kernel.ssdt.status.refreshing", QStringLiteral("状态：刷新中...")));
    ssdtStatusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::kPrimaryBlueHex));

    QPointer<KernelDock> guardThis(this);
    std::thread([guardThis]() {
        std::vector<KernelSsdtEntry> resultRows;
        QString errorText;
        const bool kSuccess = runSsdtSnapshotTask(resultRows, errorText);

        QMetaObject::invokeMethod(guardThis, [guardThis, kSuccess, errorText, resultRows = std::move(resultRows)]() mutable {
            const auto kDeferredRows =
                std::make_shared<std::vector<KernelSsdtEntry>>(std::move(resultRows));
            auto commitResult = [guardThis, kSuccess, errorText, kDeferredRows]() mutable
            {
            std::vector<KernelSsdtEntry>& resultRows = *kDeferredRows;
            if (guardThis == nullptr)
            {
                return;
            }

            guardThis->ssdtRefreshRunning_.store(false);
            guardThis->refreshSsdtButton_->setEnabled(true);

            if (!kSuccess)
            {
                guardThis->ssdtStatusLabel_->setText(kernelText("kernel.ssdt.status.failed", QStringLiteral("状态：刷新失败")));
                guardThis->ssdtStatusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::errorHex()));
                guardThis->ssdtDetailEditor_->setText(errorText);
                return;
            }

            guardThis->ssdtRows_ = std::move(resultRows);
            guardThis->rebuildSsdtTable(guardThis->ssdtFilterEdit_->text().trimmed());

            std::size_t unresolvedCount = 0U;
            for (const KernelSsdtEntry& entry : guardThis->ssdtRows_)
            {
                if (!entry.indexResolved)
                {
                    ++unresolvedCount;
                }
            }

            guardThis->ssdtStatusLabel_->setText(
                kernelText("kernel.ssdt.status.summary", QStringLiteral("状态：已刷新 %1 项，未解析索引 %2 项"))
                .arg(guardThis->ssdtRows_.size())
                .arg(unresolvedCount));
            guardThis->ssdtStatusLabel_->setStyleSheet(
                statusLabelStyle(unresolvedCount == 0U ? ksword_theme::successHex() : ksword_theme::warningHex()));

            if (guardThis->ssdtTable_->rowCount() > 0)
            {
                guardThis->ssdtTable_->setCurrentCell(0, 0);
            }
            else
            {
                guardThis->ssdtDetailEditor_->setText(kernelText("kernel.ssdt.empty", QStringLiteral("当前环境未返回可见 SSDT 条目。")));
            }
            };

            if (guardThis == nullptr)
            {
                return;
            }
            if (ks::ui::deferTableUiCommitIfContextMenuOpen(
                guardThis.data(),
                QStringLiteral("kernel-ssdt-snapshot-apply"),
                { guardThis->ssdtTable_ },
                commitResult))
            {
                return;
            }
            commitResult();
        }, Qt::QueuedConnection);
    }).detach();
}

void KernelDock::rebuildSsdtTable(const QString& filterKeyword)
{
    if (ssdtTable_ == nullptr)
    {
        return;
    }

    ks::ui::DetailLayoutRegistry::prepareDataRebuild(ssdtDetailEditor_);

    ssdtTable_->setSortingEnabled(false);
    ssdtTable_->setRowCount(0);

    for (std::size_t sourceIndex = 0; sourceIndex < ssdtRows_.size(); ++sourceIndex)
    {
        const KernelSsdtEntry& entry = ssdtRows_[sourceIndex];
        const QString kIndexText = entry.indexResolved
            ? QString::number(entry.serviceIndex)
            : kernelText("kernel.ssdt.placeholder.unknown", QStringLiteral("<未知>"));
        const QString kZwAddressText = formatAddressHex(entry.zwRoutineAddress);
        const QString kServiceAddressText = formatAddressHex(entry.serviceRoutineAddress);
        const QString kSlotAddressText =
            formatAddressHex(entry.tableEntryAddress);

        const bool kMatched = filterKeyword.isEmpty()
            || kIndexText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.serviceNameText.contains(filterKeyword, Qt::CaseInsensitive)
            || kZwAddressText.contains(filterKeyword, Qt::CaseInsensitive)
            || kServiceAddressText.contains(filterKeyword, Qt::CaseInsensitive)
            || kSlotAddressText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.moduleNameText.contains(filterKeyword, Qt::CaseInsensitive);
        if (!kMatched)
        {
            continue;
        }

        const int kRowIndex = ssdtTable_->rowCount();
        ssdtTable_->insertRow(kRowIndex);

        auto* indexItem = new QTableWidgetItem(kIndexText);
        indexItem->setData(Qt::UserRole, static_cast<qulonglong>(sourceIndex));
        auto* serviceNameItem = new QTableWidgetItem(safeText(entry.serviceNameText));
        auto* zwAddressItem = new QTableWidgetItem(kZwAddressText);
        auto* serviceAddressItem = new QTableWidgetItem(kServiceAddressText);
        auto* slotAddressItem = new QTableWidgetItem(kSlotAddressText);
        auto* moduleItem = new QTableWidgetItem(safeText(entry.moduleNameText));

        indexItem->setFlags(indexItem->flags() & ~Qt::ItemIsEditable);
        serviceNameItem->setFlags(serviceNameItem->flags() & ~Qt::ItemIsEditable);
        zwAddressItem->setFlags(zwAddressItem->flags() & ~Qt::ItemIsEditable);
        serviceAddressItem->setFlags(serviceAddressItem->flags() & ~Qt::ItemIsEditable);
        slotAddressItem->setFlags(slotAddressItem->flags() & ~Qt::ItemIsEditable);
        moduleItem->setFlags(moduleItem->flags() & ~Qt::ItemIsEditable);

        ssdtTable_->setItem(kRowIndex, static_cast<int>(SsdtColumn::kIndex), indexItem);
        ssdtTable_->setItem(kRowIndex, static_cast<int>(SsdtColumn::kServiceName), serviceNameItem);
        ssdtTable_->setItem(kRowIndex, static_cast<int>(SsdtColumn::kZwAddress), zwAddressItem);
        ssdtTable_->setItem(kRowIndex, static_cast<int>(SsdtColumn::kServiceAddress), serviceAddressItem);
        ssdtTable_->setItem(kRowIndex, static_cast<int>(SsdtColumn::kSlotAddress), slotAddressItem);
        ssdtTable_->setItem(kRowIndex, static_cast<int>(SsdtColumn::kModule), moduleItem);
    }

    ssdtTable_->setSortingEnabled(true);
}

void KernelDock::restoreSelectedSsdtBaseline()
{
    const KernelSsdtEntry* selected = currentSsdtEntry();
    if (selected == nullptr
        || !selected->cleanBaselineAvailable
        || !selected->cleanBaselineDiffers
        || selected->tableEntryAddress == 0U
        || selected->tableEntrySize == 0U
        || selected->currentTableBytes.size() != selected->tableEntrySize
        || selected->cleanTableBytes.size() != selected->tableEntrySize)
    {
        QMessageBox::information(
            this,
            kernelText(
                "kernel.ssdt.restore.title",
                QStringLiteral("SSDT 槽位恢复")),
            kernelText(
                "kernel.ssdt.restore.unavailable",
                QStringLiteral(
                    "当前行没有通过映像身份校验的差异基线，不能恢复。")));
        return;
    }

    const KernelSsdtEntry kSnapshot = *selected;
    const ksword::ark::DriverClient kClient;
    const ksword::ark::KernelInlinePatchResult kPreflight =
        kClient.patchInlineHook(
            kSnapshot.tableEntryAddress,
            KSWORD_ARK_INLINE_PATCH_MODE_RESTORE_BYTES,
            kSnapshot.tableEntrySize,
            kSnapshot.currentTableBytes,
            kSnapshot.cleanTableBytes,
            0UL);
    if (!kPreflight.io.ok
        || kPreflight.status
            != KSWORD_ARK_KERNEL_HOOK_STATUS_FORCE_REQUIRED)
    {
        QMessageBox::critical(
            this,
            kernelText(
                "kernel.ssdt.restore.title",
                QStringLiteral("SSDT 槽位恢复")),
            kernelText(
                "kernel.ssdt.restore.preflight_failed",
                QStringLiteral(
                    "R0 恢复预检失败，未写入任何内容。\nWin32=%1\n状态=%2\nNT=0x%3"))
                .arg(kPreflight.io.win32Error)
                .arg(kPreflight.status)
                .arg(static_cast<unsigned long>(kPreflight.lastStatus),
                    8,
                    16,
                    QChar('0')));
        return;
    }

    const QMessageBox::StandardButton kWarning =
        QMessageBox::warning(
            this,
            kernelText(
                "kernel.ssdt.restore.warning.title",
                QStringLiteral("高风险内核表项恢复")),
            kernelText(
                "kernel.ssdt.restore.warning.body",
                QStringLiteral(
                    "即将把 SSDT[%1] 槽位从当前编码值 0x%2 恢复为磁盘基线 0x%3。\n\n"
                    "R0 会在写入前再次逐字节比较当前值；任何并发变化都会使操作失败。"
                    "错误恢复可能立即导致系统崩溃。\n\n映像：%4"))
                .arg(kSnapshot.serviceIndex)
                .arg(static_cast<qulonglong>(kSnapshot.currentTableValue),
                    0,
                    16)
                .arg(static_cast<qulonglong>(kSnapshot.cleanTableValue),
                    0,
                    16)
                .arg(kSnapshot.cleanBaselinePath),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
    if (kWarning != QMessageBox::Yes)
    {
        return;
    }

    // Final confirmation changed to direct click: no longer requires entering a confirmation phrase; defaults to focusing 'No' to prevent accidental triggers.
    const auto kConfirmation = QMessageBox::warning(
        this,
        kernelText(
            "kernel.ssdt.restore.confirm.title",
            QStringLiteral("最终确认")),
        kernelText(
            "kernel.ssdt.restore.confirm.final",
            QStringLiteral("确认按基线恢复该 SSDT 表项？该操作会改写内核数据。")),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kConfirmation != QMessageBox::Yes)
    {
        return;
    }

    restoreSsdtButton_->setEnabled(false);
    const ksword::ark::KernelInlinePatchResult kApplied =
        kClient.patchInlineHook(
            kSnapshot.tableEntryAddress,
            KSWORD_ARK_INLINE_PATCH_MODE_RESTORE_BYTES,
            kSnapshot.tableEntrySize,
            kSnapshot.currentTableBytes,
            kSnapshot.cleanTableBytes,
            KSWORD_ARK_KERNEL_PATCH_FLAG_FORCE);
    if (!kApplied.io.ok
        || kApplied.status != KSWORD_ARK_KERNEL_HOOK_STATUS_PATCHED
        || kApplied.bytesPatched != kSnapshot.tableEntrySize)
    {
        QMessageBox::critical(
            this,
            kernelText(
                "kernel.ssdt.restore.title",
                QStringLiteral("SSDT 槽位恢复")),
            kernelText(
                "kernel.ssdt.restore.failed",
                QStringLiteral(
                    "恢复失败或当前槽值已变化。\nWin32=%1\n状态=%2\nNT=0x%3\n写入=%4"))
                .arg(kApplied.io.win32Error)
                .arg(kApplied.status)
                .arg(static_cast<unsigned long>(kApplied.lastStatus),
                    8,
                    16,
                    QChar('0'))
                .arg(kApplied.bytesPatched));
        refreshSsdtAsync();
        return;
    }

    QMessageBox::information(
        this,
        kernelText(
            "kernel.ssdt.restore.title",
            QStringLiteral("SSDT 槽位恢复")),
        kernelText(
            "kernel.ssdt.restore.success",
            QStringLiteral(
                "槽位已按验证基线恢复，并已触发重新扫描。")));
    refreshSsdtAsync();
}

bool KernelDock::currentSsdtSourceIndex(std::size_t& sourceIndexOut) const
{
    sourceIndexOut = 0U;

    if (ssdtTable_ == nullptr)
    {
        return false;
    }

    const int kCurrentRow = ssdtTable_->currentRow();
    if (kCurrentRow < 0)
    {
        return false;
    }

    QTableWidgetItem* indexItem = ssdtTable_->item(kCurrentRow, static_cast<int>(SsdtColumn::kIndex));
    if (indexItem == nullptr)
    {
        return false;
    }

    sourceIndexOut = static_cast<std::size_t>(indexItem->data(Qt::UserRole).toULongLong());
    return sourceIndexOut < ssdtRows_.size();
}

const KernelSsdtEntry* KernelDock::currentSsdtEntry() const
{
    std::size_t sourceIndex = 0U;
    if (!currentSsdtSourceIndex(sourceIndex))
    {
        return nullptr;
    }
    return &ssdtRows_[sourceIndex];
}

void KernelDock::showSsdtDetailByCurrentRow()
{
    if (ssdtDetailEditor_ == nullptr)
    {
        return;
    }

    const KernelSsdtEntry* entry = currentSsdtEntry();
    if (entry == nullptr)
    {
        ssdtDetailEditor_->setText(kernelText("kernel.ssdt.detail.initial", QStringLiteral("请选择一条 SSDT 记录查看详情。")));
        return;
    }

    const QString kDetailText = kernelText("kernel.ssdt.detail.full", QStringLiteral(
        "服务索引: %1\n"
        "服务名: %2\n"
        "模块: %3\n"
        "Zw导出地址: %4\n"
        "服务表基址: %5\n"
        "表项服务地址: %6\n"
        "槽位地址: %7\n"
        "当前编码值: 0x%8\n"
        "磁盘基线值: 0x%9\n"
        "基线状态: %10\n"
        "状态: %11\n"
        "标志: 0x%12\n\n"
        "Worker详情:\n%13"))
        .arg(entry->indexResolved ? QString::number(entry->serviceIndex) : kernelText("kernel.ssdt.placeholder.unknown", QStringLiteral("<未知>")))
        .arg(safeText(entry->serviceNameText))
        .arg(safeText(entry->moduleNameText))
        .arg(formatAddressHex(entry->zwRoutineAddress))
        .arg(formatAddressHex(entry->serviceTableBase))
        .arg(formatAddressHex(entry->serviceRoutineAddress))
        .arg(formatAddressHex(entry->tableEntryAddress))
        .arg(static_cast<qulonglong>(entry->currentTableValue), 0, 16)
        .arg(static_cast<qulonglong>(entry->cleanTableValue), 0, 16)
        .arg(safeText(entry->cleanBaselineStatus))
        .arg(safeText(entry->statusText))
        .arg(static_cast<unsigned int>(entry->flags), 8, 16, QChar('0'))
        .arg(safeText(entry->detailText));

    ssdtDetailEditor_->setText(kDetailText);
}
