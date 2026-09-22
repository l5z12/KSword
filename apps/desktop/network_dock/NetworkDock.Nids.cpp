#include "NetworkDock.InternalCommon.h"
#include "NetworkFirewallPage.h"
#include "../ui/VisibleTableWidget.h"
#include "../ui/TableInteractionSupport.h"

#include "../online_scan/SandboxUploadActions.h"
#include "../Theme.h"

#include <QApplication>
#include <QBrush>

using namespace network_dock_detail;

namespace
{
    // nidsSeverityText: Converts NIDS severity level to UI text.
    QString nidsSeverityText(const ks::network::NidsAlertSeverity severity)
    {
        switch (severity)
        {
        case ks::network::NidsAlertSeverity::kLow:
            return QStringLiteral("低");
        case ks::network::NidsAlertSeverity::kMedium:
            return QStringLiteral("中");
        case ks::network::NidsAlertSeverity::kHigh:
            return QStringLiteral("高");
        case ks::network::NidsAlertSeverity::kCritical:
            return QStringLiteral("严重");
        default:
            return QStringLiteral("未知");
        }
    }

    // nidsSeverityColor: Returns the table emphasis color by severity level.
    QColor nidsSeverityColor(const ks::network::NidsAlertSeverity severity)
    {
        switch (severity)
        {
        case ks::network::NidsAlertSeverity::kLow:
            return ksword_theme::textSecondaryColor();
        case ks::network::NidsAlertSeverity::kMedium:
            return ksword_theme::warningColor();
        case ks::network::NidsAlertSeverity::kHigh:
            return ksword_theme::errorColor();
        case ks::network::NidsAlertSeverity::kCritical:
            return ksword_theme::accentColor(ksword_theme::AccentRole::kPurple);
        default:
            return ksword_theme::textSecondaryColor();
        }
    }

    // createNidsCell: Creates a unified read-only NIDS table cell.
    QTableWidgetItem* createNidsCell(const QString& cellText)
    {
        QTableWidgetItem* tableItem = new QTableWidgetItem(cellText);
        tableItem->setFlags(tableItem->flags() & ~Qt::ItemIsEditable);
        return tableItem;
    }

    // nidsSeverityIndex: Converts severity level to int for filtering and sorting.
    int nidsSeverityIndex(const ks::network::NidsAlertSeverity severity)
    {
        return static_cast<int>(severity);
    }

    // nidsTableRowText：
    // - Input: NIDS table pointer and row index.
    // - Processing: Read the entire row in the current column order and concatenate using TSV.
    // - Returns: text ready for direct copy to clipboard or table tools.
    QString nidsTableRowText(QTableWidget* table, const int rowIndex)
    {
        if (table == nullptr || rowIndex < 0 || rowIndex >= table->rowCount())
        {
            return QString();
        }

        QStringList fields;
        fields.reserve(table->columnCount());
        for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
        {
            const QTableWidgetItem* item = table->item(rowIndex, columnIndex);
            fields.push_back(item != nullptr ? item->text() : QString());
        }
        return fields.join(QLatin1Char('\t'));
    }

    // nidsSelectedRows：
    // - Input: NIDS table pointer;
    // - Processing: Collect and deduplicate/sort row indices from the selection model; fall back to the current row if the selection is empty.
    // - Returns: list of row numbers to be copied.
    std::vector<int> nidsSelectedRows(QTableWidget* table)
    {
        std::set<int> rowSet;
        if (table != nullptr)
        {
            for (const QModelIndex& index : table->selectionModel()->selectedRows())
            {
                rowSet.insert(index.row());
            }
            if (rowSet.empty() && table->currentRow() >= 0)
            {
                rowSet.insert(table->currentRow());
            }
        }
        return std::vector<int>(rowSet.begin(), rowSet.end());
    }

    // copyNidsRowsToClipboard：
    // - Input: NIDS table and row indices to copy;
    // - Processing: Generate TSV row by row, with multiple rows separated by newlines.
    // - Return: None; silently maintain UI stability if the copy operation fails.
    void copyNidsRowsToClipboard(QTableWidget* table, const std::vector<int>& rowList)
    {
        if (table == nullptr || QApplication::clipboard() == nullptr || rowList.empty())
        {
            return;
        }

        QStringList rowTexts;
        rowTexts.reserve(static_cast<int>(rowList.size()));
        for (const int kRowIndex : rowList)
        {
            const QString kRowText = nidsTableRowText(table, kRowIndex);
            if (!kRowText.isEmpty())
            {
                rowTexts.push_back(kRowText);
            }
        }
        if (!rowTexts.isEmpty())
        {
            QApplication::clipboard()->setText(rowTexts.join(QChar('\n')));
        }
    }

    // nidsAlertSequenceForRow：
    // - Input: NIDS table pointer, target row index, and time column index (the column enum is a class member of
    //   NetworkDock, inaccessible to the anonymous namespace, so the caller pre-computes and passes the column index).
    // - Processing: Retrieve the packet sequence number associated with this alert from the Qt::UserRole of the time column;
    // - Returns: true if a non-zero index is retrieved; false if the row is out of bounds, the cell is missing, or the index is invalid.
    bool nidsAlertSequenceForRow(
        QTableWidget* table,
        const int row,
        const int timeColumn,
        std::uint64_t& sequenceIdOut)
    {
        if (table == nullptr || row < 0 || row >= table->rowCount())
        {
            return false;
        }

        const QTableWidgetItem* timeItem = table->item(row, timeColumn);
        if (timeItem == nullptr)
        {
            return false;
        }

        const QVariant kSequenceVariant = timeItem->data(Qt::UserRole);
        if (!kSequenceVariant.isValid())
        {
            return false;
        }
        sequenceIdOut = static_cast<std::uint64_t>(kSequenceVariant.toULongLong());
        return sequenceIdOut != 0;
    }

    // captureNidsProcessIdentity：
    // - Purpose: Freeze the process identity required for application-level handling at the same time the NIDS alert is generated;
    // - Processing: Read once before and once after the creation time; accept the snapshot only if both reads match and the image path is available.
    // - Returns: keeps the field empty on failure, allowing only endpoint-level blocking rules to be generated subsequently.
    void captureNidsProcessIdentity(ks::network::NidsAlert& alertRecord)
    {
        if (alertRecord.processId == 0U)
        {
            return;
        }

        std::uint64_t creationTimeBefore = 0U;
        if (!ks::process::queryProcessCreationTimeByPid(
                alertRecord.processId,
                &creationTimeBefore,
                nullptr) ||
            creationTimeBefore == 0U)
        {
            return;
        }

        const std::string kImagePath = ks::process::queryProcessPathByPid(alertRecord.processId);
        if (kImagePath.empty())
        {
            return;
        }

        std::uint64_t creationTimeAfter = 0U;
        if (!ks::process::queryProcessCreationTimeByPid(
                alertRecord.processId,
                &creationTimeAfter,
                nullptr) ||
            creationTimeAfter != creationTimeBefore)
        {
            return;
        }

        alertRecord.processCreationTime100ns = creationTimeAfter;
        alertRecord.processImagePath = kImagePath;
    }
}

void NetworkDock::initializeNidsTab()
{
    nidsPage_ = new QWidget(this);
    nidsLayout_ = new QVBoxLayout(nidsPage_);
    nidsLayout_->setContentsMargins(6, 6, 6, 6);
    nidsLayout_->setSpacing(6);

    nidsControlLayout_ = new QHBoxLayout();
    nidsControlLayout_->setSpacing(6);

    nidsEnableCheck_ = new QCheckBox(QStringLiteral("实时检测"), nidsPage_);
    nidsEnableCheck_->setChecked(true);
    nidsEnableCheck_->setToolTip(QStringLiteral("启用或暂停 NIDS 实时报文检测"));

    QLabel* severityFilterLabel = new QLabel(QStringLiteral("等级:"), nidsPage_);
    nidsSeverityFilterCombo_ = new QComboBox(nidsPage_);
    nidsSeverityFilterCombo_->addItem(QStringLiteral("全部"), static_cast<int>(ks::network::NidsAlertSeverity::kLow));
    nidsSeverityFilterCombo_->addItem(QStringLiteral("中危+"), static_cast<int>(ks::network::NidsAlertSeverity::kMedium));
    nidsSeverityFilterCombo_->addItem(QStringLiteral("高危+"), static_cast<int>(ks::network::NidsAlertSeverity::kHigh));
    nidsSeverityFilterCombo_->addItem(QStringLiteral("严重"), static_cast<int>(ks::network::NidsAlertSeverity::kCritical));
    nidsSeverityFilterCombo_->setToolTip(QStringLiteral("按最低告警等级过滤表格"));
    nidsSeverityFilterCombo_->setMaximumWidth(120);

    nidsClearButton_ = new QPushButton(nidsPage_);
    nidsClearButton_->setIcon(QIcon(":/Icon/log_clear.svg"));
    nidsClearButton_->setToolTip(QStringLiteral("清空 NIDS 告警和检测窗口"));

    nidsStatusLabel_ = new QLabel(nidsPage_);
    nidsStatusLabel_->setWordWrap(true);
    nidsStatusLabel_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

    nidsControlLayout_->addWidget(nidsEnableCheck_);
    nidsControlLayout_->addWidget(severityFilterLabel);
    nidsControlLayout_->addWidget(nidsSeverityFilterCombo_);
    nidsControlLayout_->addWidget(nidsClearButton_);
    nidsControlLayout_->addWidget(nidsStatusLabel_, 1);
    nidsLayout_->addLayout(nidsControlLayout_);

    nidsAlertTable_ = new ks::ui::VisibleTableWidget(nidsPage_);
    nidsAlertTable_->setColumnCount(toNidsAlertColumn(NidsAlertTableColumn::kCount));
    nidsAlertTable_->setHorizontalHeaderLabels({
        QStringLiteral("时间"),
        QStringLiteral("等级"),
        QStringLiteral("分类"),
        QStringLiteral("规则"),
        QStringLiteral("协议"),
        QStringLiteral("方向"),
        QStringLiteral("PID"),
        QStringLiteral("进程"),
        QStringLiteral("本地端点"),
        QStringLiteral("远端端点"),
        QStringLiteral("详情")
        });
    nidsAlertTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    nidsAlertTable_->setSelectionMode(QAbstractItemView::ExtendedSelection);
    nidsAlertTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    nidsAlertTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    nidsAlertTable_->verticalHeader()->setVisible(false);
    nidsAlertTable_->horizontalHeader()->setStretchLastSection(true);
    nidsAlertTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    nidsLayout_->addWidget(nidsAlertTable_, 1);

    connect(nidsAlertTable_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& localPosition)
    {
        // Right-click menu:
        // - Input: Click position in the NIDS alert table by the user;
        // - Processing: Locate current row, provide associated packet details, and support copying for cell/current row/multi-row selection.
        // - Return: None. The menu only views and copies audit evidence; it does not modify rules or connections.
        // Uniqueness note: the right-click menu for this table is registered only here. initializeConnections() previously registered a duplicate
        // 'details' menu; having both slots call exec() would cause two different menus to pop up sequentially on a single right-click.
        if (nidsAlertTable_ == nullptr)
        {
            return;
        }

        const QModelIndex kClickedIndex = nidsAlertTable_->indexAt(localPosition);
        if (kClickedIndex.isValid())
        {
            nidsAlertTable_->setCurrentCell(kClickedIndex.row(), kClickedIndex.column());
        }

        QMenu menu(nidsAlertTable_);
        menu.setStyleSheet(ksword_theme::contextMenuStyle());
        // Related packet details: The alert row records the packet sequence ID that triggered it in the UserRole column of the time column.
        std::uint64_t relatedPacketSequenceId = 0;
        const bool kHasRelatedPacket = nidsAlertSequenceForRow(
            nidsAlertTable_,
            nidsAlertTable_->currentRow(),
            toNidsAlertColumn(NidsAlertTableColumn::kTime),
            relatedPacketSequenceId);
        QAction* viewPacketDetailAction = menu.addAction(
            QIcon(QStringLiteral(":/Icon/process_details.svg")),
            QStringLiteral("查看关联报文详情"));
        viewPacketDetailAction->setEnabled(kHasRelatedPacket);
        menu.addSeparator();
        QAction* copyCellAction = menu.addAction(QIcon(QStringLiteral(":/Icon/log_copy.svg")), QStringLiteral("复制单元格"));
        QAction* copyRowAction = menu.addAction(QIcon(QStringLiteral(":/Icon/process_copy_row.svg")), QStringLiteral("复制当前行"));
        QAction* copySelectedRowsAction = menu.addAction(QIcon(QStringLiteral(":/Icon/log_clipboard.svg")), QStringLiteral("复制选中行"));
        const int kCurrentRow = nidsAlertTable_->currentRow();
        const QTableWidgetItem* processIdItem = kCurrentRow >= 0
            ? nidsAlertTable_->item(kCurrentRow, toNidsAlertColumn(NidsAlertTableColumn::kPid))
            : nullptr;
        std::uint32_t processId = 0;
        const bool kHasProcessId = processIdItem != nullptr &&
            ks::online_scan::tryParsePidFromText(processIdItem->text(), &processId) &&
            processId != 0U;
        QAction* openProcessDetailAction = menu.addAction(
            QIcon(QStringLiteral(":/Icon/process_details.svg")),
            QStringLiteral("转到进程详细信息"));
        openProcessDetailAction->setEnabled(kHasProcessId);
        QAction* addBlockRuleAction = menu.addAction(
            QIcon(QStringLiteral(":/Icon/process_terminate.svg")),
            QStringLiteral("预填阻断规则"));
        addBlockRuleAction->setEnabled(kHasRelatedPacket && firewallPage_ != nullptr);
        menu.addSeparator();
        QAction* uploadVirusTotalAction = ks::online_scan::addVirusTotalSandboxMenu(
            &menu,
            this,
            [this]() -> ks::online_scan::SandboxUploadTarget
            {
                // Input: Current row of the NIDS alert table.
                // Processing: Read PID column and parse the initiating process EXE path.
                // Returns: The upload path and source description; if the PID is missing or the process has exited, returns errorText.
                ks::online_scan::SandboxUploadTarget uploadTarget;
                const int kRowIndex = nidsAlertTable_ != nullptr ? nidsAlertTable_->currentRow() : -1;
                const QTableWidgetItem* pidItem =
                    (nidsAlertTable_ != nullptr && kRowIndex >= 0)
                    ? nidsAlertTable_->item(kRowIndex, toNidsAlertColumn(NidsAlertTableColumn::kPid))
                    : nullptr;
                std::uint32_t targetPid = 0;
                if (pidItem == nullptr || !ks::online_scan::tryParsePidFromText(pidItem->text(), &targetPid))
                {
                    uploadTarget.errorText = QStringLiteral("当前 NIDS 告警没有可解析 PID。");
                    return uploadTarget;
                }

                uploadTarget.filePath = QString::fromStdString(ks::process::queryProcessPathByPid(targetPid));
                uploadTarget.sourceText = QStringLiteral("NIDS 告警 PID=%1").arg(targetPid);
                return uploadTarget;
            });
        const bool kHasCurrentCell = nidsAlertTable_->currentRow() >= 0 && nidsAlertTable_->currentColumn() >= 0;
        const bool kHasCurrentRow = nidsAlertTable_->currentRow() >= 0;
        copyCellAction->setEnabled(kHasCurrentCell);
        copyRowAction->setEnabled(kHasCurrentRow);
        copySelectedRowsAction->setEnabled(!nidsSelectedRows(nidsAlertTable_).empty());
        if (uploadVirusTotalAction != nullptr)
        {
            uploadVirusTotalAction->setEnabled(kHasCurrentRow);
        }

        const QAction* selectedAction = menu.exec(nidsAlertTable_->viewport()->mapToGlobal(localPosition));
        if (selectedAction == viewPacketDetailAction)
        {
            openPacketDetailWindowBySequenceId(relatedPacketSequenceId);
        }
        else if (selectedAction == addBlockRuleAction)
        {
            const auto kAlertIt = std::find_if(
                nidsAlertList_.cbegin(),
                nidsAlertList_.cend(),
                [relatedPacketSequenceId](const ks::network::NidsAlert& alertRecord)
                {
                    return alertRecord.sequenceId == relatedPacketSequenceId;
                });
            if (kAlertIt != nidsAlertList_.cend() && firewallPage_ != nullptr)
            {
                firewallPage_->addBlockRuleFromEvidence(
                    QString::fromUtf8(kAlertIt->remoteAddress.c_str()),
                    QString::number(kAlertIt->remotePort),
                    toQString(ks::network::packetProtocolToString(kAlertIt->protocol)),
                    kAlertIt->direction == ks::network::PacketDirection::kInbound
                        ? QStringLiteral("Inbound") : QStringLiteral("Outbound"),
                    QStringLiteral("NIDS"),
                    kAlertIt->processId,
                    kAlertIt->processCreationTime100ns,
                    QString::fromUtf8(kAlertIt->processImagePath.c_str()));
            }
        }
        else if (selectedAction == copyCellAction)
        {
            const QTableWidgetItem* item = nidsAlertTable_->item(
                nidsAlertTable_->currentRow(),
                nidsAlertTable_->currentColumn());
            if (item != nullptr && QApplication::clipboard() != nullptr)
            {
                QApplication::clipboard()->setText(item->text());
            }
        }
        else if (selectedAction == copyRowAction)
        {
            copyNidsRowsToClipboard(nidsAlertTable_, std::vector<int>{ nidsAlertTable_->currentRow() });
        }
        else if (selectedAction == copySelectedRowsAction)
        {
            copyNidsRowsToClipboard(nidsAlertTable_, nidsSelectedRows(nidsAlertTable_));
        }
        else if (selectedAction == openProcessDetailAction)
        {
            ks::ui::openProcessDetailByPid(processId);
        }
        else if (selectedAction == uploadVirusTotalAction)
        {
            return;
        }
    });

    updateNidsStatusLabel();
    sideTabWidget_->addTab(nidsPage_, QIcon(":/Icon/process_critical.svg"), QStringLiteral("NIDS"));

    KLogEvent initNidsEvent;
    info << initNidsEvent << "[NetworkDock] NIDS 页初始化完成。" << eol;
}

void NetworkDock::processNidsPacket(const ks::network::PacketRecord& packetRecord)
{
    if (nidsEnableCheck_ != nullptr && !nidsEnableCheck_->isChecked())
    {
        return;
    }

    ++nidsAnalyzedPacketCount_;

    std::vector<ks::network::NidsAlert> alertList = nidsEngine_.analyzePacket(packetRecord);
    if (alertList.empty())
    {
        if ((nidsAnalyzedPacketCount_ % 256) == 0)
        {
            updateNidsStatusLabel();
        }
        return;
    }

    bool trimmed = false;
    for (ks::network::NidsAlert& alertRecord : alertList)
    {
        captureNidsProcessIdentity(alertRecord);
        nidsAlertList_.push_back(alertRecord);
        ++nidsTotalAlertCount_;
        while (nidsAlertList_.size() > kMaxNidsAlertCount)
        {
            nidsAlertList_.pop_front();
            trimmed = true;
        }

        if (!trimmed && nidsAlertPassesFilter(alertRecord))
        {
            appendNidsAlertRow(alertRecord);
        }

        KLogEvent nidsAlertEvent;
        warn << nidsAlertEvent
            << "[NetworkDock] NIDS 告警, severity="
            << ks::network::nidsAlertSeverityToString(alertRecord.severity)
            << ", rule=" << alertRecord.ruleId
            << ", pid=" << alertRecord.processId
            << ", detail=" << alertRecord.detail
            << eol;
    }

    if (trimmed)
    {
        rebuildNidsAlertTable();
    }
    else if (nidsAlertTable_ != nullptr && nidsAlertTable_->rowCount() > 0)
    {
        nidsAlertTable_->scrollToBottom();
    }

    updateNidsStatusLabel();
}

void NetworkDock::appendNidsAlertRow(const ks::network::NidsAlert& alertRecord)
{
    if (nidsAlertTable_ == nullptr)
    {
        return;
    }

    const int kNewRow = nidsAlertTable_->rowCount();
    nidsAlertTable_->setRowCount(kNewRow + 1);

    const QString kTimeText = toQString(ks::network::formatUnixTimestampMs(alertRecord.timestampMs, false));
    const QString kSeverityText = nidsSeverityText(alertRecord.severity);
    const QString kProtocolText = toQString(ks::network::packetProtocolToString(alertRecord.protocol));
    const QString kDirectionText = toQString(ks::network::packetDirectionToString(alertRecord.direction));
    const QString kPidText = QString::number(alertRecord.processId);
    const QString kProcessNameText = toQString(alertRecord.processName);
    const QString kLocalEndpointText = formatEndpointText(alertRecord.localAddress, alertRecord.localPort);
    const QString kRemoteEndpointText = formatEndpointText(alertRecord.remoteAddress, alertRecord.remotePort);
    const QString kDetailText = QStringLiteral("%1：%2")
        .arg(toQString(alertRecord.title))
        .arg(toQString(alertRecord.detail));

    QTableWidgetItem* timeItem = createNidsCell(kTimeText);
    timeItem->setData(Qt::UserRole, static_cast<qulonglong>(alertRecord.sequenceId));
    nidsAlertTable_->setItem(kNewRow, toNidsAlertColumn(NidsAlertTableColumn::kTime), timeItem);

    QTableWidgetItem* severityItem = createNidsCell(kSeverityText);
    severityItem->setForeground(QBrush(nidsSeverityColor(alertRecord.severity)));
    severityItem->setData(Qt::UserRole, nidsSeverityIndex(alertRecord.severity));
    nidsAlertTable_->setItem(kNewRow, toNidsAlertColumn(NidsAlertTableColumn::kSeverity), severityItem);

    nidsAlertTable_->setItem(kNewRow, toNidsAlertColumn(NidsAlertTableColumn::kCategory), createNidsCell(toQString(alertRecord.category)));
    nidsAlertTable_->setItem(kNewRow, toNidsAlertColumn(NidsAlertTableColumn::kRule), createNidsCell(toQString(alertRecord.ruleId)));
    nidsAlertTable_->setItem(kNewRow, toNidsAlertColumn(NidsAlertTableColumn::kProtocol), createNidsCell(kProtocolText));
    nidsAlertTable_->setItem(kNewRow, toNidsAlertColumn(NidsAlertTableColumn::kDirection), createNidsCell(kDirectionText));
    nidsAlertTable_->setItem(kNewRow, toNidsAlertColumn(NidsAlertTableColumn::kPid), createNidsCell(kPidText));

    QTableWidgetItem* processNameItem = createNidsCell(kProcessNameText);
    processNameItem->setIcon(resolveProcessIconByPid(alertRecord.processId, alertRecord.processName));
    nidsAlertTable_->setItem(kNewRow, toNidsAlertColumn(NidsAlertTableColumn::kProcessName), processNameItem);

    nidsAlertTable_->setItem(kNewRow, toNidsAlertColumn(NidsAlertTableColumn::kLocalEndpoint), createNidsCell(kLocalEndpointText));
    nidsAlertTable_->setItem(kNewRow, toNidsAlertColumn(NidsAlertTableColumn::kRemoteEndpoint), createNidsCell(kRemoteEndpointText));
    nidsAlertTable_->setItem(kNewRow, toNidsAlertColumn(NidsAlertTableColumn::kDetail), createNidsCell(kDetailText));
}

void NetworkDock::rebuildNidsAlertTable()
{
    if (nidsAlertTable_ == nullptr)
    {
        return;
    }

    const QPointer<NetworkDock> kSafeThis(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("network-nids-filter-rebuild"),
        {nidsAlertTable_},
        [kSafeThis]()
        {
            if (!kSafeThis.isNull())
            {
                kSafeThis->rebuildNidsAlertTable();
            }
        }))
    {
        return;
    }

    nidsAlertTable_->setUpdatesEnabled(false);
    nidsAlertTable_->setRowCount(0);
    for (const ks::network::NidsAlert& alertRecord : nidsAlertList_)
    {
        if (!nidsAlertPassesFilter(alertRecord))
        {
            continue;
        }
        appendNidsAlertRow(alertRecord);
    }
    nidsAlertTable_->setUpdatesEnabled(true);
    if (nidsAlertTable_->rowCount() > 0)
    {
        nidsAlertTable_->scrollToBottom();
    }
}

void NetworkDock::clearNidsAlerts()
{
    const QPointer<NetworkDock> kSafeThis(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("network-nids-clear"),
        {nidsAlertTable_},
        [kSafeThis]()
        {
            if (!kSafeThis.isNull())
            {
                kSafeThis->clearNidsAlerts();
            }
        }))
    {
        return;
    }

    nidsEngine_.reset();
    nidsAlertList_.clear();
    nidsAnalyzedPacketCount_ = 0;
    nidsTotalAlertCount_ = 0;
    if (nidsAlertTable_ != nullptr)
    {
        nidsAlertTable_->setRowCount(0);
    }
    updateNidsStatusLabel();

    KLogEvent clearNidsEvent;
    info << clearNidsEvent << "[NetworkDock] NIDS 告警与检测窗口已清空。" << eol;
}

void NetworkDock::updateNidsStatusLabel()
{
    if (nidsStatusLabel_ == nullptr)
    {
        return;
    }

    std::size_t lowCount = 0;
    std::size_t mediumCount = 0;
    std::size_t highCount = 0;
    std::size_t criticalCount = 0;
    for (const ks::network::NidsAlert& alertRecord : nidsAlertList_)
    {
        switch (alertRecord.severity)
        {
        case ks::network::NidsAlertSeverity::kLow:
            ++lowCount;
            break;
        case ks::network::NidsAlertSeverity::kMedium:
            ++mediumCount;
            break;
        case ks::network::NidsAlertSeverity::kHigh:
            ++highCount;
            break;
        case ks::network::NidsAlertSeverity::kCritical:
            ++criticalCount;
            break;
        default:
            break;
        }
    }

    const bool kEnabled = (nidsEnableCheck_ == nullptr || nidsEnableCheck_->isChecked());
    nidsStatusLabel_->setText(QStringLiteral("状态：%1 | 已分析 %2 包 | 告警 %3（低 %4 / 中 %5 / 高 %6 / 严重 %7）")
        .arg(kEnabled ? QStringLiteral("实时检测中") : QStringLiteral("已暂停"))
        .arg(static_cast<qulonglong>(nidsAnalyzedPacketCount_))
        .arg(static_cast<qulonglong>(nidsAlertList_.size()))
        .arg(static_cast<qulonglong>(lowCount))
        .arg(static_cast<qulonglong>(mediumCount))
        .arg(static_cast<qulonglong>(highCount))
        .arg(static_cast<qulonglong>(criticalCount)));
}

bool NetworkDock::nidsAlertPassesFilter(const ks::network::NidsAlert& alertRecord) const
{
    if (nidsSeverityFilterCombo_ == nullptr)
    {
        return true;
    }

    const int kMinSeverity = nidsSeverityFilterCombo_->currentData().toInt();
    return nidsSeverityIndex(alertRecord.severity) >= kMinSeverity;
}
