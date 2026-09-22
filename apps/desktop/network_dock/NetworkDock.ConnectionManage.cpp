#include "NetworkDock.InternalCommon.h"
#include "NetworkAuditPage.h"
#include "../framework/PrivilegeElevationPrompt.h"

using namespace network_dock_detail;

void NetworkDock::focusConnectionsByPids(const QVector<quint32>& processIds)
{
    QSet<quint32> processFilterSet;
    for (const quint32 kProcessId : processIds)
    {
        if (kProcessId != 0U)
        {
            processFilterSet.insert(kProcessId);
        }
    }

    if (sideTabWidget_ != nullptr && networkAuditPage_ != nullptr)
    {
        sideTabWidget_->setCurrentWidget(networkAuditPage_);
    }
    if (networkAuditPage_ != nullptr)
    {
        networkAuditPage_->focusProcessIds(processFilterSet);
    }
}

void NetworkDock::setProcessDetailConnectionScope()
{
    // Process details only provide TCP/UDP Cross-View for network auditing.
    // Global network functions such as packet capture, firewall, and diagnostics remain in the independent Network Dock.
    if (sideTabWidget_ == nullptr)
    {
        return;
    }

    for (int tabIndex = 0; tabIndex < sideTabWidget_->count(); ++tabIndex)
    {
        sideTabWidget_->setTabVisible(
            tabIndex,
            sideTabWidget_->widget(tabIndex) == networkAuditPage_);
    }

    if (networkAuditPage_ != nullptr)
    {
        sideTabWidget_->setCurrentWidget(networkAuditPage_);
        networkAuditPage_->activateCrossView();
    }
}

void NetworkDock::refreshConnectionTables()
{
    // Connection snapshot enumeration is an expensive operation:
    // - Skip directly when the connection management page is not visible;
    // - Prevent background timers on hidden pages from continually occupying the UI thread.
    if (sideTabWidget_ != nullptr &&
        connectionManagePage_ != nullptr &&
        sideTabWidget_->currentWidget() != connectionManagePage_)
    {
        return;
    }

    if (connectionRefreshPending_.exchange(true))
    {
        return;
    }

    // IP Helper enumeration and process path resolution may block. Generate a complete snapshot in the
    // background; the GUI thread only applies already-completed data to avoid page switching and scrolling lag.
    QPointer<NetworkDock> guardThis(this);
    std::thread([guardThis]() {
        std::vector<ks::network::TcpConnectionRecord> tcpSnapshot;
        std::vector<ks::network::UdpEndpointRecord> udpSnapshot;
        std::string tcpErrorText;
        std::string udpErrorText;
        const bool kTcpOk = ks::network::enumerateTcpConnectionRecords(tcpSnapshot, &tcpErrorText);
        const bool kUdpOk = ks::network::enumerateUdpEndpointRecords(udpSnapshot, &udpErrorText);
        QMetaObject::invokeMethod(qApp, [guardThis,
            tcpSnapshot = std::move(tcpSnapshot),
            udpSnapshot = std::move(udpSnapshot),
            kTcpOk,
            kUdpOk,
            tcpErrorText = std::move(tcpErrorText),
            udpErrorText = std::move(udpErrorText)]() mutable {
            if (guardThis == nullptr)
            {
                return;
            }
            guardThis->connectionRefreshPending_.store(false);
            guardThis->applyConnectionSnapshot(
                std::move(tcpSnapshot),
                std::move(udpSnapshot),
                kTcpOk,
                kUdpOk,
                std::move(tcpErrorText),
                std::move(udpErrorText));
        }, Qt::QueuedConnection);
    }).detach();
}

void NetworkDock::applyConnectionSnapshot(
    std::vector<ks::network::TcpConnectionRecord> tcpSnapshot,
    std::vector<ks::network::UdpEndpointRecord> udpSnapshot,
    const bool tcpOk,
    const bool udpOk,
    std::string tcpErrorText,
    std::string udpErrorText)
{
    if (sideTabWidget_ != nullptr
        && connectionManagePage_ != nullptr
        && sideTabWidget_->currentWidget() != connectionManagePage_)
    {
        return;
    }

    const QList<QTableView*> kConnectionTables = {
        tcpConnectionTable_,
        udpEndpointTable_
    };
    if (ks::ui::isTableUiCommitBlockedByContextMenu(kConnectionTables))
    {
        // TCP and UDP share the same background snapshot; they must be submitted as a single atomic deferred
        // operation to prevent captured rows from becoming invalid due to table reordering while the menu is open.
        const QPointer<NetworkDock> kSafeThis(this);
        ks::ui::deferTableUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("network-connection-snapshot"),
            kConnectionTables,
            [kSafeThis,
                tcpSnapshot = std::move(tcpSnapshot),
                udpSnapshot = std::move(udpSnapshot),
                tcpOk,
                udpOk,
                tcpErrorText = std::move(tcpErrorText),
                udpErrorText = std::move(udpErrorText)]() mutable
            {
                if (!kSafeThis.isNull())
                {
                    kSafeThis->applyConnectionSnapshot(
                        std::move(tcpSnapshot),
                        std::move(udpSnapshot),
                        tcpOk,
                        udpOk,
                        std::move(tcpErrorText),
                        std::move(udpErrorText));
                }
            });
        return;
    }

    if (!tcpOk || !udpOk)
    {
        if (connectionStatusLabel_ != nullptr)
        {
            connectionStatusLabel_->setText(
                tcpOk ? QStringLiteral("状态：UDP 刷新失败") : QStringLiteral("状态：TCP 刷新失败"));
        }

        KLogEvent refreshFailEvent;
        if (!tcpOk)
        {
            warn << refreshFailEvent
                << "[NetworkDock] 枚举 TCP 连接失败, detail=" << tcpErrorText
                << eol;
        }
        if (!udpOk)
        {
            warn << refreshFailEvent
                << "[NetworkDock] 枚举 UDP 端点失败, detail=" << udpErrorText
                << eol;
        }
        return;
    }

    if (!connectionPidFilterSet_.isEmpty())
    {
        const auto kPidMatches = [this](const std::uint32_t processId)
            {
                return connectionPidFilterSet_.contains(static_cast<quint32>(processId));
            };
        tcpSnapshot.erase(
            std::remove_if(tcpSnapshot.begin(), tcpSnapshot.end(),
                [&kPidMatches](const ks::network::TcpConnectionRecord& record)
                {
                    return !kPidMatches(record.processId);
                }),
            tcpSnapshot.end());
        udpSnapshot.erase(
            std::remove_if(udpSnapshot.begin(), udpSnapshot.end(),
                [&kPidMatches](const ks::network::UdpEndpointRecord& record)
                {
                    return !kPidMatches(record.processId);
                }),
            udpSnapshot.end());
    }

    tcpConnectionCache_ = std::move(tcpSnapshot);
    udpEndpointCache_ = std::move(udpSnapshot);

    if (tcpConnectionTable_ != nullptr)
    {
        const bool kUpdatesEnabled = tcpConnectionTable_->updatesEnabled();
        tcpConnectionTable_->setUpdatesEnabled(false);
        tcpConnectionTable_->setRowCount(static_cast<int>(tcpConnectionCache_.size()));
        for (int rowIndex = 0; rowIndex < static_cast<int>(tcpConnectionCache_.size()); ++rowIndex)
        {
            const ks::network::TcpConnectionRecord& connectionRecord = tcpConnectionCache_[static_cast<std::size_t>(rowIndex)];
            QTableWidgetItem* stateItem = createPacketCell(toQString(connectionRecord.tcpStateText));
            stateItem->setData(Qt::UserRole, rowIndex);
            tcpConnectionTable_->setItem(rowIndex, toTcpConnectionColumn(TcpConnectionTableColumn::kState), stateItem);
            tcpConnectionTable_->setItem(rowIndex, toTcpConnectionColumn(TcpConnectionTableColumn::kPid), createPacketCell(QString::number(connectionRecord.processId)));
            QTableWidgetItem* processItem = createPacketCell(toQString(connectionRecord.processName));
            processItem->setIcon(resolveProcessIconByPid(connectionRecord.processId, connectionRecord.processName));
            tcpConnectionTable_->setItem(rowIndex, toTcpConnectionColumn(TcpConnectionTableColumn::kProcessName), processItem);
            tcpConnectionTable_->setItem(rowIndex, toTcpConnectionColumn(TcpConnectionTableColumn::kLocalEndpoint), createPacketCell(formatEndpointText(connectionRecord.localAddressText, connectionRecord.localPort)));
            tcpConnectionTable_->setItem(rowIndex, toTcpConnectionColumn(TcpConnectionTableColumn::kRemoteEndpoint), createPacketCell(formatEndpointText(connectionRecord.remoteAddressText, connectionRecord.remotePort)));
        }
        tcpConnectionTable_->setUpdatesEnabled(kUpdatesEnabled);
        if (kUpdatesEnabled && tcpConnectionTable_->viewport() != nullptr)
        {
            tcpConnectionTable_->viewport()->update();
        }
    }

    if (udpEndpointTable_ != nullptr)
    {
        const bool kUpdatesEnabled = udpEndpointTable_->updatesEnabled();
        udpEndpointTable_->setUpdatesEnabled(false);
        udpEndpointTable_->setRowCount(static_cast<int>(udpEndpointCache_.size()));
        for (int rowIndex = 0; rowIndex < static_cast<int>(udpEndpointCache_.size()); ++rowIndex)
        {
            const ks::network::UdpEndpointRecord& endpointRecord = udpEndpointCache_[static_cast<std::size_t>(rowIndex)];
            udpEndpointTable_->setItem(rowIndex, toUdpEndpointColumn(UdpEndpointTableColumn::kPid), createPacketCell(QString::number(endpointRecord.processId)));
            QTableWidgetItem* processItem = createPacketCell(toQString(endpointRecord.processName));
            processItem->setIcon(resolveProcessIconByPid(endpointRecord.processId, endpointRecord.processName));
            udpEndpointTable_->setItem(rowIndex, toUdpEndpointColumn(UdpEndpointTableColumn::kProcessName), processItem);
            udpEndpointTable_->setItem(rowIndex, toUdpEndpointColumn(UdpEndpointTableColumn::kLocalEndpoint), createPacketCell(formatEndpointText(endpointRecord.localAddressText, endpointRecord.localPort)));
        }
        udpEndpointTable_->setUpdatesEnabled(kUpdatesEnabled);
        if (kUpdatesEnabled && udpEndpointTable_->viewport() != nullptr)
        {
            udpEndpointTable_->viewport()->update();
        }
    }

    if (connectionStatusLabel_ != nullptr)
    {
        const QString kNowText = QDateTime::currentDateTime().toString("HH:mm:ss");
        QString filterText;
        if (!connectionPidFilterSet_.isEmpty())
        {
            QStringList pidTextList;
            for (const quint32 kProcessId : std::as_const(connectionPidFilterSet_))
            {
                pidTextList.push_back(QString::number(kProcessId));
            }
            std::sort(pidTextList.begin(), pidTextList.end(), [](const QString& left, const QString& right) {
                return left.toULongLong() < right.toULongLong();
            });
            filterText = QStringLiteral("，PID筛选=%1 个进程")
                .arg(connectionPidFilterSet_.size());
            connectionStatusLabel_->setToolTip(
                QStringLiteral("PID：%1").arg(pidTextList.join(',')));
        }
        else
        {
            connectionStatusLabel_->setToolTip(QString());
        }
        connectionStatusLabel_->setText(
            QStringLiteral("状态：TCP=%1 条, UDP=%2 条%3, 刷新于 %4")
            .arg(static_cast<int>(tcpConnectionCache_.size()))
            .arg(static_cast<int>(udpEndpointCache_.size()))
            .arg(filterText)
            .arg(kNowText));
    }

    // Refresh frequency is high; use dbg level here to avoid overly dense info logs.
    KLogEvent refreshEvent;
    dbg << refreshEvent
        << "[NetworkDock] 刷新连接快照完成, tcpCount=" << tcpConnectionCache_.size()
        << ", udpCount=" << udpEndpointCache_.size()
        << eol;
}

void NetworkDock::refreshTcpConnectionTable()
{
    if (tcpConnectionTable_ == nullptr)
    {
        return;
    }

    const QPointer<NetworkDock> kSafeThis(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("network-tcp-connection-refresh"),
        {tcpConnectionTable_},
        [kSafeThis]()
        {
            if (!kSafeThis.isNull())
            {
                kSafeThis->refreshTcpConnectionTable();
            }
        }))
    {
        return;
    }

    std::vector<ks::network::TcpConnectionRecord> tcpSnapshot;
    std::string errorText;
    if (!ks::network::enumerateTcpConnectionRecords(tcpSnapshot, &errorText))
    {
        if (connectionStatusLabel_ != nullptr)
        {
            connectionStatusLabel_->setText(QStringLiteral("状态：TCP 刷新失败"));
        }

        KLogEvent refreshFailEvent;
        warn << refreshFailEvent
            << "[NetworkDock] 枚举 TCP 连接失败, detail=" << errorText
            << eol;
        return;
    }

    // Refresh cache: terminated connections will look up this cache via row index.
    tcpConnectionCache_ = std::move(tcpSnapshot);

    tcpConnectionTable_->setUpdatesEnabled(false);
    tcpConnectionTable_->setRowCount(static_cast<int>(tcpConnectionCache_.size()));

    int rowIndex = 0;
    for (const ks::network::TcpConnectionRecord& connectionRecord : tcpConnectionCache_)
    {
        const int kCacheIndex = rowIndex;
        const QString kStateText = toQString(connectionRecord.tcpStateText);
        const QString kPidText = QString::number(connectionRecord.processId);
        const QString kProcessNameText = toQString(connectionRecord.processName);
        const QString kLocalEndpointText = formatEndpointText(connectionRecord.localAddressText, connectionRecord.localPort);
        const QString kRemoteEndpointText = formatEndpointText(connectionRecord.remoteAddressText, connectionRecord.remotePort);

        QTableWidgetItem* stateItem = createPacketCell(kStateText);
        stateItem->setData(Qt::UserRole, kCacheIndex);
        tcpConnectionTable_->setItem(rowIndex, toTcpConnectionColumn(TcpConnectionTableColumn::kState), stateItem);
        tcpConnectionTable_->setItem(rowIndex, toTcpConnectionColumn(TcpConnectionTableColumn::kPid), createPacketCell(kPidText));
        QTableWidgetItem* processItem = createPacketCell(kProcessNameText);
        processItem->setIcon(resolveProcessIconByPid(connectionRecord.processId, connectionRecord.processName));
        tcpConnectionTable_->setItem(rowIndex, toTcpConnectionColumn(TcpConnectionTableColumn::kProcessName), processItem);
        tcpConnectionTable_->setItem(rowIndex, toTcpConnectionColumn(TcpConnectionTableColumn::kLocalEndpoint), createPacketCell(kLocalEndpointText));
        tcpConnectionTable_->setItem(rowIndex, toTcpConnectionColumn(TcpConnectionTableColumn::kRemoteEndpoint), createPacketCell(kRemoteEndpointText));
        ++rowIndex;
    }

    tcpConnectionTable_->setUpdatesEnabled(true);
    tcpConnectionTable_->viewport()->update();
}

void NetworkDock::refreshUdpEndpointTable()
{
    if (udpEndpointTable_ == nullptr)
    {
        return;
    }

    const QPointer<NetworkDock> kSafeThis(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("network-udp-endpoint-refresh"),
        {udpEndpointTable_},
        [kSafeThis]()
        {
            if (!kSafeThis.isNull())
            {
                kSafeThis->refreshUdpEndpointTable();
            }
        }))
    {
        return;
    }

    std::vector<ks::network::UdpEndpointRecord> udpSnapshot;
    std::string errorText;
    if (!ks::network::enumerateUdpEndpointRecords(udpSnapshot, &errorText))
    {
        if (connectionStatusLabel_ != nullptr)
        {
            connectionStatusLabel_->setText(QStringLiteral("状态：UDP 刷新失败"));
        }

        KLogEvent refreshFailEvent;
        warn << refreshFailEvent
            << "[NetworkDock] 枚举 UDP 端点失败, detail=" << errorText
            << eol;
        return;
    }

    udpEndpointCache_ = std::move(udpSnapshot);

    udpEndpointTable_->setUpdatesEnabled(false);
    udpEndpointTable_->setRowCount(static_cast<int>(udpEndpointCache_.size()));

    int rowIndex = 0;
    for (const ks::network::UdpEndpointRecord& endpointRecord : udpEndpointCache_)
    {
        const QString kPidText = QString::number(endpointRecord.processId);
        const QString kProcessNameText = toQString(endpointRecord.processName);
        const QString kLocalEndpointText = formatEndpointText(endpointRecord.localAddressText, endpointRecord.localPort);

        udpEndpointTable_->setItem(rowIndex, toUdpEndpointColumn(UdpEndpointTableColumn::kPid), createPacketCell(kPidText));
        QTableWidgetItem* processItem = createPacketCell(kProcessNameText);
        processItem->setIcon(resolveProcessIconByPid(endpointRecord.processId, endpointRecord.processName));
        udpEndpointTable_->setItem(rowIndex, toUdpEndpointColumn(UdpEndpointTableColumn::kProcessName), processItem);
        udpEndpointTable_->setItem(rowIndex, toUdpEndpointColumn(UdpEndpointTableColumn::kLocalEndpoint), createPacketCell(kLocalEndpointText));
        ++rowIndex;
    }

    udpEndpointTable_->setUpdatesEnabled(true);
    udpEndpointTable_->viewport()->update();
}

void NetworkDock::terminateSelectedTcpConnection()
{
    if (tcpConnectionTable_ == nullptr)
    {
        return;
    }

    // Explicit binding between table row and cache index:
    // - When sorting is disabled, row == cacheIndex.
    // - Subsequent header sorting will not close erroneous connections due to display row changes.
    const int kSelectedRow = tcpConnectionTable_->currentRow();
    int cacheIndex = kSelectedRow;
    if (kSelectedRow >= 0)
    {
        QTableWidgetItem* stateItem = tcpConnectionTable_->item(
            kSelectedRow,
            toTcpConnectionColumn(TcpConnectionTableColumn::kState));
        if (stateItem != nullptr)
        {
            const QVariant kCacheIndexVariant = stateItem->data(Qt::UserRole);
            bool parseOk = false;
            const int kParsedCacheIndex = kCacheIndexVariant.toInt(&parseOk);
            if (parseOk)
            {
                cacheIndex = kParsedCacheIndex;
            }
        }
    }

    if (cacheIndex < 0 || cacheIndex >= static_cast<int>(tcpConnectionCache_.size()))
    {
        QMessageBox::information(this, QStringLiteral("连接管理"), QStringLiteral("请先选中一条 TCP 连接。"));
        return;
    }

    // Copy the target record instead of holding a cache reference:
    // - QMessageBox::question enters a nested event loop;
    // - The auto-refresh timer may rebuild m_tcpConnectionCache while the confirmation dialog is open.
    // - If a reference is used directly, the user might access a dangling object after clicking confirmation, leading to incorrect close request parameters.
    const ks::network::TcpConnectionRecord kTargetConnection = tcpConnectionCache_[static_cast<std::size_t>(cacheIndex)];
    // DELETE_TCB applies only to active IPv4 connections:
    // - LISTEN entries are listening sockets, not established connections.
    // - IPv6 lines cannot be passed to IPv4-only SetTcpEntry;
    // - Intercept these scenarios before showing the confirmation dialog to avoid misinterpreting the system's error code 317 as insufficient permissions.
    const std::string kUnsupportedReason = ks::network::getTcpTerminationUnsupportedReason(kTargetConnection);
    if (!kUnsupportedReason.empty())
    {
        QMessageBox::information(
            this,
            QStringLiteral("连接管理"),
            QStringLiteral("当前 TCP 行不能通过 DELETE_TCB 终止：%1").arg(toQString(kUnsupportedReason)));

        KLogEvent unsupportedTerminateEvent;
        info << unsupportedTerminateEvent
            << "[NetworkDock] 跳过不支持的 TCP 终止请求, pid=" << kTargetConnection.processId
            << ", state=" << kTargetConnection.tcpStateText
            << ", local=" << kTargetConnection.localAddressText << ":" << kTargetConnection.localPort
            << ", remote=" << kTargetConnection.remoteAddressText << ":" << kTargetConnection.remotePort
            << ", reason=" << kUnsupportedReason
            << eol;
        return;
    }

    const int kUserChoice = QMessageBox::question(
        this,
        QStringLiteral("终止 TCP 连接"),
        QStringLiteral("确认终止连接？\nPID=%1\n本地=%2:%3\n远端=%4:%5")
        .arg(kTargetConnection.processId)
        .arg(toQString(kTargetConnection.localAddressText))
        .arg(kTargetConnection.localPort)
        .arg(toQString(kTargetConnection.remoteAddressText))
        .arg(kTargetConnection.remotePort),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kUserChoice != QMessageBox::Yes)
    {
        return;
    }

    std::string detailText;
    const bool kTerminateOk = ks::network::terminateTcpConnectionByRecord(kTargetConnection, &detailText);
    if (kTerminateOk)
    {
        QMessageBox::information(this, QStringLiteral("连接管理"), QStringLiteral("连接终止请求已提交。"));

        KLogEvent terminateEvent;
        info << terminateEvent
            << "[NetworkDock] 终止 TCP 连接成功, pid=" << kTargetConnection.processId
            << ", local=" << kTargetConnection.localAddressText << ":" << kTargetConnection.localPort
            << ", remote=" << kTargetConnection.remoteAddressText << ":" << kTargetConnection.remotePort
            << ", detail=" << detailText
            << eol;
    }
    else
    {
        // privilegePromptHandled: Do not display the generic connection error if the privilege escalation prompt has already explained the failure.
        const bool kPrivilegePromptHandled = ks::ui::promptForPrivilegeFailure(
            this,
            QStringLiteral("终止 TCP 连接"),
            QString::fromStdString(detailText));
        if (!kPrivilegePromptHandled)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("连接管理"),
                QStringLiteral("终止连接失败：%1").arg(toQString(detailText)));
        }

        KLogEvent terminateFailEvent;
        warn << terminateFailEvent
            << "[NetworkDock] 终止 TCP 连接失败, pid=" << kTargetConnection.processId
            << ", detail=" << detailText
            << eol;
    }

    refreshConnectionTables();
}

void NetworkDock::copySelectedConnectionRowToClipboard(QTableWidget* tableWidget)
{
    if (tableWidget == nullptr)
    {
        return;
    }

    const int kSelectedRow = tableWidget->currentRow();
    if (kSelectedRow < 0)
    {
        return;
    }

    QStringList rowTextList;
    rowTextList.reserve(tableWidget->columnCount());
    for (int columnIndex = 0; columnIndex < tableWidget->columnCount(); ++columnIndex)
    {
        QTableWidgetItem* item = tableWidget->item(kSelectedRow, columnIndex);
        rowTextList.push_back(item == nullptr ? QString() : item->text());
    }

    if (QGuiApplication::clipboard() != nullptr)
    {
        QGuiApplication::clipboard()->setText(rowTextList.join('\t'));
    }

    KLogEvent copyRowEvent;
    dbg << copyRowEvent
        << "[NetworkDock] 已复制连接表行到剪贴板, tableColumns=" << tableWidget->columnCount()
        << ", row=" << kSelectedRow
        << eol;
}
