#include "NetworkDock.InternalCommon.h"
#include "NetworkAuditPage.h"
#include "NetworkFirewallPage.h"
#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../PluginHost.h"
#include "../online_scan/SandboxUploadActions.h"
#include "../ui/TableInteractionSupport.h"
#include "../Theme.h"

#include <QCoreApplication>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <string>

using namespace network_dock_detail;

namespace
{
    // r0WfpPacketAddressText:
    // - Convert IPv4/IPv6 network-order addresses from shared/driver WFP packet rows to standard text.
    // - On conversion failure, return the corresponding unspecified address to avoid reading bytes beyond the protocol line;
    // - Returns: UTF-8 address suitable for writing to PacketRecord.
    std::string r0WfpPacketAddressText(
        const unsigned long addressFamily,
        const unsigned char addressBytes[16])
    {
        const int kNativeAddressFamily =
            addressFamily == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV6
            ? AF_INET6
            : AF_INET;
        char addressBuffer[INET6_ADDRSTRLEN] = {};
        if (addressBytes == nullptr ||
            InetNtopA(
                kNativeAddressFamily,
                addressBytes,
                addressBuffer,
                static_cast<DWORD>(std::size(addressBuffer))) == nullptr)
        {
            return kNativeAddressFamily == AF_INET6
                ? std::string("::")
                : std::string("0.0.0.0");
        }
        return std::string(addressBuffer);
    }

    // resolveR0WfpPacketProcessId:
    // - Prefer R0 metadata PID; resolve via local endpoint table if not provided at the IPPACKET layer.
    // - Both IPv4 and IPv6 use the existing 250ms throttled resolver defined in network.h.
    // - Returns: PID, or 0 if unattributable.
    std::uint32_t resolveR0WfpPacketProcessId(
        const KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW& packetRow,
        ks::network::detail::ConnectionPidResolver& pidResolver)
    {
        if (packetRow.processId != 0UL)
        {
            return packetRow.processId;
        }

        const auto kProtocol =
            static_cast<ks::network::PacketTransportProtocol>(packetRow.protocol);
        if (packetRow.addressFamily == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV4)
        {
            std::uint32_t localAddressNetworkOrder = 0U;
            std::uint32_t remoteAddressNetworkOrder = 0U;
            std::memcpy(
                &localAddressNetworkOrder,
                packetRow.localAddress,
                sizeof(localAddressNetworkOrder));
            std::memcpy(
                &remoteAddressNetworkOrder,
                packetRow.remoteAddress,
                sizeof(remoteAddressNetworkOrder));
            return pidResolver.resolveProcessId(
                kProtocol,
                ntohl(localAddressNetworkOrder),
                packetRow.localPort,
                ntohl(remoteAddressNetworkOrder),
                packetRow.remotePort);
        }

        ks::network::detail::Ipv6Bytes localAddress{};
        ks::network::detail::Ipv6Bytes remoteAddress{};
        std::memcpy(localAddress.data(), packetRow.localAddress, localAddress.size());
        std::memcpy(remoteAddress.data(), packetRow.remoteAddress, remoteAddress.size());
        return pidResolver.resolveProcessIdV6(
            kProtocol,
            localAddress,
            packetRow.localPort,
            remoteAddress,
            packetRow.remotePort);
    }

    // buildR0WfpPacketRecord:
    // - Convert real R0 WFP IPv4/IPv6 IP packet layer records into the unified traffic monitoring model.
    // - Preserve full packet length/payload boundaries and restricted raw prefixes; complete missing PID on the R3 side.
    // - Returns: Per-packet records ready to be written directly to the NetworkDock cache.
    ks::network::PacketRecord buildR0WfpPacketRecord(
        const KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW& packetRow,
        ks::network::detail::ConnectionPidResolver& pidResolver,
        ks::network::detail::ProcessNameResolver& processNameResolver)
    {
        constexpr std::uint64_t kWindowsEpochToUnixEpoch100ns = 116444736000000000ULL;
        ks::network::PacketRecord packetRecord;
        packetRecord.captureTimestampMs =
            packetRow.timestamp100ns >= kWindowsEpochToUnixEpoch100ns
            ? (packetRow.timestamp100ns - kWindowsEpochToUnixEpoch100ns) / 10000ULL
            : 0ULL;
        packetRecord.protocol =
            static_cast<ks::network::PacketTransportProtocol>(packetRow.protocol);
        packetRecord.direction =
            packetRow.direction == KSWORD_ARK_NETWORK_DIRECTION_OUTBOUND
            ? ks::network::PacketDirection::kOutbound
            : ks::network::PacketDirection::kInbound;
        packetRecord.processId = resolveR0WfpPacketProcessId(packetRow, pidResolver);
        packetRecord.processName = processNameResolver.resolveProcessName(packetRecord.processId);
        packetRecord.sourceSequenceId = packetRow.sequence;
        packetRecord.sourceFlags = packetRow.flags;
        packetRecord.sourceText = "R0-WFP-PACKET";
        packetRecord.localAddress = r0WfpPacketAddressText(packetRow.addressFamily, packetRow.localAddress);
        packetRecord.localPort = packetRow.localPort;
        packetRecord.remoteAddress = r0WfpPacketAddressText(packetRow.addressFamily, packetRow.remoteAddress);
        packetRecord.remotePort = packetRow.remotePort;
        packetRecord.totalPacketSize = packetRow.totalPacketLength;
        packetRecord.payloadSize = packetRow.payloadLength;
        packetRecord.payloadOffset = packetRow.payloadOffset;
        packetRecord.packetBytesTruncated =
            (packetRow.flags & KSWORD_ARK_NETWORK_TRAFFIC_PACKET_FLAG_TRUNCATED) != 0UL;
        const std::size_t kCapturedLength = std::min<std::size_t>(
            packetRow.capturedLength,
            KSWORD_ARK_NETWORK_TRAFFIC_MAX_CAPTURE_BYTES);
        packetRecord.packetBytes.assign(
            packetRow.capturedBytes,
            packetRow.capturedBytes + kCapturedLength);
        return packetRecord;
    }

    // disableNetworkTrafficCaptureAsync:
    // - Offloads the synchronous IOCTL for "disabling R0 packet-level data plane" to a background thread;
    //   CreateFileW + DeviceIoControl without OVERLAPPED: the kernel must unregister the
    //   WFP callout. Issuing directly from the UI thread would cause perceptible lag.
    // - Input: None (this control plane only has two idempotent commands: 'enable' and 'disable'; this call unconditionally issues the 'disable' command).
    // - Return: None; if disabling fails, only a warning log is written; no UI update is triggered.
    void disableNetworkTrafficCaptureAsync()
    {
        std::thread([]()
            {
                const ksword::ark::DriverClient kDriverClient;
                const ksword::ark::NetworkTrafficCaptureControlResult kCaptureControl =
                    kDriverClient.controlNetworkTrafficCapture(false);
                if (!kCaptureControl.io.ok ||
                    kCaptureControl.response.status != KSWORD_ARK_NETWORK_STATUS_DISABLED)
                {
                    KLogEvent disableEvent;
                    warn << disableEvent
                         << "[NetworkDock] R0 逐包数据面停用失败: "
                         << kCaptureControl.io.message << eol;
                }
            }).detach();
    }
}

void NetworkDock::initializeConnections()
{
    connect(sideTabWidget_, &QTabWidget::currentChanged, this, [this](const int /*index*/)
        {
            QWidget* currentPage = sideTabWidget_ != nullptr ? sideTabWidget_->currentWidget() : nullptr;
            if (currentPage == firewallPage_ && firewallPage_ != nullptr)
            {
                firewallPage_->requestInitialRefresh();
            }
            else if (currentPage == networkAuditPage_ && networkAuditPage_ != nullptr)
            {
                networkAuditPage_->requestInitialRefresh();
            }
        });

    // Connect start/stop packet capture and clear table buttons.
    connect(startMonitorButton_, &QPushButton::clicked, this, [this]()
        {
            startTrafficMonitor();
        });
    connect(stopMonitorButton_, &QPushButton::clicked, this, [this]()
        {
            stopTrafficMonitor();
        });
    connect(clearPacketButton_, &QPushButton::clicked, this, [this]()
        {
            clearAllPacketRows();
        });
    connect(networkPluginMenu_, &QMenu::aboutToShow, this, [this]()
        {
            ks::plugin_host::InvocationContext context;
            context.targetKind = ks::plugin_host::TargetKind::kNetwork;
            ks::plugin_host::populateTargetMenu(networkPluginMenu_, this, context);
        });

    // NIDS control connection: real-time detection toggle, level filtering, and clearing.
    connect(nidsEnableCheck_, &QCheckBox::toggled, this, [this](const bool checked)
        {
            if (!checked)
            {
                nidsEngine_.reset();
            }
            updateNidsStatusLabel();
        });
    connect(nidsSeverityFilterCombo_, static_cast<void(QComboBox::*)(int)>(&QComboBox::currentIndexChanged), this, [this](const int /*index*/)
        {
            rebuildNidsAlertTable();
            updateNidsStatusLabel();
        });
    connect(nidsClearButton_, &QPushButton::clicked, this, [this]()
        {
            clearNidsAlerts();
        });
    const auto kNidsAlertSequenceForRow = [this](const int row, std::uint64_t& sequenceIdOut) -> bool
        {
            if (nidsAlertTable_ == nullptr || row < 0 || row >= nidsAlertTable_->rowCount())
            {
                return false;
            }

            QTableWidgetItem* timeItem = nidsAlertTable_->item(row, toNidsAlertColumn(NidsAlertTableColumn::kTime));
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
        };
    connect(nidsAlertTable_, &QTableWidget::cellDoubleClicked, this,
        [this, kNidsAlertSequenceForRow](const int row, const int /*column*/)
        {
            std::uint64_t sequenceId = 0;
            if (kNidsAlertSequenceForRow(row, sequenceId))
            {
                openPacketDetailWindowBySequenceId(sequenceId);
            }
        });
    // NIDS alert table right-click menu description:
    // - This menu was previously registered here and in initializeNidsTab(), causing both slots to invoke QMenu::exec();
    // - Qt invokes slots sequentially based on connection order. Consequently, a single right-click first displays the 'Copy Class' menu; after
    //   closing it, the 'Details Class' menu immediately appears. This results in inconsistent menu content when right-clicking twice consecutively.
    // Currently, the merged menu is registered exclusively by initializeNidsTab() in NetworkDock.Nids.cpp; no registration occurs here.

    // Traffic timeline connection:
    // - ProcessTraceTimelineWidget reuses the ETW page's selection, drag, and wheel-zoom tools internally.
    // - Here, only the final time range is received and overlaid onto the existing rule group filtering and table rebuild process.
    if (packetTimelineWidget_ != nullptr)
    {
        packetTimelineWidget_->setSelectionChangedCallback(
            [this](const std::uint64_t start100ns, const std::uint64_t end100ns)
            {
                applyPacketTimelineSelection(start100ns, end100ns);
            });
    }

    // Combined filter control connection:
    // - The funnel button controls the visibility of the collapsed panel.
    // - Rule groups support adding, applying, importing, exporting, default saving, and one-click clearing.
    connect(monitorFilterToggleButton_, &QPushButton::toggled, this, [this](const bool checked)
        {
            if (monitorFilterPanel_ != nullptr)
            {
                monitorFilterPanel_->setVisible(checked);
            }
        });

    connect(addMonitorFilterGroupButton_, &QPushButton::clicked, this, [this]()
        {
            addMonitorFilterRuleGroup();
        });

    connect(applyMonitorFilterButton_, &QPushButton::clicked, this, [this]()
        {
            applyMonitorFilters();
        });
    connect(clearMonitorFilterButton_, &QPushButton::clicked, this, [this]()
        {
            clearAllMonitorFilterConfigurations();
        });
    connect(saveMonitorFilterButton_, &QPushButton::clicked, this, [this]()
        {
            saveMonitorFilterConfigToDefaultPath();
        });
    connect(importMonitorFilterButton_, &QPushButton::clicked, this, [this]()
        {
            importMonitorFilterConfigFromUserSelectedPath();
        });
    connect(exportMonitorFilterButton_, &QPushButton::clicked, this, [this]()
        {
            exportMonitorFilterConfigToUserSelectedPath();
        });

    // Control connections via rate-limiting rules.
    // Notes:
    // - The current version hides the 'Process Rate Limiting' page, so these buttons are typically not created.
    // - Retain null pointer protection to avoid a startup crash from QObject::connect(nullptr,
    //   ...) when temporarily restoring paths other than initializeRateLimitTab() in the future;
    // - The function has no return value and establishes a connection from the UI to the business logic only if the corresponding button exists.
    if (applyRateLimitButton_ != nullptr)
    {
        connect(applyRateLimitButton_, &QPushButton::clicked, this, [this]()
            {
                applyOrUpdateRateLimitRule();
            });
    }
    if (removeRateLimitButton_ != nullptr)
    {
        connect(removeRateLimitButton_, &QPushButton::clicked, this, [this]()
            {
                removeSelectedRateLimitRule();
            });
    }
    if (clearRateLimitButton_ != nullptr)
    {
        connect(clearRateLimitButton_, &QPushButton::clicked, this, [this]()
            {
                clearAllRateLimitRules();
            });
    }

    // The legacy connection management page is no longer created; the implementation is retained for rollback, but connections must not be established to null controls.
    if (refreshConnectionButton_ != nullptr)
    {
        connect(refreshConnectionButton_, &QPushButton::clicked, this, [this]()
        {
            KLogEvent refreshClickEvent;
            info << refreshClickEvent << "[NetworkDock] 用户触发连接快照手动刷新。" << eol;
            refreshConnectionTables();
        });
    }
    if (autoRefreshConnectionButton_ != nullptr)
    {
        connect(autoRefreshConnectionButton_, &QPushButton::toggled, this, [this](const bool checked)
        {
            if (autoRefreshConnectionButton_ != nullptr)
            {
                // The icon must follow the state: when enabled, show 'Pause' to indicate it can be clicked to pause;
                // when disabled, show 'Resume'. Otherwise, a pressed 'Pause' icon might be misread as 'Currently
                // paused, click me to resume', causing users to accidentally turn off the active auto-refresh.
                autoRefreshConnectionButton_->setIcon(QIcon(
                    checked ? QStringLiteral(":/Icon/process_pause.svg")
                    : QStringLiteral(":/Icon/process_resume.svg")));
                autoRefreshConnectionButton_->setToolTip(
                    checked ? QStringLiteral("自动刷新已开启，点击暂停")
                    : QStringLiteral("自动刷新已关闭，点击继续"));
            }
            if (connectionStatusLabel_ != nullptr)
            {
                connectionStatusLabel_->setText(
                    checked ? QStringLiteral("状态：自动刷新已开启")
                    : QStringLiteral("状态：自动刷新已关闭"));
            }

            KLogEvent autoRefreshEvent;
            info << autoRefreshEvent
                << "[NetworkDock] 连接自动刷新开关变更, enabled="
                << (checked ? "true" : "false")
                << eol;
        });
    }
    if (terminateTcpButton_ != nullptr)
    {
        connect(terminateTcpButton_, &QPushButton::clicked, this, [this]()
        {
            terminateSelectedTcpConnection();
        });
    }
    if (clearConnectionPidFilterButton_ != nullptr)
    {
        connect(clearConnectionPidFilterButton_, &QPushButton::clicked, this, [this]()
        {
            connectionPidFilterSet_.clear();
            if (clearConnectionPidFilterButton_ != nullptr)
            {
                clearConnectionPidFilterButton_->setEnabled(false);
            }
            refreshConnectionTables();
        });
    }

    // HTTPS analysis control connection.
    connect(httpsStartProxyButton_, &QPushButton::clicked, this, [this]()
        {
            startHttpsProxyService();
        });
    connect(httpsStopProxyButton_, &QPushButton::clicked, this, [this]()
        {
            stopHttpsProxyService();
        });
    connect(httpsTrustCertButton_, &QPushButton::clicked, this, [this]()
        {
            ensureHttpsRootCertificateTrusted();
        });
    connect(httpsApplyProxyButton_, &QPushButton::clicked, this, [this]()
        {
            applyHttpsSystemProxy();
        });
    connect(httpsClearProxyButton_, &QPushButton::clicked, this, [this]()
        {
            clearHttpsSystemProxy();
        });

    // Helper for parsing PID from the connection table row:
    // - Extract the PID from a specified column in any connection table (TCP/UDP).
    // - On failure, display a unified dialog and log the event to reduce code duplication.
    const auto kParsePidFromConnectionRow = [this](
        QTableWidget* tableWidget,
        const int row,
        const int pidColumn,
        std::uint32_t& pidOut,
        const QString& sourceTag) -> bool
        {
            if (tableWidget == nullptr || row < 0 || row >= tableWidget->rowCount())
            {
                return false;
            }

            QTableWidgetItem* pidItem = tableWidget->item(row, pidColumn);
            if (pidItem == nullptr)
            {
                return false;
            }

            if (!tryParsePidText(pidItem->text(), pidOut))
            {
                QMessageBox::information(
                    this,
                    QStringLiteral("连接管理"),
                    QStringLiteral("当前行 PID 无效，无法执行该操作。"));

                KLogEvent parsePidFailEvent;
                warn << parsePidFailEvent
                    << "[NetworkDock] 连接表 PID 解析失败, source="
                    << sourceTag.toStdString()
                    << ", row=" << row
                    << ", pidText=" << pidItem->text().toStdString()
                    << eol;
                return false;
            }
            return true;
        };

    // Helper to open process details:
    // - Both the connection table and traffic table reuse the same 'open detail window by PID' logic.
    // - Unified format for logs and error messages.
    const auto kOpenProcessDetailByPid = [this](const std::uint32_t targetPid, const QString& sourceTag) -> void
        {
            // Connection table jumps must avoid synchronous full static queries:
            // - queryProcessStaticDetailByPid includes signature verification by default internally;
            // - Detail window is responsible for asynchronously completing fields and lazily loading advanced pages.
            ks::process::ProcessRecord processRecord;
            processRecord.pid = targetPid;
            processRecord.processName = ks::process::getProcessNameByPid(targetPid);
            if (processRecord.processName.empty())
            {
                processRecord.processName = "PID_" + std::to_string(targetPid);
            }

            ProcessDetailWindow* detailWindow = new ProcessDetailWindow(processRecord, nullptr);
            detailWindow->setAttribute(Qt::WA_DeleteOnClose, true);
            detailWindow->setWindowFlag(Qt::Window, true);
            detailWindow->show();
            detailWindow->raise();
            detailWindow->activateWindow();

            KLogEvent processDetailEvent;
            info << processDetailEvent
                << "[NetworkDock] 连接表打开进程详情, source=" << sourceTag.toStdString()
                << ", pid=" << targetPid
                << eol;
        };

    // TCP table right-click menu:
    // - Supports 'Terminate Connection', 'Copy Row', 'Trace This Process', and 'Go to Process Details'.
    // - 'Track this process' semantically means writing the PID filter and applying it immediately.
    if (tcpConnectionTable_ != nullptr)
    {
        connect(
            tcpConnectionTable_,
            &QWidget::customContextMenuRequested,
            this,
            [this, kParsePidFromConnectionRow, kOpenProcessDetailByPid](const QPoint& position)
            {
            const QModelIndex kIndex = tcpConnectionTable_->indexAt(position);
            if (!kIndex.isValid())
            {
                return;
            }

            QMenu contextMenu(this);
            contextMenu.setStyleSheet(ksword_theme::contextMenuStyle());
            QAction* terminateAction = contextMenu.addAction(QIcon(":/Icon/process_terminate.svg"), QStringLiteral("终止此 TCP 连接"));
            QAction* copyRowAction = contextMenu.addAction(QIcon(":/Icon/process_copy_row.svg"), QStringLiteral("复制行"));
            QAction* trackProcessAction = contextMenu.addAction(QIcon(":/Icon/log_track.svg"), QStringLiteral("跟踪此进程"));
            QAction* gotoProcessDetailAction = contextMenu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("转到进程详细信息"));
            QAction* uploadVirusTotalAction = ks::online_scan::addVirusTotalSandboxMenu(
                &contextMenu,
                this,
                [this, kIndex, kParsePidFromConnectionRow]() -> ks::online_scan::SandboxUploadTarget
                {
                    // Input: Current row of the TCP connection table.
                    // Processing: Parse PID and query the initiating process EXE.
                    // Returns: Upload path and source description.
                    ks::online_scan::SandboxUploadTarget uploadTarget;
                    std::uint32_t targetPid = 0;
                    if (!kParsePidFromConnectionRow(
                        tcpConnectionTable_,
                        kIndex.row(),
                        toTcpConnectionColumn(TcpConnectionTableColumn::kPid),
                        targetPid,
                        QStringLiteral("tcp_table_upload")))
                    {
                        uploadTarget.errorText = QStringLiteral("当前 TCP 行没有可解析 PID。");
                        return uploadTarget;
                    }
                    uploadTarget.filePath = QString::fromStdString(ks::process::queryProcessPathByPid(targetPid));
                    uploadTarget.sourceText = QStringLiteral("网络 TCP 连接 PID=%1").arg(targetPid);
                    return uploadTarget;
                });
            QAction* selectedAction = contextMenu.exec(tcpConnectionTable_->viewport()->mapToGlobal(position));
            if (selectedAction == terminateAction)
            {
                tcpConnectionTable_->selectRow(kIndex.row());
                terminateSelectedTcpConnection();
            }
            else if (selectedAction == copyRowAction)
            {
                tcpConnectionTable_->selectRow(kIndex.row());
                copySelectedConnectionRowToClipboard(tcpConnectionTable_);
            }
            else if (selectedAction == trackProcessAction)
            {
                tcpConnectionTable_->selectRow(kIndex.row());

                std::uint32_t targetPid = 0;
                if (!kParsePidFromConnectionRow(
                    tcpConnectionTable_,
                    kIndex.row(),
                    toTcpConnectionColumn(TcpConnectionTableColumn::kPid),
                    targetPid,
                    QStringLiteral("tcp_table")))
                {
                    return;
                }

                addOrTrackProcessPid(targetPid);

                KLogEvent trackEvent;
                info << trackEvent
                    << "[NetworkDock] TCP 连接右键触发进程跟踪, pid=" << targetPid
                    << eol;
            }
            else if (selectedAction == gotoProcessDetailAction)
            {
                tcpConnectionTable_->selectRow(kIndex.row());

                std::uint32_t targetPid = 0;
                if (!kParsePidFromConnectionRow(
                    tcpConnectionTable_,
                    kIndex.row(),
                    toTcpConnectionColumn(TcpConnectionTableColumn::kPid),
                    targetPid,
                    QStringLiteral("tcp_table")))
                {
                    return;
                }
                kOpenProcessDetailByPid(targetPid, QStringLiteral("tcp_table"));
            }
            else if (selectedAction == uploadVirusTotalAction)
            {
                return;
            }
            });
    }

    // UDP table right-click menu:
    // - UDP lacks a standard 'terminate per connection' API, so terminate is not provided.
    // - Still supports copying rows, tracking this process, and navigating to process details.
    if (udpEndpointTable_ != nullptr)
    {
        connect(
            udpEndpointTable_,
            &QWidget::customContextMenuRequested,
            this,
            [this, kParsePidFromConnectionRow, kOpenProcessDetailByPid](const QPoint& position)
            {
            const QModelIndex kIndex = udpEndpointTable_->indexAt(position);
            if (!kIndex.isValid())
            {
                return;
            }

            QMenu contextMenu(this);
            contextMenu.setStyleSheet(ksword_theme::contextMenuStyle());
            QAction* copyRowAction = contextMenu.addAction(QIcon(":/Icon/process_copy_row.svg"), QStringLiteral("复制行"));
            QAction* trackProcessAction = contextMenu.addAction(QIcon(":/Icon/log_track.svg"), QStringLiteral("跟踪此进程"));
            QAction* gotoProcessDetailAction = contextMenu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("转到进程详细信息"));
            QAction* uploadVirusTotalAction = ks::online_scan::addVirusTotalSandboxMenu(
                &contextMenu,
                this,
                [this, kIndex, kParsePidFromConnectionRow]() -> ks::online_scan::SandboxUploadTarget
                {
                    // Input: Current row of the UDP endpoint table.
                    // Processing: Parse PID and query the initiating process EXE.
                    // Returns: Upload path and source description.
                    ks::online_scan::SandboxUploadTarget uploadTarget;
                    std::uint32_t targetPid = 0;
                    if (!kParsePidFromConnectionRow(
                        udpEndpointTable_,
                        kIndex.row(),
                        toUdpEndpointColumn(UdpEndpointTableColumn::kPid),
                        targetPid,
                        QStringLiteral("udp_table_upload")))
                    {
                        uploadTarget.errorText = QStringLiteral("当前 UDP 行没有可解析 PID。");
                        return uploadTarget;
                    }
                    uploadTarget.filePath = QString::fromStdString(ks::process::queryProcessPathByPid(targetPid));
                    uploadTarget.sourceText = QStringLiteral("网络 UDP 端点 PID=%1").arg(targetPid);
                    return uploadTarget;
                });
            QAction* selectedAction = contextMenu.exec(udpEndpointTable_->viewport()->mapToGlobal(position));
            if (selectedAction == copyRowAction)
            {
                udpEndpointTable_->selectRow(kIndex.row());
                copySelectedConnectionRowToClipboard(udpEndpointTable_);
            }
            else if (selectedAction == trackProcessAction)
            {
                udpEndpointTable_->selectRow(kIndex.row());

                std::uint32_t targetPid = 0;
                if (!kParsePidFromConnectionRow(
                    udpEndpointTable_,
                    kIndex.row(),
                    toUdpEndpointColumn(UdpEndpointTableColumn::kPid),
                    targetPid,
                    QStringLiteral("udp_table")))
                {
                    return;
                }

                addOrTrackProcessPid(targetPid);

                KLogEvent trackEvent;
                info << trackEvent
                    << "[NetworkDock] UDP 端点右键触发进程跟踪, pid=" << targetPid
                    << eol;
            }
            else if (selectedAction == gotoProcessDetailAction)
            {
                udpEndpointTable_->selectRow(kIndex.row());

                std::uint32_t targetPid = 0;
                if (!kParsePidFromConnectionRow(
                    udpEndpointTable_,
                    kIndex.row(),
                    toUdpEndpointColumn(UdpEndpointTableColumn::kPid),
                    targetPid,
                    QStringLiteral("udp_table")))
                {
                    return;
                }
                kOpenProcessDetailByPid(targetPid, QStringLiteral("udp_table"));
            }
            else if (selectedAction == uploadVirusTotalAction)
            {
                return;
            }
            });
    }

    // Note: Request construction controls the connection: executes the request, resets the form, and switches modes to automatically adjust default parameters.
    connect(manualExecuteButton_, &QPushButton::clicked, this, [this]()
        {
            executeManualRequest();
        });
    connect(manualResetButton_, &QPushButton::clicked, this, [this]()
        {
            KLogEvent resetClickEvent;
            info << resetClickEvent << "[NetworkDock] 用户点击请求构造重置按钮。" << eol;
            resetManualRequestForm();
        });
    connect(manualApiCombo_, static_cast<void(QComboBox::*)(int)>(&QComboBox::currentIndexChanged), this, [this](const int /*index*/)
        {
            if (manualApiCombo_ == nullptr)
            {
                return;
            }

            const ks::network::ManualNetworkApiKind kApiKind =
                static_cast<ks::network::ManualNetworkApiKind>(manualApiCombo_->currentData().toInt());

            // On mode switch, update only the recommended default parameters without forcibly overriding the user's explicit 'manual override' selection.
            if (manualOverrideSocketParameterCheck_ != nullptr &&
                manualOverrideSocketParameterCheck_->isChecked())
            {
                KLogEvent switchApiEvent;
                dbg << switchApiEvent
                    << "[NetworkDock] 请求构造 API 模式切换（保留手工参数）, api="
                    << ks::network::manualNetworkApiKindToString(kApiKind)
                    << eol;
                return;
            }

            if (manualSocketTypeEdit_ == nullptr || manualProtocolEdit_ == nullptr)
            {
                return;
            }

            if (kApiKind == ks::network::ManualNetworkApiKind::kWinSockTcp)
            {
                manualSocketTypeEdit_->setText(QStringLiteral("1")); // SOCK_STREAM
                manualProtocolEdit_->setText(QStringLiteral("6"));   // IPPROTO_TCP
                if (manualConnectBeforeSendCheck_ != nullptr)
                {
                    manualConnectBeforeSendCheck_->setChecked(true);
                }
            }
            else
            {
                manualSocketTypeEdit_->setText(QStringLiteral("2")); // SOCK_DGRAM
                manualProtocolEdit_->setText(QStringLiteral("17"));  // IPPROTO_UDP
            }

            const bool kOverrideSocketParameters = manualOverrideSocketParameterCheck_ != nullptr
                && manualOverrideSocketParameterCheck_->isChecked();
            KLogEvent switchApiEvent;
            dbg << switchApiEvent
                << "[NetworkDock] 请求构造 API 模式切换, api="
                << ks::network::manualNetworkApiKindToString(kApiKind)
                << ", overrideSocket="
                << (kOverrideSocketParameters ? "true" : "false")
                << eol;
        });

    // Multi-threaded download page connections: start download, select directory, and URL Enter key trigger.
    connect(multiDownloadStartButton_, &QPushButton::clicked, this, [this]()
        {
            startMultiThreadDownloadTask();
        });
    connect(multiDownloadBrowseDirButton_, &QPushButton::clicked, this, [this]()
        {
            browseMultiThreadDownloadDirectory();
        });
    connect(multiDownloadUrlEdit_, &QLineEdit::returnPressed, this, [this]()
        {
            startMultiThreadDownloadTask();
        });

    // Connect download capture settings: write to JSON after toggle or suffix change.
    connect(multiDownloadAutoCaptureClipboardCheck_, &QCheckBox::toggled, this, [this](const bool checked)
        {
            multiDownloadAutoCaptureClipboardEnabled_ = checked;
            saveMultiThreadDownloadCaptureSettings();
        });
    connect(multiDownloadCaptureSuffixEdit_, &QLineEdit::editingFinished, this, [this]()
        {
            saveMultiThreadDownloadCaptureSettings();
        });
    connect(multiDownloadSaveCaptureSettingsButton_, &QPushButton::clicked, this, [this]()
        {
            saveMultiThreadDownloadCaptureSettings();
        });

    // Clipboard listener connection:
    // - Handle only main clipboard text changes.
    // When the auto-capture switch is off, the detection function returns quickly.
    QClipboard* clipboardObject = QGuiApplication::clipboard(); // clipboardObject: System primary clipboard object.
    if (clipboardObject != nullptr)
    {
        connect(clipboardObject, &QClipboard::changed, this, [this](const QClipboard::Mode mode)
            {
                if (mode != QClipboard::Clipboard)
                {
                    return;
                }
                onMultiThreadDownloadClipboardChanged();
            });
    }

    // Multi-threaded download task selection change: switch the right-side chunk details and bind the total progress bar to the task.
    connect(multiDownloadTaskTable_, &QTableWidget::itemSelectionChanged, this, [this]()
        {
            if (multiDownloadTaskTable_ == nullptr)
            {
                return;
            }

            const QList<QTableWidgetItem*> kSelectedItemList = multiDownloadTaskTable_->selectedItems();
            if (kSelectedItemList.isEmpty())
            {
                multiDownloadSelectedTaskId_ = 0;
                refreshMultiThreadDownloadUi();
                return;
            }

            const int kSelectedRow = kSelectedItemList.first()->row();
            QTableWidgetItem* idItem = multiDownloadTaskTable_->item(kSelectedRow, 0);
            if (idItem == nullptr)
            {
                multiDownloadSelectedTaskId_ = 0;
                refreshMultiThreadDownloadUi();
                return;
            }

            bool parseOk = false;
            const int kSelectedTaskId = idItem->text().toInt(&parseOk, 10);
            multiDownloadSelectedTaskId_ = parseOk ? kSelectedTaskId : 0;
            refreshMultiThreadDownloadUi();
        });

    // Double-click packet row: Open independent detail window (non-blocking).
    connect(packetTable_, &QTableWidget::cellDoubleClicked, this,
        [this](const int row, const int /*column*/)
        {
            openPacketDetailWindowFromTableRow(packetTable_, row);
        });

    // Right-click menu: View details / Pre-fill block rule / Copy row / Batch copy ASCII/HEX / Replay to request construction / Trace this process / Navigate to process details.
    connect(packetTable_, &QWidget::customContextMenuRequested, this,
        [this](const QPoint& position)
        {
            if (packetTable_ == nullptr)
            {
                return;
            }

            const QModelIndex kIndex = packetTable_->indexAt(position);
            const bool kHasSelection =
                (packetTable_->selectionModel() != nullptr && packetTable_->selectionModel()->hasSelection());
            if (!kIndex.isValid() && !kHasSelection)
            {
                return;
            }
            if (kIndex.isValid() && !kHasSelection)
            {
                // Single-row right-click anchor:
                // - Input: Current mouse row index for the packet.
                // - Processing: When no multi-selection, set the right-clicked row as current; copy, details, and trace all use the same anchor.
                // - Return: None. Does not disrupt user selection when multiple items are already selected.
                packetTable_->setCurrentCell(kIndex.row(), kIndex.column());
                packetTable_->selectRow(kIndex.row());
            }

            // collectTargetRows:
            // - Collects the set of row indices to process for the current right-click action.
            // - If multiple selection exists, prioritize it; otherwise, fall back to the current right-clicked row.
            const auto kCollectTargetRows = [this, kIndex]() -> std::vector<int>
                {
                    std::vector<int> rowList;
                    if (packetTable_ != nullptr && packetTable_->selectionModel() != nullptr)
                    {
                        const QModelIndexList kSelectedRowIndexList =
                            packetTable_->selectionModel()->selectedRows(toPacketColumn(PacketTableColumn::kTime));
                        rowList.reserve(static_cast<std::size_t>(kSelectedRowIndexList.size()));
                        for (const QModelIndex& selectedRowIndex : kSelectedRowIndexList)
                        {
                            rowList.push_back(selectedRowIndex.row());
                        }
                    }
                    if (rowList.empty() && kIndex.isValid())
                    {
                        rowList.push_back(kIndex.row());
                    }

                    std::sort(rowList.begin(), rowList.end());
                    rowList.erase(std::unique(rowList.begin(), rowList.end()), rowList.end());
                    return rowList;
                };

            // collectSequenceListByRows:
            // - Extract packet sequenceId by row number (stored in the "Time Column UserRole");
            // - Subsequent ASCII/HEX copying and opening details rely on this sequence number to look up cached entities.
            const auto kCollectSequenceListByRows = [this](const std::vector<int>& rowList) -> std::vector<std::uint64_t>
                {
                    std::vector<std::uint64_t> sequenceList;
                    sequenceList.reserve(rowList.size());
                    for (const int kRow : rowList)
                    {
                        if (packetTable_ == nullptr || kRow < 0 || kRow >= packetTable_->rowCount())
                        {
                            continue;
                        }

                        QTableWidgetItem* timeItem = packetTable_->item(kRow, toPacketColumn(PacketTableColumn::kTime));
                        if (timeItem == nullptr)
                        {
                            continue;
                        }

                        const QVariant kSequenceVariant = timeItem->data(Qt::UserRole);
                        if (!kSequenceVariant.isValid())
                        {
                            continue;
                        }
                        sequenceList.push_back(static_cast<std::uint64_t>(kSequenceVariant.toULongLong()));
                    }
                    std::sort(sequenceList.begin(), sequenceList.end());
                    sequenceList.erase(std::unique(sequenceList.begin(), sequenceList.end()), sequenceList.end());
                    return sequenceList;
                };

            QMenu contextMenu(this);
            contextMenu.setStyleSheet(ksword_theme::contextMenuStyle());
            QAction* detailAction = contextMenu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("查看报文详情"));
            QAction* addBlockRuleAction = contextMenu.addAction(
                QIcon(QStringLiteral(":/Icon/process_terminate.svg")),
                QStringLiteral("预填阻断规则"));
            addBlockRuleAction->setEnabled(firewallPage_ != nullptr);
            QAction* copyRowAction = contextMenu.addAction(QIcon(":/Icon/process_copy_row.svg"), QStringLiteral("复制行"));
            QAction* copyAsciiAction = contextMenu.addAction(QIcon(":/Icon/process_copy_row.svg"), QStringLiteral("复制选中报文ASCII"));
            // Copy payload ASCII only action: Do not concatenate packet header metadata; output only the ASCII text of the payload.
            QAction* copyPayloadAsciiOnlyAction = contextMenu.addAction(
                QIcon(":/Icon/process_copy_row.svg"),
                QStringLiteral("复制选中payload ASCII（仅正文）"));
            QAction* copyHexAction = contextMenu.addAction(QIcon(":/Icon/process_copy_row.svg"), QStringLiteral("复制选中报文16进制"));
            // Packet replay action: automatically populate the 'Request Construction' page with a single packet for the user to edit and execute.
            QAction* replayToManualRequestAction = contextMenu.addAction(
                QIcon(":/Icon/codeeditor_paste.svg"),
                QStringLiteral("重放到请求构造"));
            replayToManualRequestAction->setToolTip(QStringLiteral("将当前报文填充到请求构造页，便于快速重放。"));
            contextMenu.addSeparator();
            QAction* trackProcessAction = contextMenu.addAction(QIcon(":/Icon/log_track.svg"), QStringLiteral("跟踪此进程"));
            QAction* gotoProcessDetailAction = contextMenu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("转到进程详细信息"));
            QAction* uploadVirusTotalAction = ks::online_scan::addVirusTotalSandboxMenu(
                &contextMenu,
                this,
                [this, kIndex]() -> ks::online_scan::SandboxUploadTarget
                {
                    // Input: right-click anchored row or first row of current multi-selection in the packet table.
                    // Processing: Read PID column and query the initiating process EXE.
                    // Returns: Upload path and source description.
                    ks::online_scan::SandboxUploadTarget uploadTarget;
                    int rowIndex = -1;
                    if (packetTable_ != nullptr && packetTable_->selectionModel() != nullptr)
                    {
                        const QModelIndexList kSelectedRows =
                            packetTable_->selectionModel()->selectedRows(toPacketColumn(PacketTableColumn::kTime));
                        if (!kSelectedRows.isEmpty())
                        {
                            rowIndex = kSelectedRows.front().row();
                        }
                    }
                    if (rowIndex < 0 && kIndex.isValid())
                    {
                        rowIndex = kIndex.row();
                    }
                    if (rowIndex < 0)
                    {
                        uploadTarget.errorText = QStringLiteral("当前报文选择为空，无法解析 PID。");
                        return uploadTarget;
                    }
                    const QTableWidgetItem* pidItem =
                        (packetTable_ != nullptr && rowIndex >= 0)
                        ? packetTable_->item(rowIndex, toPacketColumn(PacketTableColumn::kPid))
                        : nullptr;
                    std::uint32_t targetPid = 0;
                    if (pidItem == nullptr || !ks::online_scan::tryParsePidFromText(pidItem->text(), &targetPid))
                    {
                        uploadTarget.errorText = QStringLiteral("当前报文行没有可解析 PID。");
                        return uploadTarget;
                    }
                    uploadTarget.filePath = QString::fromStdString(ks::process::queryProcessPathByPid(targetPid));
                    uploadTarget.sourceText = QStringLiteral("网络报文 PID=%1").arg(targetPid);
                    return uploadTarget;
                });

            QAction* selectedAction = contextMenu.exec(packetTable_->viewport()->mapToGlobal(position));
            if (selectedAction == nullptr)
            {
                return;
            }

            const std::vector<int> kTargetRows = kCollectTargetRows();
            const int kAnchorRow = kIndex.isValid() ? kIndex.row() : (kTargetRows.empty() ? -1 : kTargetRows.front());
            if (selectedAction == detailAction)
            {
                if (kAnchorRow >= 0)
                {
                    openPacketDetailWindowFromTableRow(packetTable_, kAnchorRow);
                }
            }
            else if (selectedAction == addBlockRuleAction)
            {
                const std::vector<std::uint64_t> kSequenceList = kCollectSequenceListByRows(
                    kAnchorRow >= 0 ? std::vector<int>{ kAnchorRow } : std::vector<int>{});
                if (kSequenceList.empty() || firewallPage_ == nullptr)
                {
                    return;
                }

                const auto kPacketIt = packetBySequence_.find(kSequenceList.front());
                if (kPacketIt == packetBySequence_.end())
                {
                    return;
                }

                const ks::network::PacketRecord& packetRecord = kPacketIt->second;
                firewallPage_->addBlockRuleFromEvidence(
                    QString::fromUtf8(packetRecord.remoteAddress.c_str()),
                    QString::number(packetRecord.remotePort),
                    toQString(ks::network::packetProtocolToString(packetRecord.protocol)),
                    toQString(ks::network::packetDirectionToString(packetRecord.direction)),
                    QStringLiteral("流量报文"));
            }
            else if (selectedAction == copyRowAction)
            {
                if (kAnchorRow < 0)
                {
                    return;
                }

                QStringList rowTextList;
                rowTextList.reserve(packetTable_->columnCount());
                for (int columnIndex = 0; columnIndex < packetTable_->columnCount(); ++columnIndex)
                {
                    QTableWidgetItem* item = packetTable_->item(kAnchorRow, columnIndex);
                    rowTextList.push_back(item == nullptr ? QString() : item->text());
                }
                if (QGuiApplication::clipboard() != nullptr)
                {
                    QGuiApplication::clipboard()->setText(rowTextList.join('\t'));
                }

                KLogEvent copyPacketRowEvent;
                dbg << copyPacketRowEvent
                    << "[NetworkDock] 已复制报文行, row=" << kAnchorRow
                    << ", columnCount=" << packetTable_->columnCount()
                    << eol;
            }

            else if (
                selectedAction == copyAsciiAction ||
                selectedAction == copyPayloadAsciiOnlyAction ||
                selectedAction == copyHexAction)
            {
                const std::vector<std::uint64_t> kSequenceList = kCollectSequenceListByRows(kTargetRows);
                if (kSequenceList.empty())
                {
                    return;
                }

                // copyAsciiWithHeaderMode: Whether to copy ASCII mode with message header metadata.
                const bool kCopyAsciiWithHeaderMode = (selectedAction == copyAsciiAction);
                // copyPayloadAsciiOnlyMode: Indicates whether to copy the payload body in ASCII-only mode.
                const bool kCopyPayloadAsciiOnlyMode = (selectedAction == copyPayloadAsciiOnlyAction);
                // copyHexMode usage: whether to copy in hexadecimal mode.
                const bool kCopyHexMode = (selectedAction == copyHexAction);

                // blockTextList purpose: Concatenate copy results as 'one text block per packet'.
                QStringList blockTextList;
                blockTextList.reserve(static_cast<int>(kSequenceList.size()));
                for (const std::uint64_t kSequenceId : kSequenceList)
                {
                    const auto kIterator = packetBySequence_.find(kSequenceId);
                    if (kIterator == packetBySequence_.end())
                    {
                        continue;
                    }

                    const ks::network::PacketRecord& packetRecord = kIterator->second;
                    if (kCopyHexMode)
                    {
                        // Hex mode: Always retain packet header metadata to facilitate context tracing.
                        blockTextList.push_back(QStringLiteral("%1\n%2")
                            .arg(network_dock_detail::buildPacketCopyHeaderLine(packetRecord))
                            .arg(network_dock_detail::buildPacketHexAsciiDumpText(packetRecord)));
                        continue;
                    }

                    const QString kPayloadAsciiText = network_dock_detail::buildPayloadAsciiFullText(packetRecord);
                    if (kCopyPayloadAsciiOnlyMode)
                    {
                        // In plain text mode only: do not concatenate any header fields; retain only the payload ASCII.
                        blockTextList.push_back(kPayloadAsciiText);
                        continue;
                    }

                    if (kCopyAsciiWithHeaderMode)
                    {
                        // ASCII standard mode: preserve packet header metadata + payload ASCII text.
                        blockTextList.push_back(QStringLiteral("%1\n%2")
                            .arg(network_dock_detail::buildPacketCopyHeaderLine(packetRecord))
                            .arg(kPayloadAsciiText));
                    }
                }

                if (blockTextList.isEmpty())
                {
                    return;
                }

                // blockJoinSeparator: Use a consistent separator between packet blocks so copied text does not run together and become hard to read.
                const QString kBlockJoinSeparator = kCopyPayloadAsciiOnlyMode
                    ? QStringLiteral("\n\n")
                    : QStringLiteral("\n\n============================================================\n\n");
                const QString kFinalText = blockTextList.join(kBlockJoinSeparator);
                if (QGuiApplication::clipboard() != nullptr)
                {
                    QGuiApplication::clipboard()->setText(kFinalText);
                }

                // copyModeText usage: Mode identifier for log output to facilitate subsequent issue localization.
                const std::string kCopyModeText = kCopyHexMode
                    ? "hex"
                    : (kCopyPayloadAsciiOnlyMode ? "ascii_payload_only" : "ascii");

                KLogEvent copyPacketBatchEvent;
                info << copyPacketBatchEvent
                    << "[NetworkDock] 批量复制报文内容, mode=" << kCopyModeText
                    << ", packetCount=" << kSequenceList.size()
                    << ", outputChars=" << kFinalText.size()
                    << eol;
            }
            else if (selectedAction == replayToManualRequestAction)
            {
                if (kAnchorRow >= 0)
                {
                    replayPacketToManualRequestByTableRow(kAnchorRow);
                }
            }
            else if (selectedAction == trackProcessAction)
            {
                if (kAnchorRow >= 0)
                {
                    trackProcessByTableRow(kAnchorRow);
                }
            }
            else if (selectedAction == gotoProcessDetailAction)
            {
                if (kAnchorRow >= 0)
                {
                    gotoProcessDetailByTableRow(kAnchorRow);
                }
            }
            else if (selectedAction == uploadVirusTotalAction)
            {
                return;
            }
        });

    // ARP cache page control connection.
    connect(refreshArpButton_, &QPushButton::clicked, this, [this]()
        {
            refreshArpCacheTable();
        });
    connect(addArpButton_, &QPushButton::clicked, this, [this]()
        {
            addArpCacheEntry();
        });
    connect(removeArpButton_, &QPushButton::clicked, this, [this]()
        {
            removeSelectedArpCacheEntry();
        });
    connect(flushArpButton_, &QPushButton::clicked, this, [this]()
        {
            flushArpCache();
        });

    // DNS cache page control connection.
    connect(refreshDnsButton_, &QPushButton::clicked, this, [this]()
        {
            refreshDnsCacheTable();
        });
    connect(removeDnsButton_, &QPushButton::clicked, this, [this]()
        {
            removeDnsCacheEntry();
        });
    connect(flushDnsButton_, &QPushButton::clicked, this, [this]()
        {
            flushDnsCache();
        });
    connect(dnsTable_, &QTableWidget::itemSelectionChanged, this, [this]()
        {
            if (dnsEntryEdit_ == nullptr || dnsTable_ == nullptr)
            {
                return;
            }

            const QList<QTableWidgetItem*> kSelectedItemList = dnsTable_->selectedItems();
            if (kSelectedItemList.isEmpty())
            {
                return;
            }

            const int kRow = kSelectedItemList.first()->row();
            QTableWidgetItem* hostItem = dnsTable_->item(kRow, 0);
            if (hostItem != nullptr)
            {
                dnsEntryEdit_->setText(hostItem->text());
            }
        });

    // Connection for the host liveness scan page.
    connect(startAliveScanButton_, &QPushButton::clicked, this, [this]()
        {
            startAliveHostScan();
        });
    connect(stopAliveScanButton_, &QPushButton::clicked, this, [this]()
        {
            stopAliveHostScan();
        });

    // initialize button availability state.
    updateMonitorButtonState();

    // initialize the data for the first screen of the new page.
    refreshMultiThreadDownloadUi();
    refreshArpCacheTable();
    refreshDnsCacheTable();
}

void NetworkDock::startTrafficMonitor()
{
    if (trafficService_ == nullptr)
    {
        return;
    }

    // Immediate restart is not allowed while stopping to prevent service thread state jitter between 'stop' and 'start'.
    if (monitorStopInProgress_.load())
    {
        if (monitorStatusLabel_ != nullptr)
        {
            monitorStatusLabel_->setText(QStringLiteral("状态：停止中，请稍候..."));
        }
        return;
    }

    // If the previous stop thread object still lingers (typically already terminated), perform cleanup here to avoid handle leaks.
    if (monitorStopThread_ != nullptr && monitorStopThread_->joinable())
    {
        monitorStopThread_->join();
    }
    monitorStopThread_.reset();

    // Clear the 'background queue dropped packet count' before each start to facilitate observing the current run status.
    {
        std::lock_guard<std::mutex> guard(pendingPacketMutex_);
        droppedPacketCount_ = 0;
    }

    // First probe the versioned R0 WFP IP packet IOCTL; immediately fall back to R3 if the old driver is unavailable or the per-packet data plane is not usable.
    // Background probe failures automatically trigger startR3TrafficMonitor; no user interaction is required.
    const std::uint64_t kGeneration = monitorGeneration_.fetch_add(1) + 1ULL;
    monitorSource_ = TrafficMonitorSource::kStarting;
    monitorRunning_ = true;

    // Enabling the R0 data plane involves a synchronous IOCTL (CreateFileW + DeviceIoControl, no OVERLAPPED). The kernel side must
    // register a WFP callout/filter and initialize the ring buffer; thus, the entire control flow is offloaded to a background thread.
    // The UI thread first commits the button state and 'Scanning...' message; upon result return, it decides whether to proceed to R0 or fall back to R3.
    if (monitorStatusLabel_ != nullptr)
    {
        monitorStatusLabel_->setText(QStringLiteral("状态：正在探测 R0 WFP IPv4/IPv6 逐包数据源..."));
    }
    updateMonitorButtonState();

    const QPointer<NetworkDock> kGuardedSelf(this);
    std::thread([kGuardedSelf, kGeneration]()
        {
            const ksword::ark::DriverClient kDriverClient;
            const ksword::ark::NetworkTrafficCaptureControlResult kCaptureControl =
                kDriverClient.controlNetworkTrafficCapture(true);
            const bool kR0CaptureEnabled =
                kCaptureControl.io.ok &&
                !kCaptureControl.unsupported &&
                kCaptureControl.response.status == KSWORD_ARK_NETWORK_STATUS_APPLIED &&
                kCaptureControl.response.enabled == 1UL;
            if (!kR0CaptureEnabled)
            {
                // Perform an idempotent disable on control response corruption or business rejection after enabling to avoid unknown partial-success states.
                // This disable and enable operation completes serially within the same background thread, avoiding any UI thread occupation.
                (void)kDriverClient.controlNetworkTrafficCapture(false);
            }

            const QString kCaptureMessageText = QString::fromStdString(kCaptureControl.io.message);
            const std::string kCaptureMessageLogText = kCaptureControl.io.message;
            QCoreApplication* const kAppInstance = QCoreApplication::instance();
            if (kAppInstance == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                kAppInstance,
                [kGuardedSelf, kGeneration, kR0CaptureEnabled, kCaptureMessageText, kCaptureMessageLogText]()
                {
                    if (kGuardedSelf == nullptr)
                    {
                        return;
                    }

                    // The user may have clicked Stop or Restart before the probe returned; in this case, the results of this round are discarded entirely.
                    // If the data plane was indeed opened in this round, perform an additional asynchronous idempotent shutdown.
                    if (kGuardedSelf->monitorGeneration_.load() != kGeneration ||
                        kGuardedSelf->monitorSource_ != TrafficMonitorSource::kStarting)
                    {
                        if (kR0CaptureEnabled)
                        {
                            disableNetworkTrafficCaptureAsync();
                        }
                        return;
                    }

                    if (!kR0CaptureEnabled)
                    {
                        kGuardedSelf->startR3TrafficMonitor(kCaptureMessageText);
                        KLogEvent fallbackEvent;
                        warn << fallbackEvent
                             << "[NetworkDock] R0 逐包数据面启用失败，已回退 R3: "
                             << kCaptureMessageLogText << eol;
                        return;
                    }

                    // Newly captured sessions clear the R0 ring and restart counting from sequence=1; the R3 cursor must also be synchronized to zero.
                    kGuardedSelf->r0LastEventSequence_ = 0ULL;
                    kGuardedSelf->r0LastDroppedEventCount_ = 0ULL;
                    kGuardedSelf->refreshR0TrafficSnapshotAsync(kGeneration, true);
                    kGuardedSelf->updateMonitorButtonState();
                },
                Qt::QueuedConnection);
        }).detach();

    KLogEvent startEvent;
    info << startEvent << "[NetworkDock] 用户触发网络监控启动。" << eol;
}

void NetworkDock::stopTrafficMonitor()
{
    if (trafficService_ == nullptr)
    {
        return;
    }

    // Return immediately if the thread is already stopping to prevent multiple concurrent stop threads caused by repeated clicks.
    if (monitorStopInProgress_.exchange(true))
    {
        return;
    }

    const TrafficMonitorSource kSourceBeforeStop = monitorSource_;
    monitorGeneration_.fetch_add(1);
    monitorSource_ = TrafficMonitorSource::kStopped;
    if (r0TrafficRefreshTimer_ != nullptr)
    {
        r0TrafficRefreshTimer_->stop();
    }

    // Disabling the R0 data plane is also a synchronous IOCTL; executing it on a background thread allows the UI to optimistically advance to 'disable success'.
    // m_monitorStopInProgress remains set until the rollback completes, preventing users from restarting before the disable operation has fully taken
    // effect. This avoids race conditions between the 'enable' and 'disable' background control flows that could leave the data plane in an incorrect state.
    const bool kR0DisableDispatched =
        kSourceBeforeStop == TrafficMonitorSource::kR0 ||
        kSourceBeforeStop == TrafficMonitorSource::kStarting;
    if (kR0DisableDispatched)
    {
        const QPointer<NetworkDock> kGuardedSelf(this);
        const std::uint64_t kStopGeneration = monitorGeneration_.load();
        std::thread([kGuardedSelf, kStopGeneration]()
            {
                const ksword::ark::DriverClient kDriverClient;
                const ksword::ark::NetworkTrafficCaptureControlResult kCaptureControl =
                    kDriverClient.controlNetworkTrafficCapture(false);
                const bool kR0StopConfirmed =
                    kCaptureControl.io.ok &&
                    !kCaptureControl.unsupported &&
                    kCaptureControl.response.status == KSWORD_ARK_NETWORK_STATUS_DISABLED &&
                    kCaptureControl.response.enabled == 0UL;
                if (!kR0StopConfirmed)
                {
                    KLogEvent stopFailureEvent;
                    warn << stopFailureEvent
                         << "[NetworkDock] R0 逐包数据面停用失败: "
                         << kCaptureControl.io.message << eol;
                }

                const QString kR0StopFailure = kR0StopConfirmed
                    ? QString()
                    : QString::fromStdString(kCaptureControl.io.message);
                QCoreApplication* const kAppInstance = QCoreApplication::instance();
                if (kAppInstance == nullptr)
                {
                    return;
                }
                QMetaObject::invokeMethod(
                    kAppInstance,
                    [kGuardedSelf, kStopGeneration, kR0StopFailure]()
                    {
                        if (kGuardedSelf == nullptr)
                        {
                            return;
                        }

                        // Deactivation is complete; release the 'stopping' gate and restore the button to clickable state.
                        kGuardedSelf->monitorStopInProgress_.store(false);
                        kGuardedSelf->updateMonitorButtonState();
                        if (kR0StopFailure.isEmpty() ||
                            kGuardedSelf->monitorStatusLabel_ == nullptr)
                        {
                            return;
                        }

                        // The failure notification for stopping is only valid for the UI that is still on the current stop result;
                        // it does not overwrite the new running status text if the user has already restarted packet capture.
                        if (kGuardedSelf->monitorGeneration_.load() != kStopGeneration ||
                            kGuardedSelf->monitorSource_ != TrafficMonitorSource::kStopped)
                        {
                            return;
                        }
                        kGuardedSelf->monitorStatusLabel_->setText(
                            QStringLiteral("状态：界面已停止，但 R0 数据面停用失败：%1")
                                .arg(kR0StopFailure));
                    },
                    Qt::QueuedConnection);
            }).detach();
    }

    // Immediately switch UI to 'Stopping' to provide timely feedback and prevent user confusion about unresponsive buttons.
    monitorRunning_ = false;
    if (monitorStatusLabel_ != nullptr)
    {
        monitorStatusLabel_->setText(QStringLiteral("状态：停止中..."));
    }
    updateMonitorButtonState();

    // R0/Probe mode has no R3 packet capture thread to join, so stopping can be completed immediately on the UI thread.
    if (kSourceBeforeStop != TrafficMonitorSource::kR3 || !trafficService_->isRunning())
    {
        // When asynchronous stop dispatch is in progress, the stop gate is released by the stop completion logic; do not release it prematurely here.
        if (!kR0DisableDispatched)
        {
            monitorStopInProgress_.store(false);
        }
        if (packetTimelineSessionActive_)
        {
            endPacketTimelineMonitorSession();
        }
        if (monitorStatusLabel_ != nullptr)
        {
            monitorStatusLabel_->setText(QStringLiteral("状态：已停止（来源：无）"));
        }
        updateMonitorButtonState();
        return;
    }

    // First, reclaim the previous stop thread object to ensure only one stop worker is retained in this round.
    if (monitorStopThread_ != nullptr && monitorStopThread_->joinable())
    {
        monitorStopThread_->join();
    }
    monitorStopThread_.reset();

    // Move stopCapture to a background thread to prevent main thread join from causing UI lag.
    QPointer<NetworkDock> guardThis(this);
    ks::network::TrafficMonitorService* trafficServicePtr = trafficService_.get();
    monitorStopThread_ = std::make_unique<std::thread>([guardThis, trafficServicePtr]() {
        if (trafficServicePtr != nullptr)
        {
            trafficServicePtr->stopCapture();
        }

        QMetaObject::invokeMethod(qApp, [guardThis]() {
            if (guardThis == nullptr)
            {
                return;
            }

            // Join the thread after the stop signal to ensure no long blocking occurs on the UI thread.
            if (guardThis->monitorStopThread_ != nullptr && guardThis->monitorStopThread_->joinable())
            {
                guardThis->monitorStopThread_->join();
            }
            guardThis->monitorStopThread_.reset();
            guardThis->monitorStopInProgress_.store(false);
            guardThis->monitorRunning_ = false;
            guardThis->monitorSource_ = TrafficMonitorSource::kStopped;
            guardThis->endPacketTimelineMonitorSession();
            if (guardThis->monitorStatusLabel_ != nullptr)
            {
                guardThis->monitorStatusLabel_->setText(QStringLiteral("状态：已停止"));
            }
            guardThis->updateMonitorButtonState();

            KLogEvent stopFinishedEvent;
            info << stopFinishedEvent << "[NetworkDock] 后台停止流程完成，抓包线程已退出。" << eol;
        }, Qt::QueuedConnection);
    });

    KLogEvent stopEvent;
    info << stopEvent << "[NetworkDock] 用户触发网络监控停止（异步）。" << eol;
}

void NetworkDock::refreshR0TrafficSnapshotAsync(
    const std::uint64_t generation,
    const bool initialProbe)
{
    if (r0TrafficRefreshPending_.exchange(true))
    {
        // The user may stop and immediately restart before the previous generation R0 query returns.
        // Initial probes cannot be silently dropped; otherwise, the new generation will permanently remain in the Starting state.
        if (initialProbe)
        {
            QTimer::singleShot(120, this, [this, generation]()
            {
                if (monitorGeneration_.load() == generation
                    && monitorSource_ == TrafficMonitorSource::kStarting)
                {
                    refreshR0TrafficSnapshotAsync(generation, true);
                }
            });
        }
        return;
    }

    const std::uint64_t kAfterSequence = r0LastEventSequence_;
    QPointer<NetworkDock> safeThis(this);
    std::thread([safeThis, generation, initialProbe, kAfterSequence]()
    {
        const ksword::ark::DriverClient kDriverClient;
        const ksword::ark::NetworkTrafficPacketResult kPacketResult =
            kDriverClient.queryNetworkTrafficPackets(
                kAfterSequence,
                KSWORD_ARK_NETWORK_TRAFFIC_MAX_REQUESTED_ROWS);
        const bool kR0Usable =
            kPacketResult.io.ok &&
            !kPacketResult.unsupported &&
            kPacketResult.status == KSWORD_ARK_NETWORK_STATUS_APPLIED;

        std::vector<ks::network::PacketRecord> packetRecords;
        if (kR0Usable)
        {
            ks::network::detail::ConnectionPidResolver pidResolver;
            ks::network::detail::ProcessNameResolver processNameResolver;
            packetRecords.reserve(kPacketResult.entries.size());
            for (const KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW& packetRow : kPacketResult.entries)
            {
                packetRecords.push_back(buildR0WfpPacketRecord(
                    packetRow,
                    pidResolver,
                    processNameResolver));
            }
        }

        const QString kDiagnosticText = kR0Usable
            ? QStringLiteral("新增=%1/%2，cursor=%3，ring覆盖=%4，cursor缺口=%5")
                .arg(static_cast<qulonglong>(packetRecords.size()))
                .arg(kPacketResult.returnedCount)
                .arg(static_cast<qulonglong>(kPacketResult.nextSequence))
                .arg(static_cast<qulonglong>(kPacketResult.droppedPacketCount))
                .arg(static_cast<qulonglong>(kPacketResult.cursorGapCount))
            : QStringLiteral("packet=%1；status=%2；lastStatus=0x%3")
                .arg(QString::fromUtf8(kPacketResult.io.message.c_str()))
                .arg(kPacketResult.status)
                .arg(static_cast<quint32>(kPacketResult.lastStatus), 8, 16, QChar('0'));

        if (safeThis.isNull())
        {
            (void)kDriverClient.controlNetworkTrafficCapture(false);
            return;
        }
        QMetaObject::invokeMethod(
            safeThis.data(),
            [safeThis,
                generation,
                initialProbe,
                kR0Usable,
                kDiagnosticText,
                nextSequence = kPacketResult.nextSequence,
                droppedPacketCount = kPacketResult.droppedPacketCount,
                packetRecords = std::move(packetRecords)]() mutable
            {
                if (safeThis.isNull())
                {
                    return;
                }
                safeThis->r0TrafficRefreshPending_.store(false);
                if (safeThis->monitorGeneration_.load() != generation
                    || safeThis->monitorSource_ == TrafficMonitorSource::kStopped)
                {
                    if (safeThis->monitorSource_ == TrafficMonitorSource::kStopped)
                    {
                        // Pure fallback disablement with no subsequent steps depending on its completion order. Execute directly in
                        // the background to avoid issuing a synchronous IOCTL again within the UI thread's back-captured lambda.
                        disableNetworkTrafficCaptureAsync();
                    }
                    return;
                }

                if (!kR0Usable)
                {
                    const ksword::ark::DriverClient kDriverClient;
                    const auto kCaptureControl =
                        kDriverClient.controlNetworkTrafficCapture(false);
                    if (!kCaptureControl.io.ok ||
                        kCaptureControl.response.status != KSWORD_ARK_NETWORK_STATUS_DISABLED)
                    {
                        KLogEvent disableEvent;
                        warn << disableEvent
                             << "[NetworkDock] R0 查询失败后的数据面停用失败: "
                             << kCaptureControl.io.message << eol;
                    }
                    safeThis->startR3TrafficMonitor(kDiagnosticText);
                    return;
                }

                if (initialProbe)
                {
                    safeThis->monitorSource_ = TrafficMonitorSource::kR0;
                    safeThis->monitorRunning_ = true;
                    if (!safeThis->packetTimelineSessionActive_)
                    {
                        safeThis->beginPacketTimelineMonitorSession();
                    }
                    if (safeThis->r0TrafficRefreshTimer_ != nullptr)
                    {
                        safeThis->r0TrafficRefreshTimer_->start();
                    }
                }

                safeThis->r0LastEventSequence_ = nextSequence;
                safeThis->r0LastDroppedEventCount_ = droppedPacketCount;
                for (ks::network::PacketRecord& packetRecord : packetRecords)
                {
                    packetRecord.sequenceId = safeThis->r0SyntheticSequence_++;
                    safeThis->onPacketCaptured(packetRecord);
                }

                if (safeThis->monitorStatusLabel_ != nullptr)
                {
                    safeThis->monitorStatusLabel_->setText(
                        QStringLiteral("状态：运行中；来源：R0 WFP IPv4/IPv6 逐包捕获（报文前缀最长 %1 字节；%2）")
                            .arg(KSWORD_ARK_NETWORK_TRAFFIC_MAX_CAPTURE_BYTES)
                            .arg(kDiagnosticText));
                }
                safeThis->updateMonitorButtonState();
            },
            Qt::QueuedConnection);
    }).detach();
}

void NetworkDock::startR3TrafficMonitor(const QString& fallbackReason)
{
    if (monitorSource_ == TrafficMonitorSource::kStopped || trafficService_ == nullptr)
    {
        return;
    }
    if (r0TrafficRefreshTimer_ != nullptr)
    {
        r0TrafficRefreshTimer_->stop();
    }
    monitorSource_ = TrafficMonitorSource::kR3;

    const bool kStartIssued = trafficService_->startCapture();
    monitorRunning_ = kStartIssued && trafficService_->isRunning();
    if (!monitorRunning_)
    {
        monitorSource_ = TrafficMonitorSource::kStopped;
        if (packetTimelineSessionActive_)
        {
            endPacketTimelineMonitorSession();
        }
        if (monitorStatusLabel_ != nullptr)
        {
            monitorStatusLabel_->setText(QStringLiteral("状态：R0 不可用，R3 回退启动失败"));
        }
    }
    else
    {
        if (!packetTimelineSessionActive_)
        {
            beginPacketTimelineMonitorSession();
        }
        if (monitorStatusLabel_ != nullptr)
        {
            monitorStatusLabel_->setText(
                QStringLiteral("状态：运行中；来源：R3 用户态抓包（R0 不可用：%1）")
                    .arg(fallbackReason));
        }
    }
    updateMonitorButtonState();
}

void NetworkDock::updateMonitorButtonState()
{
    const bool kStopping = monitorStopInProgress_.load();
    if (startMonitorButton_ != nullptr)
    {
        startMonitorButton_->setEnabled(!monitorRunning_ && !kStopping);
    }
    if (stopMonitorButton_ != nullptr)
    {
        stopMonitorButton_->setEnabled(monitorRunning_ && !kStopping);
    }
}
