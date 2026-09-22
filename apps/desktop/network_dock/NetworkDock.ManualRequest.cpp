#include "NetworkDock.InternalCommon.h"

using namespace network_dock_detail;
void NetworkDock::executeManualRequest()
{
    // Concurrency gate:
    // - Only 1 manual request is allowed to run in the background at any given time.
    // - Prevent multiple blocking requests from accumulating due to repeated clicks.
    static std::atomic_bool sManualRequestInFlight = false;
    if (sManualRequestInFlight.exchange(true))
    {
        appendManualRequestLogLine(QStringLiteral("已有请求正在执行，请稍候。"));

        KLogEvent duplicateRequestEvent;
        warn << duplicateRequestEvent << "[NetworkDock] 忽略重复执行请求：上一条请求尚未完成。" << eol;
        return;
    }

    // Protective check: if the request construction page controls are not yet initialized, return immediately.
    if (manualApiCombo_ == nullptr ||
        manualOverrideSocketParameterCheck_ == nullptr ||
        manualAddressFamilyEdit_ == nullptr ||
        manualSocketTypeEdit_ == nullptr ||
        manualProtocolEdit_ == nullptr ||
        manualSocketFlagsEdit_ == nullptr ||
        manualEnableBindCheck_ == nullptr ||
        manualLocalAddressEdit_ == nullptr ||
        manualLocalPortSpin_ == nullptr ||
        manualRemoteAddressEdit_ == nullptr ||
        manualRemotePortSpin_ == nullptr ||
        manualConnectBeforeSendCheck_ == nullptr ||
        manualReuseAddressCheck_ == nullptr ||
        manualNoDelayCheck_ == nullptr ||
        manualSendTimeoutSpin_ == nullptr ||
        manualRecvTimeoutSpin_ == nullptr ||
        manualPayloadFormatCombo_ == nullptr ||
        manualPayloadEditor_ == nullptr ||
        manualSendFlagsEdit_ == nullptr ||
        manualReceiveFlagsEdit_ == nullptr ||
        manualReceiveAfterSendCheck_ == nullptr ||
        manualReceiveMaxBytesSpin_ == nullptr ||
        manualShutdownSendCheck_ == nullptr)
    {
        sManualRequestInFlight.store(false);
        return;
    }

    // Unified input error handling:
    // - First, show a popup to the user.
    // - Then write to the log to facilitate locating the failed field later.
    const auto kReportInputError = [this](const QString& errorText)
        {
            QMessageBox::warning(this, QStringLiteral("请求构造"), errorText);

            KLogEvent inputErrorEvent;
            warn << inputErrorEvent
                << "[NetworkDock] 请求构造参数校验失败, detail="
                << errorText.toStdString()
                << eol;

            // Parameter errors belong to the fast-fail path and require releasing the execution gate.
            sManualRequestInFlight.store(false);
        };

    // 1) Assemble the request object.
    ks::network::ManualNetworkRequest request;
    request.apiKind = static_cast<ks::network::ManualNetworkApiKind>(manualApiCombo_->currentData().toInt());
    request.overrideSocketParameters = manualOverrideSocketParameterCheck_->isChecked();

    if (request.overrideSocketParameters)
    {
        std::uint32_t parsedValue = 0;
        if (!tryParseUnsignedIntegerText(manualAddressFamilyEdit_->text(), parsedValue))
        {
            kReportInputError(QStringLiteral("addressFamily 格式无效。"));
            return;
        }
        request.addressFamily = static_cast<int>(parsedValue);

        if (!tryParseUnsignedIntegerText(manualSocketTypeEdit_->text(), parsedValue))
        {
            kReportInputError(QStringLiteral("socketType 格式无效。"));
            return;
        }
        request.socketType = static_cast<int>(parsedValue);

        if (!tryParseUnsignedIntegerText(manualProtocolEdit_->text(), parsedValue))
        {
            kReportInputError(QStringLiteral("protocol 格式无效。"));
            return;
        }
        request.protocol = static_cast<int>(parsedValue);

        if (!tryParseUnsignedIntegerText(manualSocketFlagsEdit_->text(), parsedValue))
        {
            kReportInputError(QStringLiteral("socketFlags 格式无效。"));
            return;
        }
        request.socketFlags = static_cast<DWORD>(parsedValue);
    }

    request.enableLocalBind = manualEnableBindCheck_->isChecked();
    request.localAddress = manualLocalAddressEdit_->text().trimmed().toStdString();
    request.localPort = static_cast<std::uint16_t>(manualLocalPortSpin_->value());
    request.remoteAddress = manualRemoteAddressEdit_->text().trimmed().toStdString();
    request.remotePort = static_cast<std::uint16_t>(manualRemotePortSpin_->value());
    request.connectBeforeSend = manualConnectBeforeSendCheck_->isChecked();
    request.enableReuseAddress = manualReuseAddressCheck_->isChecked();
    request.enableNoDelay = manualNoDelayCheck_->isChecked();
    request.sendTimeoutMs = static_cast<std::uint32_t>(manualSendTimeoutSpin_->value());
    request.receiveTimeoutMs = static_cast<std::uint32_t>(manualRecvTimeoutSpin_->value());

    std::uint32_t parsedFlagValue = 0;
    if (!tryParseUnsignedIntegerText(manualSendFlagsEdit_->text(), parsedFlagValue))
    {
        kReportInputError(QStringLiteral("sendFlags 格式无效。"));
        return;
    }
    request.sendFlags = static_cast<int>(parsedFlagValue);

    if (!tryParseUnsignedIntegerText(manualReceiveFlagsEdit_->text(), parsedFlagValue))
    {
        kReportInputError(QStringLiteral("recvFlags 格式无效。"));
        return;
    }
    request.receiveFlags = static_cast<int>(parsedFlagValue);

    request.receiveAfterSend = manualReceiveAfterSendCheck_->isChecked();
    request.receiveMaxBytes = static_cast<std::size_t>(manualReceiveMaxBytesSpin_->value());
    request.shutdownSendAfterWrite = manualShutdownSendCheck_->isChecked();
    request.payloadFormat = static_cast<ks::network::ManualPayloadFormat>(manualPayloadFormatCombo_->currentData().toInt());
    request.payloadText = manualPayloadEditor_->toPlainText().toStdString();

    ks::network::ManualNetworkRequestValidation requestValidation;
    if (!ks::network::validateManualNetworkRequest(request, &requestValidation))
    {
        kReportInputError(QStringLiteral("请求参数无效：%1").arg(toQString(requestValidation.errorText)));
        return;
    }

    // 2) Output request start logs via dual channels (UI + framework logs).
    appendManualRequestLogLine(QStringLiteral("开始执行请求：api=%1, remote=%2:%3, payloadBytes=%4")
        .arg(toQString(ks::network::manualNetworkApiKindToString(request.apiKind)))
        .arg(toQString(request.remoteAddress))
        .arg(request.remotePort)
        .arg(static_cast<qulonglong>(requestValidation.payloadByteCount)));
    appendManualRequestLogLine(QStringLiteral("请求已投递到后台线程，UI 保持可响应。"));

    KLogEvent requestStartEvent;
    info << requestStartEvent
        << "[NetworkDock] 执行手动网络请求, api=" << ks::network::manualNetworkApiKindToString(request.apiKind)
        << ", remote=" << request.remoteAddress << ":" << request.remotePort
        << ", connectBeforeSend=" << (request.connectBeforeSend ? "true" : "false")
        << ", payloadFormat=" << ks::network::manualPayloadFormatToString(request.payloadFormat)
        << ", payloadBytes=" << requestValidation.payloadByteCount
        << eol;

    // UI feedback: Disable button during background execution to prevent triggering the same request repeatedly.
    if (manualExecuteButton_ != nullptr)
    {
        manualExecuteButton_->setEnabled(false);
        manualExecuteButton_->setToolTip(QStringLiteral("请求执行中，请稍候..."));
    }

    // 3) Execute network requests in a background thread:
    // - Completely avoid blocking the UI event loop with send/recv timeout waits.
    // - Return results to the UI thread via QueuedConnection after execution completes.
    QPointer<NetworkDock> dockGuard(this);
    try
    {
        std::thread([dockGuard, request]()
            {
                ks::network::ManualNetworkResult requestResult;
                const bool kExecuteOk = ks::network::executeManualNetworkRequest(request, &requestResult);

                NetworkDock* dockPointer = dockGuard.data();
                if (dockPointer == nullptr)
                {
                    sManualRequestInFlight.store(false);
                    return;
                }

                QMetaObject::invokeMethod(
                    dockPointer,
                    [dockGuard, kExecuteOk, requestResult = std::move(requestResult)]() mutable
                    {
                        NetworkDock* uiDock = dockGuard.data();
                        if (uiDock == nullptr)
                        {
                            sManualRequestInFlight.store(false);
                            return;
                        }

                        // 4) Output result summary (here, execution has returned to the UI thread).
                        uiDock->appendManualRequestLogLine(QStringLiteral("执行结果：ok=%1, sent=%2, recv=%3, detail=%4")
                            .arg((kExecuteOk && requestResult.succeeded) ? QStringLiteral("true") : QStringLiteral("false"))
                            .arg(static_cast<qulonglong>(requestResult.bytesSent))
                            .arg(static_cast<qulonglong>(requestResult.bytesReceived))
                            .arg(toQString(requestResult.detailText)));

                        if (!requestResult.responseBytes.empty())
                        {
                            uiDock->appendManualRequestLogLine(QStringLiteral("响应HEX预览：%1")
                                .arg(formatBytesToHexText(requestResult.responseBytes, 256)));
                        }

                        if (kExecuteOk && requestResult.succeeded)
                        {
                            KLogEvent requestSuccessEvent;
                            info << requestSuccessEvent
                                << "[NetworkDock] 手动网络请求成功, sent=" << requestResult.bytesSent
                                << ", recv=" << requestResult.bytesReceived
                                << ", detail=" << requestResult.detailText
                                << eol;
                        }
                        else
                        {
                            KLogEvent requestFailEvent;
                            warn << requestFailEvent
                                << "[NetworkDock] 手动网络请求失败, wsaError=" << requestResult.wsaErrorCode
                                << ", detail=" << requestResult.detailText
                                << eol;
                        }

                        if (uiDock->manualExecuteButton_ != nullptr)
                        {
                            uiDock->manualExecuteButton_->setEnabled(true);
                            uiDock->manualExecuteButton_->setToolTip(QStringLiteral("按上方参数立即执行一次网络请求。"));
                        }

                        sManualRequestInFlight.store(false);
                    },
                    Qt::QueuedConnection);
            }).detach();
    }
    catch (...)
    {
        // In extreme cases where thread creation fails, immediately restore the UI state and log the event.
        if (manualExecuteButton_ != nullptr)
        {
            manualExecuteButton_->setEnabled(true);
            manualExecuteButton_->setToolTip(QStringLiteral("按上方参数立即执行一次网络请求。"));
        }
        sManualRequestInFlight.store(false);

        appendManualRequestLogLine(QStringLiteral("后台线程创建失败，请稍后重试。"));
        KLogEvent threadCreateFailEvent;
        err << threadCreateFailEvent << "[NetworkDock] 手动请求后台线程创建失败。" << eol;
    }
}

void NetworkDock::replayPacketToManualRequestByTableRow(const int row)
{
    // replayEvent: A unified log event chain spanning the entire 'packet capture replay draft generation' process.
    KLogEvent replayEvent;

    // Basic row validation: The right-clicked target row must be valid and within the current table range.
    if (packetTable_ == nullptr || row < 0 || row >= packetTable_->rowCount())
    {
        warn << replayEvent
            << "[NetworkDock] 报文重放失败：目标行无效, row=" << row
            << eol;
        return;
    }

    // Extract the sequenceId from the UserRole in the time column to look up the complete packet entity.
    QTableWidgetItem* timeItem = packetTable_->item(row, toPacketColumn(PacketTableColumn::kTime));
    if (timeItem == nullptr)
    {
        warn << replayEvent
            << "[NetworkDock] 报文重放失败：时间列为空, row=" << row
            << eol;
        return;
    }

    const QVariant kSequenceVariant = timeItem->data(Qt::UserRole);
    if (!kSequenceVariant.isValid())
    {
        warn << replayEvent
            << "[NetworkDock] 报文重放失败：sequenceId 缺失, row=" << row
            << eol;
        return;
    }

    const std::uint64_t kSequenceId = static_cast<std::uint64_t>(kSequenceVariant.toULongLong());
    const auto kPacketIterator = packetBySequence_.find(kSequenceId);
    if (kPacketIterator == packetBySequence_.end())
    {
        appendManualRequestLogLine(QStringLiteral("回放失败：该报文已被清理，无法生成重放草稿。"));

        warn << replayEvent
            << "[NetworkDock] 报文重放失败：缓存中不存在该序号, sequenceId=" << kSequenceId
            << eol;
        return;
    }

    // Request construction page critical control validation: if any critical control is missing, automatic population cannot be completed.
    if (manualApiCombo_ == nullptr ||
        manualOverrideSocketParameterCheck_ == nullptr ||
        manualEnableBindCheck_ == nullptr ||
        manualLocalAddressEdit_ == nullptr ||
        manualLocalPortSpin_ == nullptr ||
        manualRemoteAddressEdit_ == nullptr ||
        manualRemotePortSpin_ == nullptr ||
        manualConnectBeforeSendCheck_ == nullptr ||
        manualPayloadFormatCombo_ == nullptr ||
        manualPayloadEditor_ == nullptr)
    {
        warn << replayEvent
            << "[NetworkDock] 报文重放失败：请求构造页控件未就绪。"
            << eol;
        return;
    }

    // packetRecord usage: Carries the packet capture entity to be replayed; subsequent parameters are extracted uniformly from this object.
    const ks::network::PacketRecord& packetRecord = kPacketIterator->second;

    // The current request executor only supports IPv4; IPv6 packets provide a clear prompt to prevent user error.
    std::uint32_t remoteIpv4HostOrder = 0;
    if (!tryParseIpv4Text(toQString(packetRecord.remoteAddress), remoteIpv4HostOrder))
    {
        appendManualRequestLogLine(
            QStringLiteral("回放失败：当前快速重放仅支持 IPv4 报文，IPv6 请在请求构造页手工填写。"));

        warn << replayEvent
            << "[NetworkDock] 报文重放失败：远端地址不是 IPv4, sequenceId=" << kSequenceId
            << ", remote=" << packetRecord.remoteAddress
            << eol;
        return;
    }

    // Port 0 cannot serve as a regular target endpoint; intercept early and prompt.
    if (packetRecord.remotePort == 0)
    {
        appendManualRequestLogLine(QStringLiteral("回放失败：该报文远端端口为 0，无法自动生成目标端点。"));

        warn << replayEvent
            << "[NetworkDock] 报文重放失败：远端端口为 0, sequenceId=" << kSequenceId
            << eol;
        return;
    }

    // replayApiKind usage: maps request construction patterns (TCP/UDP) based on the captured packet protocol.
    const ks::network::ManualNetworkApiKind kReplayApiKind =
        (packetRecord.protocol == ks::network::PacketTransportProtocol::kTcp)
        ? ks::network::ManualNetworkApiKind::kWinSockTcp
        : ks::network::ManualNetworkApiKind::kWinSockUdp;
    const int kReplayApiComboIndex = manualApiCombo_->findData(static_cast<int>(kReplayApiKind));

    // payloadHexText: Converts raw payload bytes to HEX text for direct use in request construction.
    const QString kPayloadHexText = network_dock_detail::buildPayloadHexFullText(packetRecord);
    // payloadRange usage: Records the byte range of the payload available for replay in this session, facilitating log output and prompts.
    const auto kPayloadRange = network_dock_detail::buildPayloadByteRange(packetRecord);

    // Unified request construction page for manual override: Replay first generates an 'editable draft' instead of auto-executing directly.
    manualOverrideSocketParameterCheck_->setChecked(false);
    if (kReplayApiComboIndex >= 0)
    {
        manualApiCombo_->setCurrentIndex(kReplayApiComboIndex);
    }
    manualEnableBindCheck_->setChecked(false);
    manualLocalAddressEdit_->setText(QStringLiteral("0.0.0.0"));
    manualLocalPortSpin_->setValue(0);
    manualRemoteAddressEdit_->setText(toQString(packetRecord.remoteAddress));
    manualRemotePortSpin_->setValue(static_cast<int>(packetRecord.remotePort));
    manualConnectBeforeSendCheck_->setChecked(true);

    const int kHexFormatIndex = manualPayloadFormatCombo_->findData(
        static_cast<int>(ks::network::ManualPayloadFormat::kHexBytes));
    if (kHexFormatIndex >= 0)
    {
        manualPayloadFormatCombo_->setCurrentIndex(kHexFormatIndex);
    }
    manualPayloadEditor_->setPlainText(kPayloadHexText);

    // Automatically switch to the request construction page to allow users to review and make secondary adjustments immediately.
    if (sideTabWidget_ != nullptr && manualRequestPage_ != nullptr)
    {
        sideTabWidget_->setCurrentWidget(manualRequestPage_);
    }

    appendManualRequestLogLine(QStringLiteral(
        "已载入回放草稿：seq=%1, 协议=%2, 目标=%3:%4, payloadBytes=%5。")
        .arg(static_cast<qulonglong>(packetRecord.sequenceId))
        .arg(toQString(ks::network::packetProtocolToString(packetRecord.protocol)))
        .arg(toQString(packetRecord.remoteAddress))
        .arg(packetRecord.remotePort)
        .arg(static_cast<qulonglong>(kPayloadRange.second)));
    appendManualRequestLogLine(QStringLiteral("提示：已自动切换到 HEX 载荷模式，点击“执行请求”即可发送。"));

    if (packetRecord.direction == ks::network::PacketDirection::kInbound)
    {
        appendManualRequestLogLine(QStringLiteral("提示：该报文是入站包，重放时将由本机主动发往远端。"));
    }
    if (packetRecord.packetBytesTruncated)
    {
        appendManualRequestLogLine(QStringLiteral("注意：该报文抓包内容被截断，重放仅使用已保留字节。"));
    }
    if (kPayloadRange.second == 0)
    {
        appendManualRequestLogLine(QStringLiteral("提示：该报文 payload 为空，执行时将发送空载荷。"));
    }

    info << replayEvent
        << "[NetworkDock] 已生成报文重放草稿, sequenceId=" << kSequenceId
        << ", api=" << ks::network::manualNetworkApiKindToString(kReplayApiKind)
        << ", remote=" << packetRecord.remoteAddress << ":" << packetRecord.remotePort
        << ", payloadBytes=" << kPayloadRange.second
        << ", truncated=" << (packetRecord.packetBytesTruncated ? "true" : "false")
        << eol;
}

void NetworkDock::resetManualRequestForm()
{
    // Protective check: return immediately if the page has not been initialized.
    if (manualApiCombo_ == nullptr ||
        manualOverrideSocketParameterCheck_ == nullptr ||
        manualAddressFamilyEdit_ == nullptr ||
        manualSocketTypeEdit_ == nullptr ||
        manualProtocolEdit_ == nullptr ||
        manualSocketFlagsEdit_ == nullptr ||
        manualEnableBindCheck_ == nullptr ||
        manualLocalAddressEdit_ == nullptr ||
        manualLocalPortSpin_ == nullptr ||
        manualRemoteAddressEdit_ == nullptr ||
        manualRemotePortSpin_ == nullptr ||
        manualConnectBeforeSendCheck_ == nullptr ||
        manualReuseAddressCheck_ == nullptr ||
        manualNoDelayCheck_ == nullptr ||
        manualSendTimeoutSpin_ == nullptr ||
        manualRecvTimeoutSpin_ == nullptr ||
        manualPayloadFormatCombo_ == nullptr ||
        manualPayloadEditor_ == nullptr ||
        manualSendFlagsEdit_ == nullptr ||
        manualReceiveFlagsEdit_ == nullptr ||
        manualReceiveAfterSendCheck_ == nullptr ||
        manualReceiveMaxBytesSpin_ == nullptr ||
        manualShutdownSendCheck_ == nullptr)
    {
        return;
    }

    // Default parameters focus on TCP text requests that allow direct link verification.
    manualApiCombo_->setCurrentIndex(0);
    manualOverrideSocketParameterCheck_->setChecked(false);
    manualAddressFamilyEdit_->setText(QStringLiteral("2")); // AF_INET
    manualSocketTypeEdit_->setText(QStringLiteral("1"));    // SOCK_STREAM
    manualProtocolEdit_->setText(QStringLiteral("6"));      // IPPROTO_TCP
    manualSocketFlagsEdit_->setText(QStringLiteral("0x1")); // WSA_FLAG_OVERLAPPED
    manualEnableBindCheck_->setChecked(false);
    manualLocalAddressEdit_->setText(QStringLiteral("0.0.0.0"));
    manualLocalPortSpin_->setValue(0);
    manualRemoteAddressEdit_->setText(QStringLiteral("127.0.0.1"));
    manualRemotePortSpin_->setValue(80);
    manualConnectBeforeSendCheck_->setChecked(true);
    manualReuseAddressCheck_->setChecked(false);
    manualNoDelayCheck_->setChecked(false);
    manualSendTimeoutSpin_->setValue(3000);
    manualRecvTimeoutSpin_->setValue(3000);
    manualPayloadFormatCombo_->setCurrentIndex(0);
    manualPayloadEditor_->setPlainText(QStringLiteral("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"));
    manualSendFlagsEdit_->setText(QStringLiteral("0"));
    manualReceiveFlagsEdit_->setText(QStringLiteral("0"));
    manualReceiveAfterSendCheck_->setChecked(true);
    manualReceiveMaxBytesSpin_->setValue(4096);
    manualShutdownSendCheck_->setChecked(false);

    appendManualRequestLogLine(QStringLiteral("已恢复请求构造页默认参数。"));

    KLogEvent resetRequestEvent;
    info << resetRequestEvent << "[NetworkDock] 请求构造页参数已恢复默认值。" << eol;
}

void NetworkDock::appendManualRequestLogLine(const QString& logLine)
{
    if (manualResultOutput_ == nullptr)
    {
        return;
    }

    const QString kTimePrefix = QDateTime::currentDateTime().toString("HH:mm:ss.zzz");
    manualResultOutput_->appendPlainText(QStringLiteral("[%1] %2").arg(kTimePrefix, logLine));
}
