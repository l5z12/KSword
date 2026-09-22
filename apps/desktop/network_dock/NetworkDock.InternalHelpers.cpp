#include "NetworkDock.InternalHelpers.h"

#include "../ui/HexEditorWidget.h"
#include "../ui/TableInteractionSupport.h"
#include "../../../shared/platform/network/NetworkFormatTools.h"
#include "../Theme.h"
#include "../../../shared/driver/KswordArkNetworkIoctl.h"

#include <QAction>
#include <QClipboard>
#include <QGuiApplication>
#include <QMenu>
#include <QModelIndex>
#include <QLabel>
#include <QPainter>
#include <QPlainTextEdit>
#include <QStringList>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>
#include <QWidget>

namespace network_dock_detail
{
    // packetSourceDisplayText:
    // - Convert internal data sources and WFP event flags into localized, explicit source text.
    // - R0 events are always declared without a packet payload to avoid being mistaken for per-packet capture;
    static QString packetSourceDisplayText(const ks::network::PacketRecord& packetRecord)
    {
        if (!packetRecord.wfpAleEventNoPayload)
        {
            return packetRecord.sourceText.empty()
                ? QStringLiteral("R3")
                : toQString(packetRecord.sourceText);
        }
        if ((packetRecord.sourceFlags & KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_BLOCKED) != 0UL)
        {
            return QStringLiteral("R0 WFP ALE 流事件（已阻断；无 packet payload）");
        }
        if ((packetRecord.sourceFlags & KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_ACTION_WRITE_UNAVAILABLE) != 0UL)
        {
            return QStringLiteral("R0 WFP ALE 流事件（仅观察；无 packet payload）");
        }
        return QStringLiteral("R0 WFP ALE 流事件（已放行；无 packet payload）");
    }

    void installCopyCurrentRowMenu(
        QTableWidget* tableWidget,
        const QString& actionText,
        const int processIdColumn)
    {
        // installCopyCurrentRowMenu:
        // - Input: Any NetworkDock table and menu item text.
        // - Handles: Selects the row right-clicked and copies all visible columns as TSV.
        // - Returns: none. Silently returns on failure to maintain monitoring page stability.
        if (tableWidget == nullptr)
        {
            return;
        }

        tableWidget->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(
            tableWidget,
            &QTableWidget::customContextMenuRequested,
            tableWidget,
            [tableWidget, actionText, processIdColumn](const QPoint& localPosition)
            {
                const QModelIndex kClickedIndex = tableWidget->indexAt(localPosition);
                if (kClickedIndex.isValid())
                {
                    tableWidget->setCurrentCell(kClickedIndex.row(), kClickedIndex.column());
                }

                QMenu contextMenu(tableWidget);
                contextMenu.setStyleSheet(ksword_theme::contextMenuStyle());
                QAction* copyRowAction = contextMenu.addAction(
                    QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
                    actionText);
                copyRowAction->setEnabled(tableWidget->currentRow() >= 0);
                quint32 processId = 0;
                if (processIdColumn >= 0 && processIdColumn < tableWidget->columnCount() &&
                    tableWidget->currentRow() >= 0 && tableWidget->currentRow() < tableWidget->rowCount())
                {
                    const QTableWidgetItem* processIdItem = tableWidget->item(
                        tableWidget->currentRow(),
                        processIdColumn);
                    bool parseOk = false;
                    const uint kParsedProcessId = processIdItem != nullptr
                        ? processIdItem->text().toUInt(&parseOk, 10)
                        : 0U;
                    if (parseOk && kParsedProcessId != 0U)
                    {
                        processId = static_cast<quint32>(kParsedProcessId);
                    }
                }
                QAction* openProcessDetailAction = nullptr;
                if (processIdColumn >= 0)
                {
                    openProcessDetailAction = contextMenu.addAction(
                        QIcon(QStringLiteral(":/Icon/process_details.svg")),
                        QStringLiteral("转到进程详细信息"));
                    openProcessDetailAction->setEnabled(processId != 0U);
                }

                const QAction* selectedAction = contextMenu.exec(tableWidget->viewport()->mapToGlobal(localPosition));
                if (selectedAction == openProcessDetailAction)
                {
                    ks::ui::openProcessDetailByPid(processId);
                    return;
                }
                if (selectedAction != copyRowAction)
                {
                    return;
                }

                QClipboard* clipboardObject = QGuiApplication::clipboard();
                const int kRowIndex = tableWidget->currentRow();
                if (clipboardObject == nullptr || kRowIndex < 0 || kRowIndex >= tableWidget->rowCount())
                {
                    return;
                }

                QStringList rowFields;
                rowFields.reserve(tableWidget->columnCount());
                for (int columnIndex = 0; columnIndex < tableWidget->columnCount(); ++columnIndex)
                {
                    const QTableWidgetItem* item = tableWidget->item(kRowIndex, columnIndex);
                    rowFields.push_back(item != nullptr ? item->text() : QString());
                }
                clipboardObject->setText(rowFields.join(QLatin1Char('\t')));
            });
    }

    namespace
    {
        // buildPacketDetailWindowStyle:
        // - Generate independent theme styles for the 'Traffic Monitoring -> Packet Details' window;
        // - Focuses on overriding QPlainTextEdit/QTabWidget/Page to fix white background remnants in dark mode.
        QString buildPacketDetailWindowStyle()
        {
            const QString kWindowBackground = ksword_theme::surfaceHex();
            const QString kPanelBackground = ksword_theme::surfaceAltHex();
            const QString kInputBackground = ksword_theme::surfaceMutedColorHex();
            const QString kBorderColor = ksword_theme::borderHex();
            const QString kTextColor = ksword_theme::textPrimaryHex();
            const QString kSecondaryTextColor = ksword_theme::textSecondaryHex();
            const QString kAccentColor = ksword_theme::accentHex(ksword_theme::AccentRole::kBlue);

            return QStringLiteral(
                "QWidget{"
                "  background:%1;"
                "  color:%2;"
                "}"
                "QLabel{"
                "  background:transparent;"
                "  color:%2;"
                "}"
                "QTabWidget::pane{"
                "  background:%3;"
                "  border:1px solid %4;"
                "  border-radius:4px;"
                "}"
                "QTabBar::tab{"
                "  background:%1;"
                "  color:%5;"
                "  border:1px solid %4;"
                "  padding:6px 12px;"
                "  margin-right:2px;"
                "  border-top-left-radius:4px;"
                "  border-top-right-radius:4px;"
                "}"
                "QTabBar::tab:selected{"
                "  background:%3;"
                "  color:%2;"
                "  border-bottom-color:%3;"
                "}"
                "QPlainTextEdit{"
                "  background:%6;"
                "  color:%2;"
                "  border:1px solid %4;"
                "  selection-background-color:%7;"
                "  selection-color:%8;"
                "}"
                "QMenu{"
                "  background:%6;"
                "  color:%2;"
                "  border:1px solid %4;"
                "}"
                "QMenu::item:selected{"
                "  background:%7;"
                "  color:%8;"
                "}"
                "QMenu::separator{"
                "  height:1px;"
                "  background:%4;"
                "  margin:2px 6px;"
                "}"
                "QScrollBar:vertical,QScrollBar:horizontal{"
                "  background:%3;"
                "}"
                "QScrollBar::handle:vertical,QScrollBar::handle:horizontal{"
                "  background:%7;"
                "}")
                .arg(kWindowBackground)
                .arg(kTextColor)
                .arg(kPanelBackground)
                .arg(kBorderColor)
                .arg(kSecondaryTextColor)
                .arg(kInputBackground)
                .arg(kAccentColor)
                .arg(ksword_theme::onAccentDynamicHex());
        }

        // PacketDetailWindow：
        // - Packet details independent window (show is non-blocking, does not block main UI).
        // - The hexadecimal section uses a plain text editor, supporting continuous multi-line selection and copying just like text.
        class PacketDetailWindow final : public QWidget
        {
        public:
            explicit PacketDetailWindow(const ks::network::PacketRecord& packetRecord, QWidget* parent = nullptr)
                : QWidget(parent)
            {
                setAttribute(Qt::WA_DeleteOnClose, true);
                setWindowFlag(Qt::Window, true);
                setAttribute(Qt::WA_StyledBackground, true);
                setAutoFillBackground(true);
                setWindowTitle(
                    packetRecord.wfpAleEventNoPayload
                        ? QStringLiteral("R0 WFP ALE 流事件详情 - #%1").arg(packetRecord.sequenceId)
                        : QStringLiteral("报文详情 - #%1").arg(packetRecord.sequenceId));
                resize(1120, 760);
                setStyleSheet(buildPacketDetailWindowStyle());

                QVBoxLayout* rootLayout = new QVBoxLayout(this);
                rootLayout->setContentsMargins(8, 8, 8, 8);
                rootLayout->setSpacing(6);

                // Metadata area: timestamp, protocol, direction, PID, endpoint, length.
                QLabel* metaLabel = new QLabel(this);
                const QString kTimeText = toQString(
                    ks::network::formatUnixTimestampMs(packetRecord.captureTimestampMs, true));
                if (packetRecord.wfpAleEventNoPayload)
                {
                    metaLabel->setText(QStringLiteral(
                        "来源: %1\n驱动事件序号: %2  标志: 0x%3\n时间: %4\n协议: %5  方向: %6\nPID: %7  进程: %8\n本地: %9\n远端: %10\n总长度: -（ALE 元数据）, 负载: -（ALE 无 payload）")
                        .arg(packetSourceDisplayText(packetRecord))
                        .arg(packetRecord.sourceSequenceId)
                        .arg(packetRecord.sourceFlags, 8, 16, QChar('0'))
                        .arg(kTimeText)
                        .arg(toQString(ks::network::packetProtocolToString(packetRecord.protocol)))
                        .arg(toQString(ks::network::packetDirectionToString(packetRecord.direction)))
                        .arg(packetRecord.processId)
                        .arg(toQString(packetRecord.processName))
                        .arg(formatEndpointText(packetRecord.localAddress, packetRecord.localPort))
                        .arg(formatEndpointText(packetRecord.remoteAddress, packetRecord.remotePort)));
                }
                else
                {
                    metaLabel->setText(QStringLiteral(
                        "时间: %1\n协议: %2  方向: %3\nPID: %4  进程: %5\n本地: %6\n远端: %7\n总长度: %8 bytes, 负载: %9 bytes")
                        .arg(kTimeText)
                        .arg(toQString(ks::network::packetProtocolToString(packetRecord.protocol)))
                        .arg(toQString(ks::network::packetDirectionToString(packetRecord.direction)))
                        .arg(packetRecord.processId)
                        .arg(toQString(packetRecord.processName))
                        .arg(formatEndpointText(packetRecord.localAddress, packetRecord.localPort))
                        .arg(formatEndpointText(packetRecord.remoteAddress, packetRecord.remotePort))
                        .arg(packetRecord.totalPacketSize)
                        .arg(packetRecord.payloadSize));
                }
                metaLabel->setWordWrap(true);
                metaLabel->setStyleSheet(QStringLiteral("padding:6px 8px;border:1px solid %1;border-radius:4px;")
                    .arg(ksword_theme::borderHex()));
                rootLayout->addWidget(metaLabel);

                // Readable summary: First display a semantic ASCII summary matching the 'Content Preview' column to facilitate quick protocol text judgment.
                QLabel* readablePreviewLabel = new QLabel(this);
                const QString kReadablePreviewText =
                    packetRecord.wfpAleEventNoPayload
                        ? QStringLiteral("R0 WFP ALE 流事件不包含 packet payload")
                        : network_dock_detail::buildPayloadAsciiPreviewText(packetRecord);
                readablePreviewLabel->setText(
                    QStringLiteral("可读ASCII摘要: %1").arg(kReadablePreviewText));
                readablePreviewLabel->setWordWrap(true);
                readablePreviewLabel->setToolTip(
                    packetRecord.wfpAleEventNoPayload
                        ? QStringLiteral("该记录来自内核 WFP ALE 流授权层，不包含逐包长度、报文字节或 payload。")
                        : QStringLiteral("该摘要优先提取 payload 中可读 ASCII 片段。"));
                readablePreviewLabel->setStyleSheet(QStringLiteral("color:%1;").arg(ksword_theme::textSecondaryHex()));
                rootLayout->addWidget(readablePreviewLabel);

                // Details tab: currently retains only the hexadecimal view tab.
                QTabWidget* detailTabWidget = new QTabWidget(this);
                rootLayout->addWidget(detailTabWidget, 1);

                // Hex page: Unified reuse of HexEditorWidget, with functionality consistent with the memory and file modules.
                QWidget* hexPage = new QWidget(detailTabWidget);
                QVBoxLayout* hexPageLayout = new QVBoxLayout(hexPage);
                hexPageLayout->setContentsMargins(0, 0, 0, 0);
                hexPageLayout->setSpacing(4);

                QLabel* hexHintLabel = new QLabel(
                    packetRecord.wfpAleEventNoPayload
                        ? QStringLiteral("R0 WFP ALE 流事件没有报文字节；十六进制区域保持为空。")
                        : QStringLiteral("十六进制区域支持 Ctrl+F 异步查找、Ctrl+G 跳转、批量复制与导出。"),
                    hexPage);
                hexHintLabel->setWordWrap(true);
                hexHintLabel->setStyleSheet(QStringLiteral("color:%1;").arg(ksword_theme::textSecondaryHex()));
                hexPageLayout->addWidget(hexHintLabel);

                HexEditorWidget* hexEditorWidget = new HexEditorWidget(hexPage);
                hexEditorWidget->setEditable(false);
                hexEditorWidget->setBytesPerRow(16);
                if (!packetRecord.packetBytes.empty())
                {
                    const QByteArray kPacketBytes(
                        reinterpret_cast<const char*>(packetRecord.packetBytes.data()),
                        static_cast<int>(packetRecord.packetBytes.size()));
                    hexEditorWidget->setByteArray(kPacketBytes, 0);
                }
                else
                {
                    hexEditorWidget->clearData();
                }
                hexPageLayout->addWidget(hexEditorWidget, 1);

                detailTabWidget->addTab(hexPage, QStringLiteral("十六进制"));
            }
        };
    }

    QString toQString(const std::string& textValue)
    {
        return QString::fromUtf8(textValue.c_str());
    }

    QString formatEndpointText(const std::string& ipAddress, const std::uint16_t portNumber)
    {
        return toQString(ks::network::formatEndpointText(ipAddress, portNumber));
    }

    QString formatBytesToHexText(const std::vector<std::uint8_t>& byteArray, const std::size_t maxBytesToRender)
    {
        return toQString(ks::network::formatBytesToHexPreview(byteArray, maxBytesToRender));
    }

    std::pair<std::size_t, std::size_t> buildPayloadByteRange(const ks::network::PacketRecord& packetRecord)
    {
        const ks::network::PayloadByteRange kPayloadRange =
            ks::network::buildPayloadByteRange(packetRecord);
        return { kPayloadRange.offset, kPayloadRange.length };
    }

    QString buildPayloadAsciiPreviewText(const ks::network::PacketRecord& packetRecord)
    {
        return toQString(ks::network::buildPayloadAsciiPreviewText(packetRecord));
    }

    QString buildPayloadAsciiFullText(const ks::network::PacketRecord& packetRecord)
    {
        return toQString(ks::network::buildPayloadAsciiFullText(packetRecord));
    }

    QString buildPayloadHexFullText(const ks::network::PacketRecord& packetRecord)
    {
        return toQString(ks::network::buildPayloadHexFullText(packetRecord));
    }

    QString buildPacketHexAsciiDumpText(const ks::network::PacketRecord& packetRecord)
    {
        return toQString(ks::network::buildPacketHexAsciiDumpText(packetRecord));
    }

    QString buildPacketCopyHeaderLine(const ks::network::PacketRecord& packetRecord)
    {
        return toQString(ks::network::buildPacketCopyHeaderLine(packetRecord));
    }

    QString formatIpv4HostOrder(const std::uint32_t ipv4HostOrder)
    {
        return toQString(ks::network::formatIpv4HostOrder(ipv4HostOrder));
    }

    bool tryParseIpv4Text(const QString& ipv4Text, std::uint32_t& ipv4HostOrderOut)
    {
        return ks::network::tryParseIpv4Text(ipv4Text.trimmed().toStdString(), &ipv4HostOrderOut);
    }

    bool tryParseIpv4RangeText(
        const QString& rangeText,
        std::pair<std::uint32_t, std::uint32_t>& rangeOut,
        QString& normalizeTextOut)
    {
        std::string normalizedText;
        const bool kParseOk = ks::network::tryParseIpv4RangeText(
            rangeText.trimmed().toStdString(),
            &rangeOut,
            &normalizedText);
        normalizeTextOut = toQString(normalizedText);
        return kParseOk;
    }

    bool tryParsePortRangeText(
        const QString& rangeText,
        std::pair<std::uint16_t, std::uint16_t>& rangeOut,
        QString& normalizeTextOut)
    {
        std::string normalizedText;
        const bool kParseOk = ks::network::tryParsePortRangeText(
            rangeText.trimmed().toStdString(),
            &rangeOut,
            &normalizedText);
        normalizeTextOut = toQString(normalizedText);
        return kParseOk;
    }

    QTableWidgetItem* createPacketCell(const QString& cellText)
    {
        QTableWidgetItem* tableItem = new QTableWidgetItem(cellText);
        tableItem->setFlags(tableItem->flags() & ~Qt::ItemIsEditable);
        return tableItem;
    }

    void populatePacketRow(
        QTableWidget* tableWidget,
        const int rowIndex,
        const ks::network::PacketRecord& packetRecord,
        const std::uint64_t sequenceId,
        const QIcon& processIcon)
    {
        if (tableWidget == nullptr || rowIndex < 0)
        {
            return;
        }

        const QString kTimeText = toQString(
            ks::network::formatUnixTimestampMs(packetRecord.captureTimestampMs, false));
        const QString kProtocolText = toQString(ks::network::packetProtocolToString(packetRecord.protocol));
        const QString kDirectionText = toQString(ks::network::packetDirectionToString(packetRecord.direction));
        const QString kSourceText = packetSourceDisplayText(packetRecord);
        const QString kPidText = QString::number(packetRecord.processId);
        const QString kProcessNameText = toQString(packetRecord.processName);
        const QString kLocalEndpointText = formatEndpointText(packetRecord.localAddress, packetRecord.localPort);
        const QString kRemoteEndpointText = formatEndpointText(packetRecord.remoteAddress, packetRecord.remotePort);
        const QString kRemoteDomainText = packetRecord.remoteDomain.empty()
            ? QStringLiteral("解析中…")
            : toQString(packetRecord.remoteDomain);
        const QString kPacketSizeText = packetRecord.wfpAleEventNoPayload
            ? QStringLiteral("-")
            : QString::number(packetRecord.totalPacketSize);
        const QString kPayloadSizeText = packetRecord.wfpAleEventNoPayload
            ? QStringLiteral("-")
            : QString::number(packetRecord.payloadSize);
        const QString kPreviewText = packetRecord.wfpAleEventNoPayload
            ? QStringLiteral("R0 WFP ALE 流事件不包含 packet payload")
            : network_dock_detail::buildPayloadAsciiPreviewText(packetRecord);

        QTableWidgetItem* timeItem = createPacketCell(kTimeText);
        timeItem->setData(Qt::UserRole, static_cast<qulonglong>(sequenceId));
        tableWidget->setItem(rowIndex, 0, timeItem);
        tableWidget->setItem(rowIndex, 1, createPacketCell(kProtocolText));
        tableWidget->setItem(rowIndex, 2, createPacketCell(kDirectionText));
        tableWidget->setItem(rowIndex, 3, createPacketCell(kSourceText));
        tableWidget->setItem(rowIndex, 4, createPacketCell(kPidText));
        QTableWidgetItem* processNameItem = createPacketCell(kProcessNameText);
        processNameItem->setIcon(processIcon);
        tableWidget->setItem(rowIndex, 5, processNameItem);
        tableWidget->setItem(rowIndex, 6, createPacketCell(kLocalEndpointText));
        tableWidget->setItem(rowIndex, 7, createPacketCell(kRemoteEndpointText));
        QTableWidgetItem* remoteDomainItem = createPacketCell(kRemoteDomainText);
        remoteDomainItem->setData(Qt::UserRole, toQString(packetRecord.remoteAddress));
        tableWidget->setItem(rowIndex, 8, remoteDomainItem);
        tableWidget->setItem(rowIndex, 9, createPacketCell(kPacketSizeText));
        tableWidget->setItem(rowIndex, 10, createPacketCell(kPayloadSizeText));
        tableWidget->setItem(rowIndex, 11, createPacketCell(kPreviewText));
    }

    void showPacketDetailWindow(const ks::network::PacketRecord& packetRecord)
    {
        // The detail window is popped up non-modally using show(), without blocking the main UI.
        // Independent window: not docked under the main Dock to prevent layout changes in the main window from affecting the detail window.
        PacketDetailWindow* detailWindow = new PacketDetailWindow(packetRecord, nullptr);
        detailWindow->setWindowFlag(Qt::Window, true);
        detailWindow->show();
        detailWindow->raise();
        detailWindow->activateWindow();
    }
}
