#include "NetworkDock.InternalCommon.h"

using namespace network_dock_detail;
void NetworkDock::openPacketDetailWindowFromTableRow(QTableWidget* tableWidget, const int row)
{
    if (tableWidget == nullptr || row < 0)
    {
        return;
    }

    QTableWidgetItem* firstItem = tableWidget->item(row, toPacketColumn(PacketTableColumn::kTime));
    if (firstItem == nullptr)
    {
        return;
    }

    const QVariant kSequenceVariant = firstItem->data(Qt::UserRole);
    if (!kSequenceVariant.isValid())
    {
        return;
    }

    const std::uint64_t kSequenceId = static_cast<std::uint64_t>(kSequenceVariant.toULongLong());
    openPacketDetailWindowBySequenceId(kSequenceId);
}

void NetworkDock::openPacketDetailWindowBySequenceId(const std::uint64_t sequenceId)
{
    const auto kIterator = packetBySequence_.find(sequenceId);
    if (kIterator == packetBySequence_.end())
    {
        QMessageBox::information(this, QStringLiteral("报文详情"), QStringLiteral("该报文已被清理，无法查看详情。"));
        return;
    }

    // The details window is launched via a unified helper function to ensure behavior consistency with the legacy structure.
    showPacketDetailWindow(kIterator->second);

    KLogEvent detailWindowEvent;
    info << detailWindowEvent
        << "[NetworkDock] 打开报文详情窗口, sequenceId=" << sequenceId
        << ", pid=" << kIterator->second.processId
        << eol;
}

QIcon NetworkDock::resolveProcessIconByPid(const std::uint32_t processId, const std::string& processName)
{
    if (processId == 0)
    {
        return QIcon(":/Icon/process_main.svg");
    }

    const quint32 kPidKey = static_cast<quint32>(processId);
    const auto kCacheIterator = processIconCacheByPid_.constFind(kPidKey);
    if (kCacheIterator != processIconCacheByPid_.constEnd())
    {
        return kCacheIterator.value();
    }

    QIcon processIcon;

    // First, attempt to extract the system file icon based on the executable path.
    const std::string kProcessPath = ks::process::queryProcessPathByPid(processId);
    if (!kProcessPath.empty())
    {
        static QFileIconProvider fileIconProvider;
        const QString kProcessPathText = QString::fromUtf8(kProcessPath.c_str());
        processIcon = fileIconProvider.icon(QFileInfo(kProcessPathText));
    }

    // If the path is unavailable, fall back to the unified icon to ensure a visible icon is always present in the column.
    if (processIcon.isNull())
    {
        processIcon = QIcon(":/Icon/process_main.svg");
    }

    processIconCacheByPid_.insert(kPidKey, processIcon);

    // Log an exception entry even if the name is empty to facilitate source location.
    if (processName.empty())
    {
        KLogEvent iconEvent;
        warn << iconEvent << "[NetworkDock] 进程名为空，使用默认图标, pid=" << processId << eol;
    }
    return processIcon;
}

bool NetworkDock::packetPassesMonitorFilter(const ks::network::PacketRecord& packetRecord) const
{
    if (!packetPassesTimelineFilter(packetRecord))
    {
        return false;
    }

    if (activeMonitorFilterGroupList_.empty())
    {
        return true;
    }

    for (const MonitorFilterRuleGroupCompiled& groupFilter : activeMonitorFilterGroupList_)
    {
        if (!groupFilter.enabled)
        {
            continue;
        }

        if (packetMatchesMonitorFilterGroup(packetRecord, groupFilter))
        {
            return true;
        }
    }

    return false;
}

bool NetworkDock::packetPassesMonitorFilter(
    const std::uint64_t sequenceId,
    const ks::network::PacketRecord& packetRecord) const
{
    // Sequence version used for historical cache reconstruction:
    // - Timeline filtering requires the compressed time cached when the packet was first inserted.
    // - Other rules still reuse the original process/IP/port/packet length matching logic.
    if (!packetPassesTimelineFilter(sequenceId, packetRecord))
    {
        return false;
    }

    if (activeMonitorFilterGroupList_.empty())
    {
        return true;
    }

    for (const MonitorFilterRuleGroupCompiled& groupFilter : activeMonitorFilterGroupList_)
    {
        if (!groupFilter.enabled)
        {
            continue;
        }

        if (packetMatchesMonitorFilterGroup(packetRecord, groupFilter))
        {
            return true;
        }
    }

    return false;
}

int NetworkDock::toPacketColumn(const PacketTableColumn column)
{
    return static_cast<int>(column);
}

int NetworkDock::toRateLimitColumn(const RateLimitTableColumn column)
{
    return static_cast<int>(column);
}

int NetworkDock::toTcpConnectionColumn(const TcpConnectionTableColumn column)
{
    return static_cast<int>(column);
}

int NetworkDock::toUdpEndpointColumn(const UdpEndpointTableColumn column)
{
    return static_cast<int>(column);
}

int NetworkDock::toNidsAlertColumn(const NidsAlertTableColumn column)
{
    return static_cast<int>(column);
}

bool NetworkDock::tryParsePidText(const QString& pidText, std::uint32_t& pidOut)
{
    bool parseOk = false;
    const unsigned long kPidValue = pidText.trimmed().toULong(&parseOk, 10);
    if (!parseOk || kPidValue == 0 || kPidValue > 0xFFFFFFFFUL)
    {
        return false;
    }

    pidOut = static_cast<std::uint32_t>(kPidValue);
    return true;
}

bool NetworkDock::tryParseUnsignedIntegerText(const QString& integerText, std::uint32_t& valueOut)
{
    const QString kTrimmedText = integerText.trimmed();
    if (kTrimmedText.isEmpty())
    {
        return false;
    }

    bool parseOk = false;
    qulonglong parsedValue = 0;

    // Prioritize recognition of 0x-prefixed hexadecimal input.
    if (kTrimmedText.startsWith("0x", Qt::CaseInsensitive))
    {
        parsedValue = kTrimmedText.mid(2).toULongLong(&parseOk, 16);
    }
    else
    {
        // If no prefix is present, try decimal first; if that fails, try hexadecimal.
        parsedValue = kTrimmedText.toULongLong(&parseOk, 10);
        if (!parseOk)
        {
            parsedValue = kTrimmedText.toULongLong(&parseOk, 16);
        }
    }

    if (!parseOk || parsedValue > static_cast<qulonglong>(0xFFFFFFFFULL))
    {
        return false;
    }

    valueOut = static_cast<std::uint32_t>(parsedValue);
    return true;
}
