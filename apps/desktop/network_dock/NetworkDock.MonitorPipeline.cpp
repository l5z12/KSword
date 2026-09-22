#include "NetworkDock.InternalCommon.h"

#include <QAbstractItemModel>
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QImage>
#include <QPixmap>
#include <QPointer>
#include <QSet>

#include <cstddef>
#include <unordered_map>
#include <utility>

#include <objbase.h>
#include <Shellapi.h>

#pragma comment(lib, "Dnsapi.lib")

using namespace network_dock_detail;

namespace
{
    // g_pendingPacketProcessIconPidMap:
    // - Records the set of PIDs currently being background-resolved for icons per NetworkDock instance, used for deduplication by PID.
    // - Only read/write on the UI thread (dispatch and back-cast points are both on the UI thread), so no locking is needed.
    // - Keys serve only as identifiers and are never dereferenced; they are cleaned up by the back-injection branch after the host is destroyed.
    std::unordered_map<const NetworkDock*, QSet<quint32>> gPendingPacketProcessIconPidMap;

    // packetProcessPlaceholderIcon:
    // - Returns a unified placeholder icon for the packet processing column in the table. It is displayed before asynchronous parsing completes to prevent row height jitter caused by a null icon.
    // - Parameters: None;
    // - Returns: a shared QIcon reference, usable only on the UI thread.
    const QIcon& packetProcessPlaceholderIcon()
    {
        static const QIcon kPlaceholderIcon(QStringLiteral(":/Icon/process_main.svg"));
        return kPlaceholderIcon;
    }

    // extractProcessIconImageForPid:
    // - Parse the executable path by PID in a thread pool worker thread and query the small icon via Shell;
    // - SHGetFileInfoW requires the current thread to initialize COM explicitly, so CoInitializeEx and CoUninitialize are paired here.
    // - Input parameter processId: Target process PID.
    // - Return: QImage safe for cross-thread transfer; returns an empty QImage on failure (caller falls back to placeholder icon).
    QImage extractProcessIconImageForPid(const std::uint32_t processId)
    {
        const std::string kProcessPath = ks::process::queryProcessPathByPid(processId);
        if (kProcessPath.empty())
        {
            return QImage();
        }

        const HRESULT kComInitializeResult = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        const bool kComInitializedHere = SUCCEEDED(kComInitializeResult);

        const QString kProcessPathText = QString::fromUtf8(kProcessPath.c_str());
        SHFILEINFOW shellFileInfo{};
        const DWORD_PTR kShellQueryResult = ::SHGetFileInfoW(
            reinterpret_cast<const wchar_t*>(kProcessPathText.utf16()),
            0,
            &shellFileInfo,
            sizeof(shellFileInfo),
            SHGFI_ICON | SHGFI_SMALLICON);

        QImage processIconImage;
        if (kShellQueryResult != 0 && shellFileInfo.hIcon != nullptr)
        {
            // QImage::fromHICON copies pixel data; the HICON allocated by Shell must be released after conversion.
            processIconImage = QImage::fromHICON(shellFileInfo.hIcon);
            ::DestroyIcon(shellFileInfo.hIcon);
        }

        if (kComInitializedHere)
        {
            ::CoUninitialize();
        }
        return processIconImage;
    }

    // applyResolvedProcessIconToPacketRows:
    // - After asynchronous icon resolution completes, fill in the process column icons for existing rows with the same PID in the table.
    // - Input packetTable: Main packet table.
    // - Input parameters processIdColumn / processNameColumn: indices for the PID column and process name column (converted by the caller from column enumerations).
    // - Input processIdKey: PID resolved in this operation;
    // - Parameter resolvedIcon: resolved icon or placeholder icon.
    // - Return: None. This function must be called only on the UI thread.
    void applyResolvedProcessIconToPacketRows(
        QTableWidget* const packetTable,
        const int processIdColumn,
        const int processNameColumn,
        const quint32 processIdKey,
        const QIcon& resolvedIcon)
    {
        if (packetTable == nullptr || processIdColumn < 0 || processNameColumn < 0)
        {
            return;
        }

        const QString kProcessIdText = QString::number(processIdKey);
        for (int rowIndex = 0; rowIndex < packetTable->rowCount(); ++rowIndex)
        {
            const QTableWidgetItem* const kProcessIdItem = packetTable->item(rowIndex, processIdColumn);
            if (kProcessIdItem == nullptr || kProcessIdItem->text() != kProcessIdText)
            {
                continue;
            }

            QTableWidgetItem* const kProcessNameItem = packetTable->item(rowIndex, processNameColumn);
            if (kProcessNameItem != nullptr)
            {
                kProcessNameItem->setIcon(resolvedIcon);
            }
        }
    }

    // kUnixMsTo100ns：
    // - Multiplier for converting Unix millisecond timestamps to 100ns timeline units.
    // - Network packet capture uses Unix milliseconds, while the ETW timeline uses 100ns, so a unified conversion is required.
    constexpr std::uint64_t kUnixMsTo100ns = 10000ULL;

    // kFallbackTimelineRange100ns：
    // - Provides a 1-second non-zero span for the timeline when there are no packets or when the start and end times are identical.
    // - Prevent division by zero in the timeline control's internal coordinates and ensure the initial empty state remains visible.
    constexpr std::uint64_t kFallbackTimelineRange100ns = 1ULL * 1000ULL * 1000ULL * 10ULL;

    // kTimelineSecond100ns：
    // - The width of 1 second in the 100ns time axis unit;
    // - Aggregates packets into 'upload/download rate per second' buckets.
    constexpr std::uint64_t kTimelineSecond100ns = 1ULL * 1000ULL * 1000ULL * 10ULL;

    // unixMsToTimeline100ns：
    // - Purpose: Convert Unix ms duration or time difference to 100ns for timeline usage;
    // - Parameter unixMsValue: Milliseconds;
    // - Returns: 100ns time value.
    std::uint64_t unixMsToTimeline100ns(const std::uint64_t unixMsValue)
    {
        return unixMsValue * kUnixMsTo100ns;
    }

    // packetTimelineTypeText：
    // - Purpose: normalize TCP/UDP and inbound/outbound directions into time-axis colors/lanes for understandable types;
    // - Parameter packetRecord: Packet to be mapped.
    // - Returns: The typeText for the timeline point, currently unified under the 'Network' swimlane.
    QString packetTimelineTypeText(const ks::network::PacketRecord& packetRecord)
    {
        (void)packetRecord;
        return QStringLiteral("网络");
    }

    // normalizeIpAddressText:
    // - Input any valid IPv4/IPv6 text;
    // - Normalizes via InetPton/InetNtop to serve as a DNS address cache key.
    // - Return empty string for invalid text.
    QString normalizeIpAddressText(const QString& addressText)
    {
        IN_ADDR ipv4Address{};
        if (InetPtonW(AF_INET, reinterpret_cast<PCWSTR>(addressText.utf16()), &ipv4Address) == 1)
        {
            wchar_t addressBuffer[INET_ADDRSTRLEN] = {};
            return InetNtopW(AF_INET, &ipv4Address, addressBuffer, static_cast<DWORD>(std::size(addressBuffer))) != nullptr
                ? QString::fromWCharArray(addressBuffer)
                : QString();
        }

        IN6_ADDR ipv6Address{};
        if (InetPtonW(AF_INET6, reinterpret_cast<PCWSTR>(addressText.utf16()), &ipv6Address) == 1)
        {
            wchar_t addressBuffer[INET6_ADDRSTRLEN] = {};
            return InetNtopW(AF_INET6, &ipv6Address, addressBuffer, static_cast<DWORD>(std::size(addressBuffer))) != nullptr
                ? QString::fromWCharArray(addressBuffer).toLower()
                : QString();
        }
        return QString();
    }

    // rebuildLocalDnsAddressMap:
    // - First enumerate names in DnsGetCacheDataTable, then read A/AAAA records using DNS_QUERY_CACHE_ONLY;
    // - Returns an IP -> domain name mapping without triggering any online DNS queries.
    // - This function is called only on a background thread.
    QHash<QString, QString> rebuildLocalDnsAddressMap()
    {
        using DnsGetCacheDataTableFn = BOOL(WINAPI*)(PVOID);
        struct DnsCacheEntryRecord
        {
            DnsCacheEntryRecord* next = nullptr;
            PWSTR name = nullptr;
            WORD type = 0;
            WORD dataLength = 0;
            DWORD flags = 0;
        };

        QHash<QString, QString> addressNameMap;
        HMODULE dnsapiModule = GetModuleHandleW(L"dnsapi.dll");
        if (dnsapiModule == nullptr)
        {
            dnsapiModule = LoadLibraryW(L"dnsapi.dll");
        }
        if (dnsapiModule == nullptr)
        {
            return addressNameMap;
        }

        const auto kDnsGetCacheDataTable = reinterpret_cast<DnsGetCacheDataTableFn>(
            GetProcAddress(dnsapiModule, "DnsGetCacheDataTable"));
        if (kDnsGetCacheDataTable == nullptr)
        {
            return addressNameMap;
        }

        DnsCacheEntryRecord rootEntry{};
        if (kDnsGetCacheDataTable(&rootEntry) == FALSE)
        {
            return addressNameMap;
        }

        int visitedNameCount = 0;
        for (DnsCacheEntryRecord* node = rootEntry.next;
            node != nullptr && visitedNameCount < 2048;
            node = node->next, ++visitedNameCount)
        {
            if (node->name == nullptr || (node->type != DNS_TYPE_A && node->type != DNS_TYPE_AAAA))
            {
                continue;
            }

            PDNS_RECORDW recordList = nullptr;
            const DNS_STATUS kQueryStatus = DnsQuery_W(
                node->name,
                node->type,
                DNS_QUERY_CACHE_ONLY,
                nullptr,
                &recordList,
                nullptr);
            if (kQueryStatus != ERROR_SUCCESS || recordList == nullptr)
            {
                continue;
            }

            const QString kDomainText = QString::fromWCharArray(node->name);
            for (PDNS_RECORDW record = recordList; record != nullptr; record = record->pNext)
            {
                wchar_t addressBuffer[INET6_ADDRSTRLEN] = {};
                PCWSTR convertedAddress = nullptr;
                if (record->wType == DNS_TYPE_A)
                {
                    convertedAddress = InetNtopW(
                        AF_INET,
                        &record->Data.A.IpAddress,
                        addressBuffer,
                        static_cast<DWORD>(std::size(addressBuffer)));
                }
                else if (record->wType == DNS_TYPE_AAAA)
                {
                    convertedAddress = InetNtopW(
                        AF_INET6,
                        record->Data.AAAA.Ip6Address.IP6Byte,
                        addressBuffer,
                        static_cast<DWORD>(std::size(addressBuffer)));
                }
                if (convertedAddress == nullptr)
                {
                    continue;
                }

                const QString kAddressKey = normalizeIpAddressText(QString::fromWCharArray(addressBuffer));
                if (!kAddressKey.isEmpty() && !addressNameMap.contains(kAddressKey))
                {
                    addressNameMap.insert(kAddressKey, kDomainText);
                }
            }
            DnsRecordListFree(recordList, DnsFreeRecordList);
        }
        return addressNameMap;
    }

    // resolveDomainNameFromLocalCache:
    // - Only query the local DNS Client cache mapping; do not send online PTR/DNS requests.
    // - Rebuild the cache in the background at most once every 30 seconds to avoid blocking the packet capture UI thread;
    // - Returns the domain name; returns an empty string if the cache misses.
    QString resolveDomainNameFromLocalCache(const QString& addressText)
    {
        const QString kAddressKey = normalizeIpAddressText(addressText);
        if (kAddressKey.isEmpty()
            || kAddressKey == QStringLiteral("0.0.0.0")
            || kAddressKey == QStringLiteral("::"))
        {
            return QString();
        }

        static std::mutex dnsCacheMutex;
        static QHash<QString, QString> localDnsAddressMap;
        static ULONGLONG lastRefreshTick = 0;
        {
            std::lock_guard<std::mutex> guard(dnsCacheMutex);
            const ULONGLONG kNowTick = GetTickCount64();
            if (lastRefreshTick == 0ULL || (kNowTick - lastRefreshTick) >= 30000ULL)
            {
                localDnsAddressMap = rebuildLocalDnsAddressMap();
                lastRefreshTick = kNowTick;
            }
            const auto kCachedIterator = localDnsAddressMap.constFind(kAddressKey);
            if (kCachedIterator != localDnsAddressMap.constEnd())
            {
                return kCachedIterator.value();
            }
        }
        return QString();
    }
}

void NetworkDock::onPacketCaptured(const ks::network::PacketRecord& packetRecord)
{
    // timelineTime100ns is the compressed time for 'monitoring only when enabled':
    // - The wait duration after stopping monitoring no longer occupies the horizontal axis.
    // - Subsequent table filtering, event points, and rate line charts all use the same compressed time.
    const std::uint64_t kTimelineTime100ns = packetTimelineTimeForRecord(packetRecord);

    // Cache packet entities: enables the details window to look up full byte content by sequence ID.
    packetSequenceOrder_.push_back(packetRecord.sequenceId);
    packetBySequence_[packetRecord.sequenceId] = packetRecord;
    packetTimelineTimeBySequence_[packetRecord.sequenceId] = kTimelineTime100ns;

    // Synchronously write lightweight timeline points:
    // - The point list saves only time and type, not the table row index.
    // - Synchronize deletion with the packet sequence number cache during trimming to avoid displaying historical points that no longer exist on the timeline.
    ProcessTraceTimelineEventPoint timelinePoint;
    timelinePoint.time100ns = kTimelineTime100ns;
    timelinePoint.typeText = packetTimelineTypeText(packetRecord);
    packetTimelineEventPoints_.push_back(std::move(timelinePoint));
    addPacketTimelineRateSample(packetRecord, kTimelineTime100ns);
    processNidsPacket(packetRecord);

    // Append the current packet to the main table only if it passes the 'combined filter conditions' (all packets pass by default when filtering is disabled).
    if (packetPassesMonitorFilter(packetRecord.sequenceId, packetRecord))
    {
        appendPacketToMonitorTable(packetRecord);
    }
    trimOldestPacketWhenNeeded();
}

void NetworkDock::flushPendingPacketsToUi()
{
    // Set a commit barrier before reading and consuming the background queue. While the menu is open, the queue continues to accumulate; after
    // it closes, only the latest flush is triggered, ensuring no packets are lost and the row corresponding to the menu remains unchanged.
    const QPointer<NetworkDock> kSafeThis(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("network-packet-stream-flush"),
        {packetTable_},
        [kSafeThis]()
        {
            if (!kSafeThis.isNull())
            {
                kSafeThis->flushPendingPacketsToUi();
            }
        }))
    {
        return;
    }

    // First transfer the pending packets to a local container within the lock to minimize lock hold time.
    std::vector<ks::network::PacketRecord> packetBatch;
    std::uint64_t droppedCountSnapshot = 0;
    // timelineIdleRefreshNeeded: Periodically advance the compression timeline even if the background queue is empty, as long as monitoring is running.
    const bool kTimelineIdleRefreshNeeded = packetTimelineSessionActive_ && monitorRunning_;
    {
        std::lock_guard<std::mutex> guard(pendingPacketMutex_);
        if (pendingPacketQueue_.empty() && droppedPacketCount_ == 0 && !kTimelineIdleRefreshNeeded)
        {
            return;
        }

        // Consume only a small batch at a time; subsequent time budgets cap the per-frame latency.
        constexpr std::size_t kMaxConsumePerTick = 160;
        const std::size_t kConsumeCount = std::min<std::size_t>(kMaxConsumePerTick, pendingPacketQueue_.size());
        packetBatch.reserve(kConsumeCount);
        for (std::size_t index = 0; index < kConsumeCount; ++index)
        {
            packetBatch.push_back(std::move(pendingPacketQueue_.front()));
            pendingPacketQueue_.pop_front();
        }

        droppedCountSnapshot = droppedPacketCount_;
    }

    // Empty traffic heartbeat:
    // - When user monitoring is enabled but no packets are received in this second, still advance the timeline right boundary.
    // - Also add a 0 B/s rate bucket so the line chart drops back to the baseline during idle seconds.
    const bool kShouldRefreshIdleTimeline = packetBatch.empty()
        && packetTimelineSessionActive_
        && monitorRunning_;
    if (kShouldRefreshIdleTimeline)
    {
        const std::uint64_t kTimelineEnd100ns = currentPacketTimelineEnd100ns();
        const std::uint64_t kHeartbeatSecond = kTimelineEnd100ns / kTimelineSecond100ns;
        packetTimelineRangeStart100ns_ = 0;
        packetTimelineRangeEnd100ns_ = std::max(kTimelineEnd100ns, kFallbackTimelineRange100ns);
        if (kHeartbeatSecond != packetTimelineLastHeartbeatSecond_)
        {
            packetTimelineLastHeartbeatSecond_ = kHeartbeatSecond;
            packetTimelineRateBucketBySecond_.try_emplace(kHeartbeatSecond, PacketTimelineRateBucket{});
            refreshPacketTimelineRange();
            refreshPacketTimelineRatePoints();
        }
        else if (packetTimelineWidget_ != nullptr
            && packetTimelineRangeEnd100ns_ > packetTimelineWidget_->selectionEnd100ns())
        {
            refreshPacketTimelineRange();
        }
    }

    // Temporarily disable repaint during batch table updates to reduce UI jitter and lag.
    const bool kTableUpdateDisabled = !packetBatch.empty() && packetTable_ != nullptr;
    const bool kTableUpdatesEnabled = kTableUpdateDisabled && packetTable_->updatesEnabled();
    if (kTableUpdateDisabled)
    {
        packetTable_->setUpdatesEnabled(false);
    }
    QElapsedTimer budgetTimer;
    budgetTimer.start();
    std::size_t processedCount = 0;
    for (const ks::network::PacketRecord& packetRecord : packetBatch)
    {
        onPacketCaptured(packetRecord);
        ++processedCount;
        if (budgetTimer.elapsed() >= 4)
        {
            break;
        }
    }

    if (kTableUpdateDisabled)
    {
        packetTable_->setUpdatesEnabled(kTableUpdatesEnabled);
        if (kTableUpdatesEnabled && packetTable_->viewport() != nullptr)
        {
            packetTable_->viewport()->update();
        }
        if (processedCount > 0)
        {
            packetTable_->scrollToBottom();
        }
    }

    if (processedCount < packetBatch.size())
    {
        std::lock_guard<std::mutex> guard(pendingPacketMutex_);
        for (std::size_t index = packetBatch.size(); index > processedCount; --index)
        {
            pendingPacketQueue_.push_front(std::move(packetBatch[index - 1]));
        }
        while (pendingPacketQueue_.size() > kMaxPendingPacketQueueCount)
        {
            pendingPacketQueue_.pop_front();
            ++droppedPacketCount_;
        }
    }

    // Refresh the timeline after batch table refreshes.
    // - redraw the timeline only once per tick to avoid high-frequency per-packet updates;
    // - If the user has already selected a time window, new packets still enter the point cache, but the table displays them filtered by the outer time range.
    if (processedCount > 0)
    {
        refreshPacketTimelineRange();
        const qint64 kNowMs = QDateTime::currentMSecsSinceEpoch();
        if ((kNowMs - lastPacketTimelineRefreshMs_) >= 250)
        {
            refreshPacketTimelinePoints();
            refreshPacketTimelineRatePoints();
            lastPacketTimelineRefreshMs_ = kNowMs;
        }
    }

    std::size_t pendingCountForInterval = 0;
    {
        std::lock_guard<std::mutex> guard(pendingPacketMutex_);
        pendingCountForInterval = pendingPacketQueue_.size();
    }
    if (packetFlushTimer_ != nullptr)
    {
        const int kTargetIntervalMs = pendingCountForInterval >= 4000
            ? 80
            : (pendingCountForInterval > 0 ? 50 : 120);
        if (packetFlushTimer_->interval() != kTargetIntervalMs)
        {
            packetFlushTimer_->setInterval(kTargetIntervalMs);
        }
    }

    // Drop count is displayed only on the UI thread, not flushed in every callback.
    if (droppedCountSnapshot > 0 && monitorStatusLabel_ != nullptr)
    {
        const std::size_t kPendingCount = pendingCountForInterval;
        monitorStatusLabel_->setText(QStringLiteral("状态：高负载（已丢弃%1条，队列%2）")
            .arg(static_cast<qulonglong>(droppedCountSnapshot))
            .arg(static_cast<qulonglong>(kPendingCount)));

        // Log dropped packet status at least once to help users investigate why the table appears to show fewer packets.
        // Output based on count changes to avoid flooding the screen on every refresh tick.
        static std::uint64_t sLastLoggedDroppedCount = 0;
        if (droppedCountSnapshot != sLastLoggedDroppedCount)
        {
            sLastLoggedDroppedCount = droppedCountSnapshot;

            KLogEvent droppedPacketEvent;
            warn << droppedPacketEvent
                << "[NetworkDock] 抓包队列高负载丢包, dropped=" << droppedCountSnapshot
                << ", pending=" << kPendingCount
                << eol;
        }
    }
}

void NetworkDock::onStatusMessageArrived(const std::string& statusText)
{
    // R0 mode does not accept stopped R3 service callback overrides for source state.
    if (monitorSource_ == TrafficMonitorSource::kR0
        || monitorSource_ == TrafficMonitorSource::kStarting)
    {
        return;
    }

    const QString kStatusQString = toQString(statusText);
    if (monitorStatusLabel_ != nullptr)
    {
        monitorStatusLabel_->setText(
            QStringLiteral("状态：来源 R3；%1").arg(kStatusQString));
    }

    // Status callbacks may indicate startup failure or thread exit, so synchronously refresh the button state.
    const bool kWasMonitorRunning = monitorRunning_;
    if (trafficService_ != nullptr)
    {
        monitorRunning_ = trafficService_->isRunning();
    }
    if (kWasMonitorRunning && !monitorRunning_ && packetTimelineSessionActive_)
    {
        // If the background thread exits on its own due to an error or external condition, the timeline session must also be closed.
        // Otherwise, subsequent wait times would be incorrectly counted toward 'monitor active duration'.
        endPacketTimelineMonitorSession();
    }
    if (!monitorRunning_)
    {
        monitorSource_ = TrafficMonitorSource::kStopped;
    }
    updateMonitorButtonState();

    KLogEvent statusEvent;
    info << statusEvent << "[NetworkDock] 抓包状态: " << statusText << eol;
}

void NetworkDock::onRateLimitActionArrived(const ks::network::RateLimitActionEvent& actionEvent)
{
    // Append the rate-limiting action as a time-stamped log entry to the log box to facilitate troubleshooting why a specific process was suspended or resumed.
    const QString kTimeText = QDateTime::fromMSecsSinceEpoch(
        static_cast<qint64>(actionEvent.timestampMs)).toString("HH:mm:ss.zzz");
    const QString kActionText = toQString(ks::network::rateLimitActionTypeToString(actionEvent.actionType));
    const QString kResultText = actionEvent.actionSucceeded ? QStringLiteral("成功") : QStringLiteral("失败");
    const QString kLogLine = QStringLiteral("[%1] PID=%2, 动作=%3, 结果=%4, 详情=%5")
        .arg(kTimeText)
        .arg(actionEvent.processId)
        .arg(kActionText)
        .arg(kResultText)
        .arg(toQString(actionEvent.detailText));
    appendRateLimitActionLogLine(kLogLine);

    // Refresh the table immediately only when the rate limit page is visible to avoid triggering unnecessary repaints from hidden page events.
    if (sideTabWidget_ != nullptr && sideTabWidget_->currentWidget() == rateLimitPage_)
    {
        refreshRateLimitTable();
    }

    // Action events use the warn level to make them stand out in the log panel.
    KLogEvent actionEventLog;
    warn << actionEventLog
        << "[NetworkDock] 限速动作, pid=" << actionEvent.processId
        << ", action=" << ks::network::rateLimitActionTypeToString(actionEvent.actionType)
        << ", ok=" << (actionEvent.actionSucceeded ? "true" : "false")
        << ", detail=" << actionEvent.detailText
        << eol;
}

void NetworkDock::appendPacketToMonitorTable(const ks::network::PacketRecord& packetRecord)
{
    if (packetTable_ == nullptr)
    {
        return;
    }

    // For the append scenario, use direct 'rowCount' expansion instead of insertRow:
    // - insertRow triggers subsequent row shifts.
    // - setRowCount is lighter when appending at the end, suitable for high-frequency write scenarios.
    const int kNewRow = packetTable_->rowCount();
    packetTable_->setRowCount(kNewRow + 1);
    scheduleDomainResolutionForPacket(
        packetRecord.sequenceId,
        toQString(packetRecord.remoteAddress));
    const auto kCachedPacketIterator = packetBySequence_.find(packetRecord.sequenceId);
    const ks::network::PacketRecord& displayRecord = kCachedPacketIterator != packetBySequence_.end()
        ? kCachedPacketIterator->second
        : packetRecord;

    // Process icon resolution must yield to the 50ms batch refresh frame budget:
    // - Reuse directly when the PID cache is hit, achieving zero overhead in steady state.
    // - On miss, first place a placeholder icon, then offload queryProcessPathByPid + Shell icon extraction to the thread pool; upon
    //   result return, backfill the already-placed rows by PID, following the same pattern as asynchronous remote domain completion.
    const quint32 kProcessIdKey = static_cast<quint32>(displayRecord.processId);
    QIcon processIcon = packetProcessPlaceholderIcon();
    const auto kProcessIconCacheIterator = processIconCacheByPid_.constFind(kProcessIdKey);
    if (kProcessIconCacheIterator != processIconCacheByPid_.constEnd())
    {
        processIcon = kProcessIconCacheIterator.value();
    }
    else if (kProcessIdKey != 0U)
    {
        QSet<quint32>& pendingIconPidSet = gPendingPacketProcessIconPidMap[this];
        if (!pendingIconPidSet.contains(kProcessIdKey))
        {
            pendingIconPidSet.insert(kProcessIdKey);

            // ownerKey: Used solely as an identity marker (never dereferenced) to ensure the host can still be located and in-flight collections cleaned up after the host is destructed.
            const QPointer<NetworkDock> kGuardedSelf(this);
            const NetworkDock* const kOwnerKey = this;
            const int kProcessIdColumn = toPacketColumn(PacketTableColumn::kPid);
            const int kProcessNameColumn = toPacketColumn(PacketTableColumn::kProcessName);
            QThreadPool::globalInstance()->start(
                [kGuardedSelf, kOwnerKey, kProcessIdKey, kProcessIdColumn, kProcessNameColumn]()
                {
                    QImage processIconImage = extractProcessIconImageForPid(kProcessIdKey);
                    QCoreApplication* const kAppInstance = QCoreApplication::instance();
                    if (kAppInstance == nullptr)
                    {
                        return;
                    }
                    QMetaObject::invokeMethod(
                        kAppInstance,
                        [kGuardedSelf,
                            kOwnerKey,
                            kProcessIdKey,
                            kProcessIdColumn,
                            kProcessNameColumn,
                            processIconImage = std::move(processIconImage)]() mutable
                        {
                            // Remove the in-flight marker regardless of whether the host is alive to prevent residual entries from permanently blocking PID resolution.
                            const auto kPendingIterator = gPendingPacketProcessIconPidMap.find(kOwnerKey);
                            if (kPendingIterator != gPendingPacketProcessIconPidMap.end())
                            {
                                kPendingIterator->second.remove(kProcessIdKey);
                                if (kPendingIterator->second.isEmpty())
                                {
                                    gPendingPacketProcessIconPidMap.erase(kPendingIterator);
                                }
                            }
                            if (kGuardedSelf == nullptr)
                            {
                                return;
                            }

                            // QPixmap/QIcon can only be constructed on the UI thread; background threads must return QImage.
                            const QIcon kResolvedIcon = processIconImage.isNull()
                                ? packetProcessPlaceholderIcon()
                                : QIcon(QPixmap::fromImage(processIconImage));
                            kGuardedSelf->processIconCacheByPid_.insert(kProcessIdKey, kResolvedIcon);
                            applyResolvedProcessIconToPacketRows(
                                kGuardedSelf->packetTable_,
                                kProcessIdColumn,
                                kProcessNameColumn,
                                kProcessIdKey,
                                kResolvedIcon);
                        },
                        Qt::QueuedConnection);
                });
        }
    }

    populatePacketRow(
        packetTable_,
        kNewRow,
        displayRecord,
        displayRecord.sequenceId,
        processIcon);
}

void NetworkDock::scheduleDomainResolutionForPacket(
    const std::uint64_t sequenceId,
    const QString& remoteAddressText)
{
    const QString kAddressKey = normalizeIpAddressText(remoteAddressText);
    if (kAddressKey.isEmpty()
        || kAddressKey == QStringLiteral("0.0.0.0")
        || kAddressKey == QStringLiteral("::"))
    {
        auto packetIterator = packetBySequence_.find(sequenceId);
        if (packetIterator != packetBySequence_.end())
        {
            packetIterator->second.remoteDomain = "-";
        }
        return;
    }

    const auto kCachedIterator = remoteDomainCache_.constFind(kAddressKey);
    if (kCachedIterator != remoteDomainCache_.constEnd())
    {
        auto packetIterator = packetBySequence_.find(sequenceId);
        if (packetIterator != packetBySequence_.end())
        {
            packetIterator->second.remoteDomain = kCachedIterator.value().toUtf8().constData();
        }
        return;
    }
    if (remoteDomainResolutionPending_.contains(kAddressKey))
    {
        return;
    }
    remoteDomainResolutionPending_.insert(kAddressKey);

    QPointer<NetworkDock> safeThis(this);
    QThreadPool::globalInstance()->start([safeThis, kAddressKey]()
    {
        const QString kDomainText = resolveDomainNameFromLocalCache(kAddressKey);
        if (safeThis.isNull())
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis.data(),
            [safeThis, kAddressKey, kDomainText]()
            {
                if (!safeThis.isNull())
                {
                    safeThis->applyDomainResolutionResult(kAddressKey, kDomainText);
                }
            },
            Qt::QueuedConnection);
    });
}

void NetworkDock::applyDomainResolutionResult(
    const QString& remoteAddressText,
    const QString& domainText)
{
    const QString kAddressKey = normalizeIpAddressText(remoteAddressText);
    if (kAddressKey.isEmpty())
    {
        return;
    }

    const QString kDisplayText = domainText.trimmed().isEmpty()
        ? QStringLiteral("-")
        : domainText.trimmed();

    const QPointer<NetworkDock> kSafeThis(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("network-domain-resolution:%1").arg(kAddressKey),
            {packetTable_},
            [kSafeThis, kAddressKey, kDisplayText]()
            {
                if (!kSafeThis.isNull())
                {
                    kSafeThis->applyDomainResolutionResult(kAddressKey, kDisplayText);
                }
            }))
    {
        return;
    }

    remoteDomainResolutionPending_.remove(kAddressKey);
    remoteDomainCache_.insert(kAddressKey, kDisplayText);
    if (remoteDomainCache_.size() > 4096)
    {
        remoteDomainCache_.erase(remoteDomainCache_.begin());
    }

    for (auto& packetPair : packetBySequence_)
    {
        if (normalizeIpAddressText(toQString(packetPair.second.remoteAddress)) == kAddressKey)
        {
            packetPair.second.remoteDomain = kDisplayText.toUtf8().constData();
        }
    }

    if (packetTable_ == nullptr)
    {
        return;
    }
    const int kDomainColumn = toPacketColumn(PacketTableColumn::kRemoteDomain);
    for (int rowIndex = 0; rowIndex < packetTable_->rowCount(); ++rowIndex)
    {
        QTableWidgetItem* domainItem = packetTable_->item(rowIndex, kDomainColumn);
        if (domainItem == nullptr)
        {
            continue;
        }
        if (normalizeIpAddressText(domainItem->data(Qt::UserRole).toString()) == kAddressKey)
        {
            domainItem->setText(kDisplayText);
        }
    }
}

void NetworkDock::rebuildMonitorTableByFilter()
{
    if (packetTable_ == nullptr)
    {
        return;
    }

    const QPointer<NetworkDock> kSafeThis(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("network-packet-filter-rebuild"),
        {packetTable_},
        [kSafeThis]()
        {
            if (!kSafeThis.isNull())
            {
                kSafeThis->rebuildMonitorTableByFilter();
            }
        }))
    {
        return;
    }

    // First collect the list of records passing the filter, then call setRowCount once to reduce the overhead of repeated insertRow calls.
    std::vector<const ks::network::PacketRecord*> visibleRecordList;
    visibleRecordList.reserve(packetSequenceOrder_.size());
    for (const std::uint64_t kSequenceId : packetSequenceOrder_)
    {
        const auto kIterator = packetBySequence_.find(kSequenceId);
        if (kIterator == packetBySequence_.end())
        {
            continue;
        }
        const ks::network::PacketRecord& packetRecord = kIterator->second;
        if (!packetPassesMonitorFilter(kSequenceId, packetRecord))
        {
            continue;
        }
        visibleRecordList.push_back(&packetRecord);
    }

    packetTable_->setUpdatesEnabled(false);
    packetTable_->setRowCount(static_cast<int>(visibleRecordList.size()));

    int writeRow = 0;
    for (const ks::network::PacketRecord* packetRecordPtr : visibleRecordList)
    {
        if (packetRecordPtr == nullptr)
        {
            continue;
        }

        const std::uint64_t kSequenceId = packetRecordPtr->sequenceId;
        scheduleDomainResolutionForPacket(
            kSequenceId,
            toQString(packetRecordPtr->remoteAddress));
        const auto kCachedPacketIterator = packetBySequence_.find(kSequenceId);
        const ks::network::PacketRecord& displayRecord =
            kCachedPacketIterator != packetBySequence_.end()
                ? kCachedPacketIterator->second
                : *packetRecordPtr;
        const QIcon kProcessIcon = resolveProcessIconByPid(
            displayRecord.processId,
            displayRecord.processName);
        populatePacketRow(
            packetTable_,
            writeRow,
            displayRecord,
            displayRecord.sequenceId,
            kProcessIcon);
        ++writeRow;
    }

    packetTable_->setUpdatesEnabled(true);
    if (writeRow > 0)
    {
        packetTable_->scrollToBottom();
    }
}

void NetworkDock::applyPacketTimelineSelection(
    const std::uint64_t start100ns,
    const std::uint64_t end100ns)
{
    // The timeline control converts mouse drag selection into timestamps; NetworkDock only saves the range and rebuilds the table.
    packetTimelineSelectionStart100ns_ = std::min(start100ns, end100ns);
    packetTimelineSelectionEnd100ns_ = std::max(start100ns, end100ns);
    packetTimelineUserSelectionActive_ = true;

    updateMonitorFilterStateLabel();
    rebuildMonitorTableByFilter();

    KLogEvent timelineEvent;
    dbg << timelineEvent
        << "[NetworkDock] 流量时间轴选区变更, start100ns="
        << packetTimelineSelectionStart100ns_
        << ", end100ns="
        << packetTimelineSelectionEnd100ns_
        << eol;
}

void NetworkDock::resetPacketTimelineToCurrentRange()
{
    // After clearing or filtering, reset the timeline to the default full range to prevent old selections from affecting the next packet capture.
    packetTimelineUserSelectionActive_ = false;
    packetTimelineSelectionStart100ns_ = 0;
    packetTimelineSelectionEnd100ns_ = 0;
    packetTimelineRangeStart100ns_ = 0;
    packetTimelineRangeEnd100ns_ = currentPacketTimelineEnd100ns();
    if (packetTimelineRangeEnd100ns_ == 0)
    {
        packetTimelineRangeEnd100ns_ = kFallbackTimelineRange100ns;
    }

    if (packetTimelineWidget_ != nullptr)
    {
        packetTimelineWidget_->resetTimeline(0);
        packetTimelineWidget_->setCaptureRange(
            packetTimelineRangeStart100ns_,
            packetTimelineRangeEnd100ns_);
        packetTimelineSelectionStart100ns_ = packetTimelineWidget_->selectionStart100ns();
        packetTimelineSelectionEnd100ns_ = packetTimelineWidget_->selectionEnd100ns();
        packetTimelineWidget_->setEventPoints(packetTimelineEventPoints_);
    }
    refreshPacketTimelineRatePoints();
}

void NetworkDock::refreshPacketTimelineRange()
{
    if (packetTimelineWidget_ == nullptr)
    {
        return;
    }

    std::uint64_t rangeStart100ns = 0;
    // The current cumulative monitoring duration is always not earlier than the compressed timestamp of cached packets;
    // therefore, there is no need to scan the entire packet cache to recalculate the right boundary in each refresh cycle.
    std::uint64_t rangeEnd100ns = currentPacketTimelineEnd100ns();

    if (rangeEnd100ns == 0)
    {
        // When no packets are present and monitoring has not started, use a 0~1 second empty timeline.
        rangeEnd100ns = kFallbackTimelineRange100ns;
    }

    if (rangeEnd100ns <= rangeStart100ns)
    {
        rangeEnd100ns = rangeStart100ns + kFallbackTimelineRange100ns;
    }

    packetTimelineRangeStart100ns_ = rangeStart100ns;
    packetTimelineRangeEnd100ns_ = rangeEnd100ns;
    packetTimelineWidget_->setCaptureRange(rangeStart100ns, rangeEnd100ns);
    packetTimelineSelectionStart100ns_ = packetTimelineWidget_->selectionStart100ns();
    packetTimelineSelectionEnd100ns_ = packetTimelineWidget_->selectionEnd100ns();
}

void NetworkDock::refreshPacketTimelinePoints()
{
    if (packetTimelineWidget_ == nullptr)
    {
        return;
    }

    packetTimelineWidget_->setEventPoints(packetTimelineEventPoints_);
}

void NetworkDock::refreshPacketTimelineRatePoints()
{
    if (packetTimelineWidget_ == nullptr)
    {
        return;
    }
    if (packetTimelineRangeEnd100ns_ <= packetTimelineRangeStart100ns_)
    {
        packetTimelineRangeStart100ns_ = 0;
        packetTimelineRangeEnd100ns_ = std::max(
            currentPacketTimelineEnd100ns(),
            kFallbackTimelineRange100ns);
    }

    // Organize the unordered_map snapshot into line chart points sorted by second in ascending order:
    // - X-axis uses second bucket start points;
    // - The Y value is the cumulative bytes for that second, equivalent to B/s.
    const std::uint64_t kVisibleEndSecond = packetTimelineRangeEnd100ns_ / kTimelineSecond100ns;
    std::vector<std::uint64_t> secondIndexList;
    secondIndexList.reserve(packetTimelineRateBucketBySecond_.size() + 2);
    for (const auto& bucketPair : packetTimelineRateBucketBySecond_)
    {
        secondIndexList.push_back(bucketPair.first);
    }
    secondIndexList.push_back(0);
    secondIndexList.push_back(kVisibleEndSecond);
    std::sort(secondIndexList.begin(), secondIndexList.end());
    secondIndexList.erase(
        std::unique(secondIndexList.begin(), secondIndexList.end()),
        secondIndexList.end());

    std::vector<ProcessTraceTimelineRatePoint> ratePointList;
    ratePointList.reserve(secondIndexList.size());
    for (const std::uint64_t kSecondIndex : secondIndexList)
    {
        const auto kIterator = packetTimelineRateBucketBySecond_.find(kSecondIndex);

        ProcessTraceTimelineRatePoint ratePoint;
        ratePoint.time100ns = kSecondIndex * kTimelineSecond100ns;
        if (kIterator != packetTimelineRateBucketBySecond_.end())
        {
            ratePoint.uploadBytesPerSecond = static_cast<double>(kIterator->second.uploadBytes);
            ratePoint.downloadBytesPerSecond = static_cast<double>(kIterator->second.downloadBytes);
        }
        ratePointList.push_back(ratePoint);
    }

    packetTimelineWidget_->setRateOverlayPoints(ratePointList);
}

bool NetworkDock::isPacketTimelineFilterActive() const
{
    if (!packetTimelineUserSelectionActive_
        || packetTimelineSelectionEnd100ns_ == 0
        || packetTimelineSelectionEnd100ns_ <= packetTimelineSelectionStart100ns_)
    {
        return false;
    }

    if (packetTimelineRangeEnd100ns_ <= packetTimelineRangeStart100ns_)
    {
        return false;
    }

    // A full-range selection is not treated as a filter; this ensures real-time packet capture defaults to continuously displaying new packets.
    return packetTimelineSelectionStart100ns_ > packetTimelineRangeStart100ns_
        || packetTimelineSelectionEnd100ns_ < packetTimelineRangeEnd100ns_;
}

bool NetworkDock::packetPassesTimelineFilter(const ks::network::PacketRecord& packetRecord) const
{
    if (!isPacketTimelineFilterActive())
    {
        return true;
    }

    const std::uint64_t kPacketTime100ns = packetTimelineTimeForRecord(packetRecord);
    return kPacketTime100ns >= packetTimelineSelectionStart100ns_
        && kPacketTime100ns <= packetTimelineSelectionEnd100ns_;
}

bool NetworkDock::packetPassesTimelineFilter(
    const std::uint64_t sequenceId,
    const ks::network::PacketRecord& packetRecord) const
{
    if (!isPacketTimelineFilterActive())
    {
        return true;
    }

    const std::uint64_t kPacketTime100ns = packetTimelineTimeForSequence(sequenceId, packetRecord);
    return kPacketTime100ns >= packetTimelineSelectionStart100ns_
        && kPacketTime100ns <= packetTimelineSelectionEnd100ns_;
}

void NetworkDock::beginPacketTimelineMonitorSession()
{
    // Do not register again if an active session exists to avoid cumulative time misalignment caused by double-clicking the start button.
    if (packetTimelineSessionActive_)
    {
        return;
    }

    // If the previous session is still in the 'unclosed' state, close it using the current time first.
    // This ensures that even if callback ordering is abnormal, the downtime interval does not mix into the next monitoring duration.
    if (!packetTimelineSessionList_.empty()
        && packetTimelineSessionList_.back().endUnixMs == 0)
    {
        PacketTimelineCaptureSession& previousSession = packetTimelineSessionList_.back();
        previousSession.endUnixMs = static_cast<std::uint64_t>(QDateTime::currentMSecsSinceEpoch());
        const std::uint64_t kPreviousDurationMs = previousSession.endUnixMs > previousSession.startUnixMs
            ? (previousSession.endUnixMs - previousSession.startUnixMs)
            : 0;
        packetTimelineAccumulatedActive100ns_ =
            previousSession.baseStart100ns + unixMsToTimeline100ns(kPreviousDurationMs);
    }

    PacketTimelineCaptureSession session;
    session.startUnixMs = static_cast<std::uint64_t>(QDateTime::currentMSecsSinceEpoch());
    session.endUnixMs = 0;
    session.baseStart100ns = packetTimelineAccumulatedActive100ns_;
    packetTimelineSessionList_.push_back(session);
    packetTimelineSessionActive_ = true;
    packetTimelineLastHeartbeatSecond_ = session.baseStart100ns / kTimelineSecond100ns;

    refreshPacketTimelineRange();
    refreshPacketTimelineRatePoints();
}

void NetworkDock::endPacketTimelineMonitorSession()
{
    if (!packetTimelineSessionActive_ || packetTimelineSessionList_.empty())
    {
        return;
    }

    PacketTimelineCaptureSession& session = packetTimelineSessionList_.back();
    if (session.endUnixMs == 0)
    {
        session.endUnixMs = static_cast<std::uint64_t>(QDateTime::currentMSecsSinceEpoch());
    }

    const std::uint64_t kSessionDurationMs = session.endUnixMs > session.startUnixMs
        ? (session.endUnixMs - session.startUnixMs)
        : 0;
    packetTimelineAccumulatedActive100ns_ =
        session.baseStart100ns + unixMsToTimeline100ns(kSessionDurationMs);
    packetTimelineSessionActive_ = false;
    packetTimelineLastHeartbeatSecond_ = packetTimelineAccumulatedActive100ns_ / kTimelineSecond100ns;

    refreshPacketTimelineRange();
    refreshPacketTimelineRatePoints();
}

void NetworkDock::resetPacketTimelineClockForCurrentState()
{
    // wasRunning usage: captures the current running state before clearing the session list to avoid misjudgment after the state is cleared below.
    const bool kWasRunning = monitorRunning_
        || (trafficService_ != nullptr && trafficService_->isRunning());

    // Clearing packets signifies the start of a new logical timeline:
    // - Discard historical sessions and packets.
    // - If the user is currently monitoring, immediately re-register active sessions starting from 0 seconds.
    packetTimelineSessionList_.clear();
    packetTimelineTimeBySequence_.clear();
    packetTimelineRateBucketBySecond_.clear();
    packetTimelineAccumulatedActive100ns_ = 0;
    packetTimelineLastHeartbeatSecond_ = 0;
    packetTimelineSessionActive_ = false;

    if (kWasRunning)
    {
        beginPacketTimelineMonitorSession();
    }
}

std::uint64_t NetworkDock::packetTimelineTimeForRecord(const ks::network::PacketRecord& packetRecord) const
{
    if (packetRecord.captureTimestampMs == 0)
    {
        return currentPacketTimelineEnd100ns();
    }

    if (packetTimelineSessionList_.empty()
        && packetTimelineSessionActive_
        && packetTimelineAccumulatedActive100ns_ == 0)
    {
        // Theoretically, beginPacketTimelineMonitorSession registers the session first.
        // If an abnormal order results in an empty list, place the packet at the 0-second position, still without using real system time.
        return 0;
    }

    for (const PacketTimelineCaptureSession& session : packetTimelineSessionList_)
    {
        const std::uint64_t kSessionEndUnixMs = session.endUnixMs == 0
            ? std::max<std::uint64_t>(
                packetRecord.captureTimestampMs,
                static_cast<std::uint64_t>(QDateTime::currentMSecsSinceEpoch()))
            : session.endUnixMs;
        if (packetRecord.captureTimestampMs < session.startUnixMs
            || packetRecord.captureTimestampMs > kSessionEndUnixMs)
        {
            continue;
        }

        const std::uint64_t kElapsedMs = packetRecord.captureTimestampMs > session.startUnixMs
            ? (packetRecord.captureTimestampMs - session.startUnixMs)
            : 0;
        return session.baseStart100ns + unixMsToTimeline100ns(kElapsedMs);
    }

    if (packetTimelineSessionActive_ && !packetTimelineSessionList_.empty())
    {
        // In rare cases, packets may arrive before the UI registers the session (thread startup race):
        // - Assign to the start of the current active session, not the current time;
        // - This prevents the first batch of packets from being pushed to the right boundary, which would cause an instantaneous rate spike.
        return packetTimelineSessionList_.back().baseStart100ns;
    }

    // Late packets arriving after stopping are appended to the cumulative end to prevent them from falling into real system time and causing X-axis jumps.
    return currentPacketTimelineEnd100ns();
}

std::uint64_t NetworkDock::packetTimelineTimeForSequence(
    const std::uint64_t sequenceId,
    const ks::network::PacketRecord& packetRecord) const
{
    const auto kIterator = packetTimelineTimeBySequence_.find(sequenceId);
    if (kIterator != packetTimelineTimeBySequence_.end())
    {
        return kIterator->second;
    }
    return packetTimelineTimeForRecord(packetRecord);
}

std::uint64_t NetworkDock::currentPacketTimelineEnd100ns() const
{
    if (packetTimelineSessionActive_ && !packetTimelineSessionList_.empty())
    {
        const PacketTimelineCaptureSession& session = packetTimelineSessionList_.back();
        const std::uint64_t kNowUnixMs = static_cast<std::uint64_t>(QDateTime::currentMSecsSinceEpoch());
        const std::uint64_t kElapsedMs = kNowUnixMs > session.startUnixMs
            ? (kNowUnixMs - session.startUnixMs)
            : 0;
        return session.baseStart100ns + unixMsToTimeline100ns(kElapsedMs);
    }

    return packetTimelineAccumulatedActive100ns_;
}

void NetworkDock::addPacketTimelineRateSample(
    const ks::network::PacketRecord& packetRecord,
    const std::uint64_t timelineTime100ns)
{
    const std::uint64_t kSecondIndex = timelineTime100ns / kTimelineSecond100ns;
    PacketTimelineRateBucket& bucket = packetTimelineRateBucketBySecond_[kSecondIndex];

    if (packetRecord.direction == ks::network::PacketDirection::kOutbound)
    {
        bucket.uploadBytes += packetRecord.totalPacketSize;
    }
    else if (packetRecord.direction == ks::network::PacketDirection::kInbound)
    {
        bucket.downloadBytes += packetRecord.totalPacketSize;
    }
}

void NetworkDock::removePacketTimelineRateSample(
    const ks::network::PacketRecord& packetRecord,
    const std::uint64_t timelineTime100ns)
{
    const std::uint64_t kSecondIndex = timelineTime100ns / kTimelineSecond100ns;
    const auto kIterator = packetTimelineRateBucketBySecond_.find(kSecondIndex);
    if (kIterator == packetTimelineRateBucketBySecond_.end())
    {
        return;
    }

    PacketTimelineRateBucket& bucket = kIterator->second;
    if (packetRecord.direction == ks::network::PacketDirection::kOutbound)
    {
        bucket.uploadBytes = bucket.uploadBytes > packetRecord.totalPacketSize
            ? bucket.uploadBytes - packetRecord.totalPacketSize
            : 0;
    }
    else if (packetRecord.direction == ks::network::PacketDirection::kInbound)
    {
        bucket.downloadBytes = bucket.downloadBytes > packetRecord.totalPacketSize
            ? bucket.downloadBytes - packetRecord.totalPacketSize
            : 0;
    }

    if (bucket.uploadBytes == 0 && bucket.downloadBytes == 0 && !packetTimelineSessionActive_)
    {
        packetTimelineRateBucketBySecond_.erase(kIterator);
    }
}

void NetworkDock::trimOldestPacketWhenNeeded()
{
    if (packetSequenceOrder_.size() <= kMaxPacketCacheCount)
    {
        return;
    }

    // Batch trimming strategy:
    // - Avoid continuous O(n) row shifts caused by calling removeRow(0) for every incoming packet.
    // - Changed to remove a batch at once after accumulating to the threshold, significantly reducing UI jitter and lag.
    constexpr std::size_t kTrimBatchCount = 320;
    const std::size_t kOverflowCount = packetSequenceOrder_.size() - kMaxPacketCacheCount;

    // Only perform batch trimming when the overflow count reaches the batch threshold
    // to avoid frequent reordering triggered by exceeding the limit by just 1 packet.
    if (kOverflowCount < kTrimBatchCount &&
        packetSequenceOrder_.size() < (kMaxPacketCacheCount + kTrimBatchCount))
    {
        return;
    }

    const std::size_t kTrimCount = std::max<std::size_t>(kOverflowCount, kTrimBatchCount);

    std::size_t visibleTrimCount = 0;
    std::size_t timelineTrimCount = 0;
    for (std::size_t trimIndex = 0; trimIndex < kTrimCount; ++trimIndex)
    {
        if (packetSequenceOrder_.empty())
        {
            break;
        }

        const std::uint64_t kOldestSequenceId = packetSequenceOrder_.front();
        packetSequenceOrder_.pop_front();
        ++timelineTrimCount;

        const auto kOldestIterator = packetBySequence_.find(kOldestSequenceId);
        if (kOldestIterator == packetBySequence_.end())
        {
            packetTimelineTimeBySequence_.erase(kOldestSequenceId);
            continue;
        }

        const std::uint64_t kTimelineTime100ns =
            packetTimelineTimeForSequence(kOldestSequenceId, kOldestIterator->second);
        removePacketTimelineRateSample(kOldestIterator->second, kTimelineTime100ns);
        packetTimelineTimeBySequence_.erase(kOldestSequenceId);

        if (packetPassesMonitorFilter(kOldestSequenceId, kOldestIterator->second))
        {
            ++visibleTrimCount;
        }
        packetBySequence_.erase(kOldestIterator);
    }

    const std::size_t kTimelineEraseCount = std::min(timelineTrimCount, packetTimelineEventPoints_.size());
    if (kTimelineEraseCount > 0)
    {
        packetTimelineEventPoints_.erase(
            packetTimelineEventPoints_.begin(),
            packetTimelineEventPoints_.begin() + static_cast<std::ptrdiff_t>(kTimelineEraseCount));
    }

    // Only remove rows if the table actually has visible trim to reduce unnecessary UI operations.
    if (visibleTrimCount > 0 && packetTable_ != nullptr && packetTable_->rowCount() > 0)
    {
        const int kRemoveRows = std::min<int>(static_cast<int>(visibleTrimCount), packetTable_->rowCount());
        const bool kUpdatesEnabled = packetTable_->updatesEnabled();
        packetTable_->setUpdatesEnabled(false);
        if (packetTable_->model() != nullptr)
        {
            packetTable_->model()->removeRows(0, kRemoveRows);
        }
        packetTable_->setUpdatesEnabled(kUpdatesEnabled);

        KLogEvent trimEvent;
        dbg << trimEvent
            << "[NetworkDock] 报文缓存批量裁剪, trimCount=" << kTrimCount
            << ", visibleTrimCount=" << visibleTrimCount
            << ", remainCache=" << packetSequenceOrder_.size()
            << eol;
    }

    refreshPacketTimelineRange();
    refreshPacketTimelinePoints();
    refreshPacketTimelineRatePoints();
}

void NetworkDock::clearAllPacketRows()
{
    const QPointer<NetworkDock> kSafeThis(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("network-packet-clear"),
        {packetTable_, nidsAlertTable_},
        [kSafeThis]()
        {
            if (!kSafeThis.isNull())
            {
                kSafeThis->clearAllPacketRows();
            }
        }))
    {
        return;
    }

    // Clear the background refresh queue simultaneously to avoid 'just cleared, then refilled with old data'.
    {
        std::lock_guard<std::mutex> guard(pendingPacketMutex_);
        pendingPacketQueue_.clear();
        droppedPacketCount_ = 0;
    }

    packetSequenceOrder_.clear();
    packetBySequence_.clear();
    packetTimelineEventPoints_.clear();
    lastPacketTimelineRefreshMs_ = 0;
    clearNidsAlerts();
    resetPacketTimelineClockForCurrentState();
    resetPacketTimelineToCurrentRange();
    refreshPacketTimelinePoints();
    refreshPacketTimelineRatePoints();
    updateMonitorFilterStateLabel();

    if (packetTable_ != nullptr)
    {
        packetTable_->setRowCount(0);
    }

    KLogEvent clearEvent;
    info << clearEvent << "[NetworkDock] 用户清空了网络报文列表。" << eol;
}
