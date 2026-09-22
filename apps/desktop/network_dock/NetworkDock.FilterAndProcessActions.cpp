#include "NetworkDock.InternalCommon.h"
#include "../ui/VisibleTableWidget.h"

#include <QCompleter>
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFrame>
#include <QHash>
#include <QHeaderView>
#include <QImage>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QPixmap>
#include <QRegularExpression>
#include <QSet>
#include <QSignalBlocker>
#include <QStandardItem>
#include <QStandardItemModel>

#include <algorithm>
#include <string>
#include <unordered_map>
#include <utility>

#include <objbase.h>
#include <Shellapi.h>

using namespace network_dock_detail;

namespace
{
    // kMaxMonitorProcessIconExtractPerRound：
    // - Maximum number of icons to extract per background round.
    // - During the first refresh, there may be 300+ processes in the system. Performing a full cold lookup of Shell icons for all
    //   of them at once would occupy the thread pool for a long time; the excess is left for subsequent refresh rounds to complete.
    constexpr int kMaxMonitorProcessIconExtractPerRound = 128;

    // MonitorProcessCandidateSnapshotItem：
    // - Raw process candidate data produced by background threads, containing only value types safe for cross-thread transfer.
    // - QIcon/QPixmap never appear here; icons are constructed as bitmaps by the UI thread.
    struct MonitorProcessCandidateSnapshotItem
    {
        std::uint32_t pid = 0; // Process PID.
        QString processName;   // Process name (whitespace removed).
    };

    // MonitorProcessCandidateRefreshState：
    // - Asynchronous refresh scheduling state for the process candidate cache;
    // - latestRequestGeneration is used to discard old results superseded by new requests.
    // - refreshInFlight ensures only one background enumeration task runs at a time.
    struct MonitorProcessCandidateRefreshState
    {
        quint64 latestRequestGeneration = 0;
        bool refreshInFlight = false;
    };

    // g_monitorProcessCandidateRefreshStateMap：
    // - Save the scheduling state above per NetworkDock instance;
    // - Read/write operations occur exclusively on the UI thread (dispatch and re-injection points are both on the UI thread), so no locking is required.
    // - The key serves only as an identity identifier and is never dereferenced; it is cleaned up by the rollback branch after the host is destructed.
    std::unordered_map<const NetworkDock*, MonitorProcessCandidateRefreshState>
        gMonitorProcessCandidateRefreshStateMap;

    // monitorProcessPlaceholderIcon:
    // - Returns a unified placeholder icon for the process candidate dropdown; used as a placeholder until the real icon is resolved.
    // - Parameters: None;
    // - Returns: a shared QIcon reference, usable only on the UI thread.
    const QIcon& monitorProcessPlaceholderIcon()
    {
        static const QIcon kPlaceholderIcon(QStringLiteral(":/Icon/process_main.svg"));
        return kPlaceholderIcon;
    }

    // collectMonitorProcessCandidateSnapshot:
    // - Perform a system process enumeration once in a thread pool worker thread, outputting only PIDs and process names.
    // - enumerateProcesses internally fetches a global handle snapshot and PDH GPU counters; it must run off the UI thread.
    // - Parameters: None;
    // - Returns: A list of candidate raw data transferable across threads.
    std::vector<MonitorProcessCandidateSnapshotItem> collectMonitorProcessCandidateSnapshot()
    {
        const std::vector<ks::process::ProcessRecord> kProcessList =
            ks::process::enumerateProcesses(ks::process::ProcessEnumStrategy::kAuto);

        std::vector<MonitorProcessCandidateSnapshotItem> snapshotList;
        snapshotList.reserve(kProcessList.size());
        for (const ks::process::ProcessRecord& processRecord : kProcessList)
        {
            if (processRecord.pid == 0)
            {
                continue;
            }

            MonitorProcessCandidateSnapshotItem snapshotItem;
            snapshotItem.pid = processRecord.pid;
            snapshotItem.processName = toQString(processRecord.processName).trimmed();
            snapshotList.push_back(std::move(snapshotItem));
        }
        return snapshotList;
    }

    // collectMonitorProcessIconImages:
    // - Extract Shell small icon bitmaps for PIDs that currently lack icon cache, within a thread pool worker thread.
    // - Query each executable path only once and limit the extraction count per round to prevent the thread pool from being occupied for extended periods during the first refresh.
    // - SHGetFileInfoW depends on COM; worker threads must explicitly pair CoInitializeEx and CoUninitialize.
    // - Input parameter candidateSnapshotList: the candidate list enumerated in this round;
    // - Parameter cachedIconPidSet: Snapshot of PIDs whose icons are already cached in the UI thread; skip if matched.
    // - Return: PID -> icon bitmap; an empty bitmap indicates parsing failure, with the UI thread falling back to a placeholder icon.
    QHash<quint32, QImage> collectMonitorProcessIconImages(
        const std::vector<MonitorProcessCandidateSnapshotItem>& candidateSnapshotList,
        const QSet<quint32>& cachedIconPidSet)
    {
        QHash<quint32, QImage> iconImageByPid;

        const HRESULT kComInitializeResult = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        const bool kComInitializedHere = SUCCEEDED(kComInitializeResult);

        QHash<QString, QImage> iconImageByExecutablePath;
        int extractedCount = 0;
        for (const MonitorProcessCandidateSnapshotItem& snapshotItem : candidateSnapshotList)
        {
            const quint32 kProcessIdKey = static_cast<quint32>(snapshotItem.pid);
            if (cachedIconPidSet.contains(kProcessIdKey))
            {
                continue;
            }
            if (extractedCount >= kMaxMonitorProcessIconExtractPerRound)
            {
                break;
            }
            ++extractedCount;

            const std::string kProcessPath = ks::process::queryProcessPathByPid(snapshotItem.pid);
            if (kProcessPath.empty())
            {
                iconImageByPid.insert(kProcessIdKey, QImage());
                continue;
            }

            const QString kProcessPathText = QString::fromUtf8(kProcessPath.c_str());
            const auto kPathIterator = iconImageByExecutablePath.constFind(kProcessPathText);
            if (kPathIterator != iconImageByExecutablePath.constEnd())
            {
                iconImageByPid.insert(kProcessIdKey, kPathIterator.value());
                continue;
            }

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
            iconImageByExecutablePath.insert(kProcessPathText, processIconImage);
            iconImageByPid.insert(kProcessIdKey, processIconImage);
        }

        if (kComInitializedHere)
        {
            ::CoUninitialize();
        }
        return iconImageByPid;
    }

    constexpr const char* kMonitorFilterConfigRelativePath = "config/wireshark.cfg";
    constexpr const char* kMonitorFilterJsonVersionKey = "version";
    constexpr const char* kMonitorFilterJsonGroupsKey = "groups";
    constexpr const char* kMonitorFilterJsonEnabledKey = "enabled";
    constexpr const char* kMonitorFilterJsonProcessesKey = "processes";
    constexpr const char* kMonitorFilterJsonPidKey = "pid";
    constexpr const char* kMonitorFilterJsonProcessNameKey = "name";
    constexpr const char* kMonitorFilterJsonLocalAddressesKey = "local_addresses";
    constexpr const char* kMonitorFilterJsonRemoteAddressesKey = "remote_addresses";
    constexpr const char* kMonitorFilterJsonLocalPortsKey = "local_ports";
    constexpr const char* kMonitorFilterJsonRemotePortsKey = "remote_ports";
    constexpr const char* kMonitorFilterJsonPacketSizesKey = "packet_sizes";

    constexpr int kProcessSuggestPidRole = Qt::UserRole + 1;
    constexpr int kProcessSuggestNameRole = Qt::UserRole + 2;

    QStringList jsonArrayToStringList(const QJsonValue& value)
    {
        QStringList outputList;
        const QJsonArray kArrayValue = value.toArray();
        outputList.reserve(kArrayValue.size());
        for (const QJsonValue& itemValue : kArrayValue)
        {
            const QString kText = itemValue.toString().trimmed();
            if (!kText.isEmpty())
            {
                outputList.push_back(kText);
            }
        }
        return outputList;
    }

    void configureRuleValueTable(
        QTableWidget* tableWidget,
        const QStringList& headers,
        const int processIdColumn = -1)
    {
        if (tableWidget == nullptr)
        {
            return;
        }

        ks::ui::setTableActionBarMode(tableWidget, ks::ui::TableActionBarMode::kNone);
        tableWidget->setColumnCount(headers.size());
        tableWidget->setHorizontalHeaderLabels(headers);
        tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
        tableWidget->setSelectionMode(QAbstractItemView::SingleSelection);
        tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
        tableWidget->verticalHeader()->setVisible(false);
        tableWidget->horizontalHeader()->setStretchLastSection(true);
        tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
        tableWidget->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        installCopyCurrentRowMenu(
            tableWidget,
            QStringLiteral("复制当前行"),
            processIdColumn);
    }

    QTableWidgetItem* createReadonlyItem(const QString& text)
    {
        QTableWidgetItem* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }
}

QStringList NetworkDock::splitMonitorFilterTokens(const QString& inputText)
{
    static const QRegularExpression kSeparatorRegex(QStringLiteral("[,;\\s]+"));
    return inputText.split(kSeparatorRegex, Qt::SkipEmptyParts);
}

bool NetworkDock::tryParsePacketSizeToken(
    const QString& tokenText,
    UInt32Range& rangeOut,
    QString& normalizeTextOut)
{
    const QString kTrimmedText = tokenText.trimmed();
    if (kTrimmedText.isEmpty())
    {
        return false;
    }

    const auto kParseUInt32 = [](const QString& text, std::uint32_t& valueOut) -> bool
        {
            bool parseOk = false;
            const qulonglong kParsedValue = text.trimmed().toULongLong(&parseOk, 10);
            if (!parseOk || kParsedValue > 0xFFFFFFFFULL)
            {
                return false;
            }
            valueOut = static_cast<std::uint32_t>(kParsedValue);
            return true;
        };

    const int kDashIndex = kTrimmedText.indexOf('-');
    if (kDashIndex > 0)
    {
        const QString kBeginText = kTrimmedText.left(kDashIndex).trimmed();
        const QString kEndText = kTrimmedText.mid(kDashIndex + 1).trimmed();

        std::uint32_t beginValue = 0;
        std::uint32_t endValue = 0;
        if (!kParseUInt32(kBeginText, beginValue) || !kParseUInt32(kEndText, endValue))
        {
            return false;
        }

        const std::uint32_t kNormalizedBegin = std::min(beginValue, endValue);
        const std::uint32_t kNormalizedEnd = std::max(beginValue, endValue);
        rangeOut = { kNormalizedBegin, kNormalizedEnd };
        normalizeTextOut = (kNormalizedBegin == kNormalizedEnd)
            ? QString::number(kNormalizedBegin)
            : QStringLiteral("%1-%2").arg(kNormalizedBegin).arg(kNormalizedEnd);
        return true;
    }

    std::uint32_t singleValue = 0;
    if (!kParseUInt32(kTrimmedText, singleValue))
    {
        return false;
    }

    rangeOut = { singleValue, singleValue };
    normalizeTextOut = QString::number(singleValue);
    return true;
}

NetworkDock::MonitorFilterRuleGroupUiState* NetworkDock::findMonitorFilterRuleGroupById(const int groupId)
{
    for (const std::unique_ptr<MonitorFilterRuleGroupUiState>& groupState : monitorFilterRuleGroupUiList_)
    {
        if (groupState != nullptr && groupState->groupId == groupId)
        {
            return groupState.get();
        }
    }
    return nullptr;
}

const NetworkDock::MonitorFilterRuleGroupUiState* NetworkDock::findMonitorFilterRuleGroupById(const int groupId) const
{
    for (const std::unique_ptr<MonitorFilterRuleGroupUiState>& groupState : monitorFilterRuleGroupUiList_)
    {
        if (groupState != nullptr && groupState->groupId == groupId)
        {
            return groupState.get();
        }
    }
    return nullptr;
}

NetworkDock::MonitorTextRuleFieldUiState* NetworkDock::findTextRuleField(
    MonitorFilterRuleGroupUiState& groupState,
    const MonitorTextRuleFieldKind fieldKind)
{
    switch (fieldKind)
    {
    case MonitorTextRuleFieldKind::kLocalAddress:
        return &groupState.localAddressField;
    case MonitorTextRuleFieldKind::kRemoteAddress:
        return &groupState.remoteAddressField;
    case MonitorTextRuleFieldKind::kLocalPort:
        return &groupState.localPortField;
    case MonitorTextRuleFieldKind::kRemotePort:
        return &groupState.remotePortField;
    case MonitorTextRuleFieldKind::kPacketSize:
        return &groupState.packetSizeField;
    default:
        return nullptr;
    }
}

const NetworkDock::MonitorTextRuleFieldUiState* NetworkDock::findTextRuleField(
    const MonitorFilterRuleGroupUiState& groupState,
    const MonitorTextRuleFieldKind fieldKind) const
{
    switch (fieldKind)
    {
    case MonitorTextRuleFieldKind::kLocalAddress:
        return &groupState.localAddressField;
    case MonitorTextRuleFieldKind::kRemoteAddress:
        return &groupState.remoteAddressField;
    case MonitorTextRuleFieldKind::kLocalPort:
        return &groupState.localPortField;
    case MonitorTextRuleFieldKind::kRemotePort:
        return &groupState.remotePortField;
    case MonitorTextRuleFieldKind::kPacketSize:
        return &groupState.packetSizeField;
    default:
        return nullptr;
    }
}

QString NetworkDock::monitorFilterConfigPath() const
{
    return QDir(QCoreApplication::applicationDirPath())
        .absoluteFilePath(QString::fromLatin1(kMonitorFilterConfigRelativePath));
}

void NetworkDock::refreshMonitorProcessCandidateList(const bool forceRefresh)
{
    // This function has been changed from 'sync full enumeration + per-process icon extraction' to pure scheduling:
    // - The UI thread only throttles and dispatches tasks; it must never perform enumerateProcesses or Shell icon extraction here.
    // - Background task dispatched in two stages: first dispatch PID + process name for immediate dropdown availability, then dispatch icon bitmaps to complete the display;
    // - The caller currently receives the m_monitorProcessCandidateList cached from the previous round.
    const qint64 kNowMs = QDateTime::currentMSecsSinceEpoch();
    constexpr qint64 kRefreshIntervalMs = 1200;
    if (!forceRefresh &&
        !monitorProcessCandidateList_.empty() &&
        kNowMs - monitorProcessCandidateLastRefreshMs_ < kRefreshIntervalMs)
    {
        return;
    }

    MonitorProcessCandidateRefreshState& refreshState =
        gMonitorProcessCandidateRefreshStateMap[this];
    if (refreshState.refreshInFlight)
    {
        return;
    }
    refreshState.refreshInFlight = true;
    ++refreshState.latestRequestGeneration;
    const quint64 kRequestGeneration = refreshState.latestRequestGeneration;

    // The PID snapshot of cached icons is dispatched with the task; the background only extracts Shell icons for newly appearing processes.
    QSet<quint32> cachedIconPidSet;
    cachedIconPidSet.reserve(processIconCacheByPid_.size());
    for (auto iconCacheIterator = processIconCacheByPid_.constBegin();
        iconCacheIterator != processIconCacheByPid_.constEnd();
        ++iconCacheIterator)
    {
        cachedIconPidSet.insert(iconCacheIterator.key());
    }

    // refreshFocusedProcessSuggestionModels:
    // - After candidate cache or icon updates, rebuild the completion dropdown only for the 'currently being edited rule group'.
    // - Input parameter dockInstance: the host NetworkDock.
    // - Returns: Nothing.
    const auto kRefreshFocusedProcessSuggestionModels = [](NetworkDock* const dockInstance)
        {
            for (const std::unique_ptr<MonitorFilterRuleGroupUiState>& groupState :
                dockInstance->monitorFilterRuleGroupUiList_)
            {
                if (groupState == nullptr ||
                    groupState->processInputEdit == nullptr ||
                    !groupState->processInputEdit->hasFocus())
                {
                    continue;
                }
                dockInstance->refreshProcessSuggestionModelForGroup(
                    groupState->groupId,
                    groupState->processInputEdit->text());
            }
        };

    // ownerKey: Used solely as an identity marker (never dereferenced) to ensure the host can still be located and scheduled state cleaned up after the host is destructed.
    const QPointer<NetworkDock> kGuardedSelf(this);
    const NetworkDock* const kOwnerKey = this;
    QThreadPool::globalInstance()->start(
        [kGuardedSelf, kOwnerKey, kRequestGeneration, cachedIconPidSet, kRefreshFocusedProcessSuggestionModels]()
        {
            // Phase 1: Perform only process enumeration to make the dropdown candidates available as quickly as possible.
            const std::vector<MonitorProcessCandidateSnapshotItem> kCandidateSnapshotList =
                collectMonitorProcessCandidateSnapshot();

            QCoreApplication* const kNameStageAppInstance = QCoreApplication::instance();
            if (kNameStageAppInstance == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                kNameStageAppInstance,
                [kGuardedSelf,
                    kOwnerKey,
                    kRequestGeneration,
                    kCandidateSnapshotList,
                    kRefreshFocusedProcessSuggestionModels]()
                {
                    const auto kStateIterator = gMonitorProcessCandidateRefreshStateMap.find(kOwnerKey);
                    if (kStateIterator == gMonitorProcessCandidateRefreshStateMap.end() ||
                        kStateIterator->second.latestRequestGeneration != kRequestGeneration ||
                        kGuardedSelf == nullptr)
                    {
                        return;
                    }

                    std::vector<MonitorProcessCandidate> candidateList;
                    candidateList.reserve(kCandidateSnapshotList.size());
                    for (const MonitorProcessCandidateSnapshotItem& snapshotItem : kCandidateSnapshotList)
                    {
                        MonitorProcessCandidate candidate;
                        candidate.pid = snapshotItem.pid;
                        candidate.processName = snapshotItem.processName;
                        if (candidate.processName.isEmpty())
                        {
                            candidate.processName = QStringLiteral("PID_%1").arg(snapshotItem.pid);
                        }

                        // Icons are retrieved only from the cache; on cache miss, use a placeholder icon first and fill in the real one when the second segment is returned.
                        const auto kIconCacheIterator = kGuardedSelf->processIconCacheByPid_.constFind(
                            static_cast<quint32>(snapshotItem.pid));
                        candidate.processIcon =
                            kIconCacheIterator != kGuardedSelf->processIconCacheByPid_.constEnd()
                            ? kIconCacheIterator.value()
                            : monitorProcessPlaceholderIcon();
                        candidate.displayText = QStringLiteral("%1 (%2)")
                            .arg(candidate.processName)
                            .arg(candidate.pid);
                        candidate.searchText = QStringLiteral("%1 %2")
                            .arg(candidate.processName.toLower())
                            .arg(QString::number(candidate.pid));
                        candidateList.push_back(std::move(candidate));
                    }

                    std::sort(
                        candidateList.begin(),
                        candidateList.end(),
                        [](const MonitorProcessCandidate& left, const MonitorProcessCandidate& right)
                        {
                            if (left.processName.compare(right.processName, Qt::CaseInsensitive) == 0)
                            {
                                return left.pid < right.pid;
                            }
                            return left.processName.compare(right.processName, Qt::CaseInsensitive) < 0;
                        });

                    kGuardedSelf->monitorProcessCandidateList_ = std::move(candidateList);
                    kGuardedSelf->monitorProcessCandidateLastRefreshMs_ =
                        QDateTime::currentMSecsSinceEpoch();
                    kRefreshFocusedProcessSuggestionModels(kGuardedSelf.data());
                },
                Qt::QueuedConnection);

            // Second segment: Fill in PID icons that lack a cache, all completed in the background.
            const QHash<quint32, QImage> kIconImageByPid =
                collectMonitorProcessIconImages(kCandidateSnapshotList, cachedIconPidSet);

            QCoreApplication* const kIconStageAppInstance = QCoreApplication::instance();
            if (kIconStageAppInstance == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                kIconStageAppInstance,
                [kGuardedSelf,
                    kOwnerKey,
                    kRequestGeneration,
                    kIconImageByPid,
                    kRefreshFocusedProcessSuggestionModels]()
                {
                    // End of current task: release the scheduling slot first to allow subsequent inputs to continue refreshing candidates.
                    const auto kStateIterator = gMonitorProcessCandidateRefreshStateMap.find(kOwnerKey);
                    if (kStateIterator == gMonitorProcessCandidateRefreshStateMap.end())
                    {
                        return;
                    }
                    if (kStateIterator->second.latestRequestGeneration != kRequestGeneration)
                    {
                        return;
                    }
                    kStateIterator->second.refreshInFlight = false;
                    if (kGuardedSelf == nullptr)
                    {
                        gMonitorProcessCandidateRefreshStateMap.erase(kStateIterator);
                        return;
                    }
                    if (kIconImageByPid.isEmpty())
                    {
                        return;
                    }

                    // QPixmap/QIcon must be constructed on the UI thread; even if resolution fails, write to cache to avoid repeated cold lookups for the same PID.
                    for (auto iconImageIterator = kIconImageByPid.constBegin();
                        iconImageIterator != kIconImageByPid.constEnd();
                        ++iconImageIterator)
                    {
                        const QIcon kResolvedIcon = iconImageIterator.value().isNull()
                            ? monitorProcessPlaceholderIcon()
                            : QIcon(QPixmap::fromImage(iconImageIterator.value()));
                        kGuardedSelf->processIconCacheByPid_.insert(iconImageIterator.key(), kResolvedIcon);
                    }

                    for (MonitorProcessCandidate& candidate : kGuardedSelf->monitorProcessCandidateList_)
                    {
                        const auto kIconCacheIterator = kGuardedSelf->processIconCacheByPid_.constFind(
                            static_cast<quint32>(candidate.pid));
                        if (kIconCacheIterator != kGuardedSelf->processIconCacheByPid_.constEnd())
                        {
                            candidate.processIcon = kIconCacheIterator.value();
                        }
                    }
                    kRefreshFocusedProcessSuggestionModels(kGuardedSelf.data());
                },
                Qt::QueuedConnection);
        });
}

void NetworkDock::refreshProcessSuggestionModelForGroup(const int groupId, const QString& keywordText)
{
    MonitorFilterRuleGroupUiState* groupState = findMonitorFilterRuleGroupById(groupId);
    if (groupState == nullptr ||
        groupState->processSuggestionModel == nullptr ||
        groupState->processInputEdit == nullptr)
    {
        return;
    }

    // Only responsible for 'scheduling one background refresh'; this filtering still performs pure string matching on the cached candidate list.
    // After background results are returned, the dropdown is rebuilt for the currently focused input, so the user does not need to retype.
    refreshMonitorProcessCandidateList(false);

    const QString kKeyword = keywordText.trimmed().toLower();
    groupState->processSuggestionModel->clear();

    constexpr int kMaxSuggestCount = 200;
    int addedCount = 0;
    for (const MonitorProcessCandidate& candidate : monitorProcessCandidateList_)
    {
        if (!kKeyword.isEmpty() && !candidate.searchText.contains(kKeyword))
        {
            continue;
        }

        auto* item = new QStandardItem(candidate.processIcon, candidate.displayText);
        item->setData(static_cast<qulonglong>(candidate.pid), kProcessSuggestPidRole);
        item->setData(candidate.processName, kProcessSuggestNameRole);
        groupState->processSuggestionModel->appendRow(item);

        ++addedCount;
        if (addedCount >= kMaxSuggestCount)
        {
            break;
        }
    }

    if (groupState->processCompleter != nullptr)
    {
        groupState->processCompleter->setCompletionPrefix(keywordText.trimmed());
        if (groupState->processInputEdit->hasFocus() && addedCount > 0)
        {
            groupState->processCompleter->complete();
        }
    }
}

void NetworkDock::rebuildMonitorFilterRuleGroupUi()
{
    if (monitorFilterGroupHostLayout_ == nullptr)
    {
        return;
    }

    while (monitorFilterGroupHostLayout_->count() > 0)
    {
        QLayoutItem* item = monitorFilterGroupHostLayout_->takeAt(0);
        delete item;
    }

    const bool kCanRemoveGroup = monitorFilterRuleGroupUiList_.size() > 1;
    int displayIndex = 1;
    for (const std::unique_ptr<MonitorFilterRuleGroupUiState>& groupState : monitorFilterRuleGroupUiList_)
    {
        if (groupState == nullptr || groupState->containerWidget == nullptr)
        {
            continue;
        }

        if (groupState->titleLabel != nullptr)
        {
            groupState->titleLabel->setText(QStringLiteral("规则组%1").arg(displayIndex));
        }
        if (groupState->removeGroupButton != nullptr)
        {
            groupState->removeGroupButton->setEnabled(kCanRemoveGroup);
        }

        monitorFilterGroupHostLayout_->addWidget(groupState->containerWidget);
        ++displayIndex;
    }

    monitorFilterGroupHostLayout_->addStretch(1);
}

void NetworkDock::addMonitorFilterRuleGroup()
{
    if (monitorFilterGroupHostWidget_ == nullptr || monitorFilterGroupHostLayout_ == nullptr)
    {
        return;
    }

    std::unique_ptr<MonitorFilterRuleGroupUiState> groupState = std::make_unique<MonitorFilterRuleGroupUiState>();
    groupState->groupId = monitorFilterNextGroupId_++;

    groupState->containerWidget = new QWidget(monitorFilterGroupHostWidget_);
    auto* rootLayout = new QVBoxLayout(groupState->containerWidget);
    rootLayout->setContentsMargins(8, 8, 8, 8);
    rootLayout->setSpacing(6);

    auto* headerLayout = new QHBoxLayout();
    headerLayout->setSpacing(6);
    groupState->titleLabel = new QLabel(QStringLiteral("规则组"), groupState->containerWidget);
    groupState->enabledCheck = new QCheckBox(QStringLiteral("启用"), groupState->containerWidget);
    groupState->enabledCheck->setChecked(true);
    groupState->removeGroupButton = new QPushButton(groupState->containerWidget);
    groupState->removeGroupButton->setIcon(QIcon(":/Icon/log_cancel_track.svg"));
    groupState->removeGroupButton->setToolTip(QStringLiteral("删除当前规则组"));

    headerLayout->addWidget(groupState->titleLabel);
    headerLayout->addWidget(groupState->enabledCheck);
    headerLayout->addStretch(1);
    headerLayout->addWidget(groupState->removeGroupButton);
    rootLayout->addLayout(headerLayout);

    QFrame* separatorLine = new QFrame(groupState->containerWidget);
    separatorLine->setFrameShape(QFrame::HLine);
    separatorLine->setFrameShadow(QFrame::Sunken);
    rootLayout->addWidget(separatorLine);

    auto* fieldRowLayout = new QHBoxLayout();
    fieldRowLayout->setSpacing(8);

    QWidget* processBlock = new QWidget(groupState->containerWidget);
    processBlock->setMinimumWidth(340);
    auto* processBlockLayout = new QVBoxLayout(processBlock);
    processBlockLayout->setContentsMargins(0, 0, 0, 0);
    processBlockLayout->setSpacing(4);

    auto* processTopLayout = new QHBoxLayout();
    processTopLayout->setSpacing(4);
    QLabel* processLabel = new QLabel(QStringLiteral("进程"), processBlock);
    groupState->processInputEdit = new QLineEdit(processBlock);
    groupState->processInputEdit->setPlaceholderText(QStringLiteral("输入 PID 或进程名"));
    groupState->processInputEdit->setToolTip(QStringLiteral("输入后自动匹配系统进程，支持 PID/进程名。"));
    groupState->addProcessButton = new QPushButton(QStringLiteral("+"), processBlock);
    groupState->addProcessButton->setFixedWidth(26);
    groupState->addProcessButton->setToolTip(
        QStringLiteral("把上方输入框中的进程加入本规则组的进程过滤列表"));
    groupState->removeInvalidProcessButton = new QPushButton(QStringLiteral("清除失效"), processBlock);
    groupState->removeInvalidProcessButton->setToolTip(
        QStringLiteral("移除列表中已经关闭或不存在的进程"));
    groupState->clearProcessButton = new QPushButton(processBlock);
    groupState->clearProcessButton->setIcon(QIcon(":/Icon/log_clear.svg"));
    groupState->clearProcessButton->setToolTip(QStringLiteral("清空进程列表"));

    groupState->processSuggestionModel = new QStandardItemModel(groupState->processInputEdit);
    groupState->processCompleter = new QCompleter(groupState->processSuggestionModel, groupState->processInputEdit);
    groupState->processCompleter->setCaseSensitivity(Qt::CaseInsensitive);
    groupState->processCompleter->setCompletionMode(QCompleter::PopupCompletion);
    groupState->processCompleter->setFilterMode(Qt::MatchContains);
    groupState->processInputEdit->setCompleter(groupState->processCompleter);

    processTopLayout->addWidget(processLabel);
    processTopLayout->addWidget(groupState->processInputEdit, 1);
    processTopLayout->addWidget(groupState->addProcessButton);
    processTopLayout->addWidget(groupState->removeInvalidProcessButton);
    processTopLayout->addWidget(groupState->clearProcessButton);

    groupState->processTable = new ks::ui::VisibleTableWidget(processBlock);
    groupState->processTable->setMinimumHeight(56);
    groupState->processTable->setMaximumHeight(86);
    configureRuleValueTable(groupState->processTable, {
        QStringLiteral("进程"),
        QStringLiteral("PID"),
        QStringLiteral("操作")
        }, 1);

    processBlockLayout->addLayout(processTopLayout);
    processBlockLayout->addWidget(groupState->processTable);
    fieldRowLayout->addWidget(processBlock);

    const auto kBuildTextFieldBlock = [this, &fieldRowLayout, groupStatePtr = groupState.get()](
        MonitorTextRuleFieldUiState& fieldState,
        const QString& labelText,
        const QString& placeholderText,
        const MonitorTextRuleFieldKind fieldKind,
        const int minimumWidth)
        {
            fieldState.labelText = labelText;

            QWidget* block = new QWidget(groupStatePtr->containerWidget);
            block->setMinimumWidth(minimumWidth);
            auto* blockLayout = new QVBoxLayout(block);
            blockLayout->setContentsMargins(0, 0, 0, 0);
            blockLayout->setSpacing(4);

            auto* topLayout = new QHBoxLayout();
            topLayout->setSpacing(4);
            QLabel* label = new QLabel(labelText, block);
            fieldState.inputEdit = new QLineEdit(block);
            fieldState.inputEdit->setPlaceholderText(placeholderText);
            fieldState.addButton = new QPushButton(QStringLiteral("+"), block);
            fieldState.addButton->setFixedWidth(26);
            fieldState.addButton->setToolTip(
                QStringLiteral("把上方输入的地址或端口加入本条件的过滤列表"));
            fieldState.clearButton = new QPushButton(QStringLiteral("清空"), block);
            fieldState.clearButton->setToolTip(
                QStringLiteral("清空本条件已添加的所有过滤项"));

            topLayout->addWidget(label);
            topLayout->addWidget(fieldState.inputEdit, 1);
            topLayout->addWidget(fieldState.addButton);
            topLayout->addWidget(fieldState.clearButton);

            fieldState.tableWidget = new ks::ui::VisibleTableWidget(block);
            fieldState.tableWidget->setMinimumHeight(56);
            fieldState.tableWidget->setMaximumHeight(86);
            configureRuleValueTable(fieldState.tableWidget, {
                labelText,
                QStringLiteral("操作")
                });

            blockLayout->addLayout(topLayout);
            blockLayout->addWidget(fieldState.tableWidget);
            fieldRowLayout->addWidget(block);

            connect(fieldState.addButton, &QPushButton::clicked, this, [this, groupId = groupStatePtr->groupId, fieldKind]()
                {
                    addTextFilterItemsByInput(groupId, fieldKind);
                });
            connect(fieldState.clearButton, &QPushButton::clicked, this, [this, groupId = groupStatePtr->groupId, fieldKind]()
                {
                    clearTextFilterItems(groupId, fieldKind);
                });
            connect(fieldState.inputEdit, &QLineEdit::returnPressed, this, [this, groupId = groupStatePtr->groupId, fieldKind]()
                {
                    addTextFilterItemsByInput(groupId, fieldKind);
                });
        };

    kBuildTextFieldBlock(
        groupState->localAddressField,
        QStringLiteral("本地地址"),
        QStringLiteral("如 192.168.1.0/24"),
        MonitorTextRuleFieldKind::kLocalAddress,
        240);
    kBuildTextFieldBlock(
        groupState->remoteAddressField,
        QStringLiteral("远程地址"),
        QStringLiteral("如 8.8.8.8 或 10.0.0.1-10.0.0.20"),
        MonitorTextRuleFieldKind::kRemoteAddress,
        260);
    kBuildTextFieldBlock(
        groupState->localPortField,
        QStringLiteral("本地端口"),
        QStringLiteral("如 80 或 1000-2000"),
        MonitorTextRuleFieldKind::kLocalPort,
        220);
    kBuildTextFieldBlock(
        groupState->remotePortField,
        QStringLiteral("远程端口"),
        QStringLiteral("如 443 或 5000-6000"),
        MonitorTextRuleFieldKind::kRemotePort,
        220);
    kBuildTextFieldBlock(
        groupState->packetSizeField,
        QStringLiteral("包长"),
        QStringLiteral("如 40,60-80"),
        MonitorTextRuleFieldKind::kPacketSize,
        220);

    rootLayout->addLayout(fieldRowLayout);

    QFrame* bottomLine = new QFrame(groupState->containerWidget);
    bottomLine->setFrameShape(QFrame::HLine);
    bottomLine->setFrameShadow(QFrame::Sunken);
    rootLayout->addWidget(bottomLine);

    connect(groupState->enabledCheck, &QCheckBox::toggled, this, [this]()
        {
            applyMonitorFilters();
        });
    connect(groupState->removeGroupButton, &QPushButton::clicked, this, [this, groupId = groupState->groupId]()
        {
            removeMonitorFilterRuleGroup(groupId);
        });

    connect(groupState->processInputEdit, &QLineEdit::textEdited, this, [this, groupId = groupState->groupId](const QString& text)
        {
            MonitorFilterRuleGroupUiState* state = findMonitorFilterRuleGroupById(groupId);
            if (state != nullptr && state->processInputEdit != nullptr)
            {
                state->processInputEdit->setProperty("selected_pid", QVariant());
                state->processInputEdit->setProperty("selected_process_name", QVariant());
            }
            refreshProcessSuggestionModelForGroup(groupId, text);
        });
    connect(groupState->processInputEdit, &QLineEdit::returnPressed, this, [this, groupId = groupState->groupId]()
        {
            addProcessTargetByInput(groupId);
        });
    connect(groupState->addProcessButton, &QPushButton::clicked, this, [this, groupId = groupState->groupId]()
        {
            addProcessTargetByInput(groupId);
        });
    connect(groupState->removeInvalidProcessButton, &QPushButton::clicked, this, [this, groupId = groupState->groupId]()
        {
            removeInvalidProcessTargets(groupId);
        });
    connect(groupState->clearProcessButton, &QPushButton::clicked, this, [this, groupId = groupState->groupId]()
        {
            clearProcessTargetList(groupId);
        });
    connect(groupState->processCompleter,
        QOverload<const QModelIndex&>::of(&QCompleter::activated),
        this,
        [this, groupId = groupState->groupId](const QModelIndex& modelIndex)
        {
            MonitorFilterRuleGroupUiState* state = findMonitorFilterRuleGroupById(groupId);
            if (state == nullptr || state->processInputEdit == nullptr || !modelIndex.isValid())
            {
                return;
            }

            const QVariant kPidVariant = modelIndex.data(kProcessSuggestPidRole);
            const QVariant kNameVariant = modelIndex.data(kProcessSuggestNameRole);
            state->processInputEdit->setProperty("selected_pid", kPidVariant);
            state->processInputEdit->setProperty("selected_process_name", kNameVariant);
            state->processInputEdit->setText(modelIndex.data(Qt::DisplayRole).toString());
        });

    monitorFilterRuleGroupUiList_.push_back(std::move(groupState));

    rebuildMonitorFilterRuleGroupUi();
    refreshProcessTableForGroup(monitorFilterRuleGroupUiList_.back()->groupId);
    refreshTextTableForGroup(monitorFilterRuleGroupUiList_.back()->groupId, MonitorTextRuleFieldKind::kLocalAddress);
    refreshTextTableForGroup(monitorFilterRuleGroupUiList_.back()->groupId, MonitorTextRuleFieldKind::kRemoteAddress);
    refreshTextTableForGroup(monitorFilterRuleGroupUiList_.back()->groupId, MonitorTextRuleFieldKind::kLocalPort);
    refreshTextTableForGroup(monitorFilterRuleGroupUiList_.back()->groupId, MonitorTextRuleFieldKind::kRemotePort);
    refreshTextTableForGroup(monitorFilterRuleGroupUiList_.back()->groupId, MonitorTextRuleFieldKind::kPacketSize);
}

void NetworkDock::removeMonitorFilterRuleGroup(const int groupId)
{
    auto iterator = std::find_if(
        monitorFilterRuleGroupUiList_.begin(),
        monitorFilterRuleGroupUiList_.end(),
        [groupId](const std::unique_ptr<MonitorFilterRuleGroupUiState>& groupState)
        {
            return groupState != nullptr && groupState->groupId == groupId;
        });

    if (iterator == monitorFilterRuleGroupUiList_.end())
    {
        return;
    }

    if ((*iterator)->containerWidget != nullptr)
    {
        delete (*iterator)->containerWidget;
        (*iterator)->containerWidget = nullptr;
    }

    monitorFilterRuleGroupUiList_.erase(iterator);

    if (monitorFilterRuleGroupUiList_.empty())
    {
        addMonitorFilterRuleGroup();
    }

    rebuildMonitorFilterRuleGroupUi();
    applyMonitorFilters();
}

void NetworkDock::refreshProcessTableForGroup(const int groupId)
{
    MonitorFilterRuleGroupUiState* groupState = findMonitorFilterRuleGroupById(groupId);
    if (groupState == nullptr || groupState->processTable == nullptr)
    {
        return;
    }

    QTableWidget* processTable = groupState->processTable;
    processTable->setRowCount(static_cast<int>(groupState->processTargetList.size()));

    for (int row = 0; row < processTable->rowCount(); ++row)
    {
        const MonitorProcessTarget& target = groupState->processTargetList[static_cast<std::size_t>(row)];

        QTableWidgetItem* processItem = createReadonlyItem(target.processName);
        processItem->setIcon(target.processIcon);
        processTable->setItem(row, 0, processItem);
        processTable->setItem(row, 1, createReadonlyItem(QString::number(target.pid)));

        QPushButton* removeButton = new QPushButton(QStringLiteral("移除"), processTable);
        connect(removeButton, &QPushButton::clicked, this, [this, groupId, pid = target.pid]()
            {
                removeProcessTarget(groupId, pid);
            });
        processTable->setCellWidget(row, 2, removeButton);
    }
}

void NetworkDock::refreshTextTableForGroup(const int groupId, const MonitorTextRuleFieldKind fieldKind)
{
    MonitorFilterRuleGroupUiState* groupState = findMonitorFilterRuleGroupById(groupId);
    if (groupState == nullptr)
    {
        return;
    }

    MonitorTextRuleFieldUiState* fieldState = findTextRuleField(*groupState, fieldKind);
    if (fieldState == nullptr || fieldState->tableWidget == nullptr)
    {
        return;
    }

    QTableWidget* tableWidget = fieldState->tableWidget;
    tableWidget->setRowCount(fieldState->valueList.size());

    for (int row = 0; row < tableWidget->rowCount(); ++row)
    {
        tableWidget->setItem(row, 0, createReadonlyItem(fieldState->valueList[row]));
        QPushButton* removeButton = new QPushButton(QStringLiteral("移除"), tableWidget);
        connect(removeButton, &QPushButton::clicked, this, [this, groupId, fieldKind, row]()
            {
                removeTextFilterItem(groupId, fieldKind, row);
            });
        tableWidget->setCellWidget(row, 1, removeButton);
    }
}

void NetworkDock::addProcessTargetByInput(const int groupId)
{
    MonitorFilterRuleGroupUiState* groupState = findMonitorFilterRuleGroupById(groupId);
    if (groupState == nullptr || groupState->processInputEdit == nullptr)
    {
        return;
    }

    // This triggers a single background refresh (non-blocking on click): candidate caching is already completed in the background during
    // user input, and this parsing still follows the 'cached candidates -> PID text -> getProcessNameByPid' three-level fallback.
    refreshMonitorProcessCandidateList(true);

    const QString kInputText = groupState->processInputEdit->text().trimmed();
    if (kInputText.isEmpty())
    {
        return;
    }

    std::uint32_t resolvedPid = 0;
    QString resolvedName;
    QIcon resolvedIcon;

    const QVariant kSelectedPidVariant = groupState->processInputEdit->property("selected_pid");
    const QVariant kSelectedNameVariant = groupState->processInputEdit->property("selected_process_name");
    if (kSelectedPidVariant.isValid())
    {
        resolvedPid = static_cast<std::uint32_t>(kSelectedPidVariant.toULongLong());
        resolvedName = kSelectedNameVariant.toString().trimmed();
    }

    if (resolvedPid == 0)
    {
        std::uint32_t parsedPid = 0;
        if (tryParsePidText(kInputText, parsedPid))
        {
            resolvedPid = parsedPid;
        }
        else
        {
            const QString kLoweredInput = kInputText.toLower();
            for (const MonitorProcessCandidate& candidate : monitorProcessCandidateList_)
            {
                if (candidate.processName.compare(kLoweredInput, Qt::CaseInsensitive) == 0 ||
                    candidate.searchText.contains(kLoweredInput))
                {
                    resolvedPid = candidate.pid;
                    resolvedName = candidate.processName;
                    resolvedIcon = candidate.processIcon;
                    break;
                }
            }
        }
    }

    if (resolvedPid == 0)
    {
        QMessageBox::warning(this, QStringLiteral("流量筛选"), QStringLiteral("未匹配到目标进程，请重新输入 PID 或进程名。"));
        return;
    }

    if (resolvedName.isEmpty())
    {
        for (const MonitorProcessCandidate& candidate : monitorProcessCandidateList_)
        {
            if (candidate.pid == resolvedPid)
            {
                resolvedName = candidate.processName;
                resolvedIcon = candidate.processIcon;
                break;
            }
        }
    }
    if (resolvedName.isEmpty())
    {
        resolvedName = toQString(ks::process::getProcessNameByPid(resolvedPid));
    }
    if (resolvedName.isEmpty())
    {
        resolvedName = QStringLiteral("PID_%1").arg(resolvedPid);
    }
    if (resolvedIcon.isNull())
    {
        resolvedIcon = resolveProcessIconByPid(resolvedPid, resolvedName.toStdString());
    }

    const bool kExisted = std::any_of(
        groupState->processTargetList.begin(),
        groupState->processTargetList.end(),
        [resolvedPid](const MonitorProcessTarget& target)
        {
            return target.pid == resolvedPid;
        });
    if (kExisted)
    {
        return;
    }

    MonitorProcessTarget target;
    target.pid = resolvedPid;
    target.processName = resolvedName;
    target.processIcon = resolvedIcon;
    groupState->processTargetList.push_back(std::move(target));

    groupState->processInputEdit->clear();
    groupState->processInputEdit->setProperty("selected_pid", QVariant());
    groupState->processInputEdit->setProperty("selected_process_name", QVariant());

    refreshProcessTableForGroup(groupId);
    applyMonitorFilters();
}

void NetworkDock::removeProcessTarget(const int groupId, const std::uint32_t pidValue)
{
    MonitorFilterRuleGroupUiState* groupState = findMonitorFilterRuleGroupById(groupId);
    if (groupState == nullptr)
    {
        return;
    }

    const auto kEraseBegin = std::remove_if(
        groupState->processTargetList.begin(),
        groupState->processTargetList.end(),
        [pidValue](const MonitorProcessTarget& target)
        {
            return target.pid == pidValue;
        });
    if (kEraseBegin == groupState->processTargetList.end())
    {
        return;
    }

    groupState->processTargetList.erase(kEraseBegin, groupState->processTargetList.end());
    refreshProcessTableForGroup(groupId);
    applyMonitorFilters();
}

void NetworkDock::clearProcessTargetList(const int groupId)
{
    MonitorFilterRuleGroupUiState* groupState = findMonitorFilterRuleGroupById(groupId);
    if (groupState == nullptr)
    {
        return;
    }

    groupState->processTargetList.clear();
    refreshProcessTableForGroup(groupId);
    applyMonitorFilters();
}

void NetworkDock::removeInvalidProcessTargets(const int groupId)
{
    MonitorFilterRuleGroupUiState* groupState = findMonitorFilterRuleGroupById(groupId);
    if (groupState == nullptr || groupState->processTargetList.empty())
    {
        return;
    }

    std::vector<ks::process::ProcessRecord> latestProcessList = ks::process::enumerateProcesses(
        ks::process::ProcessEnumStrategy::kAuto);
    std::unordered_map<std::uint32_t, QString> processNameMap;
    processNameMap.reserve(latestProcessList.size());
    for (const ks::process::ProcessRecord& processRecord : latestProcessList)
    {
        processNameMap[processRecord.pid] = toQString(processRecord.processName);
    }

    const std::size_t kBeforeCount = groupState->processTargetList.size();
    const auto kEraseBegin = std::remove_if(
        groupState->processTargetList.begin(),
        groupState->processTargetList.end(),
        [&processNameMap](const MonitorProcessTarget& target)
        {
            const auto kIterator = processNameMap.find(target.pid);
            if (kIterator == processNameMap.end())
            {
                return true;
            }

            const QString kCurrentName = kIterator->second.trimmed();
            return kCurrentName.isEmpty() ||
                kCurrentName.compare(target.processName.trimmed(), Qt::CaseInsensitive) != 0;
        });
    groupState->processTargetList.erase(kEraseBegin, groupState->processTargetList.end());

    const std::size_t kRemovedCount = kBeforeCount - groupState->processTargetList.size();
    refreshProcessTableForGroup(groupId);
    applyMonitorFilters();

    if (kRemovedCount > 0)
    {
        QMessageBox::information(this,
            QStringLiteral("流量筛选"),
            QStringLiteral("已移除 %1 条失效进程项。").arg(static_cast<qulonglong>(kRemovedCount)));
    }
}

void NetworkDock::addTextFilterItemsByInput(const int groupId, const MonitorTextRuleFieldKind fieldKind)
{
    MonitorFilterRuleGroupUiState* groupState = findMonitorFilterRuleGroupById(groupId);
    if (groupState == nullptr)
    {
        return;
    }

    MonitorTextRuleFieldUiState* fieldState = findTextRuleField(*groupState, fieldKind);
    if (fieldState == nullptr || fieldState->inputEdit == nullptr)
    {
        return;
    }

    const QString kInputText = fieldState->inputEdit->text().trimmed();
    if (kInputText.isEmpty())
    {
        return;
    }

    const QStringList kTokenList = splitMonitorFilterTokens(kInputText);
    if (kTokenList.isEmpty())
    {
        return;
    }

    for (const QString& token : kTokenList)
    {
        QString normalizedText;
        bool parseOk = false;

        if (fieldKind == MonitorTextRuleFieldKind::kLocalAddress || fieldKind == MonitorTextRuleFieldKind::kRemoteAddress)
        {
            UInt32Range ipv4Range{};
            parseOk = tryParseIpv4RangeText(token, ipv4Range, normalizedText);
        }
        else if (fieldKind == MonitorTextRuleFieldKind::kLocalPort || fieldKind == MonitorTextRuleFieldKind::kRemotePort)
        {
            UInt16Range portRange{};
            parseOk = tryParsePortRangeText(token, portRange, normalizedText);
        }
        else
        {
            UInt32Range sizeRange{};
            parseOk = tryParsePacketSizeToken(token, sizeRange, normalizedText);
        }

        if (!parseOk)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("流量筛选"),
                QStringLiteral("规则组输入无效：%1（%2）")
                .arg(fieldState->labelText)
                .arg(token));
            return;
        }

        if (!fieldState->valueList.contains(normalizedText, Qt::CaseInsensitive))
        {
            fieldState->valueList.push_back(normalizedText);
        }
    }

    fieldState->inputEdit->clear();
    refreshTextTableForGroup(groupId, fieldKind);
    applyMonitorFilters();
}

void NetworkDock::removeTextFilterItem(const int groupId, const MonitorTextRuleFieldKind fieldKind, const int itemIndex)
{
    MonitorFilterRuleGroupUiState* groupState = findMonitorFilterRuleGroupById(groupId);
    if (groupState == nullptr)
    {
        return;
    }

    MonitorTextRuleFieldUiState* fieldState = findTextRuleField(*groupState, fieldKind);
    if (fieldState == nullptr || itemIndex < 0 || itemIndex >= fieldState->valueList.size())
    {
        return;
    }

    fieldState->valueList.removeAt(itemIndex);
    refreshTextTableForGroup(groupId, fieldKind);
    applyMonitorFilters();
}

void NetworkDock::clearTextFilterItems(const int groupId, const MonitorTextRuleFieldKind fieldKind)
{
    MonitorFilterRuleGroupUiState* groupState = findMonitorFilterRuleGroupById(groupId);
    if (groupState == nullptr)
    {
        return;
    }

    MonitorTextRuleFieldUiState* fieldState = findTextRuleField(*groupState, fieldKind);
    if (fieldState == nullptr)
    {
        return;
    }

    fieldState->valueList.clear();
    refreshTextTableForGroup(groupId, fieldKind);
    applyMonitorFilters();
}

void NetworkDock::clearAllMonitorFilterConfigurations()
{
    for (const std::unique_ptr<MonitorFilterRuleGroupUiState>& groupState : monitorFilterRuleGroupUiList_)
    {
        if (groupState != nullptr && groupState->containerWidget != nullptr)
        {
            delete groupState->containerWidget;
        }
    }

    monitorFilterRuleGroupUiList_.clear();
    monitorFilterNextGroupId_ = 1;
    addMonitorFilterRuleGroup();
    rebuildMonitorFilterRuleGroupUi();
    resetPacketTimelineToCurrentRange();
    applyMonitorFilters();
}

void NetworkDock::addOrTrackProcessPid(const std::uint32_t pidValue)
{
    if (pidValue == 0)
    {
        return;
    }

    if (monitorFilterRuleGroupUiList_.empty())
    {
        addMonitorFilterRuleGroup();
    }

    MonitorFilterRuleGroupUiState* groupState = monitorFilterRuleGroupUiList_.empty()
        ? nullptr
        : monitorFilterRuleGroupUiList_.front().get();
    if (groupState == nullptr)
    {
        return;
    }

    const bool kExisted = std::any_of(
        groupState->processTargetList.begin(),
        groupState->processTargetList.end(),
        [pidValue](const MonitorProcessTarget& target)
        {
            return target.pid == pidValue;
        });
    if (!kExisted)
    {
        refreshMonitorProcessCandidateList(true);

        MonitorProcessTarget target;
        target.pid = pidValue;
        target.processName = toQString(ks::process::getProcessNameByPid(pidValue)).trimmed();
        if (target.processName.isEmpty())
        {
            target.processName = QStringLiteral("PID_%1").arg(pidValue);
        }
        target.processIcon = resolveProcessIconByPid(pidValue, target.processName.toStdString());
        groupState->processTargetList.push_back(std::move(target));
        refreshProcessTableForGroup(groupState->groupId);
    }

    if (groupState->enabledCheck != nullptr)
    {
        groupState->enabledCheck->setChecked(true);
    }

    applyMonitorFilters();
}

bool NetworkDock::tryCompileMonitorFilterGroups(
    std::vector<MonitorFilterRuleGroupCompiled>& compiledGroupsOut,
    QString& errorTextOut) const
{
    compiledGroupsOut.clear();
    errorTextOut.clear();

    int displayIndex = 1;
    for (const std::unique_ptr<MonitorFilterRuleGroupUiState>& groupState : monitorFilterRuleGroupUiList_)
    {
        if (groupState == nullptr)
        {
            continue;
        }

        const bool kEnabled = (groupState->enabledCheck == nullptr) ? true : groupState->enabledCheck->isChecked();
        if (!kEnabled)
        {
            ++displayIndex;
            continue;
        }

        MonitorFilterRuleGroupCompiled compiledGroup;
        compiledGroup.groupId = groupState->groupId;
        compiledGroup.enabled = true;

        for (const MonitorProcessTarget& target : groupState->processTargetList)
        {
            if (target.pid != 0)
            {
                compiledGroup.processIdList.push_back(target.pid);
            }
        }

        const auto kParseFieldList = [&](const MonitorTextRuleFieldKind fieldKind) -> bool
            {
                const MonitorTextRuleFieldUiState* fieldState = findTextRuleField(*groupState, fieldKind);
                if (fieldState == nullptr)
                {
                    return true;
                }

                for (const QString& ruleText : fieldState->valueList)
                {
                    if (fieldKind == MonitorTextRuleFieldKind::kLocalAddress ||
                        fieldKind == MonitorTextRuleFieldKind::kRemoteAddress)
                    {
                        UInt32Range range{};
                        QString normalizedText;
                        if (!tryParseIpv4RangeText(ruleText, range, normalizedText))
                        {
                            errorTextOut = QStringLiteral("规则组%1 中 %2 条目无效：%3")
                                .arg(displayIndex)
                                .arg(fieldState->labelText)
                                .arg(ruleText);
                            return false;
                        }
                        if (fieldKind == MonitorTextRuleFieldKind::kLocalAddress)
                        {
                            compiledGroup.localAddressRangeList.push_back(range);
                        }
                        else
                        {
                            compiledGroup.remoteAddressRangeList.push_back(range);
                        }
                    }
                    else if (fieldKind == MonitorTextRuleFieldKind::kLocalPort ||
                        fieldKind == MonitorTextRuleFieldKind::kRemotePort)
                    {
                        UInt16Range range{};
                        QString normalizedText;
                        if (!tryParsePortRangeText(ruleText, range, normalizedText))
                        {
                            errorTextOut = QStringLiteral("规则组%1 中 %2 条目无效：%3")
                                .arg(displayIndex)
                                .arg(fieldState->labelText)
                                .arg(ruleText);
                            return false;
                        }
                        if (fieldKind == MonitorTextRuleFieldKind::kLocalPort)
                        {
                            compiledGroup.localPortRangeList.push_back(range);
                        }
                        else
                        {
                            compiledGroup.remotePortRangeList.push_back(range);
                        }
                    }
                    else
                    {
                        UInt32Range range{};
                        QString normalizedText;
                        if (!tryParsePacketSizeToken(ruleText, range, normalizedText))
                        {
                            errorTextOut = QStringLiteral("规则组%1 中 %2 条目无效：%3")
                                .arg(displayIndex)
                                .arg(fieldState->labelText)
                                .arg(ruleText);
                            return false;
                        }
                        compiledGroup.packetSizeRangeList.push_back(range);
                    }
                }

                return true;
            };

        if (!kParseFieldList(MonitorTextRuleFieldKind::kLocalAddress) ||
            !kParseFieldList(MonitorTextRuleFieldKind::kRemoteAddress) ||
            !kParseFieldList(MonitorTextRuleFieldKind::kLocalPort) ||
            !kParseFieldList(MonitorTextRuleFieldKind::kRemotePort) ||
            !kParseFieldList(MonitorTextRuleFieldKind::kPacketSize))
        {
            return false;
        }

        if (compiledGroup.hasAnyCondition())
        {
            compiledGroupsOut.push_back(std::move(compiledGroup));
        }

        ++displayIndex;
    }

    return true;
}

void NetworkDock::applyMonitorFilters()
{
    std::vector<MonitorFilterRuleGroupCompiled> compiledGroupList;
    QString compileErrorText;
    if (!tryCompileMonitorFilterGroups(compiledGroupList, compileErrorText))
    {
        QMessageBox::warning(this, QStringLiteral("流量筛选"), compileErrorText);
        return;
    }

    activeMonitorFilterGroupList_ = std::move(compiledGroupList);

    updateMonitorFilterStateLabel();
    rebuildMonitorTableByFilter();

    KLogEvent filterApplyEvent;
    info << filterApplyEvent
        << "[NetworkDock] 应用规则组过滤, activeGroupCount="
        << activeMonitorFilterGroupList_.size()
        << eol;
}

void NetworkDock::clearMonitorFilters()
{
    clearAllMonitorFilterConfigurations();

    KLogEvent clearFilterEvent;
    info << clearFilterEvent << "[NetworkDock] 已清空全部流量筛选条件。" << eol;
}

void NetworkDock::updateMonitorFilterStateLabel()
{
    if (monitorFilterStateLabel_ == nullptr)
    {
        return;
    }

    const bool kTimelineFilterActive = isPacketTimelineFilterActive();
    if (activeMonitorFilterGroupList_.empty())
    {
        monitorFilterStateLabel_->setText(kTimelineFilterActive
            ? QStringLiteral("当前过滤：时间轴已筛选")
            : QStringLiteral("当前过滤：无"));
        return;
    }

    QStringList groupSummaryList;
    groupSummaryList.reserve(static_cast<int>(activeMonitorFilterGroupList_.size()));
    int displayIndex = 1;
    for (const MonitorFilterRuleGroupCompiled& groupFilter : activeMonitorFilterGroupList_)
    {
        QStringList conditionList;
        if (!groupFilter.processIdList.empty())
        {
            conditionList.push_back(QStringLiteral("进程%1项").arg(groupFilter.processIdList.size()));
        }
        if (!groupFilter.localAddressRangeList.empty())
        {
            conditionList.push_back(QStringLiteral("本地地址%1项").arg(groupFilter.localAddressRangeList.size()));
        }
        if (!groupFilter.remoteAddressRangeList.empty())
        {
            conditionList.push_back(QStringLiteral("远程地址%1项").arg(groupFilter.remoteAddressRangeList.size()));
        }
        if (!groupFilter.localPortRangeList.empty())
        {
            conditionList.push_back(QStringLiteral("本地端口%1项").arg(groupFilter.localPortRangeList.size()));
        }
        if (!groupFilter.remotePortRangeList.empty())
        {
            conditionList.push_back(QStringLiteral("远程端口%1项").arg(groupFilter.remotePortRangeList.size()));
        }
        if (!groupFilter.packetSizeRangeList.empty())
        {
            conditionList.push_back(QStringLiteral("包长%1项").arg(groupFilter.packetSizeRangeList.size()));
        }

        groupSummaryList.push_back(QStringLiteral("规则组%1[%2]")
            .arg(displayIndex)
            .arg(conditionList.join(QStringLiteral(" | "))));
        ++displayIndex;
    }

    QString summaryText = QStringLiteral("当前过滤：%1").arg(groupSummaryList.join(QStringLiteral("  OR  ")));
    if (kTimelineFilterActive)
    {
        // The timeline is an outer time window independent of rule groups; append this hint to avoid users thinking only rule group filtering is applied.
        summaryText += QStringLiteral(" | 时间轴已筛选");
    }
    monitorFilterStateLabel_->setText(summaryText);
}

bool NetworkDock::packetMatchesMonitorFilterGroup(
    const ks::network::PacketRecord& packetRecord,
    const MonitorFilterRuleGroupCompiled& groupFilter) const
{
    if (!groupFilter.processIdList.empty())
    {
        const bool kProcessMatched = std::find(
            groupFilter.processIdList.begin(),
            groupFilter.processIdList.end(),
            packetRecord.processId) != groupFilter.processIdList.end();
        if (!kProcessMatched)
        {
            return false;
        }
    }

    if (!groupFilter.localAddressRangeList.empty())
    {
        std::uint32_t localIpHostOrder = 0;
        if (!tryParseIpv4Text(toQString(packetRecord.localAddress), localIpHostOrder))
        {
            return false;
        }

        const bool kMatched = std::any_of(
            groupFilter.localAddressRangeList.begin(),
            groupFilter.localAddressRangeList.end(),
            [localIpHostOrder](const UInt32Range& range)
            {
                return localIpHostOrder >= range.first && localIpHostOrder <= range.second;
            });
        if (!kMatched)
        {
            return false;
        }
    }

    if (!groupFilter.remoteAddressRangeList.empty())
    {
        std::uint32_t remoteIpHostOrder = 0;
        if (!tryParseIpv4Text(toQString(packetRecord.remoteAddress), remoteIpHostOrder))
        {
            return false;
        }

        const bool kMatched = std::any_of(
            groupFilter.remoteAddressRangeList.begin(),
            groupFilter.remoteAddressRangeList.end(),
            [remoteIpHostOrder](const UInt32Range& range)
            {
                return remoteIpHostOrder >= range.first && remoteIpHostOrder <= range.second;
            });
        if (!kMatched)
        {
            return false;
        }
    }

    if (!groupFilter.localPortRangeList.empty())
    {
        const bool kMatched = std::any_of(
            groupFilter.localPortRangeList.begin(),
            groupFilter.localPortRangeList.end(),
            [localPort = packetRecord.localPort](const UInt16Range& range)
            {
                return localPort >= range.first && localPort <= range.second;
            });
        if (!kMatched)
        {
            return false;
        }
    }

    if (!groupFilter.remotePortRangeList.empty())
    {
        const bool kMatched = std::any_of(
            groupFilter.remotePortRangeList.begin(),
            groupFilter.remotePortRangeList.end(),
            [remotePort = packetRecord.remotePort](const UInt16Range& range)
            {
                return remotePort >= range.first && remotePort <= range.second;
            });
        if (!kMatched)
        {
            return false;
        }
    }

    if (!groupFilter.packetSizeRangeList.empty())
    {
        const bool kMatched = std::any_of(
            groupFilter.packetSizeRangeList.begin(),
            groupFilter.packetSizeRangeList.end(),
            [packetSize = packetRecord.totalPacketSize](const UInt32Range& range)
            {
                return packetSize >= range.first && packetSize <= range.second;
            });
        if (!kMatched)
        {
            return false;
        }
    }

    return true;
}

bool NetworkDock::saveMonitorFilterConfigToPath(const QString& filePath, const bool showErrorDialog) const
{
    const QString kNormalizedPath = QFileInfo(filePath).absoluteFilePath();
    if (kNormalizedPath.trimmed().isEmpty())
    {
        if (showErrorDialog)
        {
            QMessageBox::warning(nullptr, QStringLiteral("流量筛选"), QStringLiteral("配置保存路径无效。"));
        }
        return false;
    }

    QJsonObject rootObject;
    rootObject.insert(QString::fromLatin1(kMonitorFilterJsonVersionKey), 1);

    QJsonArray groupsArray;
    for (const std::unique_ptr<MonitorFilterRuleGroupUiState>& groupState : monitorFilterRuleGroupUiList_)
    {
        if (groupState == nullptr)
        {
            continue;
        }

        QJsonObject groupObject;
        groupObject.insert(
            QString::fromLatin1(kMonitorFilterJsonEnabledKey),
            (groupState->enabledCheck == nullptr) ? true : groupState->enabledCheck->isChecked());

        QJsonArray processArray;
        for (const MonitorProcessTarget& target : groupState->processTargetList)
        {
            if (target.pid == 0)
            {
                continue;
            }

            QJsonObject processObject;
            processObject.insert(QString::fromLatin1(kMonitorFilterJsonPidKey), static_cast<qint64>(target.pid));
            processObject.insert(QString::fromLatin1(kMonitorFilterJsonProcessNameKey), target.processName);
            processArray.push_back(processObject);
        }
        groupObject.insert(QString::fromLatin1(kMonitorFilterJsonProcessesKey), processArray);

        const auto kAppendTextFieldArray = [this, &groupObject, &groupState](
            const MonitorTextRuleFieldKind fieldKind,
            const char* jsonKey)
            {
                const MonitorTextRuleFieldUiState* fieldState = findTextRuleField(*groupState, fieldKind);
                QJsonArray array;
                if (fieldState != nullptr)
                {
                    for (const QString& text : fieldState->valueList)
                    {
                        array.push_back(text);
                    }
                }
                groupObject.insert(QString::fromLatin1(jsonKey), array);
            };

        kAppendTextFieldArray(MonitorTextRuleFieldKind::kLocalAddress, kMonitorFilterJsonLocalAddressesKey);
        kAppendTextFieldArray(MonitorTextRuleFieldKind::kRemoteAddress, kMonitorFilterJsonRemoteAddressesKey);
        kAppendTextFieldArray(MonitorTextRuleFieldKind::kLocalPort, kMonitorFilterJsonLocalPortsKey);
        kAppendTextFieldArray(MonitorTextRuleFieldKind::kRemotePort, kMonitorFilterJsonRemotePortsKey);
        kAppendTextFieldArray(MonitorTextRuleFieldKind::kPacketSize, kMonitorFilterJsonPacketSizesKey);

        groupsArray.push_back(groupObject);
    }

    rootObject.insert(QString::fromLatin1(kMonitorFilterJsonGroupsKey), groupsArray);

    const QFileInfo kFileInfo(kNormalizedPath);
    QDir outputDirectory(kFileInfo.absolutePath());
    if (!outputDirectory.exists() && !outputDirectory.mkpath(QStringLiteral(".")))
    {
        if (showErrorDialog)
        {
            QMessageBox::warning(
                nullptr,
                QStringLiteral("流量筛选"),
                QStringLiteral("创建配置目录失败：%1").arg(outputDirectory.absolutePath()));
        }
        return false;
    }

    QFile outputFile(kNormalizedPath);
    if (!outputFile.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text))
    {
        if (showErrorDialog)
        {
            QMessageBox::warning(
                nullptr,
                QStringLiteral("流量筛选"),
                QStringLiteral("打开配置文件失败：%1").arg(kNormalizedPath));
        }
        return false;
    }

    outputFile.write(QJsonDocument(rootObject).toJson(QJsonDocument::Indented));
    outputFile.close();

    return true;
}

bool NetworkDock::loadMonitorFilterConfigFromPath(const QString& filePath, const bool showErrorDialog)
{
    const QString kNormalizedPath = QFileInfo(filePath).absoluteFilePath();
    QFile inputFile(kNormalizedPath);
    if (!inputFile.exists())
    {
        if (showErrorDialog)
        {
            QMessageBox::warning(this, QStringLiteral("流量筛选"), QStringLiteral("配置文件不存在：%1").arg(kNormalizedPath));
        }
        return false;
    }

    if (!inputFile.open(QIODevice::ReadOnly | QIODevice::Text))
    {
        if (showErrorDialog)
        {
            QMessageBox::warning(this, QStringLiteral("流量筛选"), QStringLiteral("读取配置文件失败：%1").arg(kNormalizedPath));
        }
        return false;
    }

    QJsonParseError parseError;
    const QJsonDocument kJsonDocument = QJsonDocument::fromJson(inputFile.readAll(), &parseError);
    inputFile.close();

    if (parseError.error != QJsonParseError::NoError || !kJsonDocument.isObject())
    {
        if (showErrorDialog)
        {
            QMessageBox::warning(this, QStringLiteral("流量筛选"), QStringLiteral("配置文件格式无效：%1").arg(kNormalizedPath));
        }
        return false;
    }

    const QJsonObject kRootObject = kJsonDocument.object();
    const QJsonArray kGroupArray = kRootObject.value(QString::fromLatin1(kMonitorFilterJsonGroupsKey)).toArray();

    for (const std::unique_ptr<MonitorFilterRuleGroupUiState>& groupState : monitorFilterRuleGroupUiList_)
    {
        if (groupState != nullptr && groupState->containerWidget != nullptr)
        {
            delete groupState->containerWidget;
        }
    }
    monitorFilterRuleGroupUiList_.clear();
    monitorFilterNextGroupId_ = 1;

    if (kGroupArray.isEmpty())
    {
        addMonitorFilterRuleGroup();
        applyMonitorFilters();
        return true;
    }

    for (const QJsonValue& groupValue : kGroupArray)
    {
        if (!groupValue.isObject())
        {
            continue;
        }

        addMonitorFilterRuleGroup();
        MonitorFilterRuleGroupUiState* groupState = monitorFilterRuleGroupUiList_.back().get();
        if (groupState == nullptr)
        {
            continue;
        }

        const QJsonObject kGroupObject = groupValue.toObject();
        if (groupState->enabledCheck != nullptr)
        {
            const QSignalBlocker kBlocker(groupState->enabledCheck);
            groupState->enabledCheck->setChecked(kGroupObject.value(QString::fromLatin1(kMonitorFilterJsonEnabledKey)).toBool(true));
        }

        groupState->processTargetList.clear();
        const QJsonArray kProcessArray = kGroupObject.value(QString::fromLatin1(kMonitorFilterJsonProcessesKey)).toArray();
        for (const QJsonValue& processValue : kProcessArray)
        {
            if (!processValue.isObject())
            {
                continue;
            }

            const QJsonObject kProcessObject = processValue.toObject();
            const std::uint32_t kPid = static_cast<std::uint32_t>(
                kProcessObject.value(QString::fromLatin1(kMonitorFilterJsonPidKey)).toVariant().toULongLong());
            if (kPid == 0)
            {
                continue;
            }

            MonitorProcessTarget target;
            target.pid = kPid;
            target.processName = kProcessObject.value(QString::fromLatin1(kMonitorFilterJsonProcessNameKey)).toString().trimmed();
            if (target.processName.isEmpty())
            {
                target.processName = toQString(ks::process::getProcessNameByPid(kPid));
            }
            if (target.processName.isEmpty())
            {
                target.processName = QStringLiteral("PID_%1").arg(kPid);
            }
            target.processIcon = resolveProcessIconByPid(kPid, target.processName.toStdString());
            groupState->processTargetList.push_back(std::move(target));
        }

        const auto kLoadTextField = [this, &kGroupObject, groupState](
            const MonitorTextRuleFieldKind fieldKind,
            const char* jsonKey)
            {
                MonitorTextRuleFieldUiState* fieldState = findTextRuleField(*groupState, fieldKind);
                if (fieldState == nullptr)
                {
                    return;
                }

                fieldState->valueList.clear();
                const QStringList kRawList = jsonArrayToStringList(kGroupObject.value(QString::fromLatin1(jsonKey)));
                for (const QString& token : kRawList)
                {
                    QString normalizedText;
                    bool parseOk = false;

                    if (fieldKind == MonitorTextRuleFieldKind::kLocalAddress ||
                        fieldKind == MonitorTextRuleFieldKind::kRemoteAddress)
                    {
                        UInt32Range range{};
                        parseOk = tryParseIpv4RangeText(token, range, normalizedText);
                    }
                    else if (fieldKind == MonitorTextRuleFieldKind::kLocalPort ||
                        fieldKind == MonitorTextRuleFieldKind::kRemotePort)
                    {
                        UInt16Range range{};
                        parseOk = tryParsePortRangeText(token, range, normalizedText);
                    }
                    else
                    {
                        UInt32Range range{};
                        parseOk = tryParsePacketSizeToken(token, range, normalizedText);
                    }

                    if (parseOk && !fieldState->valueList.contains(normalizedText, Qt::CaseInsensitive))
                    {
                        fieldState->valueList.push_back(normalizedText);
                    }
                }
            };

        kLoadTextField(MonitorTextRuleFieldKind::kLocalAddress, kMonitorFilterJsonLocalAddressesKey);
        kLoadTextField(MonitorTextRuleFieldKind::kRemoteAddress, kMonitorFilterJsonRemoteAddressesKey);
        kLoadTextField(MonitorTextRuleFieldKind::kLocalPort, kMonitorFilterJsonLocalPortsKey);
        kLoadTextField(MonitorTextRuleFieldKind::kRemotePort, kMonitorFilterJsonRemotePortsKey);
        kLoadTextField(MonitorTextRuleFieldKind::kPacketSize, kMonitorFilterJsonPacketSizesKey);

        refreshProcessTableForGroup(groupState->groupId);
        refreshTextTableForGroup(groupState->groupId, MonitorTextRuleFieldKind::kLocalAddress);
        refreshTextTableForGroup(groupState->groupId, MonitorTextRuleFieldKind::kRemoteAddress);
        refreshTextTableForGroup(groupState->groupId, MonitorTextRuleFieldKind::kLocalPort);
        refreshTextTableForGroup(groupState->groupId, MonitorTextRuleFieldKind::kRemotePort);
        refreshTextTableForGroup(groupState->groupId, MonitorTextRuleFieldKind::kPacketSize);
    }

    if (monitorFilterRuleGroupUiList_.empty())
    {
        addMonitorFilterRuleGroup();
    }

    rebuildMonitorFilterRuleGroupUi();
    applyMonitorFilters();
    return true;
}

void NetworkDock::loadMonitorFilterConfigFromDefaultPath()
{
    const QString kDefaultPath = monitorFilterConfigPath();
    const bool kLoadedOk = loadMonitorFilterConfigFromPath(kDefaultPath, false);
    if (!kLoadedOk && monitorFilterRuleGroupUiList_.empty())
    {
        addMonitorFilterRuleGroup();
        applyMonitorFilters();
    }
}

void NetworkDock::saveMonitorFilterConfigToDefaultPath() const
{
    const QString kDefaultPath = monitorFilterConfigPath();
    if (saveMonitorFilterConfigToPath(kDefaultPath, true))
    {
        QMessageBox::information(const_cast<NetworkDock*>(this),
            QStringLiteral("流量筛选"),
            QStringLiteral("筛选配置已保存到：%1").arg(kDefaultPath));
    }
}

void NetworkDock::importMonitorFilterConfigFromUserSelectedPath()
{
    const QString kSelectedPath = QFileDialog::getOpenFileName(
        this,
        QStringLiteral("导入流量筛选配置"),
        QFileInfo(monitorFilterConfigPath()).absolutePath(),
        QStringLiteral("Wireshark Config (*.cfg *.json);;All Files (*.*)"));
    if (kSelectedPath.trimmed().isEmpty())
    {
        return;
    }

    if (loadMonitorFilterConfigFromPath(kSelectedPath, true))
    {
        saveMonitorFilterConfigToPath(monitorFilterConfigPath(), false);
        QMessageBox::information(this,
            QStringLiteral("流量筛选"),
            QStringLiteral("已导入配置：%1").arg(QFileInfo(kSelectedPath).absoluteFilePath()));
    }
}

void NetworkDock::exportMonitorFilterConfigToUserSelectedPath() const
{
    const QString kDefaultPath = monitorFilterConfigPath();
    QWidget* parentWidget = const_cast<NetworkDock*>(this);
    const QString kSelectedPath = QFileDialog::getSaveFileName(
        parentWidget,
        QStringLiteral("导出流量筛选配置"),
        kDefaultPath,
        QStringLiteral("Wireshark Config (*.cfg);;JSON (*.json);;All Files (*.*)"));
    if (kSelectedPath.trimmed().isEmpty())
    {
        return;
    }

    if (saveMonitorFilterConfigToPath(kSelectedPath, true))
    {
        QMessageBox::information(parentWidget,
            QStringLiteral("流量筛选"),
            QStringLiteral("已导出配置：%1").arg(QFileInfo(kSelectedPath).absoluteFilePath()));
    }
}

void NetworkDock::trackProcessByTableRow(const int row)
{
    if (packetTable_ == nullptr || row < 0 || row >= packetTable_->rowCount())
    {
        return;
    }

    QTableWidgetItem* pidItem = packetTable_->item(row, toPacketColumn(PacketTableColumn::kPid));
    if (pidItem == nullptr)
    {
        return;
    }

    std::uint32_t targetPid = 0;
    if (!tryParsePidText(pidItem->text(), targetPid))
    {
        QMessageBox::information(this, QStringLiteral("跟踪进程"), QStringLiteral("该行 PID 无效，无法跟踪。"));
        return;
    }

    addOrTrackProcessPid(targetPid);

    KLogEvent trackEvent;
    info << trackEvent << "[NetworkDock] 跟踪此进程触发, pid=" << targetPid << eol;
}

void NetworkDock::gotoProcessDetailByTableRow(const int row)
{
    if (packetTable_ == nullptr || row < 0 || row >= packetTable_->rowCount())
    {
        return;
    }

    QTableWidgetItem* pidItem = packetTable_->item(row, toPacketColumn(PacketTableColumn::kPid));
    if (pidItem == nullptr)
    {
        return;
    }

    std::uint32_t targetPid = 0;
    if (!tryParsePidText(pidItem->text(), targetPid))
    {
        QMessageBox::information(this, QStringLiteral("进程详情"), QStringLiteral("该行 PID 无效，无法打开进程详情。"));
        return;
    }

    // Network table jump creates only a lightweight record:
    // - Full static details and signature verification are performed in the background of ProcessDetailWindow.
    // - Prevents right-click menu actions from blocking the UI thread while waiting for process tokens or certificate chain queries.
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
        << "[NetworkDock] 打开进程详情窗口, pid=" << targetPid
        << eol;
}
