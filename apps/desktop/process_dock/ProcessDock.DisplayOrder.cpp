#include "ProcessDock.Support.h"
#include "ProcessActivityChartWidget.h"
#include "ProcessActivityTimelineSlider.h"

using namespace ksword::ui::process_dock;

std::vector<ProcessDock::DisplayRow> ProcessDock::buildDisplayOrder() const
{
    if (isProcessActivityTableSnapshotActive())
    {
        return buildActivitySnapshotDisplayOrder();
    }

    // When search is active, return flat results uniformly:
    // - The user's search target is 'quickly locate processes', so tree structures should not interfere.
    // - Flat results also avoid leaving orphaned indentation when parent nodes miss.
    if (!currentProcessSearchText().isEmpty())
    {
        return buildListDisplayOrder();
    }

    if (isFriendlyViewEnabled())
    {
        return buildFriendlyDisplayOrder();
    }

    return isTreeModeEnabled() ? buildTreeDisplayOrder() : buildListDisplayOrder();
}

std::vector<ProcessDock::DisplayRow> ProcessDock::buildActivitySnapshotDisplayOrder() const
{
    // Historical timeline mode:
    // - The process table below directly displays the process snapshot from the sample at that time.
    // - Avoid mixing historical moments with current system state by not using real-time cache or tree-based parent-child sorting.
    std::vector<DisplayRow> displayRows;
    displayRows.reserve(activityTableSnapshotRecords_.size());
    for (const ks::process::ProcessRecord& processRecord : activityTableSnapshotRecords_)
    {
        if (!processRecordMatchesSearch(processRecord))
        {
            continue;
        }

        DisplayRow displayRow{};
        displayRow.record = const_cast<ks::process::ProcessRecord*>(&processRecord);
        displayRow.depth = 0;
        displayRow.isNew = false;
        displayRow.isExited = false;
        displayRow.isKernelOnly = false;
        displayRows.push_back(displayRow);
    }

    std::sort(displayRows.begin(), displayRows.end(), [](const DisplayRow& leftRow, const DisplayRow& rightRow) {
        if (leftRow.record == nullptr || rightRow.record == nullptr)
        {
            return false;
        }
        return leftRow.record->pid < rightRow.record->pid;
    });
    return displayRows;
}

std::vector<ProcessDock::DisplayRow> ProcessDock::buildListDisplayOrder() const
{
    std::vector<DisplayRow> displayRows;
    displayRows.reserve(cacheByIdentity_.size());

    for (const auto& cachePair : cacheByIdentity_)
    {
        const bool kIsKswordHidden =
            ((cachePair.second.record.r0Flags & KSWORD_ARK_PROCESS_FLAG_HIDDEN_BY_KSWORD_UI) != 0U) ||
            (hiddenProcessPidSet_.find(cachePair.second.record.pid) != hiddenProcessPidSet_.end());
        const bool kShowKswordHidden =
            (showKswordHiddenProcessCheck_ != nullptr && showKswordHiddenProcessCheck_->isChecked());
        if (kIsKswordHidden && !kShowKswordHidden)
        {
            continue;
        }
        if (!processRecordMatchesSearch(cachePair.second.record))
        {
            continue;
        }

        DisplayRow displayRow{};
        displayRow.record = const_cast<ks::process::ProcessRecord*>(&cachePair.second.record);
        displayRow.depth = 0;
        displayRow.isNew = cachePair.second.isNewInLatestRound;
        displayRow.isExited = cachePair.second.isExitedInLatestRound;
        displayRow.isKernelOnly = cachePair.second.isKernelOnlyInLatestRound;
        displayRows.push_back(displayRow);
    }

    std::sort(displayRows.begin(), displayRows.end(), [](const DisplayRow& leftRow, const DisplayRow& rightRow) {
        if (leftRow.record == nullptr || rightRow.record == nullptr)
        {
            return false;
        }
        return leftRow.record->pid < rightRow.record->pid;
    });
    return displayRows;
}

std::vector<ProcessDock::DisplayRow> ProcessDock::buildTreeDisplayOrder() const
{
    // Step1: Convert the cache into a pointer array for easier processing.
    struct Node
    {
        const std::string* identityKey = nullptr;
        const CacheEntry* cacheEntry = nullptr;
    };
    std::vector<Node> nodes;
    nodes.reserve(cacheByIdentity_.size());
    for (const auto& cachePair : cacheByIdentity_)
    {
        const bool kIsKswordHidden =
            ((cachePair.second.record.r0Flags & KSWORD_ARK_PROCESS_FLAG_HIDDEN_BY_KSWORD_UI) != 0U) ||
            (hiddenProcessPidSet_.find(cachePair.second.record.pid) != hiddenProcessPidSet_.end());
        const bool kShowKswordHidden =
            (showKswordHiddenProcessCheck_ != nullptr && showKswordHiddenProcessCheck_->isChecked());
        if (kIsKswordHidden && !kShowKswordHidden)
        {
            continue;
        }
        nodes.push_back(Node{ &cachePair.first, &cachePair.second });
    }

    // Step2: Following the ProcessModel in KswordARKLight, first build a PID source index, then associate valid parent nodes.
    std::unordered_map<std::uint32_t, std::vector<Node>> childrenByParentPid;
    std::unordered_map<std::uint32_t, const Node*> sourceNodeByPid;
    sourceNodeByPid.reserve(nodes.size());
    for (const Node& node : nodes)
    {
        if (node.cacheEntry == nullptr)
        {
            continue;
        }
        const std::uint32_t kProcessId = node.cacheEntry->record.pid;
        const auto kExistingSourceIt = sourceNodeByPid.find(kProcessId);
        if (kExistingSourceIt == sourceNodeByPid.end() ||
            (kExistingSourceIt->second->cacheEntry->isExitedInLatestRound && !node.cacheEntry->isExitedInLatestRound) ||
            node.cacheEntry->record.creationTime100ns > kExistingSourceIt->second->cacheEntry->record.creationTime100ns)
        {
            sourceNodeByPid[kProcessId] = &node;
        }
    }

    const auto kNodeLess = [](const Node& leftNode, const Node& rightNode)
    {
        if (leftNode.cacheEntry == nullptr || rightNode.cacheEntry == nullptr)
        {
            return leftNode.cacheEntry != nullptr;
        }
        const QString kLeftName = QString::fromStdString(leftNode.cacheEntry->record.processName);
        const QString kRightName = QString::fromStdString(rightNode.cacheEntry->record.processName);
        const int kNameResult = kLeftName.compare(kRightName, Qt::CaseInsensitive);
        if (kNameResult != 0)
        {
            return kNameResult < 0;
        }
        if (leftNode.cacheEntry->record.pid != rightNode.cacheEntry->record.pid)
        {
            return leftNode.cacheEntry->record.pid < rightNode.cacheEntry->record.pid;
        }
        return leftNode.cacheEntry->record.creationTime100ns < rightNode.cacheEntry->record.creationTime100ns;
    };

    for (const Node& node : nodes)
    {
        if (node.cacheEntry == nullptr)
        {
            continue;
        }
        const std::uint32_t kProcessId = node.cacheEntry->record.pid;
        const std::uint32_t kParentPid = node.cacheEntry->record.parentPid;
        if (kParentPid != 0U && kParentPid != kProcessId && sourceNodeByPid.find(kParentPid) != sourceNodeByPid.end())
        {
            childrenByParentPid[kParentPid].push_back(node);
        }
    }

    // The child list is sorted by "Name (case-insensitive) + PID" to match the stable order of KswordARKLight.
    for (auto& pair : childrenByParentPid)
    {
        auto& childNodes = pair.second;
        std::sort(childNodes.begin(), childNodes.end(), kNodeLess);
    }

    // Step3: Treat as root node if parent PID is missing, 0, or self-referential.
    std::vector<Node> rootNodes;
    for (const Node& node : nodes)
    {
        if (node.cacheEntry == nullptr)
        {
            continue;
        }
        const std::uint32_t kProcessId = node.cacheEntry->record.pid;
        const std::uint32_t kParentPid = node.cacheEntry->record.parentPid;
        if (kParentPid == 0U || kParentPid == kProcessId || sourceNodeByPid.find(kParentPid) == sourceNodeByPid.end())
        {
            rootNodes.push_back(node);
        }
    }
    std::sort(rootNodes.begin(), rootNodes.end(), kNodeLess);

    // Step4: DFS generates 'tree-list order + indentation depth'.
    std::vector<DisplayRow> displayRows;
    std::unordered_set<std::string> visitedIdentitySet;

    std::function<void(const Node&, int)> appendNode;
    appendNode = [&](const Node& node, const int depth)
        {
            if (node.identityKey == nullptr || node.cacheEntry == nullptr)
            {
                return;
            }
            if (visitedIdentitySet.find(*node.identityKey) != visitedIdentitySet.end())
            {
                return;
            }
            visitedIdentitySet.insert(*node.identityKey);

            DisplayRow displayRow{};
            displayRow.record = const_cast<ks::process::ProcessRecord*>(&node.cacheEntry->record);
            displayRow.depth = depth;
            displayRow.hasChildren =
                childrenByParentPid.find(node.cacheEntry->record.pid) != childrenByParentPid.end();
            displayRow.isNew = node.cacheEntry->isNewInLatestRound;
            displayRow.isExited = node.cacheEntry->isExitedInLatestRound;
            displayRow.isKernelOnly = node.cacheEntry->isKernelOnlyInLatestRound;
            displayRows.push_back(displayRow);

            const auto kChildIt = childrenByParentPid.find(node.cacheEntry->record.pid);
            if (kChildIt == childrenByParentPid.end())
            {
                return;
            }
            for (const Node& childNode : kChildIt->second)
            {
                appendNode(childNode, depth + 1);
            }
        };

    for (const Node& rootNode : rootNodes)
    {
        appendNode(rootNode, 0);
    }

    // Fallback: if unvisited nodes remain (extreme parent cycles), flatten and append them directly.
    for (const Node& node : nodes)
    {
        if (node.identityKey == nullptr || node.cacheEntry == nullptr)
        {
            continue;
        }
        if (visitedIdentitySet.find(*node.identityKey) != visitedIdentitySet.end())
        {
            continue;
        }
        DisplayRow fallbackRow{};
        fallbackRow.record = const_cast<ks::process::ProcessRecord*>(&node.cacheEntry->record);
        fallbackRow.depth = 0;
        fallbackRow.hasChildren = childrenByParentPid.find(node.cacheEntry->record.pid) != childrenByParentPid.end();
        fallbackRow.isNew = node.cacheEntry->isNewInLatestRound;
        fallbackRow.isExited = node.cacheEntry->isExitedInLatestRound;
        fallbackRow.isKernelOnly = node.cacheEntry->isKernelOnlyInLatestRound;
        displayRows.push_back(fallbackRow);
    }

    return displayRows;
}

std::unordered_map<std::uint32_t, ProcessDock::FriendlyProcessGroupType>
ProcessDock::buildFriendlyGroupTypeByPid() const
{
    // Input: Current process cache.
    // Note: Reuse the three-category rules of the friendly view (visible window ownership -> application; Windows directory -> system; others -> background).
    // Return: mapping from PID to group type, used by the "Type" column to retrieve values in any view mode.
    std::unordered_map<std::uint32_t, FriendlyProcessGroupType> groupTypeByPid;
    groupTypeByPid.reserve(cacheByIdentity_.size() * 2U + 1U);

    std::unordered_map<std::uint32_t, std::uint32_t> parentPidByPid;
    parentPidByPid.reserve(cacheByIdentity_.size() * 2U + 1U);
    for (const auto& cachePair : cacheByIdentity_)
    {
        parentPidByPid[cachePair.second.record.pid] = cachePair.second.record.parentPid;
    }

    const QSet<std::uint32_t> kVisibleWindowPidSet = collectVisibleWindowPidSet();
    wchar_t windowsDirectoryBuffer[MAX_PATH]{};
    QString windowsDirectoryPath;
    const UINT kWindowsDirectoryLength = ::GetWindowsDirectoryW(windowsDirectoryBuffer, MAX_PATH);
    if (kWindowsDirectoryLength > 0U)
    {
        windowsDirectoryPath = QDir::fromNativeSeparators(
            QString::fromWCharArray(windowsDirectoryBuffer, static_cast<int>(kWindowsDirectoryLength))).toLower();
    }

    for (const auto& cachePair : cacheByIdentity_)
    {
        const ks::process::ProcessRecord& processRecord = cachePair.second.record;
        if (findFriendlyApplicationRootPid(processRecord.pid, parentPidByPid, kVisibleWindowPidSet) != 0U)
        {
            groupTypeByPid[processRecord.pid] = FriendlyProcessGroupType::kApplication;
            continue;
        }
        groupTypeByPid[processRecord.pid] =
            isFriendlyWindowsSystemProcess(processRecord, windowsDirectoryPath)
            ? FriendlyProcessGroupType::kWindowsSystem
            : FriendlyProcessGroupType::kBackground;
    }

    return groupTypeByPid;
}

std::vector<ProcessDock::DisplayRow> ProcessDock::buildFriendlyDisplayOrder() const
{
    // Inputs: live process cache, hidden-item switch, and current visible-window owners.
    // Processing: classify rows into Application/Background/System, then emit a source-order
    // table that visually behaves like a tree while staying on QTableView + FlatTableModel.
    // Return: display rows containing group headers, application aggregates, and real processes.
    struct FriendlyNode
    {
        const std::string* identityKey = nullptr;
        const CacheEntry* cacheEntry = nullptr;
        std::uint32_t applicationRootPid = 0;
    };

    std::vector<FriendlyNode> nodes;
    nodes.reserve(cacheByIdentity_.size());
    std::unordered_map<std::uint32_t, std::uint32_t> parentPidByPid;
    parentPidByPid.reserve(cacheByIdentity_.size());

    for (const auto& cachePair : cacheByIdentity_)
    {
        const ks::process::ProcessRecord& processRecord = cachePair.second.record;
        const bool kIsKswordHidden =
            ((processRecord.r0Flags & KSWORD_ARK_PROCESS_FLAG_HIDDEN_BY_KSWORD_UI) != 0U) ||
            (hiddenProcessPidSet_.find(processRecord.pid) != hiddenProcessPidSet_.end());
        const bool kShowKswordHidden =
            (showKswordHiddenProcessCheck_ != nullptr && showKswordHiddenProcessCheck_->isChecked());
        if (kIsKswordHidden && !kShowKswordHidden)
        {
            continue;
        }

        parentPidByPid[processRecord.pid] = processRecord.parentPid;
        nodes.push_back(FriendlyNode{ &cachePair.first, &cachePair.second, 0U });
    }

    const QSet<std::uint32_t> kVisibleWindowPidSet = collectVisibleWindowPidSet();
    wchar_t windowsDirectoryBuffer[MAX_PATH]{};
    QString windowsDirectoryPath;
    const UINT kWindowsDirectoryLength = ::GetWindowsDirectoryW(windowsDirectoryBuffer, MAX_PATH);
    if (kWindowsDirectoryLength > 0U)
    {
        windowsDirectoryPath = QDir::fromNativeSeparators(
            QString::fromWCharArray(windowsDirectoryBuffer, static_cast<int>(kWindowsDirectoryLength))).toLower();
    }

    std::vector<const FriendlyNode*> applicationNodes;
    std::vector<const FriendlyNode*> backgroundNodes;
    std::vector<const FriendlyNode*> systemNodes;
    applicationNodes.reserve(nodes.size());
    backgroundNodes.reserve(nodes.size());
    systemNodes.reserve(nodes.size());

    for (FriendlyNode& node : nodes)
    {
        if (node.cacheEntry == nullptr)
        {
            continue;
        }

        node.applicationRootPid = findFriendlyApplicationRootPid(
            node.cacheEntry->record.pid,
            parentPidByPid,
            kVisibleWindowPidSet);
        if (node.applicationRootPid != 0U)
        {
            applicationNodes.push_back(&node);
            continue;
        }

        if (isFriendlyWindowsSystemProcess(node.cacheEntry->record, windowsDirectoryPath))
        {
            systemNodes.push_back(&node);
        }
        else
        {
            backgroundNodes.push_back(&node);
        }
    }

    const int kFriendlySortColumn = std::clamp(
        friendlySortColumn_,
        0,
        static_cast<int>(TableColumn::kCount) - 1);
    const Qt::SortOrder kFriendlySortOrder = friendlySortOrder_;
    const auto kCompareRecordByFriendlySort =
        [this, kFriendlySortColumn, kFriendlySortOrder](
            const ks::process::ProcessRecord& leftRecord,
            const ks::process::ProcessRecord& rightRecord) -> bool
        {
            // Inputs: two process records and the active friendly-view sort column/order.
            // Processing: reuse the model's numeric sort key or displayed text with the selected direction,
            // then use name/PID/creation time as ascending tie breakers so rows do not jitter.
            // Return: true when left should be displayed before right.
            const auto kCompareText = [](const QString& leftText, const QString& rightText) -> int
            {
                return leftText.localeAwareCompare(rightText);
            };

            int primaryResult = 0;
            const TableColumn kTableColumn = static_cast<TableColumn>(kFriendlySortColumn);
            bool leftNumericOk = false;
            bool rightNumericOk = false;
            const double kLeftNumericValue = processNumericSortValue(leftRecord, kTableColumn)
                .toDouble(&leftNumericOk);
            const double kRightNumericValue = processNumericSortValue(rightRecord, kTableColumn)
                .toDouble(&rightNumericOk);
            if (leftNumericOk && rightNumericOk && kLeftNumericValue != kRightNumericValue)
            {
                primaryResult = kLeftNumericValue < kRightNumericValue ? -1 : 1;
            }
            else
            {
                primaryResult = kCompareText(
                    formatColumnText(leftRecord, kTableColumn, 0),
                    formatColumnText(rightRecord, kTableColumn, 0));
            }

            if (primaryResult != 0)
            {
                return kFriendlySortOrder == Qt::AscendingOrder
                    ? primaryResult < 0
                    : primaryResult > 0;
            }

            const int kNameTieResult = kCompareText(
                QString::fromStdString(leftRecord.processName),
                QString::fromStdString(rightRecord.processName));
            if (kNameTieResult != 0)
            {
                return kNameTieResult < 0;
            }
            if (leftRecord.pid != rightRecord.pid)
            {
                return leftRecord.pid < rightRecord.pid;
            }
            return leftRecord.creationTime100ns < rightRecord.creationTime100ns;
        };

    const auto kProcessSorter = [&kCompareRecordByFriendlySort](const FriendlyNode* leftNode, const FriendlyNode* rightNode) -> bool
    {
        if (leftNode == nullptr || rightNode == nullptr ||
            leftNode->cacheEntry == nullptr || rightNode->cacheEntry == nullptr)
        {
            return leftNode < rightNode;
        }

        return kCompareRecordByFriendlySort(leftNode->cacheEntry->record, rightNode->cacheEntry->record);
    };

    std::sort(applicationNodes.begin(), applicationNodes.end(), kProcessSorter);
    std::sort(backgroundNodes.begin(), backgroundNodes.end(), kProcessSorter);
    std::sort(systemNodes.begin(), systemNodes.end(), kProcessSorter);

    friendlySyntheticRecords_.clear();
    friendlySyntheticRecords_.reserve(applicationNodes.size() + 3U);

    std::vector<DisplayRow> displayRows;
    displayRows.reserve(nodes.size() + applicationNodes.size() + 3U);

    const auto kAppendSyntheticRecordRow =
        [this, &displayRows](
            const ks::process::ProcessRecord& syntheticRecord,
            const ProcessTableRowKind rowKind,
            const FriendlyProcessGroupType groupType,
            const QString& title,
            const QString& expansionKey,
            const std::vector<std::string>& actionIdentityKeys,
            const int depth)
        {
            // Inputs: prepared synthetic ProcessRecord and row metadata.
            // Processing: store the record in a stable member vector, then add a DisplayRow pointer.
            // Return: no value; displayRows receives one synthetic row.
            friendlySyntheticRecords_.push_back(syntheticRecord);

            DisplayRow displayRow{};
            displayRow.record = &friendlySyntheticRecords_.back();
            displayRow.rowKind = rowKind;
            displayRow.friendlyGroupType = groupType;
            displayRow.syntheticTitle = title;
            displayRow.expansionKey = expansionKey;
            displayRow.actionIdentityKeys = actionIdentityKeys;
            displayRow.depth = depth;
            displayRow.hasChildren = rowKind == ProcessTableRowKind::kGroupHeader ||
                rowKind == ProcessTableRowKind::kApplicationAggregate;
            displayRows.push_back(std::move(displayRow));
        };

    const auto kAppendGroupHeader =
        [&kAppendSyntheticRecordRow](const FriendlyProcessGroupType groupType, const int entryCount)
        {
            ks::process::ProcessRecord syntheticRecord{};
            syntheticRecord.processName = friendlyGroupTitle(groupType, entryCount).toStdString();
            syntheticRecord.imagePath = "[FriendlyGroup]";
            kAppendSyntheticRecordRow(
                syntheticRecord,
                ProcessTableRowKind::kGroupHeader,
                groupType,
                friendlyGroupTitle(groupType, entryCount),
                friendlyExpansionKeyForGroup(groupType),
                {},
                0);
        };

    const auto kAppendRealNode =
        [&displayRows](const FriendlyNode* node, const int depth, const bool hasChildren = false)
        {
            if (node == nullptr || node->cacheEntry == nullptr)
            {
                return;
            }

            DisplayRow displayRow{};
            displayRow.record = const_cast<ks::process::ProcessRecord*>(&node->cacheEntry->record);
            displayRow.rowKind = ProcessTableRowKind::kProcess;
            displayRow.depth = depth;
            displayRow.hasChildren = hasChildren;
            displayRow.isNew = node->cacheEntry->isNewInLatestRound;
            displayRow.isExited = node->cacheEntry->isExitedInLatestRound;
            displayRow.isKernelOnly = node->cacheEntry->isKernelOnlyInLatestRound;
            displayRows.push_back(std::move(displayRow));
        };

    kAppendGroupHeader(FriendlyProcessGroupType::kApplication, static_cast<int>(applicationNodes.size()));
    if (friendlyExpandedStateByKey_.value(
        friendlyExpansionKeyForGroup(FriendlyProcessGroupType::kApplication),
        true))
    {
        std::unordered_map<std::uint32_t, std::vector<const FriendlyNode*>> applicationNodesByRootPid;
        for (const FriendlyNode* node : applicationNodes)
        {
            if (node == nullptr || node->cacheEntry == nullptr)
            {
                continue;
            }
            const std::uint32_t kRootPid = node->applicationRootPid != 0U
                ? node->applicationRootPid
                : node->cacheEntry->record.pid;
            applicationNodesByRootPid[kRootPid].push_back(node);
        }

        std::vector<std::pair<std::uint32_t, std::vector<const FriendlyNode*>>> applicationBuckets;
        applicationBuckets.reserve(applicationNodesByRootPid.size());
        for (auto& bucketPair : applicationNodesByRootPid)
        {
            std::sort(bucketPair.second.begin(), bucketPair.second.end(), kProcessSorter);
            applicationBuckets.push_back(std::make_pair(bucketPair.first, std::move(bucketPair.second)));
        }

        const auto kAggregateApplicationBucket =
            [](const std::vector<const FriendlyNode*>& bucketNodes, const std::uint32_t rootPid)
            {
                std::vector<const CacheEntry*> cacheEntries;
                cacheEntries.reserve(bucketNodes.size());
                for (const FriendlyNode* node : bucketNodes)
                {
                    if (node != nullptr && node->cacheEntry != nullptr)
                    {
                        cacheEntries.push_back(node->cacheEntry);
                    }
                }
                return aggregateFriendlyApplicationRecord(cacheEntries, rootPid);
            };

        std::sort(
            applicationBuckets.begin(),
            applicationBuckets.end(),
            [&kAggregateApplicationBucket, &kCompareRecordByFriendlySort](const auto& leftBucket, const auto& rightBucket)
            {
                const ks::process::ProcessRecord kLeftAggregate =
                    kAggregateApplicationBucket(leftBucket.second, leftBucket.first);
                const ks::process::ProcessRecord kRightAggregate =
                    kAggregateApplicationBucket(rightBucket.second, rightBucket.first);
                return kCompareRecordByFriendlySort(kLeftAggregate, kRightAggregate);
            });

        for (const auto& bucket : applicationBuckets)
        {
            const std::uint32_t kRootPid = bucket.first;
            const std::vector<const FriendlyNode*>& bucketNodes = bucket.second;
            if (bucketNodes.empty())
            {
                continue;
            }

            const ks::process::ProcessRecord kAggregateRecord =
                kAggregateApplicationBucket(bucketNodes, kRootPid);
            std::vector<std::string> aggregateActionIdentityKeys;
            aggregateActionIdentityKeys.reserve(bucketNodes.size());
            for (const FriendlyNode* bucketNode : bucketNodes)
            {
                if (bucketNode != nullptr &&
                    bucketNode->identityKey != nullptr &&
                    !bucketNode->identityKey->empty())
                {
                    aggregateActionIdentityKeys.push_back(*bucketNode->identityKey);
                }
            }
            kAppendSyntheticRecordRow(
                kAggregateRecord,
                ProcessTableRowKind::kApplicationAggregate,
                FriendlyProcessGroupType::kApplication,
                QStringLiteral("%1 (%2)").arg(QString::fromStdString(kAggregateRecord.processName)).arg(bucketNodes.size()),
                friendlyExpansionKeyForApplication(kRootPid),
                aggregateActionIdentityKeys,
                1);

            if (!friendlyExpandedStateByKey_.value(friendlyExpansionKeyForApplication(kRootPid), false))
            {
                continue;
            }

            std::unordered_map<std::uint32_t, std::vector<const FriendlyNode*>> childrenByParentPid;
            childrenByParentPid.reserve(bucketNodes.size());
            for (const FriendlyNode* node : bucketNodes)
            {
                if (node == nullptr || node->cacheEntry == nullptr)
                {
                    continue;
                }
                childrenByParentPid[node->cacheEntry->record.parentPid].push_back(node);
            }
            for (auto& childPair : childrenByParentPid)
            {
                std::sort(childPair.second.begin(), childPair.second.end(), kProcessSorter);
            }

            std::unordered_set<std::uint32_t> emittedPidSet;
            const std::function<void(const FriendlyNode*, int)> kAppendTreeNode =
                [&](const FriendlyNode* node, const int depth)
                {
                    if (node == nullptr || node->cacheEntry == nullptr)
                    {
                        return;
                    }
                    const std::uint32_t kPid = node->cacheEntry->record.pid;
                    if (!emittedPidSet.insert(kPid).second)
                    {
                        return;
                    }

                    kAppendRealNode(
                        node,
                        depth,
                        childrenByParentPid.find(kPid) != childrenByParentPid.end());
                    const auto kChildIt = childrenByParentPid.find(kPid);
                    if (kChildIt == childrenByParentPid.end())
                    {
                        return;
                    }
                    for (const FriendlyNode* childNode : kChildIt->second)
                    {
                        kAppendTreeNode(childNode, depth + 1);
                    }
                };

            const auto kRootIt = std::find_if(
                bucketNodes.cbegin(),
                bucketNodes.cend(),
                [kRootPid](const FriendlyNode* node)
                {
                    return node != nullptr &&
                        node->cacheEntry != nullptr &&
                        node->cacheEntry->record.pid == kRootPid;
                });
            if (kRootIt != bucketNodes.cend())
            {
                kAppendTreeNode(*kRootIt, 2);
            }

            for (const FriendlyNode* node : bucketNodes)
            {
                if (node == nullptr || node->cacheEntry == nullptr)
                {
                    continue;
                }
                if (emittedPidSet.find(node->cacheEntry->record.pid) == emittedPidSet.end())
                {
                    kAppendTreeNode(node, 2);
                }
            }
        }
    }

    const auto kAppendFlatGroup =
        [&](const FriendlyProcessGroupType groupType, const std::vector<const FriendlyNode*>& groupNodes)
        {
            kAppendGroupHeader(groupType, static_cast<int>(groupNodes.size()));
            if (!friendlyExpandedStateByKey_.value(friendlyExpansionKeyForGroup(groupType), true))
            {
                return;
            }
            for (const FriendlyNode* node : groupNodes)
            {
                kAppendRealNode(node, 1);
            }
        };
    kAppendFlatGroup(FriendlyProcessGroupType::kBackground, backgroundNodes);
    kAppendFlatGroup(FriendlyProcessGroupType::kWindowsSystem, systemNodes);

    return displayRows;
}
