#include "MonitorDock.Support.h"

using namespace ksword::ui::monitor_dock;

void MonitorDock::updateEtwFilterStateLabel(const EtwFilterStage stage)
{
    QLabel* stateLabel = stage == EtwFilterStage::kPre ? etwPreFilterStateLabel_ : etwPostFilterStateLabel_;
    if (stateLabel == nullptr)
    {
        return;
    }

    const std::vector<EtwFilterRuleGroupCompiled>& compiledGroupList =
        stage == EtwFilterStage::kPre ? etwPreFilterCompiledGroupList_ : etwPostFilterCompiledGroupList_;
    bool archiveAvailable = false;
    if (stage == EtwFilterStage::kPost)
    {
        std::lock_guard<std::mutex> lock(etwArchiveMutex_);
        archiveAvailable = !etwArchiveDirectory_.trimmed().isEmpty();
    }

    if (compiledGroupList.empty())
    {
        const QString kTailText = stage == EtwFilterStage::kPre
            ? QStringLiteral("前置筛选当前无规则（全部捕获）")
            : QStringLiteral("后置筛选当前无规则（全部显示）");
        if (stage == EtwFilterStage::kPost
            && !archiveAvailable
            && etwEventTable_ != nullptr
            && isEtwTimelineFilterActive())
        {
            int visibleCount = 0;
            for (int row = 0; row < etwEventTable_->rowCount(); ++row)
            {
                if (!etwEventTable_->isRowHidden(row))
                {
                    ++visibleCount;
                }
            }
            stateLabel->setText(QStringLiteral("%1 | 可见: %2 / %3 | 时间轴已筛选")
                .arg(QStringLiteral("后置筛选当前无规则"))
                .arg(visibleCount)
                .arg(etwEventTable_->rowCount()));
            ks::ui::applyStatusRole(stateLabel, ks::ui::StatusRole::kInfo);
        }
        else
        {
            stateLabel->setText(kTailText);
            ks::ui::applyStatusRole(stateLabel, ks::ui::StatusRole::kIdle);
        }
        return;
    }

    QStringList groupSummaryList;
    for (const EtwFilterRuleGroupCompiled& groupRule : compiledGroupList)
    {
        groupSummaryList.push_back(QStringLiteral("规则组%1[%2项]")
            .arg(groupRule.displayIndex)
            .arg(groupRule.fieldList.size()));
    }

    QString summaryText = QStringLiteral("%1：%2")
        .arg(etwFilterStageText(stage))
        .arg(groupSummaryList.join(QStringLiteral(" OR ")));
    if (stage == EtwFilterStage::kPost && !archiveAvailable && etwEventTable_ != nullptr)
    {
        int visibleCount = 0;
        for (int row = 0; row < etwEventTable_->rowCount(); ++row)
        {
            if (!etwEventTable_->isRowHidden(row))
            {
                ++visibleCount;
            }
        }
        summaryText += QStringLiteral(" | 可见: %1 / %2").arg(visibleCount).arg(etwEventTable_->rowCount());
        if (isEtwTimelineFilterActive())
        {
            summaryText += QStringLiteral(" | 时间轴已筛选");
        }
    }

    stateLabel->setText(summaryText);
    ks::ui::applyStatusRole(stateLabel, ks::ui::StatusRole::kInfo);
}

void MonitorDock::applyEtwPostFilterToTable(const int firstRow, const bool updateStateLabel)
{
    if (etwEventTable_ == nullptr)
    {
        return;
    }

    const int kRowCount = std::min(
        etwEventTable_->rowCount(),
        static_cast<int>(etwCapturedRows_.size()));

    const bool kHasPostRules = etwPostSimpleFilterCompiled_.hasAnyCondition()
        || !etwPostFilterCompiledGroupList_.empty();
    const bool kTimelineFilterActive = isEtwTimelineFilterActive();
    const int kFirstRowToApply = std::clamp(firstRow, 0, kRowCount);

    // During real-time appending, only new rows are calculated. Rule changes or timeline selection changes still trigger a full table recalculation starting from firstRow=0.
    // This avoids rescanning up to 6000 historical events for every batch while listening.
    for (int row = kFirstRowToApply; row < kRowCount; ++row)
    {
        bool visible = true;
        const EtwCapturedEventRow& rowData = etwCapturedRows_[static_cast<std::size_t>(row)];
        if (kHasPostRules)
        {
            visible = etwFilterStageMatches(
                etwPostSimpleFilterCompiled_,
                etwPostFilterCompiledGroupList_,
                rowData);
        }
        if (visible && kTimelineFilterActive)
        {
            // The timeline represents the outer valid execution time window constraint; intermediate pause segments are excluded from coordinate comparison.
            const std::uint64_t kRowTimelineTimestamp100ns =
                etwRawTimestampToTimelineTimestamp(rowData.timestampValue);
            visible = kRowTimelineTimestamp100ns >= etwTimelineSelectionStart100ns_
                && kRowTimelineTimestamp100ns <= etwTimelineSelectionEnd100ns_;
        }
        etwEventTable_->setRowHidden(row, !visible);
    }
    for (int row = std::max(kRowCount, kFirstRowToApply); row < etwEventTable_->rowCount(); ++row)
    {
        etwEventTable_->setRowHidden(row, false);
    }

    if (updateStateLabel)
    {
        updateEtwFilterStateLabel(EtwFilterStage::kPost);
    }
}

void MonitorDock::applyEtwFilterRules(const EtwFilterStage stage)
{
    EtwSimpleFilterCompiled simpleFilter;
    QString compileErrorText;
    if (!tryCompileEtwSimpleFilter(stage, simpleFilter, compileErrorText))
    {
        EtwSimpleFilterUiState& uiState = etwSimpleFilterUi(stage);
        if (uiState.stateLabel != nullptr)
        {
            uiState.stateLabel->setText(compileErrorText);
            ks::ui::applyStatusRole(uiState.stateLabel, ks::ui::StatusRole::kError);
        }
        return;
    }

    std::vector<EtwFilterRuleGroupCompiled> compiledGroupList;
    if (!tryCompileEtwFilterGroups(stage, compiledGroupList, compileErrorText))
    {
        QMessageBox::warning(this, QStringLiteral("ETW筛选器"), compileErrorText);
        return;
    }

    if (stage == EtwFilterStage::kPre)
    {
        etwPreSimpleFilterCompiled_ = simpleFilter;
        etwPreFilterCompiledGroupList_ = std::move(compiledGroupList);
        EtwFilterStageCompiledSnapshot stageSnapshot;
        stageSnapshot.simpleFilter = etwPreSimpleFilterCompiled_;
        stageSnapshot.detailedGroupList = etwPreFilterCompiledGroupList_;
        {
            std::lock_guard<std::mutex> lock(etwPreFilterSnapshotMutex_);
            etwPreFilterCompiledSnapshot_ =
                std::make_shared<const EtwFilterStageCompiledSnapshot>(std::move(stageSnapshot));
        }
    }
    else
    {
        etwPostSimpleFilterCompiled_ = simpleFilter;
        etwPostFilterCompiledGroupList_ = std::move(compiledGroupList);
        QString archiveDirectory;
        {
            std::lock_guard<std::mutex> lock(etwArchiveMutex_);
            archiveDirectory = etwArchiveDirectory_;
        }
        if (archiveDirectory.trimmed().isEmpty())
        {
            applyEtwPostFilterToTable();
        }
        else
        {
            scheduleEtwArchiveFilterRebuild();
        }
    }

    updateEtwSimpleFilterStateLabel(stage);
    updateEtwFilterStateLabel(stage);
    saveEtwFilterConfigToPath(etwFilterConfigPath(), false);
    updateEtwCollapseHeight();

    KLogEvent event;
    info << event
        << "[MonitorDock] 应用ETW筛选规则, stage="
        << (stage == EtwFilterStage::kPre ? "pre" : "post")
        << ", activeGroupCount="
        << (stage == EtwFilterStage::kPre
            ? etwPreFilterCompiledGroupList_.size()
            : etwPostFilterCompiledGroupList_.size())
        << ", simpleActive="
        << (simpleFilter.hasAnyCondition() ? 1 : 0)
        << eol;
}
