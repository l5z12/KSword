#include "NetworkDock.InternalCommon.h"

using namespace network_dock_detail;
void NetworkDock::applyOrUpdateRateLimitRule()
{
    if (trafficService_ == nullptr || rateLimitPidEdit_ == nullptr ||
        rateLimitKBpsSpin_ == nullptr || rateLimitSuspendMsSpin_ == nullptr)
    {
        return;
    }

    std::uint32_t targetPid = 0;
    if (!tryParsePidText(rateLimitPidEdit_->text(), targetPid))
    {
        QMessageBox::warning(this, QStringLiteral("进程限速"), QStringLiteral("请输入有效的 PID。"));
        return;
    }

    std::uint64_t processCreationTime100ns = 0U;
    if (!ks::process::queryProcessCreationTimeByPid(
            targetPid,
            &processCreationTime100ns) ||
        processCreationTime100ns == 0U)
    {
        QMessageBox::warning(
            this,
            QStringLiteral("进程限速"),
            QStringLiteral("无法确认目标进程身份，规则未保存。"));
        return;
    }

    ks::network::ProcessRateLimitRule limitRule;
    limitRule.processId = targetPid;
    limitRule.processCreationTime100ns = processCreationTime100ns;
    limitRule.bytesPerSecond = static_cast<std::uint64_t>(rateLimitKBpsSpin_->value()) * 1024ULL;
    limitRule.suspendDurationMs = static_cast<std::uint32_t>(rateLimitSuspendMsSpin_->value());
    limitRule.enabled = true;

    trafficService_->upsertRateLimitRule(limitRule);
    refreshRateLimitTable();

    const QString kFormattedRateText = toQString(ks::network::formatBytesPerSecond(limitRule.bytesPerSecond));
    appendRateLimitActionLogLine(QStringLiteral("更新限速规则：PID=%1, %2, suspend=%3 ms")
        .arg(targetPid)
        .arg(kFormattedRateText)
        .arg(rateLimitSuspendMsSpin_->value()));

    KLogEvent limitEvent;
    info << limitEvent
        << "[NetworkDock] 设置限速规则, pid=" << targetPid
        << ", bytesPerSecond=" << limitRule.bytesPerSecond
        << ", rateText=" << kFormattedRateText.toStdString()
        << ", suspendMs=" << limitRule.suspendDurationMs
        << eol;
}

void NetworkDock::removeSelectedRateLimitRule()
{
    if (trafficService_ == nullptr || rateLimitTable_ == nullptr)
    {
        return;
    }

    const int kSelectedRow = rateLimitTable_->currentRow();
    if (kSelectedRow < 0)
    {
        QMessageBox::information(this, QStringLiteral("进程限速"), QStringLiteral("请先选中一条规则。"));
        return;
    }

    QTableWidgetItem* pidItem = rateLimitTable_->item(kSelectedRow, toRateLimitColumn(RateLimitTableColumn::kPid));
    if (pidItem == nullptr)
    {
        return;
    }

    std::uint32_t targetPid = 0;
    if (!tryParsePidText(pidItem->text(), targetPid))
    {
        return;
    }

    trafficService_->removeRateLimitRule(targetPid);
    refreshRateLimitTable();
    appendRateLimitActionLogLine(QStringLiteral("删除限速规则：PID=%1").arg(targetPid));
}

void NetworkDock::clearAllRateLimitRules()
{
    if (trafficService_ == nullptr)
    {
        return;
    }

    const int kUserChoice = QMessageBox::question(
        this,
        QStringLiteral("进程限速"),
        QStringLiteral("确认清空全部限速规则吗？"),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kUserChoice != QMessageBox::Yes)
    {
        return;
    }

    trafficService_->clearRateLimitRules();
    refreshRateLimitTable();
    appendRateLimitActionLogLine(QStringLiteral("已清空全部限速规则。"));
}

void NetworkDock::refreshRateLimitTable()
{
    if (rateLimitTable_ == nullptr || trafficService_ == nullptr)
    {
        return;
    }

    const std::vector<ks::network::ProcessRateLimitSnapshot> kSnapshots =
        trafficService_->snapshotRateLimitRules();

    // PID -> process name static cache:
    // - Reduce the cost of repeated QueryProcessNameByPID calls during periodic refreshes;
    // - Rules usually remain associated with a PID for a long time, yielding a high cache hit rate.
    static std::unordered_map<std::uint32_t, std::string> sProcessNameCacheByPid;

    rateLimitTable_->setUpdatesEnabled(false);
    rateLimitTable_->setRowCount(static_cast<int>(kSnapshots.size()));
    int rowIndex = 0;
    for (const ks::network::ProcessRateLimitSnapshot& snapshot : kSnapshots)
    {
        const std::uint32_t kProcessId = snapshot.rule.processId;
        const auto kCacheIterator = sProcessNameCacheByPid.find(kProcessId);
        std::string processName;
        if (kCacheIterator != sProcessNameCacheByPid.end())
        {
            processName = kCacheIterator->second;
        }
        else
        {
            processName = ks::process::getProcessNameByPid(kProcessId);
            sProcessNameCacheByPid.insert({ kProcessId, processName });
        }
        const QString kStateText = snapshot.currentlySuspended ? QStringLiteral("已挂起") : QStringLiteral("运行中");

        rateLimitTable_->setItem(rowIndex, toRateLimitColumn(RateLimitTableColumn::kPid),
            createPacketCell(QString::number(kProcessId)));
        rateLimitTable_->setItem(rowIndex, toRateLimitColumn(RateLimitTableColumn::kProcessName),
            createPacketCell(toQString(processName)));
        rateLimitTable_->setItem(rowIndex, toRateLimitColumn(RateLimitTableColumn::kLimitKBps),
            createPacketCell(QString::number(snapshot.rule.bytesPerSecond / 1024ULL)));
        rateLimitTable_->setItem(rowIndex, toRateLimitColumn(RateLimitTableColumn::kSuspendMs),
            createPacketCell(QString::number(snapshot.rule.suspendDurationMs)));
        rateLimitTable_->setItem(rowIndex, toRateLimitColumn(RateLimitTableColumn::kTriggerCount),
            createPacketCell(QString::number(snapshot.triggerCount)));
        rateLimitTable_->setItem(rowIndex, toRateLimitColumn(RateLimitTableColumn::kCurrentWindowBytes),
            createPacketCell(toQString(ks::network::formatByteCount(snapshot.currentWindowBytes))));
        rateLimitTable_->setItem(rowIndex, toRateLimitColumn(RateLimitTableColumn::kState),
            createPacketCell(kStateText));
        ++rowIndex;
    }

    rateLimitTable_->setUpdatesEnabled(true);
    rateLimitTable_->viewport()->update();
}

void NetworkDock::appendRateLimitActionLogLine(const QString& logLine)
{
    if (rateLimitLogOutput_ == nullptr)
    {
        return;
    }

    const QString kTimePrefix = QDateTime::currentDateTime().toString("HH:mm:ss.zzz");
    rateLimitLogOutput_->appendPlainText(QStringLiteral("[%1] %2").arg(kTimePrefix, logLine));
}
