#include "MonitorDock.Support.h"

using namespace ksword::ui::monitor_dock;

void MonitorDock::refreshEtwProvidersAsync()
{
    KLogEvent startEvent;
    info << startEvent
        << "[MonitorDock] 开始异步刷新ETW Provider。"
        << eol;

    etwProviderStatusLabel_->setText(QStringLiteral("● 刷新中..."));
    ks::ui::applyStatusRole(etwProviderStatusLabel_, ks::ui::StatusRole::kInfo);

    if (etwCaptureProgressPid_ == 0)
    {
        etwCaptureProgressPid_ = kPro.addReusable(this, "监控", "刷新ETW Provider");
    }
    kPro.set(etwCaptureProgressPid_, "调用TdhEnumerateProviders", 0, 10.0f);

    QPointer<MonitorDock> guardThis(this);
    std::thread([guardThis]() {
        std::vector<EtwProviderEntry> providers;

        ULONG bufferSize = 0;
        ULONG status = ::TdhEnumerateProviders(nullptr, &bufferSize);
        if (status == ERROR_INSUFFICIENT_BUFFER && bufferSize > 0)
        {
            std::vector<unsigned char> buffer(bufferSize, 0);
            auto* info = reinterpret_cast<PROVIDER_ENUMERATION_INFO*>(buffer.data());
            status = ::TdhEnumerateProviders(info, &bufferSize);
            if (status == ERROR_SUCCESS && info != nullptr)
            {
                providers.reserve(info->NumberOfProviders);
                for (ULONG i = 0; i < info->NumberOfProviders; ++i)
                {
                    const TRACE_PROVIDER_INFO& item = info->TraceProviderInfoArray[i];
                    const wchar_t* namePtr = reinterpret_cast<const wchar_t*>(buffer.data() + item.ProviderNameOffset);

                    EtwProviderEntry entry;
                    entry.providerName = namePtr != nullptr ? QString::fromWCharArray(namePtr) : QStringLiteral("<Unknown>");
                    entry.providerGuidText = guidToText(item.ProviderGuid);
                    providers.push_back(entry);
                }
            }
        }

        QMetaObject::invokeMethod(qApp, [guardThis, providers, status]() {
            if (guardThis == nullptr)
            {
                return;
            }

            guardThis->etwProviders_ = providers;
            guardThis->etwProviderList_->clear();

            for (const EtwProviderEntry& entry : guardThis->etwProviders_)
            {
                QListWidgetItem* item = new QListWidgetItem(
                    QStringLiteral("%1 (%2)").arg(entry.providerName, entry.providerGuidText),
                    guardThis->etwProviderList_);
                item->setData(Qt::UserRole, entry.providerName);
                item->setData(Qt::UserRole + 1, entry.providerGuidText);
                item->setFlags(item->flags() | Qt::ItemIsUserCheckable);
                item->setCheckState(Qt::Unchecked);
            }

            if (status == ERROR_SUCCESS)
            {
                guardThis->etwProviderStatusLabel_->setText(
                    QStringLiteral("● 已刷新 %1 项").arg(guardThis->etwProviders_.size()));
                ks::ui::applyStatusRole(guardThis->etwProviderStatusLabel_, ks::ui::StatusRole::kSuccess);
                kPro.set(guardThis->etwCaptureProgressPid_, "ETW Provider完成", 0, 100.0f);

                KLogEvent event;
                info << event
                    << "[MonitorDock] ETW Provider刷新完成, providerCount="
                    << guardThis->etwProviders_.size()
                    << eol;
            }
            else
            {
                guardThis->etwProviderStatusLabel_->setText(QStringLiteral("● 刷新失败:%1").arg(status));
                ks::ui::applyStatusRole(guardThis->etwProviderStatusLabel_, ks::ui::StatusRole::kError);
                kPro.set(guardThis->etwCaptureProgressPid_, "ETW Provider失败", 0, 100.0f);

                KLogEvent event;
                err << event
                    << "[MonitorDock] ETW Provider刷新失败, status="
                    << status
                    << eol;
            }

            guardThis->updateEtwCollapseHeight();
        }, Qt::QueuedConnection);
    }).detach();
}

void MonitorDock::refreshEtwSessionsAsync()
{
    const std::uint64_t kRequestTicket = etwSessionRefreshTicket_.fetch_add(
        1,
        std::memory_order_relaxed) + 1;

    if (etwSessionStatusLabel_ != nullptr)
    {
        etwSessionStatusLabel_->setText(QStringLiteral("● 刷新中..."));
        ks::ui::applyStatusRole(etwSessionStatusLabel_, ks::ui::StatusRole::kInfo);
    }
    if (etwSessionStopButton_ != nullptr)
    {
        etwSessionStopButton_->setEnabled(false);
    }

    if (etwSessionRefreshProgressPid_ == 0)
    {
        etwSessionRefreshProgressPid_ = kPro.addReusable(this, "监控", "刷新ETW会话");
    }
    kPro.set(etwSessionRefreshProgressPid_, "枚举系统活动 ETW 会话", 0, 10.0f);

    QPointer<MonitorDock> guardThis(this);
    std::thread([guardThis, kRequestTicket]() {
        std::vector<EtwSessionEntry> sessionList;
        constexpr ULONG kQuerySessionCapacity = 128;
        constexpr ULONG kTraceNameChars = 1024;
        constexpr ULONG kLogFileChars = 1024;
        constexpr ULONG kPropertyBufferSize =
            sizeof(EVENT_TRACE_PROPERTIES)
            + (kTraceNameChars + kLogFileChars) * sizeof(wchar_t);

        std::vector<std::vector<unsigned char>> propertyBufferList(
            kQuerySessionCapacity,
            std::vector<unsigned char>(kPropertyBufferSize, 0));
        std::vector<EVENT_TRACE_PROPERTIES*> propertyPointerList(kQuerySessionCapacity, nullptr);

        for (ULONG indexValue = 0; indexValue < kQuerySessionCapacity; ++indexValue)
        {
            auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(propertyBufferList[indexValue].data());
            properties->Wnode.BufferSize = kPropertyBufferSize;
            properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
            properties->LogFileNameOffset =
                sizeof(EVENT_TRACE_PROPERTIES) + kTraceNameChars * sizeof(wchar_t);
            propertyPointerList[indexValue] = properties;
        }

        ULONG sessionCount = kQuerySessionCapacity;
        const ULONG kQueryStatus = ::QueryAllTracesW(
            propertyPointerList.data(),
            kQuerySessionCapacity,
            &sessionCount);
        if (kQueryStatus == ERROR_SUCCESS || kQueryStatus == ERROR_MORE_DATA)
        {
            sessionList.reserve(sessionCount);
            for (ULONG indexValue = 0; indexValue < sessionCount && indexValue < kQuerySessionCapacity; ++indexValue)
            {
                const EVENT_TRACE_PROPERTIES* properties = propertyPointerList[indexValue];
                if (properties == nullptr || properties->LoggerNameOffset == 0)
                {
                    continue;
                }

                const wchar_t* loggerNamePointer = reinterpret_cast<const wchar_t*>(
                    propertyBufferList[indexValue].data() + properties->LoggerNameOffset);
                const QString kSessionNameText = QString::fromWCharArray(loggerNamePointer).trimmed();
                if (kSessionNameText.isEmpty())
                {
                    continue;
                }

                const wchar_t* logFileNamePointer = properties->LogFileNameOffset == 0
                    ? nullptr
                    : reinterpret_cast<const wchar_t*>(
                        propertyBufferList[indexValue].data() + properties->LogFileNameOffset);
                const QString kLogFileNameText = logFileNamePointer != nullptr
                    ? QString::fromWCharArray(logFileNamePointer).trimmed()
                    : QString();

                QStringList modeTextList;
                if ((properties->LogFileMode & EVENT_TRACE_REAL_TIME_MODE) != 0)
                {
                    modeTextList << QStringLiteral("实时");
                }
                if ((properties->LogFileMode & EVENT_TRACE_FILE_MODE_SEQUENTIAL) != 0
                    || (properties->LogFileMode & EVENT_TRACE_FILE_MODE_CIRCULAR) != 0
                    || (properties->LogFileMode & EVENT_TRACE_FILE_MODE_APPEND) != 0
                    || !kLogFileNameText.isEmpty())
                {
                    modeTextList << QStringLiteral("文件");
                }
                if (modeTextList.isEmpty())
                {
                    modeTextList << QStringLiteral("未知");
                }

                EtwSessionEntry entry;
                entry.sessionName = kSessionNameText;
                entry.modeText = modeTextList.join(QStringLiteral(" + "));
                entry.bufferText = QStringLiteral("%1KB | %2/%3/%4")
                    .arg(properties->BufferSize)
                    .arg(properties->NumberOfBuffers)
                    .arg(properties->MinimumBuffers)
                    .arg(properties->MaximumBuffers);
                entry.eventsLost = properties->EventsLost;
                entry.logFilePath = kLogFileNameText;
                sessionList.push_back(std::move(entry));
            }
        }

        QMetaObject::invokeMethod(qApp, [guardThis, kRequestTicket, sessionList = std::move(sessionList), kQueryStatus]() {
            if (guardThis == nullptr ||
                guardThis->etwSessionRefreshTicket_.load(std::memory_order_relaxed) != kRequestTicket)
            {
                return;
            }

            const auto kCommitSessions = [guardThis, kRequestTicket, sessionList, kQueryStatus]()
            {
                if (guardThis == nullptr ||
                    guardThis->etwSessionRefreshTicket_.load(std::memory_order_relaxed) != kRequestTicket)
                {
                    return;
                }

                guardThis->etwSessions_ = sessionList;
                if (guardThis->etwSessionTable_ != nullptr)
                {
                    guardThis->etwSessionTable_->clearContents();
                    guardThis->etwSessionTable_->setRowCount(static_cast<int>(guardThis->etwSessions_.size()));
                    for (int row = 0; row < static_cast<int>(guardThis->etwSessions_.size()); ++row)
                    {
                        const EtwSessionEntry& entry = guardThis->etwSessions_[static_cast<std::size_t>(row)];
                        QTableWidgetItem* nameItem = new QTableWidgetItem(entry.sessionName);
                        nameItem->setToolTip(entry.sessionName);
                        guardThis->etwSessionTable_->setItem(row, 0, nameItem);

                        QTableWidgetItem* modeItem = new QTableWidgetItem(entry.modeText);
                        modeItem->setToolTip(entry.modeText);
                        guardThis->etwSessionTable_->setItem(row, 1, modeItem);

                        QTableWidgetItem* bufferItem = new QTableWidgetItem(entry.bufferText);
                        bufferItem->setToolTip(entry.bufferText);
                        guardThis->etwSessionTable_->setItem(row, 2, bufferItem);

                        QTableWidgetItem* lostItem = new QTableWidgetItem(QString::number(entry.eventsLost));
                        lostItem->setToolTip(lostItem->text());
                        guardThis->etwSessionTable_->setItem(row, 3, lostItem);

                        QTableWidgetItem* logItem = new QTableWidgetItem(entry.logFilePath);
                        logItem->setToolTip(entry.logFilePath);
                        guardThis->etwSessionTable_->setItem(row, 4, logItem);
                    }
                }

                if (guardThis->etwSessionStatusLabel_ != nullptr)
                {
                    if (kQueryStatus == ERROR_SUCCESS || kQueryStatus == ERROR_MORE_DATA)
                    {
                        guardThis->etwSessionStatusLabel_->setText(
                            QStringLiteral("● 已刷新 %1 项").arg(guardThis->etwSessions_.size()));
                        ks::ui::applyStatusRole(guardThis->etwSessionStatusLabel_, ks::ui::StatusRole::kSuccess);
                        kPro.set(guardThis->etwSessionRefreshProgressPid_, "ETW会话刷新完成", 0, 100.0f);
                    }
                    else
                    {
                        guardThis->etwSessionStatusLabel_->setText(
                            QStringLiteral("● 刷新失败:%1").arg(kQueryStatus));
                        ks::ui::applyStatusRole(guardThis->etwSessionStatusLabel_, ks::ui::StatusRole::kError);
                        kPro.set(guardThis->etwSessionRefreshProgressPid_, "ETW会话刷新失败", 0, 100.0f);
                    }
                }

                guardThis->updateEtwCollapseHeight();
            };

            if (guardThis == nullptr)
            {
                return;
            }
            if (ks::ui::deferTableUiCommitIfContextMenuOpen(
                guardThis.data(),
                QStringLiteral("monitor-etw-session-apply"),
                { guardThis->etwSessionTable_ },
                kCommitSessions))
            {
                return;
            }
            kCommitSessions();
        }, Qt::QueuedConnection);
    }).detach();
}

void MonitorDock::stopSelectedEtwSessions()
{
    if (etwSessionTable_ == nullptr)
    {
        return;
    }

    std::set<int> selectedRowSet;
    const QList<QTableWidgetItem*> kItemList = etwSessionTable_->selectedItems();
    for (QTableWidgetItem* itemPointer : kItemList)
    {
        if (itemPointer != nullptr)
        {
            selectedRowSet.insert(itemPointer->row());
        }
    }

    if (selectedRowSet.empty())
    {
        return;
    }

    QStringList sessionNameList;
    for (const int kRow : selectedRowSet)
    {
        if (kRow < 0 || kRow >= static_cast<int>(etwSessions_.size()))
        {
            continue;
        }
        const QString kSessionNameText = etwSessions_[static_cast<std::size_t>(kRow)].sessionName.trimmed();
        if (!kSessionNameText.isEmpty())
        {
            sessionNameList << kSessionNameText;
        }
    }
    sessionNameList.removeDuplicates();
    if (sessionNameList.isEmpty())
    {
        return;
    }

    if (etwSessionStatusLabel_ != nullptr)
    {
        etwSessionStatusLabel_->setText(QStringLiteral("● 正在结束会话..."));
        ks::ui::applyStatusRole(etwSessionStatusLabel_, ks::ui::StatusRole::kWarning);
    }
    if (etwSessionStopButton_ != nullptr)
    {
        etwSessionStopButton_->setEnabled(false);
    }

    if (etwSessionRefreshProgressPid_ == 0)
    {
        etwSessionRefreshProgressPid_ = kPro.addReusable(this, "监控", "结束ETW会话");
    }
    kPro.set(etwSessionRefreshProgressPid_, "停止选中的 ETW 会话", 0, 10.0f);

    QPointer<MonitorDock> guardThis(this);
    std::thread([guardThis, sessionNameList]() {
        int successCount = 0;
        QStringList failureTextList;

        for (const QString& sessionNameText : sessionNameList)
        {
            const std::wstring kSessionNameWide = sessionNameText.toStdWString();
            std::vector<unsigned char> propertyBuffer(
                sizeof(EVENT_TRACE_PROPERTIES) + (kSessionNameWide.size() + 1) * sizeof(wchar_t),
                0);
            auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(propertyBuffer.data());
            properties->Wnode.BufferSize = static_cast<ULONG>(propertyBuffer.size());
            properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
            wchar_t* loggerNamePointer = reinterpret_cast<wchar_t*>(
                propertyBuffer.data() + properties->LoggerNameOffset);
            ::wcscpy_s(loggerNamePointer, kSessionNameWide.size() + 1, kSessionNameWide.c_str());

            const ULONG kStopStatus = ::ControlTraceW(0, loggerNamePointer, properties, EVENT_TRACE_CONTROL_STOP);
            if (kStopStatus == ERROR_SUCCESS)
            {
                ++successCount;
            }
            else
            {
                failureTextList << QStringLiteral("%1(%2)").arg(sessionNameText).arg(kStopStatus);
            }
        }

        QMetaObject::invokeMethod(qApp, [guardThis, sessionNameList, successCount, failureTextList]() {
            if (guardThis == nullptr)
            {
                return;
            }

            if (guardThis->etwSessionStatusLabel_ != nullptr)
            {
                if (failureTextList.isEmpty())
                {
                    guardThis->etwSessionStatusLabel_->setText(
                        QStringLiteral("● 已结束 %1 项").arg(successCount));
                    ks::ui::applyStatusRole(guardThis->etwSessionStatusLabel_, ks::ui::StatusRole::kSuccess);
                    kPro.set(guardThis->etwSessionRefreshProgressPid_, "结束ETW会话完成", 0, 100.0f);
                }
                else
                {
                    guardThis->etwSessionStatusLabel_->setText(
                        QStringLiteral(
                            "● 已结束 %1 项，%2 项失败；详情已写入日志。")
                            .arg(successCount)
                            .arg(failureTextList.size()));
                    ks::ui::applyStatusRole(guardThis->etwSessionStatusLabel_, ks::ui::StatusRole::kWarning);
                    kPro.set(guardThis->etwSessionRefreshProgressPid_, "结束ETW会话部分失败", 0, 100.0f);
                }
            }

            KLogEvent event;
            (failureTextList.isEmpty() ? info : warn) << event
                << "[MonitorDock] ETW会话停止完成, requestedCount="
                << sessionNameList.size()
                << ", successCount="
                << successCount
                << ", failureCount="
                << failureTextList.size()
                << ", failureDetails="
                << (failureTextList.isEmpty()
                    ? "none"
                    : failureTextList
                        .join(QStringLiteral(" | "))
                        .toStdString())
                << eol;

            guardThis->refreshEtwSessionsAsync();
        }, Qt::QueuedConnection);
    }).detach();
}
