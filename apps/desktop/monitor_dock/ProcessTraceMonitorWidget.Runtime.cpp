#include "ProcessTraceMonitorWidget.h"

// ============================================================
// ProcessTraceMonitorWidget.Runtime.cpp
// Purpose:
// 1) Implements ETW session control, including start/stop/pause state transitions.
// 2) Maintain synchronization of seeding and runtime snapshots for the target process tree;
// 3) Extract heavy runtime control logic from the event decoding file to control single-file size.
// ============================================================

#include <QApplication>
#include <QDateTime>
#include <QMessageBox>
#include <QMetaObject>
#include <QPointer>
#include <QTableWidget>
#include <QTimer>

#include <algorithm>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>

#pragma comment(lib, "Tdh.lib")

namespace
{
    // ProviderSelectionResolved：
    // - Purpose: Store Providers that have resolved GUIDs and are ready to be enabled.
    // - Used internally by the background ETW thread in startMonitoring.
    struct ProviderSelectionResolved
    {
        QString providerName;
        QString providerGuidText;
        QString providerTypeText;
        GUID providerGuid{};
    };

    // defaultProviderNameList：
    // - Purpose: Define the fixed list of wide-coverage Providers that are always enabled for 'Process-Oriented Monitoring'.
    // - Invocation: Enabled uniformly by the background thread in startMonitoring after resolving GUIDs by name.
    QStringList defaultProviderNameList()
    {
        return QStringList{
            QStringLiteral("Microsoft-Windows-Kernel-Process"),
            QStringLiteral("Microsoft-Windows-Kernel-Thread"),
            QStringLiteral("Microsoft-Windows-Kernel-Image"),
            QStringLiteral("Microsoft-Windows-Kernel-File"),
            QStringLiteral("Microsoft-Windows-Kernel-Registry"),
            QStringLiteral("Microsoft-Windows-TCPIP"),
            QStringLiteral("Microsoft-Windows-DNS-Client"),
            QStringLiteral("Microsoft-Windows-Winsock-AFD"),
            QStringLiteral("Microsoft-Windows-PowerShell"),
            QStringLiteral("Microsoft-Windows-WMI-Activity"),
            QStringLiteral("Microsoft-Windows-TaskScheduler"),
            QStringLiteral("Microsoft-Windows-Security-Auditing"),
            QStringLiteral("Microsoft-Windows-Windows Defender")
        };
    }

    void stopActiveKswordTraceSessionsByPrefix(const QStringList& sessionPrefixList)
    {
        constexpr ULONG kQuerySessionCapacity = 96;
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
        if (kQueryStatus != ERROR_SUCCESS && kQueryStatus != ERROR_MORE_DATA)
        {
            return;
        }

        for (ULONG indexValue = 0; indexValue < sessionCount && indexValue < kQuerySessionCapacity; ++indexValue)
        {
            const EVENT_TRACE_PROPERTIES* properties = propertyPointerList[indexValue];
            if (properties == nullptr || properties->LoggerNameOffset == 0)
            {
                continue;
            }

            const wchar_t* loggerNamePointer = reinterpret_cast<const wchar_t*>(
                propertyBufferList[indexValue].data() + properties->LoggerNameOffset);
            const QString kLoggerNameText = QString::fromWCharArray(loggerNamePointer).trimmed();
            if (kLoggerNameText.isEmpty())
            {
                continue;
            }

            const bool kShouldStop = std::any_of(
                sessionPrefixList.begin(),
                sessionPrefixList.end(),
                [&kLoggerNameText](const QString& prefixText) {
                    return !prefixText.trimmed().isEmpty()
                        && kLoggerNameText.startsWith(prefixText, Qt::CaseInsensitive);
                });
            if (!kShouldStop)
            {
                continue;
            }

            const std::wstring kLoggerNameWide = kLoggerNameText.toStdWString();
            std::vector<unsigned char> stopBuffer(
                sizeof(EVENT_TRACE_PROPERTIES) + (kLoggerNameWide.size() + 1) * sizeof(wchar_t),
                0);
            auto* stopProperties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(stopBuffer.data());
            stopProperties->Wnode.BufferSize = static_cast<ULONG>(stopBuffer.size());
            stopProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
            wchar_t* stopLoggerNamePointer = reinterpret_cast<wchar_t*>(
                stopBuffer.data() + stopProperties->LoggerNameOffset);
            ::wcscpy_s(stopLoggerNamePointer, kLoggerNameWide.size() + 1, kLoggerNameWide.c_str());
            ::ControlTraceW(0, stopLoggerNamePointer, stopProperties, EVENT_TRACE_CONTROL_STOP);
        }
    }
}

void ProcessTraceMonitorWidget::startMonitoring()
{
    if (captureRunning_.load())
    {
        if (capturePaused_.load())
        {
            setMonitoringPaused(false);
        }
        return;
    }

    if (targetProcessList_.empty())
    {
        QMessageBox::information(this, QStringLiteral("进程定向监控"), QStringLiteral("请先添加至少一个监控目标。"));
        return;
    }

    if (captureThread_ != nullptr && captureThread_->joinable())
    {
        captureThread_->join();
        captureThread_.reset();
    }

    // Clear old results before starting to avoid mixing events from different batches.
    if (eventTable_ != nullptr)
    {
        eventTable_->clearContents();
        eventTable_->setRowCount(0);
    }
    timelineEventPoints_.clear();
    captureStartTime100ns_ = currentSystemTime100ns();
    captureStopTime100ns_ = 0;
    timelineSelectionStart100ns_ = captureStartTime100ns_;
    timelineSelectionEnd100ns_ = captureStartTime100ns_;
    timelineUserSelectionActive_ = false;
    if (eventTimelineWidget_ != nullptr)
    {
        eventTimelineWidget_->resetTimeline(captureStartTime100ns_);
        timelineSelectionStart100ns_ = eventTimelineWidget_->selectionStart100ns();
        timelineSelectionEnd100ns_ = eventTimelineWidget_->selectionEnd100ns();
    }
    {
        std::lock_guard<std::mutex> lock(pendingMutex_);
        pendingRows_.clear();
        pendingDroppedRows_ = 0;
    }
    lastTimelineRefreshMs_ = 0;

    // Seed the target process tree with a single process snapshot to ensure child processes are captured before the ETW session starts.
    std::vector<ks::process::ProcessRecord> processList = ks::process::enumerateProcesses(
        ks::process::ProcessEnumStrategy::kAuto);
    seedTrackedProcessTree(processList);
    refreshTargetTable();

    captureRunning_.store(true);
    capturePaused_.store(false);
    captureStopFlag_.store(false);
    runtimeRefreshPending_.store(false);
    sessionHandle_.store(0);
    traceHandle_.store(0);
    stopActiveKswordTraceSessionsByPrefix(QStringList{ QStringLiteral("KswordProcessTrace") });
    sessionName_ = QStringLiteral("KswordProcessTrace");

    if (captureProgressPid_ == 0)
    {
        captureProgressPid_ = kPro.addReusable(this, "监控", "进程定向监控");
    }
    kPro.set(captureProgressPid_, "准备固定 ETW Provider 与目标进程树", 0, 10.0f);

    if (uiUpdateTimer_ != nullptr && !uiUpdateTimer_->isActive())
    {
        uiUpdateTimer_->start();
    }
    if (runtimeRefreshTimer_ != nullptr && !runtimeRefreshTimer_->isActive())
    {
        runtimeRefreshTimer_->start();
    }

    updateActionState();
    updateStatusLabel();

    KLogEvent startEvent;
    info << startEvent
        << "[ProcessTraceMonitorWidget] 启动进程定向监控, targetCount="
        << targetProcessList_.size()
        << eol;

    QPointer<ProcessTraceMonitorWidget> guardThis(this);
    captureThread_ = std::make_unique<std::thread>([guardThis]() {
        if (guardThis == nullptr)
        {
            return;
        }

        // Fixed Provider resolution:
        // - enumerate all system Providers first.
        // - Perform exact/fuzzy matching based on preset names.
        // - Include any provider whose GUID can be resolved in this session.
        QStringList wantedProviderNames = defaultProviderNameList();
        std::vector<ProviderSelectionResolved> selectedProviders;

        ULONG providerBufferSize = 0;
        ULONG enumerateStatus = ::TdhEnumerateProviders(nullptr, &providerBufferSize);
        if (enumerateStatus == ERROR_INSUFFICIENT_BUFFER && providerBufferSize > 0)
        {
            std::vector<unsigned char> providerBuffer(providerBufferSize, 0);
            auto* providerInfo = reinterpret_cast<PROVIDER_ENUMERATION_INFO*>(providerBuffer.data());
            enumerateStatus = ::TdhEnumerateProviders(providerInfo, &providerBufferSize);
            if (enumerateStatus == ERROR_SUCCESS && providerInfo != nullptr)
            {
                std::vector<ProviderSelectionResolved> allProviders;
                allProviders.reserve(providerInfo->NumberOfProviders);
                for (ULONG indexValue = 0; indexValue < providerInfo->NumberOfProviders; ++indexValue)
                {
                    const TRACE_PROVIDER_INFO& traceInfo = providerInfo->TraceProviderInfoArray[indexValue];
                    const wchar_t* providerNamePointer = reinterpret_cast<const wchar_t*>(
                        providerBuffer.data() + traceInfo.ProviderNameOffset);

                    ProviderSelectionResolved entry;
                    entry.providerName = providerNamePointer != nullptr
                        ? QString::fromWCharArray(providerNamePointer)
                        : QStringLiteral("<Unknown>");
                    entry.providerGuidText = guardThis->guidToText(traceInfo.ProviderGuid);
                    entry.providerTypeText = guardThis->providerTypeFromName(entry.providerName);
                    entry.providerGuid = traceInfo.ProviderGuid;
                    allProviders.push_back(entry);
                }

                for (const QString& wantedName : wantedProviderNames)
                {
                    auto found = std::find_if(
                        allProviders.begin(),
                        allProviders.end(),
                        [wantedName](const ProviderSelectionResolved& item) {
                            return item.providerName.compare(wantedName, Qt::CaseInsensitive) == 0;
                        });
                    if (found == allProviders.end())
                    {
                        found = std::find_if(
                            allProviders.begin(),
                            allProviders.end(),
                            [wantedName](const ProviderSelectionResolved& item) {
                                return item.providerName.contains(wantedName, Qt::CaseInsensitive)
                                    || wantedName.contains(item.providerName, Qt::CaseInsensitive);
                            });
                    }
                    if (found == allProviders.end())
                    {
                        continue;
                    }

                    const bool kDuplicate = std::any_of(
                        selectedProviders.begin(),
                        selectedProviders.end(),
                        [found](const ProviderSelectionResolved& item) {
                            return ::IsEqualGUID(item.providerGuid, found->providerGuid) != FALSE;
                        });
                    if (!kDuplicate)
                    {
                        selectedProviders.push_back(*found);
                    }
                }
            }
        }

        if (selectedProviders.empty())
        {
            QMetaObject::invokeMethod(qApp, [guardThis]() {
                if (guardThis == nullptr)
                {
                    return;
                }

                guardThis->captureRunning_.store(false);
                guardThis->capturePaused_.store(false);
                if (guardThis->runtimeRefreshTimer_ != nullptr)
                {
                    guardThis->runtimeRefreshTimer_->stop();
                }
                if (guardThis->uiUpdateTimer_ != nullptr)
                {
                    guardThis->uiUpdateTimer_->stop();
                }
                kPro.set(guardThis->captureProgressPid_, "预置 Provider 解析失败", 0, 100.0f);
                QMessageBox::warning(
                    guardThis,
                    QStringLiteral("进程定向监控"),
                    QStringLiteral("未解析到任何可用的 ETW Provider，监控无法启动。"));
                guardThis->updateActionState();
                guardThis->updateStatusLabel();
            }, Qt::QueuedConnection);
            return;
        }

        {
            std::lock_guard<std::mutex> lock(guardThis->runtimeMutex_);
            guardThis->activeProviderList_.clear();
            for (const ProviderSelectionResolved& provider : selectedProviders)
            {
                ProviderEntry entry;
                entry.providerName = provider.providerName;
                entry.providerGuidText = provider.providerGuidText;
                entry.providerTypeText = provider.providerTypeText;
                guardThis->activeProviderList_.push_back(entry);
            }
        }

        const std::wstring kSessionNameWide = guardThis->sessionName_.toStdWString();
        const ULONG kPropertyBufferSize = static_cast<ULONG>(
            sizeof(EVENT_TRACE_PROPERTIES) + (kSessionNameWide.size() + 1) * sizeof(wchar_t));
        std::vector<unsigned char> propertyBuffer(kPropertyBufferSize, 0);
        auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(propertyBuffer.data());

        properties->Wnode.BufferSize = kPropertyBufferSize;
        properties->Wnode.ClientContext = 2;
        properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        properties->BufferSize = 256;
        properties->MinimumBuffers = 32;
        properties->MaximumBuffers = 128;

        wchar_t* loggerNamePointer = reinterpret_cast<wchar_t*>(propertyBuffer.data() + properties->LoggerNameOffset);
        if (!kSessionNameWide.empty())
        {
            ::wcscpy_s(loggerNamePointer, kSessionNameWide.size() + 1, kSessionNameWide.c_str());
        }

        TRACEHANDLE sessionHandle = 0;
        ULONG startStatus = ::StartTraceW(&sessionHandle, loggerNamePointer, properties);
        if (startStatus == ERROR_ALREADY_EXISTS)
        {
            ::ControlTraceW(0, loggerNamePointer, properties, EVENT_TRACE_CONTROL_STOP);
            startStatus = ::StartTraceW(&sessionHandle, loggerNamePointer, properties);
        }

        if (startStatus != ERROR_SUCCESS)
        {
            QMetaObject::invokeMethod(qApp, [guardThis, startStatus]() {
                if (guardThis == nullptr)
                {
                    return;
                }

                guardThis->captureRunning_.store(false);
                guardThis->capturePaused_.store(false);
                if (guardThis->runtimeRefreshTimer_ != nullptr)
                {
                    guardThis->runtimeRefreshTimer_->stop();
                }
                if (guardThis->uiUpdateTimer_ != nullptr)
                {
                    guardThis->uiUpdateTimer_->stop();
                }
                kPro.set(guardThis->captureProgressPid_, "ETW 会话启动失败", 0, 100.0f);
                QMessageBox::warning(
                    guardThis,
                    QStringLiteral("进程定向监控"),
                    QStringLiteral("StartTraceW 失败，错误码=%1。").arg(startStatus));
                guardThis->updateActionState();
                guardThis->updateStatusLabel();
            }, Qt::QueuedConnection);
            return;
        }

        guardThis->sessionHandle_.store(static_cast<std::uint64_t>(sessionHandle));
        kPro.set(guardThis->captureProgressPid_, "启用固定 Provider 集合", 0, 30.0f);

        int enableSuccessCount = 0;
        for (const ProviderSelectionResolved& provider : selectedProviders)
        {
            if (guardThis == nullptr || guardThis->captureStopFlag_.load())
            {
                break;
            }

            const ULONG kEnableStatus = ::EnableTraceEx2(
                sessionHandle,
                &provider.providerGuid,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                TRACE_LEVEL_VERBOSE,
                0xFFFFFFFFFFFFFFFFULL,
                0,
                0,
                nullptr);
            if (kEnableStatus == ERROR_SUCCESS)
            {
                ++enableSuccessCount;
            }
            else
            {
                KLogEvent event;
                warn << event
                    << "[ProcessTraceMonitorWidget] EnableTraceEx2失败, provider="
                    << provider.providerName.toStdString()
                    << ", status="
                    << kEnableStatus
                    << eol;
            }
        }

        if (enableSuccessCount == 0)
        {
            ::ControlTraceW(sessionHandle, loggerNamePointer, properties, EVENT_TRACE_CONTROL_STOP);
            guardThis->sessionHandle_.store(0);
            QMetaObject::invokeMethod(qApp, [guardThis]() {
                if (guardThis == nullptr)
                {
                    return;
                }

                guardThis->captureRunning_.store(false);
                guardThis->capturePaused_.store(false);
                if (guardThis->runtimeRefreshTimer_ != nullptr)
                {
                    guardThis->runtimeRefreshTimer_->stop();
                }
                if (guardThis->uiUpdateTimer_ != nullptr)
                {
                    guardThis->uiUpdateTimer_->stop();
                }
                kPro.set(guardThis->captureProgressPid_, "Provider 启用失败", 0, 100.0f);
                QMessageBox::warning(
                    guardThis,
                    QStringLiteral("进程定向监控"),
                    QStringLiteral("固定 Provider 集合全部启用失败，监控已停止。"));
                guardThis->updateActionState();
                guardThis->updateStatusLabel();
            }, Qt::QueuedConnection);
            return;
        }

        EVENT_TRACE_LOGFILEW traceLogFile{};
        traceLogFile.LoggerName = loggerNamePointer;
        traceLogFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        traceLogFile.EventRecordCallback = &ProcessTraceMonitorWidget::processTraceEtwCallback;
        traceLogFile.Context = guardThis.data();

        TRACEHANDLE traceHandle = ::OpenTraceW(&traceLogFile);
        if (traceHandle == INVALID_PROCESSTRACE_HANDLE)
        {
            ::ControlTraceW(sessionHandle, loggerNamePointer, properties, EVENT_TRACE_CONTROL_STOP);
            guardThis->sessionHandle_.store(0);

            const ULONG kLastError = ::GetLastError();
            QMetaObject::invokeMethod(qApp, [guardThis, kLastError]() {
                if (guardThis == nullptr)
                {
                    return;
                }

                guardThis->captureRunning_.store(false);
                guardThis->capturePaused_.store(false);
                if (guardThis->runtimeRefreshTimer_ != nullptr)
                {
                    guardThis->runtimeRefreshTimer_->stop();
                }
                if (guardThis->uiUpdateTimer_ != nullptr)
                {
                    guardThis->uiUpdateTimer_->stop();
                }
                kPro.set(guardThis->captureProgressPid_, "OpenTrace 失败", 0, 100.0f);
                QMessageBox::warning(
                    guardThis,
                    QStringLiteral("进程定向监控"),
                    QStringLiteral("OpenTraceW 失败，错误码=%1。").arg(kLastError));
                guardThis->updateActionState();
                guardThis->updateStatusLabel();
            }, Qt::QueuedConnection);
            return;
        }

        guardThis->traceHandle_.store(static_cast<std::uint64_t>(traceHandle));
        kPro.set(guardThis->captureProgressPid_, "开始接收目标相关 ETW 事件", 0, 55.0f);

        const ULONG kProcessStatus = ::ProcessTrace(&traceHandle, 1, nullptr, nullptr);
        const std::uint64_t kOwnedTraceHandle = guardThis->traceHandle_.exchange(0);
        if (kOwnedTraceHandle != 0)
        {
            ::CloseTrace(static_cast<TRACEHANDLE>(kOwnedTraceHandle));
        }

        const std::uint64_t kOwnedSessionHandle = guardThis->sessionHandle_.exchange(0);
        if (kOwnedSessionHandle != 0)
        {
            ::ControlTraceW(
                static_cast<TRACEHANDLE>(kOwnedSessionHandle),
                loggerNamePointer,
                properties,
                EVENT_TRACE_CONTROL_STOP);
        }

        QMetaObject::invokeMethod(qApp, [guardThis, kProcessStatus]() {
            if (guardThis == nullptr)
            {
                return;
            }

            if (guardThis->captureStopTime100ns_ == 0)
            {
                guardThis->captureStopTime100ns_ = guardThis->currentSystemTime100ns();
            }
            guardThis->captureRunning_.store(false);
            guardThis->capturePaused_.store(false);
            if (guardThis->runtimeRefreshTimer_ != nullptr)
            {
                guardThis->runtimeRefreshTimer_->stop();
            }
            if (guardThis->uiUpdateTimer_ != nullptr)
            {
                guardThis->flushPendingRows();
            }
            kPro.set(guardThis->captureProgressPid_, "进程定向监控结束", 0, 100.0f);
            guardThis->refreshTimelineRange(true);
            if (guardThis->hasAnyEventFilterActive())
            {
                guardThis->applyEventFilter();
            }

            if (kProcessStatus == ERROR_SUCCESS)
            {
                guardThis->updateActionState();
                guardThis->updateStatusLabel();
            }
            else
            {
                guardThis->updateActionState();
                guardThis->updateStatusLabel();
                QMessageBox::warning(
                    guardThis,
                    QStringLiteral("进程定向监控"),
                    QStringLiteral("ProcessTrace 结束，状态码=%1。").arg(kProcessStatus));
            }
        }, Qt::QueuedConnection);
    });
}

void ProcessTraceMonitorWidget::stopMonitoring()
{
    stopMonitoringInternal(false);
}

void ProcessTraceMonitorWidget::stopMonitoringInternal(const bool waitForThread)
{
    captureStopFlag_.store(true);
    if (captureRunning_.load() && captureStopTime100ns_ == 0)
    {
        captureStopTime100ns_ = currentSystemTime100ns();
        refreshTimelineRange(true);
    }

    const std::uint64_t kOwnedTraceHandle = traceHandle_.exchange(0);
    if (kOwnedTraceHandle != 0)
    {
        ::CloseTrace(static_cast<TRACEHANDLE>(kOwnedTraceHandle));
    }

    const std::uint64_t kOwnedSessionHandle = sessionHandle_.exchange(0);
    if (kOwnedSessionHandle != 0)
    {
        const std::wstring kSessionNameWide = sessionName_.toStdWString();
        const ULONG kPropertyBufferSize = static_cast<ULONG>(
            sizeof(EVENT_TRACE_PROPERTIES) + (kSessionNameWide.size() + 1) * sizeof(wchar_t));
        std::vector<unsigned char> propertyBuffer(kPropertyBufferSize, 0);
        auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(propertyBuffer.data());
        properties->Wnode.BufferSize = kPropertyBufferSize;
        properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        wchar_t* loggerNamePointer = reinterpret_cast<wchar_t*>(propertyBuffer.data() + properties->LoggerNameOffset);
        if (!kSessionNameWide.empty())
        {
            ::wcscpy_s(loggerNamePointer, kSessionNameWide.size() + 1, kSessionNameWide.c_str());
        }

        ::ControlTraceW(
            static_cast<TRACEHANDLE>(kOwnedSessionHandle),
            loggerNamePointer,
            properties,
            EVENT_TRACE_CONTROL_STOP);
    }

    if (runtimeRefreshTimer_ != nullptr && runtimeRefreshTimer_->isActive())
    {
        runtimeRefreshTimer_->stop();
    }
    if (waitForThread && uiUpdateTimer_ != nullptr && uiUpdateTimer_->isActive())
    {
        uiUpdateTimer_->stop();
    }

    if (captureThread_ == nullptr || !captureThread_->joinable())
    {
        captureThread_.reset();
        captureRunning_.store(false);
        capturePaused_.store(false);
        updateActionState();
        updateStatusLabel();
        return;
    }

    if (waitForThread)
    {
        captureThread_->join();
        captureThread_.reset();
        captureRunning_.store(false);
        capturePaused_.store(false);
        updateActionState();
        updateStatusLabel();
        return;
    }

    // Interaction stop only requests the ETW thread to exit; it must not move the sole join handle to the detached
    // recycling thread. The destructor must still be able to synchronously wait for that thread, ensuring the
    // control pointed to by the ETW callback Context remains valid until ProcessTrace and all callbacks complete.
    updateActionState();
    updateStatusLabel();
}

void ProcessTraceMonitorWidget::setMonitoringPaused(const bool paused)
{
    if (!captureRunning_.load())
    {
        return;
    }

    capturePaused_.store(paused);
    updateActionState();
    updateStatusLabel();

    KLogEvent event;
    info << event
        << "[ProcessTraceMonitorWidget] 监控暂停状态变更, paused="
        << (paused ? "true" : "false")
        << eol;
}

void ProcessTraceMonitorWidget::refreshTrackedProcessSnapshotAsync()
{
    if (!captureRunning_.load() || runtimeRefreshPending_.exchange(true))
    {
        return;
    }

    QPointer<ProcessTraceMonitorWidget> guardThis(this);
    std::thread([guardThis]() {
        std::vector<ks::process::ProcessRecord> processList = ks::process::enumerateProcesses(
            ks::process::ProcessEnumStrategy::kAuto);
        QMetaObject::invokeMethod(qApp, [guardThis, processList = std::move(processList)]() {
            if (guardThis == nullptr)
            {
                return;
            }

            guardThis->runtimeRefreshPending_.store(false);
            guardThis->syncTrackedProcessTree(processList);
            guardThis->refreshTargetTable();
            guardThis->updateStatusLabel();
        }, Qt::QueuedConnection);
    }).detach();
}

void ProcessTraceMonitorWidget::seedTrackedProcessTree(const std::vector<ks::process::ProcessRecord>& processList)
{
    std::lock_guard<std::mutex> lock(runtimeMutex_);
    trackedProcessMap_.clear();

    for (TargetProcessEntry& targetEntry : targetProcessList_)
    {
        targetEntry.alive = false;
        const auto kFound = std::find_if(
            processList.begin(),
            processList.end(),
            [&targetEntry](const ks::process::ProcessRecord& record) {
                return record.pid == targetEntry.pid;
            });

        RuntimeTrackedProcess trackedProcess;
        trackedProcess.pid = targetEntry.pid;
        trackedProcess.parentPid = 0;
        trackedProcess.rootPid = targetEntry.pid;
        trackedProcess.processName = targetEntry.processName;
        trackedProcess.imagePath = targetEntry.imagePath;
        trackedProcess.creationTime100ns = targetEntry.creationTime100ns;
        trackedProcess.alive = targetEntry.alive;
        trackedProcess.isRoot = true;
        trackedProcess.staleSnapshotRounds = 0;
        trackedProcess.lastRelatedEventTime100ns = 0;

        if (kFound != processList.end())
        {
            const bool kCreationMatches = targetEntry.creationTime100ns == 0
                || kFound->creationTime100ns == 0
                || targetEntry.creationTime100ns == kFound->creationTime100ns;
            if (kCreationMatches)
            {
                trackedProcess.parentPid = kFound->parentPid;
                trackedProcess.processName = QString::fromStdString(kFound->processName);
                trackedProcess.imagePath = QString::fromStdString(kFound->imagePath);
                trackedProcess.creationTime100ns = kFound->creationTime100ns;
                trackedProcess.alive = true;

                targetEntry.processName = trackedProcess.processName;
                targetEntry.imagePath = trackedProcess.imagePath;
                targetEntry.creationTime100ns = trackedProcess.creationTime100ns;
                targetEntry.alive = true;
            }
        }

        trackedProcessMap_[trackedProcess.pid] = trackedProcess;
    }

    bool added = true;
    while (added)
    {
        added = false;
        for (const ks::process::ProcessRecord& record : processList)
        {
            if (record.pid == 0 || trackedProcessMap_.find(record.pid) != trackedProcessMap_.end())
            {
                continue;
            }

            const auto kParentIt = trackedProcessMap_.find(record.parentPid);
            if (kParentIt == trackedProcessMap_.end())
            {
                continue;
            }

            RuntimeTrackedProcess trackedProcess;
            trackedProcess.pid = record.pid;
            trackedProcess.parentPid = record.parentPid;
            trackedProcess.rootPid = kParentIt->second.rootPid;
            trackedProcess.processName = QString::fromStdString(record.processName);
            trackedProcess.imagePath = QString::fromStdString(record.imagePath);
            trackedProcess.creationTime100ns = record.creationTime100ns;
            trackedProcess.alive = true;
            trackedProcess.isRoot = false;
            trackedProcess.staleSnapshotRounds = 0;
            trackedProcess.lastRelatedEventTime100ns = 0;
            trackedProcessMap_[trackedProcess.pid] = trackedProcess;
            added = true;
        }
    }
}

void ProcessTraceMonitorWidget::syncTrackedProcessTree(const std::vector<ks::process::ProcessRecord>& processList)
{
    std::lock_guard<std::mutex> lock(runtimeMutex_);

    for (auto& [pidValue, trackedProcess] : trackedProcessMap_)
    {
        (void)pidValue;
        trackedProcess.alive = false;
    }

    bool added = true;
    while (added)
    {
        added = false;
        for (const ks::process::ProcessRecord& record : processList)
        {
            if (record.pid == 0)
            {
                continue;
            }

            auto existingIt = trackedProcessMap_.find(record.pid);
            if (existingIt != trackedProcessMap_.end())
            {
                const bool kCreationMatches = existingIt->second.creationTime100ns == 0
                    || record.creationTime100ns == 0
                    || existingIt->second.creationTime100ns == record.creationTime100ns;
                if (!kCreationMatches)
                {
                    if (existingIt->second.isRoot)
                    {
                        existingIt->second.alive = false;
                        continue;
                    }

                    const auto kParentIt = trackedProcessMap_.find(record.parentPid);
                    if (kParentIt == trackedProcessMap_.end())
                    {
                        existingIt->second.alive = false;
                        continue;
                    }

                    existingIt->second.parentPid = record.parentPid;
                    existingIt->second.rootPid = kParentIt->second.rootPid;
                    existingIt->second.processName = QString::fromStdString(record.processName);
                    existingIt->second.imagePath = QString::fromStdString(record.imagePath);
                    existingIt->second.creationTime100ns = record.creationTime100ns;
                    existingIt->second.alive = true;
                    existingIt->second.isRoot = false;
                    existingIt->second.staleSnapshotRounds = 0;
                    continue;
                }

                existingIt->second.parentPid = record.parentPid;
                existingIt->second.processName = QString::fromStdString(record.processName);
                existingIt->second.imagePath = QString::fromStdString(record.imagePath);
                existingIt->second.creationTime100ns = record.creationTime100ns;
                existingIt->second.alive = true;
                existingIt->second.staleSnapshotRounds = 0;
                continue;
            }

            const auto kParentIt = trackedProcessMap_.find(record.parentPid);
            if (kParentIt == trackedProcessMap_.end())
            {
                continue;
            }

            RuntimeTrackedProcess trackedProcess;
            trackedProcess.pid = record.pid;
            trackedProcess.parentPid = record.parentPid;
            trackedProcess.rootPid = kParentIt->second.rootPid;
            trackedProcess.processName = QString::fromStdString(record.processName);
            trackedProcess.imagePath = QString::fromStdString(record.imagePath);
            trackedProcess.creationTime100ns = record.creationTime100ns;
            trackedProcess.alive = true;
            trackedProcess.isRoot = false;
            trackedProcess.staleSnapshotRounds = 0;
            trackedProcess.lastRelatedEventTime100ns = 0;
            trackedProcessMap_[trackedProcess.pid] = trackedProcess;
            added = true;
        }
    }

    pruneStaleTrackedProcesses();

    for (TargetProcessEntry& targetEntry : targetProcessList_)
    {
        const auto kTrackedIt = trackedProcessMap_.find(targetEntry.pid);
        if (kTrackedIt == trackedProcessMap_.end())
        {
            targetEntry.alive = false;
            continue;
        }

        const bool kCreationMatches = targetEntry.creationTime100ns == 0
            || kTrackedIt->second.creationTime100ns == 0
            || targetEntry.creationTime100ns == kTrackedIt->second.creationTime100ns;
        targetEntry.alive = kTrackedIt->second.alive && kCreationMatches;
        if (!kCreationMatches)
        {
            continue;
        }
        if (!kTrackedIt->second.processName.trimmed().isEmpty())
        {
            targetEntry.processName = kTrackedIt->second.processName;
        }
        if (!kTrackedIt->second.imagePath.trimmed().isEmpty())
        {
            targetEntry.imagePath = kTrackedIt->second.imagePath;
        }
        if (kTrackedIt->second.creationTime100ns != 0)
        {
            targetEntry.creationTime100ns = kTrackedIt->second.creationTime100ns;
        }
    }
}

void ProcessTraceMonitorWidget::pruneStaleTrackedProcesses()
{
    FILETIME fileTimeValue{};
    ::GetSystemTimeAsFileTime(&fileTimeValue);
    ULARGE_INTEGER currentTimeValue{};
    currentTimeValue.LowPart = fileTimeValue.dwLowDateTime;
    currentTimeValue.HighPart = fileTimeValue.dwHighDateTime;
    const std::uint64_t kCurrentTime100ns = static_cast<std::uint64_t>(currentTimeValue.QuadPart);
    const std::uint64_t kRecentEventKeepWindow100ns = 15ULL * 1000ULL * 1000ULL * 10ULL;

    std::vector<std::uint32_t> pidListNeedErase;
    pidListNeedErase.reserve(trackedProcessMap_.size());

    for (auto& [pidValue, trackedProcess] : trackedProcessMap_)
    {
        (void)pidValue;
        if (trackedProcess.alive)
        {
            trackedProcess.staleSnapshotRounds = 0;
            continue;
        }

        ++trackedProcess.staleSnapshotRounds;
        const bool kRecentEventHit = trackedProcess.lastRelatedEventTime100ns != 0
            && trackedProcess.lastRelatedEventTime100ns <= kCurrentTime100ns
            && (kCurrentTime100ns - trackedProcess.lastRelatedEventTime100ns) <= kRecentEventKeepWindow100ns;
        if (!trackedProcess.isRoot
            && trackedProcess.staleSnapshotRounds >= 3
            && !kRecentEventHit)
        {
            pidListNeedErase.push_back(trackedProcess.pid);
        }
    }

    for (const std::uint32_t kPidValue : pidListNeedErase)
    {
        trackedProcessMap_.erase(kPidValue);
    }
}
