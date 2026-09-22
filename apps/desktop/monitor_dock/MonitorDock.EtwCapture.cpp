#include "MonitorDock.Support.h"

using namespace ksword::ui::monitor_dock;

void MonitorDock::startEtwCapture()
{
    if (etwCaptureRunning_.load())
    {
        if (etwCapturePaused_.load())
        {
            setEtwCapturePaused(false);
        }
        else
        {
            KLogEvent event;
            dbg << event
                << "[MonitorDock] 忽略启动ETW：当前已在监听。"
                << eol;
        }
        return;
    }

    if (etwCaptureThread_ != nullptr && etwCaptureThread_->joinable())
    {
        etwCaptureThread_->join();
        etwCaptureThread_.reset();
    }

    EtwSimpleFilterCompiled preSimpleCheck;
    EtwSimpleFilterCompiled postSimpleCheck;
    std::vector<EtwFilterRuleGroupCompiled> preCheckGroupList;
    std::vector<EtwFilterRuleGroupCompiled> postCheckGroupList;
    QString filterCompileError;
    if (!tryCompileEtwSimpleFilter(EtwFilterStage::kPre, preSimpleCheck, filterCompileError)
        || !tryCompileEtwFilterGroups(EtwFilterStage::kPre, preCheckGroupList, filterCompileError))
    {
        QMessageBox::warning(this, QStringLiteral("ETW前置筛选"), filterCompileError);
        return;
    }
    if (!tryCompileEtwSimpleFilter(EtwFilterStage::kPost, postSimpleCheck, filterCompileError)
        || !tryCompileEtwFilterGroups(EtwFilterStage::kPost, postCheckGroupList, filterCompileError))
    {
        QMessageBox::warning(this, QStringLiteral("ETW后置筛选"), filterCompileError);
        return;
    }

    applyEtwFilterRules(EtwFilterStage::kPre);
    applyEtwFilterRules(EtwFilterStage::kPost);

    // Collect selected providers and parse their GUIDs.
    struct ProviderSelection
    {
        QString name; // Provider name, used for logging/display.
        GUID guid{};  // Provider GUID, used for EnableTraceEx2.
    };

    std::vector<ProviderSelection> selectedProviders;
    selectedProviders.reserve(static_cast<std::size_t>(
        etwProviderList_->count()
        + (etwPresetProviderList_ != nullptr ? etwPresetProviderList_->count() : 0)
        + 1));

    auto tryAppendProvider = [&selectedProviders](const QString& providerName, const QString& guidText) {
        GUID guidValue{};
        if (!parseGuidText(guidText, guidValue))
        {
            return false;
        }

        const bool kDuplicate = std::any_of(
            selectedProviders.begin(),
            selectedProviders.end(),
            [&guidValue](const ProviderSelection& item) {
                return ::IsEqualGUID(item.guid, guidValue) != FALSE;
            });
        if (kDuplicate)
        {
            return true;
        }

        ProviderSelection selection;
        selection.name = providerName;
        selection.guid = guidValue;
        selectedProviders.push_back(selection);
        return true;
    };

    for (int i = 0; i < etwProviderList_->count(); ++i)
    {
        QListWidgetItem* item = etwProviderList_->item(i);
        if (item == nullptr || item->checkState() != Qt::Checked)
        {
            continue;
        }
        const QString kProviderName = item->data(Qt::UserRole).toString();
        const QString kProviderGuid = item->data(Qt::UserRole + 1).toString();
        tryAppendProvider(kProviderName, kProviderGuid);
    }

    // Preset template check options: standard providers map by name to GUID; threads and images use classic kernel flags.
    int presetCheckedCount = 0;
    int presetMatchedCount = 0;
    ULONG legacyKernelEnableFlags = 0;
    if (etwPresetProviderList_ != nullptr)
    {
        for (int i = 0; i < etwPresetProviderList_->count(); ++i)
        {
            QListWidgetItem* item = etwPresetProviderList_->item(i);
            if (item == nullptr || item->checkState() != Qt::Checked)
            {
                continue;
            }
            ++presetCheckedCount;

            const QString kPresetProviderName = item->data(Qt::UserRole).toString().trimmed();
            if (kPresetProviderName.isEmpty())
            {
                continue;
            }

            const EtwPresetProviderDescriptor* presetDescriptor =
                findEtwPresetProviderDescriptor(kPresetProviderName);
            if (presetDescriptor != nullptr && presetDescriptor->legacyKernelEnableFlags != 0)
            {
                legacyKernelEnableFlags |= presetDescriptor->legacyKernelEnableFlags;
                ++presetMatchedCount;
                continue;
            }

            const auto kExactFound = std::find_if(
                etwProviders_.begin(),
                etwProviders_.end(),
                [kPresetProviderName](const EtwProviderEntry& entry) {
                    return entry.providerName.compare(kPresetProviderName, Qt::CaseInsensitive) == 0;
                });

            bool matched = false;
            if (kExactFound != etwProviders_.end())
            {
                matched = tryAppendProvider(kExactFound->providerName, kExactFound->providerGuidText);
            }
            else
            {
                // Fuzzy fallback: Allow template names to have suffix differences from system Provider names.
                const auto kFuzzyFound = std::find_if(
                    etwProviders_.begin(),
                    etwProviders_.end(),
                    [kPresetProviderName](const EtwProviderEntry& entry) {
                        return entry.providerName.contains(kPresetProviderName, Qt::CaseInsensitive)
                            || kPresetProviderName.contains(entry.providerName, Qt::CaseInsensitive);
                    });
                if (kFuzzyFound != etwProviders_.end())
                {
                    matched = tryAppendProvider(kFuzzyFound->providerName, kFuzzyFound->providerGuidText);
                }
            }

            if (matched)
            {
                ++presetMatchedCount;
            }
            else
            {
                KLogEvent event;
                warn << event
                    << "[MonitorDock] ETW预置模板未命中系统Provider, template="
                    << kPresetProviderName.toStdString()
                    << eol;
            }
        }
    }

    // Manual input supports both GUIDs and Provider names.
    const QString kManualText = etwManualProviderEdit_->text().trimmed();
    if (!kManualText.isEmpty())
    {
        if (!tryAppendProvider(kManualText, kManualText))
        {
            const auto kFound = std::find_if(
                etwProviders_.begin(),
                etwProviders_.end(),
                [kManualText](const EtwProviderEntry& entry) {
                    return entry.providerName.compare(kManualText, Qt::CaseInsensitive) == 0;
                });
            if (kFound != etwProviders_.end())
            {
                tryAppendProvider(kFound->providerName, kFound->providerGuidText);
            }
        }
    }

    {
        KLogEvent event;
        info << event
            << "[MonitorDock] ETW预置模板统计, checked="
            << presetCheckedCount
            << ", matched="
            << presetMatchedCount
            << eol;
    }

    if (selectedProviders.empty() && legacyKernelEnableFlags == 0)
    {
        KLogEvent event;
        warn << event
            << "[MonitorDock] 启动ETW失败：未选择可用Provider。"
            << eol;
        QMessageBox::information(this, QStringLiteral("ETW监听"), QStringLiteral("请至少选择一个可解析 GUID 的 Provider。"));
        return;
    }

    // The capture callback reads only this session snapshot; Provider refresh no longer causes concurrent access to m_etwProviders with the callback thread.
    etwCaptureProviderNames_.clear();
    for (const ProviderSelection& provider : selectedProviders)
    {
        etwCaptureProviderNames_.insert(guidToText(provider.guid), provider.name);
    }
    if (legacyKernelEnableFlags != 0)
    {
        etwCaptureProviderNames_.insert(
            guidToText(kWindowsKernelTraceProviderGuid),
            QStringLiteral("Windows Kernel Trace"));
    }

    QString archiveErrorText;
    if (!prepareEtwArchiveSession(&archiveErrorText))
    {
        QMessageBox::warning(this, QStringLiteral("ETW监听"), archiveErrorText);
        return;
    }

    // Clear old results before starting a new ETW listening session.
    // - The table, post-cache, and timeline points must be synchronized to zero.
    // - The timeline start uses the 100ns timestamp at the launch instant, with the right boundary following in real-time.
    if (etwEventTable_ != nullptr)
    {
        etwEventTable_->clearContents();
        etwEventTable_->setRowCount(0);
    }
    etwCapturedRows_.clear();
    etwTimelineEventPoints_.clear();
    etwTimelinePauseIntervals_.clear();
    etwCaptureStartTime100ns_ = currentSystemTime100ns();
    etwCaptureStopTime100ns_ = 0;
    etwTimelinePauseTime100ns_ = 0;
    etwTimelineSelectionStart100ns_ = etwCaptureStartTime100ns_;
    etwTimelineSelectionEnd100ns_ = etwCaptureStartTime100ns_;
    etwTimelineUserSelectionActive_ = false;
    if (etwTimelineWidget_ != nullptr)
    {
        etwTimelineWidget_->resetTimeline(etwCaptureStartTime100ns_);
        etwTimelineSelectionStart100ns_ = etwTimelineWidget_->selectionStart100ns();
        etwTimelineSelectionEnd100ns_ = etwTimelineWidget_->selectionEnd100ns();
    }
    applyEtwPostFilterToTable();

    // Clear the pending refresh queue to avoid mixing data from the previous round into the current one.
    {
        std::lock_guard<std::mutex> lock(etwPendingMutex_);
        etwPendingRows_.clear();
    }
    etwUiSkippedRows_.store(0, std::memory_order_relaxed);
    etwSourceEventsLost_.store(0, std::memory_order_relaxed);

    // Refresh the schema cache once before each listening round:
    // - This ensures that the current session is remodeled based on the latest event layout.
    // - Subsequent events of the same type directly use the cache without repeatedly calling TDH.
    clearEtwSchemaCache();

    etwCaptureRunning_.store(true);
    etwCapturePaused_.store(false);
    etwTimelinePauseTime100ns_ = 0;
    etwCaptureStopFlag_.store(false);
    etwSessionHandle_.store(0);
    etwTraceHandle_.store(0);
    stopActiveKswordTraceSessionsByPrefix(QStringList{ QStringLiteral("KswordEtw") });
    etwSessionName_ = QStringLiteral("KswordEtw");

    if (etwCaptureProgressPid_ == 0)
    {
        etwCaptureProgressPid_ = kPro.addReusable(this, "监控", "ETW监听");
    }
    kPro.set(etwCaptureProgressPid_, "准备ETW实时会话", 0, 10.0f);

    etwCaptureStatusLabel_->setText(QStringLiteral("● 监听中"));
    ks::ui::applyStatusRole(etwCaptureStatusLabel_, ks::ui::StatusRole::kInfo);
    updateEtwCaptureActionState();

    if (etwUiUpdateTimer_ != nullptr && !etwUiUpdateTimer_->isActive())
    {
        etwUiUpdateTimer_->start();
    }

    const UCHAR kTraceLevel = etwLevelFromText(etwLevelCombo_->currentText());
    const ULONGLONG kKeywordMask = parseKeywordMaskText(etwKeywordMaskEdit_->text());
    const ULONG kBufferSizeKb = static_cast<ULONG>(etwBufferSizeSpin_->value());
    const ULONG kMinBuffer = static_cast<ULONG>(etwMinBufferSpin_->value());
    const ULONG kMaxBuffer = static_cast<ULONG>(etwMaxBufferSpin_->value());

    {
        KLogEvent event;
        info << event
            << "[MonitorDock] 启动ETW监听, providerCount="
            << selectedProviders.size()
            << ", level="
            << static_cast<int>(kTraceLevel)
            << ", keywordMask=0x"
            << QString::number(static_cast<qulonglong>(kKeywordMask), 16).toUpper().toStdString()
            << ", bufferSizeKb="
            << kBufferSizeKb
            << ", minBuffer="
            << kMinBuffer
            << ", maxBuffer="
            << kMaxBuffer
            << eol;
    }

    QPointer<MonitorDock> guardThis(this);
    etwCaptureThread_ = std::make_unique<std::thread>(
        [guardThis, selectedProviders, legacyKernelEnableFlags, kTraceLevel, kKeywordMask, kBufferSizeKb, kMinBuffer, kMaxBuffer]() {
        if (guardThis == nullptr)
        {
            return;
        }

        const auto kReportStopped = [guardThis]()
        {
            QMetaObject::invokeMethod(qApp, [guardThis]() {
                if (guardThis == nullptr)
                {
                    return;
                }
                const bool kWasPaused = guardThis->etwCapturePaused_.load();
                const std::uint64_t kPauseEnd100ns = guardThis->etwTimelinePauseTime100ns_;
                guardThis->etwCaptureRunning_.store(false);
                guardThis->etwCapturePaused_.store(false);
                if (guardThis->etwCaptureStopTime100ns_ == 0)
                {
                    guardThis->etwCaptureStopTime100ns_ = kWasPaused && kPauseEnd100ns != 0
                        ? kPauseEnd100ns
                        : currentSystemTime100ns();
                }
                if (kWasPaused && kPauseEnd100ns != 0)
                {
                    guardThis->closeEtwTimelinePauseInterval(kPauseEnd100ns);
                }
                guardThis->etwTimelinePauseTime100ns_ = 0;

                const std::uint64_t kEventsLost = guardThis->etwSourceEventsLost_.load(std::memory_order_relaxed);
                const bool kArchiveFailed = guardThis->etwArchiveWriteFailed_.load(std::memory_order_relaxed);
                if (guardThis->etwCaptureStatusLabel_ != nullptr)
                {
                    guardThis->etwCaptureStatusLabel_->setText(kArchiveFailed
                        ? QStringLiteral("● ETW归档写入失败")
                        : (kEventsLost == 0
                            ? QStringLiteral("● 已停止")
                            : QStringLiteral("● ETW源事件丢失:%1").arg(static_cast<qulonglong>(kEventsLost))));
                    ks::ui::applyStatusRole(guardThis->etwCaptureStatusLabel_,
                        !kArchiveFailed && kEventsLost == 0 ? ks::ui::StatusRole::kIdle : ks::ui::StatusRole::kError);
                }
                guardThis->updateEtwCaptureActionState();
                if (guardThis->etwUiUpdateTimer_ != nullptr && guardThis->etwUiUpdateTimer_->isActive())
                {
                    guardThis->etwUiUpdateTimer_->stop();
                }
                guardThis->flushEtwPendingRows(true);
                guardThis->scheduleEtwArchiveFilterRebuild();
                kPro.set(guardThis->etwCaptureProgressPid_, "ETW监听结束", 0, 100.0f);
            }, Qt::QueuedConnection);
        };

        const std::wstring kSessionNameWide = guardThis->etwSessionName_.toStdWString();
        const ULONG kPropertyBufferSize = static_cast<ULONG>(
            sizeof(EVENT_TRACE_PROPERTIES) + (kSessionNameWide.size() + 1) * sizeof(wchar_t));
        std::vector<unsigned char> propertyBuffer(kPropertyBufferSize, 0);
        auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(propertyBuffer.data());

        properties->Wnode.BufferSize = kPropertyBufferSize;
        properties->Wnode.ClientContext = 2; // 2=SystemTime（100ns）。
        properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        if (legacyKernelEnableFlags != 0)
        {
            // Kernel-Thread and Kernel-Image are classic kernel events that do not appear in the
            // TdhEnumerateProviders list. Enable them via a private SystemTraceProvider session while
            // retaining the EnableTraceEx2 subscription capability of standard manifest Providers.
            properties->Wnode.Guid = kKswordEtwKernelSessionGuid;
            properties->LogFileMode |= EVENT_TRACE_SYSTEM_LOGGER_MODE;
            properties->EnableFlags = legacyKernelEnableFlags;
        }
        properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        properties->BufferSize = kBufferSizeKb;
        properties->MinimumBuffers = kMinBuffer;
        properties->MaximumBuffers = kMaxBuffer;

        wchar_t* loggerNamePtr = reinterpret_cast<wchar_t*>(propertyBuffer.data() + properties->LoggerNameOffset);
        if (!kSessionNameWide.empty())
        {
            ::wcscpy_s(loggerNamePtr, kSessionNameWide.size() + 1, kSessionNameWide.c_str());
        }

        TRACEHANDLE sessionHandle = 0;
        ULONG startStatus = ::StartTraceW(&sessionHandle, loggerNamePtr, properties);
        if (startStatus == ERROR_ALREADY_EXISTS)
        {
            ::ControlTraceW(0, loggerNamePtr, properties, EVENT_TRACE_CONTROL_STOP);
            startStatus = ::StartTraceW(&sessionHandle, loggerNamePtr, properties);
        }

        if (startStatus != ERROR_SUCCESS)
        {
            guardThis->finishEtwArchiveSession();
            QMetaObject::invokeMethod(qApp, [guardThis, startStatus]() {
                if (guardThis == nullptr)
                {
                    return;
                }
                guardThis->etwCaptureRunning_.store(false);
                guardThis->etwCapturePaused_.store(false);
                guardThis->etwTimelinePauseTime100ns_ = 0;
                guardThis->etwCaptureStatusLabel_->setText(QStringLiteral("● 启动失败:%1").arg(startStatus));
                ks::ui::applyStatusRole(guardThis->etwCaptureStatusLabel_, ks::ui::StatusRole::kError);
                guardThis->updateEtwCaptureActionState();
                kPro.set(guardThis->etwCaptureProgressPid_, "ETW会话启动失败", 0, 100.0f);
            }, Qt::QueuedConnection);
            return;
        }

        guardThis->etwSessionHandle_.store(static_cast<std::uint64_t>(sessionHandle));
        if (guardThis->etwCaptureStopFlag_.load())
        {
            const std::uint64_t kOwnedSessionHandle = guardThis->etwSessionHandle_.exchange(0);
            if (kOwnedSessionHandle != 0)
            {
                ::ControlTraceW(
                    static_cast<TRACEHANDLE>(kOwnedSessionHandle),
                    loggerNamePtr,
                    properties,
                    EVENT_TRACE_CONTROL_STOP);
            }
            guardThis->finishEtwArchiveSession();
            kReportStopped();
            return;
        }
        kPro.set(guardThis->etwCaptureProgressPid_, "启用Provider", 0, 30.0f);

        int enableSuccessCount = legacyKernelEnableFlags != 0 ? 1 : 0;
        for (const ProviderSelection& provider : selectedProviders)
        {
            if (guardThis == nullptr || guardThis->etwCaptureStopFlag_.load())
            {
                break;
            }

            const ULONG kEnableStatus = ::EnableTraceEx2(
                sessionHandle,
                &provider.guid,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                kTraceLevel,
                kKeywordMask,
                0,
                0,
                nullptr);

            if (kEnableStatus == ERROR_SUCCESS)
            {
                ++enableSuccessCount;
            }
            else
            {
                KLogEvent enableEvent;
                warn << enableEvent
                    << "[MonitorDock] EnableTraceEx2失败 provider="
                    << provider.name.toStdString()
                    << ", status="
                    << kEnableStatus
                    << eol;
            }
        }

        if (enableSuccessCount == 0)
        {
            ::ControlTraceW(sessionHandle, loggerNamePtr, properties, EVENT_TRACE_CONTROL_STOP);
            guardThis->etwSessionHandle_.store(0);
            guardThis->finishEtwArchiveSession();
            QMetaObject::invokeMethod(qApp, [guardThis]() {
                if (guardThis == nullptr)
                {
                    return;
                }
                guardThis->etwCaptureRunning_.store(false);
                guardThis->etwCapturePaused_.store(false);
                guardThis->etwTimelinePauseTime100ns_ = 0;
                guardThis->etwCaptureStatusLabel_->setText(QStringLiteral("● 无可用Provider"));
                ks::ui::applyStatusRole(guardThis->etwCaptureStatusLabel_, ks::ui::StatusRole::kError);
                guardThis->updateEtwCaptureActionState();
                kPro.set(guardThis->etwCaptureProgressPid_, "Provider启用失败", 0, 100.0f);
            }, Qt::QueuedConnection);
            return;
        }

        // Open a real-time consumption handle and enter ProcessTrace for blocking reads.
        EVENT_TRACE_LOGFILEW logFile{};
        logFile.LoggerName = loggerNamePtr;
        logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logFile.EventRecordCallback = &MonitorDock::etwEventRecordCallback;
        logFile.Context = guardThis.data();

        TRACEHANDLE traceHandle = ::OpenTraceW(&logFile);
        if (traceHandle == INVALID_PROCESSTRACE_HANDLE)
        {
            ::ControlTraceW(sessionHandle, loggerNamePtr, properties, EVENT_TRACE_CONTROL_STOP);
            guardThis->etwSessionHandle_.store(0);
            guardThis->finishEtwArchiveSession();

            const ULONG kLastError = ::GetLastError();
            QMetaObject::invokeMethod(qApp, [guardThis, kLastError]() {
                if (guardThis == nullptr)
                {
                    return;
                }
                guardThis->etwCaptureRunning_.store(false);
                guardThis->etwCapturePaused_.store(false);
                guardThis->etwTimelinePauseTime100ns_ = 0;
                guardThis->etwCaptureStatusLabel_->setText(QStringLiteral("● OpenTrace失败:%1").arg(kLastError));
                ks::ui::applyStatusRole(guardThis->etwCaptureStatusLabel_, ks::ui::StatusRole::kError);
                guardThis->updateEtwCaptureActionState();
                kPro.set(guardThis->etwCaptureProgressPid_, "OpenTrace失败", 0, 100.0f);
            }, Qt::QueuedConnection);
            return;
        }

        guardThis->etwTraceHandle_.store(static_cast<std::uint64_t>(traceHandle));
        if (guardThis->etwCaptureStopFlag_.load())
        {
            const std::uint64_t kOwnedTraceHandle = guardThis->etwTraceHandle_.exchange(0);
            if (kOwnedTraceHandle != 0)
            {
                ::CloseTrace(static_cast<TRACEHANDLE>(kOwnedTraceHandle));
            }
            const std::uint64_t kOwnedSessionHandle = guardThis->etwSessionHandle_.exchange(0);
            if (kOwnedSessionHandle != 0)
            {
                ::ControlTraceW(
                    static_cast<TRACEHANDLE>(kOwnedSessionHandle),
                    loggerNamePtr,
                    properties,
                    EVENT_TRACE_CONTROL_STOP);
            }
            guardThis->finishEtwArchiveSession();
            kReportStopped();
            return;
        }
        kPro.set(guardThis->etwCaptureProgressPid_, "ETW事件接收中", 0, 55.0f);

        const ULONG kProcessStatus = ::ProcessTrace(&traceHandle, 1, nullptr, nullptr);
        const ULONG kEventsLost = logFile.EventsLost;
        guardThis->etwSourceEventsLost_.store(kEventsLost, std::memory_order_relaxed);
        guardThis->finishEtwArchiveSession();
        const std::uint64_t kOwnedTraceHandle = guardThis->etwTraceHandle_.exchange(0);
        if (kOwnedTraceHandle != 0)
        {
            ::CloseTrace(static_cast<TRACEHANDLE>(kOwnedTraceHandle));
        }

        const std::uint64_t kOwnedSessionHandle = guardThis->etwSessionHandle_.exchange(0);
        if (kOwnedSessionHandle != 0)
        {
            ::ControlTraceW(
                static_cast<TRACEHANDLE>(kOwnedSessionHandle),
                loggerNamePtr,
                properties,
                EVENT_TRACE_CONTROL_STOP);
        }

        QMetaObject::invokeMethod(qApp, [guardThis, kProcessStatus, kEventsLost]() {
            if (guardThis == nullptr)
            {
                return;
            }
            const bool kWasPaused = guardThis->etwCapturePaused_.load();
            const std::uint64_t kPauseEnd100ns = guardThis->etwTimelinePauseTime100ns_;
            guardThis->etwCaptureRunning_.store(false);
            guardThis->etwCapturePaused_.store(false);
            if (guardThis->etwCaptureStopTime100ns_ == 0)
            {
                guardThis->etwCaptureStopTime100ns_ = kWasPaused && kPauseEnd100ns != 0
                    ? kPauseEnd100ns
                    : currentSystemTime100ns();
            }
            if (kWasPaused && kPauseEnd100ns != 0)
            {
                guardThis->closeEtwTimelinePauseInterval(kPauseEnd100ns);
            }
            guardThis->etwTimelinePauseTime100ns_ = 0;

            if (guardThis->etwArchiveWriteFailed_.load(std::memory_order_relaxed))
            {
                guardThis->etwCaptureStatusLabel_->setText(QStringLiteral("● ETW归档写入失败"));
                ks::ui::applyStatusRole(guardThis->etwCaptureStatusLabel_, ks::ui::StatusRole::kError);
            }
            else if (kEventsLost != 0)
            {
                guardThis->etwCaptureStatusLabel_->setText(
                    QStringLiteral("● ETW源事件丢失:%1").arg(kEventsLost));
                ks::ui::applyStatusRole(guardThis->etwCaptureStatusLabel_, ks::ui::StatusRole::kError);
            }
            else if (kProcessStatus == ERROR_SUCCESS)
            {
                guardThis->etwCaptureStatusLabel_->setText(QStringLiteral("● 已停止"));
                ks::ui::applyStatusRole(guardThis->etwCaptureStatusLabel_, ks::ui::StatusRole::kIdle);
            }
            else
            {
                guardThis->etwCaptureStatusLabel_->setText(QStringLiteral("● 处理结束:%1").arg(kProcessStatus));
                ks::ui::applyStatusRole(guardThis->etwCaptureStatusLabel_, ks::ui::StatusRole::kWarning);
            }
            guardThis->updateEtwCaptureActionState();
            if (guardThis->etwUiUpdateTimer_ != nullptr && guardThis->etwUiUpdateTimer_->isActive())
            {
                guardThis->etwUiUpdateTimer_->stop();
            }
            guardThis->flushEtwPendingRows(true);
            guardThis->scheduleEtwArchiveFilterRebuild();
            if (kEventsLost != 0)
            {
                KLogEvent lostEvent;
                err << lostEvent
                    << "[MonitorDock] ETW源报告事件丢失, eventsLost="
                    << kEventsLost
                    << eol;
            }
            kPro.set(guardThis->etwCaptureProgressPid_, "ETW监听结束", 0, 100.0f);
        }, Qt::QueuedConnection);
    });
}
