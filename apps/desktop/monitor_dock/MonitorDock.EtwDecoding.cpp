#include "MonitorDock.Support.h"

using namespace ksword::ui::monitor_dock;

void WINAPI MonitorDock::etwEventRecordCallback(struct _EVENT_RECORD* eventRecordPtr)
{
    if (eventRecordPtr == nullptr)
    {
        return;
    }

    EVENT_RECORD* eventRecord = reinterpret_cast<EVENT_RECORD*>(eventRecordPtr);
    if (eventRecord == nullptr || eventRecord->UserContext == nullptr)
    {
        return;
    }

    auto* monitorDock = reinterpret_cast<MonitorDock*>(eventRecord->UserContext);
    monitorDock->enqueueEtwEventFromRecord(eventRecordPtr);
}

void MonitorDock::enqueueEtwEventFromRecord(const struct _EVENT_RECORD* eventRecordPtr)
{
    const EVENT_RECORD* eventRecord = reinterpret_cast<const EVENT_RECORD*>(eventRecordPtr);
    if (eventRecord == nullptr)
    {
        return;
    }

    if (etwCaptureStopFlag_.load() || etwCapturePaused_.load())
    {
        return;
    }

    const QString kProviderGuidText = guidToText(eventRecord->EventHeader.ProviderId);
    QString providerNameText = kProviderGuidText;
    const auto kProviderNameIt = etwCaptureProviderNames_.constFind(kProviderGuidText);
    if (kProviderNameIt != etwCaptureProviderNames_.cend())
    {
        providerNameText = kProviderNameIt.value();
    }

    EtwCapturedEventRow rowData;
    rowData.timestampText = etwTimestamp100nsText(eventRecord);
    rowData.timestampValue = static_cast<std::uint64_t>(eventRecord->EventHeader.TimeStamp.QuadPart);
    rowData.providerName = providerNameText;
    rowData.providerGuid = kProviderGuidText;
    rowData.providerCategory = etwInferProviderCategory(providerNameText);
    rowData.eventId = static_cast<int>(eventRecord->EventHeader.EventDescriptor.Id);
    rowData.eventName = QStringLiteral("Event_%1").arg(rowData.eventId);
    rowData.task = static_cast<int>(eventRecord->EventHeader.EventDescriptor.Task);
    rowData.opcode = static_cast<int>(eventRecord->EventHeader.EventDescriptor.Opcode);
    rowData.level = static_cast<int>(eventRecord->EventHeader.EventDescriptor.Level);
    rowData.levelText = etwFilterLevelTextFromValue(rowData.level);
    rowData.keywordMaskValue = static_cast<std::uint64_t>(eventRecord->EventHeader.EventDescriptor.Keyword);
    rowData.keywordMaskText = QStringLiteral("0x%1")
        .arg(static_cast<qulonglong>(rowData.keywordMaskValue), 16, 16, QChar(u'0'))
        .toUpper();
    rowData.headerPid = static_cast<std::uint32_t>(eventRecord->EventHeader.ProcessId);
    rowData.headerTid = static_cast<std::uint32_t>(eventRecord->EventHeader.ThreadId);
    rowData.activityId = guidToText(eventRecord->EventHeader.ActivityId);
    rowData.pidTidText = QStringLiteral("%1 / %2").arg(rowData.headerPid).arg(rowData.headerTid);

    EtwSchemaEntry schemaEntry;
    const bool kSchemaReady = tryGetEtwSchemaCached(eventRecord, &schemaEntry);
    if (kSchemaReady)
    {
        rowData.taskName = schemaEntry.taskNameText.trimmed();
        rowData.opcodeName = schemaEntry.opcodeNameText.trimmed();
        if (!schemaEntry.eventNameText.trimmed().isEmpty())
        {
            rowData.eventName = schemaEntry.eventNameText.trimmed();
        }
        else if (!schemaEntry.taskNameText.trimmed().isEmpty())
        {
            rowData.eventName = schemaEntry.taskNameText.trimmed();
        }
        else if (!schemaEntry.opcodeNameText.trimmed().isEmpty())
        {
            rowData.eventName = schemaEntry.opcodeNameText.trimmed();
        }
    }

    std::vector<EtwDecodedPropertyEntry> decodedPropertyList;
    QString unparsedTailHexText;
    ULONG parsedBytes = 0;
    bool decodeAttempted = false;
    auto ensureDecodedPayload = [&]() -> bool {
        if (rowData.decodedReady)
        {
            return true;
        }
        if (decodeAttempted && !rowData.decodedReady)
        {
            return false;
        }
        decodeAttempted = true;

        if (kSchemaReady)
        {
            decodeEtwPropertiesBySchema(
                eventRecord,
                schemaEntry,
                &decodedPropertyList,
                &parsedBytes,
                &unparsedTailHexText);

            const EtwSemanticSummary kSemanticSummary = inferEtwSemanticSummary(
                providerNameText,
                rowData.eventName,
                rowData.opcodeName,
                decodedPropertyList);
            rowData.detailJson = buildEtwDetailJson(
                eventRecord,
                kProviderGuidText,
                providerNameText,
                schemaEntry,
                kSemanticSummary,
                decodedPropertyList,
                parsedBytes,
                unparsedTailHexText);
            rowData.detailSummary = buildEtwSummaryText(
                providerNameText,
                rowData.eventName,
                rowData.opcodeName,
                rowData.headerPid,
                rowData.headerTid,
                kSemanticSummary,
                decodedPropertyList);
            fillEtwCapturedRowDecodedFields(
                &rowData,
                providerNameText,
                rowData.eventName,
                kSemanticSummary,
                decodedPropertyList);
        }
        else
        {
            if (eventRecord->UserData != nullptr && eventRecord->UserDataLength > 0)
            {
                const unsigned char* rawUserDataPointer = reinterpret_cast<const unsigned char*>(eventRecord->UserData);
                parsedBytes = 0;
                unparsedTailHexText = etwHexDump(rawUserDataPointer, eventRecord->UserDataLength);
            }

            QJsonObject fallbackMeta;
            fallbackMeta.insert(QStringLiteral("providerGuid"), kProviderGuidText);
            fallbackMeta.insert(QStringLiteral("providerName"), providerNameText);
            fallbackMeta.insert(QStringLiteral("eventId"), rowData.eventId);
            fallbackMeta.insert(QStringLiteral("eventName"), rowData.eventName);
            fallbackMeta.insert(QStringLiteral("task"), rowData.task);
            fallbackMeta.insert(QStringLiteral("opcode"), rowData.opcode);
            fallbackMeta.insert(QStringLiteral("level"), rowData.level);
            fallbackMeta.insert(QStringLiteral("keyword"), rowData.keywordMaskText);
            fallbackMeta.insert(QStringLiteral("note"), QStringLiteral("未获取到TDH schema，已保留原始十六进制数据"));
            fallbackMeta.insert(QStringLiteral("userDataLength"), static_cast<int>(eventRecord->UserDataLength));

            QJsonObject fallbackSemantic;
            fallbackSemantic.insert(QStringLiteral("resourceType"), inferEtwResourceType(providerNameText, rowData.eventName));
            fallbackSemantic.insert(QStringLiteral("action"), inferEtwActionText(rowData.eventName, rowData.opcodeName));
            fallbackSemantic.insert(QStringLiteral("target"), QString());
            fallbackSemantic.insert(QStringLiteral("status"), QString());

            QJsonObject fallbackRoot;
            fallbackRoot.insert(QStringLiteral("meta"), fallbackMeta);
            fallbackRoot.insert(QStringLiteral("semantic"), fallbackSemantic);
            if (!unparsedTailHexText.trimmed().isEmpty())
            {
                fallbackRoot.insert(QStringLiteral("rawFallback"), unparsedTailHexText);
            }
            rowData.detailJson = QString::fromUtf8(QJsonDocument(fallbackRoot).toJson(QJsonDocument::Compact));
            rowData.resourceTypeText = fallbackSemantic.value(QStringLiteral("resourceType")).toString();
            rowData.actionText = fallbackSemantic.value(QStringLiteral("action")).toString();
            rowData.targetText.clear();
            rowData.statusText.clear();
            rowData.detailSummary = QStringLiteral("%1 | PID=%2 TID=%3 | 原始数据=%4字节")
                .arg(etwToSingleLine(rowData.eventName).isEmpty() ? QStringLiteral("事件") : etwToSingleLine(rowData.eventName))
                .arg(rowData.headerPid)
                .arg(rowData.headerTid)
                .arg(static_cast<int>(eventRecord->UserDataLength));
            rowData.decodedReady = true;
        }

        if (rowData.detailSummary.trimmed().isEmpty())
        {
            rowData.detailSummary = QStringLiteral("%1 | PID=%2 TID=%3")
                .arg(etwToSingleLine(rowData.eventName).isEmpty() ? QStringLiteral("事件") : etwToSingleLine(rowData.eventName))
                .arg(rowData.headerPid)
                .arg(rowData.headerTid);
        }

        rowData.detailVisibleText = QStringLiteral("%1 %2 %3 %4 %5 %6 %7")
            .arg(rowData.timestampText)
            .arg(rowData.providerName)
            .arg(rowData.eventId)
            .arg(rowData.eventName)
            .arg(rowData.pidTidText)
            .arg(rowData.detailSummary)
            .arg(rowData.activityId);

        rowData.detailAllText = QStringLiteral("%1 %2 %3 %4 %5 %6 %7 %8 %9 %10")
            .arg(rowData.detailVisibleText)
            .arg(rowData.resourceTypeText)
            .arg(rowData.actionText)
            .arg(rowData.targetText)
            .arg(rowData.statusText)
            .arg(rowData.processNameText)
            .arg(rowData.filePathText)
            .arg(rowData.registryKeyPathText)
            .arg(rowData.scriptKeywordText)
            .arg(rowData.detailJson);
        rowData.detailAllText = etwSingleLineOrEmpty(rowData.detailAllText);

        rowData.decodedReady = true;
        return true;
    };

    std::shared_ptr<const EtwFilterStageCompiledSnapshot> preFilterSnapshot;
    {
        std::lock_guard<std::mutex> lock(etwPreFilterSnapshotMutex_);
        preFilterSnapshot = etwPreFilterCompiledSnapshot_;
    }

    bool preMatched = true;
    if (preFilterSnapshot != nullptr)
    {
        bool simpleRequiresDecodedPayload = false;
        preMatched = etwSimpleFilterMatchesHeaderFields(
            preFilterSnapshot->simpleFilter,
            rowData,
            &simpleRequiresDecodedPayload);
        if (preMatched && simpleRequiresDecodedPayload && !rowData.decodedReady)
        {
            ensureDecodedPayload();
        }
        if (preMatched)
        {
            preMatched = etwSimpleFilterMatches(preFilterSnapshot->simpleFilter, rowData);
        }

        if (preMatched && !preFilterSnapshot->detailedGroupList.empty())
        {
            preMatched = false;
            for (const EtwFilterRuleGroupCompiled& groupRule : preFilterSnapshot->detailedGroupList)
            {
                bool groupMatched = true;
                for (const EtwFilterRuleFieldCompiled& fieldRule : groupRule.fieldList)
                {
                    if (fieldRule.requiresDecodedPayload && !rowData.decodedReady)
                    {
                        ensureDecodedPayload();
                    }
                    if (!etwFilterFieldMatches(
                        fieldRule,
                        rowData,
                        groupRule.detailVisibleColumnsOnly,
                        groupRule.detailMatchAllFields))
                    {
                        groupMatched = false;
                        break;
                    }
                }
                if (groupRule.invertMatch)
                {
                    groupMatched = !groupMatched;
                }
                if (groupMatched)
                {
                    preMatched = true;
                    break;
                }
            }
        }
    }

    if (!preMatched)
    {
        return;
    }

    ensureDecodedPayload();

    // Full archival precedes UI snapshot queuing. Even if the UI cannot keep up with the event surge, disk records remain complete.
    if (!archiveEtwCapturedRow(&rowData))
    {
        etwCaptureStopFlag_.store(true);
        QPointer<MonitorDock> guardThis(this);
        QMetaObject::invokeMethod(qApp, [guardThis]() {
            if (guardThis == nullptr)
            {
                return;
            }
            if (guardThis->etwCaptureStatusLabel_ != nullptr)
            {
                guardThis->etwCaptureStatusLabel_->setText(
                    QStringLiteral("● 处理结束:%1").arg(ERROR_WRITE_FAULT));
                ks::ui::applyStatusRole(guardThis->etwCaptureStatusLabel_, ks::ui::StatusRole::kError);
            }
            guardThis->stopEtwCaptureInternal(false);
        }, Qt::QueuedConnection);
        return;
    }

    constexpr std::size_t kMaxEtwUiPendingRows = 2048;
    {
        std::unique_lock<std::mutex> lock(etwPendingMutex_, std::try_to_lock);
        if (!lock.owns_lock())
        {
            etwUiSkippedRows_.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        if (etwPendingRows_.size() >= kMaxEtwUiPendingRows)
        {
            etwPendingRows_.pop_front();
            etwUiSkippedRows_.fetch_add(1, std::memory_order_relaxed);
        }
        etwPendingRows_.push_back(std::move(rowData));
    }
}
