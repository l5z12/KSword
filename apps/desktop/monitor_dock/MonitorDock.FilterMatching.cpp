#include "MonitorDock.Support.h"

namespace ksword::ui::monitor_dock
{
    QString etwFilterLevelTextFromValue(const int levelValue)
    {
        switch (levelValue)
        {
        case 1: return QStringLiteral("Critical");
        case 2: return QStringLiteral("Error");
        case 3: return QStringLiteral("Warning");
        case 4: return QStringLiteral("Information");
        case 5: return QStringLiteral("Verbose");
        default: return QStringLiteral("Level_%1").arg(levelValue);
        }
    }

    bool etwRegexAnyMatch(
        const QString& valueText,
        const std::vector<QRegularExpression>& regexList)
    {
        if (regexList.empty())
        {
            return true;
        }
        for (const QRegularExpression& regex : regexList)
        {
            if (regex.isValid() && regex.match(valueText).hasMatch())
            {
                return true;
            }
        }
        return false;
    }

    bool etwNumericInRanges(
        const std::uint64_t value,
        const std::vector<MonitorDock::EtwFilterNumericRange>& rangeList)
    {
        if (rangeList.empty())
        {
            return true;
        }
        return std::any_of(
            rangeList.begin(),
            rangeList.end(),
            [value](const MonitorDock::EtwFilterNumericRange& rangeValue) {
                return value >= rangeValue.minValue && value <= rangeValue.maxValue;
            });
    }

    bool etwIpInRanges(
        const std::uint32_t value,
        const std::vector<MonitorDock::EtwFilterIpRange>& rangeList)
    {
        if (rangeList.empty())
        {
            return true;
        }
        return std::any_of(
            rangeList.begin(),
            rangeList.end(),
            [value](const MonitorDock::EtwFilterIpRange& rangeValue) {
                return value >= rangeValue.minValue && value <= rangeValue.maxValue;
            });
    }

    bool etwPortInRanges(
        const std::uint16_t value,
        const std::vector<MonitorDock::EtwFilterPortRange>& rangeList)
    {
        if (rangeList.empty())
        {
            return true;
        }
        return std::any_of(
            rangeList.begin(),
            rangeList.end(),
            [value](const MonitorDock::EtwFilterPortRange& rangeValue) {
                return value >= rangeValue.minValue && value <= rangeValue.maxValue;
            });
    }

    QString etwSingleLineOrEmpty(const QString& valueText)
    {
        QString normalizedText = valueText;
        normalizedText.replace(QChar(u'\r'), QChar(u' '));
        normalizedText.replace(QChar(u'\n'), QChar(u' '));
        return normalizedText.simplified();
    }

    QString etwFieldTextValue(
        const MonitorDock::EtwCapturedEventRow& rowData,
        const MonitorDock::EtwFilterFieldId fieldId,
        const bool detailVisibleOnly,
        const bool detailAllFields)
    {
        switch (fieldId)
        {
        case MonitorDock::EtwFilterFieldId::kProviderName: return rowData.providerName;
        case MonitorDock::EtwFilterFieldId::kProviderGuid: return rowData.providerGuid;
        case MonitorDock::EtwFilterFieldId::kProviderCategory: return rowData.providerCategory;
        case MonitorDock::EtwFilterFieldId::kEventName: return rowData.eventName;
        case MonitorDock::EtwFilterFieldId::kTask:
            return rowData.taskName.trimmed().isEmpty()
                ? QString::number(rowData.task)
                : QStringLiteral("%1 (%2)").arg(rowData.taskName, QString::number(rowData.task));
        case MonitorDock::EtwFilterFieldId::kOpcode:
            return rowData.opcodeName.trimmed().isEmpty()
                ? QString::number(rowData.opcode)
                : QStringLiteral("%1 (%2)").arg(rowData.opcodeName, QString::number(rowData.opcode));
        case MonitorDock::EtwFilterFieldId::kLevel:
            return rowData.levelText.trimmed().isEmpty()
                ? QString::number(rowData.level)
                : QStringLiteral("%1 (%2)").arg(rowData.levelText, QString::number(rowData.level));
        case MonitorDock::EtwFilterFieldId::kKeywordMask: return rowData.keywordMaskText;
        case MonitorDock::EtwFilterFieldId::kActivityId: return rowData.activityId;
        case MonitorDock::EtwFilterFieldId::kResourceType: return rowData.resourceTypeText;
        case MonitorDock::EtwFilterFieldId::kAction: return rowData.actionText;
        case MonitorDock::EtwFilterFieldId::kTarget: return rowData.targetText;
        case MonitorDock::EtwFilterFieldId::kStatus: return rowData.statusText;
        case MonitorDock::EtwFilterFieldId::kDetailKeyword:
            if (detailVisibleOnly)
            {
                return rowData.detailVisibleText;
            }
            return detailAllFields ? rowData.detailAllText : rowData.detailSummary;
        case MonitorDock::EtwFilterFieldId::kProcessName: return rowData.processNameText;
        case MonitorDock::EtwFilterFieldId::kImagePath: return rowData.imagePathText;
        case MonitorDock::EtwFilterFieldId::kCommandLine: return rowData.commandLineText;
        case MonitorDock::EtwFilterFieldId::kFilePath: return rowData.filePathText;
        case MonitorDock::EtwFilterFieldId::kFileOldPath: return rowData.fileOldPathText;
        case MonitorDock::EtwFilterFieldId::kFileNewPath: return rowData.fileNewPathText;
        case MonitorDock::EtwFilterFieldId::kFileOperation: return rowData.fileOperationText;
        case MonitorDock::EtwFilterFieldId::kFileStatusCode: return rowData.fileStatusCodeText;
        case MonitorDock::EtwFilterFieldId::kFileAccessMask: return rowData.fileAccessMaskText;
        case MonitorDock::EtwFilterFieldId::kRegistryKeyPath: return rowData.registryKeyPathText;
        case MonitorDock::EtwFilterFieldId::kRegistryValueName: return rowData.registryValueNameText;
        case MonitorDock::EtwFilterFieldId::kRegistryHive: return rowData.registryHiveText;
        case MonitorDock::EtwFilterFieldId::kRegistryOperation: return rowData.registryOperationText;
        case MonitorDock::EtwFilterFieldId::kRegistryStatus: return rowData.registryStatusText;
        case MonitorDock::EtwFilterFieldId::kSourceIp: return rowData.sourceIpText;
        case MonitorDock::EtwFilterFieldId::kDestinationIp: return rowData.destinationIpText;
        case MonitorDock::EtwFilterFieldId::kProtocol: return rowData.protocolText;
        case MonitorDock::EtwFilterFieldId::kDirection: return rowData.directionText;
        case MonitorDock::EtwFilterFieldId::kDomain: return rowData.domainText;
        case MonitorDock::EtwFilterFieldId::kHost: return rowData.hostText;
        case MonitorDock::EtwFilterFieldId::kAuditResult: return rowData.auditResultText;
        case MonitorDock::EtwFilterFieldId::kUserText: return rowData.userText;
        case MonitorDock::EtwFilterFieldId::kSidText: return rowData.sidText;
        case MonitorDock::EtwFilterFieldId::kSecurityLevel: return rowData.securityLevelText;
        case MonitorDock::EtwFilterFieldId::kScriptHostProcess: return rowData.scriptHostProcessText;
        case MonitorDock::EtwFilterFieldId::kScriptKeyword: return rowData.scriptKeywordText;
        case MonitorDock::EtwFilterFieldId::kScriptTaskName: return rowData.scriptTaskNameText;
        case MonitorDock::EtwFilterFieldId::kWmiClassName: return rowData.wmiClassNameText;
        case MonitorDock::EtwFilterFieldId::kWmiNamespace: return rowData.wmiNamespaceText;
        default:
            break;
        }
        return QString();
    }

    bool etwFieldNumericValue(
        const MonitorDock::EtwCapturedEventRow& rowData,
        const MonitorDock::EtwFilterFieldId fieldId,
        std::uint64_t* valueOut)
    {
        if (valueOut == nullptr)
        {
            return false;
        }

        switch (fieldId)
        {
        case MonitorDock::EtwFilterFieldId::kEventId:
            *valueOut = static_cast<std::uint64_t>(rowData.eventId);
            return true;
        case MonitorDock::EtwFilterFieldId::kTask:
            *valueOut = static_cast<std::uint64_t>(rowData.task);
            return true;
        case MonitorDock::EtwFilterFieldId::kOpcode:
            *valueOut = static_cast<std::uint64_t>(rowData.opcode);
            return true;
        case MonitorDock::EtwFilterFieldId::kLevel:
            *valueOut = static_cast<std::uint64_t>(rowData.level);
            return true;
        case MonitorDock::EtwFilterFieldId::kKeywordMask:
            *valueOut = rowData.keywordMaskValue;
            return true;
        case MonitorDock::EtwFilterFieldId::kHeaderPid:
            *valueOut = static_cast<std::uint64_t>(rowData.headerPid);
            return true;
        case MonitorDock::EtwFilterFieldId::kHeaderTid:
            *valueOut = static_cast<std::uint64_t>(rowData.headerTid);
            return true;
        case MonitorDock::EtwFilterFieldId::kTimestampRange:
            *valueOut = rowData.timestampValue;
            return true;
        case MonitorDock::EtwFilterFieldId::kTargetPid:
            if (!rowData.targetPidValid)
            {
                return false;
            }
            *valueOut = static_cast<std::uint64_t>(rowData.targetPid);
            return true;
        case MonitorDock::EtwFilterFieldId::kParentPid:
            if (!rowData.parentPidValid)
            {
                return false;
            }
            *valueOut = static_cast<std::uint64_t>(rowData.parentPid);
            return true;
        case MonitorDock::EtwFilterFieldId::kTargetTid:
            if (!rowData.targetTidValid)
            {
                return false;
            }
            *valueOut = static_cast<std::uint64_t>(rowData.targetTid);
            return true;
        case MonitorDock::EtwFilterFieldId::kSecurityPid:
            if (!rowData.securityPidValid)
            {
                return false;
            }
            *valueOut = static_cast<std::uint64_t>(rowData.securityPid);
            return true;
        case MonitorDock::EtwFilterFieldId::kSecurityTid:
            if (!rowData.securityTidValid)
            {
                return false;
            }
            *valueOut = static_cast<std::uint64_t>(rowData.securityTid);
            return true;
        default:
            break;
        }

        return false;
    }

    bool etwFieldIpValue(
        const MonitorDock::EtwCapturedEventRow& rowData,
        const MonitorDock::EtwFilterFieldId fieldId,
        std::uint32_t* valueOut)
    {
        if (valueOut == nullptr)
        {
            return false;
        }
        if (fieldId == MonitorDock::EtwFilterFieldId::kSourceIp && rowData.sourceIpValid)
        {
            *valueOut = rowData.sourceIpValue;
            return true;
        }
        if (fieldId == MonitorDock::EtwFilterFieldId::kDestinationIp && rowData.destinationIpValid)
        {
            *valueOut = rowData.destinationIpValue;
            return true;
        }
        return false;
    }

    bool etwFieldPortValue(
        const MonitorDock::EtwCapturedEventRow& rowData,
        const MonitorDock::EtwFilterFieldId fieldId,
        std::uint16_t* valueOut)
    {
        if (valueOut == nullptr)
        {
            return false;
        }
        if (fieldId == MonitorDock::EtwFilterFieldId::kSourcePort && rowData.sourcePortValid)
        {
            *valueOut = rowData.sourcePort;
            return true;
        }
        if (fieldId == MonitorDock::EtwFilterFieldId::kDestinationPort && rowData.destinationPortValid)
        {
            *valueOut = rowData.destinationPort;
            return true;
        }
        return false;
    }

    bool etwFilterFieldMatches(
        const MonitorDock::EtwFilterRuleFieldCompiled& fieldRule,
        const MonitorDock::EtwCapturedEventRow& rowData,
        const bool detailVisibleOnly,
        const bool detailAllFields)
    {
        if (fieldRule.fieldType == MonitorDock::EtwFilterFieldType::kIp)
        {
            std::uint32_t value = 0;
            if (!etwFieldIpValue(rowData, fieldRule.fieldId, &value))
            {
                return false;
            }
            return etwIpInRanges(value, fieldRule.ipRangeList);
        }

        if (fieldRule.fieldType == MonitorDock::EtwFilterFieldType::kPort)
        {
            std::uint16_t value = 0;
            if (!etwFieldPortValue(rowData, fieldRule.fieldId, &value))
            {
                return false;
            }
            return etwPortInRanges(value, fieldRule.portRangeList);
        }

        if (fieldRule.fieldType == MonitorDock::EtwFilterFieldType::kNumber
            || fieldRule.fieldType == MonitorDock::EtwFilterFieldType::kTimeRange)
        {
            std::uint64_t numericValue = 0;
            if (!etwFieldNumericValue(rowData, fieldRule.fieldId, &numericValue))
            {
                return false;
            }
            return etwNumericInRanges(numericValue, fieldRule.numericRangeList);
        }

        if (fieldRule.fieldType == MonitorDock::EtwFilterFieldType::kNumberOrText)
        {
            bool numericMatched = false;
            bool numericChecked = false;
            if (!fieldRule.numericRangeList.empty())
            {
                numericChecked = true;
                std::uint64_t numericValue = 0;
                if (etwFieldNumericValue(rowData, fieldRule.fieldId, &numericValue))
                {
                    numericMatched = etwNumericInRanges(numericValue, fieldRule.numericRangeList);
                }
            }

            bool textMatched = false;
            bool textChecked = false;
            if (!fieldRule.regexRuleList.empty())
            {
                textChecked = true;
                const QString kTextValue = etwFieldTextValue(
                    rowData,
                    fieldRule.fieldId,
                    detailVisibleOnly,
                    detailAllFields);
                textMatched = etwRegexAnyMatch(kTextValue, fieldRule.regexRuleList);
            }

            if (numericChecked && textChecked)
            {
                return numericMatched || textMatched;
            }
            if (numericChecked)
            {
                return numericMatched;
            }
            if (textChecked)
            {
                return textMatched;
            }
            return true;
        }

        const QString kTextValue = etwFieldTextValue(
            rowData,
            fieldRule.fieldId,
            detailVisibleOnly,
            detailAllFields);
        return etwRegexAnyMatch(kTextValue, fieldRule.regexRuleList);
    }

    bool etwFilterGroupMatches(
        const MonitorDock::EtwFilterRuleGroupCompiled& groupRule,
        const MonitorDock::EtwCapturedEventRow& rowData)
    {
        bool matched = true;
        for (const MonitorDock::EtwFilterRuleFieldCompiled& fieldRule : groupRule.fieldList)
        {
            if (!etwFilterFieldMatches(
                fieldRule,
                rowData,
                groupRule.detailVisibleColumnsOnly,
                groupRule.detailMatchAllFields))
            {
                matched = false;
                break;
            }
        }

        if (groupRule.invertMatch)
        {
            matched = !matched;
        }
        return matched;
    }

    QStringList splitEtwSimpleFilterTokens(const QString& inputText)
    {
        static const QRegularExpression kSeparatorRegex(QStringLiteral("[,;]+"));
        QStringList result;
        for (const QString& tokenText : inputText.split(kSeparatorRegex, Qt::SkipEmptyParts))
        {
            const QString kTrimmed = tokenText.trimmed();
            if (!kTrimmed.isEmpty())
            {
                result.push_back(kTrimmed);
            }
        }
        return result;
    }

    bool etwTextContainsAnyToken(const QString& valueText, const QStringList& tokenList)
    {
        if (tokenList.isEmpty())
        {
            return true;
        }
        return std::any_of(
            tokenList.begin(),
            tokenList.end(),
            [&valueText](const QString& tokenText) {
                return valueText.contains(tokenText, Qt::CaseInsensitive);
            });
    }

    bool etwAnyTextValueContainsAnyToken(
        const std::initializer_list<const QString*> valueList,
        const QStringList& tokenList)
    {
        if (tokenList.isEmpty())
        {
            return true;
        }
        for (const QString& tokenText : tokenList)
        {
            for (const QString* valuePointer : valueList)
            {
                if (valuePointer != nullptr
                    && valuePointer->contains(tokenText, Qt::CaseInsensitive))
                {
                    return true;
                }
            }
        }
        return false;
    }

    bool etwSimpleProviderMatches(
        const MonitorDock::EtwSimpleFilterCompiled& simpleFilter,
        const MonitorDock::EtwCapturedEventRow& rowData)
    {
        if (simpleFilter.providerPresetNameList.isEmpty()
            && simpleFilter.providerCustomTokenList.isEmpty())
        {
            return true;
        }

        for (const QString& presetName : simpleFilter.providerPresetNameList)
        {
            if (rowData.providerName.compare(presetName, Qt::CaseInsensitive) == 0)
            {
                return true;
            }
        }
        if (simpleFilter.providerCustomTokenList.isEmpty())
        {
            return false;
        }
        return etwAnyTextValueContainsAnyToken(
            { &rowData.providerName, &rowData.providerGuid },
            simpleFilter.providerCustomTokenList);
    }

    bool etwSimplePidMatches(
        const MonitorDock::EtwSimpleFilterCompiled& simpleFilter,
        const MonitorDock::EtwCapturedEventRow& rowData)
    {
        if (simpleFilter.pidRangeList.empty())
        {
            return true;
        }
        if (etwNumericInRanges(rowData.headerPid, simpleFilter.pidRangeList))
        {
            return true;
        }
        return (rowData.targetPidValid && etwNumericInRanges(rowData.targetPid, simpleFilter.pidRangeList))
            || (rowData.parentPidValid && etwNumericInRanges(rowData.parentPid, simpleFilter.pidRangeList))
            || (rowData.securityPidValid && etwNumericInRanges(rowData.securityPid, simpleFilter.pidRangeList));
    }

    bool etwSimpleFilterMatchesHeaderFields(
        const MonitorDock::EtwSimpleFilterCompiled& simpleFilter,
        const MonitorDock::EtwCapturedEventRow& rowData,
        bool* decodedPayloadRequiredOut)
    {
        if (decodedPayloadRequiredOut != nullptr)
        {
            *decodedPayloadRequiredOut = false;
        }
        if (!simpleFilter.hasAnyCondition())
        {
            return true;
        }
        if (!etwSimpleProviderMatches(simpleFilter, rowData))
        {
            return false;
        }
        if (!simpleFilter.eventIdRangeList.empty()
            && !etwNumericInRanges(static_cast<std::uint64_t>(rowData.eventId), simpleFilter.eventIdRangeList))
        {
            return false;
        }
        if (!etwTextContainsAnyToken(rowData.eventName, simpleFilter.eventNameTokenList))
        {
            return false;
        }

        bool decodedPayloadRequired = false;
        if (!simpleFilter.pidRangeList.empty()
            && !etwNumericInRanges(rowData.headerPid, simpleFilter.pidRangeList))
        {
            decodedPayloadRequired = true;
        }
        decodedPayloadRequired = decodedPayloadRequired
            || !simpleFilter.networkAddressRangeList.empty()
            || !simpleFilter.networkPortRangeList.empty()
            || !simpleFilter.actionPresetList.empty()
            || !simpleFilter.actionCustomTokenList.empty()
            || !simpleFilter.processNameTokenList.empty()
            || !simpleFilter.filePathTokenList.empty()
            || !simpleFilter.registryPathTokenList.empty()
            || !simpleFilter.statusTokenList.empty();
        if (decodedPayloadRequiredOut != nullptr)
        {
            *decodedPayloadRequiredOut = decodedPayloadRequired;
        }
        return true;
    }

    bool etwSimpleFilterMatches(
        const MonitorDock::EtwSimpleFilterCompiled& simpleFilter,
        const MonitorDock::EtwCapturedEventRow& rowData)
    {
        if (!simpleFilter.hasAnyCondition())
        {
            return true;
        }
        if (!etwSimpleProviderMatches(simpleFilter, rowData)
            || (!simpleFilter.eventIdRangeList.empty()
                && !etwNumericInRanges(
                    static_cast<std::uint64_t>(rowData.eventId),
                    simpleFilter.eventIdRangeList))
            || !etwTextContainsAnyToken(rowData.eventName, simpleFilter.eventNameTokenList)
            || !etwSimplePidMatches(simpleFilter, rowData)
            || !etwTextContainsAnyToken(rowData.processNameText, simpleFilter.processNameTokenList)
            || !etwAnyTextValueContainsAnyToken(
                { &rowData.filePathText, &rowData.fileOldPathText, &rowData.fileNewPathText },
                simpleFilter.filePathTokenList)
            || !etwAnyTextValueContainsAnyToken(
                { &rowData.registryKeyPathText, &rowData.registryValueNameText },
                simpleFilter.registryPathTokenList)
            || !etwAnyTextValueContainsAnyToken(
                { &rowData.statusText, &rowData.fileStatusCodeText, &rowData.registryStatusText,
                  &rowData.auditResultText },
                simpleFilter.statusTokenList))
        {
            return false;
        }

        if (!simpleFilter.networkAddressRangeList.empty())
        {
            const bool kAddressMatched = (rowData.sourceIpValid
                    && etwIpInRanges(rowData.sourceIpValue, simpleFilter.networkAddressRangeList))
                || (rowData.destinationIpValid
                    && etwIpInRanges(rowData.destinationIpValue, simpleFilter.networkAddressRangeList));
            if (!kAddressMatched)
            {
                return false;
            }
        }
        if (!simpleFilter.networkPortRangeList.empty())
        {
            const bool kPortMatched = (rowData.sourcePortValid
                    && etwPortInRanges(rowData.sourcePort, simpleFilter.networkPortRangeList))
                || (rowData.destinationPortValid
                    && etwPortInRanges(rowData.destinationPort, simpleFilter.networkPortRangeList));
            if (!kPortMatched)
            {
                return false;
            }
        }

        if (!simpleFilter.actionPresetList.isEmpty()
            || !simpleFilter.actionCustomTokenList.isEmpty())
        {
            bool actionMatched = false;
            for (const QString& actionText : simpleFilter.actionPresetList)
            {
                if (rowData.actionText.compare(actionText, Qt::CaseInsensitive) == 0)
                {
                    actionMatched = true;
                    break;
                }
            }
            if (!actionMatched && !simpleFilter.actionCustomTokenList.isEmpty())
            {
                actionMatched = etwTextContainsAnyToken(
                    rowData.actionText,
                    simpleFilter.actionCustomTokenList);
            }
            if (!actionMatched)
            {
                return false;
            }
        }
        return true;
    }

    bool etwDetailedFilterMatches(
        const std::vector<MonitorDock::EtwFilterRuleGroupCompiled>& groupList,
        const MonitorDock::EtwCapturedEventRow& rowData)
    {
        if (groupList.empty())
        {
            return true;
        }
        return std::any_of(
            groupList.begin(),
            groupList.end(),
            [&rowData](const MonitorDock::EtwFilterRuleGroupCompiled& groupRule) {
                return etwFilterGroupMatches(groupRule, rowData);
            });
    }

    bool etwFilterStageMatches(
        const MonitorDock::EtwSimpleFilterCompiled& simpleFilter,
        const std::vector<MonitorDock::EtwFilterRuleGroupCompiled>& detailedGroupList,
        const MonitorDock::EtwCapturedEventRow& rowData)
    {
        return etwSimpleFilterMatches(simpleFilter, rowData)
            && etwDetailedFilterMatches(detailedGroupList, rowData);
    }
}
