#include "MonitorDock.Support.h"

using namespace ksword::ui::monitor_dock;

bool MonitorDock::tryCompileEtwSimpleFilterModel(
    const EtwFilterStage stage,
    const EtwSimpleFilterModel& filterModel,
    EtwSimpleFilterCompiled& compiledFilterOut,
    QString& errorTextOut) const
{
    compiledFilterOut = EtwSimpleFilterCompiled{};
    errorTextOut.clear();
    compiledFilterOut.enabled = filterModel.enabled;

    const auto kCompileNumericRanges = [stage, &errorTextOut](
        const QString& inputText,
        const QString& fieldLabel,
        std::vector<EtwFilterNumericRange>& rangesOut,
        const std::uint64_t maximumValue) {
        for (const QString& tokenText : splitEtwSimpleFilterTokens(inputText))
        {
            EtwFilterNumericRange rangeValue;
            if (!tryParseUInt64RangeToken(tokenText, rangeValue)
                || rangeValue.maxValue > maximumValue)
            {
                errorTextOut = QStringLiteral("%1简易筛选字段[%2]无效值：%3")
                    .arg(etwFilterStageText(stage), fieldLabel, tokenText);
                return false;
            }
            rangesOut.push_back(rangeValue);
        }
        return true;
    };

    if (!kCompileNumericRanges(
            filterModel.pidText,
            QStringLiteral("PID"),
            compiledFilterOut.pidRangeList,
            std::numeric_limits<std::uint32_t>::max())
        || !kCompileNumericRanges(
            filterModel.eventIdText,
            QStringLiteral("事件ID"),
            compiledFilterOut.eventIdRangeList,
            std::numeric_limits<std::uint16_t>::max()))
    {
        return false;
    }

    for (const QString& tokenText : splitEtwSimpleFilterTokens(filterModel.networkAddressText))
    {
        EtwFilterIpRange rangeValue;
        if (!tryParseIpv4RangeToken(tokenText, rangeValue))
        {
            errorTextOut = QStringLiteral("%1简易筛选字段[网络地址]无效值：%2")
                .arg(etwFilterStageText(stage), tokenText);
            return false;
        }
        compiledFilterOut.networkAddressRangeList.push_back(rangeValue);
    }
    for (const QString& tokenText : splitEtwSimpleFilterTokens(filterModel.networkPortText))
    {
        EtwFilterPortRange rangeValue;
        if (!tryParsePortRangeToken(tokenText, rangeValue))
        {
            errorTextOut = QStringLiteral("%1简易筛选字段[网络端口]无效值：%2")
                .arg(etwFilterStageText(stage), tokenText);
            return false;
        }
        compiledFilterOut.networkPortRangeList.push_back(rangeValue);
    }

    compiledFilterOut.providerPresetNameList = filterModel.providerPresetNameList;
    compiledFilterOut.actionPresetList = filterModel.actionPresetList;
    compiledFilterOut.providerCustomTokenList =
        splitEtwSimpleFilterTokens(filterModel.customProviderText);
    compiledFilterOut.actionCustomTokenList =
        splitEtwSimpleFilterTokens(filterModel.customActionText);
    compiledFilterOut.processNameTokenList =
        splitEtwSimpleFilterTokens(filterModel.processNameText);
    compiledFilterOut.filePathTokenList =
        splitEtwSimpleFilterTokens(filterModel.filePathText);
    compiledFilterOut.eventNameTokenList =
        splitEtwSimpleFilterTokens(filterModel.eventNameText);
    compiledFilterOut.registryPathTokenList =
        splitEtwSimpleFilterTokens(filterModel.registryPathText);
    compiledFilterOut.statusTokenList =
        splitEtwSimpleFilterTokens(filterModel.statusText);
    return true;
}

bool MonitorDock::tryCompileEtwFilterGroupModels(
    const EtwFilterStage stage,
    const std::vector<EtwFilterRuleGroupModel>& groupModelList,
    std::vector<EtwFilterRuleGroupCompiled>& compiledGroupsOut,
    QString& errorTextOut) const
{
    compiledGroupsOut.clear();
    errorTextOut.clear();

    int displayIndex = 1;
    for (const EtwFilterRuleGroupModel& groupModel : groupModelList)
    {
        EtwFilterRuleGroupCompiled compiledGroup;
        compiledGroup.groupId = groupModel.groupId;
        compiledGroup.displayIndex = displayIndex;
        compiledGroup.enabled = groupModel.enabled;
        compiledGroup.stringMode = groupModel.stringMode;
        compiledGroup.caseSensitive = groupModel.caseSensitive;
        compiledGroup.invertMatch = groupModel.invertMatch;
        compiledGroup.detailVisibleColumnsOnly = groupModel.detailVisibleColumnsOnly;
        compiledGroup.detailMatchAllFields = groupModel.detailMatchAllFields;

        std::vector<EtwFilterRuleFieldModel> fieldModelList = groupModel.fieldList;
        const auto kProviderCategoryField = std::find_if(
            fieldModelList.begin(),
            fieldModelList.end(),
            [](const EtwFilterRuleFieldModel& fieldModel) {
                return fieldModel.fieldId == EtwFilterFieldId::kProviderCategory;
            });
        if (kProviderCategoryField == fieldModelList.end()
            && !groupModel.providerCategoryList.isEmpty())
        {
            const EtwFilterFieldDescriptor* descriptor =
                findEtwFilterFieldDescriptorById(EtwFilterFieldId::kProviderCategory);
            if (descriptor != nullptr)
            {
                EtwFilterRuleFieldModel fieldModel;
                fieldModel.fieldId = descriptor->fieldId;
                fieldModel.fieldKey = QString::fromLatin1(descriptor->key);
                fieldModel.fieldLabel = QString::fromUtf8(descriptor->label);
                fieldModelList.push_back(std::move(fieldModel));
            }
        }

        for (const EtwFilterRuleFieldModel& fieldModel : fieldModelList)
        {
            const EtwFilterFieldDescriptor* descriptor =
                findEtwFilterFieldDescriptorById(fieldModel.fieldId);
            if (descriptor == nullptr)
            {
                continue;
            }

            QString inputText = fieldModel.inputText.trimmed();
            if (fieldModel.fieldId == EtwFilterFieldId::kProviderCategory
                && !groupModel.providerCategoryList.isEmpty())
            {
                inputText = inputText.isEmpty()
                    ? groupModel.providerCategoryList.join(QStringLiteral(","))
                    : inputText + QStringLiteral(",")
                        + groupModel.providerCategoryList.join(QStringLiteral(","));
            }

            if (inputText.isEmpty())
            {
                continue;
            }

            const QStringList kTokenList = splitEtwFilterTokens(inputText);
            if (kTokenList.isEmpty())
            {
                continue;
            }

            EtwFilterRuleFieldCompiled compiledField;
            compiledField.fieldId = fieldModel.fieldId;
            compiledField.fieldKey = fieldModel.fieldKey;
            compiledField.fieldLabel = fieldModel.fieldLabel;
            compiledField.fieldType = descriptor->fieldType;
            compiledField.requiresDecodedPayload = descriptor->requiresDecodedPayload;

            const QRegularExpression::PatternOptions kRegexOptions = compiledGroup.caseSensitive
                ? QRegularExpression::NoPatternOption
                : QRegularExpression::CaseInsensitiveOption;

            for (const QString& tokenTextRaw : kTokenList)
            {
                const QString kTokenText = tokenTextRaw.trimmed();
                if (kTokenText.isEmpty())
                {
                    continue;
                }

                if (descriptor->fieldType == EtwFilterFieldType::kText)
                {
                    const QString kRegexPattern = etwFilterRegexPatternFromToken(kTokenText, compiledGroup.stringMode);
                    const QRegularExpression kRegex(kRegexPattern, kRegexOptions);
                    if (!kRegex.isValid())
                    {
                        errorTextOut = QStringLiteral("%1 规则组%2 字段[%3] 无效值：%4")
                            .arg(etwFilterStageText(stage))
                            .arg(displayIndex)
                            .arg(fieldModel.fieldLabel)
                            .arg(kTokenText);
                        return false;
                    }
                    compiledField.regexRuleList.push_back(kRegex);
                    continue;
                }

                if (descriptor->fieldType == EtwFilterFieldType::kNumber
                    || descriptor->fieldType == EtwFilterFieldType::kTimeRange)
                {
                    EtwFilterNumericRange range;
                    if (!tryParseUInt64RangeToken(kTokenText, range))
                    {
                        errorTextOut = QStringLiteral("%1 规则组%2 字段[%3] 无效值：%4")
                            .arg(etwFilterStageText(stage))
                            .arg(displayIndex)
                            .arg(fieldModel.fieldLabel)
                            .arg(kTokenText);
                        return false;
                    }
                    compiledField.numericRangeList.push_back(range);
                    continue;
                }

                if (descriptor->fieldType == EtwFilterFieldType::kNumberOrText)
                {
                    EtwFilterNumericRange range;
                    if (tryParseUInt64RangeToken(kTokenText, range))
                    {
                        compiledField.numericRangeList.push_back(range);
                        continue;
                    }

                    const QString kRegexPattern = etwFilterRegexPatternFromToken(kTokenText, compiledGroup.stringMode);
                    const QRegularExpression kRegex(kRegexPattern, kRegexOptions);
                    if (!kRegex.isValid())
                    {
                        errorTextOut = QStringLiteral("%1 规则组%2 字段[%3] 无效值：%4")
                            .arg(etwFilterStageText(stage))
                            .arg(displayIndex)
                            .arg(fieldModel.fieldLabel)
                            .arg(kTokenText);
                        return false;
                    }
                    compiledField.regexRuleList.push_back(kRegex);
                    continue;
                }

                if (descriptor->fieldType == EtwFilterFieldType::kIp)
                {
                    EtwFilterIpRange range;
                    if (!tryParseIpv4RangeToken(kTokenText, range))
                    {
                        errorTextOut = QStringLiteral("%1 规则组%2 字段[%3] 无效值：%4")
                            .arg(etwFilterStageText(stage))
                            .arg(displayIndex)
                            .arg(fieldModel.fieldLabel)
                            .arg(kTokenText);
                        return false;
                    }
                    compiledField.ipRangeList.push_back(range);
                    continue;
                }

                if (descriptor->fieldType == EtwFilterFieldType::kPort)
                {
                    EtwFilterPortRange range;
                    if (!tryParsePortRangeToken(kTokenText, range))
                    {
                        errorTextOut = QStringLiteral("%1 规则组%2 字段[%3] 无效值：%4")
                            .arg(etwFilterStageText(stage))
                            .arg(displayIndex)
                            .arg(fieldModel.fieldLabel)
                            .arg(kTokenText);
                        return false;
                    }
                    compiledField.portRangeList.push_back(range);
                    continue;
                }
            }

            if (compiledField.regexRuleList.empty()
                && compiledField.numericRangeList.empty()
                && compiledField.ipRangeList.empty()
                && compiledField.portRangeList.empty())
            {
                continue;
            }

            if (compiledField.requiresDecodedPayload)
            {
                compiledGroup.requiresDecodedPayload = true;
            }
            compiledGroup.fieldList.push_back(std::move(compiledField));
        }

        if (compiledGroup.enabled && compiledGroup.hasAnyCondition())
        {
            compiledGroupsOut.push_back(std::move(compiledGroup));
        }

        ++displayIndex;
    }

    return true;
}

bool MonitorDock::tryCompileEtwFilterConfigModel(
    const EtwFilterConfigModel& filterModel,
    EtwFilterConfigCompiledModel& compiledModelOut,
    QString& errorTextOut) const
{
    compiledModelOut = EtwFilterConfigCompiledModel{};
    errorTextOut.clear();
    return tryCompileEtwSimpleFilterModel(
            EtwFilterStage::kPre,
            filterModel.preSimpleFilter,
            compiledModelOut.preSimpleFilter,
            errorTextOut)
        && tryCompileEtwFilterGroupModels(
            EtwFilterStage::kPre,
            filterModel.preGroupList,
            compiledModelOut.preGroupList,
            errorTextOut)
        && tryCompileEtwSimpleFilterModel(
            EtwFilterStage::kPost,
            filterModel.postSimpleFilter,
            compiledModelOut.postSimpleFilter,
            errorTextOut)
        && tryCompileEtwFilterGroupModels(
            EtwFilterStage::kPost,
            filterModel.postGroupList,
            compiledModelOut.postGroupList,
            errorTextOut);
}

bool MonitorDock::tryCompileEtwSimpleFilter(
    const EtwFilterStage stage,
    EtwSimpleFilterCompiled& compiledFilterOut,
    QString& errorTextOut) const
{
    const EtwSimpleFilterModel kFilterModel = captureEtwSimpleFilterModel(stage);
    return tryCompileEtwSimpleFilterModel(
        stage,
        kFilterModel,
        compiledFilterOut,
        errorTextOut);
}

bool MonitorDock::tryCompileEtwFilterGroups(
    const EtwFilterStage stage,
    std::vector<EtwFilterRuleGroupCompiled>& compiledGroupsOut,
    QString& errorTextOut) const
{
    const std::vector<EtwFilterRuleGroupModel> kGroupModelList =
        captureEtwFilterGroupModels(stage);
    return tryCompileEtwFilterGroupModels(
        stage,
        kGroupModelList,
        compiledGroupsOut,
        errorTextOut);
}
