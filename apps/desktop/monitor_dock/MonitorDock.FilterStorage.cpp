#include "MonitorDock.Support.h"

using namespace ksword::ui::monitor_dock;

QString MonitorDock::etwFilterConfigPath() const
{
    return QDir(QCoreApplication::applicationDirPath())
        .absoluteFilePath(QString::fromLatin1(kEtwFilterConfigRelativePath));
}

bool MonitorDock::tryParseEtwFilterConfigModel(
    const QByteArray& jsonData,
    EtwFilterConfigModel& filterModelOut) const
{
    ksword::monitor::EtwFilterChoices choices;
    for (const auto kStage : { EtwFilterStage::kPre, EtwFilterStage::kPost })
    {
        auto& known = kStage == EtwFilterStage::kPre ? choices.pre : choices.post;
        const auto& ui = etwSimpleFilterUi(kStage);
        for (const auto& check : ui.providerCheckList) known.providers.push_back(check.valueText);
        for (const auto& check : ui.actionCheckList) known.actions.push_back(check.valueText);
    }
    return ksword::monitor::parseEtwFilterConfigModel(jsonData, choices, filterModelOut);
}

QJsonObject MonitorDock::serializeEtwFilterConfigModel(
    const EtwFilterConfigModel& filterModel) const
{
    return ksword::monitor::serializeEtwFilterConfigModel(filterModel);
}

bool MonitorDock::saveEtwFilterConfigModelToPath(
    const EtwFilterConfigModel& filterModel,
    const QString& filePath,
    const bool showErrorDialog) const
{
    const QString kNormalizedPath = QFileInfo(filePath).absoluteFilePath();
    if (kNormalizedPath.trimmed().isEmpty())
    {
        if (showErrorDialog)
        {
            QMessageBox::warning(nullptr, QStringLiteral("ETW筛选"), QStringLiteral("配置保存路径无效。"));
        }
        return false;
    }

    const QFileInfo kFileInfo(kNormalizedPath);
    QDir outputDirectory(kFileInfo.absolutePath());
    if (!outputDirectory.exists() && !outputDirectory.mkpath(QStringLiteral(".")))
    {
        if (showErrorDialog)
        {
            QMessageBox::warning(
                nullptr,
                QStringLiteral("ETW筛选"),
                QStringLiteral("创建配置目录失败：%1").arg(outputDirectory.absolutePath()));
        }
        return false;
    }

    const QByteArray kSerializedData =
        QJsonDocument(serializeEtwFilterConfigModel(filterModel))
            .toJson(QJsonDocument::Indented);
    QSaveFile outputFile(kNormalizedPath);
    if (!outputFile.open(QIODevice::WriteOnly | QIODevice::Text)
        || outputFile.write(kSerializedData) != kSerializedData.size()
        || !outputFile.commit())
    {
        if (showErrorDialog)
        {
            QMessageBox::warning(
                nullptr,
                QStringLiteral("ETW筛选"),
                QStringLiteral("打开配置文件失败：%1").arg(kNormalizedPath));
        }
        return false;
    }
    return true;
}

void MonitorDock::commitEtwFilterConfigModel(
    const EtwFilterConfigModel& filterModel,
    EtwFilterConfigCompiledModel compiledModel)
{
    EtwFilterStageCompiledSnapshot preStageSnapshot;
    preStageSnapshot.simpleFilter = compiledModel.preSimpleFilter;
    preStageSnapshot.detailedGroupList = compiledModel.preGroupList;
    const std::shared_ptr<const EtwFilterStageCompiledSnapshot> kPreSnapshotPointer =
        std::make_shared<const EtwFilterStageCompiledSnapshot>(std::move(preStageSnapshot));

    const auto kApplySimpleModel = [this](
        const EtwFilterStage stage,
        const EtwSimpleFilterModel& simpleModel) {
        EtwSimpleFilterUiState& uiState = etwSimpleFilterUi(stage);
        if (uiState.applyDebounceTimer != nullptr)
        {
            uiState.applyDebounceTimer->stop();
        }
        if (uiState.enabledCheck != nullptr)
        {
            const QSignalBlocker kBlocker(uiState.enabledCheck);
            uiState.enabledCheck->setChecked(simpleModel.enabled);
        }
        const auto kSetEditText = [](QLineEdit* edit, const QString& text) {
            if (edit == nullptr)
            {
                return;
            }
            const QSignalBlocker kBlocker(edit);
            edit->setText(text);
        };
        kSetEditText(uiState.pidEdit, simpleModel.pidText);
        kSetEditText(uiState.processNameEdit, simpleModel.processNameText);
        kSetEditText(uiState.filePathEdit, simpleModel.filePathText);
        kSetEditText(uiState.eventIdEdit, simpleModel.eventIdText);
        kSetEditText(uiState.eventNameEdit, simpleModel.eventNameText);
        kSetEditText(uiState.registryPathEdit, simpleModel.registryPathText);
        kSetEditText(uiState.networkAddressEdit, simpleModel.networkAddressText);
        kSetEditText(uiState.networkPortEdit, simpleModel.networkPortText);
        kSetEditText(uiState.statusEdit, simpleModel.statusText);
        kSetEditText(uiState.customProviderEdit, simpleModel.customProviderText);
        kSetEditText(uiState.customActionEdit, simpleModel.customActionText);

        for (EtwSimpleFilterCheckUiState& checkState : uiState.providerCheckList)
        {
            if (checkState.checkBox == nullptr)
            {
                continue;
            }
            const QSignalBlocker kBlocker(checkState.checkBox);
            checkState.checkBox->setChecked(
                simpleModel.providerPresetNameList.contains(
                    checkState.valueText,
                    Qt::CaseInsensitive));
        }
        for (EtwSimpleFilterCheckUiState& checkState : uiState.actionCheckList)
        {
            if (checkState.checkBox == nullptr)
            {
                continue;
            }
            const QSignalBlocker kBlocker(checkState.checkBox);
            checkState.checkBox->setChecked(
                simpleModel.actionPresetList.contains(
                    checkState.valueText,
                    Qt::CaseInsensitive));
        }
    };
    const auto kApplyGroupModels = [this](
        const EtwFilterStage stage,
        const std::vector<EtwFilterRuleGroupModel>& groupModelList) {
        std::vector<std::unique_ptr<EtwFilterRuleGroupUiState>>& targetGroupList =
            stage == EtwFilterStage::kPre
                ? etwPreFilterRuleGroupUiList_
                : etwPostFilterRuleGroupUiList_;
        for (const std::unique_ptr<EtwFilterRuleGroupUiState>& groupState : targetGroupList)
        {
            if (groupState != nullptr && groupState->containerWidget != nullptr)
            {
                delete groupState->containerWidget;
            }
        }
        targetGroupList.clear();
        if (stage == EtwFilterStage::kPre)
        {
            etwPreFilterNextGroupId_ = 1;
        }
        else
        {
            etwPostFilterNextGroupId_ = 1;
        }

        const std::size_t kGroupCount = std::max<std::size_t>(groupModelList.size(), 1U);
        for (std::size_t groupIndex = 0; groupIndex < kGroupCount; ++groupIndex)
        {
            addEtwFilterRuleGroup(stage);
            if (groupIndex >= groupModelList.size() || targetGroupList.empty())
            {
                continue;
            }

            EtwFilterRuleGroupUiState* groupState = targetGroupList.back().get();
            if (groupState == nullptr)
            {
                continue;
            }
            const EtwFilterRuleGroupModel& groupModel = groupModelList[groupIndex];
            if (groupState->enabledCheck != nullptr)
            {
                const QSignalBlocker kBlocker(groupState->enabledCheck);
                groupState->enabledCheck->setChecked(groupModel.enabled);
            }
            if (groupState->stringModeCombo != nullptr)
            {
                const QString kModeText = etwFilterStringModeToText(groupModel.stringMode);
                const QSignalBlocker kBlocker(groupState->stringModeCombo);
                for (int index = 0; index < groupState->stringModeCombo->count(); ++index)
                {
                    if (groupState->stringModeCombo->itemData(index).toString()
                            .compare(kModeText, Qt::CaseInsensitive) == 0)
                    {
                        groupState->stringModeCombo->setCurrentIndex(index);
                        break;
                    }
                }
            }
            if (groupState->caseSensitiveCheck != nullptr)
            {
                const QSignalBlocker kBlocker(groupState->caseSensitiveCheck);
                groupState->caseSensitiveCheck->setChecked(groupModel.caseSensitive);
            }
            if (groupState->invertCheck != nullptr)
            {
                const QSignalBlocker kBlocker(groupState->invertCheck);
                groupState->invertCheck->setChecked(groupModel.invertMatch);
            }
            if (groupState->detailVisibleColumnsCheck != nullptr)
            {
                const QSignalBlocker kBlocker(groupState->detailVisibleColumnsCheck);
                groupState->detailVisibleColumnsCheck->setChecked(
                    groupModel.detailVisibleColumnsOnly);
            }
            if (groupState->detailMatchAllFieldsCheck != nullptr)
            {
                const QSignalBlocker kBlocker(groupState->detailMatchAllFieldsCheck);
                groupState->detailMatchAllFieldsCheck->setChecked(
                    groupModel.detailMatchAllFields);
            }

            for (EtwFilterCategoryCheckUiState& categoryUi : groupState->categoryCheckList)
            {
                if (categoryUi.checkBox == nullptr)
                {
                    continue;
                }
                const QSignalBlocker kBlocker(categoryUi.checkBox);
                categoryUi.checkBox->setChecked(
                    groupModel.providerCategoryList.contains(
                        categoryUi.categoryText,
                        Qt::CaseInsensitive));
            }
            for (EtwFilterFieldUiState& fieldUi : groupState->fieldList)
            {
                if (fieldUi.inputEdit == nullptr)
                {
                    continue;
                }
                const auto kFound = std::find_if(
                    groupModel.fieldList.cbegin(),
                    groupModel.fieldList.cend(),
                    [&fieldUi](const EtwFilterRuleFieldModel& fieldModel) {
                        return fieldModel.fieldId == fieldUi.fieldId;
                    });
                const QSignalBlocker kBlocker(fieldUi.inputEdit);
                fieldUi.inputEdit->setText(
                    kFound == groupModel.fieldList.cend()
                        ? QString()
                        : kFound->inputText);
            }
        }
        rebuildEtwFilterRuleGroupUi(stage);
    };

    kApplySimpleModel(EtwFilterStage::kPre, filterModel.preSimpleFilter);
    kApplySimpleModel(EtwFilterStage::kPost, filterModel.postSimpleFilter);
    kApplyGroupModels(EtwFilterStage::kPre, filterModel.preGroupList);
    kApplyGroupModels(EtwFilterStage::kPost, filterModel.postGroupList);

    etwPreSimpleFilterCompiled_ = std::move(compiledModel.preSimpleFilter);
    etwPreFilterCompiledGroupList_ = std::move(compiledModel.preGroupList);
    etwPostSimpleFilterCompiled_ = std::move(compiledModel.postSimpleFilter);
    etwPostFilterCompiledGroupList_ = std::move(compiledModel.postGroupList);
    {
        std::lock_guard<std::mutex> lock(etwPreFilterSnapshotMutex_);
        etwPreFilterCompiledSnapshot_ = kPreSnapshotPointer;
    }

    QString archiveDirectory;
    {
        std::lock_guard<std::mutex> lock(etwArchiveMutex_);
        archiveDirectory = etwArchiveDirectory_;
    }
    if (archiveDirectory.trimmed().isEmpty())
    {
        applyEtwPostFilterToTable(0, false);
    }
    else
    {
        scheduleEtwArchiveFilterRebuild();
    }

    updateEtwSimpleFilterStateLabel(EtwFilterStage::kPre);
    updateEtwSimpleFilterStateLabel(EtwFilterStage::kPost);
    updateEtwFilterStateLabel(EtwFilterStage::kPre);
    updateEtwFilterStateLabel(EtwFilterStage::kPost);
    updateEtwCollapseHeight();
}
