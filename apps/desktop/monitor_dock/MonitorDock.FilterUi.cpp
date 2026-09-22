#include "MonitorDock.Support.h"

using namespace ksword::ui::monitor_dock;

MonitorDock::EtwFilterRuleGroupUiState* MonitorDock::findEtwFilterRuleGroupById(
    const EtwFilterStage stage,
    const int groupId)
{
    std::vector<std::unique_ptr<EtwFilterRuleGroupUiState>>& groupList =
        stage == EtwFilterStage::kPre ? etwPreFilterRuleGroupUiList_ : etwPostFilterRuleGroupUiList_;
    for (const std::unique_ptr<EtwFilterRuleGroupUiState>& groupState : groupList)
    {
        if (groupState != nullptr && groupState->groupId == groupId)
        {
            return groupState.get();
        }
    }
    return nullptr;
}

const MonitorDock::EtwFilterRuleGroupUiState* MonitorDock::findEtwFilterRuleGroupById(
    const EtwFilterStage stage,
    const int groupId) const
{
    const std::vector<std::unique_ptr<EtwFilterRuleGroupUiState>>& groupList =
        stage == EtwFilterStage::kPre ? etwPreFilterRuleGroupUiList_ : etwPostFilterRuleGroupUiList_;
    for (const std::unique_ptr<EtwFilterRuleGroupUiState>& groupState : groupList)
    {
        if (groupState != nullptr && groupState->groupId == groupId)
        {
            return groupState.get();
        }
    }
    return nullptr;
}

void MonitorDock::rebuildEtwFilterRuleGroupUi(const EtwFilterStage stage)
{
    QVBoxLayout* hostLayout = stage == EtwFilterStage::kPre
        ? etwPreFilterGroupHostLayout_
        : etwPostFilterGroupHostLayout_;
    if (hostLayout == nullptr)
    {
        return;
    }

    std::vector<std::unique_ptr<EtwFilterRuleGroupUiState>>& groupList =
        stage == EtwFilterStage::kPre ? etwPreFilterRuleGroupUiList_ : etwPostFilterRuleGroupUiList_;

    while (hostLayout->count() > 0)
    {
        QLayoutItem* item = hostLayout->takeAt(0);
        delete item;
    }

    const bool kCanRemove = groupList.size() > 1;
    int displayIndex = 1;
    for (const std::unique_ptr<EtwFilterRuleGroupUiState>& groupState : groupList)
    {
        if (groupState == nullptr || groupState->containerWidget == nullptr)
        {
            continue;
        }
        if (groupState->titleLabel != nullptr)
        {
            groupState->titleLabel->setText(QStringLiteral("规则组%1").arg(displayIndex));
        }
        if (groupState->removeGroupButton != nullptr)
        {
            groupState->removeGroupButton->setEnabled(kCanRemove);
        }
        hostLayout->addWidget(groupState->containerWidget);
        ++displayIndex;
    }
    hostLayout->addStretch(1);
    updateEtwCollapseHeight();
}

void MonitorDock::addEtwFilterRuleGroup(const EtwFilterStage stage)
{
    QWidget* hostWidget = stage == EtwFilterStage::kPre
        ? etwPreFilterGroupHostWidget_
        : etwPostFilterGroupHostWidget_;
    if (hostWidget == nullptr)
    {
        return;
    }

    std::vector<std::unique_ptr<EtwFilterRuleGroupUiState>>& groupList =
        stage == EtwFilterStage::kPre ? etwPreFilterRuleGroupUiList_ : etwPostFilterRuleGroupUiList_;
    int& nextGroupId = stage == EtwFilterStage::kPre ? etwPreFilterNextGroupId_ : etwPostFilterNextGroupId_;

    std::unique_ptr<EtwFilterRuleGroupUiState> groupState = std::make_unique<EtwFilterRuleGroupUiState>();
    groupState->groupId = nextGroupId++;
    groupState->containerWidget = new QWidget(hostWidget);

    QVBoxLayout* rootLayout = new QVBoxLayout(groupState->containerWidget);
    rootLayout->setContentsMargins(8, 8, 8, 8);
    rootLayout->setSpacing(6);

    QHBoxLayout* headerLayout = new QHBoxLayout();
    headerLayout->setContentsMargins(0, 0, 0, 0);
    headerLayout->setSpacing(6);
    groupState->titleLabel = new QLabel(QStringLiteral("规则组"), groupState->containerWidget);
    groupState->enabledCheck = new QCheckBox(QStringLiteral("启用"), groupState->containerWidget);
    groupState->enabledCheck->setChecked(true);
    groupState->removeGroupButton = new QPushButton(QIcon(":/Icon/log_cancel_track.svg"), QString(), groupState->containerWidget);
    groupState->removeGroupButton->setToolTip(QStringLiteral("删除当前规则组"));
    groupState->removeGroupButton->setStyleSheet(blueButtonStyle());
    groupState->removeGroupButton->setFixedWidth(32);
    headerLayout->addWidget(groupState->titleLabel);
    headerLayout->addWidget(groupState->enabledCheck);
    headerLayout->addStretch(1);
    headerLayout->addWidget(groupState->removeGroupButton);
    rootLayout->addLayout(headerLayout);

    QFrame* separatorLine = new QFrame(groupState->containerWidget);
    separatorLine->setFrameShape(QFrame::HLine);
    separatorLine->setFrameShadow(QFrame::Sunken);
    rootLayout->addWidget(separatorLine);

    QHBoxLayout* optionLayout = new QHBoxLayout();
    optionLayout->setContentsMargins(0, 0, 0, 0);
    optionLayout->setSpacing(6);
    optionLayout->addWidget(new QLabel(QStringLiteral("字符串匹配"), groupState->containerWidget));
    groupState->stringModeCombo = new QComboBox(groupState->containerWidget);
    groupState->stringModeCombo->setStyleSheet(blueInputStyle());
    groupState->stringModeCombo->addItem(QStringLiteral("正则"), QStringLiteral("regex"));
    groupState->stringModeCombo->addItem(QStringLiteral("精确"), QStringLiteral("exact"));
    groupState->stringModeCombo->addItem(QStringLiteral("包含"), QStringLiteral("contains"));
    groupState->stringModeCombo->addItem(QStringLiteral("前缀"), QStringLiteral("prefix"));
    groupState->stringModeCombo->addItem(QStringLiteral("后缀"), QStringLiteral("suffix"));
    groupState->caseSensitiveCheck = new QCheckBox(QStringLiteral("区分大小写"), groupState->containerWidget);
    groupState->invertCheck = new QCheckBox(QStringLiteral("反向"), groupState->containerWidget);
    groupState->detailVisibleColumnsCheck = new QCheckBox(QStringLiteral("仅匹配可见列"), groupState->containerWidget);
    groupState->detailMatchAllFieldsCheck = new QCheckBox(QStringLiteral("Detail匹配全字段"), groupState->containerWidget);
    groupState->detailMatchAllFieldsCheck->setChecked(true);
    optionLayout->addWidget(groupState->stringModeCombo, 0);
    optionLayout->addWidget(groupState->caseSensitiveCheck, 0);
    optionLayout->addWidget(groupState->invertCheck, 0);
    optionLayout->addWidget(groupState->detailVisibleColumnsCheck, 0);
    optionLayout->addWidget(groupState->detailMatchAllFieldsCheck, 0);
    optionLayout->addStretch(1);
    rootLayout->addLayout(optionLayout);

    QHBoxLayout* categoryLayout = new QHBoxLayout();
    categoryLayout->setContentsMargins(0, 0, 0, 0);
    categoryLayout->setSpacing(6);
    categoryLayout->addWidget(new QLabel(QStringLiteral("Provider分类开关"), groupState->containerWidget));
    for (const QString& categoryText : etwFilterProviderCategoryList())
    {
        QCheckBox* checkBox = new QCheckBox(categoryText, groupState->containerWidget);
        groupState->categoryCheckList.push_back({ categoryText, checkBox });
        categoryLayout->addWidget(checkBox, 0);
    }
    categoryLayout->addStretch(1);
    rootLayout->addLayout(categoryLayout);

    QGridLayout* fieldLayout = new QGridLayout();
    fieldLayout->setContentsMargins(0, 0, 0, 0);
    fieldLayout->setHorizontalSpacing(8);
    fieldLayout->setVerticalSpacing(4);

    const std::vector<EtwFilterFieldDescriptor>& fieldDescriptorList = etwFilterFieldDescriptorList();
    constexpr int kColumnCount = 2;
    int fieldIndex = 0;
    for (const EtwFilterFieldDescriptor& descriptor : fieldDescriptorList)
    {
        QLabel* fieldLabel = new QLabel(QString::fromUtf8(descriptor.label), groupState->containerWidget);
        QLineEdit* fieldEdit = new QLineEdit(groupState->containerWidget);
        fieldEdit->setStyleSheet(blueInputStyle());
        fieldEdit->setPlaceholderText(
            QStringLiteral("%1（逗号/分号/空白分隔）").arg(QString::fromUtf8(descriptor.placeholder)));

        const int kRow = fieldIndex / kColumnCount;
        const int kCol = fieldIndex % kColumnCount;
        QWidget* fieldCellWidget = new QWidget(groupState->containerWidget);
        QVBoxLayout* fieldCellLayout = new QVBoxLayout(fieldCellWidget);
        fieldCellLayout->setContentsMargins(0, 0, 0, 0);
        fieldCellLayout->setSpacing(2);
        fieldCellLayout->addWidget(fieldLabel);
        fieldCellLayout->addWidget(fieldEdit);
        fieldLayout->addWidget(fieldCellWidget, kRow, kCol);

        EtwFilterFieldUiState fieldUi;
        fieldUi.fieldId = descriptor.fieldId;
        fieldUi.fieldKey = QString::fromLatin1(descriptor.key);
        fieldUi.fieldLabel = QString::fromUtf8(descriptor.label);
        fieldUi.inputEdit = fieldEdit;
        groupState->fieldList.push_back(std::move(fieldUi));

        ++fieldIndex;
    }

    rootLayout->addLayout(fieldLayout);

    const int kGroupId = groupState->groupId;
    connect(groupState->enabledCheck, &QCheckBox::toggled, this, [this, stage]() {
        applyEtwFilterRules(stage);
    });
    connect(groupState->removeGroupButton, &QPushButton::clicked, this, [this, stage, kGroupId]() {
        removeEtwFilterRuleGroup(stage, kGroupId);
    });
    connect(groupState->stringModeCombo, &QComboBox::currentIndexChanged, this, [this, stage](int) {
        applyEtwFilterRules(stage);
    });
    connect(groupState->caseSensitiveCheck, &QCheckBox::toggled, this, [this, stage]() {
        applyEtwFilterRules(stage);
    });
    connect(groupState->invertCheck, &QCheckBox::toggled, this, [this, stage]() {
        applyEtwFilterRules(stage);
    });
    connect(groupState->detailVisibleColumnsCheck, &QCheckBox::toggled, this, [this, stage]() {
        applyEtwFilterRules(stage);
    });
    connect(groupState->detailMatchAllFieldsCheck, &QCheckBox::toggled, this, [this, stage]() {
        applyEtwFilterRules(stage);
    });
    for (const EtwFilterFieldUiState& fieldUi : groupState->fieldList)
    {
        if (fieldUi.inputEdit != nullptr)
        {
            connect(fieldUi.inputEdit, &QLineEdit::editingFinished, this, [this, stage]() {
                applyEtwFilterRules(stage);
            });
        }
    }
    for (const EtwFilterCategoryCheckUiState& categoryUi : groupState->categoryCheckList)
    {
        if (categoryUi.checkBox != nullptr)
        {
            connect(categoryUi.checkBox, &QCheckBox::toggled, this, [this, stage]() {
                applyEtwFilterRules(stage);
            });
        }
    }

    groupList.push_back(std::move(groupState));
    rebuildEtwFilterRuleGroupUi(stage);
}

void MonitorDock::removeEtwFilterRuleGroup(const EtwFilterStage stage, const int groupId)
{
    std::vector<std::unique_ptr<EtwFilterRuleGroupUiState>>& groupList =
        stage == EtwFilterStage::kPre ? etwPreFilterRuleGroupUiList_ : etwPostFilterRuleGroupUiList_;
    const auto kIterator = std::find_if(
        groupList.begin(),
        groupList.end(),
        [groupId](const std::unique_ptr<EtwFilterRuleGroupUiState>& groupState) {
            return groupState != nullptr && groupState->groupId == groupId;
        });
    if (kIterator == groupList.end())
    {
        return;
    }

    if ((*kIterator) != nullptr && (*kIterator)->containerWidget != nullptr)
    {
        delete (*kIterator)->containerWidget;
    }
    groupList.erase(kIterator);
    if (groupList.empty())
    {
        addEtwFilterRuleGroup(stage);
    }
    rebuildEtwFilterRuleGroupUi(stage);
    applyEtwFilterRules(stage);
}

void MonitorDock::clearEtwFilterGroups(const EtwFilterStage stage, const bool resetTimelineSelection)
{
    std::vector<std::unique_ptr<EtwFilterRuleGroupUiState>>& groupList =
        stage == EtwFilterStage::kPre ? etwPreFilterRuleGroupUiList_ : etwPostFilterRuleGroupUiList_;
    for (const std::unique_ptr<EtwFilterRuleGroupUiState>& groupState : groupList)
    {
        if (groupState != nullptr && groupState->containerWidget != nullptr)
        {
            delete groupState->containerWidget;
        }
    }
    groupList.clear();
    if (stage == EtwFilterStage::kPre)
    {
        etwPreFilterNextGroupId_ = 1;
    }
    else
    {
        etwPostFilterNextGroupId_ = 1;
    }
    if (stage == EtwFilterStage::kPost && resetTimelineSelection && etwTimelineWidget_ != nullptr)
    {
        // The 'Clear' semantics of post-filtering override display-layer filtering and reset the timeline selection to the full range.
        etwTimelineWidget_->resetSelectionToFullRange();
        etwTimelineSelectionStart100ns_ = etwTimelineWidget_->selectionStart100ns();
        etwTimelineSelectionEnd100ns_ = etwTimelineWidget_->selectionEnd100ns();
        etwTimelineUserSelectionActive_ = false;
    }
    addEtwFilterRuleGroup(stage);
    rebuildEtwFilterRuleGroupUi(stage);
}

MonitorDock::EtwSimpleFilterModel MonitorDock::captureEtwSimpleFilterModel(
    const EtwFilterStage stage) const
{
    const EtwSimpleFilterUiState& uiState = etwSimpleFilterUi(stage);
    const auto kEditText = [](QLineEdit* edit) {
        return edit == nullptr ? QString() : edit->text().trimmed();
    };

    EtwSimpleFilterModel filterModel;
    filterModel.enabled = uiState.enabledCheck == nullptr || uiState.enabledCheck->isChecked();
    filterModel.pidText = kEditText(uiState.pidEdit);
    filterModel.processNameText = kEditText(uiState.processNameEdit);
    filterModel.filePathText = kEditText(uiState.filePathEdit);
    filterModel.eventIdText = kEditText(uiState.eventIdEdit);
    filterModel.eventNameText = kEditText(uiState.eventNameEdit);
    filterModel.registryPathText = kEditText(uiState.registryPathEdit);
    filterModel.networkAddressText = kEditText(uiState.networkAddressEdit);
    filterModel.networkPortText = kEditText(uiState.networkPortEdit);
    filterModel.statusText = kEditText(uiState.statusEdit);
    filterModel.customProviderText = kEditText(uiState.customProviderEdit);
    filterModel.customActionText = kEditText(uiState.customActionEdit);

    for (const EtwSimpleFilterCheckUiState& checkState : uiState.providerCheckList)
    {
        if (checkState.checkBox != nullptr && checkState.checkBox->isChecked())
        {
            filterModel.providerPresetNameList.push_back(checkState.valueText);
        }
    }
    for (const EtwSimpleFilterCheckUiState& checkState : uiState.actionCheckList)
    {
        if (checkState.checkBox != nullptr && checkState.checkBox->isChecked())
        {
            filterModel.actionPresetList.push_back(checkState.valueText);
        }
    }
    return filterModel;
}

std::vector<MonitorDock::EtwFilterRuleGroupModel> MonitorDock::captureEtwFilterGroupModels(
    const EtwFilterStage stage) const
{
    const std::vector<std::unique_ptr<EtwFilterRuleGroupUiState>>& groupList =
        stage == EtwFilterStage::kPre ? etwPreFilterRuleGroupUiList_ : etwPostFilterRuleGroupUiList_;
    std::vector<EtwFilterRuleGroupModel> groupModelList;
    groupModelList.reserve(groupList.size());

    for (const std::unique_ptr<EtwFilterRuleGroupUiState>& groupState : groupList)
    {
        if (groupState == nullptr)
        {
            continue;
        }

        EtwFilterRuleGroupModel groupModel;
        groupModel.groupId = groupState->groupId;
        groupModel.enabled = groupState->enabledCheck == nullptr || groupState->enabledCheck->isChecked();
        groupModel.stringMode = etwFilterStringModeFromText(
            groupState->stringModeCombo == nullptr
                ? QStringLiteral("regex")
                : groupState->stringModeCombo->currentData().toString());
        groupModel.caseSensitive = groupState->caseSensitiveCheck != nullptr
            && groupState->caseSensitiveCheck->isChecked();
        groupModel.invertMatch = groupState->invertCheck != nullptr
            && groupState->invertCheck->isChecked();
        groupModel.detailVisibleColumnsOnly = groupState->detailVisibleColumnsCheck != nullptr
            && groupState->detailVisibleColumnsCheck->isChecked();
        groupModel.detailMatchAllFields = groupState->detailMatchAllFieldsCheck == nullptr
            || groupState->detailMatchAllFieldsCheck->isChecked();

        for (const EtwFilterCategoryCheckUiState& categoryUi : groupState->categoryCheckList)
        {
            if (categoryUi.checkBox != nullptr && categoryUi.checkBox->isChecked())
            {
                groupModel.providerCategoryList.push_back(categoryUi.categoryText);
            }
        }
        for (const EtwFilterFieldUiState& fieldUi : groupState->fieldList)
        {
            if (fieldUi.inputEdit == nullptr)
            {
                continue;
            }

            const QString kInputText = fieldUi.inputEdit->text().trimmed();
            if (kInputText.isEmpty())
            {
                continue;
            }

            EtwFilterRuleFieldModel fieldModel;
            fieldModel.fieldId = fieldUi.fieldId;
            fieldModel.fieldKey = fieldUi.fieldKey;
            fieldModel.fieldLabel = fieldUi.fieldLabel;
            fieldModel.inputText = kInputText;
            groupModel.fieldList.push_back(std::move(fieldModel));
        }
        groupModelList.push_back(std::move(groupModel));
    }
    return groupModelList;
}

MonitorDock::EtwFilterConfigModel MonitorDock::captureEtwFilterConfigModel() const
{
    EtwFilterConfigModel filterModel;
    filterModel.preSimpleFilter = captureEtwSimpleFilterModel(EtwFilterStage::kPre);
    filterModel.postSimpleFilter = captureEtwSimpleFilterModel(EtwFilterStage::kPost);
    filterModel.preGroupList = captureEtwFilterGroupModels(EtwFilterStage::kPre);
    filterModel.postGroupList = captureEtwFilterGroupModels(EtwFilterStage::kPost);
    return filterModel;
}
