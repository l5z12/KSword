#include "HandleDock.h"

// ============================================================
// HandleDock.Filter.cpp
// Purpose:
// - Hosts the handle module's local filtering, status text, and right-click menu logic;
// - Prevents the main UI file from becoming too long;
// - Separate the responsibilities of 'enumeration' and 'local interaction'.
// ============================================================

#include "../Theme.h"
#include "../internationalization/LanguageManager.h"
#include "../ui/TableInteractionSupport.h"

#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFile>
#include <QFileDialog>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMenu>
#include <QMessageBox>
#include <QPushButton>
#include <QSaveFile>
#include <QSet>
#include <QSettings>
#include <QSignalBlocker>
#include <QSpinBox>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QVBoxLayout>

#include <algorithm>
#include <functional>
#include <limits>
#include <set>

namespace
{
    constexpr std::size_t kHandleRulePageSize = 300;

    QString sanitizeTsvField(QString value)
    {
        value.replace('\t', QStringLiteral("\\t"));
        value.replace('\r', QStringLiteral("\\r"));
        value.replace('\n', QStringLiteral("\\n"));
        value.replace(QChar::Null, QStringLiteral("\\0"));
        qsizetype firstMeaningfulIndex = 0;
        while (firstMeaningfulIndex < value.size()
            && value.at(firstMeaningfulIndex).isSpace())
        {
            ++firstMeaningfulIndex;
        }
        if (firstMeaningfulIndex < value.size()
            && (value.at(firstMeaningfulIndex) == QLatin1Char('=')
                || value.at(firstMeaningfulIndex) == QLatin1Char('+')
                || value.at(firstMeaningfulIndex) == QLatin1Char('-')
                || value.at(firstMeaningfulIndex) == QLatin1Char('@')))
        {
            // Prevent process names, object names, or rule names from being interpreted as formulas in the spreadsheet.
            value.prepend(QLatin1Char('\''));
        }
        return value;
    }

    QString processIdsToText(const QVector<std::uint32_t>& processIds)
    {
        QStringList textList;
        textList.reserve(processIds.size());
        for (const std::uint32_t kProcessId : processIds)
        {
            textList.push_back(QString::number(kProcessId));
        }
        return textList.join(QStringLiteral(", "));
    }

    bool sameGlobalSettings(
        const ks::handle::HandleFilterGlobalSettings& left,
        const ks::handle::HandleFilterGlobalSettings& right)
    {
        return left.enumMode == right.enumMode
            && left.resolveObjectName == right.resolveObjectName
            && left.nameResolveBudget == right.nameResolveBudget;
    }
}

void HandleDock::applyLocalHandleFilters()
{
    applyLocalHandleFilters(true);
}

void HandleDock::applyLocalHandleFilters(const bool rebuildTable)
{
    ruleMatchStates_.clear();
    totalRuleMatchCount_ = 0;

    const QVector<ks::handle::HandleFilterRule> kActiveRuleList = temporaryFilterActive_
        ? QVector<ks::handle::HandleFilterRule>{ temporaryFilterRule_ }
        : filterDocument_.rules;
    ruleMatchStates_.reserve(static_cast<std::size_t>(kActiveRuleList.size()));
    for (const ks::handle::HandleFilterRule& rule : kActiveRuleList)
    {
        HandleRuleMatchState state;
        state.ruleId = rule.id;
        state.ruleName = rule.name;
        state.enabled = rule.enabled;
        if (rule.enabled)
        {
            state.rowIndices.reserve(std::min<std::size_t>(allRows_.size(), 4096));
            for (std::size_t sourceRowIndex = 0;
                sourceRowIndex < allRows_.size();
                ++sourceRowIndex)
            {
                if (handleRowMatchesRule(allRows_[sourceRowIndex], rule))
                {
                    state.rowIndices.push_back(sourceRowIndex);
                }
            }
            totalRuleMatchCount_ += state.rowIndices.size();
        }
        ruleMatchStates_.push_back(std::move(state));
    }

    if (!rebuildTable)
    {
        return;
    }

    rebuildHandleTable();
    updateHandleSummaryStatus();
}

bool HandleDock::handleRowMatchesRule(
    const HandleRow& row,
    const ks::handle::HandleFilterRule& rule) const
{
    if (!rule.processIds.isEmpty() && !rule.processIds.contains(row.processId))
    {
        return false;
    }
    if (!rule.typeName.trimmed().isEmpty() &&
        row.typeName.compare(rule.typeName.trimmed(), Qt::CaseInsensitive) != 0)
    {
        return false;
    }
    switch (rule.diffStatus)
    {
    case ks::handle::FilterDiffStatus::kUserOnly:
        if (row.diffStatus != HandleDiffStatus::kUserOnly) return false;
        break;
    case ks::handle::FilterDiffStatus::kKernelOnly:
        if (row.diffStatus != HandleDiffStatus::kKernelOnly) return false;
        break;
    case ks::handle::FilterDiffStatus::kBoth:
        if (row.diffStatus != HandleDiffStatus::kBoth) return false;
        break;
    case ks::handle::FilterDiffStatus::kAny:
    default:
        break;
    }
    if (rule.onlyNamed && row.objectName.trimmed().isEmpty())
    {
        return false;
    }

    const QString kKeyword = rule.keyword.trimmed().toLower();
    if (kKeyword.isEmpty())
    {
        return true;
    }
    const QString kPidValueText = QString::number(row.processId);
    const QString kTypeIndexText = QString::number(row.typeIndex);
    const QString kHandleText = QStringLiteral("0x%1")
        .arg(static_cast<qulonglong>(row.handleValue), 0, 16).toLower();
    const QString kAddressText = QStringLiteral("0x%1")
        .arg(static_cast<qulonglong>(row.objectAddress), 0, 16).toLower();
    const QString kAccessText = QStringLiteral("0x%1")
        .arg(row.grantedAccess, 8, 16, QChar('0')).toLower();
    return row.processName.toLower().contains(kKeyword)
        || row.typeName.toLower().contains(kKeyword)
        || row.objectName.toLower().contains(kKeyword)
        || kPidValueText.contains(kKeyword)
        || kTypeIndexText.contains(kKeyword)
        || kHandleText.contains(kKeyword)
        || kAddressText.contains(kKeyword)
        || kAccessText.contains(kKeyword)
        || decodeGrantedAccessText(row.typeName, row.grantedAccess).toLower().contains(kKeyword)
        || formatHandleSourceText(row.sourceMode).toLower().contains(kKeyword)
        || formatHandleDecodeStatusText(row.decodeStatus).toLower().contains(kKeyword)
        || formatHandleDiffStatusText(row.diffStatus).toLower().contains(kKeyword);
}

HandleDock::HandleRuleMatchState* HandleDock::findRuleMatchState(const QString& ruleId)
{
    for (HandleRuleMatchState& state : ruleMatchStates_)
    {
        if (state.ruleId == ruleId)
        {
            return &state;
        }
    }
    return nullptr;
}

const HandleDock::HandleRuleMatchState* HandleDock::findRuleMatchState(const QString& ruleId) const
{
    for (const HandleRuleMatchState& state : ruleMatchStates_)
    {
        if (state.ruleId == ruleId)
        {
            return &state;
        }
    }
    return nullptr;
}

const ks::handle::HandleFilterRule* HandleDock::findActiveRule(const QString& ruleId) const
{
    if (temporaryFilterActive_)
    {
        return temporaryFilterRule_.id == ruleId ? &temporaryFilterRule_ : nullptr;
    }
    for (const ks::handle::HandleFilterRule& rule : filterDocument_.rules)
    {
        if (rule.id == ruleId)
        {
            return &rule;
        }
    }
    return nullptr;
}

void HandleDock::rebuildRuleSummaryTree()
{
    if (tableWidget_ == nullptr)
    {
        return;
    }
    ++processIconResolveGeneration_;
    if (processIconResolveCancelFlag_ != nullptr)
    {
        processIconResolveCancelFlag_->store(true);
    }
    processIconResolveCancelFlag_ = std::make_shared<std::atomic_bool>(false);
    tableWidget_->clear();

    for (std::size_t ruleIndex = 0; ruleIndex < ruleMatchStates_.size(); ++ruleIndex)
    {
        HandleRuleMatchState& state = ruleMatchStates_[ruleIndex];
        auto* summaryItem = new QTreeWidgetItem();
        summaryItem->setData(0, ks::handle::kHandleTreeItemKindRole,
            static_cast<int>(ks::handle::HandleTreeItemKind::kRuleSummary));
        summaryItem->setData(0, ks::handle::kHandleTreeRuleIdRole, state.ruleId);
        summaryItem->setData(0, ks::handle::kHandleTreeRuleOrderRole,
            static_cast<qulonglong>(ruleIndex));
        summaryItem->setText(
            static_cast<int>(HandleTableColumn::kProcessId),
            state.enabled
                ? ks::i18n::sourceText(QStringLiteral("%1 命中 %2 条"))
                    .arg(state.ruleName).arg(state.rowIndices.size())
                : ks::i18n::sourceText(QStringLiteral("%1 已停用"))
                    .arg(state.ruleName));
        const ks::handle::HandleFilterRule* rule = findActiveRule(state.ruleId);
        if (rule != nullptr)
        {
            summaryItem->setToolTip(0, buildRuleConditionSummary(*rule));
        }
        for (int column = 0; column < static_cast<int>(HandleTableColumn::kCount); ++column)
        {
            summaryItem->setForeground(column, ksword_theme::primaryBlueColor);
        }
        if (state.enabled && !state.rowIndices.empty())
        {
            auto* placeholderItem = new QTreeWidgetItem(summaryItem);
            placeholderItem->setData(0, ks::handle::kHandleTreeItemKindRole,
                static_cast<int>(ks::handle::HandleTreeItemKind::kLazyPlaceholder));
            placeholderItem->setData(0, ks::handle::kHandleTreeRuleIdRole, state.ruleId);
        }
        tableWidget_->addTopLevelItem(summaryItem);
        state.summaryItem = summaryItem;
        state.loadedCount = 0;
    }

    if (tableWidget_->topLevelItemCount() > 0)
    {
        tableWidget_->setCurrentItem(tableWidget_->topLevelItem(0));
    }
    else
    {
        showHandleDetailPlaceholder(QStringLiteral("没有可用的句柄筛选规则。"));
    }
}

void HandleDock::appendNextRuleResultBatch(const QString& ruleId)
{
    HandleRuleMatchState* state = findRuleMatchState(ruleId);
    if (state == nullptr || state->summaryItem == nullptr || !state->enabled)
    {
        return;
    }
    QTreeWidgetItem* const kSummaryItem = state->summaryItem;
    for (int childIndex = kSummaryItem->childCount() - 1; childIndex >= 0; --childIndex)
    {
        QTreeWidgetItem* childItem = kSummaryItem->child(childIndex);
        const int kKind = childItem->data(0, ks::handle::kHandleTreeItemKindRole).toInt();
        if (kKind == static_cast<int>(ks::handle::HandleTreeItemKind::kLazyPlaceholder)
            || kKind == static_cast<int>(ks::handle::HandleTreeItemKind::kLoadMore))
        {
            delete kSummaryItem->takeChild(childIndex);
        }
    }
    if (state->loadedCount >= state->rowIndices.size())
    {
        return;
    }

    const std::size_t kBatchEnd = std::min(
        state->loadedCount + kHandleRulePageSize,
        state->rowIndices.size());
    QVector<qulonglong> sourceRowIndices;
    QVector<QTreeWidgetItem*> newItems;
    sourceRowIndices.reserve(static_cast<qsizetype>(kBatchEnd - state->loadedCount));
    newItems.reserve(static_cast<qsizetype>(kBatchEnd - state->loadedCount));
    for (std::size_t matchIndex = state->loadedCount; matchIndex < kBatchEnd; ++matchIndex)
    {
        const std::size_t kSourceRowIndex = state->rowIndices[matchIndex];
        QTreeWidgetItem* item = createHandleTreeRow(kSourceRowIndex);
        if (item == nullptr)
        {
            continue;
        }
        item->setData(0, ks::handle::kHandleTreeRuleIdRole, ruleId);
        kSummaryItem->addChild(item);
        sourceRowIndices.push_back(static_cast<qulonglong>(kSourceRowIndex));
        newItems.push_back(item);
    }
    state->loadedCount = kBatchEnd;
    if (state->loadedCount < state->rowIndices.size())
    {
        auto* loadMoreItem = new QTreeWidgetItem(kSummaryItem);
        loadMoreItem->setData(0, ks::handle::kHandleTreeItemKindRole,
            static_cast<int>(ks::handle::HandleTreeItemKind::kLoadMore));
        loadMoreItem->setData(0, ks::handle::kHandleTreeRuleIdRole, ruleId);
        loadMoreItem->setText(
            0,
            ks::i18n::sourceText(QStringLiteral("继续加载（已显示 %1 / %2）"))
                .arg(state->loadedCount)
                .arg(state->rowIndices.size()));
        loadMoreItem->setForeground(0, ksword_theme::primaryBlueColor);
    }
    sortLoadedRuleRows(handleSortColumn_, handleSortOrder_);
    scheduleProcessIconResolution(sourceRowIndices, newItems);
}

void HandleDock::sortLoadedRuleRows(const int column, const Qt::SortOrder order)
{
    if (column < 0 || column >= static_cast<int>(HandleTableColumn::kCount))
    {
        return;
    }
    for (HandleRuleMatchState& state : ruleMatchStates_)
    {
        QTreeWidgetItem* summaryItem = state.summaryItem;
        if (summaryItem == nullptr || summaryItem->childCount() < 2)
        {
            continue;
        }
        QList<QTreeWidgetItem*> handleItems;
        QList<QTreeWidgetItem*> trailingItems;
        while (summaryItem->childCount() > 0)
        {
            QTreeWidgetItem* childItem = summaryItem->takeChild(0);
            if (childItem->data(0, ks::handle::kHandleTreeItemKindRole).toInt() ==
                static_cast<int>(ks::handle::HandleTreeItemKind::kHandleRow))
            {
                handleItems.push_back(childItem);
            }
            else
            {
                trailingItems.push_back(childItem);
            }
        }
        const auto kCompareItems = [this, column, order](QTreeWidgetItem* left, QTreeWidgetItem* right)
        {
            const std::size_t kLeftIndex = static_cast<std::size_t>(
                left->data(0, ks::handle::kHandleTreeSourceRowIndexRole).toULongLong());
            const std::size_t kRightIndex = static_cast<std::size_t>(
                right->data(0, ks::handle::kHandleTreeSourceRowIndexRole).toULongLong());
            if (kLeftIndex >= allRows_.size() || kRightIndex >= allRows_.size())
            {
                return false;
            }
            const HandleRow& leftRow = allRows_[kLeftIndex];
            const HandleRow& rightRow = allRows_[kRightIndex];
            int comparison = 0;
            switch (static_cast<HandleTableColumn>(column))
            {
            case HandleTableColumn::kProcessId:
                comparison = leftRow.processId < rightRow.processId ? -1 : leftRow.processId > rightRow.processId ? 1 : 0;
                break;
            case HandleTableColumn::kHandleValue:
                comparison = leftRow.handleValue < rightRow.handleValue ? -1 : leftRow.handleValue > rightRow.handleValue ? 1 : 0;
                break;
            case HandleTableColumn::kTypeIndex:
                comparison = leftRow.typeIndex < rightRow.typeIndex ? -1 : leftRow.typeIndex > rightRow.typeIndex ? 1 : 0;
                break;
            case HandleTableColumn::kObjectAddress:
                comparison = leftRow.objectAddress < rightRow.objectAddress ? -1 : leftRow.objectAddress > rightRow.objectAddress ? 1 : 0;
                break;
            case HandleTableColumn::kGrantedAccess:
                comparison = leftRow.grantedAccess < rightRow.grantedAccess ? -1 : leftRow.grantedAccess > rightRow.grantedAccess ? 1 : 0;
                break;
            case HandleTableColumn::kHandleCount:
                comparison = leftRow.handleCount < rightRow.handleCount ? -1 : leftRow.handleCount > rightRow.handleCount ? 1 : 0;
                break;
            case HandleTableColumn::kPointerCount:
                comparison = leftRow.pointerCount < rightRow.pointerCount ? -1 : leftRow.pointerCount > rightRow.pointerCount ? 1 : 0;
                break;
            default:
                comparison = QString::localeAwareCompare(left->text(column), right->text(column));
                break;
            }
            return order == Qt::AscendingOrder ? comparison < 0 : comparison > 0;
        };
        std::stable_sort(handleItems.begin(), handleItems.end(), kCompareItems);
        summaryItem->addChildren(handleItems);
        summaryItem->addChildren(trailingItems);
    }
}

void HandleDock::updateHandleSummaryStatus()
{
    QString statusText = ks::i18n::sourceText(
        QStringLiteral("● 已匹配 %1 条结果 | 规则:%2 | 快照:%3"))
        .arg(totalRuleMatchCount_)
        .arg(ruleMatchStates_.size())
        .arg(allRows_.size());
    if (temporaryFilterActive_)
    {
        statusText += ks::i18n::sourceText(QStringLiteral(" | 临时筛选"));
    }
    if (!lastRefreshDiagnosticText_.trimmed().isEmpty())
    {
        statusText += QStringLiteral(" | 有诊断");
    }
    updateHandleStatusLabel(statusText, false);
}

void HandleDock::loadFilterConfiguration()
{
    QSettings settings;
    const QByteArray kStoredJson = settings.value(
        QStringLiteral("HandleDock/FilterConfigurationV1")).toByteArray();
    if (kStoredJson.isEmpty())
    {
        filterDocument_ = ks::handle::createDefaultHandleFilterDocument();
        if (!filterDocument_.rules.isEmpty())
        {
            filterDocument_.rules.front().name =
                ks::i18n::sourceText(QStringLiteral("全部句柄"));
        }
        saveFilterConfiguration();
        return;
    }

    ks::handle::HandleFilterDocument loadedDocument;
    QStringList warningList;
    QString errorText;
    if (!ks::handle::deserializeHandleFilterDocument(
        kStoredJson,
        &loadedDocument,
        &warningList,
        &errorText))
    {
        filterDocument_ = ks::handle::createDefaultHandleFilterDocument();
        if (!filterDocument_.rules.isEmpty())
        {
            filterDocument_.rules.front().name =
                ks::i18n::sourceText(QStringLiteral("全部句柄"));
        }
        KLogEvent loadFilterEvent;
        warn << loadFilterEvent
            << "[HandleDock] loadFilterConfiguration: invalid saved configuration, reset to default: "
            << errorText.toStdString()
            << eol;
        saveFilterConfiguration();
        return;
    }
    filterDocument_ = std::move(loadedDocument);
}

void HandleDock::saveFilterConfiguration() const
{
    ks::handle::HandleFilterDocument storedDocument = filterDocument_;
    storedDocument.exportedAtUtc = QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);
    QString errorText;
    const QByteArray kJsonBytes =
        ks::handle::serializeHandleFilterDocument(storedDocument, &errorText);
    if (kJsonBytes.isEmpty())
    {
        KLogEvent saveFilterEvent;
        err << saveFilterEvent
            << "[HandleDock] saveFilterConfiguration: "
            << errorText.toStdString()
            << eol;
        return;
    }
    QSettings settings;
    settings.setValue(QStringLiteral("HandleDock/FilterConfigurationV1"), kJsonBytes);
}

void HandleDock::applyFilterGlobalSettingsToControls()
{
    if (enumModeCombo_ == nullptr || resolveNameCheckBox_ == nullptr || nameBudgetSpinBox_ == nullptr)
    {
        return;
    }
    const QSignalBlocker kEnumBlocker(enumModeCombo_);
    const QSignalBlocker kResolveBlocker(resolveNameCheckBox_);
    const QSignalBlocker kBudgetBlocker(nameBudgetSpinBox_);
    const int kEnumValue = static_cast<int>(filterDocument_.globalSettings.enumMode);
    const int kEnumIndex = enumModeCombo_->findData(kEnumValue);
    enumModeCombo_->setCurrentIndex(kEnumIndex >= 0 ? kEnumIndex : 1);
    resolveNameCheckBox_->setChecked(filterDocument_.globalSettings.resolveObjectName);
    nameBudgetSpinBox_->setValue(filterDocument_.globalSettings.nameResolveBudget);
}

void HandleDock::collectFilterGlobalSettingsFromControls()
{
    if (enumModeCombo_ == nullptr || resolveNameCheckBox_ == nullptr || nameBudgetSpinBox_ == nullptr)
    {
        return;
    }
    const int kEnumValue = enumModeCombo_->currentData().toInt();
    switch (static_cast<ks::handle::FilterEnumMode>(kEnumValue))
    {
    case ks::handle::FilterEnumMode::kUserSnapshot:
    case ks::handle::FilterEnumMode::kKernelHandleTable:
    case ks::handle::FilterEnumMode::kDuplicateHandle:
        filterDocument_.globalSettings.enumMode =
            static_cast<ks::handle::FilterEnumMode>(kEnumValue);
        break;
    default:
        filterDocument_.globalSettings.enumMode = ks::handle::FilterEnumMode::kDuplicateHandle;
        break;
    }
    filterDocument_.globalSettings.resolveObjectName = resolveNameCheckBox_->isChecked();
    filterDocument_.globalSettings.nameResolveBudget = nameBudgetSpinBox_->value();
}

QString HandleDock::buildRuleConditionSummary(
    const ks::handle::HandleFilterRule& rule) const
{
    QStringList conditionList;
    if (!rule.processIds.isEmpty())
    {
        conditionList.push_back(
            ks::i18n::sourceText(QStringLiteral("PID：%1"))
                .arg(processIdsToText(rule.processIds)));
    }
    if (!rule.keyword.trimmed().isEmpty())
    {
        conditionList.push_back(
            ks::i18n::sourceText(QStringLiteral("关键字：%1"))
                .arg(rule.keyword.trimmed()));
    }
    if (!rule.typeName.trimmed().isEmpty())
    {
        conditionList.push_back(
            ks::i18n::sourceText(QStringLiteral("对象类型：%1"))
                .arg(rule.typeName.trimmed()));
    }
    switch (rule.diffStatus)
    {
    case ks::handle::FilterDiffStatus::kUserOnly:
        conditionList.push_back(ks::i18n::sourceText(QStringLiteral("差异：仅用户态可见")));
        break;
    case ks::handle::FilterDiffStatus::kKernelOnly:
        conditionList.push_back(ks::i18n::sourceText(QStringLiteral("差异：仅内核可见")));
        break;
    case ks::handle::FilterDiffStatus::kBoth:
        conditionList.push_back(ks::i18n::sourceText(QStringLiteral("差异：两者均可见")));
        break;
    case ks::handle::FilterDiffStatus::kAny:
    default:
        break;
    }
    if (rule.onlyNamed)
    {
        conditionList.push_back(ks::i18n::sourceText(QStringLiteral("仅命名对象")));
    }
    return conditionList.isEmpty()
        ? ks::i18n::sourceText(QStringLiteral("全部句柄"))
        : conditionList.join(QStringLiteral("；"));
}

bool HandleDock::showRuleEditorDialog(
    ks::handle::HandleFilterRule* ruleInOut,
    const QVector<ks::handle::HandleFilterRule>& existingRules)
{
    if (ruleInOut == nullptr)
    {
        return false;
    }

    QDialog dialog(this);
    dialog.setWindowTitle(QStringLiteral("编辑句柄筛选规则"));
    dialog.resize(520, 360);
    auto* layout = new QVBoxLayout(&dialog);
    auto* formLayout = new QFormLayout();

    auto* nameEdit = new QLineEdit(ruleInOut->name, &dialog);
    auto* enabledCheck = new QCheckBox(QStringLiteral("启用此规则"), &dialog);
    enabledCheck->setChecked(ruleInOut->enabled);
    auto* pidEdit = new QLineEdit(processIdsToText(ruleInOut->processIds), &dialog);
    pidEdit->setPlaceholderText(QStringLiteral("多个 PID 使用逗号或空格分隔，留空表示不限"));
    auto* keywordEdit = new QLineEdit(ruleInOut->keyword, &dialog);
    keywordEdit->setPlaceholderText(QStringLiteral("不区分大小写，匹配现有句柄搜索字段"));
    auto* typeCombo = new QComboBox(&dialog);
    typeCombo->setEditable(true);
    typeCombo->addItem(QStringLiteral("全部类型"), QString());
    for (const QString& typeName : availableHandleTypeList_)
    {
        typeCombo->addItem(typeName, typeName);
    }
    if (ruleInOut->typeName.trimmed().isEmpty())
    {
        typeCombo->setCurrentIndex(0);
    }
    else
    {
        typeCombo->setEditText(ruleInOut->typeName);
    }
    auto* diffCombo = new QComboBox(&dialog);
    diffCombo->addItem(QStringLiteral("全部差异"), static_cast<int>(ks::handle::FilterDiffStatus::kAny));
    diffCombo->addItem(QStringLiteral("仅用户态可见"), static_cast<int>(ks::handle::FilterDiffStatus::kUserOnly));
    diffCombo->addItem(QStringLiteral("仅内核可见"), static_cast<int>(ks::handle::FilterDiffStatus::kKernelOnly));
    diffCombo->addItem(QStringLiteral("两者均可见"), static_cast<int>(ks::handle::FilterDiffStatus::kBoth));
    diffCombo->setCurrentIndex(std::max(
        0,
        diffCombo->findData(static_cast<int>(ruleInOut->diffStatus))));
    auto* onlyNamedCheck = new QCheckBox(QStringLiteral("仅匹配对象名非空的句柄"), &dialog);
    onlyNamedCheck->setChecked(ruleInOut->onlyNamed);

    formLayout->addRow(QStringLiteral("规则名称"), nameEdit);
    formLayout->addRow(QStringLiteral("状态"), enabledCheck);
    formLayout->addRow(QStringLiteral("PID 列表"), pidEdit);
    formLayout->addRow(QStringLiteral("关键字"), keywordEdit);
    formLayout->addRow(QStringLiteral("对象类型"), typeCombo);
    formLayout->addRow(QStringLiteral("差异状态"), diffCombo);
    formLayout->addRow(QStringLiteral("命名条件"), onlyNamedCheck);
    layout->addLayout(formLayout);

    auto* helpLabel = new QLabel(
        QStringLiteral("同一规则内的有效条件按 AND 匹配；启用规则之间按 OR 分组展示。"),
        &dialog);
    helpLabel->setWordWrap(true);
    helpLabel->setStyleSheet(
        QStringLiteral("color:%1;").arg(ksword_theme::textSecondaryHex()));
    layout->addWidget(helpLabel);

    auto* buttonBox = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel,
        &dialog);
    buttonBox->button(QDialogButtonBox::Ok)->setText(QStringLiteral("保存"));
    buttonBox->button(QDialogButtonBox::Cancel)->setText(QStringLiteral("取消"));
    connect(buttonBox, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    layout->addWidget(buttonBox);

    while (dialog.exec() == QDialog::Accepted)
    {
        const QString kRequestedName = nameEdit->text().trimmed();
        if (kRequestedName.isEmpty())
        {
            QMessageBox::warning(&dialog, QStringLiteral("规则名称"), QStringLiteral("规则名称不能为空。"));
            continue;
        }

        QString normalizedPidText = pidEdit->text();
        normalizedPidText.replace(',', ' ');
        normalizedPidText.replace(';', ' ');
        normalizedPidText.replace('\n', ' ');
        normalizedPidText.replace('\t', ' ');
        QVector<std::uint32_t> processIds;
        QSet<std::uint32_t> seenProcessIds;
        bool invalidPid = false;
        for (const QString& token : normalizedPidText.split(' ', Qt::SkipEmptyParts))
        {
            bool parseOk = false;
            const quint64 kValue = token.toULongLong(&parseOk, 10);
            if (!parseOk || kValue == 0 || kValue > std::numeric_limits<std::uint32_t>::max())
            {
                invalidPid = true;
                break;
            }
            const std::uint32_t kProcessId = static_cast<std::uint32_t>(kValue);
            if (!seenProcessIds.contains(kProcessId))
            {
                seenProcessIds.insert(kProcessId);
                processIds.push_back(kProcessId);
            }
        }
        if (invalidPid)
        {
            QMessageBox::warning(&dialog, QStringLiteral("PID 列表"), QStringLiteral("PID 列表包含无效值。"));
            continue;
        }

        ruleInOut->name = ks::handle::makeUniqueHandleFilterRuleName(
            kRequestedName,
            existingRules,
            ruleInOut->id);
        ruleInOut->enabled = enabledCheck->isChecked();
        ruleInOut->processIds = processIds;
        ruleInOut->keyword = keywordEdit->text().trimmed();
        const QString kSelectedType = typeCombo->currentText().trimmed();
        const bool kAllTypesSelected = typeCombo->currentIndex() == 0
            && kSelectedType == typeCombo->itemText(0).trimmed();
        ruleInOut->typeName = kAllTypesSelected
            ? QString()
            : kSelectedType;
        ruleInOut->diffStatus = static_cast<ks::handle::FilterDiffStatus>(
            diffCombo->currentData().toInt());
        ruleInOut->onlyNamed = onlyNamedCheck->isChecked();
        return true;
    }
    return false;
}

void HandleDock::showRuleManagerDialog(const QString& initiallySelectedRuleId)
{
    QDialog dialog(this);
    dialog.setWindowTitle(QStringLiteral("句柄筛选规则管理"));
    dialog.resize(760, 460);
    auto* rootLayout = new QVBoxLayout(&dialog);
    auto* contentLayout = new QHBoxLayout();
    auto* ruleList = new QListWidget(&dialog);
    ruleList->setContextMenuPolicy(Qt::CustomContextMenu);
    contentLayout->addWidget(ruleList, 1);

    auto* actionLayout = new QVBoxLayout();
    auto* newButton = new QPushButton(QStringLiteral("新建"), &dialog);
    auto* editButton = new QPushButton(QStringLiteral("编辑"), &dialog);
    auto* copyButton = new QPushButton(QStringLiteral("复制"), &dialog);
    auto* deleteButton = new QPushButton(QStringLiteral("删除"), &dialog);
    auto* toggleButton = new QPushButton(QStringLiteral("启用/停用"), &dialog);
    auto* moveUpButton = new QPushButton(QStringLiteral("上移"), &dialog);
    auto* moveDownButton = new QPushButton(QStringLiteral("下移"), &dialog);
    for (QPushButton* button : {
        newButton, editButton, copyButton, deleteButton,
        toggleButton, moveUpButton, moveDownButton })
    {
        actionLayout->addWidget(button);
    }
    actionLayout->addStretch(1);
    contentLayout->addLayout(actionLayout);
    rootLayout->addLayout(contentLayout, 1);

    QVector<ks::handle::HandleFilterRule> workingRules = filterDocument_.rules;
    std::function<void(int)> refreshRuleList =
        [this, ruleList, &workingRules, &refreshRuleList](const int selectedIndex)
        {
            const QSignalBlocker kListBlocker(ruleList);
            ruleList->clear();
            for (const ks::handle::HandleFilterRule& rule : workingRules)
            {
                auto* item = new QListWidgetItem(
                    ks::i18n::sourceText(QStringLiteral("%1  [%2]\n%3"))
                        .arg(rule.name)
                        .arg(rule.enabled
                            ? ks::i18n::sourceText(QStringLiteral("启用"))
                            : ks::i18n::sourceText(QStringLiteral("停用")))
                        .arg(buildRuleConditionSummary(rule)),
                    ruleList);
                item->setData(Qt::UserRole, rule.id);
            }
            if (!workingRules.isEmpty())
            {
                ruleList->setCurrentRow(std::clamp(
                    selectedIndex,
                    0,
                    static_cast<int>(workingRules.size()) - 1));
            }
        };

    int initialIndex = 0;
    for (qsizetype ruleIndex = 0; ruleIndex < workingRules.size(); ++ruleIndex)
    {
        if (workingRules.at(ruleIndex).id == initiallySelectedRuleId)
        {
            initialIndex = static_cast<int>(ruleIndex);
            break;
        }
    }
    refreshRuleList(initialIndex);

    connect(ruleList, &QListWidget::customContextMenuRequested, &dialog,
        [ruleList](const QPoint& point)
        {
            QListWidgetItem* item = ruleList->itemAt(point);
            if (item == nullptr)
            {
                return;
            }
            QMenu menu(ruleList);
            menu.setStyleSheet(ksword_theme::contextMenuStyle());
            QAction* copyAction = menu.addAction(QStringLiteral("复制"));
            if (menu.exec(ruleList->viewport()->mapToGlobal(point)) == copyAction)
            {
                QApplication::clipboard()->setText(item->text());
            }
        });

    connect(newButton, &QPushButton::clicked, &dialog,
        [this, ruleList, &workingRules, &refreshRuleList]()
        {
            ks::handle::HandleFilterRule rule;
            rule.id = ks::handle::createHandleFilterRuleId();
            rule.name = ks::handle::makeUniqueHandleFilterRuleName(
                ks::i18n::sourceText(QStringLiteral("规则 %1"))
                    .arg(workingRules.size() + 1),
                workingRules);
            if (showRuleEditorDialog(&rule, workingRules))
            {
                workingRules.push_back(std::move(rule));
                refreshRuleList(workingRules.size() - 1);
            }
        });
    const auto kEditCurrentRule =
        [this, ruleList, &workingRules, &refreshRuleList]()
        {
            const int kRow = ruleList->currentRow();
            if (kRow < 0 || kRow >= workingRules.size())
            {
                return;
            }
            ks::handle::HandleFilterRule editedRule = workingRules.at(kRow);
            if (showRuleEditorDialog(&editedRule, workingRules))
            {
                workingRules[kRow] = std::move(editedRule);
                refreshRuleList(kRow);
            }
        };
    connect(editButton, &QPushButton::clicked, &dialog, kEditCurrentRule);
    connect(ruleList, &QListWidget::itemDoubleClicked, &dialog,
        [kEditCurrentRule](QListWidgetItem*) { kEditCurrentRule(); });
    connect(copyButton, &QPushButton::clicked, &dialog,
        [this, ruleList, &workingRules, &refreshRuleList]()
        {
            const int kRow = ruleList->currentRow();
            if (kRow < 0 || kRow >= workingRules.size())
            {
                return;
            }
            ks::handle::HandleFilterRule copiedRule = workingRules.at(kRow);
            copiedRule.id = ks::handle::createHandleFilterRuleId();
            copiedRule.name = ks::handle::makeUniqueHandleFilterRuleName(
                copiedRule.name + ks::i18n::sourceText(QStringLiteral(" 副本")),
                workingRules);
            workingRules.insert(kRow + 1, std::move(copiedRule));
            refreshRuleList(kRow + 1);
        });
    connect(deleteButton, &QPushButton::clicked, &dialog,
        [ruleList, &workingRules, &refreshRuleList]()
        {
            const int kRow = ruleList->currentRow();
            if (kRow < 0 || kRow >= workingRules.size())
            {
                return;
            }
            workingRules.removeAt(kRow);
            refreshRuleList(std::min(
                kRow,
                static_cast<int>(workingRules.size()) - 1));
        });
    connect(toggleButton, &QPushButton::clicked, &dialog,
        [ruleList, &workingRules, &refreshRuleList]()
        {
            const int kRow = ruleList->currentRow();
            if (kRow < 0 || kRow >= workingRules.size())
            {
                return;
            }
            workingRules[kRow].enabled = !workingRules[kRow].enabled;
            refreshRuleList(kRow);
        });
    connect(moveUpButton, &QPushButton::clicked, &dialog,
        [ruleList, &workingRules, &refreshRuleList]()
        {
            const int kRow = ruleList->currentRow();
            if (kRow <= 0 || kRow >= workingRules.size())
            {
                return;
            }
            workingRules.swapItemsAt(kRow, kRow - 1);
            refreshRuleList(kRow - 1);
        });
    connect(moveDownButton, &QPushButton::clicked, &dialog,
        [ruleList, &workingRules, &refreshRuleList]()
        {
            const int kRow = ruleList->currentRow();
            if (kRow < 0 || kRow + 1 >= workingRules.size())
            {
                return;
            }
            workingRules.swapItemsAt(kRow, kRow + 1);
            refreshRuleList(kRow + 1);
        });

    auto* buttonBox = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel,
        &dialog);
    buttonBox->button(QDialogButtonBox::Ok)->setText(QStringLiteral("应用"));
    buttonBox->button(QDialogButtonBox::Cancel)->setText(QStringLiteral("取消"));
    connect(buttonBox, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    rootLayout->addWidget(buttonBox);

    if (dialog.exec() != QDialog::Accepted)
    {
        return;
    }
    filterDocument_.rules = std::move(workingRules);
    temporaryFilterActive_ = false;
    if (returnSavedFilterButton_ != nullptr)
    {
        returnSavedFilterButton_->setVisible(false);
    }
    saveFilterConfiguration();
    if (snapshotScopedToTemporarySinglePid_)
    {
        requestAsyncRefresh(true);
    }
    else
    {
        applyLocalHandleFilters(true);
    }
}

void HandleDock::importFilterConfiguration()
{
    const QString kFilePath = QFileDialog::getOpenFileName(
        this,
        ks::i18n::sourceText(QStringLiteral("导入句柄筛选配置")),
        QString(),
        ks::i18n::sourceText(QStringLiteral("JSON 配置 (*.json);;所有文件 (*)")));
    if (kFilePath.isEmpty())
    {
        return;
    }
    QFile sourceFile(kFilePath);
    if (!sourceFile.open(QIODevice::ReadOnly))
    {
        QMessageBox::warning(
            this,
            ks::i18n::sourceText(QStringLiteral("导入句柄筛选配置")),
            ks::i18n::sourceText(QStringLiteral("无法读取配置文件：%1"))
                .arg(sourceFile.errorString()));
        return;
    }

    ks::handle::HandleFilterDocument importedDocument;
    QStringList warningList;
    QString errorText;
    if (!ks::handle::deserializeHandleFilterDocument(
        sourceFile.readAll(),
        &importedDocument,
        &warningList,
        &errorText))
    {
        QMessageBox::warning(
            this,
            ks::i18n::sourceText(QStringLiteral("导入句柄筛选配置")),
            ks::i18n::sourceText(QStringLiteral("配置文件无效：%1"))
                .arg(ks::i18n::displayText(errorText)));
        return;
    }

    QMessageBox choiceBox(this);
    choiceBox.setWindowTitle(ks::i18n::sourceText(QStringLiteral("导入句柄筛选配置")));
    choiceBox.setText(ks::i18n::sourceText(QStringLiteral("选择配置导入方式。")));
    QPushButton* replaceButton = choiceBox.addButton(
        ks::i18n::sourceText(QStringLiteral("替换全部")), QMessageBox::AcceptRole);
    QPushButton* appendButton = choiceBox.addButton(
        ks::i18n::sourceText(QStringLiteral("追加导入")), QMessageBox::ActionRole);
    QPushButton* cancelButton = choiceBox.addButton(
        ks::i18n::sourceText(QStringLiteral("取消")), QMessageBox::RejectRole);
    choiceBox.setDefaultButton(replaceButton);
    choiceBox.setEscapeButton(cancelButton);
    choiceBox.exec();
    if (choiceBox.clickedButton() == cancelButton || choiceBox.clickedButton() == nullptr)
    {
        return;
    }

    const ks::handle::HandleFilterGlobalSettings kPreviousGlobalSettings =
        filterDocument_.globalSettings;
    if (choiceBox.clickedButton() == replaceButton)
    {
        filterDocument_ = std::move(importedDocument);
    }
    else if (choiceBox.clickedButton() == appendButton)
    {
        for (ks::handle::HandleFilterRule importedRule : importedDocument.rules)
        {
            importedRule.id = ks::handle::createHandleFilterRuleId();
            importedRule.name = ks::handle::makeUniqueHandleFilterRuleName(
                importedRule.name,
                filterDocument_.rules);
            filterDocument_.rules.push_back(std::move(importedRule));
        }
    }

    temporaryFilterActive_ = false;
    if (returnSavedFilterButton_ != nullptr)
    {
        returnSavedFilterButton_->setVisible(false);
    }
    applyFilterGlobalSettingsToControls();
    saveFilterConfiguration();
    const bool kGlobalSettingsChanged = !sameGlobalSettings(
        kPreviousGlobalSettings,
        filterDocument_.globalSettings);
    if (kGlobalSettingsChanged || snapshotScopedToTemporarySinglePid_)
    {
        requestAsyncRefresh(true);
    }
    else
    {
        applyLocalHandleFilters(true);
    }
    QStringList displayWarningList;
    displayWarningList.reserve(warningList.size());
    for (const QString& warningText : warningList)
    {
        displayWarningList.push_back(ks::i18n::displayText(warningText));
    }
    QMessageBox::information(
        this,
        ks::i18n::sourceText(QStringLiteral("导入句柄筛选配置")),
        displayWarningList.isEmpty()
            ? ks::i18n::sourceText(QStringLiteral("筛选配置已导入。"))
            : ks::i18n::sourceText(QStringLiteral("筛选配置已导入。\n%1"))
                .arg(displayWarningList.join('\n')));
}

void HandleDock::exportFilterConfiguration() const
{
    const QString kFilePath = QFileDialog::getSaveFileName(
        const_cast<HandleDock*>(this),
        ks::i18n::sourceText(QStringLiteral("导出句柄筛选配置")),
        ks::i18n::sourceText(QStringLiteral("句柄筛选配置.json")),
        ks::i18n::sourceText(QStringLiteral("JSON 配置 (*.json);;所有文件 (*)")));
    if (kFilePath.isEmpty())
    {
        return;
    }
    ks::handle::HandleFilterDocument exportDocument = filterDocument_;
    exportDocument.exportedAtUtc = QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);
    QString errorText;
    const QByteArray kJsonBytes =
        ks::handle::serializeHandleFilterDocument(exportDocument, &errorText);
    if (kJsonBytes.isEmpty())
    {
        QMessageBox::warning(
            const_cast<HandleDock*>(this),
            ks::i18n::sourceText(QStringLiteral("导出句柄筛选配置")),
            ks::i18n::displayText(errorText));
        return;
    }
    QSaveFile targetFile(kFilePath);
    if (!targetFile.open(QIODevice::WriteOnly)
        || targetFile.write(kJsonBytes) != kJsonBytes.size()
        || !targetFile.commit())
    {
        QMessageBox::warning(
            const_cast<HandleDock*>(this),
            ks::i18n::sourceText(QStringLiteral("导出句柄筛选配置")),
            ks::i18n::sourceText(QStringLiteral("配置文件写入失败：%1"))
                .arg(targetFile.errorString()));
        return;
    }
    QMessageBox::information(
        const_cast<HandleDock*>(this),
        ks::i18n::sourceText(QStringLiteral("导出句柄筛选配置")),
        ks::i18n::sourceText(QStringLiteral("筛选配置已导出。")));
}

void HandleDock::exportRuleResults(const QString& ruleId) const
{
    const QString kFilePath = QFileDialog::getSaveFileName(
        const_cast<HandleDock*>(this),
        ks::i18n::sourceText(QStringLiteral("导出句柄筛选结果")),
        ks::i18n::sourceText(QStringLiteral("句柄筛选结果.tsv")),
        ks::i18n::sourceText(QStringLiteral("TSV 文件 (*.tsv);;所有文件 (*)")));
    if (kFilePath.isEmpty())
    {
        return;
    }

    QSaveFile targetFile(kFilePath);
    if (!targetFile.open(QIODevice::WriteOnly))
    {
        QMessageBox::warning(
            const_cast<HandleDock*>(this),
            ks::i18n::sourceText(QStringLiteral("导出句柄筛选结果")),
            ks::i18n::sourceText(QStringLiteral("结果文件写入失败：%1"))
                .arg(targetFile.errorString()));
        return;
    }
    if (targetFile.write("\xEF\xBB\xBF", 3) != 3)
    {
        QMessageBox::warning(
            const_cast<HandleDock*>(this),
            ks::i18n::sourceText(QStringLiteral("导出句柄筛选结果")),
            ks::i18n::sourceText(QStringLiteral("结果文件写入失败：%1"))
                .arg(targetFile.errorString()));
        targetFile.cancelWriting();
        return;
    }
    const QStringList kHeaderList{
        ks::i18n::sourceText(QStringLiteral("规则名")),
        ks::i18n::sourceText(QStringLiteral("PID")),
        ks::i18n::sourceText(QStringLiteral("进程名")),
        ks::i18n::sourceText(QStringLiteral("句柄")),
        ks::i18n::sourceText(QStringLiteral("TypeIndex/类型")),
        ks::i18n::sourceText(QStringLiteral("对象名")),
        ks::i18n::sourceText(QStringLiteral("对象地址")),
        ks::i18n::sourceText(QStringLiteral("访问掩码")),
        ks::i18n::sourceText(QStringLiteral("属性")),
        ks::i18n::sourceText(QStringLiteral("HandleCount")),
        ks::i18n::sourceText(QStringLiteral("PointerCount")),
        ks::i18n::sourceText(QStringLiteral("来源")),
        ks::i18n::sourceText(QStringLiteral("解码状态")),
        ks::i18n::sourceText(QStringLiteral("差异"))
    };
    const QByteArray kHeaderBytes = (kHeaderList.join('\t') + '\n').toUtf8();
    if (targetFile.write(kHeaderBytes) != kHeaderBytes.size())
    {
        QMessageBox::warning(
            const_cast<HandleDock*>(this),
            ks::i18n::sourceText(QStringLiteral("导出句柄筛选结果")),
            ks::i18n::sourceText(QStringLiteral("结果文件写入失败：%1"))
                .arg(targetFile.errorString()));
        targetFile.cancelWriting();
        return;
    }

    std::size_t exportedRowCount = 0;
    for (const HandleRuleMatchState& state : ruleMatchStates_)
    {
        if (!state.enabled || (!ruleId.isEmpty() && state.ruleId != ruleId))
        {
            continue;
        }
        for (const std::size_t kSourceRowIndex : state.rowIndices)
        {
            if (kSourceRowIndex >= allRows_.size())
            {
                continue;
            }
            const HandleRow& row = allRows_[kSourceRowIndex];
            QStringList fieldList{
                state.ruleName,
                QString::number(row.processId),
                row.processName,
                formatHex(row.handleValue, 0),
                ks::i18n::displayText(formatTypeIndexDisplayText(row.typeIndex, row.typeName)),
                ks::i18n::displayText(formatObjectNameDisplayText(row)),
                formatHex(row.objectAddress, 0),
                formatHex(row.grantedAccess, 8),
                ks::i18n::displayText(formatHandleAttributes(row.attributes)),
                ks::i18n::displayText(formatOptionalObjectCount(row.handleCount, row.basicInfoAvailable)),
                ks::i18n::displayText(formatOptionalObjectCount(row.pointerCount, row.basicInfoAvailable)),
                ks::i18n::displayText(formatHandleSourceText(row.sourceMode)),
                ks::i18n::displayText(formatHandleDecodeStatusText(row.decodeStatus)),
                ks::i18n::displayText(formatHandleDiffStatusText(row.diffStatus))
            };
            for (QString& field : fieldList)
            {
                field = sanitizeTsvField(field);
            }
            const QByteArray kLineBytes = (fieldList.join('\t') + '\n').toUtf8();
            if (targetFile.write(kLineBytes) != kLineBytes.size())
            {
                QMessageBox::warning(
                    const_cast<HandleDock*>(this),
                    ks::i18n::sourceText(QStringLiteral("导出句柄筛选结果")),
                    ks::i18n::sourceText(QStringLiteral("结果文件写入失败：%1"))
                        .arg(targetFile.errorString()));
                targetFile.cancelWriting();
                return;
            }
            ++exportedRowCount;
        }
    }
    if (!targetFile.commit())
    {
        QMessageBox::warning(
            const_cast<HandleDock*>(this),
            ks::i18n::sourceText(QStringLiteral("导出句柄筛选结果")),
            ks::i18n::sourceText(QStringLiteral("结果文件提交失败：%1"))
                .arg(targetFile.errorString()));
        return;
    }
    QMessageBox::information(
        const_cast<HandleDock*>(this),
        ks::i18n::sourceText(QStringLiteral("导出句柄筛选结果")),
        ks::i18n::sourceText(QStringLiteral("已导出 %1 条命中结果。"))
            .arg(exportedRowCount));
}

void HandleDock::returnToSavedFilters()
{
    if (!temporaryFilterActive_)
    {
        return;
    }
    temporaryFilterActive_ = false;
    temporaryFilterRule_ = ks::handle::HandleFilterRule{};
    if (returnSavedFilterButton_ != nullptr)
    {
        returnSavedFilterButton_->setVisible(false);
    }
    if (snapshotScopedToTemporarySinglePid_)
    {
        requestAsyncRefresh(true);
    }
    else
    {
        applyLocalHandleFilters(true);
    }
}

void HandleDock::updateTypeFilterItems(const std::vector<QString>& availableTypeList)
{
    availableHandleTypeList_ = availableTypeList;
}

void HandleDock::refreshTypeFilterItemsFromAllRows()
{
    std::set<QString> typeNameSet;
    for (const HandleRow& row : allRows_)
    {
        if (!row.typeName.trimmed().isEmpty())
        {
            typeNameSet.insert(row.typeName);
        }
    }

    std::vector<QString> availableTypeList;
    availableTypeList.reserve(typeNameSet.size());
    for (const QString& typeNameText : typeNameSet)
    {
        availableTypeList.push_back(typeNameText);
    }
    updateTypeFilterItems(availableTypeList);
}

void HandleDock::syncHandleTypeNamesFromObjectTypeMap()
{
    if (allRows_.empty() || typeNameMapByIndexFromObjectTab_.empty())
    {
        if (handleRenderDeferredUntilTypeMap_ && !allRows_.empty())
        {
            // Object type snapshots may fail or return a null map. In this case, do not permanently suppress the handle list; instead,
            // fall back to rendering once using the type text from the enumeration phase to ensure the user still sees the refresh result.
            handleRenderDeferredUntilTypeMap_ = false;
            refreshTypeFilterItemsFromAllRows();
            applyLocalHandleFilters(true);
        }
        return;
    }

    // Object type mapping reached: Convert the current cache row to the final type name, then trigger the handle table render only once.
    for (HandleRow& row : allRows_)
    {
        const auto kFoundIt = typeNameMapByIndexFromObjectTab_.find(row.typeIndex);
        if (kFoundIt != typeNameMapByIndexFromObjectTab_.end() && !kFoundIt->second.empty())
        {
            row.typeName = QString::fromStdString(kFoundIt->second);
        }
    }
    refreshTypeFilterItemsFromAllRows();
    handleRenderDeferredUntilTypeMap_ = false;
    applyLocalHandleFilters();

    KLogEvent syncTypeNameEvent;
    info << syncTypeNameEvent
        << "[HandleDock] syncHandleTypeNamesFromObjectTypeMap: syncedRows="
        << allRows_.size()
        << ", mappedTypes="
        << typeNameMapByIndexFromObjectTab_.size()
        << eol;
}

void HandleDock::updateHandleStatusLabel(const QString& statusText, const bool refreshing)
{
    if (statusLabel_ == nullptr)
    {
        return;
    }
    statusLabel_->setText(statusText);
    if (refreshing)
    {
        statusLabel_->setStyleSheet(
            QStringLiteral("color:%1;font-weight:700;")
            .arg(ksword_theme::kPrimaryBlueHex));
        return;
    }

    const bool kHasDiagnostic =
        statusText.contains(QStringLiteral("失败")) ||
        statusText.contains(QStringLiteral("预算")) ||
        statusText.contains(QStringLiteral("异常")) ||
        statusText.contains(QStringLiteral("截断"));
    const QString kTextColor = kHasDiagnostic
        ? ksword_theme::warningColor().name(QColor::HexRgb)
        : ksword_theme::successColor().name(QColor::HexRgb);
    statusLabel_->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;")
        .arg(kTextColor));
}

void HandleDock::updateObjectTypeStatusLabel(const QString& statusText, const bool refreshing)
{
    if (objectTypeStatusLabel_ == nullptr)
    {
        return;
    }
    objectTypeStatusLabel_->setText(statusText);
    if (refreshing)
    {
        objectTypeStatusLabel_->setStyleSheet(
            QStringLiteral("color:%1;font-weight:700;")
            .arg(ksword_theme::kPrimaryBlueHex));
        return;
    }

    const bool kHasDiagnostic = statusText.contains(QStringLiteral("失败"));
    const QString kTextColor = kHasDiagnostic
        ? ksword_theme::warningColor().name(QColor::HexRgb)
        : ksword_theme::successColor().name(QColor::HexRgb);
    objectTypeStatusLabel_->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;")
        .arg(kTextColor));
}

void HandleDock::focusObjectTypeByIndex(const std::uint16_t typeIndex)
{
    if (tabWidget_ != nullptr && objectTypePage_ != nullptr)
    {
        tabWidget_->setCurrentWidget(objectTypePage_);
    }

    if (objectTypeRows_.empty() && !objectTypeRefreshInProgress_)
    {
        requestObjectTypeRefreshAsync(true);
        return;
    }

    if (objectTypeFilterEdit_ != nullptr)
    {
        objectTypeFilterEdit_->setText(QString::number(typeIndex));
    }

    for (int row = 0; row < objectTypeTable_->topLevelItemCount(); ++row)
    {
        QTreeWidgetItem* item = objectTypeTable_->topLevelItem(row);
        if (item == nullptr)
        {
            continue;
        }
        if (item->text(static_cast<int>(ObjectTypeTableColumn::kTypeIndex)).toUInt() == typeIndex)
        {
            objectTypeTable_->setCurrentItem(item);
            break;
        }
    }
}

void HandleDock::showHandleTableContextMenu(const QPoint& localPosition)
{
    QTreeWidgetItem* clickedItem = tableWidget_->itemAt(localPosition);
    if (clickedItem == nullptr)
    {
        return;
    }
    tableWidget_->setCurrentItem(clickedItem);

    QMenu menu(this);
    menu.setStyleSheet(ksword_theme::contextMenuStyle());
    QAction* copyCellAction = menu.addAction(QIcon(":/Icon/handle_copy.svg"), QStringLiteral("复制单元格"));
    QAction* copyRowAction = menu.addAction(QIcon(":/Icon/handle_copy_row.svg"), QStringLiteral("复制整行"));
    const auto kItemKind = static_cast<ks::handle::HandleTreeItemKind>(
        clickedItem->data(0, ks::handle::kHandleTreeItemKindRole).toInt());
    const QString kRuleId = clickedItem->data(0, ks::handle::kHandleTreeRuleIdRole).toString();

    QAction* loadMoreAction = nullptr;
    QAction* editRuleAction = nullptr;
    QAction* toggleRuleAction = nullptr;
    QAction* exportRuleAction = nullptr;
    QAction* openProcessAction = nullptr;
    QAction* gotoTypeAction = nullptr;
    QAction* refreshAction = nullptr;
    if (kItemKind == ks::handle::HandleTreeItemKind::kLoadMore)
    {
        menu.addSeparator();
        loadMoreAction = menu.addAction(QStringLiteral("加载下一批"));
    }
    else if (kItemKind == ks::handle::HandleTreeItemKind::kRuleSummary)
    {
        menu.addSeparator();
        editRuleAction = menu.addAction(QStringLiteral("编辑规则"));
        const ks::handle::HandleFilterRule* rule = findActiveRule(kRuleId);
        toggleRuleAction = menu.addAction(
            rule != nullptr && rule->enabled
                ? QStringLiteral("停用规则")
                : QStringLiteral("启用规则"));
        exportRuleAction = menu.addAction(QStringLiteral("导出该规则结果"));
    }
    else if (kItemKind == ks::handle::HandleTreeItemKind::kHandleRow)
    {
        menu.addSeparator();
        HandleRow* selectedRow = selectedHandleRow();
        openProcessAction = menu.addAction(
            QIcon(QStringLiteral(":/Icon/process_details.svg")),
            QStringLiteral("转到进程详细信息"));
        openProcessAction->setEnabled(selectedRow != nullptr && selectedRow->processId != 0U);
        gotoTypeAction = menu.addAction(QIcon(":/Icon/process_tree.svg"), QStringLiteral("转到对象类型"));
        refreshAction = menu.addAction(QIcon(":/Icon/handle_refresh.svg"), QStringLiteral("刷新"));
    }

    QAction* selectedAction = menu.exec(tableWidget_->viewport()->mapToGlobal(localPosition));
    if (selectedAction == nullptr)
    {
        return;
    }
    if (selectedAction == copyCellAction)
    {
        copyCurrentHandleCell();
        return;
    }
    if (selectedAction == copyRowAction)
    {
        copyCurrentHandleRow();
        return;
    }
    if (selectedAction == loadMoreAction)
    {
        appendNextRuleResultBatch(kRuleId);
        return;
    }
    if (selectedAction == editRuleAction)
    {
        if (temporaryFilterActive_ && temporaryFilterRule_.id == kRuleId)
        {
            ks::handle::HandleFilterRule editedRule = temporaryFilterRule_;
            if (showRuleEditorDialog(
                &editedRule,
                QVector<ks::handle::HandleFilterRule>{ temporaryFilterRule_ }))
            {
                temporaryFilterRule_ = std::move(editedRule);
                const bool kCachedSnapshotCannotServeEditedRule =
                    snapshotScopedToTemporarySinglePid_
                    && (temporaryFilterRule_.processIds.size() != 1
                        || temporaryFilterRule_.processIds.front() !=
                            snapshotScopedProcessId_);
                if (kCachedSnapshotCannotServeEditedRule)
                {
                    requestAsyncRefresh(true);
                }
                else
                {
                    applyLocalHandleFilters(true);
                }
            }
        }
        else
        {
            for (qsizetype ruleIndex = 0; ruleIndex < filterDocument_.rules.size(); ++ruleIndex)
            {
                if (filterDocument_.rules.at(ruleIndex).id != kRuleId)
                {
                    continue;
                }
                ks::handle::HandleFilterRule editedRule =
                    filterDocument_.rules.at(ruleIndex);
                if (showRuleEditorDialog(&editedRule, filterDocument_.rules))
                {
                    filterDocument_.rules[ruleIndex] = std::move(editedRule);
                    saveFilterConfiguration();
                    applyLocalHandleFilters(true);
                }
                break;
            }
        }
        return;
    }
    if (selectedAction == toggleRuleAction)
    {
        if (temporaryFilterActive_ && temporaryFilterRule_.id == kRuleId)
        {
            temporaryFilterRule_.enabled = !temporaryFilterRule_.enabled;
        }
        else
        {
            for (ks::handle::HandleFilterRule& rule : filterDocument_.rules)
            {
                if (rule.id == kRuleId)
                {
                    rule.enabled = !rule.enabled;
                    break;
                }
            }
            saveFilterConfiguration();
        }
        applyLocalHandleFilters(true);
        return;
    }
    if (selectedAction == exportRuleAction)
    {
        exportRuleResults(kRuleId);
        return;
    }
    if (selectedAction == openProcessAction)
    {
        HandleRow* selectedRow = selectedHandleRow();
        if (selectedRow != nullptr)
        {
            ks::ui::openProcessDetailByPid(selectedRow->processId);
        }
        return;
    }
    if (selectedAction == gotoTypeAction)
    {
        HandleRow* row = selectedHandleRow();
        if (row != nullptr)
        {
            focusObjectTypeByIndex(row->typeIndex);
        }
        return;
    }
    if (selectedAction == refreshAction)
    {
        requestAsyncRefresh(true);
    }
}
