#pragma once

// ============================================================
// RegistryOptimizationPage.h
// Purpose:
// 1) Dynamically load Dism++ style registry optimization JSON from profiles/;
// 2) Build the System Optimization UI at runtime instead of hardcoding rows;
// 3) Apply selected registry/service/explorer actions with explicit confirmation.
// ============================================================

#include <QJsonObject>
#include <QString>
#include <QStringList>
#include <QVector>
#include <QWidget>

#include <cstdint>

class QLabel;
class QLineEdit;
class QPushButton;
class QProcess;
class QSplitter;
class QTableWidget;
class QTemporaryDir;
class QTreeWidget;
class QTimer;
class CodeEditorWidget;

// RegistryOptimizationPage:
// - Input: parent widget plus profiles/registry_optimization_items.json at runtime;
// - Processing: parses item/group/scope/state/action objects and creates controls per visible row;
// - Return behavior: QWidget subclass has no direct return value; status is surfaced in the UI.
class RegistryOptimizationPage final : public QWidget
{
public:
    // Constructor:
    // - Input parent: Qt parent widget owning this page;
    // - Processing: builds controls, wires signals, then loads the JSON profile;
    // - Return: no explicit return value.
    explicit RegistryOptimizationPage(QWidget* parent = nullptr);
    ~RegistryOptimizationPage() override;

private:
    // OptimizationState:
    // - Input: parsed from one JSON states[] object;
    // - Processing: stores label, detection condition, warning, and action list;
    // - Return: value object used by table controls.
    struct OptimizationState
    {
        QString tagText;
        QString labelText;
        QString conditionText;
        QString warningText;
        QVector<QJsonObject> actionList;
    };

    // OptimizationScope:
    // - Input: parsed from one JSON scopes[] object;
    // - Processing: groups state choices by Current/Default/System scope;
    // - Return: value object used by one table row.
    struct OptimizationScope
    {
        QString scopeText;
        QString conditionText;
        QVector<OptimizationState> stateList;
    };

    // OptimizationItem:
    // - Input: parsed from one top-level JSON item object;
    // - Processing: keeps item metadata and all scope definitions;
    // - Return: value object stored in m_itemList.
    struct OptimizationItem
    {
        int groupIndex = 0;
        int itemIndex = 0;
        QString groupNameText;
        QString itemNameText;
        QString itemTypeText;
        QString groupConditionText;
        QString itemConditionText;
        QString warningText;
        QVector<OptimizationScope> scopeList;
    };

    // VisibleRow:
    // - Input: item/scope indexes selected by current group/filter;
    // - Processing: maps QTableWidget rows back to parsed model objects;
    // - Return: lightweight row reference.
    struct VisibleRow
    {
        int itemIndex = -1;
        int scopeIndex = -1;
    };

private:
    // ColumnPreset：
    // - Purpose: Record the current A/B/custom column group used in the system optimization table;
    // - A: Operation view, B: Diagnostic view, Custom: User manually adjusts columns via the header menu.
    enum class ColumnPreset
    {
        kA,
        kB,
        kCustom
    };

private:
    void initializeUi();
    void initializeConnections();
    void loadOptimizationProfile();
    QStringList profileCandidatePaths() const;
    void rebuildGroupTree();
    void rebuildItemTable();
    void refreshVisibleStates();
    void refreshVisibleRowState(int tableRow);
    void cancelStateRefresh();
    void updateDetailPanel(int tableRow);
    void updateStatusText(const QString& text);
    void applyColumnPreset(ColumnPreset preset);
    void refreshColumnPresetButtonStyles();
    void showHeaderColumnMenu(const QPoint& localPos);
    bool isColumnVisibleInPreset(int columnIndex, ColumnPreset preset) const;

    const OptimizationState* selectedTargetStateForRow(int tableRow) const;
    const OptimizationState* detectedStateForScope(const OptimizationScope& scope) const;
    bool applyVisibleRow(int tableRow);
    void beginStateApply(int tableRow, const OptimizationItem& item, const OptimizationScope& scope, const OptimizationState& state);
    void continueStateApply();
    void finishStateApply();
    void cancelStateApply(const QString& reasonText = QString());
    void completePendingAction(bool actionOk, const QString& errorText);
    void setApplyControlsEnabled(bool enabled);
    bool startExternalAction(const QJsonObject& actionObject, QString* errorTextOut);
    static bool actionRequiresExternalProcess(const QJsonObject& actionObject);
    bool executeAction(
        const QJsonObject& actionObject,
        QStringList* detailLinesOut,
        bool* restartExplorerOut);

    bool executeRegistryWriteAction(const QJsonObject& actionObject, QString* errorTextOut);
    bool executeRegistryDeleteAction(const QJsonObject& actionObject, QString* errorTextOut);
    bool executeRegistryMoveAction(const QJsonObject& actionObject, QString* errorTextOut);
    bool executeServiceStartAction(const QJsonObject& actionObject, QString* errorTextOut);
    bool executeExplorerNotifyAction(const QJsonObject& actionObject, QString* errorTextOut);

    static bool evaluateConditionText(const QString& conditionText);

private:
    QPushButton* columnPresetAButton_ = nullptr; // Column group A button: default operation view.
    QPushButton* columnPresetBButton_ = nullptr; // Column B group button: Condition/warning diagnostic view.
    QLineEdit* filterEdit_ = nullptr;           // Free-text filter for group/item/scope names.
    QPushButton* reloadButton_ = nullptr;       // Reloads JSON from profiles at runtime.
    QPushButton* refreshStateButton_ = nullptr; // Re-evaluates visible row state conditions.
    QPushButton* cancelApplyButton_ = nullptr;  // Cancels the current external optimization action sequence.
    QTimer* filterDebounceTimer_ = nullptr;     // Debounce continuous filter inputs.
    QSplitter* splitter_ = nullptr;             // Left groups, right item list/details.
    QTreeWidget* groupTree_ = nullptr;          // Dynamic group tree from JSON group_name.
    QTableWidget* itemTable_ = nullptr;         // Dynamic option rows and per-row controls.
    CodeEditorWidget* detailText_ = nullptr;    // Read-only details for the selected item/action, supporting language switching and repainting.
    QLabel* statusLabel_ = nullptr;             // Profile load/apply status.

    QString loadedProfilePath_;                 // Actual JSON path selected from candidates.
    QVector<OptimizationItem> itemList_;        // Parsed top-level optimization items.
    QVector<VisibleRow> visibleRows_;           // Current table row to model mapping.
    ColumnPreset columnPreset_ = ColumnPreset::kA; // Current column group preset.
    bool rebuildingTable_ = false;              // Guards refresh signals during table rebuild.
    bool stateRefreshInProgress_ = false;       // Whether the background refresh of the visible state is still in progress.
    std::uint64_t stateRefreshGeneration_ = 0;  // Ignore expired background state results.
    bool stateApplyInProgress_ = false;         // Whether serial optimization actions are currently in progress.
    int stateApplyTableRow_ = -1;               // The table row corresponding to when the application starts.
    QString stateApplyItemName_;                // Name of the item being applied.
    QString stateApplyTargetLabel_;             // Target state name in the application.
    QVector<QJsonObject> stateApplyActions_;    // Actions to be executed while preserving the original JSON order.
    int stateApplyNextActionIndex_ = 0;         // Index of the next action to be executed.
    QJsonObject stateApplyActiveAction_;        // Current asynchronous external action.
    QStringList stateApplyDetailLines_;         // Diagnostic information for the current action sequence.
    bool stateApplyAllOk_ = true;               // Whether all completed actions were successful.
    bool stateApplyRestartExplorer_ = false;    // Whether to prompt for an Explorer restart.
    QProcess* stateApplyProcess_ = nullptr;     // Holds only the current non-blocking cmd/tar subprocess.
    QTemporaryDir* stateApplyTemporaryDir_ = nullptr; // Retain the temporary directory during FileCreateByZIP extraction.
    QString stateApplyZipDestinationPath_;      // Final destination path for FileCreateByZIP.
};
