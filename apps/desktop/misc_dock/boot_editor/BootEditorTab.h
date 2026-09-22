#pragma once

// ============================================================
// BootEditorTab.h
// Purpose:
// 1) Provides a visual editor for Windows BCD (Boot Configuration Data);
// 2) Supports enumeration, filtering, editing, copying, deletion, import/export, and one-time launch operations;
// 3) Provides a custom bcdedit command execution area and a raw output log area to cover advanced usage scenarios.
// ============================================================

#include "../../Framework.h"

#include <QMap>
#include <QWidget>

#include <vector>

class QCheckBox;
class QComboBox;
class QFormLayout;
class QGroupBox;
class QHBoxLayout;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QShowEvent;
class QSplitter;
class QSpinBox;
class QTableWidget;
class QTabWidget;
class QToolButton;
class QVBoxLayout;

class BootEditorTab final : public QWidget
{
    Q_OBJECT

public:
    // Constructor:
    // - Purpose: initialize only the Boot Editor UI and signal connections; perform no BCD enumeration.
    // - Parameter parent: Qt parent widget.
    // - Returns: nothing (constructor).
    explicit BootEditorTab(QWidget* parent = nullptr);
    ~BootEditorTab() override = default;

protected:
    // showEvent：
    // - Purpose: Queues the initial BCD enumeration only when the page becomes truly visible for the first time, avoiding triggering bcdedit immediately upon construction of the 'Misc' page.
    // - Parameter event: Qt show event.
    // - Returns: Nothing.
    void showEvent(QShowEvent* event) override;

private:
    // BcdEntry：
    // - Purpose: Describes a BCD entry (e.g., bootmgr, current loader, recovery entry, etc.).
    struct BcdEntry
    {
        QString objectTypeText;           // objectTypeText: Object type text (from bcdedit section headers).
        QString identifierText;           // identifierText: Object identifier (e.g., {bootmgr}/{current}/GUID).
        QMap<QString, QString> elementMap; // elementMap: A normalized key -> value field set.
        QString rawBlockText;             // rawBlockText: Raw block text of the object, for advanced troubleshooting.
        bool isBootManager = false;       // isBootManager: whether it is {bootmgr}.
        bool isCurrent = false;           // isCurrent: Indicates whether it is {current}.
        bool isDefault = false;           // isDefault: Whether it is the current default boot item.
    };

    // BcdCommandResult：
    // - Purpose: Consume individual bcdedit execution results and unify feedback to the UI and logs.
    struct BcdCommandResult
    {
        bool startSucceeded = false;  // startSucceeded: Whether the process started successfully.
        bool timeout = false;         // timeout: Whether the command has timed out.
        int exitCode = -1;            // exitCode: bcdedit process exit code.
        QString standardOutputText;   // standardOutputText: Standard output text.
        QString standardErrorText;    // standardErrorText: Standard error text.
        QString mergedOutputText;     // mergedOutputText: Merged text of stdout and stderr.
    };

private:
    // ===================== Initialization =====================
    void initializeUi();
    void initializeToolbar();
    void initializeCenterPane();
    void initializeConnections();

    // ===================== Data Refresh and Synchronization =====================
    void refreshBcdEntries();
    void rebuildEntryTable();
    void syncEditorFromSelection();
    void clearEditorForNoSelection();
    void updateStatusSummary();

    // ===================== Interaction actions =====================
    void applySelectedEntryChanges();
    void applyBootManagerChanges();
    void setLegacyBootForSelectedEntry();
    void setLegacyBootForDefaultEntry();
    void setStandardBootForSelectedEntry();
    void setSelectedAsDefaultEntry();
    void addSelectedToBootSequence();
    void createCopyFromSelectedEntry();
    void deleteSelectedEntry();
    void exportBcdStore();
    void importBcdStore();
    void executeCustomCommand();
    void copySelectedRowToClipboard();

    // ===================== Utility Functions =====================
    int currentEntryIndex() const;
    const BcdEntry* currentEntry() const;
    bool entryMatchesFilter(const BcdEntry& entry) const;
    QString readElementValue(const BcdEntry& entry, const QStringList& candidateKeyList) const;
    bool readElementBool(
        const BcdEntry& entry,
        const QStringList& candidateKeyList,
        bool defaultValue) const;
    void appendCommandLog(const QString& commandTitle, const BcdCommandResult& commandResult);
    BcdCommandResult runBcdEdit(
        const QStringList& argumentList,
        int timeoutMs,
        const QString& commandDescription);
    bool runBcdAndExpectSuccess(
        const QStringList& argumentList,
        const QString& operationText,
        bool showSuccessToast);
    bool applyBootMenuPolicyByIdentifier(
        const QString& identifierText,
        const QString& policyValueText,
        const QString& operationText);

    // ===================== Parsing Functions =====================
    static QString normalizeElementKey(const QString& rawKeyText);
    static std::vector<BcdEntry> parseBcdEnumOutput(const QString& enumOutputText);
    static QString boolToBcdOnOff(bool enabled);
    static QString boolToBcdYesNo(bool enabled);

private:
    // ===================== Top-level Layout =====================
    QVBoxLayout* rootLayout_ = nullptr;        // m_rootLayout: Boot page root layout.
    QWidget* toolbarWidget_ = nullptr;         // m_toolbarWidget: The top toolbar container.
    QHBoxLayout* toolbarLayout_ = nullptr;     // m_toolbarLayout: The top toolbar layout.
    QSplitter* mainSplitter_ = nullptr;        // m_mainSplitter: Vertical splitter separating the upper table from the lower edit area.
    QTableWidget* entryTable_ = nullptr;       // m_entryTable: BCD entry list table.
    QWidget* editorPane_ = nullptr;            // m_editorPane: Container for the three-column editing area below.
    QVBoxLayout* editorPaneLayout_ = nullptr;  // m_editorPaneLayout: Root layout for the three-column editor area below.

    // ===================== Top Toolbar Buttons =====================
    QToolButton* refreshButton_ = nullptr;      // m_refreshButton: BCD enumeration refresh button.
    QToolButton* exportButton_ = nullptr;       // m_exportButton: Export BCD store button.
    QToolButton* importButton_ = nullptr;       // m_importButton: Button to import BCD store.
    QToolButton* copyEntryButton_ = nullptr;    // m_copyEntryButton: Button to copy the current boot entry.
    QToolButton* deleteEntryButton_ = nullptr;  // m_deleteEntryButton: Button to delete the current boot entry.
    QToolButton* setDefaultButton_ = nullptr;   // m_setDefaultButton: Button to set as default boot item.
    QToolButton* bootOnceButton_ = nullptr;     // m_bootOnceButton: One-time boot (bootsequence) button.
    QToolButton* copyRowButton_ = nullptr;      // m_copyRowButton: Button to copy the summary information of the current row.
    QLineEdit* filterEdit_ = nullptr;           // m_filterEdit: Keyword filter input box.
    QLabel* adminHintLabel_ = nullptr;          // m_adminHintLabel: Administrator privilege hint label.

    // ===================== Basic Information Section =====================
    QLabel* identifierValueLabel_ = nullptr;   // m_identifierValueLabel: Display of the current item identifier.
    QLabel* typeValueLabel_ = nullptr;         // m_typeValueLabel: Current entry type display.
    QLineEdit* descriptionEdit_ = nullptr;     // m_descriptionEdit: Input field for the description field.
    QLineEdit* deviceEdit_ = nullptr;          // m_deviceEdit: Device field editor.
    QLineEdit* osDeviceEdit_ = nullptr;        // m_osDeviceEdit: OS device field editor.
    QLineEdit* pathEdit_ = nullptr;            // m_pathEdit: Path field editor.
    QLineEdit* systemRootEdit_ = nullptr;      // m_systemRootEdit: systemroot field editor.
    QLineEdit* localeEdit_ = nullptr;          // m_localeEdit: The locale field editor.
    QComboBox* bootMenuPolicyCombo_ = nullptr; // m_bootMenuPolicyCombo: bootmenupolicy option box.
    QSpinBox* timeoutSpin_ = nullptr;          // m_timeoutSpin: Configuration for bootmgr timeout.
    QLabel* legacyModeHintLabel_ = nullptr;    // m_legacyModeHintLabel: Legacy boot hint label.
    QPushButton* setLegacyForSelectedButton_ = nullptr; // m_setLegacyForSelectedButton: Enables Legacy/F8 for the current entry.
    QPushButton* setLegacyForDefaultButton_ = nullptr;  // m_setLegacyForDefaultButton: Enable Legacy/F8 for the default entry.
    QPushButton* setStandardForSelectedButton_ = nullptr; // m_setStandardForSelectedButton: Restores the Standard setting for the current entry.

    // ===================== Advanced Switches Section =====================
    QCheckBox* testSigningCheck_ = nullptr;       // m_testSigningCheck: testsigning switch.
    QCheckBox* noIntegrityCheck_ = nullptr;       // m_noIntegrityCheck: nointegritychecks switch.
    QCheckBox* debugCheck_ = nullptr;             // m_debugCheck: Debug switch.
    QCheckBox* bootLogCheck_ = nullptr;           // m_bootLogCheck: bootlog toggle.
    QCheckBox* baseVideoCheck_ = nullptr;         // m_baseVideoCheck: basevideo switch.
    QCheckBox* recoveryEnabledCheck_ = nullptr;   // m_recoveryEnabledCheck: recoveryenabled switch.
    QComboBox* safeBootCombo_ = nullptr;          // m_safeBootCombo: Safe boot mode selection box.

    // ===================== Action Area =====================
    QPushButton* applyEntryButton_ = nullptr;    // m_applyEntryButton: Button to apply modifications to the current entry.
    QPushButton* applyBootMgrButton_ = nullptr;  // m_applyBootMgrButton: Button to apply bootmgr parameters.
    QPushButton* reloadOneButton_ = nullptr;     // m_reloadOneButton: Button to reload the currently selected entry.

    // ===================== Custom Command Area =====================
    QLineEdit* customCommandEdit_ = nullptr;      // m_customCommandEdit: User-input bcdedit parameters.
    QPushButton* runCustomCommandButton_ = nullptr; // m_runCustomCommandButton: Button to execute a custom command.
    QPlainTextEdit* rawOutputEdit_ = nullptr;     // m_rawOutputEdit: Text box for raw output and command logs.
    QLabel* statusLabel_ = nullptr;               // m_statusLabel: Bottom status summary label.

    // ===================== Data Cache =====================
    std::vector<BcdEntry> entryList_;      // m_entryList: Cache of current BCD enumeration results.
    QString lastEnumRawText_;              // m_lastEnumRawText: Most recent complete raw enumeration text.
    QString defaultIdentifierText_;        // m_defaultIdentifierText: Cache for the current default boot entry identifier.

    // ===================== Initial Load Status =====================
    bool firstShowHandled_ = false;        // m_firstShowHandled: Whether the initial BCD enumeration has been queued upon first visibility.
};
