#pragma once

// ============================================================
// ApplicationControlPage.h
// Purpose:
// 1) Provide an 'Application Control' diagnostics and controlled editing page within MiscDock.
// 2) Aggregates AppLocker, WDAC / Code Integrity, Defender / ASR, platform security, event logs, and file diagnostics;
// 3) Supports viewing, copying, exporting, and editing confirmed AppLocker, WDAC, and Defender configurations.
// ============================================================

#include "../Framework.h"

#include <QWidget>

#include <cstdint>
#include <utility>
#include <vector>

class QLabel;
class QComboBox;
class QLineEdit;
class CodeEditorWidget;
class QPushButton;
class QTabWidget;
class QTableWidget;
class QVBoxLayout;
class QPoint;

namespace ks::misc
{
    // ApplicationControlPage：
    // - Input: Qt parent control;
    // - Processing: Asynchronously collect AppLocker / WDAC / Defender / Platform / CodeIntegrity / file diagnostic information.
    // - Output: Display diagnostic data via tables, status labels, and text boxes, and provide controlled configuration edit entry points.
    class ApplicationControlPage final : public QWidget
    {
    public:
        // Constructor:
        // - parent is the Qt parent widget;
        // - Create UI and immediately trigger a background refresh.
        explicit ApplicationControlPage(QWidget* parent = nullptr);

        // Destructor:
        // - The page manages controls using the Qt object tree.
        // - Background tasks use QPointer for back-casting, requiring no explicit cleanup.
        ~ApplicationControlPage() override = default;

    private:
        // AppLockerRuleRecord: Read-only display model for AppLocker rule rows.
        struct AppLockerRuleRecord
        {
            QString idText;             // idText: Unique rule ID, used for right-click editing and deletion.
            QString collectionText;     // collectionText: Display name of the rule collection.
            QString actionText;         // actionText：Allow / Deny。
            QString userText;           // userText: User or group text.
            QString sidText;            // sidText: Original SID value.
            QString conditionTypeText;  // conditionTypeText：Publisher / Path / Hash。
            QString conditionText;      // conditionText: path, publisher, or hash digest.
            QString descriptionText;    // descriptionText: Rule description.
            QString riskText;          // riskText: Risk label text.
        };

        // PolicyFileRecord: WDAC / Code Integrity policy file information.
        struct PolicyFileRecord
        {
            QString pathText;      // pathText: File path.
            QString existsText;    // existsText: whether it exists.
            QString sizeText;      // sizeText: file size.
            QString modifiedText;  // modifiedText: Modification time.
            QString countText;     // countText: Policy count / shard count.
            QString detailText;    // detailText: supplementary explanation.
        };

        // EventRecord: Code Integrity event log entry.
        struct EventRecord
        {
            QString timeText;      // timeText: Event timestamp.
            QString idText;        // idText: event ID.
            QString levelText;    // levelText: Event level.
            QString verdictText;  // verdictText: Allow/Block/Audit/Other.
            QString messageText;  // messageText: Summary message.
        };

        // KeyValueRecord: Defender/status class table row.
        struct KeyValueRecord
        {
            QString nameText;     // nameText: Field name.
            QString valueText;    // valueText: field value.
            QString detailText;   // detailText: supplementary explanation.
        };

    private:
        // initializeUi：
        // - Create the top toolbar and five sub-pages.
        // - No input parameters or return value.
        void initializeUi();

        // buildAppLockerPage：
        // - Build the AppLocker view page.
        // - Returns a new child widget with this page as its parent; the caller adds it to m_tabWidget.
        QWidget* buildAppLockerPage();

        // buildWdacPage：
        // - Constructs the WDAC / Code Integrity view page;
        // - Returns a new child widget with this page as its parent; the caller adds it to m_tabWidget.
        QWidget* buildWdacPage();

        // buildDefenderPage：
        // - Build the Defender / ASR view page;
        // - Returns a new child widget with this page as its parent; the caller adds it to m_tabWidget.
        QWidget* buildDefenderPage();

        // buildPlatformPage：
        // - Build read-only diagnostic pages for CI / VBS / Hyper-V / Driver Trust / BAM;
        // - Returns a new child widget with this page as its parent; the caller adds it to m_tabWidget.
        QWidget* buildPlatformPage();

        // buildEventLogPage：
        // - Build the event log page;
        // - Returns a new child widget with this page as its parent; the caller adds it to m_tabWidget.
        QWidget* buildEventLogPage();

        // buildFileDiagnosisPage：
        // - Build the file diagnosis page.
        // - Returns a new child widget with this page as its parent; the caller adds it to m_tabWidget.
        QWidget* buildFileDiagnosisPage();

        // editAppLockerPolicy：
        // - Read the local AppLocker XML policy, confirm in the editor, and write back in Replace mode.
        // - No input parameters or return value.
        void editAppLockerPolicy();

        // editWdacPolicy：
        // - Edits the user-selected WDAC source XML; optional compilation and deployment via CiTool.
        // - If sourcePath is empty, display a file selection dialog; otherwise, directly edit the specified path.
        // - No return value; returns immediately if a configuration write is already in progress to prevent re-entry.
        void editWdacPolicy(const QString& sourcePath = QString());

        // editDefenderSetting：
        // - Edits the currently selected supported configuration item in the Defender table.
        // - No input parameters or return value.
        void editDefenderSetting();

        // runPowerShellMutationAsync：
        // - Execute the configuration write script confirmed by the UI in the background, and refresh the page upon success.
        // - operationName is a user-readable operation name; scriptText is the script to be written.
        // - No return value.
        void runPowerShellMutationAsync(const QString& operationName, const QString& scriptText);

        // Right-click menus for three editable pages; global facilities automatically append copy and TSV export options.
        void showAppLockerContextMenu(const QPoint& localPosition);
        void showWdacContextMenu(const QPoint& localPosition);
        void showDefenderContextMenu(const QPoint& localPosition);

        // Operations for adding and removing AppLocker path rules, WDAC source XML, and Defender/ASR configurations.
        void addAppLockerRule();
        void editAppLockerRule(int row);
        void deleteAppLockerRule();
        void addWdacPolicy();
        void deleteWdacPolicy();
        void addDefenderAsrRule();
        void deleteDefenderSetting();

        // initializeTable：
        // - Sets unified read-only, row selection, and right-click menu behavior for the table;
        // - table is the target table; returns immediately if nullptr is passed.
        // - stretchLastColumn: Determines whether the last column absorbs the remaining width.
        // - No return value.
        void initializeTable(QTableWidget* table, bool stretchLastColumn = true);

        // refreshAsync：
        // - Collect diagnostic data for AppLocker, WDAC, Defender, and Event Log in the background.
        // - No return value; results are posted back to the UI thread.
        void refreshAsync();

        // applyRefreshResult：
        // - Apply background refresh results on the UI thread;
        // - refreshGeneration must equal the current generation; results from older tasks are discarded;
        // - No return value.
        void applyRefreshResult(
            std::uint64_t refreshGeneration,
            QString statusText,
            QString appLockerSummary,
            QString wdacSummary,
            QString defenderSummary,
            QString platformSummary,
            QString eventSummary,
            QVector<AppLockerRuleRecord> appLockerRules,
            QVector<PolicyFileRecord> policyFiles,
            QVector<EventRecord> events,
            QVector<KeyValueRecord> defenderRows,
            QVector<KeyValueRecord> platformRows);

        // runFileDiagnosisAsync：
        // - Perform read-only diagnosis on the input file path.
        // - No return value; results are posted back to the UI thread.
        void runFileDiagnosisAsync();

        // applyFileDiagnosisResult：
        // - Apply file diagnosis results on the UI thread;
        // - No return value.
        void applyFileDiagnosisResult(QString summaryText, QVector<KeyValueRecord> rows);

        // exportCurrentTableTsv：
        // - Export the main table of the currently active page as TSV;
        // - No return value; failure is indicated via a message box.
        void exportCurrentTableTsv();

        // currentExportTable：
        // - Get the export table corresponding to the currently active page.
        // - Returns nullptr if there is no exportable table on the current page.
        QTableWidget* currentExportTable() const;


        // tableToTsv：
        // - Export the entire table content as TSV text.
        // - When selectedOnly is true, only the currently selected rows are exported.
        // - Returns the TSV string.
        QString tableToTsv(QTableWidget* table, bool selectedOnly) const;

        // runPowerShellCaptureText：
        // - Execute scripts via powershell.exe within an asynchronous thread and capture standard output.
        // - scriptText is a PowerShell script;
        // - timeoutMs is the timeout duration.
        // - Returns the execution output; returns an empty string on failure with an optional error message.
        static QString runPowerShellCaptureText(const QString& scriptText, int timeoutMs, QString* errorTextOut);

        // parseAppLockerPolicyXml：
        // - Parse rules from the output of Get-AppLockerPolicy -Effective -Xml.
        // - xmlText is the XML text.
        // - Returns the parsing result and summary text.
        static std::pair<QVector<AppLockerRuleRecord>, QString> parseAppLockerPolicyXml(const QString& xmlText);

        // buildAppLockerRiskText：
        // - Generates risk markers based on AppLocker rules.
        // - Return multi-line risk text or an empty string.
        static QString buildAppLockerRiskText(
            const QString& actionText,
            const QString& sidText,
            const QString& conditionTypeText,
            const QString& conditionText);

        // parseEventsJson：
        // - Convert PowerShell JSON output into event table rows;
        // - jsonText is the raw JSON.
        // - Returns the event row and summary text.
        static std::pair<QVector<EventRecord>, QString> parseEventsJson(const QString& jsonText);

        // parseDefenderJson：
        // - Converts Defender PowerShell JSON output into key-value table rows.
        // - jsonText is the raw JSON.
        // - Returns the key-value table rows and summary text.
        static std::pair<QVector<KeyValueRecord>, QString> parseDefenderJson(const QString& jsonText);

        // rebuildEventTable：
        // - Input: Read current cached events and event category filter controls;
        // - Processing: Apply allow/block/audit/event filtering and rebuild the event table.
        // - Returns: Nothing.
        void rebuildEventTable();

        // selectedEventLimit：
        // - Input: event count dropdown;
        // - Processing: Convert UI text to the count used by PowerShell -MaxEvents.
        // - Returns: positive integer event limit.
        int selectedEventLimit() const;

        // buildPathMatchHint：
        // - Generate a potential hit hint for the specified path using the AppLocker rule snapshot provided by the caller.
        // - filePathText is the input path; appLockerRules is a read-only snapshot.
        // - Returns match summary.
        static QString buildPathMatchHint(
            const QString& filePathText,
            const QVector<AppLockerRuleRecord>& appLockerRules);

    private:
        QVBoxLayout* rootLayout_ = nullptr;        // m_rootLayout: Page root layout.
        QWidget* toolbarWidget_ = nullptr;         // m_toolbarWidget: The top toolbar container.
        QPushButton* refreshButton_ = nullptr;     // m_refreshButton: Refresh button.
        QPushButton* exportButton_ = nullptr;      // m_exportButton: Export button.
        QPushButton* appLockerEditButton_ = nullptr; // m_appLockerEditButton: AppLocker policy edit button.
        QPushButton* wdacEditButton_ = nullptr;      // m_wdacEditButton: Button to edit the WDAC source policy.
        QPushButton* defenderEditButton_ = nullptr;  // m_defenderEditButton: Defender configuration edit button.
        QLabel* statusLabel_ = nullptr;            // m_statusLabel: Overall status label.
        QTabWidget* tabWidget_ = nullptr;          // m_tabWidget: The main Tab containing five sub-pages.

        QWidget* appLockerPage_ = nullptr;         // m_appLockerPage: AppLocker page.
        QWidget* wdacPage_ = nullptr;              // m_wdacPage: WDAC / Code Integrity page.
        QWidget* defenderPage_ = nullptr;          // m_defenderPage: Defender / ASR page.
        QWidget* eventPage_ = nullptr;             // m_eventPage: Event log page.
        QWidget* fileDiagnosisPage_ = nullptr;      // m_fileDiagnosisPage: File diagnosis page.

        CodeEditorWidget* appLockerSummary_ = nullptr;   // m_appLockerSummary: AppLocker description text.
        QTableWidget* appLockerTable_ = nullptr;       // m_appLockerTable: AppLocker rules table.
        CodeEditorWidget* wdacSummary_ = nullptr;        // m_wdacSummary: WDAC description text.
        QTableWidget* policyFileTable_ = nullptr;      // m_policyFileTable: WDAC policy file table.
        QTableWidget* codeIntegrityEventTable_ = nullptr; // m_codeIntegrityEventTable: Code Integrity event table.
        CodeEditorWidget* defenderSummary_ = nullptr;    // m_defenderSummary: Defender status text.
        QTableWidget* defenderTable_ = nullptr;        // m_defenderTable: Defender registry key-value table.
        QWidget* platformPage_ = nullptr;              // m_platformPage: Platform security page.
        CodeEditorWidget* platformSummary_ = nullptr;    // m_platformSummary: Platform security status text.
        QTableWidget* platformTable_ = nullptr;        // m_platformTable: Platform security key-value table.
        CodeEditorWidget* eventSummary_ = nullptr;       // m_eventSummary: Event log text.
        QTableWidget* eventTable_ = nullptr;           // m_eventTable: Event table.
        QComboBox* eventVerdictFilterCombo_ = nullptr; // m_eventVerdictFilterCombo: Event category filter.
        QComboBox* eventLimitCombo_ = nullptr;         // m_eventLimitCombo: Event read count selector.
        QLineEdit* filePathEdit_ = nullptr;            // m_filePathEdit: File diagnostic input box.
        QPushButton* fileBrowseButton_ = nullptr;      // m_fileBrowseButton: Browse button.
        QPushButton* fileDiagnoseButton_ = nullptr;    // m_fileDiagnoseButton: Diagnosis button.
        CodeEditorWidget* fileDiagnosisSummary_ = nullptr; // m_fileDiagnosisSummary: File diagnosis description text.
        QTableWidget* fileDiagnosisTable_ = nullptr;   // m_fileDiagnosisTable: File diagnosis results table.

        QVector<AppLockerRuleRecord> appLockerRules_;  // m_appLockerRules: Snapshot of the most recent AppLocker rules.
        QVector<EventRecord> eventRows_;               // m_eventRows: Cache of the most recent complete event log.
        QVector<KeyValueRecord> platformRows_;         // m_platformRows: Cache of the most recent platform security diagnosis.
        std::uint64_t refreshGeneration_ = 0;           // m_refreshGeneration: Refresh generation maintained by the UI thread to prevent old results from being written back.
        int pendingMutationCount_ = 0;                  // m_pendingMutationCount: Number of configuration write tasks currently in progress.
        bool appLockerModuleAvailable_ = false;         // m_appLockerModuleAvailable: Whether the current system provides the AppLocker management module.
    };
}
