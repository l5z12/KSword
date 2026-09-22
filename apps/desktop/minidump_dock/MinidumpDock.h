#pragma once

// ============================================================
// MinidumpDock.h
// Purpose:
// - Provides the 'Dump Analysis' page: opens and parses Windows dump files.
// - Support user-mode MDMP minidumps (application crash dumps) and kernel
//   PAGEDUMP/PAGEDU64 dumps (BSOD DMPs, including small dumps in C:\Windows\Minidump).
// - Display diagnostic conclusions, candidate faulting modules, overview, exception/stop codes, call stacks, registers,
//   stream directories, modules/drivers, threads, memory, raw memory preview, handles, unloaded modules, and full reports.
//   Parsing executes in a thread pool to avoid blocking the UI.
// Call method:
// - mainWindow lazily creates this control when dockKey is "minidump";
// - Automatically parse after the user selects a file via the toolbar; re-parse on Enter or clicking the Parse button.
// ============================================================

#include <QString>
#include <QStringList>
#include <QWidget>

#include <atomic>
#include <cstdint>
#include <memory>

class CodeEditorWidget;
class QEvent;
class QLabel;
class QLineEdit;
class QPushButton;
class QTabWidget;
class QTableWidget;
class QTextBrowser;
class DumpMemoryView;
struct MinidumpAsyncState;

namespace ks::minidump
{
    struct DumpParseResult;
}

// MinidumpDock: root control for the dump analysis page; manages the toolbar, status bar, and result tabs.
class MinidumpDock final : public QWidget
{
public:
    // Constructor purpose: initialize the interface and enter the 'waiting for dump file selection' state.
    // Parameter parent: Qt parent widget; return value: none.
    explicit MinidumpDock(QWidget* parent = nullptr);

    // Destructor: Invalidates asynchronous parse results that have not yet returned to the UI thread.
    ~MinidumpDock() override;

    // openDumpFile: Action to specify a dump file externally and immediately begin parsing.
    // Parameter filePath: full path to the dump file; Return value: none.
    // Called by the mainWindow's "New Dump Found" confirmation dialog after user confirmation.
    void openDumpFile(const QString& filePath);

protected:
    // changeEvent: Re-translate fixed controls and re-render existing parsed results when the language is switched.
    // Parameter event: Qt event; Return value: None.
    void changeEvent(QEvent* event) override;

private:
    // The following functions are responsible for building/translating the UI, selecting files, and starting asynchronous parsing and report export.
    void buildUi();
    void retranslateUi();
    void chooseFile();
    void beginParse();
    void exportReport();

    // finishParse: Accept only the background parse result for the current generation and update the UI.
    // generation: Task generation; result: Self-contained parse result.
    void finishParse(
        std::uint64_t generation,
        std::shared_ptr<ks::minidump::DumpParseResult> result);

    // renderResult: Renders the parse result into tabs for overview, exceptions, streams, modules, etc.
    // Parameter result: Parse result; return value: none. Implementation is located in MinidumpDock.Tables.cpp.
    void renderResult(const ks::minidump::DumpParseResult& result);

    // promptKswordRelatedCrash: When the parse result points to a KSword component, guide the user to report the crash.
    // Parameter result: Parse result; Return value: None.
    // Only prompt when a culprit candidate/call stack/unloaded table is hit—only appearing in the loaded
    // module table does not constitute evidence; it must be in the table during KSword execution.
    void promptKswordRelatedCrash(const ks::minidump::DumpParseResult& result);

    // clearResultTabs: Removes all result tabs (controls are reused, not destroyed).
    void clearResultTabs();

    // createReadOnlyTable: Creates a uniformly styled read-only table; the caller is responsible for populating it.
    // Parameter parent: parent widget; Return value: new table. Implementation is in MinidumpDock.Tables.cpp.
    QTableWidget* createReadOnlyTable(QWidget* parent = nullptr) const;

    // createStructuredTablePage purpose: Establish complementary A/B/C column group presets and a header right-click menu for
    // toggling column visibility per column for wide tables; return the original table directly if it has 5 or fewer columns.
    // Parameter table: target table; columnCount: number of columns; Return value: wrapped page control.
    QWidget* createStructuredTablePage(QTableWidget* table, int columnCount) const;

    // buildReportText: Assemble the parsing result into a full report (in Chinese standard text).
    // Parameter result: parse result; Return value: report text. Implementation is located in MinidumpDock.Tables.cpp.
    QString buildReportText(const ks::minidump::DumpParseResult& result) const;

    // The following helper functions unify localization and status bar handling.
    QString translated(const char* key, const char* fallback) const;
    void setStatus(const char* key, const char* fallback, const QStringList& arguments = {});
    void refreshStatus();
    void setBusy(bool busy);

    QLabel* pathLabel_ = nullptr;      // m_pathLabel: Target path field title.
    QLineEdit* pathEdit_ = nullptr;    // m_pathEdit: Current dump file path.
    QLabel* symbolPathLabel_ = nullptr;   // m_symbolPathLabel: Symbol path field title.
    QLineEdit* symbolPathEdit_ = nullptr; // m_symbolPathEdit: symbol search path; empty uses local default path.
    QPushButton* browseButton_ = nullptr;   // m_browseButton: File browser button.
    QPushButton* systemDirButton_ = nullptr; // m_systemDirButton: Locate the system blue screen dump directory.
    QPushButton* parseButton_ = nullptr;    // m_parseButton: Start parsing.
    QPushButton* exportButton_ = nullptr;   // m_exportButton: Export full report button.
    QLabel* statusLabel_ = nullptr;    // m_statusLabel: Display the current task and final result.

    QTabWidget* resultTabs_ = nullptr; // m_resultTabs: Container for parsing result tabs.
    // m_analysisView: Diagnosis conclusion page.
    // We deliberately avoid using a table here: the conclusion follows a narrative structure of 'one-sentence judgment + evidence chain + recommendation'. Placing
    // this into a 'Project-Content' two-column format would force every piece of evidence to repeat the word 'found', burying the key conclusion within the rows.
    QTextBrowser* analysisView_ = nullptr;
    QTableWidget* blameTable_ = nullptr;     // m_blameTable: Candidate table for the responsible module.
    QTableWidget* stackTable_ = nullptr;     // m_stackTable: Suspected call stack table.
    QTableWidget* registerTable_ = nullptr;  // m_registerTable: Crash point register table.
    QTableWidget* overviewTable_ = nullptr;  // m_overviewTable: Overview 'property-value' table.
    QTableWidget* exceptionTable_ = nullptr; // m_exceptionTable: Exception/stop code details table.
    QTableWidget* executionContextTable_ = nullptr; // m_executionContextTable: Table for crash context CPU/thread/process snapshots.
    QTableWidget* streamTable_ = nullptr;    // m_streamTable: Stream directory / TRIAGE layout table.
    QTableWidget* moduleTable_ = nullptr;    // m_moduleTable: Module/Driver table.
    QTableWidget* threadTable_ = nullptr;    // m_threadTable: Thread table.
    QTableWidget* memoryTable_ = nullptr;    // m_memoryTable: Memory region table.
    QTableWidget* handleTable_ = nullptr;    // m_handleTable: Handle table.
    QTableWidget* unloadedTable_ = nullptr;  // m_unloadedTable: Table for unloaded modules.
    QTableWidget* symbolTable_ = nullptr;    // m_symbolTable: Per-module symbol match status table.
    QTableWidget* poolTagTable_ = nullptr;   // m_poolTagTable: Pool tag candidates and ownership table.
    QTableWidget* crashHistoryTable_ = nullptr; // m_crashHistoryTable: System crash timeline table.
    QWidget* stackPage_ = nullptr;     // m_stackPage: A/B/C wrapper pages for the call stack table.
    QWidget* modulePage_ = nullptr;    // m_modulePage: Module table A/B/C wrapper page.
    QWidget* threadPage_ = nullptr;    // m_threadPage: A/B/C wrapper pages for the thread table.
    QWidget* memoryPage_ = nullptr;    // m_memoryPage: Memory table A/B/C wrapper page.
    QWidget* handlePage_ = nullptr;    // m_handlePage: A/B/C wrapper page for the handle table.
    CodeEditorWidget* rawMemoryEditor_ = nullptr; // m_rawMemoryEditor: Read-only hex preview of validated TRIAGE data blocks.
    DumpMemoryView* memoryView_ = nullptr; // m_memoryView: Read-only memory viewer for reopening a DMP file by virtual address.
    CodeEditorWidget* reportEditor_ = nullptr; // m_reportEditor: Read-only editor for the full report.

    std::shared_ptr<ks::minidump::DumpParseResult> lastResult_; // m_lastResult: The most recent result for repainting during language switching.
    QString statusKey_;        // m_statusKey: Language pack key for the current status.
    QString statusFallback_;   // m_statusFallback: Chinese text used when language packs are missing.
    QStringList statusArguments_; // m_statusArguments: Placeholders in the status text replaced in order.
    std::atomic<std::uint64_t> parseGeneration_{ 0 }; // m_parseGeneration: Evicts expired parse callbacks.
    std::shared_ptr<MinidumpAsyncState> asyncState_; // m_asyncState: Protects the owner's lifetime during cross-thread dispatch.
    bool parseBusy_ = false;   // m_parseBusy: Whether the parsing task is running.
};
