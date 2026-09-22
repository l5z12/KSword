#pragma once

// ============================================================
// RenderBenchmarkPage.h
// Purpose:
// 1) Provides an entry point for window rendering and DWM composition benchmarking under 'Misc';
// 2) Quantify the real cost of a full tree repaint in the main window once, and separate the proportions of the background layer and the child control tree.
// 3) Use an isomorphic off-screen window to simulate dragging, comparing frame drop rates between "redrawing the entire tree on refresh" and "no redraw".
// 4) Capture screen sampling to verify if local acrylic is actually effective and whether it resamples according to window position changes;
// 5) Use WM_NULL round-trip probing to detect UI thread stalls in any target window during movement.
// Design notes:
// - All measurements are executed on the UI thread: the object under test is the UI thread itself, and it cannot be measured if placed in a background thread;
//   Therefore, each test briefly occupies the UI; disable buttons and display status during execution.
// - The main window item is rendered to an off-screen bitmap using QWidget::render, avoiding touching real screen
//   pixels. This captures rendering time comparable to a real redraw while preventing UI flicker for the user.
// - Conclusions may vary with Windows versions (especially regarding undocumented ACCENT_POLICY
//   behavior), so only report locally measured values here, without hardcoding any 'expected' judgments.
// ============================================================

#include "../../Framework.h"

#include <QString>
#include <QVector>
#include <QWidget>

class QComboBox;
class QLabel;
class QPlainTextEdit;
class QProgressBar;
class QPushButton;
class QSpinBox;

namespace ks::misc
{
    // BenchmarkSampleSummary:
    // - Aggregates a set of latency samples; all four tests share the same statistical methodology;
    // - overBudgetCount is based on a 60fps frame budget (16.7ms) and directly corresponds to frame drops.
    struct BenchmarkSampleSummary
    {
        double averageMs = 0.0;   // averageMs: Sample average duration.
        double p95Ms = 0.0;       // p95Ms: 95th percentile latency, which better reflects perceived stutter than the average.
        double worstMs = 0.0;     // worstMs: Worst single execution time.
        int overBudgetCount = 0;  // overBudgetCount: Number of samples exceeding the frame budget.
        int sampleCount = 0;      // sampleCount: Total number of valid samples.
    };

    // TargetWindowEntry:
    // - Candidate target windows responding to the probe;
    // - Stores the HWND value instead of a pointer to avoid dangling references after the window is destroyed.
    struct TargetWindowEntry
    {
        quint64 windowHandleValue = 0; // windowHandleValue: Integer representation of the target window handle.
        QString displayText;           // displayText: "Title - Process Name (PID)" used for the dropdown display.
        bool belongsToSelf = false;    // belongsToSelf: whether it is the current process window; selected by default.
    };

    class RenderBenchmarkPage final : public QWidget
    {
    public:
        // Constructor: creates the UI only, without automatically running any tests.
        // - Benchmarks occupy the UI thread for several seconds and must be explicitly initiated by the user.
        // - Parameter parent: Qt parent widget.
        explicit RenderBenchmarkPage(QWidget* parent = nullptr);
        ~RenderBenchmarkPage() override = default;

    private:
        // initializeUi: Creates the description, four test groups, and the report area.
        void initializeUi();
        // initializeConnections: Connect test buttons to the report area actions.
        void initializeConnections();

        // runMainWindowRepaintBenchmark：
        // - Measure the time taken for a full tree repaint of the main window root container, and isolate the portion involving only the background layer.
        // - Uses off-screen rendering to avoid affecting the actual on-screen interface.
        void runMainWindowRepaintBenchmark();

        // runDragSimulationBenchmark：
        // - Create a test window isomorphic to the main window (transparent + frosted + full-screen transparent table),
        //   simulate 60fps dragging, and compare the strategies of 'redrawing the entire tree on every refresh' vs. 'no redraw'.
        void runDragSimulationBenchmark();

        // runCompositionProbe：
        // - Place two solid-color panels as the background, move the frosted window between them, capture the screen, and calculate the average color.
        // - Determine if acrylic is actually active and whether it automatically re-samples based on window position changes.
        void runCompositionProbe();

        // runWindowResponseProbe：
        // - Continuously call SetWindowPos on the selected target window to simulate dragging;
        //   measure the duration the window's UI thread is blocked per frame using WM_NULL round-trips.
        // - Return the window to its original position after testing.
        void runWindowResponseProbe();

        // runAllBenchmarks: Run all four benchmarks sequentially while keeping the UI responsive in between.
        void runAllBenchmarks();

        // refreshTargetWindowList: enumerate currently visible top-level windows and populate the target dropdown for probes.
        void refreshTargetWindowList();

        // appendReportLine / appendReportSection: writes results into the report section.
        void appendReportLine(const QString& lineText);
        void appendReportSection(const QString& titleText);

        // appendSummaryLine: Outputs statistics for a set of samples in a unified format.
        void appendSummaryLine(const QString& labelText, const BenchmarkSampleSummary& summary);

        // setBusy: Disable all trigger buttons during testing to prevent reentrancy.
        void setBusy(bool busy, const QString& statusText = QString());

        // copyReportToClipboard / saveReportToFile: Report export.
        void copyReportToClipboard();
        void saveReportToFile();

    private:
        QLabel* statusLabel_ = nullptr;              // m_statusLabel: Current running status and prompt.
        QPushButton* runAllButton_ = nullptr;        // m_runAllButton: Executes all tests sequentially.
        QPushButton* runRepaintButton_ = nullptr;    // m_runRepaintButton: Main window repaint benchmark.
        QPushButton* runDragButton_ = nullptr;       // m_runDragButton: Drag to compare A/B.
        QPushButton* runCompositionButton_ = nullptr;// m_runCompositionButton: DWM composition capability detection.
        QPushButton* runResponseButton_ = nullptr;   // m_runResponseButton: Target window response probe button.
        QPushButton* refreshTargetsButton_ = nullptr;// m_refreshTargetsButton: Re-enumerate candidate windows.
        QPushButton* copyReportButton_ = nullptr;    // m_copyReportButton: Copy report.
        QPushButton* saveReportButton_ = nullptr;    // m_saveReportButton: Exports the report.
        QPushButton* clearReportButton_ = nullptr;   // m_clearReportButton: Clear report.

        QSpinBox* repaintIterationSpin_ = nullptr;   // m_repaintIterationSpin: Number of samples for the repaint benchmark.
        QSpinBox* dragFrameSpin_ = nullptr;          // m_dragFrameSpin: Number of frames for drag simulation.
        QSpinBox* dragRowSpin_ = nullptr;            // m_dragRowSpin: Number of table rows in the test window.
        QSpinBox* responseFrameSpin_ = nullptr;      // m_responseFrameSpin: Response probe frame count.
        QComboBox* targetWindowCombo_ = nullptr;     // m_targetWindowCombo: Target window for the response probe.

        QProgressBar* progressBar_ = nullptr;        // m_progressBar: Progress indicator for long-running tests.
        QPlainTextEdit* reportEdit_ = nullptr;       // m_reportEdit: Result report area.

        QVector<TargetWindowEntry> targetWindows_;   // m_targetWindows: Snapshot of candidate target windows.
        bool busy_ = false;                          // m_busy: Whether a test is currently executing.
        // m_batchRunning: Whether currently in the 'Run All Tests' batch.
        // When a single test ends, the busy state is cleared. Without explicitly tracking batch status, the brief window between tests
        // where release events are allowed would make the button clickable again, enabling users to trigger the second test prematurely.
        bool batchRunning_ = false;
    };
}
