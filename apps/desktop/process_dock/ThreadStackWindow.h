#pragma once

// ============================================================
// ThreadStackWindow.h
// Purpose:
// - Provides a standalone Phase-8 "Thread Call Stack" window;
// - Capture user-mode stack frames in R3 and resolve modules/symbols;
// - R0 only provides KTHREAD stack boundary assistance for diagnostics and does not use kernel addresses as operational credentials.
// ============================================================

#include "../Framework.h"

#include <QDialog>

#include <cstdint>
#include <vector>

class QLabel;
class QPushButton;
class QTreeWidget;
class QVBoxLayout;
class QHBoxLayout;

// ThreadStackTarget:
// - Describe a thread whose call stack is to be captured.
// - Both ProcessDock and ProcessDetailWindow can construct this structure to open the window.
struct ThreadStackTarget
{
    std::uint32_t processId = 0;        // Target process PID.
    std::uint32_t threadId = 0;         // Target thread TID.
    QString processName;                // Process name, display only.
    QString processPath;                // Process path, for display and symbol assistance only.
    std::uint64_t startAddress = 0;     // Thread start address, display only.
    std::uint64_t win32StartAddress = 0;// Win32StartAddress, display only.
    std::uint64_t tebBaseAddress = 0;   // TEB address; if missing, the window attempts to re-query.
    std::uint64_t userStackBase = 0;    // User stack base; if missing, the window attempts to read from the TEB.
    std::uint64_t userStackLimit = 0;   // User stack limit; if missing, the window attempts to read from the TEB.
    std::uint64_t r0KernelStack = 0;    // KTHREAD.KernelStack。
    std::uint64_t r0StackBase = 0;      // KTHREAD.StackBase。
    std::uint64_t r0StackLimit = 0;     // KTHREAD.StackLimit。
    std::uint64_t r0InitialStack = 0;   // KTHREAD.InitialStack。
    std::uint32_t r0ThreadStatus = 0;   // R0 thread extended status.
    std::uint64_t r0CapabilityMask = 0; // R0 DynData capability。
};

class ThreadStackWindow final : public QDialog
{
public:
    // Constructor purpose:
    // - Accept thread target information;
    // initialize the UI
    // - Automatically initiate a call stack capture.
    // Parameter target: Target thread.
    // Parameter parent: Qt parent object.
    explicit ThreadStackWindow(const ThreadStackTarget& target, QWidget* parent = nullptr);

    struct StackFrameRow
    {
        std::uint32_t index = 0;      // Frame index.
        std::uint64_t address = 0;    // Instruction address.
        QString moduleName;           // Module name.
        QString symbolName;           // Symbol name.
        std::uint64_t displacement = 0;// Symbol offset.
        QString modeText;             // User/Kernel boundary/Unavailable。
    };

    struct CaptureResult
    {
        std::vector<StackFrameRow> frames; // Captured stack frames.
        ThreadStackTarget enrichedTarget;  // Enriched target diagnostic fields.
        QString diagnosticText;            // Failure or downgrade diagnosis.
        std::uint64_t elapsedMs = 0;       // Capture duration.
        bool ok = false;                   // Whether at least one frame was successfully captured.
    };

    enum class StackColumn
    {
        kIndex = 0,
        kAddress,
        kModule,
        kSymbol,
        kOffset,
        kMode,
        kCount
    };

private:
    // initializeUi purpose: Create the top status, buttons, and stack frame table.
    void initializeUi();
    // initializeConnections purpose: Bind refresh and copy actions.
    void initializeConnections();
    // requestAsyncCapture: Captures stack traces in a thread pool to avoid blocking the UI.
    void requestAsyncCapture(bool forceRefresh);
    // applyCaptureResult: Fills in the capture results on the UI thread.
    void applyCaptureResult(std::uint64_t ticket, const CaptureResult& result);
    // rebuildFrameTable purpose: Rebuild the table based on m_frames.
    void rebuildFrameTable();
    // updateBoundaryText purpose: Refresh user stack/R0 stack boundary diagnostic labels.
    void updateBoundaryText();
    // copyAllFrames action: Copies all stack frames as TSV.
    void copyAllFrames();
    // copyCurrentFrame: Copies the current stack frame.
    void copyCurrentFrame();
    // showFrameContextMenu purpose: Display the table's right-click context menu.
    void showFrameContextMenu(const QPoint& localPosition);
    // resizeEvent purpose: Reallocate column widths after window size changes.
    void resizeEvent(QResizeEvent* event) override;
    // applyAdaptiveColumnWidths: Sets the table column widths.
    void applyAdaptiveColumnWidths();

private:
    ThreadStackTarget target_;             // Current target thread.
    std::vector<StackFrameRow> frames_;    // Current stack frame cache.

    QVBoxLayout* rootLayout_ = nullptr;    // Root layout.
    QHBoxLayout* toolbarLayout_ = nullptr; // Top button layout.
    QPushButton* refreshButton_ = nullptr; // Refresh button.
    QPushButton* copyButton_ = nullptr;    // Copy button.
    QLabel* targetLabel_ = nullptr;        // Target thread summary.
    QLabel* boundaryLabel_ = nullptr;      // Stack boundary summary.
    QLabel* statusLabel_ = nullptr;        // Capture status.
    QTreeWidget* frameTable_ = nullptr;    // Stack frame table.

    bool captureInProgress_ = false;       // Capture-in-progress flag.
    bool capturePending_ = false;          // Capture pending flag.
    std::uint64_t captureTicket_ = 0;      // Capture sequence number.
    int captureProgressPid_ = 0;           // kPro task ID.
};
