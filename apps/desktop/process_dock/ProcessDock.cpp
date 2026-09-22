#include "ProcessDock.Support.h"
#include "ProcessActivityChartWidget.h"
#include "ProcessActivityTimelineSlider.h"

using namespace ksword::ui::process_dock;

ProcessDock::ProcessDock(QWidget* parent)
    : QWidget(parent)
{
    mainWindowActionReceiver_ = parent;

    // Processor Group awareness: ALL_PROCESSOR_GROUPS covers systems with more than 64 logical processors.
    const DWORD kActiveProcessorCount = ::GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    logicalCpuCount_ = kActiveProcessorCount != 0
        ? static_cast<std::uint32_t>(kActiveProcessorCount)
        : std::max<std::uint32_t>(1, std::thread::hardware_concurrency());

    // Shell icon parsing may block disk or icon handlers; use a dedicated thread pool with a concurrency limit.
    // Maintain at least two worker threads to process application icons in parallel; cap at eight to avoid excessive Shell queries in a short time.
    const int kIconExtractionWorkerCount = std::clamp(static_cast<int>(logicalCpuCount_), 2, 8);
    processIconExtractionPool_.setMaxThreadCount(kIconExtractionWorkerCount);
    processIconExtractionPool_.setExpiryTimeout(1000);

    // Construction phase executes in the order: 'UI -> Connections -> Timer -> First Refresh'.
    activityTotalPhysicalMemoryMB_ = totalPhysicalMemoryMB();
    initializeUi();
    initializeConnections();
    initializeTimer();
    if (QApplication::instance() != nullptr)
    {
        QApplication::instance()->installEventFilter(this);
    }
    monitoringEnabled_ = false;
}

ProcessDock::~ProcessDock()
{
    // Invalidate return results of running tasks and cancel icon query tasks that have not yet started.
    // Thread pool destruction waits for running tasks to complete; tasks use only their own path copies and no longer access Dock members.
    ++processIconExtractionGeneration_;
    processIconExtractionPool_.clear();
    processIconPathsInFlight_.clear();

    // In the destructor phase, first stop the internal ETW consumer thread:
    // - Inputs: None;
    // - Handling: Request ProcessNetworkEtwMonitor to exit and wait for thread join;
    // - Return: None; prevents ETW callbacks from accessing members after object destruction.
    stopProcessNetworkTrafficCapture();
    stopCpuCoreUsageCapture();

    // Proactively remove the global event filter during destruction to prevent QApplication click events from accessing the already-destroyed Dock.
    if (QApplication::instance() != nullptr)
    {
        QApplication::instance()->removeEventFilter(this);
    }
}

bool ProcessDock::eventFilter(QObject* watched, QEvent* event)
{
    if (event == nullptr)
    {
        return QWidget::eventFilter(watched, event);
    }

    // Handle left button press only:
    // - Mouse release/move does not change the selection;
    // - Right-click retains the frozen selection semantics for the context menu.
    if (event->type() != QEvent::MouseButtonPress)
    {
        return QWidget::eventFilter(watched, event);
    }

    const QMouseEvent* mouseEvent = static_cast<QMouseEvent*>(event);
    if (mouseEvent == nullptr || mouseEvent->button() != Qt::LeftButton)
    {
        return QWidget::eventFilter(watched, event);
    }

    if (processTable_ == nullptr ||
        sideTabWidget_ == nullptr ||
        sideTabWidget_->currentWidget() != processListPage_ ||
        contextMenuVisible_ ||
        !isVisible())
    {
        return QWidget::eventFilter(watched, event);
    }

    QWidget* watchedWidget = qobject_cast<QWidget*>(watched);
    if (watchedWidget == nullptr)
    {
        return QWidget::eventFilter(watched, event);
    }

    // Respond only to clicks inside the current ProcessDock to avoid affecting other Docks or independent detail windows.
    const bool kClickedInsideThisDock = (watchedWidget == this) || isAncestorOf(watchedWidget);
    if (!kClickedInsideThisDock)
    {
        return QWidget::eventFilter(watched, event);
    }

    // The table blank area has no item; clicking here should also be treated as 'canceling the current process selection'.
    if (watchedWidget == processTable_->viewport())
    {
        const QPoint kViewportPosition = activityMousePosition(mouseEvent);
        if (!processTable_->indexAt(kViewportPosition).isValid())
        {
            clearProcessTableSelection();
        }
        return QWidget::eventFilter(watched, event);
    }

    // The header, scrollbars, and actual cells still belong to the table, so the selection is not cleared; other controls/blank areas are cleared.
    const bool kClickedInsideProcessTable =
        (watchedWidget == processTable_) ||
        processTable_->isAncestorOf(watchedWidget);
    if (!kClickedInsideProcessTable)
    {
        clearProcessTableSelection();
    }

    return QWidget::eventFilter(watched, event);
}

void ProcessDock::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);

    // On first display or when returning to visible state, give focus to the process search box:
    // - Allows users to type search terms immediately after switching to this page.
    // - Does not require manually clicking the search box first.
    if (sideTabWidget_ != nullptr && sideTabWidget_->currentWidget() == processListPage_)
    {
        focusProcessSearchBox(true);
    }

    if (initialRefreshScheduled_)
    {
        return;
    }

    // Start asynchronous refresh immediately upon first entering the process page:
    // - Do not enumerate during main window startup; start only after the user actually switches to the page.
    // - Uses the same cycle monitoring and activity recording state as the "Start Refresh" button.
    // - Force the initial refresh without waiting for the timer interval to prevent users from seeing an empty table.
    initialRefreshScheduled_ = true;
    monitoringEnabled_ = true;
    activityRecordingEnabled_ = true;
    if (activitySamples_.empty())
    {
        activityRecordingStartTick100ns_ = steadyNow100ns();
        activityNextSequence_ = 0;
    }
    activityTimelinePinnedToLatest_ = true;
    activityTableSnapshotIndex_ = -1;
    activityTableSnapshotRecords_.clear();
    updateProcessActivityStatusLabel();
    requestAsyncRefresh(true);

    // The isVisible() status of the internal phase list page within showEvent may not be stable yet; delay starting the periodic timer until the first iteration of the event loop.
    QTimer::singleShot(0, this, [this]() {
        if (refreshTimer_ != nullptr && isProcessActivityRefreshAllowedNow())
        {
            refreshTimer_->start(refreshIntervalMillisecondsFromInput());
        }
        updateProcessActivityStatusLabel();
    });
}

void ProcessDock::resizeEvent(QResizeEvent* event)
{
    QWidget::resizeEvent(event);

    // Request default adaptive sizing only once after dock size change:
    // - If column widths are not manually adjusted, push to the viewport.
    // - Preserve user-defined column widths when manually adjusted; show horizontal scrollbar only when needed.
    applyAdaptiveColumnWidths();
}
