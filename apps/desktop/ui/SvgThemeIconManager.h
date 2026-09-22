#pragma once

// ============================================================
// SvgThemeIconManager.h
// Purpose:
// - Centrally adapt the theme color for SVG and flat icons during the main interface loading phase.
// - Uses pixel signature caching for one-time coloring results to avoid redundant rendering for each button.
// - Skips the default theme color by default; restores original icons when reverting to defaults at runtime.
// ============================================================

#include <QColor>
#include <QIcon>
#include <QObject>

#include <functional>

class QAction;
class QApplication;
class QEvent;
class QTabWidget;
class QWidget;

namespace ks::ui
{
    // SvgThemeIconApplyResult：
    // - Stores observable results from a single batch coloring operation;
    // - mainWindow uses it to record elapsed time, traversal count, and cache hit rate.
    struct SvgThemeIconApplyResult
    {
        int visitedWidgetCount = 0; // visitedWidgetCount: Number of QWidget instances visited in this traversal.
        int recoloredIconCount = 0; // recoloredIconCount: Actual number of icon slots replaced.
        int cacheHitCount = 0;      // cacheHitCount: Number of times a cached rendered icon was reused.
        bool skippedDefaultTheme = false; // skippedDefaultTheme: Whether to skip the default theme directly.
        qint64 elapsedMilliseconds = 0;   // elapsedMilliseconds: Total duration of the batch processing.
    };

    // SvgThemeIconManager：
    // - Call applyToApplication() to perform centralized processing during startup or theme switching;
    // - The global event filter only takes over subsequent lazy-loaded pages; call sites no longer need to handle coloring themselves.
    class SvgThemeIconManager final : public QObject
    {
    public:
        // instance：
        // - Returns the process-local singleton manager;
        // - On the first theme application, the manager installs a global event filter itself.
        static SvgThemeIconManager& instance();

        // applyToApplication：
        // - application: current QApplication
        // - themeColor: Current theme accent color
        // - isDefaultThemeColor: skips the first batch coloring per contract when true.
        // - progressCallback: returns the count of processed/total controls for displaying the startup progress bar;
        // - Control traversal is sliced by time budget: the first slice executes synchronously, while subsequent slices resume via the event loop;
        //   when this function returns, batch processing may not yet be complete (controls created during slicing are handled by event filters);
        // - Return: Batch processing statistics: visitedWidgetCount is the total number of widgets planned for
        //   traversal in this round; other counts and durations cover only the first batch executed synchronously.
        SvgThemeIconApplyResult applyToApplication(
            QApplication* application,
            const QColor& themeColor,
            bool isDefaultThemeColor,
            const std::function<void(int, int)>& progressCallback = {});

    protected:
        // eventFilter：
        // - Centralize handling of lazy-loaded controls and actions created after the theme is applied;
        // - No SVG or pixel shader execution is performed when the cache is hit.
        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override;

    private:
        SvgThemeIconManager() = default;
        ~SvgThemeIconManager() override = default;
        SvgThemeIconManager(const SvgThemeIconManager&) = delete;
        SvgThemeIconManager& operator=(const SvgThemeIconManager&) = delete;

        // runIconApplySlice：
        // - runGeneration: the generation recorded when initiating this batch processing; a mismatch indicates it has been superseded by a new round.
        // - cacheHitCount: Accumulates cache hit counts; may be null.
        // - Only process widgets within the time budget; if not finished, schedule the next batch using QTimer::singleShot(0).
        // - Returns the actual number of icon slots replaced or restored in this slice.
        int runIconApplySlice(quint64 runGeneration, int* cacheHitCount);

        // The following functions handle QWidget, QAction, Tab, and a single QIcon respectively.
        int applyToWidget(QWidget* widgetPointer, int* cacheHitCount);
        bool applyToAction(QAction* actionPointer, int* cacheHitCount);
        int applyToTabWidget(QTabWidget* tabWidgetPointer, int* cacheHitCount);
        QIcon themedIcon(const QIcon& sourceIcon, bool* cacheHitOut);

        bool filterInstalled_ = false; // m_filterInstalled: Whether the global event filter is installed.
        bool customTintActive_ = false; // m_customTintActive: Whether a non-default theme tint is currently applied.
        QColor themeColor_; // m_themeColor: The emphasis color used for the current batch of coloring.
    };
}
