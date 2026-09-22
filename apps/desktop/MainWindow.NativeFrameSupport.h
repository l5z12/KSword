#pragma once

// Implementation details shared by mainWindow's responsibility-specific units.
// Public window API remains in mainWindow.h.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <QWidget>

class MainWindow;

namespace ksword::ui::main_window
{
    inline constexpr const char* kKswordProcessUiAccessPropertyName = "ksword_process_uiaccess_enabled";

    inline constexpr const char* kKswordMainWindowTopMostPropertyName = "ksword_main_window_topmost";

    inline constexpr const char* kKswordMainWindowHwndPropertyName = "ksword_main_window_hwnd";

    // kBackdropRefreshThrottleMs:
    // - Acrylic resampling merged window (milliseconds);
    // - Dragging and scaling continuously trigger geometry events; throttling ensures a combined feature is issued only once when the action stabilizes.
    inline constexpr int kBackdropRefreshThrottleMs = 40;

    bool applyHighestPermittedTopMostLevel(
        const HWND windowHandle,
        const bool pinnedState,
        DWORD* errorCodeOut,
        bool* uiAccessBandAppliedOut);

    bool isKswordPopupTopMostTrackingEnabled();

    void applyTopMostToTopLevelWidget(QWidget* widget, const bool topMostState);

    void syncTopMostForAllAuxiliaryTopLevelWidgets(QWidget* mainWindow, const bool topMostState);

    void configureSingleInstanceMessageReception(HWND mainWindowHandle);

    void clearSingleInstanceMessageReception(HWND mainWindowHandle);
}
