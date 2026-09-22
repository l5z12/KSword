#pragma once

// ============================================================
// GlobalUiBaseStyle.h
// Purpose:
// 1) Provide a unified style block for QApplication-level "basic controls" (buttons, input fields, headers, progress bars, etc.);
// 2) Serves as the visual baseline for all pages to reduce style drift caused by scattered setStyleSheet calls across modules.
// 3) fragments include start/end markers and are managed uniformly by the mainWindow's global style block replacement mechanism.
// ============================================================

#include <QString>

namespace ks::ui
{
    // kBaseControlStyleBeginMarker / kBaseControlStyleEndMarker Purpose:
    // - Mark the start and end positions of the "base control baseline style" in the QApplication stylesheet.
    // - Replaces old fragments when theme or custom colors change to avoid duplicate appends.
    inline constexpr const char* kBaseControlStyleBeginMarker = "/*KSWORD_BASE_CONTROL_STYLE_BEGIN*/";
    inline constexpr const char* kBaseControlStyleEndMarker = "/*KSWORD_BASE_CONTROL_STYLE_END*/";

    // buildGlobalBaseControlStyleBlock:
    // - Generate a base control style snippet with start and end markers;
    // - Override common controls not managed by dedicated style blocks, such as QPushButton,
    //   single-line/multi-line input fields, QGroupBox, QHeaderView, QProgressBar, and QSplitter;
    // - Rules do not use !important, allowing local styles on individual pages to override the baseline as needed.
    // Call method: Called within the theme refresh chain by mainWindow::applyAppearanceSettings.
    // Returns: a base control snippet directly appendable to the QApplication stylesheet.
    QString buildGlobalBaseControlStyleBlock();
}
