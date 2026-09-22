#pragma once

// ============================================================
// MonitorTextViewer.h
// Purpose:
// 1) Provides a unified read-only text viewing window for the monitoring module.
// 2) Reuse CodeEditorWidget to display text details for ETW/WMI/process-oriented monitoring.
// 3) Avoid each Dock independently reimplementing the "text details popup".
// ============================================================

#include <QString>

class QWidget;

namespace monitor_text_viewer
{
    // showReadOnlyTextWindow：
    // - Purpose: Pop up a non-modal read-only text editor window;
    // - Call: reused in scenarios such as the monitoring module viewing ETW details, raw event text, and pre-export preview;
    // - Input parentWidget: the parent window;
    // - Input titleText: window title.
    // - Input contentText: the main text content;
    // - Input virtualPathText: virtual path/source label; may be null.
    // - Return: None; display the window directly.
    void showReadOnlyTextWindow(
        QWidget* parentWidget,
        const QString& titleText,
        const QString& contentText,
        const QString& virtualPathText = QString());
}
