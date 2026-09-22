#pragma once

// ============================================================
// WindowPickerButton.h
// Purpose:
// - Provide a process picker button that allows dragging a crosshair to a target window; releasing the mouse yields the process owning that window.
//
// Why it is needed:
// - Selecting a target by process name is unreliable for programs with multiple processes of the same name. For programs
//   like QQ, opening it spawns ten processes with the same name; the main process and auxiliary processes differ only in PID
//   and memory size. An address copied from elsewhere belongs to one of them. Attaching to a different one results in "address
//   read failure," even though the read path is completely normal, which misdirects the investigation toward memory reading.
// - Users know which window they want, not the PID. Let them select the window and have the
//   tool resolve the PID; this path eliminates the possibility of selecting the wrong one.
//
// Boundary:
// - Skip windows belonging to this own process during picking; otherwise, hovering over the main interface would incorrectly report itself as the target.
// - The highlight box must be transparent to hit testing (WS_EX_TRANSPARENT); otherwise, WindowFromPoint
//   will detect the highlight box itself, causing it to be recognized only wherever it is dragged.
// ============================================================

#include <QString>
#include <QToolButton>

#include <cstdint>

class QWidget;

namespace ks::ui
{
    // WindowPickerHighlight: A highlighted border overlaying the target window's outer edge.
    class WindowPickerHighlight;

    class WindowPickerButton : public QToolButton
    {
        Q_OBJECT

    public:
        explicit WindowPickerButton(QWidget* parent = nullptr);
        ~WindowPickerButton() override;

    signals:
        // processPicked: Picking completes on mouse release. A processId of 0 indicates no valid target at the drop location.
        void processPicked(quint32 processId, const QString& processName);
        // hoverPreview: Notifies the caller of target changes during dragging for real-time feedback.
        void hoverPreview(quint32 processId, const QString& processName);
        // pickingChanged: Enters/exits pick mode, allowing the caller to toggle the hint text.
        void pickingChanged(bool picking);

    protected:
        void mousePressEvent(QMouseEvent* event) override;
        void mouseMoveEvent(QMouseEvent* event) override;
        void mouseReleaseEvent(QMouseEvent* event) override;
        void keyPressEvent(QKeyEvent* event) override;

    private:
        void beginPicking();
        void finishPicking(bool commit);
        void refreshTargetUnderCursor();

        bool picking_ = false;
        quint32 hoverProcessId_ = 0;
        QString hoverProcessName_;
        WindowPickerHighlight* highlight_ = nullptr;
    };
}
