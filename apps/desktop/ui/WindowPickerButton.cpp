#include "WindowPickerButton.h"

#include "../Theme.h"

#include <QKeyEvent>
#include <QMouseEvent>
#include <QPaintEvent>
#include <QPainter>
#include <QPen>
#include <QWidget>

#include <windows.h>
#include <psapi.h>

// ============================================================
// WindowPickerButton.cpp
// Purpose:
// - Implement crosshair picker: press to grab mouse, parse the process under
//   the cursor while moving and highlight it, release to submit, Esc to cancel.
// ============================================================

namespace ks::ui
{
    // WindowPickerHighlight：
    // - A borderless, topmost widget that draws only a border to indicate which window will be picked.
    // - Position is sent directly using Win32 physical pixels. This avoids the conversion between logical and physical pixels:
    //   GetWindowRect returns physical coordinates, while Qt's setGeometry expects logical coordinates. On multi-monitor setups with
    //   different scaling factors, the origins and scales differ, making manual conversion prone to misalignment on secondary screens.
    //   After passing to SetWindowPos, Qt adjusts its geometry in response to WM_SIZE, and rendering proceeds normally.
    class WindowPickerHighlight : public QWidget
    {
    public:
        WindowPickerHighlight()
            : QWidget(nullptr,
                Qt::Tool | Qt::FramelessWindowHint | Qt::WindowStaysOnTopHint
                | Qt::WindowTransparentForInput | Qt::NoDropShadowWindowHint)
        {
            setAttribute(Qt::WA_TranslucentBackground, true);
            setAttribute(Qt::WA_ShowWithoutActivating, true);
            setAttribute(Qt::WA_TransparentForMouseEvents, true);
            // Instantiate the native window first to obtain the HWND for positioning.
            (void)winId();
        }

        // nativeHandle: When picking, exclude the highlighted box itself from the hit test results.
        HWND nativeHandle() const
        {
            return reinterpret_cast<HWND>(winId());
        }

        void showOverPhysicalRect(const RECT& physicalRect)
        {
            const int kWidth = physicalRect.right - physicalRect.left;
            const int kHeight = physicalRect.bottom - physicalRect.top;
            if (kWidth <= 0 || kHeight <= 0)
            {
                hide();
                return;
            }
            ::SetWindowPos(
                nativeHandle(),
                HWND_TOPMOST,
                physicalRect.left,
                physicalRect.top,
                kWidth,
                kHeight,
                SWP_NOACTIVATE | SWP_SHOWWINDOW);
            update();
        }

    protected:
        void paintEvent(QPaintEvent*) override
        {
            QPainter painter(this);
            painter.setRenderHint(QPainter::Antialiasing, false);
            // A 3-pixel solid border: visible on both light and dark windows without obscuring content.
            QPen pen(ksword_theme::primaryAccentColor());
            pen.setWidth(3);
            painter.setPen(pen);
            painter.setBrush(Qt::NoBrush);
            painter.drawRect(rect().adjusted(1, 1, -2, -2));
        }
    };

    namespace
    {
        // processNameOf: retrieves the process image file name. Returns an empty string if unavailable;
        // the caller decides how to handle it, rather than fabricating a placeholder name here.
        QString processNameOf(const DWORD processId)
        {
            if (processId == 0)
            {
                return QString();
            }
            const HANDLE kProcessHandle = ::OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
            if (kProcessHandle == nullptr)
            {
                return QString();
            }
            wchar_t imagePath[MAX_PATH] = {};
            DWORD pathLength = MAX_PATH;
            QString name;
            if (::QueryFullProcessImageNameW(kProcessHandle, 0, imagePath, &pathLength) != FALSE)
            {
                const QString kFullPath = QString::fromWCharArray(imagePath, static_cast<int>(pathLength));
                const int kSeparatorIndex = kFullPath.lastIndexOf(QLatin1Char('\\'));
                name = (kSeparatorIndex >= 0) ? kFullPath.mid(kSeparatorIndex + 1) : kFullPath;
            }
            ::CloseHandle(kProcessHandle);
            return name;
        }
    }

    WindowPickerButton::WindowPickerButton(QWidget* const parent)
        : QToolButton(parent)
    {
        setCheckable(false);
        setCursor(Qt::CrossCursor);
        setFocusPolicy(Qt::StrongFocus);
    }

    WindowPickerButton::~WindowPickerButton()
    {
        delete highlight_;
        highlight_ = nullptr;
    }

    void WindowPickerButton::mousePressEvent(QMouseEvent* const event)
    {
        if (event->button() != Qt::LeftButton)
        {
            QToolButton::mousePressEvent(event);
            return;
        }
        beginPicking();
        event->accept();
    }

    void WindowPickerButton::mouseMoveEvent(QMouseEvent* const event)
    {
        if (!picking_)
        {
            QToolButton::mouseMoveEvent(event);
            return;
        }
        refreshTargetUnderCursor();
        event->accept();
    }

    void WindowPickerButton::mouseReleaseEvent(QMouseEvent* const event)
    {
        if (!picking_)
        {
            QToolButton::mouseReleaseEvent(event);
            return;
        }
        refreshTargetUnderCursor();
        finishPicking(true);
        event->accept();
    }

    void WindowPickerButton::keyPressEvent(QKeyEvent* const event)
    {
        if (picking_ && event->key() == Qt::Key_Escape)
        {
            finishPicking(false);
            event->accept();
            return;
        }
        QToolButton::keyPressEvent(event);
    }

    void WindowPickerButton::beginPicking()
    {
        if (picking_)
        {
            return;
        }
        picking_ = true;
        hoverProcessId_ = 0;
        hoverProcessName_.clear();

        if (highlight_ == nullptr)
        {
            highlight_ = new WindowPickerHighlight();
        }
        // Grab keyboard too: Esc cancellation depends on this control receiving key events.
        grabMouse(QCursor(Qt::CrossCursor));
        grabKeyboard();
        emit pickingChanged(true);
        refreshTargetUnderCursor();
    }

    void WindowPickerButton::finishPicking(const bool commit)
    {
        if (!picking_)
        {
            return;
        }
        picking_ = false;
        releaseMouse();
        releaseKeyboard();
        if (highlight_ != nullptr)
        {
            highlight_->hide();
        }
        emit pickingChanged(false);

        if (commit)
        {
            emit processPicked(hoverProcessId_, hoverProcessName_);
        }
        hoverProcessId_ = 0;
        hoverProcessName_.clear();
    }

    void WindowPickerButton::refreshTargetUnderCursor()
    {
        // Use Win32 to get cursor position instead of QCursor::pos(): WindowFromPoint consumes physical pixels, while Qt
        // provides logical pixels. On multi-monitor setups with different scaling, these differ; mixing them causes the
        // cursor to point to the wrong window on secondary monitors. Using Win32 for both eliminates the need for conversion.
        POINT cursorPoint{};
        if (::GetCursorPos(&cursorPoint) == FALSE)
        {
            return;
        }

        HWND targetWindow = ::WindowFromPoint(cursorPoint);
        // Although the highlight box has WS_EX_TRANSPARENT, we explicitly skip it here: if this check fails, the symptom is
        // 'picking up the same process everywhere', at which point it becomes hard to tell the highlight box is blocking the way.
        if (highlight_ != nullptr && targetWindow == highlight_->nativeHandle())
        {
            targetWindow = nullptr;
        }
        if (targetWindow != nullptr)
        {
            // The hit is often a child control; we need its parent top-level window.
            HWND rootWindow = ::GetAncestor(targetWindow, GA_ROOT);
            if (rootWindow != nullptr)
            {
                targetWindow = rootWindow;
            }
        }

        DWORD targetProcessId = 0;
        if (targetWindow != nullptr)
        {
            ::GetWindowThreadProcessId(targetWindow, &targetProcessId);
        }
        // Skip self: do not report this process as the target when the mouse hovers over the main interface.
        if (targetProcessId == ::GetCurrentProcessId())
        {
            targetProcessId = 0;
            targetWindow = nullptr;
        }

        const quint32 kNewProcessId = static_cast<quint32>(targetProcessId);
        if (targetWindow == nullptr || kNewProcessId == 0)
        {
            if (highlight_ != nullptr)
            {
                highlight_->hide();
            }
            if (hoverProcessId_ != 0)
            {
                hoverProcessId_ = 0;
                hoverProcessName_.clear();
                emit hoverPreview(0, QString());
            }
            return;
        }

        RECT windowRect{};
        if (::GetWindowRect(targetWindow, &windowRect) != FALSE && highlight_ != nullptr)
        {
            highlight_->showOverPhysicalRect(windowRect);
        }

        if (kNewProcessId != hoverProcessId_)
        {
            hoverProcessId_ = kNewProcessId;
            hoverProcessName_ = processNameOf(targetProcessId);
            emit hoverPreview(hoverProcessId_, hoverProcessName_);
        }
    }
}
