# Desktop drawing

[简体中文](zh-CN/desktop-drawing.md) · [Documentation index](README.md)

Open **Miscellaneous → Desktop drawing**, choose a monitor, shape, color, size,
line width, and refresh rate, then start drawing. Coordinates are physical pixels
relative to the selected monitor's top-left corner. The center action recenters
the shape on that monitor.

Shapes include a crosshair, ring, rectangle, diamond, and five-pointed star.
Drawing continues after switching tabs or minimizing the application. Use the
stop-and-refresh button or **Ctrl+Alt+F10** to stop. A failed hotkey registration
is reported; the stop button remains available. Normal shutdown, input-desktop
loss/change, and display-configuration changes also stop drawing.

The backend obtains `GetDC(nullptr)` each frame, draws to the current screen DC,
and releases it on the same thread. It creates no drawing HWND, modifies no target
window, and injects no DWM code. The control page remains a regular Qt widget.

This is an overlay experiment, including UIAccess windows. It does not depend on
the application's window Z-order. **API success means submission succeeded; it
does not prove sustained coverage over UIAccess.** Composition, target repainting,
and display drivers can cover the shape or cause flicker. Exclusive fullscreen,
hardware overlay planes, and secure desktops are not guaranteed targets.

Stopping asynchronously requests repaint of affected desktop/window regions; it
does not paste a saved screenshot back onto the screen. A target may delay its
repaint. Refresh that UI if an afterimage remains.

## Manual validation

1. Verify the target process has nonzero `TokenUIAccess`; topmost styling alone
   is not evidence of UIAccess.
2. Draw inside its window and observe stationary, moving, repainting, and active
   states. Check visibility and flicker over time, not only in one screenshot.
3. Change tabs and minimize, then stop with Ctrl+Alt+F10. Restart and separately
   test the button and normal application-exit cleanup.
4. Check negative-coordinate secondary monitors, mixed DPI, and edge clipping.
   Change the display layout or lock the screen; drawing should require a manual restart.
5. Check both languages and themes, including running state and hotkey-failure text.

The original implementation references are retained in the Chinese copy.
