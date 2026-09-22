#pragma once

// ============================================================
// CustomTitleBar.h
// Purpose:
// 1) Provide a custom-drawn title bar for the main window (left: app icon and feature entry, center: dual-mode "Search/CMD" input, right: control buttons);
// 2) Provide interaction signals for topmost/minimize/maximize/close.
// 3) The middle input box defaults to "Search" mode (global page text search); clicking
//    the left mode button switches to CMD mode (executing cmd /K in a new console).
// 4) Support switching between light and dark themes.
// ============================================================

#include "../Framework.h"

#include <QPoint>
#include <QWidget>

class QAction;
class QLabel;
class QLineEdit;
class QMenu;
class QPushButton;
class QToolButton;
class QGridLayout;
class QHBoxLayout;
class QMouseEvent;
class QResizeEvent;

namespace ks::ui
{
    // ============================================================
    // CustomTitleBar
    // Notes:
    // - This class is responsible solely for title bar UI and event forwarding, without directly controlling main window behavior;
    // - Specific window actions (always on top/minimize/command execution) are handled by mainWindow after receiving signals.
    // ============================================================
    class CustomTitleBar final : public QWidget
    {
        Q_OBJECT

    public:
        // Constructor:
        // - Purpose: Creates and initializes a custom-drawn title bar.
        // - Called: Created during mainWindow construction and mounted via setMenuWidget;
        // - Input parentWidget: Qt parent widget.
        // - Output: None.
        explicit CustomTitleBar(QWidget* parentWidget = nullptr);

        // Destructor:
        // - Purpose: Default destructor is sufficient; child controls are automatically reclaimed via Qt's parent-child relationship.
        ~CustomTitleBar() override = default;

        // setPinnedState：
        // - Purpose: Synchronize the pin button display state (hollow/solid);
        // - Call: Invoked by mainWindow after each change in the pinned state.
        // - Input pinnedState: true=pinned to top, false=not pinned.
        // - Output: None.
        void setPinnedState(bool pinnedState);

        // setCaptureProtectionState：
        // - Purpose: Synchronize the display state of the screenshot blocking button (eye/open eye icon).
        // - Invocation: Called by mainWindow after each SetWindowDisplayAffinity state change.
        // - Input protectedState: true = screen capture blocked, false = screen capture allowed;
        // - Output: None.
        void setCaptureProtectionState(bool protectedState);

        // setMaximizedState：
        // - Purpose: Synchronize the maximize button icon (maximize/restore);
        // - Invocation: Called when mainWindow window state changes;
        // - Input maximizedState: true = currently maximized;
        // - Output: None.
        void setMaximizedState(bool maximizedState);

        // setDarkModeEnabled：
        // - Purpose: Toggle the title bar between light and dark theme styles.
        // - Invocation: Called within mainWindow::applyAppearanceSettings;
        // - Passes darkModeEnabled: true means dark mode.
        // - Output: None.
        void setDarkModeEnabled(bool darkModeEnabled);

        // isPointInDraggableRegion：
        // - Purpose: Check if a point on the title bar belongs to the 'draggable region'.
        // - Invocation: Called within mainWindow::nativeEvent (HTCAPTION hit test);
        // - Input localPos: coordinates relative to the top-left corner of the title bar.
        // - Out: true = draggable region, false = hit interactive control.
        bool isPointInDraggableRegion(const QPoint& localPos) const;

        // titleBarHeight：
        // - Purpose: Return the fixed title bar height for reuse in main window hit testing.
        int titleBarHeight() const;

        // setCustomLeftWidget: Mount custom function entry controls after the application icon and title text.
        void setCustomLeftWidget(QWidget* customLeftWidget);

        // setCustomRightWidget：
        // - Purpose: Insert a custom control (e.g., permission status button group) before the right-side control buttons;
        // - Invocation: Called after mainWindow initializes the permission button;
        // - Pass customRightWidget: the custom widget to attach; pass nullptr to remove it.
        // - Output: None.
        void setCustomRightWidget(QWidget* customRightWidget);

        // titleInputLineEdit：
        // - Purpose: Expose the middle input box for the global search controller to install keyboard navigation filters.
        // - Invocation: Called when mainWindow connects to GlobalUiSearchController;
        // - Out: Pointer to the middle input box.
        QLineEdit* titleInputLineEdit() const;

        // titleInputAnchorWidget：
        // - Purpose: Exposes the intermediate input group container as the alignment anchor for the search result popup.
        // - Invocation: Called when mainWindow connects to GlobalUiSearchController;
        // - Out: Pointer to the input group container.
        QWidget* titleInputAnchorWidget() const;

        // isSearchInputModeActive：
        // - Purpose: Query the current input mode;
        // - Out: true=search mode, false=CMD mode.
        bool isSearchInputModeActive() const;

        // activateSearchInput: Switch back to search mode; focusInput determines whether to move focus to the top input box.
        void activateSearchInput(bool focusInput = true);

        // setSearchScopeDisplayText: Refresh the top search scope label and tab switch hints.
        void setSearchScopeDisplayText(const QString& displayText);

    signals:
        // requestTogglePinned：
        // - Purpose: Request toggling the pinned state;
        // - Triggered: when the pin button is clicked.
        void requestTogglePinned();

        // requestToggleCaptureProtection：
        // - Purpose: Request toggling the main window screenshot protection state.
        // - Triggered when the title bar eye button is clicked.
        void requestToggleCaptureProtection();

        // requestMinimizeWindow：
        // - Purpose: Request to minimize the main window.
        // - Trigger: Fired when the minimize button is clicked.
        void requestMinimizeWindow();

        // requestToggleMaximizeWindow：
        // - Purpose: Request to maximize or restore the main window.
        // - Trigger: Fired when the maximize button is clicked or the draggable area is double-clicked.
        void requestToggleMaximizeWindow();

        // requestCloseWindow：
        // - Purpose: Request closing the main window;
        // - Triggered: when the close button is clicked.
        void requestCloseWindow();

        // commandSubmitted：
        // - Purpose: Submit command-line text to the main window for execution.
        // - Trigger: Fires when Enter is pressed in the command input box in CMD mode;
        // - Input commandText: the user-entered command text (before execution).
        void commandSubmitted(const QString& commandText);

        // searchTextEdited：
        // - Purpose: Forward the input text in search mode to the global search controller.
        // - Triggered when the input box text changes in search mode, or when switching back to search mode from CMD.
        // - Input: searchText (current input box text, untrimmed).
        void searchTextEdited(const QString& searchText);

        // inputModeChanged：
        // - Purpose: Notify input mode changes (used to collapse/restore the search results popup).
        // - Triggered when the user switches between search and CMD modes in the mode menu;
        // - Input searchModeActive: true = search mode, false = CMD mode.
        void inputModeChanged(bool searchModeActive);


    protected:
        // resizeEvent：
        // - Purpose: Maintains the middle input box width at 1/3 of the title bar width during window resize events.
        void resizeEvent(QResizeEvent* resizeEventPointer) override;

        // mousePressEvent：
        // - Purpose: Record the left-click state of the title bar to provide a starting point for subsequent drag/double-click determination.
        // - Note: Do not drag immediately upon press to avoid stealing the double-click sequence.
        void mousePressEvent(QMouseEvent* mouseEventPointer) override;

        // mouseMoveEvent：
        // - Purpose: Initiate a system-level drag after the drag threshold is reached.
        // - Note: In maximized state, the window first restores to normal size before continuing the drag operation.
        void mouseMoveEvent(QMouseEvent* mouseEventPointer) override;

        // mouseReleaseEvent：
        // - Purpose: End the title bar press/drag candidate state to prevent residual state from affecting the next interaction.
        void mouseReleaseEvent(QMouseEvent* mouseEventPointer) override;

        // mouseDoubleClickEvent：
        // - Purpose: Request maximize/restore when the title bar's draggable area is double-clicked.
        void mouseDoubleClickEvent(QMouseEvent* mouseEventPointer) override;

    private:
        // initializeUi：
        // - Purpose: Construct the title bar control tree and layout.
        // - Invocation: Called within the constructor.
        void initializeUi();

        // initializeConnections：
        // - Purpose: Bind button click and Enter submission signals.
        // - Invocation: Called within the constructor.
        void initializeConnections();

        // updateVisualState：
        // - Purpose: Refresh icons, text, and styles (including theme and always-on-top state).
        // - Invocation: Call uniformly when the state changes.
        void updateVisualState();

        // updateCommandLineWidth：
        // - Purpose: Adjust the width of the middle input group to 1/3 of the title bar's available width.
        void updateCommandLineWidth();

        // setTitleInputMode：
        // - Purpose: Toggle search/CMD input mode and synchronize buttons, placeholders, and signals.
        // - Call: Triggered by mode menu actions.
        // - Input searchModeActive: true = search mode, false = CMD mode.
        void setTitleInputMode(bool searchModeActive, bool focusInput = true);

        // updateTitleInputModeVisuals：
        // - Purpose: Refresh the mode button text, menu checkmarks, and input box placeholders based on the current mode.
        // - Call: Invoked during initialization, mode switching, and theme refresh.
        void updateTitleInputModeVisuals();

        // tryStartWindowSystemMove：
        // - Purpose: Initiate a system-level drag on the host window.
        // - Call: Invoked by mouseMoveEvent after the drag threshold is reached.
        // - Input globalPoint: current mouse global coordinates;
        // - Output: true if the system has taken over the drag, false if the drag was not started.
        bool tryStartWindowSystemMove(const QPoint& globalPoint);

        // restoreWindowFromMaximizedForDrag：
        // - Purpose: When dragging a maximized window, restore it to windowed mode and position it below the mouse cursor first.
        // - Called: mouseMoveEvent detects 'dragging from maximized state' and invokes this.
        // - Pass hostWindowWidget: the top-level window to which the title bar belongs.
        // - Input globalPoint: current mouse global coordinates;
        // - Output: None.
        void restoreWindowFromMaximizedForDrag(QWidget* hostWindowWidget, const QPoint& globalPoint);

        // resolveWindowsVersionText：
        // - Purpose: Read the current Windows release version and full kernel version number;
        // - Call: Invoked when initializing the right-side system version label;
        // - Input: None;
        // - Out: e.g., Win10 1909[10.0.18363.592].
        QString resolveWindowsVersionText() const;

    private:
        QWidget* leftWidget_ = nullptr;          // m_leftWidget: Left information area container (icon + title).
        QHBoxLayout* leftLayout_ = nullptr;      // m_leftLayout: Left information area layout.
        QLabel* appIconLabel_ = nullptr;         // m_appIconLabel: Application icon label.
        QLabel* titleTextLabel_ = nullptr;       // m_titleTextLabel: Title text.
        QWidget* customLeftWidget_ = nullptr;    // m_customLeftWidget: Container for custom function entries after the title text.

        QWidget* centerInputGroup_ = nullptr;    // m_centerInputGroup: Center input group container (mode button + input field).
        QHBoxLayout* centerInputLayout_ = nullptr; // m_centerInputLayout: Horizontal layout for the middle input group.
        QToolButton* inputModeButton_ = nullptr; // m_inputModeButton: Input mode toggle button (Search/CMD).
        QMenu* inputModeMenu_ = nullptr;         // m_inputModeMenu: Input mode selection menu.
        QAction* searchModeAction_ = nullptr;    // m_searchModeAction: Menu option for 'Search' mode.
        QAction* commandModeAction_ = nullptr;   // m_commandModeAction: Menu 'CMD Command' mode option.
        QLineEdit* commandLineEdit_ = nullptr;   // m_commandLineEdit: Input field in the center of the title bar (shared for search and commands).

        QWidget* rightWidget_ = nullptr;         // m_rightWidget: Container for the right button area.
        QHBoxLayout* rightLayout_ = nullptr;     // m_rightLayout: Layout for the right button area.
        QWidget* customRightWidget_ = nullptr;   // m_customRightWidget: Custom extension control before the right-side control buttons.
        QLabel* systemVersionLabel_ = nullptr;   // m_systemVersionLabel: System version text located to the left of the eye and pin buttons.
        QPushButton* captureProtectionButton_ = nullptr; // m_captureProtectionButton: Screenshot protection toggle button.
        QPushButton* pinButton_ = nullptr;       // m_pinButton: Pin toggle button.
        QPushButton* minButton_ = nullptr;       // m_minButton: Minimize button.
        QPushButton* maxButton_ = nullptr;       // m_maxButton: Maximize/Restore button.
        QPushButton* closeButton_ = nullptr;     // m_closeButton: Close button.

        QGridLayout* rootLayout_ = nullptr;      // m_rootLayout: Main layout for the title bar (left/center/right sections).

        QString searchScopeDisplayText_ = QStringLiteral("全局"); // m_searchScopeDisplayText: Top search scope label.
        bool captureProtectionEnabled_ = false;  // m_captureProtectionEnabled: Whether screenshot protection is currently enabled.
        bool isPinned_ = false;                  // m_isPinned: Current pinned state.
        bool isMaximized_ = false;               // m_isMaximized: Whether the current window is maximized.
        bool darkModeEnabled_ = false;           // m_darkModeEnabled: Whether dark mode is currently enabled.
        bool searchInputModeActive_ = true;      // m_searchInputModeActive: Whether the middle input box is in search mode (default search).
        bool dragCandidateActive_ = false;       // m_dragCandidateActive: Whether the title bar is currently in a drag candidate state.
        bool dragInProgress_ = false;            // m_dragInProgress: Whether the drag operation has been handed over to the system for processing.
        QPoint dragPressLocalPos_;               // m_dragPressLocalPos: The coordinate relative to the top-left corner of the title bar at the time of the press.
        QPoint dragPressGlobalPos_;              // m_dragPressGlobalPos: Global screen coordinates at the time of the current press.
    };
}
