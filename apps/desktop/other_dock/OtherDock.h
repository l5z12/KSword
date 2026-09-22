#pragma once

// ============================================================
// OtherDock.h
// Purpose:
// 1) Builds the 'Window Management' page, including window list, filtering, grouping, and preview area;
// 2) Provide window right-click actions (activate, bring to top, show/hide, enable/disable, terminate process, etc.);
// 3) Support opening a non-modal 'Window Details' dialog for deep inspection and modification.
// ============================================================

#include "../Framework.h"

#include <QWidget>
#include <QSet>
#include <QVector>

#include <atomic>      // std::atomic_bool: Controls mutual exclusion refresh for the background enumeration thread.
#include <vector>      // std::vector: Window snapshot container.

// Qt forward declaration: reduces header file compilation coupling.
class QCheckBox;
class CodeEditorWidget;
class QComboBox;
class QLineEdit;
class QPushButton;
class QSplitter;
class QSpinBox;
class QTableWidget;
class QTabWidget;
class QStatusBar;
class QTextEdit;
class QTimer;
class QTreeWidget;
class QTreeWidgetItem;
class QLabel;
class QVBoxLayout;
class QHBoxLayout;
class QPoint;

// ============================================================
// OtherDock
// Notes:
// - This class focuses on window enumeration and window property operations.
// - Move all re-enumeration operations to background threads to avoid blocking the UI.
// ============================================================
class OtherDock : public QWidget
{
    Q_OBJECT

public:
    // Constructor:
    // - Purpose: initialize the window list page and toolbar, and trigger the first enumeration.
    // - Parameter parent: Qt parent widget.
    explicit OtherDock(QWidget* parent = nullptr);

    // Destructor:
    // - Purpose: Stop the auto-refresh timer to ensure safe background process exit.
    ~OtherDock() override;

    void focusProcessIds(const QVector<quint32>& processIds);
    void clearExternalProcessFilter();

    // setWindowListOnlyScope: Hides the desktop management page for use within the embedded process details window list.
    void setWindowListOnlyScope();

    // WindowInfo：
    // - Purpose: Cache key attributes of a single window for reuse by list and detail popups.
    struct WindowInfo
    {
        quint64 hwndValue = 0;              // Window handle (as an integer).
        quint64 parentHwndValue = 0;        // Parent window handle.
        quint64 ownerHwndValue = 0;         // Owner window handle.
        QString titleText;                  // Window title.
        QString classNameText;              // Window class name.
        std::uint32_t processId = 0;        // Associated process PID.
        std::uint64_t processCreationTime100ns = 0; // Enum for process creation time, used to prevent erroneous operations due to PID reuse.
        std::uint32_t threadId = 0;         // Create thread TID.
        QString processNameText;            // Process name.
        QString processImagePathText;       // Full path of the process executable.
        QRect windowRect;                   // Window rectangle (screen coordinates).
        quint64 styleValue = 0;             // Window style bits (WS_*).
        quint64 exStyleValue = 0;           // Extended style bits (WS_EX_*).
        bool visible = false;               // Whether visible.
        bool enabled = false;               // Whether enabled.
        bool topMost = false;               // Whether topmost.
        bool minimized = false;             // Whether minimized.
        bool maximized = false;             // Whether maximized.
        bool valid = false;                 // IsWindow validity check.
        bool displayAffinityKnown = false;  // Whether DisplayAffinity was successfully read.
        std::uint32_t displayAffinityValue = 0; // DisplayAffinity - Original WDA_* value.
        std::uint32_t displayAffinityError = 0; // Win32 error when reading DisplayAffinity fails.
        int zOrder = 0;                     // Enumeration order (approximate Z-order).
        QString enumApiName;                // Enum source API name.
        int alphaValue = 255;               // Layered window transparency (0-255).
        bool isChildWindow = false;         // Whether child window.
    };

    // CreatedDesktopRecord：
    // - Purpose: Record the desktop handle created and retained by this process.
    // - Purpose: Private DACL desktops may no longer be openable by name via OpenDesktopW; the handle returned at creation must be reused during switching.
    // - Lifecycle: OtherDock's destructor uniformly calls CloseDesktop to avoid leaking desktop object references.
    struct CreatedDesktopRecord
    {
        QString windowStationName;          // Name of the window station at creation.
        QString desktopName;                // Desktop object name.
        void* desktopHandle = nullptr;      // HDESK handle; using void* in the header file to avoid propagating Windows.h.
        std::uint32_t desiredAccess = 0;    // DESKTOP_* access mask requested at creation.
        bool privateAccess = false;         // Whether to use a private DACL that denies access to other processes.
        bool inheritableHandle = false;     // Returns whether the handle is inheritable by child processes.
    };

private:
    // ===================== UI Initialization ======================
    void initializeUi();
    void initializeConnections();
    void applyViewMode();

    // ===================== List Refresh =====================
    void refreshWindowListAsync();
    void rebuildWindowTreeFromSnapshot();
    bool passFilter(const WindowInfo& info) const;
    void updateStatusBar();
    void updatePreviewPanel(const WindowInfo* info);
    // refreshDesktopList：
    // - Purpose: Refresh the window station/desktop list in the 'Desktop Management' page;
    // - Call: Invoked after UI initialization, after clicking the refresh button, and after a successful switch.
    // - Input: None;
    // - Out: None. Results are written directly to m_desktopTable and m_desktopStatusLabel.
    void refreshDesktopList();

    // switchToSelectedDesktop：
    // - Purpose: Switch to the currently selected desktop in the table.
    // - Invocation: called when clicking the switch button or double-clicking a desktop row;
    // - Input: None;
    // - Output: None. Status results are reported via logs and m_desktopStatusLabel.
    void switchToSelectedDesktop();

    // showCreateDesktopDialog：
    // - Purpose: Display the 'New Desktop' parameter dialog to collect parameters such as name, heap size, access mask, and security descriptor.
    // - Called: when clicking the 'New' button on the Desktop Management page or selecting 'New Desktop' from the right-click context menu.
    // - Input: None;
    // - Output: None; creation results are reflected via logs, status bar, and desktop list refresh.
    void showCreateDesktopDialog();

    // showDesktopContextMenu：
    // - Purpose: Display a right-click context menu in the desktop management table.
    // - Invocation: Triggered when the user right-clicks on the desktop table.
    // - Input localPos: viewport coordinates of the table view.
    // - Out: None; menu actions directly drive switching, copying, or viewing details.
    void showDesktopContextMenu(const QPoint& localPos);

    // ===================== Interaction Operations ======================
    void showWindowContextMenu(const QPoint& localPos);
    void exportVisibleRowsToTsv();
    void openWindowDetailDialog(const WindowInfo& info, bool inputSettings = false);
    const WindowInfo* findInfoByHwnd(quint64 hwndValue) const;
    // setCaptureProtectionForSelectedWindow：
    // - Purpose: Enables/disables screenshot protection for the currently selected window.
    // - Invocation: Window List toolbar button;
    // Input protectedState: true=enable, false=disable;
    // - Out: None; results are reported via logs, message boxes, and list refreshes.
    void setCaptureProtectionForSelectedWindow(bool protectedState);

    // setCaptureProtectionForWindow：
    // - Purpose: Apply screenshot protection to a snapshot of the specified window.
    // - Call: Right-click menu and selected item toolbar.
    // - Input info: target window snapshot.
    // Input protectedState: true=enable, false=disable.
    void setCaptureProtectionForWindow(const WindowInfo& info, bool protectedState);

    // handleWindowPickerRelease：
    // - Purpose: Handle the "crosshair drag-and-drop pick" release event, locate the window under the mouse, and display details.
    // - Call: Triggered by the top picker button of the window list on mouse release.
    // - Input globalPos: global screen coordinates when the mouse is released.
    // - Output: None; opens the window details dialog directly upon success.
    void handleWindowPickerRelease(const QPoint& globalPos);

private:
    // Top-level layout and toolbar.
    QVBoxLayout* rootLayout_ = nullptr;          // Root layout.
    QWidget* toolBarWidget_ = nullptr;           // Top toolbar container.
    QHBoxLayout* toolBarLayout_ = nullptr;       // Top toolbar layout.
    QPushButton* refreshButton_ = nullptr;       // Refresh button.
    QPushButton* clearExternalProcessFilterButton_ = nullptr; // Clear cross-page PID filter.
    QCheckBox* autoRefreshCheck_ = nullptr;      // Auto-refresh toggle.
    QSpinBox* autoRefreshIntervalSpin_ = nullptr; // Auto-refresh interval (ms).
    QLineEdit* filterEdit_ = nullptr;            // Keyword filter input.
    QComboBox* filterModeCombo_ = nullptr;       // Condition filter dropdown.
    QComboBox* enumModeCombo_ = nullptr;         // Enumeration mode dropdown.
    QComboBox* groupModeCombo_ = nullptr;        // Grouping mode combo box.
    QComboBox* viewModeCombo_ = nullptr;         // Display style toggle.
    QPushButton* exportButton_ = nullptr;        // Export button.

    // Central main area: Main Tab (Window List / Desktop Management).
    QTabWidget* contentTabWidget_ = nullptr;     // Main content Tab container.
    QWidget* windowListPage_ = nullptr;          // Window list page.
    QVBoxLayout* windowListPageLayout_ = nullptr;// Window list page layout.
    QWidget* windowListToolWidget_ = nullptr;    // Container for the toolbar at the top of the window list page.
    QHBoxLayout* windowListToolLayout_ = nullptr;// Layout for the toolbar at the top of the window list page.
    QPushButton* windowPickerButton_ = nullptr;  // Crosshair drag-and-drop pick button (opens window details based on mouse position upon release).
    QPushButton* protectCaptureButton_ = nullptr; // Button to enable screenshot protection for the selected window.
    QPushButton* unprotectCaptureButton_ = nullptr; // Button to disable screenshot protection for the selected window.
    QLabel* windowPickerHintLabel_ = nullptr;    // Tooltip text next to the crosshair button, explaining the drag-and-drop usage.

    // Window list page: tree on the left, preview on the right.
    QSplitter* mainSplitter_ = nullptr;          // Left-right splitter.
    QTreeWidget* windowTree_ = nullptr;          // Window tree/list.
    QWidget* previewWidget_ = nullptr;           // Right-side preview container.
    QVBoxLayout* previewLayout_ = nullptr;       // Right-side preview layout.
    QLabel* thumbnailLabel_ = nullptr;           // Window thumbnail.
    QPushButton* captureButton_ = nullptr;       // Screenshot button.
    CodeEditorWidget* quickInfoText_ = nullptr;  // Key property summary text, supports immediate language redraw.

    // Desktop management page: enumerate window stations and desktop lists, displaying context such as SessionId, SID, and switching capabilities.
    QWidget* desktopPage_ = nullptr;             // Desktop management page container.
    QVBoxLayout* desktopPageLayout_ = nullptr;   // Main layout for the desktop management page.
    QHBoxLayout* desktopToolLayout_ = nullptr;   // Desktop management toolbar layout.
    QPushButton* desktopRefreshButton_ = nullptr;// Button to refresh the desktop list.
    QPushButton* desktopSwitchButton_ = nullptr; // Switch to the selected desktop button.
    QPushButton* desktopCreateButton_ = nullptr; // Desktop creation button; detailed parameters are configured in the popup dialog.
    QTableWidget* desktopTable_ = nullptr;       // Desktop list table (Window Station / Desktop / SessionId / SID / SID Details / Remarks).
    QLabel* desktopStatusLabel_ = nullptr;       // Desktop status hint label.
    std::vector<CreatedDesktopRecord> createdDesktopHandles_; // Desktop handle records created and retained by this process.

    // Bottom status bar.
    QStatusBar* statusBar_ = nullptr;            // Status bar.
    QLabel* totalLabel_ = nullptr;               // Total window count.
    QLabel* visibleLabel_ = nullptr;             // Visible window count.
    QLabel* systemLabel_ = nullptr;              // System window count.
    QLabel* selectedLabel_ = nullptr;            // Currently selected item information

    // Auto-refresh timer.
    QTimer* autoRefreshTimer_ = nullptr;         // Periodic refresh control.

    // Data cache.
    std::vector<WindowInfo> windowSnapshot_;     // Current window snapshot.
    std::vector<WindowInfo> previousSnapshot_;   // Previous window snapshot.
    std::vector<WindowInfo> exitedOneRound_;     // Retain exited windows for one round.
    std::vector<quint64> newWindowHandles_;      // List of new window handles (used for highlighting).
    QSet<quint32> externalProcessIdFilterSet_;   // Cross-view PID filter for the process page.
    int refreshProgressPid_ = 0;                 // PID for the refresh task progress card.
    std::atomic_bool refreshRunning_{ false };   // Flag indicating background refresh is in progress.
};
