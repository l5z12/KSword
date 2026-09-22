#pragma once

// ============================================================
// CommandExecutionPopup.h
// Purpose:
// 1) Provides a command execution configuration popup below the input box for CMD mode in the title bar;
// 2) Centralizes collection of working directory, user token, privilege level, and CMD window display options;
// 3) Responsible only for displaying and collecting parameters; the actual CreateProcess call is executed by mainWindow.
// ============================================================

#include <QFrame>
#include <QPointer>
#include <QString>
#include <QtGlobal>

class QCheckBox;
class QComboBox;
class QEvent;
class QLabel;
class QLineEdit;
class QToolButton;
class QWidget;

namespace ks::ui
{
    // ============================================================
    // CommandExecutionOptions
    // Note: Describes startup options for a title bar CMD command, passed between UI and mainWindow.
    // ============================================================
    struct CommandExecutionOptions
    {
        // UserMode: Specifies the source of the user token when creating the command process.
        enum class UserMode : int
        {
            kCurrentUser = 0, // Follows the user token of the current KSword process.
            kSystem = 1,      // Use the SYSTEM process token (PID 4).
            kProcessToken = 2 // Use the process token for the user-specified PID.
        };

        // PrivilegeMode: Select the target privilege level under the current user mode.
        enum class PrivilegeMode : int
        {
            kCurrent = 0,      // Inherit current KSword permissions.
            kAdministrator = 1, // Request administrator privileges via UAC.
            kStandard = 2      // Use the standard user token for an interactive shell when elevated.
        };

        QString workingDirectory; // workingDirectory: Initial working directory for cmd.exe.
        UserMode userMode = UserMode::kCurrentUser; // userMode: Source of the user token.
        quint32 tokenSourcePid = 0; // tokenSourcePid: Source process PID in ProcessToken mode.
        PrivilegeMode privilegeMode = PrivilegeMode::kCurrent; // privilegeMode: privilege selection.
        bool openConsoleWindow = true; // openConsoleWindow: Whether to create a visible and persistent CMD window.
    };

    // ============================================================
    // CommandExecutionPopup
    // Notes:
    // - Displayed as a child control of the main window below the title bar input group, visually consistent with the global search popup;
    // - Retain control state after the popup closes, so the last selection is reused when switching back to CMD mode next time.
    // - Does not execute external commands directly to prevent the UI layer from bypassing mainWindow's permission and error handling.
    // ============================================================
    class CommandExecutionPopup final : public QFrame
    {
        Q_OBJECT

    public:
        // Constructor: Creates the command option control and anchors the popup to the title bar input group.
        // Parameter popupHostWindow: The main window hosting the popup.
        // Parameter popupAnchorWidget: the title bar input group; the popup displays below it.
        // Parameter commandInputEdit: The title bar CMD input box, used to read commands and listen for focus changes.
        // Parameter parentObject: Qt parent object.
        explicit CommandExecutionPopup(
            QWidget* popupHostWindow,
            QWidget* popupAnchorWidget,
            QLineEdit* commandInputEdit,
            QObject* parentObject = nullptr);

        // setCommandModeActive: Synchronizes whether CMD mode is active and shows/hides the popup as needed.
        // Parameter commandModeActive: true indicates CMD mode, false indicates search mode.
        void setCommandModeActive(bool commandModeActive);

        // currentOptions: Reads the current control state to assemble the launch request for mainWindow.
        CommandExecutionOptions currentOptions() const;

        // isPopupVisible: Returns whether the configured popup is currently visible.
        bool isPopupVisible() const;

    public slots:
        // dismissPopup: Dismiss the popup but retain user-selected parameters.
        void dismissPopup();

    signals:
        // executeRequested: Emits the command and parameter snapshot when the user clicks the execution button on the popup.
        void executeRequested(
            const QString& commandText,
            const CommandExecutionOptions& options);

    protected:
        // eventFilter: Handles input field focus, main window move/resize, and clicks outside the popup.
        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override;

    private:
        // initializeUi: Creates title, directory, user, permission, and window option controls within the popup.
        void initializeUi();

        // refreshTextAndStyle: Refresh popup text and opaque background styles according to the current theme and language pack.
        void refreshTextAndStyle();

        // showPopupPanel: Calculate dimensions and position the popup below the title bar input group.
        void showPopupPanel();

        // repositionPopupPanel: Repositions the popup panel when the window moves or changes size.
        void repositionPopupPanel();

        // updateUserModeUi: Display PID input and restrict inapplicable permission options based on the user token source.
        void updateUserModeUi();

        // selectWorkingDirectory: Opens the directory picker and fills the working directory input field.
        void selectWorkingDirectory();

        // requestExecution: Validates the current input and issues an execution request.
        void requestExecution();

        // widgetBelongsToBranch: Determines if a widget belongs to a specified parent widget branch.
        static bool widgetBelongsToBranch(QWidget* widget, QWidget* branchRoot);

        // isComboPopupEvent: Identifies independent Qt Popup events for user/permission combo boxes to prevent the parent popup from collapsing when an option is clicked.
        bool isComboPopupEvent(QObject* watchedObject) const;

        // text: reads semantic language keys; fallbackText serves as Chinese fallback when the language pack is missing.
        static QString text(const QString& key, const QString& fallbackText);

    private:
        QPointer<QWidget> popupHostWindow_; // m_popupHostWindow: Main window host.
        QPointer<QWidget> popupAnchorWidget_; // m_popupAnchorWidget: Title bar input group anchor.
        QPointer<QLineEdit> commandInputEdit_; // m_commandInputEdit: Command input box in the title bar.

        QLabel* titleLabel_ = nullptr; // m_titleLabel: Popup title.
        QToolButton* closeButton_ = nullptr; // m_closeButton: Button to collapse the popup.
        QLabel* workingDirectoryLabel_ = nullptr; // m_workingDirectoryLabel: Directory field label.
        QLineEdit* workingDirectoryEdit_ = nullptr; // m_workingDirectoryEdit: Working directory input field.
        QToolButton* browseDirectoryButton_ = nullptr; // m_browseDirectoryButton: Select directory button.
        QLabel* userModeLabel_ = nullptr; // m_userModeLabel: Label for the user field.
        QComboBox* userModeCombo_ = nullptr; // m_userModeCombo: User token source dropdown.
        QLabel* tokenPidLabel_ = nullptr; // m_tokenPidLabel: Token PID field label.
        QLineEdit* tokenPidEdit_ = nullptr; // m_tokenPidEdit: Input field for specifying the process token PID.
        QLabel* privilegeLabel_ = nullptr; // m_privilegeLabel: privilege field label.
        QComboBox* privilegeCombo_ = nullptr; // m_privilegeCombo: privilege level dropdown.
        QCheckBox* openConsoleCheckBox_ = nullptr; // m_openConsoleCheckBox: CMD window display switch.
        QLabel* hintLabel_ = nullptr; // m_hintLabel: Explanation of Enter, /K, and /C behaviors.
        QToolButton* executeButton_ = nullptr; // m_executeButton: Button to issue command execution requests.

        bool commandModeActive_ = false; // m_commandModeActive: Indicates if CMD mode is currently active.
    };
}
