#pragma once

#include <QDialog>

class QCheckBox;
class QLabel;
class QPushButton;
class QSpinBox;
class QTimer;
class TaskbarNotificationService;

// TaskbarSettingsDialog provides Taskbar-specific notification toggles, earthquake source diagnostics, and test warning entry points.
// All screens share a single non-modal instance to prevent inconsistent settings from separate modifications on multi-monitor setups.
class TaskbarSettingsDialog : public QDialog
{
    Q_OBJECT

public:
    // Constructor: pass the global notification service; set up settings controls and subscribe to their state change signals.
    explicit TaskbarSettingsDialog(TaskbarNotificationService* notificationService, QWidget* parent = nullptr);

private slots:
    // applyClipboardSetting: Synchronizes the checkbox state to the global notification service.
    void applyClipboardSetting(bool enabled);

    // applyDeviceSetting: sync checkbox state to the global notification service.
    void applyDeviceSetting(bool enabled);

    // applyEarthquakeSetting: Synchronize the checkbox state to the global notification service.
    void applyEarthquakeSetting(bool enabled);

    // applyNotificationDuration: Synchronizes the message retention duration (in seconds) to the global notification service.
    void applyNotificationDuration(int seconds);

    // refreshFromService: Read global settings to avoid stale window states from windows opened on other monitors.
    void refreshFromService();

    // refreshSourceDiagnostics: Refresh multi-source connection status text.
    void refreshSourceDiagnostics();

    // restartTaskbar: Start waiting for the replacement instance of the current PID, then exit this process to release the AppBar.
    void restartTaskbar();

private:
    // m_notificationService is a global service, not owned or destroyed by this dialog.
    TaskbarNotificationService* notificationService_;

    // Three checkboxes correspond to notification features that must be retained from WindowsMarker.
    QCheckBox* clipboardCheckBox_;
    QCheckBox* deviceCheckBox_;
    QCheckBox* earthquakeCheckBox_;
    // m_notificationDurationSpinBox: Sets the full retention duration for the body of each standard message.
    QSpinBox* notificationDurationSpinBox_;

    // m_sourceStatusLabel shows the WebSocket source connection state to help diagnose an unavailable network or server.
    QLabel* sourceStatusLabel_;

    // m_testEarthquakeButton: Immediately broadcasts a local earthquake test to verify the red alert state and queue suspension.
    QPushButton* testEarthquakeButton_;

    // m_restartTaskbarButton: Launches a PID-aware replacement instance to ensure the old process releases all AppBar resources first.
    QPushButton* restartTaskbarButton_;

    // m_refreshTimer: Periodically refresh connection diagnostics while the window is displayed, without modifying business state.
    QTimer* refreshTimer_;
};
