#pragma once

#include "TaskbarEarthquakeClient.h"

#include <QAbstractNativeEventFilter>
#include <QObject>
#include <QTimer>

class QWidget;

// TaskbarNotificationKind distinguishes three types of standard notifications to allow independent enabling/disabling via the settings page.
enum class TaskbarNotificationKind
{
    kClipboard, // System clipboard text change.
    kDevice,    // USB, disk, or volume attachment, removal, and topology changes.
    kEarthquake // Multi-source real-time earthquake warning.
};

// TaskbarNotificationView represents the current snapshot of notifications displayed for all screen sharing sessions.
struct TaskbarNotificationView
{
    TaskbarNotificationKind kind = TaskbarNotificationKind::kClipboard; // Notification source type.
    QString source;            // Compact source text.
    QString title;             // Notification title.
    QString body;              // Notification body.
    bool earthquake = false;   // When true, the Taskbar immediately switches to the red alert theme.
};

// TaskbarNotificationService unifies system message listening, maintains a standard notification FIFO queue, and controls the highest priority for earthquake alerts.
// It creates only a hidden message window, so multiple Taskbar screen windows always display the same notification content.
class TaskbarNotificationService : public QObject, public QAbstractNativeEventFilter
{
    Q_OBJECT

public:
    // Constructor: accepts the global Earthquake client; installs clipboard/device listeners and starts the notification scheduling timer.
    explicit TaskbarNotificationService(TaskbarEarthquakeClient* earthquakeClient, QObject* parent = nullptr);

    // Destructor: unregister Win32 listeners, destroy the hidden window, and stop the audio player.
    ~TaskbarNotificationService() override;

    // currentNotification: No input; returns the global current notification. An empty title indicates no notification.
    TaskbarNotificationView currentNotification() const;

    // hasVisibleNotification: No input; returns whether a notification should replace the central spectrum and clock.
    bool hasVisibleNotification() const;

    // earthquakeActive: No input; returns whether at least one active real or test earthquake warning exists.
    bool earthquakeActive() const;

    // clipboardNotificationsEnabled: No input; returns the clipboard text notification switch.
    bool clipboardNotificationsEnabled() const;

    // deviceNotificationsEnabled: No input; returns the device change notification toggle state.
    bool deviceNotificationsEnabled() const;

    // earthquakeNotificationsEnabled: No input; returns the earthquake warning switch status.
    bool earthquakeNotificationsEnabled() const;

    // notificationDurationSeconds: No input; returns the full duration in seconds that a standard message remains visible.
    int notificationDurationSeconds() const;

    // setClipboardNotificationsEnabled: Enable/disable clipboard text change notifications and persist the setting.
    void setClipboardNotificationsEnabled(bool enabled);

    // setDeviceNotificationsEnabled: Enables device change notifications and persists the setting.
    void setDeviceNotificationsEnabled(bool enabled);

    // setEarthquakeNotificationsEnabled: Enable/disable earthquake warnings and persist the setting.
    void setEarthquakeNotificationsEnabled(bool enabled);

    // setNotificationDurationSeconds: Set the full retention duration in seconds for standard messages and persist it; range is 1 to 60 seconds.
    void setNotificationDurationSeconds(int seconds);

    // injectTestEarthquake: No input; requests the earthquake client to broadcast a local test warning.
    void injectTestEarthquake();

    // sourceStatuses: No input; returns the latest connection status of the earthquake client for display in the settings window.
    QList<TaskbarEarthquakeSourceStatus> sourceStatuses() const;

    // nativeEventFilter: Receive Win32 clipboard and device messages for the exclusive hidden window.
    bool nativeEventFilter(const QByteArray& eventType, void* message, qintptr* result) override;

signals:
    // presentationChanged: Indicates a change in the current notification or earthquake alert state; all Taskbar windows synchronize the central area based on this.
    void presentationChanged();

    // settingsChanged: Emitted after any persistent notification setting change to allow the settings window to refresh checkboxes.
    void settingsChanged();

    // sourceStatusesChanged: Emitted when an earthquake source's connection state changes, allowing the settings window to refresh diagnostics.
    void sourceStatusesChanged();

private slots:
    // advancePresentation: Driven by a short-interval clock; responsible for normal queue carousel and earthquake status refresh.
    void advancePresentation();

    // refreshEarthquakePresentation: Immediately take over or release the standard notification queue when earthquake activity status changes.
    void refreshEarthquakePresentation();

private:
    // handleNativeMessage: handles WM_CLIPBOARDUPDATE and WM_DEVICECHANGE messages received by the hidden window.
    bool handleNativeMessage(void* message, qintptr* result);

    // enqueueClipboardText: Reads and normalizes clipboard Unicode text on the GUI thread, then enqueues it into the standard queue.
    void enqueueClipboardText();

    // handleDeviceChange: adds device messages that match criteria and are not duplicates to the normal queue.
    void handleDeviceChange(quintptr wParam, qintptr lParam);

    // enqueueNotification: Appends a normal message to the FIFO queue; discards the oldest item if the queue is too long.
    void enqueueNotification(const TaskbarNotificationView& notification);

    // updateCurrentNormalNotification: Switch to the next normal notification; does not affect earthquake priority.
    void updateCurrentNormalNotification();

    // normalNotificationDurationMilliseconds: Converts the configured dwell seconds into a duration including fade-in/fade-out budget.
    qint64 normalNotificationDurationMilliseconds() const;

    // loadSettings: Reads three notification switch settings from Taskbar-specific QSettings.
    void loadSettings();

    // saveSettings: Write the three types of notification switches to Taskbar-specific QSettings.
    void saveSettings() const;

    // registerDeviceNotifications: Registers device messages for USB, disk, and volumes on a hidden window.
    void registerDeviceNotifications();

    // unregisterDeviceNotifications: unregister all previously registered device message handles.
    void unregisterDeviceNotifications();

    TaskbarEarthquakeClient* earthquakeClient_; // Unique process earthquake receiver; not owned by the service for its lifetime.
    QTimer tickTimer_;                           // 100ms carousel and earthquake status refresh timer.
    TaskbarNotificationView currentNotification_; // Current displayed content for all screen sharing sessions.
    QList<TaskbarNotificationView> queue_;       // Pending clipboard and device change messages for display.
    qint64 currentNormalStartedMs_ = 0;          // Monotonic clock start value for current normal notifications.
    qint64 currentNormalDurationMs_ = 6000;      // Current message duration, including a 1-second central region transition budget.
    int notificationDurationSeconds_ = 5;        // Full duration in seconds for standard message body retention; adjustable in the settings page.
    bool earthquakeActive_ = false;              // Earthquake priority mode: when true, normal queue timers are paused.
    bool clipboardNotificationsEnabled_ = true;  // Clipboard text notification toggle.
    bool deviceNotificationsEnabled_ = true;     // Device hot-plug notification switch.
    bool earthquakeNotificationsEnabled_ = true; // Earthquake warning display and audio toggle.
    QWidget* messageWindow_ = nullptr;           // The only hidden native window, responsible for clipboard and device broadcast listening.
    QList<void*> deviceNotificationHandles_;     // Handle returned by RegisterDeviceNotificationW.
    QString lastDeviceNotificationKey_;          // Device message deduplication key (500ms).
    qint64 lastDeviceNotificationMs_ = 0;        // Monotonic clock of the last device message.
};
