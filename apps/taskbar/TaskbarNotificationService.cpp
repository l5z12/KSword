#include "TaskbarNotificationService.h"

#include <QApplication>
#include <QCoreApplication>
#include <QDateTime>
#include <QGuiApplication>
#include <QSettings>
#include <QWidget>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <dbt.h>

#include <shellapi.h>

namespace
{
    // Standard message timing includes a 500ms animation budget for fade-out and 500ms for fade-in in the central area, while the body text remains displayed for the full configured duration.
    constexpr qint64 kNotificationTransitionBudgetMs = 1000;
    constexpr int kDefaultNotificationDurationSeconds = 5;
    constexpr int kMinimumNotificationDurationSeconds = 1;
    constexpr int kMaximumNotificationDurationSeconds = 60;
    constexpr qint64 kDeviceDeduplicationMs = 500;
    constexpr int kMaximumQueuedNotifications = 32;

    // The three GUIDs reuse the local definitions from WindowsMarker to avoid conflicts with SDK macro definitions.
    const GUID kUsbDeviceInterfaceGuid =
        { 0xA5DCBF10, 0x6530, 0x11D2, { 0x90, 0x1F, 0x00, 0xC0, 0x4F, 0xB9, 0x51, 0xED } };
    const GUID kDiskDeviceInterfaceGuid =
        { 0x53F56307, 0xB6BF, 0x11D0, { 0x94, 0xF2, 0x00, 0xA0, 0xC9, 0x1E, 0xFB, 0x8B } };
    const GUID kVolumeDeviceInterfaceGuid =
        { 0x53F5630D, 0xB6BF, 0x11D0, { 0x94, 0xF2, 0x00, 0xA0, 0xC9, 0x1E, 0xFB, 0x8B } };

    // monotonicMilliseconds returns a monotonic clock to prevent notification carousel jumps caused by system time adjustments.
    qint64 monotonicMilliseconds()
    {
        return static_cast<qint64>(::GetTickCount64());
    }

    // truncateText: limits clipboard text by Unicode character count to prevent overflowing the 32px height taskbar.
    QString truncateText(const QString& text, int maximumCharacters)
    {
        if (text.size() <= maximumCharacters)
        {
            return text;
        }
        return text.left(maximumCharacters) + QStringLiteral("...");
    }

    // deviceVolumeDescription converts the DBT_DEVTYP_VOLUME bitmap into a user-readable list of drive letters.
    QString deviceVolumeDescription(ULONG unitMask)
    {
        QStringList drives;
        for (int index = 0; index < 26; ++index)
        {
            if ((unitMask & (1u << index)) != 0)
            {
                drives.push_back(QStringLiteral("%1:").arg(QChar(u'A' + index)));
            }
        }
        return drives.isEmpty() ? QStringLiteral("卷") : QStringLiteral("卷 %1").arg(drives.join(QStringLiteral(", ")));
    }

    // describeDeviceChange converts Windows device broadcast parameters into a compact single-line text suitable for the middle notification bar.
    QString describeDeviceChange(LPARAM lParam)
    {
        if (lParam == 0)
        {
            return QStringLiteral("设备拓扑变化");
        }

        const DEV_BROADCAST_HDR* header = reinterpret_cast<const DEV_BROADCAST_HDR*>(lParam);
        if (header->dbch_devicetype == DBT_DEVTYP_VOLUME)
        {
            const DEV_BROADCAST_VOLUME* volume = reinterpret_cast<const DEV_BROADCAST_VOLUME*>(lParam);
            return deviceVolumeDescription(volume->dbcv_unitmask);
        }

        if (header->dbch_devicetype == DBT_DEVTYP_DEVICEINTERFACE)
        {
            const DEV_BROADCAST_DEVICEINTERFACE_W* device =
                reinterpret_cast<const DEV_BROADCAST_DEVICEINTERFACE_W*>(lParam);
            const QString kPath = QString::fromWCharArray(device->dbcc_name ? device->dbcc_name : L"");
            const QString kKind = kPath.contains(QStringLiteral("USB"), Qt::CaseInsensitive)
                ? QStringLiteral("USB 设备") : QStringLiteral("设备接口");
            if (kPath.isEmpty())
            {
                return kKind;
            }
            return QStringLiteral("%1 %2").arg(kKind, truncateText(kPath, 96));
        }

        return QStringLiteral("设备拓扑变化");
    }
}

TaskbarNotificationService::TaskbarNotificationService(TaskbarEarthquakeClient* earthquakeClient, QObject* parent)
    : QObject(parent)
    , earthquakeClient_(earthquakeClient)
{
    // Read the persisted switch once; these settings are process-scoped, so all screen windows naturally share the same configuration.
    loadSettings();
    if (earthquakeClient_ != nullptr)
    {
        earthquakeClient_->setAlertAudioEnabled(earthquakeNotificationsEnabled_);
    }

    // Create an invisible native window as the sole broadcast receiver to prevent each screen's Taskbar from queuing the same event repeatedly.
    messageWindow_ = new QWidget();
    messageWindow_->setWindowFlags(Qt::Tool | Qt::FramelessWindowHint | Qt::WindowDoesNotAcceptFocus);
    messageWindow_->setAttribute(Qt::WA_DontShowOnScreen, true);
    messageWindow_->setAttribute(Qt::WA_NativeWindow, true);
    messageWindow_->setGeometry(-10000, -10000, 1, 1);
    const HWND kMessageWindowHandle = reinterpret_cast<HWND>(messageWindow_->winId());
    if (kMessageWindowHandle != nullptr)
    {
        ::AddClipboardFormatListener(kMessageWindowHandle);
        registerDeviceNotifications();
    }
    qApp->installNativeEventFilter(this);

    // High-priority earthquake status changes directly preempt the normal queue; source status updates only the settings window diagnostics.
    if (earthquakeClient_ != nullptr)
    {
        connect(earthquakeClient_, &TaskbarEarthquakeClient::activeWarningsChanged, this,
            &TaskbarNotificationService::refreshEarthquakePresentation);
        connect(earthquakeClient_, &TaskbarEarthquakeClient::sourceStatusesChanged, this,
            &TaskbarNotificationService::sourceStatusesChanged);
    }

    // A 100ms interval balances test alert expiration, network event timeouts, and a two-second notification carousel, eliminating the need for a background timer thread.
    tickTimer_.setInterval(100);
    connect(&tickTimer_, &QTimer::timeout, this, &TaskbarNotificationService::advancePresentation);
    tickTimer_.start();
    refreshEarthquakePresentation();
}

TaskbarNotificationService::~TaskbarNotificationService()
{
    // On destruction, remove the native filter first, then unregister notification handles to avoid callbacks to a destroyed service during exit.
    qApp->removeNativeEventFilter(this);
    unregisterDeviceNotifications();
    if (messageWindow_ != nullptr)
    {
        const HWND kMessageWindowHandle = reinterpret_cast<HWND>(messageWindow_->winId());
        if (kMessageWindowHandle != nullptr)
        {
            ::RemoveClipboardFormatListener(kMessageWindowHandle);
        }
        delete messageWindow_;
        messageWindow_ = nullptr;
    }
}

TaskbarNotificationView TaskbarNotificationService::currentNotification() const
{
    // The return value is a lightweight QString value object copy; the caller does not need to synchronize with the service's internal queue.
    return currentNotification_;
}

bool TaskbarNotificationService::hasVisibleNotification() const
{
    // If an earthquake alert or a standard notification has a title, the Taskbar center area should display the notification instead of the time and spectrum.
    return earthquakeActive_ || !currentNotification_.title.isEmpty();
}

bool TaskbarNotificationService::earthquakeActive() const
{
    // The earthquake status is independent of the current body text, ensuring the background theme remains stable when refreshed from multiple sources.
    return earthquakeActive_;
}

bool TaskbarNotificationService::clipboardNotificationsEnabled() const
{
    return clipboardNotificationsEnabled_;
}

bool TaskbarNotificationService::deviceNotificationsEnabled() const
{
    return deviceNotificationsEnabled_;
}

bool TaskbarNotificationService::earthquakeNotificationsEnabled() const
{
    return earthquakeNotificationsEnabled_;
}

int TaskbarNotificationService::notificationDurationSeconds() const
{
    // Returns the standard message body dwell seconds used by the settings page, excluding the central region transition animation.
    return notificationDurationSeconds_;
}

void TaskbarNotificationService::setClipboardNotificationsEnabled(bool enabled)
{
    // Note: Only write to disk and emit signals when the state actually changes to avoid meaningless loops caused by window refreshes.
    if (clipboardNotificationsEnabled_ == enabled)
    {
        return;
    }
    clipboardNotificationsEnabled_ = enabled;
    saveSettings();
    emit settingsChanged();
}

void TaskbarNotificationService::setDeviceNotificationsEnabled(bool enabled)
{
    if (deviceNotificationsEnabled_ == enabled)
    {
        return;
    }
    deviceNotificationsEnabled_ = enabled;
    saveSettings();
    emit settingsChanged();
}

void TaskbarNotificationService::setEarthquakeNotificationsEnabled(bool enabled)
{
    if (earthquakeNotificationsEnabled_ == enabled)
    {
        return;
    }
    earthquakeNotificationsEnabled_ = enabled;
    if (earthquakeClient_ != nullptr)
    {
        earthquakeClient_->setAlertAudioEnabled(enabled);
    }
    saveSettings();
    refreshEarthquakePresentation();
    emit settingsChanged();
}

void TaskbarNotificationService::setNotificationDurationSeconds(int seconds)
{
    // Clamp the input seconds to the range defined in the settings page to prevent abnormal configurations from permanently occupying the taskbar.
    const int kBoundedSeconds = qBound(kMinimumNotificationDurationSeconds,
        seconds, kMaximumNotificationDurationSeconds);
    if (notificationDurationSeconds_ == kBoundedSeconds)
    {
        return;
    }

    notificationDurationSeconds_ = kBoundedSeconds;
    currentNormalDurationMs_ = normalNotificationDurationMilliseconds();
    saveSettings();
    emit settingsChanged();
}

void TaskbarNotificationService::injectTestEarthquake()
{
    // The test button still goes through the unique earthquake client, so all screens enter the exact same alert state simultaneously.
    if (earthquakeClient_ != nullptr)
    {
        earthquakeClient_->injectTestWarning();
    }
}

QList<TaskbarEarthquakeSourceStatus> TaskbarNotificationService::sourceStatuses() const
{
    // Returns an empty list when no client exists, allowing the window to display that the connection feature is unavailable rather than fabricating a status.
    return earthquakeClient_ != nullptr ? earthquakeClient_->sourceStatuses()
        : QList<TaskbarEarthquakeSourceStatus>();
}

bool TaskbarNotificationService::nativeEventFilter(const QByteArray& eventType, void* message, qintptr* result)
{
    // Qt Windows backend delivers MSG via windows_generic_MSG; allow other platforms or event types to pass through directly.
    if (eventType != QByteArrayLiteral("windows_generic_MSG") && eventType != QByteArrayLiteral("windows_dispatcher_MSG"))
    {
        return false;
    }
    return handleNativeMessage(message, result);
}

bool TaskbarNotificationService::handleNativeMessage(void* message, qintptr* result)
{
    MSG* nativeMessage = static_cast<MSG*>(message);
    if (nativeMessage == nullptr || messageWindow_ == nullptr)
    {
        return false;
    }

    const HWND kMessageWindowHandle = reinterpret_cast<HWND>(messageWindow_->winId());
    if (nativeMessage->hwnd != kMessageWindowHandle)
    {
        return false;
    }

    if (nativeMessage->message == WM_CLIPBOARDUPDATE && clipboardNotificationsEnabled_)
    {
        enqueueClipboardText();
    }
    else if (nativeMessage->message == WM_DEVICECHANGE)
    {
        handleDeviceChange(nativeMessage->wParam, nativeMessage->lParam);
    }

    if (result != nullptr)
    {
        *result = 0;
    }
    return false;
}

void TaskbarNotificationService::enqueueClipboardText()
{
    // Extract only CF_UNICODETEXT as requested by the user; do not read files, bitmaps, or icons, and do not display images in the Taskbar.
    const HWND kMessageWindowHandle = messageWindow_ != nullptr ? reinterpret_cast<HWND>(messageWindow_->winId()) : nullptr;
    if (kMessageWindowHandle == nullptr || ::OpenClipboard(kMessageWindowHandle) == FALSE)
    {
        return;
    }

    const HANDLE kClipboardData = ::GetClipboardData(CF_UNICODETEXT);
    const wchar_t* source = kClipboardData != nullptr ? static_cast<const wchar_t*>(::GlobalLock(kClipboardData)) : nullptr;
    if (source == nullptr)
    {
        ::CloseClipboard();
        return;
    }

    QString text = QString::fromWCharArray(source);
    ::GlobalUnlock(kClipboardData);
    ::CloseClipboard();
    text.replace(QChar(u'\r'), QChar(u' '));
    text.replace(QChar(u'\n'), QChar(u' '));
    text.replace(QChar(u'\t'), QChar(u' '));
    text = text.simplified();
    if (text.isEmpty())
    {
        return;
    }

    TaskbarNotificationView notification;
    notification.kind = TaskbarNotificationKind::kClipboard;
    notification.source = QStringLiteral("剪贴板");
    notification.title = QStringLiteral("剪贴板新内容");
    notification.body = truncateText(text, 120);
    enqueueNotification(notification);
}

void TaskbarNotificationService::handleDeviceChange(quintptr wParam, qintptr lParam)
{
    // Only retain device arrival, removal, and topology change messages of interest to WindowsMarker to prevent other device broadcasts from flooding the notification queue.
    if (!deviceNotificationsEnabled_ || (wParam != DBT_DEVICEARRIVAL &&
        wParam != DBT_DEVICEREMOVECOMPLETE && wParam != DBT_DEVNODES_CHANGED))
    {
        return;
    }

    const QString kBody = describeDeviceChange(static_cast<LPARAM>(lParam));
    const QString kKey = QStringLiteral("%1|%2").arg(wParam).arg(kBody);
    const qint64 kNow = monotonicMilliseconds();
    if (kKey == lastDeviceNotificationKey_ && kNow >= lastDeviceNotificationMs_ &&
        kNow - lastDeviceNotificationMs_ < kDeviceDeduplicationMs)
    {
        return;
    }

    lastDeviceNotificationKey_ = kKey;
    lastDeviceNotificationMs_ = kNow;
    TaskbarNotificationView notification;
    notification.kind = TaskbarNotificationKind::kDevice;
    notification.source = QStringLiteral("设备变化");
    notification.title = wParam == DBT_DEVICEARRIVAL ? QStringLiteral("设备接入")
        : (wParam == DBT_DEVICEREMOVECOMPLETE ? QStringLiteral("设备移除") : QStringLiteral("设备变化"));
    notification.body = kBody;
    enqueueNotification(notification);
}

void TaskbarNotificationService::enqueueNotification(const TaskbarNotificationView& notification)
{
    // When an earthquake warning appears, the normal queue can continue accumulating, but display is uniformly paused by the high-priority state.
    if (queue_.size() >= kMaximumQueuedNotifications)
    {
        queue_.removeFirst();
    }
    queue_.push_back(notification);
    if (!earthquakeActive_ && !currentNotification_.title.isEmpty())
    {
        // When a new message enters the queue, the current message continues using the user-configured full retention duration.
        currentNormalDurationMs_ = normalNotificationDurationMilliseconds();
    }
    if (!earthquakeActive_ && currentNotification_.title.isEmpty())
    {
        updateCurrentNormalNotification();
    }
}

void TaskbarNotificationService::updateCurrentNormalNotification()
{
    // Retrieve the first item from the FIFO and set the duration with an animation budget; the full body retention duration in seconds is uniformly controlled by the settings page.
    if (queue_.isEmpty())
    {
        const bool kChanged = !currentNotification_.title.isEmpty();
        currentNotification_ = TaskbarNotificationView();
        currentNormalStartedMs_ = 0;
        if (kChanged)
        {
            emit presentationChanged();
        }
        return;
    }

    currentNotification_ = queue_.takeFirst();
    currentNormalStartedMs_ = monotonicMilliseconds();
    currentNormalDurationMs_ = normalNotificationDurationMilliseconds();
    emit presentationChanged();
}

qint64 TaskbarNotificationService::normalNotificationDurationMilliseconds() const
{
    // Returns the sum of the body dwell seconds and the two central region animation budgets to maintain stable setting semantics.
    return static_cast<qint64>(notificationDurationSeconds_) * 1000 + kNotificationTransitionBudgetMs;
}

void TaskbarNotificationService::advancePresentation()
{
    // At each tick, first check if earthquake activity has changed; if true, intentionally do not advance the normal queue timer.
    refreshEarthquakePresentation();
    if (earthquakeActive_ || currentNotification_.title.isEmpty() || currentNormalStartedMs_ == 0)
    {
        return;
    }

    const qint64 kNow = monotonicMilliseconds();
    if (kNow >= currentNormalStartedMs_ && kNow - currentNormalStartedMs_ >= currentNormalDurationMs_)
    {
        updateCurrentNormalNotification();
    }
}

void TaskbarNotificationService::refreshEarthquakePresentation()
{
    // Immediately take over if a real or test warning exists; restore the normal queue only after cancellation, final report, or timeout expiration.
    const QList<TaskbarEarthquakeEvent> kWarnings = earthquakeClient_ != nullptr && earthquakeNotificationsEnabled_
        ? earthquakeClient_->activeWarnings() : QList<TaskbarEarthquakeEvent>();
    const bool kNextEarthquakeActive = !kWarnings.isEmpty();
    if (kNextEarthquakeActive)
    {
        const TaskbarEarthquakeEvent& event = kWarnings.first();
        TaskbarNotificationView notification;
        notification.kind = TaskbarNotificationKind::kEarthquake;
        notification.source = QStringLiteral("地震预警");
        notification.title = QStringLiteral("地震预警 %1").arg(event.hypoCenter.isEmpty() ? QStringLiteral("震源未知") : event.hypoCenter);
        QStringList details;
        if (!event.magnitudeText.isEmpty())
        {
            details.push_back(QStringLiteral("震级 %1").arg(event.magnitudeText));
        }
        if (!event.depthText.isEmpty())
        {
            details.push_back(QStringLiteral("深度 %1 公里").arg(event.depthText));
        }
        if (event.reportNum > 0)
        {
            details.push_back(QStringLiteral("第 %1 报").arg(event.reportNum));
        }
        notification.body = details.isEmpty() ? QStringLiteral("正在接收预警数据") : details.join(QStringLiteral("  |  "));
        notification.earthquake = true;

        const bool kContentChanged = !earthquakeActive_ || currentNotification_.title != notification.title ||
            currentNotification_.body != notification.body;
        earthquakeActive_ = true;
        currentNotification_ = notification;
        if (kContentChanged)
        {
            emit presentationChanged();
        }
        return;
    }

    if (earthquakeActive_)
    {
        // Immediately publish the next state upon leaving earthquake mode; each Taskbar UI handles a 0.5s fade-out of the alert followed by a fade-in of the next page.
        earthquakeActive_ = false;
        currentNotification_ = TaskbarNotificationView();
        currentNormalStartedMs_ = 0;
        if (!queue_.isEmpty())
        {
            currentNotification_ = queue_.takeFirst();
            currentNormalStartedMs_ = monotonicMilliseconds();
            currentNormalDurationMs_ = normalNotificationDurationMilliseconds();
        }
        emit presentationChanged();
    }
}

void TaskbarNotificationService::loadSettings()
{
    // Taskbar uses IniFormat independently to prevent the main process's global configuration or registry paths from affecting this lightweight resident module.
    QSettings settings(QCoreApplication::applicationDirPath() + QStringLiteral("/TaskbarNotifications.ini"),
        QSettings::IniFormat);
    clipboardNotificationsEnabled_ = settings.value(QStringLiteral("notifications/clipboardEnabled"), true).toBool();
    deviceNotificationsEnabled_ = settings.value(QStringLiteral("notifications/deviceEnabled"), true).toBool();
    earthquakeNotificationsEnabled_ = settings.value(QStringLiteral("notifications/earthquakeEnabled"), true).toBool();
    notificationDurationSeconds_ = qBound(kMinimumNotificationDurationSeconds,
        settings.value(QStringLiteral("notifications/durationSeconds"), kDefaultNotificationDurationSeconds).toInt(),
        kMaximumNotificationDurationSeconds);
    currentNormalDurationMs_ = normalNotificationDurationMilliseconds();
}

void TaskbarNotificationService::saveSettings() const
{
    // Only write the three switches and one duration setting to TaskbarNotifications.ini; do not touch WindowsMarker or the main program configuration file.
    QSettings settings(QCoreApplication::applicationDirPath() + QStringLiteral("/TaskbarNotifications.ini"),
        QSettings::IniFormat);
    settings.setValue(QStringLiteral("notifications/clipboardEnabled"), clipboardNotificationsEnabled_);
    settings.setValue(QStringLiteral("notifications/deviceEnabled"), deviceNotificationsEnabled_);
    settings.setValue(QStringLiteral("notifications/earthquakeEnabled"), earthquakeNotificationsEnabled_);
    settings.setValue(QStringLiteral("notifications/durationSeconds"), notificationDurationSeconds_);
    settings.sync();
}

void TaskbarNotificationService::registerDeviceNotifications()
{
    // Registers three interface types and volume broadcast on the unique hidden window; Taskbar windows on each screen do not directly subscribe to device messages.
    const HWND kMessageWindowHandle = messageWindow_ != nullptr ? reinterpret_cast<HWND>(messageWindow_->winId()) : nullptr;
    if (kMessageWindowHandle == nullptr)
    {
        return;
    }

    const GUID* interfaceClasses[] = {
        &kUsbDeviceInterfaceGuid,
        &kDiskDeviceInterfaceGuid,
        &kVolumeDeviceInterfaceGuid
    };
    for (const GUID* interfaceClass : interfaceClasses)
    {
        DEV_BROADCAST_DEVICEINTERFACE_W filter = {};
        filter.dbcc_size = sizeof(filter);
        filter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
        filter.dbcc_classguid = *interfaceClass;
        HDEVNOTIFY handle = ::RegisterDeviceNotificationW(kMessageWindowHandle, &filter, DEVICE_NOTIFY_WINDOW_HANDLE);
        if (handle != nullptr)
        {
            deviceNotificationHandles_.push_back(handle);
        }
    }

    DEV_BROADCAST_VOLUME volumeFilter = {};
    volumeFilter.dbcv_size = sizeof(volumeFilter);
    volumeFilter.dbcv_devicetype = DBT_DEVTYP_VOLUME;
    HDEVNOTIFY volumeHandle = ::RegisterDeviceNotificationW(kMessageWindowHandle, &volumeFilter, DEVICE_NOTIFY_WINDOW_HANDLE);
    if (volumeHandle != nullptr)
    {
        deviceNotificationHandles_.push_back(volumeHandle);
    }
}

void TaskbarNotificationService::unregisterDeviceNotifications()
{
    // Unregister in registration order before exit; failure only indicates that Windows has already released the associated device state.
    for (void* rawHandle : deviceNotificationHandles_)
    {
        if (rawHandle != nullptr)
        {
            ::UnregisterDeviceNotification(static_cast<HDEVNOTIFY>(rawHandle));
        }
    }
    deviceNotificationHandles_.clear();
}
