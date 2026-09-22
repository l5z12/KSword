#include "Taskbar.h"
#include "Function.h"
#include "Override.h"
#include "TaskbarSettingsDialog.h"

#include <windows.h>
#include <shellapi.h>
#include <cmath>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QWidget>
#include <QPixmap>
#include <QStyle>
#include <qpushbutton.h>
#include <qtimer.h>
#include <QDateTime>
#include <QCoreApplication>
#include <QAbstractAnimation>
#include <QGraphicsOpacityEffect>
#include <QEasingCurve>
#include <QPropertyAnimation>
#include <QSizePolicy>
#include <QStackedLayout>
#include <QProcessEnvironment>
#include <QResizeEvent>
#include <Qscreen.h>
#include <QVariantAnimation>

#pragma comment(lib, "shell32.lib")

namespace {
constexpr int kTaskbarLogicalHeight = 32;
constexpr int kTaskbarOuterMargin = 2;
constexpr int kTaskbarContentHeight = kTaskbarLogicalHeight - (kTaskbarOuterMargin * 2);
constexpr int kMinimumSpectrumWidth = 80;
constexpr int kLargeScreenSpectrumMinimumWidth = 220;
constexpr int kMaximumSpectrumWidth = 320;
constexpr int kCompactScreenNonSpectrumBudget = 620;

struct MonitorSearchContext {
    QString targetName;
    QRect nativeGeometry;
    bool found;
};

// resolveCurrentUserNameText:
// - Input: None; reads current process environment variables and Win32 username API;
// - Processing: Prefer USERNAME; if that fails, call GetUserNameW, and finally provide a stable fallback.
// - Returns: The current logged-in username for the identity text on the left side of the taskbar.
QString resolveCurrentUserNameText()
{
    const QString kEnvUserNameText =
        QProcessEnvironment::systemEnvironment().value(QStringLiteral("USERNAME")).trimmed();
    if (!kEnvUserNameText.isEmpty()) {
        return kEnvUserNameText;
    }

    wchar_t userNameBuffer[256] = {};
    DWORD bufferLength = static_cast<DWORD>(std::size(userNameBuffer));
    if (::GetUserNameW(userNameBuffer, &bufferLength) != FALSE) {
        const QString kApiUserNameText = QString::fromWCharArray(userNameBuffer).trimmed();
        if (!kApiUserNameText.isEmpty()) {
            return kApiUserNameText;
        }
    }

    return QStringLiteral("UnknownUser");
}

// Win32 monitor enumeration callback: input is an HMONITOR and caller context;
// processing compares MONITORINFOEX device names; return value controls enumeration continuation.
BOOL CALLBACK findMonitorByDisplayName(HMONITOR monitor, HDC, LPRECT, LPARAM userData)
{
    MonitorSearchContext* context = reinterpret_cast<MonitorSearchContext*>(userData);
    if (!context || context->targetName.isEmpty()) {
        return TRUE;
    }

    MONITORINFOEXW monitorInfo = {};
    monitorInfo.cbSize = sizeof(monitorInfo);
    if (!GetMonitorInfoW(monitor, &monitorInfo)) {
        return TRUE;
    }

    const QString kMonitorName = QString::fromWCharArray(monitorInfo.szDevice).trimmed().toUpper();
    if (kMonitorName != context->targetName) {
        return TRUE;
    }

    const RECT& nativeRect = monitorInfo.rcMonitor;
    context->nativeGeometry = QRect(
        nativeRect.left,
        nativeRect.top,
        nativeRect.right - nativeRect.left,
        nativeRect.bottom - nativeRect.top
    );
    context->found = true;
    return FALSE;
}

// Validate a device pixel ratio: input is a Qt DPR value; processing rejects invalid values;
// return value is a positive scale factor suitable for pixel conversion.
qreal safeDevicePixelRatio(qreal devicePixelRatio)
{
    if (!std::isfinite(devicePixelRatio) || devicePixelRatio <= 0.0) {
        return 1.0;
    }
    return devicePixelRatio;
}

// Convert a logical length to native pixels: input is a Qt DIP length and DPR; processing rounds
// to the nearest physical pixel; return value is at least 1 pixel for non-empty AppBar reservation.
int logicalLengthToNativePixels(int logicalLength, qreal devicePixelRatio)
{
    return qMax(1, qRound(static_cast<qreal>(logicalLength) * safeDevicePixelRatio(devicePixelRatio)));
}

// Convert a Qt logical rectangle to native pixels: input is a DIP rectangle and DPR; processing
// scales origin and size; return value uses Win32-style physical pixel units.
QRect logicalRectToNativePixels(const QRect& logicalRect, qreal devicePixelRatio)
{
    const qreal kDpr = safeDevicePixelRatio(devicePixelRatio);
    return QRect(
        qRound(static_cast<qreal>(logicalRect.x()) * kDpr),
        qRound(static_cast<qreal>(logicalRect.y()) * kDpr),
        qRound(static_cast<qreal>(logicalRect.width()) * kDpr),
        qRound(static_cast<qreal>(logicalRect.height()) * kDpr)
    );
}

// normalize a Qt screen name to the Win32 MONITORINFOEX device form: input is either
// "DISPLAY1" or "\\.\DISPLAY1"; processing adds the missing prefix; return value is uppercase.
QString normalizeDisplayDeviceNameForWin32(const QString& displayName)
{
    QString normalizedName = displayName.trimmed().replace('/', '\\').toUpper();
    const QString kWin32Prefix = QStringLiteral("\\\\.\\");
    if (!normalizedName.isEmpty() && !normalizedName.startsWith(kWin32Prefix)) {
        normalizedName.prepend(kWin32Prefix);
    }
    return normalizedName;
}

// Resolve the monitor under a native point: input is a physical-pixel point; processing queries
// MonitorFromPoint and GetMonitorInfo; return value is the monitor rectangle or an invalid rect.
QRect nativeMonitorGeometryFromPoint(const QPoint& nativePoint)
{
    POINT point = { nativePoint.x(), nativePoint.y() };
    HMONITOR monitor = MonitorFromPoint(point, MONITOR_DEFAULTTONULL);
    if (!monitor) {
        return QRect();
    }

    MONITORINFOEXW monitorInfo = {};
    monitorInfo.cbSize = sizeof(monitorInfo);
    if (!GetMonitorInfoW(monitor, &monitorInfo)) {
        return QRect();
    }

    const RECT& nativeRect = monitorInfo.rcMonitor;
    return QRect(
        nativeRect.left,
        nativeRect.top,
        nativeRect.right - nativeRect.left,
        nativeRect.bottom - nativeRect.top
    );
}

// Resolve the monitor containing a window: input is an HWND; processing asks Win32 for the
// nearest monitor and reads MONITORINFOEX; return value is the monitor rectangle or invalid.
QRect nativeMonitorGeometryFromWindow(HWND windowHandle)
{
    if (!windowHandle) {
        return QRect();
    }

    HMONITOR monitor = MonitorFromWindow(windowHandle, MONITOR_DEFAULTTONULL);
    if (!monitor) {
        return QRect();
    }

    MONITORINFOEXW monitorInfo = {};
    monitorInfo.cbSize = sizeof(monitorInfo);
    if (!GetMonitorInfoW(monitor, &monitorInfo)) {
        return QRect();
    }

    const RECT& nativeRect = monitorInfo.rcMonitor;
    return QRect(
        nativeRect.left,
        nativeRect.top,
        nativeRect.right - nativeRect.left,
        nativeRect.bottom - nativeRect.top
    );
}

// Map an AppBar rectangle from native monitor coordinates into Qt logical coordinates: input is
// the native AppBar rect plus native/logical monitor rects; processing converts only per-monitor
// offsets, not global desktop origin; return value is safe for mixed-DPI multi-monitor layouts.
QRect mapNativeAppBarRectToLogicalScreen(const QRect& nativeAppBarRect,
                                         const QRect& nativeScreenRect,
                                         const QRect& logicalScreenRect,
                                         qreal devicePixelRatio)
{
    const qreal kDpr = safeDevicePixelRatio(devicePixelRatio);
    const int kLogicalLeft = logicalScreenRect.left()
        + qRound(static_cast<qreal>(nativeAppBarRect.left() - nativeScreenRect.left()) / kDpr);
    const int kLogicalTop = logicalScreenRect.top()
        + qRound(static_cast<qreal>(nativeAppBarRect.top() - nativeScreenRect.top()) / kDpr);
    const int kLogicalWidth = qRound(static_cast<qreal>(nativeAppBarRect.width()) / kDpr);
    const int kLogicalHeight = qRound(static_cast<qreal>(nativeAppBarRect.height()) / kDpr);

    return QRect(kLogicalLeft, kLogicalTop, kLogicalWidth, kLogicalHeight);
}

// Check system window management commands: The Taskbar is a fixed top AppBar that does not
// accept external window state changes such as minimize, maximize, restore, move, or resize.
bool isIgnoredTaskbarSystemCommand(WPARAM command)
{
    switch (static_cast<UINT_PTR>(command) & 0xFFF0U) {
    case SC_MINIMIZE:
    case SC_MAXIMIZE:
    case SC_RESTORE:
    case SC_MOVE:
    case SC_SIZE:
        return true;
    default:
        return false;
    }
}
}

bool Taskbar::nativeEvent(const QByteArray& eventType, void* message, qintptr* result)
{
    Q_UNUSED(eventType);

    MSG* msg = static_cast<MSG*>(message);
    if (msg == nullptr) {
        return QMainWindow::nativeEvent(eventType, message, result);
    }

    // Win+D minimizes regular top-level windows via SC_MINIMIZE. The Taskbar, as an AppBar, must
    // remain visible, so ignore this command and other system commands that change window state.
    if (msg->message == WM_SYSCOMMAND && isIgnoredTaskbarSystemCommand(msg->wParam)) {
        if (result != nullptr) {
            *result = 0;
        }
        return true;
    }

    // Handles this in coordination with the system command above to prevent other window management paths from minimizing the AppBar.
    if (msg->message == WM_SIZE && msg->wParam == SIZE_MINIMIZED) {
        if (result != nullptr) {
            *result = 0;
        }
        return true;
    }

    if (msg->message == appBarMessageId_) {
        // Handle app bar notifications.
        if (msg->wParam == ABN_POSCHANGED) {
            // Re-adjust on position change.
            registerAsAppBar();
        }
        if (result != nullptr) {
            *result = 0;
        }
        return true;
    }

    return QMainWindow::nativeEvent(eventType, message, result);
}

Taskbar::Taskbar(QScreen* targetScreen, TaskbarSharedState* sharedState,
                 TaskbarNotificationService* notificationService, QWidget* parent)
    : QMainWindow(parent)
    , leftSpectrum_(nullptr)
    , rightSpectrum_(nullptr)
    , sharedState_(sharedState)
    , notificationService_(notificationService)
    , targetScreenGeometry_(targetScreen ? targetScreen->geometry() : QRect())
    , targetScreenName_(targetScreen ? targetScreen->name() : QString())
    , targetDevicePixelRatio_(targetScreen ? targetScreen->devicePixelRatio() : 1.0)
    , cpuBarContainer_(nullptr)
    , timer_(nullptr)
    , timeLabel_(nullptr)
    , contentLabel_(nullptr)
    , logoLabel_(nullptr)
    , networkSpeedContainer_(nullptr)
    , uploadSpeedLabel_(nullptr)
    , downloadSpeedLabel_(nullptr)
    , networkUiTimer_(nullptr)
    , isAppBarRegistered_(false)
    , centralWidget_(nullptr)
    , normalCenterWidget_(nullptr)
    , notificationCenterWidget_(nullptr)
    , centerStackLayout_(nullptr)
    , normalCenterOpacity_(nullptr)
    , notificationCenterOpacity_(nullptr)
    , notificationSourceLabel_(nullptr)
    , notificationTitleLabel_(nullptr)
    , notificationBodyLabel_(nullptr)
    , notificationVisible_(false)
    , earthquakePresentation_(false)
    , alertFlashAnimation_(nullptr)
    , alertFlashBright_(false)
    , notificationFlashWidget_(nullptr)
    , notificationFlashOpacity_(nullptr)
    , notificationFlashAnimation_(nullptr)
    , rightBtnContainer_(nullptr)
    , rightBtnLayout_(nullptr)
    , exitBtn_(nullptr)
    , lockBtn_(nullptr)
    , toolBtn_(nullptr)
    , settingsBtn_(nullptr)
    , userBtn_(nullptr)
    , settingsDialog_(nullptr)
    , appBarMessageId_(0)
    , cpuUpdateTimer_(nullptr)
{
    // The Taskbar creates a separate AppBar window for each QScreen, but central notification content and alert status are shared by a global service.
    setWindowFlags(Qt::FramelessWindowHint | Qt::WindowStaysOnTopHint | Qt::ToolTip);
    setFixedHeight(kTaskbarLogicalHeight);
    setAttribute(Qt::WA_TranslucentBackground, false);

    centralWidget_ = new QWidget(this);
    QVBoxLayout* vLayout = new QVBoxLayout(centralWidget_);
    vLayout->setContentsMargins(0, 0, 0, 0);
    vLayout->setSpacing(0);
    vLayout->setSizeConstraint(QLayout::SetNoConstraint);
    centralWidget_->setLayout(vLayout);

    QHBoxLayout* hLayout = new QHBoxLayout();
    hLayout->setContentsMargins(2, 2, 2, 2);
    hLayout->setSpacing(5);

    // The left-side logo is colored by applyTaskbarTheme for non-transparent pixels only in alert mode.
    logoLabel_ = new QLabel(centralWidget_);
    logoPixmap_ = QPixmap(":/Image/Resource/Image/MainLogo.png");
    if (!logoPixmap_.isNull()) {
        logoLabel_->setFixedHeight(kTaskbarContentHeight);
        logoLabel_->setMinimumWidth(1);
        logoLabel_->setPixmap(logoPixmap_.scaled(QSize(QWIDGETSIZE_MAX, logoLabel_->height()),
            Qt::KeepAspectRatio, Qt::SmoothTransformation));
        logoLabel_->setAlignment(Qt::AlignCenter);
    }
    hLayout->addWidget(logoLabel_);

    contentLabel_ = new QLabel(centralWidget_);
    contentLabel_->setText(QStringLiteral("· %1 [Dev].").arg(resolveCurrentUserNameText()));
    contentLabel_->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    hLayout->addWidget(contentLabel_);
    hLayout->addStretch(1);

    // The normal tab continues using the original dual spectrum and clock; the notification tab is fully overlaid on it without changing the taskbar width or AppBar geometry.
    leftSpectrum_ = new SpectrumWidget(SpectrumWidget::kCenterToLeft, this);
    rightSpectrum_ = new SpectrumWidget(SpectrumWidget::kCenterToRight, this);
    leftSpectrum_->setFixedHeight(kTaskbarContentHeight);
    rightSpectrum_->setFixedHeight(kTaskbarContentHeight);
    leftSpectrum_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    rightSpectrum_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    timeLabel_ = new QLabel(centralWidget_);
    timeLabel_->setAlignment(Qt::AlignCenter);
    timeLabel_->setMinimumWidth(52);

    QWidget* centerHost = new QWidget(centralWidget_);
    centerHost->setMinimumWidth(spectrumMinimumWidthForScreen() * 2 + timeLabel_->minimumWidth());
    centerHost->setMaximumWidth(spectrumMaximumWidthForScreen() * 2 + timeLabel_->minimumWidth());
    centerHost->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    centerStackLayout_ = new QStackedLayout(centerHost);
    centerStackLayout_->setContentsMargins(0, 0, 0, 0);
    centerStackLayout_->setStackingMode(QStackedLayout::StackAll);

    normalCenterWidget_ = new QWidget(centerHost);
    QHBoxLayout* spectrumTimeLayout = new QHBoxLayout(normalCenterWidget_);
    spectrumTimeLayout->setContentsMargins(0, 0, 0, 0);
    spectrumTimeLayout->setSpacing(0);
    spectrumTimeLayout->addWidget(leftSpectrum_);
    spectrumTimeLayout->addWidget(timeLabel_);
    spectrumTimeLayout->addWidget(rightSpectrum_);

    notificationCenterWidget_ = new QWidget(centerHost);
    QHBoxLayout* notificationLayout = new QHBoxLayout(notificationCenterWidget_);
    notificationLayout->setContentsMargins(4, 0, 4, 0);
    notificationLayout->setSpacing(5);
    notificationSourceLabel_ = new QLabel(notificationCenterWidget_);
    notificationSourceLabel_->setFixedWidth(52);
    notificationSourceLabel_->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    notificationTitleLabel_ = new QLabel(notificationCenterWidget_);
    notificationTitleLabel_->setMinimumWidth(84);
    notificationTitleLabel_->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    notificationBodyLabel_ = new QLabel(notificationCenterWidget_);
    notificationBodyLabel_->setMinimumWidth(0);
    notificationBodyLabel_->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    notificationBodyLabel_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    notificationBodyLabel_->setTextFormat(Qt::PlainText);
    notificationLayout->addWidget(notificationSourceLabel_);
    notificationLayout->addWidget(notificationTitleLabel_);
    notificationLayout->addWidget(notificationBodyLabel_, 1);

    normalCenterOpacity_ = new QGraphicsOpacityEffect(normalCenterWidget_);
    normalCenterOpacity_->setOpacity(1.0);
    normalCenterWidget_->setGraphicsEffect(normalCenterOpacity_);
    notificationCenterOpacity_ = new QGraphicsOpacityEffect(notificationCenterWidget_);
    notificationCenterOpacity_->setOpacity(0.0);
    notificationCenterWidget_->setGraphicsEffect(notificationCenterOpacity_);
    centerStackLayout_->addWidget(normalCenterWidget_);
    centerStackLayout_->addWidget(notificationCenterWidget_);
    hLayout->addWidget(centerHost);
    hLayout->addStretch(1);

    // CPU and network sampling still directly read existing shared state objects without creating additional sampling threads due to the notification module.
    cpuBarContainer_ = new QWidget(centralWidget_);
    QHBoxLayout* cpuBarLayout = new QHBoxLayout(cpuBarContainer_);
    cpuBarLayout->setContentsMargins(3, 3, 3, 3);
    cpuBarLayout->setSpacing(2);
    SYSTEM_INFO sysInfo = {};
    GetSystemInfo(&sysInfo);
    const int kCoreCount = static_cast<int>(sysInfo.dwNumberOfProcessors);
    cpuBars_.resize(kCoreCount);
    for (int index = 0; index < kCoreCount; ++index) {
        QLabel* bar = new QLabel(cpuBarContainer_);
        bar->setAlignment(Qt::AlignBottom);
        cpuBars_[index] = bar;
        cpuBarLayout->addWidget(bar, 0, Qt::AlignBottom);
    }
    hLayout->addWidget(cpuBarContainer_);

    networkSpeedContainer_ = new QWidget(centralWidget_);
    networkSpeedContainer_->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Preferred);
    networkSpeedContainer_->setMinimumWidth(74);
    QVBoxLayout* networkSpeedLayout = new QVBoxLayout(networkSpeedContainer_);
    networkSpeedLayout->setContentsMargins(2, 2, 2, 2);
    networkSpeedLayout->setSpacing(0);
    uploadSpeedLabel_ = new QLabel(networkSpeedContainer_);
    downloadSpeedLabel_ = new QLabel(networkSpeedContainer_);
    uploadSpeedLabel_->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    downloadSpeedLabel_->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    networkSpeedLayout->addWidget(uploadSpeedLabel_);
    networkSpeedLayout->addWidget(downloadSpeedLabel_);
    hLayout->addWidget(networkSpeedContainer_);

    // Hover tooltips are provided for all top-right icon buttons; icons use the existing Taskbar SVG resource library rather than WindowsMarker icons.
    const QSize kIconSize(20, 20);
    rightBtnContainer_ = new QWidget(centralWidget_);
    rightBtnContainer_->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Preferred);
    rightBtnLayout_ = new QHBoxLayout(rightBtnContainer_);
    rightBtnLayout_->setContentsMargins(0, 0, 0, 0);
    rightBtnLayout_->setSpacing(1);
    lockBtn_ = new GlowIconButton(":/Icon/Resource/Icon/lock_line.svg", kIconSize, rightBtnContainer_);
    lockBtn_->setToolTip(QStringLiteral("锁定工作站"));
    toolBtn_ = new GlowIconButton(":/Icon/Resource/Icon/tool_line.svg", kIconSize, rightBtnContainer_);
    toolBtn_->setToolTip(QStringLiteral("打开命令提示符"));
    settingsBtn_ = new GlowIconButton(":/Icon/Resource/svg/system/settings_6_line.svg", kIconSize, rightBtnContainer_);
    settingsBtn_->setToolTip(QStringLiteral("通知设置"));
    userBtn_ = new GlowIconButton(":/Icon/Resource/Icon/user_2_line.svg", kIconSize, rightBtnContainer_);
    userBtn_->setToolTip(QStringLiteral("用户自定义功能"));
    exitBtn_ = new GlowIconButton(":/Icon/Resource/Icon/exit_fill.svg", kIconSize, rightBtnContainer_);
    exitBtn_->setToolTip(QStringLiteral("退出任务栏"));
    rightBtnLayout_->addWidget(lockBtn_);
    rightBtnLayout_->addWidget(toolBtn_);
    rightBtnLayout_->addWidget(settingsBtn_);
    rightBtnLayout_->addWidget(userBtn_);
    rightBtnLayout_->addWidget(exitBtn_);
    rightBtnLayout_->setAlignment(Qt::AlignRight);
    connect(lockBtn_, &QPushButton::clicked, lockWorkstation);
    connect(toolBtn_, &QPushButton::clicked, openCmd);
    connect(settingsBtn_, &QPushButton::clicked, this, &Taskbar::showSettingsDialog);
    connect(userBtn_, &QPushButton::clicked, userCustomFunction);
    connect(exitBtn_, &QPushButton::clicked, this, &Taskbar::onExitClicked);
    hLayout->addWidget(rightBtnContainer_);

    vLayout->addLayout(hLayout);
    setCentralWidget(centralWidget_);

    // The new message highlight layer covers the entire Taskbar but is set to mouse-transparent to avoid blocking interactions with the right-side buttons.
    notificationFlashWidget_ = new QWidget(centralWidget_);
    notificationFlashWidget_->setAttribute(Qt::WA_TransparentForMouseEvents, true);
    notificationFlashWidget_->setStyleSheet(QStringLiteral("background-color: rgba(255, 255, 255, 32);"));
    notificationFlashWidget_->setGeometry(centralWidget_->rect());
    notificationFlashWidget_->raise();
    notificationFlashOpacity_ = new QGraphicsOpacityEffect(notificationFlashWidget_);
    notificationFlashOpacity_->setOpacity(0.0);
    notificationFlashWidget_->setGraphicsEffect(notificationFlashOpacity_);
    notificationFlashAnimation_ = new QPropertyAnimation(notificationFlashOpacity_, "opacity", this);
    notificationFlashAnimation_->setDuration(500);
    notificationFlashAnimation_->setEasingCurve(QEasingCurve::Linear);

    // Earthquake alerts use a color value animation: a gradient from bright red to dark red, with the transition from dark red back to bright red occurring only instantaneously at animation cycle boundaries.
    alertFlashAnimation_ = new QVariantAnimation(this);
    alertFlashAnimation_->setDuration(500);
    alertFlashAnimation_->setEasingCurve(QEasingCurve::Linear);
    connect(alertFlashAnimation_, &QVariantAnimation::valueChanged, this, [this](const QVariant& value) {
        if (earthquakePresentation_)
        {
            applyTaskbarTheme(true, value.value<QColor>());
        }
    });
    connect(alertFlashAnimation_, &QVariantAnimation::finished, this, [this]() {
        if (!earthquakePresentation_)
        {
            return;
        }
        alertFlashBright_ = false;
        applyTaskbarTheme(true, QColor(QStringLiteral("#480000")));
        alertFlashBright_ = true;
        applyTaskbarTheme(true, QColor(QStringLiteral("#D90000")));
        startAlertFlashCycle();
    });
    applyTaskbarTheme(false, QColor(QStringLiteral("#0A0F16")));

    // Maintain existing spectrum, time, CPU, and network refresh rhythms; the notification service only adds its own lightweight UI state signals.
    if (sharedState_) {
        connect(sharedState_, &TaskbarSharedState::spectrumDataReady, this,
            &Taskbar::onSpectrumDataReady, Qt::QueuedConnection);
    }
    timer_ = new QTimer(this);
    timer_->setInterval(500);
    connect(timer_, &QTimer::timeout, this, &Taskbar::updateTime);
    timer_->start();
    updateTime();
    cpuUpdateTimer_ = new QTimer(this);
    cpuUpdateTimer_->setInterval(200);
    connect(cpuUpdateTimer_, &QTimer::timeout, this, &Taskbar::updateCPUUsage);
    cpuUpdateTimer_->start();
    updateCPUUsage();
    networkUiTimer_ = new QTimer(this);
    networkUiTimer_->setInterval(250);
    connect(networkUiTimer_, &QTimer::timeout, this, &Taskbar::updateNetworkSpeedLabels);
    networkUiTimer_->start();
    updateNetworkSpeedLabels();

    if (notificationService_ != nullptr) {
        connect(notificationService_, &TaskbarNotificationService::presentationChanged, this,
            &Taskbar::onNotificationPresentationChanged);
        updateNotificationPresentation();
    }
    registerAsAppBar();
}

int Taskbar::appBarThicknessInNativePixels() const
{
    // Input: none. Processing: convert the visible Qt taskbar height from device-independent
    // pixels to Win32 native pixels. Return: AppBar reservation height in physical pixels.
    return logicalLengthToNativePixels(height(), targetDevicePixelRatio_);
}

QRect Taskbar::targetScreenNativeGeometry() const
{
    // Input: none. Processing: prefer MONITORINFOEX because SHAppBarMessage consumes physical
    // monitor coordinates; fall back to Qt geometry scaled by DPR. Return: native monitor rect.
    const QString kNormalizedTargetName = normalizeDisplayDeviceNameForWin32(targetScreenName_);
    if (!kNormalizedTargetName.isEmpty()) {
        MonitorSearchContext context = { kNormalizedTargetName, QRect(), false };
        EnumDisplayMonitors(nullptr, nullptr, findMonitorByDisplayName, reinterpret_cast<LPARAM>(&context));
        if (context.found && context.nativeGeometry.isValid()) {
            return context.nativeGeometry;
        }
    }

    if (targetScreenGeometry_.isValid()) {
        const QRect kWindowMonitorGeometry = nativeMonitorGeometryFromWindow(reinterpret_cast<HWND>(winId()));
        if (kWindowMonitorGeometry.isValid()) {
            return kWindowMonitorGeometry;
        }

        const QPoint kLogicalCenter = targetScreenGeometry_.center();
        const QPoint kNativeCenter(
            qRound(static_cast<qreal>(kLogicalCenter.x()) * safeDevicePixelRatio(targetDevicePixelRatio_)),
            qRound(static_cast<qreal>(kLogicalCenter.y()) * safeDevicePixelRatio(targetDevicePixelRatio_))
        );
        const QRect kNativeMonitorGeometry = nativeMonitorGeometryFromPoint(kNativeCenter);
        if (kNativeMonitorGeometry.isValid()) {
            return kNativeMonitorGeometry;
        }

        return logicalRectToNativePixels(targetScreenGeometry_, targetDevicePixelRatio_);
    }

    if (screen()) {
        return logicalRectToNativePixels(screen()->geometry(), screen()->devicePixelRatio());
    }

    return QRect(0, 0, 1920, appBarThicknessInNativePixels());
}

QRect Taskbar::targetScreenLogicalGeometry() const
{
    // Input: none. Processing: use the constructor-bound QScreen geometry for stable multi-monitor
    // placement, with the live QWidget screen as a fallback. Return: Qt logical screen rectangle.
    if (targetScreenGeometry_.isValid()) {
        return targetScreenGeometry_;
    }

    if (screen()) {
        return screen()->geometry();
    }

    return QRect(0, 0, 1920, kTaskbarLogicalHeight);
}

int Taskbar::spectrumMinimumWidthForScreen() const
{
    // Input: none. Processing: reserve room for fixed logo/text/CPU/network/buttons first, then
    // allow both spectrum widgets to shrink on compact screens. Return: minimum spectrum width.
    const int kLogicalScreenWidth = targetScreenGeometry_.isValid()
        ? targetScreenGeometry_.width()
        : 1920;
    const int kAvailableForEachSpectrum =
        (kLogicalScreenWidth - kCompactScreenNonSpectrumBudget) / 2;

    return qBound(
        kMinimumSpectrumWidth,
        kAvailableForEachSpectrum,
        kLargeScreenSpectrumMinimumWidth
    );
}

int Taskbar::spectrumMaximumWidthForScreen() const
{
    // Input: none. Processing: keep the middle audio visualizer elastic but bounded, so the
    // surrounding spacers absorb wide-screen slack instead of pushing fixed content outward.
    // Return: maximum spectrum width.
    return qMax(spectrumMinimumWidthForScreen(), kMaximumSpectrumWidth);
}

void Taskbar::registerAsAppBar()
{
    // Input: none. Processing: register/update a top-edge AppBar using Win32 native-pixel
    // coordinates, then position the Qt window in the same native rectangle. Return: none.
    const QRect kLogicalScreenGeometry = targetScreenLogicalGeometry();
    setGeometry(
        kLogicalScreenGeometry.left(),
        kLogicalScreenGeometry.top(),
        kLogicalScreenGeometry.width(),
        height()
    );

    APPBARDATA abd = { 0 };
    abd.cbSize = sizeof(APPBARDATA);
    abd.hWnd = (HWND)winId();

    if (appBarMessageId_ == 0) {
        appBarMessageId_ = RegisterWindowMessageA("KswordTaskbarAppBarMessage");
    }
    abd.uCallbackMessage = appBarMessageId_;

    if (!isAppBarRegistered_) {
        SHAppBarMessage(ABM_NEW, &abd);
        isAppBarRegistered_ = true;
    }

    abd.uEdge = ABE_TOP;

    const QRect kScreenGeometry = targetScreenNativeGeometry();
    const int kAppBarThickness = appBarThicknessInNativePixels();

    abd.rc.left = kScreenGeometry.left();
    abd.rc.top = kScreenGeometry.top();
    abd.rc.right = kScreenGeometry.right() + 1;
    abd.rc.bottom = kScreenGeometry.top() + kAppBarThickness;

    SHAppBarMessage(ABM_QUERYPOS, &abd);
    abd.rc.bottom = abd.rc.top + kAppBarThickness;
    SHAppBarMessage(ABM_SETPOS, &abd);

    const QRect kNativeAppBarRect(
        abd.rc.left,
        abd.rc.top,
        abd.rc.right - abd.rc.left,
        abd.rc.bottom - abd.rc.top
    );
    const QRect kLogicalAppBarRect = mapNativeAppBarRectToLogicalScreen(
        kNativeAppBarRect,
        kScreenGeometry,
        kLogicalScreenGeometry,
        targetDevicePixelRatio_
    );

    setGeometry(kLogicalAppBarRect.left(), kLogicalAppBarRect.top(), kLogicalAppBarRect.width(), height());
}

Taskbar::~Taskbar()
{
    // The destructor only unregisters this window's AppBar; shared sampling is managed by TaskbarSharedState.
    removeAppBar();
}

void Taskbar::onExitClicked()
{
    // The primary goal of the exit button is to terminate the process: trigger the shutdown flow first, then exit the event loop.
    close();
    QCoreApplication::quit();
}

void Taskbar::closeEvent(QCloseEvent* event)
{
    // Closing the window unregisters only this window's AppBar to avoid affecting windows on other monitors.
    removeAppBar();

    event->accept();
    QMainWindow::closeEvent(event);
}

void Taskbar::removeAppBar()
{
    // Input is empty; handle the current window's AppBar unregistration; no return value.
    if (!isAppBarRegistered_) {
        return;
    }

    APPBARDATA abd = { 0 };
    abd.cbSize = sizeof(APPBARDATA);
    abd.hWnd = (HWND)winId();
    SHAppBarMessage(ABM_REMOVE, &abd);
    isAppBarRegistered_ = false;
}

void Taskbar::updateTime()
{
    QDateTime currentTime = QDateTime::currentDateTime();
    QString timeStr = currentTime.toString("HH:mm");
    timeLabel_->setText(timeStr);
}

void Taskbar::updateCPUUsage()
{
    if (!sharedState_) {
        return;
    }

    const QVector<int> kCurrentCpuUsage = sharedState_->cpuUsageSnapshot();
    if (kCurrentCpuUsage.size() != cpuBars_.size()) {
        return;
    }

    int maxBarHeight = cpuBarContainer_->height() - 8;
    if (maxBarHeight <= 0) {
        maxBarHeight = 24;
    }

    for (int i = 0; i < cpuBars_.size(); ++i) {
        int barHeight = (kCurrentCpuUsage[i] * maxBarHeight) / 100;
        barHeight = qBound(0, barHeight, maxBarHeight);
        cpuBars_[i]->setFixedSize(4, barHeight);
    }
}

QString Taskbar::formatNetworkSpeed(std::uint64_t bytesPerSecond) const
{
    // Automatic unit conversion: B/s -> KB/s -> MB/s -> GB/s -> TB/s.
    static const char* units[] = { "B/s", "KB/s", "MB/s", "GB/s", "TB/s" };

    double speed = static_cast<double>(bytesPerSecond);
    int unitIndex = 0;
    while (speed >= 1024.0 && unitIndex < 4) {
        speed /= 1024.0;
        ++unitIndex;
    }

    // Maintain consistency with the example style: e.g., 1.2MB/s, 240KB/s.
    int precision = 0;
    if (unitIndex > 0 && speed < 100.0) {
        precision = 1;
    }

    return QString("%1%2").arg(QString::number(speed, 'f', precision), units[unitIndex]);
}

void Taskbar::updateNetworkSpeedLabels()
{
    // Performs UI text refresh only; contains no system sampling logic.
    if (!uploadSpeedLabel_ || !downloadSpeedLabel_ || !sharedState_) {
        return;
    }

    const std::uint64_t kUp = sharedState_->uploadSpeedBytesPerSecond();
    const std::uint64_t kDown = sharedState_->downloadSpeedBytesPerSecond();

    uploadSpeedLabel_->setText(QStringLiteral("\u2191%1").arg(formatNetworkSpeed(kUp)));
    downloadSpeedLabel_->setText(QStringLiteral("\u2193%1").arg(formatNetworkSpeed(kDown)));
}

void Taskbar::onNotificationPresentationChanged()
{
    // All monitors are triggered by the same notification service for this slot, so each screen switches to the same content within the same event loop.
    updateNotificationPresentation();
}

void Taskbar::updateNotificationPresentation()
{
    // Earthquake alerts have the highest priority and do not fade in. Transitions between ordinary notifications and the normal spectrum/clock use a half-second fade-out followed by a half-second fade-in.
    if (notificationService_ == nullptr)
    {
        return;
    }

    const TaskbarNotificationView kNotification = notificationService_->currentNotification();
    if (notificationService_->earthquakeActive())
    {
        showEarthquakePresentation(kNotification);
        return;
    }

    if (notificationService_->hasVisibleNotification())
    {
        transitionToNotification(kNotification);
        return;
    }

    transitionToNormalCenter();
}

void Taskbar::updateNotificationText(const TaskbarNotificationView& notification)
{
    // All text uses single-line truncation to prevent the fixed-height taskbar from expanding due to long device paths or clipboard content.
    notificationSourceLabel_->setText(notification.source);
    notificationTitleLabel_->setText(notification.title);
    notificationBodyLabel_->setText(notification.body);
    notificationBodyLabel_->setToolTip(notification.body);
    displayedNotification_ = notification;
}

void Taskbar::transitionToNotification(const TaskbarNotificationView& notification)
{
    // Do not restart the animation for identical standard notifications to avoid central area flickering caused by multiple earthquake source reports.
    if (!earthquakePresentation_ && notificationVisible_ &&
        displayedNotification_.title == notification.title && displayedNotification_.body == notification.body &&
        displayedNotification_.source == notification.source)
    {
        return;
    }

    if (!earthquakePresentation_)
    {
        // The entire taskbar highlights immediately when a normal message is generated, then fades back to normal over 500ms via an independent animation.
        flashNotificationBackground();
    }
    stopCentralAnimations();
    if (earthquakePresentation_)
    {
        // After the earthquake, fade out the current alert body for half a second, then fade in the queued normal notification; prevent the spectrum from briefly inserting.
        earthquakePresentation_ = false;
        if (alertFlashAnimation_ != nullptr)
        {
            alertFlashAnimation_->stop();
        }
        animateOpacity(notificationCenterOpacity_, notificationCenterOpacity_->opacity(), 0.0, [this, notification]() {
            updateNotificationText(notification);
            applyTaskbarTheme(false, QColor(QStringLiteral("#0A0F16")));
            animateOpacity(notificationCenterOpacity_, 0.0, 1.0, []() {});
        });
        notificationVisible_ = true;
        return;
    }

    if (notificationVisible_)
    {
        // Standard notifications use a full 0.5s fade-out and 0.5s fade-in; content replacement occurs only after full transparency.
        animateOpacity(notificationCenterOpacity_, notificationCenterOpacity_->opacity(), 0.0, [this, notification]() {
            updateNotificationText(notification);
            animateOpacity(notificationCenterOpacity_, 0.0, 1.0, []() {});
        });
        return;
    }

    // First fade the normal spectrum and clock to hidden over half a second, then display and fade in the ordinary notification over half a second.
    animateOpacity(normalCenterOpacity_, normalCenterOpacity_->opacity(), 0.0, [this, notification]() {
        updateNotificationText(notification);
        animateOpacity(notificationCenterOpacity_, 0.0, 1.0, []() {});
    });
    notificationVisible_ = true;
}

void Taskbar::transitionToNormalCenter()
{
    // When there are no notifications to display, reverse the half-second fade-out of the notification and the half-second fade-in of the spectrum/clock.
    if (!notificationVisible_)
    {
        return;
    }

    stopCentralAnimations();
    if (earthquakePresentation_)
    {
        earthquakePresentation_ = false;
        if (alertFlashAnimation_ != nullptr)
        {
            alertFlashAnimation_->stop();
        }
    }
    animateOpacity(notificationCenterOpacity_, notificationCenterOpacity_->opacity(), 0.0, [this]() {
        applyTaskbarTheme(false, QColor(QStringLiteral("#0A0F16")));
        animateOpacity(normalCenterOpacity_, 0.0, 1.0, []() {});
    });
    notificationVisible_ = false;
    displayedNotification_ = TaskbarNotificationView();
}

void Taskbar::showEarthquakePresentation(const TaskbarNotificationView& notification)
{
    // On new earthquake arrival, immediately discard current transitions and normal notification visibility, skipping central body fade-in.
    const bool kSameWarning = earthquakePresentation_ && displayedNotification_.title == notification.title &&
        displayedNotification_.body == notification.body;
    stopCentralAnimations();
    updateNotificationText(notification);
    normalCenterOpacity_->setOpacity(0.0);
    notificationCenterOpacity_->setOpacity(1.0);
    notificationVisible_ = true;
    earthquakePresentation_ = true;
    if (!kSameWarning || alertFlashAnimation_ == nullptr ||
        alertFlashAnimation_->state() != QAbstractAnimation::Running)
    {
        alertFlashBright_ = true;
        applyTaskbarTheme(true, QColor(QStringLiteral("#D90000")));
        startAlertFlashCycle();
    }
    if (!kSameWarning)
    {
        // The earthquake message itself triggers an instantaneous brightening of the entire Taskbar followed by a 500ms fade to dark.
        flashNotificationBackground();
    }
}

void Taskbar::animateOpacity(QGraphicsOpacityEffect* effect, qreal startOpacity, qreal endOpacity,
                              const std::function<void()>& completed)
{
    // Each animation is strictly fixed at 500ms, creating the fade-in/fade-out rhythm requested by the user without altering the taskbar layout dimensions.
    if (effect == nullptr)
    {
        if (completed)
        {
            completed();
        }
        return;
    }

    QPropertyAnimation* animation = new QPropertyAnimation(effect, "opacity", this);
    animation->setDuration(500);
    animation->setStartValue(startOpacity);
    animation->setEndValue(endOpacity);
    animation->setEasingCurve(QEasingCurve::InOutQuad);
    centralAnimations_.push_back(animation);
    connect(animation, &QPropertyAnimation::finished, this, [this, animation, completed]() {
        centralAnimations_.removeAll(animation);
        if (completed)
        {
            completed();
        }
        animation->deleteLater();
    });
    animation->start();
}

void Taskbar::stopCentralAnimations()
{
    // Seismic preemption or a new state transition cancels old animations, ensuring no stale finished callbacks overwrite new content.
    const QList<QPropertyAnimation*> kRunningAnimations = centralAnimations_;
    centralAnimations_.clear();
    for (QPropertyAnimation* animation : kRunningAnimations)
    {
        if (animation != nullptr)
        {
            animation->stop();
            animation->deleteLater();
        }
    }
}

void Taskbar::showSettingsDialog()
{
    // Maintain at most one non-modal settings dialog per screen window, all connected to the same global notification service and profile.
    if (settingsDialog_ == nullptr)
    {
        settingsDialog_ = new TaskbarSettingsDialog(notificationService_, this);
    }
    settingsDialog_->show();
    settingsDialog_->raise();
    settingsDialog_->activateWindow();
}

void Taskbar::onSpectrumDataReady(const QVector<float>& spectrumData)
{
    // Each monitor window shares the same data, but refreshes its own left and right spectrum components independently.
    if (leftSpectrum_) {
        leftSpectrum_->setSpectrumData(spectrumData);
    }
    if (rightSpectrum_) {
        rightSpectrum_->setSpectrumData(spectrumData);
    }
}
