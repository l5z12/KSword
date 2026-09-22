#include "DisplayRestartMonitor.h"
#include "TaskbarRestartCoordinator.h"

#include <windows.h>
#include <QCoreApplication>
#include <QGuiApplication>
#include <QScreen>
#include <QStringList>

DisplayRestartMonitor::DisplayRestartMonitor(QObject* parent)
    : QObject(parent),
      initialDisplaySignature_(buildDisplaySignature()),
      restartScheduled_(false)
{
    // Register a native event filter to ensure Windows resolution change messages also trigger a restart.
    if (QCoreApplication::instance()) {
        QCoreApplication::instance()->installNativeEventFilter(this);
    }

    // Monitor screen count changes and geometry changes for each screen at the Qt level.
    connect(
        qApp,
        &QGuiApplication::screenAdded,
        this,
        &DisplayRestartMonitor::onScreenAdded
    );
    connect(
        qApp,
        &QGuiApplication::screenRemoved,
        this,
        &DisplayRestartMonitor::onScreenRemoved
    );

    for (QScreen* screen : QGuiApplication::screens()) {
        attachScreen(screen);
    }

    // Delay restart to merge multiple screen change events from the graphics driver.
    restartTimer_.setSingleShot(true);
    restartTimer_.setInterval(1000);
    connect(&restartTimer_, &QTimer::timeout, this, &DisplayRestartMonitor::restartProcess);
}

DisplayRestartMonitor::~DisplayRestartMonitor()
{
    // Unregister the filter to avoid callbacks to freed objects during QApplication destruction.
    if (QCoreApplication::instance()) {
        QCoreApplication::instance()->removeNativeEventFilter(this);
    }
}

bool DisplayRestartMonitor::nativeEventFilter(const QByteArray& eventType,
                                              void* message,
                                              qintptr* result)
{
    Q_UNUSED(eventType);
    Q_UNUSED(result);

    MSG* nativeMessage = static_cast<MSG*>(message);
    if (nativeMessage && nativeMessage->message == WM_DISPLAYCHANGE) {
        scheduleRestart();
    }

    return false;
}

void DisplayRestartMonitor::onScreenAdded(QScreen* screen)
{
    // After a new monitor is added, attach the geometry signal first, then determine if a restart is needed.
    attachScreen(screen);
    scheduleRestartIfChanged();
}

void DisplayRestartMonitor::onScreenRemoved(QScreen* screen)
{
    // When a screen is removed, Qt may have already updated screens(); do not access the removed screen here.
    Q_UNUSED(screen);
    scheduleRestartIfChanged();
}

void DisplayRestartMonitor::onScreenGeometryChanged(const QRect& geometry)
{
    // Changes in resolution or screen coordinates alter the geometry; use signature comparison uniformly.
    Q_UNUSED(geometry);
    scheduleRestartIfChanged();
}

QString DisplayRestartMonitor::buildDisplaySignature() const
{
    // The signature includes only screen count and geometry, excluding availableGeometry, to prevent self-restart caused by the AppBar modifying the work area.
    QStringList screenParts;
    for (QScreen* screen : QGuiApplication::screens()) {
        if (!screen) {
            continue;
        }

        const QRect kGeometry = screen->geometry();
        screenParts.append(QString("%1,%2,%3,%4")
            .arg(kGeometry.x())
            .arg(kGeometry.y())
            .arg(kGeometry.width())
            .arg(kGeometry.height()));
    }

    screenParts.sort();
    return screenParts.join("|");
}

void DisplayRestartMonitor::attachScreen(QScreen* screen)
{
    // Each screen only needs to monitor physical geometry changes; Qt::UniqueConnection prevents duplicate connections.
    if (!screen) {
        return;
    }

    connect(
        screen,
        &QScreen::geometryChanged,
        this,
        &DisplayRestartMonitor::onScreenGeometryChanged,
        Qt::UniqueConnection
    );
}

void DisplayRestartMonitor::scheduleRestartIfChanged()
{
    // Restart only if the count or resolution/coordinate names actually change to reduce meaningless restarts.
    if (buildDisplaySignature() != initialDisplaySignature_) {
        scheduleRestart();
    }
}

void DisplayRestartMonitor::scheduleRestart()
{
    // Multiple screen events may arrive consecutively; ensure only one restart is scheduled.
    if (restartScheduled_) {
        return;
    }

    restartScheduled_ = true;
    restartTimer_.start();
}

void DisplayRestartMonitor::restartProcess()
{
    // The replacement instance waits for this process to exit before initializing to avoid overlapping registration of AppBar for each screen by two instances.
    if (taskbar_restart_coordinator::scheduleAfterCurrentProcessExit()) {
        QCoreApplication::quit();
        return;
    }

    // On scheduling failure, retain the current instance and allow subsequent display changes to retry.
    restartScheduled_ = false;
}
