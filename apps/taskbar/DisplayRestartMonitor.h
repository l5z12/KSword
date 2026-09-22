#ifndef DISPLAYRESTARTMONITOR_H
#define DISPLAYRESTARTMONITOR_H

#include <QAbstractNativeEventFilter>
#include <QObject>
#include <QString>
#include <QRect>
#include <QTimer>

class QScreen;

class DisplayRestartMonitor : public QObject, public QAbstractNativeEventFilter
{
    Q_OBJECT

public:
    // Constructor: accepts a parent QObject; handles initial display snapshot and signal connections; no business logic return value.
    explicit DisplayRestartMonitor(QObject* parent = nullptr);

    // Destructor: takes no input; handles unregistration of the native event filter; returns no value.
    ~DisplayRestartMonitor() override;

    // Native event filter: accepts Qt event type, native message, and return value pointer; handles WM_DISPLAYCHANGE; returns whether to intercept the event.
    bool nativeEventFilter(const QByteArray& eventType, void* message, qintptr* result) override;

private slots:
    // Monitor addition: accept the new screen as input; handle signal binding and restart logic; no return value.
    void onScreenAdded(QScreen* screen);

    // Screen removal: input removed screen; handle restart judgment; no return value.
    void onScreenRemoved(QScreen* screen);

    // Screen geometry change: input new geometry; handle restart judgment; no return value.
    void onScreenGeometryChanged(const QRect& geometry);

private:
    // Build display signature: no input; process screen count and geometric ordering; return a stable signature string.
    QString buildDisplaySignature() const;

    // Attach screen signals: input screen object; handle geometryChanged connection; no return value.
    void attachScreen(QScreen* screen);

    // Check and schedule restart: no input; handles signature comparison and debouncing; no return value.
    void scheduleRestartIfChanged();

    // Schedule restart: no input; handles a single delayed restart; no return value.
    void scheduleRestart();

    // Execution restart: no input; handles starting a new process and exiting the current event loop; no return value.
    void restartProcess();

    QString initialDisplaySignature_;   // Display count and resolution signature at startup.
    bool restartScheduled_;             // Prevents multiple display events from repeatedly starting the process.
    QTimer restartTimer_;               // Delayed restart timer, used to wait for system display events to stabilize.
};

#endif
