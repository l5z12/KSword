#include "Taskbar.h"
#include "DisplayRestartMonitor.h"
#include "SosHotkeyLauncher.h"
#include "TaskbarEarthquakeClient.h"
#include "TaskbarNotificationService.h"
#include "TaskbarRestartCoordinator.h"
#include "TaskbarSharedState.h"

#include <QtWidgets/QApplication>
#include <QCoreApplication>
#include <QGuiApplication>
#include <QList>
#include <QScreen>
#include <QVector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

namespace
{
    // initializeProcessDpiAwareness:
    // - Input: none.
    // - Processing: sets process DPI awareness before QApplication is created.
    // - Return: none; the process falls back to system DPI awareness on older Windows builds.
    void initializeProcessDpiAwareness()
    {
        HMODULE user32ModuleHandle = ::GetModuleHandleW(L"user32.dll");
        if (user32ModuleHandle != nullptr)
        {
            using SetDpiAwarenessContextFunction = BOOL(WINAPI*)(DPI_AWARENESS_CONTEXT);
            const SetDpiAwarenessContextFunction kSetContextFunction =
                reinterpret_cast<SetDpiAwarenessContextFunction>(
                    ::GetProcAddress(user32ModuleHandle, "SetProcessDpiAwarenessContext"));
            if (kSetContextFunction != nullptr)
            {
                if (kSetContextFunction(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2))
                {
                    return;
                }
                if (kSetContextFunction(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE))
                {
                    return;
                }
            }
        }

        // Older Windows fallback: keep at least system-DPI-aware coordinates.
        ::SetProcessDPIAware();
    }
}

int main(int argc, char* argv[])
{
    // Enable OpenGLES to follow the original taskbar drawing path and avoid changing Qt rendering strategies.
    QCoreApplication::setAttribute(Qt::AA_UseOpenGLES);

    // Set DPI awareness before QApplication so QScreen geometry and AppBar math agree.
    initializeProcessDpiAwareness();

    // QApplication manages the lifecycle of all Taskbar windows, screen events, and shared state objects.
    QApplication app(argc, argv);

    // The successor instance for PID-aware restart must wait for the old process to exit before creating the window, AppBar, and background sampling thread.
    if (!taskbar_restart_coordinator::waitForPredecessorIfRequested())
    {
        return 2;
    }

    // Start SOS keyboard hook as early as possible:
    // - Install WH_KEYBOARD_LL in an independent high-priority thread.
    // - Only detects the fixed SOS Enter sequence;
    // - Launch the Ksword5.1 main program upon a hit.
    SosHotkeyLauncher sosHotkeyLauncher(QCoreApplication::applicationDirPath());
    sosHotkeyLauncher.start();

    // The display change monitor automatically launches a new process and exits the old one when the number of screens or resolution changes.
    DisplayRestartMonitor displayRestartMonitor(&app);

    // Shared state starts sampling only once; multiple monitor windows share data without re-opening audio/CPU/network samplers.
    TaskbarSharedState sharedState(&app);
    sharedState.start();

    // The earthquake client and system notification service are process-unique: all desktops receive the same source status and the same notification queue.
    TaskbarEarthquakeClient earthquakeClient(&app);
    earthquakeClient.start();
    TaskbarNotificationService notificationService(&earthquakeClient, &app);

    // Create an identical Taskbar window for each monitor and request the top AppBar edge from the system for each.
    QVector<Taskbar*> windows;
    const QList<QScreen*> kScreens = QGuiApplication::screens();
    windows.reserve(kScreens.size());

    for (QScreen* screen : kScreens) {
        Taskbar* window = new Taskbar(screen, &sharedState, &notificationService);
        windows.append(window);
        window->show();
    }

    return app.exec();
}
