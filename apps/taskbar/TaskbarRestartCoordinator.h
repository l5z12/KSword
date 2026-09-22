#ifndef TASKBARRESTARTCOORDINATOR_H
#define TASKBARRESTARTCOORDINATOR_H

namespace taskbar_restart_coordinator
{
    // scheduleAfterCurrentProcessExit: launch a replacement instance of the same process carrying the current PID.
    // The successor instance waits for the current process to truly exit before normal initialization; returns whether the successor instance started successfully.
    bool scheduleAfterCurrentProcessExit();

    // waitForPredecessorIfRequested: Handle the --restart-after-pid startup parameter.
    // Returns true directly if no parameters are provided; otherwise, waits for the old process to exit. Returns false if parameters are invalid or the wait fails.
    bool waitForPredecessorIfRequested();
}

#endif
