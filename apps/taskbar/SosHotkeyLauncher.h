#ifndef SOSHOTKEYLAUNCHER_H
#define SOSHOTKEYLAUNCHER_H

#include <QString>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>

// SosHotkeyLauncher：
// - Purpose: Install a global low-level keyboard hook after the Taskbar helper program starts.
// - Detect the fixed sequence S, O, S, Enter;
// - Launch the Ksword5.1 main program upon activation; do not record other keyboard input.
class SosHotkeyLauncher final
{
public:
    // Constructor:
    // - Input applicationDirectoryPath: directory containing Taskbar.exe;
    // - Processing: Parse candidate paths for Ksword5.1.exe.
    // - Returns: Nothing.
    explicit SosHotkeyLauncher(const QString& applicationDirectoryPath);

    // Destructor:
    // - Processing: Stop the hook thread and unregister WH_KEYBOARD_LL.
    // - Returns: Nothing.
    ~SosHotkeyLauncher();

    // start：
    // - Inputs: None;
    // - Processing: Start a dedicated high-priority keyboard hook thread;
    // - Return: true indicates successful thread creation; false indicates failure.
    bool start();

    // stop：
    // - Inputs: None;
    // - Processing: Request the hook thread to exit and wait for termination.
    // - Returns: Nothing.
    void stop();

private:
    // lowLevelKeyboardProc：
    // - Input: Windows low-level keyboard hook parameters;
    // - Processing: Only pass key-down events to the current instance state machine.
    // - Returns: The result of CallNextHookEx.
    static LRESULT CALLBACK lowLevelKeyboardProc(int code, WPARAM wParam, LPARAM lParam);

    // hookThreadMain：
    // - Inputs: None;
    // - Processing: Set thread priority, install hooks, and run the message loop.
    // - Returns: Nothing.
    void hookThreadMain();

    // handleKeyDown：
    // - Input: vkCode/flags are Windows virtual-key codes and low-level hook flags;
    // - Processing: Advance the SOS Enter state machine.
    // - Returns: Nothing.
    void handleKeyDown(DWORD vkCode, DWORD flags);

    // launchKswordFromHookThread：
    // - Inputs: None;
    // - Handling: Launch Ksword5.1.exe from the hook thread;
    // - Returns: Nothing.
    void launchKswordFromHookThread();

    // resolveKswordExecutablePath：
    // - Input applicationDirectoryPath: directory containing Taskbar.exe;
    // - Processing: Support both distribution package same-directory and source build output directories;
    // - Returns: The main executable path; falls back to candidates in the same directory if not found.
    static QString resolveKswordExecutablePath(const QString& applicationDirectoryPath);

    // ignoredModifierKey：
    // - Input: vkCode; Windows virtual-key code;
    // - Processing: Identify modifier keys that should not interrupt the SOS sequence.
    // - Returns: true indicates the key is ignored.
    static bool ignoredModifierKey(DWORD vkCode);

    // postLaunchRequest：
    // - Inputs: None;
    // - Processing: Dispatch launch requests from the hook callback to the hook thread's message loop.
    // - Returns: Nothing.
    void postLaunchRequest();

private:
    static SosHotkeyLauncher* sActiveInstance;      // Current unique active instance, used for forwarding static hook callbacks.

    std::thread hookThread_;                        // Dedicated keyboard hook thread.
    std::atomic_bool stopRequested_{ false };       // Thread exit request flag.
    std::atomic_bool hookInstalled_{ false };       // Whether WH_KEYBOARD_LL was installed successfully.

    std::mutex stateMutex_;                         // Thread startup state mutex.
    std::condition_variable stateCondition_;        // Condition variable for start to wait for thread readiness.
    bool threadReady_ = false;                      // Whether the hook thread has completed initialization.

    std::atomic<DWORD> hookThreadId_{ 0 };           // Hook thread ID, used for PostThreadMessage.
    HHOOK keyboardHook_ = nullptr;                  // Keyboard hook handle returned by SetWindowsHookExW.
    int sequenceIndex_ = 0;                         // Current position in the matched SOS Enter sequence.
    ULONGLONG lastLaunchTickMs_ = 0;                // timestamp of the last main program launch, used for debouncing.

    std::wstring kswordExecutablePath_;             // Absolute path to Ksword5.1.exe.
    std::wstring kswordWorkingDirectory_;           // Working directory for the main program startup.
};

#endif
