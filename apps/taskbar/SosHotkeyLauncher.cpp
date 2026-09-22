#include "SosHotkeyLauncher.h"

#include <QCoreApplication>
#include <QDebug>
#include <QDir>
#include <QFileInfo>
#include <QStringList>

#include <array>
#include <chrono>
#include <vector>

namespace
{
    constexpr UINT kSosLaunchMessage = WM_APP + 0x0515;      // Startup message within the hook thread.
    constexpr ULONGLONG kLaunchDebounceMs = 3000ULL;         // Prevents SOS from repeatedly triggering duplicate launches.
    constexpr int kHookReadyWaitMs = 2000;                   // Wait time for hook thread initialization.

    // buildMutableCommandLine：
    // - Input: executablePath: path of the executable to launch.
    // - Processing: Construct a writable command-line buffer required for CreateProcessW.
    // - Returns: A NUL-terminated wchar_t buffer.
    std::vector<wchar_t> buildMutableCommandLine(const std::wstring& executablePath)
    {
        std::wstring commandLineText = L"\"" + executablePath + L"\"";
        std::vector<wchar_t> commandLineBuffer(commandLineText.begin(), commandLineText.end());
        commandLineBuffer.push_back(L'\0');
        return commandLineBuffer;
    }
}

SosHotkeyLauncher* SosHotkeyLauncher::sActiveInstance = nullptr;

SosHotkeyLauncher::SosHotkeyLauncher(const QString& applicationDirectoryPath)
{
    // executablePath usage: Stores the main executable path, which the subsequent hook thread uses directly to launch via Win32 API.
    const QString kExecutablePath = resolveKswordExecutablePath(applicationDirectoryPath);
    const QFileInfo kExecutableInfo(kExecutablePath);

    kswordExecutablePath_ = QDir::toNativeSeparators(kExecutableInfo.absoluteFilePath()).toStdWString();
    kswordWorkingDirectory_ = QDir::toNativeSeparators(kExecutableInfo.absolutePath()).toStdWString();
}

SosHotkeyLauncher::~SosHotkeyLauncher()
{
    // The destructor must stop the message loop before releasing the object to prevent static hook callbacks from accessing a dangling instance.
    stop();
}

bool SosHotkeyLauncher::start()
{
    if (hookThread_.joinable())
    {
        return hookInstalled_.load();
    }

    // s_activeInstance usage: WH_KEYBOARD_LL is a C callback, so it must forward to the object state machine via a static pointer.
    sActiveInstance = this;
    stopRequested_.store(false);
    hookThreadId_.store(0, std::memory_order_release);
    threadReady_ = false;

    try
    {
        hookThread_ = std::thread(&SosHotkeyLauncher::hookThreadMain, this);
    }
    catch (...)
    {
        sActiveInstance = nullptr;
        qWarning() << "[Taskbar][SOS] 键盘钩子线程创建失败。";
        return false;
    }

    std::unique_lock<std::mutex> stateLock(stateMutex_);
    const bool kHookReady = stateCondition_.wait_for(
        stateLock,
        std::chrono::milliseconds(kHookReadyWaitMs),
        [this]() {
            return threadReady_;
        });
    stateLock.unlock();

    // Synchronously reclaim resources only when the thread has explicitly completed initialization and hook installation failed; the timeout path retains
    // the original non-blocking semantics, with stop() and the destructor responsible for waiting to avoid deadlocks before the message queue is created.
    if (kHookReady && !hookInstalled_.load(std::memory_order_acquire))
    {
        if (hookThread_.joinable())
        {
            hookThread_.join();
        }
        hookThreadId_.store(0, std::memory_order_release);
        if (sActiveInstance == this)
        {
            sActiveInstance = nullptr;
        }
        return false;
    }

    return hookThread_.joinable();
}

void SosHotkeyLauncher::stop()
{
    stopRequested_.store(true);

    // Purpose of hookThreadId: dispatch exit messages to the dedicated thread to unblock GetMessageW.
    const DWORD kHookThreadId = hookThreadId_.load(std::memory_order_acquire);
    if (kHookThreadId != 0)
    {
        ::PostThreadMessageW(kHookThreadId, WM_QUIT, 0, 0);
    }

    if (hookThread_.joinable())
    {
        hookThread_.join();
    }
    hookThreadId_.store(0, std::memory_order_release);

    if (sActiveInstance == this)
    {
        sActiveInstance = nullptr;
    }
}

LRESULT CALLBACK SosHotkeyLauncher::lowLevelKeyboardProc(
    const int code,
    const WPARAM wParam,
    const LPARAM lParam)
{
    SosHotkeyLauncher* const kInstance = sActiveInstance;
    if (code == HC_ACTION && kInstance != nullptr &&
        (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN))
    {
        const KBDLLHOOKSTRUCT* const kKeyboardEvent =
            reinterpret_cast<const KBDLLHOOKSTRUCT*>(lParam);
        if (kKeyboardEvent != nullptr)
        {
            kInstance->handleKeyDown(kKeyboardEvent->vkCode, kKeyboardEvent->flags);
        }
    }

    return ::CallNextHookEx(
        kInstance != nullptr ? kInstance->keyboardHook_ : nullptr,
        code,
        wParam,
        lParam);
}

void SosHotkeyLauncher::hookThreadMain()
{
    hookThreadId_.store(::GetCurrentThreadId(), std::memory_order_release);

    // Thread priority purpose: Ensure the SOS low-level keyboard hook responds as early as possible, ahead of standard UI operations.
    ::SetThreadPriority(::GetCurrentThread(), THREAD_PRIORITY_HIGHEST);

    // m_keyboardHook purpose: Global WH_KEYBOARD_LL hook, does not inject into other processes.
    keyboardHook_ = ::SetWindowsHookExW(
        WH_KEYBOARD_LL,
        &SosHotkeyLauncher::lowLevelKeyboardProc,
        ::GetModuleHandleW(nullptr),
        0);
    hookInstalled_.store(keyboardHook_ != nullptr);

    {
        std::lock_guard<std::mutex> stateLock(stateMutex_);
        threadReady_ = true;
    }
    stateCondition_.notify_all();

    if (keyboardHook_ == nullptr)
    {
        qWarning() << "[Taskbar][SOS] WH_KEYBOARD_LL 安装失败, error=" << ::GetLastError();
        return;
    }

    qInfo() << "[Taskbar][SOS] SOS Enter 键盘钩子已启动。";

    MSG message{};
    while (!stopRequested_.load())
    {
        const BOOL kGetMessageResult = ::GetMessageW(&message, nullptr, 0, 0);
        if (kGetMessageResult <= 0)
        {
            break;
        }

        if (message.message == kSosLaunchMessage)
        {
            launchKswordFromHookThread();
            continue;
        }

        ::TranslateMessage(&message);
        ::DispatchMessageW(&message);
    }

    if (keyboardHook_ != nullptr)
    {
        ::UnhookWindowsHookEx(keyboardHook_);
        keyboardHook_ = nullptr;
    }
    hookInstalled_.store(false);
    qInfo() << "[Taskbar][SOS] SOS Enter 键盘钩子已停止。";
}

void SosHotkeyLauncher::handleKeyDown(const DWORD vkCode, const DWORD flags)
{
    if ((flags & LLKHF_INJECTED) != 0)
    {
        return;
    }
    if (ignoredModifierKey(vkCode))
    {
        return;
    }

    // sequenceKeys usage: matches only the fixed S O S Enter sequence, caching or outputting no other keys.
    static constexpr std::array<DWORD, 4> kSequenceKeys = {
        static_cast<DWORD>('S'),
        static_cast<DWORD>('O'),
        static_cast<DWORD>('S'),
        static_cast<DWORD>(VK_RETURN)
    };

    if (vkCode == kSequenceKeys[static_cast<std::size_t>(sequenceIndex_)])
    {
        ++sequenceIndex_;
        if (sequenceIndex_ >= static_cast<int>(kSequenceKeys.size()))
        {
            sequenceIndex_ = 0;
            postLaunchRequest();
        }
        return;
    }

    // mismatch handling: if the current key is also 'S', treat it as the start of a new sequence; otherwise, clear it.
    sequenceIndex_ = (vkCode == static_cast<DWORD>('S')) ? 1 : 0;
}

void SosHotkeyLauncher::launchKswordFromHookThread()
{
    const ULONGLONG kNowTickMs = ::GetTickCount64();
    if (lastLaunchTickMs_ != 0 &&
        kNowTickMs - lastLaunchTickMs_ < kLaunchDebounceMs)
    {
        return;
    }

    if (kswordExecutablePath_.empty())
    {
        qWarning() << "[Taskbar][SOS] Ksword5.1.exe 路径为空，无法启动。";
        return;
    }

    STARTUPINFOW startupInfo{};
    PROCESS_INFORMATION processInfo{};
    startupInfo.cb = sizeof(startupInfo);

    std::vector<wchar_t> commandLineBuffer = buildMutableCommandLine(kswordExecutablePath_);
    const BOOL kCreateOk = ::CreateProcessW(
        kswordExecutablePath_.c_str(),
        commandLineBuffer.data(),
        nullptr,
        nullptr,
        FALSE,
        CREATE_NEW_PROCESS_GROUP,
        nullptr,
        kswordWorkingDirectory_.empty() ? nullptr : kswordWorkingDirectory_.c_str(),
        &startupInfo,
        &processInfo);

    if (kCreateOk == FALSE)
    {
        qWarning() << "[Taskbar][SOS] 启动 Ksword5.1.exe 失败, error=" << ::GetLastError();
        return;
    }

    ::CloseHandle(processInfo.hThread);
    ::CloseHandle(processInfo.hProcess);
    lastLaunchTickMs_ = kNowTickMs;
    qInfo() << "[Taskbar][SOS] 已通过 SOS Enter 启动 Ksword5.1.exe。";
}

QString SosHotkeyLauncher::resolveKswordExecutablePath(const QString& applicationDirectoryPath)
{
    const QDir kApplicationDirectory(applicationDirectoryPath);
    const QString kCurrentDirectoryPath = QDir::currentPath();

    // candidates purpose: Prioritizes support for the same directory as the distribution package, then falls back to compatibility with the source tree Taskbar\x64\Release output.
    const QStringList kCandidates = {
        kApplicationDirectory.filePath(QStringLiteral("Ksword5.1.exe")),
        kApplicationDirectory.filePath(QStringLiteral("../Ksword5.1.exe")),
        kApplicationDirectory.filePath(QStringLiteral("../../../../artifacts/bin/x64/Release/Ksword5.1.exe")),
        QDir(kCurrentDirectoryPath).filePath(QStringLiteral("Ksword5.1.exe"))
    };

    for (const QString& candidatePath : kCandidates)
    {
        const QFileInfo kCandidateInfo(QDir::cleanPath(candidatePath));
        if (kCandidateInfo.exists() && kCandidateInfo.isFile())
        {
            return kCandidateInfo.absoluteFilePath();
        }
    }

    return QFileInfo(QDir::cleanPath(kCandidates.first())).absoluteFilePath();
}

bool SosHotkeyLauncher::ignoredModifierKey(const DWORD vkCode)
{
    switch (vkCode)
    {
    case VK_SHIFT:
    case VK_LSHIFT:
    case VK_RSHIFT:
    case VK_CONTROL:
    case VK_LCONTROL:
    case VK_RCONTROL:
    case VK_MENU:
    case VK_LMENU:
    case VK_RMENU:
    case VK_CAPITAL:
    case VK_LWIN:
    case VK_RWIN:
        return true;
    default:
        return false;
    }
}

void SosHotkeyLauncher::postLaunchRequest()
{
    if (hookThreadId_.load(std::memory_order_acquire) == 0)
    {
        return;
    }

    ::PostThreadMessageW(hookThreadId_, kSosLaunchMessage, 0, 0);
}
