#include "pch.h"
#include "MonitorAgent.h"
#include "core/MonitorPipe.h"
#include "hook/HookEngine.h"
#include "hook/HookTargets.h"

namespace apimon
{
    namespace
    {
        std::atomic_bool gStopRequested{ false };     // g_stopRequested: Global stop flag.
        std::atomic_bool gProcessDetachRequested{ false }; // g_processDetachRequested: The DLL is unloading; the worker must not start another session.
        MonitorConfig gActiveConfig{};                // g_activeConfig: Currently loaded session configuration.
        constexpr DWORD kSessionIdlePollMs = 100;       // kSessionIdlePollMs: Infrequent polling interval while waiting for the next UI session configuration.
        constexpr DWORD kSessionActivePollMs = 250;     // kSessionActivePollMs: Interval for polling the stop flag after Hook installation.

        void traceAgentFailure(const std::wstring& errorText)
        {
            if (errorText.empty())
            {
                return;
            }

            const std::wstring kOutputText = L"[APIMonitor_x64] " + errorText + L"\n";
            ::OutputDebugStringW(kOutputText.c_str());
        }

        // waitForNextSessionConfig:
        // - Inputs: configOut receives the next fully loaded session configuration that is ready to start;
        // - Processing: Keep the Agent resident while the stop flag exists; return only after the UI atomically commits a new INI and clears the flag;
        // - Returns: true when a session is ready to start, or false when the DLL is unloading.
        bool waitForNextSessionConfig(MonitorConfig* const configOut)
        {
            if (configOut == nullptr)
            {
                return false;
            }

            std::wstring lastErrorText;
            while (!gProcessDetachRequested.load())
            {
                MonitorConfig candidateConfig;
                std::wstring errorText;
                if (!loadMonitorConfigForCurrentProcess(&candidateConfig, &errorText))
                {
                    if (errorText != lastErrorText)
                    {
                        traceAgentFailure(errorText);
                        lastErrorText = errorText;
                    }
                    ::Sleep(kSessionIdlePollMs);
                    continue;
                }

                lastErrorText.clear();
                if (isStopFlagPresent(candidateConfig))
                {
                    ::Sleep(kSessionIdlePollMs);
                    continue;
                }

                // Reset the stop state for a new session only after the stop flag is cleared, so a session that just ended is not immediately restarted.
                gStopRequested.store(false);
                *configOut = candidateConfig;
                return true;
            }
            return false;
        }

        // sessionConfigWasReplaced:
        // - Inputs: activeConfigValue is the session configuration for the currently installed Hook;
        // - Processing: Re-read the atomically committed INI and compare the unique session_id written by the UI;
        // - Returns: true when a different session is detected; false on read failure or for a legacy configuration without an identifier.
        bool sessionConfigWasReplaced(const MonitorConfig& activeConfigValue)
        {
            if (activeConfigValue.sessionId.empty())
            {
                return false;
            }

            MonitorConfig observedConfig;
            std::wstring ignoredErrorText;
            if (!loadMonitorConfigForCurrentProcess(&observedConfig, &ignoredErrorText)
                || observedConfig.sessionId.empty())
            {
                return false;
            }
            return observedConfig.sessionId != activeConfigValue.sessionId;
        }

        // waitForCurrentSessionStop:
        // - Inputs: configValue is the stable configuration of the session that has started;
        // - Processing: Wait for the UI stop flag or a DLL unload request, and synchronize the file flag with the in-process stop state;
        // - Returns: Nothing. After return, the caller must unload the Hook and stop the pipe.
        void waitForCurrentSessionStop(const MonitorConfig& configValue)
        {
            while (!gProcessDetachRequested.load() && !stopRequested())
            {
                if (isStopFlagPresent(configValue) || sessionConfigWasReplaced(configValue))
                {
                    requestStop();
                    break;
                }
                ::Sleep(kSessionActivePollMs);
            }
        }

        DWORD WINAPI monitorWorkerThread(LPVOID parameterValue)
        {
            (void)parameterValue;

            // agentBypassScope：
            // - Inputs: None;
            // - Processing: Exclude the Agent worker thread's own session waits, event sends, and unload operations from the monitored event stream;
            // - Returns: Nothing. The scope covers the entire lifetime of the restartable worker.
            // - Reason: The internal control thread is not the application thread being monitored. Monitoring it adds recursive Wait/File/Loader noise and can cause a shutdown crash.
            ScopedInlineHookInternalBypass agentBypassScope;
            while (!gProcessDetachRequested.load())
            {
                MonitorConfig configValue;
                if (!waitForNextSessionConfig(&configValue))
                {
                    break;
                }

                replaceActiveConfig(configValue);
                std::wstring errorText;
                if (!startMonitorPipeServer(configValue, &errorText))
                {
                    if (!gProcessDetachRequested.load() && !isStopFlagPresent(configValue))
                    {
                        traceAgentFailure(errorText);
                    }
                    // Keep the worker after a pipe handshake failure: the UI may recreate the reader on the next attempt. One 45-second timeout must not permanently prevent restart.
                    ::Sleep(kSessionIdlePollMs);
                    continue;
                }

                sendMonitorEvent(
                    ks::winapi_monitor::EventCategory::kInternal,
                    L"Agent",
                    L"SessionReady",
                    0,
                    L"Agent connected and pipe server is ready.");

                if (!installConfiguredHooks(&errorText))
                {
                    sendMonitorEvent(
                        ks::winapi_monitor::EventCategory::kInternal,
                        L"Agent",
                        L"InstallHooksFailed",
                        1,
                        errorText);
                    waitForCurrentSessionStop(configValue);
                    uninstallConfiguredHooks();
                    stopMonitorPipeServer();
                    continue;
                }
                if (!errorText.empty())
                {
                    sendMonitorEvent(
                        ks::winapi_monitor::EventCategory::kInternal,
                        L"Agent",
                        L"HooksPartial",
                        0,
                        errorText);
                }

                sendMonitorEvent(
                    ks::winapi_monitor::EventCategory::kInternal,
                    L"Agent",
                    L"HooksInstalled",
                    0,
                    L"Configured inline hooks are now active.");

                waitForCurrentSessionStop(configValue);
                uninstallConfiguredHooks();
                sendMonitorEvent(
                    ks::winapi_monitor::EventCategory::kInternal,
                    L"Agent",
                    L"HooksRemoved",
                    0,
                    L"Inline hooks removed and agent is waiting for the next session.");
                stopMonitorPipeServer();
            }
            return 0;
        }
    }

    void onProcessAttach(const HMODULE moduleHandle)
    {
        ::DisableThreadLibraryCalls(moduleHandle);
        gProcessDetachRequested.store(false);
        gStopRequested.store(false);

        HANDLE workerHandle = ::CreateThread(
            nullptr,
            0,
            &monitorWorkerThread,
            nullptr,
            0,
            nullptr);
        if (workerHandle != nullptr)
        {
            ::CloseHandle(workerHandle);
        }
        else
        {
            traceAgentFailure(L"CreateThread for monitor worker failed.");
        }
    }

    void onProcessDetach()
    {
        gProcessDetachRequested.store(true);
        requestStop();
    }

    const MonitorConfig& activeConfig()
    {
        return gActiveConfig;
    }

    void replaceActiveConfig(const MonitorConfig& configValue)
    {
        gActiveConfig = configValue;
    }

    bool stopRequested()
    {
        return gStopRequested.load();
    }

    void requestStop()
    {
        gStopRequested.store(true);
    }
}
