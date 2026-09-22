#pragma once

// Implementation details shared by mainWindow's responsibility-specific units.
// Public window API remains in mainWindow.h.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <QString>
#include <atomic>
#include <functional>
#include <string>
#include "Framework.h"

namespace ksword::ui::main_window
{
    struct R0ServiceOperationOutcome;
    class ScopedServiceHandle;

    inline constexpr int kR0LogIdlePollSleepMs = 120;

    inline constexpr char kR0LogPrefixDebug[] = "[Debug]";

    inline constexpr char kR0LogPrefixInfo[] = "[Info]";

    inline constexpr char kR0LogPrefixWarn[] = "[Warn]";

    inline constexpr char kR0LogPrefixError[] = "[Error]";

    inline constexpr char kR0LogPrefixFatal[] = "[Fatal]";

    KLogEvent& sharedR0DriverLogEvent();

    bool startsWithLiteral(const std::string& text, const char* prefixText);

    bool queryServiceStatus(const SC_HANDLE serviceHandle, SERVICE_STATUS_PROCESS& statusOut, DWORD& errorCodeOut);

    bool isRunningLikeServiceState(const DWORD serviceState);

    bool enableCurrentProcessPrivilege(const wchar_t* const privilegeName, DWORD* const errorCodeOut);

    extern std::atomic_bool gR0ServiceOperationInFlight;

    void dispatchR0ServiceStopToWorker(
        std::function<void(const R0ServiceOperationOutcome&)> completionCallback);

    void dispatchR0ServiceStartToWorker(
        const QString& nativeDriverPath,
        std::function<void(const R0ServiceOperationOutcome&)> completionCallback);

    class ScopedServiceHandle final
    {
    public:
        ScopedServiceHandle() = default;
        explicit ScopedServiceHandle(const SC_HANDLE handle)
            : handle_(handle)
        {
        }

        ScopedServiceHandle(const ScopedServiceHandle&) = delete;
        ScopedServiceHandle& operator=(const ScopedServiceHandle&) = delete;

        ScopedServiceHandle(ScopedServiceHandle&& other) noexcept
            : handle_(other.handle_)
        {
            other.handle_ = nullptr;
        }

        ScopedServiceHandle& operator=(ScopedServiceHandle&& other) noexcept
        {
            if (this != &other)
            {
                reset();
                handle_ = other.handle_;
                other.handle_ = nullptr;
            }
            return *this;
        }

        ~ScopedServiceHandle()
        {
            reset();
        }

        void reset(const SC_HANDLE newHandle = nullptr)
        {
            if (handle_ != nullptr)
            {
                ::CloseServiceHandle(handle_);
            }
            handle_ = newHandle;
        }

        SC_HANDLE get() const
        {
            return handle_;
        }

        bool isValid() const
        {
            return handle_ != nullptr;
        }

    private:
        SC_HANDLE handle_ = nullptr;
    };

    // R0ServiceOperationOutcome:
    // - Input: none; populated field-by-field when SCM operations are executed by the background thread;
    // - Processing: Collapse all conclusions of a single R0 driver service start/stop into a pure value type to satisfy the 'cross-thread only return value types' constraint;
    // - Return: See member comments for field meanings; UI thread decides on dialog and status refresh after receiving.
    struct R0ServiceOperationOutcome
    {
        bool succeeded = false;                  // succeeded: indicates whether the SCM side has reached the target state.
        bool alreadyInTargetState = false;       // alreadyInTargetState: the service was already in the target state upon entry (do not log "created and started").
        bool startServiceCallFailed = false;     // startServiceCallFailed: failure occurred in StartServiceW itself; errorCode can be used to determine signature failure.
        bool usedDirectNtUnloadFallback = false; // usedDirectNtUnloadFallback: driver unloading fell back to direct NtUnloadDriver call.
        DWORD errorCode = ERROR_SUCCESS;         // errorCode: Win32 error code on failure.
        QString stageText;                       // stageText: Description of the failure stage, can be used directly as the title line of the R0 error dialog.
        QString detailText;                      // detailText: Failure troubleshooting details, directly displayed in the error dialog's 'Details' section.
    };
}
