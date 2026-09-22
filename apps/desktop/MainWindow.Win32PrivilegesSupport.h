#pragma once

// Implementation details shared by mainWindow's responsibility-specific units.
// Public window API remains in mainWindow.h.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <QString>
#include <QStringList>
#include <string>

namespace ksword::ui::main_window
{
    class ScopedHandle;
    class ScopedThreadImpersonation;

    inline constexpr wchar_t kKswordPrivilegeRestartArgument[] = L"--ksword-privilege-restart";

    inline constexpr wchar_t kKswordEnableR0AfterElevationArgument[] = L"--ksword-enable-r0-after-elevation";

    QString formatWin32ErrorText(const DWORD errorCode);

    QString quoteWin32CommandLineArgument(const std::wstring& argumentText);

    QStringList argumentsWithPrivilegeRestartTakeover(
        QStringList argumentList,
        const DWORD predecessorProcessId);

    QString formatWin32StepFailure(const QString& stepText, const DWORD errorCode);

    QString privilegeNameToDisplayText(const wchar_t* const privilegeName);

    bool enableTokenPrivilege(
        const HANDLE tokenHandle,
        const wchar_t* const privilegeName,
        DWORD* const errorCodeOut);

    QString tryEnableCurrentProcessPrivilegeForUiAccess(const wchar_t* const privilegeName);

    bool queryTokenSessionId(const HANDLE tokenHandle, DWORD* const sessionIdOut, DWORD* const errorCodeOut);

    bool tokenBelongsToLocalSystem(const HANDLE tokenHandle, DWORD* const errorCodeOut);

    bool findSystemProcessTokenCandidate(
        const DWORD currentSessionId,
        DWORD* const processIdOut,
        QString* const processNameOut,
        DWORD* const processSessionIdOut,
        QString* const detailTextOut);

    QString quoteQStringCommandLineArgument(QString argumentText);

    bool launchSelfAsUnelevatedFromExplorer(const QStringList& argumentList, QString* detailTextOut);

    class ScopedHandle final
    {
    public:
        // Constructor:
        // - Input: Windows kernel object handle.
        // - Processing: Save the handle and automatically call CloseHandle during destruction.
        // - Returns: Nothing.
        explicit ScopedHandle(const HANDLE handleValue = nullptr)
            : handle_(handleValue)
        {
        }

        ScopedHandle(const ScopedHandle&) = delete;
        ScopedHandle& operator=(const ScopedHandle&) = delete;

        // Move constructor:
        // - Input: another handle-holding object
        // - Processing: Transfer handle ownership to prevent both objects from closing the same handle.
        // - Returns: Nothing.
        ScopedHandle(ScopedHandle&& other) noexcept
            : handle_(other.handle_)
        {
            other.handle_ = nullptr;
        }

        // Move assignment:
        // - Input: another handle-holding object
        // - Handling: close the current old handle, then take ownership of the other handle.
        // - Returns: reference to the current object.
        ScopedHandle& operator=(ScopedHandle&& other) noexcept
        {
            if (this != &other)
            {
                reset();
                handle_ = other.handle_;
                other.handle_ = nullptr;
            }
            return *this;
        }

        // Destructor:
        // - Inputs: None;
        // - Processing: close handles still held by the object;
        // - Returns: Nothing.
        ~ScopedHandle()
        {
            reset();
        }

        // reset：
        // - Input: new handle, default null handle;
        // - Processing: close the old handle and save the new handle;
        // - Returns: Nothing.
        void reset(const HANDLE newHandle = nullptr)
        {
            if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE)
            {
                ::CloseHandle(handle_);
            }
            handle_ = newHandle;
        }

        // release：
        // - Inputs: None;
        // - Action: Release ownership without closing the handle;
        // - Returns: The original handle; the caller assumes responsibility for closing it.
        HANDLE release()
        {
            const HANDLE kOldHandle = handle_;
            handle_ = nullptr;
            return kOldHandle;
        }

        // get：
        // - Inputs: None;
        // - Processing: Return the current raw handle.
        // - Returns: HANDLE, which may be null.
        HANDLE get() const
        {
            return handle_;
        }

        // isValid：
        // - Inputs: None;
        // - Processing: Check if the handle is valid for Win32 API usage.
        // - Return: true indicates the handle is non-null and not INVALID_HANDLE_VALUE.
        bool isValid() const
        {
            return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
        }

    private:
        HANDLE handle_ = nullptr; // m_handle: Currently managed Win32 handle.
    };

    class ScopedThreadImpersonation final
    {
    public:
        ScopedThreadImpersonation() = default;
        ScopedThreadImpersonation(const ScopedThreadImpersonation&) = delete;
        ScopedThreadImpersonation& operator=(const ScopedThreadImpersonation&) = delete;

        // Destructor:
        // - Inputs: None;
        // - Processing: If the current object has thread impersonation enabled, automatically call RevertToSelf.
        // - Returns: Nothing.
        ~ScopedThreadImpersonation()
        {
            reset();
        }

        // impersonate：
        // - Input: Token handle to impersonate;
        // - Processing: Enter the security context of the token for the current thread.
        // - Returns: true indicates successful impersonation.
        bool impersonate(const HANDLE tokenHandle, DWORD* const errorCodeOut)
        {
            if (errorCodeOut != nullptr)
            {
                *errorCodeOut = ERROR_SUCCESS;
            }
            reset();
            if (tokenHandle == nullptr)
            {
                if (errorCodeOut != nullptr)
                {
                    *errorCodeOut = ERROR_INVALID_HANDLE;
                }
                return false;
            }
            if (::ImpersonateLoggedOnUser(tokenHandle) == FALSE)
            {
                if (errorCodeOut != nullptr)
                {
                    *errorCodeOut = ::GetLastError();
                }
                return false;
            }
            active_ = true;
            return true;
        }

        // reset：
        // - Inputs: None;
        // - Processing: Revert current thread impersonation and restore the calling thread's identity.
        // - Returns: Nothing.
        void reset()
        {
            if (active_)
            {
                ::RevertToSelf();
                active_ = false;
            }
        }

    private:
        bool active_ = false; // m_active: Indicates whether thread impersonation must be reverted during destruction.
    };
}
