#include "ArkDriverClient.h"
#include "ArkDriverResponseSupport.h"

#include "ArkDriverError.h"

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <functional>
#include <mutex>
#include <string>
#include <utility>


namespace ksword::ark
{
    namespace
    {
        constexpr unsigned long kDefaultShareMode = FILE_SHARE_READ | FILE_SHARE_WRITE;

        // g_r0NotificationMutex: serializes global handlers, deduplicates timeouts, and tracks in-flight callback counts.
        std::mutex gR0NotificationMutex;
        // g_r0NotificationIdleCondition: Ensures the window destructor waits for all worker threads that have acquired the lease.
        std::condition_variable gR0NotificationIdleCondition;
        // g_r0NotificationInvocationCount: Records the number of callbacks whose handlers have been copied but not yet completed.
        std::size_t gR0NotificationInvocationCount = 0U;
        DriverClient::R0UnavailableHandler gR0UnavailableHandler;
        std::chrono::steady_clock::time_point gLastR0UnavailableNotification;
        DriverClient::R0PermissionRequiredHandler gR0PermissionRequiredHandler;
        std::chrono::steady_clock::time_point gLastR0PermissionNotification;

        // finishR0NotificationInvocation：
        // - Return the lease at the end of a handler call outside the lock.
        // - Wake the main window currently being destructed after the last lease is returned.
        void finishR0NotificationInvocation()
        {
            std::lock_guard<std::mutex> lock(gR0NotificationMutex);
            if (gR0NotificationInvocationCount > 0U)
            {
                --gR0NotificationInvocationCount;
            }
            if (gR0NotificationInvocationCount == 0U)
            {
                gR0NotificationIdleCondition.notify_all();
            }
        }

        // R0NotificationInvocationLease：
        // - handler obtains an in-flight lease after successfully copying from the global state.
        // - Automatically returns on destruction to ensure waiters are not permanently blocked if the handler throws an exception.
        class R0NotificationInvocationLease final
        {
        public:
            R0NotificationInvocationLease() = default;
            R0NotificationInvocationLease(const R0NotificationInvocationLease&) = delete;
            R0NotificationInvocationLease& operator=(const R0NotificationInvocationLease&) = delete;

            ~R0NotificationInvocationLease()
            {
                if (active_)
                {
                    finishR0NotificationInvocation();
                }
            }

            // activate: Marks the local lease only after the global count has been incremented; the caller need not pass arguments.
            void activate() noexcept
            {
                active_ = true;
            }

        private:
            // m_active: Distinguishes between early-return paths and calls that actually acquire a global in-flight reference.
            bool active_ = false;
        };

        bool isR0DriverNotEnabledError(const unsigned long win32Error)
        {
            // ERROR_FILE_NOT_FOUND is the expected behavior for CreateFile(\\.\\KswordARKLog) when the service is not running.
            // PATH_NOT_FOUND covers exceptional device namespace states; other errors are still passed to the caller for handling based on permissions,
            // signatures, or protocol issues, avoiding the misinterpretation of 'driver enabled but operation failed' as 'please enable R0'.
            return win32Error == ERROR_FILE_NOT_FOUND || win32Error == ERROR_PATH_NOT_FOUND;
        }

        void notifyR0DriverUnavailable(const unsigned long win32Error)
        {
            if (!isR0DriverNotEnabledError(win32Error))
            {
                return;
            }

            DriverClient::R0UnavailableHandler handler;
            R0NotificationInvocationLease invocationLease;
            {
                std::lock_guard<std::mutex> lock(gR0NotificationMutex);
                const auto kNow = std::chrono::steady_clock::now();
                if (!gR0UnavailableHandler ||
                    (gLastR0UnavailableNotification.time_since_epoch().count() != 0 &&
                        kNow - gLastR0UnavailableNotification < std::chrono::seconds(2)))
                {
                    return;
                }
                gLastR0UnavailableNotification = kNow;
                handler = gR0UnavailableHandler;
                ++gR0NotificationInvocationCount;
                invocationLease.activate();
            }

            // Do not execute UI callbacks within the lock; the lease ensures that handler is cleared and the current call completes before proceeding.
            handler(win32Error);
        }

        bool isR0PermissionRequiredError(const unsigned long win32Error)
        {
            return win32Error == ERROR_ACCESS_DENIED ||
                win32Error == ERROR_PRIVILEGE_NOT_HELD ||
                win32Error == ERROR_ELEVATION_REQUIRED ||
                win32Error == ERROR_NOT_ALL_ASSIGNED;
        }

        void notifyR0PermissionRequired(const unsigned long win32Error)
        {
            if (!isR0PermissionRequiredError(win32Error))
            {
                return;
            }

            DriverClient::R0PermissionRequiredHandler handler;
            R0NotificationInvocationLease invocationLease;
            {
                std::lock_guard<std::mutex> lock(gR0NotificationMutex);
                const auto kNow = std::chrono::steady_clock::now();
                if (!gR0PermissionRequiredHandler ||
                    (gLastR0PermissionNotification.time_since_epoch().count() != 0 &&
                        kNow - gLastR0PermissionNotification < std::chrono::seconds(2)))
                {
                    return;
                }
                gLastR0PermissionNotification = kNow;
                handler = gR0PermissionRequiredHandler;
                ++gR0NotificationInvocationCount;
                invocationLease.activate();
            }
            handler(win32Error);
        }

    }

    void DriverClient::setR0UnavailableHandler(R0UnavailableHandler handler)
    {
        std::lock_guard<std::mutex> lock(gR0NotificationMutex);
        gR0UnavailableHandler = std::move(handler);
        gLastR0UnavailableNotification = {};
    }

    void DriverClient::setR0PermissionRequiredHandler(R0PermissionRequiredHandler handler)
    {
        std::lock_guard<std::mutex> lock(gR0NotificationMutex);
        gR0PermissionRequiredHandler = std::move(handler);
        gLastR0PermissionNotification = {};
    }

    void DriverClient::clearR0NotificationHandlersAndWait()
    {
        // First revoke both entries within the same critical section so worker threads can no longer acquire new leases.
        std::unique_lock<std::mutex> lock(gR0NotificationMutex);
        gR0UnavailableHandler = {};
        gR0PermissionRequiredHandler = {};
        gLastR0UnavailableNotification = {};
        gLastR0PermissionNotification = {};

        // Threads that have copied the handler complete the dispatch outside the lock and are woken here by the lease destructor.
        gR0NotificationIdleCondition.wait(lock, []()
            {
                return gR0NotificationInvocationCount == 0U;
            });
    }

    DriverHandle::DriverHandle(const HANDLE handleValue) noexcept
        : handle_(handleValue)
    {
    }

    DriverHandle::~DriverHandle()
    {
        reset();
    }

    DriverHandle::DriverHandle(DriverHandle&& other) noexcept
        : handle_(other.release())
    {
    }

    DriverHandle& DriverHandle::operator=(DriverHandle&& other) noexcept
    {
        if (this != &other)
        {
            reset(other.release());
        }
        return *this;
    }

    bool DriverHandle::isValid() const noexcept
    {
        return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
    }

    HANDLE DriverHandle::native() const noexcept
    {
        return handle_;
    }

    HANDLE DriverHandle::release() noexcept
    {
        HANDLE detachedHandle = handle_;
        handle_ = INVALID_HANDLE_VALUE;
        return detachedHandle;
    }

    void DriverHandle::reset(const HANDLE newHandle) noexcept
    {
        if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE)
        {
            ::CloseHandle(handle_);
        }
        handle_ = newHandle;
    }

    DriverHandle DriverClient::open(const unsigned long desiredAccess) const
    {
        DriverHandle handle(::CreateFileW(
            KSWORD_ARK_LOG_WIN32_PATH,
            desiredAccess,
            kDefaultShareMode,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr));
        if (!handle.isValid())
        {
            const unsigned long kOpenError = ::GetLastError();
            notifyR0DriverUnavailable(kOpenError);
            notifyR0PermissionRequired(kOpenError);
        }
        return handle;
    }

    DriverHandle DriverClient::openSilently(const unsigned long desiredAccess) const
    {
        return DriverHandle(::CreateFileW(
            KSWORD_ARK_LOG_WIN32_PATH,
            desiredAccess,
            kDefaultShareMode,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr));
    }

    DriverHandle DriverClient::openOverlapped(const unsigned long desiredAccess) const
    {
        DriverHandle handle(::CreateFileW(
            KSWORD_ARK_LOG_WIN32_PATH,
            desiredAccess,
            kDefaultShareMode,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
            nullptr));
        if (!handle.isValid())
        {
            const unsigned long kOpenError = ::GetLastError();
            notifyR0DriverUnavailable(kOpenError);
            notifyR0PermissionRequired(kOpenError);
        }
        return handle;
    }

    IoResult DriverClient::deviceIoControl(
        const unsigned long ioControlCode,
        void* const inputBuffer,
        const unsigned long inputBytes,
        void* const outputBuffer,
        const unsigned long outputBytes,
        DriverHandle* const existingHandle) const
    {
        DriverHandle localHandle;
        DriverHandle* activeHandle = existingHandle;
        if (activeHandle == nullptr)
        {
            localHandle = open();
            activeHandle = &localHandle;
        }

        if (activeHandle == nullptr || !activeHandle->isValid())
        {
            const unsigned long kOpenError = ::GetLastError();
            notifyR0PermissionRequired(kOpenError);
            IoResult result = makeWin32IoResult(false, kOpenError, 0, "CreateFileW(KswordARK)");
            return result;
        }

        DWORD bytesReturned = 0;
        const BOOL kIoctlOk = ::DeviceIoControl(
            activeHandle->native(),
            ioControlCode,
            inputBuffer,
            inputBytes,
            outputBuffer,
            outputBytes,
            &bytesReturned,
            nullptr);
        const unsigned long kIoctlError = kIoctlOk ? ERROR_SUCCESS : ::GetLastError();
        if (kIoctlOk == FALSE)
        {
            notifyR0PermissionRequired(kIoctlError);
        }
        return makeWin32IoResult(kIoctlOk != FALSE, kIoctlError, bytesReturned, "KswordARK DeviceIoControl");
    }

    AsyncIoResult DriverClient::deviceIoControlAsync(
        DriverHandle& handle,
        const unsigned long ioControlCode,
        void* const inputBuffer,
        const unsigned long inputBytes,
        void* const outputBuffer,
        const unsigned long outputBytes,
        OVERLAPPED* const overlapped) const
    {
        AsyncIoResult result{};
        if (!handle.isValid())
        {
            result.issued = false;
            result.win32Error = ERROR_INVALID_HANDLE;
            return result;
        }

        DWORD bytesReturned = 0;
        const BOOL kIoctlOk = ::DeviceIoControl(
            handle.native(),
            ioControlCode,
            inputBuffer,
            inputBytes,
            outputBuffer,
            outputBytes,
            &bytesReturned,
            overlapped);
        result.issued = (kIoctlOk != FALSE);
        result.win32Error = result.issued ? ERROR_SUCCESS : ::GetLastError();
        if (!result.issued)
        {
            notifyR0PermissionRequired(result.win32Error);
        }
        result.bytesReturned = bytesReturned;
        return result;
    }

}
