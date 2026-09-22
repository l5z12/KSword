#include "WindowInputClient.h"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include "../../../shared/ark_client/ArkDriverClient.h"
#include <map>

namespace ks::window_input
{
    namespace
    {
        struct Saved
        {
            dwm_order::WindowIdentity identity;
            LONG_PTR originalStyle = 0;
            LONG_PTR originalExStyle = 0;
            LONG_PTR changedExMask = 0;
            Mode mode = Mode::kUnchanged;
            HANDLE cookie = nullptr;
            bool changedEnabled = false;
            bool changedTopmost = false;
            bool changedDwm = false;
            bool layerAttributesInitialized = false;
            std::uint32_t originalBand = 0;
            std::uint64_t windowObject = 0;
            bool changedBand = false;
        };
        std::map<std::uint64_t, Saved> savedWindows;
        std::uintptr_t nextCookie = 0;

        bool crossBand(Mode mode)
        { return mode == Mode::kUiAccessFront || mode == Mode::kUiAccessBack || mode == Mode::kUiAccessCovered; }
        bool covered(Mode mode) { return mode == Mode::kCovered || mode == Mode::kUiAccessCovered; }

        ksword::ark::WindowBandResult bandCall(const dwm_order::WindowIdentity& identity,
            ULONG operation, ULONG expected = 0, ULONG desired = 0, ULONG position = KSW_BAND_TOP,
            std::uint64_t object = 0)
        {
            KSWORD_ARK_WINDOW_BAND_REQUEST request{};
            request.operation = operation;
            request.hwnd = identity.hwnd;
            request.processId = identity.processId;
            request.threadId = identity.threadId;
            request.processCreated = identity.processCreated;
            request.expectedBand = expected;
            request.newBand = desired;
            request.position = position;
            request.expectedObject = object;
            if (operation == KSW_BAND_SET) request.confirmation = KSW_BAND_CONFIRMED;
            return ksword::ark::DriverClient().controlWindowBand(request);
        }

        bool bandReceipt(const ksword::ark::WindowBandResult& reply, Result& result)
        {
            result.kernelAttempted = true;
            result.kernelStatus = reply.response.lastStatus;
            result.band = reply.response.currentBand;
            if (!reply.io.ok) result.error = reply.io.win32Error;
            return reply.io.ok && reply.response.lastStatus >= 0 && (reply.response.flags & KSW_BAND_VERIFIED);
        }

        const wchar_t* propertyName()
        {
            static const std::wstring kName = L"KSword.WindowInput."
                + std::to_wstring(GetCurrentProcessId()) + L"." + std::to_wstring(GetTickCount64());
            return kName.c_str();
        }

        HWND window(const dwm_order::WindowIdentity& identity)
        { return reinterpret_cast<HWND>(identity.hwnd); }

        bool same(const dwm_order::WindowIdentity& expected)
        {
            dwm_order::WindowIdentity current;
            std::uint32_t error = 0;
            return capture(expected.hwnd, current, error)
                && current.processId == expected.processId && current.threadId == expected.threadId
                && current.processCreated == expected.processCreated;
        }

        bool alive(const Saved& saved)
        {
            // A HWND may be reused by the same process/thread. A property belongs
            // to the actual window object and disappears when that object dies.
            return same(saved.identity) && GetPropW(window(saved.identity), propertyName()) == saved.cookie;
        }

        void prune()
        {
            for (auto it = savedWindows.begin(); it != savedWindows.end();)
                if (!alive(it->second)) it = savedWindows.erase(it);
                else ++it;
        }

        bool readLong(HWND hwnd, int index, LONG_PTR& value, std::uint32_t& error)
        {
            SetLastError(ERROR_SUCCESS);
            value = GetWindowLongPtrW(hwnd, index);
            error = GetLastError();
            return value != 0 || error == ERROR_SUCCESS;
        }

        bool writeLong(HWND hwnd, int index, LONG_PTR value, std::uint32_t& error)
        {
            SetLastError(ERROR_SUCCESS);
            const LONG_PTR kPrevious = SetWindowLongPtrW(hwnd, index, value);
            error = GetLastError();
            LONG_PTR actual = 0;
            if ((!kPrevious && error) || !readLong(hwnd, index, actual, error)) return false;
            if (actual != value) { error = ERROR_INVALID_DATA; return false; }
            return true;
        }

        bool setEnabled(HWND hwnd, bool enabled, std::uint32_t& error)
        {
            SetLastError(ERROR_SUCCESS);
            // EnableWindow returns the PREVIOUS disabled state, not success.
            EnableWindow(hwnd, enabled ? TRUE : FALSE);
            error = GetLastError();
            LONG_PTR style = 0;
            std::uint32_t readError = 0;
            if (!readLong(hwnd, GWL_STYLE, style, readError)) { error = readError; return false; }
            if (((style & WS_DISABLED) == 0) != enabled)
            { if (!error) error = ERROR_ACCESS_DENIED; return false; }
            error = 0;
            return true;
        }

        bool setTopmost(HWND hwnd, bool topmost, std::uint32_t& error)
        {
            if (!SetWindowPos(hwnd, topmost ? HWND_TOPMOST : HWND_NOTOPMOST, 0, 0, 0, 0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_NOOWNERZORDER))
            { error = GetLastError(); return false; }
            LONG_PTR exStyle = 0;
            if (!readLong(hwnd, GWL_EXSTYLE, exStyle, error)) return false;
            if (((exStyle & WS_EX_TOPMOST) != 0) != topmost)
            { error = ERROR_INVALID_DATA; return false; }
            return true;
        }

        Result readState(const dwm_order::WindowIdentity& identity)
        {
            Result result;
            if (!same(identity))
            { result.status = Status::kInvalidWindow; result.error = ERROR_INVALID_WINDOW_HANDLE; return result; }
            LONG_PTR style = 0, exStyle = 0;
            if (!readLong(window(identity), GWL_STYLE, style, result.error)
                || !readLong(window(identity), GWL_EXSTYLE, exStyle, result.error))
            { result.status = Status::kNativeFailure; return result; }
            result.enabled = (style & WS_DISABLED) == 0;
            result.clickThrough = (exStyle & (WS_EX_LAYERED | WS_EX_TRANSPARENT))
                == (WS_EX_LAYERED | WS_EX_TRANSPARENT);
            result.topmost = (exStyle & WS_EX_TOPMOST) != 0;
            auto it = savedWindows.find(identity.hwnd);
            if (it != savedWindows.end() && alive(it->second))
            { result.managed = true; result.mode = it->second.mode; }
            return result;
        }

        bool restoreSaved(Saved& saved, const std::wstring& agentPath, Result& result)
        {
            if (!alive(saved)) return true; // Do not touch a replacement window.
            const HWND kHwnd = window(saved.identity);
            if (saved.changedBand)
            {
                auto current = bandCall(saved.identity, KSW_BAND_QUERY);
                if (!bandReceipt(current, result) || current.response.windowObject != saved.windowObject) return false;
                if (!bandReceipt(bandCall(saved.identity, KSW_BAND_SET, current.response.currentBand,
                    saved.originalBand, KSW_BAND_TOP, saved.windowObject), result)) return false;
                saved.changedBand = false;
            }
            if (saved.changedTopmost)
            {
                if (!setTopmost(kHwnd, (saved.originalExStyle & WS_EX_TOPMOST) != 0, result.error)) return false;
                saved.changedTopmost = false;
            }
            if (saved.changedDwm)
            {
                dwm_order::Request request;
                request.action = dwm_order::Action::kRestore;
                request.target = saved.identity;
                result.dwmAttempted = true;
                result.dwm = dwm_order::executeRequest(request, agentPath);
                if (result.dwm.response.status != dwm_order::Status::kNotRunning
                    && (result.dwm.response.status != dwm_order::Status::kOk
                        || !(result.dwm.response.flags & dwm_order::kVerified))) return false;
                saved.changedDwm = false;
            }
            if (!alive(saved)) return true;
            if (saved.changedEnabled)
            {
                if (!setEnabled(kHwnd, (saved.originalStyle & WS_DISABLED) == 0, result.error)) return false;
                saved.changedEnabled = false;
            }
            if (saved.changedExMask)
            {
                LONG_PTR current = 0;
                if (!readLong(kHwnd, GWL_EXSTYLE, current, result.error)) return false;
                LONG_PTR restoreMask = saved.changedExMask;
                if ((restoreMask & WS_EX_LAYERED) && saved.layerAttributesInitialized)
                {
                    COLORREF color = 0;
                    BYTE alpha = 0;
                    DWORD flags = 0;
                    // Preserve layering if the target has since adopted its own
                    // attributes or per-pixel rendering. We own only alpha=255.
                    if (!GetLayeredWindowAttributes(kHwnd, &color, &alpha, &flags)
                        || flags != LWA_ALPHA || alpha != 255)
                        restoreMask &= ~static_cast<LONG_PTR>(WS_EX_LAYERED);
                }
                if (!writeLong(kHwnd, GWL_EXSTYLE,
                    (current & ~restoreMask) | (saved.originalExStyle & restoreMask), result.error)) return false;
                saved.changedExMask = 0;
                RedrawWindow(kHwnd, nullptr, nullptr, RDW_INVALIDATE | RDW_FRAME | RDW_ALLCHILDREN);
            }
            RemovePropW(kHwnd, propertyName());
            return true;
        }
    }

    bool capture(std::uint64_t hwndValue, dwm_order::WindowIdentity& identity, std::uint32_t& error)
    {
        identity = {};
        const HWND kHwnd = reinterpret_cast<HWND>(hwndValue);
        DWORD pid = 0;
        const DWORD kTid = GetWindowThreadProcessId(kHwnd, &pid);
        if (!kHwnd || !kTid || !pid) { error = ERROR_INVALID_WINDOW_HANDLE; return false; }
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!process) { error = GetLastError(); return false; }
        FILETIME created{}, exited{}, kernel{}, user{};
        const bool kOk = GetProcessTimes(process, &created, &exited, &kernel, &user) != FALSE;
        error = kOk ? ERROR_SUCCESS : GetLastError();
        CloseHandle(process);
        if (!kOk) return false;
        DWORD checkedPid = 0;
        if (GetWindowThreadProcessId(kHwnd, &checkedPid) != kTid || checkedPid != pid)
        { error = ERROR_INVALID_WINDOW_HANDLE; return false; }
        identity = {hwndValue, pid, kTid,
            (static_cast<std::uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime};
        return true;
    }

    Result query(const dwm_order::WindowIdentity& identity, const std::wstring& agentPath)
    {
        const std::lock_guard<std::recursive_mutex> kLock(dwm_order::operationMutex());
        prune();
        Result result = readState(identity);
        if (result.status == Status::kOk && result.managed && crossBand(result.mode))
        {
            auto reply = bandCall(identity, KSW_BAND_QUERY, 0, 0,
                result.mode == Mode::kUiAccessBack ? KSW_BAND_BOTTOM : KSW_BAND_TOP);
            if (!bandReceipt(reply, result)) result.status = Status::kKernelFailure;
            else if (result.band != 2 || !(reply.response.flags & KSW_BAND_POSITION_VERIFIED)) result.status = Status::kOrderChanged;
        }
        if (result.status == Status::kOk && result.managed && covered(result.mode))
        {
            dwm_order::Request request;
            request.target = identity;
            result.dwmAttempted = true;
            result.dwm = dwm_order::executeRequest(request, agentPath);
            if (result.dwm.response.status != dwm_order::Status::kOk)
                result.status = Status::kDwmFailure;
            else if (!result.topmost || !(result.dwm.response.flags & dwm_order::kVerified)
                || !(result.dwm.response.flags & dwm_order::kMaintaining)
                || result.dwm.response.maintainedWindow != identity.hwnd)
                result.status = Status::kOrderChanged;
        }
        return result;
    }

    Result restore(const dwm_order::WindowIdentity& identity, const std::wstring& agentPath)
    {
        const std::lock_guard<std::recursive_mutex> kLock(dwm_order::operationMutex());
        Result result;
        auto it = savedWindows.find(identity.hwnd);
        const bool kHadRecord = it != savedWindows.end();
        if (it != savedWindows.end())
        {
            if (identity.processId != it->second.identity.processId
                || identity.threadId != it->second.identity.threadId
                || identity.processCreated != it->second.identity.processCreated)
            { result.status = Status::kInvalidWindow; result.error = ERROR_INVALID_WINDOW_HANDLE; return result; }
            if (!restoreSaved(it->second, agentPath, result))
            { result.status = Status::kRestoreFailed; return result; }
            savedWindows.erase(it);
        }
        result = readState(identity);
        result.restored = kHadRecord;
        return result;
    }

    Result apply(const dwm_order::WindowIdentity& identity, Mode mode, const std::wstring& agentPath)
    {
        const std::lock_guard<std::recursive_mutex> kLock(dwm_order::operationMutex());
        prune();
        Result result = readState(identity);
        if (result.status != Status::kOk) return result;
        if (identity.processId == GetCurrentProcessId()) { result.status = Status::kSelfWindow; return result; }
        if (mode < Mode::kUnchanged || mode > Mode::kUiAccessCovered)
        { result.status = Status::kUnsupportedWindow; return result; }
        if (mode == Mode::kUnchanged) return restore(identity, agentPath);
        if (result.managed)
        {
            result = restore(identity, agentPath);
            if (result.status != Status::kOk) return result;
        }
        if (savedWindows.size() >= 128) { result.status = Status::kLimitReached; return result; }
        const HWND kHwnd = window(identity);
        Saved saved;
        saved.identity = identity;
        saved.mode = mode;
        if (!readLong(kHwnd, GWL_STYLE, saved.originalStyle, result.error)
            || !readLong(kHwnd, GWL_EXSTYLE, saved.originalExStyle, result.error))
        { result.status = Status::kNativeFailure; return result; }
        if (mode == Mode::kClickThrough && !(saved.originalExStyle & WS_EX_LAYERED)
            && (GetClassLongPtrW(kHwnd, GCL_STYLE) & (CS_OWNDC | CS_CLASSDC)))
        { result.status = Status::kUnsupportedWindow; return result; }
        if (covered(mode) || crossBand(mode))
        {
            if (GetAncestor(kHwnd, GA_ROOT) != kHwnd || GetWindow(kHwnd, GW_OWNER)
                || !result.enabled || (saved.originalExStyle & WS_EX_TRANSPARENT)
                || !IsWindowVisible(kHwnd) || IsIconic(kHwnd))
            { result.status = Status::kUnsupportedWindow; return result; }
        }
        if (crossBand(mode))
        {
            auto reply = bandCall(identity, KSW_BAND_QUERY);
            if (!bandReceipt(reply, result)) { result.status = Status::kKernelFailure; return result; }
            saved.originalBand = reply.response.currentBand;
            saved.windowObject = reply.response.windowObject;
        }
        if (covered(mode))
        {
            dwm_order::Request request;
            request.target = identity;
            result.dwmAttempted = true;
            result.dwm = dwm_order::executeRequest(request, agentPath);
            if (result.dwm.response.status != dwm_order::Status::kOk
                || !(result.dwm.response.flags & dwm_order::kVerified))
            { result.status = Status::kDwmFailure; return result; }
            if (result.dwm.response.flags & dwm_order::kMaintaining)
            { result.status = Status::kOrderInUse; return result; }
        }
        saved.cookie = reinterpret_cast<HANDLE>(++nextCookie);
        if (!same(identity))
        { result.status = Status::kInvalidWindow; result.error = ERROR_INVALID_WINDOW_HANDLE; return result; }
        if (!SetPropW(kHwnd, propertyName(), saved.cookie))
        { result.status = Status::kNativeFailure; result.error = GetLastError(); return result; }
        auto& record = savedWindows.emplace(identity.hwnd, saved).first->second;
        bool ok = false;
        if (mode == Mode::kDisabled)
        {
            record.changedEnabled = (record.originalStyle & WS_DISABLED) == 0;
            ok = setEnabled(kHwnd, false, result.error);
        }
        else if (mode == Mode::kClickThrough)
        {
            const LONG_PTR kDesired = record.originalExStyle | WS_EX_LAYERED | WS_EX_TRANSPARENT;
            record.changedExMask = kDesired ^ record.originalExStyle;
            ok = writeLong(kHwnd, GWL_EXSTYLE, kDesired, result.error);
            if (ok && (record.changedExMask & WS_EX_LAYERED))
            {
                ok = SetLayeredWindowAttributes(kHwnd, 0, 255, LWA_ALPHA) != FALSE;
                record.layerAttributesInitialized = ok;
                if (!ok) result.error = GetLastError();
            }
        }
        else if (covered(mode) || crossBand(mode))
        {
            if (crossBand(mode))
            {
                // Keep recovery even if transport fails after R0 has committed.
                record.changedBand = true;
                record.changedTopmost = true;
                ok = bandReceipt(bandCall(identity, KSW_BAND_SET, record.originalBand, 2,
                    mode == Mode::kUiAccessBack ? KSW_BAND_BOTTOM : KSW_BAND_TOP, record.windowObject), result);
                if (!ok) result.status = Status::kKernelFailure;
            }
            else
            {
                record.changedTopmost = (record.originalExStyle & WS_EX_TOPMOST) == 0;
                ok = setTopmost(kHwnd, true, result.error);
            }
            if (ok && covered(mode))
            {
                dwm_order::Request request;
                request.action = dwm_order::Action::kApply;
                request.target = identity;
                request.position = dwm_order::Position::kBack;
                request.maintain = 1;
                record.changedDwm = true; // A timeout can still have applied the request.
                result.dwmAttempted = true;
                result.dwm = dwm_order::executeRequest(request, agentPath);
                ok = result.dwm.response.status == dwm_order::Status::kOk
                    && (result.dwm.response.flags & dwm_order::kVerified)
                    && (result.dwm.response.flags & dwm_order::kMaintaining)
                    && result.dwm.response.maintainedWindow == identity.hwnd;
                if (!ok) result.status = Status::kDwmFailure;
            }
        }
        if (ok && alive(record))
        {
            Result current = readState(identity);
            if (current.status == Status::kOk
                && (mode != Mode::kDisabled || !current.enabled)
                && (mode != Mode::kClickThrough || current.clickThrough)
                && (!covered(mode) || current.topmost))
            {
                current.kernelAttempted = result.kernelAttempted;
                current.kernelStatus = result.kernelStatus;
                current.band = result.band;
                return current;
            }
        }
        if (result.status == Status::kOk) result.status = Status::kNativeFailure;
        Result rollback;
        if (restoreSaved(record, agentPath, rollback)) savedWindows.erase(identity.hwnd);
        else
        {
            result.status = Status::kRestoreFailed;
            result.error = rollback.error;
            if (rollback.dwmAttempted) { result.dwm = rollback.dwm; result.dwmAttempted = true; }
            if (rollback.kernelAttempted) { result.kernelStatus = rollback.kernelStatus; result.kernelAttempted = true; }
        }
        return result;
    }

    Result restoreAll(const std::wstring& agentPath)
    {
        const std::lock_guard<std::recursive_mutex> kLock(dwm_order::operationMutex());
        Result firstFailure;
        for (auto it = savedWindows.begin(); it != savedWindows.end();)
        {
            Result result;
            if (restoreSaved(it->second, agentPath, result)) it = savedWindows.erase(it);
            else
            {
                result.status = Status::kRestoreFailed;
                if (firstFailure.status == Status::kOk) firstFailure = result;
                ++it;
            }
        }
        return firstFailure;
    }

    Result queryBandSupport()
    {
        const std::lock_guard<std::recursive_mutex> kLock(dwm_order::operationMutex());
        Result result;
        if (!bandReceipt(bandCall({}, KSW_BAND_PROBE), result)) result.status = Status::kKernelFailure;
        return result;
    }

    bool hasCoveredWindow()
    {
        const std::lock_guard<std::recursive_mutex> kLock(dwm_order::operationMutex());
        prune();
        for (const auto& [hwnd, saved] : savedWindows)
        {
            (void)hwnd;
            if (saved.changedDwm) return true;
        }
        return false;
    }
}
