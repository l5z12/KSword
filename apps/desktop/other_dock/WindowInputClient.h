#pragma once

#include "DwmZOrderClient.h"

namespace ks::window_input
{
    enum class Mode { kUnchanged, kDisabled, kClickThrough, kCovered, kUiAccessFront, kUiAccessBack, kUiAccessCovered };
    enum class Status
    {
        kOk, kInvalidWindow, kSelfWindow, kUnsupportedWindow, kNativeFailure,
        kDwmFailure, kOrderInUse, kRestoreFailed, kLimitReached, kOrderChanged, kKernelFailure
    };
    struct Result
    {
        Status status = Status::kOk;
        std::uint32_t error = 0;
        bool enabled = false;
        bool clickThrough = false;
        bool topmost = false;
        bool managed = false;
        bool restored = false;
        bool dwmAttempted = false;
        bool kernelAttempted = false;
        std::int32_t kernelStatus = 0;
        std::uint32_t band = 0;
        Mode mode = Mode::kUnchanged;
        dwm_order::Reply dwm;
    };

    // Supports child windows as well as top-level windows. Read-only.
    bool capture(std::uint64_t hwnd, dwm_order::WindowIdentity& identity, std::uint32_t& error);
    Result query(const dwm_order::WindowIdentity& identity, const std::wstring& agentPath = {});
    Result apply(const dwm_order::WindowIdentity& identity, Mode mode, const std::wstring& agentPath);
    Result restore(const dwm_order::WindowIdentity& identity, const std::wstring& agentPath);
    Result restoreAll(const std::wstring& agentPath);
    bool hasCoveredWindow();
    Result queryBandSupport();
}
