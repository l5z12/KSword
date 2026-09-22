#pragma once

// ============================================================
// WindowCaptureProtection.h
// Purpose:
// 1) Provides HWND-level screenshot protection encapsulation for the window management page;
// 2) Directly call SetWindowDisplayAffinity for this process's windows.
// 3) External x64 processes invoke calls within the target process via short remote threads.
// ============================================================

#include <cstdint>
#include <string>

namespace ks::window
{
    // DisplayAffinity constants:
    // - AllowCapture: restores normal screenshot/screen recording;
    // - MonitorOnly: Fallback for older systems; screenshots show a black screen.
    // - ExcludeFromCapture: New system priority strategy; hides windows during screenshots/screen recordings.
    constexpr std::uint32_t kDisplayAffinityAllowCapture = 0x00000000;
    constexpr std::uint32_t kDisplayAffinityMonitorOnly = 0x00000001;
    constexpr std::uint32_t kDisplayAffinityExcludeFromCapture = 0x00000011;

    // CaptureProtectionResult：
    // - Purpose: Holds the complete result of a screenshot protection write operation.
    // - Call: OtherDock displays logs and prompts based on success/detail.
    struct CaptureProtectionResult
    {
        bool success = false;                       // success: Whether SetWindowDisplayAffinity ultimately succeeded.
        bool requestedProtection = false;           // requestedProtection: Indicates whether protection is requested in this instance.
        bool usedRemoteThread = false;              // usedRemoteThread: Whether to use cross-process remote thread calls.
        bool usedRootWindow = false;                // usedRootWindow: Whether to merge from child windows to the root window for execution.
        std::uint64_t requestedHwnd = 0;             // requestedHwnd: Original HWND selected by the user.
        std::uint64_t appliedHwnd = 0;               // appliedHwnd: The HWND that actually writes to DisplayAffinity.
        std::uint32_t processId = 0;                 // processId: PID of the process owning the target root window.
        std::uint32_t appliedAffinity = 0;           // appliedAffinity: The final requested/applied WDA_* value.
        std::uint32_t win32Error = 0;                // win32Error: Retains the Win32 error code upon failure.
        std::string detail;                         // detail: Diagnostic text for logs or prompts.
    };

    // setWindowCaptureProtection:
    // - Enable or disable screenshot protection for a given HWND;
    // - Input hwndValue: Window handle integer value;
    // - Input enableProtection: true=enable, false=disable;
    // - Returns CaptureProtectionResult; the caller is responsible for displaying the result.
    CaptureProtectionResult setWindowCaptureProtection(
        std::uint64_t hwndValue,
        bool enableProtection);

    // queryWindowDisplayAffinity:
    // - Attempt to read the window's current DisplayAffinity.
    // - Input hwndValue: Window handle integer value;
    // - Output affinityOut: write WDA_* value on success.
    // - Returns true on successful read; false if the system denies access or the window is unsupported.
    bool queryWindowDisplayAffinity(
        std::uint64_t hwndValue,
        std::uint32_t& affinityOut,
        std::uint32_t* win32ErrorOut);

    // displayAffinityName:
    // - Convert WDA_* values to Chinese descriptions.
    // - Call: UI summary, logs, and message boxes are reusable.
    std::string displayAffinityName(std::uint32_t affinityValue);
}
