#pragma once

#include <QString>

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace ks::process
{
    // UserModeHotkeyRecord: A hotkey record readable by R3 in the 'Hotkeys' page of process details.
    struct UserModeHotkeyRecord
    {
        QString objectText;
        std::uint32_t hotkeyId = 0;
        std::uint32_t modifiers = 0;
        std::uint32_t virtualKey = 0;
        QString hotkeyText;
        std::uint32_t processId = 0;
        std::uint32_t threadId = 0;
        QString processName;
        QString sourceText;
        QString detailText;
    };

    struct UserModeHotkeyProcessTarget
    {
        std::uint32_t processId = 0;
        QString processName;
        QString processImagePath;
    };

    struct UserModeHotkeyBatchProgress
    {
        std::uint32_t completedProcessCount = 0;
        std::uint32_t totalProcessCount = 0;
        QString processName;
        QString diagnosticText;
        std::vector<UserModeHotkeyRecord> records;
    };

    using UserModeHotkeyBatchCallback = std::function<void(UserModeHotkeyBatchProgress progress)>;

    // enumerateUserModeHotkeysForProcess: Reuse the R3 hotkey collection path from process details.
    // Scans only window hotkeys, menu accelerators, PE accelerator resources, and .lnk shortcut hotkeys; does not access drivers.
    std::vector<UserModeHotkeyRecord> enumerateUserModeHotkeysForProcess(
        std::uint32_t processId,
        QString processName = {},
        QString processImagePath = {},
        QString* diagnosticTextOut = nullptr);

    // enumerateUserModeHotkeysForProcesses: shares a single .lnk read result during full scans, with per-process callbacks.
    void enumerateUserModeHotkeysForProcesses(
        const std::vector<UserModeHotkeyProcessTarget>& targets,
        const UserModeHotkeyBatchCallback& progressCallback,
        QString* diagnosticTextOut = nullptr);
}
