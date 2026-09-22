#pragma once

#include "Win32Lean.h"

#include <string>
#include <vector>

namespace ksword::core {

// PrivilegeEnableResult records one startup AdjustTokenPrivileges attempt.
// Inputs are filled by enableStartupPrivileges; processing code reads ok/error
// to summarize non-blocking startup privilege state; there is no behavior here.
struct PrivilegeEnableResult {
    std::wstring name;
    bool enabled = false;
    DWORD errorCode = ERROR_SUCCESS;
    std::wstring message;
};

// isRunningAsAdmin checks the current token elevation/member state. There is no
// input; processing queries the process token and Administrators SID; output is
// true when elevated enough for SCM/driver operations.
bool isRunningAsAdmin();

// relaunchElevated starts the same executable through ShellExecuteW("runas").
// Input is the current command tail; processing asks UAC for elevation; output
// is true when ShellExecute accepted the launch request.
bool relaunchElevated(const std::wstring& commandLineTail = L"");

// isUiAccessEnabled reports the current token UIAccess flag. There is no input;
// processing queries TokenUIAccess; output is false on failure or when disabled.
bool isUiAccessEnabled();

// describePrivilegeState creates compact status text. There is no input;
// processing combines Admin/UIAccess state; output is suitable for logs/status.
std::wstring describePrivilegeState();

// enableStartupPrivileges enables common process privileges after the shell is
// created. There is no input; processing opens the current token and applies
// AdjustTokenPrivileges one privilege at a time; output contains per-privilege
// status and never blocks startup because unavailable privileges are recorded.
std::vector<PrivilegeEnableResult> enableStartupPrivileges();

// summarizePrivilegeEnableResults creates a compact one-line status string.
// Input is the per-privilege result list; processing counts success/failure and
// names a few failures; output is suitable for status text or tooltip display.
std::wstring summarizePrivilegeEnableResults(const std::vector<PrivilegeEnableResult>& results);

// launchSelfWithSystemUiAccessToken starts a new instance with a duplicated
// SYSTEM primary token whose TokenUIAccess flag is enabled. Input is an optional
// detail output string; processing follows the KswordARK SYSTEM TokenUIAccess
// fallback path; output is true when the replacement process is created.
bool launchSelfWithSystemUiAccessToken(std::wstring* detailTextOut = nullptr);

} // namespace Ksword::Core
