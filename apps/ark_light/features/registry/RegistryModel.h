#pragma once

#include "../../core/Win32Lean.h"

#include <cstdint>
#include <string>
#include <vector>

namespace ksword::features::registry {

// RegistryValueKind identifies what a displayed row represents. Inputs are set
// by R3/R0 enumeration code; processing in the view uses the value to choose
// context-menu commands; no behavior is embedded in the enum itself.
enum class RegistryRowKind {
    kSubKey,
    kValue
};

// RegistryViewMode chooses whether enumeration uses normal Win32 registry APIs
// or the KswordARK R0 registry IOCTL facade. Inputs come from the toolbar; output
// influences only the next refresh/read/write command.
enum class RegistryViewMode {
    kWinApi,
    kR0
};

// RegistryEntry is one visible row in the registry dock. Inputs are collected
// from either RegEnumKeyEx/RegEnumValue or ArkDriverClient; processing stores
// stable display fields and raw bytes for copy/read actions.
struct RegistryEntry {
    RegistryRowKind kind = RegistryRowKind::kSubKey;
    std::wstring name;
    std::wstring typeText;
    std::wstring dataText;
    std::wstring detailText;
    std::uint32_t valueType = 0;
    std::vector<std::uint8_t> data;
};

// RegistrySnapshot is the result of enumerating one key. Inputs are a requested
// path and mode; processing fills rows and status; output is consumed by the
// Win32 view.
struct RegistrySnapshot {
    bool success = false;
    RegistryViewMode mode = RegistryViewMode::kWinApi;
    std::wstring displayPath;
    std::wstring kernelPath;
    std::wstring statusText;
    std::vector<RegistryEntry> rows;
};

// RegistryOperationResult describes create/delete/rename/write/read commands.
// Inputs depend on the operation; processing is done in RegistryActions; output
// is a compact status plus optional returned data.
struct RegistryOperationResult {
    bool success = false;
    DWORD win32Error = ERROR_SUCCESS;
    long ntStatus = 0;
    std::wstring statusText;
    std::vector<std::uint8_t> data;
    std::uint32_t valueType = 0;
};

// RegistryPathInfo is the parsed form of a user path. Inputs are root aliases
// such as HKLM\Software or kernel paths such as \REGISTRY\MACHINE\Software;
// processing resolves Win32 and kernel paths; output is used by both transports.
struct RegistryPathInfo {
    bool valid = false;
    HKEY root = nullptr;
    std::wstring rootText;
    std::wstring subKey;
    std::wstring displayPath;
    std::wstring kernelPath;
    std::wstring errorText;
};

// parseRegistryPath converts display/kernel registry paths into a common model.
// Input is raw user text; output contains Win32 root/subkey plus kernel path.
RegistryPathInfo parseRegistryPath(const std::wstring& text);

// parentRegistryPath returns the direct parent path of one registry key.
// Inputs are a display path such as HKLM\Software\Classes; output keeps the
// same root and removes one trailing segment; root keys are returned unchanged.
std::wstring parentRegistryPath(const std::wstring& text);

// rootRegistryPath returns the canonical root path for a display path. Inputs
// are any registry path; output is HKCR/HKCU/HKLM/HKU/HKCC or empty on failure.
std::wstring rootRegistryPath(const std::wstring& text);

// registryTypeText converts REG_* constants into display text. Input is a value
// type from Win32 or R0; output is a stable label.
std::wstring registryTypeText(std::uint32_t type);

// formatRegistryData converts raw registry value bytes to compact display text.
// Inputs are value type and byte buffer; processing decodes common string/DWORD
// forms and falls back to hex; output is safe for list controls.
std::wstring formatRegistryData(std::uint32_t type, const std::vector<std::uint8_t>& data);

// parseRegistryDataText converts user-entered text into raw bytes for the given
// REG_* type. Inputs are type and edit text; output is true with bytes or false
// with errorText.
bool parseRegistryDataText(std::uint32_t type, const std::wstring& text, std::vector<std::uint8_t>& bytes, std::wstring& errorText);

} // namespace Ksword::Features::Registry
