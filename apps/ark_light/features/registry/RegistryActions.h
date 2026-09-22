#pragma once

#include "RegistryModel.h"
#include "RegistrySearchModel.h"

#include <atomic>
#include <memory>

namespace ksword::features::registry {

// enumerateRegistryKey reads subkeys and values for one registry path. Inputs
// are a display/kernel path and transport mode; processing uses WinAPI or
// ArkDriverClient; output is a snapshot for the view.
RegistrySnapshot enumerateRegistryKey(const std::wstring& path, RegistryViewMode mode);

// enumerateRegistrySubKeyNames reads only the direct child key names for one
// registry path. Inputs are a display/kernel path and transport mode; processing
// does not enumerate values and never recurses; output is used by the lazy
// TreeView expansion logic.
std::vector<std::wstring> enumerateRegistrySubKeyNames(const std::wstring& path, RegistryViewMode mode, std::wstring* statusTextOut = nullptr);

// searchRegistryWinApi walks one WinAPI registry subtree with fixed work,
// result, depth and preview bounds.  Inputs are a search request and an
// optional shared cancellation token; processing never uses the driver or the
// R0 browser mode; output is one immutable partial-or-complete snapshot.
RegistrySearchSnapshot searchRegistryWinApi(
    const RegistrySearchRequest& request,
    const std::shared_ptr<std::atomic_bool>& cancelToken);

// readRegistryValue reads a single value. Inputs are key path, value name, and
// transport mode; output contains raw bytes and status text.
RegistryOperationResult readRegistryValue(const std::wstring& path, const std::wstring& valueName, RegistryViewMode mode);

// writeRegistryValue writes a value. Inputs are path, value name, REG_* type,
// raw bytes and mode; output is a status object.
RegistryOperationResult writeRegistryValue(const std::wstring& path, const std::wstring& valueName, std::uint32_t type, const std::vector<std::uint8_t>& data, RegistryViewMode mode);

// deleteRegistryValue removes one value. Inputs are path, value name and mode;
// output describes whether deletion succeeded.
RegistryOperationResult deleteRegistryValue(const std::wstring& path, const std::wstring& valueName, RegistryViewMode mode);

// createRegistryKey creates one key. Inputs are full key path and mode; output
// describes the operation result.
RegistryOperationResult createRegistryKey(const std::wstring& path, RegistryViewMode mode);

// deleteRegistryKey deletes one key/subtree. Inputs are full key path and mode;
// output describes the operation result.
RegistryOperationResult deleteRegistryKey(const std::wstring& path, RegistryViewMode mode);

// renameRegistryValue renames one value under a key. Inputs are key path, old
// value name, new value name and mode; output describes the operation result.
RegistryOperationResult renameRegistryValue(const std::wstring& path, const std::wstring& oldName, const std::wstring& newName, RegistryViewMode mode);

// renameRegistryKey renames the final key component. Inputs are full key path,
// new leaf name and mode; output describes the operation result.
RegistryOperationResult renameRegistryKey(const std::wstring& path, const std::wstring& newName, RegistryViewMode mode);

// copyRegistryTextToClipboard writes Unicode text to the clipboard. Inputs are
// owner HWND and text; output is true when Windows accepts ownership.
bool copyRegistryTextToClipboard(HWND owner, const std::wstring& text);

} // namespace Ksword::Features::Registry
