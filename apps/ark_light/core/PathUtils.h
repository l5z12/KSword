#pragma once

#include <string>

namespace ksword::core {

// modulePath returns the current executable path. There is no input; processing
// expands a Win32 path buffer; output is empty only when GetModuleFileNameW fails.
std::wstring modulePath();

// moduleDirectory returns the directory containing this executable. There is no
// input; processing trims modulePath at the final separator; output is empty on
// failure.
std::wstring moduleDirectory();

// JoinPath joins two Windows path fragments. Inputs are a base and child path;
// processing inserts one slash when needed; output is a combined path string.
std::wstring joinPath(const std::wstring& base, const std::wstring& child);

// fileExists checks for a normal filesystem file. Input is a path; processing
// queries file attributes; output is true only for existing non-directory files.
bool fileExists(const std::wstring& path);

} // namespace Ksword::Core
