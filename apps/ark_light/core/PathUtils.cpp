#include "PathUtils.h"

#include "Win32Lean.h"
#include <vector>

namespace ksword::core {

std::wstring modulePath() {
    std::vector<wchar_t> buffer(1024, L'\0');
    while (buffer.size() < 32768) {
        const DWORD kWritten = ::GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (kWritten == 0) {
            return {};
        }
        if (kWritten < buffer.size()) {
            return std::wstring(buffer.data(), kWritten);
        }
        buffer.resize(buffer.size() * 2, L'\0');
    }
    return {};
}

std::wstring moduleDirectory() {
    const std::wstring kPath = modulePath();
    const std::size_t kPos = kPath.find_last_of(L"\\/");
    return kPos == std::wstring::npos ? std::wstring() : kPath.substr(0, kPos);
}

std::wstring joinPath(const std::wstring& base, const std::wstring& child) {
    if (base.empty()) {
        return child;
    }
    if (child.empty()) {
        return base;
    }
    const wchar_t kLast = base.back();
    if (kLast == L'\\' || kLast == L'/') {
        return base + child;
    }
    return base + L"\\" + child;
}

bool fileExists(const std::wstring& path) {
    const DWORD kAttrs = ::GetFileAttributesW(path.c_str());
    return kAttrs != INVALID_FILE_ATTRIBUTES && (kAttrs & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

} // namespace Ksword::Core
