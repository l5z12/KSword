#include "PathNavigator.h"

#include <algorithm>

namespace ksword::features::file {
namespace {

// trimWhitespace removes leading and trailing ASCII/Unicode whitespace from a
// path-like string. Input is any string; output keeps interior characters.
std::wstring trimWhitespace(const std::wstring& value) {
    const auto kFirst = std::find_if_not(value.begin(), value.end(), [](wchar_t ch) {
        return ch == L' ' || ch == L'\t' || ch == L'\r' || ch == L'\n';
    });
    if (kFirst == value.end()) {
        return {};
    }
    const auto kLast = std::find_if_not(value.rbegin(), value.rend(), [](wchar_t ch) {
        return ch == L' ' || ch == L'\t' || ch == L'\r' || ch == L'\n';
    }).base();
    return std::wstring(kFirst, kLast);
}

// trimWrappingQuotes removes one matching pair of command-line style quotes.
// Input is a trimmed string; output is unquoted only when both ends match.
std::wstring trimWrappingQuotes(const std::wstring& value) {
    if (value.size() >= 2 && value.front() == L'"' && value.back() == L'"') {
        return value.substr(1, value.size() - 2);
    }
    return value;
}

// expandEnvironmentPath expands %VAR% fragments using ExpandEnvironmentStringsW.
// Input is a user supplied path; output falls back to the input if expansion
// fails or if the result is unexpectedly empty.
std::wstring expandEnvironmentPath(const std::wstring& value) {
    const DWORD kNeeded = ::ExpandEnvironmentStringsW(value.c_str(), nullptr, 0);
    if (kNeeded == 0) {
        return value;
    }
    std::wstring expanded(kNeeded, L'\0');
    const DWORD kWritten = ::ExpandEnvironmentStringsW(value.c_str(), expanded.data(), kNeeded);
    if (kWritten == 0 || kWritten > kNeeded) {
        return value;
    }
    if (!expanded.empty() && expanded.back() == L'\0') {
        expanded.pop_back();
    }
    return expanded.empty() ? value : expanded;
}

// endsWithSeparator reports whether a path already ends with a Windows path
// separator. Input is a path string; output is a simple boolean.
bool endsWithSeparator(const std::wstring& path) {
    return !path.empty() && (path.back() == L'\\' || path.back() == L'/');
}

// isAsciiDriveLetter reports whether ch can introduce a DOS drive root. Input
// is one character; output is true only for ASCII A-Z or a-z.
bool isAsciiDriveLetter(const wchar_t ch) {
    return (ch >= L'A' && ch <= L'Z') || (ch >= L'a' && ch <= L'z');
}

// isValidKnownPathComponent accepts one literal component from a cached
// absolute path. It deliberately rejects wildcard, device and traversal syntax
// instead of attempting expansion or filesystem-based canonicalization.
bool isValidKnownPathComponent(const std::wstring& component) {
    if (component.empty() || component == L"." || component == L"..") {
        return false;
    }
    for (const wchar_t kCh : component) {
        if (kCh < L' ' || kCh == L'"' || kCh == L'*' || kCh == L'?' || kCh == L'<' ||
            kCh == L'>' || kCh == L'|' || kCh == L':') {
            return false;
        }
    }
    return true;
}

// validateKnownPathComponents checks every component after a root. Inputs are a
// normalized path and the root length; output is false for empty, duplicate or
// traversal components. No filesystem access occurs.
bool validateKnownPathComponents(const std::wstring& path, std::size_t rootLength) {
    if (rootLength > path.size()) {
        return false;
    }
    if (rootLength < path.size() && path[rootLength] == L'\\') {
        ++rootLength;
    }
    while (rootLength < path.size()) {
        const std::size_t kSeparator = path.find(L'\\', rootLength);
        const std::size_t kEnd = kSeparator == std::wstring::npos ? path.size() : kSeparator;
        if (!isValidKnownPathComponent(path.substr(rootLength, kEnd - rootLength))) {
            return false;
        }
        if (kSeparator == std::wstring::npos) {
            break;
        }
        rootLength = kSeparator + 1U;
    }
    return true;
}

// normalizeKnownAbsolutePath only accepts literal DOS and UNC names that came
// from an existing snapshot. It neither expands variables nor asks Windows to
// resolve a path, preserving the provenance boundary for cross-page routes.
std::wstring normalizeKnownAbsolutePath(const std::wstring& value, std::size_t& rootLength) {
    std::wstring path = trimWrappingQuotes(trimWhitespace(value));
    std::replace(path.begin(), path.end(), L'/', L'\\');
    rootLength = 0;
    if (path.empty()) {
        return {};
    }

    if (path.rfind(L"\\\\?\\", 0) == 0 || path.rfind(L"\\\\.\\", 0) == 0 ||
        path.rfind(L"\\??\\", 0) == 0 || path.rfind(L"\\Device\\", 0) == 0) {
        return {};
    }

    if (path.size() >= 3U && isAsciiDriveLetter(path[0]) && path[1] == L':' && path[2] == L'\\') {
        rootLength = 3U;
        while (path.size() > rootLength && path.back() == L'\\') {
            path.pop_back();
        }
        return validateKnownPathComponents(path, rootLength) ? path : std::wstring{};
    }

    if (path.rfind(L"\\\\", 0) != 0) {
        return {};
    }
    const std::size_t kServerEnd = path.find(L'\\', 2U);
    if (kServerEnd == std::wstring::npos || !isValidKnownPathComponent(path.substr(2U, kServerEnd - 2U))) {
        return {};
    }
    const std::size_t kShareStart = kServerEnd + 1U;
    const std::size_t kShareEnd = path.find(L'\\', kShareStart);
    const std::size_t kShareLength = (kShareEnd == std::wstring::npos ? path.size() : kShareEnd) - kShareStart;
    if (!isValidKnownPathComponent(path.substr(kShareStart, kShareLength))) {
        return {};
    }
    rootLength = kShareEnd == std::wstring::npos ? path.size() : kShareEnd;
    while (path.size() > rootLength && path.back() == L'\\') {
        path.pop_back();
    }
    return validateKnownPathComponents(path, rootLength) ? path : std::wstring{};
}

} // namespace

PathNavigator::PathNavigator() = default;

const std::wstring& PathNavigator::currentPath() const {
    return currentPath_;
}

std::wstring PathNavigator::navigateTo(const std::wstring& path) {
    const std::wstring kNormalized = normalizeDirectoryPath(path);
    if (kNormalized != currentPath_) {
        pushHistory(currentPath_);
        currentPath_ = kNormalized;
        forwardStack_.clear();
    }
    return currentPath_;
}

std::wstring PathNavigator::navigateUp() {
    return navigateTo(parentPath(currentPath_));
}

bool PathNavigator::navigateBack() {
    if (backStack_.empty()) {
        return false;
    }
    forwardStack_.push_back(currentPath_);
    currentPath_ = backStack_.back();
    backStack_.pop_back();
    return true;
}

bool PathNavigator::navigateForward() {
    if (forwardStack_.empty()) {
        return false;
    }
    backStack_.push_back(currentPath_);
    currentPath_ = forwardStack_.back();
    forwardStack_.pop_back();
    return true;
}

bool PathNavigator::canNavigateBack() const {
    return !backStack_.empty();
}

bool PathNavigator::canNavigateForward() const {
    return !forwardStack_.empty();
}

std::wstring PathNavigator::normalizeDirectoryPath(const std::wstring& path) {
    std::wstring normalized = expandEnvironmentPath(trimWrappingQuotes(trimWhitespace(path)));
    std::replace(normalized.begin(), normalized.end(), L'/', L'\\');
    if (normalized == L"此电脑" || normalized == L"计算机") {
        return {};
    }
    if (normalized == L"." || normalized == L".\\") {
        wchar_t buffer[MAX_PATH]{};
        const DWORD kLen = ::GetCurrentDirectoryW(MAX_PATH, buffer);
        if (kLen > 0 && kLen < MAX_PATH) {
            normalized.assign(buffer, kLen);
        }
    }
    while (normalized.size() > 3 && normalized.back() == L'\\') {
        normalized.pop_back();
    }
    if (normalized.size() == 2 && normalized[1] == L':') {
        normalized.push_back(L'\\');
    }
    return normalized;
}

std::wstring PathNavigator::normalizeKnownDirectoryPath(const std::wstring& path) {
    std::size_t rootLength = 0;
    return normalizeKnownAbsolutePath(path, rootLength);
}

std::wstring PathNavigator::parentDirectoryForKnownFilePath(const std::wstring& path) {
    std::size_t rootLength = 0;
    const std::wstring kNormalized = normalizeKnownAbsolutePath(path, rootLength);
    if (kNormalized.empty() || kNormalized.size() <= rootLength) {
        return {};
    }
    const std::size_t kSeparator = kNormalized.find_last_of(L'\\');
    if (kSeparator == std::wstring::npos) {
        return {};
    }
    if (rootLength == 3U && kSeparator == rootLength - 1U) {
        return kNormalized.substr(0, rootLength);
    }
    if (kSeparator <= rootLength) {
        return kNormalized.substr(0, rootLength);
    }
    return kNormalized.substr(0, kSeparator);
}

std::wstring PathNavigator::parentPath(const std::wstring& path) {
    const std::wstring kNormalized = normalizeDirectoryPath(path);
    if (kNormalized.empty() || isDriveRoot(kNormalized)) {
        return {};
    }
    if (kNormalized.size() <= 2) {
        return {};
    }

    std::wstring trimmed = kNormalized;
    while (trimmed.size() > 3 && trimmed.back() == L'\\') {
        trimmed.pop_back();
    }
    const std::wstring::size_type kSlash = trimmed.find_last_of(L'\\');
    if (kSlash == std::wstring::npos) {
        return {};
    }
    if (kSlash == 2 && trimmed.size() >= 3 && trimmed[1] == L':') {
        return trimmed.substr(0, 3);
    }
    if (kSlash == 0) {
        return L"\\";
    }
    return trimmed.substr(0, kSlash);
}

std::wstring PathNavigator::joinChildPath(const std::wstring& directory, const std::wstring& childName) {
    if (directory.empty()) {
        return childName;
    }
    if (endsWithSeparator(directory)) {
        return directory + childName;
    }
    return directory + L"\\" + childName;
}

std::wstring PathNavigator::makeSearchPattern(const std::wstring& directory) {
    if (directory.empty()) {
        return L"*";
    }
    return joinChildPath(directory, L"*");
}

bool PathNavigator::isDriveRoot(const std::wstring& path) {
    return path.size() == 3 &&
        ((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) &&
        path[1] == L':' &&
        path[2] == L'\\';
}

void PathNavigator::pushHistory(const std::wstring& path) {
    if (!backStack_.empty() && backStack_.back() == path) {
        return;
    }
    backStack_.push_back(path);
}

} // namespace Ksword::Features::File
