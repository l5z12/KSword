#include "Launcher.h"

#include <bcrypt.h>
#include <shlobj.h>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <vector>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shell32.lib")

namespace launcher {

std::wstring utf8ToWide(const std::string& text) {
    if (text.empty()) return {};
    const int kCount = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (kCount <= 0) return {};
    std::wstring output(static_cast<size_t>(kCount), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), &output[0], kCount);
    return output;
}

std::string wideToUtf8(const std::wstring& text) {
    if (text.empty()) return {};
    const int kCount = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (kCount <= 0) return {};
    std::string output(static_cast<size_t>(kCount), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), &output[0], kCount, nullptr, nullptr);
    return output;
}

std::wstring lowerWide(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) { return static_cast<wchar_t>(towlower(ch)); });
    return value;
}

std::string upperAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) { return static_cast<char>(toupper(ch)); });
    return value;
}

std::wstring joinPath(const std::wstring& parent, const std::wstring& child) {
    if (parent.empty()) return child;
    if (child.empty()) return parent;
    if (parent.back() == L'\\' || parent.back() == L'/') return parent + child;
    return parent + L"\\" + child;
}

bool fileExists(const std::wstring& path) {
    const DWORD kAttributes = GetFileAttributesW(path.c_str());
    return kAttributes != INVALID_FILE_ATTRIBUTES && !(kAttributes & FILE_ATTRIBUTE_DIRECTORY);
}

bool ensureDirectory(const std::wstring& path) {
    if (path.empty()) return false;
    if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES) return true;
    const size_t kSeparator = path.find_last_of(L"\\/");
    if (kSeparator != std::wstring::npos && kSeparator > 2 && !ensureDirectory(path.substr(0, kSeparator))) return false;
    return CreateDirectoryW(path.c_str(), nullptr) || GetLastError() == ERROR_ALREADY_EXISTS;
}

bool readFileBytes(const std::wstring& path, std::vector<BYTE>* bytes) {
    if (!bytes) return false;
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size = {};
    const bool kSizeOk = GetFileSizeEx(file, &size) && size.QuadPart >= 0 && size.QuadPart <= 512LL * 1024LL * 1024LL;
    if (!kSizeOk) { CloseHandle(file); return false; }
    bytes->resize(static_cast<size_t>(size.QuadPart));
    DWORD read = 0;
    const bool kReadOk = bytes->empty() || ReadFile(file, bytes->data(), static_cast<DWORD>(bytes->size()), &read, nullptr) != FALSE;
    CloseHandle(file);
    if (!kReadOk || read != bytes->size()) { bytes->clear(); return false; }
    return true;
}

bool writeTextFile(const std::wstring& path, const std::string& text) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    const bool kOk = text.empty() || (WriteFile(file, text.data(), static_cast<DWORD>(text.size()), &written, nullptr) != FALSE && written == text.size());
    CloseHandle(file);
    return kOk;
}

bool readTextFile(const std::wstring& path, std::string* text) {
    std::vector<BYTE> bytes;
    if (!readFileBytes(path, &bytes)) return false;
    if (bytes.size() >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF) bytes.erase(bytes.begin(), bytes.begin() + 3);
    text->assign(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    return true;
}

std::string sha256Bytes(const BYTE* data, size_t size) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectLength = 0;
    DWORD resultLength = 0;
    std::string output;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return {};
    if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &resultLength, 0) != 0) { BCryptCloseAlgorithmProvider(algorithm, 0); return {}; }
    std::vector<BYTE> object(objectLength);
    if (BCryptCreateHash(algorithm, &hash, object.data(), objectLength, nullptr, 0, 0) != 0) { BCryptCloseAlgorithmProvider(algorithm, 0); return {}; }
    if (size > 0 && BCryptHashData(hash, const_cast<PUCHAR>(data), static_cast<ULONG>(size), 0) != 0) { BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(algorithm, 0); return {}; }
    BYTE digest[32] = {};
    if (BCryptFinishHash(hash, digest, sizeof(digest), 0) == 0) {
        static const char kDigits[] = "0123456789abcdef";
        output.reserve(64);
        for (BYTE value : digest) { output.push_back(kDigits[value >> 4]); output.push_back(kDigits[value & 0x0F]); }
    }
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return output;
}

std::string sha256File(const std::wstring& path) {
    std::vector<BYTE> bytes;
    return readFileBytes(path, &bytes) ? sha256Bytes(bytes.data(), bytes.size()) : std::string();
}

std::string formatWin32Error(DWORD error) {
    wchar_t* buffer = nullptr;
    const DWORD kLength = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, error, 0, reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);
    std::wstring text = kLength && buffer ? std::wstring(buffer, kLength) : L"unknown error";
    if (buffer) LocalFree(buffer);
    while (!text.empty() && (text.back() == L'\r' || text.back() == L'\n' || text.back() == L' ')) text.pop_back();
    return wideToUtf8(text);
}

std::string hex32(DWORD value) {
    char buffer[9] = {};
    sprintf_s(buffer, "%08X", value);
    return buffer;
}

bool isChineseUi() {
    // The UI language should use the Windows user interface language, not the potentially different date/number format locale.
    const LANGID kLanguage = GetUserDefaultUILanguage();
    return PRIMARYLANGID(kLanguage) == LANG_CHINESE;
}

OsInfo queryOsInfo() {
    OsInfo output;
    using RtlGetVersionFn = LONG(WINAPI*)(PRTL_OSVERSIONINFOW);
    auto getVersion = reinterpret_cast<RtlGetVersionFn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion"));
    RTL_OSVERSIONINFOW version = { sizeof(version) };
    if (getVersion && getVersion(&version) == 0) {
        output.major = version.dwMajorVersion;
        output.minor = version.dwMinorVersion;
        output.build = version.dwBuildNumber;
    }
    return output;
}

RuntimePaths resolveRuntimePaths() {
    RuntimePaths paths;
    wchar_t executable[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, executable, MAX_PATH);
    paths.launcherDirectory = executable;
    const size_t kSeparator = paths.launcherDirectory.find_last_of(L"\\/");
    paths.launcherDirectory = kSeparator == std::wstring::npos ? L"." : paths.launcherDirectory.substr(0, kSeparator);
    paths.configDirectory = joinPath(paths.launcherDirectory, L"config");
    paths.manifestPath = joinPath(paths.launcherDirectory, L"profiles\\launcher_support_manifest.json");
    paths.mainPath = joinPath(paths.launcherDirectory, L"Ksword5.1.exe");
    paths.lightPath = joinPath(paths.launcherDirectory, L"KswordARKLight.exe");
    paths.markerPath = joinPath(paths.configDirectory, L"launcher_check.json");
    return paths;
}

bool loadSupportManifest(const RuntimePaths& paths, SupportManifest* manifest) {
    if (!manifest) return false;
    *manifest = SupportManifest();
    std::string text;
    if (!readTextFile(paths.manifestPath, &text)) { manifest->error = "manifest file is missing or unreadable"; return false; }
    manifest->sha256 = sha256File(paths.manifestPath);
    JsonValue root;
    std::string error;
    if (!parseJson(text, &root, &error) || !root.isObject()) { manifest->error = "manifest JSON parse failed: " + error; return false; }
    manifest->schemaVersion = static_cast<int>(root.numberOr("schemaVersion", 0));
    manifest->generatedUtc = root.stringOr("generatedUtc", "");
    manifest->product = root.stringOr("product", "");
    const JsonValue* policy = root.get("osPolicy");
    if (manifest->schemaVersion != 1 || !policy || !policy->isObject()) { manifest->error = "manifest schemaVersion or osPolicy is invalid"; return false; }
    manifest->minimumWindowsMajor = static_cast<DWORD>(policy->numberOr("minimumWindowsMajor", 0));
    manifest->qtMinimumBuild = static_cast<DWORD>(policy->numberOr("qtMinimumBuild", 0));
    manifest->advertisedMaximumBuild = static_cast<DWORD>(policy->numberOr("advertisedMaximumBuild", 0));
    manifest->allowNewerWindows11 = policy->booleanOr("allowNewerWindows11", false);
    const JsonValue* modules = root.get("modules");
    const JsonValue* profiles = root.get("profiles");
    if (!modules || !modules->isArray() || modules->array().size() != 11 || !profiles || !profiles->isArray()) { manifest->error = "manifest module/profile arrays are invalid"; return false; }
    for (const JsonValue& value : modules->array()) {
        if (!value.isObject()) { manifest->error = "manifest contains an invalid module"; return false; }
        ModuleDefinition module;
        module.classId = static_cast<int>(value.numberOr("classId", -1));
        module.className = value.stringOr("className", "");
        module.alwaysCollect = value.booleanOr("alwaysCollect", false);
        module.compatibilityRequired = value.booleanOr("compatibilityRequired", false);
        module.collectionOnly = value.booleanOr("collectionOnly", false);
        module.supportSource = value.stringOr("supportSource", "pdb-profile");
        module.publishedProfileCount = static_cast<int>(value.numberOr("publishedProfileCount", 0));
        module.completeProfileCount = static_cast<int>(value.numberOr("completeProfileCount", 0));
        module.coverageStatus = value.stringOr("coverageStatus", "unpublished");
        const JsonValue* names = value.get("fileNames");
        if (module.classId < 0 || module.className.empty() || (module.compatibilityRequired && module.collectionOnly) || !names || !names->isArray() || names->array().empty()) { manifest->error = "manifest module fields are invalid"; return false; }
        for (const JsonValue& name : names->array()) if (name.isString()) module.fileNames.push_back(utf8ToWide(name.string()));
        if (module.fileNames.empty()) { manifest->error = "manifest module fileNames are invalid"; return false; }
        manifest->modules.push_back(std::move(module));
    }
    for (const JsonValue& value : profiles->array()) {
        if (!value.isObject()) { manifest->error = "manifest contains an invalid profile"; return false; }
        SupportProfile profile;
        profile.classId = static_cast<int>(value.numberOr("moduleClassId", -1));
        profile.machine = static_cast<DWORD>(value.numberOr("machine", 0));
        profile.timeDateStamp = static_cast<DWORD>(value.numberOr("timeDateStamp", 0));
        profile.sizeOfImage = static_cast<DWORD>(value.numberOr("sizeOfImage", 0));
        profile.pdbName = value.stringOr("pdbName", "");
        profile.pdbGuid = upperAscii(value.stringOr("pdbGuid", ""));
        profile.pdbAge = static_cast<DWORD>(value.numberOr("pdbAge", 0));
        profile.complete = value.booleanOr("complete", false);
        profile.coveragePercent = value.numberOr("coveragePercent", 0.0);
        profile.profileName = value.stringOr("profileName", "");
        if (profile.classId < 0 || profile.pdbName.empty() || profile.pdbGuid.empty()) { manifest->error = "manifest profile identity is invalid"; return false; }
        manifest->profiles.push_back(std::move(profile));
    }
    manifest->valid = true;
    return true;
}

}
