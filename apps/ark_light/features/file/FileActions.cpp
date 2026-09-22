#include "FileActions.h"

#include "PathNavigator.h"

#include "../../../../shared/ark_client/ArkDriverClient.h"
#include "../../../../shared/platform/file/PeAnalyzer.h"

#include <commdlg.h>
#include <filesystem>
#include <objbase.h>
#include <Aclapi.h>
#include <restartmanager.h>
#include <shellapi.h>
#include <shobjidl.h>
#include <softpub.h>
#include <wincrypt.h>
#include <wintrust.h>

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <iomanip>
#include <new>
#include <sstream>
#include <vector>

namespace ksword::features::file {
namespace {


// utf8ToWide converts ArkDriverClient narrow diagnostics to UTF-16 UI text.
// Input is the driver-client message; processing uses strict UTF-8 first and a
// byte-wise fallback; output is safe for status labels and message boxes.
std::wstring utf8ToWide(const std::string& text) {
    if (text.empty()) {
        return {};
    }

    const int kRequired = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.c_str(), static_cast<int>(text.size()), nullptr, 0);
    if (kRequired > 0) {
        std::wstring wide(static_cast<std::size_t>(kRequired), L'\0');
        ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.c_str(), static_cast<int>(text.size()), wide.data(), kRequired);
        return wide;
    }

    std::wstring fallback;
    fallback.reserve(text.size());
    for (const unsigned char kCh : text) {
        fallback.push_back(static_cast<wchar_t>(kCh));
    }
    return fallback;
}

// enablePrivilege turns on one token privilege for the current process. Input is
// a privilege name such as SE_TAKE_OWNERSHIP_NAME; processing uses
// OpenProcessToken/AdjustTokenPrivileges; output reports whether the privilege
// is now enabled for the attempted operation.
bool enablePrivilege(const wchar_t* privilegeName) {
    HANDLE token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        return false;
    }

    TOKEN_PRIVILEGES privileges{};
    privileges.PrivilegeCount = 1;
    if (!::LookupPrivilegeValueW(nullptr, privilegeName, &privileges.Privileges[0].Luid)) {
        ::CloseHandle(token);
        return false;
    }
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    const BOOL kAdjusted = ::AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), nullptr, nullptr);
    const DWORD kError = ::GetLastError();
    ::CloseHandle(token);
    return kAdjusted && kError == ERROR_SUCCESS;
}

// HexText formats driver diagnostic addresses. Input is a 64-bit value; output
// is a compact uppercase hexadecimal string for result summaries.
std::wstring hexText(std::uint64_t value) {
    std::wostringstream stream;
    stream << L"0x" << std::hex << std::uppercase << value;
    return stream.str();
}

// buildDriverNtPath mirrors the original FileDock conversion before calling R0.
// Inputs are Win32, extended-length, UNC, or existing NT-style paths; processing
// normalizes separators and applies the shared driver path convention; output is
// empty only when input is empty.
std::wstring buildDriverNtPath(const std::wstring& path) {
    std::wstring nativePath = path;
    while (!nativePath.empty() && (nativePath.back() == L' ' || nativePath.back() == L'\t' || nativePath.back() == L'\r' || nativePath.back() == L'\n')) {
        nativePath.pop_back();
    }
    std::size_t first = 0;
    while (first < nativePath.size() && (nativePath[first] == L' ' || nativePath[first] == L'\t' || nativePath[first] == L'\r' || nativePath[first] == L'\n')) {
        ++first;
    }
    if (first > 0) {
        nativePath.erase(0, first);
    }
    for (wchar_t& ch : nativePath) {
        if (ch == L'/') {
            ch = L'\\';
        }
    }
    if (nativePath.empty()) {
        return {};
    }
    if (nativePath.rfind(L"\\??\\", 0) == 0) {
        return nativePath;
    }
    if (nativePath.rfind(L"\\\\?\\", 0) == 0) {
        return L"\\??\\" + nativePath.substr(4);
    }
    if (nativePath.rfind(L"\\Device\\", 0) == 0) {
        return nativePath;
    }
    if (nativePath.rfind(L"\\\\", 0) == 0) {
        return L"\\??\\UNC\\" + nativePath.substr(2);
    }
    return L"\\??\\" + nativePath;
}

// sectionKindText converts KSWORD_ARK_FILE_SECTION_KIND_* into display text.
// Input is a shared-protocol enum value; output is concise row text.
const wchar_t* sectionKindText(std::uint32_t value) {
    switch (value) {
    case KSWORD_ARK_FILE_SECTION_KIND_DATA: return L"Data";
    case KSWORD_ARK_FILE_SECTION_KIND_IMAGE: return L"Image";
    default: return L"Unknown";
    }
}

// viewMapTypeText converts KSWORD_ARK_SECTION_MAP_TYPE_* into display text.
// Input is a shared-protocol mapping type; output is concise row text.
const wchar_t* viewMapTypeText(std::uint32_t value) {
    switch (value) {
    case KSWORD_ARK_SECTION_MAP_TYPE_PROCESS: return L"Process";
    case KSWORD_ARK_SECTION_MAP_TYPE_SESSION: return L"Session";
    case KSWORD_ARK_SECTION_MAP_TYPE_SYSTEM_CACHE: return L"SystemCache";
    default: return L"Unknown";
    }
}

// fileSectionStatusText converts the R0 file-section query status. Input is a
// KSWORD_ARK_FILE_SECTION_QUERY_STATUS_* value; output matches the original UI
// diagnostics without depending on framework helpers.
const wchar_t* fileSectionStatusText(std::uint32_t value) {
    switch (value) {
    case KSWORD_ARK_FILE_SECTION_QUERY_STATUS_OK: return L"OK";
    case KSWORD_ARK_FILE_SECTION_QUERY_STATUS_PARTIAL: return L"Partial";
    case KSWORD_ARK_FILE_SECTION_QUERY_STATUS_DYNDATA_MISSING: return L"DynData Missing";
    case KSWORD_ARK_FILE_SECTION_QUERY_STATUS_FILE_OPEN_FAILED: return L"File Open Failed";
    case KSWORD_ARK_FILE_SECTION_QUERY_STATUS_FILE_OBJECT_FAILED: return L"FileObject Failed";
    case KSWORD_ARK_FILE_SECTION_QUERY_STATUS_SECTION_POINTERS_MISSING: return L"SectionObjectPointer Missing";
    case KSWORD_ARK_FILE_SECTION_QUERY_STATUS_CONTROL_AREA_MISSING: return L"ControlArea Missing";
    case KSWORD_ARK_FILE_SECTION_QUERY_STATUS_MAPPING_QUERY_FAILED: return L"Mapping Query Failed";
    case KSWORD_ARK_FILE_SECTION_QUERY_STATUS_BUFFER_TOO_SMALL: return L"Buffer Too Small";
    default: return L"Unavailable";
    }
}

// selectedPath returns the selected row's full path or an empty string. Input is
// a menu context; output is safe for Win32 APIs that require LPCWSTR paths.
std::wstring selectedPath(const FileActionContext& context) {
    return context.hasSelection ? context.selectedEntry.fullPath : std::wstring{};
}

// shellOpenPath delegates a path to ShellExecuteW. Inputs are owner/path; output
// is true when ShellExecuteW reports a value above 32.
bool shellOpenPath(HWND owner, const std::wstring& path) {
    if (path.empty()) {
        return false;
    }
    const HINSTANCE kRc = ::ShellExecuteW(owner, L"open", path.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
    return reinterpret_cast<INT_PTR>(kRc) > 32;
}

// openTerminalAtDirectory starts wt.exe or cmd.exe in a directory. Inputs are
// owner/current directory; processing never blocks waiting for the process;
// output is true if one ShellExecuteW launch succeeds.
bool openTerminalAtDirectory(HWND owner, const std::wstring& directory) {
    const std::wstring kCwd = directory.empty() ? L"C:\\" : directory;
    HINSTANCE rc = ::ShellExecuteW(owner, L"open", L"wt.exe", nullptr, kCwd.c_str(), SW_SHOWNORMAL);
    if (reinterpret_cast<INT_PTR>(rc) > 32) {
        return true;
    }
    rc = ::ShellExecuteW(owner, L"open", L"cmd.exe", nullptr, kCwd.c_str(), SW_SHOWNORMAL);
    return reinterpret_cast<INT_PTR>(rc) > 32;
}

// shortPathForFile returns the DOS 8.3 path when the volume provides one. Input
// is a full path; output is empty when GetShortPathNameW fails.
std::wstring shortPathForFile(const std::wstring& path) {
    const DWORD kNeeded = ::GetShortPathNameW(path.c_str(), nullptr, 0);
    if (kNeeded == 0) {
        return {};
    }
    std::wstring shortPath(kNeeded + 1, L'\0');
    const DWORD kWritten = ::GetShortPathNameW(path.c_str(), shortPath.data(), static_cast<DWORD>(shortPath.size()));
    if (kWritten == 0 || kWritten >= shortPath.size()) {
        return {};
    }
    shortPath.resize(kWritten);
    return shortPath;
}

// resolveLinkTarget reads a shell link target using IShellLink/IPersistFile.
// Input is a selected .lnk path; output is the resolved path or empty on
// unsupported file types/failures.
std::wstring resolveLinkTarget(const std::wstring& path) {
    if (path.size() < 4 || _wcsicmp(path.c_str() + path.size() - 4, L".lnk") != 0) {
        return {};
    }
    const HRESULT kInitResult = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    const bool kUninitializeCom = kInitResult == S_OK || kInitResult == S_FALSE;
    IShellLinkW* shellLink = nullptr;
    HRESULT hr = ::CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&shellLink));
    if (FAILED(hr) || shellLink == nullptr) {
        if (kUninitializeCom) {
            ::CoUninitialize();
        }
        return {};
    }
    IPersistFile* persistFile = nullptr;
    hr = shellLink->QueryInterface(IID_PPV_ARGS(&persistFile));
    if (FAILED(hr) || persistFile == nullptr) {
        shellLink->Release();
        if (kUninitializeCom) {
            ::CoUninitialize();
        }
        return {};
    }
    std::wstring target(MAX_PATH, L'\0');
    hr = persistFile->Load(path.c_str(), STGM_READ);
    if (SUCCEEDED(hr)) {
        WIN32_FIND_DATAW data{};
        hr = shellLink->GetPath(target.data(), static_cast<int>(target.size()), &data, SLGP_UNCPRIORITY);
    }
    persistFile->Release();
    shellLink->Release();
    if (kUninitializeCom) {
        ::CoUninitialize();
    }
    if (FAILED(hr)) {
        return {};
    }
    target.resize(std::wcslen(target.c_str()));
    return target;
}

// parentDirectoryOf returns the parent folder for a full path. Input is a file
// or directory path; output is empty if no separator exists.
std::wstring parentDirectoryOf(const std::wstring& path) {
    const std::size_t kSlash = path.find_last_of(L"\\/");
    if (kSlash == std::wstring::npos) {
        return {};
    }
    return path.substr(0, kSlash);
}

// displayNameFromPath returns the leaf file name. Input is a full path; output
// is the whole input when no separator exists.
std::wstring displayNameFromPath(const std::wstring& path) {
    const std::size_t kSlash = path.find_last_of(L"\\/");
    if (kSlash == std::wstring::npos || kSlash + 1 >= path.size()) {
        return path;
    }
    return path.substr(kSlash + 1);
}

// pickTargetFolder shows the standard shell folder picker. Inputs are the owner
// HWND and dialog title; processing uses IFileDialog with FOS_PICKFOLDERS so the
// file page stays Windows-API-only; output is the selected filesystem path or
// empty when the user cancels or the shell cannot resolve a path.
std::wstring pickTargetFolder(HWND owner, const wchar_t* title) {
    const HRESULT kInitResult = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    const bool kUninitializeCom = kInitResult == S_OK || kInitResult == S_FALSE;
    IFileDialog* dialog = nullptr;
    HRESULT hr = ::CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&dialog));
    if (FAILED(hr) || dialog == nullptr) {
        if (kUninitializeCom) {
            ::CoUninitialize();
        }
        return {};
    }

    DWORD options = 0;
    dialog->GetOptions(&options);
    dialog->SetOptions(options | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST);
    dialog->SetTitle(title);
    std::wstring selectedPath;
    hr = dialog->Show(owner);
    if (SUCCEEDED(hr)) {
        IShellItem* item = nullptr;
        hr = dialog->GetResult(&item);
        if (SUCCEEDED(hr) && item != nullptr) {
            PWSTR path = nullptr;
            hr = item->GetDisplayName(SIGDN_FILESYSPATH, &path);
            if (SUCCEEDED(hr) && path != nullptr) {
                selectedPath = path;
                ::CoTaskMemFree(path);
            }
            item->Release();
        }
    }
    dialog->Release();
    if (kUninitializeCom) {
        ::CoUninitialize();
    }
    return selectedPath;
}

// copyOrMovePathToFolder copies or moves the selected path into a user-selected
// target folder. Inputs are source path, destination directory, and move flag;
// processing uses std::filesystem so both files and directories are covered;
// output is a FileActionResult-style status through statusOut and a success bit.
bool copyOrMovePathToFolder(
    const std::wstring& sourcePath,
    const std::wstring& targetFolder,
    bool move,
    std::wstring& statusOut) {
    if (sourcePath.empty() || targetFolder.empty()) {
        statusOut = L"源路径或目标文件夹为空。";
        return false;
    }

    std::error_code error;
    const std::filesystem::path kSource(sourcePath);
    const std::filesystem::path kTarget = std::filesystem::path(targetFolder) / kSource.filename();
    if (move) {
        std::filesystem::rename(kSource, kTarget, error);
        if (error) {
            std::filesystem::copy(kSource, kTarget, std::filesystem::copy_options::recursive | std::filesystem::copy_options::overwrite_existing, error);
            if (!error) {
                std::filesystem::remove_all(kSource, error);
            }
        }
    } else {
        std::filesystem::copy(kSource, kTarget, std::filesystem::copy_options::recursive | std::filesystem::copy_options::overwrite_existing, error);
    }

    if (error) {
        statusOut = std::wstring(move ? L"移动失败: " : L"复制失败: ") + std::wstring(error.message().begin(), error.message().end());
        return false;
    }
    statusOut = std::wstring(move ? L"已移动到: " : L"已复制到: ") + kTarget.wstring();
    return true;
}

// takeOwnershipPath sets the selected file or directory owner to the current
// user. Inputs are a Win32 path and owner HWND only for diagnostics; processing
// enables SeTakeOwnershipPrivilege and calls SetNamedSecurityInfoW; output is a
// concise status message for the File page.
std::wstring takeOwnershipPath(const std::wstring& path) {
    if (path.empty()) {
        return L"路径为空，无法取得所有权。";
    }
    const bool kPrivilegeEnabled = enablePrivilege(SE_TAKE_OWNERSHIP_NAME);

    HANDLE token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return L"OpenProcessToken 失败，错误 " + std::to_wstring(::GetLastError());
    }

    DWORD bytes = 0;
    ::GetTokenInformation(token, TokenUser, nullptr, 0, &bytes);
    std::vector<BYTE> buffer(bytes);
    if (bytes == 0 || !::GetTokenInformation(token, TokenUser, buffer.data(), bytes, &bytes)) {
        const DWORD kError = ::GetLastError();
        ::CloseHandle(token);
        return L"GetTokenInformation(TokenUser) 失败，错误 " + std::to_wstring(kError);
    }
    TOKEN_USER* tokenUser = reinterpret_cast<TOKEN_USER*>(buffer.data());
    const DWORD kResult = ::SetNamedSecurityInfoW(
        const_cast<LPWSTR>(path.c_str()),
        SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION,
        tokenUser->User.Sid,
        nullptr,
        nullptr,
        nullptr);
    ::CloseHandle(token);

    if (kResult == ERROR_SUCCESS) {
        return std::wstring(L"已取得所有权。") + (kPrivilegeEnabled ? L"" : L"（SeTakeOwnershipPrivilege 未显式启用，但操作成功。）");
    }
    return std::wstring(L"取得所有权失败，错误 ") + std::to_wstring(kResult) +
        (kPrivilegeEnabled ? L"" : L"；同时无法启用 SeTakeOwnershipPrivilege。");
}

// queryFileLockers uses Restart Manager to list processes that currently hold
// the selected path. Inputs are a filesystem path; processing starts a temporary
// RM session and registers the file resource; output is a text report. It does
// not kill or unlock processes in the light build.
std::wstring queryFileLockers(const std::wstring& path) {
    if (path.empty()) {
        return L"路径为空，无法扫描占用进程。";
    }

    DWORD session = 0;
    wchar_t sessionKey[CCH_RM_SESSION_KEY + 1]{};
    DWORD status = ::RmStartSession(&session, 0, sessionKey);
    if (status != ERROR_SUCCESS) {
        return L"RmStartSession 失败，错误 " + std::to_wstring(status);
    }

    const wchar_t* resources[] = { path.c_str() };
    status = ::RmRegisterResources(session, 1, resources, 0, nullptr, 0, nullptr);
    if (status != ERROR_SUCCESS) {
        ::RmEndSession(session);
        return L"RmRegisterResources 失败，错误 " + std::to_wstring(status);
    }

    UINT needed = 0;
    UINT count = 0;
    DWORD reason = 0;
    status = ::RmGetList(session, &needed, &count, nullptr, &reason);
    std::vector<RM_PROCESS_INFO> processes(needed == 0 ? 1 : needed);
    count = static_cast<UINT>(processes.size());
    if (status == ERROR_MORE_DATA || status == ERROR_SUCCESS) {
        status = ::RmGetList(session, &needed, &count, processes.data(), &reason);
    }
    ::RmEndSession(session);

    if (status != ERROR_SUCCESS) {
        return L"RmGetList 失败，错误 " + std::to_wstring(status);
    }

    std::wostringstream report;
    report << L"文件解锁器(R3/R0) - Restart Manager 占用扫描\r\n\r\n"
           << L"目标: " << path << L"\r\n"
           << L"占用进程数: " << count << L"\r\n"
           << L"RebootReason: 0x" << std::hex << std::uppercase << reason << L"\r\n\r\n";
    if (count == 0) {
        report << L"未发现 Restart Manager 可见的占用进程。";
        return report.str();
    }
    for (UINT index = 0; index < count && index < processes.size(); ++index) {
        const RM_PROCESS_INFO& process = processes[index];
        report << L"PID=" << std::dec << process.Process.dwProcessId
               << L" App=" << process.strAppName
               << L" Service=" << process.strServiceShortName
               << L" Type=" << process.ApplicationType
               << L" Status=0x" << std::hex << std::uppercase << process.AppStatus
               << L"\r\n";
    }
    report << L"\r\n轻量版仅枚举占用者，不执行强制关闭/解锁。";
    return report.str();
}

// PromptForText uses a simple InputBox.exe fallback-free edit dialog based on
// DialogBoxIndirectParamW would be overkill here; instead it asks through a
// common save-file dialog seeded to the current parent. Input is the original
// path; output is the chosen destination path or empty when cancelled.
std::wstring promptRenameTarget(HWND owner, const std::wstring& originalPath) {
    wchar_t path[MAX_PATH]{};
    const std::wstring kLeaf = displayNameFromPath(originalPath);
    const std::wstring kParent = parentDirectoryOf(originalPath);
    if (kLeaf.size() < std::size(path)) {
        ::wcsncpy_s(path, std::size(path), kLeaf.c_str(), _TRUNCATE);
    }
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = owner;
    ofn.lpstrFile = path;
    ofn.nMaxFile = static_cast<DWORD>(std::size(path));
    ofn.lpstrInitialDir = kParent.empty() ? nullptr : kParent.c_str();
    ofn.lpstrTitle = L"重命名为";
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR;
    if (!::GetSaveFileNameW(&ofn)) {
        return {};
    }
    return std::wstring(path);
}

// bytesToHex formats a binary buffer as uppercase hex. Input is bytes; output is
// compact text for hashes and previews.
std::wstring bytesToHex(const BYTE* data, DWORD bytes) {
    std::wostringstream stream;
    stream << std::uppercase << std::hex << std::setfill(L'0');
    for (DWORD index = 0; index < bytes; ++index) {
        stream << std::setw(2) << static_cast<unsigned int>(data[index]);
    }
    return stream.str();
}

// computeSha256 hashes a file using CryptoAPI. Input is file path; output is
// hash text or empty; errorOut receives a compact diagnostic when provided.
std::wstring computeSha256(const std::wstring& path, std::wstring* errorOut) {
    HANDLE file = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        if (errorOut) {
            *errorOut = L"CreateFileW error " + std::to_wstring(::GetLastError());
        }
        return {};
    }
    HCRYPTPROV provider = 0;
    HCRYPTHASH hash = 0;
    if (!::CryptAcquireContextW(&provider, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) ||
        !::CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash)) {
        const DWORD kError = ::GetLastError();
        if (hash) {
            ::CryptDestroyHash(hash);
        }
        if (provider) {
            ::CryptReleaseContext(provider, 0);
        }
        ::CloseHandle(file);
        if (errorOut) {
            *errorOut = L"CryptoAPI error " + std::to_wstring(kError);
        }
        return {};
    }
    BYTE buffer[64 * 1024]{};
    DWORD read = 0;
    bool ok = true;
    while (::ReadFile(file, buffer, sizeof(buffer), &read, nullptr) && read > 0) {
        if (!::CryptHashData(hash, buffer, read, 0)) {
            ok = false;
            break;
        }
    }
    DWORD hashBytes = 32;
    BYTE hashValue[32]{};
    if (ok) {
        ok = ::CryptGetHashParam(hash, HP_HASHVAL, hashValue, &hashBytes, 0) != FALSE;
    }
    const DWORD kError = ok ? ERROR_SUCCESS : ::GetLastError();
    ::CryptDestroyHash(hash);
    ::CryptReleaseContext(provider, 0);
    ::CloseHandle(file);
    if (!ok) {
        if (errorOut) {
            *errorOut = L"Hash read error " + std::to_wstring(kError);
        }
        return {};
    }
    return bytesToHex(hashValue, hashBytes);
}

// computeFileEntropy samples a file and computes byte entropy. Inputs are path
// and max bytes; output is bits-per-byte, or negative on failure.
double computeFileEntropy(const std::wstring& path, std::uint64_t maxBytes, std::uint64_t* sampledOut) {
    HANDLE file = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return -1.0;
    }
    std::uint64_t counts[256]{};
    BYTE buffer[64 * 1024]{};
    DWORD read = 0;
    std::uint64_t total = 0;
    while (total < maxBytes && ::ReadFile(file, buffer, static_cast<DWORD>(std::min<std::uint64_t>(sizeof(buffer), maxBytes - total)), &read, nullptr) && read > 0) {
        for (DWORD index = 0; index < read; ++index) {
            ++counts[buffer[index]];
        }
        total += read;
    }
    ::CloseHandle(file);
    if (sampledOut) {
        *sampledOut = total;
    }
    if (total == 0) {
        return 0.0;
    }
    double entropy = 0.0;
    for (std::uint64_t count : counts) {
        if (count == 0) {
            continue;
        }
        const double kP = static_cast<double>(count) / static_cast<double>(total);
        entropy -= kP * (std::log(kP) / std::log(2.0));
    }
    return entropy;
}

// hexPreview reads the first bytes of a file and returns a small hex/ascii dump.
// Input is path and byte limit; output is display text or empty on failure.
std::wstring hexPreview(const std::wstring& path, DWORD maxBytes) {
    HANDLE file = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return {};
    }
    std::vector<BYTE> buffer(maxBytes);
    DWORD read = 0;
    const BOOL kOk = ::ReadFile(file, buffer.data(), maxBytes, &read, nullptr);
    ::CloseHandle(file);
    if (!kOk) {
        return {};
    }
    std::wostringstream dump;
    dump << std::uppercase << std::hex << std::setfill(L'0');
    for (DWORD offset = 0; offset < read; offset += 16) {
        dump << std::setw(8) << offset << L"  ";
        for (DWORD index = 0; index < 16; ++index) {
            if (offset + index < read) {
                dump << std::setw(2) << static_cast<unsigned int>(buffer[offset + index]) << L' ';
            } else {
                dump << L"   ";
            }
        }
        dump << L" ";
        for (DWORD index = 0; index < 16 && offset + index < read; ++index) {
            const BYTE kCh = buffer[offset + index];
            dump << (kCh >= 32 && kCh < 127 ? static_cast<wchar_t>(kCh) : L'.');
        }
        dump << L"\r\n";
    }
    return dump.str();
}

// verifyEmbeddedSignature checks Authenticode trust through WinVerifyTrust.
// Inputs are the selected file path; processing asks the OS trust provider
// without UI; output is a compact status line for the retained signature menu.
std::wstring verifyEmbeddedSignature(const std::wstring& path) {
    if (path.empty()) {
        return L"路径为空，无法检查签名。";
    }

    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = path.c_str();

    WINTRUST_DATA trustData{};
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const LONG kStatus = ::WinVerifyTrust(nullptr, &policy, &trustData);
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    (void)::WinVerifyTrust(nullptr, &policy, &trustData);

    if (kStatus == ERROR_SUCCESS) {
        return L"数字签名验证通过。";
    }
    if (kStatus == TRUST_E_NOSIGNATURE) {
        return L"文件没有嵌入式 Authenticode 签名。";
    }
    if (kStatus == CERT_E_EXPIRED) {
        return L"数字签名证书已过期。";
    }
    if (kStatus == TRUST_E_BAD_DIGEST) {
        return L"数字签名摘要不匹配，文件可能已被修改。";
    }
    return L"数字签名验证失败，状态 0x" + hexText(static_cast<std::uint32_t>(kStatus));
}

// buildPeHeaderSummary preserves Lite's original small PE-header reader. It
// deliberately reads only the DOS/NT/File/Optional header fields, so callers
// can still inspect files which are unsuitable for the bounded deep parser.
std::wstring buildPeHeaderSummary(const std::wstring& path) {
    HANDLE file = ::CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return L"打开文件失败，错误 " + std::to_wstring(::GetLastError());
    }

    IMAGE_DOS_HEADER dos{};
    DWORD read = 0;
    if (!::ReadFile(file, &dos, sizeof(dos), &read, nullptr) ||
        read != sizeof(dos) || dos.e_magic != IMAGE_DOS_SIGNATURE) {
        ::CloseHandle(file);
        return L"不是有效的 PE 文件：DOS 头无效。";
    }
    if (::SetFilePointer(file, dos.e_lfanew, nullptr, FILE_BEGIN) == INVALID_SET_FILE_POINTER &&
        ::GetLastError() != ERROR_SUCCESS) {
        ::CloseHandle(file);
        return L"定位 NT 头失败，错误 " + std::to_wstring(::GetLastError());
    }

    DWORD signature = 0;
    IMAGE_FILE_HEADER fileHeader{};
    if (!::ReadFile(file, &signature, sizeof(signature), &read, nullptr) ||
        read != sizeof(signature) || signature != IMAGE_NT_SIGNATURE ||
        !::ReadFile(file, &fileHeader, sizeof(fileHeader), &read, nullptr) ||
        read != sizeof(fileHeader)) {
        ::CloseHandle(file);
        return L"不是有效的 PE 文件：NT 头无效。";
    }

    WORD optionalMagic = 0;
    if (!::ReadFile(file, &optionalMagic, sizeof(optionalMagic), &read, nullptr) ||
        read != sizeof(optionalMagic)) {
        ::CloseHandle(file);
        return L"读取 OptionalHeader 失败。";
    }
    ::CloseHandle(file);

    std::wostringstream text;
    text << L"PE 头部摘要\r\n\r\n"
         << L"Machine: 0x" << std::hex << std::uppercase << fileHeader.Machine << L"\r\n"
         << L"Sections: " << std::dec << fileHeader.NumberOfSections << L"\r\n"
         << L"TimeDateStamp: 0x" << std::hex << std::uppercase << fileHeader.TimeDateStamp << L"\r\n"
         << L"Characteristics: 0x" << std::hex << std::uppercase << fileHeader.Characteristics << L"\r\n"
         << L"OptionalHeader.Magic: 0x" << std::hex << std::uppercase << optionalMagic
         << (optionalMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ? L" (PE32+)" :
             optionalMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ? L" (PE32)" : L"") << L"\r\n\r\n"
         << L"KswordARKLight 仅显示轻量 PE 摘要；完整属性页已按要求移除。";
    return text.str();
}

constexpr std::uint64_t kLitePeStaticMaxFileBytes = 16ULL * 1024ULL * 1024ULL;
constexpr std::size_t kLitePeStaticMaxSectionRows = 32;
constexpr std::size_t kLitePeStaticMaxImportModuleRows = 64;
constexpr std::size_t kLitePeStaticMaxDisplayChars = 240;

struct PeStaticSummaryResult {
    bool success = false;
    bool partial = true;
    std::wstring text;
};

// isLiteralDosOrUncFilePath gates only the bounded deep parser. Other paths
// retain the original header-only reader through the compatibility fallback.
bool isLiteralDosOrUncFilePath(const std::wstring& path) {
    const auto kIsAsciiLetter = [](const wchar_t value) {
        return (value >= L'A' && value <= L'Z') || (value >= L'a' && value <= L'z');
    };
    if (path.size() >= 3 && kIsAsciiLetter(path[0]) && path[1] == L':' &&
        (path[2] == L'\\' || path[2] == L'/')) {
        return true;
    }

    if (path.size() < 5 || path[0] != L'\\' || path[1] != L'\\' ||
        path[2] == L'?' || path[2] == L'.') {
        return false;
    }

    const std::size_t kServerEnd = path.find_first_of(L"\\/", 2);
    if (kServerEnd == std::wstring::npos || kServerEnd == 2) {
        return false;
    }
    const std::size_t kShareStart = kServerEnd + 1;
    if (kShareStart >= path.size()) {
        return false;
    }
    const std::size_t kShareEnd = path.find_first_of(L"\\/", kShareStart);
    return kShareEnd == std::wstring::npos || kShareEnd > kShareStart;
}

// readLitePeSnapshot obtains one bounded byte snapshot before the shared PE
// parser runs. The explicit 16 MiB ceiling matches Lite's existing entropy
// action and prevents the parser from reopening a larger replacement file.
bool readLitePeSnapshot(
    const std::wstring& path,
    std::vector<std::uint8_t>& bytesOut,
    std::uint64_t& sizeOut,
    std::wstring& errorOut) {
    bytesOut.clear();
    sizeOut = 0;
    errorOut.clear();

    HANDLE file = ::CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        errorOut = L"打开文件失败，错误 " + std::to_wstring(::GetLastError()) + L"。";
        return false;
    }

    LARGE_INTEGER fileSize{};
    if (::GetFileSizeEx(file, &fileSize) == FALSE || fileSize.QuadPart < 0) {
        const DWORD kError = ::GetLastError();
        ::CloseHandle(file);
        errorOut = L"获取文件大小失败，错误 " + std::to_wstring(kError) + L"。";
        return false;
    }
    if (static_cast<std::uint64_t>(fileSize.QuadPart) > kLitePeStaticMaxFileBytes) {
        ::CloseHandle(file);
        errorOut = L"文件大小为 " + std::to_wstring(fileSize.QuadPart) +
            L" bytes，超过 Lite PE 静态摘要的 16 MiB 上限。";
        return false;
    }

    try {
        bytesOut.resize(static_cast<std::size_t>(fileSize.QuadPart));
    } catch (const std::bad_alloc&) {
        ::CloseHandle(file);
        bytesOut.clear();
        errorOut = L"无法为受限 PE 快照分配内存。";
        return false;
    }

    std::size_t totalRead = 0;
    while (totalRead < bytesOut.size()) {
        const std::size_t kRemaining = bytesOut.size() - totalRead;
        const DWORD kRequestSize = static_cast<DWORD>(std::min<std::size_t>(kRemaining, 1024U * 1024U));
        DWORD read = 0;
        if (::ReadFile(file, bytesOut.data() + totalRead, kRequestSize, &read, nullptr) == FALSE) {
            const DWORD kError = ::GetLastError();
            ::CloseHandle(file);
            bytesOut.clear();
            errorOut = L"读取文件失败，错误 " + std::to_wstring(kError) + L"。";
            return false;
        }
        if (read == 0) {
            ::CloseHandle(file);
            bytesOut.clear();
            errorOut = L"文件在读取期间提前结束或发生变化。";
            return false;
        }
        totalRead += read;
    }

    ::CloseHandle(file);
    sizeOut = static_cast<std::uint64_t>(fileSize.QuadPart);
    return true;
}

// singleLinePreview bounds and normalizes untrusted names and diagnostics from
// the file. The result is safe for one MessageBox row rather than a full report.
std::wstring singleLinePreview(std::wstring text, const std::size_t maxChars) {
    for (wchar_t& character : text) {
        if (character == L'\r' || character == L'\n' || character == L'\t' ||
            character < L' ' || character == 0x7F) {
            character = L' ';
        }
    }
    if (text.size() > maxChars) {
        text.resize(maxChars);
        text += L"...";
    }
    return text;
}

// buildPeHeaderFallback keeps the pre-existing PE-header capability whenever
// Lite's bounded deep analysis cannot safely cover the selected file.
PeStaticSummaryResult buildPeHeaderFallback(const std::wstring& path, const std::wstring& reason) {
    PeStaticSummaryResult result;
    result.success = true;
    result.partial = true;
    result.text = L"PE 静态摘要（Partial）\r\n\r\n"
        L"深度解析未完成：" + singleLinePreview(reason, kLitePeStaticMaxDisplayChars) +
        L"\r\n\r\n已保留兼容的轻量 PE 头部摘要：\r\n\r\n" + buildPeHeaderSummary(path);
    return result;
}

std::wstring peMachineText(const std::uint16_t machine) {
    switch (machine) {
    case IMAGE_FILE_MACHINE_I386: return L"x86";
    case IMAGE_FILE_MACHINE_AMD64: return L"x64";
    case IMAGE_FILE_MACHINE_ARM64: return L"ARM64";
    case IMAGE_FILE_MACHINE_ARM: return L"ARM";
    case IMAGE_FILE_MACHINE_ARMNT: return L"ARMNT";
    case IMAGE_FILE_MACHINE_IA64: return L"IA64";
    default: return L"Unknown";
    }
}

std::wstring peSubsystemText(const std::uint16_t subsystem) {
    switch (subsystem) {
    case IMAGE_SUBSYSTEM_NATIVE: return L"Native";
    case IMAGE_SUBSYSTEM_WINDOWS_GUI: return L"Windows GUI";
    case IMAGE_SUBSYSTEM_WINDOWS_CUI: return L"Windows CUI";
    case IMAGE_SUBSYSTEM_POSIX_CUI: return L"POSIX CUI";
    case IMAGE_SUBSYSTEM_EFI_APPLICATION: return L"EFI Application";
    case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER: return L"EFI Boot Service Driver";
    case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER: return L"EFI Runtime Driver";
    case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION: return L"Windows Boot Application";
    default: return L"Unknown";
    }
}

// buildPeStaticSummary presents only fixed-size, user-mode PE evidence. It
// intentionally omits the parser's full report and individual import functions.
PeStaticSummaryResult buildPeStaticSummary(const std::wstring& path) {
    PeStaticSummaryResult result;
    if (!isLiteralDosOrUncFilePath(path)) {
        return buildPeHeaderFallback(
            path,
            L"深度解析仅支持普通 DOS 盘符或 UNC 路径；当前路径继续使用原有轻量读取器。");
    }

    std::vector<std::uint8_t> fileBytes;
    std::uint64_t fileSize = 0;
    std::wstring readError;
    if (!readLitePeSnapshot(path, fileBytes, fileSize, readError)) {
        return buildPeHeaderFallback(path, readError);
    }

    const ks::file::PeAnalysisResult kAnalysis = ks::file::analyzePeBytes(fileBytes);
    if (!kAnalysis.success) {
        const std::wstring kDiagnostic = kAnalysis.reportText.empty()
            ? L"共享 PE 解析器未返回可用结果。"
            : singleLinePreview(kAnalysis.reportText, kLitePeStaticMaxDisplayChars);
        return buildPeHeaderFallback(path, L"深度解析失败：" + kDiagnostic);
    }

    std::wostringstream text;
    text << L"PE 静态摘要（只读）\r\n\r\n"
         << L"路径: " << singleLinePreview(path, 512) << L"\r\n"
         << L"快照大小: " << fileSize << L" bytes（上限 16 MiB）\r\n"
         << L"格式: " << (kAnalysis.isPe64 ? L"PE32+" : L"PE32") << L"\r\n"
         << L"Machine: " << hexText(kAnalysis.machine) << L" (" << peMachineText(kAnalysis.machine) << L")\r\n"
         << L"Subsystem: " << hexText(kAnalysis.subsystem) << L" (" << peSubsystemText(kAnalysis.subsystem) << L")\r\n"
         << L"ImageBase: " << hexText(kAnalysis.imageBase) << L"\r\n"
         << L"EntryPoint RVA: " << hexText(kAnalysis.entryPointRva) << L"\r\n"
         << L"EntryPoint File Offset: "
         << (kAnalysis.entryPointFileOffsetValid ? hexText(kAnalysis.entryPointFileOffset) : L"<unmapped>") << L"\r\n"
         << L"解析到的区段: " << kAnalysis.sections.size() << L"\r\n"
         << L"解析到的导入模块: " << kAnalysis.importModules.size() << L"\r\n";

    const std::size_t kSectionDisplayCount = std::min(kAnalysis.sections.size(), kLitePeStaticMaxSectionRows);
    text << L"\r\n区段（最多显示 " << kLitePeStaticMaxSectionRows << L" 个）\r\n";
    if (kSectionDisplayCount == 0) {
        text << L"<none>\r\n";
    } else {
        for (std::size_t index = 0; index < kSectionDisplayCount; ++index) {
            const ks::file::PeSectionSummary& section = kAnalysis.sections[index];
            text << L"[" << index << L"] "
                 << singleLinePreview(utf8ToWide(section.name), 80)
                 << L" | VA=" << hexText(section.virtualAddress)
                 << L" | VSz=" << hexText(section.virtualSize)
                 << L" | Raw=" << hexText(section.rawOffset) << L"+" << hexText(section.rawSize)
                 << L" | Chars=" << hexText(section.characteristics)
                 << L" | Entropy=" << std::fixed << std::setprecision(2) << section.entropy
                 << L"\r\n";
        }
        if (kAnalysis.sections.size() > kSectionDisplayCount) {
            text << L"...仅显示前 " << kSectionDisplayCount << L" 个区段。\r\n";
        }
    }

    bool partial = false;
    const std::size_t kImportDisplayCount = std::min(kAnalysis.importModules.size(), kLitePeStaticMaxImportModuleRows);
    text << L"\r\n导入模块摘要（最多显示 " << kLitePeStaticMaxImportModuleRows
         << L" 个；不显示导入函数）\r\n";
    if (kImportDisplayCount == 0) {
        text << L"<none>\r\n";
    } else {
        for (std::size_t index = 0; index < kImportDisplayCount; ++index) {
            const ks::file::PeImportModuleSummary& module = kAnalysis.importModules[index];
            std::wstring moduleName = singleLinePreview(utf8ToWide(module.dllName), kLitePeStaticMaxDisplayChars);
            if (moduleName.empty()) {
                moduleName = L"<unnamed module>";
            }
            text << L"[" << module.descriptorIndex << L"] " << moduleName
                 << L" | parsed entries=" << module.imports.size();
            if (!module.diagnosticText.empty()) {
                partial = true;
                text << L" | Partial: "
                     << singleLinePreview(utf8ToWide(module.diagnosticText), kLitePeStaticMaxDisplayChars);
            }
            text << L"\r\n";
        }
        if (kAnalysis.importModules.size() > kImportDisplayCount) {
            text << L"...仅显示前 " << kImportDisplayCount << L" 个导入模块。\r\n";
        }
    }

    result.success = true;
    result.partial = partial;
    result.text = text.str();
    return result;
}

// createEmptyFile creates one new empty text file under the current directory.
// Inputs are a directory path; output is the created full path or empty on
// failure. Existing files are never overwritten.
std::wstring createEmptyFile(const std::wstring& directory) {
    if (directory.empty()) {
        return {};
    }
    for (int index = 1; index < 1000; ++index) {
        const std::wstring kName = index == 1 ? L"新建文件.txt" : L"新建文件 (" + std::to_wstring(index) + L").txt";
        const std::wstring kPath = PathNavigator::joinChildPath(directory, kName);
        HANDLE file = ::CreateFileW(kPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file != INVALID_HANDLE_VALUE) {
            ::CloseHandle(file);
            return kPath;
        }
        if (::GetLastError() != ERROR_FILE_EXISTS && ::GetLastError() != ERROR_ALREADY_EXISTS) {
            return {};
        }
    }
    return {};
}

// createNewDirectory creates a unique `新建文件夹` (new folder) child. Inputs are a directory;
// output is the created path or empty if all attempts fail.
std::wstring createNewDirectory(const std::wstring& directory) {
    if (directory.empty()) {
        return {};
    }
    for (int index = 1; index < 1000; ++index) {
        const std::wstring kName = index == 1 ? L"新建文件夹" : L"新建文件夹 (" + std::to_wstring(index) + L")";
        const std::wstring kPath = PathNavigator::joinChildPath(directory, kName);
        if (::CreateDirectoryW(kPath.c_str(), nullptr)) {
            return kPath;
        }
        if (::GetLastError() != ERROR_ALREADY_EXISTS) {
            return {};
        }
    }
    return {};
}

} // namespace

FileActionId FileActions::showContextMenu(HWND owner, const FileActionContext& context, POINT screenPoint) {
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return FileActionId::kNone;
    }

    // showContextMenu groups the retained FileDock actions so the lightweight
    // Win32 page stays compact. Inputs are the popup owner, current selection
    // state and screen point; processing creates only Win32 HMENU submenus and
    // greys commands that require a selected row; output is the chosen action id.
    const auto kAppendAction = [&](HMENU target, FileActionId id, const wchar_t* text, bool requiresSelection) {
        UINT flags = MF_STRING;
        if (requiresSelection && !context.hasSelection) {
            flags |= MF_GRAYED;
        }
        ::AppendMenuW(target, flags, static_cast<UINT_PTR>(id), text);
    };

    HMENU openMenu = ::CreatePopupMenu();
    if (openMenu) {
        kAppendAction(openMenu, FileActionId::kOpenRun, L"打开/运行", true);
        kAppendAction(openMenu, FileActionId::kOpenLinkTarget, L"打开链接目标", true);
        kAppendAction(openMenu, FileActionId::kLocateLinkTarget, L"定位链接目标", true);
        kAppendAction(openMenu, FileActionId::kOpenTerminal, L"在终端中打开", false);
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(openMenu), L"打开");
    }

    HMENU copyMenu = ::CreatePopupMenu();
    if (copyMenu) {
        kAppendAction(copyMenu, FileActionId::kCopyPath, L"复制路径", true);
        kAppendAction(copyMenu, FileActionId::kCopyKernelModeAddress, L"复制内核模式路径", true);
        kAppendAction(copyMenu, FileActionId::kCopyShortFileName, L"复制短文件名", true);
        kAppendAction(copyMenu, FileActionId::kCopyLinkTarget, L"复制链接目标", true);
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(copyMenu), L"复制");
    }

    HMENU fileMenu = ::CreatePopupMenu();
    if (fileMenu) {
        kAppendAction(fileMenu, FileActionId::kCopyToOppositePanel, L"复制到目标文件夹...", true);
        kAppendAction(fileMenu, FileActionId::kMoveToOppositePanel, L"移动到目标文件夹...", true);
        kAppendAction(fileMenu, FileActionId::kRename, L"重命名(F2)", true);
        kAppendAction(fileMenu, FileActionId::kDeleteItem, L"删除(Delete)", true);
        kAppendAction(fileMenu, FileActionId::kTakeOwnership, L"取得所有权", true);
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(fileMenu), L"文件操作");
    }

    HMENU kernelMenu = ::CreatePopupMenu();
    if (kernelMenu) {
        kAppendAction(kernelMenu, FileActionId::kDriverDelete, L"驱动删除(R0)", true);
        kAppendAction(kernelMenu, FileActionId::kFileUnlocker, L"文件解锁器(R3/R0)", true);
        kAppendAction(kernelMenu, FileActionId::kMappedProcessScan, L"扫描映射进程(R0)", true);
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(kernelMenu), L"R0/占用");
    }

    HMENU newMenu = ::CreatePopupMenu();
    if (newMenu) {
        kAppendAction(newMenu, FileActionId::kNewFile, L"新建文件", false);
        kAppendAction(newMenu, FileActionId::kNewFolder, L"新建文件夹", false);
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(newMenu), L"新建");
    }

    HMENU analysisMenu = ::CreatePopupMenu();
    if (analysisMenu) {
        kAppendAction(analysisMenu, FileActionId::kHash, L"计算哈希值", true);
        kAppendAction(analysisMenu, FileActionId::kSignature, L"检查数字签名", true);
        kAppendAction(analysisMenu, FileActionId::kEntropy, L"计算熵值", true);
        kAppendAction(analysisMenu, FileActionId::kHexView, L"十六进制查看", true);
        kAppendAction(analysisMenu, FileActionId::kPeViewer, L"在 PE 查看器中打开", true);
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(analysisMenu), L"分析");
    }

    HMENU viewMenu = ::CreatePopupMenu();
    if (viewMenu) {
        kAppendAction(viewMenu, FileActionId::kSelectColumns, L"选择列...", false);
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(viewMenu), L"视图");
    }

    const int kChosen = ::TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y, 0, owner, nullptr);
    ::DestroyMenu(menu);
    return static_cast<FileActionId>(kChosen);
}

// prepareBackground keeps modal confirmations and shell dialogs on the window
// thread. All filesystem, security, Restart Manager and driver work remains in
// execute(), which FileView dispatches to its background action task.
FileActionPreparation FileActions::prepareBackground(FileActionId action, FileActionContext& context) {
    FileActionPreparation preparation{};
    const std::wstring kSelected = selectedPath(context);
    switch (action) {
    case FileActionId::kDeleteItem:
        if (!kSelected.empty() &&
            ::MessageBoxW(context.owner, kSelected.c_str(), L"确认删除选中项？", MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2) != IDYES) {
            preparation.ready = false;
            preparation.statusText = L"已取消删除。";
        } else {
            context.confirmed = !kSelected.empty();
        }
        break;
    case FileActionId::kCopyToOppositePanel:
    case FileActionId::kMoveToOppositePanel: {
        if (kSelected.empty()) {
            break;
        }
        const bool kMove = action == FileActionId::kMoveToOppositePanel;
        context.targetDirectory = pickTargetFolder(
            context.owner,
            kMove ? L"选择移动目标文件夹" : L"选择复制目标文件夹");
        if (context.targetDirectory.empty()) {
            preparation.ready = false;
            preparation.statusText = kMove ? L"已取消移动。" : L"已取消复制。";
        }
        break;
    }
    case FileActionId::kRename:
        if (!kSelected.empty()) {
            context.renameTarget = promptRenameTarget(context.owner, kSelected);
            if (context.renameTarget.empty()) {
                preparation.ready = false;
                preparation.statusText = L"已取消重命名。";
            }
        }
        break;
    case FileActionId::kDriverDelete: {
        const std::wstring kNtPath = buildDriverNtPath(kSelected);
        if (!kNtPath.empty() &&
            ::MessageBoxW(context.owner, kNtPath.c_str(), L"确认通过R0驱动删除选中项？", MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2) != IDYES) {
            preparation.ready = false;
            preparation.statusText = L"已取消R0驱动删除。";
        } else {
            context.confirmed = !kNtPath.empty();
        }
        break;
    }
    default:
        break;
    }
    return preparation;
}

FileActionResult FileActions::execute(FileActionId action, const FileActionContext& context) {
    FileActionResult result;
    const std::wstring kSelected = selectedPath(context);
    switch (action) {
    case FileActionId::kOpenRun:
        result.handled = true;
        if (shellOpenPath(context.owner, kSelected)) {
            result.statusText = L"已请求打开：" + kSelected;
        } else {
            result.statusText = L"打开失败：" + kSelected;
        }
        return result;
    case FileActionId::kCopyPath:
        result.handled = true;
        if (context.backgroundExecution) {
            result.clipboardText = kSelected;
            result.statusText = kSelected.empty() ? L"没有可复制的路径。" : L"已获取路径。";
            return result;
        }
        result.statusText = copyTextToClipboard(context.owner, kSelected) ? L"已复制路径。" : L"复制路径失败。";
        return result;
    case FileActionId::kCopyShortFileName: {
        result.handled = true;
        const std::wstring kShortPath = shortPathForFile(kSelected);
        if (context.backgroundExecution) {
            result.clipboardText = kShortPath;
            result.statusText = kShortPath.empty() ? L"短文件名不可用。" : L"已获取短文件名。";
            return result;
        }
        if (!kShortPath.empty() && copyTextToClipboard(context.owner, kShortPath)) {
            result.statusText = L"已复制短文件名。";
        } else {
            result.statusText = L"短文件名不可用或复制失败。";
        }
        return result;
    }
    case FileActionId::kDeleteItem:
        result.handled = true;
        if (kSelected.empty()) {
            result.statusText = L"没有选中文件。";
            return result;
        }
        if (!context.backgroundExecution &&
            ::MessageBoxW(context.owner, kSelected.c_str(), L"确认删除选中项？", MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2) != IDYES) {
            result.statusText = L"已取消删除。";
            return result;
        }
        if (context.backgroundExecution && !context.confirmed) {
            result.statusText = L"删除未获得用户确认。";
            return result;
        }
        if (context.selectedEntry.kind == FileEntryKind::kDirectory) {
            if (::RemoveDirectoryW(kSelected.c_str())) {
                result.refreshRequested = true;
                result.statusText = L"目录已删除。";
            } else {
                result.statusText = L"目录删除失败，错误 " + std::to_wstring(::GetLastError());
            }
        } else if (::DeleteFileW(kSelected.c_str())) {
            result.refreshRequested = true;
            result.statusText = L"文件已删除。";
        } else {
            result.statusText = L"文件删除失败，错误 " + std::to_wstring(::GetLastError());
        }
        return result;
    case FileActionId::kNewFile: {
        result.handled = true;
        const std::wstring kPath = createEmptyFile(context.currentDirectory);
        result.refreshRequested = !kPath.empty();
        result.statusText = kPath.empty() ? L"新建文件失败。" : L"已新建文件：" + kPath;
        return result;
    }
    case FileActionId::kNewFolder: {
        result.handled = true;
        const std::wstring kPath = createNewDirectory(context.currentDirectory);
        result.refreshRequested = !kPath.empty();
        result.statusText = kPath.empty() ? L"新建文件夹失败。" : L"已新建文件夹：" + kPath;
        return result;
    }
    case FileActionId::kOpenTerminal:
        result.handled = true;
        result.statusText = openTerminalAtDirectory(context.owner, context.currentDirectory) ? L"已请求打开终端。" : L"打开终端失败。";
        return result;
    case FileActionId::kCopyKernelModeAddress:
        result.handled = true;
        if (context.backgroundExecution) {
            result.clipboardText = buildDriverNtPath(kSelected);
            result.statusText = result.clipboardText.empty() ? L"内核模式路径不可用。" : L"已获取内核模式路径。";
            return result;
        }
        result.statusText = copyTextToClipboard(context.owner, buildDriverNtPath(kSelected)) ? L"已复制内核模式路径。" : L"复制内核模式路径失败。";
        return result;
    case FileActionId::kCopyLinkTarget: {
        result.handled = true;
        const std::wstring kTarget = resolveLinkTarget(kSelected);
        if (context.backgroundExecution) {
            result.clipboardText = kTarget;
            result.statusText = kTarget.empty() ? L"链接目标不可用。" : L"已获取链接目标。";
            return result;
        }
        result.statusText = !kTarget.empty() && copyTextToClipboard(context.owner, kTarget) ? L"已复制链接目标。" : L"链接目标不可用或复制失败。";
        return result;
    }
    case FileActionId::kOpenLinkTarget: {
        result.handled = true;
        const std::wstring kTarget = resolveLinkTarget(kSelected);
        result.statusText = !kTarget.empty() && shellOpenPath(context.owner, kTarget) ? L"已打开链接目标。" : L"打开链接目标失败。";
        return result;
    }
    case FileActionId::kLocateLinkTarget: {
        result.handled = true;
        const std::wstring kTarget = resolveLinkTarget(kSelected);
        if (kTarget.empty()) {
            result.statusText = L"链接目标不可用。";
            return result;
        }
        const std::wstring kArgs = L"/select,\"" + kTarget + L"\"";
        const HINSTANCE kRc = ::ShellExecuteW(context.owner, L"open", L"explorer.exe", kArgs.c_str(), nullptr, SW_SHOWNORMAL);
        result.statusText = reinterpret_cast<INT_PTR>(kRc) > 32 ? L"已定位链接目标。" : L"定位链接目标失败。";
        return result;
    }
    case FileActionId::kCopyToOppositePanel:
    case FileActionId::kMoveToOppositePanel: {
        result.handled = true;
        if (kSelected.empty()) {
            result.statusText = L"没有选中文件或目录。";
            return result;
        }
        const bool kMove = action == FileActionId::kMoveToOppositePanel;
        const std::wstring kTargetFolder = context.backgroundExecution
            ? context.targetDirectory
            : pickTargetFolder(context.owner, kMove ? L"选择移动目标文件夹" : L"选择复制目标文件夹");
        if (kTargetFolder.empty()) {
            result.statusText = kMove ? L"已取消移动。" : L"已取消复制。";
            return result;
        }
        std::wstring status;
        const bool kOk = copyOrMovePathToFolder(kSelected, kTargetFolder, kMove, status);
        result.refreshRequested = kOk && kMove;
        result.statusText = status;
        return result;
    }
    case FileActionId::kRename: {
        result.handled = true;
        const std::wstring kTarget = context.backgroundExecution
            ? context.renameTarget
            : promptRenameTarget(context.owner, kSelected);
        if (kTarget.empty()) {
            result.statusText = L"已取消重命名。";
            return result;
        }
        if (::MoveFileExW(kSelected.c_str(), kTarget.c_str(), MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING)) {
            result.refreshRequested = true;
            result.statusText = L"已重命名为：" + kTarget;
        } else {
            result.statusText = L"重命名失败，错误 " + std::to_wstring(::GetLastError());
        }
        return result;
    }
    case FileActionId::kDriverDelete: {
        result.handled = true;
        if (kSelected.empty()) {
            result.statusText = L"没有选中文件。";
            return result;
        }
        const std::wstring kNtPath = buildDriverNtPath(kSelected);
        if (kNtPath.empty()) {
            result.statusText = L"驱动删除失败：NT路径转换为空。";
            return result;
        }
        if (!context.backgroundExecution &&
            ::MessageBoxW(context.owner, kNtPath.c_str(), L"确认通过R0驱动删除选中项？", MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2) != IDYES) {
            result.statusText = L"已取消R0驱动删除。";
            return result;
        }
        if (context.backgroundExecution && !context.confirmed) {
            result.statusText = L"R0 驱动删除未获得用户确认。";
            return result;
        }
        const bool kIsDirectory = context.selectedEntry.kind == FileEntryKind::kDirectory;
        const ksword::ark::DriverClient kDriverClient;
        const ksword::ark::IoResult kIo = kDriverClient.deletePath(kNtPath, kIsDirectory);
        result.refreshRequested = kIo.ok;
        result.statusText = std::wstring(L"驱动删除(R0)") + (kIo.ok ? L"成功：" : L"失败：") + kNtPath + L" | " + utf8ToWide(kIo.message);
        return result;
    }
    case FileActionId::kFileUnlocker:
        result.handled = true;
        result.dialogText = queryFileLockers(kSelected);
        result.dialogTitle = L"文件解锁器(R3/R0)";
        result.dialogFlags = MB_ICONINFORMATION;
        result.statusText = L"已完成文件占用扫描。";
        if (!context.backgroundExecution) {
            ::MessageBoxW(context.owner, result.dialogText.c_str(), result.dialogTitle.c_str(), MB_OK | result.dialogFlags);
        }
        return result;
    case FileActionId::kTakeOwnership:
        result.handled = true;
        result.statusText = takeOwnershipPath(kSelected);
        return result;
    case FileActionId::kSelectColumns:
        result.handled = true;
        result.statusText = L"已打开列选择菜单。";
        return result;
    case FileActionId::kHash: {
        result.handled = true;
        if (context.selectedEntry.kind != FileEntryKind::kFile) {
            result.statusText = L"计算哈希值只支持文件。";
            return result;
        }
        std::wstring error;
        const std::wstring kHash = computeSha256(kSelected, &error);
        result.statusText = kHash.empty() ? L"SHA-256 计算失败：" + error : L"SHA-256: " + kHash;
        if (!kHash.empty()) {
            result.clipboardText = kHash;
            result.dialogTitle = L"文件哈希";
            result.dialogText = result.statusText;
            result.dialogFlags = MB_ICONINFORMATION;
            if (!context.backgroundExecution) {
                copyTextToClipboard(context.owner, kHash);
                ::MessageBoxW(context.owner, result.dialogText.c_str(), result.dialogTitle.c_str(), MB_OK | result.dialogFlags);
            }
        }
        return result;
    }
    case FileActionId::kSignature:
        result.handled = true;
        if (context.selectedEntry.kind != FileEntryKind::kFile) {
            result.statusText = L"检查数字签名只支持文件。";
            return result;
        }
        result.statusText = verifyEmbeddedSignature(kSelected);
        result.dialogTitle = L"数字签名";
        result.dialogText = result.statusText;
        result.dialogFlags = MB_ICONINFORMATION;
        if (!context.backgroundExecution) {
            ::MessageBoxW(context.owner, result.dialogText.c_str(), result.dialogTitle.c_str(), MB_OK | result.dialogFlags);
        }
        return result;
    case FileActionId::kEntropy: {
        result.handled = true;
        if (context.selectedEntry.kind != FileEntryKind::kFile) {
            result.statusText = L"计算熵值只支持文件。";
            return result;
        }
        std::uint64_t sampled = 0;
        const double kEntropy = computeFileEntropy(kSelected, 16ull * 1024ull * 1024ull, &sampled);
        if (kEntropy < 0.0) {
            result.statusText = L"计算熵值失败，错误 " + std::to_wstring(::GetLastError());
        } else {
            wchar_t buffer[160]{};
            ::swprintf_s(buffer, L"Entropy: %.4f bits/byte, sampled=%llu bytes", kEntropy, static_cast<unsigned long long>(sampled));
            result.statusText = buffer;
            result.dialogTitle = L"文件熵值";
            result.dialogText = result.statusText;
            result.dialogFlags = MB_ICONINFORMATION;
            if (!context.backgroundExecution) {
                ::MessageBoxW(context.owner, result.dialogText.c_str(), result.dialogTitle.c_str(), MB_OK | result.dialogFlags);
            }
        }
        return result;
    }
    case FileActionId::kHexView: {
        result.handled = true;
        if (context.selectedEntry.kind != FileEntryKind::kFile) {
            result.statusText = L"十六进制查看只支持文件。";
            return result;
        }
        const std::wstring kPreview = hexPreview(kSelected, 512);
        if (kPreview.empty()) {
            result.statusText = L"读取十六进制预览失败，错误 " + std::to_wstring(::GetLastError());
            return result;
        }
        result.dialogTitle = L"十六进制预览（前 512 字节）";
        result.dialogText = kPreview;
        result.dialogFlags = MB_ICONINFORMATION;
        if (!context.backgroundExecution) {
            ::MessageBoxW(context.owner, result.dialogText.c_str(), result.dialogTitle.c_str(), MB_OK | result.dialogFlags);
        }
        result.statusText = L"已显示十六进制预览。";
        return result;
    }
    case FileActionId::kPeViewer:
        result.handled = true;
        if (context.selectedEntry.kind != FileEntryKind::kFile) {
            result.statusText = L"PE 查看只支持文件。";
            return result;
        }
        {
            const PeStaticSummaryResult kSummary = buildPeStaticSummary(kSelected);
            result.statusText = kSummary.success
                ? (kSummary.partial ? L"PE 静态摘要已生成（Partial）。" : L"已生成受限 PE 静态摘要。")
                : L"PE 静态摘要不可用（Partial）。";
            result.dialogTitle = L"PE 静态摘要（只读）";
            result.dialogText = kSummary.text;
            result.dialogFlags = kSummary.partial ? MB_ICONWARNING : MB_ICONINFORMATION;
        }
        if (!context.backgroundExecution) {
            ::MessageBoxW(context.owner, result.dialogText.c_str(), result.dialogTitle.c_str(), MB_OK | result.dialogFlags);
        }
        return result;
    case FileActionId::kMappedProcessScan: {
        result.handled = true;
        if (kSelected.empty()) {
            result.statusText = L"没有选中文件。";
            return result;
        }
        if (context.selectedEntry.kind != FileEntryKind::kFile) {
            result.statusText = L"扫描映射进程(R0)只支持文件。";
            return result;
        }
        const std::wstring kNtPath = buildDriverNtPath(kSelected);
        if (kNtPath.empty()) {
            result.statusText = L"扫描映射进程失败：NT路径转换为空。";
            return result;
        }
        const ksword::ark::DriverClient kDriverClient;
        const ksword::ark::FileSectionMappingsQueryResult kQuery = kDriverClient.queryFileSectionMappings(
            kNtPath,
            KSWORD_ARK_FILE_SECTION_QUERY_FLAG_INCLUDE_ALL,
            KSWORD_ARK_SECTION_MAPPING_LIMIT_DEFAULT);
        std::wostringstream summary;
        summary << L"扫描映射进程(R0): " << (kQuery.io.ok ? L"IO OK" : L"IO FAIL")
                << L" | 状态=" << fileSectionStatusText(kQuery.queryStatus)
                << L" | total=" << kQuery.totalCount
                << L" | returned=" << kQuery.returnedCount
                << L" | dataCA=" << hexText(kQuery.dataControlAreaAddress)
                << L" | imageCA=" << hexText(kQuery.imageControlAreaAddress)
                << L" | " << utf8ToWide(kQuery.io.message);
        if (!kQuery.mappings.empty()) {
            summary << L"\r\n";
            const std::size_t kLimit = kQuery.mappings.size() < 24 ? kQuery.mappings.size() : 24;
            for (std::size_t i = 0; i < kLimit; ++i) {
                const ksword::ark::FileSectionMappingEntry& row = kQuery.mappings[i];
                summary << L"#" << (i + 1)
                        << L" PID=" << row.processId
                        << L" Section=" << sectionKindText(row.sectionKind)
                        << L" Map=" << viewMapTypeText(row.viewMapType)
                        << L" VA=" << hexText(row.startVa) << L"-" << hexText(row.endVa)
                        << L" CA=" << hexText(row.controlAreaAddress)
                        << L"\r\n";
            }
            if (kQuery.mappings.size() > kLimit) {
                summary << L"... remaining " << (kQuery.mappings.size() - kLimit) << L" rows omitted from status text.";
            }
        }
        result.statusText = summary.str();
        result.dialogTitle = L"文件映射进程(R0)";
        result.dialogText = result.statusText;
        result.dialogFlags = kQuery.io.ok ? MB_ICONINFORMATION : MB_ICONWARNING;
        if (!context.backgroundExecution && context.owner) {
            ::MessageBoxW(context.owner, result.dialogText.c_str(), result.dialogTitle.c_str(), MB_OK | result.dialogFlags);
        }
        return result;
    }
    default:
        break;
    }
    result.statusText = L"未选择动作。";
    return result;
}

bool FileActions::copyTextToClipboard(HWND owner, const std::wstring& text) {
    if (!::OpenClipboard(owner)) {
        return false;
    }
    ::EmptyClipboard();
    const SIZE_T kBytes = (text.size() + 1) * sizeof(wchar_t);
    HGLOBAL memory = ::GlobalAlloc(GMEM_MOVEABLE, kBytes);
    if (!memory) {
        ::CloseClipboard();
        return false;
    }
    void* target = ::GlobalLock(memory);
    if (!target) {
        ::GlobalFree(memory);
        ::CloseClipboard();
        return false;
    }
    std::memcpy(target, text.c_str(), kBytes);
    ::GlobalUnlock(memory);
    if (!::SetClipboardData(CF_UNICODETEXT, memory)) {
        ::GlobalFree(memory);
        ::CloseClipboard();
        return false;
    }
    ::CloseClipboard();
    return true;
}

} // namespace Ksword::Features::File
