#pragma execution_character_set("utf-8")

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <ShlObj.h>
#include <ShObjIdl.h>
#include <Shellapi.h>
#include <Objbase.h>

#include "gui/KswordStyle.h"
#include "resource.h"
#include "PayloadResources.h"

#include "Fl.H"
#include "Fl_Window.H"

#include <algorithm>
#include <cstdint>
#include <exception>
#include <fstream>
#include <iomanip>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Ole32.lib")

extern HWND flWin32Xid(const Fl_Window* window);

#ifndef KSWORD_SETUP_ENABLE_TOPMOST
#define KSWORD_SETUP_ENABLE_TOPMOST 0
#endif

namespace {
constexpr int kWindowWidth = 600;
constexpr int kWindowHeight = 504;
constexpr int kLayeredImageWidth = 405;
// kImageOverlap controls how much of the character PNG covers the installer
// panel. 243 is about 60% of the 405px character width; tweak this one value
// when fine-adjusting the horizontal overlap.
constexpr int kImageOverlap = 223;
constexpr int kImageDrawHeight = 720;
constexpr int kImageVerticalOffset = (kImageDrawHeight - kWindowHeight) / 2;
constexpr int kPad = 24;
constexpr wchar_t kDefaultInstallLeaf[] = L"KswordARK";
constexpr wchar_t kStateArg[] = L"--install-state";
constexpr wchar_t kSettingsRel[] = L"Style\\appearance_settings.json";
constexpr wchar_t kMainExe[] = L"Ksword5.1.exe";
constexpr wchar_t kLauncherExe[] = L"Launcher.exe";
constexpr wchar_t kTaskmgrScript[] = L"TaskmgrHijack.ps1";

// appendPath joins two path fragments without depending on later helpers. Inputs
// are a parent directory and child name; processing inserts one slash when
// needed; output is a Windows path string.
std::wstring appendPath(const std::wstring& dir, const wchar_t* child) {
    if (dir.empty()) return child ? std::wstring(child) : std::wstring();
    if (!child || !*child) return dir;
    if (dir.back() == L'\\' || dir.back() == L'/') return dir + child;
    return dir + L"\\" + child;
}

// defaultInstallDir resolves the per-user installation root. Input is none;
// processing prefers %LOCALAPPDATA%\Programs and falls back to %LOCALAPPDATA%;
// output is a writable current-user path that normally does not need UAC.
std::wstring defaultInstallDir() {
    PWSTR raw = nullptr;
    HRESULT hr = ::SHGetKnownFolderPath(FOLDERID_UserProgramFiles, KF_FLAG_CREATE, nullptr, &raw);
    if (FAILED(hr) || !raw) {
        hr = ::SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_CREATE, nullptr, &raw);
    }
    if (SUCCEEDED(hr) && raw) {
        std::wstring dir(raw);
        ::CoTaskMemFree(raw);
        return appendPath(dir, kDefaultInstallLeaf);
    }

    wchar_t localAppData[MAX_PATH]{};
    DWORD n = ::GetEnvironmentVariableW(L"LOCALAPPDATA", localAppData, MAX_PATH);
    if (n > 0 && n < MAX_PATH) {
        return appendPath(appendPath(localAppData, L"Programs"), kDefaultInstallLeaf);
    }
    return appendPath(L".", kDefaultInstallLeaf);
}

// InstallOptions is the installer input model. Values come from FLTK widgets or
// the elevation handoff JSON file; performInstall consumes them and returns no
// mutations through this struct after installation starts.
struct InstallOptions {
    std::wstring installDir = defaultInstallDir();
    bool startupAdmin = true;
    bool startupMaximized = true;
    bool replaceTaskmgr = false;
    bool testMode = false;
    bool desktopShortcut = true;
    bool startMenuShortcut = true;
    bool launchAfterInstall = true;
};

// InstallResult is the user-visible outcome. Each installation phase appends a
// line to logText, and the final page displays this text in the status control.
struct InstallResult {
    bool ok = true;
    bool rebootNow = false;
    std::wstring logText;
};

// PageLayout groups the right-side safe content rectangle. The left gutter is
// intentionally blank because the character art overlaps that part of the card.
struct PageLayout {
    int cardX = 0;
    int cardY = 0;
    int cardW = 0;
    int cardH = 0;
    int contentX = 0;
    int contentW = 0;
};

KLayeredImageWindow gCharacterWindow;
KInput* gPathInput = nullptr;
KCheckBox* gAdminCheck = nullptr;
KCheckBox* gMaxCheck = nullptr;
KCheckBox* gTaskmgrCheck = nullptr;
KCheckBox* gTestModeCheck = nullptr;
KCheckBox* gDesktopCheck = nullptr;
KCheckBox* gStartMenuCheck = nullptr;
KCheckBox* gLaunchCheck = nullptr;
KTextDisplay* gStatus = nullptr;
KButton* gInstallButton = nullptr;
KButton* gBrowseButton = nullptr;
KCard* gSetupPage = nullptr;
KCard* gInstallPage = nullptr;
Fl_Window* gMainWindow = nullptr;
bool gTopMostPaused = false;
std::wstring gCharacterImagePath;

// buildPageLayout computes the reusable installer card geometry. Input is none;
// processing reserves a 30% left gutter for the overlaid character; output is
// the card and safe content rectangle used by every page.
PageLayout buildPageLayout() {
    PageLayout layout;
    layout.cardX = kPad;
    layout.cardY = 20;
    layout.cardW = kWindowWidth - kPad * 2;
    layout.cardH = kWindowHeight - 40;
    const int kGutterW = layout.cardW * 30 / 100;
    layout.contentX = layout.cardX + kGutterW + 18;
    layout.contentW = layout.cardW - kGutterW - 42;
    return layout;
}

void applyInstallerZOrder(Fl_Window* owner);
void setInstallerShellDialogMode(bool enabled);
int topMostMessageBox(const wchar_t* text, const wchar_t* caption, UINT type);
void ensureTaskbarAppWindow(Fl_Window* window);

// wideToUtf8 converts UTF-16 Win32 text to UTF-8 for FLTK widgets. Input is a
// UTF-16 string, processing uses WideCharToMultiByte, and output is UTF-8 bytes.
std::string wideToUtf8(const std::wstring& text) {
    if (text.empty()) return {};
    const int kN = ::WideCharToMultiByte(CP_UTF8, 0, text.c_str(), (int)text.size(), nullptr, 0, nullptr, nullptr);
    if (kN <= 0) return {};
    std::string out((size_t)kN, '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, text.c_str(), (int)text.size(), &out[0], kN, nullptr, nullptr);
    return out;
}

// utf8ToWide converts FLTK UTF-8 text to UTF-16 for Win32 APIs. Input is UTF-8
// bytes, processing uses MultiByteToWideChar, and output is UTF-16 text.
std::wstring utf8ToWide(const std::string& text) {
    if (text.empty()) return {};
    const int kN = ::MultiByteToWideChar(CP_UTF8, 0, text.c_str(), (int)text.size(), nullptr, 0);
    if (kN <= 0) return {};
    std::wstring out((size_t)kN, L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, text.c_str(), (int)text.size(), &out[0], kN);
    return out;
}

// Trim removes surrounding whitespace from user-entered paths. Input is a string,
// processing scans both ends, and output is the cleaned string.
std::wstring trim(const std::wstring& text) {
    const wchar_t* ws = L" \t\r\n";
    const size_t kFirst = text.find_first_not_of(ws);
    if (kFirst == std::wstring::npos) return {};
    const size_t kLast = text.find_last_not_of(ws);
    return text.substr(kFirst, kLast - kFirst + 1);
}

// Join combines a directory and child path. Inputs are two path fragments,
// processing inserts one separator when needed, and output is a Windows path.
std::wstring join(const std::wstring& dir, const std::wstring& child) {
    if (dir.empty()) return child;
    if (child.empty()) return dir;
    if (dir.back() == L'\\' || dir.back() == L'/') return dir + child;
    return dir + L"\\" + child;
}

// Parent returns the directory portion of a file path. Input is a path string,
// processing finds the final separator, and output is empty on failure.
std::wstring parent(const std::wstring& path) {
    const size_t kPos = path.find_last_of(L"\\/");
    return kPos == std::wstring::npos ? std::wstring() : path.substr(0, kPos);
}

// existsFile reports whether a non-directory path exists. Input is a candidate
// path, processing queries Win32 attributes, and output is a boolean result.
bool existsFile(const std::wstring& path) {
    const DWORD kAttr = ::GetFileAttributesW(path.c_str());
    return kAttr != INVALID_FILE_ATTRIBUTES && (kAttr & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

// ensureDir creates a directory tree. Input is a directory path, processing uses
// SHCreateDirectoryExW for recursive creation, and output is true on success.
bool ensureDir(const std::wstring& dir) {
    if (dir.empty()) return false;
    const int kRc = ::SHCreateDirectoryExW(nullptr, dir.c_str(), nullptr);
    return kRc == ERROR_SUCCESS || kRc == ERROR_ALREADY_EXISTS || kRc == ERROR_FILE_EXISTS;
}

// jsonEscape encodes a wide string as a JSON string body. Input is raw text;
// processing escapes backslash, quote, and control characters; output is JSON-safe.
std::wstring jsonEscape(const std::wstring& text) {
    std::wstring out;
    out.reserve(text.size() + 8);
    for (wchar_t ch : text) {
        switch (ch) {
        case L'\\': out += L"\\\\"; break;
        case L'"': out += L"\\\""; break;
        case L'\b': out += L"\\b"; break;
        case L'\f': out += L"\\f"; break;
        case L'\n': out += L"\\n"; break;
        case L'\r': out += L"\\r"; break;
        case L'\t': out += L"\\t"; break;
        default:
            if (ch < 0x20) {
                wchar_t buf[7]{};
                swprintf_s(buf, L"\\u%04X", (unsigned int)ch);
                out += buf;
            } else {
                out += ch;
            }
            break;
        }
    }
    return out;
}

// jsonUnescape decodes a JSON string body. Input is an escaped UTF-8 token
// without surrounding quotes; processing handles common escape sequences and
// converts the resulting UTF-8 bytes; output is wide text for the state file.
std::wstring jsonUnescape(const std::string& text) {
    std::string out;
    out.reserve(text.size());
    for (size_t i = 0; i < text.size(); ++i) {
        char ch = text[i];
        if (ch != '\\' || i + 1 >= text.size()) {
            out.push_back(ch);
            continue;
        }
        char next = text[++i];
        switch (next) {
        case '\\': out.push_back('\\'); break;
        case '"': out.push_back('"'); break;
        case '/': out.push_back('/'); break;
        case 'b': out.push_back('\b'); break;
        case 'f': out.push_back('\f'); break;
        case 'n': out.push_back('\n'); break;
        case 'r': out.push_back('\r'); break;
        case 't': out.push_back('\t'); break;
        case 'u':
            if (i + 4 < text.size()) {
                unsigned int value = 0;
                for (int k = 0; k < 4; ++k) {
                    char hex = text[i + 1 + (size_t)k];
                    value <<= 4;
                    if (hex >= '0' && hex <= '9') value |= (unsigned int)(hex - '0');
                    else if (hex >= 'A' && hex <= 'F') value |= 10u + (unsigned int)(hex - 'A');
                    else if (hex >= 'a' && hex <= 'f') value |= 10u + (unsigned int)(hex - 'a');
                }
                if (value < 0x80) {
                    out.push_back((char)value);
                } else if (value < 0x800) {
                    out.push_back((char)(0xC0 | (value >> 6)));
                    out.push_back((char)(0x80 | (value & 0x3F)));
                } else {
                    out.push_back((char)(0xE0 | (value >> 12)));
                    out.push_back((char)(0x80 | ((value >> 6) & 0x3F)));
                    out.push_back((char)(0x80 | (value & 0x3F)));
                }
                i += 4;
            }
            break;
        default:
            out.push_back(next);
            break;
        }
    }
    return utf8ToWide(out);
}

// jsonFindString returns a string value from a small JSON object. Inputs are the
// raw UTF-8 JSON text, the member name, and a default wide string; output is the
// found string or the default when the key is absent.
std::wstring jsonFindString(const std::string& json, const char* key, const std::wstring& defValue) {
    const std::string kNeedle = std::string("\"") + key + "\"";
    size_t keyPos = json.find(kNeedle);
    if (keyPos == std::string::npos) return defValue;
    size_t colon = json.find(':', keyPos + kNeedle.size());
    if (colon == std::string::npos) return defValue;
    size_t start = json.find('"', colon + 1);
    if (start == std::string::npos) return defValue;
    ++start;
    std::string raw;
    raw.reserve(64);
    bool escaped = false;
    for (size_t i = start; i < json.size(); ++i) {
        char ch = json[i];
        if (!escaped && ch == '"') return jsonUnescape(raw);
        if (!escaped && ch == '\\') {
            escaped = true;
            raw.push_back(ch);
            continue;
        }
        escaped = false;
        raw.push_back(ch);
    }
    return defValue;
}

// jsonFindBool returns a boolean member from a small JSON object. Inputs are the
// raw UTF-8 JSON text, the member name, and a default value; output is a parsed
// flag or the default when parsing fails.
bool jsonFindBool(const std::string& json, const char* key, bool defValue) {
    const std::string kNeedle = std::string("\"") + key + "\"";
    size_t keyPos = json.find(kNeedle);
    if (keyPos == std::string::npos) return defValue;
    size_t colon = json.find(':', keyPos + kNeedle.size());
    if (colon == std::string::npos) return defValue;
    size_t start = json.find_first_not_of(" \t\r\n", colon + 1);
    if (start == std::string::npos) return defValue;
    if (json.compare(start, 4, "true") == 0) return true;
    if (json.compare(start, 5, "false") == 0) return false;
    return defValue;
}

// needsElevation evaluates whether the requested options touch privileged
// locations. Input is install options; output is true when UAC should be used.
bool needsElevation(const InstallOptions& o) {
    return o.replaceTaskmgr || o.testMode;
}

// fileExistsInDir reports whether a file exists under the install root. Input is
// root and relative path; output is a boolean used to detect update installs.
bool fileExistsInDir(const std::wstring& dir, const std::wstring& rel) {
    return existsFile(join(dir, rel));
}

// appendLog appends one line to the result log and refreshes the status widget.
// Input is mutable log text and one line; processing appends CRLF; no return.
void appendLog(std::wstring* log, const std::wstring& line) {
    if (!log) return;
    *log += line;
    *log += L"\r\n";
    if (gStatus) {
        const std::string kUtf8 = wideToUtf8(*log);
        gStatus->setText(kUtf8.c_str());
        Fl::check();
    }
}

// setStatus replaces status text directly. Input is UTF-16 text; processing
// converts to UTF-8; no value is returned.
void setStatus(const std::wstring& text) {
    if (!gStatus) return;
    const std::string kUtf8 = wideToUtf8(text);
    gStatus->setText(kUtf8.c_str());
    Fl::check();
}

// writeBytes creates or overwrites a file with binary data. Inputs are file path,
// byte pointer and size; processing creates the parent directory; output is true
// when all bytes are written.
bool writeBytes(const std::wstring& path, const void* data, DWORD size) {
    const std::wstring kParent = parent(path);
    if (!kParent.empty() && !ensureDir(kParent)) return false;
    HANDLE h = ::CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    const BOOL kOk = ::WriteFile(h, data, size, &written, nullptr);
    ::CloseHandle(h);
    return kOk && written == size;
}

// readBytes loads a file into memory through Win32 wide-path APIs. Input is a
// file path; processing reads the complete stream; output is true on success.
bool readBytes(const std::wstring& path, std::vector<char>* data) {
    if (!data) return false;
    data->clear();
    HANDLE h = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size{};
    if (!::GetFileSizeEx(h, &size) || size.QuadPart < 0 || size.QuadPart > 1024 * 1024) {
        ::CloseHandle(h);
        return false;
    }
    data->resize((size_t)size.QuadPart);
    DWORD read = 0;
    const BOOL kOk = data->empty() || ::ReadFile(h, data->data(), (DWORD)data->size(), &read, nullptr);
    ::CloseHandle(h);
    return kOk && read == data->size();
}

// extractRc writes an embedded RCDATA resource to disk. Inputs are resource id
// and output path; processing locates and locks the resource; output is true when
// extraction succeeds.
bool extractRc(unsigned int id, const std::wstring& path) {
    HRSRC res = ::FindResourceW(nullptr, MAKEINTRESOURCEW(id), RT_RCDATA);
    if (!res) return false;
    HGLOBAL loaded = ::LoadResource(nullptr, res);
    const void* bytes = loaded ? ::LockResource(loaded) : nullptr;
    const DWORD kSize = ::SizeofResource(nullptr, res);
    return bytes && kSize > 0 && writeBytes(path, bytes, kSize);
}

// ExePath returns the current installer executable path. Input is none;
// processing expands a stack buffer through GetModuleFileNameW; output is empty
// on failure.
std::wstring exePath() {
    std::vector<wchar_t> buf(1024, L'\0');
    while (buf.size() < 32768) {
        DWORD n = ::GetModuleFileNameW(nullptr, buf.data(), (DWORD)buf.size());
        if (n == 0) return {};
        if (n < buf.size()) return {buf.data(), n};
        buf.resize(buf.size() * 2, L'\0');
    }
    return {};
}

// isElevated checks the current token elevation state. Input is current process;
// processing queries TokenElevation; output is true for administrator elevation.
bool isElevated() {
    HANDLE token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION elevation{};
    DWORD len = 0;
    BOOL ok = ::GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &len);
    ::CloseHandle(token);
    return ok && elevation.TokenIsElevated;
}

// Quote returns a quoted command-line argument. Input is raw text, processing
// escapes double quotes, and output is suitable for ShellExecute/CreateProcess.
std::wstring quote(const std::wstring& arg) {
    std::wstring out = L"\"";
    for (wchar_t ch : arg) out += (ch == L'\"') ? L"\\\"" : std::wstring(1, ch);
    out += L"\"";
    return out;
}

// systemExePath resolves a system executable inside the Windows directory.
// Input is a relative path under System32; output is an absolute path used to
// avoid CreateProcess search-path ambiguity and WOW64 surprises.
std::wstring systemExePath(const wchar_t* relativePath) {
    wchar_t sysDir[MAX_PATH]{};
    if (!::GetSystemDirectoryW(sysDir, MAX_PATH)) {
        return relativePath ? std::wstring(relativePath) : std::wstring();
    }
    return join(sysDir, relativePath ? std::wstring(relativePath) : std::wstring());
}

// tempStatePath allocates an elevation handoff file path. Input is none;
// processing uses GetTempPath/GetTempFileName; output is a temporary path.
std::wstring tempStatePath() {
    wchar_t dir[MAX_PATH]{};
    wchar_t file[MAX_PATH]{};
    if (!::GetTempPathW(MAX_PATH, dir) || !::GetTempFileNameW(dir, L"ksw", 0, file)) return L"KswordSetup.state";
    return file;
}

// saveState writes install options to a JSON file. Inputs are path and options;
// processing stores UTF-8 state used by the elevated continuation; output is
// true when the handoff file is written.
bool saveState(const std::wstring& file, const InstallOptions& o) {
    std::wostringstream json;
    json << L"{\n"
         << L"  \"installDir\": \"" << jsonEscape(o.installDir) << L"\",\n"
         << L"  \"startupAdmin\": " << (o.startupAdmin ? L"true" : L"false") << L",\n"
         << L"  \"startupMaximized\": " << (o.startupMaximized ? L"true" : L"false") << L",\n"
         << L"  \"replaceTaskmgr\": " << (o.replaceTaskmgr ? L"true" : L"false") << L",\n"
         << L"  \"testMode\": " << (o.testMode ? L"true" : L"false") << L",\n"
         << L"  \"desktopShortcut\": " << (o.desktopShortcut ? L"true" : L"false") << L",\n"
         << L"  \"startMenuShortcut\": " << (o.startMenuShortcut ? L"true" : L"false") << L",\n"
         << L"  \"launchAfterInstall\": " << (o.launchAfterInstall ? L"true" : L"false") << L"\n"
         << L"}\n";
    const std::string kUtf8 = wideToUtf8(json.str());
    return writeBytes(file, kUtf8.data(), (DWORD)kUtf8.size());
}

// loadState reads install options from a JSON handoff file. Input is path;
// processing reads expected fields with defaults; output is reconstructed
// options for the elevated installer instance.
InstallOptions loadState(const std::wstring& file) {
    InstallOptions o;
    std::vector<char> bytes;
    if (!readBytes(file, &bytes)) return o;
    const std::string kJson(bytes.begin(), bytes.end());
    o.installDir = jsonFindString(kJson, "installDir", defaultInstallDir());
    o.startupAdmin = jsonFindBool(kJson, "startupAdmin", true);
    o.startupMaximized = jsonFindBool(kJson, "startupMaximized", true);
    o.replaceTaskmgr = jsonFindBool(kJson, "replaceTaskmgr", false);
    o.testMode = jsonFindBool(kJson, "testMode", false);
    o.desktopShortcut = jsonFindBool(kJson, "desktopShortcut", true);
    o.startMenuShortcut = jsonFindBool(kJson, "startMenuShortcut", true);
    o.launchAfterInstall = jsonFindBool(kJson, "launchAfterInstall", true);
    return o;
}

// relaunchElevated starts this installer with runas and an install-state file.
// Input is state path; processing calls ShellExecuteW; output is true if Windows
// accepted the elevated launch request.
bool relaunchElevated(const std::wstring& stateFile) {
    const std::wstring kExe = exePath();
    if (kExe.empty()) return false;
    const std::wstring kArgs = std::wstring(kStateArg) + L" " + quote(stateFile);
    HINSTANCE rc = ::ShellExecuteW(nullptr, L"runas", kExe.c_str(), kArgs.c_str(), parent(kExe).c_str(), SW_SHOWNORMAL);
    return reinterpret_cast<INT_PTR>(rc) > 32;
}

// showSetupPage activates the first settings page. Input is none; processing
// flips FLTK group visibility and refreshes the window; no value is returned.
void showSetupPage() {
    if (gSetupPage) gSetupPage->show();
    if (gInstallPage) gInstallPage->hide();
    if (gMainWindow) gMainWindow->redraw();
}

// showInstallPage activates the second progress/result page. Input is none;
// processing hides the initial settings components and refreshes; no return.
void showInstallPage() {
    if (gSetupPage) gSetupPage->hide();
    if (gInstallPage) gInstallPage->show();
    if (gMainWindow) gMainWindow->redraw();
    Fl::check();
}

// collectOptions reads the current widget state. Input is global FLTK widgets;
// processing applies defaults and trimming; output is an InstallOptions object.
InstallOptions collectOptions() {
    InstallOptions o;
    if (gPathInput && gPathInput->value()) o.installDir = trim(utf8ToWide(gPathInput->value()));
    if (o.installDir.empty()) o.installDir = defaultInstallDir();
    o.startupAdmin = !gAdminCheck || gAdminCheck->value() != 0;
    o.startupMaximized = !gMaxCheck || gMaxCheck->value() != 0;
    o.replaceTaskmgr = gTaskmgrCheck && gTaskmgrCheck->value() != 0;
    o.testMode = gTestModeCheck && gTestModeCheck->value() != 0;
    o.desktopShortcut = !gDesktopCheck || gDesktopCheck->value() != 0;
    o.startMenuShortcut = !gStartMenuCheck || gStartMenuCheck->value() != 0;
    o.launchAfterInstall = !gLaunchCheck || gLaunchCheck->value() != 0;
    return o;
}

// applyOptions writes saved state back into widgets. Input is install options;
// processing updates each FLTK control; no value is returned.
void applyOptions(const InstallOptions& o) {
    if (gPathInput) gPathInput->value(wideToUtf8(o.installDir).c_str());
    if (gAdminCheck) gAdminCheck->value(o.startupAdmin ? 1 : 0);
    if (gMaxCheck) gMaxCheck->value(o.startupMaximized ? 1 : 0);
    if (gTaskmgrCheck) gTaskmgrCheck->value(o.replaceTaskmgr ? 1 : 0);
    if (gTestModeCheck) gTestModeCheck->value(o.testMode ? 1 : 0);
    if (gDesktopCheck) gDesktopCheck->value(o.desktopShortcut ? 1 : 0);
    if (gStartMenuCheck) gStartMenuCheck->value(o.startMenuShortcut ? 1 : 0);
    if (gLaunchCheck) gLaunchCheck->value(o.launchAfterInstall ? 1 : 0);
}

// PayloadDeployment records one switched payload file. The record carries the
// original-file backup needed to restore every earlier replacement on failure.
struct PayloadDeployment {
    std::wstring target;
    std::wstring backup;
    bool replacedExisting = false;
};

// removePayloadWorkTree removes only the installer-created staging tree. Input
// is its exact root; processing recursively removes staging files; output is a
// best-effort cleanup result and never touches the installation payload itself.
bool removePayloadWorkTree(const std::wstring& root) {
    WIN32_FIND_DATAW findData{};
    HANDLE find = ::FindFirstFileW(join(root, L"*").c_str(), &findData);
    if (find != INVALID_HANDLE_VALUE) {
        do {
            const std::wstring kName(findData.cFileName);
            if (kName == L"." || kName == L"..") continue;

            const std::wstring kChild = join(root, kName);
            if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
                removePayloadWorkTree(kChild);
            }
            else {
                ::DeleteFileW(kChild.c_str());
            }
        } while (::FindNextFileW(find, &findData));
        ::FindClose(find);
    }
    return ::RemoveDirectoryW(root.c_str()) != FALSE || ::GetLastError() == ERROR_FILE_NOT_FOUND;
}

// restorePayloadDeployments restores already replaced files in reverse order.
// Input is the successful switch list; processing puts backups back in place;
// output is false only when Windows rejects one of the rollback operations.
bool restorePayloadDeployments(const std::vector<PayloadDeployment>& deployments) {
    bool restored = true;
    for (auto it = deployments.rbegin(); it != deployments.rend(); ++it) {
        if (!it->replacedExisting) {
            if (existsFile(it->target) && !::DeleteFileW(it->target.c_str())) {
                restored = false;
            }
            continue;
        }

        if (!existsFile(it->backup)) {
            restored = false;
            continue;
        }

        if (existsFile(it->target)) {
            if (!::ReplaceFileW(it->target.c_str(), it->backup.c_str(), nullptr,
                REPLACEFILE_WRITE_THROUGH, nullptr, nullptr)) {
                restored = false;
            }
        }
        else if (!::MoveFileExW(it->backup.c_str(), it->target.c_str(), MOVEFILE_WRITE_THROUGH)) {
            restored = false;
        }
    }
    return restored;
}

// switchStagedPayloadFile installs one fully written staging file. Input is the
// staged path, final path, and backup path; output describes a reversible switch.
bool switchStagedPayloadFile(const std::wstring& staged, const std::wstring& target,
    const std::wstring& backup, PayloadDeployment* deployment) {
    if (!deployment || !ensureDir(parent(target))) return false;

    deployment->target = target;
    deployment->backup = backup;
    deployment->replacedExisting = existsFile(target);

    if (deployment->replacedExisting) {
        if (!ensureDir(parent(backup))) return false;
        return ::ReplaceFileW(target.c_str(), staged.c_str(), backup.c_str(),
            REPLACEFILE_WRITE_THROUGH, nullptr, nullptr) != FALSE;
    }

    return ::MoveFileExW(staged.c_str(), target.c_str(), MOVEFILE_WRITE_THROUGH) != FALSE;
}

// extractPayload stages every generated resource before any live file changes.
// Input is install options and log text; processing commits reversible switches;
// output is true only when the full payload becomes available as one update.
bool extractPayload(const InstallOptions& o, std::wstring* log) {
    if (!ensureDir(o.installDir)) {
        appendLog(log, L"创建安装目录失败: " + o.installDir);
        return false;
    }

    // Use the process ID and clock tick to create a work directory unique to this installation, avoiding overwriting existing installation content.
    const std::wstring kWorkRoot = join(o.installDir, L".kswordsetup-staging-" +
        std::to_wstring(::GetCurrentProcessId()) + L"-" + std::to_wstring(::GetTickCount64()));
    if (!::CreateDirectoryW(kWorkRoot.c_str(), nullptr)) {
        appendLog(log, L"创建安装临时目录失败: " + kWorkRoot);
        return false;
    }

    const std::wstring kPayloadRoot = join(kWorkRoot, L"payload");
    const std::wstring kBackupRoot = join(kWorkRoot, L"backup");
    for (unsigned int i = 0; i < kKswordSetupPayloadResourceCount; ++i) {
        const auto& e = kKswordSetupPayloadResources[i];
        const std::wstring kStaged = join(kPayloadRoot, e.relativePath);
        appendLog(log, L"准备: " + std::wstring(e.relativePath));
        if (!extractRc(e.resourceId, kStaged)) {
            appendLog(log, L"准备安装文件失败: " + kStaged);
            removePayloadWorkTree(kWorkRoot);
            return false;
        }
    }

    // Only touch existing installations after all resources are fully written to staging; restore previous files on failure.
    std::vector<PayloadDeployment> deployments;
    deployments.reserve(kKswordSetupPayloadResourceCount);
    for (unsigned int i = 0; i < kKswordSetupPayloadResourceCount; ++i) {
        const auto& e = kKswordSetupPayloadResources[i];
        const std::wstring kTarget = join(o.installDir, e.relativePath);
        const std::wstring kStaged = join(kPayloadRoot, e.relativePath);
        const std::wstring kBackup = join(kBackupRoot, e.relativePath);
        PayloadDeployment deployment;

        appendLog(log, L"安装: " + std::wstring(e.relativePath));
        if (!switchStagedPayloadFile(kStaged, kTarget, kBackup, &deployment)) {
            const DWORD kError = ::GetLastError();
            const bool kRestored = restorePayloadDeployments(deployments);
            appendLog(log, L"安装切换失败，错误码: " + std::to_wstring(kError) + L"，已" +
                (kRestored ? L"恢复原有文件。" : L"尝试恢复原有文件，但仍有文件未恢复。"));
            // Keep the backup in the working directory when rollback is incomplete to prevent cleanup from erasing the last recoverable copy of the original file.
            if (kRestored) {
                removePayloadWorkTree(kWorkRoot);
            }
            else {
                appendLog(log, L"已保留恢复备份目录: " + kWorkRoot);
            }
            return false;
        }
        deployments.push_back(std::move(deployment));
    }

    // Backup is no longer needed after success; deletion is limited to the current random staging directory and does not affect user files or configurations.
    removePayloadWorkTree(kWorkRoot);
    return true;
}

// writeSettings creates or optionally overwrites Style/appearance_settings.json.
// Input is install options; processing asks before replacing existing settings;
// output is true when the final policy is applied successfully.
bool writeSettings(const InstallOptions& o, std::wstring* log) {
    const std::wstring kFile = join(o.installDir, kSettingsRel);
    if (existsFile(kFile)) {
        setInstallerShellDialogMode(true);
        int choice = topMostMessageBox(
            L"检测到已有配置文件。\n\n选择“是”覆盖安装器生成配置；选择“否”保留原有一切配置。",
            L"KswordSetup 覆盖安装", MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2);
        setInstallerShellDialogMode(false);
        if (choice != IDYES) {
            appendLog(log, L"保留已有配置: " + kFile);
            return true;
        }
    }
    std::ostringstream json;
    json << "{\n"
         << "    \"theme_mode\": \"follow_system\",\n"
         << "    \"background_image_path\": \"Style/ksword_background.png\",\n"
         << "    \"background_opacity_percent\": 35,\n"
         << "    \"startup_default_tab_key\": \"welcome\",\n"
         << "    \"startup_maximized\": " << (o.startupMaximized ? "true" : "false") << ",\n"
         << "    \"startup_topmost_enabled\": false,\n"
         << "    \"startup_auto_request_admin\": " << (o.startupAdmin ? "true" : "false") << ",\n"
         << "    \"startup_window_scale_factor\": 1.0,\n"
         << "    \"startup_scale_recommend_prompt_disabled\": false,\n"
         << "    \"unlocker_shell_context_menu_enabled\": false,\n"
         << "    \"use_wide_scroll_bars\": false,\n"
         << "    \"scroll_bar_auto_hide_enabled\": false,\n"
         << "    \"slider_wheel_adjust_enabled\": false\n"
         << "}\n";
    const std::string kData = json.str();
    if (!writeBytes(kFile, kData.data(), (DWORD)kData.size())) {
        appendLog(log, L"写入配置失败: " + kFile);
        return false;
    }
    appendLog(log, L"写入启动配置: " + kFile);
    return true;
}

// RunWait starts a process and waits for completion. Inputs are executable,
// arguments, working directory and timeout; processing uses CreateProcessW;
// output is true when exit code is zero.
bool runWait(const std::wstring& exe, const std::wstring& args, const std::wstring& cwd, DWORD timeoutMs, DWORD* exitCode) {
    std::wstring cmd = quote(exe) + (args.empty() ? L"" : L" " + args);
    std::vector<wchar_t> mutableCmd(cmd.begin(), cmd.end());
    mutableCmd.push_back(L'\0');
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!::CreateProcessW(exe.c_str(), mutableCmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, cwd.empty() ? nullptr : cwd.c_str(), &si, &pi)) {
        if (exitCode) *exitCode = ::GetLastError();
        return false;
    }
    DWORD wait = ::WaitForSingleObject(pi.hProcess, timeoutMs);
    if (wait == WAIT_TIMEOUT) ::TerminateProcess(pi.hProcess, 1460);
    DWORD code = 1;
    ::GetExitCodeProcess(pi.hProcess, &code);
    ::CloseHandle(pi.hThread);
    ::CloseHandle(pi.hProcess);
    if (exitCode) *exitCode = code;
    return wait == WAIT_OBJECT_0 && code == 0;
}

// runWaitCapture starts a process, waits for completion, and captures combined
// stdout/stderr text for diagnostics. Inputs mirror RunWait plus an output
// buffer; output text is decoded with the OEM code page because console tools
// usually emit that encoding when launched without a console window.
bool runWaitCapture(const std::wstring& exe, const std::wstring& args, const std::wstring& cwd, DWORD timeoutMs, DWORD* exitCode, std::wstring* output) {
    if (output) output->clear();

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = nullptr;

    HANDLE readPipe = nullptr;
    HANDLE writePipe = nullptr;
    if (!::CreatePipe(&readPipe, &writePipe, &sa, 0)) {
        if (exitCode) *exitCode = ::GetLastError();
        return false;
    }
    // The read end must not be inherited by child processes; otherwise, the reader will not see EOF after the child exits.
    if (!::SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0)) {
        const DWORD kError = ::GetLastError();
        ::CloseHandle(readPipe);
        ::CloseHandle(writePipe);
        if (exitCode) *exitCode = kError;
        return false;
    }

    // The launched helper and every descendant are kept in one job.  If a
    // helper exits while a descendant still owns stdout/stderr, closing the job
    // lets the reader finish instead of leaving the installer waiting forever.
    HANDLE job = ::CreateJobObjectW(nullptr, nullptr);
    if (!job) {
        const DWORD kError = ::GetLastError();
        ::CloseHandle(readPipe);
        ::CloseHandle(writePipe);
        if (exitCode) *exitCode = kError;
        if (output) *output = L"无法创建子进程作业对象。";
        return false;
    }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jobInfo{};
    jobInfo.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!::SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &jobInfo,
            sizeof(jobInfo))) {
        const DWORD kError = ::GetLastError();
        ::CloseHandle(job);
        ::CloseHandle(readPipe);
        ::CloseHandle(writePipe);
        if (exitCode) *exitCode = kError;
        if (output) *output = L"无法配置子进程作业对象。";
        return false;
    }

    std::wstring cmd = quote(exe) + (args.empty() ? L"" : L" " + args);
    std::vector<wchar_t> mutableCmd(cmd.begin(), cmd.end());
    mutableCmd.push_back(L'\0');

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = ::GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = writePipe;
    si.hStdError = writePipe;

    PROCESS_INFORMATION pi{};
    const BOOL kCreated = ::CreateProcessW(
        exe.c_str(),
        mutableCmd.data(),
        nullptr,
        nullptr,
        TRUE,
        CREATE_NO_WINDOW | CREATE_SUSPENDED,
        nullptr,
        cwd.empty() ? nullptr : cwd.c_str(),
        &si,
        &pi);
    const DWORD kCreateError = kCreated ? ERROR_SUCCESS : ::GetLastError();

    ::CloseHandle(writePipe);
    writePipe = nullptr;

    if (!kCreated) {
        if (output) {
            *output = L"CreateProcessW failed, last error=" + std::to_wstring(kCreateError);
        }
        ::CloseHandle(readPipe);
        ::CloseHandle(job);
        if (exitCode) *exitCode = kCreateError;
        return false;
    }

    // Assign before resuming so helpers cannot start a child outside our job
    // between CreateProcessW and AssignProcessToJobObject.
    if (!::AssignProcessToJobObject(job, pi.hProcess)) {
        const DWORD kError = ::GetLastError();
        ::TerminateProcess(pi.hProcess, kError);
        ::WaitForSingleObject(pi.hProcess, 5000);
        ::CloseHandle(readPipe);
        ::CloseHandle(pi.hThread);
        ::CloseHandle(pi.hProcess);
        ::CloseHandle(job);
        if (exitCode) *exitCode = kError;
        if (output) *output = L"无法将诊断子进程加入受控作业，last error=" + std::to_wstring(kError);
        return false;
    }
    if (::ResumeThread(pi.hThread) == static_cast<DWORD>(-1)) {
        const DWORD kError = ::GetLastError();
        ::TerminateJobObject(job, kError);
        ::WaitForSingleObject(pi.hProcess, 5000);
        ::CloseHandle(readPipe);
        ::CloseHandle(pi.hThread);
        ::CloseHandle(pi.hProcess);
        ::CloseHandle(job);
        if (exitCode) *exitCode = kError;
        if (output) *output = L"无法启动诊断子进程，last error=" + std::to_wstring(kError);
        return false;
    }

    // The child process may fill the anonymous pipe; synchronous draining prevents a deadlock where the parent waits for the child and the child waits for the parent.
    std::shared_ptr<std::string> captured;
    std::thread reader;
    try {
        captured = std::make_shared<std::string>();
        reader = std::thread([readPipe, captured]() {
            constexpr size_t kMaxCapturedBytes = 1024 * 1024;
            char buffer[4096];
            DWORD read = 0;
            try {
                while (::ReadFile(readPipe, buffer, sizeof(buffer), &read, nullptr) && read > 0) {
                    // Continue reading the empty pipe even if the diagnostic text exceeds the limit to avoid re-introducing child process blocking.
                    const size_t kAvailable = captured->size() < kMaxCapturedBytes
                        ? kMaxCapturedBytes - captured->size() : 0;
                    captured->append(buffer, buffer + std::min<size_t>(read, kAvailable));
                }
            }
            catch (...) {
                // Diagnostic cache failures should not terminate the installer; closing the read end allows the child process to detect the broken pipe.
            }
            ::CloseHandle(readPipe);
        });
    }
    catch (const std::exception&) {
        // If the reader cannot be created, execution must stop to prevent child processes from filling the pipe; after bounded cleanup, return an error to the UI.
        constexpr DWORD kReaderCreationFailure = ERROR_NOT_ENOUGH_MEMORY;
        ::TerminateJobObject(job, kReaderCreationFailure);
        ::WaitForSingleObject(pi.hProcess, 5000);
        ::CloseHandle(readPipe);
        ::CloseHandle(pi.hThread);
        ::CloseHandle(pi.hProcess);
        ::CloseHandle(job);
        if (exitCode) *exitCode = kReaderCreationFailure;
        if (output) *output = L"无法创建诊断输出读取线程。";
        return false;
    }

    DWORD wait = ::WaitForSingleObject(pi.hProcess, timeoutMs);
    if (wait != WAIT_OBJECT_0) {
        // Terminate the entire process tree on timeout or wait failure, rather than killing only the parent and leaving descendants that hold output pipes.
        ::TerminateJobObject(job, wait == WAIT_TIMEOUT ? 1460 : ::GetLastError());
        ::WaitForSingleObject(pi.hProcess, 5000);
    }

    // PowerShell or other tools may cause descendants to inherit the output pipe; bounded waiting for EOF is required even after the initial process exits.
    constexpr DWORD kReaderDrainTimeoutMs = 5000;
    constexpr DWORD kReaderCancelTimeoutMs = 2000;
    const HANDLE kReaderThread = reinterpret_cast<HANDLE>(reader.native_handle());
    DWORD readerWait = ::WaitForSingleObject(kReaderThread, kReaderDrainTimeoutMs);
    bool readerCancelled = readerWait != WAIT_OBJECT_0;
    if (readerCancelled) {
        // First terminate the job tree to close inherited output handles; this is more reliable than terminating only the parent process.
        ::TerminateJobObject(job, ERROR_OPERATION_ABORTED);
        ::WaitForSingleObject(pi.hProcess, 5000);
        readerWait = ::WaitForSingleObject(kReaderThread, kReaderDrainTimeoutMs);
    }
    if (readerWait != WAIT_OBJECT_0) {
        // If the reader is currently blocked on a synchronous ReadFile, request cancellation from the target thread and wait only for a limited duration.
        ::CancelSynchronousIo(kReaderThread);
        readerWait = ::WaitForSingleObject(kReaderThread, kReaderCancelTimeoutMs);
    }
    const bool kReaderDetached = readerWait != WAIT_OBJECT_0;
    if (kReaderDetached) {
        // Do not forcibly kill unknown I/O threads unsafely; the shared buffer is still held by the thread, so the installer can return immediately.
        reader.detach();
    }
    else {
        reader.join();
    }

    DWORD code = 1;
    ::GetExitCodeProcess(pi.hProcess, &code);
    ::CloseHandle(pi.hThread);
    ::CloseHandle(pi.hProcess);
    ::CloseHandle(job);
    if (exitCode) *exitCode = code;

    if (output && !kReaderDetached && captured && !captured->empty()) {
        const int kWideLen = ::MultiByteToWideChar(CP_OEMCP, 0, captured->data(), (int)captured->size(), nullptr, 0);
        if (kWideLen > 0) {
            std::wstring wide((size_t)kWideLen, L'\0');
            ::MultiByteToWideChar(CP_OEMCP, 0, captured->data(), (int)captured->size(), &wide[0], kWideLen);
            *output = std::move(wide);
        }
    }
    if (output && readerCancelled) {
        *output += L"\r\n诊断输出管道仍被子进程占用，已停止继续等待。";
    }
    if (output && kReaderDetached) {
        *output += L"\r\n诊断输出读取线程未能及时退出，安装器已放弃等待。";
    }

    return wait == WAIT_OBJECT_0 && code == 0 && !readerCancelled && !kReaderDetached;
}

// installTaskmgr calls the released TaskmgrHijack.ps1 in parameter mode. Input is
// install options; processing points IFEO at installed Ksword5.1.exe; output is
// true when PowerShell exits successfully.
bool installTaskmgr(const InstallOptions& o, std::wstring* log) {
    const std::wstring kScript = join(o.installDir, kTaskmgrScript);
    const std::wstring kTarget = join(o.installDir, kMainExe);
    const std::wstring kPowershell = systemExePath(L"WindowsPowerShell\\v1.0\\powershell.exe");
    const std::wstring kArgs = L"-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File " + quote(kScript) + L" -Install -TargetExe " + quote(kTarget);
    DWORD code = 1;
    std::wstring detail;
    const bool kOk = existsFile(kScript) && existsFile(kTarget) && runWaitCapture(kPowershell, kArgs, o.installDir, 60000, &code, &detail);
    if (kOk) {
        appendLog(log, L"已替换系统任务管理器。");
    }
    else {
        appendLog(log, L"任务管理器替换失败，退出码: " + std::to_wstring(code));
        if (!detail.empty()) {
            appendLog(log, L"详细信息: " + detail);
        }
    }
    return kOk;
}

// enableTestMode runs bcdedit /set testsigning on. Input is log text; processing
// waits for bcdedit; output is true when Windows accepts the setting.
bool enableTestMode(std::wstring* log) {
    DWORD code = 1;
    const std::wstring kBcdedit = systemExePath(L"bcdedit.exe");
    std::wstring detail;
    const bool kOk = runWaitCapture(kBcdedit, L"/set testsigning on", L"", 60000, &code, &detail);
    if (kOk) {
        appendLog(log, L"已执行 bcdedit /set testsigning on。");
    }
    else {
        appendLog(log, L"启动测试模式失败，退出码: " + std::to_wstring(code));
        if (!detail.empty()) {
            appendLog(log, L"详细信息: " + detail);
        }
    }
    return kOk;
}

// knownFolder returns a Windows known-folder path. Input is a folder id;
// processing calls SHGetKnownFolderPath; output is empty when unavailable.
std::wstring knownFolder(const KNOWNFOLDERID& id) {
    PWSTR raw = nullptr;
    HRESULT hr = ::SHGetKnownFolderPath(id, 0, nullptr, &raw);
    if (FAILED(hr) || !raw) return {};
    std::wstring out(raw);
    ::CoTaskMemFree(raw);
    return out;
}

// createShortcut writes one .lnk file. Inputs are link path, target and working
// directory; processing uses IShellLinkW/IPersistFile; output is success flag.
bool createShortcut(const std::wstring& link, const std::wstring& target, const std::wstring& cwd) {
    if (!ensureDir(parent(link))) return false;
    IShellLinkW* sl = nullptr;
    HRESULT hr = ::CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_IShellLinkW, (void**)&sl);
    if (FAILED(hr) || !sl) return false;
    sl->SetPath(target.c_str());
    sl->SetWorkingDirectory(cwd.c_str());
    sl->SetDescription(L"KswordARK");
    IPersistFile* pf = nullptr;
    hr = sl->QueryInterface(IID_IPersistFile, (void**)&pf);
    if (SUCCEEDED(hr) && pf) {
        hr = pf->Save(link.c_str(), TRUE);
        pf->Release();
    }
    sl->Release();
    return SUCCEEDED(hr);
}

// createShortcuts creates selected current-user shortcuts. Input is install
// options; processing writes Desktop/Programs links for the interactive user;
// output is true when all requested shortcuts succeed.
bool createShortcuts(const InstallOptions& o, std::wstring* log) {
    bool all = true;
    const std::wstring kTarget = join(o.installDir, kLauncherExe);
    if (o.desktopShortcut) {
        bool ok = createShortcut(join(knownFolder(FOLDERID_Desktop), L"KswordARK.lnk"), kTarget, o.installDir);
        appendLog(log, ok ? L"已创建桌面快捷方式。" : L"创建桌面快捷方式失败。");
        all = all && ok;
    }
    if (o.startMenuShortcut) {
        bool ok = createShortcut(join(join(knownFolder(FOLDERID_Programs), L"KswordARK"), L"KswordARK.lnk"), kTarget, o.installDir);
        appendLog(log, ok ? L"已创建开始菜单快捷方式。" : L"创建开始菜单快捷方式失败。");
        all = all && ok;
    }
    return all;
}

// launchKsword starts the installed Launcher. Input is install directory;
// processing uses ShellExecuteW; output is true when launch is accepted.
bool launchKsword(const std::wstring& dir) {
    HINSTANCE rc = ::ShellExecuteW(nullptr, L"open", join(dir, kLauncherExe).c_str(), nullptr, dir.c_str(), SW_SHOWNORMAL);
    return reinterpret_cast<INT_PTR>(rc) > 32;
}

// performInstall executes the full install transaction. Input is options;
// processing extracts payload, applies optional actions, prompts for reboot, and
// output is the final result model for follow-up launch/reboot behavior.
InstallResult performInstall(const InstallOptions& o) {
    InstallResult r;
    appendLog(&r.logText, L"开始安装到: " + o.installDir);
    if (fileExistsInDir(o.installDir, kLauncherExe) || fileExistsInDir(o.installDir, kMainExe)) {
        appendLog(&r.logText, L"检测到已有安装，按合并覆盖方式更新。");
    }
    r.ok = extractPayload(o, &r.logText) && r.ok;
    if (!r.ok) return r;
    r.ok = writeSettings(o, &r.logText) && r.ok;
    r.ok = createShortcuts(o, &r.logText) && r.ok;
    if (o.replaceTaskmgr) r.ok = installTaskmgr(o, &r.logText) && r.ok;
    if (o.testMode) {
        const bool kTestOk = enableTestMode(&r.logText);
        r.ok = kTestOk && r.ok;
        if (kTestOk) {
            setInstallerShellDialogMode(true);
            int choice = topMostMessageBox(L"测试模式已写入，需要重启系统后生效。是否立即重启？", L"KswordSetup", MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2);
            setInstallerShellDialogMode(false);
            r.rebootNow = choice == IDYES;
        }
    }
    appendLog(&r.logText, r.ok ? L"安装完成。" : L"安装完成，但存在失败项，请查看日志。");
    return r;
}

// startInstall handles the Install button and elevated continuation. Input is
// current UI state; processing performs UAC handoff when needed; no return.
void startInstall() {
    InstallOptions o = collectOptions();
    showInstallPage();
    setStatus(L"准备安装...");
    if (needsElevation(o) && !isElevated()) {
        setStatus(L"当前选项需要管理员权限，正在请求 UAC...\r\n需要管理员权限的选项包括替换任务管理器或启动测试模式。");
        std::wstring state = tempStatePath();
        if (!saveState(state, o)) {
            topMostMessageBox(L"写入提权状态文件失败。", L"KswordSetup", MB_ICONERROR);
            showSetupPage();
            return;
        }
        if (relaunchElevated(state)) {
            setStatus(L"已请求管理员权限，请在 UAC 窗口确认。确认后安装将在新窗口继续。");
            return;
        }
        topMostMessageBox(L"管理员权限请求被取消或启动失败。", L"KswordSetup", MB_ICONWARNING);
        showSetupPage();
        return;
    }
    if (gInstallButton) gInstallButton->deactivate();
    if (gBrowseButton) gBrowseButton->deactivate();
    InstallResult result = performInstall(o);
    if (gInstallButton) gInstallButton->activate();
    if (gBrowseButton) gBrowseButton->activate();
    if (result.rebootNow) {
        ::ShellExecuteW(nullptr, L"open", L"shutdown.exe", L"/r /t 0", nullptr, SW_HIDE);
        return;
    }
    if (result.ok && o.launchAfterInstall) launchKsword(o.installDir);
}

// browseInstallDir opens the native folder picker. Input is current UI path;
// processing uses IFileDialog in folder mode; no return value.
void browseInstallDir() {
    setInstallerShellDialogMode(true);
    IFileDialog* dlg = nullptr;
    HRESULT hr = ::CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER, IID_IFileDialog, (void**)&dlg);
    if (FAILED(hr) || !dlg) {
        setInstallerShellDialogMode(false);
        return;
    }
    DWORD opts = 0;
    dlg->GetOptions(&opts);
    dlg->SetOptions(opts | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM);
    dlg->SetTitle(L"选择 KswordARK 安装目录");
    if (SUCCEEDED(dlg->Show(nullptr))) {
        IShellItem* item = nullptr;
        if (SUCCEEDED(dlg->GetResult(&item)) && item) {
            PWSTR raw = nullptr;
            if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &raw)) && raw) {
                if (gPathInput) gPathInput->value(wideToUtf8(raw).c_str());
                ::CoTaskMemFree(raw);
            }
            item->Release();
        }
    }
    dlg->Release();
    setInstallerShellDialogMode(false);
}

// extractCharacterImage releases the left PNG to temp for KLayeredImageWindow.
// Input is none; processing extracts once; output is a UTF-8 filesystem path.
std::string extractCharacterImage() {
    if (!gCharacterImagePath.empty() && existsFile(gCharacterImagePath)) return wideToUtf8(gCharacterImagePath);
    wchar_t temp[MAX_PATH]{};
    if (!::GetTempPathW(MAX_PATH, temp)) gCharacterImagePath = L"KswordSetupCharacter.png";
    else gCharacterImagePath = join(temp, L"KswordSetupCharacter.png");
    extractRc(IDR_KSWORD_SETUP_CHARACTER_PNG, gCharacterImagePath);
    return wideToUtf8(gCharacterImagePath);
}

// applyInstallerZOrder keeps the installer panel and character image in the
// requested topmost order. When the compile-time switch is disabled, this
// becomes a no-op so the installer can be tested without any topmost behavior.
void applyInstallerZOrder(Fl_Window* owner) {
#if KSWORD_SETUP_ENABLE_TOPMOST
    if (!owner) return;
    HWND ownerHwnd = flWin32Xid(owner);
    if (ownerHwnd) {
        ::SetWindowPos(ownerHwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    }
    HWND imageHwnd = g_characterWindow.hwnd();
    if (imageHwnd) {
        ::SetWindowPos(imageHwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    }
#else
    (void)owner;
#endif
}

// setInstallerShellDialogMode temporarily disables the topmost behavior while a
// shell dialog is shown. When the compile-time switch is disabled, the helper
// stays inert and simply preserves the installer state.
void setInstallerShellDialogMode(bool enabled) {
#if KSWORD_SETUP_ENABLE_TOPMOST
    g_topMostPaused = enabled;
    HWND ownerHwnd = g_mainWindow ? flWin32Xid(g_mainWindow) : nullptr;
    HWND imageHwnd = g_characterWindow.hwnd();
    const HWND insertAfter = enabled ? HWND_NOTOPMOST : HWND_TOPMOST;
    const UINT flags = SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE;
    if (ownerHwnd) {
        ::SetWindowPos(ownerHwnd, insertAfter, 0, 0, 0, 0, flags);
    }
    if (imageHwnd) {
        ::SetWindowPos(imageHwnd, insertAfter, 0, 0, 0, 0, flags);
    }
    if (!enabled && g_mainWindow) {
        applyInstallerZOrder(g_mainWindow);
    }
#else
    (void)enabled;
#endif
}

// topMostMessageBox shows a native message box above the installer. Inputs are
// normal MessageBoxW parameters; processing optionally adds MB_TOPMOST when the
// compile-time switch is enabled; output is the clicked button id.
int topMostMessageBox(const wchar_t* text, const wchar_t* caption, UINT type) {
    HWND ownerHwnd = gMainWindow ? flWin32Xid(gMainWindow) : nullptr;
#if KSWORD_SETUP_ENABLE_TOPMOST
    return ::MessageBoxW(ownerHwnd, text, caption, type | MB_TOPMOST | MB_SETFOREGROUND);
#else
    return ::MessageBoxW(ownerHwnd, text, caption, type | MB_SETFOREGROUND);
#endif
}

// ensureTaskbarAppWindow makes the FLTK owner a normal shell application window.
// Input is the right-side installer window; processing removes tool/noactivate
// styles and forces WS_EX_APPWINDOW; no value is returned.
void ensureTaskbarAppWindow(Fl_Window* window) {
    HWND hwnd = window ? flWin32Xid(window) : nullptr;
    if (!hwnd) return;
    LONG_PTR exStyle = ::GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
    exStyle &= ~(static_cast<LONG_PTR>(WS_EX_TOOLWINDOW) | static_cast<LONG_PTR>(WS_EX_NOACTIVATE));
    exStyle |= WS_EX_APPWINDOW;
    ::SetWindowLongPtrW(hwnd, GWL_EXSTYLE, exStyle);
    ::SetWindowLongPtrW(hwnd, GWLP_HWNDPARENT, 0);
    ::SetWindowPos(hwnd, nullptr, 0, 0, 0, 0,
        SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOOWNERZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
}

// reassertInstallerZOrder is a low-frequency FLTK timer callback. Input is the
// owner window pointer; processing reapplies z-order after activation/focus
// churn; no value is returned and the timer stops once the owner closes.
void reassertInstallerZOrder(void* data) {
    auto* owner = static_cast<Fl_Window*>(data);
    if (!owner || !owner->shown()) return;
#if KSWORD_SETUP_ENABLE_TOPMOST
    if (!g_topMostPaused) {
        applyInstallerZOrder(owner);
    }
    Fl::repeat_timeout(0.75, reassertInstallerZOrder, data);
#endif
}

// parseStateArgument returns the --install-state path. Input is process command
// line; processing tokenizes with CommandLineToArgvW; output is empty when absent.
std::wstring parseStateArgument() {
    int argc = 0;
    LPWSTR* argv = ::CommandLineToArgvW(::GetCommandLineW(), &argc);
    if (!argv) return {};
    std::wstring out;
    for (int i = 1; i + 1 < argc; ++i) {
        if (std::wstring(argv[i]) == kStateArg) { out = argv[i + 1]; break; }
    }
    ::LocalFree(argv);
    return out;
}

// configureRightContent builds the installer page. Input is owner window;
// processing creates K* widgets and callbacks; no return value.
void configureRightContent(Fl_Window* window) {
    const KTheme& theme = KThemeManager::instance().theme();
    const PageLayout kLayout = buildPageLayout();

    gSetupPage = kCreateCard(kLayout.cardX, kLayout.cardY, kLayout.cardW, kLayout.cardH, nullptr);
    gSetupPage->setTitle("");
    gSetupPage->setSubtitle("");
    gSetupPage->begin();
    KText* headerTitle = kCreateText(kLayout.contentX, kLayout.cardY + 22, kLayout.contentW, 26, "KswordSetup");
    headerTitle->labelsize(19);
    headerTitle->labelcolor(theme.text);
    KText* headerSubtitle = kCreateText(kLayout.contentX, kLayout.cardY + 46, kLayout.contentW, 22, "选择安装路径和首次启动行为，点击安装时按需请求管理员权限。");
    headerSubtitle->labelsize(13);
    headerSubtitle->labelcolor(theme.mutedText);
    KText* title = kCreateText(kLayout.contentX, kLayout.cardY + 82, kLayout.contentW, 26, "安装路径");
    title->labelsize(19);
    title->labelcolor(theme.text);
    gPathInput = kCreateInput(kLayout.contentX, kLayout.cardY + 108, kLayout.contentW - 112, 30, nullptr);
    gPathInput->value(wideToUtf8(defaultInstallDir()).c_str());
    gBrowseButton = kCreateButton(kLayout.contentX + kLayout.contentW - 94, kLayout.cardY + 108, 94, 30, "浏览", kKbuttonLight);
    gBrowseButton->callback([](Fl_Widget*, void*) { browseInstallDir(); });
    int y = kLayout.cardY + 150;
    gAdminCheck = kCreateCheckBox(kLayout.contentX, y, kLayout.contentW, 24, "启动时自动请求管理员权限"); gAdminCheck->value(1); y += 27;
    gMaxCheck = kCreateCheckBox(kLayout.contentX, y, kLayout.contentW, 24, "启动时默认最大化"); gMaxCheck->value(1); y += 27;
    gTaskmgrCheck = kCreateCheckBox(kLayout.contentX, y, kLayout.contentW, 24, "替换系统自带任务管理器（需要管理员权限）"); y += 27;
    gTestModeCheck = kCreateCheckBox(kLayout.contentX, y, kLayout.contentW, 24, "启动测试模式 testsigning（需要管理员权限）"); y += 27;
    gDesktopCheck = kCreateCheckBox(kLayout.contentX, y, kLayout.contentW, 24, "创建桌面快捷方式"); gDesktopCheck->value(1); y += 27;
    gStartMenuCheck = kCreateCheckBox(kLayout.contentX, y, kLayout.contentW, 24, "创建开始菜单快捷方式"); gStartMenuCheck->value(1);
    gInstallButton = kCreateButton(kLayout.contentX + kLayout.contentW - 224, kLayout.cardY + kLayout.cardH - 48, 104, 34, "安装", kKbuttonHeavy);
    gInstallButton->callback([](Fl_Widget*, void*) { startInstall(); });
    KButton* closeButton = kCreateButton(kLayout.contentX + kLayout.contentW - 104, kLayout.cardY + kLayout.cardH - 48, 100, 34, "关闭", kKbuttonLight);
    closeButton->callback([](Fl_Widget*, void* data) {
        gCharacterWindow.destroy();
        if (auto* owner = static_cast<Fl_Window*>(data)) owner->hide();
    }, window);
    gSetupPage->end();

    gInstallPage = kCreateCard(kLayout.cardX, kLayout.cardY, kLayout.cardW, kLayout.cardH, nullptr);
    gInstallPage->setTitle("");
    gInstallPage->setSubtitle("");
    gInstallPage->begin();
    KText* installTitle = kCreateText(kLayout.contentX, kLayout.cardY + 22, kLayout.contentW, 28, "安装进度");
    installTitle->labelsize(19);
    installTitle->labelcolor(theme.text);
    KText* installSubtitle = kCreateText(kLayout.contentX, kLayout.cardY + 48, kLayout.contentW, 22, "安装时会释放内嵌 payload，并在需要时执行管理员操作。");
    installSubtitle->labelsize(13);
    installSubtitle->labelcolor(theme.mutedText);
    gStatus = kCreateTextDisplay(kLayout.contentX, kLayout.cardY + 86, kLayout.contentW, 250, nullptr);
    gStatus->setText("等待开始安装。");
    gLaunchCheck = kCreateCheckBox(kLayout.contentX, kLayout.cardY + 350, kLayout.contentW, 24, "安装完成后启动 Ksword");
    gLaunchCheck->value(1);
    KButton* backButton = kCreateButton(kLayout.contentX + kLayout.contentW - 224, kLayout.cardY + kLayout.cardH - 48, 104, 34, "返回", kKbuttonLight);
    backButton->callback([](Fl_Widget*, void*) { showSetupPage(); });
    KButton* finishButton = kCreateButton(kLayout.contentX + kLayout.contentW - 104, kLayout.cardY + kLayout.cardH - 48, 100, 34, "关闭", kKbuttonLight);
    finishButton->callback([](Fl_Widget*, void* data) {
        gCharacterWindow.destroy();
        if (auto* owner = static_cast<Fl_Window*>(data)) owner->hide();
    }, window);
    gInstallPage->end();
    gInstallPage->hide();
}
} // namespace

// guiInitMain builds the right-side FLTK installer content. Inputs are arguments
// and the owner window; processing sets style and widgets; no value is returned.
void guiInitMain(const std::vector<std::string>& args, Fl_Window* mainWindow) {
    (void)args;
    if (!mainWindow) return;
    gMainWindow = mainWindow;
    mainWindow->label("KswordSetup");
    mainWindow->size(kWindowWidth, kWindowHeight);
    mainWindow->border(0);
    setWindowStyle(mainWindow);
    configureRightContent(mainWindow);
    KThemeManager::instance().refreshAll();
}

// guiAfterShowMain creates the transparent left PNG window and starts elevated
// continuation when --install-state is present. Input is the shown owner window;
// no value is returned.
void guiAfterShowMain(Fl_Window* mainWindow) {
    if (!mainWindow) return;
    ensureTaskbarAppWindow(mainWindow);
    const std::string kCharacterPath = extractCharacterImage();
    gCharacterWindow.setClickThrough(true);
    gCharacterWindow.showPngForWindow(mainWindow, kCharacterPath, -kLayeredImageWidth + kImageOverlap, -kImageVerticalOffset, kLayeredImageWidth, kImageDrawHeight);
    applyInstallerZOrder(mainWindow);
    Fl::add_timeout(0.75, reassertInstallerZOrder, mainWindow);
    const std::wstring kState = parseStateArgument();
    if (!kState.empty()) {
        applyOptions(loadState(kState));
        ::DeleteFileW(kState.c_str());
        setStatus(L"已获得管理员权限，正在继续安装...");
        Fl::add_timeout(0.20, [](void*) { startInstall(); });
    }
}

// asyncMain remains present for the framework entry point contract. Input args
// are unused by the installer background thread; output zero means success.
int asyncMain(const std::vector<std::string>& args) {
    (void)args;
    return 0;
}
