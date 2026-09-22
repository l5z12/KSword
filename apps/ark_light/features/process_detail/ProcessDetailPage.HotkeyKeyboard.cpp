#include "ProcessDetailPage.h"

#include "../../../../shared/ark_client/ArkDriverClient.h"

#include <objbase.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <tlhelp32.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cwchar>
#include <cwctype>
#include <filesystem>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

namespace ksword::features::process_detail {
namespace {

constexpr std::size_t kHotkeyColumnCount = 9;
constexpr std::size_t kHookColumnCount = 10;
constexpr int kToolbarHeight = 30;
constexpr std::uint16_t kAcceleratorEndFlag = 0x0080U; // Last item marker for RT_ACCELERATOR.

// HotkeyCandidate is a background-collected value object; it holds no HWND, HMODULE, or COM interfaces.
struct HotkeyCandidate final {
    std::wstring objectText;
    std::wstring hotkeyText;
    std::wstring processName;
    std::wstring sourceText;
    std::wstring detailText;
    DWORD processId = 0;
    DWORD threadId = 0;
    std::uint32_t hotkeyId = 0;
    std::uint32_t modifiers = 0;
    std::uint32_t virtualKey = 0;
};

// HookCandidate is the value object for the R0 keyboard hook chain; the address is for audit display only.
struct HookCandidate final {
    std::wstring objectText;
    std::wstring typeText;
    std::wstring scopeText;
    std::wstring procedureText;
    std::wstring moduleText;
    std::wstring sourceText;
    std::wstring flagsText;
    std::wstring detailText;
    DWORD processId = 0;
    DWORD threadId = 0;
};

// AcceleratorResourceEntry corresponds to the 8-byte resource layout of PE RT_ACCELERATOR.
struct AcceleratorResourceEntry final {
    std::uint16_t flags = 0;
    std::uint16_t key = 0;
    std::uint16_t commandId = 0;
    std::uint16_t padding = 0;
};

static_assert(sizeof(AcceleratorResourceEntry) == 8U);

// WindowContext stores the target PID, seen HWNDs, and results for various window enumeration callbacks.
struct WindowContext final {
    DWORD processId = 0;
    std::unordered_set<HWND> seen;
    std::vector<HWND> windows;
};

// AcceleratorContext is used by resource enumeration callbacks; all members remain valid during the synchronous callback.
struct AcceleratorContext final {
    HMODULE module = nullptr;
    DWORD processId = 0;
    const std::wstring* processName = nullptr;
    std::vector<HotkeyCandidate>* rows = nullptr;
    std::unordered_set<std::wstring>* dedupe = nullptr;
};

// HexText formats addresses, flags, and IDs into stable hexadecimal text.
std::wstring hexText(std::uint64_t value) {
    std::wostringstream stream;
    stream << L"0x" << std::uppercase << std::hex << value;
    return stream.str();
}

// utf8ToWide: Converts UTF-8 diagnostics returned by ArkDriverClient; retains raw bytes on failure.
std::wstring utf8ToWide(const std::string& text) {
    if (text.empty()) {
        return {};
    }
    const int kLength = ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (kLength <= 0) {
        return { text.begin(), text.end() };
    }
    std::wstring result(static_cast<std::size_t>(kLength), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), result.data(), kLength);
    return result;
}

// appendDiagnostic combines diagnostics from multiple collection sources for display in the corresponding page status bar.
void appendDiagnostic(std::wstring& target, const std::wstring& text) {
    if (text.empty()) {
        return;
    }
    if (!target.empty()) {
        target += L" | ";
    }
    target += text;
}

// modifiersFromHotkeyf converts HOTKEYF bits from WM_GETHOTKEY / .lnk to MOD_*.
std::uint32_t modifiersFromHotkeyf(std::uint32_t value) {
    std::uint32_t result = 0;
    if ((value & HOTKEYF_ALT) != 0U) {
        result |= MOD_ALT;
    }
    if ((value & HOTKEYF_CONTROL) != 0U) {
        result |= MOD_CONTROL;
    }
    if ((value & HOTKEYF_SHIFT) != 0U) {
        result |= MOD_SHIFT;
    }
    return result;
}

// virtualKeyText outputs the human-readable name of the virtual key; unknown keys are retained as hexadecimal VK.
std::wstring virtualKeyText(std::uint32_t virtualKey) {
    if ((virtualKey >= L'A' && virtualKey <= L'Z') ||
        (virtualKey >= L'0' && virtualKey <= L'9')) {
        return std::wstring(1, static_cast<wchar_t>(virtualKey));
    }
    if (virtualKey >= VK_F1 && virtualKey <= VK_F24) {
        return L"F" + std::to_wstring(virtualKey - VK_F1 + 1U);
    }
    const UINT kScanCode = ::MapVirtualKeyW(virtualKey, MAPVK_VK_TO_VSC);
    wchar_t name[80]{};
    if (kScanCode != 0U && ::GetKeyNameTextW(static_cast<LONG>(kScanCode << 16), name, std::size(name)) > 0) {
        return name;
    }
    return L"VK_" + hexText(virtualKey);
}

// formatHotkey displays modifier and virtual key combinations in the Ctrl+Shift+K format.
std::wstring formatHotkey(std::uint32_t modifiers, std::uint32_t virtualKey) {
    std::wstring result;
    const auto kAppend = [&result](const wchar_t* text) {
        if (!result.empty()) {
            result += L"+";
        }
        result += text;
    };
    if ((modifiers & MOD_CONTROL) != 0U) {
        kAppend(L"Ctrl");
    }
    if ((modifiers & MOD_SHIFT) != 0U) {
        kAppend(L"Shift");
    }
    if ((modifiers & MOD_ALT) != 0U) {
        kAppend(L"Alt");
    }
    if ((modifiers & MOD_WIN) != 0U) {
        kAppend(L"Win");
    }
    if (!result.empty()) {
        result += L"+";
    }
    result += virtualKeyText(virtualKey);
    return result;
}

// keyboardStatusText displays the overall enumeration status returned by R0; PARTIAL cannot be hidden as success.
std::wstring keyboardStatusText(std::uint32_t status) {
    switch (status) {
    case KSWORD_ARK_KEYBOARD_ENUM_STATUS_OK: return L"OK";
    case KSWORD_ARK_KEYBOARD_ENUM_STATUS_PARTIAL: return L"Partial";
    case KSWORD_ARK_KEYBOARD_ENUM_STATUS_UNSUPPORTED: return L"Unsupported";
    case KSWORD_ARK_KEYBOARD_ENUM_STATUS_WIN32K_NOT_FOUND: return L"win32k not found";
    case KSWORD_ARK_KEYBOARD_ENUM_STATUS_PATTERN_NOT_FOUND: return L"pattern not found";
    case KSWORD_ARK_KEYBOARD_ENUM_STATUS_SESSION_UNAVAILABLE: return L"session unavailable";
    case KSWORD_ARK_KEYBOARD_ENUM_STATUS_BUFFER_TRUNCATED: return L"buffer truncated";
    case KSWORD_ARK_KEYBOARD_ENUM_STATUS_READ_FAILED: return L"read failed";
    default: return L"Unknown(" + std::to_wstring(status) + L")";
    }
}

// hookScopeText converts the keyboard hook chain scope into human-readable text.
std::wstring hookScopeText(std::uint32_t scope) {
    switch (scope) {
    case KSWORD_ARK_KEYBOARD_HOOK_SCOPE_THREAD: return L"线程链";
    case KSWORD_ARK_KEYBOARD_HOOK_SCOPE_GLOBAL: return L"全局/桌面链";
    default: return L"未知";
    }
}

// hookTypeText converts protocol-supported keyboard hook types to Win32 constant names.
std::wstring hookTypeText(std::uint32_t type) {
    switch (type) {
    case KSWORD_ARK_KEYBOARD_HOOK_TYPE_KEYBOARD: return L"WH_KEYBOARD";
    case KSWORD_ARK_KEYBOARD_HOOK_TYPE_KEYBOARD_LL: return L"WH_KEYBOARD_LL";
    default: return L"WH_" + std::to_wstring(type);
    }
}

// addCandidate deduplicates based on source, object, and key combination to prevent multiple public APIs from reporting the same row.
void addCandidate(
    std::vector<HotkeyCandidate>& rows,
    std::unordered_set<std::wstring>& dedupe,
    HotkeyCandidate candidate) {
    const std::wstring kKey = candidate.sourceText + L"\n" + candidate.objectText + L"\n" +
        std::to_wstring(candidate.hotkeyId) + L"\n" + std::to_wstring(candidate.modifiers) + L"\n" +
        std::to_wstring(candidate.virtualKey);
    if (dedupe.insert(kKey).second) {
        rows.push_back(std::move(candidate));
    }
}

// addWindow re-validates the PID for the HWND in the callback and recursively collects child windows.
void addWindow(WindowContext& context, HWND window) {
    DWORD ownerProcessId = 0;
    if (!window || ::GetWindowThreadProcessId(window, &ownerProcessId) == 0U ||
        ownerProcessId != context.processId || !context.seen.insert(window).second) {
        return;
    }
    context.windows.push_back(window);
    ::EnumChildWindows(window, [](HWND child, LPARAM value) -> BOOL {
        auto* childContext = reinterpret_cast<WindowContext*>(value);
        addWindow(*childContext, child);
        return TRUE;
    }, reinterpret_cast<LPARAM>(&context));
}

// collectTopLevelWindow is the adapter callback for EnumWindows.
BOOL CALLBACK collectTopLevelWindow(HWND window, LPARAM value) {
    auto* context = reinterpret_cast<WindowContext*>(value);
    if (context) {
        addWindow(*context, window);
    }
    return TRUE;
}

// collectThreadWindow is the adapter callback for EnumThreadWindows, used to collect non-top-level windows.
BOOL CALLBACK collectThreadWindow(HWND window, LPARAM value) {
    auto* context = reinterpret_cast<WindowContext*>(value);
    if (context) {
        addWindow(*context, window);
    }
    return TRUE;
}

// collectProcessWindows combines global and thread enumeration to collect all windows visible to the current PID.
std::vector<HWND> collectProcessWindows(DWORD processId) {
    WindowContext context{};
    context.processId = processId;
    ::EnumWindows(collectTopLevelWindow, reinterpret_cast<LPARAM>(&context));
    HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return context.windows;
    }
    THREADENTRY32 thread{};
    thread.dwSize = sizeof(thread);
    if (::Thread32First(snapshot, &thread)) {
        do {
            if (thread.th32OwnerProcessID == processId) {
                ::EnumThreadWindows(thread.th32ThreadID, collectThreadWindow, reinterpret_cast<LPARAM>(&context));
            }
        } while (::Thread32Next(snapshot, &thread));
    }
    ::CloseHandle(snapshot);
    return context.windows;
}

// windowTitle retrieves a single-line window title for hotkey details; an empty title does not prevent record discovery.
std::wstring windowTitle(HWND window) {
    const int kLength = ::GetWindowTextLengthW(window);
    if (kLength <= 0) {
        return {};
    }
    std::wstring result(static_cast<std::size_t>(kLength) + 1U, L'\0');
    ::GetWindowTextW(window, result.data(), static_cast<int>(result.size()));
    result.resize(std::wcslen(result.c_str()));
    return result;
}

// menuMnemonic parses a single menu mnemonic, skipping escaped && in text.
std::optional<wchar_t> menuMnemonic(const std::wstring& text) {
    for (std::size_t index = 0; index + 1U < text.size(); ++index) {
        if (text[index] != L'&') {
            continue;
        }
        if (text[index + 1U] == L'&') {
            ++index;
            continue;
        }
        return static_cast<wchar_t>(std::towupper(text[index + 1U]));
    }
    return std::nullopt;
}

// collectMenuHotkeysRecursive: Recursively scans Alt mnemonics in menus accessible on the current interactive desktop.
void collectMenuHotkeysRecursive(
    HMENU menu,
    HWND window,
    DWORD processId,
    const std::wstring& processName,
    std::vector<HotkeyCandidate>& rows,
    std::unordered_set<std::wstring>& dedupe) {
    const int kCount = menu ? ::GetMenuItemCount(menu) : 0;
    for (int index = 0; index < kCount; ++index) {
        MENUITEMINFOW item{};
        item.cbSize = sizeof(item);
        item.fMask = MIIM_ID | MIIM_SUBMENU;
        if (!::GetMenuItemInfoW(menu, static_cast<UINT>(index), TRUE, &item)) {
            continue;
        }
        wchar_t label[512]{};
        ::GetMenuStringW(menu, static_cast<UINT>(index), label, std::size(label), MF_BYPOSITION);
        const std::wstring kLabelText(label);
        if (const std::optional<wchar_t> kMnemonic = menuMnemonic(kLabelText)) {
            HotkeyCandidate candidate{};
            candidate.objectText = L"HWND=" + hexText(reinterpret_cast<std::uintptr_t>(window));
            candidate.hotkeyText = L"Alt+" + std::wstring(1, *kMnemonic);
            candidate.processName = processName;
            candidate.sourceText = L"菜单快捷键";
            candidate.detailText = kLabelText;
            candidate.processId = processId;
            candidate.hotkeyId = item.wID;
            candidate.modifiers = MOD_ALT;
            candidate.virtualKey = static_cast<std::uint32_t>(*kMnemonic);
            addCandidate(rows, dedupe, std::move(candidate));
        }
        if (item.hSubMenu) {
            collectMenuHotkeysRecursive(item.hSubMenu, window, processId, processName, rows, dedupe);
        }
    }
}

// collectWindowAndMenuHotkeys scans two public R3 sources: WM_GETHOTKEY and menu mnemonics.
void collectWindowAndMenuHotkeys(
    DWORD processId,
    const std::wstring& processName,
    std::vector<HotkeyCandidate>& rows,
    std::unordered_set<std::wstring>& dedupe) {
    for (HWND window : collectProcessWindows(processId)) {
        DWORD_PTR response = 0;
        if (::SendMessageTimeoutW(window, WM_GETHOTKEY, 0, 0, SMTO_ABORTIFHUNG | SMTO_BLOCK, 500, &response) != 0) {
            const WORD kHotkey = static_cast<WORD>(response);
            if (kHotkey != 0U) {
                HotkeyCandidate candidate{};
                candidate.objectText = L"HWND=" + hexText(reinterpret_cast<std::uintptr_t>(window));
                candidate.modifiers = modifiersFromHotkeyf(HIBYTE(kHotkey));
                candidate.virtualKey = LOBYTE(kHotkey);
                candidate.hotkeyText = formatHotkey(candidate.modifiers, candidate.virtualKey);
                candidate.processId = processId;
                candidate.processName = processName;
                candidate.sourceText = L"窗口热键";
                candidate.detailText = windowTitle(window);
                addCandidate(rows, dedupe, std::move(candidate));
            }
        }
        if (HMENU menu = ::GetMenu(window)) {
            collectMenuHotkeysRecursive(menu, window, processId, processName, rows, dedupe);
        }
    }
}

// resourceNameText converts integer or string RT_ACCELERATOR names to table text.
std::wstring resourceNameText(LPWSTR name) {
    if (IS_INTRESOURCE(name)) {
        return L"#" + std::to_wstring(LOWORD(reinterpret_cast<ULONG_PTR>(name)));
    }
    return name ? name : L"?";
}

// enumerateAcceleratorResource decodes PE RT_ACCELERATOR; resource entries must be stepped in 8-byte increments.
BOOL CALLBACK enumerateAcceleratorResource(HMODULE, LPCWSTR, LPWSTR resourceName, LONG_PTR value) {
    auto* context = reinterpret_cast<AcceleratorContext*>(value);
    if (!context || !context->module || !context->processName || !context->rows || !context->dedupe) {
        return TRUE;
    }
    HRSRC resource = ::FindResourceW(context->module, resourceName, RT_ACCELERATOR);
    HGLOBAL handle = resource ? ::LoadResource(context->module, resource) : nullptr;
    const DWORD kBytes = resource ? ::SizeofResource(context->module, resource) : 0;
    const auto* entries = handle ? static_cast<const AcceleratorResourceEntry*>(::LockResource(handle)) : nullptr;
    if (!entries || kBytes < sizeof(AcceleratorResourceEntry)) {
        return TRUE;
    }
    const std::wstring kResourceNameText = resourceNameText(resourceName);
    const std::size_t kCount = kBytes / sizeof(AcceleratorResourceEntry);
    for (std::size_t index = 0; index < kCount; ++index) {
        const AcceleratorResourceEntry& source = entries[index];
        const std::uint16_t kFlags = source.flags & 0x007FU;
        std::uint32_t modifiers = 0;
        if ((kFlags & FCONTROL) != 0U) {
            modifiers |= MOD_CONTROL;
        }
        if ((kFlags & FSHIFT) != 0U) {
            modifiers |= MOD_SHIFT;
        }
        if ((kFlags & FALT) != 0U) {
            modifiers |= MOD_ALT;
        }
        HotkeyCandidate candidate{};
        candidate.objectText = L"RT_ACCELERATOR " + kResourceNameText;
        candidate.hotkeyId = source.commandId;
        candidate.modifiers = modifiers;
        candidate.virtualKey = source.key;
        candidate.hotkeyText = formatHotkey(modifiers, source.key);
        candidate.processId = context->processId;
        candidate.processName = *context->processName;
        candidate.sourceText = L"PE Accelerator";
        candidate.detailText = L"资源=" + kResourceNameText + L" 命令=" + std::to_wstring(source.commandId);
        addCandidate(*context->rows, *context->dedupe, std::move(candidate));
        if ((source.flags & kAcceleratorEndFlag) != 0U) {
            break;
        }
    }
    return TRUE;
}

// collectAcceleratorHotkeys loads the target image only as a data file, without executing its entry point.
void collectAcceleratorHotkeys(
    DWORD processId,
    const std::wstring& processName,
    const std::wstring& imagePath,
    std::vector<HotkeyCandidate>& rows,
    std::unordered_set<std::wstring>& dedupe,
    std::wstring& diagnostic) {
    if (imagePath.empty()) {
        appendDiagnostic(diagnostic, L"未取得映像路径，跳过 PE Accelerator。");
        return;
    }
    HMODULE module = ::LoadLibraryExW(imagePath.c_str(), nullptr, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    if (!module) {
        appendDiagnostic(diagnostic, L"无法读取 PE Accelerator，Win32=" + std::to_wstring(::GetLastError()));
        return;
    }
    AcceleratorContext context{};
    context.module = module;
    context.processId = processId;
    context.processName = &processName;
    context.rows = &rows;
    context.dedupe = &dedupe;
    ::EnumResourceNamesW(module, RT_ACCELERATOR, enumerateAcceleratorResource, reinterpret_cast<LONG_PTR>(&context));
    ::FreeLibrary(module);
}

// equalPath performs case-insensitive normalized path comparison between a shortcut target and the target process image.
bool equalPath(const std::wstring& left, const std::wstring& right) {
    if (left.empty() || right.empty()) {
        return false;
    }
    std::error_code error;
    const std::filesystem::path kLeftPath = std::filesystem::weakly_canonical(left, error);
    error.clear();
    const std::filesystem::path kRightPath = std::filesystem::weakly_canonical(right, error);
    const std::wstring kNormalizedLeft = kLeftPath.empty() ? left : kLeftPath.native();
    const std::wstring kNormalizedRight = kRightPath.empty() ? right : kRightPath.native();
    return ::CompareStringOrdinal(kNormalizedLeft.c_str(), -1, kNormalizedRight.c_str(), -1, TRUE) == CSTR_EQUAL;
}

// shortcutRoots returns the current user and public Desktop/Start Menu scopes, avoiding a full disk scan.
std::vector<std::wstring> shortcutRoots() {
    constexpr std::array<int, 3> kFolders{ CSIDL_DESKTOPDIRECTORY, CSIDL_PROGRAMS, CSIDL_COMMON_PROGRAMS };
    std::vector<std::wstring> roots;
    for (const int kFolder : kFolders) {
        wchar_t path[MAX_PATH]{};
        if (SUCCEEDED(::SHGetFolderPathW(nullptr, kFolder, nullptr, SHGFP_TYPE_CURRENT, path)) && path[0] != L'\0') {
            roots.emplace_back(path);
        }
    }
    return roots;
}

// collectShortcutHotkeys matches .lnk files in the desktop and Start menu, with an enumeration limit to prevent abnormal directories from blocking refresh.
void collectShortcutHotkeys(
    DWORD processId,
    const std::wstring& processName,
    const std::wstring& imagePath,
    std::vector<HotkeyCandidate>& rows,
    std::unordered_set<std::wstring>& dedupe,
    std::wstring& diagnostic) {
    if (imagePath.empty()) {
        return;
    }
    const HRESULT kInit = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    const bool kUninitialize = kInit == S_OK || kInit == S_FALSE;
    if (FAILED(kInit) && kInit != RPC_E_CHANGED_MODE) {
        appendDiagnostic(diagnostic, L"快捷方式 COM 初始化失败。");
        return;
    }
    constexpr std::size_t kMaximumShortcuts = 8000;
    std::size_t examined = 0;
    for (const std::wstring& root : shortcutRoots()) {
        std::error_code error;
        std::filesystem::recursive_directory_iterator iterator(
            root,
            std::filesystem::directory_options::skip_permission_denied,
            error);
        const std::filesystem::recursive_directory_iterator kEnd;
        for (; !error && iterator != kEnd && examined < kMaximumShortcuts; iterator.increment(error)) {
            const std::filesystem::directory_entry& file = *iterator;
            if (file.path().extension() != L".lnk" && file.path().extension() != L".LNK") {
                continue;
            }
            ++examined;
            IShellLinkW* link = nullptr;
            IPersistFile* persist = nullptr;
            HRESULT operation = ::CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&link));
            if (SUCCEEDED(operation) && link) {
                operation = link->QueryInterface(IID_PPV_ARGS(&persist));
            }
            if (SUCCEEDED(operation) && persist) {
                operation = persist->Load(file.path().c_str(), STGM_READ);
            }
            WORD hotkey = 0;
            wchar_t target[MAX_PATH * 4]{};
            WIN32_FIND_DATAW data{};
            if (SUCCEEDED(operation)) {
                link->GetHotkey(&hotkey);
                operation = link->GetPath(target, std::size(target), &data, SLGP_RAWPATH);
            }
            if (SUCCEEDED(operation) && hotkey != 0U && equalPath(target, imagePath)) {
                HotkeyCandidate candidate{};
                candidate.objectText = file.path().native();
                candidate.modifiers = modifiersFromHotkeyf(HIBYTE(hotkey));
                candidate.virtualKey = LOBYTE(hotkey);
                candidate.hotkeyText = formatHotkey(candidate.modifiers, candidate.virtualKey);
                candidate.processId = processId;
                candidate.processName = processName;
                candidate.sourceText = L"快捷方式热键";
                candidate.detailText = target;
                addCandidate(rows, dedupe, std::move(candidate));
            }
            if (persist) {
                persist->Release();
            }
            if (link) {
                link->Release();
            }
        }
        if (examined >= kMaximumShortcuts) {
            appendDiagnostic(diagnostic, L"快捷方式扫描达到 8000 个文件上限。");
            break;
        }
    }
    if (kUninitialize) {
        ::CoUninitialize();
    }
}

// collectR0Hotkeys queries the win32k tagHOTKEY table for the current PID via ArkDriverClient.
void collectR0Hotkeys(
    DWORD processId,
    const std::wstring& processName,
    std::vector<HotkeyCandidate>& rows,
    std::unordered_set<std::wstring>& dedupe,
    std::wstring& diagnostic) {
    const ksword::ark::DriverClient kClient;
    const auto kQuery = kClient.enumerateKeyboardHotkeys(
        processId,
        KSWORD_ARK_KEYBOARD_ENUM_FLAG_FILTER_PROCESS |
            KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_SYSTEM |
            KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_DIAGNOSTICS);
    appendDiagnostic(diagnostic, L"R0 热键=" + keyboardStatusText(kQuery.status) + L"，返回=" +
        std::to_wstring(kQuery.entries.size()));
    if (!kQuery.io.ok) {
        appendDiagnostic(diagnostic, utf8ToWide(kQuery.io.message));
        return;
    }
    for (const auto& source : kQuery.entries) {
        HotkeyCandidate candidate{};
        candidate.objectText = hexText(source.hotkeyObject);
        candidate.hotkeyId = source.hotkeyId;
        candidate.modifiers = source.modifiers;
        candidate.virtualKey = source.virtualKey;
        candidate.hotkeyText = formatHotkey(source.modifiers, source.virtualKey);
        candidate.processId = source.processId;
        candidate.threadId = source.threadId;
        candidate.processName = processName;
        candidate.sourceText = L"R0 RegisterHotKey";
        candidate.detailText = L"Bucket=" + std::to_wstring(source.bucketIndex) +
            L" Depth=" + std::to_wstring(source.depth) +
            L" Flags=" + hexText(source.entryFlags) + L" | " + source.detail;
        addCandidate(rows, dedupe, std::move(candidate));
    }
}

// collectHotkeysForProcess aggregates hotkey sources from the main program's windows, menus, PE resources, .lnk files, and R0.
std::vector<HotkeyCandidate> collectHotkeysForProcess(
    DWORD processId,
    const std::wstring& processName,
    const std::wstring& imagePath,
    std::wstring& diagnostic) {
    std::vector<HotkeyCandidate> rows;
    std::unordered_set<std::wstring> dedupe;
    collectWindowAndMenuHotkeys(processId, processName, rows, dedupe);
    collectAcceleratorHotkeys(processId, processName, imagePath, rows, dedupe, diagnostic);
    collectShortcutHotkeys(processId, processName, imagePath, rows, dedupe, diagnostic);
    collectR0Hotkeys(processId, processName, rows, dedupe, diagnostic);
    std::sort(rows.begin(), rows.end(), [](const HotkeyCandidate& left, const HotkeyCandidate& right) {
        if (left.hotkeyText != right.hotkeyText) {
            return left.hotkeyText < right.hotkeyText;
        }
        if (left.sourceText != right.sourceText) {
            return left.sourceText < right.sourceText;
        }
        return left.objectText < right.objectText;
    });
    return rows;
}

// collectR0KeyboardHooks queries the WH_KEYBOARD and WH_KEYBOARD_LL chains associated with the current PID.
std::vector<HookCandidate> collectR0KeyboardHooks(DWORD processId, std::wstring& diagnostic) {
    std::vector<HookCandidate> rows;
    const ksword::ark::DriverClient kClient;
    const auto kQuery = kClient.enumerateKeyboardHooks(
        processId,
        KSWORD_ARK_KEYBOARD_ENUM_FLAG_FILTER_PROCESS |
            KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_THREAD_HOOKS |
            KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_GLOBAL_HOOKS |
            KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_DIAGNOSTICS);
    appendDiagnostic(diagnostic, L"R0 键盘钩子=" + keyboardStatusText(kQuery.status) + L"，返回=" +
        std::to_wstring(kQuery.entries.size()));
    if (!kQuery.io.ok) {
        appendDiagnostic(diagnostic, utf8ToWide(kQuery.io.message));
        return rows;
    }
    for (const auto& source : kQuery.entries) {
        HookCandidate candidate{};
        candidate.objectText = hexText(source.hookObject);
        candidate.typeText = hookTypeText(source.hookType);
        candidate.scopeText = hookScopeText(source.hookScope);
        candidate.procedureText = hexText(source.procedureAddress) + L" / " + hexText(source.procedureOffset);
        candidate.moduleText = source.moduleBase != 0U
            ? hexText(source.moduleBase)
            : L"ModuleId " + std::to_wstring(source.moduleId);
        candidate.sourceText = source.source == KSWORD_ARK_KEYBOARD_SOURCE_WIN32K_GLOBAL_HOOK_CHAIN
            ? L"R0 全局 Hook 链"
            : L"R0 线程 Hook 链";
        candidate.flagsText = hexText(source.flags);
        candidate.detailText = source.detail;
        candidate.processId = source.processId;
        candidate.threadId = source.threadId;
        rows.push_back(std::move(candidate));
    }
    return rows;
}

// addButtonTooltip installs native hover tooltips for the icon buttons on this page; literal text satisfies the deferred read lifecycle.
void addButtonTooltip(HWND parent, HWND control, const wchar_t* text) {
    if (!parent || !control || !text) {
        return;
    }
    HWND tooltip = ::CreateWindowExW(
        WS_EX_TOPMOST,
        TOOLTIPS_CLASSW,
        nullptr,
        WS_POPUP | TTS_ALWAYSTIP,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        parent,
        nullptr,
        ::GetModuleHandleW(nullptr),
        nullptr);
    if (!tooltip) {
        return;
    }
    TOOLINFOW info{};
    info.cbSize = sizeof(info);
    info.uFlags = TTF_IDISHWND | TTF_SUBCLASS;
    info.hwnd = parent;
    info.uId = reinterpret_cast<UINT_PTR>(control);
    info.lpszText = const_cast<LPWSTR>(text);
    ::SendMessageW(tooltip, TTM_ADDTOOLW, 0, reinterpret_cast<LPARAM>(&info));
}

// resetListColumns: Clears the old column groups of the ListView to allow safe internal column switching for the keyboard.
void resetListColumns(HWND list) {
    if (!list) {
        return;
    }
    HWND header = ListView_GetHeader(list);
    for (int index = header ? Header_GetItemCount(header) - 1 : -1; index >= 0; --index) {
        ListView_DeleteColumn(list, index);
    }
    ListView_DeleteAllItems(list);
}

} // namespace

// createHotkeyTab creates the 'Process Hotkey' page; all read operations are executed within the refresh task.
bool ProcessDetailPage::createHotkeyTab() {
    const TabIndex kTab = TabIndex::kHotkey;
    HWND refresh = addButton(kTab, kHotkeyRefresh, L"↻", 6, 6, 34, kToolbarHeight);
    addButtonTooltip(pages_[static_cast<std::size_t>(kTab)].hwnd, refresh, L"刷新当前进程的窗口、菜单、PE 资源、快捷方式和 R0 热键表");
    addLabel(kTab, kHotkeyStatus, L"● 尚未刷新进程热键", 48, 8, -6, 24);
    if (!addList(kTab, kHotkeyList, 6, 44, -6, -6)) {
        return false;
    }
    rebuildHotkeyList();
    return refresh != nullptr;
}

// createKeyboardTab: Creates the 'Keyboard' page, switching internal tabs between the hotkey table and the keyboard hook chain.
bool ProcessDetailPage::createKeyboardTab() {
    const TabIndex kTab = TabIndex::kKeyboard;
    HWND refresh = addButton(kTab, kKeyboardRefresh, L"↻", 6, 6, 34, kToolbarHeight);
    addButtonTooltip(pages_[static_cast<std::size_t>(kTab)].hwnd, refresh, L"刷新 R0 热键表以及 WH_KEYBOARD/WH_KEYBOARD_LL 钩子链");
    addLabel(kTab, kKeyboardStatus, L"● 尚未刷新键盘证据", 48, 8, -6, 24);
    HWND innerTab = addControl(kTab, 0, WC_TABCONTROLW, L"", WS_TABSTOP | WS_CLIPSIBLINGS,
        kKeyboardInnerTab, 6, 42, -6, 26);
    if (innerTab) {
        TCITEMW hotkeys{};
        hotkeys.mask = TCIF_TEXT;
        hotkeys.pszText = const_cast<LPWSTR>(L"热键");
        ::SendMessageW(innerTab, TCM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&hotkeys));
        TCITEMW hooks{};
        hooks.mask = TCIF_TEXT;
        hooks.pszText = const_cast<LPWSTR>(L"键盘钩子");
        ::SendMessageW(innerTab, TCM_INSERTITEMW, 1, reinterpret_cast<LPARAM>(&hooks));
        ::SendMessageW(innerTab, TCM_SETCURSEL, 0, 0);
    }
    if (!innerTab || !addList(kTab, kKeyboardList, 6, 74, -6, -6)) {
        return false;
    }
    rebuildKeyboardList();
    return refresh != nullptr;
}

// populateHotkeyTab restores the idle prompt when no snapshot exists, preventing display of stale state from destroyed pages.
void ProcessDetailPage::populateHotkeyTab() {
    if (!hotkeyLoaded_) {
        setPageStatus(TabIndex::kHotkey, kHotkeyStatus, L"● 尚未刷新进程热键");
    }
}

// populateKeyboardTab restores the idle prompt when no snapshot has been generated, preventing the display of stale state from a destroyed page.
void ProcessDetailPage::populateKeyboardTab() {
    if (!keyboardLoaded_) {
        setPageStatus(TabIndex::kKeyboard, kKeyboardStatus, L"● 尚未刷新键盘证据");
    }
}

// handleHotkeyCommand: Handles the refresh button command for the process hotkey page.
bool ProcessDetailPage::handleHotkeyCommand(int controlId) {
    if (controlId != kHotkeyRefresh) {
        return false;
    }
    refreshHotkeys();
    return true;
}

// handleKeyboardCommand: Handles the refresh button command for the keyboard page.
bool ProcessDetailPage::handleKeyboardCommand(int controlId) {
    if (controlId != kKeyboardRefresh) {
        return false;
    }
    refreshKeyboard();
    return true;
}

// refreshHotkeys aggregates complete process hotkey auditing in the background; the UI thread only fills in the final snapshot.
void ProcessDetailPage::refreshHotkeys() {
    if (!hotkeyTask_ || hotkeyTask_->running()) {
        return;
    }
    setPageStatus(TabIndex::kHotkey, kHotkeyStatus, L"● 正在后台扫描进程热键...");
    ::EnableWindow(findControl(TabIndex::kHotkey, kHotkeyRefresh), FALSE);
    const DWORD kProcessId = processId_;
    const std::wstring kProcessName = snapshot_.basic.processName;
    const std::wstring kImagePath = snapshot_.basic.imagePath;
    hotkeyTask_->request(
        [kProcessId, kProcessName, kImagePath] {
            ProcessHotkeySnapshot snapshot{};
            const auto kBegin = std::chrono::steady_clock::now();
            std::wstring diagnostic = L"R3 窗口/菜单/PE Accelerator/.lnk";
            const std::wstring kName = kProcessName.empty() ? L"PID " + std::to_wstring(kProcessId) : kProcessName;
            const std::vector<HotkeyCandidate> kRows = collectHotkeysForProcess(kProcessId, kName, kImagePath, diagnostic);
            snapshot.entries.reserve(kRows.size());
            for (const HotkeyCandidate& source : kRows) {
                ProcessHotkeyEntry entry{};
                entry.objectText = source.objectText;
                entry.hotkeyText = source.hotkeyText;
                entry.processName = source.processName;
                entry.sourceText = source.sourceText;
                entry.detailText = source.detailText;
                entry.processId = source.processId;
                entry.threadId = source.threadId;
                entry.hotkeyId = source.hotkeyId;
                entry.modifiers = source.modifiers;
                entry.virtualKey = source.virtualKey;
                snapshot.entries.push_back(std::move(entry));
            }
            const auto kElapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - kBegin).count();
            snapshot.statusText = L"● 刷新完成 " + std::to_wstring(kElapsed) + L" ms | 热键=" +
                std::to_wstring(snapshot.entries.size()) + L" | " + diagnostic;
            snapshot.completed = true;
            return snapshot;
        },
        [this](std::uint64_t, std::optional<ProcessHotkeySnapshot>&& snapshot, std::exception_ptr error) {
            ::EnableWindow(findControl(TabIndex::kHotkey, kHotkeyRefresh), TRUE);
            if (error || !snapshot.has_value()) {
                setPageStatus(TabIndex::kHotkey, kHotkeyStatus, L"● 进程热键后台扫描异常结束。");
                return;
            }
            hotkeyEntries_ = std::move(snapshot->entries);
            hotkeyLoaded_ = snapshot->completed;
            setPageStatus(TabIndex::kHotkey, kHotkeyStatus, snapshot->statusText);
            rebuildHotkeyList();
        });
}

// refreshKeyboard: Generates a same-generation hotkey table and keyboard hook chain in the background, then submits them to the UI at once.
void ProcessDetailPage::refreshKeyboard() {
    if (!keyboardTask_ || keyboardTask_->running()) {
        return;
    }
    setPageStatus(TabIndex::kKeyboard, kKeyboardStatus, L"● 正在后台扫描键盘热键与钩子...");
    ::EnableWindow(findControl(TabIndex::kKeyboard, kKeyboardRefresh), FALSE);
    const DWORD kProcessId = processId_;
    const std::wstring kProcessName = snapshot_.basic.processName;
    const std::wstring kImagePath = snapshot_.basic.imagePath;
    keyboardTask_->request(
        [kProcessId, kProcessName, kImagePath] {
            KeyboardSnapshot snapshot{};
            const auto kBegin = std::chrono::steady_clock::now();
            std::wstring diagnostic = L"R3 窗口/菜单/PE Accelerator/.lnk + R0 win32k";
            const std::wstring kName = kProcessName.empty() ? L"PID " + std::to_wstring(kProcessId) : kProcessName;
            const std::vector<HotkeyCandidate> kHotkeys = collectHotkeysForProcess(kProcessId, kName, kImagePath, diagnostic);
            snapshot.hotkeys.reserve(kHotkeys.size());
            for (const HotkeyCandidate& source : kHotkeys) {
                ProcessHotkeyEntry entry{};
                entry.objectText = source.objectText;
                entry.hotkeyText = source.hotkeyText;
                entry.processName = source.processName;
                entry.sourceText = source.sourceText;
                entry.detailText = source.detailText;
                entry.processId = source.processId;
                entry.threadId = source.threadId;
                entry.hotkeyId = source.hotkeyId;
                entry.modifiers = source.modifiers;
                entry.virtualKey = source.virtualKey;
                snapshot.hotkeys.push_back(std::move(entry));
            }
            const std::vector<HookCandidate> kHooks = collectR0KeyboardHooks(kProcessId, diagnostic);
            snapshot.hooks.reserve(kHooks.size());
            for (const HookCandidate& source : kHooks) {
                KeyboardHookEntry entry{};
                entry.objectText = source.objectText;
                entry.typeText = source.typeText;
                entry.scopeText = source.scopeText;
                entry.procedureText = source.procedureText;
                entry.moduleText = source.moduleText;
                entry.sourceText = source.sourceText;
                entry.flagsText = source.flagsText;
                entry.detailText = source.detailText;
                entry.processId = source.processId;
                entry.threadId = source.threadId;
                snapshot.hooks.push_back(std::move(entry));
            }
            const auto kElapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - kBegin).count();
            snapshot.statusText = L"● 刷新完成 " + std::to_wstring(kElapsed) + L" ms | 热键=" +
                std::to_wstring(snapshot.hotkeys.size()) + L" | 键盘钩子=" +
                std::to_wstring(snapshot.hooks.size()) + L" | " + diagnostic;
            snapshot.completed = true;
            return snapshot;
        },
        [this](std::uint64_t, std::optional<KeyboardSnapshot>&& snapshot, std::exception_ptr error) {
            ::EnableWindow(findControl(TabIndex::kKeyboard, kKeyboardRefresh), TRUE);
            if (error || !snapshot.has_value()) {
                setPageStatus(TabIndex::kKeyboard, kKeyboardStatus, L"● 键盘后台扫描异常结束。");
                return;
            }
            keyboardHotkeyEntries_ = std::move(snapshot->hotkeys);
            keyboardHookEntries_ = std::move(snapshot->hooks);
            keyboardLoaded_ = snapshot->completed;
            setPageStatus(TabIndex::kKeyboard, kKeyboardStatus, snapshot->statusText);
            rebuildKeyboardList();
        });
}

// rebuildHotkeyList generates the complete column group for 'process hotkeys' based on a cached snapshot, supporting a generic copy right-click menu.
void ProcessDetailPage::rebuildHotkeyList() {
    HWND list = findControl(TabIndex::kHotkey, kHotkeyList);
    if (!list) {
        return;
    }
    resetListColumns(list);
    const std::array<std::pair<const wchar_t*, int>, kHotkeyColumnCount> kColumns{{
        { L"对象", 190 }, { L"热键ID", 85 }, { L"热键", 150 }, { L"进程ID", 80 },
        { L"线程ID", 80 }, { L"进程名", 130 }, { L"来源", 145 }, { L"VK/Mod", 130 }, { L"详情", 340 }
    }};
    for (int index = 0; index < static_cast<int>(kColumns.size()); ++index) {
        addListColumn(list, index, kColumns[static_cast<std::size_t>(index)].first, kColumns[static_cast<std::size_t>(index)].second);
    }
    listColumnCounts_[list] = static_cast<int>(kColumns.size());
    listContextColumns_[list] = 0;
    for (std::size_t index = 0; index < hotkeyEntries_.size(); ++index) {
        const ProcessHotkeyEntry& entry = hotkeyEntries_[index];
        addListRow(list, static_cast<int>(index), {
            entry.objectText, entry.hotkeyId == 0U ? L"0" : hexText(entry.hotkeyId), entry.hotkeyText,
            std::to_wstring(entry.processId), entry.threadId == 0U ? L"-" : std::to_wstring(entry.threadId),
            entry.processName, entry.sourceText,
            L"VK=" + hexText(entry.virtualKey) + L" MOD=" + hexText(entry.modifiers), entry.detailText
        }, static_cast<LPARAM>(index + 1U));
    }
}

// rebuildKeyboardList rebuilds the same list based on the current view of the internal TabControl to avoid double-table window compression.
void ProcessDetailPage::rebuildKeyboardList() {
    HWND list = findControl(TabIndex::kKeyboard, kKeyboardList);
    HWND innerTab = findControl(TabIndex::kKeyboard, kKeyboardInnerTab);
    if (!list || !innerTab) {
        return;
    }
    const int kSelected = static_cast<int>(::SendMessageW(innerTab, TCM_GETCURSEL, 0, 0));
    resetListColumns(list);
    if (kSelected == 1) {
        const std::array<std::pair<const wchar_t*, int>, kHookColumnCount> kColumns{{
            { L"对象", 180 }, { L"类型", 120 }, { L"范围", 100 }, { L"进程ID", 80 }, { L"线程ID", 80 },
            { L"函数/偏移", 180 }, { L"模块", 150 }, { L"来源", 140 }, { L"Flags", 100 }, { L"详情", 320 }
        }};
        for (int index = 0; index < static_cast<int>(kColumns.size()); ++index) {
            addListColumn(list, index, kColumns[static_cast<std::size_t>(index)].first, kColumns[static_cast<std::size_t>(index)].second);
        }
        listColumnCounts_[list] = static_cast<int>(kColumns.size());
        for (std::size_t index = 0; index < keyboardHookEntries_.size(); ++index) {
            const KeyboardHookEntry& entry = keyboardHookEntries_[index];
            addListRow(list, static_cast<int>(index), {
                entry.objectText, entry.typeText, entry.scopeText, std::to_wstring(entry.processId),
                entry.threadId == 0U ? L"-" : std::to_wstring(entry.threadId), entry.procedureText,
                entry.moduleText, entry.sourceText, entry.flagsText, entry.detailText
            }, static_cast<LPARAM>(index + 1U));
        }
    } else {
        const std::array<std::pair<const wchar_t*, int>, kHotkeyColumnCount> kColumns{{
            { L"对象", 190 }, { L"热键ID", 85 }, { L"热键", 150 }, { L"进程ID", 80 },
            { L"线程ID", 80 }, { L"进程名", 130 }, { L"来源", 145 }, { L"VK/Mod", 130 }, { L"详情", 340 }
        }};
        for (int index = 0; index < static_cast<int>(kColumns.size()); ++index) {
            addListColumn(list, index, kColumns[static_cast<std::size_t>(index)].first, kColumns[static_cast<std::size_t>(index)].second);
        }
        listColumnCounts_[list] = static_cast<int>(kColumns.size());
        for (std::size_t index = 0; index < keyboardHotkeyEntries_.size(); ++index) {
            const ProcessHotkeyEntry& entry = keyboardHotkeyEntries_[index];
            addListRow(list, static_cast<int>(index), {
                entry.objectText, entry.hotkeyId == 0U ? L"0" : hexText(entry.hotkeyId), entry.hotkeyText,
                std::to_wstring(entry.processId), entry.threadId == 0U ? L"-" : std::to_wstring(entry.threadId),
                entry.processName, entry.sourceText,
                L"VK=" + hexText(entry.virtualKey) + L" MOD=" + hexText(entry.modifiers), entry.detailText
            }, static_cast<LPARAM>(index + 1U));
        }
    }
    listContextColumns_[list] = 0;
}

} // namespace Ksword::Features::process_detail
