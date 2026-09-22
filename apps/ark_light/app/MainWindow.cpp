#include "MainWindow.h"

#include "../core/Common.h"
#include "../core/DriverService.h"
#include "../core/Privilege.h"
#include "../core/WorkspaceConfig.h"
#include "../features/FeatureRegistry.h"
#include "../features/file/FileFeature.h"
#include "../features/handle/HandleFeature.h"
#include "../features/memory/MemoryFeature.h"
#include "../features/monitor/MonitorFeature.h"
#include "../features/network/NetworkFeature.h"
#include "../features/process/ProcessFeature.h"
#include "../features/registry/RegistryFeature.h"
#include "../features/window/WindowFeature.h"
#include "../ui/Controls.h"
#include "../ui/EntityNavigation.h"
#include "../ui/EvidenceSession.h"
#include "../ui/EvidenceSessionView.h"
#include "../ui/ExportUtil.h"
#include "../ui/Theme.h"
#include "../resource.h"

#include <algorithm>
#include <commctrl.h>
#include <cstdint>
#include <tlhelp32.h>
#include <cwctype>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

namespace ksword::app {
namespace {
constexpr wchar_t kMainWindowClass[] = L"KswordARKLight.MainWindow";
constexpr int kTopmostMenuId = 1000;
constexpr int kPrivilegeMenuId = 1001;
constexpr int kDriverMenuId = 1002;
constexpr int kCommandEditId = 1003;
constexpr int kStatusTextId = 1004;
constexpr int kNavigationPaletteMenuId = 1005;
constexpr int kEvidenceInspectorMenuId = 1099;
constexpr int kEvidenceJsonPrivacyMenuId = 1100;
constexpr int kEvidenceJsonRawMenuId = 1101;
constexpr int kEvidenceTsvPrivacyMenuId = 1102;
constexpr int kEvidenceDiffMenuId = 1103;
constexpr int kEvidenceClearMenuId = 1104;
constexpr int kCommandEditWidth = 320;
constexpr int kCommandEditHeight = 22;
constexpr int kCommandEditMenuGap = 8;
constexpr int kNavigationPaletteWidth = 560;
constexpr int kNavigationPaletteHeight = 440;
constexpr int kStatusHeight = 18;
constexpr int kWindowMenuDockBaseId = 42000;
constexpr int kProcessModuleCommandId = 40001;
constexpr int kMemoryModuleCommandId = 40002;
constexpr int kFileModuleCommandId = 40003;
constexpr int kMonitorModuleCommandId = 40006;
constexpr int kWindowModuleCommandId = 40008;
constexpr int kRegistryModuleCommandId = 40010;
constexpr int kNetworkModuleCommandId = 40011;
constexpr int kHandleModuleCommandId = 40012;
constexpr UINT kMsgQueryDriverStatus = WM_APP + 101;
constexpr UINT kMsgDockActivated = WM_APP + 102;
constexpr UINT kMsgMaterializeDock = WM_APP + 103;
constexpr wchar_t kWorkspaceRegistryPath[] = L"Software\\KSwordDEV\\KswordARKLight\\Workspace";
constexpr wchar_t kWorkspaceRegistryValue[] = L"State";

// registerMainWindowClass registers the top-level shell class. Input is the
// module instance; processing installs icon/cursor/background metadata; output
// is true after RegisterClassW succeeds or the class already exists.
bool registerMainWindowClass(HINSTANCE instance) {
    WNDCLASSW wc{};
    wc.lpfnWndProc = MainWindow::wndProc;
    wc.hInstance = instance;
    wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = ksword::ui::appTheme().windowBrush();
    wc.hIcon = ::LoadIconW(instance, MAKEINTRESOURCEW(IDI_KSWORDARKLIGHT_APP));
    wc.lpszClassName = kMainWindowClass;
    if (::RegisterClassW(&wc)) {
        return true;
    }
    return ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
}

// centerWindowRect returns a centered rectangle in the primary work area. Inputs
// are requested dimensions; output is the rectangle used for CreateWindowExW.
RECT centerWindowRect(int width, int height) {
    RECT work{};
    ::SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
    const int kX = work.left + ((work.right - work.left) - width) / 2;
    const int kY = work.top + ((work.bottom - work.top) - height) / 2;
    return { kX, kY, kX + width, kY + height };
}

// trimWhitespace removes leading/trailing Unicode whitespace from one command.
// Input is raw edit text; processing keeps interior spacing intact; output is
// used only to decide whether Enter should launch cmd.exe.
std::wstring trimWhitespace(const std::wstring& value) {
    std::size_t first = 0;
    while (first < value.size() && std::iswspace(value[first])) {
        ++first;
    }
    std::size_t last = value.size();
    while (last > first && std::iswspace(value[last - 1])) {
        --last;
    }
    return value.substr(first, last - first);
}

std::wstring lowerText(std::wstring value) {
    for (wchar_t& character : value) {
        character = static_cast<wchar_t>(std::towlower(character));
    }
    return value;
}

// clampWorkspaceNormalRect keeps a persisted outer screen rectangle on an
// available monitor. It deliberately operates on GetWindowRect coordinates,
// never WINDOWPLACEMENT::rcNormalPosition work-area coordinates.
bool clampWorkspaceNormalRect(const ksword::core::WorkspaceNormalRect& saved, RECT* rectOut) {
    if (!rectOut || !ksword::core::isWorkspaceNormalRectValid(saved)) {
        return false;
    }

    RECT candidate{
        static_cast<LONG>(saved.left),
        static_cast<LONG>(saved.top),
        static_cast<LONG>(saved.right),
        static_cast<LONG>(saved.bottom)
    };
    const HMONITOR kMonitor = ::MonitorFromRect(&candidate, MONITOR_DEFAULTTONEAREST);
    MONITORINFO monitorInfo{};
    monitorInfo.cbSize = sizeof(monitorInfo);
    if (!kMonitor || !::GetMonitorInfoW(kMonitor, &monitorInfo)) {
        return false;
    }

    const std::int64_t kWorkWidth = static_cast<std::int64_t>(monitorInfo.rcWork.right) - monitorInfo.rcWork.left;
    const std::int64_t kWorkHeight = static_cast<std::int64_t>(monitorInfo.rcWork.bottom) - monitorInfo.rcWork.top;
    const std::int64_t kSavedWidth = static_cast<std::int64_t>(saved.right) - saved.left;
    const std::int64_t kSavedHeight = static_cast<std::int64_t>(saved.bottom) - saved.top;
    if (kWorkWidth <= 0 || kWorkHeight <= 0 || kSavedWidth <= 0 || kSavedHeight <= 0) {
        return false;
    }

    const std::int64_t kWidth = (std::min)(kSavedWidth, kWorkWidth);
    const std::int64_t kHeight = (std::min)(kSavedHeight, kWorkHeight);
    const std::int64_t kLeft = (std::clamp)(
        static_cast<std::int64_t>(saved.left),
        static_cast<std::int64_t>(monitorInfo.rcWork.left),
        static_cast<std::int64_t>(monitorInfo.rcWork.right) - kWidth);
    const std::int64_t kTop = (std::clamp)(
        static_cast<std::int64_t>(saved.top),
        static_cast<std::int64_t>(monitorInfo.rcWork.top),
        static_cast<std::int64_t>(monitorInfo.rcWork.bottom) - kHeight);
    *rectOut = {
        static_cast<LONG>(kLeft),
        static_cast<LONG>(kTop),
        static_cast<LONG>(kLeft + kWidth),
        static_cast<LONG>(kTop + kHeight)
    };
    return rectOut->right > rectOut->left && rectOut->bottom > rectOut->top;
}

ksword::core::WorkspaceConfig loadWorkspaceConfig() {
    HKEY key = nullptr;
    if (::RegOpenKeyExW(HKEY_CURRENT_USER, kWorkspaceRegistryPath, 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) {
        return {};
    }

    DWORD type = 0;
    DWORD byteCount = 0;
    LONG status = ::RegQueryValueExW(key, kWorkspaceRegistryValue, nullptr, &type, nullptr, &byteCount);
    if (status != ERROR_SUCCESS || type != REG_BINARY || byteCount != ksword::core::kWorkspaceConfigBinarySize) {
        ::RegCloseKey(key);
        return {};
    }

    ksword::core::WorkspaceConfigBinary bytes{};
    byteCount = static_cast<DWORD>(bytes.size());
    status = ::RegQueryValueExW(key, kWorkspaceRegistryValue, nullptr, &type, bytes.data(), &byteCount);
    ::RegCloseKey(key);
    if (status != ERROR_SUCCESS || type != REG_BINARY || byteCount != bytes.size()) {
        return {};
    }

    const ksword::core::WorkspaceConfigDecodeResult kDecoded = ksword::core::deserializeWorkspaceConfig(bytes);
    return kDecoded.valid() ? kDecoded.config : ksword::core::WorkspaceConfig{};
}

void storeWorkspaceConfig(const ksword::core::WorkspaceConfig& config) {
    HKEY key = nullptr;
    if (::RegCreateKeyExW(HKEY_CURRENT_USER, kWorkspaceRegistryPath, 0, nullptr, REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE, nullptr, &key, nullptr) != ERROR_SUCCESS) {
        return;
    }

    const ksword::core::WorkspaceConfigBinary kBytes = ksword::core::serializeWorkspaceConfig(config);
    ::RegSetValueExW(key, kWorkspaceRegistryValue, 0, REG_BINARY, kBytes.data(), static_cast<DWORD>(kBytes.size()));
    ::RegCloseKey(key);
}

bool allowsPersistedMaximize(const int showCommand) noexcept {
    return showCommand == SW_SHOWNORMAL || showCommand == SW_SHOW || showCommand == SW_SHOWDEFAULT;
}

bool isEditableTextControl(const HWND hwnd) {
    if (!hwnd) {
        return false;
    }
    wchar_t className[32]{};
    if (::GetClassNameW(hwnd, className, static_cast<int>(sizeof(className) / sizeof(className[0]))) <= 0) {
        return false;
    }
    return ::lstrcmpiW(className, L"EDIT") == 0 ||
        ::lstrcmpiW(className, L"RICHEDIT20W") == 0 ||
        ::lstrcmpiW(className, L"RICHEDIT50W") == 0;
}

bool isMainWindowDescendant(const HWND root, const HWND hwnd) {
    return root && hwnd && (root == hwnd || ::IsChild(root, hwnd));
}

DWORD processIdForThread(const DWORD threadId) {
    HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }
    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    DWORD processId = 0;
    if (::Thread32First(snapshot, &entry)) {
        do {
            if (entry.th32ThreadID == threadId) {
                processId = entry.th32OwnerProcessID;
                break;
            }
        } while (::Thread32Next(snapshot, &entry));
    }
    ::CloseHandle(snapshot);
    return processId;
}

std::wstring hexIdentifier(const std::uint64_t value) {
    std::wostringstream output;
    output << L"0x" << std::hex << std::uppercase << value;
    return output.str();
}
} // namespace

MainWindow::MainWindow()
    : instance_(nullptr), hwnd_(nullptr), commandEdit_(nullptr), navigationPalette_(nullptr), statusText_(nullptr),
      mainMenu_(nullptr), windowMenu_(nullptr), evidenceMenu_(nullptr),
      commandEditProc_(nullptr), navigationPaletteProc_(nullptr),
      dockManager_(std::make_unique<ksword::docking::DockManager>()) {}

MainWindow::~MainWindow() = default;

bool MainWindow::create(HINSTANCE instance, int showCommand) {
    instance_ = instance;
    ksword::ui::appTheme().ensure();
    ksword::ui::registerControlClasses(instance);
    ksword::docking::registerDockingClasses(instance);
    if (!registerMainWindowClass(instance)) {
        return false;
    }

    const ksword::core::WorkspaceConfig kRestoredWorkspace = loadWorkspaceConfig();
    RECT rect = centerWindowRect(1240, 780);
    if (kRestoredWorkspace.hasNormalRect) {
        RECT restoredRect{};
        if (clampWorkspaceNormalRect(kRestoredWorkspace.normalRect, &restoredRect)) {
            rect = restoredRect;
        }
    }
    lastNormalScreenRect_ = rect;
    hasLastNormalScreenRect_ = true;
    restoredModuleCommandId_ = kRestoredWorkspace.activeCommandId;
    restoreMaximized_ = kRestoredWorkspace.maximized;
    wasMaximized_ = restoreMaximized_;
    hwnd_ = ::CreateWindowExW(0, kMainWindowClass, L"KswordARKLight", WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top,
        nullptr, nullptr, instance, this);
    if (!hwnd_) {
        return false;
    }

    const int kEffectiveShowCommand = restoreMaximized_ && allowsPersistedMaximize(showCommand)
        ? SW_SHOWMAXIMIZED
        : showCommand;
    ::ShowWindow(hwnd_, kEffectiveShowCommand);
    ::UpdateWindow(hwnd_);
    return true;
}

int MainWindow::run() {
    MSG msg{};
    while (::GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if (msg.message == WM_KEYDOWN && msg.wParam == static_cast<WPARAM>(L'K') &&
            (::GetKeyState(VK_CONTROL) & 0x8000) != 0) {
            const HWND kFocus = ::GetFocus();
            if (isMainWindowDescendant(hwnd_, kFocus) && !isEditableTextControl(kFocus)) {
                showNavigationPalette();
                continue;
            }
        }
        ::TranslateMessage(&msg);
        ::DispatchMessageW(&msg);
    }
    return static_cast<int>(msg.wParam);
}

LRESULT CALLBACK MainWindow::wndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    MainWindow* window = reinterpret_cast<MainWindow*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        window = cs ? static_cast<MainWindow*>(cs->lpCreateParams) : nullptr;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(window));
        if (window) {
            // CreateWindowExW sends WM_NCCREATE/WM_CREATE before it returns to
            // mainWindow::create(). Store the real HWND immediately so all
            // child controls and dock hosts created during WM_CREATE receive a
            // valid parent window and become visible.
            window->hwnd_ = hwnd;
        }
    }
    if (window) {
        return window->handleMessage(hwnd, msg, wParam, lParam);
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK MainWindow::commandEditProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    MainWindow* window = reinterpret_cast<MainWindow*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    WNDPROC originalProc = window ? window->commandEditProc_ : nullptr;
    switch (msg) {
    case WM_GETDLGCODE:
        return DLGC_WANTALLKEYS;
    case WM_KEYDOWN:
        if (wParam == VK_RETURN) {
            if (window) {
                window->executeCommandInput();
            }
            return 0;
        }
        break;
    case WM_CHAR:
        if (wParam == VK_RETURN || wParam == L'\r') {
            return 0;
        }
        break;
    case WM_NCDESTROY:
        if (window && window->commandEditProc_) {
            ::SetWindowLongPtrW(hwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(window->commandEditProc_));
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            originalProc = window->commandEditProc_;
            window->commandEditProc_ = nullptr;
            window->commandEdit_ = nullptr;
        }
        break;
    default:
        break;
    }
    return originalProc ? ::CallWindowProcW(originalProc, hwnd, msg, wParam, lParam) : ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK MainWindow::navigationPaletteProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    MainWindow* window = reinterpret_cast<MainWindow*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    WNDPROC originalProc = window ? window->navigationPaletteProc_ : nullptr;
    switch (msg) {
    case WM_GETDLGCODE:
        return DLGC_WANTALLKEYS;
    case WM_KEYDOWN:
        if (wParam == VK_RETURN) {
            if (window) {
                window->activateNavigationPaletteSelection();
            }
            return 0;
        }
        if (wParam == VK_ESCAPE) {
            if (window) {
                window->hideNavigationPalette(true);
            }
            return 0;
        }
        break;
    case WM_LBUTTONDBLCLK: {
        const LRESULT kResult = originalProc
            ? ::CallWindowProcW(originalProc, hwnd, msg, wParam, lParam)
            : ::DefWindowProcW(hwnd, msg, wParam, lParam);
        if (window) {
            window->activateNavigationPaletteSelection();
        }
        return kResult;
    }
    case WM_KILLFOCUS:
        if (window) {
            window->hideNavigationPalette(false);
        }
        break;
    case WM_NCDESTROY:
        if (window && window->navigationPalette_ == hwnd && window->navigationPaletteProc_) {
            ::SetWindowLongPtrW(hwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(window->navigationPaletteProc_));
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            originalProc = window->navigationPaletteProc_;
            window->navigationPaletteProc_ = nullptr;
            window->navigationPalette_ = nullptr;
        }
        break;
    default:
        break;
    }
    return originalProc ? ::CallWindowProcW(originalProc, hwnd, msg, wParam, lParam) : ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

LRESULT MainWindow::handleMessage(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE:
        if (!driverLease_.acquire()) {
            ::OutputDebugStringW(L"[KswordARKLight] Driver lease registration unavailable; automatic driver stop is disabled for safety.\r\n");
        }
        createMenuBar();
        createCommandInput();
        createChildControls();
        createModuleDocks();
        refreshPrivilegeText();
        refreshDriverText(driverStatus_);
        enableStartupPrivileges();
        refreshPrivilegeText();
        ::PostMessageW(hwnd_, kMsgQueryDriverStatus, 0, 0);
        layout();
        return 0;
    case kMsgQueryDriverStatus:
        queryDriverStatusDeferred();
        return 0;
    case kMsgDockActivated:
        queueDockMaterialization(static_cast<int>(wParam));
        return 0;
    case kMsgMaterializeDock:
        materializeDockForDockIndex(static_cast<int>(wParam));
        return 0;
    case ksword::ui::kEntityNavigationMessage:
        if (lParam != 0) {
            return routeNavigation(*reinterpret_cast<const ksword::core::NavigationRequest*>(lParam)) ? 1 : 0;
        }
        return 0;
    case WM_SIZE:
        if (wParam == SIZE_MAXIMIZED) {
            wasMaximized_ = true;
        } else if (wParam == SIZE_RESTORED) {
            wasMaximized_ = false;
            captureNormalWindowRect();
        }
        positionCommandInput();
        layout();
        return 0;
    case WM_MOVE:
        captureNormalWindowRect();
        positionCommandInput();
        return 0;
    case WM_SETTINGCHANGE:
        ksword::ui::refreshSystemUiFont();
        ksword::ui::setWindowFontRecursive(hwnd_);
        if (navigationPalette_) {
            ::SendMessageW(navigationPalette_, WM_SETFONT, reinterpret_cast<WPARAM>(ksword::ui::systemUiFont()), TRUE);
            ::InvalidateRect(navigationPalette_, nullptr, TRUE);
        }
        refreshTopmostMenuText();
        positionCommandInput();
        layout();
        ::InvalidateRect(hwnd_, nullptr, TRUE);
        return 0;
    case WM_COMMAND: {
        const int kId = LOWORD(wParam);
        if (kId >= kWindowMenuDockBaseId && kId < kWindowMenuDockBaseId + static_cast<int>(modules_.size())) {
            toggleModuleDock(kId - kWindowMenuDockBaseId);
            return 0;
        }
        if (kId == kTopmostMenuId) {
            toggleTopmost();
            return 0;
        }
        if (kId == kPrivilegeMenuId) {
            handleUiAccessButtonClicked();
            return 0;
        }
        if (kId == kDriverMenuId) {
            installDriverFromButton();
            return 0;
        }
        if (kId == kNavigationPaletteMenuId) {
            showNavigationPalette();
            return 0;
        }
        if (kId == kEvidenceInspectorMenuId) {
            if (!ksword::ui::showEvidenceSessionInspector(hwnd_) && statusText_) {
                ::SetWindowTextW(statusText_, L"证据会话检查器无法创建。");
            }
            return 0;
        }
        if (kId >= kEvidenceJsonPrivacyMenuId && kId <= kEvidenceClearMenuId) {
            exportEvidence(kId);
            return 0;
        }
        break;
    }
    case WM_INITMENU:
        if (reinterpret_cast<HMENU>(wParam) == mainMenu_) {
            refreshTopmostMenuText();
            positionCommandInput();
            return 0;
        }
        break;
    case WM_INITMENUPOPUP:
        if (reinterpret_cast<HMENU>(wParam) == windowMenu_) {
            rebuildWindowMenuChecks();
            return 0;
        }
        break;
    case WM_CTLCOLORSTATIC: {
        HDC dc = reinterpret_cast<HDC>(wParam);
        ::SetBkMode(dc, TRANSPARENT);
        ::SetTextColor(dc, ksword::ui::appTheme().textColor);
        return reinterpret_cast<LRESULT>(ksword::ui::appTheme().windowBrush());
    }
    case WM_CTLCOLORLISTBOX:
        if (reinterpret_cast<HWND>(lParam) == navigationPalette_) {
            HDC dc = reinterpret_cast<HDC>(wParam);
            ::SetBkMode(dc, OPAQUE);
            ::SetBkColor(dc, ksword::ui::appTheme().panelColor);
            ::SetTextColor(dc, ksword::ui::appTheme().textColor);
            return reinterpret_cast<LRESULT>(ksword::ui::appTheme().panelBrush());
        }
        break;
    case WM_PAINT: {
        PAINTSTRUCT ps{};
        HDC dc = ::BeginPaint(hwnd, &ps);
        paint(dc);
        ::EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_DESTROY:
        persistWorkspaceState();
        stopDriverOnExit();
        if (navigationPalette_) {
            ::DestroyWindow(navigationPalette_);
            navigationPalette_ = nullptr;
        }
        if (commandEdit_) {
            ::DestroyWindow(commandEdit_);
            commandEdit_ = nullptr;
        }
        ::PostQuitMessage(0);
        return 0;
    default:
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

void MainWindow::createMenuBar() {
    modules_ = ksword::features::getModuleDescriptors();
    mainMenu_ = ::CreateMenu();
    windowMenu_ = ::CreatePopupMenu();
    evidenceMenu_ = ::CreatePopupMenu();
    if (!mainMenu_ || !windowMenu_ || !evidenceMenu_) {
        return;
    }

    for (int index = 0; index < static_cast<int>(modules_.size()); ++index) {
        ::AppendMenuW(windowMenu_, MF_STRING | MF_CHECKED, kWindowMenuDockBaseId + index, modules_[index].title.c_str());
    }
    ::AppendMenuW(mainMenu_, MF_POPUP, reinterpret_cast<UINT_PTR>(windowMenu_), L"窗口");
    ::AppendMenuW(mainMenu_, MF_STRING, kNavigationPaletteMenuId, L"导航");
    ::AppendMenuW(evidenceMenu_, MF_STRING, kEvidenceInspectorMenuId, L"查看证据会话...");
    ::AppendMenuW(evidenceMenu_, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(evidenceMenu_, MF_STRING, kEvidenceJsonPrivacyMenuId, L"导出 JSON（隐私脱敏）...");
    ::AppendMenuW(evidenceMenu_, MF_STRING, kEvidenceJsonRawMenuId, L"导出 JSON（完整）...");
    ::AppendMenuW(evidenceMenu_, MF_STRING, kEvidenceTsvPrivacyMenuId, L"导出 TSV（隐私脱敏）...");
    ::AppendMenuW(evidenceMenu_, MF_STRING, kEvidenceDiffMenuId, L"导出最近两次差异...");
    ::AppendMenuW(evidenceMenu_, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(evidenceMenu_, MF_STRING, kEvidenceClearMenuId, L"清空证据会话");
    ::AppendMenuW(mainMenu_, MF_POPUP, reinterpret_cast<UINT_PTR>(evidenceMenu_), L"证据");
    MENUITEMINFOW topmostItem{};
    topmostItem.cbSize = sizeof(topmostItem);
    topmostItem.fMask = MIIM_FTYPE | MIIM_ID | MIIM_STRING;
    topmostItem.fType = MFT_STRING | MFT_RIGHTJUSTIFY;
    topmostItem.wID = kTopmostMenuId;
    topmostItem.dwTypeData = const_cast<LPWSTR>(L"置顶");
    ::InsertMenuItemW(mainMenu_, ::GetMenuItemCount(mainMenu_), TRUE, &topmostItem);
    ::AppendMenuW(mainMenu_, MF_STRING, kPrivilegeMenuId, L"UIAccess");
    ::AppendMenuW(mainMenu_, MF_STRING, kDriverMenuId, L"R0");
    ::SetMenu(hwnd_, mainMenu_);
    refreshTopmostMenuText();
    ::DrawMenuBar(hwnd_);
}

void MainWindow::createCommandInput() {
    // The native menu bar is not a child-window container. Use an owned popup
    // edit instead so the command box can sit visually on the menu row without
    // replacing the existing HMENU-based shell.
    commandEdit_ = ::CreateWindowExW(WS_EX_TOOLWINDOW, L"EDIT", L"",
        WS_POPUP | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
        0, 0, kCommandEditWidth, kCommandEditHeight,
        hwnd_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kCommandEditId)), instance_, nullptr);
    if (!commandEdit_) {
        return;
    }

    ::SendMessageW(commandEdit_, WM_SETFONT, reinterpret_cast<WPARAM>(ksword::ui::systemUiFont()), TRUE);
    ::SendMessageW(commandEdit_, EM_SETCUEBANNER, FALSE,
        reinterpret_cast<LPARAM>(L"模块 / pid 1234 / !命令"));
    ::SetWindowLongPtrW(commandEdit_, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this));
    commandEditProc_ = reinterpret_cast<WNDPROC>(
        ::SetWindowLongPtrW(commandEdit_, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(&MainWindow::commandEditProc)));
    positionCommandInput();
}

void MainWindow::rebuildNavigationPalette() {
    navigationPaletteEntries_.clear();
    navigationPaletteEntries_.reserve(modules_.size() + 9U);
    for (int moduleIndex = 0; moduleIndex < static_cast<int>(modules_.size()); ++moduleIndex) {
        const ksword::ui::ModuleDescriptor& module = modules_[moduleIndex];
        NavigationPaletteEntry entry;
        entry.action = NavigationPaletteAction::kModule;
        entry.moduleIndex = moduleIndex;
        entry.displayText = L"模块： " + module.title + L"  —  " + module.summary;
        navigationPaletteEntries_.push_back(std::move(entry));
    }

    const struct TemplateDescriptor {
        const wchar_t* command;
        const wchar_t* description;
    } kTemplates[] = {
        { L"pid <PID>", L"打开当前进程详细信息" },
        { L"tid <TID>", L"按线程 ID 打开所属进程详细信息" },
        { L"mem <PID>", L"定位到该进程的内存操作" },
        { L"hwnd <HWND>", L"在窗口模块查询窗口句柄" },
        { L"net <PID>", L"筛选该进程的网络连接" },
        { L"handle <PID>", L"筛选该进程的句柄表" },
        { L"etw <PID>", L"定位到该进程的 ETW 监控" },
        { L"file <路径>", L"在文件模块导航到路径" },
        { L"reg <注册表路径>", L"在注册表模块导航到键" },
    };
    for (const TemplateDescriptor& descriptor : kTemplates) {
        NavigationPaletteEntry entry;
        entry.action = NavigationPaletteAction::kTemplate;
        entry.commandTemplate = descriptor.command;
        entry.displayText = L"命令模板： " + entry.commandTemplate + L"  —  " + descriptor.description;
        navigationPaletteEntries_.push_back(std::move(entry));
    }

    if (!navigationPalette_ || !::IsWindow(navigationPalette_)) {
        return;
    }
    ::SendMessageW(navigationPalette_, LB_RESETCONTENT, 0, 0);
    for (std::size_t index = 0; index < navigationPaletteEntries_.size(); ++index) {
        const LRESULT kListIndex = ::SendMessageW(navigationPalette_, LB_ADDSTRING, 0,
            reinterpret_cast<LPARAM>(navigationPaletteEntries_[index].displayText.c_str()));
        if (kListIndex != LB_ERR && kListIndex != LB_ERRSPACE) {
            ::SendMessageW(navigationPalette_, LB_SETITEMDATA, static_cast<WPARAM>(kListIndex),
                static_cast<LPARAM>(index));
        }
    }
}

void MainWindow::showNavigationPalette() {
    if (!hwnd_) {
        return;
    }
    if (!navigationPalette_ || !::IsWindow(navigationPalette_)) {
        HWND palette = ::CreateWindowExW(WS_EX_TOOLWINDOW, WC_LISTBOXW, L"",
            WS_POPUP | WS_BORDER | WS_VSCROLL | LBS_NOTIFY | LBS_NOINTEGRALHEIGHT,
            0, 0, kNavigationPaletteWidth, kNavigationPaletteHeight,
            hwnd_, nullptr, instance_, nullptr);
        if (!palette) {
            if (statusText_) {
                ::SetWindowTextW(statusText_, L"导航面板无法创建。");
            }
            return;
        }
        navigationPalette_ = palette;
        ::SendMessageW(navigationPalette_, WM_SETFONT, reinterpret_cast<WPARAM>(ksword::ui::systemUiFont()), TRUE);
        ::SetWindowLongPtrW(navigationPalette_, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this));
        navigationPaletteProc_ = reinterpret_cast<WNDPROC>(
            ::SetWindowLongPtrW(navigationPalette_, GWLP_WNDPROC,
                reinterpret_cast<LONG_PTR>(&MainWindow::navigationPaletteProc)));
    }

    rebuildNavigationPalette();
    if (navigationPaletteEntries_.empty()) {
        return;
    }
    ::SendMessageW(navigationPalette_, LB_SETCURSEL, 0, 0);

    RECT anchor{};
    if (!commandEdit_ || !::GetWindowRect(commandEdit_, &anchor)) {
        ::GetWindowRect(hwnd_, &anchor);
    }
    HMONITOR monitor = ::MonitorFromWindow(hwnd_, MONITOR_DEFAULTTONEAREST);
    MONITORINFO monitorInfo{};
    monitorInfo.cbSize = sizeof(monitorInfo);
    if (!::GetMonitorInfoW(monitor, &monitorInfo)) {
        ::SystemParametersInfoW(SPI_GETWORKAREA, 0, &monitorInfo.rcWork, 0);
    }
    const RECT kWork = monitorInfo.rcWork;
    const int kWorkLeft = static_cast<int>(kWork.left);
    const int kWorkTop = static_cast<int>(kWork.top);
    const int kWorkRight = static_cast<int>(kWork.right);
    const int kWorkBottom = static_cast<int>(kWork.bottom);
    const int kWidth = (std::min)(kNavigationPaletteWidth, (std::max)(1, kWorkRight - kWorkLeft - 16));
    const int kHeight = (std::min)(kNavigationPaletteHeight, (std::max)(1, kWorkBottom - kWorkTop - 16));
    int x = static_cast<int>(anchor.left);
    int y = static_cast<int>(anchor.bottom) + 3;
    if (x + kWidth > kWorkRight) {
        x = kWorkRight - kWidth;
    }
    if (x < kWorkLeft) {
        x = kWorkLeft;
    }
    if (y + kHeight > kWorkBottom) {
        y = (std::max)(kWorkTop, static_cast<int>(anchor.top) - kHeight - 3);
    }
    ::SetWindowPos(navigationPalette_, HWND_TOP, x, y, kWidth, kHeight, SWP_NOACTIVATE | SWP_SHOWWINDOW);
    ::SetFocus(navigationPalette_);
}

void MainWindow::hideNavigationPalette(const bool focusCommandInput) {
    if (navigationPalette_ && ::IsWindow(navigationPalette_)) {
        ::ShowWindow(navigationPalette_, SW_HIDE);
    }
    if (focusCommandInput && commandEdit_ && ::IsWindow(commandEdit_)) {
        positionCommandInput();
        ::SetFocus(commandEdit_);
    }
}

void MainWindow::activateNavigationPaletteSelection() {
    if (!navigationPalette_ || !::IsWindow(navigationPalette_)) {
        return;
    }
    const LRESULT kSelected = ::SendMessageW(navigationPalette_, LB_GETCURSEL, 0, 0);
    if (kSelected == LB_ERR) {
        return;
    }
    const LRESULT kEntryIndex = ::SendMessageW(navigationPalette_, LB_GETITEMDATA,
        static_cast<WPARAM>(kSelected), 0);
    if (kEntryIndex == LB_ERR || kEntryIndex < 0 ||
        static_cast<std::size_t>(kEntryIndex) >= navigationPaletteEntries_.size()) {
        return;
    }
    const NavigationPaletteEntry kEntry = navigationPaletteEntries_[static_cast<std::size_t>(kEntryIndex)];
    hideNavigationPalette(false);

    if (kEntry.action == NavigationPaletteAction::kModule) {
        if (kEntry.moduleIndex < 0 || kEntry.moduleIndex >= static_cast<int>(modules_.size())) {
            return;
        }
        ksword::core::NavigationRequest request{};
        request.target = ksword::core::NavigationTarget::kDefault;
        request.entity.kind = ksword::core::EntityKind::kModule;
        request.entity.text = modules_[kEntry.moduleIndex].title;
        if (!routeNavigation(request) && statusText_) {
            ::SetWindowTextW(statusText_, L"导航面板无法打开所选模块。");
        }
        return;
    }

    if (!commandEdit_ || !::IsWindow(commandEdit_)) {
        return;
    }
    ::SetWindowTextW(commandEdit_, kEntry.commandTemplate.c_str());
    positionCommandInput();
    ::SetFocus(commandEdit_);
    const std::size_t kPlaceholderBegin = kEntry.commandTemplate.find(L'<');
    const std::size_t kPlaceholderEnd = kEntry.commandTemplate.find(L'>', kPlaceholderBegin);
    if (kPlaceholderBegin != std::wstring::npos && kPlaceholderEnd != std::wstring::npos &&
        kPlaceholderEnd >= kPlaceholderBegin) {
        ::SendMessageW(commandEdit_, EM_SETSEL, static_cast<WPARAM>(kPlaceholderBegin),
            static_cast<LPARAM>(kPlaceholderEnd + 1U));
        ::SendMessageW(commandEdit_, EM_SCROLLCARET, 0, 0);
    }
    if (statusText_) {
        ::SetWindowTextW(statusText_, L"已填入导航模板；替换尖括号中的参数后按 Enter。");
    }
}

void MainWindow::createChildControls() {
    statusText_ = ksword::ui::createText(hwnd_, kStatusTextId, L"Ready", 0, 0, 900, kStatusHeight);

    RECT dockBounds{ 0, 0, 900, 700 };
    dockManager_->create(hwnd_, dockBounds);
    dockManager_->setActivationChangedMessage(kMsgDockActivated);
}

void MainWindow::createModuleDocks() {
    if (modules_.empty()) {
        modules_ = ksword::features::getModuleDescriptors();
    }
    dockSlots_.clear();
    dockSlots_.resize(modules_.size());
    pendingNavigation_.clear();
    pendingNavigation_.resize(modules_.size());
    RECT pageBounds{ 0, 0, 600, 400 };
    for (int moduleIndex = 0; moduleIndex < static_cast<int>(modules_.size()); ++moduleIndex) {
        const auto& module = modules_[moduleIndex];
        HWND page = createModulePlaceholderPage(module, pageBounds);
        const int kIndex = dockManager_->addDock(ksword::docking::DockPosition::kCenter, module.title, page);
        dockSlots_[moduleIndex].dockIndex = kIndex;
        dockSlots_[moduleIndex].page = page;
        dockSlots_[moduleIndex].materialized = false;
        dockSlots_[moduleIndex].materializing = false;
    }
    if (!dockSlots_.empty()) {
        int initialModuleIndex = moduleIndexForCommandId(restoredModuleCommandId_);
        if (initialModuleIndex < 0) {
            initialModuleIndex = 0;
        }
        dockManager_->activateDock(dockSlots_[initialModuleIndex].dockIndex);
    }
    rebuildWindowMenuChecks();
}

void MainWindow::captureNormalWindowRect() {
    if (!hwnd_ || ::IsIconic(hwnd_) || ::IsZoomed(hwnd_)) {
        return;
    }
    RECT rect{};
    if (::GetWindowRect(hwnd_, &rect) && rect.right > rect.left && rect.bottom > rect.top) {
        lastNormalScreenRect_ = rect;
        hasLastNormalScreenRect_ = true;
    }
}

int MainWindow::activeModuleCommandId() const {
    if (!dockManager_) {
        return 0;
    }
    const int kActiveDockIndex = dockManager_->activeDockIndex();
    for (int moduleIndex = 0; moduleIndex < static_cast<int>(dockSlots_.size()) && moduleIndex < static_cast<int>(modules_.size()); ++moduleIndex) {
        if (dockSlots_[moduleIndex].dockIndex == kActiveDockIndex) {
            return modules_[moduleIndex].commandId;
        }
    }
    return 0;
}

void MainWindow::persistWorkspaceState() {
    ksword::core::WorkspaceConfig config{};
    config.maximized = wasMaximized_;
    config.activeCommandId = activeModuleCommandId();
    if (hasLastNormalScreenRect_ && lastNormalScreenRect_.right > lastNormalScreenRect_.left &&
        lastNormalScreenRect_.bottom > lastNormalScreenRect_.top) {
        config.hasNormalRect = true;
        config.normalRect = {
            static_cast<std::int32_t>(lastNormalScreenRect_.left),
            static_cast<std::int32_t>(lastNormalScreenRect_.top),
            static_cast<std::int32_t>(lastNormalScreenRect_.right),
            static_cast<std::int32_t>(lastNormalScreenRect_.bottom)
        };
    }
    storeWorkspaceConfig(config);
}

HWND MainWindow::createModulePlaceholderPage(const ksword::ui::ModuleDescriptor& module, const RECT& bounds) const {
    // This intentionally avoids module.createPage so startup only creates cheap
    // Win32 placeholders and dock labels. The real module page is built by
    // materializeDockForDockIndex after the shell is already visible.
    return ksword::ui::createPlaceholderPage(dockManager_->hwnd(), module, bounds);
}

HWND MainWindow::createModulePage(const ksword::ui::ModuleDescriptor& module, const RECT& bounds) const {
    // Input is one registry descriptor plus initial dock bounds. Processing uses
    // the module's factory when present, then falls back to a simple page so a
    // failed module cannot break the whole shell. Return value is a child HWND.
    HWND page = nullptr;
    if (module.createPage) {
        page = module.createPage(dockManager_->hwnd(), bounds);
    }
    if (!page) {
        page = ksword::ui::createPlaceholderPage(dockManager_->hwnd(), module, bounds);
    }
    return page;
}

void MainWindow::queueDockMaterialization(const int dockIndex) {
    if (!dockManager_ || dockIndex < 0) {
        return;
    }

    for (int moduleIndex = 0; moduleIndex < static_cast<int>(dockSlots_.size()); ++moduleIndex) {
        DockSlot& slot = dockSlots_[moduleIndex];
        if (slot.dockIndex != dockIndex || slot.materialized || slot.materializing) {
            continue;
        }
        slot.materializing = true;
        const std::wstring kStatus = L"准备加载“" + modules_[moduleIndex].title + L"”页面…";
        ksword::ui::setPlaceholderPageProgress(slot.page, kStatus, 8);
        if (statusText_) {
            ::SetWindowTextW(statusText_, kStatus.c_str());
        }
        ::PostMessageW(hwnd_, kMsgMaterializeDock, static_cast<WPARAM>(dockIndex), 0);
        return;
    }
}

void MainWindow::materializeDockForDockIndex(const int dockIndex) {
    if (!dockManager_ || dockIndex < 0) {
        return;
    }

    for (int moduleIndex = 0; moduleIndex < static_cast<int>(dockSlots_.size()); ++moduleIndex) {
        DockSlot& slot = dockSlots_[moduleIndex];
        if (slot.dockIndex != dockIndex || slot.materialized || !slot.materializing) {
            continue;
        }

        RECT pageBounds{ 0, 0, 600, 400 };
        if (slot.page) {
            RECT existing{};
            ::GetWindowRect(slot.page, &existing);
            POINT topLeft{ existing.left, existing.top };
            POINT bottomRight{ existing.right, existing.bottom };
            ::ScreenToClient(dockManager_->hwnd(), &topLeft);
            ::ScreenToClient(dockManager_->hwnd(), &bottomRight);
            pageBounds = { topLeft.x, topLeft.y, bottomRight.x, bottomRight.y };
        }

        // This is the frame the user actually stares at: the module factory on
        // the next line owns the UI thread until it returns, so the bar stands
        // still at this value for the whole construction. That is the honest
        // picture and it is left alone -- a fake animation here would only hide
        // which page is slow to build.
        ksword::ui::setPlaceholderPageProgress(
            slot.page,
            L"正在创建“" + modules_[moduleIndex].title + L"”页面内容…",
            30);

        HWND realPage = createModulePage(modules_[moduleIndex], pageBounds);
        if (!realPage) {
            slot.materializing = false;
            ksword::ui::setPlaceholderPageLoading(slot.page, false, L"页面创建失败，切换到此页面可重试。" );
            return;
        }

        // Last refresh the placeholder ever gets: mounting the real content
        // takes this HWND out of the dock, so a 100% frame would never be seen.
        ksword::ui::setPlaceholderPageProgress(
            slot.page,
            L"正在挂载“" + modules_[moduleIndex].title + L"”页面…",
            80);

        HWND oldPage = slot.page;
        if (dockManager_->replaceDockContent(slot.dockIndex, realPage, true)) {
            slot.page = realPage;
            slot.materialized = true;
            slot.materializing = false;
            if (statusText_) {
                const std::wstring kMessage = L"已加载模块：" + modules_[moduleIndex].title;
                ::SetWindowTextW(statusText_, kMessage.c_str());
            }
            if (moduleIndex < static_cast<int>(pendingNavigation_.size()) && pendingNavigation_[moduleIndex]) {
                const bool kRouted = applyNavigationToModule(moduleIndex, *pendingNavigation_[moduleIndex]);
                pendingNavigation_[moduleIndex].reset();
                if (statusText_) {
                    ::SetWindowTextW(statusText_, kRouted ? L"已完成实体导航。" : L"模块已加载，但无法应用导航目标。");
                }
            }
        } else {
            ::DestroyWindow(realPage);
            slot.page = oldPage;
            slot.materializing = false;
            ksword::ui::setPlaceholderPageLoading(slot.page, false, L"页面替换失败，切换到此页面可重试。" );
        }
        return;
    }
}

void MainWindow::rebuildWindowMenuChecks() {
    if (!windowMenu_) {
        return;
    }
    for (int index = 0; index < static_cast<int>(modules_.size()); ++index) {
        const UINT kState = moduleDockVisible(index) ? MF_CHECKED : MF_UNCHECKED;
        ::CheckMenuItem(windowMenu_, kWindowMenuDockBaseId + index, MF_BYCOMMAND | kState);
    }
    ::DrawMenuBar(hwnd_);
}

bool MainWindow::moduleDockVisible(int moduleIndex) const {
    if (moduleIndex < 0 || moduleIndex >= static_cast<int>(dockSlots_.size())) {
        return false;
    }
    const DockSlot& slot = dockSlots_[moduleIndex];
    return slot.page && slot.dockIndex >= 0 && dockManager_ && dockManager_->dockVisible(slot.dockIndex);
}

bool MainWindow::isTopmost() const {
    if (!hwnd_) {
        return false;
    }
    const LONG_PTR kExStyle = ::GetWindowLongPtrW(hwnd_, GWL_EXSTYLE);
    return (kExStyle & WS_EX_TOPMOST) != 0;
}

void MainWindow::toggleTopmost() {
    if (!hwnd_) {
        return;
    }
    const bool kEnableTopmost = !isTopmost();
    const HWND kInsertAfter = kEnableTopmost ? HWND_TOPMOST : HWND_NOTOPMOST;
    if (::SetWindowPos(hwnd_, kInsertAfter, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE)) {
        refreshTopmostMenuText();
        if (statusText_) {
            ::SetWindowTextW(statusText_, kEnableTopmost ? L"Window is topmost." : L"Window is no longer topmost.");
        }
    }
}

void MainWindow::refreshTopmostMenuText() {
    if (!mainMenu_) {
        return;
    }
    const wchar_t* text = isTopmost() ? L"取消置顶" : L"置顶";
    MENUITEMINFOW item{};
    item.cbSize = sizeof(item);
    item.fMask = MIIM_FTYPE | MIIM_STRING;
    item.fType = MFT_STRING | MFT_RIGHTJUSTIFY;
    item.dwTypeData = const_cast<LPWSTR>(text);
    ::SetMenuItemInfoW(mainMenu_, kTopmostMenuId, FALSE, &item);
    ::DrawMenuBar(hwnd_);
    positionCommandInput();
}

void MainWindow::positionCommandInput() {
    if (!hwnd_ || !mainMenu_ || !commandEdit_) {
        return;
    }

    if (::IsIconic(hwnd_)) {
        ::ShowWindow(commandEdit_, SW_HIDE);
        return;
    }

    const int kMenuCount = ::GetMenuItemCount(mainMenu_);
    int topmostIndex = -1;
    for (int index = 0; index < kMenuCount; ++index) {
        if (::GetMenuItemID(mainMenu_, index) == kTopmostMenuId) {
            topmostIndex = index;
            break;
        }
    }
    if (topmostIndex < 0) {
        ::ShowWindow(commandEdit_, SW_HIDE);
        return;
    }

    RECT topmostRect{};
    RECT windowRect{};
    if (!::GetMenuItemRect(hwnd_, mainMenu_, topmostIndex, &topmostRect) || !::GetWindowRect(hwnd_, &windowRect)) {
        ::ShowWindow(commandEdit_, SW_HIDE);
        return;
    }

    const int kMenuHeight = topmostRect.bottom - topmostRect.top;
    const int kEditHeight = (kMenuHeight > 6) ? (kMenuHeight - 4) : kCommandEditHeight;
    int x = topmostRect.left - kCommandEditMenuGap - kCommandEditWidth;
    const int kMinX = windowRect.left + 160;
    if (x < kMinX) {
        x = kMinX;
    }
    const int kY = topmostRect.top + ((kMenuHeight - kEditHeight) / 2);
    ::SetWindowPos(commandEdit_, HWND_TOP, x, kY, kCommandEditWidth, kEditHeight,
        SWP_NOACTIVATE | SWP_SHOWWINDOW);
}

void MainWindow::enableStartupPrivileges() {
    startupPrivilegeResults_ = ksword::core::enableStartupPrivileges();
    startupPrivilegeSummary_ = ksword::core::summarizePrivilegeEnableResults(startupPrivilegeResults_);
    if (!startupPrivilegeSummary_.empty()) {
        ::OutputDebugStringW((L"[KswordARKLight] " + startupPrivilegeSummary_ + L"\r\n").c_str());
    }

    for (const ksword::core::PrivilegeEnableResult& result : startupPrivilegeResults_) {
        if (result.enabled) {
            continue;
        }
        std::wstring line = L"[KswordARKLight] Startup privilege failed: " + result.name +
            L", error=" + std::to_wstring(result.errorCode) + L", " + result.message + L"\r\n";
        ::OutputDebugStringW(line.c_str());
    }

    if (statusText_ && !startupPrivilegeSummary_.empty()) {
        ::SetWindowTextW(statusText_, startupPrivilegeSummary_.c_str());
    }
}

void MainWindow::executeCommandInput() {
    if (!commandEdit_) {
        return;
    }

    const int kTextLength = ::GetWindowTextLengthW(commandEdit_);
    if (kTextLength <= 0) {
        return;
    }

    std::vector<wchar_t> textBuffer(static_cast<std::size_t>(kTextLength) + 1, L'\0');
    ::GetWindowTextW(commandEdit_, textBuffer.data(), static_cast<int>(textBuffer.size()));
    const std::wstring kCommandText = trimWhitespace(textBuffer.data());
    if (kCommandText.empty()) {
        return;
    }

    const ksword::core::CommandInputResult kParsed = ksword::core::parseCommandInput(kCommandText);
    if (kParsed.kind == ksword::core::CommandInputKind::kInvalid) {
        if (statusText_) {
            ::SetWindowTextW(statusText_, kParsed.error.c_str());
        }
        return;
    }
    if (kParsed.kind == ksword::core::CommandInputKind::kNavigation) {
        const bool kRouted = routeNavigation(kParsed.navigation);
        if (kRouted) {
            ::SetWindowTextW(commandEdit_, L"");
        } else if (statusText_) {
            ::SetWindowTextW(statusText_, L"没有找到可接收该命令的模块。");
        }
        return;
    }

    std::wstring commandLine = L"cmd.exe /k " + kParsed.shellCommand;
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    const BOOL kCreated = ::CreateProcessW(nullptr, commandLine.data(),
        nullptr, nullptr, FALSE, CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT,
        nullptr, nullptr, &startup, &process);
    if (!kCreated) {
        const DWORD kError = ::GetLastError();
        if (statusText_) {
            const std::wstring kMessage = L"Command launch failed: " + std::to_wstring(kError) +
                L", " + ksword::core::lastErrorMessage(kError);
            ::SetWindowTextW(statusText_, kMessage.c_str());
        }
        return;
    }

    if (process.hThread) {
        ::CloseHandle(process.hThread);
    }
    if (process.hProcess) {
        ::CloseHandle(process.hProcess);
    }
    ::SetWindowTextW(commandEdit_, L"");
    if (statusText_) {
        ::SetWindowTextW(statusText_, L"Command launched in a new console.");
    }
}

int MainWindow::moduleIndexForCommandId(const int commandId) const {
    for (int index = 0; index < static_cast<int>(modules_.size()); ++index) {
        if (modules_[index].commandId == commandId) {
            return index;
        }
    }
    return -1;
}

int MainWindow::moduleIndexForTitle(const std::wstring& query) const {
    const std::wstring kLoweredQuery = lowerText(trimWhitespace(query));
    if (kLoweredQuery.empty()) {
        return -1;
    }
    for (int index = 0; index < static_cast<int>(modules_.size()); ++index) {
        if (lowerText(modules_[index].title) == kLoweredQuery) {
            return index;
        }
    }
    for (int index = 0; index < static_cast<int>(modules_.size()); ++index) {
        const std::wstring kTitle = lowerText(modules_[index].title);
        if (kTitle.find(kLoweredQuery) != std::wstring::npos || kLoweredQuery.find(kTitle) != std::wstring::npos) {
            return index;
        }
    }
    return -1;
}

bool MainWindow::activateModule(const int moduleIndex) {
    if (!dockManager_ || moduleIndex < 0 || moduleIndex >= static_cast<int>(modules_.size())) {
        return false;
    }
    if (dockSlots_.size() < modules_.size()) {
        dockSlots_.resize(modules_.size());
    }
    if (pendingNavigation_.size() < modules_.size()) {
        pendingNavigation_.resize(modules_.size());
    }
    DockSlot& slot = dockSlots_[moduleIndex];
    if (!moduleDockVisible(moduleIndex)) {
        RECT pageBounds{ 0, 0, 600, 400 };
        slot.page = createModulePlaceholderPage(modules_[moduleIndex], pageBounds);
        slot.dockIndex = dockManager_->addDock(
            ksword::docking::DockPosition::kCenter, modules_[moduleIndex].title, slot.page);
        slot.materialized = false;
        slot.materializing = false;
        rebuildWindowMenuChecks();
    }
    if (slot.dockIndex < 0) {
        return false;
    }
    dockManager_->activateDock(slot.dockIndex);
    if (!slot.materialized) {
        queueDockMaterialization(slot.dockIndex);
    }
    return true;
}

bool MainWindow::routeNavigation(const ksword::core::NavigationRequest& request) {
    int commandId = 0;
    switch (request.target) {
    case ksword::core::NavigationTarget::kDefault:
        if (request.entity.kind == ksword::core::EntityKind::kModule) {
            const int kModuleIndex = moduleIndexForTitle(request.entity.text);
            if (kModuleIndex < 0) {
                return false;
            }
            const bool kActivated = activateModule(kModuleIndex);
            if (kActivated && statusText_) {
                ::SetWindowTextW(statusText_, (L"已切换到模块：" + modules_[kModuleIndex].title).c_str());
            }
            return kActivated;
        }
        return false;
    case ksword::core::NavigationTarget::kProcessDetails: commandId = kProcessModuleCommandId; break;
    case ksword::core::NavigationTarget::kMemoryOperations: commandId = kMemoryModuleCommandId; break;
    case ksword::core::NavigationTarget::kFileBrowser: commandId = kFileModuleCommandId; break;
    case ksword::core::NavigationTarget::kRegistryBrowser: commandId = kRegistryModuleCommandId; break;
    case ksword::core::NavigationTarget::kNetworkConnections: commandId = kNetworkModuleCommandId; break;
    case ksword::core::NavigationTarget::kHandleTable: commandId = kHandleModuleCommandId; break;
    case ksword::core::NavigationTarget::kWindowManager: commandId = kWindowModuleCommandId; break;
    case ksword::core::NavigationTarget::kEtwMonitor: commandId = kMonitorModuleCommandId; break;
    }
    const int kModuleIndex = moduleIndexForCommandId(commandId);
    if (kModuleIndex < 0) {
        return false;
    }
    if (pendingNavigation_.size() < modules_.size()) {
        pendingNavigation_.resize(modules_.size());
    }
    pendingNavigation_[kModuleIndex] = request;
    if (!activateModule(kModuleIndex)) {
        pendingNavigation_[kModuleIndex].reset();
        return false;
    }
    DockSlot& slot = dockSlots_[kModuleIndex];
    if (!slot.materialized) {
        if (statusText_) {
            ::SetWindowTextW(statusText_, (L"正在加载并导航到“" + modules_[kModuleIndex].title + L"”…").c_str());
        }
        return true;
    }
    const bool kRouted = applyNavigationToModule(kModuleIndex, request);
    pendingNavigation_[kModuleIndex].reset();
    return kRouted;
}

bool MainWindow::applyNavigationToModule(
    const int moduleIndex,
    const ksword::core::NavigationRequest& request) {
    if (moduleIndex < 0 || moduleIndex >= static_cast<int>(dockSlots_.size()) || !dockSlots_[moduleIndex].page) {
        return false;
    }
    HWND page = dockSlots_[moduleIndex].page;
    switch (request.target) {
    case ksword::core::NavigationTarget::kProcessDetails: {
        DWORD processId = static_cast<DWORD>(request.entity.id);
        if (request.entity.kind == ksword::core::EntityKind::kThread) {
            processId = processIdForThread(processId);
        }
        return processId != 0 && ksword::features::process::requestProcessFeatureOpenDetails(
            page, processId, request.entity.creationTime100ns);
    }
    case ksword::core::NavigationTarget::kMemoryOperations:
        return request.entity.kind == ksword::core::EntityKind::kProcess && request.entity.id != 0U &&
            request.entity.id <= static_cast<std::uint64_t>((std::numeric_limits<DWORD>::max)()) &&
            ksword::features::memory::requestMemoryFeatureProcess(page, static_cast<DWORD>(request.entity.id));
    case ksword::core::NavigationTarget::kFileBrowser:
        return ksword::features::file::requestFileFeatureNavigate(page, request.entity.text);
    case ksword::core::NavigationTarget::kRegistryBrowser:
        return ksword::features::registry::requestRegistryFeatureNavigate(page, request.entity.text);
    case ksword::core::NavigationTarget::kNetworkConnections:
        return ksword::features::network::requestNetworkFeatureProcess(page, static_cast<DWORD>(request.entity.id));
    case ksword::core::NavigationTarget::kHandleTable:
        return ksword::features::handle::requestHandleFeatureProcess(page, static_cast<DWORD>(request.entity.id));
    case ksword::core::NavigationTarget::kWindowManager:
        return ksword::features::window::requestWindowFeatureQuery(
            page,
            request.entity.kind == ksword::core::EntityKind::kWindow
                ? hexIdentifier(request.entity.id)
                : std::to_wstring(request.entity.id));
    case ksword::core::NavigationTarget::kEtwMonitor:
        return ksword::features::monitor::requestMonitorFeatureProcess(page, static_cast<DWORD>(request.entity.id));
    case ksword::core::NavigationTarget::kDefault:
        return true;
    }
    return false;
}

void MainWindow::exportEvidence(const int commandId) {
    ksword::ui::EvidenceSession& session = ksword::ui::globalEvidenceSession();
    if (commandId == kEvidenceClearMenuId) {
        session.clear();
        if (statusText_) {
            ::SetWindowTextW(statusText_, L"证据会话已清空。");
        }
        return;
    }
    if (session.size() == 0U) {
        if (statusText_) {
            ::SetWindowTextW(statusText_, L"证据会话为空；复制或导出模块结果后再试。");
        }
        return;
    }

    std::wstring text;
    const wchar_t* name = L"ksword-arklight-evidence.json";
    const wchar_t* title = L"导出证据会话";
    const wchar_t* filter = L"JSON (*.json)\0*.json\0All Files (*.*)\0*.*\0";
    const wchar_t* extension = L"json";
    if (commandId == kEvidenceTsvPrivacyMenuId) {
        text = session.exportTsv(ksword::ui::EvidenceRedaction::kPrivacy);
        name = L"ksword-arklight-evidence.tsv";
        filter = L"TSV (*.tsv)\0*.tsv\0All Files (*.*)\0*.*\0";
        extension = L"tsv";
    } else if (commandId == kEvidenceDiffMenuId) {
        if (session.size() < 2U) {
            if (statusText_) {
                ::SetWindowTextW(statusText_, L"至少需要两次证据采集才能生成差异。");
            }
            return;
        }
        text = ksword::ui::renderEvidenceDiff(session.latestDiff());
        name = L"ksword-arklight-evidence-diff.txt";
        filter = L"Text (*.txt)\0*.txt\0All Files (*.*)\0*.*\0";
        extension = L"txt";
    } else {
        text = session.exportJson(commandId == kEvidenceJsonRawMenuId
            ? ksword::ui::EvidenceRedaction::kNone
            : ksword::ui::EvidenceRedaction::kPrivacy);
    }
    std::wstring error;
    const ksword::ui::SaveTextFileResult kResult = ksword::ui::saveUtf8TextFileWithDialog(
        hwnd_, name, title, filter, extension, text, &error);
    if (statusText_) {
        if (kResult == ksword::ui::SaveTextFileResult::kSaved) {
            ::SetWindowTextW(statusText_, L"证据会话已导出。");
        } else if (kResult == ksword::ui::SaveTextFileResult::kFailed) {
            ::SetWindowTextW(statusText_, error.c_str());
        }
    }
}

void MainWindow::toggleModuleDock(int moduleIndex) {
    if (moduleIndex < 0 || moduleIndex >= static_cast<int>(modules_.size()) || !dockManager_) {
        return;
    }
    if (dockSlots_.size() < modules_.size()) {
        dockSlots_.resize(modules_.size());
    }

    DockSlot& slot = dockSlots_[moduleIndex];
    if (moduleDockVisible(moduleIndex)) {
        dockManager_->closeDock(slot.dockIndex);
        if (slot.page) {
            ::DestroyWindow(slot.page);
        }
        slot.page = nullptr;
        slot.dockIndex = -1;
        slot.materialized = false;
        slot.materializing = false;
        if (moduleIndex < static_cast<int>(pendingNavigation_.size())) {
            pendingNavigation_[moduleIndex].reset();
        }
        rebuildWindowMenuChecks();
        layout();
        return;
    }

    RECT pageBounds{ 0, 0, 600, 400 };
    slot.page = createModulePlaceholderPage(modules_[moduleIndex], pageBounds);
    slot.dockIndex = dockManager_->addDock(ksword::docking::DockPosition::kCenter, modules_[moduleIndex].title, slot.page);
    slot.materialized = false;
    slot.materializing = false;
    dockManager_->activateDock(slot.dockIndex);
    rebuildWindowMenuChecks();
    layout();
}

void MainWindow::layout() {
    if (!hwnd_) {
        return;
    }
    RECT rc{};
    ::GetClientRect(hwnd_, &rc);
    const int kWidth = rc.right - rc.left;
    const int kHeight = rc.bottom - rc.top;

    ::MoveWindow(statusText_, 0, kHeight - kStatusHeight, kWidth, kStatusHeight, TRUE);

    RECT dockBounds{
        0,
        0,
        kWidth,
        kHeight - kStatusHeight
    };
    dockManager_->layout(dockBounds);
    if (dockManager_->hwnd()) {
        ::ShowWindow(dockManager_->hwnd(), SW_SHOW);
        ::InvalidateRect(dockManager_->hwnd(), nullptr, TRUE);
    }
}

void MainWindow::refreshPrivilegeText() {
    if (!mainMenu_) {
        return;
    }
    std::wstring text = L"UIAccess";
    if (!startupPrivilegeResults_.empty()) {
        int enabledCount = 0;
        for (const ksword::core::PrivilegeEnableResult& result : startupPrivilegeResults_) {
            if (result.enabled) {
                ++enabledCount;
            }
        }
        text += L" 权限 " + std::to_wstring(enabledCount) + L"/" +
            std::to_wstring(startupPrivilegeResults_.size());
    }
    ::ModifyMenuW(mainMenu_, kPrivilegeMenuId, MF_BYCOMMAND | MF_STRING, kPrivilegeMenuId, text.c_str());
    ::DrawMenuBar(hwnd_);
    positionCommandInput();
}

void MainWindow::refreshDriverText(const ksword::core::DriverRuntimeStatus& status) {
    if (mainMenu_) {
        const wchar_t* text = status.serviceRunning || status.controlDeviceOpen ? L"卸载驱动" : L"装载驱动";
        ::ModifyMenuW(mainMenu_, kDriverMenuId, MF_BYCOMMAND | MF_STRING, kDriverMenuId, text);
        ::DrawMenuBar(hwnd_);
        positionCommandInput();
    }
    if (statusText_ && !status.message.empty()) {
        ::SetWindowTextW(statusText_, status.message.c_str());
    } else if (statusText_ && !driverStatusKnown_) {
        ::SetWindowTextW(statusText_, L"R0 driver status will be queried after startup.");
    }
}

void MainWindow::queryDriverStatusDeferred() {
    driverStatus_ = ksword::core::queryDriverStatus();
    driverStatusKnown_ = true;
    refreshDriverText(driverStatus_);
    if (driverStatus_.serviceRunning || driverStatus_.controlDeviceOpen) {
        requestProcessDockRefreshIfLoaded();
    }
}

void MainWindow::requestProcessDockRefreshIfLoaded() {
    if (dockSlots_.empty() || modules_.empty()) {
        return;
    }

    for (int moduleIndex = 0; moduleIndex < static_cast<int>(modules_.size()); ++moduleIndex) {
        if (modules_[moduleIndex].commandId != kProcessModuleCommandId) {
            continue;
        }
        if (moduleIndex >= static_cast<int>(dockSlots_.size())) {
            return;
        }

        const DockSlot& slot = dockSlots_[moduleIndex];
        if (!slot.materialized || !slot.page) {
            return;
        }

        // slot.page usage: Materialized process page HWND; triggers a default R0 hidden process scan refresh immediately after driver loading.
        ksword::features::process::requestProcessFeatureRefresh(slot.page);
        return;
    }
}

void MainWindow::handleUiAccessButtonClicked() {
    if (ksword::core::isUiAccessEnabled()) {
        ::SetWindowTextW(statusText_, L"UIAccess is already enabled.");
        return;
    }

    if (!ksword::core::isRunningAsAdmin()) {
        ::SetWindowTextW(statusText_, L"UIAccess needs Admin first; requesting elevation.");
        if (ksword::core::relaunchElevated()) {
            ::PostMessageW(hwnd_, WM_CLOSE, 0, 0);
        } else {
            ::MessageBoxW(hwnd_, L"Admin elevation launch failed or was canceled.", L"UIAccess", MB_ICONWARNING | MB_OK);
        }
        return;
    }

    std::wstring detail;
    if (!ksword::core::launchSelfWithSystemUiAccessToken(&detail)) {
        ::MessageBoxW(hwnd_, detail.c_str(), L"UIAccess fallback failed", MB_ICONWARNING | MB_OK);
        refreshPrivilegeText();
        return;
    }

    ::SetWindowTextW(statusText_, L"UIAccess instance started; exiting current process.");
    ::PostMessageW(hwnd_, WM_CLOSE, 0, 0);
}

void MainWindow::installDriverFromButton() {
    ksword::core::DriverRuntimeStatus current = driverStatusKnown_ ? driverStatus_ : ksword::core::queryDriverStatus();
    driverStatusKnown_ = true;
    driverStatus_ = current;
    if (current.serviceRunning || current.controlDeviceOpen) {
        driverStatus_ = ksword::core::stopDriverService();
        if (!driverStatus_.serviceRunning && !driverStatus_.controlDeviceOpen) {
            driverLease_.observeExplicitStop();
        }
        refreshDriverText(driverStatus_);
        if (driverStatus_.serviceRunning || driverStatus_.controlDeviceOpen) {
            ::MessageBoxW(hwnd_, driverStatus_.message.c_str(), L"KswordARKLight R0 Driver", MB_ICONWARNING | MB_OK);
        }
        return;
    }

    driverStatus_ = ksword::core::installAndStartDriver();
    driverLease_.observeStartTransition(
        current.serviceRunning || current.controlDeviceOpen,
        driverStatus_.serviceRunning || driverStatus_.controlDeviceOpen);
    refreshDriverText(driverStatus_);
    if (driverStatus_.serviceRunning || driverStatus_.controlDeviceOpen) {
        requestProcessDockRefreshIfLoaded();
    }
    if (!driverStatus_.serviceRunning && !driverStatus_.controlDeviceOpen) {
        ::MessageBoxW(hwnd_, driverStatus_.message.c_str(), L"KswordARKLight R0 Driver", MB_ICONWARNING | MB_OK);
    }
}

void MainWindow::stopDriverOnExit() {
    if (!driverLease_.releaseRequestsStop()) {
        ::OutputDebugStringW(L"[KswordARKLight] Driver remains running: it was pre-existing or another Light lease is active.\r\n");
        return;
    }
    const ksword::core::DriverRuntimeStatus kCurrent = ksword::core::queryDriverStatus();
    if (!kCurrent.serviceRunning && !kCurrent.controlDeviceOpen) {
        return;
    }

    driverStatus_ = ksword::core::stopDriverService();
    driverStatusKnown_ = true;
    ::OutputDebugStringW((L"[KswordARKLight] Exit driver stop: " + driverStatus_.message + L"\r\n").c_str());
}

void MainWindow::paint(HDC dc) {
    RECT rc{};
    ::GetClientRect(hwnd_, &rc);
    ::FillRect(dc, &rc, ksword::ui::appTheme().windowBrush());

    HPEN border = ::CreatePen(PS_SOLID, 1, ksword::ui::appTheme().borderColor);
    HGDIOBJ oldPen = ::SelectObject(dc, border);
    ::MoveToEx(dc, 0, rc.bottom - kStatusHeight, nullptr);
    ::LineTo(dc, rc.right, rc.bottom - kStatusHeight);
    ::SelectObject(dc, oldPen);
    ::DeleteObject(border);
}

} // namespace Ksword::App
