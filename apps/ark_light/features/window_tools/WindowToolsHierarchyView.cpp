#include "WindowToolsHierarchyView.h"

#include "WindowToolsCommon.h"
#include "../../core/EntityRef.h"
#include "../../ui/AsyncTask.h"
#include "../../ui/Controls.h"
#include "../../ui/EntityNavigation.h"
#include "../../ui/ExportUtil.h"
#include "../../ui/FilterBar.h"
#include "../../ui/ListViewUtil.h"
#include "../../ui/LoadingOverlay.h"
#include "../../ui/TextFindSupport.h"
#include "../../ui/Theme.h"
#include "../../ui/VirtualListView.h"

#include <commctrl.h>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace ksword::features::window_tools {
namespace {

constexpr wchar_t kHierarchyViewClass[] = L"KswordARKLight.WindowTools.HierarchyView";
constexpr wchar_t kHierarchyReportViewClass[] = L"KswordARKLight.WindowTools.HierarchyReportView";

constexpr int kRefreshButtonId = 67201;
constexpr int kFilterBarId = 67202;
constexpr int kWindowListId = 67203;
constexpr int kReportEditId = 67204;
constexpr int kLoadingOverlayId = 67205;
constexpr int kExportButtonId = 67206;

constexpr UINT kMenuCopyReport = 67641;
constexpr UINT kMenuCopyRow = 67642;
constexpr UINT kMenuCopyVisible = 67643;
constexpr UINT kMenuRefresh = 67644;
constexpr UINT kMenuOpenProcess = 67645;

constexpr UINT kMsgRefreshCompleted = WM_APP + 675;
constexpr UINT kMsgFilterCompleted = WM_APP + 676;

constexpr int kGap = 6;
constexpr int kRowHeight = 24;
constexpr int kHeaderHeight = kGap * 3 + kRowHeight * 2;
constexpr int kStatusHeight = 22;
constexpr int kColumnCount = 5;

// kAncestorChainLimit stops the parent walk from running forever. A well-formed
// chain ends at the desktop in a handful of steps; a handle that keeps returning
// a new parent means the tree changed under the walk, and a bound is the only
// way to leave that loop.
constexpr int kAncestorChainLimit = 32;
constexpr DWORD kDwmwaExtendedFrameBounds = 9;
constexpr DWORD kDwmwaCloaked = 14;
constexpr DWORD kDwmCloakedApp = 0x00000001;
constexpr DWORD kDwmCloakedShell = 0x00000002;
constexpr DWORD kDwmCloakedInherited = 0x00000004;

int width(const RECT& rc) {
    return rc.right > rc.left ? static_cast<int>(rc.right - rc.left) : 0;
}

int height(const RECT& rc) {
    return rc.bottom > rc.top ? static_cast<int>(rc.bottom - rc.top) : 0;
}

struct HierarchyFilterResult final {
    std::uint64_t generation = 0;
    std::wstring query;
    bool useRegex = false;
    std::wstring selectedStableKey;
    std::vector<std::size_t> visibleIndexes;
};

struct HierarchyViewState final {
    HWND hwnd = nullptr;
    HWND refreshButton = nullptr;
    HWND exportButton = nullptr;
    HWND filterBar = nullptr;
    HWND reportEdit = nullptr;
    HWND loadingOverlay = nullptr;
    ksword::ui::VirtualListView windowList;
    std::vector<TopLevelWindowInfo> windows;
    std::shared_ptr<const std::vector<ksword::ui::VirtualListRow>> filterRows;
    std::wstring statusText = L"正在枚举顶层窗口…";
    std::wstring filterQuery;
    bool filterUseRegex = false;
    std::uint64_t displayGeneration = 0;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<std::vector<TopLevelWindowInfo>>> refreshTask;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<HierarchyFilterResult>> filterTask;
};

// DpiApi resolves the per-window DPI entry points at run time.
//
// These arrived in Windows 10 1607 and the SDK only declares them for a matching
// _WIN32_WINNT. Binding them late keeps this page working on an older target
// without gating the whole project's minimum version on one diagnostic field,
// and it lets the report say "This system does not provide" instead of failing to start.
struct DpiApi final {
    using GetDpiForWindowFn = UINT(WINAPI*)(HWND);
    using GetWindowDpiAwarenessContextFn = void* (WINAPI*)(HWND);
    using GetAwarenessFromDpiAwarenessContextFn = int(WINAPI*)(void*);
    using GetDpiFromDpiAwarenessContextFn = UINT(WINAPI*)(void*);
    using AreDpiAwarenessContextsEqualFn = BOOL(WINAPI*)(void*, void*);

    GetDpiForWindowFn getDpiForWindow = nullptr;
    GetWindowDpiAwarenessContextFn getWindowContext = nullptr;
    GetAwarenessFromDpiAwarenessContextFn getAwareness = nullptr;
    GetDpiFromDpiAwarenessContextFn getDpiFromContext = nullptr;
    AreDpiAwarenessContextsEqualFn contextsEqual = nullptr;
};

// DwmApi is deliberately resolved at runtime. DwmGetWindowAttribute is useful
// evidence when it exists, but this diagnostic field must not add a load-time
// dwmapi dependency or narrow the systems on which Lite starts.
struct DwmApi final {
    using GetWindowAttributeFn = HRESULT(WINAPI*)(HWND, DWORD, PVOID, DWORD);

    GetWindowAttributeFn getWindowAttribute = nullptr;
};

const DpiApi& loadDpiApi() {
    static const DpiApi kApi = [] {
        DpiApi loaded{};
        HMODULE user32 = ::GetModuleHandleW(L"user32.dll");
        if (!user32) {
            return loaded;
        }
        loaded.getDpiForWindow =
            reinterpret_cast<DpiApi::GetDpiForWindowFn>(::GetProcAddress(user32, "GetDpiForWindow"));
        loaded.getWindowContext =
            reinterpret_cast<DpiApi::GetWindowDpiAwarenessContextFn>(::GetProcAddress(user32, "GetWindowDpiAwarenessContext"));
        loaded.getAwareness =
            reinterpret_cast<DpiApi::GetAwarenessFromDpiAwarenessContextFn>(::GetProcAddress(user32, "GetAwarenessFromDpiAwarenessContext"));
        loaded.getDpiFromContext =
            reinterpret_cast<DpiApi::GetDpiFromDpiAwarenessContextFn>(::GetProcAddress(user32, "GetDpiFromDpiAwarenessContext"));
        loaded.contextsEqual =
            reinterpret_cast<DpiApi::AreDpiAwarenessContextsEqualFn>(::GetProcAddress(user32, "AreDpiAwarenessContextsEqual"));
        return loaded;
    }();
    return kApi;
}

const DwmApi& loadDwmApi() {
    static const DwmApi kApi = [] {
        DwmApi loaded{};
        HMODULE module = ::GetModuleHandleW(L"dwmapi.dll");
        if (!module) {
            module = ::LoadLibraryW(L"dwmapi.dll");
        }
        if (module) {
            loaded.getWindowAttribute = reinterpret_cast<DwmApi::GetWindowAttributeFn>(
                ::GetProcAddress(module, "DwmGetWindowAttribute"));
        }
        return loaded;
    }();
    return kApi;
}

// dpiContextSentinel builds one of the DPI_AWARENESS_CONTEXT pseudo-handles.
// They are small negative values rather than real pointers, which is why they
// can be reconstructed here without the SDK macros.
void* dpiContextSentinel(const std::intptr_t value) {
    return reinterpret_cast<void*>(value);
}

std::wstring describeDpiContext(void* context) {
    if (!context) {
        return L"(无)";
    }
    const DpiApi& api = loadDpiApi();
    if (api.contextsEqual) {
        struct NamedContext final {
            std::intptr_t value;
            const wchar_t* name;
        };
        static const NamedContext kNamed[] = {
            { -1, L"DPI_AWARENESS_CONTEXT_UNAWARE" },
            { -2, L"DPI_AWARENESS_CONTEXT_SYSTEM_AWARE" },
            { -3, L"DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE" },
            { -4, L"DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2" },
            { -5, L"DPI_AWARENESS_CONTEXT_UNAWARE_GDISCALED" },
        };
        for (const NamedContext& named : kNamed) {
            if (api.contextsEqual(context, dpiContextSentinel(named.value))) {
                return named.name;
            }
        }
    }
    if (api.getAwareness) {
        switch (api.getAwareness(context)) {
        case 0: return L"DPI_AWARENESS_UNAWARE";
        case 1: return L"DPI_AWARENESS_SYSTEM_AWARE";
        case 2: return L"DPI_AWARENESS_PER_MONITOR_AWARE";
        default: break;
        }
    }
    return L"未知上下文 " + pointerText(reinterpret_cast<std::uint64_t>(context));
}

void appendLine(std::wstring& text, const std::wstring& line) {
    text += line;
    text += L"\r\n";
}

void appendSection(std::wstring& text, const wchar_t* title) {
    if (!text.empty()) {
        appendLine(text, L"");
    }
    appendLine(text, std::wstring(L"==== ") + title + L" ====");
}

void appendField(std::wstring& text, const wchar_t* label, const std::wstring& value) {
    appendLine(text, std::wstring(L"  ") + label + L"：" + value);
}

void appendBits(std::wstring& text, const std::vector<std::wstring>& bits) {
    for (const std::wstring& bit : bits) {
        appendLine(text, L"    " + bit);
    }
}

// appendBasics writes the identity block. The window is revalidated by the
// caller, so everything here is a plain read.
void appendBasics(std::wstring& text, HWND hwnd) {
    DWORD processId = 0;
    const DWORD kThreadId = ::GetWindowThreadProcessId(hwnd, &processId);
    std::wstring title = windowTitleText(hwnd);
    if (title.empty()) {
        title = L"(无标题)";
    }
    appendSection(text, L"基本信息");
    appendField(text, L"窗口句柄", hwndText(hwnd));
    appendField(text, L"标题", title);
    appendField(text, L"类名", windowClassText(hwnd));
    appendField(text, L"进程", processNameFromId(processId) + L"（PID " + std::to_wstring(processId) + L"）");
    appendField(text, L"线程 ID", std::to_wstring(kThreadId));
    appendField(text, L"可见 / 启用 / 最小化 / 最大化",
        std::wstring(::IsWindowVisible(hwnd) ? L"是" : L"否") + L" / " +
        (::IsWindowEnabled(hwnd) ? L"是" : L"否") + L" / " +
        (::IsIconic(hwnd) ? L"是" : L"否") + L" / " +
        (::IsZoomed(hwnd) ? L"是" : L"否"));
    appendField(text, L"Unicode 窗口", ::IsWindowUnicode(hwnd) ? L"是" : L"否（窗口过程按 ANSI 收消息）");
}

// appendAncestry writes the three GetAncestor results plus the walked chain.
//
// The three are not interchangeable: GA_PARENT stops at the immediate parent,
// GA_ROOT climbs to the top-level window, and GA_ROOTOWNER follows the owner
// links past it. A dialog owned by a main window has a different GA_ROOT and
// GA_ROOTOWNER, and that difference is usually the answer to "which window does
// this really belong to".
void appendAncestry(std::wstring& text, HWND hwnd) {
    appendSection(text, L"祖先链");
    appendField(text, L"GetAncestor(GA_PARENT)", describeWindowBrief(::GetAncestor(hwnd, GA_PARENT)));
    appendField(text, L"GetAncestor(GA_ROOT)", describeWindowBrief(::GetAncestor(hwnd, GA_ROOT)));
    appendField(text, L"GetAncestor(GA_ROOTOWNER)", describeWindowBrief(::GetAncestor(hwnd, GA_ROOTOWNER)));
    appendField(text, L"GetParent()", describeWindowBrief(::GetParent(hwnd)));
    appendField(text, L"GetWindow(GW_OWNER)", describeWindowBrief(::GetWindow(hwnd, GW_OWNER)));

    appendLine(text, L"  逐级父窗口（GA_PARENT 向上直到桌面）：");
    HWND current = ::GetAncestor(hwnd, GA_PARENT);
    int level = 0;
    while (current && level < kAncestorChainLimit) {
        appendLine(text, L"    [" + std::to_wstring(level) + L"] " + describeWindowBrief(current));
        HWND next = ::GetAncestor(current, GA_PARENT);
        if (next == current) {
            break;
        }
        current = next;
        ++level;
    }
    if (level == 0) {
        appendLine(text, L"    (无父窗口，已是顶层窗口)");
    } else if (level >= kAncestorChainLimit) {
        appendLine(text, L"    (链长超过上限，已停止)");
    }
}

// appendZOrder locates the window inside the top-level Z order.
//
// The index is computed by walking GW_HWNDNEXT from GetTopWindow rather than by
// reusing the list snapshot, because the snapshot is as old as the last refresh
// and Z order changes on every click somewhere else on the desktop.
void appendZOrder(std::wstring& text, HWND hwnd) {
    appendSection(text, L"Z 序");
    HWND root = ::GetAncestor(hwnd, GA_ROOT);
    int index = -1;
    int total = 0;
    for (HWND current = ::GetTopWindow(nullptr); current != nullptr; current = ::GetWindow(current, GW_HWNDNEXT)) {
        if (current == root && index < 0) {
            index = total;
        }
        ++total;
    }
    appendField(text, L"顶层 Z 序位置", index >= 0
        ? L"第 " + std::to_wstring(index + 1) + L" / 共 " + std::to_wstring(total) + L"（序号越小越靠上）"
        : std::wstring(L"未在顶层 Z 序中找到（可能是子窗口或已关闭）"));
    appendField(text, L"GetWindow(GW_HWNDPREV)", describeWindowBrief(::GetWindow(root, GW_HWNDPREV)));
    appendField(text, L"GetWindow(GW_HWNDNEXT)", describeWindowBrief(::GetWindow(root, GW_HWNDNEXT)));
    appendField(text, L"最顶层标志 WS_EX_TOPMOST",
        (static_cast<DWORD>(::GetWindowLongPtrW(hwnd, GWL_EXSTYLE)) & WS_EX_TOPMOST) != 0 ? L"是" : L"否");
}

void appendStyles(std::wstring& text, HWND hwnd) {
    const DWORD kStyle = static_cast<DWORD>(::GetWindowLongPtrW(hwnd, GWL_STYLE));
    const DWORD kExStyle = static_cast<DWORD>(::GetWindowLongPtrW(hwnd, GWL_EXSTYLE));
    const bool kIsChild = (kStyle & WS_CHILD) != 0;

    appendSection(text, L"窗口样式");
    appendField(text, L"GWL_STYLE", hexText(kStyle, 8));
    appendBits(text, decodeWindowStyleBits(kStyle, kIsChild));

    appendSection(text, L"扩展样式");
    appendField(text, L"GWL_EXSTYLE", hexText(kExStyle, 8));
    appendBits(text, decodeWindowExStyleBits(kExStyle));
}

// appendClassInfo reports the class through two different doors.
//
// GetClassLongPtr takes an HWND and therefore works for any window on the
// desktop. GetClassInfoExW takes a class name and only finds classes registered
// in this process or marked CS_GLOBALCLASS, so it fails for most foreign
// windows. Both are shown because the failure itself is information: it tells
// the user the class lives in another process, not that the query broke.
void appendClassInfo(std::wstring& text, HWND hwnd) {
    appendSection(text, L"类信息");
    const std::wstring kClassName = windowClassText(hwnd);
    const DWORD kClassStyle = static_cast<DWORD>(::GetClassLongPtrW(hwnd, GCL_STYLE));
    const ULONG_PTR kClassAtom = ::GetClassLongPtrW(hwnd, GCW_ATOM);
    const ULONG_PTR kClassWndProc = ::GetClassLongPtrW(hwnd, GCLP_WNDPROC);
    const LONG_PTR kWindowWndProc = ::GetWindowLongPtrW(hwnd, GWLP_WNDPROC);

    appendField(text, L"类名", kClassName);
    appendField(text, L"类原子 GCW_ATOM", hexText(kClassAtom, 4));
    appendField(text, L"类样式 GCL_STYLE", hexText(kClassStyle, 8));
    appendBits(text, decodeClassStyleBits(kClassStyle));
    appendField(text, L"类窗口过程 GCLP_WNDPROC", pointerText(static_cast<std::uint64_t>(kClassWndProc)));
    appendField(text, L"实例窗口过程 GWLP_WNDPROC",
        pointerText(static_cast<std::uint64_t>(static_cast<ULONG_PTR>(kWindowWndProc))));
    appendLine(text, kClassWndProc != static_cast<ULONG_PTR>(kWindowWndProc)
        ? L"    注：两者不同，通常说明该窗口被子类化。跨进程读到的可能是系统代理值，不能据此下结论。"
        : L"    注：两者相同，未观察到子类化痕迹。");
    appendField(text, L"类额外字节 GCL_CBCLSEXTRA",
        std::to_wstring(static_cast<std::uint64_t>(::GetClassLongPtrW(hwnd, GCL_CBCLSEXTRA))));
    appendField(text, L"窗口额外字节 GCL_CBWNDEXTRA",
        std::to_wstring(static_cast<std::uint64_t>(::GetClassLongPtrW(hwnd, GCL_CBWNDEXTRA))));

    WNDCLASSEXW classInfo{};
    classInfo.cbSize = sizeof(classInfo);
    bool resolved = false;
    if (!kClassName.empty()) {
        resolved = ::GetClassInfoExW(::GetModuleHandleW(nullptr), kClassName.c_str(), &classInfo) != FALSE;
        if (!resolved) {
            resolved = ::GetClassInfoExW(nullptr, kClassName.c_str(), &classInfo) != FALSE;
        }
    }
    if (resolved) {
        appendField(text, L"GetClassInfoExW", L"成功（该类在本进程可见）");
        appendField(text, L"  style", hexText(classInfo.style, 8));
        appendField(text, L"  lpfnWndProc", pointerText(reinterpret_cast<std::uint64_t>(classInfo.lpfnWndProc)));
        appendField(text, L"  cbClsExtra / cbWndExtra",
            std::to_wstring(classInfo.cbClsExtra) + L" / " + std::to_wstring(classInfo.cbWndExtra));
        appendField(text, L"  hInstance", pointerText(reinterpret_cast<std::uint64_t>(classInfo.hInstance)));
    } else {
        appendField(text, L"GetClassInfoExW",
            L"失败：该窗口类未在本进程注册，也不是全局类。上面基于 HWND 的字段仍然有效。");
    }
}

void appendGeometry(std::wstring& text, HWND hwnd) {
    appendSection(text, L"几何");
    RECT windowRect{};
    RECT clientRect{};
    ::GetWindowRect(hwnd, &windowRect);
    ::GetClientRect(hwnd, &clientRect);
    appendField(text, L"GetWindowRect（屏幕坐标）", rectText(windowRect));
    appendField(text, L"GetClientRect（客户区坐标）", rectText(clientRect));

    POINT clientOrigin{ 0, 0 };
    if (::ClientToScreen(hwnd, &clientOrigin)) {
        appendField(text, L"客户区左上角屏幕坐标",
            L"(" + std::to_wstring(clientOrigin.x) + L", " + std::to_wstring(clientOrigin.y) + L")");
        appendField(text, L"非客户区边距（左 / 上）",
            std::to_wstring(clientOrigin.x - windowRect.left) + L" / " +
            std::to_wstring(clientOrigin.y - windowRect.top));
    }
}

void appendDpi(std::wstring& text, HWND hwnd) {
    appendSection(text, L"DPI 感知");
    const DpiApi& api = loadDpiApi();
    if (api.getDpiForWindow) {
        const UINT kDpi = api.getDpiForWindow(hwnd);
        appendField(text, L"GetDpiForWindow", kDpi != 0
            ? std::to_wstring(kDpi) + L"（缩放 " + std::to_wstring(kDpi * 100 / 96) + L"%）"
            : std::wstring(L"0（调用失败）"));
    } else {
        appendField(text, L"GetDpiForWindow", L"本系统不提供该 API");
    }

    if (api.getWindowContext) {
        void* context = api.getWindowContext(hwnd);
        appendField(text, L"GetWindowDpiAwarenessContext", describeDpiContext(context));
        if (context && api.getDpiFromContext) {
            const UINT kContextDpi = api.getDpiFromContext(context);
            appendField(text, L"GetDpiFromDpiAwarenessContext",
                kContextDpi != 0 ? std::to_wstring(kContextDpi) : std::wstring(L"0（上下文非固定 DPI）"));
        }
    } else {
        appendField(text, L"GetWindowDpiAwarenessContext", L"本系统不提供该 API");
    }
}

std::wstring cloakStateText(const DWORD flags) {
    if (flags == 0) {
        return L"未 Cloak";
    }
    std::vector<std::wstring> sources;
    if ((flags & kDwmCloakedApp) != 0) {
        sources.push_back(L"应用");
    }
    if ((flags & kDwmCloakedShell) != 0) {
        sources.push_back(L"Shell");
    }
    if ((flags & kDwmCloakedInherited) != 0) {
        sources.push_back(L"继承");
    }
    std::wstring text = L"已 Cloak " + hexText(flags, 8);
    if (!sources.empty()) {
        text += L"（";
        for (std::size_t index = 0; index < sources.size(); ++index) {
            if (index != 0) {
                text += L" / ";
            }
            text += sources[index];
        }
        text += L"）";
    }
    return text;
}

std::wstring hresultText(const HRESULT status) {
    return hexText(static_cast<std::uint32_t>(status), 8);
}

std::wstring layeredFlagsText(const DWORD flags) {
    std::wstring text = hexText(flags, 8);
    std::vector<std::wstring> names;
    if ((flags & LWA_ALPHA) != 0) {
        names.push_back(L"LWA_ALPHA");
    }
    if ((flags & LWA_COLORKEY) != 0) {
        names.push_back(L"LWA_COLORKEY");
    }
    if (!names.empty()) {
        text += L"（";
        for (std::size_t index = 0; index < names.size(); ++index) {
            if (index != 0) {
                text += L" / ";
            }
            text += names[index];
        }
        text += L"）";
    }
    return text;
}

// appendCompositionState adds a small, explicit read-only composition block to
// the per-window report. Each query is independent so an unsupported DWM field
// never hides the documented User32 evidence or turns into a page-level error.
void appendCompositionState(std::wstring& text, HWND hwnd) {
    appendSection(text, L"合成与分层状态（只读）");

    const DwmApi& dwm = loadDwmApi();
    if (!dwm.getWindowAttribute) {
        appendField(text, L"DwmGetWindowAttribute", L"Unsupported（dwmapi.dll 或入口不可用）");
    } else {
        DWORD cloaked = 0;
        const HRESULT kCloakStatus = dwm.getWindowAttribute(hwnd, kDwmwaCloaked, &cloaked, sizeof(cloaked));
        appendField(text, L"DWMWA_CLOAKED", SUCCEEDED(kCloakStatus)
            ? cloakStateText(cloaked)
            : L"Partial（HRESULT " + hresultText(kCloakStatus) + L"）");

        RECT extendedFrame{};
        const HRESULT kFrameStatus = dwm.getWindowAttribute(
            hwnd, kDwmwaExtendedFrameBounds, &extendedFrame, sizeof(extendedFrame));
        appendField(text, L"DWMWA_EXTENDED_FRAME_BOUNDS", SUCCEEDED(kFrameStatus)
            ? rectText(extendedFrame)
            : L"Partial（HRESULT " + hresultText(kFrameStatus) + L"）");
    }

    DWORD affinity = WDA_NONE;
    ::SetLastError(ERROR_SUCCESS);
    if (::GetWindowDisplayAffinity(hwnd, &affinity)) {
        appendField(text, L"GetWindowDisplayAffinity", displayAffinityText(affinity, true));
    } else {
        appendField(text, L"GetWindowDisplayAffinity",
            L"Partial（Win32=" + std::to_wstring(::GetLastError()) + L"）");
    }

    const DWORD kExStyle = static_cast<DWORD>(::GetWindowLongPtrW(hwnd, GWL_EXSTYLE));
    if ((kExStyle & WS_EX_LAYERED) == 0) {
        appendField(text, L"GetLayeredWindowAttributes", L"不适用（未设置 WS_EX_LAYERED）");
    } else {
        COLORREF colorKey = 0;
        BYTE alpha = 0;
        DWORD flags = 0;
        ::SetLastError(ERROR_SUCCESS);
        if (::GetLayeredWindowAttributes(hwnd, &colorKey, &alpha, &flags)) {
            appendField(text, L"GetLayeredWindowAttributes",
                L"Alpha=" + std::to_wstring(alpha) +
                L"  ColorKey=" + hexText(colorKey, 8) +
                L"  Flags=" + layeredFlagsText(flags));
        } else {
            appendField(text, L"GetLayeredWindowAttributes",
                L"Partial（Win32=" + std::to_wstring(::GetLastError()) + L"）");
        }
    }
}

std::wstring buildHierarchyReport(HWND hwnd) {
    if (!hwnd) {
        return L"在左侧选择一个窗口，这里会显示它的祖先链、Z 序、样式位、类信息、几何与 DPI 感知上下文。";
    }
    if (!::IsWindow(hwnd)) {
        return L"该窗口句柄已失效（窗口已关闭）。请刷新窗口列表后重试。";
    }

    std::wstring text;
    appendBasics(text, hwnd);
    appendAncestry(text, hwnd);
    appendZOrder(text, hwnd);
    appendStyles(text, hwnd);
    appendClassInfo(text, hwnd);
    appendGeometry(text, hwnd);
    appendDpi(text, hwnd);
    appendCompositionState(text, hwnd);
    return text;
}

int selectedModelIndex(const HierarchyViewState& state) {
    const HWND kList = state.windowList.hwnd();
    const int kSelected = kList ? ListView_GetNextItem(kList, -1, LVNI_SELECTED) : -1;
    const auto& visible = state.windowList.visibleIndexes();
    if (kSelected < 0 || static_cast<std::size_t>(kSelected) >= visible.size()) {
        return -1;
    }
    const std::size_t kModelIndex = visible[static_cast<std::size_t>(kSelected)];
    return kModelIndex < state.windows.size() ? static_cast<int>(kModelIndex) : -1;
}

HWND selectedWindowHandle(const HierarchyViewState& state) {
    const int kIndex = selectedModelIndex(state);
    return kIndex >= 0 ? state.windows[static_cast<std::size_t>(kIndex)].hwnd : nullptr;
}

void showReportForSelection(HierarchyViewState& state) {
    if (!state.reportEdit) {
        return;
    }
    const std::wstring kReport = buildHierarchyReport(selectedWindowHandle(state));
    ::SetWindowTextW(state.reportEdit, kReport.c_str());
}

// selectRowAtPoint makes row commands act on the window under the pointer,
// instead of retaining a selection that belongs to a different HWND.
void selectRowAtPoint(HierarchyViewState& state, const POINT screenPoint) {
    const HWND kList = state.windowList.hwnd();
    if (!kList) {
        return;
    }
    POINT clientPoint = screenPoint;
    ::ScreenToClient(kList, &clientPoint);
    LVHITTESTINFO hit{};
    hit.pt = clientPoint;
    const int kClickedItem = ListView_SubItemHitTest(kList, &hit);
    ListView_SetItemState(kList, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    if (kClickedItem >= 0 && static_cast<std::size_t>(kClickedItem) < state.windowList.visibleIndexes().size()) {
        ListView_SetItemState(kList, kClickedItem, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    showReportForSelection(state);
}

// currentProcessIdForWindow re-reads the owner from the live HWND. A snapshot
// PID is deliberately not used because a window can close or be recycled while
// the diagnostics page is open.
DWORD currentProcessIdForWindow(const HWND hwnd) {
    if (!hwnd || !::IsWindow(hwnd)) {
        return 0;
    }
    DWORD processId = 0;
    return ::GetWindowThreadProcessId(hwnd, &processId) != 0U ? processId : 0U;
}

std::wstring stableKeyFromListItem(const HierarchyViewState& state, const int item) {
    const auto& visible = state.windowList.visibleIndexes();
    const auto& rows = state.windowList.rows();
    if (item < 0 || static_cast<std::size_t>(item) >= visible.size()) {
        return {};
    }
    const std::size_t kSourceIndex = visible[static_cast<std::size_t>(item)];
    return kSourceIndex < rows.size() ? rows[kSourceIndex].stableKey : std::wstring{};
}

void applyHierarchyFilter(HierarchyViewState& state, HierarchyFilterResult result) {
    if (result.generation != state.displayGeneration || result.query != state.filterQuery ||
        result.useRegex != state.filterUseRegex || !state.windowList.hwnd()) {
        return;
    }

    state.windowList.setVisibleIndexes(std::move(result.visibleIndexes));
    const auto& visible = state.windowList.visibleIndexes();
    const auto& rows = state.windowList.rows();
    int selectedItem = -1;
    for (std::size_t item = 0; item < visible.size(); ++item) {
        const std::size_t kSourceIndex = visible[item];
        if (kSourceIndex < rows.size() && rows[kSourceIndex].stableKey == result.selectedStableKey) {
            selectedItem = static_cast<int>(item);
            break;
        }
    }

    HWND list = state.windowList.hwnd();
    ListView_SetItemState(list, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    if (selectedItem >= 0) {
        ListView_SetItemState(list, selectedItem, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(list, selectedItem, FALSE);
    } else if (!visible.empty()) {
        ListView_SetItemState(list, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    showReportForSelection(state);
    if (!result.query.empty()) {
        state.statusText = L"筛选结果 " + std::to_wstring(visible.size()) + L" / " +
            std::to_wstring(rows.size()) + L" 个窗口。";
    }
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

void requestHierarchyFilter(HierarchyViewState& state, std::wstring query, std::wstring selectedStableKey) {
    state.filterQuery = std::move(query);
    state.filterUseRegex = ksword::ui::getFilterBarRegexEnabled(state.filterBar);
    const auto kRows = state.filterRows;
    const std::uint64_t kGeneration = state.displayGeneration;
    const bool kUseRegex = state.filterUseRegex;
    if (!state.filterTask || !kRows) {
        return;
    }
    state.filterTask->request(
        [kRows, kGeneration, kUseRegex, query = state.filterQuery,
            selectedStableKey = std::move(selectedStableKey)]() mutable {
            HierarchyFilterResult result{};
            result.generation = kGeneration;
            result.query = std::move(query);
            result.useRegex = kUseRegex;
            result.selectedStableKey = std::move(selectedStableKey);
            result.visibleIndexes = ksword::ui::VirtualListView::filterRowIndexes(*kRows, result.query, kUseRegex);
            return result;
        },
        [&state](std::uint64_t, std::optional<HierarchyFilterResult>&& result, std::exception_ptr error) {
            if (error || !result.has_value()) {
                state.statusText = L"窗口筛选任务异常结束，已保留当前结果。";
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            applyHierarchyFilter(state, std::move(*result));
        });
}

void buildRows(HierarchyViewState& state) {
    std::vector<ksword::ui::VirtualListRow> rows;
    rows.reserve(state.windows.size());
    for (std::size_t index = 0; index < state.windows.size(); ++index) {
        const TopLevelWindowInfo& info = state.windows[index];
        ksword::ui::VirtualListRow row{};
        row.stableKey = hwndText(info.hwnd);
        row.itemData = static_cast<LPARAM>(index);
        row.cells.reserve(kColumnCount);
        row.cells.push_back(hwndText(info.hwnd));
        row.cells.push_back(info.title.empty() ? L"(无标题)" : info.title);
        row.cells.push_back(info.className);
        row.cells.push_back(std::to_wstring(info.processId));
        row.cells.push_back(info.processName);
        rows.push_back(std::move(row));
    }
    auto shared = std::make_shared<std::vector<ksword::ui::VirtualListRow>>(std::move(rows));
    state.windowList.setRows(*shared);
    state.filterRows = std::move(shared);
    ++state.displayGeneration;
}

void beginRefresh(HierarchyViewState& state) {
    if (!state.refreshTask) {
        return;
    }
    const bool kFirstLoad = state.windowList.rows().empty();
    state.statusText = state.refreshTask->running() ? L"刷新已排队，等待当前快照完成…" : L"正在后台枚举顶层窗口…";
    if (state.refreshButton) {
        ::EnableWindow(state.refreshButton, FALSE);
    }
    if (kFirstLoad) {
        ksword::ui::setLoadingOverlay(state.loadingOverlay, true, L"正在枚举顶层窗口…");
    }
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
    state.refreshTask->request(
        [] { return enumerateTopLevelWindowInfo(); },
        [&state](std::uint64_t, std::optional<std::vector<TopLevelWindowInfo>>&& snapshot, std::exception_ptr error) {
            if (state.refreshButton) {
                ::EnableWindow(state.refreshButton, TRUE);
            }
            ksword::ui::setLoadingOverlay(state.loadingOverlay, false);
            if (error || !snapshot.has_value()) {
                state.statusText = L"窗口枚举异常结束。";
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            const std::wstring kSelectedStableKey =
                stableKeyFromListItem(state, ListView_GetNextItem(state.windowList.hwnd(), -1, LVNI_SELECTED));
            const std::size_t kTotal = snapshot->size();
            state.windows = std::move(*snapshot);
            buildRows(state);
            state.statusText = L"共 " + std::to_wstring(kTotal) + L" 个顶层窗口，选中一行查看完整诊断。";
            requestHierarchyFilter(state,
                state.filterBar ? ksword::ui::getFilterBarText(state.filterBar) : state.filterQuery,
                kSelectedStableKey);
            ::InvalidateRect(state.hwnd, nullptr, TRUE);
        });
}

std::wstring reportText(const HierarchyViewState& state) {
    const int kLength = state.reportEdit ? ::GetWindowTextLengthW(state.reportEdit) : 0;
    if (kLength <= 0) {
        return {};
    }
    std::wstring text(static_cast<std::size_t>(kLength) + 1U, L'\0');
    const int kCopied = ::GetWindowTextW(state.reportEdit, text.data(), kLength + 1);
    text.resize(kCopied > 0 ? static_cast<std::size_t>(kCopied) : 0U);
    return text;
}

void exportVisibleRows(HierarchyViewState& state) {
    const std::wstring kText = ksword::ui::buildVisibleVirtualListTsv(
        { L"窗口句柄", L"标题", L"类名", L"PID", L"进程" }, state.windowList);
    if (kText.empty()) {
        state.statusText = L"没有可导出的可见结果。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }
    std::wstring error;
    switch (ksword::ui::saveUtf8TextFileWithDialog(state.hwnd, L"window_hierarchy.tsv", L"导出窗口层级诊断",
        L"TSV (*.tsv)\0*.tsv\0All Files (*.*)\0*.*\0", L"tsv", kText, &error)) {
    case ksword::ui::SaveTextFileResult::kSaved: state.statusText = L"窗口层级可见结果已导出。"; break;
    case ksword::ui::SaveTextFileResult::kCancelled: state.statusText = L"已取消导出窗口层级结果。"; break;
    case ksword::ui::SaveTextFileResult::kFailed: state.statusText = L"导出窗口层级结果失败：" + error; break;
    }
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

// openSelectedWindowProcess routes only the current owner PID observed from a
// live HWND. The process page resolves that PID again before it opens details.
void openSelectedWindowProcess(HierarchyViewState& state) {
    const HWND kHwnd = selectedWindowHandle(state);
    const DWORD kProcessId = currentProcessIdForWindow(kHwnd);
    if (kProcessId == 0U) {
        state.statusText = L"所选窗口已关闭或无法读取当前所属 PID。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }

    ksword::core::NavigationRequest request{};
    request.target = ksword::core::NavigationTarget::kProcessDetails;
    request.entity.kind = ksword::core::EntityKind::kProcess;
    request.entity.id = kProcessId;
    state.statusText = ksword::ui::requestEntityNavigation(state.hwnd, request)
        ? L"已请求打开当前窗口所属 PID " + std::to_wstring(kProcessId) +
            L" 的进程详细信息；目标页会重新确认当前进程实例。"
        : L"无法导航到当前窗口所属的进程实例。";
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

void showContextMenu(HierarchyViewState& state, const POINT screenPoint) {
    selectRowAtPoint(state, screenPoint);
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    const HWND kSelectedWindow = selectedWindowHandle(state);
    const bool kHasSelection = kSelectedWindow != nullptr;
    const bool kHasCurrentProcess = currentProcessIdForWindow(kSelectedWindow) != 0U;
    ::AppendMenuW(menu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyReport, L"复制诊断报告");
    ::AppendMenuW(menu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制选中行");
    ::AppendMenuW(menu, MF_STRING, kMenuCopyVisible, L"复制可见行");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING | (kHasCurrentProcess ? MF_ENABLED : MF_GRAYED),
        kMenuOpenProcess, L"查看当前窗口所属进程的详细信息");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING, kMenuRefresh, L"刷新");

    const int kCommand = ::TrackPopupMenu(
        menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y, 0, state.hwnd, nullptr);
    ::DestroyMenu(menu);

    switch (static_cast<UINT>(kCommand)) {
    case kMenuCopyReport:
        state.statusText = copyTextToClipboard(state.hwnd, reportText(state)) ? L"已复制诊断报告。" : L"复制失败。";
        break;
    case kMenuCopyRow:
        state.statusText = copyTextToClipboard(state.hwnd, rowsAsTsv(state.windowList, false, kColumnCount))
            ? L"已复制选中行。" : L"复制失败。";
        break;
    case kMenuCopyVisible:
        state.statusText = copyTextToClipboard(state.hwnd, rowsAsTsv(state.windowList, true, kColumnCount))
            ? L"已复制可见行。" : L"复制失败。";
        break;
    case kMenuOpenProcess:
        openSelectedWindowProcess(state);
        return;
    case kMenuRefresh:
        beginRefresh(state);
        return;
    default:
        return;
    }
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

void layoutView(HierarchyViewState& state) {
    RECT client{};
    ::GetClientRect(state.hwnd, &client);
    const int kWidth = width(client);
    const int kHeight = height(client);

    int cursorX = kGap;
    if (state.refreshButton) {
        ::MoveWindow(state.refreshButton, cursorX, kGap, 64, kRowHeight, TRUE);
    }
    cursorX += 64 + kGap;
    if (state.exportButton) {
        ::MoveWindow(state.exportButton, cursorX, kGap, 78, kRowHeight, TRUE);
    }
    const int kSecondRowY = kGap * 2 + kRowHeight;
    if (state.filterBar) {
        ::MoveWindow(state.filterBar, kGap, kSecondRowY, (std::max)(120, kWidth - kGap * 2), kRowHeight, TRUE);
    }

    const int kContentTop = kHeaderHeight;
    const int kContentHeight = (std::max)(0, kHeight - kStatusHeight - kContentTop - kGap);
    const int kListWidth = (std::max)(160, (kWidth - kGap * 3) * 45 / 100);
    if (HWND list = state.windowList.hwnd()) {
        ::MoveWindow(list, kGap, kContentTop, kListWidth, kContentHeight, TRUE);
    }
    if (state.loadingOverlay) {
        ::MoveWindow(state.loadingOverlay, kGap, kContentTop, kListWidth, kContentHeight, TRUE);
    }
    if (state.reportEdit) {
        const int kReportLeft = kGap * 2 + kListWidth;
        ::MoveWindow(state.reportEdit, kReportLeft, kContentTop,
            (std::max)(0, kWidth - kReportLeft - kGap), kContentHeight, TRUE);
    }
}

bool createChildControls(HierarchyViewState& state) {
    HWND hwnd = state.hwnd;
    state.refreshButton = ksword::ui::createButton(hwnd, kRefreshButtonId, L"刷新", 0, 0, 0, 0);
    state.exportButton = ksword::ui::createButton(hwnd, kExportButtonId, L"导出 TSV", 0, 0, 0, 0);
    state.filterBar = ksword::ui::createFilterBar(hwnd, kFilterBarId, L"筛选句柄、标题、类名与进程", 0, 0, 0, 0);
    if (!state.refreshButton || !state.exportButton || !state.filterBar) {
        return false;
    }

    if (!state.windowList.create(hwnd, kWindowListId, 0, 0, 1, 1, LVS_SHOWSELALWAYS | LVS_SINGLESEL)) {
        return false;
    }
    state.windowList.addColumns({
        { 0, 130, LVCFMT_LEFT, L"窗口句柄" },
        { 1, 220, LVCFMT_LEFT, L"标题" },
        { 2, 170, LVCFMT_LEFT, L"类名" },
        { 3, 70,  LVCFMT_RIGHT, L"PID" },
        { 4, 150, LVCFMT_LEFT, L"进程" },
    });
    if (HWND list = state.windowList.hwnd()) {
        ListView_SetExtendedListViewStyle(list,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);
    }

    state.reportEdit = ::CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | WS_HSCROLL |
            ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_READONLY,
        0, 0, 1, 1, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kReportEditId)),
        ::GetModuleHandleW(nullptr), nullptr);
    if (!state.reportEdit) {
        return false;
    }
    ksword::ui::attachTextFindSupport(state.reportEdit);

    state.loadingOverlay = ksword::ui::createLoadingOverlay(hwnd, kLoadingOverlayId, { 0, 0, 1, 1 });
    if (!state.loadingOverlay) {
        return false;
    }

    ksword::ui::setWindowFontRecursive(hwnd);
    return true;
}

LRESULT CALLBACK hierarchyViewProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    auto* state = reinterpret_cast<HierarchyViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (msg) {
    case WM_NCCREATE: {
        auto owned = std::make_unique<HierarchyViewState>();
        owned->hwnd = hwnd;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(owned.release()));
        return TRUE;
    }
    case WM_CREATE:
        if (state) {
            if (!createChildControls(*state)) {
                return -1;
            }
            state->refreshTask =
                std::make_unique<ksword::ui::AsyncSnapshotTask<std::vector<TopLevelWindowInfo>>>(hwnd, kMsgRefreshCompleted);
            state->filterTask =
                std::make_unique<ksword::ui::AsyncSnapshotTask<HierarchyFilterResult>>(hwnd, kMsgFilterCompleted);
            layoutView(*state);
            showReportForSelection(*state);
            beginRefresh(*state);
        }
        return 0;
    case WM_SIZE:
        if (state) {
            layoutView(*state);
        }
        return 0;
    case WM_COMMAND:
        if (state) {
            const int kId = LOWORD(wParam);
            const int kNotification = HIWORD(wParam);
            if (kId == kFilterBarId && kNotification == EN_CHANGE) {
                requestHierarchyFilter(*state, ksword::ui::getFilterBarText(state->filterBar),
                    stableKeyFromListItem(*state, ListView_GetNextItem(state->windowList.hwnd(), -1, LVNI_SELECTED)));
                return 0;
            }
            if (kNotification == BN_CLICKED && kId == kRefreshButtonId) {
                beginRefresh(*state);
                return 0;
            }
            if (kNotification == BN_CLICKED && kId == kExportButtonId) {
                exportVisibleRows(*state);
                return 0;
            }
        }
        break;
    case WM_NOTIFY:
        if (state) {
            const auto* header = reinterpret_cast<const NMHDR*>(lParam);
            if (header) {
                LRESULT result = 0;
                if (state->windowList.handleNotify(*header, result)) {
                    return result;
                }
                if (header->hwndFrom == state->windowList.hwnd() && header->code == LVN_ITEMCHANGED) {
                    const auto* changed = reinterpret_cast<const NMLISTVIEW*>(lParam);
                    if (changed && (changed->uNewState & LVIS_SELECTED) != 0) {
                        showReportForSelection(*state);
                    }
                    return 0;
                }
                if (header->hwndFrom == state->windowList.hwnd() && header->code == NM_RCLICK) {
                    POINT point{};
                    ::GetCursorPos(&point);
                    showContextMenu(*state, point);
                    return 0;
                }
            }
        }
        break;
    case WM_CTLCOLORSTATIC: {
        HDC dc = reinterpret_cast<HDC>(wParam);
        ::SetTextColor(dc, ksword::ui::appTheme().textColor);
        if (state && reinterpret_cast<HWND>(lParam) == state->reportEdit) {
            ::SetBkColor(dc, ksword::ui::appTheme().panelColor);
            return reinterpret_cast<LRESULT>(ksword::ui::appTheme().panelBrush());
        }
        ::SetBkMode(dc, TRANSPARENT);
        return reinterpret_cast<LRESULT>(ksword::ui::appTheme().windowBrush());
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT:
        if (state) {
            PAINTSTRUCT paint{};
            HDC dc = ::BeginPaint(hwnd, &paint);
            RECT client{};
            ::GetClientRect(hwnd, &client);
            ::FillRect(dc, &client, ksword::ui::appTheme().windowBrush());
            RECT statusRect{ kGap, client.bottom - kStatusHeight, client.right - kGap, client.bottom };
            ksword::ui::drawTextLine(dc, state->statusText, statusRect,
                ksword::ui::appTheme().mutedTextColor, ksword::ui::systemUiFont(),
                DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
            ::EndPaint(hwnd, &paint);
            return 0;
        }
        break;
    default:
        if (state) {
            if (msg == kMsgRefreshCompleted && state->refreshTask) {
                state->refreshTask->consume(hwnd, wParam, lParam);
                return 0;
            }
            if (msg == kMsgFilterCompleted && state->filterTask) {
                state->filterTask->consume(hwnd, wParam, lParam);
                return 0;
            }
        }
        if (msg == WM_NCDESTROY && state) {
            if (state->refreshTask) {
                state->refreshTask->cancel();
            }
            if (state->filterTask) {
                state->filterTask->cancel();
            }
            state->windowList.detach();
            delete state;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        }
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

bool ensureHierarchyViewClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = hierarchyViewProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = ksword::ui::appTheme().windowBrush();
    windowClass.lpszClassName = kHierarchyViewClass;
    registered = ::RegisterClassW(&windowClass) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

struct HierarchyReportViewState final {
    HWND hwnd = nullptr;
    HWND reportEdit = nullptr;
};

HierarchyReportViewState* reportStateFromWindow(HWND hwnd) {
    return reinterpret_cast<HierarchyReportViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

void layoutHierarchyReportView(HierarchyReportViewState& state) {
    RECT client{};
    ::GetClientRect(state.hwnd, &client);
    const int kWidth = width(client);
    const int kHeight = height(client);
    if (state.reportEdit) {
        ::MoveWindow(state.reportEdit, kGap, 30, (std::max)(1, kWidth - kGap * 2),
            (std::max)(1, kHeight - 30 - kGap), TRUE);
    }
}

LRESULT CALLBACK hierarchyReportViewProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    HierarchyReportViewState* state = reportStateFromWindow(hwnd);
    if (msg == WM_NCCREATE) {
        auto owned = std::make_unique<HierarchyReportViewState>();
        owned->hwnd = hwnd;
        state = owned.get();
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(owned.release()));
    }
    switch (msg) {
    case WM_NCCREATE:
        return TRUE;
    case WM_CREATE:
        if (!state) {
            return -1;
        }
        state->reportEdit = ::CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | WS_HSCROLL |
                ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_READONLY,
            0, 0, 1, 1, hwnd, nullptr, ::GetModuleHandleW(nullptr), nullptr);
        if (!state->reportEdit) {
            return -1;
        }
        ksword::ui::attachTextFindSupport(state->reportEdit);
        ksword::ui::setWindowFontRecursive(hwnd);
        ::SetWindowTextW(state->reportEdit, buildHierarchyReport(nullptr).c_str());
        layoutHierarchyReportView(*state);
        return 0;
    case WM_SIZE:
        if (state) {
            layoutHierarchyReportView(*state);
        }
        return 0;
    case WM_CTLCOLORSTATIC: {
        HDC dc = reinterpret_cast<HDC>(wParam);
        ::SetTextColor(dc, ksword::ui::appTheme().textColor);
        if (state && reinterpret_cast<HWND>(lParam) == state->reportEdit) {
            ::SetBkColor(dc, ksword::ui::appTheme().panelColor);
            return reinterpret_cast<LRESULT>(ksword::ui::appTheme().panelBrush());
        }
        ::SetBkMode(dc, TRANSPARENT);
        return reinterpret_cast<LRESULT>(ksword::ui::appTheme().windowBrush());
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT:
        if (state) {
            PAINTSTRUCT paint{};
            HDC dc = ::BeginPaint(hwnd, &paint);
            RECT client{};
            ::GetClientRect(hwnd, &client);
            ::FillRect(dc, &client, ksword::ui::appTheme().windowBrush());
            RECT titleRect{ kGap, 0, client.right - kGap, 30 };
            ksword::ui::drawTextLine(dc, L"窗口层级诊断（跟随左侧窗口选择）", titleRect,
                ksword::ui::appTheme().textColor, ksword::ui::systemUiFont(),
                DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
            ::EndPaint(hwnd, &paint);
            return 0;
        }
        break;
    case WM_NCDESTROY:
        delete state;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        return 0;
    default:
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

bool ensureHierarchyReportViewClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = hierarchyReportViewProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = ksword::ui::appTheme().windowBrush();
    windowClass.lpszClassName = kHierarchyReportViewClass;
    registered = ::RegisterClassW(&windowClass) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

} // namespace

HWND createWindowHierarchyView(HWND parent, const RECT& bounds) {
    if (!parent || !ensureHierarchyViewClass()) {
        return nullptr;
    }
    return ::CreateWindowExW(
        0, kHierarchyViewClass, L"", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        bounds.left, bounds.top, bounds.right - bounds.left, bounds.bottom - bounds.top,
        parent, nullptr, ::GetModuleHandleW(nullptr), nullptr);
}

HWND createWindowHierarchyReportView(HWND parent, const RECT& bounds) {
    if (!parent || !ensureHierarchyReportViewClass()) {
        return nullptr;
    }
    return ::CreateWindowExW(
        0, kHierarchyReportViewClass, L"", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        bounds.left, bounds.top, bounds.right - bounds.left, bounds.bottom - bounds.top,
        parent, nullptr, ::GetModuleHandleW(nullptr), nullptr);
}

void updateWindowHierarchyReportView(HWND reportView, HWND selectedWindow) {
    HierarchyReportViewState* state = reportStateFromWindow(reportView);
    if (!state || !state->reportEdit) {
        return;
    }
    const std::wstring kReport = buildHierarchyReport(selectedWindow);
    ::SetWindowTextW(state->reportEdit, kReport.c_str());
}

} // namespace Ksword::Features::window_tools
