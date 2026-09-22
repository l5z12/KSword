#include "ProcessDetailPage.h"
#include "../../core/Common.h"
#include "../../ui/FilterBar.h"

#include "../../ui/Controls.h"
#include "../../ui/ExportUtil.h"
#include "../../ui/NumericSortKey.h"
#include "../../ui/TextFindSupport.h"
#include "../../ui/Theme.h"

#include <commctrl.h>
#include <shellapi.h>
#include <windowsx.h>

#include <algorithm>
#include <chrono>
#include <cwctype>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <iomanip>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

namespace ksword::features::process_detail {
namespace {

constexpr UINT kModuleMenuCopyCell = 64101;
constexpr UINT kModuleMenuCopyRow = 64102;
constexpr UINT kModuleMenuDetail = 64103;
constexpr UINT kModuleMenuOpenFolder = 64104;
constexpr UINT kModuleMenuUnload = 64105;
constexpr UINT kModuleMenuSuspendThread = 64106;
constexpr UINT kModuleMenuResumeThread = 64107;
constexpr UINT kModuleMenuTerminateThread = 64108;

constexpr UINT_PTR kModulePageVisualSubclassId = 0x4D4F4455U; // "MODU"
constexpr UINT_PTR kModuleHeaderSubclassId = 0x4D4F4448U;     // "MODH"
constexpr UINT_PTR kModuleStatusSubclassId = 0x4D4F4453U;     // "MODS"

constexpr wchar_t kModuleDetailClass[] = L"KswordARKLight.ProcessDetail.ModuleDetail";
constexpr int kModuleDetailSummaryId = 65101;
constexpr int kModuleDetailEditId = 65102;
constexpr int kModuleDetailCopyId = 65103;
constexpr int kModuleDetailOpenFolderId = 65104;
constexpr int kModuleDetailCloseId = 65105;

struct ModuleDetailDialogState {
    HWND hwnd = nullptr;
    HWND summary = nullptr;
    HWND edit = nullptr;
    HWND copyButton = nullptr;
    HWND openFolderButton = nullptr;
    HWND closeButton = nullptr;
    std::wstring summaryText;
    std::wstring detailText;
    std::wstring modulePath;
};

// readControlText returns one native control's complete UTF-16 text. The
// caller owns the returned value and no HWND lifetime is retained.
std::wstring readControlText(HWND hwnd) {
    if (!hwnd) {
        return {};
    }
    const int kLength = ::GetWindowTextLengthW(hwnd);
    std::wstring text(static_cast<std::size_t>(std::max(0, kLength)) + 1U, L'\0');
    ::GetWindowTextW(hwnd, text.data(), static_cast<int>(text.size()));
    text.resize(std::wcslen(text.c_str()));
    return text;
}

// readListCell is the module-local equivalent of the root list helper. It is
// used by native header sorting and custom draw callbacks that are not class
// members and therefore cannot access private ProcessDetailPage helpers.
std::wstring readListCell(HWND list, int row, int column) {
    if (!list || row < 0 || column < 0) {
        return {};
    }
    std::vector<wchar_t> buffer(8192U, L'\0');
    ListView_GetItemText(list, row, column, buffer.data(), static_cast<int>(buffer.size()));
    return buffer.data();
}

// selectedSnapshotIndex returns the stable snapshot index stored in LVITEM's
// lParam. Sorting changes visual row order but never changes this identity.
std::size_t selectedSnapshotIndex(HWND list) {
    if (!list) {
        return static_cast<std::size_t>(-1);
    }
    const int kRow = ListView_GetNextItem(list, -1, LVNI_SELECTED);
    if (kRow < 0) {
        return static_cast<std::size_t>(-1);
    }
    LVITEMW item{};
    item.mask = LVIF_PARAM;
    item.iItem = kRow;
    if (!ListView_GetItem(list, &item) || item.lParam < 0) {
        return static_cast<std::size_t>(-1);
    }
    return static_cast<std::size_t>(item.lParam);
}

std::wstring baseNameFromPath(const std::wstring& path) {
    const std::size_t kSeparator = path.find_last_of(L"\\/");
    if (kSeparator == std::wstring::npos || kSeparator + 1U >= path.size()) {
        return path;
    }
    return path.substr(kSeparator + 1U);
}

std::wstring formatHex(std::uintptr_t value) {
    std::wostringstream text;
    text << L"0x" << std::uppercase << std::hex << value;
    return text.str();
}

std::wstring formatModuleSize(DWORD bytes) {
    const double kKilobytes = static_cast<double>(bytes) / 1024.0;
    std::wostringstream text;
    if (kKilobytes < 1024.0) {
        text << std::fixed << std::setprecision(1) << kKilobytes << L" KB";
    } else {
        text << std::fixed << std::setprecision(2) << (kKilobytes / 1024.0) << L" MB";
    }
    return text.str();
}

std::wstring moduleSignatureText(bool requested) {
    // The frozen ProcessModuleInfo model has no signature result field. Make
    // that boundary explicit instead of presenting the collector status as a
    // cryptographic trust decision.
    return requested ? L"Unavailable" : L"Pending";
}

std::wstring moduleRunningState(const ProcessModuleInfo& module) {
    return module.statusText == L"OK" ? L"Loaded" : L"Unknown";
}

std::wstring moduleThreadText(const ProcessModuleInfo& module) {
    return module.representativeThreadId == 0
        ? L"-"
        : std::to_wstring(module.representativeThreadId);
}

std::wstring lastErrorText(const wchar_t* operation, DWORD error) {
    wchar_t* systemText = nullptr;
    const DWORD kFlags = FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    ::FormatMessageW(
        kFlags,
        nullptr,
        error,
        0,
        reinterpret_cast<LPWSTR>(&systemText),
        0,
        nullptr);
    std::wstring result = operation ? operation : L"Win32 operation";
    result += L" failed";
    if (systemText) {
        result += L": ";
        result += systemText;
        while (!result.empty() &&
               (result.back() == L'\r' || result.back() == L'\n' || result.back() == L' ')) {
            result.pop_back();
        }
        ::LocalFree(systemText);
    } else {
        result += L" (" + std::to_wstring(error) + L")";
    }
    return result;
}

bool writeClipboardText(HWND owner, const std::wstring& text) {
    return ksword::ui::copyTextToClipboard(owner, text, L"进程模块详情");
}

bool openFolderAndSelectPath(HWND owner, const std::wstring& path) {
    if (path.empty() || path.front() == L'<') {
        return false;
    }
    const std::wstring kParameters = L"/select,\"" + path + L"\"";
    const HINSTANCE kResult = ::ShellExecuteW(
        owner,
        L"open",
        L"explorer.exe",
        kParameters.c_str(),
        nullptr,
        SW_SHOWNORMAL);
    return reinterpret_cast<INT_PTR>(kResult) > 32;
}

void updateSortIndicator(HWND list, int sortColumn, bool descending) {
    HWND header = list ? ListView_GetHeader(list) : nullptr;
    const int kCount = header ? Header_GetItemCount(header) : 0;
    for (int index = 0; index < kCount; ++index) {
        HDITEMW item{};
        item.mask = HDI_FORMAT;
        if (!Header_GetItem(header, index, &item)) {
            continue;
        }
        item.fmt &= ~(HDF_SORTUP | HDF_SORTDOWN);
        if (index == sortColumn) {
            item.fmt |= descending ? HDF_SORTDOWN : HDF_SORTUP;
        }
        Header_SetItem(header, index, &item);
    }
}

COLORREF signatureColor(const std::wstring& text) {
    if (text == L"Pending" || text == L"Unknown" || text == L"Unavailable" || text.empty()) {
        return ksword::ui::appTheme().mutedTextColor;
    }
    if (text.find(L"Trusted") != std::wstring::npos ||
        text.find(L"Valid") != std::wstring::npos ||
        text.find(L"可信") != std::wstring::npos ||
        text.find(L"有效") != std::wstring::npos) {
        return RGB(24, 128, 56);
    }
    return RGB(196, 43, 28);
}

LRESULT CALLBACK modulePageVisualSubclassProc(
    HWND hwnd,
    UINT message,
    WPARAM wParam,
    LPARAM lParam,
    UINT_PTR subclassId,
    DWORD_PTR referenceData) {
    HWND moduleList = reinterpret_cast<HWND>(referenceData);
    if (message == WM_NOTIFY) {
        auto* header = reinterpret_cast<NMHDR*>(lParam);
        if (header && header->hwndFrom == moduleList && header->code == NM_CUSTOMDRAW) {
            auto* draw = reinterpret_cast<NMLVCUSTOMDRAW*>(lParam);
            const DWORD kStage = draw->nmcd.dwDrawStage;
            if (kStage == CDDS_PREPAINT) {
                return CDRF_NOTIFYITEMDRAW;
            }
            if (kStage == CDDS_ITEMPREPAINT) {
                return CDRF_NOTIFYSUBITEMDRAW;
            }
            if (kStage == (CDDS_ITEMPREPAINT | CDDS_SUBITEM)) {
                const bool kSelected = (draw->nmcd.uItemState & CDIS_SELECTED) != 0;
                if (kSelected) {
                    draw->clrText = ::GetSysColor(COLOR_HIGHLIGHTTEXT);
                    draw->clrTextBk = ::GetSysColor(COLOR_HIGHLIGHT);
                } else {
                    draw->clrText = ksword::ui::appTheme().textColor;
                    draw->clrTextBk = (draw->nmcd.dwItemSpec % 2U) == 0U
                        ? ksword::ui::appTheme().panelColor
                        : ksword::ui::appTheme().windowColor;
                    if (draw->iSubItem == 2) {
                        draw->clrText = signatureColor(readListCell(
                            moduleList,
                            static_cast<int>(draw->nmcd.dwItemSpec),
                            2));
                    }
                }
                return CDRF_NEWFONT;
            }
        }
    }
    if (message == WM_NCDESTROY) {
        ::RemoveWindowSubclass(hwnd, modulePageVisualSubclassProc, subclassId);
    }
    return ::DefSubclassProc(hwnd, message, wParam, lParam);
}

LRESULT CALLBACK moduleStatusSubclassProc(
    HWND hwnd,
    UINT message,
    WPARAM wParam,
    LPARAM lParam,
    UINT_PTR subclassId,
    DWORD_PTR referenceData) {
    (void)referenceData;
    if (message == WM_SETTEXT) {
        const LRESULT kResult = ::DefSubclassProc(hwnd, message, wParam, lParam);
        ::InvalidateRect(hwnd, nullptr, TRUE);
        return kResult;
    }
    if (message == WM_ERASEBKGND) {
        return 1;
    }
    if (message == WM_PAINT) {
        PAINTSTRUCT paint{};
        HDC dc = ::BeginPaint(hwnd, &paint);
        RECT client{};
        ::GetClientRect(hwnd, &client);
        ::FillRect(dc, &client, ksword::ui::appTheme().windowBrush());
        ::SetBkMode(dc, TRANSPARENT);
        const std::wstring kText = readControlText(hwnd);
        COLORREF color = RGB(24, 128, 56);
        if (kText.find(L"正在") != std::wstring::npos) {
            color = ksword::ui::appTheme().accentColor;
        } else if (kText.find(L"失败") != std::wstring::npos ||
                   kText.find(L"模块:0") != std::wstring::npos) {
            color = RGB(196, 43, 28);
        } else if (kText.find(L"等待") != std::wstring::npos) {
            color = ksword::ui::appTheme().mutedTextColor;
        }
        ::SetTextColor(dc, color);
        HFONT font = reinterpret_cast<HFONT>(::SendMessageW(hwnd, WM_GETFONT, 0, 0));
        HGDIOBJ oldFont = font ? ::SelectObject(dc, font) : nullptr;
        ::DrawTextW(
            dc,
            kText.c_str(),
            static_cast<int>(kText.size()),
            &client,
            DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
        if (oldFont) {
            ::SelectObject(dc, oldFont);
        }
        ::EndPaint(hwnd, &paint);
        return 0;
    }
    if (message == WM_NCDESTROY) {
        ::RemoveWindowSubclass(hwnd, moduleStatusSubclassProc, subclassId);
    }
    return ::DefSubclassProc(hwnd, message, wParam, lParam);
}

int systemIconIndexForPath(const std::wstring& path, HIMAGELIST* imageListOut) {
    SHFILEINFOW info{};
    UINT flags = SHGFI_SYSICONINDEX | SHGFI_SMALLICON;
    DWORD attributes = 0;
    if (path.empty() || path.front() == L'<') {
        flags |= SHGFI_USEFILEATTRIBUTES;
        attributes = FILE_ATTRIBUTE_NORMAL;
    }
    const DWORD_PTR kResult = ::SHGetFileInfoW(
        path.empty() ? L"module.dll" : path.c_str(),
        attributes,
        &info,
        sizeof(info),
        flags);
    if (imageListOut && kResult != 0) {
        *imageListOut = reinterpret_cast<HIMAGELIST>(kResult);
    }
    return kResult != 0 ? info.iIcon : -1;
}

std::vector<ksword::ui::VirtualListRow> buildModuleVirtualRows(
    const std::vector<ProcessModuleInfo>& modules,
    const bool verifySignatures,
    const int sortColumn,
    const bool sortDescending,
    HIMAGELIST& imageListOut) {
    std::vector<ksword::ui::VirtualListRow> rows;
    rows.reserve(modules.size());
    for (std::size_t index = 0; index < modules.size(); ++index) {
        const ProcessModuleInfo& module = modules[index];
        ksword::ui::VirtualListRow row{};
        row.stableKey = module.modulePath + L"\n" + formatHex(module.baseAddress);
        row.itemData = static_cast<LPARAM>(index);
        row.cells = {
            module.modulePath,
            formatModuleSize(module.imageSize),
            moduleSignatureText(verifySignatures),
            L"Unavailable",
            moduleRunningState(module),
            moduleThreadText(module)
        };
        HIMAGELIST rowImages = nullptr;
        row.imageIndex = systemIconIndexForPath(module.modulePath, &rowImages);
        if (!imageListOut && rowImages) {
            imageListOut = rowImages;
        }
        rows.push_back(std::move(row));
    }
    const int kColumn = std::clamp(sortColumn, 0, 5);
    // The size and thread-count columns are numeric, and an ordinal compare
    // ordered them by printed characters: "512.0 KiB" sorted after "4.0 MiB"
    // and 9 threads after 10. compareCellsNumericAware reads the leading number
    // back out of the cell and only falls back to text order for the path,
    // signature and state columns.
    std::stable_sort(rows.begin(), rows.end(), [kColumn, sortDescending](const auto& left, const auto& right) {
        const std::wstring& leftCell = left.cells[static_cast<std::size_t>(kColumn)];
        const std::wstring& rightCell = right.cells[static_cast<std::size_t>(kColumn)];
        const int kComparison = ksword::ui::compareCellsNumericAware(leftCell, rightCell);
        if (kComparison == 0) {
            return left.stableKey < right.stableKey;
        }
        return sortDescending ? kComparison > 0 : kComparison < 0;
    });
    return rows;
}

std::wstring stableKeyAt(const ksword::ui::VirtualListView& list, int visibleIndex) {
    if (visibleIndex < 0 || static_cast<std::size_t>(visibleIndex) >= list.visibleIndexes().size()) {
        return {};
    }
    const std::size_t kRowIndex = list.visibleIndexes()[static_cast<std::size_t>(visibleIndex)];
    return kRowIndex < list.rows().size() ? list.rows()[kRowIndex].stableKey : std::wstring{};
}

void restoreListPosition(
    HWND list,
    const ksword::ui::VirtualListView& virtualList,
    const std::wstring& selectedKey,
    const std::wstring& topKey) {
    int selectedIndex = -1;
    int topIndex = -1;
    for (std::size_t index = 0; index < virtualList.visibleIndexes().size(); ++index) {
        const std::size_t kRowIndex = virtualList.visibleIndexes()[index];
        if (kRowIndex >= virtualList.rows().size()) {
            continue;
        }
        const std::wstring& stableKey = virtualList.rows()[kRowIndex].stableKey;
        if (!selectedKey.empty() && stableKey == selectedKey) {
            selectedIndex = static_cast<int>(index);
        }
        if (!topKey.empty() && stableKey == topKey) {
            topIndex = static_cast<int>(index);
        }
    }
    if (selectedIndex >= 0) {
        ListView_SetItemState(list, selectedIndex, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    if (topIndex >= 0) {
        ListView_EnsureVisible(list, topIndex, FALSE);
    }
}

void applyDialogFont(HWND hwnd) {
    if (hwnd) {
        ::SendMessageW(
            hwnd,
            WM_SETFONT,
            reinterpret_cast<WPARAM>(ksword::ui::systemUiFont()),
            TRUE);
    }
}

void layoutModuleDetailDialog(ModuleDetailDialogState& state) {
    if (!state.hwnd) {
        return;
    }
    RECT client{};
    ::GetClientRect(state.hwnd, &client);
    constexpr int kMargin = 10;
    constexpr int kSpacing = 8;
    constexpr int kSummaryHeight = 42;
    constexpr int kButtonHeight = 28;
    constexpr int kCopyWidth = 96;
    constexpr int kOpenWidth = 96;
    constexpr int kCloseWidth = 72;
    const int kWidth = std::max(0L, client.right - client.left);
    const int kHeight = std::max(0L, client.bottom - client.top);
    const int kButtonY = std::max(kMargin, kHeight - kMargin - kButtonHeight);
    int buttonX = std::max(kMargin, kWidth - kMargin - kCloseWidth);
    ::MoveWindow(state.closeButton, buttonX, kButtonY, kCloseWidth, kButtonHeight, TRUE);
    buttonX -= kSpacing + kOpenWidth;
    ::MoveWindow(state.openFolderButton, buttonX, kButtonY, kOpenWidth, kButtonHeight, TRUE);
    buttonX -= kSpacing + kCopyWidth;
    ::MoveWindow(state.copyButton, buttonX, kButtonY, kCopyWidth, kButtonHeight, TRUE);
    ::MoveWindow(state.summary, kMargin, kMargin, std::max(0, kWidth - kMargin * 2), kSummaryHeight, TRUE);
    const int kEditY = kMargin + kSummaryHeight + kSpacing;
    const int kEditHeight = std::max(0, kButtonY - kSpacing - kEditY);
    ::MoveWindow(state.edit, kMargin, kEditY, std::max(0, kWidth - kMargin * 2), kEditHeight, TRUE);
}

LRESULT CALLBACK moduleDetailWindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    auto* state = reinterpret_cast<ModuleDetailDialogState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (message == WM_NCCREATE) {
        const auto* create = reinterpret_cast<const CREATESTRUCTW*>(lParam);
        state = create ? static_cast<ModuleDetailDialogState*>(create->lpCreateParams) : nullptr;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
        if (state) {
            state->hwnd = hwnd;
        }
    }
    switch (message) {
    case WM_CREATE:
        if (!state) {
            return -1;
        }
        state->summary = ::CreateWindowExW(
            0, WC_STATICW, state->summaryText.c_str(),
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            0, 0, 0, 0, hwnd,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(kModuleDetailSummaryId)),
            ::GetModuleHandleW(nullptr), nullptr);
        state->edit = ::CreateWindowExW(
            WS_EX_CLIENTEDGE, WC_EDITW, state->detailText.c_str(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_LEFT | ES_MULTILINE |
                ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL | WS_VSCROLL | WS_HSCROLL,
            0, 0, 0, 0, hwnd,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(kModuleDetailEditId)),
            ::GetModuleHandleW(nullptr), nullptr);
        ksword::ui::attachTextFindSupport(state->edit);
        state->copyButton = ::CreateWindowExW(
            0, WC_BUTTONW, L"复制全部", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, 0, 0, hwnd,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(kModuleDetailCopyId)),
            ::GetModuleHandleW(nullptr), nullptr);
        state->openFolderButton = ::CreateWindowExW(
            0, WC_BUTTONW, L"打开目录", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, 0, 0, hwnd,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(kModuleDetailOpenFolderId)),
            ::GetModuleHandleW(nullptr), nullptr);
        state->closeButton = ::CreateWindowExW(
            0, WC_BUTTONW, L"关闭", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
            0, 0, 0, 0, hwnd,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(kModuleDetailCloseId)),
            ::GetModuleHandleW(nullptr), nullptr);
        applyDialogFont(state->summary);
        applyDialogFont(state->edit);
        applyDialogFont(state->copyButton);
        applyDialogFont(state->openFolderButton);
        applyDialogFont(state->closeButton);
        layoutModuleDetailDialog(*state);
        return 0;
    case WM_SIZE:
        if (state) {
            layoutModuleDetailDialog(*state);
        }
        return 0;
    case WM_GETMINMAXINFO:
        if (auto* sizeInfo = reinterpret_cast<MINMAXINFO*>(lParam)) {
            sizeInfo->ptMinTrackSize.x = 600;
            sizeInfo->ptMinTrackSize.y = 400;
        }
        return 0;
    case WM_COMMAND:
        if (!state) {
            break;
        }
        switch (LOWORD(wParam)) {
        case kModuleDetailCopyId:
            writeClipboardText(hwnd, state->detailText);
            return 0;
        case kModuleDetailOpenFolderId:
            openFolderAndSelectPath(hwnd, state->modulePath);
            return 0;
        case kModuleDetailCloseId:
            ::DestroyWindow(hwnd);
            return 0;
        default:
            break;
        }
        break;
    case WM_CLOSE:
        ::DestroyWindow(hwnd);
        return 0;
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORBTN:
        ::SetBkMode(reinterpret_cast<HDC>(wParam), TRANSPARENT);
        ::SetTextColor(reinterpret_cast<HDC>(wParam), ksword::ui::appTheme().textColor);
        return reinterpret_cast<LRESULT>(ksword::ui::appTheme().windowBrush());
    case WM_CTLCOLOREDIT:
        ::SetBkColor(reinterpret_cast<HDC>(wParam), ksword::ui::appTheme().panelColor);
        ::SetTextColor(reinterpret_cast<HDC>(wParam), ksword::ui::appTheme().textColor);
        return reinterpret_cast<LRESULT>(ksword::ui::appTheme().panelBrush());
    case WM_NCDESTROY:
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        if (state) {
            state->hwnd = nullptr;
        }
        return 0;
    default:
        break;
    }
    return ::DefWindowProcW(hwnd, message, wParam, lParam);
}

bool registerModuleDetailClass() {
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = moduleDetailWindowProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = ksword::ui::appTheme().windowBrush();
    windowClass.lpszClassName = kModuleDetailClass;
    if (::RegisterClassW(&windowClass)) {
        return true;
    }
    return ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
}

void runModuleDetailDialog(HWND parent, const std::wstring& title, ModuleDetailDialogState& state) {
    if (!registerModuleDetailClass()) {
        return;
    }
    HWND owner = parent ? ::GetAncestor(parent, GA_ROOT) : nullptr;
    RECT ownerRect{};
    if (!owner || !::GetWindowRect(owner, &ownerRect)) {
        ownerRect = { 100, 100, 860, 620 };
    }
    RECT windowRect{ 0, 0, 760, 520 };
    constexpr DWORD kStyle = WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME;
    constexpr DWORD kExStyle = WS_EX_DLGMODALFRAME;
    ::AdjustWindowRectEx(&windowRect, kStyle, FALSE, kExStyle);
    const int kWidth = windowRect.right - windowRect.left;
    const int kHeight = windowRect.bottom - windowRect.top;
    const int kX = ownerRect.left + std::max(0L, (ownerRect.right - ownerRect.left - kWidth) / 2);
    const int kY = ownerRect.top + std::max(0L, (ownerRect.bottom - ownerRect.top - kHeight) / 2);
    HWND dialog = ::CreateWindowExW(
        kExStyle,
        kModuleDetailClass,
        title.c_str(),
        kStyle,
        kX,
        kY,
        kWidth,
        kHeight,
        owner,
        nullptr,
        ::GetModuleHandleW(nullptr),
        &state);
    if (!dialog) {
        return;
    }
    const bool kOwnerWasEnabled = !owner || ::IsWindowEnabled(owner) != FALSE;
    if (owner && kOwnerWasEnabled) {
        ::EnableWindow(owner, FALSE);
    }
    ::ShowWindow(dialog, SW_SHOW);
    ::UpdateWindow(dialog);

    MSG message{};
    bool sawQuit = false;
    int quitCode = 0;
    while (::IsWindow(dialog)) {
        const BOOL kResult = ::GetMessageW(&message, nullptr, 0, 0);
        if (kResult <= 0) {
            if (kResult == 0) {
                sawQuit = true;
                quitCode = static_cast<int>(message.wParam);
            }
            break;
        }
        if (message.message == WM_KEYDOWN && message.wParam == VK_ESCAPE) {
            ::DestroyWindow(dialog);
            continue;
        }
        if (!::IsDialogMessageW(dialog, &message)) {
            ::TranslateMessage(&message);
            ::DispatchMessageW(&message);
        }
    }
    if (owner && kOwnerWasEnabled) {
        ::EnableWindow(owner, TRUE);
        ::SetActiveWindow(owner);
    }
    if (sawQuit) {
        ::PostQuitMessage(quitCode);
    }
}

} // namespace

bool ProcessDetailPage::createModuleTab() {
    HWND refresh = addButton(TabIndex::kModules, kModuleRefresh, L"刷新模块", 6, 6, 112, 28);
    HWND verify = addCheck(
        TabIndex::kModules,
        kModuleVerifySignature,
        L"刷新时校验签名",
        126,
        6,
        166,
        28);
    HWND status = addControl(
        TabIndex::kModules,
        0,
        WC_STATICW,
        L"● 等待首次刷新",
        SS_RIGHT | SS_CENTERIMAGE,
        kModuleStatus,
        304,
        6,
        -6,
        28);
    HWND page = pages_[static_cast<std::size_t>(TabIndex::kModules)].hwnd;
    HWND filter = ksword::ui::createFilterBar(page, kModuleFilter, L"筛选模块路径、签名和线程", 6, 40, 100, 26);
    if (filter) {
        pages_[static_cast<std::size_t>(TabIndex::kModules)].placements.push_back(Placement{ filter, 6, 40, -6, 26 });
    }
    HWND list = addVirtualList(TabIndex::kModules, kModuleList, 6, 72, -6, -6, moduleVirtualList_);
    if (!refresh || !verify || !status || !filter || !list) {
        return false;
    }

    ::SendMessageW(verify, BM_SETCHECK, BST_CHECKED, 0);
    addListColumn(list, 0, L"模块路径", 560);
    addListColumn(list, 1, L"大小", 110);
    addListColumn(list, 2, L"数字签名", 260);
    addListColumn(list, 3, L"入口偏移量", 120);
    addListColumn(list, 4, L"运行状态", 90);
    addListColumn(list, 5, L"ThreadID", 180);
    listColumnCounts_[list] = 6;
    if (moduleFilterRows_) {
        moduleVirtualList_.setSharedRows(moduleFilterRows_);
        moduleVirtualList_.setVisibleIndexes(moduleVisibleIndexes_);
    }

    ::SetWindowSubclass(
        pages_[static_cast<std::size_t>(TabIndex::kModules)].hwnd,
        modulePageVisualSubclassProc,
        kModulePageVisualSubclassId,
        reinterpret_cast<DWORD_PTR>(list));
    ::SetWindowSubclass(status, moduleStatusSubclassProc, kModuleStatusSubclassId, 0);

    if (HWND header = ListView_GetHeader(list)) {
        ::SetWindowSubclass(
            header,
            ProcessDetailPage::moduleHeaderSubclassProc,
            kModuleHeaderSubclassId,
            reinterpret_cast<DWORD_PTR>(this));
    }
    updateSortIndicator(list, moduleSortColumn_, moduleSortDescending_);
    return true;
}

void ProcessDetailPage::populateModuleTab() {
    HWND list = findControl(TabIndex::kModules, kModuleList);
    if (!list) {
        return;
    }
    if (moduleFilterRows_) {
        moduleVirtualList_.setSharedRows(moduleFilterRows_);
        moduleVirtualList_.setVisibleIndexes(moduleVisibleIndexes_);
    }
    if (pendingModuleEntries_ || !moduleFilterRows_) {
        setPageStatus(TabIndex::kModules, kModuleStatus, L"● 正在后台准备模块表...");
    }
}

bool ProcessDetailPage::handleModuleCommand(int controlId) {
    if (controlId == kModuleVerifySignature) {
        if (HWND verify = findControl(TabIndex::kModules, kModuleVerifySignature)) {
            moduleVerifySignatures_ = ::SendMessageW(verify, BM_GETCHECK, 0, 0) == BST_CHECKED;
        }
        requestModuleFilter(true);
        return true;
    }
    if (controlId == kModuleFilter) {
        requestModuleFilter(false);
        return true;
    }
    if (controlId != kModuleRefresh) {
        return false;
    }

    setPageStatus(TabIndex::kModules, kModuleStatus, L"● 正在后台刷新模块列表...");
    refreshAll();
    return true;
}

void ProcessDetailPage::requestModuleFilter(bool rebuildRows) {
    if (!moduleFilterTask_) {
        return;
    }
    const HWND kFilter = findControl(TabIndex::kModules, kModuleFilter);
    moduleFilterQuery_ = kFilter ? ksword::ui::getFilterBarText(kFilter) : moduleFilterQuery_;
    moduleFilterUseRegex_ = ksword::ui::getFilterBarRegexEnabled(kFilter);
    const auto kExistingRows = moduleFilterRows_;
    const auto kSource = pendingModuleEntries_ ? pendingModuleEntries_ : moduleEntries_;
    // Preserve request ordering when a refresh and typing overlap: the newest
    // query always rebuilds from the pending snapshot, never the old table.
    const bool kBuildRows = rebuildRows || !kExistingRows || pendingModuleEntries_;
    if (!kSource && kBuildRows) {
        return;
    }
    const std::uint64_t kGeneration = moduleSourceGeneration_;
    const int kSortColumn = moduleSortColumn_;
    const bool kSortDescending = moduleSortDescending_;
    const bool kVerifySignatures = moduleVerifySignatures_;
    const bool kUseRegex = moduleFilterUseRegex_;
    setPageStatus(TabIndex::kModules, kModuleStatus, L"● 正在后台筛选模块表...");
    moduleFilterTask_->request(
        [kSource, kExistingRows, kBuildRows, kGeneration, kSortColumn, kSortDescending, kVerifySignatures, kUseRegex, query = moduleFilterQuery_]() mutable {
            DetailTableFilterResult result{};
            result.sourceGeneration = kGeneration;
            result.query = std::move(query);
            result.useRegex = kUseRegex;
            result.sortColumn = kSortColumn;
            result.sortDescending = kSortDescending;
            if (kBuildRows) {
                HIMAGELIST imageList = nullptr;
                result.rows = std::make_shared<const std::vector<ksword::ui::VirtualListRow>>(
                    buildModuleVirtualRows(*kSource, kVerifySignatures, kSortColumn, kSortDescending, imageList));
                result.imageList = imageList;
            } else {
                result.rows = kExistingRows;
            }
            if (result.rows) {
                result.visibleIndexes = ksword::ui::VirtualListView::filterRowIndexes(*result.rows, result.query, kUseRegex);
            }
            return result;
        },
        [this](std::uint64_t, std::optional<DetailTableFilterResult>&& result, std::exception_ptr error) {
            if (error || !result.has_value() || result->sourceGeneration != moduleSourceGeneration_ ||
                result->query != moduleFilterQuery_ || result->useRegex != moduleFilterUseRegex_ ||
                result->sortColumn != moduleSortColumn_ ||
                result->sortDescending != moduleSortDescending_ || !result->rows) {
                return;
            }
            const HWND kList = moduleVirtualList_.hwnd();
            const std::wstring kSelectedKey = ::IsWindow(kList)
                ? stableKeyAt(moduleVirtualList_, ListView_GetNextItem(kList, -1, LVNI_SELECTED))
                : std::wstring{};
            const std::wstring kTopKey = ::IsWindow(kList)
                ? stableKeyAt(moduleVirtualList_, ListView_GetTopIndex(kList))
                : std::wstring{};
            const bool kReplaceRows = result->rows != moduleFilterRows_;
            const std::size_t kVisibleCount = result->visibleIndexes.size();
            moduleFilterRows_ = result->rows;
            moduleVisibleIndexes_ = result->visibleIndexes;
            if (kReplaceRows) {
                moduleEntries_ = pendingModuleEntries_ ? pendingModuleEntries_ : moduleEntries_;
                pendingModuleEntries_.reset();
            }
            if (::IsWindow(kList)) {
                if (result->imageList) {
                    ListView_SetImageList(kList, result->imageList, LVSIL_SMALL);
                }
                if (kReplaceRows) {
                    moduleVirtualList_.setSharedRows(moduleFilterRows_);
                }
                moduleVirtualList_.setVisibleIndexes(std::move(result->visibleIndexes));
                restoreListPosition(kList, moduleVirtualList_, kSelectedKey, kTopKey);
                updateSortIndicator(kList, moduleSortColumn_, moduleSortDescending_);
            }
            std::wstring status;
            if (!snapshot_.modulesSucceeded) {
                status = L"● 模块刷新失败";
                if (!snapshot_.errorText.empty()) {
                    status += L" | " + snapshot_.errorText;
                }
            } else {
                status = L"● 刷新完成 | 模块:" + std::to_wstring(kVisibleCount) +
                    L" / " + std::to_wstring(moduleEntries().size());
                if (moduleEntries().empty() && !snapshot_.errorText.empty()) {
                    status += L" | " + snapshot_.errorText;
                }
            }
            if (moduleVerifySignatures_) {
                status += L" | 签名校验结果不可用";
            }
            setPageStatus(TabIndex::kModules, kModuleStatus, status);
        });
}

void ProcessDetailPage::onModuleSortRequested(const int column) {
    if (column < 0 || column >= 6) {
        return;
    }
    if (moduleSortColumn_ == column) {
        moduleSortDescending_ = !moduleSortDescending_;
    } else {
        moduleSortColumn_ = column;
        moduleSortDescending_ = false;
    }
    updateSortIndicator(moduleVirtualList_.hwnd(), moduleSortColumn_, moduleSortDescending_);
    requestModuleFilter(true);
}

LRESULT CALLBACK ProcessDetailPage::moduleHeaderSubclassProc(
    HWND hwnd,
    UINT message,
    WPARAM wParam,
    LPARAM lParam,
    UINT_PTR subclassId,
    DWORD_PTR referenceData) {
    auto* page = reinterpret_cast<ProcessDetailPage*>(referenceData);
    if (message == WM_LBUTTONUP && page) {
        HDHITTESTINFO hit{};
        hit.pt.x = GET_X_LPARAM(lParam);
        hit.pt.y = GET_Y_LPARAM(lParam);
        const int kColumn = static_cast<int>(::SendMessageW(hwnd, HDM_HITTEST, 0, reinterpret_cast<LPARAM>(&hit)));
        const LRESULT kResult = ::DefSubclassProc(hwnd, message, wParam, lParam);
        page->onModuleSortRequested(kColumn);
        return kResult;
    }
    if (message == WM_NCDESTROY) {
        ::RemoveWindowSubclass(hwnd, moduleHeaderSubclassProc, subclassId);
    }
    return ::DefSubclassProc(hwnd, message, wParam, lParam);
}

bool ProcessDetailPage::handleModuleContextMenu(POINT screenPoint) {
    HWND list = findControl(TabIndex::kModules, kModuleList);
    if (!list || selectedListRow(list) < 0) {
        return true;
    }
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return true;
    }
    ::AppendMenuW(menu, MF_STRING, kModuleMenuCopyCell, L"复制单元格");
    ::AppendMenuW(menu, MF_STRING, kModuleMenuCopyRow, L"复制行");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING, kModuleMenuDetail, L"查看模块详情");
    ::AppendMenuW(menu, MF_STRING, kModuleMenuOpenFolder, L"打开文件夹");
    ::AppendMenuW(menu, MF_STRING, kModuleMenuUnload, L"卸载");
    ::AppendMenuW(menu, MF_STRING, kModuleMenuSuspendThread, L"挂起Thread");
    ::AppendMenuW(menu, MF_STRING, kModuleMenuResumeThread, L"取消挂起Thread");
    ::AppendMenuW(menu, MF_STRING, kModuleMenuTerminateThread, L"结束Thread");
    const UINT kCommand = ::TrackPopupMenu(
        menu,
        TPM_RETURNCMD | TPM_RIGHTBUTTON,
        screenPoint.x,
        screenPoint.y,
        0,
        hwnd_,
        nullptr);
    ::DestroyMenu(menu);

    switch (kCommand) {
    case kModuleMenuCopyCell: copyListCell(list); break;
    case kModuleMenuCopyRow: copyListRow(list); break;
    case kModuleMenuDetail: showModuleDetailDialog(); break;
    case kModuleMenuOpenFolder: openSelectedModuleFolder(); break;
    case kModuleMenuUnload: unloadSelectedModule(); break;
    case kModuleMenuSuspendThread: suspendSelectedModuleThread(); break;
    case kModuleMenuResumeThread: resumeSelectedModuleThread(); break;
    case kModuleMenuTerminateThread: terminateSelectedModuleThread(); break;
    default: break;
    }
    return true;
}

void ProcessDetailPage::showModuleDetailDialog() {
    HWND list = findControl(TabIndex::kModules, kModuleList);
    const std::size_t kIndex = selectedSnapshotIndex(list);
    const auto& modules = moduleEntries();
    if (kIndex >= modules.size()) {
        setPageStatus(TabIndex::kModules, kModuleStatus, L"● 查看模块详情失败 | 当前无有效选中项");
        return;
    }
    const ProcessModuleInfo& module = modules[kIndex];
    const std::wstring kSignature = moduleSignatureText(moduleVerifySignatures_);
    const std::wstring kModuleName = !module.moduleName.empty()
        ? module.moduleName
        : baseNameFromPath(module.modulePath);
    std::wstring processName = snapshot_.basic.processName.empty()
        ? baseNameFromPath(snapshot_.basic.imagePath)
        : snapshot_.basic.processName;
    if (processName.empty()) {
        processName = L"Unknown";
    }

    ModuleDetailDialogState dialogState{};
    dialogState.modulePath = module.modulePath;
    dialogState.summaryText = L"模块基址 " + formatHex(module.baseAddress) +
        L" | 大小 " + formatModuleSize(module.imageSize) +
        L" | 签名 " + kSignature;
    std::wostringstream detail;
    detail << L"进程 ID: " << processId_ << L"\r\n"
           << L"进程名: " << processName << L"\r\n"
           << L"模块路径: " << module.modulePath << L"\r\n"
           << L"模块基址: " << formatHex(module.baseAddress) << L"\r\n"
           << L"模块大小: " << formatModuleSize(module.imageSize) << L"\r\n"
           << L"入口点 RVA: Unavailable\r\n"
           << L"签名状态: " << kSignature << L"\r\n"
           << L"签名可信: Unavailable\r\n"
           << L"运行状态: " << moduleRunningState(module) << L"\r\n"
           << L"代表线程 ID: " << module.representativeThreadId << L"\r\n"
           << L"线程 ID 文本: " << moduleThreadText(module);
    dialogState.detailText = detail.str();
    runModuleDetailDialog(hwnd_, L"模块详情 - " + (kModuleName.empty() ? L"Unknown" : kModuleName), dialogState);
}

void ProcessDetailPage::openSelectedModuleFolder() {
    HWND list = findControl(TabIndex::kModules, kModuleList);
    const std::size_t kIndex = selectedSnapshotIndex(list);
    const auto& modules = moduleEntries();
    if (kIndex >= modules.size()) {
        setPageStatus(TabIndex::kModules, kModuleStatus, L"● 打开文件夹失败 | 当前无有效选中项");
        return;
    }
    const bool kOpened = openFolderAndSelectPath(hwnd_, modules[kIndex].modulePath);
    setPageStatus(
        TabIndex::kModules,
        kModuleStatus,
        kOpened ? L"● 已打开模块所在目录" : L"● 打开模块所在目录失败");
}

void ProcessDetailPage::unloadSelectedModule() {
    HWND list = findControl(TabIndex::kModules, kModuleList);
    const std::size_t kIndex = selectedSnapshotIndex(list);
    const auto& modules = moduleEntries();
    if (kIndex >= modules.size()) {
        setPageStatus(TabIndex::kModules, kModuleStatus, L"● 卸载模块失败 | 当前无有效选中项");
        return;
    }
    const std::uintptr_t kModuleBase = modules[kIndex].baseAddress;
    if (kModuleBase == 0) {
        setPageStatus(TabIndex::kModules, kModuleStatus, L"● 卸载模块失败 | 模块基址不可用");
        return;
    }
    const auto kModuleSnapshot = moduleEntries_;
    const DWORD kTargetProcessId = processId_;
    const ULONGLONG kExpectedProcessCreationTime100ns = expectedCreationTime100ns_;
    executeBackgroundAction(
        TabIndex::kModules,
        kModuleStatus,
        L"● 正在后台卸载模块…",
        [kModuleBase, kTargetProcessId, kExpectedProcessCreationTime100ns, kModuleSnapshot] {
            ProcessDetailActionResult action{};
            HMODULE localKernel32 = ::GetModuleHandleW(L"kernel32.dll");
            FARPROC localFreeLibrary = localKernel32 ? ::GetProcAddress(localKernel32, "FreeLibrary") : nullptr;
            HMODULE localFunctionModule = nullptr;
            if (!localFreeLibrary || !::GetModuleHandleExW(
                    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                    reinterpret_cast<LPCWSTR>(localFreeLibrary),
                    &localFunctionModule)) {
                action.statusText = L"● 卸载模块失败 | 无法解析 FreeLibrary";
                return action;
            }
            wchar_t localFunctionPath[32768]{};
            const DWORD kLocalFunctionPathLength = ::GetModuleFileNameW(
                localFunctionModule,
                localFunctionPath,
                static_cast<DWORD>(std::size(localFunctionPath)));
            const std::wstring kFunctionModuleName = kLocalFunctionPathLength > 0
                ? baseNameFromPath(std::wstring(localFunctionPath, kLocalFunctionPathLength))
                : L"kernel32.dll";
            std::uintptr_t remoteFunctionModule = 0;
            if (kModuleSnapshot) {
                for (const ProcessModuleInfo& module : *kModuleSnapshot) {
                    if (_wcsicmp(baseNameFromPath(module.modulePath).c_str(), kFunctionModuleName.c_str()) == 0) {
                        remoteFunctionModule = module.baseAddress;
                        break;
                    }
                }
            }
            const std::uintptr_t kLocalFunctionModuleAddress = reinterpret_cast<std::uintptr_t>(localFunctionModule);
            const std::uintptr_t kFreeLibraryOffset =
                reinterpret_cast<std::uintptr_t>(localFreeLibrary) - kLocalFunctionModuleAddress;
            const std::uintptr_t kRemoteFreeLibrary = remoteFunctionModule
                ? remoteFunctionModule + kFreeLibraryOffset
                : reinterpret_cast<std::uintptr_t>(localFreeLibrary);

            ksword::core::UniqueHandle verifiedProcess;
            std::wstring identityError;
            if (!ProcessDetailPage::openVerifiedProcessActionTarget(
                    kTargetProcessId,
                    kExpectedProcessCreationTime100ns,
                    PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ,
                    verifiedProcess,
                    identityError)) {
                action.statusText = L"● 卸载模块失败 | " + identityError;
                return action;
            }
            ksword::core::UniqueHandle remoteThread(::CreateRemoteThread(
                verifiedProcess.get(),
                nullptr,
                0,
                reinterpret_cast<LPTHREAD_START_ROUTINE>(kRemoteFreeLibrary),
                reinterpret_cast<void*>(kModuleBase),
                0,
                nullptr));
            if (!remoteThread.valid()) {
                action.statusText = L"● 卸载模块失败 | " + lastErrorText(L"CreateRemoteThread", ::GetLastError());
                return action;
            }
            const DWORD kWaitResult = ::WaitForSingleObject(remoteThread.get(), 10000);
            DWORD exitCode = 0;
            const bool kCompleted = kWaitResult == WAIT_OBJECT_0 &&
                ::GetExitCodeThread(remoteThread.get(), &exitCode) != FALSE && exitCode != 0;
            if (!kCompleted) {
                action.statusText = L"● 卸载模块失败 | FreeLibrary 未成功返回";
                return action;
            }
            action.refreshRequired = true;
            action.statusText = L"● 卸载模块成功";
            return action;
        });
}

void ProcessDetailPage::suspendSelectedModuleThread() {
    HWND list = findControl(TabIndex::kModules, kModuleList);
    const std::size_t kIndex = selectedSnapshotIndex(list);
    const auto& modules = moduleEntries();
    if (kIndex >= modules.size() || modules[kIndex].representativeThreadId == 0 ||
        modules[kIndex].representativeThreadCreationTime100ns == 0U) {
        setPageStatus(TabIndex::kModules, kModuleStatus, L"● 挂起 Thread 失败 | 当前模块行没有可用 ThreadID。");
        return;
    }
    const DWORD kThreadId = modules[kIndex].representativeThreadId;
    const ULONGLONG kExpectedThreadCreationTime100ns =
        modules[kIndex].representativeThreadCreationTime100ns;
    const DWORD kTargetProcessId = processId_;
    const ULONGLONG kExpectedProcessCreationTime100ns = expectedCreationTime100ns_;
    executeBackgroundAction(
        TabIndex::kModules,
        kModuleStatus,
        L"● 正在后台挂起模块线程…",
        [kThreadId, kExpectedThreadCreationTime100ns, kTargetProcessId, kExpectedProcessCreationTime100ns] {
            ProcessDetailActionResult action{};
            ksword::core::UniqueHandle verifiedProcess;
            ksword::core::UniqueHandle verifiedThread;
            std::wstring identityError;
            if (!ProcessDetailPage::openVerifiedThreadActionTarget(
                    kTargetProcessId,
                    kExpectedProcessCreationTime100ns,
                    kThreadId,
                    kExpectedThreadCreationTime100ns,
                    THREAD_SUSPEND_RESUME,
                    verifiedProcess,
                    verifiedThread,
                    identityError)) {
                action.statusText = L"● 挂起 Thread 失败 | " + identityError;
                return action;
            }
            const DWORD kPreviousCount = ::SuspendThread(verifiedThread.get());
            const DWORD kError = kPreviousCount == static_cast<DWORD>(-1) ? ::GetLastError() : ERROR_SUCCESS;
            action.refreshRequired = kError == ERROR_SUCCESS;
            action.statusText = kError == ERROR_SUCCESS
                ? L"● 挂起 Thread 成功"
                : L"● 挂起 Thread 失败 | " + lastErrorText(L"SuspendThread", kError);
            return action;
        });
}

void ProcessDetailPage::resumeSelectedModuleThread() {
    HWND list = findControl(TabIndex::kModules, kModuleList);
    const std::size_t kIndex = selectedSnapshotIndex(list);
    const auto& modules = moduleEntries();
    if (kIndex >= modules.size() || modules[kIndex].representativeThreadId == 0 ||
        modules[kIndex].representativeThreadCreationTime100ns == 0U) {
        setPageStatus(TabIndex::kModules, kModuleStatus, L"● 取消挂起 Thread 失败 | 当前模块行没有可用 ThreadID。");
        return;
    }
    const DWORD kThreadId = modules[kIndex].representativeThreadId;
    const ULONGLONG kExpectedThreadCreationTime100ns =
        modules[kIndex].representativeThreadCreationTime100ns;
    const DWORD kTargetProcessId = processId_;
    const ULONGLONG kExpectedProcessCreationTime100ns = expectedCreationTime100ns_;
    executeBackgroundAction(
        TabIndex::kModules,
        kModuleStatus,
        L"● 正在后台恢复模块线程…",
        [kThreadId, kExpectedThreadCreationTime100ns, kTargetProcessId, kExpectedProcessCreationTime100ns] {
            ProcessDetailActionResult action{};
            ksword::core::UniqueHandle verifiedProcess;
            ksword::core::UniqueHandle verifiedThread;
            std::wstring identityError;
            if (!ProcessDetailPage::openVerifiedThreadActionTarget(
                    kTargetProcessId,
                    kExpectedProcessCreationTime100ns,
                    kThreadId,
                    kExpectedThreadCreationTime100ns,
                    THREAD_SUSPEND_RESUME,
                    verifiedProcess,
                    verifiedThread,
                    identityError)) {
                action.statusText = L"● 取消挂起 Thread 失败 | " + identityError;
                return action;
            }
            const DWORD kPreviousCount = ::ResumeThread(verifiedThread.get());
            const DWORD kError = kPreviousCount == static_cast<DWORD>(-1) ? ::GetLastError() : ERROR_SUCCESS;
            action.refreshRequired = kError == ERROR_SUCCESS;
            action.statusText = kError == ERROR_SUCCESS
                ? L"● 取消挂起 Thread 成功"
                : L"● 取消挂起 Thread 失败 | " + lastErrorText(L"ResumeThread", kError);
            return action;
        });
}

void ProcessDetailPage::terminateSelectedModuleThread() {
    HWND list = findControl(TabIndex::kModules, kModuleList);
    const std::size_t kIndex = selectedSnapshotIndex(list);
    const auto& modules = moduleEntries();
    if (kIndex >= modules.size() || modules[kIndex].representativeThreadId == 0 ||
        modules[kIndex].representativeThreadCreationTime100ns == 0U) {
        setPageStatus(TabIndex::kModules, kModuleStatus, L"● 结束 Thread 失败 | 当前模块行没有可用 ThreadID。");
        return;
    }
    const DWORD kThreadId = modules[kIndex].representativeThreadId;
    const ULONGLONG kExpectedThreadCreationTime100ns =
        modules[kIndex].representativeThreadCreationTime100ns;
    const DWORD kTargetProcessId = processId_;
    const ULONGLONG kExpectedProcessCreationTime100ns = expectedCreationTime100ns_;
    executeBackgroundAction(
        TabIndex::kModules,
        kModuleStatus,
        L"● 正在后台结束模块线程…",
        [kThreadId, kExpectedThreadCreationTime100ns, kTargetProcessId, kExpectedProcessCreationTime100ns] {
            ProcessDetailActionResult action{};
            ksword::core::UniqueHandle verifiedProcess;
            ksword::core::UniqueHandle verifiedThread;
            std::wstring identityError;
            if (!ProcessDetailPage::openVerifiedThreadActionTarget(
                    kTargetProcessId,
                    kExpectedProcessCreationTime100ns,
                    kThreadId,
                    kExpectedThreadCreationTime100ns,
                    THREAD_TERMINATE,
                    verifiedProcess,
                    verifiedThread,
                    identityError)) {
                action.statusText = L"● 结束 Thread 失败 | " + identityError;
                return action;
            }
            const BOOL kTerminated = ::TerminateThread(verifiedThread.get(), 0);
            const DWORD kError = kTerminated ? ERROR_SUCCESS : ::GetLastError();
            if (!kTerminated) {
                action.statusText = L"● 结束 Thread 失败 | " + lastErrorText(L"TerminateThread", kError);
                return action;
            }
            action.refreshRequired = true;
            action.statusText = L"● 结束 Thread 成功";
            return action;
        });
}

} // namespace Ksword::Features::process_detail
