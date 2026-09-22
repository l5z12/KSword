#include "ContextMenuView.h"

#include "ContextMenuScanner.h"
#include "../../core/EntityRef.h"
#include "../file/PathNavigator.h"
#include "../../ui/AsyncTask.h"
#include "../../ui/Controls.h"
#include "../../ui/EntityNavigation.h"
#include "../../ui/FilterBar.h"
#include "../../ui/ListViewUtil.h"
#include "../../ui/LoadingOverlay.h"
#include "../../ui/TextFindSupport.h"
#include "../../ui/Theme.h"
#include "../../ui/VirtualListView.h"

#include <commctrl.h>
#include <windowsx.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace ksword::features::sys_tools {
namespace {

constexpr wchar_t kContextMenuViewClass[] = L"KswordARKLight.SysTools.ContextMenuView";

constexpr int kRefreshButtonId = 67301;
constexpr int kDisableButtonId = 67302;
constexpr int kEnableButtonId = 67303;
constexpr int kFilterBarId = 67304;
constexpr int kListId = 67305;
constexpr int kDetailEditId = 67306;
constexpr int kLoadingOverlayId = 67307;

constexpr UINT kMenuDisable = 67621;
constexpr UINT kMenuEnable = 67622;
constexpr UINT kMenuCopyRow = 67623;
constexpr UINT kMenuCopyVisible = 67624;
constexpr UINT kMenuRefresh = 67625;
constexpr UINT kMenuOpenRegistry = 67626;
constexpr UINT kMenuOpenModuleDirectory = 67627;

constexpr UINT kMsgScanCompleted = WM_APP + 710;
constexpr UINT kMsgFilterCompleted = WM_APP + 711;
constexpr UINT kMsgActionCompleted = WM_APP + 712;

constexpr int kGap = 6;
constexpr int kRowHeight = 24;
constexpr int kHeaderHeight = kGap * 3 + kRowHeight * 2;
constexpr int kDetailHeight = 120;
constexpr int kStatusHeight = 22;
constexpr int kColumnCount = 7;

int width(const RECT& rc) {
    return rc.right > rc.left ? static_cast<int>(rc.right - rc.left) : 0;
}

int height(const RECT& rc) {
    return rc.bottom > rc.top ? static_cast<int>(rc.bottom - rc.top) : 0;
}

struct ContextMenuFilterResult final {
    std::uint64_t generation = 0;
    std::wstring query;
    bool useRegex = false;
    std::vector<std::size_t> visibleIndexes;
};

struct ContextMenuViewState final {
    HWND hwnd = nullptr;
    HWND refreshButton = nullptr;
    HWND disableButton = nullptr;
    HWND enableButton = nullptr;
    HWND filterBar = nullptr;
    HWND detailEdit = nullptr;
    HWND loadingOverlay = nullptr;
    ksword::ui::VirtualListView list;
    std::vector<ContextMenuEntry> entries;
    std::shared_ptr<const std::vector<ksword::ui::VirtualListRow>> filterRows;
    std::wstring statusText = L"正在枚举 shell 扩展注册点…";
    std::wstring filterQuery;
    bool filterUseRegex = false;
    bool actionInProgress = false;
    std::uint64_t displayGeneration = 0;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<ContextMenuScanResult>> scanTask;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<ContextMenuFilterResult>> filterTask;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<ContextMenuActionResult>> actionTask;
};

bool copyText(HWND owner, const std::wstring& text) {
    if (text.empty() || !::OpenClipboard(owner)) {
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

std::wstring kindText(const ContextMenuKind kind) {
    return kind == ContextMenuKind::kShellVerb ? L"shell 动词" : L"shellex 处理程序";
}

// moduleStateText separates the three states an operator reacts to differently:
// a working module, a registration pointing at a file that is gone (a classic
// leftover from an uninstalled product), and an entry that has no file to check.
std::wstring moduleStateText(const ContextMenuEntry& entry) {
    if (entry.moduleFile.empty()) {
        return L"无模块";
    }
    return entry.moduleExists ? L"存在" : L"缺失";
}

std::wstring cellText(const ContextMenuEntry& entry, const int column) {
    switch (column) {
    case 0:
        return entry.enabled ? L"启用" : L"已禁用";
    case 1:
        return entry.scopeText;
    case 2:
        return kindText(entry.kind);
    case 3:
        return entry.name;
    case 4:
        return entry.clsid;
    case 5:
        return entry.modulePath;
    case 6:
        return moduleStateText(entry);
    default:
        return {};
    }
}

COLORREF rowColor(const ContextMenuEntry& entry) {
    if (!entry.enabled) {
        return RGB(128, 128, 128);
    }
    // A registration whose module is missing is dead weight in every shell
    // menu it appears in, so it is the one state worth coloring.
    if (!entry.moduleFile.empty() && !entry.moduleExists) {
        return RGB(176, 32, 32);
    }
    return CLR_DEFAULT;
}

int selectedModelIndex(const ContextMenuViewState& state) {
    const HWND kList = state.list.hwnd();
    const int kSelected = kList ? ListView_GetNextItem(kList, -1, LVNI_SELECTED) : -1;
    const auto& visible = state.list.visibleIndexes();
    if (kSelected < 0 || static_cast<std::size_t>(kSelected) >= visible.size()) {
        return -1;
    }
    const std::size_t kModelIndex = visible[static_cast<std::size_t>(kSelected)];
    return kModelIndex < state.entries.size() ? static_cast<int>(kModelIndex) : -1;
}

const ContextMenuEntry* selectedEntry(const ContextMenuViewState& state) {
    const int kIndex = selectedModelIndex(state);
    return kIndex >= 0 ? &state.entries[static_cast<std::size_t>(kIndex)] : nullptr;
}

std::wstring detailTextForEntry(const ContextMenuEntry& entry) {
    std::wostringstream stream;
    stream << L"注册路径：HKEY_CLASSES_ROOT\\" << entry.registrationPath << L"\r\n"
        << L"作用域：" << entry.scopeText << L"    类型：" << kindText(entry.kind) << L"\r\n"
        << L"名称：" << entry.name << L"    显示名：" << entry.displayText << L"\r\n"
        << L"CLSID：" << (entry.clsid.empty() ? std::wstring(L"—") : entry.clsid) << L"\r\n"
        << L"模块：" << (entry.modulePath.empty() ? std::wstring(L"—") : entry.modulePath)
        << L"（" << moduleStateText(entry) << L"）\r\n"
        << L"状态：" << (entry.enabled ? L"启用" : L"已禁用");
    if (!entry.backupKeyName.empty()) {
        stream << L"\r\n备份键：" << contextMenuBackupRootPath() << L"\\" << entry.backupKeyName;
    }
    if (!entry.diagnosticText.empty()) {
        stream << L"\r\n说明：" << entry.diagnosticText;
    }
    return stream.str();
}

void showDetail(ContextMenuViewState& state) {
    if (!state.detailEdit) {
        return;
    }
    const ContextMenuEntry* entry = selectedEntry(state);
    if (!entry) {
        ::SetWindowTextW(state.detailEdit, L"选择一项查看注册详情。禁用会把整个注册子树备份到本工具的备份键后再删除。");
        return;
    }
    const std::wstring kText = detailTextForEntry(*entry);
    ::SetWindowTextW(state.detailEdit, kText.c_str());
}

void updateActionButtons(ContextMenuViewState& state) {
    const ContextMenuEntry* entry = state.actionInProgress ? nullptr : selectedEntry(state);
    if (state.disableButton) {
        ::EnableWindow(state.disableButton, entry != nullptr && entry->enabled);
    }
    if (state.enableButton) {
        ::EnableWindow(state.enableButton, entry != nullptr && !entry->enabled);
    }
}

void refreshSelectionDependentUi(ContextMenuViewState& state) {
    showDetail(state);
    updateActionButtons(state);
}

void applyFilterResult(ContextMenuViewState& state, ContextMenuFilterResult result) {
    if (result.generation != state.displayGeneration || result.query != state.filterQuery ||
        result.useRegex != state.filterUseRegex || !state.list.hwnd()) {
        return;
    }
    state.list.setVisibleIndexes(std::move(result.visibleIndexes));
    refreshSelectionDependentUi(state);
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

void requestFilter(ContextMenuViewState& state, std::wstring query) {
    state.filterQuery = std::move(query);
    state.filterUseRegex = ksword::ui::getFilterBarRegexEnabled(state.filterBar);
    const auto kRows = state.filterRows;
    const std::uint64_t kGeneration = state.displayGeneration;
    const bool kUseRegex = state.filterUseRegex;
    if (!state.filterTask || !kRows) {
        return;
    }
    state.filterTask->request(
        [kRows, kGeneration, kUseRegex, query = state.filterQuery]() mutable {
            ContextMenuFilterResult result{};
            result.generation = kGeneration;
            result.query = std::move(query);
            result.useRegex = kUseRegex;
            result.visibleIndexes = ksword::ui::VirtualListView::filterRowIndexes(*kRows, result.query, kUseRegex);
            return result;
        },
        [&state](std::uint64_t, std::optional<ContextMenuFilterResult>&& result, std::exception_ptr error) {
            if (error || !result.has_value()) {
                return;
            }
            applyFilterResult(state, std::move(*result));
        });
}

void buildRows(ContextMenuViewState& state) {
    std::vector<ksword::ui::VirtualListRow> rows;
    rows.reserve(state.entries.size());
    for (std::size_t index = 0; index < state.entries.size(); ++index) {
        const ContextMenuEntry& entry = state.entries[index];
        ksword::ui::VirtualListRow row{};
        // The HKCR-relative registration path is unique across all five roots
        // and survives disable/enable, which is exactly what selection restore
        // after a refresh needs.
        row.stableKey = entry.registrationPath;
        row.itemData = static_cast<LPARAM>(index);
        row.textColor = rowColor(entry);
        row.cells.reserve(kColumnCount + 3);
        for (int column = 0; column < kColumnCount; ++column) {
            row.cells.push_back(cellText(entry, column));
        }
        row.cells.push_back(entry.displayText);
        row.cells.push_back(entry.registrationPath);
        row.cells.push_back(entry.diagnosticText);
        rows.push_back(std::move(row));
    }
    auto filterRows = std::make_shared<std::vector<ksword::ui::VirtualListRow>>(std::move(rows));
    state.list.setRows(*filterRows);
    state.filterRows = std::move(filterRows);
    ++state.displayGeneration;
}

void beginScan(ContextMenuViewState& state) {
    if (!state.scanTask) {
        return;
    }
    if (state.refreshButton) {
        ::EnableWindow(state.refreshButton, FALSE);
    }
    state.statusText = L"正在后台枚举 shell 扩展注册点…";
    ksword::ui::setLoadingOverlay(state.loadingOverlay, true, L"正在读取注册表…");
    ::InvalidateRect(state.hwnd, nullptr, TRUE);

    state.scanTask->request(
        [] { return scanContextMenuEntries(); },
        [&state](std::uint64_t, std::optional<ContextMenuScanResult>&& scan, std::exception_ptr error) {
            if (state.refreshButton) {
                ::EnableWindow(state.refreshButton, TRUE);
            }
            ksword::ui::setLoadingOverlay(state.loadingOverlay, false);
            if (error || !scan.has_value() || !scan->success) {
                state.statusText = L"右键菜单注册项枚举异常结束。";
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }

            std::size_t disabled = 0;
            std::size_t missing = 0;
            for (const ContextMenuEntry& entry : scan->entries) {
                if (!entry.enabled) {
                    ++disabled;
                } else if (!entry.moduleFile.empty() && !entry.moduleExists) {
                    ++missing;
                }
            }
            state.entries = std::move(scan->entries);
            buildRows(state);

            std::wostringstream summary;
            summary << L"共 " << state.entries.size() << L" 项，其中已禁用 " << disabled
                << L"，模块缺失 " << missing << L"。备份键：" << contextMenuBackupRootPath();
            if (!scan->diagnosticText.empty()) {
                summary << L"。" << scan->diagnosticText;
            }
            state.statusText = summary.str();
            requestFilter(state, state.filterBar ? ksword::ui::getFilterBarText(state.filterBar) : std::wstring{});
            refreshSelectionDependentUi(state);
            ::InvalidateRect(state.hwnd, nullptr, TRUE);
        });
}

// confirmDisable is the one prompt on this page. Disabling means deleting a live
// HKCR subtree, and although the backup makes it reversible, the shell will lose
// the entry immediately and the user has to know that before it happens. The
// default button is No so a stray Enter cannot remove a handler.
bool confirmDisable(HWND owner, const ContextMenuEntry& entry) {
    std::wstring text = L"将备份并删除右键菜单注册项：\n\nHKEY_CLASSES_ROOT\\" + entry.registrationPath + L"\n\n";
    if (!entry.displayText.empty()) {
        text += L"显示名：" + entry.displayText + L"\n";
    }
    if (!entry.modulePath.empty()) {
        text += L"模块：" + entry.modulePath + L"\n";
    }
    text += L"\n整个注册子树会先完整备份到：\n" + contextMenuBackupRootPath() +
        L"\n\n删除后可用“启用”还原。是否继续？";
    return ::MessageBoxW(owner, text.c_str(), L"禁用右键菜单项", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) == IDYES;
}

void runAction(ContextMenuViewState& state, const bool disable) {
    const ContextMenuEntry* selected = selectedEntry(state);
    if (!selected) {
        state.statusText = L"未选择注册项。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }
    if (state.actionInProgress || !state.actionTask) {
        state.statusText = L"注册表操作正在执行。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }
    if (disable && !confirmDisable(state.hwnd, *selected)) {
        state.statusText = L"已取消禁用操作。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }

    const ContextMenuEntry kEntry = *selected;
    state.actionInProgress = true;
    updateActionButtons(state);
    state.statusText = disable ? L"正在备份并删除注册项…" : L"正在从备份还原注册项…";
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
    state.actionTask->request(
        [kEntry, disable] { return disable ? disableContextMenuEntry(kEntry) : enableContextMenuEntry(kEntry); },
        [&state](std::uint64_t, std::optional<ContextMenuActionResult>&& result, std::exception_ptr error) {
            state.actionInProgress = false;
            if (error || !result.has_value()) {
                state.statusText = L"注册表操作异常结束。";
                updateActionButtons(state);
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            state.statusText = result->message;
            if (result->success) {
                // The table always lies after a successful mutation, so it is
                // re-read rather than patched in place.
                beginScan(state);
                return;
            }
            updateActionButtons(state);
            ::InvalidateRect(state.hwnd, nullptr, TRUE);
        });
}

std::wstring rowsAsText(const ContextMenuViewState& state, const bool allVisible) {
    const auto& rows = state.list.rows();
    const auto& visible = state.list.visibleIndexes();
    const HWND kList = state.list.hwnd();
    std::wstring text;
    for (std::size_t item = 0; item < visible.size(); ++item) {
        if (!allVisible &&
            (!kList || (ListView_GetItemState(kList, static_cast<int>(item), LVIS_SELECTED) & LVIS_SELECTED) == 0)) {
            continue;
        }
        const std::size_t kRowIndex = visible[item];
        if (kRowIndex >= rows.size()) {
            continue;
        }
        const auto& cells = rows[kRowIndex].cells;
        for (std::size_t column = 0; column < (std::min)(static_cast<std::size_t>(kColumnCount), cells.size()); ++column) {
            if (column != 0) {
                text += L'\t';
            }
            text += cells[column];
        }
        text += L"\r\n";
    }
    return text;
}

// selectRowAtPoint makes a right-click command apply to the row under the
// pointer rather than a stale selection left by an earlier operation.
void selectRowAtPoint(ContextMenuViewState& state, const POINT screenPoint) {
    const HWND kList = state.list.hwnd();
    if (!kList) {
        return;
    }
    POINT clientPoint = screenPoint;
    ::ScreenToClient(kList, &clientPoint);
    LVHITTESTINFO hit{};
    hit.pt = clientPoint;
    const int kClickedItem = ListView_HitTest(kList, &hit);
    ListView_SetItemState(kList, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    if (kClickedItem < 0 || static_cast<std::size_t>(kClickedItem) >= state.list.visibleIndexes().size()) {
        refreshSelectionDependentUi(state);
        return;
    }
    ListView_SetItemState(kList, kClickedItem, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    refreshSelectionDependentUi(state);
}

// openSelectedRegistryKey routes a live HKCR-relative registration to the
// registry browser. The destination reopens the key, so this snapshot never
// grants access to a deleted or changed registration.
void openSelectedRegistryKey(ContextMenuViewState& state) {
    const ContextMenuEntry* entry = selectedEntry(state);
    if (!entry || !entry->enabled || entry->registrationPath.empty()) {
        state.statusText = L"当前选择没有可打开的活动注册项。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }

    ksword::core::NavigationRequest request{};
    request.target = ksword::core::NavigationTarget::kRegistryBrowser;
    request.entity.kind = ksword::core::EntityKind::kRegistryKey;
    request.entity.text = L"HKCR\\" + entry->registrationPath;
    state.statusText = ksword::ui::requestEntityNavigation(state.hwnd, request)
        ? L"已转到注册表浏览器；目标路径会重新读取。"
        : L"无法导航到该活动注册表项。";
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

std::wstring moduleDirectoryForEntry(const ContextMenuEntry& entry) {
    if (!entry.moduleExists) {
        return {};
    }
    return ksword::features::file::PathNavigator::parentDirectoryForKnownFilePath(entry.moduleFile);
}

// openSelectedModuleDirectory accepts only a file the scanner explicitly
// checked, then applies the strict known DOS/UNC path gate before routing.
void openSelectedModuleDirectory(ContextMenuViewState& state) {
    const ContextMenuEntry* entry = selectedEntry(state);
    const std::wstring kDirectory = entry ? moduleDirectoryForEntry(*entry) : std::wstring{};
    if (kDirectory.empty()) {
        state.statusText = L"当前项没有已验证的可导航模块文件路径。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }

    ksword::core::NavigationRequest request{};
    request.target = ksword::core::NavigationTarget::kFileBrowser;
    request.entity.kind = ksword::core::EntityKind::kFile;
    request.entity.text = kDirectory;
    state.statusText = ksword::ui::requestEntityNavigation(state.hwnd, request)
        ? L"已在文件模块打开模块所在目录。"
        : L"文件模块当前无法接收模块所在目录。";
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

void showContextMenu(ContextMenuViewState& state, POINT screenPoint) {
    selectRowAtPoint(state, screenPoint);
    const ContextMenuEntry* entry = selectedEntry(state);
    const std::wstring kModuleDirectory = entry ? moduleDirectoryForEntry(*entry) : std::wstring{};
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    const bool kBusy = state.actionInProgress;
    ::AppendMenuW(menu, MF_STRING | ((entry && entry->enabled && !kBusy) ? MF_ENABLED : MF_GRAYED),
        kMenuDisable, L"禁用（备份后删除）");
    ::AppendMenuW(menu, MF_STRING | ((entry && !entry->enabled && !kBusy) ? MF_ENABLED : MF_GRAYED),
        kMenuEnable, L"启用（从备份还原）");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING | ((entry && entry->enabled && !entry->registrationPath.empty() && !kBusy) ? MF_ENABLED : MF_GRAYED),
        kMenuOpenRegistry, L"在注册表中打开");
    ::AppendMenuW(menu, MF_STRING | ((!kModuleDirectory.empty() && !kBusy) ? MF_ENABLED : MF_GRAYED),
        kMenuOpenModuleDirectory, L"打开模块所在目录");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING | (entry ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制选中行");
    ::AppendMenuW(menu, MF_STRING, kMenuCopyVisible, L"复制可见行");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING, kMenuRefresh, L"刷新");

    const int kCommand = ::TrackPopupMenu(
        menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y, 0, state.hwnd, nullptr);
    ::DestroyMenu(menu);

    switch (static_cast<UINT>(kCommand)) {
    case kMenuDisable:
        runAction(state, true);
        break;
    case kMenuEnable:
        runAction(state, false);
        break;
    case kMenuOpenRegistry:
        openSelectedRegistryKey(state);
        break;
    case kMenuOpenModuleDirectory:
        openSelectedModuleDirectory(state);
        break;
    case kMenuCopyRow:
        state.statusText = copyText(state.hwnd, rowsAsText(state, false)) ? L"已复制选中行。" : L"复制失败。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        break;
    case kMenuCopyVisible:
        state.statusText = copyText(state.hwnd, rowsAsText(state, true)) ? L"已复制可见行。" : L"复制失败。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        break;
    case kMenuRefresh:
        beginScan(state);
        break;
    default:
        break;
    }
}

void layoutView(ContextMenuViewState& state) {
    RECT client{};
    ::GetClientRect(state.hwnd, &client);
    const int kWidth = width(client);
    const int kHeight = height(client);

    int cursorX = kGap;
    const int kFirstRowY = kGap;
    const auto kPlace = [&cursorX, kFirstRowY](HWND control, int controlWidth) {
        if (control) {
            ::MoveWindow(control, cursorX, kFirstRowY, controlWidth, kRowHeight, TRUE);
        }
        cursorX += controlWidth + kGap;
    };
    kPlace(state.refreshButton, 64);
    kPlace(state.disableButton, 140);
    kPlace(state.enableButton, 140);

    const int kSecondRowY = kFirstRowY + kRowHeight + kGap;
    if (state.filterBar) {
        ::MoveWindow(state.filterBar, kGap, kSecondRowY, (std::max)(120, kWidth - kGap * 2), kRowHeight, TRUE);
    }

    const int kListTop = kHeaderHeight;
    const int kDetailTop = (std::max)(kListTop, kHeight - kStatusHeight - kDetailHeight);
    const int kListHeight = (std::max)(0, kDetailTop - kListTop - kGap);
    if (HWND list = state.list.hwnd()) {
        ::MoveWindow(list, kGap, kListTop, (std::max)(0, kWidth - kGap * 2), kListHeight, TRUE);
    }
    if (state.detailEdit) {
        ::MoveWindow(state.detailEdit, kGap, kDetailTop, (std::max)(0, kWidth - kGap * 2),
            (std::max)(0, kHeight - kStatusHeight - kDetailTop - kGap), TRUE);
    }
    if (state.loadingOverlay) {
        ::MoveWindow(state.loadingOverlay, kGap, kListTop, (std::max)(0, kWidth - kGap * 2), kListHeight, TRUE);
    }
}

bool createChildControls(ContextMenuViewState& state) {
    HWND hwnd = state.hwnd;
    state.refreshButton = ksword::ui::createButton(hwnd, kRefreshButtonId, L"刷新", 0, 0, 0, 0);
    state.disableButton = ksword::ui::createButton(hwnd, kDisableButtonId, L"禁用（备份后删除）", 0, 0, 0, 0);
    state.enableButton = ksword::ui::createButton(hwnd, kEnableButtonId, L"启用（从备份还原）", 0, 0, 0, 0);
    state.filterBar = ksword::ui::createFilterBar(
        hwnd, kFilterBarId, L"筛选作用域、名称、CLSID 与模块路径", 0, 0, 0, 0);
    if (!state.refreshButton || !state.disableButton || !state.enableButton || !state.filterBar) {
        return false;
    }

    if (!state.list.create(hwnd, kListId, 0, 0, 1, 1, LVS_SHOWSELALWAYS | LVS_SINGLESEL)) {
        return false;
    }
    state.list.addColumns({
        { 0, 70, LVCFMT_LEFT, L"状态" },
        { 1, 80, LVCFMT_LEFT, L"作用域" },
        { 2, 130, LVCFMT_LEFT, L"类型" },
        { 3, 180, LVCFMT_LEFT, L"名称" },
        { 4, 250, LVCFMT_LEFT, L"CLSID" },
        { 5, 340, LVCFMT_LEFT, L"模块路径" },
        { 6, 70, LVCFMT_LEFT, L"模块" },
    });
    if (HWND list = state.list.hwnd()) {
        ListView_SetExtendedListViewStyle(list,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);
        ::SendMessageW(list, WM_SETFONT, reinterpret_cast<WPARAM>(ksword::ui::systemUiFont()), TRUE);
    }

    state.detailEdit = ::CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
        0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kDetailEditId)),
        ::GetModuleHandleW(nullptr), nullptr);
    if (!state.detailEdit) {
        return false;
    }
    ::SendMessageW(state.detailEdit, WM_SETFONT, reinterpret_cast<WPARAM>(ksword::ui::systemUiFont()), TRUE);
    ksword::ui::attachTextFindSupport(state.detailEdit);

    state.loadingOverlay = ksword::ui::createLoadingOverlay(hwnd, kLoadingOverlayId, { 0, 0, 1, 1 });
    if (!state.loadingOverlay) {
        return false;
    }

    ksword::ui::setWindowFontRecursive(hwnd);
    return true;
}

LRESULT CALLBACK contextMenuViewProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    auto* state = reinterpret_cast<ContextMenuViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (msg) {
    case WM_NCCREATE: {
        auto owned = std::make_unique<ContextMenuViewState>();
        owned->hwnd = hwnd;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(owned.release()));
        return TRUE;
    }
    case WM_CREATE:
        if (state) {
            if (!createChildControls(*state)) {
                return -1;
            }
            state->scanTask = std::make_unique<ksword::ui::AsyncSnapshotTask<ContextMenuScanResult>>(hwnd, kMsgScanCompleted);
            state->filterTask = std::make_unique<ksword::ui::AsyncSnapshotTask<ContextMenuFilterResult>>(hwnd, kMsgFilterCompleted);
            state->actionTask = std::make_unique<ksword::ui::AsyncSnapshotTask<ContextMenuActionResult>>(hwnd, kMsgActionCompleted);
            layoutView(*state);
            refreshSelectionDependentUi(*state);
            beginScan(*state);
        }
        return 0;
    case WM_SIZE:
        if (state) {
            layoutView(*state);
        }
        return 0;
    case WM_COMMAND:
        if (!state) {
            break;
        }
        {
            const int kId = LOWORD(wParam);
            const int kNotification = HIWORD(wParam);
            if (kId == kFilterBarId && kNotification == EN_CHANGE) {
                requestFilter(*state, ksword::ui::getFilterBarText(state->filterBar));
                return 0;
            }
            if (kNotification == BN_CLICKED) {
                switch (kId) {
                case kRefreshButtonId:
                    beginScan(*state);
                    return 0;
                case kDisableButtonId:
                    runAction(*state, true);
                    return 0;
                case kEnableButtonId:
                    runAction(*state, false);
                    return 0;
                default:
                    break;
                }
            }
        }
        break;
    case WM_NOTIFY:
        if (state) {
            const auto* header = reinterpret_cast<const NMHDR*>(lParam);
            if (header) {
                LRESULT result = 0;
                if (state->list.handleNotify(*header, result)) {
                    return result;
                }
                if (header->hwndFrom == state->list.hwnd() && header->code == LVN_ITEMCHANGED) {
                    const auto* changed = reinterpret_cast<const NMLISTVIEW*>(lParam);
                    if (changed && (changed->uNewState & LVIS_SELECTED) != 0) {
                        refreshSelectionDependentUi(*state);
                    }
                    return 0;
                }
                if (header->hwndFrom == state->list.hwnd() && header->code == NM_RCLICK) {
                    POINT point{};
                    ::GetCursorPos(&point);
                    showContextMenu(*state, point);
                    return 0;
                }
            }
        }
        break;
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
    case WM_CTLCOLORSTATIC: {
        HDC dc = reinterpret_cast<HDC>(wParam);
        ::SetBkMode(dc, TRANSPARENT);
        ::SetTextColor(dc, ksword::ui::appTheme().textColor);
        return reinterpret_cast<LRESULT>(ksword::ui::appTheme().windowBrush());
    }
    default:
        if (state) {
            if (msg == kMsgScanCompleted && state->scanTask) {
                state->scanTask->consume(hwnd, wParam, lParam);
                return 0;
            }
            if (msg == kMsgFilterCompleted && state->filterTask) {
                state->filterTask->consume(hwnd, wParam, lParam);
                return 0;
            }
            if (msg == kMsgActionCompleted && state->actionTask) {
                state->actionTask->consume(hwnd, wParam, lParam);
                return 0;
            }
        }
        if (msg == WM_NCDESTROY && state) {
            if (state->scanTask) {
                state->scanTask->cancel();
            }
            if (state->filterTask) {
                state->filterTask->cancel();
            }
            if (state->actionTask) {
                state->actionTask->cancel();
            }
            state->list.detach();
            delete state;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        }
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

bool ensureContextMenuViewClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = contextMenuViewProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = ksword::ui::appTheme().windowBrush();
    windowClass.lpszClassName = kContextMenuViewClass;
    registered = ::RegisterClassW(&windowClass) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

} // namespace

HWND createContextMenuView(HWND parent, const RECT& bounds) {
    if (!parent || !ensureContextMenuViewClass()) {
        return nullptr;
    }
    return ::CreateWindowExW(
        0, kContextMenuViewClass, L"", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        bounds.left, bounds.top, bounds.right - bounds.left, bounds.bottom - bounds.top,
        parent, nullptr, ::GetModuleHandleW(nullptr), nullptr);
}

} // namespace Ksword::Features::SysTools
