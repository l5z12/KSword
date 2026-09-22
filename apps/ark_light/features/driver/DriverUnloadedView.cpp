#include "DriverUnloadedView.h"

#include "../../ui/AsyncTask.h"
#include "../../ui/Controls.h"
#include "../../ui/ExportUtil.h"
#include "../../ui/FilterBar.h"
#include "../../ui/ListViewUtil.h"
#include "../../ui/LoadingOverlay.h"
#include "../../ui/Theme.h"
#include "../../ui/VirtualListView.h"
#include "../../../../shared/ark_client/ArkDriverClient.h"
#include "../../../../shared/driver/KswordArkUnloadedDriverIoctl.h"

#include <commctrl.h>
#include <windowsx.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <memory>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace ksword::features::driver {
namespace {

constexpr wchar_t kUnloadedViewClass[] = L"KswordARKLight.Driver.UnloadedView";

constexpr int kRefreshButtonId = 66001;
constexpr int kSourceComboId = 66002;
constexpr int kFilterBarId = 66003;
constexpr int kListId = 66004;
constexpr int kLoadingOverlayId = 66005;

constexpr UINT kMenuCopyRow = 66601;
constexpr UINT kMenuCopyVisible = 66602;
constexpr UINT kMenuRefresh = 66603;

constexpr UINT kMsgRefreshCompleted = WM_APP + 660;
constexpr UINT kMsgFilterCompleted = WM_APP + 661;

constexpr int kGap = 6;
constexpr int kRowHeight = 24;
constexpr int kHeaderHeight = kGap * 2 + kRowHeight;
constexpr int kStatusHeight = 22;
constexpr int kColumnCount = 8;

// kMissingFieldText marks a column the selected source genuinely does not carry.
// The IOCTL contract is explicit that a missing field must not be shown as 0,
// because a zero base address or a 1970 timestamp reads as real evidence.
constexpr const wchar_t* kMissingFieldText = L"—";

int width(const RECT& rc) {
    return rc.right > rc.left ? static_cast<int>(rc.right - rc.left) : 0;
}

int height(const RECT& rc) {
    return rc.bottom > rc.top ? static_cast<int>(rc.bottom - rc.top) : 0;
}

struct UnloadedFilterResult final {
    std::uint64_t generation = 0;
    std::wstring query;
    bool useRegex = false;
    std::vector<std::size_t> visibleIndexes;
};

struct UnloadedSnapshot final {
    std::uint32_t source = 0;
    bool transportOk = false;
    bool unsupported = false;
    std::uint32_t queryStatus = 0;
    std::uint32_t responseFlags = 0;
    std::uint32_t totalRows = 0;
    std::uint32_t skippedRows = 0;
    long lastStatus = 0;
    std::wstring transportMessage;
    std::vector<ksword::ark::UnloadedDriverEntry> entries;
};

struct UnloadedViewState final {
    HWND hwnd = nullptr;
    HWND refreshButton = nullptr;
    HWND sourceCombo = nullptr;
    HWND filterBar = nullptr;
    HWND loadingOverlay = nullptr;
    ksword::ui::VirtualListView list;
    std::shared_ptr<const std::vector<ksword::ui::VirtualListRow>> filterRows;
    std::wstring statusText = L"选择来源后点击刷新读取内核卸载记录。";
    std::wstring filterQuery;
    bool filterUseRegex = false;
    std::uint64_t displayGeneration = 0;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<UnloadedSnapshot>> refreshTask;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<UnloadedFilterResult>> filterTask;
};

std::wstring utf8ToWide(const std::string& text) {
    if (text.empty()) {
        return {};
    }
    const int kRequired = ::MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0);
    if (kRequired <= 0) {
        return {};
    }
    std::wstring wide(static_cast<std::size_t>(kRequired), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), wide.data(), kRequired);
    return wide;
}

std::wstring formatHex(const std::uint64_t value) {
    std::wostringstream stream;
    stream << L"0x" << std::uppercase << std::hex << std::setw(16) << std::setfill(L'0') << value;
    return stream.str();
}

// formatFileTime renders the 100ns unload timestamp. Zero is reported as missing
// rather than as 1601-01-01, which is what a raw conversion would produce.
std::wstring formatFileTime(const std::uint64_t rawTime) {
    if (rawTime == 0) {
        return kMissingFieldText;
    }
    FILETIME fileTime{};
    fileTime.dwLowDateTime = static_cast<DWORD>(rawTime & 0xFFFFFFFFULL);
    fileTime.dwHighDateTime = static_cast<DWORD>(rawTime >> 32);
    FILETIME localTime{};
    SYSTEMTIME systemTime{};
    if (!::FileTimeToLocalFileTime(&fileTime, &localTime) ||
        !::FileTimeToSystemTime(&localTime, &systemTime)) {
        return formatHex(rawTime);
    }
    std::wostringstream stream;
    stream << std::setfill(L'0')
        << systemTime.wYear << L'-' << std::setw(2) << systemTime.wMonth << L'-' << std::setw(2) << systemTime.wDay
        << L' ' << std::setw(2) << systemTime.wHour << L':' << std::setw(2) << systemTime.wMinute
        << L':' << std::setw(2) << systemTime.wSecond;
    return stream.str();
}

// formatPeTimestamp renders the PE header's TimeDateStamp, which is a 32-bit
// UTC time_t rather than a FILETIME. It is kept in both forms because the raw
// value is what a signature or a hash lookup is keyed on.
std::wstring formatPeTimestamp(const std::uint32_t rawStamp) {
    if (rawStamp == 0) {
        return kMissingFieldText;
    }
    const std::uint64_t kAsFileTime = static_cast<std::uint64_t>(rawStamp) * 10000000ULL + 116444736000000000ULL;
    return formatFileTime(kAsFileTime) + L" (0x" + [rawStamp] {
        std::wostringstream stream;
        stream << std::uppercase << std::hex << rawStamp;
        return stream.str();
    }() + L")";
}

std::wstring sourceText(const std::uint32_t source) {
    switch (source) {
    case KSWORD_ARK_UNLOADED_DRIVER_SOURCE_MM_UNLOADED_DRIVERS:
        return L"MmUnloadedDrivers";
    case KSWORD_ARK_UNLOADED_DRIVER_SOURCE_PIDDB_CACHE_TABLE:
        return L"PiDDBCacheTable";
    case KSWORD_ARK_UNLOADED_DRIVER_SOURCE_KERNEL_HASH_BUCKET_LIST:
        return L"g_KernelHashBucketList";
    default:
        return L"Source" + std::to_wstring(source);
    }
}

std::wstring queryStatusText(const std::uint32_t status) {
    switch (status) {
    case KSWORD_ARK_UNLOADED_DRIVER_STATUS_OK:
        return L"OK";
    case KSWORD_ARK_UNLOADED_DRIVER_STATUS_INVALID_REQUEST:
        return L"请求无效";
    case KSWORD_ARK_UNLOADED_DRIVER_STATUS_DYNDATA_UNAVAILABLE:
        return L"DynData 不可用（需要先加载符号偏移）";
    case KSWORD_ARK_UNLOADED_DRIVER_STATUS_MODULE_PROFILE_UNAVAILABLE:
        return L"模块 profile 不可用";
    case KSWORD_ARK_UNLOADED_DRIVER_STATUS_LAYOUT_UNAVAILABLE:
        return L"结构布局不可用";
    case KSWORD_ARK_UNLOADED_DRIVER_STATUS_READ_FAILED:
        return L"内核读取失败";
    case KSWORD_ARK_UNLOADED_DRIVER_STATUS_PARTIAL:
        return L"部分成功";
    default:
        return L"未知状态(" + std::to_wstring(status) + L")";
    }
}

std::wstring responseFlagText(const std::uint32_t flags) {
    std::wstring text;
    const auto kAppend = [&text](const wchar_t* label) {
        if (!text.empty()) {
            text += L" / ";
        }
        text += label;
    };
    if ((flags & KSWORD_ARK_UNLOADED_DRIVER_RESPONSE_FLAG_TRUNCATED) != 0) {
        kAppend(L"结果被行数上限截断");
    }
    if ((flags & KSWORD_ARK_UNLOADED_DRIVER_RESPONSE_FLAG_SKIPPED_INVALID_ROW) != 0) {
        kAppend(L"跳过了无效条目");
    }
    if ((flags & KSWORD_ARK_UNLOADED_DRIVER_RESPONSE_FLAG_SNAPSHOT_RACY) != 0) {
        kAppend(L"采集期间缓存发生变化");
    }
    return text;
}

// CellText renders one column, consulting the row's HAS_* bits first. Each of
// the three sources fills a different subset, so a column that reads "—" means
// this source does not track that field at all -- not that the value is zero.
std::wstring cellText(const ksword::ark::UnloadedDriverEntry& entry, const int column) {
    switch (column) {
    case 0:
        return sourceText(entry.source);
    case 1:
        return (entry.flags & KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_NAME) != 0
            ? entry.driverName
            : kMissingFieldText;
    case 2:
        return (entry.flags & KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_BASE) != 0
            ? formatHex(entry.baseAddress)
            : kMissingFieldText;
    case 3:
        return (entry.flags & KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_SIZE) != 0
            ? formatHex(entry.imageSize)
            : kMissingFieldText;
    case 4:
        return (entry.flags & KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_UNLOAD_TIME) != 0
            ? formatFileTime(entry.unloadTime)
            : kMissingFieldText;
    case 5:
        return (entry.flags & KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_TIMESTAMP) != 0
            ? formatPeTimestamp(entry.timeDateStamp)
            : kMissingFieldText;
    case 6:
        return (entry.flags & KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_LOAD_STATUS) != 0
            ? formatHex(static_cast<std::uint64_t>(static_cast<std::uint32_t>(entry.loadStatus)))
            : kMissingFieldText;
    case 7:
        return formatHex(entry.entryAddress);
    default:
        return {};
    }
}

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

std::wstring rowsAsText(const UnloadedViewState& state, bool visibleRows) {
    const auto& rows = state.list.rows();
    const auto& visible = state.list.visibleIndexes();
    const HWND kList = state.list.hwnd();
    std::wstring text;
    for (std::size_t item = 0; item < visible.size(); ++item) {
        if (!visibleRows &&
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

const std::vector<std::wstring>& unloadedColumnTitles() {
    static const std::vector<std::wstring> kTitles{
        L"来源", L"驱动名", L"基址", L"映像大小", L"卸载时间", L"编译时间戳", L"加载状态", L"条目地址"
    };
    return kTitles;
}

void applyUnloadedFilter(UnloadedViewState& state, UnloadedFilterResult result) {
    if (result.generation != state.displayGeneration || result.query != state.filterQuery ||
        result.useRegex != state.filterUseRegex || !state.list.hwnd()) {
        return;
    }
    state.list.setVisibleIndexes(std::move(result.visibleIndexes));
    if (!result.query.empty()) {
        state.statusText = L"筛选结果 " + std::to_wstring(state.list.visibleIndexes().size()) + L" / " +
            std::to_wstring(state.list.rows().size()) + L" 项。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
    }
}

void requestUnloadedFilter(UnloadedViewState& state, std::wstring query) {
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
            UnloadedFilterResult result{};
            result.generation = kGeneration;
            result.query = std::move(query);
            result.useRegex = kUseRegex;
            result.visibleIndexes = ksword::ui::VirtualListView::filterRowIndexes(*kRows, result.query, kUseRegex);
            return result;
        },
        [&state](std::uint64_t, std::optional<UnloadedFilterResult>&& result, std::exception_ptr error) {
            if (error || !result.has_value()) {
                state.statusText = L"卸载记录筛选异常结束，已保留当前结果。";
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            applyUnloadedFilter(state, std::move(*result));
        });
}

std::uint32_t selectedSource(const UnloadedViewState& state) {
    const LRESULT kSelection = state.sourceCombo ? ::SendMessageW(state.sourceCombo, CB_GETCURSEL, 0, 0) : 0;
    switch (kSelection) {
    case 1:
        return KSWORD_ARK_UNLOADED_DRIVER_SOURCE_PIDDB_CACHE_TABLE;
    case 2:
        return KSWORD_ARK_UNLOADED_DRIVER_SOURCE_KERNEL_HASH_BUCKET_LIST;
    case 0:
    default:
        return KSWORD_ARK_UNLOADED_DRIVER_SOURCE_MM_UNLOADED_DRIVERS;
    }
}

void buildRows(UnloadedViewState& state, const std::vector<ksword::ark::UnloadedDriverEntry>& entries) {
    std::vector<ksword::ui::VirtualListRow> rows;
    rows.reserve(entries.size());
    for (std::size_t index = 0; index < entries.size(); ++index) {
        const ksword::ark::UnloadedDriverEntry& entry = entries[index];
        ksword::ui::VirtualListRow row{};
        // The cache slot address is unique per row and survives a re-read, which
        // is what a stable key needs; the driver name is not unique because the
        // same driver can be loaded and unloaded repeatedly.
        row.stableKey = formatHex(entry.entryAddress) + L"|" + std::to_wstring(index);
        row.itemData = static_cast<LPARAM>(index);
        row.cells.reserve(kColumnCount);
        for (int column = 0; column < kColumnCount; ++column) {
            row.cells.push_back(cellText(entry, column));
        }
        rows.push_back(std::move(row));
    }
    auto filterRows = std::make_shared<std::vector<ksword::ui::VirtualListRow>>(std::move(rows));
    state.list.setRows(*filterRows);
    state.filterRows = std::move(filterRows);
    ++state.displayGeneration;
}

void beginRefresh(UnloadedViewState& state) {
    if (!state.refreshTask) {
        return;
    }
    const std::uint32_t kSource = selectedSource(state);
    state.statusText = L"正在读取 " + sourceText(kSource) + L" …";
    if (state.refreshButton) {
        ::EnableWindow(state.refreshButton, FALSE);
    }
    ksword::ui::setLoadingOverlay(state.loadingOverlay, true, L"正在查询内核卸载记录…");
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
    state.refreshTask->request(
        [kSource] {
            UnloadedSnapshot snapshot{};
            snapshot.source = kSource;
            const ksword::ark::DriverClient kClient;
            const ksword::ark::UnloadedDriverQueryResult kQuery =
                kClient.queryUnloadedDrivers(kSource, KSWORD_ARK_UNLOADED_DRIVER_DEFAULT_ROWS);
            snapshot.transportOk = kQuery.io.ok;
            snapshot.unsupported = kQuery.unsupported;
            snapshot.queryStatus = kQuery.queryStatus;
            snapshot.responseFlags = kQuery.responseFlags;
            snapshot.totalRows = kQuery.totalRows;
            snapshot.skippedRows = kQuery.skippedRows;
            snapshot.lastStatus = kQuery.lastStatus;
            snapshot.transportMessage = utf8ToWide(kQuery.io.message);
            snapshot.entries = kQuery.entries;
            return snapshot;
        },
        [&state](std::uint64_t, std::optional<UnloadedSnapshot>&& snapshot, std::exception_ptr error) {
            if (state.refreshButton) {
                ::EnableWindow(state.refreshButton, TRUE);
            }
            ksword::ui::setLoadingOverlay(state.loadingOverlay, false);
            if (error || !snapshot.has_value()) {
                state.statusText = L"卸载记录查询异常结束。";
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            if (snapshot->unsupported) {
                state.statusText = L"当前 KswordARK 驱动不支持卸载记录 IOCTL，请更新驱动。";
                buildRows(state, {});
                requestUnloadedFilter(state, state.filterQuery);
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            if (!snapshot->transportOk) {
                state.statusText = L"驱动通信失败：" + snapshot->transportMessage;
                buildRows(state, {});
                requestUnloadedFilter(state, state.filterQuery);
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }

            const std::size_t kReturned = snapshot->entries.size();
            buildRows(state, snapshot->entries);
            std::wstring status = sourceText(snapshot->source) + L"：返回 " + std::to_wstring(kReturned) +
                L" / 共 " + std::to_wstring(snapshot->totalRows) + L" 条，状态 " +
                queryStatusText(snapshot->queryStatus);
            if (snapshot->skippedRows != 0) {
                status += L"，跳过 " + std::to_wstring(snapshot->skippedRows) + L" 条";
            }
            if (const std::wstring kFlagText = responseFlagText(snapshot->responseFlags); !kFlagText.empty()) {
                status += L"（" + kFlagText + L"）";
            }
            // A degraded status still shows whatever rows came back; saying why
            // the read was partial is more useful than an empty table.
            if (snapshot->queryStatus != KSWORD_ARK_UNLOADED_DRIVER_STATUS_OK &&
                snapshot->queryStatus != KSWORD_ARK_UNLOADED_DRIVER_STATUS_PARTIAL) {
                status += L"；NTSTATUS=0x" + [&snapshot] {
                    std::wostringstream stream;
                    stream << std::uppercase << std::hex << static_cast<std::uint32_t>(snapshot->lastStatus);
                    return stream.str();
                }();
            }
            state.statusText = std::move(status);
            requestUnloadedFilter(state, state.filterQuery);
            ::InvalidateRect(state.hwnd, nullptr, TRUE);
        });
}

void showContextMenu(UnloadedViewState& state, POINT screenPoint) {
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    ::AppendMenuW(menu, MF_STRING, kMenuCopyRow, L"复制选中行");
    ::AppendMenuW(menu, MF_STRING, kMenuCopyVisible, L"复制可见行");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING, kMenuRefresh, L"刷新");
    const int kCommand = ::TrackPopupMenu(
        menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y, 0, state.hwnd, nullptr);
    ::DestroyMenu(menu);
    switch (static_cast<UINT>(kCommand)) {
    case kMenuCopyRow:
        state.statusText = copyText(state.hwnd, rowsAsText(state, false)) ? L"已复制选中行。" : L"复制失败。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        break;
    case kMenuCopyVisible:
        state.statusText = copyText(state.hwnd, rowsAsText(state, true)) ? L"已复制可见行。" : L"复制失败。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        break;
    case kMenuRefresh:
        beginRefresh(state);
        break;
    default:
        break;
    }
}

void layoutView(UnloadedViewState& state) {
    RECT client{};
    ::GetClientRect(state.hwnd, &client);
    const int kWidth = width(client);
    const int kHeight = height(client);

    int cursorX = kGap;
    if (state.refreshButton) {
        ::MoveWindow(state.refreshButton, cursorX, kGap, 64, kRowHeight, TRUE);
    }
    cursorX += 64 + kGap;
    if (state.sourceCombo) {
        ::MoveWindow(state.sourceCombo, cursorX, kGap, 200, kRowHeight * 6, TRUE);
    }
    cursorX += 200 + kGap;
    if (state.filterBar) {
        ::MoveWindow(state.filterBar, cursorX, kGap, (std::max)(120, kWidth - cursorX - kGap), kRowHeight, TRUE);
    }

    const int kListTop = kHeaderHeight;
    const int kListHeight = (std::max)(0, kHeight - kListTop - kStatusHeight - kGap);
    if (HWND list = state.list.hwnd()) {
        ::MoveWindow(list, kGap, kListTop, (std::max)(0, kWidth - kGap * 2), kListHeight, TRUE);
    }
    if (state.loadingOverlay) {
        ::MoveWindow(state.loadingOverlay, kGap, kListTop, (std::max)(0, kWidth - kGap * 2), kListHeight, TRUE);
    }
}

bool createChildControls(UnloadedViewState& state) {
    HWND hwnd = state.hwnd;
    state.refreshButton = ksword::ui::createButton(hwnd, kRefreshButtonId, L"刷新", 0, 0, 0, 0);
    state.sourceCombo = ::CreateWindowExW(0, WC_COMBOBOXW, L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST | CBS_HASSTRINGS,
        0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kSourceComboId)),
        ::GetModuleHandleW(nullptr), nullptr);
    if (!state.sourceCombo) {
        return false;
    }
    for (const wchar_t* label : { L"MmUnloadedDrivers", L"PiDDBCacheTable", L"g_KernelHashBucketList" }) {
        ::SendMessageW(state.sourceCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(label));
    }
    ::SendMessageW(state.sourceCombo, CB_SETCURSEL, 0, 0);
    state.filterBar = ksword::ui::createFilterBar(hwnd, kFilterBarId, L"筛选驱动名、地址与时间", 0, 0, 0, 0);

    if (!state.list.create(hwnd, kListId, 0, 0, 1, 1, LVS_SHOWSELALWAYS)) {
        return false;
    }
    state.list.addColumns({
        { 0, 170, LVCFMT_LEFT, L"来源" },
        { 1, 220, LVCFMT_LEFT, L"驱动名" },
        { 2, 150, LVCFMT_LEFT, L"基址" },
        { 3, 130, LVCFMT_LEFT, L"映像大小" },
        { 4, 150, LVCFMT_LEFT, L"卸载时间" },
        { 5, 200, LVCFMT_LEFT, L"编译时间戳" },
        { 6, 120, LVCFMT_LEFT, L"加载状态" },
        { 7, 150, LVCFMT_LEFT, L"条目地址" },
    });
    if (HWND list = state.list.hwnd()) {
        ListView_SetExtendedListViewStyle(list,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);
        ::SendMessageW(list, WM_SETFONT, reinterpret_cast<WPARAM>(ksword::ui::systemUiFont()), TRUE);
    }

    state.loadingOverlay = ksword::ui::createLoadingOverlay(hwnd, kLoadingOverlayId, { 0, 0, 1, 1 });
    if (!state.refreshButton || !state.filterBar || !state.loadingOverlay) {
        return false;
    }
    ksword::ui::setWindowFontRecursive(hwnd);
    return true;
}

UnloadedViewState* stateFromWindow(HWND hwnd) {
    return reinterpret_cast<UnloadedViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

LRESULT CALLBACK unloadedViewProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    auto* state = stateFromWindow(hwnd);
    switch (msg) {
    case WM_NCCREATE: {
        auto owned = std::make_unique<UnloadedViewState>();
        owned->hwnd = hwnd;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(owned.release()));
        return TRUE;
    }
    case WM_CREATE:
        if (state) {
            if (!createChildControls(*state)) {
                return -1;
            }
            state->refreshTask = std::make_unique<ksword::ui::AsyncSnapshotTask<UnloadedSnapshot>>(hwnd, kMsgRefreshCompleted);
            state->filterTask = std::make_unique<ksword::ui::AsyncSnapshotTask<UnloadedFilterResult>>(hwnd, kMsgFilterCompleted);
            layoutView(*state);
            // The first read is deferred to an explicit refresh: this page talks
            // to the driver, and the driver may not be loaded when the tab is
            // merely created alongside its siblings.
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
                requestUnloadedFilter(*state, ksword::ui::getFilterBarText(state->filterBar));
                return 0;
            }
            if (kId == kSourceComboId && kNotification == CBN_SELCHANGE) {
                beginRefresh(*state);
                return 0;
            }
            if (kId == kRefreshButtonId && kNotification == BN_CLICKED) {
                beginRefresh(*state);
                return 0;
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
            state->list.detach();
            delete state;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        }
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

bool ensureUnloadedViewClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = unloadedViewProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = ksword::ui::appTheme().windowBrush();
    windowClass.lpszClassName = kUnloadedViewClass;
    registered = ::RegisterClassW(&windowClass) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

} // namespace

HWND createDriverUnloadedView(HWND parent, const RECT& bounds) {
    if (!parent || !ensureUnloadedViewClass()) {
        return nullptr;
    }
    return ::CreateWindowExW(
        0, kUnloadedViewClass, L"", WS_CHILD | WS_CLIPCHILDREN,
        bounds.left, bounds.top, bounds.right - bounds.left, bounds.bottom - bounds.top,
        parent, nullptr, ::GetModuleHandleW(nullptr), nullptr);
}

std::wstring exportDriverUnloadedViewTsv(HWND page) {
    auto* state = page ? stateFromWindow(page) : nullptr;
    if (!state) {
        return {};
    }
    return ksword::ui::buildVisibleVirtualListTsv(unloadedColumnTitles(), state->list);
}

} // namespace Ksword::Features::Driver
