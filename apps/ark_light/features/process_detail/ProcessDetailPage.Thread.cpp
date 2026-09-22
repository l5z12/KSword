#include "../../core/Common.h"
#include "../../core/Win32Lean.h"
#include "../../ui/FilterBar.h"

#include "../../../../shared/ark_client/ArkDriverClient.h"
#include "../../../../shared/ThreadAffinityR3.h"

#include <commctrl.h>

#include "ProcessDetailPage.h"

#include <algorithm>
#include <cstdint>
#include <cwctype>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

namespace ksword::features::process_detail {
namespace {

constexpr UINT kThreadCopyCellCommand = 64101;
constexpr UINT kThreadCopyRowCommand = 64102;
constexpr UINT kThreadCopyAllCommand = 64103;
constexpr UINT kThreadShowDetailCommand = 64104;
constexpr UINT kThreadSuspendCommand = 64105;
constexpr UINT kThreadResumeCommand = 64106;
constexpr UINT kThreadTerminateCommand = 64107;
constexpr UINT kThreadR0TerminateCommand = 64108;
constexpr UINT kThreadAffinityFollowProcessCommand = 50000;
constexpr UINT kThreadAffinityProcessorBaseCommand = 50001;
constexpr std::size_t kThreadAffinityMaxProcessorCommands = 15000U;

constexpr UINT_PTR kThreadLayoutSubclassId = 0x54485244U; // "THRD"
constexpr UINT_PTR kThreadLayoutTimerId = 0x54485245U;

struct ThreadLayoutState {
    HWND group = nullptr;
    HWND refresh = nullptr;
    HWND sample = nullptr;
    HWND stack = nullptr;
    HWND status = nullptr;
    HWND filter = nullptr;
    HWND list = nullptr;
    HWND output = nullptr;
};

struct ThreadAffinityMenuState {
    ksword::thread_affinity_r3::Snapshot snapshot;
    bool readable = false;
};

std::wstring utf8ToWide(const std::string& text);

std::wstring threadAffinityProcessorText(
    const ksword::thread_affinity_r3::LogicalProcessorState& processor) {
    std::wstring text = L"G" + std::to_wstring(processor.coordinate.group) +
        L":L" + std::to_wstring(processor.coordinate.logicalIndex);
    if (!processor.topologyLabel.empty()) {
        text += L" (" + utf8ToWide(processor.topologyLabel) + L")";
    }
    return text;
}

void appendThreadAffinitySubMenu(
    HMENU parentMenu,
    DWORD processId,
    DWORD threadId,
    ULONGLONG threadCreationTime100ns,
    ThreadAffinityMenuState& state) {
    HMENU affinityMenu = ::CreatePopupMenu();
    if (!affinityMenu) {
        return;
    }

    std::string detailText;
    state.readable = ksword::thread_affinity_r3::queryThreadAffinityState(
        threadId,
        processId,
        threadCreationTime100ns,
        &state.snapshot,
        &detailText);
    if (!state.readable) {
        ::AppendMenuW(
            affinityMenu,
            MF_STRING | MF_GRAYED,
            0,
            L"当前线程亲和性不可用");
    } else {
        ::AppendMenuW(
            affinityMenu,
            MF_STRING | (state.snapshot.followsProcessCpuSets ? MF_CHECKED : MF_UNCHECKED),
            kThreadAffinityFollowProcessCommand,
            L"跟随进程 CPU Set");
        ::AppendMenuW(affinityMenu, MF_SEPARATOR, 0, nullptr);

        const std::size_t kProcessorCount = std::min(
            state.snapshot.processors.size(),
            kThreadAffinityMaxProcessorCommands);
        for (std::size_t index = 0; index < kProcessorCount; ++index) {
            const auto& processor = state.snapshot.processors[index];
            UINT flags = MF_STRING | (processor.selected ? MF_CHECKED : MF_UNCHECKED);
            if (!processor.available) {
                flags |= MF_GRAYED;
            }
            const std::wstring kText = threadAffinityProcessorText(processor);
            ::AppendMenuW(
                affinityMenu,
                flags,
                kThreadAffinityProcessorBaseCommand + static_cast<UINT>(index),
                kText.c_str());
        }
    }

    ::AppendMenuW(
        parentMenu,
        MF_POPUP,
        reinterpret_cast<UINT_PTR>(affinityMenu),
        L"线程亲和性");
}

bool buildThreadAffinityRule(
    const ThreadAffinityMenuState& state,
    UINT command,
    ksword::thread_affinity_r3::Rule& rule) {
    rule = {};
    if (!state.readable) {
        return false;
    }
    if (command == kThreadAffinityFollowProcessCommand) {
        rule.followProcessCpuSets = true;
        return true;
    }
    if (command < kThreadAffinityProcessorBaseCommand) {
        return false;
    }
    const std::size_t kProcessorIndex =
        static_cast<std::size_t>(command - kThreadAffinityProcessorBaseCommand);
    if (kProcessorIndex >= state.snapshot.processors.size() ||
        !state.snapshot.processors[kProcessorIndex].available) {
        return false;
    }

    for (const auto& processor : state.snapshot.processors) {
        if (processor.available &&
            (state.snapshot.followsProcessCpuSets || processor.selected)) {
            rule.processors.push_back(processor.coordinate);
        }
    }
    const auto kClickedCoordinate = state.snapshot.processors[kProcessorIndex].coordinate;
    const auto kExisting = std::find(
        rule.processors.begin(),
        rule.processors.end(),
        kClickedCoordinate);
    if (kExisting == rule.processors.end()) {
        rule.processors.push_back(kClickedCoordinate);
    } else {
        rule.processors.erase(kExisting);
    }
    ksword::thread_affinity_r3::normalizeCoordinates(&rule.processors);
    return !rule.processors.empty();
}

int clientWidth(HWND hwnd) {
    RECT client{};
    return hwnd && ::GetClientRect(hwnd, &client)
        ? std::max(0L, client.right - client.left)
        : 0;
}

int clientHeight(HWND hwnd) {
    RECT client{};
    return hwnd && ::GetClientRect(hwnd, &client)
        ? std::max(0L, client.bottom - client.top)
        : 0;
}

void moveControl(HWND hwnd, int x, int y, int width, int height) {
    if (hwnd) {
        ::MoveWindow(hwnd, x, y, std::max(0, width), std::max(0, height), TRUE);
    }
}

void layoutThreadControls(HWND page, const ThreadLayoutState& state) {
    const int kWidth = clientWidth(page);
    const int kHeight = clientHeight(page);
    if (kWidth <= 0 || kHeight <= 0) {
        return;
    }

    constexpr int kOuterMargin = 6;
    constexpr int kInnerMargin = 8;
    constexpr int kSpacing = 6;
    constexpr int kToolbarY = 25;
    constexpr int kToolbarHeight = 28;
    constexpr int kFilterY = 59;
    constexpr int kFilterHeight = 26;
    constexpr int kListY = kFilterY + kFilterHeight + kSpacing;
    constexpr int kPreferredOutputHeight = 220;
    constexpr int kMinimumOutputHeight = 90;
    constexpr int kMinimumListHeight = 80;

    moveControl(
        state.group,
        kOuterMargin,
        kOuterMargin,
        kWidth - kOuterMargin * 2,
        kHeight - kOuterMargin * 2);

    int x = kOuterMargin + kInnerMargin;
    moveControl(state.refresh, x, kToolbarY, 92, kToolbarHeight);
    x += 92 + kSpacing;
    moveControl(state.sample, x, kToolbarY, 112, kToolbarHeight);
    x += 112 + kSpacing;
    moveControl(state.stack, x, kToolbarY, 108, kToolbarHeight);
    x += 108 + kSpacing;
    moveControl(state.status, x, kToolbarY, kWidth - x - kOuterMargin - kInnerMargin, kToolbarHeight);
    moveControl(state.filter, kOuterMargin + kInnerMargin, kFilterY, kWidth - (kOuterMargin + kInnerMargin) * 2, kFilterHeight);

    const int kContentBottom = kHeight - kOuterMargin - kInnerMargin;
    const int kAvailableBelowToolbar = std::max(0, kContentBottom - kListY);
    int outputHeight = std::min(kPreferredOutputHeight, std::max(kMinimumOutputHeight, kAvailableBelowToolbar / 3));
    if (kAvailableBelowToolbar < kMinimumListHeight + kSpacing + kMinimumOutputHeight) {
        outputHeight = std::max(48, kAvailableBelowToolbar - kMinimumListHeight - kSpacing);
    }
    const int kOutputY = std::max(kListY + kMinimumListHeight + kSpacing, kContentBottom - outputHeight);
    const int kListHeight = std::max(0, kOutputY - kSpacing - kListY);
    const int kContentWidth = kWidth - (kOuterMargin + kInnerMargin) * 2;
    moveControl(state.list, kOuterMargin + kInnerMargin, kListY, kContentWidth, kListHeight);
    moveControl(state.output, kOuterMargin + kInnerMargin, kOutputY, kContentWidth, kContentBottom - kOutputY);
}

LRESULT CALLBACK threadLayoutSubclassProc(
    HWND hwnd,
    UINT message,
    WPARAM wParam,
    LPARAM lParam,
    UINT_PTR subclassId,
    DWORD_PTR referenceData) {
    auto* state = reinterpret_cast<ThreadLayoutState*>(referenceData);
    if (!state) {
        return ::DefSubclassProc(hwnd, message, wParam, lParam);
    }

    if (message == WM_SIZE) {
        // The common page subclass applies the frozen placement table first.
        // Re-run the thread-specific bottom anchoring after that pass completes.
        const LRESULT kResult = ::DefSubclassProc(hwnd, message, wParam, lParam);
        ::SetTimer(hwnd, kThreadLayoutTimerId, 1, nullptr);
        return kResult;
    }
    if (message == WM_TIMER && wParam == kThreadLayoutTimerId) {
        ::KillTimer(hwnd, kThreadLayoutTimerId);
        layoutThreadControls(hwnd, *state);
        return 0;
    }
    if (message == WM_NCDESTROY) {
        ::KillTimer(hwnd, kThreadLayoutTimerId);
        ::RemoveWindowSubclass(hwnd, threadLayoutSubclassProc, subclassId);
        delete state;
    }
    return ::DefSubclassProc(hwnd, message, wParam, lParam);
}

std::wstring decimalText(std::uint64_t value) {
    return std::to_wstring(value);
}

std::wstring signedDecimalText(LONG value) {
    return std::to_wstring(static_cast<long long>(value));
}

std::wstring hexAddressText(std::uintptr_t value) {
    if (value == 0) {
        return L"-";
    }
    std::wostringstream text;
    text << L"0x" << std::hex << std::uppercase << value;
    return text.str();
}

std::wstring win32ErrorText(const wchar_t* operation, DWORD error) {
    wchar_t* message = nullptr;
    const DWORD kLength = ::FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        error,
        0,
        reinterpret_cast<LPWSTR>(&message),
        0,
        nullptr);

    std::wstring result = operation ? operation : L"Win32";
    result += L" 失败 (" + std::to_wstring(error) + L")";
    if (kLength != 0 && message) {
        std::wstring detail(message, kLength);
        while (!detail.empty() &&
               (detail.back() == L'\r' || detail.back() == L'\n' || detail.back() == L' ')) {
            detail.pop_back();
        }
        if (!detail.empty()) {
            result += L": " + detail;
        }
    }
    if (message) {
        ::LocalFree(message);
    }
    return result;
}

std::wstring utf8ToWide(const std::string& text) {
    if (text.empty()) {
        return {};
    }
    const int kRequired = ::MultiByteToWideChar(
        CP_UTF8,
        0,
        text.data(),
        static_cast<int>(text.size()),
        nullptr,
        0);
    if (kRequired <= 0) {
        return { text.begin(), text.end() };
    }
    std::wstring result(static_cast<std::size_t>(kRequired), L'\0');
    ::MultiByteToWideChar(
        CP_UTF8,
        0,
        text.data(),
        static_cast<int>(text.size()),
        result.data(),
        kRequired);
    return result;
}

std::vector<ksword::ui::VirtualListRow> buildThreadVirtualRows(const std::vector<ProcessThreadInfo>& threads) {
    std::vector<ksword::ui::VirtualListRow> rows;
    rows.reserve(threads.size());
    for (std::size_t index = 0; index < threads.size(); ++index) {
        const ProcessThreadInfo& thread = threads[index];
        ksword::ui::VirtualListRow row{};
        row.stableKey = decimalText(thread.threadId) + L"\n" + hexAddressText(thread.startAddress);
        row.itemData = static_cast<LPARAM>(index + 1);
        row.cells = {
            decimalText(thread.threadId),
            thread.statusText.empty() ? L"-" : thread.statusText,
            signedDecimalText(thread.basePriority),
            L"-",
            hexAddressText(thread.startAddress),
            L"Unavailable",
            L"Unavailable",
            L"Unavailable",
            L"U:Unavailable | K:Unavailable | Unavailable",
            L"Unavailable"
        };
        rows.push_back(std::move(row));
    }
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

bool selectedItemData(HWND list, std::size_t& indexOut) {
    indexOut = 0;
    if (!list) {
        return false;
    }
    const int kRow = ListView_GetNextItem(list, -1, LVNI_SELECTED);
    if (kRow < 0) {
        return false;
    }
    LVITEMW item{};
    item.mask = LVIF_PARAM;
    item.iItem = kRow;
    if (!ListView_GetItem(list, &item) || item.lParam <= 0) {
        return false;
    }
    indexOut = static_cast<std::size_t>(item.lParam - 1);
    return true;
}

} // namespace

bool ProcessDetailPage::openVerifiedProcessActionTarget(
    DWORD targetProcessId,
    ULONGLONG expectedProcessCreationTime100ns,
    DWORD requestedProcessAccess,
    ksword::core::UniqueHandle& processOut,
    std::wstring& errorText) {
    processOut.reset();
    errorText.clear();
    if (targetProcessId == 0U || expectedProcessCreationTime100ns == 0U) {
        errorText = L"目标进程身份不可用，已取消操作。";
        return false;
    }

    processOut.reset(::OpenProcess(
        requestedProcessAccess | PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        targetProcessId));
    if (!processOut.valid()) {
        errorText = win32ErrorText(L"OpenProcess", ::GetLastError());
        return false;
    }
    FILETIME processCreationTime{};
    FILETIME processExitTime{};
    FILETIME processKernelTime{};
    FILETIME processUserTime{};
    if (!::GetProcessTimes(
            processOut.get(),
            &processCreationTime,
            &processExitTime,
            &processKernelTime,
            &processUserTime)) {
        errorText = win32ErrorText(L"GetProcessTimes", ::GetLastError());
        return false;
    }
    const ULONGLONG kActualProcessCreationTime100ns =
        (static_cast<ULONGLONG>(processCreationTime.dwHighDateTime) << 32U) |
        static_cast<ULONGLONG>(processCreationTime.dwLowDateTime);
    if (kActualProcessCreationTime100ns == 0U ||
        kActualProcessCreationTime100ns != expectedProcessCreationTime100ns) {
        errorText = L"目标进程实例已变更，已取消操作。";
        return false;
    }
    return true;
}

bool ProcessDetailPage::openVerifiedThreadActionTarget(
    DWORD targetProcessId,
    ULONGLONG expectedProcessCreationTime100ns,
    DWORD targetThreadId,
    ULONGLONG expectedThreadCreationTime100ns,
    DWORD requestedThreadAccess,
    ksword::core::UniqueHandle& processOut,
    ksword::core::UniqueHandle& threadOut,
    std::wstring& errorText) {
    threadOut.reset();
    if (targetThreadId == 0U || expectedThreadCreationTime100ns == 0U) {
        processOut.reset();
        errorText = L"目标线程身份不可用，已取消操作。";
        return false;
    }
    if (!openVerifiedProcessActionTarget(
            targetProcessId,
            expectedProcessCreationTime100ns,
            PROCESS_QUERY_LIMITED_INFORMATION,
            processOut,
            errorText)) {
        return false;
    }

    threadOut.reset(::OpenThread(
        THREAD_QUERY_LIMITED_INFORMATION | requestedThreadAccess,
        FALSE,
        targetThreadId));
    if (!threadOut.valid()) {
        errorText = win32ErrorText(L"OpenThread", ::GetLastError());
        return false;
    }
    const DWORD kActualOwnerProcessId = ::GetProcessIdOfThread(threadOut.get());
    if (kActualOwnerProcessId == 0U) {
        errorText = win32ErrorText(L"GetProcessIdOfThread", ::GetLastError());
        return false;
    }
    if (kActualOwnerProcessId != targetProcessId) {
        errorText = L"目标线程已不属于所选进程，已取消操作。";
        return false;
    }

    FILETIME threadCreationTime{};
    FILETIME threadExitTime{};
    FILETIME threadKernelTime{};
    FILETIME threadUserTime{};
    if (!::GetThreadTimes(
            threadOut.get(),
            &threadCreationTime,
            &threadExitTime,
            &threadKernelTime,
            &threadUserTime)) {
        errorText = win32ErrorText(L"GetThreadTimes", ::GetLastError());
        return false;
    }
    const ULONGLONG kActualThreadCreationTime100ns =
        (static_cast<ULONGLONG>(threadCreationTime.dwHighDateTime) << 32U) |
        static_cast<ULONGLONG>(threadCreationTime.dwLowDateTime);
    if (kActualThreadCreationTime100ns == 0U ||
        kActualThreadCreationTime100ns != expectedThreadCreationTime100ns) {
        errorText = L"目标线程实例已变更，已取消操作。";
        return false;
    }
    return true;
}

bool ProcessDetailPage::createThreadTab() {
    const TabIndex kTab = TabIndex::kThreads;
    HWND group = addGroup(kTab, L"线程枚举与上下文摘要", 6, 6, -6, -6);
    HWND refresh = addButton(kTab, kThreadRefresh, L"刷新线程", 14, 25, 92, 28);
    HWND sample = addButton(kTab, kThreadSample, L"采样PDB字段", 112, 25, 112, 28);
    HWND stack = addButton(kTab, kThreadStack, L"查看调用栈", 230, 25, 108, 28);
    HWND status = addLabel(kTab, kThreadStatus, L"● 尚未刷新", 344, 25, -14, 28);
    HWND page = pages_[static_cast<std::size_t>(kTab)].hwnd;
    HWND filter = ksword::ui::createFilterBar(page, kThreadFilter, L"筛选线程字段与 R0 详情", 14, 59, 100, 26);
    if (filter) {
        pages_[static_cast<std::size_t>(kTab)].placements.push_back(Placement{ filter, 14, 59, -14, 26 });
    }
    HWND list = addVirtualList(kTab, kThreadList, 14, 91, -14, -244, threadVirtualList_);
    HWND output = addEdit(
        kTab,
        kThreadRuntimeOutput,
        L"选择线程行后可查看 runtime detail；当前快照未提供的字段将明确显示为 Unavailable。",
        true,
        true,
        14,
        430,
        -14,
        -14);

    if (!group || !refresh || !sample || !stack || !status || !filter || !list || !output) {
        return false;
    }

    addListColumn(list, 0, L"ThreadID", 96);
    addListColumn(list, 1, L"状态", 82);
    addListColumn(list, 2, L"优先级", 72);
    addListColumn(list, 3, L"上下文切换", 96);
    addListColumn(list, 4, L"起始地址", 130);
    addListColumn(list, 5, L"TEB地址", 130);
    addListColumn(list, 6, L"亲和性", 108);
    addListColumn(list, 7, L"寄存器", 100);
    addListColumn(list, 8, L"R0栈边界", 260);
    addListColumn(list, 9, L"R0详情", 360);
    listColumnCounts_[list] = 10;
    if (threadFilterRows_) {
        threadVirtualList_.setSharedRows(threadFilterRows_);
        threadVirtualList_.setVisibleIndexes(threadVisibleIndexes_);
    }

    auto* layoutState = new ThreadLayoutState{
        group,
        refresh,
        sample,
        stack,
        status,
        filter,
        list,
        output
    };
    if (!page || !::SetWindowSubclass(
            page,
            threadLayoutSubclassProc,
            kThreadLayoutSubclassId,
            reinterpret_cast<DWORD_PTR>(layoutState))) {
        delete layoutState;
        return false;
    }
    layoutThreadControls(page, *layoutState);
    return true;
}

void ProcessDetailPage::populateThreadTab() {
    HWND list = findControl(TabIndex::kThreads, kThreadList);
    if (!list) {
        return;
    }
    if (threadFilterRows_) {
        threadVirtualList_.setSharedRows(threadFilterRows_);
        threadVirtualList_.setVisibleIndexes(threadVisibleIndexes_);
    }
    if (pendingThreadEntries_ || !threadFilterRows_) {
        setPageStatus(TabIndex::kThreads, kThreadStatus, L"● 正在后台准备线程表...");
    }
}

void ProcessDetailPage::requestThreadFilter(bool rebuildRows) {
    if (!threadFilterTask_) {
        return;
    }
    const HWND kFilter = findControl(TabIndex::kThreads, kThreadFilter);
    threadFilterQuery_ = kFilter ? ksword::ui::getFilterBarText(kFilter) : threadFilterQuery_;
    threadFilterUseRegex_ = ksword::ui::getFilterBarRegexEnabled(kFilter);
    const auto kExistingRows = threadFilterRows_;
    const auto kSource = pendingThreadEntries_ ? pendingThreadEntries_ : threadEntries_;
    // A newer collector snapshot remains pending until its display rows are
    // installed. Any coalesced filter request must therefore rebuild from the
    // pending immutable source instead of applying the new query to old rows.
    const bool kBuildRows = rebuildRows || !kExistingRows || pendingThreadEntries_;
    if (!kSource && kBuildRows) {
        return;
    }
    const std::uint64_t kGeneration = threadSourceGeneration_;
    const bool kUseRegex = threadFilterUseRegex_;
    setPageStatus(TabIndex::kThreads, kThreadStatus, L"● 正在后台筛选线程表...");
    threadFilterTask_->request(
        [kSource, kExistingRows, kBuildRows, kGeneration, kUseRegex, query = threadFilterQuery_]() mutable {
            DetailTableFilterResult result{};
            result.sourceGeneration = kGeneration;
            result.query = std::move(query);
            result.useRegex = kUseRegex;
            result.rows = kBuildRows
                ? std::make_shared<const std::vector<ksword::ui::VirtualListRow>>(buildThreadVirtualRows(*kSource))
                : kExistingRows;
            if (result.rows) {
                result.visibleIndexes = ksword::ui::VirtualListView::filterRowIndexes(*result.rows, result.query, kUseRegex);
            }
            return result;
        },
        [this](std::uint64_t, std::optional<DetailTableFilterResult>&& result, std::exception_ptr error) {
            if (error || !result.has_value() || result->sourceGeneration != threadSourceGeneration_ ||
                result->query != threadFilterQuery_ || result->useRegex != threadFilterUseRegex_ || !result->rows) {
                return;
            }
            const HWND kList = threadVirtualList_.hwnd();
            const std::wstring kSelectedKey = ::IsWindow(kList)
                ? stableKeyAt(threadVirtualList_, ListView_GetNextItem(kList, -1, LVNI_SELECTED))
                : std::wstring{};
            const std::wstring kTopKey = ::IsWindow(kList)
                ? stableKeyAt(threadVirtualList_, ListView_GetTopIndex(kList))
                : std::wstring{};
            const bool kReplaceRows = result->rows != threadFilterRows_;
            threadFilterRows_ = result->rows;
            threadVisibleIndexes_ = result->visibleIndexes;
            if (kReplaceRows) {
                threadEntries_ = pendingThreadEntries_ ? pendingThreadEntries_ : threadEntries_;
                pendingThreadEntries_.reset();
            }
            if (::IsWindow(kList)) {
                if (kReplaceRows) {
                    threadVirtualList_.setSharedRows(threadFilterRows_);
                }
                threadVirtualList_.setVisibleIndexes(std::move(result->visibleIndexes));
                restoreListPosition(kList, threadVirtualList_, kSelectedKey, kTopKey);
            }
            if (snapshot_.threadsSucceeded) {
                setPageStatus(
                    TabIndex::kThreads,
                    kThreadStatus,
                    L"● 刷新完成 | 线程 " + decimalText(threadVirtualList_.rowCount()) +
                        L" / " + decimalText(threadEntries().size()));
            } else {
                std::wstring status = L"● 线程刷新失败";
                if (!snapshot_.errorText.empty()) {
                    status += L" | " + snapshot_.errorText;
                }
                setPageStatus(TabIndex::kThreads, kThreadStatus, status);
            }
        });
}

bool ProcessDetailPage::handleThreadCommand(int controlId) {
    switch (controlId) {
    case kThreadRefresh:
        setPageStatus(TabIndex::kThreads, kThreadStatus, L"● 正在后台刷新线程细节...");
        refreshAll();
        return true;

    case kThreadFilter:
        requestThreadFilter(false);
        return true;

    case kThreadSample: {
        HWND list = findControl(TabIndex::kThreads, kThreadList);
        std::size_t index = 0;
        const auto& threads = threadEntries();
        if (!selectedItemData(list, index) || index >= threads.size()) {
            setControlText(TabIndex::kThreads, kThreadRuntimeOutput, L"请先在线程表中选择一条线程记录。");
            setPageStatus(TabIndex::kThreads, kThreadStatus, L"● 请先选择一个线程。");
            return true;
        }
        const ProcessThreadInfo& thread = threads[index];
        std::wostringstream text;
        text << L"[Selected Thread Runtime Context]\r\n"
             << L"TID/PID: " << thread.threadId << L"/" << thread.ownerProcessId << L"\r\n"
             << L"Start/Win32Start: " << hexAddressText(thread.startAddress) << L" / Unavailable\r\n"
             << L"TEB: Unavailable\r\n"
             << L"R0 fixed detail: Unavailable\r\n\r\n"
             << L"当前 Light 快照未包含 PDB deep runtime 字段，未执行伪造采样。";
        setControlText(TabIndex::kThreads, kThreadRuntimeOutput, text.str());
        setPageStatus(TabIndex::kThreads, kThreadStatus, L"● 当前线程 PDB 字段不可用");
        return true;
    }

    case kThreadStack:
        showSelectedThreadSummary();
        return true;

    default:
        return false;
    }
}

bool ProcessDetailPage::handleThreadContextMenu(POINT screenPoint) {
    HWND list = findControl(TabIndex::kThreads, kThreadList);
    if (!list || selectedListRow(list) < 0) {
        return true;
    }

    std::size_t selectedIndex = 0;
    const auto& threads = threadEntries();
    if (!selectedItemData(list, selectedIndex) || selectedIndex >= threads.size()) {
        return true;
    }
    const ProcessThreadInfo kSelectedThread = threads[selectedIndex];
    ThreadAffinityMenuState affinityMenuState{};

    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return true;
    }
    ::AppendMenuW(menu, MF_STRING, kThreadCopyCellCommand, L"复制当前单元格");
    ::AppendMenuW(menu, MF_STRING, kThreadCopyRowCommand, L"复制当前行");
    ::AppendMenuW(menu, MF_STRING, kThreadCopyAllCommand, L"复制全部");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING, kThreadShowDetailCommand, L"线程详细信息");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    appendThreadAffinitySubMenu(
        menu,
        kSelectedThread.ownerProcessId,
        kSelectedThread.threadId,
        kSelectedThread.creationTime100ns,
        affinityMenuState);
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING, kThreadSuspendCommand, L"挂起线程");
    ::AppendMenuW(menu, MF_STRING, kThreadResumeCommand, L"恢复线程");
    ::AppendMenuW(menu, MF_STRING, kThreadTerminateCommand, L"终止线程");
    ::AppendMenuW(menu, MF_STRING, kThreadR0TerminateCommand, L"R0结束线程");

    const UINT kCommand = ::TrackPopupMenu(
        menu,
        TPM_RETURNCMD | TPM_RIGHTBUTTON,
        screenPoint.x,
        screenPoint.y,
        0,
        hwnd_,
        nullptr);
    ::DestroyMenu(menu);

    const bool kAffinityCommand =
        kCommand == kThreadAffinityFollowProcessCommand ||
        (kCommand >= kThreadAffinityProcessorBaseCommand &&
            kCommand < kThreadAffinityProcessorBaseCommand +
                static_cast<UINT>(std::min(
                    affinityMenuState.snapshot.processors.size(),
                    kThreadAffinityMaxProcessorCommands)));
    if (kAffinityCommand) {
        ksword::thread_affinity_r3::Rule rule;
        if (!buildThreadAffinityRule(affinityMenuState, kCommand, rule)) {
            setPageStatus(
                TabIndex::kThreads,
                kThreadStatus,
                L"● 至少保留一个可用逻辑处理器。" );
            return true;
        }
        const DWORD kThreadId = kSelectedThread.threadId;
        const ULONGLONG kExpectedThreadCreationTime100ns = kSelectedThread.creationTime100ns;
        const DWORD kTargetProcessId = processId_;
        const ULONGLONG kExpectedProcessCreationTime100ns = expectedCreationTime100ns_;
        if (kThreadId == 0U || kExpectedThreadCreationTime100ns == 0U ||
            kSelectedThread.ownerProcessId != kTargetProcessId ||
            kExpectedProcessCreationTime100ns == 0U) {
            setPageStatus(TabIndex::kThreads, kThreadStatus, L"● 线程身份不可用，无法安全设置亲和性。" );
            return true;
        }
        executeBackgroundAction(
            TabIndex::kThreads,
            kThreadStatus,
            L"● 正在通过 R3 设置线程亲和性 " + decimalText(kThreadId) + L"…",
            [kThreadId,
                kExpectedThreadCreationTime100ns,
                kTargetProcessId,
                kExpectedProcessCreationTime100ns,
                rule] {
                ProcessDetailActionResult result{};
                ksword::core::UniqueHandle verifiedProcess;
                ksword::core::UniqueHandle verifiedThread;
                std::wstring identityError;
                if (!ProcessDetailPage::openVerifiedThreadActionTarget(
                        kTargetProcessId,
                        kExpectedProcessCreationTime100ns,
                        kThreadId,
                        kExpectedThreadCreationTime100ns,
                        THREAD_SET_LIMITED_INFORMATION,
                        verifiedProcess,
                        verifiedThread,
                        identityError)) {
                    result.statusText = L"● 设置线程亲和性失败 | " + identityError;
                    return result;
                }
                std::string detailText;
                if (!ksword::thread_affinity_r3::setThreadAffinityRule(
                        kThreadId,
                        kTargetProcessId,
                        kExpectedThreadCreationTime100ns,
                        rule,
                        &detailText)) {
                    result.statusText = L"● 设置线程亲和性失败 | " +
                        (detailText.empty() ? L"R3 API 调用失败。" : utf8ToWide(detailText));
                    return result;
                }
                result.refreshRequired = true;
                result.statusText = L"● 已通过 R3 更新线程 " + decimalText(kThreadId) +
                    L" 的 CPU Set 亲和性。";
                return result;
            });
        return true;
    }

    switch (kCommand) {
    case kThreadCopyCellCommand: copyListCell(list); break;
    case kThreadCopyRowCommand: copyListRow(list); break;
    case kThreadCopyAllCommand: copyListAll(list); break;
    case kThreadShowDetailCommand: showSelectedThreadSummary(); break;
    case kThreadSuspendCommand: suspendSelectedThread(); break;
    case kThreadResumeCommand: resumeSelectedThread(); break;
    case kThreadTerminateCommand: terminateSelectedThread(); break;
    case kThreadR0TerminateCommand: terminateSelectedThreadByR0(); break;
    default: break;
    }
    return true;
}

void ProcessDetailPage::suspendSelectedThread() {
    HWND list = findControl(TabIndex::kThreads, kThreadList);
    std::size_t index = 0;
    const auto& threads = threadEntries();
    if (!selectedItemData(list, index) || index >= threads.size()) {
        setPageStatus(TabIndex::kThreads, kThreadStatus, L"● 没有选中线程。");
        return;
    }
    const ProcessThreadInfo& selectedThread = threads[index];
    const DWORD kThreadId = selectedThread.threadId;
    const ULONGLONG kExpectedThreadCreationTime100ns = selectedThread.creationTime100ns;
    const DWORD kTargetProcessId = processId_;
    const ULONGLONG kExpectedProcessCreationTime100ns = expectedCreationTime100ns_;
    if (kThreadId == 0U || kExpectedThreadCreationTime100ns == 0U ||
        selectedThread.ownerProcessId != kTargetProcessId || kExpectedProcessCreationTime100ns == 0U) {
        setPageStatus(TabIndex::kThreads, kThreadStatus, L"● 线程身份不可用，无法安全操作。");
        return;
    }
    if (kThreadId == ::GetCurrentThreadId()) {
        setPageStatus(TabIndex::kThreads, kThreadStatus, L"● 拒绝挂起当前 Light UI 线程。");
        return;
    }

    executeBackgroundAction(
        TabIndex::kThreads,
        kThreadStatus,
        L"● 正在后台挂起线程 " + decimalText(kThreadId) + L"…",
        [kThreadId, kExpectedThreadCreationTime100ns, kTargetProcessId, kExpectedProcessCreationTime100ns] {
            ProcessDetailActionResult result{};
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
                result.statusText = L"● " + identityError;
                return result;
            }
            const DWORD kPreviousCount = ::SuspendThread(verifiedThread.get());
            const DWORD kError = kPreviousCount == static_cast<DWORD>(-1) ? ::GetLastError() : ERROR_SUCCESS;
            if (kError != ERROR_SUCCESS) {
                result.statusText = L"● " + win32ErrorText(L"SuspendThread", kError);
                return result;
            }
            result.refreshRequired = true;
            result.statusText = L"● 已挂起线程 " + decimalText(kThreadId) +
                L"（原挂起计数 " + decimalText(kPreviousCount) + L"）";
            return result;
        });
}

void ProcessDetailPage::resumeSelectedThread() {
    HWND list = findControl(TabIndex::kThreads, kThreadList);
    std::size_t index = 0;
    const auto& threads = threadEntries();
    if (!selectedItemData(list, index) || index >= threads.size()) {
        setPageStatus(TabIndex::kThreads, kThreadStatus, L"● 没有选中线程。");
        return;
    }
    const ProcessThreadInfo& selectedThread = threads[index];
    const DWORD kThreadId = selectedThread.threadId;
    const ULONGLONG kExpectedThreadCreationTime100ns = selectedThread.creationTime100ns;
    const DWORD kTargetProcessId = processId_;
    const ULONGLONG kExpectedProcessCreationTime100ns = expectedCreationTime100ns_;
    if (kThreadId == 0U || kExpectedThreadCreationTime100ns == 0U ||
        selectedThread.ownerProcessId != kTargetProcessId || kExpectedProcessCreationTime100ns == 0U) {
        setPageStatus(TabIndex::kThreads, kThreadStatus, L"● 线程身份不可用，无法安全操作。");
        return;
    }
    executeBackgroundAction(
        TabIndex::kThreads,
        kThreadStatus,
        L"● 正在后台恢复线程 " + decimalText(kThreadId) + L"…",
        [kThreadId, kExpectedThreadCreationTime100ns, kTargetProcessId, kExpectedProcessCreationTime100ns] {
            ProcessDetailActionResult result{};
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
                result.statusText = L"● " + identityError;
                return result;
            }
            const DWORD kPreviousCount = ::ResumeThread(verifiedThread.get());
            const DWORD kError = kPreviousCount == static_cast<DWORD>(-1) ? ::GetLastError() : ERROR_SUCCESS;
            if (kError != ERROR_SUCCESS) {
                result.statusText = L"● " + win32ErrorText(L"ResumeThread", kError);
                return result;
            }
            result.refreshRequired = true;
            result.statusText = L"● 已恢复线程 " + decimalText(kThreadId) +
                L"（原挂起计数 " + decimalText(kPreviousCount) + L"）";
            return result;
        });
}

void ProcessDetailPage::terminateSelectedThread() {
    HWND list = findControl(TabIndex::kThreads, kThreadList);
    std::size_t index = 0;
    const auto& threads = threadEntries();
    if (!selectedItemData(list, index) || index >= threads.size()) {
        setPageStatus(TabIndex::kThreads, kThreadStatus, L"● 没有选中线程。");
        return;
    }
    const ProcessThreadInfo& selectedThread = threads[index];
    const DWORD kThreadId = selectedThread.threadId;
    const ULONGLONG kExpectedThreadCreationTime100ns = selectedThread.creationTime100ns;
    const DWORD kTargetProcessId = processId_;
    const ULONGLONG kExpectedProcessCreationTime100ns = expectedCreationTime100ns_;
    if (kThreadId == 0U || kExpectedThreadCreationTime100ns == 0U ||
        selectedThread.ownerProcessId != kTargetProcessId || kExpectedProcessCreationTime100ns == 0U) {
        setPageStatus(TabIndex::kThreads, kThreadStatus, L"● 线程身份不可用，无法安全操作。");
        return;
    }
    if (kThreadId == ::GetCurrentThreadId()) {
        setPageStatus(TabIndex::kThreads, kThreadStatus, L"● 拒绝终止当前 Light UI 线程。");
        return;
    }
    const int kAnswer = ::MessageBoxW(
        hwnd_,
        L"确定要终止选中的线程吗？这可能导致目标进程崩溃。",
        L"终止线程",
        MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2);
    if (kAnswer != IDYES) {
        setPageStatus(TabIndex::kThreads, kThreadStatus, L"● 已取消终止线程。");
        return;
    }

    executeBackgroundAction(
        TabIndex::kThreads,
        kThreadStatus,
        L"● 正在后台终止线程 " + decimalText(kThreadId) + L"…",
        [kThreadId, kExpectedThreadCreationTime100ns, kTargetProcessId, kExpectedProcessCreationTime100ns] {
            ProcessDetailActionResult result{};
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
                result.statusText = L"● " + identityError;
                return result;
            }
            const BOOL kTerminated = ::TerminateThread(verifiedThread.get(), 1);
            const DWORD kError = kTerminated ? ERROR_SUCCESS : ::GetLastError();
            if (!kTerminated) {
                result.statusText = L"● " + win32ErrorText(L"TerminateThread", kError);
                return result;
            }
            result.refreshRequired = true;
            result.statusText = L"● 已请求终止线程 " + decimalText(kThreadId);
            return result;
        });
}

void ProcessDetailPage::terminateSelectedThreadByR0() {
    HWND list = findControl(TabIndex::kThreads, kThreadList);
    std::size_t index = 0;
    const auto& threads = threadEntries();
    if (!selectedItemData(list, index) || index >= threads.size()) {
        setPageStatus(TabIndex::kThreads, kThreadStatus, L"● 没有选中线程。");
        return;
    }

    const ProcessThreadInfo& selectedThread = threads[index];
    const DWORD kThreadId = selectedThread.threadId;
    const ULONGLONG kExpectedThreadCreationTime100ns = selectedThread.creationTime100ns;
    const DWORD kTargetProcessId = processId_;
    const ULONGLONG kExpectedProcessCreationTime100ns = expectedCreationTime100ns_;
    if (kThreadId == 0U || kTargetProcessId == 0U || kTargetProcessId <= 4 ||
        kExpectedThreadCreationTime100ns == 0U || kExpectedProcessCreationTime100ns == 0U ||
        selectedThread.ownerProcessId != kTargetProcessId) {
        setPageStatus(TabIndex::kThreads, kThreadStatus, L"● 拒绝结束系统、无效或未验证身份的线程。");
        return;
    }
    if (kThreadId == ::GetCurrentThreadId()) {
        setPageStatus(TabIndex::kThreads, kThreadStatus, L"● 拒绝终止当前 Light UI 线程。");
        return;
    }
    const std::wstring kConfirmationText =
        L"将通过 R0 结束 PID " + decimalText(kTargetProcessId) +
        L" 的线程 " + decimalText(kThreadId) + L"。该操作不可撤销，是否继续？";
    const int kAnswer = ::MessageBoxW(
        hwnd_,
        kConfirmationText.c_str(),
        L"R0结束线程",
        MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2);
    if (kAnswer != IDYES) {
        setPageStatus(TabIndex::kThreads, kThreadStatus, L"● 已取消 R0 结束线程。");
        return;
    }

    executeBackgroundAction(
        TabIndex::kThreads,
        kThreadStatus,
        L"● 正在后台通过 R0 结束线程 " + decimalText(kThreadId) + L"…",
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
                    0,
                    verifiedProcess,
                    verifiedThread,
                    identityError)) {
                action.statusText = L"● R0结束线程失败 | " + identityError;
                return action;
            }
            const ksword::ark::IoResult kResult = ksword::ark::DriverClient().terminateThread(
                kThreadId,
                kTargetProcessId,
                static_cast<long>(0xC0000005u));
            if (!kResult.ok) {
                action.statusText = L"● R0结束线程失败 | " + utf8ToWide(kResult.message);
                return action;
            }
            action.refreshRequired = true;
            action.statusText = L"● R0 已请求结束线程 " + decimalText(kThreadId) + L"。";
            return action;
        });
}

void ProcessDetailPage::showSelectedThreadSummary() {
    HWND list = findControl(TabIndex::kThreads, kThreadList);
    std::size_t index = 0;
    const auto& threads = threadEntries();
    if (!selectedItemData(list, index) || index >= threads.size()) {
        setPageStatus(TabIndex::kThreads, kThreadStatus, L"● 没有选中线程。");
        setControlText(TabIndex::kThreads, kThreadRuntimeOutput, L"请选择一条线程记录查看 runtime detail。");
        return;
    }

    const ProcessThreadInfo& thread = threads[index];
    std::wostringstream detail;
    detail << L"[Thread Runtime Detail]\r\n"
           << L"TID/PID: " << thread.threadId << L"/" << thread.ownerProcessId << L"\r\n"
           << L"State: " << (thread.statusText.empty() ? L"-" : thread.statusText) << L"\r\n"
           << L"Priority: " << thread.basePriority << L" (Delta " << thread.deltaPriority << L")\r\n"
           << L"Context switches: Unavailable\r\n"
           << L"Start/Win32Start: " << hexAddressText(thread.startAddress) << L" / Unavailable\r\n"
           << L"TEB: Unavailable\r\n"
           << L"Affinity: Unavailable\r\n"
           << L"Registers: Unavailable\r\n"
           << L"User/R0 stack: Unavailable\r\n"
           << L"R0 detail: Unavailable\r\n\r\n"
           << L"当前快照没有调用栈帧数据，调用栈功能暂不可用。";
    const std::wstring kDetailText = detail.str();
    setControlText(TabIndex::kThreads, kThreadRuntimeOutput, kDetailText);
    ::MessageBoxW(hwnd_, kDetailText.c_str(), L"线程详细信息", MB_OK | MB_ICONINFORMATION);
    setPageStatus(
        TabIndex::kThreads,
        kThreadStatus,
        L"● 已显示线程 " + decimalText(thread.threadId) + L" 的详细信息");
}

} // namespace Ksword::Features::process_detail
