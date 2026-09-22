#include "RegistryView.h"

#include "RegistryActions.h"
#include "RegistryModel.h"
#include "../../ui/AsyncTask.h"
#include "../../ui/Controls.h"
#include "../../ui/ExportUtil.h"
#include "../../ui/FilterBar.h"
#include "../../ui/ListViewUtil.h"
#include "../../ui/LoadingOverlay.h"
#include "../../ui/TextFindSupport.h"
#include "../../ui/Theme.h"
#include "../../ui/TreeViewUtil.h"
#include "../../ui/VirtualListView.h"

#include <commctrl.h>
#include <windowsx.h>

#include <algorithm>
#include <cwchar>
#include <iterator>
#include <memory>
#include <string>
#include <vector>

namespace ksword::features::registry {
namespace {

constexpr wchar_t kRegistryViewClass[] = L"KswordARKLight.RegistryView";
constexpr int kRefreshButtonId = 68001;
constexpr int kPathEditId = 68002;
constexpr int kGoButtonId = 68003;
constexpr int kModeComboId = 68004;
constexpr int kListId = 68005;
constexpr int kNameEditId = 68006;
constexpr int kTypeComboId = 68007;
constexpr int kDataEditId = 68008;
constexpr int kReadButtonId = 68009;
constexpr int kWriteButtonId = 68010;
constexpr int kCreateKeyButtonId = 68011;
constexpr int kDeleteButtonId = 68012;
constexpr int kRenameButtonId = 68013;
constexpr int kStatusId = 68014;
constexpr int kTreeId = 68015;
constexpr int kUpButtonId = 68016;
constexpr int kValueFilterBarId = 68017;
constexpr int kTreeFilterBarId = 68018;

constexpr UINT kMenuRefresh = 68101;
constexpr UINT kMenuCopyName = 68102;
constexpr UINT kMenuCopyData = 68103;
constexpr UINT kMenuRead = 68104;
constexpr UINT kMenuWrite = 68105;
constexpr UINT kMenuDelete = 68106;
constexpr UINT kMenuCreateSubKey = 68107;
constexpr UINT kMenuRename = 68108;
constexpr UINT kMenuCopyRow = 68110;
constexpr UINT kMenuCopyVisible = 68111;
constexpr UINT kMenuCopyCell = 68112;
constexpr UINT kMenuExportVisible = 68113;
constexpr UINT kMsgSnapshotCompleted = WM_APP + 560;
constexpr UINT kMsgTreeChildrenCompleted = WM_APP + 561;
constexpr UINT kMsgFilterCompleted = WM_APP + 562;
constexpr UINT kMsgOperationCompleted = WM_APP + 563;
constexpr UINT kMsgExternalNavigate = WM_APP + 564;
constexpr int kLoadingOverlayId = 68109;

struct RegistryRefreshSnapshot {
    std::wstring path;
    RegistryViewMode mode = RegistryViewMode::kWinApi;
    std::uint64_t navigationGeneration = 0;
    RegistrySnapshot snapshot;
};

struct RegistryTreeChildrenSnapshot {
    std::wstring path;
    RegistryViewMode mode = RegistryViewMode::kWinApi;
    std::wstring query;
    std::wstring statusText;
    std::vector<std::wstring> subKeys;
};

struct RegistryFilterResult {
    std::uint64_t generation = 0;
    std::wstring query;
    bool useRegex = false;
    std::wstring selectedStableKey;
    std::wstring topStableKey;
    std::vector<std::size_t> visibleIndexes;
};

enum class RegistryOperationKind {
    kRead,
    kWrite,
    kCreateKey,
    kDeleteValue,
    kDeleteKey,
    kRenameValue,
    kRenameKey
};

struct RegistryOperationRequest {
    RegistryOperationKind kind = RegistryOperationKind::kRead;
    std::wstring path;
    std::wstring name;
    std::wstring alternateName;
    RegistryViewMode mode = RegistryViewMode::kWinApi;
    std::uint32_t valueType = REG_SZ;
    std::vector<std::uint8_t> data;
};

struct RegistryOperationSnapshot {
    RegistryOperationKind kind = RegistryOperationKind::kRead;
    RegistryOperationResult result;
    bool refreshRequired = false;
};

struct RegistryViewState {
    HWND hwnd = nullptr;
    HWND refreshButton = nullptr;
    HWND upButton = nullptr;
    HWND pathEdit = nullptr;
    HWND goButton = nullptr;
    HWND modeCombo = nullptr;
    HWND tree = nullptr;
    HWND valueFilterBar = nullptr;
    HWND treeFilterBar = nullptr;
    ksword::ui::VirtualListView list;
    HWND nameEdit = nullptr;
    HWND typeCombo = nullptr;
    HWND dataEdit = nullptr;
    HWND readButton = nullptr;
    HWND writeButton = nullptr;
    HWND createKeyButton = nullptr;
    HWND deleteButton = nullptr;
    HWND renameButton = nullptr;
    HWND statusText = nullptr;
    HWND loadingOverlay = nullptr;
    RegistryViewMode mode = RegistryViewMode::kWinApi;
    RegistrySnapshot snapshot;
    std::shared_ptr<const std::vector<ksword::ui::VirtualListRow>> filterRows;
    std::wstring valueFilterQuery;
    bool valueFilterUseRegex = false;
    std::wstring treeFilterQuery;
    bool treeFilterUseRegex = false;
    std::wstring treeLoadingPath;
    std::uint64_t displayGeneration = 0;
    std::uint64_t navigationGeneration = 0;
    bool currentSnapshotReady = false;
    bool operationInProgress = false;
    int contextColumn = 0;
    bool syncingTreeSelection = false;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<RegistryRefreshSnapshot>> refreshTask;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<RegistryTreeChildrenSnapshot>> treeChildrenTask;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<RegistryFilterResult>> filterTask;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<RegistryOperationSnapshot>> operationTask;
};

struct RegistryTreeNodeData {
    std::wstring path;
    bool childrenLoaded = false;
    bool childrenLoading = false;
    bool placeholder = false;
};

struct RegistryTypeOption {
    std::uint32_t type;
    const wchar_t* text;
};

struct RegistryRootNode {
    const wchar_t* displayText;
    const wchar_t* pathText;
};

struct TreeSelectionSyncGuard {
    bool& syncing;

    // TreeSelectionSyncGuard suppresses selection notifications generated by
    // programmatic TreeView navigation. Input is the state flag; construction
    // marks syncing active; destruction restores normal user-driven selection.
    explicit TreeSelectionSyncGuard(bool& flag) : syncing(flag) {
        syncing = true;
    }

    ~TreeSelectionSyncGuard() {
        syncing = false;
    }
};

constexpr RegistryTypeOption kTypeOptions[] = {
    { REG_SZ, L"REG_SZ" },
    { REG_EXPAND_SZ, L"REG_EXPAND_SZ" },
    { REG_MULTI_SZ, L"REG_MULTI_SZ" },
    { REG_DWORD, L"REG_DWORD" },
    { REG_BINARY, L"REG_BINARY" },
};

constexpr RegistryRootNode kRootNodes[] = {
    { L"HKEY_CLASSES_ROOT", L"HKCR" },
    { L"HKEY_CURRENT_USER", L"HKCU" },
    { L"HKEY_LOCAL_MACHINE", L"HKLM" },
    { L"HKEY_USERS", L"HKU" },
    { L"HKEY_CURRENT_CONFIG", L"HKCC" },
};

void populateList(RegistryViewState& state);
void refreshSnapshot(RegistryViewState& state);
void syncEditorFromSelection(RegistryViewState& state);
void layoutChildren(RegistryViewState& state);
void selectPathInTree(RegistryViewState& state, const std::wstring& path);
void navigateTo(RegistryViewState& state, const std::wstring& path);
void invalidateCurrentSnapshot(RegistryViewState& state);
void setOperationControlsEnabled(RegistryViewState& state, bool enabled);
void requestValueFilter(RegistryViewState& state, std::wstring query, std::wstring selectedStableKey, std::wstring topStableKey);

RegistryViewState* stateFromWindow(HWND hwnd) {
    return reinterpret_cast<RegistryViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

int width(const RECT& rc) {
    return rc.right > rc.left ? rc.right - rc.left : 0;
}

int height(const RECT& rc) {
    return rc.bottom > rc.top ? rc.bottom - rc.top : 0;
}

std::wstring windowTextOf(HWND hwnd) {
    if (!hwnd) {
        return {};
    }
    const int kLength = ::GetWindowTextLengthW(hwnd);
    std::wstring text(static_cast<std::size_t>(std::max(kLength, 0)) + 1U, L'\0');
    ::GetWindowTextW(hwnd, text.data(), kLength + 1);
    text.resize(static_cast<std::size_t>(std::max(kLength, 0)));
    return text;
}

std::wstring displayPathFromRootAndChild(const std::wstring& rootText, const std::wstring& childName) {
    if (rootText.empty()) {
        return childName;
    }
    return childName.empty() ? rootText : (rootText + L"\\" + childName);
}

void setStatus(RegistryViewState& state, const std::wstring& text) {
    if (state.statusText) {
        ::SetWindowTextW(state.statusText, text.c_str());
    }
}

std::wstring currentPath(const RegistryViewState& state) {
    return windowTextOf(state.pathEdit);
}

std::uint32_t selectedRegistryType(const RegistryViewState& state) {
    if (!state.typeCombo) {
        return REG_SZ;
    }
    const LRESULT kSelection = ::SendMessageW(state.typeCombo, CB_GETCURSEL, 0, 0);
    if (kSelection < 0 || kSelection >= static_cast<LRESULT>(std::size(kTypeOptions))) {
        return REG_SZ;
    }
    return kTypeOptions[static_cast<std::size_t>(kSelection)].type;
}

void setSelectedRegistryType(RegistryViewState& state, const std::uint32_t type) {
    for (std::size_t index = 0; index < std::size(kTypeOptions); ++index) {
        if (kTypeOptions[index].type == type) {
            ::SendMessageW(state.typeCombo, CB_SETCURSEL, static_cast<WPARAM>(index), 0);
            return;
        }
    }
    ::SendMessageW(state.typeCombo, CB_SETCURSEL, 0, 0);
}

std::wstring formatDataForEditor(const RegistryEntry& entry) {
    if (entry.valueType == REG_DWORD && entry.data.size() >= sizeof(std::uint32_t)) {
        const std::uint32_t kValue = static_cast<std::uint32_t>(entry.data[0]) |
            (static_cast<std::uint32_t>(entry.data[1]) << 8) |
            (static_cast<std::uint32_t>(entry.data[2]) << 16) |
            (static_cast<std::uint32_t>(entry.data[3]) << 24);
        wchar_t buffer[32]{};
        ::swprintf_s(buffer, L"0x%08X", kValue);
        return buffer;
    }
    return formatRegistryData(entry.valueType, entry.data);
}

std::wstring childPath(const std::wstring& basePath, const std::wstring& name) {
    if (name.empty()) {
        return basePath;
    }
    if (basePath.empty()) {
        return name;
    }
    return basePath.back() == L'\\' ? (basePath + name) : (basePath + L"\\" + name);
}

std::wstring parentPath(const std::wstring& path) {
    return parentRegistryPath(path);
}

std::vector<ksword::ui::ListViewColumn> registryColumns() {
    return {
        { 0, 220, LVCFMT_LEFT, L"名称" },
        { 1, 120, LVCFMT_LEFT, L"类型" },
        { 2, 420, LVCFMT_LEFT, L"数据" },
        { 3, 260, LVCFMT_LEFT, L"详情" },
    };
}

bool selectedEntry(RegistryViewState& state, int* rowIndex, RegistryEntry** entryOut) {
    const HWND kList = state.list.hwnd();
    if (!kList) {
        return false;
    }
    const int kSelected = ListView_GetNextItem(kList, -1, LVNI_SELECTED);
    const auto& visibleIndexes = state.list.visibleIndexes();
    const auto& rows = state.list.rows();
    if (kSelected < 0 || static_cast<std::size_t>(kSelected) >= visibleIndexes.size()) {
        return false;
    }
    const std::size_t kSourceIndex = visibleIndexes[static_cast<std::size_t>(kSelected)];
    if (kSourceIndex >= rows.size()) {
        return false;
    }
    const std::size_t kSnapshotIndex = static_cast<std::size_t>(rows[kSourceIndex].itemData);
    if (kSnapshotIndex >= state.snapshot.rows.size()) {
        return false;
    }
    if (rowIndex) {
        *rowIndex = kSelected;
    }
    if (entryOut) {
        *entryOut = &state.snapshot.rows[kSnapshotIndex];
    }
    return true;
}

RegistryTreeNodeData* treeItemData(HWND treeView, HTREEITEM item) {
    // Inputs are a TreeView and item handle. Processing reads TVIF_PARAM only;
    // output is the per-node registry path state or nullptr when unavailable.
    if (!treeView || !item) {
        return nullptr;
    }
    TVITEMW tvItem{};
    tvItem.mask = TVIF_PARAM;
    tvItem.hItem = item;
    if (!TreeView_GetItem(treeView, &tvItem)) {
        return nullptr;
    }
    return reinterpret_cast<RegistryTreeNodeData*>(tvItem.lParam);
}

HTREEITEM insertTreeNode(HWND treeView, HTREEITEM parentItem, const std::wstring& text, const std::wstring& path, const bool hasChildren) {
    // Inputs describe one visible node and its canonical registry path.
    // Processing attaches RegistryTreeNodeData and, when requested, adds one
    // empty placeholder child so Windows shows the expand affordance. Output is
    // the inserted node handle or nullptr on allocation/control failure.
    auto* nodeData = new RegistryTreeNodeData();
    nodeData->path = path;
    nodeData->childrenLoaded = false;
    nodeData->placeholder = false;

    TVINSERTSTRUCTW insert{};
    insert.hParent = parentItem;
    insert.hInsertAfter = TVI_LAST;
    insert.item.mask = TVIF_TEXT | TVIF_PARAM;
    insert.item.pszText = const_cast<LPWSTR>(text.c_str());
    insert.item.lParam = reinterpret_cast<LPARAM>(nodeData);

    HTREEITEM item = TreeView_InsertItem(treeView, &insert);
    if (!item) {
        delete nodeData;
        return nullptr;
    }

    if (hasChildren) {
        auto* placeholder = new RegistryTreeNodeData();
        placeholder->placeholder = true;
        TVINSERTSTRUCTW childInsert{};
        childInsert.hParent = item;
        childInsert.hInsertAfter = TVI_LAST;
        childInsert.item.mask = TVIF_TEXT | TVIF_PARAM;
        childInsert.item.pszText = const_cast<LPWSTR>(L"");
        childInsert.item.lParam = reinterpret_cast<LPARAM>(placeholder);
        HTREEITEM placeholderItem = TreeView_InsertItem(treeView, &childInsert);
        if (!placeholderItem) {
            delete placeholder;
        }
    }
    return item;
}

void clearTreeNodeDataRecursive(HWND treeView, HTREEITEM item) {
    // Input is the first sibling in a TreeView subtree. Processing walks every
    // child and sibling, deleting only the heap data owned by RegistryView.
    // No value is returned; the control items are deleted separately.
    while (item) {
        HTREEITEM next = TreeView_GetNextSibling(treeView, item);
        HTREEITEM child = TreeView_GetChild(treeView, item);
        if (child) {
            clearTreeNodeDataRecursive(treeView, child);
        }
        RegistryTreeNodeData* data = treeItemData(treeView, item);
        if (data) {
            delete data;
        }
        item = next;
    }
}

void clearRegistryTree(HWND treeView) {
    if (!treeView) {
        return;
    }
    HTREEITEM root = TreeView_GetRoot(treeView);
    clearTreeNodeDataRecursive(treeView, root);
    ksword::ui::clearTreeView(treeView);
}

HTREEITEM findChildTreeItemByText(HWND treeView, HTREEITEM parentItem, const std::wstring& text) {
    // Inputs are a parent item and a child display segment from the path edit.
    // Processing scans only direct children, matching case-insensitively.
    // Output is the matching child or nullptr; this never enumerates registry.
    if (!treeView) {
        return nullptr;
    }
    HTREEITEM child = parentItem ? TreeView_GetChild(treeView, parentItem) : TreeView_GetRoot(treeView);
    while (child) {
        wchar_t buffer[512]{};
        TVITEMW item{};
        item.mask = TVIF_TEXT;
        item.hItem = child;
        item.pszText = buffer;
        item.cchTextMax = static_cast<int>(std::size(buffer));
        if (TreeView_GetItem(treeView, &item) && _wcsicmp(text.c_str(), buffer) == 0) {
            return child;
        }
        child = TreeView_GetNextSibling(treeView, child);
    }
    return nullptr;
}

HTREEITEM findRootTreeItemByPath(HWND treeView, const std::wstring& path) {
    // Input is a canonical root path such as HKLM. Processing compares against
    // node data instead of display text so roots can be shown as HKEY_* names.
    // Output is the root TreeView item or nullptr.
    if (!treeView) {
        return nullptr;
    }
    HTREEITEM root = TreeView_GetRoot(treeView);
    while (root) {
        const RegistryTreeNodeData* data = treeItemData(treeView, root);
        if (data && data->path == path) {
            return root;
        }
        root = TreeView_GetNextSibling(treeView, root);
    }
    return nullptr;
}

HTREEITEM findTreeItemByPath(HWND treeView, HTREEITEM item, const std::wstring& path) {
    while (item) {
        const RegistryTreeNodeData* data = treeItemData(treeView, item);
        if (data && !data->placeholder && data->path == path) {
            return item;
        }
        if (HTREEITEM child = TreeView_GetChild(treeView, item)) {
            if (HTREEITEM found = findTreeItemByPath(treeView, child, path)) {
                return found;
            }
        }
        item = TreeView_GetNextSibling(treeView, item);
    }
    return nullptr;
}

void replaceTreeNodeChildren(RegistryViewState& state, HTREEITEM item, const RegistryTreeChildrenSnapshot& snapshot) {
    if (!state.tree || !item) {
        return;
    }
    RegistryTreeNodeData* nodeData = treeItemData(state.tree, item);
    if (!nodeData || nodeData->placeholder || nodeData->path != snapshot.path) {
        return;
    }
    nodeData->childrenLoading = false;
    nodeData->childrenLoaded = true;
    HTREEITEM child = TreeView_GetChild(state.tree, item);
    while (child) {
        HTREEITEM next = TreeView_GetNextSibling(state.tree, child);
        if (HTREEITEM grandChild = TreeView_GetChild(state.tree, child)) {
            clearTreeNodeDataRecursive(state.tree, grandChild);
        }
        if (RegistryTreeNodeData* childData = treeItemData(state.tree, child)) {
            delete childData;
        }
        TreeView_DeleteItem(state.tree, child);
        child = next;
    }
    for (const std::wstring& subKey : snapshot.subKeys) {
        const std::wstring kChildPath = displayPathFromRootAndChild(snapshot.path, subKey);
        insertTreeNode(state.tree, item, subKey, kChildPath, true);
    }
    setStatus(state, snapshot.statusText.empty() ? L"已加载注册表子键。" : snapshot.statusText);
}

void ensureTreeChildrenLoaded(RegistryViewState& state, HTREEITEM item) {
    // The direct-child registry query belongs to an independent snapshot task.
    // Tree expansion therefore shows feedback immediately and never blocks a
    // dock switch, drag, or close operation.
    if (!state.tree || !item) {
        return;
    }
    RegistryTreeNodeData* nodeData = treeItemData(state.tree, item);
    if (!nodeData || nodeData->placeholder || nodeData->childrenLoaded || nodeData->childrenLoading || !state.treeChildrenTask) {
        return;
    }
    if (!state.treeLoadingPath.empty() && state.treeLoadingPath != nodeData->path) {
        if (const HTREEITEM kPrevious = findTreeItemByPath(state.tree, TreeView_GetRoot(state.tree), state.treeLoadingPath)) {
            if (RegistryTreeNodeData* previousData = treeItemData(state.tree, kPrevious)) {
                previousData->childrenLoading = false;
            }
        }
    }
    nodeData->childrenLoading = true;
    const std::wstring kPath = nodeData->path;
    const RegistryViewMode kMode = state.mode;
    const std::wstring kQuery = state.treeFilterBar ? ksword::ui::getFilterBarText(state.treeFilterBar) : state.treeFilterQuery;
    state.treeFilterUseRegex = ksword::ui::getFilterBarRegexEnabled(state.treeFilterBar);
    const bool kUseRegex = state.treeFilterUseRegex;
    state.treeLoadingPath = kPath;
    setStatus(state, L"正在后台加载注册表树节点…");
    state.treeChildrenTask->request(
        [kPath, kMode, kQuery, kUseRegex] {
            RegistryTreeChildrenSnapshot snapshot{};
            snapshot.path = kPath;
            snapshot.mode = kMode;
            snapshot.query = kQuery;
            snapshot.subKeys = enumerateRegistrySubKeyNames(kPath, kMode, &snapshot.statusText);
            if (!snapshot.query.empty()) {
                std::vector<ksword::ui::VirtualListRow> rows;
                rows.reserve(snapshot.subKeys.size());
                for (const std::wstring& subKey : snapshot.subKeys) {
                    rows.push_back({ subKey, { subKey }, 0 });
                }
                const std::vector<std::size_t> kVisible = ksword::ui::VirtualListView::filterRowIndexes(rows, snapshot.query, kUseRegex);
                std::vector<std::wstring> filtered;
                filtered.reserve(kVisible.size());
                for (const std::size_t kIndex : kVisible) {
                    filtered.push_back(std::move(snapshot.subKeys[kIndex]));
                }
                snapshot.subKeys = std::move(filtered);
            }
            return snapshot;
        },
        [&state](std::uint64_t, std::optional<RegistryTreeChildrenSnapshot>&& snapshot, std::exception_ptr error) {
            if (error || !snapshot.has_value()) {
                state.treeLoadingPath.clear();
                setStatus(state, L"注册表树节点加载异常结束。已保留现有节点。");
                return;
            }
            if (snapshot->mode != state.mode) {
                return;
            }
            const HTREEITEM kItem = findTreeItemByPath(state.tree, TreeView_GetRoot(state.tree), snapshot->path);
            if (!kItem) {
                return;
            }
            state.treeLoadingPath.clear();
            replaceTreeNodeChildren(state, kItem, *snapshot);
        });
}

void selectPathInTree(RegistryViewState& state, const std::wstring& path) {
    // Inputs are a registry path from the edit box or navigation command.
    // Processing expands just the ancestor chain needed to reveal the path and
    // suppresses selection callbacks generated by TreeView_SelectItem. There is
    // no return value; the tree selection is best-effort.
    if (!state.tree) {
        return;
    }
    const RegistryPathInfo kParsed = parseRegistryPath(path);
    if (!kParsed.valid) {
        return;
    }

    HTREEITEM current = findRootTreeItemByPath(state.tree, kParsed.rootText);
    if (!current) {
        return;
    }

    TreeSelectionSyncGuard syncGuard(state.syncingTreeSelection);
    TreeView_Expand(state.tree, current, TVE_EXPAND);
    ensureTreeChildrenLoaded(state, current);

    std::wstring remaining = kParsed.subKey;
    while (!remaining.empty()) {
        const std::size_t kSlash = remaining.find(L'\\');
        const std::wstring kSegment = kSlash == std::wstring::npos ? remaining : remaining.substr(0, kSlash);
        current = findChildTreeItemByText(state.tree, current, kSegment);
        if (!current) {
            break;
        }
        TreeView_Expand(state.tree, current, TVE_EXPAND);
        ensureTreeChildrenLoaded(state, current);
        if (kSlash == std::wstring::npos) {
            break;
        }
        remaining.erase(0, kSlash + 1);
    }

    TreeView_SelectItem(state.tree, current);
    TreeView_EnsureVisible(state.tree, current);
}

void syncEditorFromSelection(RegistryViewState& state) {
    RegistryEntry* entry = nullptr;
    if (!selectedEntry(state, nullptr, &entry) || entry == nullptr) {
        return;
    }
    ::SetWindowTextW(state.nameEdit, entry->name.c_str());
    if (entry->kind == RegistryRowKind::kValue) {
        setSelectedRegistryType(state, entry->valueType);
        ::SetWindowTextW(state.dataEdit, formatDataForEditor(*entry).c_str());
    } else {
        ::SetWindowTextW(state.dataEdit, L"");
    }
}

std::wstring stableKeyForRegistryEntry(const RegistryEntry& entry) {
    return entry.name + L"|" + std::to_wstring(entry.valueType) + L"|" + entry.typeText;
}

std::wstring stableKeyFromListItem(const RegistryViewState& state, int item) {
    const auto& visible = state.list.visibleIndexes();
    const auto& rows = state.list.rows();
    if (item < 0 || static_cast<std::size_t>(item) >= visible.size()) {
        return {};
    }
    const std::size_t kSourceIndex = visible[static_cast<std::size_t>(item)];
    return kSourceIndex < rows.size() ? rows[kSourceIndex].stableKey : std::wstring{};
}

void applyValueFilter(RegistryViewState& state, RegistryFilterResult result) {
    if (!state.list.hwnd() || result.generation != state.displayGeneration || result.query != state.valueFilterQuery ||
        result.useRegex != state.valueFilterUseRegex) {
        return;
    }
    state.list.setVisibleIndexes(std::move(result.visibleIndexes));
    const auto& visible = state.list.visibleIndexes();
    const auto& rows = state.list.rows();
    HWND list = state.list.hwnd();
    int selectedItem = -1;
    int topItem = -1;
    for (std::size_t item = 0; item < visible.size(); ++item) {
        const std::size_t kSource = visible[item];
        if (kSource >= rows.size()) {
            continue;
        }
        if (selectedItem < 0 && rows[kSource].stableKey == result.selectedStableKey) {
            selectedItem = static_cast<int>(item);
        }
        if (topItem < 0 && rows[kSource].stableKey == result.topStableKey) {
            topItem = static_cast<int>(item);
        }
    }
    ListView_SetItemState(list, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    if (selectedItem < 0 && !visible.empty()) {
        selectedItem = 0;
    }
    if (selectedItem >= 0) {
        ListView_SetItemState(list, selectedItem, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        syncEditorFromSelection(state);
    } else {
        ::SetWindowTextW(state.nameEdit, L"");
        ::SetWindowTextW(state.dataEdit, L"");
    }
    if (topItem >= 0) {
        ListView_EnsureVisible(list, topItem, FALSE);
    }
    if (!result.query.empty()) {
        setStatus(state, L"注册表筛选结果 " + std::to_wstring(visible.size()) + L" / " +
            std::to_wstring(rows.size()) + L" 项。");
    }
}

void requestValueFilter(RegistryViewState& state,
    std::wstring query,
    std::wstring selectedStableKey,
    std::wstring topStableKey) {
    state.valueFilterQuery = std::move(query);
    state.valueFilterUseRegex = ksword::ui::getFilterBarRegexEnabled(state.valueFilterBar);
    const auto kRows = state.filterRows;
    const std::uint64_t kGeneration = state.displayGeneration;
    const bool kUseRegex = state.valueFilterUseRegex;
    if (!state.filterTask || !kRows) {
        return;
    }
    state.filterTask->request(
        [kRows, kGeneration, kUseRegex, query = state.valueFilterQuery, selectedStableKey = std::move(selectedStableKey), topStableKey = std::move(topStableKey)]() mutable {
            RegistryFilterResult result{};
            result.generation = kGeneration;
            result.query = std::move(query);
            result.useRegex = kUseRegex;
            result.selectedStableKey = std::move(selectedStableKey);
            result.topStableKey = std::move(topStableKey);
            result.visibleIndexes = ksword::ui::VirtualListView::filterRowIndexes(*kRows, result.query, kUseRegex);
            return result;
        },
        [&state](std::uint64_t, std::optional<RegistryFilterResult>&& result, std::exception_ptr error) {
            if (error || !result.has_value()) {
                setStatus(state, L"注册表筛选任务异常结束，已保留当前可见结果。");
                return;
            }
            applyValueFilter(state, std::move(*result));
        });
}

void populateList(RegistryViewState& state) {
    const std::wstring kSelectedStableKey = stableKeyFromListItem(state, ListView_GetNextItem(state.list.hwnd(), -1, LVNI_SELECTED));
    const std::wstring kTopStableKey = stableKeyFromListItem(state, ListView_GetTopIndex(state.list.hwnd()));
    auto rows = std::make_shared<std::vector<ksword::ui::VirtualListRow>>();
    rows->reserve(state.snapshot.rows.size());
    for (std::size_t index = 0; index < state.snapshot.rows.size(); ++index) {
        const RegistryEntry& row = state.snapshot.rows[index];
        if (row.kind != RegistryRowKind::kValue) {
            continue;
        }
        ksword::ui::VirtualListRow displayRow{};
        displayRow.stableKey = stableKeyForRegistryEntry(row);
        displayRow.itemData = static_cast<LPARAM>(index);
        displayRow.cells = {
            row.name.empty() ? std::wstring(L"(Default)") : row.name,
            row.typeText,
            row.dataText,
            row.detailText
        };
        rows->push_back(std::move(displayRow));
    }
    state.list.setRows(*rows);
    state.list.setVisibleIndexes({});
    state.filterRows = std::move(rows);
    ++state.displayGeneration;
    requestValueFilter(state,
        state.valueFilterBar ? ksword::ui::getFilterBarText(state.valueFilterBar) : state.valueFilterQuery,
        kSelectedStableKey,
        kTopStableKey);
}

void refreshSnapshot(RegistryViewState& state) {
    if (!state.refreshTask) {
        return;
    }
    const std::wstring kCurrent = currentPath(state);
    const RegistryViewMode kMode = state.mode;
    const std::uint64_t kNavigationGeneration = state.navigationGeneration;
    const bool kFirstLoad = state.list.rows().empty();
    setStatus(state, state.refreshTask->running()
        ? L"注册表刷新已排队，等待当前快照完成…"
        : L"正在后台枚举注册表键和值…");
    if (state.refreshButton) {
        ::EnableWindow(state.refreshButton, FALSE);
    }
    if (kFirstLoad) {
        ksword::ui::setLoadingOverlay(state.loadingOverlay, true, L"正在后台加载注册表键和值…");
    }
    state.refreshTask->request(
        [kCurrent, kMode, kNavigationGeneration]() {
            RegistryRefreshSnapshot snapshot{};
            snapshot.path = kCurrent;
            snapshot.mode = kMode;
            snapshot.navigationGeneration = kNavigationGeneration;
            snapshot.snapshot = enumerateRegistryKey(kCurrent, kMode);
            return snapshot;
        },
        [&state, kNavigationGeneration](std::uint64_t, std::optional<RegistryRefreshSnapshot>&& snapshot, std::exception_ptr error) {
            if (kNavigationGeneration != state.navigationGeneration) {
                return;
            }
            if (state.refreshButton) {
                ::EnableWindow(state.refreshButton, TRUE);
            }
            ksword::ui::setLoadingOverlay(state.loadingOverlay, false);
            if (error || !snapshot.has_value()) {
                setStatus(state, L"注册表后台枚举异常结束。请检查权限、路径和驱动状态。");
                return;
            }
            if (snapshot->navigationGeneration != state.navigationGeneration ||
                snapshot->path != currentPath(state) || snapshot->mode != state.mode) {
                return;
            }
            state.snapshot = std::move(snapshot->snapshot);
            state.currentSnapshotReady = state.snapshot.success;
            populateList(state);
            setOperationControlsEnabled(state, state.currentSnapshotReady && !state.operationInProgress);
            setStatus(state, state.snapshot.statusText);
        });
}

void rebuildRegistryTree(RegistryViewState& state) {
    // Input is the current view state. Processing recreates only the five root
    // nodes with placeholder children; real subkeys are still loaded lazily.
    // No value is returned.
    if (!state.tree) {
        return;
    }
    clearRegistryTree(state.tree);
    for (const RegistryRootNode& rootNode : kRootNodes) {
        insertTreeNode(state.tree, TVI_ROOT, rootNode.displayText, rootNode.pathText, true);
    }
    selectPathInTree(state, currentPath(state));
}

// prepareModeForExternalNavigation preserves the selected R0 view when it can
// address the requested key, but moves roots such as HKCR/HKCU/HKCC to the
// already-supported WinAPI view before the external route reports success.
void prepareModeForExternalNavigation(RegistryViewState& state, const std::wstring& path) {
    if (state.mode != RegistryViewMode::kR0) {
        return;
    }
    const RegistryPathInfo kParsed = parseRegistryPath(path);
    if (!kParsed.valid || !kParsed.kernelPath.empty()) {
        return;
    }
    state.mode = RegistryViewMode::kWinApi;
    if (state.modeCombo) {
        ::SendMessageW(state.modeCombo, CB_SETCURSEL, 0, 0);
    }
    rebuildRegistryTree(state);
}

void navigateTo(RegistryViewState& state, const std::wstring& path) {
    invalidateCurrentSnapshot(state);
    ::SetWindowTextW(state.pathEdit, path.c_str());
    selectPathInTree(state, path);
    refreshSnapshot(state);
}

HWND createEdit(HWND parent, int id, DWORD style) {
    HWND hwnd = ::CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | style,
        0, 0, 0, 0, parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), ::GetModuleHandleW(nullptr), nullptr);
    if (hwnd) {
        ::SendMessageW(hwnd, WM_SETFONT, reinterpret_cast<WPARAM>(ksword::ui::systemUiFont()), TRUE);
    }
    return hwnd;
}

HWND createCombo(HWND parent, int id) {
    HWND hwnd = ::CreateWindowExW(0, WC_COMBOBOXW, L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | CBS_HASSTRINGS | WS_VSCROLL,
        0, 0, 0, 200, parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), ::GetModuleHandleW(nullptr), nullptr);
    if (hwnd) {
        ::SendMessageW(hwnd, WM_SETFONT, reinterpret_cast<WPARAM>(ksword::ui::systemUiFont()), TRUE);
    }
    return hwnd;
}

void layoutChildren(RegistryViewState& state) {
    RECT rc{};
    ::GetClientRect(state.hwnd, &rc);
    const int kWidth = width(rc);
    const int kHeight = height(rc);
    const int kGap = 6;
    const int kMargin = 6;
    const int kToolbarHeight = 24;
    const int kActionRowHeight = 24;
    const int kTreeWidth = std::clamp(kWidth / 4, 220, 360);
    const int kEditorWidth = std::max(260, kWidth / 3);
    const int kListWidth = std::max(200, kWidth - kTreeWidth - kEditorWidth - kGap * 4 - kMargin * 2);

    int x = kMargin;
    int y = kMargin;
    ::MoveWindow(state.refreshButton, x, y, 58, kToolbarHeight, TRUE); x += 58 + kGap;
    ::MoveWindow(state.upButton, x, y, 58, kToolbarHeight, TRUE); x += 58 + kGap;
    ::MoveWindow(state.goButton, x, y, 58, kToolbarHeight, TRUE); x += 58 + kGap;
    ::MoveWindow(state.modeCombo, x, y, 120, 300, TRUE); x += 120 + kGap;
    ::MoveWindow(state.pathEdit, x, y, std::max(120, kWidth - x - kMargin), kToolbarHeight, TRUE);

    const int kFilterTop = y + kToolbarHeight + kGap;
    const int kTreeLeft = kMargin;
    const int kListLeft = kTreeLeft + kTreeWidth + kGap;
    const int kEditorLeft = kListLeft + kListWidth + kGap;
    ::MoveWindow(state.treeFilterBar, kTreeLeft, kFilterTop, kTreeWidth, kToolbarHeight, TRUE);
    ::MoveWindow(state.valueFilterBar, kListLeft, kFilterTop, kListWidth, kToolbarHeight, TRUE);
    const int kContentTop = kFilterTop + kToolbarHeight + kGap;
    const int kListHeight = std::max(120, kHeight - kContentTop - 92);
    ::MoveWindow(state.tree, kTreeLeft, kContentTop, kTreeWidth, kListHeight, TRUE);
    ::MoveWindow(state.list.hwnd(), kListLeft, kContentTop, kListWidth, kListHeight, TRUE);
    if (state.loadingOverlay) {
        ::MoveWindow(state.loadingOverlay, kListLeft, kContentTop, kListWidth, kListHeight, TRUE);
    }

    int editY = kContentTop;
    ::MoveWindow(state.nameEdit, kEditorLeft, editY, kEditorWidth, 24, TRUE);
    editY += 24 + kGap;
    ::MoveWindow(state.typeCombo, kEditorLeft, editY, kEditorWidth, 220, TRUE);
    editY += 24 + kGap;
    ::MoveWindow(state.dataEdit, kEditorLeft, editY, kEditorWidth, std::max(90, kListHeight - 24 - kGap - kActionRowHeight * 2), TRUE);
    editY += std::max(90, kListHeight - 24 - kGap - kActionRowHeight * 2) + kGap;
    ::MoveWindow(state.readButton, kEditorLeft, editY, 58, kActionRowHeight, TRUE);
    ::MoveWindow(state.writeButton, kEditorLeft + 58 + kGap, editY, 58, kActionRowHeight, TRUE);
    ::MoveWindow(state.createKeyButton, kEditorLeft + (58 + kGap) * 2, editY, 70, kActionRowHeight, TRUE);
    editY += kActionRowHeight + kGap;
    ::MoveWindow(state.deleteButton, kEditorLeft, editY, 58, kActionRowHeight, TRUE);
    ::MoveWindow(state.renameButton, kEditorLeft + 58 + kGap, editY, 70, kActionRowHeight, TRUE);

    ::MoveWindow(state.statusText, kMargin, kHeight - 22, kWidth - kMargin * 2, 20, TRUE);
}

RegistryOperationSnapshot executeRegistryOperation(const RegistryOperationRequest& request) {
    RegistryOperationSnapshot snapshot{};
    snapshot.kind = request.kind;
    switch (request.kind) {
    case RegistryOperationKind::kRead:
        snapshot.result = readRegistryValue(request.path, request.name, request.mode);
        break;
    case RegistryOperationKind::kWrite:
        snapshot.result = writeRegistryValue(request.path, request.name, request.valueType, request.data, request.mode);
        snapshot.refreshRequired = snapshot.result.success;
        break;
    case RegistryOperationKind::kCreateKey:
        snapshot.result = createRegistryKey(request.path, request.mode);
        snapshot.refreshRequired = snapshot.result.success;
        break;
    case RegistryOperationKind::kDeleteValue:
        snapshot.result = deleteRegistryValue(request.path, request.name, request.mode);
        snapshot.refreshRequired = snapshot.result.success;
        break;
    case RegistryOperationKind::kDeleteKey:
        snapshot.result = deleteRegistryKey(request.path, request.mode);
        snapshot.refreshRequired = snapshot.result.success;
        break;
    case RegistryOperationKind::kRenameValue:
        snapshot.result = renameRegistryValue(request.path, request.name, request.alternateName, request.mode);
        snapshot.refreshRequired = snapshot.result.success;
        break;
    case RegistryOperationKind::kRenameKey:
        snapshot.result = renameRegistryKey(request.path, request.alternateName, request.mode);
        snapshot.refreshRequired = snapshot.result.success;
        break;
    }
    return snapshot;
}

void setOperationControlsEnabled(RegistryViewState& state, bool enabled) {
    for (HWND control : { state.readButton, state.writeButton, state.createKeyButton, state.deleteButton, state.renameButton }) {
        if (control) {
            ::EnableWindow(control, enabled);
        }
    }
}

// invalidateCurrentSnapshot prevents a row captured for one registry key or
// transport mode from being used after navigation begins. The next matching
// background snapshot is the only point that re-enables registry operations.
void invalidateCurrentSnapshot(RegistryViewState& state) {
    ++state.navigationGeneration;
    state.currentSnapshotReady = false;
    state.snapshot = {};
    state.filterRows.reset();
    state.list.setRows({});
    ++state.displayGeneration;
    if (state.nameEdit) {
        ::SetWindowTextW(state.nameEdit, L"");
    }
    if (state.dataEdit) {
        ::SetWindowTextW(state.dataEdit, L"");
    }
    setOperationControlsEnabled(state, false);
}

void beginRegistryOperation(RegistryViewState& state, RegistryOperationRequest request) {
    if (!state.currentSnapshotReady) {
        setStatus(state, L"当前注册表快照尚未就绪，不能执行读写操作。");
        return;
    }
    if (!state.operationTask || state.operationInProgress) {
        setStatus(state, L"注册表操作正在执行。");
        return;
    }
    const std::uint64_t kOperationGeneration = state.navigationGeneration;
    state.operationInProgress = true;
    setOperationControlsEnabled(state, false);
    setStatus(state, L"正在后台执行注册表操作…");
    state.operationTask->request(
        [request = std::move(request)] { return executeRegistryOperation(request); },
        [&state, kOperationGeneration](std::uint64_t, std::optional<RegistryOperationSnapshot>&& snapshot, std::exception_ptr error) {
            state.operationInProgress = false;
            if (kOperationGeneration != state.navigationGeneration) {
                setOperationControlsEnabled(state, state.currentSnapshotReady);
                return;
            }
            if (error || !snapshot.has_value()) {
                setOperationControlsEnabled(state, state.currentSnapshotReady);
                setStatus(state, L"注册表操作异常结束。请检查权限、路径和驱动状态。");
                return;
            }
            setStatus(state, snapshot->result.statusText);
            if (snapshot->kind == RegistryOperationKind::kRead && snapshot->result.success) {
                setSelectedRegistryType(state, snapshot->result.valueType);
                RegistryEntry entry;
                entry.valueType = snapshot->result.valueType;
                entry.data = snapshot->result.data;
                ::SetWindowTextW(state.dataEdit, formatDataForEditor(entry).c_str());
            }
            if (snapshot->refreshRequired) {
                invalidateCurrentSnapshot(state);
                refreshSnapshot(state);
                return;
            }
            setOperationControlsEnabled(state, state.currentSnapshotReady);
        });
}

bool confirmMutation(HWND owner, const wchar_t* action, const std::wstring& targetPath) {
    const std::wstring kPrompt = std::wstring(L"该操作将修改注册表：") + action +
        L"。\n\n目标键：" + targetPath + L"\n是否继续？";
    return ::MessageBoxW(owner, kPrompt.c_str(), L"确认注册表操作", MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2) == IDYES;
}

void createSubKeyFromEditor(RegistryViewState& state) {
    const std::wstring kChildName = windowTextOf(state.nameEdit);
    if (kChildName.empty()) {
        setStatus(state, L"Create key needs a key name in the name edit.");
        return;
    }
    RegistryOperationRequest request{};
    request.kind = RegistryOperationKind::kCreateKey;
    request.path = childPath(currentPath(state), kChildName);
    request.mode = state.mode;
    if (!confirmMutation(state.hwnd, L"创建子键", request.path)) {
        return;
    }
    beginRegistryOperation(state, std::move(request));
}

void deleteSelection(RegistryViewState& state) {
    RegistryEntry* entry = nullptr;
    if (!selectedEntry(state, nullptr, &entry) || entry == nullptr) {
        setStatus(state, L"No registry row is selected.");
        return;
    }
    RegistryOperationRequest request{};
    request.path = currentPath(state);
    request.mode = state.mode;
    if (entry->kind == RegistryRowKind::kSubKey) {
        request.kind = RegistryOperationKind::kDeleteKey;
        request.path = childPath(request.path, entry->name);
    } else {
        request.kind = RegistryOperationKind::kDeleteValue;
        request.name = entry->name;
    }
    if (!confirmMutation(state.hwnd, L"删除选中项", request.path)) {
        return;
    }
    beginRegistryOperation(state, std::move(request));
}

void renameSelection(RegistryViewState& state) {
    RegistryEntry* entry = nullptr;
    if (!selectedEntry(state, nullptr, &entry) || entry == nullptr) {
        setStatus(state, L"No registry row is selected.");
        return;
    }
    const std::wstring kNewName = windowTextOf(state.nameEdit);
    if (kNewName.empty()) {
        setStatus(state, L"Rename needs a non-empty name.");
        return;
    }
    RegistryOperationRequest request{};
    request.path = currentPath(state);
    request.mode = state.mode;
    request.alternateName = kNewName;
    if (entry->kind == RegistryRowKind::kSubKey) {
        request.kind = RegistryOperationKind::kRenameKey;
        request.path = childPath(request.path, entry->name);
    } else {
        request.kind = RegistryOperationKind::kRenameValue;
        request.name = entry->name;
    }
    if (!confirmMutation(state.hwnd, L"重命名选中项", request.path)) {
        return;
    }
    beginRegistryOperation(state, std::move(request));
}

void readCurrentValue(RegistryViewState& state) {
    RegistryOperationRequest request{};
    request.kind = RegistryOperationKind::kRead;
    request.path = currentPath(state);
    request.name = windowTextOf(state.nameEdit);
    request.mode = state.mode;
    beginRegistryOperation(state, std::move(request));
}

void writeCurrentValue(RegistryViewState& state) {
    const std::wstring kValueName = windowTextOf(state.nameEdit);
    std::vector<std::uint8_t> bytes;
    std::wstring errorText;
    const std::uint32_t kType = selectedRegistryType(state);
    if (!parseRegistryDataText(kType, windowTextOf(state.dataEdit), bytes, errorText)) {
        setStatus(state, errorText);
        return;
    }
    RegistryOperationRequest request{};
    request.kind = RegistryOperationKind::kWrite;
    request.path = currentPath(state);
    request.name = kValueName;
    request.mode = state.mode;
    request.valueType = kType;
    request.data = std::move(bytes);
    if (!confirmMutation(state.hwnd, L"写入值", request.path)) {
        return;
    }
    beginRegistryOperation(state, std::move(request));
}

std::wstring registryRowsAsText(const RegistryViewState& state, bool allVisible) {
    const HWND kList = state.list.hwnd();
    const auto& visible = state.list.visibleIndexes();
    const auto& rows = state.list.rows();
    std::wstring text;
    for (std::size_t item = 0; item < visible.size(); ++item) {
        if (!allVisible && (!kList || (ListView_GetItemState(kList, static_cast<int>(item), LVIS_SELECTED) & LVIS_SELECTED) == 0)) {
            continue;
        }
        const std::size_t kSourceIndex = visible[item];
        if (kSourceIndex >= rows.size()) {
            continue;
        }
        const auto& cells = rows[kSourceIndex].cells;
        for (std::size_t column = 0; column < cells.size(); ++column) {
            if (column != 0) {
                text += L'\t';
            }
            text += cells[column];
        }
        text += L"\r\n";
    }
    return text;
}

std::wstring registrySelectedCellText(const RegistryViewState& state) {
    const HWND kList = state.list.hwnd();
    const int kSelected = kList ? ListView_GetNextItem(kList, -1, LVNI_SELECTED) : -1;
    const auto& visible = state.list.visibleIndexes();
    const auto& rows = state.list.rows();
    if (kSelected < 0 || static_cast<std::size_t>(kSelected) >= visible.size()) {
        return {};
    }
    const std::size_t kSource = visible[static_cast<std::size_t>(kSelected)];
    if (kSource >= rows.size() || state.contextColumn < 0 || static_cast<std::size_t>(state.contextColumn) >= rows[kSource].cells.size()) {
        return {};
    }
    return rows[kSource].cells[static_cast<std::size_t>(state.contextColumn)];
}

// exportVisibleRegistrySnapshot writes only the values already materialized in
// the current ListView. It never re-reads the registry, recursively exports a
// key, or turns a partial R0 snapshot into a claimed .reg backup.
void exportVisibleRegistrySnapshot(RegistryViewState& state) {
    if (!state.currentSnapshotReady) {
        setStatus(state, L"当前注册表快照尚未就绪，无法导出。");
        return;
    }

    const std::wstring kText = ksword::ui::buildVisibleVirtualListTsv(
        { L"名称", L"类型", L"数据", L"详情" }, state.list);
    if (kText.empty()) {
        setStatus(state, L"当前没有可导出的注册表可见值。");
        return;
    }

    std::wstring error;
    switch (ksword::ui::saveUtf8TextFileWithDialog(
        state.hwnd,
        L"ksword-arklight-registry-visible.tsv",
        L"导出当前可见注册表快照",
        L"TSV (*.tsv)\0*.tsv\0All Files (*.*)\0*.*\0",
        L"tsv",
        kText,
        &error)) {
    case ksword::ui::SaveTextFileResult::kSaved:
        setStatus(state, L"已导出当前可见注册表快照 TSV。");
        break;
    case ksword::ui::SaveTextFileResult::kCancelled:
        setStatus(state, L"已取消导出当前可见注册表快照。");
        break;
    case ksword::ui::SaveTextFileResult::kFailed:
    default:
        setStatus(state, L"导出当前可见注册表快照失败：" + error);
        break;
    }
}

void showContextMenu(RegistryViewState& state, POINT screenPoint) {
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    POINT client = screenPoint;
    ::ScreenToClient(state.list.hwnd(), &client);
    LVHITTESTINFO hit{};
    hit.pt = client;
    const int kClickedItem = ListView_SubItemHitTest(state.list.hwnd(), &hit);
    ListView_SetItemState(state.list.hwnd(), -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    if (kClickedItem >= 0 && static_cast<std::size_t>(kClickedItem) < state.list.visibleIndexes().size()) {
        ListView_SetItemState(state.list.hwnd(), kClickedItem, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        state.contextColumn = hit.iSubItem;
        syncEditorFromSelection(state);
    }
    const bool kHasSelection = selectedEntry(state, nullptr, nullptr);
    const bool kCanOperate = state.currentSnapshotReady && !state.operationInProgress;
    const bool kCanExportVisible = state.currentSnapshotReady && !state.list.visibleIndexes().empty();
    ::AppendMenuW(menu, MF_STRING, kMenuRefresh, L"刷新");
    ::AppendMenuW(menu, MF_STRING | (kHasSelection ? 0U : MF_GRAYED), kMenuCopyName, L"复制名称");
    ::AppendMenuW(menu, MF_STRING | (kHasSelection ? 0U : MF_GRAYED), kMenuCopyData, L"复制数据");
    ::AppendMenuW(menu, MF_STRING | (kHasSelection ? 0U : MF_GRAYED), kMenuCopyCell, L"复制单元格");
    ::AppendMenuW(menu, MF_STRING | (kHasSelection ? 0U : MF_GRAYED), kMenuCopyRow, L"复制行");
    ::AppendMenuW(menu, MF_STRING | (!state.list.visibleIndexes().empty() ? 0U : MF_GRAYED), kMenuCopyVisible, L"复制可见结果");
    ::AppendMenuW(menu, MF_STRING | (kCanExportVisible ? 0U : MF_GRAYED), kMenuExportVisible, L"导出当前可见值 TSV");
    ::AppendMenuW(menu, MF_STRING | (kCanOperate ? 0U : MF_GRAYED), kMenuRead, L"读取值");
    ::AppendMenuW(menu, MF_STRING | (kCanOperate ? 0U : MF_GRAYED), kMenuWrite, L"写入值");
    ::AppendMenuW(menu, MF_STRING | (kCanOperate ? 0U : MF_GRAYED), kMenuCreateSubKey, L"创建子键");
    ::AppendMenuW(menu, MF_STRING | (kCanOperate && kHasSelection ? 0U : MF_GRAYED), kMenuDelete, L"删除");
    ::AppendMenuW(menu, MF_STRING | (kCanOperate && kHasSelection ? 0U : MF_GRAYED), kMenuRename, L"重命名");

    const UINT kCommand = ::TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y, 0, state.hwnd, nullptr);
    ::DestroyMenu(menu);
    if (kCommand == 0) {
        return;
    }

    RegistryEntry* entry = nullptr;
    switch (kCommand) {
    case kMenuRefresh:
        refreshSnapshot(state);
        break;
    case kMenuCopyName:
        if (selectedEntry(state, nullptr, &entry) && entry) {
            setStatus(state, copyRegistryTextToClipboard(state.hwnd, entry->name) ? L"Name copied." : L"Copy name failed.");
        }
        break;
    case kMenuCopyData:
        if (selectedEntry(state, nullptr, &entry) && entry) {
            setStatus(state, copyRegistryTextToClipboard(state.hwnd, entry->dataText) ? L"Data copied." : L"Copy data failed.");
        }
        break;
    case kMenuCopyCell:
        setStatus(state, copyRegistryTextToClipboard(state.hwnd, registrySelectedCellText(state)) ? L"已复制单元格。" : L"复制单元格失败。");
        break;
    case kMenuCopyRow:
        setStatus(state, copyRegistryTextToClipboard(state.hwnd, registryRowsAsText(state, false)) ? L"已复制注册表行。" : L"复制注册表行失败。");
        break;
    case kMenuCopyVisible:
        setStatus(state, copyRegistryTextToClipboard(state.hwnd, registryRowsAsText(state, true)) ? L"已复制可见注册表结果。" : L"复制可见注册表结果失败。");
        break;
    case kMenuExportVisible:
        exportVisibleRegistrySnapshot(state);
        break;
    case kMenuRead:
        readCurrentValue(state);
        break;
    case kMenuWrite:
        writeCurrentValue(state);
        break;
    case kMenuCreateSubKey:
        createSubKeyFromEditor(state);
        break;
    case kMenuDelete:
        deleteSelection(state);
        break;
    case kMenuRename:
        renameSelection(state);
        break;
    default:
        break;
    }
}

bool createChildControls(RegistryViewState& state) {
    state.refreshButton = ksword::ui::createButton(state.hwnd, kRefreshButtonId, L"刷新", 0, 0, 0, 0);
    state.upButton = ksword::ui::createButton(state.hwnd, kUpButtonId, L"上一级", 0, 0, 0, 0);
    state.pathEdit = createEdit(state.hwnd, kPathEditId, ES_AUTOHSCROLL);
    state.goButton = ksword::ui::createButton(state.hwnd, kGoButtonId, L"转到", 0, 0, 0, 0);
    state.modeCombo = createCombo(state.hwnd, kModeComboId);
    state.tree = ksword::ui::createTreeView(state.hwnd, kTreeId, 0, 0, 0, 0);
    state.treeFilterBar = ksword::ui::createFilterBar(state.hwnd, kTreeFilterBarId, L"筛选已加载的树节点", 0, 0, 0, 0);
    state.valueFilterBar = ksword::ui::createFilterBar(state.hwnd, kValueFilterBarId, L"筛选名称、类型、数据和详情", 0, 0, 0, 0);
    state.nameEdit = createEdit(state.hwnd, kNameEditId, ES_AUTOHSCROLL);
    state.typeCombo = createCombo(state.hwnd, kTypeComboId);
    state.dataEdit = createEdit(state.hwnd, kDataEditId, ES_MULTILINE | ES_AUTOVSCROLL | ES_WANTRETURN | WS_VSCROLL);
    // Writable, so this one also gets replace: REG_MULTI_SZ and long REG_SZ
    // payloads are routinely edited by hand here.
    ksword::ui::attachTextFindSupport(state.dataEdit);
    state.readButton = ksword::ui::createButton(state.hwnd, kReadButtonId, L"读取", 0, 0, 0, 0);
    state.writeButton = ksword::ui::createButton(state.hwnd, kWriteButtonId, L"写入", 0, 0, 0, 0);
    state.createKeyButton = ksword::ui::createButton(state.hwnd, kCreateKeyButtonId, L"建子键", 0, 0, 0, 0);
    state.deleteButton = ksword::ui::createButton(state.hwnd, kDeleteButtonId, L"删除", 0, 0, 0, 0);
    state.renameButton = ksword::ui::createButton(state.hwnd, kRenameButtonId, L"重命名", 0, 0, 0, 0);
    state.statusText = ksword::ui::createText(state.hwnd, kStatusId, L"", 0, 0, 0, 0);
    state.loadingOverlay = ksword::ui::createLoadingOverlay(state.hwnd, kLoadingOverlayId, { 0, 0, 1, 1 });
    if (!state.refreshButton || !state.upButton || !state.pathEdit || !state.goButton || !state.modeCombo || !state.tree || !state.treeFilterBar || !state.valueFilterBar ||
        !state.nameEdit || !state.typeCombo || !state.dataEdit || !state.readButton || !state.writeButton ||
        !state.createKeyButton || !state.deleteButton || !state.renameButton || !state.statusText || !state.loadingOverlay ||
        !state.list.create(state.hwnd, kListId, 0, 0, 0, 0, LVS_SHOWSELALWAYS)) {
        return false;
    }

    ::SendMessageW(state.modeCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"WinAPI"));
    ::SendMessageW(state.modeCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"R0"));
    ::SendMessageW(state.modeCombo, CB_SETCURSEL, 0, 0);
    for (const RegistryTypeOption& option : kTypeOptions) {
        ::SendMessageW(state.typeCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(option.text));
    }
    ::SendMessageW(state.typeCombo, CB_SETCURSEL, 0, 0);
    ksword::ui::addListViewColumns(state.list.hwnd(), registryColumns());
    ListView_SetExtendedListViewStyle(state.list.hwnd(), LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);
    ::SetWindowTextW(state.pathEdit, L"HKLM\\SOFTWARE");
    setOperationControlsEnabled(state, false);
    setStatus(state, L"Registry dock ready.");
    return true;
}

LRESULT CALLBACK registryViewProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    RegistryViewState* state = stateFromWindow(hwnd);
    if (msg == WM_NCCREATE) {
        auto* create = reinterpret_cast<CREATESTRUCTW*>(lParam);
        state = create ? static_cast<RegistryViewState*>(create->lpCreateParams) : nullptr;
        if (state) {
            state->hwnd = hwnd;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
        }
    }

    switch (msg) {
    case WM_CREATE:
        if (state) {
            if (!createChildControls(*state)) {
                delete state;
                ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                return -1;
            }
            state->refreshTask = std::make_unique<ksword::ui::AsyncSnapshotTask<RegistryRefreshSnapshot>>(hwnd, kMsgSnapshotCompleted);
            state->treeChildrenTask = std::make_unique<ksword::ui::AsyncSnapshotTask<RegistryTreeChildrenSnapshot>>(hwnd, kMsgTreeChildrenCompleted);
            state->filterTask = std::make_unique<ksword::ui::AsyncSnapshotTask<RegistryFilterResult>>(hwnd, kMsgFilterCompleted);
            state->operationTask = std::make_unique<ksword::ui::AsyncSnapshotTask<RegistryOperationSnapshot>>(hwnd, kMsgOperationCompleted);
            layoutChildren(*state);
            rebuildRegistryTree(*state);
            refreshSnapshot(*state);
        }
        return 0;
    case WM_SIZE:
        if (state) {
            layoutChildren(*state);
        }
        return 0;
    case kMsgSnapshotCompleted:
        if (state && state->refreshTask && state->refreshTask->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgTreeChildrenCompleted:
        if (state && state->treeChildrenTask && state->treeChildrenTask->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgFilterCompleted:
        if (state && state->filterTask && state->filterTask->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgOperationCompleted:
        if (state && state->operationTask && state->operationTask->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgExternalNavigate:
        if (state && lParam != 0) {
            const auto* path = reinterpret_cast<const std::wstring*>(lParam);
            if (!path->empty()) {
                prepareModeForExternalNavigation(*state, *path);
                navigateTo(*state, *path);
                return TRUE;
            }
        }
        return FALSE;
    case WM_NOTIFY:
        if (state) {
            const auto* header = reinterpret_cast<const NMHDR*>(lParam);
            if (header && header->hwndFrom == state->list.hwnd()) {
                LRESULT result = 0;
                if (state->list.handleNotify(*header, result)) {
                    return result;
                }
            }
            if (header && header->hwndFrom == state->list.hwnd() && header->code == LVN_ITEMCHANGED) {
                const auto* changed = reinterpret_cast<const NMLISTVIEW*>(lParam);
                if ((changed->uNewState & LVIS_SELECTED) != 0) {
                    syncEditorFromSelection(*state);
                }
                return 0;
            }
            if (header && header->hwndFrom == state->list.hwnd() && header->code == NM_DBLCLK) {
                RegistryEntry* entry = nullptr;
                if (selectedEntry(*state, nullptr, &entry) && entry && entry->kind == RegistryRowKind::kSubKey) {
                    navigateTo(*state, childPath(currentPath(*state), entry->name));
                }
                return 0;
            }
            if (header && header->hwndFrom == state->list.hwnd() && header->code == NM_RCLICK) {
                POINT pt{};
                ::GetCursorPos(&pt);
                showContextMenu(*state, pt);
                return 0;
            }
            if (header && header->hwndFrom == state->tree && header->code == TVN_SELCHANGEDW) {
                const auto* changed = reinterpret_cast<const NMTREEVIEWW*>(lParam);
                if (changed && !state->syncingTreeSelection) {
                    const RegistryTreeNodeData* nodeData = reinterpret_cast<const RegistryTreeNodeData*>(changed->itemNew.lParam);
                    if (nodeData && !nodeData->placeholder) {
                        navigateTo(*state, nodeData->path);
                    }
                }
                return 0;
            }
            if (header && header->hwndFrom == state->tree && header->code == TVN_ITEMEXPANDINGW) {
                const auto* expanding = reinterpret_cast<const NMTREEVIEWW*>(lParam);
                if (expanding && expanding->action == TVE_EXPAND) {
                    ensureTreeChildrenLoaded(*state, expanding->itemNew.hItem);
                }
                return 0;
            }
        }
        break;
    case WM_COMMAND:
        if (state) {
            if (LOWORD(wParam) == kPathEditId && HIWORD(wParam) == EN_CHANGE) {
                if (state->currentSnapshotReady) {
                    invalidateCurrentSnapshot(*state);
                    setStatus(*state, L"路径已更改；请先转到新路径并等待快照加载完成。");
                }
                return 0;
            }
            if (LOWORD(wParam) == kValueFilterBarId && HIWORD(wParam) == EN_CHANGE) {
                requestValueFilter(*state,
                    ksword::ui::getFilterBarText(state->valueFilterBar),
                    stableKeyFromListItem(*state, ListView_GetNextItem(state->list.hwnd(), -1, LVNI_SELECTED)),
                    stableKeyFromListItem(*state, ListView_GetTopIndex(state->list.hwnd())));
                return 0;
            }
            if (LOWORD(wParam) == kTreeFilterBarId && HIWORD(wParam) == EN_CHANGE) {
                state->treeFilterQuery = ksword::ui::getFilterBarText(state->treeFilterBar);
                rebuildRegistryTree(*state);
                return 0;
            }
            switch (LOWORD(wParam)) {
            case kRefreshButtonId:
                refreshSnapshot(*state);
                return 0;
            case kUpButtonId:
                navigateTo(*state, parentPath(currentPath(*state)));
                return 0;
            case kGoButtonId:
                navigateTo(*state, currentPath(*state));
                return 0;
            case kReadButtonId:
                readCurrentValue(*state);
                return 0;
            case kWriteButtonId:
                writeCurrentValue(*state);
                return 0;
            case kCreateKeyButtonId:
                createSubKeyFromEditor(*state);
                return 0;
            case kDeleteButtonId:
                deleteSelection(*state);
                return 0;
            case kRenameButtonId:
                renameSelection(*state);
                return 0;
            case kModeComboId:
                if (HIWORD(wParam) == CBN_SELCHANGE) {
                    state->mode = (::SendMessageW(state->modeCombo, CB_GETCURSEL, 0, 0) == 1)
                        ? RegistryViewMode::kR0
                        : RegistryViewMode::kWinApi;
                    invalidateCurrentSnapshot(*state);
                    rebuildRegistryTree(*state);
                    refreshSnapshot(*state);
                    return 0;
                }
                break;
            default:
                break;
            }
        }
        break;
    case WM_CONTEXTMENU:
        if (state) {
            if (reinterpret_cast<HWND>(wParam) != state->list.hwnd()) {
                return 0;
            }
            POINT pt{ GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
            if (pt.x == -1 && pt.y == -1) {
                RECT rc{};
                ::GetWindowRect(state->list.hwnd(), &rc);
                pt = { rc.left + 16, rc.top + 16 };
            }
            showContextMenu(*state, pt);
            return 0;
        }
        break;
    case WM_CTLCOLORSTATIC: {
        HDC dc = reinterpret_cast<HDC>(wParam);
        ::SetBkMode(dc, TRANSPARENT);
        ::SetTextColor(dc, ksword::ui::appTheme().textColor);
        return reinterpret_cast<LRESULT>(ksword::ui::appTheme().windowBrush());
    }
    case WM_NCDESTROY:
        if (state) {
            if (state->refreshTask) {
                state->refreshTask->cancel();
            }
            if (state->treeChildrenTask) {
                state->treeChildrenTask->cancel();
            }
            if (state->filterTask) {
                state->filterTask->cancel();
            }
            if (state->operationTask) {
                state->operationTask->cancel();
            }
            clearRegistryTree(state->tree);
        }
        delete state;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        return 0;
    default:
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

bool registerRegistryViewClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW wc{};
    wc.lpfnWndProc = registryViewProc;
    wc.hInstance = ::GetModuleHandleW(nullptr);
    wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = ksword::ui::appTheme().windowBrush();
    wc.lpszClassName = kRegistryViewClass;
    if (::RegisterClassW(&wc) || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS) {
        registered = true;
    }
    return registered;
}

} // namespace

HWND createRegistryView(HWND parent, const RECT& bounds) {
    if (!parent || !registerRegistryViewClass()) {
        return nullptr;
    }
    auto* state = new RegistryViewState();
    HWND hwnd = ::CreateWindowExW(
        0,
        kRegistryViewClass,
        L"Registry",
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        bounds.left,
        bounds.top,
        bounds.right - bounds.left,
        bounds.bottom - bounds.top,
        parent,
        nullptr,
        ::GetModuleHandleW(nullptr),
        state);
    if (!hwnd) {
        delete state;
    }
    return hwnd;
}

bool requestRegistryViewNavigate(HWND page, const std::wstring& path) {
    return page && !path.empty() &&
        ::SendMessageW(page, kMsgExternalNavigate, 0, reinterpret_cast<LPARAM>(&path)) != 0;
}

} // namespace Ksword::Features::Registry
