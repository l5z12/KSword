#include "ProcessModel.h"
#include "ProcessColumns.h"

#include <algorithm>
#include <cwchar>
#include <cwctype>
#include <unordered_map>

namespace ksword::features::process {
namespace {
std::wstring lowerText(std::wstring text) {
    std::transform(text.begin(), text.end(), text.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(::towlower(ch));
    });
    return text;
}

std::wstring numberText(ULONGLONG value) {
    wchar_t buffer[64]{};
    ::swprintf_s(buffer, L"%llu", static_cast<unsigned long long>(value));
    return buffer;
}

// hexPointerText formats R0 object addresses for read-only audit columns. Input
// is an integer address copied from ArkDriverClient; output is "-" when absent.
std::wstring hexPointerText(std::uintptr_t value) {
    if (value == 0) {
        return L"-";
    }

    wchar_t buffer[32]{};
    ::swprintf_s(buffer,
        L"0x%0*llX",
        sizeof(void*) == 8 ? 16 : 8,
        static_cast<unsigned long long>(value));
    return buffer;
}

std::wstring percentText(double value) {
    wchar_t buffer[32]{};
    ::swprintf_s(buffer, L"%.1f%%", value);
    return buffer;
}

} // namespace

ProcessModel::ProcessModel() = default;

void ProcessModel::setRows(std::vector<ProcessSnapshotRow> rows) {
    rows_ = std::move(rows);
    rebuildDisplayRows();
}

const std::vector<ProcessSnapshotRow>& ProcessModel::rows() const {
    return rows_;
}

const std::vector<ProcessDisplayRow>& ProcessModel::displayRows(ProcessViewMode mode) const {
    return mode == ProcessViewMode::kDetail ? detailRows_ : friendlyRows_;
}

const ProcessSnapshotRow* ProcessModel::rowForDisplayRow(const ProcessDisplayRow& displayRow) const {
    if (displayRow.groupHeader || displayRow.sourceIndex >= rows_.size()) {
        return nullptr;
    }
    return &rows_[displayRow.sourceIndex];
}

std::wstring ProcessModel::textForColumn(const ProcessDisplayRow& displayRow, int column, ProcessViewMode mode) const {
    if (displayRow.groupHeader) {
        return column == 0 ? displayRow.title : (column == 1 ? displayRow.status : L"");
    }

    const ProcessSnapshotRow* row = rowForDisplayRow(displayRow);
    if (!row) {
        return {};
    }

    if (mode == ProcessViewMode::kDetail) {
        switch (column) {
        case 0: return row->imageName;
        case 1: return numberText(row->processId);
        case 2: return numberText(row->parentProcessId);
        case 3: return numberText(row->threadCount);
        case 4: return formatByteSize(static_cast<ULONGLONG>(row->workingSetBytes));
        case 5: return formatByteSize(static_cast<ULONGLONG>(row->privatePageBytes));
        case 6: return formatByteSize(static_cast<ULONGLONG>(row->virtualSizeBytes));
        case 7: return numberText(static_cast<ULONGLONG>(row->basePriority));
        case 8: return numberText(row->sessionId);
        case 9: return hexPointerText(row->r0ProcessObjectAddress);
        case 10: return row->r0AuditSummary.empty() ? L"-" : row->r0AuditSummary;
        case 11: return row->r0AuditDetail.empty() ? L"-" : row->r0AuditDetail;
        case 12: return row->imagePath.empty() ? L"<access denied>" : row->imagePath;
        default: return {};
        }
    }

    switch (column) {
    case 0: return row->imageName;
    case 1: return numberText(row->processId);
    case 2: return percentText(row->cpuUsagePercent);
    case 3: return formatByteSize(static_cast<ULONGLONG>(row->workingSetBytes));
    case 4: return formatByteSize(static_cast<ULONGLONG>(row->privatePageBytes));
    case 5: return formatByteSize(static_cast<ULONGLONG>(row->virtualSizeBytes));
    case 6: return numberText(row->threadCount);
    case 7: return numberText(row->sessionId);
    case 8: return numberText(row->pageFaultCount);
    default: return {};
    }
}

std::wstring ProcessModel::textForColumn(const ProcessDisplayRow& displayRow, ProcessColumnId column) const {
    if (displayRow.groupHeader) {
        return column == ProcessColumnId::kName ? displayRow.title : std::wstring();
    }
    const ProcessSnapshotRow* row = rowForDisplayRow(displayRow);
    return row ? processColumnText(*row, column) : std::wstring();
}

std::wstring ProcessModel::iconPathForRow(const ProcessDisplayRow& displayRow) const {
    const ProcessSnapshotRow* row = rowForDisplayRow(displayRow);
    if (!row) {
        return {};
    }
    return row->imagePath;
}

std::vector<DWORD> ProcessModel::selectedPids(const std::vector<int>& displayIndexes, ProcessViewMode mode) const {
    std::vector<DWORD> pids;
    const auto& visibleRows = displayRows(mode);
    for (int index : displayIndexes) {
        if (index < 0 || index >= static_cast<int>(visibleRows.size())) {
            continue;
        }
        const ProcessSnapshotRow* row = rowForDisplayRow(visibleRows[static_cast<std::size_t>(index)]);
        if (row) {
            pids.push_back(row->processId);
        }
    }
    return pids;
}

void ProcessModel::toggleGroupCollapsed(ProcessFriendlyGroup group) {
    const std::size_t kIndex = groupIndex(group);
    if (kIndex >= collapsedGroups_.size()) {
        return;
    }
    collapsedGroups_[kIndex] = !collapsedGroups_[kIndex];
    rebuildDisplayRows();
}

bool ProcessModel::isGroupCollapsed(ProcessFriendlyGroup group) const {
    const std::size_t kIndex = groupIndex(group);
    return kIndex < collapsedGroups_.size() ? collapsedGroups_[kIndex] : false;
}

void ProcessModel::rebuildDisplayRows() {
    friendlyRows_.clear();
    detailRows_.clear();

    std::vector<std::size_t> indexes(rows_.size());
    for (std::size_t i = 0; i < rows_.size(); ++i) {
        indexes[i] = i;
    }
    std::sort(indexes.begin(), indexes.end(), [this](std::size_t left, std::size_t right) {
        const ProcessSnapshotRow& a = rows_[left];
        const ProcessSnapshotRow& b = rows_[right];
        const std::wstring kAn = lowerText(a.imageName);
        const std::wstring kBn = lowerText(b.imageName);
        if (kAn != kBn) {
            return kAn < kBn;
        }
        return a.processId < b.processId;
    });

    for (ProcessFriendlyGroup group : { ProcessFriendlyGroup::kApplications, ProcessFriendlyGroup::kBackground, ProcessFriendlyGroup::kWindowsSystem }) {
        appendGroupRows(group, indexes);
    }
}

void ProcessModel::appendGroupRows(ProcessFriendlyGroup group, const std::vector<std::size_t>& sortedIndexes) {
    std::vector<std::size_t> groupIndexes;
    for (std::size_t index : sortedIndexes) {
        if (classifyRow(rows_[index]) == group) {
            groupIndexes.push_back(index);
        }
    }

    const bool kCollapsed = isGroupCollapsed(group);
    const ProcessDisplayRow kHeader{ true, group, 0, 0, groupTitle(group, static_cast<int>(groupIndexes.size())), kCollapsed ? L"Collapsed" : L"Expanded" };
    friendlyRows_.push_back(kHeader);
    detailRows_.push_back(kHeader);
    if (kCollapsed) {
        return;
    }

    std::unordered_map<DWORD, std::size_t> sourceByPid;
    for (std::size_t sourceIndex : groupIndexes) {
        sourceByPid.emplace(rows_[sourceIndex].processId, sourceIndex);
    }

    std::vector<std::vector<std::size_t>> childrenBySourceIndex(rows_.size());
    std::vector<std::size_t> roots;
    for (std::size_t sourceIndex : groupIndexes) {
        const DWORD kParentPid = rows_[sourceIndex].parentProcessId;
        const auto kParent = sourceByPid.find(kParentPid);
        if (kParent != sourceByPid.end() && kParent->second != sourceIndex) {
            childrenBySourceIndex[kParent->second].push_back(sourceIndex);
        } else {
            roots.push_back(sourceIndex);
        }
    }

    auto rowLess = [this](std::size_t left, std::size_t right) {
        const std::wstring kLeftName = lowerText(rows_[left].imageName);
        const std::wstring kRightName = lowerText(rows_[right].imageName);
        if (kLeftName != kRightName) {
            return kLeftName < kRightName;
        }
        return rows_[left].processId < rows_[right].processId;
    };
    std::sort(roots.begin(), roots.end(), rowLess);
    for (std::vector<std::size_t>& children : childrenBySourceIndex) {
        std::sort(children.begin(), children.end(), rowLess);
    }

    std::vector<bool> emitted(rows_.size(), false);
    for (std::size_t root : roots) {
        appendTreeRows(group, root, 1, childrenBySourceIndex, emitted);
    }
    for (std::size_t sourceIndex : groupIndexes) {
        if (!emitted[sourceIndex]) {
            appendTreeRows(group, sourceIndex, 1, childrenBySourceIndex, emitted);
        }
    }
}

void ProcessModel::appendTreeRows(ProcessFriendlyGroup group,
    std::size_t sourceIndex,
    int depth,
    const std::vector<std::vector<std::size_t>>& childrenBySourceIndex,
    std::vector<bool>& emitted) {
    if (sourceIndex >= rows_.size() || emitted[sourceIndex]) {
        return;
    }

    emitted[sourceIndex] = true;
    const ProcessDisplayRow kRow{ false, group, depth, sourceIndex, {}, {} };
    friendlyRows_.push_back(kRow);
    detailRows_.push_back(kRow);

    if (sourceIndex < childrenBySourceIndex.size()) {
        for (std::size_t child : childrenBySourceIndex[sourceIndex]) {
            appendTreeRows(group, child, depth + 1, childrenBySourceIndex, emitted);
        }
    }
}

ProcessFriendlyGroup ProcessModel::classifyRow(const ProcessSnapshotRow& row) {
    const std::wstring kName = lowerText(row.imageName);
    const std::wstring kPath = lowerText(row.imagePath);
    if (row.processId <= 4 || kPath.find(L"\\windows\\system32\\") != std::wstring::npos ||
        kName == L"system" || kName == L"smss.exe" || kName == L"csrss.exe" || kName == L"wininit.exe" ||
        kName == L"services.exe" || kName == L"lsass.exe" || kName == L"winlogon.exe") {
        return ProcessFriendlyGroup::kWindowsSystem;
    }
    if (kPath.find(L"\\program files") != std::wstring::npos || kPath.find(L"\\users\\") != std::wstring::npos) {
        return ProcessFriendlyGroup::kApplications;
    }
    return ProcessFriendlyGroup::kBackground;
}

std::wstring ProcessModel::groupTitle(ProcessFriendlyGroup group, int count) const {
    const wchar_t* title = L"后台进程";
    if (group == ProcessFriendlyGroup::kApplications) {
        title = L"应用";
    } else if (group == ProcessFriendlyGroup::kWindowsSystem) {
        title = L"系统进程";
    }
    const wchar_t* marker = isGroupCollapsed(group) ? L"▶" : L"▼";
    wchar_t buffer[128]{};
    ::swprintf_s(buffer, L"%s %s (%d)", marker, title, count);
    return buffer;
}

std::size_t ProcessModel::groupIndex(ProcessFriendlyGroup group) {
    switch (group) {
    case ProcessFriendlyGroup::kApplications: return 0;
    case ProcessFriendlyGroup::kBackground: return 1;
    case ProcessFriendlyGroup::kWindowsSystem: return 2;
    default: return 1;
    }
}

std::wstring formatByteSize(ULONGLONG bytes) {
    const wchar_t* suffixes[] = { L"B", L"KiB", L"MiB", L"GiB", L"TiB" };
    double value = static_cast<double>(bytes);
    int suffix = 0;
    while (value >= 1024.0 && suffix < 4) {
        value /= 1024.0;
        ++suffix;
    }
    wchar_t buffer[64]{};
    if (suffix == 0) {
        ::swprintf_s(buffer, L"%llu %s", static_cast<unsigned long long>(bytes), suffixes[suffix]);
    } else {
        ::swprintf_s(buffer, L"%.1f %s", value, suffixes[suffix]);
    }
    return buffer;
}

std::wstring leafName(const std::wstring& path) {
    const std::size_t kSlash = path.find_last_of(L"\\/");
    if (kSlash == std::wstring::npos || kSlash + 1 >= path.size()) {
        return path;
    }
    return path.substr(kSlash + 1);
}

} // namespace Ksword::Features::Process
