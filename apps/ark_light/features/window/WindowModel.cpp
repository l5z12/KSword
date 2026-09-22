#include "WindowModel.h"

#include <algorithm>
#include <sstream>
#include <utility>

namespace ksword::features::window {
namespace {

// addProperty appends a detail row. Inputs are detail, label and value; processing
// omits empty values to avoid noisy detail panes; no value is returned.
void addProperty(WindowDetail& detail, const std::wstring& name, const std::wstring& value) {
    if (!value.empty()) {
        detail.properties.push_back({ name, value });
    }
}

// styleToText formats a window style value. Input is a DWORD style; output is a
// hexadecimal display string suitable for diagnostics.
std::wstring styleToText(DWORD style) {
    std::wstringstream stream;
    stream << L"0x" << std::hex << std::uppercase << style;
    return stream.str();
}

// processColumnText combines process identity into one compact list column.
// Inputs are a window row with process name/PID; output is suitable for the
// ListView PID column that now carries process icon, name, and numeric PID.
std::wstring processColumnText(const WindowSnapshotRow& row) {
    const std::wstring kName = row.processName.empty() ? L"(unknown process)" : row.processName;
    return kName + L" (" + std::to_wstring(row.processId) + L")";
}

} // namespace

WindowModel::WindowModel() = default;

void WindowModel::setRows(std::vector<WindowSnapshotRow> rows) {
    originalRows_ = std::move(rows);
    rebuildRows();
}

void WindowModel::setSortMode(WindowSortMode mode) {
    if (sortMode_ == mode) {
        return;
    }
    sortMode_ = mode;
    rebuildRows();
}

WindowSortMode WindowModel::sortMode() const {
    return sortMode_;
}

const std::vector<WindowSnapshotRow>& WindowModel::rows() const {
    return rows_;
}

const WindowSnapshotRow* WindowModel::rowAt(int index) const {
    if (index < 0 || index >= static_cast<int>(rows_.size())) {
        return nullptr;
    }
    return &rows_[index];
}

void WindowModel::rebuildRows() {
    rows_ = originalRows_;
    if (sortMode_ == WindowSortMode::kStackingOrder) {
        return;
    }

    std::sort(rows_.begin(), rows_.end(), [](const WindowSnapshotRow& left, const WindowSnapshotRow& right) {
        const std::wstring kLeftName = left.processName.empty() ? L"(unknown process)" : left.processName;
        const std::wstring kRightName = right.processName.empty() ? L"(unknown process)" : right.processName;
        if (kLeftName != kRightName) {
            return kLeftName < kRightName;
        }
        if (left.processId != right.processId) {
            return left.processId < right.processId;
        }
        if (left.title != right.title) {
            return left.title < right.title;
        }
        return reinterpret_cast<UINT_PTR>(left.hwnd) < reinterpret_cast<UINT_PTR>(right.hwnd);
    });
}

std::wstring WindowModel::textForColumn(const WindowSnapshotRow& row, int column) const {
    switch (column) {
    case 0:
        return processColumnText(row);
    case 1:
        return hwndToText(row.hwnd);
    case 2:
        return row.title.empty() ? L"(untitled)" : row.title;
    case 3:
        return row.className;
    case 4:
        return windowStateText(row);
    default:
        break;
    }
    return {};
}

WindowDetail WindowModel::detailFromRow(const WindowSnapshotRow& row) const {
    WindowDetail detail;
    detail.found = true;
    detail.hwnd = row.hwnd;
    detail.title = row.title.empty() ? hwndToText(row.hwnd) : row.title;
    addProperty(detail, L"HWND", hwndToText(row.hwnd));
    addProperty(detail, L"Title", row.title.empty() ? L"(untitled)" : row.title);
    addProperty(detail, L"Class", row.className);
    addProperty(detail, L"Process ID", std::to_wstring(row.processId));
    addProperty(detail, L"Process name", row.processName);
    addProperty(detail, L"Thread ID", std::to_wstring(row.threadId));
    addProperty(detail, L"State", windowStateText(row));
    addProperty(detail, L"Window rect", rectToText(row.windowRect));
    addProperty(detail, L"Client rect", rectToText(row.clientRect));
    addProperty(detail, L"Style", styleToText(row.style));
    addProperty(detail, L"Extended style", styleToText(row.exStyle));
    addProperty(detail, L"Unicode", row.unicode ? L"Yes" : L"No");
    addProperty(detail, L"Process image", row.processImagePath);
    return detail;
}

std::wstring windowStateText(const WindowSnapshotRow& row) {
    std::wstring state = row.visible ? L"Visible" : L"Hidden";
    state += row.enabled ? L", Enabled" : L", Disabled";
    if (row.minimized) {
        state += L", Minimized";
    } else if (row.maximized) {
        state += L", Maximized";
    }
    return state;
}

std::wstring hwndToText(HWND hwnd) {
    std::wstringstream stream;
    stream << L"0x" << std::hex << std::uppercase << reinterpret_cast<UINT_PTR>(hwnd);
    return stream.str();
}

std::wstring rectToText(const RECT& rect) {
    const LONG kWidth = rect.right - rect.left;
    const LONG kHeight = rect.bottom - rect.top;
    return std::to_wstring(rect.left) + L"," + std::to_wstring(rect.top) + L" " +
        std::to_wstring(kWidth) + L"x" + std::to_wstring(kHeight);
}

} // namespace Ksword::Features::Window
