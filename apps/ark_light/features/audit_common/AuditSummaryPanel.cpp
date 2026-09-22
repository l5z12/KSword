#include "AuditSummaryPanel.h"

#include "AuditTable.h"

#include <utility>

namespace ksword::features::audit_common {

HWND createAuditSummaryPanel(HWND parent, const int id, const RECT& bounds) {
    // The summary panel intentionally uses the same report ListView as large
    // audit tables, so copy/export behavior and keyboard navigation stay
    // consistent across feature pages.
    return createReadOnlyAuditTable(parent, id, bounds, {
        { L"Key", 180, LVCFMT_LEFT },
        { L"Value", 360, LVCFMT_LEFT },
        { L"Status", 120, LVCFMT_LEFT },
        { L"Detail", 520, LVCFMT_LEFT },
    });
}

void setAuditSummaryItems(HWND panel, const std::vector<AuditSummaryItem>& items) {
    std::vector<std::vector<std::wstring>> rows;
    rows.reserve(items.size());
    for (const AuditSummaryItem& item : items) {
        const AuditStatusInfo kStatusInfo = describeAuditStatus(item.status);
        rows.push_back({
            item.key,
            item.value,
            kStatusInfo.label,
            item.detail.empty() ? kStatusInfo.detail : item.detail,
        });
    }
    replaceAuditTableRows(panel, rows);
}

std::wstring buildAuditSummaryTsv(HWND panel) {
    return buildAuditTableTsv(panel);
}

void appendAuditSummaryItem(
    std::vector<AuditSummaryItem>& items,
    const std::wstring& key,
    const std::wstring& value,
    const AuditStatus status,
    const std::wstring& detail) {
    AuditSummaryItem item;
    item.key = key;
    item.value = value;
    item.status = status;
    item.detail = detail;
    items.push_back(std::move(item));
}

} // namespace Ksword::Features::audit_common
