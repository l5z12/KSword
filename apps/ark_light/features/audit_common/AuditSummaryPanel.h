#pragma once

#include "AuditStatus.h"
#include "../../core/Win32Lean.h"

#include <string>
#include <vector>

namespace ksword::features::audit_common {

// AuditSummaryItem describes one key-value audit summary row. Inputs are a
// property name, display value, normalized status and optional detail; processing
// is performed by setAuditSummaryItems; output is rendered as a read-only row.
struct AuditSummaryItem {
    std::wstring key;
    std::wstring value;
    AuditStatus status = AuditStatus::kUnknown;
    std::wstring detail;
};

// createAuditSummaryPanel creates a compact read-only key-value ListView.
// Inputs are parent/id/bounds; processing creates columns Key/Value/Status/Detail
// using the shared table helper; output is the ListView HWND or nullptr.
HWND createAuditSummaryPanel(HWND parent, int id, const RECT& bounds);

// setAuditSummaryItems replaces the summary panel rows. Inputs are the panel
// HWND and summary items; processing renders one row per item; no value returns.
void setAuditSummaryItems(HWND panel, const std::vector<AuditSummaryItem>& items);

// buildAuditSummaryTsv serializes the summary panel. Input is a panel HWND;
// processing delegates to the shared table TSV reader; output is TSV text.
std::wstring buildAuditSummaryTsv(HWND panel);

// appendAuditSummaryItem adds one item to a vector with compact call-site
// syntax. Inputs are destination vector and row fields; processing appends a
// value object; no return value is needed.
void appendAuditSummaryItem(
    std::vector<AuditSummaryItem>& items,
    const std::wstring& key,
    const std::wstring& value,
    AuditStatus status,
    const std::wstring& detail = std::wstring());

} // namespace Ksword::Features::audit_common
