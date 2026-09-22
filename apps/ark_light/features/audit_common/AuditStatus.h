#pragma once

#include "../../core/Win32Lean.h"

#include <string>

namespace ksword::features::audit_common {

// AuditStatus is the UI-neutral status vocabulary shared by read-only audit
// pages. Inputs are collected by feature-specific R3/R0 facades; processing maps
// them to consistent labels/colors; output is a stable state for tables, summary
// panels, and export text.
enum class AuditStatus {
    kUnknown,
    kOk,
    kUnsupported,
    kAccessDenied,
    kPartial,
    kFailed,
};

// AuditStatusInfo carries the display attributes for one AuditStatus. Inputs
// are produced by describeAuditStatus; processing keeps label, detail, color and
// export token together; output is consumed by Win32 STATIC/ListView rendering.
struct AuditStatusInfo {
    AuditStatus status = AuditStatus::kUnknown;
    std::wstring label;
    std::wstring detail;
    std::wstring exportToken;
    COLORREF textColor = RGB(96, 103, 112);
};

// describeAuditStatus returns display attributes for one audit state. Input is
// a normalized AuditStatus value; processing applies the project-wide read-only
// audit color semantics; output is an AuditStatusInfo record.
AuditStatusInfo describeAuditStatus(AuditStatus status);

// auditStatusFromWin32Error maps common Win32 failures to the shared audit
// vocabulary. Input is a Win32 error code from GetLastError or an IO result;
// processing recognizes access-denied and unsupported-style codes; output is a
// normalized AuditStatus.
AuditStatus auditStatusFromWin32Error(DWORD errorCode);

// auditStatusFromNtStatus maps common NTSTATUS values to the shared audit
// vocabulary without including ntstatus.h. Input is a signed NTSTATUS value;
// processing recognizes success, access denied and not-supported codes; output
// is a normalized AuditStatus.
AuditStatus auditStatusFromNtStatus(LONG status);

// setStatusLabel updates a STATIC-like label with consistent status text.
// Inputs are a label HWND, an AuditStatus and optional suffix; processing writes
// the label text and invalidates the control; callers can use describeAuditStatus
// when they need the matching color in WM_CTLCOLORSTATIC; no value is returned.
void setStatusLabel(HWND label, AuditStatus status, const std::wstring& suffix = std::wstring());

} // namespace Ksword::Features::audit_common
