#include "AuditStatus.h"

namespace ksword::features::audit_common {
namespace {

// MakeInfo builds an AuditStatusInfo record. Inputs are status, label, detail,
// token and color; processing only groups the values; output is the display
// descriptor returned by describeAuditStatus.
AuditStatusInfo makeInfo(
    AuditStatus status,
    const wchar_t* label,
    const wchar_t* detail,
    const wchar_t* exportToken,
    COLORREF color) {
    AuditStatusInfo info;
    info.status = status;
    info.label = label ? label : L"";
    info.detail = detail ? detail : L"";
    info.exportToken = exportToken ? exportToken : L"";
    info.textColor = color;
    return info;
}

} // namespace

AuditStatusInfo describeAuditStatus(const AuditStatus status) {
    // Colors mirror the audit-prep UI guidance:
    // green = clean/normal, yellow/orange = partial, gray = unsupported,
    // red = failed/access denied. Unsupported/partial are never green.
    switch (status) {
    case AuditStatus::kOk:
        return makeInfo(status, L"OK", L"读取成功，未发现查询层面的异常。", L"ok", RGB(24, 128, 56));
    case AuditStatus::kUnsupported:
        return makeInfo(status, L"unsupported", L"当前系统、权限或驱动能力不支持该只读查询。", L"unsupported", RGB(112, 112, 112));
    case AuditStatus::kAccessDenied:
        return makeInfo(status, L"access denied", L"权限不足；请以管理员权限或具备相应能力后重试。", L"access_denied", RGB(176, 48, 48));
    case AuditStatus::kPartial:
        return makeInfo(status, L"partial", L"仅获取到部分证据，不能作为 clean 结论。", L"partial", RGB(176, 112, 0));
    case AuditStatus::kFailed:
        return makeInfo(status, L"failed", L"查询失败；请查看错误码和详情。", L"failed", RGB(176, 48, 48));
    case AuditStatus::kUnknown:
    default:
        return makeInfo(status, L"unknown", L"尚未执行查询或状态无法归类。", L"unknown", RGB(96, 103, 112));
    }
}

AuditStatus auditStatusFromWin32Error(const DWORD errorCode) {
    // ERROR_SUCCESS represents a successful Win32 call. Access and unsupported
    // failures are elevated into first-class UI states so callers do not render
    // them as generic errors.
    switch (errorCode) {
    case ERROR_SUCCESS:
        return AuditStatus::kOk;
    case ERROR_ACCESS_DENIED:
    case ERROR_PRIVILEGE_NOT_HELD:
        return AuditStatus::kAccessDenied;
    case ERROR_CALL_NOT_IMPLEMENTED:
    case ERROR_NOT_SUPPORTED:
    case ERROR_INVALID_FUNCTION:
        return AuditStatus::kUnsupported;
    case ERROR_MORE_DATA:
    case ERROR_INSUFFICIENT_BUFFER:
        return AuditStatus::kPartial;
    default:
        return AuditStatus::kFailed;
    }
}

AuditStatus auditStatusFromNtStatus(const LONG status) {
    // Numeric constants are used intentionally to keep this R3 helper small and
    // independent from ntstatus.h include ordering. The values are stable
    // NTSTATUS definitions used only for display classification.
    constexpr LONG kStatusSuccess = static_cast<LONG>(0x00000000L);
    constexpr LONG kStatusBufferOverflow = static_cast<LONG>(0x80000005UL);
    constexpr LONG kStatusBufferTooSmall = static_cast<LONG>(0xC0000023UL);
    constexpr LONG kStatusAccessDenied = static_cast<LONG>(0xC0000022UL);
    constexpr LONG kStatusPrivilegeNotHeld = static_cast<LONG>(0xC0000061UL);
    constexpr LONG kStatusNotSupported = static_cast<LONG>(0xC00000BBUL);
    constexpr LONG kStatusNotImplemented = static_cast<LONG>(0xC0000002UL);

    if (status == kStatusSuccess) {
        return AuditStatus::kOk;
    }
    if (status == kStatusAccessDenied || status == kStatusPrivilegeNotHeld) {
        return AuditStatus::kAccessDenied;
    }
    if (status == kStatusNotSupported || status == kStatusNotImplemented) {
        return AuditStatus::kUnsupported;
    }
    if (status == kStatusBufferOverflow || status == kStatusBufferTooSmall) {
        return AuditStatus::kPartial;
    }
    return AuditStatus::kFailed;
}

void setStatusLabel(HWND label, const AuditStatus status, const std::wstring& suffix) {
    if (!label) {
        return;
    }

    const AuditStatusInfo kInfo = describeAuditStatus(status);
    std::wstring text = kInfo.label;
    if (!suffix.empty()) {
        text += L" - ";
        text += suffix;
    }
    ::SetWindowTextW(label, text.c_str());
    ::InvalidateRect(label, nullptr, TRUE);
}

} // namespace Ksword::Features::audit_common
