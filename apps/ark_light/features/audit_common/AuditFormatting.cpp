#include "AuditFormatting.h"

#include "AuditStatus.h"
#include "../../ui/ExportUtil.h"

#include <cstring>
#include <iomanip>
#include <sstream>

namespace ksword::features::audit_common {

std::wstring formatHexValue(const std::uint64_t value, const int minimumDigits) {
    // The output intentionally avoids locale-specific grouping so addresses and
    // protocol bitfields remain stable across machines and exports.
    std::wostringstream stream;
    stream << L"0x" << std::uppercase << std::hex;
    if (minimumDigits > 0) {
        stream << std::setw(minimumDigits) << std::setfill(L'0');
    }
    stream << value;
    return stream.str();
}

std::wstring formatHexAddress(const std::uint64_t value) {
    return formatHexValue(value, sizeof(void*) == 8 ? 16 : 8);
}

std::wstring formatNtStatus(const LONG status) {
    const std::uint32_t kRaw = static_cast<std::uint32_t>(status);
    const AuditStatus kAuditStatus = auditStatusFromNtStatus(status);
    const AuditStatusInfo kInfo = describeAuditStatus(kAuditStatus);
    return formatHexValue(kRaw, 8) + L" (" + kInfo.label + L")";
}

std::wstring formatWin32Error(const DWORD errorCode) {
    LPWSTR buffer = nullptr;
    const DWORD kFlags = FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS;
    const DWORD kChars = ::FormatMessageW(
        kFlags,
        nullptr,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&buffer),
        0,
        nullptr);

    std::wstring message;
    if (kChars != 0 && buffer) {
        message.assign(buffer, buffer + kChars);
        while (!message.empty() &&
            (message.back() == L'\r' || message.back() == L'\n' || message.back() == L' ' || message.back() == L'\t')) {
            message.pop_back();
        }
        ::LocalFree(buffer);
    } else {
        message = L"Win32 error " + std::to_wstring(errorCode);
    }

    return L"Win32 " + std::to_wstring(errorCode) + L": " + message;
}

std::wstring sanitizeTsvCell(const std::wstring& text) {
    std::wstring sanitized = text;
    for (wchar_t& ch : sanitized) {
        if (ch == L'\t' || ch == L'\r' || ch == L'\n') {
            ch = L' ';
        }
    }
    return sanitized;
}

std::wstring buildTsv(
    const std::vector<std::wstring>& headers,
    const std::vector<std::vector<std::wstring>>& rows) {
    std::wstring output;
    auto appendRow = [&output](const std::vector<std::wstring>& cells) {
        for (std::size_t index = 0; index < cells.size(); ++index) {
            if (index != 0) {
                output.push_back(L'\t');
            }
            output += sanitizeTsvCell(cells[index]);
        }
        output += L"\r\n";
    };

    if (!headers.empty()) {
        appendRow(headers);
    }
    for (const std::vector<std::wstring>& row : rows) {
        appendRow(row);
    }
    return output;
}

bool copyTextToClipboard(HWND owner, const std::wstring& text) {
    return ksword::ui::copyTextToClipboard(owner, text, L"审计结果");
}

} // namespace Ksword::Features::audit_common
