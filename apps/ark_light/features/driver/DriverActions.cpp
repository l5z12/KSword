#include "DriverActions.h"

#include "../../../../shared/ark_client/ArkDriverClient.h"
#include "../../ui/ExportUtil.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

namespace ksword::features::driver {
namespace {

// appendTsvRow joins one row with tabs and a trailing CRLF. Inputs are an
// output string and column cells; processing sanitizes each cell first; no value
// is returned because the result is accumulated into the output buffer.
void appendTsvRow(std::wstring& output, const std::vector<std::wstring>& cells) {
    for (std::size_t index = 0; index < cells.size(); ++index) {
        if (index != 0) {
            output.push_back(L'\t');
        }
        output += DriverModel::sanitizeTsvCell(cells[index]);
    }
    output += L"\r\n";
}

// utf8ToWide converts ArkDriverClient's narrow diagnostic messages into UI
// text. Input is a UTF-8 or byte-oriented string; processing tries strict UTF-8
// first and falls back byte-by-byte; output is always safe UTF-16 text.
std::wstring utf8ToWide(const std::string& text) {
    if (text.empty()) {
        return {};
    }

    const int kRequired = ::MultiByteToWideChar(
        CP_UTF8,
        MB_ERR_INVALID_CHARS,
        text.c_str(),
        static_cast<int>(text.size()),
        nullptr,
        0);
    if (kRequired > 0) {
        std::wstring wide(static_cast<std::size_t>(kRequired), L'\0');
        ::MultiByteToWideChar(
            CP_UTF8,
            MB_ERR_INVALID_CHARS,
            text.c_str(),
            static_cast<int>(text.size()),
            wide.data(),
            kRequired);
        return wide;
    }

    std::wstring fallback;
    fallback.reserve(text.size());
    for (const unsigned char kCh : text) {
        fallback.push_back(static_cast<wchar_t>(kCh));
    }
    return fallback;
}

// HexText formats protocol addresses and bitfields. Input is an integer value;
// processing uses uppercase hexadecimal without locale-specific formatting;
// output is compact diagnostic text.
std::wstring hexText(const std::uint64_t value) {
    std::wostringstream stream;
    stream << L"0x" << std::uppercase << std::hex << value;
    return stream.str();
}

// ntStatusText formats signed NTSTATUS values while preserving their low
// 32-bit representation. Input is a signed long from the shared protocol;
// output is a diagnostic hexadecimal string.
std::wstring ntStatusText(const long status) {
    return hexText(static_cast<std::uint32_t>(status));
}

// driverObjectQueryStatusText maps the shared DriverObject query status to a
// short label. Input is a KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_* value; output
// is display text for the detail popup.
const wchar_t* driverObjectQueryStatusText(const std::uint32_t status) {
    switch (status) {
    case KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_OK: return L"OK";
    case KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_PARTIAL: return L"Partial";
    case KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_NAME_INVALID: return L"Name invalid";
    case KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_NOT_FOUND: return L"Not found";
    case KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_REFERENCE_FAILED: return L"Reference failed";
    case KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_BUFFER_TOO_SMALL: return L"Buffer too small";
    case KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_QUERY_FAILED: return L"Query failed";
    default: return L"Unavailable";
    }
}

// majorFunctionName returns a standard IRP_MJ_* name for one dispatch slot.
// Input is a major-function index; output falls back to a numeric label when
// the value is not in the common Windows range.
std::wstring majorFunctionName(const std::uint32_t value) {
    switch (value) {
    case 0x00: return L"IRP_MJ_CREATE";
    case 0x01: return L"IRP_MJ_CREATE_NAMED_PIPE";
    case 0x02: return L"IRP_MJ_CLOSE";
    case 0x03: return L"IRP_MJ_READ";
    case 0x04: return L"IRP_MJ_WRITE";
    case 0x05: return L"IRP_MJ_QUERY_INFORMATION";
    case 0x06: return L"IRP_MJ_SET_INFORMATION";
    case 0x07: return L"IRP_MJ_QUERY_EA";
    case 0x08: return L"IRP_MJ_SET_EA";
    case 0x09: return L"IRP_MJ_FLUSH_BUFFERS";
    case 0x0A: return L"IRP_MJ_QUERY_VOLUME_INFORMATION";
    case 0x0B: return L"IRP_MJ_SET_VOLUME_INFORMATION";
    case 0x0C: return L"IRP_MJ_DIRECTORY_CONTROL";
    case 0x0D: return L"IRP_MJ_FILE_SYSTEM_CONTROL";
    case 0x0E: return L"IRP_MJ_DEVICE_CONTROL";
    case 0x0F: return L"IRP_MJ_INTERNAL_DEVICE_CONTROL";
    case 0x10: return L"IRP_MJ_SHUTDOWN";
    case 0x11: return L"IRP_MJ_LOCK_CONTROL";
    case 0x12: return L"IRP_MJ_CLEANUP";
    case 0x13: return L"IRP_MJ_CREATE_MAILSLOT";
    case 0x14: return L"IRP_MJ_QUERY_SECURITY";
    case 0x15: return L"IRP_MJ_SET_SECURITY";
    case 0x16: return L"IRP_MJ_POWER";
    case 0x17: return L"IRP_MJ_SYSTEM_CONTROL";
    case 0x18: return L"IRP_MJ_DEVICE_CHANGE";
    case 0x19: return L"IRP_MJ_QUERY_QUOTA";
    case 0x1A: return L"IRP_MJ_SET_QUOTA";
    case 0x1B: return L"IRP_MJ_PNP";
    default: return L"IRP_MJ_" + std::to_wstring(value);
    }
}

// appendLine appends one labelled line to a detail string. Inputs are output,
// label and value; processing keeps CRLF formatting consistent; no value is
// returned because the output buffer is mutated in place.
void appendLine(std::wstring& text, const std::wstring& label, const std::wstring& value) {
    text += label;
    text += L": ";
    text += value;
    text += L"\r\n";
}

} // namespace

DriverActionResult DriverActions::refreshModel(DriverModel& model) {
    const DriverEnumerationResult kResult = enumerateDriverSnapshot();
    model.setOverviewRows(kResult.overviewRows);
    model.setObjectRows(kResult.objectRows);

    DriverActionResult actionResult;
    actionResult.success = kResult.success;
    actionResult.statusText = kResult.diagnosticText;
    return actionResult;
}

bool DriverActions::copyTextToClipboard(HWND owner, const std::wstring& text) {
    return ksword::ui::copyTextToClipboard(owner, text, L"驱动模块");
}

std::wstring DriverActions::buildTsv(
    const std::vector<std::wstring>& headers,
    const std::vector<std::vector<std::wstring>>& rows) {
    std::wstring output;
    if (!headers.empty()) {
        appendTsvRow(output, headers);
    }
    for (const auto& row : rows) {
        appendTsvRow(output, row);
    }
    return output;
}

DriverActionResult DriverActions::buildDriverObjectDetailText(const std::wstring& driverObjectName) {
    DriverActionResult result;
    if (driverObjectName.empty()) {
        result.statusText = L"DriverObject 名称为空，无法调用 R0 详情查询。";
        return result;
    }

    const ksword::ark::DriverClient kClient;
    const ksword::ark::DriverObjectQueryResult kQuery = kClient.queryDriverObject(
        driverObjectName,
        KSWORD_ARK_DRIVER_OBJECT_QUERY_FLAG_INCLUDE_ALL,
        KSWORD_ARK_DRIVER_DEVICE_LIMIT_DEFAULT,
        KSWORD_ARK_DRIVER_ATTACHED_LIMIT_DEFAULT);

    result.success = kQuery.io.ok &&
        (kQuery.queryStatus == KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_OK ||
            kQuery.queryStatus == KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_PARTIAL);

    std::wstring text;
    appendLine(text, L"Request", driverObjectName);
    appendLine(text, L"IO", kQuery.io.ok ? L"OK" : L"FAIL");
    appendLine(text, L"Win32", std::to_wstring(kQuery.io.win32Error));
    appendLine(text, L"BytesReturned", std::to_wstring(kQuery.io.bytesReturned));
    appendLine(text, L"QueryStatus", std::wstring(driverObjectQueryStatusText(kQuery.queryStatus)) + L" (" + std::to_wstring(kQuery.queryStatus) + L")");
    appendLine(text, L"LastStatus", ntStatusText(kQuery.lastStatus));
    appendLine(text, L"FieldFlags", hexText(kQuery.fieldFlags));
    appendLine(text, L"DriverName", kQuery.driverName);
    appendLine(text, L"ServiceKey", kQuery.serviceKeyName);
    appendLine(text, L"ImagePath", kQuery.imagePath);
    appendLine(text, L"DriverObject", hexText(kQuery.driverObjectAddress));
    appendLine(text, L"DriverStart", hexText(kQuery.driverStart));
    appendLine(text, L"DriverSection", hexText(kQuery.driverSection));
    appendLine(text, L"DriverUnload", hexText(kQuery.driverUnload));
    appendLine(text, L"DriverFlags", hexText(kQuery.driverFlags));
    appendLine(text, L"DriverSize", hexText(kQuery.driverSize));
    appendLine(text, L"MajorFunctionCount", std::to_wstring(kQuery.majorFunctionCount));
    appendLine(text, L"TotalDeviceCount", std::to_wstring(kQuery.totalDeviceCount));
    appendLine(text, L"ReturnedDeviceCount", std::to_wstring(kQuery.returnedDeviceCount));
    appendLine(text, L"Message", utf8ToWide(kQuery.io.message));

    if (!kQuery.majorFunctions.empty()) {
        text += L"\r\nMajorFunctions:\r\n";
        for (const ksword::ark::DriverMajorFunctionEntry& entry : kQuery.majorFunctions) {
            text += L"  ";
            text += majorFunctionName(entry.majorFunction);
            text += L" Dispatch=" + hexText(entry.dispatchAddress);
            text += L" Module=" + entry.moduleName;
            text += L" ModuleBase=" + hexText(entry.moduleBase);
            text += L" Flags=" + hexText(entry.flags);
            text += L"\r\n";
        }
    }

    if (!kQuery.devices.empty()) {
        text += L"\r\nDeviceObjects:\r\n";
        for (const ksword::ark::DriverDeviceEntry& entry : kQuery.devices) {
            text += L"  ";
            text += entry.deviceName.empty() ? L"<unnamed>" : entry.deviceName;
            text += L" Device=" + hexText(entry.deviceObjectAddress);
            text += L" Attached=" + hexText(entry.attachedDeviceObjectAddress);
            text += L" Next=" + hexText(entry.nextDeviceObjectAddress);
            text += L" Type=" + hexText(entry.deviceType);
            text += L" Flags=" + hexText(entry.flags);
            text += L" Depth=" + std::to_wstring(entry.relationDepth);
            text += L"\r\n";
        }
    }

    result.statusText = text;
    return result;
}

} // namespace Ksword::Features::Driver
