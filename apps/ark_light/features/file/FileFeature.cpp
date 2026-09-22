#include "FileFeature.h"

#include "FileView.h"

#include "../audit_common/AuditFormatting.h"
#include "../audit_common/AuditTable.h"
#include "../../core/EntityRef.h"
#include "../../ui/AsyncTask.h"
#include "../../ui/Controls.h"
#include "../../ui/EntityNavigation.h"
#include "../../ui/ListViewUtil.h"
#include "../../ui/LoadingOverlay.h"
#include "../../ui/TabUtil.h"
#include "../../ui/Theme.h"
#include "../../../../shared/ark_client/ArkDriverClient.h"

#include <commctrl.h>
#include <fltuser.h>
#include <oleauto.h>
#include <wbemidl.h>
#include <windowsx.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cwchar>
#include <iomanip>
#include <iterator>
#include <memory>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#pragma comment(lib, "FltLib.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "wbemuuid.lib")

namespace ksword::features::file {
namespace {

constexpr wchar_t kFileHostClass[] = L"KswordARKLight.FileFeatureHost";
constexpr wchar_t kFileAuditClass[] = L"KswordARKLight.FileAuditPage";
constexpr int kHostTabId = 52600;
constexpr int kBrowserTabIndex = 0;
constexpr int kAuditTabIndex = 1;
constexpr int kAuditTargetEditId = 52610;
constexpr int kAuditRefreshButtonId = 52611;
constexpr int kAuditInnerTabId = 52612;
constexpr int kAuditListId = 52613;
constexpr int kAuditStatusId = 52614;
constexpr int kAuditIntegrityButtonId = 52615;
constexpr int kAuditLoadingOverlayId = 52616;
constexpr int kAuditMinifilterTabIndex = 0;
constexpr int kAuditFileObjectTabIndex = 1;
constexpr int kAuditSectionTabIndex = 2;
constexpr int kAuditStorageTabIndex = 3;
constexpr int kAuditBitLockerTabIndex = 4;
constexpr unsigned long kAuditMaxSectionMappings = 256UL;
constexpr UINT kIntegrityMenuUntrusted = 52701;
constexpr UINT kIntegrityMenuLow = 52702;
constexpr UINT kIntegrityMenuMedium = 52703;
constexpr UINT kIntegrityMenuMediumPlus = 52704;
constexpr UINT kIntegrityMenuHigh = 52705;
constexpr UINT kIntegrityMenuSystem = 52706;
constexpr UINT kAuditMenuCopyCell = 52721;
constexpr UINT kAuditMenuCopyRow = 52722;
constexpr UINT kAuditMenuCopyAll = 52723;
constexpr UINT kAuditMenuOpenMappedProcess = 52724;
constexpr UINT kMsgAuditRefreshCompleted = WM_APP + 550;
constexpr UINT kMsgFileIntegrityCompleted = WM_APP + 551;

#ifndef SECURITY_MANDATORY_MEDIUM_PLUS_RID
#define SECURITY_MANDATORY_MEDIUM_PLUS_RID (0x00002100L)
#endif

// AuditRow is the common table model for every read-only file audit subpage.
// Inputs are collected by R3 public APIs or ArkDriverClient; processing only
// formats evidence; the row owns no handles and returns no resources.
struct AuditRow {
    std::wstring item;
    std::wstring source;
    std::wstring status;
    std::wstring value;
    std::wstring detail;
    // Only a process mapping row may populate this non-display metadata. It
    // is never reconstructed from the diagnostic text or a kernel address.
    std::uint32_t relatedProcessId = 0;
};

struct AuditRefreshSnapshot {
    int tab = kAuditMinifilterTabIndex;
    std::wstring targetPath;
    std::vector<AuditRow> rows;
};

struct FileIntegrityActionResult {
    AuditRow row;
    bool success = false;
    std::wstring statusText;
    std::wstring failureDetail;
};

// FileFeatureHostState owns the outer File feature tabs. Inputs arrive through
// Win32 messages; processing only sizes and shows child pages; no value is
// returned and ownership is released in WM_NCDESTROY.
struct FileFeatureHostState {
    HWND hwnd = nullptr;
    HWND tab = nullptr;
    HWND browserPage = nullptr;
    HWND auditPage = nullptr;
    int currentTab = kBrowserTabIndex;
};

// FileAuditPageState owns the audit target controls and result table. Inputs are
// the current target path plus active subtab; processing rebuilds rows on demand;
// no kernel object is modified and the state is destroyed with the HWND.
struct FileAuditPageState {
    HWND hwnd = nullptr;
    HWND targetEdit = nullptr;
    HWND refreshButton = nullptr;
    HWND integrityButton = nullptr;
    HWND tab = nullptr;
    HWND list = nullptr;
    HWND status = nullptr;
    HWND loadingOverlay = nullptr;
    int currentTab = kAuditMinifilterTabIndex;
    std::vector<AuditRow> rows;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<AuditRefreshSnapshot>> refreshTask;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<FileIntegrityActionResult>> integrityTask;
};

// Width returns a non-negative rectangle width. Input is a RECT; output is a
// pixel count suitable for MoveWindow.
int width(const RECT& rc) {
    return rc.right > rc.left ? rc.right - rc.left : 0;
}

// Height returns a non-negative rectangle height. Input is a RECT; output is a
// pixel count suitable for MoveWindow.
int height(const RECT& rc) {
    return rc.bottom > rc.top ? rc.bottom - rc.top : 0;
}

// fileTimeToText converts a FILETIME-compatible integer to local display text.
// Input is a 64-bit FILETIME value; processing uses FileTimeToSystemTime after
// local conversion; output is a readable timestamp or an unavailable marker.
std::wstring fileTimeToText(const std::int64_t value) {
    if (value <= 0) {
        return L"<不可用>";
    }
    FILETIME utc{};
    utc.dwLowDateTime = static_cast<DWORD>(static_cast<std::uint64_t>(value) & 0xFFFFFFFFULL);
    utc.dwHighDateTime = static_cast<DWORD>((static_cast<std::uint64_t>(value) >> 32) & 0xFFFFFFFFULL);
    FILETIME local{};
    SYSTEMTIME st{};
    if (!::FileTimeToLocalFileTime(&utc, &local) || !::FileTimeToSystemTime(&local, &st)) {
        return L"<时间转换失败>";
    }
    wchar_t buffer[64]{};
    ::swprintf_s(buffer, L"%04u-%02u-%02u %02u:%02u:%02u", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buffer;
}

// HexText formats a diagnostic integer/address. Input is a 64-bit value; output
// is uppercase hexadecimal text used only as evidence, never as an action key.
std::wstring hexText(const std::uint64_t value) {
    std::wostringstream stream;
    stream << L"0x" << std::hex << std::uppercase << value;
    return stream.str();
}

// BoolText converts a boolean flag to Chinese display text. Input is a bool;
// output is a stable label for audit rows.
const wchar_t* boolText(const bool value) {
    return value ? L"是" : L"否";
}

// utf8ToWide converts ArkDriverClient diagnostics to UTF-16. Input is a UTF-8
// or byte-oriented message; processing tries strict UTF-8 and falls back to a
// byte copy; output is safe for UI status cells.
std::wstring utf8ToWide(const std::string& text) {
    if (text.empty()) {
        return {};
    }
    const int kRequired = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.c_str(), static_cast<int>(text.size()), nullptr, 0);
    if (kRequired > 0) {
        std::wstring wide(static_cast<std::size_t>(kRequired), L'\0');
        ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.c_str(), static_cast<int>(text.size()), wide.data(), kRequired);
        return wide;
    }
    std::wstring fallback;
    fallback.reserve(text.size());
    for (const unsigned char kCh : text) {
        fallback.push_back(static_cast<wchar_t>(kCh));
    }
    return fallback;
}

// formatWin32Error converts GetLastError style failures to a compact reason.
// Input is a Win32 error code; processing calls FormatMessage when possible;
// output includes the numeric code for static triage.
std::wstring formatWin32Error(const DWORD error) {
    wchar_t* message = nullptr;
    const DWORD kChars = ::FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        error,
        0,
        reinterpret_cast<LPWSTR>(&message),
        0,
        nullptr);
    std::wstring text = L"Win32=" + std::to_wstring(error);
    if (kChars > 0 && message) {
        text += L" ";
        text += message;
        while (!text.empty() && (text.back() == L'\r' || text.back() == L'\n' || text.back() == L' ' || text.back() == L'\t')) {
            text.pop_back();
        }
    }
    if (message) {
        ::LocalFree(message);
    }
    return text;
}

// formatHresult formats an HRESULT with a likely human reason. Input is an
// HRESULT from Filter Manager or WMI; output is a compact diagnostic string.
std::wstring formatHresult(const HRESULT hr) {
    std::wostringstream stream;
    stream << L"HRESULT=0x" << std::hex << std::uppercase << static_cast<unsigned long>(hr);
    if (HRESULT_FACILITY(hr) == FACILITY_WIN32) {
        stream << L" (" << formatWin32Error(HRESULT_CODE(hr)) << L")";
    }
    return stream.str();
}

// textFromWindow returns the current text of a child control. Input is an HWND;
// processing reads bounded Win32 text; output is empty if the window is absent.
std::wstring textFromWindow(HWND hwnd) {
    if (!hwnd) {
        return {};
    }
    const int kLength = ::GetWindowTextLengthW(hwnd);
    std::wstring text(static_cast<std::size_t>(kLength) + 1U, L'\0');
    if (kLength > 0) {
        ::GetWindowTextW(hwnd, text.data(), static_cast<int>(text.size()));
    }
    text.resize(static_cast<std::size_t>(kLength));
    return text;
}

// trimmedPath removes surrounding whitespace from a user supplied path. Input
// is raw edit text; processing trims only whitespace and leaves path semantics
// untouched; output may be empty.
std::wstring trimmedPath(std::wstring text) {
    while (!text.empty() && (text.back() == L' ' || text.back() == L'\t' || text.back() == L'\r' || text.back() == L'\n')) {
        text.pop_back();
    }
    std::size_t first = 0;
    while (first < text.size() && (text[first] == L' ' || text[first] == L'\t' || text[first] == L'\r' || text[first] == L'\n')) {
        ++first;
    }
    if (first > 0) {
        text.erase(0, first);
    }
    return text;
}

// buildDriverNtPath mirrors the existing FileActions path convention for R0
// read-only queries. Input is a Win32/UNC/NT path; processing normalizes slashes
// and prefixes \??\ where needed; output is empty only for empty input.
std::wstring buildDriverNtPath(const std::wstring& path) {
    std::wstring nativePath = trimmedPath(path);
    for (wchar_t& ch : nativePath) {
        if (ch == L'/') {
            ch = L'\\';
        }
    }
    if (nativePath.empty()) {
        return {};
    }
    if (nativePath.rfind(L"\\??\\", 0) == 0 || nativePath.rfind(L"\\Device\\", 0) == 0) {
        return nativePath;
    }
    if (nativePath.rfind(L"\\\\?\\", 0) == 0) {
        return L"\\??\\" + nativePath.substr(4);
    }
    if (nativePath.rfind(L"\\\\", 0) == 0) {
        return L"\\??\\UNC\\" + nativePath.substr(2);
    }
    return L"\\??\\" + nativePath;
}

// probeWin32PathForAttributes converts driver-style \??\ paths back to Win32
// form for a best-effort directory check. Input is the user target text; output
// may still be an NT path when no lossless Win32 projection exists.
std::wstring probeWin32PathForAttributes(const std::wstring& path) {
    std::wstring trimmed = trimmedPath(path);
    for (wchar_t& ch : trimmed) {
        if (ch == L'/') {
            ch = L'\\';
        }
    }
    if (trimmed.rfind(L"\\??\\UNC\\", 0) == 0) {
        return L"\\\\" + trimmed.substr(8);
    }
    if (trimmed.rfind(L"\\??\\", 0) == 0) {
        return trimmed.substr(4);
    }
    return trimmed;
}

// integrityRidFromMenu maps the popup preset to a mandatory label RID. Input is
// the command id selected from the File page menu; output false means unknown id.
bool integrityRidFromMenu(const UINT command, unsigned long& ridOut, std::wstring& labelOut) {
    switch (command) {
    case kIntegrityMenuUntrusted:
        ridOut = SECURITY_MANDATORY_UNTRUSTED_RID;
        labelOut = L"Untrusted";
        return true;
    case kIntegrityMenuLow:
        ridOut = SECURITY_MANDATORY_LOW_RID;
        labelOut = L"Low";
        return true;
    case kIntegrityMenuMedium:
        ridOut = SECURITY_MANDATORY_MEDIUM_RID;
        labelOut = L"Medium";
        return true;
    case kIntegrityMenuMediumPlus:
        ridOut = SECURITY_MANDATORY_MEDIUM_PLUS_RID;
        labelOut = L"Medium Plus";
        return true;
    case kIntegrityMenuHigh:
        ridOut = SECURITY_MANDATORY_HIGH_RID;
        labelOut = L"High";
        return true;
    case kIntegrityMenuSystem:
        ridOut = SECURITY_MANDATORY_SYSTEM_RID;
        labelOut = L"System";
        return true;
    default:
        ridOut = 0;
        labelOut.clear();
        return false;
    }
}

// ntStatusText formats signed NTSTATUS values from R0 responses. Input is the
// status value; output is an uppercase hex string for stable troubleshooting.
std::wstring ntStatusText(const long status) {
    std::wostringstream stream;
    stream << L"0x" << std::uppercase << std::hex << std::setw(8) << std::setfill(L'0')
           << static_cast<std::uint32_t>(status);
    return stream.str();
}

// defaultAuditTarget chooses a harmless existing target for initial display.
// There is no input; processing prefers ntdll.dll for FileObject/Section demos
// and falls back to the system drive; output is a Win32 path.
std::wstring defaultAuditTarget() {
    wchar_t windowsDir[MAX_PATH]{};
    const UINT kChars = ::GetWindowsDirectoryW(windowsDir, static_cast<UINT>(std::size(windowsDir)));
    if (kChars > 0 && kChars < std::size(windowsDir)) {
        std::wstring ntdll = std::wstring(windowsDir) + L"\\System32\\ntdll.dll";
        if (::GetFileAttributesW(ntdll.c_str()) != INVALID_FILE_ATTRIBUTES) {
            return ntdll;
        }
        std::wstring root = std::wstring(windowsDir).substr(0, 3);
        if (root.size() == 3 && root[1] == L':' && (root[2] == L'\\' || root[2] == L'/')) {
            return root;
        }
    }
    return L"C:\\";
}

// readUtf16FieldAtOffset extracts a non-NUL-terminated WCHAR field from a Filter
// Manager aggregate buffer. Inputs are the record buffer, byte count, field
// offset and byte length; output is empty when bounds are invalid.
std::wstring readUtf16FieldAtOffset(const void* buffer, const std::size_t bytes, const USHORT offset, const USHORT lengthBytes) {
    if (!buffer || lengthBytes == 0U || offset >= bytes || static_cast<std::size_t>(offset) + lengthBytes > bytes) {
        return {};
    }
    const auto* base = static_cast<const unsigned char*>(buffer);
    const auto* text = reinterpret_cast<const wchar_t*>(base + offset);
    return std::wstring(text, text + (lengthBytes / sizeof(wchar_t)));
}

// fieldPresentText renders whether a shared protocol field flag is set. Inputs
// are the response flags and one mask; output states whether the R0 protocol
// populated that field in this query.
std::wstring fieldPresentText(const std::uint32_t flags, const std::uint32_t mask) {
    return (flags & mask) ? L"present" : L"unavailable";
}

// fileInfoStatusText converts KSWORD_ARK_FILE_INFO_STATUS_* into UI text. Input
// is the shared status enum; output is a stable label with degradation meaning.
const wchar_t* fileInfoStatusText(const std::uint32_t value) {
    switch (value) {
    case KSWORD_ARK_FILE_INFO_STATUS_OK: return L"OK";
    case KSWORD_ARK_FILE_INFO_STATUS_PARTIAL: return L"Partial";
    case KSWORD_ARK_FILE_INFO_STATUS_OPEN_FAILED: return L"OpenFailed";
    case KSWORD_ARK_FILE_INFO_STATUS_BASIC_FAILED: return L"BasicFailed";
    case KSWORD_ARK_FILE_INFO_STATUS_STANDARD_FAILED: return L"StandardFailed";
    case KSWORD_ARK_FILE_INFO_STATUS_OBJECT_FAILED: return L"ObjectFailed";
    case KSWORD_ARK_FILE_INFO_STATUS_NAME_FAILED: return L"NameFailed";
    default: return L"Unavailable";
    }
}

// fileSectionStatusText converts KSWORD_ARK_FILE_SECTION_QUERY_STATUS_* into UI
// text. Input is the shared status enum; output is a stable label.
const wchar_t* fileSectionStatusText(const std::uint32_t value) {
    switch (value) {
    case KSWORD_ARK_FILE_SECTION_QUERY_STATUS_OK: return L"OK";
    case KSWORD_ARK_FILE_SECTION_QUERY_STATUS_PARTIAL: return L"Partial";
    case KSWORD_ARK_FILE_SECTION_QUERY_STATUS_DYNDATA_MISSING: return L"DynDataMissing";
    case KSWORD_ARK_FILE_SECTION_QUERY_STATUS_FILE_OPEN_FAILED: return L"FileOpenFailed";
    case KSWORD_ARK_FILE_SECTION_QUERY_STATUS_FILE_OBJECT_FAILED: return L"FileObjectFailed";
    case KSWORD_ARK_FILE_SECTION_QUERY_STATUS_SECTION_POINTERS_MISSING: return L"SectionPointersMissing";
    case KSWORD_ARK_FILE_SECTION_QUERY_STATUS_CONTROL_AREA_MISSING: return L"ControlAreaMissing";
    case KSWORD_ARK_FILE_SECTION_QUERY_STATUS_MAPPING_QUERY_FAILED: return L"MappingQueryFailed";
    case KSWORD_ARK_FILE_SECTION_QUERY_STATUS_BUFFER_TOO_SMALL: return L"BufferTooSmall";
    default: return L"Unavailable";
    }
}

// sectionKindText converts the file-section kind enum to display text. Input is
// KSWORD_ARK_FILE_SECTION_KIND_*; output is Data/Image/Unknown.
const wchar_t* sectionKindText(const std::uint32_t value) {
    switch (value) {
    case KSWORD_ARK_FILE_SECTION_KIND_DATA: return L"Data";
    case KSWORD_ARK_FILE_SECTION_KIND_IMAGE: return L"Image";
    default: return L"Unknown";
    }
}

// viewMapTypeText converts a mapped-view source enum to display text. Input is
// KSWORD_ARK_SECTION_MAP_TYPE_*; output is used in ControlArea rows.
const wchar_t* viewMapTypeText(const std::uint32_t value) {
    switch (value) {
    case KSWORD_ARK_SECTION_MAP_TYPE_PROCESS: return L"Process";
    case KSWORD_ARK_SECTION_MAP_TYPE_SESSION: return L"Session";
    case KSWORD_ARK_SECTION_MAP_TYPE_SYSTEM_CACHE: return L"SystemCache";
    default: return L"Unknown";
    }
}

// fltFilesystemText converts FLT_FILESYSTEM_TYPE into a concise name. Input is
// a Filter Manager file-system enum; output is a label or numeric fallback.
std::wstring fltFilesystemText(const FLT_FILESYSTEM_TYPE type) {
    switch (type) {
    case FLT_FSTYPE_UNKNOWN: return L"Unknown";
    case FLT_FSTYPE_RAW: return L"RAW";
    case FLT_FSTYPE_NTFS: return L"NTFS";
    case FLT_FSTYPE_FAT: return L"FAT";
    case FLT_FSTYPE_CDFS: return L"CDFS";
    case FLT_FSTYPE_UDFS: return L"UDFS";
    case FLT_FSTYPE_LANMAN: return L"LANMAN";
    case FLT_FSTYPE_WEBDAV: return L"WebDAV";
    case FLT_FSTYPE_RDPDR: return L"RDPDR";
    case FLT_FSTYPE_NFS: return L"NFS";
    case FLT_FSTYPE_EXFAT: return L"exFAT";
    case FLT_FSTYPE_REFS: return L"ReFS";
    case FLT_FSTYPE_CSVFS: return L"CSVFS";
    case FLT_FSTYPE_CIMFS: return L"CIMFS";
    default: return L"Type=" + std::to_wstring(static_cast<int>(type));
    }
}


// AddRow appends one evidence row. Inputs are the row fields; processing only
// stores display text in the vector; no value is returned.
void addRow(std::vector<AuditRow>& rows,
    std::wstring item,
    std::wstring source,
    std::wstring status,
    std::wstring value,
    std::wstring detail,
    const std::uint32_t relatedProcessId = 0) {
    rows.push_back({
        std::move(item), std::move(source), std::move(status), std::move(value), std::move(detail), relatedProcessId
    });
}

// appendMinifilterRecord parses one FilterFind* aggregate record. Inputs are the
// Filter Manager buffer and byte count; processing extracts only public fields;
// no kernel filter state is modified.
void appendMinifilterRecord(std::vector<AuditRow>& rows, const void* buffer, const std::size_t bytes) {
    if (!buffer || bytes < sizeof(FILTER_AGGREGATE_STANDARD_INFORMATION)) {
        addRow(rows, L"Filter", L"FilterMgr API", L"数据不可用", L"<record too small>", L"FilterAggregateStandardInformation 缓冲区过小。");
        return;
    }
    const auto* record = static_cast<const FILTER_AGGREGATE_STANDARD_INFORMATION*>(buffer);
    const bool kMinifilter = (record->Flags & FLTFL_ASI_IS_MINIFILTER) != 0;
    const std::wstring kName = kMinifilter
        ? readUtf16FieldAtOffset(buffer, bytes, record->Type.MiniFilter.FilterNameBufferOffset, record->Type.MiniFilter.FilterNameLength)
        : readUtf16FieldAtOffset(buffer, bytes, record->Type.LegacyFilter.FilterNameBufferOffset, record->Type.LegacyFilter.FilterNameLength);
    const std::wstring kAltitude = kMinifilter
        ? readUtf16FieldAtOffset(buffer, bytes, record->Type.MiniFilter.FilterAltitudeBufferOffset, record->Type.MiniFilter.FilterAltitudeLength)
        : readUtf16FieldAtOffset(buffer, bytes, record->Type.LegacyFilter.FilterAltitudeBufferOffset, record->Type.LegacyFilter.FilterAltitudeLength);
    std::wostringstream detail;
    detail << L"Kind=" << (kMinifilter ? L"Minifilter" : L"LegacyFilter")
           << L", Flags=" << hexText(record->Flags);
    if (kMinifilter) {
        detail << L", FrameID=" << record->Type.MiniFilter.FrameID
               << L", Instances=" << record->Type.MiniFilter.NumberOfInstances;
    }
    addRow(rows, kName.empty() ? L"<unknown filter>" : kName, L"FilterFindFirst/Next", L"OK", kAltitude.empty() ? L"<altitude unavailable>" : kAltitude, detail.str());
}

// appendInstanceRecord parses one FilterInstanceFind* aggregate record. Inputs
// are the public Filter Manager record buffer; processing extracts instance,
// volume, filter and altitude fields; no detach/unload action exists here.
void appendInstanceRecord(std::vector<AuditRow>& rows, const void* buffer, const std::size_t bytes) {
    if (!buffer || bytes < sizeof(INSTANCE_AGGREGATE_STANDARD_INFORMATION)) {
        addRow(rows, L"Instance", L"FilterMgr API", L"数据不可用", L"<record too small>", L"InstanceAggregateStandardInformation 缓冲区过小。");
        return;
    }
    const auto* record = static_cast<const INSTANCE_AGGREGATE_STANDARD_INFORMATION*>(buffer);
    const bool kMinifilter = (record->Flags & FLTFL_IASI_IS_MINIFILTER) != 0;
    std::wstring instanceName;
    std::wstring altitude;
    std::wstring volumeName;
    std::wstring filterName;
    FLT_FILESYSTEM_TYPE fsType = FLT_FSTYPE_UNKNOWN;
    ULONG frameId = 0;
    ULONG flags = 0;
    if (kMinifilter) {
        instanceName = readUtf16FieldAtOffset(buffer, bytes, record->Type.MiniFilter.InstanceNameBufferOffset, record->Type.MiniFilter.InstanceNameLength);
        altitude = readUtf16FieldAtOffset(buffer, bytes, record->Type.MiniFilter.AltitudeBufferOffset, record->Type.MiniFilter.AltitudeLength);
        volumeName = readUtf16FieldAtOffset(buffer, bytes, record->Type.MiniFilter.VolumeNameBufferOffset, record->Type.MiniFilter.VolumeNameLength);
        filterName = readUtf16FieldAtOffset(buffer, bytes, record->Type.MiniFilter.FilterNameBufferOffset, record->Type.MiniFilter.FilterNameLength);
        fsType = record->Type.MiniFilter.VolumeFileSystemType;
        frameId = record->Type.MiniFilter.FrameID;
        flags = record->Type.MiniFilter.Flags;
    } else {
        altitude = readUtf16FieldAtOffset(buffer, bytes, record->Type.LegacyFilter.AltitudeBufferOffset, record->Type.LegacyFilter.AltitudeLength);
        volumeName = readUtf16FieldAtOffset(buffer, bytes, record->Type.LegacyFilter.VolumeNameBufferOffset, record->Type.LegacyFilter.VolumeNameLength);
        filterName = readUtf16FieldAtOffset(buffer, bytes, record->Type.LegacyFilter.FilterNameBufferOffset, record->Type.LegacyFilter.FilterNameLength);
        flags = record->Type.LegacyFilter.Flags;
    }
    std::wostringstream value;
    value << (altitude.empty() ? L"<altitude unavailable>" : altitude)
          << L" @ " << (volumeName.empty() ? L"<volume unavailable>" : volumeName);
    std::wostringstream detail;
    detail << L"Filter=" << (filterName.empty() ? L"<unknown>" : filterName)
           << L", Kind=" << (kMinifilter ? L"Minifilter" : L"LegacyFilter")
           << L", FrameID=" << frameId
           << L", FS=" << fltFilesystemText(fsType)
           << L", Flags=" << hexText(flags);
    addRow(rows, instanceName.empty() ? filterName : instanceName, L"FilterInstanceFindFirst/Next", L"OK", value.str(), detail.str());
}

// appendVolumeRecord parses one FilterVolumeFind* standard record. Inputs are
// the public Filter Manager record buffer; processing extracts volume name,
// frame and file-system type; output is appended table rows only.
void appendVolumeRecord(std::vector<AuditRow>& rows, const void* buffer, const std::size_t bytes) {
    if (!buffer || bytes < sizeof(FILTER_VOLUME_STANDARD_INFORMATION)) {
        addRow(rows, L"Volume", L"FilterMgr API", L"数据不可用", L"<record too small>", L"FilterVolumeStandardInformation 缓冲区过小。");
        return;
    }
    const auto* record = static_cast<const FILTER_VOLUME_STANDARD_INFORMATION*>(buffer);
    const std::wstring kVolumeName = readUtf16FieldAtOffset(buffer, bytes, static_cast<USHORT>(offsetof(FILTER_VOLUME_STANDARD_INFORMATION, FilterVolumeName)), record->FilterVolumeNameLength);
    std::wostringstream detail;
    detail << L"FrameID=" << record->FrameID
           << L", FS=" << fltFilesystemText(record->FileSystemType)
           << L", Flags=" << hexText(record->Flags);
    addRow(rows, kVolumeName.empty() ? L"<unknown volume>" : kVolumeName, L"FilterVolumeFindFirst/Next", L"OK", fltFilesystemText(record->FileSystemType), detail.str());
}

// queryMinifilterRows builds the Minifilter/Instance/Volume audit view. There
// is no target input because Filter Manager exposes global inventory; processing
// uses documented enumeration APIs only; output rows include unsupported and
// permission-denied reasons when enumeration fails.
std::vector<AuditRow> queryMinifilterRows() {
    std::vector<AuditRow> rows;
    const ksword::ark::DriverClient kClient;
    const ksword::ark::MinifilterInventoryResult kR0Inventory = kClient.queryMinifilterInventory();
    addRow(rows, L"R0 cross-view", L"ArkDriverClient::queryMinifilterInventory", kR0Inventory.io.ok ? L"OK" : (kR0Inventory.unsupported ? L"驱动不支持" : L"驱动不可用/权限不足"), std::to_wstring(kR0Inventory.returnedCount) + L"/" + std::to_wstring(kR0Inventory.totalCount), utf8ToWide(kR0Inventory.io.message));
    for (const KSWORD_ARK_MINIFILTER_INVENTORY_ENTRY& entry : kR0Inventory.entries) {
        std::wostringstream detail;
        detail << L"FilterObject=" << hexText(entry.filterObject)
               << L", VolumeObject=" << hexText(entry.volumeObject)
               << L", Instances=" << entry.instanceCount
               << L", Frame=" << entry.frameId
               << L", Flags=" << hexText(entry.fieldFlags);
        addRow(rows, entry.filterName[0] ? entry.filterName : L"<R0 unnamed filter>", L"R0 MinifilterInventory", std::to_wstring(entry.status), entry.altitude[0] ? entry.altitude : L"<altitude unavailable>", detail.str());
    }
    addRow(rows, L"安全边界", L"UI", L"只读", L"无卸载/分离/绕过", L"本页不调用 FilterUnload、FilterDetach、patch、bypass 或任意修改接口。");

    std::vector<unsigned char> buffer(16U * 1024U, 0U);
    DWORD bytesReturned = 0;
    HANDLE findHandle = nullptr;
    HRESULT hr = E_FAIL;
    for (;;) {
        hr = ::FilterFindFirst(FilterAggregateStandardInformation, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesReturned, &findHandle);
        if (SUCCEEDED(hr)) {
            break;
        }
        if (hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) || hr == HRESULT_FROM_WIN32(ERROR_MORE_DATA)) {
            buffer.resize(buffer.size() * 2U);
            continue;
        }
        addRow(rows, L"Filter list", L"FilterFindFirst", L"数据不可用", formatHresult(hr), L"可能原因：权限不足、fltMgr 不可用或系统不支持该信息类。");
        return rows;
    }

    std::vector<std::wstring> filterNames;
    const auto kCaptureFilterName = [&](const void* data, const std::size_t bytes) {
        if (!data || bytes < sizeof(FILTER_AGGREGATE_STANDARD_INFORMATION)) {
            return;
        }
        const auto* record = static_cast<const FILTER_AGGREGATE_STANDARD_INFORMATION*>(data);
        if ((record->Flags & FLTFL_ASI_IS_MINIFILTER) == 0) {
            return;
        }
        const std::wstring kName = readUtf16FieldAtOffset(data, bytes, record->Type.MiniFilter.FilterNameBufferOffset, record->Type.MiniFilter.FilterNameLength);
        if (!kName.empty()) {
            filterNames.push_back(kName);
        }
    };

    appendMinifilterRecord(rows, buffer.data(), bytesReturned);
    kCaptureFilterName(buffer.data(), bytesReturned);
    for (;;) {
        bytesReturned = 0;
        hr = ::FilterFindNext(findHandle, FilterAggregateStandardInformation, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesReturned);
        if (SUCCEEDED(hr)) {
            appendMinifilterRecord(rows, buffer.data(), bytesReturned);
            kCaptureFilterName(buffer.data(), bytesReturned);
            continue;
        }
        if (hr == HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS)) {
            break;
        }
        if (hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) || hr == HRESULT_FROM_WIN32(ERROR_MORE_DATA)) {
            buffer.resize(buffer.size() * 2U);
            continue;
        }
        addRow(rows, L"Filter list", L"FilterFindNext", L"部分数据", formatHresult(hr), L"后续 filter 枚举失败，已保留前面成功记录。");
        break;
    }
    if (findHandle) {
        ::FilterFindClose(findHandle);
    }

    for (const std::wstring& filterName : filterNames) {
        HANDLE instanceHandle = nullptr;
        bytesReturned = 0;
        hr = ::FilterInstanceFindFirst(filterName.c_str(), InstanceAggregateStandardInformation, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesReturned, &instanceHandle);
        if (FAILED(hr)) {
            if (hr != HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS)) {
                addRow(rows, filterName, L"FilterInstanceFindFirst", L"数据不可用", formatHresult(hr), L"该 filter 的 instance 信息不可用，保留 filter 基础行。");
            }
            continue;
        }
        appendInstanceRecord(rows, buffer.data(), bytesReturned);
        for (;;) {
            bytesReturned = 0;
            hr = ::FilterInstanceFindNext(instanceHandle, InstanceAggregateStandardInformation, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesReturned);
            if (SUCCEEDED(hr)) {
                appendInstanceRecord(rows, buffer.data(), bytesReturned);
                continue;
            }
            if (hr != HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS)) {
                addRow(rows, filterName, L"FilterInstanceFindNext", L"部分数据", formatHresult(hr), L"后续 instance 枚举失败，已保留前面成功记录。");
            }
            break;
        }
        ::FilterInstanceFindClose(instanceHandle);
    }

    HANDLE volumeHandle = nullptr;
    bytesReturned = 0;
    hr = ::FilterVolumeFindFirst(FilterVolumeStandardInformation, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesReturned, &volumeHandle);
    if (SUCCEEDED(hr)) {
        appendVolumeRecord(rows, buffer.data(), bytesReturned);
        for (;;) {
            bytesReturned = 0;
            hr = ::FilterVolumeFindNext(volumeHandle, FilterVolumeStandardInformation, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesReturned);
            if (SUCCEEDED(hr)) {
                appendVolumeRecord(rows, buffer.data(), bytesReturned);
                continue;
            }
            if (hr != HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS)) {
                addRow(rows, L"Volume list", L"FilterVolumeFindNext", L"部分数据", formatHresult(hr), L"后续 volume 枚举失败，已保留前面成功记录。");
            }
            break;
        }
        ::FilterVolumeFindClose(volumeHandle);
    } else if (hr != HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS)) {
        addRow(rows, L"Volume list", L"FilterVolumeFindFirst", L"数据不可用", formatHresult(hr), L"可能原因：权限不足或 Filter Manager volume 信息不可用。");
    }
    return rows;
}


// queryFileObjectRows builds the FileObject audit view for one target path.
// Input is a Win32 or NT path; processing calls ArkDriverClient::queryFileInfo
// only and displays per-field availability; output rows include all failures as
// degraded evidence instead of raising UI errors.
std::vector<AuditRow> queryFileObjectRows(const std::wstring& targetPath) {
    std::vector<AuditRow> rows;
    const std::wstring kTrimmed = trimmedPath(targetPath);
    const std::wstring kNtPath = buildDriverNtPath(kTrimmed);
    addRow(rows, L"目标路径", L"UI", kTrimmed.empty() ? L"数据不可用" : L"OK", kTrimmed.empty() ? L"<empty>" : kTrimmed, L"可输入 Win32、UNC、\\??\\ 或 \\Device\\ 路径。");
    addRow(rows, L"NT 路径", L"PathAdapter", kNtPath.empty() ? L"数据不可用" : L"OK", kNtPath.empty() ? L"<empty>" : kNtPath, L"仅用于 R0 只读查询，不作为后续修改凭据。");
    if (kNtPath.empty()) {
        addRow(rows, L"FileObject", L"ArkDriverClient", L"数据不可用", L"<empty path>", L"请输入一个文件或目录路径后刷新。");
        return rows;
    }

    const ksword::ark::DriverClient kClient;
    const ksword::ark::FileInfoQueryResult kQuery = kClient.queryFileInfo(kNtPath, KSWORD_ARK_QUERY_FILE_INFO_FLAG_INCLUDE_ALL);
    const std::wstring kIoMessage = utf8ToWide(kQuery.io.message);
    addRow(rows, L"IOCTL_KSWORD_ARK_QUERY_FILE_INFO", L"ArkDriverClient", kQuery.io.ok ? L"OK" : L"驱动不支持/权限不足", kQuery.io.ok ? L"DeviceIoControl OK" : L"DeviceIoControl failed", kIoMessage);
    addRow(rows, L"QueryStatus", L"R0 FileInfo", fileInfoStatusText(kQuery.queryStatus), std::to_wstring(kQuery.queryStatus), L"open/basic/standard/object/name 均以独立状态返回，失败不会毒化整页。");
    addRow(rows, L"FieldFlags", L"R0 FileInfo", kQuery.fieldFlags ? L"OK" : L"数据不可用", hexText(kQuery.fieldFlags), L"字段 present/unavailable 依据 shared 协议位显示。");
    addRow(rows, L"OpenStatus", L"R0 FileInfo", kQuery.openStatus >= 0 ? L"OK" : L"数据不可用", hexText(static_cast<std::uint32_t>(kQuery.openStatus)), L"ZwCreateFile/ObReference 路径状态。");
    addRow(rows, L"BasicStatus", L"R0 FileInfo", kQuery.basicStatus >= 0 ? L"OK" : L"数据不可用", hexText(static_cast<std::uint32_t>(kQuery.basicStatus)), L"FileBasicInformation 状态。");
    addRow(rows, L"StandardStatus", L"R0 FileInfo", kQuery.standardStatus >= 0 ? L"OK" : L"数据不可用", hexText(static_cast<std::uint32_t>(kQuery.standardStatus)), L"FileStandardInformation 状态。");
    addRow(rows, L"ObjectStatus", L"R0 FileInfo", kQuery.objectStatus >= 0 ? L"OK" : L"数据不可用", hexText(static_cast<std::uint32_t>(kQuery.objectStatus)), L"FileObject/SectionObjectPointers 安全读取状态。");
    addRow(rows, L"NameStatus", L"R0 FileInfo", kQuery.nameStatus >= 0 ? L"OK" : L"数据不可用", hexText(static_cast<std::uint32_t>(kQuery.nameStatus)), L"ObQueryNameString 状态。");
    addRow(rows, L"FileObject", L"R0 FileInfo", fieldPresentText(kQuery.fieldFlags, KSWORD_ARK_FILE_INFO_FIELD_FILE_OBJECT_PRESENT), hexText(kQuery.fileObjectAddress), L"诊断地址，仅展示，不作为 UI 动作输入。");
    addRow(rows, L"SectionObjectPointers", L"R0 FileInfo", fieldPresentText(kQuery.fieldFlags, KSWORD_ARK_FILE_INFO_FIELD_SECTION_POINTERS_PRESENT), hexText(kQuery.sectionObjectPointersAddress), L"_FILE_OBJECT.SectionObjectPointer 诊断地址。");
    addRow(rows, L"DataSectionObject", L"R0 FileInfo", fieldPresentText(kQuery.fieldFlags, KSWORD_ARK_FILE_INFO_FIELD_DATA_SECTION_PRESENT), hexText(kQuery.dataSectionObjectAddress), L"数据段 SectionObject，可能为空。");
    addRow(rows, L"ImageSectionObject", L"R0 FileInfo", fieldPresentText(kQuery.fieldFlags, KSWORD_ARK_FILE_INFO_FIELD_IMAGE_SECTION_PRESENT), hexText(kQuery.imageSectionObjectAddress), L"映像段 SectionObject，非映像文件通常为空。");
    addRow(rows, L"ObjectName", L"R0 FileInfo", kQuery.objectName.empty() ? L"数据不可用" : L"OK", kQuery.objectName.empty() ? L"<empty>" : kQuery.objectName, L"R0 对象名安全读取结果。");
    addRow(rows, L"NtPathEcho", L"R0 FileInfo", kQuery.ntPath.empty() ? L"数据不可用" : L"OK", kQuery.ntPath.empty() ? L"<empty>" : kQuery.ntPath, L"驱动回显路径。");
    addRow(rows, L"Attributes", L"R0 FileInfo", fieldPresentText(kQuery.fieldFlags, KSWORD_ARK_FILE_INFO_FIELD_BASIC_PRESENT), hexText(kQuery.fileAttributes), L"FILE_ATTRIBUTE_*。");
    addRow(rows, L"EndOfFile", L"R0 FileInfo", fieldPresentText(kQuery.fieldFlags, KSWORD_ARK_FILE_INFO_FIELD_STANDARD_PRESENT), std::to_wstring(kQuery.endOfFile), L"逻辑文件大小。");
    addRow(rows, L"AllocationSize", L"R0 FileInfo", fieldPresentText(kQuery.fieldFlags, KSWORD_ARK_FILE_INFO_FIELD_STANDARD_PRESENT), std::to_wstring(kQuery.allocationSize), L"分配大小。");
    addRow(rows, L"CreationTime", L"R0 FileInfo", fieldPresentText(kQuery.fieldFlags, KSWORD_ARK_FILE_INFO_FIELD_BASIC_PRESENT), fileTimeToText(kQuery.creationTime), L"FILETIME 本地化显示。");
    addRow(rows, L"LastWriteTime", L"R0 FileInfo", fieldPresentText(kQuery.fieldFlags, KSWORD_ARK_FILE_INFO_FIELD_BASIC_PRESENT), fileTimeToText(kQuery.lastWriteTime), L"FILETIME 本地化显示。");
    const ksword::ark::ImageSignatureQueryResult kSignature = kClient.queryImageSignature(kNtPath);
    const std::wstring kSignatureEvidence = utf8ToWide(ksword::ark::formatImageSignatureEvidence(kSignature));
    addRow(rows,
        L"IOCTL_KSWORD_ARK_QUERY_IMAGE_SIGNATURE",
        L"ArkDriverClient",
        kSignature.io.ok ? L"OK" : (kSignature.unsupported ? L"驱动不支持" : L"驱动不支持/权限不足"),
        kSignature.io.ok ? L"R0 image signature evidence" : L"Image signature query failed",
        utf8ToWide(kSignature.io.message));
    addRow(rows,
        L"ImageSignatureEvidence",
        L"R0 Image Signature",
        kSignature.io.ok ? L"OK" : L"不可用",
        kNtPath,
        kSignatureEvidence.empty() ? utf8ToWide(kSignature.io.message) : kSignatureEvidence);
    addRow(rows, L"降级说明", L"UI", kQuery.io.ok ? L"OK" : L"驱动不支持/权限不足", kQuery.io.ok ? L"R0 FileInfo 可用" : L"R0 FileInfo 不可用", L"若旧驱动未注册 IOCTL 或服务未加载，本页保留路径和错误原因，不执行 fallback 写操作。");
    return rows;
}

// querySectionRows builds the Section/ControlArea audit view for one target
// file. Input is a path; processing calls ArkDriverClient::queryFileSectionMappings;
// output rows show data/image ControlArea and bounded mapping entries.
std::vector<AuditRow> querySectionRows(const std::wstring& targetPath) {
    std::vector<AuditRow> rows;
    const std::wstring kTrimmed = trimmedPath(targetPath);
    const std::wstring kNtPath = buildDriverNtPath(kTrimmed);
    addRow(rows, L"目标路径", L"UI", kTrimmed.empty() ? L"数据不可用" : L"OK", kTrimmed.empty() ? L"<empty>" : kTrimmed, L"Section 查询只读打开文件并返回诊断字段。");
    if (kNtPath.empty()) {
        addRow(rows, L"ControlArea", L"ArkDriverClient", L"数据不可用", L"<empty path>", L"请输入一个普通文件路径后刷新。");
        return rows;
    }

    const ksword::ark::DriverClient kClient;
    const ksword::ark::FileSectionMappingsQueryResult kQuery = kClient.queryFileSectionMappings(
        kNtPath,
        KSWORD_ARK_FILE_SECTION_QUERY_FLAG_INCLUDE_ALL,
        kAuditMaxSectionMappings);
    addRow(rows, L"IOCTL_KSWORD_ARK_QUERY_FILE_SECTION_MAPPINGS", L"ArkDriverClient", kQuery.io.ok ? L"OK" : L"驱动不支持/权限不足", kQuery.io.ok ? L"DeviceIoControl OK" : L"DeviceIoControl failed", utf8ToWide(kQuery.io.message));
    addRow(rows, L"QueryStatus", L"R0 Section", fileSectionStatusText(kQuery.queryStatus), std::to_wstring(kQuery.queryStatus), L"DynData/profile 缺失会显示为降级，不导致 UI 失败。");
    addRow(rows, L"FieldFlags", L"R0 Section", kQuery.fieldFlags ? L"OK" : L"数据不可用", hexText(kQuery.fieldFlags), L"KSWORD_ARK_FILE_SECTION_FIELD_*。");
    addRow(rows, L"LastStatus", L"R0 Section", kQuery.lastStatus >= 0 ? L"OK" : L"部分数据", hexText(static_cast<std::uint32_t>(kQuery.lastStatus)), L"最近一次 NTSTATUS。");
    addRow(rows, L"FileObject", L"R0 Section", fieldPresentText(kQuery.fieldFlags, KSWORD_ARK_FILE_SECTION_FIELD_FILE_OBJECT_PRESENT), hexText(kQuery.fileObjectAddress), L"诊断地址，仅展示。");
    addRow(rows, L"SectionObjectPointers", L"R0 Section", fieldPresentText(kQuery.fieldFlags, KSWORD_ARK_FILE_SECTION_FIELD_SECTION_POINTERS_PRESENT), hexText(kQuery.sectionObjectPointersAddress), L"_SECTION_OBJECT_POINTERS 地址。");
    addRow(rows, L"DataControlArea", L"R0 Section", fieldPresentText(kQuery.fieldFlags, KSWORD_ARK_FILE_SECTION_FIELD_DATA_CONTROL_AREA_PRESENT), hexText(kQuery.dataControlAreaAddress), L"数据映射 ControlArea。");
    addRow(rows, L"ImageControlArea", L"R0 Section", fieldPresentText(kQuery.fieldFlags, KSWORD_ARK_FILE_SECTION_FIELD_IMAGE_CONTROL_AREA_PRESENT), hexText(kQuery.imageControlAreaAddress), L"映像映射 ControlArea。");
    addRow(rows, L"Mappings", L"R0 Section", kQuery.mappings.empty() ? L"数据不可用" : L"OK", std::to_wstring(kQuery.returnedCount) + L"/" + std::to_wstring(kQuery.totalCount), L"最多请求 256 行，R0 仍有硬上限和截断标记。");
    if ((kQuery.fieldFlags & KSWORD_ARK_FILE_SECTION_FIELD_MAPPING_TRUNCATED) != 0U) {
        addRow(rows, L"MappingTruncated", L"R0 Section", L"部分数据", L"true", L"R0 返回截断标记，表格仅展示已返回行。");
    }
    const std::size_t kLimit = std::min<std::size_t>(kQuery.mappings.size(), 96U);
    for (std::size_t index = 0; index < kLimit; ++index) {
        const ksword::ark::FileSectionMappingEntry& row = kQuery.mappings[index];
        std::wostringstream item;
        item << L"Mapping #" << (index + 1U) << L" PID=" << row.processId;
        std::wostringstream value;
        value << sectionKindText(row.sectionKind) << L" " << viewMapTypeText(row.viewMapType);
        std::wostringstream detail;
        detail << L"VA=" << hexText(row.startVa) << L"-" << hexText(row.endVa)
               << L", ControlArea=" << hexText(row.controlAreaAddress);
        const std::uint32_t kMappedProcessId =
            row.viewMapType == KSWORD_ARK_SECTION_MAP_TYPE_PROCESS ? row.processId : 0U;
        addRow(rows, item.str(), L"R0 VAD/ControlArea", L"OK", value.str(), detail.str(), kMappedProcessId);
    }
    if (kQuery.mappings.size() > kLimit) {
        addRow(rows, L"Mapping display cap", L"UI", L"部分数据", std::to_wstring(kLimit) + L"/" + std::to_wstring(kQuery.mappings.size()), L"UI 限制展示 96 行，避免轻量页卡顿；R0 returnedCount 保留真实数量。");
    }
    addRow(rows, L"安全边界", L"UI", L"只读", L"无解除映射/关闭句柄", L"本页不接受任意 ControlArea 地址作为操作输入，不解除 VAD、不修改 Section。");
    return rows;
}


// volumeRootFromPath resolves a path to a Win32 volume root. Input is a file,
// directory, drive or empty string; processing uses GetVolumePathName and safe
// fallbacks; output may be empty when Windows cannot map the path.
std::wstring volumeRootFromPath(const std::wstring& targetPath) {
    std::wstring path = trimmedPath(targetPath);
    if (path.empty()) {
        path = defaultAuditTarget();
    }
    wchar_t volumeRoot[MAX_PATH]{};
    if (::GetVolumePathNameW(path.c_str(), volumeRoot, static_cast<DWORD>(std::size(volumeRoot)))) {
        return volumeRoot;
    }
    if (path.size() >= 2 && path[1] == L':') {
        std::wstring root = path.substr(0, 2) + L"\\";
        return root;
    }
    return {};
}

// queryVolumeGuid resolves a volume root to its stable Volume GUID path. Input
// is a root such as C:\; processing calls GetVolumeNameForVolumeMountPoint;
// output is empty when the mapping is unavailable.
std::wstring queryVolumeGuid(const std::wstring& volumeRoot, DWORD* errorOut = nullptr) {
    wchar_t guid[128]{};
    if (::GetVolumeNameForVolumeMountPointW(volumeRoot.c_str(), guid, static_cast<DWORD>(std::size(guid)))) {
        if (errorOut) {
            *errorOut = ERROR_SUCCESS;
        }
        return guid;
    }
    if (errorOut) {
        *errorOut = ::GetLastError();
    }
    return {};
}

// queryDosDeviceForVolume resolves C: to a \Device\HarddiskVolume* path. Input
// is a volume root; output is empty with an optional error when unavailable.
std::wstring queryDosDeviceForVolume(const std::wstring& volumeRoot, DWORD* errorOut = nullptr) {
    if (volumeRoot.size() < 2 || volumeRoot[1] != L':') {
        if (errorOut) {
            *errorOut = ERROR_INVALID_PARAMETER;
        }
        return {};
    }
    wchar_t device[1024]{};
    wchar_t driveName[3] = { volumeRoot[0], L':', L'\0' };
    const DWORD kChars = ::QueryDosDeviceW(driveName, device, static_cast<DWORD>(std::size(device)));
    if (kChars > 0) {
        if (errorOut) {
            *errorOut = ERROR_SUCCESS;
        }
        return device;
    }
    if (errorOut) {
        *errorOut = ::GetLastError();
    }
    return {};
}

// queryMountPoints returns drive-letter and mount-point names for a Volume GUID.
// Input is a Volume GUID path; processing calls documented Win32 APIs only;
// output is a semicolon separated list or a degradation reason.
std::wstring queryMountPoints(const std::wstring& volumeGuid) {
    if (volumeGuid.empty()) {
        return L"<Volume GUID unavailable>";
    }
    DWORD needed = 0;
    ::GetVolumePathNamesForVolumeNameW(volumeGuid.c_str(), nullptr, 0, &needed);
    if (needed == 0) {
        return L"<no mount points or query unsupported>";
    }
    std::vector<wchar_t> buffer(static_cast<std::size_t>(needed) + 2U, L'\0');
    if (!::GetVolumePathNamesForVolumeNameW(volumeGuid.c_str(), buffer.data(), static_cast<DWORD>(buffer.size()), &needed)) {
        return L"查询失败: " + formatWin32Error(::GetLastError());
    }
    std::wstring result;
    const wchar_t* current = buffer.data();
    while (*current) {
        if (!result.empty()) {
            result += L"; ";
        }
        result += current;
        current += std::wcslen(current) + 1U;
    }
    return result.empty() ? L"<no mount points>" : result;
}

// QueryVolumeInfoRows appends Win32 volume metadata. Inputs are a volume root and
// output row vector; processing uses GetVolumeInformation and related read-only
// APIs; no handles or volume state are changed.
void appendVolumeInfoRows(std::vector<AuditRow>& rows, const std::wstring& volumeRoot) {
    wchar_t label[MAX_PATH]{};
    wchar_t fsName[MAX_PATH]{};
    DWORD serial = 0;
    DWORD maxComponent = 0;
    DWORD flags = 0;
    if (::GetVolumeInformationW(volumeRoot.c_str(), label, static_cast<DWORD>(std::size(label)), &serial, &maxComponent, &flags, fsName, static_cast<DWORD>(std::size(fsName)))) {
        addRow(rows, L"FileSystem", L"GetVolumeInformation", L"OK", fsName[0] ? fsName : L"<empty>", L"Volume label=" + std::wstring(label) + L", Serial=" + hexText(serial) + L", Flags=" + hexText(flags));
    } else {
        addRow(rows, L"FileSystem", L"GetVolumeInformation", L"数据不可用", formatWin32Error(::GetLastError()), L"可能是权限不足、卷离线、网络路径或非本地卷。");
    }
    ULARGE_INTEGER freeBytesAvailable{};
    ULARGE_INTEGER totalBytes{};
    ULARGE_INTEGER totalFree{};
    if (::GetDiskFreeSpaceExW(volumeRoot.c_str(), &freeBytesAvailable, &totalBytes, &totalFree)) {
        addRow(rows, L"Capacity", L"GetDiskFreeSpaceEx", L"OK", std::to_wstring(totalBytes.QuadPart), L"Free=" + std::to_wstring(totalFree.QuadPart) + L", CallerFree=" + std::to_wstring(freeBytesAvailable.QuadPart));
    } else {
        addRow(rows, L"Capacity", L"GetDiskFreeSpaceEx", L"数据不可用", formatWin32Error(::GetLastError()), L"容量信息不可用。");
    }
}

// queryStorageRows builds the Storage/Volume/MountMgr read-only view. Input is
// the current target path; processing uses ArkDriverClient storage wrappers plus
// documented R3 APIs for cross-view context; output rows are suitable for the
// shared audit grid.
std::vector<AuditRow> queryStorageRows(const std::wstring& targetPath) {
    std::vector<AuditRow> rows;
    const ksword::ark::DriverClient kClient;
    const ksword::ark::StorageVolumeStackAuditResult kR0Stack = kClient.queryVolumeStackAudit();
    addRow(rows, L"R0 VolumeStack", L"ArkDriverClient::queryVolumeStackAudit", kR0Stack.io.ok ? L"OK" : (kR0Stack.unsupported ? L"驱动不支持" : L"驱动不可用/权限不足"), std::to_wstring(kR0Stack.returnedCount) + L"/" + std::to_wstring(kR0Stack.totalCount), utf8ToWide(kR0Stack.io.message));
    for (const KSWORD_ARK_VOLUME_STACK_ROW& row : kR0Stack.rows) {
        std::wostringstream detail;
        detail << L"Device=" << hexText(row.deviceObjectAddress)
               << L", Driver=" << hexText(row.driverObjectAddress)
               << L", Attached=" << hexText(row.attachedDeviceAddress)
               << L", Risk=" << hexText(row.riskFlags)
               << L", Confidence=" << row.confidence;
        addRow(rows, row.driverName[0] ? row.driverName : L"<R0 driver>", L"R0 VolumeStack", std::to_wstring(row.stackIndex), row.volumeDeviceName[0] ? row.volumeDeviceName : L"<volume unavailable>", detail.str());
    }
    const ksword::ark::StorageMountMgrMappingAuditResult kR0Mount = kClient.queryMountMgrMappingAudit();
    addRow(rows, L"R0 MountMgr", L"ArkDriverClient::queryMountMgrMappingAudit", kR0Mount.io.ok ? L"OK" : (kR0Mount.unsupported ? L"驱动不支持" : L"驱动不可用/权限不足"), std::to_wstring(kR0Mount.returnedCount) + L"/" + std::to_wstring(kR0Mount.totalCount), utf8ToWide(kR0Mount.io.message));
    for (const KSWORD_ARK_MOUNTMGR_MAPPING_ROW& row : kR0Mount.rows) {
        std::wostringstream detail;
        detail << L"Confidence=" << row.confidence
               << L", Risk=" << hexText(row.riskFlags)
               << L", Status=" << hexText(static_cast<std::uint32_t>(row.lastStatus));
        addRow(rows, row.driveLetter[0] ? row.driveLetter : L"<mount>", L"R0 MountMgr", L"OK", row.volumeGuid[0] ? row.volumeGuid : L"<guid unavailable>", row.ntDevicePath[0] ? std::wstring(row.ntDevicePath) + L"; " + detail.str() : detail.str());
    }
    const ksword::ark::StorageFilesystemIntegrityAuditResult kR0Fs = kClient.queryFilesystemIntegrityAudit();
    addRow(rows, L"R0 FilesystemIntegrity", L"ArkDriverClient::queryFilesystemIntegrityAudit", kR0Fs.io.ok ? L"OK" : (kR0Fs.unsupported ? L"驱动不支持" : L"驱动不可用/权限不足"), std::to_wstring(kR0Fs.returnedCount) + L"/" + std::to_wstring(kR0Fs.totalCount), utf8ToWide(kR0Fs.io.message));
    const std::wstring kVolumeRoot = volumeRootFromPath(targetPath);
    addRow(rows, L"VolumeRoot", L"GetVolumePathName", kVolumeRoot.empty() ? L"数据不可用" : L"OK", kVolumeRoot.empty() ? L"<unknown>" : kVolumeRoot, L"从目标路径推导卷根。");
    if (kVolumeRoot.empty()) {
        addRow(rows, L"Storage", L"Win32", L"数据不可用", L"<no volume root>", L"无法定位卷根，后续 MountMgr/Volume 查询降级。");
        return rows;
    }

    DWORD guidError = ERROR_SUCCESS;
    const std::wstring kVolumeGuid = queryVolumeGuid(kVolumeRoot, &guidError);
    addRow(rows, L"VolumeGuid", L"GetVolumeNameForVolumeMountPoint", kVolumeGuid.empty() ? L"数据不可用" : L"OK", kVolumeGuid.empty() ? formatWin32Error(guidError) : kVolumeGuid, L"MountMgr 公开视图中的 Volume GUID 路径。");
    DWORD deviceError = ERROR_SUCCESS;
    const std::wstring kNtDevice = queryDosDeviceForVolume(kVolumeRoot, &deviceError);
    addRow(rows, L"NtDevicePath", L"QueryDosDevice", kNtDevice.empty() ? L"数据不可用" : L"OK", kNtDevice.empty() ? formatWin32Error(deviceError) : kNtDevice, L"DOS 盘符到 NT 设备路径的公开映射。");
    addRow(rows, L"MountPoints", L"GetVolumePathNamesForVolumeName", kVolumeGuid.empty() ? L"数据不可用" : L"OK", queryMountPoints(kVolumeGuid), L"公开 MountMgr cross-view；不删除 stale mapping。");
    appendVolumeInfoRows(rows, kVolumeRoot);
    addRow(rows, L"VolumeStack", L"R3 Win32 cross-view", kR0Stack.io.ok ? L"R0 已接入" : L"数据不可用", kR0Stack.io.ok ? L"R0 volume stack wrapper available" : L"<R0 volume stack unavailable>", L"R3 Win32 cross-view 仍保留，用于和 R0 结果对照。");
    addRow(rows, L"安全边界", L"UI", L"只读", L"无卸载/解锁/绕过", L"本页不调用卸载卷、修改挂载点、BitLocker 解锁或密钥导出接口。");
    return rows;
}

// wmiPropertyToText reads one VARIANT property into a display string. Inputs are
// an IWbemClassObject and property name; processing handles common scalar types;
// output is empty when the property is absent.
std::wstring wmiPropertyToText(IWbemClassObject* object, const wchar_t* name) {
    if (!object || !name) {
        return {};
    }
    VARIANT value;
    ::VariantInit(&value);
    const HRESULT kHr = object->Get(name, 0, &value, nullptr, nullptr);
    if (FAILED(kHr)) {
        ::VariantClear(&value);
        return {};
    }
    std::wstring text;
    switch (value.vt) {
    case VT_BSTR:
        text = value.bstrVal ? value.bstrVal : L"";
        break;
    case VT_I4:
        text = std::to_wstring(value.lVal);
        break;
    case VT_UI4:
        text = std::to_wstring(value.ulVal);
        break;
    case VT_BOOL:
        text = (value.boolVal == VARIANT_TRUE) ? L"true" : L"false";
        break;
    default:
        break;
    }
    ::VariantClear(&value);
    return text;
}

// appendBitLockerWmiRows queries Win32_EncryptableVolume status labels. Input is
// a drive root such as C:\; processing uses WMI read-only SELECT and only emits
// status fields; no key protector material is requested or exported.
void appendBitLockerWmiRows(std::vector<AuditRow>& rows, const std::wstring& volumeRoot) {
    if (volumeRoot.size() < 2 || volumeRoot[1] != L':') {
        addRow(rows, L"BitLocker WMI", L"Win32_EncryptableVolume", L"数据不可用", L"<no drive letter>", L"WMI BitLocker 类按 DriveLetter 查询；无盘符卷降级。");
        return;
    }

    const HRESULT kInit = ::CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    const bool kUninit = SUCCEEDED(kInit);
    if (FAILED(kInit) && kInit != RPC_E_CHANGED_MODE) {
        addRow(rows, L"BitLocker WMI", L"CoInitializeEx", L"数据不可用", formatHresult(kInit), L"COM 初始化失败。");
        return;
    }

    IWbemLocator* locator = nullptr;
    HRESULT hr = ::CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_IWbemLocator, reinterpret_cast<void**>(&locator));
    if (FAILED(hr) || !locator) {
        addRow(rows, L"BitLocker WMI", L"CoCreateInstance", L"数据不可用", formatHresult(hr), L"无法创建 IWbemLocator。");
        if (kUninit) {
            ::CoUninitialize();
        }
        return;
    }

    IWbemServices* services = nullptr;
    BSTR namespaceName = ::SysAllocString(L"ROOT\\CIMV2\\Security\\MicrosoftVolumeEncryption");
    hr = namespaceName
        ? locator->ConnectServer(namespaceName, nullptr, nullptr, nullptr, 0, nullptr, nullptr, &services)
        : E_OUTOFMEMORY;
    if (namespaceName) {
        ::SysFreeString(namespaceName);
    }
    locator->Release();
    if (FAILED(hr) || !services) {
        addRow(rows, L"BitLocker WMI", L"ConnectServer", L"驱动不支持/权限不足", formatHresult(hr), L"命名空间不可用通常表示系统版本/权限/服务不支持。");
        if (kUninit) {
            ::CoUninitialize();
        }
        return;
    }

    hr = ::CoSetProxyBlanket(services, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
    if (FAILED(hr)) {
        addRow(rows, L"BitLocker WMI", L"CoSetProxyBlanket", L"权限不足", formatHresult(hr), L"无法设置 WMI 调用安全上下文。");
        services->Release();
        if (kUninit) {
            ::CoUninitialize();
        }
        return;
    }

    std::wstring query = L"SELECT DriveLetter,ConversionStatus,ProtectionStatus,LockStatus,EncryptionMethod FROM Win32_EncryptableVolume WHERE DriveLetter='";
    query.push_back(volumeRoot[0]);
    query += L":'";
    IEnumWbemClassObject* enumerator = nullptr;
    BSTR wql = ::SysAllocString(L"WQL");
    BSTR queryText = ::SysAllocString(query.c_str());
    hr = (wql && queryText)
        ? services->ExecQuery(wql, queryText, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &enumerator)
        : E_OUTOFMEMORY;
    if (queryText) {
        ::SysFreeString(queryText);
    }
    if (wql) {
        ::SysFreeString(wql);
    }
    services->Release();
    if (FAILED(hr) || !enumerator) {
        addRow(rows, L"BitLocker WMI", L"ExecQuery", L"数据不可用", formatHresult(hr), L"只读查询失败；未调用任何解锁或 protector 方法。");
        if (kUninit) {
            ::CoUninitialize();
        }
        return;
    }

    ULONG returned = 0;
    IWbemClassObject* object = nullptr;
    hr = enumerator->Next(2500, 1, &object, &returned);
    if (SUCCEEDED(hr) && returned == 1 && object) {
        addRow(rows, L"DriveLetter", L"Win32_EncryptableVolume", L"OK", wmiPropertyToText(object, L"DriveLetter"), L"BitLocker WMI 可见卷。");
        addRow(rows, L"ConversionStatus", L"Win32_EncryptableVolume", L"OK", wmiPropertyToText(object, L"ConversionStatus"), L"状态枚举值，UI 不推断密钥材料。");
        addRow(rows, L"ProtectionStatus", L"Win32_EncryptableVolume", L"OK", wmiPropertyToText(object, L"ProtectionStatus"), L"保护状态枚举值。");
        addRow(rows, L"LockStatus", L"Win32_EncryptableVolume", L"OK", wmiPropertyToText(object, L"LockStatus"), L"锁定状态枚举值。");
        addRow(rows, L"EncryptionMethod", L"Win32_EncryptableVolume", L"OK", wmiPropertyToText(object, L"EncryptionMethod"), L"加密方法枚举值；不导出密钥。");
        object->Release();
    } else {
        addRow(rows, L"BitLocker WMI", L"Win32_EncryptableVolume", L"数据不可用", SUCCEEDED(hr) ? L"<no row>" : formatHresult(hr), L"该卷可能未启用 BitLocker、无权限或 WMI 未返回 DriveLetter 行。");
    }
    enumerator->Release();
    if (kUninit) {
        ::CoUninitialize();
    }
}

// queryBitLockerRows builds the BitLocker status page. Input is the target path;
// processing resolves the volume and queries WMI/status-only evidence; output
// never contains key material, protector payloads or unlock actions.
std::vector<AuditRow> queryBitLockerRows(const std::wstring& targetPath) {
    std::vector<AuditRow> rows;
    const ksword::ark::DriverClient kClient;
    const ksword::ark::StorageBitlockerFveAuditResult kR0Fve = kClient.queryBitlockerFveAudit();
    addRow(rows, L"R0 FVE audit", L"ArkDriverClient::queryBitlockerFveAudit", kR0Fve.io.ok ? L"OK" : (kR0Fve.unsupported ? L"驱动不支持" : L"驱动不可用/权限不足"), std::to_wstring(kR0Fve.returnedCount) + L"/" + std::to_wstring(kR0Fve.totalCount), utf8ToWide(kR0Fve.io.message));
    for (const KSWORD_ARK_BITLOCKER_FVE_ROW& row : kR0Fve.rows) {
        std::wostringstream detail;
        detail << L"Fvevol=" << row.fvevolPresent
               << L", StackPos=" << row.fvevolStackPosition
               << L", Protection=" << row.protectionStatus
               << L", Conversion=" << row.conversionStatus
               << L", Lock=" << row.lockStatus
               << L", Confidence=" << row.confidence
               << L", Risk=" << hexText(row.riskFlags);
        addRow(rows, row.volumeDeviceName[0] ? row.volumeDeviceName : L"<R0 volume>", L"R0 BitLocker/FVE", L"OK", detail.str(), row.detail[0] ? row.detail : L"协议不返回密钥材料。");
    }
    const std::wstring kVolumeRoot = volumeRootFromPath(targetPath);
    addRow(rows, L"VolumeRoot", L"GetVolumePathName", kVolumeRoot.empty() ? L"数据不可用" : L"OK", kVolumeRoot.empty() ? L"<unknown>" : kVolumeRoot, L"BitLocker 状态按卷聚合展示。");
    appendBitLockerWmiRows(rows, kVolumeRoot);
    addRow(rows, L"安全边界", L"UI", L"只读", L"不导出密钥/不解锁/不暂停保护", L"本页只读取 WMI 状态标签，不调用 GetKeyProtectors、UnlockWith*、DisableKeyProtectors 等方法。");
    return rows;
}


// stateFromHostWindow returns the outer host state from GWLP_USERDATA. Input is
// the host HWND; output may be null during creation/destruction.
FileFeatureHostState* stateFromHostWindow(HWND hwnd) {
    return reinterpret_cast<FileFeatureHostState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

// stateFromAuditWindow returns the audit page state from GWLP_USERDATA. Input is
// the audit HWND; output may be null during creation/destruction.
FileAuditPageState* stateFromAuditWindow(HWND hwnd) {
    return reinterpret_cast<FileAuditPageState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

// setAuditStatus writes one status line for the audit page. Inputs are state and
// text; processing updates the STATIC control; there is no return value.
void setAuditStatus(FileAuditPageState& state, const std::wstring& text) {
    if (state.status) {
        ::SetWindowTextW(state.status, text.c_str());
    }
}

// showHostPages toggles the outer File browser/audit pages. Input is host state;
// processing hides inactive child HWNDs and shows the selected tab; no return.
void showHostPages(FileFeatureHostState& state) {
    if (state.browserPage) {
        ::ShowWindow(state.browserPage, state.currentTab == kBrowserTabIndex ? SW_SHOW : SW_HIDE);
    }
    if (state.auditPage) {
        ::ShowWindow(state.auditPage, state.currentTab == kAuditTabIndex ? SW_SHOW : SW_HIDE);
    }
}

// layoutHostChildren sizes the outer tab and its two child pages. Input is host
// state; processing uses the current tab display rectangle; no value is returned.
void layoutHostChildren(FileFeatureHostState& state) {
    RECT rc{};
    ::GetClientRect(state.hwnd, &rc);
    ::MoveWindow(state.tab, 0, 0, width(rc), height(rc), TRUE);
    RECT display = ksword::ui::getTabDisplayRect(state.tab);
    const int kPageW = width(display);
    const int kPageH = height(display);
    if (state.browserPage) {
        ::MoveWindow(state.browserPage, display.left, display.top, kPageW, kPageH, TRUE);
    }
    if (state.auditPage) {
        ::MoveWindow(state.auditPage, display.left, display.top, kPageW, kPageH, TRUE);
    }
    showHostPages(state);
}

// addAuditColumns creates the shared audit table columns. Input is a report
// list HWND; processing inserts five stable columns; output is true on success.
bool addAuditColumns(HWND list) {
    return ksword::ui::addListViewColumns(list, {
        { 0, 210, LVCFMT_LEFT, L"项目" },
        { 1, 190, LVCFMT_LEFT, L"数据来源" },
        { 2, 130, LVCFMT_LEFT, L"状态/降级" },
        { 3, 260, LVCFMT_LEFT, L"值" },
        { 4, 560, LVCFMT_LEFT, L"详情" },
    });
}

// queryRowsForAuditTab dispatches a read-only audit query from its immutable
// tab/target inputs. It is safe to run from AsyncSnapshotTask's worker thread.
std::vector<AuditRow> queryRowsForAuditTab(const int tab, const std::wstring& targetPath) {
    switch (tab) {
    case kAuditMinifilterTabIndex:
        return queryMinifilterRows();
    case kAuditFileObjectTabIndex:
        return queryFileObjectRows(targetPath);
    case kAuditSectionTabIndex:
        return querySectionRows(targetPath);
    case kAuditStorageTabIndex:
        return queryStorageRows(targetPath);
    case kAuditBitLockerTabIndex:
        return queryBitLockerRows(targetPath);
    default:
        break;
    }
    std::vector<AuditRow> rows;
    addRow(rows, L"Audit", L"UI", L"数据不可用", L"<unknown tab>", L"未知文件审计页索引。");
    return rows;
}

// populateAuditList writes the current row model into the ListView. Input is the
// audit page state; processing deletes old rows and inserts new text rows; no
// value is returned.
void populateAuditList(FileAuditPageState& state) {
    ksword::ui::ScopedListViewRedrawLock redrawLock(state.list);
    ksword::ui::clearListViewRows(state.list);
    for (const AuditRow& row : state.rows) {
        ksword::ui::insertListViewTextRow(state.list, { row.item, row.source, row.status, row.value, row.detail });
    }
}

// selectAuditListRowAtPoint keeps the typed row model and the native ListView
// selection aligned before a context action is evaluated. It returns the
// selected display column for copy-cell semantics.
int selectAuditListRowAtPoint(FileAuditPageState& state, POINT screenPoint, int* columnOut) {
    if (columnOut) {
        *columnOut = 0;
    }
    if (!state.list) {
        return -1;
    }

    POINT clientPoint = screenPoint;
    ::ScreenToClient(state.list, &clientPoint);
    LVHITTESTINFO hit{};
    hit.pt = clientPoint;
    const int kHitRow = ListView_SubItemHitTest(state.list, &hit);
    if (kHitRow >= 0) {
        if ((ListView_GetItemState(state.list, kHitRow, LVIS_SELECTED) & LVIS_SELECTED) == 0) {
            ListView_SetItemState(state.list, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
            ListView_SetItemState(state.list, kHitRow, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        }
        if (columnOut && hit.iSubItem >= 0) {
            *columnOut = hit.iSubItem;
        }
        return kHitRow;
    }

    return ListView_GetNextItem(state.list, -1, LVNI_SELECTED);
}

// mappedProcessIdAtAuditRow reads only the typed metadata produced from the
// existing R0 mapping response. Session/SystemCache rows and arbitrary display
// strings never become navigation inputs.
std::uint32_t mappedProcessIdAtAuditRow(const FileAuditPageState& state, const int rowIndex) {
    if (state.currentTab != kAuditSectionTabIndex || rowIndex < 0 ||
        static_cast<std::size_t>(rowIndex) >= state.rows.size()) {
        return 0U;
    }
    return state.rows[static_cast<std::size_t>(rowIndex)].relatedProcessId;
}

void openMappedProcessDetails(FileAuditPageState& state, const std::uint32_t processId) {
    if (processId == 0U) {
        setAuditStatus(state, L"状态：当前行不是可导航的进程映射。");
        return;
    }

    // The driver mapping protocol intentionally carries PID but no creation
    // time. Do not open a source-side process handle here; ProcessDetails
    // resolves the current process instance before showing its snapshot.
    ksword::core::NavigationRequest request{};
    request.target = ksword::core::NavigationTarget::kProcessDetails;
    request.entity.kind = ksword::core::EntityKind::kProcess;
    request.entity.id = processId;
    const bool kRouted = ksword::ui::requestEntityNavigation(state.hwnd, request);
    setAuditStatus(state, kRouted
        ? L"状态：已请求打开映射 PID " + std::to_wstring(processId) + L" 的进程详细信息；目标页会重新确认当前实例。"
        : L"状态：无法导航到该映射 PID 的当前进程实例。");
}

// showFileAuditContextMenu retains the shared read-only copy behavior and adds
// one typed, non-mutating cross-view action for process-backed Section rows.
void showFileAuditContextMenu(FileAuditPageState& state, POINT screenPoint) {
    int column = 0;
    const int kSelectedRow = selectAuditListRowAtPoint(state, screenPoint, &column);
    const bool kHasSelection = kSelectedRow >= 0;
    // Capture the typed PID before TrackPopupMenu enters its nested message
    // loop. A completed refresh cannot then substitute a same-index row.
    const std::uint32_t kMappedProcessId = mappedProcessIdAtAuditRow(state, kSelectedRow);
    const bool kCanOpenMappedProcess = kMappedProcessId != 0U;

    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    ::AppendMenuW(menu, MF_STRING | (kHasSelection ? 0U : MF_GRAYED), kAuditMenuCopyCell, L"复制单元格");
    ::AppendMenuW(menu, MF_STRING | (kHasSelection ? 0U : MF_GRAYED), kAuditMenuCopyRow, L"复制整行");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING, kAuditMenuCopyAll, L"复制全部 TSV");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING | (kCanOpenMappedProcess ? 0U : MF_GRAYED),
        kAuditMenuOpenMappedProcess, L"查看当前 PID 的进程详细信息");

    const UINT kCommand = ::TrackPopupMenu(
        menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y, 0, state.hwnd, nullptr);
    ::DestroyMenu(menu);

    switch (kCommand) {
    case kAuditMenuCopyCell:
        ksword::features::audit_common::copyTextToClipboard(
            state.hwnd,
            ksword::features::audit_common::getAuditTableCellText(state.list, kSelectedRow, column));
        break;
    case kAuditMenuCopyRow:
        ksword::features::audit_common::copyTextToClipboard(
            state.hwnd,
            ksword::features::audit_common::getSelectedAuditTableRowText(state.list));
        break;
    case kAuditMenuCopyAll:
        ksword::features::audit_common::copyTextToClipboard(
            state.hwnd,
            ksword::features::audit_common::buildAuditTableTsv(state.list));
        break;
    case kAuditMenuOpenMappedProcess:
        openMappedProcessDetails(state, kMappedProcessId);
        break;
    default:
        break;
    }
}

std::wstring auditTabName(const int tab) {
    switch (tab) {
    case kAuditMinifilterTabIndex: return L"Minifilter";
    case kAuditFileObjectTabIndex: return L"FileObject";
    case kAuditSectionTabIndex: return L"Section / ControlArea";
    case kAuditStorageTabIndex: return L"Storage / Volume / MountMgr";
    case kAuditBitLockerTabIndex: return L"BitLocker";
    default: return L"Audit";
    }
}

// refreshAuditRows schedules the active read-only query away from the UI
// thread. New target/tab requests replace the queued work and stale snapshots
// cannot overwrite the latest audit selection.
void refreshAuditRows(FileAuditPageState& state) {
    if (!state.refreshTask) {
        return;
    }
    const std::wstring kTarget = textFromWindow(state.targetEdit);
    const int kTab = state.currentTab;
    setAuditStatus(state, state.refreshTask->running()
        ? L"状态：审计刷新已排队，等待当前快照完成…"
        : L"状态：正在后台采集 " + auditTabName(kTab) + L" 只读审计…");
    if (state.refreshButton) {
        ::EnableWindow(state.refreshButton, FALSE);
    }
    ksword::ui::setLoadingOverlay(state.loadingOverlay, true, L"正在后台采集只读审计…");
    state.refreshTask->request(
        [kTab, kTarget]() {
            AuditRefreshSnapshot snapshot{};
            snapshot.tab = kTab;
            snapshot.targetPath = kTarget;
            snapshot.rows = queryRowsForAuditTab(kTab, kTarget);
            return snapshot;
        },
        [&state](std::uint64_t, std::optional<AuditRefreshSnapshot>&& snapshot, std::exception_ptr error) {
            if (state.refreshButton) {
                ::EnableWindow(state.refreshButton, TRUE);
            }
            ksword::ui::setLoadingOverlay(state.loadingOverlay, false);
            if (error || !snapshot.has_value()) {
                setAuditStatus(state, L"状态：审计后台任务异常结束。请检查驱动状态、权限和目标路径。");
                return;
            }
            if (snapshot->tab != state.currentTab || snapshot->targetPath != textFromWindow(state.targetEdit)) {
                return;
            }
            state.rows = std::move(snapshot->rows);
            populateAuditList(state);
            setAuditStatus(state,
                L"状态：" + auditTabName(state.currentTab) +
                L" 只读审计完成，行数=" + std::to_wstring(state.rows.size()) +
                L"。灰/黄状态表示驱动不支持、数据不可用或权限不足。");
        });
}

// applyFileIntegrityPreset mirrors Ksword5.1's ArkDriverClient file-integrity
// call. Inputs are the audit page and a mandatory-label preset; processing
// normalizes to the driver NT path, asks for explicit confirmation, calls the R0
// wrapper, and appends the operation result to the visible table.
void applyFileIntegrityPreset(FileAuditPageState& state, const unsigned long rid, const std::wstring& label) {
    const std::wstring kTarget = trimmedPath(textFromWindow(state.targetEdit));
    if (kTarget.empty()) {
        setAuditStatus(state, L"状态：文件完整性设置失败，目标路径为空。");
        return;
    }

    const std::wstring kNtPath = buildDriverNtPath(kTarget);
    std::wstring prompt = L"将通过 KswordARK R0 文件完整性协议设置 Mandatory Label。\r\n\r\n目标: ";
    prompt += kTarget;
    prompt += L"\r\n驱动路径: " + kNtPath;
    prompt += L"\r\n级别: " + label + L" (RID=" + hexText(rid) + L")";
    prompt += L"\r\n类型: 将在后台探测文件属性";
    prompt += L"\r\n\r\n该操作会修改文件/目录安全标签，是否继续？";
    if (::MessageBoxW(state.hwnd, prompt.c_str(), L"确认 R0 文件完整性设置", MB_YESNO | MB_DEFBUTTON2 | MB_ICONWARNING) != IDYES) {
        setAuditStatus(state, L"状态：用户取消文件完整性设置。");
        return;
    }
    if (!state.integrityTask) {
        setAuditStatus(state, L"状态：文件完整性后台任务不可用。");
        return;
    }
    if (state.integrityTask->running()) {
        setAuditStatus(state, L"状态：已有文件完整性设置正在后台执行。");
        return;
    }
    ::EnableWindow(state.integrityButton, FALSE);
    setAuditStatus(state, L"状态：正在后台探测目标并设置 R0 文件完整性…");
    state.integrityTask->request(
        [kTarget, kNtPath, rid, label] {
            FileIntegrityActionResult action{};
            const std::wstring kProbePath = probeWin32PathForAttributes(kTarget);
            const DWORD kAttributes = ::GetFileAttributesW(kProbePath.c_str());
            const bool kAttributesKnown = kAttributes != INVALID_FILE_ATTRIBUTES;
            const bool kIsDirectory = kAttributesKnown && (kAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            const ksword::ark::DriverClient kClient;
            const ksword::ark::FileIntegrityResult kResult = kClient.setFileIntegrity(kNtPath, kIsDirectory, rid);
            action.success = kResult.io.ok &&
                !kResult.unsupported &&
                kResult.lastStatus >= 0 &&
                kResult.status == KSWORD_ARK_FILE_INTEGRITY_STATUS_APPLIED;

            std::wostringstream value;
            value << label << L", RID=0x" << std::hex << std::uppercase << rid
                  << L", directory=" << (kIsDirectory ? 1 : 0);
            std::wostringstream detail;
            detail << utf8ToWide(kResult.io.message)
                   << L"; status=" << kResult.status
                   << L"; lastStatus=" << ntStatusText(kResult.lastStatus)
                   << L"; bytes=" << kResult.io.bytesReturned;
            if (!kAttributesKnown) {
                detail << L"; GetFileAttributesW unavailable, submitted as file";
            }
            if (kResult.unsupported) {
                detail << L"; unsupported";
            }
            action.row = {
                L"IOCTL_KSWORD_ARK_SET_FILE_INTEGRITY",
                L"ArkDriverClient::setFileIntegrity",
                action.success ? L"OK" : L"失败",
                value.str(),
                detail.str()
            };
            action.statusText = action.success
                ? L"状态：R0 文件完整性设置成功，结果已追加到表格。"
                : L"状态：R0 文件完整性设置失败，结果已追加到表格。";
            action.failureDetail = action.success ? std::wstring{} : detail.str();
            return action;
        },
        [&state](std::uint64_t, std::optional<FileIntegrityActionResult>&& result, std::exception_ptr error) {
            ::EnableWindow(state.integrityButton, TRUE);
            if (error || !result.has_value()) {
                setAuditStatus(state, L"状态：文件完整性后台任务异常结束。");
                return;
            }
            state.rows.push_back(std::move(result->row));
            populateAuditList(state);
            setAuditStatus(state, result->statusText);
            if (!result->success) {
                ::MessageBoxW(state.hwnd, result->failureDetail.c_str(), L"R0 文件完整性设置失败", MB_OK | MB_ICONINFORMATION);
            }
        });
}

// showFileIntegrityMenu displays mandatory-label presets for the current target.
// Input is page state and a screen point; processing maps the selected item to a
// RID and delegates to applyFileIntegrityPreset.
void showFileIntegrityMenu(FileAuditPageState& state, POINT screenPoint) {
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    ::AppendMenuW(menu, MF_STRING, kIntegrityMenuUntrusted, L"Untrusted (S-1-16-0)");
    ::AppendMenuW(menu, MF_STRING, kIntegrityMenuLow, L"Low (S-1-16-4096)");
    ::AppendMenuW(menu, MF_STRING, kIntegrityMenuMedium, L"Medium (S-1-16-8192)");
    ::AppendMenuW(menu, MF_STRING, kIntegrityMenuMediumPlus, L"Medium Plus (S-1-16-8448)");
    ::AppendMenuW(menu, MF_STRING, kIntegrityMenuHigh, L"High (S-1-16-12288)");
    ::AppendMenuW(menu, MF_STRING, kIntegrityMenuSystem, L"System (S-1-16-16384)");
    const UINT kCommand = ::TrackPopupMenu(
        menu,
        TPM_RETURNCMD | TPM_RIGHTBUTTON,
        screenPoint.x,
        screenPoint.y,
        0,
        state.hwnd,
        nullptr);
    ::DestroyMenu(menu);

    unsigned long rid = 0;
    std::wstring label;
    if (integrityRidFromMenu(kCommand, rid, label)) {
        applyFileIntegrityPreset(state, rid, label);
    }
}

// layoutAuditChildren sizes the audit controls. Input is audit state; processing
// uses the current client rectangle and tab display area; no value is returned.
void layoutAuditChildren(FileAuditPageState& state) {
    RECT rc{};
    ::GetClientRect(state.hwnd, &rc);
    const int kMargin = 8;
    const int kButtonW = 82;
    const int kIntegrityButtonW = 108;
    const int kTopH = 26;
    const int kStatusH = 22;
    const int kGap = 6;
    const int kEditW = std::max(160, width(rc) - kMargin * 2 - kButtonW - kIntegrityButtonW - kGap * 2);
    ::MoveWindow(state.targetEdit, kMargin, kMargin, kEditW, kTopH, TRUE);
    ::MoveWindow(state.refreshButton, kMargin + kEditW + kGap, kMargin, kButtonW, kTopH, TRUE);
    ::MoveWindow(state.integrityButton, kMargin + kEditW + kGap + kButtonW + kGap, kMargin, kIntegrityButtonW, kTopH, TRUE);

    const int kTabTop = kMargin + kTopH + kGap;
    const int kTabH = std::max(80, height(rc) - kTabTop - kStatusH - kMargin);
    ::MoveWindow(state.tab, kMargin, kTabTop, std::max(80, width(rc) - kMargin * 2), kTabH, TRUE);
    RECT display = ksword::ui::getTabDisplayRect(state.tab);
    ::MoveWindow(state.list, display.left, display.top, width(display), height(display), TRUE);
    if (state.loadingOverlay) {
        ::MoveWindow(state.loadingOverlay, display.left, display.top, width(display), height(display), TRUE);
    }
    ::MoveWindow(state.status, kMargin, kTabTop + kTabH + 2, std::max(80, width(rc) - kMargin * 2), kStatusH, TRUE);
}

// createAuditControls builds the read-only audit subpage controls. Input is an
// initialized audit state; processing creates edit/button/tabs/list/status and
// seeds the target path; output is true when required HWNDs exist.
bool createAuditControls(FileAuditPageState& state) {
    state.targetEdit = ::CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", defaultAuditTarget().c_str(), WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        0, 0, 0, 0, state.hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kAuditTargetEditId)), ::GetModuleHandleW(nullptr), nullptr);
    state.refreshButton = ksword::ui::createButton(state.hwnd, kAuditRefreshButtonId, L"刷新", 0, 0, 0, 0);
    state.integrityButton = ksword::ui::createButton(state.hwnd, kAuditIntegrityButtonId, L"设置完整性", 0, 0, 0, 0);
    state.tab = ksword::ui::createTabControl(state.hwnd, kAuditInnerTabId, 0, 0, 0, 0);
    state.list = ksword::ui::createReportListView(state.tab, kAuditListId, 0, 0, 0, 0);
    state.status = ksword::ui::createText(state.hwnd, kAuditStatusId, L"状态：等待刷新。", 0, 0, 0, 0);
    state.loadingOverlay = ksword::ui::createLoadingOverlay(state.tab, kAuditLoadingOverlayId, { 0, 0, 1, 1 });
    if (!state.targetEdit || !state.refreshButton || !state.integrityButton || !state.tab || !state.list || !state.status || !state.loadingOverlay) {
        return false;
    }
    ::SendMessageW(state.targetEdit, WM_SETFONT, reinterpret_cast<WPARAM>(ksword::ui::systemUiFont()), TRUE);
    ksword::ui::addTabPage(state.tab, kAuditMinifilterTabIndex, { L"Minifilter" });
    ksword::ui::addTabPage(state.tab, kAuditFileObjectTabIndex, { L"FileObject" });
    ksword::ui::addTabPage(state.tab, kAuditSectionTabIndex, { L"Section / ControlArea" });
    ksword::ui::addTabPage(state.tab, kAuditStorageTabIndex, { L"Storage / MountMgr" });
    ksword::ui::addTabPage(state.tab, kAuditBitLockerTabIndex, { L"BitLocker" });
    ::SendMessageW(state.tab, TCM_SETCURSEL, static_cast<WPARAM>(kAuditMinifilterTabIndex), 0);
    return addAuditColumns(state.list);
}

// registerAuditClass registers the audit page window class. There is no input;
// processing is idempotent; output is true once the class is usable.
bool registerAuditClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW wc{};
    wc.lpfnWndProc = [](HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) -> LRESULT {
        FileAuditPageState* state = stateFromAuditWindow(hwnd);
        if (msg == WM_NCCREATE) {
            const auto* create = reinterpret_cast<CREATESTRUCTW*>(lParam);
            state = create ? static_cast<FileAuditPageState*>(create->lpCreateParams) : nullptr;
            if (state) {
                state->hwnd = hwnd;
                ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
            }
        }
        switch (msg) {
        case WM_CREATE:
            if (state) {
                if (!createAuditControls(*state)) {
                    delete state;
                    ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                    return -1;
                }
                layoutAuditChildren(*state);
                state->refreshTask = std::make_unique<ksword::ui::AsyncSnapshotTask<AuditRefreshSnapshot>>(hwnd, kMsgAuditRefreshCompleted);
                state->integrityTask = std::make_unique<ksword::ui::AsyncSnapshotTask<FileIntegrityActionResult>>(hwnd, kMsgFileIntegrityCompleted);
                refreshAuditRows(*state);
            }
            return 0;
        case WM_SIZE:
            if (state) {
                layoutAuditChildren(*state);
            }
            return 0;
        case WM_COMMAND:
            if (state && LOWORD(wParam) == kAuditRefreshButtonId) {
                refreshAuditRows(*state);
                return 0;
            }
            if (state && LOWORD(wParam) == kAuditIntegrityButtonId) {
                POINT pt{};
                if (state->integrityButton) {
                    RECT rc{};
                    ::GetWindowRect(state->integrityButton, &rc);
                    pt.x = rc.left;
                    pt.y = rc.bottom;
                } else {
                    ::GetCursorPos(&pt);
                }
                showFileIntegrityMenu(*state, pt);
                return 0;
            }
            if (state && LOWORD(wParam) == kAuditTargetEditId && HIWORD(wParam) == EN_UPDATE) {
                setAuditStatus(*state, L"状态：目标路径已修改，点击刷新重新采集只读审计数据。");
                return 0;
            }
            break;
        case kMsgAuditRefreshCompleted:
            if (state && state->refreshTask && state->refreshTask->consume(hwnd, wParam, lParam)) {
                return 0;
            }
            break;
        case kMsgFileIntegrityCompleted:
            if (state && state->integrityTask && state->integrityTask->consume(hwnd, wParam, lParam)) {
                return 0;
            }
            break;
        case WM_NOTIFY:
            if (state) {
                const auto* header = reinterpret_cast<const NMHDR*>(lParam);
                if (header && header->hwndFrom == state->tab && header->code == TCN_SELCHANGE) {
                    const LRESULT kSelected = ::SendMessageW(state->tab, TCM_GETCURSEL, 0, 0);
                    if (kSelected >= 0) {
                        state->currentTab = static_cast<int>(kSelected);
                    }
                    refreshAuditRows(*state);
                    return 0;
                }
                if (header && header->hwndFrom == state->list && header->code == NM_RCLICK) {
                    POINT pt{};
                    ::GetCursorPos(&pt);
                    showFileAuditContextMenu(*state, pt);
                    return 0;
                }
            }
            break;
        case WM_CONTEXTMENU:
            if (state && reinterpret_cast<HWND>(wParam) == state->list) {
                POINT pt{ GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
                if (pt.x == -1 && pt.y == -1) {
                    RECT rc{};
                    ::GetWindowRect(state->list, &rc);
                    pt.x = rc.left + 24;
                    pt.y = rc.top + 24;
                }
                showFileAuditContextMenu(*state, pt);
                return 0;
            }
            break;
        case WM_CTLCOLORSTATIC: {
            HDC dc = reinterpret_cast<HDC>(wParam);
            ::SetBkMode(dc, TRANSPARENT);
            ::SetTextColor(dc, ksword::ui::appTheme().textColor);
            return reinterpret_cast<LRESULT>(ksword::ui::appTheme().windowBrush());
        }
        case WM_ERASEBKGND:
            return 1;
        case WM_PAINT: {
            PAINTSTRUCT ps{};
            HDC dc = ::BeginPaint(hwnd, &ps);
            RECT rc{};
            ::GetClientRect(hwnd, &rc);
            ::FillRect(dc, &rc, ksword::ui::appTheme().windowBrush());
            ::EndPaint(hwnd, &ps);
            return 0;
        }
        case WM_NCDESTROY:
            if (state && state->refreshTask) {
                state->refreshTask->cancel();
            }
            if (state && state->integrityTask) {
                state->integrityTask->cancel();
            }
            delete state;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            return 0;
        default:
            break;
        }
        return ::DefWindowProcW(hwnd, msg, wParam, lParam);
    };
    wc.hInstance = ::GetModuleHandleW(nullptr);
    wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = ksword::ui::appTheme().windowBrush();
    wc.lpszClassName = kFileAuditClass;
    if (::RegisterClassW(&wc) || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS) {
        registered = true;
    }
    return registered;
}

// createFileAuditPage creates one audit child page. Inputs are parent and bounds;
// processing allocates page state and creates the registered class; output is an
// HWND or nullptr when registration/window creation fails.
HWND createFileAuditPage(HWND parent, const RECT& bounds) {
    if (!parent || !registerAuditClass()) {
        return nullptr;
    }
    auto* state = new FileAuditPageState();
    HWND hwnd = ::CreateWindowExW(0, kFileAuditClass, L"FileAudit", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        bounds.left, bounds.top, width(bounds), height(bounds), parent, nullptr, ::GetModuleHandleW(nullptr), state);
    if (!hwnd) {
        delete state;
    }
    return hwnd;
}

// createHostControls builds the outer File feature tabs and child pages. Input
// is host state; processing creates the existing browser page plus audit page;
// output is true when both children are available.
bool createHostControls(FileFeatureHostState& state) {
    state.tab = ksword::ui::createTabControl(state.hwnd, kHostTabId, 0, 0, 0, 0);
    if (!state.tab) {
        return false;
    }
    ksword::ui::addTabPage(state.tab, kBrowserTabIndex, { L"文件浏览" });
    ksword::ui::addTabPage(state.tab, kAuditTabIndex, { L"只读审计" });
    ::SendMessageW(state.tab, TCM_SETCURSEL, static_cast<WPARAM>(kBrowserTabIndex), 0);

    RECT pageRect{};
    ::GetClientRect(state.tab, &pageRect);
    pageRect = ksword::ui::getTabDisplayRect(state.tab);
    const RECT kChildBounds{ 0, 0, std::max(1, width(pageRect)), std::max(1, height(pageRect)) };
    state.browserPage = createFileViewPage(state.tab, kChildBounds);
    state.auditPage = createFileAuditPage(state.tab, kChildBounds);
    if (!state.browserPage || !state.auditPage) {
        return false;
    }
    showHostPages(state);
    return true;
}

// registerHostClass registers the outer File feature host. There is no input;
// processing is idempotent; output reports whether createFileFeaturePage can
// instantiate the class.
bool registerHostClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW wc{};
    wc.lpfnWndProc = [](HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) -> LRESULT {
        FileFeatureHostState* state = stateFromHostWindow(hwnd);
        if (msg == WM_NCCREATE) {
            const auto* create = reinterpret_cast<CREATESTRUCTW*>(lParam);
            state = create ? static_cast<FileFeatureHostState*>(create->lpCreateParams) : nullptr;
            if (state) {
                state->hwnd = hwnd;
                ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
            }
        }
        switch (msg) {
        case WM_CREATE:
            if (state) {
                if (!createHostControls(*state)) {
                    delete state;
                    ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                    return -1;
                }
                layoutHostChildren(*state);
            }
            return 0;
        case WM_SIZE:
            if (state) {
                layoutHostChildren(*state);
            }
            return 0;
        case WM_NOTIFY:
            if (state) {
                const auto* header = reinterpret_cast<const NMHDR*>(lParam);
                if (header && header->hwndFrom == state->tab && header->code == TCN_SELCHANGE) {
                    const LRESULT kSelected = ::SendMessageW(state->tab, TCM_GETCURSEL, 0, 0);
                    if (kSelected >= 0) {
                        state->currentTab = static_cast<int>(kSelected);
                    }
                    showHostPages(*state);
                    return 0;
                }
            }
            break;
        case WM_CTLCOLORSTATIC: {
            HDC dc = reinterpret_cast<HDC>(wParam);
            ::SetBkMode(dc, TRANSPARENT);
            ::SetTextColor(dc, ksword::ui::appTheme().textColor);
            return reinterpret_cast<LRESULT>(ksword::ui::appTheme().windowBrush());
        }
        case WM_ERASEBKGND:
            return 1;
        case WM_PAINT: {
            PAINTSTRUCT ps{};
            HDC dc = ::BeginPaint(hwnd, &ps);
            RECT rc{};
            ::GetClientRect(hwnd, &rc);
            ::FillRect(dc, &rc, ksword::ui::appTheme().windowBrush());
            ::EndPaint(hwnd, &ps);
            return 0;
        }
        case WM_NCDESTROY:
            delete state;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            return 0;
        default:
            break;
        }
        return ::DefWindowProcW(hwnd, msg, wParam, lParam);
    };
    wc.hInstance = ::GetModuleHandleW(nullptr);
    wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = ksword::ui::appTheme().windowBrush();
    wc.lpszClassName = kFileHostClass;
    if (::RegisterClassW(&wc) || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS) {
        registered = true;
    }
    return registered;
}

} // namespace

HWND createFileFeaturePage(HWND parent, const RECT& bounds) {
    if (!parent || !registerHostClass()) {
        return nullptr;
    }
    auto* state = new FileFeatureHostState();
    HWND hwnd = ::CreateWindowExW(
        0,
        kFileHostClass,
        L"File",
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

bool requestFileFeatureNavigate(HWND page, const std::wstring& path) {
    FileFeatureHostState* state = stateFromHostWindow(page);
    if (!state || !state->browserPage || path.empty()) {
        return false;
    }
    state->currentTab = kBrowserTabIndex;
    ::SendMessageW(state->tab, TCM_SETCURSEL, static_cast<WPARAM>(kBrowserTabIndex), 0);
    showHostPages(*state);
    return requestFileViewNavigate(state->browserPage, path);
}

} // namespace Ksword::Features::File
