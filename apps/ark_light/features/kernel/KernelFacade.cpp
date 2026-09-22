#include "KernelFacade.h"

#include "KernelDynDataProfiles.h"
#include "KernelNativeQueries.h"
#include "../../../../shared/ark_client/ArkDriverClient.h"
#include "../../../../shared/driver/KswordArkKernelObjectIoctl.h"

#include <algorithm>
#include <memory>
#include <psapi.h>
#include <unordered_map>
#include <cstdint>
#include <cwctype>
#include <cstdlib>
#include <iomanip>
#include <cstring>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace ksword::features::kernel {
namespace {

// utf8ToWide converts ArkDriverClient's narrow diagnostic strings to UTF-16.
// Input is a UTF-8/narrow string; processing uses strict UTF-8 first and then a
// byte-wise fallback; output is safe for Win32 controls.
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

// HexText formats unsigned diagnostic values from shared driver protocols.
// Input is a 64-bit integer; output is uppercase hexadecimal UI text.
std::wstring hexText(const std::uint64_t value) {
    std::wostringstream stream;
    stream << L"0x" << std::hex << std::uppercase << value;
    return stream.str();
}

// ntStatusText formats NTSTATUS values in the same diagnostic style as the full
// KernelDock reports. Input is a signed NTSTATUS-sized value; output is an
// uppercase eight-digit hexadecimal string.
std::wstring ntStatusText(const long status) {
    std::wostringstream stream;
    stream << L"0x" << std::uppercase << std::hex << std::setw(8) << std::setfill(L'0')
           << static_cast<std::uint32_t>(status);
    return stream.str();
}

// dynDataFieldPresent mirrors the original KernelDock field validity test.
// Inputs are the R0 field flags and raw offset; processing rejects both the
// absent PRESENT bit and DynData sentinel offsets; output is true for usable
// offsets that should be displayed as available.
bool dynDataFieldPresent(const std::uint32_t flags, const std::uint32_t offset) {
    return (flags & KSW_DYN_FIELD_FLAG_PRESENT) != 0U &&
        offset != 0xFFFFFFFFU &&
        offset != 0x0000FFFFU;
}

// dynDataFieldStatusText converts one DynData field row into the original
// "Available/Missing" status text. Inputs are the R0 flags and offset; output is a
// compact Chinese label consumed by the Win32 ListView status column.
const wchar_t* dynDataFieldStatusText(const std::uint32_t flags, const std::uint32_t offset) {
    if (dynDataFieldPresent(flags, offset)) {
        return L"可用";
    }
    return (flags & KSW_DYN_FIELD_FLAG_REQUIRED) != 0U ? L"缺失(必需)" : L"缺失(可选)";
}

// moduleIdentityText mirrors the original DriverStatus/DynData single-line
// identity summary. Input is the ArkDriverClient module identity; output is a
// compact text containing class, machine, timestamp, size and base address.
std::wstring moduleIdentityText(const ksword::ark::ArkDynModuleIdentity& identity) {
    if (!identity.present) {
        return L"<未识别>";
    }
    std::wostringstream stream;
    stream << (identity.moduleName.empty() ? L"<unnamed>" : identity.moduleName)
           << L"，Class=" << identity.classId
           << L"，Machine=" << hexText(identity.machine)
           << L"，TimeDateStamp=" << hexText(identity.timeDateStamp)
           << L"，SizeOfImage=" << hexText(identity.sizeOfImage)
           << L"，Base=" << hexText(identity.imageBase);
    return stream.str();
}

// fixedAnsiText converts NUL-terminated protocol char arrays into UTF-16 text.
// Inputs are a bounded ANSI/UTF-8-ish buffer and its capacity; processing stops
// at the first NUL and uses the same UTF-8 fallback as ArkDriverClient messages;
// output is safe display text for profile, capability, and missing-item rows.
std::wstring fixedAnsiText(const char* text, const std::size_t maxBytes) {
    if (text == nullptr || maxBytes == 0U) {
        return {};
    }
    std::size_t length = 0U;
    while (length < maxBytes && text[length] != '\0') {
        ++length;
    }
    if (length == 0U) {
        return {};
    }
    return utf8ToWide(std::string(text, text + length));
}

// fixedWideText converts bounded UTF-16 protocol arrays into std::wstring.
// Inputs are a wchar_t array and its maximum element count; processing stops at
// the first NUL to avoid over-reading non-terminated driver packets; output is a
// normal string usable by ListView rows and detail panels.
std::wstring fixedWideText(const wchar_t* text, const std::size_t maxChars) {
    if (text == nullptr || maxChars == 0U) {
        return {};
    }
    std::size_t length = 0U;
    while (length < maxChars && text[length] != L'\0') {
        ++length;
    }
    return std::wstring(text, text + length);
}

// dynDataSourceName keeps DriverStatus field-source summaries aligned with the
// original sourceText helper. Input is KSW_DYN_FIELD_SOURCE_*; output is a UI
// label only.
const wchar_t* dynDataSourceName(const std::uint32_t source) {
    switch (source) {
    case KSW_DYN_FIELD_SOURCE_SYSTEM_INFORMER: return L"System Informer";
    case KSW_DYN_FIELD_SOURCE_RUNTIME_PATTERN: return L"Ksword runtime pattern";
    case KSW_DYN_FIELD_SOURCE_KSWORD_EXTRA_TABLE: return L"Ksword extra table";
    case KSW_DYN_FIELD_SOURCE_PDB_PROFILE: return L"PDB profile";
    default: return L"Unavailable";
    }
}

// DynDataFieldsSummary is the R3-side aggregate used by the Win32 DriverStatus
// page. Inputs are queryDynDataFields entries; processing counts availability,
// required gaps and source classes; output is rendered as hidden summary fields.
struct DynDataFieldsSummary {
    std::uint32_t present = 0;
    std::uint32_t returned = 0;
    std::uint32_t declared = 0;
    std::uint32_t requiredMissing = 0;
    std::uint32_t pdb = 0;
    std::uint32_t runtime = 0;
    std::uint32_t systemInformer = 0;
    std::uint32_t extra = 0;
    std::uint32_t unavailable = 0;
    bool activeProcessLinksPresent = false;
    std::uint32_t activeProcessLinksOffset = 0xFFFFFFFFU;
    std::uint32_t activeProcessLinksSource = KSW_DYN_FIELD_SOURCE_UNAVAILABLE;
};

// summarizeDynDataFields computes the same coverage/source counters shown by
// the original DriverStatus page. Inputs are fields query results; output is a
// value object with no ownership of the source query.
DynDataFieldsSummary summarizeDynDataFields(const ksword::ark::DynDataFieldsResult& fields) {
    DynDataFieldsSummary summary;
    summary.returned = fields.returnedCount;
    summary.declared = fields.totalCount;
    for (const ksword::ark::DynDataFieldEntry& entry : fields.entries) {
        const bool kPresent = dynDataFieldPresent(entry.flags, entry.offset);
        if (kPresent) {
            ++summary.present;
        }
        if (!kPresent && (entry.flags & KSW_DYN_FIELD_FLAG_REQUIRED) != 0U) {
            ++summary.requiredMissing;
        }
        switch (entry.source) {
        case KSW_DYN_FIELD_SOURCE_SYSTEM_INFORMER:
            ++summary.systemInformer;
            break;
        case KSW_DYN_FIELD_SOURCE_RUNTIME_PATTERN:
            ++summary.runtime;
            break;
        case KSW_DYN_FIELD_SOURCE_KSWORD_EXTRA_TABLE:
            ++summary.extra;
            break;
        case KSW_DYN_FIELD_SOURCE_PDB_PROFILE:
            ++summary.pdb;
            break;
        default:
            ++summary.unavailable;
            break;
        }
        if (entry.fieldName == "EpActiveProcessLinks" || entry.fieldName == "_EPROCESS.ActiveProcessLinks") {
            summary.activeProcessLinksPresent = kPresent;
            summary.activeProcessLinksOffset = entry.offset;
            summary.activeProcessLinksSource = entry.source;
        }
    }
    return summary;
}

// fieldCoverageText mirrors fieldCoverageText from the original dock. Input
// is a DynDataFieldsSummary plus optional pack coverage; output is a one-line
// coverage sentence.
std::wstring fieldCoverageText(const DynDataFieldsSummary& summary, const double coveragePercent) {
    std::wostringstream stream;
    stream << L"可用 " << summary.present
           << L" / 返回 " << summary.returned
           << L" / R0声明 " << summary.declared
           << L"，必需缺失 " << summary.requiredMissing;
    if (coveragePercent >= 0.0) {
        stream << L"，pack覆盖率 " << std::fixed << std::setprecision(1) << coveragePercent << L"%";
    }
    return stream.str();
}

// fieldSourcesText mirrors fieldSourceSummaryText from the original dock. Input is a
// field aggregate; output lists counts by source class.
std::wstring fieldSourcesText(const DynDataFieldsSummary& summary) {
    std::wostringstream stream;
    stream << L"PDB=" << summary.pdb
           << L"，RuntimePattern=" << summary.runtime
           << L"，SystemInformer=" << summary.systemInformer
           << L"，Extra=" << summary.extra
           << L"，不可用=" << summary.unavailable;
    return stream.str();
}

// localPdbProfileText mirrors localPdbProfileText in a compact form. Inputs are
// the local pack match result and field aggregate; output is used by DriverStatus
// summary/detail rows without applying the profile.
std::wstring localPdbProfileText(const DynDataProfileMatch& match) {
    if (match.matched) {
        std::wostringstream stream;
        stream << L"命中：" << utf8ToWide(match.profile.profileName)
               << L"，来源=" << match.source
               << L"，字段=" << match.fieldCount
               << L"，typedItems=" << match.typedItemCount
               << L"，callbackItems=" << match.callbackItemCount
               << L"，coverage=";
        if (match.coveragePercent >= 0.0) {
            stream << std::fixed << std::setprecision(1) << match.coveragePercent << L"%";
        } else {
            stream << L"<未知>";
        }
        stream << L"，packProfiles=" << match.profileCount
               << L"，路径=" << match.path;
        return stream.str();
    }
    return match.message.empty() ? L"未命中或未扫描。" : match.message;
}

// activeProcessLinksText mirrors activeProcessLinksOffsetText. Inputs are the
// local match and current R0 field aggregate; output highlights whether R0 has a
// usable offset and its source.
std::wstring activeProcessLinksText(const DynDataFieldsSummary& fields) {
    std::wostringstream stream;
    stream << L"LocalPack=<见本地 PDB profile>；R0="
           << (fields.activeProcessLinksPresent ? hexText(fields.activeProcessLinksOffset) : L"<未应用>")
           << L"；R0Source=" << dynDataSourceName(fields.activeProcessLinksSource);
    return stream.str();
}

// trustedOffsetText mirrors trustedOffsetText from the original driver status
// page. Inputs are status flags, local pack match and field aggregate; output is
// a human-readable trusted-offset state.
std::wstring trustedOffsetText(
    const std::uint32_t dynDataStatusFlags,
    const DynDataProfileMatch& match,
    const DynDataFieldsSummary& fields) {
    const bool kPdbActive = (dynDataStatusFlags & KSW_DYN_STATUS_FLAG_PDB_PROFILE_ACTIVE) != 0U;
    const bool kCallbackActive = (dynDataStatusFlags & KSW_DYN_STATUS_FLAG_CALLBACK_PROFILE_ACTIVE) != 0U;
    if (kPdbActive) {
        std::wostringstream stream;
        stream << L"已启用可信 PDB 偏移；PDB字段 " << fields.pdb
               << L" / 可用字段 " << fields.present
               << L"，pack=" << (match.matched ? L"命中" : L"未确认")
               << L"，callback=" << (kCallbackActive ? L"Active" : L"Inactive") << L"。";
        return stream.str();
    }
    if (match.matched) {
        return L"本地 pack 已匹配当前内核，但 R0 当前字段来源尚未切换到 PDB profile。";
    }
    if (fields.present != 0U) {
        return L"当前有可用 DynData 字段，但未发现 PDB profile 字段；来源=" + fieldSourcesText(fields) + L"。";
    }
    return L"暂无可用可信偏移。";
}

// BoolText converts protocol booleans into compact Chinese text. Input is a
// boolean-like value; output is display text only.
const wchar_t* boolText(const bool value) {
    return value ? L"是" : L"否";
}

// yesNoText is the std::wstring form used when composing result rows. Input is a
// boolean; output intentionally matches BoolText so UI summary rows can compare
// against one stable Chinese value.
std::wstring yesNoText(const bool value) {
    return value ? L"是" : L"否";
}

// SizeText formats byte counts the same way the original MemoryDock pages did.
// Inputs are raw byte counts from ArkDriverClient; processing selects GB/MB/KB/B
// units without changing the numeric source value; output is display-only text.
std::wstring sizeText(const std::uint64_t bytes) {
    std::wostringstream stream;
    if (bytes >= 1024ULL * 1024ULL * 1024ULL) {
        stream << std::fixed << std::setprecision(2)
               << (static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0))
               << L" GB";
    } else if (bytes >= 1024ULL * 1024ULL) {
        stream << std::fixed << std::setprecision(2)
               << (static_cast<double>(bytes) / (1024.0 * 1024.0))
               << L" MB";
    } else if (bytes >= 1024ULL) {
        stream << std::fixed << std::setprecision(2)
               << (static_cast<double>(bytes) / 1024.0)
               << L" KB";
    } else {
        stream << bytes << L" B";
    }
    return stream.str();
}

// processDisplayName resolves a PID to a compact executable name using only
// Win32 APIs. Input is a process id from R0 event data; processing tries
// QueryFullProcessImageNameW and falls back to System/Idle labels; output is
// display-only and does not fail the kernel query when access is denied.
std::wstring processDisplayName(const std::uint32_t processId) {
    if (processId == 0) {
        return L"Idle/System";
    }
    HANDLE process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (!process) {
        return L"PID " + std::to_wstring(processId);
    }
    std::wstring path(MAX_PATH * 4, L'\0');
    DWORD length = static_cast<DWORD>(path.size());
    std::wstring name = L"PID " + std::to_wstring(processId);
    if (::QueryFullProcessImageNameW(process, 0, path.data(), &length) && length > 0) {
        path.resize(length);
        const std::size_t kSlash = path.find_last_of(L"\\/");
        name = kSlash == std::wstring::npos ? path : path.substr(kSlash + 1);
    }
    ::CloseHandle(process);
    return name;
}

// BytesHex formats a bounded byte vector for list/detail display. Input is a
// byte buffer and max output count; processing avoids huge UI strings; output is
// uppercase hex bytes separated by spaces.
std::wstring bytesHex(const std::vector<std::uint8_t>& bytes, const std::size_t maxBytes = 32) {
    std::wostringstream stream;
    const std::size_t kLimit = std::min<std::size_t>(bytes.size(), maxBytes);
    for (std::size_t i = 0; i < kLimit; ++i) {
        if (i > 0) {
            stream << L' ';
        }
        stream << std::uppercase << std::hex << std::setw(2) << std::setfill(L'0') << static_cast<unsigned int>(bytes[i]);
    }
    if (bytes.size() > kLimit) {
        stream << L" ...";
    }
    return stream.str();
}


struct KernelModuleDiskInfo {
    std::uint64_t base = 0;
    std::wstring ntPath;
    std::wstring win32Path;
};

struct InlineDiskBaseline {
    bool available = false;
    bool differs = false;
    std::uint64_t rva = 0;
    std::uint32_t byteCount = 0;
    std::vector<std::uint8_t> bytes;
    std::wstring statusText = L"磁盘基线：未校验";
    std::wstring filePath;
};

std::wstring normalizeKernelModulePath(const std::wstring& path) {
    std::wstring result = path;
    constexpr wchar_t kNtPrefix[] = L"\\??\\";
    if (_wcsnicmp(result.c_str(), kNtPrefix, 4) == 0) {
        result.erase(0, 4);
    }
    constexpr wchar_t kSystemRootPrefix[] = L"\\SystemRoot\\";
    if (_wcsnicmp(result.c_str(), kSystemRootPrefix, 12) == 0) {
        wchar_t windowsDir[MAX_PATH]{};
        if (::GetWindowsDirectoryW(windowsDir, MAX_PATH) != 0) {
            result = std::wstring(windowsDir) + result.substr(11);
        }
    }
    constexpr wchar_t kSysrootPrefix[] = L"SystemRoot\\";
    if (_wcsnicmp(result.c_str(), kSysrootPrefix, 11) == 0) {
        wchar_t windowsDir[MAX_PATH]{};
        if (::GetWindowsDirectoryW(windowsDir, MAX_PATH) != 0) {
            result = std::wstring(windowsDir) + L"\\" + result.substr(11);
        }
    }
    return result;
}

std::unordered_map<std::uint64_t, KernelModuleDiskInfo> queryLoadedKernelModuleMap() {
    std::unordered_map<std::uint64_t, KernelModuleDiskInfo> modules;
    DWORD bytesNeeded = 0;
    ::EnumDeviceDrivers(nullptr, 0, &bytesNeeded);
    if (bytesNeeded == 0) {
        return modules;
    }
    std::vector<LPVOID> bases(bytesNeeded / sizeof(LPVOID));
    if (!::EnumDeviceDrivers(bases.data(), bytesNeeded, &bytesNeeded)) {
        return modules;
    }
    const DWORD kCount = bytesNeeded / sizeof(LPVOID);
    for (DWORD index = 0; index < kCount; ++index) {
        wchar_t path[MAX_PATH * 4]{};
        if (!::GetDeviceDriverFileNameW(bases[index], path, static_cast<DWORD>(std::size(path)))) {
            continue;
        }
        KernelModuleDiskInfo info;
        info.base = reinterpret_cast<std::uint64_t>(bases[index]);
        info.ntPath = path;
        info.win32Path = normalizeKernelModulePath(info.ntPath);
        modules[info.base] = std::move(info);
    }
    return modules;
}

bool readWholeBinaryFile(const std::wstring& path, std::vector<std::uint8_t>& bytesOut) {
    HANDLE file = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }
    LARGE_INTEGER size{};
    if (!::GetFileSizeEx(file, &size) || size.QuadPart <= 0 || size.QuadPart > 128LL * 1024LL * 1024LL) {
        ::CloseHandle(file);
        return false;
    }
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size.QuadPart));
    DWORD read = 0;
    const BOOL kOk = ::ReadFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr);
    ::CloseHandle(file);
    if (!kOk || read != bytes.size()) {
        return false;
    }
    bytesOut = std::move(bytes);
    return true;
}

bool rvaToFileOffset(const std::vector<std::uint8_t>& fileBytes, const std::uint32_t rva, const std::uint32_t bytesToRead, std::uint64_t& offsetOut) {
    if (fileBytes.size() < sizeof(IMAGE_DOS_HEADER)) {
        return false;
    }
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(fileBytes.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) {
        return false;
    }
    const std::uint64_t kNtOffset = static_cast<std::uint64_t>(dos->e_lfanew);
    if (kNtOffset + sizeof(IMAGE_NT_HEADERS64) > fileBytes.size()) {
        return false;
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(fileBytes.data() + kNtOffset);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->FileHeader.NumberOfSections == 0 || nt->FileHeader.NumberOfSections > 96) {
        return false;
    }
    const std::uint64_t kOptionalOffset = kNtOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    const std::uint64_t kSectionOffset = kOptionalOffset + nt->FileHeader.SizeOfOptionalHeader;
    const std::uint64_t kSectionBytes = static_cast<std::uint64_t>(nt->FileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
    if (kSectionOffset + kSectionBytes > fileBytes.size()) {
        return false;
    }
    if (rva + bytesToRead <= nt->OptionalHeader.SizeOfHeaders && rva + bytesToRead <= fileBytes.size()) {
        offsetOut = rva;
        return true;
    }
    const auto* sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(fileBytes.data() + kSectionOffset);
    for (std::uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        const IMAGE_SECTION_HEADER& section = sections[i];
        const std::uint32_t kMappedSize = std::max(section.Misc.VirtualSize, section.SizeOfRawData);
        if (kMappedSize == 0 || rva < section.VirtualAddress || rva >= section.VirtualAddress + kMappedSize) {
            continue;
        }
        const std::uint32_t kDelta = rva - section.VirtualAddress;
        if (kDelta + bytesToRead > section.SizeOfRawData) {
            return false;
        }
        const std::uint64_t kFileOffset = static_cast<std::uint64_t>(section.PointerToRawData) + kDelta;
        if (kFileOffset + bytesToRead > fileBytes.size()) {
            return false;
        }
        offsetOut = kFileOffset;
        return true;
    }
    return false;
}

InlineDiskBaseline readInlineDiskBaseline(
    const ksword::ark::KernelInlineHookEntry& entry,
    const std::unordered_map<std::uint64_t, KernelModuleDiskInfo>& modules,
    std::unordered_map<std::wstring, std::vector<std::uint8_t>>& fileCache) {
    InlineDiskBaseline baseline;
    const std::uint32_t kByteCount = static_cast<std::uint32_t>(std::min<std::size_t>(
        std::min<std::size_t>(entry.currentBytes.size(), entry.currentByteCount),
        KSWORD_ARK_KERNEL_HOOK_BYTES));
    baseline.byteCount = kByteCount;
    if (kByteCount == 0) {
        baseline.statusText = L"不可用：R0 未返回内存字节。";
        return baseline;
    }
    if (entry.moduleBase == 0 || entry.functionAddress < entry.moduleBase) {
        baseline.statusText = L"不可用：函数地址或模块基址无效。";
        return baseline;
    }
    const std::uint64_t kRva64 = entry.functionAddress - entry.moduleBase;
    baseline.rva = kRva64;
    if (kRva64 > 0xFFFFFFFFULL) {
        baseline.statusText = L"不可用：函数 RVA 超出 32 位 PE 范围。";
        return baseline;
    }
    const auto kModule = modules.find(entry.moduleBase);
    if (kModule == modules.end()) {
        baseline.statusText = L"不可用：R3 未能反查模块磁盘路径。";
        return baseline;
    }
    baseline.filePath = kModule->second.win32Path;
    if (baseline.filePath.empty() || ::GetFileAttributesW(baseline.filePath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        baseline.statusText = L"不可用：磁盘模块文件不存在或路径不可转换（" + kModule->second.ntPath + L"）。";
        return baseline;
    }
    auto cache = fileCache.find(baseline.filePath);
    if (cache == fileCache.end()) {
        std::vector<std::uint8_t> fileBytes;
        if (!readWholeBinaryFile(baseline.filePath, fileBytes)) {
            baseline.statusText = L"不可用：磁盘模块文件读取失败。";
            return baseline;
        }
        cache = fileCache.emplace(baseline.filePath, std::move(fileBytes)).first;
    }
    std::uint64_t fileOffset = 0;
    if (!rvaToFileOffset(cache->second, static_cast<std::uint32_t>(kRva64), kByteCount, fileOffset)) {
        baseline.statusText = L"不可用：未找到覆盖目标 RVA 的 PE 区段。";
        return baseline;
    }
    baseline.bytes.assign(cache->second.begin() + static_cast<std::ptrdiff_t>(fileOffset),
        cache->second.begin() + static_cast<std::ptrdiff_t>(fileOffset + kByteCount));
    baseline.available = true;
    baseline.differs = !std::equal(baseline.bytes.begin(), baseline.bytes.end(), entry.currentBytes.begin());
    baseline.statusText = baseline.differs ? L"不同：内存字节与磁盘基线不一致" : L"一致：内存字节与磁盘基线相同";
    return baseline;
}

// Row builds one generic result row. Inputs are any number of key/value pairs;
// processing copies them into KernelResultRow; output is display-neutral data.
KernelResultRow makeResultRow(std::initializer_list<std::pair<std::wstring, std::wstring>> columns, const std::wstring& detail = {}) {
    KernelResultRow row;
    row.columns.assign(columns.begin(), columns.end());
    row.detailText = detail;
    return row;
}

// containsI checks whether text contains a fragment ignoring case. Inputs are
// display strings; output is true for empty filters or substring matches.
bool containsI(std::wstring text, std::wstring fragment) {
    if (fragment.empty()) {
        return true;
    }
    std::transform(text.begin(), text.end(), text.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(::towlower(ch));
    });
    std::transform(fragment.begin(), fragment.end(), fragment.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(::towlower(ch));
    });
    return text.find(fragment) != std::wstring::npos;
}

// rowMatchesFilter checks a generic row against user filter text. Inputs are one
// result row and filter; output controls whether ArkDriverClient rows are shown.
bool rowMatchesFilter(const KernelResultRow& row, const std::wstring& filter) {
    if (filter.empty() || containsI(row.detailText, filter)) {
        return true;
    }
    for (const auto& column : row.columns) {
        if (containsI(column.first, filter) || containsI(column.second, filter)) {
            return true;
        }
    }
    return false;
}

// pushFilteredRow appends a row only when it matches the generic UI filter.
// Inputs are destination, row and filter; no value is returned.
void pushFilteredRow(KernelOperationResult& result, KernelResultRow row, const std::wstring& filter) {
    if (rowMatchesFilter(row, filter)) {
        result.rows.push_back(std::move(row));
    }
}

// fieldValue extracts one selected-row field from a KernelActionRequest. Inputs
// are row key/value pairs and the requested key; output is an empty string when
// the selected result row does not carry that field.
std::wstring fieldValue(const KernelActionRequest& request, const std::wstring& key) {
    for (const auto& field : request.rowFields) {
        if (_wcsicmp(field.first.c_str(), key.c_str()) == 0) {
            return field.second;
        }
    }
    return {};
}

// parseUnsigned64 accepts decimal or 0x-prefixed hexadecimal UI text. Input is a
// ListView cell value; processing rejects empty/invalid text; output is whether
// parsing consumed the complete value.
bool parseUnsigned64(const std::wstring& text, std::uint64_t& valueOut) {
    if (text.empty()) {
        return false;
    }
    wchar_t* end = nullptr;
    const int kBase = (text.size() > 2 && text[0] == L'0' && (text[1] == L'x' || text[1] == L'X')) ? 16 : 10;
    const unsigned long long kParsed = std::wcstoull(text.c_str(), &end, kBase);
    if (end == text.c_str()) {
        return false;
    }
    while (end != nullptr && *end != L'\0') {
        if (!std::iswspace(*end)) {
            return false;
        }
        ++end;
    }
    valueOut = static_cast<std::uint64_t>(kParsed);
    return true;
}

// firstFieldValue returns the first non-empty selected-row field from a preferred
// key list. Inputs are the action request and likely column names; output is
// empty only when the current row cannot provide any requested field.
std::wstring firstFieldValue(const KernelActionRequest& request, std::initializer_list<const wchar_t*> keys) {
    for (const wchar_t* key : keys) {
        const std::wstring kValue = fieldValue(request, key);
        if (!kValue.empty()) {
            return kValue;
        }
    }
    return {};
}

// mutationOperationText maps the shared mutation operation enum to readable
// labels. Input is KSWORD_ARK_MUTATION_OPERATION_*; output is static display
// text with numeric fallback handled by callers.
const wchar_t* mutationOperationText(const std::uint32_t operation) {
    switch (operation) {
    case KSWORD_ARK_MUTATION_OPERATION_PREPARE: return L"Prepare";
    case KSWORD_ARK_MUTATION_OPERATION_COMMIT: return L"Commit";
    case KSWORD_ARK_MUTATION_OPERATION_ROLLBACK: return L"Rollback";
    case KSWORD_ARK_MUTATION_OPERATION_QUERY_AUDIT: return L"QueryAudit";
    case KSWORD_ARK_MUTATION_OPERATION_UNKNOWN:
    default:
        return L"Unknown";
    }
}

// mutationStatusText maps transaction status values into user-facing labels.
// Input is KSWORD_ARK_MUTATION_STATUS_*; output is static text used by audit and
// action result rows.
const wchar_t* mutationStatusText(const std::uint32_t status) {
    switch (status) {
    case KSWORD_ARK_MUTATION_STATUS_PREPARED: return L"Prepared";
    case KSWORD_ARK_MUTATION_STATUS_DRY_RUN: return L"Dry-run";
    case KSWORD_ARK_MUTATION_STATUS_COMMITTED: return L"Committed";
    case KSWORD_ARK_MUTATION_STATUS_ROLLED_BACK: return L"Rolled back";
    case KSWORD_ARK_MUTATION_STATUS_ALREADY_AT_BEFORE: return L"Already at before";
    case KSWORD_ARK_MUTATION_STATUS_REJECTED_INVALID_REQUEST: return L"Rejected: invalid request";
    case KSWORD_ARK_MUTATION_STATUS_REJECTED_UNKNOWN_TARGET: return L"Rejected: unknown target";
    case KSWORD_ARK_MUTATION_STATUS_REJECTED_SIZE_LIMIT: return L"Rejected: size limit";
    case KSWORD_ARK_MUTATION_STATUS_REJECTED_SAFETY_POLICY: return L"Rejected: safety policy";
    case KSWORD_ARK_MUTATION_STATUS_REJECTED_BEFORE_MISMATCH: return L"Rejected: before mismatch";
    case KSWORD_ARK_MUTATION_STATUS_REJECTED_UNSUPPORTED_TARGET: return L"Rejected: unsupported target";
    case KSWORD_ARK_MUTATION_STATUS_REJECTED_PLAN_ONLY: return L"Rejected: plan only";
    case KSWORD_ARK_MUTATION_STATUS_REJECTED_NOT_FOUND: return L"Rejected: not found";
    case KSWORD_ARK_MUTATION_STATUS_REJECTED_BUSY: return L"Rejected: busy";
    case KSWORD_ARK_MUTATION_STATUS_REJECTED_TARGET_CHANGED: return L"Rejected: target changed";
    case KSWORD_ARK_MUTATION_STATUS_READ_FAILED: return L"Read failed";
    case KSWORD_ARK_MUTATION_STATUS_WRITE_FAILED: return L"Write failed";
    case KSWORD_ARK_MUTATION_STATUS_UNKNOWN:
    default:
        return L"Unknown";
    }
}

// mutationTargetText maps target-kind protocol values to readable labels. Input
// is KSWORD_ARK_MUTATION_TARGET_*; output is static display text.
const wchar_t* mutationTargetText(const std::uint32_t targetKind) {
    switch (targetKind) {
    case KSWORD_ARK_MUTATION_TARGET_KERNEL_VIRTUAL_BYTES_SMALL: return L"Kernel virtual bytes";
    case KSWORD_ARK_MUTATION_TARGET_PROCESS_PROTECTION_BYTES: return L"Process protection bytes";
    case KSWORD_ARK_MUTATION_TARGET_CALLBACK_ENTRY_UNLINK_PLAN: return L"Callback unlink plan";
    case KSWORD_ARK_MUTATION_TARGET_UNKNOWN:
    default:
        return L"Unknown";
    }
}

// appendFlagName appends one readable flag when the bit is present. Inputs are
// the output vector, mask, bit, and label; processing is local string assembly;
// no value is returned.
void appendFlagName(std::vector<std::wstring>& names, const std::uint32_t mask, const std::uint32_t bit, const wchar_t* label) {
    if ((mask & bit) != 0U) {
        names.push_back(label);
    }
}

// appendFlagName64 appends one readable flag from a 64-bit protocol mask. Inputs
// mirror appendFlagName but are used by CPUID feature masks; no value is returned.
void appendFlagName64(std::vector<std::wstring>& names, const std::uint64_t mask, const std::uint64_t bit, const wchar_t* label) {
    if ((mask & bit) != 0ULL) {
        names.push_back(label);
    }
}

// joinNames joins flag labels into a compact string. Input is a vector of labels;
// output is "None" for no flags or a comma-separated string otherwise.
std::wstring joinNames(const std::vector<std::wstring>& names) {
    if (names.empty()) {
        return L"None";
    }
    std::wstring result;
    for (const std::wstring& name : names) {
        if (!result.empty()) {
            result += L", ";
        }
        result += name;
    }
    return result;
}

// joinNamesOrNormal joins flag labels but uses the original KswordARK wording
// for a clean row. Input is a vector of risk/anomaly labels; output is "Normal"
// when no labels are present, otherwise a compact pipe-separated list.
std::wstring joinNamesOrNormal(const std::vector<std::wstring>& names) {
    if (names.empty()) {
        return L"正常";
    }
    std::wstring result;
    for (const std::wstring& name : names) {
        if (!result.empty()) {
            result += L" | ";
        }
        result += name;
    }
    return result;
}

// sourceYesNo renders one source-matrix bit in the same compact style as the
// original ProcessDock Cross-View tables. Inputs are the source mask and target
// bit; output is `是` when present or `-` when absent.
std::wstring sourceYesNo(const std::uint32_t sourceMask, const std::uint32_t bit) {
    return (sourceMask & bit) != 0U ? L"是" : L"-";
}

// cpuVectorText formats driver-integrity CPU coordinates. Inputs are processor
// group, CPU number, and optional vector; output mirrors "Gx CPUy Vz" while
// hiding the vector when the protocol uses all-bits-set as "not applicable".
std::wstring cpuVectorText(const std::uint32_t group, const std::uint32_t cpu, const std::uint32_t vector) {
    std::wostringstream stream;
    stream << L"G" << group << L" CPU" << cpu;
    if (vector != 0xFFFFFFFFUL) {
        stream << L" V" << vector;
    }
    return stream.str();
}

// hotkeyDisplayText formats the R0 hotkey tuple for table display. Inputs are
// modifier flags, VK, and hotkey id; output keeps both hex flags and identifier
// so the compact Win32 table still has enough information for diagnostics.
std::wstring hotkeyDisplayText(const std::uint32_t modifiers, const std::uint32_t virtualKey, const std::uint32_t hotkeyId) {
    std::wostringstream stream;
    stream << L"VK " << hexText(virtualKey)
           << L" Mod " << hexText(modifiers)
           << L" Id " << hexText(hotkeyId);
    return stream.str();
}

// mutationRiskText expands the mutation risk mask. Input is a bitmask returned
// by R0; output is a stable, readable summary for audit/action rows.
std::wstring mutationRiskText(const std::uint32_t riskFlags) {
    std::vector<std::wstring> names;
    appendFlagName(names, riskFlags, KSWORD_ARK_MUTATION_RISK_FORCE_REQUIRED, L"Force required");
    appendFlagName(names, riskFlags, KSWORD_ARK_MUTATION_RISK_FORCE_USED, L"Force used");
    appendFlagName(names, riskFlags, KSWORD_ARK_MUTATION_RISK_DRY_RUN, L"Dry-run");
    appendFlagName(names, riskFlags, KSWORD_ARK_MUTATION_RISK_POLICY_REQUIRED, L"Policy required");
    appendFlagName(names, riskFlags, KSWORD_ARK_MUTATION_RISK_POLICY_DENIED, L"Policy denied");
    appendFlagName(names, riskFlags, KSWORD_ARK_MUTATION_RISK_BEFORE_MISMATCH, L"Before mismatch");
    appendFlagName(names, riskFlags, KSWORD_ARK_MUTATION_RISK_WRITE_BLOCKED_BY_DESIGN, L"Write blocked");
    appendFlagName(names, riskFlags, KSWORD_ARK_MUTATION_RISK_PLAN_ONLY, L"Plan only");
    appendFlagName(names, riskFlags, KSWORD_ARK_MUTATION_RISK_DYNDATA_REQUIRED, L"DynData required");
    appendFlagName(names, riskFlags, KSWORD_ARK_MUTATION_RISK_DYNDATA_CONFIRMED, L"DynData confirmed");
    appendFlagName(names, riskFlags, KSWORD_ARK_MUTATION_RISK_CANONICAL_REQUIRED, L"Canonical required");
    appendFlagName(names, riskFlags, KSWORD_ARK_MUTATION_RISK_NONPAGED_REQUIRED, L"Nonpaged required");
    appendFlagName(names, riskFlags, KSWORD_ARK_MUTATION_RISK_READ_SNAPSHOT_TAKEN, L"Read snapshot");
    appendFlagName(names, riskFlags, KSWORD_ARK_MUTATION_RISK_ROLLBACK_IDEMPOTENT, L"Rollback idempotent");
    appendFlagName(names, riskFlags, KSWORD_ARK_MUTATION_RISK_KERNEL_PATCH_SURFACE, L"Kernel patch surface");
    appendFlagName(names, riskFlags, KSWORD_ARK_MUTATION_RISK_PROCESS_PROTECTION_SURFACE, L"Process protection surface");
    appendFlagName(names, riskFlags, KSWORD_ARK_MUTATION_RISK_CALLBACK_UNLINK_SURFACE, L"Callback unlink surface");
    appendFlagName(names, riskFlags, KSWORD_ARK_MUTATION_RISK_SIZE_LIMITED, L"Size limited");
    appendFlagName(names, riskFlags, KSWORD_ARK_MUTATION_RISK_TARGET_CHANGED, L"Target changed");
    return joinNames(names);
}

// mutationFlagsText expands user/action flags. Input is KSWORD_ARK_MUTATION_FLAG
// bitmask; output is a compact display string.
std::wstring mutationFlagsText(const std::uint32_t flags) {
    std::vector<std::wstring> names;
    appendFlagName(names, flags, KSWORD_ARK_MUTATION_FLAG_FORCE, L"Force");
    appendFlagName(names, flags, KSWORD_ARK_MUTATION_FLAG_UI_CONFIRMED, L"UI confirmed");
    appendFlagName(names, flags, KSWORD_ARK_MUTATION_FLAG_DRY_RUN, L"Dry-run");
    appendFlagName(names, flags, KSWORD_ARK_MUTATION_FLAG_EXPECTED_BEFORE_PRESENT, L"Expected-before");
    return joinNames(names);
}

// parseUnsigned32 is a bounds-checked wrapper around parseUnsigned64. Input is a
// UI cell value; output is true only when the value fits an unsigned 32-bit field.
bool parseUnsigned32(const std::wstring& text, std::uint32_t& valueOut) {
    std::uint64_t parsed = 0;
    if (!parseUnsigned64(text, parsed) || parsed > 0xFFFFFFFFULL) {
        return false;
    }
    valueOut = static_cast<std::uint32_t>(parsed);
    return true;
}

// parseHexByteList parses strings produced by BytesHex, such as "48 8B ..."
// into a byte vector. Inputs are display text from the selected row; output is a
// bounded byte vector suitable for ArkDriverClient's expected-current snapshot.
std::vector<std::uint8_t> parseHexByteList(const std::wstring& text) {
    std::vector<std::uint8_t> bytes;
    std::wstring token;
    auto flushToken = [&]() {
        if (token.empty() || token == L"...") {
            token.clear();
            return;
        }
        std::uint64_t value = 0;
        if (parseUnsigned64(L"0x" + token, value) && value <= 0xFF &&
            bytes.size() < KSWORD_ARK_KERNEL_HOOK_PATCH_MAX_BYTES) {
            bytes.push_back(static_cast<std::uint8_t>(value));
        }
        token.clear();
    };
    for (const wchar_t kCh : text) {
        if (std::iswspace(kCh) || kCh == L',' || kCh == L';') {
            flushToken();
        } else {
            token.push_back(kCh);
        }
    }
    flushToken();
    return bytes;
}

// parsePidList accepts comma/space/semicolon separated process ids for the
// minifilter bypass action. Input is the generic filter edit; output is a unique,
// bounded PID vector accepted by ArkDriverClient.
std::vector<std::uint32_t> parsePidList(const std::wstring& text) {
    std::vector<std::uint32_t> pids;
    std::wstring token;
    auto flushToken = [&]() {
        if (token.empty()) {
            return;
        }
        std::uint32_t pid = 0;
        if (parseUnsigned32(token, pid) && pid != 0 &&
            std::find(pids.begin(), pids.end(), pid) == pids.end() &&
            pids.size() < KSWORD_ARK_MINIFILTER_BYPASS_PID_MAX_COUNT) {
            pids.push_back(pid);
        }
        token.clear();
    };
    for (const wchar_t kCh : text) {
        if (kCh == L',' || kCh == L';' || std::iswspace(kCh)) {
            flushToken();
        } else {
            token.push_back(kCh);
        }
    }
    flushToken();
    return pids;
}

// parseFirstUnsigned64FromText extracts the first decimal or hexadecimal number
// from a free-form filter string. Inputs may be a plain "1234", "0xFFFF", or a
// copied row such as "PID: 1234"; output is false when no complete numeric token
// is found.
bool parseFirstUnsigned64FromText(const std::wstring& text, std::uint64_t& valueOut) {
    std::wstring token;
    auto flush = [&]() -> bool {
        if (token.empty()) {
            return false;
        }
        std::uint64_t parsed = 0;
        const bool kOk = parseUnsigned64(token, parsed);
        token.clear();
        if (kOk) {
            valueOut = parsed;
            return true;
        }
        return false;
    };
    for (const wchar_t kCh : text) {
        const bool kNumeric = std::iswxdigit(kCh) || kCh == L'x' || kCh == L'X';
        if (kNumeric) {
            token.push_back(kCh);
        } else if (flush()) {
            return true;
        }
    }
    return flush();
}

// parseFirstPidFromText extracts a PID from the generic filter box. Input is a
// free-form string; output is 0 when no usable 32-bit PID is present.
std::uint32_t parseFirstPidFromText(const std::wstring& text) {
    std::uint64_t parsed = 0;
    if (!parseFirstUnsigned64FromText(text, parsed) || parsed > 0xFFFFFFFFULL) {
        return 0;
    }
    return static_cast<std::uint32_t>(parsed);
}

// startsWithI reports whether text starts with prefix ignoring case. Inputs are
// UI/path strings; processing compares one character at a time; output is true
// only when prefix is fully present.
bool startsWithI(const std::wstring& text, const std::wstring& prefix) {
    if (text.size() < prefix.size()) {
        return false;
    }
    for (std::size_t i = 0; i < prefix.size(); ++i) {
        if (::towlower(text[i]) != ::towlower(prefix[i])) {
            return false;
        }
    }
    return true;
}

// isDriverObjectQuerySuccess maps the shared query status into a table success
// decision. Input is one DriverObject query response; output is true for full or
// partial DriverObject evidence so callers still display partial rows.
bool isDriverObjectQuerySuccess(const ksword::ark::DriverObjectQueryResult& query) {
    return query.io.ok &&
        (query.queryStatus == KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_OK ||
            query.queryStatus == KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_PARTIAL);
}

// driverObjectQueryStatusText maps the R0 query status enum to compact display
// text. Input is KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_*; output is static text.
const wchar_t* driverObjectQueryStatusText(const std::uint32_t status) {
    switch (status) {
    case KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_OK: return L"OK";
    case KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_PARTIAL: return L"Partial";
    case KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_NAME_INVALID: return L"Name invalid";
    case KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_NOT_FOUND: return L"Not found";
    case KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_REFERENCE_FAILED: return L"Reference failed";
    case KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_BUFFER_TOO_SMALL: return L"Buffer too small";
    case KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_QUERY_FAILED: return L"Query failed";
    case KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_UNAVAILABLE:
    default:
        return L"Unavailable";
    }
}

// driverUnloadStatusText maps the force-unload response enum into a concise
// label. Input is KSWORD_ARK_DRIVER_UNLOAD_STATUS_*; output is static text.
const wchar_t* driverUnloadStatusText(const std::uint32_t status) {
    switch (status) {
    case KSWORD_ARK_DRIVER_UNLOAD_STATUS_UNLOADED: return L"Unloaded";
    case KSWORD_ARK_DRIVER_UNLOAD_STATUS_UNLOAD_ROUTINE_MISSING: return L"Unload routine missing";
    case KSWORD_ARK_DRIVER_UNLOAD_STATUS_REFERENCE_FAILED: return L"Reference failed";
    case KSWORD_ARK_DRIVER_UNLOAD_STATUS_THREAD_FAILED: return L"Thread failed";
    case KSWORD_ARK_DRIVER_UNLOAD_STATUS_WAIT_TIMEOUT: return L"Wait timeout";
    case KSWORD_ARK_DRIVER_UNLOAD_STATUS_OPERATION_FAILED: return L"Operation failed";
    case KSWORD_ARK_DRIVER_UNLOAD_STATUS_FORCED_CLEANUP: return L"Forced cleanup";
    case KSWORD_ARK_DRIVER_UNLOAD_STATUS_CLEANUP_FAILED: return L"Cleanup failed";
    default: return L"Unknown";
    }
}

// driverUnloadSucceeded reports whether the aggregate R0 unload status should
// be considered successful. Input is the status field; output drives result UI.
bool driverUnloadSucceeded(const std::uint32_t status) {
    return status == KSWORD_ARK_DRIVER_UNLOAD_STATUS_UNLOADED ||
        status == KSWORD_ARK_DRIVER_UNLOAD_STATUS_FORCED_CLEANUP;
}

// majorFunctionName returns the conventional IRP_MJ_* label. Input is a major
// function index; output falls back to a numeric IRP_MJ_N label.
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
    default: return std::wstring(L"IRP_MJ_") + std::to_wstring(value);
    }
}

// normalizeDriverObjectName converts a selected row path/name into the canonical
// \Driver\Name form required by ArkDriverClient. Input is user-visible text;
// output is empty for strings that cannot identify a DriverObject.
std::wstring normalizeDriverObjectName(std::wstring value, const bool allowBareName) {
    while (!value.empty() && std::iswspace(value.front())) {
        value.erase(value.begin());
    }
    while (!value.empty() && std::iswspace(value.back())) {
        value.pop_back();
    }
    if (value.empty()) {
        return {};
    }
    if (startsWithI(value, L"\\Driver\\")) {
        return value;
    }
    if (startsWithI(value, L"Driver\\")) {
        return L"\\" + value;
    }
    if (allowBareName && value.find(L'\\') == std::wstring::npos) {
        return L"\\Driver\\" + value;
    }
    return {};
}

// appendUniqueDriverObjectName adds one canonical name if it is not already in
// the vector. Inputs are the destination list and candidate; no value is
// returned because the list is mutated in place.
void appendUniqueDriverObjectName(std::vector<std::wstring>& names, const std::wstring& candidate) {
    if (candidate.empty()) {
        return;
    }
    const auto kExists = std::find_if(names.begin(), names.end(), [&](const std::wstring& item) {
        return _wcsicmp(item.c_str(), candidate.c_str()) == 0;
    });
    if (kExists == names.end()) {
        names.push_back(candidate);
    }
}

// RowField extracts one field from a generic result row. Inputs are row and key;
// output is an empty string when the key is not present.
std::wstring rowField(const KernelResultRow& row, const std::wstring& key) {
    for (const auto& column : row.columns) {
        if (_wcsicmp(column.first.c_str(), key.c_str()) == 0) {
            return column.second;
        }
    }
    return {};
}

// driverObjectNameFromRow resolves a DriverObject name from native or R0 rows.
// Inputs are one generic result row; processing checks explicit Path/DriverName
// first and then \Driver parent rows; output is canonical or empty.
std::wstring driverObjectNameFromRow(const KernelResultRow& row) {
    const auto kFirstRowField = [&](std::initializer_list<const wchar_t*> keys) {
        for (const wchar_t* key : keys) {
            const std::wstring kValue = rowField(row, key);
            if (!kValue.empty()) {
                return kValue;
            }
        }
        return std::wstring{};
    };
    const std::wstring kDirect = normalizeDriverObjectName(kFirstRowField({ L"DriverName", L"objectName", L"对象名称", L"Name" }), false);
    if (!kDirect.empty()) {
        return kDirect;
    }
    const std::wstring kPath = normalizeDriverObjectName(kFirstRowField({ L"Path", L"fullPath", L"FullPath", L"完整路径", L"NtPath" }), false);
    if (!kPath.empty()) {
        return kPath;
    }
    const std::wstring kParent = kFirstRowField({ L"Parent", L"Directory", L"directoryPath", L"目录路径" });
    const std::wstring kSource = kFirstRowField({ L"Source", L"来源目录" });
    const std::wstring kType = kFirstRowField({ L"Type", L"objectType", L"对象类型", L"类型" });
    const bool kAllowName =
        _wcsicmp(kParent.c_str(), L"\\Driver") == 0 ||
        _wcsicmp(kSource.c_str(), L"\\Driver") == 0 ||
        _wcsicmp(kType.c_str(), L"DriverObject") == 0;
    return normalizeDriverObjectName(kFirstRowField({ L"Name", L"objectName", L"对象名称", L"名称" }), kAllowName);
}

// driverObjectNameFromActionRequest resolves the selected row snapshot carried
// by KernelPage into a canonical \Driver\Name string. Inputs are value-only
// row fields copied from the ListView; processing checks R0 DriverName/Path
// columns first and then native \Driver parent/name columns; output is empty
// when the selected row is not a DriverObject-related row.
std::wstring driverObjectNameFromActionRequest(const KernelActionRequest& request) {
    const std::wstring kDirect = normalizeDriverObjectName(fieldValue(request, L"DriverName"), false);
    if (!kDirect.empty()) {
        return kDirect;
    }
    const std::wstring kPath = normalizeDriverObjectName(firstFieldValue(request, {
        L"Path",
        L"fullPath",
        L"FullPath",
        L"完整路径",
        L"NtPath",
        L"NT Path",
    }), false);
    if (!kPath.empty()) {
        return kPath;
    }
    const std::wstring kParent = firstFieldValue(request, {
        L"Parent",
        L"Directory",
        L"directoryPath",
        L"目录路径",
    });
    const std::wstring kSource = firstFieldValue(request, {
        L"Source",
        L"来源目录",
    });
    const std::wstring kType = firstFieldValue(request, {
        L"Type",
        L"objectType",
        L"对象类型",
        L"类型",
    });
    const bool kAllowName =
        _wcsicmp(kParent.c_str(), L"\\Driver") == 0 ||
        _wcsicmp(kSource.c_str(), L"\\Driver") == 0 ||
        _wcsicmp(kType.c_str(), L"DriverObject") == 0 ||
        _wcsicmp(kSource.c_str(), L"R0 DriverObject") == 0 ||
        _wcsicmp(kSource.c_str(), L"R0 MajorFunction") == 0 ||
        _wcsicmp(kSource.c_str(), L"R0 DeviceObject") == 0;
    return normalizeDriverObjectName(firstFieldValue(request, {
        L"Name",
        L"objectName",
        L"对象名称",
        L"名称",
    }), kAllowName);
}

// driverModuleBaseFromActionRequest extracts a loaded-driver image base from the
// immutable row snapshot. It accepts the detail query's DriverStart first and
// falls back to the module-base fields used by integrity and dispatch rows.
std::uint64_t driverModuleBaseFromActionRequest(const KernelActionRequest& request) {
    const std::wstring kValue = firstFieldValue(request, {
        L"DriverStart",
        L"ModuleBase",
        L"OwnerModuleBase",
        L"OwnerBase",
    });
    std::uint64_t moduleBase = 0;
    return parseFirstUnsigned64FromText(kValue, moduleBase) ? moduleBase : 0ULL;
}

// inlinePatchLength mirrors the original KernelDock conservative NOP length
// selection. Inputs are hook type and available bytes; output is zero when the
// selected row is not safe for automatic NOP patching.
std::uint32_t inlinePatchLength(const std::uint32_t hookType, const std::uint32_t availableBytes) {
    std::uint32_t desired = 0;
    switch (hookType) {
    case KSWORD_ARK_INLINE_HOOK_TYPE_JMP_REL32:
        desired = 5;
        break;
    case KSWORD_ARK_INLINE_HOOK_TYPE_JMP_REL8:
        desired = 2;
        break;
    case KSWORD_ARK_INLINE_HOOK_TYPE_JMP_RIP_INDIRECT:
        desired = 6;
        break;
    case KSWORD_ARK_INLINE_HOOK_TYPE_MOV_RAX_JMP_RAX:
        desired = 12;
        break;
    case KSWORD_ARK_INLINE_HOOK_TYPE_MOV_R11_JMP_R11:
        desired = 13;
        break;
    case KSWORD_ARK_INLINE_HOOK_TYPE_RET_PATCH:
    case KSWORD_ARK_INLINE_HOOK_TYPE_INT3_PATCH:
        desired = 1;
        break;
    default:
        desired = 0;
        break;
    }
    return std::min<std::uint32_t>(desired, availableBytes);
}

// callbackRemoveTypeForClass converts callback enumeration classes into the
// removeExternalCallbackEx request class expected by the driver protocol.
// Inputs are enum rows from ArkDriverClient; output is zero when no safe public
// removal path exists.
std::uint32_t callbackRemoveTypeForClass(const std::uint32_t callbackClass) {
    switch (callbackClass) {
    case KSWORD_ARK_CALLBACK_TYPE_REGISTRY:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_REGISTRY;
    case KSWORD_ARK_CALLBACK_TYPE_PROCESS_CREATE:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_PROCESS;
    case KSWORD_ARK_CALLBACK_TYPE_THREAD_CREATE:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_THREAD;
    case KSWORD_ARK_CALLBACK_TYPE_IMAGE_LOAD:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_IMAGE;
    case KSWORD_ARK_CALLBACK_TYPE_OBJECT:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_OBJECT;
    case KSWORD_ARK_CALLBACK_TYPE_MINIFILTER:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_MINIFILTER;
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_WFP_CALLOUT:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_WFP_CALLOUT;
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_ETW_PROVIDER:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_ETW_PROVIDER;
    default:
        return 0;
    }
}

// crc32Step advances the same reflected CRC32 algorithm used by the callback
// rule validator in R0. Inputs are a byte span and a running CRC value; output
// is the updated running value before final bit inversion.
std::uint32_t crc32Step(const std::uint8_t* const data, const std::size_t length, const std::uint32_t currentCrc) {
    std::uint32_t crc = currentCrc;
    if (data == nullptr || length == 0) {
        return crc;
    }
    for (std::size_t byteIndex = 0; byteIndex < length; ++byteIndex) {
        crc ^= static_cast<std::uint32_t>(data[byteIndex]);
        for (int bitIndex = 0; bitIndex < 8; ++bitIndex) {
            crc = (crc & 1U) != 0U ? ((crc >> 1U) ^ 0xEDB88320U) : (crc >> 1U);
        }
    }
    return crc;
}

// Crc32 computes the finalized reflected CRC32 for callback rule blobs. Input
// is the serialized blob with header.crc32 still zero; output is the value that
// must be copied into KSWORD_ARK_CALLBACK_RULE_BLOB_HEADER::crc32.
std::uint32_t crc32(const std::vector<std::uint8_t>& bytes) {
    return ~crc32Step(bytes.data(), bytes.size(), 0xFFFFFFFFU);
}

// buildDisabledCallbackRuleBlob creates a valid empty callback-rule snapshot.
// Inputs are a monotonically increasing rule version; processing writes the
// shared header, uses no groups/rules/string pool, and fills the required CRC;
// output is ready for ArkDriverClient::setCallbackRules.
std::vector<std::uint8_t> buildDisabledCallbackRuleBlob(const std::uint64_t ruleVersion) {
    KSWORD_ARK_CALLBACK_RULE_BLOB_HEADER header{};
    header.size = static_cast<unsigned long>(sizeof(header));
    header.magic = KSWORD_ARK_CALLBACK_RULE_BLOB_MAGIC;
    header.protocolVersion = KSWORD_ARK_CALLBACK_PROTOCOL_VERSION;
    header.schemaVersion = KSWORD_ARK_CALLBACK_RULE_SCHEMA_VERSION;
    header.globalFlags = 0;
    header.groupCount = 0;
    header.ruleCount = 0;
    header.groupOffsetBytes = static_cast<unsigned long>(sizeof(header));
    header.ruleOffsetBytes = static_cast<unsigned long>(sizeof(header));
    header.stringOffsetBytes = static_cast<unsigned long>(sizeof(header));
    header.stringBytes = 0;
    header.crc32 = 0;
    header.reserved = 0;
    header.ruleVersion = ruleVersion;

    std::vector<std::uint8_t> blob(sizeof(header), 0);
    std::memcpy(blob.data(), &header, sizeof(header));
    header.crc32 = crc32(blob);
    std::memcpy(blob.data(), &header, sizeof(header));
    return blob;
}

struct LocalCallbackRuleGroup {
    std::uint32_t id = 0;
    bool enabled = true;
    std::uint32_t priority = 10;
    std::wstring name;
    std::wstring comment;
};

struct LocalCallbackRule {
    std::uint32_t id = 0;
    std::uint32_t groupId = 0;
    std::uint32_t typeIndex = 0;
    bool enabled = true;
    std::uint32_t priority = 10;
    std::uint32_t timeoutMs = 0;
    std::wstring name;
    std::wstring operation;
    std::wstring matchMode;
    std::wstring action;
    std::wstring timeoutDefault;
    std::wstring initiatorPattern;
    std::wstring targetPattern;
    std::wstring comment;
};

struct LocalCallbackRuleDocument {
    bool globalEnabled = true;
    std::vector<LocalCallbackRuleGroup> groups;
    std::vector<LocalCallbackRule> rules;
};

// splitTabs keeps empty fields while parsing the lightweight Win32 rule export.
// Input is one serialized line; output is an ordered list of tab fields.
std::vector<std::wstring> splitTabs(const std::wstring& line) {
    std::vector<std::wstring> fields;
    std::wstring current;
    for (const wchar_t kCh : line) {
        if (kCh == L'\t') {
            fields.push_back(current);
            current.clear();
        } else {
            current.push_back(kCh);
        }
    }
    fields.push_back(current);
    return fields;
}

// unescapeLocalRuleField reverses the UI serializer for local callback rule
// text. Input is one field; output is plain Unicode text for blob string pool.
std::wstring unescapeLocalRuleField(const std::wstring& text) {
    std::wstring value;
    value.reserve(text.size());
    bool escaping = false;
    for (const wchar_t kCh : text) {
        if (escaping) {
            switch (kCh) {
            case L't': value.push_back(L'\t'); break;
            case L'r': value.push_back(L'\r'); break;
            case L'n': value.push_back(L'\n'); break;
            case L'\\': value.push_back(L'\\'); break;
            default: value.push_back(kCh); break;
            }
            escaping = false;
            continue;
        }
        if (kCh == L'\\') {
            escaping = true;
        } else {
            value.push_back(kCh);
        }
    }
    if (escaping) {
        value.push_back(L'\\');
    }
    return value;
}

std::uint32_t parseLocalUInt(const std::wstring& text, const std::uint32_t fallback) {
    if (text.empty()) {
        return fallback;
    }
    wchar_t* end = nullptr;
    const unsigned long kValue = std::wcstoul(text.c_str(), &end, 10);
    return end != text.c_str() ? static_cast<std::uint32_t>(kValue) : fallback;
}

// parseLocalCallbackRuleDocument parses the UI-exported .kswrules text. Inputs
// are the serialized local editor state and an error sink; output is a document
// used only to build the shared R0 rule blob.
bool parseLocalCallbackRuleDocument(const std::wstring& text, LocalCallbackRuleDocument& document, std::wstring& errorText) {
    std::wistringstream input(text);
    std::wstring line;
    bool sawHeader = false;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == L'\r') {
            line.pop_back();
        }
        if (line.empty()) {
            continue;
        }
        if (!sawHeader) {
            if (line != L"KSWORD_ARKLIGHT_CALLBACK_RULES_V1") {
                errorText = L"本地规则配置头不匹配。";
                return false;
            }
            sawHeader = true;
            continue;
        }
        const std::vector<std::wstring> kFields = splitTabs(line);
        if (kFields.empty()) {
            continue;
        }
        if (kFields[0] == L"GLOBAL") {
            if (kFields.size() >= 2) {
                document.globalEnabled = parseLocalUInt(kFields[1], 1) != 0;
            }
        } else if (kFields[0] == L"GROUP") {
            if (kFields.size() < 6) {
                errorText = L"GROUP 字段不足。";
                return false;
            }
            LocalCallbackRuleGroup group;
            group.id = parseLocalUInt(kFields[1], 0);
            group.enabled = parseLocalUInt(kFields[2], 0) != 0;
            group.priority = parseLocalUInt(kFields[3], 10);
            group.name = unescapeLocalRuleField(kFields[4]);
            group.comment = unescapeLocalRuleField(kFields[5]);
            if (group.id == 0) {
                errorText = L"GROUP id 非法。";
                return false;
            }
            document.groups.push_back(std::move(group));
        } else if (kFields[0] == L"RULE") {
            if (kFields.size() < 13) {
                errorText = L"RULE 字段不足。";
                return false;
            }
            LocalCallbackRule rule;
            rule.id = parseLocalUInt(kFields[1], 0);
            rule.groupId = parseLocalUInt(kFields[2], 0);
            rule.typeIndex = parseLocalUInt(kFields[3], 0);
            rule.enabled = parseLocalUInt(kFields[4], 0) != 0;
            rule.priority = parseLocalUInt(kFields[5], 10);
            rule.timeoutMs = parseLocalUInt(kFields[6], 0);
            rule.name = unescapeLocalRuleField(kFields[7]);
            rule.operation = unescapeLocalRuleField(kFields[8]);
            rule.matchMode = unescapeLocalRuleField(kFields[9]);
            rule.action = unescapeLocalRuleField(kFields[10]);
            rule.timeoutDefault = unescapeLocalRuleField(kFields[11]);
            if (kFields.size() >= 15) {
                rule.initiatorPattern = unescapeLocalRuleField(kFields[12]);
                rule.targetPattern = unescapeLocalRuleField(kFields[13]);
                rule.comment = unescapeLocalRuleField(kFields[14]);
            } else {
                rule.initiatorPattern = L"*";
                rule.targetPattern = L"*";
                rule.comment = unescapeLocalRuleField(kFields[12]);
            }
            if (rule.id == 0 || rule.groupId == 0 || rule.typeIndex > 5) {
                errorText = L"RULE id/group/type 非法。";
                return false;
            }
            document.rules.push_back(std::move(rule));
        }
    }
    if (!sawHeader) {
        errorText = L"本地规则配置为空或缺少头。";
        return false;
    }
    if (document.groups.size() > KSWORD_ARK_CALLBACK_MAX_GROUP_COUNT ||
        document.rules.size() > KSWORD_ARK_CALLBACK_MAX_RULE_COUNT) {
        errorText = L"本地规则数量超过驱动协议限制。";
        return false;
    }
    return true;
}

std::uint32_t localCallbackTypeFromIndex(const std::uint32_t typeIndex) {
    switch (typeIndex) {
    case 0: return KSWORD_ARK_CALLBACK_TYPE_REGISTRY;
    case 1: return KSWORD_ARK_CALLBACK_TYPE_PROCESS_CREATE;
    case 2: return KSWORD_ARK_CALLBACK_TYPE_THREAD_CREATE;
    case 3: return KSWORD_ARK_CALLBACK_TYPE_IMAGE_LOAD;
    case 4: return KSWORD_ARK_CALLBACK_TYPE_OBJECT;
    case 5: return KSWORD_ARK_CALLBACK_TYPE_MINIFILTER;
    default: return KSWORD_ARK_CALLBACK_TYPE_NONE;
    }
}

std::uint32_t localOperationMaskFromRule(const LocalCallbackRule& rule) {
    switch (rule.typeIndex) {
    case 0: return KSWORD_ARK_REG_OP_ALL;
    case 1: return KSWORD_ARK_PROCESS_OP_CREATE;
    case 2: return KSWORD_ARK_THREAD_OP_CREATE | KSWORD_ARK_THREAD_OP_EXIT;
    case 3: return KSWORD_ARK_IMAGE_OP_LOAD;
    case 4: return KSWORD_ARK_OBJECT_OP_HANDLE_CREATE | KSWORD_ARK_OBJECT_OP_HANDLE_DUPLICATE | KSWORD_ARK_OBJECT_OP_TYPE_PROCESS | KSWORD_ARK_OBJECT_OP_TYPE_THREAD;
    case 5: return KSWORD_ARK_MINIFILTER_OP_ALL;
    default: return 0;
    }
}

std::uint32_t localMatchModeFromText(const std::wstring& text) {
    if (text.find(L"正则") != std::wstring::npos || text.find(L"Regex") != std::wstring::npos || text.find(L"regex") != std::wstring::npos) {
        return KSWORD_ARK_MATCH_MODE_REGEX;
    }
    if (text.find(L"通配") != std::wstring::npos || text.find(L"Wildcard") != std::wstring::npos || text.find(L"*") != std::wstring::npos) {
        return KSWORD_ARK_MATCH_MODE_WILDCARD;
    }
    if (text.find(L"前缀") != std::wstring::npos || text.find(L"Prefix") != std::wstring::npos) {
        return KSWORD_ARK_MATCH_MODE_PREFIX;
    }
    if (text.find(L"精确") != std::wstring::npos || text.find(L"Exact") != std::wstring::npos) {
        return KSWORD_ARK_MATCH_MODE_EXACT;
    }
    return KSWORD_ARK_MATCH_MODE_WILDCARD;
}

std::uint32_t localActionFromText(const std::wstring& text) {
    if (text.find(L"拒绝") != std::wstring::npos || text.find(L"Deny") != std::wstring::npos) {
        return KSWORD_ARK_RULE_ACTION_DENY;
    }
    if (text.find(L"允许") != std::wstring::npos || text.find(L"Allow") != std::wstring::npos) {
        return KSWORD_ARK_RULE_ACTION_ALLOW;
    }
    if (text.find(L"询问") != std::wstring::npos || text.find(L"Ask") != std::wstring::npos) {
        return KSWORD_ARK_RULE_ACTION_ASK_USER;
    }
    if (text.find(L"降权") != std::wstring::npos || text.find(L"Strip") != std::wstring::npos) {
        return KSWORD_ARK_RULE_ACTION_STRIP_ACCESS;
    }
    return KSWORD_ARK_RULE_ACTION_LOG_ONLY;
}

std::uint32_t localDecisionFromText(const std::wstring& text) {
    if (text.find(L"拒绝") != std::wstring::npos || text.find(L"Deny") != std::wstring::npos) {
        return KSWORD_ARK_DECISION_DENY;
    }
    if (text.find(L"允许") != std::wstring::npos || text.find(L"Allow") != std::wstring::npos) {
        return KSWORD_ARK_DECISION_ALLOW;
    }
    return KSWORD_ARK_DECISION_ALLOW;
}

// buildCallbackRuleBlob converts local Win32 rule editor data into the shared
// R0 KSWORD_ARK_CALLBACK_RULE_BLOB format. Inputs are parsed groups/rules and
// a ruleVersion; output is a CRC-filled byte vector accepted by ArkDriverClient.
std::vector<std::uint8_t> buildCallbackRuleBlob(const LocalCallbackRuleDocument& document, const std::uint64_t ruleVersion) {
    struct StringRef {
        std::uint32_t offset = 0;
        std::uint16_t chars = 0;
    };
    std::vector<std::uint8_t> stringBytes;
    const auto kAddString = [&](const std::wstring& value) -> StringRef {
        StringRef ref{};
        if (value.empty()) {
            return ref;
        }
        ref.offset = static_cast<std::uint32_t>(stringBytes.size());
        ref.chars = static_cast<std::uint16_t>(std::min<std::size_t>(value.size(), 0xFFFFU));
        const std::size_t kByteCount = static_cast<std::size_t>(ref.chars) * sizeof(wchar_t);
        const auto* bytes = reinterpret_cast<const std::uint8_t*>(value.data());
        stringBytes.insert(stringBytes.end(), bytes, bytes + kByteCount);
        stringBytes.push_back(0);
        stringBytes.push_back(0);
        return ref;
    };

    std::vector<KSWORD_ARK_CALLBACK_GROUP_BLOB> groups(document.groups.size());
    for (std::size_t index = 0; index < document.groups.size(); ++index) {
        const LocalCallbackRuleGroup& source = document.groups[index];
        KSWORD_ARK_CALLBACK_GROUP_BLOB& target = groups[index];
        const StringRef kName = kAddString(source.name);
        const StringRef kComment = kAddString(source.comment);
        target.groupId = source.id;
        target.flags = source.enabled ? KSWORD_ARK_CALLBACK_GROUP_FLAG_ENABLED : 0;
        target.priority = source.priority;
        target.nameOffsetBytes = kName.offset;
        target.nameLengthChars = kName.chars;
        target.commentOffsetBytes = kComment.offset;
        target.commentLengthChars = kComment.chars;
    }

    std::vector<KSWORD_ARK_CALLBACK_RULE_BLOB> rules(document.rules.size());
    for (std::size_t index = 0; index < document.rules.size(); ++index) {
        const LocalCallbackRule& source = document.rules[index];
        KSWORD_ARK_CALLBACK_RULE_BLOB& target = rules[index];
        const StringRef kName = kAddString(source.name);
        const StringRef kComment = kAddString(source.comment);
        const StringRef kInitiator = kAddString(source.initiatorPattern.empty() ? L"*" : source.initiatorPattern);
        const StringRef kTargetPattern = kAddString(source.targetPattern.empty() ? L"*" : source.targetPattern);
        target.ruleId = source.id;
        target.groupId = source.groupId;
        target.flags = source.enabled ? KSWORD_ARK_CALLBACK_RULE_FLAG_ENABLED : 0;
        target.callbackType = localCallbackTypeFromIndex(source.typeIndex);
        target.operationMask = localOperationMaskFromRule(source);
        target.action = localActionFromText(source.action);
        target.matchMode = localMatchModeFromText(source.matchMode);
        target.priority = source.priority;
        target.initiatorOffsetBytes = kInitiator.offset;
        target.initiatorLengthChars = kInitiator.chars;
        target.targetOffsetBytes = kTargetPattern.offset;
        target.targetLengthChars = kTargetPattern.chars;
        target.askTimeoutMs = source.timeoutMs;
        target.askDefaultDecision = localDecisionFromText(source.timeoutDefault);
        target.ruleNameOffsetBytes = kName.offset;
        target.ruleNameLengthChars = kName.chars;
        target.commentOffsetBytes = kComment.offset;
        target.commentLengthChars = kComment.chars;
    }

    KSWORD_ARK_CALLBACK_RULE_BLOB_HEADER header{};
    header.size = static_cast<unsigned long>(
        sizeof(header) +
        groups.size() * sizeof(KSWORD_ARK_CALLBACK_GROUP_BLOB) +
        rules.size() * sizeof(KSWORD_ARK_CALLBACK_RULE_BLOB) +
        stringBytes.size());
    header.magic = KSWORD_ARK_CALLBACK_RULE_BLOB_MAGIC;
    header.protocolVersion = KSWORD_ARK_CALLBACK_PROTOCOL_VERSION;
    header.schemaVersion = KSWORD_ARK_CALLBACK_RULE_SCHEMA_VERSION;
    header.globalFlags = document.globalEnabled ? KSWORD_ARK_CALLBACK_GLOBAL_FLAG_ENABLED : 0;
    header.groupCount = static_cast<unsigned long>(groups.size());
    header.ruleCount = static_cast<unsigned long>(rules.size());
    header.groupOffsetBytes = static_cast<unsigned long>(sizeof(header));
    header.ruleOffsetBytes = header.groupOffsetBytes + static_cast<unsigned long>(groups.size() * sizeof(KSWORD_ARK_CALLBACK_GROUP_BLOB));
    header.stringOffsetBytes = header.ruleOffsetBytes + static_cast<unsigned long>(rules.size() * sizeof(KSWORD_ARK_CALLBACK_RULE_BLOB));
    header.stringBytes = static_cast<unsigned long>(stringBytes.size());
    header.ruleVersion = ruleVersion;

    std::vector<std::uint8_t> blob(header.size, 0);
    std::memcpy(blob.data(), &header, sizeof(header));
    if (!groups.empty()) {
        std::memcpy(blob.data() + header.groupOffsetBytes, groups.data(), groups.size() * sizeof(KSWORD_ARK_CALLBACK_GROUP_BLOB));
    }
    if (!rules.empty()) {
        std::memcpy(blob.data() + header.ruleOffsetBytes, rules.data(), rules.size() * sizeof(KSWORD_ARK_CALLBACK_RULE_BLOB));
    }
    if (!stringBytes.empty()) {
        std::memcpy(blob.data() + header.stringOffsetBytes, stringBytes.data(), stringBytes.size());
    }
    header.crc32 = crc32(blob);
    std::memcpy(blob.data(), &header, sizeof(header));
    return blob;
}

// currentUtc100ns returns the Win32 FILETIME timestamp used by the callback
// protocol. Input is none; processing asks the OS for UTC system time; output is
// a 100ns timestamp suitable for ruleVersion display fallback.
std::uint64_t currentUtc100ns() {
    FILETIME fileTime{};
    ::GetSystemTimeAsFileTime(&fileTime);
    ULARGE_INTEGER value{};
    value.LowPart = fileTime.dwLowDateTime;
    value.HighPart = fileTime.dwHighDateTime;
    return value.QuadPart;
}

// utc100nsToLocalText formats FILETIME-style timestamps returned by R0. Input
// is a UTC 100ns value; processing converts to local SYSTEMTIME when possible;
// output keeps the raw hexadecimal value in separate columns and returns a
// compact wall-clock string for operators.
std::wstring utc100nsToLocalText(const std::uint64_t utc100ns) {
    if (utc100ns == 0) {
        return L"N/A";
    }

    FILETIME utc{};
    utc.dwLowDateTime = static_cast<DWORD>(utc100ns & 0xFFFFFFFFULL);
    utc.dwHighDateTime = static_cast<DWORD>(utc100ns >> 32U);
    FILETIME local{};
    SYSTEMTIME systemTime{};
    if (!::FileTimeToLocalFileTime(&utc, &local) || !::FileTimeToSystemTime(&local, &systemTime)) {
        return L"Invalid";
    }

    std::wostringstream stream;
    stream << std::setfill(L'0')
           << std::setw(4) << systemTime.wYear << L'-'
           << std::setw(2) << systemTime.wMonth << L'-'
           << std::setw(2) << systemTime.wDay << L' '
           << std::setw(2) << systemTime.wHour << L':'
           << std::setw(2) << systemTime.wMinute << L':'
           << std::setw(2) << systemTime.wSecond;
    return stream.str();
}

// callbackRegisteredMaskText expands the runtime registration mask. Input is
// the R0 mask; processing uses the driver-defined bit layout mirrored here for
// display only; output is a comma-separated summary.
std::wstring callbackRegisteredMaskText(const std::uint32_t mask) {
    std::vector<std::wstring> names;
    appendFlagName(names, mask, 0x00000001UL, L"Registry");
    appendFlagName(names, mask, 0x00000002UL, L"Process");
    appendFlagName(names, mask, 0x00000004UL, L"Thread");
    appendFlagName(names, mask, 0x00000008UL, L"Image");
    appendFlagName(names, mask, 0x00000010UL, L"Object");
    appendFlagName(names, mask, 0x00000020UL, L"Minifilter");
    return joinNames(names);
}

// callbackEnumClassText mirrors KswordARK's callbackEnumClassText mapping.
// Input is a shared callback enum class; output is the operator-facing class
// label used in the lightweight table.
std::wstring callbackEnumClassText(const std::uint32_t callbackClass) {
    switch (callbackClass) {
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_REGISTRY: return L"注册表 CmCallback";
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_PROCESS: return L"进程 Notify";
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_THREAD: return L"线程 Notify";
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_IMAGE: return L"镜像加载 Notify";
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_OBJECT: return L"Object Callback";
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_MINIFILTER: return L"Minifilter";
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_WFP_CALLOUT: return L"WFP Callout";
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_ETW_PROVIDER: return L"ETW Provider/Consumer";
    default: return std::wstring(L"未知(") + std::to_wstring(callbackClass) + L")";
    }
}

// callbackEnumSourceText mirrors KswordARK's source-name mapping. Input is the
// callback source id; output explains whether evidence came from public APIs,
// private structure walks, PDB profiles, or Ksword itself.
std::wstring callbackEnumSourceText(const std::uint32_t source) {
    switch (source) {
    case KSWORD_ARK_CALLBACK_ENUM_SOURCE_KSWORD_SELF: return L"Ksword 自身注册";
    case KSWORD_ARK_CALLBACK_ENUM_SOURCE_FLTMGR_ENUMERATION: return L"FltMgr 公开枚举";
    case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_UNSUPPORTED: return L"私有结构诊断";
    case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_PATTERN_SCAN: return L"私有特征定位";
    case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_NOTIFY_ARRAY: return L"Psp Notify 数组";
    case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_REGISTRY_LIST: return L"Cm 回调链表";
    case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_OBJECT_TYPE_LIST: return L"Ob 对象类型链表";
    case KSWORD_ARK_CALLBACK_ENUM_SOURCE_WFP_MGMT_API: return L"WFP 管理 API";
    case KSWORD_ARK_CALLBACK_ENUM_SOURCE_ETW_DYNDATA: return L"ETW DynData";
    case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PDB_PROFILE: return L"PDB 可信 profile";
    case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PUBLIC_API: return L"公开 API";
    default: return std::wstring(L"未知(") + std::to_wstring(source) + L")";
    }
}

// callbackEnumStatusText maps R0 callback-row statuses to readable text. Input
// is KSWORD_ARK_CALLBACK_ENUM_STATUS_*; output keeps the numeric value separate.
std::wstring callbackEnumStatusText(const std::uint32_t status) {
    switch (status) {
    case KSWORD_ARK_CALLBACK_ENUM_STATUS_OK: return L"OK";
    case KSWORD_ARK_CALLBACK_ENUM_STATUS_NOT_REGISTERED: return L"Not registered";
    case KSWORD_ARK_CALLBACK_ENUM_STATUS_UNSUPPORTED: return L"Unsupported";
    case KSWORD_ARK_CALLBACK_ENUM_STATUS_QUERY_FAILED: return L"Query failed";
    case KSWORD_ARK_CALLBACK_ENUM_STATUS_BUFFER_TRUNCATED: return L"Buffer truncated";
    default: return L"Unknown";
    }
}

// callbackEnumFieldFlagsText expands KSWORD_ARK_CALLBACK_ENUM_FIELD_* bits.
// Input is a bitmask from ArkDriverClient; output follows the original Dock's
// evidence-focused display while preserving unknown bits by hex fallback.
std::wstring callbackEnumFieldFlagsText(const std::uint32_t flags) {
    std::vector<std::wstring> names;
    appendFlagName(names, flags, KSWORD_ARK_CALLBACK_ENUM_FIELD_CALLBACK_ADDRESS, L"callback");
    appendFlagName(names, flags, KSWORD_ARK_CALLBACK_ENUM_FIELD_CONTEXT_ADDRESS, L"context");
    appendFlagName(names, flags, KSWORD_ARK_CALLBACK_ENUM_FIELD_REGISTRATION_ADDRESS, L"registration");
    appendFlagName(names, flags, KSWORD_ARK_CALLBACK_ENUM_FIELD_MODULE, L"module");
    appendFlagName(names, flags, KSWORD_ARK_CALLBACK_ENUM_FIELD_NAME, L"name");
    appendFlagName(names, flags, KSWORD_ARK_CALLBACK_ENUM_FIELD_ALTITUDE, L"altitude");
    appendFlagName(names, flags, KSWORD_ARK_CALLBACK_ENUM_FIELD_OWNED_BY_KSWORD, L"owned");
    appendFlagName(names, flags, KSWORD_ARK_CALLBACK_ENUM_FIELD_REMOVABLE_CANDIDATE, L"removable candidate");
    appendFlagName(names, flags, KSWORD_ARK_CALLBACK_ENUM_FIELD_OPERATION_MASK, L"operation mask");
    appendFlagName(names, flags, KSWORD_ARK_CALLBACK_ENUM_FIELD_OBJECT_TYPE_MASK, L"object type mask");
    appendFlagName(names, flags, KSWORD_ARK_CALLBACK_ENUM_FIELD_IDENTIFIER, L"identifier");
    appendFlagName(names, flags, KSWORD_ARK_CALLBACK_ENUM_FIELD_HANDLE, L"handle");
    appendFlagName(names, flags, KSWORD_ARK_CALLBACK_ENUM_FIELD_TRUSTED, L"trusted");
    appendFlagName(names, flags, KSWORD_ARK_CALLBACK_ENUM_FIELD_VERIFIED_REMOVE, L"verified remove");
    appendFlagName(names, flags, KSWORD_ARK_CALLBACK_ENUM_FIELD_EXPERIMENTAL_REMOVE, L"experimental remove");
    appendFlagName(names, flags, KSWORD_ARK_CALLBACK_ENUM_FIELD_RAW_STORAGE_VALUE, L"raw storage");
    const std::uint32_t kKnownFlags =
        KSWORD_ARK_CALLBACK_ENUM_FIELD_CALLBACK_ADDRESS |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_CONTEXT_ADDRESS |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_REGISTRATION_ADDRESS |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_MODULE |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_NAME |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_ALTITUDE |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_OWNED_BY_KSWORD |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_REMOVABLE_CANDIDATE |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_OPERATION_MASK |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_OBJECT_TYPE_MASK |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_IDENTIFIER |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_HANDLE |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_TRUSTED |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_VERIFIED_REMOVE |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_EXPERIMENTAL_REMOVE |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_RAW_STORAGE_VALUE;
    if ((flags & ~kKnownFlags) != 0U) {
        names.push_back(std::wstring(L"unknown=") + hexText(flags & ~kKnownFlags));
    }
    return joinNames(names);
}

// callbackEnumTrustFlagsText expands trust provenance bits. Input is R0 trust
// flags; output matches the original Dock's PDB/public/fallback/revalidated
// diagnostic wording.
std::wstring callbackEnumTrustFlagsText(const std::uint32_t flags) {
    std::vector<std::wstring> names;
    appendFlagName(names, flags, KSWORD_ARK_CALLBACK_TRUST_PDB_PROFILE, L"pdb profile");
    appendFlagName(names, flags, KSWORD_ARK_CALLBACK_TRUST_PUBLIC_API, L"public api");
    appendFlagName(names, flags, KSWORD_ARK_CALLBACK_TRUST_FALLBACK_PATTERN, L"fallback pattern");
    appendFlagName(names, flags, KSWORD_ARK_CALLBACK_TRUST_REVALIDATED, L"revalidated");
    const std::uint32_t kKnownFlags =
        KSWORD_ARK_CALLBACK_TRUST_PDB_PROFILE |
        KSWORD_ARK_CALLBACK_TRUST_PUBLIC_API |
        KSWORD_ARK_CALLBACK_TRUST_FALLBACK_PATTERN |
        KSWORD_ARK_CALLBACK_TRUST_REVALIDATED;
    if ((flags & ~kKnownFlags) != 0U) {
        names.push_back(std::wstring(L"unknown=") + hexText(flags & ~kKnownFlags));
    }
    return joinNames(names);
}

// callbackEnumRemoveBehaviorText expands removal behavior bits. Input is the
// behavior mask returned by R0; output explains whether public API removal or
// experimental unlink is involved.
std::wstring callbackEnumRemoveBehaviorText(const std::uint32_t flags) {
    std::vector<std::wstring> names;
    appendFlagName(names, flags, KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_PUBLIC_API, L"public api");
    appendFlagName(names, flags, KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_EXPERIMENTAL_UNLINK, L"experimental unlink");
    appendFlagName(names, flags, KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_REQUIRE_REVALIDATION, L"require revalidation");
    appendFlagName(names, flags, KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_FORCE_AFTER_PUBLIC_FAILURE, L"force after public failure");
    const std::uint32_t kKnownFlags =
        KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_PUBLIC_API |
        KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_EXPERIMENTAL_UNLINK |
        KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_REQUIRE_REVALIDATION |
        KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_FORCE_AFTER_PUBLIC_FAILURE;
    if ((flags & ~kKnownFlags) != 0U) {
        names.push_back(std::wstring(L"unknown=") + hexText(flags & ~kKnownFlags));
    }
    return joinNames(names);
}

// callbackEnumMappingText mirrors the original remove-result mapping display.
// Input is KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_*; output names all known
// evidence channels and keeps future bits visible.
std::wstring callbackEnumMappingText(const std::uint32_t flags) {
    std::vector<std::wstring> names;
    appendFlagName(names, flags, KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_MODULE, L"module");
    appendFlagName(names, flags, KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_ENUMERATED, L"enumerated");
    appendFlagName(names, flags, KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_PUBLIC_API, L"public api");
    appendFlagName(names, flags, KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_PDB_TRUSTED, L"pdb trusted");
    appendFlagName(names, flags, KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_EXPERIMENTAL, L"experimental");
    const std::uint32_t kKnownFlags =
        KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_MODULE |
        KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_ENUMERATED |
        KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_PUBLIC_API |
        KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_PDB_TRUSTED |
        KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_EXPERIMENTAL;
    if ((flags & ~kKnownFlags) != 0U) {
        names.push_back(std::wstring(L"unknown=") + hexText(flags & ~kKnownFlags));
    }
    return joinNames(names);
}

// callbackEnumIsPublicApiSource returns whether the row came from documented
// enumeration paths. Input is a source id; output follows the original Dock's
// public API bucket.
bool callbackEnumIsPublicApiSource(const std::uint32_t source) {
    return source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_FLTMGR_ENUMERATION ||
        source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_WFP_MGMT_API ||
        source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PUBLIC_API;
}

// callbackEnumIsFallbackSource returns whether the row is private/fallback
// evidence. Input is a source id; output guides trust and removal labels.
bool callbackEnumIsFallbackSource(const std::uint32_t source) {
    switch (source) {
    case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_PATTERN_SCAN:
    case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_NOTIFY_ARRAY:
    case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_REGISTRY_LIST:
    case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_OBJECT_TYPE_LIST:
    case KSWORD_ARK_CALLBACK_ENUM_SOURCE_ETW_DYNDATA:
        return true;
    default:
        return false;
    }
}

// callbackEnumTrustBucket mirrors the original Dock's trust summary. Input is
// one callback row; output is a compact risk/trust bucket for the result table.
std::wstring callbackEnumTrustBucket(const ksword::ark::CallbackEnumEntry& entry) {
    if (entry.source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_UNSUPPORTED ||
        entry.status == KSWORD_ARK_CALLBACK_ENUM_STATUS_UNSUPPORTED) {
        return L"unsupported（当前协议/平台未支持）";
    }
    if (entry.source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_KSWORD_SELF ||
        (entry.fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_OWNED_BY_KSWORD) != 0U ||
        (entry.fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_TRUSTED) != 0U ||
        (entry.trustFlags & (KSWORD_ARK_CALLBACK_TRUST_PDB_PROFILE | KSWORD_ARK_CALLBACK_TRUST_REVALIDATED)) != 0U) {
        return L"trusted（可信/自有或预留 PDB）";
    }
    if (callbackEnumIsPublicApiSource(entry.source) ||
        (entry.trustFlags & KSWORD_ARK_CALLBACK_TRUST_PUBLIC_API) != 0U ||
        (entry.removeBehavior & KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_PUBLIC_API) != 0U) {
        return L"public api（公开 API）";
    }
    if (callbackEnumIsFallbackSource(entry.source) ||
        (entry.trustFlags & KSWORD_ARK_CALLBACK_TRUST_FALLBACK_PATTERN) != 0U) {
        return L"fallback/pattern（私有结构诊断）";
    }
    return L"fallback（未知来源保守展示）";
}

// callbackEnumRemovePolicyText mirrors the original Dock's conservative remove
// policy. Input is one callback row; output states whether safe removal is
// verified, merely candidate, experimental-only, or not allowed.
std::wstring callbackEnumRemovePolicyText(const ksword::ark::CallbackEnumEntry& entry) {
    if (entry.source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_UNSUPPORTED ||
        entry.status != KSWORD_ARK_CALLBACK_ENUM_STATUS_OK ||
        callbackRemoveTypeForClass(entry.callbackClass) == 0U) {
        return L"not removable（不可移除）";
    }

    const bool kRemovableCandidate = (entry.fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_REMOVABLE_CANDIDATE) != 0U;
    const bool kVerifiedRemove =
        (entry.fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_VERIFIED_REMOVE) != 0U ||
        (entry.removeBehavior & KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_PUBLIC_API) != 0U;
    const bool kExperimentalRemove =
        (entry.fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_EXPERIMENTAL_REMOVE) != 0U ||
        (entry.removeBehavior & KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_EXPERIMENTAL_UNLINK) != 0U;
    const bool kHasRequestValue = entry.callbackAddress != 0 || entry.registrationAddress != 0 || entry.rawStorageValue != 0;

    if (kHasRequestValue && (kVerifiedRemove || (kRemovableCandidate && callbackEnumIsPublicApiSource(entry.source)))) {
        return L"removable verified（公开 API 可验证）";
    }
    if (kRemovableCandidate && kHasRequestValue) {
        return L"removable candidate（旧协议候选）";
    }
    if ((kExperimentalRemove || callbackEnumIsFallbackSource(entry.source)) && kHasRequestValue) {
        return L"experimental only（仅预留 unlink）";
    }
    return L"not removable（不可移除）";
}

// kernelHookStatusText mirrors KswordARK's kernelHookStatusText. Input is a
// shared hook status; output is the Chinese status shown by the original Dock.
std::wstring kernelHookStatusText(const std::uint32_t status) {
    switch (status) {
    case KSWORD_ARK_KERNEL_HOOK_STATUS_CLEAN: return L"干净";
    case KSWORD_ARK_KERNEL_HOOK_STATUS_SUSPICIOUS: return L"可疑外跳";
    case KSWORD_ARK_KERNEL_HOOK_STATUS_INTERNAL_BRANCH: return L"模块内跳转";
    case KSWORD_ARK_KERNEL_HOOK_STATUS_READ_FAILED: return L"读取失败";
    case KSWORD_ARK_KERNEL_HOOK_STATUS_PARSE_FAILED: return L"解析失败";
    case KSWORD_ARK_KERNEL_HOOK_STATUS_FORCE_REQUIRED: return L"需要强制确认";
    case KSWORD_ARK_KERNEL_HOOK_STATUS_PATCHED: return L"已修复/摘除";
    case KSWORD_ARK_KERNEL_HOOK_STATUS_PATCH_FAILED: return L"修复失败";
    case KSWORD_ARK_KERNEL_HOOK_STATUS_UNKNOWN:
    default:
        return std::wstring(L"未知(") + std::to_wstring(status) + L")";
    }
}

// inlineHookTypeText mirrors KswordARK's inlineHookTypeText. Input is the R0
// inline patch type; output is a readable instruction-pattern label.
std::wstring inlineHookTypeText(const std::uint32_t hookType) {
    switch (hookType) {
    case KSWORD_ARK_INLINE_HOOK_TYPE_NONE: return L"无明显补丁";
    case KSWORD_ARK_INLINE_HOOK_TYPE_JMP_REL32: return L"JMP rel32";
    case KSWORD_ARK_INLINE_HOOK_TYPE_JMP_REL8: return L"JMP rel8";
    case KSWORD_ARK_INLINE_HOOK_TYPE_JMP_RIP_INDIRECT: return L"JMP [RIP+rel32]";
    case KSWORD_ARK_INLINE_HOOK_TYPE_MOV_RAX_JMP_RAX: return L"MOV RAX; JMP RAX";
    case KSWORD_ARK_INLINE_HOOK_TYPE_MOV_R11_JMP_R11: return L"MOV R11; JMP R11";
    case KSWORD_ARK_INLINE_HOOK_TYPE_RET_PATCH: return L"RET 补丁";
    case KSWORD_ARK_INLINE_HOOK_TYPE_INT3_PATCH: return L"INT3 补丁";
    case KSWORD_ARK_INLINE_HOOK_TYPE_UNKNOWN_PATCH: return L"未知补丁";
    default:
        return std::wstring(L"未知(") + std::to_wstring(hookType) + L")";
    }
}

// iatEatClassText mirrors KswordARK's iatEatClassText. Input is the hook class;
// output is IAT/EAT text with a numeric fallback.
std::wstring iatEatClassText(const std::uint32_t hookClass) {
    switch (hookClass) {
    case KSWORD_ARK_IAT_EAT_HOOK_CLASS_IAT: return L"IAT";
    case KSWORD_ARK_IAT_EAT_HOOK_CLASS_EAT: return L"EAT";
    default:
        return std::wstring(L"未知(") + std::to_wstring(hookClass) + L")";
    }
}

// buildInlineHookDetailText reproduces the original KernelDock detail editor
// for one Inline Hook row. Inputs are one ArkDriverClient row and its optional
// R3 disk baseline; output is a complete multiline detail string.
std::wstring buildInlineHookDetailText(
    const ksword::ark::KernelInlineHookEntry& entry,
    const InlineDiskBaseline& disk) {
    const std::wstring kModuleText = entry.moduleName.empty() ? L"<空>" : entry.moduleName;
    const std::wstring kFunctionText = entry.functionName.empty() ? L"<空>" : utf8ToWide(entry.functionName);
    const std::wstring kTargetModuleText = entry.targetModuleName.empty() ? L"<未解析>" : entry.targetModuleName;
    const std::wstring kDiskBytesText = disk.available ? bytesHex(disk.bytes, disk.byteCount) : L"<不可用>";
    const std::wstring kDiskByteCountText = disk.available ? std::to_wstring(disk.byteCount) : L"0";
    const std::wstring kDiskPathText = disk.filePath.empty() ? L"<不可用>" : disk.filePath;
    const std::wstring kRvaText = entry.moduleBase != 0 && entry.functionAddress >= entry.moduleBase
        ? hexText(entry.functionAddress - entry.moduleBase)
        : L"<未解析>";

    std::wostringstream detail;
    detail << L"Inline Hook 检测详情\r\n"
           << L"模块: " << kModuleText << L"\r\n"
           << L"函数: " << kFunctionText << L"\r\n"
           << L"函数地址: " << hexText(entry.functionAddress) << L"\r\n"
           << L"Hook类型: " << inlineHookTypeText(entry.hookType) << L"\r\n"
           << L"目标地址: " << hexText(entry.targetAddress) << L"\r\n"
           << L"目标模块: " << kTargetModuleText << L"\r\n"
           << L"状态: " << kernelHookStatusText(entry.status) << L"\r\n"
           << L"模块基址: " << hexText(entry.moduleBase) << L"\r\n"
           << L"目标模块基址: " << hexText(entry.targetModuleBase) << L"\r\n"
           << L"当前内存字节(" << entry.currentByteCount << L"): " << bytesHex(entry.currentBytes, entry.currentByteCount) << L"\r\n"
           << L"R0 观察基线(" << entry.originalByteCount << L"): " << bytesHex(entry.expectedBytes, entry.originalByteCount) << L"\r\n"
           << L"磁盘基线字节(" << kDiskByteCountText << L"): " << kDiskBytesText << L"\r\n"
           << L"差异状态: " << disk.statusText << L"\r\n"
           << L"磁盘路径: " << kDiskPathText << L"\r\n"
           << L"RVA: " << kRvaText << L"\r\n"
           << L"标志: " << hexText(entry.flags) << L"\r\n\r\n"
           << L"说明: 当前协议字段 expectedBytes 在 R0 中来自内存观察，通常是 currentBytes 的同源快照，不代表磁盘原始字节。"
           << L"本页额外由 R3 按模块基址和 RVA 从磁盘模块文件读取基线字节并与当前内存字节比较；"
           << L"如果磁盘基线不可用，请只把 R0 观察基线当作诊断快照，不要把它理解为干净基线。"
           << L"磁盘基线是文件同 RVA 的 raw 字节，未应用重定位、热补丁或厂商运行时改写校正，差异仍需结合 Hook 类型和目标地址判断。"
           << L"摘除操作保持原有 NOP 流程，不新增自动修复能力。";
    return detail.str();
}

// buildIatEatHookDetailText reproduces the original KernelDock detail editor
// for one IAT/EAT row. Input is one ArkDriverClient hook row; output is the
// complete multiline details shown by the Win32 detail edit.
std::wstring buildIatEatHookDetailText(const ksword::ark::KernelIatEatHookEntry& entry) {
    const std::wstring kFunctionText = !entry.functionName.empty()
        ? utf8ToWide(entry.functionName)
        : std::wstring(L"#") + std::to_wstring(entry.ordinal);
    std::wostringstream detail;
    detail << L"IAT/EAT Hook 检测详情\r\n"
           << L"类别: " << iatEatClassText(entry.hookClass) << L"\r\n"
           << L"模块: " << (entry.moduleName.empty() ? L"<空>" : entry.moduleName) << L"\r\n"
           << L"导入模块: " << (entry.importModuleName.empty() ? L"<不适用>" : entry.importModuleName) << L"\r\n"
           << L"函数/序号: " << kFunctionText << L"\r\n"
           << L"Thunk/EAT项: " << hexText(entry.thunkAddress) << L"\r\n"
           << L"当前目标: " << hexText(entry.currentTarget) << L"\r\n"
           << L"期望目标: " << hexText(entry.expectedTarget) << L"\r\n"
           << L"目标模块: " << (entry.targetModuleName.empty() ? L"<未解析>" : entry.targetModuleName) << L"\r\n"
           << L"所属模块基址: " << hexText(entry.moduleBase) << L"\r\n"
           << L"目标模块基址: " << hexText(entry.targetModuleBase) << L"\r\n"
           << L"状态: " << kernelHookStatusText(entry.status) << L"\r\n"
           << L"标志: " << hexText(entry.flags) << L"\r\n\r\n"
           << L"说明: IAT 检测比较 thunk 当前目标是否仍落在声明导入模块内；"
           << L"EAT 检测导出 RVA 是否落在自身映像或转发导出区域内。";
    return detail.str();
}

// ssdtFlagsText expands the SSDT/SSSDT row flags using the same concepts as
// the original Dock detail pane. Input is the R0 flags mask; output names the
// resolved index/table/shadow/stub evidence.
std::wstring ssdtFlagsText(const std::uint32_t flags) {
    std::vector<std::wstring> names;
    appendFlagName(names, flags, KSWORD_ARK_SSDT_ENTRY_FLAG_INDEX_RESOLVED, L"索引已解析");
    appendFlagName(names, flags, KSWORD_ARK_SSDT_ENTRY_FLAG_TABLE_ADDRESS_VALID, L"服务表有效");
    appendFlagName(names, flags, KSWORD_ARK_SSDT_ENTRY_FLAG_SHADOW_TABLE, L"Shadow/GUI表");
    appendFlagName(names, flags, KSWORD_ARK_SSDT_ENTRY_FLAG_STUB_EXPORT, L"Stub导出");
    const std::uint32_t kKnownFlags =
        KSWORD_ARK_SSDT_ENTRY_FLAG_INDEX_RESOLVED |
        KSWORD_ARK_SSDT_ENTRY_FLAG_TABLE_ADDRESS_VALID |
        KSWORD_ARK_SSDT_ENTRY_FLAG_SHADOW_TABLE |
        KSWORD_ARK_SSDT_ENTRY_FLAG_STUB_EXPORT;
    if ((flags & ~kKnownFlags) != 0U) {
        names.push_back(std::wstring(L"unknown=") + hexText(flags & ~kKnownFlags));
    }
    return joinNames(names);
}

// ssdtStatusText builds the SSSDT-style status summary from the original Dock.
// Inputs are one SSDT row and whether this is a shadow table; output is a compact
// row-status sentence.
std::wstring ssdtStatusText(const ksword::ark::SsdtEntry& entry, const bool shadow) {
    std::vector<std::wstring> parts;
    if (shadow || (entry.flags & KSWORD_ARK_SSDT_ENTRY_FLAG_SHADOW_TABLE) != 0U) {
        parts.push_back(L"Shadow/GUI表");
    }
    parts.push_back((entry.flags & KSWORD_ARK_SSDT_ENTRY_FLAG_INDEX_RESOLVED) != 0U ? L"索引已解析" : L"索引未解析");
    parts.push_back((entry.flags & KSWORD_ARK_SSDT_ENTRY_FLAG_STUB_EXPORT) != 0U ? L"Stub导出" : L"非Stub导出");
    parts.push_back(entry.serviceRoutineAddress != 0 ? L"表项已解析" : L"表项地址暂不可用");
    return joinNames(parts);
}

// pagePermissionText expands page-table permission bits used by executable
// kernel-memory scan rows. Input is a permission mask from R0; output keeps the
// common R/W/X/NX/Large/Global signals readable while preserving raw hex columns.
std::wstring pagePermissionText(const std::uint32_t flags) {
    std::vector<std::wstring> names;
    std::wstring rwx;
    rwx += (flags & KSWORD_ARK_PAGE_TABLE_FLAG_PRESENT) != 0U ? L'R' : L'-';
    rwx += (flags & KSWORD_ARK_PAGE_TABLE_FLAG_WRITABLE) != 0U ? L'W' : L'-';
    rwx += (flags & KSWORD_ARK_PAGE_TABLE_FLAG_NX) != 0U ? L'-' : L'X';
    names.push_back(rwx);
    appendFlagName(names, flags, KSWORD_ARK_PAGE_TABLE_FLAG_NX, L"NX");
    appendFlagName(names, flags, KSWORD_ARK_PAGE_TABLE_FLAG_LARGE_PAGE, L"Large");
    appendFlagName(names, flags, KSWORD_ARK_PAGE_TABLE_FLAG_USER, L"User");
    appendFlagName(names, flags, KSWORD_ARK_PAGE_TABLE_FLAG_GLOBAL, L"Global");
    appendFlagName(names, flags, KSWORD_ARK_PAGE_TABLE_FLAG_WRITE_THROUGH, L"WriteThrough");
    appendFlagName(names, flags, KSWORD_ARK_PAGE_TABLE_FLAG_CACHE_DISABLE, L"CacheDisable");
    appendFlagName(names, flags, KSWORD_ARK_PAGE_TABLE_FLAG_ACCESSED, L"Accessed");
    appendFlagName(names, flags, KSWORD_ARK_PAGE_TABLE_FLAG_DIRTY, L"Dirty");
    const std::uint32_t kKnownFlags =
        KSWORD_ARK_PAGE_TABLE_FLAG_PRESENT |
        KSWORD_ARK_PAGE_TABLE_FLAG_WRITABLE |
        KSWORD_ARK_PAGE_TABLE_FLAG_USER |
        KSWORD_ARK_PAGE_TABLE_FLAG_WRITE_THROUGH |
        KSWORD_ARK_PAGE_TABLE_FLAG_CACHE_DISABLE |
        KSWORD_ARK_PAGE_TABLE_FLAG_ACCESSED |
        KSWORD_ARK_PAGE_TABLE_FLAG_DIRTY |
        KSWORD_ARK_PAGE_TABLE_FLAG_LARGE_PAGE |
        KSWORD_ARK_PAGE_TABLE_FLAG_GLOBAL |
        KSWORD_ARK_PAGE_TABLE_FLAG_NX;
    if ((flags & ~kKnownFlags) != 0U) {
        names.push_back(std::wstring(L"unknown=") + hexText(flags & ~kKnownFlags));
    }
    return joinNames(names);
}

// kernelExecStatusText maps executable-memory aggregate/row statuses. Input is
// KSWORD_ARK_KERNEL_EXEC_SCAN_STATUS_*; output is a compact diagnostic label.
std::wstring kernelExecStatusText(const std::uint32_t status) {
    switch (status) {
    case KSWORD_ARK_KERNEL_EXEC_SCAN_STATUS_UNAVAILABLE: return L"Unavailable";
    case KSWORD_ARK_KERNEL_EXEC_SCAN_STATUS_CONSERVATIVE: return L"Conservative";
    case KSWORD_ARK_KERNEL_EXEC_SCAN_STATUS_PARTIAL_CONSERVATIVE: return L"Partial conservative";
    case KSWORD_ARK_KERNEL_EXEC_SCAN_STATUS_QUERY_FAILED: return L"Query failed";
    case KSWORD_ARK_KERNEL_EXEC_SCAN_STATUS_INVALID_RANGE: return L"Invalid range";
    case KSWORD_ARK_KERNEL_EXEC_SCAN_STATUS_IRQL_REJECTED: return L"IRQL rejected";
    default: return std::wstring(L"Unknown(") + std::to_wstring(status) + L")";
    }
}

// kernelExecOwnerText names executable-memory owner classes. Input is the R0
// owner kind; output follows the module text / non-text / writable-exec buckets.
std::wstring kernelExecOwnerText(const std::uint32_t ownerKind) {
    switch (ownerKind) {
    case KSWORD_ARK_KERNEL_EXEC_OWNER_UNKNOWN: return L"未知";
    case KSWORD_ARK_KERNEL_EXEC_OWNER_MODULE_TEXT: return L"模块 .text";
    case KSWORD_ARK_KERNEL_EXEC_OWNER_MODULE_NON_TEXT: return L"模块非 .text";
    case KSWORD_ARK_KERNEL_EXEC_OWNER_MODULE_WRITABLE_EXECUTABLE: return L"模块 WX";
    default: return std::wstring(L"未知(") + std::to_wstring(ownerKind) + L")";
    }
}

// kernelExecRiskText expands executable-memory risk bits. Input is a risk mask;
// output names writable-executable, non-text executable, writable section, and
// large-page findings for quick triage.
std::wstring kernelExecRiskText(const std::uint32_t flags) {
    if (flags == 0U) {
        return L"正常";
    }
    std::vector<std::wstring> names;
    appendFlagName(names, flags, KSWORD_ARK_KERNEL_EXEC_RISK_WRITABLE_EXECUTABLE, L"WX");
    appendFlagName(names, flags, KSWORD_ARK_KERNEL_EXEC_RISK_MODULE_NON_TEXT_EXECUTABLE, L"非.text可执行");
    appendFlagName(names, flags, KSWORD_ARK_KERNEL_EXEC_RISK_SECTION_WRITABLE, L"节可写");
    appendFlagName(names, flags, KSWORD_ARK_KERNEL_EXEC_RISK_LARGE_PAGE, L"大页");
    const std::uint32_t kKnownFlags =
        KSWORD_ARK_KERNEL_EXEC_RISK_WRITABLE_EXECUTABLE |
        KSWORD_ARK_KERNEL_EXEC_RISK_MODULE_NON_TEXT_EXECUTABLE |
        KSWORD_ARK_KERNEL_EXEC_RISK_SECTION_WRITABLE |
        KSWORD_ARK_KERNEL_EXEC_RISK_LARGE_PAGE;
    if ((flags & ~kKnownFlags) != 0U) {
        names.push_back(std::wstring(L"unknown=") + hexText(flags & ~kKnownFlags));
    }
    return joinNames(names);
}

// memoryEvidenceHashText mirrors the original MemoryDock hash column. Inputs
// are one evidence row; processing combines algorithm, section and FNV/hash
// value; output is `无` (none) when R0 did not provide a text-section hash.
std::wstring memoryEvidenceHashText(const ksword::ark::KernelMemoryEvidenceEntry& entry) {
    if (entry.hashAlgorithm == KSWORD_ARK_MEMORY_EVIDENCE_HASH_NONE || entry.contentHash == 0ULL) {
        return L"无";
    }
    std::wstring algorithm = entry.hashAlgorithm == KSWORD_ARK_MEMORY_EVIDENCE_HASH_FNV1A64
        ? L"FNV1A64"
        : std::wstring(L"Hash(") + std::to_wstring(entry.hashAlgorithm) + L")";
    std::wstring section = utf8ToWide(entry.sectionName);
    if (section.empty()) {
        section = L".text?";
    }
    return algorithm + L" " + section + L" " + hexText(entry.contentHash);
}

// memoryEvidenceStatusText maps the memory-evidence response status. Input is
// KSWORD_ARK_MEMORY_EVIDENCE_STATUS_*; output is used by summary rows.
std::wstring memoryEvidenceStatusText(const std::uint32_t status) {
    switch (status) {
    case KSWORD_ARK_MEMORY_EVIDENCE_STATUS_UNAVAILABLE: return L"Unavailable";
    case KSWORD_ARK_MEMORY_EVIDENCE_STATUS_OK: return L"OK";
    case KSWORD_ARK_MEMORY_EVIDENCE_STATUS_PARTIAL: return L"Partial";
    case KSWORD_ARK_MEMORY_EVIDENCE_STATUS_QUERY_FAILED: return L"Query failed";
    case KSWORD_ARK_MEMORY_EVIDENCE_STATUS_INVALID_REQUEST: return L"Invalid request";
    case KSWORD_ARK_MEMORY_EVIDENCE_STATUS_IRQL_REJECTED: return L"IRQL rejected";
    default: return std::wstring(L"Unknown(") + std::to_wstring(status) + L")";
    }
}

// memoryEvidenceKindText maps row kinds from the unified evidence scan. Input
// is KSWORD_ARK_MEMORY_EVIDENCE_KIND_*; output separates exec ranges, bigpool,
// and sampled text-section memory.
std::wstring memoryEvidenceKindText(const std::uint32_t kind) {
    switch (kind) {
    case KSWORD_ARK_MEMORY_EVIDENCE_KIND_UNKNOWN: return L"未知";
    case KSWORD_ARK_MEMORY_EVIDENCE_KIND_EXECUTABLE_RANGE: return L"执行页";
    case KSWORD_ARK_MEMORY_EVIDENCE_KIND_BIGPOOL: return L"BigPool";
    case KSWORD_ARK_MEMORY_EVIDENCE_KIND_TEXT_SECTION_MEMORY: return L"text hash";
    default: return std::wstring(L"未知(") + std::to_wstring(kind) + L")";
    }
}

// memoryEvidencePermissionText expands evidence-specific permission bits. Input
// is a permission mask from R0; output names present/read/write/execute/NX flags.
std::wstring memoryEvidencePermissionText(const std::uint32_t flags) {
    std::vector<std::wstring> names;
    std::wstring rwx;
    rwx += (flags & KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_READ) != 0U ? L'R' : L'-';
    rwx += (flags & KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_WRITE) != 0U ? L'W' : L'-';
    rwx += (flags & KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_EXECUTE) != 0U ? L'X' : L'-';
    names.push_back(rwx);
    appendFlagName(names, flags, KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_PRESENT, L"Present");
    appendFlagName(names, flags, KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_NX, L"NX");
    appendFlagName(names, flags, KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_LARGE, L"Large");
    appendFlagName(names, flags, KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_GLOBAL, L"Global");
    appendFlagName(names, flags, KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_USER, L"User");
    const std::uint32_t kKnownFlags =
        KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_PRESENT |
        KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_READ |
        KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_WRITE |
        KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_EXECUTE |
        KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_NX |
        KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_LARGE |
        KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_GLOBAL |
        KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_USER;
    if ((flags & ~kKnownFlags) != 0U) {
        names.push_back(std::wstring(L"unknown=") + hexText(flags & ~kKnownFlags));
    }
    return joinNames(names);
}

// memoryEvidenceOwnerText maps evidence owner classes. Input is a row owner id;
// output follows the R0 loaded-module/nonmodule/bigpool/system-PTE/MDL buckets.
std::wstring memoryEvidenceOwnerText(const std::uint32_t ownerKind) {
    switch (ownerKind) {
    case KSWORD_ARK_MEMORY_EVIDENCE_OWNER_UNKNOWN: return L"Unknown";
    case KSWORD_ARK_MEMORY_EVIDENCE_OWNER_LOADED_MODULE: return L"LoadedModule";
    case KSWORD_ARK_MEMORY_EVIDENCE_OWNER_NONMODULE: return L"Non-module";
    case KSWORD_ARK_MEMORY_EVIDENCE_OWNER_BIGPOOL: return L"BigPool";
    case KSWORD_ARK_MEMORY_EVIDENCE_OWNER_SYSTEM_PTE: return L"SystemPte";
    case KSWORD_ARK_MEMORY_EVIDENCE_OWNER_MDL_LIKE: return L"MdlLike";
    default: return std::wstring(L"Unknown(") + std::to_wstring(ownerKind) + L")";
    }
}

// memoryEvidenceRiskText expands memory evidence risk bits. Input is a R0 risk
// mask; output highlights RWX, non-module executable, executable pool and owner
// missing conditions.
std::wstring memoryEvidenceRiskText(const std::uint32_t flags) {
    if (flags == 0U) {
        return L"正常";
    }
    std::vector<std::wstring> names;
    appendFlagName(names, flags, KSWORD_ARK_MEMORY_EVIDENCE_RISK_RWX, L"RWX");
    appendFlagName(names, flags, KSWORD_ARK_MEMORY_EVIDENCE_RISK_NONMODULE_EXECUTABLE, L"非模块执行");
    appendFlagName(names, flags, KSWORD_ARK_MEMORY_EVIDENCE_RISK_MODULE_NON_TEXT_EXECUTABLE, L"模块非text执行");
    appendFlagName(names, flags, KSWORD_ARK_MEMORY_EVIDENCE_RISK_EXECUTABLE_POOL, L"执行池");
    appendFlagName(names, flags, KSWORD_ARK_MEMORY_EVIDENCE_RISK_LARGE_EXECUTABLE, L"大页执行");
    appendFlagName(names, flags, KSWORD_ARK_MEMORY_EVIDENCE_RISK_OWNER_MISSING, L"Owner缺失");
    const std::uint32_t kKnownFlags =
        KSWORD_ARK_MEMORY_EVIDENCE_RISK_RWX |
        KSWORD_ARK_MEMORY_EVIDENCE_RISK_NONMODULE_EXECUTABLE |
        KSWORD_ARK_MEMORY_EVIDENCE_RISK_MODULE_NON_TEXT_EXECUTABLE |
        KSWORD_ARK_MEMORY_EVIDENCE_RISK_EXECUTABLE_POOL |
        KSWORD_ARK_MEMORY_EVIDENCE_RISK_LARGE_EXECUTABLE |
        KSWORD_ARK_MEMORY_EVIDENCE_RISK_OWNER_MISSING;
    if ((flags & ~kKnownFlags) != 0U) {
        names.push_back(std::wstring(L"unknown=") + hexText(flags & ~kKnownFlags));
    }
    return joinNames(names);
}

// driverIntegrityStatusText maps aggregate integrity query statuses. Input is
// KSWORD_ARK_DRIVER_INTEGRITY_STATUS_*; output is used for DriverIntegrity and
// CPU/IDT integrity pages.
std::wstring driverIntegrityStatusText(const std::uint32_t status) {
    switch (status) {
    case KSWORD_ARK_DRIVER_INTEGRITY_STATUS_UNAVAILABLE: return L"Unavailable";
    case KSWORD_ARK_DRIVER_INTEGRITY_STATUS_OK: return L"OK";
    case KSWORD_ARK_DRIVER_INTEGRITY_STATUS_PARTIAL: return L"Partial";
    case KSWORD_ARK_DRIVER_INTEGRITY_STATUS_NOT_FOUND: return L"Not found";
    case KSWORD_ARK_DRIVER_INTEGRITY_STATUS_BUFFER_TOO_SMALL: return L"Buffer too small";
    case KSWORD_ARK_DRIVER_INTEGRITY_STATUS_QUERY_FAILED: return L"Query failed";
    default: return std::wstring(L"Unknown(") + std::to_wstring(status) + L")";
    }
}

// driverIntegrityClassText names the evidence-class buckets used by the original
// KswordARK integrity Dock. Input is one evidenceClass id; output identifies
// DriverObject, LDR, CPU, IDT, MSR, and optional global rows.
std::wstring driverIntegrityClassText(const std::uint32_t evidenceClass) {
    switch (evidenceClass) {
    case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MODULE_VIEW: return L"ModuleView";
    case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_PS_LOADED_MODULES: return L"PsLoadedModuleList";
    case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DRIVER_OBJECT: return L"DriverObject";
    case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DRIVER_SECTION: return L"DriverSection";
    case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MAJOR_FUNCTION: return L"MajorFunction";
    case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_FAST_IO: return L"FastIo";
    case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DEVICE_CHAIN: return L"DeviceChain";
    case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_SERVICE: return L"Service";
    case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_CPU_CONTROL: return L"CPU";
    case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DESCRIPTOR_TABLE: return L"Descriptor";
    case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MSR_ENTRY: return L"MSR";
    case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_IDT_HANDLER: return L"IDT";
    case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_OPTIONAL_GLOBAL: return L"OptionalGlobal";
    default: return std::wstring(L"Class(") + std::to_wstring(evidenceClass) + L")";
    }
}

// driverIntegritySourceText expands evidence source bits. Input is a R0 source
// mask; output names module lists, DriverObject, service registry, CPU, IDT/GDT,
// MSR, and DynData sources.
std::wstring driverIntegritySourceText(const std::uint32_t flags) {
    std::vector<std::wstring> names;
    appendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SYSTEM_MODULE, L"SystemModule");
    appendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_AUXKLIB, L"AuxKlib");
    appendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_PS_LOADED_MODULES, L"PsLoadedModules");
    appendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_OBJECT, L"DriverObject");
    appendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_SECTION, L"DriverSection");
    appendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SERVICE_REGISTRY, L"ServiceRegistry");
    appendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_CPU_REGISTER, L"CPU");
    appendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_IDT, L"IDT");
    appendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_GDT, L"GDT");
    appendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_MSR, L"MSR");
    appendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DYNDATA, L"DynData");
    const std::uint32_t kKnownFlags =
        KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SYSTEM_MODULE |
        KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_AUXKLIB |
        KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_PS_LOADED_MODULES |
        KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_OBJECT |
        KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_SECTION |
        KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SERVICE_REGISTRY |
        KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_CPU_REGISTER |
        KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_IDT |
        KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_GDT |
        KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_MSR |
        KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DYNDATA;
    if ((flags & ~kKnownFlags) != 0U) {
        names.push_back(std::wstring(L"unknown=") + hexText(flags & ~kKnownFlags));
    }
    return joinNames(names);
}

// driverIntegrityRiskText expands integrity risk bits. Input is a R0 risk mask;
// output surfaces owner mismatch, code outside image, service gaps, CPU control
// risks, descriptor issues, DynData gaps and truncation.
std::wstring driverIntegrityRiskText(const std::uint32_t flags) {
    std::vector<std::wstring> names;
    appendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_UNAVAILABLE, L"不可用");
    appendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_QUERY_FAILED, L"查询失败");
    appendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_MODULE_UNRESOLVED, L"模块未解析");
    appendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_OWNER_MISMATCH, L"Owner不匹配");
    appendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_OUTSIDE_DRIVER_IMAGE, L"外跳");
    appendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_SECTION_MISMATCH, L"Section不匹配");
    appendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_SERVICE_MISSING, L"服务缺失");
    appendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_EMPTY_UNLOAD, L"Unload为空");
    appendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_DEVICE_LOOP, L"Device环");
    appendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_ATTACHED_LOOP, L"Attached环");
    appendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_CROSS_DRIVER_ATTACH, L"跨驱动挂接");
    appendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_NULL_POINTER, L"空指针");
    appendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_NON_CORE_OWNER, L"IDT外部Owner");
    appendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_WP_DISABLED, L"WP关闭");
    appendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_NXE_DISABLED, L"NXE关闭");
    appendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_SMEP_DISABLED, L"SMEP关闭");
    appendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_SMAP_DISABLED, L"SMAP关闭");
    appendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_DESCRIPTOR_INVALID, L"描述符异常");
    appendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_DYNDATA_UNAVAILABLE, L"DynData缺失");
    appendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_TRUNCATED, L"截断");
    const std::uint32_t kKnownFlags =
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_UNAVAILABLE |
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_QUERY_FAILED |
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_MODULE_UNRESOLVED |
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_OWNER_MISMATCH |
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_OUTSIDE_DRIVER_IMAGE |
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_SECTION_MISMATCH |
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_SERVICE_MISSING |
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_EMPTY_UNLOAD |
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_DEVICE_LOOP |
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_ATTACHED_LOOP |
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_CROSS_DRIVER_ATTACH |
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_NULL_POINTER |
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_NON_CORE_OWNER |
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_WP_DISABLED |
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_NXE_DISABLED |
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_SMEP_DISABLED |
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_SMAP_DISABLED |
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_DESCRIPTOR_INVALID |
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_DYNDATA_UNAVAILABLE |
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_TRUNCATED;
    if ((flags & ~kKnownFlags) != 0U) {
        names.push_back(std::wstring(L"unknown=") + hexText(flags & ~kKnownFlags));
    }
    return joinNamesOrNormal(names);
}

// crossViewStatusText maps process/thread cross-view aggregate statuses. Input
// is KSWORD_ARK_CROSSVIEW_STATUS_*; output states whether evidence is complete,
// partial, capability-limited, or failed.
std::wstring crossViewStatusText(const std::uint32_t status) {
    switch (status) {
    case KSWORD_ARK_CROSSVIEW_STATUS_UNKNOWN: return L"Unknown";
    case KSWORD_ARK_CROSSVIEW_STATUS_OK: return L"OK";
    case KSWORD_ARK_CROSSVIEW_STATUS_PARTIAL: return L"Partial";
    case KSWORD_ARK_CROSSVIEW_STATUS_CAPABILITY_MISSING: return L"Capability missing";
    case KSWORD_ARK_CROSSVIEW_STATUS_READ_FAILED: return L"Read failed";
    default: return std::wstring(L"Unknown(") + std::to_wstring(status) + L")";
    }
}

// crossViewSourceText expands source evidence bits. Input is a process/thread
// cross-view source mask; output names public walk, active list, CID table, and
// thread-list sources.
std::wstring crossViewSourceText(const std::uint32_t flags) {
    std::vector<std::wstring> names;
    appendFlagName(names, flags, KSWORD_ARK_CROSSVIEW_SOURCE_PUBLIC_WALK, L"public walk");
    appendFlagName(names, flags, KSWORD_ARK_CROSSVIEW_SOURCE_ACTIVE_LIST, L"active list");
    appendFlagName(names, flags, KSWORD_ARK_CROSSVIEW_SOURCE_CID_TABLE, L"cid table");
    appendFlagName(names, flags, KSWORD_ARK_CROSSVIEW_SOURCE_THREAD_LIST, L"thread list");
    const std::uint32_t kKnownFlags =
        KSWORD_ARK_CROSSVIEW_SOURCE_PUBLIC_WALK |
        KSWORD_ARK_CROSSVIEW_SOURCE_ACTIVE_LIST |
        KSWORD_ARK_CROSSVIEW_SOURCE_CID_TABLE |
        KSWORD_ARK_CROSSVIEW_SOURCE_THREAD_LIST;
    if ((flags & ~kKnownFlags) != 0U) {
        names.push_back(std::wstring(L"unknown=") + hexText(flags & ~kKnownFlags));
    }
    return joinNames(names);
}

// crossViewAnomalyText expands DKOM anomaly bits. Input is a row anomaly mask;
// output names CID-only, active-only, hidden/missing, orphan, start-address, and
// dangling-object evidence.
std::wstring crossViewAnomalyText(const std::uint32_t flags) {
    std::vector<std::wstring> names;
    appendFlagName(names, flags, KSWORD_ARK_CROSSVIEW_ANOMALY_CID_ONLY, L"CID-only");
    appendFlagName(names, flags, KSWORD_ARK_CROSSVIEW_ANOMALY_ACTIVE_ONLY, L"Active-only");
    appendFlagName(names, flags, KSWORD_ARK_CROSSVIEW_ANOMALY_MISSING_FROM_ACTIVE_LIST, L"缺 ActiveList");
    appendFlagName(names, flags, KSWORD_ARK_CROSSVIEW_ANOMALY_MISSING_FROM_CID_TABLE, L"缺 CID");
    appendFlagName(names, flags, KSWORD_ARK_CROSSVIEW_ANOMALY_THREAD_ORPHAN, L"孤儿线程");
    appendFlagName(names, flags, KSWORD_ARK_CROSSVIEW_ANOMALY_THREAD_NOT_IN_PROCESS_LIST, L"线程进程缺失");
    appendFlagName(names, flags, KSWORD_ARK_CROSSVIEW_ANOMALY_START_ADDRESS_OUTSIDE_MODULE, L"入口出模块");
    appendFlagName(names, flags, KSWORD_ARK_CROSSVIEW_ANOMALY_DANGLING_OBJECT, L"悬空对象");
    const std::uint32_t kKnownFlags =
        KSWORD_ARK_CROSSVIEW_ANOMALY_CID_ONLY |
        KSWORD_ARK_CROSSVIEW_ANOMALY_ACTIVE_ONLY |
        KSWORD_ARK_CROSSVIEW_ANOMALY_MISSING_FROM_ACTIVE_LIST |
        KSWORD_ARK_CROSSVIEW_ANOMALY_MISSING_FROM_CID_TABLE |
        KSWORD_ARK_CROSSVIEW_ANOMALY_THREAD_ORPHAN |
        KSWORD_ARK_CROSSVIEW_ANOMALY_THREAD_NOT_IN_PROCESS_LIST |
        KSWORD_ARK_CROSSVIEW_ANOMALY_START_ADDRESS_OUTSIDE_MODULE |
        KSWORD_ARK_CROSSVIEW_ANOMALY_DANGLING_OBJECT;
    if ((flags & ~kKnownFlags) != 0U) {
        names.push_back(std::wstring(L"unknown=") + hexText(flags & ~kKnownFlags));
    }
    return joinNamesOrNormal(names);
}

// dynV4StatusText expands per-module/profile status bits. Input is the v4
// statusFlags mask; output distinguishes exact identity match, applied profile,
// required completeness, optional degradation, rejected identity, and validation
// failure without guessing profile state in R3.
std::wstring dynV4StatusText(const std::uint32_t flags) {
    std::vector<std::wstring> names;
    appendFlagName(names, flags, KSW_DYN_V4_STATUS_FLAG_IDENTITY_MATCHED, L"Identity matched");
    appendFlagName(names, flags, KSW_DYN_V4_STATUS_FLAG_PROFILE_APPLIED, L"Profile applied");
    appendFlagName(names, flags, KSW_DYN_V4_STATUS_FLAG_REQUIRED_COMPLETE, L"Required complete");
    appendFlagName(names, flags, KSW_DYN_V4_STATUS_FLAG_OPTIONAL_DEGRADED, L"Optional degraded");
    appendFlagName(names, flags, KSW_DYN_V4_STATUS_FLAG_IDENTITY_REJECTED, L"Identity rejected");
    appendFlagName(names, flags, KSW_DYN_V4_STATUS_FLAG_VALIDATION_FAILED, L"Validation failed");
    const std::uint32_t kKnownFlags =
        KSW_DYN_V4_STATUS_FLAG_IDENTITY_MATCHED |
        KSW_DYN_V4_STATUS_FLAG_PROFILE_APPLIED |
        KSW_DYN_V4_STATUS_FLAG_REQUIRED_COMPLETE |
        KSW_DYN_V4_STATUS_FLAG_OPTIONAL_DEGRADED |
        KSW_DYN_V4_STATUS_FLAG_IDENTITY_REJECTED |
        KSW_DYN_V4_STATUS_FLAG_VALIDATION_FAILED;
    if ((flags & ~kKnownFlags) != 0U) {
        names.push_back(std::wstring(L"unknown=") + hexText(flags & ~kKnownFlags));
    }
    return joinNames(names);
}

// dynV4ItemKindText maps v4 item kinds to schema names. Input is the protocol
// itemKind value; output mirrors docs/pdb_r0_audit_prep item type labels.
const wchar_t* dynV4ItemKindText(const std::uint32_t itemKind) {
    switch (itemKind) {
    case KSW_DYN_V4_ITEM_KIND_STRUCT_OFFSET: return L"StructOffset";
    case KSW_DYN_V4_ITEM_KIND_GLOBAL_RVA: return L"GlobalRva";
    case KSW_DYN_V4_ITEM_KIND_FUNCTION_RVA: return L"FunctionRva";
    case KSW_DYN_V4_ITEM_KIND_ENUM_VALUE: return L"EnumValue";
    case KSW_DYN_V4_ITEM_KIND_TYPE_SIZE: return L"TypeSize";
    case KSW_DYN_V4_ITEM_KIND_BIT_FIELD: return L"BitField";
    case KSW_DYN_V4_ITEM_KIND_LIST_HEAD_GLOBAL: return L"ListHeadGlobal";
    default: return L"Unknown";
    }
}

// dynV4MissingKindText names required/optional missing item buckets. Input is a
// protocol missing kind; output is display-only and never changes gating logic.
const wchar_t* dynV4MissingKindText(const std::uint32_t missingKind) {
    switch (missingKind) {
    case KSW_DYN_V4_MISSING_KIND_REQUIRED: return L"Required";
    case KSW_DYN_V4_MISSING_KIND_OPTIONAL: return L"Optional";
    default: return L"Unknown";
    }
}

// dynV4ItemFlagsText expands v4 item flags into profile semantics. Input is a
// KSW_DYN_V4_ITEM_FLAG_* mask; processing names required/optional bits and
// preserves unknown bits as hexadecimal; output is display-only text.
std::wstring dynV4ItemFlagsText(const std::uint32_t flags) {
    std::vector<std::wstring> names;
    appendFlagName(names, flags, KSW_DYN_V4_ITEM_FLAG_REQUIRED, L"Required");
    appendFlagName(names, flags, KSW_DYN_V4_ITEM_FLAG_OPTIONAL, L"Optional");
    const std::uint32_t kKnownFlags =
        KSW_DYN_V4_ITEM_FLAG_REQUIRED |
        KSW_DYN_V4_ITEM_FLAG_OPTIONAL;
    if ((flags & ~kKnownFlags) != 0U) {
        names.push_back(std::wstring(L"unknown=") + hexText(flags & ~kKnownFlags));
    }
    return joinNames(names);
}

// dynV4ItemValueText formats the 64-bit value carried by one accepted v4 item.
// Input is the shared item packet; processing combines valueHigh/valueLow and
// keeps aux values visible; output is a compact table/detail string.
std::wstring dynV4ItemValueText(const KSW_DYN_V4_ITEM_PACKET& item) {
    const std::uint64_t kValue =
        (static_cast<std::uint64_t>(item.valueHigh) << 32U) |
        static_cast<std::uint64_t>(item.valueLow);
    std::wostringstream stream;
    stream << hexText(kValue)
           << L" aux0=" << hexText(item.aux0)
           << L" aux1=" << hexText(item.aux1)
           << L" aux2=" << hexText(item.aux2)
           << L" aux3=" << hexText(item.aux3);
    return stream.str();
}

// cidObjectKindText names CID table object kinds. Input is R0 expectedObjectKind;
// output is a compact label used by the CID table summary page.
const wchar_t* cidObjectKindText(const std::uint32_t kind) {
    switch (kind) {
    case KSWORD_ARK_CID_OBJECT_KIND_PROCESS: return L"Process";
    case KSWORD_ARK_CID_OBJECT_KIND_THREAD: return L"Thread";
    case KSWORD_ARK_CID_OBJECT_KIND_UNKNOWN:
    default: return L"Unknown";
    }
}

// cidEnumStatusText names aggregate CID table enumeration statuses. Input is the
// protocol status; output explains capability/PDB degradation without implying
// a malicious object when R0 only returned partial evidence.
const wchar_t* cidEnumStatusText(const std::uint32_t status) {
    switch (status) {
    case KSWORD_ARK_CID_ENUM_STATUS_OK: return L"OK";
    case KSWORD_ARK_CID_ENUM_STATUS_PARTIAL: return L"Partial";
    case KSWORD_ARK_CID_ENUM_STATUS_DYNDATA_MISSING: return L"DynData missing";
    case KSWORD_ARK_CID_ENUM_STATUS_PSPCID_UNAVAILABLE: return L"PspCidTable unavailable";
    case KSWORD_ARK_CID_ENUM_STATUS_TYPE_UNAVAILABLE: return L"Type unavailable";
    case KSWORD_ARK_CID_ENUM_STATUS_BUFFER_TRUNCATED: return L"Buffer truncated";
    case KSWORD_ARK_CID_ENUM_STATUS_BUDGET_EXHAUSTED: return L"Budget exhausted";
    case KSWORD_ARK_CID_ENUM_STATUS_UNAVAILABLE:
    default: return L"Unavailable";
    }
}

// objectSummaryStatusText names the single-object metadata query status. Input
// is KSWORD_ARK_OBJECT_SUMMARY_STATUS_*; output is used in the CID summary page
// and does not alter object lifetime or reference counts.
const wchar_t* objectSummaryStatusText(const std::uint32_t status) {
    switch (status) {
    case KSWORD_ARK_OBJECT_SUMMARY_STATUS_OK: return L"OK";
    case KSWORD_ARK_OBJECT_SUMMARY_STATUS_PARTIAL: return L"Partial";
    case KSWORD_ARK_OBJECT_SUMMARY_STATUS_UNSUPPORTED_TARGET: return L"Unsupported target";
    case KSWORD_ARK_OBJECT_SUMMARY_STATUS_LOOKUP_FAILED: return L"Lookup failed";
    case KSWORD_ARK_OBJECT_SUMMARY_STATUS_TYPE_QUERY_FAILED: return L"Type query failed";
    case KSWORD_ARK_OBJECT_SUMMARY_STATUS_COUNTERS_UNAVAILABLE: return L"Counters unavailable";
    case KSWORD_ARK_OBJECT_SUMMARY_STATUS_UNAVAILABLE:
    default: return L"Unavailable";
    }
}

// objectHeaderStatusText names ObjectHeader profile readiness. Input is
// KSWORD_ARK_OBJECT_HEADER_STATUS_*; output explains whether type/counter
// fields are trustworthy for read-only display.
const wchar_t* objectHeaderStatusText(const std::uint32_t status) {
    switch (status) {
    case KSWORD_ARK_OBJECT_HEADER_STATUS_PROFILE_MISSING: return L"Profile missing";
    case KSWORD_ARK_OBJECT_HEADER_STATUS_PARTIAL_PROFILE: return L"Partial profile";
    case KSWORD_ARK_OBJECT_HEADER_STATUS_AVAILABLE: return L"Available";
    case KSWORD_ARK_OBJECT_HEADER_STATUS_UNAVAILABLE:
    default: return L"Unavailable";
    }
}

// cidEntryFlagsText expands CID row anomaly flags. Input is one entry flag mask;
// output highlights dangling/type-mismatch/reference state for read-only audit.
std::wstring cidEntryFlagsText(const std::uint32_t flags) {
    std::vector<std::wstring> names;
    appendFlagName(names, flags, KSWORD_ARK_CID_ENTRY_FLAG_DANGLING, L"Dangling");
    appendFlagName(names, flags, KSWORD_ARK_CID_ENTRY_FLAG_TYPE_MISMATCH, L"Type mismatch");
    appendFlagName(names, flags, KSWORD_ARK_CID_ENTRY_FLAG_REFERENCED, L"Referenced");
    const std::uint32_t kKnownFlags =
        KSWORD_ARK_CID_ENTRY_FLAG_DANGLING |
        KSWORD_ARK_CID_ENTRY_FLAG_TYPE_MISMATCH |
        KSWORD_ARK_CID_ENTRY_FLAG_REFERENCED;
    if ((flags & ~kKnownFlags) != 0U) {
        names.push_back(std::wstring(L"unknown=") + hexText(flags & ~kKnownFlags));
    }
    return joinNames(names);
}

// ipcSummaryStatusText names R0 IPC summary states. Input is one protocol status
// value; output is a human-readable downgrade reason for IPC/ALPC/pipe rows.
const wchar_t* ipcSummaryStatusText(const std::uint32_t status) {
    switch (status) {
    case KSWORD_ARK_IPC_SUMMARY_STATUS_OK: return L"OK";
    case KSWORD_ARK_IPC_SUMMARY_STATUS_PARTIAL: return L"Partial";
    case KSWORD_ARK_IPC_SUMMARY_STATUS_STUB: return L"LegacyStub(旧驱动占位)";
    case KSWORD_ARK_IPC_SUMMARY_STATUS_FAILED: return L"Failed";
    case KSWORD_ARK_IPC_SUMMARY_STATUS_UNAVAILABLE:
    default: return L"Unavailable";
    }
}

// cpuFeatureText renders KSWORD_ARK_CPU_FEATURE_* bits as compact badges. Input
// is the R0 CPUID feature mask; output is suitable for the CPU hardware page and
// falls back to "None" when no stable feature bits were returned.
std::wstring cpuFeatureText(const std::uint64_t flags) {
    std::vector<std::wstring> names;
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_SSE3, L"SSE3");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_PCLMULQDQ, L"PCLMULQDQ");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_VMX, L"VMX");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_SSSE3, L"SSSE3");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_FMA, L"FMA");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_SSE41, L"SSE4.1");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_SSE42, L"SSE4.2");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_AES, L"AES");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_XSAVE, L"XSAVE");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_OSXSAVE, L"OSXSAVE");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_AVX, L"AVX");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_HYPERVISOR, L"Hypervisor");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_MSR, L"MSR");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_PAE, L"PAE");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_MCE, L"MCE");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_CX8, L"CX8");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_APIC, L"APIC");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_SEP, L"SEP");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_MTRR, L"MTRR");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_PGE, L"PGE");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_MCA, L"MCA");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_CMOV, L"CMOV");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_PAT, L"PAT");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_PSE36, L"PSE36");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_CLFSH, L"CLFSH");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_MMX, L"MMX");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_FXSR, L"FXSR");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_SSE, L"SSE");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_SSE2, L"SSE2");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_FSGSBASE, L"FSGSBASE");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_BMI1, L"BMI1");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_HLE, L"HLE");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_AVX2, L"AVX2");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_SMEP, L"SMEP");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_BMI2, L"BMI2");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_ERMS, L"ERMS");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_INVPCID, L"INVPCID");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_RTM, L"RTM");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_AVX512F, L"AVX512F");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_RDSEED, L"RDSEED");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_ADX, L"ADX");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_SMAP, L"SMAP");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_CLFLUSHOPT, L"CLFLUSHOPT");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_CLWB, L"CLWB");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_UMIP, L"UMIP");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_PKU, L"PKU");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_OSPKE, L"OSPKE");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_RDRAND, L"RDRAND");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_RDTSCP, L"RDTSCP");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_NX, L"NX");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_LM, L"LM");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_INVARIANT_TSC, L"InvariantTSC");
    appendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_LAHF_LM, L"LAHF_LM");
    return joinNames(names);
}

// keyboardEnumStatusText maps win32k keyboard enumeration statuses. Input is a
// KSWORD_ARK_KEYBOARD_ENUM_STATUS_* value; output is used by hotkey/hook pages.
std::wstring keyboardEnumStatusText(const std::uint32_t status) {
    switch (status) {
    case KSWORD_ARK_KEYBOARD_ENUM_STATUS_UNKNOWN: return L"Unknown";
    case KSWORD_ARK_KEYBOARD_ENUM_STATUS_OK: return L"OK";
    case KSWORD_ARK_KEYBOARD_ENUM_STATUS_PARTIAL: return L"Partial";
    case KSWORD_ARK_KEYBOARD_ENUM_STATUS_UNSUPPORTED: return L"Unsupported";
    case KSWORD_ARK_KEYBOARD_ENUM_STATUS_WIN32K_NOT_FOUND: return L"win32k not found";
    case KSWORD_ARK_KEYBOARD_ENUM_STATUS_PATTERN_NOT_FOUND: return L"pattern not found";
    case KSWORD_ARK_KEYBOARD_ENUM_STATUS_SESSION_UNAVAILABLE: return L"session unavailable";
    case KSWORD_ARK_KEYBOARD_ENUM_STATUS_BUFFER_TRUNCATED: return L"buffer truncated";
    case KSWORD_ARK_KEYBOARD_ENUM_STATUS_READ_FAILED: return L"read failed";
    default: return std::wstring(L"Unknown(") + std::to_wstring(status) + L")";
    }
}

// keyboardSourceText names hotkey/hook source chains. Input is a source id from
// R0; output identifies hotkey table, thread hook chain, or global hook chain.
std::wstring keyboardSourceText(const std::uint32_t source) {
    switch (source) {
    case KSWORD_ARK_KEYBOARD_SOURCE_WIN32K_HOTKEY_TABLE: return L"win32k hotkey table";
    case KSWORD_ARK_KEYBOARD_SOURCE_WIN32K_THREAD_HOOK_CHAIN: return L"thread hook chain";
    case KSWORD_ARK_KEYBOARD_SOURCE_WIN32K_GLOBAL_HOOK_CHAIN: return L"global hook chain";
    default: return std::wstring(L"Unknown(") + std::to_wstring(source) + L")";
    }
}

// keyboardHookScopeText maps hook scope values. Input is a hook scope id; output
// distinguishes thread/global hooks.
std::wstring keyboardHookScopeText(const std::uint32_t scope) {
    switch (scope) {
    case KSWORD_ARK_KEYBOARD_HOOK_SCOPE_UNKNOWN: return L"Unknown";
    case KSWORD_ARK_KEYBOARD_HOOK_SCOPE_THREAD: return L"Thread";
    case KSWORD_ARK_KEYBOARD_HOOK_SCOPE_GLOBAL: return L"Global";
    default: return std::wstring(L"Unknown(") + std::to_wstring(scope) + L")";
    }
}

// keyboardHookTypeText maps WH_KEYBOARD and WH_KEYBOARD_LL constants. Input is
// a hook type id; output keeps unknown types visible by number.
std::wstring keyboardHookTypeText(const std::uint32_t type) {
    switch (type) {
    case KSWORD_ARK_KEYBOARD_HOOK_TYPE_KEYBOARD: return L"WH_KEYBOARD";
    case KSWORD_ARK_KEYBOARD_HOOK_TYPE_KEYBOARD_LL: return L"WH_KEYBOARD_LL";
    default: return std::wstring(L"Hook(") + std::to_wstring(type) + L")";
    }
}

// appendCallbackRuntimeRows expands KSWORD_ARK_CALLBACK_RUNTIME_STATE into
// operator-friendly rows. Inputs are one state snapshot, an optional source
// label, and a UI filter; processing appends status/rule/registration rows;
// output is written to the common KernelOperationResult table.
void appendCallbackRuntimeRows(
    KernelOperationResult& result,
    const KSWORD_ARK_CALLBACK_RUNTIME_STATE& state,
    const std::wstring& filter,
    const std::wstring& source) {
    pushFilteredRow(result, makeResultRow({
        { L"Source", source },
        { L"Section", L"Runtime" },
        { L"Size", std::to_wstring(state.size) },
        { L"Version", std::to_wstring(state.version) },
        { L"DriverOnline", boolText(state.driverOnline != 0) },
        { L"GlobalEnabled", boolText(state.globalEnabled != 0) },
        { L"RulesApplied", boolText(state.rulesApplied != 0) },
        { L"Health", state.driverOnline != 0 && state.globalEnabled != 0 ? L"Active" : L"Disabled/Offline" },
    }, L"驱动回调运行态总览。"), filter);

    pushFilteredRow(result, makeResultRow({
        { L"Source", source },
        { L"Section", L"Callbacks" },
        { L"RegisteredMask", hexText(state.callbacksRegisteredMask) },
        { L"RegisteredText", callbackRegisteredMaskText(state.callbacksRegisteredMask) },
    }, L"已注册的 R0 回调类型。"), filter);

    // The AskUser queue is not a kernel callback, but like the five-tuple callbacks, it may be absent during a degraded boot. Therefore,
    // the original state is provided separately to avoid misjudging 'rules set to ask the user but no popup appeared' as a software defect.
    pushFilteredRow(result, makeResultRow({
        { L"Source", source },
        { L"Section", L"AskUserQueue" },
        { L"Available", boolText(state.waitQueueStatus == 0) },
        { L"Status", hexText(static_cast<std::uint32_t>(state.waitQueueStatus)) },
    }, L"用户询问队列不可用时，Ask 规则回落到规则自身的默认决策。"), filter);

    const struct {
        const wchar_t* name;
        std::uint32_t bit;
        long registerStatus;
        bool hasRegisterStatus;
    } kCallbackTypes[] = {
        { L"Registry", 0x00000001UL, state.registryCallbackStatus, true },
        { L"Process", 0x00000002UL, state.processCallbackStatus, true },
        { L"Thread", 0x00000004UL, state.threadCallbackStatus, true },
        { L"Image", 0x00000008UL, state.imageCallbackStatus, true },
        { L"Object", 0x00000010UL, state.objectCallbackStatus, true },
        // Minifilter registration status uses a dedicated minifilter query interface and is not included in this structure.
        { L"Minifilter", 0x00000020UL, 0L, false },
    };
    for (const auto& callbackType : kCallbackTypes) {
        pushFilteredRow(result, makeResultRow({
            { L"Source", source },
            { L"Section", L"CallbackType" },
            { L"Name", callbackType.name },
            { L"Mask", hexText(callbackType.bit) },
            { L"Registered", boolText((state.callbacksRegisteredMask & callbackType.bit) != 0U) },
            // On registration failure, this contains the raw NTSTATUS returned by the kernel, such as altitude conflicts or slot exhaustion.
            { L"Status", callbackType.hasRegisterStatus
                ? hexText(static_cast<std::uint32_t>(callbackType.registerStatus))
                : std::wstring(L"-") },
        }), filter);
    }

    pushFilteredRow(result, makeResultRow({
        { L"Source", source },
        { L"Section", L"Rules" },
        { L"Groups", std::to_wstring(state.groupCount) },
        { L"Rules", std::to_wstring(state.ruleCount) },
        { L"RuleVersion", std::to_wstring(state.appliedRuleVersion) },
        { L"AppliedAt", utc100nsToLocalText(state.appliedAtUtc100ns) },
        { L"AppliedAtRaw", hexText(state.appliedAtUtc100ns) },
    }, L"当前已应用的回调规则快照。"), filter);

    pushFilteredRow(result, makeResultRow({
        { L"Source", source },
        { L"Section", L"PendingDecision" },
        { L"Pending", std::to_wstring(state.pendingDecisionCount) },
        { L"WaitingReceivers", std::to_wstring(state.waitingReceiverCount) },
        { L"Attention", state.pendingDecisionCount != 0U ? L"有等待用户决策的回调事件" : L"无等待决策" },
    }, L"右键可取消全部等待决策。"), filter);
}

// makeActionError returns a structured failure packet for invalid UI action
// parameters. Inputs are action request and reason; output is rendered by the
// normal kernel result table.
KernelOperationResult makeActionError(const KernelActionRequest& request, const std::wstring& reason) {
    KernelOperationResult result;
    result.supported = true;
    result.success = false;
    result.destructiveAction = request.actionId != KernelActionId::kNone;
    result.message = reason;
    result.rows.push_back(makeResultRow({
        { L"功能", toDisplayName(request.featureId) },
        { L"动作", std::to_wstring(static_cast<std::uint32_t>(request.actionId)) },
        { L"状态", L"参数无效" },
    }, reason));
    return result;
}

// applyIoSummary fills common result metadata from ArkDriverClient IoResult.
// Inputs are the original request, operation label, IoResult and result object;
// processing writes success/message and an overview row; no value is returned.
void applyIoSummary(
    const KernelRequest& request,
    const std::wstring& operation,
    const ksword::ark::IoResult& io,
    KernelOperationResult& result) {
    result.supported = true;
    result.success = io.ok;
    result.message = operation + (io.ok ? L" 查询完成。" : L" 查询失败。") + L" " + utf8ToWide(io.message);
    result.rows.push_back(makeResultRow({
        { L"功能", toDisplayName(request.featureId) },
        { L"操作", operation },
        { L"IO", io.ok ? L"OK" : L"FAIL" },
        { L"Win32", std::to_wstring(io.win32Error) },
        { L"Bytes", std::to_wstring(io.bytesReturned) },
    }, utf8ToWide(io.message)));
}

// makeUnsupportedResult reports impossible facade routes accurately. Inputs are
// a request and a concrete message; output is a diagnostic row rather than fake
// kernel data.
KernelOperationResult makeUnsupportedResult(const KernelRequest& request, const std::wstring& message) {
    KernelOperationResult result;
    result.supported = false;
    result.success = false;
    result.message = message;
    result.rows.push_back(makeResultRow({
        { L"功能", toDisplayName(request.featureId) },
        { L"数据源", L"KernelFacade" },
        { L"状态", L"Unsupported route" },
    }, message));
    return result;
}

// isArkDriverBacked reports whether a retained feature has a real
// ArkDriverClient read-only query in this light project. Input is a feature id;
// output controls facade routing only.
bool isArkDriverBacked(const KernelFeatureId id) {
    switch (id) {
    case KernelFeatureId::kSsdt:
    case KernelFeatureId::kShadowSsdt:
    case KernelFeatureId::kInlineHook:
    case KernelFeatureId::kIatEatHook:
    case KernelFeatureId::kDynData:
    case KernelFeatureId::kDriverStatus:
    case KernelFeatureId::kCallbackIntercept:
    case KernelFeatureId::kCallbackEnumeration:
    case KernelFeatureId::kKernelExecutableMemory:
    case KernelFeatureId::kKernelMemoryEvidence:
    case KernelFeatureId::kProcessCrossView:
    case KernelFeatureId::kThreadCrossView:
    case KernelFeatureId::kDriverIntegrity:
    case KernelFeatureId::kKernelCpuIntegrity:
    case KernelFeatureId::kCpuHardwareSnapshot:
    case KernelFeatureId::kPhysicalMemoryLayout:
    case KernelFeatureId::kMutationAudit:
    case KernelFeatureId::kKeyboardHotkeys:
    case KernelFeatureId::kKeyboardHooks:
    case KernelFeatureId::kDynDataCapabilities:
    case KernelFeatureId::kPdbProfileStatus:
    case KernelFeatureId::kCidTableSummary:
    case KernelFeatureId::kIpcSummary:
    case KernelFeatureId::kHookAuditSummary:
    case KernelFeatureId::kMinifilterBypassPids:
    case KernelFeatureId::kKernelTimerDpc:
    case KernelFeatureId::kIoctlRegistry:
    case KernelFeatureId::kWorkQueueThreads:
    case KernelFeatureId::kSlatIommuAudit:
    case KernelFeatureId::kHvmStatus:
    case KernelFeatureId::kHvmEvents:
    case KernelFeatureId::kDriverDispatchTable:
    case KernelFeatureId::kDriverImageFields:
    case KernelFeatureId::kDriverCommunication:
    case KernelFeatureId::kPlatformAudit:
    case KernelFeatureId::kSystemTimeState:
    case KernelFeatureId::kI8042Audit:
    case KernelFeatureId::kPiDdbCache:
    case KernelFeatureId::kRawDiskSectors:
    case KernelFeatureId::kNetworkTrafficPackets:
        return true;
    default:
        return false;
    }
}

// appendDriverObjectQueryRows expands one ArkDriverClient DriverObject query
// into summary, MajorFunction, and DeviceObject rows. Inputs are the requested
// object name, parsed client response, and result sink; processing formats every
// protocol address as text only; no value is returned because rows are appended.
void appendDriverObjectQueryRows(
    const std::wstring& requestedName,
    const ksword::ark::DriverObjectQueryResult& query,
    KernelOperationResult& result) {
    const std::wstring kDriverName = query.driverName.empty() ? requestedName : query.driverName;
    const bool kQueryOk = isDriverObjectQuerySuccess(query);

    result.rows.push_back(makeResultRow({
        { L"Source", L"R0 DriverObject" },
        { L"Name", kDriverName },
        { L"Type", L"DriverObject" },
        { L"Path", kDriverName },
        { L"DriverName", kDriverName },
        { L"DriverObject", hexText(query.driverObjectAddress) },
        { L"DriverStart", hexText(query.driverStart) },
        { L"DriverSection", hexText(query.driverSection) },
        { L"DriverUnload", hexText(query.driverUnload) },
        { L"DriverSize", hexText(query.driverSize) },
        { L"DriverFlags", hexText(query.driverFlags) },
        { L"ServiceKey", query.serviceKeyName },
        { L"ImagePath", query.imagePath },
        { L"MajorFunctions", std::to_wstring(query.majorFunctionCount) },
        { L"Devices", std::to_wstring(query.returnedDeviceCount) + L"/" + std::to_wstring(query.totalDeviceCount) },
        { L"QueryStatus", std::wstring(driverObjectQueryStatusText(query.queryStatus)) + L" (" + std::to_wstring(query.queryStatus) + L")" },
        { L"IO", query.io.ok ? L"OK" : L"FAIL" },
        { L"Win32", std::to_wstring(query.io.win32Error) },
        { L"LastStatus", hexText(static_cast<std::uint32_t>(query.lastStatus)) },
        { L"FieldFlags", hexText(query.fieldFlags) },
    }, kQueryOk ? query.imagePath : utf8ToWide(query.io.message)));

    if (!kQueryOk) {
        return;
    }

    for (const ksword::ark::DriverMajorFunctionEntry& entry : query.majorFunctions) {
        result.rows.push_back(makeResultRow({
            { L"Source", L"R0 MajorFunction" },
            { L"Name", majorFunctionName(entry.majorFunction) },
            { L"Type", L"MajorFunction" },
            { L"Path", kDriverName },
            { L"DriverName", kDriverName },
            { L"Major", std::to_wstring(entry.majorFunction) },
            { L"Dispatch", hexText(entry.dispatchAddress) },
            { L"Module", entry.moduleName },
            { L"ModuleBase", hexText(entry.moduleBase) },
            { L"Flags", hexText(entry.flags) },
        }, entry.moduleName));
    }

    for (const ksword::ark::DriverDeviceEntry& entry : query.devices) {
        result.rows.push_back(makeResultRow({
            { L"Source", L"R0 DeviceObject" },
            { L"Name", entry.deviceName.empty() ? hexText(entry.deviceObjectAddress) : entry.deviceName },
            { L"Type", entry.relationDepth == 0 ? L"DeviceObject" : L"AttachedDevice" },
            { L"Path", entry.deviceName },
            { L"DriverName", kDriverName },
            { L"DeviceName", entry.deviceName },
            { L"DeviceObject", hexText(entry.deviceObjectAddress) },
            { L"RootDeviceObject", hexText(entry.rootDeviceObjectAddress) },
            { L"AttachedDevice", hexText(entry.attachedDeviceObjectAddress) },
            { L"NextDevice", hexText(entry.nextDeviceObjectAddress) },
            { L"DeviceDriverObject", hexText(entry.driverObjectAddress) },
            { L"DeviceType", hexText(entry.deviceType) },
            { L"Flags", hexText(entry.flags) },
            { L"Characteristics", hexText(entry.characteristics) },
            { L"StackSize", std::to_wstring(entry.stackSize) },
            { L"Alignment", std::to_wstring(entry.alignmentRequirement) },
            { L"Depth", std::to_wstring(entry.relationDepth) },
            { L"NameStatus", hexText(static_cast<std::uint32_t>(entry.nameStatus)) },
        }, entry.deviceName));
    }
}

// queryDeviceDriverObjectsHybrid preserves the native object-manager directory
// view and augments selected \Driver rows with ArkDriverClient DriverObject
// evidence. Input is the UI request; processing queries R3 first, then caps R0
// DriverObject queries to avoid blocking refresh; output is one combined table.
KernelOperationResult queryDeviceDriverObjectsHybrid(const KernelRequest& request) {
    KernelOperationResult result = queryNativeKernelFeature(request);
    std::vector<std::wstring> driverNames;
    driverNames.reserve(64);

    for (const KernelResultRow& row : result.rows) {
        appendUniqueDriverObjectName(driverNames, driverObjectNameFromRow(row));
    }
    appendUniqueDriverObjectName(driverNames, normalizeDriverObjectName(request.filterText, false));

    if (driverNames.empty()) {
        result.rows.push_back(makeResultRow({
            { L"Source", L"R0 DriverObject" },
            { L"Status", L"Skipped" },
            { L"Reason", L"未发现可用于 R0 DriverObject 查询的 \\Driver 条目" },
        }));
        return result;
    }

    const ksword::ark::DriverClient kClient;
    const ksword::ark::DriverCapabilitiesQueryResult kCapability = kClient.queryDriverCapabilities();
    result.rows.push_back(makeResultRow({
        { L"Source", L"R0 DriverObject" },
        { L"R0", kCapability.io.ok ? L"Online" : L"Unavailable" },
        { L"Protocol", std::to_wstring(kCapability.driverProtocolVersion) },
        { L"Win32", std::to_wstring(kCapability.io.win32Error) },
        { L"Queued", std::to_wstring(driverNames.size()) },
    }, kCapability.io.ok ? utf8ToWide(kCapability.lastErrorSummary) : utf8ToWide(kCapability.io.message)));
    if (!kCapability.io.ok) {
        result.message += L" R0 DriverObject 查询跳过：";
        result.message += utf8ToWide(kCapability.io.message);
        return result;
    }

    constexpr std::size_t kMaxDriverObjectQueries = 64;
    const std::size_t kQueryLimit = std::min<std::size_t>(driverNames.size(), kMaxDriverObjectQueries);
    std::size_t okCount = 0;
    std::size_t failCount = 0;
    for (std::size_t index = 0; index < kQueryLimit; ++index) {
        const ksword::ark::DriverObjectQueryResult kQuery = kClient.queryDriverObject(
            driverNames[index],
            KSWORD_ARK_DRIVER_OBJECT_QUERY_FLAG_INCLUDE_ALL,
            KSWORD_ARK_DRIVER_DEVICE_LIMIT_DEFAULT,
            KSWORD_ARK_DRIVER_ATTACHED_LIMIT_DEFAULT);
        if (isDriverObjectQuerySuccess(kQuery)) {
            ++okCount;
        } else {
            ++failCount;
        }
        appendDriverObjectQueryRows(driverNames[index], kQuery, result);
    }
    if (driverNames.size() > kQueryLimit) {
        result.rows.push_back(makeResultRow({
            { L"Source", L"R0 DriverObject" },
            { L"Status", L"Truncated" },
            { L"Shown", std::to_wstring(kQueryLimit) },
            { L"Total", std::to_wstring(driverNames.size()) },
        }));
    }
    result.message += L" R0 DriverObject 查询完成：OK=" + std::to_wstring(okCount) + L"，Failed=" + std::to_wstring(failCount) + L"。";
    return result;
}

// appendTruncationRow records when a driver result is intentionally capped for
// UI responsiveness. Inputs are the source total, emitted count and result sink;
// processing appends one diagnostic row only when data was truncated.
void appendTruncationRow(const std::wstring& tableName, const std::size_t total, const std::size_t shown, KernelOperationResult& result) {
    if (total <= shown) {
        return;
    }
    result.rows.push_back(makeResultRow({
        { L"Table", tableName },
        { L"Shown", std::to_wstring(shown) },
        { L"Total", std::to_wstring(total) },
        { L"Status", L"Truncated for UI responsiveness" },
    }));
}

// appendSsdtRows converts an SSDT result into generic rows. Inputs are table
// label, query result and destination; processing caps rows to keep the edit box
// responsive; no return value is needed.
void appendSsdtRows(const wchar_t* tableName, const ksword::ark::SsdtEnumResult& query, const KernelRequest& request, KernelOperationResult& result) {
    const bool kShadow = std::wstring(tableName).find(L"Shadow") != std::wstring::npos;
    result.rows.push_back(makeResultRow({
        { L"表", tableName },
        { L"Version", std::to_wstring(query.version) },
        { L"Total", std::to_wstring(query.totalCount) },
        { L"Returned", std::to_wstring(query.returnedCount) },
        { L"ServiceTable", hexText(query.serviceTableBase) },
        { L"ServiceCount", std::to_wstring(query.serviceCountFromTable) },
    }));

    const std::size_t kLimit = std::min<std::size_t>(query.entries.size(), 256);
    for (std::size_t i = 0; i < kLimit; ++i) {
        const ksword::ark::SsdtEntry& entry = query.entries[i];
        pushFilteredRow(result, makeResultRow({
            { L"索引", ((entry.flags & KSWORD_ARK_SSDT_ENTRY_FLAG_INDEX_RESOLVED) != 0U) ? std::to_wstring(entry.serviceIndex) : L"<未知>" },
            { L"Index", std::to_wstring(entry.serviceIndex) },
            { L"IndexResolved", ((entry.flags & KSWORD_ARK_SSDT_ENTRY_FLAG_INDEX_RESOLVED) != 0U) ? L"1" : L"0" },
            { L"服务名", utf8ToWide(entry.serviceName) },
            { L"ServiceName", utf8ToWide(entry.serviceName) },
            { L"Name", utf8ToWide(entry.serviceName) },
            { L"Stub地址", hexText(entry.zwRoutineAddress) },
            { L"Zw导出地址", hexText(entry.zwRoutineAddress) },
            { L"Zw", hexText(entry.zwRoutineAddress) },
            { L"服务例程", hexText(entry.serviceRoutineAddress) },
            { L"表项地址", hexText(entry.serviceRoutineAddress) },
            { L"ServiceAddress", hexText(entry.serviceRoutineAddress) },
            { L"Service", hexText(entry.serviceRoutineAddress) },
            { L"模块", utf8ToWide(entry.moduleName) },
            { L"Module", utf8ToWide(entry.moduleName) },
            { L"ServiceTable", hexText(query.serviceTableBase) },
            { L"ServiceTableBase", hexText(query.serviceTableBase) },
            { L"Flags", hexText(entry.flags) },
            { L"FlagsText", ssdtFlagsText(entry.flags) },
            { L"Status", ssdtStatusText(entry, kShadow) },
            { L"Detail", std::wstring(tableName) + L"\r\n"
                L"Version: " + std::to_wstring(query.version) + L"\r\n"
                L"ServiceTableBase: " + hexText(query.serviceTableBase) + L"\r\n"
                L"ServiceCountFromTable: " + std::to_wstring(query.serviceCountFromTable) + L"\r\n"
                L"Flags: " + hexText(entry.flags) + L" (" + ssdtFlagsText(entry.flags) + L")" },
        }), request.filterText.empty() ? request.moduleFilterText : request.filterText);
    }
    appendTruncationRow(tableName, query.entries.size(), kLimit, result);
}

// querySsdt calls the shared SSDT IOCTL through ArkDriverClient. Inputs are the
// UI request and whether the shadow table is requested; output contains rows.
KernelOperationResult querySsdt(const KernelRequest& request, const bool shadow) {
    const ksword::ark::DriverClient kClient;
    const ksword::ark::SsdtEnumResult kQuery = shadow
        ? kClient.enumerateShadowSsdt(KSWORD_ARK_ENUM_SSDT_FLAG_INCLUDE_UNRESOLVED)
        : kClient.enumerateSsdt(KSWORD_ARK_ENUM_SSDT_FLAG_INCLUDE_UNRESOLVED);

    KernelOperationResult result;
    applyIoSummary(request, shadow ? L"Shadow SSDT" : L"SSDT", kQuery.io, result);
    appendSsdtRows(shadow ? L"Shadow SSDT" : L"SSDT", kQuery, request, result);
    return result;
}

// queryInlineHooks calls IOCTL_KSWORD_ARK_SCAN_INLINE_HOOKS through the original
// client. Inputs are module filter fields from KernelRequest; output is generic
// rows for the light UI.
KernelOperationResult queryInlineHooks(const KernelRequest& request) {
    const ksword::ark::DriverClient kClient;
    unsigned long flags = 0;
    if ((request.flags & kKernelRequestFlagIncludeInternal) != 0U) {
        flags |= KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_INTERNAL;
    }
    if ((request.flags & kKernelRequestFlagIncludeClean) != 0U) {
        flags |= KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_CLEAN;
    }
    if (!request.moduleFilterText.empty()) {
        flags |= KSWORD_ARK_KERNEL_SCAN_FLAG_MODULE_FILTER;
    }
    const ksword::ark::KernelInlineHookScanResult kQuery = kClient.scanInlineHooks(flags, KSWORD_ARK_KERNEL_HOOK_DEFAULT_MAX_ENTRIES, request.moduleFilterText);

    KernelOperationResult result;
    applyIoSummary(request, L"Inline Hook", kQuery.io, result);
    result.rows.push_back(makeResultRow({
        { L"Status", std::wstring(kernelHookStatusText(kQuery.status)) + L" (" + std::to_wstring(kQuery.status) + L")" },
        { L"Total", std::to_wstring(kQuery.totalCount) },
        { L"Returned", std::to_wstring(kQuery.returnedCount) },
        { L"Modules", std::to_wstring(kQuery.moduleCount) },
        { L"LastStatus", hexText(static_cast<std::uint32_t>(kQuery.lastStatus)) },
    }));

    const std::unordered_map<std::uint64_t, KernelModuleDiskInfo> kModuleMap = queryLoadedKernelModuleMap();
    std::unordered_map<std::wstring, std::vector<std::uint8_t>> diskFileCache;
    const std::size_t kLimit = std::min<std::size_t>(kQuery.entries.size(), 128);
    for (std::size_t i = 0; i < kLimit; ++i) {
        const ksword::ark::KernelInlineHookEntry& entry = kQuery.entries[i];
        const InlineDiskBaseline kDisk = readInlineDiskBaseline(entry, kModuleMap, diskFileCache);
        const std::wstring kDetailText = buildInlineHookDetailText(entry, kDisk);
        pushFilteredRow(result, makeResultRow({
            { L"函数", utf8ToWide(entry.functionName) },
            { L"Function", utf8ToWide(entry.functionName) },
            { L"函数地址", hexText(entry.functionAddress) },
            { L"Address", hexText(entry.functionAddress) },
            { L"目标地址", hexText(entry.targetAddress) },
            { L"Target", hexText(entry.targetAddress) },
            { L"模块", entry.moduleName },
            { L"Module", entry.moduleName },
            { L"目标模块", entry.targetModuleName.empty() ? L"<未解析>" : entry.targetModuleName },
            { L"TargetModule", entry.targetModuleName },
            { L"状态", std::wstring(kernelHookStatusText(entry.status)) },
            { L"Status", std::wstring(kernelHookStatusText(entry.status)) + L" (" + std::to_wstring(entry.status) + L")" },
            { L"类型", inlineHookTypeText(entry.hookType) },
            { L"Type", std::to_wstring(entry.hookType) },
            { L"TypeText", inlineHookTypeText(entry.hookType) },
            { L"Flags", hexText(entry.flags) },
            { L"ModuleBase", hexText(entry.moduleBase) },
            { L"TargetModuleBase", hexText(entry.targetModuleBase) },
            { L"内存字节", bytesHex(entry.currentBytes, entry.currentByteCount) },
            { L"CurrentBytes", bytesHex(entry.currentBytes, entry.currentBytes.size()) },
            { L"CurrentByteCount", std::to_wstring(entry.currentByteCount) },
            { L"磁盘字节", kDisk.available ? bytesHex(kDisk.bytes, kDisk.byteCount) : L"<未获取>" },
            { L"DiskBytes", kDisk.available ? bytesHex(kDisk.bytes, kDisk.byteCount) : L"<未获取>" },
            { L"差异状态", kDisk.statusText },
            { L"DiskDiff", kDisk.statusText },
            { L"DiskPath", kDisk.filePath },
            { L"DiskRva", hexText(kDisk.rva) },
            { L"ExpectedBytes", bytesHex(entry.expectedBytes, entry.expectedBytes.size()) },
            { L"OriginalByteCount", std::to_wstring(entry.originalByteCount) },
            { L"Detail", kDetailText },
        }, kDetailText), request.filterText.empty() ? request.moduleFilterText : request.filterText);
    }
    appendTruncationRow(L"Inline Hook", kQuery.entries.size(), kLimit, result);
    return result;
}

// queryIatEatHooks calls IOCTL_KSWORD_ARK_ENUM_IAT_EAT_HOOKS through the shared
// client. Inputs are filters from KernelRequest; output is generic rows.
KernelOperationResult queryIatEatHooks(const KernelRequest& request) {
    const ksword::ark::DriverClient kClient;
    unsigned long flags = 0;
    if ((request.flags & kKernelRequestFlagIncludeIat) != 0U || (request.flags & (kKernelRequestFlagIncludeIat | kKernelRequestFlagIncludeEat)) == 0U) {
        flags |= KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_IMPORTS;
    }
    if ((request.flags & kKernelRequestFlagIncludeEat) != 0U || (request.flags & (kKernelRequestFlagIncludeIat | kKernelRequestFlagIncludeEat)) == 0U) {
        flags |= KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_EXPORTS;
    }
    if ((request.flags & kKernelRequestFlagIncludeClean) != 0U) {
        flags |= KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_CLEAN;
    }
    if (!request.moduleFilterText.empty()) {
        flags |= KSWORD_ARK_KERNEL_SCAN_FLAG_MODULE_FILTER;
    }
    const ksword::ark::KernelIatEatHookScanResult kQuery = kClient.enumerateIatEatHooks(flags, KSWORD_ARK_KERNEL_HOOK_DEFAULT_MAX_ENTRIES, request.moduleFilterText);

    KernelOperationResult result;
    applyIoSummary(request, L"IAT/EAT Hook", kQuery.io, result);
    result.rows.push_back(makeResultRow({
        { L"Status", std::wstring(kernelHookStatusText(kQuery.status)) + L" (" + std::to_wstring(kQuery.status) + L")" },
        { L"Total", std::to_wstring(kQuery.totalCount) },
        { L"Returned", std::to_wstring(kQuery.returnedCount) },
        { L"Modules", std::to_wstring(kQuery.moduleCount) },
        { L"LastStatus", hexText(static_cast<std::uint32_t>(kQuery.lastStatus)) },
    }));

    const std::size_t kLimit = std::min<std::size_t>(kQuery.entries.size(), 128);
    for (std::size_t i = 0; i < kLimit; ++i) {
        const ksword::ark::KernelIatEatHookEntry& entry = kQuery.entries[i];
        const std::wstring kDetailText = buildIatEatHookDetailText(entry);
        pushFilteredRow(result, makeResultRow({
            { L"类别", iatEatClassText(entry.hookClass) },
            { L"Class", std::to_wstring(entry.hookClass) },
            { L"ClassText", iatEatClassText(entry.hookClass) },
            { L"模块", entry.moduleName },
            { L"Module", entry.moduleName },
            { L"导入模块", entry.importModuleName.empty() ? L"<不适用>" : entry.importModuleName },
            { L"Import", entry.importModuleName },
            { L"函数/序号", !entry.functionName.empty() ? utf8ToWide(entry.functionName) : (std::wstring(L"#") + std::to_wstring(entry.ordinal)) },
            { L"FunctionOrdinal", !entry.functionName.empty() ? utf8ToWide(entry.functionName) : (std::wstring(L"#") + std::to_wstring(entry.ordinal)) },
            { L"Function", utf8ToWide(entry.functionName) },
            { L"Thunk/EAT项", hexText(entry.thunkAddress) },
            { L"Thunk", hexText(entry.thunkAddress) },
            { L"当前目标", hexText(entry.currentTarget) },
            { L"Current", hexText(entry.currentTarget) },
            { L"期望目标", hexText(entry.expectedTarget) },
            { L"Expected", hexText(entry.expectedTarget) },
            { L"目标模块", entry.targetModuleName.empty() ? L"<未解析>" : entry.targetModuleName },
            { L"TargetModule", entry.targetModuleName },
            { L"状态", std::wstring(kernelHookStatusText(entry.status)) },
            { L"Status", std::wstring(kernelHookStatusText(entry.status)) + L" (" + std::to_wstring(entry.status) + L")" },
            { L"Flags", hexText(entry.flags) },
            { L"Ordinal", std::to_wstring(entry.ordinal) },
            { L"ModuleBase", hexText(entry.moduleBase) },
            { L"TargetModuleBase", hexText(entry.targetModuleBase) },
            { L"Detail", kDetailText },
        }, kDetailText), request.filterText.empty() ? request.moduleFilterText : request.filterText);
    }
    appendTruncationRow(L"IAT/EAT Hook", kQuery.entries.size(), kLimit, result);
    return result;
}

// queryDynData collects DynData status and field rows through ArkDriverClient.
// Input is the kernel request; output includes both status and field metadata.
KernelOperationResult queryDynData(const KernelRequest& request) {
    const ksword::ark::DriverClient kClient;
    const ksword::ark::DynDataStatusResult kStatus = kClient.queryDynDataStatus();

    KernelOperationResult result;
    applyIoSummary(request, L"DynData Status", kStatus.io, result);
    result.rows.push_back(makeResultRow({
        { L"StatusFlags", hexText(kStatus.statusFlags) },
        { L"StatusQueryOk", yesNoText(kStatus.io.ok) },
        { L"SI Version", std::to_wstring(kStatus.systemInformerDataVersion) },
        { L"SI Length", std::to_wstring(kStatus.systemInformerDataLength) },
        { L"LastStatus", ntStatusText(kStatus.lastStatus) },
        { L"MatchedClass", std::to_wstring(kStatus.matchedProfileClass) },
        { L"MatchedProfileOffset", hexText(kStatus.matchedProfileOffset) },
        { L"MatchedFieldsId", std::to_wstring(kStatus.matchedFieldsId) },
        { L"FieldCount", std::to_wstring(kStatus.fieldCount) },
        { L"CapabilityMask", hexText(kStatus.capabilityMask) },
        { L"Ntos", kStatus.ntoskrnl.moduleName },
        { L"NtosIdentity", moduleIdentityText(kStatus.ntoskrnl) },
        { L"Lxcore", kStatus.lxcore.moduleName },
        { L"LxcoreIdentity", moduleIdentityText(kStatus.lxcore) },
        { L"UnavailableReason", kStatus.unavailableReason },
    }, kStatus.unavailableReason));

    // DynData R0 features are often limited until a matching local PDB profile
    // is applied. The local pack scan is intentionally done during the read-only
    // query as a diagnostic row; applying the match remains a separate explicit
    // right-click action so the Dock does not mutate R0 state while refreshing.
    const DynDataProfileMatch kProfileMatch = findMatchingDynDataProfile(kStatus.ntoskrnl);
    result.rows.push_back(makeResultRow({
        { L"Source", L"Local PDB Profile Summary" },
        { L"PdbProfileScanAttempted", yesNoText(kProfileMatch.scanned) },
        { L"PdbProfileFound", yesNoText(kProfileMatch.matched) },
        { L"PdbProfileApplied", L"否" },
        { L"PdbProfileSource", kProfileMatch.matched ? kProfileMatch.source : L"None" },
        { L"PdbProfileName", utf8ToWide(kProfileMatch.profile.profileName) },
        { L"PdbProfilePath", kProfileMatch.path },
        { L"PdbProfileStatus", kProfileMatch.valid ? L"OK" : L"NotApplied" },
        { L"PdbProfileAppliedFields", L"0" },
        { L"PdbProfileRejectedFields", L"0" },
        { L"PdbProfileUnknownFields", L"0" },
        { L"PdbProfileIgnoredJsonFields", L"0" },
        { L"PdbProfileMessage", kProfileMatch.message },
        { L"PdbProfileIo", kProfileMatch.source == L"Runtime Exact PDB" ? L"DbgHelp exact PDB" : L"Local scan only" },
    }, kProfileMatch.message));
    appendDynDataProfileRows(result, kProfileMatch, request.filterText);

    const ksword::ark::DynDataFieldsResult kFields = kClient.queryDynDataFields();
    result.rows.push_back(makeResultRow({
        { L"DynData Fields IO", kFields.io.ok ? L"OK" : L"FAIL" },
        { L"FieldsQueryOk", yesNoText(kFields.io.ok) },
        { L"FieldsTotal", std::to_wstring(kFields.totalCount) },
        { L"FieldsReturned", std::to_wstring(kFields.returnedCount) },
    }, utf8ToWide(kFields.io.message)));
    result.success = result.success && kFields.io.ok;

    const std::size_t kLimit = std::min<std::size_t>(kFields.entries.size(), 256);
    for (std::size_t i = 0; i < kLimit; ++i) {
        const ksword::ark::DynDataFieldEntry& entry = kFields.entries[i];
        result.rows.push_back(makeResultRow({
            { L"Field", utf8ToWide(entry.fieldName) },
            { L"Id", std::to_wstring(entry.fieldId) },
            { L"Offset", hexText(entry.offset) },
            { L"Status", dynDataFieldStatusText(entry.flags, entry.offset) },
            { L"Source", utf8ToWide(entry.sourceName) },
            { L"Feature", utf8ToWide(entry.featureName) },
            { L"Mask", hexText(entry.capabilityMask) },
            { L"Flags", hexText(entry.flags) },
        }));
    }
    appendTruncationRow(L"DynData Fields", kFields.entries.size(), kLimit, result);
    return result;
}

// queryDriverStatus calls the driver capability matrix IOCTL. Input is a kernel
// request; output contains the runtime protocol and feature dependency rows.
KernelOperationResult queryDriverStatus(const KernelRequest& request) {
    const ksword::ark::DriverClient kClient;
    const ksword::ark::DriverCapabilitiesQueryResult kQuery = kClient.queryDriverCapabilities();
    const ksword::ark::DynDataStatusResult kDynStatus = kClient.queryDynDataStatus();
    const ksword::ark::DynDataFieldsResult kDynFields = kClient.queryDynDataFields();
    const DynDataFieldsSummary kFieldSummary = summarizeDynDataFields(kDynFields);
    const DynDataProfileMatch kProfileMatch = findMatchingDynDataProfile(kDynStatus.ntoskrnl);
    const std::uint32_t kEffectiveDynStatusFlags = kDynStatus.io.ok ? kDynStatus.statusFlags : kQuery.dynDataStatusFlags;
    const std::uint64_t kEffectiveDynCapabilityMask = kDynStatus.io.ok ? kDynStatus.capabilityMask : kQuery.dynDataCapabilityMask;
    const bool kDriverLoaded = (kQuery.statusFlags & KSWORD_ARK_DRIVER_STATUS_FLAG_DRIVER_LOADED) != 0U;
    const bool kProtocolOk = (kQuery.statusFlags & KSWORD_ARK_DRIVER_STATUS_FLAG_PROTOCOL_OK) != 0U;
    const bool kDynMissing = (kQuery.statusFlags & KSWORD_ARK_DRIVER_STATUS_FLAG_DYNDATA_MISSING) != 0U;
    const bool kLimited = (kQuery.statusFlags & KSWORD_ARK_DRIVER_STATUS_FLAG_LIMITED) != 0U;
    const bool kPdbActive = (kEffectiveDynStatusFlags & KSW_DYN_STATUS_FLAG_PDB_PROFILE_ACTIVE) != 0U;
    const bool kCallbackActive = (kEffectiveDynStatusFlags & KSW_DYN_STATUS_FLAG_CALLBACK_PROFILE_ACTIVE) != 0U;

    std::wstring badges = kDriverLoaded ? L"Driver Loaded" : L"Driver Missing";
    if (!kProtocolOk) { badges += L", Protocol Mismatch"; }
    if (kDynMissing) { badges += L", DynData Missing"; }
    if (kPdbActive) { badges += L", PDB Profile Active"; }
    if (kCallbackActive) { badges += L", Callback Profile Active"; }
    if (kProfileMatch.matched) { badges += L", Pack Matched"; }
    if (kPdbActive) { badges += L", Trusted Offsets"; }
    if (kFieldSummary.requiredMissing != 0U) { badges += L", Required Offsets Missing"; }
    if (kLimited) { badges += L", Limited"; }

    KernelOperationResult result;
    applyIoSummary(request, L"Driver Capabilities", kQuery.io, result);
    result.success = result.success && kDynStatus.io.ok && kDynFields.io.ok;
    result.rows.push_back(makeResultRow({
        { L"Version", std::to_wstring(kQuery.version) },
        { L"Protocol", std::to_wstring(kQuery.driverProtocolVersion) },
        { L"ExpectedProtocol", hexText(KSWORD_ARK_DRIVER_PROTOCOL_VERSION) },
        { L"StatusFlags", hexText(kQuery.statusFlags) },
        { L"StatusBadges", badges },
        { L"SecurityPolicy", hexText(kQuery.securityPolicyFlags) },
        { L"DynDataStatus", hexText(kEffectiveDynStatusFlags) },
        { L"DynDataCapability", hexText(kEffectiveDynCapabilityMask) },
        { L"FeatureTotal", std::to_wstring(kQuery.totalFeatureCount) },
        { L"FeatureReturned", std::to_wstring(kQuery.returnedFeatureCount) },
        { L"LastError", utf8ToWide(kQuery.lastErrorSource) },
        { L"LastErrorSummary", utf8ToWide(kQuery.lastErrorSummary) },
        { L"LastErrorStatus", hexText(static_cast<std::uint32_t>(kQuery.lastErrorStatus)) },
        { L"DynDataStatusQueryOk", boolText(kDynStatus.io.ok) },
        { L"DynDataFieldsQueryOk", boolText(kDynFields.io.ok) },
        { L"DynDataStatusIo", utf8ToWide(kDynStatus.io.message) },
        { L"DynDataFieldsIo", utf8ToWide(kDynFields.io.message) },
        { L"FieldCoverage", fieldCoverageText(kFieldSummary, kProfileMatch.coveragePercent) },
        { L"FieldSources", fieldSourcesText(kFieldSummary) },
        { L"RequiredMissing", std::to_wstring(kFieldSummary.requiredMissing) },
        { L"NtosIdentity", moduleIdentityText(kDynStatus.ntoskrnl) },
        { L"LxcoreIdentity", moduleIdentityText(kDynStatus.lxcore) },
        { L"LocalPdbProfileMatched", yesNoText(kProfileMatch.matched) },
        { L"LocalPdbProfile", localPdbProfileText(kProfileMatch) },
        { L"LocalPdbProfileName", utf8ToWide(kProfileMatch.profile.profileName) },
        { L"LocalPdbProfilePath", kProfileMatch.path },
        { L"LocalPdbMessage", kProfileMatch.message },
        { L"LocalPdbVersion", utf8ToWide(kProfileMatch.profile.profileName) },
        { L"ActiveProcessLinksOffset", activeProcessLinksText(kFieldSummary) },
        { L"CallbackProfileCoverage", std::to_wstring(kProfileMatch.callbackItemCount) + L" callback items" },
        { L"PdbProfileActive", yesNoText(kPdbActive) },
        { L"CallbackProfileActive", yesNoText(kCallbackActive) },
        { L"TrustedPdbOffsetsActive", yesNoText(kPdbActive) },
        { L"TrustedOffset", trustedOffsetText(kEffectiveDynStatusFlags, kProfileMatch, kFieldSummary) },
        { L"SI Version", std::to_wstring(kDynStatus.systemInformerDataVersion) },
        { L"SI Length", std::to_wstring(kDynStatus.systemInformerDataLength) },
        { L"MatchedClass", std::to_wstring(kDynStatus.matchedProfileClass) },
        { L"MatchedProfileOffset", hexText(kDynStatus.matchedProfileOffset) },
        { L"MatchedFieldsId", std::to_wstring(kDynStatus.matchedFieldsId) },
        { L"UnavailableReason", kDynStatus.unavailableReason },
    }, utf8ToWide(kQuery.lastErrorSummary)));

    const std::size_t kLimit = std::min<std::size_t>(kQuery.entries.size(), 256);
    for (std::size_t i = 0; i < kLimit; ++i) {
        const ksword::ark::DriverFeatureCapabilityEntry& entry = kQuery.entries[i];
        result.rows.push_back(makeResultRow({
            { L"Feature", utf8ToWide(entry.featureName) },
            { L"Id", std::to_wstring(entry.featureId) },
            { L"State", utf8ToWide(entry.stateName) },
            { L"Status", utf8ToWide(entry.stateName) },
            { L"StateId", std::to_wstring(entry.state) },
            { L"Flags", hexText(entry.flags) },
            { L"Policy", hexText(entry.requiredPolicyFlags) },
            { L"RequiredPolicy", hexText(entry.requiredPolicyFlags) },
            { L"DeniedPolicy", hexText(entry.deniedPolicyFlags) },
            { L"RequiredDyn", hexText(entry.requiredDynDataMask) },
            { L"PresentDyn", hexText(entry.presentDynDataMask) },
            { L"Dependency", utf8ToWide(entry.dependencyText) },
            { L"Fields", utf8ToWide(entry.dependencyText) },
            { L"Reason", utf8ToWide(entry.reasonText) },
        }, utf8ToWide(entry.dependencyText + " " + entry.reasonText)));
    }
    appendTruncationRow(L"Driver Capabilities", kQuery.entries.size(), kLimit, result);
    return result;
}

// queryCallbackRuntime calls the callback-runtime state IOCTL. Input is a kernel
// request; output is a readable runtime table rather than one opaque mask row.
KernelOperationResult queryCallbackRuntime(const KernelRequest& request) {
    const ksword::ark::DriverClient kClient;
    const ksword::ark::CallbackRuntimeResult kQuery = kClient.queryCallbackRuntimeState();

    KernelOperationResult result;
    applyIoSummary(request, L"Callback Runtime", kQuery.io, result);
    appendCallbackRuntimeRows(result, kQuery.state, request.filterText, L"Query");
    const ksword::ark::MinifilterBypassPidResult kBypass = kClient.queryMinifilterBypassPids();
    result.rows.push_back(makeResultRow({
        { L"Section", L"MinifilterBypass" },
        { L"Status", kBypass.io.ok ? L"OK" : L"FAIL" },
        { L"PidCount", std::to_wstring(kBypass.response.pidCount) },
        { L"Flags", hexText(kBypass.response.flags) },
        { L"Win32", std::to_wstring(kBypass.io.win32Error) },
    }, utf8ToWide(kBypass.io.message)));
    const std::uint32_t kBypassCount = std::min<std::uint32_t>(kBypass.response.pidCount, KSWORD_ARK_MINIFILTER_BYPASS_PID_MAX_COUNT);
    for (std::uint32_t index = 0; index < kBypassCount; ++index) {
        pushFilteredRow(result, makeResultRow({
            { L"Section", L"BypassPid" },
            { L"Index", std::to_wstring(index) },
            { L"PID", std::to_wstring(kBypass.response.processIds[index]) },
            { L"Process", processDisplayName(kBypass.response.processIds[index]) },
        }), request.filterText);
    }
    return result;
}

// queryCallbackEnumeration calls callback enumeration through ArkDriverClient.
// Input is a kernel request; output is callback rows with module/name/details.
KernelOperationResult queryCallbackEnumeration(const KernelRequest& request) {
    const ksword::ark::DriverClient kClient;
    const ksword::ark::CallbackEnumResult kQuery = kClient.enumerateCallbacks(KSWORD_ARK_ENUM_CALLBACK_FLAG_INCLUDE_ALL);

    KernelOperationResult result;
    applyIoSummary(request, L"Callback Enumeration", kQuery.io, result);
    result.rows.push_back(makeResultRow({
        { L"Version", std::to_wstring(kQuery.version) },
        { L"Total", std::to_wstring(kQuery.totalCount) },
        { L"Returned", std::to_wstring(kQuery.returnedCount) },
        { L"Flags", hexText(kQuery.flags) },
        { L"ResponseFlags", hexText(kQuery.flags) },
        { L"CallbackEnumResponseFlags", hexText(kQuery.flags) },
        { L"CallbackEnumTruncated", (kQuery.flags & KSWORD_ARK_ENUM_CALLBACK_RESPONSE_FLAG_TRUNCATED) != 0U ? L"1" : L"0" },
        { L"LastStatus", hexText(static_cast<std::uint32_t>(kQuery.lastStatus)) },
    }, std::wstring(L"Callback Enumeration response: returned=") + std::to_wstring(kQuery.returnedCount) +
        L" total=" + std::to_wstring(kQuery.totalCount) +
        L" flags=" + hexText(kQuery.flags)));

    const std::size_t kLimit = std::min<std::size_t>(kQuery.entries.size(), 256);
    for (std::size_t i = 0; i < kLimit; ++i) {
        const ksword::ark::CallbackEnumEntry& entry = kQuery.entries[i];
        pushFilteredRow(result, makeResultRow({
            { L"类别", callbackEnumClassText(entry.callbackClass) },
            { L"Class", std::to_wstring(entry.callbackClass) },
            { L"ClassText", callbackEnumClassText(entry.callbackClass) },
            { L"名称", entry.name },
            { L"Name", entry.name },
            { L"Altitude", entry.altitude },
            { L"回调/对象地址", hexText(entry.callbackAddress) },
            { L"Callback", hexText(entry.callbackAddress) },
            { L"Context", hexText(entry.contextAddress) },
            { L"Registration", hexText(entry.registrationAddress) },
            { L"来源", callbackEnumSourceText(entry.source) },
            { L"Source", std::to_wstring(entry.source) },
            { L"SourceText", callbackEnumSourceText(entry.source) },
            { L"可信状态", callbackEnumTrustBucket(entry) },
            { L"SourceTrust", callbackEnumTrustBucket(entry) },
            { L"状态", std::wstring(callbackEnumStatusText(entry.status)) + L" (" + std::to_wstring(entry.status) + L")" },
            { L"Status", std::wstring(callbackEnumStatusText(entry.status)) + L" (" + std::to_wstring(entry.status) + L")" },
            { L"OperationMask", hexText(entry.operationMask) },
            { L"ObjectTypeMask", hexText(entry.objectTypeMask) },
            { L"Generation", hexText(entry.generation) },
            { L"IdentityHash", hexText(entry.identityHash) },
            { L"RawStorageValue", hexText(entry.rawStorageValue) },
            { L"模块", entry.modulePath },
            { L"ModuleBase", hexText(entry.moduleBase) },
            { L"ModuleSize", hexText(entry.moduleSize) },
            { L"ModulePath", entry.modulePath },
            { L"FieldFlags", hexText(entry.fieldFlags) },
            { L"FieldText", callbackEnumFieldFlagsText(entry.fieldFlags) },
            { L"Trust", hexText(entry.trustFlags) },
            { L"TrustText", callbackEnumTrustFlagsText(entry.trustFlags) },
            { L"Remove", hexText(entry.removeBehavior) },
            { L"RemoveText", callbackEnumRemoveBehaviorText(entry.removeBehavior) },
            { L"移除策略", callbackEnumRemovePolicyText(entry) },
            { L"RemovePolicy", callbackEnumRemovePolicyText(entry) },
            { L"LastStatus", hexText(static_cast<std::uint32_t>(entry.lastStatus)) },
        }, entry.modulePath.empty() ? entry.detail : entry.modulePath + L" | " + entry.detail), request.filterText.empty() ? request.moduleFilterText : request.filterText);
    }
    appendTruncationRow(L"Callback Enumeration", kQuery.entries.size(), kLimit, result);
    return result;
}

// queryKernelExecutableMemory calls the ArkDriverClient executable-page scanner.
// Inputs are optional module/path filter text from the UI; output is a readable
// row set with page range, owner, permission and risk data.
KernelOperationResult queryKernelExecutableMemory(const KernelRequest& request) {
    const ksword::ark::DriverClient kClient;
    const ksword::ark::KernelExecutableMemoryScanResult kQuery = kClient.scanKernelExecutableMemory(
        KSWORD_ARK_KERNEL_EXEC_SCAN_FLAG_INCLUDE_ALL,
        4096UL,
        request.moduleFilterText);

    KernelOperationResult result;
    applyIoSummary(request, L"Kernel Executable Memory", kQuery.io, result);
    result.rows.push_back(makeResultRow({
        { L"Unsupported", boolText(kQuery.unsupported) },
        { L"Version", std::to_wstring(kQuery.version) },
        { L"Status", std::wstring(kernelExecStatusText(kQuery.status)) + L" (" + std::to_wstring(kQuery.status) + L")" },
        { L"Total", std::to_wstring(kQuery.totalCount) },
        { L"Returned", std::to_wstring(kQuery.returnedCount) },
        { L"Modules", std::to_wstring(kQuery.moduleCount) },
        { L"LastStatus", hexText(static_cast<std::uint32_t>(kQuery.lastStatus)) },
    }));

    for (const ksword::ark::KernelExecutableMemoryPageEntry& entry : kQuery.entries) {
        const std::wstring kOwnerText = kernelExecOwnerText(entry.ownerKind);
        const std::wstring kOwnerDisplay = entry.owner.empty() ? kOwnerText : kOwnerText + L" " + entry.owner;
        result.rows.push_back(makeResultRow({
            { L"VA", hexText(entry.virtualAddress) },
            { L"RegionSize", hexText(entry.regionSize) },
            { L"Pages", std::to_wstring(entry.pageCount) },
            { L"PageSize", std::to_wstring(entry.pageSize) },
            { L"Perm", hexText(entry.permissionFlags) },
            { L"PermText", pagePermissionText(entry.permissionFlags) },
            { L"Risk", hexText(entry.riskFlags) },
            { L"RiskText", kernelExecRiskText(entry.riskFlags) },
            { L"OwnerKind", std::to_wstring(entry.ownerKind) },
            { L"OwnerKindText", kOwnerText },
            { L"OwnerDisplay", kOwnerDisplay },
            { L"Owner", entry.owner },
            { L"OwnerAddress", hexText(entry.ownerAddress) },
            { L"ModuleBase", hexText(entry.moduleBase) },
            { L"ModuleSize", hexText(entry.moduleSize) },
            { L"Module", entry.modulePath },
            { L"ModulePath", entry.modulePath },
            { L"Status", std::wstring(kernelExecStatusText(entry.status)) + L" (" + std::to_wstring(entry.status) + L")" },
            { L"LastStatus", hexText(static_cast<std::uint32_t>(entry.lastStatus)) },
        }, entry.detail));
    }
    return result;
}

// queryKernelMemoryEvidence calls the unified memory-evidence IOCTL. Inputs are
// optional filter text; output contains risk, owner, hash and sample summaries.
KernelOperationResult queryKernelMemoryEvidence(const KernelRequest& request) {
    const ksword::ark::DriverClient kClient;
    const bool kIncludeNonModuleRange = (request.flags & kKernelRequestFlagIncludeNonModuleExecutableRanges) != 0;
    if (kIncludeNonModuleRange && (request.startAddress == 0 || request.endAddress <= request.startAddress)) {
        KernelOperationResult invalid;
        invalid.supported = true;
        invalid.success = false;
        invalid.message = L"非模块执行范围需要有效的起始/结束 VA。";
        invalid.rows.push_back(makeResultRow({
            { L"Status", L"Invalid request" },
            { L"Detail", invalid.message },
        }, invalid.message));
        return invalid;
    }

    unsigned long flags =
        KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_LOADED_MODULE_EXECUTABLE |
        KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_BIGPOOL |
        KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_TEXT_SECTION_SAMPLES |
        KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_SUSPECTED_BIGPOOL;
    if (kIncludeNonModuleRange) {
        flags |= KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_NONMODULE_EXECUTABLE_RANGES;
    }
    unsigned long maxRows = request.maxRows == 0 ? KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_MAX_ROWS : request.maxRows;
    maxRows = std::max<unsigned long>(16UL, std::min<unsigned long>(maxRows, KSWORD_ARK_MEMORY_EVIDENCE_HARD_MAX_ROWS));
    const ksword::ark::KernelMemoryEvidenceResult kQuery = kClient.queryKernelMemoryEvidence(
        flags,
        maxRows,
        kIncludeNonModuleRange ? request.startAddress : 0ULL,
        kIncludeNonModuleRange ? request.endAddress : 0ULL,
        KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_MAX_BYTES,
        KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_BIGPOOL_ROWS,
        KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_SAMPLE_BYTES);

    KernelOperationResult result;
    applyIoSummary(request, L"Kernel Memory Evidence", kQuery.io, result);
    result.rows.push_back(makeResultRow({
        { L"Unsupported", boolText(kQuery.unsupported) },
        { L"Version", std::to_wstring(kQuery.version) },
        { L"Status", std::wstring(memoryEvidenceStatusText(kQuery.status)) + L" (" + std::to_wstring(kQuery.status) + L")" },
        { L"Total", std::to_wstring(kQuery.totalRows) },
        { L"Returned", std::to_wstring(kQuery.returnedRows) },
        { L"ResponseFlags", hexText(kQuery.responseFlags) },
        { L"SourceFlags", hexText(kQuery.sourceFlags) },
        { L"MaxRows", std::to_wstring(kQuery.maxRows) },
        { L"MaxBytes", hexText(kQuery.maxBytes) },
        { L"BytesScanned", hexText(kQuery.bytesScanned) },
        { L"AddressFilter", kIncludeNonModuleRange ? hexText(request.startAddress) + L"-" + hexText(request.endAddress) : L"" },
        { L"Modules", std::to_wstring(kQuery.moduleCount) },
        { L"BigPoolRows", std::to_wstring(kQuery.bigPoolRowsSeen) },
        { L"LastStatus", hexText(static_cast<std::uint32_t>(kQuery.lastStatus)) },
    }));

    for (const ksword::ark::KernelMemoryEvidenceEntry& entry : kQuery.entries) {
        const std::wstring kOwnerKind = memoryEvidenceOwnerText(entry.ownerKind);
        const std::wstring kOwnerDisplay = entry.ownerName.empty() ? kOwnerKind : kOwnerKind + L" " + entry.ownerName;
        const std::wstring kHashText = memoryEvidenceHashText(entry);
        result.rows.push_back(makeResultRow({
            { L"Kind", std::to_wstring(entry.evidenceKind) },
            { L"KindText", memoryEvidenceKindText(entry.evidenceKind) },
            { L"VA", hexText(entry.virtualAddress) },
            { L"RegionSize", hexText(entry.regionSize) },
            { L"SizeText", sizeText(entry.regionSize) },
            { L"PageSize", std::to_wstring(entry.pageSize) },
            { L"Perm", hexText(entry.permissionFlags) },
            { L"PermText", memoryEvidencePermissionText(entry.permissionFlags) },
            { L"Risk", hexText(entry.riskFlags) },
            { L"RiskText", memoryEvidenceRiskText(entry.riskFlags) },
            { L"OwnerKind", std::to_wstring(entry.ownerKind) },
            { L"OwnerKindText", kOwnerKind },
            { L"OwnerDisplay", kOwnerDisplay },
            { L"Owner", entry.ownerName },
            { L"OwnerAddress", hexText(entry.ownerAddress) },
            { L"ModuleBase", hexText(entry.moduleBase) },
            { L"ModuleSize", hexText(entry.moduleSize) },
            { L"ModuleSizeText", sizeText(entry.moduleSize) },
            { L"Confidence", std::to_wstring(entry.confidence) },
            { L"BigPoolTag", hexText(entry.bigPoolTag) },
            { L"BigPoolFlags", hexText(entry.bigPoolFlags) },
            { L"SectionRva", hexText(entry.sectionRva) },
            { L"SectionSize", hexText(entry.sectionSize) },
            { L"SectionSizeText", sizeText(entry.sectionSize) },
            { L"Section", utf8ToWide(entry.sectionName) },
            { L"HashAlgorithm", std::to_wstring(entry.hashAlgorithm) },
            { L"SampleSize", std::to_wstring(entry.sampleSize) },
            { L"Hash", hexText(entry.contentHash) },
            { L"HashText", kHashText },
            { L"Sample", bytesHex(entry.sample) },
            { L"LastStatus", hexText(static_cast<std::uint32_t>(entry.lastStatus)) },
        }, entry.detail));
    }
    return result;
}

// queryProcessCrossView calls the R0 process DKOM cross-view query. Input is an
// optional text filter; output lists source/anomaly masks and object addresses.
KernelOperationResult queryProcessCrossView(const KernelRequest& request) {
    const ksword::ark::DriverClient kClient;
    const std::uint32_t kPidFilter = parseFirstPidFromText(request.filterText);
    const ksword::ark::ProcessCrossViewResult kQuery = kClient.queryProcessCrossView(
        KSWORD_ARK_PROCESS_CROSSVIEW_FLAG_INCLUDE_ALL,
        kPidFilter,
        kPidFilter);

    KernelOperationResult result;
    applyIoSummary(request, L"Process CrossView", kQuery.io, result);
    result.rows.push_back(makeResultRow({
        { L"Unsupported", boolText(kQuery.unsupported) },
        { L"Version", std::to_wstring(kQuery.version) },
        { L"Status", std::wstring(crossViewStatusText(kQuery.status)) + L" (" + std::to_wstring(kQuery.status) + L")" },
        { L"Total", std::to_wstring(kQuery.totalCount) },
        { L"Returned", std::to_wstring(kQuery.returnedCount) },
        { L"DynData", hexText(kQuery.dynDataCapabilityMask) },
        { L"MissingDyn", hexText(kQuery.missingCapabilityMask) },
        { L"PidFilter", kPidFilter == 0 ? L"" : std::to_wstring(kPidFilter) },
        { L"LastStatus", hexText(static_cast<std::uint32_t>(kQuery.lastStatus)) },
    }));
    result.rows.push_back(makeResultRow({
        { L"OffsetSet", L"ProcessCrossView" },
        { L"EP.UniqueProcessId", hexText(kQuery.fieldOffsets.epUniqueProcessId) },
        { L"EP.ActiveProcessLinks", hexText(kQuery.fieldOffsets.epActiveProcessLinks) },
        { L"EP.ThreadListHead", hexText(kQuery.fieldOffsets.epThreadListHead) },
        { L"EP.ImageFileName", hexText(kQuery.fieldOffsets.epImageFileName) },
        { L"ET.Cid", hexText(kQuery.fieldOffsets.etCid) },
        { L"ET.ThreadListEntry", hexText(kQuery.fieldOffsets.etThreadListEntry) },
        { L"ET.StartAddress", hexText(kQuery.fieldOffsets.etStartAddress) },
        { L"ET.Win32StartAddress", hexText(kQuery.fieldOffsets.etWin32StartAddress) },
        { L"KT.Process", hexText(kQuery.fieldOffsets.ktProcess) },
        { L"HT.TableCode", hexText(kQuery.fieldOffsets.htTableCode) },
        { L"HTE.LowValue", hexText(kQuery.fieldOffsets.hteLowValue) },
        { L"PspCidTableRva", hexText(kQuery.fieldOffsets.pspCidTableRva) },
        { L"PspCidTable", hexText(kQuery.fieldOffsets.pspCidTableAddress) },
    }, L"DynData offsets used by R0 cross-view enumeration."));

    for (const ksword::ark::ProcessCrossViewEntry& entry : kQuery.entries) {
        result.rows.push_back(makeResultRow({
            { L"ID", std::to_wstring(entry.processId) },
            { L"对象", hexText(entry.objectAddress) },
            { L"进程", utf8ToWide(entry.imageName) },
            { L"PublicWalk", sourceYesNo(entry.sourceMask, KSWORD_ARK_CROSSVIEW_SOURCE_PUBLIC_WALK) },
            { L"Active/ThreadList", sourceYesNo(entry.sourceMask, KSWORD_ARK_CROSSVIEW_SOURCE_ACTIVE_LIST) },
            { L"CID", sourceYesNo(entry.sourceMask, KSWORD_ARK_CROSSVIEW_SOURCE_CID_TABLE) },
            { L"异常", crossViewAnomalyText(entry.anomalyFlags) },
            { L"置信度", std::to_wstring(entry.confidence) },
            { L"PID", std::to_wstring(entry.processId) },
            { L"PPID", std::to_wstring(entry.parentProcessId) },
            { L"Image", utf8ToWide(entry.imageName) },
            { L"Object", hexText(entry.objectAddress) },
            { L"ProcessObject", hexText(entry.objectAddress) },
            { L"Start", hexText(entry.startAddress) },
            { L"StartAddress", hexText(entry.startAddress) },
            { L"SourceMask", hexText(entry.sourceMask) },
            { L"SourceText", crossViewSourceText(entry.sourceMask) },
            { L"Anomaly", hexText(entry.anomalyFlags) },
            { L"AnomalyText", crossViewAnomalyText(entry.anomalyFlags) },
            { L"DynData", hexText(entry.dynDataCapabilityMask) },
            { L"DynDataCapabilityMask", hexText(entry.dynDataCapabilityMask) },
            { L"EP.UniqueProcessId", hexText(entry.fieldOffsets.epUniqueProcessId) },
            { L"EP.ActiveProcessLinks", hexText(entry.fieldOffsets.epActiveProcessLinks) },
            { L"EP.ThreadListHead", hexText(entry.fieldOffsets.epThreadListHead) },
            { L"EP.ImageFileName", hexText(entry.fieldOffsets.epImageFileName) },
            { L"ET.Cid", hexText(entry.fieldOffsets.etCid) },
            { L"ET.ThreadListEntry", hexText(entry.fieldOffsets.etThreadListEntry) },
            { L"ET.StartAddress", hexText(entry.fieldOffsets.etStartAddress) },
            { L"ET.Win32StartAddress", hexText(entry.fieldOffsets.etWin32StartAddress) },
            { L"KT.Process", hexText(entry.fieldOffsets.ktProcess) },
            { L"HT.TableCode", hexText(entry.fieldOffsets.htTableCode) },
            { L"HTE.LowValue", hexText(entry.fieldOffsets.hteLowValue) },
            { L"PspCidTableRva", hexText(entry.fieldOffsets.pspCidTableRva) },
            { L"PspCidTable", hexText(entry.fieldOffsets.pspCidTableAddress) },
            { L"Confidence", std::to_wstring(entry.confidence) },
            { L"LastStatus", hexText(static_cast<std::uint32_t>(entry.lastStatus)) },
        }, utf8ToWide(entry.detail)));
    }
    return result;
}

// queryThreadCrossView calls the R0 thread DKOM cross-view query. Input is an
// optional text filter; output lists ETHREAD/KTHREAD source/anomaly evidence.
KernelOperationResult queryThreadCrossView(const KernelRequest& request) {
    const ksword::ark::DriverClient kClient;
    const std::uint32_t kPidFilter = parseFirstPidFromText(request.filterText);
    const ksword::ark::ThreadCrossViewResult kQuery = kClient.queryThreadCrossView(
        KSWORD_ARK_THREAD_CROSSVIEW_FLAG_INCLUDE_ALL,
        kPidFilter);

    KernelOperationResult result;
    applyIoSummary(request, L"Thread CrossView", kQuery.io, result);
    result.rows.push_back(makeResultRow({
        { L"Unsupported", boolText(kQuery.unsupported) },
        { L"Version", std::to_wstring(kQuery.version) },
        { L"Status", std::wstring(crossViewStatusText(kQuery.status)) + L" (" + std::to_wstring(kQuery.status) + L")" },
        { L"Total", std::to_wstring(kQuery.totalCount) },
        { L"Returned", std::to_wstring(kQuery.returnedCount) },
        { L"DynData", hexText(kQuery.dynDataCapabilityMask) },
        { L"MissingDyn", hexText(kQuery.missingCapabilityMask) },
        { L"PidFilter", kPidFilter == 0 ? L"" : std::to_wstring(kPidFilter) },
        { L"LastStatus", hexText(static_cast<std::uint32_t>(kQuery.lastStatus)) },
    }));
    result.rows.push_back(makeResultRow({
        { L"OffsetSet", L"ThreadCrossView" },
        { L"EP.UniqueProcessId", hexText(kQuery.fieldOffsets.epUniqueProcessId) },
        { L"EP.ActiveProcessLinks", hexText(kQuery.fieldOffsets.epActiveProcessLinks) },
        { L"EP.ThreadListHead", hexText(kQuery.fieldOffsets.epThreadListHead) },
        { L"EP.ImageFileName", hexText(kQuery.fieldOffsets.epImageFileName) },
        { L"ET.Cid", hexText(kQuery.fieldOffsets.etCid) },
        { L"ET.ThreadListEntry", hexText(kQuery.fieldOffsets.etThreadListEntry) },
        { L"ET.StartAddress", hexText(kQuery.fieldOffsets.etStartAddress) },
        { L"ET.Win32StartAddress", hexText(kQuery.fieldOffsets.etWin32StartAddress) },
        { L"KT.Process", hexText(kQuery.fieldOffsets.ktProcess) },
        { L"HT.TableCode", hexText(kQuery.fieldOffsets.htTableCode) },
        { L"HTE.LowValue", hexText(kQuery.fieldOffsets.hteLowValue) },
        { L"PspCidTableRva", hexText(kQuery.fieldOffsets.pspCidTableRva) },
        { L"PspCidTable", hexText(kQuery.fieldOffsets.pspCidTableAddress) },
    }, L"DynData offsets used by R0 thread cross-view enumeration."));

    for (const ksword::ark::ThreadCrossViewEntry& entry : kQuery.entries) {
        const std::wstring kImageName = utf8ToWide(entry.imageName);
        const std::wstring kProcessText = std::to_wstring(entry.processId) + L" " + kImageName;
        result.rows.push_back(makeResultRow({
            { L"ID", std::to_wstring(entry.threadId) },
            { L"对象", hexText(entry.objectAddress) },
            { L"进程", kProcessText },
            { L"PublicWalk", sourceYesNo(entry.sourceMask, KSWORD_ARK_CROSSVIEW_SOURCE_PUBLIC_WALK) },
            { L"Active/ThreadList", sourceYesNo(entry.sourceMask, KSWORD_ARK_CROSSVIEW_SOURCE_THREAD_LIST) },
            { L"CID", sourceYesNo(entry.sourceMask, KSWORD_ARK_CROSSVIEW_SOURCE_CID_TABLE) },
            { L"异常", crossViewAnomalyText(entry.anomalyFlags) },
            { L"置信度", std::to_wstring(entry.confidence) },
            { L"PID", std::to_wstring(entry.processId) },
            { L"TID", std::to_wstring(entry.threadId) },
            { L"Image", kImageName },
            { L"ThreadObject", hexText(entry.objectAddress) },
            { L"ProcessObject", hexText(entry.processObjectAddress) },
            { L"Start", hexText(entry.startAddress) },
            { L"StartAddress", hexText(entry.startAddress) },
            { L"SourceMask", hexText(entry.sourceMask) },
            { L"SourceText", crossViewSourceText(entry.sourceMask) },
            { L"Anomaly", hexText(entry.anomalyFlags) },
            { L"AnomalyText", crossViewAnomalyText(entry.anomalyFlags) },
            { L"DynData", hexText(entry.dynDataCapabilityMask) },
            { L"DynDataCapabilityMask", hexText(entry.dynDataCapabilityMask) },
            { L"EP.UniqueProcessId", hexText(entry.fieldOffsets.epUniqueProcessId) },
            { L"EP.ActiveProcessLinks", hexText(entry.fieldOffsets.epActiveProcessLinks) },
            { L"EP.ThreadListHead", hexText(entry.fieldOffsets.epThreadListHead) },
            { L"EP.ImageFileName", hexText(entry.fieldOffsets.epImageFileName) },
            { L"ET.Cid", hexText(entry.fieldOffsets.etCid) },
            { L"ET.ThreadListEntry", hexText(entry.fieldOffsets.etThreadListEntry) },
            { L"ET.StartAddress", hexText(entry.fieldOffsets.etStartAddress) },
            { L"ET.Win32StartAddress", hexText(entry.fieldOffsets.etWin32StartAddress) },
            { L"KT.Process", hexText(entry.fieldOffsets.ktProcess) },
            { L"HT.TableCode", hexText(entry.fieldOffsets.htTableCode) },
            { L"HTE.LowValue", hexText(entry.fieldOffsets.hteLowValue) },
            { L"PspCidTableRva", hexText(entry.fieldOffsets.pspCidTableRva) },
            { L"PspCidTable", hexText(entry.fieldOffsets.pspCidTableAddress) },
            { L"Confidence", std::to_wstring(entry.confidence) },
            { L"LastStatus", hexText(static_cast<std::uint32_t>(entry.lastStatus)) },
        }, utf8ToWide(entry.detail)));
    }
    return result;
}

// appendDriverIntegrityRows converts DriverIntegrityResult entries into generic
// rows. Inputs are the raw R0 query result and the UI operation result; processing
// appends every evidence row so KernelPage can perform local filtering without
// losing rows during edit-box changes; no value is returned.
void appendDriverIntegrityRows(const ksword::ark::DriverIntegrityResult& query, KernelOperationResult& result) {
    result.rows.push_back(makeResultRow({
        { L"Unsupported", boolText(query.unsupported) },
        { L"Version", std::to_wstring(query.version) },
        { L"Status", std::wstring(driverIntegrityStatusText(query.queryStatus)) + L" (" + std::to_wstring(query.queryStatus) + L")" },
        { L"Flags", hexText(query.flags) },
        { L"SourceMask", hexText(query.sourceMask) },
        { L"SourceText", driverIntegritySourceText(query.sourceMask) },
        { L"FieldFlags", hexText(query.fieldFlags) },
        { L"StatusFlags", hexText(query.statusFlags) },
        { L"Total", std::to_wstring(query.totalCount) },
        { L"Returned", std::to_wstring(query.returnedCount) },
        { L"CpuCount", std::to_wstring(query.cpuCount) },
        { L"ModuleCount", std::to_wstring(query.moduleCount) },
        { L"LastStatus", hexText(static_cast<std::uint32_t>(query.lastStatus)) },
    }));

    for (const ksword::ark::DriverIntegrityEvidenceEntry& entry : query.entries) {
        const std::wstring kOwnerDisplay = entry.ownerModule.empty()
            ? hexText(entry.ownerModuleBase)
            : entry.ownerModule + L" " + hexText(entry.ownerModuleBase);
        const std::wstring kCpuVector = cpuVectorText(entry.processorGroup, entry.processorNumber, entry.vector);
        result.rows.push_back(makeResultRow({
            { L"类别", driverIntegrityClassText(entry.evidenceClass) },
            { L"对象", hexText(entry.objectAddress) },
            { L"目标", hexText(entry.targetAddress) },
            { L"Owner", kOwnerDisplay },
            { L"CPU/Vector", kCpuVector },
            { L"风险", driverIntegrityRiskText(entry.riskFlags) },
            { L"置信度", std::to_wstring(entry.confidence) },
            { L"Class", std::to_wstring(entry.evidenceClass) },
            { L"ClassText", driverIntegrityClassText(entry.evidenceClass) },
            { L"Risk", hexText(entry.riskFlags) },
            { L"RiskText", driverIntegrityRiskText(entry.riskFlags) },
            { L"EntryStatus", std::to_wstring(entry.entryStatus) },
            { L"StatusFlags", hexText(entry.statusFlags) },
            { L"FieldMask", hexText(entry.fieldMask) },
            { L"RiskScore", std::to_wstring(entry.riskScore) },
            { L"RangeState", std::to_wstring(entry.rangeState) },
            { L"Ordinal", std::to_wstring(entry.ordinal) },
            { L"Source", hexText(entry.sourceMask) },
            { L"SourceText", driverIntegritySourceText(entry.sourceMask) },
            { L"Confidence", std::to_wstring(entry.confidence) },
            { L"Group", std::to_wstring(entry.processorGroup) },
            { L"CPU", std::to_wstring(entry.processorNumber) },
            { L"Vector", std::to_wstring(entry.vector) },
            { L"CpuVector", kCpuVector },
            { L"Object", hexText(entry.objectAddress) },
            { L"ObjectAddress", hexText(entry.objectAddress) },
            { L"Target", hexText(entry.targetAddress) },
            { L"TargetAddress", hexText(entry.targetAddress) },
            { L"OwnerBase", hexText(entry.ownerModuleBase) },
            { L"OwnerModuleBase", hexText(entry.ownerModuleBase) },
            { L"OwnerSize", hexText(entry.ownerModuleSize) },
            { L"OwnerModuleSize", hexText(entry.ownerModuleSize) },
            { L"OwnerModuleSizeText", sizeText(entry.ownerModuleSize) },
            { L"OwnerModule", entry.ownerModule },
            { L"DriverObject", hexText(entry.driverObjectAddress) },
            { L"DriverStart", hexText(entry.driverStart) },
            { L"DriverSize", sizeText(entry.driverSize) },
            { L"DriverSection", hexText(entry.driverSection) },
            { L"DriverUnload", hexText(entry.driverUnload) },
            { L"DeviceObject", hexText(entry.deviceObjectAddress) },
            { L"AttachedDevice", hexText(entry.attachedDeviceObjectAddress) },
            { L"KldrEntry", hexText(entry.kldrEntryAddress) },
            { L"KldrListHead", hexText(entry.kldrListHeadAddress) },
            { L"KldrDllBase", hexText(entry.kldrDllBase) },
            { L"KldrSize", sizeText(entry.kldrSizeOfImage) },
            { L"LastStatus", hexText(static_cast<std::uint32_t>(query.lastStatus)) },
        }, entry.detail));
    }
}

KernelOperationResult queryDriverIntegrity(const KernelRequest& request) {
    const ksword::ark::DriverClient kClient;
    std::uint64_t targetModuleBase = 0;
    const bool kHasModuleBaseFilter = parseFirstUnsigned64FromText(request.filterText, targetModuleBase);
    const unsigned long kMaxRows = request.maxRows == 0 ? KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_MAX_ROWS : request.maxRows;
    const ksword::ark::DriverIntegrityResult kQuery = kClient.queryDriverIntegrity(
        request.moduleFilterText,
        kHasModuleBaseFilter ? targetModuleBase : 0ULL,
        KSWORD_ARK_DRIVER_INTEGRITY_FLAG_DEFAULT | KSWORD_ARK_DRIVER_INTEGRITY_FLAG_OPTIONAL_GLOBALS,
        kMaxRows,
        KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_IDT_VECTORS);
    KernelOperationResult result;
    applyIoSummary(request, L"Driver Integrity", kQuery.io, result);
    if (kHasModuleBaseFilter) {
        result.rows.push_back(makeResultRow({
            { L"DriverIntegrityFilter", L"ModuleBase" },
            { L"ModuleBase", hexText(targetModuleBase) },
            { L"DriverName", request.moduleFilterText },
        }, L"R0 queryDriverIntegrity received targetModuleBase from the generic filter box."));
    }
    appendDriverIntegrityRows(kQuery, result);
    return result;
}

KernelOperationResult queryKernelCpuIntegrity(const KernelRequest& request) {
    const ksword::ark::DriverClient kClient;
    const unsigned long kMaxRows = request.maxRows == 0 ? KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_MAX_ROWS : request.maxRows;
    const unsigned long kIdtVectors = request.idtVectorLimit == 0 ? 0UL : request.idtVectorLimit;
    const unsigned long kFlags = kIdtVectors == 0
        ? KSWORD_ARK_DRIVER_INTEGRITY_FLAG_CPU
        : (KSWORD_ARK_DRIVER_INTEGRITY_FLAG_CPU | KSWORD_ARK_DRIVER_INTEGRITY_FLAG_IDT_ENTRIES);
    const ksword::ark::DriverIntegrityResult kQuery = kClient.queryKernelCpuIntegrity(
        kFlags,
        kMaxRows,
        kIdtVectors);
    KernelOperationResult result;
    applyIoSummary(request, L"CPU/IDT Integrity", kQuery.io, result);
    appendDriverIntegrityRows(kQuery, result);
    return result;
}

KernelOperationResult queryCpuHardwareSnapshot(const KernelRequest& request) {
    const ksword::ark::DriverClient kClient;
    const ksword::ark::CpuHardwareSnapshotResult kQuery = kClient.queryCpuHardwareSnapshot();
    KernelOperationResult result;
    applyIoSummary(request, L"CPU Hardware Snapshot", kQuery.io, result);
    const std::wstring kVendor = utf8ToWide(kQuery.vendor);
    const std::wstring kBrand = utf8ToWide(kQuery.brand);
    const std::wstring kFeatures = cpuFeatureText(kQuery.featureMask);
    const std::wstring kLeaves = L"basic=" + hexText(kQuery.maxBasicLeaf) + L" ext=" + hexText(kQuery.maxExtendedLeaf);
    result.rows.push_back(makeResultRow({
        { L"项目", L"R0 CPUID" },
        { L"值", kBrand.empty() ? kVendor : kBrand },
        { L"摘要", kVendor + L" F" + std::to_wstring(kQuery.family) + L"/M" + std::to_wstring(kQuery.model) + L"/S" + std::to_wstring(kQuery.stepping) },
        { L"状态", kQuery.io.ok ? L"OK" : L"Failed" },
        { L"Unsupported", boolText(kQuery.unsupported) },
        { L"Version", std::to_wstring(kQuery.version) },
        { L"FieldFlags", hexText(kQuery.fieldFlags) },
        { L"Vendor", kVendor },
        { L"Brand", kBrand },
        { L"Logical", std::to_wstring(kQuery.logicalProcessorCount) },
        { L"Active", std::to_wstring(kQuery.activeProcessorCount) },
        { L"Package", std::to_wstring(kQuery.packageCount) },
        { L"Family", std::to_wstring(kQuery.family) },
        { L"Model", std::to_wstring(kQuery.model) },
        { L"Stepping", std::to_wstring(kQuery.stepping) },
        { L"ProcessorType", std::to_wstring(kQuery.processorType) },
        { L"BrandIndex", std::to_wstring(kQuery.brandIndex) },
        { L"CLFlushLine", std::to_wstring(kQuery.clflushLineSize) },
        { L"InitialApicId", std::to_wstring(kQuery.initialApicId) },
        { L"MaxBasicLeaf", hexText(kQuery.maxBasicLeaf) },
        { L"MaxExtendedLeaf", hexText(kQuery.maxExtendedLeaf) },
        { L"Leaves", kLeaves },
        { L"FeatureMask", hexText(kQuery.featureMask) },
        { L"Features", kFeatures },
        { L"Leaf1ECX", hexText(kQuery.leaf1Ecx) },
        { L"Leaf1EDX", hexText(kQuery.leaf1Edx) },
        { L"Leaf7EBX", hexText(kQuery.leaf7Ebx) },
        { L"Leaf7ECX", hexText(kQuery.leaf7Ecx) },
        { L"Leaf7EDX", hexText(kQuery.leaf7Edx) },
        { L"Leaf80000001ECX", hexText(kQuery.leaf80000001Ecx) },
        { L"Leaf80000001EDX", hexText(kQuery.leaf80000001Edx) },
        { L"LastStatus", hexText(static_cast<std::uint32_t>(kQuery.lastStatus)) },
    }));
    return result;
}

// queryKernelTimerDpc returns the immutable R0 TimerTable snapshot. The caller
// executes this facade query on KernelPage's worker and only applies the value
// result when its request generation is still current.
KernelOperationResult queryKernelTimerDpc(const KernelRequest& request) {
    const ksword::ark::DriverClient kClient;
    const unsigned long kMaxEntries = request.maxRows == 0
        ? KSWORD_ARK_TIMER_DPC_DEFAULT_MAX_ENTRIES
        : request.maxRows;
    const ksword::ark::KernelTimerDpcEnumResult kQuery = kClient.enumerateKernelTimerDpc(kMaxEntries);
    KernelOperationResult result;
    applyIoSummary(request, L"Kernel Timer/DPC", kQuery.io, result);
    result.rows.push_back(makeResultRow({
        { L"Status", kQuery.io.ok ? L"OK" : L"Failed" },
        { L"Unsupported", boolText(kQuery.unsupported) },
        { L"Version", std::to_wstring(kQuery.version) },
        { L"QueryStatus", hexText(kQuery.queryStatus) },
        { L"StatusFlags", hexText(kQuery.statusFlags) },
        { L"Total", std::to_wstring(kQuery.totalCount) },
        { L"Returned", std::to_wstring(kQuery.returnedCount) },
        { L"ProcessorCount", std::to_wstring(kQuery.processorCount) },
        { L"BucketCount", std::to_wstring(kQuery.bucketCount) },
        { L"BucketsVisited", std::to_wstring(kQuery.bucketsVisited) },
        { L"CorruptBuckets", std::to_wstring(kQuery.corruptBucketCount) },
        { L"ReadFailures", std::to_wstring(kQuery.readFailureCount) },
        { L"Duplicates", std::to_wstring(kQuery.duplicateCount) },
        { L"LastStatus", hexText(static_cast<std::uint32_t>(kQuery.lastStatus)) },
    }, L"KTIMER/KDPC snapshot uses the driver's bounded per-bucket traversal. Partial or corrupt diagnostics remain visible in the query summary."));

    for (const ksword::ark::KernelTimerDpcEntry& entry : kQuery.entries) {
        const std::wstring kCpu = std::to_wstring(entry.processorGroup) + L":" + std::to_wstring(entry.processorNumber);
        std::wostringstream detail;
        detail << L"CPU: " << kCpu << L"\r\n"
               << L"Bucket: " << entry.bucketIndex << L"\r\n"
               << L"Timer: " << hexText(entry.timerAddress) << L"\r\n"
               << L"DueTime: " << entry.dueTime << L"\r\n"
               << L"Period: " << entry.period << L"\r\n"
               << L"TimerType: " << entry.timerType << L"\r\n"
               << L"DPC: " << hexText(entry.dpcAddress) << L"\r\n"
               << L"DeferredRoutine: " << hexText(entry.deferredRoutine) << L"\r\n"
               << L"DeferredContext: " << hexText(entry.deferredContext) << L"\r\n"
               << L"Flags: " << hexText(entry.flags);
        result.rows.push_back(makeResultRow({
            { L"CPU", kCpu },
            { L"Processor", kCpu },
            { L"Bucket", std::to_wstring(entry.bucketIndex) },
            { L"BucketIndex", std::to_wstring(entry.bucketIndex) },
            { L"Timer", hexText(entry.timerAddress) },
            { L"TimerAddress", hexText(entry.timerAddress) },
            { L"DueTime", std::to_wstring(entry.dueTime) },
            { L"Period", std::to_wstring(entry.period) },
            { L"类型", std::to_wstring(entry.timerType) },
            { L"TimerType", std::to_wstring(entry.timerType) },
            { L"DPC", hexText(entry.dpcAddress) },
            { L"Dpc", hexText(entry.dpcAddress) },
            { L"DpcAddress", hexText(entry.dpcAddress) },
            { L"例程", hexText(entry.deferredRoutine) },
            { L"DeferredRoutine", hexText(entry.deferredRoutine) },
            { L"上下文", hexText(entry.deferredContext) },
            { L"DeferredContext", hexText(entry.deferredContext) },
            { L"标志", hexText(entry.flags) },
            { L"Flags", hexText(entry.flags) },
            { L"状态", L"Captured" },
            { L"Status", L"Captured" },
        }, detail.str()));
    }
    return result;
}

// fixedWideField copies a fixed-size wide array out of a protocol row. The
// driver pads these to their full length, so a plain wstring(ptr) would read
// past the terminator when the field happens to be full.
std::wstring fixedWideField(const wchar_t* field, const std::size_t capacity) {
    if (field == nullptr || capacity == 0) {
        return {};
    }
    std::size_t length = 0;
    while (length < capacity && field[length] != L'\0') {
        ++length;
    }
    return std::wstring(field, length);
}

// fixedAnsiField is the same for the ANSI vendor strings the CPUID paths return.
std::wstring fixedAnsiField(const char* field, const std::size_t capacity) {
    if (field == nullptr || capacity == 0) {
        return {};
    }
    std::size_t length = 0;
    while (length < capacity && field[length] != '\0') {
        ++length;
    }
    std::wstring wide;
    wide.reserve(length);
    for (std::size_t index = 0; index < length; ++index) {
        wide.push_back(static_cast<wchar_t>(static_cast<unsigned char>(field[index])));
    }
    return wide;
}

// appendZeroResponseWarning flags a response the driver never actually filled.
// These IOCTL handlers zero the output buffer before calling their worker and
// still report the full length, so a worker that bails out early leaves a
// response whose queryStatus reads as STATUS_SUCCESS. version/size are set by
// the worker itself, so both being zero is the reliable "nothing ran" signal.
void appendZeroResponseWarning(
    const std::uint32_t version,
    const std::uint32_t size,
    std::vector<KernelResultRow>& rows) {
    if (version != 0 || size != 0) {
        return;
    }
    rows.push_back(makeResultRow({
        { L"Warning", L"R0 返回了全零响应" },
        { L"Meaning", L"驱动侧 worker 未写入任何字段，其中的 0 状态不代表成功" },
    }, L"IOCTL handler zeroes the output buffer before invoking its worker and still reports the full "
       L"response length. version/size are written by the worker, so both being zero means the worker "
       L"never ran and no field in this response should be trusted."));
}

// queryWorkQueueThreads enumerates ExWorkerQueue work items and their hosting
// threads. A work item whose routine sits outside any loaded module is the
// interesting case, so the module columns stay visible even when empty.
KernelOperationResult queryWorkQueueThreads(const KernelRequest& request) {
    const ksword::ark::DriverClient kClient;
    const unsigned long kMaxEntries = request.maxRows == 0
        ? KSWORD_ARK_WORK_QUEUE_DEFAULT_MAX_ENTRIES
        : request.maxRows;
    const ksword::ark::WorkQueueEnumResult kQuery =
        kClient.enumerateWorkQueues(KSWORD_ARK_WORK_QUEUE_FLAG_INCLUDE_ALL, kMaxEntries);
    KernelOperationResult result;
    applyIoSummary(request, L"Kernel WorkQueue", kQuery.io, result);
    result.rows.push_back(makeResultRow({
        { L"Status", kQuery.io.ok ? L"OK" : L"Failed" },
        { L"Unsupported", boolText(kQuery.unsupported) },
        { L"Version", std::to_wstring(kQuery.version) },
        { L"QueryStatus", hexText(kQuery.queryStatus) },
        { L"StatusFlags", hexText(kQuery.statusFlags) },
        { L"Total", std::to_wstring(kQuery.totalCount) },
        { L"Returned", std::to_wstring(kQuery.returnedCount) },
        { L"Nodes", std::to_wstring(kQuery.nodeCount) },
        { L"QueuesVisited", std::to_wstring(kQuery.queuesVisited) },
        { L"CorruptLists", std::to_wstring(kQuery.corruptListCount) },
        { L"ReadFailures", std::to_wstring(kQuery.readFailureCount) },
        { L"ReferenceFailures", std::to_wstring(kQuery.referenceFailureCount) },
        { L"LastStatus", hexText(static_cast<std::uint32_t>(kQuery.lastStatus)) },
    }, L"ExWorkerQueue traversal is bounded per queue by the driver. Corrupt-list and read-failure "
       L"counts stay visible so a partial walk is never mistaken for an empty one."));

    for (const ksword::ark::WorkQueueEntry& entry : kQuery.entries) {
        const std::wstring kModuleName = utf8ToWide(entry.moduleName);
        const std::wstring kModulePath = utf8ToWide(entry.modulePath);
        std::wostringstream detail;
        detail << L"RowKind: " << entry.rowKind << L"\r\n"
               << L"QueueType: " << entry.queueType << L"\r\n"
               << L"Priority: " << entry.priorityIndex << L"\r\n"
               << L"Node: " << entry.nodeIndex << L"\r\n"
               << L"Queue: " << hexText(entry.queueAddress) << L"\r\n"
               << L"WorkItem: " << hexText(entry.workItemAddress) << L"\r\n"
               << L"Routine: " << hexText(entry.routineAddress) << L"\r\n"
               << L"Parameter: " << hexText(entry.parameterAddress) << L"\r\n"
               << L"Thread: " << hexText(entry.threadObject) << L" (TID " << entry.threadId << L")\r\n"
               << L"ModuleBase: " << hexText(entry.moduleBase) << L"\r\n"
               << L"ModuleSize: " << hexText(entry.moduleSize) << L"\r\n"
               << L"ModulePath: " << kModulePath << L"\r\n"
               << L"Flags: " << hexText(entry.flags) << L"\r\n"
               << L"Status: " << hexText(entry.status);
        result.rows.push_back(makeResultRow({
            { L"QueueType", std::to_wstring(entry.queueType) },
            { L"Priority", std::to_wstring(entry.priorityIndex) },
            { L"Node", std::to_wstring(entry.nodeIndex) },
            { L"Queue", hexText(entry.queueAddress) },
            { L"WorkItem", hexText(entry.workItemAddress) },
            { L"Routine", hexText(entry.routineAddress) },
            { L"Module", kModuleName.empty() ? L"(未归属模块)" : kModuleName },
            { L"ThreadId", entry.threadId != 0 ? std::to_wstring(entry.threadId) : L"-" },
            { L"Thread", hexText(entry.threadObject) },
            { L"Flags", hexText(entry.flags) },
        }, detail.str()));
    }
    return result;
}

// querySlatIommuAudit reads the EPT/NPT cross-view probes plus DMAR/IVRS
// firmware evidence. A clean guest-visible result cannot prove an opaque outer
// SLAT is clean, which is why the probe mismatch counters are surfaced as their
// own row rather than folded into a verdict.
KernelOperationResult querySlatIommuAudit(const KernelRequest& request) {
    const ksword::ark::DriverClient kClient;
    const bool kIncludeMmio = (request.flags & kKernelRequestFlagIncludeInternal) != 0;
    const ksword::ark::SlatIommuAuditResult kQuery = kClient.querySlatIommuAudit(kIncludeMmio);
    KernelOperationResult result;
    applyIoSummary(request, L"SLAT/IOMMU Audit", kQuery.io, result);
    const KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_RESPONSE& response = kQuery.response;
    result.rows.push_back(makeResultRow({
        { L"Status", kQuery.io.ok ? L"OK" : L"Failed" },
        { L"Unsupported", boolText(kQuery.unsupported) },
        { L"Version", std::to_wstring(response.version) },
        { L"QueryStatus", hexText(static_cast<std::uint32_t>(response.queryStatus)) },
        { L"RiskFlags", hexText(response.riskFlags) },
        { L"FieldFlags", hexText(response.fieldFlags) },
        { L"CpuVendor", fixedAnsiField(response.cpuVendor, KSWORD_ARK_SLAT_IOMMU_VENDOR_CHARS) },
        { L"HypervisorVendor", fixedAnsiField(response.hypervisorVendor, KSWORD_ARK_SLAT_IOMMU_VENDOR_CHARS) },
        { L"Probes", std::to_wstring(response.probeCount) },
        { L"Mismatches", std::to_wstring(response.mismatchCount) },
        { L"Unstable", std::to_wstring(response.unstableCount) },
        { L"IommuRows", std::to_wstring(response.iommuRowCount) },
        { L"ReservedMemory", std::to_wstring(response.reservedMemoryCount) },
        { L"MalformedRows", std::to_wstring(response.malformedRowCount) },
        { L"DmarStatus", hexText(static_cast<std::uint32_t>(response.dmarStatus)) },
        { L"IvrsStatus", hexText(static_cast<std::uint32_t>(response.ivrsStatus)) },
        { L"IommuInterface", hexText(static_cast<std::uint32_t>(response.iommuInterfaceStatus)) },
        { L"VmxFeatureControl", hexText(response.vmxFeatureControl) },
        { L"VmxEptVpidCaps", hexText(response.vmxEptVpidCapabilities) },
        { L"AmdVmCr", hexText(response.amdVmCr) },
        { L"CpuidCycles", std::to_wstring(response.cpuidCyclesMinimum) + L"/" +
            std::to_wstring(response.cpuidCyclesMedian) + L"/" + std::to_wstring(response.cpuidCyclesMaximum) },
    }, L"Probe mismatches and CPUID timing spread are reported as raw counts. A guest-visible view that "
       L"looks clean cannot prove an outer SLAT is clean, so no verdict is derived here. "
       L"DMAR/IVRS use STATUS_NOT_FOUND when the firmware table is simply absent."));
    appendZeroResponseWarning(response.version, response.size, result.rows);
    return result;
}

// queryHvmStatus reads virtualization capability and takeover state. It never
// prepares, tests or tears down anything -- those are control actions.
KernelOperationResult queryHvmStatus(const KernelRequest& request) {
    const ksword::ark::DriverClient kClient;
    const ksword::ark::HvmStatusResult kQuery = kClient.queryHvmStatus();
    KernelOperationResult result;
    applyIoSummary(request, L"HVM Status", kQuery.io, result);
    const KSWORD_ARK_QUERY_HVM_RESPONSE& response = kQuery.response;
    result.rows.push_back(makeResultRow({
        { L"Status", kQuery.io.ok ? L"OK" : L"Failed" },
        { L"Unsupported", boolText(kQuery.unsupported) },
        { L"Version", std::to_wstring(response.version) },
        { L"QueryStatus", hexText(response.queryStatus) },
        { L"StateFlags", hexText(response.stateFlags) },
        { L"Generation", std::to_wstring(response.generation) },
        { L"Processors", std::to_wstring(response.processorCount) },
        { L"Prepared", std::to_wstring(response.preparedProcessorCount) },
        { L"SelfTestPassed", std::to_wstring(response.selfTestPassedProcessorCount) },
        { L"Resident", std::to_wstring(response.residentProcessorCount) },
        { L"ResidentImpl", std::to_wstring(response.residentImplementation) },
        { L"EptImpl", std::to_wstring(response.eptImplementation) },
        { L"NestedImpl", std::to_wstring(response.nestedImplementation) },
        { L"EvmcsImpl", std::to_wstring(response.evmcsImplementation) },
        { L"EptRules", std::to_wstring(response.eptRuleCount) },
        { L"EptPages", std::to_wstring(response.eptPageCount) },
        { L"Events", std::to_wstring(response.eventCount) },
        { L"DroppedEvents", std::to_wstring(response.droppedEventCount) },
        { L"OverwrittenEvents", std::to_wstring(response.overwrittenEventCount) },
        { L"PublishedEvents", std::to_wstring(response.publishedEventCount) },
        { L"NestedState", std::to_wstring(response.nestedState) },
        { L"EvmcsState", std::to_wstring(response.evmcsState) },
        { L"FeatureFlags", hexText(response.featureFlags) },
        { L"VmxBasic", hexText(response.vmxBasic) },
    }, L"Read-only virtualization state. preparedProcessorCount below processorCount means the takeover "
       L"is partial, which matters because a per-CPU view can differ from the machine-wide one."));
    appendZeroResponseWarning(response.version, response.size, result.rows);
    return result;
}

// queryHvmEvents drains the VM-exit event ring without clearing it. Clearing is
// deliberately not offered here: another reader would silently lose events.
KernelOperationResult queryHvmEvents(const KernelRequest& request) {
    const ksword::ark::DriverClient kClient;
    const unsigned long kMaxRows = request.maxRows == 0
        ? KSWORD_ARK_HVM_MAX_EVENT_ROWS
        : request.maxRows;
    const ksword::ark::HvmEventResult kQuery = kClient.queryHvmEvents(0, kMaxRows, false);
    KernelOperationResult result;
    applyIoSummary(request, L"HVM Events", kQuery.io, result);
    const KSWORD_ARK_HVM_EVENT_QUERY_RESPONSE& response = kQuery.response;
    result.rows.push_back(makeResultRow({
        { L"Status", kQuery.io.ok ? L"OK" : L"Failed" },
        { L"Unsupported", boolText(kQuery.unsupported) },
        { L"Version", std::to_wstring(response.version) },
        { L"Returned", std::to_wstring(response.returnedRows) },
        { L"Available", std::to_wstring(response.availableRows) },
        { L"Dropped", std::to_wstring(response.droppedRows) },
        { L"NewestSequence", std::to_wstring(response.newestSequence) },
    }, L"Nonblocking snapshot of the VM-exit ring, read without clearing it so a second reader does not "
       L"lose events. droppedRows counts entries overwritten before this read."));
    appendZeroResponseWarning(response.version, response.size, result.rows);

    const unsigned long kRowCount = response.returnedRows < KSWORD_ARK_HVM_MAX_EVENT_ROWS
        ? response.returnedRows
        : KSWORD_ARK_HVM_MAX_EVENT_ROWS;
    for (unsigned long index = 0; index < kRowCount; ++index) {
        const KSWORD_ARK_HVM_EVENT_ROW& row = response.rows[index];
        std::wostringstream rowDetail;
        rowDetail << L"Sequence: " << row.sequence << L"\r\n"
                  << L"Timestamp: " << row.timestamp << L"\r\n"
                  << L"CPU: " << row.processorGroup << L":" << static_cast<unsigned>(row.processorNumber) << L"\r\n"
                  << L"Type: " << row.type << L"\r\n"
                  << L"ExitReason: " << hexText(row.exitReason) << L"\r\n"
                  << L"Qualification: " << hexText(row.qualification) << L"\r\n"
                  << L"GuestRip: " << hexText(row.guestRip) << L"\r\n"
                  << L"GuestPhysical: " << hexText(row.guestPhysicalAddress) << L"\r\n"
                  << L"GuestLinear: " << hexText(row.guestLinearAddress) << L"\r\n"
                  << L"Access: " << hexText(row.access) << L"\r\n"
                  << L"RuleId: " << row.ruleId << L"\r\n"
                  << L"Status: " << hexText(static_cast<std::uint32_t>(row.status));
        result.rows.push_back(makeResultRow({
            { L"Sequence", std::to_wstring(row.sequence) },
            { L"CPU", std::to_wstring(row.processorGroup) + L":" + std::to_wstring(static_cast<unsigned>(row.processorNumber)) },
            { L"Type", std::to_wstring(row.type) },
            { L"ExitReason", hexText(row.exitReason) },
            { L"Qualification", hexText(row.qualification) },
            { L"GuestRip", hexText(row.guestRip) },
            { L"GuestPhysical", hexText(row.guestPhysicalAddress) },
            { L"Access", hexText(row.access) },
            { L"RuleId", std::to_wstring(row.ruleId) },
        }, rowDetail.str()));
    }
    return result;
}

// buildDriverTargetIdentity reads the target driver out of the shared filter
// box. These three queries address one driver rather than enumerating, because
// the underlying protocol is per-DriverObject.
struct DriverTargetIdentity {
    std::uint64_t moduleBase = 0;
    std::wstring driverName;
    bool valid = false;
};

DriverTargetIdentity buildDriverTargetIdentity(const KernelRequest& request) {
    DriverTargetIdentity identity;
    identity.driverName = request.filterText;
    identity.moduleBase = request.startAddress;
    identity.valid = !identity.driverName.empty() || identity.moduleBase != 0;
    return identity;
}

KernelOperationResult makeDriverTargetPrompt(const KernelRequest& request, const wchar_t* label) {
    KernelOperationResult result;
    result.supported = true;
    result.success = false;
    result.message = std::wstring(label) + L"：请先在过滤框输入驱动名（例如 disk.sys），或在起点地址填入模块基址。";
    result.rows.push_back(makeResultRow({
        { L"Hint", L"需要指定目标驱动" },
        { L"Filter", L"驱动名，例如 disk.sys" },
        { L"StartAddress", L"可选，模块基址" },
    }, L"This protocol addresses one DriverObject at a time rather than enumerating every driver, so a "
       L"target has to be named before the query can run."));
    static_cast<void>(request);
    return result;
}

// queryDriverDispatchTable reads one driver's MajorFunction slot against the
// baseline the driver recorded. Read-only: no slot is written here.
KernelOperationResult queryDriverDispatchTable(const KernelRequest& request) {
    const DriverTargetIdentity kIdentity = buildDriverTargetIdentity(request);
    if (!kIdentity.valid) {
        return makeDriverTargetPrompt(request, L"驱动派遣表");
    }
    const ksword::ark::DriverClient kClient;
    const unsigned long kMajorFunction = request.idtVectorLimit;
    const ksword::ark::DriverDispatchControlResult kQuery =
        kClient.queryDriverDispatch(kIdentity.moduleBase, kIdentity.driverName, kMajorFunction);
    KernelOperationResult result;
    applyIoSummary(request, L"Driver Dispatch", kQuery.io, result);
    result.rows.push_back(makeResultRow({
        { L"Status", kQuery.io.ok ? L"OK" : L"Failed" },
        { L"Unsupported", boolText(kQuery.unsupported) },
        { L"Version", std::to_wstring(kQuery.version) },
        { L"Driver", kIdentity.driverName.empty() ? hexText(kIdentity.moduleBase) : kIdentity.driverName },
        { L"MajorFunction", hexText(kQuery.majorFunction) },
        { L"State", std::to_wstring(kQuery.state) },
        { L"Generation", std::to_wstring(kQuery.generation) },
        { L"ModuleBase", hexText(kQuery.targetModuleBase) },
        { L"DriverObject", hexText(kQuery.driverObjectAddress) },
        { L"Current", hexText(kQuery.currentDispatchAddress) },
        { L"Original", hexText(kQuery.originalDispatchAddress) },
        { L"Applied", hexText(kQuery.appliedDispatchAddress) },
        { L"ResponseFlags", hexText(kQuery.responseFlags) },
        { L"LastStatus", hexText(static_cast<std::uint32_t>(kQuery.lastStatus)) },
    }, L"Current versus original dispatch address for one MajorFunction slot. Use the row limit box to "
       L"choose the major function index; 0 is IRP_MJ_CREATE."));
    return result;
}

// queryDriverImageFields reads one LDR image entry's identity fields together
// with whatever restore record the driver still holds for them.
KernelOperationResult queryDriverImageFields(const KernelRequest& request) {
    const DriverTargetIdentity kIdentity = buildDriverTargetIdentity(request);
    if (!kIdentity.valid) {
        return makeDriverTargetPrompt(request, L"驱动镜像字段");
    }
    const ksword::ark::DriverClient kClient;
    const ksword::ark::DriverImageControlResult kQuery =
        kClient.queryDriverImage(kIdentity.moduleBase, kIdentity.driverName);
    KernelOperationResult result;
    applyIoSummary(request, L"Driver Image", kQuery.io, result);
    result.rows.push_back(makeResultRow({
        { L"Status", kQuery.io.ok ? L"OK" : L"Failed" },
        { L"Unsupported", boolText(kQuery.unsupported) },
        { L"Version", std::to_wstring(kQuery.version) },
        { L"Driver", kIdentity.driverName.empty() ? hexText(kIdentity.moduleBase) : kIdentity.driverName },
        { L"State", std::to_wstring(kQuery.state) },
        { L"Generation", std::to_wstring(kQuery.generation) },
        { L"ModuleBase", hexText(kQuery.targetModuleBase) },
        { L"ManagedFields", hexText(kQuery.managedFieldMask) },
        { L"OwnedFields", hexText(kQuery.ownedFieldMask) },
        { L"ConflictFields", hexText(kQuery.conflictFieldMask) },
        { L"ChangedFields", hexText(kQuery.changedFieldMask) },
        { L"LayoutFlags", hexText(kQuery.layoutFlags) },
        { L"ResponseFlags", hexText(kQuery.responseFlags) },
        { L"LoaderStatus", hexText(static_cast<std::uint32_t>(kQuery.loaderStatus)) },
        { L"LastStatus", hexText(static_cast<std::uint32_t>(kQuery.lastStatus)) },
    }, L"A non-zero conflictFieldMask means a third party rewrote a field this driver still holds a "
       L"restore record for, so the recorded original can no longer be assumed to be the live value."));
    return result;
}

// queryDriverCommunication reads whether a driver's dispatch surface is
// currently pointed at the system reject entry, and who owns that state.
KernelOperationResult queryDriverCommunication(const KernelRequest& request) {
    const DriverTargetIdentity kIdentity = buildDriverTargetIdentity(request);
    if (!kIdentity.valid) {
        return makeDriverTargetPrompt(request, L"驱动通信端点");
    }
    const ksword::ark::DriverClient kClient;
    const ksword::ark::DriverCommunicationControlResult kQuery =
        kClient.queryDriverCommunication(kIdentity.moduleBase, kIdentity.driverName);
    KernelOperationResult result;
    applyIoSummary(request, L"Driver Communication", kQuery.io, result);
    result.rows.push_back(makeResultRow({
        { L"Status", kQuery.io.ok ? L"OK" : L"Failed" },
        { L"Version", std::to_wstring(kQuery.version) },
        { L"Driver", kIdentity.driverName.empty() ? hexText(kIdentity.moduleBase) : kIdentity.driverName },
        { L"State", std::to_wstring(kQuery.state) },
        { L"Generation", std::to_wstring(kQuery.generation) },
        { L"TargetedMask", hexText(kQuery.targetedMask) },
        { L"ActiveMask", hexText(kQuery.activeMask) },
        { L"OwnedMask", hexText(kQuery.ownedMask) },
        { L"ConflictMask", hexText(kQuery.conflictMask) },
        { L"ChangedMask", hexText(kQuery.changedMask) },
        { L"DriverObject", hexText(kQuery.driverObjectAddress) },
        { L"DriverStart", hexText(kQuery.driverStart) },
        { L"RejectDispatch", hexText(kQuery.rejectDispatchAddress) },
        { L"ResponseFlags", hexText(kQuery.responseFlags) },
        { L"LastStatus", hexText(static_cast<std::uint32_t>(kQuery.lastStatus)) },
    }, L"activeMask lists the MajorFunction slots currently pointing at the system reject entry. "
       L"ownedMask is the subset this driver may still restore; anything in conflictMask was rewritten "
       L"by someone else and is no longer safe to restore blindly."));
    return result;
}

// queryPlatformAudit reads HAL table entries, WDF functions and WDF callbacks
// with the driver's own signature-verified evidence attached.
KernelOperationResult queryPlatformAudit(const KernelRequest& request) {
    const ksword::ark::DriverClient kClient;
    const unsigned long kMaxRows = request.maxRows == 0
        ? KSWORD_ARK_PLATFORM_DEFAULT_MAX_ROWS
        : request.maxRows;
    const ksword::ark::PlatformAuditResult kQuery =
        kClient.queryPlatformAudit(KSWORD_ARK_PLATFORM_AUDIT_SCOPE_ALL, kMaxRows);
    KernelOperationResult result;
    applyIoSummary(request, L"Platform Audit", kQuery.io, result);
    result.rows.push_back(makeResultRow({
        { L"Status", kQuery.io.ok ? L"OK" : L"Failed" },
        { L"Unsupported", boolText(kQuery.unsupported) },
        { L"Version", std::to_wstring(kQuery.version) },
        { L"QueryStatus", hexText(kQuery.status) },
        { L"ScopeMask", hexText(kQuery.scopeMask) },
        { L"ResponseFlags", hexText(kQuery.responseFlags) },
        { L"BuildNumber", std::to_wstring(kQuery.buildNumber) },
        { L"SignaturePolicy", hexText(kQuery.signaturePolicyFlags) },
        { L"Total", std::to_wstring(kQuery.totalCount) },
        { L"Returned", std::to_wstring(kQuery.returnedCount) },
        { L"LastStatus", hexText(static_cast<std::uint32_t>(kQuery.lastStatus)) },
    }, L"HAL/WDF slot evidence. Rows carry the driver's own confidence and signature id rather than a "
       L"derived verdict, because an unrecognized prologue is not by itself evidence of a hook."));

    for (const KSWORD_ARK_PLATFORM_AUDIT_ENTRY& entry : kQuery.entries) {
        const std::wstring kName = fixedWideField(entry.name, KSWORD_ARK_PLATFORM_NAME_CHARS);
        const std::wstring kModulePath = fixedWideField(entry.modulePath, KSWORD_ARK_PLATFORM_MODULE_PATH_CHARS);
        std::wostringstream detail;
        detail << L"Name: " << kName << L"\r\n"
               << L"Scope: " << entry.scope << L"\r\n"
               << L"RowKind: " << entry.rowKind << L"\r\n"
               << L"EntryIndex: " << entry.entryIndex << L"\r\n"
               << L"Live: " << hexText(entry.liveAddress) << L"\r\n"
               << L"Original: " << hexText(entry.originalAddress) << L"\r\n"
               << L"Table: " << hexText(entry.tableAddress) << L"\r\n"
               << L"ModuleBase: " << hexText(entry.moduleBase) << L"\r\n"
               << L"ModuleSize: " << hexText(entry.moduleSize) << L"\r\n"
               << L"ModulePath: " << kModulePath << L"\r\n"
               << L"HookStatus: " << hexText(entry.hookStatus) << L"\r\n"
               << L"Confidence: " << entry.confidence << L"\r\n"
               << L"SignatureId: " << entry.signatureId << L"\r\n"
               << L"LastStatus: " << hexText(static_cast<std::uint32_t>(entry.lastStatus));
        result.rows.push_back(makeResultRow({
            { L"Name", kName.empty() ? L"(未命名槽)" : kName },
            { L"Scope", std::to_wstring(entry.scope) },
            { L"Index", std::to_wstring(entry.entryIndex) },
            { L"Live", hexText(entry.liveAddress) },
            { L"Original", hexText(entry.originalAddress) },
            { L"HookStatus", hexText(entry.hookStatus) },
            { L"Confidence", std::to_wstring(entry.confidence) },
            { L"Module", kModulePath },
        }, detail.str()));
    }
    return result;
}

// querySystemTimeState reads which performance-counter backend is in use and
// whether the multiplier is currently taken over. Read-only: the takeover
// itself is a control action and is not reachable from here.
KernelOperationResult querySystemTimeState(const KernelRequest& request) {
    const ksword::ark::DriverClient kClient;
    const ksword::ark::SystemTimeQueryResult kQuery = kClient.querySystemTime();
    KernelOperationResult result;
    applyIoSummary(request, L"System Time", kQuery.io, result);
    const KSWORD_ARK_QUERY_SYSTEM_TIME_RESPONSE& response = kQuery.response;
    result.rows.push_back(makeResultRow({
        { L"Status", kQuery.io.ok ? L"OK" : L"Failed" },
        { L"Unsupported", boolText(kQuery.unsupported) },
        { L"Version", std::to_wstring(response.version) },
        { L"QueryStatus", hexText(response.status) },
        { L"StateFlags", hexText(response.stateFlags) },
        { L"Generation", std::to_wstring(response.generation) },
        { L"Factor", std::to_wstring(response.factor) },
        { L"Backend", std::to_wstring(response.backend) },
        { L"ResolutionMode", std::to_wstring(response.resolutionMode) },
        { L"OsBuild", std::to_wstring(response.osBuildNumber) },
        { L"CounterValue", hexText(response.counterValue) },
        { L"CounterSource", hexText(response.counterSourceAddress) },
        { L"PrimarySlot", hexText(response.primarySlotAddress) },
        { L"SecondarySlot", hexText(response.secondarySlotAddress) },
        { L"HvSharedPage", hexText(response.hypervisorSharedPageAddress) },
        { L"HvOrigMultiplier", hexText(response.hypervisorOriginalMultiplier) },
        { L"HvCurMultiplier", hexText(response.hypervisorCurrentMultiplier) },
        { L"HvOrigBias", hexText(response.hypervisorOriginalBias) },
        { L"HvCurBias", hexText(response.hypervisorCurrentBias) },
        { L"LastStatus", hexText(static_cast<std::uint32_t>(response.lastStatus)) },
    }, L"A current multiplier or bias that differs from the recorded original means the system clock "
       L"rate is being scaled by someone. Under a hypervisor the shared-page values are the ones that "
       L"matter, since the guest-visible counter is derived from them."));
    appendZeroResponseWarning(response.version, response.size, result.rows);
    return result;
}

// queryI8042Audit enumerates the keyboard/mouse filter callbacks on the i8042
// port stack. A callback whose owning module is not the expected class driver
// is the classic shape of a kernel keylogger, so the owner module is a column
// rather than a detail-only field.
KernelOperationResult queryI8042Audit(const KernelRequest& request) {
    const ksword::ark::DriverClient kClient;
    const unsigned long kMaxRows = request.maxRows == 0
        ? KSWORD_ARK_I8042_DEFAULT_MAX_ROWS
        : request.maxRows;
    const ksword::ark::I8042AuditResult kQuery = kClient.queryI8042Audit(kMaxRows);
    KernelOperationResult result;
    applyIoSummary(request, L"i8042 Audit", kQuery.io, result);
    result.rows.push_back(makeResultRow({
        { L"Status", kQuery.io.ok ? L"OK" : L"Failed" },
        { L"Unsupported", boolText(kQuery.unsupported) },
        { L"Version", std::to_wstring(kQuery.version) },
        { L"QueryStatus", hexText(kQuery.status) },
        { L"ResponseFlags", hexText(kQuery.responseFlags) },
        { L"DescriptorId", std::to_wstring(kQuery.descriptorId) },
        { L"ImageBase", hexText(kQuery.imageBase) },
        { L"ImageSize", hexText(kQuery.imageSize) },
        { L"ImageTimeDateStamp", hexText(kQuery.imageTimeDateStamp) },
        { L"PdbAge", std::to_wstring(kQuery.pdbAge) },
        { L"Total", std::to_wstring(kQuery.totalCount) },
        { L"Returned", std::to_wstring(kQuery.returnedCount) },
        { L"LastStatus", hexText(static_cast<std::uint32_t>(kQuery.lastStatus)) },
    }, L"Endpoint rows are resolved against an exact i8042prt build descriptor. A zero descriptorId "
       L"means the running build was not recognized and the offsets behind these rows are unverified."));

    for (const KSWORD_ARK_I8042_AUDIT_ENTRY& entry : kQuery.entries) {
        const std::wstring kPnpId = fixedWideField(entry.pnpId, KSWORD_ARK_I8042_PNP_ID_CHARS);
        const std::wstring kOwnerPath = fixedWideField(entry.ownerModulePath, KSWORD_ARK_I8042_MODULE_PATH_CHARS);
        std::wostringstream detail;
        detail << L"PnpId: " << kPnpId << L"\r\n"
               << L"RowKind: " << entry.rowKind << L"\r\n"
               << L"DeviceKind: " << entry.deviceKind << L"\r\n"
               << L"EndpointKind: " << entry.endpointKind << L"\r\n"
               << L"Verdict: " << entry.verdict << L"\r\n"
               << L"DeviceObject: " << hexText(entry.deviceObject) << L"\r\n"
               << L"ClassDeviceObject: " << hexText(entry.classDeviceObject) << L"\r\n"
               << L"Callback: " << hexText(entry.callbackAddress) << L"\r\n"
               << L"Context: " << hexText(entry.contextAddress) << L"\r\n"
               << L"ModuleBase: " << hexText(entry.moduleBase) << L"\r\n"
               << L"ModuleSize: " << hexText(entry.moduleSize) << L"\r\n"
               << L"OwnerModule: " << kOwnerPath << L"\r\n"
               << L"DetailCode: " << hexText(entry.detailCode) << L"\r\n"
               << L"LastStatus: " << hexText(static_cast<std::uint32_t>(entry.lastStatus));
        result.rows.push_back(makeResultRow({
            { L"PnpId", kPnpId },
            { L"DeviceKind", std::to_wstring(entry.deviceKind) },
            { L"EndpointKind", std::to_wstring(entry.endpointKind) },
            { L"Verdict", std::to_wstring(entry.verdict) },
            { L"Callback", hexText(entry.callbackAddress) },
            { L"OwnerModule", kOwnerPath.empty() ? L"(未归属模块)" : kOwnerPath },
            { L"DeviceObject", hexText(entry.deviceObject) },
            { L"Status", hexText(entry.status) },
        }, detail.str()));
    }
    return result;
}

// queryPiDdbCache enumerates PiDDBCacheTable, which records every driver the
// loader has vetted. Its entries survive an unload, so a driver that is gone
// from the module list can still be named here.
KernelOperationResult queryPiDdbCache(const KernelRequest& request) {
    const ksword::ark::DriverClient kClient;
    const unsigned long kMaxRows = request.maxRows == 0
        ? KSWORD_ARK_PIDDB_DEFAULT_ROWS
        : request.maxRows;
    const ksword::ark::PiDdbQueryResult kQuery = kClient.queryPiDdb(kMaxRows);
    KernelOperationResult result;
    applyIoSummary(request, L"PiDDB Cache", kQuery.io, result);
    result.rows.push_back(makeResultRow({
        { L"Status", kQuery.io.ok ? L"OK" : L"Failed" },
        { L"Unsupported", boolText(kQuery.unsupported) },
        { L"QueryStatus", hexText(kQuery.queryStatus) },
        { L"ResponseFlags", hexText(kQuery.responseFlags) },
        { L"Total", std::to_wstring(kQuery.totalRows) },
        { L"Returned", std::to_wstring(kQuery.entries.size()) },
        { L"LastStatus", hexText(static_cast<std::uint32_t>(kQuery.lastStatus)) },
    }, L"PiDDBCacheTable is walked read-only. Entries persist after a driver unloads, which is why this "
       L"table and the loaded-module list disagree by design."));

    for (const ksword::ark::PiDdbEntry& entry : kQuery.entries) {
        std::wostringstream detail;
        detail << L"Driver: " << entry.driverName << L"\r\n"
               << L"Entry: " << hexText(entry.entryAddress) << L"\r\n"
               << L"TimeDateStamp: " << hexText(entry.timeDateStamp) << L"\r\n"
               << L"LoadStatus: " << hexText(static_cast<std::uint32_t>(entry.loadStatus));
        result.rows.push_back(makeResultRow({
            { L"Driver", entry.driverName },
            { L"TimeDateStamp", hexText(entry.timeDateStamp) },
            { L"LoadStatus", hexText(static_cast<std::uint32_t>(entry.loadStatus)) },
            { L"Entry", hexText(entry.entryAddress) },
        }, detail.str()));
    }
    return result;
}

// formatIpAddress renders one 16-byte address slot. IPv4 rows leave the trailing
// 12 bytes zeroed, so the family decides how many of them mean anything.
std::wstring formatIpAddress(const unsigned char* address, const unsigned long addressFamily) {
    if (address == nullptr) {
        return {};
    }
    std::wostringstream text;
    // AF_INET6 is 23 on Windows; anything else is rendered as IPv4 because the
    // driver only ever fills these two shapes.
    if (addressFamily == 23UL) {
        for (int group = 0; group < 8; ++group) {
            if (group != 0) {
                text << L':';
            }
            const unsigned kValue =
                (static_cast<unsigned>(address[group * 2]) << 8) | static_cast<unsigned>(address[group * 2 + 1]);
            text << std::hex << kValue;
        }
        return text.str();
    }
    text << static_cast<unsigned>(address[0]) << L'.' << static_cast<unsigned>(address[1]) << L'.'
         << static_cast<unsigned>(address[2]) << L'.' << static_cast<unsigned>(address[3]);
    return text.str();
}

// queryRawDiskSectors reads sector-aligned bytes straight off a physical disk
// through the driver's storage backend. The disk number comes from the filter
// box and the byte offset from the start-address box; both are required because
// there is no sane default for "which disk to read".
KernelOperationResult queryRawDiskSectors(const KernelRequest& request) {
    const ksword::ark::DriverClient kClient;
    unsigned long diskNumber = 0;
    bool diskNumberValid = false;
    if (!request.filterText.empty()) {
        try {
            diskNumber = static_cast<unsigned long>(std::stoul(request.filterText));
            diskNumberValid = true;
        } catch (const std::exception&) {
            diskNumberValid = false;
        }
    }
    if (!diskNumberValid) {
        KernelOperationResult prompt;
        prompt.supported = true;
        prompt.success = false;
        prompt.message = L"物理磁盘扇区：请在过滤框填写磁盘号（0 表示 PhysicalDrive0），起点地址填字节偏移。";
        prompt.rows.push_back(makeResultRow({
            { L"Hint", L"需要磁盘号" },
            { L"Filter", L"磁盘号，例如 0" },
            { L"StartAddress", L"字节偏移，会被向下对齐到扇区边界" },
            { L"MaxRows", L"读取字节数，默认一个扇区" },
        }, L"Reading a physical disk has no meaningful default target, so the disk number is required "
           L"rather than guessed."));
        return prompt;
    }

    KernelOperationResult result;
    const ksword::ark::RawDiskBackendResult kBackend = kClient.queryRawDiskBackend(diskNumber);
    applyIoSummary(request, L"Raw Disk", kBackend.io, result);
    const KSWORD_ARK_QUERY_RAW_DISK_BACKEND_RESPONSE& info = kBackend.response;
    const unsigned long kSectorSize = info.logicalSectorSize != 0 ? info.logicalSectorSize : 512UL;
    result.rows.push_back(makeResultRow({
        { L"Status", kBackend.io.ok ? L"OK" : L"Failed" },
        { L"Unsupported", boolText(kBackend.unsupported) },
        { L"Disk", std::to_wstring(info.diskNumber) },
        { L"BackendStatus", hexText(info.status) },
        { L"Capabilities", hexText(info.capabilityFlags) },
        { L"AvailableBackends", hexText(info.availableBackendMask) },
        { L"LogicalSector", std::to_wstring(info.logicalSectorSize) },
        { L"PhysicalSector", std::to_wstring(info.physicalSectorSize) },
        { L"DiskSize", std::to_wstring(info.diskSizeBytes) },
        { L"BusType", std::to_wstring(info.busType) },
        { L"Model", fixedWideField(info.model, KSWORD_ARK_RAW_DISK_MODEL_CHARS) },
        { L"Serial", fixedWideField(info.serial, KSWORD_ARK_RAW_DISK_SERIAL_CHARS) },
        { L"DevicePath", fixedWideField(info.devicePath, KSWORD_ARK_RAW_DISK_PATH_CHARS) },
        { L"Detail", fixedWideField(info.detail, KSWORD_ARK_RAW_DISK_DETAIL_CHARS) },
        { L"LastStatus", hexText(static_cast<std::uint32_t>(info.lastStatus)) },
    }, L"Backend capability for this disk. availableBackendMask lists which of the three storage paths "
       L"the driver can actually use here."));
    if (!kBackend.io.ok) {
        return result;
    }

    // Both offset and length are snapped to the sector grid, because the storage
    // path rejects anything else and a silent partial read would be worse.
    const std::uint64_t kAlignedOffset = (request.startAddress / kSectorSize) * kSectorSize;
    unsigned long requestedLength = request.maxRows == 0 ? kSectorSize : request.maxRows;
    requestedLength = ((requestedLength + kSectorSize - 1) / kSectorSize) * kSectorSize;
    if (requestedLength > KSWORD_ARK_RAW_DISK_MAX_TRANSFER_BYTES) {
        requestedLength = KSWORD_ARK_RAW_DISK_MAX_TRANSFER_BYTES;
    }

    const ksword::ark::RawDiskReadResult kRead =
        kClient.readRawDisk(diskNumber, 0UL, kAlignedOffset, requestedLength);
    result.rows.push_back(makeResultRow({
        { L"ReadStatus", hexText(kRead.status) },
        { L"BackendUsed", std::to_wstring(kRead.backendUsed) },
        { L"SectorSize", std::to_wstring(kRead.logicalSectorSize) },
        { L"Offset", hexText(kAlignedOffset) },
        { L"Requested", std::to_wstring(requestedLength) },
        { L"Returned", std::to_wstring(kRead.bytes.size()) },
        { L"Transport", kRead.io.ok ? L"OK" : L"Failed" },
    }, L"Offset and length are aligned down/up to the logical sector size before the request is sent; "
       L"the storage path rejects unaligned transfers outright."));

    // 16 bytes per row keeps each line readable next to the offset column.
    constexpr std::size_t kBytesPerRow = 16;
    for (std::size_t offset = 0; offset < kRead.bytes.size(); offset += kBytesPerRow) {
        const std::size_t kChunk = (std::min)(kBytesPerRow, kRead.bytes.size() - offset);
        std::wostringstream hex;
        std::wostringstream ascii;
        for (std::size_t index = 0; index < kChunk; ++index) {
            const unsigned char kValue = kRead.bytes[offset + index];
            if (index != 0) {
                hex << L' ';
            }
            hex << std::uppercase << std::hex << std::setw(2) << std::setfill(L'0') << static_cast<unsigned>(kValue);
            ascii << (kValue >= 0x20 && kValue < 0x7F ? static_cast<wchar_t>(kValue) : L'.');
        }
        result.rows.push_back(makeResultRow({
            { L"Offset", hexText(kAlignedOffset + offset) },
            { L"Hex", hex.str() },
            { L"Ascii", ascii.str() },
        }, L"Raw sector bytes."));
    }
    return result;
}

// queryNetworkTrafficPackets drains the R0 WFP per-packet ring. The capture is
// off by default and its start/stop switch is a control action, so an empty
// result here usually means capture was never turned on rather than that no
// traffic occurred.
KernelOperationResult queryNetworkTrafficPackets(const KernelRequest& request) {
    const ksword::ark::DriverClient kClient;
    const unsigned long kMaxRows = request.maxRows == 0
        ? KSWORD_ARK_NETWORK_TRAFFIC_DEFAULT_REQUESTED_ROWS
        : request.maxRows;
    const ksword::ark::NetworkTrafficPacketResult kQuery = kClient.queryNetworkTrafficPackets(0, kMaxRows);
    KernelOperationResult result;
    applyIoSummary(request, L"Network Traffic", kQuery.io, result);
    result.rows.push_back(makeResultRow({
        { L"Status", kQuery.io.ok ? L"OK" : L"Failed" },
        { L"Unsupported", boolText(kQuery.unsupported) },
        { L"Version", std::to_wstring(kQuery.version) },
        { L"QueryStatus", hexText(kQuery.status) },
        { L"Capacity", std::to_wstring(kQuery.capacity) },
        { L"OldestSequence", std::to_wstring(kQuery.oldestSequence) },
        { L"NewestSequence", std::to_wstring(kQuery.newestSequence) },
        { L"NextCursor", std::to_wstring(kQuery.nextSequence) },
        { L"DroppedPackets", std::to_wstring(kQuery.droppedPacketCount) },
        { L"CursorGap", std::to_wstring(kQuery.cursorGapCount) },
        { L"Total", std::to_wstring(kQuery.totalCount) },
        { L"Returned", std::to_wstring(kQuery.entries.size()) },
        { L"LastStatus", hexText(static_cast<std::uint32_t>(kQuery.lastStatus)) },
    }, L"Packets come from the driver's own WFP capture ring, so no Npcap or raw-socket path is "
       L"involved. Capture is off until it is explicitly started, which is why an empty ring with a "
       L"zero newestSequence means it was never running rather than that the link was idle. "
       L"droppedPacketCount counts packets the ring overwrote before anyone read them."));

    for (const KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW& row : kQuery.entries) {
        const std::wstring kLocal =
            formatIpAddress(row.localAddress, row.addressFamily) + L":" + std::to_wstring(row.localPort);
        const std::wstring kRemote =
            formatIpAddress(row.remoteAddress, row.addressFamily) + L":" + std::to_wstring(row.remotePort);
        std::wostringstream detail;
        detail << L"Sequence: " << row.sequence << L"\r\n"
               << L"Timestamp: " << row.timestamp100ns << L"\r\n"
               << L"Family: " << row.addressFamily << L"\r\n"
               << L"Direction: " << row.direction << L"\r\n"
               << L"Protocol: " << row.protocol << L"\r\n"
               << L"ProcessId: " << row.processId << L"\r\n"
               << L"Local: " << kLocal << L"\r\n"
               << L"Remote: " << kRemote << L"\r\n"
               << L"TotalLength: " << row.totalPacketLength << L"\r\n"
               << L"CapturedLength: " << row.capturedLength << L"\r\n"
               << L"PayloadOffset: " << row.payloadOffset << L"\r\n"
               << L"PayloadLength: " << row.payloadLength << L"\r\n"
               << L"Flags: " << hexText(row.flags);
        result.rows.push_back(makeResultRow({
            { L"Sequence", std::to_wstring(row.sequence) },
            { L"Direction", std::to_wstring(row.direction) },
            { L"Protocol", std::to_wstring(row.protocol) },
            { L"Local", kLocal },
            { L"Remote", kRemote },
            { L"ProcessId", row.processId != 0 ? std::to_wstring(row.processId) : L"-" },
            { L"Length", std::to_wstring(row.totalPacketLength) },
            { L"Captured", std::to_wstring(row.capturedLength) },
        }, detail.str()));
    }
    return result;
}

// queryIoctlRegistry exposes the driver's registered dispatch metadata without
// duplicating transport primitives in the UI. It is a read-only bounded query.
KernelOperationResult queryIoctlRegistry(const KernelRequest& request) {
    const ksword::ark::DriverClient kClient;
    const unsigned long kMaxEntries = request.maxRows == 0
        ? KSWORD_ARK_IOCTL_REGISTRY_MAX_ENTRIES
        : request.maxRows;
    const ksword::ark::IoctlRegistryQueryResult kQuery = kClient.queryIoctlRegistry(
        KSWORD_ARK_IOCTL_REGISTRY_FLAG_INCLUDE_HANDLER,
        kMaxEntries);
    KernelOperationResult result;
    applyIoSummary(request, L"IOCTL Dispatch Registry", kQuery.io, result);
    result.rows.push_back(makeResultRow({
        { L"Status", kQuery.io.ok ? L"OK" : L"Failed" },
        { L"Unsupported", boolText(kQuery.unsupported) },
        { L"Version", std::to_wstring(kQuery.version) },
        { L"RegistryStatus", hexText(kQuery.status) },
        { L"Total", std::to_wstring(kQuery.totalCount) },
        { L"Returned", std::to_wstring(kQuery.returnedCount) },
        { L"Duplicates", std::to_wstring(kQuery.duplicateCount) },
        { L"LastStatus", hexText(static_cast<std::uint32_t>(kQuery.lastStatus)) },
    }, L"The registry is a diagnostic snapshot of handlers registered by KswordARK's centralized IOCTL dispatcher."));

    for (const ksword::ark::IoctlRegistryEntry& entry : kQuery.entries) {
        const std::wstring kMethodAccess = std::to_wstring(entry.method) + L" / " + std::to_wstring(entry.access);
        const std::wstring kName = utf8ToWide(entry.name);
        std::wostringstream detail;
        detail << L"IOCTL: " << hexText(entry.ioControlCode) << L"\r\n"
               << L"Function: " << entry.functionNumber << L"\r\n"
               << L"Method/Access: " << kMethodAccess << L"\r\n"
               << L"Required capability: " << hexText(entry.requiredCapability) << L"\r\n"
               << L"Handler: " << hexText(entry.handlerAddress) << L"\r\n"
               << L"Name: " << kName << L"\r\n"
               << L"Flags: " << hexText(entry.flags);
        result.rows.push_back(makeResultRow({
            { L"IOCTL", hexText(entry.ioControlCode) },
            { L"IoControlCode", hexText(entry.ioControlCode) },
            { L"函数", std::to_wstring(entry.functionNumber) },
            { L"Function", std::to_wstring(entry.functionNumber) },
            { L"FunctionNumber", std::to_wstring(entry.functionNumber) },
            { L"Method/Access", kMethodAccess },
            { L"MethodAccess", kMethodAccess },
            { L"Capability", hexText(entry.requiredCapability) },
            { L"RequiredCapability", hexText(entry.requiredCapability) },
            { L"Handler", hexText(entry.handlerAddress) },
            { L"HandlerAddress", hexText(entry.handlerAddress) },
            { L"名称", kName },
            { L"Name", kName },
            { L"Flags", hexText(entry.flags) },
            { L"状态", L"Registered" },
            { L"Status", L"Registered" },
        }, detail.str()));
    }
    return result;
}

KernelOperationResult queryPhysicalMemoryLayout(const KernelRequest& request) {
    const ksword::ark::DriverClient kClient;
    const ksword::ark::PhysicalMemoryLayoutResult kQuery = kClient.queryPhysicalMemoryLayout();
    KernelOperationResult result;
    applyIoSummary(request, L"Physical Memory Layout", kQuery.io, result);
    result.rows.push_back(makeResultRow({
        { L"范围", std::to_wstring(kQuery.rangeCount) },
        { L"总物理内存", sizeText(kQuery.totalPhysicalBytes) },
        { L"最高物理地址", hexText(kQuery.highestPhysicalAddress) },
        { L"最大连续Range", sizeText(kQuery.largestRangeBytes) },
        { L"状态", kQuery.io.ok ? L"OK" : L"Failed" },
        { L"Unsupported", boolText(kQuery.unsupported) },
        { L"Version", std::to_wstring(kQuery.version) },
        { L"FieldFlags", hexText(kQuery.fieldFlags) },
        { L"Ranges", std::to_wstring(kQuery.rangeCount) },
        { L"ZeroRanges", std::to_wstring(kQuery.zeroLengthRangeCount) },
        { L"Truncated", std::to_wstring(kQuery.truncated) },
        { L"TotalBytes", hexText(kQuery.totalPhysicalBytes) },
        { L"TotalText", sizeText(kQuery.totalPhysicalBytes) },
        { L"HighestAddress", hexText(kQuery.highestPhysicalAddress) },
        { L"LargestRange", hexText(kQuery.largestRangeBytes) },
        { L"LargestRangeText", sizeText(kQuery.largestRangeBytes) },
        { L"SmallestRange", hexText(kQuery.smallestRangeBytes) },
        { L"SmallestRangeText", sizeText(kQuery.smallestRangeBytes) },
        { L"FirstBase", hexText(kQuery.firstBaseAddress) },
        { L"LastEnd", hexText(kQuery.lastEndAddress) },
        { L"GapBytes", hexText(kQuery.estimatedAddressSpaceGapBytes) },
        { L"GapText", sizeText(kQuery.estimatedAddressSpaceGapBytes) },
        { L"LastStatus", hexText(static_cast<std::uint32_t>(kQuery.lastStatus)) },
    }));
    return result;
}

KernelOperationResult queryMutationAudit(const KernelRequest& request) {
    const ksword::ark::DriverClient kClient;
    const ksword::ark::MutationAuditResult kQuery = kClient.queryMutationAudit(KSWORD_ARK_MUTATION_QUERY_AUDIT_FLAG_INCLUDE_BYTES);
    KernelOperationResult result;
    applyIoSummary(request, L"Mutation Audit", kQuery.io, result);
    result.rows.push_back(makeResultRow({
        { L"Unsupported", boolText(kQuery.unsupported) },
        { L"Version", std::to_wstring(kQuery.version) },
        { L"Total", std::to_wstring(kQuery.totalCount) },
        { L"Returned", std::to_wstring(kQuery.returnedCount) },
        { L"Lost", std::to_wstring(kQuery.lostCount) },
        { L"OldestSeq", hexText(kQuery.oldestSequence) },
        { L"NextSeq", hexText(kQuery.nextSequence) },
    }));

    for (const ksword::ark::MutationAuditEntry& entry : kQuery.entries) {
        result.rows.push_back(makeResultRow({
            { L"Seq", hexText(entry.sequence) },
            { L"Tx", hexText(entry.transactionId) },
            { L"TransactionId", std::to_wstring(entry.transactionId) },
            { L"TransactionIdHex", hexText(entry.transactionId) },
            { L"Operation", std::wstring(mutationOperationText(entry.operation)) + L" (" + std::to_wstring(entry.operation) + L")" },
            { L"OperationText", mutationOperationText(entry.operation) },
            { L"Status", std::wstring(mutationStatusText(entry.status)) + L" (" + std::to_wstring(entry.status) + L")" },
            { L"StatusText", mutationStatusText(entry.status) },
            { L"TargetKind", std::wstring(mutationTargetText(entry.targetKind)) + L" (" + std::to_wstring(entry.targetKind) + L")" },
            { L"TargetKindText", mutationTargetText(entry.targetKind) },
            { L"Risk", hexText(entry.riskFlags) },
            { L"RiskText", mutationRiskText(entry.riskFlags) },
            { L"Flags", hexText(entry.flags) },
            { L"FlagsText", mutationFlagsText(entry.flags) },
            { L"PID", std::to_wstring(entry.processId) },
            { L"Address", hexText(entry.targetAddress) },
            { L"Context", hexText(entry.targetContext) },
            { L"Bytes", std::to_wstring(entry.bytes) },
            { L"BeforeHash", hexText(entry.beforeHash) },
            { L"AfterHash", hexText(entry.afterHash) },
            { L"Data", bytesHex(entry.byteData) },
            { L"LastStatus", hexText(static_cast<std::uint32_t>(entry.lastStatus)) },
        }));
    }
    return result;
}

KernelOperationResult queryKeyboardHotkeys(const KernelRequest& request) {
    const ksword::ark::DriverClient kClient;
    const std::uint32_t kPidFilter = parseFirstPidFromText(request.filterText);
    const ksword::ark::KeyboardHotkeyEnumResult kQuery = kClient.enumerateKeyboardHotkeys(kPidFilter);
    KernelOperationResult result;
    applyIoSummary(request, L"Keyboard Hotkeys", kQuery.io, result);
    result.rows.push_back(makeResultRow({
        { L"Version", std::to_wstring(kQuery.version) },
        { L"Status", std::wstring(keyboardEnumStatusText(kQuery.status)) + L" (" + std::to_wstring(kQuery.status) + L")" },
        { L"Total", std::to_wstring(kQuery.totalCount) },
        { L"Returned", std::to_wstring(kQuery.returnedCount) },
        { L"Flags", hexText(kQuery.flags) },
        { L"Win32kBase", hexText(kQuery.win32kBase) },
        { L"SessionGlobals", hexText(kQuery.sessionGlobals) },
        { L"TableOffset", hexText(kQuery.tableOffset) },
        { L"HotkeyNextOffset", hexText(kQuery.hotkeyNextOffset) },
        { L"HotkeyModifiersOffset", hexText(kQuery.hotkeyModifiersOffset) },
        { L"HotkeyVkOffset", hexText(kQuery.hotkeyVkOffset) },
        { L"HotkeyIdOffset", hexText(kQuery.hotkeyIdOffset) },
        { L"PidFilter", kPidFilter == 0 ? L"" : std::to_wstring(kPidFilter) },
        { L"LastStatus", hexText(static_cast<std::uint32_t>(kQuery.lastStatus)) },
    }));
    for (const ksword::ark::KeyboardHotkeyEntry& entry : kQuery.entries) {
        const std::wstring kProcessName = processDisplayName(entry.processId);
        const std::wstring kHotkeyText = hotkeyDisplayText(entry.modifiers, entry.virtualKey, entry.hotkeyId);
        const std::wstring kVkModText = L"VK=" + hexText(entry.virtualKey) + L" Mod=" + hexText(entry.modifiers);
        result.rows.push_back(makeResultRow({
            { L"对象", hexText(entry.hotkeyObject) },
            { L"热键ID", hexText(entry.hotkeyId) },
            { L"进程ID", std::to_wstring(entry.processId) },
            { L"线程ID", std::to_wstring(entry.threadId) },
            { L"进程名", kProcessName },
            { L"VK/Mod", kVkModText },
            { L"详情", entry.detail },
            { L"PID", std::to_wstring(entry.processId) },
            { L"TID", std::to_wstring(entry.threadId) },
            { L"Process", kProcessName },
            { L"窗口", hexText(entry.windowObject) },
            { L"热键", kHotkeyText },
            { L"来源", keyboardSourceText(entry.source) },
            { L"VK", hexText(entry.virtualKey) },
            { L"Modifiers", hexText(entry.modifiers) },
            { L"ModifierFlags2", hexText(entry.modifierFlags2) },
            { L"Id", hexText(entry.hotkeyId) },
            { L"Object", hexText(entry.hotkeyObject) },
            { L"Next", hexText(entry.nextHotkeyObject) },
            { L"ThreadInfo", hexText(entry.threadInfo) },
            { L"ThreadObject", hexText(entry.threadObject) },
            { L"WindowObject", hexText(entry.windowObject) },
            { L"Source", hexText(entry.source) },
            { L"SourceText", keyboardSourceText(entry.source) },
            { L"Status", std::wstring(keyboardEnumStatusText(entry.status)) + L" (" + std::to_wstring(entry.status) + L")" },
            { L"Flags", hexText(entry.flags) },
            { L"Bucket", std::to_wstring(entry.bucketIndex) },
            { L"Depth", std::to_wstring(entry.depth) },
            { L"LastStatus", hexText(static_cast<std::uint32_t>(entry.lastStatus)) },
        }, entry.detail));
    }
    return result;
}

KernelOperationResult queryKeyboardHooks(const KernelRequest& request) {
    const ksword::ark::DriverClient kClient;
    const std::uint32_t kPidFilter = parseFirstPidFromText(request.filterText);
    const ksword::ark::KeyboardHookEnumResult kQuery = kClient.enumerateKeyboardHooks(kPidFilter);
    KernelOperationResult result;
    applyIoSummary(request, L"Keyboard Hooks", kQuery.io, result);
    result.rows.push_back(makeResultRow({
        { L"Version", std::to_wstring(kQuery.version) },
        { L"Status", std::wstring(keyboardEnumStatusText(kQuery.status)) + L" (" + std::to_wstring(kQuery.status) + L")" },
        { L"Total", std::to_wstring(kQuery.totalCount) },
        { L"Returned", std::to_wstring(kQuery.returnedCount) },
        { L"Flags", hexText(kQuery.flags) },
        { L"Win32kBase", hexText(kQuery.win32kBase) },
        { L"ThreadHookArrayOffset", hexText(kQuery.threadHookArrayOffset) },
        { L"DesktopInfoOffset", hexText(kQuery.desktopInfoOffset) },
        { L"DesktopHookArrayOffset", hexText(kQuery.desktopHookArrayOffset) },
        { L"HookNextOffset", hexText(kQuery.hookNextOffset) },
        { L"HookTypeOffset", hexText(kQuery.hookTypeOffset) },
        { L"HookProcedureOffset", hexText(kQuery.hookProcedureOffset) },
        { L"HookFlagsOffset", hexText(kQuery.hookFlagsOffset) },
        { L"HookModuleIdOffset", hexText(kQuery.hookModuleIdOffset) },
        { L"HookTargetThreadInfoOffset", hexText(kQuery.hookTargetThreadInfoOffset) },
        { L"PidFilter", kPidFilter == 0 ? L"" : std::to_wstring(kPidFilter) },
        { L"LastStatus", hexText(static_cast<std::uint32_t>(kQuery.lastStatus)) },
    }));
    for (const ksword::ark::KeyboardHookEntry& entry : kQuery.entries) {
        const std::wstring kProcessName = processDisplayName(entry.processId);
        const std::wstring kModuleDisplay = entry.moduleBase != 0
            ? hexText(entry.moduleBase)
            : std::wstring(L"ModuleId ") + std::to_wstring(entry.moduleId);
        const std::wstring kProcedureDisplay = hexText(entry.procedureAddress) + L" / " + hexText(entry.procedureOffset);
        result.rows.push_back(makeResultRow({
            { L"对象", hexText(entry.hookObject) },
            { L"类型", keyboardHookTypeText(entry.hookType) },
            { L"范围", keyboardHookScopeText(entry.hookScope) },
            { L"进程ID", std::to_wstring(entry.processId) },
            { L"线程ID", std::to_wstring(entry.threadId) },
            { L"函数/偏移", kProcedureDisplay },
            { L"详情", entry.detail },
            { L"PID", std::to_wstring(entry.processId) },
            { L"TID", std::to_wstring(entry.threadId) },
            { L"Process", kProcessName },
            { L"Hook类型", keyboardHookTypeText(entry.hookType) },
            { L"回调", hexText(entry.procedureAddress) },
            { L"模块", kModuleDisplay },
            { L"来源", keyboardSourceText(entry.source) },
            { L"Type", std::to_wstring(entry.hookType) },
            { L"TypeText", keyboardHookTypeText(entry.hookType) },
            { L"Scope", std::to_wstring(entry.hookScope) },
            { L"ScopeText", keyboardHookScopeText(entry.hookScope) },
            { L"Object", hexText(entry.hookObject) },
            { L"ChainHead", hexText(entry.chainHead) },
            { L"Next", hexText(entry.nextHookObject) },
            { L"ThreadInfo", hexText(entry.threadInfo) },
            { L"TargetThreadInfo", hexText(entry.targetThreadInfo) },
            { L"DesktopInfo", hexText(entry.desktopInfo) },
            { L"Procedure", hexText(entry.procedureAddress) },
            { L"ProcedureOffset", hexText(entry.procedureOffset) },
            { L"ModuleBase", hexText(entry.moduleBase) },
            { L"ModuleId", std::to_wstring(entry.moduleId) },
            { L"Source", hexText(entry.source) },
            { L"SourceText", keyboardSourceText(entry.source) },
            { L"Status", std::wstring(keyboardEnumStatusText(entry.status)) + L" (" + std::to_wstring(entry.status) + L")" },
            { L"Flags", hexText(entry.flags) },
            { L"LastStatus", hexText(static_cast<std::uint32_t>(entry.lastStatus)) },
        }, entry.detail));
    }
    return result;
}

KernelOperationResult queryDynDataCapabilities(const KernelRequest& request) {
    const ksword::ark::DriverClient kClient;
    const ksword::ark::DynDataCapabilitiesResult kQuery = kClient.queryDynDataCapabilities();
    KernelOperationResult result;
    applyIoSummary(request, L"DynData Capabilities", kQuery.io, result);
    result.rows.push_back(makeResultRow({
        { L"Capability", hexText(kQuery.capabilityMask) },
        { L"状态", hexText(kQuery.statusFlags) },
        { L"字段", L"DynData capability mask" },
        { L"原因", utf8ToWide(kQuery.io.message) },
        { L"StatusFlags", hexText(kQuery.statusFlags) },
        { L"CapabilityMask", hexText(kQuery.capabilityMask) },
    }, utf8ToWide(kQuery.io.message)));
    return result;
}

// queryPdbProfileStatus summarizes DynData v3/v4 profile state through existing
// ArkDriverClient transport. Input is the current UI request; processing reads
// legacy status, fields, v4 module status, v4 capability groups, and missing
// items; output is read-only rows used by the PDB Profile status page.
KernelOperationResult queryPdbProfileStatus(const KernelRequest& request) {
    const ksword::ark::DriverClient kClient;
    const ksword::ark::DynDataStatusResult kStatus = kClient.queryDynDataStatus();
    const ksword::ark::DynDataFieldsResult kFields = kClient.queryDynDataFields();
    const ksword::ark::DynDataCapabilitiesResult kCaps = kClient.queryDynDataCapabilities();
    const ksword::ark::DynDataV4ModulesResult kV4Modules = kClient.queryDynDataV4Modules();
    const ksword::ark::DynDataV4CapabilityGroupsResult kV4Groups = kClient.queryDynDataV4CapabilityGroups();
    const ksword::ark::DynDataV4MissingItemsResult kV4Missing = kClient.queryDynDataV4MissingItems();
    const ksword::ark::DynDataV4ItemsResult kV4Items = kClient.queryDynDataV4Items();
    const DynDataProfileMatch kProfileMatch = findMatchingDynDataProfile(kStatus.ntoskrnl);

    KernelOperationResult result;
    applyIoSummary(request, L"PDB Profile/DynData Status", kStatus.io, result);
    result.success = kStatus.io.ok && kFields.io.ok && kCaps.io.ok;

    result.rows.push_back(makeResultRow({
        { L"模块", L"ntoskrnl" },
        { L"Module", kStatus.ntoskrnl.moduleName },
        { L"Class", std::to_wstring(kStatus.ntoskrnl.classId) },
        { L"Profile", utf8ToWide(kProfileMatch.profile.profileName) },
        { L"状态", trustedOffsetText(kStatus.statusFlags, kProfileMatch, summarizeDynDataFields(kFields)) },
        { L"Status", hexText(kStatus.statusFlags) },
        { L"Capability", hexText(kStatus.capabilityMask) },
        { L"CapabilityMask", hexText(kCaps.capabilityMask) },
        { L"缺失", kFields.io.ok ? fieldCoverageText(summarizeDynDataFields(kFields), kProfileMatch.coveragePercent) : L"字段查询失败" },
        { L"Identity", moduleIdentityText(kStatus.ntoskrnl) },
        { L"PdbProfileName", utf8ToWide(kProfileMatch.profile.profileName) },
        { L"PdbProfilePath", kProfileMatch.path },
        { L"Reason", kProfileMatch.message },
    }, kProfileMatch.message));

    result.rows.push_back(makeResultRow({
        { L"模块", L"legacy-v3" },
        { L"Class", std::to_wstring(kStatus.matchedProfileClass) },
        { L"Profile", utf8ToWide(kProfileMatch.profile.profileName) },
        { L"状态", kProfileMatch.matched ? L"Local pack matched" : L"Local pack not matched" },
        { L"Capability", hexText(kStatus.capabilityMask) },
        { L"缺失", L"RequiredMissing=" + std::to_wstring(summarizeDynDataFields(kFields).requiredMissing) },
        { L"Identity", moduleIdentityText(kStatus.ntoskrnl) },
        { L"Detail", L"v3 兼容路径保持不破坏；应用 profile 仍需显式动作，不在刷新时修改 R0 状态。" },
    }));

    result.rows.push_back(makeResultRow({
        { L"模块", L"v4-modules" },
        { L"Class", L"multi-module" },
        { L"Profile", L"profile-v4" },
        { L"状态", kV4Modules.io.ok ? L"OK" : L"Unavailable" },
        { L"Capability", L"module status" },
        { L"缺失", kV4Modules.io.ok ? L"" : utf8ToWide(kV4Modules.io.message) },
        { L"Identity", L"ArkDriverClient::queryDynDataV4Modules" },
        { L"Detail", utf8ToWide(kV4Modules.io.message) },
    }, utf8ToWide(kV4Modules.io.message)));
    result.rows.push_back(makeResultRow({
        { L"模块", L"v4-items" },
        { L"Class", L"accepted-items" },
        { L"Profile", L"profile-v4" },
        { L"状态", kV4Items.io.ok ? L"OK" : (kV4Items.unsupported ? L"Unsupported" : L"Unavailable") },
        { L"Capability", L"item status" },
        { L"缺失", kV4Items.io.ok ? L"" : utf8ToWide(kV4Items.io.message) },
        { L"Identity", L"ArkDriverClient::queryDynDataV4Items" },
        { L"Detail", L"returned=" + std::to_wstring(kV4Items.returnedCount) +
            L"/" + std::to_wstring(kV4Items.totalCount) +
            L"; " + utf8ToWide(kV4Items.io.message) },
    }, utf8ToWide(kV4Items.io.message)));
    if (kV4Modules.io.ok) {
        for (const KSW_DYN_V4_MODULE_STATUS_ENTRY& entry : kV4Modules.entries) {
            const std::wstring kModuleName = fixedWideText(entry.module.image.moduleName, KSW_DYN_MODULE_NAME_CHARS);
            const std::wstring kProfileName = fixedAnsiText(entry.module.profileName, KSW_DYN_V4_PROFILE_NAME_CHARS);
            const std::wstring kPdbName = fixedAnsiText(entry.module.pdb.pdbName, KSW_DYN_PDB_NAME_CHARS);
            const std::wstring kPdbGuid = fixedAnsiText(entry.module.pdb.pdbGuid, KSW_DYN_PDB_GUID_CHARS);
            std::wostringstream identity;
            identity << kModuleName
                     << L" machine=" << hexText(entry.module.image.machine)
                     << L" timestamp=" << hexText(entry.module.image.timeDateStamp)
                     << L" size=" << hexText(entry.module.image.sizeOfImage)
                     << L" pdb=" << kPdbName << L"/" << kPdbGuid
                     << L"/age=" << entry.module.pdb.pdbAge;
            result.rows.push_back(makeResultRow({
                { L"模块", kModuleName.empty() ? L"<unnamed>" : kModuleName },
                { L"Module", kModuleName },
                { L"ModuleName", kModuleName },
                { L"Class", std::to_wstring(entry.module.image.classId) },
                { L"ModuleClassId", std::to_wstring(entry.module.image.classId) },
                { L"Profile", kProfileName },
                { L"ProfileName", kProfileName },
                { L"状态", dynV4StatusText(entry.statusFlags) },
                { L"Status", hexText(entry.statusFlags) },
                { L"StatusFlags", hexText(entry.statusFlags) },
                { L"Capability", std::to_wstring(entry.activeCapabilityGroupCount) + L"/" + std::to_wstring(entry.capabilityGroupCount) },
                { L"缺失", L"required=" + std::to_wstring(entry.missingRequiredItemCount) + L", optional=" + std::to_wstring(entry.missingOptionalItemCount) },
                { L"MissingSummary", L"required=" + std::to_wstring(entry.missingRequiredItemCount) + L", optional=" + std::to_wstring(entry.missingOptionalItemCount) },
                { L"Identity", identity.str() },
                { L"Detail", L"v4 module profile status row" },
            }, identity.str()));
        }
    }

    if (kV4Items.io.ok) {
        for (const KSW_DYN_V4_ITEM_STATUS_ENTRY& entry : kV4Items.entries) {
            const KSW_DYN_V4_ITEM_PACKET& item = entry.item;
            const std::wstring kKindText = dynV4ItemKindText(item.itemKind);
            const std::wstring kFlagsText = dynV4ItemFlagsText(item.flags);
            result.rows.push_back(makeResultRow({
                { L"模块", L"v4-item" },
                { L"ModuleClassId", std::to_wstring(entry.moduleClassId) },
                { L"Class", std::to_wstring(entry.moduleClassId) },
                { L"Profile", L"ItemId=" + std::to_wstring(item.itemId) },
                { L"状态", kFlagsText },
                { L"Status", kFlagsText },
                { L"Capability", L"group=" + std::to_wstring(item.capabilityGroupId) },
                { L"Group", std::to_wstring(item.capabilityGroupId) },
                { L"缺失", kKindText },
                { L"Identity", L"itemIndex=" + std::to_wstring(entry.itemIndex) },
                { L"ItemIndex", std::to_wstring(entry.itemIndex) },
                { L"ItemId", std::to_wstring(item.itemId) },
                { L"ItemKind", kKindText },
                { L"Flags", hexText(item.flags) },
                { L"Value", dynV4ItemValueText(item) },
                { L"Detail", dynV4ItemValueText(item) },
            }, dynV4ItemValueText(item)));
        }
    }

    if (kV4Groups.io.ok) {
        for (const KSW_DYN_V4_CAPABILITY_GROUP_STATUS_ENTRY& entry : kV4Groups.entries) {
            result.rows.push_back(makeResultRow({
                { L"模块", L"capability-group" },
                { L"Class", std::to_wstring(entry.moduleClassId) },
                { L"Profile", fixedAnsiText(entry.groupName, KSW_DYN_V4_CAPABILITY_NAME_CHARS) },
                { L"状态", dynV4StatusText(entry.statusFlags) },
                { L"Capability", L"group=" + std::to_wstring(entry.groupId) },
                { L"Group", std::to_wstring(entry.groupId) },
                { L"缺失", L"required " + std::to_wstring(entry.presentRequiredItemCount) + L"/" + std::to_wstring(entry.requiredItemCount) +
                    L", optional " + std::to_wstring(entry.presentOptionalItemCount) + L"/" + std::to_wstring(entry.optionalItemCount) },
                { L"Identity", L"ModuleClassId=" + std::to_wstring(entry.moduleClassId) },
                { L"Detail", L"v4 capability group status row" },
            }));
        }
    }

    if (kV4Missing.io.ok) {
        for (const KSW_DYN_V4_MISSING_ITEM_ENTRY& entry : kV4Missing.entries) {
            const std::wstring kItemName = fixedAnsiText(entry.itemName, KSW_DYN_V4_ITEM_NAME_CHARS);
            const std::wstring kReason = fixedAnsiText(entry.reason, KSW_DYN_V4_MISSING_REASON_CHARS);
            result.rows.push_back(makeResultRow({
                { L"模块", L"missing-item" },
                { L"Class", std::to_wstring(entry.moduleClassId) },
                { L"Profile", kItemName },
                { L"状态", dynV4MissingKindText(entry.missingKind) },
                { L"Capability", L"group=" + std::to_wstring(entry.capabilityGroupId) },
                { L"缺失", std::wstring(dynV4ItemKindText(entry.itemKind)) + L" " + kItemName },
                { L"Identity", L"ItemId=" + std::to_wstring(entry.itemId) },
                { L"Reason", kReason },
                { L"Detail", kReason },
            }, kReason));
        }
    }
    return result;
}

// queryCidTableSummary uses the ArkDriverClient high-level CID wrapper. Input
// may contain a PID/CID filter; processing never requests mutation and leaves
// protocol parsing inside ArkDriverClient; output preserves the existing Light
// table columns for source/dangling/type-mismatch evidence.
KernelOperationResult queryCidTableSummary(const KernelRequest& request) {
    const ksword::ark::DriverClient kClient;
    const std::uint32_t kCidFilter = parseFirstPidFromText(request.filterText);
    const ksword::ark::CidTableAuditResult kQuery = kClient.enumCidTable(
        KSWORD_ARK_CID_ENUM_FLAG_INCLUDE_ALL,
        256,
        8192,
        kCidFilter,
        kCidFilter);

    KernelOperationResult result;
    applyIoSummary(request, L"CID Table Summary", kQuery.io, result);
    if (!kQuery.io.ok) {
        return result;
    }

    result.rows.push_back(makeResultRow({
        { L"CID", kCidFilter == 0 ? L"<all>" : std::to_wstring(kCidFilter) },
        { L"对象", hexText(kQuery.pspCidTableAddress) },
        { L"类型", L"PspCidTable" },
        { L"状态", cidEnumStatusText(kQuery.status) },
        { L"Flags", hexText(kQuery.flags) },
        { L"引用", L"visited=" + std::to_wstring(kQuery.visitedCount) + L"/" + std::to_wstring(kQuery.maxVisitCount) },
        { L"Detail", L"total=" + std::to_wstring(kQuery.totalCount) + L", returned=" + std::to_wstring(kQuery.returnedCount) },
        { L"CapabilityMask", hexText(kQuery.dynDataCapabilityMask) },
        { L"HT.TableCode", hexText(kQuery.htTableCodeOffset) },
        { L"HTE.LowValue", hexText(kQuery.hteLowValueOffset) },
        { L"LastStatus", hexText(static_cast<std::uint32_t>(kQuery.lastStatus)) },
    }));

    for (const KSWORD_ARK_CID_TABLE_ENTRY& entry : kQuery.entries) {
        result.rows.push_back(makeResultRow({
            { L"CID", std::to_wstring(entry.cidValue) },
            { L"Cid", std::to_wstring(entry.cidValue) },
            { L"对象", hexText(entry.objectAddress) },
            { L"Object", hexText(entry.objectAddress) },
            { L"ObjectAddress", hexText(entry.objectAddress) },
            { L"类型", cidObjectKindText(entry.expectedObjectKind) },
            { L"Kind", cidObjectKindText(entry.expectedObjectKind) },
            { L"状态", hexText(static_cast<std::uint32_t>(entry.lookupStatus)) },
            { L"Status", hexText(static_cast<std::uint32_t>(entry.lookupStatus)) },
            { L"LookupStatus", hexText(static_cast<std::uint32_t>(entry.lookupStatus)) },
            { L"Flags", hexText(entry.flags) },
            { L"FlagText", cidEntryFlagsText(entry.flags) },
            { L"引用", hexText(static_cast<std::uint32_t>(entry.referenceStatus)) },
            { L"ReferenceStatus", hexText(static_cast<std::uint32_t>(entry.referenceStatus)) },
            { L"HandleIndex", std::to_wstring(entry.handleIndex) },
            { L"Detail", cidEntryFlagsText(entry.flags) },
        }));
    }

    const std::size_t kObjectSummaryLimit = kCidFilter == 0U ? 16U : 64U;
    const std::size_t kObjectSummaryCount = std::min(kQuery.entries.size(), kObjectSummaryLimit);
    for (std::size_t index = 0U; index < kObjectSummaryCount; ++index) {
        const KSWORD_ARK_CID_TABLE_ENTRY& entry = kQuery.entries[index];
        if (entry.cidValue == 0U && entry.objectAddress == 0ULL) {
            continue;
        }
        const ksword::ark::KernelObjectSummaryAuditResult kSummary =
            kClient.queryKernelObjectSummary(entry.expectedObjectKind, entry.cidValue, entry.objectAddress);
        const KSWORD_ARK_QUERY_KERNEL_OBJECT_SUMMARY_RESPONSE& response = kSummary.response;
        const std::wstring kTransportStatus = kSummary.io.ok
            ? objectSummaryStatusText(response.status)
            : (kSummary.unsupported ? L"Unsupported" : L"Unavailable");
        const std::wstring kTypeName = fixedWideText(response.typeName, KSWORD_ARK_KERNEL_OBJECT_TYPE_NAME_CHARS);
        const std::wstring kDetailText = fixedWideText(response.detail, KSWORD_ARK_KERNEL_OBJECT_DETAIL_CHARS);
        result.rows.push_back(makeResultRow({
            { L"CID", std::to_wstring(entry.cidValue) },
            { L"Cid", std::to_wstring(entry.cidValue) },
            { L"对象", hexText(response.objectAddress != 0ULL ? response.objectAddress : entry.objectAddress) },
            { L"Object", hexText(response.objectAddress != 0ULL ? response.objectAddress : entry.objectAddress) },
            { L"ObjectAddress", hexText(response.objectAddress != 0ULL ? response.objectAddress : entry.objectAddress) },
            { L"类型", kTypeName.empty() ? cidObjectKindText(entry.expectedObjectKind) : kTypeName },
            { L"Kind", cidObjectKindText(response.targetKind != KSWORD_ARK_CID_OBJECT_KIND_UNKNOWN ? response.targetKind : entry.expectedObjectKind) },
            { L"状态", kTransportStatus },
            { L"Status", kTransportStatus },
            { L"LookupStatus", ntStatusText(response.lookupStatus) },
            { L"TypeStatus", ntStatusText(response.typeStatus) },
            { L"CounterStatus", ntStatusText(response.counterStatus) },
            { L"ObjectHeaderStatus", objectHeaderStatusText(response.objectHeaderStatus) },
            { L"Flags", hexText(response.fieldFlags) },
            { L"FieldFlags", hexText(response.fieldFlags) },
            { L"引用", L"ptr=" + std::to_wstring(response.pointerCount) + L", handle=" + std::to_wstring(response.handleCount) },
            { L"ReferenceStatus", L"ptr=" + std::to_wstring(response.pointerCount) + L", handle=" + std::to_wstring(response.handleCount) },
            { L"HandleIndex", std::to_wstring(entry.handleIndex) },
            { L"TypeIndex", std::to_wstring(response.typeIndex) },
            { L"ObjectType", hexText(response.objectTypeAddress) },
            { L"DynDataCapabilityMask", hexText(response.dynDataCapabilityMask) },
            { L"OT.NameOffset", hexText(response.otNameOffset) },
            { L"OT.IndexOffset", hexText(response.otIndexOffset) },
            { L"Source", L"ArkDriverClient::queryKernelObjectSummary" },
            { L"Detail", kDetailText.empty() ? utf8ToWide(kSummary.io.message) : kDetailText },
        }, kDetailText.empty() ? utf8ToWide(kSummary.io.message) : kDetailText));
    }
    if (kQuery.entries.size() > kObjectSummaryCount) {
        result.rows.push_back(makeResultRow({
            { L"CID", L"<summary-limit>" },
            { L"对象", hexText(kQuery.pspCidTableAddress) },
            { L"类型", L"KernelObjectSummary" },
            { L"状态", L"Truncated" },
            { L"引用", std::to_wstring(kObjectSummaryCount) + L"/" + std::to_wstring(kQuery.entries.size()) },
            { L"Detail", L"未带筛选时仅查询前 16 条对象摘要；输入 PID/CID 筛选可扩大到 64 条，避免刷新页时过量 IOCTL。" },
        }));
    }
    return result;
}

// queryIpcSummary reads the R0 IPC summary protocol and augments it with the
// KernelLight local NamedPipe/communication-endpoint entry points. Input is one
// UI request; processing remains read-only and does not enumerate or mutate pipe
// contents; output distinguishes ALPC, NamedPipe, Mailslot and SMB fallback.
KernelOperationResult queryIpcSummary(const KernelRequest& request) {
    const ksword::ark::DriverClient kClient;
    const std::uint32_t kPidFilter = parseFirstPidFromText(request.filterText);
    const ksword::ark::IpcSummaryAuditResult kQuery = kClient.queryIpcSummary(
        kPidFilter,
        0,
        KSWORD_ARK_IPC_QUERY_FLAG_INCLUDE_ALL,
        128);
    const KSWORD_ARK_QUERY_IPC_SUMMARY_RESPONSE& response = kQuery.response;

    KernelOperationResult result;
    applyIoSummary(request, L"IPC Summary", kQuery.io, result);
    result.rows.push_back(makeResultRow({
        { L"类别", L"ALPC" },
        { L"Class", L"ALPC" },
        { L"状态", kQuery.io.ok ? ipcSummaryStatusText(response.alpcStatus) : L"Unavailable" },
        { L"Status", kQuery.io.ok ? ipcSummaryStatusText(response.alpcStatus) : L"Unavailable" },
        { L"进程", kPidFilter == 0 ? L"<all/current capability>" : std::to_wstring(kPidFilter) },
        { L"PID", std::to_wstring(response.processId) },
        { L"Handle/Object", hexText(response.alpcObjectAddress) },
        { L"Object", hexText(response.alpcObjectAddress) },
        { L"Capability", hexText(response.dynDataCapabilityMask) },
        { L"CapabilityMask", hexText(response.dynDataCapabilityMask) },
        { L"来源", L"ArkDriverClient::queryIpcSummary" },
        { L"Source", L"R0 IPC summary" },
        { L"Detail", fixedWideText(response.detail, KSWORD_ARK_KERNEL_OBJECT_DETAIL_CHARS) },
        { L"TypeName", fixedWideText(response.alpcTypeName, KSWORD_ARK_KERNEL_OBJECT_TYPE_NAME_CHARS) },
        { L"LastStatus", hexText(static_cast<std::uint32_t>(response.lastStatus)) },
    }, fixedWideText(response.detail, KSWORD_ARK_KERNEL_OBJECT_DETAIL_CHARS)));
    result.rows.push_back(makeResultRow({
        { L"类别", L"NamedPipe" },
        { L"状态", kQuery.io.ok ? ipcSummaryStatusText(response.namedPipeStatus) : L"Use NamedPipe tab" },
        { L"进程", L"<namespace>" },
        { L"Handle/Object", L"\\Device\\NamedPipe" },
        { L"Capability", L"R3 Native + R0 summary" },
        { L"来源", L"命名管道页" },
        { L"Detail", L"切换到 IPC/命名管道子页可执行只读 NT object namespace 枚举。" },
    }));
    result.rows.push_back(makeResultRow({
        { L"类别", L"Mailslot" },
        { L"状态", kQuery.io.ok ? ipcSummaryStatusText(response.mailslotStatus) : L"Unavailable" },
        { L"进程", L"<namespace>" },
        { L"Handle/Object", L"\\Device\\Mailslot" },
        { L"Capability", hexText(response.dynDataCapabilityMask) },
        { L"来源", L"R0 IPC summary" },
        { L"Detail", L"当前只读摘要；缺字段时显示 partial/unavailable，不猜测对象布局。" },
    }));
    result.rows.push_back(makeResultRow({
        { L"类别", L"SMB" },
        { L"状态", L"Fallback" },
        { L"进程", L"<system/network>" },
        { L"Handle/Object", L"Lanman/Redirector" },
        { L"Capability", L"network stack audit pending" },
        { L"来源", L"docs/pdb_r0_audit_prep/04_network_stack_audit.md" },
        { L"Detail", L"SMB 仅作为 IPC 风险入口提示；本轮不修改 Network 模块，也不新增网络 IOCTL 调用。" },
    }));
    return result;
}

// queryHookAuditSummary aggregates existing read-only hook/callback audit entry
// points. Input is the UI request; processing queries lightweight capability and
// selected existing collectors; output is a compact routing/status table rather
// than a destructive repair panel.
KernelOperationResult queryHookAuditSummary(const KernelRequest& request) {
    KernelOperationResult result;
    result.supported = true;
    result.success = true;
    result.message = L"Hook/callback 只读审计入口汇总完成。";

    const KernelRequest kCallbackRequest{ KernelFeatureId::kCallbackEnumeration, request.filterText, request.moduleFilterText, request.flags, request.startAddress, request.endAddress, 128, request.idtVectorLimit };
    const KernelRequest kInlineRequest{ KernelFeatureId::kInlineHook, request.filterText, request.moduleFilterText, request.flags | kKernelRequestFlagRiskOnly, request.startAddress, request.endAddress, 128, request.idtVectorLimit };
    const KernelRequest kIatEatRequest{ KernelFeatureId::kIatEatHook, request.filterText, request.moduleFilterText, request.flags | kKernelRequestFlagRiskOnly, request.startAddress, request.endAddress, 128, request.idtVectorLimit };
    const KernelRequest kSsdtRequest{ KernelFeatureId::kSsdt, request.filterText, request.moduleFilterText, request.flags, request.startAddress, request.endAddress, 128, request.idtVectorLimit };
    const KernelOperationResult kCallbacks = queryCallbackEnumeration(kCallbackRequest);
    const KernelOperationResult kInlineHooks = queryInlineHooks(kInlineRequest);
    const KernelOperationResult kIatEatHooks = queryIatEatHooks(kIatEatRequest);
    const KernelOperationResult kSsdt = querySsdt(kSsdtRequest, false);

    const auto kAppendSummary = [&](const wchar_t* cls, const wchar_t* entry, const KernelOperationResult& source, const wchar_t* capability) {
        result.success = result.success && source.success;
        result.rows.push_back(makeResultRow({
            { L"类别", cls },
            { L"Class", cls },
            { L"入口", entry },
            { L"Entry", entry },
            { L"状态", source.success ? L"OK" : (source.supported ? L"Partial/Failed" : L"Unsupported") },
            { L"Status", source.message },
            { L"Capability", capability },
            { L"Rows", std::to_wstring(source.rows.size()) },
            { L"风险/降级", source.success ? L"只读审计可用" : source.message },
            { L"Detail", source.message },
        }, source.message));
    };

    kAppendSummary(L"Callback", L"回调遍历", kCallbacks, L"KSW_CAP_CALLBACK_*");
    kAppendSummary(L"InlineHook", L"Inline Hook", kInlineHooks, L"kernel hook scan");
    kAppendSummary(L"IAT/EAT", L"IAT/EAT", kIatEatHooks, L"import/export scan");
    kAppendSummary(L"SSDT", L"SSDT", kSsdt, L"service table scan");
    result.rows.push_back(makeResultRow({
        { L"类别", L"ShadowSSDT" },
        { L"入口", L"ShadowSSDT 子页" },
        { L"状态", L"Available on dedicated tab" },
        { L"Capability", L"win32k/profile gated" },
        { L"Rows", L"-" },
        { L"风险/降级", L"请切换 Hook审计/ShadowSSDT 或原 SSSDT 解析页查看完整行。" },
        { L"Detail", L"摘要页避免一次刷新触发过多 win32k/ShadowSSDT 查询；专页仍保持只读审计。" },
    }));
    return result;
}

KernelOperationResult queryMinifilterBypassPids(const KernelRequest& request) {
    const ksword::ark::DriverClient kClient;
    const ksword::ark::MinifilterBypassPidResult kQuery = kClient.queryMinifilterBypassPids();
    KernelOperationResult result;
    applyIoSummary(request, L"Minifilter Bypass PIDs", kQuery.io, result);
    result.rows.push_back(makeResultRow({
        { L"Version", std::to_wstring(kQuery.response.version) },
        { L"PidCount", std::to_wstring(kQuery.response.pidCount) },
        { L"Flags", hexText(kQuery.response.flags) },
    }));
    const std::uint32_t kCount = std::min<std::uint32_t>(kQuery.response.pidCount, KSWORD_ARK_MINIFILTER_BYPASS_PID_MAX_COUNT);
    for (std::uint32_t index = 0; index < kCount; ++index) {
        const std::uint32_t kPid = kQuery.response.processIds[index];
        result.rows.push_back(makeResultRow({
            { L"Index", std::to_wstring(index) },
            { L"PID", std::to_wstring(kPid) },
            { L"Process", processDisplayName(kPid) },
            { L"状态", L"放行" },
            { L"来源", L"R0 minifilter bypass whitelist" },
        }));
    }
    return result;
}

// executeInlineHookNopPatch sends the selected Inline Hook row through
// ArkDriverClient::patchInlineHook. Inputs are row fields from the ListView and
// the force flag controlled by UI confirmation; output includes R0 before/after
// bytes and transport diagnostics.
KernelOperationResult executeInlineHookNopPatch(const KernelActionRequest& request) {
    std::uint64_t functionAddress = 0;
    std::uint32_t hookType = 0;
    if (!parseUnsigned64(fieldValue(request, L"Address"), functionAddress) ||
        !parseUnsigned32(fieldValue(request, L"Type"), hookType) ||
        functionAddress == 0) {
        return makeActionError(request, L"当前行缺少 Inline Hook Address/Type 字段。请先刷新 Inline Hook 页并选择一条真实 Hook 行。");
    }

    std::uint32_t currentByteCount = 0;
    parseUnsigned32(fieldValue(request, L"CurrentByteCount"), currentByteCount);
    const std::uint32_t kAvailableBytes = currentByteCount != 0 ? currentByteCount : KSWORD_ARK_KERNEL_HOOK_BYTES;
    const std::uint32_t kPatchBytes = inlinePatchLength(hookType, kAvailableBytes);
    if (kPatchBytes == 0) {
        return makeActionError(request, L"当前 Hook 类型不适合自动 NOP 摘除。");
    }

    const ksword::ark::DriverClient kClient;
    const unsigned long kFlags = request.force ? KSWORD_ARK_KERNEL_PATCH_FLAG_FORCE : 0UL;
    const std::vector<std::uint8_t> kCurrentBytes = parseHexByteList(fieldValue(request, L"CurrentBytes"));
    const ksword::ark::KernelInlinePatchResult kPatch = kClient.patchInlineHook(
        functionAddress,
        KSWORD_ARK_INLINE_PATCH_MODE_NOP_BRANCH,
        kPatchBytes,
        kCurrentBytes,
        {},
        kFlags);

    KernelOperationResult result;
    result.supported = true;
    result.success = kPatch.io.ok && kPatch.status == KSWORD_ARK_KERNEL_HOOK_STATUS_PATCHED;
    result.destructiveAction = true;
    result.message = std::wstring(L"Inline Hook NOP 摘除")
        + (request.force ? L"（强制）" : L"")
        + (result.success ? L"完成。" : L"未完成。")
        + L" "
        + utf8ToWide(kPatch.io.message);
    result.rows.push_back(makeResultRow({
        { L"Action", L"InlineHookNopPatch" },
        { L"Forced", boolText(request.force) },
        { L"IO", kPatch.io.ok ? L"OK" : L"FAIL" },
        { L"Win32", std::to_wstring(kPatch.io.win32Error) },
        { L"BytesReturned", std::to_wstring(kPatch.io.bytesReturned) },
        { L"Version", std::to_wstring(kPatch.version) },
        { L"Status", std::to_wstring(kPatch.status) },
        { L"BytesPatched", std::to_wstring(kPatch.bytesPatched) },
        { L"FieldFlags", hexText(kPatch.fieldFlags) },
        { L"LastStatus", hexText(static_cast<std::uint32_t>(kPatch.lastStatus)) },
        { L"Address", hexText(kPatch.functionAddress != 0 ? kPatch.functionAddress : functionAddress) },
        { L"Before", bytesHex(kPatch.beforeBytes, KSWORD_ARK_KERNEL_HOOK_PATCH_MAX_BYTES) },
        { L"After", bytesHex(kPatch.afterBytes, KSWORD_ARK_KERNEL_HOOK_PATCH_MAX_BYTES) },
    }, utf8ToWide(kPatch.io.message)));
    return result;
}

// executeCallbackSafeRemove removes one enumerated callback using only the public
// API behavior path. Inputs are selected callback row fields; output reports the
// EX response packet and never uses the experimental unlink behavior.
KernelOperationResult executeCallbackSafeRemove(const KernelActionRequest& request) {
    std::uint32_t callbackClass = 0;
    std::uint64_t callbackAddress = 0;
    std::uint64_t registrationAddress = 0;
    std::uint64_t rawStorageValue = 0;
    std::uint64_t generation = 0;
    std::uint64_t identityHash = 0;
    std::uint32_t source = 0;
    std::uint32_t operationMask = 0;
    std::uint32_t objectTypeMask = 0;
    std::uint32_t trustFlags = 0;
    std::uint32_t removeBehavior = 0;
    if (!parseUnsigned32(fieldValue(request, L"Class"), callbackClass) ||
        !parseUnsigned64(fieldValue(request, L"Callback"), callbackAddress) ||
        callbackClass == 0 ||
        callbackAddress == 0) {
        return makeActionError(request, L"当前行缺少 Callback Enumeration 的 Class/Callback 字段。");
    }
    parseUnsigned64(fieldValue(request, L"Registration"), registrationAddress);
    parseUnsigned64(fieldValue(request, L"RawStorageValue"), rawStorageValue);
    parseUnsigned64(fieldValue(request, L"Generation"), generation);
    parseUnsigned64(fieldValue(request, L"IdentityHash"), identityHash);
    parseUnsigned32(fieldValue(request, L"Source"), source);
    parseUnsigned32(fieldValue(request, L"OperationMask"), operationMask);
    parseUnsigned32(fieldValue(request, L"ObjectTypeMask"), objectTypeMask);
    parseUnsigned32(fieldValue(request, L"Trust"), trustFlags);
    parseUnsigned32(fieldValue(request, L"Remove"), removeBehavior);

    KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_REQUEST packet{};
    packet.size = sizeof(packet);
    packet.version = KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_PROTOCOL_VERSION;
    packet.callbackClass = callbackRemoveTypeForClass(callbackClass);
    if (packet.callbackClass == 0) {
        return makeActionError(request, L"当前回调类型没有安全公开 API 移除映射。");
    }
    packet.flags = KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_FLAG_REQUIRE_REVALIDATION;
    packet.callbackAddress = callbackAddress;
    packet.registrationAddress = registrationAddress;
    packet.rawStorageValue = rawStorageValue;
    packet.enumerationGeneration = generation;
    packet.identityHash = identityHash;
    packet.source = source;
    packet.operationMask = operationMask;
    packet.objectTypeMask = objectTypeMask;
    packet.trustFlags = trustFlags;
    packet.removeBehavior = removeBehavior != 0
        ? removeBehavior
        : (KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_PUBLIC_API | KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_REQUIRE_REVALIDATION);

    const ksword::ark::DriverClient kClient;
    const ksword::ark::CallbackRemoveExResult kRemoved = kClient.removeExternalCallbackEx(packet);
    const KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_RESPONSE& response = kRemoved.response;

    KernelOperationResult result;
    result.supported = true;
    result.success = kRemoved.io.ok && response.ntstatus >= 0;
    result.destructiveAction = true;
    result.message = std::wstring(L"Callback 安全移除")
        + (result.success ? L"完成。" : L"未完成。")
        + L" "
        + utf8ToWide(kRemoved.io.message);
    result.rows.push_back(makeResultRow({
        { L"Action", L"CallbackSafeRemove" },
        { L"IO", kRemoved.io.ok ? L"OK" : L"FAIL" },
        { L"Win32", std::to_wstring(kRemoved.io.win32Error) },
        { L"BytesReturned", std::to_wstring(kRemoved.io.bytesReturned) },
        { L"RequestClass", std::to_wstring(packet.callbackClass) },
        { L"RequestCallback", hexText(packet.callbackAddress) },
        { L"RequestRegistration", hexText(packet.registrationAddress) },
        { L"RequestRawStorageValue", hexText(packet.rawStorageValue) },
        { L"RequestGeneration", hexText(packet.enumerationGeneration) },
        { L"RequestIdentityHash", hexText(packet.identityHash) },
        { L"RequestBehavior", hexText(packet.removeBehavior) },
        { L"RequestBehaviorText", callbackEnumRemoveBehaviorText(packet.removeBehavior) },
        { L"ResponseClass", std::to_wstring(response.callbackClass) },
        { L"ResponseClassText", callbackEnumClassText(response.callbackClass) },
        { L"ResponseSource", std::to_wstring(response.source) },
        { L"ResponseSourceText", callbackEnumSourceText(response.source) },
        { L"Callback", hexText(response.callbackAddress) },
        { L"Registration", hexText(response.registrationAddress) },
        { L"RawStorageValue", hexText(response.rawStorageValue) },
        { L"Generation", hexText(response.enumerationGeneration) },
        { L"IdentityHash", hexText(response.identityHash) },
        { L"NTSTATUS", hexText(static_cast<std::uint32_t>(response.ntstatus)) },
        { L"Revalidation", hexText(static_cast<std::uint32_t>(response.revalidationStatus)) },
        { L"ResponseTrust", hexText(response.trustFlags) },
        { L"ResponseTrustText", callbackEnumTrustFlagsText(response.trustFlags) },
        { L"ResponseBehavior", hexText(response.removeBehavior) },
        { L"ResponseBehaviorText", callbackEnumRemoveBehaviorText(response.removeBehavior) },
        { L"Mapping", hexText(response.mappingFlags) },
        { L"MappingText", callbackEnumMappingText(response.mappingFlags) },
        { L"ModuleBase", hexText(response.moduleBase) },
        { L"ModuleSize", hexText(response.moduleSize) },
        { L"ModulePath", response.modulePath },
        { L"Service", response.serviceName },
        { L"Message", response.message },
    }, utf8ToWide(kRemoved.io.message)));
    return result;
}


// executeCallbackExperimentalUnlink sends the original KernelDock experimental
// unlink request through ArkDriverClient::removeExternalCallbackEx. Inputs are
// the selected CallbackEnum row fields; processing sets the protocol's explicit
// EXPERIMENTAL_UNLINK flag and behavior bits; output reports the R0 response.
KernelOperationResult executeCallbackExperimentalUnlink(const KernelActionRequest& request) {
    std::uint32_t callbackClass = 0;
    std::uint64_t callbackAddress = 0;
    std::uint64_t registrationAddress = 0;
    std::uint64_t rawStorageValue = 0;
    std::uint64_t generation = 0;
    std::uint64_t identityHash = 0;
    std::uint32_t source = 0;
    std::uint32_t operationMask = 0;
    std::uint32_t objectTypeMask = 0;
    std::uint32_t trustFlags = 0;
    std::uint32_t removeBehavior = 0;
    if (!parseUnsigned32(fieldValue(request, L"Class"), callbackClass) || callbackClass == 0) {
        return makeActionError(request, L"当前行缺少 Callback Enumeration 的 Class 字段。");
    }
    parseUnsigned64(fieldValue(request, L"Callback"), callbackAddress);
    parseUnsigned64(fieldValue(request, L"Registration"), registrationAddress);
    parseUnsigned64(fieldValue(request, L"RawStorageValue"), rawStorageValue);
    parseUnsigned64(fieldValue(request, L"Generation"), generation);
    parseUnsigned64(fieldValue(request, L"IdentityHash"), identityHash);
    parseUnsigned32(fieldValue(request, L"Source"), source);
    parseUnsigned32(fieldValue(request, L"OperationMask"), operationMask);
    parseUnsigned32(fieldValue(request, L"ObjectTypeMask"), objectTypeMask);
    parseUnsigned32(fieldValue(request, L"Trust"), trustFlags);
    parseUnsigned32(fieldValue(request, L"Remove"), removeBehavior);

    const std::uint64_t kPrimaryRemoveValue = rawStorageValue != 0 ? rawStorageValue :
        (registrationAddress != 0 ? registrationAddress : callbackAddress);
    if (kPrimaryRemoveValue == 0) {
        return makeActionError(request, L"当前行缺少 Callback/Registration/RawStorageValue，无法构造 experimental unlink 请求。");
    }

    KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_REQUEST packet{};
    packet.size = sizeof(packet);
    packet.version = KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_PROTOCOL_VERSION;
    packet.callbackClass = callbackRemoveTypeForClass(callbackClass);
    if (packet.callbackClass == 0) {
        return makeActionError(request, L"当前回调类型没有 removeExternalCallbackEx 映射，不能发送 experimental unlink。");
    }
    packet.flags = KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_FLAG_EXPERIMENTAL_UNLINK |
        KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_FLAG_REQUIRE_REVALIDATION;
    packet.callbackAddress = callbackAddress;
    packet.registrationAddress = registrationAddress;
    packet.rawStorageValue = rawStorageValue;
    packet.enumerationGeneration = generation;
    packet.identityHash = identityHash;
    packet.source = source;
    packet.operationMask = operationMask;
    packet.objectTypeMask = objectTypeMask;
    packet.trustFlags = trustFlags;
    packet.removeBehavior = removeBehavior != 0
        ? (removeBehavior | KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_EXPERIMENTAL_UNLINK | KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_REQUIRE_REVALIDATION)
        : (KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_EXPERIMENTAL_UNLINK | KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_REQUIRE_REVALIDATION);

    const ksword::ark::DriverClient kClient;
    const ksword::ark::CallbackRemoveExResult kRemoved = kClient.removeExternalCallbackEx(packet);
    const KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_RESPONSE& response = kRemoved.response;

    KernelOperationResult result;
    result.supported = true;
    result.success = kRemoved.io.ok && response.ntstatus >= 0;
    result.destructiveAction = true;
    result.message = std::wstring(L"Callback experimental unlink ")
        + (result.success ? L"完成。" : L"未完成或被 R0 拒绝。")
        + L" "
        + utf8ToWide(kRemoved.io.message);
    result.rows.push_back(makeResultRow({
        { L"Action", L"CallbackExperimentalUnlink" },
        { L"IO", kRemoved.io.ok ? L"OK" : L"FAIL" },
        { L"Win32", std::to_wstring(kRemoved.io.win32Error) },
        { L"BytesReturned", std::to_wstring(kRemoved.io.bytesReturned) },
        { L"RequestClass", std::to_wstring(packet.callbackClass) },
        { L"RequestFlags", hexText(packet.flags) },
        { L"RequestCallback", hexText(packet.callbackAddress) },
        { L"RequestRegistration", hexText(packet.registrationAddress) },
        { L"RequestRawStorageValue", hexText(packet.rawStorageValue) },
        { L"RequestGeneration", hexText(packet.enumerationGeneration) },
        { L"RequestIdentityHash", hexText(packet.identityHash) },
        { L"RequestBehavior", hexText(packet.removeBehavior) },
        { L"RequestBehaviorText", callbackEnumRemoveBehaviorText(packet.removeBehavior) },
        { L"ResponseClass", std::to_wstring(response.callbackClass) },
        { L"ResponseClassText", callbackEnumClassText(response.callbackClass) },
        { L"ResponseSource", std::to_wstring(response.source) },
        { L"ResponseSourceText", callbackEnumSourceText(response.source) },
        { L"Callback", hexText(response.callbackAddress) },
        { L"Registration", hexText(response.registrationAddress) },
        { L"RawStorageValue", hexText(response.rawStorageValue) },
        { L"Generation", hexText(response.enumerationGeneration) },
        { L"IdentityHash", hexText(response.identityHash) },
        { L"NTSTATUS", hexText(static_cast<std::uint32_t>(response.ntstatus)) },
        { L"Revalidation", hexText(static_cast<std::uint32_t>(response.revalidationStatus)) },
        { L"ResponseTrust", hexText(response.trustFlags) },
        { L"ResponseTrustText", callbackEnumTrustFlagsText(response.trustFlags) },
        { L"ResponseBehavior", hexText(response.removeBehavior) },
        { L"ResponseBehaviorText", callbackEnumRemoveBehaviorText(response.removeBehavior) },
        { L"Mapping", hexText(response.mappingFlags) },
        { L"MappingText", callbackEnumMappingText(response.mappingFlags) },
        { L"ModuleBase", hexText(response.moduleBase) },
        { L"ModuleSize", hexText(response.moduleSize) },
        { L"ModulePath", response.modulePath },
        { L"Service", response.serviceName },
        { L"Message", response.message },
    }, utf8ToWide(kRemoved.io.message)));
    return result;
}

// executeCallbackRuntimeControl performs page-level callback runtime operations.
// Inputs are action id and current filter text; processing goes only through
// ArkDriverClient callback APIs; output contains the action transport result and
// a fresh runtime snapshot so operators can verify the new state immediately.
KernelOperationResult executeCallbackRuntimeControl(const KernelActionRequest& request) {
    const ksword::ark::DriverClient kClient;
    ksword::ark::IoResult io{};
    const wchar_t* actionName = L"CallbackUnknown";
    std::vector<std::uint8_t> blob;

    if (request.actionId == KernelActionId::kCallbackCancelPendingDecisions) {
        actionName = L"CallbackCancelPendingDecisions";
        io = kClient.cancelAllPendingCallbackDecisions();
    } else if (request.actionId == KernelActionId::kCallbackApplyDisabledEmptyRules) {
        actionName = L"CallbackApplyDisabledEmptyRules";
        const ksword::ark::CallbackRuntimeResult kBefore = kClient.queryCallbackRuntimeState();
        const std::uint64_t kNextRuleVersion = kBefore.io.ok && kBefore.state.appliedRuleVersion != 0
            ? kBefore.state.appliedRuleVersion + 1ULL
            : currentUtc100ns();
        blob = buildDisabledCallbackRuleBlob(kNextRuleVersion);
        io = kClient.setCallbackRules(blob.data(), static_cast<unsigned long>(blob.size()));
    } else if (request.actionId == KernelActionId::kCallbackApplyLocalRules) {
        actionName = L"CallbackApplyLocalRules";
        LocalCallbackRuleDocument document;
        std::wstring parseError;
        if (!parseLocalCallbackRuleDocument(request.moduleFilterText, document, parseError)) {
            return makeActionError(request, L"本地 Callback 规则解析失败：" + parseError);
        }
        const ksword::ark::CallbackRuntimeResult kBefore = kClient.queryCallbackRuntimeState();
        const std::uint64_t kNextRuleVersion = kBefore.io.ok && kBefore.state.appliedRuleVersion != 0
            ? kBefore.state.appliedRuleVersion + 1ULL
            : currentUtc100ns();
        blob = buildCallbackRuleBlob(document, kNextRuleVersion);
        io = kClient.setCallbackRules(blob.data(), static_cast<unsigned long>(blob.size()));
    } else {
        return makeActionError(request, L"未知 CallbackIntercept 动作。");
    }

    KernelOperationResult result;
    result.supported = true;
    result.success = io.ok;
    result.destructiveAction = true;
    result.message = std::wstring(actionName)
        + (io.ok ? L" 完成。" : L" 失败。")
        + L" "
        + utf8ToWide(io.message);
    result.rows.push_back(makeResultRow({
        { L"Action", actionName },
        { L"IO", io.ok ? L"OK" : L"FAIL" },
        { L"Win32", std::to_wstring(io.win32Error) },
        { L"BytesReturned", std::to_wstring(io.bytesReturned) },
        { L"BlobBytes", std::to_wstring(blob.size()) },
        { L"Source", request.actionId == KernelActionId::kCallbackApplyLocalRules ? L"LocalRules" : L"RuntimeControl" },
    }, utf8ToWide(io.message)));

    const ksword::ark::CallbackRuntimeResult kAfter = kClient.queryCallbackRuntimeState();
    result.rows.push_back(makeResultRow({
        { L"Action", L"CallbackRuntimeRefresh" },
        { L"IO", kAfter.io.ok ? L"OK" : L"FAIL" },
        { L"Win32", std::to_wstring(kAfter.io.win32Error) },
        { L"BytesReturned", std::to_wstring(kAfter.io.bytesReturned) },
    }, utf8ToWide(kAfter.io.message)));
    appendCallbackRuntimeRows(result, kAfter.state, request.filterText, L"AfterAction");
    return result;
}

// parseCallbackEventGuid validates the compact hexadecimal GUID sent by the
// Win32 callback receiver. Input accepts only 32 hex digits so a UI row cannot
// inject an arbitrary binary answer packet into the driver call.
bool parseCallbackEventGuid(const std::wstring& text, KSWORD_ARK_GUID128& guidOut) {
    std::wstring compact;
    compact.reserve(32);
    for (const wchar_t kCh : text) {
        if (kCh != L'-' && kCh != L'{' && kCh != L'}') {
            if (!std::iswxdigit(kCh)) {
                return false;
            }
            compact.push_back(kCh);
        }
    }
    if (compact.size() != 32U) {
        return false;
    }
    for (std::size_t index = 0; index < sizeof(guidOut.bytes); ++index) {
        const auto kDigit = [](const wchar_t ch) -> int {
            if (ch >= L'0' && ch <= L'9') return ch - L'0';
            if (ch >= L'a' && ch <= L'f') return 10 + ch - L'a';
            return 10 + ch - L'A';
        };
        guidOut.bytes[index] = static_cast<unsigned char>((kDigit(compact[index * 2U]) << 4U) | kDigit(compact[index * 2U + 1U]));
    }
    return true;
}

// executeCallbackAnswerEvent sends one explicit allow/deny decision received by
// the background wait loop. The caller supplies the event GUID and session only
// after an operator confirmation; this function performs no implicit fallback.
KernelOperationResult executeCallbackAnswerEvent(const KernelActionRequest& request) {
    KSWORD_ARK_CALLBACK_ANSWER_REQUEST answer{};
    if (!parseCallbackEventGuid(fieldValue(request, L"EventGuid"), answer.eventGuid)) {
        return makeActionError(request, L"待决策事件 GUID 无效，已拒绝向驱动发送应答。" );
    }
    std::uint32_t sourceSessionId = 0;
    if (!parseUnsigned32(fieldValue(request, L"SourceSessionId"), sourceSessionId)) {
        return makeActionError(request, L"待决策事件缺少有效 SourceSessionId。" );
    }
    const std::wstring kDecisionText = fieldValue(request, L"Decision");
    const bool kDeny = kDecisionText == L"Deny";
    if (!kDeny && kDecisionText != L"Allow") {
        return makeActionError(request, L"待决策事件的允许/拒绝动作无效。" );
    }
    answer.size = sizeof(answer);
    answer.version = KSWORD_ARK_CALLBACK_PROTOCOL_VERSION;
    answer.decision = kDeny ? KSWORD_ARK_DECISION_DENY : KSWORD_ARK_DECISION_ALLOW;
    answer.sourceSessionId = sourceSessionId;
    answer.answeredAtUtc100ns = currentUtc100ns();

    const ksword::ark::DriverClient kClient;
    const ksword::ark::IoResult kIo = kClient.answerCallbackEvent(answer);
    KernelOperationResult result;
    result.supported = true;
    result.success = kIo.ok;
    result.destructiveAction = true;
    result.message = std::wstring(L"Callback 待决策应答 ") + (kDeny ? L"拒绝" : L"允许") +
        (kIo.ok ? L"完成。" : L"失败。") + L" " + utf8ToWide(kIo.message);
    result.rows.push_back(makeResultRow({
        { L"Action", L"CallbackAnswerEvent" },
        { L"Decision", kDeny ? L"Deny" : L"Allow" },
        { L"EventGuid", fieldValue(request, L"EventGuid") },
        { L"SourceSessionId", std::to_wstring(sourceSessionId) },
        { L"IO", kIo.ok ? L"OK" : L"FAIL" },
        { L"Win32", std::to_wstring(kIo.win32Error) },
        { L"BytesReturned", std::to_wstring(kIo.bytesReturned) },
    }, utf8ToWide(kIo.message)));
    return result;
}

// executeSetMinifilterBypassPids writes the minifilter bypass PID list through
// ArkDriverClient. Inputs are PIDs typed into the generic filter box; output
// includes the new R0 whitelist snapshot when the write succeeds.
KernelOperationResult executeSetMinifilterBypassPids(const KernelActionRequest& request) {
    const std::vector<std::uint32_t> kPids = request.actionId == KernelActionId::kMinifilterClearBypassPids
        ? std::vector<std::uint32_t>{}
        : parsePidList(request.filterText);
    if (request.actionId == KernelActionId::kMinifilterSetBypassPids && kPids.empty()) {
        return makeActionError(request, L"请在“过滤/起点”输入 PID 列表，例如：1234,5678。");
    }

    const ksword::ark::DriverClient kClient;
    const ksword::ark::IoResult kIo = kClient.setMinifilterBypassPids(kPids);
    KernelOperationResult result;
    result.supported = true;
    result.success = kIo.ok;
    result.destructiveAction = true;
    result.message = std::wstring(L"Minifilter bypass PID 列表写入")
        + (kIo.ok ? L"完成。" : L"失败。")
        + L" "
        + utf8ToWide(kIo.message);
    result.rows.push_back(makeResultRow({
        { L"Action", request.actionId == KernelActionId::kMinifilterClearBypassPids ? L"MinifilterClearBypassPids" : L"MinifilterSetBypassPids" },
        { L"IO", kIo.ok ? L"OK" : L"FAIL" },
        { L"Win32", std::to_wstring(kIo.win32Error) },
        { L"BytesReturned", std::to_wstring(kIo.bytesReturned) },
        { L"PidCount", std::to_wstring(kPids.size()) },
    }, utf8ToWide(kIo.message)));
    for (std::size_t index = 0; index < kPids.size(); ++index) {
        result.rows.push_back(makeResultRow({
            { L"Index", std::to_wstring(index) },
            { L"PID", std::to_wstring(kPids[index]) },
        }));
    }
    return result;
}

// executeFileMonitorControl mirrors the original CallbackIntercept file-monitor
// buttons. Inputs are the selected action; processing goes through
// ArkDriverClient and emits table rows for the Win32 panel; output is rendered
// by the normal result pipeline.
// actionRowField reads one field out of the selected row snapshot. Inputs are the
// request and the candidate column names; output is empty when the row does not
// carry any of them.
std::wstring actionRowField(const KernelActionRequest& request, const std::vector<std::wstring>& names) {
    for (const std::wstring& name : names) {
        for (const auto& field : request.rowFields) {
            if (field.first == name) {
                return field.second;
            }
        }
    }
    return {};
}

// parseHexOrDecimal accepts both the "0x..." form the tables print and a plain
// decimal, because a user retyping a value by hand rarely reproduces the prefix.
std::uint64_t parseHexOrDecimal(const std::wstring& text) {
    std::size_t begin = 0;
    while (begin < text.size() && std::iswspace(text[begin]) != 0) {
        ++begin;
    }
    std::size_t end = text.size();
    while (end > begin && std::iswspace(text[end - 1]) != 0) {
        --end;
    }
    const std::wstring kTrimmed = text.substr(begin, end - begin);
    if (kTrimmed.empty()) {
        return 0;
    }
    try {
        if (kTrimmed.size() > 2 && kTrimmed[0] == L'0' && (kTrimmed[1] == L'x' || kTrimmed[1] == L'X')) {
            return std::stoull(kTrimmed.substr(2), nullptr, 16);
        }
        return std::stoull(kTrimmed, nullptr, 10);
    } catch (const std::exception&) {
        return 0;
    }
}

// executeNetworkCaptureControl starts or stops the R0 per-packet capture ring.
// Starting it makes the driver copy packet headers into a fixed non-paged ring;
// that ring is bounded, so leaving capture on does not grow without limit, but it
// does keep the WFP callout doing work for every packet.
KernelOperationResult executeNetworkCaptureControl(const KernelActionRequest& request) {
    const ksword::ark::DriverClient kClient;
    const bool kEnable = request.actionId == KernelActionId::kNetworkCaptureStart;
    KernelOperationResult result;
    result.supported = true;
    // Stopping is not destructive: the ring keeps whatever it already holds and
    // stays readable, only new packets stop arriving.
    result.destructiveAction = false;

    const ksword::ark::NetworkTrafficCaptureControlResult kControl = kClient.controlNetworkTrafficCapture(kEnable);
    result.success = kControl.io.ok && !kControl.unsupported;
    if (kControl.unsupported) {
        result.message = L"当前 KswordARK 驱动未注册逐包捕获控制 IOCTL，无法" +
            std::wstring(kEnable ? L"启动" : L"停止") + L"。请勿据此认为 R0 已停止采集。";
    } else {
        result.message = std::wstring(kEnable ? L"逐包捕获启动" : L"逐包捕获停止") +
            (kControl.io.ok ? L"完成。" : L"失败。") + L" " + utf8ToWide(kControl.io.message);
    }
    result.rows.push_back(makeResultRow({
        { L"Section", L"NetworkTraffic" },
        { L"Action", kEnable ? L"StartCapture" : L"StopCapture" },
        { L"Status", kControl.io.ok ? L"OK" : L"FAIL" },
        { L"Unsupported", boolText(kControl.unsupported) },
        { L"Win32", std::to_wstring(kControl.io.win32Error) },
    }, L"The capture ring is a fixed non-paged buffer, so an enabled capture cannot grow without bound; "
       L"what it does cost is per-packet work in the WFP callout. An unsupported result must not be read "
       L"as 'capture is off' -- the driver simply never answered the question."));
    return result;
}

// executePiDdbDeleteEntry removes one PiDDBCacheTable record. This erases the
// loader's evidence that a driver was ever vetted on this machine, which is
// exactly why it is gated behind a confirmation and reports the matched entry
// back: an operator should be able to see what was removed after the fact.
KernelOperationResult executePiDdbDeleteEntry(const KernelActionRequest& request) {
    KernelOperationResult result;
    result.supported = true;
    result.destructiveAction = true;

    ksword::ark::PiDdbEntry expected{};
    expected.driverName = actionRowField(request, { L"Driver", L"驱动" });
    expected.entryAddress = parseHexOrDecimal(actionRowField(request, { L"Entry", L"条目地址" }));
    expected.timeDateStamp =
        static_cast<std::uint32_t>(parseHexOrDecimal(actionRowField(request, { L"TimeDateStamp", L"时间戳" })));
    expected.loadStatus =
        static_cast<long>(parseHexOrDecimal(actionRowField(request, { L"LoadStatus", L"加载状态" })));

    if (expected.entryAddress == 0 || expected.driverName.empty()) {
        result.success = false;
        result.message = L"未能从选中行还原 PiDDB 条目（需要驱动名与条目地址），已放弃删除。";
        return result;
    }

    const ksword::ark::DriverClient kClient;
    // The expected entry is passed through so R0 can verify the slot still holds
    // what the UI showed; force stays false, so a slot that changed underneath is
    // refused rather than overwritten blind.
    const ksword::ark::PiDdbDeleteResult kRemove = kClient.deletePiDdbEntry(expected, request.force, true);
    result.success = kRemove.io.ok && !kRemove.unsupported;
    if (kRemove.unsupported) {
        result.message = L"当前 KswordARK 驱动未注册 PiDDB 删除 IOCTL。";
    } else {
        result.message = std::wstring(L"PiDDB 条目删除") + (result.success ? L"完成。" : L"失败。") +
            L" " + utf8ToWide(kRemove.io.message);
    }
    result.rows.push_back(makeResultRow({
        { L"Section", L"PiDDB" },
        { L"Action", L"DeleteEntry" },
        { L"Status", kRemove.io.ok ? L"OK" : L"FAIL" },
        { L"Unsupported", boolText(kRemove.unsupported) },
        { L"DeleteStatus", hexText(kRemove.status) },
        { L"RemainingRows", std::to_wstring(kRemove.remainingRows) },
        { L"RequestedDriver", expected.driverName },
        { L"RequestedEntry", hexText(expected.entryAddress) },
        { L"MatchedDriver", kRemove.matchedEntry.driverName },
        { L"MatchedEntry", hexText(kRemove.matchedEntry.entryAddress) },
        { L"LastStatus", hexText(static_cast<std::uint32_t>(kRemove.lastStatus)) },
    }, L"The entry the UI displayed is sent along so R0 can confirm the slot still matches before "
       L"removing it; without force a slot that changed in between is refused instead of overwritten. "
       L"Removing a record erases the loader's evidence that this driver was ever vetted here."));
    return result;
}

// DriverRecoveryIdentity is the target a restore/abandon addresses. Every field
// is read back out of the row the user selected rather than retyped, because
// these protocols verify identity and generation before touching anything: a
// hand-entered value that no longer matches is refused, which looks like a bug
// but is the protocol working.
struct DriverRecoveryIdentity {
    std::uint64_t moduleBase = 0;
    std::uint64_t driverObjectAddress = 0;
    std::uint32_t generation = 0;
    unsigned long majorFunction = 0;
    unsigned long fieldMask = 0;
    std::wstring driverName;
    bool valid = false;
};

DriverRecoveryIdentity buildDriverRecoveryIdentity(const KernelActionRequest& request) {
    DriverRecoveryIdentity identity;
    identity.driverName = request.filterText;
    identity.moduleBase = parseHexOrDecimal(actionRowField(request, { L"ModuleBase", L"DriverStart" }));
    identity.driverObjectAddress = parseHexOrDecimal(actionRowField(request, { L"DriverObject" }));
    identity.generation = static_cast<std::uint32_t>(parseHexOrDecimal(actionRowField(request, { L"Generation" })));
    identity.majorFunction = static_cast<unsigned long>(parseHexOrDecimal(actionRowField(request, { L"MajorFunction" })));
    identity.fieldMask = static_cast<unsigned long>(parseHexOrDecimal(actionRowField(request, { L"ManagedFields" })));
    identity.valid = identity.moduleBase != 0 || !identity.driverName.empty();
    return identity;
}

KernelOperationResult makeRecoveryPrompt(const wchar_t* label) {
    KernelOperationResult result;
    result.supported = true;
    result.success = false;
    result.message = std::wstring(label) + L"：请先查询目标驱动并选中结果行，动作需要行内的模块基址与代次。";
    return result;
}

// executeDriverDispatchRecovery restores one MajorFunction slot to its recorded
// original, or abandons the restore record while leaving the current value in
// place. Abandon is the more dangerous of the two despite touching nothing: it
// throws away the only record of what the slot used to be.
KernelOperationResult executeDriverDispatchRecovery(const KernelActionRequest& request) {
    const DriverRecoveryIdentity kIdentity = buildDriverRecoveryIdentity(request);
    const bool kRestore = request.actionId == KernelActionId::kDriverDispatchRestore;
    if (!kIdentity.valid) {
        return makeRecoveryPrompt(kRestore ? L"恢复驱动派遣槽" : L"放弃派遣恢复记录");
    }

    const ksword::ark::DriverClient kClient;
    const ksword::ark::DriverDispatchControlResult kControl = kRestore
        ? kClient.restoreDriverDispatch(
            kIdentity.moduleBase, kIdentity.driverName, kIdentity.majorFunction,
            kIdentity.driverObjectAddress, kIdentity.generation)
        : kClient.abandonDriverDispatch(
            kIdentity.moduleBase, kIdentity.driverName, kIdentity.majorFunction,
            kIdentity.driverObjectAddress, kIdentity.generation);

    KernelOperationResult result;
    result.supported = true;
    result.destructiveAction = !kRestore;
    result.success = kControl.io.ok && !kControl.unsupported;
    result.message = std::wstring(kRestore ? L"派遣槽恢复" : L"派遣恢复记录放弃") +
        (result.success ? L"完成。" : L"失败。") + L" " + utf8ToWide(kControl.io.message);
    result.rows.push_back(makeResultRow({
        { L"Section", L"DriverDispatch" },
        { L"Action", kRestore ? L"Restore" : L"Abandon" },
        { L"Status", kControl.io.ok ? L"OK" : L"FAIL" },
        { L"Unsupported", boolText(kControl.unsupported) },
        { L"MajorFunction", hexText(kControl.majorFunction) },
        { L"State", std::to_wstring(kControl.state) },
        { L"Generation", std::to_wstring(kControl.generation) },
        { L"Current", hexText(kControl.currentDispatchAddress) },
        { L"Original", hexText(kControl.originalDispatchAddress) },
        { L"ResponseFlags", hexText(kControl.responseFlags) },
        { L"LastStatus", hexText(static_cast<std::uint32_t>(kControl.lastStatus)) },
    }, L"Restore writes the recorded original back into the slot. Abandon changes nothing in the kernel "
       L"but permanently drops the record of what the original was, so a later restore becomes "
       L"impossible. The generation is checked first: if someone else altered the slot in between, the "
       L"request is refused rather than applied on top."));
    return result;
}

// executeDriverImageRecovery restores the LDR image fields this driver still
// holds records for, or drops those records. The field mask comes from the row's
// ManagedFields so a restore covers exactly what was actually changed.
KernelOperationResult executeDriverImageRecovery(const KernelActionRequest& request) {
    const DriverRecoveryIdentity kIdentity = buildDriverRecoveryIdentity(request);
    const bool kRestore = request.actionId == KernelActionId::kDriverImageRestore;
    if (!kIdentity.valid) {
        return makeRecoveryPrompt(kRestore ? L"恢复驱动镜像字段" : L"放弃镜像恢复记录");
    }

    const ksword::ark::DriverClient kClient;
    const ksword::ark::DriverImageControlResult kControl = kRestore
        ? kClient.restoreDriverImage(
            kIdentity.moduleBase, kIdentity.driverName, kIdentity.fieldMask, true,
            kIdentity.driverObjectAddress, kIdentity.generation)
        : kClient.abandonDriverImage(
            kIdentity.moduleBase, kIdentity.driverName,
            kIdentity.driverObjectAddress, kIdentity.generation);

    KernelOperationResult result;
    result.supported = true;
    result.destructiveAction = !kRestore;
    result.success = kControl.io.ok && !kControl.unsupported;
    result.message = std::wstring(kRestore ? L"镜像字段恢复" : L"镜像恢复记录放弃") +
        (result.success ? L"完成。" : L"失败。") + L" " + utf8ToWide(kControl.io.message);
    result.rows.push_back(makeResultRow({
        { L"Section", L"DriverImage" },
        { L"Action", kRestore ? L"Restore" : L"Abandon" },
        { L"Status", kControl.io.ok ? L"OK" : L"FAIL" },
        { L"Unsupported", boolText(kControl.unsupported) },
        { L"RequestedMask", hexText(kIdentity.fieldMask) },
        { L"ManagedFields", hexText(kControl.managedFieldMask) },
        { L"OwnedFields", hexText(kControl.ownedFieldMask) },
        { L"ConflictFields", hexText(kControl.conflictFieldMask) },
        { L"ChangedFields", hexText(kControl.changedFieldMask) },
        { L"State", std::to_wstring(kControl.state) },
        { L"Generation", std::to_wstring(kControl.generation) },
        { L"LastStatus", hexText(static_cast<std::uint32_t>(kControl.lastStatus)) },
    }, L"The restore mask comes from the row's ManagedFields, so it covers exactly the fields this "
       L"driver actually changed. A field listed in conflictFieldMask was rewritten by a third party "
       L"since — the recorded original is no longer what that field held before, and restoring it would "
       L"overwrite someone else's value."));
    return result;
}

// executeDriverCommunicationRestore points a driver's dispatch surface back at
// its own handlers after it was aimed at the system reject entry.
KernelOperationResult executeDriverCommunicationRestore(const KernelActionRequest& request) {
    const DriverRecoveryIdentity kIdentity = buildDriverRecoveryIdentity(request);
    if (!kIdentity.valid) {
        return makeRecoveryPrompt(L"恢复驱动通信");
    }

    const ksword::ark::DriverClient kClient;
    const ksword::ark::DriverCommunicationControlResult kControl =
        kClient.restoreDriverCommunication(kIdentity.moduleBase, kIdentity.driverName);

    KernelOperationResult result;
    result.supported = true;
    result.destructiveAction = false;
    result.success = kControl.io.ok;
    result.message = std::wstring(L"驱动通信恢复") + (result.success ? L"完成。" : L"失败。") +
        L" " + utf8ToWide(kControl.io.message);
    result.rows.push_back(makeResultRow({
        { L"Section", L"DriverCommunication" },
        { L"Action", L"Restore" },
        { L"Status", kControl.io.ok ? L"OK" : L"FAIL" },
        { L"State", std::to_wstring(kControl.state) },
        { L"TargetedMask", hexText(kControl.targetedMask) },
        { L"ActiveMask", hexText(kControl.activeMask) },
        { L"OwnedMask", hexText(kControl.ownedMask) },
        { L"ConflictMask", hexText(kControl.conflictMask) },
        { L"ChangedMask", hexText(kControl.changedMask) },
        { L"Generation", std::to_wstring(kControl.generation) },
        { L"LastStatus", hexText(static_cast<std::uint32_t>(kControl.lastStatus)) },
    }, L"Only the slots in ownedMask are restored — those are the ones this driver redirected and can "
       L"still account for. Slots in conflictMask were rewritten by someone else and are deliberately "
       L"left alone rather than reset to a value that is no longer theirs."));
    return result;
}

KernelOperationResult executeFileMonitorControl(const KernelActionRequest& request) {
    const ksword::ark::DriverClient kClient;
    KernelOperationResult result;
    result.supported = true;
    result.destructiveAction = request.actionId == KernelActionId::kFileMonitorClear;

    if (request.actionId == KernelActionId::kFileMonitorStartFsctl) {
        const ksword::ark::FileMonitorStatusResult kBefore = kClient.queryFileMonitorStatus();
        unsigned long requestedMask = KSWORD_ARK_FILE_MONITOR_OPERATION_FSCTL;
        if (kBefore.io.ok) {
            requestedMask |= kBefore.operationMask;
        }
        const ksword::ark::IoResult kIo = kClient.controlFileMonitor(KSWORD_ARK_FILE_MONITOR_ACTION_START, requestedMask, 0UL, 0UL);
        result.success = kIo.ok;
        result.message = std::wstring(L"FSCTL 文件监控启动") + (kIo.ok ? L"完成。" : L"失败。") + L" " + utf8ToWide(kIo.message);
        result.rows.push_back(makeResultRow({
            { L"Section", L"FileMonitor" },
            { L"Action", L"StartFsctl" },
            { L"Status", kIo.ok ? L"OK" : L"FAIL" },
            { L"OperationMask", hexText(requestedMask) },
            { L"Win32", std::to_wstring(kIo.win32Error) },
        }, utf8ToWide(kIo.message)));
    } else if (request.actionId == KernelActionId::kFileMonitorClear) {
        const ksword::ark::IoResult kIo = kClient.controlFileMonitor(KSWORD_ARK_FILE_MONITOR_ACTION_CLEAR, KSWORD_ARK_FILE_MONITOR_OPERATION_ALL, 0UL, 0UL);
        result.success = kIo.ok;
        result.message = std::wstring(L"文件监控队列清空") + (kIo.ok ? L"完成。" : L"失败。") + L" " + utf8ToWide(kIo.message);
        result.rows.push_back(makeResultRow({
            { L"Section", L"FileMonitor" },
            { L"Action", L"Clear" },
            { L"Status", kIo.ok ? L"OK" : L"FAIL" },
            { L"Win32", std::to_wstring(kIo.win32Error) },
        }, utf8ToWide(kIo.message)));
    }

    if (request.actionId == KernelActionId::kFileMonitorDrain ||
        request.actionId == KernelActionId::kFileMonitorStartFsctl ||
        request.actionId == KernelActionId::kFileMonitorClear) {
        const ksword::ark::FileMonitorDrainResult kDrain = kClient.drainFileMonitor(128UL, 0UL);
        result.success = result.success || kDrain.io.ok;
        if (result.message.empty()) {
            result.message = std::wstring(L"文件监控事件拉取") + (kDrain.io.ok ? L"完成。" : L"失败。") + L" " + utf8ToWide(kDrain.io.message);
        }
        result.rows.push_back(makeResultRow({
            { L"Section", L"FileMonitor" },
            { L"Action", L"Drain" },
            { L"Status", kDrain.io.ok ? L"OK" : L"FAIL" },
            { L"Returned", std::to_wstring(kDrain.returnedCount) },
            { L"Parsed", std::to_wstring(kDrain.events.size()) },
            { L"QueuedBefore", std::to_wstring(kDrain.totalQueuedBeforeDrain) },
            { L"Dropped", std::to_wstring(kDrain.droppedCount) },
            { L"Win32", std::to_wstring(kDrain.io.win32Error) },
        }, utf8ToWide(kDrain.io.message)));
        for (const ksword::ark::FileMonitorEventRow& event : kDrain.events) {
            const bool kFsctlEvent = (event.operationType & KSWORD_ARK_FILE_MONITOR_OPERATION_FSCTL) != 0U;
            const bool kPathPresent = (event.fieldFlags & KSWORD_ARK_FILE_MONITOR_FIELD_PATH_PRESENT) != 0U;
            const bool kPathTruncated = (event.fieldFlags & KSWORD_ARK_FILE_MONITOR_FIELD_PATH_TRUNCATED) != 0U;
            const std::wstring kPathState = kPathTruncated
                ? L"截断"
                : kPathPresent
                    ? L"完整"
                    : L"未确认";
            pushFilteredRow(result, makeResultRow({
                { L"Section", L"FileEvent" },
                { L"Time", utc100nsToLocalText(static_cast<std::uint64_t>(event.timeUtc100ns)) },
                { L"TimeRaw", hexText(static_cast<std::uint64_t>(event.timeUtc100ns)) },
                { L"PID", std::to_wstring(event.processId) },
                { L"Process", processDisplayName(event.processId) },
                { L"Path", event.path },
                { L"PathState", kPathState },
                { L"PathLength", std::to_wstring(event.pathLengthChars) },
                { L"FieldFlags", hexText(event.fieldFlags) },
                { L"FsctlName", kFsctlEvent ? std::wstring(KswordARKFileMonitorFsctlCodeToText(event.fsControlCode)) : L"-" },
                { L"ControlCode", kFsctlEvent ? hexText(event.fsControlCode) : L"-" },
                { L"Status", kFsctlEvent ? hexText(static_cast<std::uint32_t>(event.resultStatus)) : L"-" },
                { L"FileObject", hexText(event.fileObjectAddress) },
                { L"InputLength", kFsctlEvent ? std::to_wstring(event.fsInputBufferLength) : L"-" },
                { L"OutputLength", kFsctlEvent ? std::to_wstring(event.fsOutputBufferLength) : L"-" },
                { L"Operation", hexText(event.operationType) },
                { L"Major", std::to_wstring(event.majorFunction) },
                { L"Minor", std::to_wstring(event.minorFunction) },
                { L"TID", std::to_wstring(event.threadId) },
            }), request.filterText);
        }
    }
    return result;
}

// executeDriverObjectQueryDetail resolves the selected Device/DriverObjects row
// to a canonical DriverObject name and performs a focused R0 query. Inputs are
// selected row text fields; processing goes through ArkDriverClient only; output
// is the same generic row model used by normal refresh results.
KernelOperationResult executeDriverObjectQueryDetail(const KernelActionRequest& request) {
    const std::wstring kDriverName = driverObjectNameFromActionRequest(request);
    if (kDriverName.empty()) {
        return makeActionError(request, L"当前行不是可解析的 \\Driver\\Name 或 R0 DriverObject 行。");
    }

    const ksword::ark::DriverClient kClient;
    const ksword::ark::DriverObjectQueryResult kQuery = kClient.queryDriverObject(
        kDriverName,
        KSWORD_ARK_DRIVER_OBJECT_QUERY_FLAG_INCLUDE_ALL,
        KSWORD_ARK_DRIVER_DEVICE_LIMIT_DEFAULT,
        KSWORD_ARK_DRIVER_ATTACHED_LIMIT_DEFAULT);

    KernelOperationResult result;
    result.supported = true;
    result.success = isDriverObjectQuerySuccess(kQuery);
    result.destructiveAction = false;
    result.message = std::wstring(L"DriverObject 详情查询")
        + (result.success ? L"完成。" : L"未完成。")
        + L" "
        + utf8ToWide(kQuery.io.message);
    result.rows.push_back(makeResultRow({
        { L"Action", L"DriverObjectQueryDetail" },
        { L"Request", kDriverName },
        { L"IO", kQuery.io.ok ? L"OK" : L"FAIL" },
        { L"Win32", std::to_wstring(kQuery.io.win32Error) },
        { L"BytesReturned", std::to_wstring(kQuery.io.bytesReturned) },
        { L"QueryStatus", std::wstring(driverObjectQueryStatusText(kQuery.queryStatus)) + L" (" + std::to_wstring(kQuery.queryStatus) + L")" },
        { L"LastStatus", hexText(static_cast<std::uint32_t>(kQuery.lastStatus)) },
    }, utf8ToWide(kQuery.io.message)));
    appendDriverObjectQueryRows(kDriverName, kQuery, result);
    return result;
}

// executeDriverObjectForceUnload requests the R0 DriverObject force-unload path
// for the selected driver row. Inputs are selected row text fields; processing
// asks ArkDriverClient to call the shared IOCTL; output reports every returned
// status field so the UI does not hide partial cleanup/failure details.
KernelOperationResult executeDriverObjectForceUnload(const KernelActionRequest& request) {
    const std::wstring kDriverName = driverObjectNameFromActionRequest(request);
    const std::uint64_t kModuleBase = driverModuleBaseFromActionRequest(request);
    if (kDriverName.empty() && kModuleBase == 0ULL) {
        return makeActionError(request, L"当前行没有可卸载的 \\Driver\\Name 或模块基址。请先查询 R0 DriverObject 详情。 ");
    }

    const ksword::ark::DriverClient kClient;
    const ksword::ark::DriverForceUnloadResult kUnload = kModuleBase != 0ULL
        ? kClient.forceUnloadDriverByModuleBase(kModuleBase, kDriverName, 0UL, 3000UL)
        : kClient.forceUnloadDriver(kDriverName, 0UL, 3000UL);

    KernelOperationResult result;
    result.supported = true;
    result.success = kUnload.io.ok && driverUnloadSucceeded(kUnload.status);
    result.destructiveAction = true;
    result.message = std::wstring(L"DriverObject 强制卸载")
        + (result.success ? L"完成。" : L"未完成。")
        + L" "
        + utf8ToWide(kUnload.io.message);
    result.rows.push_back(makeResultRow({
        { L"Action", L"DriverObjectForceUnload" },
        { L"Request", kDriverName },
        { L"ModuleBase", hexText(kModuleBase) },
        { L"Resolution", kModuleBase != 0ULL ? L"ModuleBase" : L"DriverName" },
        { L"IO", kUnload.io.ok ? L"OK" : L"FAIL" },
        { L"Win32", std::to_wstring(kUnload.io.win32Error) },
        { L"BytesReturned", std::to_wstring(kUnload.io.bytesReturned) },
        { L"Version", std::to_wstring(kUnload.version) },
        { L"Status", std::wstring(driverUnloadStatusText(kUnload.status)) + L" (" + std::to_wstring(kUnload.status) + L")" },
        { L"Flags", hexText(kUnload.flags) },
        { L"DriverName", kUnload.driverName.empty() ? kDriverName : kUnload.driverName },
        { L"DriverObject", hexText(kUnload.driverObjectAddress) },
        { L"DriverUnload", hexText(kUnload.driverUnloadAddress) },
        { L"LastStatus", hexText(static_cast<std::uint32_t>(kUnload.lastStatus)) },
        { L"WaitStatus", hexText(static_cast<std::uint32_t>(kUnload.waitStatus)) },
        { L"CleanupFlagsApplied", hexText(kUnload.cleanupFlagsApplied) },
        { L"DeletedDeviceCount", std::to_wstring(kUnload.deletedDeviceCount) },
        { L"CallbackCandidates", std::to_wstring(kUnload.callbackCandidates) },
        { L"CallbacksRemoved", std::to_wstring(kUnload.callbacksRemoved) },
        { L"CallbackFailures", std::to_wstring(kUnload.callbackFailures) },
        { L"CallbackLastStatus", hexText(static_cast<std::uint32_t>(kUnload.callbackLastStatus)) },
    }, utf8ToWide(kUnload.io.message)));
    return result;
}

// executeDynDataApplyMatchedProfile finds the current ntoskrnl PDB profile and
// sends it to R0 through ArkDriverClient. Inputs are the action request and
// current driver identity read from DynData status; processing never opens the
// KswordARK device directly; output reports match metadata plus the driver apply
// response so the UI can diagnose rejected/unknown fields precisely.
KernelOperationResult executeDynDataApplyMatchedProfile(const KernelActionRequest& request) {
    const ksword::ark::DriverClient kClient;
    const ksword::ark::DynDataStatusResult kStatus = kClient.queryDynDataStatus();
    if (!kStatus.io.ok) {
        KernelOperationResult result;
        result.supported = true;
        result.success = false;
        result.destructiveAction = true;
        result.message = L"DynData status 查询失败，无法匹配并应用本地 profile。 " + utf8ToWide(kStatus.io.message);
        result.rows.push_back(makeResultRow({
            { L"Action", L"DynDataApplyMatchedProfile" },
            { L"Stage", L"QueryDynDataStatus" },
            { L"IO", kStatus.io.ok ? L"OK" : L"FAIL" },
            { L"Win32", std::to_wstring(kStatus.io.win32Error) },
            { L"BytesReturned", std::to_wstring(kStatus.io.bytesReturned) },
        }, utf8ToWide(kStatus.io.message)));
        return result;
    }

    const DynDataProfileMatch kMatch = findMatchingDynDataProfile(kStatus.ntoskrnl);
    if (!kMatch.valid) {
        KernelOperationResult result;
        result.supported = true;
        result.success = false;
        result.destructiveAction = true;
        result.message = L"没有可应用的匹配 DynData profile。 " + kMatch.message;
        result.rows.push_back(makeResultRow({
            { L"Action", L"DynDataApplyMatchedProfile" },
            { L"Stage", L"MatchLocalProfile" },
            { L"Matched", kMatch.matched ? L"是" : L"否" },
            { L"Valid", kMatch.valid ? L"是" : L"否" },
            { L"ProfilePath", kMatch.path },
            { L"ExistingPacks", std::to_wstring(kMatch.existingPackCount) },
            { L"ScannedProfiles", std::to_wstring(kMatch.scannedProfileCount) },
        }, kMatch.message));
        appendDynDataProfileRows(result, kMatch, request.filterText);
        return result;
    }

    KernelOperationResult result;
    result.supported = true;
    result.destructiveAction = true;
    result.success = true;
    bool appliedAnyLayer = false;
    const auto kAppendLayerMessage = [&result](const std::wstring& message) {
        if (!result.message.empty()) {
            result.message += L" | ";
        }
        result.message += message;
    };

    if (!kMatch.profile.fields.empty()) {
        appliedAnyLayer = true;
        const ksword::ark::DynDataProfileApplyResult kApplied = kClient.applyDynDataProfile(kMatch.profile);
        const bool kLayerSucceeded =
            kApplied.io.ok &&
            kApplied.status >= 0 &&
            kApplied.rejectedFieldCount == 0 &&
            kApplied.unknownFieldCount == 0;
        result.success = result.success && kLayerSucceeded;
        kAppendLayerMessage(
            std::wstring(L"DynData legacy profile 应用")
            + (kLayerSucceeded ? L"完成。" : L"失败或部分拒绝。")
            + L" "
            + kApplied.message
            + L" "
            + utf8ToWide(kApplied.io.message));
        result.rows.push_back(makeResultRow({
            { L"Action", L"DynDataApplyMatchedProfile" },
            { L"Mode", L"Legacy" },
            { L"IO", kApplied.io.ok ? L"OK" : L"FAIL" },
            { L"Win32", std::to_wstring(kApplied.io.win32Error) },
            { L"BytesReturned", std::to_wstring(kApplied.io.bytesReturned) },
            { L"NTSTATUS", hexText(static_cast<std::uint32_t>(kApplied.status)) },
            { L"AppliedFields", std::to_wstring(kApplied.appliedFieldCount) },
            { L"RejectedFields", std::to_wstring(kApplied.rejectedFieldCount) },
            { L"UnknownFields", std::to_wstring(kApplied.unknownFieldCount) },
            { L"StatusFlags", hexText(kApplied.statusFlags) },
            { L"CapabilityMask", hexText(kApplied.capabilityMask) },
            { L"Profile", utf8ToWide(kMatch.profile.profileName) },
            { L"PdbName", utf8ToWide(kMatch.profile.pdbName) },
            { L"PdbGuid", utf8ToWide(kMatch.profile.pdbGuid) },
            { L"PdbAge", std::to_wstring(kMatch.profile.pdbAge) },
            { L"ProfilePath", kMatch.path },
        }, kApplied.message.empty() ? utf8ToWide(kApplied.io.message) : kApplied.message));
    }

    if (!kMatch.profileEx.items.empty()) {
        appliedAnyLayer = true;
        const ksword::ark::DynDataProfileApplyExResult kApplied = kClient.applyDynDataProfileEx(kMatch.profileEx);
        const bool kLayerSucceeded =
            kApplied.io.ok &&
            kApplied.status >= 0 &&
            kApplied.rejectedItemCount == 0 &&
            kApplied.unknownItemCount == 0;
        result.success = result.success && kLayerSucceeded;
        kAppendLayerMessage(
            std::wstring(L"DynData EX profile 应用")
            + (kLayerSucceeded ? L"完成。" : L"失败或部分拒绝。")
            + L" "
            + kApplied.message
            + L" "
            + utf8ToWide(kApplied.io.message));
        result.rows.push_back(makeResultRow({
            { L"Action", L"DynDataApplyMatchedProfile" },
            { L"Mode", L"EX" },
            { L"IO", kApplied.io.ok ? L"OK" : L"FAIL" },
            { L"Win32", std::to_wstring(kApplied.io.win32Error) },
            { L"BytesReturned", std::to_wstring(kApplied.io.bytesReturned) },
            { L"NTSTATUS", hexText(static_cast<std::uint32_t>(kApplied.status)) },
            { L"AppliedItems", std::to_wstring(kApplied.appliedItemCount) },
            { L"RejectedItems", std::to_wstring(kApplied.rejectedItemCount) },
            { L"UnknownItems", std::to_wstring(kApplied.unknownItemCount) },
            { L"StatusFlags", hexText(kApplied.statusFlags) },
            { L"CapabilityMask", hexText(kApplied.capabilityMask) },
            { L"Profile", utf8ToWide(kMatch.profileEx.profileName) },
            { L"PdbName", utf8ToWide(kMatch.profileEx.pdbName) },
            { L"PdbGuid", utf8ToWide(kMatch.profileEx.pdbGuid) },
            { L"PdbAge", std::to_wstring(kMatch.profileEx.pdbAge) },
            { L"ProfilePath", kMatch.path },
        }, kApplied.message.empty() ? utf8ToWide(kApplied.io.message) : kApplied.message));
    }

    if (!kMatch.profileV4.items.empty()) {
        appliedAnyLayer = true;
        const ksword::ark::DynDataV4ApplyResult kApplied = kClient.applyDynDataProfileV4(kMatch.profileV4);
        const KSW_APPLY_DYN_PROFILE_V4_RESPONSE& response = kApplied.response;
        const bool kLayerSucceeded = kApplied.io.ok && !kApplied.unsupported && response.status >= 0 &&
            response.rejectedItemCount == 0 && response.missingRequiredItemCount == 0;
        result.success = result.success && kLayerSucceeded;
        kAppendLayerMessage(
            std::wstring(L"DynData V4 profile 应用")
            + (kLayerSucceeded ? L"完成。" : L"失败、旧驱动不支持或存在必需项缺失。")
            + L" "
            + response.message
            + L" "
            + utf8ToWide(kApplied.io.message));
        result.rows.push_back(makeResultRow({
            { L"Action", L"DynDataApplyMatchedProfile" },
            { L"Mode", L"V4" },
            { L"IO", kApplied.io.ok ? L"OK" : L"FAIL" },
            { L"Unsupported", boolText(kApplied.unsupported) },
            { L"Win32", std::to_wstring(kApplied.io.win32Error) },
            { L"BytesReturned", std::to_wstring(kApplied.io.bytesReturned) },
            { L"NTSTATUS", hexText(static_cast<std::uint32_t>(response.status)) },
            { L"StatusFlags", hexText(response.statusFlags) },
            { L"AppliedItems", std::to_wstring(response.appliedItemCount) },
            { L"RejectedItems", std::to_wstring(response.rejectedItemCount) },
            { L"RequiredItems", std::to_wstring(response.requiredItemCount) },
            { L"PresentRequiredItems", std::to_wstring(response.presentRequiredItemCount) },
            { L"OptionalItems", std::to_wstring(response.optionalItemCount) },
            { L"PresentOptionalItems", std::to_wstring(response.presentOptionalItemCount) },
            { L"ActiveCapabilityGroups", std::to_wstring(response.activeCapabilityGroupCount) },
            { L"MissingRequiredItems", std::to_wstring(response.missingRequiredItemCount) },
            { L"MissingOptionalItems", std::to_wstring(response.missingOptionalItemCount) },
            { L"Profile", utf8ToWide(kMatch.profile.profileName) },
            { L"PdbName", utf8ToWide(kMatch.profile.pdbName) },
            { L"PdbGuid", utf8ToWide(kMatch.profile.pdbGuid) },
            { L"PdbAge", std::to_wstring(kMatch.profile.pdbAge) },
            { L"ItemCount", std::to_wstring(kMatch.profileV4.items.size()) },
            { L"CapabilityGroupCount", std::to_wstring(kMatch.profileV4.capabilityGroups.size()) },
            { L"ProfilePath", kMatch.path },
        }, response.message[0] == L'\0' ? utf8ToWide(kApplied.io.message) : std::wstring(response.message)));
    }

    if (!appliedAnyLayer) {
        result.success = false;
        result.message = L"匹配的 DynData profile 没有可下发的 Legacy、EX 或 V4 数据层。";
    }

    appendDynDataProfileRows(result, kMatch, request.filterText);
    return result;
}

// mutationActionName maps action ids to display names. Input is a mutation action
// enum; output is a stable label for result rows and messages.
const wchar_t* mutationActionName(const KernelActionId actionId) {
    switch (actionId) {
    case KernelActionId::kMutationCommitDryRun: return L"MutationCommitDryRun";
    case KernelActionId::kMutationRollbackDryRun: return L"MutationRollbackDryRun";
    case KernelActionId::kMutationRollbackConfirmed: return L"MutationRollbackConfirmed";
    default: return L"MutationUnknown";
    }
}

// mutationActionSucceeded classifies the response status for user feedback. Input
// is a response packet and whether the request was dry-run; output is true when
// the operation reached the expected dry-run/rollback/commit outcome.
bool mutationActionSucceeded(const ksword::ark::MutationResponseResult& response, const bool dryRun, const bool rollback) {
    if (!response.io.ok) {
        return false;
    }
    if (dryRun) {
        return response.status == KSWORD_ARK_MUTATION_STATUS_DRY_RUN ||
            response.status == KSWORD_ARK_MUTATION_STATUS_ALREADY_AT_BEFORE;
    }
    if (rollback) {
        return response.status == KSWORD_ARK_MUTATION_STATUS_ROLLED_BACK ||
            response.status == KSWORD_ARK_MUTATION_STATUS_ALREADY_AT_BEFORE;
    }
    return response.status == KSWORD_ARK_MUTATION_STATUS_COMMITTED;
}

// executeMutationTransaction runs commit/rollback actions for a selected audit
// transaction. Inputs are the current action request and selected Tx field;
// processing only calls ArkDriverClient transaction APIs and never accepts
// arbitrary write bytes from UI; output contains full response metadata and a
// refreshed audit snapshot so the user can see the resulting event.
KernelOperationResult executeMutationTransaction(const KernelActionRequest& request) {
    const std::wstring kTxText = firstFieldValue(request, { L"Tx", L"TransactionId" });
    std::uint64_t transactionId = 0;
    if (!parseUnsigned64(kTxText, transactionId) || transactionId == 0) {
        return makeActionError(request, L"当前 Mutation Audit 行缺少有效 TransactionId/Tx 字段。");
    }

    const bool kRollback = request.actionId != KernelActionId::kMutationCommitDryRun;
    const bool kDryRun = request.actionId != KernelActionId::kMutationRollbackConfirmed;
    const unsigned long kFlags = kDryRun
        ? KSWORD_ARK_MUTATION_FLAG_DRY_RUN
        : (KSWORD_ARK_MUTATION_FLAG_FORCE | KSWORD_ARK_MUTATION_FLAG_UI_CONFIRMED);

    const ksword::ark::DriverClient kClient;
    const ksword::ark::MutationResponseResult kResponse = kRollback
        ? kClient.rollbackMutation(transactionId, kFlags)
        : kClient.commitMutation(transactionId, kFlags);

    KernelOperationResult result;
    result.supported = true;
    result.destructiveAction = !kDryRun;
    result.success = mutationActionSucceeded(kResponse, kDryRun, kRollback);
    result.message = std::wstring(mutationActionName(request.actionId))
        + (result.success ? L" 完成。" : L" 未完成。")
        + L" "
        + utf8ToWide(kResponse.io.message);
    result.rows.push_back(makeResultRow({
        { L"Action", mutationActionName(request.actionId) },
        { L"RequestTx", hexText(transactionId) },
        { L"RequestFlags", hexText(kFlags) },
        { L"RequestFlagsText", mutationFlagsText(kFlags) },
        { L"IO", kResponse.io.ok ? L"OK" : L"FAIL" },
        { L"Unsupported", boolText(kResponse.unsupported) },
        { L"Win32", std::to_wstring(kResponse.io.win32Error) },
        { L"BytesReturned", std::to_wstring(kResponse.io.bytesReturned) },
        { L"Version", std::to_wstring(kResponse.version) },
        { L"Status", std::wstring(mutationStatusText(kResponse.status)) + L" (" + std::to_wstring(kResponse.status) + L")" },
        { L"TargetKind", std::wstring(mutationTargetText(kResponse.targetKind)) + L" (" + std::to_wstring(kResponse.targetKind) + L")" },
        { L"PID", std::to_wstring(kResponse.processId) },
        { L"Tx", hexText(kResponse.transactionId) },
        { L"Address", hexText(kResponse.targetAddress) },
        { L"Context", hexText(kResponse.targetContext) },
        { L"Bytes", std::to_wstring(kResponse.bytes) },
        { L"Risk", hexText(kResponse.riskFlags) },
        { L"RiskText", mutationRiskText(kResponse.riskFlags) },
        { L"BeforeHash", hexText(kResponse.beforeHash) },
        { L"AfterHash", hexText(kResponse.afterHash) },
        { L"BeforeBytes", bytesHex(kResponse.beforeBytes) },
        { L"AfterBytes", bytesHex(kResponse.afterBytes) },
        { L"LastStatus", hexText(static_cast<std::uint32_t>(kResponse.lastStatus)) },
    }, utf8ToWide(kResponse.io.message)));

    const ksword::ark::MutationAuditResult kAudit = kClient.queryMutationAudit(
        KSWORD_ARK_MUTATION_QUERY_AUDIT_FLAG_INCLUDE_BYTES,
        KSWORD_ARK_MUTATION_AUDIT_RING_CAPACITY,
        0);
    result.rows.push_back(makeResultRow({
        { L"Action", L"MutationAuditRefresh" },
        { L"IO", kAudit.io.ok ? L"OK" : L"FAIL" },
        { L"Unsupported", boolText(kAudit.unsupported) },
        { L"Returned", std::to_wstring(kAudit.returnedCount) },
        { L"Lost", std::to_wstring(kAudit.lostCount) },
        { L"OldestSeq", hexText(kAudit.oldestSequence) },
        { L"NextSeq", hexText(kAudit.nextSequence) },
    }, utf8ToWide(kAudit.io.message)));
    for (const ksword::ark::MutationAuditEntry& entry : kAudit.entries) {
        if (entry.transactionId != transactionId) {
            continue;
        }
        result.rows.push_back(makeResultRow({
            { L"Source", L"AuditAfterAction" },
            { L"Seq", hexText(entry.sequence) },
            { L"Tx", hexText(entry.transactionId) },
            { L"Operation", std::wstring(mutationOperationText(entry.operation)) + L" (" + std::to_wstring(entry.operation) + L")" },
            { L"Status", std::wstring(mutationStatusText(entry.status)) + L" (" + std::to_wstring(entry.status) + L")" },
            { L"TargetKind", std::wstring(mutationTargetText(entry.targetKind)) + L" (" + std::to_wstring(entry.targetKind) + L")" },
            { L"Risk", hexText(entry.riskFlags) },
            { L"RiskText", mutationRiskText(entry.riskFlags) },
            { L"Flags", hexText(entry.flags) },
            { L"FlagsText", mutationFlagsText(entry.flags) },
            { L"Data", bytesHex(entry.byteData) },
            { L"LastStatus", hexText(static_cast<std::uint32_t>(entry.lastStatus)) },
        }));
    }
    return result;
}

} // namespace

KernelOperationResult KernelFacade::queryFeature(const KernelRequest& request) const {
    if (request.featureId == KernelFeatureId::kDeviceDriverObjects) {
        return queryDeviceDriverObjectsHybrid(request);
    }
    if (isNativeKernelFeature(request.featureId)) {
        return queryNativeKernelFeature(request);
    }
    if (isArkDriverBacked(request.featureId)) {
        return queryArkDriverFeature(request);
    }
    return makeUnsupportedResult(request, L"该内核条目没有注册 R3 Native 或 ArkDriverClient 查询路径。");
}

KernelOperationResult KernelFacade::executeAction(const KernelActionRequest& request) const {
    switch (request.actionId) {
    case KernelActionId::kInlineHookNopPatch:
        return executeInlineHookNopPatch(request);
    case KernelActionId::kCallbackCancelPendingDecisions:
    case KernelActionId::kCallbackApplyDisabledEmptyRules:
    case KernelActionId::kCallbackApplyLocalRules:
        return executeCallbackRuntimeControl(request);
    case KernelActionId::kCallbackAnswerEvent:
        return executeCallbackAnswerEvent(request);
    case KernelActionId::kCallbackSafeRemove:
        return executeCallbackSafeRemove(request);
    case KernelActionId::kCallbackExperimentalUnlink:
        return executeCallbackExperimentalUnlink(request);
    case KernelActionId::kMinifilterSetBypassPids:
    case KernelActionId::kMinifilterClearBypassPids:
        return executeSetMinifilterBypassPids(request);
    case KernelActionId::kNetworkCaptureStart:
    case KernelActionId::kNetworkCaptureStop:
        return executeNetworkCaptureControl(request);
    case KernelActionId::kPiDdbDeleteEntry:
        return executePiDdbDeleteEntry(request);
    case KernelActionId::kDriverDispatchRestore:
    case KernelActionId::kDriverDispatchAbandon:
        return executeDriverDispatchRecovery(request);
    case KernelActionId::kDriverImageRestore:
    case KernelActionId::kDriverImageAbandon:
        return executeDriverImageRecovery(request);
    case KernelActionId::kDriverCommunicationRestore:
        return executeDriverCommunicationRestore(request);
    case KernelActionId::kFileMonitorStartFsctl:
    case KernelActionId::kFileMonitorDrain:
    case KernelActionId::kFileMonitorClear:
        return executeFileMonitorControl(request);
    case KernelActionId::kDriverObjectQueryDetail:
        return executeDriverObjectQueryDetail(request);
    case KernelActionId::kDriverObjectForceUnload:
        return executeDriverObjectForceUnload(request);
    case KernelActionId::kNativeObjectQueryDetail:
    case KernelActionId::kNativeSymbolicLinkResolve:
    case KernelActionId::kNativeNamedPipeProbe:
        return executeNativeKernelAction(request);
    case KernelActionId::kDynDataApplyMatchedProfile:
        return executeDynDataApplyMatchedProfile(request);
    case KernelActionId::kMutationCommitDryRun:
    case KernelActionId::kMutationRollbackDryRun:
    case KernelActionId::kMutationRollbackConfirmed:
        return executeMutationTransaction(request);
    case KernelActionId::kNone:
    default:
        return makeActionError(request, L"未选择可执行的内核动作。");
    }
}

KernelOperationResult KernelFacade::queryArkDriverFeature(const KernelRequest& request) const {
    const ksword::ark::DriverClient kClient;
    const ksword::ark::DriverCapabilitiesQueryResult kCapability = kClient.queryDriverCapabilities();
    auto attachCapability = [&](KernelOperationResult result) {
        result.rows.insert(result.rows.begin(), makeResultRow({
            { L"R0", kCapability.io.ok ? L"Online" : L"Unavailable" },
            { L"Protocol", std::to_wstring(kCapability.driverProtocolVersion) },
            { L"StatusFlags", hexText(kCapability.statusFlags) },
            { L"DynDataStatus", hexText(kCapability.dynDataStatusFlags) },
            { L"Win32", std::to_wstring(kCapability.io.win32Error) },
            { L"CapabilityBytes", std::to_wstring(kCapability.io.bytesReturned) },
        }, kCapability.io.ok ? utf8ToWide(kCapability.lastErrorSummary) : utf8ToWide(kCapability.io.message)));
        if (!kCapability.io.ok && result.message.find(L"R0") == std::wstring::npos) {
            result.message = std::wstring(L"R0 驱动能力查询失败：") + utf8ToWide(kCapability.io.message) + L" " + result.message;
        }
        return result;
    };

    switch (request.featureId) {
    case KernelFeatureId::kSsdt:
        return attachCapability(querySsdt(request, false));
    case KernelFeatureId::kShadowSsdt:
        return attachCapability(querySsdt(request, true));
    case KernelFeatureId::kInlineHook:
        return attachCapability(queryInlineHooks(request));
    case KernelFeatureId::kIatEatHook:
        return attachCapability(queryIatEatHooks(request));
    case KernelFeatureId::kDynData:
        return attachCapability(queryDynData(request));
    case KernelFeatureId::kDriverStatus:
        return attachCapability(queryDriverStatus(request));
    case KernelFeatureId::kCallbackIntercept:
        return attachCapability(queryCallbackRuntime(request));
    case KernelFeatureId::kCallbackEnumeration:
        return attachCapability(queryCallbackEnumeration(request));
    case KernelFeatureId::kKernelExecutableMemory:
        return attachCapability(queryKernelExecutableMemory(request));
    case KernelFeatureId::kKernelMemoryEvidence:
        return attachCapability(queryKernelMemoryEvidence(request));
    case KernelFeatureId::kProcessCrossView:
        return attachCapability(queryProcessCrossView(request));
    case KernelFeatureId::kThreadCrossView:
        return attachCapability(queryThreadCrossView(request));
    case KernelFeatureId::kDriverIntegrity:
        return attachCapability(queryDriverIntegrity(request));
    case KernelFeatureId::kKernelCpuIntegrity:
        return attachCapability(queryKernelCpuIntegrity(request));
    case KernelFeatureId::kCpuHardwareSnapshot:
        return attachCapability(queryCpuHardwareSnapshot(request));
    case KernelFeatureId::kPhysicalMemoryLayout:
        return attachCapability(queryPhysicalMemoryLayout(request));
    case KernelFeatureId::kMutationAudit:
        return attachCapability(queryMutationAudit(request));
    case KernelFeatureId::kKeyboardHotkeys:
        return attachCapability(queryKeyboardHotkeys(request));
    case KernelFeatureId::kKeyboardHooks:
        return attachCapability(queryKeyboardHooks(request));
    case KernelFeatureId::kDynDataCapabilities:
        return attachCapability(queryDynDataCapabilities(request));
    case KernelFeatureId::kPdbProfileStatus:
        return attachCapability(queryPdbProfileStatus(request));
    case KernelFeatureId::kCidTableSummary:
        return attachCapability(queryCidTableSummary(request));
    case KernelFeatureId::kIpcSummary:
        return attachCapability(queryIpcSummary(request));
    case KernelFeatureId::kHookAuditSummary:
        return attachCapability(queryHookAuditSummary(request));
    case KernelFeatureId::kMinifilterBypassPids:
        return attachCapability(queryMinifilterBypassPids(request));
    case KernelFeatureId::kKernelTimerDpc:
        return attachCapability(queryKernelTimerDpc(request));
    case KernelFeatureId::kIoctlRegistry:
        return attachCapability(queryIoctlRegistry(request));
    case KernelFeatureId::kWorkQueueThreads:
        return attachCapability(queryWorkQueueThreads(request));
    case KernelFeatureId::kSlatIommuAudit:
        return attachCapability(querySlatIommuAudit(request));
    case KernelFeatureId::kHvmStatus:
        return attachCapability(queryHvmStatus(request));
    case KernelFeatureId::kHvmEvents:
        return attachCapability(queryHvmEvents(request));
    case KernelFeatureId::kDriverDispatchTable:
        return attachCapability(queryDriverDispatchTable(request));
    case KernelFeatureId::kDriverImageFields:
        return attachCapability(queryDriverImageFields(request));
    case KernelFeatureId::kDriverCommunication:
        return attachCapability(queryDriverCommunication(request));
    case KernelFeatureId::kPlatformAudit:
        return attachCapability(queryPlatformAudit(request));
    case KernelFeatureId::kSystemTimeState:
        return attachCapability(querySystemTimeState(request));
    case KernelFeatureId::kI8042Audit:
        return attachCapability(queryI8042Audit(request));
    case KernelFeatureId::kPiDdbCache:
        return attachCapability(queryPiDdbCache(request));
    case KernelFeatureId::kRawDiskSectors:
        return attachCapability(queryRawDiskSectors(request));
    case KernelFeatureId::kNetworkTrafficPackets:
        return attachCapability(queryNetworkTrafficPackets(request));
    default:
        return makeUnsupportedResult(request, L"该内核条目没有对应的 ArkDriverClient 只读 IOCTL。 ");
    }
}

} // namespace Ksword::Features::Kernel
