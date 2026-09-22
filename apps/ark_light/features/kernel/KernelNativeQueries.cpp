#include "KernelNativeQueries.h"

#include "../../core/Win32Lean.h"

#include <winternl.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cwctype>
#include <cwchar>
#include <deque>
#include <functional>
#include <iomanip>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifndef DIRECTORY_QUERY
#define DIRECTORY_QUERY 0x0001
#endif

#ifndef SYMBOLIC_LINK_QUERY
#define SYMBOLIC_LINK_QUERY 0x0001
#endif

#ifndef FILE_LIST_DIRECTORY
#define FILE_LIST_DIRECTORY 0x0001
#endif

#ifndef FILE_DIRECTORY_FILE
#define FILE_DIRECTORY_FILE 0x00000001
#endif

#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#endif

#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040L
#endif

#ifndef OBJ_INHERIT
#define OBJ_INHERIT 0x00000002L
#endif

#ifndef OBJ_PERMANENT
#define OBJ_PERMANENT 0x00000010L
#endif

#ifndef OBJ_EXCLUSIVE
#define OBJ_EXCLUSIVE 0x00000020L
#endif

#ifndef OBJ_OPENIF
#define OBJ_OPENIF 0x00000080L
#endif

#ifndef OBJ_OPENLINK
#define OBJ_OPENLINK 0x00000100L
#endif

#ifndef OBJ_KERNEL_HANDLE
#define OBJ_KERNEL_HANDLE 0x00000200L
#endif

#ifndef OBJ_FORCE_ACCESS_CHECK
#define OBJ_FORCE_ACCESS_CHECK 0x00000400L
#endif

#ifndef OBJ_IGNORE_IMPERSONATED_DEVICEMAP
#define OBJ_IGNORE_IMPERSONATED_DEVICEMAP 0x00000800L
#endif

#ifndef OBJ_DONT_REPARSE
#define OBJ_DONT_REPARSE 0x00001000L
#endif

namespace ksword::features::kernel {
namespace {

constexpr LONG kStatusSuccess = 0x00000000L;
constexpr LONG kStatusInfoLengthMismatch = static_cast<LONG>(0xC0000004UL);
constexpr LONG kStatusBufferTooSmall = static_cast<LONG>(0xC0000023UL);
constexpr LONG kStatusBufferOverflow = static_cast<LONG>(0x80000005UL);
constexpr LONG kStatusNoMoreEntries = static_cast<LONG>(0x8000001AUL);
constexpr LONG kStatusNoSuchFile = static_cast<LONG>(0xC000000FUL);
constexpr LONG kStatusUnsuccessful = static_cast<LONG>(0xC0000001UL);
constexpr LONG kStatusInvalidHandle = static_cast<LONG>(0xC0000008UL);
constexpr LONG kStatusAccessDenied = static_cast<LONG>(0xC0000022UL);
constexpr LONG kStatusObjectTypeMismatch = static_cast<LONG>(0xC0000024UL);
constexpr LONG kStatusObjectNameNotFound = static_cast<LONG>(0xC0000034UL);
constexpr LONG kStatusObjectPathNotFound = static_cast<LONG>(0xC000003AUL);
constexpr LONG kStatusNameTooLong = static_cast<LONG>(0xC0000106UL);
constexpr LONG kStatusPipeDisconnected = static_cast<LONG>(0xC00000B0UL);
constexpr LONG kStatusPipeBusy = static_cast<LONG>(0xC00000AEUL);
constexpr LONG kStatusInstanceNotAvailable = static_cast<LONG>(0xC00000ABUL);
constexpr ULONG kObjectBasicInformation = 0;
constexpr ULONG kObjectNameInformation = 1;
constexpr ULONG kObjectTypeInformation = 2;
constexpr ULONG kObjectTypesInformation = 3;
constexpr ULONG kFileDirectoryInformation = 1;
constexpr std::size_t kMaxDirectoryRows = 2500;
constexpr std::size_t kMaxTypeRows = 256;
constexpr std::size_t kMaxExportRows = 512;

using NtOpenDirectoryObjectFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
using NtQueryDirectoryObjectFn = NTSTATUS(NTAPI*)(HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG);
using NtOpenSymbolicLinkObjectFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
using NtQuerySymbolicLinkObjectFn = NTSTATUS(NTAPI*)(HANDLE, PUNICODE_STRING, PULONG);
using NtQueryObjectFn = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtOpenFileFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);
using NtQueryDirectoryFileFn = NTSTATUS(NTAPI*)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG, BOOLEAN, PUNICODE_STRING, BOOLEAN);
using NtQuerySystemInformationFn = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
using NtQueryInformationProcessFn = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtQueryInformationThreadFn = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtQueryInformationTokenFn = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

// KobjectDirectoryInformation is the compact entry returned by
// NtQueryDirectoryObject. Inputs are ntdll-owned counted strings; processing
// copies them immediately into std::wstring before the buffer is reused.
struct KobjectDirectoryInformation {
    UNICODE_STRING name;
    UNICODE_STRING typeName;
};

// KobjectBasicInformation contains the small count fields needed for object
// diagnostics. Input bytes come from NtQueryObject(ObjectBasicInformation);
// output is copied to display text only.
struct KobjectBasicInformation {
    ULONG attributes;
    ACCESS_MASK grantedAccess;
    ULONG handleCount;
    ULONG pointerCount;
    ULONG pagedPoolUsage;
    ULONG nonPagedPoolUsage;
    ULONG reserved[3];
    ULONG nameInfoSize;
    ULONG typeInfoSize;
    ULONG securityDescriptorSize;
    LARGE_INTEGER creationTime;
};

// KobjectTypeInformation mirrors the object type block used by
// NtQueryObject(ObjectTypesInformation). The trailing TypeName buffer is stored
// after this structure and aligned by pointer size.
struct KobjectTypeInformation {
    UNICODE_STRING typeName;
    ULONG totalNumberOfObjects;
    ULONG totalNumberOfHandles;
    ULONG totalPagedPoolUsage;
    ULONG totalNonPagedPoolUsage;
    ULONG totalNamePoolUsage;
    ULONG totalHandleTableUsage;
    ULONG highWaterNumberOfObjects;
    ULONG highWaterNumberOfHandles;
    ULONG highWaterPagedPoolUsage;
    ULONG highWaterNonPagedPoolUsage;
    ULONG highWaterNamePoolUsage;
    ULONG highWaterHandleTableUsage;
    ULONG invalidAttributes;
    GENERIC_MAPPING genericMapping;
    ULONG validAccessMask;
    BOOLEAN securityRequired;
    BOOLEAN maintainHandleCount;
    UCHAR typeIndex;
    CHAR reservedByte;
    ULONG poolType;
    ULONG defaultPagedPoolCharge;
    ULONG defaultNonPagedPoolCharge;
};

// KfileDirectoryInformation is the native directory result used for the
// named-pipe namespace. Input is a byte chain with NextEntryOffset links;
// processing copies names and timestamps into rows.
struct KfileDirectoryInformation {
    ULONG nextEntryOffset;
    ULONG fileIndex;
    LARGE_INTEGER creationTime;
    LARGE_INTEGER lastAccessTime;
    LARGE_INTEGER lastWriteTime;
    LARGE_INTEGER changeTime;
    LARGE_INTEGER endOfFile;
    LARGE_INTEGER allocationSize;
    ULONG fileAttributes;
    ULONG fileNameLength;
    WCHAR fileName[1];
};

// NtRuntime stores all dynamically resolved ntdll calls needed by the native
// kernel pages. Input is the loaded ntdll module; output is a best-effort table
// so individual pages can degrade without crashing.
struct NtRuntime {
    NtOpenDirectoryObjectFn openDirectoryObject = nullptr;
    NtQueryDirectoryObjectFn queryDirectoryObject = nullptr;
    NtOpenSymbolicLinkObjectFn openSymbolicLinkObject = nullptr;
    NtQuerySymbolicLinkObjectFn querySymbolicLinkObject = nullptr;
    NtQueryObjectFn queryObject = nullptr;
    NtOpenFileFn openFile = nullptr;
    NtQueryDirectoryFileFn queryDirectoryFile = nullptr;
    NtQuerySystemInformationFn querySystemInformation = nullptr;
    NtQueryInformationProcessFn queryInformationProcess = nullptr;
    NtQueryInformationThreadFn queryInformationThread = nullptr;
    NtQueryInformationTokenFn queryInformationToken = nullptr;
};

// DirectoryEntry is one object-manager child. Inputs are a parent path plus the
// native name/type; processing derives FullPath and optional symlink target;
// output is converted into KernelResultRow by the query workers.
struct DirectoryEntry {
    std::wstring parentPath;
    std::wstring name;
    std::wstring typeName;
    std::wstring fullPath;
    std::wstring targetPath;
    std::wstring statusText;
    std::wstring handleCountText;
    std::wstring pointerCountText;
    bool canOpen = false;
};

// QueryPacket carries rows and warnings while one worker runs. Inputs are row
// append calls and warning text; processing later turns it into a facade result;
// output is value-only and owns all strings.
struct QueryPacket {
    std::vector<KernelResultRow> rows;
    std::vector<std::wstring> warnings;
};

// makeResult is defined after the directory row helpers, but the Native action
// helpers also need the same result finalizer. This forward declaration keeps
// all R3 Native code inside one translation unit without introducing another
// wrapper file or direct UI dependency.
KernelOperationResult makeResult(KernelFeatureId id, bool success, const std::wstring& operation, QueryPacket&& packet);
std::vector<DirectoryEntry> enumerateDirectoryFlat(const NtRuntime& runtime, const std::wstring& directoryPath, std::vector<std::wstring>& warnings);
void appendDirectoryEntryRow(
    QueryPacket& packet,
    const std::wstring& source,
    std::size_t depth,
    const DirectoryEntry& entry,
    const std::wstring& enumApi = L"NtOpenDirectoryObject + NtQueryDirectoryObject");

// Row builds one generic result row from named columns. Inputs are key/value
// pairs and optional detail text; processing copies all strings; return is the
// common model row used by KernelPage.
KernelResultRow makeResultRow(std::initializer_list<std::pair<std::wstring, std::wstring>> columns, const std::wstring& detail = {}) {
    KernelResultRow row;
    row.columns.assign(columns.begin(), columns.end());
    row.detailText = detail;
    return row;
}

// HexText formats a 64-bit diagnostic integer. Input is an integer value;
// processing uses uppercase hexadecimal; return is display text.
std::wstring hexText(const std::uint64_t value) {
    std::wostringstream stream;
    stream << L"0x" << std::uppercase << std::hex << value;
    return stream.str();
}

// statusText formats NTSTATUS values without losing the original 32-bit code.
// Input is a signed NTSTATUS; return is uppercase hex display text.
std::wstring statusText(const LONG status) {
    return hexText(static_cast<std::uint32_t>(status));
}

// appendFlagText appends a symbolic flag name into a compact "A|B|C" string.
// Inputs are the output text, tested value, one flag and its display name; there
// is no return value because the function mutates the output accumulator.
void appendFlagText(std::wstring& text, const ULONG value, const ULONG flag, const wchar_t* name) {
    if ((value & flag) == 0) {
        return;
    }
    if (!text.empty()) {
        text += L"|";
    }
    text += name;
}

// objectAttributesText converts OBJ_* bits returned by NtQueryObject into
// readable text. Input is the raw Attributes field; return includes unknown bits
// as hex so no diagnostic information is lost.
std::wstring objectAttributesText(const ULONG attributes) {
    std::wstring text;
    appendFlagText(text, attributes, OBJ_INHERIT, L"INHERIT");
    appendFlagText(text, attributes, OBJ_PERMANENT, L"PERMANENT");
    appendFlagText(text, attributes, OBJ_EXCLUSIVE, L"EXCLUSIVE");
    appendFlagText(text, attributes, OBJ_CASE_INSENSITIVE, L"CASE_INSENSITIVE");
    appendFlagText(text, attributes, OBJ_OPENIF, L"OPENIF");
    appendFlagText(text, attributes, OBJ_OPENLINK, L"OPENLINK");
    appendFlagText(text, attributes, OBJ_KERNEL_HANDLE, L"KERNEL_HANDLE");
    appendFlagText(text, attributes, OBJ_FORCE_ACCESS_CHECK, L"FORCE_ACCESS_CHECK");
    appendFlagText(text, attributes, OBJ_IGNORE_IMPERSONATED_DEVICEMAP, L"IGNORE_IMPERSONATED_DEVICEMAP");
    appendFlagText(text, attributes, OBJ_DONT_REPARSE, L"DONT_REPARSE");
    const ULONG kKnown = OBJ_INHERIT
        | OBJ_PERMANENT
        | OBJ_EXCLUSIVE
        | OBJ_CASE_INSENSITIVE
        | OBJ_OPENIF
        | OBJ_OPENLINK
        | OBJ_KERNEL_HANDLE
        | OBJ_FORCE_ACCESS_CHECK
        | OBJ_IGNORE_IMPERSONATED_DEVICEMAP
        | OBJ_DONT_REPARSE;
    const ULONG kUnknown = attributes & ~kKnown;
    if (kUnknown != 0) {
        if (!text.empty()) {
            text += L"|";
        }
        text += L"UNKNOWN(" + hexText(kUnknown) + L")";
    }
    return text.empty() ? L"0" : text;
}

// accessMaskText explains common access-mask bits for native object handles.
// Input is ACCESS_MASK from ObjectBasicInformation; return is a compact
// high-level description plus unknown bits when present.
std::wstring accessMaskText(const ACCESS_MASK access) {
    std::wstring text;
    appendFlagText(text, access, DELETE, L"DELETE");
    appendFlagText(text, access, READ_CONTROL, L"READ_CONTROL");
    appendFlagText(text, access, WRITE_DAC, L"WRITE_DAC");
    appendFlagText(text, access, WRITE_OWNER, L"WRITE_OWNER");
    appendFlagText(text, access, SYNCHRONIZE, L"SYNCHRONIZE");
    appendFlagText(text, access, ACCESS_SYSTEM_SECURITY, L"ACCESS_SYSTEM_SECURITY");
    appendFlagText(text, access, GENERIC_READ, L"GENERIC_READ");
    appendFlagText(text, access, GENERIC_WRITE, L"GENERIC_WRITE");
    appendFlagText(text, access, GENERIC_EXECUTE, L"GENERIC_EXECUTE");
    appendFlagText(text, access, GENERIC_ALL, L"GENERIC_ALL");
    const ULONG kKnown = DELETE
        | READ_CONTROL
        | WRITE_DAC
        | WRITE_OWNER
        | SYNCHRONIZE
        | ACCESS_SYSTEM_SECURITY
        | GENERIC_READ
        | GENERIC_WRITE
        | GENERIC_EXECUTE
        | GENERIC_ALL;
    const ULONG kUnknown = access & ~kKnown;
    if (kUnknown != 0) {
        if (!text.empty()) {
            text += L"|";
        }
        text += L"SPECIFIC(" + hexText(kUnknown) + L")";
    }
    return text.empty() ? L"0" : text;
}

// isSuccessStatus reports whether an NTSTATUS indicates success. Input is the
// native status code; return follows the NT_SUCCESS convention.
bool isSuccessStatus(const LONG status) {
    return status >= 0;
}

// statusMeaningText explains common native status values shown by object and
// pipe actions. Input is one NTSTATUS; return is a short human-readable reason
// while preserving the raw hex in adjacent columns.
std::wstring statusMeaningText(const LONG status) {
    switch (status) {
    case kStatusSuccess: return L"成功";
    case kStatusInfoLengthMismatch: return L"缓冲区长度不匹配";
    case kStatusBufferTooSmall: return L"缓冲区过小";
    case kStatusBufferOverflow: return L"缓冲区溢出/需重试";
    case kStatusNoMoreEntries: return L"没有更多条目";
    case kStatusNoSuchFile: return L"对象/文件不存在";
    case kStatusUnsuccessful: return L"操作失败";
    case kStatusInvalidHandle: return L"句柄无效";
    case kStatusAccessDenied: return L"访问被拒绝";
    case kStatusObjectTypeMismatch: return L"对象类型不匹配";
    case kStatusObjectNameNotFound: return L"对象名不存在";
    case kStatusObjectPathNotFound: return L"对象路径不存在";
    case kStatusNameTooLong: return L"名称过长";
    case kStatusPipeDisconnected: return L"管道已断开";
    case kStatusPipeBusy: return L"管道忙";
    case kStatusInstanceNotAvailable: return L"管道实例不可用";
    default:
        return isSuccessStatus(status) ? L"成功或信息状态" : L"失败/受限";
    }
}

// isRetryStatus reports whether a native query should retry with a larger
// buffer. Input is an NTSTATUS; return is true for common size statuses.
bool isRetryStatus(const LONG status) {
    return status == kStatusInfoLengthMismatch || status == kStatusBufferTooSmall || status == kStatusBufferOverflow;
}

// countedString copies a UNICODE_STRING into std::wstring. Input is the native
// string descriptor; return is empty when the descriptor has no buffer.
std::wstring countedString(const UNICODE_STRING& value) {
    if (!value.Buffer || value.Length == 0) {
        return {};
    }
    return std::wstring(value.Buffer, value.Buffer + (value.Length / sizeof(wchar_t)));
}

// makeUnicodeString creates a temporary UNICODE_STRING view over a std::wstring.
// Input must outlive the call using the returned descriptor; return contains no
// owned memory and is safe for immediate Nt* calls only.
UNICODE_STRING makeUnicodeString(const std::wstring& text) {
    UNICODE_STRING result{};
    result.Buffer = const_cast<PWSTR>(text.c_str());
    result.Length = static_cast<USHORT>(text.size() * sizeof(wchar_t));
    result.MaximumLength = static_cast<USHORT>(result.Length + sizeof(wchar_t));
    return result;
}

// makeObjectAttributes creates case-insensitive object attributes for one
// native path. Inputs are a UNICODE_STRING and optional root handle; output is a
// stack-only OBJECT_ATTRIBUTES value for immediate Nt* calls.
OBJECT_ATTRIBUTES makeObjectAttributes(UNICODE_STRING& name, HANDLE root = nullptr) {
    OBJECT_ATTRIBUTES attributes{};
    attributes.Length = sizeof(attributes);
    attributes.RootDirectory = root;
    attributes.Attributes = OBJ_CASE_INSENSITIVE;
    attributes.ObjectName = &name;
    return attributes;
}

// joinObjectPath combines a directory path with a child name. Inputs are object
// manager path components; processing avoids duplicate separators; return is the
// child full path.
std::wstring joinObjectPath(const std::wstring& directoryPath, const std::wstring& name) {
    if (directoryPath.empty()) {
        return name;
    }
    if (name.empty()) {
        return directoryPath;
    }
    if (directoryPath.back() == L'\\') {
        return directoryPath + name;
    }
    return directoryPath + L"\\" + name;
}

// toLowerCopy normalizes type names for case-insensitive comparisons. Input is
// display text; return is a lower-case copy without modifying the original.
std::wstring toLowerCopy(std::wstring text) {
    std::transform(text.begin(), text.end(), text.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(std::towlower(ch));
    });
    return text;
}

// containsI checks whether text contains a fragment ignoring case. Inputs are
// two strings; return is true when the fragment appears in text.
bool containsI(const std::wstring& text, const std::wstring& fragment) {
    if (fragment.empty()) {
        return true;
    }
    return toLowerCopy(text).find(toLowerCopy(fragment)) != std::wstring::npos;
}

// startsWithI checks whether text starts with a prefix ignoring case. Inputs are
// two strings; return is true when the prefix occupies the beginning of text.
bool startsWithI(const std::wstring& text, const std::wstring& prefix) {
    if (prefix.empty()) {
        return true;
    }
    if (text.size() < prefix.size()) {
        return false;
    }
    return _wcsnicmp(text.c_str(), prefix.c_str(), prefix.size()) == 0;
}

// parseHexOrDecimal converts display numbers such as "0x001F0003" or "123" to
// a native access mask. Input is one cell string; processing accepts hex or
// decimal and rejects partial parses; output is zero when the cell is empty or
// malformed, which keeps detail rendering safe for non-numeric rows.
ACCESS_MASK parseHexOrDecimal(const std::wstring& text) {
    if (text.empty()) {
        return 0;
    }
    wchar_t* end = nullptr;
    const int kBase = startsWithI(text, L"0x") ? 16 : 10;
    const unsigned long kValue = std::wcstoul(text.c_str(), &end, kBase);
    if (end == text.c_str() || (end != nullptr && *end != L'\0')) {
        return 0;
    }
    return static_cast<ACCESS_MASK>(kValue);
}

// joinStrings joins short display fragments with one separator. Inputs are
// already formatted fragments; return is empty when there are no fragments.
std::wstring joinStrings(const std::vector<std::wstring>& values, const std::wstring& separator) {
    std::wstring result;
    for (const std::wstring& value : values) {
        if (value.empty()) {
            continue;
        }
        if (!result.empty()) {
            result += separator;
        }
        result += value;
    }
    return result;
}

// dosPathCandidatesFromNtPath mirrors the original KernelSymbolicLinkWorker
// helper: it maps \Device\... targets back to visible DOS drive candidates with
// QueryDosDeviceW. Input is one NT target path; return is a de-duplicated list.
std::vector<std::wstring> dosPathCandidatesFromNtPath(const std::wstring& ntPath) {
    std::vector<std::wstring> candidates;
    if (!startsWithI(ntPath, L"\\Device\\")) {
        return candidates;
    }

    for (wchar_t drive = L'A'; drive <= L'Z'; ++drive) {
        wchar_t driveName[3]{ drive, L':', L'\0' };
        wchar_t mappingBuffer[4096]{};
        const DWORD kMappingLength = ::QueryDosDeviceW(driveName, mappingBuffer, static_cast<DWORD>(_countof(mappingBuffer)));
        if (kMappingLength == 0) {
            continue;
        }

        const wchar_t* cursor = mappingBuffer;
        while (*cursor != L'\0') {
            const std::wstring kMapping(cursor);
            if (!kMapping.empty() && startsWithI(ntPath, kMapping)) {
                std::wstring candidate(driveName);
                const std::wstring kSuffix = ntPath.substr(kMapping.size());
                candidate += kSuffix.empty() ? L"\\" : kSuffix;
                const bool kDuplicate = std::any_of(candidates.begin(), candidates.end(), [&](const std::wstring& existing) {
                    return _wcsicmp(existing.c_str(), candidate.c_str()) == 0;
                });
                if (!kDuplicate) {
                    candidates.push_back(std::move(candidate));
                }
            }
            cursor += std::wcslen(cursor) + 1;
        }
    }
    return candidates;
}

// joinStrings joins a short list for display/filter matching. Inputs are copied
// strings and a separator; processing is linear and side-effect free; output is
// empty when there are no values.
std::wstring joinStrings(const std::vector<std::wstring>& values, const wchar_t* separator) {
    std::wstring joined;
    for (const std::wstring& value : values) {
        if (value.empty()) {
            continue;
        }
        if (!joined.empty()) {
            joined += separator;
        }
        joined += value;
    }
    return joined;
}

// matchesDirectoryFilter checks all meaningful object row fields against the
// user's filter. Inputs are one object-manager entry and a filter string;
// processing is case-insensitive; return controls whether the row is displayed.
bool matchesDirectoryFilter(const DirectoryEntry& entry, const std::wstring& filter) {
    if (filter.empty()) {
        return true;
    }
    return containsI(entry.parentPath, filter)
        || containsI(entry.name, filter)
        || containsI(entry.typeName, filter)
        || containsI(entry.fullPath, filter)
        || containsI(entry.targetPath, filter)
        || containsI(entry.statusText, filter);
}

// matchesColumnsFilter checks generic key/value columns against user text.
// Inputs are a generic row and filter string; return is true when any key,
// value, or detail field matches case-insensitively.
bool matchesColumnsFilter(const KernelResultRow& row, const std::wstring& filter) {
    if (filter.empty()) {
        return true;
    }
    if (containsI(row.detailText, filter)) {
        return true;
    }
    for (const auto& column : row.columns) {
        if (containsI(column.first, filter) || containsI(column.second, filter)) {
            return true;
        }
    }
    return false;
}

// fieldValue extracts one selected-row field from an action packet. Inputs are
// the text fields copied by KernelPage and the desired key; output is empty when
// the current row does not expose the requested column.
std::wstring fieldValue(const KernelActionRequest& request, const std::wstring& key) {
    for (const auto& field : request.rowFields) {
        if (_wcsicmp(field.first.c_str(), key.c_str()) == 0) {
            return field.second;
        }
    }
    return {};
}

// firstNonEmpty returns the first non-empty string from a short candidate list.
// Inputs are already-normalized display strings; output is the preferred value
// used to resolve object paths from heterogeneous KernelResultRow layouts.
std::wstring firstNonEmpty(std::initializer_list<std::wstring> values) {
    for (const std::wstring& value : values) {
        if (!value.empty()) {
            return value;
        }
    }
    return {};
}

// nativePathFromAction resolves a native object path from the selected row. The
// input may be a generic object row, symbolic-link row, named-pipe row, or
// fallback filter text; output is empty only when no usable path is available.
std::wstring nativePathFromAction(const KernelActionRequest& request) {
    const std::wstring kDirect = firstNonEmpty({
        fieldValue(request, L"Path"),
        fieldValue(request, L"NtPath"),
        fieldValue(request, L"fullPath"),
        fieldValue(request, L"FullPath"),
        fieldValue(request, L"完整路径"),
        fieldValue(request, L"NT Path"),
        fieldValue(request, L"targetPath"),
        fieldValue(request, L"symbolicTarget"),
        fieldValue(request, L"目标路径"),
        fieldValue(request, L"符号链接目标"),
        fieldValue(request, L"Directory"),
        fieldValue(request, L"directoryPath"),
        fieldValue(request, L"sourceDirectory"),
        fieldValue(request, L"目录路径"),
        fieldValue(request, L"来源目录"),
        request.filterText,
    });
    if (!kDirect.empty()) {
        return kDirect;
    }
    const std::wstring kParent = fieldValue(request, L"Parent");
    const std::wstring kName = firstNonEmpty({
        fieldValue(request, L"Name"),
        fieldValue(request, L"objectName"),
        fieldValue(request, L"linkName"),
        fieldValue(request, L"对象名称"),
        fieldValue(request, L"名称"),
        fieldValue(request, L"Pipe"),
        fieldValue(request, L"Pipe Name"),
    });
    return joinObjectPath(kParent, kName);
}

// objectTypeNameFromAction resolves a type name from ObjectTypeMatrix and other
// object-result rows. Inputs are selected-row fields copied by KernelPage; the
// return value is empty only when no type-like cell exists.
std::wstring objectTypeNameFromAction(const KernelActionRequest& request) {
    return firstNonEmpty({
        fieldValue(request, L"Type"),
        fieldValue(request, L"TypeName"),
        fieldValue(request, L"ObjectType"),
        fieldValue(request, L"objectType"),
        fieldValue(request, L"对象类型"),
        fieldValue(request, L"类型"),
        fieldValue(request, L"类型名"),
    });
}

// appendObjectTypeDetailRow renders an ObjectTypeMatrix row as a first-class
// detail result. Inputs are the selected action request, resolved type name and
// packet; processing copies count/access-mask fields without opening an object;
// no value is returned because the row is appended to the packet.
void appendObjectTypeDetailRow(const KernelActionRequest& request, const std::wstring& type, QueryPacket& packet) {
    packet.rows.push_back(makeResultRow({
        { L"Action", L"NativeObjectTypeDetail" },
        { L"Type", type },
        { L"TypeIndex", fieldValue(request, L"TypeIndex") },
        { L"Objects", fieldValue(request, L"Objects") },
        { L"Handles", fieldValue(request, L"Handles") },
        { L"HighObjects", fieldValue(request, L"HighObjects") },
        { L"HighHandles", fieldValue(request, L"HighHandles") },
        { L"ValidAccess", fieldValue(request, L"ValidAccess") },
        { L"ValidAccessText", accessMaskText(parseHexOrDecimal(fieldValue(request, L"ValidAccess"))) },
        { L"GenericRead", fieldValue(request, L"GenericRead") },
        { L"GenericWrite", fieldValue(request, L"GenericWrite") },
        { L"GenericExecute", fieldValue(request, L"GenericExecute") },
        { L"GenericAll", fieldValue(request, L"GenericAll") },
        { L"SecurityRequired", fieldValue(request, L"SecurityRequired") },
        { L"MaintainHandleCount", fieldValue(request, L"MaintainHandleCount") },
        { L"PoolType", fieldValue(request, L"PoolType") },
        { L"Strategy", type == L"SymbolicLink"
            ? L"NtOpenSymbolicLinkObject + NtQuerySymbolicLinkObject"
            : (type.find(L"Port") != std::wstring::npos ? L"对象目录枚举 + R3 对象详情" : L"对象类型统计；具体对象需从对象目录页打开") },
        { L"Status", L"对象类型矩阵行详情" },
    }, L"对象类型矩阵行不对应单一对象路径，因此展示类型统计与访问掩码。"));
}

// makeNativeActionResult creates the common result packet for R3 Native row
// actions. Inputs are the action request, success flag, operation text, and
// accumulated rows/warnings; output is the same grid model used by queries.
KernelOperationResult makeNativeActionResult(const KernelActionRequest& request, const bool success, const std::wstring& operation, QueryPacket&& packet) {
    KernelOperationResult result = makeResult(request.featureId, success, operation, std::move(packet));
    result.destructiveAction = false;
    return result;
}

// appendObjectBasicInfoRow queries NtQueryObject(ObjectBasicInformation) for an
// opened object handle. Inputs are runtime, object path, handle and open status;
// processing appends a row even when the open failed so the UI shows the exact
// status rather than silently doing nothing.
void appendObjectBasicInfoRow(QueryPacket& packet, const NtRuntime& runtime, const std::wstring& path, HANDLE handle, const LONG openStatus) {
    KobjectBasicInformation basic{};
    ULONG returned = 0;
    LONG queryStatus = kStatusNoSuchFile;
    if (handle && runtime.queryObject) {
        queryStatus = runtime.queryObject(handle, kObjectBasicInformation, &basic, static_cast<ULONG>(sizeof(basic)), &returned);
    }
    const bool kHasBasic = handle && runtime.queryObject && isSuccessStatus(queryStatus);

    packet.rows.push_back(makeResultRow({
        { L"Action", L"NativeObjectQueryDetail" },
        { L"Path", path },
        { L"OpenStatus", statusText(openStatus) },
        { L"OpenStatusText", statusMeaningText(openStatus) },
        { L"QueryStatus", runtime.queryObject ? statusText(queryStatus) : L"NtQueryObject unavailable" },
        { L"QueryStatusText", runtime.queryObject ? statusMeaningText(queryStatus) : L"NtQueryObject 未解析" },
        { L"QueryReturned", std::to_wstring(returned) },
        { L"Attributes", kHasBasic ? hexText(basic.attributes) : L"" },
        { L"AttributesText", kHasBasic ? objectAttributesText(basic.attributes) : L"" },
        { L"GrantedAccess", kHasBasic ? hexText(basic.grantedAccess) : L"" },
        { L"GrantedAccessText", kHasBasic ? accessMaskText(basic.grantedAccess) : L"" },
        { L"Handles", kHasBasic ? std::to_wstring(basic.handleCount) : L"" },
        { L"Pointers", kHasBasic ? std::to_wstring(basic.pointerCount) : L"" },
        { L"PagedPool", kHasBasic ? std::to_wstring(basic.pagedPoolUsage) : L"" },
        { L"NonPagedPool", kHasBasic ? std::to_wstring(basic.nonPagedPoolUsage) : L"" },
        { L"NameInfoSize", kHasBasic ? std::to_wstring(basic.nameInfoSize) : L"" },
        { L"TypeInfoSize", kHasBasic ? std::to_wstring(basic.typeInfoSize) : L"" },
        { L"SecurityDescriptorSize", kHasBasic ? std::to_wstring(basic.securityDescriptorSize) : L"" },
        { L"Status", kHasBasic ? L"已打开并读取对象基础信息" : L"未能读取对象基础信息" },
    }, kHasBasic ? accessMaskText(basic.grantedAccess) : statusMeaningText(openStatus)));
}

// appendQueriedObjectText asks NtQueryObject for name/type information. Inputs
// are an opened object handle and info class; processing uses the growable query
// helper shape manually because this file keeps Native actions local; output is
// one detail row when the query is available.
void appendQueriedObjectText(QueryPacket& packet, const NtRuntime& runtime, HANDLE handle, const ULONG infoClass, const std::wstring& label) {
    if (!runtime.queryObject || !handle) {
        return;
    }
    ULONG bufferSize = 4096;
    std::vector<std::byte> buffer;
    LONG status = kStatusInfoLengthMismatch;
    ULONG returned = 0;
    for (int attempt = 0; attempt < 5; ++attempt) {
        buffer.assign(bufferSize, std::byte{});
        returned = 0;
        status = runtime.queryObject(handle, infoClass, buffer.data(), bufferSize, &returned);
        if (isSuccessStatus(status) || !isRetryStatus(status)) {
            break;
        }
        bufferSize = std::max<ULONG>(bufferSize * 2, returned + 0x1000);
    }
    std::wstring value;
    if (isSuccessStatus(status) && buffer.size() >= sizeof(UNICODE_STRING)) {
        const auto* counted = reinterpret_cast<const UNICODE_STRING*>(buffer.data());
        value = countedString(*counted);
    }
    packet.rows.push_back(makeResultRow({
        { L"Action", L"NtQueryObject" },
        { L"InfoClass", std::to_wstring(infoClass) },
        { L"Field", label },
        { L"Status", statusText(status) },
        { L"Bytes", std::to_wstring(buffer.size()) },
        { L"Returned", std::to_wstring(returned) },
        { L"Value", value },
    }, value));
}

// Runtime loads ntdll exports lazily. Inputs are none; processing resolves each
// symbol by name; return is a cached function table.
const NtRuntime& ntRuntime() {
    static NtRuntime runtime = [] {
        NtRuntime result{};
        HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) {
            ntdll = ::LoadLibraryW(L"ntdll.dll");
        }
        if (!ntdll) {
            return result;
        }
        result.openDirectoryObject = reinterpret_cast<NtOpenDirectoryObjectFn>(::GetProcAddress(ntdll, "NtOpenDirectoryObject"));
        result.queryDirectoryObject = reinterpret_cast<NtQueryDirectoryObjectFn>(::GetProcAddress(ntdll, "NtQueryDirectoryObject"));
        result.openSymbolicLinkObject = reinterpret_cast<NtOpenSymbolicLinkObjectFn>(::GetProcAddress(ntdll, "NtOpenSymbolicLinkObject"));
        result.querySymbolicLinkObject = reinterpret_cast<NtQuerySymbolicLinkObjectFn>(::GetProcAddress(ntdll, "NtQuerySymbolicLinkObject"));
        result.queryObject = reinterpret_cast<NtQueryObjectFn>(::GetProcAddress(ntdll, "NtQueryObject"));
        result.openFile = reinterpret_cast<NtOpenFileFn>(::GetProcAddress(ntdll, "NtOpenFile"));
        result.queryDirectoryFile = reinterpret_cast<NtQueryDirectoryFileFn>(::GetProcAddress(ntdll, "NtQueryDirectoryFile"));
        result.querySystemInformation = reinterpret_cast<NtQuerySystemInformationFn>(::GetProcAddress(ntdll, "NtQuerySystemInformation"));
        result.queryInformationProcess = reinterpret_cast<NtQueryInformationProcessFn>(::GetProcAddress(ntdll, "NtQueryInformationProcess"));
        result.queryInformationThread = reinterpret_cast<NtQueryInformationThreadFn>(::GetProcAddress(ntdll, "NtQueryInformationThread"));
        result.queryInformationToken = reinterpret_cast<NtQueryInformationTokenFn>(::GetProcAddress(ntdll, "NtQueryInformationToken"));
        return result;
    }();
    return runtime;
}

// openDirectory opens an object-manager directory. Input is a native path such
// as \Device; processing calls NtOpenDirectoryObject; return is a handle that
// the caller must close or null on failure.
HANDLE openDirectory(const NtRuntime& runtime, const std::wstring& path, LONG* statusOut = nullptr) {
    if (!runtime.openDirectoryObject || path.empty()) {
        if (statusOut) {
            *statusOut = kStatusNoSuchFile;
        }
        return nullptr;
    }

    UNICODE_STRING unicodePath = makeUnicodeString(path);
    OBJECT_ATTRIBUTES attributes = makeObjectAttributes(unicodePath);
    HANDLE handle = nullptr;
    const LONG kStatus = runtime.openDirectoryObject(&handle, DIRECTORY_QUERY, &attributes);
    if (statusOut) {
        *statusOut = kStatus;
    }
    return isSuccessStatus(kStatus) ? handle : nullptr;
}

// openSymbolicLink opens one object-manager symbolic link. Input is a native
// link path; processing calls NtOpenSymbolicLinkObject; return is a closeable
// handle or null on failure.
HANDLE openSymbolicLink(const NtRuntime& runtime, const std::wstring& path, LONG* statusOut = nullptr) {
    if (!runtime.openSymbolicLinkObject || path.empty()) {
        if (statusOut) {
            *statusOut = kStatusNoSuchFile;
        }
        return nullptr;
    }

    UNICODE_STRING unicodePath = makeUnicodeString(path);
    OBJECT_ATTRIBUTES attributes = makeObjectAttributes(unicodePath);
    HANDLE handle = nullptr;
    const LONG kStatus = runtime.openSymbolicLinkObject(&handle, SYMBOLIC_LINK_QUERY, &attributes);
    if (statusOut) {
        *statusOut = kStatus;
    }
    return isSuccessStatus(kStatus) ? handle : nullptr;
}

// querySymbolicLinkTarget reads a symbolic-link target. Input is an opened link
// handle; processing calls NtQuerySymbolicLinkObject; return is empty on error.
std::wstring querySymbolicLinkTarget(const NtRuntime& runtime, HANDLE link) {
    if (!runtime.querySymbolicLinkObject || !link) {
        return {};
    }

    std::vector<wchar_t> buffer(2048, L'\0');
    UNICODE_STRING target{};
    target.Buffer = buffer.data();
    target.MaximumLength = static_cast<USHORT>(buffer.size() * sizeof(wchar_t));
    const LONG kStatus = runtime.querySymbolicLinkObject(link, &target, nullptr);
    if (!isSuccessStatus(kStatus)) {
        return {};
    }
    return countedString(target);
}

// queryBasicObjectCounts reads handle and pointer counts from any object handle.
// Inputs are runtime and object handle; processing calls NtQueryObject; output
// strings stay empty when the object does not allow the query.
void queryBasicObjectCounts(const NtRuntime& runtime, HANDLE handle, std::wstring& handleCountText, std::wstring& pointerCountText) {
    if (!runtime.queryObject || !handle) {
        return;
    }

    KobjectBasicInformation basic{};
    ULONG returned = 0;
    const LONG kStatus = runtime.queryObject(handle, kObjectBasicInformation, &basic, static_cast<ULONG>(sizeof(basic)), &returned);
    if (!isSuccessStatus(kStatus)) {
        return;
    }
    handleCountText = std::to_wstring(basic.handleCount);
    pointerCountText = std::to_wstring(basic.pointerCount);
}

// openNamedPipeReadOnly opens a named pipe namespace entry without reading or
// writing payload data. Inputs are runtime and native pipe path; processing uses
// NtOpenFile with FILE_READ_ATTRIBUTES|SYNCHRONIZE; return is a closeable handle
// or null while statusOut/ioStatusOut carry the exact native result.
HANDLE openNamedPipeReadOnly(const NtRuntime& runtime, const std::wstring& path, LONG* statusOut, IO_STATUS_BLOCK* ioStatusOut) {
    if (!runtime.openFile || path.empty()) {
        if (statusOut) {
            *statusOut = kStatusNoSuchFile;
        }
        if (ioStatusOut) {
            *ioStatusOut = {};
        }
        return nullptr;
    }

    UNICODE_STRING unicodePath = makeUnicodeString(path);
    OBJECT_ATTRIBUTES attributes = makeObjectAttributes(unicodePath);
    IO_STATUS_BLOCK localIoStatus{};
    HANDLE pipe = nullptr;
    const LONG kOpenStatus = runtime.openFile(
        &pipe,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &attributes,
        &localIoStatus,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_SYNCHRONOUS_IO_NONALERT);
    if (statusOut) {
        *statusOut = kOpenStatus;
    }
    if (ioStatusOut) {
        *ioStatusOut = localIoStatus;
    }
    return isSuccessStatus(kOpenStatus) ? pipe : nullptr;
}

// appendDirectoryPreviewRows adds a small, live child preview for an opened
// object directory. Inputs are a native path and row limit; processing reuses the
// one-level directory enumerator; output rows make the right-click details page
// actionable without forcing the full recursive tab.
void appendDirectoryPreviewRows(QueryPacket& packet, const NtRuntime& runtime, const std::wstring& path, const std::size_t limit) {
    std::vector<std::wstring> warnings;
    const std::vector<DirectoryEntry> kEntries = enumerateDirectoryFlat(runtime, path, warnings);
    packet.rows.push_back(makeResultRow({
        { L"Action", L"NativeDirectoryPreview" },
        { L"Path", path },
        { L"Children", std::to_wstring(kEntries.size()) },
        { L"PreviewLimit", std::to_wstring(limit) },
        { L"Warnings", std::to_wstring(warnings.size()) },
        { L"Status", kEntries.empty() ? L"无可显示子项或访问受限" : L"已读取目录子项预览" },
    }));
    for (const std::wstring& warning : warnings) {
        packet.warnings.push_back(warning);
    }
    std::size_t added = 0;
    for (const DirectoryEntry& entry : kEntries) {
        if (added >= limit) {
            break;
        }
        appendDirectoryEntryRow(packet, L"DetailPreview", 0, entry);
        ++added;
    }
}

// directoryStatusText explains one object-manager row. Inputs are type and
// query state; return is compact display text for the status/details column.
std::wstring directoryStatusText(const std::wstring& typeName, const bool canOpen, const bool hasTarget) {
    if (typeName == L"Directory") {
        return canOpen ? L"目录，可继续展开" : L"目录，当前权限无法打开";
    }
    if (typeName == L"SymbolicLink") {
        return hasTarget ? L"符号链接，已解析目标" : L"符号链接，目标未解析";
    }
    return canOpen ? L"对象可打开" : L"叶子对象或权限受限";
}

// enumerateDirectoryFlat returns one level of object-manager children. Inputs
// are runtime, directory path and warning sink; processing loops
// NtQueryDirectoryObject; return is a vector of copied entries.
std::vector<DirectoryEntry> enumerateDirectoryFlat(const NtRuntime& runtime, const std::wstring& directoryPath, std::vector<std::wstring>& warnings) {
    std::vector<DirectoryEntry> entries;
    if (!runtime.openDirectoryObject || !runtime.queryDirectoryObject) {
        warnings.push_back(L"NtOpenDirectoryObject/NtQueryDirectoryObject 不可用。");
        return entries;
    }

    LONG openStatus = 0;
    HANDLE directory = openDirectory(runtime, directoryPath, &openStatus);
    if (!directory) {
        warnings.push_back(std::wstring(L"无法打开对象目录 ") + directoryPath + L"，NTSTATUS=" + statusText(openStatus));
        return entries;
    }

    std::vector<std::byte> buffer(64 * 1024);
    ULONG context = 0;
    BOOLEAN restart = TRUE;
    for (;;) {
        ULONG returned = 0;
        const LONG kStatus = runtime.queryDirectoryObject(
            directory,
            buffer.data(),
            static_cast<ULONG>(buffer.size()),
            TRUE,
            restart,
            &context,
            &returned);
        restart = FALSE;
        if (kStatus == kStatusNoMoreEntries) {
            break;
        }
        if (!isSuccessStatus(kStatus)) {
            warnings.push_back(std::wstring(L"查询对象目录失败 ") + directoryPath + L"，NTSTATUS=" + statusText(kStatus));
            break;
        }

        const auto* nativeEntry = reinterpret_cast<const KobjectDirectoryInformation*>(buffer.data());
        const std::wstring kName = countedString(nativeEntry->name);
        if (kName.empty()) {
            continue;
        }

        DirectoryEntry entry;
        entry.parentPath = directoryPath;
        entry.name = kName;
        entry.typeName = countedString(nativeEntry->typeName);
        if (entry.typeName.empty()) {
            entry.typeName = L"<unknown>";
        }
        entry.fullPath = joinObjectPath(directoryPath, entry.name);

        if (entry.typeName == L"Directory") {
            LONG childStatus = 0;
            HANDLE child = openDirectory(runtime, entry.fullPath, &childStatus);
            if (child) {
                entry.canOpen = true;
                queryBasicObjectCounts(runtime, child, entry.handleCountText, entry.pointerCountText);
                ::CloseHandle(child);
            }
        } else if (entry.typeName == L"SymbolicLink") {
            LONG linkStatus = 0;
            HANDLE link = openSymbolicLink(runtime, entry.fullPath, &linkStatus);
            if (link) {
                entry.canOpen = true;
                queryBasicObjectCounts(runtime, link, entry.handleCountText, entry.pointerCountText);
                entry.targetPath = querySymbolicLinkTarget(runtime, link);
                ::CloseHandle(link);
            }
        }

        if (entry.handleCountText.empty()) {
            entry.handleCountText = L"N/A";
        }
        if (entry.pointerCountText.empty()) {
            entry.pointerCountText = L"N/A";
        }
        entry.statusText = directoryStatusText(entry.typeName, entry.canOpen, !entry.targetPath.empty());
        entries.push_back(std::move(entry));
    }

    ::CloseHandle(directory);
    return entries;
}

// appendDirectoryEntryRow converts one object-manager entry into a generic row.
// Inputs are a source label, depth, object entry, and enumApi text; processing
// formats the original KernelDock tree metadata plus copyable enumeration API
// text; output is appended to the query packet with no return value.
void appendDirectoryEntryRow(
    QueryPacket& packet,
    const std::wstring& source,
    const std::size_t depth,
    const DirectoryEntry& entry,
    const std::wstring& enumApi) {
    packet.rows.push_back(makeResultRow({
        { L"Source", source },
        { L"EnumApi", enumApi },
        { L"enumApi", enumApi },
        { L"枚举 API", enumApi },
        { L"Depth", std::to_wstring(depth) },
        { L"Parent", entry.parentPath },
        { L"Directory", entry.parentPath },
        { L"directoryPath", entry.parentPath },
        { L"sourceDirectory", entry.parentPath },
        { L"Name", entry.name },
        { L"objectName", entry.name },
        { L"linkName", entry.name },
        { L"Type", entry.typeName },
        { L"objectType", entry.typeName },
        { L"Path", entry.fullPath },
        { L"fullPath", entry.fullPath },
        { L"Target", entry.targetPath.empty() ? L"" : entry.targetPath },
        { L"targetPath", entry.targetPath.empty() ? L"" : entry.targetPath },
        { L"symbolicTarget", entry.targetPath.empty() ? L"" : entry.targetPath },
        { L"dosCandidate", entry.targetPath.empty() ? L"" : joinStrings(dosPathCandidatesFromNtPath(entry.targetPath), L"; ") },
        { L"Win32Path", entry.targetPath.empty() ? L"" : joinStrings(dosPathCandidatesFromNtPath(entry.targetPath), L"; ") },
        { L"Handles", entry.handleCountText },
        { L"Pointers", entry.pointerCountText },
        { L"Status", entry.statusText },
        { L"statusText", entry.statusText },
    }, entry.targetPath.empty() ? entry.statusText : entry.targetPath));
}

// makeResult finalizes a worker packet. Inputs are feature id, success state,
// operation message and packet data; output is the facade result consumed by UI.
KernelOperationResult makeResult(KernelFeatureId id, const bool success, const std::wstring& operation, QueryPacket&& packet) {
    KernelOperationResult result;
    result.supported = true;
    result.success = success;
    result.message = operation + (success ? L" 完成。" : L" 未完整完成。");
    if (!packet.warnings.empty()) {
        result.message += L" ";
        for (const std::wstring& warning : packet.warnings) {
            result.message += warning;
            result.message += L" ";
        }
    }
    for (KernelResultRow& row : packet.rows) {
        result.rows.push_back(std::move(row));
    }
    for (const std::wstring& warning : packet.warnings) {
        result.rows.push_back(makeResultRow({
            { L"Warning", warning },
        }, warning));
    }
    return result;
}

// appendDirectoryRoot appends all direct children under one root. Inputs are a
// root path and source label; processing calls enumerateDirectoryFlat; no value
// is returned because rows/warnings are accumulated in packet.
void appendDirectoryRoot(QueryPacket& packet, const NtRuntime& runtime, const std::wstring& root, const std::wstring& source, const std::wstring& filter) {
    const std::vector<DirectoryEntry> kEntries = enumerateDirectoryFlat(runtime, root, packet.warnings);
    if (kEntries.empty()) {
        if (filter.empty() || containsI(root, filter)) {
            packet.rows.push_back(makeResultRow({
                { L"Source", source },
                { L"Path", root },
                { L"Status", L"无可显示子项或访问受限" },
            }));
        }
        return;
    }
    for (const DirectoryEntry& entry : kEntries) {
        if (matchesDirectoryFilter(entry, filter)) {
            appendDirectoryEntryRow(packet, source, 0, entry);
        }
    }
}

// commonNamespaceRoots returns object-manager roots used by multiple pages.
// Input is none; return is an ordered list of readable high-value directories.
std::vector<DWORD> discoverSessionIds(const NtRuntime& runtime) {
    // discoverSessionIds mirrors the original BaseNamedObjects worker by
    // enumerating numeric children under \Sessions. Inputs are the resolved NT
    // runtime; processing also includes the current process session and session
    // 0; output is de-duplicated and sorted for stable UI order.
    DWORD currentSessionId = 0;
    ::ProcessIdToSessionId(::GetCurrentProcessId(), &currentSessionId);
    std::vector<DWORD> sessions{ 0, currentSessionId };
    std::vector<std::wstring> warnings;
    const std::vector<DirectoryEntry> kEntries = enumerateDirectoryFlat(runtime, L"\\Sessions", warnings);
    for (const DirectoryEntry& entry : kEntries) {
        wchar_t* end = nullptr;
        const unsigned long kValue = std::wcstoul(entry.name.c_str(), &end, 10);
        if (end != entry.name.c_str() && *end == L'\0') {
            sessions.push_back(static_cast<DWORD>(kValue));
        }
    }
    std::sort(sessions.begin(), sessions.end());
    sessions.erase(std::unique(sessions.begin(), sessions.end()), sessions.end());
    return sessions;
}

std::vector<std::wstring> commonNamespaceRoots() {
    const NtRuntime& runtime = ntRuntime();
    std::vector<std::wstring> roots{
        L"\\",
        L"\\Device",
        L"\\Driver",
        L"\\FileSystem",
        L"\\FileSystem\\Filters",
        L"\\BaseNamedObjects",
        L"\\RPC Control",
        L"\\Callback",
        L"\\KernelObjects",
        L"\\KnownDlls",
        L"\\KnownDlls32",
        L"\\Nls",
        L"\\ObjectTypes",
        L"\\Security",
        L"\\Sessions",
    };
    for (const DWORD kSessionId : discoverSessionIds(runtime)) {
        const std::wstring kPrefix = std::wstring(L"\\Sessions\\") + std::to_wstring(kSessionId);
        roots.push_back(kPrefix + L"\\BaseNamedObjects");
        roots.push_back(kPrefix + L"\\DosDevices");
        roots.push_back(kPrefix + L"\\Windows");
    }
    std::sort(roots.begin(), roots.end());
    roots.erase(std::unique(roots.begin(), roots.end()), roots.end());
    return roots;
}

// queryObjectNamespaceOverview implements the first object namespace page.
// Input is the request; processing enumerates key object directories one level;
// return contains live R3 namespace rows.
KernelOperationResult queryObjectNamespaceOverview(const KernelRequest& request) {
    const NtRuntime& runtime = ntRuntime();
    QueryPacket packet;
    for (const std::wstring& root : commonNamespaceRoots()) {
        appendDirectoryRoot(packet, runtime, root, root, request.filterText);
    }
    return makeResult(request.featureId, !packet.rows.empty(), L"对象命名空间枚举", std::move(packet));
}

// queryObjectDirectoryRecursive implements bounded recursive namespace walking.
// Input is the request filter as optional start path; processing BFS-enumerates
// directories with caps to keep the UI responsive; return contains tree rows.
KernelOperationResult queryObjectDirectoryRecursive(const KernelRequest& request) {
    const NtRuntime& runtime = ntRuntime();
    QueryPacket packet;
    const bool kFilterLooksLikePath = !request.filterText.empty() && request.filterText.front() == L'\\';
    const std::wstring kStartPath = kFilterLooksLikePath ? request.filterText : L"\\";
    const std::wstring kRowFilter = kFilterLooksLikePath ? std::wstring{} : request.filterText;
    std::size_t maxDepth = 4;
    if (!request.moduleFilterText.empty()) {
        wchar_t* end = nullptr;
        const unsigned long kParsed = std::wcstoul(request.moduleFilterText.c_str(), &end, 10);
        if (end != request.moduleFilterText.c_str()) {
            maxDepth = std::min<std::size_t>(32, kParsed);
        }
    }
    struct WorkItem {
        std::wstring path;
        std::size_t depth = 0;
    };

    std::deque<WorkItem> queue;
    std::set<std::wstring> visited;
    std::size_t scannedRows = 0;
    queue.push_back({ kStartPath, 0 });
    visited.insert(toLowerCopy(kStartPath));

    while (!queue.empty() && packet.rows.size() < kMaxDirectoryRows && scannedRows < kMaxDirectoryRows * 4) {
        const WorkItem kItem = queue.front();
        queue.pop_front();
        const std::vector<DirectoryEntry> kEntries = enumerateDirectoryFlat(runtime, kItem.path, packet.warnings);
        for (const DirectoryEntry& entry : kEntries) {
            ++scannedRows;
            if (matchesDirectoryFilter(entry, kRowFilter)) {
                appendDirectoryEntryRow(packet, L"Recursive", kItem.depth, entry);
            }
            if (entry.typeName == L"Directory" && kItem.depth < maxDepth && packet.rows.size() < kMaxDirectoryRows && scannedRows < kMaxDirectoryRows * 4) {
                const std::wstring kKey = toLowerCopy(entry.fullPath);
                if (visited.insert(kKey).second) {
                    queue.push_back({ entry.fullPath, kItem.depth + 1 });
                }
            }
        }
    }

    if (!queue.empty() || scannedRows >= kMaxDirectoryRows * 4) {
        packet.warnings.push_back(std::wstring(L"目录递归达到显示上限 ") + std::to_wstring(kMaxDirectoryRows) + L" 行，已截断。可在“过滤/起点”输入框指定更小的对象目录。");
    }
    return makeResult(request.featureId, !packet.rows.empty(), L"对象目录递归", std::move(packet));
}

// querySymbolicLinks enumerates common directories and resolves link targets.
// Input is the request; processing filters object rows by SymbolicLink type;
// return contains source path and target text.
KernelOperationResult querySymbolicLinks(const KernelRequest& request) {
    const NtRuntime& runtime = ntRuntime();
    QueryPacket packet;
    for (const std::wstring& root : commonNamespaceRoots()) {
        const std::vector<DirectoryEntry> kEntries = enumerateDirectoryFlat(runtime, root, packet.warnings);
        for (const DirectoryEntry& entry : kEntries) {
            const bool kTargetMatched = request.moduleFilterText.empty() ||
                containsI(entry.targetPath, request.moduleFilterText) ||
                containsI(joinStrings(dosPathCandidatesFromNtPath(entry.targetPath), L"; "), request.moduleFilterText);
            if (entry.typeName == L"SymbolicLink" && matchesDirectoryFilter(entry, request.filterText) && kTargetMatched) {
                appendDirectoryEntryRow(packet, root, 0, entry);
            }
        }
    }
    return makeResult(request.featureId, !packet.rows.empty(), L"符号链接解析", std::move(packet));
}

// queryDeviceDriverObjects enumerates object-manager device/driver roots. Input
// is the request; processing is R3-only and does not call DeviceIoControl;
// return contains Device/Driver/FileSystem object rows.
KernelOperationResult queryDeviceDriverObjects(const KernelRequest& request) {
    const NtRuntime& runtime = ntRuntime();
    QueryPacket packet;
    const std::array<std::wstring, 4> kRoots{
        L"\\Device",
        L"\\Driver",
        L"\\FileSystem",
        L"\\FileSystem\\Filters",
    };
    for (const std::wstring& root : kRoots) {
        appendDirectoryRoot(packet, runtime, root, root, request.filterText);
    }
    return makeResult(request.featureId, !packet.rows.empty(), L"设备与驱动对象枚举", std::move(packet));
}

// queryBaseNamedObjects enumerates per-session and global BaseNamedObjects.
// Input is the request; processing reads object-manager directories; return
// contains mutex/event/section/semaphore style user-visible objects.
KernelOperationResult queryBaseNamedObjects(const KernelRequest& request) {
    const NtRuntime& runtime = ntRuntime();
    QueryPacket packet;
    std::vector<std::wstring> roots{
        L"\\BaseNamedObjects",
    };
    for (const DWORD kSessionId : discoverSessionIds(runtime)) {
        roots.push_back(std::wstring(L"\\Sessions\\") + std::to_wstring(kSessionId) + L"\\BaseNamedObjects");
    }
    std::sort(roots.begin(), roots.end());
    roots.erase(std::unique(roots.begin(), roots.end()), roots.end());
    for (const std::wstring& root : roots) {
        appendDirectoryRoot(packet, runtime, root, root, request.filterText);
    }
    return makeResult(request.featureId, !packet.rows.empty(), L"BaseNamedObjects 枚举", std::move(packet));
}

// isCommunicationType reports whether an object type is relevant to IPC or
// synchronization. Input is an object-manager type string; return drives the
// communication endpoint page filter.
bool isCommunicationType(const std::wstring& typeName) {
    const std::wstring kLower = toLowerCopy(typeName);
    return kLower == L"alpc port"
        || kLower == L"port"
        || kLower == L"waitcompletionpacket"
        || kLower == L"tpworkerfactory"
        || kLower == L"event"
        || kLower == L"section"
        || kLower == L"mutant"
        || kLower == L"semaphore"
        || kLower == L"iocompletion"
        || kLower == L"timer"
        || kLower == L"job"
        || kLower == L"keyed event";
}

// appendCommunicationEndpointsRecursive walks object-manager directories with a
// small depth cap and records IPC/synchronization objects. Inputs are a root
// path, source label and filter; processing avoids revisiting directories and
// stops at the global row cap; no value is returned because rows accumulate in
// the QueryPacket.
void appendCommunicationEndpointsRecursive(
    QueryPacket& packet,
    const NtRuntime& runtime,
    const std::wstring& root,
    const std::wstring& source,
    const std::wstring& filter) {
    struct WorkItem {
        std::wstring path;
        std::size_t depth = 0;
    };

    std::deque<WorkItem> queue;
    std::set<std::wstring> visited;
    queue.push_back({ root, 0 });
    visited.insert(toLowerCopy(root));
    while (!queue.empty() && packet.rows.size() < kMaxDirectoryRows) {
        const WorkItem kItem = queue.front();
        queue.pop_front();
        const std::vector<DirectoryEntry> kEntries = enumerateDirectoryFlat(runtime, kItem.path, packet.warnings);
        for (const DirectoryEntry& entry : kEntries) {
            if (isCommunicationType(entry.typeName) && matchesDirectoryFilter(entry, filter)) {
                appendDirectoryEntryRow(packet, source, kItem.depth, entry);
            }
            if (entry.typeName == L"Directory" && kItem.depth < 3 && packet.rows.size() < kMaxDirectoryRows) {
                const std::wstring kKey = toLowerCopy(entry.fullPath);
                if (visited.insert(kKey).second) {
                    queue.push_back({ entry.fullPath, kItem.depth + 1 });
                }
            }
        }
    }
}

// queryCommunicationEndpoint enumerates user/kernel-visible communication and
// synchronization objects. Input is the request; processing filters common
// namespace roots by type; return contains endpoint rows.
KernelOperationResult queryCommunicationEndpoint(const KernelRequest& request) {
    const NtRuntime& runtime = ntRuntime();
    QueryPacket packet;
    for (const std::wstring& root : commonNamespaceRoots()) {
        appendCommunicationEndpointsRecursive(packet, runtime, root, root, request.filterText);
    }
    return makeResult(request.featureId, !packet.rows.empty(), L"通信端点枚举", std::move(packet));
}

// alignPointer rounds an address up to the native pointer alignment. Input is a
// byte pointer represented as uintptr_t; return points at the next entry block.
std::uintptr_t alignPointer(const std::uintptr_t value) {
    const std::uintptr_t kAlign = sizeof(void*) - 1;
    return (value + kAlign) & ~kAlign;
}

// queryObjectTypeMatrix calls NtQueryObject(ObjectTypesInformation). Input is
// the request; processing parses the variable-length type array; return contains
// object counts, handle counts and access masks.
KernelOperationResult queryObjectTypeMatrix(const KernelRequest& request) {
    const NtRuntime& runtime = ntRuntime();
    QueryPacket packet;
    if (!runtime.queryObject) {
        packet.warnings.push_back(L"NtQueryObject 不可用。");
        return makeResult(request.featureId, false, L"对象类型矩阵", std::move(packet));
    }

    ULONG bufferSize = 256 * 1024;
    std::vector<std::byte> buffer;
    LONG status = kStatusInfoLengthMismatch;
    for (int attempt = 0; attempt < 6; ++attempt) {
        buffer.assign(bufferSize, std::byte{});
        ULONG returned = 0;
        status = runtime.queryObject(nullptr, kObjectTypesInformation, buffer.data(), bufferSize, &returned);
        if (isSuccessStatus(status)) {
            break;
        }
        if (!isRetryStatus(status)) {
            break;
        }
        bufferSize = std::max<ULONG>(bufferSize * 2, returned + 0x10000);
    }

    if (!isSuccessStatus(status) || buffer.size() < sizeof(ULONG)) {
        packet.warnings.push_back(std::wstring(L"NtQueryObject(ObjectTypesInformation) 失败，NTSTATUS=") + statusText(status));
        return makeResult(request.featureId, false, L"对象类型矩阵", std::move(packet));
    }

    const ULONG kCount = *reinterpret_cast<const ULONG*>(buffer.data());
    std::uintptr_t cursor = alignPointer(reinterpret_cast<std::uintptr_t>(buffer.data() + sizeof(ULONG)));
    const std::uintptr_t kEnd = reinterpret_cast<std::uintptr_t>(buffer.data() + buffer.size());
    const std::size_t kLimit = std::min<std::size_t>(kCount, kMaxTypeRows);
    for (std::size_t index = 0; index < kLimit && cursor + sizeof(KobjectTypeInformation) <= kEnd; ++index) {
        const auto* typeInfo = reinterpret_cast<const KobjectTypeInformation*>(cursor);
        const std::wstring kTypeName = countedString(typeInfo->typeName);
        KernelResultRow row = makeResultRow({
            { L"Index", std::to_wstring(index) },
            { L"TypeIndex", std::to_wstring(typeInfo->typeIndex) },
            { L"Type", kTypeName.empty() ? L"<unknown>" : kTypeName },
            { L"Objects", std::to_wstring(typeInfo->totalNumberOfObjects) },
            { L"Handles", std::to_wstring(typeInfo->totalNumberOfHandles) },
            { L"HighObjects", std::to_wstring(typeInfo->highWaterNumberOfObjects) },
            { L"HighHandles", std::to_wstring(typeInfo->highWaterNumberOfHandles) },
            { L"PagedPool", std::to_wstring(typeInfo->totalPagedPoolUsage) },
            { L"NonPagedPool", std::to_wstring(typeInfo->totalNonPagedPoolUsage) },
            { L"NamePool", std::to_wstring(typeInfo->totalNamePoolUsage) },
            { L"HandleTable", std::to_wstring(typeInfo->totalHandleTableUsage) },
            { L"HighPagedPool", std::to_wstring(typeInfo->highWaterPagedPoolUsage) },
            { L"HighNonPagedPool", std::to_wstring(typeInfo->highWaterNonPagedPoolUsage) },
            { L"ValidAccess", hexText(typeInfo->validAccessMask) },
            { L"InvalidAttributes", hexText(typeInfo->invalidAttributes) },
            { L"GenericRead", hexText(typeInfo->genericMapping.GenericRead) },
            { L"GenericWrite", hexText(typeInfo->genericMapping.GenericWrite) },
            { L"GenericExecute", hexText(typeInfo->genericMapping.GenericExecute) },
            { L"GenericAll", hexText(typeInfo->genericMapping.GenericAll) },
            { L"SecurityRequired", typeInfo->securityRequired ? L"true" : L"false" },
            { L"MaintainHandleCount", typeInfo->maintainHandleCount ? L"true" : L"false" },
            { L"PoolType", std::to_wstring(typeInfo->poolType) },
            { L"DefaultPagedCharge", std::to_wstring(typeInfo->defaultPagedPoolCharge) },
            { L"DefaultNonPagedCharge", std::to_wstring(typeInfo->defaultNonPagedPoolCharge) },
        });
        if (matchesColumnsFilter(row, request.filterText)) {
            packet.rows.push_back(std::move(row));
        }

        cursor += sizeof(KobjectTypeInformation);
        cursor += typeInfo->typeName.MaximumLength;
        cursor = alignPointer(cursor);
    }

    if (kCount > kLimit) {
        packet.warnings.push_back(std::wstring(L"对象类型数量 ") + std::to_wstring(kCount) + L"，本次显示前 " + std::to_wstring(kLimit) + L" 项。");
    }
    return makeResult(request.featureId, !packet.rows.empty(), L"对象类型矩阵", std::move(packet));
}

// fileTimeText converts a native LARGE_INTEGER timestamp into local time. Input
// is a FILETIME-compatible large integer; return is compact date/time text or
// empty when the timestamp is zero.
std::wstring fileTimeText(const LARGE_INTEGER& value) {
    if (value.QuadPart == 0) {
        return {};
    }
    FILETIME utc{};
    utc.dwLowDateTime = static_cast<DWORD>(value.LowPart);
    utc.dwHighDateTime = static_cast<DWORD>(value.HighPart);
    FILETIME local{};
    SYSTEMTIME system{};
    if (!::FileTimeToLocalFileTime(&utc, &local) || !::FileTimeToSystemTime(&local, &system)) {
        return {};
    }
    wchar_t text[64]{};
    ::swprintf_s(text, L"%04u-%02u-%02u %02u:%02u:%02u", system.wYear, system.wMonth, system.wDay, system.wHour, system.wMinute, system.wSecond);
    return text;
}

// queryNamedPipeDirectory enumerates one native named-pipe directory. Inputs are
// the runtime, path and packet; processing uses NtOpenFile/NtQueryDirectoryFile;
// no value is returned because rows are appended to packet.
void queryNamedPipeDirectory(const NtRuntime& runtime, const std::wstring& path, const std::wstring& filter, QueryPacket& packet) {
    if (!runtime.openFile || !runtime.queryDirectoryFile) {
        packet.warnings.push_back(L"NtOpenFile/NtQueryDirectoryFile 不可用。");
        return;
    }

    UNICODE_STRING unicodePath = makeUnicodeString(path);
    OBJECT_ATTRIBUTES attributes = makeObjectAttributes(unicodePath);
    IO_STATUS_BLOCK ioStatus{};
    HANDLE directory = nullptr;
    const LONG kOpenStatus = runtime.openFile(
        &directory,
        FILE_LIST_DIRECTORY | SYNCHRONIZE,
        &attributes,
        &ioStatus,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    if (!isSuccessStatus(kOpenStatus) || !directory) {
        packet.warnings.push_back(std::wstring(L"无法打开命名管道目录 ") + path + L"，NTSTATUS=" + statusText(kOpenStatus));
        return;
    }

    std::vector<std::byte> buffer(128 * 1024);
    BOOLEAN restart = TRUE;
    for (;;) {
        std::fill(buffer.begin(), buffer.end(), std::byte{});
        ioStatus = {};
        const LONG kStatus = runtime.queryDirectoryFile(
            directory,
            nullptr,
            nullptr,
            nullptr,
            &ioStatus,
            buffer.data(),
            static_cast<ULONG>(buffer.size()),
            kFileDirectoryInformation,
            FALSE,
            nullptr,
            restart);
        restart = FALSE;
        if (kStatus == kStatusNoMoreEntries) {
            break;
        }
        if (!isSuccessStatus(kStatus)) {
            packet.warnings.push_back(std::wstring(L"查询命名管道目录失败 ") + path + L"，NTSTATUS=" + statusText(kStatus));
            break;
        }

        std::size_t offset = 0;
        for (;;) {
            if (offset + sizeof(KfileDirectoryInformation) > buffer.size()) {
                break;
            }
            const auto* info = reinterpret_cast<const KfileDirectoryInformation*>(buffer.data() + offset);
            const std::wstring kName(info->fileName, info->fileName + (info->fileNameLength / sizeof(wchar_t)));
            if (!kName.empty() && kName != L"." && kName != L"..") {
                KernelResultRow row = makeResultRow({
                    { L"Pipe", kName },
                    { L"Directory", path },
                    { L"NtPath", joinObjectPath(path, kName) },
                    { L"Win32Path", std::wstring(L"\\\\.\\pipe\\") + kName },
                    { L"Attributes", hexText(info->fileAttributes) },
                    { L"Size", std::to_wstring(info->endOfFile.QuadPart) },
                    { L"Created", fileTimeText(info->creationTime) },
                    { L"LastAccess", fileTimeText(info->lastAccessTime) },
                    { L"LastWrite", fileTimeText(info->lastWriteTime) },
                    { L"Changed", fileTimeText(info->changeTime) },
                    { L"Status", L"NtQueryDirectoryFile" },
                });
                if (matchesColumnsFilter(row, filter)) {
                    packet.rows.push_back(std::move(row));
                }
            }
            if (info->nextEntryOffset == 0) {
                break;
            }
            offset += info->nextEntryOffset;
        }
    }

    ::CloseHandle(directory);
}

// queryNamedPipes enumerates native named-pipe namespaces. Input is the request;
// processing uses only Windows/Native file APIs; return lists live pipes.
KernelOperationResult queryNamedPipes(const KernelRequest& request) {
    const NtRuntime& runtime = ntRuntime();
    QueryPacket packet;
    queryNamedPipeDirectory(runtime, L"\\Device\\NamedPipe", request.filterText, packet);
    queryNamedPipeDirectory(runtime, L"\\??\\PIPE", request.filterText, packet);
    return makeResult(request.featureId, !packet.rows.empty(), L"命名管道枚举", std::move(packet));
}

// queryAtomTable probes global atoms and registered clipboard formats. Input is
// the request; processing uses documented Win32 getters only; return contains a
// best-effort visible atom/format list.
KernelOperationResult queryAtomTable(const KernelRequest& request) {
    QueryPacket packet;
    const auto kAtomHexText = [](const UINT atomValue) {
        std::wostringstream stream;
        stream << L"0x" << std::uppercase << std::hex << std::setw(4) << std::setfill(L'0') << atomValue;
        return stream.str();
    };

    for (UINT atom = 0xC000; atom <= 0xFFFF; ++atom) {
        wchar_t globalNameBuffer[512]{};
        const UINT kGlobalLength = ::GlobalGetAtomNameW(
            static_cast<ATOM>(atom),
            globalNameBuffer,
            static_cast<int>(_countof(globalNameBuffer)));

        wchar_t clipboardNameBuffer[512]{};
        const int kClipboardLength = ::GetClipboardFormatNameW(
            atom,
            clipboardNameBuffer,
            static_cast<int>(_countof(clipboardNameBuffer)));

        if (kGlobalLength == 0 && kClipboardLength <= 0) {
            continue;
        }

        const std::wstring kGlobalName = kGlobalLength > 0
            ? std::wstring(globalNameBuffer, globalNameBuffer + kGlobalLength)
            : std::wstring();
        const std::wstring kClipboardName = kClipboardLength > 0
            ? std::wstring(clipboardNameBuffer, clipboardNameBuffer + kClipboardLength)
            : std::wstring();
        const std::wstring kDisplayName = !kGlobalName.empty() ? kGlobalName : kClipboardName;

        std::wstring sourceText;
        std::wstring detailText;
        if (!kGlobalName.empty() && !kClipboardName.empty()) {
            sourceText = L"GlobalGetAtomNameW + GetClipboardFormatNameW";
            if (_wcsicmp(kGlobalName.c_str(), kClipboardName.c_str()) == 0) {
                detailText = L"Atom值: " + std::to_wstring(atom) + L" (" + kAtomHexText(atom) + L")\r\n"
                    L"名称: " + kDisplayName + L"\r\n"
                    L"来源: Global + ClipboardFormat（同名）";
            } else {
                detailText = L"Atom值: " + std::to_wstring(atom) + L" (" + kAtomHexText(atom) + L")\r\n"
                    L"Global名称: " + kGlobalName + L"\r\n"
                    L"ClipboardFormat名称: " + kClipboardName + L"\r\n"
                    L"来源: Global + ClipboardFormat（名称不同）";
            }
        } else if (!kGlobalName.empty()) {
            sourceText = L"GlobalGetAtomNameW";
            detailText = L"Atom值: " + std::to_wstring(atom) + L" (" + kAtomHexText(atom) + L")\r\n"
                L"名称: " + kDisplayName + L"\r\n"
                L"来源: GlobalGetAtomNameW";
        } else {
            sourceText = L"GetClipboardFormatNameW";
            detailText = L"Atom值: " + std::to_wstring(atom) + L" (" + kAtomHexText(atom) + L")\r\n"
                L"名称: " + kDisplayName + L"\r\n"
                L"来源: GetClipboardFormatNameW";
        }

        packet.rows.push_back(makeResultRow({
            { L"Id", std::to_wstring(atom) },
            { L"Hex", kAtomHexText(atom) },
            { L"Name", kDisplayName },
            { L"Source", sourceText },
            { L"Kind", sourceText },
            { L"Status", L"SUCCESS" },
            { L"GlobalName", kGlobalName },
            { L"ClipboardName", kClipboardName },
        }, detailText));
    }

    return makeResult(request.featureId, true, L"Atom/Clipboard Format 遍历", std::move(packet));
}

// queryGrowable invokes one NtQuery* function that follows the common
// buffer-size contract. Inputs are a callable and initial size; processing grows
// the buffer on size-related statuses; output is status and owned bytes.
std::pair<LONG, std::vector<std::byte>> queryGrowable(const std::function<LONG(PVOID, ULONG, PULONG)>& query, ULONG initialSize) {
    std::vector<std::byte> buffer;
    LONG status = kStatusInfoLengthMismatch;
    ULONG bufferSize = initialSize;
    for (int attempt = 0; attempt < 6; ++attempt) {
        buffer.assign(bufferSize, std::byte{});
        ULONG returned = 0;
        status = query(buffer.data(), bufferSize, &returned);
        if (isSuccessStatus(status)) {
            return { status, std::move(buffer) };
        }
        if (!isRetryStatus(status)) {
            break;
        }
        bufferSize = std::max<ULONG>(bufferSize * 2, returned + 0x1000);
    }
    return { status, std::move(buffer) };
}

// appendNtQueryRow writes a safe NtQuery probe result. Inputs identify the API,
// class number, status and returned byte count; output is appended to packet.
void appendNtQueryRow(QueryPacket& packet, const std::wstring& filter, const std::wstring& category, const std::wstring& functionName, ULONG infoClass, LONG status, std::size_t bytes, const std::wstring& detail) {
    KernelResultRow row = makeResultRow({
        { L"Category", category },
        { L"Function", functionName },
        { L"Class", std::to_wstring(infoClass) },
        { L"Status", statusText(status) },
        { L"Success", isSuccessStatus(status) ? L"true" : L"false" },
        { L"Bytes", std::to_wstring(bytes) },
        { L"Detail", detail },
    }, detail);
    if (matchesColumnsFilter(row, filter)) {
        packet.rows.push_back(std::move(row));
    }
}

// appendNtdllExportRows lists NtQuery* exports from ntdll. Input is packet;
// processing parses the PE export directory in memory; no value is returned.
void appendNtdllExportRows(QueryPacket& packet, const std::wstring& filter) {
    HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        packet.warnings.push_back(L"ntdll.dll 未加载，无法枚举 NtQuery* 导出。");
        return;
    }

    const auto* base = reinterpret_cast<const std::byte*>(ntdll);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        packet.warnings.push_back(L"ntdll DOS 头无效。");
        return;
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        packet.warnings.push_back(L"ntdll NT 头无效。");
        return;
    }
    const IMAGE_DATA_DIRECTORY& exportData = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportData.VirtualAddress == 0 || exportData.Size == 0) {
        packet.warnings.push_back(L"ntdll 无导出目录。");
        return;
    }

    const auto* exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(base + exportData.VirtualAddress);
    const auto* names = reinterpret_cast<const DWORD*>(base + exports->AddressOfNames);
    const auto* ordinals = reinterpret_cast<const WORD*>(base + exports->AddressOfNameOrdinals);
    const auto* functions = reinterpret_cast<const DWORD*>(base + exports->AddressOfFunctions);
    std::size_t added = 0;
    for (DWORD index = 0; index < exports->NumberOfNames && added < kMaxExportRows; ++index) {
        const char* exportName = reinterpret_cast<const char*>(base + names[index]);
        if (!exportName || std::strncmp(exportName, "NtQuery", 7) != 0) {
            continue;
        }
        const WORD kOrdinalIndex = ordinals[index];
        const DWORD kRva = kOrdinalIndex < exports->NumberOfFunctions ? functions[kOrdinalIndex] : 0;
        const int kWideLength = ::MultiByteToWideChar(CP_ACP, 0, exportName, -1, nullptr, 0);
        std::wstring wideName;
        if (kWideLength > 0) {
            wideName.assign(static_cast<std::size_t>(kWideLength - 1), L'\0');
            ::MultiByteToWideChar(CP_ACP, 0, exportName, -1, wideName.data(), kWideLength);
        }
        KernelResultRow row = makeResultRow({
            { L"Category", L"Export" },
            { L"Function", wideName.empty() ? L"NtQuery*" : wideName },
            { L"Ordinal", std::to_wstring(exports->Base + kOrdinalIndex) },
            { L"RVA", hexText(kRva) },
            { L"Status", L"Exported" },
        });
        if (matchesColumnsFilter(row, filter)) {
            packet.rows.push_back(std::move(row));
            ++added;
        }
    }
}

// queryNtQueryLegacy executes safe NtQuery probes against current process,
// thread and token handles, plus lists NtQuery* exports. Input is the request;
// output is a live status matrix rather than static text.
KernelOperationResult queryNtQueryLegacy(const KernelRequest& request) {
    const NtRuntime& runtime = ntRuntime();
    QueryPacket packet;
    appendNtdllExportRows(packet, request.filterText);

    if (runtime.querySystemInformation) {
        const std::array<ULONG, 6> kClasses{ 0, 2, 3, 5, 11, 16 };
        for (const ULONG kInfoClass : kClasses) {
            auto [status, buffer] = queryGrowable([&](PVOID data, ULONG size, PULONG returned) {
                return runtime.querySystemInformation(kInfoClass, data, size, returned);
            }, kInfoClass == 11 ? 1024 * 1024 : 128 * 1024);
            appendNtQueryRow(packet, request.filterText, L"System", L"NtQuerySystemInformation", kInfoClass, status, buffer.size(), L"安全枚举类探测");
        }
    } else {
        packet.warnings.push_back(L"NtQuerySystemInformation 不可用。");
    }

    if (runtime.queryInformationProcess) {
        const std::array<ULONG, 4> kClasses{ 0, 7, 20, 27 };
        for (const ULONG kInfoClass : kClasses) {
            auto [status, buffer] = queryGrowable([&](PVOID data, ULONG size, PULONG returned) {
                return runtime.queryInformationProcess(::GetCurrentProcess(), kInfoClass, data, size, returned);
            }, 4096);
            appendNtQueryRow(packet, request.filterText, L"Process", L"NtQueryInformationProcess", kInfoClass, status, buffer.size(), L"当前进程句柄");
        }
    } else {
        packet.warnings.push_back(L"NtQueryInformationProcess 不可用。");
    }

    if (runtime.queryInformationThread) {
        const std::array<ULONG, 2> kClasses{ 0, 1 };
        for (const ULONG kInfoClass : kClasses) {
            auto [status, buffer] = queryGrowable([&](PVOID data, ULONG size, PULONG returned) {
                return runtime.queryInformationThread(::GetCurrentThread(), kInfoClass, data, size, returned);
            }, 4096);
            appendNtQueryRow(packet, request.filterText, L"Thread", L"NtQueryInformationThread", kInfoClass, status, buffer.size(), L"当前线程句柄");
        }
    } else {
        packet.warnings.push_back(L"NtQueryInformationThread 不可用。");
    }

    if (runtime.queryInformationToken) {
        HANDLE token = nullptr;
        if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token)) {
            const std::array<ULONG, 3> kClasses{ 1, 25, 10 };
            for (const ULONG kInfoClass : kClasses) {
                auto [status, buffer] = queryGrowable([&](PVOID data, ULONG size, PULONG returned) {
                    return runtime.queryInformationToken(token, kInfoClass, data, size, returned);
                }, 4096);
                appendNtQueryRow(packet, request.filterText, L"Token", L"NtQueryInformationToken", kInfoClass, status, buffer.size(), L"当前进程令牌");
            }
            ::CloseHandle(token);
        } else {
            packet.warnings.push_back(std::wstring(L"OpenProcessToken 失败，Win32=") + std::to_wstring(::GetLastError()));
        }
    } else {
        packet.warnings.push_back(L"NtQueryInformationToken 不可用。");
    }

    if (runtime.queryObject) {
        const std::array<ULONG, 3> kClasses{ kObjectBasicInformation, kObjectNameInformation, kObjectTypeInformation };
        for (const ULONG kInfoClass : kClasses) {
            auto [status, buffer] = queryGrowable([&](PVOID data, ULONG size, PULONG returned) {
                return runtime.queryObject(::GetCurrentProcess(), kInfoClass, data, size, returned);
            }, 4096);
            appendNtQueryRow(packet, request.filterText, L"Object", L"NtQueryObject", kInfoClass, status, buffer.size(), L"当前进程伪句柄");
        }
    } else {
        packet.warnings.push_back(L"NtQueryObject 不可用。");
    }

    return makeResult(request.featureId, !packet.rows.empty(), L"历史 NtQuery 探测", std::move(packet));
}

// executeNativeObjectDetail opens the selected object-manager path when the
// type has a safe read-only opener in this lightweight project. Inputs are the
// selected row fields; processing never guesses destructive access and records
// unsupported object types as explicit rows; output is a detailed result table.
KernelOperationResult executeNativeObjectDetail(const KernelActionRequest& request) {
    const NtRuntime& runtime = ntRuntime();
    QueryPacket packet;
    std::wstring type = objectTypeNameFromAction(request);
    if (request.featureId == KernelFeatureId::kObjectTypeMatrix && !type.empty()) {
        appendObjectTypeDetailRow(request, type, packet);
        return makeNativeActionResult(request, true, L"R3 对象类型详情", std::move(packet));
    }

    const std::wstring kPath = nativePathFromAction(request);
    if (kPath.empty()) {
        if (request.featureId == KernelFeatureId::kObjectTypeMatrix && !type.empty()) {
            appendObjectTypeDetailRow(request, type, packet);
            return makeNativeActionResult(request, true, L"R3 对象类型详情", std::move(packet));
        }
        packet.warnings.push_back(L"当前行没有 Path/NtPath/Parent+Name，无法定位对象。");
        return makeNativeActionResult(request, false, L"R3 对象详情", std::move(packet));
    }
    if (type.empty() && (startsWithI(kPath, L"\\Device\\NamedPipe") || startsWithI(kPath, L"\\??\\PIPE"))) {
        type = L"NamedPipe";
    }
    if (type.empty() && (kPath == L"\\" || kPath == fieldValue(request, L"Directory"))) {
        type = L"Directory";
    }

    HANDLE handle = nullptr;
    LONG openStatus = kStatusNoSuchFile;
    IO_STATUS_BLOCK ioStatus{};
    if (_wcsicmp(type.c_str(), L"SymbolicLink") == 0) {
        handle = openSymbolicLink(runtime, kPath, &openStatus);
    } else if (_wcsicmp(type.c_str(), L"Directory") == 0 || kPath == L"\\") {
        handle = openDirectory(runtime, kPath, &openStatus);
    } else if (_wcsicmp(type.c_str(), L"NamedPipe") == 0 || startsWithI(kPath, L"\\Device\\NamedPipe") || startsWithI(kPath, L"\\??\\PIPE")) {
        type = L"NamedPipe";
        handle = openNamedPipeReadOnly(runtime, kPath, &openStatus, &ioStatus);
    }

    if (!handle && _wcsicmp(type.c_str(), L"Directory") != 0 && _wcsicmp(type.c_str(), L"SymbolicLink") != 0 && _wcsicmp(type.c_str(), L"NamedPipe") != 0) {
        packet.rows.push_back(makeResultRow({
            { L"Action", L"NativeObjectQueryDetail" },
            { L"Path", kPath },
            { L"Type", type.empty() ? L"<unknown>" : type },
            { L"Status", L"未打开" },
            { L"Reason", L"该对象类型需要专用 NtOpen* API；轻量版当前仅对 Directory/SymbolicLink/NamedPipe 执行安全只读打开。" },
            { L"Next", L"如需深入该类型，应新增专用 opener 并只走 R3 Native 或 ArkDriverClient。" },
        }));
        return makeNativeActionResult(request, false, L"R3 对象详情", std::move(packet));
    }

    appendObjectBasicInfoRow(packet, runtime, kPath, handle, openStatus);
    appendQueriedObjectText(packet, runtime, handle, kObjectNameInformation, L"Name");
    appendQueriedObjectText(packet, runtime, handle, kObjectTypeInformation, L"Type");

    if (_wcsicmp(type.c_str(), L"Directory") == 0 && handle) {
        appendDirectoryPreviewRows(packet, runtime, kPath, 32);
    } else if (_wcsicmp(type.c_str(), L"SymbolicLink") == 0) {
        std::wstring target;
        if (handle) {
            target = querySymbolicLinkTarget(runtime, handle);
        }
        const std::vector<std::wstring> kCandidates = dosPathCandidatesFromNtPath(target);
        packet.rows.push_back(makeResultRow({
            { L"Action", L"NativeSymbolicLinkDetail" },
            { L"Path", kPath },
            { L"OpenStatus", statusText(openStatus) },
            { L"OpenStatusText", statusMeaningText(openStatus) },
            { L"Target", target },
            { L"DosCandidates", joinStrings(kCandidates, L"; ") },
            { L"Status", target.empty() ? L"符号链接目标未解析" : L"已解析符号链接目标" },
        }, target));
    } else if (_wcsicmp(type.c_str(), L"NamedPipe") == 0) {
        packet.rows.push_back(makeResultRow({
            { L"Action", L"NativeNamedPipeDetail" },
            { L"NtPath", kPath },
            { L"Win32Path", startsWithI(kPath, L"\\Device\\NamedPipe\\") ? std::wstring(L"\\\\.\\pipe\\") + kPath.substr(18) : L"" },
            { L"OpenStatus", statusText(openStatus) },
            { L"OpenStatusText", statusMeaningText(openStatus) },
            { L"IoStatus", statusText(static_cast<LONG>(ioStatus.Status)) },
            { L"IoStatusText", statusMeaningText(static_cast<LONG>(ioStatus.Status)) },
            { L"Information", std::to_wstring(static_cast<std::uint64_t>(ioStatus.Information)) },
            { L"Status", handle ? L"可只读打开管道对象" : L"不可打开、管道忙或权限受限" },
        }));
    }

    if (handle) {
        ::CloseHandle(handle);
    }
    return makeNativeActionResult(request, handle != nullptr, L"R3 对象详情", std::move(packet));
}

// executeNativeSymbolicLinkResolve resolves the selected symbolic link again on
// demand. Inputs are row fields or the filter edit as fallback; processing calls
// NtOpenSymbolicLinkObject/NtQuerySymbolicLinkObject only; output shows target,
// DOS candidates and object count fields so the right-click operation is useful.
KernelOperationResult executeNativeSymbolicLinkResolve(const KernelActionRequest& request) {
    const NtRuntime& runtime = ntRuntime();
    QueryPacket packet;
    const std::wstring kPath = nativePathFromAction(request);
    if (kPath.empty()) {
        packet.warnings.push_back(L"当前行没有可解析的符号链接 Path。");
        return makeNativeActionResult(request, false, L"符号链接解析", std::move(packet));
    }

    LONG openStatus = 0;
    HANDLE link = openSymbolicLink(runtime, kPath, &openStatus);
    std::wstring handleCount;
    std::wstring pointerCount;
    std::wstring target;
    if (link) {
        queryBasicObjectCounts(runtime, link, handleCount, pointerCount);
        target = querySymbolicLinkTarget(runtime, link);
    }
    const std::vector<std::wstring> kCandidates = dosPathCandidatesFromNtPath(target);
    packet.rows.push_back(makeResultRow({
        { L"Action", L"NativeSymbolicLinkResolve" },
        { L"Path", kPath },
        { L"OpenStatus", statusText(openStatus) },
        { L"OpenStatusText", statusMeaningText(openStatus) },
        { L"Target", target },
        { L"DosCandidates", joinStrings(kCandidates, L"; ") },
        { L"Handles", handleCount.empty() ? L"N/A" : handleCount },
        { L"Pointers", pointerCount.empty() ? L"N/A" : pointerCount },
        { L"Status", link ? (target.empty() ? L"已打开但目标为空" : L"已打开并查询") : L"打开失败" },
    }, target.empty() ? statusMeaningText(openStatus) : target));
    if (link) {
        ::CloseHandle(link);
    }
    return makeNativeActionResult(request, link != nullptr && !target.empty(), L"符号链接解析", std::move(packet));
}

// executeNativeNamedPipeProbe validates whether the selected named-pipe entry
// can be opened as a native file object. Inputs are the selected Pipe/NtPath
// fields; processing uses NtOpenFile with read-only/synchronize access; output
// reports NTSTATUS and basic object metadata without reading or writing pipe
// payloads.
KernelOperationResult executeNativeNamedPipeProbe(const KernelActionRequest& request) {
    const NtRuntime& runtime = ntRuntime();
    QueryPacket packet;
    const std::wstring kPath = nativePathFromAction(request);
    if (kPath.empty()) {
        packet.warnings.push_back(L"当前行没有 NtPath/Pipe，无法验证命名管道。");
        return makeNativeActionResult(request, false, L"命名管道打开验证", std::move(packet));
    }
    if (!runtime.openFile) {
        packet.warnings.push_back(L"NtOpenFile 不可用。");
        return makeNativeActionResult(request, false, L"命名管道打开验证", std::move(packet));
    }

    LONG openStatus = kStatusNoSuchFile;
    IO_STATUS_BLOCK ioStatus{};
    HANDLE pipe = openNamedPipeReadOnly(runtime, kPath, &openStatus, &ioStatus);
    appendObjectBasicInfoRow(packet, runtime, kPath, pipe, openStatus);
    packet.rows.push_back(makeResultRow({
        { L"Action", L"NativeNamedPipeProbe" },
        { L"NtPath", kPath },
        { L"Win32Path", startsWithI(kPath, L"\\Device\\NamedPipe\\") ? std::wstring(L"\\\\.\\pipe\\") + kPath.substr(18) : L"" },
        { L"OpenStatus", statusText(openStatus) },
        { L"OpenStatusText", statusMeaningText(openStatus) },
        { L"IoStatus", statusText(static_cast<LONG>(ioStatus.Status)) },
        { L"IoStatusText", statusMeaningText(static_cast<LONG>(ioStatus.Status)) },
        { L"Information", std::to_wstring(static_cast<std::uint64_t>(ioStatus.Information)) },
        { L"Access", L"FILE_READ_ATTRIBUTES|SYNCHRONIZE" },
        { L"Share", L"READ|WRITE|DELETE" },
        { L"Status", pipe ? L"可打开" : L"不可打开、管道忙或权限受限" },
    }, statusMeaningText(openStatus)));
    if (pipe) {
        ::CloseHandle(pipe);
    }
    return makeNativeActionResult(request, pipe != nullptr, L"命名管道打开验证", std::move(packet));
}

} // namespace

bool isNativeKernelFeature(const KernelFeatureId id) {
    switch (id) {
    case KernelFeatureId::kObjectNamespaceOverview:
    case KernelFeatureId::kObjectDirectoryRecursive:
    case KernelFeatureId::kNamedPipe:
    case KernelFeatureId::kBaseNamedObjects:
    case KernelFeatureId::kSymbolicLink:
    case KernelFeatureId::kDeviceDriverObjects:
    case KernelFeatureId::kObjectTypeMatrix:
    case KernelFeatureId::kCommunicationEndpoint:
    case KernelFeatureId::kAtomTable:
    case KernelFeatureId::kNtQueryLegacy:
        return true;
    default:
        return false;
    }
}

KernelOperationResult queryNativeKernelFeature(const KernelRequest& request) {
    switch (request.featureId) {
    case KernelFeatureId::kObjectNamespaceOverview:
        return queryObjectNamespaceOverview(request);
    case KernelFeatureId::kObjectDirectoryRecursive:
        return queryObjectDirectoryRecursive(request);
    case KernelFeatureId::kNamedPipe:
        return queryNamedPipes(request);
    case KernelFeatureId::kBaseNamedObjects:
        return queryBaseNamedObjects(request);
    case KernelFeatureId::kSymbolicLink:
        return querySymbolicLinks(request);
    case KernelFeatureId::kDeviceDriverObjects:
        return queryDeviceDriverObjects(request);
    case KernelFeatureId::kObjectTypeMatrix:
        return queryObjectTypeMatrix(request);
    case KernelFeatureId::kCommunicationEndpoint:
        return queryCommunicationEndpoint(request);
    case KernelFeatureId::kAtomTable:
        return queryAtomTable(request);
    case KernelFeatureId::kNtQueryLegacy:
        return queryNtQueryLegacy(request);
    default: {
        KernelOperationResult result;
        result.supported = false;
        result.success = false;
        result.message = L"该内核条目不是 R3 Native 查询项。";
        result.rows.push_back(makeResultRow({
            { L"功能", toDisplayName(request.featureId) },
            { L"状态", L"Unsupported native route" },
        }, result.message));
        return result;
    }
    }
}

KernelOperationResult executeNativeKernelAction(const KernelActionRequest& request) {
    switch (request.actionId) {
    case KernelActionId::kNativeObjectQueryDetail:
        return executeNativeObjectDetail(request);
    case KernelActionId::kNativeSymbolicLinkResolve:
        return executeNativeSymbolicLinkResolve(request);
    case KernelActionId::kNativeNamedPipeProbe:
        return executeNativeNamedPipeProbe(request);
    default: {
        QueryPacket packet;
        packet.rows.push_back(makeResultRow({
            { L"功能", toDisplayName(request.featureId) },
            { L"Action", std::to_wstring(static_cast<std::uint32_t>(request.actionId)) },
            { L"状态", L"Unsupported native action" },
        }, L"该 R3 Native 动作没有注册执行路径。"));
        return makeNativeActionResult(request, false, L"R3 Native 动作", std::move(packet));
    }
    }
}

} // namespace Ksword::Features::Kernel
