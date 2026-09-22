#include "KernelPage.h"

#include "KernelCatalog.h"
#include "KernelPageLayout.h"
#include "../../ui/Controls.h"
#include "../../ui/EntityNavigation.h"
#include "../../ui/ListViewUtil.h"
#include "../../ui/NumericSortKey.h"
#include "../../ui/TextFindSupport.h"
#include "../../../../shared/driver/KswordArkCallbackIoctl.h"
#include "../../../../shared/driver/KswordArkCapabilityIoctl.h"
#include "../../../../shared/driver/KswordArkDynDataIoctl.h"

#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <windowsx.h>

#include <algorithm>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <functional>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <limits>
#include <set>
#include <sstream>
#include <unordered_map>

namespace ksword::features::kernel {
namespace {
constexpr wchar_t kKernelPageClass[] = L"KswordARKLight.KernelPage";
constexpr int kIdPrimaryTab = 51001;
constexpr int kIdSecondaryTab = 51002;
constexpr int kIdRefresh = 51003;
constexpr int kIdResultList = 51005;
constexpr int kIdFilterEdit = 51006;
constexpr int kIdModuleFilterEdit = 51007;
constexpr int kIdLocate = 51008;
constexpr int kIdIncludeCombo = 51009;
constexpr int kIdCallbackRuleTab = 51010;
constexpr int kIdCallbackLogTab = 51011;
constexpr int kIdCallbackApply = 51012;
constexpr int kIdCallbackReload = 51013;
constexpr int kIdCallbackBypassApply = 51014;
constexpr int kIdCallbackBypassClear = 51015;
constexpr int kIdCallbackBypassRefresh = 51016;
constexpr int kIdCallbackStartFsctl = 51017;
constexpr int kIdCallbackDrainFileMonitor = 51018;
constexpr int kIdCallbackClearFileMonitor = 51019;
constexpr int kIdCallbackImport = 51020;
constexpr int kIdCallbackExport = 51021;
constexpr int kIdCallbackAddGroup = 51022;
constexpr int kIdCallbackRemoveGroup = 51023;
constexpr int kIdCallbackRenameGroup = 51024;
constexpr int kIdCallbackMoveGroupUp = 51025;
constexpr int kIdCallbackMoveGroupDown = 51026;
constexpr int kIdCallbackAddRule = 51027;
constexpr int kIdCallbackRemoveRule = 51028;
constexpr int kIdCallbackMoveRuleUp = 51029;
constexpr int kIdCallbackMoveRuleDown = 51030;
constexpr int kIdCallbackBypassAdd = 51031;
constexpr int kIdCallbackBypassRemove = 51032;
constexpr int kIdCallbackExportFileMonitor = 51033;
constexpr int kIdCopyDiagnosticReport = 51034;
constexpr int kIdRiskOnlyCheck = 51035;
constexpr int kIdEvidenceIncludeNonModuleCheck = 51036;
constexpr int kIdEvidenceStartEdit = 51037;
constexpr int kIdEvidenceEndEdit = 51038;
constexpr int kIdEvidenceMaxRowsEdit = 51039;
constexpr int kIdEvidenceMaxRowsSpin = 51040;
constexpr int kIdIntegrityModuleBaseEdit = 51041;
constexpr int kIdIntegrityFillFromSelection = 51042;
constexpr int kIdIntegrityCpuOnly = 51043;
constexpr int kIdIntegrityIdtVectorsEdit = 51044;
constexpr int kIdIntegrityIdtVectorsSpin = 51045;
constexpr UINT kMsgKernelQueryCompleted = WM_APP + 605;
constexpr UINT kMsgKernelActionCompleted = WM_APP + 606;
constexpr UINT kMsgCallbackEventReceived = WM_APP + 607;
constexpr UINT kMsgCallbackAnswerCompleted = WM_APP + 608;
constexpr UINT kMsgR0EvidenceFilterCompleted = WM_APP + 609;
constexpr UINT kMsgCallbackFileIoCompleted = WM_APP + 610;
constexpr UINT_PTR kTimerR0EvidenceFilter = 51057;
constexpr int kIdCallbackGlobalEnabled = 51047;
constexpr int kIdCallbackFileMonitorFsctlOnly = 51048;
constexpr int kIdDeviceDriverDirectoryCombo = 51049;
constexpr int kIdDeviceDriverTypeCombo = 51050;
constexpr int kIdBaseNamedScopeCombo = 51051;
constexpr int kIdBaseNamedTypeCombo = 51052;
constexpr int kIdCallbackStartReceiver = 51053;
constexpr int kIdCallbackStopReceiver = 51054;
constexpr int kIdCallbackAllowEvent = 51055;
constexpr int kIdCallbackDenyEvent = 51056;
constexpr UINT_PTR kFilterEditSubclassId = 51046;
constexpr UINT_PTR kMenuRefreshCurrentFeature = 51100;
constexpr UINT_PTR kMenuCopyCell = 51101;
constexpr UINT_PTR kMenuCopyRow = 51102;
constexpr UINT_PTR kMenuCopyAll = 51103;
constexpr UINT_PTR kMenuInlineNopPatch = 51104;
constexpr UINT_PTR kMenuCallbackSafeRemove = 51105;
constexpr UINT_PTR kMenuCallbackExperimentalUnlink = 51106;
constexpr UINT_PTR kMenuCallbackOpenModuleFolder = 51107;
constexpr UINT_PTR kMenuCallbackModuleFileDetail = 51108;
constexpr UINT_PTR kMenuMinifilterSetBypass = 51109;
constexpr UINT_PTR kMenuMinifilterClearBypass = 51110;
constexpr UINT_PTR kMenuNetworkCaptureStart = 51190;
constexpr UINT_PTR kMenuNetworkCaptureStop = 51191;
constexpr UINT_PTR kMenuPiDdbDeleteEntry = 51192;
constexpr UINT_PTR kMenuDriverDispatchRestore = 51193;
constexpr UINT_PTR kMenuDriverDispatchAbandon = 51194;
constexpr UINT_PTR kMenuDriverImageRestore = 51195;
constexpr UINT_PTR kMenuDriverImageAbandon = 51196;
constexpr UINT_PTR kMenuDriverCommunicationRestore = 51197;
constexpr UINT_PTR kMenuDriverObjectQueryDetail = 51111;
constexpr UINT_PTR kMenuDriverObjectForceUnload = 51112;
constexpr UINT_PTR kMenuNativeObjectQueryDetail = 51113;
constexpr UINT_PTR kMenuNativeSymbolicLinkResolve = 51114;
constexpr UINT_PTR kMenuNativeNamedPipeProbe = 51115;
constexpr UINT_PTR kMenuFilterByModule = 51116;
constexpr UINT_PTR kMenuFilterByTargetModule = 51117;
constexpr UINT_PTR kMenuFilterByAddress = 51118;
constexpr UINT_PTR kMenuShowRowDialog = 51119;
constexpr UINT_PTR kMenuFilterByPath = 51120;
constexpr UINT_PTR kMenuDynDataApplyMatchedProfile = 51121;
constexpr UINT_PTR kMenuMutationCommitDryRun = 51122;
constexpr UINT_PTR kMenuMutationRollbackDryRun = 51123;
constexpr UINT_PTR kMenuMutationRollbackConfirmed = 51124;
constexpr UINT_PTR kMenuCallbackCancelPendingDecisions = 51125;
constexpr UINT_PTR kMenuCallbackApplyDisabledEmptyRules = 51126;
constexpr UINT_PTR kMenuExportAllTsv = 51127;
constexpr UINT_PTR kMenuFilterByType = 51128;
constexpr UINT_PTR kMenuFilterByName = 51129;
constexpr UINT_PTR kMenuFilterByTarget = 51130;
constexpr UINT_PTR kMenuAtomVerify = 51131;
constexpr UINT_PTR kMenuAtomCopySnippet = 51132;
constexpr UINT_PTR kMenuCopySameDirectory = 51133;
constexpr UINT_PTR kMenuMapDosPath = 51134;
constexpr UINT_PTR kMenuCopyObjectName = 51135;
constexpr UINT_PTR kMenuCopyObjectType = 51136;
constexpr UINT_PTR kMenuCopyFullPath = 51137;
constexpr UINT_PTR kMenuCopySymbolicTarget = 51138;
constexpr UINT_PTR kMenuCopyAtomValue = 51139;
constexpr UINT_PTR kMenuCopyAtomHex = 51140;
constexpr UINT_PTR kMenuCopyAtomName = 51141;
constexpr UINT_PTR kMenuCopyAtomSource = 51142;
constexpr UINT_PTR kMenuCopyDiagnosticReport = 51143;
constexpr UINT_PTR kMenuCopySelectedRows = 51144;
constexpr UINT_PTR kMenuCopySelectedRowsWithHeader = 51145;
constexpr UINT_PTR kMenuCopySelectedDetails = 51146;
constexpr UINT_PTR kMenuCopyObjectEnumSource = 51147;
constexpr UINT_PTR kMenuCallbackGroupAdd = 51148;
constexpr UINT_PTR kMenuCallbackGroupRemove = 51149;
constexpr UINT_PTR kMenuCallbackGroupRename = 51150;
constexpr UINT_PTR kMenuCallbackGroupMoveUp = 51151;
constexpr UINT_PTR kMenuCallbackGroupMoveDown = 51152;
constexpr UINT_PTR kMenuCallbackRuleAdd = 51153;
constexpr UINT_PTR kMenuCallbackRuleRemove = 51154;
constexpr UINT_PTR kMenuCallbackRuleMoveUp = 51155;
constexpr UINT_PTR kMenuCallbackRuleMoveDown = 51156;
constexpr UINT_PTR kMenuCallbackBypassAdd = 51157;
constexpr UINT_PTR kMenuCallbackBypassRemove = 51158;
constexpr UINT_PTR kMenuCallbackBypassApply = 51159;
constexpr UINT_PTR kMenuCallbackBypassClear = 51160;
constexpr UINT_PTR kMenuCallbackBypassRefresh = 51161;
constexpr UINT_PTR kMenuCallbackFileMonitorStart = 51162;
constexpr UINT_PTR kMenuCallbackFileMonitorDrain = 51163;
constexpr UINT_PTR kMenuCallbackFileMonitorClear = 51164;
constexpr UINT_PTR kMenuCallbackFileMonitorExport = 51165;
constexpr UINT_PTR kMenuCallbackCopyPanelSelection = 51166;
constexpr UINT_PTR kMenuCallbackGroupToggleEnabled = 51167;
constexpr UINT_PTR kMenuCallbackRuleToggleEnabled = 51168;
constexpr UINT_PTR kMenuCallbackImportConfig = 51169;
constexpr UINT_PTR kMenuCallbackExportConfig = 51170;
constexpr UINT_PTR kMenuCallbackApplyLocalRules = 51171;
constexpr UINT_PTR kMenuCallbackReloadRuntime = 51172;
constexpr UINT_PTR kMenuCallbackRuleCopyText = 51176;
constexpr UINT_PTR kMenuCallbackRulePasteNew = 51177;
constexpr UINT_PTR kMenuCallbackFileMonitorOpenProcess = 51178;
constexpr UINT_PTR kMenuCallbackFileMonitorOpenPath = 51179;
constexpr UINT_PTR kMenuObjectFilterByRoot = 51173;
constexpr UINT_PTR kMenuObjectFilterByDirectory = 51174;
constexpr UINT_PTR kMenuCopyDosCandidate = 51175;
constexpr UINT_PTR kMenuCallbackCopyColumnBase = 51180;
constexpr UINT_PTR kMenuCallbackCopyColumnMax = 51188;
constexpr UINT_PTR kMenuFilterByOwner = 51189;
constexpr UINT_PTR kMenuFilterByRisk = 51190;
constexpr UINT_PTR kMenuFilterByPidTid = 51191;
constexpr UINT_PTR kMenuFilterByCapability = 51192;
constexpr UINT_PTR kMenuRefreshSelectedDetail = 51193;
constexpr UINT_PTR kMenuCopyColumnBase = 51200;
constexpr UINT_PTR kMenuCopyColumnMax = 51299;
constexpr int kCallbackFileMonitorPidColumn = 1;
constexpr int kCallbackFileMonitorPathColumn = 3;
constexpr int kCallbackFileMonitorPathStateColumn = 10;
constexpr wchar_t kInlineHookForceRequiredStatusText[] = L"6";
constexpr int kKernelSplitterThickness = 5;
constexpr const wchar_t* kDeviceDriverFixedDirectories[] = {
    L"\\Device",
    L"\\Driver",
    L"\\FileSystem",
    L"\\FileSystem\\Filters",
};

// isR0EvidenceFeature identifies the large snapshot pages that share the
// generic R0 evidence projection. These pages use one debounced background
// filter path to keep edit notifications off the UI thread.
bool isR0EvidenceFeature(const KernelFeatureId featureId) {
    switch (featureId) {
    case KernelFeatureId::kCpuHardwareSnapshot:
    case KernelFeatureId::kPhysicalMemoryLayout:
    case KernelFeatureId::kMutationAudit:
    case KernelFeatureId::kKeyboardHotkeys:
    case KernelFeatureId::kKeyboardHooks:
    case KernelFeatureId::kDynDataCapabilities:
    case KernelFeatureId::kMinifilterBypassPids:
    case KernelFeatureId::kKernelTimerDpc:
    case KernelFeatureId::kIoctlRegistry:
        return true;
    default:
        return false;
    }
}

// MinMaxValue keeps this file independent from std::min/std::max macro
// collisions when Windows headers are included before NOMINMAX is visible.
template <typename T>
constexpr const T& minValue(const T& left, const T& right) {
    return (right < left) ? right : left;
}

// MaxValue keeps this file independent from std::min/std::max macro
// collisions when Windows headers are included before NOMINMAX is visible.
template <typename T>
constexpr const T& maxValue(const T& left, const T& right) {
    return (left < right) ? right : left;
}

// clampValue returns value clamped into [low, high] without depending on
// std::clamp. Inputs are the candidate value and inclusive bounds; output is
// always within the supplied range.
template <typename T>
constexpr T clampValue(const T& value, const T& low, const T& high) {
    return value < low ? low : (high < value ? high : value);
}


// ensureKernelPageClass registers the page window class once. Input is none;
// processing calls RegisterClassW idempotently; no value is returned.
void ensureKernelPageClass() {
    static bool registered = false;
    if (registered) {
        return;
    }

    WNDCLASSW wc{};
    wc.lpfnWndProc = KernelPage::wndProc;
    wc.hInstance = ::GetModuleHandleW(nullptr);
    wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName = kKernelPageClass;
    ::RegisterClassW(&wc);
    registered = true;
}

// BoolText converts metadata or result booleans into compact Chinese labels.
// Input is a boolean value; output is `是` or `否`.
const wchar_t* boolText(const bool value) {
    return value ? L"是" : L"否";
}

// hexToUInt64 parses decimal or 0x-prefixed protocol numbers from cached rows.
// Input is display text emitted by KernelFacade; processing uses wcstoull and
// requires full-token consumption; output is false when the cell is missing or
// not numeric.
bool hexToUInt64(const std::wstring& text, std::uint64_t& valueOut) {
    if (text.empty()) {
        return false;
    }
    wchar_t* end = nullptr;
    const int kBase = text.size() > 2 && text[0] == L'0' && (text[1] == L'x' || text[1] == L'X') ? 16 : 10;
    const unsigned long long kValue = std::wcstoull(text.c_str(), &end, kBase);
    if (end == text.c_str() || *end != L'\0') {
        return false;
    }
    valueOut = static_cast<std::uint64_t>(kValue);
    return true;
}

// callbackGuidText formats the opaque callback event identifier for display and
// for the strongly validated facade action. It does not reinterpret the bytes
// as a Windows GUID, preserving the driver protocol's original byte order.
std::wstring callbackGuidText(const KSWORD_ARK_GUID128& guid) {
    std::wostringstream stream;
    stream << std::hex << std::uppercase << std::setfill(L'0');
    for (const unsigned char kValue : guid.bytes) {
        stream << std::setw(2) << static_cast<unsigned int>(kValue);
    }
    return stream.str();
}

// fixedWideText converts a fixed shared-protocol wchar buffer to a bounded UI
// string. Input may have no terminator after a malformed driver response; the
// returned display text therefore never scans beyond the packet field.
template <std::size_t Size>
std::wstring fixedWideText(const wchar_t (&value)[Size]) {
    const std::size_t kLength = std::find(value, value + Size, L'\0') - value;
    return std::wstring(value, kLength);
}

std::wstring rowFieldByName(const std::vector<std::wstring>& row,
    const std::vector<std::wstring>& columns,
    std::initializer_list<const wchar_t*> names);

// firstRowValue returns the first non-empty field with one of the supplied
// aliases. Inputs are a row cache and column aliases; output is empty when no
// matching cell is present.
std::wstring firstRowValue(
    const std::vector<std::vector<std::wstring>>& rows,
    const std::vector<std::wstring>& columns,
    std::initializer_list<const wchar_t*> names) {
    for (const std::vector<std::wstring>& row : rows) {
        const std::wstring kValue = rowFieldByName(row, columns, names);
        if (!kValue.empty()) {
            return kValue;
        }
    }
    return {};
}

// firstRowUInt64 returns a numeric value from the first matching cached row.
// Inputs are row data, columns and aliases; processing accepts hexadecimal and
// decimal display forms; output uses fallback when no numeric value is found.
std::uint64_t firstRowUInt64(
    const std::vector<std::vector<std::wstring>>& rows,
    const std::vector<std::wstring>& columns,
    std::initializer_list<const wchar_t*> names,
    const std::uint64_t fallback = 0) {
    for (const std::vector<std::wstring>& row : rows) {
        std::uint64_t value = 0;
        if (hexToUInt64(rowFieldByName(row, columns, names), value)) {
            return value;
        }
    }
    return fallback;
}

// firstNonZeroField reads one numeric field from a single cached row. Inputs are
// a raw row, its schema, and accepted column aliases; processing accepts decimal
// and hexadecimal text; output is zero when the field is absent or zero.
std::uint64_t firstNonZeroField(
    const std::vector<std::wstring>& row,
    const std::vector<std::wstring>& columns,
    std::initializer_list<const wchar_t*> names) {
    std::uint64_t value = 0;
    if (hexToUInt64(rowFieldByName(row, columns, names), value) && value != 0) {
        return value;
    }
    return 0;
}

// flagEnabled checks whether a numeric bitmask contains a requested flag. Inputs
// are protocol flags and a flag value; output is true when all flag bits are set.
bool flagEnabled(const std::uint64_t flags, const std::uint64_t flag) {
    return (flags & flag) == flag;
}

// isZeroMaskText identifies empty dependency masks in their common display
// forms. Input is a cell string; output is true for blank, decimal zero, or
// hexadecimal zero variants.
bool isZeroMaskText(const std::wstring& text) {
    std::uint64_t value = 0;
    return text.empty() || (hexToUInt64(text, value) && value == 0);
}

// NamedMask describes one protocol bit with its C macro name and original
// KernelDock Chinese title. Inputs are static constants; processing helpers use
// it to render bitsets; no runtime ownership is stored here.
struct NamedMask {
    std::uint64_t mask;
    const wchar_t* name;
    const wchar_t* title;
};

constexpr NamedMask kDynCapabilityMasks[] = {
    { KSW_CAP_DYN_NTOS_ACTIVE, L"KSW_CAP_DYN_NTOS_ACTIVE", L"ntoskrnl profile 已激活" },
    { KSW_CAP_DYN_LXCORE_ACTIVE, L"KSW_CAP_DYN_LXCORE_ACTIVE", L"lxcore profile 已激活" },
    { KSW_CAP_OBJECT_TYPE_FIELDS, L"KSW_CAP_OBJECT_TYPE_FIELDS", L"对象类型字段" },
    { KSW_CAP_HANDLE_TABLE_DECODE, L"KSW_CAP_HANDLE_TABLE_DECODE", L"句柄表解码" },
    { KSW_CAP_PROCESS_OBJECT_TABLE, L"KSW_CAP_PROCESS_OBJECT_TABLE", L"进程 ObjectTable" },
    { KSW_CAP_THREAD_STACK_FIELDS, L"KSW_CAP_THREAD_STACK_FIELDS", L"线程栈字段" },
    { KSW_CAP_THREAD_IO_COUNTERS, L"KSW_CAP_THREAD_IO_COUNTERS", L"线程 I/O 计数" },
    { KSW_CAP_ALPC_FIELDS, L"KSW_CAP_ALPC_FIELDS", L"ALPC 字段" },
    { KSW_CAP_SECTION_CONTROL_AREA, L"KSW_CAP_SECTION_CONTROL_AREA", L"Section/ControlArea" },
    { KSW_CAP_PROCESS_PROTECTION_PATCH, L"KSW_CAP_PROCESS_PROTECTION_PATCH", L"进程保护修改" },
    { KSW_CAP_WSL_LXCORE_FIELDS, L"KSW_CAP_WSL_LXCORE_FIELDS", L"WSL/lxcore 字段" },
    { KSW_CAP_ETW_GUID_FIELDS, L"KSW_CAP_ETW_GUID_FIELDS", L"ETW GUID/Registration 字段" },
    { KSW_CAP_CALLBACK_NOTIFY_GLOBALS, L"KSW_CAP_CALLBACK_NOTIFY_GLOBALS", L"Callback Notify 全局 RVA" },
    { KSW_CAP_CALLBACK_REGISTRY_GLOBALS, L"KSW_CAP_CALLBACK_REGISTRY_GLOBALS", L"Registry Callback 全局 RVA" },
    { KSW_CAP_CALLBACK_OBJECT_FIELDS, L"KSW_CAP_CALLBACK_OBJECT_FIELDS", L"Object Callback 结构偏移" },
    { KSW_CAP_PROCESS_LIST_FIELDS, L"KSW_CAP_PROCESS_LIST_FIELDS", L"进程链表字段" },
    { KSW_CAP_THREAD_LIST_FIELDS, L"KSW_CAP_THREAD_LIST_FIELDS", L"线程链表字段" },
    { KSW_CAP_CID_TABLE_WALK, L"KSW_CAP_CID_TABLE_WALK", L"CID 表遍历" },
    { KSW_CAP_KERNEL_MODULE_LIST_FIELDS, L"KSW_CAP_KERNEL_MODULE_LIST_FIELDS", L"内核模块链表字段" },
    { KSW_CAP_DRIVER_OBJECT_FIELDS, L"KSW_CAP_DRIVER_OBJECT_FIELDS", L"驱动对象字段" },
    { KSW_CAP_KERNEL_GLOBALS, L"KSW_CAP_KERNEL_GLOBALS", L"内核全局 RVA" },
};

constexpr NamedMask kSecurityPolicyMasks[] = {
    { KSWORD_ARK_SECURITY_POLICY_FLAG_ACTIVE, L"POLICY_ACTIVE", L"安全策略启用" },
    { KSWORD_ARK_SECURITY_POLICY_ALLOW_MUTATING_ACTIONS, L"ALLOW_MUTATING_ACTIONS", L"允许进程修改动作" },
    { KSWORD_ARK_SECURITY_POLICY_ALLOW_FILE_DELETE, L"ALLOW_FILE_DELETE", L"允许文件删除" },
    { KSWORD_ARK_SECURITY_POLICY_ALLOW_CALLBACK_CONTROL, L"ALLOW_CALLBACK_CONTROL", L"允许回调控制" },
    { KSWORD_ARK_SECURITY_POLICY_ALLOW_PROCESS_PROTECTION, L"ALLOW_PROCESS_PROTECTION", L"允许进程保护修改" },
    { KSWORD_ARK_SECURITY_POLICY_ALLOW_KERNEL_SNAPSHOTS, L"ALLOW_KERNEL_SNAPSHOTS", L"允许内核快照" },
    { KSWORD_ARK_SECURITY_POLICY_REQUIRE_CONFIRMATION, L"REQUIRE_CONFIRMATION", L"要求确认" },
    { KSWORD_ARK_SECURITY_POLICY_DENY_CRITICAL_PROCESS, L"DENY_CRITICAL_PROCESS", L"拒绝关键进程" },
    { KSWORD_ARK_SECURITY_POLICY_ADVANCED_MODE, L"ADVANCED_MODE", L"高级模式" },
};

constexpr NamedMask kFeatureFlagMasks[] = {
    { KSWORD_ARK_FEATURE_FLAG_REQUIRES_DYNDATA, L"Requires DynData", L"需要 DynData" },
    { KSWORD_ARK_FEATURE_FLAG_MUTATING, L"Mutating", L"修改性操作" },
    { KSWORD_ARK_FEATURE_FLAG_KERNEL_ONLY, L"Kernel Only", L"仅内核" },
    { KSWORD_ARK_FEATURE_FLAG_READ_ONLY, L"Read Only", L"只读" },
    { KSWORD_ARK_FEATURE_FLAG_POLICY_GATED, L"Policy Gated", L"受策略控制" },
};

// hexTextPadded formats numeric protocol values the same way the full
// KernelDock helpers did. Inputs are value and hex digits; output is uppercase
// 0x-prefixed text used in details/reports without mutating cached row values.
std::wstring hexTextPadded(const std::uint64_t value, const int digits) {
    std::wostringstream stream;
    stream << L"0x" << std::uppercase << std::hex << std::setw(digits) << std::setfill(L'0') << value;
    return stream.str();
}

// namedMaskText renders a protocol bitset as "MACRO (Chinese)" entries. Inputs are
// a mask and table; processing preserves original KernelDock names; output is
// "None" when no known bit is enabled.
std::wstring namedMaskText(const std::uint64_t mask, const NamedMask* items, const std::size_t count) {
    std::wstring text;
    for (std::size_t index = 0; index < count; ++index) {
        const NamedMask& item = items[index];
        if ((mask & item.mask) != item.mask) {
            continue;
        }
        if (!text.empty()) {
            text += L", ";
        }
        text += item.name;
        text += L" (";
        text += item.title;
        text += L")";
    }
    return text.empty() ? L"None" : text;
}

// dynCapabilityNames renders KSW_CAP_* bits. Input is a 64-bit mask; output is
// the original capability name list used by DynData and DriverStatus pages.
std::wstring dynCapabilityNames(const std::uint64_t mask) {
    return namedMaskText(mask, kDynCapabilityMasks, std::size(kDynCapabilityMasks));
}

// securityPolicyNames renders KSWORD_ARK_SECURITY_POLICY_* bits. Input is a
// 32-bit policy mask; output matches the original DriverStatus detail text.
std::wstring securityPolicyNames(const std::uint32_t mask) {
    return namedMaskText(mask, kSecurityPolicyMasks, std::size(kSecurityPolicyMasks));
}

// featureFlagNames renders KSWORD_ARK_FEATURE_FLAG_* bits. Input is a 32-bit
// feature mask; output mirrors the original capability detail panel.
std::wstring featureFlagNames(const std::uint32_t mask) {
    return namedMaskText(mask, kFeatureFlagMasks, std::size(kFeatureFlagMasks));
}

// disabledDynCapabilitySummary lists the Chinese names of capability bits that
// are not enabled. Input is the global DynData capability mask; output is "none"
// when all known bits are active.
std::wstring disabledDynCapabilitySummary(const std::uint64_t mask) {
    std::wstring text;
    for (const NamedMask& item : kDynCapabilityMasks) {
        if ((mask & item.mask) == item.mask) {
            continue;
        }
        if (!text.empty()) {
            text += L"、";
        }
        text += item.title;
    }
    return text.empty() ? L"无" : text;
}

// dynDataStatusFlagsText renders KSW_DYN_STATUS_FLAG_* in the same English
// badge style as the full KernelDock. Input is status flags; output is "None" if empty.
std::wstring dynDataStatusFlagsText(const std::uint32_t flags) {
    std::vector<std::wstring> parts;
    if (flagEnabled(flags, KSW_DYN_STATUS_FLAG_INITIALIZED)) { parts.push_back(L"Initialized"); }
    if (flagEnabled(flags, KSW_DYN_STATUS_FLAG_NTOS_ACTIVE)) { parts.push_back(L"NtosActive"); }
    if (flagEnabled(flags, KSW_DYN_STATUS_FLAG_LXCORE_ACTIVE)) { parts.push_back(L"LxcoreActive"); }
    if (flagEnabled(flags, KSW_DYN_STATUS_FLAG_EXTRA_ACTIVE)) { parts.push_back(L"ExtraActive"); }
    if (flagEnabled(flags, KSW_DYN_STATUS_FLAG_PDB_PROFILE_ACTIVE)) { parts.push_back(L"PdbProfileActive"); }
    if (flagEnabled(flags, KSW_DYN_STATUS_FLAG_CALLBACK_PROFILE_ACTIVE)) { parts.push_back(L"CallbackProfileActive"); }
    std::wstring text;
    for (const std::wstring& part : parts) {
        if (!text.empty()) {
            text += L", ";
        }
        text += part;
    }
    return text.empty() ? L"None" : text;
}

// featureStateText normalizes numeric driver feature states. Inputs are state
// id and optional fallback text; output follows the original DriverStatus table.
std::wstring featureStateText(const std::uint32_t state, const std::wstring& fallbackText) {
    switch (state) {
    case KSWORD_ARK_FEATURE_STATE_AVAILABLE: return L"Available";
    case KSWORD_ARK_FEATURE_STATE_UNAVAILABLE: return L"Unavailable";
    case KSWORD_ARK_FEATURE_STATE_DEGRADED: return L"Degraded";
    case KSWORD_ARK_FEATURE_STATE_DENIED_BY_POLICY: return L"Denied by policy";
    default: return fallbackText.empty() ? L"Unknown" : fallbackText;
    }
}

// setTabText inserts one tab item. Inputs are target tab, index and caption;
// processing sends TCM_INSERTITEMW; no value is returned.
void setTabText(HWND tab, int index, const std::wstring& text) {
    TCITEMW item{};
    item.mask = TCIF_TEXT;
    item.pszText = const_cast<LPWSTR>(text.c_str());
    ::SendMessageW(tab, TCM_INSERTITEMW, static_cast<WPARAM>(index), reinterpret_cast<LPARAM>(&item));
}

// Width returns a non-negative rectangle width. Input is a RECT; output is a
// pixel width safe for MoveWindow/ListView column sizing.
int width(const RECT& rect) {
    return rect.right > rect.left ? rect.right - rect.left : 0;
}

// Height returns a non-negative rectangle height. Input is a RECT; output is a
// pixel height safe for MoveWindow.
int height(const RECT& rect) {
    return rect.bottom > rect.top ? rect.bottom - rect.top : 0;
}

// ClampInt restricts a calculated splitter coordinate or size to a safe pixel
// range. Inputs are value/min/max; output is the nearest in-range value.
int clampInt(const int value, const int minimum, const int maximum) {
    if (maximum < minimum) {
        return minimum;
    }
    return std::max(minimum, std::min(value, maximum));
}

// windowText reads a Win32 edit/static text into std::wstring. Input is a child
// HWND; processing uses GetWindowTextLengthW/GetWindowTextW; return is empty for
// null handles or empty controls.
std::wstring windowText(HWND hwnd) {
    if (!hwnd) {
        return {};
    }
    const int kLength = ::GetWindowTextLengthW(hwnd);
    if (kLength <= 0) {
        return {};
    }
    std::wstring text(static_cast<std::size_t>(kLength), L'\0');
    ::GetWindowTextW(hwnd, text.data(), kLength + 1);
    return text;
}

// setEditCueBanner assigns the Win32 Edit cue-banner text used as a lightweight
// cue banner. Inputs are the edit HWND and cue text; processing sends
// EM_SETCUEBANNER and intentionally ignores failure on older controls; no value
// is returned because the edit remains usable without the banner.
void setEditCueBanner(HWND edit, const wchar_t* text) {
    if (!edit) {
        return;
    }
    ::SendMessageW(edit, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(text != nullptr ? text : L""));
}

// hasColumn reports whether a dynamic result column has already been added.
// Inputs are the ordered column vector and a candidate name; output avoids
// duplicate ListView columns while preserving first-seen order.
bool hasColumn(const std::vector<std::wstring>& columns, const std::wstring& name) {
    return std::find(columns.begin(), columns.end(), name) != columns.end();
}

// emptyDetailTextForFeature returns the original KernelDock empty-detail text.
// Input is the active feature; output is shown when the table has no visible
// rows after a refresh or filter pass.
const wchar_t* emptyDetailTextForFeature(const KernelFeatureId featureId) {
    switch (featureId) {
    case KernelFeatureId::kAtomTable:
        return L"请选择一条原子记录查看详情。";
    case KernelFeatureId::kNtQueryLegacy:
        return L"请选择一条 NtQuery 结果查看详情。";
    case KernelFeatureId::kSsdt:
        return L"当前环境未返回可见 SSDT 条目。";
    case KernelFeatureId::kShadowSsdt:
        return L"当前环境未返回 SSSDT stub 解析结果。";
    case KernelFeatureId::kInlineHook:
        return L"当前过滤条件下未返回 Inline Hook 记录。";
    case KernelFeatureId::kIatEatHook:
        return L"当前过滤条件下未返回 IAT/EAT 记录。";
    case KernelFeatureId::kCallbackEnumeration:
        return L"当前环境未返回可见回调记录。";
    case KernelFeatureId::kNamedPipe:
        return L"说明：命名管道属于 NPFS 文件系统目录枚举，本页使用 NtOpenFile + NtQueryDirectoryFile 读取 \\Device\\NamedPipe。\r\n这不是 NtQueryDirectoryObject 下钻，也不是系统句柄表枚举。";
    case KernelFeatureId::kObjectDirectoryRecursive:
        return L"输入根路径后点击刷新。";
    case KernelFeatureId::kDynData:
        return L"请选择一条动态偏移字段查看详情。";
    case KernelFeatureId::kDriverStatus:
        return L"当前筛选条件下没有驱动能力记录。";
    default:
        return L"";
    }
}

// containsCaseInsensitive checks whether text contains a fragment without case
// sensitivity. Inputs are display strings; output is true for empty fragments or
// any case-insensitive substring match.
bool containsCaseInsensitive(std::wstring text, std::wstring fragment) {
    if (fragment.empty()) {
        return true;
    }
    std::transform(text.begin(), text.end(), text.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(std::towlower(ch));
    });
    std::transform(fragment.begin(), fragment.end(), fragment.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(std::towlower(ch));
    });
    return text.find(fragment) != std::wstring::npos;
}

// columnWidth returns a practical default width for a kernel result column.
// Input is a column title; output is a compact but readable ListView width.
int columnWidth(const std::wstring& name) {
    if (name == L"#") {
        return 52;
    }
    if (name == L"字段" || name == L"功能") {
        return 260;
    }
    if (name == L"Path" || name == L"NtPath" || name == L"Target" || name == L"Detail" || name == L"Module" || name == L"TargetModule" ||
        name == L"路径/说明" || name == L"符号链接目标" || name == L"完整路径" || name == L"目标路径" ||
        name == L"targetPath" || name == L"fullPath" || name == L"dosCandidate" || name == L"Win32Path" ||
        name == L"模块" || name == L"目标模块" || name == L"原因" || name == L"导入模块") {
        if (name == L"完整路径" || name == L"目标路径") {
            return 320;
        }
        return 260;
    }
    if (name == L"服务名" || name == L"函数" || name == L"函数/序号") {
        return 240;
    }
    if (name == L"Function" || name == L"Name" || name == L"objectName" || name == L"linkName" ||
        name == L"Pipe" || name == L"Pipe Name" || name == L"Type" || name == L"objectType" || name == L"Status" ||
        name == L"函数" || name == L"名称" || name == L"对象名称" || name == L"类型" || name == L"对象类型" ||
        name == L"状态" || name == L"服务名") {
        return 180;
    }
    if (name == L"Parent" || name == L"Source" || name == L"Directory" || name == L"directoryPath" ||
        name == L"sourceDirectory" || name == L"目录路径" || name == L"来源目录") {
        return name == L"目录路径" ? 190 : 220;
    }
    if (name == L"Address" || name == L"Target" || name == L"Service" || name == L"Zw" || name == L"Callback" ||
        name == L"函数地址" || name == L"目标地址" || name == L"回调/对象地址" || name == L"表项地址" ||
        name == L"Stub地址" || name == L"Zw导出地址" || name == L"服务例程" || name == L"当前目标" ||
        name == L"期望目标" || name == L"Thunk/EAT项") {
        return 180;
    }
    if (name == L"索引") {
        return 90;
    }
    if (name == L"偏移" || name == L"类型" || name == L"类别" || name == L"状态" || name == L"策略" ||
        name == L"所需DynData" || name == L"已满足DynData") {
        return name == L"状态" ? 260 : 140;
    }
    if (name == L"能力提示") {
        return 320;
    }
    return 130;
}

// setClipboardText copies Unicode text to the process clipboard. Input is the
// text to copy; processing owns the global memory after SetClipboardData; no
// value is returned.
void setClipboardText(HWND owner, const std::wstring& text) {
    if (!::OpenClipboard(owner)) {
        return;
    }
    ::EmptyClipboard();
    const SIZE_T kBytes = (text.size() + 1) * sizeof(wchar_t);
    HGLOBAL memory = ::GlobalAlloc(GMEM_MOVEABLE, kBytes);
    if (memory) {
        void* target = ::GlobalLock(memory);
        if (target) {
            std::memcpy(target, text.c_str(), kBytes);
            ::GlobalUnlock(memory);
            ::SetClipboardData(CF_UNICODETEXT, memory);
            memory = nullptr;
        }
        if (memory) {
            ::GlobalFree(memory);
        }
    }
    ::CloseClipboard();
}

// getClipboardText reads Unicode text from the process clipboard. Input is the
// owner HWND used for OpenClipboard; processing copies CF_UNICODETEXT into a
// std::wstring before releasing the global handle; output is empty on failure.
std::wstring getClipboardText(HWND owner) {
    if (!::OpenClipboard(owner)) {
        return {};
    }
    std::wstring text;
    HANDLE data = ::GetClipboardData(CF_UNICODETEXT);
    if (data) {
        const wchar_t* raw = static_cast<const wchar_t*>(::GlobalLock(data));
        if (raw) {
            text = raw;
            ::GlobalUnlock(data);
        }
    }
    ::CloseClipboard();
    return text;
}

// listViewText reads one cell from a report ListView. Inputs are list HWND, row
// and column indexes; output is the current display text.
std::wstring listViewText(HWND list, const int row, const int column) {
    if (!list || row < 0 || column < 0) {
        return {};
    }
    std::wstring text(4096, L'\0');
    LVITEMW item{};
    item.iSubItem = column;
    item.cchTextMax = static_cast<int>(text.size());
    item.pszText = text.data();
    ::SendMessageW(list, LVM_GETITEMTEXTW, static_cast<WPARAM>(row), reinterpret_cast<LPARAM>(&item));
    text.resize(std::wcslen(text.c_str()));
    return text;
}

// headerColumnCount returns the number of visible ListView columns. Input is a
// ListView HWND; output is zero when no header exists.
int headerColumnCount(HWND list) {
    HWND header = ListView_GetHeader(list);
    return header ? Header_GetItemCount(header) : 0;
}

// buildListViewSelectionTsv serializes selected rows from any report ListView.
// Inputs are the list and includeHeader flag; processing reads visible text
// exactly as displayed; output is a tab-separated string suitable for clipboard
// or file export.
std::wstring buildListViewSelectionTsv(HWND list, const bool includeHeader) {
    if (!list) {
        return {};
    }
    const int kColumns = headerColumnCount(list);
    const int kRows = ListView_GetItemCount(list);
    std::wstring text;
    if (includeHeader) {
        for (int column = 0; column < kColumns; ++column) {
            if (column > 0) {
                text += L'\t';
            }
            wchar_t headerText[256]{};
            LVCOLUMNW lvColumn{};
            lvColumn.mask = LVCF_TEXT;
            lvColumn.pszText = headerText;
            lvColumn.cchTextMax = static_cast<int>(std::size(headerText));
            ListView_GetColumn(list, column, &lvColumn);
            text += headerText;
        }
    }
    bool wroteRow = includeHeader;
    for (int row = 0; row < kRows; ++row) {
        if (ListView_GetItemState(list, row, LVIS_SELECTED) == 0) {
            continue;
        }
        if (wroteRow) {
            text += L"\r\n";
        }
        for (int column = 0; column < kColumns; ++column) {
            if (column > 0) {
                text += L'\t';
            }
            text += listViewText(list, row, column);
        }
        wroteRow = true;
    }
    return text;
}


// rowFieldByName reads a named value from a cached dynamic row. Inputs are a row,
// the current column names and one or more accepted column aliases; processing is
// case-insensitive and preserves the original display value; output is empty when
// no alias is present or the selected cell is blank.
std::wstring rowFieldByName(const std::vector<std::wstring>& row,
    const std::vector<std::wstring>& columns,
    std::initializer_list<const wchar_t*> names) {
    for (const wchar_t* name : names) {
        for (std::size_t column = 0; column < columns.size() && column < row.size(); ++column) {
            if (_wcsicmp(columns[column].c_str(), name) == 0 && !row[column].empty()) {
                return row[column];
            }
        }
    }
    return {};
}

// isObjectNamespaceFeature reports whether a feature belongs to the original
// KernelDock 'Object Namespace' group. Inputs are stable feature IDs; output drives
// the dedicated tree/table renderer instead of the generic result grid.
bool isObjectNamespaceFeature(const KernelFeatureId featureId) {
    switch (featureId) {
    case KernelFeatureId::kObjectNamespaceOverview:
    case KernelFeatureId::kObjectDirectoryRecursive:
    case KernelFeatureId::kNamedPipe:
    case KernelFeatureId::kBaseNamedObjects:
    case KernelFeatureId::kSymbolicLink:
    case KernelFeatureId::kDeviceDriverObjects:
    case KernelFeatureId::kObjectTypeMatrix:
    case KernelFeatureId::kCommunicationEndpoint:
        return true;
    default:
        return false;
    }
}

// usesObjectNamespaceTreeIndexColumn is retained for old call sites but now
// always reports false. The original KernelDock object namespace and directory
// recursive pages are QTreeWidget pages with visible tree columns only; they do
// not expose a synthetic "#" column.
bool usesObjectNamespaceTreeIndexColumn(const KernelFeatureId featureId) {
    (void)featureId;
    return false;
}

// isKernelHookFeature reports whether a feature uses the original KernelDock
// SSDT/SSSDT/Inline/IAT hook split layout. Input is a feature id; output drives
// the compact Win32 toolbar plus table/detail split.
bool isKernelHookFeature(const KernelFeatureId featureId) {
    return featureId == KernelFeatureId::kSsdt ||
        featureId == KernelFeatureId::kShadowSsdt ||
        featureId == KernelFeatureId::kInlineHook ||
        featureId == KernelFeatureId::kIatEatHook;
}

// isR0TableDetailFeature reports pages that use the same vertical table/detail
// splitter as their source dock pages. Input is a stable feature id; output is
// true when the user must be able to resize the result table and detail editor.
bool isR0TableDetailFeature(const KernelFeatureId featureId) {
    switch (featureId) {
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
    case KernelFeatureId::kMinifilterBypassPids:
    case KernelFeatureId::kKernelTimerDpc:
    case KernelFeatureId::kIoctlRegistry:
        return true;
    default:
        return false;
    }
}

// isR0OriginalNoPopupFeature identifies source pages whose tables did not own a
// row context menu. Inputs are feature ids; output true means the Win32 port
// should swallow WM_CONTEXTMENU instead of appending generic kernel actions.
bool isR0OriginalNoPopupFeature(const KernelFeatureId featureId) {
    switch (featureId) {
    case KernelFeatureId::kKernelExecutableMemory:
    case KernelFeatureId::kKernelMemoryEvidence:
    case KernelFeatureId::kProcessCrossView:
    case KernelFeatureId::kThreadCrossView:
    case KernelFeatureId::kDriverIntegrity:
    case KernelFeatureId::kKernelCpuIntegrity:
    case KernelFeatureId::kCpuHardwareSnapshot:
    case KernelFeatureId::kPhysicalMemoryLayout:
    case KernelFeatureId::kKeyboardHotkeys:
    case KernelFeatureId::kKeyboardHooks:
    case KernelFeatureId::kDynDataCapabilities:
        return true;
    default:
        return false;
    }
}

// isOriginalDetailPreferredFeature reports pages whose original KernelDock
// detail editor stored a complete detailText per source row. Input is a feature
// id; output controls copy/detail behavior so Win32 menus do not wrap those
// details with generic row labels.
bool isOriginalDetailPreferredFeature(const KernelFeatureId featureId) {
    return isKernelHookFeature(featureId) ||
        featureId == KernelFeatureId::kCallbackEnumeration ||
        featureId == KernelFeatureId::kAtomTable ||
        featureId == KernelFeatureId::kNtQueryLegacy;
}

// kernelHookVisibleColumnIndices returns the ListView column indices that match
// the original KernelDock SSDT/SSSDT/Inline/IAT-EAT table headers. Inputs are
// the feature id and current dynamic column schema; processing skips synthetic
// "#" and hidden diagnostic columns; output is used by Win32 copy/menu code.
std::vector<int> kernelHookVisibleColumnIndices(
    const KernelFeatureId featureId,
    const std::vector<std::wstring>& columns) {
    std::vector<int> indices;
    if (!isKernelHookFeature(featureId)) {
        return indices;
    }
    const std::vector<std::wstring> kCanonical = canonicalColumnNames(featureId);
    indices.reserve(kCanonical.size());
    for (const std::wstring& name : kCanonical) {
        for (int index = 0; index < static_cast<int>(columns.size()); ++index) {
            if (_wcsicmp(columns[static_cast<std::size_t>(index)].c_str(), name.c_str()) == 0) {
                indices.push_back(index);
                break;
            }
        }
    }
    return indices;
}

// canonicalVisibleColumnIndices returns the original table columns for pages
// whose Win32 rows also carry hidden protocol fields. Inputs are the feature id
// and current dynamic schema; processing maps canonicalColumnNames back to
// actual ListView indices; output is empty for pages that should copy every
// column.
std::vector<int> canonicalVisibleColumnIndices(
    const KernelFeatureId featureId,
    const std::vector<std::wstring>& columns) {
    if (featureId != KernelFeatureId::kCallbackEnumeration &&
        featureId != KernelFeatureId::kDynData &&
        featureId != KernelFeatureId::kDriverStatus) {
        return {};
    }

    std::vector<int> indices;
    const std::vector<std::wstring> kCanonical = canonicalColumnNames(featureId);
    indices.reserve(kCanonical.size());
    for (const std::wstring& name : kCanonical) {
        for (int index = 0; index < static_cast<int>(columns.size()); ++index) {
            if (_wcsicmp(columns[static_cast<std::size_t>(index)].c_str(), name.c_str()) == 0) {
                indices.push_back(index);
                break;
            }
        }
    }
    return indices;
}

// preferredCopyColumnIndices chooses the column set that should participate in
// row/header copy operations. Inputs are the active feature and current schema;
// output preserves the original KernelDock visible table contract while hidden
// Win32 protocol fields remain available for context menu actions.
std::vector<int> preferredCopyColumnIndices(
    const KernelFeatureId featureId,
    const std::vector<std::wstring>& columns) {
    std::vector<int> indices = kernelHookVisibleColumnIndices(featureId, columns);
    if (!indices.empty()) {
        return indices;
    }
    return canonicalVisibleColumnIndices(featureId, columns);
}

// isKernelHookVisibleColumn reports whether a dynamic column should be shown in
// original hook tables. Inputs are the feature id and a display column name;
// output hides R0 capability, hidden address/detail, and synthetic columns while
// keeping the exact original KernelDock headers visible.
bool isKernelHookVisibleColumn(const KernelFeatureId featureId, const std::wstring& name) {
    if (!isKernelHookFeature(featureId)) {
        return true;
    }
    const std::vector<std::wstring> kCanonical = canonicalColumnNames(featureId);
    return std::any_of(kCanonical.begin(), kCanonical.end(), [&name](const std::wstring& column) {
        return _wcsicmp(column.c_str(), name.c_str()) == 0;
    });
}

// hasKernelHookDisplayValues checks whether a row contains at least one value in
// the original visible hook columns. Inputs are a row, feature id, and current
// schema; output lets the UI hide injected R0 capability/status rows without
// dropping the hidden detail/action data on real rows.
bool hasKernelHookDisplayValues(
    const KernelFeatureId featureId,
    const std::vector<std::wstring>& columns,
    const std::vector<std::wstring>& row) {
    const std::vector<int> kIndices = kernelHookVisibleColumnIndices(featureId, columns);
    for (const int kIndex : kIndices) {
        if (kIndex >= 0 && kIndex < static_cast<int>(row.size()) && !row[static_cast<std::size_t>(kIndex)].empty()) {
            return true;
        }
    }
    return false;
}

// hasNonEmptyField checks whether a cached row carries at least one meaningful
// field. Inputs are the row, its column schema, and candidate field names; output
// lets the object namespace renderer hide generic diagnostic rows from the tree.
bool hasNonEmptyField(const std::vector<std::wstring>& row,
    const std::vector<std::wstring>& columns,
    std::initializer_list<const wchar_t*> names) {
    return !rowFieldByName(row, columns, names).empty();
}

// mergeRowText concatenates all non-empty fields of one cached result row.
// Inputs are row cells; processing joins values with a stable separator; output
// is used by local filter predicates without changing the backing result data.
std::wstring mergeRowText(const std::vector<std::wstring>& row) {
    std::wstring merged;
    for (const std::wstring& value : row) {
        if (value.empty()) {
            continue;
        }
        if (!merged.empty()) {
            merged += L" | ";
        }
        merged += value;
    }
    return merged;
}

// lowerInvariantKey normalizes object-manager paths for TreeView lookup. Inputs
// are display strings from query rows; processing lowercases only for map keys
// and leaves the original UI text untouched; output is empty when no key exists.
std::wstring lowerInvariantKey(std::wstring text) {
    std::transform(text.begin(), text.end(), text.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(std::towlower(ch));
    });
    return text;
}

// parentObjectPath derives a native parent path from a full object path when a
// row lacks an explicit Parent field. Input is a path like "\Device\Foo";
// output is "\Device", "\" for direct root children, or empty for invalid text.
std::wstring parentObjectPath(const std::wstring& path) {
    if (path.empty() || path == L"\\") {
        return {};
    }
    const std::size_t kSlash = path.find_last_of(L'\\');
    if (kSlash == std::wstring::npos) {
        return {};
    }
    if (kSlash == 0) {
        return L"\\";
    }
    return path.substr(0, kSlash);
}

// leafObjectName returns the display leaf for synthetic TreeView directory
// nodes. Input is a native object path; output is "\" for the root, the last
// component for normal paths, or the original text when no separator exists.
std::wstring leafObjectName(const std::wstring& path) {
    if (path.empty() || path == L"\\") {
        return L"\\";
    }
    const std::size_t kSlash = path.find_last_of(L'\\');
    if (kSlash == std::wstring::npos || kSlash + 1 >= path.size()) {
        return path;
    }
    return path.substr(kSlash + 1);
}

// listViewInsertRow appends one row to a report ListView. Inputs are the target
// control and ordered cells; processing fills subitems after inserting column 0;
// there is no return value because the control stores the display state.
void listViewInsertRow(HWND list, const std::vector<std::wstring>& cells) {
    if (!list || cells.empty()) {
        return;
    }
    LVITEMW item{};
    item.mask = LVIF_TEXT;
    item.iItem = ListView_GetItemCount(list);
    item.iSubItem = 0;
    item.pszText = const_cast<LPWSTR>(cells[0].c_str());
    const int kInserted = ListView_InsertItem(list, &item);
    if (kInserted < 0) {
        return;
    }
    for (int column = 1; column < static_cast<int>(cells.size()); ++column) {
        ListView_SetItemText(list, kInserted, column, const_cast<LPWSTR>(cells[static_cast<std::size_t>(column)].c_str()));
    }
}

// appendReportLine appends one diagnostic key/value pair. Inputs are a stream,
// a label and a value; processing skips empty values so copied reports stay
// compact like the original diagnostic reports; there is no return value.
void appendReportLine(std::wostringstream& report, const wchar_t* label, const std::wstring& value) {
    if (!value.empty()) {
        report << label << L": " << value << L"\r\n";
    }
}

// addListColumn inserts a report column into an auxiliary ListView. Inputs are a
// target ListView, index, title and width; processing is a direct Win32 column
// insert; no value is returned.
void addListColumn(HWND list, const int index, const wchar_t* title, const int width) {
    if (!list) {
        return;
    }
    LVCOLUMNW column{};
    column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
    column.fmt = LVCFMT_LEFT;
    column.cx = width;
    column.pszText = const_cast<LPWSTR>(title);
    ListView_InsertColumn(list, index, &column);
}

// addListRow appends one row to an auxiliary ListView. Inputs are target list
// and ordered cell text; processing inserts the first cell then subitems; output
// is only visible UI state.
void addListRow(HWND list, const std::vector<std::wstring>& cells) {
    if (!list || cells.empty()) {
        return;
    }
    LVITEMW item{};
    item.mask = LVIF_TEXT;
    item.iItem = ListView_GetItemCount(list);
    item.iSubItem = 0;
    item.pszText = const_cast<LPWSTR>(cells[0].c_str());
    const int kRow = ListView_InsertItem(list, &item);
    for (int column = 1; kRow >= 0 && column < static_cast<int>(cells.size()); ++column) {
        ListView_SetItemText(list, kRow, column, const_cast<LPWSTR>(cells[static_cast<std::size_t>(column)].c_str()));
    }
}

// configureReportList applies compact ListView behavior used by all Win32
// kernel subpanels. Input is a ListView HWND; output is style state only.
void configureReportList(HWND list) {
    if (!list) {
        return;
    }
    ListView_SetExtendedListViewStyleEx(list,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP | LVS_EX_GRIDLINES,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP | LVS_EX_GRIDLINES);
}

// escapeConfigField stores a local callback rule field in a tab-separated
// lightweight file. Input is arbitrary UI text; output escapes separators and
// line breaks without depending on JSON or third-party parsers.
std::wstring escapeConfigField(const std::wstring& text) {
    std::wstring escaped;
    escaped.reserve(text.size());
    for (const wchar_t kCh : text) {
        switch (kCh) {
        case L'\\': escaped += L"\\\\"; break;
        case L'\t': escaped += L"\\t"; break;
        case L'\r': escaped += L"\\r"; break;
        case L'\n': escaped += L"\\n"; break;
        default: escaped.push_back(kCh); break;
        }
    }
    return escaped;
}

// unescapeConfigField reverses escapeConfigField. Input is one serialized field;
// output is the UI text used by the local callback rule editor.
std::wstring unescapeConfigField(const std::wstring& text) {
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
            default:
                value.push_back(kCh);
                break;
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

// splitTabLine splits a callback config line while preserving empty fields.
// Input is a single CR/LF-free line; output is tab-separated fields.
std::vector<std::wstring> splitTabLine(const std::wstring& line) {
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

// parseUnsigned converts a serialized unsigned field. Input is decimal text;
// output is fallback on invalid input so importing cannot crash the UI.
std::uint32_t parseUnsigned(const std::wstring& text, const std::uint32_t fallback) {
    if (text.empty()) {
        return fallback;
    }
    wchar_t* end = nullptr;
    const unsigned long kValue = std::wcstoul(text.c_str(), &end, 10);
    return end != text.c_str() ? static_cast<std::uint32_t>(kValue) : fallback;
}

// parseSigned converts a serialized signed field. Input is decimal text; output
// is fallback when parsing fails.
int parseSigned(const std::wstring& text, const int fallback) {
    if (text.empty()) {
        return fallback;
    }
    wchar_t* end = nullptr;
    const long kValue = std::wcstol(text.c_str(), &end, 10);
    return end != text.c_str() ? static_cast<int>(kValue) : fallback;
}

// parseUnsigned64Value converts decimal or 0x-prefixed text into a 64-bit value.
// Inputs are an edit-control string and an output reference; processing trims
// common whitespace and accepts the same address forms used by the original
// MemoryDock pages; output is true only when the whole token parsed.
bool parseUnsigned64Value(const std::wstring& text, std::uint64_t& valueOut) {
    std::wstring trimmed = text;
    trimmed.erase(trimmed.begin(), std::find_if(trimmed.begin(), trimmed.end(), [](wchar_t ch) {
        return !std::iswspace(ch);
    }));
    trimmed.erase(std::find_if(trimmed.rbegin(), trimmed.rend(), [](wchar_t ch) {
        return !std::iswspace(ch);
    }).base(), trimmed.end());
    if (trimmed.empty()) {
        return false;
    }
    wchar_t* end = nullptr;
    const int kBase = trimmed.size() > 2 && trimmed[0] == L'0' && (trimmed[1] == L'x' || trimmed[1] == L'X') ? 16 : 10;
    const unsigned long long kValue = std::wcstoull(trimmed.c_str(), &end, kBase);
    if (end == trimmed.c_str() || *end != L'\0') {
        return false;
    }
    valueOut = static_cast<std::uint64_t>(kValue);
    return true;
}

// isNavigableWin32OrUncPath accepts only unambiguous drive-rooted or UNC paths
// from callback file-monitor rows. Kernel device paths and extended/device
// namespaces deliberately stay display-only because this R3 browser must not
// guess a user-mode path for them.
bool isNavigableWin32OrUncPath(const std::wstring& path) {
    const bool kHasAsciiDriveLetter = path.size() >= 1U &&
        ((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z'));
    if (path.size() >= 3U && kHasAsciiDriveLetter && path[1] == L':' &&
        (path[2] == L'\\' || path[2] == L'/')) {
        return true;
    }
    if (path.size() < 5U || path[0] != L'\\' || path[1] != L'\\' ||
        path[2] == L'?' || path[2] == L'.') {
        return false;
    }
    const std::size_t kServerEnd = path.find(L'\\', 2U);
    if (kServerEnd == std::wstring::npos || kServerEnd == 2U || kServerEnd + 1U >= path.size()) {
        return false;
    }
    const std::size_t kShareEnd = path.find(L'\\', kServerEnd + 1U);
    return kShareEnd != kServerEnd + 1U;
}

// fileMonitorContainingDirectory derives the safe directory context of a
// complete event path without touching the filesystem. FileView enumerates
// directories, not individual files, so forwarding an observed file pathname
// itself would always produce an invalid "file\\*" search pattern.
std::wstring fileMonitorContainingDirectory(const std::wstring& path) {
    if (!isNavigableWin32OrUncPath(path)) {
        return {};
    }
    std::wstring normalized = path;
    std::replace(normalized.begin(), normalized.end(), L'/', L'\\');
    if (normalized.back() == L'\\') {
        return normalized;
    }

    const std::size_t kLastSeparator = normalized.find_last_of(L'\\');
    if (kLastSeparator == std::wstring::npos) {
        return {};
    }
    const bool kDrivePath = normalized.size() >= 3U && normalized[1] == L':';
    if (kDrivePath && kLastSeparator == 2U) {
        return normalized.substr(0U, 3U);
    }
    if (!kDrivePath) {
        const std::size_t kServerSeparator = normalized.find(L'\\', 2U);
        if (kServerSeparator == std::wstring::npos) {
            return {};
        }
        if (kLastSeparator == kServerSeparator) {
            return normalized;
        }
    }
    return kLastSeparator > 0U ? normalized.substr(0U, kLastSeparator) : std::wstring{};
}

// isKernelMemoryHiddenColumn preserves R0/action fields while hiding them from
// the original MemoryDock-style list. Inputs are fixed display/raw column names;
// output is true when the ListView column width should be zero.
bool isKernelMemoryHiddenColumn(const std::wstring& name) {
    return name == L"RegionSize" ||
        name == L"Perm" ||
        name == L"Risk" ||
        name == L"OwnerKind" ||
        name == L"OwnerKindText" ||
        name == L"OwnerAddress" ||
        name == L"ModuleBase" ||
        name == L"ModuleSize" ||
        name == L"ModuleSizeText" ||
        name == L"Status" ||
        name == L"LastStatus" ||
        name == L"Kind" ||
        name == L"PageSize" ||
        name == L"Confidence" ||
        name == L"BigPoolTag" ||
        name == L"BigPoolFlags" ||
        name == L"SectionRva" ||
        name == L"SectionSize" ||
        name == L"SectionSizeText" ||
        name == L"Section" ||
        name == L"HashAlgorithm" ||
        name == L"SampleSize" ||
        name == L"Hash" ||
        name == L"HashText" ||
        name == L"Sample";
}

// isIntegrityHiddenColumn preserves raw R0 evidence fields while keeping the
// DriverIntegrity and CPU/IDT grids visually close to the original KernelDock
// tables. Input is a column name; output is true when the Win32 ListView column
// should be retained for detail/actions but hidden with width zero.
bool isIntegrityHiddenColumn(const std::wstring& name) {
    return name == L"Class" ||
        name == L"ClassText" ||
        name == L"Risk" ||
        name == L"RiskText" ||
        name == L"Source" ||
        name == L"SourceMask" ||
        name == L"SourceText" ||
        name == L"Confidence" ||
        name == L"Group" ||
        name == L"CPU" ||
        name == L"Vector" ||
        name == L"CpuVector" ||
        name == L"Object" ||
        name == L"ObjectAddress" ||
        name == L"Target" ||
        name == L"TargetAddress" ||
        name == L"OwnerBase" ||
        name == L"OwnerModuleBase" ||
        name == L"OwnerSize" ||
        name == L"OwnerModuleSize" ||
        name == L"OwnerModuleSizeText" ||
        name == L"OwnerModule" ||
        name == L"LastStatus";
}

// callbackRemoveClassForEnumClass maps one callback-enumeration row class to
// the R0 remove protocol class. Input is the hidden "Class" cell value; output
// is zero when no public remove path exists for that callback category.
std::uint32_t callbackRemoveClassForEnumClass(const std::uint32_t callbackClass) {
    switch (callbackClass) {
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_REGISTRY:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_REGISTRY;
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_PROCESS:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_PROCESS;
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_THREAD:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_THREAD;
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_IMAGE:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_IMAGE;
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_OBJECT:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_OBJECT;
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_MINIFILTER:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_MINIFILTER;
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_WFP_CALLOUT:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_WFP_CALLOUT;
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_ETW_PROVIDER:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_ETW_PROVIDER;
    default:
        return 0;
    }
}

// callbackEnumPrimaryRemoveValue selects the address/id that remove operations
// can send for one visible callback row. Inputs are selected-row text fields;
// output follows the original KernelDock priority for callback, registration,
// and raw storage values.
std::uint64_t callbackEnumPrimaryRemoveValue(
    const std::uint64_t callbackAddress,
    const std::uint64_t registrationAddress,
    const std::uint64_t rawStorageValue,
    const std::uint32_t fieldFlags) {
    if (callbackAddress != 0 &&
        ((fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_CALLBACK_ADDRESS) != 0 ||
            (fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_IDENTIFIER) != 0 ||
            (fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_HANDLE) != 0 ||
            (fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_REMOVABLE_CANDIDATE) != 0)) {
        return callbackAddress;
    }
    if (registrationAddress != 0 &&
        (fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_IDENTIFIER) != 0) {
        return registrationAddress;
    }
    return rawStorageValue != 0 ? rawStorageValue : registrationAddress;
}

// callbackEnumFallbackSource reports whether a callback row came from private
// unsupported/pattern diagnostics. Input is the shared source id; output drives
// experimental-only menu enablement without calling the driver.
bool callbackEnumFallbackSource(const std::uint32_t source) {
    return source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_PATTERN_SCAN ||
        source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_NOTIFY_ARRAY ||
        source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_REGISTRY_LIST ||
        source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_OBJECT_TYPE_LIST ||
        source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_UNSUPPORTED;
}

// callbackEnumSafeRemoveAllowed mirrors the original table menu policy for the
// public API path. Inputs are selected-row numeric/text fields; output is true
// only for a single verified/candidate row with a compatible request value.
bool callbackEnumSafeRemoveAllowed(
    const std::uint32_t callbackClass,
    const std::uint32_t status,
    const std::uint32_t source,
    const std::uint32_t fieldFlags,
    const std::uint32_t removeBehavior,
    const std::uint64_t requestValue,
    const std::wstring& removePolicy) {
    if (callbackRemoveClassForEnumClass(callbackClass) == 0 ||
        status != KSWORD_ARK_CALLBACK_ENUM_STATUS_OK ||
        requestValue == 0 ||
        containsCaseInsensitive(removePolicy, L"not removable") ||
        containsCaseInsensitive(removePolicy, L"不可移除") ||
        containsCaseInsensitive(removePolicy, L"experimental only")) {
        return false;
    }
    const bool kVerified = (fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_VERIFIED_REMOVE) != 0 ||
        (removeBehavior & KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_PUBLIC_API) != 0;
    const bool kCandidate = (fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_REMOVABLE_CANDIDATE) != 0 ||
        containsCaseInsensitive(removePolicy, L"candidate") ||
        containsCaseInsensitive(removePolicy, L"verified");
    const bool kPublicSource = source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PUBLIC_API ||
        source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_FLTMGR_ENUMERATION ||
        source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_WFP_MGMT_API ||
        source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_ETW_DYNDATA;
    return kVerified || kCandidate || kPublicSource;
}

// callbackEnumExperimentalUnlinkAllowed mirrors the original unlink menu policy.
// Inputs are selected-row numeric/text fields; output is false for diagnostics
// with no address-like storage or for explicitly non-removable rows.
bool callbackEnumExperimentalUnlinkAllowed(
    const std::uint32_t callbackClass,
    const std::uint32_t status,
    const std::uint32_t source,
    const std::uint32_t fieldFlags,
    const std::uint32_t removeBehavior,
    const std::uint64_t requestValue,
    const std::uint64_t contextAddress,
    const std::wstring& removePolicy) {
    if (callbackRemoveClassForEnumClass(callbackClass) == 0 ||
        status != KSWORD_ARK_CALLBACK_ENUM_STATUS_OK ||
        containsCaseInsensitive(removePolicy, L"not removable") ||
        containsCaseInsensitive(removePolicy, L"不可移除")) {
        return false;
    }
    const bool kHasAnyStorage = requestValue != 0 || contextAddress != 0;
    if (!kHasAnyStorage) {
        return false;
    }
    const bool kExperimental = (fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_EXPERIMENTAL_REMOVE) != 0 ||
        (removeBehavior & KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_EXPERIMENTAL_UNLINK) != 0 ||
        containsCaseInsensitive(removePolicy, L"experimental") ||
        containsCaseInsensitive(removePolicy, L"candidate") ||
        containsCaseInsensitive(removePolicy, L"verified");
    return kExperimental || callbackEnumFallbackSource(source);
}

// readWholeFileText reads a UTF-16LE-BOM or UTF-8 text file selected by the
// user. Inputs are path and error sink; output is decoded Unicode text.
std::wstring readWholeFileText(const std::wstring& path, std::wstring* errorText) {
    HANDLE file = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        if (errorText) {
            *errorText = L"无法打开文件，Win32=" + std::to_wstring(::GetLastError());
        }
        return {};
    }
    LARGE_INTEGER size{};
    if (!::GetFileSizeEx(file, &size) || size.QuadPart < 0 || size.QuadPart > 16 * 1024 * 1024) {
        if (errorText) {
            *errorText = L"文件大小不可用或超过 16MB。";
        }
        ::CloseHandle(file);
        return {};
    }
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size.QuadPart));
    DWORD read = 0;
    const BOOL kOk = bytes.empty() ? TRUE : ::ReadFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr);
    ::CloseHandle(file);
    if (!kOk || read != bytes.size()) {
        if (errorText) {
            *errorText = L"读取文件失败，Win32=" + std::to_wstring(::GetLastError());
        }
        return {};
    }
    if (bytes.size() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE) {
        const auto* wide = reinterpret_cast<const wchar_t*>(bytes.data() + 2);
        const std::size_t kWcharCount = (bytes.size() - 2) / sizeof(wchar_t);
        return std::wstring(wide, wide + kWcharCount);
    }
    const int kNeeded = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, reinterpret_cast<const char*>(bytes.data()), static_cast<int>(bytes.size()), nullptr, 0);
    if (kNeeded > 0) {
        std::wstring text(static_cast<std::size_t>(kNeeded), L'\0');
        ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, reinterpret_cast<const char*>(bytes.data()), static_cast<int>(bytes.size()), text.data(), kNeeded);
        return text;
    }
    const int kAnsiNeeded = ::MultiByteToWideChar(CP_ACP, 0, reinterpret_cast<const char*>(bytes.data()), static_cast<int>(bytes.size()), nullptr, 0);
    if (kAnsiNeeded <= 0) {
        if (errorText) {
            *errorText = L"无法按 UTF-8/ANSI 解码配置文件。";
        }
        return {};
    }
    std::wstring text(static_cast<std::size_t>(kAnsiNeeded), L'\0');
    ::MultiByteToWideChar(CP_ACP, 0, reinterpret_cast<const char*>(bytes.data()), static_cast<int>(bytes.size()), text.data(), kAnsiNeeded);
    return text;
}

// writeWholeFileText writes UTF-16LE with BOM. Inputs are path and text; output
// is success/failure and optional Win32 error message.
bool writeWholeFileText(const std::wstring& path, const std::wstring& text, std::wstring* errorText) {
    HANDLE file = ::CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        if (errorText) {
            *errorText = L"无法创建文件，Win32=" + std::to_wstring(::GetLastError());
        }
        return false;
    }
    const std::uint8_t kBom[] = { 0xFF, 0xFE };
    DWORD written = 0;
    BOOL ok = ::WriteFile(file, kBom, sizeof(kBom), &written, nullptr);
    if (ok) {
        ok = ::WriteFile(file, text.data(), static_cast<DWORD>(text.size() * sizeof(wchar_t)), &written, nullptr);
    }
    const DWORD kError = ok ? ERROR_SUCCESS : ::GetLastError();
    ::CloseHandle(file);
    if (!ok && errorText) {
        *errorText = L"写入文件失败，Win32=" + std::to_wstring(kError);
    }
    return ok != FALSE;
}

} // namespace

// KernelObjectNamespaceTreeNodeState is the per-TreeView node payload used by
// the Win32 object namespace port. Inputs are copied from the current table
// cache when the tree is rebuilt; processing stores this object behind
// TVITEM::lParam; return behavior is pointer-based selection with ownership kept
// by KernelPage::objectNamespaceTreeNodeStorage_.
struct KernelObjectNamespaceTreeNodeState {
    int rowIndex = -1;
    std::wstring nodeKind;
    std::wstring nodeName;
    std::wstring nodeType;
    std::wstring nodePath;
    std::wstring nodeDescription;
};

KernelPage::KernelPage() = default;
KernelPage::~KernelPage() = default;

void KernelPage::setInitialFeature(const KernelFeatureId featureId) noexcept {
    // Store the requested feature until WM_CREATE constructs primary and
    // secondary tabs. Input is a stable catalog id; no value is returned.
    initialFeatureId_ = featureId;
    hasInitialFeatureId_ = true;
}

HWND KernelPage::create(HWND parent, const int controlId, const RECT& bounds) {
    ensureKernelPageClass();
    hwnd_ = ::CreateWindowExW(
        0,
        kKernelPageClass,
        L"Kernel",
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        bounds.left,
        bounds.top,
        bounds.right - bounds.left,
        bounds.bottom - bounds.top,
        parent,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(controlId)),
        ::GetModuleHandleW(nullptr),
        this);
    return hwnd_;
}

LRESULT CALLBACK KernelPage::wndProc(HWND hwnd, const UINT msg, const WPARAM wParam, const LPARAM lParam) {
    KernelPage* page = reinterpret_cast<KernelPage*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (msg == WM_NCCREATE) {
        auto* create = reinterpret_cast<CREATESTRUCTW*>(lParam);
        page = static_cast<KernelPage*>(create->lpCreateParams);
        page->hwnd_ = hwnd;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(page));
    }

    if (page) {
        return page->handleMessage(hwnd, msg, wParam, lParam);
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK KernelPage::filterEditSubclassProc(HWND hwnd, const UINT msg, const WPARAM wParam, const LPARAM lParam,
    const UINT_PTR subclassId, const DWORD_PTR refData) {
    // filterEditSubclassProc gives the object-directory root edit the same
    // return-key refresh behavior as the original root-path edit. Inputs are the
    // edit HWND and normal subclass parameters; processing only intercepts Enter
    // while the active page is "Directory Recursion"; output otherwise delegates to the
    // default subclass proc.
    auto* page = reinterpret_cast<KernelPage*>(refData);
    if (msg == WM_KEYDOWN && wParam == VK_RETURN && page != nullptr) {
        const KernelFeatureDescriptor* descriptor = page->currentDescriptor();
        if (descriptor != nullptr && descriptor->id == KernelFeatureId::kObjectDirectoryRecursive) {
            page->refreshSelectedFeature();
            return 0;
        }
    }
    if (msg == WM_NCDESTROY) {
        ::RemoveWindowSubclass(hwnd, KernelPage::filterEditSubclassProc, subclassId);
    }
    return ::DefSubclassProc(hwnd, msg, wParam, lParam);
}

LRESULT KernelPage::handleMessage(HWND hwnd, const UINT msg, const WPARAM wParam, const LPARAM lParam) {
    switch (msg) {
    case WM_CREATE:
        queryTask_ = std::make_unique<ksword::ui::AsyncSnapshotTask<KernelOperationResult>>(hwnd, kMsgKernelQueryCompleted);
        actionTask_ = std::make_unique<ksword::ui::AsyncSnapshotTask<KernelOperationResult>>(hwnd, kMsgKernelActionCompleted);
        callbackAnswerTask_ = std::make_unique<ksword::ui::AsyncSnapshotTask<KernelOperationResult>>(hwnd, kMsgCallbackAnswerCompleted);
        callbackFileIoTask_ = std::make_unique<ksword::ui::AsyncSnapshotTask<CallbackFileIoResult>>(hwnd, kMsgCallbackFileIoCompleted);
        r0EvidenceFilterTask_ = std::make_unique<ksword::ui::AsyncSnapshotTask<KernelR0EvidenceSnapshot>>(hwnd, kMsgR0EvidenceFilterCompleted);
        callbackEventReceiver_ = std::make_unique<CallbackEventReceiver>(hwnd, kMsgCallbackEventReceived);
        createChildControls();
        populateTabs();
        layout();
        return 0;
    case WM_SIZE:
        layout();
        return 0;
    case kMsgKernelQueryCompleted:
        if (queryTask_ && queryTask_->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgKernelActionCompleted:
        if (actionTask_ && actionTask_->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgCallbackEventReceived:
    {
        std::unique_ptr<CallbackEventSnapshot> snapshot(reinterpret_cast<CallbackEventSnapshot*>(lParam));
        if (snapshot && callbackEventReceiver_ && callbackEventReceiver_->accepts(snapshot->generation)) {
            acceptCallbackEvent(std::move(*snapshot));
        }
        return 0;
    }
    case kMsgCallbackAnswerCompleted:
        if (callbackAnswerTask_ && callbackAnswerTask_->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgCallbackFileIoCompleted:
        if (callbackFileIoTask_ && callbackFileIoTask_->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgR0EvidenceFilterCompleted:
        if (r0EvidenceFilterTask_ && r0EvidenceFilterTask_->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case WM_TIMER:
        if (wParam == kTimerR0EvidenceFilter) {
            ::KillTimer(hwnd, kTimerR0EvidenceFilter);
            if (hasPendingR0EvidenceFilter_) {
                hasPendingR0EvidenceFilter_ = false;
                requestR0EvidenceRebuild(pendingR0EvidenceFeatureId_);
            }
            return 0;
        }
        break;
    case WM_SETCURSOR:
        if (LOWORD(lParam) == HTCLIENT && currentFeatureUsesVerticalSplitter()) {
            POINT cursor{};
            ::GetCursorPos(&cursor);
            ::ScreenToClient(hwnd_, &cursor);
            if (::PtInRect(&verticalSplitterRect_, cursor)) {
                ::SetCursor(::LoadCursorW(nullptr, IDC_SIZENS));
                return TRUE;
            }
        }
        break;
    case WM_LBUTTONDOWN:
    {
        POINT point{ GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
        if (currentFeatureUsesVerticalSplitter() && ::PtInRect(&verticalSplitterRect_, point)) {
            verticalSplitterDragging_ = true;
            ::SetCapture(hwnd_);
            ::SetCursor(::LoadCursorW(nullptr, IDC_SIZENS));
            return 0;
        }
        break;
    }
    case WM_MOUSEMOVE:
        if (verticalSplitterDragging_) {
            moveVerticalSplitterFromMouse(GET_Y_LPARAM(lParam));
            return 0;
        }
        break;
    case WM_LBUTTONUP:
        if (verticalSplitterDragging_) {
            verticalSplitterDragging_ = false;
            if (::GetCapture() == hwnd_) {
                ::ReleaseCapture();
            }
            moveVerticalSplitterFromMouse(GET_Y_LPARAM(lParam));
            return 0;
        }
        break;
    case WM_CAPTURECHANGED:
        if (reinterpret_cast<HWND>(lParam) != hwnd_) {
            verticalSplitterDragging_ = false;
        }
        break;
    case WM_COMMAND:
        if (LOWORD(wParam) == kIdRefresh && HIWORD(wParam) == BN_CLICKED) {
            refreshSelectedFeature();
            return 0;
        }
        if (LOWORD(wParam) == kIdLocate && HIWORD(wParam) == BN_CLICKED) {
            if (const KernelFeatureDescriptor* descriptor = currentDescriptor(); descriptor != nullptr && isObjectNamespaceFeature(descriptor->id)) {
                executeObjectNamespaceToolbarAction();
            } else {
                locateNextResult();
            }
            return 0;
        }
        if (LOWORD(wParam) == kIdIntegrityFillFromSelection && HIWORD(wParam) == BN_CLICKED) {
            fillIntegrityInputsFromSelection();
            return 0;
        }
        if (LOWORD(wParam) == kIdIntegrityCpuOnly && HIWORD(wParam) == BN_CLICKED) {
            refreshKernelCpuIntegrityFromDriverPage();
            return 0;
        }
        if ((LOWORD(wParam) == kIdFilterEdit || LOWORD(wParam) == kIdModuleFilterEdit) && HIWORD(wParam) == EN_CHANGE) {
            if (suppressFilterChange_) {
                return 0;
            }
            if (const KernelFeatureDescriptor* descriptor = currentDescriptor();
                descriptor != nullptr && isR0EvidenceFeature(descriptor->id) && !currentRawColumns_.empty()) {
                scheduleR0EvidenceFilter(descriptor->id);
                return 0;
            }
            if (const KernelFeatureDescriptor* descriptor = currentDescriptor();
                descriptor != nullptr &&
                (descriptor->id == KernelFeatureId::kSymbolicLink ||
                    descriptor->id == KernelFeatureId::kObjectNamespaceOverview ||
                    descriptor->id == KernelFeatureId::kObjectDirectoryRecursive ||
                    descriptor->id == KernelFeatureId::kBaseNamedObjects ||
                    descriptor->id == KernelFeatureId::kDeviceDriverObjects ||
                    descriptor->id == KernelFeatureId::kObjectTypeMatrix ||
                    descriptor->id == KernelFeatureId::kCommunicationEndpoint ||
                    descriptor->id == KernelFeatureId::kAtomTable ||
                    descriptor->id == KernelFeatureId::kDynData ||
                    descriptor->id == KernelFeatureId::kDriverStatus ||
                    descriptor->id == KernelFeatureId::kCallbackEnumeration ||
                    descriptor->id == KernelFeatureId::kKernelExecutableMemory ||
                    descriptor->id == KernelFeatureId::kKernelMemoryEvidence ||
                    descriptor->id == KernelFeatureId::kProcessCrossView ||
                    descriptor->id == KernelFeatureId::kThreadCrossView ||
                    descriptor->id == KernelFeatureId::kDriverIntegrity ||
                    descriptor->id == KernelFeatureId::kKernelCpuIntegrity ||
                    descriptor->id == KernelFeatureId::kCpuHardwareSnapshot ||
                    descriptor->id == KernelFeatureId::kPhysicalMemoryLayout ||
                    descriptor->id == KernelFeatureId::kMutationAudit ||
                    descriptor->id == KernelFeatureId::kKeyboardHotkeys ||
                    descriptor->id == KernelFeatureId::kKeyboardHooks ||
                    descriptor->id == KernelFeatureId::kDynDataCapabilities ||
                    descriptor->id == KernelFeatureId::kMinifilterBypassPids ||
                    descriptor->id == KernelFeatureId::kKernelTimerDpc ||
                    descriptor->id == KernelFeatureId::kIoctlRegistry ||
                    isKernelHookFeature(descriptor->id)) &&
                !currentRawColumns_.empty()) {
                currentColumns_ = currentRawColumns_;
                currentRows_ = currentRawRows_;
                if (isObjectNamespaceFeature(descriptor->id)) {
                    rebuildObjectNamespaceListFromCache(descriptor->id);
                } else if (descriptor->id == KernelFeatureId::kAtomTable) {
                    rebuildAtomTableFromCache();
                } else if (descriptor->id == KernelFeatureId::kDynData ||
                    descriptor->id == KernelFeatureId::kDriverStatus) {
                    rebuildDiagnosticDualTableFromCache(descriptor->id);
                } else if (descriptor->id == KernelFeatureId::kCallbackEnumeration) {
                    rebuildCallbackEnumerationListFromCache();
                } else if (isKernelHookFeature(descriptor->id)) {
                    rebuildKernelHookListFromCache(descriptor->id);
                } else if (descriptor->id == KernelFeatureId::kKernelExecutableMemory ||
                    descriptor->id == KernelFeatureId::kKernelMemoryEvidence) {
                    rebuildKernelMemoryScanListFromCache(descriptor->id);
                } else if (descriptor->id == KernelFeatureId::kProcessCrossView ||
                    descriptor->id == KernelFeatureId::kThreadCrossView) {
                    rebuildCrossViewListFromCache(descriptor->id);
                } else if (descriptor->id == KernelFeatureId::kDriverIntegrity ||
                    descriptor->id == KernelFeatureId::kKernelCpuIntegrity) {
                    rebuildIntegrityEvidenceListFromCache(descriptor->id);
                } else if (descriptor->id == KernelFeatureId::kCpuHardwareSnapshot ||
                    descriptor->id == KernelFeatureId::kPhysicalMemoryLayout ||
                    descriptor->id == KernelFeatureId::kMutationAudit ||
                    descriptor->id == KernelFeatureId::kKeyboardHotkeys ||
                    descriptor->id == KernelFeatureId::kKeyboardHooks ||
                    descriptor->id == KernelFeatureId::kDynDataCapabilities ||
                    descriptor->id == KernelFeatureId::kMinifilterBypassPids ||
                    descriptor->id == KernelFeatureId::kKernelTimerDpc ||
                    descriptor->id == KernelFeatureId::kIoctlRegistry) {
                    rebuildR0EvidenceListFromCache(descriptor->id);
                } else {
                    rebuildResultListFromCache();
                }
                configureVisibleLayout();
                invalidateCurrentFeatureViewCache();
            }
            return 0;
        }
        if ((LOWORD(wParam) == kIdDeviceDriverDirectoryCombo || LOWORD(wParam) == kIdDeviceDriverTypeCombo) &&
            HIWORD(wParam) == CBN_SELCHANGE) {
            if (const KernelFeatureDescriptor* descriptor = currentDescriptor();
                descriptor != nullptr &&
                descriptor->id == KernelFeatureId::kDeviceDriverObjects &&
                !currentRawColumns_.empty()) {
                currentColumns_ = currentRawColumns_;
                currentRows_ = currentRawRows_;
                rebuildObjectNamespaceListFromCache(descriptor->id);
                configureVisibleLayout();
                invalidateCurrentFeatureViewCache();
            }
            return 0;
        }
        if ((LOWORD(wParam) == kIdBaseNamedScopeCombo || LOWORD(wParam) == kIdBaseNamedTypeCombo) &&
            HIWORD(wParam) == CBN_SELCHANGE) {
            if (const KernelFeatureDescriptor* descriptor = currentDescriptor();
                descriptor != nullptr &&
                descriptor->id == KernelFeatureId::kBaseNamedObjects &&
                !currentRawColumns_.empty()) {
                currentColumns_ = currentRawColumns_;
                currentRows_ = currentRawRows_;
                rebuildObjectNamespaceListFromCache(descriptor->id);
                configureVisibleLayout();
                invalidateCurrentFeatureViewCache();
            }
            return 0;
        }
        if ((LOWORD(wParam) == kIdRiskOnlyCheck || LOWORD(wParam) == kIdEvidenceIncludeNonModuleCheck) &&
            HIWORD(wParam) == BN_CLICKED) {
            if (const KernelFeatureDescriptor* descriptor = currentDescriptor();
                descriptor != nullptr &&
                !currentRawColumns_.empty()) {
                currentColumns_ = currentRawColumns_;
                currentRows_ = currentRawRows_;
                if (descriptor->id == KernelFeatureId::kKernelExecutableMemory ||
                    descriptor->id == KernelFeatureId::kKernelMemoryEvidence) {
                    rebuildKernelMemoryScanListFromCache(descriptor->id);
                } else if (descriptor->id == KernelFeatureId::kProcessCrossView ||
                    descriptor->id == KernelFeatureId::kThreadCrossView) {
                    rebuildCrossViewListFromCache(descriptor->id);
                } else if (descriptor->id == KernelFeatureId::kCallbackIntercept) {
                    populateCallbackInterceptPanel();
                } else if (descriptor->id == KernelFeatureId::kDriverIntegrity ||
                    descriptor->id == KernelFeatureId::kKernelCpuIntegrity) {
                    rebuildIntegrityEvidenceListFromCache(descriptor->id);
                } else if (descriptor->id == KernelFeatureId::kCpuHardwareSnapshot ||
                    descriptor->id == KernelFeatureId::kPhysicalMemoryLayout ||
                    descriptor->id == KernelFeatureId::kMutationAudit ||
                    descriptor->id == KernelFeatureId::kKeyboardHotkeys ||
                    descriptor->id == KernelFeatureId::kKeyboardHooks ||
                    descriptor->id == KernelFeatureId::kDynDataCapabilities ||
                    descriptor->id == KernelFeatureId::kMinifilterBypassPids ||
                    descriptor->id == KernelFeatureId::kKernelTimerDpc ||
                    descriptor->id == KernelFeatureId::kIoctlRegistry) {
                    rebuildR0EvidenceListFromCache(descriptor->id);
                }
                configureVisibleLayout();
                invalidateCurrentFeatureViewCache();
            }
            return 0;
        }
        if (LOWORD(wParam) == kIdCopyDiagnosticReport && HIWORD(wParam) == BN_CLICKED) {
            if (const KernelFeatureDescriptor* descriptor = currentDescriptor();
                descriptor != nullptr && descriptor->id == KernelFeatureId::kDeviceDriverObjects) {
                exportAllRowsTsv();
            } else if (descriptor != nullptr && descriptor->id == KernelFeatureId::kSymbolicLink) {
                copyPreferredSelectedField({ L"targetPath", L"symbolicTarget", L"Target", L"目标路径", L"符号链接目标" }, L"状态：已复制符号链接目标。");
            } else if (descriptor != nullptr && isObjectNamespaceFeature(descriptor->id)) {
                executeObjectNamespaceDetailAction();
            } else if (descriptor != nullptr && descriptor->id == KernelFeatureId::kInlineHook) {
                executeSelectedAction(KernelActionId::kInlineHookNopPatch);
            } else {
                copyDiagnosticReport();
            }
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackReload && HIWORD(wParam) == BN_CLICKED) {
            refreshSelectedFeature();
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackApply && HIWORD(wParam) == BN_CLICKED) {
            executeSelectedAction(KernelActionId::kCallbackApplyLocalRules);
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackImport && HIWORD(wParam) == BN_CLICKED) {
            onCallbackImportConfig();
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackExport && HIWORD(wParam) == BN_CLICKED) {
            onCallbackExportConfig();
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackStartReceiver && HIWORD(wParam) == BN_CLICKED) {
            startCallbackEventReceiver();
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackStopReceiver && HIWORD(wParam) == BN_CLICKED) {
            stopCallbackEventReceiver();
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackAllowEvent && HIWORD(wParam) == BN_CLICKED) {
            answerCurrentCallbackEvent(true);
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackDenyEvent && HIWORD(wParam) == BN_CLICKED) {
            answerCurrentCallbackEvent(false);
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackAddGroup && HIWORD(wParam) == BN_CLICKED) {
            onCallbackAddGroup();
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackRemoveGroup && HIWORD(wParam) == BN_CLICKED) {
            onCallbackRemoveGroup();
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackRenameGroup && HIWORD(wParam) == BN_CLICKED) {
            onCallbackRenameGroup();
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackMoveGroupUp && HIWORD(wParam) == BN_CLICKED) {
            onCallbackMoveGroup(true);
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackMoveGroupDown && HIWORD(wParam) == BN_CLICKED) {
            onCallbackMoveGroup(false);
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackAddRule && HIWORD(wParam) == BN_CLICKED) {
            onCallbackAddRule();
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackRemoveRule && HIWORD(wParam) == BN_CLICKED) {
            onCallbackRemoveRule();
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackMoveRuleUp && HIWORD(wParam) == BN_CLICKED) {
            onCallbackMoveRule(true);
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackMoveRuleDown && HIWORD(wParam) == BN_CLICKED) {
            onCallbackMoveRule(false);
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackBypassAdd && HIWORD(wParam) == BN_CLICKED) {
            onCallbackBypassAdd();
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackBypassRemove && HIWORD(wParam) == BN_CLICKED) {
            onCallbackBypassRemove();
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackBypassApply && HIWORD(wParam) == BN_CLICKED) {
            ::SetWindowTextW(filterEdit_, windowText(callbackBypassPidEdit_).c_str());
            executeSelectedAction(KernelActionId::kMinifilterSetBypassPids);
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackBypassClear && HIWORD(wParam) == BN_CLICKED) {
            executeSelectedAction(KernelActionId::kMinifilterClearBypassPids);
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackBypassRefresh && HIWORD(wParam) == BN_CLICKED) {
            refreshSelectedFeature();
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackStartFsctl && HIWORD(wParam) == BN_CLICKED) {
            executeSelectedAction(KernelActionId::kFileMonitorStartFsctl);
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackDrainFileMonitor && HIWORD(wParam) == BN_CLICKED) {
            executeSelectedAction(KernelActionId::kFileMonitorDrain);
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackClearFileMonitor && HIWORD(wParam) == BN_CLICKED) {
            executeSelectedAction(KernelActionId::kFileMonitorClear);
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackExportFileMonitor && HIWORD(wParam) == BN_CLICKED) {
            onCallbackExportFileMonitor();
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackGlobalEnabled && HIWORD(wParam) == BN_CLICKED) {
            appendCallbackAppLog(callbackRulesGlobalEnabled() ? L"全局启用已打开，下一次应用规则时生效。" : L"全局启用已关闭，下一次应用规则时生效。");
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackFileMonitorFsctlOnly && HIWORD(wParam) == BN_CLICKED) {
            appendCallbackAppLog(Button_GetCheck(callbackFileMonitorFsctlOnlyCheck_) == BST_CHECKED
                ? L"文件监控过滤：仅显示 Oplock / FSCTL。"
                : L"文件监控过滤：显示全部当前事件。");
            return 0;
        }
        if (LOWORD(wParam) == kMenuRefreshCurrentFeature) {
            refreshSelectedFeature();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCopyCell) {
            copySelectedCell();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCopyRow) {
            copySelectedRow();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCopySelectedRows) {
            copySelectedRows(false);
            return 0;
        }
        if (LOWORD(wParam) == kMenuCopySelectedRowsWithHeader) {
            copySelectedRows(true);
            return 0;
        }
        if (LOWORD(wParam) == kMenuCopySelectedDetails) {
            copySelectedDetails();
            return 0;
        }
        if (LOWORD(wParam) >= kMenuCallbackCopyColumnBase && LOWORD(wParam) <= kMenuCallbackCopyColumnMax) {
            const std::vector<int> kCopyColumns = currentCopyColumnIndices();
            const int kIndex = static_cast<int>(LOWORD(wParam) - kMenuCallbackCopyColumnBase);
            if (kIndex >= 0 && kIndex < static_cast<int>(kCopyColumns.size())) {
                copySelectedColumn(kCopyColumns[static_cast<std::size_t>(kIndex)]);
            }
            return 0;
        }
        if (LOWORD(wParam) >= kMenuCopyColumnBase && LOWORD(wParam) <= kMenuCopyColumnMax) {
            copySelectedColumn(static_cast<int>(LOWORD(wParam) - kMenuCopyColumnBase));
            return 0;
        }
        if (LOWORD(wParam) == kMenuCopyAll) {
            copyAllRows();
            return 0;
        }
        if (LOWORD(wParam) == kMenuExportAllTsv) {
            exportAllRowsTsv();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCopyDiagnosticReport) {
            copyDiagnosticReport();
            return 0;
        }
        if (LOWORD(wParam) == kMenuRefreshSelectedDetail) {
            updateSelectedRowDetail();
            ::SetWindowTextW(statusText_, L"状态：已刷新详情面板。");
            return 0;
        }
        if (LOWORD(wParam) == kMenuInlineNopPatch) {
            executeSelectedAction(KernelActionId::kInlineHookNopPatch);
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackCancelPendingDecisions) {
            executeSelectedAction(KernelActionId::kCallbackCancelPendingDecisions);
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackApplyDisabledEmptyRules) {
            executeSelectedAction(KernelActionId::kCallbackApplyDisabledEmptyRules);
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackSafeRemove) {
            executeSelectedAction(KernelActionId::kCallbackSafeRemove);
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackExperimentalUnlink) {
            executeSelectedAction(KernelActionId::kCallbackExperimentalUnlink);
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackOpenModuleFolder) {
            openSelectedCallbackModuleFolder();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackModuleFileDetail) {
            showSelectedCallbackModuleFileDetail();
            return 0;
        }
        if (LOWORD(wParam) == kMenuNetworkCaptureStart) {
            executeSelectedAction(KernelActionId::kNetworkCaptureStart);
            return 0;
        }
        if (LOWORD(wParam) == kMenuNetworkCaptureStop) {
            executeSelectedAction(KernelActionId::kNetworkCaptureStop);
            return 0;
        }
        if (LOWORD(wParam) == kMenuPiDdbDeleteEntry) {
            executeSelectedAction(KernelActionId::kPiDdbDeleteEntry);
            return 0;
        }
        if (LOWORD(wParam) == kMenuDriverDispatchRestore) {
            executeSelectedAction(KernelActionId::kDriverDispatchRestore);
            return 0;
        }
        if (LOWORD(wParam) == kMenuDriverDispatchAbandon) {
            executeSelectedAction(KernelActionId::kDriverDispatchAbandon);
            return 0;
        }
        if (LOWORD(wParam) == kMenuDriverImageRestore) {
            executeSelectedAction(KernelActionId::kDriverImageRestore);
            return 0;
        }
        if (LOWORD(wParam) == kMenuDriverImageAbandon) {
            executeSelectedAction(KernelActionId::kDriverImageAbandon);
            return 0;
        }
        if (LOWORD(wParam) == kMenuDriverCommunicationRestore) {
            executeSelectedAction(KernelActionId::kDriverCommunicationRestore);
            return 0;
        }
        if (LOWORD(wParam) == kMenuMinifilterSetBypass) {
            executeSelectedAction(KernelActionId::kMinifilterSetBypassPids);
            return 0;
        }
        if (LOWORD(wParam) == kMenuMinifilterClearBypass) {
            executeSelectedAction(KernelActionId::kMinifilterClearBypassPids);
            return 0;
        }
        if (LOWORD(wParam) == kMenuDriverObjectQueryDetail) {
            executeSelectedAction(KernelActionId::kDriverObjectQueryDetail);
            return 0;
        }
        if (LOWORD(wParam) == kMenuDriverObjectForceUnload) {
            executeSelectedAction(KernelActionId::kDriverObjectForceUnload);
            return 0;
        }
        if (LOWORD(wParam) == kMenuNativeObjectQueryDetail) {
            executeSelectedAction(KernelActionId::kNativeObjectQueryDetail);
            return 0;
        }
        if (LOWORD(wParam) == kMenuNativeSymbolicLinkResolve) {
            executeSelectedAction(KernelActionId::kNativeSymbolicLinkResolve);
            return 0;
        }
        if (LOWORD(wParam) == kMenuNativeNamedPipeProbe) {
            executeSelectedAction(KernelActionId::kNativeNamedPipeProbe);
            return 0;
        }
        if (LOWORD(wParam) == kMenuDynDataApplyMatchedProfile) {
            executeSelectedAction(KernelActionId::kDynDataApplyMatchedProfile);
            return 0;
        }
        if (LOWORD(wParam) == kMenuMutationCommitDryRun) {
            executeSelectedAction(KernelActionId::kMutationCommitDryRun);
            return 0;
        }
        if (LOWORD(wParam) == kMenuMutationRollbackDryRun) {
            executeSelectedAction(KernelActionId::kMutationRollbackDryRun);
            return 0;
        }
        if (LOWORD(wParam) == kMenuMutationRollbackConfirmed) {
            executeSelectedAction(KernelActionId::kMutationRollbackConfirmed);
            return 0;
        }
        if (LOWORD(wParam) == kMenuFilterByModule) {
            applySelectedModuleFilter(false);
            return 0;
        }
        if (LOWORD(wParam) == kMenuFilterByTargetModule) {
            applySelectedModuleFilter(true);
            return 0;
        }
        if (LOWORD(wParam) == kMenuFilterByAddress) {
            applySelectedAddressFilter();
            return 0;
        }
        if (LOWORD(wParam) == kMenuFilterByPath) {
            applySelectedPathFilter();
            return 0;
        }
        if (LOWORD(wParam) == kMenuFilterByOwner) {
            applySelectedOwnerFilter();
            return 0;
        }
        if (LOWORD(wParam) == kMenuFilterByRisk) {
            applySelectedRiskFilter();
            return 0;
        }
        if (LOWORD(wParam) == kMenuFilterByPidTid) {
            applySelectedPidTidFilter();
            return 0;
        }
        if (LOWORD(wParam) == kMenuFilterByCapability) {
            applySelectedCapabilityFilter();
            return 0;
        }
        if (LOWORD(wParam) == kMenuObjectFilterByRoot) {
            const std::wstring kValue = firstSelectedRowField({
                L"RootPath", L"rootPath", L"Source", L"Parent", L"Directory",
                L"directoryPath", L"sourceDirectory", L"Path", L"fullPath", L"目录路径", L"来源目录", L"完整路径"
            });
            if (!kValue.empty()) {
                ::SetWindowTextW(filterEdit_, kValue.c_str());
                ::SetWindowTextW(statusText_, L"状态：已按目录路径过滤。");
                if (const KernelFeatureDescriptor* descriptor = currentDescriptor();
                    descriptor != nullptr && isObjectNamespaceFeature(descriptor->id)) {
                    rebuildObjectNamespaceListFromCache(descriptor->id);
                }
            }
            return 0;
        }
        if (LOWORD(wParam) == kMenuObjectFilterByDirectory) {
            const std::wstring kValue = firstSelectedRowField({
                L"directoryPath", L"Parent", L"Directory", L"sourceDirectory", L"Source", L"目录路径", L"来源目录"
            });
            if (!kValue.empty()) {
                ::SetWindowTextW(filterEdit_, kValue.c_str());
                ::SetWindowTextW(statusText_, L"状态：已按当前目录过滤。");
                if (const KernelFeatureDescriptor* descriptor = currentDescriptor();
                    descriptor != nullptr && isObjectNamespaceFeature(descriptor->id)) {
                    rebuildObjectNamespaceListFromCache(descriptor->id);
                }
            }
            return 0;
        }
        if (LOWORD(wParam) == kMenuFilterByType) {
            applySelectedTypeFilter();
            return 0;
        }
        if (LOWORD(wParam) == kMenuFilterByName) {
            applySelectedNameFilter();
            return 0;
        }
        if (LOWORD(wParam) == kMenuFilterByTarget) {
            applySelectedTargetFilter();
            return 0;
        }
        if (LOWORD(wParam) == kMenuAtomVerify) {
            verifySelectedAtom();
            return 0;
        }
        if (LOWORD(wParam) == kMenuAtomCopySnippet) {
            copySelectedAtomSnippet();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCopySameDirectory) {
            copyRowsWithSameDirectory();
            return 0;
        }
        if (LOWORD(wParam) == kMenuMapDosPath) {
            mapSelectedNtPathAsDosPaths();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCopyObjectName) {
            copyPreferredSelectedField({ L"objectName", L"Name", L"名称", L"对象名称", L"linkName", L"Pipe", L"Pipe Name" }, L"状态：已复制对象名。");
            return 0;
        }
        if (LOWORD(wParam) == kMenuCopyObjectType) {
            copyPreferredSelectedField({ L"objectType", L"Type", L"对象类型", L"类型" }, L"状态：已复制对象类型。");
            return 0;
        }
        if (LOWORD(wParam) == kMenuCopyFullPath) {
            copyPreferredSelectedField({ L"fullPath", L"Path", L"完整路径", L"NtPath", L"NT Path" }, L"状态：已复制完整路径。");
            return 0;
        }
        if (LOWORD(wParam) == kMenuCopySymbolicTarget) {
            copyPreferredSelectedField({ L"symbolicTarget", L"targetPath", L"Target", L"目标路径", L"符号链接目标" }, L"状态：已复制符号链接目标。");
            return 0;
        }
        if (LOWORD(wParam) == kMenuCopyObjectEnumSource) {
            copyPreferredSelectedField({ L"EnumApi", L"enumApi", L"枚举 API", L"EnumerationApi" }, L"状态：已复制枚举 API。");
            return 0;
        }
        if (LOWORD(wParam) == kMenuCopyDosCandidate) {
            copyPreferredSelectedField({ L"dosCandidate", L"Win32Path", L"DosCandidates" }, L"状态：已复制 dosCandidate。");
            return 0;
        }
        if (LOWORD(wParam) == kMenuCopyAtomValue) {
            copyPreferredSelectedField({ L"Atom值", L"Id" }, L"状态：已复制 Atom 值。");
            return 0;
        }
        if (LOWORD(wParam) == kMenuCopyAtomHex) {
            copyPreferredSelectedField({ L"十六进制", L"Id" }, L"状态：已复制 Atom 十六进制。");
            return 0;
        }
        if (LOWORD(wParam) == kMenuCopyAtomName) {
            copyPreferredSelectedField({ L"名称", L"Name" }, L"状态：已复制 Atom 名称。");
            return 0;
        }
        if (LOWORD(wParam) == kMenuCopyAtomSource) {
            copyPreferredSelectedField({ L"来源", L"Source" }, L"状态：已复制 Atom 来源。");
            return 0;
        }
        if (LOWORD(wParam) == kMenuShowRowDialog) {
            showSelectedRowDialog();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackGroupAdd) {
            onCallbackAddGroup();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackGroupRemove) {
            onCallbackRemoveGroup();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackGroupRename) {
            onCallbackRenameGroup();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackGroupMoveUp) {
            onCallbackMoveGroup(true);
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackGroupMoveDown) {
            onCallbackMoveGroup(false);
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackGroupToggleEnabled) {
            onCallbackToggleGroupEnabled();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackRuleAdd) {
            onCallbackAddRule();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackRuleRemove) {
            onCallbackRemoveRule();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackRuleMoveUp) {
            onCallbackMoveRule(true);
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackRuleMoveDown) {
            onCallbackMoveRule(false);
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackRuleToggleEnabled) {
            onCallbackToggleRuleEnabled();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackRuleCopyText) {
            onCallbackCopyRuleText();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackRulePasteNew) {
            onCallbackPasteRuleText();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackBypassAdd) {
            onCallbackBypassAdd();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackBypassRemove) {
            onCallbackBypassRemove();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackBypassApply) {
            ::SetWindowTextW(filterEdit_, windowText(callbackBypassPidEdit_).c_str());
            executeSelectedAction(KernelActionId::kMinifilterSetBypassPids);
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackBypassClear) {
            executeSelectedAction(KernelActionId::kMinifilterClearBypassPids);
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackBypassRefresh) {
            refreshSelectedFeature();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackFileMonitorStart) {
            executeSelectedAction(KernelActionId::kFileMonitorStartFsctl);
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackFileMonitorDrain) {
            executeSelectedAction(KernelActionId::kFileMonitorDrain);
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackFileMonitorClear) {
            executeSelectedAction(KernelActionId::kFileMonitorClear);
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackFileMonitorExport) {
            onCallbackExportFileMonitor();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackFileMonitorOpenProcess) {
            openCallbackFileMonitorProcess();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackFileMonitorOpenPath) {
            openCallbackFileMonitorPath();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackCopyPanelSelection) {
            const HWND kFocus = ::GetFocus();
            copyCallbackPanelSelection(kFocus);
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackImportConfig) {
            onCallbackImportConfig();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackExportConfig) {
            onCallbackExportConfig();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackApplyLocalRules) {
            executeSelectedAction(KernelActionId::kCallbackApplyLocalRules);
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackReloadRuntime) {
            refreshSelectedFeature();
            return 0;
        }
        break;
    case WM_CONTEXTMENU:
        if (reinterpret_cast<HWND>(wParam) == callbackGroupList_ ||
            reinterpret_cast<HWND>(wParam) == callbackBypassList_ ||
            reinterpret_cast<HWND>(wParam) == callbackFileMonitorList_ ||
            std::find(callbackRuleLists_.begin(), callbackRuleLists_.end(), reinterpret_cast<HWND>(wParam)) != callbackRuleLists_.end()) {
            POINT point{ GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
            showCallbackInterceptContextMenu(reinterpret_cast<HWND>(wParam), point);
            return 0;
        }
        if (reinterpret_cast<HWND>(wParam) == objectNamespaceTree_) {
            POINT point{ GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
            if (point.x == -1 && point.y == -1) {
                const HTREEITEM kSelectedItem = TreeView_GetSelection(objectNamespaceTree_);
                RECT itemRect{};
                if (kSelectedItem != nullptr && TreeView_GetItemRect(objectNamespaceTree_, kSelectedItem, &itemRect, TRUE)) {
                    point.x = itemRect.left;
                    point.y = itemRect.bottom;
                    ::ClientToScreen(objectNamespaceTree_, &point);
                }
            } else {
                POINT clientPoint = point;
                ::ScreenToClient(objectNamespaceTree_, &clientPoint);
                TVHITTESTINFO hit{};
                hit.pt = clientPoint;
                const HTREEITEM kItem = TreeView_HitTest(objectNamespaceTree_, &hit);
                if (kItem != nullptr) {
                    TreeView_SelectItem(objectNamespaceTree_, kItem);
                }
            }
            showResultContextMenu(point);
            return 0;
        }
        if (reinterpret_cast<HWND>(wParam) == resultList_) {
            POINT point{ GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
            contextColumn_ = -1;
            if (point.x != -1 || point.y != -1) {
                POINT clientPoint = point;
                ::ScreenToClient(resultList_, &clientPoint);
                LVHITTESTINFO hit{};
                hit.pt = clientPoint;
                const int kRow = ListView_HitTest(resultList_, &hit);
                contextColumn_ = hit.iSubItem >= 0 ? hit.iSubItem : 0;
                if (kRow >= 0) {
                    const UINT kState = ListView_GetItemState(resultList_, kRow, LVIS_SELECTED);
                    if ((kState & LVIS_SELECTED) == 0) {
                        ListView_SetItemState(resultList_, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
                    }
                    ListView_SetItemState(resultList_, kRow, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
                    ListView_EnsureVisible(resultList_, kRow, FALSE);
                    updateSelectedRowDetail();
                }
            } else {
                const int kSelected = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED);
                contextColumn_ = headerColumnCount(resultList_) > 1 ? 1 : 0;
                if (kSelected >= 0) {
                    ListView_SetItemState(resultList_, kSelected, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
                    ListView_EnsureVisible(resultList_, kSelected, FALSE);
                }
            }
            showResultContextMenu(point);
            return 0;
        }
        break;
    case WM_NOTIFY:
        if (const auto* header = reinterpret_cast<const NMHDR*>(lParam)) {
            if (header->hwndFrom == primaryTab_ && header->code == TCN_SELCHANGE) {
                ksword::ui::ScopedWindowRedrawLock pageRedrawLock(hwnd_);
                parkCurrentFeatureViewCache();
                hasDirectFeatureId_ = false;
                rebuildSecondLevelTabs();
                selectCurrentFeature();
                return 0;
            }
            if (header->hwndFrom == secondaryTab_ && header->code == TCN_SELCHANGE) {
                ksword::ui::ScopedWindowRedrawLock pageRedrawLock(hwnd_);
                parkCurrentFeatureViewCache();
                hasDirectFeatureId_ = false;
                selectCurrentFeature();
                return 0;
            }
            if (header->hwndFrom == resultList_ && header->code == NM_CUSTOMDRAW) {
                return handleResultListCustomDraw(lParam);
            }
            if (header->hwndFrom == resultList_ && header->code == LVN_GETDISPINFOW) {
                auto* info = reinterpret_cast<NMLVDISPINFOW*>(lParam);
                if (info && (info->item.mask & LVIF_TEXT) != 0 && info->item.pszText && info->item.cchTextMax > 0) {
                    const std::wstring kText = resultCellText(info->item.iItem, info->item.iSubItem);
                    ::wcsncpy_s(info->item.pszText, static_cast<std::size_t>(info->item.cchTextMax), kText.c_str(), _TRUNCATE);
                }
                if (info && (info->item.mask & LVIF_INDENT) != 0) {
                    const int kRow = info->item.iItem;
                    info->item.iIndent = kRow >= 0 && kRow < static_cast<int>(currentRowIndents_.size())
                        ? std::max(0, std::min(currentRowIndents_[static_cast<std::size_t>(kRow)], 32))
                        : 0;
                }
                return 0;
            }
            if (header->hwndFrom == resultList_ && header->code == LVN_COLUMNCLICK) {
                const auto* click = reinterpret_cast<const NMLISTVIEW*>(lParam);
                sortResultRowsByColumn(click->iSubItem);
                return 0;
            }
            if (header->hwndFrom == resultList_ && header->code == NM_DBLCLK) {
                const auto* activate = reinterpret_cast<const NMITEMACTIVATE*>(lParam);
                toggleObjectNamespaceListNode(activate->iItem);
                return 0;
            }
            if (header->hwndFrom == resultList_ && header->code == LVN_ITEMCHANGED) {
                const auto* item = reinterpret_cast<const NMLISTVIEW*>(lParam);
                if ((item->uChanged & LVIF_STATE) != 0 &&
                    ((item->uNewState ^ item->uOldState) & LVIS_SELECTED) != 0) {
                    updateSelectedRowDetail();
                }
                return 0;
            }
            if (header->hwndFrom == objectNamespaceTree_ && header->code == TVN_SELCHANGEDW) {
                const auto* changed = reinterpret_cast<const NMTREEVIEWW*>(lParam);
                selectObjectNamespaceTreeItem(changed->itemNew.lParam);
                return 0;
            }
            if ((header->hwndFrom == callbackRuleTab_ || header->hwndFrom == callbackLogTab_) && header->code == TCN_SELCHANGE) {
                layout();
                return 0;
            }
        }
        break;
    case WM_CTLCOLORSTATIC:
        ::SetBkMode(reinterpret_cast<HDC>(wParam), TRANSPARENT);
        return reinterpret_cast<LRESULT>(::GetSysColorBrush(COLOR_WINDOW));
    case WM_PAINT:
    {
        PAINTSTRUCT paint{};
        HDC dc = ::BeginPaint(hwnd, &paint);
        if (width(verticalSplitterRect_) > 0 && height(verticalSplitterRect_) > 0) {
            ::FillRect(dc, &verticalSplitterRect_, ::GetSysColorBrush(COLOR_BTNFACE));
            RECT line = verticalSplitterRect_;
            const int kCenterY = line.top + height(line) / 2;
            line.top = kCenterY;
            line.bottom = kCenterY + 1;
            ::FillRect(dc, &line, ::GetSysColorBrush(COLOR_3DSHADOW));
        }
        ::EndPaint(hwnd, &paint);
        return 0;
    }
    case WM_NCDESTROY:
        ::KillTimer(hwnd, kTimerR0EvidenceFilter);
        if (callbackEventReceiver_) {
            callbackEventReceiver_->shutdown();
        }
        if (queryTask_) {
            queryTask_->cancel();
        }
        if (actionTask_) {
            actionTask_->cancel();
        }
        if (callbackAnswerTask_) {
            callbackAnswerTask_->cancel();
        }
        if (callbackFileIoTask_) {
            callbackFileIoTask_->cancel();
        }
        if (r0EvidenceFilterTask_) {
            r0EvidenceFilterTask_->cancel();
        }
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        hwnd_ = nullptr;
        delete this;
        return 0;
    default:
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

void KernelPage::createChildControls() {
    // UI owns only Win32 controls. All kernel data requests continue through
    // KernelFacade, so driver/protocol access stays out of this view layer.
    primaryTab_ = ::CreateWindowExW(0,
        WC_TABCONTROLW,
        L"",
        WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
        0,
        0,
        0,
        0,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdPrimaryTab)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    secondaryTab_ = ::CreateWindowExW(0,
        WC_TABCONTROLW,
        L"",
        WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
        0,
        0,
        0,
        0,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdSecondaryTab)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    titleText_ = ksword::ui::createText(hwnd_, 0, L"内核", 0, 0, 0, 0);
    summaryText_ = ksword::ui::createText(hwnd_, 0, L"", 0, 0, 0, 0);
    backendText_ = ksword::ui::createText(hwnd_, 0, L"", 0, 0, 0, 0);
    statusText_ = ksword::ui::createText(hwnd_, 0, L"选择一个二级页后点击刷新/查询。", 0, 0, 0, 0);
    filterLabel_ = ksword::ui::createText(hwnd_, 0, L"过滤/起点", 0, 0, 0, 0);
    filterEdit_ = ::CreateWindowExW(WS_EX_CLIENTEDGE,
        WC_EDITW,
        L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        0,
        0,
        0,
        0,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdFilterEdit)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    if (filterEdit_) {
        ::SetWindowSubclass(filterEdit_, KernelPage::filterEditSubclassProc, kFilterEditSubclassId, reinterpret_cast<DWORD_PTR>(this));
    }
    moduleFilterLabel_ = ksword::ui::createText(hwnd_, 0, L"模块过滤", 0, 0, 0, 0);
    moduleFilterEdit_ = ::CreateWindowExW(WS_EX_CLIENTEDGE,
        WC_EDITW,
        L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        0,
        0,
        0,
        0,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdModuleFilterEdit)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    symbolicLinkNoteText_ = ksword::ui::createText(hwnd_,
        0,
        L"说明：SymbolicLink 本身不是可递归容器，本页只解析目标；若目标指向 Directory，后续由目录递归 tab 处理。",
        0,
        0,
        0,
        0);
    deviceDriverDirectoryLabel_ = ksword::ui::createText(hwnd_, 0, L"目录：", 0, 0, 0, 0);
    deviceDriverDirectoryCombo_ = ::CreateWindowExW(0,
        WC_COMBOBOXW,
        L"",
        WS_CHILD | WS_TABSTOP | CBS_DROPDOWNLIST | CBS_HASSTRINGS | WS_VSCROLL,
        0,
        0,
        0,
        0,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdDeviceDriverDirectoryCombo)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    deviceDriverTypeLabel_ = ksword::ui::createText(hwnd_, 0, L"类型：", 0, 0, 0, 0);
    deviceDriverTypeCombo_ = ::CreateWindowExW(0,
        WC_COMBOBOXW,
        L"",
        WS_CHILD | WS_TABSTOP | CBS_DROPDOWNLIST | CBS_HASSTRINGS | WS_VSCROLL,
        0,
        0,
        0,
        0,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdDeviceDriverTypeCombo)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    baseNamedScopeCombo_ = ::CreateWindowExW(0,
        WC_COMBOBOXW,
        L"",
        WS_CHILD | WS_TABSTOP | CBS_DROPDOWNLIST | CBS_HASSTRINGS | WS_VSCROLL,
        0,
        0,
        0,
        0,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdBaseNamedScopeCombo)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    baseNamedTypeCombo_ = ::CreateWindowExW(0,
        WC_COMBOBOXW,
        L"",
        WS_CHILD | WS_TABSTOP | CBS_DROPDOWNLIST | CBS_HASSTRINGS | WS_VSCROLL,
        0,
        0,
        0,
        0,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdBaseNamedTypeCombo)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    integrityModuleBaseLabel_ = ksword::ui::createText(hwnd_, 0, L"模块基址", 0, 0, 0, 0);
    integrityModuleBaseEdit_ = ::CreateWindowExW(WS_EX_CLIENTEDGE,
        WC_EDITW,
        L"",
        WS_CHILD | WS_TABSTOP | ES_AUTOHSCROLL,
        0,
        0,
        0,
        0,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdIntegrityModuleBaseEdit)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    integrityFillFromSelectionButton_ = ksword::ui::createButton(hwnd_, kIdIntegrityFillFromSelection, L"填充", 0, 0, 0, 0);
    integrityCpuOnlyButton_ = ksword::ui::createButton(hwnd_, kIdIntegrityCpuOnly, L"CPU", 0, 0, 0, 0);
    includeCombo_ = ::CreateWindowExW(0,
        WC_COMBOBOXW,
        L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | CBS_HASSTRINGS,
        0,
        0,
        0,
        0,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdIncludeCombo)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    refreshButton_ = ksword::ui::createButton(hwnd_, kIdRefresh, L"刷新/查询", 0, 0, 0, 0);
    locateButton_ = ksword::ui::createButton(hwnd_, kIdLocate, L"定位", 0, 0, 0, 0);
    copyDiagnosticButton_ = ksword::ui::createButton(hwnd_, kIdCopyDiagnosticReport, L"复制诊断", 0, 0, 0, 0);
    objectNamespaceTree_ = ::CreateWindowExW(WS_EX_CLIENTEDGE,
        WC_TREEVIEWW,
        L"",
        WS_CHILD | WS_TABSTOP | TVS_HASBUTTONS | TVS_HASLINES | TVS_LINESATROOT | TVS_SHOWSELALWAYS,
        0,
        0,
        0,
        0,
        hwnd_,
        nullptr,
        ::GetModuleHandleW(nullptr),
        nullptr);
    resultList_ = ::CreateWindowExW(WS_EX_CLIENTEDGE,
        WC_LISTVIEWW,
        L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_OWNERDATA | LVS_SHOWSELALWAYS,
        0,
        0,
        0,
        0,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdResultList)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    if (resultList_) {
        ListView_SetExtendedListViewStyleEx(resultList_,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP | LVS_EX_GRIDLINES,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP | LVS_EX_GRIDLINES);
    }
    propertyList_ = ::CreateWindowExW(WS_EX_CLIENTEDGE,
        WC_LISTVIEWW,
        L"",
        WS_CHILD | WS_TABSTOP | LVS_REPORT | LVS_SHOWSELALWAYS,
        0,
        0,
        0,
        0,
        hwnd_,
        nullptr,
        ::GetModuleHandleW(nullptr),
        nullptr);
    if (propertyList_) {
        ListView_SetExtendedListViewStyleEx(propertyList_,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP | LVS_EX_GRIDLINES,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP | LVS_EX_GRIDLINES);
        LVCOLUMNW nameColumn{};
        nameColumn.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
        nameColumn.fmt = LVCFMT_LEFT;
        nameColumn.cx = 180;
        nameColumn.pszText = const_cast<LPWSTR>(L"属性项");
        ListView_InsertColumn(propertyList_, 0, &nameColumn);
        LVCOLUMNW valueColumn{};
        valueColumn.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
        valueColumn.fmt = LVCFMT_LEFT;
        valueColumn.cx = 320;
        valueColumn.pszText = const_cast<LPWSTR>(L"值");
        ListView_InsertColumn(propertyList_, 1, &valueColumn);
    }
    summaryList_ = ::CreateWindowExW(WS_EX_CLIENTEDGE,
        WC_LISTVIEWW,
        L"",
        WS_CHILD | WS_TABSTOP | LVS_REPORT | LVS_SHOWSELALWAYS,
        0,
        0,
        0,
        0,
        hwnd_,
        nullptr,
        ::GetModuleHandleW(nullptr),
        nullptr);
    if (summaryList_) {
        ListView_SetExtendedListViewStyleEx(summaryList_,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP | LVS_EX_GRIDLINES,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP | LVS_EX_GRIDLINES);
        LVCOLUMNW nameColumn{};
        nameColumn.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
        nameColumn.fmt = LVCFMT_LEFT;
        nameColumn.cx = 220;
        nameColumn.pszText = const_cast<LPWSTR>(L"项目");
        ListView_InsertColumn(summaryList_, 0, &nameColumn);
        LVCOLUMNW valueColumn{};
        valueColumn.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
        valueColumn.fmt = LVCFMT_LEFT;
        valueColumn.cx = 520;
        valueColumn.pszText = const_cast<LPWSTR>(L"值");
        ListView_InsertColumn(summaryList_, 1, &valueColumn);
    }
    detailEdit_ = ::CreateWindowExW(WS_EX_CLIENTEDGE,
        WC_EDITW,
        L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL,
        0,
        0,
        0,
        0,
        hwnd_,
        nullptr,
        ::GetModuleHandleW(nullptr),
        nullptr);
    // The selected-row detail pane is where a single kernel object expands into
    // dozens of lines, which is exactly where scanning by eye stops working.
    ksword::ui::attachTextFindSupport(detailEdit_);
    riskOnlyCheck_ = ::CreateWindowExW(0,
        WC_BUTTONW,
        L"仅风险项",
        WS_CHILD | BS_AUTOCHECKBOX | WS_TABSTOP,
        0,
        0,
        0,
        0,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdRiskOnlyCheck)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    Button_SetCheck(riskOnlyCheck_, BST_CHECKED);
    evidenceIncludeNonModuleCheck_ = ::CreateWindowExW(0,
        WC_BUTTONW,
        L"包含非模块执行范围",
        WS_CHILD | BS_AUTOCHECKBOX | WS_TABSTOP,
        0,
        0,
        0,
        0,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdEvidenceIncludeNonModuleCheck)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    evidenceStartEdit_ = ::CreateWindowExW(WS_EX_CLIENTEDGE,
        WC_EDITW,
        L"",
        WS_CHILD | WS_TABSTOP | ES_AUTOHSCROLL,
        0,
        0,
        0,
        0,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdEvidenceStartEdit)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    evidenceEndEdit_ = ::CreateWindowExW(WS_EX_CLIENTEDGE,
        WC_EDITW,
        L"",
        WS_CHILD | WS_TABSTOP | ES_AUTOHSCROLL,
        0,
        0,
        0,
        0,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdEvidenceEndEdit)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    evidenceMaxRowsLabel_ = ksword::ui::createText(hwnd_, 0, L"行数:", 0, 0, 0, 0);
    evidenceMaxRowsEdit_ = ::CreateWindowExW(WS_EX_CLIENTEDGE,
        WC_EDITW,
        L"256",
        WS_CHILD | WS_TABSTOP | ES_NUMBER | ES_AUTOHSCROLL,
        0,
        0,
        0,
        0,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdEvidenceMaxRowsEdit)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    evidenceMaxRowsSpin_ = ::CreateWindowExW(0,
        UPDOWN_CLASSW,
        L"",
        WS_CHILD | UDS_SETBUDDYINT | UDS_ALIGNRIGHT | UDS_ARROWKEYS,
        0,
        0,
        0,
        0,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdEvidenceMaxRowsSpin)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    ::SendMessageW(evidenceMaxRowsSpin_, UDM_SETBUDDY, reinterpret_cast<WPARAM>(evidenceMaxRowsEdit_), 0);
    ::SendMessageW(evidenceMaxRowsSpin_, UDM_SETRANGE32, 16, 4096);
    integrityIdtVectorsLabel_ = ksword::ui::createText(hwnd_, 0, L"IDT/CPU:", 0, 0, 0, 0);
    integrityIdtVectorsEdit_ = ::CreateWindowExW(WS_EX_CLIENTEDGE,
        WC_EDITW,
        L"64",
        WS_CHILD | WS_TABSTOP | ES_NUMBER | ES_AUTOHSCROLL,
        0,
        0,
        0,
        0,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdIntegrityIdtVectorsEdit)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    integrityIdtVectorsSpin_ = ::CreateWindowExW(0,
        UPDOWN_CLASSW,
        L"",
        WS_CHILD | UDS_SETBUDDYINT | UDS_ALIGNRIGHT | UDS_ARROWKEYS,
        0,
        0,
        0,
        0,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdIntegrityIdtVectorsSpin)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    ::SendMessageW(integrityIdtVectorsSpin_, UDM_SETBUDDY, reinterpret_cast<WPARAM>(integrityIdtVectorsEdit_), 0);
    ::SendMessageW(integrityIdtVectorsSpin_, UDM_SETRANGE32, 0, 256);
    callbackGlobalEnabledCheck_ = ::CreateWindowExW(0,
        WC_BUTTONW,
        L"全局启用",
        WS_CHILD | BS_AUTOCHECKBOX | WS_TABSTOP,
        0,
        0,
        0,
        0,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdCallbackGlobalEnabled)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    Button_SetCheck(callbackGlobalEnabledCheck_, BST_CHECKED);
    callbackApplyButton_ = ksword::ui::createButton(hwnd_, kIdCallbackApply, L"应用", 0, 0, 0, 0);
    callbackReloadButton_ = ksword::ui::createButton(hwnd_, kIdCallbackReload, L"重新加载驱动状态", 0, 0, 0, 0);
    callbackImportButton_ = ksword::ui::createButton(hwnd_, kIdCallbackImport, L"导入配置", 0, 0, 0, 0);
    callbackExportButton_ = ksword::ui::createButton(hwnd_, kIdCallbackExport, L"导出配置", 0, 0, 0, 0);
    callbackStartReceiverButton_ = ksword::ui::createButton(hwnd_, kIdCallbackStartReceiver, L"接收待决策", 0, 0, 0, 0);
    callbackStopReceiverButton_ = ksword::ui::createButton(hwnd_, kIdCallbackStopReceiver, L"停止接收", 0, 0, 0, 0);
    callbackAllowEventButton_ = ksword::ui::createButton(hwnd_, kIdCallbackAllowEvent, L"允许当前", 0, 0, 0, 0);
    callbackDenyEventButton_ = ksword::ui::createButton(hwnd_, kIdCallbackDenyEvent, L"拒绝当前", 0, 0, 0, 0);
    callbackStatusText_ = ksword::ui::createText(hwnd_, 0, L"状态：等待刷新", 0, 0, 0, 0);
    callbackGroupLabel_ = ksword::ui::createText(hwnd_, 0, L"规则组", 0, 0, 0, 0);
    callbackAddGroupButton_ = ksword::ui::createButton(hwnd_, kIdCallbackAddGroup, L"新增组", 0, 0, 0, 0);
    callbackRemoveGroupButton_ = ksword::ui::createButton(hwnd_, kIdCallbackRemoveGroup, L"删除组", 0, 0, 0, 0);
    callbackRenameGroupButton_ = ksword::ui::createButton(hwnd_, kIdCallbackRenameGroup, L"重命名", 0, 0, 0, 0);
    callbackMoveGroupUpButton_ = ksword::ui::createButton(hwnd_, kIdCallbackMoveGroupUp, L"上移", 0, 0, 0, 0);
    callbackMoveGroupDownButton_ = ksword::ui::createButton(hwnd_, kIdCallbackMoveGroupDown, L"下移", 0, 0, 0, 0);
    callbackGroupList_ = ::CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
        WS_CHILD | WS_TABSTOP | LVS_REPORT | LVS_SHOWSELALWAYS, 0, 0, 0, 0, hwnd_, nullptr, ::GetModuleHandleW(nullptr), nullptr);
    configureReportList(callbackGroupList_);
    addListColumn(callbackGroupList_, 0, L"groupId", 58);
    addListColumn(callbackGroupList_, 1, L"组名称", 150);
    addListColumn(callbackGroupList_, 2, L"启用", 60);
    addListColumn(callbackGroupList_, 3, L"优先级", 70);
    addListColumn(callbackGroupList_, 4, L"备注", 220);

    callbackRuleLabel_ = ksword::ui::createText(hwnd_, 0, L"规则", 0, 0, 0, 0);
    callbackAddRuleButton_ = ksword::ui::createButton(hwnd_, kIdCallbackAddRule, L"新增规则", 0, 0, 0, 0);
    callbackRemoveRuleButton_ = ksword::ui::createButton(hwnd_, kIdCallbackRemoveRule, L"删除规则", 0, 0, 0, 0);
    callbackMoveRuleUpButton_ = ksword::ui::createButton(hwnd_, kIdCallbackMoveRuleUp, L"规则上移", 0, 0, 0, 0);
    callbackMoveRuleDownButton_ = ksword::ui::createButton(hwnd_, kIdCallbackMoveRuleDown, L"规则下移", 0, 0, 0, 0);
    callbackRuleTab_ = ::CreateWindowExW(0, WC_TABCONTROLW, L"",
        WS_CHILD | WS_CLIPSIBLINGS, 0, 0, 0, 0, hwnd_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdCallbackRuleTab)), ::GetModuleHandleW(nullptr), nullptr);
    const wchar_t* ruleTabTitles[] = { L"注册表", L"进程创建", L"线程创建", L"镜像加载", L"对象管理器", L"文件系统微过滤器", L"Minifilter PID 放行" };
    constexpr int kRuleTabCount = static_cast<int>(sizeof(ruleTabTitles) / sizeof(ruleTabTitles[0]));
    for (int index = 0; index < kRuleTabCount; ++index) {
        setTabText(callbackRuleTab_, index, ruleTabTitles[index]);
        HWND ruleList = ::CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
            WS_CHILD | LVS_REPORT | LVS_SHOWSELALWAYS, 0, 0, 0, 0, hwnd_, nullptr, ::GetModuleHandleW(nullptr), nullptr);
        configureReportList(ruleList);
        addListColumn(ruleList, 0, L"启用", 42);
        addListColumn(ruleList, 1, L"RuleID", 58);
        addListColumn(ruleList, 2, L"GroupID", 96);
        addListColumn(ruleList, 3, L"规则名称", 170);
        addListColumn(ruleList, 4, L"操作类型", 480);
        addListColumn(ruleList, 5, L"匹配模式", 104);
        addListColumn(ruleList, 6, L"动作", 104);
        addListColumn(ruleList, 7, L"超时毫秒", 72);
        addListColumn(ruleList, 8, L"超时决策", 78);
        addListColumn(ruleList, 9, L"优先级", 58);
        callbackRuleLists_.push_back(ruleList);
    }
    ::SendMessageW(callbackRuleTab_, TCM_SETCURSEL, 0, 0);

    callbackBypassLabel_ = ksword::ui::createText(hwnd_, 0, L"Minifilter PID 放行", 0, 0, 0, 0);
    callbackBypassPidEdit_ = ::CreateWindowExW(WS_EX_CLIENTEDGE, WC_EDITW, L"",
        WS_CHILD | WS_TABSTOP | ES_AUTOHSCROLL, 0, 0, 0, 0, hwnd_, nullptr, ::GetModuleHandleW(nullptr), nullptr);
    callbackBypassAddButton_ = ksword::ui::createButton(hwnd_, kIdCallbackBypassAdd, L"添加", 0, 0, 0, 0);
    callbackBypassRemoveButton_ = ksword::ui::createButton(hwnd_, kIdCallbackBypassRemove, L"移除选中", 0, 0, 0, 0);
    callbackBypassApplyButton_ = ksword::ui::createButton(hwnd_, kIdCallbackBypassApply, L"应用到驱动", 0, 0, 0, 0);
    callbackBypassClearButton_ = ksword::ui::createButton(hwnd_, kIdCallbackBypassClear, L"清空并应用", 0, 0, 0, 0);
    callbackBypassRefreshButton_ = ksword::ui::createButton(hwnd_, kIdCallbackBypassRefresh, L"从驱动刷新", 0, 0, 0, 0);
    callbackBypassList_ = ::CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
        WS_CHILD | LVS_REPORT | LVS_SHOWSELALWAYS, 0, 0, 0, 0, hwnd_, nullptr, ::GetModuleHandleW(nullptr), nullptr);
    configureReportList(callbackBypassList_);
    addListColumn(callbackBypassList_, 0, L"PID", 80);
    addListColumn(callbackBypassList_, 1, L"进程", 200);
    callbackBypassStatusText_ = ksword::ui::createText(hwnd_, 0, L"尚未从驱动刷新；编辑后点击“应用到驱动”生效。", 0, 0, 0, 0);

    callbackLogTab_ = ::CreateWindowExW(0, WC_TABCONTROLW, L"",
        WS_CHILD | WS_CLIPSIBLINGS, 0, 0, 0, 0, hwnd_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdCallbackLogTab)), ::GetModuleHandleW(nullptr), nullptr);
    setTabText(callbackLogTab_, 0, L"应用日志");
    setTabText(callbackLogTab_, 1, L"事件日志");
    ::SendMessageW(callbackLogTab_, TCM_SETCURSEL, 0, 0);
    callbackAppLogEdit_ = ::CreateWindowExW(WS_EX_CLIENTEDGE, WC_EDITW, L"",
        WS_CHILD | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL, 0, 0, 0, 0, hwnd_, nullptr, ::GetModuleHandleW(nullptr), nullptr);
    callbackEventLogEdit_ = ::CreateWindowExW(WS_EX_CLIENTEDGE, WC_EDITW, L"",
        WS_CHILD | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL, 0, 0, 0, 0, hwnd_, nullptr, ::GetModuleHandleW(nullptr), nullptr);
    // Both callback logs grow without bound while the driver is running, so
    // finding one event in them is a search problem, not a scrolling one.
    ksword::ui::attachTextFindSupport(callbackAppLogEdit_);
    ksword::ui::attachTextFindSupport(callbackEventLogEdit_);

    callbackFileMonitorLabel_ = ksword::ui::createText(hwnd_, 0, L"文件系统事件", 0, 0, 0, 0);
    callbackStartFsctlButton_ = ksword::ui::createButton(hwnd_, kIdCallbackStartFsctl, L"启动 FSCTL 监控", 0, 0, 0, 0);
    callbackDrainFileMonitorButton_ = ksword::ui::createButton(hwnd_, kIdCallbackDrainFileMonitor, L"拉取事件", 0, 0, 0, 0);
    callbackClearFileMonitorButton_ = ksword::ui::createButton(hwnd_, kIdCallbackClearFileMonitor, L"清空", 0, 0, 0, 0);
    callbackExportFileMonitorButton_ = ksword::ui::createButton(hwnd_, kIdCallbackExportFileMonitor, L"导出", 0, 0, 0, 0);
    callbackFileMonitorFsctlOnlyCheck_ = ::CreateWindowExW(0,
        WC_BUTTONW,
        L"仅显示 Oplock / FSCTL",
        WS_CHILD | BS_AUTOCHECKBOX | WS_TABSTOP,
        0,
        0,
        0,
        0,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdCallbackFileMonitorFsctlOnly)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    Button_SetCheck(callbackFileMonitorFsctlOnlyCheck_, BST_CHECKED);
    callbackFileMonitorStatusText_ = ksword::ui::createText(hwnd_, 0, L"等待启动或读取事件", 0, 0, 0, 0);
    callbackFileMonitorList_ = ::CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
        WS_CHILD | LVS_REPORT | LVS_SHOWSELALWAYS, 0, 0, 0, 0, hwnd_, nullptr, ::GetModuleHandleW(nullptr), nullptr);
    configureReportList(callbackFileMonitorList_);
    addListColumn(callbackFileMonitorList_, 0, L"时间", 140);
    addListColumn(callbackFileMonitorList_, 1, L"PID", 70);
    addListColumn(callbackFileMonitorList_, 2, L"进程", 120);
    addListColumn(callbackFileMonitorList_, 3, L"文件路径", 260);
    addListColumn(callbackFileMonitorList_, 4, L"FSCTL 名称", 130);
    addListColumn(callbackFileMonitorList_, 5, L"控制码", 100);
    addListColumn(callbackFileMonitorList_, 6, L"状态码", 90);
    addListColumn(callbackFileMonitorList_, 7, L"FileObject", 150);
    addListColumn(callbackFileMonitorList_, 8, L"In", 90);
    addListColumn(callbackFileMonitorList_, 9, L"Out", 95);
    addListColumn(callbackFileMonitorList_, kCallbackFileMonitorPathStateColumn, L"路径状态", 90);
    ksword::ui::setWindowFontRecursive(hwnd_);
}

void KernelPage::layout() {
    RECT rc{};
    ::GetClientRect(hwnd_, &rc);
    const int kWidth = width(rc);
    const int kHeight = height(rc);
    const RECT kOldSplitterRect = verticalSplitterRect_;
    verticalSplitterRect_ = {};
    const int kTabHeight = 28;
    const bool kShowPrimary = !hasDirectFeatureId_;
    const bool kShowSecondary = currentPrimaryUsesSecondaryTabs();
    const KernelFeatureDescriptor* descriptor = currentDescriptor();
    const bool kShowPropertyTable = descriptor != nullptr &&
        layoutKindForFeature(descriptor->id) == KernelPageLayoutKind::kTreeWithPropertyTable;
    const bool kShowSummaryTable = descriptor != nullptr &&
        layoutKindForFeature(descriptor->id) == KernelPageLayoutKind::kDualTable;
    const bool kShowRuntimePanel = descriptor != nullptr &&
        layoutKindForFeature(descriptor->id) == KernelPageLayoutKind::kRuntimePanel;
    const bool kShowCallbackPanel = descriptor != nullptr &&
        descriptor->id == KernelFeatureId::kCallbackIntercept;
    const bool kShowTableDetail = descriptor != nullptr &&
        layoutKindForFeature(descriptor->id) == KernelPageLayoutKind::kTableWithDetail;
    const bool kShowObjectNamespacePanel = descriptor != nullptr && isObjectNamespaceFeature(descriptor->id);
    const bool kShowAtomPanel = descriptor != nullptr && descriptor->id == KernelFeatureId::kAtomTable;
    const bool kShowNtQueryPanel = descriptor != nullptr && descriptor->id == KernelFeatureId::kNtQueryLegacy;
    const bool kShowKernelHookPanel = descriptor != nullptr && isKernelHookFeature(descriptor->id);
    const bool kShowIncludeCombo = descriptor != nullptr &&
        (descriptor->id == KernelFeatureId::kInlineHook || descriptor->id == KernelFeatureId::kIatEatHook);
    const int kSecondaryHeight = kShowSecondary ? kTabHeight : 0;
    const bool kShowDiagnosticDualPanel = descriptor != nullptr &&
        (descriptor->id == KernelFeatureId::kDynData || descriptor->id == KernelFeatureId::kDriverStatus);
    const bool kShowCallbackEnumerationPanel = descriptor != nullptr && descriptor->id == KernelFeatureId::kCallbackEnumeration;
    const bool kShowKernelMemoryScanPanel = descriptor != nullptr &&
        (descriptor->id == KernelFeatureId::kKernelExecutableMemory ||
            descriptor->id == KernelFeatureId::kKernelMemoryEvidence);
    const bool kShowCrossViewPanel = descriptor != nullptr &&
        (descriptor->id == KernelFeatureId::kProcessCrossView ||
            descriptor->id == KernelFeatureId::kThreadCrossView);
    const bool kShowIntegrityPanel = descriptor != nullptr &&
        (descriptor->id == KernelFeatureId::kDriverIntegrity ||
            descriptor->id == KernelFeatureId::kKernelCpuIntegrity);
    const bool kShowR0EvidencePanel = descriptor != nullptr &&
        (descriptor->id == KernelFeatureId::kCpuHardwareSnapshot ||
            descriptor->id == KernelFeatureId::kPhysicalMemoryLayout ||
            descriptor->id == KernelFeatureId::kMutationAudit ||
            descriptor->id == KernelFeatureId::kKeyboardHotkeys ||
             descriptor->id == KernelFeatureId::kKeyboardHooks ||
             descriptor->id == KernelFeatureId::kDynDataCapabilities ||
             descriptor->id == KernelFeatureId::kMinifilterBypassPids ||
             descriptor->id == KernelFeatureId::kKernelTimerDpc ||
             descriptor->id == KernelFeatureId::kIoctlRegistry);
    const int kInfoHeight = (kShowObjectNamespacePanel || kShowAtomPanel || kShowNtQueryPanel || kShowKernelHookPanel || kShowDiagnosticDualPanel ||
        kShowCallbackEnumerationPanel || kShowKernelMemoryScanPanel || kShowCrossViewPanel || kShowIntegrityPanel || kShowR0EvidencePanel) ? 28 : 96;
    const int kButtonWidth = 92;
    const int kButtonHeight = 24;
    const int kStatusHeight = 20;
    const bool kShowCopyDiagnostic = descriptor != nullptr &&
        (descriptor->id == KernelFeatureId::kDynData || descriptor->id == KernelFeatureId::kDriverStatus);
    const int kCopyWidth = kShowCopyDiagnostic ? 82 : 0;
    const int kDetailHeight = kShowKernelHookPanel
        ? std::max(130, (std::max(0, kHeight - (kTabHeight + kSecondaryHeight + kInfoHeight + kStatusHeight)) * 2) / 5)
        : kShowTableDetail
        ? std::max(96, (std::max(0, kHeight - (kTabHeight + kSecondaryHeight + kInfoHeight + kStatusHeight)) * 2) / 5)
        : std::min(150, std::max(72, kHeight / 5));
    const int kFilterLabelWidth = 72;
    const int kLocateWidth = 52;
    const int kIncludeWidth = kShowIncludeCombo ? 150 : 0;
    const int kFilterEditWidth = std::max(120, (kWidth - kButtonWidth - kLocateWidth - kCopyWidth - kIncludeWidth - kFilterLabelWidth * 2) / 2);

    ::ShowWindow(primaryTab_, kShowPrimary ? SW_SHOW : SW_HIDE);
    ::MoveWindow(primaryTab_, 0, 0, kWidth, kTabHeight, TRUE);
    ::ShowWindow(secondaryTab_, kShowSecondary ? SW_SHOW : SW_HIDE);
    ::MoveWindow(secondaryTab_, 0, kTabHeight, kWidth, kSecondaryHeight, TRUE);
    const int kContentTop = (kShowPrimary ? kTabHeight : 0) + kSecondaryHeight;
    const int kActionRight = kWidth;
    const int kRefreshLeft = std::max(0, kActionRight - kButtonWidth);
    const int kCopyLeft = std::max(0, kRefreshLeft - kCopyWidth);
    const int kLocateLeft = std::max(0, kCopyLeft - kLocateWidth);
    ::MoveWindow(titleText_, 0, kContentTop, std::max(0, kLocateLeft - 4), 22, TRUE);
    ::MoveWindow(locateButton_, kLocateLeft, kContentTop, kLocateWidth, kButtonHeight, TRUE);
    ::ShowWindow(copyDiagnosticButton_, kShowCopyDiagnostic ? SW_SHOW : SW_HIDE);
    ::MoveWindow(copyDiagnosticButton_, kCopyLeft, kContentTop, kCopyWidth, kButtonHeight, TRUE);
    ::MoveWindow(refreshButton_, kRefreshLeft, kContentTop, kButtonWidth, kButtonHeight, TRUE);
    ::MoveWindow(summaryText_, 0, kContentTop + 22, kWidth, 28, TRUE);
    ::MoveWindow(backendText_, 0, kContentTop + 50, kWidth, 22, TRUE);
    const int kFilterTop = kContentTop + 72;
    int cursorX = 0;
    ::MoveWindow(filterLabel_, cursorX, kFilterTop + 3, kFilterLabelWidth, 20, TRUE);
    cursorX += kFilterLabelWidth;
    ::MoveWindow(filterEdit_, cursorX, kFilterTop, kFilterEditWidth, 22, TRUE);
    cursorX += kFilterEditWidth;
    ::MoveWindow(moduleFilterLabel_, cursorX, kFilterTop + 3, kFilterLabelWidth, 20, TRUE);
    cursorX += kFilterLabelWidth;
    const int kModuleWidth = std::max(0, kWidth - cursorX - kIncludeWidth);
    ::MoveWindow(moduleFilterEdit_, cursorX, kFilterTop, kModuleWidth, 22, TRUE);
    cursorX += kModuleWidth;
    ::ShowWindow(includeCombo_, kShowIncludeCombo ? SW_SHOW : SW_HIDE);
    ::MoveWindow(includeCombo_, cursorX, kFilterTop, kIncludeWidth, 240, TRUE);
    ::MoveWindow(statusText_, 0, kContentTop + kInfoHeight, kWidth, kStatusHeight, TRUE);
    const int kResultTop = kContentTop + kInfoHeight + kStatusHeight;
    const int kResultHeight = std::max(0, kHeight - (kResultTop + kDetailHeight));
    const auto kMoveResultDetailSplitter = [&](const int panelTop, const int minimumTableHeight, const int minimumDetailHeight) {
        // moveResultDetailSplitter mirrors the vertical splitters used by the
        // source dock pages. Inputs are the top edge and minimum pane heights;
        // processing clamps the saved table height, moves the table/detail HWNDs,
        // and redraws only the splitter strip; there is no return value.
        const int kAvailableHeight = std::max(0, kHeight - panelTop);
        const int kMaximumTableHeight = std::max(minimumTableHeight,
            kAvailableHeight - minimumDetailHeight - kKernelSplitterThickness);
        if (verticalSplitterOffset_ < 0) {
            verticalSplitterOffset_ = std::max(minimumTableHeight, (kAvailableHeight * 3) / 5);
        }
        const int kTableHeight = clampInt(verticalSplitterOffset_, minimumTableHeight, kMaximumTableHeight);
        const int kSplitterTop = panelTop + kTableHeight;
        const int kDetailTop = kSplitterTop + kKernelSplitterThickness;
        verticalSplitterOffset_ = kTableHeight;
        verticalSplitterRect_ = RECT{ 0, kSplitterTop, kWidth, kSplitterTop + kKernelSplitterThickness };
        ::MoveWindow(resultList_, 0, panelTop, kWidth, std::min(kAvailableHeight, kTableHeight), TRUE);
        ::MoveWindow(detailEdit_, 0, kDetailTop, kWidth, std::max(0, kHeight - kDetailTop), TRUE);
        ::InvalidateRect(hwnd_, &verticalSplitterRect_, FALSE);
        if (width(kOldSplitterRect) > 0 || height(kOldSplitterRect) > 0) {
            ::InvalidateRect(hwnd_, &kOldSplitterRect, FALSE);
        }
    };
    std::vector<HWND> callbackControls = {
        callbackGlobalEnabledCheck_, callbackApplyButton_, callbackReloadButton_, callbackImportButton_, callbackExportButton_,
        callbackStartReceiverButton_, callbackStopReceiverButton_, callbackAllowEventButton_, callbackDenyEventButton_,
        callbackStatusText_, callbackGroupLabel_, callbackAddGroupButton_, callbackRemoveGroupButton_,
        callbackRenameGroupButton_, callbackMoveGroupUpButton_, callbackMoveGroupDownButton_, callbackGroupList_,
        callbackRuleLabel_, callbackAddRuleButton_, callbackRemoveRuleButton_, callbackMoveRuleUpButton_,
        callbackMoveRuleDownButton_, callbackRuleTab_, callbackBypassLabel_, callbackBypassPidEdit_,
        callbackBypassAddButton_, callbackBypassRemoveButton_, callbackBypassApplyButton_, callbackBypassClearButton_,
        callbackBypassRefreshButton_, callbackBypassList_, callbackBypassStatusText_, callbackLogTab_, callbackAppLogEdit_, callbackEventLogEdit_,
        callbackFileMonitorLabel_, callbackStartFsctlButton_, callbackDrainFileMonitorButton_, callbackClearFileMonitorButton_,
        callbackExportFileMonitorButton_, callbackFileMonitorFsctlOnlyCheck_, callbackFileMonitorStatusText_, callbackFileMonitorList_
    };
    for (HWND child : callbackRuleLists_) {
        callbackControls.push_back(child);
    }
    for (HWND child : callbackControls) {
        ::ShowWindow(child, kShowCallbackPanel ? SW_SHOW : SW_HIDE);
    }
    const std::vector<HWND> kKernelMemoryControls = {
        riskOnlyCheck_, evidenceIncludeNonModuleCheck_, evidenceStartEdit_, evidenceEndEdit_,
        evidenceMaxRowsLabel_, evidenceMaxRowsEdit_, evidenceMaxRowsSpin_,
        integrityModuleBaseLabel_, integrityModuleBaseEdit_, integrityFillFromSelectionButton_, integrityCpuOnlyButton_,
        integrityIdtVectorsLabel_, integrityIdtVectorsEdit_, integrityIdtVectorsSpin_,
        deviceDriverDirectoryLabel_, deviceDriverDirectoryCombo_, deviceDriverTypeLabel_, deviceDriverTypeCombo_,
        baseNamedScopeCombo_, baseNamedTypeCombo_, symbolicLinkNoteText_
    };
    for (HWND child : kKernelMemoryControls) {
        ::ShowWindow(child, SW_HIDE);
    }
    ::ShowWindow(objectNamespaceTree_, SW_HIDE);

    if (kShowAtomPanel) {
        ::ShowWindow(titleText_, SW_HIDE);
        ::ShowWindow(summaryText_, SW_HIDE);
        ::ShowWindow(backendText_, SW_HIDE);
        ::ShowWindow(filterLabel_, SW_HIDE);
        ::ShowWindow(filterEdit_, SW_SHOW);
        ::ShowWindow(moduleFilterLabel_, SW_HIDE);
        ::ShowWindow(moduleFilterEdit_, SW_HIDE);
        ::ShowWindow(includeCombo_, SW_HIDE);
        ::ShowWindow(locateButton_, SW_HIDE);
        ::ShowWindow(copyDiagnosticButton_, SW_HIDE);
        ::ShowWindow(refreshButton_, SW_SHOW);
        ::ShowWindow(propertyList_, SW_HIDE);
        ::ShowWindow(summaryList_, SW_HIDE);
        ::ShowWindow(resultList_, SW_SHOW);
        ::ShowWindow(detailEdit_, SW_SHOW);

        const int kToolbarTop = kContentTop;
        int toolbarX = 0;
        ::MoveWindow(refreshButton_, toolbarX, kToolbarTop + 2, 34, kButtonHeight, TRUE);
        toolbarX += 40;
        const int kStatusWidth = std::min(360, std::max(120, kWidth / 3));
        const int kFilterWidth = std::max(120, kWidth - toolbarX - kStatusWidth - 6);
        ::MoveWindow(filterEdit_, toolbarX, kToolbarTop + 3, kFilterWidth, 22, TRUE);
        toolbarX += kFilterWidth + 6;
        ::MoveWindow(statusText_, toolbarX, kToolbarTop + 4, std::max(0, kWidth - toolbarX), 22, TRUE);

        const int kPanelTop = kContentTop + kInfoHeight;
        const int kAvailableHeight = std::max(0, kHeight - kPanelTop);
        const int kTableHeight = std::max(120, (kAvailableHeight * 3) / 5);
        ::MoveWindow(resultList_, 0, kPanelTop, kWidth, std::min(kAvailableHeight, kTableHeight), TRUE);
        ::MoveWindow(detailEdit_, 0, kPanelTop + std::min(kAvailableHeight, kTableHeight), kWidth,
            std::max(0, kAvailableHeight - std::min(kAvailableHeight, kTableHeight)), TRUE);
        return;
    }

    if (kShowNtQueryPanel) {
        ::ShowWindow(titleText_, SW_HIDE);
        ::ShowWindow(summaryText_, SW_HIDE);
        ::ShowWindow(backendText_, SW_HIDE);
        ::ShowWindow(filterLabel_, SW_HIDE);
        ::ShowWindow(filterEdit_, SW_HIDE);
        ::ShowWindow(moduleFilterLabel_, SW_HIDE);
        ::ShowWindow(moduleFilterEdit_, SW_HIDE);
        ::ShowWindow(includeCombo_, SW_HIDE);
        ::ShowWindow(locateButton_, SW_HIDE);
        ::ShowWindow(copyDiagnosticButton_, SW_HIDE);
        ::ShowWindow(refreshButton_, SW_SHOW);
        ::ShowWindow(propertyList_, SW_HIDE);
        ::ShowWindow(summaryList_, SW_HIDE);
        ::ShowWindow(resultList_, SW_SHOW);
        ::ShowWindow(detailEdit_, SW_SHOW);

        const int kToolbarTop = kContentTop;
        ::MoveWindow(refreshButton_, 0, kToolbarTop + 2, 34, kButtonHeight, TRUE);
        ::MoveWindow(statusText_, 40, kToolbarTop + 4, std::max(0, kWidth - 40), 22, TRUE);

        const int kPanelTop = kContentTop + kInfoHeight;
        const int kAvailableHeight = std::max(0, kHeight - kPanelTop);
        const int kTableHeight = std::max(120, (kAvailableHeight * 3) / 5);
        const int kVisibleTableHeight = std::min(kAvailableHeight, kTableHeight);
        ::MoveWindow(resultList_, 0, kPanelTop, kWidth, kVisibleTableHeight, TRUE);
        ::MoveWindow(detailEdit_, 0, kPanelTop + kVisibleTableHeight, kWidth,
            std::max(0, kAvailableHeight - kVisibleTableHeight), TRUE);
        return;
    }

    if (kShowObjectNamespacePanel) {
        if (descriptor->id == KernelFeatureId::kObjectNamespaceOverview) {
            ::ShowWindow(titleText_, SW_HIDE);
            ::ShowWindow(summaryText_, SW_HIDE);
            ::ShowWindow(backendText_, SW_HIDE);
            ::ShowWindow(filterLabel_, SW_HIDE);
            ::ShowWindow(filterEdit_, SW_SHOW);
            ::ShowWindow(moduleFilterLabel_, SW_HIDE);
            ::ShowWindow(moduleFilterEdit_, SW_HIDE);
            ::ShowWindow(symbolicLinkNoteText_, SW_HIDE);
            ::ShowWindow(deviceDriverDirectoryLabel_, SW_HIDE);
            ::ShowWindow(deviceDriverDirectoryCombo_, SW_HIDE);
            ::ShowWindow(deviceDriverTypeLabel_, SW_HIDE);
            ::ShowWindow(deviceDriverTypeCombo_, SW_HIDE);
            ::ShowWindow(baseNamedScopeCombo_, SW_HIDE);
            ::ShowWindow(baseNamedTypeCombo_, SW_HIDE);
            ::ShowWindow(includeCombo_, SW_HIDE);
            ::ShowWindow(locateButton_, SW_HIDE);
            ::ShowWindow(copyDiagnosticButton_, SW_HIDE);
            ::ShowWindow(refreshButton_, SW_SHOW);
            ::ShowWindow(statusText_, SW_SHOW);
            ::ShowWindow(summaryList_, SW_HIDE);
            ::ShowWindow(propertyList_, SW_SHOW);
            ::ShowWindow(resultList_, SW_SHOW);
            ::ShowWindow(objectNamespaceTree_, SW_HIDE);
            ::ShowWindow(detailEdit_, SW_SHOW);

            const int kToolbarTop = kContentTop;
            int toolbarX = 0;
            ::MoveWindow(refreshButton_, toolbarX, kToolbarTop + 2, 34, kButtonHeight, TRUE);
            toolbarX += 40;
            const int kStatusWidth = std::min(360, std::max(150, kWidth / 3));
            const int kFilterWidth = std::max(160, std::max(0, kWidth - toolbarX - kStatusWidth - 6));
            ::MoveWindow(filterEdit_, toolbarX, kToolbarTop + 3, kFilterWidth, 22, TRUE);
            toolbarX += kFilterWidth + 6;
            ::MoveWindow(statusText_, toolbarX, kToolbarTop + 4, std::max(0, kWidth - toolbarX), 22, TRUE);

            const int kObjectTop = kContentTop + kInfoHeight;
            const int kAvailableHeight = std::max(0, kHeight - kObjectTop);
            const int kObjectDetailHeight = std::max(96, kAvailableHeight / 3);
            const int kObjectResultHeight = std::max(0, kAvailableHeight - kObjectDetailHeight);
            const int kPropertyWidth = std::max(260, (kWidth * 2) / 5);
            ::MoveWindow(resultList_, 0, kObjectTop, std::max(0, kWidth - kPropertyWidth), kObjectResultHeight, TRUE);
            ::MoveWindow(objectNamespaceTree_, 0, kObjectTop, 0, 0, TRUE);
            ::MoveWindow(propertyList_, std::max(0, kWidth - kPropertyWidth), kObjectTop, kPropertyWidth, kObjectResultHeight, TRUE);
            ::MoveWindow(detailEdit_, 0, kObjectTop + kObjectResultHeight, kWidth, kObjectDetailHeight, TRUE);
            return;
        }
        if (descriptor->id == KernelFeatureId::kObjectDirectoryRecursive) {
            ::ShowWindow(titleText_, SW_HIDE);
            ::ShowWindow(summaryText_, SW_HIDE);
            ::ShowWindow(backendText_, SW_HIDE);
            ::ShowWindow(filterLabel_, SW_SHOW);
            ::ShowWindow(filterEdit_, SW_SHOW);
            ::ShowWindow(moduleFilterLabel_, SW_SHOW);
            ::ShowWindow(moduleFilterEdit_, SW_SHOW);
            ::ShowWindow(symbolicLinkNoteText_, SW_HIDE);
            ::ShowWindow(deviceDriverDirectoryLabel_, SW_HIDE);
            ::ShowWindow(deviceDriverDirectoryCombo_, SW_HIDE);
            ::ShowWindow(deviceDriverTypeLabel_, SW_HIDE);
            ::ShowWindow(deviceDriverTypeCombo_, SW_HIDE);
            ::ShowWindow(baseNamedScopeCombo_, SW_HIDE);
            ::ShowWindow(baseNamedTypeCombo_, SW_HIDE);
            ::ShowWindow(includeCombo_, SW_HIDE);
            ::ShowWindow(locateButton_, SW_HIDE);
            ::ShowWindow(copyDiagnosticButton_, SW_HIDE);
            ::ShowWindow(refreshButton_, SW_SHOW);
            ::ShowWindow(statusText_, SW_SHOW);
            ::ShowWindow(summaryList_, SW_HIDE);
            ::ShowWindow(propertyList_, SW_HIDE);
            ::ShowWindow(resultList_, SW_SHOW);
            ::ShowWindow(objectNamespaceTree_, SW_HIDE);
            ::ShowWindow(detailEdit_, SW_SHOW);

            const int kToolbarTop = kContentTop;
            int toolbarX = 0;
            ::MoveWindow(filterLabel_, toolbarX, kToolbarTop + 5, 52, 20, TRUE);
            toolbarX += 52;
            const int kDepthLabelWidth = 64;
            const int kDepthEditWidth = 56;
            const int kRefreshWidth = 56;
            const int kStatusWidth = std::min(360, std::max(150, kWidth / 3));
            const int kRootEditWidth = std::max(120,
                std::max(0, kWidth - toolbarX - kDepthLabelWidth - kDepthEditWidth - kRefreshWidth - kStatusWidth - 24));
            ::MoveWindow(filterEdit_, toolbarX, kToolbarTop + 3, kRootEditWidth, 22, TRUE);
            toolbarX += kRootEditWidth + 6;
            ::MoveWindow(moduleFilterLabel_, toolbarX, kToolbarTop + 5, kDepthLabelWidth, 20, TRUE);
            toolbarX += kDepthLabelWidth;
            ::MoveWindow(moduleFilterEdit_, toolbarX, kToolbarTop + 3, kDepthEditWidth, 22, TRUE);
            toolbarX += kDepthEditWidth + 6;
            ::MoveWindow(refreshButton_, toolbarX, kToolbarTop + 2, kRefreshWidth, kButtonHeight, TRUE);
            toolbarX += kRefreshWidth + 6;
            ::MoveWindow(statusText_, toolbarX, kToolbarTop + 4, std::max(0, kWidth - toolbarX), 22, TRUE);

            const int kObjectTop = kContentTop + kInfoHeight;
            const int kAvailableHeight = std::max(0, kHeight - kObjectTop);
            const int kObjectDetailHeight = std::max(120, kAvailableHeight / 3);
            const int kObjectResultHeight = std::max(0, kAvailableHeight - kObjectDetailHeight);
            ::MoveWindow(resultList_, 0, kObjectTop, kWidth, kObjectResultHeight, TRUE);
            ::MoveWindow(detailEdit_, 0, kObjectTop + kObjectResultHeight, kWidth, kObjectDetailHeight, TRUE);
            return;
        }
        if (descriptor->id == KernelFeatureId::kNamedPipe) {
            ::ShowWindow(titleText_, SW_HIDE);
            ::ShowWindow(summaryText_, SW_HIDE);
            ::ShowWindow(backendText_, SW_HIDE);
            ::ShowWindow(filterLabel_, SW_HIDE);
            ::ShowWindow(filterEdit_, SW_SHOW);
            ::ShowWindow(moduleFilterLabel_, SW_HIDE);
            ::ShowWindow(moduleFilterEdit_, SW_HIDE);
            ::ShowWindow(symbolicLinkNoteText_, SW_HIDE);
            ::ShowWindow(deviceDriverDirectoryLabel_, SW_HIDE);
            ::ShowWindow(deviceDriverDirectoryCombo_, SW_HIDE);
            ::ShowWindow(deviceDriverTypeLabel_, SW_HIDE);
            ::ShowWindow(deviceDriverTypeCombo_, SW_HIDE);
            ::ShowWindow(baseNamedScopeCombo_, SW_HIDE);
            ::ShowWindow(baseNamedTypeCombo_, SW_HIDE);
            ::ShowWindow(includeCombo_, SW_HIDE);
            ::ShowWindow(locateButton_, SW_HIDE);
            ::ShowWindow(copyDiagnosticButton_, SW_SHOW);
            ::ShowWindow(refreshButton_, SW_SHOW);
            ::ShowWindow(statusText_, SW_SHOW);
            ::ShowWindow(summaryList_, SW_HIDE);
            ::ShowWindow(propertyList_, SW_HIDE);
            ::ShowWindow(resultList_, SW_SHOW);
            ::ShowWindow(objectNamespaceTree_, SW_HIDE);
            ::ShowWindow(detailEdit_, SW_SHOW);

            const int kToolbarTop = kContentTop;
            int toolbarX = 0;
            ::MoveWindow(refreshButton_, toolbarX, kToolbarTop + 2, 34, kButtonHeight, TRUE);
            toolbarX += 38;
            ::MoveWindow(copyDiagnosticButton_, toolbarX, kToolbarTop + 2, 34, kButtonHeight, TRUE);
            toolbarX += 38;
            const int kStatusWidth = std::min(360, std::max(180, kWidth / 3));
            const int kFilterWidth = std::max(140, std::max(0, kWidth - toolbarX - kStatusWidth - 6));
            ::MoveWindow(filterEdit_, toolbarX, kToolbarTop + 3, kFilterWidth, 22, TRUE);
            toolbarX += kFilterWidth + 6;
            ::MoveWindow(statusText_, toolbarX, kToolbarTop + 4, std::max(0, kWidth - toolbarX), 22, TRUE);

            const int kObjectTop = kContentTop + 28;
            const int kObjectDetailHeight = std::min(150, std::max(96, kHeight / 4));
            const int kObjectResultHeight = std::max(0, kHeight - kObjectTop - kObjectDetailHeight);
            ::MoveWindow(resultList_, 0, kObjectTop, kWidth, kObjectResultHeight, TRUE);
            ::MoveWindow(detailEdit_, 0, std::max(0, kHeight - kObjectDetailHeight), kWidth, kObjectDetailHeight, TRUE);
            return;
        }
        if (descriptor->id == KernelFeatureId::kSymbolicLink) {
            ::ShowWindow(titleText_, SW_HIDE);
            ::ShowWindow(summaryText_, SW_HIDE);
            ::ShowWindow(backendText_, SW_HIDE);
            ::ShowWindow(filterLabel_, SW_HIDE);
            ::ShowWindow(filterEdit_, SW_SHOW);
            ::ShowWindow(moduleFilterLabel_, SW_HIDE);
            ::ShowWindow(moduleFilterEdit_, SW_SHOW);
            ::ShowWindow(symbolicLinkNoteText_, SW_SHOW);
            ::ShowWindow(deviceDriverDirectoryLabel_, SW_HIDE);
            ::ShowWindow(deviceDriverDirectoryCombo_, SW_HIDE);
            ::ShowWindow(deviceDriverTypeLabel_, SW_HIDE);
            ::ShowWindow(deviceDriverTypeCombo_, SW_HIDE);
            ::ShowWindow(baseNamedScopeCombo_, SW_HIDE);
            ::ShowWindow(baseNamedTypeCombo_, SW_HIDE);
            ::ShowWindow(includeCombo_, SW_HIDE);
            ::ShowWindow(locateButton_, SW_HIDE);
            ::ShowWindow(copyDiagnosticButton_, SW_SHOW);
            ::ShowWindow(refreshButton_, SW_SHOW);
            ::ShowWindow(statusText_, SW_SHOW);
            ::ShowWindow(summaryList_, SW_HIDE);
            ::ShowWindow(propertyList_, SW_HIDE);
            ::ShowWindow(resultList_, SW_SHOW);
            ::ShowWindow(objectNamespaceTree_, SW_HIDE);
            ::ShowWindow(detailEdit_, SW_HIDE);

            const int kToolbarTop = kContentTop;
            int toolbarX = 0;
            ::MoveWindow(refreshButton_, toolbarX, kToolbarTop + 2, 56, kButtonHeight, TRUE);
            toolbarX += 60;
            ::MoveWindow(copyDiagnosticButton_, toolbarX, kToolbarTop + 2, 76, kButtonHeight, TRUE);
            toolbarX += 82;
            const int kStatusWidth = std::min(320, std::max(140, kWidth / 4));
            const int kFilterWidth = std::max(140, std::max(0, (kWidth - toolbarX - kStatusWidth - 12) / 2));
            ::MoveWindow(filterEdit_, toolbarX, kToolbarTop + 3, kFilterWidth, 22, TRUE);
            toolbarX += kFilterWidth + 6;
            ::MoveWindow(moduleFilterEdit_, toolbarX, kToolbarTop + 3, kFilterWidth, 22, TRUE);
            toolbarX += kFilterWidth + 6;
            ::MoveWindow(statusText_, toolbarX, kToolbarTop + 4, std::max(0, kWidth - toolbarX), 22, TRUE);

            const int kNoteTop = kToolbarTop + 28;
            ::MoveWindow(symbolicLinkNoteText_, 0, kNoteTop + 2, kWidth, 22, TRUE);
            const int kObjectTop = kContentTop + 56;
            ::MoveWindow(resultList_, 0, kObjectTop, kWidth, std::max(0, kHeight - kObjectTop), TRUE);
            ::MoveWindow(detailEdit_, 0, kHeight, kWidth, 0, TRUE);
            return;
        }
        if (descriptor->id == KernelFeatureId::kBaseNamedObjects) {
            ::ShowWindow(titleText_, SW_HIDE);
            ::ShowWindow(summaryText_, SW_HIDE);
            ::ShowWindow(backendText_, SW_HIDE);
            ::ShowWindow(filterLabel_, SW_HIDE);
            ::ShowWindow(filterEdit_, SW_SHOW);
            ::ShowWindow(moduleFilterLabel_, SW_HIDE);
            ::ShowWindow(moduleFilterEdit_, SW_HIDE);
            ::ShowWindow(deviceDriverDirectoryLabel_, SW_HIDE);
            ::ShowWindow(deviceDriverDirectoryCombo_, SW_HIDE);
            ::ShowWindow(deviceDriverTypeLabel_, SW_HIDE);
            ::ShowWindow(deviceDriverTypeCombo_, SW_HIDE);
            ::ShowWindow(baseNamedScopeCombo_, SW_SHOW);
            ::ShowWindow(baseNamedTypeCombo_, SW_SHOW);
            ::ShowWindow(includeCombo_, SW_HIDE);
            ::ShowWindow(locateButton_, SW_HIDE);
            ::ShowWindow(copyDiagnosticButton_, SW_HIDE);
            ::ShowWindow(refreshButton_, SW_SHOW);
            ::ShowWindow(statusText_, SW_SHOW);
            ::ShowWindow(summaryList_, SW_HIDE);
            ::ShowWindow(propertyList_, SW_HIDE);
            ::ShowWindow(resultList_, SW_SHOW);
            ::ShowWindow(objectNamespaceTree_, SW_HIDE);
            ::ShowWindow(detailEdit_, SW_HIDE);

            const int kToolbarTop = kContentTop;
            int toolbarX = 0;
            ::MoveWindow(refreshButton_, toolbarX, kToolbarTop + 2, 56, kButtonHeight, TRUE);
            toolbarX += 62;
            const int kScopeWidth = std::max(130, std::min(190, kWidth / 6));
            ::MoveWindow(baseNamedScopeCombo_, toolbarX, kToolbarTop + 2, kScopeWidth, 240, TRUE);
            toolbarX += kScopeWidth + 6;
            const int kTypeWidth = std::max(130, std::min(190, kWidth / 6));
            ::MoveWindow(baseNamedTypeCombo_, toolbarX, kToolbarTop + 2, kTypeWidth, 240, TRUE);
            toolbarX += kTypeWidth + 6;
            const int kStatusWidth = std::min(360, std::max(150, kWidth / 3));
            const int kKeywordWidth = std::max(120, std::max(0, kWidth - toolbarX - kStatusWidth - 6));
            ::MoveWindow(filterEdit_, toolbarX, kToolbarTop + 3, kKeywordWidth, 22, TRUE);
            toolbarX += kKeywordWidth + 6;
            ::MoveWindow(statusText_, toolbarX, kToolbarTop + 4, std::max(0, kWidth - toolbarX), 22, TRUE);

            const int kObjectTop = kContentTop + 28;
            ::MoveWindow(resultList_, 0, kObjectTop, kWidth, std::max(0, kHeight - kObjectTop), TRUE);
            ::MoveWindow(detailEdit_, 0, kHeight, kWidth, 0, TRUE);
            return;
        }
        if (descriptor->id == KernelFeatureId::kDeviceDriverObjects) {
            ::ShowWindow(titleText_, SW_HIDE);
            ::ShowWindow(summaryText_, SW_HIDE);
            ::ShowWindow(backendText_, SW_HIDE);
            ::ShowWindow(filterLabel_, SW_SHOW);
            ::ShowWindow(filterEdit_, SW_SHOW);
            ::ShowWindow(moduleFilterLabel_, SW_HIDE);
            ::ShowWindow(moduleFilterEdit_, SW_HIDE);
            ::ShowWindow(deviceDriverDirectoryLabel_, SW_SHOW);
            ::ShowWindow(deviceDriverDirectoryCombo_, SW_SHOW);
            ::ShowWindow(deviceDriverTypeLabel_, SW_SHOW);
            ::ShowWindow(deviceDriverTypeCombo_, SW_SHOW);
            ::ShowWindow(includeCombo_, SW_HIDE);
            ::ShowWindow(locateButton_, SW_HIDE);
            ::ShowWindow(refreshButton_, SW_SHOW);
            ::ShowWindow(copyDiagnosticButton_, SW_SHOW);
            ::ShowWindow(statusText_, SW_SHOW);
            ::ShowWindow(summaryList_, SW_HIDE);
            ::ShowWindow(propertyList_, SW_HIDE);
            ::ShowWindow(resultList_, SW_SHOW);
            ::ShowWindow(objectNamespaceTree_, SW_HIDE);
            ::ShowWindow(detailEdit_, SW_HIDE);

            const int kToolbarTop = kContentTop;
            int toolbarX = 0;
            ::MoveWindow(refreshButton_, toolbarX, kToolbarTop + 2, 56, kButtonHeight, TRUE);
            toolbarX += 60;
            ::MoveWindow(copyDiagnosticButton_, toolbarX, kToolbarTop + 2, 76, kButtonHeight, TRUE);
            toolbarX += 82;
            ::MoveWindow(statusText_, toolbarX, kToolbarTop + 4, std::max(0, kWidth - toolbarX), 22, TRUE);

            const int kFilterTop = kToolbarTop + 28;
            int filterX = 0;
            ::MoveWindow(deviceDriverDirectoryLabel_, filterX, kFilterTop + 5, 42, 20, TRUE);
            filterX += 42;
            const int kDirectoryWidth = std::max(150, std::min(230, kWidth / 5));
            ::MoveWindow(deviceDriverDirectoryCombo_, filterX, kFilterTop + 2, kDirectoryWidth, 260, TRUE);
            filterX += kDirectoryWidth + 6;
            ::MoveWindow(deviceDriverTypeLabel_, filterX, kFilterTop + 5, 42, 20, TRUE);
            filterX += 42;
            const int kTypeWidth = std::max(130, std::min(200, kWidth / 6));
            ::MoveWindow(deviceDriverTypeCombo_, filterX, kFilterTop + 2, kTypeWidth, 260, TRUE);
            filterX += kTypeWidth + 6;
            ::SetWindowTextW(filterLabel_, L"关键字：");
            ::MoveWindow(filterLabel_, filterX, kFilterTop + 5, 58, 20, TRUE);
            filterX += 58;
            ::MoveWindow(filterEdit_, filterX, kFilterTop + 3, std::max(0, kWidth - filterX), 22, TRUE);

            const int kObjectTop = kContentTop + 56;
            ::MoveWindow(resultList_, 0, kObjectTop, kWidth, std::max(0, kHeight - kObjectTop), TRUE);
            ::MoveWindow(detailEdit_, 0, kHeight, kWidth, 0, TRUE);
            return;
        }
        if (descriptor->id == KernelFeatureId::kObjectTypeMatrix) {
            ::ShowWindow(titleText_, SW_HIDE);
            ::ShowWindow(summaryText_, SW_HIDE);
            ::ShowWindow(backendText_, SW_HIDE);
            ::ShowWindow(filterLabel_, SW_HIDE);
            ::ShowWindow(filterEdit_, SW_SHOW);
            ::ShowWindow(moduleFilterLabel_, SW_HIDE);
            ::ShowWindow(moduleFilterEdit_, SW_HIDE);
            ::ShowWindow(symbolicLinkNoteText_, SW_HIDE);
            ::ShowWindow(deviceDriverDirectoryLabel_, SW_HIDE);
            ::ShowWindow(deviceDriverDirectoryCombo_, SW_HIDE);
            ::ShowWindow(deviceDriverTypeLabel_, SW_HIDE);
            ::ShowWindow(deviceDriverTypeCombo_, SW_HIDE);
            ::ShowWindow(baseNamedScopeCombo_, SW_HIDE);
            ::ShowWindow(baseNamedTypeCombo_, SW_HIDE);
            ::ShowWindow(includeCombo_, SW_HIDE);
            ::ShowWindow(locateButton_, SW_HIDE);
            ::ShowWindow(copyDiagnosticButton_, SW_HIDE);
            ::ShowWindow(refreshButton_, SW_SHOW);
            ::ShowWindow(statusText_, SW_SHOW);
            ::ShowWindow(summaryList_, SW_HIDE);
            ::ShowWindow(propertyList_, SW_HIDE);
            ::ShowWindow(resultList_, SW_SHOW);
            ::ShowWindow(objectNamespaceTree_, SW_HIDE);
            ::ShowWindow(detailEdit_, SW_HIDE);

            const int kToolbarTop = kContentTop;
            int toolbarX = 0;
            ::MoveWindow(refreshButton_, toolbarX, kToolbarTop + 2, 34, kButtonHeight, TRUE);
            toolbarX += 38;
            const int kStatusWidth = std::min(320, std::max(150, kWidth / 3));
            const int kFilterWidth = std::max(120, std::max(0, kWidth - toolbarX - kStatusWidth - 6));
            ::MoveWindow(filterEdit_, toolbarX, kToolbarTop + 3, kFilterWidth, 22, TRUE);
            toolbarX += kFilterWidth + 6;
            ::MoveWindow(statusText_, toolbarX, kToolbarTop + 4, std::max(0, kWidth - toolbarX), 22, TRUE);

            const int kObjectTop = kContentTop + 28;
            ::MoveWindow(resultList_, 0, kObjectTop, kWidth, std::max(0, kHeight - kObjectTop), TRUE);
            ::MoveWindow(detailEdit_, 0, kHeight, kWidth, 0, TRUE);
            return;
        }
        ::ShowWindow(titleText_, SW_HIDE);
        ::ShowWindow(summaryText_, SW_HIDE);
        ::ShowWindow(backendText_, SW_HIDE);
        ::ShowWindow(filterLabel_, SW_SHOW);
        ::ShowWindow(filterEdit_, SW_SHOW);
        ::ShowWindow(locateButton_, SW_SHOW);
        ::ShowWindow(refreshButton_, SW_SHOW);
        ::ShowWindow(statusText_, SW_SHOW);
        const bool kShowObjectAuxEdit = descriptor->id == KernelFeatureId::kObjectDirectoryRecursive ||
            descriptor->id == KernelFeatureId::kBaseNamedObjects ||
            descriptor->id == KernelFeatureId::kSymbolicLink ||
            descriptor->id == KernelFeatureId::kDeviceDriverObjects;
        ::ShowWindow(moduleFilterLabel_, kShowObjectAuxEdit ? SW_SHOW : SW_HIDE);
        ::ShowWindow(moduleFilterEdit_, kShowObjectAuxEdit ? SW_SHOW : SW_HIDE);
        ::ShowWindow(includeCombo_, SW_HIDE);
        const bool kShowObjectExtraButton = descriptor->id == KernelFeatureId::kNamedPipe ||
            descriptor->id == KernelFeatureId::kDeviceDriverObjects ||
            descriptor->id == KernelFeatureId::kSymbolicLink ||
            descriptor->id == KernelFeatureId::kBaseNamedObjects;
        ::ShowWindow(copyDiagnosticButton_, kShowObjectExtraButton ? SW_SHOW : SW_HIDE);
        ::ShowWindow(summaryList_, SW_HIDE);
        // The original KswordARK object namespace and recursive-directory tabs
        // are tree widget pages, meaning a tree with visible report columns. A
        // plain Win32 TreeView loses those columns, so the Win32-light page keeps
        // the report ListView visible as the tree-table surface and uses hidden
        // row fields for actions/details.
        ::ShowWindow(resultList_, SW_SHOW);
        ::ShowWindow(objectNamespaceTree_, SW_HIDE);
        ::ShowWindow(detailEdit_, SW_SHOW);

        const int kToolbarTop = kContentTop;
        int toolbarX = 0;
        ::MoveWindow(refreshButton_, toolbarX, kToolbarTop + 2, 74, kButtonHeight, TRUE);
        toolbarX += 76;
        const int kFilterLabelObjectWidth = descriptor->id == KernelFeatureId::kObjectDirectoryRecursive ? 52 : 40;
        ::MoveWindow(filterLabel_, toolbarX, kToolbarTop + 5, kFilterLabelObjectWidth, 20, TRUE);
        toolbarX += kFilterLabelObjectWidth;
        const int kActionWidthObject = kShowObjectExtraButton ? 76 : 0;
        const int kLocateWidthObject = descriptor->id == KernelFeatureId::kNamedPipe ? 58 : 52;
        const int kAuxLabelWidth = kShowObjectAuxEdit ? 64 : 0;
        const int kAuxEditWidth = kShowObjectAuxEdit ? std::max(72, std::min(170, kWidth / 5)) : 0;
        const int kFilterWidth = std::max(160, std::min(kWidth / 3, std::max(0, kWidth - toolbarX - kLocateWidthObject - kActionWidthObject - kAuxLabelWidth - kAuxEditWidth - 220)));
        ::MoveWindow(filterEdit_, toolbarX, kToolbarTop + 3, kFilterWidth, 22, TRUE);
        toolbarX += kFilterWidth + 2;
        if (kShowObjectAuxEdit) {
            ::MoveWindow(moduleFilterLabel_, toolbarX, kToolbarTop + 5, kAuxLabelWidth, 20, TRUE);
            toolbarX += kAuxLabelWidth;
            ::MoveWindow(moduleFilterEdit_, toolbarX, kToolbarTop + 3, kAuxEditWidth, 22, TRUE);
            toolbarX += kAuxEditWidth + 2;
        }
        ::MoveWindow(locateButton_, toolbarX, kToolbarTop + 2, kLocateWidthObject, kButtonHeight, TRUE);
        toolbarX += kLocateWidthObject + 4;
        if (kShowObjectExtraButton) {
            ::MoveWindow(copyDiagnosticButton_, toolbarX, kToolbarTop + 2, kActionWidthObject, kButtonHeight, TRUE);
            toolbarX += kActionWidthObject + 4;
        }
        ::MoveWindow(statusText_, toolbarX, kToolbarTop + 4, std::max(0, kWidth - toolbarX), 22, TRUE);

        const int kObjectTop = kContentTop + kInfoHeight;
        const int kObjectDetailHeight = std::min(160, std::max(96, kHeight / 5));
        const int kObjectResultHeight = std::max(0, kHeight - kObjectTop - kObjectDetailHeight);
        if (descriptor->id == KernelFeatureId::kObjectNamespaceOverview) {
            const int kPropertyWidth = std::max(260, kWidth / 3);
            ::ShowWindow(propertyList_, SW_SHOW);
            ::MoveWindow(resultList_, 0, kObjectTop, std::max(0, kWidth - kPropertyWidth), kObjectResultHeight, TRUE);
            ::MoveWindow(objectNamespaceTree_, 0, kObjectTop, 0, 0, TRUE);
            ::MoveWindow(propertyList_, std::max(0, kWidth - kPropertyWidth), kObjectTop, kPropertyWidth, kObjectResultHeight, TRUE);
        } else if (descriptor->id == KernelFeatureId::kObjectDirectoryRecursive) {
            ::ShowWindow(propertyList_, SW_HIDE);
            ::MoveWindow(resultList_, 0, kObjectTop, kWidth, kObjectResultHeight, TRUE);
            ::MoveWindow(objectNamespaceTree_, 0, kObjectTop, 0, 0, TRUE);
            ::MoveWindow(propertyList_, kWidth, kObjectTop, 0, kObjectResultHeight, TRUE);
        } else {
            ::ShowWindow(propertyList_, SW_HIDE);
            ::MoveWindow(resultList_, 0, kObjectTop, kWidth, kObjectResultHeight, TRUE);
            ::MoveWindow(propertyList_, kWidth, kObjectTop, 0, kObjectResultHeight, TRUE);
        }
        ::MoveWindow(detailEdit_, 0, std::max(0, kHeight - kObjectDetailHeight), kWidth, kObjectDetailHeight, TRUE);
        return;
    }

    if (kShowKernelHookPanel) {
        ::ShowWindow(titleText_, SW_HIDE);
        ::ShowWindow(summaryText_, SW_HIDE);
        ::ShowWindow(backendText_, SW_HIDE);
        ::ShowWindow(filterLabel_, SW_HIDE);
        ::ShowWindow(filterEdit_, SW_SHOW);
        ::ShowWindow(moduleFilterLabel_, SW_HIDE);
        ::ShowWindow(moduleFilterEdit_, descriptor->id == KernelFeatureId::kInlineHook || descriptor->id == KernelFeatureId::kIatEatHook ? SW_SHOW : SW_HIDE);
        ::ShowWindow(includeCombo_, kShowIncludeCombo ? SW_SHOW : SW_HIDE);
        ::ShowWindow(locateButton_, SW_HIDE);
        ::ShowWindow(copyDiagnosticButton_, descriptor->id == KernelFeatureId::kInlineHook ? SW_SHOW : SW_HIDE);
        ::ShowWindow(refreshButton_, SW_SHOW);
        ::ShowWindow(statusText_, SW_SHOW);
        ::ShowWindow(summaryList_, SW_HIDE);
        ::ShowWindow(propertyList_, SW_HIDE);
        ::ShowWindow(resultList_, SW_SHOW);
        ::ShowWindow(detailEdit_, SW_SHOW);

        const int kToolbarTop = kContentTop;
        int toolbarX = 0;
        const int kRefreshWidth = 34;
        ::MoveWindow(refreshButton_, toolbarX, kToolbarTop + 2, kRefreshWidth, kButtonHeight, TRUE);
        toolbarX += kRefreshWidth + 4;
        if (descriptor->id == KernelFeatureId::kInlineHook) {
            ::MoveWindow(copyDiagnosticButton_, toolbarX, kToolbarTop + 2, 96, kButtonHeight, TRUE);
            toolbarX += 100;
        }
        if (descriptor->id == KernelFeatureId::kInlineHook || descriptor->id == KernelFeatureId::kIatEatHook) {
            const int kReservedRight = (kShowIncludeCombo ? 174 : 0) + std::max(220, kWidth / 4);
            const int kEditArea = std::max(260, kWidth - toolbarX - kReservedRight - 8);
            const int kModuleEditWidth = std::max(160, kEditArea / 2);
            ::MoveWindow(moduleFilterEdit_, toolbarX, kToolbarTop + 3, kModuleEditWidth, 22, TRUE);
            toolbarX += kModuleEditWidth + 4;
            const int kFilterWidth = std::max(180, kEditArea - kModuleEditWidth);
            ::MoveWindow(filterEdit_, toolbarX, kToolbarTop + 3, kFilterWidth, 22, TRUE);
            toolbarX += kFilterWidth + 4;
        } else {
            const int kStatusWidth = std::min(420, std::max(160, kWidth / 3));
            const int kFilterWidth = std::max(180, std::max(0, kWidth - toolbarX - kStatusWidth - 8));
            ::MoveWindow(filterEdit_, toolbarX, kToolbarTop + 3, kFilterWidth, 22, TRUE);
            toolbarX += kFilterWidth + 4;
        }
        if (kShowIncludeCombo) {
            ::MoveWindow(includeCombo_, toolbarX, kToolbarTop + 2, 170, 240, TRUE);
            toolbarX += 174;
        }
        ::MoveWindow(statusText_, toolbarX, kToolbarTop + 4, std::max(0, kWidth - toolbarX), 22, TRUE);
        const int kHookTop = kContentTop + kInfoHeight;
        kMoveResultDetailSplitter(kHookTop, 88, 88);
        return;
    }

    if (kShowDiagnosticDualPanel) {
        ::ShowWindow(titleText_, SW_HIDE);
        ::ShowWindow(summaryText_, SW_HIDE);
        ::ShowWindow(backendText_, SW_HIDE);
        ::ShowWindow(filterLabel_, SW_HIDE);
        ::ShowWindow(filterEdit_, SW_SHOW);
        ::ShowWindow(moduleFilterLabel_, SW_HIDE);
        ::ShowWindow(moduleFilterEdit_, SW_HIDE);
        ::ShowWindow(includeCombo_, SW_HIDE);
        ::ShowWindow(locateButton_, SW_HIDE);
        ::ShowWindow(copyDiagnosticButton_, SW_SHOW);
        ::ShowWindow(refreshButton_, SW_SHOW);
        ::ShowWindow(propertyList_, SW_HIDE);
        ::ShowWindow(summaryList_, SW_SHOW);
        ::ShowWindow(resultList_, SW_SHOW);
        ::ShowWindow(detailEdit_, SW_SHOW);

        const int kToolbarTop = kContentTop;
        int toolbarX = 0;
        ::MoveWindow(refreshButton_, toolbarX, kToolbarTop + 2, 34, kButtonHeight, TRUE);
        toolbarX += 40;
        ::MoveWindow(copyDiagnosticButton_, toolbarX, kToolbarTop + 2, 82, kButtonHeight, TRUE);
        toolbarX += 88;
        ::MoveWindow(filterLabel_, toolbarX, kToolbarTop + 5, 0, 20, TRUE);
        const int kStatusWidth = std::min(420, std::max(160, kWidth / 3));
        const int kDiagnosticFilterWidth = std::max(180, std::max(0, kWidth - toolbarX - kStatusWidth - 8));
        ::MoveWindow(filterEdit_, toolbarX, kToolbarTop + 3, kDiagnosticFilterWidth, 22, TRUE);
        toolbarX += kDiagnosticFilterWidth + 8;
        ::MoveWindow(statusText_, toolbarX, kToolbarTop + 4, std::max(0, kWidth - toolbarX), 22, TRUE);

        const int kPanelTop = kContentTop + kInfoHeight;
        const int kAvailableHeight = std::max(0, kHeight - kPanelTop);
        const int kSummaryHeight = std::min(kAvailableHeight, std::max(96, (kAvailableHeight * 2) / 7));
        const int kLowerTop = kPanelTop + kSummaryHeight;
        const int kLowerHeight = std::max(0, kHeight - kLowerTop);
        const int kListWidth = std::min(kWidth, std::max(320, (kWidth * 3) / 5));
        ::MoveWindow(summaryList_, 0, kPanelTop, kWidth, kSummaryHeight, TRUE);
        ::MoveWindow(resultList_, 0, kLowerTop, kListWidth, kLowerHeight, TRUE);
        ::MoveWindow(propertyList_, kWidth, kPanelTop, 0, 0, TRUE);
        ::MoveWindow(detailEdit_, kListWidth, kLowerTop, std::max(0, kWidth - kListWidth), kLowerHeight, TRUE);
        return;
    }

    if (kShowCallbackEnumerationPanel) {
        ::ShowWindow(titleText_, SW_HIDE);
        ::ShowWindow(summaryText_, SW_HIDE);
        ::ShowWindow(backendText_, SW_HIDE);
        ::ShowWindow(filterLabel_, SW_HIDE);
        ::ShowWindow(moduleFilterLabel_, SW_HIDE);
        ::ShowWindow(moduleFilterEdit_, SW_HIDE);
        ::ShowWindow(includeCombo_, SW_HIDE);
        ::ShowWindow(locateButton_, SW_HIDE);
        ::ShowWindow(copyDiagnosticButton_, SW_HIDE);
        ::ShowWindow(refreshButton_, SW_SHOW);
        ::ShowWindow(filterEdit_, SW_SHOW);
        ::ShowWindow(statusText_, SW_SHOW);
        ::ShowWindow(propertyList_, SW_HIDE);
        ::ShowWindow(summaryList_, SW_HIDE);
        ::ShowWindow(resultList_, SW_SHOW);
        ::ShowWindow(detailEdit_, SW_SHOW);

        const int kToolbarTop = kContentTop;
        int toolbarX = 0;
        ::MoveWindow(refreshButton_, toolbarX, kToolbarTop + 2, 34, kButtonHeight, TRUE);
        toolbarX += 38;
        const int kCallbackFilterWidth = std::max(220, std::min(kWidth / 2, std::max(0, kWidth - toolbarX - 320)));
        ::MoveWindow(filterEdit_, toolbarX, kToolbarTop + 3, kCallbackFilterWidth, 22, TRUE);
        toolbarX += kCallbackFilterWidth + 6;
        ::MoveWindow(statusText_, toolbarX, kToolbarTop + 4, std::max(0, kWidth - toolbarX), 22, TRUE);

        const int kPanelTop = kContentTop + kInfoHeight;
        kMoveResultDetailSplitter(kPanelTop, 120, 96);
        return;
    }

    if (kShowKernelMemoryScanPanel) {
        const bool kEvidencePage = descriptor->id == KernelFeatureId::kKernelMemoryEvidence;
        ::ShowWindow(titleText_, SW_HIDE);
        ::ShowWindow(summaryText_, SW_HIDE);
        ::ShowWindow(backendText_, SW_HIDE);
        ::ShowWindow(filterLabel_, kEvidencePage ? SW_HIDE : SW_HIDE);
        ::ShowWindow(filterEdit_, kEvidencePage ? SW_SHOW : SW_HIDE);
        ::ShowWindow(moduleFilterLabel_, SW_HIDE);
        ::ShowWindow(moduleFilterEdit_, kEvidencePage ? SW_HIDE : SW_SHOW);
        ::ShowWindow(includeCombo_, SW_HIDE);
        ::ShowWindow(locateButton_, SW_HIDE);
        ::ShowWindow(copyDiagnosticButton_, SW_HIDE);
        ::ShowWindow(refreshButton_, SW_SHOW);
        ::ShowWindow(riskOnlyCheck_, SW_SHOW);
        ::ShowWindow(evidenceIncludeNonModuleCheck_, kEvidencePage ? SW_SHOW : SW_HIDE);
        ::ShowWindow(evidenceStartEdit_, kEvidencePage ? SW_SHOW : SW_HIDE);
        ::ShowWindow(evidenceEndEdit_, kEvidencePage ? SW_SHOW : SW_HIDE);
        ::ShowWindow(evidenceMaxRowsLabel_, kEvidencePage ? SW_SHOW : SW_HIDE);
        ::ShowWindow(evidenceMaxRowsEdit_, kEvidencePage ? SW_SHOW : SW_HIDE);
        ::ShowWindow(evidenceMaxRowsSpin_, kEvidencePage ? SW_SHOW : SW_HIDE);
        ::ShowWindow(propertyList_, SW_HIDE);
        ::ShowWindow(summaryList_, SW_HIDE);
        ::ShowWindow(resultList_, SW_SHOW);
        ::ShowWindow(detailEdit_, SW_SHOW);

        const int kToolbarTop = kContentTop;
        int toolbarX = 0;
        const int kRefreshWidth = kEvidencePage ? 70 : 48;
        ::MoveWindow(refreshButton_, toolbarX, kToolbarTop + 2, kRefreshWidth, kButtonHeight, TRUE);
        toolbarX += kRefreshWidth + 4;
        ::MoveWindow(riskOnlyCheck_, toolbarX, kToolbarTop + 3, 74, 22, TRUE);
        toolbarX += 78;
        if (kEvidencePage) {
            ::MoveWindow(evidenceIncludeNonModuleCheck_, toolbarX, kToolbarTop + 3, 138, 22, TRUE);
            toolbarX += 142;
            ::MoveWindow(evidenceStartEdit_, toolbarX, kToolbarTop + 3, 130, 22, TRUE);
            toolbarX += 134;
            ::MoveWindow(evidenceEndEdit_, toolbarX, kToolbarTop + 3, 130, 22, TRUE);
            toolbarX += 134;
            ::MoveWindow(evidenceMaxRowsLabel_, toolbarX, kToolbarTop + 5, 36, 20, TRUE);
            toolbarX += 36;
            ::MoveWindow(evidenceMaxRowsEdit_, toolbarX, kToolbarTop + 3, 70, 22, TRUE);
            ::MoveWindow(evidenceMaxRowsSpin_, toolbarX + 50, kToolbarTop + 3, 20, 22, TRUE);
            toolbarX += 74;
            const int kFilterWidth = std::max(160, std::min(300, std::max(0, kWidth - toolbarX - 260)));
            ::MoveWindow(filterEdit_, toolbarX, kToolbarTop + 3, kFilterWidth, 22, TRUE);
            toolbarX += kFilterWidth + 6;
        } else {
            const int kModuleWidth = std::max(220, std::min(520, std::max(0, kWidth - toolbarX - 300)));
            ::MoveWindow(moduleFilterEdit_, toolbarX, kToolbarTop + 3, kModuleWidth, 22, TRUE);
            toolbarX += kModuleWidth + 6;
        }
        ::MoveWindow(statusText_, toolbarX, kToolbarTop + 4, std::max(0, kWidth - toolbarX), 22, TRUE);

        const int kPanelTop = kContentTop + kInfoHeight;
        kMoveResultDetailSplitter(kPanelTop, 120, 96);
        return;
    }

    if (kShowCrossViewPanel) {
        ::ShowWindow(titleText_, SW_HIDE);
        ::ShowWindow(summaryText_, SW_HIDE);
        ::ShowWindow(backendText_, SW_HIDE);
        ::ShowWindow(filterLabel_, SW_HIDE);
        ::ShowWindow(filterEdit_, SW_SHOW);
        ::ShowWindow(moduleFilterLabel_, SW_HIDE);
        ::ShowWindow(moduleFilterEdit_, SW_HIDE);
        ::ShowWindow(includeCombo_, SW_HIDE);
        ::ShowWindow(locateButton_, SW_HIDE);
        ::ShowWindow(copyDiagnosticButton_, SW_HIDE);
        ::ShowWindow(refreshButton_, SW_SHOW);
        ::ShowWindow(riskOnlyCheck_, SW_SHOW);
        ::ShowWindow(propertyList_, SW_HIDE);
        ::ShowWindow(summaryList_, SW_HIDE);
        ::ShowWindow(resultList_, SW_SHOW);
        ::ShowWindow(detailEdit_, SW_SHOW);

        const int kToolbarTop = kContentTop;
        int toolbarX = 0;
        ::MoveWindow(refreshButton_, toolbarX, kToolbarTop + 2, 74, kButtonHeight, TRUE);
        toolbarX += 78;
        ::MoveWindow(riskOnlyCheck_, toolbarX, kToolbarTop + 3, 74, 22, TRUE);
        toolbarX += 78;
        const int kFilterWidth = std::max(220, std::min(kWidth / 2, std::max(0, kWidth - toolbarX - 300)));
        ::MoveWindow(filterEdit_, toolbarX, kToolbarTop + 3, kFilterWidth, 22, TRUE);
        toolbarX += kFilterWidth + 6;
        ::MoveWindow(statusText_, toolbarX, kToolbarTop + 4, std::max(0, kWidth - toolbarX), 22, TRUE);

        const int kPanelTop = kContentTop + kInfoHeight;
        kMoveResultDetailSplitter(kPanelTop, 120, 96);
        return;
    }

    if (kShowR0EvidencePanel) {
        ::ShowWindow(titleText_, SW_HIDE);
        ::ShowWindow(summaryText_, SW_HIDE);
        ::ShowWindow(backendText_, SW_HIDE);
        ::ShowWindow(filterLabel_, SW_HIDE);
        ::ShowWindow(filterEdit_, SW_SHOW);
        ::ShowWindow(moduleFilterLabel_, SW_HIDE);
        ::ShowWindow(moduleFilterEdit_, SW_HIDE);
        ::ShowWindow(includeCombo_, SW_HIDE);
        ::ShowWindow(locateButton_, SW_HIDE);
        ::ShowWindow(copyDiagnosticButton_, SW_HIDE);
        ::ShowWindow(refreshButton_, SW_SHOW);
        const bool kShowR0RiskOnly = descriptor->id == KernelFeatureId::kMutationAudit;
        ::ShowWindow(riskOnlyCheck_, kShowR0RiskOnly ? SW_SHOW : SW_HIDE);
        ::ShowWindow(propertyList_, SW_HIDE);
        ::ShowWindow(summaryList_, SW_HIDE);
        ::ShowWindow(resultList_, SW_SHOW);
        ::ShowWindow(detailEdit_, SW_SHOW);

        const int kToolbarTop = kContentTop;
        int toolbarX = 0;
        ::MoveWindow(refreshButton_, toolbarX, kToolbarTop + 2, 74, kButtonHeight, TRUE);
        toolbarX += 78;
        if (kShowR0RiskOnly) {
            ::MoveWindow(riskOnlyCheck_, toolbarX, kToolbarTop + 3, 74, 22, TRUE);
            toolbarX += 78;
        }
        const int kFilterWidth = std::max(220, std::min(kWidth / 2, std::max(0, kWidth - toolbarX - 320)));
        ::MoveWindow(filterEdit_, toolbarX, kToolbarTop + 3, kFilterWidth, 22, TRUE);
        toolbarX += kFilterWidth + 6;
        ::MoveWindow(statusText_, toolbarX, kToolbarTop + 4, std::max(0, kWidth - toolbarX), 22, TRUE);

        const int kPanelTop = kContentTop + kInfoHeight;
        kMoveResultDetailSplitter(kPanelTop, 120, 96);
        return;
    }

    if (kShowIntegrityPanel) {
        const bool kDriverIntegrityPage = descriptor->id == KernelFeatureId::kDriverIntegrity;
        const bool kCpuIntegrityPage = descriptor->id == KernelFeatureId::kKernelCpuIntegrity;
        ::ShowWindow(titleText_, SW_HIDE);
        ::ShowWindow(summaryText_, SW_HIDE);
        ::ShowWindow(backendText_, SW_HIDE);
        ::ShowWindow(filterLabel_, SW_HIDE);
        ::ShowWindow(filterEdit_, SW_SHOW);
        ::ShowWindow(moduleFilterLabel_, kDriverIntegrityPage ? SW_SHOW : SW_HIDE);
        ::ShowWindow(moduleFilterEdit_, kDriverIntegrityPage ? SW_SHOW : SW_HIDE);
        ::ShowWindow(integrityModuleBaseLabel_, kDriverIntegrityPage ? SW_SHOW : SW_HIDE);
        ::ShowWindow(integrityModuleBaseEdit_, kDriverIntegrityPage ? SW_SHOW : SW_HIDE);
        ::ShowWindow(integrityFillFromSelectionButton_, kDriverIntegrityPage ? SW_SHOW : SW_HIDE);
        ::ShowWindow(integrityCpuOnlyButton_, kDriverIntegrityPage ? SW_SHOW : SW_HIDE);
        ::ShowWindow(integrityIdtVectorsLabel_, kCpuIntegrityPage ? SW_SHOW : SW_HIDE);
        ::ShowWindow(integrityIdtVectorsEdit_, kCpuIntegrityPage ? SW_SHOW : SW_HIDE);
        ::ShowWindow(integrityIdtVectorsSpin_, kCpuIntegrityPage ? SW_SHOW : SW_HIDE);
        ::ShowWindow(includeCombo_, SW_HIDE);
        ::ShowWindow(locateButton_, SW_HIDE);
        ::ShowWindow(copyDiagnosticButton_, SW_HIDE);
        ::ShowWindow(refreshButton_, SW_SHOW);
        ::ShowWindow(riskOnlyCheck_, SW_SHOW);
        ::ShowWindow(evidenceMaxRowsLabel_, SW_SHOW);
        ::ShowWindow(evidenceMaxRowsEdit_, SW_SHOW);
        ::ShowWindow(evidenceMaxRowsSpin_, SW_SHOW);
        ::ShowWindow(propertyList_, SW_HIDE);
        ::ShowWindow(summaryList_, SW_HIDE);
        ::ShowWindow(resultList_, SW_SHOW);
        ::ShowWindow(detailEdit_, SW_SHOW);

        const int kToolbarTop = kContentTop;
        int toolbarX = 0;
        if (kDriverIntegrityPage) {
            ::MoveWindow(moduleFilterLabel_, toolbarX, kToolbarTop + 5, 78, 20, TRUE);
            toolbarX += 78;
            const int kDriverNameWidth = std::max(120, std::min(260, kWidth / 5));
            ::MoveWindow(moduleFilterEdit_, toolbarX, kToolbarTop + 3, kDriverNameWidth, 22, TRUE);
            toolbarX += kDriverNameWidth + 4;
            ::MoveWindow(integrityModuleBaseLabel_, toolbarX, kToolbarTop + 5, 58, 20, TRUE);
            toolbarX += 58;
            ::MoveWindow(integrityModuleBaseEdit_, toolbarX, kToolbarTop + 3, 132, 22, TRUE);
            toolbarX += 136;
            ::MoveWindow(integrityFillFromSelectionButton_, toolbarX, kToolbarTop + 2, 44, kButtonHeight, TRUE);
            toolbarX += 48;
        }
        ::MoveWindow(refreshButton_, toolbarX, kToolbarTop + 2, kDriverIntegrityPage ? 48 : 88, kButtonHeight, TRUE);
        toolbarX += kDriverIntegrityPage ? 52 : 92;
        if (kDriverIntegrityPage) {
            ::MoveWindow(integrityCpuOnlyButton_, toolbarX, kToolbarTop + 2, 42, kButtonHeight, TRUE);
            toolbarX += 46;
        }
        ::MoveWindow(riskOnlyCheck_, toolbarX, kToolbarTop + 3, 74, 22, TRUE);
        toolbarX += 78;
        ::MoveWindow(evidenceMaxRowsLabel_, toolbarX, kToolbarTop + 5, 36, 20, TRUE);
        toolbarX += 36;
        ::MoveWindow(evidenceMaxRowsEdit_, toolbarX, kToolbarTop + 3, 70, 22, TRUE);
        ::MoveWindow(evidenceMaxRowsSpin_, toolbarX + 50, kToolbarTop + 3, 20, 22, TRUE);
        toolbarX += 74;
        if (kCpuIntegrityPage) {
            ::MoveWindow(integrityIdtVectorsLabel_, toolbarX, kToolbarTop + 5, 58, 20, TRUE);
            toolbarX += 58;
            ::MoveWindow(integrityIdtVectorsEdit_, toolbarX, kToolbarTop + 3, 70, 22, TRUE);
            ::MoveWindow(integrityIdtVectorsSpin_, toolbarX + 50, kToolbarTop + 3, 20, 22, TRUE);
            toolbarX += 74;
        }
        const int kRemainingAfterTools = std::max(0, kWidth - toolbarX);
        const int kTargetStatusWidth = kDriverIntegrityPage ? 360 : 320;
        const int kFilterWidth = std::max(140,
            std::min(kDriverIntegrityPage ? 260 : std::max(180, kWidth / 3),
                std::max(0, kRemainingAfterTools - kTargetStatusWidth)));
        ::MoveWindow(filterEdit_, toolbarX, kToolbarTop + 3, kFilterWidth, 22, TRUE);
        toolbarX += kFilterWidth + 6;
        ::MoveWindow(statusText_, toolbarX, kToolbarTop + 4, std::max(0, kWidth - toolbarX), 22, TRUE);

        const int kPanelTop = kContentTop + kInfoHeight;
        kMoveResultDetailSplitter(kPanelTop, 120, 96);
        return;
    }

    ::ShowWindow(titleText_, SW_SHOW);
    ::ShowWindow(summaryText_, SW_SHOW);
    ::ShowWindow(backendText_, SW_SHOW);
    ::ShowWindow(filterLabel_, SW_SHOW);
    ::ShowWindow(filterEdit_, SW_SHOW);
    ::ShowWindow(moduleFilterLabel_, SW_SHOW);
    ::ShowWindow(moduleFilterEdit_, SW_SHOW);
    ::ShowWindow(locateButton_, SW_SHOW);
    ::ShowWindow(refreshButton_, SW_SHOW);

    if (kShowCallbackPanel) {
        ::ShowWindow(titleText_, SW_HIDE);
        ::ShowWindow(summaryText_, SW_HIDE);
        ::ShowWindow(backendText_, SW_HIDE);
        ::ShowWindow(filterLabel_, SW_HIDE);
        ::ShowWindow(filterEdit_, SW_HIDE);
        ::ShowWindow(moduleFilterLabel_, SW_HIDE);
        ::ShowWindow(moduleFilterEdit_, SW_HIDE);
        ::ShowWindow(includeCombo_, SW_HIDE);
        ::ShowWindow(locateButton_, SW_HIDE);
        ::ShowWindow(copyDiagnosticButton_, SW_HIDE);
        ::ShowWindow(refreshButton_, SW_HIDE);
        ::ShowWindow(statusText_, SW_HIDE);
        ::ShowWindow(summaryList_, SW_HIDE);
        ::ShowWindow(propertyList_, SW_HIDE);
        ::ShowWindow(resultList_, SW_HIDE);
        ::ShowWindow(detailEdit_, SW_HIDE);
        ::MoveWindow(summaryList_, 0, kResultTop, 0, 0, TRUE);
        ::MoveWindow(propertyList_, kWidth, kResultTop, 0, 0, TRUE);
        ::MoveWindow(resultList_, 0, kResultTop, 0, 0, TRUE);
        ::MoveWindow(detailEdit_, 0, kHeight, 0, 0, TRUE);

        const int kPanelTop = kContentTop;
        const int kCompactGap = 4;
        const int kToolbarHeight = kButtonHeight;
        int toolbarX = 0;
        ::MoveWindow(callbackGlobalEnabledCheck_, toolbarX, kPanelTop + 3, 76, 20, TRUE); toolbarX += 80;
        ::MoveWindow(callbackApplyButton_, toolbarX, kPanelTop, 52, kToolbarHeight, TRUE); toolbarX += 56;
        ::MoveWindow(callbackReloadButton_, toolbarX, kPanelTop, 126, kToolbarHeight, TRUE); toolbarX += 130;
        ::MoveWindow(callbackImportButton_, toolbarX, kPanelTop, 72, kToolbarHeight, TRUE); toolbarX += 76;
        ::MoveWindow(callbackExportButton_, toolbarX, kPanelTop, 72, kToolbarHeight, TRUE); toolbarX += 76;
        ::MoveWindow(callbackStartReceiverButton_, toolbarX, kPanelTop, 82, kToolbarHeight, TRUE); toolbarX += 86;
        ::MoveWindow(callbackStopReceiverButton_, toolbarX, kPanelTop, 68, kToolbarHeight, TRUE); toolbarX += 72;
        ::MoveWindow(callbackAllowEventButton_, toolbarX, kPanelTop, 68, kToolbarHeight, TRUE); toolbarX += 72;
        ::MoveWindow(callbackDenyEventButton_, toolbarX, kPanelTop, 68, kToolbarHeight, TRUE); toolbarX += 72;
        ::MoveWindow(callbackStatusText_, toolbarX, kPanelTop + 3, std::max(0, kWidth - toolbarX), 20, TRUE);

        const int kStatusTop = kPanelTop + kToolbarHeight + kCompactGap;
        ::MoveWindow(callbackStatusText_, 0, kStatusTop, kWidth, 20, TRUE);
        const int kMainTop = kStatusTop + 22;
        const int kFileMonitorMinHeight = std::min(210, std::max(120, kHeight / 4));
        const int kLogHeight = std::min(150, std::max(74, kHeight / 7));
        const int kFileBlockHeight = std::min(std::max(0, kHeight - kMainTop - kLogHeight - kCompactGap), kFileMonitorMinHeight);
        const int kMainHeight = std::max(120, kHeight - kMainTop - kLogHeight - kFileBlockHeight - kCompactGap * 2);
        const int kLeftWidth = std::max(250, (kWidth * 3) / 10);
        const int kRightX = kLeftWidth + kCompactGap;
        const int kRightWidth = std::max(0, kWidth - kRightX);

        int gx = 0;
        ::MoveWindow(callbackAddGroupButton_, gx, kMainTop, 30, kButtonHeight, TRUE); gx += 34;
        ::MoveWindow(callbackRemoveGroupButton_, gx, kMainTop, 30, kButtonHeight, TRUE); gx += 34;
        ::MoveWindow(callbackRenameGroupButton_, gx, kMainTop, 30, kButtonHeight, TRUE); gx += 34;
        ::MoveWindow(callbackMoveGroupUpButton_, gx, kMainTop, 30, kButtonHeight, TRUE); gx += 34;
        ::MoveWindow(callbackMoveGroupDownButton_, gx, kMainTop, 30, kButtonHeight, TRUE);
        ::MoveWindow(callbackGroupLabel_, gx + 36, kMainTop + 4, std::max(0, kLeftWidth - gx - 36), 18, TRUE);
        ::MoveWindow(callbackGroupList_, 0, kMainTop + kButtonHeight + kCompactGap, kLeftWidth, std::max(0, kMainHeight - kButtonHeight - kCompactGap), TRUE);

        int rb = kRightX;
        ::MoveWindow(callbackAddRuleButton_, rb, kMainTop, 30, kButtonHeight, TRUE); rb += 34;
        ::MoveWindow(callbackRemoveRuleButton_, rb, kMainTop, 30, kButtonHeight, TRUE); rb += 34;
        ::MoveWindow(callbackMoveRuleUpButton_, rb, kMainTop, 30, kButtonHeight, TRUE); rb += 34;
        ::MoveWindow(callbackMoveRuleDownButton_, rb, kMainTop, 30, kButtonHeight, TRUE); rb += 34;
        ::MoveWindow(callbackRuleLabel_, rb + 2, kMainTop + 4, std::max(0, kRightX + kRightWidth - rb - 2), 18, TRUE);
        const int kRuleTabTop = kMainTop + kButtonHeight + kCompactGap;
        ::MoveWindow(callbackRuleTab_, kRightX, kRuleTabTop, kRightWidth, std::max(0, kMainHeight - kButtonHeight - kCompactGap), TRUE);
        RECT tabClient{ kRightX, kRuleTabTop, kRightX + kRightWidth, kRuleTabTop + std::max(0, kMainHeight - kButtonHeight - kCompactGap) };
        ::SendMessageW(callbackRuleTab_, TCM_ADJUSTRECT, FALSE, reinterpret_cast<LPARAM>(&tabClient));
        const int kSelectedRuleTab = static_cast<int>(::SendMessageW(callbackRuleTab_, TCM_GETCURSEL, 0, 0));
        for (int index = 0; index < static_cast<int>(callbackRuleLists_.size()); ++index) {
            const bool kShowRuleList = index == kSelectedRuleTab && index < 6;
            ::ShowWindow(callbackRuleLists_[static_cast<std::size_t>(index)], kShowRuleList ? SW_SHOW : SW_HIDE);
            ::MoveWindow(callbackRuleLists_[static_cast<std::size_t>(index)],
                tabClient.left,
                tabClient.top,
                width(tabClient),
                height(tabClient),
                TRUE);
        }

        const bool kShowBypass = kSelectedRuleTab == 6;
        ::ShowWindow(callbackBypassLabel_, kShowBypass ? SW_SHOW : SW_HIDE);
        ::ShowWindow(callbackBypassPidEdit_, kShowBypass ? SW_SHOW : SW_HIDE);
        ::ShowWindow(callbackBypassAddButton_, kShowBypass ? SW_SHOW : SW_HIDE);
        ::ShowWindow(callbackBypassRemoveButton_, kShowBypass ? SW_SHOW : SW_HIDE);
        ::ShowWindow(callbackBypassApplyButton_, kShowBypass ? SW_SHOW : SW_HIDE);
        ::ShowWindow(callbackBypassClearButton_, kShowBypass ? SW_SHOW : SW_HIDE);
        ::ShowWindow(callbackBypassRefreshButton_, kShowBypass ? SW_SHOW : SW_HIDE);
        ::ShowWindow(callbackBypassList_, kShowBypass ? SW_SHOW : SW_HIDE);
        ::ShowWindow(callbackBypassStatusText_, kShowBypass ? SW_SHOW : SW_HIDE);
        ::MoveWindow(callbackBypassLabel_, tabClient.left, tabClient.top + 2, width(tabClient), 18, TRUE);
        int bx = tabClient.left;
        const int kBypassInputWidth = std::max(120, width(tabClient) - 374);
        ::MoveWindow(callbackBypassPidEdit_, bx, tabClient.top + 24, kBypassInputWidth, 22, TRUE); bx += kBypassInputWidth + 4;
        ::MoveWindow(callbackBypassAddButton_, bx, tabClient.top + 23, 48, kButtonHeight, TRUE); bx += 52;
        ::MoveWindow(callbackBypassRemoveButton_, bx, tabClient.top + 23, 76, kButtonHeight, TRUE); bx += 80;
        ::MoveWindow(callbackBypassApplyButton_, bx, tabClient.top + 23, 78, kButtonHeight, TRUE); bx += 82;
        ::MoveWindow(callbackBypassClearButton_, bx, tabClient.top + 23, 78, kButtonHeight, TRUE); bx += 82;
        ::MoveWindow(callbackBypassRefreshButton_, bx, tabClient.top + 23, 78, kButtonHeight, TRUE);
        const int kBypassListTop = tabClient.top + 50;
        ::MoveWindow(callbackBypassList_, tabClient.left, kBypassListTop, width(tabClient), std::max(0, height(tabClient) - 72), TRUE);
        ::MoveWindow(callbackBypassStatusText_, tabClient.left, tabClient.top + height(tabClient) - 20, width(tabClient), 18, TRUE);

        const int kLogTop = kMainTop + kMainHeight + kCompactGap;
        ::MoveWindow(callbackLogTab_, 0, kLogTop, kWidth, kLogHeight, TRUE);
        RECT logClient{ 0, kLogTop, kWidth, kLogTop + kLogHeight };
        ::SendMessageW(callbackLogTab_, TCM_ADJUSTRECT, FALSE, reinterpret_cast<LPARAM>(&logClient));
        const int kSelectedLog = static_cast<int>(::SendMessageW(callbackLogTab_, TCM_GETCURSEL, 0, 0));
        ::ShowWindow(callbackAppLogEdit_, kSelectedLog == 0 ? SW_SHOW : SW_HIDE);
        ::ShowWindow(callbackEventLogEdit_, kSelectedLog == 1 ? SW_SHOW : SW_HIDE);
        ::MoveWindow(callbackAppLogEdit_, logClient.left, logClient.top, width(logClient), height(logClient), TRUE);
        ::MoveWindow(callbackEventLogEdit_, logClient.left, logClient.top, width(logClient), height(logClient), TRUE);

        const int kFileTop = kLogTop + kLogHeight + kCompactGap;
        int fx = 0;
        ::MoveWindow(callbackFileMonitorLabel_, fx, kFileTop + 4, 132, 18, TRUE); fx += 136;
        ::MoveWindow(callbackStartFsctlButton_, fx, kFileTop, 104, kButtonHeight, TRUE); fx += 108;
        ::MoveWindow(callbackDrainFileMonitorButton_, fx, kFileTop, 68, kButtonHeight, TRUE); fx += 72;
        ::MoveWindow(callbackClearFileMonitorButton_, fx, kFileTop, 48, kButtonHeight, TRUE); fx += 52;
        ::MoveWindow(callbackExportFileMonitorButton_, fx, kFileTop, 48, kButtonHeight, TRUE); fx += 52;
        ::MoveWindow(callbackFileMonitorFsctlOnlyCheck_, fx, kFileTop + 3, 142, 20, TRUE); fx += 146;
        ::MoveWindow(callbackFileMonitorStatusText_, fx, kFileTop + 4, std::max(0, kWidth - fx), 18, TRUE);
        ::MoveWindow(callbackFileMonitorList_, 0, kFileTop + kButtonHeight + kCompactGap, kWidth, std::max(0, kHeight - kFileTop - kButtonHeight - kCompactGap), TRUE);
        return;
    }

    if (kShowPropertyTable) {
        const int kPropertyWidth = std::max(260, kWidth / 3);
        ::MoveWindow(summaryList_, 0, kResultTop, 0, 0, TRUE);
        ::MoveWindow(resultList_, 0, kResultTop, std::max(0, kWidth - kPropertyWidth), kResultHeight, TRUE);
        ::MoveWindow(propertyList_, std::max(0, kWidth - kPropertyWidth), kResultTop, kPropertyWidth, kResultHeight, TRUE);
    } else if (kShowSummaryTable) {
        const int kAvailableHeight = std::max(0, kHeight - kResultTop);
        const int kSummaryHeight = std::min(std::max(96, kAvailableHeight / 4), std::max(96, kAvailableHeight / 2));
        const int kLowerTop = kResultTop + kSummaryHeight;
        const int kLowerHeight = std::max(0, kHeight - kLowerTop);
        const int kListWidth = (kWidth * 3) / 5;
        ::MoveWindow(summaryList_, 0, kResultTop, kWidth, kSummaryHeight, TRUE);
        ::MoveWindow(resultList_, 0, kLowerTop, kListWidth, kLowerHeight, TRUE);
        ::MoveWindow(propertyList_, kWidth, kResultTop, 0, kResultHeight, TRUE);
        ::MoveWindow(detailEdit_, kListWidth, kLowerTop, std::max(0, kWidth - kListWidth), kLowerHeight, TRUE);
        ::ShowWindow(propertyList_, SW_HIDE);
        ::ShowWindow(summaryList_, SW_SHOW);
        ::ShowWindow(detailEdit_, SW_SHOW);
        return;
    } else if (kShowRuntimePanel) {
        const int kSummaryHeight = std::max(96, kResultHeight / 3);
        ::MoveWindow(summaryList_, 0, kResultTop, kWidth, kSummaryHeight, TRUE);
        ::MoveWindow(resultList_, 0, kResultTop + kSummaryHeight, kWidth, std::max(0, kResultHeight - kSummaryHeight), TRUE);
        ::MoveWindow(propertyList_, kWidth, kResultTop, 0, kResultHeight, TRUE);
    } else {
        ::MoveWindow(summaryList_, 0, kResultTop, 0, 0, TRUE);
        ::MoveWindow(resultList_, 0, kResultTop, kWidth, kResultHeight, TRUE);
        ::MoveWindow(propertyList_, kWidth, kResultTop, 0, kResultHeight, TRUE);
    }
    ::ShowWindow(propertyList_, kShowPropertyTable ? SW_SHOW : SW_HIDE);
    ::ShowWindow(summaryList_, (kShowSummaryTable || kShowRuntimePanel) ? SW_SHOW : SW_HIDE);
    ::MoveWindow(detailEdit_,
        0,
        std::max(0, kHeight - kDetailHeight),
        kWidth,
        kDetailHeight,
        TRUE);
    ::ShowWindow(detailEdit_, SW_SHOW);
}

void KernelPage::populateTabs() {
    features_ = getKernelFeatureDescriptors();
    primaryTabs_.clear();
    primaryFeatureIds_.clear();

    ::SendMessageW(primaryTab_, TCM_DELETEALLITEMS, 0, 0);
    for (const TopLevelTabSpec& spec : originalTopLevelTabs()) {
        if (featureById(spec.featureId) == nullptr) {
            continue;
        }
        primaryTabs_.push_back(spec.title);
        primaryFeatureIds_.push_back(spec.featureId);
        setTabText(primaryTab_, static_cast<int>(primaryTabs_.size() - 1), spec.title);
    }

    if (!primaryTabs_.empty()) {
        ::SendMessageW(primaryTab_, TCM_SETCURSEL, 0, 0);
        rebuildSecondLevelTabs();
        if (hasInitialFeatureId_) {
            // Embedded callers use createKernelSingleFeaturePage. Keep that
            // contract even when the requested feature also belongs to the
            // full Kernel dock's primary/secondary navigation tree; otherwise
            // the host dock ends up rendering a duplicate tab strip.
            hasInitialFeatureId_ = false;
            if (featureById(initialFeatureId_) != nullptr) {
                hasDirectFeatureId_ = true;
                directFeatureId_ = initialFeatureId_;
                selectCurrentFeature();
                layout();
            } else {
                selectCurrentFeature();
            }
        } else {
            selectCurrentFeature();
        }
    }
}

bool KernelPage::selectFeatureById(const KernelFeatureId featureId) {
    // selectFeatureById maps one retained feature id into the original
    // primary/secondary tab model. Inputs are immutable catalog ids; processing
    // changes tab selection when the feature is visible in the Kernel dock, or
    // enters a direct single-feature mode when an external dock embeds a hidden
    // retained page through setInitialFeature. Output reports whether a feature
    // was selected.
    ksword::ui::ScopedWindowRedrawLock pageRedrawLock(hwnd_);
    if (featureById(featureId) == nullptr) {
        return false;
    }
    if (!hasActiveFeatureId_ || activeFeatureId_ != featureId) {
        parkCurrentFeatureViewCache();
    }
    for (int primaryIndex = 0; primaryIndex < static_cast<int>(primaryFeatureIds_.size()); ++primaryIndex) {
        const KernelFeatureId kPrimaryId = primaryFeatureIds_[static_cast<std::size_t>(primaryIndex)];
        if (kPrimaryId == featureId) {
            hasDirectFeatureId_ = false;
            ::SendMessageW(primaryTab_, TCM_SETCURSEL, static_cast<WPARAM>(primaryIndex), 0);
            rebuildSecondLevelTabs();
            selectCurrentFeature();
            return true;
        }

        const std::vector<ObjectNamespaceTabSpec>& secondaryTabs = secondaryTabsForPrimary(kPrimaryId);
        for (const ObjectNamespaceTabSpec& secondary : secondaryTabs) {
            if (secondary.featureId != featureId || featureById(secondary.featureId) == nullptr) {
                continue;
            }
            hasDirectFeatureId_ = false;
            ::SendMessageW(primaryTab_, TCM_SETCURSEL, static_cast<WPARAM>(primaryIndex), 0);
            rebuildSecondLevelTabs();
            for (int secondaryIndex = 0; secondaryIndex < static_cast<int>(secondaryFeatureIds_.size()); ++secondaryIndex) {
                if (secondaryFeatureIds_[static_cast<std::size_t>(secondaryIndex)] == featureId) {
                    ::SendMessageW(secondaryTab_, TCM_SETCURSEL, static_cast<WPARAM>(secondaryIndex), 0);
                    selectCurrentFeature();
                    return true;
                }
            }
            selectCurrentFeature();
            return true;
        }
    }
    hasDirectFeatureId_ = true;
    directFeatureId_ = featureId;
    ::SendMessageW(primaryTab_, TCM_SETCURSEL, static_cast<WPARAM>(-1), 0);
    ::SendMessageW(secondaryTab_, TCM_DELETEALLITEMS, 0, 0);
    secondaryFeatureIds_.clear();
    selectCurrentFeature();
    layout();
    return true;
}

void KernelPage::rebuildSecondLevelTabs() {
    ::SendMessageW(secondaryTab_, TCM_DELETEALLITEMS, 0, 0);
    secondaryFeatureIds_.clear();
    const int kPrimary = currentPrimaryIndex();
    if (kPrimary < 0 || kPrimary >= static_cast<int>(primaryFeatureIds_.size())) {
        clearResultTable();
        layout();
        return;
    }
    const KernelFeatureId kPrimaryFeatureId = primaryFeatureIds_[static_cast<std::size_t>(kPrimary)];
    int tabIndex = 0;
    for (const ObjectNamespaceTabSpec& spec : secondaryTabsForPrimary(kPrimaryFeatureId)) {
        if (featureById(spec.featureId) != nullptr) {
            secondaryFeatureIds_.push_back(spec.featureId);
            setTabText(secondaryTab_, tabIndex++, spec.title);
        }
    }
    if (tabIndex > 0) {
        int selectedSecondary = 0;
        const auto kRemembered = lastSecondaryFeatureByPrimary_.find(kPrimaryFeatureId);
        if (kRemembered != lastSecondaryFeatureByPrimary_.end()) {
            for (int index = 0; index < static_cast<int>(secondaryFeatureIds_.size()); ++index) {
                if (secondaryFeatureIds_[static_cast<std::size_t>(index)] == kRemembered->second) {
                    selectedSecondary = index;
                    break;
                }
            }
        }
        ::SendMessageW(secondaryTab_, TCM_SETCURSEL, static_cast<WPARAM>(selectedSecondary), 0);
    }
    layout();
}

void KernelPage::onFeatureSelectionChanged() {
    selectCurrentFeature();
}

void KernelPage::selectCurrentFeature() {
    const KernelFeatureDescriptor* descriptor = currentDescriptor();
    if (!descriptor) {
        clearResultTable();
        return;
    }
    if (hasActiveFeatureId_ && activeFeatureId_ == descriptor->id) {
        configureVisibleLayout();
        return;
    }
    if (const int kPrimary = currentPrimaryIndex(); kPrimary >= 0 && kPrimary < static_cast<int>(primaryFeatureIds_.size())) {
        lastSecondaryFeatureByPrimary_[primaryFeatureIds_[static_cast<std::size_t>(kPrimary)]] = descriptor->id;
    }
    verticalSplitterOffset_ = -1;
    verticalSplitterRect_ = {};
    configureToolbarForDescriptor(*descriptor);
    if (!restoreFeatureViewCache(descriptor->id)) {
        renderDescriptor(*descriptor);
    }
    activeFeatureId_ = descriptor->id;
    hasActiveFeatureId_ = true;
    configureVisibleLayout();
}

void KernelPage::parkCurrentFeatureViewCache() {
    // parkCurrentFeatureViewCache moves the currently visible feature buffers
    // into the retained cache before tab selection points at another feature.
    // Input is the activeFeatureId_ state; processing is skipped when no page is
    // active or when the live buffers are already empty; no value is returned.
    if (!hasActiveFeatureId_ ||
        (currentColumns_.empty() && currentRows_.empty() && currentRawColumns_.empty() && currentRawRows_.empty())) {
        return;
    }
    saveCurrentFeatureViewCache(true);
}

void KernelPage::refreshSelectedFeature() {
    const KernelFeatureDescriptor* descriptor = currentDescriptor();
    if (!descriptor) {
        return;
    }
    activeFeatureId_ = descriptor->id;
    hasActiveFeatureId_ = true;
    KernelRequest request = buildCurrentRequest(descriptor->id);
    if (!queryTask_) {
        const KernelOperationResult kResult = facade_.queryFeature(request);
        renderResult(kResult);
        invalidateCurrentFeatureViewCache();
        return;
    }
    const KernelFeatureId kFeatureId = descriptor->id;
    const std::uint64_t kRequestId = ++queryRequestId_;
    if (statusText_) {
        ::SetWindowTextW(statusText_, queryTask_->running()
            ? L"正在排队后台内核查询…"
            : L"正在后台查询内核快照…");
    }
    ::EnableWindow(refreshButton_, FALSE);
    queryTask_->request(
        [request] {
            KernelFacade facade;
            return facade.queryFeature(request);
        },
        [this, kFeatureId, kRequestId](std::uint64_t, std::optional<KernelOperationResult>&& result, std::exception_ptr error) {
            ::EnableWindow(refreshButton_, TRUE);
            const KernelFeatureDescriptor* current = currentDescriptor();
            if (error || !result.has_value()) {
                if (kRequestId == queryRequestId_ && current && current->id == kFeatureId && statusText_) {
                    ::SetWindowTextW(statusText_, L"内核后台查询异常结束，已保留当前结果。");
                }
                return;
            }
            if (kRequestId != queryRequestId_ || !current || current->id != kFeatureId) {
                return;
            }
            renderResult(*result);
            invalidateCurrentFeatureViewCache();
        });
}

void KernelPage::saveCurrentFeatureViewCache(const bool transferDataToCache) {
    // saveCurrentFeatureViewCache stores the currently rendered page under the
    // last active feature id rather than currentDescriptor(). Inputs select
    // whether the large row buffers should be transferred into the cache. Tab
    // switches pass true so rows are moved instead of copied; in-place refresh,
    // sort, and filter paths pass false and only update lightweight UI state.
    // There is no return value.
    if (!hasActiveFeatureId_) {
        return;
    }
    const KernelFeatureId kCacheFeatureId = activeFeatureId_;
    KernelFeatureViewCache& cache = featureViewCache_[kCacheFeatureId];
    if (transferDataToCache) {
        cache.columns = std::move(currentColumns_);
        cache.rows = std::move(currentRows_);
        cache.rowIndents = std::move(currentRowIndents_);
        cache.rawColumns = std::move(currentRawColumns_);
        cache.rawRows = std::move(currentRawRows_);
        cache.collapsedObjectPaths = std::move(collapsedObjectPaths_);
        cache.propertyRows = captureReportListRows(propertyList_);
        cache.summaryRows = captureReportListRows(summaryList_);
    }
    cache.filterText = windowText(filterEdit_);
    cache.moduleFilterText = windowText(moduleFilterEdit_);
    cache.objectNamespaceSelectedRow = objectNamespaceSelectedRow_;
    cache.objectNamespaceSelectedKind = objectNamespaceSelectedKind_;
    cache.objectNamespaceSelectedPath = objectNamespaceSelectedPath_;
    cache.objectNamespaceSelectedDescription = objectNamespaceSelectedDescription_;
    cache.sortColumn = sortColumn_;
    cache.sortAscending = sortAscending_;
    cache.selectedRow = resultList_ ? ListView_GetNextItem(resultList_, -1, LVNI_SELECTED) : -1;
    cache.topRow = resultList_ ? ListView_GetTopIndex(resultList_) : 0;
    if (transferDataToCache) {
        cache.hasData = !cache.columns.empty() || !cache.rows.empty() || !cache.rawRows.empty();
    }
    if (detailEdit_) {
        cache.detailText = windowText(detailEdit_);
    }
    if (statusText_) {
        cache.statusText = windowText(statusText_);
    }
    if (transferDataToCache) {
        clearResultGridOnly();
    }
}

void KernelPage::invalidateCurrentFeatureViewCache() {
    // invalidateCurrentFeatureViewCache drops any stale parked snapshot for the
    // currently active feature after refresh/filter/sort mutates the live
    // buffers. Inputs are the current activeFeatureId_ state; processing keeps
    // the live page untouched and only marks the cached parked copy unusable;
    // no value is returned.
    if (!hasActiveFeatureId_) {
        return;
    }
    auto found = featureViewCache_.find(activeFeatureId_);
    if (found == featureViewCache_.end()) {
        return;
    }
    found->second.hasData = false;
    found->second.columns.clear();
    found->second.rows.clear();
    found->second.rowIndents.clear();
    found->second.rawColumns.clear();
    found->second.rawRows.clear();
    found->second.collapsedObjectPaths.clear();
    found->second.propertyRows.clear();
    found->second.summaryRows.clear();
}

bool KernelPage::restoreFeatureViewCache(const KernelFeatureId featureId) {
    // If the requested page is still resident in the current buffers, keep it
    // live instead of moving from the cache. This covers repeated selection or
    // control-notification noise and avoids a needless ListView reset.
    if (hasActiveFeatureId_ && activeFeatureId_ == featureId && (!currentColumns_.empty() || !currentRows_.empty() || !currentRawRows_.empty())) {
        return true;
    }

    auto found = featureViewCache_.find(featureId);
    if (found == featureViewCache_.end() || !found->second.hasData) {
        return false;
    }

    KernelFeatureViewCache& cache = found->second;
    currentColumns_ = std::move(cache.columns);
    currentRows_ = std::move(cache.rows);
    currentRowIndents_ = std::move(cache.rowIndents);
    currentRawColumns_ = std::move(cache.rawColumns);
    currentRawRows_ = std::move(cache.rawRows);
    collapsedObjectPaths_ = std::move(cache.collapsedObjectPaths);
    objectNamespaceSelectedRow_ = cache.objectNamespaceSelectedRow;
    objectNamespaceSelectedKind_ = cache.objectNamespaceSelectedKind;
    objectNamespaceSelectedPath_ = cache.objectNamespaceSelectedPath;
    objectNamespaceSelectedDescription_ = cache.objectNamespaceSelectedDescription;
    sortColumn_ = cache.sortColumn;
    sortAscending_ = cache.sortAscending;
    struct ScopedFilterChangeSuppressor {
        bool& flag;
        explicit ScopedFilterChangeSuppressor(bool& target) : flag(target) { flag = true; }
        ~ScopedFilterChangeSuppressor() { flag = false; }
    } suppressor(suppressFilterChange_);
    if (filterEdit_) {
        ::SetWindowTextW(filterEdit_, cache.filterText.c_str());
    }
    if (moduleFilterEdit_) {
        ::SetWindowTextW(moduleFilterEdit_, cache.moduleFilterText.c_str());
    }

    clearResultGridOnly();
    ensureResultColumnsForCurrentFeature();
    syncResultListVirtualRows();
    restoreReportListRows(propertyList_, cache.propertyRows);
    restoreReportListRows(summaryList_, cache.summaryRows);
    if (featureId == KernelFeatureId::kObjectNamespaceOverview || featureId == KernelFeatureId::kObjectDirectoryRecursive) {
        const bool kTreeMatchesPage = hasObjectNamespaceTreeFeatureId_ && objectNamespaceTreeFeatureId_ == featureId;
        if (!objectNamespaceTree_ || TreeView_GetCount(objectNamespaceTree_) == 0 || !kTreeMatchesPage) {
            rebuildObjectNamespaceTreeFromCurrentRows();
        }
    }
    if (statusText_) {
        ::SetWindowTextW(statusText_, cache.statusText.empty() ? L"状态：已恢复缓存。": cache.statusText.c_str());
    }
    if (detailEdit_) {
        ::SetWindowTextW(detailEdit_, cache.detailText.c_str());
    }
    if (!currentRows_.empty()) {
        const int kSelected = cache.selectedRow >= 0 && cache.selectedRow < static_cast<int>(currentRows_.size())
            ? cache.selectedRow
            : 0;
        const int kTopRow = std::max(0, std::min(cache.topRow, static_cast<int>(currentRows_.size()) - 1));
        ListView_SetItemState(resultList_, kSelected, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        if (kTopRow > 0) {
            ListView_EnsureVisible(resultList_, kTopRow, FALSE);
        } else {
            ListView_EnsureVisible(resultList_, kSelected, FALSE);
        }
    }
    cache.hasData = false;
    return true;
}

void KernelPage::resetVisibleResultRows() {
    currentRows_.clear();
    currentRowIndents_.clear();
    syncResultListVirtualRows();
}

void KernelPage::syncResultListVirtualRows() {
    if (!resultList_) {
        return;
    }
    const int kRows = static_cast<int>(std::min<std::size_t>(currentRows_.size(), static_cast<std::size_t>(std::numeric_limits<int>::max())));
    ListView_SetItemCountEx(resultList_, kRows, LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL);
    if (kRows == 0) {
        ListView_SetItemState(resultList_, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    }
    ::InvalidateRect(resultList_, nullptr, FALSE);
}

std::vector<std::vector<std::wstring>> KernelPage::captureReportListRows(HWND list) const {
    // captureReportListRows snapshots small auxiliary report controls such as
    // propertyList_ and summaryList_. Input is a ListView HWND; processing reads
    // visible cell text only; output is a row-major text table. It deliberately
    // is not used for resultList_, which is owner-data and can be huge.
    std::vector<std::vector<std::wstring>> rows;
    if (!list) {
        return rows;
    }
    const int kRowCount = ListView_GetItemCount(list);
    const int kColumnCount = headerColumnCount(list);
    rows.reserve(static_cast<std::size_t>(std::max(0, kRowCount)));
    for (int row = 0; row < kRowCount; ++row) {
        std::vector<std::wstring> cells;
        cells.reserve(static_cast<std::size_t>(std::max(0, kColumnCount)));
        for (int column = 0; column < kColumnCount; ++column) {
            cells.push_back(listViewText(list, row, column));
        }
        rows.push_back(std::move(cells));
    }
    return rows;
}

void KernelPage::restoreReportListRows(HWND list, const std::vector<std::vector<std::wstring>>& rows) {
    // restoreReportListRows restores small auxiliary report controls after a
    // tab switch. Inputs are the target ListView and cached text rows;
    // processing bulk-inserts rows under a redraw lock; no value is returned.
    if (!list) {
        return;
    }
    ksword::ui::ScopedListViewRedrawLock redrawLock(list);
    ListView_DeleteAllItems(list);
    for (const std::vector<std::wstring>& row : rows) {
        listViewInsertRow(list, row);
    }
}

void KernelPage::ensureResultColumnsForCurrentFeature() {
    // ensureResultColumnsForCurrentFeature syncs the owner-data ListView header
    // with currentColumns_. Inputs are the active feature and cached schema;
    // processing recreates only columns, never rows, so tab restore and sorting
    // stay lightweight. There is no return value.
    if (!resultList_) {
        return;
    }
    HWND header = ListView_GetHeader(resultList_);
    const int kCount = header ? Header_GetItemCount(header) : 0;
    for (int index = kCount - 1; index >= 0; --index) {
        ListView_DeleteColumn(resultList_, index);
    }

    const KernelFeatureDescriptor* descriptor = currentDescriptor();
    const auto kIsObjectHiddenColumn = [](const std::wstring& name) {
        return name == L"Parent" ||
            name == L"Source" ||
            name == L"Directory" ||
            name == L"directoryPath" ||
            name == L"sourceDirectory" ||
            name == L"Depth" ||
            name == L"Path" ||
            name == L"NtPath" ||
            name == L"Target" ||
            name == L"Win32Path" ||
            name == L"dosCandidate" ||
            name == L"fullPath" ||
            name == L"targetPath" ||
            name == L"symbolicTarget" ||
            name == L"objectName" ||
            name == L"objectType" ||
            name == L"linkName" ||
            name == L"Handles" ||
            name == L"Pointers" ||
            name == L"EnumApi" ||
            name == L"enumApi" ||
            name == L"枚举 API" ||
            name == L"EnumerationApi" ||
            name == L"NodeKind" ||
            name == L"Detail";
    };
    const auto kIsDiagnosticHiddenColumn = [](const std::wstring& name) {
        return name == L"Id" ||
            name == L"StateId" ||
            name == L"SourceIndex" ||
            name == L"StatusFlags" ||
            name == L"CapabilityMask" ||
            name == L"Version" ||
            name == L"Protocol" ||
            name == L"ExpectedProtocol" ||
            name == L"SecurityPolicy" ||
            name == L"DynDataStatus" ||
            name == L"DynDataCapability" ||
            name == L"FeatureTotal" ||
            name == L"FeatureReturned" ||
            name == L"LastError" ||
            name == L"LastErrorSummary" ||
            name == L"LastErrorStatus" ||
            name == L"Class" ||
            name == L"Source" ||
            name == L"Callback" ||
            name == L"Context" ||
            name == L"Registration" ||
            name == L"ModulePath" ||
            name == L"Win32ModulePath" ||
            name == L"ModuleBase" ||
            name == L"ModuleSize" ||
            name == L"OperationMask" ||
            name == L"ObjectTypeMask" ||
            name == L"FieldFlags" ||
            name == L"Trust" ||
            name == L"Remove" ||
            name == L"RemoveFlags" ||
            name == L"Generation" ||
            name == L"IdentityHash" ||
            name == L"RawStorageValue" ||
            name == L"LastStatus" ||
            name == L"Detail";
    };

    for (std::size_t index = 0; index < currentColumns_.size(); ++index) {
        const std::wstring& name = currentColumns_[index];
        bool hidden = false;
        if (descriptor != nullptr) {
            if (isObjectNamespaceFeature(descriptor->id)) {
                hidden = kIsObjectHiddenColumn(name);
            } else if (isKernelHookFeature(descriptor->id)) {
                hidden = !isKernelHookVisibleColumn(descriptor->id, name);
            } else if (descriptor->id == KernelFeatureId::kDynData ||
                descriptor->id == KernelFeatureId::kDriverStatus ||
                descriptor->id == KernelFeatureId::kCallbackEnumeration) {
                hidden = kIsDiagnosticHiddenColumn(name);
            } else if (descriptor->id == KernelFeatureId::kKernelExecutableMemory ||
                descriptor->id == KernelFeatureId::kKernelMemoryEvidence) {
                hidden = isKernelMemoryHiddenColumn(name);
            } else if (descriptor->id == KernelFeatureId::kDriverIntegrity ||
                descriptor->id == KernelFeatureId::kKernelCpuIntegrity) {
                const bool kCanonicalColumn = hasColumn(canonicalColumnNames(descriptor->id), name);
                hidden = !kCanonicalColumn && isIntegrityHiddenColumn(name);
            }
        }
        addResultTableColumn(static_cast<int>(index), name, hidden ? 0 : columnWidth(name));
    }
}

std::wstring KernelPage::resultCellText(const int row, const int column) const {
    if (row < 0 || column < 0 ||
        row >= static_cast<int>(currentRows_.size()) ||
        column >= static_cast<int>(currentRows_[static_cast<std::size_t>(row)].size())) {
        return {};
    }
    return currentRows_[static_cast<std::size_t>(row)][static_cast<std::size_t>(column)];
}

std::wstring KernelPage::visibleCellText(const int row, const int column) const {
    // visibleCellText reads the current owner-data table cache. Inputs are
    // visible row and column indexes; output is the displayed string or empty
    // for invalid coordinates.
    return resultCellText(row, column);
}

void KernelPage::locateNextResult() {
    // locateNextResult finds the next visible result row containing the generic
    // filter text. Inputs are current ListView rows and filter edit text;
    // processing wraps after the last row; output is ListView selection/focus.
    if (!resultList_) {
        return;
    }
    const std::wstring kNeedle = windowText(filterEdit_);
    if (kNeedle.empty()) {
        return;
    }
    const int kRowCount = ListView_GetItemCount(resultList_);
    const int kColumnCount = headerColumnCount(resultList_);
    if (kRowCount <= 0 || kColumnCount <= 0) {
        return;
    }
    int start = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED);
    start = start < 0 ? 0 : (start + 1) % kRowCount;
    for (int step = 0; step < kRowCount; ++step) {
        const int kRow = (start + step) % kRowCount;
        bool matched = false;
        for (int column = 0; column < kColumnCount; ++column) {
            if (containsCaseInsensitive(visibleCellText(kRow, column), kNeedle)) {
                matched = true;
                break;
            }
        }
        if (matched) {
            ListView_SetItemState(resultList_, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
            ListView_SetItemState(resultList_, kRow, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
            ListView_EnsureVisible(resultList_, kRow, FALSE);
            updateSelectedRowDetail();
            return;
        }
    }
}

KernelRequest KernelPage::buildCurrentRequest(const KernelFeatureId featureId) const {
    // buildCurrentRequest is the single UI-to-facade request mapper. Inputs are
    // the selected feature id plus current edit-control values; processing keeps
    // generic filters available to all R3 pages and module filters available to
    // R0 hook scans; return is a value object with no HWND lifetime dependency.
    KernelRequest request;
    request.featureId = featureId;
    request.filterText = windowText(filterEdit_);
    request.moduleFilterText = windowText(moduleFilterEdit_);
    if (featureId == KernelFeatureId::kNtQueryLegacy) {
        request.filterText.clear();
        request.moduleFilterText.clear();
    }
    if (featureId == KernelFeatureId::kSymbolicLink) {
        // SymbolicLink mirrors the original full tab: R3 returns the complete
        // snapshot, then the main and target filter edits are applied locally.
        request.filterText.clear();
        request.moduleFilterText.clear();
    }
    if (featureId == KernelFeatureId::kNamedPipe ||
        featureId == KernelFeatureId::kBaseNamedObjects ||
        featureId == KernelFeatureId::kCommunicationEndpoint) {
        // These R3 object pages keep their original behavior: enumerate the full
        // backing namespace first, then let the visible toolbar controls filter
        // the cached rows. Keeping request filters empty prevents a stale edit
        // value from hiding rows before combo options/details are rebuilt.
        request.filterText.clear();
        request.moduleFilterText.clear();
    }
    if (featureId == KernelFeatureId::kDriverIntegrity) {
        request.filterText = windowText(integrityModuleBaseEdit_);
        request.moduleFilterText = windowText(moduleFilterEdit_);
    }
    if (featureId == KernelFeatureId::kKernelExecutableMemory ||
        featureId == KernelFeatureId::kKernelMemoryEvidence) {
        if (riskOnlyCheck_ && Button_GetCheck(riskOnlyCheck_) == BST_CHECKED) {
            request.flags |= kKernelRequestFlagRiskOnly;
        }
        if (featureId == KernelFeatureId::kKernelMemoryEvidence) {
            if (evidenceIncludeNonModuleCheck_ && Button_GetCheck(evidenceIncludeNonModuleCheck_) == BST_CHECKED) {
                request.flags |= kKernelRequestFlagIncludeNonModuleExecutableRanges;
            }
            parseUnsigned64Value(windowText(evidenceStartEdit_), request.startAddress);
            parseUnsigned64Value(windowText(evidenceEndEdit_), request.endAddress);
            request.maxRows = parseUnsigned(windowText(evidenceMaxRowsEdit_), 256);
        }
    }
    if (featureId == KernelFeatureId::kDriverIntegrity ||
        featureId == KernelFeatureId::kKernelCpuIntegrity) {
        request.maxRows = parseUnsigned(windowText(evidenceMaxRowsEdit_), 1024);
        request.idtVectorLimit = parseUnsigned(windowText(integrityIdtVectorsEdit_), 64);
    }
    if (featureId == KernelFeatureId::kDeviceDriverObjects) {
        // Device/Driver Objects intentionally requests a full snapshot. The
        // keyword edit plus directory/type comboboxes are local filters applied
        // after data arrives, matching the original full KernelDock tab behavior.
        request.filterText.clear();
        request.moduleFilterText.clear();
    }
    if (featureId == KernelFeatureId::kObjectTypeMatrix) {
        // Object Type Matrix also mirrors the original tab: NtQueryObject returns
        // the whole object-type table, and the edit box only filters the already
        // loaded rows locally. The request therefore carries no remote filter.
        request.filterText.clear();
        request.moduleFilterText.clear();
    }
    if (featureId == KernelFeatureId::kObjectDirectoryRecursive) {
        const std::uint32_t kDepth = parseUnsigned(windowText(moduleFilterEdit_), 4);
        request.moduleFilterText = std::to_wstring(std::min<std::uint32_t>(kDepth, 32));
    }
    request.flags |= currentIncludeFlags();
    return request;
}

void KernelPage::executeObjectNamespaceToolbarAction() {
    // executeObjectNamespaceToolbarAction mirrors the per-page small toolbar
    // action in the original R3 object-namespace tabs. Inputs are current
    // feature/selection; processing dispatches to copy/filter helpers; no value
    // is returned because the effect is UI state or clipboard text.
    const KernelFeatureDescriptor* descriptor = currentDescriptor();
    if (descriptor == nullptr) {
        return;
    }
    switch (descriptor->id) {
    case KernelFeatureId::kObjectDirectoryRecursive:
        refreshSelectedFeature();
        break;
    case KernelFeatureId::kNamedPipe:
        copyPreferredSelectedField({ L"Pipe", L"Pipe Name", L"Name", L"objectName" }, L"状态：已复制命名管道名称。");
        break;
    case KernelFeatureId::kDeviceDriverObjects:
        exportAllRowsTsv();
        break;
    case KernelFeatureId::kObjectTypeMatrix:
        copyPreferredSelectedField({ L"类型名", L"Type", L"objectType" }, L"状态：已复制对象类型名。");
        break;
    case KernelFeatureId::kCommunicationEndpoint:
        copyPreferredSelectedField({ L"完整路径", L"fullPath", L"Path" }, L"状态：已复制通信端点完整路径。");
        break;
    case KernelFeatureId::kBaseNamedObjects:
        copyPreferredSelectedField({ L"fullPath", L"Path", L"完整路径" }, L"状态：已复制 BaseNamedObjects 完整路径。");
        break;
    case KernelFeatureId::kSymbolicLink:
        copyPreferredSelectedField({ L"targetPath", L"symbolicTarget", L"Target", L"目标路径", L"符号链接目标" }, L"状态：已复制符号链接目标。");
        break;
    default:
        locateNextResult();
        break;
    }
}

void KernelPage::executeObjectNamespaceDetailAction() {
    // executeObjectNamespaceDetailAction mirrors the extra toolbar button on the
    // original object-namespace pages. Inputs are current page/selection; output
    // is either copied TSV/DOS text or refreshed detail text.
    const KernelFeatureDescriptor* descriptor = currentDescriptor();
    if (descriptor == nullptr) {
        return;
    }
    switch (descriptor->id) {
    case KernelFeatureId::kNamedPipe:
        executeSelectedAction(KernelActionId::kNativeNamedPipeProbe);
        break;
    case KernelFeatureId::kSymbolicLink:
        executeSelectedAction(KernelActionId::kNativeSymbolicLinkResolve);
        break;
    case KernelFeatureId::kDeviceDriverObjects:
        executeSelectedAction(KernelActionId::kNativeObjectQueryDetail);
        break;
    case KernelFeatureId::kObjectTypeMatrix:
        applySelectedTypeFilter();
        break;
    case KernelFeatureId::kCommunicationEndpoint:
        executeSelectedAction(KernelActionId::kNativeObjectQueryDetail);
        break;
    case KernelFeatureId::kBaseNamedObjects:
        executeSelectedAction(KernelActionId::kNativeObjectQueryDetail);
        break;
    default:
        copyDiagnosticReport();
        break;
    }
}

void KernelPage::fillIntegrityInputsFromSelection() {
    // fillIntegrityInputsFromSelection mirrors the original DriverDock helper in
    // a page-local way. Inputs are the currently selected evidence row; processing
    // copies any driver-object path and module-base value into the query edits;
    // there is no return value because the visible controls are updated directly.
    const std::wstring kDriverObject = firstSelectedRowField({
        L"DriverObject", L"DriverName", L"完整路径", L"fullPath", L"Path", L"Name"
    });
    const std::wstring kModuleBase = firstSelectedRowField({
        L"OwnerModuleBase", L"OwnerBase", L"ModuleBase"
    });

    bool updated = false;
    if (!kDriverObject.empty() && (containsCaseInsensitive(kDriverObject, L"\\Driver\\") || kDriverObject[0] == L'\\')) {
        ::SetWindowTextW(moduleFilterEdit_, kDriverObject.c_str());
        updated = true;
    }
    if (!kModuleBase.empty() && kModuleBase != L"0" && kModuleBase != L"0x0") {
        ::SetWindowTextW(integrityModuleBaseEdit_, kModuleBase.c_str());
        updated = true;
    }
    ::SetWindowTextW(statusText_, updated
        ? L"状态：已从当前选中行填充 DriverObject/模块基址。"
        : L"状态：当前选中行没有可填充的 DriverObject 或模块基址。");
}

void KernelPage::refreshKernelCpuIntegrityFromDriverPage() {
    // refreshKernelCpuIntegrityFromDriverPage implements the original
    // DriverDock CPU-only button. Inputs are the current max-row/risk controls;
    // processing queries KernelCpuIntegrity through KernelFacade and renders the
    // evidence rows in the same table; there is no direct driver access here.
    KernelRequest request = buildCurrentRequest(KernelFeatureId::kKernelCpuIntegrity);
    if (!queryTask_) {
        const KernelOperationResult kResult = facade_.queryFeature(request);
        renderResult(kResult);
        ::SetWindowTextW(statusText_, (L"状态：CPU-only 完整性查询完成 | " + kResult.message).c_str());
        return;
    }
    const KernelFeatureId kActiveFeatureId = activeFeatureId_;
    const std::uint64_t kRequestId = ++queryRequestId_;
    ::SetWindowTextW(statusText_, L"状态：正在后台查询 CPU-only 完整性快照…");
    ::EnableWindow(refreshButton_, FALSE);
    queryTask_->request(
        [request] {
            KernelFacade facade;
            return facade.queryFeature(request);
        },
        [this, kActiveFeatureId, kRequestId](std::uint64_t, std::optional<KernelOperationResult>&& result, std::exception_ptr error) {
            ::EnableWindow(refreshButton_, TRUE);
            if (error || !result.has_value() || kRequestId != queryRequestId_ || activeFeatureId_ != kActiveFeatureId) {
                if (kRequestId == queryRequestId_ && activeFeatureId_ == kActiveFeatureId) {
                    ::SetWindowTextW(statusText_, L"状态：CPU-only 后台完整性查询异常结束。");
                }
                return;
            }
            renderResult(*result);
            ::SetWindowTextW(statusText_, (L"状态：CPU-only 完整性查询完成 | " + result->message).c_str());
        });
}

KernelActionRequest KernelPage::buildCurrentActionRequest(const KernelActionId actionId) const {
    // buildCurrentActionRequest copies the selected result row into a value-only
    // packet. Inputs are the current feature, edit filters, selected row, and
    // action id; processing deliberately stores only text fields so this UI layer
    // never owns driver handles or protocol structs; output is consumed by facade.
    KernelActionRequest request;
    const KernelFeatureDescriptor* descriptor = currentDescriptor();
    if (descriptor != nullptr) {
        request.featureId = descriptor->id;
    }
    request.actionId = actionId;
    request.filterText = windowText(filterEdit_);
    request.moduleFilterText = windowText(moduleFilterEdit_);

    const int kRow = resultList_ ? ListView_GetNextItem(resultList_, -1, LVNI_SELECTED) : -1;
    if (kRow >= 0) {
        const int kColumns = headerColumnCount(resultList_);
        for (int column = 0; column < kColumns; ++column) {
            const std::wstring kName = column < static_cast<int>(currentColumns_.size())
                ? currentColumns_[static_cast<std::size_t>(column)]
                : std::wstring(L"Column ") + std::to_wstring(column);
            request.rowFields.push_back({ kName, visibleCellText(kRow, column) });
        }
        if (kRow < static_cast<int>(currentRows_.size())) {
            const std::vector<std::wstring>& cachedRow = currentRows_[static_cast<std::size_t>(kRow)];
            for (int column = 0; column < static_cast<int>(currentColumns_.size()) && column < static_cast<int>(cachedRow.size()); ++column) {
                const std::wstring& name = currentColumns_[static_cast<std::size_t>(column)];
                const bool kAlreadyPresent = std::any_of(request.rowFields.begin(), request.rowFields.end(), [&](const auto& field) {
                    return _wcsicmp(field.first.c_str(), name.c_str()) == 0;
                });
                if (!kAlreadyPresent || (!cachedRow[static_cast<std::size_t>(column)].empty() && selectedRowField(name).empty())) {
                    request.rowFields.push_back({ name, cachedRow[static_cast<std::size_t>(column)] });
                }
            }
        }
    }
    return request;
}

void KernelPage::executeSelectedAction(const KernelActionId actionId) {
    if (actionTask_ && actionTask_->running()) {
        ::SetWindowTextW(statusText_, L"状态：内核动作正在后台执行，请等待当前结果。");
        return;
    }
    // executeSelectedAction is the only UI entry for mutable kernel operations.
    // Inputs are the menu action id and current selection/filter text; processing
    // asks for confirmation, calls KernelFacade, optionally asks for force
    // confirmation on inline patch refusal, and renders the action result.
    const KernelFeatureDescriptor* descriptor = currentDescriptor();
    if (descriptor == nullptr) {
        return;
    }

    KernelActionRequest request = buildCurrentActionRequest(actionId);
    std::wstring confirmTitle = L"内核动作确认";
    std::wstring confirmText = L"确认执行该内核动作？";
    bool requireSelectedRow = true;

    switch (actionId) {
    case KernelActionId::kInlineHookNopPatch:
        confirmTitle = L"Inline Hook NOP 摘除";
        confirmText =
            L"将通过 ArkDriverClient 对当前 Inline Hook 行发起 NOP 摘除请求。\n\n"
            L"函数: " + firstSelectedRowValue({ L"Function", L"函数" }) + L"\n"
            L"地址: " + firstSelectedRowValue({ L"Address", L"函数地址", L"目标地址" }) + L"\n"
            L"模块: " + firstSelectedRowValue({ L"Module", L"ModulePath", L"模块" }) + L"\n\n"
            L"该操作可能修改内核代码页。是否继续？";
        break;
    case KernelActionId::kCallbackCancelPendingDecisions:
        requireSelectedRow = false;
        confirmTitle = L"取消全部 Callback 等待决策";
        confirmText =
            L"将通过 ArkDriverClient::cancelAllPendingCallbackDecisions 通知 R0 取消当前所有等待用户回答的回调事件。\n\n"
            L"该操作会影响正在等待 AskUser 决策的回调请求；完成后会刷新运行态。是否继续？";
        break;
    case KernelActionId::kCallbackApplyDisabledEmptyRules:
        requireSelectedRow = false;
        confirmTitle = L"应用禁用空 Callback 规则";
        confirmText =
            L"将构造一个有效的空规则 blob，并通过 ArkDriverClient::setCallbackRules 应用到 R0。\n\n"
            L"规则组数和规则数均为 0，globalEnabled 为 false。该操作相当于禁用当前回调规则集，"
            L"并会改变 R0 callback runtime 的 ruleVersion。是否继续？";
        break;
    case KernelActionId::kCallbackApplyLocalRules:
        requireSelectedRow = false;
        request.moduleFilterText = serializeCallbackLocalConfig();
        confirmTitle = L"应用本地 Callback 规则";
        confirmText =
            L"将把当前 Win32 规则组/规则编辑器内容编译为 KSWORD_ARK_CALLBACK_RULE_BLOB，"
            L"并通过 ArkDriverClient::setCallbackRules 应用到 R0。\n\n"
            L"规则组数: " + std::to_wstring(callbackGroups_.size()) + L"\n"
            L"规则数: " + std::to_wstring(callbackRules_.size()) + L"\n\n"
            L"该操作会改变 R0 callback runtime 的 ruleVersion。是否继续？";
        break;
    case KernelActionId::kCallbackSafeRemove:
        confirmTitle = L"Callback 安全移除";
        confirmText =
            L"将通过 ArkDriverClient::removeExternalCallbackEx 的公开 API 路径移除当前回调。\n\n"
            L"名称: " + firstSelectedRowValue({ L"Name", L"名称" }) + L"\n"
            L"地址: " + selectedRowField(L"Callback") + L"\n"
            L"模块: " + firstSelectedRowValue({ L"ModulePath", L"Module", L"模块" }) + L"\n\n"
            L"不会使用 experimental unlink。是否继续？";
        break;
    case KernelActionId::kMinifilterSetBypassPids:
        requireSelectedRow = false;
        confirmTitle = L"设置 Minifilter 放行 PID";
        confirmText =
            L"将把“过滤/起点”输入框中的 PID 列表写入 R0 minifilter bypass 白名单。\n\n"
            L"PID 列表: " + request.filterText + L"\n\n"
            L"示例格式: 1234,5678。是否继续？";
        break;
    case KernelActionId::kMinifilterClearBypassPids:
        requireSelectedRow = false;
        confirmTitle = L"清空 Minifilter 放行 PID";
        confirmText = L"将清空 R0 minifilter bypass PID 白名单。是否继续？";
        break;
    case KernelActionId::kNetworkCaptureStart:
        requireSelectedRow = false;
        confirmTitle = L"启动逐包捕获";
        confirmText =
            L"将通过 ArkDriverClient::controlNetworkTrafficCapture 启动 R0 WFP 逐包采集。\n\n"
            L"采集环是固定大小的非分页缓冲，不会无限增长；代价是 WFP callout 会对每个报文做一次拷贝，"
            L"高流量时有可测量的开销。是否继续？";
        break;
    case KernelActionId::kNetworkCaptureStop:
        requireSelectedRow = false;
        confirmTitle = L"停止逐包捕获";
        confirmText =
            L"将停止 R0 WFP 逐包采集。已在环中的报文仍然保留、仍可读取，只是不再有新报文进入。\n\n"
            L"是否继续？";
        break;
    case KernelActionId::kDriverDispatchRestore:
        confirmTitle = L"恢复驱动派遣槽";
        confirmText =
            L"将把选中 MajorFunction 槽位写回本驱动记录的原始地址。\n\n"
            L"槽位: " + firstSelectedRowValue({ L"MajorFunction" }) + L"\n"
            L"当前值: " + firstSelectedRowValue({ L"Current" }) + L"\n"
            L"原始值: " + firstSelectedRowValue({ L"Original" }) + L"\n\n"
            L"R0 会先核对代次与 DriverObject 身份；期间若被他人改写过则直接拒绝，"
            L"不会覆盖。是否继续？";
        break;
    case KernelActionId::kDriverDispatchAbandon:
        confirmTitle = L"放弃派遣恢复记录";
        confirmText =
            L"将永久丢弃该 MajorFunction 槽位的恢复记录，内核中的当前值保持不变。\n\n"
            L"槽位: " + firstSelectedRowValue({ L"MajorFunction" }) + L"\n"
            L"当前值: " + firstSelectedRowValue({ L"Current" }) + L"\n"
            L"原始值: " + firstSelectedRowValue({ L"Original" }) + L"\n\n"
            L"此操作不改内核状态，但之后将再也无法把该槽位恢复回原值。是否继续？";
        break;
    case KernelActionId::kDriverImageRestore:
        confirmTitle = L"恢复驱动镜像字段";
        confirmText =
            L"将按该行的 ManagedFields 掩码，把本驱动改过的镜像字段写回原值，并恢复加载器链。\n\n"
            L"受管字段: " + firstSelectedRowValue({ L"ManagedFields" }) + L"\n"
            L"冲突字段: " + firstSelectedRowValue({ L"ConflictFields" }) + L"\n\n"
            L"冲突字段是已被第三方改写的部分，记录中的原值不再是它当时的值；"
            L"恢复会覆盖对方的写入。是否继续？";
        break;
    case KernelActionId::kDriverImageAbandon:
        confirmTitle = L"放弃镜像恢复记录";
        confirmText =
            L"将永久丢弃该驱动镜像字段的恢复记录，当前值与链状态全部保持不变。\n\n"
            L"受管字段: " + firstSelectedRowValue({ L"ManagedFields" }) + L"\n\n"
            L"此操作不改内核状态，但之后将再也无法恢复这些字段。是否继续？";
        break;
    case KernelActionId::kDriverCommunicationRestore:
        confirmTitle = L"恢复驱动通信";
        confirmText =
            L"将把该驱动被指向系统拒绝入口的派遣槽恢复为其自身处理例程。\n\n"
            L"当前生效掩码: " + firstSelectedRowValue({ L"ActiveMask" }) + L"\n"
            L"可恢复掩码: " + firstSelectedRowValue({ L"OwnedMask" }) + L"\n"
            L"冲突掩码: " + firstSelectedRowValue({ L"ConflictMask" }) + L"\n\n"
            L"只恢复可恢复掩码内的槽位；冲突槽位由他人改写，会被有意跳过。是否继续？";
        break;
    case KernelActionId::kPiDdbDeleteEntry:
        confirmTitle = L"删除 PiDDB 条目";
        confirmText =
            L"将通过 ArkDriverClient::deletePiDdbEntry 从 PiDDBCacheTable 中移除选中记录。\n\n"
            L"驱动: " + firstSelectedRowValue({ L"Driver", L"驱动" }) + L"\n"
            L"条目地址: " + firstSelectedRowValue({ L"Entry", L"条目地址" }) + L"\n"
            L"时间戳: " + firstSelectedRowValue({ L"TimeDateStamp", L"时间戳" }) + L"\n\n"
            L"该记录是加载器留下的「这个驱动曾在本机通过校验」的证据，删除后无法恢复，"
            L"也会改变取证结论。R0 会先核对该槽位是否仍与此处显示的一致，不一致则拒绝。是否继续？";
        break;
    case KernelActionId::kFileMonitorStartFsctl:
        requireSelectedRow = false;
        confirmTitle = L"启动 FSCTL 文件监控";
        confirmText = L"将通过 ArkDriverClient 启动/补充 R0 文件监控 FSCTL/Oplock 事件掩码。是否继续？";
        break;
    case KernelActionId::kFileMonitorDrain:
        requireSelectedRow = false;
        confirmTitle = L"拉取文件监控事件";
        confirmText = L"将从 R0 file-monitor ring buffer 拉取当前排队事件。是否继续？";
        break;
    case KernelActionId::kFileMonitorClear:
        requireSelectedRow = false;
        confirmTitle = L"清空文件监控表格";
        confirmText = L"将清空 R0 file-monitor 队列并刷新当前表格。是否继续？";
        break;
    case KernelActionId::kDriverObjectQueryDetail:
        confirmTitle = L"DriverObject 详情查询";
        confirmText =
            L"将通过 ArkDriverClient 查询当前行对应的 R0 DriverObject 详情。\n\n"
            L"DriverName: " + firstSelectedRowValue({ L"DriverName", L"对象名称", L"Name" }) + L"\n"
            L"Path: " + firstSelectedRowValue({ L"Path", L"fullPath", L"完整路径", L"NtPath" }) + L"\n"
            L"Name: " + firstSelectedRowValue({ L"Name", L"objectName", L"对象名称", L"名称" }) + L"\n\n"
            L"该操作只读取 DriverObject/MajorFunction/DeviceObject 信息。是否继续？";
        break;
    case KernelActionId::kDriverObjectForceUnload:
        confirmTitle = L"DriverObject 强制卸载";
        confirmText =
            L"将通过 ArkDriverClient 请求 R0 强制卸载当前行对应的 DriverObject。\n\n"
            L"DriverName: " + firstSelectedRowValue({ L"DriverName", L"对象名称", L"Name" }) + L"\n"
            L"Path: " + firstSelectedRowValue({ L"Path", L"fullPath", L"完整路径", L"NtPath" }) + L"\n"
            L"Name: " + firstSelectedRowValue({ L"Name", L"objectName", L"对象名称", L"名称" }) + L"\n\n"
            L"该操作可能调用 DriverUnload、删除 DeviceObject 并清理相关回调。是否继续？";
        break;
    case KernelActionId::kNativeObjectQueryDetail:
        confirmTitle = L"R3 对象详情";
        confirmText =
            L"将使用 NtOpenDirectoryObject/NtOpenSymbolicLinkObject/NtQueryObject 对当前行执行只读详情查询。\n\n"
            L"Path: " + firstSelectedRowValue({ L"Path", L"fullPath", L"完整路径", L"NtPath", L"NT Path" }) + L"\n"
            L"NtPath: " + firstSelectedRowValue({ L"NtPath", L"NT Path", L"Path", L"fullPath", L"完整路径" }) + L"\n"
            L"Type: " + firstSelectedRowValue({ L"Type", L"objectType", L"对象类型", L"类型", L"类型名" }) + L"\n\n"
            L"该操作不访问 R0 驱动，也不修改对象。是否继续？";
        break;
    case KernelActionId::kNativeSymbolicLinkResolve:
        confirmTitle = L"符号链接解析";
        confirmText =
            L"将使用 NtOpenSymbolicLinkObject/NtQuerySymbolicLinkObject 重新解析当前符号链接。\n\n"
            L"Path: " + firstSelectedRowValue({ L"Path", L"fullPath", L"完整路径", L"NtPath" }) + L"\n"
            L"Target: " + firstSelectedRowValue({ L"Target", L"targetPath", L"symbolicTarget", L"目标路径", L"符号链接目标" }) + L"\n\n"
            L"该操作只读。是否继续？";
        break;
    case KernelActionId::kNativeNamedPipeProbe:
        confirmTitle = L"命名管道打开验证";
        confirmText =
            L"将使用 NtOpenFile 以只读属性访问验证当前命名管道是否可打开。\n\n"
            L"NtPath: " + firstSelectedRowValue({ L"NtPath", L"NT Path", L"Path", L"fullPath" }) + L"\n"
            L"Pipe: " + firstSelectedRowValue({ L"Pipe", L"Pipe Name", L"Name", L"objectName" }) + L"\n\n"
            L"不会读写管道数据。是否继续？";
        break;
    case KernelActionId::kDynDataApplyMatchedProfile:
        requireSelectedRow = false;
        confirmTitle = L"DynData Profile 应用";
        confirmText =
            L"将查询当前 R0 ntoskrnl identity，在本地 profiles\\ark_dyndata_pack_v4.json 中寻找精确匹配，"
            L"然后通过 ArkDriverClient 调用 applyDynDataProfile/Ex 写入驱动 DynData 状态。\n\n"
            L"该操作会改变 R0 DynData 字段来源，影响后续内核枚举、CrossView、回调和 DriverObject 解析。是否继续？";
        break;
    case KernelActionId::kMutationCommitDryRun:
        confirmTitle = L"Mutation Commit Dry-run";
        confirmText =
            L"将对当前 Audit 行的 TransactionId 执行 ArkDriverClient::commitMutation dry-run。\n\n"
            L"Tx: " + firstSelectedRowField({ L"Tx", L"TransactionId" }) + L"\n"
            L"Status: " + selectedRowField(L"Status") + L"\n"
            L"TargetKind: " + selectedRowField(L"TargetKind") + L"\n\n"
            L"该动作不会提交写入，只验证事务状态和风险。是否继续？";
        break;
    case KernelActionId::kMutationRollbackDryRun:
        confirmTitle = L"Mutation Rollback Dry-run";
        confirmText =
            L"将对当前 Audit 行的 TransactionId 执行 ArkDriverClient::rollbackMutation dry-run。\n\n"
            L"Tx: " + firstSelectedRowField({ L"Tx", L"TransactionId" }) + L"\n"
            L"Status: " + selectedRowField(L"Status") + L"\n"
            L"TargetKind: " + selectedRowField(L"TargetKind") + L"\n\n"
            L"该动作不会写回 before 快照，只验证能否回滚。是否继续？";
        break;
    case KernelActionId::kMutationRollbackConfirmed:
        confirmTitle = L"Mutation Rollback 确认执行";
        confirmText =
            L"将对当前 Audit 行的 TransactionId 执行非 dry-run rollback，并带 UI_CONFIRMED 标志。\n\n"
            L"Tx: " + firstSelectedRowField({ L"Tx", L"TransactionId" }) + L"\n"
            L"Address: " + selectedRowField(L"Address") + L"\n"
            L"Bytes: " + selectedRowField(L"Bytes") + L"\n\n"
            L"该操作会尝试把 R0 事务目标恢复到 before 快照。是否继续？";
        break;
    case KernelActionId::kNone:
    default:
        return;
    }

    if (requireSelectedRow && (!resultList_ || ListView_GetNextItem(resultList_, -1, LVNI_SELECTED) < 0)) {
        ::MessageBoxW(hwnd_, L"请先选择一条结果行。", confirmTitle.c_str(), MB_OK | MB_ICONWARNING);
        return;
    }

    if (::MessageBoxW(hwnd_, confirmText.c_str(), confirmTitle.c_str(), MB_YESNO | MB_DEFBUTTON2 | MB_ICONWARNING) != IDYES) {
        ::SetWindowTextW(statusText_, L"状态：用户取消内核动作。");
        return;
    }

    executeActionInBackground(std::move(request), actionId, true);
}

void KernelPage::executeActionInBackground(KernelActionRequest request, const KernelActionId actionId, const bool offerForcedRetry) {
    if (!actionTask_) {
        renderResult(facade_.executeAction(request));
        return;
    }
    const KernelFeatureId kFeatureId = request.featureId;
    const std::uint64_t kRequestId = ++actionRequestId_;
    const KernelActionRequest kRetryRequest = request;
    ::SetWindowTextW(statusText_, L"状态：正在后台执行内核动作…");
    ::EnableWindow(refreshButton_, FALSE);
    actionTask_->request(
        [request] {
            KernelFacade facade;
            return facade.executeAction(request);
        },
        [this, request = kRetryRequest, actionId, kFeatureId, kRequestId, offerForcedRetry](std::uint64_t, std::optional<KernelOperationResult>&& result, std::exception_ptr error) mutable {
            ::EnableWindow(refreshButton_, TRUE);
            const KernelFeatureDescriptor* current = currentDescriptor();
            if (error || !result.has_value()) {
                if (kRequestId == actionRequestId_ && current && current->id == kFeatureId) {
                    ::SetWindowTextW(statusText_, L"状态：内核后台动作异常结束，未覆盖当前结果。");
                }
                return;
            }
            if (kRequestId != actionRequestId_ || !current || current->id != kFeatureId) {
                return;
            }
            bool forceRequired = false;
            if (offerForcedRetry && actionId == KernelActionId::kInlineHookNopPatch && !result->success) {
                for (const KernelResultRow& row : result->rows) {
                    for (const auto& column : row.columns) {
                        if (column.first == L"Status" && column.second == kInlineHookForceRequiredStatusText) {
                            forceRequired = true;
                            break;
                        }
                    }
                    if (forceRequired) {
                        break;
                    }
                }
            }
            if (forceRequired) {
                const std::wstring kForceText =
                    L"R0 拒绝了普通 Inline Hook NOP 请求并要求强制确认。\n\n"
                    L"地址: " + firstSelectedRowValue({ L"Address", L"函数地址", L"目标地址" }) + L"\n"
                    L"模块: " + firstSelectedRowValue({ L"Module", L"ModulePath", L"模块" }) + L"\n\n"
                    L"强制继续会修改内核代码页，只应在确认目标和当前字节无误时使用。是否强制继续？";
                if (::MessageBoxW(hwnd_, kForceText.c_str(), L"强制 Inline Hook 摘除", MB_YESNO | MB_DEFBUTTON2 | MB_ICONERROR) == IDYES) {
                    request.force = true;
                    executeActionInBackground(std::move(request), actionId, false);
                    return;
                }
            }
            renderResult(*result);
        });
}

void KernelPage::renderDescriptor(const KernelFeatureDescriptor& descriptor) {
    ::SetWindowTextW(titleText_, descriptor.title.c_str());
    ::SetWindowTextW(summaryText_, L"");
    ::SetWindowTextW(backendText_, L"");
    ::SetWindowTextW(statusText_, L"状态：等待刷新。");

    currentColumns_.clear();
    currentRows_.clear();
    currentRawColumns_.clear();
    currentRawRows_.clear();
    sortColumn_ = -1;
    sortAscending_ = true;
    clearResultTable();
    ::SetWindowTextW(detailEdit_, emptyDetailTextForFeature(descriptor.id));
    if (isObjectNamespaceFeature(descriptor.id)) {
        const std::vector<std::wstring> kColumns = canonicalColumnNames(descriptor.id);
        if (usesObjectNamespaceTreeIndexColumn(descriptor.id)) {
            currentColumns_.push_back(L"#");
        }
        for (const std::wstring& column : kColumns) {
            currentColumns_.push_back(column);
        }
        if (!hasColumn(currentColumns_, L"Parent")) {
            currentColumns_.push_back(L"Parent");
        }
        if (!hasColumn(currentColumns_, L"Source")) {
            currentColumns_.push_back(L"Source");
        }
        if (!hasColumn(currentColumns_, L"Detail")) {
            currentColumns_.push_back(L"Detail");
        }
        rebuildObjectNamespaceListFromCache(descriptor.id);
        ::SetWindowTextW(statusText_, L"状态：等待刷新。");
        return;
    }

    const std::vector<std::wstring> kColumns = canonicalColumnNames(descriptor.id);
    if (kColumns.empty()) {
        addResultTableColumn(0, L"字段", 180);
        addResultTableColumn(1, L"值", 520);
        return;
    }
    currentColumns_ = kColumns;
    for (std::size_t index = 0; index < kColumns.size(); ++index) {
        addResultTableColumn(static_cast<int>(index), kColumns[index], columnWidth(kColumns[index]));
    }

    switch (descriptor.id) {
    case KernelFeatureId::kAtomTable:
        ::SetWindowTextW(detailEdit_, L"请选择一条原子记录查看详情。");
        break;
    case KernelFeatureId::kNtQueryLegacy:
        ::SetWindowTextW(detailEdit_, L"请选择一条 NtQuery 结果查看详情。");
        break;
    case KernelFeatureId::kSsdt:
        ::SetWindowTextW(detailEdit_, L"请选择一条 SSDT 记录查看详情。");
        break;
    case KernelFeatureId::kShadowSsdt:
        ::SetWindowTextW(detailEdit_, L"请选择一条 SSSDT 记录查看详情。");
        break;
    case KernelFeatureId::kInlineHook:
        ::SetWindowTextW(detailEdit_, L"请选择一条 Inline Hook 记录查看详情。");
        break;
    case KernelFeatureId::kIatEatHook:
        ::SetWindowTextW(detailEdit_, L"请选择一条 IAT/EAT 记录查看详情。");
        break;
    case KernelFeatureId::kCallbackEnumeration:
        ::SetWindowTextW(detailEdit_, L"请选择一条回调遍历记录查看详情。");
        break;
    default:
        ::SetWindowTextW(detailEdit_, L"");
        break;
    }
}

void KernelPage::renderResult(const KernelOperationResult& result) {
    ksword::ui::ScopedListViewRedrawLock resultListLock(resultList_);
    ksword::ui::ScopedListViewRedrawLock propertyListLock(propertyList_);
    ksword::ui::ScopedListViewRedrawLock summaryListLock(summaryList_);
    ksword::ui::ScopedWindowRedrawLock objectTreeLock(objectNamespaceTree_);
    std::vector<std::wstring> orderedColumns;
    addDynamicResultColumns(result, orderedColumns);
    bool statusHandledBySpecializedRenderer = false;
    currentColumns_ = orderedColumns;
    currentRows_.clear();
    currentRawColumns_.clear();
    currentRawRows_.clear();
    sortColumn_ = -1;
    sortAscending_ = true;

    for (std::size_t rowIndex = 0; rowIndex < result.rows.size(); ++rowIndex) {
        addDynamicResultRow(static_cast<int>(rowIndex), result.rows[rowIndex], orderedColumns);
    }
    currentRawColumns_ = currentColumns_;
    currentRawRows_ = currentRows_;
    if (const KernelFeatureDescriptor* descriptor = currentDescriptor();
        descriptor != nullptr && isObjectNamespaceFeature(descriptor->id)) {
        rebuildObjectNamespaceListFromCache(descriptor->id);
        statusHandledBySpecializedRenderer = true;
    } else if (const KernelFeatureDescriptor* descriptor = currentDescriptor();
        descriptor != nullptr && descriptor->id == KernelFeatureId::kAtomTable) {
        rebuildAtomTableFromCache();
        statusHandledBySpecializedRenderer = true;
    } else if (const KernelFeatureDescriptor* descriptor = currentDescriptor();
        descriptor != nullptr && descriptor->id == KernelFeatureId::kNtQueryLegacy) {
        rebuildNtQueryLegacyListFromCache();
        statusHandledBySpecializedRenderer = true;
    } else if (const KernelFeatureDescriptor* descriptor = currentDescriptor();
        descriptor != nullptr &&
        (descriptor->id == KernelFeatureId::kDynData || descriptor->id == KernelFeatureId::kDriverStatus)) {
        rebuildDiagnosticDualTableFromCache(descriptor->id);
        statusHandledBySpecializedRenderer = true;
    } else if (const KernelFeatureDescriptor* descriptor = currentDescriptor();
        descriptor != nullptr && descriptor->id == KernelFeatureId::kCallbackEnumeration) {
        rebuildCallbackEnumerationListFromCache();
        statusHandledBySpecializedRenderer = true;
    } else if (const KernelFeatureDescriptor* descriptor = currentDescriptor();
        descriptor != nullptr && isKernelHookFeature(descriptor->id)) {
        rebuildKernelHookListFromCache(descriptor->id);
        statusHandledBySpecializedRenderer = true;
    } else if (const KernelFeatureDescriptor* descriptor = currentDescriptor();
        descriptor != nullptr &&
        (descriptor->id == KernelFeatureId::kKernelExecutableMemory ||
            descriptor->id == KernelFeatureId::kKernelMemoryEvidence)) {
        rebuildKernelMemoryScanListFromCache(descriptor->id);
        statusHandledBySpecializedRenderer = true;
    } else if (const KernelFeatureDescriptor* descriptor = currentDescriptor();
        descriptor != nullptr &&
        (descriptor->id == KernelFeatureId::kProcessCrossView ||
            descriptor->id == KernelFeatureId::kThreadCrossView)) {
        rebuildCrossViewListFromCache(descriptor->id);
        statusHandledBySpecializedRenderer = true;
    } else if (const KernelFeatureDescriptor* descriptor = currentDescriptor();
        descriptor != nullptr &&
        (descriptor->id == KernelFeatureId::kDriverIntegrity ||
            descriptor->id == KernelFeatureId::kKernelCpuIntegrity)) {
        rebuildIntegrityEvidenceListFromCache(descriptor->id);
        statusHandledBySpecializedRenderer = true;
    } else if (const KernelFeatureDescriptor* descriptor = currentDescriptor();
        descriptor != nullptr &&
        (descriptor->id == KernelFeatureId::kCpuHardwareSnapshot ||
            descriptor->id == KernelFeatureId::kPhysicalMemoryLayout ||
            descriptor->id == KernelFeatureId::kMutationAudit ||
            descriptor->id == KernelFeatureId::kKeyboardHotkeys ||
             descriptor->id == KernelFeatureId::kKeyboardHooks ||
             descriptor->id == KernelFeatureId::kDynDataCapabilities ||
             descriptor->id == KernelFeatureId::kMinifilterBypassPids ||
             descriptor->id == KernelFeatureId::kKernelTimerDpc ||
             descriptor->id == KernelFeatureId::kIoctlRegistry)) {
        rebuildR0EvidenceListFromCache(descriptor->id);
        statusHandledBySpecializedRenderer = true;
    } else {
        rebuildResultListFromCache();
    }
    configureVisibleLayout();
    if (const KernelFeatureDescriptor* descriptor = currentDescriptor();
        descriptor != nullptr && descriptor->id == KernelFeatureId::kCallbackIntercept) {
        populateCallbackInterceptPanel();
        statusHandledBySpecializedRenderer = true;
    }

    if (statusHandledBySpecializedRenderer) {
        invalidateCurrentFeatureViewCache();
        return;
    }

    std::wostringstream status;
    if (const KernelFeatureDescriptor* descriptor = currentDescriptor(); descriptor != nullptr && isKernelHookFeature(descriptor->id)) {
        const auto kRowValue = [](const std::vector<std::wstring>& row, const std::vector<std::wstring>& columns, std::initializer_list<const wchar_t*> names) -> std::wstring {
            return rowFieldByName(row, columns, names);
        };
        std::size_t unresolved = 0;
        std::size_t suspicious = 0;
        for (const std::vector<std::wstring>& row : currentRows_) {
            const std::wstring kStatusText = kRowValue(row, currentColumns_, { L"状态", L"Status" });
            if (containsCaseInsensitive(kStatusText, L"未解析")) {
                ++unresolved;
            }
            if (containsCaseInsensitive(kStatusText, L"Hook") ||
                containsCaseInsensitive(kStatusText, L"可疑") ||
                containsCaseInsensitive(kStatusText, L"不同") ||
                containsCaseInsensitive(kStatusText, L"异常")) {
                ++suspicious;
            }
        }
        if (descriptor->id == KernelFeatureId::kSsdt) {
            status << L"状态：已刷新 " << result.rows.size() << L" 项，未解析索引 " << unresolved << L" 项";
        } else if (descriptor->id == KernelFeatureId::kShadowSsdt) {
            status << L"状态：SSSDT 已刷新 " << result.rows.size() << L" 项，未解析索引 " << unresolved << L" 项";
        } else if (descriptor->id == KernelFeatureId::kInlineHook) {
            status << L"状态：Inline Hook 扫描完成，可疑/差异 " << suspicious << L" 项，可见 " << result.rows.size() << L" 项";
        } else {
            status << L"状态：IAT/EAT 扫描完成，可疑 " << suspicious << L" 项，可见 " << result.rows.size() << L" 项";
        }
        status << L" | " << result.message;
    } else {
        status << L"状态：" << (result.success ? L"刷新完成" : L"刷新未完成")
               << L" | 支持: " << (result.supported ? L"是" : L"否")
               << L" | 行数: " << result.rows.size()
               << L" | " << result.message;
    }
    ::SetWindowTextW(statusText_, status.str().c_str());
}

void KernelPage::addDynamicResultColumns(const KernelOperationResult& result, std::vector<std::wstring>& orderedColumns) {
    // addDynamicResultColumns creates a useful table for heterogeneous kernel
    // workers. Inputs are the complete operation result; processing preserves
    // each worker's first-seen column order and keeps the original KernelDock
    // table schemas. Object-namespace tree-table pages use a private "#" helper
    // column for expansion; all other pages avoid synthetic row-number columns.
    orderedColumns.clear();
    if (const KernelFeatureDescriptor* descriptor = currentDescriptor()) {
        if (isObjectNamespaceFeature(descriptor->id) && usesObjectNamespaceTreeIndexColumn(descriptor->id)) {
            orderedColumns.push_back(L"#");
        }
        for (const std::wstring& columnName : canonicalColumnNames(descriptor->id)) {
            if (!hasColumn(orderedColumns, columnName)) {
                orderedColumns.push_back(columnName);
            }
        }
    }
    for (const KernelResultRow& row : result.rows) {
        for (const auto& column : row.columns) {
            if (!hasColumn(orderedColumns, column.first)) {
                orderedColumns.push_back(column.first);
            }
        }
    }
    if (!hasColumn(orderedColumns, L"Detail")) {
        orderedColumns.push_back(L"Detail");
    }

}

void KernelPage::addDynamicResultRow(const int rowIndex, const KernelResultRow& resultRow, const std::vector<std::wstring>& orderedColumns) {
    // addDynamicResultRow maps a key/value result packet onto the current table
    // schema. Inputs are the model row and ordered columns; processing fills
    // missing values with empty cells and only writes rowIndex into the private
    // object-namespace "#" helper column; there is no return value.
    std::vector<std::wstring> cells;
    const KernelFeatureDescriptor* descriptor = currentDescriptor();
    cells.reserve(orderedColumns.size());
    for (const std::wstring& columnName : orderedColumns) {
        if (columnName == L"#") {
            cells.push_back(std::to_wstring(rowIndex));
            continue;
        }
        if (columnName == L"Detail") {
            cells.push_back(resultRow.detailText);
            continue;
        }
        std::wstring value;
        std::vector<std::wstring> aliases = descriptor != nullptr
            ? columnAliases(descriptor->id, columnName)
            : std::vector<std::wstring>{ columnName };
        if (aliases.empty()) {
            aliases.push_back(columnName);
        }
        for (const std::wstring& alias : aliases) {
            auto found = std::find_if(resultRow.columns.begin(), resultRow.columns.end(), [&alias](const auto& column) {
                return _wcsicmp(column.first.c_str(), alias.c_str()) == 0;
            });
            if (found != resultRow.columns.end() && !found->second.empty()) {
                value = found->second;
                break;
            }
        }
        cells.push_back(std::move(value));
    }
    currentRows_.push_back(std::move(cells));
}

void KernelPage::rebuildResultListFromCache() {
    // rebuildResultListFromCache projects cached row data into the owner-data
    // ListView. Inputs are currentColumns_/currentRows_; processing rebuilds
    // only the column headers plus an in-memory visible-row vector, then exposes
    // the final row count with one ListView_SetItemCountEx call. It does not
    // return a value.
    const std::vector<std::vector<std::wstring>>& sourceRows = currentRows_;
    const std::vector<int>& sourceIndents = currentRowIndents_;
    clearResultTable();
    const KernelFeatureDescriptor* descriptor = currentDescriptor();
    const bool kObjectNamespaceLayout = descriptor != nullptr && isObjectNamespaceFeature(descriptor->id);
    const auto kIsHiddenObjectColumn = [](const std::wstring& name) {
        return name == L"Parent" ||
            name == L"Source" ||
            name == L"Directory" ||
            name == L"directoryPath" ||
            name == L"sourceDirectory" ||
            name == L"Depth" ||
            name == L"Path" ||
            name == L"NtPath" ||
            name == L"Target" ||
            name == L"Win32Path" ||
            name == L"dosCandidate" ||
            name == L"fullPath" ||
            name == L"targetPath" ||
            name == L"symbolicTarget" ||
            name == L"objectName" ||
            name == L"objectType" ||
            name == L"linkName" ||
            name == L"Handles" ||
            name == L"Pointers" ||
            name == L"Detail";
    };
    for (std::size_t index = 0; index < currentColumns_.size(); ++index) {
        const bool kHiddenColumn =
            (kObjectNamespaceLayout && kIsHiddenObjectColumn(currentColumns_[index])) ||
            (descriptor != nullptr && isKernelHookFeature(descriptor->id) && !isKernelHookVisibleColumn(descriptor->id, currentColumns_[index]));
        const int kWidth = kHiddenColumn ? 0 : columnWidth(currentColumns_[index]);
        addResultTableColumn(static_cast<int>(index), currentColumns_[index], kWidth);
    }
    const std::wstring kHookFilter = windowText(filterEdit_);
    const std::wstring kHookModuleFilter = windowText(moduleFilterEdit_);
    const auto kHookRowMatches = [&](const std::vector<std::wstring>& row) {
        if (descriptor == nullptr || !isKernelHookFeature(descriptor->id)) {
            return true;
        }
        std::wstring merged;
        for (const std::wstring& value : row) {
            if (!merged.empty()) {
                merged += L" | ";
            }
            merged += value;
        }
        if (!kHookFilter.empty() && !containsCaseInsensitive(merged, kHookFilter)) {
            return false;
        }
        if ((descriptor->id == KernelFeatureId::kInlineHook || descriptor->id == KernelFeatureId::kIatEatHook) && !kHookModuleFilter.empty()) {
            const std::wstring kModule = rowFieldByName(row, currentColumns_, { L"模块", L"Module", L"目标模块", L"TargetModule", L"导入模块", L"Import" });
            if (!containsCaseInsensitive(kModule, kHookModuleFilter)) {
                return false;
            }
        }
        return true;
    };

    std::vector<std::vector<std::wstring>> visibleRows;
    std::vector<int> visibleIndents;
    visibleRows.reserve(sourceRows.size());
    visibleIndents.reserve(sourceRows.size());
    for (std::size_t sourceIndex = 0; sourceIndex < sourceRows.size(); ++sourceIndex) {
        const std::vector<std::wstring>& row = sourceRows[sourceIndex];
        if (descriptor != nullptr && isKernelHookFeature(descriptor->id) &&
            !hasKernelHookDisplayValues(descriptor->id, currentColumns_, row)) {
            continue;
        }
        if (!kHookRowMatches(row)) {
            continue;
        }
        visibleRows.push_back(row);
        visibleIndents.push_back(sourceIndex < sourceIndents.size() ? sourceIndents[sourceIndex] : 0);
    }
    currentRows_ = std::move(visibleRows);
    currentRowIndents_ = std::move(visibleIndents);
    syncResultListVirtualRows();

    if (!currentRows_.empty()) {
        ListView_SetItemState(resultList_, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(resultList_, 0, FALSE);
        updateSelectedRowDetail();
    } else {
        ::SetWindowTextW(detailEdit_,
            descriptor != nullptr ? emptyDetailTextForFeature(descriptor->id) : L"");
    }
}

void KernelPage::rebuildKernelHookListFromCache(const KernelFeatureId featureId) {
    // rebuildKernelHookListFromCache mirrors the original SSDT/SSSDT/Inline
    // Hook/IAT-EAT tables. Inputs are cached raw rows from KernelFacade plus
    // local filter controls; processing projects only the original visible
    // columns while preserving hidden protocol/detail cells for actions; output
    // is the ListView, detail pane, and status text.
    if (!resultList_ || !isKernelHookFeature(featureId)) {
        return;
    }

    const std::vector<std::wstring>& rawColumns = !currentRawColumns_.empty() ? currentRawColumns_ : currentColumns_;
    const std::vector<std::vector<std::wstring>>& rawRows = !currentRawRows_.empty() ? currentRawRows_ : currentRows_;
    const std::wstring kFilterText = windowText(filterEdit_);
    const std::wstring kModuleFilterText = windowText(moduleFilterEdit_);
    const auto kRawValue = [&](const std::vector<std::wstring>& row, std::initializer_list<const wchar_t*> names) -> std::wstring {
        return rowFieldByName(row, rawColumns, names);
    };
    const auto kAddColumnIfMissing = [](std::vector<std::wstring>& columns, const wchar_t* name) {
        if (!hasColumn(columns, name)) {
            columns.push_back(name);
        }
    };
    const auto kDisplayValue = [&](const std::vector<std::wstring>& row, const std::wstring& columnName) -> std::wstring {
        std::vector<std::wstring> aliases = columnAliases(featureId, columnName);
        if (aliases.empty()) {
            aliases.push_back(columnName);
        }
        for (const std::wstring& alias : aliases) {
            const std::wstring kValue = kRawValue(row, { alias.c_str() });
            if (!kValue.empty()) {
                return kValue;
            }
        }
        return {};
    };
    const auto kIsMeaningful = [&](const std::vector<std::wstring>& row) {
        switch (featureId) {
        case KernelFeatureId::kSsdt:
        case KernelFeatureId::kShadowSsdt:
            return hasNonEmptyField(row, rawColumns, { L"Index", L"Name", L"ServiceName", L"Zw", L"Stub", L"Service", L"ServiceAddress" });
        case KernelFeatureId::kInlineHook:
            return hasNonEmptyField(row, rawColumns, { L"Module", L"Function", L"Address", L"Target", L"CurrentBytes", L"DiskBytes" });
        case KernelFeatureId::kIatEatHook:
            return hasNonEmptyField(row, rawColumns, { L"ClassText", L"Class", L"Module", L"Import", L"Function", L"Thunk", L"Current", L"Expected" });
        default:
            return false;
        }
    };
    const auto kHiddenColumn = [&](const std::wstring& name) {
        if (hasColumn(canonicalColumnNames(featureId), name)) {
            return false;
        }
        return true;
    };

    std::vector<std::wstring> displayColumns;
    for (const std::wstring& column : canonicalColumnNames(featureId)) {
        kAddColumnIfMissing(displayColumns, column.c_str());
    }
    for (const std::wstring& column : rawColumns) {
        kAddColumnIfMissing(displayColumns, column.c_str());
    }
    kAddColumnIfMissing(displayColumns, L"Detail");

    std::vector<std::vector<std::wstring>> displayRows;
    std::size_t totalRows = 0;
    std::size_t unresolvedRows = 0;
    std::size_t suspiciousRows = 0;
    std::size_t cleanRows = 0;
    std::size_t diskDiffRows = 0;
    std::size_t reportedTotalRows = 0;
    std::size_t reportedReturnedRows = 0;
    for (const std::vector<std::wstring>& rawRow : rawRows) {
        const std::uint64_t kRawTotal = firstNonZeroField(rawRow, rawColumns, { L"Total" });
        const std::uint64_t kRawReturned = firstNonZeroField(rawRow, rawColumns, { L"Returned" });
        if (kRawTotal != 0) {
            reportedTotalRows = static_cast<std::size_t>(kRawTotal);
        }
        if (kRawReturned != 0) {
            reportedReturnedRows = static_cast<std::size_t>(kRawReturned);
        }
        if (!kIsMeaningful(rawRow)) {
            continue;
        }
        ++totalRows;

        std::vector<std::wstring> cells(displayColumns.size());
        for (std::size_t column = 0; column < displayColumns.size(); ++column) {
            const std::wstring& name = displayColumns[column];
            if (name == L"Detail") {
                cells[column] = kRawValue(rawRow, { L"Detail", L"FlagsText", L"DiskDiff", L"Status" });
            } else {
                cells[column] = kDisplayValue(rawRow, name);
            }
        }

        const std::wstring kMerged = mergeRowText(cells) + L" | " + kRawValue(rawRow, { L"Detail" });
        if (!kFilterText.empty() && !containsCaseInsensitive(kMerged, kFilterText)) {
            continue;
        }
        if ((featureId == KernelFeatureId::kInlineHook || featureId == KernelFeatureId::kIatEatHook) && !kModuleFilterText.empty()) {
            const std::wstring kModuleText =
                rowFieldByName(cells, displayColumns, { L"模块", L"Module" }) + L" | " +
                rowFieldByName(cells, displayColumns, { L"目标模块", L"TargetModule" }) + L" | " +
                rowFieldByName(cells, displayColumns, { L"导入模块", L"Import", L"ImportModule" });
            if (!containsCaseInsensitive(kModuleText, kModuleFilterText)) {
                continue;
            }
        }

        const std::wstring kStatus = rowFieldByName(cells, displayColumns, { L"状态", L"Status" });
        const std::wstring kDiff = rowFieldByName(cells, displayColumns, { L"差异状态", L"差异", L"DiskDiff" });
        if (containsCaseInsensitive(kStatus, L"未解析") ||
            containsCaseInsensitive(kStatus, L"unresolved") ||
            rowFieldByName(cells, displayColumns, { L"索引", L"Index" }) == L"<未知>") {
            ++unresolvedRows;
        }
        if (containsCaseInsensitive(kStatus, L"Hook") ||
            containsCaseInsensitive(kStatus, L"可疑") ||
            containsCaseInsensitive(kStatus, L"异常") ||
            containsCaseInsensitive(kStatus, L"outside") ||
            containsCaseInsensitive(kDiff, L"不同") ||
            containsCaseInsensitive(kDiff, L"diff")) {
            ++suspiciousRows;
        } else if (!kStatus.empty()) {
            ++cleanRows;
        }
        if (containsCaseInsensitive(kDiff, L"不同") || containsCaseInsensitive(kDiff, L"diff")) {
            ++diskDiffRows;
        }
        displayRows.push_back(std::move(cells));
    }

    currentColumns_ = std::move(displayColumns);
    currentRows_ = std::move(displayRows);
    clearResultTable();
    for (std::size_t index = 0; index < currentColumns_.size(); ++index) {
        int width = kHiddenColumn(currentColumns_[index]) ? 0 : columnWidth(currentColumns_[index]);
        if (currentColumns_[index] == L"索引") {
            width = 90;
        } else if (currentColumns_[index] == L"服务名" || currentColumns_[index] == L"函数") {
            width = 260;
        } else if (currentColumns_[index] == L"Zw导出地址" ||
            currentColumns_[index] == L"Stub地址" ||
            currentColumns_[index] == L"表项地址" ||
            currentColumns_[index] == L"服务例程" ||
            currentColumns_[index] == L"函数地址" ||
            currentColumns_[index] == L"目标地址" ||
            currentColumns_[index] == L"Thunk/EAT项" ||
            currentColumns_[index] == L"当前目标" ||
            currentColumns_[index] == L"期望目标") {
            width = 170;
        } else if (currentColumns_[index] == L"模块" ||
            currentColumns_[index] == L"导入模块" ||
            currentColumns_[index] == L"目标模块") {
            width = 190;
        } else if (currentColumns_[index] == L"内存字节" ||
            currentColumns_[index] == L"磁盘字节") {
            width = 240;
        } else if (currentColumns_[index] == L"差异状态" ||
            currentColumns_[index] == L"状态") {
            width = 180;
        }
        addResultTableColumn(static_cast<int>(index), currentColumns_[index], width);
    }
    syncResultListVirtualRows();

    std::wostringstream status;
    switch (featureId) {
    case KernelFeatureId::kSsdt:
        status << L"状态：已刷新 " << totalRows << L" 项，显示 " << currentRows_.size()
               << L" 项，未解析索引 " << unresolvedRows << L" 项";
        break;
    case KernelFeatureId::kShadowSsdt:
        status << L"状态：已解析 "
               << (reportedReturnedRows == 0 ? totalRows : reportedReturnedRows)
               << L"/"
               << (reportedTotalRows == 0 ? totalRows : reportedTotalRows)
               << L" 项，显示 " << currentRows_.size()
               << L" 项，未解析索引 " << unresolvedRows << L" 项";
        break;
    case KernelFeatureId::kInlineHook:
        status << L"状态：Inline Hook 扫描完成，显示 " << currentRows_.size()
               << L" / " << totalRows << L" 项，可疑/差异 " << suspiciousRows
               << L" 项，磁盘差异 " << diskDiffRows << L" 项";
        break;
    case KernelFeatureId::kIatEatHook:
        status << L"状态：IAT/EAT 扫描完成，显示 " << currentRows_.size()
               << L" / " << totalRows << L" 项，可疑 " << suspiciousRows
               << L" 项，干净 " << cleanRows << L" 项";
        break;
    default:
        break;
    }
    if (!kFilterText.empty()) {
        status << L"，过滤=" << kFilterText;
    }
    if (!kModuleFilterText.empty() && (featureId == KernelFeatureId::kInlineHook || featureId == KernelFeatureId::kIatEatHook)) {
        status << L"，模块过滤=" << kModuleFilterText;
    }
    ::SetWindowTextW(statusText_, status.str().c_str());

    if (!currentRows_.empty()) {
        ListView_SetItemState(resultList_, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(resultList_, 0, FALSE);
        updateSelectedRowDetail();
    } else {
        ::SetWindowTextW(detailEdit_, emptyDetailTextForFeature(featureId));
    }
}

void KernelPage::rebuildObjectNamespaceListFromCache(const KernelFeatureId featureId) {
    // rebuildObjectNamespaceListFromCache reshapes generic KernelFacade rows
    // into the original KernelDock object-namespace tree/table schemas. Inputs
    // are currentColumns_/currentRows_ from addDynamicResultRow; processing adds
    // root rows, tree indentation, original headers and hidden action fields;
    // there is no return value because the ListView owns the visible output.
    const std::vector<std::wstring>& rawColumns = !currentRawColumns_.empty() ? currentRawColumns_ : currentColumns_;
    const std::vector<std::vector<std::wstring>>& rawRows = !currentRawRows_.empty() ? currentRawRows_ : currentRows_;
    std::vector<std::wstring> displayColumns;
    for (const std::wstring& column : canonicalColumnNames(featureId)) {
        if (!hasColumn(displayColumns, column)) {
            displayColumns.push_back(column);
        }
    }
    const auto kAddHiddenColumn = [&](const wchar_t* name) {
        if (!hasColumn(displayColumns, name)) {
            displayColumns.push_back(name);
        }
    };
    kAddHiddenColumn(L"Parent");
    kAddHiddenColumn(L"Source");
    kAddHiddenColumn(L"Directory");
    kAddHiddenColumn(L"directoryPath");
    kAddHiddenColumn(L"sourceDirectory");
    kAddHiddenColumn(L"Depth");
    kAddHiddenColumn(L"Path");
    kAddHiddenColumn(L"NtPath");
    kAddHiddenColumn(L"Target");
    kAddHiddenColumn(L"Win32Path");
    kAddHiddenColumn(L"dosCandidate");
    kAddHiddenColumn(L"fullPath");
    kAddHiddenColumn(L"targetPath");
    kAddHiddenColumn(L"symbolicTarget");
    kAddHiddenColumn(L"objectName");
    kAddHiddenColumn(L"objectType");
    kAddHiddenColumn(L"linkName");
    kAddHiddenColumn(L"Handles");
    kAddHiddenColumn(L"Pointers");
    kAddHiddenColumn(L"Detail");
    kAddHiddenColumn(L"EnumApi");
    kAddHiddenColumn(L"enumApi");
    kAddHiddenColumn(L"枚举 API");
    kAddHiddenColumn(L"EnumerationApi");
    kAddHiddenColumn(L"NodeKind");

    const auto kRawValue = [&](const std::vector<std::wstring>& row, std::initializer_list<const wchar_t*> names) -> std::wstring {
        return rowFieldByName(row, rawColumns, names);
    };
    const auto kDisplayValue = [&](const std::vector<std::wstring>& row, const std::wstring& columnName) -> std::wstring {
        if (columnName == L"Detail") {
            return kRawValue(row, { L"Detail" });
        }
        std::vector<std::wstring> aliases = columnAliases(featureId, columnName);
        if (aliases.empty()) {
            aliases.push_back(columnName);
        }
        for (const std::wstring& alias : aliases) {
            const std::wstring kValue = rowFieldByName(row, rawColumns, { alias.c_str() });
            if (!kValue.empty()) {
                return kValue;
            }
        }
        return {};
    };
    if (featureId == KernelFeatureId::kDeviceDriverObjects && deviceDriverDirectoryCombo_ && deviceDriverTypeCombo_) {
        std::set<std::wstring> types;
        for (const std::vector<std::wstring>& rawRow : rawRows) {
            const std::wstring kType = kRawValue(rawRow, { L"Type", L"objectType", L"对象类型", L"类型" });
            if (!kType.empty()) {
                types.insert(kType);
            }
        }
        const std::wstring kPreviousDirectory = [this]() -> std::wstring {
            const int kSelection = static_cast<int>(::SendMessageW(deviceDriverDirectoryCombo_, CB_GETCURSEL, 0, 0));
            if (kSelection <= 0) {
                return {};
            }
            wchar_t buffer[512]{};
            ::SendMessageW(deviceDriverDirectoryCombo_, CB_GETLBTEXT, static_cast<WPARAM>(kSelection), reinterpret_cast<LPARAM>(buffer));
            return buffer;
        }();
        const std::wstring kPreviousType = [this]() -> std::wstring {
            const int kSelection = static_cast<int>(::SendMessageW(deviceDriverTypeCombo_, CB_GETCURSEL, 0, 0));
            if (kSelection <= 0) {
                return {};
            }
            wchar_t buffer[512]{};
            ::SendMessageW(deviceDriverTypeCombo_, CB_GETLBTEXT, static_cast<WPARAM>(kSelection), reinterpret_cast<LPARAM>(buffer));
            return buffer;
        }();

        ::SendMessageW(deviceDriverDirectoryCombo_, CB_RESETCONTENT, 0, 0);
        ::SendMessageW(deviceDriverDirectoryCombo_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"全部目录"));
        int restoredDirectory = 0;
        for (const wchar_t* directory : kDeviceDriverFixedDirectories) {
            const int kIndex = static_cast<int>(::SendMessageW(deviceDriverDirectoryCombo_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(directory)));
            if (!kPreviousDirectory.empty() && _wcsicmp(kPreviousDirectory.c_str(), directory) == 0) {
                restoredDirectory = kIndex;
            }
        }
        ::SendMessageW(deviceDriverDirectoryCombo_, CB_SETCURSEL, restoredDirectory, 0);

        ::SendMessageW(deviceDriverTypeCombo_, CB_RESETCONTENT, 0, 0);
        ::SendMessageW(deviceDriverTypeCombo_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"全部类型"));
        int restoredType = 0;
        for (const std::wstring& type : types) {
            const int kIndex = static_cast<int>(::SendMessageW(deviceDriverTypeCombo_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(type.c_str())));
            if (!kPreviousType.empty() && _wcsicmp(kPreviousType.c_str(), type.c_str()) == 0) {
                restoredType = kIndex;
            }
        }
        ::SendMessageW(deviceDriverTypeCombo_, CB_SETCURSEL, restoredType, 0);
    }
    if (featureId == KernelFeatureId::kBaseNamedObjects && baseNamedScopeCombo_ && baseNamedTypeCombo_) {
        std::set<std::wstring> scopes;
        std::set<std::wstring> types;
        for (const std::vector<std::wstring>& rawRow : rawRows) {
            const std::wstring kScope = kRawValue(rawRow, { L"Source", L"Scope", L"scope" });
            const std::wstring kType = kRawValue(rawRow, { L"Type", L"objectType", L"类型" });
            if (!kScope.empty()) {
                scopes.insert(kScope);
            }
            if (!kType.empty()) {
                types.insert(kType);
            }
        }
        const std::wstring kPreviousScope = [this]() -> std::wstring {
            const int kSelection = static_cast<int>(::SendMessageW(baseNamedScopeCombo_, CB_GETCURSEL, 0, 0));
            if (kSelection <= 0) {
                return {};
            }
            wchar_t buffer[512]{};
            ::SendMessageW(baseNamedScopeCombo_, CB_GETLBTEXT, static_cast<WPARAM>(kSelection), reinterpret_cast<LPARAM>(buffer));
            return buffer;
        }();
        const std::wstring kPreviousType = [this]() -> std::wstring {
            const int kSelection = static_cast<int>(::SendMessageW(baseNamedTypeCombo_, CB_GETCURSEL, 0, 0));
            if (kSelection <= 0) {
                return {};
            }
            wchar_t buffer[512]{};
            ::SendMessageW(baseNamedTypeCombo_, CB_GETLBTEXT, static_cast<WPARAM>(kSelection), reinterpret_cast<LPARAM>(buffer));
            return buffer;
        }();
        ::SendMessageW(baseNamedScopeCombo_, CB_RESETCONTENT, 0, 0);
        ::SendMessageW(baseNamedScopeCombo_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"全部 Session"));
        int restoredScope = 0;
        for (const std::wstring& scope : scopes) {
            const int kIndex = static_cast<int>(::SendMessageW(baseNamedScopeCombo_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(scope.c_str())));
            if (!kPreviousScope.empty() && _wcsicmp(kPreviousScope.c_str(), scope.c_str()) == 0) {
                restoredScope = kIndex;
            }
        }
        ::SendMessageW(baseNamedScopeCombo_, CB_SETCURSEL, restoredScope, 0);
        ::SendMessageW(baseNamedTypeCombo_, CB_RESETCONTENT, 0, 0);
        ::SendMessageW(baseNamedTypeCombo_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"全部类型"));
        int restoredType = 0;
        for (const std::wstring& type : types) {
            const int kIndex = static_cast<int>(::SendMessageW(baseNamedTypeCombo_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(type.c_str())));
            if (!kPreviousType.empty() && _wcsicmp(kPreviousType.c_str(), type.c_str()) == 0) {
                restoredType = kIndex;
            }
        }
        ::SendMessageW(baseNamedTypeCombo_, CB_SETCURSEL, restoredType, 0);
    }
    const auto kRowMatchesObjectFilters = [&](const std::vector<std::wstring>& row) -> bool {
        const std::wstring kPrimaryFilter = windowText(filterEdit_);
        const std::wstring kSecondaryFilter = windowText(moduleFilterEdit_);
        if (featureId == KernelFeatureId::kObjectNamespaceOverview) {
            const std::wstring kMerged = kRawValue(row, { L"Parent", L"Source" }) + L" | " +
                kRawValue(row, { L"Name" }) + L" | " +
                kRawValue(row, { L"Type" }) + L" | " +
                kRawValue(row, { L"Path" }) + L" | " +
                kRawValue(row, { L"Status" }) + L" | " +
                kRawValue(row, { L"Target" });
            return kPrimaryFilter.empty() || containsCaseInsensitive(kMerged, kPrimaryFilter);
        }
        if (featureId == KernelFeatureId::kObjectDirectoryRecursive) {
            return true;
        }
        if (featureId == KernelFeatureId::kBaseNamedObjects) {
            std::wstring scopeFilter;
            std::wstring typeFilter;
            if (baseNamedScopeCombo_) {
                const int kSelection = static_cast<int>(::SendMessageW(baseNamedScopeCombo_, CB_GETCURSEL, 0, 0));
                if (kSelection > 0) {
                    wchar_t buffer[512]{};
                    ::SendMessageW(baseNamedScopeCombo_, CB_GETLBTEXT, static_cast<WPARAM>(kSelection), reinterpret_cast<LPARAM>(buffer));
                    scopeFilter = buffer;
                }
            }
            if (baseNamedTypeCombo_) {
                const int kSelection = static_cast<int>(::SendMessageW(baseNamedTypeCombo_, CB_GETCURSEL, 0, 0));
                if (kSelection > 0) {
                    wchar_t buffer[512]{};
                    ::SendMessageW(baseNamedTypeCombo_, CB_GETLBTEXT, static_cast<WPARAM>(kSelection), reinterpret_cast<LPARAM>(buffer));
                    typeFilter = buffer;
                }
            }
            const std::wstring kMerged = kRawValue(row, { L"Source", L"Scope" }) + L" | " +
                kRawValue(row, { L"Parent", L"Directory" }) + L" | " +
                kRawValue(row, { L"Name" }) + L" | " +
                kRawValue(row, { L"Type" }) + L" | " +
                kRawValue(row, { L"Path" }) + L" | " +
                kRawValue(row, { L"Target" }) + L" | " +
                kRawValue(row, { L"Status" });
            const bool kKeywordMatched = kPrimaryFilter.empty() || containsCaseInsensitive(kMerged, kPrimaryFilter);
            const bool kScopeMatched = scopeFilter.empty() ||
                _wcsicmp(kRawValue(row, { L"Source", L"Scope", L"scope" }).c_str(), scopeFilter.c_str()) == 0;
            const bool kTypeMatched = typeFilter.empty() ||
                _wcsicmp(kRawValue(row, { L"Type", L"objectType" }).c_str(), typeFilter.c_str()) == 0;
            const bool kLegacyMatched = kSecondaryFilter.empty() ||
                containsCaseInsensitive(kRawValue(row, { L"Source", L"Scope" }), kSecondaryFilter) ||
                containsCaseInsensitive(kRawValue(row, { L"Type" }), kSecondaryFilter);
            const bool kAuxMatched = kScopeMatched && kTypeMatched && kLegacyMatched;
            return kKeywordMatched && kAuxMatched;
        }
        if (featureId == KernelFeatureId::kNamedPipe) {
            const std::wstring kMerged = kRawValue(row, { L"Pipe", L"Name" }) + L" | " +
                kRawValue(row, { L"NtPath", L"Path" }) + L" | " +
                kRawValue(row, { L"Attributes" }) + L" | " +
                kRawValue(row, { L"LastWrite" }) + L" | " +
                kRawValue(row, { L"Status" }) + L" | " +
                kRawValue(row, { L"Directory", L"Source" });
            return kPrimaryFilter.empty() || containsCaseInsensitive(kMerged, kPrimaryFilter);
        }
        if (featureId == KernelFeatureId::kObjectTypeMatrix) {
            const std::wstring kMerged = kRawValue(row, { L"TypeIndex", L"Index" }) + L" | " +
                kRawValue(row, { L"Type" }) + L" | " +
                kRawValue(row, { L"Objects" }) + L" | " +
                kRawValue(row, { L"Handles" }) + L" | " +
                kRawValue(row, { L"ValidAccess" }) + L" | " +
                kRawValue(row, { L"Detail", L"Status" });
            return kPrimaryFilter.empty() || containsCaseInsensitive(kMerged, kPrimaryFilter);
        }
        if (featureId == KernelFeatureId::kCommunicationEndpoint) {
            const std::wstring kMerged = kRawValue(row, { L"Source", L"Parent" }) + L" | " +
                kRawValue(row, { L"Name" }) + L" | " +
                kRawValue(row, { L"Type" }) + L" | " +
                kRawValue(row, { L"Path" }) + L" | " +
                kRawValue(row, { L"Status" });
            return kPrimaryFilter.empty() || containsCaseInsensitive(kMerged, kPrimaryFilter);
        }
        if (featureId != KernelFeatureId::kSymbolicLink &&
            featureId != KernelFeatureId::kDeviceDriverObjects) {
            return true;
        }
        if (featureId == KernelFeatureId::kSymbolicLink) {
            const std::wstring kMerged = kRawValue(row, { L"Source", L"Parent" }) + L" | " +
                kRawValue(row, { L"Name" }) + L" | " +
                kRawValue(row, { L"Path" }) + L" | " +
                kRawValue(row, { L"Status" }) + L" | " +
                kRawValue(row, { L"Target" }) + L" | " +
                kRawValue(row, { L"Win32Path", L"DosCandidates" });
            const bool kPrimaryMatched = kPrimaryFilter.empty() || containsCaseInsensitive(kMerged, kPrimaryFilter);
            const bool kSecondaryMatched = kSecondaryFilter.empty() ||
                containsCaseInsensitive(kRawValue(row, { L"Target" }), kSecondaryFilter) ||
                containsCaseInsensitive(kRawValue(row, { L"Win32Path", L"DosCandidates" }), kSecondaryFilter);
            return kPrimaryMatched && kSecondaryMatched;
        }
        if (featureId == KernelFeatureId::kDeviceDriverObjects) {
            std::wstring directoryFilter;
            std::wstring typeFilter;
            if (deviceDriverDirectoryCombo_) {
                const int kSelection = static_cast<int>(::SendMessageW(deviceDriverDirectoryCombo_, CB_GETCURSEL, 0, 0));
                if (kSelection > 0) {
                    wchar_t buffer[512]{};
                    ::SendMessageW(deviceDriverDirectoryCombo_, CB_GETLBTEXT, static_cast<WPARAM>(kSelection), reinterpret_cast<LPARAM>(buffer));
                    directoryFilter = buffer;
                }
            }
            if (deviceDriverTypeCombo_) {
                const int kSelection = static_cast<int>(::SendMessageW(deviceDriverTypeCombo_, CB_GETCURSEL, 0, 0));
                if (kSelection > 0) {
                    wchar_t buffer[512]{};
                    ::SendMessageW(deviceDriverTypeCombo_, CB_GETLBTEXT, static_cast<WPARAM>(kSelection), reinterpret_cast<LPARAM>(buffer));
                    typeFilter = buffer;
                }
            }
            const std::wstring kDirectory = kRawValue(row, { L"Parent", L"Directory", L"Source", L"directoryPath", L"目录路径" });
            const std::wstring kType = kRawValue(row, { L"Type", L"objectType", L"对象类型", L"类型" });
            const std::wstring kKeywordMerged = kDirectory + L" | " +
                kRawValue(row, { L"Name", L"DriverName", L"objectName", L"对象名称" }) + L" | " +
                kType + L" | " +
                kRawValue(row, { L"Path", L"NtPath", L"fullPath", L"完整路径" }) + L" | " +
                kRawValue(row, { L"Target", L"targetPath", L"symbolicTarget", L"目标路径" }) + L" | " +
                kRawValue(row, { L"Status", L"statusText", L"状态" }) + L" | " +
                kRawValue(row, { L"Detail", L"Capability", L"capabilityHintText", L"能力提示" });
            const bool kKeywordMatched = kPrimaryFilter.empty() || containsCaseInsensitive(kKeywordMerged, kPrimaryFilter);
            const bool kDirectoryMatched = directoryFilter.empty() || _wcsicmp(kDirectory.c_str(), directoryFilter.c_str()) == 0;
            const bool kTypeMatched = typeFilter.empty() || _wcsicmp(kType.c_str(), typeFilter.c_str()) == 0;
            return kKeywordMatched && kDirectoryMatched && kTypeMatched;
        }
        return true;
    };
    const auto kDepthOf = [&](const std::vector<std::wstring>& row) -> int {
        const std::wstring kText = kRawValue(row, { L"Depth", L"深度" });
        if (kText.empty()) {
            return 0;
        }
        wchar_t* end = nullptr;
        const long kValue = std::wcstol(kText.c_str(), &end, 10);
        return end != kText.c_str() && kValue > 0 ? static_cast<int>(std::min<long>(kValue, 16)) : 0;
    };
    std::vector<std::vector<std::wstring>> displayRows;
    std::vector<int> displayIndents;
    std::vector<std::wstring> insertedRoots;
    std::vector<std::wstring> insertedDirectories;
    std::size_t meaningfulRowCount = 0;
    const auto kAppendDisplayRow = [&](std::vector<std::wstring> cells, const int indent) {
        if (!cells.empty() && !displayColumns.empty() && displayColumns[0] == L"#") {
            cells[0] = std::to_wstring(displayRows.size());
        }
        displayRows.push_back(std::move(cells));
        displayIndents.push_back(std::max(0, indent));
    };
    const auto kMakeEmptyCells = [&]() {
        return std::vector<std::wstring>(displayColumns.size());
    };
    const auto kAppendOverviewRoot = [&](const std::wstring& root, const std::wstring& status) {
        if (root.empty()) {
            return;
        }
        const auto kDuplicate = std::find_if(insertedRoots.begin(), insertedRoots.end(), [&](const std::wstring& existing) {
            return _wcsicmp(existing.c_str(), root.c_str()) == 0;
        });
        if (kDuplicate != insertedRoots.end()) {
            return;
        }
        insertedRoots.push_back(root);
        std::vector<std::wstring> cells = kMakeEmptyCells();
        for (std::size_t column = 0; column < displayColumns.size(); ++column) {
            const std::wstring& name = displayColumns[column];
            if (name == L"名称") cells[column] = root;
            else if (name == L"类型") cells[column] = L"根目录";
            else if (name == L"路径/说明") cells[column] = status.empty() ? root : status;
            else if (name == L"状态") cells[column] = L"根节点";
            else if (name == L"Parent" || name == L"Source" || name == L"Path") cells[column] = root;
            else if (name == L"Depth") cells[column] = L"0";
            else if (name == L"NodeKind") cells[column] = L"Root";
            else if (name == L"Detail") cells[column] = L"Object Manager root: " + root;
        }
        kAppendDisplayRow(std::move(cells), 0);
    };
    const auto kAppendOverviewDirectory = [&](const std::wstring& root, const std::wstring& directory, const std::wstring& scope) {
        // appendOverviewDirectory reproduces the original middle tree level:
        // each root owns one row per enumerated directory, and object rows sit
        // under that directory. Inputs are root/scope/directory text from the
        // facade row; processing de-duplicates the pair; no value is returned.
        if (directory.empty()) {
            return;
        }
        const std::wstring kKey = root + L"\n" + directory;
        const auto kDuplicate = std::find_if(insertedDirectories.begin(), insertedDirectories.end(), [&](const std::wstring& existing) {
            return _wcsicmp(existing.c_str(), kKey.c_str()) == 0;
        });
        if (kDuplicate != insertedDirectories.end()) {
            return;
        }
        insertedDirectories.push_back(kKey);
        std::vector<std::wstring> cells = kMakeEmptyCells();
        for (std::size_t column = 0; column < displayColumns.size(); ++column) {
            const std::wstring& name = displayColumns[column];
            if (name == L"名称") cells[column] = leafObjectName(directory);
            else if (name == L"类型") cells[column] = L"目录";
            else if (name == L"路径/说明") cells[column] = directory;
            else if (name == L"状态") cells[column] = L"已展开枚举";
            else if (name == L"Parent" || name == L"Source") cells[column] = root;
            else if (name == L"Directory" || name == L"directoryPath" || name == L"Path" || name == L"fullPath") cells[column] = directory;
            else if (name == L"Depth") cells[column] = L"1";
            else if (name == L"NodeKind") cells[column] = L"Directory";
            else if (name == L"Detail") cells[column] = scope.empty()
                ? (L"Object Manager directory: " + directory)
                : (L"Object Manager directory: " + directory + L"\r\n" + scope);
        }
        kAppendDisplayRow(std::move(cells), 1);
    };
    if (featureId == KernelFeatureId::kObjectDirectoryRecursive) {
        std::wstring rootPath = windowText(filterEdit_);
        if (rootPath.empty()) {
            rootPath = L"\\";
        }
        std::vector<std::wstring> cells = kMakeEmptyCells();
        for (std::size_t column = 0; column < displayColumns.size(); ++column) {
            const std::wstring& name = displayColumns[column];
            if (name == L"名称") cells[column] = leafObjectName(rootPath);
            else if (name == L"类型") cells[column] = L"Directory";
            else if (name == L"完整路径" || name == L"Path") cells[column] = rootPath;
            else if (name == L"深度" || name == L"Depth") cells[column] = L"0";
            else if (name == L"状态") cells[column] = L"根目录";
            else if (name == L"Parent" || name == L"Source") cells[column] = parentObjectPath(rootPath).empty() ? rootPath : parentObjectPath(rootPath);
            else if (name == L"Detail") cells[column] = L"Object Manager recursive root: " + rootPath;
        }
        kAppendDisplayRow(std::move(cells), 0);
    }

    for (const std::vector<std::wstring>& rawRow : rawRows) {
        const bool kMeaningful =
            hasNonEmptyField(rawRow, rawColumns, { L"Name", L"Path", L"NtPath", L"Pipe", L"TypeIndex", L"Type" }) ||
            hasNonEmptyField(rawRow, rawColumns, { L"Parent", L"Source", L"Directory", L"Target" });
        if (!kMeaningful) {
            continue;
        }
        ++meaningfulRowCount;
        const std::wstring kParent = kRawValue(rawRow, { L"Parent", L"Directory", L"sourceDirectory", L"来源目录", L"目录路径" });
        const std::wstring kSource = kRawValue(rawRow, { L"Source", L"scope" });
        const std::wstring kPath = kRawValue(rawRow, { L"Path", L"NtPath", L"fullPath", L"完整路径" });
        const std::wstring kObjectName = kRawValue(rawRow, { L"Name", L"Pipe", L"objectName", L"linkName", L"名称", L"对象名称", L"Type" });
        const std::wstring kObjectType = kRawValue(rawRow, { L"Type", L"objectType", L"类型", L"对象类型" });
        const bool kIsQueryHeader = !hasNonEmptyField(rawRow, rawColumns, { L"Name", L"Pipe", L"objectName", L"linkName", L"TypeIndex" }) &&
            hasNonEmptyField(rawRow, rawColumns, { L"功能", L"数据源", L"Rows", L"Warnings" });
        if (kIsQueryHeader) {
            continue;
        }
        if (!kRowMatchesObjectFilters(rawRow)) {
            continue;
        }

        if (featureId == KernelFeatureId::kObjectNamespaceOverview) {
            const std::wstring kDirectory = !kParent.empty() ? kParent : (!kRawValue(rawRow, { L"directoryPathText", L"directoryPath", L"Directory" }).empty()
                ? kRawValue(rawRow, { L"directoryPathText", L"directoryPath", L"Directory" })
                : parentObjectPath(kPath));
            const std::wstring kRoot = !kSource.empty() ? kSource : (!kRawValue(rawRow, { L"rootPathText", L"Root" }).empty()
                ? kRawValue(rawRow, { L"rootPathText", L"Root" })
                : (!kDirectory.empty() ? kDirectory : kPath));
            const std::wstring kScope = kRawValue(rawRow, { L"scopeDescriptionText", L"Scope", L"scope", L"Detail" });
            if (windowText(filterEdit_).empty() ||
                containsCaseInsensitive(kRoot, windowText(filterEdit_)) ||
                containsCaseInsensitive(kDirectory, windowText(filterEdit_)) ||
                containsCaseInsensitive(kScope, windowText(filterEdit_)) ||
                containsCaseInsensitive(kPath, windowText(filterEdit_)) ||
                containsCaseInsensitive(kObjectName, windowText(filterEdit_)) ||
                containsCaseInsensitive(kObjectType, windowText(filterEdit_)) ||
                containsCaseInsensitive(kRawValue(rawRow, { L"Status" }), windowText(filterEdit_)) ||
                containsCaseInsensitive(kRawValue(rawRow, { L"Target" }), windowText(filterEdit_))) {
                kAppendOverviewRoot(kRoot, kScope);
                kAppendOverviewDirectory(kRoot, kDirectory, kScope);
            }
            if (kObjectName.empty() && kObjectType.empty() && kParent.empty()) {
                continue;
            }
        }

        std::vector<std::wstring> cells = kMakeEmptyCells();
        int rowIndent = 0;
        if (featureId == KernelFeatureId::kObjectNamespaceOverview) {
            rowIndent = 2;
        } else if (featureId == KernelFeatureId::kObjectDirectoryRecursive) {
            rowIndent = kDepthOf(rawRow) + 1;
        }
        for (std::size_t column = 0; column < displayColumns.size(); ++column) {
            const std::wstring& name = displayColumns[column];
            if (name == L"#") {
                continue;
            }
            std::wstring value = kDisplayValue(rawRow, name);
            if (featureId == KernelFeatureId::kObjectNamespaceOverview && name == L"名称") {
                value = kObjectName.empty() ? kPath : kObjectName;
            } else if (featureId == KernelFeatureId::kObjectNamespaceOverview && name == L"类型" && value.empty()) {
                value = kObjectType.empty() ? L"<未知>" : kObjectType;
            } else if (featureId == KernelFeatureId::kObjectNamespaceOverview && name == L"路径/说明" && value.empty()) {
                value = kPath;
            } else if (featureId == KernelFeatureId::kObjectNamespaceOverview && name == L"NodeKind") {
                value = L"ObjectEntry";
            } else if (featureId == KernelFeatureId::kObjectDirectoryRecursive && name == L"名称") {
                value = kObjectName.empty() ? kPath : kObjectName;
            } else if (featureId == KernelFeatureId::kNamedPipe && name == L"Pipe Name" && value.empty()) {
                const std::wstring kNtPath = kRawValue(rawRow, { L"NtPath", L"Path" });
                const std::size_t kSlash = kNtPath.find_last_of(L'\\');
                value = kSlash == std::wstring::npos ? kNtPath : kNtPath.substr(kSlash + 1);
            } else if (featureId == KernelFeatureId::kDeviceDriverObjects && name == L"目标路径" && value.empty()) {
                value = L"<无>";
            } else if (name == L"Detail" && value.empty()) {
                value = kRawValue(rawRow, { L"Status", L"statusText", L"Target", L"symbolicTarget", L"targetPath" });
            }
            cells[column] = std::move(value);
        }
        kAppendDisplayRow(std::move(cells), rowIndent);
    }

    currentColumns_ = std::move(displayColumns);
    currentRows_ = std::move(displayRows);
    clearResultTable();
    for (std::size_t index = 0; index < currentColumns_.size(); ++index) {
        const std::wstring& columnName = currentColumns_[index];
        const bool kHidden = columnName == L"Parent" ||
            columnName == L"Source" ||
            columnName == L"Directory" ||
            columnName == L"directoryPath" ||
            columnName == L"sourceDirectory" ||
            columnName == L"Depth" ||
            columnName == L"Path" ||
            columnName == L"NtPath" ||
            columnName == L"Target" ||
            columnName == L"Win32Path" ||
            columnName == L"dosCandidate" ||
            columnName == L"fullPath" ||
            columnName == L"targetPath" ||
            columnName == L"symbolicTarget" ||
            columnName == L"objectName" ||
            columnName == L"objectType" ||
            columnName == L"linkName" ||
            columnName == L"Handles" ||
            columnName == L"Pointers" ||
            columnName == L"EnumApi" ||
            columnName == L"enumApi" ||
            columnName == L"枚举 API" ||
            columnName == L"EnumerationApi" ||
            columnName == L"NodeKind" ||
            columnName == L"Detail";
        int width = kHidden ? 0 : columnWidth(columnName);
        if (featureId == KernelFeatureId::kDeviceDriverObjects) {
            if (columnName == L"目录路径") width = 190;
            else if (columnName == L"对象名称") width = 180;
            else if (columnName == L"对象类型") width = 130;
            else if (columnName == L"完整路径") width = 320;
            else if (columnName == L"目标路径") width = 320;
            else if (columnName == L"状态") width = 260;
            else if (columnName == L"能力提示") width = 360;
        }
        addResultTableColumn(static_cast<int>(index), columnName, width);
    }
    currentRowIndents_ = std::move(displayIndents);
    syncResultListVirtualRows();
    if (featureId == KernelFeatureId::kObjectNamespaceOverview ||
        featureId == KernelFeatureId::kObjectDirectoryRecursive) {
        rebuildObjectNamespaceTreeFromCurrentRows();
    }
    std::wostringstream status;
    switch (featureId) {
    case KernelFeatureId::kObjectNamespaceOverview:
    {
        const std::wstring kKeyword = windowText(filterEdit_);
        status << L"状态：对象命名空间已刷新，显示 " << currentRows_.size()
               << L" / " << meaningfulRowCount << L" 项";
        if (!kKeyword.empty()) {
            status << L"，过滤=" << kKeyword;
        }
        break;
    }
    case KernelFeatureId::kObjectDirectoryRecursive:
    {
        std::size_t directoryCount = 0;
        std::size_t failedDirectoryCount = 0;
        bool depthLimitReached = false;
        for (const std::vector<std::wstring>& row : currentRows_) {
            const std::wstring kType = rowFieldByName(row, currentColumns_, { L"类型", L"Type", L"objectType" });
            const std::wstring kRowStatus = rowFieldByName(row, currentColumns_, { L"状态", L"Status", L"statusText" });
            if (_wcsicmp(kType.c_str(), L"Directory") == 0) {
                ++directoryCount;
                if (containsCaseInsensitive(kRowStatus, L"失败") ||
                    containsCaseInsensitive(kRowStatus, L"denied") ||
                    containsCaseInsensitive(kRowStatus, L"error") ||
                    containsCaseInsensitive(kRowStatus, L"0xC")) {
                    ++failedDirectoryCount;
                }
            }
            if (containsCaseInsensitive(kRowStatus, L"深度") ||
                containsCaseInsensitive(kRowStatus, L"depth")) {
                depthLimitReached = true;
            }
        }
        status << L"状态：已枚举 " << currentRows_.size()
               << L" 项，目录 " << directoryCount
               << L" 个，失败目录 " << failedDirectoryCount << L" 个";
        if (depthLimitReached) {
            status << L"，触达深度上限";
        }
        break;
    }
    case KernelFeatureId::kNamedPipe:
    {
        const std::wstring kKeyword = windowText(filterEdit_);
        status << L"状态：显示 " << currentRows_.size() << L" / " << meaningfulRowCount;
        if (!kKeyword.empty()) {
            status << L"，过滤=" << kKeyword;
        }
        break;
    }
    case KernelFeatureId::kBaseNamedObjects:
    {
        std::wstring scopeText = L"全部 Session";
        std::wstring typeText = L"全部类型";
        if (baseNamedScopeCombo_) {
            const int kSelection = static_cast<int>(::SendMessageW(baseNamedScopeCombo_, CB_GETCURSEL, 0, 0));
            if (kSelection >= 0) {
                wchar_t buffer[512]{};
                ::SendMessageW(baseNamedScopeCombo_, CB_GETLBTEXT, static_cast<WPARAM>(kSelection), reinterpret_cast<LPARAM>(buffer));
                if (buffer[0] != L'\0') {
                    scopeText = buffer;
                }
            }
        }
        if (baseNamedTypeCombo_) {
            const int kSelection = static_cast<int>(::SendMessageW(baseNamedTypeCombo_, CB_GETCURSEL, 0, 0));
            if (kSelection >= 0) {
                wchar_t buffer[512]{};
                ::SendMessageW(baseNamedTypeCombo_, CB_GETLBTEXT, static_cast<WPARAM>(kSelection), reinterpret_cast<LPARAM>(buffer));
                if (buffer[0] != L'\0') {
                    typeText = buffer;
                }
            }
        }
        const std::wstring kKeyword = windowText(filterEdit_);
        status << L"状态：BaseNamedObjects 已刷新，总数 " << meaningfulRowCount
               << L"，可见 " << currentRows_.size()
               << L"，scope=" << scopeText
               << L"，类型=" << typeText;
        if (!kKeyword.empty()) {
            status << L"，关键字=" << kKeyword;
        }
        break;
    }
    case KernelFeatureId::kSymbolicLink:
    {
        const std::wstring kKeyword = windowText(filterEdit_);
        const std::wstring kTargetKeyword = windowText(moduleFilterEdit_);
        status << L"状态：显示 " << currentRows_.size() << L" / " << meaningfulRowCount;
        if (!kKeyword.empty()) {
            status << L"，过滤=" << kKeyword;
        }
        if (!kTargetKeyword.empty()) {
            status << L"，目标过滤=" << kTargetKeyword;
        }
        break;
    }
    case KernelFeatureId::kDeviceDriverObjects:
    {
        const std::size_t kLoadedRows = meaningfulRowCount;
        const std::size_t kVisibleRows = currentRows_.size();
        if (kLoadedRows == 0) {
            status << L"状态：暂无结果，点击刷新开始枚举对象目录。";
        } else if (kVisibleRows == 0) {
            status << L"状态：已加载 " << kLoadedRows << L" 条，当前过滤后无可见结果。";
        } else {
            status << L"状态：已加载 " << kLoadedRows << L" 条，当前显示 " << kVisibleRows << L" 条。";
        }
        break;
    }
    case KernelFeatureId::kObjectTypeMatrix:
    {
        const std::wstring kKeyword = windowText(filterEdit_);
        status << L"状态：已加载 " << meaningfulRowCount << L" 类，显示 " << currentRows_.size() << L" 类";
        if (!kKeyword.empty()) {
            status << L"，过滤=" << kKeyword;
        }
        break;
    }
    case KernelFeatureId::kCommunicationEndpoint:
    {
        const std::wstring kKeyword = windowText(filterEdit_);
        status << L"状态：已加载 " << meaningfulRowCount << L" 项，显示 " << currentRows_.size() << L" 项";
        if (!kKeyword.empty()) {
            status << L"，过滤=" << kKeyword;
        }
        break;
    }
    default:
        status << L"状态：对象页已刷新，显示 " << currentRows_.size() << L" 项";
        break;
    }
    ::SetWindowTextW(statusText_, status.str().c_str());
    if (!currentRows_.empty()) {
        ListView_SetItemState(resultList_, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(resultList_, 0, FALSE);
        updateSelectedRowDetail();
    } else {
        ::SetWindowTextW(detailEdit_, emptyDetailTextForFeature(featureId));
    }
}

void KernelPage::rebuildObjectNamespaceTreeFromCurrentRows() {
    // rebuildObjectNamespaceTreeFromCurrentRows renders the original object
    // namespace overview as a three-level Win32 TreeView. Inputs are
    // currentRows_ and currentColumns_ already projected to the original
    // root/directory/object schema; processing creates stable node payloads in
    // objectNamespaceTreeNodeStorage_ and binds them to TVITEM::lParam; no value
    // is returned.
    if (!objectNamespaceTree_) {
        return;
    }
    TreeView_DeleteAllItems(objectNamespaceTree_);
    if (const KernelFeatureDescriptor* descriptor = currentDescriptor()) {
        objectNamespaceTreeFeatureId_ = descriptor->id;
        hasObjectNamespaceTreeFeatureId_ = true;
    }
    objectNamespaceTreeNodeStorage_.clear();

    std::unordered_map<std::wstring, HTREEITEM> rootItems;
    std::unordered_map<std::wstring, HTREEITEM> directoryItems;
    HTREEITEM firstItem = nullptr;
    HTREEITEM firstEntryItem = nullptr;
    const bool kExpandAll = !windowText(filterEdit_).empty();
    const auto kRowText = [&](const std::vector<std::wstring>& row, std::initializer_list<const wchar_t*> names) {
        return rowFieldByName(row, currentColumns_, names);
    };
    const auto kSafeText = [](const std::wstring& value, const wchar_t* fallback = L"<空>") -> std::wstring {
        return value.empty() ? std::wstring(fallback) : value;
    };
    const auto kRootFromPath = [](const std::wstring& path) -> std::wstring {
        if (path.empty()) {
            return L"\\";
        }
        if (path == L"\\") {
            return path;
        }
        const std::size_t kNextSlash = path.find(L'\\', 1);
        return kNextSlash == std::wstring::npos ? path : path.substr(0, kNextSlash);
    };
    const auto kMakeState = [&](const int rowIndex,
        std::wstring kind,
        std::wstring name,
        std::wstring type,
        std::wstring path,
        std::wstring description) -> KernelObjectNamespaceTreeNodeState* {
        auto state = std::make_unique<KernelObjectNamespaceTreeNodeState>();
        state->rowIndex = rowIndex;
        state->nodeKind = std::move(kind);
        state->nodeName = std::move(name);
        state->nodeType = std::move(type);
        state->nodePath = std::move(path);
        state->nodeDescription = std::move(description);
        KernelObjectNamespaceTreeNodeState* raw = state.get();
        objectNamespaceTreeNodeStorage_.push_back(std::move(state));
        return raw;
    };
    const auto kInsertTreeItem = [&](HTREEITEM parent,
        const std::wstring& text,
        KernelObjectNamespaceTreeNodeState* state) -> HTREEITEM {
        if (text.empty()) {
            return nullptr;
        }
        TVINSERTSTRUCTW insert{};
        insert.hParent = parent != nullptr ? parent : TVI_ROOT;
        insert.hInsertAfter = TVI_LAST;
        insert.item.mask = TVIF_TEXT | TVIF_PARAM;
        insert.item.pszText = const_cast<LPWSTR>(text.c_str());
        insert.item.lParam = reinterpret_cast<LPARAM>(state);
        return TreeView_InsertItem(objectNamespaceTree_, &insert);
    };

    const auto kEnsureRoot = [&](std::wstring rootPath, const std::wstring& description) -> HTREEITEM {
        if (rootPath.empty()) {
            rootPath = L"\\";
        }
        const std::wstring kKey = lowerInvariantKey(rootPath);
        if (const auto kFound = rootItems.find(kKey); kFound != rootItems.end()) {
            return kFound->second;
        }
        std::wstring text = rootPath + L"    [根目录]    " + kSafeText(description, L"<无>");
        KernelObjectNamespaceTreeNodeState* state = kMakeState(
            -1,
            L"Root",
            rootPath,
            L"根目录",
            rootPath,
            description);
        HTREEITEM item = kInsertTreeItem(nullptr, text, state);
        if (item != nullptr) {
            rootItems.emplace(kKey, item);
            if (firstItem == nullptr) {
                firstItem = item;
            }
            TreeView_Expand(objectNamespaceTree_, item, TVE_EXPAND);
        }
        return item;
    };
    const auto kEnsureDirectory = [&](std::wstring rootPath,
        std::wstring directoryPath,
        const std::wstring& description) -> HTREEITEM {
        if (directoryPath.empty()) {
            directoryPath = rootPath.empty() ? L"\\" : rootPath;
        }
        if (rootPath.empty() || rootPath[0] != L'\\') {
            rootPath = kRootFromPath(directoryPath);
        }
        HTREEITEM rootItem = kEnsureRoot(rootPath, description);
        const std::wstring kKey = lowerInvariantKey(rootPath + L"\n" + directoryPath);
        if (const auto kFound = directoryItems.find(kKey); kFound != directoryItems.end()) {
            return kFound->second;
        }
        std::wstring text = leafObjectName(directoryPath) + L"    [目录]    " + directoryPath;
        KernelObjectNamespaceTreeNodeState* state = kMakeState(
            -1,
            L"Directory",
            leafObjectName(directoryPath),
            L"目录",
            directoryPath,
            description);
        HTREEITEM item = kInsertTreeItem(rootItem, text, state);
        if (item != nullptr) {
            directoryItems.emplace(kKey, item);
            if (firstItem == nullptr) {
                firstItem = item;
            }
            if (rootItem != nullptr) {
                TreeView_Expand(objectNamespaceTree_, rootItem, TVE_EXPAND);
            }
            if (kExpandAll) {
                TreeView_Expand(objectNamespaceTree_, item, TVE_EXPAND);
            }
        }
        return item;
    };

    for (std::size_t rowIndex = 0; rowIndex < currentRows_.size(); ++rowIndex) {
        const std::vector<std::wstring>& row = currentRows_[rowIndex];
        std::wstring nodeKind = kRowText(row, { L"NodeKind" });
        const std::wstring kName = kRowText(row, { L"名称", L"Name", L"objectName" });
        const std::wstring kType = kRowText(row, { L"类型", L"Type", L"objectType" });
        const std::wstring kPath = kRowText(row, { L"Path", L"完整路径", L"fullPath", L"路径/说明" });
        const std::wstring kDirectory = kRowText(row, { L"Directory", L"directoryPath", L"Parent", L"sourceDirectory", L"来源目录" });
        std::wstring root = kRowText(row, { L"rootPathText", L"Root", L"Source" });
        const std::wstring kDescription = kRowText(row, { L"scopeDescriptionText", L"Scope", L"scope", L"Detail", L"路径/说明" });
        const std::wstring kStatus = kRowText(row, { L"状态", L"Status", L"statusText" });
        const std::wstring kTarget = kRowText(row, { L"符号链接目标", L"Target", L"symbolicTarget", L"targetPath" });
        if (kName.empty() && kPath.empty()) {
            continue;
        }

        if (nodeKind.empty()) {
            if (_wcsicmp(kType.c_str(), L"根目录") == 0 || _wcsicmp(kStatus.c_str(), L"根节点") == 0) {
                nodeKind = L"Root";
            } else if (_wcsicmp(kType.c_str(), L"目录") == 0 || _wcsicmp(kStatus.c_str(), L"已展开枚举") == 0) {
                nodeKind = L"Directory";
            } else {
                nodeKind = L"ObjectEntry";
            }
        }

        if (_wcsicmp(nodeKind.c_str(), L"Root") == 0) {
            kEnsureRoot(kPath.empty() ? kName : kPath, kDescription);
            continue;
        }
        if (_wcsicmp(nodeKind.c_str(), L"Directory") == 0) {
            const std::wstring kDirectoryPath = kPath.empty() ? kDirectory : kPath;
            if (root.empty() || root[0] != L'\\') {
                root = kRootFromPath(kDirectoryPath);
            }
            kEnsureDirectory(root, kDirectoryPath, kDescription);
            continue;
        }

        std::wstring directoryPath = !kDirectory.empty() ? kDirectory : parentObjectPath(kPath);
        if (root.empty() || root[0] != L'\\') {
            root = kRootFromPath(!directoryPath.empty() ? directoryPath : kPath);
        }
        HTREEITEM directoryItem = kEnsureDirectory(root, directoryPath, kDescription);
        std::wstring displayText = kSafeText(kName, L"<未命名对象>");
        displayText += L"    [" + kSafeText(kType) + L"]    " + kSafeText(kPath);
        if (!kTarget.empty() && kTarget != L"<无>") {
            displayText += L"    -> " + kTarget;
        } else if (!kStatus.empty()) {
            displayText += L"    " + kStatus;
        }
        KernelObjectNamespaceTreeNodeState* state = kMakeState(
            static_cast<int>(rowIndex),
            L"ObjectEntry",
            kName.empty() ? L"<未命名对象>" : kName,
            kType,
            kPath,
            kDescription);
        const HTREEITEM kItem = kInsertTreeItem(directoryItem, displayText, state);
        if (kItem == nullptr) {
            continue;
        }
        if (firstItem == nullptr) {
            firstItem = kItem;
        }
        if (firstEntryItem == nullptr) {
            firstEntryItem = kItem;
        }
        if (kExpandAll && directoryItem != nullptr) {
            TreeView_Expand(objectNamespaceTree_, directoryItem, TVE_EXPAND);
        }
    }

    if (firstEntryItem != nullptr) {
        TreeView_SelectItem(objectNamespaceTree_, firstEntryItem);
    } else if (firstItem != nullptr) {
        TreeView_SelectItem(objectNamespaceTree_, firstItem);
    }
}

void KernelPage::toggleObjectNamespaceListNode(const int rowIndex) {
    // toggleObjectNamespaceListNode provides the Win32 report-list equivalent
    // of double-clicking a tree widget object node. Input is the activated
    // visible row; processing uses object type/path cells to perform the most
    // useful original action: directories become the recursive root and symbolic
    // links are resolved again; there is no return value.
    const KernelFeatureDescriptor* descriptor = currentDescriptor();
    if (descriptor == nullptr || !isObjectNamespaceFeature(descriptor->id) ||
        rowIndex < 0 || rowIndex >= static_cast<int>(currentRows_.size())) {
        return;
    }

    ListView_SetItemState(resultList_, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    ListView_SetItemState(resultList_, rowIndex, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    updateSelectedRowDetail();

    const std::vector<std::wstring>& row = currentRows_[static_cast<std::size_t>(rowIndex)];
    const std::wstring kType = rowFieldByName(row, currentColumns_, { L"类型", L"Type", L"objectType", L"对象类型" });
    const std::wstring kPath = rowFieldByName(row, currentColumns_, { L"完整路径", L"Path", L"fullPath", L"路径/说明", L"NT Path", L"NtPath" });
    if (_wcsicmp(kType.c_str(), L"Directory") == 0 && !kPath.empty()) {
        ::SetWindowTextW(filterEdit_, kPath.c_str());
        ::SetWindowTextW(moduleFilterEdit_, L"4");
        for (std::size_t index = 0; index < primaryFeatureIds_.size(); ++index) {
            if (primaryFeatureIds_[index] == KernelFeatureId::kObjectNamespaceOverview && secondaryTab_) {
                for (int tab = 0; tab < static_cast<int>(objectNamespaceTabs().size()); ++tab) {
                    if (objectNamespaceTabs()[static_cast<std::size_t>(tab)].featureId == KernelFeatureId::kObjectDirectoryRecursive) {
                        ::SendMessageW(secondaryTab_, TCM_SETCURSEL, tab, 0);
                        selectCurrentFeature();
                        refreshSelectedFeature();
                        return;
                    }
                }
            }
        }
        refreshSelectedFeature();
        return;
    }
    if (_wcsicmp(kType.c_str(), L"SymbolicLink") == 0) {
        executeSelectedAction(KernelActionId::kNativeSymbolicLinkResolve);
        return;
    }
    executeSelectedAction(KernelActionId::kNativeObjectQueryDetail);
}

void KernelPage::selectObjectNamespaceTreeRow(const LPARAM rowIndex) {
    // selectObjectNamespaceTreeRow maps a TreeView selection back to the hidden
    // ListView row model. Input is the row index stored in TVITEM::lParam;
    // processing updates selection/focus so all copy/filter/detail code remains
    // shared; there is no return value.
    if (!resultList_) {
        return;
    }
    if (rowIndex < 0 || rowIndex >= static_cast<LPARAM>(currentRows_.size())) {
        ListView_SetItemState(resultList_, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
        ::SetWindowTextW(detailEdit_, L"这是为保持目录层级自动补出的父目录节点，当前没有可执行的结果行。");
        updatePropertyTableFromSelection();
        return;
    }
    const int kRow = static_cast<int>(rowIndex);
    ListView_SetItemState(resultList_, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    ListView_SetItemState(resultList_, kRow, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    updateSelectedRowDetail();
}

void KernelPage::selectObjectNamespaceTreeItem(const LPARAM itemData) {
    // selectObjectNamespaceTreeItem applies the original Qt tree-node selection
    // semantics. Input is a KernelObjectNamespaceTreeNodeState pointer stored in
    // TVITEM::lParam; processing either selects the backing result row or shows
    // synthetic root/directory node details; no value is returned.
    if (!resultList_ || !detailEdit_) {
        return;
    }
    const auto* state = reinterpret_cast<const KernelObjectNamespaceTreeNodeState*>(itemData);
    if (state == nullptr) {
        objectNamespaceSelectedRow_ = -1;
        objectNamespaceSelectedKind_ = L"";
        objectNamespaceSelectedPath_ = L"";
        objectNamespaceSelectedDescription_ = L"";
        ListView_SetItemState(resultList_, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
        ::SetWindowTextW(detailEdit_, L"请选择对象命名空间树节点查看详情。");
        updatePropertyTableFromSelection();
        return;
    }

    objectNamespaceSelectedRow_ = state->rowIndex;
    objectNamespaceSelectedKind_ = state->nodeKind;
    objectNamespaceSelectedPath_ = state->nodePath;
    objectNamespaceSelectedDescription_ = state->nodeDescription;
    if (state->rowIndex >= 0 && state->rowIndex < static_cast<int>(currentRows_.size())) {
        ListView_SetItemState(resultList_, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_SetItemState(resultList_, state->rowIndex, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(resultList_, state->rowIndex, FALSE);
        updateSelectedRowDetail();
        return;
    }

    ListView_SetItemState(resultList_, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    std::wostringstream detail;
    detail << L"当前节点名称: " << (state->nodeName.empty() ? L"<空>" : state->nodeName) << L"\r\n"
           << L"当前节点类型: " << (state->nodeType.empty() ? L"<空>" : state->nodeType) << L"\r\n"
           << L"当前节点路径: " << (state->nodePath.empty() ? L"<无>" : state->nodePath) << L"\r\n"
           << L"节点说明: " << (state->nodeDescription.empty() ? L"<无>" : state->nodeDescription) << L"\r\n\r\n"
           << L"提示: 请选择目录下具体对象项以查看完整对象字段。";
    ::SetWindowTextW(detailEdit_, detail.str().c_str());
    updatePropertyTableFromSelection();
}

void KernelPage::rebuildAtomTableFromCache() {
    // rebuildAtomTableFromCache mirrors the original KernelDock atom page. The
    // input is the unfiltered R3 Win32 atom snapshot cached by renderResult; the
    // processing projects the fixed Atom value/hex/name/source/status table and applies
    // the edit-box filter locally; the return behavior is direct ListView and
    // detail-pane updates with no extra driver/native calls.
    if (!resultList_) {
        return;
    }

    const std::vector<std::wstring>& rawColumns = !currentRawColumns_.empty() ? currentRawColumns_ : currentColumns_;
    const std::vector<std::vector<std::wstring>>& rawRows = !currentRawRows_.empty() ? currentRawRows_ : currentRows_;
    const std::wstring kFilterText = windowText(filterEdit_);
    const auto kRawValue = [&](const std::vector<std::wstring>& row, std::initializer_list<const wchar_t*> names) -> std::wstring {
        return rowFieldByName(row, rawColumns, names);
    };
    const auto kDisplayValue = [&](const std::vector<std::wstring>& row, const std::wstring& columnName) -> std::wstring {
        std::vector<std::wstring> aliases = columnAliases(KernelFeatureId::kAtomTable, columnName);
        if (aliases.empty()) {
            aliases.push_back(columnName);
        }
        for (const std::wstring& alias : aliases) {
            const std::wstring kValue = kRawValue(row, { alias.c_str() });
            if (!kValue.empty()) {
                return kValue;
            }
        }
        return {};
    };

    std::vector<std::wstring> displayColumns{ L"#" };
    for (const std::wstring& column : canonicalColumnNames(KernelFeatureId::kAtomTable)) {
        if (!hasColumn(displayColumns, column)) {
            displayColumns.push_back(column);
        }
    }
    const wchar_t* hiddenColumns[] = {
        L"Id", L"Hex", L"Name", L"Source", L"Kind", L"GlobalName", L"ClipboardName", L"Length", L"Detail"
    };
    for (const wchar_t* column : hiddenColumns) {
        if (!hasColumn(displayColumns, column)) {
            displayColumns.push_back(column);
        }
    }

    std::vector<std::vector<std::wstring>> displayRows;
    std::size_t totalRows = 0;
    for (const std::vector<std::wstring>& rawRow : rawRows) {
        const bool kAtomRow = hasNonEmptyField(rawRow, rawColumns, { L"Id", L"Name", L"Source", L"Kind" });
        if (!kAtomRow) {
            continue;
        }
        ++totalRows;
        if (!kFilterText.empty() && !containsCaseInsensitive(mergeRowText(rawRow), kFilterText)) {
            continue;
        }

        std::vector<std::wstring> cells(displayColumns.size());
        for (std::size_t column = 0; column < displayColumns.size(); ++column) {
            const std::wstring& name = displayColumns[column];
            if (name == L"#") {
                cells[column] = std::to_wstring(displayRows.size());
            } else if (name == L"Detail") {
                cells[column] = kRawValue(rawRow, { L"Detail" });
            } else {
                cells[column] = kDisplayValue(rawRow, name);
            }
        }
        displayRows.push_back(std::move(cells));
    }

    currentColumns_ = std::move(displayColumns);
    currentRows_ = std::move(displayRows);
    currentRowIndents_.clear();
    clearResultTable();
    const std::vector<std::wstring> kCanonical = canonicalColumnNames(KernelFeatureId::kAtomTable);
    for (std::size_t index = 0; index < currentColumns_.size(); ++index) {
        const std::wstring& name = currentColumns_[index];
        const bool kHidden = name == L"#" ? false : !hasColumn(kCanonical, name);
        int width = kHidden ? 0 : columnWidth(name);
        if (name == L"Atom值" || name == L"十六进制") {
            width = 110;
        } else if (name == L"名称") {
            width = 360;
        } else if (name == L"来源") {
            width = 220;
        } else if (name == L"状态") {
            width = 160;
        }
        addResultTableColumn(static_cast<int>(index), name, width);
    }
    syncResultListVirtualRows();

    std::wostringstream status;
    status << L"状态：原子表已刷新，返回 " << currentRows_.size() << L"/" << totalRows;
    ::SetWindowTextW(statusText_, status.str().c_str());
    if (!currentRows_.empty()) {
        ListView_SetItemState(resultList_, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(resultList_, 0, FALSE);
        updateSelectedRowDetail();
    } else {
        ::SetWindowTextW(detailEdit_, totalRows == 0 ? L"尚未返回原子记录。" : L"当前过滤条件下没有原子记录。");
    }
}

void KernelPage::rebuildNtQueryLegacyListFromCache() {
    // rebuildNtQueryLegacyListFromCache mirrors the original 'Historical NtQuery' page.
    // Inputs are the cached safe NtQuery probe rows; processing keeps the fixed
    // Category/function/query item/status/summary table with hidden diagnostics for details; the
    // output is the refreshed ListView and detail pane only.
    if (!resultList_) {
        return;
    }

    const std::vector<std::wstring>& rawColumns = !currentRawColumns_.empty() ? currentRawColumns_ : currentColumns_;
    const std::vector<std::vector<std::wstring>>& rawRows = !currentRawRows_.empty() ? currentRawRows_ : currentRows_;
    const auto kRawValue = [&](const std::vector<std::wstring>& row, std::initializer_list<const wchar_t*> names) -> std::wstring {
        return rowFieldByName(row, rawColumns, names);
    };
    const auto kDisplayValue = [&](const std::vector<std::wstring>& row, const std::wstring& columnName) -> std::wstring {
        std::vector<std::wstring> aliases = columnAliases(KernelFeatureId::kNtQueryLegacy, columnName);
        if (aliases.empty()) {
            aliases.push_back(columnName);
        }
        for (const std::wstring& alias : aliases) {
            const std::wstring kValue = kRawValue(row, { alias.c_str() });
            if (!kValue.empty()) {
                return kValue;
            }
        }
        return {};
    };

    std::vector<std::wstring> displayColumns{ L"#" };
    for (const std::wstring& column : canonicalColumnNames(KernelFeatureId::kNtQueryLegacy)) {
        if (!hasColumn(displayColumns, column)) {
            displayColumns.push_back(column);
        }
    }
    const wchar_t* hiddenColumns[] = {
        L"Category", L"Function", L"Class", L"InfoClass", L"Status", L"Success", L"Bytes", L"Ordinal", L"RVA", L"Detail"
    };
    for (const wchar_t* column : hiddenColumns) {
        if (!hasColumn(displayColumns, column)) {
            displayColumns.push_back(column);
        }
    }

    std::vector<std::vector<std::wstring>> displayRows;
    std::size_t successRows = 0;
    for (const std::vector<std::wstring>& rawRow : rawRows) {
        const bool kNtQueryRow = hasNonEmptyField(rawRow, rawColumns, { L"Category", L"Function", L"Class", L"Ordinal", L"RVA" });
        if (!kNtQueryRow) {
            continue;
        }
        if (kRawValue(rawRow, { L"Success" }) == L"true" ||
            containsCaseInsensitive(kRawValue(rawRow, { L"Status" }), L"Exported") ||
            kRawValue(rawRow, { L"Status" }) == L"0x0") {
            ++successRows;
        }
        std::vector<std::wstring> cells(displayColumns.size());
        for (std::size_t column = 0; column < displayColumns.size(); ++column) {
            const std::wstring& name = displayColumns[column];
            if (name == L"#") {
                cells[column] = std::to_wstring(displayRows.size());
            } else if (name == L"Detail") {
                cells[column] = kRawValue(rawRow, { L"Detail" });
            } else {
                cells[column] = kDisplayValue(rawRow, name);
            }
        }
        displayRows.push_back(std::move(cells));
    }

    currentColumns_ = std::move(displayColumns);
    currentRows_ = std::move(displayRows);
    currentRowIndents_.clear();
    clearResultTable();
    const std::vector<std::wstring> kCanonical = canonicalColumnNames(KernelFeatureId::kNtQueryLegacy);
    for (std::size_t index = 0; index < currentColumns_.size(); ++index) {
        const std::wstring& name = currentColumns_[index];
        const bool kHidden = name == L"#" ? false : !hasColumn(kCanonical, name);
        int width = kHidden ? 0 : columnWidth(name);
        if (name == L"类别") {
            width = 110;
        } else if (name == L"函数") {
            width = 230;
        } else if (name == L"查询项") {
            width = 110;
        } else if (name == L"状态") {
            width = 130;
        } else if (name == L"摘要") {
            width = 360;
        }
        addResultTableColumn(static_cast<int>(index), name, width);
    }
    syncResultListVirtualRows();

    std::wostringstream status;
    status << L"状态：已刷新 " << currentRows_.size() << L" 项，成功 " << successRows << L" 项";
    ::SetWindowTextW(statusText_, status.str().c_str());
    if (!currentRows_.empty()) {
        ListView_SetItemState(resultList_, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(resultList_, 0, FALSE);
        updateSelectedRowDetail();
    } else {
        ::SetWindowTextW(detailEdit_, L"无可展示的 NtQuery 结果。");
    }
}

void KernelPage::rebuildDiagnosticDualTableFromCache(const KernelFeatureId featureId) {
    // rebuildDiagnosticDualTableFromCache reshapes DynData and DriverStatus
    // result packets into the original KernelDock dual-table layout. Inputs are
    // raw ArkDriverClient rows and the local filter text; processing builds the
    // original summary labels, visible matrix rows, and status sentence; output
    // updates the summary table, result table, detail editor, and status label.
    if (!resultList_ || !summaryList_) {
        return;
    }

    const std::vector<std::wstring>& rawColumns = !currentRawColumns_.empty() ? currentRawColumns_ : currentColumns_;
    const std::vector<std::vector<std::wstring>>& rawRows = !currentRawRows_.empty() ? currentRawRows_ : currentRows_;
    const std::wstring kFilterText = windowText(filterEdit_);
    const auto kRawValue = [&](const std::vector<std::wstring>& row, std::initializer_list<const wchar_t*> names) -> std::wstring {
        return rowFieldByName(row, rawColumns, names);
    };
    const auto kFirstValue = [&](std::initializer_list<const wchar_t*> names) -> std::wstring {
        return firstRowValue(rawRows, rawColumns, names);
    };
    const auto kFirstNumber = [&](std::initializer_list<const wchar_t*> names, const std::uint64_t fallback = 0) -> std::uint64_t {
        return firstRowUInt64(rawRows, rawColumns, names, fallback);
    };
    const auto kAppendSummary = [&](const std::wstring& name, const std::wstring& value) {
        if (!name.empty() && !value.empty()) {
            listViewInsertRow(summaryList_, { name, value });
        }
    };
    const auto kAppendSummaryBool = [&](const std::wstring& name, const bool value) {
        listViewInsertRow(summaryList_, { name, boolText(value) });
    };
    const auto kAddHiddenColumn = [](std::vector<std::wstring>& columns, const wchar_t* name) {
        if (!hasColumn(columns, name)) {
            columns.push_back(name);
        }
    };
    const auto kDisplayValue = [&](const std::vector<std::wstring>& row, const std::wstring& columnName) -> std::wstring {
        std::vector<std::wstring> aliases = columnAliases(featureId, columnName);
        if (aliases.empty()) {
            aliases.push_back(columnName);
        }
        for (const std::wstring& alias : aliases) {
            const std::wstring kValue = kRawValue(row, { alias.c_str() });
            if (!kValue.empty()) {
                return kValue;
            }
        }
        if (columnName == L"Capability") {
            return kRawValue(row, { L"Mask", L"CapabilityMask" });
        }
        if (columnName == L"策略") {
            return kRawValue(row, { L"Policy", L"RequiredPolicy", L"Flags", L"SecurityPolicy" });
        }
        if (columnName == L"依赖字段") {
            return kRawValue(row, { L"Dependency", L"DependencyText" });
        }
        if (columnName == L"原因") {
            return kRawValue(row, { L"Reason", L"Detail", L"LastError" });
        }
        return {};
    };

    clearResultTable();
    ListView_DeleteAllItems(summaryList_);

    std::vector<std::wstring> displayColumns;
    for (const std::wstring& column : canonicalColumnNames(featureId)) {
        if (!hasColumn(displayColumns, column)) {
            displayColumns.push_back(column);
        }
    }
    kAddHiddenColumn(displayColumns, L"Id");
    kAddHiddenColumn(displayColumns, L"StateId");
    kAddHiddenColumn(displayColumns, L"StatusFlags");
    kAddHiddenColumn(displayColumns, L"CapabilityMask");
    kAddHiddenColumn(displayColumns, L"Version");
    kAddHiddenColumn(displayColumns, L"Protocol");
    kAddHiddenColumn(displayColumns, L"ExpectedProtocol");
    kAddHiddenColumn(displayColumns, L"SecurityPolicy");
    kAddHiddenColumn(displayColumns, L"DynDataStatus");
    kAddHiddenColumn(displayColumns, L"DynDataCapability");
    kAddHiddenColumn(displayColumns, L"FeatureTotal");
    kAddHiddenColumn(displayColumns, L"FeatureReturned");
    kAddHiddenColumn(displayColumns, L"LastError");
    kAddHiddenColumn(displayColumns, L"LastErrorSummary");
        kAddHiddenColumn(displayColumns, L"LastErrorStatus");
        kAddHiddenColumn(displayColumns, L"Flags");
        kAddHiddenColumn(displayColumns, L"StatusQueryOk");
        kAddHiddenColumn(displayColumns, L"FieldsQueryOk");
        kAddHiddenColumn(displayColumns, L"PdbProfileScanAttempted");
        kAddHiddenColumn(displayColumns, L"PdbProfileFound");
        kAddHiddenColumn(displayColumns, L"PdbProfileApplied");
        kAddHiddenColumn(displayColumns, L"PdbProfileSource");
        kAddHiddenColumn(displayColumns, L"PdbProfileName");
        kAddHiddenColumn(displayColumns, L"PdbProfilePath");
        kAddHiddenColumn(displayColumns, L"PdbProfileStatus");
        kAddHiddenColumn(displayColumns, L"PdbProfileAppliedFields");
        kAddHiddenColumn(displayColumns, L"PdbProfileRejectedFields");
        kAddHiddenColumn(displayColumns, L"PdbProfileUnknownFields");
        kAddHiddenColumn(displayColumns, L"PdbProfileIgnoredJsonFields");
        kAddHiddenColumn(displayColumns, L"PdbProfileMessage");
        kAddHiddenColumn(displayColumns, L"PdbProfileIo");
        kAddHiddenColumn(displayColumns, L"MatchedProfileOffset");
        kAddHiddenColumn(displayColumns, L"MatchedFieldsId");
        kAddHiddenColumn(displayColumns, L"RequiredPolicy");
        kAddHiddenColumn(displayColumns, L"DeniedPolicy");
        kAddHiddenColumn(displayColumns, L"StatusBadges");
        kAddHiddenColumn(displayColumns, L"DynDataStatusQueryOk");
        kAddHiddenColumn(displayColumns, L"DynDataFieldsQueryOk");
        kAddHiddenColumn(displayColumns, L"DynDataStatusIo");
        kAddHiddenColumn(displayColumns, L"DynDataFieldsIo");
        kAddHiddenColumn(displayColumns, L"FieldCoverage");
        kAddHiddenColumn(displayColumns, L"FieldSources");
        kAddHiddenColumn(displayColumns, L"RequiredMissing");
        kAddHiddenColumn(displayColumns, L"NtosIdentity");
        kAddHiddenColumn(displayColumns, L"LxcoreIdentity");
        kAddHiddenColumn(displayColumns, L"LocalPdbProfileMatched");
        kAddHiddenColumn(displayColumns, L"LocalPdbProfile");
        kAddHiddenColumn(displayColumns, L"LocalPdbProfileName");
        kAddHiddenColumn(displayColumns, L"LocalPdbProfilePath");
        kAddHiddenColumn(displayColumns, L"LocalPdbMessage");
        kAddHiddenColumn(displayColumns, L"LocalPdbVersion");
        kAddHiddenColumn(displayColumns, L"ActiveProcessLinksOffset");
        kAddHiddenColumn(displayColumns, L"CallbackProfileCoverage");
        kAddHiddenColumn(displayColumns, L"PdbProfileActive");
        kAddHiddenColumn(displayColumns, L"CallbackProfileActive");
        kAddHiddenColumn(displayColumns, L"TrustedPdbOffsetsActive");
        kAddHiddenColumn(displayColumns, L"TrustedOffset");
        kAddHiddenColumn(displayColumns, L"UnavailableReason");
        kAddHiddenColumn(displayColumns, L"Detail");

    std::vector<std::vector<std::wstring>> displayRows;
    std::size_t profileRows = 0;
    std::size_t failedRows = 0;
    std::size_t missingRequiredRows = 0;
    std::size_t unavailableRows = 0;
    std::size_t dynDataDependentRows = 0;
    for (const std::vector<std::wstring>& rawRow : rawRows) {
        const bool kIsDynField = featureId == KernelFeatureId::kDynData &&
            hasNonEmptyField(rawRow, rawColumns, { L"Field", L"字段", L"Offset", L"Source", L"Feature", L"Mask" }) &&
            !kRawValue(rawRow, { L"Field", L"字段" }).empty();
        const bool kIsDriverFeature = featureId == KernelFeatureId::kDriverStatus &&
            hasNonEmptyField(rawRow, rawColumns, { L"Feature", L"功能", L"State", L"RequiredDyn", L"PresentDyn" }) &&
            !kRawValue(rawRow, { L"Feature", L"功能" }).empty();
        const std::wstring kMerged = mergeRowText(rawRow);
        if (featureId == KernelFeatureId::kDynData) {
            const std::wstring kSource = kRawValue(rawRow, { L"Source", L"来源" });
            const std::wstring kStatus = kRawValue(rawRow, { L"Status", L"状态", L"DynData Fields IO" });
            if (containsCaseInsensitive(kSource, L"profile") || containsCaseInsensitive(kSource, L"pack") ||
                containsCaseInsensitive(kSource, L"pdb")) {
                ++profileRows;
            }
            if (containsCaseInsensitive(kStatus, L"fail") || containsCaseInsensitive(kStatus, L"失败") ||
                containsCaseInsensitive(kStatus, L"missing") || containsCaseInsensitive(kStatus, L"缺失")) {
                ++failedRows;
            }
            if (kIsDynField && containsCaseInsensitive(kStatus, L"缺失(必需)")) {
                ++missingRequiredRows;
            }
        } else if (featureId == KernelFeatureId::kDriverStatus) {
            const std::wstring kState = kRawValue(rawRow, { L"State", L"状态", L"Status" });
            const std::wstring kRequiredDyn = kRawValue(rawRow, { L"RequiredDyn", L"所需DynData" });
            if (containsCaseInsensitive(kState, L"unavailable") || containsCaseInsensitive(kState, L"disabled") ||
                containsCaseInsensitive(kState, L"denied") || containsCaseInsensitive(kState, L"不可用") ||
                containsCaseInsensitive(kState, L"禁用")) {
                ++unavailableRows;
            }
            if (!isZeroMaskText(kRequiredDyn)) {
                ++dynDataDependentRows;
            }
        }
        if (!kIsDynField && !kIsDriverFeature) {
            continue;
        }
        if (!kFilterText.empty() && !containsCaseInsensitive(kMerged, kFilterText)) {
            continue;
        }

        std::vector<std::wstring> cells(displayColumns.size());
        for (std::size_t column = 0; column < displayColumns.size(); ++column) {
            const std::wstring& name = displayColumns[column];
            if (name == L"Detail") {
                cells[column] = kRawValue(rawRow, { L"Detail" });
            } else {
                cells[column] = kDisplayValue(rawRow, name);
            }
        }
        displayRows.push_back(std::move(cells));
    }

    if (featureId == KernelFeatureId::kDynData) {
        const std::uint64_t kStatusFlags = kFirstNumber({ L"StatusFlags" });
        const bool kInitialized = flagEnabled(kStatusFlags, KSW_DYN_STATUS_FLAG_INITIALIZED);
        const bool kNtosActive = flagEnabled(kStatusFlags, KSW_DYN_STATUS_FLAG_NTOS_ACTIVE);
        const bool kLxcoreActive = flagEnabled(kStatusFlags, KSW_DYN_STATUS_FLAG_LXCORE_ACTIVE);
        const bool kExtraActive = flagEnabled(kStatusFlags, KSW_DYN_STATUS_FLAG_EXTRA_ACTIVE);
        const bool kPdbActive = flagEnabled(kStatusFlags, KSW_DYN_STATUS_FLAG_PDB_PROFILE_ACTIVE);
        const bool kCallbackActive = flagEnabled(kStatusFlags, KSW_DYN_STATUS_FLAG_CALLBACK_PROFILE_ACTIVE);
        kAppendSummaryBool(L"DynData 初始化", kInitialized);
        kAppendSummaryBool(L"ntoskrnl profile", kNtosActive);
        kAppendSummaryBool(L"lxcore profile", kLxcoreActive);
        kAppendSummaryBool(L"Ksword runtime offset", kExtraActive);
        kAppendSummaryBool(L"PDB profile active", kPdbActive);
        kAppendSummaryBool(L"PDB profile 扫描", kFirstValue({ L"PdbProfileScanAttempted" }) == L"是");
        kAppendSummaryBool(L"PDB profile 命中", kFirstValue({ L"PdbProfileFound" }) == L"是");
        kAppendSummaryBool(L"PDB profile 本次应用", kFirstValue({ L"PdbProfileApplied" }) == L"是");
        kAppendSummary(L"PDB profile 来源", kFirstValue({ L"PdbProfileSource" }));
        kAppendSummary(L"PDB profile 名称", kFirstValue({ L"PdbProfileName" }));
        kAppendSummary(L"PDB profile 路径", kFirstValue({ L"PdbProfilePath" }));
        kAppendSummary(L"PDB profile 状态", kFirstValue({ L"PdbProfileStatus" }));
        kAppendSummary(L"PDB profile 字段", L"applied=" + kFirstValue({ L"PdbProfileAppliedFields" }) +
            L" rejected=" + kFirstValue({ L"PdbProfileRejectedFields" }) +
            L" unknown=" + kFirstValue({ L"PdbProfileUnknownFields" }) +
            L" ignoredJson=" + kFirstValue({ L"PdbProfileIgnoredJsonFields" }));
        kAppendSummary(L"PDB profile 消息", kFirstValue({ L"PdbProfileMessage" }));
        kAppendSummary(L"PDB profile IO", kFirstValue({ L"PdbProfileIo" }));
        kAppendSummaryBool(L"Callback profile active", kCallbackActive);
        kAppendSummary(L"状态位", kFirstValue({ L"StatusFlags" }));
        kAppendSummary(L"System Informer 版本", kFirstValue({ L"SI Version" }));
        kAppendSummary(L"System Informer 数据长度", kFirstValue({ L"SI Length" }));
        kAppendSummary(L"MatchedProfileClass", kFirstValue({ L"MatchedClass", L"ProfileClass" }));
        kAppendSummary(L"MatchedProfileOffset", kFirstValue({ L"MatchedProfileOffset" }));
        kAppendSummary(L"MatchedFieldsId", kFirstValue({ L"MatchedFieldsId" }));
        kAppendSummary(L"CapabilityMask", kFirstValue({ L"CapabilityMask", L"Mask" }));
        kAppendSummary(L"字段总数/当前返回", kFirstValue({ L"FieldCount", L"FieldsTotal" }) + L" / " + std::to_wstring(displayRows.size()));
        kAppendSummary(L"Fields IO", kFirstValue({ L"DynData Fields IO" }));
        kAppendSummary(L"ntoskrnl", kFirstValue({ L"Ntos", L"NtosIdentity" }));
        kAppendSummary(L"lxcore", kFirstValue({ L"Lxcore", L"LxcoreIdentity" }));
        kAppendSummary(L"Profile/Pack 诊断行", std::to_wstring(profileRows));
        kAppendSummary(L"失败诊断行", std::to_wstring(failedRows));

        std::wstring statusLine = std::wstring(L"状态：") +
            (kNtosActive ? L"ntos profile 已命中" : L"ntos profile 未命中") +
            (kPdbActive ? L"，PDB profile 已启用" : L"") +
            L"，字段 " + std::to_wstring(displayRows.size()) +
            L" 项，缺失必需 " + std::to_wstring(missingRequiredRows) + L" 项";
        ::SetWindowTextW(statusText_, statusLine.c_str());
    } else {
        const std::uint64_t kStatusFlags = kFirstNumber({ L"StatusFlags" });
        const bool kDriverLoaded = flagEnabled(kStatusFlags, KSWORD_ARK_DRIVER_STATUS_FLAG_DRIVER_LOADED);
        const bool kProtocolOk = flagEnabled(kStatusFlags, KSWORD_ARK_DRIVER_STATUS_FLAG_PROTOCOL_OK);
        const bool kDynDataMissing = flagEnabled(kStatusFlags, KSWORD_ARK_DRIVER_STATUS_FLAG_DYNDATA_MISSING);
        const bool kLimited = flagEnabled(kStatusFlags, KSWORD_ARK_DRIVER_STATUS_FLAG_LIMITED);
        const std::wstring kBadges = kFirstValue({ L"StatusBadges" }).empty()
            ? (std::wstring(L"Driver Loaded=") + boolText(kDriverLoaded) +
                L"；Protocol OK=" + boolText(kProtocolOk) +
                L"；DynData Missing=" + boolText(kDynDataMissing) +
                L"；Limited=" + boolText(kLimited))
            : kFirstValue({ L"StatusBadges" });
        const std::wstring kDynStatus = kFirstValue({ L"DynDataStatus" });
        const std::wstring kDynCapability = kFirstValue({ L"DynDataCapability", L"CapabilityMask" });
        const std::wstring kTrustedOffset = !kFirstValue({ L"TrustedOffset" }).empty()
            ? kFirstValue({ L"TrustedOffset" })
            : (!kDynCapability.empty() && kDynCapability != L"0x0"
                ? std::wstring(L"已存在 DynData capability ") + kDynCapability
                : std::wstring(L"暂无可用可信偏移。"));
        kAppendSummary(L"状态栏", kBadges);
        kAppendSummaryBool(L"Driver Loaded", kDriverLoaded);
        kAppendSummaryBool(L"Protocol OK", kProtocolOk);
        kAppendSummaryBool(L"DynData Missing", kDynDataMissing);
        kAppendSummaryBool(L"Limited", kLimited);
        kAppendSummary(L"当前内核", kFirstValue({ L"NtosIdentity", L"Ntos" }));
        kAppendSummary(L"识别版本", kFirstValue({ L"LocalPdbVersion", L"KernelVersion" }));
        kAppendSummary(L"本地 PDB profile", kFirstValue({ L"LocalPdbProfile", L"LocalPdbMessage" }));
        kAppendSummary(L"ActiveProcessLinks 偏移", kFirstValue({ L"ActiveProcessLinksOffset" }));
        kAppendSummary(L"Callback profile 覆盖", kFirstValue({ L"CallbackProfileCoverage" }));
        kAppendSummary(L"可信偏移", kTrustedOffset);
        kAppendSummary(L"字段覆盖", kFirstValue({ L"FieldCoverage" }));
        kAppendSummary(L"字段来源", kFirstValue({ L"FieldSources" }));
        kAppendSummary(L"缺失必需字段", kFirstValue({ L"RequiredMissing" }));
        kAppendSummary(L"能力协议版本", kFirstValue({ L"Version" }));
        kAppendSummary(L"驱动协议版本", kFirstValue({ L"Protocol" }));
        kAppendSummary(L"期望协议版本", kFirstValue({ L"ExpectedProtocol" }));
        kAppendSummary(L"状态位", kFirstValue({ L"StatusFlags" }));
        kAppendSummary(L"安全策略位", kFirstValue({ L"SecurityPolicy", L"Policy", L"策略" }));
        kAppendSummary(L"DynData 状态位", kDynStatus);
        kAppendSummary(L"DynData 能力位", kDynCapability);
        kAppendSummary(L"System Informer 数据", L"version=" + kFirstValue({ L"SI Version" }) + L" length=" + kFirstValue({ L"SI Length" }));
        kAppendSummary(L"匹配内置 Profile", L"class=" + kFirstValue({ L"MatchedClass" }) +
            L" offset=" + kFirstValue({ L"MatchedProfileOffset" }) +
            L" fieldsId=" + kFirstValue({ L"MatchedFieldsId" }));
        kAppendSummary(L"DynData R3 IO", L"Status=" + kFirstValue({ L"DynDataStatusQueryOk" }) +
            L" (" + kFirstValue({ L"DynDataStatusIo" }) + L")；Fields=" +
            kFirstValue({ L"DynDataFieldsQueryOk" }) + L" (" + kFirstValue({ L"DynDataFieldsIo" }) + L")");
        kAppendSummary(L"DynData 不可用原因", kFirstValue({ L"UnavailableReason" }));
        kAppendSummary(L"功能数", L"显示 " + std::to_wstring(displayRows.size()) +
            L" / 返回 " + kFirstValue({ L"FeatureReturned" }) +
            L" / 总计 " + kFirstValue({ L"FeatureTotal" }));
        kAppendSummary(L"最近错误", kFirstValue({ L"LastErrorStatus" }) + L" / " +
            kFirstValue({ L"LastError" }) + L" / " + kFirstValue({ L"LastErrorSummary" }));
        kAppendSummary(L"R3 IO", kFirstValue({ L"IoMessage", L"Driver Capabilities" }));
        kAppendSummary(L"不可用/禁用行", std::to_wstring(unavailableRows));
        kAppendSummary(L"DynData 依赖行", std::to_wstring(dynDataDependentRows));

        const bool kDriverQueryFailed = rawRows.empty() || (!kDriverLoaded && !kProtocolOk && kFirstValue({ L"Version" }).empty());
        if (kDriverQueryFailed && kDynStatus.empty()) {
            ::SetWindowTextW(statusText_, L"状态：驱动与 DynData 查询均失败");
        } else {
            const std::wstring kKernelText = kFirstValue({ L"NtosIdentity", L"Ntos" }).empty() ? L"内核未识别" : kFirstValue({ L"NtosIdentity", L"Ntos" });
            const std::wstring kStatusLine = L"状态：" + kBadges + L"；" + kKernelText + L"；功能 " +
                std::to_wstring(displayRows.size()) + L" 项；可信偏移 " + kTrustedOffset;
            ::SetWindowTextW(statusText_, kStatusLine.c_str());
        }
    }

    currentColumns_ = std::move(displayColumns);
    currentRows_ = std::move(displayRows);
    currentRowIndents_.clear();
    for (std::size_t index = 0; index < currentColumns_.size(); ++index) {
        const bool kHidden = currentColumns_[index] == L"Id" ||
            currentColumns_[index] == L"StateId" ||
            currentColumns_[index] == L"StatusFlags" ||
            currentColumns_[index] == L"CapabilityMask" ||
            currentColumns_[index] == L"Version" ||
            currentColumns_[index] == L"Protocol" ||
            currentColumns_[index] == L"ExpectedProtocol" ||
            currentColumns_[index] == L"SecurityPolicy" ||
            currentColumns_[index] == L"DynDataStatus" ||
            currentColumns_[index] == L"DynDataCapability" ||
            currentColumns_[index] == L"FeatureTotal" ||
            currentColumns_[index] == L"FeatureReturned" ||
            currentColumns_[index] == L"LastError" ||
            currentColumns_[index] == L"LastErrorSummary" ||
            currentColumns_[index] == L"LastErrorStatus" ||
            currentColumns_[index] == L"Flags" ||
            currentColumns_[index] == L"StatusQueryOk" ||
            currentColumns_[index] == L"FieldsQueryOk" ||
            currentColumns_[index].find(L"PdbProfile") == 0 ||
            currentColumns_[index] == L"MatchedProfileOffset" ||
            currentColumns_[index] == L"MatchedFieldsId" ||
            currentColumns_[index] == L"RequiredPolicy" ||
            currentColumns_[index] == L"DeniedPolicy" ||
            currentColumns_[index] == L"StatusBadges" ||
            currentColumns_[index] == L"DynDataStatusQueryOk" ||
            currentColumns_[index] == L"DynDataFieldsQueryOk" ||
            currentColumns_[index] == L"DynDataStatusIo" ||
            currentColumns_[index] == L"DynDataFieldsIo" ||
            currentColumns_[index] == L"FieldCoverage" ||
            currentColumns_[index] == L"FieldSources" ||
            currentColumns_[index] == L"RequiredMissing" ||
            currentColumns_[index] == L"NtosIdentity" ||
            currentColumns_[index] == L"LxcoreIdentity" ||
            currentColumns_[index] == L"LocalPdbProfileMatched" ||
            currentColumns_[index] == L"LocalPdbProfile" ||
            currentColumns_[index] == L"LocalPdbProfileName" ||
            currentColumns_[index] == L"LocalPdbProfilePath" ||
            currentColumns_[index] == L"LocalPdbMessage" ||
            currentColumns_[index] == L"LocalPdbVersion" ||
            currentColumns_[index] == L"ActiveProcessLinksOffset" ||
            currentColumns_[index] == L"CallbackProfileCoverage" ||
            currentColumns_[index] == L"PdbProfileActive" ||
            currentColumns_[index] == L"CallbackProfileActive" ||
            currentColumns_[index] == L"TrustedPdbOffsetsActive" ||
            currentColumns_[index] == L"TrustedOffset" ||
            currentColumns_[index] == L"UnavailableReason" ||
            currentColumns_[index] == L"Detail";
        addResultTableColumn(static_cast<int>(index), currentColumns_[index], kHidden ? 0 : columnWidth(currentColumns_[index]));
    }
    syncResultListVirtualRows();
    if (!currentRows_.empty()) {
        ListView_SetItemState(resultList_, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(resultList_, 0, FALSE);
        updateSelectedRowDetail();
    } else {
        const std::wstring kReport = buildDiagnosticReportForCurrentFeature();
        ::SetWindowTextW(detailEdit_, kReport.empty() ? emptyDetailTextForFeature(featureId) : kReport.c_str());
    }
}

void KernelPage::rebuildCallbackEnumerationListFromCache() {
    // rebuildCallbackEnumerationListFromCache mirrors the original
    // KernelDock.CallbackEnum table. Inputs are raw rows from
    // ArkDriverClient::enumerateCallbacks; processing keeps the exact visible
    // nine columns, preserves hidden protocol fields for remove actions, and
    // applies the local filter edit; output updates resultList_ and detailEdit_.
    if (!resultList_) {
        return;
    }
    const std::vector<std::wstring>& rawColumns = !currentRawColumns_.empty() ? currentRawColumns_ : currentColumns_;
    const std::vector<std::vector<std::wstring>>& rawRows = !currentRawRows_.empty() ? currentRawRows_ : currentRows_;
    const std::wstring kFilterText = windowText(filterEdit_);
    const auto kRawValue = [&](const std::vector<std::wstring>& row, std::initializer_list<const wchar_t*> names) -> std::wstring {
        return rowFieldByName(row, rawColumns, names);
    };
    const auto kAddColumnIfMissing = [](std::vector<std::wstring>& columns, const wchar_t* name) {
        if (!hasColumn(columns, name)) {
            columns.push_back(name);
        }
    };
    const auto kDisplayValue = [&](const std::vector<std::wstring>& row, const std::wstring& columnName) -> std::wstring {
        std::vector<std::wstring> aliases = columnAliases(KernelFeatureId::kCallbackEnumeration, columnName);
        if (aliases.empty()) {
            aliases.push_back(columnName);
        }
        for (const std::wstring& alias : aliases) {
            const std::wstring kValue = kRawValue(row, { alias.c_str() });
            if (!kValue.empty()) {
                return kValue;
            }
        }
        return {};
    };

    std::vector<std::wstring> displayColumns;
    for (const std::wstring& column : canonicalColumnNames(KernelFeatureId::kCallbackEnumeration)) {
        kAddColumnIfMissing(displayColumns, column.c_str());
    }
    kAddColumnIfMissing(displayColumns, L"SourceIndex");
    kAddColumnIfMissing(displayColumns, L"Class");
    kAddColumnIfMissing(displayColumns, L"Source");
    kAddColumnIfMissing(displayColumns, L"Callback");
    kAddColumnIfMissing(displayColumns, L"Context");
    kAddColumnIfMissing(displayColumns, L"Registration");
    kAddColumnIfMissing(displayColumns, L"ModulePath");
    kAddColumnIfMissing(displayColumns, L"Win32ModulePath");
    kAddColumnIfMissing(displayColumns, L"ModuleBase");
    kAddColumnIfMissing(displayColumns, L"ModuleSize");
    kAddColumnIfMissing(displayColumns, L"OperationMask");
    kAddColumnIfMissing(displayColumns, L"ObjectTypeMask");
    kAddColumnIfMissing(displayColumns, L"FieldFlags");
    kAddColumnIfMissing(displayColumns, L"Trust");
    kAddColumnIfMissing(displayColumns, L"Remove");
    kAddColumnIfMissing(displayColumns, L"RemoveFlags");
    kAddColumnIfMissing(displayColumns, L"Generation");
    kAddColumnIfMissing(displayColumns, L"IdentityHash");
    kAddColumnIfMissing(displayColumns, L"RawStorageValue");
    kAddColumnIfMissing(displayColumns, L"LastStatus");
    kAddColumnIfMissing(displayColumns, L"Detail");

    std::vector<std::vector<std::wstring>> displayRows;
    std::size_t unsupportedCount = 0;
    std::size_t totalCallbackRows = 0;
    bool responseTruncated = false;
    for (const std::vector<std::wstring>& rawRow : rawRows) {
        std::uint64_t flagsValue = 0;
        if (parseUnsigned64Value(kRawValue(rawRow, { L"CallbackEnumResponseFlags", L"ResponseFlags", L"Flags" }), flagsValue) &&
            flagEnabled(flagsValue, KSWORD_ARK_ENUM_CALLBACK_RESPONSE_FLAG_TRUNCATED)) {
            responseTruncated = true;
        }
        if (kRawValue(rawRow, { L"CallbackEnumTruncated" }) == L"1") {
            responseTruncated = true;
        }
    }
    for (std::size_t sourceIndex = 0; sourceIndex < rawRows.size(); ++sourceIndex) {
        const std::vector<std::wstring>& rawRow = rawRows[sourceIndex];
        const bool kMeaningful = hasNonEmptyField(rawRow, rawColumns, {
            L"ClassText", L"Class", L"SourceText", L"Source", L"Callback", L"Object", L"Registration", L"RawStorageValue", L"Name", L"ModulePath"
        });
        if (!kMeaningful) {
            continue;
        }
        ++totalCallbackRows;
        const std::wstring kStatus = kRawValue(rawRow, { L"Status", L"状态" });
        if (containsCaseInsensitive(kStatus, L"unsupported") || containsCaseInsensitive(kStatus, L"未支持")) {
            ++unsupportedCount;
        }
        const std::wstring kMerged = mergeRowText(rawRow);
        if (!kFilterText.empty() && !containsCaseInsensitive(kMerged, kFilterText)) {
            continue;
        }

        std::vector<std::wstring> cells(displayColumns.size());
        for (std::size_t column = 0; column < displayColumns.size(); ++column) {
            const std::wstring& name = displayColumns[column];
            if (name == L"SourceIndex") {
                cells[column] = std::to_wstring(sourceIndex);
            } else if (name == L"回调/对象地址") {
                std::wstring value = kRawValue(rawRow, { L"Callback" });
                if (value.empty() || value == L"0" || value == L"0x0" || value == L"0x0000000000000000") {
                    value = kRawValue(rawRow, { L"Object", L"Registration", L"RawStorageValue", L"Context" });
                }
                cells[column] = std::move(value);
            } else if (name == L"模块") {
                std::wstring module = kRawValue(rawRow, { L"ModulePath", L"Module" });
                if (module.empty()) {
                    module = L"<未解析>";
                }
                cells[column] = std::move(module);
            } else if (name == L"名称") {
                std::wstring value = kRawValue(rawRow, { L"Name", L"名称" });
                if (value.empty()) {
                    value = L"<无名称>";
                }
                cells[column] = std::move(value);
            } else if (name == L"Win32ModulePath") {
                cells[column] = normalizeCallbackModulePath(kRawValue(rawRow, { L"ModulePath", L"Module" }));
            } else if (name == L"Detail") {
                cells[column] = kRawValue(rawRow, { L"Detail", L"FieldText", L"TrustText", L"RemoveText" });
            } else {
                cells[column] = kDisplayValue(rawRow, name);
            }
        }
        displayRows.push_back(std::move(cells));
    }

    currentColumns_ = std::move(displayColumns);
    currentRows_ = std::move(displayRows);
    clearResultTable();
    for (std::size_t index = 0; index < currentColumns_.size(); ++index) {
        const bool kHidden = currentColumns_[index] == L"SourceIndex" ||
            currentColumns_[index] == L"Class" ||
            currentColumns_[index] == L"Source" ||
            currentColumns_[index] == L"Callback" ||
            currentColumns_[index] == L"Context" ||
            currentColumns_[index] == L"Registration" ||
            currentColumns_[index] == L"ModulePath" ||
            currentColumns_[index] == L"Win32ModulePath" ||
            currentColumns_[index] == L"ModuleBase" ||
            currentColumns_[index] == L"ModuleSize" ||
            currentColumns_[index] == L"OperationMask" ||
            currentColumns_[index] == L"ObjectTypeMask" ||
            currentColumns_[index] == L"FieldFlags" ||
            currentColumns_[index] == L"Trust" ||
            currentColumns_[index] == L"Remove" ||
            currentColumns_[index] == L"RemoveFlags" ||
            currentColumns_[index] == L"Generation" ||
            currentColumns_[index] == L"IdentityHash" ||
            currentColumns_[index] == L"RawStorageValue" ||
            currentColumns_[index] == L"LastStatus" ||
            currentColumns_[index] == L"Detail";
        int width = kHidden ? 0 : columnWidth(currentColumns_[index]);
        if (currentColumns_[index] == L"可信状态") {
            width = 170;
        } else if (currentColumns_[index] == L"移除策略") {
            width = 200;
        } else if (currentColumns_[index] == L"回调/对象地址") {
            width = 180;
        } else if (currentColumns_[index] == L"模块") {
            width = 220;
        } else if (currentColumns_[index] == L"名称") {
            width = 260;
        }
        addResultTableColumn(static_cast<int>(index), currentColumns_[index], width);
    }
    syncResultListVirtualRows();
    std::wostringstream status;
    status << L"状态：已刷新 " << totalCallbackRows
           << L" 项，私有未支持 " << unsupportedCount << L" 项";
    if (responseTruncated) {
        status << L"，响应截断";
    }
    if (!kFilterText.empty()) {
        status << L"，显示 " << currentRows_.size() << L" 项";
    }
    ::SetWindowTextW(statusText_, status.str().c_str());
    if (!currentRows_.empty()) {
        ListView_SetItemState(resultList_, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(resultList_, 0, FALSE);
        updateSelectedRowDetail();
    } else {
        ::SetWindowTextW(detailEdit_, L"当前环境未返回可见回调记录。");
    }
}

void KernelPage::rebuildKernelMemoryScanListFromCache(const KernelFeatureId featureId) {
    // rebuildKernelMemoryScanListFromCache mirrors the original MemoryDock
    // kernel executable/evidence grids. Inputs are raw ArkDriverClient rows
    // cached by renderResult plus current Win32 filter controls; processing
    // projects only original visible columns while retaining hidden R0 fields for
    // details/actions; return behavior is UI state only.
    if (!resultList_) {
        return;
    }

    const std::vector<std::wstring>& rawColumns = !currentRawColumns_.empty() ? currentRawColumns_ : currentColumns_;
    const std::vector<std::vector<std::wstring>>& rawRows = !currentRawRows_.empty() ? currentRawRows_ : currentRows_;
    const bool kExecutablePage = featureId == KernelFeatureId::kKernelExecutableMemory;
    const bool kRiskOnly = riskOnlyCheck_ && Button_GetCheck(riskOnlyCheck_) == BST_CHECKED;
    const std::wstring kPrimaryFilter = kExecutablePage ? windowText(moduleFilterEdit_) : windowText(filterEdit_);
    const auto kRawValue = [&](const std::vector<std::wstring>& row, std::initializer_list<const wchar_t*> names) -> std::wstring {
        return rowFieldByName(row, rawColumns, names);
    };
    const auto kAddColumnIfMissing = [](std::vector<std::wstring>& columns, const wchar_t* name) {
        if (!hasColumn(columns, name)) {
            columns.push_back(name);
        }
    };
    const auto kDisplayValue = [&](const std::vector<std::wstring>& row, const std::wstring& columnName) -> std::wstring {
        std::vector<std::wstring> aliases = columnAliases(featureId, columnName);
        if (aliases.empty()) {
            aliases.push_back(columnName);
        }
        for (const std::wstring& alias : aliases) {
            const std::wstring kValue = kRawValue(row, { alias.c_str() });
            if (!kValue.empty()) {
                return kValue;
            }
        }
        return {};
    };

    std::vector<std::wstring> displayColumns;
    displayColumns.push_back(L"#");
    for (const std::wstring& column : canonicalColumnNames(featureId)) {
        if (!hasColumn(displayColumns, column)) {
            displayColumns.push_back(column);
        }
    }
    const wchar_t* hiddenExecutable[] = {
        L"RegionSize", L"Perm", L"Risk", L"OwnerKind", L"OwnerKindText", L"OwnerAddress",
        L"ModuleBase", L"ModuleSize", L"Module", L"Status", L"LastStatus", L"Detail"
    };
    const wchar_t* hiddenEvidence[] = {
        L"Kind", L"RegionSize", L"PageSize", L"Perm", L"Risk", L"OwnerKind", L"OwnerKindText",
        L"OwnerAddress", L"ModuleBase", L"ModuleSize", L"ModuleSizeText", L"Confidence",
        L"BigPoolTag", L"BigPoolFlags", L"SectionRva", L"SectionSize", L"SectionSizeText",
        L"Section", L"HashAlgorithm", L"SampleSize", L"Hash", L"HashText", L"Sample",
        L"LastStatus", L"Detail"
    };
    if (kExecutablePage) {
        for (const wchar_t* column : hiddenExecutable) {
            kAddColumnIfMissing(displayColumns, column);
        }
    } else {
        for (const wchar_t* column : hiddenEvidence) {
            kAddColumnIfMissing(displayColumns, column);
        }
    }

    std::vector<std::vector<std::wstring>> displayRows;
    std::size_t totalRows = 0;
    std::size_t returnedRows = 0;
    std::size_t reportedModuleRows = 0;
    std::size_t reportedBigPoolRows = 0;
    std::size_t moduleRows = 0;
    std::size_t bigPoolRows = 0;
    std::size_t riskRows = 0;
    for (const std::vector<std::wstring>& rawRow : rawRows) {
        const std::uint64_t kTotal = firstNonZeroField(rawRow, rawColumns, { L"Total" });
        const std::uint64_t kReturned = firstNonZeroField(rawRow, rawColumns, { L"Returned" });
        const std::uint64_t kModules = firstNonZeroField(rawRow, rawColumns, { L"Modules" });
        const std::uint64_t kBigPool = firstNonZeroField(rawRow, rawColumns, { L"BigPoolRows" });
        if (kTotal != 0) {
            totalRows = static_cast<std::size_t>(kTotal);
        }
        if (kReturned != 0) {
            returnedRows = static_cast<std::size_t>(kReturned);
        }
        if (kModules != 0) {
            reportedModuleRows = static_cast<std::size_t>(kModules);
        }
        if (kBigPool != 0) {
            reportedBigPoolRows = static_cast<std::size_t>(kBigPool);
        }
    }
    for (const std::vector<std::wstring>& rawRow : rawRows) {
        const bool kIsDataRow = kExecutablePage
            ? hasNonEmptyField(rawRow, rawColumns, { L"VA", L"Pages", L"PermText", L"RiskText", L"OwnerDisplay", L"ModulePath" })
            : hasNonEmptyField(rawRow, rawColumns, { L"VA", L"KindText", L"RiskText", L"OwnerDisplay", L"HashText" });
        if (!kIsDataRow) {
            continue;
        }
        if (totalRows == 0) {
            ++returnedRows;
        }
        const std::wstring kRiskText = kRawValue(rawRow, { L"RiskText", L"风险", L"风险标志" });
        const std::wstring kRiskValue = kRawValue(rawRow, { L"Risk" });
        const bool kRisky = !kRiskText.empty() &&
            !containsCaseInsensitive(kRiskText, L"正常") &&
            !containsCaseInsensitive(kRiskValue, L"0x0");
        if (kRisky) {
            ++riskRows;
        }
        if (kRiskOnly && !kRisky) {
            continue;
        }

        std::wstring merged = mergeRowText(rawRow);
        if (kExecutablePage) {
            merged += L" | " + kRawValue(rawRow, { L"ModulePath", L"Module" });
            if (!kPrimaryFilter.empty() && !containsCaseInsensitive(merged, kPrimaryFilter)) {
                continue;
            }
            if (!kRawValue(rawRow, { L"ModulePath", L"Module" }).empty()) {
                ++moduleRows;
            }
        } else {
            if (!kPrimaryFilter.empty() && !containsCaseInsensitive(merged, kPrimaryFilter)) {
                continue;
            }
            if (containsCaseInsensitive(kRawValue(rawRow, { L"KindText", L"类型" }), L"BigPool")) {
                ++bigPoolRows;
            }
            if (!kRawValue(rawRow, { L"ModuleBase" }).empty()) {
                ++moduleRows;
            }
        }

        std::vector<std::wstring> cells(displayColumns.size());
        for (std::size_t column = 0; column < displayColumns.size(); ++column) {
            const std::wstring& name = displayColumns[column];
            if (name == L"#") {
                cells[column] = std::to_wstring(displayRows.size());
            } else if (name == L"Detail") {
                cells[column] = kRawValue(rawRow, { L"Detail" });
            } else {
                cells[column] = kDisplayValue(rawRow, name);
            }
        }
        displayRows.push_back(std::move(cells));
    }

    currentColumns_ = std::move(displayColumns);
    currentRows_ = std::move(displayRows);
    clearResultTable();
    for (std::size_t index = 0; index < currentColumns_.size(); ++index) {
        int width = isKernelMemoryHiddenColumn(currentColumns_[index]) ? 0 : columnWidth(currentColumns_[index]);
        if (currentColumns_[index] == L"VA") {
            width = 170;
        } else if (currentColumns_[index] == L"页数" || currentColumns_[index] == L"页大小" || currentColumns_[index] == L"大小") {
            width = 82;
        } else if (currentColumns_[index] == L"权限" || currentColumns_[index] == L"PTE权限") {
            width = 160;
        } else if (currentColumns_[index] == L"Owner") {
            width = 190;
        } else if (currentColumns_[index] == L"模块路径") {
            width = 320;
        } else if (currentColumns_[index] == L"风险标志" || currentColumns_[index] == L"风险") {
            width = 210;
        } else if (currentColumns_[index] == L"text hash/diff") {
            width = 240;
        }
        addResultTableColumn(static_cast<int>(index), currentColumns_[index], width);
    }
    syncResultListVirtualRows();

    std::wostringstream status;
    if (kExecutablePage) {
        const std::size_t kEffectiveTotal = totalRows == 0 ? returnedRows : totalRows;
        const std::size_t kEffectiveModules = reportedModuleRows == 0 ? moduleRows : reportedModuleRows;
        status << L"状态：总计 " << kEffectiveTotal
               << L"，显示 " << currentRows_.size()
               << L"，模块 " << kEffectiveModules
               << L"，风险项 " << riskRows;
    } else {
        const std::size_t kEffectiveTotal = totalRows == 0 ? returnedRows : totalRows;
        const std::size_t kEffectiveReturned = returnedRows == 0 ? kEffectiveTotal : returnedRows;
        const std::size_t kEffectiveModules = reportedModuleRows == 0 ? moduleRows : reportedModuleRows;
        const std::size_t kEffectiveBigPool = reportedBigPoolRows == 0 ? bigPoolRows : reportedBigPoolRows;
        status << L"状态：总计 " << kEffectiveTotal
               << L"，返回 " << kEffectiveReturned
               << L"，显示 " << currentRows_.size()
               << L"，模块 " << kEffectiveModules
               << L"，BigPool seen " << kEffectiveBigPool;
    }
    ::SetWindowTextW(statusText_, status.str().c_str());
    if (!currentRows_.empty()) {
        ListView_SetItemState(resultList_, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(resultList_, 0, FALSE);
        updateSelectedRowDetail();
    } else {
        ::SetWindowTextW(detailEdit_, kExecutablePage
            ? L"当前过滤条件下没有内核可执行页记录。"
            : L"当前过滤条件下没有内核内存证据记录。");
    }
}

void KernelPage::rebuildCrossViewListFromCache(const KernelFeatureId featureId) {
    // rebuildCrossViewListFromCache mirrors the original ProcessDock CrossView
    // matrix table. Inputs are raw R0 rows cached by renderResult and the local
    // filter edit; processing keeps the visible matrix columns identical while
    // preserving offset/source fields for details; output is ListView/detail UI.
    if (!resultList_) {
        return;
    }

    const std::vector<std::wstring>& rawColumns = !currentRawColumns_.empty() ? currentRawColumns_ : currentColumns_;
    const std::vector<std::vector<std::wstring>>& rawRows = !currentRawRows_.empty() ? currentRawRows_ : currentRows_;
    const std::wstring kFilterText = windowText(filterEdit_);
    const auto kRawValue = [&](const std::vector<std::wstring>& row, std::initializer_list<const wchar_t*> names) -> std::wstring {
        return rowFieldByName(row, rawColumns, names);
    };
    const auto kDisplayValue = [&](const std::vector<std::wstring>& row, const std::wstring& columnName) -> std::wstring {
        std::vector<std::wstring> aliases = columnAliases(featureId, columnName);
        if (aliases.empty()) {
            aliases.push_back(columnName);
        }
        for (const std::wstring& alias : aliases) {
            const std::wstring kValue = kRawValue(row, { alias.c_str() });
            if (!kValue.empty()) {
                return kValue;
            }
        }
        return {};
    };
    const auto kAddColumnIfMissing = [](std::vector<std::wstring>& columns, const wchar_t* name) {
        if (!hasColumn(columns, name)) {
            columns.push_back(name);
        }
    };

    std::vector<std::wstring> displayColumns;
    for (const std::wstring& column : canonicalColumnNames(featureId)) {
        kAddColumnIfMissing(displayColumns, column.c_str());
    }
    const wchar_t* hiddenColumns[] = {
        L"PID", L"PPID", L"TID", L"Image", L"Object", L"ProcessObject", L"ThreadObject",
        L"Start", L"StartAddress", L"SourceMask", L"SourceText", L"Anomaly", L"AnomalyText",
        L"DynData", L"DynDataCapabilityMask", L"EP.UniqueProcessId", L"EP.ActiveProcessLinks",
        L"EP.ThreadListHead", L"EP.ImageFileName", L"ET.Cid", L"ET.ThreadListEntry",
        L"ET.StartAddress", L"ET.Win32StartAddress", L"KT.Process", L"HT.TableCode",
        L"HTE.LowValue", L"PspCidTableRva", L"PspCidTable", L"Confidence", L"LastStatus"
    };
    for (const wchar_t* column : hiddenColumns) {
        kAddColumnIfMissing(displayColumns, column);
    }

    std::size_t reportedTotalRows = 0;
    std::size_t reportedReturnedRows = 0;
    std::wstring missingDynText;
    for (const std::vector<std::wstring>& rawRow : rawRows) {
        const std::uint64_t kTotal = firstNonZeroField(rawRow, rawColumns, { L"Total" });
        const std::uint64_t kReturned = firstNonZeroField(rawRow, rawColumns, { L"Returned" });
        if (kTotal != 0) {
            reportedTotalRows = static_cast<std::size_t>(kTotal);
        }
        if (kReturned != 0) {
            reportedReturnedRows = static_cast<std::size_t>(kReturned);
        }
        if (missingDynText.empty()) {
            missingDynText = kRawValue(rawRow, { L"MissingDyn", L"MissingDynData", L"MissingCapabilityMask" });
        }
    }

    std::vector<std::vector<std::wstring>> displayRows;
    std::size_t totalRows = 0;
    std::size_t anomalyRows = 0;
    std::size_t cidOnlyRows = 0;
    const bool kAnomalyOnly = riskOnlyCheck_ && Button_GetCheck(riskOnlyCheck_) == BST_CHECKED;
    for (const std::vector<std::wstring>& rawRow : rawRows) {
        const bool kRowLooksLikeProcess = featureId == KernelFeatureId::kProcessCrossView &&
            hasNonEmptyField(rawRow, rawColumns, { L"PID", L"ProcessObject", L"Object", L"Image" });
        const bool kRowLooksLikeThread = featureId == KernelFeatureId::kThreadCrossView &&
            hasNonEmptyField(rawRow, rawColumns, { L"TID", L"ThreadObject", L"Object", L"ProcessObject" });
        if (!kRowLooksLikeProcess && !kRowLooksLikeThread) {
            continue;
        }
        ++totalRows;
        std::uint64_t anomalyMask = 0;
        const bool kParsedAnomalyMask = hexToUInt64(kRawValue(rawRow, { L"Anomaly" }), anomalyMask);
        const std::wstring kAnomaly = kRawValue(rawRow, { L"异常", L"AnomalyText" });
        const bool kAnomalous = kParsedAnomalyMask
            ? anomalyMask != 0
            : (!kAnomaly.empty() && !containsCaseInsensitive(kAnomaly, L"正常") && !containsCaseInsensitive(kAnomaly, L"0x0"));
        if (kAnomalous) {
            ++anomalyRows;
        }
        if (kAnomalyOnly && !kAnomalous) {
            continue;
        }
        const std::wstring kMerged = mergeRowText(rawRow);
        if (!kFilterText.empty() && !containsCaseInsensitive(kMerged, kFilterText)) {
            continue;
        }
        const std::wstring kPublicWalk = kRawValue(rawRow, { L"PublicWalk" });
        const std::wstring kActive = kRawValue(rawRow, { L"Active/ThreadList" });
        const std::wstring kCid = kRawValue(rawRow, { L"CID" });
        if (containsCaseInsensitive(kCid, L"是") &&
            !containsCaseInsensitive(kPublicWalk, L"是") &&
            !containsCaseInsensitive(kActive, L"是")) {
            ++cidOnlyRows;
        }

        std::vector<std::wstring> cells(displayColumns.size());
        for (std::size_t column = 0; column < displayColumns.size(); ++column) {
            const std::wstring& name = displayColumns[column];
            if (name == L"Detail") {
                cells[column] = kRawValue(rawRow, { L"Detail" });
            } else {
                cells[column] = kDisplayValue(rawRow, name);
            }
        }
        displayRows.push_back(std::move(cells));
    }

    currentColumns_ = std::move(displayColumns);
    currentRows_ = std::move(displayRows);
    clearResultTable();
    for (std::size_t index = 0; index < currentColumns_.size(); ++index) {
        const std::wstring& name = currentColumns_[index];
        const bool kHidden = name == L"PID" ||
            name == L"PPID" ||
            name == L"TID" ||
            name == L"Image" ||
            name == L"Object" ||
            name == L"ProcessObject" ||
            name == L"ThreadObject" ||
            name == L"Start" ||
            name == L"StartAddress" ||
            name == L"SourceMask" ||
            name == L"SourceText" ||
            name == L"Anomaly" ||
            name == L"AnomalyText" ||
            name == L"DynData" ||
            name == L"DynDataCapabilityMask" ||
            name == L"EP.UniqueProcessId" ||
            name == L"EP.ActiveProcessLinks" ||
            name == L"EP.ThreadListHead" ||
            name == L"EP.ImageFileName" ||
            name == L"ET.Cid" ||
            name == L"ET.ThreadListEntry" ||
            name == L"ET.StartAddress" ||
            name == L"ET.Win32StartAddress" ||
            name == L"KT.Process" ||
            name == L"HT.TableCode" ||
            name == L"HTE.LowValue" ||
            name == L"PspCidTableRva" ||
            name == L"PspCidTable" ||
            name == L"Confidence" ||
            name == L"LastStatus";
        int width = kHidden ? 0 : columnWidth(name);
        if (name == L"ID") {
            width = 84;
        } else if (name == L"对象") {
            width = 170;
        } else if (name == L"进程") {
            width = 180;
        } else if (name == L"PublicWalk" || name == L"Active/ThreadList" || name == L"CID") {
            width = 92;
        } else if (name == L"异常") {
            width = 210;
        } else if (name == L"置信度") {
            width = 72;
        } else if (name == L"Detail") {
            width = 300;
        }
        addResultTableColumn(static_cast<int>(index), name, width);
    }
    syncResultListVirtualRows();

    std::wostringstream status;
    const std::size_t kEffectiveTotal = reportedTotalRows == 0 ? totalRows : reportedTotalRows;
    const std::size_t kEffectiveReturned = reportedReturnedRows == 0 ? totalRows : reportedReturnedRows;
    status << L"状态：" << (featureId == KernelFeatureId::kProcessCrossView ? L"进程" : L"线程")
           << L" Cross-View 已刷新，显示 " << currentRows_.size()
           << L"，返回 " << kEffectiveReturned << L"/" << kEffectiveTotal
           << L"，异常 " << anomalyRows << L"，CID-only " << cidOnlyRows
           << L"，missingCaps=" << (missingDynText.empty() ? L"0x0" : missingDynText);
    ::SetWindowTextW(statusText_, status.str().c_str());
    if (!currentRows_.empty()) {
        ListView_SetItemState(resultList_, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(resultList_, 0, FALSE);
        updateSelectedRowDetail();
    } else {
        ::SetWindowTextW(detailEdit_, L"当前过滤条件下没有 Cross-View 记录。");
    }
}


void KernelPage::rebuildIntegrityEvidenceListFromCache(const KernelFeatureId featureId) {
    // rebuildIntegrityEvidenceListFromCache mirrors the original DriverDock and
    // HardwareDock integrity evidence tables. Inputs are raw R0 rows cached by
    // renderResult and the local filter edit; processing projects the original
    // visible columns while retaining raw protocol fields for detail/actions;
    // output is the updated ListView, status text, and detail pane selection.
    if (!resultList_) {
        return;
    }

    const std::vector<std::wstring>& rawColumns = !currentRawColumns_.empty() ? currentRawColumns_ : currentColumns_;
    const std::vector<std::vector<std::wstring>>& rawRows = !currentRawRows_.empty() ? currentRawRows_ : currentRows_;
    const std::wstring kFilterText = windowText(filterEdit_);
    const bool kCpuPage = featureId == KernelFeatureId::kKernelCpuIntegrity;
    const auto kRawValue = [&](const std::vector<std::wstring>& row, std::initializer_list<const wchar_t*> names) -> std::wstring {
        return rowFieldByName(row, rawColumns, names);
    };
    const auto kAddColumnIfMissing = [](std::vector<std::wstring>& columns, const wchar_t* name) {
        if (!hasColumn(columns, name)) {
            columns.push_back(name);
        }
    };
    const auto kDisplayValue = [&](const std::vector<std::wstring>& row, const std::wstring& columnName) -> std::wstring {
        std::vector<std::wstring> aliases = columnAliases(featureId, columnName);
        if (aliases.empty()) {
            aliases.push_back(columnName);
        }
        for (const std::wstring& alias : aliases) {
            const std::wstring kValue = kRawValue(row, { alias.c_str() });
            if (!kValue.empty()) {
                return kValue;
            }
        }
        return {};
    };

    std::vector<std::wstring> displayColumns;
    displayColumns.push_back(L"#");
    for (const std::wstring& column : canonicalColumnNames(featureId)) {
        kAddColumnIfMissing(displayColumns, column.c_str());
    }
    const wchar_t* hiddenColumns[] = {
        L"Class", L"ClassText", L"Risk", L"RiskText", L"Source", L"SourceMask", L"SourceText",
        L"Confidence", L"Group", L"CPU", L"Vector", L"CpuVector", L"Object", L"ObjectAddress",
        L"Target", L"TargetAddress", L"OwnerBase", L"OwnerModuleBase", L"OwnerSize",
        L"OwnerModuleSize", L"OwnerModuleSizeText", L"OwnerModule", L"LastStatus"
    };
    for (const wchar_t* column : hiddenColumns) {
        kAddColumnIfMissing(displayColumns, column);
    }

    std::vector<std::vector<std::wstring>> displayRows;
    std::size_t reportedTotalRows = 0;
    std::size_t reportedReturnedRows = 0;
    std::size_t reportedCpuRows = 0;
    std::size_t reportedModuleRows = 0;
    std::size_t totalRows = 0;
    std::size_t riskRows = 0;
    std::wstring r0State;
    std::wstring r0Protocol;
    std::wstring dynDataState;
    std::wstring queryStatus;
    std::wstring sourceText;
    for (const std::vector<std::wstring>& rawRow : rawRows) {
        const std::uint64_t kTotal = firstNonZeroField(rawRow, rawColumns, { L"Total" });
        const std::uint64_t kReturned = firstNonZeroField(rawRow, rawColumns, { L"Returned" });
        const std::uint64_t kCpuCount = firstNonZeroField(rawRow, rawColumns, { L"CpuCount" });
        const std::uint64_t kModuleCount = firstNonZeroField(rawRow, rawColumns, { L"ModuleCount" });
        if (kTotal != 0) {
            reportedTotalRows = static_cast<std::size_t>(kTotal);
        }
        if (kReturned != 0) {
            reportedReturnedRows = static_cast<std::size_t>(kReturned);
        }
        if (kCpuCount != 0) {
            reportedCpuRows = static_cast<std::size_t>(kCpuCount);
        }
        if (kModuleCount != 0) {
            reportedModuleRows = static_cast<std::size_t>(kModuleCount);
        }
        if (r0State.empty()) {
            r0State = rowFieldByName(rawRow, rawColumns, { L"R0" });
        }
        if (r0Protocol.empty()) {
            r0Protocol = rowFieldByName(rawRow, rawColumns, { L"Protocol" });
        }
        if (dynDataState.empty()) {
            dynDataState = rowFieldByName(rawRow, rawColumns, { L"DynDataStatus" });
        }
        if (queryStatus.empty()) {
            queryStatus = rowFieldByName(rawRow, rawColumns, { L"Status" });
        }
        if (sourceText.empty()) {
            sourceText = rowFieldByName(rawRow, rawColumns, { L"SourceText", L"SourceMask" });
        }
    }
    for (const std::vector<std::wstring>& rawRow : rawRows) {
        const bool kEvidenceRow = hasNonEmptyField(rawRow, rawColumns, {
            L"类别", L"Class", L"ClassText", L"对象", L"ObjectAddress", L"目标", L"TargetAddress",
            L"Owner", L"OwnerModule", L"CPU/Vector", L"CpuVector", L"风险", L"RiskText"
        });
        if (!kEvidenceRow) {
            continue;
        }
        ++totalRows;
        const std::wstring kRiskText = kRawValue(rawRow, { L"风险", L"RiskText", L"Risk" });
        const std::wstring kRiskMask = kRawValue(rawRow, { L"Risk" });
        const bool kRisky = !kRiskText.empty() &&
            !containsCaseInsensitive(kRiskText, L"正常") &&
            !containsCaseInsensitive(kRiskMask, L"0x0") &&
            kRiskMask != L"0";
        if (kRisky) {
            ++riskRows;
        }
        const bool kSupportsRiskOnly = featureId == KernelFeatureId::kMutationAudit;
        if (kSupportsRiskOnly && riskOnlyCheck_ && Button_GetCheck(riskOnlyCheck_) == BST_CHECKED && !kRisky) {
            continue;
        }
        const std::wstring kMerged = mergeRowText(rawRow);
        if (!kFilterText.empty() && !containsCaseInsensitive(kMerged, kFilterText)) {
            continue;
        }

        std::vector<std::wstring> cells(displayColumns.size());
        for (std::size_t column = 0; column < displayColumns.size(); ++column) {
            const std::wstring& name = displayColumns[column];
            if (name == L"#") {
                cells[column] = std::to_wstring(displayRows.size());
            } else if (name == L"Detail") {
                cells[column] = kRawValue(rawRow, { L"Detail" });
            } else {
                cells[column] = kDisplayValue(rawRow, name);
            }
        }
        displayRows.push_back(std::move(cells));
    }

    currentColumns_ = std::move(displayColumns);
    currentRows_ = std::move(displayRows);
    clearResultTable();
    for (std::size_t index = 0; index < currentColumns_.size(); ++index) {
        const std::wstring& name = currentColumns_[index];
        const bool kCanonicalColumn = hasColumn(canonicalColumnNames(featureId), name);
        int width = (!kCanonicalColumn && isIntegrityHiddenColumn(name)) ? 0 : columnWidth(name);
        if (name == L"类别") {
            width = 150;
        } else if (name == L"对象" || name == L"目标" || name == L"对象/寄存器" || name == L"目标/入口") {
            width = 170;
        } else if (name == L"Owner" || name == L"Owner模块") {
            width = 240;
        } else if (name == L"CPU/Vector") {
            width = 110;
        } else if (name == L"风险") {
            width = 220;
        } else if (name == L"置信度") {
            width = 72;
        } else if (name == L"Detail") {
            width = 360;
        }
        addResultTableColumn(static_cast<int>(index), name, width);
    }
    syncResultListVirtualRows();

    std::wostringstream status;
    const std::size_t kEffectiveTotal = reportedTotalRows == 0 ? totalRows : reportedTotalRows;
    const std::size_t kEffectiveReturned = reportedReturnedRows == 0 ? totalRows : reportedReturnedRows;
    status << L"状态：" << (kCpuPage ? L"CPU/IDT 完整性" : L"驱动完整性")
           << L"已刷新，显示 " << currentRows_.size()
           << L"，返回 " << kEffectiveReturned << L"/" << kEffectiveTotal
           << L"，风险 " << riskRows;
    if (!queryStatus.empty()) {
        status << L"，Query " << queryStatus;
    }
    if (!sourceText.empty()) {
        status << L"，Source " << sourceText;
    }
    if (reportedCpuRows != 0 || reportedModuleRows != 0) {
        status << L"，CPU " << reportedCpuRows << L"，模块 " << reportedModuleRows;
    }
    if (kCpuPage && (!r0State.empty() || !r0Protocol.empty() || !dynDataState.empty())) {
        status << L"，R0 " << (r0State.empty() ? L"<unknown>" : r0State)
               << L"，Protocol " << (r0Protocol.empty() ? L"-" : r0Protocol)
               << L"，DynData " << (dynDataState.empty() ? L"-" : dynDataState);
    }
    ::SetWindowTextW(statusText_, status.str().c_str());
    if (!currentRows_.empty()) {
        ListView_SetItemState(resultList_, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(resultList_, 0, FALSE);
        updateSelectedRowDetail();
    } else {
        ::SetWindowTextW(detailEdit_, kCpuPage
            ? L"当前过滤条件下没有 CPU/IDT 完整性证据。"
            : L"当前过滤条件下没有驱动完整性证据。");
    }
}

// buildR0EvidenceSnapshot projects an immutable raw R0 table without touching
// Win32 controls. It runs on the filter worker, allowing large driver audits to
// remain responsive while the user edits the local search text.
KernelR0EvidenceSnapshot buildR0EvidenceSnapshot(
    const KernelFeatureId featureId,
    std::wstring pageName,
    std::vector<std::wstring> rawColumns,
    std::vector<std::vector<std::wstring>> rawRows,
    std::wstring filterText,
    const bool riskOnly,
    std::wstring selectedRowSignature,
    const int topRow) {
    KernelR0EvidenceSnapshot snapshot{};
    snapshot.featureId = featureId;
    snapshot.selectedRowSignature = std::move(selectedRowSignature);
    snapshot.topRow = topRow;

    const auto kRawValue = [&](const std::vector<std::wstring>& row, std::initializer_list<const wchar_t*> names) -> std::wstring {
        return rowFieldByName(row, rawColumns, names);
    };
    const auto kAddColumnIfMissing = [](std::vector<std::wstring>& columns, const wchar_t* name) {
        if (!hasColumn(columns, name)) {
            columns.push_back(name);
        }
    };
    const auto kDisplayValue = [&](const std::vector<std::wstring>& row, const std::wstring& columnName) -> std::wstring {
        std::vector<std::wstring> aliases = columnAliases(featureId, columnName);
        if (aliases.empty()) {
            aliases.push_back(columnName);
        }
        for (const std::wstring& alias : aliases) {
            const std::wstring kValue = kRawValue(row, { alias.c_str() });
            if (!kValue.empty()) {
                return kValue;
            }
        }
        return {};
    };
    const auto kIsDataRow = [&](const std::vector<std::wstring>& row) {
        switch (featureId) {
        case KernelFeatureId::kCpuHardwareSnapshot:
            return hasNonEmptyField(row, rawColumns, { L"Brand", L"Vendor", L"FeatureMask", L"Leaf1ECX", L"项目" });
        case KernelFeatureId::kPhysicalMemoryLayout:
            return hasNonEmptyField(row, rawColumns, { L"Ranges", L"TotalBytes", L"HighestAddress", L"范围" });
        case KernelFeatureId::kMutationAudit:
            return hasNonEmptyField(row, rawColumns, { L"Seq", L"Tx", L"Operation", L"TargetKind", L"Address" });
        case KernelFeatureId::kKeyboardHotkeys:
            return hasNonEmptyField(row, rawColumns, { L"PID", L"TID", L"热键", L"Object", L"WindowObject" });
        case KernelFeatureId::kKeyboardHooks:
            return hasNonEmptyField(row, rawColumns, { L"PID", L"TID", L"Hook类型", L"Procedure", L"Object" });
        case KernelFeatureId::kDynDataCapabilities:
            return hasNonEmptyField(row, rawColumns, { L"Capability", L"CapabilityMask", L"StatusFlags", L"字段" });
        case KernelFeatureId::kMinifilterBypassPids:
            return hasNonEmptyField(row, rawColumns, { L"PID", L"Process", L"Index" });
        case KernelFeatureId::kKernelTimerDpc:
            return hasNonEmptyField(row, rawColumns, { L"Timer", L"TimerAddress", L"DPC", L"DpcAddress" });
        case KernelFeatureId::kIoctlRegistry:
            return hasNonEmptyField(row, rawColumns, { L"IOCTL", L"IoControlCode", L"Name", L"FunctionNumber" });
        default:
            return false;
        }
    };

    snapshot.columns.push_back(L"#");
    for (const std::wstring& column : canonicalColumnNames(featureId)) {
        kAddColumnIfMissing(snapshot.columns, column.c_str());
    }
    for (const std::wstring& column : rawColumns) {
        kAddColumnIfMissing(snapshot.columns, column.c_str());
    }
    kAddColumnIfMissing(snapshot.columns, L"Detail");

    std::size_t reportedTotalRows = 0;
    std::size_t reportedReturnedRows = 0;
    std::size_t totalRows = 0;
    std::size_t riskRows = 0;
    std::wstring queryStatus;
    std::wstring unsupportedText;
    std::wstring protocolVersion;
    std::wstring lastStatus;
    for (const std::vector<std::wstring>& rawRow : rawRows) {
        const std::uint64_t kTotal = firstNonZeroField(rawRow, rawColumns, { L"Total", L"TotalCount" });
        const std::uint64_t kReturned = firstNonZeroField(rawRow, rawColumns, { L"Returned", L"ReturnedCount" });
        if (kTotal != 0) {
            reportedTotalRows = static_cast<std::size_t>(kTotal);
        }
        if (kReturned != 0) {
            reportedReturnedRows = static_cast<std::size_t>(kReturned);
        }
        if (queryStatus.empty()) {
            queryStatus = kRawValue(rawRow, { L"Status", L"状态" });
        }
        if (unsupportedText.empty()) {
            unsupportedText = kRawValue(rawRow, { L"Unsupported" });
        }
        if (protocolVersion.empty()) {
            protocolVersion = kRawValue(rawRow, { L"Version", L"Protocol" });
        }
        if (lastStatus.empty()) {
            lastStatus = kRawValue(rawRow, { L"LastStatus" });
        }
    }
    snapshot.rows.reserve(rawRows.size());
    for (const std::vector<std::wstring>& rawRow : rawRows) {
        if (!kIsDataRow(rawRow)) {
            continue;
        }
        ++totalRows;
        const std::wstring kRisk = kRawValue(rawRow, { L"RiskText", L"Risk", L"FlagsText", L"Flags", L"状态", L"Status" });
        const bool kRisky = containsCaseInsensitive(kRisk, L"风险") ||
            containsCaseInsensitive(kRisk, L"异常") ||
            containsCaseInsensitive(kRisk, L"failed") ||
            containsCaseInsensitive(kRisk, L"失败") ||
            containsCaseInsensitive(kRisk, L"rejected");
        if (kRisky) {
            ++riskRows;
        }
        if (riskOnly && !kRisky) {
            continue;
        }
        if (!filterText.empty() && !containsCaseInsensitive(mergeRowText(rawRow), filterText)) {
            continue;
        }
        std::vector<std::wstring> cells(snapshot.columns.size());
        for (std::size_t column = 0; column < snapshot.columns.size(); ++column) {
            const std::wstring& name = snapshot.columns[column];
            if (name == L"#") {
                cells[column] = std::to_wstring(snapshot.rows.size());
            } else if (name == L"Detail") {
                cells[column] = kRawValue(rawRow, { L"Detail" });
            } else {
                cells[column] = kDisplayValue(rawRow, name);
            }
        }
        snapshot.rows.push_back(std::move(cells));
    }

    const std::size_t kEffectiveTotal = reportedTotalRows == 0 ? totalRows : reportedTotalRows;
    const std::size_t kEffectiveReturned = reportedReturnedRows == 0 ? totalRows : reportedReturnedRows;
    std::wostringstream status;
    status << L"状态：" << pageName << L"已刷新，显示 " << snapshot.rows.size()
           << L"，返回 " << kEffectiveReturned << L"/" << kEffectiveTotal;
    if (riskRows != 0) {
        status << L"，风险/异常 " << riskRows;
    }
    if (!queryStatus.empty()) {
        status << L"，Query " << queryStatus;
    }
    if (!unsupportedText.empty()) {
        status << L"，Unsupported " << unsupportedText;
    }
    if (!protocolVersion.empty()) {
        status << L"，Ver " << protocolVersion;
    }
    if (!lastStatus.empty()) {
        status << L"，Last " << lastStatus;
    }
    snapshot.statusText = status.str();
    return snapshot;
}

void KernelPage::rebuildR0EvidenceListFromCache(const KernelFeatureId featureId) {
    // rebuildR0EvidenceListFromCache projects remaining R0-only KernelDock pages
    // into their original fixed-column tables. Inputs are raw facade rows and
    // the local filter edit; processing applies client-side filtering so edit-box
    // changes do not discard rows; output is the visible Win32 ListView and the
    // detail pane for the selected row.
    requestR0EvidenceRebuild(featureId);
}

void KernelPage::scheduleR0EvidenceFilter(const KernelFeatureId featureId) {
    if (!hwnd_ || !isR0EvidenceFeature(featureId)) {
        return;
    }
    pendingR0EvidenceFeatureId_ = featureId;
    hasPendingR0EvidenceFilter_ = true;
    ::SetTimer(hwnd_, kTimerR0EvidenceFilter, 200, nullptr);
    if (const KernelFeatureDescriptor* descriptor = currentDescriptor(); descriptor != nullptr) {
        ::SetWindowTextW(statusText_, (L"状态：正在等待筛选输入完成（200ms）… " + descriptor->title).c_str());
    }
}

void KernelPage::requestR0EvidenceRebuild(const KernelFeatureId featureId) {
    if (!resultList_ || !isR0EvidenceFeature(featureId)) {
        return;
    }
    const KernelFeatureDescriptor* descriptor = currentDescriptor();
    if (descriptor == nullptr || descriptor->id != featureId) {
        return;
    }
    std::vector<std::wstring> rawColumns = !currentRawColumns_.empty() ? currentRawColumns_ : currentColumns_;
    std::vector<std::vector<std::wstring>> rawRows = !currentRawRows_.empty() ? currentRawRows_ : currentRows_;
    const std::wstring kFilterText = windowText(filterEdit_);
    const bool kRiskOnly = riskOnlyCheck_ && Button_GetCheck(riskOnlyCheck_) == BST_CHECKED;
    const int kSelected = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED);
    std::wstring selectedSignature = kSelected >= 0 && kSelected < static_cast<int>(currentRows_.size())
        ? mergeRowText(currentRows_[static_cast<std::size_t>(kSelected)])
        : std::wstring{};
    const int kTopRow = std::max(0, ListView_GetTopIndex(resultList_));
    std::wstring pageName = descriptor->title;
    if (!r0EvidenceFilterTask_) {
        applyR0EvidenceSnapshot(buildR0EvidenceSnapshot(featureId, pageName, rawColumns, rawRows, kFilterText,
            kRiskOnly, selectedSignature, kTopRow));
        return;
    }
    ::SetWindowTextW(statusText_, (L"状态：正在后台筛选 " + pageName + L"…").c_str());
    r0EvidenceFilterTask_->request(
        [featureId, pageName = std::move(pageName), rawColumns = std::move(rawColumns), rawRows = std::move(rawRows),
            filterText = std::move(kFilterText), kRiskOnly, selectedSignature = std::move(selectedSignature), kTopRow]() mutable {
            return buildR0EvidenceSnapshot(featureId, std::move(pageName), std::move(rawColumns), std::move(rawRows),
                std::move(filterText), kRiskOnly, std::move(selectedSignature), kTopRow);
        },
        [this](std::uint64_t, std::optional<KernelR0EvidenceSnapshot>&& snapshot, std::exception_ptr error) {
            if (error || !snapshot.has_value()) {
                ::SetWindowTextW(statusText_, L"状态：R0 证据后台筛选异常结束，保留当前结果。");
                return;
            }
            const KernelFeatureDescriptor* descriptor = currentDescriptor();
            if (descriptor == nullptr || descriptor->id != snapshot->featureId) {
                return;
            }
            applyR0EvidenceSnapshot(std::move(*snapshot));
        });
}

void KernelPage::applyR0EvidenceSnapshot(KernelR0EvidenceSnapshot snapshot) {
    if (!resultList_ || !isR0EvidenceFeature(snapshot.featureId)) {
        return;
    }
    const KernelFeatureDescriptor* descriptor = currentDescriptor();
    if (descriptor == nullptr || descriptor->id != snapshot.featureId) {
        return;
    }
    const bool kSchemaChanged = currentColumns_ != snapshot.columns;
    currentColumns_ = std::move(snapshot.columns);
    currentRows_ = std::move(snapshot.rows);
    currentRowIndents_.clear();
    if (kSchemaChanged) {
        clearResultGridOnly();
        const std::vector<std::wstring> kCanonical = canonicalColumnNames(snapshot.featureId);
        for (std::size_t index = 0; index < currentColumns_.size(); ++index) {
            const std::wstring& name = currentColumns_[index];
            int width = (name != L"#" && !hasColumn(kCanonical, name)) ? 0 : columnWidth(name);
            if (name == L"对象") width = 180;
            else if (name == L"热键ID" || name == L"进程ID" || name == L"线程ID" || name == L"Flags") width = 80;
            else if (name == L"热键" || name == L"类型" || name == L"范围" || name == L"VK/Mod") width = 130;
            else if (name == L"函数/偏移") width = 170;
            else if (name == L"详情") width = 300;
            else if (name == L"项目" || name == L"Capability") width = 170;
            else if (name == L"值" || name == L"摘要" || name == L"Features" || name == L"字段" || name == L"原因") width = 260;
            else if (name == L"Tx" || name == L"Address" || name == L"回调") width = 165;
            else if (name == L"PID" || name == L"TID" || name == L"Bytes") width = 72;
            else if (name == L"进程" || name == L"Process") width = 180;
            else if (name == L"Detail") width = 320;
            addResultTableColumn(static_cast<int>(index), name, width);
        }
    }
    syncResultListVirtualRows();
    ::SetWindowTextW(statusText_, snapshot.statusText.c_str());
    if (currentRows_.empty()) {
        ::SetWindowTextW(detailEdit_, L"当前过滤条件下没有 R0 证据记录。");
        invalidateCurrentFeatureViewCache();
        return;
    }
    int selectedRow = 0;
    if (!snapshot.selectedRowSignature.empty()) {
        const auto kFound = std::find_if(currentRows_.begin(), currentRows_.end(), [&snapshot](const auto& row) {
            return mergeRowText(row) == snapshot.selectedRowSignature;
        });
        if (kFound != currentRows_.end()) {
            selectedRow = static_cast<int>(std::distance(currentRows_.begin(), kFound));
        }
    }
    const int kTopRow = std::max(0, std::min(snapshot.topRow, static_cast<int>(currentRows_.size()) - 1));
    ListView_SetItemState(resultList_, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    ListView_SetItemState(resultList_, selectedRow, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    ListView_EnsureVisible(resultList_, kTopRow > 0 ? kTopRow : selectedRow, FALSE);
    updateSelectedRowDetail();
    invalidateCurrentFeatureViewCache();
}

void KernelPage::sortResultRowsByColumn(const int columnIndex) {
    // sortResultRowsByColumn sorts the current result cache by one visible
    // column. Input is the clicked column index; processing toggles direction
    // when clicking the same column; output is the rebuilt ListView.
    if (columnIndex < 0 || columnIndex >= static_cast<int>(currentColumns_.size()) || currentRows_.empty()) {
        return;
    }
    if (const KernelFeatureDescriptor* descriptor = currentDescriptor();
        descriptor != nullptr &&
        (descriptor->id == KernelFeatureId::kObjectNamespaceOverview ||
            descriptor->id == KernelFeatureId::kObjectDirectoryRecursive)) {
        ::SetWindowTextW(statusText_, L"状态：对象命名空间树保持目录层级顺序，未执行排序。");
        return;
    }
    if (sortColumn_ == columnIndex) {
        sortAscending_ = !sortAscending_;
    } else {
        sortColumn_ = columnIndex;
        sortAscending_ = true;
    }
    ksword::ui::ScopedListViewRedrawLock resultListLock(resultList_);
    ksword::ui::ScopedListViewRedrawLock propertyListLock(propertyList_);
    ksword::ui::ScopedListViewRedrawLock summaryListLock(summaryList_);
    ksword::ui::ScopedWindowRedrawLock objectTreeLock(objectNamespaceTree_);

    // Nearly every kernel feature table puts addresses, sizes, counts and status
    // codes in these columns, and a plain string compare orders them by their
    // printed characters: 0x2 lands after 0x1FF and 9 lands after 10. The
    // comparison is numeric whenever both cells start with a number and falls
    // back to the case-insensitive string order otherwise.
    std::stable_sort(currentRows_.begin(), currentRows_.end(), [&](const auto& left, const auto& right) {
        const std::wstring kLeftValue = columnIndex < static_cast<int>(left.size()) ? left[static_cast<std::size_t>(columnIndex)] : std::wstring{};
        const std::wstring kRightValue = columnIndex < static_cast<int>(right.size()) ? right[static_cast<std::size_t>(columnIndex)] : std::wstring{};
        const int kCompare = ksword::ui::compareCellsNumericAware(kLeftValue, kRightValue);
        return sortAscending_ ? kCompare < 0 : kCompare > 0;
    });
    syncResultListVirtualRows();
    updateSelectedRowDetail();
    invalidateCurrentFeatureViewCache();
}

void KernelPage::updateSelectedRowDetail() {
    // updateSelectedRowDetail expands the selected result row into key/value
    // text. Inputs are current selection and cached columns; processing reads
    // visible ListView text so sorted rows stay accurate; output is the read-only
    // detail edit content.
    if (!resultList_ || !detailEdit_) {
        return;
    }
    const int kRow = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED);
    if (kRow < 0) {
        ::SetWindowTextW(detailEdit_, L"");
        return;
    }
    if (const KernelFeatureDescriptor* descriptor = currentDescriptor()) {
        const std::wstring kOriginalStyleDetail = buildOriginalStyleSelectedRowDetail(descriptor->id, kRow);
        if (!kOriginalStyleDetail.empty()) {
            ::SetWindowTextW(detailEdit_, kOriginalStyleDetail.c_str());
            updatePropertyTableFromSelection();
            return;
        }
    }
    const int kColumns = headerColumnCount(resultList_);
    std::wstring detail;
    for (int column = 0; column < kColumns; ++column) {
        const std::wstring kName = column < static_cast<int>(currentColumns_.size())
            ? currentColumns_[static_cast<std::size_t>(column)]
            : std::wstring(L"Column ") + std::to_wstring(column);
        const std::wstring kValue = visibleCellText(kRow, column);
        if (kValue.empty()) {
            continue;
        }
        if (!detail.empty()) {
            detail += L"\r\n";
        }
        detail += kName;
        detail += L": ";
        detail += kValue;
    }
    ::SetWindowTextW(detailEdit_, detail.c_str());
    updatePropertyTableFromSelection();
}

LRESULT KernelPage::handleResultListCustomDraw(const LPARAM lParam) {
    // handleResultListCustomDraw colors Callback Enumeration evidence columns
    // like the original full Dock table. Input is the ListView custom-draw payload;
    // processing only changes text color for trust/status/remove-policy
    // subitems; output is the custom-draw stage directive expected by Win32.
    auto* draw = reinterpret_cast<NMLVCUSTOMDRAW*>(lParam);
    if (draw == nullptr) {
        return CDRF_DODEFAULT;
    }

    switch (draw->nmcd.dwDrawStage) {
    case CDDS_PREPAINT:
        return CDRF_NOTIFYITEMDRAW;
    case CDDS_ITEMPREPAINT:
        return CDRF_NOTIFYSUBITEMDRAW;
    case CDDS_SUBITEM | CDDS_ITEMPREPAINT:
        break;
    default:
        return CDRF_DODEFAULT;
    }

    const KernelFeatureDescriptor* descriptor = currentDescriptor();
    if (descriptor == nullptr || descriptor->id != KernelFeatureId::kCallbackEnumeration) {
        return CDRF_DODEFAULT;
    }

    const int kRow = static_cast<int>(draw->nmcd.dwItemSpec);
    const int kColumn = draw->iSubItem;
    if (kRow < 0 || kColumn < 0 || kColumn >= static_cast<int>(currentColumns_.size())) {
        return CDRF_DODEFAULT;
    }

    const std::wstring& columnName = currentColumns_[static_cast<std::size_t>(kColumn)];
    const std::wstring kValue = visibleCellText(kRow, kColumn);
    if (columnName == L"可信状态") {
        if (containsCaseInsensitive(kValue, L"可信") || containsCaseInsensitive(kValue, L"public") ||
            containsCaseInsensitive(kValue, L"pdb")) {
            draw->clrText = RGB(0x3A, 0x8F, 0x3A);
        } else if (containsCaseInsensitive(kValue, L"fallback") || containsCaseInsensitive(kValue, L"pattern") ||
            containsCaseInsensitive(kValue, L"私有")) {
            draw->clrText = RGB(0xD7, 0x7A, 0x00);
        } else if (containsCaseInsensitive(kValue, L"unsupported") || containsCaseInsensitive(kValue, L"未支持")) {
            draw->clrText = RGB(0x8A, 0x8A, 0x8A);
        }
        return CDRF_DODEFAULT;
    }

    if (columnName == L"状态") {
        if (containsCaseInsensitive(kValue, L"Query failed") || containsCaseInsensitive(kValue, L"失败")) {
            draw->clrText = RGB(0xB2, 0x3A, 0x3A);
        } else if (containsCaseInsensitive(kValue, L"Unsupported") || containsCaseInsensitive(kValue, L"未支持") ||
            containsCaseInsensitive(kValue, L"truncated")) {
            draw->clrText = RGB(0xD7, 0x7A, 0x00);
        }
        return CDRF_DODEFAULT;
    }

    if (columnName == L"移除策略") {
        if (containsCaseInsensitive(kValue, L"not removable") || containsCaseInsensitive(kValue, L"不可移除")) {
            draw->clrText = RGB(0x8A, 0x8A, 0x8A);
        } else if (containsCaseInsensitive(kValue, L"verified") || containsCaseInsensitive(kValue, L"公开") ||
            containsCaseInsensitive(kValue, L"可移除")) {
            draw->clrText = RGB(0x3A, 0x8F, 0x3A);
        } else if (containsCaseInsensitive(kValue, L"candidate") || containsCaseInsensitive(kValue, L"experimental") ||
            containsCaseInsensitive(kValue, L"候选") || containsCaseInsensitive(kValue, L"实验")) {
            draw->clrText = RGB(0xD7, 0x7A, 0x00);
        }
        return CDRF_DODEFAULT;
    }

    return CDRF_DODEFAULT;
}

std::wstring KernelPage::buildOriginalStyleSelectedRowDetail(const KernelFeatureId featureId, const int row) const {
    // buildOriginalStyleSelectedRowDetail mirrors the text bodies used by the
    // original KernelDock detail editors for SSDT/SSSDT/Inline/IAT-EAT. Input
    // is the active feature and ListView row; processing reads display columns
    // and hidden diagnostic columns; output is empty for pages that still use
    // generic key/value detail text.
    const auto kCell = [&](std::initializer_list<std::wstring> names) -> std::wstring {
        for (const std::wstring& name : names) {
            for (int column = 0; column < static_cast<int>(currentColumns_.size()); ++column) {
                if (_wcsicmp(currentColumns_[static_cast<std::size_t>(column)].c_str(), name.c_str()) == 0) {
                    const std::wstring kValue = visibleCellText(row, column);
                    if (!kValue.empty()) {
                        return kValue;
                    }
                }
            }
        }
        return {};
    };
    const auto kRawSummary = [&](std::initializer_list<const wchar_t*> names) -> std::wstring {
        const std::vector<std::wstring>& rawColumns = !currentRawColumns_.empty() ? currentRawColumns_ : currentColumns_;
        const std::vector<std::vector<std::wstring>>& rawRows = !currentRawRows_.empty() ? currentRawRows_ : currentRows_;
        for (const std::vector<std::wstring>& rawRow : rawRows) {
            const std::wstring kValue = rowFieldByName(rawRow, rawColumns, names);
            if (!kValue.empty()) {
                return kValue;
            }
        }
        return {};
    };

    switch (featureId) {
    case KernelFeatureId::kAtomTable: {
        const std::wstring kDetailText = kCell({ L"Detail" });
        if (!kDetailText.empty()) {
            return kDetailText;
        }
        std::wostringstream detail;
        detail << L"Atom值: " << kCell({ L"Atom值", L"Id" }) << L" (" << kCell({ L"十六进制", L"Hex" }) << L")\r\n"
               << L"名称: " << kCell({ L"名称", L"Name" }) << L"\r\n"
               << L"来源: " << kCell({ L"来源", L"Source", L"Kind" }) << L"\r\n"
               << L"状态: " << kCell({ L"状态", L"Status" }) << L"\r\n";
        return detail.str();
    }
    case KernelFeatureId::kNtQueryLegacy: {
        std::wostringstream detail;
        detail << L"类别: " << kCell({ L"类别", L"Category" }) << L"\r\n"
               << L"函数: " << kCell({ L"函数", L"Function" }) << L"\r\n"
               << L"查询项: " << kCell({ L"查询项", L"Class", L"InfoClass", L"Ordinal", L"RVA" }) << L"\r\n"
               << L"状态: " << kCell({ L"状态", L"Status" }) << L"\r\n"
               << L"摘要: " << kCell({ L"摘要", L"Detail" }) << L"\r\n\r\n"
               << L"详细输出:\r\n" << kCell({ L"Detail" });
        return detail.str();
    }
    case KernelFeatureId::kObjectDirectoryRecursive: {
        std::wostringstream detail;
        detail << L"[Object Manager Directory Recursive Entry]\r\n"
               << L"RootPath: " << windowText(filterEdit_) << L"\r\n"
               << L"DirectoryPath: " << kCell({ L"Parent", L"Directory", L"Source" }) << L"\r\n"
               << L"ObjectName: " << kCell({ L"名称", L"Name", L"objectName" }) << L"\r\n"
               << L"ObjectType: " << kCell({ L"类型", L"Type", L"objectType" }) << L"\r\n"
               << L"FullPath: " << kCell({ L"Path", L"完整路径", L"fullPath" }) << L"\r\n"
               << L"Depth: " << kCell({ L"深度", L"Depth" }) << L"\r\n"
               << L"IsDirectory: " << (_wcsicmp(kCell({ L"类型", L"Type" }).c_str(), L"Directory") == 0 ? L"true" : L"false") << L"\r\n"
               << L"QuerySucceeded: " << (kCell({ L"状态", L"Status" }).empty() ? L"false" : L"true") << L"\r\n"
               << L"Status: " << kCell({ L"状态", L"Status", L"statusText" }) << L"\r\n";
        return detail.str();
    }
    case KernelFeatureId::kBaseNamedObjects: {
        std::wostringstream detail;
        detail << L"BaseNamedObjects Entry\r\n"
               << L"----------------------------------------\r\n"
               << L"scope: " << kCell({ L"scope", L"Source" }) << L"\r\n"
               << L"directoryPath: " << kCell({ L"directoryPath", L"Parent", L"Directory" }) << L"\r\n"
               << L"objectName: " << kCell({ L"objectName", L"Name" }) << L"\r\n"
               << L"objectType: " << kCell({ L"objectType", L"Type" }) << L"\r\n"
               << L"fullPath: " << kCell({ L"fullPath", L"Path" }) << L"\r\n"
               << L"symbolicTarget: " << kCell({ L"symbolicTarget", L"targetPath", L"Target", L"目标路径", L"符号链接目标" }) << L"\r\n"
               << L"statusText: " << kCell({ L"statusText", L"Status" }) << L"\r\n";
        return detail.str();
    }
    case KernelFeatureId::kCommunicationEndpoint: {
        std::wostringstream detail;
        detail << L"Communication Endpoint Entry\r\n"
               << L"----------------------------------------\r\n"
               << L"来源目录: " << kCell({ L"来源目录", L"Source", L"Parent", L"Directory", L"directoryPath", L"sourceDirectory" }) << L"\r\n"
               << L"名称: " << kCell({ L"名称", L"Name", L"objectName" }) << L"\r\n"
               << L"类型: " << kCell({ L"类型", L"Type", L"objectType" }) << L"\r\n"
               << L"完整路径: " << kCell({ L"完整路径", L"Path", L"fullPath" }) << L"\r\n"
               << L"状态: " << kCell({ L"状态", L"Status" }) << L"\r\n";
        return detail.str();
    }
    case KernelFeatureId::kObjectNamespaceOverview: {
    const std::wstring kName = kCell({ L"名称", L"Name", L"objectName" });
    const std::wstring kType = kCell({ L"类型", L"Type", L"objectType" });
    const std::wstring kPath = kCell({ L"Path", L"完整路径", L"fullPath", L"路径/说明" });
    const std::wstring kParent = kCell({ L"Parent", L"directoryPath", L"来源目录", L"Source" });
    const std::wstring kStatus = kCell({ L"状态", L"Status", L"statusText" });
    const std::wstring kTarget = kCell({ L"Target", L"符号链接目标", L"symbolicTarget", L"targetPath" });
        const std::wstring kNodeKind = kCell({ L"NodeKind" });
        std::wostringstream detail;
        if (_wcsicmp(kNodeKind.c_str(), L"Root") == 0) {
            detail << L"对象命名空间根节点\r\n"
                   << L"----------------------------------------\r\n"
                   << L"节点名称: " << kName << L"\r\n"
                   << L"节点类型: " << kType << L"\r\n"
                   << L"节点路径: " << kPath << L"\r\n"
                   << L"节点说明: " << kCell({ L"Detail", L"路径/说明" }) << L"\r\n"
                   << L"提示: 当前节点是树层级摘要，展开下级并选择对象项可查看完整字段。\r\n";
            return detail.str();
        }
        if (_wcsicmp(kNodeKind.c_str(), L"Directory") == 0) {
            detail << L"对象命名空间目录节点\r\n"
                   << L"----------------------------------------\r\n"
                   << L"节点名称: " << kName << L"\r\n"
                   << L"节点类型: " << kType << L"\r\n"
                   << L"节点路径: " << kPath << L"\r\n"
                   << L"根目录: " << kParent << L"\r\n"
                   << L"节点说明: " << kCell({ L"Detail", L"路径/说明" }) << L"\r\n"
                   << L"提示: 当前节点是树层级摘要，展开下级并选择对象项可查看完整字段。\r\n";
            return detail.str();
        }
        detail << L"对象命名空间详情\r\n"
               << L"----------------------------------------\r\n"
               << L"名称: " << kName << L"\r\n"
               << L"类型: " << kType << L"\r\n"
               << L"完整路径: " << kPath << L"\r\n"
               << L"父目录/来源: " << kParent << L"\r\n"
               << L"符号链接目标: " << kTarget << L"\r\n"
               << L"句柄数: " << kCell({ L"Handles" }) << L"\r\n"
               << L"引用数: " << kCell({ L"Pointers" }) << L"\r\n"
               << L"状态: " << kStatus << L"\r\n\r\n"
               << L"操作: 右键可复制对象字段、复制同目录路径、按目录/对象名过滤或尝试映射 DOS 路径。";
        return detail.str();
    }
    case KernelFeatureId::kNamedPipe: {
        std::wostringstream detail;
        detail << L"命名管道详情\r\n"
               << L"----------------------------------------\r\n"
               << L"Pipe Name: " << kCell({ L"Pipe Name", L"Pipe", L"Name" }) << L"\r\n"
               << L"NT Path: " << kCell({ L"NT Path", L"NtPath", L"Path" }) << L"\r\n"
               << L"Win32 Path: " << kCell({ L"Win32Path" }) << L"\r\n"
               << L"Attributes: " << kCell({ L"Attributes" }) << L"\r\n"
               << L"LastWriteTime: " << kCell({ L"LastWriteTime", L"LastWrite" }) << L"\r\n"
               << L"Status: " << kCell({ L"Status" }) << L"\r\n"
               << L"Source: " << kCell({ L"Source", L"Directory" }) << L"\r\n\r\n"
               << L"操作: 右键可用 NtOpenFile 只读属性打开验证，不读写管道数据。";
        return detail.str();
    }
    case KernelFeatureId::kSymbolicLink: {
        std::wostringstream detail;
        detail << L"符号链接详情\r\n"
               << L"----------------------------------------\r\n"
               << L"来源目录: " << kCell({ L"sourceDirectory", L"Source", L"Parent" }) << L"\r\n"
               << L"链接名: " << kCell({ L"linkName", L"objectName", L"Name", L"名称" }) << L"\r\n"
               << L"完整路径: " << kCell({ L"fullPath", L"Path", L"完整路径" }) << L"\r\n"
               << L"目标路径: " << kCell({ L"targetPath", L"symbolicTarget", L"Target", L"目标路径", L"符号链接目标" }) << L"\r\n"
               << L"DOS 候选: " << kCell({ L"dosCandidate", L"Win32Path" }) << L"\r\n"
               << L"状态: " << kCell({ L"statusText", L"Status" }) << L"\r\n\r\n"
               << L"操作: 右键可复制单元格、targetPath、dosCandidate、整行，或按目标路径过滤。";
        return detail.str();
    }
    case KernelFeatureId::kDeviceDriverObjects: {
        std::wostringstream detail;
        detail << L"设备/驱动对象详情\r\n"
               << L"----------------------------------------\r\n"
               << L"目录路径: " << kCell({ L"目录路径", L"Parent", L"Directory", L"Source" }) << L"\r\n"
               << L"对象名称: " << kCell({ L"对象名称", L"objectName", L"Name", L"DriverName" }) << L"\r\n"
               << L"对象类型: " << kCell({ L"对象类型", L"objectType", L"Type" }) << L"\r\n"
               << L"完整路径: " << kCell({ L"完整路径", L"fullPath", L"Path" }) << L"\r\n"
               << L"目标路径: " << kCell({ L"目标路径", L"targetPath", L"symbolicTarget", L"Target" }) << L"\r\n"
               << L"状态: " << kCell({ L"状态", L"Status" }) << L"\r\n"
               << L"能力提示: " << kCell({ L"能力提示", L"Capability", L"Detail" }) << L"\r\n\r\n"
               << L"操作: 右键可复制单元格、当前行、可见结果 TSV，或导出 TSV。";
        return detail.str();
    }
    case KernelFeatureId::kObjectTypeMatrix: {
        std::wostringstream detail;
        detail << L"对象类型矩阵详情\r\n"
               << L"----------------------------------------\r\n"
               << L"类型编号: " << kCell({ L"类型编号", L"TypeIndex", L"Index" }) << L"\r\n"
               << L"类型名: " << kCell({ L"类型名", L"Type" }) << L"\r\n"
               << L"对象数: " << kCell({ L"对象数", L"Objects" }) << L"\r\n"
               << L"句柄数: " << kCell({ L"句柄数", L"Handles" }) << L"\r\n"
               << L"访问掩码: " << kCell({ L"访问掩码", L"ValidAccess" }) << L"\r\n"
               << L"枚举策略: " << kCell({ L"枚举策略", L"Detail", L"Status" }) << L"\r\n";
        return detail.str();
    }
    case KernelFeatureId::kSsdt: {
        const std::wstring kOriginalDetailText = kCell({ L"Detail" });
        if (!kOriginalDetailText.empty() && kOriginalDetailText.find(L"服务索引:") == 0) {
            return kOriginalDetailText;
        }
        std::wostringstream detail;
        detail << L"服务索引: " << kCell({ L"索引", L"Index" }) << L"\r\n"
               << L"服务名: " << kCell({ L"服务名", L"Name", L"ServiceName" }) << L"\r\n"
               << L"模块: " << kCell({ L"模块", L"Module" }) << L"\r\n"
               << L"Zw导出地址: " << kCell({ L"Zw导出地址", L"Zw" }) << L"\r\n"
               << L"服务表基址: " << kCell({ L"ServiceTable", L"ServiceTableBase" }) << L"\r\n"
               << L"表项服务地址: " << kCell({ L"表项地址", L"Service", L"ServiceAddress" }) << L"\r\n"
               << L"状态: " << kCell({ L"状态", L"Status" }) << L"\r\n"
               << L"标志: " << kCell({ L"Flags" }) << L"\r\n\r\n"
               << L"Worker详情:\r\n" << kCell({ L"Detail", L"FlagsText" });
        return detail.str();
    }
    case KernelFeatureId::kShadowSsdt: {
        const std::wstring kOriginalDetailText = kCell({ L"Detail" });
        if (!kOriginalDetailText.empty() && kOriginalDetailText.find(L"SSSDT/Shadow SSDT 解析") == 0) {
            return kOriginalDetailText;
        }
        std::wostringstream detail;
        detail << L"SSSDT/Shadow SSDT 解析\r\n"
               << L"协议版本: " << kCell({ L"Version" }) << L"\r\n"
               << L"总条目: " << kCell({ L"Total" }) << L"\r\n"
               << L"返回条目: " << kCell({ L"Returned" }) << L"\r\n"
               << L"服务名: " << kCell({ L"服务名", L"Name", L"ServiceName" }) << L"\r\n"
               << L"模块: " << kCell({ L"模块", L"Module" }) << L"\r\n"
               << L"服务索引: " << kCell({ L"索引", L"Index" }) << L"\r\n"
               << L"Stub地址: " << kCell({ L"Stub地址", L"Zw", L"Stub" }) << L"\r\n"
               << L"Shadow服务表基址: " << kCell({ L"ServiceTable", L"ServiceTableBase" }) << L"\r\n"
               << L"服务例程地址: " << kCell({ L"服务地址", L"Service", L"ServiceAddress" }) << L"\r\n"
               << L"驱动标志: " << kCell({ L"Flags" }) << L"\r\n\r\n"
               << L"说明: 当前 R0 参考 System Informer 的 ksyscall 思路，从 win32k.sys 的 __win32kstub_* 和 win32u.dll 的 Nt* stub 中解析 syscall index。"
               << L"若已应用包含 KeServiceDescriptorTableShadow 的 PDB/DynData profile，会继续解析 shadow service table 实际表项；服务例程地址为 0 表示 profile 缺失、身份不匹配或表项暂不可读。";
        return detail.str();
    }
    case KernelFeatureId::kInlineHook: {
        const std::wstring kOriginalDetailText = kCell({ L"Detail" });
        if (!kOriginalDetailText.empty() && kOriginalDetailText.find(L"Inline Hook 检测详情") == 0) {
            return kOriginalDetailText;
        }
        std::wostringstream detail;
        detail << L"Inline Hook 检测详情\r\n"
               << L"模块: " << kCell({ L"模块", L"Module" }) << L"\r\n"
               << L"函数: " << kCell({ L"函数", L"Function" }) << L"\r\n"
               << L"函数地址: " << kCell({ L"函数地址", L"Address" }) << L"\r\n"
               << L"Hook类型: " << kCell({ L"Hook类型", L"TypeText", L"Type" }) << L"\r\n"
               << L"目标地址: " << kCell({ L"目标地址", L"Target" }) << L"\r\n"
               << L"目标模块: " << kCell({ L"目标模块", L"TargetModule" }) << L"\r\n"
               << L"状态: " << kCell({ L"状态", L"Status" }) << L"\r\n"
               << L"模块基址: " << kCell({ L"ModuleBase" }) << L"\r\n"
               << L"目标模块基址: " << kCell({ L"TargetModuleBase" }) << L"\r\n"
               << L"当前内存字节(" << kCell({ L"CurrentByteCount" }) << L"): " << kCell({ L"当前字节", L"CurrentBytes" }) << L"\r\n"
               << L"R0 观察基线(" << kCell({ L"OriginalByteCount" }) << L"): " << kCell({ L"ExpectedBytes" }) << L"\r\n"
               << L"磁盘基线字节: " << kCell({ L"磁盘字节", L"DiskBytes" }) << L"\r\n"
               << L"差异状态: " << kCell({ L"差异", L"DiskDiff" }) << L"\r\n"
               << L"标志: " << kCell({ L"Flags" }) << L"\r\n\r\n"
               << L"说明: 当前协议字段 expectedBytes 在 R0 中来自内存观察，通常是 currentBytes 的同源快照，不代表磁盘原始字节。"
               << L"摘除操作保持原有 NOP 流程，不新增自动修复能力。";
        return detail.str();
    }
    case KernelFeatureId::kIatEatHook: {
        const std::wstring kOriginalDetailText = kCell({ L"Detail" });
        if (!kOriginalDetailText.empty() && kOriginalDetailText.find(L"IAT/EAT Hook 检测详情") == 0) {
            return kOriginalDetailText;
        }
        std::wostringstream detail;
        detail << L"IAT/EAT Hook 检测详情\r\n"
               << L"类别: " << kCell({ L"类别", L"ClassText", L"Class" }) << L"\r\n"
               << L"模块: " << kCell({ L"模块", L"Module" }) << L"\r\n"
               << L"导入模块: " << kCell({ L"导入模块", L"Import", L"ImportModule" }) << L"\r\n"
               << L"函数/序号: " << kCell({ L"函数", L"Function" }) << L" / #" << kCell({ L"Ordinal" }) << L"\r\n"
               << L"Thunk/EAT项: " << kCell({ L"Thunk地址", L"Thunk", L"ThunkAddress" }) << L"\r\n"
               << L"当前目标: " << kCell({ L"当前目标", L"Current", L"CurrentTarget" }) << L"\r\n"
               << L"期望目标: " << kCell({ L"期望目标", L"Expected", L"ExpectedTarget" }) << L"\r\n"
               << L"目标模块: " << kCell({ L"目标模块", L"TargetModule" }) << L"\r\n"
               << L"所属模块基址: " << kCell({ L"ModuleBase" }) << L"\r\n"
               << L"目标模块基址: " << kCell({ L"TargetModuleBase" }) << L"\r\n"
               << L"状态: " << kCell({ L"状态", L"Status" }) << L"\r\n"
               << L"标志: " << kCell({ L"Flags" }) << L"\r\n\r\n"
               << L"说明: IAT 检测比较 thunk 当前目标是否仍落在声明导入模块内；EAT 检测导出 RVA 是否落在自身映像或转发导出区域内。";
        return detail.str();
    }
    case KernelFeatureId::kCallbackEnumeration: {
        const auto kYesNo = [](const std::wstring& value) -> const wchar_t* {
            return (!value.empty() && value != L"0" && _wcsicmp(value.c_str(), L"false") != 0) ? L"是" : L"否";
        };
        const std::wstring kTrustText = kCell({ L"可信状态", L"SourceTrust", L"TrustText" });
        const bool kFallbackOnly = kTrustText.find(L"fallback") != std::wstring::npos ||
            kTrustText.find(L"pattern") != std::wstring::npos ||
            kTrustText.find(L"Fallback") != std::wstring::npos;
        const bool kSecondConfirm = kCell({ L"移除策略", L"RemovePolicy" }).find(L"experimental") != std::wstring::npos ||
            kCell({ L"移除策略", L"RemovePolicy" }).find(L"候选") != std::wstring::npos;
        std::wostringstream detail;
        detail << L"类别: " << kCell({ L"类别", L"ClassText", L"Class" }) << L"\r\n"
               << L"来源: " << kCell({ L"来源", L"SourceText", L"Source" }) << L"\r\n"
               << L"可信状态: " << kTrustText << L"\r\n"
               << L"移除策略: " << kCell({ L"移除策略", L"RemovePolicy" }) << L"\r\n"
               << L"是否需要二次确认: " << kYesNo(kSecondConfirm ? L"1" : L"0") << L"\r\n"
               << L"当前来源是否只是 fallback/pattern: " << kYesNo(kFallbackOnly ? L"1" : L"0") << L"\r\n"
               << L"状态: " << kCell({ L"状态", L"Status" }) << L"\r\n"
               << L"名称: " << kCell({ L"名称", L"Name" }) << L"\r\n"
               << L"Altitude: " << kCell({ L"Altitude" }) << L"\r\n"
               << L"主地址显示: " << kCell({ L"回调/对象地址", L"Callback", L"Object", L"Registration", L"RawStorageValue" }) << L"\r\n"
               << L"真实回调地址: " << kCell({ L"Callback" }) << L"\r\n"
               << L"上下文/诊断值: " << kCell({ L"Context" }) << L"\r\n"
               << L"注册句柄/Cookie/全局节点: " << kCell({ L"Registration" }) << L"\r\n"
               << L"模块路径: " << kCell({ L"模块", L"ModulePath", L"Module" }) << L"\r\n"
               << L"Win32模块路径: " << kCell({ L"Win32ModulePath" }) << L"\r\n"
               << L"模块基址: " << kCell({ L"ModuleBase" }) << L"\r\n"
               << L"模块大小: " << kCell({ L"ModuleSize" }) << L"\r\n"
               << L"操作掩码: " << kCell({ L"OperationMask" }) << L"\r\n"
               << L"对象类型掩码: " << kCell({ L"ObjectTypeMask" }) << L"\r\n"
               << L"字段标志: " << kCell({ L"FieldFlags" }) << L"\r\n"
               << L"可信标志(预留): " << kCell({ L"Trust" }) << L"\r\n"
               << L"移除行为(预留): " << kCell({ L"Remove" }) << L"\r\n"
               << L"移除标志(预留): " << kCell({ L"RemoveFlags" }) << L"\r\n"
               << L"Generation(预留): " << kCell({ L"Generation" }) << L"\r\n"
               << L"IdentityHash(预留): " << kCell({ L"IdentityHash" }) << L"\r\n"
               << L"RawStorageValue(预留): " << kCell({ L"RawStorageValue" }) << L"\r\n"
               << L"LastStatus: " << kCell({ L"LastStatus" }) << L"\r\n\r\n"
               << L"说明: 主地址显示会优先显示真实回调函数；定位/诊断行没有真实回调函数时显示全局数组、链表节点、标识符或诊断值。"
               << L"旧协议尚未返回 generation/identity hash/raw storage value 时保持 0 或空值；实验 unlink 仅为 UI 预留，不作为默认路径。\r\n\r\n"
               << L"详情:\r\n" << kCell({ L"Detail", L"FieldText", L"TrustText", L"RemoveText" });
        return detail.str();
    }
    case KernelFeatureId::kDynData: {
        std::uint64_t fieldMask = 0;
        std::uint64_t globalMask = 0;
        hexToUInt64(kCell({ L"Capability", L"CapabilityMask", L"Mask" }), fieldMask);
        hexToUInt64(kRawSummary({ L"CapabilityMask", L"DynDataCapability", L"Mask" }), globalMask);
        const std::wstring kGlobalMaskText = globalMask != 0 ? hexTextPadded(globalMask, 16) : kRawSummary({ L"CapabilityMask", L"DynDataCapability", L"Mask" });
        std::wostringstream detail;
        detail << L"字段名: " << kCell({ L"字段", L"Field", L"Name" }) << L"\r\n"
               << L"字段ID: " << kCell({ L"Id", L"FieldId" }) << L"\r\n"
               << L"偏移: " << kCell({ L"偏移", L"Offset" }) << L"\r\n"
               << L"状态: " << kCell({ L"状态", L"Status", L"DynData Fields IO" }) << L"\r\n"
               << L"来源: " << kCell({ L"来源", L"Source" }) << L"\r\n"
               << L"功能: " << kCell({ L"功能", L"Feature" }) << L"\r\n"
               << L"字段标志: " << kCell({ L"Flags" }) << L"\r\n"
               << L"字段能力位: " << (fieldMask != 0 ? hexTextPadded(fieldMask, 16) : kCell({ L"Capability", L"CapabilityMask", L"Mask" })) << L"\r\n"
               << L"字段能力名: " << dynCapabilityNames(fieldMask) << L"\r\n\r\n"
               << L"当前全局能力位: " << kGlobalMaskText << L"\r\n"
               << L"当前未启用能力: " << disabledDynCapabilitySummary(globalMask) << L"\r\n\r\n"
               << L"R0不可用原因: " << kRawSummary({ L"UnavailableReason", L"Reason", L"Detail" }) << L"\r\n\r\n"
               << L"StatusFlags: " << kRawSummary({ L"StatusFlags" }) << L" (" << dynDataStatusFlagsText(static_cast<std::uint32_t>(firstRowUInt64(!currentRawRows_.empty() ? currentRawRows_ : currentRows_, !currentRawColumns_.empty() ? currentRawColumns_ : currentColumns_, { L"StatusFlags" }))) << L")\r\n"
               << L"SystemInformerDataVersion: " << kRawSummary({ L"SI Version" }) << L"\r\n"
               << L"SystemInformerDataLength: " << kRawSummary({ L"SI Length" }) << L"\r\n"
               << L"MatchedProfileClass: " << kRawSummary({ L"MatchedClass", L"ProfileClass" }) << L"\r\n"
               << L"MatchedProfileOffset: " << kRawSummary({ L"MatchedProfileOffset" }) << L"\r\n"
               << L"MatchedFieldsId: " << kRawSummary({ L"MatchedFieldsId" }) << L"\r\n"
               << L"ntoskrnl: " << kRawSummary({ L"Ntos", L"NtosIdentity" }) << L"\r\n"
               << L"lxcore: " << kRawSummary({ L"Lxcore", L"LxcoreIdentity" });
        return detail.str();
    }
    case KernelFeatureId::kDriverStatus: {
        std::uint64_t requiredDyn = 0;
        std::uint64_t presentDyn = 0;
        std::uint64_t globalDyn = 0;
        std::uint64_t featureFlags64 = 0;
        std::uint64_t requiredPolicy64 = 0;
        std::uint64_t deniedPolicy64 = 0;
        std::uint64_t stateId64 = 0;
        hexToUInt64(kCell({ L"所需DynData", L"RequiredDyn" }), requiredDyn);
        hexToUInt64(kCell({ L"已满足DynData", L"PresentDyn" }), presentDyn);
        hexToUInt64(kRawSummary({ L"DynDataCapability", L"CapabilityMask" }), globalDyn);
        hexToUInt64(kCell({ L"Flags" }), featureFlags64);
        hexToUInt64(kCell({ L"策略", L"Policy", L"RequiredPolicy" }), requiredPolicy64);
        hexToUInt64(kCell({ L"DeniedPolicy" }), deniedPolicy64);
        hexToUInt64(kCell({ L"StateId" }), stateId64);
        const std::uint32_t kFeatureFlags = static_cast<std::uint32_t>(featureFlags64);
        const std::uint32_t kRequiredPolicy = static_cast<std::uint32_t>(requiredPolicy64);
        const std::uint32_t kDeniedPolicy = static_cast<std::uint32_t>(deniedPolicy64);
        const std::uint32_t kDynStatusFlags = static_cast<std::uint32_t>(firstRowUInt64(!currentRawRows_.empty() ? currentRawRows_ : currentRows_, !currentRawColumns_.empty() ? currentRawColumns_ : currentColumns_, { L"DynDataStatus" }));
        std::wostringstream detail;
        detail << L"功能: " << kCell({ L"功能", L"Feature", L"Name", L"项目" }) << L"\r\n"
               << L"FeatureId: " << kCell({ L"Id" }) << L"\r\n"
               << L"状态: " << featureStateText(static_cast<std::uint32_t>(stateId64), kCell({ L"状态", L"State", L"Status", L"值" })) << L"\r\n"
               << L"功能标志: " << (featureFlags64 != 0 ? hexTextPadded(kFeatureFlags, 8) : kCell({ L"Flags" })) << L" (" << featureFlagNames(kFeatureFlags) << L")\r\n\r\n"
               << L"依赖字段: " << kCell({ L"依赖字段", L"Fields", L"Dependency" }) << L"\r\n"
               << L"状态原因: " << kCell({ L"原因", L"Reason", L"Detail" }) << L"\r\n\r\n"
               << L"所需安全策略: " << hexTextPadded(kRequiredPolicy, 8) << L" (" << securityPolicyNames(kRequiredPolicy) << L")\r\n"
               << L"被拒绝策略位: " << hexTextPadded(kDeniedPolicy, 8) << L" (" << securityPolicyNames(kDeniedPolicy) << L")\r\n"
               << L"所需 DynData capability: " << hexTextPadded(requiredDyn, 16) << L" (" << dynCapabilityNames(requiredDyn) << L")\r\n"
               << L"已满足 DynData capability: " << hexTextPadded(presentDyn, 16) << L" (" << dynCapabilityNames(presentDyn) << L")\r\n"
               << L"全局 DynData capability: " << hexTextPadded(globalDyn, 16) << L" (" << dynCapabilityNames(globalDyn) << L")\r\n\r\n"
               << L"当前内核: " << kRawSummary({ L"NtosIdentity", L"Ntos" }) << L"\r\n"
               << L"识别版本: " << kRawSummary({ L"LocalPdbVersion", L"KernelVersion" }) << L"\r\n"
               << L"本地 PDB profile: " << kRawSummary({ L"LocalPdbProfile", L"LocalPdbMessage" }) << L"\r\n"
               << L"ActiveProcessLinks 偏移: " << kRawSummary({ L"ActiveProcessLinksOffset" }) << L"\r\n"
               << L"可信偏移: " << kRawSummary({ L"TrustedOffset" }) << L"\r\n"
               << L"字段覆盖: " << kRawSummary({ L"FieldCoverage" }) << L"\r\n"
               << L"字段来源: " << kRawSummary({ L"FieldSources" }) << L"\r\n\r\n"
               << L"驱动状态: " << kRawSummary({ L"StatusBadges", L"StatusFlags" }) << L"\r\n"
               << L"DynDataStatus: " << kRawSummary({ L"DynDataStatus" }) << L" (" << dynDataStatusFlagsText(kDynStatusFlags) << L")\r\n"
               << L"最近 R0 错误: " << kRawSummary({ L"LastErrorStatus" }) << L" / " << kRawSummary({ L"LastError" }) << L" / " << kRawSummary({ L"LastErrorSummary" });
        return detail.str();
    }
    case KernelFeatureId::kKernelExecutableMemory: {
        std::wostringstream detail;
        detail << L"内核可执行页扫描详情\r\n"
               << L"VA: " << kCell({ L"VA" }) << L"\r\n"
               << L"RegionSize: " << kCell({ L"RegionSize" }) << L"\r\n"
               << L"PageCount: " << kCell({ L"页数", L"Pages" }) << L"\r\n"
               << L"PageSize: " << kCell({ L"页大小", L"PageSize" }) << L"\r\n"
               << L"Permissions: " << kCell({ L"权限", L"PermText" }) << L" (" << kCell({ L"Perm" }) << L")\r\n"
               << L"RiskFlags: " << kCell({ L"风险标志", L"RiskText" }) << L" (" << kCell({ L"Risk" }) << L")\r\n"
               << L"Status: " << kCell({ L"Status" }) << L"\r\n"
               << L"LastStatus: " << kCell({ L"LastStatus" }) << L"\r\n"
               << L"OwnerKind: " << kCell({ L"OwnerKind" }) << L"\r\n"
               << L"Owner: " << kCell({ L"Owner", L"OwnerKindText" }) << L"\r\n"
               << L"OwnerAddress: " << kCell({ L"OwnerAddress" }) << L"\r\n"
               << L"ModuleBase: " << kCell({ L"ModuleBase" }) << L"\r\n"
               << L"ModuleSize: " << kCell({ L"ModuleSize" }) << L"\r\n"
               << L"ModulePath: " << kCell({ L"模块路径", L"ModulePath", L"Module" }) << L"\r\n";
        const std::wstring kR0Detail = kCell({ L"Detail" });
        if (!kR0Detail.empty()) {
            detail << L"\r\nR0 Detail:\r\n" << kR0Detail << L"\r\n";
        }
        return detail.str();
    }
    case KernelFeatureId::kKernelMemoryEvidence: {
        std::wostringstream detail;
        detail << L"内核内存证据详情\r\n"
               << L"Address: " << kCell({ L"VA" }) << L"\r\n"
               << L"RegionSize: " << kCell({ L"RegionSize" }) << L" (" << kCell({ L"大小", L"SizeText" }) << L")\r\n"
               << L"EvidenceKind: " << kCell({ L"类型", L"KindText" }) << L"\r\n"
               << L"OwnerKind: " << kCell({ L"OwnerKindText" }) << L"\r\n"
               << L"OwnerName: " << kCell({ L"Owner" }) << L"\r\n"
               << L"OwnerAddress: " << kCell({ L"OwnerAddress" }) << L"\r\n"
               << L"ModuleBase: " << kCell({ L"ModuleBase" }) << L"\r\n"
               << L"ModuleSize: " << kCell({ L"ModuleSize" }) << L" (" << kCell({ L"ModuleSizeText" }) << L")\r\n"
               << L"PermissionFlags: " << kCell({ L"PTE权限", L"PermText" }) << L" (" << kCell({ L"Perm" }) << L")\r\n"
               << L"RiskFlags: " << kCell({ L"风险", L"RiskText" }) << L" (" << kCell({ L"Risk" }) << L")\r\n"
               << L"BigPoolTag: " << kCell({ L"BigPoolTag" }) << L"\r\n"
               << L"BigPoolFlags: " << kCell({ L"BigPoolFlags" }) << L"\r\n"
               << L"Section: " << kCell({ L"Section" }) << L" RVA=" << kCell({ L"SectionRva" }) << L" Size=" << kCell({ L"SectionSizeText", L"SectionSize" }) << L"\r\n"
               << L"Hash: " << kCell({ L"text hash/diff", L"HashText", L"Hash" }) << L"\r\n"
               << L"SampleSize: " << kCell({ L"SampleSize" }) << L"\r\n";
        const std::wstring kSample = kCell({ L"Sample" });
        if (!kSample.empty()) {
            detail << L"Sample: " << kSample << L"\r\n";
        }
        detail << L"Confidence: " << kCell({ L"Confidence" }) << L"\r\n"
               << L"LastStatus: " << kCell({ L"LastStatus" }) << L"\r\n"
               << L"Detail: " << kCell({ L"Detail" }) << L"\r\n";
        return detail.str();
    }
    case KernelFeatureId::kProcessCrossView:
    {
        std::wostringstream detail;
        detail << L"进程 Cross-View 详情\r\n"
               << L"PID: " << kCell({ L"PID", L"ID" }) << L" PPID: " << kCell({ L"PPID" }) << L" Image: " << kCell({ L"Image", L"进程" }) << L"\r\n"
               << L"ProcessObject: " << kCell({ L"ProcessObject", L"对象", L"Object" }) << L"\r\n"
               << L"StartAddress: " << kCell({ L"StartAddress", L"Start" }) << L"\r\n"
               << L"SourceMask: " << kCell({ L"SourceMask" }) << L"\r\n"
               << L"AnomalyFlags: " << kCell({ L"异常", L"AnomalyText" }) << L" (" << kCell({ L"Anomaly" }) << L")\r\n"
               << L"DynDataCapabilityMask: " << kCell({ L"DynDataCapabilityMask", L"DynData" }) << L"\r\n"
               << L"EPROCESS.UniqueProcessId: " << kCell({ L"EP.UniqueProcessId" }) << L"\r\n"
               << L"EPROCESS.ActiveProcessLinks: " << kCell({ L"EP.ActiveProcessLinks" }) << L"\r\n"
               << L"EPROCESS.ThreadListHead: " << kCell({ L"EP.ThreadListHead" }) << L"\r\n"
               << L"EPROCESS.ImageFileName: " << kCell({ L"EP.ImageFileName" }) << L"\r\n"
               << L"ETHREAD.Cid: " << kCell({ L"ET.Cid" }) << L"\r\n"
               << L"ETHREAD.ThreadListEntry: " << kCell({ L"ET.ThreadListEntry" }) << L"\r\n"
               << L"ETHREAD.StartAddress: " << kCell({ L"ET.StartAddress" }) << L"\r\n"
               << L"KTHREAD.Process: " << kCell({ L"KT.Process" }) << L"\r\n"
               << L"PspCidTableRva: " << kCell({ L"PspCidTableRva" }) << L"\r\n"
               << L"PspCidTableAddress: " << kCell({ L"PspCidTable" }) << L"\r\n"
               << L"LastStatus: " << kCell({ L"LastStatus" }) << L"\r\n"
               << L"Confidence: " << kCell({ L"置信度", L"Confidence" }) << L"\r\n"
               << L"Detail: " << kCell({ L"Detail" }) << L"\r\n";
        return detail.str();
    }
    case KernelFeatureId::kThreadCrossView:
    {
        std::wostringstream detail;
        detail << L"线程 Cross-View 详情\r\n"
               << L"TID: " << kCell({ L"TID", L"ID" }) << L" PID: " << kCell({ L"PID" }) << L" Image: " << kCell({ L"Image" }) << L"\r\n"
               << L"ThreadObject: " << kCell({ L"ThreadObject", L"对象", L"Object" }) << L"\r\n"
               << L"ProcessObject: " << kCell({ L"ProcessObject" }) << L"\r\n"
               << L"StartAddress: " << kCell({ L"StartAddress", L"Start" }) << L"\r\n"
               << L"SourceMask: " << kCell({ L"SourceMask" }) << L"\r\n"
               << L"AnomalyFlags: " << kCell({ L"异常", L"AnomalyText" }) << L" (" << kCell({ L"Anomaly" }) << L")\r\n"
               << L"DynDataCapabilityMask: " << kCell({ L"DynDataCapabilityMask", L"DynData" }) << L"\r\n"
               << L"EPROCESS.UniqueProcessId: " << kCell({ L"EP.UniqueProcessId" }) << L"\r\n"
               << L"EPROCESS.ActiveProcessLinks: " << kCell({ L"EP.ActiveProcessLinks" }) << L"\r\n"
               << L"EPROCESS.ThreadListHead: " << kCell({ L"EP.ThreadListHead" }) << L"\r\n"
               << L"EPROCESS.ImageFileName: " << kCell({ L"EP.ImageFileName" }) << L"\r\n"
               << L"ETHREAD.Cid: " << kCell({ L"ET.Cid" }) << L"\r\n"
               << L"ETHREAD.ThreadListEntry: " << kCell({ L"ET.ThreadListEntry" }) << L"\r\n"
               << L"ETHREAD.StartAddress: " << kCell({ L"ET.StartAddress" }) << L"\r\n"
               << L"KTHREAD.Process: " << kCell({ L"KT.Process" }) << L"\r\n"
               << L"PspCidTableRva: " << kCell({ L"PspCidTableRva" }) << L"\r\n"
               << L"PspCidTableAddress: " << kCell({ L"PspCidTable" }) << L"\r\n"
               << L"LastStatus: " << kCell({ L"LastStatus" }) << L"\r\n"
               << L"Confidence: " << kCell({ L"置信度", L"Confidence" }) << L"\r\n"
               << L"Detail: " << kCell({ L"Detail" }) << L"\r\n";
        return detail.str();
    }
    case KernelFeatureId::kDriverIntegrity:
    case KernelFeatureId::kKernelCpuIntegrity:
    {
        std::wostringstream detail;
        if (featureId == KernelFeatureId::kKernelCpuIntegrity) {
            detail << L"R0 查询摘要\r\n"
                   << L"R0: " << kRawSummary({ L"R0" }) << L"\r\n"
                   << L"Protocol: " << kRawSummary({ L"Protocol" }) << L"\r\n"
                   << L"DynDataStatus: " << kRawSummary({ L"DynDataStatus" }) << L"\r\n"
                   << L"Win32: " << kRawSummary({ L"Win32" }) << L"\r\n\r\n";
        }
        detail << L"驱动完整性证据详情\r\n"
               << L"----------------------------------------\r\n"
               << L"Class: " << kCell({ L"类别", L"ClassText" }) << L" (" << kCell({ L"Class" }) << L")\r\n"
               << L"RiskFlags: " << kCell({ L"风险", L"RiskText" }) << L" (" << kCell({ L"Risk" }) << L")\r\n"
               << L"SourceMask: " << kCell({ L"Source" }) << L" (" << kCell({ L"SourceText" }) << L")\r\n"
               << L"Confidence: " << kCell({ L"置信度", L"Confidence" }) << L"\r\n"
               << L"ObjectAddress: " << kCell({ L"对象", L"对象/寄存器", L"ObjectAddress", L"Object" }) << L"\r\n"
               << L"TargetAddress: " << kCell({ L"目标", L"目标/入口", L"TargetAddress", L"Target" }) << L"\r\n"
               << L"OwnerModule: " << kCell({ L"Owner模块", L"OwnerModule" }) << L"\r\n"
               << L"OwnerModuleBase: " << kCell({ L"OwnerModuleBase", L"OwnerBase" }) << L"\r\n"
               << L"OwnerModuleSize: " << kCell({ L"OwnerModuleSizeText", L"OwnerModuleSize", L"OwnerSize" }) << L"\r\n"
               << L"CPU: group=" << kCell({ L"Group" }) << L" cpu=" << kCell({ L"CPU" }) << L" vector=" << kCell({ L"Vector" }) << L"\r\n"
               << L"CPU/Vector: " << kCell({ L"CPU/Vector", L"CpuVector" }) << L"\r\n"
               << L"Detail: " << kCell({ L"Detail" }) << L"\r\n";
        return detail.str();
    }
    case KernelFeatureId::kCpuHardwareSnapshot:
    {
        std::wostringstream detail;
        detail << L"R0 CPUID 硬件快照详情\r\n"
               << L"----------------------------------------\r\n"
               << L"Brand: " << kCell({ L"Brand", L"值" }) << L"\r\n"
               << L"Vendor: " << kCell({ L"Vendor" }) << L"\r\n"
               << L"Family/Model/Stepping: " << kCell({ L"Family" }) << L"/" << kCell({ L"Model" }) << L"/" << kCell({ L"Stepping" }) << L"\r\n"
               << L"ProcessorType/BrandIndex: " << kCell({ L"ProcessorType" }) << L"/" << kCell({ L"BrandIndex" }) << L"\r\n"
               << L"Logical/Active/Package: " << kCell({ L"Logical" }) << L"/" << kCell({ L"Active" }) << L"/" << kCell({ L"Package" }) << L"\r\n"
               << L"InitialApicId: " << kCell({ L"InitialApicId" }) << L"\r\n"
               << L"CLFLUSH line: " << kCell({ L"CLFlushLine" }) << L" bytes\r\n"
               << L"Leaves: " << kCell({ L"Leaves" }) << L"\r\n"
               << L"FeatureMask: " << kCell({ L"FeatureMask" }) << L"\r\n"
               << L"Features: " << kCell({ L"Features" }) << L"\r\n"
               << L"Leaf1ECX: " << kCell({ L"Leaf1ECX" }) << L"\r\n"
               << L"Leaf1EDX: " << kCell({ L"Leaf1EDX" }) << L"\r\n"
               << L"Leaf7EBX: " << kCell({ L"Leaf7EBX" }) << L"\r\n"
               << L"Leaf7ECX: " << kCell({ L"Leaf7ECX" }) << L"\r\n"
               << L"Leaf7EDX: " << kCell({ L"Leaf7EDX" }) << L"\r\n"
               << L"Leaf80000001ECX: " << kCell({ L"Leaf80000001ECX" }) << L"\r\n"
               << L"Leaf80000001EDX: " << kCell({ L"Leaf80000001EDX" }) << L"\r\n"
               << L"FieldFlags: " << kCell({ L"FieldFlags" }) << L"\r\n"
               << L"LastStatus: " << kCell({ L"LastStatus" }) << L"\r\n";
        return detail.str();
    }
    case KernelFeatureId::kPhysicalMemoryLayout:
    {
        std::wostringstream detail;
        detail << L"R0 物理内存布局详情\r\n"
               << L"----------------------------------------\r\n"
               << L"总物理内存: " << kCell({ L"总物理内存", L"TotalText" }) << L" (" << kCell({ L"TotalBytes" }) << L")\r\n"
               << L"Range数量: " << kCell({ L"范围", L"Ranges" }) << L"\r\n"
               << L"零长度Range: " << kCell({ L"ZeroRanges" }) << L"\r\n"
               << L"Truncated: " << kCell({ L"Truncated" }) << L"\r\n"
               << L"最大连续Range: " << kCell({ L"最大连续Range", L"LargestRangeText" }) << L" (" << kCell({ L"LargestRange" }) << L")\r\n"
               << L"最小Range: " << kCell({ L"SmallestRangeText" }) << L" (" << kCell({ L"SmallestRange" }) << L")\r\n"
               << L"最高物理地址: " << kCell({ L"最高物理地址", L"HighestAddress" }) << L"\r\n"
               << L"首Range基址: " << kCell({ L"FirstBase" }) << L"\r\n"
               << L"末Range结束: " << kCell({ L"LastEnd" }) << L"\r\n"
               << L"估算地址空洞: " << kCell({ L"GapText" }) << L" (" << kCell({ L"GapBytes" }) << L")\r\n"
               << L"FieldFlags: " << kCell({ L"FieldFlags" }) << L"\r\n"
               << L"LastStatus: " << kCell({ L"LastStatus" }) << L"\r\n";
        return detail.str();
    }
    case KernelFeatureId::kMutationAudit:
    {
        std::wostringstream detail;
        detail << L"R0 Mutation Audit 详情\r\n"
               << L"----------------------------------------\r\n"
               << L"Seq: " << kCell({ L"Seq" }) << L"\r\n"
               << L"TransactionId: " << kCell({ L"Tx", L"TransactionIdHex", L"TransactionId" }) << L"\r\n"
               << L"Operation: " << kCell({ L"Operation" }) << L"\r\n"
               << L"Status: " << kCell({ L"Status" }) << L"\r\n"
               << L"TargetKind: " << kCell({ L"TargetKind" }) << L"\r\n"
               << L"PID: " << kCell({ L"PID" }) << L"\r\n"
               << L"Address: " << kCell({ L"Address" }) << L"\r\n"
               << L"Context: " << kCell({ L"Context" }) << L"\r\n"
               << L"Bytes: " << kCell({ L"Bytes" }) << L"\r\n"
               << L"RiskFlags: " << kCell({ L"RiskText", L"Risk" }) << L" (" << kCell({ L"Risk" }) << L")\r\n"
               << L"Flags: " << kCell({ L"FlagsText", L"Flags" }) << L" (" << kCell({ L"Flags" }) << L")\r\n"
               << L"BeforeHash: " << kCell({ L"BeforeHash" }) << L"\r\n"
               << L"AfterHash: " << kCell({ L"AfterHash" }) << L"\r\n"
               << L"LastStatus: " << kCell({ L"LastStatus" }) << L"\r\n"
               << L"Data: " << kCell({ L"Data" }) << L"\r\n\r\n"
               << L"说明: 该页仅展示 R0 mutation transaction 审计和显式 dry-run/rollback 操作，不提供任意写入口。";
        return detail.str();
    }
    case KernelFeatureId::kKeyboardHotkeys:
    {
        std::wostringstream detail;
        detail << L"win32k 热键枚举详情\r\n"
               << L"----------------------------------------\r\n"
               << L"PID/TID: " << kCell({ L"PID" }) << L" / " << kCell({ L"TID" }) << L"\r\n"
               << L"Process: " << kCell({ L"进程", L"Process" }) << L"\r\n"
               << L"HotkeyObject: " << kCell({ L"Object" }) << L"\r\n"
               << L"NextHotkeyObject: " << kCell({ L"Next" }) << L"\r\n"
               << L"WindowObject: " << kCell({ L"窗口", L"WindowObject" }) << L"\r\n"
               << L"ThreadInfo: " << kCell({ L"ThreadInfo" }) << L"\r\n"
               << L"ThreadObject: " << kCell({ L"ThreadObject" }) << L"\r\n"
               << L"Hotkey: " << kCell({ L"热键" }) << L"\r\n"
               << L"VK: " << kCell({ L"VK" }) << L"\r\n"
               << L"Modifiers: " << kCell({ L"Modifiers" }) << L"\r\n"
               << L"ModifierFlags2: " << kCell({ L"ModifierFlags2" }) << L"\r\n"
               << L"Id: " << kCell({ L"Id" }) << L"\r\n"
               << L"Source: " << kCell({ L"来源", L"SourceText" }) << L" (" << kCell({ L"Source" }) << L")\r\n"
               << L"Status: " << kCell({ L"状态", L"Status" }) << L"\r\n"
               << L"Bucket/Depth: " << kCell({ L"Bucket" }) << L" / " << kCell({ L"Depth" }) << L"\r\n"
               << L"Flags: " << kCell({ L"Flags" }) << L"\r\n"
               << L"LastStatus: " << kCell({ L"LastStatus" }) << L"\r\n"
               << L"Detail: " << kCell({ L"Detail" }) << L"\r\n";
        return detail.str();
    }
    case KernelFeatureId::kKeyboardHooks:
    {
        std::wostringstream detail;
        detail << L"win32k 键盘钩子枚举详情\r\n"
               << L"----------------------------------------\r\n"
               << L"PID/TID: " << kCell({ L"PID" }) << L" / " << kCell({ L"TID" }) << L"\r\n"
               << L"Process: " << kCell({ L"进程", L"Process" }) << L"\r\n"
               << L"HookType: " << kCell({ L"Hook类型", L"TypeText" }) << L" (" << kCell({ L"Type" }) << L")\r\n"
               << L"Scope: " << kCell({ L"ScopeText", L"Scope" }) << L" (" << kCell({ L"Scope" }) << L")\r\n"
               << L"HookObject: " << kCell({ L"Object" }) << L"\r\n"
               << L"ChainHead: " << kCell({ L"ChainHead" }) << L"\r\n"
               << L"NextHookObject: " << kCell({ L"Next" }) << L"\r\n"
               << L"ThreadInfo: " << kCell({ L"ThreadInfo" }) << L"\r\n"
               << L"TargetThreadInfo: " << kCell({ L"TargetThreadInfo" }) << L"\r\n"
               << L"DesktopInfo: " << kCell({ L"DesktopInfo" }) << L"\r\n"
               << L"Procedure: " << kCell({ L"回调", L"Procedure" }) << L"\r\n"
               << L"ProcedureOffset: " << kCell({ L"ProcedureOffset" }) << L"\r\n"
               << L"Module: " << kCell({ L"模块", L"ModuleBase" }) << L"\r\n"
               << L"ModuleId: " << kCell({ L"ModuleId" }) << L"\r\n"
               << L"Source: " << kCell({ L"来源", L"SourceText" }) << L" (" << kCell({ L"Source" }) << L")\r\n"
               << L"Status: " << kCell({ L"状态", L"Status" }) << L"\r\n"
               << L"Flags: " << kCell({ L"Flags" }) << L"\r\n"
               << L"LastStatus: " << kCell({ L"LastStatus" }) << L"\r\n"
               << L"Detail: " << kCell({ L"Detail" }) << L"\r\n";
        return detail.str();
    }
    case KernelFeatureId::kDynDataCapabilities:
    {
        std::wostringstream detail;
        detail << L"DynData 能力详情\r\n"
               << L"----------------------------------------\r\n"
               << L"CapabilityMask: " << kCell({ L"Capability", L"CapabilityMask" }) << L"\r\n"
               << L"StatusFlags: " << kCell({ L"状态", L"StatusFlags" }) << L"\r\n"
               << L"字段: " << kCell({ L"字段", L"Fields", L"Field" }) << L"\r\n"
               << L"原因/详情: " << kCell({ L"原因", L"Reason", L"Detail" }) << L"\r\n";
        return detail.str();
    }
    case KernelFeatureId::kMinifilterBypassPids: {
        std::wostringstream detail;
        detail << L"Minifilter PID 放行详情\r\n"
               << L"----------------------------------------\r\n"
               << L"Index: " << kCell({ L"Index" }) << L"\r\n"
               << L"PID: " << kCell({ L"PID" }) << L"\r\n"
               << L"Process: " << kCell({ L"进程", L"Process" }) << L"\r\n"
               << L"Status: " << kCell({ L"状态", L"Status" }) << L"\r\n"
               << L"Source: " << kCell({ L"来源" }) << L"\r\n\r\n"
               << L"说明: 右键可用过滤框中的 PID 列表写入 R0 minifilter bypass whitelist，或清空 whitelist。";
        return detail.str();
    }
    case KernelFeatureId::kKernelTimerDpc: {
        std::wostringstream detail;
        detail << L"KTIMER / KDPC 详情\r\n"
               << L"----------------------------------------\r\n"
               << L"CPU: " << kCell({ L"CPU", L"Processor" }) << L"\r\n"
               << L"Bucket: " << kCell({ L"Bucket", L"BucketIndex" }) << L"\r\n"
               << L"Timer: " << kCell({ L"Timer", L"TimerAddress" }) << L"\r\n"
               << L"DueTime / Period: " << kCell({ L"DueTime" }) << L" / " << kCell({ L"Period" }) << L"\r\n"
               << L"TimerType: " << kCell({ L"类型", L"TimerType" }) << L"\r\n"
               << L"DPC: " << kCell({ L"DPC", L"DpcAddress" }) << L"\r\n"
               << L"DeferredRoutine: " << kCell({ L"例程", L"DeferredRoutine" }) << L"\r\n"
               << L"DeferredContext: " << kCell({ L"上下文", L"DeferredContext" }) << L"\r\n"
               << L"Flags: " << kCell({ L"标志", L"Flags" }) << L"\r\n\r\n"
               << L"查询摘要：CPU=" << kRawSummary({ L"ProcessorCount" })
               << L"，Bucket=" << kRawSummary({ L"BucketsVisited" }) << L"/"
               << kRawSummary({ L"BucketCount" }) << L"，损坏=" << kRawSummary({ L"CorruptBuckets" })
               << L"，读取失败=" << kRawSummary({ L"ReadFailures" })
               << L"，重复=" << kRawSummary({ L"Duplicates" });
        return detail.str();
    }
    case KernelFeatureId::kIoctlRegistry: {
        std::wostringstream detail;
        detail << L"KswordARK IOCTL 派遣注册表详情\r\n"
               << L"----------------------------------------\r\n"
               << L"IOCTL: " << kCell({ L"IOCTL", L"IoControlCode" }) << L"\r\n"
               << L"Function: " << kCell({ L"函数", L"Function", L"FunctionNumber" }) << L"\r\n"
               << L"Method/Access: " << kCell({ L"Method/Access", L"MethodAccess" }) << L"\r\n"
               << L"RequiredCapability: " << kCell({ L"Capability", L"RequiredCapability" }) << L"\r\n"
               << L"Handler: " << kCell({ L"Handler", L"HandlerAddress" }) << L"\r\n"
               << L"Name: " << kCell({ L"名称", L"Name" }) << L"\r\n"
               << L"Flags: " << kCell({ L"Flags" }) << L"\r\n"
               << L"Status: " << kCell({ L"状态", L"Status" }) << L"\r\n\r\n"
               << L"查询摘要：返回 " << kRawSummary({ L"Returned" }) << L"/"
               << kRawSummary({ L"Total" }) << L"，重复控制码=" << kRawSummary({ L"Duplicates" })
               << L"，RegistryStatus=" << kRawSummary({ L"RegistryStatus" });
        return detail.str();
    }
    default:
        return {};
    }
}

void KernelPage::configureVisibleLayout() {
    // configureVisibleLayout applies original KernelDock layout metadata to the
    // current Win32 controls. Inputs are the selected feature; processing hides
    // or shows the object-namespace property table and relayouts children; no
    // value is returned.
    layout();
    updatePropertyTableFromSelection();
    if (const KernelFeatureDescriptor* descriptor = currentDescriptor();
        descriptor != nullptr &&
        (descriptor->id == KernelFeatureId::kDynData || descriptor->id == KernelFeatureId::kDriverStatus)) {
        return;
    }
    updateSummaryTableFromRows();
}

void KernelPage::configureToolbarForDescriptor(const KernelFeatureDescriptor& descriptor) {
    // configureToolbarForDescriptor mirrors the original KernelDock toolbar for
    // the selected page. Input is the current feature descriptor; processing
    // changes static labels, combo items and default scan flags; there is no
    // return value because Win32 controls keep the state.
    ::SetWindowTextW(filterLabel_, L"过滤/起点");
    ::SetWindowTextW(moduleFilterLabel_, L"模块过滤");
    ::SetWindowTextW(locateButton_, L"定位");
    ::SetWindowTextW(refreshButton_, L"刷新/查询");
    ::SetWindowTextW(copyDiagnosticButton_, L"复制诊断");
    if (riskOnlyCheck_) {
        ::SetWindowTextW(riskOnlyCheck_, L"仅风险项");
    }
    setEditCueBanner(filterEdit_, L"");
    setEditCueBanner(moduleFilterEdit_, L"");
    if (includeCombo_) {
        ::SendMessageW(includeCombo_, CB_RESETCONTENT, 0, 0);
        ::ShowWindow(includeCombo_, SW_HIDE);
    }
    if (evidenceIncludeNonModuleCheck_) {
        Button_SetCheck(evidenceIncludeNonModuleCheck_, BST_UNCHECKED);
    }
    if (riskOnlyCheck_) {
        Button_SetCheck(riskOnlyCheck_, BST_UNCHECKED);
    }
    if (integrityFillFromSelectionButton_) {
        ::SetWindowTextW(integrityFillFromSelectionButton_, L"填充");
    }
    if (integrityCpuOnlyButton_) {
        ::SetWindowTextW(integrityCpuOnlyButton_, L"CPU");
    }
    if (integrityIdtVectorsLabel_) {
        ::SetWindowTextW(integrityIdtVectorsLabel_, L"IDT");
    }

    switch (descriptor.id) {
    case KernelFeatureId::kObjectNamespaceOverview:
        ::SetWindowTextW(filterLabel_, L"过滤");
        ::SetWindowTextW(locateButton_, L"定位");
        ::SetWindowTextW(refreshButton_, L"刷新");
        setEditCueBanner(filterEdit_, L"过滤目录 / 名称 / 类型 / 完整路径 / 状态 / 目标");
        ::SetWindowTextW(statusText_, L"状态：等待刷新");
        break;
    case KernelFeatureId::kObjectDirectoryRecursive:
        ::SetWindowTextW(filterLabel_, L"根路径:");
        ::SetWindowTextW(moduleFilterLabel_, L"最大深度:");
        ::SetWindowTextW(locateButton_, L"");
        ::SetWindowTextW(refreshButton_, L"刷新");
        setEditCueBanner(filterEdit_, L"\\、\\Device、\\BaseNamedObjects、\\Sessions");
        setEditCueBanner(moduleFilterEdit_, L"0-32");
        ::SetWindowTextW(statusText_, L"状态：等待刷新");
        if (windowText(filterEdit_).empty()) {
            ::SetWindowTextW(filterEdit_, L"\\");
        }
        if (windowText(moduleFilterEdit_).empty()) {
            ::SetWindowTextW(moduleFilterEdit_, L"4");
        }
        break;
    case KernelFeatureId::kNamedPipe:
        ::SetWindowTextW(filterLabel_, L"过滤");
        ::SetWindowTextW(locateButton_, L"复制行");
        ::SetWindowTextW(copyDiagnosticButton_, L"刷新详情");
        ::SetWindowTextW(refreshButton_, L"刷新");
        setEditCueBanner(filterEdit_, L"过滤管道名、NT路径、状态");
        ::SetWindowTextW(statusText_, L"状态：等待刷新");
        break;
    case KernelFeatureId::kSymbolicLink:
        ::SetWindowTextW(filterLabel_, L"过滤");
        ::SetWindowTextW(moduleFilterLabel_, L"");
        ::SetWindowTextW(locateButton_, L"");
        ::SetWindowTextW(refreshButton_, L"刷新");
        ::SetWindowTextW(copyDiagnosticButton_, L"复制目标");
        setEditCueBanner(filterEdit_, L"过滤目录 / 名称 / 完整路径 / 状态");
        setEditCueBanner(moduleFilterEdit_, L"按目标路径 / DOS 候选过滤");
        ::SetWindowTextW(statusText_, L"状态：等待刷新");
        break;
    case KernelFeatureId::kDeviceDriverObjects:
        ::SetWindowTextW(filterLabel_, L"关键字：");
        ::SetWindowTextW(moduleFilterLabel_, L"");
        ::SetWindowTextW(locateButton_, L"");
        ::SetWindowTextW(copyDiagnosticButton_, L"导出 TSV");
        ::SetWindowTextW(refreshButton_, L"刷新");
        setEditCueBanner(filterEdit_, L"关键字过滤：名称 / 类型 / 路径 / 目标 / 提示");
        ::SetWindowTextW(statusText_, L"状态：首次打开后正在加载设备与驱动对象...");
        break;
    case KernelFeatureId::kObjectTypeMatrix:
        ::SetWindowTextW(filterLabel_, L"过滤");
        ::SetWindowTextW(locateButton_, L"复制行");
        ::SetWindowTextW(copyDiagnosticButton_, L"");
        ::SetWindowTextW(refreshButton_, L"刷新");
        setEditCueBanner(filterEdit_, L"按类型名、编号、策略筛选");
        ::SetWindowTextW(statusText_, L"状态：等待刷新");
        break;
    case KernelFeatureId::kCommunicationEndpoint:
        ::SetWindowTextW(filterLabel_, L"过滤");
        ::SetWindowTextW(locateButton_, L"复制行");
        ::SetWindowTextW(copyDiagnosticButton_, L"");
        ::SetWindowTextW(refreshButton_, L"刷新");
        setEditCueBanner(filterEdit_, L"按名称、类型、路径筛选");
        ::SetWindowTextW(statusText_, L"状态：等待刷新");
        break;
    case KernelFeatureId::kBaseNamedObjects:
        ::SetWindowTextW(filterLabel_, L"");
        ::SetWindowTextW(moduleFilterLabel_, L"");
        ::SetWindowTextW(locateButton_, L"");
        ::SetWindowTextW(refreshButton_, L"刷新");
        setEditCueBanner(filterEdit_, L"过滤 scope / 目录 / 名称 / 类型 / 目标 / 状态");
        ::SetWindowTextW(statusText_, L"等待刷新");
        break;
    case KernelFeatureId::kAtomTable:
        ::SetWindowTextW(filterLabel_, L"");
        ::SetWindowTextW(refreshButton_, L"↻");
        ::SetWindowTextW(statusText_, L"状态：等待刷新");
        break;
    case KernelFeatureId::kNtQueryLegacy:
        ::SetWindowTextW(filterLabel_, L"");
        ::SetWindowTextW(refreshButton_, L"↻");
        ::SetWindowTextW(statusText_, L"状态：等待刷新");
        break;
    case KernelFeatureId::kSsdt:
        ::SetWindowTextW(filterLabel_, L"本地筛选");
        ::SetWindowTextW(moduleFilterLabel_, L"");
        ::SetWindowTextW(refreshButton_, L"↻");
        setEditCueBanner(filterEdit_, L"按索引/服务名/地址/模块/状态筛选");
        ::SetWindowTextW(statusText_, L"状态：等待刷新 SSDT。");
        break;
    case KernelFeatureId::kShadowSsdt:
        ::SetWindowTextW(filterLabel_, L"本地筛选");
        ::SetWindowTextW(moduleFilterLabel_, L"");
        ::SetWindowTextW(refreshButton_, L"↻");
        setEditCueBanner(filterEdit_, L"按索引/服务名/stub/服务例程/模块/状态筛选");
        ::SetWindowTextW(statusText_, L"状态：等待刷新 SSSDT。");
        break;
    case KernelFeatureId::kInlineHook:
        ::SetWindowTextW(filterLabel_, L"本地筛选");
        ::SetWindowTextW(moduleFilterLabel_, L"模块过滤");
        ::SetWindowTextW(refreshButton_, L"↻");
        ::SetWindowTextW(copyDiagnosticButton_, L"NOP摘除");
        setEditCueBanner(filterEdit_, L"按模块/函数/地址/Hook类型/状态/字节筛选");
        setEditCueBanner(moduleFilterEdit_, L"按模块或目标模块筛选");
        ::SetWindowTextW(statusText_, L"状态：等待重新扫描 Inline Hook。");
        if (includeCombo_) {
            const int kSuspicious = static_cast<int>(::SendMessageW(includeCombo_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"仅可疑外跳")));
            ::SendMessageW(includeCombo_, CB_SETITEMDATA, kSuspicious, 0);
            const int kInternal = static_cast<int>(::SendMessageW(includeCombo_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"可疑 + 模块内跳转")));
            ::SendMessageW(includeCombo_, CB_SETITEMDATA, kInternal, kKernelRequestFlagIncludeInternal);
            const int kClean = static_cast<int>(::SendMessageW(includeCombo_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"包含干净项")));
            ::SendMessageW(includeCombo_, CB_SETITEMDATA, kClean, kKernelRequestFlagIncludeInternal | kKernelRequestFlagIncludeClean);
            ::SendMessageW(includeCombo_, CB_SETCURSEL, kInternal, 0);
            ::ShowWindow(includeCombo_, SW_SHOW);
        }
        break;
    case KernelFeatureId::kIatEatHook:
        ::SetWindowTextW(filterLabel_, L"本地筛选");
        ::SetWindowTextW(moduleFilterLabel_, L"模块过滤");
        ::SetWindowTextW(refreshButton_, L"↻");
        setEditCueBanner(filterEdit_, L"按类别/模块/导入模块/函数/目标/状态筛选");
        setEditCueBanner(moduleFilterEdit_, L"按模块/导入模块/目标模块筛选");
        ::SetWindowTextW(statusText_, L"状态：等待重新扫描 IAT/EAT。");
        if (includeCombo_) {
            const int kBoth = static_cast<int>(::SendMessageW(includeCombo_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"IAT + EAT 可疑项")));
            ::SendMessageW(includeCombo_, CB_SETITEMDATA, kBoth, kKernelRequestFlagIncludeIat | kKernelRequestFlagIncludeEat);
            const int kIat = static_cast<int>(::SendMessageW(includeCombo_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"仅 IAT 可疑项")));
            ::SendMessageW(includeCombo_, CB_SETITEMDATA, kIat, kKernelRequestFlagIncludeIat);
            const int kEat = static_cast<int>(::SendMessageW(includeCombo_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"仅 EAT 可疑项")));
            ::SendMessageW(includeCombo_, CB_SETITEMDATA, kEat, kKernelRequestFlagIncludeEat);
            const int kClean = static_cast<int>(::SendMessageW(includeCombo_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"IAT + EAT + 干净项")));
            ::SendMessageW(includeCombo_, CB_SETITEMDATA, kClean, kKernelRequestFlagIncludeIat | kKernelRequestFlagIncludeEat | kKernelRequestFlagIncludeClean);
            ::SendMessageW(includeCombo_, CB_SETCURSEL, kBoth, 0);
            ::ShowWindow(includeCombo_, SW_SHOW);
        }
        break;
    case KernelFeatureId::kDynData:
        ::SetWindowTextW(filterLabel_, L"");
        setEditCueBanner(filterEdit_, L"按字段名/偏移/状态/来源/功能/capability 筛选");
        ::SetWindowTextW(refreshButton_, L"↻");
        ::SetWindowTextW(copyDiagnosticButton_, L"复制诊断");
        ::SetWindowTextW(statusText_, L"状态：等待刷新 DynData 状态、profile 命中和字段表。");
        break;
    case KernelFeatureId::kDriverStatus:
        ::SetWindowTextW(filterLabel_, L"");
        setEditCueBanner(filterEdit_, L"按功能/状态/策略/DynData capability/依赖字段筛选");
        ::SetWindowTextW(refreshButton_, L"↻");
        ::SetWindowTextW(copyDiagnosticButton_, L"复制诊断");
        ::SetWindowTextW(statusText_, L"状态：等待刷新驱动状态、协议、安全策略和能力矩阵。");
        break;
    case KernelFeatureId::kCallbackEnumeration:
        ::SetWindowTextW(filterLabel_, L"");
        setEditCueBanner(filterEdit_, L"按类别/来源/可信状态/移除策略/名称/地址/模块/Altitude筛选");
        ::SetWindowTextW(refreshButton_, L"↻");
        ::SetWindowTextW(statusText_, L"状态：等待刷新回调遍历。");
        break;
    case KernelFeatureId::kKernelExecutableMemory:
        ::SetWindowTextW(filterLabel_, L"");
        ::SetWindowTextW(moduleFilterLabel_, L"");
        setEditCueBanner(moduleFilterEdit_, L"按模块路径过滤，如 ntoskrnl.exe / drivers\\xxx.sys");
        ::SetWindowTextW(refreshButton_, L"刷新");
        ::SetWindowTextW(statusText_, L"状态：等待刷新内核可执行页。");
        if (riskOnlyCheck_) {
            Button_SetCheck(riskOnlyCheck_, BST_CHECKED);
        }
        break;
    case KernelFeatureId::kKernelMemoryEvidence:
        ::SetWindowTextW(filterLabel_, L"");
        ::SetWindowTextW(moduleFilterLabel_, L"");
        setEditCueBanner(filterEdit_, L"过滤 owner / detail / risk / hash");
        setEditCueBanner(evidenceStartEdit_, L"起始VA(可选)");
        setEditCueBanner(evidenceEndEdit_, L"结束VA(可选)");
        ::SetWindowTextW(refreshButton_, L"刷新证据");
        ::SetWindowTextW(statusText_, L"状态：等待刷新内核内存证据。");
        if (riskOnlyCheck_) {
            Button_SetCheck(riskOnlyCheck_, BST_CHECKED);
        }
        if (evidenceIncludeNonModuleCheck_) {
            Button_SetCheck(evidenceIncludeNonModuleCheck_, BST_UNCHECKED);
        }
        if (windowText(evidenceMaxRowsEdit_).empty() || windowText(evidenceMaxRowsEdit_) == L"256") {
            ::SetWindowTextW(evidenceMaxRowsEdit_, L"512");
        }
        ::SetWindowTextW(detailEdit_,
            L"请选择一条内核内存证据记录查看详情。\r\n"
            L"说明：text diff 的磁盘对比由 R3 后续阶段完成，本页当前展示 R0 内存 hash/sample 状态。");
        break;
    case KernelFeatureId::kProcessCrossView:
        ::SetWindowTextW(filterLabel_, L"");
        setEditCueBanner(filterEdit_, L"过滤 PID/TID/进程名/异常/详情");
        ::SetWindowTextW(refreshButton_, L"刷新矩阵");
        ::SetWindowTextW(statusText_, L"状态：等待刷新进程 Cross-View 矩阵。");
        if (riskOnlyCheck_) {
            ::SetWindowTextW(riskOnlyCheck_, L"仅异常");
            Button_SetCheck(riskOnlyCheck_, BST_CHECKED);
        }
        break;
    case KernelFeatureId::kThreadCrossView:
        ::SetWindowTextW(filterLabel_, L"");
        setEditCueBanner(filterEdit_, L"过滤 PID/TID/进程名/异常/详情");
        ::SetWindowTextW(refreshButton_, L"刷新矩阵");
        ::SetWindowTextW(statusText_, L"状态：等待刷新线程 Cross-View 矩阵。");
        if (riskOnlyCheck_) {
            ::SetWindowTextW(riskOnlyCheck_, L"仅异常");
            Button_SetCheck(riskOnlyCheck_, BST_CHECKED);
        }
        break;
    case KernelFeatureId::kDriverIntegrity:
        ::SetWindowTextW(filterLabel_, L"");
        ::SetWindowTextW(moduleFilterLabel_, L"DriverObject");
        ::SetWindowTextW(integrityModuleBaseLabel_, L"模块基址");
        ::SetWindowTextW(integrityFillFromSelectionButton_, L"填充");
        ::SetWindowTextW(integrityCpuOnlyButton_, L"CPU");
        setEditCueBanner(moduleFilterEdit_, L"\\Driver\\Name（可选）");
        setEditCueBanner(integrityModuleBaseEdit_, L"模块基址（可选）");
        setEditCueBanner(filterEdit_, L"过滤类别/对象/目标/Owner/风险/详情");
        ::SetWindowTextW(refreshButton_, L"刷新");
        ::SetWindowTextW(statusText_, L"状态：等待刷新驱动完整性证据。");
        if (riskOnlyCheck_) { Button_SetCheck(riskOnlyCheck_, BST_UNCHECKED); }
        if (windowText(evidenceMaxRowsEdit_).empty() || windowText(evidenceMaxRowsEdit_) == L"256") {
            ::SetWindowTextW(evidenceMaxRowsEdit_, L"1024");
        }
        break;
    case KernelFeatureId::kKernelCpuIntegrity:
        ::SetWindowTextW(filterLabel_, L"");
        ::SetWindowTextW(moduleFilterLabel_, L"");
        ::SetWindowTextW(integrityIdtVectorsLabel_, L"IDT/CPU:");
        setEditCueBanner(filterEdit_, L"过滤CPU/Vector/Owner/风险/详情");
        setEditCueBanner(integrityIdtVectorsEdit_, L"IDT向量数");
        ::SetWindowTextW(refreshButton_, L"刷新");
        ::SetWindowTextW(statusText_, L"状态：等待刷新 CPU/IDT 完整性证据。");
        if (riskOnlyCheck_) { Button_SetCheck(riskOnlyCheck_, BST_UNCHECKED); }
        if (windowText(evidenceMaxRowsEdit_).empty() || windowText(evidenceMaxRowsEdit_) == L"256") {
            ::SetWindowTextW(evidenceMaxRowsEdit_, L"1024");
        }
        if (windowText(integrityIdtVectorsEdit_).empty()) {
            ::SetWindowTextW(integrityIdtVectorsEdit_, L"64");
        }
        break;
    case KernelFeatureId::kCpuHardwareSnapshot:
        ::SetWindowTextW(filterLabel_, L"");
        setEditCueBanner(filterEdit_, L"过滤厂商/型号/Features/状态");
        ::SetWindowTextW(refreshButton_, L"刷新快照");
        ::SetWindowTextW(statusText_, L"状态：等待刷新 CPU 硬件快照。");
        if (riskOnlyCheck_) { Button_SetCheck(riskOnlyCheck_, BST_UNCHECKED); }
        break;
    case KernelFeatureId::kPhysicalMemoryLayout:
        ::SetWindowTextW(filterLabel_, L"");
        setEditCueBanner(filterEdit_, L"过滤范围/地址/状态");
        ::SetWindowTextW(refreshButton_, L"刷新布局");
        ::SetWindowTextW(statusText_, L"状态：等待刷新 R0 物理内存布局。");
        if (riskOnlyCheck_) { Button_SetCheck(riskOnlyCheck_, BST_UNCHECKED); }
        break;
    case KernelFeatureId::kMutationAudit:
        ::SetWindowTextW(filterLabel_, L"");
        setEditCueBanner(filterEdit_, L"过滤操作/目标/PID/地址/风险/Flags");
        ::SetWindowTextW(refreshButton_, L"刷新审计");
        ::SetWindowTextW(statusText_, L"状态：等待刷新内核修改审计。");
        if (riskOnlyCheck_) { Button_SetCheck(riskOnlyCheck_, BST_UNCHECKED); }
        break;
    case KernelFeatureId::kKeyboardHotkeys:
        ::SetWindowTextW(filterLabel_, L"");
        setEditCueBanner(filterEdit_, L"过滤PID/TID/进程/热键/来源");
        ::SetWindowTextW(refreshButton_, L"刷新热键");
        ::SetWindowTextW(statusText_, L"状态：等待刷新键盘热键。");
        if (riskOnlyCheck_) { Button_SetCheck(riskOnlyCheck_, BST_UNCHECKED); }
        break;
    case KernelFeatureId::kKeyboardHooks:
        ::SetWindowTextW(filterLabel_, L"");
        setEditCueBanner(filterEdit_, L"过滤PID/TID/类型/模块/来源/详情");
        ::SetWindowTextW(refreshButton_, L"刷新钩子");
        ::SetWindowTextW(statusText_, L"状态：等待刷新键盘钩子。");
        if (riskOnlyCheck_) { Button_SetCheck(riskOnlyCheck_, BST_UNCHECKED); }
        break;
    case KernelFeatureId::kDynDataCapabilities:
        ::SetWindowTextW(filterLabel_, L"");
        setEditCueBanner(filterEdit_, L"过滤Capability/状态/字段/原因");
        ::SetWindowTextW(refreshButton_, L"刷新能力");
        ::SetWindowTextW(statusText_, L"状态：等待刷新 DynData 能力。");
        if (riskOnlyCheck_) { Button_SetCheck(riskOnlyCheck_, BST_UNCHECKED); }
        break;
    case KernelFeatureId::kMinifilterBypassPids:
        ::SetWindowTextW(filterLabel_, L"PID列表");
        setEditCueBanner(filterEdit_, L"过滤PID/进程/状态/来源");
        ::SetWindowTextW(refreshButton_, L"刷新PID");
        ::SetWindowTextW(statusText_, L"状态：等待刷新 Minifilter PID 放行表。");
        if (riskOnlyCheck_) { Button_SetCheck(riskOnlyCheck_, BST_UNCHECKED); }
        break;
    case KernelFeatureId::kKernelTimerDpc:
        ::SetWindowTextW(filterLabel_, L"");
        setEditCueBanner(filterEdit_, L"过滤CPU/Bucket/Timer/DPC/例程/标志/详情");
        ::SetWindowTextW(refreshButton_, L"刷新定时器");
        ::SetWindowTextW(statusText_, L"状态：等待刷新每 CPU KTIMER/DPC 快照。");
        if (riskOnlyCheck_) { Button_SetCheck(riskOnlyCheck_, BST_UNCHECKED); }
        break;
    case KernelFeatureId::kIoctlRegistry:
        ::SetWindowTextW(filterLabel_, L"");
        setEditCueBanner(filterEdit_, L"过滤IOCTL/函数/名称/Capability/Handler/Flags");
        ::SetWindowTextW(refreshButton_, L"刷新派遣表");
        ::SetWindowTextW(statusText_, L"状态：等待刷新 KswordARK IOCTL 派遣注册表。");
        if (riskOnlyCheck_) { Button_SetCheck(riskOnlyCheck_, BST_UNCHECKED); }
        break;
    default:
        break;
    }
}

void KernelPage::populateCallbackInterceptPanel() {
    // populateCallbackInterceptPanel maps the callback-runtime result rows onto
    // the dedicated Win32 panel that mirrors the original CallbackIntercept
    // controller: rule-group table, per-callback rule tabs, minifilter bypass
    // table, app log, event log, and file-monitor grid. Inputs are the current
    // cached result rows; processing is display-only except explicit button
    // actions; no value is returned.
    if (!callbackGroupList_ || !callbackRuleTab_) {
        return;
    }
    ensureCallbackLocalModel();
    ListView_DeleteAllItems(callbackGroupList_);
    for (HWND ruleList : callbackRuleLists_) {
        ListView_DeleteAllItems(ruleList);
    }
    if (callbackBypassList_) {
        ListView_DeleteAllItems(callbackBypassList_);
    }
    if (callbackFileMonitorList_) {
        ListView_DeleteAllItems(callbackFileMonitorList_);
    }
    renderCallbackLocalModel();

    std::wstring runtimeStatus = L"状态：等待刷新";
    std::wstring appLog;
    std::wstring eventLog;
    std::wstring registeredText;
    std::wstring ruleVersion;
    std::wstring groupCount;
    std::wstring ruleCount;
    std::wstring pendingCount;
    std::wstring waitingCount;

    const auto kRowValue = [](const std::vector<std::wstring>& row, const std::vector<std::wstring>& columns, std::initializer_list<const wchar_t*> names) -> std::wstring {
        for (const wchar_t* name : names) {
            for (std::size_t column = 0; column < columns.size() && column < row.size(); ++column) {
                if (_wcsicmp(columns[column].c_str(), name) == 0 && !row[column].empty()) {
                    return row[column];
                }
            }
        }
        return {};
    };

    for (const std::vector<std::wstring>& row : currentRows_) {
        const std::wstring kSection = kRowValue(row, currentColumns_, { L"Section" });
        if (kSection == L"Runtime") {
            runtimeStatus = L"状态：驱动";
            runtimeStatus += kRowValue(row, currentColumns_, { L"DriverOnline" }) == L"是" ? L"在线" : L"离线";
            runtimeStatus += L" | 全局启用=" + kRowValue(row, currentColumns_, { L"GlobalEnabled" });
            runtimeStatus += L" | 规则已应用=" + kRowValue(row, currentColumns_, { L"RulesApplied" });
            appLog += L"[Runtime] ";
            appLog += kRowValue(row, currentColumns_, { L"Health" });
            appLog += L"\r\n";
        } else if (kSection == L"Callbacks") {
            registeredText = kRowValue(row, currentColumns_, { L"RegisteredText" });
            appLog += L"[Callbacks] 已注册: " + registeredText + L"\r\n";
        } else if (kSection == L"CallbackType") {
            const std::wstring kName = kRowValue(row, currentColumns_, { L"Name", L"Type" });
            const std::wstring kRegistered = kRowValue(row, currentColumns_, { L"Registered" });
            if (callbackRuleLists_.empty() || ListView_GetItemCount(callbackRuleLists_.front()) == 0) {
                addListRow(callbackRuleLists_.empty() ? nullptr : callbackRuleLists_.front(), {
                    kRegistered, L"", L"", kName, kRowValue(row, currentColumns_, { L"Mask" }), L"", L"运行态注册", L"", L"", L""
                });
            }
        } else if (kSection == L"Rules") {
            groupCount = kRowValue(row, currentColumns_, { L"Groups" });
            ruleCount = kRowValue(row, currentColumns_, { L"Rules" });
            ruleVersion = kRowValue(row, currentColumns_, { L"RuleVersion" });
            if (ListView_GetItemCount(callbackGroupList_) == 0) {
                addListRow(callbackGroupList_, {
                    L"0",
                    L"当前驱动规则快照",
                    kRowValue(row, currentColumns_, { L"RulesApplied" }).empty() ? L"是" : kRowValue(row, currentColumns_, { L"RulesApplied" }),
                    L"0",
                    L"Groups=" + groupCount + L" Rules=" + ruleCount + L" Version=" + ruleVersion
                });
            }
            appLog += L"[Rules] groups=" + groupCount + L", rules=" + ruleCount + L", version=" + ruleVersion + L"\r\n";
        } else if (kSection == L"PendingDecision") {
            pendingCount = kRowValue(row, currentColumns_, { L"Pending", L"PendingDecisions" });
            waitingCount = kRowValue(row, currentColumns_, { L"WaitingReceivers" });
            eventLog += L"[PendingDecision] pending=" + pendingCount + L", waitingReceivers=" + waitingCount + L"\r\n";
            addListRow(callbackRuleLists_.empty() ? nullptr : callbackRuleLists_.front(), {
                L"是", L"", L"", L"等待用户决策", L"", L"", kRowValue(row, currentColumns_, { L"Attention" }), L"", L"", L""
            });
        } else if (kSection == L"Action") {
            appLog += L"[Action] " + kRowValue(row, currentColumns_, { L"Action" }) + L" Win32=" + kRowValue(row, currentColumns_, { L"Win32" }) + L"\r\n";
        } else if (kSection == L"MinifilterBypass" || kSection == L"BypassPid") {
            addListRow(callbackBypassList_, {
                kRowValue(row, currentColumns_, { L"PID", L"Pid" }),
                kRowValue(row, currentColumns_, { L"Process", L"Name", L"Source" })
            });
        } else if (kSection == L"FileMonitor" || kSection == L"FileEvent") {
            const bool kFsctlOnly = callbackFileMonitorFsctlOnlyCheck_ == nullptr ||
                Button_GetCheck(callbackFileMonitorFsctlOnlyCheck_) == BST_CHECKED;
            const std::wstring kFsctlName = kRowValue(row, currentColumns_, { L"FsctlName" });
            const std::wstring kControlCode = kRowValue(row, currentColumns_, { L"ControlCode" });
            if (kSection == L"FileEvent" && kFsctlOnly &&
                (kFsctlName.empty() || kFsctlName == L"-") &&
                (kControlCode.empty() || kControlCode == L"-")) {
                continue;
            }
            addListRow(callbackFileMonitorList_, {
                kRowValue(row, currentColumns_, { L"Time" }),
                kRowValue(row, currentColumns_, { L"PID", L"Pid" }),
                kRowValue(row, currentColumns_, { L"Process" }),
                kRowValue(row, currentColumns_, { L"Path" }),
                kFsctlName,
                kControlCode,
                kRowValue(row, currentColumns_, { L"Status" }),
                kRowValue(row, currentColumns_, { L"FileObject" }),
                kRowValue(row, currentColumns_, { L"InputLength" }),
                kRowValue(row, currentColumns_, { L"OutputLength" }),
                kRowValue(row, currentColumns_, { L"PathState" }),
            });
        }
    }

    if (callbackGroupList_ && ListView_GetItemCount(callbackGroupList_) == 0) {
        addListRow(callbackGroupList_, { L"1", L"默认规则组", L"是", L"10", L"本地规则编辑器默认组；点击应用后写入驱动。" });
    }
    for (std::size_t index = 1; index < callbackRuleLists_.size() && index < 6; ++index) {
        if (ListView_GetItemCount(callbackRuleLists_[index]) == 0) {
            addListRow(callbackRuleLists_[index], { L"", L"", L"", L"暂无规则", L"", L"", L"", L"", L"", L"" });
        }
    }
    if (callbackBypassList_ && ListView_GetItemCount(callbackBypassList_) == 0) {
        addListRow(callbackBypassList_, { L"", L"尚未从驱动刷新；编辑后点击“应用到驱动”生效。" });
    }
    if (callbackFileMonitorList_ && ListView_GetItemCount(callbackFileMonitorList_) == 0) {
        addListRow(callbackFileMonitorList_, { L"", L"", L"", L"尚无文件系统事件；点击“启动 FSCTL 监控/拉取事件”后显示。", L"", L"", L"", L"", L"", L"", L"" });
    }

    runtimeStatus += L" | 规则版本=" + (ruleVersion.empty() ? L"<未知>" : ruleVersion);
    runtimeStatus += L" | 规则数=" + (ruleCount.empty() ? L"0" : ruleCount);
    runtimeStatus += L" | 等待接收者=" + (waitingCount.empty() ? L"0" : waitingCount);
    runtimeStatus += L" | 待决策=" + (pendingCount.empty() ? L"0" : pendingCount);
    ::SetWindowTextW(callbackStatusText_, runtimeStatus.c_str());
    if (callbackBypassStatusText_) {
        const int kBypassRows = callbackBypassList_ ? ListView_GetItemCount(callbackBypassList_) : 0;
        std::wstring bypassStatus = L"尚未从驱动刷新；编辑后点击“应用到驱动”生效。";
        if (kBypassRows > 0 && !listViewText(callbackBypassList_, 0, 0).empty()) {
            bypassStatus = L"当前 PID 放行项: " + std::to_wstring(kBypassRows) + L"；点击“应用到驱动”后生效。";
        }
        ::SetWindowTextW(callbackBypassStatusText_, bypassStatus.c_str());
    }
    if (callbackFileMonitorStatusText_) {
        const int kFileRows = callbackFileMonitorList_ ? ListView_GetItemCount(callbackFileMonitorList_) : 0;
        std::wstring fileStatus = kFileRows > 0 && !listViewText(callbackFileMonitorList_, 0, 3).empty()
            ? L"当前文件监控事件: " + std::to_wstring(kFileRows)
            : L"等待启动或读取事件";
        ::SetWindowTextW(callbackFileMonitorStatusText_, fileStatus.c_str());
    }
    if (appLog.empty()) {
        appLog = L"应用日志：刷新后显示驱动回调运行态、规则应用与控制动作。\r\n";
    }
    if (eventLog.empty()) {
        eventLog = L"事件日志：等待决策、文件系统事件和用户决策将显示在这里。\r\n";
    }
    ::SetWindowTextW(callbackAppLogEdit_, appLog.c_str());
    if (!callbackPendingEvents_.empty() || (callbackEventReceiver_ && callbackEventReceiver_->running())) {
        refreshCallbackEventLog();
    } else {
        ::SetWindowTextW(callbackEventLogEdit_, eventLog.c_str());
    }
}

void KernelPage::ensureCallbackLocalModel() {
    // ensureCallbackLocalModel initializes the in-memory CallbackIntercept rule
    // editor. There is no input; processing creates one default group so the
    // original add/remove/move UI can operate immediately; no value is returned.
    if (!callbackGroups_.empty()) {
        return;
    }
    callbackGroups_.push_back({ 1, L"默认组", true, 10, L"默认规则组" });
    nextCallbackGroupId_ = 2;
    nextCallbackRuleId_ = 1;
}

void KernelPage::renderCallbackLocalModel() {
    // renderCallbackLocalModel maps local rule groups and rules into the Win32
    // grids. Inputs are callbackGroups_/callbackRules_; processing refreshes
    // group and per-type rule ListViews; output is visible UI state only.
    ensureCallbackLocalModel();
    if (callbackGroupList_) {
        ListView_DeleteAllItems(callbackGroupList_);
    }
    for (HWND ruleList : callbackRuleLists_) {
        ListView_DeleteAllItems(ruleList);
    }
    for (const CallbackRuleGroup& group : callbackGroups_) {
        addListRow(callbackGroupList_, {
            std::to_wstring(group.id),
            group.name,
            boolText(group.enabled),
            std::to_wstring(group.priority),
            group.comment,
        });
    }
    for (const CallbackRule& rule : callbackRules_) {
        if (rule.typeIndex < 0 || rule.typeIndex >= static_cast<int>(callbackRuleLists_.size()) || rule.typeIndex >= 6) {
            continue;
        }
        HWND ruleList = callbackRuleLists_[static_cast<std::size_t>(rule.typeIndex)];
        addListRow(ruleList, {
            boolText(rule.enabled),
            std::to_wstring(rule.id),
            std::to_wstring(rule.groupId),
            rule.name,
            rule.operation,
            rule.matchMode,
            rule.action,
            std::to_wstring(rule.timeoutMs),
            rule.timeoutDefault,
            std::to_wstring(rule.priority),
        });
        addListRow(ruleList, {
            L"",
            L"",
            L"发起程序匹配",
            rule.initiatorPattern.empty() ? L"*" : rule.initiatorPattern,
            L"目标程序匹配",
            rule.targetPattern.empty() ? L"*" : rule.targetPattern,
            L"备注",
            rule.comment,
            L"",
            L"",
        });
    }
}

void KernelPage::appendCallbackAppLog(const std::wstring& message) {
    // appendCallbackAppLog appends one operational line to the CallbackIntercept
    // app log. Input is already localized text; output updates the read-only
    // log edit and status label.
    std::wstring log = windowText(callbackAppLogEdit_);
    if (!log.empty() && log.back() != L'\n') {
        log += L"\r\n";
    }
    log += message;
    log += L"\r\n";
    ::SetWindowTextW(callbackAppLogEdit_, log.c_str());
    ::SetWindowTextW(callbackStatusText_, message.c_str());
}

void KernelPage::startCallbackEventReceiver() {
    if (!callbackEventReceiver_) {
        return;
    }
    if (callbackPendingEvents_.size() >= 64U) {
        appendCallbackAppLog(L"待决策队列已达到 64 条，为避免丢失事件，未继续接收。请先处理当前事件。");
        refreshCallbackEventLog();
        return;
    }
    if (callbackEventReceiver_->start()) {
        appendCallbackAppLog(L"已启动 Callback 待决策后台接收器。");
    } else if (callbackEventReceiver_->running()) {
        appendCallbackAppLog(L"Callback 待决策后台接收器已在运行。");
    } else if (callbackEventReceiver_->stopping()) {
        appendCallbackAppLog(L"Callback 待决策后台接收器正在停止，取消完成后可再次启动。");
    } else {
        appendCallbackAppLog(L"无法启动 Callback 待决策后台接收器。");
    }
    refreshCallbackEventLog();
}

void KernelPage::stopCallbackEventReceiver() {
    if (callbackEventReceiver_ && callbackEventReceiver_->running()) {
        callbackEventReceiver_->stop();
        appendCallbackAppLog(L"已请求停止 Callback 待决策后台接收器，当前待决策事件仍可应答。");
    }
    refreshCallbackEventLog();
}

void KernelPage::acceptCallbackEvent(CallbackEventSnapshot snapshot) {
    if (callbackPendingEvents_.size() >= 64U) {
        stopCallbackEventReceiver();
        appendCallbackAppLog(L"待决策队列已满，已停止接收以保留现有事件。请处理当前事件后再继续接收。");
        return;
    }
    const std::wstring kGuid = callbackGuidText(snapshot.event.eventGuid);
    callbackPendingEvents_.push_back(std::move(snapshot));
    appendCallbackAppLog(L"收到待决策 Callback 事件 " + kGuid + L"，等待显式允许或拒绝。");
    if (callbackPendingEvents_.size() >= 64U) {
        stopCallbackEventReceiver();
    }
    refreshCallbackEventLog();
}

void KernelPage::answerCurrentCallbackEvent(const bool allow) {
    if (callbackPendingEvents_.empty()) {
        appendCallbackAppLog(L"没有等待用户决策的 Callback 事件。");
        return;
    }
    if (!callbackAnswerTask_ || callbackAnswerTask_->running()) {
        appendCallbackAppLog(L"上一条 Callback 决策仍在后台提交，请等待结果。");
        return;
    }

    const CallbackEventSnapshot kSnapshot = callbackPendingEvents_.front();
    const std::wstring kGuid = callbackGuidText(kSnapshot.event.eventGuid);
    const std::wstring kTarget = fixedWideText(kSnapshot.event.targetPath);
    const std::wstring kPrompt = std::wstring(allow ? L"允许" : L"拒绝") + L" 当前 Callback 事件？\n\n"
        + L"事件: " + kGuid + L"\n"
        + L"发起 PID: " + std::to_wstring(kSnapshot.event.originatingPid) + L"\n"
        + L"目标: " + (kTarget.empty() ? L"<不可用>" : kTarget) + L"\n\n"
        + L"此决定会立即发送给驱动，超时前不会自动替代为默认动作。";
    if (::MessageBoxW(hwnd_, kPrompt.c_str(), allow ? L"确认允许 Callback 事件" : L"确认拒绝 Callback 事件",
            MB_YESNO | MB_DEFBUTTON2 | MB_ICONWARNING) != IDYES) {
        appendCallbackAppLog(L"用户取消了 Callback 待决策应答。");
        return;
    }

    KernelActionRequest request;
    request.featureId = KernelFeatureId::kCallbackIntercept;
    request.actionId = KernelActionId::kCallbackAnswerEvent;
    request.rowFields = {
        { L"EventGuid", kGuid },
        { L"SourceSessionId", std::to_wstring(kSnapshot.event.sessionId) },
        { L"Decision", allow ? L"Allow" : L"Deny" },
    };
    ::EnableWindow(callbackAllowEventButton_, FALSE);
    ::EnableWindow(callbackDenyEventButton_, FALSE);
    ::SetWindowTextW(callbackStatusText_, L"正在后台提交 Callback 待决策应答…");
    callbackAnswerTask_->request(
        [request] {
            KernelFacade facade;
            return facade.executeAction(request);
        },
        [this, kGuid, allow](std::uint64_t, std::optional<KernelOperationResult>&& result, std::exception_ptr error) {
            if (error || !result.has_value()) {
                appendCallbackAppLog(L"Callback 待决策应答后台任务异常结束，事件仍保留在队列。" );
                refreshCallbackEventLog();
                return;
            }
            if (result->success) {
                const auto kFound = std::find_if(callbackPendingEvents_.begin(), callbackPendingEvents_.end(),
                    [&kGuid](const CallbackEventSnapshot& item) { return callbackGuidText(item.event.eventGuid) == kGuid; });
                if (kFound != callbackPendingEvents_.end()) {
                    callbackPendingEvents_.erase(kFound);
                }
                appendCallbackAppLog(std::wstring(L"Callback 事件 ") + kGuid + (allow ? L" 已允许。" : L" 已拒绝。"));
            } else {
                appendCallbackAppLog(L"Callback 待决策应答失败，事件保留在队列。 " + result->message);
            }
            refreshCallbackEventLog();
        });
}

void KernelPage::refreshCallbackEventLog() {
    const bool kReceiverRunning = callbackEventReceiver_ && callbackEventReceiver_->running();
    const bool kAnswerRunning = callbackAnswerTask_ && callbackAnswerTask_->running();
    if (callbackStartReceiverButton_) {
        const bool kReceiverStopping = callbackEventReceiver_ && callbackEventReceiver_->stopping();
        ::EnableWindow(callbackStartReceiverButton_, !kReceiverRunning && !kReceiverStopping && callbackPendingEvents_.size() < 64U);
    }
    if (callbackStopReceiverButton_) {
        ::EnableWindow(callbackStopReceiverButton_, kReceiverRunning);
    }
    if (callbackAllowEventButton_) {
        ::EnableWindow(callbackAllowEventButton_, !callbackPendingEvents_.empty() && !kAnswerRunning);
    }
    if (callbackDenyEventButton_) {
        ::EnableWindow(callbackDenyEventButton_, !callbackPendingEvents_.empty() && !kAnswerRunning);
    }
    if (!callbackEventLogEdit_) {
        return;
    }

    std::wostringstream log;
    log << L"接收器: " << (kReceiverRunning ? L"运行中" : L"已停止")
        << L" | 待决策: " << callbackPendingEvents_.size() << L"/64\r\n";
    if (callbackPendingEvents_.empty()) {
        log << L"暂无待决策事件。启动接收器后，驱动的 Ask User 规则事件会在这里显示。\r\n";
    } else {
        const CallbackEventSnapshot& current = callbackPendingEvents_.front();
        log << L"当前事件（点击“允许当前”或“拒绝当前”后才会应答）\r\n"
            << L"GUID: " << callbackGuidText(current.event.eventGuid) << L"\r\n"
            << L"类型/操作: " << current.event.callbackType << L" / " << current.event.operationType << L"\r\n"
            << L"发起: PID=" << current.event.originatingPid << L", TID=" << current.event.originatingTid
            << L", Session=" << current.event.sessionId << L"\r\n"
            << L"规则: [" << current.event.groupId << L"] " << fixedWideText(current.event.groupName)
            << L" / [" << current.event.ruleId << L"] " << fixedWideText(current.event.ruleName) << L"\r\n"
            << L"发起路径: " << fixedWideText(current.event.initiatorPath) << L"\r\n"
            << L"目标路径: " << fixedWideText(current.event.targetPath) << L"\r\n"
            << L"默认决策: " << current.event.defaultDecision << L", 超时毫秒: " << current.event.timeoutMs << L"\r\n";
        if (callbackPendingEvents_.size() > 1U) {
            log << L"\r\n后续待决策事件:\r\n";
            const std::size_t kTail = std::min<std::size_t>(callbackPendingEvents_.size(), 16U);
            for (std::size_t index = 1; index < kTail; ++index) {
                const CallbackEventSnapshot& item = callbackPendingEvents_[index];
                log << L"[" << index << L"] " << callbackGuidText(item.event.eventGuid)
                    << L" PID=" << item.event.originatingPid
                    << L" " << fixedWideText(item.event.targetPath) << L"\r\n";
            }
            if (callbackPendingEvents_.size() > kTail) {
                log << L"…其余 " << (callbackPendingEvents_.size() - kTail) << L" 条保留在队列。\r\n";
            }
        }
    }
    ::SetWindowTextW(callbackEventLogEdit_, log.str().c_str());
}

int KernelPage::callbackSelectedRuleTabIndex() const {
    // callbackSelectedRuleTabIndex returns the selected rule tab index. There is
    // no input; output is clamped into the real rule-list range.
    const int kIndex = callbackRuleTab_ ? static_cast<int>(::SendMessageW(callbackRuleTab_, TCM_GETCURSEL, 0, 0)) : 0;
    if (kIndex < 0 || kIndex >= static_cast<int>(callbackRuleLists_.size())) {
        return 0;
    }
    return kIndex;
}

int KernelPage::callbackSelectedGroupRow() const {
    // callbackSelectedGroupRow returns the selected group ListView row. There is
    // no input; output is -1 when the user has not selected a group.
    return callbackGroupList_ ? ListView_GetNextItem(callbackGroupList_, -1, LVNI_SELECTED) : -1;
}

int KernelPage::callbackSelectedRuleRow() const {
    // callbackSelectedRuleRow returns the selected rule row on the active rule
    // tab. There is no input; output is the header row of the two-row original
    // rule presentation, or -1 when no row is selected.
    const int kTab = callbackSelectedRuleTabIndex();
    if (kTab < 0 || kTab >= static_cast<int>(callbackRuleLists_.size())) {
        return -1;
    }
    const int kSelected = ListView_GetNextItem(callbackRuleLists_[static_cast<std::size_t>(kTab)], -1, LVNI_SELECTED);
    if (kSelected < 0) {
        return -1;
    }
    return kSelected % 2 == 0 ? kSelected : kSelected - 1;
}

std::uint32_t KernelPage::callbackSelectedGroupId() const {
    // callbackSelectedGroupId reads the selected group id from the visible grid.
    // There is no input; output falls back to the first local group id.
    const int kRow = callbackSelectedGroupRow();
    if (kRow >= 0) {
        const std::uint32_t kId = parseUnsigned(listViewText(callbackGroupList_, kRow, 0), 0);
        if (kId != 0) {
            return kId;
        }
    }
    return callbackGroups_.empty() ? 0 : callbackGroups_.front().id;
}

void KernelPage::onCallbackAddGroup() {
    // onCallbackAddGroup creates a local rule group. Input is optional name text
    // from the generic filter box; output updates the group grid and app log.
    ensureCallbackLocalModel();
    CallbackRuleGroup group;
    group.id = nextCallbackGroupId_++;
    group.name = windowText(filterEdit_);
    if (group.name.empty()) {
        group.name = L"规则组" + std::to_wstring(group.id);
    }
    group.enabled = true;
    group.priority = static_cast<int>(10 + callbackGroups_.size());
    group.comment = L"Win32 Light 本地规则组";
    callbackGroups_.push_back(group);
    renderCallbackLocalModel();
    appendCallbackAppLog(L"新增规则组: " + group.name);
}

void KernelPage::onCallbackRemoveGroup() {
    // onCallbackRemoveGroup deletes the selected local group and its rules.
    // Input is the group ListView selection; output refreshes local UI state.
    const std::uint32_t kGroupId = callbackSelectedGroupId();
    if (kGroupId == 0 || callbackGroups_.size() <= 1) {
        appendCallbackAppLog(L"至少保留一个规则组，删除已取消。");
        return;
    }
    callbackGroups_.erase(std::remove_if(callbackGroups_.begin(), callbackGroups_.end(), [kGroupId](const CallbackRuleGroup& group) {
        return group.id == kGroupId;
    }), callbackGroups_.end());
    callbackRules_.erase(std::remove_if(callbackRules_.begin(), callbackRules_.end(), [kGroupId](const CallbackRule& rule) {
        return rule.groupId == kGroupId;
    }), callbackRules_.end());
    renderCallbackLocalModel();
    appendCallbackAppLog(L"删除规则组: groupId=" + std::to_wstring(kGroupId));
}

void KernelPage::onCallbackRenameGroup() {
    // onCallbackRenameGroup renames the selected group. Input is the selected
    // group plus filter-box text as the new name; output refreshes the grid.
    const std::uint32_t kGroupId = callbackSelectedGroupId();
    std::wstring newName = windowText(filterEdit_);
    if (newName.empty()) {
        newName = L"规则组" + std::to_wstring(kGroupId) + L"-重命名";
    }
    for (CallbackRuleGroup& group : callbackGroups_) {
        if (group.id == kGroupId) {
            group.name = newName;
            renderCallbackLocalModel();
            appendCallbackAppLog(L"重命名规则组: " + newName);
            return;
        }
    }
}

void KernelPage::onCallbackMoveGroup(const bool moveUp) {
    // onCallbackMoveGroup moves the selected local group. Input is direction;
    // output is reordered local state and refreshed UI.
    const std::uint32_t kGroupId = callbackSelectedGroupId();
    auto found = std::find_if(callbackGroups_.begin(), callbackGroups_.end(), [kGroupId](const CallbackRuleGroup& group) {
        return group.id == kGroupId;
    });
    if (found == callbackGroups_.end()) {
        return;
    }
    const std::size_t kIndex = static_cast<std::size_t>(std::distance(callbackGroups_.begin(), found));
    if (moveUp) {
        if (kIndex == 0) {
            return;
        }
        std::swap(callbackGroups_[kIndex], callbackGroups_[kIndex - 1]);
    } else {
        if (kIndex + 1 >= callbackGroups_.size()) {
            return;
        }
        std::swap(callbackGroups_[kIndex], callbackGroups_[kIndex + 1]);
    }
    renderCallbackLocalModel();
    appendCallbackAppLog(moveUp ? L"规则组已上移。" : L"规则组已下移。");
}

void KernelPage::onCallbackToggleGroupEnabled() {
    // onCallbackToggleGroupEnabled flips the selected local group enabled flag.
    // Input is the current group row selection; output refreshes the group grid
    // and logs the new effective state used by later rule application.
    const std::uint32_t kGroupId = callbackSelectedGroupId();
    for (CallbackRuleGroup& group : callbackGroups_) {
        if (group.id == kGroupId) {
            group.enabled = !group.enabled;
            renderCallbackLocalModel();
            appendCallbackAppLog(L"规则组 " + std::to_wstring(kGroupId) + L" 启用状态=" + boolText(group.enabled));
            return;
        }
    }
    appendCallbackAppLog(L"没有选中可切换的规则组。");
}

void KernelPage::onCallbackAddRule() {
    // onCallbackAddRule appends a rule to the active callback type tab. Inputs
    // are active tab and selected/default group; output is a new local rule row.
    ensureCallbackLocalModel();
    const int kTypeIndex = callbackSelectedRuleTabIndex();
    if (kTypeIndex >= 6) {
        appendCallbackAppLog(L"PID 放行页不创建规则；请使用 PID 添加/移除按钮。");
        return;
    }
    CallbackRule rule;
    rule.id = nextCallbackRuleId_++;
    rule.groupId = callbackSelectedGroupId();
    rule.typeIndex = kTypeIndex;
    rule.name = windowText(filterEdit_);
    if (rule.name.empty()) {
        rule.name = L"规则" + std::to_wstring(rule.id);
    }
    rule.enabled = true;
    rule.operation = kTypeIndex == 0 ? L"全部注册表操作" :
        kTypeIndex == 1 ? L"进程创建" :
        kTypeIndex == 2 ? L"线程创建/退出" :
        kTypeIndex == 3 ? L"镜像加载" :
        kTypeIndex == 4 ? L"句柄创建/复制 + 进程/线程对象" :
        L"文件系统微过滤器全部操作";
    rule.matchMode = L"通配";
    rule.action = L"记录";
    rule.timeoutMs = 5000;
    rule.timeoutDefault = L"允许";
    rule.initiatorPattern = L"*";
    rule.targetPattern = L"*";
    rule.priority = (static_cast<int>(callbackRules_.size()) + 1) * 10;
    rule.comment = L"新建规则";
    callbackRules_.push_back(rule);
    renderCallbackLocalModel();
    appendCallbackAppLog(L"新增规则: " + rule.name);
}

void KernelPage::onCallbackRemoveRule() {
    // onCallbackRemoveRule deletes the selected rule from the active tab. Input
    // is ListView selection; output refreshes local rule tables.
    const int kTab = callbackSelectedRuleTabIndex();
    const int kRow = callbackSelectedRuleRow();
    if (kRow < 0 || kTab >= 6) {
        appendCallbackAppLog(L"当前未选中可删除规则。");
        return;
    }
    const std::uint32_t kRuleId = parseUnsigned(listViewText(callbackRuleLists_[static_cast<std::size_t>(kTab)], kRow, 1), 0);
    callbackRules_.erase(std::remove_if(callbackRules_.begin(), callbackRules_.end(), [kRuleId](const CallbackRule& rule) {
        return rule.id == kRuleId;
    }), callbackRules_.end());
    renderCallbackLocalModel();
    appendCallbackAppLog(L"删除规则: ruleId=" + std::to_wstring(kRuleId));
}

void KernelPage::onCallbackMoveRule(const bool moveUp) {
    // onCallbackMoveRule reorders the selected rule inside local storage. Input
    // is direction and active rule selection; output is refreshed rule grids.
    const int kTab = callbackSelectedRuleTabIndex();
    const int kRow = callbackSelectedRuleRow();
    if (kRow < 0 || kTab >= 6) {
        return;
    }
    const std::uint32_t kRuleId = parseUnsigned(listViewText(callbackRuleLists_[static_cast<std::size_t>(kTab)], kRow, 1), 0);
    auto found = std::find_if(callbackRules_.begin(), callbackRules_.end(), [kRuleId](const CallbackRule& rule) {
        return rule.id == kRuleId;
    });
    if (found == callbackRules_.end()) {
        return;
    }
    const std::size_t kIndex = static_cast<std::size_t>(std::distance(callbackRules_.begin(), found));
    if (moveUp) {
        if (kIndex == 0) {
            return;
        }
        std::swap(callbackRules_[kIndex], callbackRules_[kIndex - 1]);
    } else {
        if (kIndex + 1 >= callbackRules_.size()) {
            return;
        }
        std::swap(callbackRules_[kIndex], callbackRules_[kIndex + 1]);
    }
    renderCallbackLocalModel();
    appendCallbackAppLog(moveUp ? L"规则已上移。" : L"规则已下移。");
}

void KernelPage::onCallbackToggleRuleEnabled() {
    // onCallbackToggleRuleEnabled flips the selected rule enabled flag. Input is
    // the active rule tab selection; output refreshes rule grids and logs state.
    const int kTab = callbackSelectedRuleTabIndex();
    const int kRow = callbackSelectedRuleRow();
    if (kRow < 0 || kTab >= 6) {
        appendCallbackAppLog(L"当前未选中可切换规则。");
        return;
    }
    const std::uint32_t kRuleId = parseUnsigned(listViewText(callbackRuleLists_[static_cast<std::size_t>(kTab)], kRow, 1), 0);
    for (CallbackRule& rule : callbackRules_) {
        if (rule.id == kRuleId) {
            rule.enabled = !rule.enabled;
            renderCallbackLocalModel();
            appendCallbackAppLog(L"规则 " + std::to_wstring(kRuleId) + L" 启用状态=" + boolText(rule.enabled));
            return;
        }
    }
    appendCallbackAppLog(L"未找到选中的本地规则。");
}

void KernelPage::onCallbackCopyRuleText() {
    // onCallbackCopyRuleText mirrors the original rule-table context action.
    // Input is the selected two-row rule; processing serializes one rule as
    // key/value text; output writes CF_UNICODETEXT and an app-log line.
    const int kTab = callbackSelectedRuleTabIndex();
    const int kRow = callbackSelectedRuleRow();
    if (kRow < 0 || kTab >= 6) {
        appendCallbackAppLog(L"复制规则失败：当前未选中有效规则。");
        return;
    }
    const std::uint32_t kRuleId = parseUnsigned(listViewText(callbackRuleLists_[static_cast<std::size_t>(kTab)], kRow, 1), 0);
    const auto kFound = std::find_if(callbackRules_.cbegin(), callbackRules_.cend(), [kRuleId](const CallbackRule& rule) {
        return rule.id == kRuleId;
    });
    if (kFound == callbackRules_.cend()) {
        appendCallbackAppLog(L"复制规则失败：未找到本地规则模型。");
        return;
    }
    const CallbackRule& rule = *kFound;
    std::wostringstream out;
    out << L"KSWORD_CALLBACK_RULE_TEXT_V1\r\n"
        << L"ruleId=" << rule.id << L"\r\n"
        << L"groupId=" << rule.groupId << L"\r\n"
        << L"typeIndex=" << rule.typeIndex << L"\r\n"
        << L"enabled=" << (rule.enabled ? 1 : 0) << L"\r\n"
        << L"priority=" << rule.priority << L"\r\n"
        << L"timeoutMs=" << rule.timeoutMs << L"\r\n"
        << L"ruleName=" << escapeConfigField(rule.name) << L"\r\n"
        << L"operation=" << escapeConfigField(rule.operation) << L"\r\n"
        << L"matchMode=" << escapeConfigField(rule.matchMode) << L"\r\n"
        << L"action=" << escapeConfigField(rule.action) << L"\r\n"
        << L"timeoutDefault=" << escapeConfigField(rule.timeoutDefault) << L"\r\n"
        << L"initiatorPattern=" << escapeConfigField(rule.initiatorPattern) << L"\r\n"
        << L"targetPattern=" << escapeConfigField(rule.targetPattern) << L"\r\n"
        << L"comment=" << escapeConfigField(rule.comment) << L"\r\n";
    setClipboardText(hwnd_, out.str());
    appendCallbackAppLog(L"已复制规则到剪贴板：ruleId=" + std::to_wstring(rule.id));
}

void KernelPage::onCallbackPasteRuleText() {
    // onCallbackPasteRuleText mirrors the original paste-as-new-rule action.
    // Input is CF_UNICODETEXT containing key/value rule text; processing assigns
    // a fresh rule id and current group/type fallback; output appends a rule row.
    const std::wstring kText = getClipboardText(hwnd_);
    if (kText.empty()) {
        appendCallbackAppLog(L"粘贴失败：剪贴板为空。");
        return;
    }
    std::wistringstream input(kText);
    std::wstring line;
    bool sawHeader = false;
    std::unordered_map<std::wstring, std::wstring> values;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == L'\r') {
            line.pop_back();
        }
        if (line.empty()) {
            continue;
        }
        if (!sawHeader) {
            sawHeader = line == L"KSWORD_CALLBACK_RULE_TEXT_V1";
            if (!sawHeader) {
                appendCallbackAppLog(L"粘贴失败：不是支持的规则文本格式。");
                return;
            }
            continue;
        }
        const std::size_t kEqual = line.find(L'=');
        if (kEqual == std::wstring::npos) {
            continue;
        }
        values.emplace(line.substr(0, kEqual), line.substr(kEqual + 1));
    }
    if (!sawHeader) {
        appendCallbackAppLog(L"粘贴失败：不是支持的规则文本格式。");
        return;
    }

    CallbackRule rule;
    rule.id = nextCallbackRuleId_++;
    rule.groupId = parseUnsigned(values[L"groupId"], callbackSelectedGroupId());
    if (rule.groupId == 0) {
        rule.groupId = callbackSelectedGroupId();
    }
    rule.typeIndex = static_cast<int>(parseUnsigned(values[L"typeIndex"], static_cast<std::uint32_t>(callbackSelectedRuleTabIndex())));
    if (rule.typeIndex < 0 || rule.typeIndex > 5) {
        rule.typeIndex = std::min(callbackSelectedRuleTabIndex(), 5);
    }
    rule.enabled = parseUnsigned(values[L"enabled"], 1) != 0;
    rule.priority = parseSigned(values[L"priority"], 10 + static_cast<int>(callbackRules_.size()));
    rule.timeoutMs = parseUnsigned(values[L"timeoutMs"], 5000);
    rule.name = unescapeConfigField(values[L"ruleName"]);
    if (rule.name.empty()) {
        rule.name = L"规则" + std::to_wstring(rule.id);
    }
    rule.operation = unescapeConfigField(values[L"operation"]);
    rule.matchMode = unescapeConfigField(values[L"matchMode"]);
    rule.action = unescapeConfigField(values[L"action"]);
    rule.timeoutDefault = unescapeConfigField(values[L"timeoutDefault"]);
    rule.initiatorPattern = unescapeConfigField(values[L"initiatorPattern"]);
    rule.targetPattern = unescapeConfigField(values[L"targetPattern"]);
    rule.comment = unescapeConfigField(values[L"comment"]);
    if (rule.operation.empty()) { rule.operation = L"回调事件"; }
    if (rule.matchMode.empty()) { rule.matchMode = L"通配"; }
    if (rule.action.empty()) { rule.action = L"记录"; }
    if (rule.timeoutDefault.empty()) { rule.timeoutDefault = L"允许"; }
    if (rule.initiatorPattern.empty()) { rule.initiatorPattern = L"*"; }
    if (rule.targetPattern.empty()) { rule.targetPattern = L"*"; }
    if (rule.comment.empty()) { rule.comment = L"粘贴规则"; }

    callbackRules_.push_back(rule);
    renderCallbackLocalModel();
    appendCallbackAppLog(L"已从剪贴板粘贴规则：newRuleId=" + std::to_wstring(rule.id));
}

void KernelPage::onCallbackBypassAdd() {
    // onCallbackBypassAdd adds PID text from the edit into the bypass table.
    // Input is a comma/semicolon/space separated PID list; output updates table
    // and synchronizes the hidden filter field used by the R0 apply action.
    const std::wstring kText = windowText(callbackBypassPidEdit_);
    std::wstring token;
    std::vector<std::wstring> pids;
    for (const wchar_t kCh : kText) {
        if (kCh == L',' || kCh == L';' || kCh == L' ' || kCh == L'\r' || kCh == L'\n' || kCh == L'\t') {
            if (!token.empty()) {
                pids.push_back(token);
                token.clear();
            }
        } else {
            token.push_back(kCh);
        }
    }
    if (!token.empty()) {
        pids.push_back(token);
    }
    for (const std::wstring& pid : pids) {
        bool exists = false;
        const int kRows = callbackBypassList_ ? ListView_GetItemCount(callbackBypassList_) : 0;
        for (int row = 0; row < kRows; ++row) {
            if (listViewText(callbackBypassList_, row, 0) == pid) {
                exists = true;
                break;
            }
        }
        if (!exists) {
            addListRow(callbackBypassList_, { pid, L"<本地编辑>" });
        }
    }
    std::wstring joined;
    const int kRows = callbackBypassList_ ? ListView_GetItemCount(callbackBypassList_) : 0;
    for (int row = 0; row < kRows; ++row) {
        const std::wstring kPid = listViewText(callbackBypassList_, row, 0);
        if (kPid.empty()) {
            continue;
        }
        if (!joined.empty()) {
            joined += L",";
        }
        joined += kPid;
    }
    ::SetWindowTextW(callbackBypassPidEdit_, joined.c_str());
    ::SetWindowTextW(filterEdit_, joined.c_str());
    if (callbackBypassStatusText_) {
        const std::wstring kStatus = joined.empty()
            ? L"尚未添加 PID；编辑后点击“应用到驱动”生效。"
            : L"已更新本地 PID 放行列表；点击“应用到驱动”后生效。";
        ::SetWindowTextW(callbackBypassStatusText_, kStatus.c_str());
    }
    appendCallbackAppLog(L"PID 放行列表已更新: " + joined);
}

void KernelPage::onCallbackBypassRemove() {
    // onCallbackBypassRemove removes selected PID rows from the bypass table.
    // Input is current ListView selection; output updates table and edit text.
    if (!callbackBypassList_) {
        return;
    }
    int row = -1;
    while ((row = ListView_GetNextItem(callbackBypassList_, -1, LVNI_SELECTED)) >= 0) {
        ListView_DeleteItem(callbackBypassList_, row);
    }
    std::wstring joined;
    const int kRows = ListView_GetItemCount(callbackBypassList_);
    for (int index = 0; index < kRows; ++index) {
        const std::wstring kPid = listViewText(callbackBypassList_, index, 0);
        if (kPid.empty()) {
            continue;
        }
        if (!joined.empty()) {
            joined += L",";
        }
        joined += kPid;
    }
    ::SetWindowTextW(callbackBypassPidEdit_, joined.c_str());
    ::SetWindowTextW(filterEdit_, joined.c_str());
    if (callbackBypassStatusText_) {
        const std::wstring kStatus = joined.empty()
            ? L"已移除选中 PID；当前本地列表为空。"
            : L"已移除选中 PID；点击“应用到驱动”后生效。";
        ::SetWindowTextW(callbackBypassStatusText_, kStatus.c_str());
    }
    appendCallbackAppLog(L"已移除选中 PID，当前列表: " + joined);
}

// buildCallbackModuleFileDetail performs all file metadata, version-resource
// and PE-header reads from an immutable path/row-summary pair. It is called by
// the file-I/O worker and never accesses HWNDs or page state.
std::wstring buildCallbackModuleFileDetail(
    const std::wstring& modulePath,
    const std::wstring& callbackSummary,
    std::wstring* errorText) {
    WIN32_FILE_ATTRIBUTE_DATA fileData{};
    if (!::GetFileAttributesExW(modulePath.c_str(), GetFileExInfoStandard, &fileData)) {
        if (errorText) {
            *errorText = L"当前回调行没有可访问的模块文件，错误 " + std::to_wstring(::GetLastError());
        }
        return {};
    }

    const ULARGE_INTEGER kFileSize{ { fileData.nFileSizeLow, fileData.nFileSizeHigh } };
    const auto kFileTimeText = [](const FILETIME& ft) -> std::wstring {
        FILETIME localFt{};
        SYSTEMTIME st{};
        if (!::FileTimeToLocalFileTime(&ft, &localFt) || !::FileTimeToSystemTime(&localFt, &st)) {
            return L"<unknown>";
        }
        std::wostringstream out;
        out << std::setfill(L'0')
            << std::setw(4) << st.wYear << L'-'
            << std::setw(2) << st.wMonth << L'-'
            << std::setw(2) << st.wDay << L' '
            << std::setw(2) << st.wHour << L':'
            << std::setw(2) << st.wMinute << L':'
            << std::setw(2) << st.wSecond;
        return out.str();
    };

    std::wstring versionText;
    const DWORD kVersionSize = ::GetFileVersionInfoSizeW(modulePath.c_str(), nullptr);
    if (kVersionSize != 0) {
        std::vector<std::uint8_t> versionBytes(kVersionSize);
        if (::GetFileVersionInfoW(modulePath.c_str(), 0, kVersionSize, versionBytes.data())) {
            VS_FIXEDFILEINFO* info = nullptr;
            UINT infoSize = 0;
            if (::VerQueryValueW(versionBytes.data(), L"\\", reinterpret_cast<void**>(&info), &infoSize) && info != nullptr) {
                std::wostringstream version;
                version << HIWORD(info->dwFileVersionMS) << L'.' << LOWORD(info->dwFileVersionMS)
                    << L'.' << HIWORD(info->dwFileVersionLS) << L'.' << LOWORD(info->dwFileVersionLS);
                versionText = version.str();
            }
        }
    }

    std::wstring peText = L"PE: <unavailable>";
    HANDLE file = ::CreateFileW(modulePath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file != INVALID_HANDLE_VALUE) {
        std::uint8_t header[4096]{};
        DWORD bytesRead = 0;
        if (::ReadFile(file, header, sizeof(header), &bytesRead, nullptr) && bytesRead >= sizeof(IMAGE_DOS_HEADER)) {
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(header);
            if (dos->e_magic == IMAGE_DOS_SIGNATURE && dos->e_lfanew > 0 &&
                static_cast<DWORD>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) <= bytesRead) {
                const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(header + dos->e_lfanew);
                if (nt->Signature == IMAGE_NT_SIGNATURE) {
                    std::wostringstream pe;
                    pe << L"PE Machine=0x" << std::hex << std::uppercase << nt->FileHeader.Machine
                       << L", Sections=" << std::dec << nt->FileHeader.NumberOfSections
                       << L", TimeDateStamp=0x" << std::hex << std::uppercase << nt->FileHeader.TimeDateStamp
                       << L", ImageBase=0x" << nt->OptionalHeader.ImageBase
                       << L", SizeOfImage=0x" << nt->OptionalHeader.SizeOfImage;
                    peText = pe.str();
                }
            }
        }
        ::CloseHandle(file);
    }

    std::wostringstream detail;
    detail << L"模块文件详细信息\r\n"
           << L"----------------------------------------\r\n"
           << L"文件路径: " << modulePath << L"\r\n"
           << L"文件大小: " << kFileSize.QuadPart << L" bytes\r\n"
           << L"创建时间: " << kFileTimeText(fileData.ftCreationTime) << L"\r\n"
           << L"修改时间: " << kFileTimeText(fileData.ftLastWriteTime) << L"\r\n"
           << L"访问时间: " << kFileTimeText(fileData.ftLastAccessTime) << L"\r\n"
           << L"版本: " << (versionText.empty() ? L"<unavailable>" : versionText) << L"\r\n"
           << peText << L"\r\n\r\n"
           << callbackSummary;
    return detail.str();
}

// buildDosPathMapping performs the bounded drive-to-device lookup away from
// the UI thread. It returns display text and an optional plain mapping string
// for the UI thread to place on the clipboard.
std::wstring buildDosPathMapping(const std::wstring& ntPath, std::wstring* clipboardText) {
    std::vector<wchar_t> drives(32768, L'\0');
    const DWORD kChars = ::GetLogicalDriveStringsW(static_cast<DWORD>(drives.size()), drives.data());
    std::wstring mappings;
    for (wchar_t* cursor = drives.data(); kChars != 0 && *cursor != L'\0'; cursor += std::wcslen(cursor) + 1) {
        const std::wstring kDriveRoot(cursor);
        if (kDriveRoot.size() < 2 || kDriveRoot[1] != L':') {
            continue;
        }
        const std::wstring kDriveName = kDriveRoot.substr(0, 2);
        std::vector<wchar_t> device(4096, L'\0');
        if (::QueryDosDeviceW(kDriveName.c_str(), device.data(), static_cast<DWORD>(device.size())) == 0) {
            continue;
        }
        const std::wstring kDevicePath(device.data());
        if (kDevicePath.empty() || _wcsnicmp(ntPath.c_str(), kDevicePath.c_str(), kDevicePath.size()) != 0) {
            continue;
        }
        if (!mappings.empty()) {
            mappings += L"\r\n";
        }
        mappings += kDriveName + ntPath.substr(kDevicePath.size());
    }

    if (mappings.empty()) {
        return L"路径: " + ntPath + L"\r\n未找到可用 DOS 路径映射。";
    }
    if (clipboardText) {
        *clipboardText = mappings;
    }
    return L"路径: " + ntPath + L"\r\n已找到 DOS 路径映射（并已复制）:\r\n" + mappings;
}

// setCallbackFileIoControlsEnabled serializes the import/export surface while a
// filesystem task runs. Other callback views remain inspectable and the worker
// result is discarded automatically if this page closes.
void KernelPage::setCallbackFileIoControlsEnabled(const bool enabled) {
    for (const HWND kControl : { callbackImportButton_, callbackExportButton_, callbackExportFileMonitorButton_ }) {
        if (kControl) {
            ::EnableWindow(kControl, enabled);
        }
    }
}

// startCallbackFileIo is the sole callback-rule file I/O entry. Dialog paths
// and immutable text snapshots are captured on the UI thread, while decoding
// and writing execute on AsyncSnapshotTask's worker.
void KernelPage::startCallbackFileIo(
    const CallbackFileIoOperation operation,
    std::wstring path,
    std::wstring text) {
    if (!callbackFileIoTask_) {
        ::MessageBoxW(hwnd_, L"回调配置文件任务不可用。", L"回调文件操作", MB_OK | MB_ICONWARNING);
        return;
    }
    if (callbackFileIoTask_->running()) {
        appendCallbackAppLog(L"回调配置文件任务正在后台执行，请等待完成。");
        return;
    }

    const bool kCallbackOperation = operation != CallbackFileIoOperation::kExportResultTsv;
    const wchar_t* operationText = operation == CallbackFileIoOperation::kImportConfig
        ? L"正在后台导入回调配置…"
        : operation == CallbackFileIoOperation::kExportConfig
            ? L"正在后台导出回调配置…"
            : operation == CallbackFileIoOperation::kExportFileMonitor
                ? L"正在后台导出文件监控事件…"
                : operation == CallbackFileIoOperation::kExportResultTsv
                    ? L"正在后台导出内核结果 TSV…"
                : operation == CallbackFileIoOperation::kCallbackModuleDetail
                    ? L"正在后台读取模块文件详细信息…"
                    : operation == CallbackFileIoOperation::kMapNtPath
                        ? L"正在后台映射 DOS 路径…"
                        : L"正在后台打开模块所在目录…";
    ::SetWindowTextW(statusText_, (std::wstring(L"状态：") + operationText).c_str());
    if (kCallbackOperation) {
        appendCallbackAppLog(operationText);
        setCallbackFileIoControlsEnabled(false);
    }
    callbackFileIoTask_->request(
        [operation, path = std::move(path), text = std::move(text)]() mutable {
            CallbackFileIoResult result{};
            result.operation = operation;
            result.path = std::move(path);
            if (operation == CallbackFileIoOperation::kImportConfig) {
                result.text = readWholeFileText(result.path, &result.errorText);
            } else if (operation == CallbackFileIoOperation::kCallbackModuleDetail) {
                result.text = buildCallbackModuleFileDetail(result.path, text, &result.errorText);
            } else if (operation == CallbackFileIoOperation::kMapNtPath) {
                result.text = buildDosPathMapping(result.path, &result.clipboardText);
            } else if (operation == CallbackFileIoOperation::kOpenModuleFolder) {
                if (::GetFileAttributesW(result.path.c_str()) == INVALID_FILE_ATTRIBUTES) {
                    result.errorText = L"当前回调行没有可访问的模块文件，错误 " + std::to_wstring(::GetLastError());
                } else {
                    const std::wstring kParameters = L"/select,\"" + result.path + L"\"";
                    const HINSTANCE kLaunched = ::ShellExecuteW(nullptr, L"open", L"explorer.exe", kParameters.c_str(), nullptr, SW_SHOWNORMAL);
                    if (reinterpret_cast<INT_PTR>(kLaunched) <= 32) {
                        result.errorText = L"打开模块所在目录失败。";
                    } else {
                        result.text = L"状态：已打开模块所在目录。";
                    }
                }
            } else if (!writeWholeFileText(result.path, text, &result.errorText)) {
                result.text.clear();
            }
            return result;
        },
        [this, operation](std::uint64_t, std::optional<CallbackFileIoResult>&& result, std::exception_ptr error) {
            const bool kCallbackOperation = operation != CallbackFileIoOperation::kExportResultTsv;
            if (kCallbackOperation) {
                setCallbackFileIoControlsEnabled(true);
            }
            if (error || !result.has_value()) {
                const wchar_t* title = kCallbackOperation ? L"回调文件操作" : L"导出 TSV";
                const wchar_t* detail = kCallbackOperation ? L"回调配置文件后台任务异常结束。" : L"内核结果 TSV 后台导出异常结束。";
                if (kCallbackOperation) {
                    appendCallbackAppLog(detail);
                }
                ::SetWindowTextW(statusText_, (std::wstring(L"状态：") + detail).c_str());
                ::MessageBoxW(hwnd_, detail, title, MB_OK | MB_ICONWARNING);
                return;
            }
            applyCallbackFileIoResult(std::move(*result));
        });
}

// applyCallbackFileIoResult applies the completed immutable worker value. The
// file body has already been read or written, so this code only updates local
// callback models and UI diagnostics.
void KernelPage::applyCallbackFileIoResult(CallbackFileIoResult result) {
    const bool kCallbackOperation = result.operation != CallbackFileIoOperation::kExportResultTsv;
    const wchar_t* title = result.operation == CallbackFileIoOperation::kImportConfig
        ? L"导入配置"
        : result.operation == CallbackFileIoOperation::kExportConfig
            ? L"导出配置"
            : result.operation == CallbackFileIoOperation::kExportFileMonitor
                ? L"导出文件事件"
                : result.operation == CallbackFileIoOperation::kExportResultTsv
                    ? L"导出 TSV"
                : result.operation == CallbackFileIoOperation::kCallbackModuleDetail
                    ? L"模块文件详细信息"
                    : result.operation == CallbackFileIoOperation::kMapNtPath
                        ? L"DOS 路径映射"
                        : L"打开模块所在目录";
    if (!result.errorText.empty()) {
        if (kCallbackOperation) {
            appendCallbackAppLog(std::wstring(title) + L"失败: " + result.errorText);
        }
        ::SetWindowTextW(statusText_, (std::wstring(L"状态：") + title + L"失败: " + result.errorText).c_str());
        ::MessageBoxW(hwnd_, result.errorText.c_str(), title, MB_OK | MB_ICONWARNING);
        return;
    }

    if (result.operation == CallbackFileIoOperation::kImportConfig) {
        std::wstring parseError;
        if (!loadCallbackLocalConfig(result.text, &parseError)) {
            appendCallbackAppLog(L"导入配置解析失败: " + parseError);
            ::MessageBoxW(hwnd_, parseError.c_str(), title, MB_OK | MB_ICONWARNING);
            return;
        }
        renderCallbackLocalModel();
        appendCallbackAppLog(L"导入配置成功: " + result.path);
        ::SetWindowTextW(statusText_, (std::wstring(L"状态：已导入回调配置: ") + result.path).c_str());
        return;
    }

    if (result.operation == CallbackFileIoOperation::kCallbackModuleDetail) {
        ::SetWindowTextW(detailEdit_, result.text.c_str());
        ::SetWindowTextW(statusText_, L"状态：已显示模块文件详细信息。");
        return;
    }

    if (result.operation == CallbackFileIoOperation::kMapNtPath) {
        if (!result.clipboardText.empty()) {
            setClipboardText(hwnd_, result.clipboardText);
        }
        ::SetWindowTextW(detailEdit_, result.text.c_str());
        ::SetWindowTextW(statusText_, L"状态：DOS 路径映射完成。");
        return;
    }

    if (result.operation == CallbackFileIoOperation::kOpenModuleFolder) {
        ::SetWindowTextW(statusText_, result.text.c_str());
        return;
    }

    const std::wstring kSuccessText = result.operation == CallbackFileIoOperation::kExportConfig
        ? L"导出配置成功: " + result.path
        : result.operation == CallbackFileIoOperation::kExportFileMonitor
            ? L"文件系统事件导出成功: " + result.path
            : L"已导出 TSV: " + result.path;
    if (kCallbackOperation) {
        appendCallbackAppLog(kSuccessText);
    }
    ::SetWindowTextW(statusText_, (std::wstring(L"状态：") + kSuccessText).c_str());
}

void KernelPage::onCallbackImportConfig() {
    // onCallbackImportConfig obtains the file path on the UI thread, then
    // delegates decoding and disk I/O to startCallbackFileIo.
    if (callbackFileIoTask_ && callbackFileIoTask_->running()) {
        appendCallbackAppLog(L"回调配置文件任务正在后台执行，请等待完成。");
        return;
    }
    wchar_t path[MAX_PATH]{};
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd_;
    ofn.lpstrFilter = L"Ksword Rule File (*.kswrules)\0*.kswrules\0Text (*.txt)\0*.txt\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = path;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (!::GetOpenFileNameW(&ofn)) {
        return;
    }
    startCallbackFileIo(CallbackFileIoOperation::kImportConfig, path);
}

void KernelPage::onCallbackExportConfig() {
    // onCallbackExportConfig captures the current model snapshot before the
    // worker writes it, leaving the page responsive during disk activity.
    if (callbackFileIoTask_ && callbackFileIoTask_->running()) {
        appendCallbackAppLog(L"回调配置文件任务正在后台执行，请等待完成。");
        return;
    }
    wchar_t path[MAX_PATH] = L"callback_rules.kswrules";
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd_;
    ofn.lpstrFilter = L"Ksword Rule File (*.kswrules)\0*.kswrules\0Text (*.txt)\0*.txt\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = path;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    ofn.lpstrDefExt = L"kswrules";
    if (!::GetSaveFileNameW(&ofn)) {
        return;
    }
    startCallbackFileIo(CallbackFileIoOperation::kExportConfig, path, serializeCallbackLocalConfig());
}

void KernelPage::onCallbackExportFileMonitor() {
    // onCallbackExportFileMonitor snapshots the visible table before the worker
    // writes it. The UI read is bounded to the current list contents and disk
    // I/O does not run in this command handler.
    if (callbackFileIoTask_ && callbackFileIoTask_->running()) {
        appendCallbackAppLog(L"回调配置文件任务正在后台执行，请等待完成。");
        return;
    }
    wchar_t path[MAX_PATH] = L"callback_file_monitor.tsv";
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd_;
    ofn.lpstrFilter = L"TSV (*.tsv)\0*.tsv\0Text (*.txt)\0*.txt\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = path;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    ofn.lpstrDefExt = L"tsv";
    if (!::GetSaveFileNameW(&ofn)) {
        return;
    }
    std::wstring text;
    const int kRows = callbackFileMonitorList_ ? ListView_GetItemCount(callbackFileMonitorList_) : 0;
    const int kColumns = callbackFileMonitorList_ ? headerColumnCount(callbackFileMonitorList_) : 0;
    for (int row = 0; row < kRows; ++row) {
        if (row > 0) {
            text += L"\r\n";
        }
        for (int column = 0; column < kColumns; ++column) {
            if (column > 0) {
                text += L'\t';
            }
            text += listViewText(callbackFileMonitorList_, row, column);
        }
    }
    startCallbackFileIo(CallbackFileIoOperation::kExportFileMonitor, path, std::move(text));
}

void KernelPage::openCallbackFileMonitorProcess() {
    // File-monitor rows carry an observed PID but not a creation-time identity.
    // Route it as the current PID so a terminated/reused process is never
    // presented as a guaranteed historical event owner.
    const int kRow = callbackFileMonitorList_
        ? ListView_GetNextItem(callbackFileMonitorList_, -1, LVNI_SELECTED)
        : -1;
    std::uint64_t processId = 0;
    if (kRow < 0 || !parseUnsigned64Value(listViewText(callbackFileMonitorList_, kRow, kCallbackFileMonitorPidColumn), processId) ||
        processId == 0U || processId > static_cast<std::uint64_t>((std::numeric_limits<DWORD>::max)())) {
        appendCallbackAppLog(L"所选文件监控行没有可导航的当前 PID。");
        return;
    }

    ksword::core::NavigationRequest request{};
    request.target = ksword::core::NavigationTarget::kProcessDetails;
    request.entity.kind = ksword::core::EntityKind::kProcess;
    request.entity.id = processId;
    const bool kRouted = ksword::ui::requestEntityNavigation(hwnd_, request);
    appendCallbackAppLog(kRouted
        ? L"已请求打开文件监控事件的当前 PID " + std::to_wstring(processId) + L"；历史归属会重新校验。"
        : L"无法导航到文件监控事件的当前进程实例。");
}

void KernelPage::openCallbackFileMonitorPath() {
    // Only hand the File browser the containing directory of an event path it
    // can interpret without a lossy kernel-to-DOS conversion. The event stays
    // display-only when the driver did not confirm that the path is complete.
    const int kRow = callbackFileMonitorList_
        ? ListView_GetNextItem(callbackFileMonitorList_, -1, LVNI_SELECTED)
        : -1;
    const std::wstring kPath = kRow >= 0
        ? listViewText(callbackFileMonitorList_, kRow, kCallbackFileMonitorPathColumn)
        : std::wstring{};
    const std::wstring kDirectory = kRow >= 0 &&
        listViewText(callbackFileMonitorList_, kRow, kCallbackFileMonitorPathStateColumn) == L"完整"
        ? fileMonitorContainingDirectory(kPath)
        : std::wstring{};
    if (kDirectory.empty()) {
        appendCallbackAppLog(L"所选文件监控路径未确认完整或不是可打开的 DOS/UNC 路径；已保留原始事件文本。");
        return;
    }

    ksword::core::NavigationRequest request{};
    request.target = ksword::core::NavigationTarget::kFileBrowser;
    request.entity.kind = ksword::core::EntityKind::kFile;
    request.entity.text = kDirectory;
    const bool kRouted = ksword::ui::requestEntityNavigation(hwnd_, request);
    appendCallbackAppLog(kRouted
        ? L"已在文件模块打开文件监控路径所在目录。"
        : L"文件模块当前无法接收该文件监控路径所在目录。");
}

void KernelPage::copyCallbackPanelSelection(HWND source) {
    // copyCallbackPanelSelection copies rows from the active CallbackIntercept
    // sub-table. Input is the focused/context ListView; processing falls back to
    // the last context source; output places selected rows with headers on the
    // clipboard and writes a short app-log line.
    HWND list = source;
    if (list != callbackGroupList_ &&
        list != callbackBypassList_ &&
        list != callbackFileMonitorList_ &&
        std::find(callbackRuleLists_.begin(), callbackRuleLists_.end(), list) == callbackRuleLists_.end()) {
        list = callbackContextList_;
    }
    if (!list) {
        appendCallbackAppLog(L"没有可复制的 CallbackIntercept 表格。");
        return;
    }
    std::wstring text = buildListViewSelectionTsv(list, true);
    if (text.empty()) {
        const int kRows = ListView_GetItemCount(list);
        if (kRows > 0) {
            ListView_SetItemState(list, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
            text = buildListViewSelectionTsv(list, true);
        }
    }
    if (text.empty()) {
        appendCallbackAppLog(L"当前表格没有可复制的选中行。");
        return;
    }
    setClipboardText(hwnd_, text);
    appendCallbackAppLog(L"已复制 CallbackIntercept 表格选中行。");
}

void KernelPage::showCallbackInterceptContextMenu(HWND source, POINT screenPoint) {
    // showCallbackInterceptContextMenu mirrors the original CallbackIntercept
    // right-click workflow for groups, rules, PID bypass and file-monitor rows.
    // Inputs are the source ListView and screen coordinates; output is a modal
    // popup whose commands dispatch through WM_COMMAND.
    if (!source) {
        return;
    }
    callbackContextList_ = source;
    if (screenPoint.x == -1 && screenPoint.y == -1) {
        RECT rc{};
        const int kSelected = ListView_GetNextItem(source, -1, LVNI_SELECTED);
        if (kSelected >= 0 && ListView_GetItemRect(source, kSelected, &rc, LVIR_BOUNDS)) {
            screenPoint.x = rc.left;
            screenPoint.y = rc.bottom;
            ::ClientToScreen(source, &screenPoint);
        } else {
            ::GetCursorPos(&screenPoint);
        }
    } else {
        POINT clientPoint = screenPoint;
        ::ScreenToClient(source, &clientPoint);
        LVHITTESTINFO hit{};
        hit.pt = clientPoint;
        const int kRow = ListView_HitTest(source, &hit);
        if (kRow >= 0) {
            const UINT kState = ListView_GetItemState(source, kRow, LVIS_SELECTED);
            if ((kState & LVIS_SELECTED) == 0) {
                ListView_SetItemState(source, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
            }
            ListView_SetItemState(source, kRow, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
            ListView_EnsureVisible(source, kRow, FALSE);
        }
    }

    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    const bool kHasSelection = ListView_GetNextItem(source, -1, LVNI_SELECTED) >= 0;
    bool appendCopySelection = false;
    if (source == callbackGroupList_) {
        ::AppendMenuW(menu, MF_STRING, kMenuCallbackGroupAdd, L"新增规则组");
        ::AppendMenuW(menu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCallbackGroupToggleEnabled, L"切换规则组启用");
        ::AppendMenuW(menu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCallbackGroupRename, L"重命名规则组");
        ::AppendMenuW(menu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCallbackGroupRemove, L"删除规则组");
        ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(menu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCallbackGroupMoveUp, L"规则组上移");
        ::AppendMenuW(menu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCallbackGroupMoveDown, L"规则组下移");
        appendCopySelection = true;
    } else if (std::find(callbackRuleLists_.begin(), callbackRuleLists_.end(), source) != callbackRuleLists_.end()) {
        ::AppendMenuW(menu, MF_STRING, kMenuCallbackRuleAdd, L"新增规则");
        ::AppendMenuW(menu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCallbackRuleToggleEnabled, L"切换规则启用");
        ::AppendMenuW(menu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCallbackRuleRemove, L"删除规则");
        ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(menu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCallbackRuleMoveUp, L"规则上移");
        ::AppendMenuW(menu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCallbackRuleMoveDown, L"规则下移");
        ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(menu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCallbackRuleCopyText, L"复制规则文本");
        ::AppendMenuW(menu, MF_STRING, kMenuCallbackRulePasteNew, L"粘贴为新规则");
        ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(menu, MF_STRING, kMenuCallbackGroupAdd, L"新增规则组");
        appendCopySelection = false;
    } else if (source == callbackBypassList_) {
        ::AppendMenuW(menu, MF_STRING, kMenuCallbackBypassAdd, L"添加 PID 到本地列表");
        ::AppendMenuW(menu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCallbackBypassRemove, L"移除选中 PID");
        ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(menu, MF_STRING, kMenuCallbackBypassApply, L"应用 PID 放行到驱动");
        ::AppendMenuW(menu, MF_STRING, kMenuCallbackBypassClear, L"清空驱动 PID 放行");
        ::AppendMenuW(menu, MF_STRING, kMenuCallbackBypassRefresh, L"从驱动刷新 PID 放行");
        appendCopySelection = true;
    } else if (source == callbackFileMonitorList_) {
        const int kSelected = kHasSelection ? ListView_GetNextItem(source, -1, LVNI_SELECTED) : -1;
        std::uint64_t processId = 0;
        const bool kCanOpenProcess = kSelected >= 0 &&
            parseUnsigned64Value(listViewText(source, kSelected, kCallbackFileMonitorPidColumn), processId) &&
            processId != 0U && processId <= static_cast<std::uint64_t>((std::numeric_limits<DWORD>::max)());
        const bool kCanOpenPath = kSelected >= 0 &&
            listViewText(source, kSelected, kCallbackFileMonitorPathStateColumn) == L"完整" &&
            !fileMonitorContainingDirectory(listViewText(source, kSelected, kCallbackFileMonitorPathColumn)).empty();
        ::AppendMenuW(menu, MF_STRING, kMenuCallbackFileMonitorStart, L"启动/补充 FSCTL 文件监控");
        ::AppendMenuW(menu, MF_STRING, kMenuCallbackFileMonitorDrain, L"拉取文件监控事件");
        ::AppendMenuW(menu, MF_STRING, kMenuCallbackFileMonitorClear, L"清空当前文件事件");
        ::AppendMenuW(menu, MF_STRING, kMenuCallbackFileMonitorExport, L"导出当前文件事件");
        HMENU investigationMenu = ::CreatePopupMenu();
        if (investigationMenu) {
            ::AppendMenuW(investigationMenu, MF_STRING | (kCanOpenProcess ? MF_ENABLED : MF_GRAYED),
                kMenuCallbackFileMonitorOpenProcess, L"打开所属进程详细信息");
            ::AppendMenuW(investigationMenu, MF_STRING | (kCanOpenPath ? MF_ENABLED : MF_GRAYED),
                kMenuCallbackFileMonitorOpenPath, L"在文件模块查看所在目录");
            ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(investigationMenu), L"关联调查");
        }
        appendCopySelection = true;
    } else {
        ::DestroyMenu(menu);
        return;
    }
    if (appendCopySelection) {
        ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(menu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCallbackCopyPanelSelection, L"复制选中行（含表头）");
    }
    ::TrackPopupMenu(menu, TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y, 0, hwnd_, nullptr);
    ::DestroyMenu(menu);
}

std::wstring KernelPage::serializeCallbackLocalConfig() const {
    // serializeCallbackLocalConfig converts local callback groups/rules into a
    // stable tab-separated text format. There is no input; output can be saved
    // as .kswrules and later imported by this lightweight editor.
    std::wostringstream out;
    out << L"KSWORD_ARKLIGHT_CALLBACK_RULES_V1\r\n";
    out << L"GLOBAL\t" << (callbackRulesGlobalEnabled() ? 1 : 0) << L"\r\n";
    for (const CallbackRuleGroup& group : callbackGroups_) {
        out << L"GROUP\t"
            << group.id << L'\t'
            << (group.enabled ? 1 : 0) << L'\t'
            << group.priority << L'\t'
            << escapeConfigField(group.name) << L'\t'
            << escapeConfigField(group.comment) << L"\r\n";
    }
    for (const CallbackRule& rule : callbackRules_) {
        out << L"RULE\t"
            << rule.id << L'\t'
            << rule.groupId << L'\t'
            << rule.typeIndex << L'\t'
            << (rule.enabled ? 1 : 0) << L'\t'
            << rule.priority << L'\t'
            << rule.timeoutMs << L'\t'
            << escapeConfigField(rule.name) << L'\t'
            << escapeConfigField(rule.operation) << L'\t'
            << escapeConfigField(rule.matchMode) << L'\t'
            << escapeConfigField(rule.action) << L'\t'
            << escapeConfigField(rule.timeoutDefault) << L'\t'
            << escapeConfigField(rule.initiatorPattern) << L'\t'
            << escapeConfigField(rule.targetPattern) << L'\t'
            << escapeConfigField(rule.comment) << L"\r\n";
    }
    return out.str();
}

bool KernelPage::callbackRulesGlobalEnabled() const {
    // callbackRulesGlobalEnabled reads the original CallbackIntercept global
    // enable checkbox. There is no input; output controls the globalFlags field
    // in the serialized local rule document consumed by KernelFacade.
    return callbackGlobalEnabledCheck_ == nullptr || Button_GetCheck(callbackGlobalEnabledCheck_) == BST_CHECKED;
}

bool KernelPage::loadCallbackLocalConfig(const std::wstring& text, std::wstring* errorText) {
    // loadCallbackLocalConfig parses the lightweight tab-separated rule format.
    // Input is a complete text file; output updates local vectors and reports
    // false with an error string on malformed mandatory fields.
    std::vector<CallbackRuleGroup> groups;
    std::vector<CallbackRule> rules;
    std::uint32_t maxGroupId = 0;
    std::uint32_t maxRuleId = 0;
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
                if (errorText) {
                    *errorText = L"配置头不匹配，无法导入。";
                }
                return false;
            }
            sawHeader = true;
            continue;
        }
        const std::vector<std::wstring> kFields = splitTabLine(line);
        if (kFields.empty()) {
            continue;
        }
        if (kFields[0] == L"GLOBAL") {
            if (kFields.size() >= 2 && callbackGlobalEnabledCheck_ != nullptr) {
                Button_SetCheck(callbackGlobalEnabledCheck_, parseUnsigned(kFields[1], 1) != 0 ? BST_CHECKED : BST_UNCHECKED);
            }
        } else if (kFields[0] == L"GROUP") {
            if (kFields.size() < 6) {
                if (errorText) {
                    *errorText = L"GROUP 行字段不足。";
                }
                return false;
            }
            CallbackRuleGroup group;
            group.id = parseUnsigned(kFields[1], 0);
            group.enabled = parseUnsigned(kFields[2], 0) != 0;
            group.priority = parseSigned(kFields[3], 10);
            group.name = unescapeConfigField(kFields[4]);
            group.comment = unescapeConfigField(kFields[5]);
            if (group.id == 0) {
                if (errorText) {
                    *errorText = L"GROUP id 非法。";
                }
                return false;
            }
            maxGroupId = std::max(maxGroupId, group.id);
            groups.push_back(group);
        } else if (kFields[0] == L"RULE") {
            if (kFields.size() < 13) {
                if (errorText) {
                    *errorText = L"RULE 行字段不足。";
                }
                return false;
            }
            CallbackRule rule;
            rule.id = parseUnsigned(kFields[1], 0);
            rule.groupId = parseUnsigned(kFields[2], 0);
            rule.typeIndex = parseSigned(kFields[3], 0);
            rule.enabled = parseUnsigned(kFields[4], 0) != 0;
            rule.priority = parseSigned(kFields[5], 10);
            rule.timeoutMs = parseUnsigned(kFields[6], 0);
            rule.name = unescapeConfigField(kFields[7]);
            rule.operation = unescapeConfigField(kFields[8]);
            rule.matchMode = unescapeConfigField(kFields[9]);
            rule.action = unescapeConfigField(kFields[10]);
            rule.timeoutDefault = unescapeConfigField(kFields[11]);
            if (kFields.size() >= 15) {
                rule.initiatorPattern = unescapeConfigField(kFields[12]);
                rule.targetPattern = unescapeConfigField(kFields[13]);
                rule.comment = unescapeConfigField(kFields[14]);
            } else {
                rule.initiatorPattern = L"*";
                rule.targetPattern = L"*";
                rule.comment = unescapeConfigField(kFields[12]);
            }
            if (rule.id == 0 || rule.groupId == 0 || rule.typeIndex < 0 || rule.typeIndex > 5) {
                if (errorText) {
                    *errorText = L"RULE id/group/type 非法。";
                }
                return false;
            }
            maxRuleId = std::max(maxRuleId, rule.id);
            rules.push_back(rule);
        }
    }
    if (!sawHeader) {
        if (errorText) {
            *errorText = L"空配置或缺少头。";
        }
        return false;
    }
    if (groups.empty()) {
        groups.push_back({ 1, L"默认组", true, 10, L"导入文件未包含组，自动创建。" });
        maxGroupId = 1;
    }
    callbackGroups_ = std::move(groups);
    callbackRules_ = std::move(rules);
    nextCallbackGroupId_ = maxGroupId + 1;
    nextCallbackRuleId_ = maxRuleId + 1;
    return true;
}

std::uint32_t KernelPage::currentIncludeFlags() const {
    // currentIncludeFlags reads the Hook include combo. Input is the selected
    // combo item; processing returns the item data only on pages that use it;
    // output is KernelRequest::flags consumed by KernelFacade.
    if (!includeCombo_) {
        return 0;
    }
    const int kSelection = static_cast<int>(::SendMessageW(includeCombo_, CB_GETCURSEL, 0, 0));
    if (kSelection < 0) {
        return 0;
    }
    const LRESULT kData = ::SendMessageW(includeCombo_, CB_GETITEMDATA, static_cast<WPARAM>(kSelection), 0);
    if (kData == CB_ERR) {
        return 0;
    }
    return static_cast<std::uint32_t>(kData);
}

void KernelPage::updateSummaryTableFromRows() {
    // updateSummaryTableFromRows mirrors original DynData/DriverStatus summary
    // tables. Inputs are current cached rows and columns; processing extracts
    // Populate the first few non-detail summary rows into a project/value list; output updates.
    // summaryList_ without changing the main result table.
    if (!summaryList_) {
        return;
    }
    ListView_DeleteAllItems(summaryList_);
    const KernelFeatureDescriptor* descriptor = currentDescriptor();
    if (descriptor == nullptr) {
        return;
    }
    const KernelPageLayoutKind kKind = layoutKindForFeature(descriptor->id);
    if (kKind != KernelPageLayoutKind::kDualTable && kKind != KernelPageLayoutKind::kRuntimePanel) {
        return;
    }
    const auto kValueFromRow = [](const std::vector<std::wstring>& row, const std::vector<std::wstring>& columns, std::initializer_list<const wchar_t*> names) -> std::wstring {
        for (const wchar_t* name : names) {
            for (std::size_t column = 0; column < columns.size() && column < row.size(); ++column) {
                if (_wcsicmp(columns[column].c_str(), name) == 0 && !row[column].empty()) {
                    return row[column];
                }
            }
        }
        return {};
    };
    const auto kAppendSummary = [&](int& rowIndex, const std::wstring& name, const std::wstring& value) {
        if (name.empty() || value.empty()) {
            return;
        }
        LVITEMW item{};
        item.mask = LVIF_TEXT;
        item.iItem = rowIndex;
        item.iSubItem = 0;
        item.pszText = const_cast<LPWSTR>(name.c_str());
        const int kInserted = ListView_InsertItem(summaryList_, &item);
        if (kInserted >= 0) {
            ListView_SetItemText(summaryList_, kInserted, 1, const_cast<LPWSTR>(value.c_str()));
            ++rowIndex;
        }
    };
    if (descriptor->id == KernelFeatureId::kDynData) {
        int rowIndex = 0;
        int profileRows = 0;
        int fieldRows = 0;
        int failedRows = 0;
        for (const std::vector<std::wstring>& row : currentRows_) {
            const std::wstring kField = kValueFromRow(row, currentColumns_, { L"Field", L"字段" });
            const std::wstring kSource = kValueFromRow(row, currentColumns_, { L"Source", L"来源" });
            const std::wstring kStatus = kValueFromRow(row, currentColumns_, { L"Status", L"状态", L"DynData Fields IO" });
            if (!kField.empty()) {
                ++fieldRows;
            }
            if (kSource.find(L"Profile") != std::wstring::npos || kSource.find(L"Pack") != std::wstring::npos) {
                ++profileRows;
            }
            if (kStatus.find(L"FAIL") != std::wstring::npos || kStatus.find(L"失败") != std::wstring::npos) {
                ++failedRows;
            }
        }
        for (const std::vector<std::wstring>& row : currentRows_) {
            kAppendSummary(rowIndex, L"状态标志", kValueFromRow(row, currentColumns_, { L"StatusFlags" }));
            kAppendSummary(rowIndex, L"System Informer 版本", kValueFromRow(row, currentColumns_, { L"SI Version" }));
            kAppendSummary(rowIndex, L"System Informer 长度", kValueFromRow(row, currentColumns_, { L"SI Length" }));
            kAppendSummary(rowIndex, L"匹配 Profile Class", kValueFromRow(row, currentColumns_, { L"MatchedClass" }));
            kAppendSummary(rowIndex, L"驱动字段数", kValueFromRow(row, currentColumns_, { L"FieldCount" }));
            kAppendSummary(rowIndex, L"能力掩码", kValueFromRow(row, currentColumns_, { L"CapabilityMask" }));
            kAppendSummary(rowIndex, L"ntoskrnl", kValueFromRow(row, currentColumns_, { L"Ntos" }));
            kAppendSummary(rowIndex, L"lxcore", kValueFromRow(row, currentColumns_, { L"Lxcore" }));
            kAppendSummary(rowIndex, L"字段 IO", kValueFromRow(row, currentColumns_, { L"DynData Fields IO" }));
            kAppendSummary(rowIndex, L"字段总数", kValueFromRow(row, currentColumns_, { L"FieldsTotal" }));
            kAppendSummary(rowIndex, L"字段返回数", kValueFromRow(row, currentColumns_, { L"FieldsReturned" }));
            if (rowIndex >= 10) {
                break;
            }
        }
        kAppendSummary(rowIndex, L"可见字段行", std::to_wstring(fieldRows));
        kAppendSummary(rowIndex, L"Profile/Pack 诊断行", std::to_wstring(profileRows));
        kAppendSummary(rowIndex, L"失败诊断行", std::to_wstring(failedRows));
        return;
    }
    if (descriptor->id == KernelFeatureId::kDriverStatus) {
        int rowIndex = 0;
        int featureRows = 0;
        int unavailableRows = 0;
        for (const std::vector<std::wstring>& row : currentRows_) {
            const std::wstring kFeature = kValueFromRow(row, currentColumns_, { L"Feature", L"功能" });
            const std::wstring kState = kValueFromRow(row, currentColumns_, { L"State", L"状态" });
            if (!kFeature.empty()) {
                ++featureRows;
            }
            if (kState.find(L"Unavailable") != std::wstring::npos || kState.find(L"Disabled") != std::wstring::npos || kState.find(L"不可用") != std::wstring::npos) {
                ++unavailableRows;
            }
        }
        for (const std::vector<std::wstring>& row : currentRows_) {
            kAppendSummary(rowIndex, L"能力版本", kValueFromRow(row, currentColumns_, { L"Version" }));
            kAppendSummary(rowIndex, L"协议版本", kValueFromRow(row, currentColumns_, { L"Protocol" }));
            kAppendSummary(rowIndex, L"状态标志", kValueFromRow(row, currentColumns_, { L"StatusFlags" }));
            kAppendSummary(rowIndex, L"安全策略", kValueFromRow(row, currentColumns_, { L"SecurityPolicy" }));
            kAppendSummary(rowIndex, L"DynData 状态", kValueFromRow(row, currentColumns_, { L"DynDataStatus" }));
            kAppendSummary(rowIndex, L"功能总数", kValueFromRow(row, currentColumns_, { L"FeatureTotal" }));
            kAppendSummary(rowIndex, L"功能返回数", kValueFromRow(row, currentColumns_, { L"FeatureReturned" }));
            kAppendSummary(rowIndex, L"最后错误来源", kValueFromRow(row, currentColumns_, { L"LastError" }));
            if (rowIndex >= 8) {
                break;
            }
        }
        kAppendSummary(rowIndex, L"可见能力行", std::to_wstring(featureRows));
        kAppendSummary(rowIndex, L"不可用/禁用行", std::to_wstring(unavailableRows));
        return;
    }
    int outRow = 0;
    const std::size_t kMaxRows = std::min<std::size_t>(currentRows_.size(), 8);
    for (std::size_t rowIndex = 0; rowIndex < kMaxRows; ++rowIndex) {
        const std::vector<std::wstring>& row = currentRows_[rowIndex];
        for (std::size_t column = 1; column < currentColumns_.size() && column < row.size(); ++column) {
            if (row[column].empty()) {
                continue;
            }
            const std::wstring& name = currentColumns_[column];
            if (name == L"Detail" || name == L"功能" || name == L"原因" ||
                (name == L"状态" && kKind != KernelPageLayoutKind::kRuntimePanel)) {
                continue;
            }
            if (kKind == KernelPageLayoutKind::kRuntimePanel &&
                name != L"Section" &&
                name != L"RegisteredText" &&
                name != L"Pending" &&
                name != L"PendingDecisions" &&
                name != L"WaitingReceivers" &&
                name != L"RuleVersion" &&
                name != L"AppliedTime" &&
                name != L"Status" &&
                name != L"Type" &&
                name != L"Enabled") {
                continue;
            }
            LVITEMW item{};
            item.mask = LVIF_TEXT;
            item.iItem = outRow;
            item.iSubItem = 0;
            item.pszText = const_cast<LPWSTR>(name.c_str());
            const int kInserted = ListView_InsertItem(summaryList_, &item);
            if (kInserted >= 0) {
                ListView_SetItemText(summaryList_, kInserted, 1, const_cast<LPWSTR>(row[column].c_str()));
                ++outRow;
            }
            if (outRow >= 64) {
                return;
            }
        }
    }
}

void KernelPage::updatePropertyTableFromSelection() {
    // updatePropertyTableFromSelection mirrors the original object namespace
    // property table. Inputs are either the selected object row or the selected
    // synthetic tree node; processing emits the same fixed fields as the Qt
    // KernelDock; output is propertyList_ content.
    if (!propertyList_) {
        return;
    }
    ListView_DeleteAllItems(propertyList_);
    const KernelFeatureDescriptor* descriptor = currentDescriptor();
    if (descriptor == nullptr || layoutKindForFeature(descriptor->id) != KernelPageLayoutKind::kTreeWithPropertyTable) {
        return;
    }
    int propertyRow = 0;
    const auto kAppendProperty = [&](const std::wstring& name, const std::wstring& value) {
        if (name.empty()) {
            return;
        }
        LVITEMW item{};
        item.mask = LVIF_TEXT;
        item.iItem = propertyRow;
        item.iSubItem = 0;
        item.pszText = const_cast<LPWSTR>(name.c_str());
        const int kInserted = ListView_InsertItem(propertyList_, &item);
        if (kInserted >= 0) {
            ListView_SetItemText(propertyList_, kInserted, 1, const_cast<LPWSTR>(value.c_str()));
            ++propertyRow;
        }
    };
    const auto kSafeText = [](const std::wstring& value, const wchar_t* fallback = L"<空>") -> std::wstring {
        return value.empty() ? std::wstring(fallback) : value;
    };
    const auto kCellAt = [&](const int row, std::initializer_list<const wchar_t*> names) -> std::wstring {
        if (!resultList_ || row < 0) {
            return {};
        }
        for (const wchar_t* name : names) {
            for (int column = 0; column < static_cast<int>(currentColumns_.size()); ++column) {
                if (_wcsicmp(currentColumns_[static_cast<std::size_t>(column)].c_str(), name) == 0) {
                    const std::wstring kValue = visibleCellText(row, column);
                    if (!kValue.empty()) {
                        return kValue;
                    }
                }
            }
        }
        return {};
    };
    const int kRow = resultList_ ? ListView_GetNextItem(resultList_, -1, LVNI_SELECTED) : -1;
    const std::wstring kSelectedNodeKind = kRow >= 0 ? kCellAt(kRow, { L"NodeKind" }) : objectNamespaceSelectedKind_;
    const bool kSyntheticNode = kRow < 0 ||
        _wcsicmp(kSelectedNodeKind.c_str(), L"Root") == 0 ||
        _wcsicmp(kSelectedNodeKind.c_str(), L"Directory") == 0;
    if (kSyntheticNode) {
        const std::wstring kNodeName = kRow >= 0
            ? kCellAt(kRow, { L"名称", L"Name" })
            : objectNamespaceSelectedPath_;
        const std::wstring kNodeType = kRow >= 0
            ? kCellAt(kRow, { L"类型", L"Type" })
            : objectNamespaceSelectedKind_;
        const std::wstring kNodePath = kRow >= 0
            ? kCellAt(kRow, { L"Path", L"完整路径", L"fullPath", L"路径/说明", L"Source", L"Parent" })
            : objectNamespaceSelectedPath_;
        const std::wstring kNodeDescription = kRow >= 0
            ? kCellAt(kRow, { L"Detail", L"scopeDescriptionText", L"Scope", L"scope", L"路径/说明" })
            : objectNamespaceSelectedDescription_;
        kAppendProperty(L"节点名称", kSafeText(kNodeName));
        kAppendProperty(L"节点类型", kSafeText(kNodeType));
        kAppendProperty(L"节点路径", kSafeText(kNodePath, L"<无>"));
        kAppendProperty(L"节点说明", kSafeText(kNodeDescription, L"<无>"));
        kAppendProperty(L"提示", L"当前节点是树层级摘要，展开下级并选择对象项可查看完整字段。");
        return;
    }

    kAppendProperty(L"rootPathText（根目录）", kSafeText(kCellAt(kRow, { L"rootPathText", L"Root", L"Source" })));
    kAppendProperty(L"scopeDescriptionText（作用说明）", kSafeText(kCellAt(kRow, { L"scopeDescriptionText", L"Scope", L"scope", L"Detail", L"路径/说明" })));
    kAppendProperty(L"directoryPathText（当前目录）", kSafeText(kCellAt(kRow, { L"directoryPathText", L"directoryPath", L"Directory", L"Parent", L"来源目录" })));
    kAppendProperty(L"objectNameText（对象名）", kSafeText(kCellAt(kRow, { L"objectNameText", L"objectName", L"Name", L"名称" })));
    kAppendProperty(L"objectTypeText（对象类型）", kSafeText(kCellAt(kRow, { L"objectTypeText", L"objectType", L"Type", L"类型" })));
    kAppendProperty(L"fullPathText（完整路径）", kSafeText(kCellAt(kRow, { L"fullPathText", L"fullPath", L"Path", L"完整路径", L"路径/说明" })));
    kAppendProperty(L"enumApiText（枚举API）", kSafeText(kCellAt(kRow, { L"enumApiText", L"enumApi", L"EnumApi", L"枚举 API", L"EnumerationApi" })));
    kAppendProperty(L"symbolicLinkTargetText（符号链接目标）", kSafeText(kCellAt(kRow, { L"symbolicLinkTargetText", L"symbolicTarget", L"Target", L"targetPath", L"符号链接目标" }), L"<无>"));
    kAppendProperty(L"statusText（状态）", kSafeText(kCellAt(kRow, { L"statusText", L"Status", L"状态" })));
    kAppendProperty(L"statusCode（NTSTATUS）", kSafeText(kCellAt(kRow, { L"statusCode", L"StatusCode", L"NTSTATUS", L"LastStatus" }), L"0x00000000"));
    kAppendProperty(L"querySucceeded（查询成功）", kSafeText(kCellAt(kRow, { L"querySucceeded", L"QuerySucceeded" }), L"<未知>"));
    kAppendProperty(L"isDirectory（是否目录）", kSafeText(kCellAt(kRow, { L"isDirectory", L"IsDirectory" }), _wcsicmp(kCellAt(kRow, { L"类型", L"Type", L"objectType" }).c_str(), L"Directory") == 0 ? L"true" : L"false"));
    kAppendProperty(L"isSymbolicLink（是否符号链接）", kSafeText(kCellAt(kRow, { L"isSymbolicLink", L"IsSymbolicLink" }), _wcsicmp(kCellAt(kRow, { L"类型", L"Type", L"objectType" }).c_str(), L"SymbolicLink") == 0 ? L"true" : L"false"));
    kAppendProperty(L"详情", kSafeText(kCellAt(kRow, { L"Detail" }), L"<无>"));
    const int kColumns = headerColumnCount(resultList_);
    for (int column = 0; column < kColumns; ++column) {
        const std::wstring kName = column < static_cast<int>(currentColumns_.size())
            ? currentColumns_[static_cast<std::size_t>(column)]
            : std::wstring(L"Column ") + std::to_wstring(column);
        const std::wstring kValue = visibleCellText(kRow, column);
        if (kName.empty() || kValue.empty()) {
            continue;
        }
        bool alreadyShown = false;
        for (int existing = 0; existing < propertyRow; ++existing) {
            if (_wcsicmp(listViewText(propertyList_, existing, 0).c_str(), kName.c_str()) == 0) {
                alreadyShown = true;
                break;
            }
        }
        if (!alreadyShown) {
            kAppendProperty(kName, kValue);
        }
    }
}

void KernelPage::showResultContextMenu(POINT screenPoint) {
    // showResultContextMenu exposes copy operations for real kernel rows.
    // Inputs are screen coordinates from WM_CONTEXTMENU; processing creates a
    // short-lived Win32 popup; no value is returned.
    if (!resultList_) {
        return;
    }
    if (screenPoint.x == -1 && screenPoint.y == -1) {
        RECT rc{};
        const int kSelected = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED);
        if (kSelected >= 0 && ListView_GetItemRect(resultList_, kSelected, &rc, LVIR_BOUNDS)) {
            screenPoint.x = rc.left;
            screenPoint.y = rc.bottom;
            ::ClientToScreen(resultList_, &screenPoint);
        } else {
            ::GetCursorPos(&screenPoint);
        }
    }

    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    const KernelFeatureDescriptor* descriptor = currentDescriptor();
    if (descriptor != nullptr && descriptor->id == KernelFeatureId::kNtQueryLegacy &&
        showNtQueryContextMenu(screenPoint, *descriptor)) {
        ::DestroyMenu(menu);
        return;
    }
    if (descriptor != nullptr && descriptor->id == KernelFeatureId::kAtomTable &&
        showAtomTableContextMenu(screenPoint, *descriptor)) {
        ::DestroyMenu(menu);
        return;
    }
    if (descriptor != nullptr && descriptor->id == KernelFeatureId::kDeviceDriverObjects &&
        showDeviceDriverObjectsContextMenu(screenPoint, *descriptor)) {
        ::DestroyMenu(menu);
        return;
    }
    if (descriptor != nullptr && descriptor->id == KernelFeatureId::kBaseNamedObjects &&
        showSimpleObjectTableContextMenu(screenPoint, *descriptor)) {
        ::DestroyMenu(menu);
        return;
    }
    if (descriptor != nullptr && descriptor->id == KernelFeatureId::kObjectNamespaceOverview &&
        showObjectNamespaceOverviewContextMenu(screenPoint, *descriptor)) {
        ::DestroyMenu(menu);
        return;
    }
    if (descriptor != nullptr && descriptor->id == KernelFeatureId::kObjectDirectoryRecursive &&
        showObjectDirectoryRecursiveContextMenu(screenPoint, *descriptor)) {
        ::DestroyMenu(menu);
        return;
    }
    if (descriptor != nullptr && descriptor->id == KernelFeatureId::kNamedPipe &&
        showNamedPipeContextMenu(screenPoint, *descriptor)) {
        ::DestroyMenu(menu);
        return;
    }
    if (descriptor != nullptr && descriptor->id == KernelFeatureId::kSymbolicLink &&
        showSymbolicLinkContextMenu(screenPoint, *descriptor)) {
        ::DestroyMenu(menu);
        return;
    }
    if (descriptor != nullptr && descriptor->id == KernelFeatureId::kObjectTypeMatrix &&
        showObjectTypeMatrixContextMenu(screenPoint, *descriptor)) {
        ::DestroyMenu(menu);
        return;
    }
    if (descriptor != nullptr && descriptor->id == KernelFeatureId::kCommunicationEndpoint &&
        showCommunicationEndpointContextMenu(screenPoint, *descriptor)) {
        ::DestroyMenu(menu);
        return;
    }
    if (descriptor != nullptr && isObjectNamespaceFeature(descriptor->id) &&
        showObjectNamespaceContextMenu(screenPoint, *descriptor)) {
        ::DestroyMenu(menu);
        return;
    }
    if (descriptor != nullptr && isKernelHookFeature(descriptor->id)) {
        if (descriptor->id == KernelFeatureId::kSsdt) {
            // The original SSDT tab only refreshes/selects rows; unlike
            // SSSDT/Inline/IAT-EAT it does not attach a row popup. Swallow the
            // Win32 context message here so the generic kernel menu does not
            // create extra actions that never existed in KswordARK.
            ::DestroyMenu(menu);
            return;
        }
        if (showKernelHookContextMenu(screenPoint, *descriptor)) {
            ::DestroyMenu(menu);
            return;
        }
    }
    if (descriptor != nullptr && descriptor->id == KernelFeatureId::kCallbackEnumeration &&
        showCallbackEnumerationContextMenu(screenPoint, *descriptor)) {
        ::DestroyMenu(menu);
        return;
    }
    if (descriptor != nullptr &&
        (descriptor->id == KernelFeatureId::kDynData ||
            descriptor->id == KernelFeatureId::kDriverStatus)) {
        ::DestroyMenu(menu);
        return;
    }
    if (descriptor != nullptr && isR0OriginalNoPopupFeature(descriptor->id)) {
        ::DestroyMenu(menu);
        return;
    }
    if (descriptor != nullptr &&
        (descriptor->id == KernelFeatureId::kMutationAudit ||
            descriptor->id == KernelFeatureId::kMinifilterBypassPids) &&
        showR0EvidenceContextMenu(screenPoint, *descriptor)) {
        ::DestroyMenu(menu);
        return;
    }
    if (descriptor != nullptr) {
        std::wstring refreshText = L"刷新当前页";
        ::AppendMenuW(menu, MF_STRING, kMenuRefreshCurrentFeature, refreshText.c_str());
        ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    }
    const bool kCanCopyDiagnostic = descriptor != nullptr &&
        (descriptor->id == KernelFeatureId::kDynData || descriptor->id == KernelFeatureId::kDriverStatus);
    const int kVisibleColumns = headerColumnCount(resultList_);
    HMENU copyMenu = ::CreatePopupMenu();
    if (copyMenu != nullptr) {
        ::AppendMenuW(copyMenu, MF_STRING, kMenuCopyCell, L"复制当前列（选中行）");
        ::AppendMenuW(copyMenu, MF_STRING, kMenuCopyRow, L"复制当前行（TSV）");
        ::AppendMenuW(copyMenu, MF_STRING, kMenuCopySelectedRows, L"复制选中行（TSV）");
        ::AppendMenuW(copyMenu, MF_STRING, kMenuCopySelectedRowsWithHeader, L"复制表头+选中行（TSV）");
        ::AppendMenuW(copyMenu, MF_STRING, kMenuCopyAll, L"复制全部结果");
        ::AppendMenuW(copyMenu, MF_STRING, kMenuCopySelectedDetails, L"复制详情（选中行）");
        ::AppendMenuW(copyMenu, MF_STRING | (kCanCopyDiagnostic ? MF_ENABLED : MF_GRAYED), kMenuCopyDiagnosticReport, L"复制诊断报告");
        HMENU columnMenu = ::CreatePopupMenu();
        if (columnMenu != nullptr) {
            for (int column = 0; column < kVisibleColumns && column < static_cast<int>(currentColumns_.size()) && column < static_cast<int>(kMenuCopyColumnMax - kMenuCopyColumnBase); ++column) {
                const std::wstring& columnName = currentColumns_[static_cast<std::size_t>(column)];
                ::AppendMenuW(columnMenu, MF_STRING, kMenuCopyColumnBase + static_cast<UINT_PTR>(column), columnName.c_str());
            }
            ::AppendMenuW(copyMenu, MF_POPUP | (kVisibleColumns > 0 ? MF_ENABLED : MF_GRAYED), reinterpret_cast<UINT_PTR>(columnMenu), L"复制指定栏目（选中行）");
        }
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(copyMenu), L"复制");
    }
    ::AppendMenuW(menu, MF_STRING, kMenuExportAllTsv, L"导出全部 TSV");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING, kMenuShowRowDialog, L"查看当前行详情");
    const bool kHasModule = !firstSelectedRowField({ L"Module", L"ModulePath", L"OwnerModule", L"Owner", L"Import" }).empty();
    const bool kHasTargetModule = !firstSelectedRowField({ L"TargetModule", L"OwnerModule", L"Module", L"ModulePath", L"Owner", L"Import" }).empty();
    const bool kHasAddress = !firstSelectedRowField({
        L"Address",
        L"Target",
        L"Service",
        L"Zw",
        L"Current",
        L"Expected",
        L"VA",
        L"Object",
        L"ThreadObject",
        L"ProcessObject",
        L"DriverObject",
        L"DeviceObject",
        L"Callback",
        L"Registration",
    }).empty();
    ::AppendMenuW(menu, MF_STRING | (kHasModule ? MF_ENABLED : MF_GRAYED), kMenuFilterByModule, L"按当前行模块重查");
    ::AppendMenuW(menu, MF_STRING | (kHasTargetModule ? MF_ENABLED : MF_GRAYED), kMenuFilterByTargetModule, L"按目标模块重查");
    ::AppendMenuW(menu, MF_STRING | (kHasAddress ? MF_ENABLED : MF_GRAYED), kMenuFilterByAddress, L"按地址/对象过滤");

    if (descriptor != nullptr) {
        if (descriptor->id == KernelFeatureId::kCallbackIntercept) {
            ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
            ::AppendMenuW(menu, MF_STRING, kMenuCallbackCancelPendingDecisions, L"取消全部等待决策");
            ::AppendMenuW(menu, MF_STRING, kMenuCallbackApplyDisabledEmptyRules, L"应用禁用空规则集");
        } else if (descriptor->id == KernelFeatureId::kMinifilterBypassPids) {
            ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
            ::AppendMenuW(menu, MF_STRING, kMenuMinifilterSetBypass, L"设置放行 PID（过滤/起点）");
            ::AppendMenuW(menu, MF_STRING, kMenuMinifilterClearBypass, L"清空放行 PID");
        } else if (descriptor->id == KernelFeatureId::kNetworkTrafficPackets) {
            ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
            ::AppendMenuW(menu, MF_STRING, kMenuNetworkCaptureStart, L"启动逐包捕获");
            ::AppendMenuW(menu, MF_STRING, kMenuNetworkCaptureStop, L"停止逐包捕获");
        } else if (descriptor->id == KernelFeatureId::kPiDdbCache) {
            const bool kHasEntry = !firstSelectedRowField({ L"Entry", L"条目地址" }).empty();
            ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
            ::AppendMenuW(menu, MF_STRING | (kHasEntry ? MF_ENABLED : MF_GRAYED), kMenuPiDdbDeleteEntry, L"删除选中 PiDDB 条目");
        } else if (descriptor->id == KernelFeatureId::kDriverDispatchTable) {
            const bool kHasTarget = !firstSelectedRowField({ L"ModuleBase" }).empty();
            ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
            ::AppendMenuW(menu, MF_STRING | (kHasTarget ? MF_ENABLED : MF_GRAYED), kMenuDriverDispatchRestore, L"恢复派遣槽为原值");
            ::AppendMenuW(menu, MF_STRING | (kHasTarget ? MF_ENABLED : MF_GRAYED), kMenuDriverDispatchAbandon, L"放弃派遣恢复记录");
        } else if (descriptor->id == KernelFeatureId::kDriverImageFields) {
            const bool kHasTarget = !firstSelectedRowField({ L"ModuleBase" }).empty();
            ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
            ::AppendMenuW(menu, MF_STRING | (kHasTarget ? MF_ENABLED : MF_GRAYED), kMenuDriverImageRestore, L"恢复镜像字段为原值");
            ::AppendMenuW(menu, MF_STRING | (kHasTarget ? MF_ENABLED : MF_GRAYED), kMenuDriverImageAbandon, L"放弃镜像恢复记录");
        } else if (descriptor->id == KernelFeatureId::kDriverCommunication) {
            const bool kHasTarget = !firstSelectedRowField({ L"DriverStart", L"ModuleBase" }).empty();
            ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
            ::AppendMenuW(menu, MF_STRING | (kHasTarget ? MF_ENABLED : MF_GRAYED), kMenuDriverCommunicationRestore, L"恢复驱动通信");
        } else if (descriptor->id == KernelFeatureId::kDynData) {
            ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
            ::AppendMenuW(menu, MF_STRING, kMenuDynDataApplyMatchedProfile, L"应用匹配 DynData Profile");
        } else if (descriptor->id == KernelFeatureId::kMutationAudit) {
            const bool kHasTransaction = !firstSelectedRowField({ L"Tx", L"TransactionId" }).empty();
            ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
            ::AppendMenuW(menu, MF_STRING | (kHasTransaction ? MF_ENABLED : MF_GRAYED), kMenuMutationCommitDryRun, L"Commit dry-run 当前事务");
            ::AppendMenuW(menu, MF_STRING | (kHasTransaction ? MF_ENABLED : MF_GRAYED), kMenuMutationRollbackDryRun, L"Rollback dry-run 当前事务");
            ::AppendMenuW(menu, MF_STRING | (kHasTransaction ? MF_ENABLED : MF_GRAYED), kMenuMutationRollbackConfirmed, L"确认 Rollback 当前事务");
        }
    }
    ::TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, screenPoint.x, screenPoint.y, 0, hwnd_, nullptr);
    ::DestroyMenu(menu);
}

bool KernelPage::prepareResultContextPoint(POINT& screenPoint, const bool updatePropertyTable) {
    // prepareResultContextPoint normalizes keyboard and mouse context-menu
    // positions for the result ListView. Inputs are a mutable screen point and
    // whether property panes must refresh; processing selects the clicked row
    // while preserving existing multi-selection when Ctrl/Shift is held or the
    // clicked row is already selected. Return is false only when resultList_ is
    // unavailable.
    if (!resultList_) {
        return false;
    }
    if (screenPoint.x == -1 && screenPoint.y == -1) {
        RECT rc{};
        const int kSelected = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED);
        if (kSelected >= 0 && ListView_GetItemRect(resultList_, kSelected, &rc, LVIR_BOUNDS)) {
            screenPoint.x = rc.left;
            screenPoint.y = rc.bottom;
            ::ClientToScreen(resultList_, &screenPoint);
        } else {
            ::GetCursorPos(&screenPoint);
        }
        return true;
    }

    POINT clientPoint = screenPoint;
    ::ScreenToClient(resultList_, &clientPoint);
    LVHITTESTINFO hit{};
    hit.pt = clientPoint;
    const int kRow = ListView_HitTest(resultList_, &hit);
    if (kRow < 0) {
        return true;
    }

    const bool kPreserveMultiSelection = (::GetKeyState(VK_CONTROL) & 0x8000) != 0 ||
        (::GetKeyState(VK_SHIFT) & 0x8000) != 0 ||
        (ListView_GetItemState(resultList_, kRow, LVIS_SELECTED) & LVIS_SELECTED) != 0;
    if (!kPreserveMultiSelection) {
        ListView_SetItemState(resultList_, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    }
    ListView_SetItemState(resultList_, kRow, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    ListView_EnsureVisible(resultList_, kRow, FALSE);
    updateSelectedRowDetail();
    if (updatePropertyTable) {
        updatePropertyTableFromSelection();
    }
    return true;
}

bool KernelPage::showNtQueryContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor) {
    // showNtQueryContextMenu keeps the legacy NtQuery history page close to the
    // original KernelDock surface. The source page only offered refresh and
    // detail-oriented inspection, so this popup intentionally avoids the
    // generic kernel filtering and mutation actions. Input is the screen point
    // from WM_CONTEXTMENU plus the active descriptor; return true means the
    // caller must not append the generic result menu.
    if (!resultList_ || descriptor.id != KernelFeatureId::kNtQueryLegacy) {
        return false;
    }

    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return false;
    }
    const bool kHasSelection = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED) >= 0;

    ::AppendMenuW(menu, MF_STRING, kMenuRefreshCurrentFeature, L"刷新历史 NtQuery");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制当前行");
    ::AppendMenuW(menu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopySelectedDetails, L"复制详情");

    ::TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, screenPoint.x, screenPoint.y, 0, hwnd_, nullptr);
    ::DestroyMenu(menu);
    return true;
}

bool KernelPage::showAtomTableContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor) {
    // showAtomTableContextMenu mirrors the original KernelDock atom popup: one
    // refresh command, a Copy submenu, and an Atom operation submenu. Inputs are
    // screen coordinates and the active descriptor; output true tells the
    // generic menu builder not to append unrelated kernel actions.
    if (!resultList_ || descriptor.id != KernelFeatureId::kAtomTable) {
        return false;
    }
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return false;
    }
    const bool kHasSelection = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED) >= 0;
    const bool kHasName = !firstSelectedRowField({ L"名称", L"Name" }).empty();

    ::AppendMenuW(menu, MF_STRING, kMenuRefreshCurrentFeature, L"刷新原子表");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);

    HMENU copyMenu = ::CreatePopupMenu();
    if (copyMenu != nullptr) {
        ::AppendMenuW(copyMenu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyCell, L"复制当前单元格");
        ::AppendMenuW(copyMenu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyAtomValue, L"复制Atom值");
        ::AppendMenuW(copyMenu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyAtomHex, L"复制十六进制");
        ::AppendMenuW(copyMenu, MF_STRING | (kHasName ? MF_ENABLED : MF_GRAYED), kMenuCopyAtomName, L"复制名称");
        ::AppendMenuW(copyMenu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyAtomSource, L"复制来源");
        ::AppendMenuW(copyMenu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制当前行");
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(copyMenu), L"复制");
    }

    HMENU operationMenu = ::CreatePopupMenu();
    if (operationMenu != nullptr) {
        ::AppendMenuW(operationMenu, MF_STRING | (kHasName ? MF_ENABLED : MF_GRAYED), kMenuFilterByName, L"用名称过滤");
        ::AppendMenuW(operationMenu, MF_STRING | (kHasName ? MF_ENABLED : MF_GRAYED), kMenuAtomVerify, L"使用GlobalFindAtomW校验");
        ::AppendMenuW(operationMenu, MF_STRING | (kHasName ? MF_ENABLED : MF_GRAYED), kMenuAtomCopySnippet, L"复制调用代码片段");
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(operationMenu), L"原子操作");
    }

    ::TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, screenPoint.x, screenPoint.y, 0, hwnd_, nullptr);
    ::DestroyMenu(menu);
    return true;
}

bool KernelPage::showObjectNamespaceContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor) {
    // showObjectNamespaceContextMenu mirrors the original object namespace tab
    // family: every page starts with refresh, then exposes a Copy submenu and a
    // small operation submenu when the source tab had row actions. Inputs are
    // screen coordinates plus the active descriptor; return true prevents the
    // generic kernel result menu from adding unrelated actions.
    if (!resultList_) {
        return false;
    }

    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return false;
    }

    const bool kHasSelection = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED) >= 0;
    const bool kHasPath = !firstSelectedRowField({ L"Path", L"NtPath", L"fullPath", L"FullPath", L"完整路径", L"路径/说明" }).empty();
    const bool kHasTarget = !firstSelectedRowField({ L"Target", L"targetPath", L"symbolicTarget", L"符号链接目标", L"dosCandidate", L"Win32Path" }).empty();
    const bool kHasType = !firstSelectedRowField({ L"Type", L"objectType", L"对象类型", L"类型" }).empty();
    const bool kHasName = !firstSelectedRowField({ L"Name", L"objectName", L"名称", L"linkName", L"Pipe", L"Pipe Name" }).empty();
    const bool kHasDirectory = !firstSelectedRowField({ L"directoryPath", L"Parent", L"Directory", L"Source", L"sourceDirectory", L"目录路径", L"来源目录" }).empty();
    const bool kHasEnumApi = !firstSelectedRowField({ L"EnumApi", L"enumApi", L"枚举 API", L"EnumerationApi" }).empty();
    const bool kHasDosCandidate = !firstSelectedRowField({ L"dosCandidate", L"Win32Path", L"DosCandidates" }).empty();
    const bool kIsSymbolicLink = containsCaseInsensitive(firstSelectedRowField({ L"Type", L"objectType", L"对象类型", L"类型" }), L"SymbolicLink") ||
        containsCaseInsensitive(firstSelectedRowField({ L"类型" }), L"符号链接");

    const auto kAppendRefresh = [&](const wchar_t* refreshText) {
        ::AppendMenuW(menu, MF_STRING, kMenuRefreshCurrentFeature, refreshText);
        ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    };
    const auto kAppendBasicCopyMenu = [&](const bool includeCell, const bool includeFields, const bool includeSameDirectory, const bool includeVisibleRows) {
        HMENU copyMenu = ::CreatePopupMenu();
        if (copyMenu == nullptr) {
            return;
        }
        if (includeCell) {
            ::AppendMenuW(copyMenu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyCell, L"复制当前单元格");
        }
        if (includeFields) {
            ::AppendMenuW(copyMenu, MF_STRING | (kHasName ? MF_ENABLED : MF_GRAYED), kMenuCopyObjectName, L"复制对象名");
            ::AppendMenuW(copyMenu, MF_STRING | (kHasType ? MF_ENABLED : MF_GRAYED), kMenuCopyObjectType, L"复制对象类型");
            ::AppendMenuW(copyMenu, MF_STRING | (kHasPath ? MF_ENABLED : MF_GRAYED), kMenuCopyFullPath, L"复制完整路径");
            ::AppendMenuW(copyMenu, MF_STRING | (kHasTarget ? MF_ENABLED : MF_GRAYED), kMenuCopySymbolicTarget, L"复制符号链接目标");
            ::AppendMenuW(copyMenu, MF_STRING | (kHasEnumApi ? MF_ENABLED : MF_GRAYED), kMenuCopyObjectEnumSource, L"复制枚举 API");
            ::AppendMenuW(copyMenu, MF_SEPARATOR, 0, nullptr);
        }
        ::AppendMenuW(copyMenu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制当前行");
        if (includeSameDirectory) {
            ::AppendMenuW(copyMenu, MF_STRING | (kHasDirectory || kHasPath ? MF_ENABLED : MF_GRAYED), kMenuCopySameDirectory, L"复制同目录路径全部行");
        }
        if (includeVisibleRows) {
            ::AppendMenuW(copyMenu, MF_STRING, kMenuCopyAll, L"复制可见结果 TSV");
            ::AppendMenuW(copyMenu, MF_STRING, kMenuExportAllTsv, L"导出 TSV");
        }
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(copyMenu), L"复制");
    };
    const auto kAppendObjectOperationMenu = [&](const bool includeObjectDetail, const bool includeRootFilter, const bool includeNameFilter, const bool includeTargetFilter, const bool includeDosMap) {
        HMENU operationMenu = ::CreatePopupMenu();
        if (operationMenu == nullptr) {
            return;
        }
        if (includeObjectDetail) {
            ::AppendMenuW(operationMenu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuNativeObjectQueryDetail, L"R3 对象详情");
        }
        if (includeRootFilter) {
            ::AppendMenuW(operationMenu, MF_STRING | (kHasDirectory || kHasPath ? MF_ENABLED : MF_GRAYED), kMenuObjectFilterByRoot, L"用目录路径过滤");
            ::AppendMenuW(operationMenu, MF_STRING | (kHasDirectory ? MF_ENABLED : MF_GRAYED), kMenuObjectFilterByDirectory, L"用当前目录过滤");
        }
        if (includeNameFilter) {
            ::AppendMenuW(operationMenu, MF_STRING | (kHasName ? MF_ENABLED : MF_GRAYED), kMenuFilterByName, L"用对象名过滤");
        }
        if (includeTargetFilter) {
            ::AppendMenuW(operationMenu, MF_STRING | (kHasTarget ? MF_ENABLED : MF_GRAYED), kMenuFilterByTarget, L"按目标路径过滤");
        }
        if (kIsSymbolicLink || descriptor.id == KernelFeatureId::kSymbolicLink) {
            ::AppendMenuW(operationMenu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuNativeSymbolicLinkResolve, L"解析符号链接目标");
        }
        if (includeDosMap) {
            ::AppendMenuW(operationMenu, MF_STRING | (kHasPath || kHasTarget ? MF_ENABLED : MF_GRAYED), kMenuMapDosPath, L"尝试映射为 DOS 路径");
        }
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(operationMenu), L"对象操作");
    };

    switch (descriptor.id) {
    case KernelFeatureId::kObjectNamespaceOverview:
        kAppendRefresh(L"刷新对象命名空间");
        kAppendBasicCopyMenu(true, true, true, false);
        kAppendObjectOperationMenu(false, true, true, false, true);
        break;
    case KernelFeatureId::kBaseNamedObjects:
        ::DestroyMenu(menu);
        return true;
    case KernelFeatureId::kNamedPipe:
        ::AppendMenuW(menu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制当前行");
        ::AppendMenuW(menu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuShowRowDialog, L"刷新详情");
        break;
    case KernelFeatureId::kSymbolicLink:
        ::AppendMenuW(menu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyCell, L"复制单元格");
        ::AppendMenuW(menu, MF_STRING | (kHasTarget ? MF_ENABLED : MF_GRAYED), kMenuCopySymbolicTarget, L"复制 targetPath");
        ::AppendMenuW(menu, MF_STRING | (kHasDosCandidate ? MF_ENABLED : MF_GRAYED), kMenuCopyDosCandidate, L"复制 dosCandidate");
        ::AppendMenuW(menu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制整行");
        ::AppendMenuW(menu, MF_STRING | (kHasTarget ? MF_ENABLED : MF_GRAYED), kMenuFilterByTarget, L"按此目标路径过滤");
        break;
    case KernelFeatureId::kDeviceDriverObjects:
        kAppendRefresh(L"刷新设备/驱动对象");
        ::AppendMenuW(menu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyCell, L"复制单元格");
        ::AppendMenuW(menu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制当前行");
        ::AppendMenuW(menu, MF_STRING | (currentRows_.empty() ? MF_GRAYED : MF_ENABLED), kMenuCopyAll, L"复制可见结果 TSV");
        ::AppendMenuW(menu, MF_STRING | (currentRows_.empty() ? MF_GRAYED : MF_ENABLED), kMenuExportAllTsv, L"导出 TSV");
        break;
    case KernelFeatureId::kObjectTypeMatrix:
        kAppendRefresh(L"刷新对象类型统计");
        ::AppendMenuW(menu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制当前行");
        break;
    case KernelFeatureId::kCommunicationEndpoint:
        ::DestroyMenu(menu);
        return true;
    default:
        ::DestroyMenu(menu);
        return false;
    }

    ::TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, screenPoint.x, screenPoint.y, 0, hwnd_, nullptr);
    ::DestroyMenu(menu);
    return true;
}

bool KernelPage::showObjectNamespaceOverviewContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor) {
    // showObjectNamespaceOverviewContextMenu mirrors the original object
    // namespace overview actions without leaking generic kernel mutation items.
    // Inputs are the popup screen point and descriptor; processing selects the
    // clicked row, then exposes copy, directory filtering and DOS mapping.
    // Return true means the popup is fully handled here.
    if (!resultList_ || descriptor.id != KernelFeatureId::kObjectNamespaceOverview) {
        return false;
    }
    if (!prepareResultContextPoint(screenPoint, true)) {
        return false;
    }

    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return false;
    }
    const bool kHasSelection = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED) >= 0;
    const bool kHasPath = !firstSelectedRowField({ L"Path", L"NtPath", L"fullPath", L"FullPath", L"完整路径", L"路径/说明" }).empty();
    const bool kHasTarget = !firstSelectedRowField({ L"Target", L"targetPath", L"symbolicTarget", L"符号链接目标", L"dosCandidate", L"Win32Path" }).empty();
    const bool kHasType = !firstSelectedRowField({ L"Type", L"objectType", L"对象类型", L"类型" }).empty();
    const bool kHasName = !firstSelectedRowField({ L"Name", L"objectName", L"名称", L"linkName" }).empty();
    const bool kHasDirectory = !firstSelectedRowField({ L"directoryPath", L"Parent", L"Directory", L"Source", L"sourceDirectory", L"目录路径", L"来源目录" }).empty();
    const bool kHasEnumApi = !firstSelectedRowField({ L"EnumApi", L"enumApi", L"枚举 API", L"EnumerationApi" }).empty();
    const bool kHasEntry = _wcsicmp(firstSelectedRowField({ L"NodeKind" }).c_str(), L"ObjectEntry") == 0 ||
        firstSelectedRowField({ L"NodeKind" }).empty();
    const bool kCanMapDos = kHasEntry && (kHasPath || kHasTarget);
    const bool kIsSymbolicLink = containsCaseInsensitive(firstSelectedRowField({ L"Type", L"objectType", L"对象类型", L"类型" }), L"SymbolicLink") ||
        containsCaseInsensitive(firstSelectedRowField({ L"类型" }), L"符号链接");

    ::AppendMenuW(menu, MF_STRING, kMenuRefreshCurrentFeature, L"刷新对象命名空间");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);

    HMENU copyMenu = ::CreatePopupMenu();
    if (copyMenu != nullptr) {
        ::AppendMenuW(copyMenu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyCell, L"复制当前单元格");
        ::AppendMenuW(copyMenu, MF_STRING | (kHasEntry && kHasName ? MF_ENABLED : MF_GRAYED), kMenuCopyObjectName, L"复制对象名");
        ::AppendMenuW(copyMenu, MF_STRING | (kHasEntry && kHasType ? MF_ENABLED : MF_GRAYED), kMenuCopyObjectType, L"复制对象类型");
        ::AppendMenuW(copyMenu, MF_STRING | (kHasEntry && kHasPath ? MF_ENABLED : MF_GRAYED), kMenuCopyFullPath, L"复制完整路径");
        ::AppendMenuW(copyMenu, MF_STRING | (kHasEntry && kHasTarget ? MF_ENABLED : MF_GRAYED), kMenuCopySymbolicTarget, L"复制符号链接目标");
        ::AppendMenuW(copyMenu, MF_STRING | (kHasEntry && kHasEnumApi ? MF_ENABLED : MF_GRAYED), kMenuCopyObjectEnumSource, L"复制枚举 API");
        ::AppendMenuW(copyMenu, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(copyMenu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制当前行");
        ::AppendMenuW(copyMenu, MF_STRING | (kHasEntry && (kHasDirectory || kHasPath) ? MF_ENABLED : MF_GRAYED), kMenuCopySameDirectory, L"复制同目录路径全部行");
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(copyMenu), L"复制");
    }

    HMENU operationMenu = ::CreatePopupMenu();
    if (operationMenu != nullptr) {
        ::AppendMenuW(operationMenu, MF_STRING | (kHasEntry && kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuNativeObjectQueryDetail, L"R3 对象详情");
        ::AppendMenuW(operationMenu, MF_STRING | (kHasEntry && (kHasDirectory || kHasPath) ? MF_ENABLED : MF_GRAYED), kMenuObjectFilterByRoot, L"用目录路径过滤");
        ::AppendMenuW(operationMenu, MF_STRING | (kHasEntry && kHasDirectory ? MF_ENABLED : MF_GRAYED), kMenuObjectFilterByDirectory, L"用当前目录过滤");
        ::AppendMenuW(operationMenu, MF_STRING | (kHasEntry && kHasName ? MF_ENABLED : MF_GRAYED), kMenuFilterByName, L"用对象名过滤");
        if (kIsSymbolicLink) {
            ::AppendMenuW(operationMenu, MF_STRING | (kHasEntry && kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuNativeSymbolicLinkResolve, L"解析符号链接目标");
        }
        ::AppendMenuW(operationMenu, MF_STRING | (kCanMapDos ? MF_ENABLED : MF_GRAYED), kMenuMapDosPath, L"尝试映射为 DOS 路径");
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(operationMenu), L"对象操作");
    }

    ::TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, screenPoint.x, screenPoint.y, 0, hwnd_, nullptr);
    ::DestroyMenu(menu);
    return true;
}

bool KernelPage::showObjectDirectoryRecursiveContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor) {
    // showObjectDirectoryRecursiveContextMenu handles the recursive Object
    // Manager directory page. Inputs are the popup coordinates and descriptor;
    // processing selects the clicked row, exposes copy/export under one submenu,
    // and exposes read-only object helpers under another submenu. The recursive
    // page uses filterEdit_ as its next traversal root, so it intentionally does
    // not offer cached type/name filters; the only filter action resets the
    // traversal root to the selected full path and refreshes the query. The
    // return value is true when the menu is fully handled.
    if (!resultList_ || descriptor.id != KernelFeatureId::kObjectDirectoryRecursive) {
        return false;
    }
    if (!prepareResultContextPoint(screenPoint, false)) {
        return false;
    }

    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return false;
    }
    const bool kHasSelection = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED) >= 0;
    const bool kHasRows = ListView_GetItemCount(resultList_) > 0;
    const bool kHasPath = !firstSelectedRowField({ L"完整路径", L"fullPath", L"Path", L"NtPath" }).empty();
    const bool kHasType = !firstSelectedRowField({ L"类型", L"objectType", L"Type" }).empty();
    const bool kHasName = !firstSelectedRowField({ L"名称", L"objectName", L"Name" }).empty();
    const bool kHasTarget = !firstSelectedRowField({ L"Target", L"targetPath", L"symbolicTarget", L"符号链接目标", L"dosCandidate", L"Win32Path" }).empty();
    const bool kIsSymbolicLink = containsCaseInsensitive(firstSelectedRowField({ L"Type", L"objectType", L"对象类型", L"类型" }), L"SymbolicLink") ||
        containsCaseInsensitive(firstSelectedRowField({ L"类型" }), L"符号链接");

    ::AppendMenuW(menu, MF_STRING, kMenuRefreshCurrentFeature, L"刷新目录递归");

    HMENU copyMenu = ::CreatePopupMenu();
    if (copyMenu != nullptr) {
        ::AppendMenuW(copyMenu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyCell, L"复制单元格");
        ::AppendMenuW(copyMenu, MF_STRING | (kHasName ? MF_ENABLED : MF_GRAYED), kMenuCopyObjectName, L"复制对象名");
        ::AppendMenuW(copyMenu, MF_STRING | (kHasType ? MF_ENABLED : MF_GRAYED), kMenuCopyObjectType, L"复制对象类型");
        ::AppendMenuW(copyMenu, MF_STRING | (kHasPath ? MF_ENABLED : MF_GRAYED), kMenuCopyFullPath, L"复制完整路径");
        ::AppendMenuW(copyMenu, MF_STRING | (kHasTarget ? MF_ENABLED : MF_GRAYED), kMenuCopySymbolicTarget, L"复制符号链接目标");
        ::AppendMenuW(copyMenu, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(copyMenu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制当前行");
        ::AppendMenuW(copyMenu, MF_STRING | (kHasRows ? MF_ENABLED : MF_GRAYED), kMenuCopyAll, L"复制可见结果 TSV");
        ::AppendMenuW(copyMenu, MF_STRING | (kHasRows ? MF_ENABLED : MF_GRAYED), kMenuExportAllTsv, L"导出 TSV");
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(copyMenu), L"复制");
    }

    HMENU operationMenu = ::CreatePopupMenu();
    if (operationMenu != nullptr) {
        ::AppendMenuW(operationMenu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuNativeObjectQueryDetail, L"R3 对象详情");
        ::AppendMenuW(operationMenu, MF_STRING | (kHasPath ? MF_ENABLED : MF_GRAYED), kMenuFilterByPath, L"以完整路径作为递归根");
        if (kIsSymbolicLink) {
            ::AppendMenuW(operationMenu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuNativeSymbolicLinkResolve, L"解析符号链接目标");
        }
        ::AppendMenuW(operationMenu, MF_STRING | ((kHasPath || kHasTarget) ? MF_ENABLED : MF_GRAYED), kMenuMapDosPath, L"尝试映射为 DOS 路径");
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(operationMenu), L"对象操作");
    }

    ::TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, screenPoint.x, screenPoint.y, 0, hwnd_, nullptr);
    ::DestroyMenu(menu);
    return true;
}

bool KernelPage::showDeviceDriverObjectsContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor) {
    // showDeviceDriverObjectsContextMenu mirrors the original full tab's base
    // menu exactly: copy cell, copy current row, copy visible TSV, and export
    // TSV. Inputs are the screen-space popup point and descriptor; processing
    // selects the clicked ListView row and optionally exposes R3/R0 helpers in
    // a separate submenu so original copy/export workflow stays first; output
    // is true when the popup was handled.
    if (!resultList_ || descriptor.id != KernelFeatureId::kDeviceDriverObjects) {
        return false;
    }
    if (!prepareResultContextPoint(screenPoint, false)) {
        return false;
    }

    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return false;
    }
    const bool kHasSelection = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED) >= 0;
    const bool kHasRows = ListView_GetItemCount(resultList_) > 0;
    const std::wstring kObjectType = firstSelectedRowField({ L"对象类型", L"objectType", L"Type", L"类型" });
    const std::wstring kObjectPath = firstSelectedRowField({ L"完整路径", L"fullPath", L"Path", L"NtPath" });
    const bool kIsDriverObject = containsCaseInsensitive(kObjectType, L"Driver") ||
        containsCaseInsensitive(kObjectPath, L"\\Driver\\") ||
        !firstSelectedRowField({ L"DriverName" }).empty();

    ::AppendMenuW(menu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyCell, L"复制单元格");
    ::AppendMenuW(menu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制当前行");
    ::AppendMenuW(menu, MF_STRING | (kHasRows ? MF_ENABLED : MF_GRAYED), kMenuCopyAll, L"复制可见结果 TSV");
    ::AppendMenuW(menu, MF_STRING | (kHasRows ? MF_ENABLED : MF_GRAYED), kMenuExportAllTsv, L"导出 TSV");

    HMENU objectMenu = ::CreatePopupMenu();
    if (objectMenu != nullptr) {
        ::AppendMenuW(objectMenu, MF_STRING, kMenuRefreshCurrentFeature, L"刷新设备/驱动对象");
        ::AppendMenuW(objectMenu, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(objectMenu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuNativeObjectQueryDetail, L"R3 对象详情");
        ::AppendMenuW(objectMenu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuFilterByPath, L"按完整路径过滤");
        ::AppendMenuW(objectMenu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuFilterByType, L"按对象类型过滤");
        ::AppendMenuW(objectMenu, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(objectMenu, MF_STRING | (kHasSelection && kIsDriverObject ? MF_ENABLED : MF_GRAYED), kMenuDriverObjectQueryDetail, L"R0 DriverObject 详情");
        ::AppendMenuW(objectMenu, MF_STRING | (kHasSelection && kIsDriverObject ? MF_ENABLED : MF_GRAYED), kMenuDriverObjectForceUnload, L"R0 强制卸载 DriverObject");
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(objectMenu), L"对象操作");
    }

    ::TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, screenPoint.x, screenPoint.y, 0, hwnd_, nullptr);
    ::DestroyMenu(menu);
    return true;
}

bool KernelPage::showSimpleObjectTableContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor) {
    // showSimpleObjectTableContextMenu handles BaseNamedObjects. Inputs are
    // screen coordinates and the active descriptor; processing keeps copy/export
    // in a submenu and exposes R3 detail/filter actions without mixing in R0
    // mutation entries. The return value is true when the popup was handled.
    if (!resultList_ || descriptor.id != KernelFeatureId::kBaseNamedObjects) {
        return false;
    }
    if (!prepareResultContextPoint(screenPoint, false)) {
        return false;
    }

    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return false;
    }
    const bool kHasSelection = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED) >= 0;
    ::AppendMenuW(menu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制当前行");
    ::TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, screenPoint.x, screenPoint.y, 0, hwnd_, nullptr);
    ::DestroyMenu(menu);
    return true;
}

bool KernelPage::showNamedPipeContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor) {
    // showNamedPipeContextMenu handles the NPFS named-pipe page. Inputs are the
    // popup point and active descriptor; processing selects the clicked row,
    // exposes copy/export commands under one submenu, and exposes read-only
    // probe/filter commands under another submenu. The return value is true
    // when no generic kernel menu should be appended.
    if (!resultList_ || descriptor.id != KernelFeatureId::kNamedPipe) {
        return false;
    }
    if (!prepareResultContextPoint(screenPoint, false)) {
        return false;
    }

    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return false;
    }
    const bool kHasSelection = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED) >= 0;
    ::AppendMenuW(menu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制当前行");
    ::AppendMenuW(menu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuShowRowDialog, L"刷新详情");
    ::TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, screenPoint.x, screenPoint.y, 0, hwnd_, nullptr);
    ::DestroyMenu(menu);
    return true;
}

bool KernelPage::showSymbolicLinkContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor) {
    // showSymbolicLinkContextMenu mirrors the original SymbolicLink tab popup.
    // Inputs are the context-menu screen point and active feature descriptor;
    // processing selects the row under the mouse and exposes only the original
    // five actions: copy cell, targetPath, dosCandidate, row, and target filter.
    // Return value is true when this flat table handled the popup.
    if (!resultList_ || descriptor.id != KernelFeatureId::kSymbolicLink) {
        return false;
    }
    if (!prepareResultContextPoint(screenPoint, false)) {
        return false;
    }

    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return false;
    }

    const bool kHasSelection = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED) >= 0;
    const bool kHasTarget = !firstSelectedRowField({
        L"targetPath",
        L"symbolicTarget",
        L"Target",
        L"目标路径",
        L"符号链接目标",
    }).empty();
    const bool kHasDosCandidate = !firstSelectedRowField({
        L"dosCandidate",
        L"Win32Path",
        L"DosCandidates",
    }).empty();
    ::AppendMenuW(menu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyCell, L"复制单元格");
    ::AppendMenuW(menu, MF_STRING | (kHasTarget ? MF_ENABLED : MF_GRAYED), kMenuCopySymbolicTarget, L"复制 targetPath");
    ::AppendMenuW(menu, MF_STRING | (kHasDosCandidate ? MF_ENABLED : MF_GRAYED), kMenuCopyDosCandidate, L"复制 dosCandidate");
    ::AppendMenuW(menu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制整行");
    ::AppendMenuW(menu, MF_STRING | (kHasTarget ? MF_ENABLED : MF_GRAYED), kMenuFilterByTarget, L"按此目标路径过滤");

    ::TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, screenPoint.x, screenPoint.y, 0, hwnd_, nullptr);
    ::DestroyMenu(menu);
    return true;
}

bool KernelPage::showObjectTypeMatrixContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor) {
    // showObjectTypeMatrixContextMenu keeps the object-type matrix popup as
    // small as the original source tab: the only row action is copying the
    // current type row. Inputs are the popup screen point and descriptor; return
    // true means the generic kernel/object menus must not add extra operations.
    if (!resultList_ || descriptor.id != KernelFeatureId::kObjectTypeMatrix) {
        return false;
    }
    if (!prepareResultContextPoint(screenPoint, false)) {
        return false;
    }

    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return false;
    }
    const bool kHasSelection = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED) >= 0;
    ::AppendMenuW(menu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制当前行");
    ::TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, screenPoint.x, screenPoint.y, 0, hwnd_, nullptr);
    ::DestroyMenu(menu);
    return true;
}

bool KernelPage::showCommunicationEndpointContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor) {
    // showCommunicationEndpointContextMenu handles ALPC/Port endpoint rows.
    // Inputs are screen coordinates and the current descriptor; processing
    // selects the clicked row and exposes the same single "copy row" action as
    // the original endpoint tab. Return true prevents unrelated object or driver
    // operations from being appended.
    if (!resultList_ || descriptor.id != KernelFeatureId::kCommunicationEndpoint) {
        return false;
    }
    if (!prepareResultContextPoint(screenPoint, false)) {
        return false;
    }

    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return false;
    }
    const bool kHasSelection = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED) >= 0;
    ::AppendMenuW(menu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制当前行");
    ::TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, screenPoint.x, screenPoint.y, 0, hwnd_, nullptr);
    ::DestroyMenu(menu);
    return true;
}

bool KernelPage::showKernelHookContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor) {
    // showKernelHookContextMenu mirrors the original hook-related popup menus.
    // SSDT had no context menu in the original page. SSSDT, Inline, and IAT/EAT
    // keep their refresh/copy actions plus Inline's NOP entry. Inputs are screen
    // coordinates and the active descriptor; return true prevents generic kernel
    // actions.
    if (!resultList_ || descriptor.id == KernelFeatureId::kSsdt) {
        return false;
    }
    if (screenPoint.x == -1 && screenPoint.y == -1) {
        RECT rc{};
        const int kSelected = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED);
        if (kSelected >= 0 && ListView_GetItemRect(resultList_, kSelected, &rc, LVIR_BOUNDS)) {
            screenPoint.x = rc.left;
            screenPoint.y = rc.bottom;
            ::ClientToScreen(resultList_, &screenPoint);
        } else {
            ::GetCursorPos(&screenPoint);
        }
    } else {
        POINT clientPoint = screenPoint;
        ::ScreenToClient(resultList_, &clientPoint);
        LVHITTESTINFO hit{};
        hit.pt = clientPoint;
        const int kRow = ListView_HitTest(resultList_, &hit);
        if (kRow >= 0) {
            const bool kPreserveMultiSelection = (::GetKeyState(VK_CONTROL) & 0x8000) != 0 ||
                (::GetKeyState(VK_SHIFT) & 0x8000) != 0;
            if (!kPreserveMultiSelection && ListView_GetItemState(resultList_, kRow, LVIS_SELECTED) == 0) {
                ListView_SetItemState(resultList_, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
            }
            ListView_SetItemState(resultList_, kRow, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
            ListView_EnsureVisible(resultList_, kRow, FALSE);
            updateSelectedRowDetail();
        }
    }
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return false;
    }
    const bool kHasSelection = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED) >= 0;
    const wchar_t* refreshText = L"刷新当前页";
    if (descriptor.id == KernelFeatureId::kSsdt) {
        refreshText = L"刷新 SSDT";
    } else if (descriptor.id == KernelFeatureId::kShadowSsdt) {
        refreshText = L"刷新 SSSDT";
    } else if (descriptor.id == KernelFeatureId::kInlineHook) {
        refreshText = L"重新扫描 Inline Hook";
    } else if (descriptor.id == KernelFeatureId::kIatEatHook) {
        refreshText = L"重新扫描 IAT/EAT";
    }
    ::AppendMenuW(menu, MF_STRING, kMenuRefreshCurrentFeature, refreshText);
    if (descriptor.id == KernelFeatureId::kInlineHook) {
        ::AppendMenuW(menu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuInlineNopPatch, L"NOP 摘除当前 Hook");
    }
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);

    HMENU copyMenu = ::CreatePopupMenu();
    if (copyMenu != nullptr) {
        ::AppendMenuW(copyMenu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyCell, L"复制当前列（选中行）");
        ::AppendMenuW(copyMenu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopySelectedRows, L"复制选中行（TSV）");
        ::AppendMenuW(copyMenu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopySelectedRowsWithHeader, L"复制表头+选中行（TSV）");
        ::AppendMenuW(copyMenu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopySelectedDetails, L"复制详情（选中行）");
        ::AppendMenuW(copyMenu, MF_SEPARATOR, 0, nullptr);
        HMENU columnMenu = ::CreatePopupMenu();
        if (columnMenu != nullptr) {
            const std::vector<int> kCopyColumns = kernelHookVisibleColumnIndices(descriptor.id, currentColumns_);
            for (std::size_t position = 0; position < kCopyColumns.size() && position < static_cast<std::size_t>(kMenuCopyColumnMax - kMenuCopyColumnBase); ++position) {
                const int kColumn = kCopyColumns[position];
                if (kColumn < 0 || kColumn >= static_cast<int>(currentColumns_.size())) {
                    continue;
                }
                ::AppendMenuW(columnMenu,
                    MF_STRING,
                    kMenuCopyColumnBase + static_cast<UINT_PTR>(kColumn),
                    currentColumns_[static_cast<std::size_t>(kColumn)].c_str());
            }
            ::AppendMenuW(copyMenu,
                MF_POPUP | (kHasSelection && !kCopyColumns.empty() ? MF_ENABLED : MF_GRAYED),
                reinterpret_cast<UINT_PTR>(columnMenu),
                L"复制指定栏目（选中行）");
        }
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(copyMenu), L"复制");
    }
    ::TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, screenPoint.x, screenPoint.y, 0, hwnd_, nullptr);
    ::DestroyMenu(menu);
    return true;
}

bool KernelPage::showCallbackEnumerationContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor) {
    // showCallbackEnumerationContextMenu mirrors KernelDock.CallbackEnum's menu:
    // refresh, module file actions, single-row remove entries, and copy submenu.
    // Inputs are screen coordinates and the active descriptor; output true means
    // the generic kernel menu must not add extra actions.
    if (!resultList_ || descriptor.id != KernelFeatureId::kCallbackEnumeration) {
        return false;
    }

    if (screenPoint.x == -1 && screenPoint.y == -1) {
        RECT rowBounds{};
        const int kSelected = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED);
        if (kSelected >= 0 && ListView_GetItemRect(resultList_, kSelected, &rowBounds, LVIR_BOUNDS)) {
            screenPoint.x = rowBounds.left;
            screenPoint.y = rowBounds.bottom;
            ::ClientToScreen(resultList_, &screenPoint);
        } else {
            ::GetCursorPos(&screenPoint);
        }
    } else {
        POINT clientPoint = screenPoint;
        ::ScreenToClient(resultList_, &clientPoint);
        LVHITTESTINFO hit{};
        hit.pt = clientPoint;
        const int kRow = ListView_HitTest(resultList_, &hit);
        contextColumn_ = hit.iSubItem >= 0 ? hit.iSubItem : 0;
        if (kRow >= 0) {
            const bool kPreserveMultiSelection = (::GetKeyState(VK_CONTROL) & 0x8000) != 0 ||
                (::GetKeyState(VK_SHIFT) & 0x8000) != 0;
            if (!kPreserveMultiSelection && ListView_GetItemState(resultList_, kRow, LVIS_SELECTED) == 0) {
                ListView_SetItemState(resultList_, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
            }
            ListView_SetItemState(resultList_, kRow, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
            ListView_EnsureVisible(resultList_, kRow, FALSE);
            updateSelectedRowDetail();
        }
    }

    const int kSelectedCount = ListView_GetSelectedCount(resultList_);
    const bool kHasSelection = kSelectedCount > 0;
    const bool kSingleSelection = kSelectedCount == 1;
    const std::wstring kModuleFile = selectedCallbackModulePath();
    const bool kHasModuleFile = !kModuleFile.empty() && ::GetFileAttributesW(kModuleFile.c_str()) != INVALID_FILE_ATTRIBUTES;

    std::uint32_t callbackClass = 0;
    std::uint32_t status = 0;
    std::uint32_t source = 0;
    std::uint32_t fieldFlags = 0;
    std::uint32_t removeBehavior = 0;
    std::uint64_t callbackAddress = 0;
    std::uint64_t registrationAddress = 0;
    std::uint64_t rawStorageValue = 0;
    std::uint64_t contextAddress = 0;
    std::uint64_t parsed = 0;
    if (parseUnsigned64Value(firstSelectedRowField({ L"Class" }), parsed)) {
        callbackClass = static_cast<std::uint32_t>(parsed);
    }
    if (parseUnsigned64Value(firstSelectedRowField({ L"Source" }), parsed)) {
        source = static_cast<std::uint32_t>(parsed);
    }
    if (parseUnsigned64Value(firstSelectedRowField({ L"FieldFlags" }), parsed)) {
        fieldFlags = static_cast<std::uint32_t>(parsed);
    }
    if (parseUnsigned64Value(firstSelectedRowField({ L"Remove" }), parsed)) {
        removeBehavior = static_cast<std::uint32_t>(parsed);
    }
    parseUnsigned64Value(firstSelectedRowField({ L"Callback" }), callbackAddress);
    parseUnsigned64Value(firstSelectedRowField({ L"Registration" }), registrationAddress);
    parseUnsigned64Value(firstSelectedRowField({ L"RawStorageValue" }), rawStorageValue);
    parseUnsigned64Value(firstSelectedRowField({ L"Context" }), contextAddress);

    const std::wstring kStatusText = firstSelectedRowField({ L"Status", L"状态" });
    if (containsCaseInsensitive(kStatusText, L"可见") || containsCaseInsensitive(kStatusText, L"OK") ||
        containsCaseInsensitive(kStatusText, L"success") || containsCaseInsensitive(kStatusText, L"(1)")) {
        status = KSWORD_ARK_CALLBACK_ENUM_STATUS_OK;
    }
    const std::wstring kRemovePolicy = firstSelectedRowField({ L"RemovePolicy", L"移除策略" });
    const std::uint64_t kRequestValue = callbackEnumPrimaryRemoveValue(
        callbackAddress,
        registrationAddress,
        rawStorageValue,
        fieldFlags);
    const bool kCanSafeRemove = kSingleSelection && callbackEnumSafeRemoveAllowed(
        callbackClass,
        status,
        source,
        fieldFlags,
        removeBehavior,
        kRequestValue,
        kRemovePolicy);
    const bool kCanExperimentalUnlink = kSingleSelection && callbackEnumExperimentalUnlinkAllowed(
        callbackClass,
        status,
        source,
        fieldFlags,
        removeBehavior,
        kRequestValue,
        contextAddress,
        kRemovePolicy);

    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return false;
    }
    ::AppendMenuW(menu, MF_STRING, kMenuRefreshCurrentFeature, L"刷新回调遍历");
    ::AppendMenuW(menu, MF_STRING | (kHasModuleFile ? MF_ENABLED : MF_GRAYED), kMenuCallbackOpenModuleFolder, L"打开模块所在目录");
    ::AppendMenuW(menu, MF_STRING | (kHasModuleFile ? MF_ENABLED : MF_GRAYED), kMenuCallbackModuleFileDetail, L"模块文件详细信息");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING | (kCanSafeRemove ? MF_ENABLED : MF_GRAYED), kMenuCallbackSafeRemove, L"安全移除（公开 API）");
    ::AppendMenuW(menu, MF_STRING | (kCanExperimentalUnlink ? MF_ENABLED : MF_GRAYED), kMenuCallbackExperimentalUnlink, L"实验性强制移除（unlink）");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);

    HMENU copyMenu = ::CreatePopupMenu();
    if (copyMenu != nullptr) {
        ::AppendMenuW(copyMenu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyCell, L"复制当前列（选中行）");
        ::AppendMenuW(copyMenu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopySelectedRows, L"复制选中行（TSV）");
        ::AppendMenuW(copyMenu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopySelectedRowsWithHeader, L"复制表头+选中行（TSV）");
        ::AppendMenuW(copyMenu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopySelectedDetails, L"复制详情（选中行）");
        ::AppendMenuW(copyMenu, MF_SEPARATOR, 0, nullptr);
        HMENU columnMenu = ::CreatePopupMenu();
        if (columnMenu != nullptr) {
            const std::vector<int> kCopyColumns = currentCopyColumnIndices();
            for (int column = 0; column < static_cast<int>(kCopyColumns.size()) &&
                column < static_cast<int>(kMenuCallbackCopyColumnMax - kMenuCallbackCopyColumnBase + 1); ++column) {
                const int kSourceColumn = kCopyColumns[static_cast<std::size_t>(column)];
                if (kSourceColumn < 0 || kSourceColumn >= static_cast<int>(currentColumns_.size())) {
                    continue;
                }
                ::AppendMenuW(columnMenu,
                    MF_STRING,
                    kMenuCallbackCopyColumnBase + static_cast<UINT_PTR>(column),
                    currentColumns_[static_cast<std::size_t>(kSourceColumn)].c_str());
            }
            ::AppendMenuW(copyMenu, MF_POPUP | (kHasSelection ? MF_ENABLED : MF_GRAYED), reinterpret_cast<UINT_PTR>(columnMenu), L"复制指定栏目（选中行）");
        }
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(copyMenu), L"复制");
    }

    ::TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, screenPoint.x, screenPoint.y, 0, hwnd_, nullptr);
    ::DestroyMenu(menu);
    return true;
}

bool KernelPage::showR0EvidenceContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor) {
    // showR0EvidenceContextMenu provides original-style popups only for R0
    // pages that had row actions in the source UI. Inputs are screen position
    // plus the active descriptor; processing exposes copy and explicit mutation
    // actions only; output true means the menu was handled.
    if (!resultList_) {
        return false;
    }
    if (descriptor.id != KernelFeatureId::kMutationAudit &&
        descriptor.id != KernelFeatureId::kMinifilterBypassPids) {
        return false;
    }
    if (screenPoint.x == -1 && screenPoint.y == -1) {
        RECT rc{};
        const int kSelected = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED);
        if (kSelected >= 0 && ListView_GetItemRect(resultList_, kSelected, &rc, LVIR_BOUNDS)) {
            screenPoint.x = rc.left;
            screenPoint.y = rc.bottom;
            ::ClientToScreen(resultList_, &screenPoint);
        } else {
            ::GetCursorPos(&screenPoint);
        }
    } else {
        POINT clientPoint = screenPoint;
        ::ScreenToClient(resultList_, &clientPoint);
        LVHITTESTINFO hit{};
        hit.pt = clientPoint;
        const int kRow = ListView_HitTest(resultList_, &hit);
        if (kRow >= 0) {
            const UINT kState = ListView_GetItemState(resultList_, kRow, LVIS_SELECTED);
            if ((kState & LVIS_SELECTED) == 0) {
                ListView_SetItemState(resultList_, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
            }
            ListView_SetItemState(resultList_, kRow, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
            ListView_EnsureVisible(resultList_, kRow, FALSE);
            updateSelectedRowDetail();
        }
    }

    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return false;
    }
    const bool kHasSelection = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED) >= 0;
    const bool kHasTransaction = descriptor.id == KernelFeatureId::kMutationAudit &&
        !firstSelectedRowField({ L"Tx", L"TransactionId" }).empty();

    ::AppendMenuW(menu, MF_STRING, kMenuRefreshCurrentFeature, L"刷新当前页");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);

    HMENU copyMenu = ::CreatePopupMenu();
    if (copyMenu) {
        ::AppendMenuW(copyMenu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyCell, L"复制当前列");
        ::AppendMenuW(copyMenu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制当前行 TSV");
        ::AppendMenuW(copyMenu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopySelectedRows, L"复制选中行 TSV");
        ::AppendMenuW(copyMenu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopySelectedRowsWithHeader, L"复制表头+选中行 TSV");
        ::AppendMenuW(copyMenu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopySelectedDetails, L"复制详情");
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(copyMenu), L"复制");
    }

    if (descriptor.id == KernelFeatureId::kMutationAudit) {
        ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(menu, MF_STRING | (kHasTransaction ? MF_ENABLED : MF_GRAYED), kMenuMutationCommitDryRun, L"Commit dry-run 当前事务");
        ::AppendMenuW(menu, MF_STRING | (kHasTransaction ? MF_ENABLED : MF_GRAYED), kMenuMutationRollbackDryRun, L"Rollback dry-run 当前事务");
        ::AppendMenuW(menu, MF_STRING | (kHasTransaction ? MF_ENABLED : MF_GRAYED), kMenuMutationRollbackConfirmed, L"确认 Rollback 当前事务");
    } else if (descriptor.id == KernelFeatureId::kMinifilterBypassPids) {
        ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(menu, MF_STRING, kMenuMinifilterSetBypass, L"设置放行 PID（过滤框）");
        ::AppendMenuW(menu, MF_STRING, kMenuMinifilterClearBypass, L"清空驱动 PID 放行");
    } else if (descriptor.id == KernelFeatureId::kNetworkTrafficPackets) {
        ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(menu, MF_STRING, kMenuNetworkCaptureStart, L"启动逐包捕获");
        ::AppendMenuW(menu, MF_STRING, kMenuNetworkCaptureStop, L"停止逐包捕获");
    } else if (descriptor.id == KernelFeatureId::kPiDdbCache) {
        const bool kHasEntry = !firstSelectedRowField({ L"Entry", L"条目地址" }).empty();
        ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(menu, MF_STRING | (kHasEntry ? MF_ENABLED : MF_GRAYED), kMenuPiDdbDeleteEntry, L"删除选中 PiDDB 条目");
    } else if (descriptor.id == KernelFeatureId::kDriverDispatchTable) {
        const bool kHasTarget = !firstSelectedRowField({ L"ModuleBase" }).empty();
        ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(menu, MF_STRING | (kHasTarget ? MF_ENABLED : MF_GRAYED), kMenuDriverDispatchRestore, L"恢复派遣槽为原值");
        ::AppendMenuW(menu, MF_STRING | (kHasTarget ? MF_ENABLED : MF_GRAYED), kMenuDriverDispatchAbandon, L"放弃派遣恢复记录");
    } else if (descriptor.id == KernelFeatureId::kDriverImageFields) {
        const bool kHasTarget = !firstSelectedRowField({ L"ModuleBase" }).empty();
        ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(menu, MF_STRING | (kHasTarget ? MF_ENABLED : MF_GRAYED), kMenuDriverImageRestore, L"恢复镜像字段为原值");
        ::AppendMenuW(menu, MF_STRING | (kHasTarget ? MF_ENABLED : MF_GRAYED), kMenuDriverImageAbandon, L"放弃镜像恢复记录");
    } else if (descriptor.id == KernelFeatureId::kDriverCommunication) {
        const bool kHasTarget = !firstSelectedRowField({ L"DriverStart", L"ModuleBase" }).empty();
        ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(menu, MF_STRING | (kHasTarget ? MF_ENABLED : MF_GRAYED), kMenuDriverCommunicationRestore, L"恢复驱动通信");
    }

    ::TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, screenPoint.x, screenPoint.y, 0, hwnd_, nullptr);
    ::DestroyMenu(menu);
    return true;
}

void KernelPage::applySelectedModuleFilter(const bool preferTargetModule) {
    // applySelectedModuleFilter turns a selected row into a module-filtered
    // refresh. Inputs are the active ListView selection and a target-module
    // preference; processing writes the module edit then reuses the normal
    // facade refresh path; return behavior is UI state update only.
    const std::wstring kModule = preferTargetModule
        ? firstSelectedRowField({ L"TargetModule", L"OwnerModule", L"Module", L"ModulePath", L"Owner", L"Import" })
        : firstSelectedRowField({ L"Module", L"ModulePath", L"OwnerModule", L"Owner", L"TargetModule", L"Import" });
    if (kModule.empty()) {
        ::MessageBoxW(hwnd_, L"当前行没有 Module/TargetModule/OwnerModule 字段，无法按模块重查。", L"模块过滤", MB_OK | MB_ICONINFORMATION);
        return;
    }
    if (const KernelFeatureDescriptor* descriptor = currentDescriptor();
        descriptor != nullptr && descriptor->id == KernelFeatureId::kCallbackEnumeration) {
        ::SetWindowTextW(filterEdit_, kModule.c_str());
        ::SetWindowTextW(statusText_, L"状态：已设置回调模块过滤。");
        rebuildCallbackEnumerationListFromCache();
        return;
    }
    ::SetWindowTextW(moduleFilterEdit_, kModule.c_str());
    ::SetWindowTextW(statusText_, L"状态：已设置模块过滤并重新查询。");
    refreshSelectedFeature();
}

void KernelPage::applySelectedAddressFilter() {
    // applySelectedAddressFilter uses the selected row's most meaningful address
    // or object field as the generic filter. Inputs are row text fields; output
    // is a filtered refresh through the same KernelFacade query contract.
    const std::wstring kValue = firstSelectedRowField({
        L"Address",
        L"Target",
        L"Service",
        L"Zw",
        L"Current",
        L"Expected",
        L"VA",
        L"Object",
        L"ThreadObject",
        L"ProcessObject",
        L"DriverObject",
        L"DeviceObject",
        L"Callback",
        L"Registration",
        L"RawStorageValue",
        L"Context",
    });
    if (kValue.empty()) {
        ::MessageBoxW(hwnd_, L"当前行没有可用于过滤的地址/对象字段。", L"地址过滤", MB_OK | MB_ICONINFORMATION);
        return;
    }
    ::SetWindowTextW(filterEdit_, kValue.c_str());
    if (const KernelFeatureDescriptor* descriptor = currentDescriptor();
        descriptor != nullptr && descriptor->id == KernelFeatureId::kCallbackEnumeration) {
        ::SetWindowTextW(statusText_, L"状态：已设置回调地址/对象过滤。");
        rebuildCallbackEnumerationListFromCache();
    } else {
        ::SetWindowTextW(statusText_, L"状态：已设置地址/对象过滤并重新查询。");
        refreshSelectedFeature();
    }
}

bool KernelPage::rebuildCurrentObjectNamespaceFilter(const wchar_t* statusText) {
    // rebuildCurrentObjectNamespaceFilter applies filter changes to cached R3
    // object pages instead of forcing a new Native/R0 query. Input is a status
    // message for the visible status bar; processing checks the active feature
    // and rebuilds object rows from currentRawRows_; return is true when the
    // caller should skip refreshSelectedFeature().
    const KernelFeatureDescriptor* descriptor = currentDescriptor();
    if (descriptor == nullptr || !isObjectNamespaceFeature(descriptor->id)) {
        return false;
    }
    if (descriptor->id == KernelFeatureId::kObjectDirectoryRecursive) {
        return false;
    }
    ::SetWindowTextW(statusText_, statusText);
    rebuildObjectNamespaceListFromCache(descriptor->id);
    return true;
}

void KernelPage::applySelectedPathFilter() {
    // applySelectedPathFilter uses native paths, driver names, pipe names, or
    // owner/module text as the generic filter/start field. Inputs are selected
    // row cells; processing writes the filter edit and reuses the normal query
    // path; output is a refreshed page focused on the chosen object.
    const std::wstring kValue = firstSelectedRowField({
        L"Path",
        L"NtPath",
        L"NT Path",
        L"fullPath",
        L"FullPath",
        L"完整路径",
        L"路径/说明",
        L"Target",
        L"targetPath",
        L"symbolicTarget",
        L"目标路径",
        L"符号链接目标",
        L"Win32Path",
        L"dosCandidate",
        L"DriverName",
        L"Name",
        L"objectName",
        L"linkName",
        L"对象名称",
        L"名称",
        L"Pipe",
        L"Pipe Name",
        L"Owner",
        L"OwnerModule",
    });
    if (kValue.empty()) {
        ::MessageBoxW(hwnd_, L"当前行没有 Path/NtPath/Name/Owner 字段，无法作为起点重查。", L"路径/名称过滤", MB_OK | MB_ICONINFORMATION);
        return;
    }
    ::SetWindowTextW(filterEdit_, kValue.c_str());
    if (rebuildCurrentObjectNamespaceFilter(L"状态：已设置路径/名称过滤。")) {
        return;
    }
    ::SetWindowTextW(statusText_, L"状态：已设置路径/名称过滤并重新查询。");
    refreshSelectedFeature();
}

void KernelPage::applySelectedTypeFilter() {
    // applySelectedTypeFilter mirrors the original object/atom context menu
    // "filter by type/source" actions. Inputs are selected row cells; output is
    // a refreshed page with the generic filter text set.
    const std::wstring kValue = firstSelectedRowField({
        L"Type",
        L"objectType",
        L"对象类型",
        L"类型",
        L"类型名",
        L"类别",
        L"ClassText",
        L"Class",
        L"Source",
        L"来源",
        L"来源目录",
    });
    if (kValue.empty()) {
        ::MessageBoxW(hwnd_, L"当前行没有 Type/Source 字段，无法按类型过滤。", L"类型过滤", MB_OK | MB_ICONINFORMATION);
        return;
    }
    ::SetWindowTextW(filterEdit_, kValue.c_str());
    if (const KernelFeatureDescriptor* descriptor = currentDescriptor();
        descriptor != nullptr && descriptor->id == KernelFeatureId::kCallbackEnumeration) {
        ::SetWindowTextW(statusText_, L"状态：已设置回调类别/来源过滤。");
        rebuildCallbackEnumerationListFromCache();
    } else {
        if (rebuildCurrentObjectNamespaceFilter(L"状态：已设置类型/来源过滤。")) {
            return;
        }
        ::SetWindowTextW(statusText_, L"状态：已设置类型/来源过滤并重新查询。");
        refreshSelectedFeature();
    }
}

void KernelPage::applySelectedNameFilter() {
    // applySelectedNameFilter mirrors original "use object name / atom name as
    // filter" operations. Inputs are selected name-like cells; output refreshes
    // through the existing facade query path.
    const std::wstring kValue = firstSelectedRowField({
        L"Name",
        L"objectName",
        L"名称",
        L"对象名称",
        L"linkName",
        L"Pipe",
        L"Pipe Name",
        L"Atom值",
        L"Id",
        L"函数",
        L"ServiceName",
        L"Name",
        L"Altitude",
    });
    if (kValue.empty()) {
        ::MessageBoxW(hwnd_, L"当前行没有名称字段，无法按名称过滤。", L"名称过滤", MB_OK | MB_ICONINFORMATION);
        return;
    }
    ::SetWindowTextW(filterEdit_, kValue.c_str());
    if (const KernelFeatureDescriptor* descriptor = currentDescriptor();
        descriptor != nullptr && descriptor->id == KernelFeatureId::kCallbackEnumeration) {
        ::SetWindowTextW(statusText_, L"状态：已设置回调名称过滤。");
        rebuildCallbackEnumerationListFromCache();
    } else {
        if (rebuildCurrentObjectNamespaceFilter(L"状态：已设置名称过滤。")) {
            return;
        }
        ::SetWindowTextW(statusText_, L"状态：已设置名称过滤并重新查询。");
        refreshSelectedFeature();
    }
}

void KernelPage::applySelectedTargetFilter() {
    // applySelectedTargetFilter uses symbolic-link targets, DOS candidates, or
    // generic Target columns as the filter text. Input is selected-row text;
    // output refreshes generic pages, while SymbolicLink updates its secondary
    // target filter and rebuilds cached rows to match the original tab.
    const std::wstring kValue = firstSelectedRowField({
        L"Target",
        L"targetPath",
        L"symbolicTarget",
        L"目标路径",
        L"符号链接目标",
        L"dosCandidate",
        L"Win32Path",
    });
    if (kValue.empty()) {
        ::MessageBoxW(hwnd_, L"当前行没有 Target/符号链接目标字段，无法按目标过滤。", L"目标过滤", MB_OK | MB_ICONINFORMATION);
        return;
    }
    const KernelFeatureDescriptor* descriptor = currentDescriptor();
    if (descriptor != nullptr && descriptor->id == KernelFeatureId::kSymbolicLink) {
        ::SetWindowTextW(moduleFilterEdit_, kValue.c_str());
        ::SetWindowTextW(statusText_, L"状态：已按目标路径过滤。");
        rebuildObjectNamespaceListFromCache(KernelFeatureId::kSymbolicLink);
        return;
    }
    ::SetWindowTextW(filterEdit_, kValue.c_str());
    if (rebuildCurrentObjectNamespaceFilter(L"状态：已设置目标过滤。")) {
        return;
    }
    ::SetWindowTextW(statusText_, L"状态：已设置目标过滤并重新查询。");
    refreshSelectedFeature();
}

void KernelPage::applySelectedOwnerFilter() {
    // applySelectedOwnerFilter uses owner/module/process text from evidence
    // rows. Inputs are selected row fields; processing writes filterEdit_ and
    // triggers the normal query/rebuild path; no value is returned.
    const std::wstring kValue = firstSelectedRowField({
        L"Owner",
        L"OwnerModule",
        L"Owner模块",
        L"模块",
        L"Module",
        L"ModulePath",
        L"进程",
        L"Process",
        L"Image",
        L"进程名",
    });
    if (kValue.empty()) {
        ::MessageBoxW(hwnd_, L"当前行没有 Owner/Module/Process 字段，无法按归属过滤。", L"归属过滤", MB_OK | MB_ICONINFORMATION);
        return;
    }
    ::SetWindowTextW(filterEdit_, kValue.c_str());
    ::SetWindowTextW(statusText_, L"状态：已按 Owner/Module/Process 过滤。");
    refreshSelectedFeature();
}

void KernelPage::applySelectedRiskFilter() {
    // applySelectedRiskFilter narrows evidence pages to the selected risk or
    // anomaly label. Inputs are current row risk fields; output refreshes the
    // visible table with the generic filter set.
    const std::wstring kValue = firstSelectedRowField({
        L"风险",
        L"RiskText",
        L"Risk",
        L"异常",
        L"AnomalyText",
        L"Anomaly",
        L"FlagsText",
        L"Status",
        L"状态",
    });
    if (kValue.empty()) {
        ::MessageBoxW(hwnd_, L"当前行没有 Risk/Anomaly/Status 字段，无法按风险过滤。", L"风险过滤", MB_OK | MB_ICONINFORMATION);
        return;
    }
    ::SetWindowTextW(filterEdit_, kValue.c_str());
    ::SetWindowTextW(statusText_, L"状态：已按风险/异常过滤。");
    refreshSelectedFeature();
}

void KernelPage::applySelectedPidTidFilter() {
    // applySelectedPidTidFilter uses PID/TID/ID columns from CrossView,
    // keyboard, and Minifilter pages. Inputs are selected row identifiers; the
    // filter edit becomes the chosen id; no value is returned.
    const std::wstring kValue = firstSelectedRowField({
        L"PID",
        L"进程ID",
        L"TID",
        L"线程ID",
        L"ID",
        L"热键ID",
    });
    if (kValue.empty()) {
        ::MessageBoxW(hwnd_, L"当前行没有 PID/TID/ID 字段，无法按标识过滤。", L"PID/TID 过滤", MB_OK | MB_ICONINFORMATION);
        return;
    }
    ::SetWindowTextW(filterEdit_, kValue.c_str());
    ::SetWindowTextW(statusText_, L"状态：已按 PID/TID/ID 过滤。");
    refreshSelectedFeature();
}

void KernelPage::applySelectedCapabilityFilter() {
    // applySelectedCapabilityFilter targets DynData-capability pages. Inputs
    // are selected capability/status fields; output refreshes the current page
    // with a local text filter.
    const std::wstring kValue = firstSelectedRowField({
        L"Capability",
        L"CapabilityMask",
        L"DynData",
        L"DynDataCapabilityMask",
        L"字段",
        L"Fields",
        L"状态",
        L"StatusFlags",
    });
    if (kValue.empty()) {
        ::MessageBoxW(hwnd_, L"当前行没有 Capability/DynData 字段，无法按能力过滤。", L"Capability 过滤", MB_OK | MB_ICONINFORMATION);
        return;
    }
    ::SetWindowTextW(filterEdit_, kValue.c_str());
    ::SetWindowTextW(statusText_, L"状态：已按 Capability/DynData 过滤。");
    refreshSelectedFeature();
}

void KernelPage::verifySelectedAtom() {
    // verifySelectedAtom mirrors KernelDock's GlobalFindAtomW check. Input is
    // the selected atom name; processing calls GlobalFindAtomW; output is shown
    // in the detail editor and also updates the status text.
    const std::wstring kName = firstSelectedRowField({ L"名称", L"Name" });
    if (kName.empty()) {
        ::MessageBoxW(hwnd_, L"当前行没有原子名称，无法校验。", L"原子校验", MB_OK | MB_ICONINFORMATION);
        return;
    }
    const ATOM kAtom = ::GlobalFindAtomW(kName.c_str());
    std::wostringstream detail;
    detail << L"GlobalFindAtomW 校验\r\n"
           << L"名称: " << kName << L"\r\n"
           << L"结果: " << (kAtom != 0 ? L"命中" : L"未命中") << L"\r\n"
           << L"Atom: " << static_cast<unsigned int>(kAtom) << L"\r\n"
           << L"十六进制: 0x" << std::uppercase << std::hex << static_cast<unsigned int>(kAtom);
    ::SetWindowTextW(detailEdit_, detail.str().c_str());
    ::SetWindowTextW(statusText_, kAtom != 0 ? L"状态：GlobalFindAtomW 校验命中。" : L"状态：GlobalFindAtomW 未命中。");
}

void KernelPage::copySelectedAtomSnippet() {
    // copySelectedAtomSnippet mirrors the original atom page snippet action.
    // Input is the selected atom name; output writes a Win32 call snippet to the
    // clipboard and displays it in the detail pane.
    std::wstring name = firstSelectedRowField({ L"名称", L"Name" });
    if (name.empty()) {
        ::MessageBoxW(hwnd_, L"当前行没有原子名称，无法生成调用代码。", L"原子代码片段", MB_OK | MB_ICONINFORMATION);
        return;
    }
    std::wstring escaped;
    escaped.reserve(name.size());
    for (const wchar_t kCh : name) {
        if (kCh == L'\\' || kCh == L'"') {
            escaped.push_back(L'\\');
        }
        escaped.push_back(kCh);
    }
    const std::wstring kSnippet = L"ATOM atomValue = GlobalFindAtomW(L\"" + escaped + L"\");";
    setClipboardText(hwnd_, kSnippet);
    ::SetWindowTextW(detailEdit_, (L"已复制调用代码片段:\r\n" + kSnippet).c_str());
    ::SetWindowTextW(statusText_, L"状态：已复制 GlobalFindAtomW 调用代码片段。");
}

void KernelPage::copyRowsWithSameDirectory() {
    // copyRowsWithSameDirectory mirrors KernelDock's object namespace "copy same
    // directory rows" action. Input is the selected row's parent/directory; the
    // output is the original nine-field KernelObjectNamespaceEntry TSV copied
    // to the clipboard.
    const std::wstring kDirectory = firstSelectedRowField({
        L"directoryPath",
        L"Parent",
        L"Directory",
        L"目录路径",
        L"来源目录",
        L"sourceDirectory",
    });
    if (kDirectory.empty()) {
        ::MessageBoxW(hwnd_, L"当前行没有目录字段，无法复制同目录行。", L"复制同目录", MB_OK | MB_ICONINFORMATION);
        return;
    }
    std::wstring text;
    for (const std::vector<std::wstring>& row : currentRows_) {
        bool sameDirectory = false;
        for (int column = 0; column < static_cast<int>(currentColumns_.size()) && column < static_cast<int>(row.size()); ++column) {
            const std::wstring& columnName = currentColumns_[static_cast<std::size_t>(column)];
            if ((_wcsicmp(columnName.c_str(), L"directoryPath") == 0 ||
                 _wcsicmp(columnName.c_str(), L"Parent") == 0 ||
                 _wcsicmp(columnName.c_str(), L"Directory") == 0 ||
                 _wcsicmp(columnName.c_str(), L"目录路径") == 0 ||
                 _wcsicmp(columnName.c_str(), L"来源目录") == 0 ||
                 _wcsicmp(columnName.c_str(), L"sourceDirectory") == 0) &&
                _wcsicmp(row[static_cast<std::size_t>(column)].c_str(), kDirectory.c_str()) == 0) {
                sameDirectory = true;
                break;
            }
        }
        if (!sameDirectory) {
            continue;
        }
        if (!text.empty()) {
            text += L"\r\n";
        }
        const wchar_t* fields[] = {
            L"rootPathText", L"scopeDescriptionText", L"directoryPathText",
            L"objectNameText", L"objectTypeText", L"fullPathText",
            L"enumApiText", L"symbolicLinkTargetText", L"statusText",
        };
        for (std::size_t fieldIndex = 0; fieldIndex < std::size(fields); ++fieldIndex) {
            if (fieldIndex > 0) {
                text += L'\t';
            }
            std::wstring value = rowFieldByName(row, currentColumns_, { fields[fieldIndex] });
            if (value.empty()) {
                switch (fieldIndex) {
                case 0: value = rowFieldByName(row, currentColumns_, { L"Root", L"Source" }); break;
                case 1: value = rowFieldByName(row, currentColumns_, { L"Scope", L"scope", L"Detail", L"路径/说明" }); break;
                case 2: value = rowFieldByName(row, currentColumns_, { L"directoryPath", L"Parent", L"Directory", L"来源目录" }); break;
                case 3: value = rowFieldByName(row, currentColumns_, { L"objectName", L"Name", L"名称" }); break;
                case 4: value = rowFieldByName(row, currentColumns_, { L"objectType", L"Type", L"类型" }); break;
                case 5: value = rowFieldByName(row, currentColumns_, { L"fullPath", L"Path", L"完整路径", L"路径/说明" }); break;
                case 6: value = rowFieldByName(row, currentColumns_, { L"enumApi", L"EnumApi", L"枚举 API", L"EnumerationApi" }); break;
                case 7: value = rowFieldByName(row, currentColumns_, { L"symbolicLinkTarget", L"symbolicTarget", L"Target", L"targetPath", L"符号链接目标" }); break;
                case 8: value = rowFieldByName(row, currentColumns_, { L"statusText", L"Status", L"状态" }); break;
                default: break;
                }
            }
            text += value.empty() ? L"<空>" : value;
        }
    }
    setClipboardText(hwnd_, text);
    ::SetWindowTextW(statusText_, L"状态：已复制同目录全部行。");
}

void KernelPage::mapSelectedNtPathAsDosPaths() {
    // mapSelectedNtPathAsDosPaths captures the selected NT path and delegates
    // all drive/device queries to the background file-I/O task.
    const std::wstring kNtPath = firstSelectedRowField({
        L"Target",
        L"targetPath",
        L"symbolicTarget",
        L"符号链接目标",
        L"Path",
        L"fullPath",
        L"完整路径",
    });
    if (kNtPath.empty() || kNtPath.rfind(L"\\Device\\", 0) != 0) {
        ::MessageBoxW(hwnd_, L"当前行不是 \\Device\\... NT 路径，无法映射 DOS 路径。", L"DOS 路径映射", MB_OK | MB_ICONINFORMATION);
        return;
    }
    startCallbackFileIo(CallbackFileIoOperation::kMapNtPath, kNtPath);
}

std::wstring KernelPage::normalizeCallbackModulePath(const std::wstring& modulePath) const {
    // normalizeCallbackModulePath mirrors the original CallbackEnum module path
    // normalization. Input is an R0 module path such as \SystemRoot\... or
    // \??\C:\...; processing converts it to a Win32 file path when possible;
    // output is empty when the selected row has no usable module file.
    std::wstring path = modulePath;
    while (!path.empty() && std::iswspace(path.front())) {
        path.erase(path.begin());
    }
    while (!path.empty() && std::iswspace(path.back())) {
        path.pop_back();
    }
    if (path.empty() || path == L"<未解析>" || path == L"<unknown>") {
        return {};
    }
    constexpr wchar_t kNtPrefix[] = L"\\??\\";
    if (_wcsnicmp(path.c_str(), kNtPrefix, 4) == 0) {
        path.erase(0, 4);
    }
    constexpr wchar_t kSystemRootPrefix[] = L"\\SystemRoot\\";
    if (_wcsnicmp(path.c_str(), kSystemRootPrefix, 12) == 0) {
        wchar_t windowsDir[MAX_PATH]{};
        const UINT kChars = ::GetWindowsDirectoryW(windowsDir, MAX_PATH);
        if (kChars > 0) {
            path = std::wstring(windowsDir) + path.substr(11);
        }
    }
    constexpr wchar_t kSysrootPrefix[] = L"SystemRoot\\";
    if (_wcsnicmp(path.c_str(), kSysrootPrefix, 11) == 0) {
        wchar_t windowsDir[MAX_PATH]{};
        const UINT kChars = ::GetWindowsDirectoryW(windowsDir, MAX_PATH);
        if (kChars > 0) {
            path = std::wstring(windowsDir) + L"\\" + path.substr(11);
        }
    }
    return path;
}

std::wstring KernelPage::selectedCallbackModulePath() const {
    // selectedCallbackModulePath returns the normalized module file for the
    // selected CallbackEnum row. Inputs are the current row fields; output is a
    // Win32 path suitable for ShellExecute/GetFileAttributes or empty.
    return normalizeCallbackModulePath(firstSelectedRowField({
        L"Win32ModulePath",
        L"ModulePath",
        L"Module",
        L"模块",
    }));
}

void KernelPage::openSelectedCallbackModuleFolder() {
    // openSelectedCallbackModuleFolder mirrors the original CallbackEnum Explorer
    // action. Input is the selected module path; processing asks explorer.exe to
    // select the module file; no value is returned beyond status text.
    const std::wstring kModulePath = selectedCallbackModulePath();
    if (kModulePath.empty()) {
        ::MessageBoxW(hwnd_, L"当前回调行没有可访问的模块文件。", L"打开模块所在目录", MB_OK | MB_ICONINFORMATION);
        return;
    }
    startCallbackFileIo(CallbackFileIoOperation::kOpenModuleFolder, kModulePath);
}

void KernelPage::showSelectedCallbackModuleFileDetail() {
    // showSelectedCallbackModuleFileDetail captures the selected row's immutable
    // text and delegates file metadata, version-resource and PE-header reads to
    // the callback file-I/O task.
    const std::wstring kModulePath = selectedCallbackModulePath();
    if (kModulePath.empty()) {
        ::MessageBoxW(hwnd_, L"当前回调行没有可访问的模块文件。", L"模块文件详细信息", MB_OK | MB_ICONINFORMATION);
        return;
    }
    std::wostringstream summary;
    summary << L"回调行摘要\r\n"
            << L"原始模块路径: " << firstSelectedRowField({ L"ModulePath", L"Module", L"模块" }) << L"\r\n"
            << L"类别: " << firstSelectedRowField({ L"ClassText", L"Class", L"类别" }) << L"\r\n"
            << L"来源: " << firstSelectedRowField({ L"SourceText", L"Source", L"来源" }) << L"\r\n"
            << L"名称: " << firstSelectedRowField({ L"Name", L"名称" }) << L"\r\n"
            << L"Callback: " << selectedRowField(L"Callback") << L"\r\n"
            << L"ModuleBase: " << selectedRowField(L"ModuleBase") << L"\r\n"
            << L"ModuleSize: " << selectedRowField(L"ModuleSize") << L"\r\n";
    startCallbackFileIo(CallbackFileIoOperation::kCallbackModuleDetail, kModulePath, summary.str());
}


void KernelPage::copyPreferredSelectedField(std::initializer_list<std::wstring> fieldNames, const wchar_t* statusText) {
    // copyPreferredSelectedField mirrors original per-field copy actions. Input
    // is a priority list of display column names and a final status string;
    // output is clipboard text only.
    const std::wstring kValue = firstSelectedRowField(fieldNames);
    if (kValue.empty()) {
        ::MessageBoxW(hwnd_, L"当前行没有对应字段可复制。", L"复制字段", MB_OK | MB_ICONINFORMATION);
        return;
    }
    setClipboardText(hwnd_, kValue);
    ::SetWindowTextW(statusText_, statusText);
}

std::wstring KernelPage::buildRowDetailText(const int row) const {
    // buildRowDetailText builds the same expanded key/value text shown in the
    // detail editor. Input is a ListView row index; processing prefers original
    // KernelDock detail text for pages with hand-written detail builders and
    // falls back to visible columns; output is empty for invalid rows.
    if (!resultList_ || row < 0) {
        return {};
    }
    if (const KernelFeatureDescriptor* descriptor = currentDescriptor(); descriptor != nullptr) {
        const std::wstring kOriginalStyle = buildOriginalStyleSelectedRowDetail(descriptor->id, row);
        if (!kOriginalStyle.empty()) {
            return kOriginalStyle;
        }
    }
    const int kColumns = headerColumnCount(resultList_);
    std::wstring detail;
    for (int column = 0; column < kColumns; ++column) {
        const std::wstring kName = column < static_cast<int>(currentColumns_.size())
            ? currentColumns_[static_cast<std::size_t>(column)]
            : std::wstring(L"Column ") + std::to_wstring(column);
        const std::wstring kValue = visibleCellText(row, column);
        if (!detail.empty()) {
            detail += L"\r\n";
        }
        detail += kName;
        detail += L": ";
        detail += kValue;
    }
    return detail;
}

void KernelPage::showSelectedRowDialog() {
    // showSelectedRowDialog displays the same expanded key/value text as a modal
    // dialog. Inputs are the current row; processing reuses buildRowDetailText;
    // output is a readable row detail dialog for rows with many columns.
    const int kRow = resultList_ ? ListView_GetNextItem(resultList_, -1, LVNI_SELECTED) : -1;
    if (kRow < 0) {
        ::MessageBoxW(hwnd_, L"请先选择一条结果行。", L"当前行详情", MB_OK | MB_ICONINFORMATION);
        return;
    }
    const std::wstring kDetail = buildRowDetailText(kRow);
    ::MessageBoxW(hwnd_, kDetail.c_str(), L"当前行详情", MB_OK | MB_ICONINFORMATION);
}

std::wstring KernelPage::firstSelectedRowField(std::initializer_list<std::wstring> fieldNames) const {
    // firstSelectedRowField scans a preferred field-name list and returns the
    // first selected-row value that exists. Inputs are display column names;
    // output is empty only when none of those columns contain text.
    for (const std::wstring& name : fieldNames) {
        const std::wstring kValue = selectedRowField(name);
        if (!kValue.empty()) {
            return kValue;
        }
    }
    return {};
}

std::wstring KernelPage::firstSelectedRowValue(std::initializer_list<const wchar_t*> fieldNames) const {
    // firstSelectedRowValue is a literal-friendly wrapper for confirmation
    // dialogs and action builders. Inputs are candidate column names as string
    // literals; processing reuses firstSelectedRowField; output is the first
    // non-empty selected cell value or empty when all aliases miss.
    for (const wchar_t* fieldName : fieldNames) {
        const std::wstring kValue = selectedRowField(fieldName);
        if (!kValue.empty()) {
            return kValue;
        }
    }
    return {};
}

std::wstring KernelPage::selectedRowField(const std::wstring& fieldName) const {
    // selectedRowField reads one named cell from the current result list.
    // Inputs are a dynamic column name and the active selection; processing scans
    // currentColumns_ case-insensitively and reads the matching visible cell, so
    // sorted rows and current ListView state are respected; output is empty when
    // no selection or no matching field exists.
    if (!resultList_) {
        return {};
    }
    const int kRow = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED);
    if (kRow < 0) {
        return {};
    }
    for (int column = 0; column < static_cast<int>(currentColumns_.size()); ++column) {
        if (_wcsicmp(currentColumns_[static_cast<std::size_t>(column)].c_str(), fieldName.c_str()) == 0) {
            return visibleCellText(kRow, column);
        }
    }
    return {};
}

void KernelPage::copySelectedCell() {
    // copySelectedCell copies the right-click/current column for every selected
    // row. Inputs are the current ListView selection and contextColumn_ from
    // WM_CONTEXTMENU; output is one value per line on the clipboard.
    const int kRow = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED);
    if (kRow < 0) {
        return;
    }
    const int kColumns = headerColumnCount(resultList_);
    int column = contextColumn_;
    if (column < 0 || column >= kColumns) {
        column = 1;
    }
    if (column < 0 || column >= kColumns) {
        return;
    }
    copySelectedColumn(column);
}

void KernelPage::copySelectedRow() {
    // copySelectedRow serializes the selected row as tab-separated text. Inputs
    // are current ListView selection; output is clipboard text only.
    const int kRow = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED);
    if (kRow < 0) {
        return;
    }
    if (const KernelFeatureDescriptor* descriptor = currentDescriptor();
        descriptor != nullptr && descriptor->id == KernelFeatureId::kObjectNamespaceOverview) {
        const auto kCell = [&](std::initializer_list<const wchar_t*> names) -> std::wstring {
            for (const wchar_t* name : names) {
                for (int column = 0; column < static_cast<int>(currentColumns_.size()); ++column) {
                    if (_wcsicmp(currentColumns_[static_cast<std::size_t>(column)].c_str(), name) == 0) {
                        const std::wstring kValue = visibleCellText(kRow, column);
                        if (!kValue.empty()) {
                            return kValue;
                        }
                    }
                }
            }
            return {};
        };
        const auto kSafe = [](const std::wstring& value) -> std::wstring {
            return value.empty() ? std::wstring(L"<空>") : value;
        };
        const std::wstring kNodeKind = kCell({ L"NodeKind" });
        if (_wcsicmp(kNodeKind.c_str(), L"ObjectEntry") == 0 || kNodeKind.empty()) {
            const std::wstring kFields[] = {
                kSafe(kCell({ L"rootPathText", L"Root", L"Source" })),
                kSafe(kCell({ L"scopeDescriptionText", L"Scope", L"scope", L"Detail", L"路径/说明" })),
                kSafe(kCell({ L"directoryPathText", L"directoryPath", L"Parent", L"Directory", L"来源目录" })),
                kSafe(kCell({ L"objectNameText", L"objectName", L"Name", L"名称" })),
                kSafe(kCell({ L"objectTypeText", L"objectType", L"Type", L"类型" })),
                kSafe(kCell({ L"fullPathText", L"fullPath", L"Path", L"完整路径", L"路径/说明" })),
                kSafe(kCell({ L"enumApiText", L"enumApi", L"EnumApi", L"枚举 API", L"EnumerationApi" })),
                kSafe(kCell({ L"symbolicLinkTargetText", L"symbolicLinkTarget", L"symbolicTarget", L"Target", L"targetPath", L"符号链接目标" })),
                kSafe(kCell({ L"statusText", L"Status", L"状态" })),
            };
            std::wstring text;
            for (std::size_t index = 0; index < std::size(kFields); ++index) {
                if (index > 0) {
                    text += L'\t';
                }
                text += kFields[index];
            }
            setClipboardText(hwnd_, text);
            return;
        }
        std::wstring text;
        const wchar_t* treeFields[] = { L"名称", L"类型", L"路径/说明", L"状态", L"符号链接目标" };
        for (std::size_t index = 0; index < std::size(treeFields); ++index) {
            if (index > 0) {
                text += L'\t';
            }
            text += kSafe(kCell({ treeFields[index] }));
        }
        setClipboardText(hwnd_, text);
        return;
    }
    const int kColumns = headerColumnCount(resultList_);
    std::vector<int> copyColumns;
    if (const KernelFeatureDescriptor* descriptor = currentDescriptor(); descriptor != nullptr) {
        copyColumns = preferredCopyColumnIndices(descriptor->id, currentColumns_);
    }
    if (copyColumns.empty()) {
        copyColumns.reserve(static_cast<std::size_t>(kColumns));
        for (int column = 0; column < kColumns; ++column) {
            copyColumns.push_back(column);
        }
    }
    std::wstring text;
    for (std::size_t position = 0; position < copyColumns.size(); ++position) {
        if (position > 0) {
            text += L'\t';
        }
        const int kColumn = copyColumns[position];
        if (kColumn < 0 || kColumn >= kColumns) {
            continue;
        }
        text += visibleCellText(kRow, kColumn);
    }
    setClipboardText(hwnd_, text);
}

std::wstring KernelPage::buildSelectedRowsTsv(const bool includeHeader) const {
    // buildSelectedRowsTsv serializes the current multi-selection. Input chooses
    // whether to prepend the visible header row; processing walks LVNI_SELECTED
    // so sorted/filtered ListView state is honored; output is empty when no row
    // is selected.
    if (!resultList_) {
        return {};
    }
    const int kColumns = headerColumnCount(resultList_);
    std::vector<int> copyColumns;
    if (const KernelFeatureDescriptor* descriptor = currentDescriptor(); descriptor != nullptr) {
        copyColumns = preferredCopyColumnIndices(descriptor->id, currentColumns_);
    }
    if (copyColumns.empty()) {
        copyColumns.reserve(static_cast<std::size_t>(kColumns));
        for (int column = 0; column < kColumns; ++column) {
            copyColumns.push_back(column);
        }
    }
    std::wstring text;
    if (includeHeader) {
        for (std::size_t position = 0; position < copyColumns.size(); ++position) {
            if (position > 0) {
                text += L'\t';
            }
            const int kColumn = copyColumns[position];
            text += kColumn < static_cast<int>(currentColumns_.size())
                ? currentColumns_[static_cast<std::size_t>(kColumn)]
                : std::wstring(L"Column") + std::to_wstring(kColumn);
        }
    }
    int row = -1;
    bool wroteRow = false;
    while ((row = ListView_GetNextItem(resultList_, row, LVNI_SELECTED)) >= 0) {
        if (!text.empty()) {
            text += L"\r\n";
        }
        for (std::size_t position = 0; position < copyColumns.size(); ++position) {
            if (position > 0) {
                text += L'\t';
            }
            const int kColumn = copyColumns[position];
            if (kColumn < 0 || kColumn >= kColumns) {
                continue;
            }
            text += visibleCellText(row, kColumn);
        }
        wroteRow = true;
    }
    return wroteRow ? text : std::wstring{};
}

void KernelPage::copySelectedRows(const bool includeHeader) {
    // copySelectedRows mirrors the original KernelDock multi-row TSV copy.
    // Input is includeHeader; processing serializes selected rows only; output
    // is clipboard text and a compact status message.
    const std::wstring kText = buildSelectedRowsTsv(includeHeader);
    if (kText.empty()) {
        ::MessageBoxW(hwnd_, L"请先选择至少一条结果行。", L"复制选中行", MB_OK | MB_ICONINFORMATION);
        return;
    }
    setClipboardText(hwnd_, kText);
    ::SetWindowTextW(statusText_, includeHeader ? L"状态：已复制表头和选中行。" : L"状态：已复制选中行。");
}

void KernelPage::copySelectedDetails() {
    // copySelectedDetails mirrors the original "copy detail" menu. Inputs are
    // all selected ListView rows; processing concatenates each row's detail text;
    // output is clipboard text and detailEdit_ preview.
    if (!resultList_) {
        return;
    }
    std::wstring text;
    int row = -1;
    int count = 0;
    const KernelFeatureDescriptor* descriptor = currentDescriptor();
    const bool kOriginalDetailOnly = descriptor != nullptr && isOriginalDetailPreferredFeature(descriptor->id);
    while ((row = ListView_GetNextItem(resultList_, row, LVNI_SELECTED)) >= 0) {
        if (!text.empty()) {
            text += kOriginalDetailOnly ? L"\r\n\r\n---\r\n\r\n" : L"\r\n\r\n";
        }
        if (!kOriginalDetailOnly) {
            text += L"[Row ";
            text += std::to_wstring(row + 1);
            text += L"]\r\n";
        }
        text += buildRowDetailText(row);
        ++count;
    }
    if (count == 0) {
        ::MessageBoxW(hwnd_, L"请先选择至少一条结果行。", L"复制详情", MB_OK | MB_ICONINFORMATION);
        return;
    }
    setClipboardText(hwnd_, text);
    ::SetWindowTextW(detailEdit_, text.c_str());
    ::SetWindowTextW(statusText_, L"状态：已复制选中行详情。");
}

void KernelPage::copySelectedColumn(const int columnIndex) {
    // copySelectedColumn mirrors the original per-column copy submenu. Input is
    // a visible column index chosen from the popup menu; processing copies that
    // column for all selected rows, one value per line; output is clipboard text.
    if (!resultList_ || columnIndex < 0 || columnIndex >= headerColumnCount(resultList_)) {
        return;
    }
    std::wstring text;
    int row = -1;
    int count = 0;
    while ((row = ListView_GetNextItem(resultList_, row, LVNI_SELECTED)) >= 0) {
        if (!text.empty()) {
            text += L"\r\n";
        }
        text += visibleCellText(row, columnIndex);
        ++count;
    }
    if (count == 0) {
        ::MessageBoxW(hwnd_, L"请先选择至少一条结果行。", L"复制指定栏目", MB_OK | MB_ICONINFORMATION);
        return;
    }
    setClipboardText(hwnd_, text);
    ::SetWindowTextW(statusText_, L"状态：已复制指定栏目。");
}

std::vector<int> KernelPage::currentCopyColumnIndices() const {
    // currentCopyColumnIndices returns the table columns that user-facing copy
    // and export actions should include. Inputs are the active feature and
    // current dynamic schema; processing keeps hidden protocol columns out of
    // clipboard/TSV output; output falls back to every ListView column.
    const int kColumns = resultList_ ? headerColumnCount(resultList_) : 0;
    std::vector<int> copyColumns;
    if (const KernelFeatureDescriptor* descriptor = currentDescriptor(); descriptor != nullptr) {
        copyColumns = preferredCopyColumnIndices(descriptor->id, currentColumns_);
    }
    if (copyColumns.empty()) {
        copyColumns.reserve(static_cast<std::size_t>(kColumns));
        for (int column = 0; column < kColumns; ++column) {
            copyColumns.push_back(column);
        }
    }
    return copyColumns;
}


void KernelPage::copyAllRows() {
    // copyAllRows serializes the whole result grid as tab-separated rows. There
    // is no input beyond the current ListView content; output is clipboard text.
    const int kRows = ListView_GetItemCount(resultList_);
    const int kColumns = headerColumnCount(resultList_);
    const std::vector<int> kCopyColumns = currentCopyColumnIndices();
    std::wstring text;
    for (int row = 0; row < kRows; ++row) {
        if (row > 0) {
            text += L"\r\n";
        }
        for (std::size_t position = 0; position < kCopyColumns.size(); ++position) {
            if (position > 0) {
                text += L'\t';
            }
            const int kColumn = kCopyColumns[position];
            if (kColumn < 0 || kColumn >= kColumns) {
                continue;
            }
            text += visibleCellText(row, kColumn);
        }
    }
    setClipboardText(hwnd_, text);
}


void KernelPage::copyDiagnosticReport() {
    // copyDiagnosticReport exposes the original KernelDock DynData/DriverStatus
    // "copy diagnostic" workflow. Inputs are the current feature selection and
    // cached table rows; processing builds a plain-text report and places it on
    // the clipboard; no value is returned, but statusText_ is updated.
    const std::wstring kReport = buildDiagnosticReportForCurrentFeature();
    if (kReport.empty()) {
        ::MessageBoxW(hwnd_, L"当前页没有可复制的诊断报告。", L"复制诊断", MB_OK | MB_ICONINFORMATION);
        return;
    }
    setClipboardText(hwnd_, kReport);
    ::SetWindowTextW(detailEdit_, kReport.c_str());
    ::SetWindowTextW(statusText_, L"状态：已复制诊断报告。");
}

std::wstring KernelPage::buildDiagnosticReportForCurrentFeature() const {
    // buildDiagnosticReportForCurrentFeature mirrors the original helper
    // buildDynDataReport/buildDriverStatusReport. Inputs are currentRows_ and
    // currentColumns_; processing emits summary key/value lines followed by the
    // visible field/capability matrix; output is empty for non-diagnostic pages.
    const KernelFeatureDescriptor* descriptor = currentDescriptor();
    if (descriptor == nullptr) {
        return {};
    }

    const auto kRowValue = [&](const std::vector<std::wstring>& row, std::initializer_list<const wchar_t*> names) -> std::wstring {
        return rowFieldByName(row, currentColumns_, names);
    };
    const auto kFirstValue = [&](std::initializer_list<const wchar_t*> names) -> std::wstring {
        for (const std::vector<std::wstring>& row : currentRows_) {
            const std::wstring kValue = kRowValue(row, names);
            if (!kValue.empty()) {
                return kValue;
            }
        }
        return {};
    };
    const auto kFirstRawValue = [&](std::initializer_list<const wchar_t*> names) -> std::wstring {
        const std::vector<std::wstring>& rawColumns = !currentRawColumns_.empty() ? currentRawColumns_ : currentColumns_;
        const std::vector<std::vector<std::wstring>>& rawRows = !currentRawRows_.empty() ? currentRawRows_ : currentRows_;
        for (const std::vector<std::wstring>& row : rawRows) {
            const std::wstring kValue = rowFieldByName(row, rawColumns, names);
            if (!kValue.empty()) {
                return kValue;
            }
        }
        return {};
    };
    const auto kFirstAnyValue = [&](std::initializer_list<const wchar_t*> names) -> std::wstring {
        const std::wstring kVisible = kFirstValue(names);
        return kVisible.empty() ? kFirstRawValue(names) : kVisible;
    };
    const auto kAppendTableHeader = [&](std::wostringstream& report) {
        const std::vector<int> kCopyColumns = currentCopyColumnIndices();
        for (std::size_t position = 0; position < kCopyColumns.size(); ++position) {
            if (position > 0) {
                report << L'\t';
            }
            const int kColumn = kCopyColumns[position];
            if (kColumn >= 0 && kColumn < static_cast<int>(currentColumns_.size())) {
                report << currentColumns_[static_cast<std::size_t>(kColumn)];
            }
        }
        report << L"\r\n";
    };
    const auto kAppendTableRows = [&](std::wostringstream& report) {
        const std::vector<int> kCopyColumns = currentCopyColumnIndices();
        for (const std::vector<std::wstring>& row : currentRows_) {
            for (std::size_t position = 0; position < kCopyColumns.size(); ++position) {
                if (position > 0) {
                    report << L'\t';
                }
                const int kColumn = kCopyColumns[position];
                if (kColumn < row.size()) {
                    report << row[static_cast<std::size_t>(kColumn)];
                }
            }
            report << L"\r\n";
        }
    };

    if (descriptor->id == KernelFeatureId::kDynData) {
        std::size_t fieldRows = 0;
        std::size_t profileRows = 0;
        std::size_t failedRows = 0;
        for (const std::vector<std::wstring>& row : currentRows_) {
            const std::wstring kField = kRowValue(row, { L"Field", L"字段", L"Name" });
            const std::wstring kSource = kRowValue(row, { L"Source", L"来源" });
            const std::wstring kStatus = kRowValue(row, { L"Status", L"状态", L"DynData Fields IO" });
            if (!kField.empty()) {
                ++fieldRows;
            }
            if (containsCaseInsensitive(kSource, L"profile") || containsCaseInsensitive(kSource, L"pack") ||
                containsCaseInsensitive(kSource, L"pdb")) {
                ++profileRows;
            }
            if (containsCaseInsensitive(kStatus, L"fail") || containsCaseInsensitive(kStatus, L"失败") ||
                containsCaseInsensitive(kStatus, L"missing")) {
                ++failedRows;
            }
        }

        std::wostringstream report;
        report << L"Ksword DynData Diagnostic Report\r\n";
        report << L"========================================\r\n";
        appendReportLine(report, L"StatusQueryOk", kFirstAnyValue({ L"StatusQueryOk" }));
        appendReportLine(report, L"FieldsQueryOk", kFirstAnyValue({ L"FieldsQueryOk" }));
        appendReportLine(report, L"StatusFlags", kFirstAnyValue({ L"StatusFlags" }));
        appendReportLine(report, L"CapabilityMask", kFirstAnyValue({ L"CapabilityMask", L"Capability" }));
        appendReportLine(report, L"SystemInformerDataVersion", kFirstAnyValue({ L"SI Version" }));
        appendReportLine(report, L"SystemInformerDataLength", kFirstAnyValue({ L"SI Length" }));
        appendReportLine(report, L"LastStatus", kFirstAnyValue({ L"LastStatus" }));
        appendReportLine(report, L"MatchedProfileClass", kFirstAnyValue({ L"MatchedClass", L"ProfileClass" }));
        appendReportLine(report, L"MatchedProfileOffset", kFirstAnyValue({ L"MatchedProfileOffset" }));
        appendReportLine(report, L"MatchedFieldsId", kFirstAnyValue({ L"MatchedFieldsId" }));
        appendReportLine(report, L"UnavailableReason", kFirstAnyValue({ L"UnavailableReason" }));
        appendReportLine(report, L"PdbProfileActive", flagEnabled(firstRowUInt64(!currentRawRows_.empty() ? currentRawRows_ : currentRows_,
            !currentRawColumns_.empty() ? currentRawColumns_ : currentColumns_, { L"StatusFlags" }), KSW_DYN_STATUS_FLAG_PDB_PROFILE_ACTIVE) ? L"是" : L"否");
        appendReportLine(report, L"PdbProfileScanAttempted", kFirstAnyValue({ L"PdbProfileScanAttempted" }));
        appendReportLine(report, L"PdbProfileFound", kFirstAnyValue({ L"PdbProfileFound" }));
        appendReportLine(report, L"PdbProfileAppliedThisRefresh", kFirstAnyValue({ L"PdbProfileApplied" }));
        appendReportLine(report, L"PdbProfileSource", kFirstAnyValue({ L"PdbProfileSource" }));
        appendReportLine(report, L"PdbProfileName", kFirstAnyValue({ L"PdbProfileName", L"Profile" }));
        appendReportLine(report, L"PdbProfilePath", kFirstAnyValue({ L"PdbProfilePath", L"ProfilePath" }));
        appendReportLine(report, L"PdbProfileStatus", kFirstAnyValue({ L"PdbProfileStatus" }));
        appendReportLine(report, L"PdbProfileAppliedFields", kFirstAnyValue({ L"PdbProfileAppliedFields" }));
        appendReportLine(report, L"PdbProfileRejectedFields", kFirstAnyValue({ L"PdbProfileRejectedFields" }));
        appendReportLine(report, L"PdbProfileUnknownFields", kFirstAnyValue({ L"PdbProfileUnknownFields" }));
        appendReportLine(report, L"PdbProfileIgnoredJsonFields", kFirstAnyValue({ L"PdbProfileIgnoredJsonFields" }));
        appendReportLine(report, L"PdbProfileMessage", kFirstAnyValue({ L"PdbProfileMessage" }));
        appendReportLine(report, L"PdbProfileIo", kFirstAnyValue({ L"PdbProfileIo" }));
        appendReportLine(report, L"Ntos", kFirstAnyValue({ L"Ntos", L"NtosIdentity" }));
        appendReportLine(report, L"Lxcore", kFirstAnyValue({ L"Lxcore", L"LxcoreIdentity" }));
        appendReportLine(report, L"FieldCount", kFirstAnyValue({ L"FieldCount", L"FieldsTotal" }));
        appendReportLine(report, L"FieldsReturned", kFirstAnyValue({ L"FieldsReturned" }));
        report << L"VisibleFieldRows: " << fieldRows << L"\r\n";
        report << L"ProfileDiagnosticRows: " << profileRows << L"\r\n";
        report << L"FailedDiagnosticRows: " << failedRows << L"\r\n\r\n";
        report << L"Capabilities:\r\n";
        std::uint64_t capabilityMask = 0;
        hexToUInt64(kFirstAnyValue({ L"CapabilityMask", L"Capability" }), capabilityMask);
        report << dynCapabilityNames(capabilityMask) << L"\r\n\r\n";
        report << L"Fields\r\n";
        report << L"----------------------------------------\r\n";
        kAppendTableHeader(report);
        kAppendTableRows(report);
        return report.str();
    }

    if (descriptor->id == KernelFeatureId::kDriverStatus) {
        std::size_t capabilityRows = 0;
        std::size_t unavailableRows = 0;
        std::size_t dynDataDependentRows = 0;
        for (const std::vector<std::wstring>& row : currentRows_) {
            const std::wstring kFeature = kRowValue(row, { L"Feature", L"功能", L"Name" });
            const std::wstring kState = kRowValue(row, { L"State", L"状态", L"Status" });
            const std::wstring kRequiredDyn = kRowValue(row, { L"RequiredDyn", L"所需DynData" });
            if (!kFeature.empty()) {
                ++capabilityRows;
            }
            if (containsCaseInsensitive(kState, L"unavailable") || containsCaseInsensitive(kState, L"disabled") ||
                containsCaseInsensitive(kState, L"不可用") || containsCaseInsensitive(kState, L"禁用")) {
                ++unavailableRows;
            }
            if (!kRequiredDyn.empty() && kRequiredDyn != L"0" && kRequiredDyn != L"0x0" && kRequiredDyn != L"0x0000000000000000") {
                ++dynDataDependentRows;
            }
        }

        std::wostringstream report;
        report << L"Ksword Driver Capability Diagnostic Report\r\n";
        report << L"========================================\r\n";
        appendReportLine(report, L"Status", kFirstAnyValue({ L"StatusBadges" }));
        appendReportLine(report, L"QueryOk", kFirstAnyValue({ L"IO" }));
        appendReportLine(report, L"IoMessage", kFirstAnyValue({ L"IoMessage", L"Driver Capabilities" }));
        appendReportLine(report, L"CapabilityProtocolVersion", kFirstAnyValue({ L"Version" }));
        appendReportLine(report, L"DriverProtocolVersion", kFirstAnyValue({ L"Protocol" }));
        appendReportLine(report, L"ExpectedDriverProtocolVersion", kFirstAnyValue({ L"ExpectedProtocol" }));
        appendReportLine(report, L"StatusFlags", kFirstAnyValue({ L"StatusFlags" }));
        std::uint64_t policyMask = 0;
        hexToUInt64(kFirstAnyValue({ L"SecurityPolicy", L"Policy", L"策略" }), policyMask);
        appendReportLine(report, L"SecurityPolicyFlags", kFirstAnyValue({ L"SecurityPolicy", L"Policy", L"策略" }) +
            L" (" + securityPolicyNames(static_cast<std::uint32_t>(policyMask)) + L")");
        std::uint64_t dynStatusFlags = 0;
        hexToUInt64(kFirstAnyValue({ L"DynDataStatus" }), dynStatusFlags);
        appendReportLine(report, L"DynDataStatusFlags", kFirstAnyValue({ L"DynDataStatus" }) +
            L" (" + dynDataStatusFlagsText(static_cast<std::uint32_t>(dynStatusFlags)) + L")");
        std::uint64_t dynCapability = 0;
        hexToUInt64(kFirstAnyValue({ L"DynDataCapability", L"CapabilityMask" }), dynCapability);
        appendReportLine(report, L"DynDataCapabilityMask", kFirstAnyValue({ L"DynDataCapability", L"CapabilityMask" }) +
            L" (" + dynCapabilityNames(dynCapability) + L")");
        appendReportLine(report, L"DynDataStatusQueryOk", kFirstAnyValue({ L"DynDataStatusQueryOk" }));
        appendReportLine(report, L"DynDataFieldsQueryOk", kFirstAnyValue({ L"DynDataFieldsQueryOk" }));
        appendReportLine(report, L"CurrentKernel", kFirstAnyValue({ L"NtosIdentity", L"Ntos" }));
        appendReportLine(report, L"RecognizedVersion", kFirstAnyValue({ L"LocalPdbVersion", L"KernelVersion" }));
        appendReportLine(report, L"LocalPdbProfileMatched", kFirstAnyValue({ L"LocalPdbProfileMatched" }));
        appendReportLine(report, L"LocalPdbProfileName", kFirstAnyValue({ L"LocalPdbProfileName" }));
        appendReportLine(report, L"LocalPdbProfilePath", kFirstAnyValue({ L"LocalPdbProfilePath" }));
        appendReportLine(report, L"LocalPdbProfileMessage", kFirstAnyValue({ L"LocalPdbMessage", L"LocalPdbProfile" }));
        appendReportLine(report, L"ActiveProcessLinksOffset", kFirstAnyValue({ L"ActiveProcessLinksOffset" }));
        appendReportLine(report, L"CallbackProfileCoverage", kFirstAnyValue({ L"CallbackProfileCoverage" }));
        appendReportLine(report, L"PdbProfileActive", kFirstAnyValue({ L"PdbProfileActive" }));
        appendReportLine(report, L"CallbackProfileActive", kFirstAnyValue({ L"CallbackProfileActive" }));
        appendReportLine(report, L"TrustedPdbOffsetsActive", kFirstAnyValue({ L"TrustedPdbOffsetsActive" }));
        appendReportLine(report, L"TrustedOffsetSummary", kFirstAnyValue({ L"TrustedOffset" }));
        appendReportLine(report, L"FieldCoverage", kFirstAnyValue({ L"FieldCoverage" }));
        appendReportLine(report, L"FieldSources", kFirstAnyValue({ L"FieldSources" }));
        appendReportLine(report, L"SystemInformerData", L"version=" + kFirstAnyValue({ L"SI Version" }) +
            L" length=" + kFirstAnyValue({ L"SI Length" }));
        appendReportLine(report, L"MatchedProfile", L"class=" + kFirstAnyValue({ L"MatchedClass" }) +
            L" offset=" + kFirstAnyValue({ L"MatchedProfileOffset" }) +
            L" fieldsId=" + kFirstAnyValue({ L"MatchedFieldsId" }));
        appendReportLine(report, L"DynDataUnavailableReason", kFirstAnyValue({ L"UnavailableReason" }));
        appendReportLine(report, L"DynDataIo", L"Status=" + kFirstAnyValue({ L"DynDataStatusQueryOk" }) +
            L" (" + kFirstAnyValue({ L"DynDataStatusIo" }) + L")；Fields=" +
            kFirstAnyValue({ L"DynDataFieldsQueryOk" }) + L" (" + kFirstAnyValue({ L"DynDataFieldsIo" }) + L")");
        appendReportLine(report, L"LastError", kFirstAnyValue({ L"LastErrorStatus" }) + L" / " +
            kFirstAnyValue({ L"LastError" }) + L" / " + kFirstAnyValue({ L"LastErrorSummary" }));
        appendReportLine(report, L"FeatureCount", L"returned=" + kFirstAnyValue({ L"FeatureReturned" }) +
            L" total=" + kFirstAnyValue({ L"FeatureTotal" }));
        report << L"VisibleCapabilityRows: " << capabilityRows << L"\r\n";
        report << L"UnavailableRows: " << unavailableRows << L"\r\n";
        report << L"DynDataDependentRows: " << dynDataDependentRows << L"\r\n\r\n";
        report << L"Capabilities\r\n";
        report << L"----------------------------------------\r\n";
        kAppendTableHeader(report);
        kAppendTableRows(report);
        return report.str();
    }

    return {};
}

void KernelPage::exportAllRowsTsv() {
    // exportAllRowsTsv captures the visible table text and sends the disk write
    // through the shared file-I/O task so slow folders cannot freeze the dock.
    if (callbackFileIoTask_ && callbackFileIoTask_->running()) {
        ::SetWindowTextW(statusText_, L"状态：文件任务正在后台执行，请等待完成。");
        return;
    }
    wchar_t path[MAX_PATH] = L"kernel_rows.tsv";
    if (const KernelFeatureDescriptor* descriptor = currentDescriptor();
        descriptor != nullptr && descriptor->id == KernelFeatureId::kDeviceDriverObjects) {
        wcscpy_s(path, L"kernel_device_driver_objects.tsv");
    }
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd_;
    ofn.lpstrFilter = L"TSV (*.tsv)\0*.tsv\0Text (*.txt)\0*.txt\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = path;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    ofn.lpstrDefExt = L"tsv";
    if (!::GetSaveFileNameW(&ofn)) {
        return;
    }
    const int kRows = resultList_ ? ListView_GetItemCount(resultList_) : 0;
    const int kColumns = resultList_ ? headerColumnCount(resultList_) : 0;
    const std::vector<int> kCopyColumns = currentCopyColumnIndices();
    std::wstring text;
    for (std::size_t position = 0; position < kCopyColumns.size(); ++position) {
        if (position > 0) {
            text += L'\t';
        }
        const int kColumn = kCopyColumns[position];
        text += kColumn < static_cast<int>(currentColumns_.size())
            ? currentColumns_[static_cast<std::size_t>(kColumn)]
            : std::wstring(L"Column") + std::to_wstring(kColumn);
    }
    for (int row = 0; row < kRows; ++row) {
        text += L"\r\n";
        for (std::size_t position = 0; position < kCopyColumns.size(); ++position) {
            if (position > 0) {
                text += L'\t';
            }
            const int kColumn = kCopyColumns[position];
            if (kColumn < 0 || kColumn >= kColumns) {
                continue;
            }
            text += visibleCellText(row, kColumn);
        }
    }
    startCallbackFileIo(CallbackFileIoOperation::kExportResultTsv, path, std::move(text));
}

const KernelFeatureDescriptor* KernelPage::currentDescriptor() const {
    if (hasDirectFeatureId_) {
        return featureById(directFeatureId_);
    }
    const int kPrimary = currentPrimaryIndex();
    if (kPrimary < 0 || kPrimary >= static_cast<int>(primaryFeatureIds_.size())) {
        return nullptr;
    }
    KernelFeatureId featureId = primaryFeatureIds_[static_cast<std::size_t>(kPrimary)];
    if (!secondaryFeatureIds_.empty()) {
        const int kSecondary = currentSecondaryIndex();
        if (kSecondary >= 0 && kSecondary < static_cast<int>(secondaryFeatureIds_.size())) {
            featureId = secondaryFeatureIds_[static_cast<std::size_t>(kSecondary)];
        }
    }
    return featureById(featureId);
}

const KernelFeatureDescriptor* KernelPage::featureById(const KernelFeatureId featureId) const {
    // featureById resolves one stable feature id into catalog metadata. Input is
    // a KernelFeatureId from the original-tab mapping; output is null only when
    // a future catalog accidentally omits that page.
    const auto kFound = std::find_if(features_.begin(), features_.end(), [featureId](const KernelFeatureDescriptor& descriptor) {
        return descriptor.id == featureId;
    });
    return kFound == features_.end() ? nullptr : &(*kFound);
}

bool KernelPage::currentPrimaryUsesSecondaryTabs() const {
    // A page embedded as a single feature is already hosted by an outer dock;
    // exposing this page's own group tabs would duplicate that navigation.
    if (hasDirectFeatureId_) {
        return false;
    }
    const int kPrimary = currentPrimaryIndex();
    return kPrimary >= 0 &&
        kPrimary < static_cast<int>(primaryFeatureIds_.size()) &&
        !secondaryFeatureIds_.empty();
}

void KernelPage::clearResultGridOnly() {
    // clearResultGridOnly clears only the owner-data result grid. Inputs are
    // the current resultList_ HWND; processing drops the visible row count and
    // column headers but deliberately leaves auxiliary tree/property/summary
    // controls intact for cached tab restoration. It has no return value.
    if (!resultList_) {
        return;
    }
    ListView_SetItemCountEx(resultList_, 0, LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL);
    HWND header = ListView_GetHeader(resultList_);
    const int kCount = header ? Header_GetItemCount(header) : 0;
    for (int index = kCount - 1; index >= 0; --index) {
        ListView_DeleteColumn(resultList_, index);
    }
}

void KernelPage::clearResultTable() {
    // clearResultTable clears the main result grid and all auxiliary views for
    // a real data rebuild. Inputs are owned child HWNDs; processing resets UI
    // state only and never mutates currentRows_; there is no return value.
    clearResultGridOnly();
    if (objectNamespaceTree_) {
        TreeView_DeleteAllItems(objectNamespaceTree_);
    }
    if (propertyList_) {
        ListView_DeleteAllItems(propertyList_);
    }
    if (summaryList_) {
        ListView_DeleteAllItems(summaryList_);
    }
}

void KernelPage::addResultTableColumn(int index, const std::wstring& title, int width) {
    if (!resultList_) {
        return;
    }
    LVCOLUMNW column{};
    column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
    column.fmt = LVCFMT_LEFT;
    column.cx = width;
    column.pszText = const_cast<LPWSTR>(title.c_str());
    ListView_InsertColumn(resultList_, index, &column);
}

void KernelPage::addResultTableRow(const std::vector<std::wstring>& cells) {
    addResultTableRow(cells, 0);
}

void KernelPage::addResultTableRow(const std::vector<std::wstring>& cells, const int indent) {
    // addResultTableRow appends one in-memory row for compatibility with small
    // legacy paths. Inputs are cell text plus optional tree indent; processing
    // never calls Win32 per row, so callers must invoke syncResultListVirtualRows
    // once after batch population; there is no return value.
    if (cells.empty()) {
        return;
    }
    currentRows_.push_back(cells);
    currentRowIndents_.push_back(std::max(0, std::min(indent, 32)));
}

int KernelPage::currentPrimaryIndex() const {
    if (!primaryTab_) {
        return -1;
    }
    return static_cast<int>(::SendMessageW(primaryTab_, TCM_GETCURSEL, 0, 0));
}

int KernelPage::currentSecondaryIndex() const {
    if (!secondaryTab_) {
        return -1;
    }
    return static_cast<int>(::SendMessageW(secondaryTab_, TCM_GETCURSEL, 0, 0));
}

bool KernelPage::currentFeatureUsesVerticalSplitter() const {
    // currentFeatureUsesVerticalSplitter matches the pages that were QSplitter
    // based in the original KernelDock. Inputs are current tab state only;
    // output is true when the result table/detail editor divider is active.
    const KernelFeatureDescriptor* descriptor = currentDescriptor();
    return descriptor != nullptr &&
        (isKernelHookFeature(descriptor->id) || isR0TableDetailFeature(descriptor->id));
}

void KernelPage::moveVerticalSplitterFromMouse(const int mouseY) {
    // moveVerticalSplitterFromMouse updates the table/detail split while the
    // user drags the divider. Input is client-space mouse Y; processing clamps
    // the table height so both panes stay usable; there is no return value.
    if (!currentFeatureUsesVerticalSplitter()) {
        return;
    }
    RECT rc{};
    ::GetClientRect(hwnd_, &rc);
    const int kTabHeight = 28;
    const bool kShowSecondary = currentPrimaryUsesSecondaryTabs();
    const int kContentTop = kTabHeight + (kShowSecondary ? kTabHeight : 0);
    const int kSplitterPanelTop = kContentTop + 28;
    const int kAvailableHeight = std::max(0, height(rc) - kSplitterPanelTop);
    const int kMinimumTableHeight = 88;
    const int kMinimumDetailHeight = 88;
    const int kMaximumTableHeight = std::max(kMinimumTableHeight,
        kAvailableHeight - kMinimumDetailHeight - kKernelSplitterThickness);
    verticalSplitterOffset_ = clampInt(mouseY - kSplitterPanelTop, kMinimumTableHeight, kMaximumTableHeight);
    layout();
}

HWND createKernelPage(HWND parent, const int controlId, const RECT& bounds) {
    auto* page = new KernelPage();
    HWND hwnd = page->create(parent, controlId, bounds);
    if (!hwnd) {
        delete page;
    }
    return hwnd;
}

HWND createKernelPageForFeature(HWND parent, const int controlId, const RECT& bounds, const KernelFeatureId featureId) {
    // createKernelPageForFeature creates a normal kernel page and preselects one
    // feature for embedding under Memory/Driver/Hardware docks. Inputs are
    // parent/control/bounds plus the feature id; output is an owning HWND.
    auto* page = new KernelPage();
    page->setInitialFeature(featureId);
    HWND hwnd = page->create(parent, controlId, bounds);
    if (!hwnd) {
        delete page;
    }
    return hwnd;
}

} // namespace Ksword::Features::Kernel
