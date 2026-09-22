#include "HardwareHwidDispatchView.h"

#include "../audit_common/AuditTable.h"
#include "../../ui/AsyncTask.h"
#include "../../ui/Controls.h"
#include "../../ui/TextFindSupport.h"
#include "../../ui/Theme.h"
#include "../../../../shared/ark_client/ArkDriverClient.h"

#include <commctrl.h>
#include <windowsx.h>

#include <array>
#include <cstdint>
#include <cwchar>
#include <cstring>
#include <iomanip>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

namespace ksword::features::hardware {
namespace {

constexpr wchar_t kHwidDispatchClass[] = L"KswordARKLight.Hardware.HwidDispatchView";
constexpr int kRefreshButtonId = 61201;
constexpr int kDryRunButtonId = 61202;
constexpr int kEnableButtonId = 61203;
constexpr int kDisableAllButtonId = 61204;
constexpr int kCopyPlanButtonId = 61205;
constexpr int kConfirmCheckId = 61206;
constexpr int kDiskCheckId = 61210;
constexpr int kPartMgrCheckId = 61211;
constexpr int kMountMgrCheckId = 61212;
constexpr int kNvidiaCheckId = 61213;
constexpr int kNsiProxyCheckId = 61214;
constexpr int kDiskGuidCheckId = 61220;
constexpr int kVolumeCleanCheckId = 61221;
constexpr int kArpCleanCheckId = 61222;
constexpr int kDiskModeComboId = 61230;
constexpr int kMacModeComboId = 61231;
constexpr int kFirstEditId = 61240;
constexpr int kStatusTextId = 61260;
constexpr int kPlanEditId = 61261;
constexpr int kStatusTableId = 61262;
constexpr UINT kMsgRefreshCompleted = WM_APP + 588;
constexpr UINT kMsgControlCompleted = WM_APP + 589;

enum HwidTextField : std::size_t {
    kDiskSerialField = 0,
    kDiskProductField,
    kDiskRevisionField,
    kGpuSerialField,
    kPermanentMacField,
    kCurrentMacField,
    kHwidTextFieldCount
};

struct HwidDispatchViewState {
    HWND hwnd = nullptr;
    HWND refreshButton = nullptr;
    HWND dryRunButton = nullptr;
    HWND enableButton = nullptr;
    HWND disableAllButton = nullptr;
    HWND copyPlanButton = nullptr;
    HWND confirmCheck = nullptr;
    HWND diskCheck = nullptr;
    HWND partMgrCheck = nullptr;
    HWND mountMgrCheck = nullptr;
    HWND nvidiaCheck = nullptr;
    HWND nsiProxyCheck = nullptr;
    HWND diskGuidCheck = nullptr;
    HWND volumeCleanCheck = nullptr;
    HWND arpCleanCheck = nullptr;
    HWND diskModeCombo = nullptr;
    HWND macModeCombo = nullptr;
    HWND statusText = nullptr;
    HWND planEdit = nullptr;
    HWND statusTable = nullptr;
    std::array<HWND, kHwidTextFieldCount> labels{};
    std::array<HWND, kHwidTextFieldCount> edits{};
    std::wstring logText;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<ksword::ark::HwidDispatchResult>> refreshTask;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<ksword::ark::HwidDispatchResult>> controlTask;
    bool controlInProgress = false;
};

int width(const RECT& rc) {
    return rc.right > rc.left ? rc.right - rc.left : 0;
}

int height(const RECT& rc) {
    return rc.bottom > rc.top ? rc.bottom - rc.top : 0;
}

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

std::wstring hex32(const long value) {
    std::wostringstream stream;
    stream << L"0x" << std::uppercase << std::hex << std::setw(8) << std::setfill(L'0')
           << static_cast<std::uint32_t>(value);
    return stream.str();
}

std::wstring hex64(const unsigned long long value) {
    std::wostringstream stream;
    stream << L"0x" << std::uppercase << std::hex << value;
    return stream.str();
}

std::wstring fixedWide(const wchar_t* text, const std::size_t maxChars) {
    if (!text || maxChars == 0U) {
        return {};
    }
    std::size_t length = 0;
    while (length < maxChars && text[length] != L'\0') {
        ++length;
    }
    return std::wstring(text, text + length);
}

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

void copyTextToWideField(const std::wstring& text, wchar_t* target, const std::size_t targetChars) {
    if (!target || targetChars == 0U) {
        return;
    }
    target[0] = L'\0';
    if (!text.empty()) {
        ::wcsncpy_s(target, targetChars, text.c_str(), _TRUNCATE);
    }
}

bool writeClipboardText(HWND owner, const std::wstring& text) {
    if (text.empty() || !::OpenClipboard(owner)) {
        return false;
    }
    const SIZE_T kBytes = (text.size() + 1U) * sizeof(wchar_t);
    HGLOBAL memory = ::GlobalAlloc(GMEM_MOVEABLE, kBytes);
    if (!memory) {
        ::CloseClipboard();
        return false;
    }
    void* target = ::GlobalLock(memory);
    if (!target) {
        ::GlobalFree(memory);
        ::CloseClipboard();
        return false;
    }
    std::memcpy(target, text.c_str(), kBytes);
    ::GlobalUnlock(memory);
    ::EmptyClipboard();
    if (!::SetClipboardData(CF_UNICODETEXT, memory)) {
        ::GlobalFree(memory);
        ::CloseClipboard();
        return false;
    }
    ::CloseClipboard();
    return true;
}

HWND createCheck(HWND parent, int id, const wchar_t* text, bool checked) {
    HWND hwnd = ::CreateWindowExW(
        0,
        L"BUTTON",
        text,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
        0,
        0,
        0,
        0,
        parent,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    if (hwnd) {
        ::SendMessageW(hwnd, WM_SETFONT, reinterpret_cast<WPARAM>(ksword::ui::systemUiFont()), TRUE);
        Button_SetCheck(hwnd, checked ? BST_CHECKED : BST_UNCHECKED);
    }
    return hwnd;
}

HWND createEdit(HWND parent, int id) {
    HWND hwnd = ::CreateWindowExW(
        WS_EX_CLIENTEDGE,
        L"EDIT",
        L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        0,
        0,
        0,
        0,
        parent,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    if (hwnd) {
        ::SendMessageW(hwnd, WM_SETFONT, reinterpret_cast<WPARAM>(ksword::ui::systemUiFont()), TRUE);
    }
    return hwnd;
}

void addComboItem(HWND combo, const wchar_t* text, unsigned long value) {
    const LRESULT kIndex = ::SendMessageW(combo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(text));
    if (kIndex >= 0) {
        ::SendMessageW(combo, CB_SETITEMDATA, static_cast<WPARAM>(kIndex), static_cast<LPARAM>(value));
    }
}

unsigned long comboData(HWND combo, unsigned long fallback) {
    if (!combo) {
        return fallback;
    }
    const LRESULT kIndex = ::SendMessageW(combo, CB_GETCURSEL, 0, 0);
    if (kIndex < 0) {
        return fallback;
    }
    const LRESULT kData = ::SendMessageW(combo, CB_GETITEMDATA, static_cast<WPARAM>(kIndex), 0);
    return kData == CB_ERR ? fallback : static_cast<unsigned long>(kData);
}

const wchar_t* targetNameFromFlag(const unsigned long targetFlag) {
    switch (targetFlag) {
    case KSWORD_ARK_HWID_DISPATCH_TARGET_DISK: return L"\\Driver\\Disk";
    case KSWORD_ARK_HWID_DISPATCH_TARGET_PARTMGR: return L"\\Driver\\partmgr";
    case KSWORD_ARK_HWID_DISPATCH_TARGET_MOUNTMGR: return L"\\Driver\\mountmgr";
    case KSWORD_ARK_HWID_DISPATCH_TARGET_NVIDIA: return L"\\Driver\\nvlddmkm";
    case KSWORD_ARK_HWID_DISPATCH_TARGET_NSIPROXY: return L"\\Driver\\nsiproxy";
    default: return L"<unknown>";
    }
}

const wchar_t* overallStatusText(const unsigned long status) {
    switch (status) {
    case KSWORD_ARK_HWID_DISPATCH_STATUS_READY: return L"Ready";
    case KSWORD_ARK_HWID_DISPATCH_STATUS_ACTIVE: return L"Active";
    case KSWORD_ARK_HWID_DISPATCH_STATUS_PARTIAL: return L"Partial";
    case KSWORD_ARK_HWID_DISPATCH_STATUS_UNSUPPORTED: return L"Unsupported";
    case KSWORD_ARK_HWID_DISPATCH_STATUS_DENIED: return L"Denied";
    case KSWORD_ARK_HWID_DISPATCH_STATUS_FAILED: return L"Failed";
    default: return L"Unknown";
    }
}

bool checked(HWND hwnd) {
    return hwnd && Button_GetCheck(hwnd) == BST_CHECKED;
}

unsigned long selectedTargetFlags(const HwidDispatchViewState& state) {
    unsigned long flags = 0UL;
    flags |= checked(state.diskCheck) ? KSWORD_ARK_HWID_DISPATCH_TARGET_DISK : 0UL;
    flags |= checked(state.partMgrCheck) ? KSWORD_ARK_HWID_DISPATCH_TARGET_PARTMGR : 0UL;
    flags |= checked(state.mountMgrCheck) ? KSWORD_ARK_HWID_DISPATCH_TARGET_MOUNTMGR : 0UL;
    flags |= checked(state.nvidiaCheck) ? KSWORD_ARK_HWID_DISPATCH_TARGET_NVIDIA : 0UL;
    flags |= checked(state.nsiProxyCheck) ? KSWORD_ARK_HWID_DISPATCH_TARGET_NSIPROXY : 0UL;
    return flags;
}

std::wstring buildPlanText(const HwidDispatchViewState& state) {
    std::wostringstream stream;
    stream << L"HWID Dispatch 派遣函数接入计划\r\n"
           << L"来源: FiYHer/EASY-HWID-SPOOFER dispatch-only 方案\r\n"
           << L"目标 flags: 0x" << std::hex << std::uppercase << std::setw(8) << std::setfill(L'0') << selectedTargetFlags(state) << std::dec << L"\r\n"
           << L"- \\Driver\\Disk: " << (checked(state.diskCheck) ? L"启用" : L"跳过") << L"\r\n"
           << L"- \\Driver\\partmgr: " << (checked(state.partMgrCheck) ? L"启用" : L"跳过") << L"\r\n"
           << L"- \\Driver\\mountmgr: " << (checked(state.mountMgrCheck) ? L"启用" : L"跳过") << L"\r\n"
           << L"- \\Driver\\nvlddmkm: " << (checked(state.nvidiaCheck) ? L"启用" : L"跳过") << L"\r\n"
           << L"- \\Driver\\nsiproxy: " << (checked(state.nsiProxyCheck) ? L"启用" : L"跳过") << L"\r\n"
           << L"磁盘模式: " << comboData(state.diskModeCombo, KSWORD_ARK_HWID_DISPATCH_DISK_MODE_CUSTOM) << L"\r\n"
           << L"MAC 模式(预留): " << comboData(state.macModeCombo, KSWORD_ARK_HWID_DISPATCH_MAC_MODE_RANDOM) << L"\r\n"
           << L"磁盘序列号: " << textFromWindow(state.edits[kDiskSerialField]) << L"\r\n"
           << L"磁盘产品名: " << textFromWindow(state.edits[kDiskProductField]) << L"\r\n"
           << L"磁盘固件值: " << textFromWindow(state.edits[kDiskRevisionField]) << L"\r\n"
           << L"GPU 序列号: " << textFromWindow(state.edits[kGpuSerialField]) << L"\r\n"
           << L"永久 MAC: " << textFromWindow(state.edits[kPermanentMacField]) << L"\r\n"
           << L"当前 MAC: " << textFromWindow(state.edits[kCurrentMacField]) << L"\r\n"
           << L"GPT GUID 随机化: " << (checked(state.diskGuidCheck) ? L"是" : L"否") << L"\r\n"
           << L"卷唯一标识清理: " << (checked(state.volumeCleanCheck) ? L"是" : L"否") << L"\r\n"
           << L"ARP Table 清理: " << (checked(state.arpCleanCheck) ? L"是" : L"否") << L"\r\n"
           << L"风险: 启用/卸载 Dispatch hook 可能蓝屏；真实操作需要勾选确认并二次确认。";
    if (!state.logText.empty()) {
        stream << L"\r\n\r\n--- 日志 ---\r\n" << state.logText;
    }
    return stream.str();
}

void updatePlanText(HwidDispatchViewState& state) {
    if (state.planEdit) {
        const std::wstring kPlan = buildPlanText(state);
        ::SetWindowTextW(state.planEdit, kPlan.c_str());
    }
}

void appendLog(HwidDispatchViewState& state, const std::wstring& line) {
    if (!state.logText.empty()) {
        state.logText += L"\r\n";
    }
    state.logText += line;
    updatePlanText(state);
}

KSWORD_ARK_HWID_DISPATCH_CONTROL_REQUEST buildControlRequest(
    const HwidDispatchViewState& state,
    const unsigned long action,
    const bool dryRun) {
    KSWORD_ARK_HWID_DISPATCH_CONTROL_REQUEST request{};
    request.size = sizeof(request);
    request.version = KSWORD_ARK_HWID_DISPATCH_PROTOCOL_VERSION;
    request.action = action;
    request.requestFlags = KSWORD_ARK_HWID_DISPATCH_REQUEST_FLAG_UI_CONFIRMED;
    if (dryRun) {
        request.requestFlags |= KSWORD_ARK_HWID_DISPATCH_REQUEST_FLAG_DRY_RUN;
    }
    request.profile.size = sizeof(request.profile);
    request.profile.version = KSWORD_ARK_HWID_DISPATCH_PROTOCOL_VERSION;
    request.profile.targetFlags = selectedTargetFlags(state);
    request.profile.diskMode = comboData(state.diskModeCombo, KSWORD_ARK_HWID_DISPATCH_DISK_MODE_CUSTOM);
    request.profile.macMode = comboData(state.macModeCombo, KSWORD_ARK_HWID_DISPATCH_MAC_MODE_RANDOM);
    request.profile.behaviorFlags =
        (checked(state.diskGuidCheck) ? KSWORD_ARK_HWID_DISPATCH_FLAG_DISK_GUID_RANDOM : 0UL) |
        (checked(state.volumeCleanCheck) ? KSWORD_ARK_HWID_DISPATCH_FLAG_VOLUME_ID_CLEAN : 0UL) |
        (checked(state.arpCleanCheck) ? KSWORD_ARK_HWID_DISPATCH_FLAG_ARP_TABLE_CLEAN : 0UL);
    copyTextToWideField(textFromWindow(state.edits[kDiskSerialField]), request.profile.diskSerial, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS);
    copyTextToWideField(textFromWindow(state.edits[kDiskProductField]), request.profile.diskProduct, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS);
    copyTextToWideField(textFromWindow(state.edits[kDiskRevisionField]), request.profile.diskRevision, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS);
    copyTextToWideField(textFromWindow(state.edits[kGpuSerialField]), request.profile.gpuSerial, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS);
    copyTextToWideField(textFromWindow(state.edits[kPermanentMacField]), request.profile.permanentMac, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS);
    copyTextToWideField(textFromWindow(state.edits[kCurrentMacField]), request.profile.currentMac, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS);
    return request;
}

void applyResponseToUi(HwidDispatchViewState& state, const ksword::ark::HwidDispatchResult& result) {
    if (state.statusText) {
        std::wostringstream status;
        status << L"状态：" << (result.unsupported ? L"驱动未注册 HWID Dispatch IOCTL" : (result.io.ok ? L"IOCTL 成功" : L"IOCTL 失败"))
               << L"，Overall=" << overallStatusText(result.response.overallStatus)
               << L"，Win32=" << result.io.win32Error
               << L"，NT=" << hex32(result.response.lastStatus)
               << L"，Active=0x" << std::hex << std::uppercase << result.response.activeTargetFlags;
        ::SetWindowTextW(state.statusText, status.str().c_str());
    }

    std::vector<std::vector<std::wstring>> rows;
    rows.reserve(KSWORD_ARK_HWID_DISPATCH_ENTRY_COUNT);
    for (std::size_t index = 0; index < KSWORD_ARK_HWID_DISPATCH_ENTRY_COUNT; ++index) {
        const KSWORD_ARK_HWID_DISPATCH_ENTRY& entry = result.response.entries[index];
        rows.push_back({
            targetNameFromFlag(entry.targetFlag),
            fixedWide(entry.driverName, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS),
            entry.active != 0UL ? L"是" : L"否",
            hex32(entry.lastStatus),
            hex64(entry.driverObjectAddress),
            hex64(entry.originalDispatchAddress),
            hex64(entry.currentDispatchAddress)
        });
    }
    ksword::features::audit_common::replaceAuditTableRows(state.statusTable, rows);
    appendLog(state, utf8ToWide(result.io.message));
}

void setDispatchControlsEnabled(HwidDispatchViewState& state, bool enabled) {
    for (HWND control : { state.refreshButton, state.dryRunButton, state.enableButton, state.disableAllButton }) {
        if (control) {
            ::EnableWindow(control, enabled);
        }
    }
}

void refreshDispatchState(HwidDispatchViewState& state) {
    if (!state.refreshTask) {
        return;
    }
    if (state.statusText) {
        ::SetWindowTextW(state.statusText, state.refreshTask->running() ? L"状态：HWID Dispatch 查询已排队。" : L"状态：正在后台查询 HWID Dispatch。 ");
    }
    ::EnableWindow(state.refreshButton, FALSE);
    state.refreshTask->request(
        [] {
            const ksword::ark::DriverClient kClient;
            return kClient.queryHwidDispatchState();
        },
        [&state](std::uint64_t, std::optional<ksword::ark::HwidDispatchResult>&& result, std::exception_ptr error) {
            ::EnableWindow(state.refreshButton, TRUE);
            if (error || !result.has_value()) {
                appendLog(state, L"HWID Dispatch 后台查询异常结束。");
                return;
            }
            applyResponseToUi(state, *result);
        });
}

void sendControlRequest(HwidDispatchViewState& state, const unsigned long action, const bool dryRun) {
    if (state.refreshTask && state.refreshTask->running()) {
        appendLog(state, L"HWID Dispatch 状态查询尚未完成，请稍后再执行操作。");
        return;
    }
    if (!dryRun && !checked(state.confirmCheck)) {
        ::MessageBoxW(
            state.hwnd,
            L"真实启用/卸载 Dispatch hook 前必须勾选风险确认。",
            L"HWID Dispatch",
            MB_OK | MB_ICONWARNING);
        return;
    }
    if (!dryRun) {
        const int kAnswer = ::MessageBoxW(
            state.hwnd,
            L"即将修改或恢复内核驱动 MajorFunction 派遣函数，可能立即蓝屏。是否继续？",
            L"确认 HWID Dispatch 真实操作",
            MB_YESNO | MB_DEFBUTTON2 | MB_ICONWARNING);
        if (kAnswer != IDYES) {
            appendLog(state, L"用户取消真实 Dispatch 操作。");
            return;
        }
    }

    const KSWORD_ARK_HWID_DISPATCH_CONTROL_REQUEST kRequest = buildControlRequest(state, action, dryRun);
    if (!state.controlTask || state.controlInProgress) {
        appendLog(state, L"HWID Dispatch 操作正在执行。");
        return;
    }
    state.controlInProgress = true;
    setDispatchControlsEnabled(state, false);
    if (state.statusText) {
        ::SetWindowTextW(state.statusText, L"状态：正在后台执行 HWID Dispatch 操作…");
    }
    state.controlTask->request(
        [kRequest] {
            const ksword::ark::DriverClient kClient;
            return kClient.controlHwidDispatch(kRequest);
        },
        [&state](std::uint64_t, std::optional<ksword::ark::HwidDispatchResult>&& result, std::exception_ptr error) {
            state.controlInProgress = false;
            setDispatchControlsEnabled(state, true);
            if (error || !result.has_value()) {
                appendLog(state, L"HWID Dispatch 操作异常结束。");
                return;
            }
            applyResponseToUi(state, *result);
        });
}

bool createChildControls(HwidDispatchViewState& state) {
    state.refreshButton = ksword::ui::createButton(state.hwnd, kRefreshButtonId, L"查询状态", 0, 0, 0, 0);
    state.dryRunButton = ksword::ui::createButton(state.hwnd, kDryRunButtonId, L"干跑验证", 0, 0, 0, 0);
    state.enableButton = ksword::ui::createButton(state.hwnd, kEnableButtonId, L"启用派遣函数", 0, 0, 0, 0);
    state.disableAllButton = ksword::ui::createButton(state.hwnd, kDisableAllButtonId, L"卸载全部", 0, 0, 0, 0);
    state.copyPlanButton = ksword::ui::createButton(state.hwnd, kCopyPlanButtonId, L"复制计划", 0, 0, 0, 0);
    state.confirmCheck = createCheck(state.hwnd, kConfirmCheckId, L"我已确认真实 Dispatch hook 操作可能蓝屏，已准备恢复方案。", false);
    state.diskCheck = createCheck(state.hwnd, kDiskCheckId, L"\\Driver\\Disk", true);
    state.partMgrCheck = createCheck(state.hwnd, kPartMgrCheckId, L"\\Driver\\partmgr", true);
    state.mountMgrCheck = createCheck(state.hwnd, kMountMgrCheckId, L"\\Driver\\mountmgr", true);
    state.nvidiaCheck = createCheck(state.hwnd, kNvidiaCheckId, L"\\Driver\\nvlddmkm", false);
    state.nsiProxyCheck = createCheck(state.hwnd, kNsiProxyCheckId, L"\\Driver\\nsiproxy", false);
    state.diskGuidCheck = createCheck(state.hwnd, kDiskGuidCheckId, L"随机化 GPT GUID 查询结果", false);
    state.volumeCleanCheck = createCheck(state.hwnd, kVolumeCleanCheckId, L"清理 MountMgr 卷唯一标识查询结果", false);
    state.arpCleanCheck = createCheck(state.hwnd, kArpCleanCheckId, L"清理 ARP Table 查询结果", false);

    state.diskModeCombo = ::CreateWindowExW(0, WC_COMBOBOXW, L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST,
        0, 0, 0, 0, state.hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kDiskModeComboId)), ::GetModuleHandleW(nullptr), nullptr);
    state.macModeCombo = ::CreateWindowExW(0, WC_COMBOBOXW, L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST,
        0, 0, 0, 0, state.hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kMacModeComboId)), ::GetModuleHandleW(nullptr), nullptr);
    if (state.diskModeCombo) {
        ::SendMessageW(state.diskModeCombo, WM_SETFONT, reinterpret_cast<WPARAM>(ksword::ui::systemUiFont()), TRUE);
        addComboItem(state.diskModeCombo, L"自定义序列号/产品/固件", KSWORD_ARK_HWID_DISPATCH_DISK_MODE_CUSTOM);
        addComboItem(state.diskModeCombo, L"随机化序列号", KSWORD_ARK_HWID_DISPATCH_DISK_MODE_RANDOM);
        addComboItem(state.diskModeCombo, L"清空序列号", KSWORD_ARK_HWID_DISPATCH_DISK_MODE_NULL);
        ::SendMessageW(state.diskModeCombo, CB_SETCURSEL, 0, 0);
    }
    if (state.macModeCombo) {
        ::SendMessageW(state.macModeCombo, WM_SETFONT, reinterpret_cast<WPARAM>(ksword::ui::systemUiFont()), TRUE);
        addComboItem(state.macModeCombo, L"随机化物理 MAC(预留)", KSWORD_ARK_HWID_DISPATCH_MAC_MODE_RANDOM);
        addComboItem(state.macModeCombo, L"自定义物理 MAC(预留)", KSWORD_ARK_HWID_DISPATCH_MAC_MODE_CUSTOM);
        ::SendMessageW(state.macModeCombo, CB_SETCURSEL, 0, 0);
    }

    const std::array<const wchar_t*, kHwidTextFieldCount> kLabelTexts{
        L"磁盘序列号",
        L"磁盘产品名",
        L"磁盘固件值",
        L"GPU 序列号",
        L"永久 MAC",
        L"当前 MAC"
    };
    for (std::size_t index = 0; index < kHwidTextFieldCount; ++index) {
        state.labels[index] = ksword::ui::createText(state.hwnd, kFirstEditId + static_cast<int>(index) + 100, kLabelTexts[index], 0, 0, 0, 0);
        state.edits[index] = createEdit(state.hwnd, kFirstEditId + static_cast<int>(index));
    }

    state.statusText = ksword::ui::createText(state.hwnd, kStatusTextId, L"状态：等待查询。", 0, 0, 0, 0);
    state.planEdit = ::CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL,
        0, 0, 0, 0, state.hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kPlanEditId)), ::GetModuleHandleW(nullptr), nullptr);
    if (state.planEdit) {
        ::SendMessageW(state.planEdit, WM_SETFONT, reinterpret_cast<WPARAM>(ksword::ui::systemUiFont()), TRUE);
        ksword::ui::attachTextFindSupport(state.planEdit);
    }
    RECT tableBounds{ 0, 0, 100, 100 };
    state.statusTable = ksword::features::audit_common::createReadOnlyAuditTable(
        state.hwnd,
        kStatusTableId,
        tableBounds,
        {
            { L"目标", 150, LVCFMT_LEFT },
            { L"驱动对象", 190, LVCFMT_LEFT },
            { L"Active", 70, LVCFMT_LEFT },
            { L"LastStatus", 110, LVCFMT_LEFT },
            { L"DriverObject", 150, LVCFMT_LEFT },
            { L"OriginalDispatch", 150, LVCFMT_LEFT },
            { L"CurrentDispatch", 150, LVCFMT_LEFT },
        });

    const bool kOk = state.refreshButton && state.dryRunButton && state.enableButton &&
        state.disableAllButton && state.copyPlanButton && state.confirmCheck &&
        state.diskCheck && state.partMgrCheck && state.mountMgrCheck &&
        state.nvidiaCheck && state.nsiProxyCheck && state.diskGuidCheck &&
        state.volumeCleanCheck && state.arpCleanCheck && state.diskModeCombo &&
        state.macModeCombo && state.statusText && state.planEdit && state.statusTable;
    if (kOk) {
        updatePlanText(state);
    }
    return kOk;
}

void layoutChildren(HwidDispatchViewState& state) {
    RECT rc{};
    ::GetClientRect(state.hwnd, &rc);
    const int kWidth = width(rc);
    const int kHeight = height(rc);
    const int kMargin = 8;
    const int kGap = 6;
    const int kButtonH = 26;
    int x = kMargin;
    auto moveNextButton = [&](HWND hwnd, int buttonW) {
        ::MoveWindow(hwnd, x, kMargin, buttonW, kButtonH, TRUE);
        x += buttonW + kGap;
    };
    moveNextButton(state.refreshButton, 86);
    moveNextButton(state.dryRunButton, 86);
    moveNextButton(state.enableButton, 110);
    moveNextButton(state.disableAllButton, 94);
    moveNextButton(state.copyPlanButton, 86);
    ::MoveWindow(state.statusText, x, kMargin + 3, std::max(80, kWidth - x - kMargin), 22, TRUE);

    const int kPlanW = kWidth >= 980 ? 380 : 0;
    const int kLeftW = kPlanW > 0 ? std::max(320, kWidth - kPlanW - kMargin * 3) : std::max(320, kWidth - kMargin * 2);
    ::MoveWindow(state.confirmCheck, kMargin, 40, kLeftW, 22, TRUE);

    int y = 66;
    const int kCheckW = 150;
    ::MoveWindow(state.diskCheck, kMargin, y, kCheckW, 22, TRUE);
    ::MoveWindow(state.partMgrCheck, kMargin + kCheckW, y, kCheckW, 22, TRUE);
    ::MoveWindow(state.mountMgrCheck, kMargin + kCheckW * 2, y, kCheckW, 22, TRUE);
    ::MoveWindow(state.nvidiaCheck, kMargin, y + 24, kCheckW, 22, TRUE);
    ::MoveWindow(state.nsiProxyCheck, kMargin + kCheckW, y + 24, kCheckW, 22, TRUE);

    y = 116;
    const int kLabelW = 84;
    const int kEditW = std::max(110, (kLeftW - kLabelW * 2 - kGap * 5) / 2);
    const int kCol1 = kMargin;
    const int kCol2 = kMargin + kLabelW + kEditW + kGap * 3;
    ::MoveWindow(state.labels[kDiskSerialField], kCol1, y, kLabelW, 22, TRUE);
    ::MoveWindow(state.edits[kDiskSerialField], kCol1 + kLabelW, y, kEditW, 22, TRUE);
    ::MoveWindow(state.labels[kGpuSerialField], kCol2, y, kLabelW, 22, TRUE);
    ::MoveWindow(state.edits[kGpuSerialField], kCol2 + kLabelW, y, kEditW, 22, TRUE);
    y += 26;
    ::MoveWindow(state.labels[kDiskProductField], kCol1, y, kLabelW, 22, TRUE);
    ::MoveWindow(state.edits[kDiskProductField], kCol1 + kLabelW, y, kEditW, 22, TRUE);
    ::MoveWindow(state.labels[kPermanentMacField], kCol2, y, kLabelW, 22, TRUE);
    ::MoveWindow(state.edits[kPermanentMacField], kCol2 + kLabelW, y, kEditW, 22, TRUE);
    y += 26;
    ::MoveWindow(state.labels[kDiskRevisionField], kCol1, y, kLabelW, 22, TRUE);
    ::MoveWindow(state.edits[kDiskRevisionField], kCol1 + kLabelW, y, kEditW, 22, TRUE);
    ::MoveWindow(state.labels[kCurrentMacField], kCol2, y, kLabelW, 22, TRUE);
    ::MoveWindow(state.edits[kCurrentMacField], kCol2 + kLabelW, y, kEditW, 22, TRUE);
    y += 28;
    ::MoveWindow(state.diskModeCombo, kCol1, y, kLabelW + kEditW, 120, TRUE);
    ::MoveWindow(state.macModeCombo, kCol2, y, kLabelW + kEditW, 120, TRUE);
    y += 28;
    ::MoveWindow(state.diskGuidCheck, kMargin, y, 210, 22, TRUE);
    ::MoveWindow(state.volumeCleanCheck, kMargin + 215, y, 250, 22, TRUE);
    ::MoveWindow(state.arpCleanCheck, kMargin + 470, y, 180, 22, TRUE);

    const int kTopH = 226;
    if (kPlanW > 0) {
        ::MoveWindow(state.planEdit, kWidth - kPlanW - kMargin, 40, kPlanW, kTopH - 48, TRUE);
    } else {
        ::MoveWindow(state.planEdit, kMargin, kTopH, kWidth - kMargin * 2, 1, TRUE);
    }
    ::MoveWindow(state.statusTable, kMargin, kTopH, std::max(80, kWidth - kMargin * 2), std::max(80, kHeight - kTopH - kMargin), TRUE);
}

HwidDispatchViewState* stateFromWindow(HWND hwnd) {
    return reinterpret_cast<HwidDispatchViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

bool registerHwidDispatchClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW wc{};
    wc.lpfnWndProc = [](HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) -> LRESULT {
        HwidDispatchViewState* state = stateFromWindow(hwnd);
        if (msg == WM_NCCREATE) {
            const auto* create = reinterpret_cast<CREATESTRUCTW*>(lParam);
            state = create ? static_cast<HwidDispatchViewState*>(create->lpCreateParams) : nullptr;
            if (state) {
                state->hwnd = hwnd;
                ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
            }
        }
        switch (msg) {
        case WM_CREATE:
            if (state) {
                if (!createChildControls(*state)) {
                    delete state;
                    ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                    return -1;
                }
                state->refreshTask = std::make_unique<ksword::ui::AsyncSnapshotTask<ksword::ark::HwidDispatchResult>>(hwnd, kMsgRefreshCompleted);
                state->controlTask = std::make_unique<ksword::ui::AsyncSnapshotTask<ksword::ark::HwidDispatchResult>>(hwnd, kMsgControlCompleted);
                layoutChildren(*state);
                refreshDispatchState(*state);
            }
            return 0;
        case WM_SIZE:
            if (state) {
                layoutChildren(*state);
            }
            return 0;
        case kMsgRefreshCompleted:
            if (state && state->refreshTask && state->refreshTask->consume(hwnd, wParam, lParam)) {
                return 0;
            }
            break;
        case kMsgControlCompleted:
            if (state && state->controlTask && state->controlTask->consume(hwnd, wParam, lParam)) {
                return 0;
            }
            break;
        case WM_COMMAND:
            if (state) {
                switch (LOWORD(wParam)) {
                case kRefreshButtonId:
                    refreshDispatchState(*state);
                    return 0;
                case kDryRunButtonId:
                    sendControlRequest(*state, KSWORD_ARK_HWID_DISPATCH_ACTION_ENABLE, true);
                    return 0;
                case kEnableButtonId:
                    sendControlRequest(*state, KSWORD_ARK_HWID_DISPATCH_ACTION_ENABLE, false);
                    return 0;
                case kDisableAllButtonId:
                    sendControlRequest(*state, KSWORD_ARK_HWID_DISPATCH_ACTION_DISABLE_ALL, false);
                    return 0;
                case kCopyPlanButtonId:
                    appendLog(*state, writeClipboardText(hwnd, buildPlanText(*state)) ? L"已复制 HWID Dispatch 计划。" : L"复制 HWID Dispatch 计划失败。");
                    return 0;
                default:
                    if ((HIWORD(wParam) == EN_CHANGE && LOWORD(wParam) >= kFirstEditId && LOWORD(wParam) < kFirstEditId + static_cast<int>(kHwidTextFieldCount)) ||
                        HIWORD(wParam) == CBN_SELCHANGE ||
                        HIWORD(wParam) == BN_CLICKED) {
                        updatePlanText(*state);
                    }
                    break;
                }
            }
            break;
        case WM_NOTIFY: {
            const auto* header = reinterpret_cast<const NMHDR*>(lParam);
            if (state && header && header->hwndFrom == state->statusTable && header->code == NM_RCLICK) {
                POINT pt{};
                ::GetCursorPos(&pt);
                ksword::features::audit_common::showAuditTableContextMenu(state->hwnd, state->statusTable, pt);
                return 0;
            }
            break;
        }
        case WM_CONTEXTMENU:
            if (state && reinterpret_cast<HWND>(wParam) == state->statusTable) {
                POINT pt{ GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
                if (pt.x == -1 && pt.y == -1) {
                    RECT rc{};
                    ::GetWindowRect(state->statusTable, &rc);
                    pt.x = rc.left + 24;
                    pt.y = rc.top + 24;
                }
                ksword::features::audit_common::showAuditTableContextMenu(state->hwnd, state->statusTable, pt);
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
            if (state) {
                if (state->refreshTask) state->refreshTask->cancel();
                if (state->controlTask) state->controlTask->cancel();
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
    wc.lpszClassName = kHwidDispatchClass;
    if (::RegisterClassW(&wc) || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS) {
        registered = true;
    }
    return registered;
}

} // namespace

HWND createHardwareHwidDispatchView(HWND parent, const RECT& bounds) {
    if (!parent || !registerHwidDispatchClass()) {
        return nullptr;
    }
    auto* state = new HwidDispatchViewState();
    HWND hwnd = ::CreateWindowExW(
        0,
        kHwidDispatchClass,
        L"HWID Dispatch",
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

} // namespace Ksword::Features::Hardware
