#include "ProcessDetailPage.h"

#include <sddl.h>
#include <winternl.h>

#include <algorithm>
#include <array>
#include <cwctype>
#include <iomanip>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace ksword::features::process_detail {
namespace {

using NtSetInformationTokenFn = NTSTATUS(NTAPI*)(HANDLE, TOKEN_INFORMATION_CLASS, PVOID, ULONG);

class ScopedHandle final {
public:
    explicit ScopedHandle(HANDLE value = nullptr) : value_(value) {}
    ~ScopedHandle() { if (value_) { ::CloseHandle(value_); } }
    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;
    HANDLE get() const { return value_; }
    explicit operator bool() const { return value_ != nullptr; }
private:
    HANDLE value_ = nullptr;
};

constexpr std::array<const wchar_t*, 51> kTokenClassNames{
    L"TokenUser", L"TokenGroups", L"TokenPrivileges", L"TokenOwner", L"TokenPrimaryGroup",
    L"TokenDefaultDacl", L"TokenSource", L"TokenType", L"TokenImpersonationLevel", L"TokenStatistics",
    L"TokenRestrictedSids", L"TokenSessionId", L"TokenGroupsAndPrivileges", L"TokenSessionReference",
    L"TokenSandBoxInert", L"TokenAuditPolicy", L"TokenOrigin", L"TokenElevationType", L"TokenLinkedToken",
    L"TokenElevation", L"TokenHasRestrictions", L"TokenAccessInformation", L"TokenVirtualizationAllowed",
    L"TokenVirtualizationEnabled", L"TokenIntegrityLevel", L"TokenUIAccess", L"TokenMandatoryPolicy",
    L"TokenLogonSid", L"TokenIsAppContainer", L"TokenCapabilities", L"TokenAppContainerSid",
    L"TokenAppContainerNumber", L"TokenUserClaimAttributes", L"TokenDeviceClaimAttributes",
    L"TokenRestrictedUserClaimAttributes", L"TokenRestrictedDeviceClaimAttributes", L"TokenDeviceGroups",
    L"TokenRestrictedDeviceGroups", L"TokenSecurityAttributes", L"TokenIsRestricted", L"TokenProcessTrustLevel",
    L"TokenPrivateNameSpace", L"TokenSingletonAttributes", L"TokenBnoIsolation", L"TokenChildProcessFlags",
    L"TokenIsLessPrivilegedAppContainer", L"TokenIsSandboxed", L"TokenOriginatingProcessTrustLevel",
    L"TokenLoggingInformation", L"TokenLearningMode", L"TokenIsAppSilo"
};

std::wstring tokenClassName(int informationClass) {
    if (informationClass >= 1 && informationClass <= static_cast<int>(kTokenClassNames.size())) {
        return kTokenClassNames[static_cast<std::size_t>(informationClass - 1)];
    }
    return L"TokenClass" + std::to_wstring(informationClass);
}

void addComboText(HWND combo, const std::wstring& text, LPARAM data) {
    const LRESULT kIndex = ::SendMessageW(combo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(text.c_str()));
    if (kIndex >= 0) {
        ::SendMessageW(combo, CB_SETITEMDATA, static_cast<WPARAM>(kIndex), data);
    }
}

std::wstring sidText(PSID sid) {
    if (!sid) {
        return L"<null sid>";
    }
    LPWSTR rawSid = nullptr;
    std::wstring sidValue;
    if (::ConvertSidToStringSidW(sid, &rawSid) && rawSid) {
        sidValue = rawSid;
        ::LocalFree(rawSid);
    }
    wchar_t name[256]{};
    wchar_t domain[256]{};
    DWORD nameLength = static_cast<DWORD>(std::size(name));
    DWORD domainLength = static_cast<DWORD>(std::size(domain));
    SID_NAME_USE use{};
    if (::LookupAccountSidW(nullptr, sid, name, &nameLength, domain, &domainLength, &use)) {
        std::wstring account;
        if (*domain) { account = std::wstring(domain) + L"\\"; }
        account += name;
        return account + L" (SID=" + sidValue + L")";
    }
    return L"SID=" + (sidValue.empty() ? std::wstring(L"<unavailable>") : sidValue);
}

bool queryTokenBytes(HANDLE token, int informationClass, std::vector<std::byte>& bytes, DWORD& error) {
    DWORD required = 0;
    ::SetLastError(ERROR_SUCCESS);
    ::GetTokenInformation(token, static_cast<TOKEN_INFORMATION_CLASS>(informationClass), nullptr, 0, &required);
    error = ::GetLastError();
    if (required == 0 || required > 16 * 1024 * 1024) {
        return false;
    }
    bytes.resize(required);
    if (!::GetTokenInformation(
            token,
            static_cast<TOKEN_INFORMATION_CLASS>(informationClass),
            bytes.data(),
            required,
            &required)) {
        error = ::GetLastError();
        bytes.clear();
        return false;
    }
    bytes.resize(required);
    error = ERROR_SUCCESS;
    return true;
}

std::wstring rawPreview(const std::vector<std::byte>& bytes) {
    std::wostringstream text;
    text << std::uppercase << std::hex << std::setfill(L'0');
    const std::size_t kCount = std::min<std::size_t>(24, bytes.size());
    for (std::size_t index = 0; index < kCount; ++index) {
        if (index) { text << L' '; }
        text << std::setw(2) << std::to_integer<unsigned int>(bytes[index]);
    }
    if (bytes.size() > kCount) { text << L" ..."; }
    return text.str();
}

bool parseUnsigned(const std::wstring& text, unsigned long long maximum, unsigned long long& value) {
    try {
        std::size_t consumed = 0;
        value = std::stoull(text, &consumed, 0);
        return consumed == text.size() && value <= maximum;
    } catch (...) {
        return false;
    }
}

bool isChecked(HWND checkbox) {
    return checkbox && ::SendMessageW(checkbox, BM_GETCHECK, 0, 0) == BST_CHECKED;
}

void setChecked(HWND checkbox, bool checked) {
    if (checkbox) {
        ::SendMessageW(checkbox, BM_SETCHECK, checked ? BST_CHECKED : BST_UNCHECKED, 0);
    }
}

// verifyProcessIdentity keeps the caller-owned process handle in scope so the
// PID cannot be reused while the following token operations are collected.
bool verifyProcessIdentity(
    HANDLE process,
    ULONGLONG expectedProcessCreationTime100ns,
    std::wstring& errorText) {
    errorText.clear();
    if (!process || expectedProcessCreationTime100ns == 0U) {
        errorText = L"进程身份不可用。";
        return false;
    }
    FILETIME creationTime{};
    FILETIME exitTime{};
    FILETIME kernelTime{};
    FILETIME userTime{};
    if (!::GetProcessTimes(process, &creationTime, &exitTime, &kernelTime, &userTime)) {
        errorText = L"GetProcessTimes失败(" + std::to_wstring(::GetLastError()) + L")";
        return false;
    }
    const ULONGLONG kActualProcessCreationTime100ns =
        (static_cast<ULONGLONG>(creationTime.dwHighDateTime) << 32U) |
        static_cast<ULONGLONG>(creationTime.dwLowDateTime);
    if (kActualProcessCreationTime100ns == 0U ||
        kActualProcessCreationTime100ns != expectedProcessCreationTime100ns) {
        errorText = L"目标进程实例已变更（PID 已复用）。";
        return false;
    }
    return true;
}

constexpr std::array<int, 10> kTokenBooleanInformationClasses{
    15, 23, 24, 26, 21, 29, 40, 46, 47, 51
};

ProcessTokenReportSnapshot collectTokenReportSnapshot(
    const DWORD processId,
    const ULONGLONG expectedProcessCreationTime100ns) {
    ProcessTokenReportSnapshot snapshot{};
    ScopedHandle process(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId));
    if (!process) {
        const DWORD kError = ::GetLastError();
        snapshot.statusText = L"● 刷新失败：无法打开目标令牌";
        snapshot.reportText = L"OpenProcess failed: " + std::to_wstring(kError);
        snapshot.editorStatusText = L"行:1 列:1 字符:0 文件:<未命名> 模式:只读 编码:UTF-16";
        return snapshot;
    }
    std::wstring identityError;
    if (!verifyProcessIdentity(process.get(), expectedProcessCreationTime100ns, identityError)) {
        snapshot.statusText = L"● 刷新已取消：" + identityError;
        snapshot.reportText = L"Process identity verification failed: " + identityError;
        snapshot.editorStatusText = L"行:1 列:1 字符:0 文件:<未命名> 模式:只读 编码:UTF-16";
        return snapshot;
    }
    snapshot.identityMatched = true;

    HANDLE rawToken = nullptr;
    if (!::OpenProcessToken(process.get(), TOKEN_QUERY, &rawToken)) {
        const DWORD kError = ::GetLastError();
        snapshot.statusText = L"● 刷新失败：无法打开目标令牌";
        snapshot.reportText = L"OpenProcessToken failed: " + std::to_wstring(kError);
        snapshot.editorStatusText = L"行:1 列:1 字符:0 文件:<未命名> 模式:只读 编码:UTF-16";
        return snapshot;
    }

    ScopedHandle token(rawToken);
    std::wostringstream report;
    report << L"[Token / Security Information]\r\nPID: " << processId << L"\r\n";

    std::vector<std::byte> bytes;
    DWORD error = 0;
    if (queryTokenBytes(token.get(), TokenUser, bytes, error)) {
        const auto* user = reinterpret_cast<const TOKEN_USER*>(bytes.data());
        report << L"User: " << sidText(user->User.Sid) << L"\r\n";
    }
    if (queryTokenBytes(token.get(), TokenElevationType, bytes, error)) {
        const auto kValue = *reinterpret_cast<const TOKEN_ELEVATION_TYPE*>(bytes.data());
        report << L"ElevationType: " << (kValue == TokenElevationTypeFull ? L"Full" : kValue == TokenElevationTypeLimited ? L"Limited" : L"Default") << L"\r\n";
    }
    if (queryTokenBytes(token.get(), TokenElevation, bytes, error)) {
        report << L"IsElevated: " << (reinterpret_cast<const TOKEN_ELEVATION*>(bytes.data())->TokenIsElevated ? L"true" : L"false") << L"\r\n";
    }
    if (queryTokenBytes(token.get(), TokenGroups, bytes, error)) {
        const auto* groups = reinterpret_cast<const TOKEN_GROUPS*>(bytes.data());
        report << L"GroupCount: " << groups->GroupCount << L"\r\n";
        for (DWORD index = 0; index < std::min<DWORD>(groups->GroupCount, 16); ++index) {
            report << L"  - " << sidText(groups->Groups[index].Sid) << L"\r\n";
        }
    }
    if (queryTokenBytes(token.get(), TokenPrivileges, bytes, error)) {
        const auto* privileges = reinterpret_cast<const TOKEN_PRIVILEGES*>(bytes.data());
        report << L"PrivilegeCount: " << privileges->PrivilegeCount << L"\r\n";
        for (DWORD index = 0; index < std::min<DWORD>(privileges->PrivilegeCount, 24); ++index) {
            wchar_t name[256]{};
            DWORD length = static_cast<DWORD>(std::size(name));
            ::LookupPrivilegeNameW(nullptr, const_cast<LUID*>(&privileges->Privileges[index].Luid), name, &length);
            report << L"  - " << (*name ? name : L"<unknown>") << L" ["
                   << ((privileges->Privileges[index].Attributes & SE_PRIVILEGE_ENABLED) ? L"Enabled" : L"Disabled")
                   << L"]\r\n";
        }
    }

    report << L"\r\n[All TokenInformationClass Snapshot]\r\n";
    for (int informationClass = 1; informationClass <= 80; ++informationClass) {
        if (queryTokenBytes(token.get(), informationClass, bytes, error)) {
            report << L"  [" << informationClass << L"] " << tokenClassName(informationClass)
                   << L": size=" << bytes.size() << L", raw=" << rawPreview(bytes) << L"\r\n";
        } else {
            report << L"  [" << informationClass << L"] " << tokenClassName(informationClass)
                   << L": queryFailed(" << error << L")\r\n";
        }
    }
    DWORD sessionId = 0;
    DWORD returnLength = 0;
    if (::GetTokenInformation(token.get(), TokenSessionId, &sessionId, sizeof(sessionId), &returnLength)) {
        report << L"SessionId: " << sessionId << L"\r\n";
    }

    snapshot.succeeded = true;
    snapshot.reportText = report.str();
    snapshot.statusText = L"● 刷新完成";
    snapshot.editorStatusText =
        L"行:1 列:1 字符:" + std::to_wstring(snapshot.reportText.size()) + L" 文件:<未命名> 模式:只读 编码:UTF-16";
    return snapshot;
}

ProcessTokenSwitchSnapshot collectTokenSwitchSnapshot(
    const DWORD processId,
    const ULONGLONG expectedProcessCreationTime100ns) {
    ProcessTokenSwitchSnapshot snapshot{};
    ScopedHandle process(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId));
    if (!process) {
        snapshot.statusText = L"● 刷新失败：无法打开目标令牌";
        return snapshot;
    }
    std::wstring identityError;
    if (!verifyProcessIdentity(process.get(), expectedProcessCreationTime100ns, identityError)) {
        snapshot.statusText = L"● 刷新已取消：" + identityError;
        return snapshot;
    }
    snapshot.identityMatched = true;

    HANDLE rawToken = nullptr;
    if (!::OpenProcessToken(process.get(), TOKEN_QUERY, &rawToken)) {
        snapshot.statusText = L"● 刷新失败：无法打开目标令牌";
        return snapshot;
    }

    ScopedHandle token(rawToken);
    int success = 0;
    for (std::size_t index = 0; index < kTokenBooleanInformationClasses.size(); ++index) {
        ULONG value = 0;
        DWORD returned = 0;
        if (::GetTokenInformation(
                token.get(),
                static_cast<TOKEN_INFORMATION_CLASS>(kTokenBooleanInformationClasses[index]),
                &value,
                sizeof(value),
                &returned)) {
            snapshot.values[index] = value != 0;
            snapshot.updated[index] = true;
            ++success;
        }
    }

    TOKEN_MANDATORY_POLICY policy{};
    DWORD returned = 0;
    if (::GetTokenInformation(token.get(), TokenMandatoryPolicy, &policy, sizeof(policy), &returned)) {
        snapshot.values[10] = (policy.Policy & 0x1U) != 0;
        snapshot.values[11] = (policy.Policy & 0x2U) != 0;
        snapshot.updated[10] = true;
        snapshot.updated[11] = true;
        ++success;
    }
    snapshot.succeeded = true;
    snapshot.statusText = L"● 刷新完成：" + std::to_wstring(success) + L" 项开关已同步";
    return snapshot;
}

} // namespace

bool ProcessDetailPage::createTokenTab() {
    const TabIndex kTab = TabIndex::kToken;
    addButton(kTab, kTokenRefresh, L"刷新令牌", 6, 6, 92, 30);
    addButton(kTab, kTokenCopy, L"复制", 106, 6, 64, 30);
    addButton(kTab, kTokenFind, L"查找", 178, 6, 64, 30);
    addButton(kTab, kTokenGoto, L"跳转行", 250, 6, 76, 30);
    addButton(kTab, kTokenWrap, L"自动换行", 334, 6, 86, 30);
    addLabel(kTab, kTokenStatus, L"● 尚未刷新", 430, 8, -6, 24);
    addEdit(kTab, kTokenOutput, L"令牌详细信息将在此处显示。", true, true, 6, 44, -6, -30);
    addLabel(kTab, kTokenEditorStatus, L"行:1 列:1 字符:0 文件:<未命名> 模式:只读 编码:未知", 6, -24, -6, 20);
    return findControl(kTab, kTokenRefresh) && findControl(kTab, kTokenOutput);
}

bool ProcessDetailPage::createTokenSwitchTab() {
    const TabIndex kTab = TabIndex::kTokenSwitch;
    addButton(kTab, kTokenSwitchRefresh, L"↻", 6, 6, 34, 34);
    addButton(kTab, kTokenSwitchApply, L"▶", 46, 6, 34, 34);
    addButton(kTab, kTokenSwitchRefreshAll, L"≡", 86, 6, 34, 34);
    addLabel(kTab, kTokenSwitchStatus, L"● 尚未刷新令牌开关", 130, 10, -6, 24);

    addGroup(kTab, L"Token 快捷开关", 6, 48, -6, 116);
    addCheck(kTab, kTokenSandboxInert, L"SandboxInert", 20, 72, 260, 24);
    addCheck(kTab, kTokenVirtualizationAllowed, L"VirtualizationAllowed", 310, 72, 280, 24);
    addCheck(kTab, kTokenVirtualizationEnabled, L"VirtualizationEnabled", 20, 100, 260, 24);
    addCheck(kTab, kTokenUiAccess, L"UIAccess", 310, 100, 280, 24);
    addCheck(kTab, kTokenMandatoryNoWriteUp, L"MandatoryPolicy.NoWriteUp", 20, 128, 260, 24);
    addCheck(kTab, kTokenMandatoryNewProcessMin, L"MandatoryPolicy.NewProcessMin", 310, 128, 300, 24);

    addGroup(kTab, L"Token 常用信息类（布尔语义）", 6, 172, -6, 116);
    addCheck(kTab, kTokenHasRestrictions, L"HasRestrictions", 20, 196, 260, 24);
    addCheck(kTab, kTokenIsAppContainer, L"IsAppContainer", 310, 196, 280, 24);
    addCheck(kTab, kTokenIsRestricted, L"IsRestricted", 20, 224, 260, 24);
    addCheck(kTab, kTokenIsLessPrivilegedAppContainer, L"IsLessPrivilegedAppContainer", 310, 224, 300, 24);
    addCheck(kTab, kTokenIsSandboxed, L"IsSandboxed", 20, 252, 260, 24);
    addCheck(kTab, kTokenIsAppSilo, L"IsAppSilo", 310, 252, 280, 24);

    addGroup(kTab, L"原始 NtSetInformationToken（全部信息类）", 6, 296, -6, 140);
    addLabel(kTab, 0, L"信息类", 20, 322, 92, 26);
    HWND infoClass = addCombo(kTab, kTokenRawInfoClass, 116, 320, -20, 360);
    for (int value = 1; value <= 80; ++value) {
        addComboText(infoClass, L"[" + std::to_wstring(value) + L"] " + tokenClassName(value), value);
    }
    ::SendMessageW(infoClass, CB_SETCURSEL, 14, 0);
    addLabel(kTab, 0, L"输入模式", 20, 356, 92, 26);
    HWND mode = addCombo(kTab, kTokenRawInputMode, 116, 354, -20, 180);
    addComboText(mode, L"UInt32", 0);
    addComboText(mode, L"UInt64", 1);
    addComboText(mode, L"HexBytes", 2);
    ::SendMessageW(mode, CB_SETCURSEL, 0, 0);
    addLabel(kTab, 0, L"原始负载", 20, 390, 92, 26);
    HWND payload = addEdit(kTab, kTokenRawPayload, L"", false, false, 116, 388, -64, 28);
    ::SendMessageW(payload, EM_SETCUEBANNER, FALSE,
        reinterpret_cast<LPARAM>(L"示例：UInt32=1；UInt64=0x10；HexBytes=01 00 00 00"));
    addButton(kTab, kTokenRawApply, L"▶", -50, 386, 34, 34);
    addLabel(kTab, 0,
        L"提示：可先点“刷新全部令牌信息”查看所有 TokenInformationClass 的当前状态，再按快捷或原始模式应用。",
        10, 444, -10, 44);
    if (actionTask_ && actionTask_->running()) {
        setBackgroundActionControlsEnabled(false);
    }
    return infoClass && mode && payload;
}

void ProcessDetailPage::populateTokenTab() {
    if (!tokenLoaded_) {
        setControlText(TabIndex::kToken, kTokenOutput, L"令牌详细信息将在此处显示。");
    }
}

void ProcessDetailPage::populateTokenSwitchTab() {
    if (!tokenSwitchLoaded_) {
        setPageStatus(TabIndex::kTokenSwitch, kTokenSwitchStatus, L"● 尚未刷新令牌开关");
    }
}

bool ProcessDetailPage::handleTokenCommand(int controlId) {
    switch (controlId) {
    case kTokenRefresh:
        refreshTokenReport();
        return true;
    case kTokenCopy: {
        HWND output = findControl(TabIndex::kToken, kTokenOutput);
        ::SendMessageW(output, EM_SETSEL, 0, -1);
        const std::wstring kText = readWindowText(output);
        if (!kText.empty()) {
            copyText(hwnd_, kText);
        } else {
            // Preserve the native edit-control behavior for an empty report.
            ::SendMessageW(output, WM_COPY, 0, 0);
        }
        return true;
    }
    case kTokenFind:
        ::MessageBoxW(hwnd_, L"可使用 Ctrl+F 配合系统编辑控件查找；当前布局保留查找入口。", L"查找", MB_OK | MB_ICONINFORMATION);
        return true;
    case kTokenGoto:
        ::SendMessageW(findControl(TabIndex::kToken, kTokenOutput), EM_SETSEL, 0, 0);
        ::SetFocus(findControl(TabIndex::kToken, kTokenOutput));
        return true;
    case kTokenWrap: {
        HWND output = findControl(TabIndex::kToken, kTokenOutput);
        const LONG_PTR kStyle = ::GetWindowLongPtrW(output, GWL_STYLE);
        ::SetWindowLongPtrW(output, GWL_STYLE, kStyle ^ ES_AUTOHSCROLL);
        ::SetWindowPos(output, nullptr, 0, 0, 0, 0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);
        return true;
    }
    default:
        return false;
    }
}

bool ProcessDetailPage::handleTokenSwitchCommand(int controlId) {
    switch (controlId) {
    case kTokenSwitchRefresh: refreshTokenSwitches(); return true;
    case kTokenSwitchApply: applyTokenSwitches(); return true;
    case kTokenSwitchRefreshAll: refreshTokenReport(); return true;
    case kTokenRawApply: applyRawTokenValue(); return true;
    default: return false;
    }
}

void ProcessDetailPage::refreshTokenReport() {
    if (!tokenReportTask_) {
        setPageStatus(TabIndex::kToken, kTokenStatus, L"● 令牌后台任务不可用。");
        return;
    }
    setPageStatus(TabIndex::kToken, kTokenStatus, L"● 正在刷新令牌...");
    const DWORD kProcessId = processId_;
    const ULONGLONG kExpectedProcessCreationTime100ns = expectedCreationTime100ns_;
    tokenReportTask_->request(
        [kProcessId, kExpectedProcessCreationTime100ns] {
            return collectTokenReportSnapshot(kProcessId, kExpectedProcessCreationTime100ns);
        },
        [this](std::uint64_t, std::optional<ProcessTokenReportSnapshot>&& result, std::exception_ptr error) {
            if (error || !result.has_value()) {
                setPageStatus(TabIndex::kToken, kTokenStatus, L"● 令牌后台查询异常结束。");
                return;
            }
            setControlText(TabIndex::kToken, kTokenOutput, result->reportText);
            setControlText(TabIndex::kToken, kTokenEditorStatus, result->editorStatusText);
            setPageStatus(TabIndex::kToken, kTokenStatus, result->statusText);
            tokenLoaded_ = result->succeeded && result->identityMatched;
        });
}

void ProcessDetailPage::refreshTokenSwitches() {
    if (!tokenSwitchTask_) {
        setPageStatus(TabIndex::kTokenSwitch, kTokenSwitchStatus, L"● 令牌开关后台任务不可用。");
        return;
    }
    setPageStatus(TabIndex::kTokenSwitch, kTokenSwitchStatus, L"● 正在读取令牌开关...");
    const DWORD kProcessId = processId_;
    const ULONGLONG kExpectedProcessCreationTime100ns = expectedCreationTime100ns_;
    tokenSwitchTask_->request(
        [kProcessId, kExpectedProcessCreationTime100ns] {
            return collectTokenSwitchSnapshot(kProcessId, kExpectedProcessCreationTime100ns);
        },
        [this](std::uint64_t, std::optional<ProcessTokenSwitchSnapshot>&& result, std::exception_ptr error) {
            if (error || !result.has_value()) {
                setPageStatus(TabIndex::kTokenSwitch, kTokenSwitchStatus, L"● 令牌开关后台查询异常结束。");
                return;
            }
            constexpr std::array<int, 12> kControls{
                kTokenSandboxInert,
                kTokenVirtualizationAllowed,
                kTokenVirtualizationEnabled,
                kTokenUiAccess,
                kTokenHasRestrictions,
                kTokenIsAppContainer,
                kTokenIsRestricted,
                kTokenIsLessPrivilegedAppContainer,
                kTokenIsSandboxed,
                kTokenIsAppSilo,
                kTokenMandatoryNoWriteUp,
                kTokenMandatoryNewProcessMin
            };
            for (std::size_t index = 0; index < kControls.size(); ++index) {
                if (result->updated[index]) {
                    setChecked(findControl(TabIndex::kTokenSwitch, kControls[index]), result->values[index]);
                }
            }
            setPageStatus(TabIndex::kTokenSwitch, kTokenSwitchStatus, result->statusText);
            tokenSwitchLoaded_ = result->succeeded && result->identityMatched;
        });
}

void ProcessDetailPage::applyTokenSwitches() {
    if (::MessageBoxW(hwnd_, L"将尝试写回目标进程令牌开关。部分信息类在当前系统上只读，是否继续？",
        L"令牌开关", MB_YESNO | MB_DEFBUTTON2 | MB_ICONWARNING) != IDYES) {
        return;
    }
    const std::array<bool, 12> kValues{
        isChecked(findControl(TabIndex::kTokenSwitch, kTokenSandboxInert)),
        isChecked(findControl(TabIndex::kTokenSwitch, kTokenVirtualizationAllowed)),
        isChecked(findControl(TabIndex::kTokenSwitch, kTokenVirtualizationEnabled)),
        isChecked(findControl(TabIndex::kTokenSwitch, kTokenUiAccess)),
        isChecked(findControl(TabIndex::kTokenSwitch, kTokenHasRestrictions)),
        isChecked(findControl(TabIndex::kTokenSwitch, kTokenIsAppContainer)),
        isChecked(findControl(TabIndex::kTokenSwitch, kTokenIsRestricted)),
        isChecked(findControl(TabIndex::kTokenSwitch, kTokenIsLessPrivilegedAppContainer)),
        isChecked(findControl(TabIndex::kTokenSwitch, kTokenIsSandboxed)),
        isChecked(findControl(TabIndex::kTokenSwitch, kTokenIsAppSilo)),
        isChecked(findControl(TabIndex::kTokenSwitch, kTokenMandatoryNoWriteUp)),
        isChecked(findControl(TabIndex::kTokenSwitch, kTokenMandatoryNewProcessMin))
    };
    const DWORD kProcessId = processId_;
    const ULONGLONG kExpectedProcessCreationTime100ns = expectedCreationTime100ns_;
    executeBackgroundAction(
        TabIndex::kTokenSwitch,
        kTokenSwitchStatus,
        L"● 正在后台写回令牌开关…",
        [kProcessId, kExpectedProcessCreationTime100ns, kValues] {
            ProcessDetailActionResult action{};
            const auto kSetInformation = reinterpret_cast<NtSetInformationTokenFn>(
                ::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"), "NtSetInformationToken"));
            ksword::core::UniqueHandle verifiedProcess;
            std::wstring identityError;
            if (!ProcessDetailPage::openVerifiedProcessActionTarget(
                    kProcessId,
                    kExpectedProcessCreationTime100ns,
                    PROCESS_QUERY_LIMITED_INFORMATION,
                    verifiedProcess,
                    identityError)) {
                action.statusText = L"● 应用失败：" + identityError;
                return action;
            }
            HANDLE rawToken = nullptr;
            if (!kSetInformation || !::OpenProcessToken(
                    verifiedProcess.get(), TOKEN_QUERY | TOKEN_ADJUST_DEFAULT, &rawToken)) {
                action.statusText = L"● 应用失败：无法获取 NtSetInformationToken/令牌写权限";
                return action;
            }

            ScopedHandle token(rawToken);
            int success = 0;
            int failed = 0;
            for (std::size_t index = 0; index < kTokenBooleanInformationClasses.size(); ++index) {
                ULONG value = kValues[index] ? 1UL : 0UL;
                const NTSTATUS kStatus = kSetInformation(
                    token.get(),
                    static_cast<TOKEN_INFORMATION_CLASS>(kTokenBooleanInformationClasses[index]),
                    &value,
                    sizeof(value));
                kStatus >= 0 ? ++success : ++failed;
            }
            TOKEN_MANDATORY_POLICY policy{};
            if (kValues[10]) { policy.Policy |= 0x1U; }
            if (kValues[11]) { policy.Policy |= 0x2U; }
            const NTSTATUS kPolicyStatus = kSetInformation(token.get(), TokenMandatoryPolicy, &policy, sizeof(policy));
            kPolicyStatus >= 0 ? ++success : ++failed;
            action.statusText =
                L"● 应用完成：成功" + std::to_wstring(success) + L"，失败" + std::to_wstring(failed);
            action.refreshTokenSwitches = true;
            action.refreshTokenReport = true;
            return action;
        });
}

void ProcessDetailPage::applyRawTokenValue() {
    HWND classCombo = findControl(TabIndex::kTokenSwitch, kTokenRawInfoClass);
    HWND modeCombo = findControl(TabIndex::kTokenSwitch, kTokenRawInputMode);
    const int kClassIndex = static_cast<int>(::SendMessageW(classCombo, CB_GETCURSEL, 0, 0));
    const int kModeIndex = static_cast<int>(::SendMessageW(modeCombo, CB_GETCURSEL, 0, 0));
    if (kClassIndex < 0 || kModeIndex < 0) {
        setPageStatus(TabIndex::kTokenSwitch, kTokenSwitchStatus, L"● 原始设置失败：信息类或输入模式无效");
        return;
    }
    const int kInformationClass = static_cast<int>(::SendMessageW(classCombo, CB_GETITEMDATA, kClassIndex, 0));
    const std::wstring kPayloadText = controlText(TabIndex::kTokenSwitch, kTokenRawPayload);
    std::vector<std::byte> payload;
    if (kModeIndex <= 1) {
        unsigned long long value = 0;
        const unsigned long long kMaximum = kModeIndex == 0 ? 0xFFFFFFFFULL : ~0ULL;
        if (!parseUnsigned(kPayloadText, kMaximum, value)) {
            setPageStatus(TabIndex::kTokenSwitch, kTokenSwitchStatus, L"● 原始设置失败：整数解析失败");
            return;
        }
        const std::size_t kSize = kModeIndex == 0 ? sizeof(std::uint32_t) : sizeof(std::uint64_t);
        payload.resize(kSize);
        std::memcpy(payload.data(), &value, kSize);
    } else {
        std::wstring normalized = kPayloadText;
        std::replace(normalized.begin(), normalized.end(), L',', L' ');
        std::wistringstream stream(normalized);
        std::wstring item;
        while (stream >> item) {
            unsigned long long value = 0;
            const bool kHasHexPrefix = item.size() >= 2 && item[0] == L'0' && std::towlower(item[1]) == L'x';
            if (!parseUnsigned(kHasHexPrefix ? item : L"0x" + item, 0xFF, value)) {
                setPageStatus(TabIndex::kTokenSwitch, kTokenSwitchStatus, L"● 原始设置失败：非法字节 '" + item + L"'");
                return;
            }
            payload.push_back(static_cast<std::byte>(value));
        }
        if (payload.empty()) {
            setPageStatus(TabIndex::kTokenSwitch, kTokenSwitchStatus, L"● 原始设置失败：没有字节");
            return;
        }
    }

    if (payload.size() > 16U * 1024U * 1024U) {
        setPageStatus(TabIndex::kTokenSwitch, kTokenSwitchStatus, L"● 原始设置失败：负载超过16 MiB上限");
        return;
    }
    const DWORD kProcessId = processId_;
    const ULONGLONG kExpectedProcessCreationTime100ns = expectedCreationTime100ns_;
    executeBackgroundAction(
        TabIndex::kTokenSwitch,
        kTokenSwitchStatus,
        L"● 正在后台写入原始令牌信息…",
        [kInformationClass, kProcessId, kExpectedProcessCreationTime100ns, payload = std::move(payload)]() mutable {
            ProcessDetailActionResult action{};
            const auto kSetInformation = reinterpret_cast<NtSetInformationTokenFn>(
                ::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"), "NtSetInformationToken"));
            ksword::core::UniqueHandle verifiedProcess;
            std::wstring identityError;
            if (!ProcessDetailPage::openVerifiedProcessActionTarget(
                    kProcessId,
                    kExpectedProcessCreationTime100ns,
                    PROCESS_QUERY_LIMITED_INFORMATION,
                    verifiedProcess,
                    identityError)) {
                action.statusText = L"● 原始设置失败：" + identityError;
                return action;
            }
            HANDLE rawToken = nullptr;
            if (!kSetInformation || !::OpenProcessToken(
                    verifiedProcess.get(), TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID, &rawToken)) {
                action.statusText = L"● 原始设置失败：无法打开目标令牌";
                return action;
            }
            ScopedHandle token(rawToken);
            const NTSTATUS kStatus = kSetInformation(
                token.get(),
                static_cast<TOKEN_INFORMATION_CLASS>(kInformationClass),
                payload.data(),
                static_cast<ULONG>(payload.size()));
            std::wostringstream message;
            message << (kStatus >= 0 ? L"● 原始设置成功：" : L"● 原始设置失败：")
                    << L"[" << kInformationClass << L"] " << tokenClassName(kInformationClass)
                    << L", size=" << payload.size() << L", status=0x"
                    << std::uppercase << std::hex << static_cast<std::uint32_t>(kStatus);
            action.statusText = message.str();
            action.refreshTokenSwitches = true;
            action.refreshTokenReport = true;
            return action;
        });
}

} // namespace Ksword::Features::process_detail
