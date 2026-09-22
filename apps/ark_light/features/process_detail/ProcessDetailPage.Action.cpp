#include "ProcessDetailPage.h"

#include "../process/ProcessActions.h"

#include <commdlg.h>
#include <tlhelp32.h>

#include <array>
#include <string>
#include <utility>
#include <vector>

namespace ksword::features::process_detail {
namespace {

using ksword::features::process::ProcessActionId;

constexpr LPARAM kTerminateModeMultiMethod = 1;
constexpr LPARAM kTerminateModeWin32 = 2;
constexpr LPARAM kTerminateModeAllThreads = 3;

void addComboItem(HWND combo, const wchar_t* text, LPARAM data) {
    const LRESULT kIndex = ::SendMessageW(combo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(text));
    if (kIndex >= 0) {
        ::SendMessageW(combo, CB_SETITEMDATA, static_cast<WPARAM>(kIndex), data);
    }
}

bool confirmDanger(HWND owner, const wchar_t* text) {
    return ::MessageBoxW(owner, text, L"高风险操作确认", MB_YESNO | MB_DEFBUTTON2 | MB_ICONWARNING) == IDYES;
}

bool confirmR0Injection(HWND owner, const wchar_t* action, DWORD processId, const std::wstring& path) {
    std::wstring message = L"将通过 KswordARK R0 进程注入协议执行操作：";
    message += action ? action : L"注入";
    message += L"\r\n\r\n目标 PID: " + std::to_wstring(processId);
    message += L"\r\nPayload: " + path;
    message += L"\r\n\r\n该操作会在目标进程创建远程线程，可能导致目标崩溃或系统不稳定。是否继续？";
    return ::MessageBoxW(owner, message.c_str(), L"确认 R0 注入", MB_YESNO | MB_DEFBUTTON2 | MB_ICONWARNING) == IDYES;
}

} // namespace

bool ProcessDetailPage::terminateAllThreadsIfProcessIdentityMatches(
    DWORD targetProcessId,
    ULONGLONG expectedProcessCreationTime100ns,
    std::wstring& detail) {
    detail.clear();
    ksword::core::UniqueHandle verifiedProcess;
    std::wstring identityError;
    if (!openVerifiedProcessActionTarget(
            targetProcessId,
            expectedProcessCreationTime100ns,
            PROCESS_QUERY_LIMITED_INFORMATION,
            verifiedProcess,
            identityError)) {
        detail = L"目标进程身份验证失败：" + identityError;
        return false;
    }

    ksword::core::UniqueHandle snapshot(::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
    if (!snapshot.valid()) {
        detail = L"无法创建线程快照。";
        return false;
    }

    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    if (!::Thread32First(snapshot.get(), &entry)) {
        detail = L"无法枚举目标进程线程。";
        return false;
    }

    int succeeded = 0;
    int failed = 0;
    int skipped = 0;
    do {
        if (entry.th32OwnerProcessID != targetProcessId) {
            continue;
        }
        ksword::core::UniqueHandle thread(::OpenThread(
            THREAD_QUERY_LIMITED_INFORMATION | THREAD_TERMINATE,
            FALSE,
            entry.th32ThreadID));
        if (!thread.valid()) {
            ++failed;
            continue;
        }
        if (::GetProcessIdOfThread(thread.get()) != targetProcessId) {
            // The Toolhelp entry became stale before the action handle opened.
            ++skipped;
            continue;
        }
        if (::TerminateThread(thread.get(), 1)) {
            ++succeeded;
        } else {
            ++failed;
        }
    } while (::Thread32Next(snapshot.get(), &entry));

    detail = L"TerminateThread 完成：成功 " + std::to_wstring(succeeded) +
        L"，失败 " + std::to_wstring(failed) +
        L"，身份变更跳过 " + std::to_wstring(skipped) + L"。";
    return succeeded > 0 && failed == 0 && skipped == 0;
}

bool ProcessDetailPage::createActionTab() {
    const TabIndex kTab = TabIndex::kActions;

    addGroup(kTab, L"结束与控制", 6, 6, -6, 196);
    addLabel(kTab, 0, L"结束方案", 18, 32, 88, 28);
    HWND terminateMode = addCombo(kTab, kActionTerminateMode, 110, 30, -104, 220);
    addButton(kTab, kActionTerminate, L"执行", -86, 30, 74, 32);
    addComboItem(terminateMode, L"结束进程(组合方法链)", kTerminateModeMultiMethod);
    addComboItem(terminateMode, L"TerminateProcess", kTerminateModeWin32);
    addComboItem(terminateMode, L"TerminateThread(全部线程)", kTerminateModeAllThreads);
    ::SendMessageW(terminateMode, CB_SETCURSEL, 0, 0);

    addLabel(kTab, 0, L"运行控制", 18, 70, 88, 28);
    addButton(kTab, kActionSuspend, L"挂起", 110, 68, 82, 32);
    addButton(kTab, kActionResume, L"恢复", 200, 68, 82, 32);
    addLabel(kTab, 0, L"关键进程", 18, 108, 88, 28);
    addButton(kTab, kActionSetCritical, L"设为关键", 110, 106, 96, 32);
    addButton(kTab, kActionClearCritical, L"取消关键", 214, 106, 96, 32);
    addLabel(kTab, 0, L"优先级", 18, 146, 88, 28);
    HWND priority = addCombo(kTab, kActionPriority, 110, 144, -104, 220);
    addButton(kTab, kActionApplyPriority, L"应用", -86, 144, 74, 32);
    for (const wchar_t* item : { L"Idle", L"Below Normal", L"Normal", L"Above Normal", L"High", L"Realtime" }) {
        addComboItem(priority, item, 0);
    }
    ::SendMessageW(priority, CB_SETCURSEL, 2, 0);

    addGroup(kTab, L"右键菜单同步能力", 6, 212, -6, 152);
    addLabel(kTab, 0, L"辅助", 18, 238, 88, 28);
    addButton(kTab, kActionOpenFolder, L"打开目录", 110, 236, 94, 32);
    addButton(kTab, kActionRefreshPpl, L"刷新PPL", 212, 236, 94, 32);
    addLabel(kTab, 0, L"效率模式", 18, 276, 88, 28);
    addButton(kTab, kActionEfficiencyOn, L"开效率", 110, 274, 94, 32);
    addButton(kTab, kActionEfficiencyOff, L"关效率", 212, 274, 94, 32);
    addLabel(kTab, 0, L"R0", 18, 314, 88, 28);
    addButton(kTab, kActionR0Terminate, L"R0结束", 110, 312, 92, 32);
    addButton(kTab, kActionR0Suspend, L"R0挂起", 210, 312, 92, 32);
    addButton(kTab, kActionR0Ppl, L"R0 PPL", 310, 312, 92, 32);
    addButton(kTab, kActionR0Hide, L"R0隐藏", 410, 312, 92, 32);
    addButton(kTab, kActionR0Danger, L"R0危险", 510, 312, 92, 32);

    addGroup(kTab, L"注入与载入", 6, 374, -6, 180);
    addLabel(kTab, 0, L"模式", 18, 400, 88, 28);
    HWND injectionMode = addCombo(kTab, kActionInjectionMode, 110, 398, -12, 220);
    addComboItem(injectionMode, L"R3", 0);
    addComboItem(injectionMode, L"R0驱动", 1);
    ::SendMessageW(injectionMode, CB_SETCURSEL, 0, 0);
    addLabel(kTab, 0, L"DLL", 18, 438, 88, 28);
    HWND dllPath = addEdit(kTab, kActionDllPath, L"", false, false, 110, 436, -184, 28);
    ::SendMessageW(dllPath, EM_SETCUEBANNER, FALSE, reinterpret_cast<LPARAM>(L"请选择要注入的 DLL 路径"));
    addButton(kTab, kActionBrowseDll, L"浏览", -166, 434, 72, 32);
    addButton(kTab, kActionInjectDll, L"注入", -86, 434, 72, 32);
    addLabel(kTab, 0, L"Shellcode", 18, 476, 88, 28);
    HWND shellcodePath = addEdit(kTab, kActionShellcodePath, L"", false, false, 110, 474, -184, 28);
    ::SendMessageW(shellcodePath, EM_SETCUEBANNER, FALSE, reinterpret_cast<LPARAM>(L"请选择原始 shellcode 二进制文件"));
    addButton(kTab, kActionBrowseShellcode, L"浏览", -166, 472, 72, 32);
    addButton(kTab, kActionInjectShellcode, L"执行", -86, 472, 72, 32);
    addLabel(kTab, kActionStatus, L"● 操作就绪。", 18, 518, -18, 26);

    if (actionTask_ && actionTask_->running()) {
        setBackgroundActionControlsEnabled(false);
    }

    return terminateMode && priority && injectionMode && dllPath && shellcodePath && findControl(kTab, kActionStatus);
}

bool ProcessDetailPage::handleActionCommand(int controlId) {
    switch (controlId) {
    case kActionTerminate: {
        HWND combo = findControl(TabIndex::kActions, kActionTerminateMode);
        const int kSelected = static_cast<int>(::SendMessageW(combo, CB_GETCURSEL, 0, 0));
        const LPARAM kMode = kSelected >= 0
            ? ::SendMessageW(combo, CB_GETITEMDATA, static_cast<WPARAM>(kSelected), 0)
            : -1;
        if (kMode == kTerminateModeAllThreads) {
            if (!confirmDanger(hwnd_, L"将逐个终止目标进程的全部线程。该操作不可撤销，是否继续？")) {
                return true;
            }
            const DWORD kProcessId = processId_;
            const ULONGLONG kExpectedProcessCreationTime100ns = expectedCreationTime100ns_;
            executeBackgroundAction(
                TabIndex::kActions,
                kActionStatus,
                L"● 正在后台终止目标进程的全部线程…",
                [kProcessId, kExpectedProcessCreationTime100ns] {
                    ProcessDetailActionResult action{};
                    const bool kSuccess = ProcessDetailPage::terminateAllThreadsIfProcessIdentityMatches(
                        kProcessId,
                        kExpectedProcessCreationTime100ns,
                        action.dialogText);
                    action.dialogTitle = L"结束进程";
                    action.dialogIcon = kSuccess ? MB_ICONINFORMATION : MB_ICONWARNING;
                    action.statusText = kSuccess
                        ? L"● 已在后台完成全部线程终止。"
                        : L"● 全部线程终止未完全成功。";
                    action.refreshRequired = kSuccess;
                    return action;
                });
            return true;
        }
        if (kMode == kTerminateModeMultiMethod) {
            if (!confirmDanger(hwnd_, L"将按多种结束方法依次处理目标进程。未保存的数据会丢失，是否继续？")) {
                return true;
            }
            executeProcessAction(static_cast<int>(ProcessActionId::kTerminateProcessMultiMethod));
            return true;
        }
        if (!confirmDanger(hwnd_, L"即将结束目标进程。未保存的数据会丢失，是否继续？")) {
            return true;
        }
        executeProcessAction(static_cast<int>(ProcessActionId::kTerminateProcess));
        return true;
    }
    case kActionSuspend: executeProcessAction(static_cast<int>(ProcessActionId::kSuspendProcess)); return true;
    case kActionResume: executeProcessAction(static_cast<int>(ProcessActionId::kResumeProcess)); return true;
    case kActionSetCritical:
        if (confirmDanger(hwnd_, L"把普通进程设为关键进程可能导致系统蓝屏，是否继续？")) {
            executeProcessAction(static_cast<int>(ProcessActionId::kSetCriticalProcess));
        }
        return true;
    case kActionClearCritical: executeProcessAction(static_cast<int>(ProcessActionId::kClearCriticalProcess)); return true;
    case kActionApplyPriority: {
        const int kSelected = static_cast<int>(::SendMessageW(findControl(TabIndex::kActions, kActionPriority), CB_GETCURSEL, 0, 0));
        constexpr std::array<ProcessActionId, 6> kActions{
            ProcessActionId::kSetPriorityIdle,
            ProcessActionId::kSetPriorityBelowNormal,
            ProcessActionId::kSetPriorityNormal,
            ProcessActionId::kSetPriorityAboveNormal,
            ProcessActionId::kSetPriorityHigh,
            ProcessActionId::kSetPriorityRealtime
        };
        if (kSelected >= 0 && kSelected < static_cast<int>(kActions.size())) {
            executeProcessAction(static_cast<int>(kActions[static_cast<std::size_t>(kSelected)]));
        }
        return true;
    }
    case kActionOpenFolder: executeProcessAction(static_cast<int>(ProcessActionId::kOpenFolder)); return true;
    case kActionRefreshPpl: executeProcessAction(static_cast<int>(ProcessActionId::kRefreshPplProtectionLevel)); return true;
    case kActionEfficiencyOn: executeProcessAction(static_cast<int>(ProcessActionId::kEnableEfficiencyMode)); return true;
    case kActionEfficiencyOff: executeProcessAction(static_cast<int>(ProcessActionId::kDisableEfficiencyMode)); return true;
    case kActionR0Terminate: executeProcessAction(static_cast<int>(ProcessActionId::kR0TerminateProcess)); return true;
    case kActionR0Suspend: executeProcessAction(static_cast<int>(ProcessActionId::kR0SuspendProcess)); return true;
    case kActionR0Ppl: {
        HMENU menu = ::CreatePopupMenu();
        // Order matches the process list right-click menu: first PPL (Type=1), then full PP (Type=2).
        const std::array<std::pair<const wchar_t*, ProcessActionId>, 13> kItems{{
            { L"关闭进程保护 (0x00)", ProcessActionId::kR0SetPplNone },
            { L"PPL Authenticode [0x11]", ProcessActionId::kR0SetPplAuthenticode },
            { L"PPL CodeGen [0x21]", ProcessActionId::kR0SetPplCodeGen },
            { L"PPL Antimalware [0x31]", ProcessActionId::kR0SetPplAntimalware },
            { L"PPL Lsa [0x41]", ProcessActionId::kR0SetPplLsa },
            { L"PPL Windows [0x51]", ProcessActionId::kR0SetPplWindows },
            { L"PPL WinTcb [0x61]", ProcessActionId::kR0SetPplWinTcb },
            { L"PP Authenticode [0x12]", ProcessActionId::kR0SetPpAuthenticode },
            { L"PP CodeGen [0x22]", ProcessActionId::kR0SetPpCodeGen },
            { L"PP Antimalware [0x32]", ProcessActionId::kR0SetPpAntimalware },
            { L"PP Lsa [0x42]", ProcessActionId::kR0SetPpLsa },
            { L"PP Windows [0x52]", ProcessActionId::kR0SetPpWindows },
            { L"PP WinTcb [0x62]", ProcessActionId::kR0SetPpWinTcb }
        }};
        for (std::size_t i = 0; i < kItems.size(); ++i) {
            ::AppendMenuW(menu, MF_STRING, 1 + static_cast<UINT>(i), kItems[i].first);
        }
        RECT button{}; ::GetWindowRect(findControl(TabIndex::kActions, kActionR0Ppl), &button);
        const UINT kCommand = ::TrackPopupMenu(menu, TPM_RETURNCMD, button.left, button.bottom, 0, hwnd_, nullptr);
        ::DestroyMenu(menu);
        if (kCommand && confirmDanger(hwnd_, L"修改 PPL/PP 保护字段依赖正确的内核偏移，错误操作可能导致系统崩溃。是否继续？")) {
            executeProcessAction(static_cast<int>(kItems[kCommand - 1].second));
        }
        return true;
    }
    case kActionR0Hide: {
        HMENU menu = ::CreatePopupMenu();
        const std::array<std::pair<const wchar_t*, ProcessActionId>, 5> kItems{{
            { L"隐藏：只断链", ProcessActionId::kR0HideUnlinkOnly },
            { L"隐藏：只改PID", ProcessActionId::kR0HidePatchPidOnly },
            { L"隐藏：改PID+断链(高风险)", ProcessActionId::kR0HideLegacyBoth },
            { L"取消隐藏", ProcessActionId::kR0UnhideProcess },
            { L"清空全部隐藏标记", ProcessActionId::kR0ClearHiddenMarks }
        }};
        for (std::size_t i = 0; i < kItems.size(); ++i) {
            ::AppendMenuW(menu, MF_STRING, 1 + static_cast<UINT>(i), kItems[i].first);
        }
        RECT button{}; ::GetWindowRect(findControl(TabIndex::kActions, kActionR0Hide), &button);
        const UINT kCommand = ::TrackPopupMenu(menu, TPM_RETURNCMD, button.left, button.bottom, 0, hwnd_, nullptr);
        ::DestroyMenu(menu);
        if (kCommand && confirmDanger(hwnd_, L"DKOM 隐藏操作存在竞态和系统崩溃风险，是否继续？")) {
            executeProcessAction(static_cast<int>(kItems[kCommand - 1].second));
        }
        return true;
    }
    case kActionR0Danger: {
        HMENU menu = ::CreatePopupMenu();
        const std::array<std::pair<const wchar_t*, ProcessActionId>, 4> kItems{{
            { L"启用 BreakOnTermination", ProcessActionId::kR0EnableBreakOnTermination },
            { L"关闭 BreakOnTermination", ProcessActionId::kR0DisableBreakOnTermination },
            { L"禁止APC插入(现有线程)", ProcessActionId::kR0DisableApcInsertion },
            { L"DKOM从PspCidTable删除", ProcessActionId::kR0DkomRemoveFromCidTable }
        }};
        for (std::size_t i = 0; i < kItems.size(); ++i) {
            ::AppendMenuW(menu, MF_STRING, 1 + static_cast<UINT>(i), kItems[i].first);
        }
        RECT button{}; ::GetWindowRect(findControl(TabIndex::kActions, kActionR0Danger), &button);
        const UINT kCommand = ::TrackPopupMenu(menu, TPM_RETURNCMD, button.left, button.bottom, 0, hwnd_, nullptr);
        ::DestroyMenu(menu);
        if (kCommand && confirmDanger(hwnd_, L"该 R0 操作可能造成进程不可恢复或系统崩溃，是否继续？")) {
            executeProcessAction(static_cast<int>(kItems[kCommand - 1].second));
        }
        return true;
    }
    case kActionBrowseDll: browseForPayload(true); return true;
    case kActionBrowseShellcode: browseForPayload(false); return true;
    case kActionInjectDll:
    case kActionInjectShellcode: {
        const bool kDllMode = controlId == kActionInjectDll;
        const int kMode = static_cast<int>(::SendMessageW(findControl(TabIndex::kActions, kActionInjectionMode), CB_GETCURSEL, 0, 0));
        const std::wstring kPath = controlText(TabIndex::kActions, kDllMode ? kActionDllPath : kActionShellcodePath);
        if (kPath.empty()) {
            ::MessageBoxW(hwnd_, L"请先选择载入文件。", L"注入与载入", MB_OK | MB_ICONWARNING);
            return true;
        }
        if (kMode == 0) {
            ::MessageBoxW(hwnd_, L"Light 纯 Win32 版本尚未提供 R3 注入后端。", L"注入与载入", MB_OK | MB_ICONINFORMATION);
            return true;
        }
        if (!confirmR0Injection(hwnd_, kDllMode ? L"DLL 注入" : L"Shellcode 注入", processId_, kPath)) {
            setPageStatus(TabIndex::kActions, kActionStatus, L"● 用户取消 R0 注入。");
            return true;
        }
        const DWORD kProcessId = processId_;
        ksword::features::process::ProcessSnapshotRow actionTarget{};
        actionTarget.processId = kProcessId;
        actionTarget.creationTime100ns = expectedCreationTime100ns_;
        executeBackgroundAction(
            TabIndex::kActions,
            kActionStatus,
            kDllMode ? L"● 正在后台执行 R0 DLL 注入…" : L"● 正在后台执行 R0 Shellcode 注入…",
            [kDllMode, kProcessId, actionTarget, kPath] {
                const auto kResult = kDllMode
                    ? ksword::features::process::executeR0ProcessDllInjection({ kProcessId }, { actionTarget }, kPath)
                    : ksword::features::process::executeR0ProcessShellcodeInjection({ kProcessId }, { actionTarget }, kPath);
                ProcessDetailActionResult action{};
                action.refreshRequired = kResult.success;
                action.statusText = kResult.title + L"：" + kResult.detail;
                action.dialogTitle = kResult.title;
                action.dialogText = kResult.detail;
                action.dialogIcon = kResult.success ? MB_ICONINFORMATION : MB_ICONWARNING;
                return action;
            });
        return true;
    }
    default:
        return false;
    }
}

void ProcessDetailPage::executeProcessAction(int actionId) {
    using namespace ksword::features::process;
    ProcessSnapshotRow row{};
    row.processId = processId_;
    row.creationTime100ns = expectedCreationTime100ns_;
    row.parentProcessId = snapshot_.basic.parentProcessId;
    row.imageName = snapshot_.basic.processName;
    row.imagePath = snapshot_.basic.imagePath;
    const DWORD kProcessId = processId_;
    executeBackgroundAction(
        TabIndex::kActions,
        kActionStatus,
        L"● 正在后台执行进程操作…",
        [actionId, kProcessId, row = std::move(row)] {
            const ProcessActionResult kResult = ksword::features::process::executeProcessAction(
                static_cast<ProcessActionId>(actionId), { kProcessId }, { row });
            ProcessDetailActionResult action{};
            action.refreshRequired = kResult.success;
            action.statusText = kResult.title + L"：" + kResult.detail;
            action.dialogTitle = kResult.title;
            action.dialogText = kResult.detail;
            action.dialogIcon = kResult.success ? MB_ICONINFORMATION : MB_ICONWARNING;
            return action;
        });
}

void ProcessDetailPage::browseForPayload(bool dllMode) {
    wchar_t path[MAX_PATH * 4]{};
    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = hwnd_;
    dialog.lpstrFile = path;
    dialog.nMaxFile = static_cast<DWORD>(std::size(path));
    dialog.lpstrTitle = dllMode ? L"选择要注入的 DLL" : L"选择原始 Shellcode 文件";
    dialog.lpstrFilter = dllMode
        ? L"DLL Files (*.dll)\0*.dll\0All Files (*.*)\0*.*\0\0"
        : L"Binary Files (*.bin;*.dat)\0*.bin;*.dat\0All Files (*.*)\0*.*\0\0";
    dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_EXPLORER;
    if (::GetOpenFileNameW(&dialog)) {
        setControlText(TabIndex::kActions, dllMode ? kActionDllPath : kActionShellcodePath, path);
    }
}

} // namespace Ksword::Features::process_detail
