#include "../../core/Win32Lean.h"

#include <commctrl.h>
#include <shellapi.h>

#include "ProcessDetailPage.h"

#include <algorithm>
#include <array>
#include <iomanip>
#include <sstream>
#include <string>

namespace ksword::features::process_detail {
namespace {

constexpr int kDetailMargin = 6;
constexpr int kDetailLabelWidth = 126;
constexpr int kDetailValueLeft = 166;

std::wstring displayText(const std::wstring& text, const wchar_t* fallback = L"-") {
    return text.empty() ? std::wstring(fallback) : text;
}

std::wstring workingSetText(const ULONGLONG bytes, const bool known) {
    if (!known) {
        return L"-";
    }
    std::wostringstream text;
    text << std::fixed << std::setprecision(1)
         << (static_cast<double>(bytes) / (1024.0 * 1024.0))
         << L" MB";
    return text.str();
}

void makeRightAligned(HWND label) {
    if (!label) {
        return;
    }
    LONG_PTR style = ::GetWindowLongPtrW(label, GWL_STYLE);
    style &= ~static_cast<LONG_PTR>(SS_TYPEMASK);
    style |= SS_RIGHT | SS_CENTERIMAGE | SS_NOTIFY;
    ::SetWindowLongPtrW(label, GWL_STYLE, style);
}

bool allCreated(std::initializer_list<HWND> controls) {
    return std::all_of(controls.begin(), controls.end(), [](HWND control) {
        return control != nullptr;
    });
}

} // namespace

bool ProcessDetailPage::createDetailTab() {
    const TabIndex kTab = TabIndex::kDetail;

    HWND title = addLabel(kTab, kDetailTitle, L"Unknown  (PID: 0)", 6, 6, -12, 40);
    applyFont(title, titleFont_);

    HWND pathLabel = addLabel(kTab, 0, L"程序路径:", 6, 54, 92, 28);
    makeRightAligned(pathLabel);
    HWND path = addEdit(kTab, kDetailPath, L"-", true, false, 104, 54, -260, 28);
    HWND copyPath = addButton(kTab, kDetailCopyPath, L"复制", -224, 54, 78, 28);
    HWND openFolder = addButton(kTab, kDetailOpenFolder, L"打开文件夹", -138, 54, 132, 28);

    HWND commandLabel = addLabel(kTab, 0, L"启动命令行:", 6, 88, 92, 28);
    makeRightAligned(commandLabel);
    HWND command = addEdit(kTab, kDetailCommandLine, L"-", true, false, 104, 88, -162, 28);
    HWND copyCommand = addButton(kTab, kDetailCopyCommand, L"复制", -84, 88, 78, 28);

    HWND parentLabel = addLabel(kTab, 0, L"父进程:", 6, 122, 92, 28);
    makeRightAligned(parentLabel);
    HWND parentText = addLabel(kTab, kDetailParentText, L"无父进程信息", 104, 122, -344, 28);
    HWND openHandles = addButton(kTab, kDetailOpenHandles, L"句柄", -210, 122, 32, 28);
    HWND gotoParent = addButton(kTab, kDetailGotoParent, L"转到父进程", -170, 122, 164, 28);
    ::ShowWindow(gotoParent, SW_HIDE);

    HWND detailGroup = addGroup(kTab, L"更多进程详细数据", 6, 158, -12, -12);

    struct DetailField {
        const wchar_t* label;
        int controlId;
    };
    constexpr std::array<DetailField, 12> kFields{
        DetailField{ L"启动时间", kDetailStartTime },
        DetailField{ L"用户", kDetailUser },
        DetailField{ L"管理员", kDetailAdmin },
        DetailField{ L"架构", kDetailArchitecture },
        DetailField{ L"优先级", kDetailPriority },
        DetailField{ L"Session ID", kDetailSession },
        DetailField{ L"线程数量", kDetailThreadCount },
        DetailField{ L"句柄数量", kDetailHandleCount },
        DetailField{ L"CPU 占用", kDetailCpu },
        DetailField{ L"RAM 占用", kDetailRam },
        DetailField{ L"DISK 吞吐", kDetailDisk },
        DetailField{ L"数字签名", kDetailSignature }
    };

    bool fieldsCreated = true;
    int y = 184;
    for (const DetailField& field : kFields) {
        HWND label = addLabel(kTab, 0, field.label, 24, y, kDetailLabelWidth, 25);
        makeRightAligned(label);
        HWND value = addLabel(kTab, field.controlId, L"-", kDetailValueLeft, y, -188, 25);
        fieldsCreated = fieldsCreated && label && value;
        y += 30;
    }

    return fieldsCreated && allCreated({
        title,
        pathLabel,
        path,
        copyPath,
        openFolder,
        commandLabel,
        command,
        copyCommand,
        parentLabel,
        parentText,
        openHandles,
        gotoParent,
        detailGroup
    });
}

void ProcessDetailPage::populateDetailTab() {
    const ProcessBasicInfo& basic = snapshot_.basic;
    const std::wstring kProcessName = displayText(basic.processName, L"Unknown");

    setControlText(
        TabIndex::kDetail,
        kDetailTitle,
        kProcessName + L"  (PID: " + std::to_wstring(basic.processId) + L")");
    setControlText(TabIndex::kDetail, kDetailPath, displayText(basic.imagePath));
    setControlText(TabIndex::kDetail, kDetailCommandLine, displayText(basic.commandLine));

    if (basic.parentProcessId == 0) {
        setControlText(TabIndex::kDetail, kDetailParentText, L"无父进程信息");
        ::ShowWindow(findControl(TabIndex::kDetail, kDetailGotoParent), SW_HIDE);
    } else {
        if (basic.parentProcessName.empty()) {
            setControlText(
                TabIndex::kDetail,
                kDetailParentText,
                L"父进程已退出或不可访问 (PID: " + std::to_wstring(basic.parentProcessId) + L")");
            ::ShowWindow(findControl(TabIndex::kDetail, kDetailGotoParent), SW_HIDE);
        } else {
            setControlText(
                TabIndex::kDetail,
                kDetailParentText,
                basic.parentProcessName + L" (PID: " + std::to_wstring(basic.parentProcessId) + L")");
            ::ShowWindow(findControl(TabIndex::kDetail, kDetailGotoParent), SW_SHOW);
        }
    }

    setControlText(TabIndex::kDetail, kDetailStartTime, displayText(basic.startTimeText));
    setControlText(TabIndex::kDetail, kDetailUser, displayText(basic.userName));
    setControlText(
        TabIndex::kDetail,
        kDetailAdmin,
        basic.adminKnown ? (basic.isAdmin ? L"■ 是" : L"■ 否") : L"■ 未知");
    setControlText(TabIndex::kDetail, kDetailArchitecture, displayText(basic.bitness, L"Unknown"));
    setControlText(TabIndex::kDetail, kDetailPriority, displayText(basic.priorityText, L"Unknown"));
    setControlText(TabIndex::kDetail, kDetailSession, std::to_wstring(basic.sessionId));
    setControlText(TabIndex::kDetail, kDetailThreadCount, std::to_wstring(latestThreadCount()));
    setControlText(
        TabIndex::kDetail,
        kDetailHandleCount,
        snapshot_.basicSucceeded ? std::to_wstring(basic.handleCount) : L"-");
    setControlText(TabIndex::kDetail, kDetailCpu, L"-");
    setControlText(TabIndex::kDetail, kDetailRam, workingSetText(basic.workingSetBytes, snapshot_.basicSucceeded));
    setControlText(TabIndex::kDetail, kDetailDisk, L"-");
    setControlText(TabIndex::kDetail, kDetailSignature, L"-");

    ::EnableWindow(findControl(TabIndex::kDetail, kDetailOpenHandles), processId_ != 0);
    ::EnableWindow(
        findControl(TabIndex::kDetail, kDetailOpenFolder),
        !basic.imagePath.empty());
}

bool ProcessDetailPage::handleDetailCommand(int controlId) {
    switch (controlId) {
    case kDetailCopyPath:
        copyText(hwnd_, controlText(TabIndex::kDetail, kDetailPath));
        return true;
    case kDetailOpenFolder: {
        const std::wstring kPath = controlText(TabIndex::kDetail, kDetailPath);
        if (kPath.empty() || kPath == L"-") {
            return true;
        }
        const std::wstring kArguments = L"/select,\"" + kPath + L"\"";
        const HINSTANCE kResult = ::ShellExecuteW(
            hwnd_,
            L"open",
            L"explorer.exe",
            kArguments.c_str(),
            nullptr,
            SW_SHOWNORMAL);
        if (reinterpret_cast<INT_PTR>(kResult) <= 32) {
            ::MessageBoxW(hwnd_, L"无法打开程序所在文件夹。", L"进程详细信息", MB_OK | MB_ICONWARNING);
        }
        return true;
    }
    case kDetailCopyCommand:
        copyText(hwnd_, controlText(TabIndex::kDetail, kDetailCommandLine));
        return true;
    case kDetailOpenHandles:
        ::MessageBoxW(
            hwnd_,
            L"纯 Win32 详情宿主尚未提供句柄 Dock 跳转。",
            L"进程详细信息",
            MB_OK | MB_ICONINFORMATION);
        return true;
    case kDetailGotoParent:
        ::MessageBoxW(
            hwnd_,
            L"纯 Win32 详情宿主尚未提供父进程窗口跳转。",
            L"进程详细信息",
            MB_OK | MB_ICONINFORMATION);
        return true;
    default:
        return false;
    }
}

} // namespace Ksword::Features::process_detail
