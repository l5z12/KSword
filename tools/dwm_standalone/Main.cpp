#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <CommCtrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include "Diagnostics.h"
#include <algorithm>
#include <cerrno>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <thread>

namespace
{
    using namespace ks::dwm_order;
    constexpr UINT kCompleted = WM_APP + 1;
    enum Id { kInspectId = 100, kAdminId, kDemoId, kRefreshId, kTargetId, kReferenceId, kPositionId, kMaintainId,
        kQueryId, kApplyId, kRestoreId, kStopId, kLogId, kObservationId, kNotesId, kIncludeId, kExportId };
    enum class Work { kInspect, kRequest, kExport };
    struct Job
    {
        Work work = Work::kInspect;
        HWND owner = nullptr;
        standalone::Diagnostic diagnostic;
        standalone::Operation operation;
        std::vector<standalone::Operation> history;
        std::filesystem::path destination;
        std::wstring observation, notes, error;
        bool includeImage = false;
        bool closeAfterRestore = false;
    };
    struct WindowItem { std::wstring text; WindowIdentity identity; };
    struct App
    {
        HWND window = nullptr, diagnosticLine = nullptr, log = nullptr;
        HWND title = nullptr, scope = nullptr, targetLabel = nullptr, referenceLabel = nullptr, positionLabel = nullptr, resultLabel = nullptr;
        HWND target = nullptr, reference = nullptr, position = nullptr, maintain = nullptr, observation = nullptr, notes = nullptr;
        HWND includeImage = nullptr;
        HWND testA = nullptr, testB = nullptr;
        HFONT font = nullptr;
        std::vector<HWND> inputs;
        std::vector<WindowItem> windows;
        std::vector<standalone::Operation> history;
        standalone::Diagnostic diagnostic;
        std::shared_ptr<Job> job;
        std::thread worker;
        WindowIdentity held{};
        bool busy = false, closePending = false;
        UINT dpi = 96;
    } g;

    int px(int v) { return MulDiv(v, static_cast<int>(g.dpi), 96); }
    std::wstring text(HWND window)
    {
        const int kN = GetWindowTextLengthW(window);
        std::wstring s(static_cast<std::size_t>(kN) + 1, L'\0');
        s.resize(GetWindowTextW(window, s.data(), kN + 1));
        return s;
    }
    void log(const std::wstring& text) { SetWindowTextW(g.log, text.c_str()); }
    HWND item(const wchar_t* cls, const wchar_t* text, int id, DWORD style = 0)
    {
        const DWORD kExtra = wcscmp(cls, L"EDIT") == 0 ? WS_EX_CLIENTEDGE : 0;
        HWND h = CreateWindowExW(kExtra, cls, text, WS_CHILD | WS_VISIBLE | style,
            0, 0, 1, 1, g.window, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), GetModuleHandleW(nullptr), nullptr);
        if (!h) throw std::runtime_error("Cannot create UI control");
        SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(g.font), TRUE);
        if (id >= kInspectId && id != kLogId) g.inputs.push_back(h);
        return h;
    }
    void move(HWND h, int x, int y, int w, int height) { MoveWindow(h, px(x), px(y), px(w), px(height), TRUE); }
    void moveId(int id, int x, int y, int w, int height) { move(GetDlgItem(g.window, id), x, y, w, height); }

    void layout()
    {
        RECT r{};
        GetClientRect(g.window, &r);
        const int kWidth = MulDiv(r.right, 96, static_cast<int>(g.dpi));
        const int kHeight = MulDiv(r.bottom, 96, static_cast<int>(g.dpi));
        const int kContent = kWidth - 36;
        move(g.title, 18, 12, kContent, 24);
        move(g.scope, 18, 39, kContent, 44);
        move(g.diagnosticLine, 18, 86, kContent, 43);
        moveId(kInspectId, 18, 134, 154, 30);
        moveId(kAdminId, 180, 134, 188, 30);
        moveId(kDemoId, 376, 134, 218, 30);
        moveId(kRefreshId, 602, 134, kContent - 584, 30);
        move(g.targetLabel, 18, 182, 117, 22);
        move(g.target, 135, 177, kContent - 117, 260);
        move(g.referenceLabel, 18, 220, 117, 22);
        move(g.reference, 135, 215, kContent - 117, 260);
        move(g.positionLabel, 18, 259, 117, 22);
        move(g.position, 135, 253, 356, 180);
        move(g.maintain, 506, 253, kContent - 488, 29);
        const int kActionWidth = (kContent - 24) / 4;
        for (int i = 0; i < 4; ++i) moveId(kQueryId + i, 18 + i * (kActionWidth + 8), 294, kActionWidth, 32);
        move(g.log, 18, 339, kContent, kHeight - 518);
        move(g.resultLabel, 18, kHeight - 169, kContent, 22);
        move(g.observation, 18, kHeight - 143, 250, 155);
        move(g.notes, 278, kHeight - 143, kContent - 260, 34);
        move(g.includeImage, 18, kHeight - 98, kContent, 26);
        moveId(kExportId, 18, kHeight - 55, kContent, 34);
    }

    void updateEnabled()
    {
        for (HWND input : g.inputs) EnableWindow(input, !g.busy);
        if (!g.busy)
        {
            const bool kElevated = standalone::isAdministrator();
            for (int id : {kQueryId, kApplyId, kRestoreId, kStopId}) EnableWindow(GetDlgItem(g.window, id), kElevated);
            EnableWindow(GetDlgItem(g.window, kAdminId), !kElevated);
            EnableWindow(g.reference, SendMessageW(g.position, CB_GETCURSEL, 0, 0) >= 2);
            EnableWindow(GetDlgItem(g.window, kExportId), !g.diagnostic.details.empty());
        }
    }

    BOOL CALLBACK enumerate(HWND window, LPARAM)
    {
        if (window == g.window || !IsWindowVisible(window) || GetAncestor(window, GA_ROOT) != window) return TRUE;
        wchar_t title[256]{};
        if (!GetWindowTextW(window, title, 256)) return TRUE;
        WindowIdentity identity;
        std::uint32_t error = 0;
        if (!captureWindow(reinterpret_cast<std::uint64_t>(window), identity, error)) return TRUE;
        std::wostringstream s;
        s << L"0x" << std::hex << identity.hwnd << std::dec << L"  [PID " << identity.processId << L"]  " << title;
        g.windows.push_back({s.str(), identity});
        return g.windows.size() < 4096;
    }

    void refresh()
    {
        const auto kOldTarget = text(g.target), kOldReference = text(g.reference);
        g.windows.clear();
        EnumWindows(enumerate, 0);
        for (HWND box : {g.target, g.reference})
        {
            SendMessageW(box, CB_RESETCONTENT, 0, 0);
            for (const auto& item : g.windows) SendMessageW(box, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(item.text.c_str()));
        }
        auto preserve = [](HWND box, const std::wstring& old)
        {
            const auto kAt = SendMessageW(box, CB_FINDSTRINGEXACT, static_cast<WPARAM>(-1), reinterpret_cast<LPARAM>(old.c_str()));
            if (kAt != CB_ERR) SendMessageW(box, CB_SETCURSEL, kAt, 0);
            else SetWindowTextW(box, old.c_str());
        };
        preserve(g.target, kOldTarget);
        preserve(g.reference, kOldReference);
    }

    bool identity(HWND box, WindowIdentity& result)
    {
        const auto kAt = SendMessageW(box, CB_GETCURSEL, 0, 0);
        const auto kInput = text(box);
        if (kAt >= 0 && static_cast<std::size_t>(kAt) < g.windows.size() && kInput == g.windows[kAt].text)
        { result = g.windows[kAt].identity; return true; }
        const auto kStart = kInput.find_first_not_of(L" \t");
        if (kStart == std::wstring::npos || kInput[kStart] == L'-' || kInput[kStart] == L'+') return false;
        wchar_t* end = nullptr;
        errno = 0;
        const int kBase = kInput.compare(kStart, 2, L"0x") == 0 || kInput.compare(kStart, 2, L"0X") == 0 ? 16 : 10;
        const auto kHandle = wcstoull(kInput.c_str() + kStart, &end, kBase);
        while (end && (*end == L' ' || *end == L'\t')) ++end;
        std::uint32_t error = 0;
        return !errno && end && !*end && kHandle && captureWindow(kHandle, result, error);
    }

    void begin(const std::shared_ptr<Job>& job)
    {
        if (g.busy) return;
        g.busy = true;
        g.job = job;
        job->owner = g.window;
        updateEnabled();
        log(L"正在处理，请稍候… / Working…\r\n操作期间仍可移动窗口。 / The window remains responsive.");
        try
        {
            g.worker = std::thread([job]
            {
                try
                {
                    if (job->work == Work::kInspect) job->diagnostic = standalone::inspect();
                    else if (job->work == Work::kRequest)
                    {
                        job->operation.time = standalone::timestamp();
                        job->operation.reply = executeRequest(job->operation.request, (standalone::executableDirectory() / L"KswordDwmZOrder.dll").wstring(), true);
                    }
                    else job->destination = standalone::saveReport(job->destination, job->diagnostic, job->history,
                        job->observation, job->notes, job->includeImage);
                }
                catch (const std::exception& e)
                {
                    job->error = L"操作失败 / Operation failed: ";
                    for (const char* p = e.what(); *p; ++p) job->error += static_cast<wchar_t>(static_cast<unsigned char>(*p));
                    job->operation.reply.response.status = Status::kInternalException;
                }
                catch (...) { job->error = L"未知异常 / Unexpected exception"; job->operation.reply.response.status = Status::kInternalException; }
                PostMessageW(job->owner, kCompleted, 0, 0);
            });
        }
        catch (...) { g.busy = false; g.job.reset(); updateEnabled(); log(L"无法启动工作线程 / Cannot start worker"); }
    }

    void start(Action action)
    {
        auto job = std::make_shared<Job>();
        job->work = Work::kRequest;
        auto& request = job->operation.request;
        request.action = action;
        request.position = static_cast<Position>(SendMessageW(g.position, CB_GETCURSEL, 0, 0));
        request.maintain = SendMessageW(g.maintain, BM_GETCHECK, 0, 0) == BST_CHECKED;
        if (action != Action::kStop && !identity(g.target, request.target))
        { log(L"请选择有效窗口，或输入十进制 / 0x 十六进制 HWND。\r\nSelect a window or enter its decimal / 0x hexadecimal HWND."); return; }
        if (action == Action::kApply && request.position >= Position::kBefore
            && (!identity(g.reference, request.reference) || request.reference.hwnd == request.target.hwnd))
        { log(L"请选择同一桌面上的另一个参照窗口。\r\nSelect another reference window on the same desktop."); return; }
        if (action == Action::kStop && MessageBoxW(g.window,
            L"将停止当前会话排序代理的全部保持（包括 KSword 设置的保持），并恢复系统顺序。\nStop all ordering maintenance in this session, including KSword, and restore system order?",
            L"停止全部 / Stop all", MB_OKCANCEL | MB_ICONQUESTION) != IDOK) return;
        begin(job);
    }

    LRESULT CALLBACK testWindow(HWND window, UINT message, WPARAM wParam, LPARAM lParam)
    {
        if (message == WM_NCCREATE)
        {
            SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(reinterpret_cast<CREATESTRUCTW*>(lParam)->lpCreateParams));
            return DefWindowProcW(window, message, wParam, lParam);
        }
        if (message == WM_PAINT)
        {
            PAINTSTRUCT p{};
            HDC dc = BeginPaint(window, &p);
            RECT rect{}; GetClientRect(window, &rect);
            const bool kA = GetWindowLongPtrW(window, GWLP_USERDATA) == 1;
            HBRUSH brush = CreateSolidBrush(kA ? RGB(32, 102, 178) : RGB(168, 65, 45));
            FillRect(dc, &rect, brush); DeleteObject(brush);
            SetTextColor(dc, RGB(255, 255, 255)); SetBkMode(dc, TRANSPARENT);
            const auto kOld = SelectObject(dc, GetStockObject(DEFAULT_GUI_FONT));
            DrawTextW(dc, kA ? L"A\n目标窗口 / Target\n\n观察与 B 的重叠区域\nObserve the overlap with B"
                : L"B\n参照窗口 / Reference\n\n反复激活此窗口，检查持续保持\nActivate this window repeatedly to test maintenance", -1, &rect, DT_CENTER | DT_WORDBREAK);
            SelectObject(dc, kOld); EndPaint(window, &p); return 0;
        }
        return DefWindowProcW(window, message, wParam, lParam);
    }

    void demos()
    {
        RECT rect{}; GetWindowRect(g.window, &rect);
        if (!IsWindow(g.testA)) g.testA = CreateWindowExW(0, L"DwmOrderTestWindow", L"DWM Test A / 蓝色目标",
            WS_OVERLAPPEDWINDOW | WS_VISIBLE, rect.left + px(40), rect.top + px(80), px(370), px(260),
            nullptr, nullptr, GetModuleHandleW(nullptr), reinterpret_cast<void*>(1));
        if (!IsWindow(g.testB)) g.testB = CreateWindowExW(0, L"DwmOrderTestWindow", L"DWM Test B / 红色参照",
            WS_OVERLAPPEDWINDOW | WS_VISIBLE, rect.left + px(170), rect.top + px(150), px(370), px(260),
            nullptr, nullptr, GetModuleHandleW(nullptr), reinterpret_cast<void*>(2));
        if (!IsWindow(g.testA) || !IsWindow(g.testB))
        { log(L"测试窗口创建失败 / Cannot create test windows."); return; }
        refresh();
        bool selectedA = false, selectedB = false;
        for (std::size_t i = 0; i < g.windows.size(); ++i)
        {
            if (g.windows[i].identity.hwnd == reinterpret_cast<std::uint64_t>(g.testA)) { SendMessageW(g.target, CB_SETCURSEL, i, 0); selectedA = true; }
            if (g.windows[i].identity.hwnd == reinterpret_cast<std::uint64_t>(g.testB)) { SendMessageW(g.reference, CB_SETCURSEL, i, 0); selectedB = true; }
        }
        if (!selectedA || !selectedB)
        {
            WindowIdentity identity;
            std::uint32_t errorA = 0, errorB = 0;
            captureWindow(reinterpret_cast<std::uint64_t>(g.testA), identity, errorA);
            captureWindow(reinterpret_cast<std::uint64_t>(g.testB), identity, errorB);
            log(L"测试窗口未进入可选列表 / Test windows missing from selectors.\r\nA visible=" + std::to_wstring(IsWindowVisible(g.testA))
                + L", identity error=" + std::to_wstring(errorA) + L", title=" + text(g.testA)
                + L"\r\nB visible=" + std::to_wstring(IsWindowVisible(g.testB)) + L", identity error=" + std::to_wstring(errorB) + L", title=" + text(g.testB));
            return;
        }
        log(L"已选 A 为目标、B 为参照。请应用排序并观察重叠区域。\r\nA is the target; B is the reference. Apply an order and inspect the overlap.\r\n\r\n这两个普通窗口不代表 UIAccess / 系统层验证。\r\nThese ordinary windows do not validate UIAccess or system-band coverage.");
    }

    void Export()
    {
        wchar_t path[32768] = L"DwmOrder-report.txt";
        OPENFILENAMEW dialog{};
        dialog.lStructSize = sizeof(dialog); dialog.hwndOwner = g.window;
        dialog.lpstrFilter = L"报告位置 / Report location\0*.txt\0\0";
        dialog.lpstrFile = path; dialog.nMaxFile = 32768;
        dialog.lpstrTitle = L"选择存放位置；会创建带时间戳的报告文件夹 / Choose report location";
        dialog.Flags = OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
        dialog.lpstrDefExt = L"txt";
        if (!GetSaveFileNameW(&dialog)) return;
        auto job = std::make_shared<Job>();
        job->work = Work::kExport;
        job->destination = std::filesystem::path(path).parent_path();
        job->diagnostic = g.diagnostic; job->history = g.history;
        job->observation = text(g.observation); job->notes = text(g.notes);
        job->includeImage = SendMessageW(g.includeImage, BM_GETCHECK, 0, 0) == BST_CHECKED;
        begin(job);
    }

    void close()
    {
        if (g.busy) { g.closePending = true; log(L"等待当前操作完成后关闭… / Closing after the current operation finishes…"); return; }
        g.closePending = false;
        if (g.held.hwnd)
        {
            const int kChoice = MessageBoxW(g.window, L"此工具可能仍在持续保持窗口。关闭前恢复吗？\n是：恢复后关闭。否：保留保持并退出。\n\nThis tool may still be maintaining a window. Restore before closing?\nYes: restore and close. No: leave maintenance running.",
                L"退出 / Exit", MB_YESNOCANCEL | MB_ICONQUESTION);
            if (kChoice == IDCANCEL) return;
            if (kChoice == IDYES)
            {
                auto job = std::make_shared<Job>(); job->work = Work::kRequest;
                job->operation.request.action = Action::kRestore; job->operation.request.target = g.held;
                job->closeAfterRestore = true; begin(job); return;
            }
        }
        DestroyWindow(g.window);
    }

    void finish()
    {
        if (g.worker.joinable()) g.worker.join();
        auto job = std::move(g.job);
        g.busy = false;
        if (!job) return;
        if (job->work == Work::kInspect)
        {
            g.diagnostic = job->diagnostic;
            SetWindowTextW(g.diagnosticLine, g.diagnostic.summary.c_str());
            log(g.diagnostic.details);
        }
        else if (job->work == Work::kRequest)
        {
            const auto& r = job->operation.reply.response;
            const auto& q = job->operation.request;
            if (g.history.size() == 200) g.history.erase(g.history.begin());
            g.history.push_back(job->operation);
            // Keep a conservative owner identity for timeout/partial outcomes.
            if (q.action == Action::kApply && q.maintain && (r.maintainedWindow == q.target.hwnd
                || r.status == Status::kTimeout || r.status == Status::kInternalException)) g.held = q.target;
            if (r.dwmProcessId && !(r.flags & kMaintaining) && r.status == Status::kOk) g.held = {};
            std::wstring text = standalone::statusText(r.status) + L"\r\n";
            if (r.flags & kMaintaining) text += L"持续保持中 / Maintaining\r\n";
            if (r.windowCount) text += L"合成位置 / Position: " + std::to_wstring(r.index + 1) + L" / " + std::to_wstring(r.windowCount) + L" (1 = 最前 / front)\r\n";
            text += L"\r\n" + standalone::formatOperation(job->operation);
            log(text);
        }
        else log(L"报告已保存 / Report saved:\r\n" + job->destination.wstring()
            + L"\r\n\r\n请检查后将整个报告文件夹压缩并交给维护者。程序不会自动上传。\r\nReview and zip this folder for the maintainer. Nothing is uploaded automatically.");
        if (!job->error.empty()) log(job->error);
        updateEnabled();
        if (job->closeAfterRestore)
        {
            if (job->error.empty() && job->operation.reply.response.status == Status::kOk) { DestroyWindow(g.window); return; }
            g.closePending = false;
            log(text(g.log) + L"\r\n\r\n恢复未确认成功，已保留窗口和报告。\r\nRestore was not confirmed; the tool and report remain available.");
        }
        else if (g.closePending) close();
    }

    void createUi()
    {
        g.dpi = GetDpiForWindow(g.window);
        g.font = CreateFontW(-px(15), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
            CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        g.title = item(L"STATIC", L"DWM Order Tool 1.0  ·  独立窗口排序与兼容性测试", 0);
        g.scope = item(L"STATIC", L"Win11 24H2 x64；Win10 19041 系列 x64（实验性 / experimental）。\r\n跨 Band 合成排序；鼠标命中、焦点不变。 / Composition order only; input and focus are unchanged.", 0);
        g.diagnosticLine = item(L"STATIC", L"正在读取本机 DWM 文件 / Inspecting local DWM file…", 0);
        item(L"BUTTON", L"文件诊断 / Inspect", kInspectId, WS_TABSTOP);
        item(L"BUTTON", L"管理员重启 / Elevate", kAdminId, WS_TABSTOP);
        item(L"BUTTON", L"创建测试窗口 / Test A + B", kDemoId, WS_TABSTOP);
        item(L"BUTTON", L"刷新 / Refresh", kRefreshId, WS_TABSTOP);
        g.targetLabel = item(L"STATIC", L"目标 / Target", 0);
        g.referenceLabel = item(L"STATIC", L"参照 / Reference", 0);
        g.positionLabel = item(L"STATIC", L"位置 / Position", 0);
        g.target = item(L"COMBOBOX", L"", kTargetId, CBS_DROPDOWN | CBS_AUTOHSCROLL | WS_VSCROLL | WS_TABSTOP);
        g.reference = item(L"COMBOBOX", L"", kReferenceId, CBS_DROPDOWN | CBS_AUTOHSCROLL | WS_VSCROLL | WS_TABSTOP);
        SendMessageW(g.target, CB_LIMITTEXT, 512, 0); SendMessageW(g.reference, CB_LIMITTEXT, 512, 0);
        g.position = item(L"COMBOBOX", L"", kPositionId, CBS_DROPDOWNLIST | WS_TABSTOP);
        for (const auto* text : {L"合成最前 / Front", L"合成最后 / Back", L"参照上方 / Above reference", L"参照下方 / Below reference"})
            SendMessageW(g.position, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(text));
        SendMessageW(g.position, CB_SETCURSEL, 0, 0);
        g.maintain = item(L"BUTTON", L"持续保持 / Maintain", kMaintainId, BS_AUTOCHECKBOX | WS_TABSTOP);
        SendMessageW(g.maintain, BM_SETCHECK, BST_UNCHECKED, 0);
        item(L"BUTTON", L"连接读取 / Query", kQueryId, WS_TABSTOP);
        item(L"BUTTON", L"应用顺序 / Apply", kApplyId, WS_TABSTOP);
        item(L"BUTTON", L"恢复目标 / Restore", kRestoreId, WS_TABSTOP);
        item(L"BUTTON", L"停止全部 / Stop all", kStopId, WS_TABSTOP);
        g.log = item(L"EDIT", L"", kLogId, ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL | WS_TABSTOP);
        SendMessageW(g.log, EM_SETLIMITTEXT, 200000, 0);
        g.resultLabel = item(L"STATIC", L"实际观察（请另测跨 UIAccess） / Visual observation (test UIAccess separately)", 0);
        g.observation = item(L"COMBOBOX", L"", kObservationId, CBS_DROPDOWNLIST | WS_TABSTOP);
        for (const auto* text : {L"未实测 / Not tested", L"效果正常 / Works", L"效果异常 / Incorrect", L"DWM 重启或崩溃 / DWM restarted"})
            SendMessageW(g.observation, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(text));
        SendMessageW(g.observation, CB_SETCURSEL, 0, 0);
        g.notes = item(L"EDIT", L"", kNotesId, ES_AUTOHSCROLL | WS_TABSTOP);
        SendMessageW(g.notes, EM_SETLIMITTEXT, 2000, 0);
        SendMessageW(g.notes, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(L"补充现象 / Notes (optional)"));
        g.includeImage = item(L"BUTTON", L"附带本机 uDWM.dll 以便适配（可选） / Include system uDWM.dll (optional)", kIncludeId, BS_AUTOCHECKBOX | WS_TABSTOP);
        item(L"BUTTON", L"导出兼容性报告 / Export compatibility report", kExportId, WS_TABSTOP);
        layout(); refresh(); updateEnabled();
        begin(std::make_shared<Job>());
    }

    LRESULT CALLBACK mainWindow(HWND window, UINT message, WPARAM wParam, LPARAM lParam)
    {
        try
        {
            switch (message)
            {
            case WM_CREATE: g.window = window; createUi(); return 0;
            case WM_SIZE: if (g.log) layout(); return 0;
            case WM_GETMINMAXINFO:
            {
                auto* info = reinterpret_cast<MINMAXINFO*>(lParam);
                MONITORINFO monitor{sizeof(monitor)};
                GetMonitorInfoW(MonitorFromWindow(window, MONITOR_DEFAULTTONEAREST), &monitor);
                info->ptMinTrackSize = {(std::min)(px(790), static_cast<int>(monitor.rcWork.right - monitor.rcWork.left)),
                    (std::min)(px(650), static_cast<int>(monitor.rcWork.bottom - monitor.rcWork.top))}; return 0;
            }
            case WM_DPICHANGED:
            {
                g.dpi = HIWORD(wParam);
                const auto* rect = reinterpret_cast<RECT*>(lParam);
                LOGFONTW lf{}; GetObjectW(g.font, sizeof(lf), &lf); lf.lfHeight = -px(15);
                HFONT replacement = CreateFontIndirectW(&lf);
                if (replacement)
                {
                    for (HWND child = GetWindow(window, GW_CHILD); child; child = GetWindow(child, GW_HWNDNEXT))
                        SendMessageW(child, WM_SETFONT, reinterpret_cast<WPARAM>(replacement), TRUE);
                    DeleteObject(g.font); g.font = replacement;
                }
                SetWindowPos(window, nullptr, rect->left, rect->top, rect->right - rect->left, rect->bottom - rect->top, SWP_NOZORDER | SWP_NOACTIVATE);
                layout(); return 0;
            }
            case kCompleted: finish(); return 0;
            case WM_COMMAND:
                if (g.busy) return 0;
                switch (LOWORD(wParam))
                {
                case kInspectId: begin(std::make_shared<Job>()); break;
                case kAdminId:
                {
                    const auto kExe = standalone::executableDirectory() / L"DwmOrderTool.exe";
                    const auto kResult = reinterpret_cast<INT_PTR>(ShellExecuteW(window, L"runas", kExe.c_str(), nullptr, standalone::executableDirectory().c_str(), SW_SHOWNORMAL));
                    if (kResult > 32) DestroyWindow(window);
                    else log(L"管理员重启未完成 / Elevation was cancelled or failed.");
                    break;
                }
                case kDemoId: demos(); break;
                case kRefreshId: refresh(); break;
                case kPositionId: updateEnabled(); break;
                case kQueryId: start(Action::kQuery); break;
                case kApplyId: start(Action::kApply); break;
                case kRestoreId: start(Action::kRestore); break;
                case kStopId: start(Action::kStop); break;
                case kExportId: Export(); break;
                }
                return 0;
            case WM_CLOSE: close(); return 0;
            case WM_DESTROY:
                if (IsWindow(g.testA)) DestroyWindow(g.testA);
                if (IsWindow(g.testB)) DestroyWindow(g.testB);
                if (g.font) DeleteObject(g.font);
                PostQuitMessage(0); return 0;
            }
        }
        catch (...) { if (message == WM_CREATE) return -1; log(L"界面操作失败 / UI operation failed"); }
        return DefWindowProcW(window, message, wParam, lParam);
    }
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show)
{
    try
    {
        int argc = 0;
        auto** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
        if (!argv) return 1;
        if (argc != 1)
        {
            const std::wstring kCommand = argc > 1 ? argv[1] : L"";
            const std::filesystem::path kOutput = argc == 3 ? argv[2] : L"";
            LocalFree(argv);
            if (argc != 3) return 64;
            if (kCommand == L"--self-test") return standalone::selfTest(kOutput);
            if (kCommand == L"--diagnose")
            {
                const auto kDiagnostic = standalone::inspect();
                standalone::saveReport(kOutput, kDiagnostic, {}, L"not tested", L"CLI file inspection; no injection", false);
                return kDiagnostic.complete ? (kDiagnostic.modelMatched ? 0 : 2) : 1;
            }
            return 64;
        }
        LocalFree(argv);
        INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_STANDARD_CLASSES};
        InitCommonControlsEx(&controls);
        WNDCLASSEXW cls{sizeof(cls)};
        cls.hInstance = instance; cls.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        cls.hIcon = LoadIconW(nullptr, IDI_APPLICATION); cls.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
        cls.lpfnWndProc = mainWindow; cls.lpszClassName = L"DwmOrderStandalone";
        if (!RegisterClassExW(&cls)) return 1;
        cls.lpfnWndProc = testWindow; cls.lpszClassName = L"DwmOrderTestWindow";
        if (!RegisterClassExW(&cls)) return 1;
        g.dpi = GetDpiForSystem();
        MONITORINFO monitor{sizeof(monitor)};
        GetMonitorInfoW(MonitorFromPoint(POINT{0, 0}, MONITOR_DEFAULTTOPRIMARY), &monitor);
        HWND window = CreateWindowExW(WS_EX_CONTROLPARENT, L"DwmOrderStandalone", L"DWM Order Tool / 独立兼容性测试",
            WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
            (std::min)(px(860), static_cast<int>(monitor.rcWork.right - monitor.rcWork.left)),
            (std::min)(px(780), static_cast<int>(monitor.rcWork.bottom - monitor.rcWork.top)), nullptr, nullptr, instance, nullptr);
        if (!window) return 1;
        ShowWindow(window, show); UpdateWindow(window);
        MSG message{};
        while (GetMessageW(&message, nullptr, 0, 0) > 0)
            if (!IsDialogMessageW(window, &message)) { TranslateMessage(&message); DispatchMessageW(&message); }
        if (g.worker.joinable()) g.worker.join();
        return static_cast<int>(message.wParam);
    }
    catch (...) { return 1; }
}
