#include "NetToolsDiagnosticView.h"

#include "NetToolsDiagnostics.h"
#include "../../ui/AsyncTask.h"
#include "../../ui/Controls.h"
#include "../../ui/ExportUtil.h"
#include "../../ui/LoadingOverlay.h"
#include "../../ui/TextFindSupport.h"
#include "../../ui/Theme.h"

#include <commctrl.h>
#include <windowsx.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace ksword::features::net_tools {
namespace {

constexpr wchar_t kDiagnosticViewClass[] = L"KswordARKLight.NetTools.DiagnosticView";

constexpr int kTargetLabelId = 66201;
constexpr int kTargetEditId = 66202;
constexpr int kPingButtonId = 66203;
constexpr int kTraceButtonId = 66204;
constexpr int kDnsButtonId = 66205;
constexpr int kDnsTypeComboId = 66206;
constexpr int kCopyButtonId = 66207;
constexpr int kClearButtonId = 66208;
constexpr int kOutputEditId = 66209;
constexpr int kLoadingOverlayId = 66210;
constexpr int kRefreshButtonId = 66211;
constexpr int kExportButtonId = 66212;
constexpr int kFindButtonId = 66213;

constexpr UINT kMsgDiagnosticCompleted = WM_APP + 675;

constexpr int kGap = 6;
constexpr int kRowHeight = 24;
constexpr int kHeaderHeight = kGap * 3 + kRowHeight * 2;
constexpr int kStatusHeight = 22;

// kPingTimeoutMs and kTraceTimeoutMs bound the worst case a user can wait. The
// trace timeout is deliberately shorter: a ping waits four times, a trace waits
// once per hop, so the same value would turn an unreachable target into a
// minute-long run with no output.
constexpr std::uint32_t kPingTimeoutMs = 2000;
constexpr std::uint32_t kTraceTimeoutMs = 1500;
constexpr std::uint32_t kPingEchoCount = 4;
constexpr std::uint32_t kTraceMaxHops = 30;

int width(const RECT& rc) {
    return rc.right > rc.left ? static_cast<int>(rc.right - rc.left) : 0;
}

int height(const RECT& rc) {
    return rc.bottom > rc.top ? static_cast<int>(rc.bottom - rc.top) : 0;
}

struct DiagnosticViewState final {
    HWND hwnd = nullptr;
    HWND targetLabel = nullptr;
    HWND targetEdit = nullptr;
    HWND pingButton = nullptr;
    HWND traceButton = nullptr;
    HWND dnsButton = nullptr;
    HWND dnsTypeCombo = nullptr;
    HWND refreshButton = nullptr;
    HWND exportButton = nullptr;
    HWND findButton = nullptr;
    HWND copyButton = nullptr;
    HWND clearButton = nullptr;
    HWND outputEdit = nullptr;
    HWND loadingOverlay = nullptr;
    std::wstring statusText = L"填写目标主机名或 IP 地址后选择一种探测方式。";
    bool probeInProgress = false;
    std::optional<DiagnosticRequest> lastRequest;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<DiagnosticResult>> probeTask;
};

bool copyText(HWND owner, const std::wstring& text) {
    if (text.empty() || !::OpenClipboard(owner)) {
        return false;
    }
    ::EmptyClipboard();
    const SIZE_T kBytes = (text.size() + 1) * sizeof(wchar_t);
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
    if (!::SetClipboardData(CF_UNICODETEXT, memory)) {
        ::GlobalFree(memory);
        ::CloseClipboard();
        return false;
    }
    ::CloseClipboard();
    return true;
}

std::wstring windowText(HWND control) {
    if (!control) {
        return {};
    }
    const int kLength = ::GetWindowTextLengthW(control);
    if (kLength <= 0) {
        return {};
    }
    std::wstring text(static_cast<std::size_t>(kLength) + 1, L'\0');
    const int kCopied = ::GetWindowTextW(control, text.data(), kLength + 1);
    text.resize(kCopied > 0 ? static_cast<std::size_t>(kCopied) : 0);
    return text;
}

std::wstring trimText(std::wstring value) {
    const auto kBegin = std::find_if_not(value.begin(), value.end(), [](const wchar_t ch) { return std::iswspace(ch) != 0; });
    const auto kEnd = std::find_if_not(value.rbegin(), value.rend(), [](const wchar_t ch) { return std::iswspace(ch) != 0; }).base();
    return kBegin >= kEnd ? std::wstring{} : std::wstring(kBegin, kEnd);
}

void updateActionButtons(DiagnosticViewState& state) {
    const BOOL kEnabled = state.probeInProgress ? FALSE : TRUE;
    for (HWND control : { state.pingButton, state.traceButton, state.dnsButton, state.dnsTypeCombo, state.targetEdit }) {
        if (control) {
            ::EnableWindow(control, kEnabled);
        }
    }
    if (state.refreshButton) {
        ::EnableWindow(state.refreshButton, kEnabled && state.lastRequest.has_value() ? TRUE : FALSE);
    }
    if (state.exportButton) {
        ::EnableWindow(state.exportButton, kEnabled);
    }
    if (state.findButton) {
        ::EnableWindow(state.findButton, kEnabled);
    }
}

void setOutputText(DiagnosticViewState& state, const std::wstring& text) {
    if (!state.outputEdit) {
        return;
    }
    ::SetWindowTextW(state.outputEdit, text.c_str());
    // Scroll back to the top: the interesting part of a ping or a trace is the
    // first line, and an EDIT keeps whatever caret position it had.
    ::SendMessageW(state.outputEdit, EM_SETSEL, 0, 0);
    ::SendMessageW(state.outputEdit, EM_SCROLLCARET, 0, 0);
}

void submitProbe(DiagnosticViewState& state, const DiagnosticRequest& request) {
    if (state.probeInProgress) {
        state.statusText = L"已有网络诊断正在执行，请等待其完成。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }

    state.probeInProgress = true;
    updateActionButtons(state);
    ksword::ui::setLoadingOverlay(state.loadingOverlay, true, L"正在执行网络诊断…");
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
    state.probeTask->request(
        [request] { return runDiagnostic(request); },
        [&state](std::uint64_t, std::optional<DiagnosticResult>&& result, std::exception_ptr error) {
            state.probeInProgress = false;
            ksword::ui::setLoadingOverlay(state.loadingOverlay, false);
            updateActionButtons(state);
            if (error || !result.has_value()) {
                state.statusText = L"网络诊断异常结束。";
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            setOutputText(state, result->text);
            state.statusText = result->summary;
            ::InvalidateRect(state.hwnd, nullptr, TRUE);
        });
}

void beginProbe(DiagnosticViewState& state, const DiagnosticKind kind) {
    if (!state.probeTask) {
        return;
    }
    const std::wstring kTarget = trimText(windowText(state.targetEdit));
    if (kTarget.empty()) {
        state.statusText = L"请先填写目标主机名或 IP 地址。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }

    DiagnosticRequest request{};
    request.kind = kind;
    request.target = kTarget;
    switch (kind) {
    case DiagnosticKind::kPing:
        request.echoCount = kPingEchoCount;
        request.timeoutMs = kPingTimeoutMs;
        state.statusText = L"正在后台 Ping " + kTarget + L"…";
        break;
    case DiagnosticKind::kTraceRoute:
        request.maxHops = kTraceMaxHops;
        request.timeoutMs = kTraceTimeoutMs;
        state.statusText = L"正在后台跟踪到 " + kTarget + L" 的路由，最多 " +
            std::to_wstring(kTraceMaxHops) + L" 跳…";
        break;
    case DiagnosticKind::kDnsLookup: {
        const LRESULT kSelection = state.dnsTypeCombo ? ::SendMessageW(state.dnsTypeCombo, CB_GETCURSEL, 0, 0) : 0;
        const int kChoice = kSelection == CB_ERR ? 0 : static_cast<int>(kSelection);
        request.dnsRecordType = dnsRecordTypeChoiceValue(kChoice);
        state.statusText = std::wstring(L"正在后台查询 ") + kTarget + L" 的 " +
            dnsRecordTypeChoiceLabel(kChoice) + L" 记录…";
        break;
    }
    }

    state.lastRequest = request;
    submitProbe(state, request);
}

void refreshLastProbe(DiagnosticViewState& state) {
    if (!state.lastRequest.has_value()) {
        state.statusText = L"请先执行一次网络诊断。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }
    state.statusText = L"正在重新执行上次网络诊断…";
    submitProbe(state, *state.lastRequest);
}

void exportDiagnosticOutput(DiagnosticViewState& state) {
    const std::wstring kText = windowText(state.outputEdit);
    if (kText.empty()) {
        state.statusText = L"没有可导出的诊断输出。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }
    std::wstring error;
    switch (ksword::ui::saveUtf8TextFileWithDialog(
        state.hwnd, L"network_diagnostic.txt", L"导出网络诊断",
        L"Text (*.txt)\0*.txt\0All Files (*.*)\0*.*\0", L"txt", kText, &error)) {
    case ksword::ui::SaveTextFileResult::kSaved:
        state.statusText = L"已导出网络诊断输出。";
        break;
    case ksword::ui::SaveTextFileResult::kCancelled:
        state.statusText = L"已取消导出网络诊断。";
        break;
    case ksword::ui::SaveTextFileResult::kFailed:
        state.statusText = L"导出网络诊断失败：" + error;
        break;
    }
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

void layoutView(DiagnosticViewState& state) {
    RECT client{};
    ::GetClientRect(state.hwnd, &client);
    const int kWidth = width(client);
    const int kHeight = height(client);

    const int kRowY = kGap;
    int cursorX = kGap;
    const auto kPlace = [&cursorX, kRowY](HWND control, int controlWidth, int controlHeight) {
        if (control) {
            ::MoveWindow(control, cursorX, kRowY, controlWidth, controlHeight, TRUE);
        }
        cursorX += controlWidth + kGap;
    };

    kPlace(state.targetLabel, 40, kRowHeight);
    // The target box takes whatever is left after the fixed-width probe controls
    // so a long URL or an IPv6 literal stays readable on a narrow dock.
    const int kFixedWidth = 40 + 72 + 88 + 88 + 92 + kGap * 6;
    kPlace(state.targetEdit, (std::max)(120, kWidth - kFixedWidth), kRowHeight);
    kPlace(state.pingButton, 72, kRowHeight);
    kPlace(state.traceButton, 88, kRowHeight);
    kPlace(state.dnsButton, 88, kRowHeight);
    // The combo needs room for its drop-down list, which Win32 sizes from the
    // control height rather than from the item count.
    if (state.dnsTypeCombo) {
        ::MoveWindow(state.dnsTypeCombo, cursorX, kRowY, 92, kRowHeight * 10, TRUE);
    }

    const int kToolsY = kRowY + kRowHeight + kGap;
    cursorX = kGap;
    const auto kPlaceTool = [&cursorX, kToolsY](HWND control, int controlWidth) {
        if (control) {
            ::MoveWindow(control, cursorX, kToolsY, controlWidth, kRowHeight, TRUE);
        }
        cursorX += controlWidth + kGap;
    };
    kPlaceTool(state.refreshButton, 64);
    kPlaceTool(state.exportButton, 82);
    kPlaceTool(state.findButton, 64);
    kPlaceTool(state.copyButton, 64);
    kPlaceTool(state.clearButton, 64);

    const int kOutputTop = kHeaderHeight;
    const int kOutputHeight = (std::max)(0, kHeight - kOutputTop - kStatusHeight - kGap);
    if (state.outputEdit) {
        ::MoveWindow(state.outputEdit, kGap, kOutputTop, (std::max)(0, kWidth - kGap * 2), kOutputHeight, TRUE);
    }
    if (state.loadingOverlay) {
        ::MoveWindow(state.loadingOverlay, kGap, kOutputTop, (std::max)(0, kWidth - kGap * 2), kOutputHeight, TRUE);
    }
}

bool createChildControls(DiagnosticViewState& state) {
    HWND hwnd = state.hwnd;
    state.targetLabel = ksword::ui::createText(hwnd, kTargetLabelId, L"目标", 0, 0, 0, 0);
    state.targetEdit = ::CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_LEFT | ES_AUTOHSCROLL,
        0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kTargetEditId)),
        ::GetModuleHandleW(nullptr), nullptr);
    state.pingButton = ksword::ui::createButton(hwnd, kPingButtonId, L"Ping", 0, 0, 0, 0);
    state.traceButton = ksword::ui::createButton(hwnd, kTraceButtonId, L"路由跟踪", 0, 0, 0, 0);
    state.dnsButton = ksword::ui::createButton(hwnd, kDnsButtonId, L"DNS 查询", 0, 0, 0, 0);
    state.refreshButton = ksword::ui::createButton(hwnd, kRefreshButtonId, L"刷新", 0, 0, 0, 0);
    state.exportButton = ksword::ui::createButton(hwnd, kExportButtonId, L"导出", 0, 0, 0, 0);
    state.findButton = ksword::ui::createButton(hwnd, kFindButtonId, L"查找", 0, 0, 0, 0);
    state.copyButton = ksword::ui::createButton(hwnd, kCopyButtonId, L"复制", 0, 0, 0, 0);
    state.clearButton = ksword::ui::createButton(hwnd, kClearButtonId, L"清空", 0, 0, 0, 0);

    state.dnsTypeCombo = ::CreateWindowExW(0, WC_COMBOBOXW, L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST | CBS_HASSTRINGS,
        0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kDnsTypeComboId)),
        ::GetModuleHandleW(nullptr), nullptr);
    if (!state.dnsTypeCombo) {
        return false;
    }
    for (int index = 0; index < dnsRecordTypeChoiceCount(); ++index) {
        ::SendMessageW(state.dnsTypeCombo, CB_ADDSTRING, 0,
            reinterpret_cast<LPARAM>(dnsRecordTypeChoiceLabel(index)));
    }
    ::SendMessageW(state.dnsTypeCombo, CB_SETCURSEL, 0, 0);

    state.outputEdit = ::CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | WS_HSCROLL |
            ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_READONLY,
        0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kOutputEditId)),
        ::GetModuleHandleW(nullptr), nullptr);
    if (state.outputEdit) {
        // The output routinely runs to dozens of lines, and a read-only EDIT has
        // no way to look through it without the shared find bar.
        ksword::ui::attachTextFindSupport(state.outputEdit);
    }

    state.loadingOverlay = ksword::ui::createLoadingOverlay(hwnd, kLoadingOverlayId, { 0, 0, 1, 1 });
    if (!state.targetLabel || !state.targetEdit || !state.pingButton || !state.traceButton || !state.dnsButton ||
        !state.refreshButton || !state.exportButton || !state.findButton ||
        !state.copyButton || !state.clearButton || !state.outputEdit || !state.loadingOverlay) {
        return false;
    }

    ksword::ui::setWindowFontRecursive(hwnd);
    return true;
}

LRESULT CALLBACK diagnosticViewProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    auto* state = reinterpret_cast<DiagnosticViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (msg) {
    case WM_NCCREATE: {
        auto owned = std::make_unique<DiagnosticViewState>();
        owned->hwnd = hwnd;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(owned.release()));
        return TRUE;
    }
    case WM_CREATE:
        if (state) {
            if (!createChildControls(*state)) {
                return -1;
            }
            state->probeTask =
                std::make_unique<ksword::ui::AsyncSnapshotTask<DiagnosticResult>>(hwnd, kMsgDiagnosticCompleted);
            layoutView(*state);
            updateActionButtons(*state);
        }
        return 0;
    case WM_SIZE:
        if (state) {
            layoutView(*state);
        }
        return 0;
    case WM_COMMAND:
        if (!state) {
            break;
        }
        if (HIWORD(wParam) == BN_CLICKED) {
            switch (LOWORD(wParam)) {
            case kPingButtonId:
                beginProbe(*state, DiagnosticKind::kPing);
                return 0;
            case kTraceButtonId:
                beginProbe(*state, DiagnosticKind::kTraceRoute);
                return 0;
            case kDnsButtonId:
                beginProbe(*state, DiagnosticKind::kDnsLookup);
                return 0;
            case kRefreshButtonId:
                refreshLastProbe(*state);
                return 0;
            case kExportButtonId:
                exportDiagnosticOutput(*state);
                return 0;
            case kFindButtonId:
                ksword::ui::openTextFindSupport(state->outputEdit);
                return 0;
            case kCopyButtonId:
                state->statusText = copyText(hwnd, windowText(state->outputEdit)) ? L"已复制诊断结果。" : L"复制失败。";
                ::InvalidateRect(hwnd, nullptr, TRUE);
                return 0;
            case kClearButtonId:
                setOutputText(*state, {});
                state->statusText = L"已清空诊断结果。";
                ::InvalidateRect(hwnd, nullptr, TRUE);
                return 0;
            default:
                break;
            }
        }
        break;
    case WM_CTLCOLORSTATIC:
        // Only the label is themed here. A read-only EDIT also reports through
        // WM_CTLCOLORSTATIC, and forcing a transparent background on it smears
        // the text as soon as the user scrolls.
        if (state && reinterpret_cast<HWND>(lParam) == state->targetLabel) {
            HDC dc = reinterpret_cast<HDC>(wParam);
            ::SetBkMode(dc, TRANSPARENT);
            ::SetTextColor(dc, ksword::ui::appTheme().textColor);
            return reinterpret_cast<LRESULT>(ksword::ui::appTheme().windowBrush());
        }
        break;
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT:
        if (state) {
            PAINTSTRUCT paint{};
            HDC dc = ::BeginPaint(hwnd, &paint);
            RECT client{};
            ::GetClientRect(hwnd, &client);
            ::FillRect(dc, &client, ksword::ui::appTheme().windowBrush());
            RECT statusRect{ kGap, client.bottom - kStatusHeight, client.right - kGap, client.bottom };
            ksword::ui::drawTextLine(dc, state->statusText, statusRect,
                ksword::ui::appTheme().mutedTextColor, ksword::ui::systemUiFont(),
                DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
            ::EndPaint(hwnd, &paint);
            return 0;
        }
        break;
    default:
        if (state && msg == kMsgDiagnosticCompleted && state->probeTask) {
            state->probeTask->consume(hwnd, wParam, lParam);
            return 0;
        }
        if (msg == WM_NCDESTROY && state) {
            // Cancel before destruction so a completion callback cannot run
            // against a half-torn-down state. The worker itself is not
            // interruptible: a running trace finishes into a dropped result.
            if (state->probeTask) {
                state->probeTask->cancel();
            }
            delete state;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        }
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

bool ensureDiagnosticViewClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = diagnosticViewProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = ksword::ui::appTheme().windowBrush();
    windowClass.lpszClassName = kDiagnosticViewClass;
    registered = ::RegisterClassW(&windowClass) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

} // namespace

HWND createNetToolsDiagnosticView(HWND parent, const RECT& bounds) {
    if (!parent || !ensureDiagnosticViewClass()) {
        return nullptr;
    }
    return ::CreateWindowExW(
        0, kDiagnosticViewClass, L"", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        bounds.left, bounds.top, bounds.right - bounds.left, bounds.bottom - bounds.top,
        parent, nullptr, ::GetModuleHandleW(nullptr), nullptr);
}

} // namespace Ksword::Features::NetTools
