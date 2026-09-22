#include "IoctlDecoderView.h"

#include "IoctlDecoder.h"
#include "../../ui/Controls.h"
#include "../../ui/ExportUtil.h"
#include "../../ui/TextFindSupport.h"
#include "../../ui/Theme.h"

#include <algorithm>
#include <memory>
#include <string>

namespace ksword::features::sys_tools {
namespace {

constexpr wchar_t kIoctlDecoderViewClass[] = L"KswordARKLight.SysTools.IoctlDecoderView";
constexpr int kInputEditId = 67501;
constexpr int kCopyButtonId = 67502;
constexpr int kClearButtonId = 67503;
constexpr int kReportEditId = 67504;
constexpr int kGap = 8;
constexpr int kRowHeight = 24;
constexpr int kHeaderHeight = 76;
constexpr int kStatusHeight = 22;

struct IoctlDecoderViewState final {
    HWND hwnd = nullptr;
    HWND inputEdit = nullptr;
    HWND copyButton = nullptr;
    HWND clearButton = nullptr;
    HWND reportEdit = nullptr;
    std::wstring reportText;
    std::wstring statusText = L"请输入一个 32 位十六进制 IOCTL 控制码。";
};

int width(const RECT& rect) {
    return rect.right > rect.left ? static_cast<int>(rect.right - rect.left) : 0;
}

int height(const RECT& rect) {
    return rect.bottom > rect.top ? static_cast<int>(rect.bottom - rect.top) : 0;
}

std::wstring windowText(const HWND control) {
    if (!control) {
        return {};
    }
    const int kLength = ::GetWindowTextLengthW(control);
    if (kLength <= 0) {
        return {};
    }
    std::wstring value(static_cast<std::size_t>(kLength) + 1U, L'\0');
    ::GetWindowTextW(control, value.data(), kLength + 1);
    value.resize(static_cast<std::size_t>(kLength));
    return value;
}

void applyDecode(IoctlDecoderViewState& state) {
    const IoctlDecodedFields kDecoded = decodeIoctlCode(windowText(state.inputEdit));
    switch (kDecoded.state) {
    case IoctlDecodeState::kEmpty:
        state.reportText = L"请输入十六进制 IOCTL 控制码。\r\n\r\n例如：0x222004";
        state.statusText = L"请输入一个 32 位十六进制 IOCTL 控制码。";
        break;
    case IoctlDecodeState::kInvalid:
        state.reportText = L"输入无效：请输入 1 至 8 位十六进制控制码，可带 0x 前缀。";
        state.statusText = L"输入无效，尚未读取驱动或设备。";
        break;
    case IoctlDecodeState::kValid:
        state.reportText = buildIoctlDecodedReport(kDecoded);
        state.statusText = L"已离线解析 " + formatIoctlCode(kDecoded.code) + L"；未读取驱动或设备。";
        break;
    default:
        break;
    }
    if (state.reportEdit) {
        ::SetWindowTextW(state.reportEdit, state.reportText.c_str());
    }
    if (state.copyButton) {
        ::EnableWindow(state.copyButton, kDecoded.state == IoctlDecodeState::kValid ? TRUE : FALSE);
    }
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

void layoutView(IoctlDecoderViewState& state) {
    RECT client{};
    ::GetClientRect(state.hwnd, &client);
    const int kWidth = width(client);
    const int kHeight = height(client);
    const int kInputLeft = kGap + 108;
    const int kButtonWidth = 76;
    const int kClearLeft = (std::max)(kGap, kWidth - kGap - kButtonWidth);
    const int kCopyLeft = (std::max)(kGap, kClearLeft - kGap - kButtonWidth);
    const int kInputWidth = (std::max)(80, kCopyLeft - kInputLeft - kGap);

    if (state.inputEdit) {
        ::MoveWindow(state.inputEdit, kInputLeft, kGap + kRowHeight, kInputWidth, kRowHeight, TRUE);
    }
    if (state.copyButton) {
        ::MoveWindow(state.copyButton, kCopyLeft, kGap + kRowHeight, kButtonWidth, kRowHeight, TRUE);
    }
    if (state.clearButton) {
        ::MoveWindow(state.clearButton, kClearLeft, kGap + kRowHeight, kButtonWidth, kRowHeight, TRUE);
    }
    const int kReportTop = kHeaderHeight;
    const int kReportHeight = (std::max)(0, kHeight - kReportTop - kStatusHeight - kGap);
    if (state.reportEdit) {
        ::MoveWindow(state.reportEdit, kGap, kReportTop, (std::max)(0, kWidth - kGap * 2), kReportHeight, TRUE);
    }
}

bool createChildControls(IoctlDecoderViewState& state) {
    state.inputEdit = ::CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        0, 0, 0, 0, state.hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kInputEditId)),
        ::GetModuleHandleW(nullptr), nullptr);
    state.copyButton = ksword::ui::createButton(state.hwnd, kCopyButtonId, L"复制结果", 0, 0, 0, 0);
    state.clearButton = ksword::ui::createButton(state.hwnd, kClearButtonId, L"清空", 0, 0, 0, 0);
    state.reportEdit = ::CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | WS_HSCROLL |
            ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_READONLY,
        0, 0, 0, 0, state.hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kReportEditId)),
        ::GetModuleHandleW(nullptr), nullptr);
    if (!state.inputEdit || !state.copyButton || !state.clearButton || !state.reportEdit) {
        return false;
    }
    ::SendMessageW(state.inputEdit, WM_SETFONT, reinterpret_cast<WPARAM>(ksword::ui::systemUiFont()), TRUE);
    ::SendMessageW(state.reportEdit, WM_SETFONT, reinterpret_cast<WPARAM>(ksword::ui::systemUiFont()), TRUE);
    ksword::ui::attachTextFindSupport(state.reportEdit);
    ksword::ui::setWindowFontRecursive(state.hwnd);
    applyDecode(state);
    return true;
}

LRESULT CALLBACK ioctlDecoderViewProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    auto* state = reinterpret_cast<IoctlDecoderViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (msg) {
    case WM_NCCREATE: {
        auto owned = std::make_unique<IoctlDecoderViewState>();
        owned->hwnd = hwnd;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(owned.release()));
        return TRUE;
    }
    case WM_CREATE:
        if (state && !createChildControls(*state)) {
            return -1;
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
        if (LOWORD(wParam) == kInputEditId && HIWORD(wParam) == EN_CHANGE) {
            applyDecode(*state);
            return 0;
        }
        if (HIWORD(wParam) == BN_CLICKED && LOWORD(wParam) == kCopyButtonId) {
            state->statusText = ksword::ui::copyTextToClipboard(hwnd, state->reportText, L"IOCTL 解码结果")
                ? L"已复制 IOCTL 解码结果，并已记录到证据会话。"
                : L"复制 IOCTL 解码结果失败。";
            ::InvalidateRect(hwnd, nullptr, TRUE);
            return 0;
        }
        if (HIWORD(wParam) == BN_CLICKED && LOWORD(wParam) == kClearButtonId) {
            ::SetWindowTextW(state->inputEdit, L"");
            ::SetFocus(state->inputEdit);
            return 0;
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
            RECT descriptionRect{ kGap, kGap, client.right - kGap, kGap + kRowHeight };
            ksword::ui::drawTextLine(dc,
                L"输入 32 位 IOCTL 控制码，离线解析 CTL_CODE 字段与位布局。",
                descriptionRect,
                ksword::ui::appTheme().textColor,
                ksword::ui::systemUiFont(),
                DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
            RECT inputLabelRect{ kGap, kGap + kRowHeight, kGap + 102, kGap + kRowHeight * 2 };
            ksword::ui::drawTextLine(dc,
                L"IOCTL（十六进制）：",
                inputLabelRect,
                ksword::ui::appTheme().textColor,
                ksword::ui::systemUiFont(),
                DT_LEFT | DT_VCENTER | DT_SINGLELINE);
            RECT statusRect{ kGap, client.bottom - kStatusHeight, client.right - kGap, client.bottom };
            ksword::ui::drawTextLine(dc,
                state->statusText,
                statusRect,
                ksword::ui::appTheme().mutedTextColor,
                ksword::ui::systemUiFont(),
                DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
            ::EndPaint(hwnd, &paint);
            return 0;
        }
        break;
    case WM_CTLCOLORSTATIC: {
        HDC dc = reinterpret_cast<HDC>(wParam);
        ::SetBkMode(dc, TRANSPARENT);
        ::SetTextColor(dc, ksword::ui::appTheme().textColor);
        return reinterpret_cast<LRESULT>(ksword::ui::appTheme().windowBrush());
    }
    case WM_NCDESTROY:
        delete state;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        break;
    default:
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

bool ensureIoctlDecoderViewClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = ioctlDecoderViewProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = ksword::ui::appTheme().windowBrush();
    windowClass.lpszClassName = kIoctlDecoderViewClass;
    registered = ::RegisterClassW(&windowClass) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

} // namespace

HWND createIoctlDecoderView(HWND parent, const RECT& bounds) {
    if (!parent || !ensureIoctlDecoderViewClass()) {
        return nullptr;
    }
    return ::CreateWindowExW(0,
        kIoctlDecoderViewClass,
        L"",
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        bounds.left,
        bounds.top,
        bounds.right - bounds.left,
        bounds.bottom - bounds.top,
        parent,
        nullptr,
        ::GetModuleHandleW(nullptr),
        nullptr);
}

} // namespace Ksword::Features::SysTools
