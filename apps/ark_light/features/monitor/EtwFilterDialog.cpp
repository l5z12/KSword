#include "EtwFilterDialog.h"

#include "../../ui/Controls.h"
#include "EtwEventModel.h"

#include <commctrl.h>
#include <windowsx.h>
#include <cwchar>
#include <iterator>

namespace ksword::features::monitor {
namespace {

constexpr wchar_t kEtwFilterDialogClass[] = L"KswordARKLight.EtwFilterDialog";
constexpr int kProviderListId = 51001;
constexpr int kPidEditId = 51002;
constexpr int kLevelComboId = 51003;
constexpr int kCurrentProcessCheckId = 51004;
constexpr int kOkButtonId = IDOK;
constexpr int kCancelButtonId = IDCANCEL;

void ensureDialogClass() {
    static bool registered = false;
    if (registered) {
        return;
    }

    WNDCLASSW wc{};
    wc.lpfnWndProc = &EtwFilterDialog::wndProc;
    wc.hInstance = ::GetModuleHandleW(nullptr);
    wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName = kEtwFilterDialogClass;
    ::RegisterClassW(&wc);
    registered = true;
}

void setControlFont(HWND hwnd) {
    if (hwnd != nullptr) {
        ::SendMessageW(hwnd, WM_SETFONT, reinterpret_cast<WPARAM>(ksword::ui::systemUiFont()), TRUE);
    }
}

} // namespace

EtwFilterDialog::EtwFilterDialog(HWND parent, const EtwFilterState& initialState)
    : parent_(parent), state_(initialState) {}

bool EtwFilterDialog::showModal(EtwFilterState& stateOut) {
    ensureDialogClass();
    hwnd_ = ::CreateWindowExW(
        WS_EX_DLGMODALFRAME | WS_EX_WINDOWEDGE,
        kEtwFilterDialogClass,
        L"ETW 筛选器",
        WS_POPUP | WS_CAPTION | WS_SYSMENU,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        620,
        430,
        parent_,
        nullptr,
        ::GetModuleHandleW(nullptr),
        this);
    if (hwnd_ == nullptr) {
        return false;
    }

    if (parent_ != nullptr) {
        ::EnableWindow(parent_, FALSE);
    }
    ::ShowWindow(hwnd_, SW_SHOW);
    ::UpdateWindow(hwnd_);

    MSG msg{};
    while (!finished_ && ::GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if (!::IsDialogMessageW(hwnd_, &msg)) {
            ::TranslateMessage(&msg);
            ::DispatchMessageW(&msg);
        }
    }

    if (parent_ != nullptr) {
        ::EnableWindow(parent_, TRUE);
        ::SetForegroundWindow(parent_);
    }
    if (accepted_) {
        stateOut = state_;
    }
    return accepted_;
}

LRESULT CALLBACK EtwFilterDialog::wndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    EtwFilterDialog* dialog = reinterpret_cast<EtwFilterDialog*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        dialog = cs ? static_cast<EtwFilterDialog*>(cs->lpCreateParams) : nullptr;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(dialog));
        if (dialog != nullptr) {
            dialog->hwnd_ = hwnd;
        }
    }
    return dialog != nullptr ? dialog->handleMessage(hwnd, msg, wParam, lParam) : ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

LRESULT EtwFilterDialog::handleMessage(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE:
        createControls();
        loadStateToControls();
        layout();
        return 0;
    case WM_SIZE:
        layout();
        return 0;
    case WM_COMMAND:
        if (LOWORD(wParam) == kOkButtonId) {
            if (saveControlsToState()) {
                closeWithResult(true);
            }
            return 0;
        }
        if (LOWORD(wParam) == kCancelButtonId) {
            closeWithResult(false);
            return 0;
        }
        break;
    case WM_CLOSE:
        closeWithResult(false);
        return 0;
    case WM_DESTROY:
        finished_ = true;
        return 0;
    default:
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

void EtwFilterDialog::createControls() {
    ksword::ui::createText(hwnd_, 0, L"Providers:", 16, 14, 160, 22);
    providerList_ = ::CreateWindowExW(
        WS_EX_CLIENTEDGE,
        WC_LISTVIEWW,
        L"",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
        16,
        42,
        560,
        200,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kProviderListId)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    ListView_SetExtendedListViewStyle(providerList_, LVS_EX_CHECKBOXES | LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    LVCOLUMNW column{};
    column.mask = LVCF_TEXT | LVCF_WIDTH;
    column.cx = 245;
    column.pszText = const_cast<LPWSTR>(L"Provider");
    ListView_InsertColumn(providerList_, 0, &column);
    column.cx = 285;
    column.pszText = const_cast<LPWSTR>(L"GUID");
    ListView_InsertColumn(providerList_, 1, &column);
    setControlFont(providerList_);

    ksword::ui::createText(hwnd_, 0, L"PID(0=全部):", 16, 256, 100, 22);
    pidEdit_ = ::CreateWindowExW(
        WS_EX_CLIENTEDGE,
        L"EDIT",
        L"0",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL | ES_NUMBER,
        120,
        254,
        120,
        24,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kPidEditId)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    setControlFont(pidEdit_);

    ksword::ui::createText(hwnd_, 0, L"最低级别:", 270, 256, 80, 22);
    levelCombo_ = ::CreateWindowExW(
        0,
        L"COMBOBOX",
        L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST,
        350,
        252,
        160,
        160,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kLevelComboId)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    setControlFont(levelCombo_);
    ComboBox_AddString(levelCombo_, L"Verbose");
    ComboBox_AddString(levelCombo_, L"Information");
    ComboBox_AddString(levelCombo_, L"Warning");
    ComboBox_AddString(levelCombo_, L"Error");
    ComboBox_AddString(levelCombo_, L"Critical");

    currentProcessCheck_ = ::CreateWindowExW(
        0,
        L"BUTTON",
        L"仅当前 KswordARKLight 进程",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
        16,
        292,
        260,
        24,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kCurrentProcessCheckId)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    setControlFont(currentProcessCheck_);

    okButton_ = ksword::ui::createButton(hwnd_, kOkButtonId, L"确定", 410, 340, 80, 28);
    cancelButton_ = ksword::ui::createButton(hwnd_, kCancelButtonId, L"取消", 500, 340, 80, 28);
}

void EtwFilterDialog::layout() {
    RECT rc{};
    ::GetClientRect(hwnd_, &rc);
    const int kWidth = rc.right - rc.left;
    const int kHeight = rc.bottom - rc.top;
    ::MoveWindow(providerList_, 16, 42, kWidth - 32, kHeight - 190, TRUE);
    ::MoveWindow(pidEdit_, 120, kHeight - 132, 120, 24, TRUE);
    ::MoveWindow(levelCombo_, 350, kHeight - 134, 160, 160, TRUE);
    ::MoveWindow(currentProcessCheck_, 16, kHeight - 96, 260, 24, TRUE);
    ::MoveWindow(okButton_, kWidth - 190, kHeight - 48, 80, 28, TRUE);
    ::MoveWindow(cancelButton_, kWidth - 100, kHeight - 48, 80, 28, TRUE);
}

void EtwFilterDialog::loadStateToControls() {
    ListView_DeleteAllItems(providerList_);
    for (std::size_t index = 0; index < state_.providers.size(); ++index) {
        const EtwProviderPreset& provider = state_.providers[index];
        LVITEMW item{};
        item.mask = LVIF_TEXT;
        item.iItem = static_cast<int>(index);
        item.pszText = const_cast<LPWSTR>(provider.name.c_str());
        ListView_InsertItem(providerList_, &item);
        const std::wstring kGuidText = guidToString(provider.providerGuid);
        ListView_SetItemText(providerList_, static_cast<int>(index), 1, const_cast<LPWSTR>(kGuidText.c_str()));
        ListView_SetCheckState(providerList_, static_cast<int>(index), provider.enabled ? TRUE : FALSE);
    }

    wchar_t pidText[32] = {};
    std::swprintf(pidText, std::size(pidText), L"%lu", state_.processId);
    ::SetWindowTextW(pidEdit_, pidText);

    int levelIndex = 0;
    if (state_.minimumLevel <= TRACE_LEVEL_CRITICAL) {
        levelIndex = 4;
    } else if (state_.minimumLevel <= TRACE_LEVEL_ERROR) {
        levelIndex = 3;
    } else if (state_.minimumLevel <= TRACE_LEVEL_WARNING) {
        levelIndex = 2;
    } else if (state_.minimumLevel <= TRACE_LEVEL_INFORMATION) {
        levelIndex = 1;
    }
    ComboBox_SetCurSel(levelCombo_, levelIndex);
    Button_SetCheck(currentProcessCheck_, state_.onlyCurrentProcess ? BST_CHECKED : BST_UNCHECKED);
}

bool EtwFilterDialog::saveControlsToState() {
    for (std::size_t index = 0; index < state_.providers.size(); ++index) {
        state_.providers[index].enabled = ListView_GetCheckState(providerList_, static_cast<int>(index)) != FALSE;
    }

    wchar_t pidText[32] = {};
    ::GetWindowTextW(pidEdit_, pidText, static_cast<int>(std::size(pidText)));
    state_.processId = static_cast<std::uint32_t>(std::wcstoul(pidText, nullptr, 10));

    const int kLevelIndex = ComboBox_GetCurSel(levelCombo_);
    switch (kLevelIndex) {
    case 4: state_.minimumLevel = TRACE_LEVEL_CRITICAL; break;
    case 3: state_.minimumLevel = TRACE_LEVEL_ERROR; break;
    case 2: state_.minimumLevel = TRACE_LEVEL_WARNING; break;
    case 1: state_.minimumLevel = TRACE_LEVEL_INFORMATION; break;
    default: state_.minimumLevel = TRACE_LEVEL_VERBOSE; break;
    }
    state_.onlyCurrentProcess = Button_GetCheck(currentProcessCheck_) == BST_CHECKED;
    return true;
}

void EtwFilterDialog::closeWithResult(const bool accepted) {
    accepted_ = accepted;
    finished_ = true;
    if (hwnd_ != nullptr) {
        ::DestroyWindow(hwnd_);
        hwnd_ = nullptr;
    }
}

} // namespace Ksword::Features::Monitor
