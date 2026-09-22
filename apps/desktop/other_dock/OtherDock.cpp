#include "OtherDock.h"
#include "../framework/PrivilegeElevationPrompt.h"
#include "../framework/DestructiveActionConfirmation.h"
#include "../internationalization/LanguageManager.h"
#include "../ui/TableInteractionSupport.h"
#include "../ui/VisibleTableWidget.h"

// ============================================================
// OtherDock.cpp
// Purpose:
// 1) Implement the window list tab, filtering groups, right-click actions, and export functionality;
// 2) Implement a window details dialog covering tabs for General, Style, Location, and Status.
// 3) All enumeration flows run on background threads to avoid blocking the UI thread.
// ============================================================

#include "../process_dock/ProcessDetailWindow.h"
#include "../online_scan/SandboxUploadActions.h"
#include "WindowCaptureProtection.h"
#include "WindowInputControl.h"
#include "../Theme.h"
#include "../ui/CodeEditorWidget.h"

#include <QApplication>
#include <QAbstractItemView>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QCloseEvent>
#include <QCursor>
#include <QDateTime>
#include <QDialog>
#include <QFile>
#include <QFileDialog>
#include <QFileIconProvider>
#include <QFileInfo>
#include <QFormLayout>
#include <QGuiApplication>
#include <QGridLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QMouseEvent>
#include <QPainter>
#include <QPixmap>
#include <QPointer>
#include <QProcess>
#include <QPushButton>
#include <QScrollArea>
#include <QScreen>
#include <QSlider>
#include <QSpinBox>
#include <QSplitter>
#include <QStatusBar>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTextEdit>
#include <QTextStream>
#include <QTimer>
#include <QTimeZone>
#include <QToolButton>
#include <QTreeWidget>
#include <QTreeWidgetItemIterator>
#include <QVBoxLayout>
#include <QStringList>

#include <algorithm>
#include <array>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>

namespace
{
    // Unified button style: Maintain consistency with the global blue theme to avoid visual fragmentation.
    QString blueButtonStyle()
    {
        return ksword_theme::themedButtonStyle();
    }

    // Unify input box styles: filter, dropdown, and numeric inputs share the same visual feedback.
    QString blueInputStyle()
    {
        return QStringLiteral(
            "QLineEdit,QSpinBox{"
            "  border:1px solid %2;"
            "  border-radius:3px;"
            "  background:%3;"
            "  color:%4;"
            "  padding:2px 6px;"
            "}"
            "QLineEdit:focus,QSpinBox:focus{border:1px solid %1;}")
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::textPrimaryHex())
            + ksword_theme::themedComboBoxStyle();
    }

    // Header style: highlight column headers for quick field identification.
    QString blueHeaderStyle()
    {
        return QStringLiteral(
            "QHeaderView::section{color:%1;background:transparent;/* %2 */border:1px solid %3;font-weight:600;}")
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::borderHex());
    }

    // buildOpaqueWindowDetailDialogStyle:
    // - Overrides the parent Dock's transparent style to prevent a black background for the "Window Details" dialog in light themes.
    // - Force opaque backgrounds for text editors, tables, and scroll areas.
    QString buildOpaqueWindowDetailDialogStyle(const QString& dialogObjectName)
    {
        return QStringLiteral(
            "QDialog#%1{"
            "  background-color:palette(window) !important;"
            "  color:palette(text) !important;"
            "}"
            "QDialog#%1 QTabWidget::pane{"
            "  background-color:palette(window) !important;"
            "  border:1px solid palette(mid) !important;"
            "}"
            "QDialog#%1 QPlainTextEdit,"
            "QDialog#%1 QTextEdit,"
            "QDialog#%1 QTreeWidget,"
            "QDialog#%1 QTableWidget,"
            "QDialog#%1 QAbstractScrollArea,"
            "QDialog#%1 QAbstractScrollArea::viewport{"
            "  background-color:palette(base) !important;"
            "  color:palette(text) !important;"
            "}"
            "QDialog#%1 QHeaderView::section{"
            "  background:transparent !important;"
            "  background-color:transparent !important;"
            "  color:palette(text) !important;"
            "}")
            .arg(dialogObjectName);
    }

    // Convert boolean to text: unify 'Yes/No' display to avoid inconsistent implementations across the codebase.
    QString boolText(const bool value)
    {
        return value ? QStringLiteral("是") : QStringLiteral("否");
    }

    // WindowStyleFlagDefinition：
    // - Purpose: Define a 'checkable style flag' entry (name/bitmask/purpose description);
    // - Call: WindowDetailDialog creates control groups for style checkboxes using this table.
    // - Input/Output: This structure serves only as data carrier and does not directly participate in system calls;
    struct WindowStyleFlagDefinition
    {
        const char* styleNameText = nullptr;      // styleNameText: Style bit name (e.g., WS_VISIBLE).
        quint64 styleMaskValue = 0;               // styleMaskValue: Corresponds to Win32 style bitmasks.
        const char* styleDescriptionText = nullptr; // styleDescriptionText: Tooltip and export description text.
    };

    // windowStyleFlagDefinitionList：
    // - Purpose: Return the checkbox definitions for standard window styles (GWL_STYLE).
    // - Invocation: Called by WindowDetailDialog::initializeUi when creating WS_* checkboxes on the "Style and Appearance" tab.
    // - Input/Output: No input parameters; returns a read-only reference to the definition list.
    const std::vector<WindowStyleFlagDefinition>& windowStyleFlagDefinitionList()
    {
        static const std::vector<WindowStyleFlagDefinition> kStyleDefinitionList = {
            { "WS_BORDER", static_cast<quint64>(WS_BORDER), "窗口有细边框。" },
            { "WS_CAPTION", static_cast<quint64>(WS_CAPTION), "窗口有标题栏（组合位：边框+对话框框架）。" },
            { "WS_CHILD", static_cast<quint64>(WS_CHILD), "窗口是子窗口，通常依附父窗口。" },
            { "WS_CLIPCHILDREN", static_cast<quint64>(WS_CLIPCHILDREN), "绘制时裁剪子窗口区域，减少重绘覆盖。" },
            { "WS_CLIPSIBLINGS", static_cast<quint64>(WS_CLIPSIBLINGS), "兄弟窗口之间绘制互相裁剪。" },
            { "WS_DISABLED", static_cast<quint64>(WS_DISABLED), "窗口禁用，不接收输入。" },
            { "WS_DLGFRAME", static_cast<quint64>(WS_DLGFRAME), "窗口具备对话框风格边框。" },
            { "WS_GROUP", static_cast<quint64>(WS_GROUP), "控件分组起始标记（常见于 Tab 导航组）。" },
            { "WS_HSCROLL", static_cast<quint64>(WS_HSCROLL), "窗口带水平滚动条。" },
            { "WS_MAXIMIZE", static_cast<quint64>(WS_MAXIMIZE), "窗口当前处于最大化样式状态位。" },
            { "WS_MAXIMIZEBOX", static_cast<quint64>(WS_MAXIMIZEBOX), "窗口显示最大化按钮。" },
            { "WS_MINIMIZE", static_cast<quint64>(WS_MINIMIZE), "窗口当前处于最小化样式状态位。" },
            { "WS_MINIMIZEBOX", static_cast<quint64>(WS_MINIMIZEBOX), "窗口显示最小化按钮。" },
            { "WS_POPUP", static_cast<quint64>(WS_POPUP), "弹出窗口样式（独立于父窗口裁剪关系）。" },
            { "WS_SIZEBOX", static_cast<quint64>(WS_SIZEBOX), "窗口可通过边框拖拽改变大小。" },
            { "WS_SYSMENU", static_cast<quint64>(WS_SYSMENU), "窗口带系统菜单（标题栏图标菜单）。" },
            { "WS_TABSTOP", static_cast<quint64>(WS_TABSTOP), "控件允许通过 Tab 键获得焦点。" },
            { "WS_VISIBLE", static_cast<quint64>(WS_VISIBLE), "窗口可见样式位。" },
            { "WS_VSCROLL", static_cast<quint64>(WS_VSCROLL), "窗口带垂直滚动条。" }
        };
        return kStyleDefinitionList;
    }

    // windowExStyleFlagDefinitionList：
    // - Purpose: Return the checkbox definitions for window extended styles (GWL_EXSTYLE);
    // - Called when creating WS_EX_* checkboxes on the "Style & Appearance" page in WindowDetailDialog::initializeUi.
    // - Input/Output: No input parameters; returns a read-only reference to the definition list.
    const std::vector<WindowStyleFlagDefinition>& windowExStyleFlagDefinitionList()
    {
        static const std::vector<WindowStyleFlagDefinition> kExStyleDefinitionList = {
            { "WS_EX_ACCEPTFILES", static_cast<quint64>(WS_EX_ACCEPTFILES), "允许窗口接收拖放文件。" },
            { "WS_EX_APPWINDOW", static_cast<quint64>(WS_EX_APPWINDOW), "强制窗口显示在任务栏。" },
            { "WS_EX_CLIENTEDGE", static_cast<quint64>(WS_EX_CLIENTEDGE), "客户区边缘使用凹陷边框效果。" },
            { "WS_EX_COMPOSITED", static_cast<quint64>(WS_EX_COMPOSITED), "对后代窗口启用双缓冲绘制（可能影响性能）。" },
            { "WS_EX_CONTEXTHELP", static_cast<quint64>(WS_EX_CONTEXTHELP), "标题栏显示“帮助”按钮。" },
            { "WS_EX_CONTROLPARENT", static_cast<quint64>(WS_EX_CONTROLPARENT), "父窗口参与 Tab 键焦点导航。" },
            { "WS_EX_DLGMODALFRAME", static_cast<quint64>(WS_EX_DLGMODALFRAME), "对话框模式边框。" },
            { "WS_EX_LAYERED", static_cast<quint64>(WS_EX_LAYERED), "启用分层窗口（透明度/颜色键）。" },
            { "WS_EX_LAYOUTRTL", static_cast<quint64>(WS_EX_LAYOUTRTL), "布局从右到左。" },
            { "WS_EX_LEFTSCROLLBAR", static_cast<quint64>(WS_EX_LEFTSCROLLBAR), "垂直滚动条显示在左侧。" },
            { "WS_EX_MDICHILD", static_cast<quint64>(WS_EX_MDICHILD), "标记为 MDI 子窗口。" },
            { "WS_EX_NOACTIVATE", static_cast<quint64>(WS_EX_NOACTIVATE), "窗口显示时不激活焦点。" },
#ifdef WS_EX_NOREDIRECTIONBITMAP
            { "WS_EX_NOREDIRECTIONBITMAP", static_cast<quint64>(WS_EX_NOREDIRECTIONBITMAP), "禁用 DWM 重定向位图。" },
#endif
            { "WS_EX_NOPARENTNOTIFY", static_cast<quint64>(WS_EX_NOPARENTNOTIFY), "创建/销毁时不通知父窗口。" },
            { "WS_EX_RIGHT", static_cast<quint64>(WS_EX_RIGHT), "文字和布局右对齐。" },
            { "WS_EX_RTLREADING", static_cast<quint64>(WS_EX_RTLREADING), "文本从右到左阅读。" },
            { "WS_EX_STATICEDGE", static_cast<quint64>(WS_EX_STATICEDGE), "三维静态边框样式。" },
            { "WS_EX_TOOLWINDOW", static_cast<quint64>(WS_EX_TOOLWINDOW), "工具窗口样式（小标题栏、通常不在任务栏）。" },
            { "WS_EX_TOPMOST", static_cast<quint64>(WS_EX_TOPMOST), "窗口保持置顶层级。" },
            { "WS_EX_TRANSPARENT", static_cast<quint64>(WS_EX_TRANSPARENT), "通常影响同线程窗口绘制顺序；与 WS_EX_LAYERED 组合时可让鼠标点击穿透。" },
            { "WS_EX_WINDOWEDGE", static_cast<quint64>(WS_EX_WINDOWEDGE), "窗口外框使用凸起边缘效果。" }
        };
        return kExStyleDefinitionList;
    }

    // Convert the HWND value to a hexadecimal string for use in the table's first column and the details header.
    QString hwndToText(const quint64 hwndValue)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(hwndValue), 0, 16)
            .toUpper();
    }

    // toHexText64:
    // - Format 64-bit integers uniformly as 16-character hexadecimal strings.
    // - Used to display WPARAM/LPARAM/RESULT in the message monitoring table for direct comparison with memory values.
    QString toHexText64(const quint64 numericValue)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(numericValue), 16, 16, QChar('0'))
            .toUpper();
    }

    // windowMessageName:
    // - Map common window message IDs to readable names;
    // - Unmatched messages return in the WM_0xXXXX format to maintain traceability.
    QString windowMessageName(const UINT messageId)
    {
        switch (messageId)
        {
        case WM_NULL: return QStringLiteral("WM_NULL");
        case WM_CREATE: return QStringLiteral("WM_CREATE");
        case WM_DESTROY: return QStringLiteral("WM_DESTROY");
        case WM_MOVE: return QStringLiteral("WM_MOVE");
        case WM_SIZE: return QStringLiteral("WM_SIZE");
        case WM_ACTIVATE: return QStringLiteral("WM_ACTIVATE");
        case WM_SETFOCUS: return QStringLiteral("WM_SETFOCUS");
        case WM_KILLFOCUS: return QStringLiteral("WM_KILLFOCUS");
        case WM_ENABLE: return QStringLiteral("WM_ENABLE");
        case WM_SETREDRAW: return QStringLiteral("WM_SETREDRAW");
        case WM_SETTEXT: return QStringLiteral("WM_SETTEXT");
        case WM_GETTEXT: return QStringLiteral("WM_GETTEXT");
        case WM_GETTEXTLENGTH: return QStringLiteral("WM_GETTEXTLENGTH");
        case WM_PAINT: return QStringLiteral("WM_PAINT");
        case WM_CLOSE: return QStringLiteral("WM_CLOSE");
        case WM_QUERYENDSESSION: return QStringLiteral("WM_QUERYENDSESSION");
        case WM_QUERYOPEN: return QStringLiteral("WM_QUERYOPEN");
        case WM_ENDSESSION: return QStringLiteral("WM_ENDSESSION");
        case WM_QUIT: return QStringLiteral("WM_QUIT");
        case WM_ERASEBKGND: return QStringLiteral("WM_ERASEBKGND");
        case WM_SYSCOLORCHANGE: return QStringLiteral("WM_SYSCOLORCHANGE");
        case WM_SHOWWINDOW: return QStringLiteral("WM_SHOWWINDOW");
        case WM_ACTIVATEAPP: return QStringLiteral("WM_ACTIVATEAPP");
        case WM_SETCURSOR: return QStringLiteral("WM_SETCURSOR");
        case WM_MOUSEACTIVATE: return QStringLiteral("WM_MOUSEACTIVATE");
        case WM_GETMINMAXINFO: return QStringLiteral("WM_GETMINMAXINFO");
        case WM_NCCREATE: return QStringLiteral("WM_NCCREATE");
        case WM_NCDESTROY: return QStringLiteral("WM_NCDESTROY");
        case WM_NCCALCSIZE: return QStringLiteral("WM_NCCALCSIZE");
        case WM_NCHITTEST: return QStringLiteral("WM_NCHITTEST");
        case WM_NCPAINT: return QStringLiteral("WM_NCPAINT");
        case WM_NCACTIVATE: return QStringLiteral("WM_NCACTIVATE");
        case WM_KEYDOWN: return QStringLiteral("WM_KEYDOWN");
        case WM_KEYUP: return QStringLiteral("WM_KEYUP");
        case WM_CHAR: return QStringLiteral("WM_CHAR");
        case WM_SYSKEYDOWN: return QStringLiteral("WM_SYSKEYDOWN");
        case WM_SYSKEYUP: return QStringLiteral("WM_SYSKEYUP");
        case WM_SYSCHAR: return QStringLiteral("WM_SYSCHAR");
        case WM_COMMAND: return QStringLiteral("WM_COMMAND");
        case WM_SYSCOMMAND: return QStringLiteral("WM_SYSCOMMAND");
        case WM_TIMER: return QStringLiteral("WM_TIMER");
        case WM_HSCROLL: return QStringLiteral("WM_HSCROLL");
        case WM_VSCROLL: return QStringLiteral("WM_VSCROLL");
        case WM_INITMENU: return QStringLiteral("WM_INITMENU");
        case WM_INITMENUPOPUP: return QStringLiteral("WM_INITMENUPOPUP");
        case WM_MENUSELECT: return QStringLiteral("WM_MENUSELECT");
        case WM_MENUCHAR: return QStringLiteral("WM_MENUCHAR");
        case WM_ENTERIDLE: return QStringLiteral("WM_ENTERIDLE");
        case WM_CHANGEUISTATE: return QStringLiteral("WM_CHANGEUISTATE");
        case WM_UPDATEUISTATE: return QStringLiteral("WM_UPDATEUISTATE");
        case WM_QUERYUISTATE: return QStringLiteral("WM_QUERYUISTATE");
        case WM_CTLCOLORMSGBOX: return QStringLiteral("WM_CTLCOLORMSGBOX");
        case WM_CTLCOLOREDIT: return QStringLiteral("WM_CTLCOLOREDIT");
        case WM_CTLCOLORLISTBOX: return QStringLiteral("WM_CTLCOLORLISTBOX");
        case WM_CTLCOLORBTN: return QStringLiteral("WM_CTLCOLORBTN");
        case WM_CTLCOLORDLG: return QStringLiteral("WM_CTLCOLORDLG");
        case WM_CTLCOLORSCROLLBAR: return QStringLiteral("WM_CTLCOLORSCROLLBAR");
        case WM_CTLCOLORSTATIC: return QStringLiteral("WM_CTLCOLORSTATIC");
        case WM_MOUSEMOVE: return QStringLiteral("WM_MOUSEMOVE");
        case WM_LBUTTONDOWN: return QStringLiteral("WM_LBUTTONDOWN");
        case WM_LBUTTONUP: return QStringLiteral("WM_LBUTTONUP");
        case WM_LBUTTONDBLCLK: return QStringLiteral("WM_LBUTTONDBLCLK");
        case WM_RBUTTONDOWN: return QStringLiteral("WM_RBUTTONDOWN");
        case WM_RBUTTONUP: return QStringLiteral("WM_RBUTTONUP");
        case WM_RBUTTONDBLCLK: return QStringLiteral("WM_RBUTTONDBLCLK");
        case WM_MBUTTONDOWN: return QStringLiteral("WM_MBUTTONDOWN");
        case WM_MBUTTONUP: return QStringLiteral("WM_MBUTTONUP");
        case WM_MOUSEWHEEL: return QStringLiteral("WM_MOUSEWHEEL");
        case WM_MOUSEHWHEEL: return QStringLiteral("WM_MOUSEHWHEEL");
        case WM_INPUT: return QStringLiteral("WM_INPUT");
        case WM_CAPTURECHANGED: return QStringLiteral("WM_CAPTURECHANGED");
        case WM_ENTERSIZEMOVE: return QStringLiteral("WM_ENTERSIZEMOVE");
        case WM_EXITSIZEMOVE: return QStringLiteral("WM_EXITSIZEMOVE");
        case WM_DROPFILES: return QStringLiteral("WM_DROPFILES");
        case WM_INPUTLANGCHANGE: return QStringLiteral("WM_INPUTLANGCHANGE");
        case WM_IME_STARTCOMPOSITION: return QStringLiteral("WM_IME_STARTCOMPOSITION");
        case WM_IME_COMPOSITION: return QStringLiteral("WM_IME_COMPOSITION");
        case WM_IME_ENDCOMPOSITION: return QStringLiteral("WM_IME_ENDCOMPOSITION");
        case WM_DEVICECHANGE: return QStringLiteral("WM_DEVICECHANGE");
        case WM_COPYDATA: return QStringLiteral("WM_COPYDATA");
        case WM_NOTIFY: return QStringLiteral("WM_NOTIFY");
        case WM_APP: return QStringLiteral("WM_APP");
        default:
            return QStringLiteral("WM_0x%1")
                .arg(static_cast<qulonglong>(messageId), 4, 16, QChar('0'))
                .toUpper();
        }
    }

    // winEventName:
    // - Provides event name mapping for cross-process fallback mode (WinEventHook).
    // - Facilitates distinguishing between object creation/focus/display, etc., GUI events.
    QString winEventName(const DWORD eventId)
    {
        switch (eventId)
        {
        case EVENT_SYSTEM_FOREGROUND: return QStringLiteral("EVENT_SYSTEM_FOREGROUND");
        case EVENT_SYSTEM_MENUSTART: return QStringLiteral("EVENT_SYSTEM_MENUSTART");
        case EVENT_SYSTEM_MENUEND: return QStringLiteral("EVENT_SYSTEM_MENUEND");
        case EVENT_SYSTEM_MOVESIZESTART: return QStringLiteral("EVENT_SYSTEM_MOVESIZESTART");
        case EVENT_SYSTEM_MOVESIZEEND: return QStringLiteral("EVENT_SYSTEM_MOVESIZEEND");
        case EVENT_SYSTEM_MINIMIZESTART: return QStringLiteral("EVENT_SYSTEM_MINIMIZESTART");
        case EVENT_SYSTEM_MINIMIZEEND: return QStringLiteral("EVENT_SYSTEM_MINIMIZEEND");
        case EVENT_OBJECT_CREATE: return QStringLiteral("EVENT_OBJECT_CREATE");
        case EVENT_OBJECT_DESTROY: return QStringLiteral("EVENT_OBJECT_DESTROY");
        case EVENT_OBJECT_SHOW: return QStringLiteral("EVENT_OBJECT_SHOW");
        case EVENT_OBJECT_HIDE: return QStringLiteral("EVENT_OBJECT_HIDE");
        case EVENT_OBJECT_REORDER: return QStringLiteral("EVENT_OBJECT_REORDER");
        case EVENT_OBJECT_FOCUS: return QStringLiteral("EVENT_OBJECT_FOCUS");
        case EVENT_OBJECT_SELECTION: return QStringLiteral("EVENT_OBJECT_SELECTION");
        case EVENT_OBJECT_SELECTIONADD: return QStringLiteral("EVENT_OBJECT_SELECTIONADD");
        case EVENT_OBJECT_SELECTIONREMOVE: return QStringLiteral("EVENT_OBJECT_SELECTIONREMOVE");
        case EVENT_OBJECT_SELECTIONWITHIN: return QStringLiteral("EVENT_OBJECT_SELECTIONWITHIN");
        case EVENT_OBJECT_STATECHANGE: return QStringLiteral("EVENT_OBJECT_STATECHANGE");
        case EVENT_OBJECT_LOCATIONCHANGE: return QStringLiteral("EVENT_OBJECT_LOCATIONCHANGE");
        case EVENT_OBJECT_NAMECHANGE: return QStringLiteral("EVENT_OBJECT_NAMECHANGE");
        case EVENT_OBJECT_DESCRIPTIONCHANGE: return QStringLiteral("EVENT_OBJECT_DESCRIPTIONCHANGE");
        case EVENT_OBJECT_VALUECHANGE: return QStringLiteral("EVENT_OBJECT_VALUECHANGE");
        case EVENT_OBJECT_PARENTCHANGE: return QStringLiteral("EVENT_OBJECT_PARENTCHANGE");
        default:
            return QStringLiteral("EVENT_0x%1")
                .arg(static_cast<qulonglong>(eventId), 4, 16, QChar('0'))
                .toUpper();
        }
    }

    // Column index constants:
    // - Uniformly defines the window table column order to avoid scattered magic numbers across functions.
    // - This adjustment places the 'Window Title' in the first column for easier quick browsing.
    constexpr int kWindowColumnTitle = 0;
    constexpr int kWindowColumnHandle = 1;
    constexpr int kWindowColumnEnumApi = 2;
    constexpr int kWindowColumnClassName = 3;
    constexpr int kWindowColumnPid = 4;
    constexpr int kWindowColumnProcessName = 5;
    constexpr int kWindowColumnTid = 6;
    constexpr int kWindowColumnSize = 7;
    constexpr int kWindowColumnVisible = 8;
    constexpr int kWindowColumnEnabled = 9;
    constexpr int kWindowColumnTopMost = 10;
    constexpr int kWindowColumnState = 11;
    constexpr int kWindowColumnAlpha = 12;

    // WindowPickerDragButton：
    // - Purpose: Capture the mouse after a left-click to implement the interaction of 'holding the crosshair to drag and release anywhere'.
    // - Invocation: Created by OtherDock::initializeUi and bound to a release callback via setReleaseCallback;
    // - Input: releaseCallback receives global coordinates.
    // - Output: none; callbacks are handled externally for specific window picking and detail dialogs.
    class WindowPickerDragButton final : public QPushButton
    {
    public:
        using ReleaseCallback = std::function<void(const QPoint&)>;

        explicit WindowPickerDragButton(QWidget* parent = nullptr)
            : QPushButton(parent)
        {
            // setMouseTracking(true) effect: Continuously receive move events during drag operations even without button state changes.
            setMouseTracking(true);
        }

        // setReleaseCallback：
        // - Purpose: Register the mouse release callback;
        // - Usage: Bound when OtherDock initializes the UI.
        // - Passes a callback: a function object that receives global coordinates upon release.
        // - Output: None.
        void setReleaseCallback(ReleaseCallback callback)
        {
            releaseCallback_ = std::move(callback);
        }

    protected:
        void mousePressEvent(QMouseEvent* event) override
        {
            if (event != nullptr && event->button() == Qt::LeftButton)
            {
                // m_dragTracking: Marks whether the current process is 'crosshair drag-and-drop pickup'.
                dragTracking_ = true;
                // m_pressGlobalPos is used to record the drag start point, combined with a threshold to distinguish between 'click' and 'drag'.
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
                pressGlobalPos_ = event->globalPosition().toPoint();
#else
                m_pressGlobalPos = event->globalPos();
#endif
                hasReachedDragThreshold_ = false;
                // The grabMouse + CrossCursor combination unifies the drag-and-drop visual and input to this button.
                grabMouse(QCursor(Qt::CrossCursor));
            }
            QPushButton::mousePressEvent(event);
        }

        void mouseMoveEvent(QMouseEvent* event) override
        {
            if (dragTracking_ && event != nullptr)
            {
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
                const QPoint kCurrentGlobalPos = event->globalPosition().toPoint();
#else
                const QPoint currentGlobalPos = event->globalPos();
#endif
                const int kMoveDistance = (kCurrentGlobalPos - pressGlobalPos_).manhattanLength();
                // m_hasReachedDragThreshold: Prevents accidental window pick-up on button click.
                if (kMoveDistance >= QApplication::startDragDistance())
                {
                    hasReachedDragThreshold_ = true;
                }
            }
            QPushButton::mouseMoveEvent(event);
        }

        void mouseReleaseEvent(QMouseEvent* event) override
        {
            // shouldDispatch: Ensures the window pick-up callback is triggered only at the end of the left-button drag chain.
            const bool kShouldDispatch =
                dragTracking_
                && hasReachedDragThreshold_
                && event != nullptr
                && event->button() == Qt::LeftButton;

            if (dragTracking_)
            {
                // releaseMouse purpose: Terminate global mouse capture to prevent subsequent input from being incorrectly hijacked.
                releaseMouse();
                dragTracking_ = false;
            }
            hasReachedDragThreshold_ = false;

            QPoint releaseGlobalPos;
            if (event != nullptr)
            {
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
                // releaseGlobalPos is used to record the screen coordinates when the mouse is released, subsequently used for WindowFromPoint.
                releaseGlobalPos = event->globalPosition().toPoint();
#else
                releaseGlobalPos = event->globalPos();
#endif
            }

            QPushButton::mouseReleaseEvent(event);

            if (kShouldDispatch && releaseCallback_)
            {
                releaseCallback_(releaseGlobalPos);
            }
        }

    private:
        bool dragTracking_ = false;          // m_dragTracking: Records whether the current drag-and-drop pick chain is active.
        bool hasReachedDragThreshold_ = false; // m_hasReachedDragThreshold: Whether the drag distance has reached the minimum threshold.
        QPoint pressGlobalPos_;              // m_pressGlobalPos: Records the screen coordinates when the left mouse button is pressed.
        ReleaseCallback releaseCallback_;    // m_releaseCallback: Callback to OtherDock on mouse release.
    };

    // queryProcessImagePathByPid：
    // - Query the full executable path by PID.
    // - Returns full path on success; returns empty string on failure.
    QString queryProcessImagePathByPid(const std::uint32_t pid)
    {
        if (pid == 0)
        {
            return QString();
        }

        HANDLE processHandle = ::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            FALSE,
            pid);
        if (processHandle == nullptr)
        {
            processHandle = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        }
        if (processHandle == nullptr)
        {
            return QString();
        }

        wchar_t pathBuffer[MAX_PATH * 2] = {};
        DWORD pathLength = static_cast<DWORD>(std::size(pathBuffer));
        QString fullPath;
        if (::QueryFullProcessImageNameW(processHandle, 0, pathBuffer, &pathLength) != FALSE)
        {
            fullPath = QString::fromWCharArray(pathBuffer, static_cast<int>(pathLength));
        }

        ::CloseHandle(processHandle);
        return fullPath;
    }

    // Process name query: retrieves the executable file name by PID, with an optional full path output.
    QString queryProcessNameByPid(const std::uint32_t pid, QString* imagePathOut)
    {
        if (imagePathOut != nullptr)
        {
            imagePathOut->clear();
        }
        if (pid == 0)
        {
            return QStringLiteral("System");
        }

        const QString kFullPath = queryProcessImagePathByPid(pid);
        if (kFullPath.trimmed().isEmpty())
        {
            return QStringLiteral("PID_%1").arg(pid);
        }
        if (imagePathOut != nullptr)
        {
            *imagePathOut = kFullPath;
        }

        const int kSlashPos = std::max(kFullPath.lastIndexOf('/'), kFullPath.lastIndexOf('\\'));
        return kSlashPos >= 0 ? kFullPath.mid(kSlashPos + 1) : kFullPath;
    }

    // queryProcessLogoIconByPath：
    // - Retrieve the system file icon based on the process path.
    // - Falls back to the default process icon if the path is invalid or the icon cannot be extracted.
    QIcon queryProcessLogoIconByPath(const QString& imagePathText)
    {
        static QFileIconProvider iconProvider;
        if (!imagePathText.trimmed().isEmpty())
        {
            const QIcon kFileIcon = iconProvider.icon(QFileInfo(imagePathText));
            if (!kFileIcon.isNull())
            {
                return kFileIcon;
            }
        }
        return QIcon(":/Icon/process_main.svg");
    }

    // Snapshot state text: maps minimized/maximized/normal to a unified string.
    QString windowStateText(
        const bool validState,
        const bool minimizedState,
        const bool maximizedState)
    {
        if (!validState)
        {
            return QStringLiteral("无效");
        }
        if (minimizedState)
        {
            return QStringLiteral("最小化");
        }
        if (maximizedState)
        {
            return QStringLiteral("最大化");
        }
        return QStringLiteral("正常");
    }

    // Filter mode text: used in logs to output the current filtering semantics, aiding troubleshooting of 'window not visible' issues.
    QString filterModeText(const int mode)
    {
        switch (mode)
        {
        case 0:
            return QStringLiteral("可见窗口");
        case 1:
            return QStringLiteral("隐藏窗口");
        case 2:
            return QStringLiteral("顶层窗口");
        case 3:
            return QStringLiteral("子窗口");
        case 4:
            return QStringLiteral("无效窗口");
        default:
            return QStringLiteral("未知模式");
        }
    }

    // Group mode text: convert to a readable string to avoid logging only numeric indices.
    QString groupModeText(const int mode)
    {
        switch (mode)
        {
        case 0:
            return QStringLiteral("按进程分组");
        case 1:
            return QStringLiteral("按Z序");
        case 2:
            return QStringLiteral("按层级");
        case 3:
            return QStringLiteral("按显示器");
        default:
            return QStringLiteral("未知分组");
        }
    }

    // View mode text: Records the icon/list/details switch.
    QString viewModeText(const int mode)
    {
        switch (mode)
        {
        case 0:
            return QStringLiteral("图标视图");
        case 1:
            return QStringLiteral("列表视图");
        case 2:
            return QStringLiteral("详情视图");
        default:
            return QStringLiteral("未知视图");
        }
    }

    // Enum mode text: used for log display to help locate 'missing window' issues.
    QString enumModeText(const int mode)
    {
        switch (mode)
        {
        case 0:
            return QStringLiteral("混合枚举(推荐)");
        case 1:
            return QStringLiteral("EnumWindows+子窗口");
        case 2:
            return QStringLiteral("EnumDesktopWindows+子窗口");
        case 3:
            return QStringLiteral("EnumThreadWindows+子窗口");
        case 4:
            return QStringLiteral("仅EnumWindows顶层");
        default:
            return QStringLiteral("未知模式");
        }
    }

    // Convert handle string to HWND: restore the cached handle when applying changes in the details dialog.
    HWND toHwnd(const quint64 hwndValue)
    {
        return reinterpret_cast<HWND>(static_cast<quintptr>(hwndValue));
    }

    // Window property enumeration context: used by EnumPropsExW callback to collect property names and values.
    struct WindowPropEnumContext
    {
        QStringList* lines = nullptr;   // Output text line collection.
        int maxCount = 0;               // Maximum number of rows allowed for collection.
    };

    // EnumPropsExW callback: write each property key and value to lines; terminate early if limit exceeded.
    int CALLBACK enumWindowPropProc(HWND, LPWSTR stringPtr, HANDLE dataHandle, ULONG_PTR lParam)
    {
        WindowPropEnumContext* context = reinterpret_cast<WindowPropEnumContext*>(lParam);
        if (context == nullptr || context->lines == nullptr)
        {
            return FALSE;
        }
        if (context->lines->size() >= context->maxCount)
        {
            return FALSE;
        }

        QString keyText;
        if (stringPtr != nullptr)
        {
            const quintptr kRawValue = reinterpret_cast<quintptr>(stringPtr);
            if ((kRawValue >> 16) == 0)
            {
                keyText = QStringLiteral("ATOM_%1").arg(static_cast<unsigned int>(kRawValue & 0xFFFFu));
            }
            else
            {
                keyText = QString::fromWCharArray(stringPtr);
            }
        }
        else
        {
            keyText = QStringLiteral("<null>");
        }

        context->lines->push_back(
            QStringLiteral("%1 = 0x%2")
            .arg(keyText)
            .arg(static_cast<qulonglong>(reinterpret_cast<quintptr>(dataHandle)), 0, 16));
        return TRUE;
    }

    // fileTimeToUInt64: Converts FILETIME to a 100ns count for easier time difference calculations.
    qulonglong fileTimeToUInt64(const FILETIME& fileTimeValue)
    {
        ULARGE_INTEGER fileTimeInteger{};
        fileTimeInteger.LowPart = fileTimeValue.dwLowDateTime;
        fileTimeInteger.HighPart = fileTimeValue.dwHighDateTime;
        return static_cast<qulonglong>(fileTimeInteger.QuadPart);
    }

    // fileTimeToLocalText: Formats a Windows FILETIME into a local time string.
    QString fileTimeToLocalText(const FILETIME& fileTimeValue)
    {
        constexpr qulonglong kUnixEpochOffset100ns = 116444736000000000ULL;
        const qulonglong kFileTimeTick = fileTimeToUInt64(fileTimeValue);
        if (kFileTimeTick <= kUnixEpochOffset100ns)
        {
            return QStringLiteral("<N/A>");
        }

        const qint64 kUtcMs = static_cast<qint64>((kFileTimeTick - kUnixEpochOffset100ns) / 10000ULL);
        return QDateTime::fromMSecsSinceEpoch(kUtcMs, QTimeZone::UTC).toLocalTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"));
    }

    // formatDurationFrom100ns: Format 100ns duration as 'hours:minutes:seconds.milliseconds'.
    QString formatDurationFrom100ns(const qulonglong duration100ns)
    {
        const qulonglong kTotalMs = duration100ns / 10000ULL;
        const qulonglong kTotalSeconds = kTotalMs / 1000ULL;
        const qulonglong kRemainMs = kTotalMs % 1000ULL;
        const qulonglong kHours = kTotalSeconds / 3600ULL;
        const qulonglong kMinutes = (kTotalSeconds % 3600ULL) / 60ULL;
        const qulonglong kSeconds = kTotalSeconds % 60ULL;

        return QStringLiteral("%1h %2m %3s %4ms")
            .arg(kHours)
            .arg(kMinutes)
            .arg(kSeconds)
            .arg(kRemainMs);
    }

    // buildModuleSummaryText: Enumerates modules by PID and generates summary text to avoid displaying excessively long lists in the UI.
    QString buildModuleSummaryText(const std::uint32_t processId, const int maxRenderCount, int* moduleCountOut)
    {
        if (moduleCountOut != nullptr)
        {
            *moduleCountOut = 0;
        }
        if (processId == 0)
        {
            return QStringLiteral("<System PID>");
        }

        HANDLE snapshotHandle = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
        if (snapshotHandle == INVALID_HANDLE_VALUE)
        {
            return QStringLiteral("<模块枚举失败或无权限>");
        }

        MODULEENTRY32W moduleEntry{};
        moduleEntry.dwSize = sizeof(moduleEntry);
        QStringList lineList;
        int moduleCount = 0;

        if (::Module32FirstW(snapshotHandle, &moduleEntry) != FALSE)
        {
            do
            {
                ++moduleCount;
                if (moduleCount <= maxRenderCount)
                {
                    lineList << QStringLiteral("[%1] %2 | Base=0x%3 | Size=%4")
                        .arg(moduleCount)
                        .arg(QString::fromWCharArray(moduleEntry.szModule))
                        .arg(static_cast<qulonglong>(reinterpret_cast<quintptr>(moduleEntry.modBaseAddr)), 0, 16)
                        .arg(moduleEntry.modBaseSize);
                }

                moduleEntry.dwSize = sizeof(moduleEntry);
            } while (::Module32NextW(snapshotHandle, &moduleEntry) != FALSE);
        }

        ::CloseHandle(snapshotHandle);

        if (moduleCountOut != nullptr)
        {
            *moduleCountOut = moduleCount;
        }

        if (lineList.isEmpty())
        {
            return QStringLiteral("<未读取到模块>");
        }
        return lineList.join(QChar::LineFeed);
    }

    // Window thumbnail capture: prioritize grabbing by handle; return a placeholder image on failure.
    QPixmap grabWindowPreviewPixmap(const quint64 hwndValue, const QSize& targetSize)
    {
        QPixmap sourcePixmap;
        QScreen* primaryScreen = QGuiApplication::primaryScreen();
        if (primaryScreen != nullptr)
        {
            sourcePixmap = primaryScreen->grabWindow(static_cast<WId>(hwndValue));
        }

        if (!sourcePixmap.isNull())
        {
            return sourcePixmap.scaled(
                targetSize,
                Qt::KeepAspectRatio,
                Qt::SmoothTransformation);
        }

        QPixmap fallbackPixmap(targetSize);
        fallbackPixmap.fill(ksword_theme::surfaceColor());
        QPainter painter(&fallbackPixmap);
        painter.setPen(ksword_theme::textSecondaryColor());
        painter.drawRect(fallbackPixmap.rect().adjusted(0, 0, -1, -1));
        painter.drawText(
            fallbackPixmap.rect(),
            Qt::AlignCenter,
            ks::i18n::contextText(QStringLiteral("other.thumbnail.none"), QStringLiteral("无可用缩略图")));
        painter.end();
        return fallbackPixmap;
    }

    // Open the process detail window via PID: reuse the existing ProcessDetailWindow to facilitate jump linkage.
    void openProcessDetailWindow(QWidget* parent, const std::uint32_t pid)
    {
        if (pid == 0)
        {
            return;
        }

        // Window list navigation requires only the PID and name to open the window immediately.
        // Slow fields such as full path, signature, and token are asynchronously filled by the ProcessDetailWindow background thread.
        ks::process::ProcessRecord record;
        record.pid = pid;
        record.processName = ks::process::getProcessNameByPid(pid);
        if (record.processName.empty())
        {
            record.processName = "PID_" + std::to_string(pid);
        }

        ProcessDetailWindow* detailWindow = new ProcessDetailWindow(record, nullptr);
        detailWindow->setAttribute(Qt::WA_DeleteOnClose, true);
        detailWindow->show();
        detailWindow->raise();
        detailWindow->activateWindow();
    }

    // Enumeration context: used to carry the output container in EnumWindows / EnumDesktopWindows / EnumThreadWindows callbacks.
    struct EnumContext
    {
        std::vector<OtherDock::WindowInfo>* outputList = nullptr; // outputList: Output window list.
        std::unordered_set<quint64>* seenHandleSet = nullptr;     // seenHandleSet: deduplicated handle set.
        int zOrderCounter = 0;                                    // zOrderCounter: current enumeration index.
        bool enumerateChildren = true;                            // enumerateChildren: Whether to recursively enumerate child windows.
        QString topEnumApiName = QStringLiteral("EnumWindows");   // topEnumApiName: Identifier for the source of top-level windows.
        QString childEnumApiName = QStringLiteral("EnumChildWindows"); // childEnumApiName: Identifier for the source of child windows.
    };

    // Fill a single WindowInfo: read common properties from the HWND and write them into the structure.
    void fillWindowInfo(
        HWND windowHandle,
        const int zOrderValue,
        const bool childFlag,
        const QString& enumApiName,
        OtherDock::WindowInfo& infoOut)
    {
        infoOut.hwndValue = static_cast<quint64>(reinterpret_cast<quintptr>(windowHandle));
        infoOut.parentHwndValue = static_cast<quint64>(
            reinterpret_cast<quintptr>(::GetParent(windowHandle)));
        infoOut.ownerHwndValue = static_cast<quint64>(
            reinterpret_cast<quintptr>(::GetWindow(windowHandle, GW_OWNER)));
        infoOut.enumApiName = enumApiName;
        infoOut.isChildWindow = childFlag;
        infoOut.valid = ::IsWindow(windowHandle) != FALSE;
        infoOut.zOrder = zOrderValue;

        wchar_t titleBuffer[1024] = {};
        ::GetWindowTextW(windowHandle, titleBuffer, static_cast<int>(std::size(titleBuffer)));
        infoOut.titleText = QString::fromWCharArray(titleBuffer);

        wchar_t classBuffer[512] = {};
        ::GetClassNameW(windowHandle, classBuffer, static_cast<int>(std::size(classBuffer)));
        infoOut.classNameText = QString::fromWCharArray(classBuffer);

        RECT rect{};
        if (::GetWindowRect(windowHandle, &rect) != FALSE)
        {
            infoOut.windowRect = QRect(rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top);
        }
        else
        {
            infoOut.windowRect = QRect();
        }

        infoOut.styleValue = static_cast<quint64>(::GetWindowLongPtrW(windowHandle, GWL_STYLE));
        infoOut.exStyleValue = static_cast<quint64>(::GetWindowLongPtrW(windowHandle, GWL_EXSTYLE));

        infoOut.visible = ::IsWindowVisible(windowHandle) != FALSE;
        infoOut.enabled = ::IsWindowEnabled(windowHandle) != FALSE;
        infoOut.topMost = (infoOut.exStyleValue & WS_EX_TOPMOST) != 0;
        infoOut.minimized = ::IsIconic(windowHandle) != FALSE;
        infoOut.maximized = ::IsZoomed(windowHandle) != FALSE;
        infoOut.displayAffinityKnown = ks::window::queryWindowDisplayAffinity(
            infoOut.hwndValue,
            infoOut.displayAffinityValue,
            &infoOut.displayAffinityError);

        std::uint32_t processId = 0;
        const DWORD kThreadId = ::GetWindowThreadProcessId(windowHandle, reinterpret_cast<DWORD*>(&processId));
        infoOut.processId = processId;
        infoOut.processCreationTime100ns = 0U;
        if (processId != 0U)
        {
            (void)ks::process::queryProcessCreationTimeByPid(
                processId,
                &infoOut.processCreationTime100ns);
        }
        infoOut.threadId = static_cast<std::uint32_t>(kThreadId);
        infoOut.processNameText = queryProcessNameByPid(processId, &infoOut.processImagePathText);

        // Transparency: attempt to read Alpha only if the window has the layered attribute.
        infoOut.alphaValue = 255;
        if ((infoOut.exStyleValue & WS_EX_LAYERED) != 0)
        {
            COLORREF colorKey = 0;
            BYTE alpha = 255;
            DWORD flags = 0;
            if (::GetLayeredWindowAttributes(windowHandle, &colorKey, &alpha, &flags) != FALSE)
            {
                Q_UNUSED(colorKey);
                Q_UNUSED(flags);
                infoOut.alphaValue = static_cast<int>(alpha);
            }
        }
    }

    // Child window enumeration callback: Include each child window in the snapshot to satisfy 'hierarchical view' requirements.
    // appendWindowSnapshotIfNeeded:
    // - Write window snapshot after deduplicating by handle;
    // - Returns true on successful write; false if the handle is duplicated or the context is invalid.
    bool appendWindowSnapshotIfNeeded(
        EnumContext* context,
        HWND windowHandle,
        const bool isChildWindow,
        const QString& enumApiName)
    {
        if (context == nullptr || context->outputList == nullptr || context->seenHandleSet == nullptr)
        {
            return false;
        }

        const quint64 kHwndValue = static_cast<quint64>(reinterpret_cast<quintptr>(windowHandle));
        if (context->seenHandleSet->find(kHwndValue) != context->seenHandleSet->end())
        {
            return false;
        }
        context->seenHandleSet->insert(kHwndValue);

        OtherDock::WindowInfo info;
        fillWindowInfo(
            windowHandle,
            context->zOrderCounter++,
            isChildWindow,
            enumApiName,
            info);
        context->outputList->push_back(std::move(info));
        return true;
    }

    BOOL CALLBACK enumChildWindowProc(HWND windowHandle, LPARAM param)
    {
        EnumContext* context = reinterpret_cast<EnumContext*>(param);
        if (context == nullptr)
        {
            return TRUE;
        }
        appendWindowSnapshotIfNeeded(
            context,
            windowHandle,
            true,
            context->childEnumApiName);
        return TRUE;
    }

    // Top-level window enumeration callback: record top-level windows first, then recursively enumerate their child windows.
    BOOL CALLBACK enumTopWindowProc(HWND windowHandle, LPARAM param)
    {
        EnumContext* context = reinterpret_cast<EnumContext*>(param);
        if (context == nullptr)
        {
            return TRUE;
        }

        appendWindowSnapshotIfNeeded(
            context,
            windowHandle,
            false,
            context->topEnumApiName);

        if (context->enumerateChildren)
        {
            ::EnumChildWindows(windowHandle, enumChildWindowProc, param);
        }
        return TRUE;
    }

    // enumThreadTopWindowProc purpose: Thread window enumeration callback (used by EnumThreadWindows).
    BOOL CALLBACK enumThreadTopWindowProc(HWND windowHandle, LPARAM param)
    {
        return enumTopWindowProc(windowHandle, param);
    }

    // appendByEnumWindows purpose: enumerate windows using EnumWindows and recursively enumerate child windows according to configuration.
    void appendByEnumWindows(EnumContext& context)
    {
        context.topEnumApiName = QStringLiteral("EnumWindows");
        context.childEnumApiName = QStringLiteral("EnumChildWindows");
        ::EnumWindows(enumTopWindowProc, reinterpret_cast<LPARAM>(&context));
    }

    // appendByEnumDesktopWindows: Enumerates windows within the current desktop context.
    void appendByEnumDesktopWindows(EnumContext& context)
    {
        context.topEnumApiName = QStringLiteral("EnumDesktopWindows");
        context.childEnumApiName = QStringLiteral("EnumDesktopChildWindows");
        ::EnumDesktopWindows(nullptr, enumTopWindowProc, reinterpret_cast<LPARAM>(&context));
    }

    // appendByEnumThreadWindows purpose: Iterate threads and call EnumThreadWindows to fill missing entries.
    void appendByEnumThreadWindows(EnumContext& context)
    {
        context.topEnumApiName = QStringLiteral("EnumThreadWindows");
        context.childEnumApiName = QStringLiteral("EnumThreadChildWindows");

        HANDLE snapshotHandle = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshotHandle == INVALID_HANDLE_VALUE)
        {
            return;
        }

        THREADENTRY32 threadEntry{};
        threadEntry.dwSize = sizeof(threadEntry);
        if (::Thread32First(snapshotHandle, &threadEntry) == FALSE)
        {
            ::CloseHandle(snapshotHandle);
            return;
        }

        do
        {
            // threadEntry.th32ThreadID usage: The thread ID currently being traversed, passed as an argument to EnumThreadWindows.
            ::EnumThreadWindows(
                threadEntry.th32ThreadID,
                enumThreadTopWindowProc,
                reinterpret_cast<LPARAM>(&context));
        } while (::Thread32Next(snapshotHandle, &threadEntry) != FALSE);

        ::CloseHandle(snapshotHandle);
    }

    // collectWindowSnapshotByMode purpose: Collect window snapshots according to the user-selected enumeration strategy.
    void collectWindowSnapshotByMode(const int enumMode, std::vector<OtherDock::WindowInfo>& snapshotOut)
    {
        snapshotOut.clear();
        snapshotOut.reserve(512);
        std::unordered_set<quint64> seenSet;
        seenSet.reserve(2048);

        EnumContext context;
        context.outputList = &snapshotOut;
        context.seenHandleSet = &seenSet;
        context.zOrderCounter = 0;
        context.enumerateChildren = true;

        if (enumMode == 0)
        {
            // Hybrid mode: deduplicate after stacking multiple strategies to prioritize resolving "single-API omissions".
            appendByEnumWindows(context);
            appendByEnumDesktopWindows(context);
            appendByEnumThreadWindows(context);
            return;
        }

        if (enumMode == 1)
        {
            appendByEnumWindows(context);
            return;
        }

        if (enumMode == 2)
        {
            appendByEnumDesktopWindows(context);
            return;
        }

        if (enumMode == 3)
        {
            appendByEnumThreadWindows(context);
            return;
        }

        // Mode 4: EnumWindows on top-level windows only, no recursion into child windows, for easier comparison and troubleshooting.
        context.enumerateChildren = false;
        appendByEnumWindows(context);
    }
}

// ============================================================
// WindowDetailDialog
// Purpose:
// - Independent non-modal window property dialog.
// - Provides tabbed property viewing and partial real-time modification capabilities.
// ============================================================
class WindowDetailDialog final : public QDialog
{
public:
    // Constructor:
    // - Purpose: Cache initial window information, build the UI, and synchronize runtime data once.
    // - Parameter info: Snapshot data from the window list.
    // - Parameter parent: Qt parent widget.
    explicit WindowDetailDialog(const OtherDock::WindowInfo& info, QWidget* parent = nullptr)
        : QDialog(parent)
        , info_(info)
    {
        setAttribute(Qt::WA_DeleteOnClose, true);
        setObjectName(QStringLiteral("WindowDetailDialogRoot"));
        // Keep the inspected HWND as structured metadata.  Companion pages must
        // not have to parse a localized/user-controlled window title to find it.
        setProperty("ksword.windowDetail.targetHwnd", QVariant::fromValue(info.hwndValue));
        setAttribute(Qt::WA_StyledBackground, true);
        setAutoFillBackground(true);
        setStyleSheet(buildOpaqueWindowDetailDialogStyle(objectName()));
        setWindowTitle(QStringLiteral("窗口属性 - [%1] (%2)")
            .arg(info.titleText.isEmpty() ? QStringLiteral("<无标题>") : info.titleText,
                hwndToText(info.hwndValue)));
        resize(900, 680);

        initializeUi();
        refreshRuntimeInfo();
        startMessageMonitor();
    }

    // Destructor:
    // - Purpose: Ensure message hook handles are released when closing the detail dialog to prevent system-residual callbacks.
    ~WindowDetailDialog() override
    {
        stopMessageMonitor();
    }

private:
    // StyleCheckBinding：
    // - Purpose: Save the binding between a checkbox and its corresponding style bit.
    // - Call: Refresh style by binding to fill check states; apply style by binding to collect bitmasks.
    // - Pass-by-value: this struct serves only as an internal container for WindowDetailDialog and is not passed across classes.
    struct StyleCheckBinding
    {
        QString styleNameText;            // styleNameText: Style bit name (used for display and export).
        QString styleDescriptionText;     // styleDescriptionText: Style description (used for hints).
        quint64 styleMaskValue = 0;       // styleMaskValue: Win32 style bitmask.
        QCheckBox* checkBox = nullptr;    // checkBox: Check box bound to style bits.
    };

    // PendingMessageRow: message row temporarily stored while the right-click menu is open.
    // Message streams cannot discard intermediate events using a latest-wins strategy, so they are first queued in the dialog queue.
    struct PendingMessageRow
    {
        QString channelText;
        quint64 hwndValue = 0;
        quint64 messageId = 0;
        quint64 wParamValue = 0;
        quint64 lParamValue = 0;
        quint64 resultValue = 0;
        QString extraText;
    };

    // appendStyleCheckBoxGroup：
    // - Purpose: Convert a set of style definitions into a checkbox grid and add it to the layout.
    // - Called: invoke once for each of the 'Window Style' and 'Extended Style' control groups when initializeUi creates them;
    // - Pass definitionList/bindingList: definition list and output binding container.
    // - Returns nothing; results are written directly to the UI layout and bindingList.
    void appendStyleCheckBoxGroup(
        QWidget* parentWidget,
        QVBoxLayout* hostLayout,
        const QString& groupTitleText,
        const std::vector<WindowStyleFlagDefinition>& definitionList,
        std::vector<StyleCheckBinding>* bindingList)
    {
        if (parentWidget == nullptr || hostLayout == nullptr || bindingList == nullptr)
        {
            return;
        }

        QGroupBox* groupBox = new QGroupBox(groupTitleText, parentWidget);
        QGridLayout* gridLayout = new QGridLayout(groupBox);
        gridLayout->setContentsMargins(8, 8, 8, 8);
        gridLayout->setHorizontalSpacing(12);
        gridLayout->setVerticalSpacing(4);

        int itemIndex = 0;
        for (const WindowStyleFlagDefinition& definition : definitionList)
        {
            // checkboxText: Displays the style bit name to facilitate direct mapping with documentation/Win32 constants.
            const QString kCheckboxText = QString::fromLatin1(definition.styleNameText);
            QCheckBox* flagCheckBox = new QCheckBox(kCheckboxText, groupBox);
            // checkboxTip: Explains the purpose of this style bit on mouse hover.
            const QString kCheckboxTip = QString::fromUtf8(definition.styleDescriptionText);
            flagCheckBox->setToolTip(kCheckboxTip);

            const int kRowIndex = itemIndex / 2;
            const int kColIndex = itemIndex % 2;
            gridLayout->addWidget(flagCheckBox, kRowIndex, kColIndex);
            ++itemIndex;

            StyleCheckBinding binding;
            binding.styleNameText = kCheckboxText;
            binding.styleDescriptionText = kCheckboxTip;
            binding.styleMaskValue = definition.styleMaskValue;
            binding.checkBox = flagCheckBox;
            bindingList->push_back(binding);

            connect(flagCheckBox, &QCheckBox::toggled, this, [this](bool) {
                if (styleCheckSyncing_)
                {
                    return;
                }

                // Immediately refresh the topmost/layered linkage display of the 'Status Panel' upon changes.
                updateDerivedStyleControlsFromCheckBoxes();
                if (styleApplyButton_ != nullptr)
                {
                    styleApplyButton_->setEnabled(true);
                }
                if (applyButton_ != nullptr)
                {
                    applyButton_->setEnabled(true);
                }
            });
        }

        hostLayout->addWidget(groupBox, 0);
    }

    // collectStyleFlagsFromCheckBoxes：
    // - Purpose: Aggregate all checkbox states into two masks: style and exStyle.
    // - Calls: applyStyleCheckBoxChanges, updateDerivedStyleControlsFromCheckBoxes;
    // - In/out: output the target style values via styleValueOut/exStyleValueOut.
    void collectStyleFlagsFromCheckBoxes(quint64* styleValueOut, quint64* exStyleValueOut) const
    {
        if (styleValueOut != nullptr)
        {
            *styleValueOut = 0;
        }
        if (exStyleValueOut != nullptr)
        {
            *exStyleValueOut = 0;
        }

        if (styleValueOut != nullptr)
        {
            for (const StyleCheckBinding& binding : styleCheckBindingList_)
            {
                if (binding.checkBox != nullptr && binding.checkBox->isChecked())
                {
                    *styleValueOut |= binding.styleMaskValue;
                }
            }
        }

        if (exStyleValueOut != nullptr)
        {
            for (const StyleCheckBinding& binding : exStyleCheckBindingList_)
            {
                if (binding.checkBox != nullptr && binding.checkBox->isChecked())
                {
                    *exStyleValueOut |= binding.styleMaskValue;
                }
            }
        }
    }

    // updateDerivedStyleControlsFromCheckBoxes：
    // - Purpose: Sync 'Always on Top' status and transparency control availability based on current checkbox states.
    // - Call: after checkbox state change and after refreshing styles to fill back.
    // - Input/Output: none; directly updates m_topMostCheck / m_alphaSlider.
    void updateDerivedStyleControlsFromCheckBoxes()
    {
        quint64 styleValue = 0;
        quint64 exStyleValue = 0;
        collectStyleFlagsFromCheckBoxes(&styleValue, &exStyleValue);

        if (topMostCheck_ != nullptr)
        {
            Q_UNUSED(styleValue);
            topMostCheck_->setChecked((exStyleValue & WS_EX_TOPMOST) != 0);
        }
        if (alphaSlider_ != nullptr)
        {
            alphaSlider_->setEnabled((exStyleValue & WS_EX_LAYERED) != 0);
        }
    }

    // syncStyleCheckBoxes：
    // - Purpose: Fill back the current system style values into the checkboxes.
    // - Call: refreshRuntimeInfo is invoked after reading the latest style each time;
    // - Inputs styleValue/exStyleValue: real-time style values of the target window;
    // - Output: None; UI checkbox states are synchronized to real-time values.
    void syncStyleCheckBoxes(const quint64 styleValue, const quint64 exStyleValue)
    {
        styleCheckSyncing_ = true;
        for (const StyleCheckBinding& binding : styleCheckBindingList_)
        {
            if (binding.checkBox != nullptr)
            {
                binding.checkBox->setChecked((styleValue & binding.styleMaskValue) != 0);
            }
        }
        for (const StyleCheckBinding& binding : exStyleCheckBindingList_)
        {
            if (binding.checkBox != nullptr)
            {
                binding.checkBox->setChecked((exStyleValue & binding.styleMaskValue) != 0);
            }
        }
        styleCheckSyncing_ = false;
        updateDerivedStyleControlsFromCheckBoxes();
    }

    // buildStyleSummaryText：
    // - Purpose: Concatenate detailed text combining 'hexadecimal style value' with the state of each checkbox;
    // - Called: refreshRuntimeInfo refreshes the style text area.
    // - Input styleValue/exStyleValue: real-time style values.
    // - Out: returns description text directly writable to m_styleText.
    QString buildStyleSummaryText(const quint64 styleValue, const quint64 exStyleValue) const
    {
        QString styleText;
        styleText += QStringLiteral("Style: 0x%1\n").arg(styleValue, 0, 16);
        styleText += QStringLiteral("ExStyle: 0x%1\n").arg(exStyleValue, 0, 16);
        styleText += QStringLiteral("\n[窗口样式 WS_*]\n");
        for (const StyleCheckBinding& binding : styleCheckBindingList_)
        {
            const bool kEnabled = (styleValue & binding.styleMaskValue) != 0;
            styleText += QStringLiteral("%1: %2\n")
                .arg(binding.styleNameText, boolText(kEnabled));
        }

        styleText += QStringLiteral("\n[扩展样式 WS_EX_*]\n");
        for (const StyleCheckBinding& binding : exStyleCheckBindingList_)
        {
            const bool kEnabled = (exStyleValue & binding.styleMaskValue) != 0;
            styleText += QStringLiteral("%1: %2\n")
                .arg(binding.styleNameText, boolText(kEnabled));
        }
        return styleText;
    }

    // applyStyleCheckBoxChanges：
    // - Purpose: Write the checkbox state back to the target window's GWL_STYLE/GWL_EXSTYLE.
    // - Call: Style page 'Apply Style Bits' button, bottom 'Apply Changes' button;
    // - Input showSuccessDialog: whether to show a success dialog;
    // - Output: Returns whether the style write-back was completed (does not guarantee every bit was accepted by the system).
    bool applyStyleCheckBoxChanges(const bool showSuccessDialog)
    {
        HWND windowHandle = toHwnd(info_.hwndValue);
        if (::IsWindow(windowHandle) == FALSE)
        {
            QMessageBox::warning(this, QStringLiteral("应用失败"), QStringLiteral("目标窗口句柄已失效。"));
            return false;
        }

        // selectedStyleValue/selectedExStyleValue: Target values for 'controlled bits' selected via checkboxes.
        quint64 selectedStyleValue = 0;
        quint64 selectedExStyleValue = 0;
        collectStyleFlagsFromCheckBoxes(&selectedStyleValue, &selectedExStyleValue);

        // managedStyleMask/managedExStyleMask: Total mask of style bits currently manageable by the interface.
        quint64 managedStyleMask = 0;
        quint64 managedExStyleMask = 0;
        for (const StyleCheckBinding& binding : styleCheckBindingList_)
        {
            managedStyleMask |= binding.styleMaskValue;
        }
        for (const StyleCheckBinding& binding : exStyleCheckBindingList_)
        {
            managedExStyleMask |= binding.styleMaskValue;
        }

        // currentStyleValue/currentExStyleValue: Reads the system's real-time styles, preserving bits not exposed in the UI.
        const quint64 kCurrentStyleValue = static_cast<quint64>(::GetWindowLongPtrW(windowHandle, GWL_STYLE));
        const quint64 kCurrentExStyleValue = static_cast<quint64>(::GetWindowLongPtrW(windowHandle, GWL_EXSTYLE));
        const quint64 kDesiredStyleValue =
            (kCurrentStyleValue & ~managedStyleMask)
            | (selectedStyleValue & managedStyleMask);
        const quint64 kDesiredExStyleValue =
            (kCurrentExStyleValue & ~managedExStyleMask)
            | (selectedExStyleValue & managedExStyleMask);

        ::SetLastError(ERROR_SUCCESS);
        ::SetWindowLongPtrW(windowHandle, GWL_STYLE, static_cast<LONG_PTR>(kDesiredStyleValue));
        const DWORD kStyleError = ::GetLastError();

        ::SetLastError(ERROR_SUCCESS);
        ::SetWindowLongPtrW(windowHandle, GWL_EXSTYLE, static_cast<LONG_PTR>(kDesiredExStyleValue));
        const DWORD kExStyleError = ::GetLastError();

        // SetWindowPos: triggers non-client area recalculation to ensure style changes take effect immediately.
        ::SetWindowPos(
            windowHandle,
            (kDesiredExStyleValue & WS_EX_TOPMOST) != 0 ? HWND_TOPMOST : HWND_NOTOPMOST,
            0,
            0,
            0,
            0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_FRAMECHANGED);

        // Layered window transparency: Apply Alpha only when WS_EX_LAYERED is checked.
        if ((kDesiredExStyleValue & WS_EX_LAYERED) != 0 && alphaSlider_ != nullptr)
        {
            ::SetLayeredWindowAttributes(
                windowHandle,
                0,
                static_cast<BYTE>(alphaSlider_->value()),
                LWA_ALPHA);
        }

        ::RedrawWindow(
            windowHandle,
            nullptr,
            nullptr,
            RDW_INVALIDATE | RDW_ERASE | RDW_FRAME | RDW_UPDATENOW | RDW_ALLCHILDREN);

        refreshRuntimeInfo();

        const bool kStyleWriteOk = (kStyleError == ERROR_SUCCESS);
        const bool kExStyleWriteOk = (kExStyleError == ERROR_SUCCESS);
        if (!kStyleWriteOk || !kExStyleWriteOk)
        {
            // privilegePromptHandled: Do not display the partial write prompt if the privilege escalation prompt has already covered the failure.
            const bool kPrivilegePromptHandled = ks::ui::promptForPrivilegeFailure(
                this,
                QStringLiteral("修改窗口样式"),
                kStyleWriteOk ? kExStyleError : kStyleError);
            if (!kPrivilegePromptHandled)
            {
                QMessageBox::warning(
                    this,
                    QStringLiteral("样式应用提示"),
                    QStringLiteral("样式写入完成，但部分位返回错误码：Style=%1, ExStyle=%2。")
                    .arg(kStyleError)
                    .arg(kExStyleError));
            }
        }
        else if (showSuccessDialog)
        {
            QMessageBox::information(this, QStringLiteral("窗口样式"), QStringLiteral("样式已应用。"));
        }
        return kStyleWriteOk && kExStyleWriteOk;
    }

    // Build UI: create 5 tabs (the first four property categories merged into "Basic Properties") and bind bottom action buttons.
    void initializeUi()
    {
        QVBoxLayout* rootLayout = new QVBoxLayout(this);

        tabWidget_ = new QTabWidget(this);
        rootLayout->addWidget(tabWidget_, 1);

        // ==================== 1. Basic Properties Tab (merged from the first four tabs) ====================
        QWidget* basicPage = new QWidget(tabWidget_);
        QVBoxLayout* basicLayout = new QVBoxLayout(basicPage);

        // General info group: concentrates display of key fields such as handle relationships and title class names.
        QGroupBox* generalGroup = new QGroupBox(QStringLiteral("常规信息"), basicPage);
        QFormLayout* generalLayout = new QFormLayout(generalGroup);
        handleLabel_ = new QLabel(generalGroup);
        parentHandleLabel_ = new QLabel(generalGroup);
        ownerHandleLabel_ = new QLabel(generalGroup);
        titleEdit_ = new QLineEdit(generalGroup);
        classNameLabel_ = new QLabel(generalGroup);
        instanceLabel_ = new QLabel(generalGroup);
        stateLabel_ = new QLabel(generalGroup);
        relationLabel_ = new QLabel(generalGroup);
        generalLayout->addRow(QStringLiteral("句柄"), handleLabel_);
        generalLayout->addRow(QStringLiteral("父句柄"), parentHandleLabel_);
        generalLayout->addRow(QStringLiteral("所有者句柄"), ownerHandleLabel_);
        titleEdit_->setReadOnly(true);
        generalLayout->addRow(QStringLiteral("标题"), titleEdit_);
        generalLayout->addRow(QStringLiteral("类名"), classNameLabel_);
        generalLayout->addRow(QStringLiteral("实例句柄"), instanceLabel_);
        generalLayout->addRow(QStringLiteral("状态摘要"), stateLabel_);
        generalLayout->addRow(QStringLiteral("关系摘要"), relationLabel_);
        basicLayout->addWidget(generalGroup, 0);

        // Position and Status group: displays editable position and status controls side-by-side to reduce tab switching.
        QGroupBox* layoutStateGroup = new QGroupBox(QStringLiteral("位置与状态"), basicPage);
        QHBoxLayout* layoutStateLayout = new QHBoxLayout(layoutStateGroup);
        QWidget* positionPanel = new QWidget(layoutStateGroup);
        QFormLayout* positionLayout = new QFormLayout(positionPanel);
        QWidget* statePanel = new QWidget(layoutStateGroup);
        QFormLayout* stateLayout = new QFormLayout(statePanel);

        xSpin_ = new QSpinBox(positionPanel);
        ySpin_ = new QSpinBox(positionPanel);
        widthSpin_ = new QSpinBox(positionPanel);
        heightSpin_ = new QSpinBox(positionPanel);
        for (QSpinBox* spinBox : { xSpin_, ySpin_, widthSpin_, heightSpin_ })
        {
            spinBox->setRange(-32768, 32768);
            spinBox->setReadOnly(true);
            spinBox->setButtonSymbols(QAbstractSpinBox::NoButtons);
        }
        widthSpin_->setRange(1, 32768);
        heightSpin_->setRange(1, 32768);

        QPushButton* centerScreenButton = new QPushButton(QIcon(":/Icon/process_tree.svg"), QStringLiteral("居中到屏幕"), positionPanel);
        centerScreenButton->setToolTip(QStringLiteral("把窗口移动到主屏幕中央"));
        centerScreenButton->setStyleSheet(blueButtonStyle());
        positionLayout->addRow(QStringLiteral("X"), xSpin_);
        positionLayout->addRow(QStringLiteral("Y"), ySpin_);
        positionLayout->addRow(QStringLiteral("宽度"), widthSpin_);
        positionLayout->addRow(QStringLiteral("高度"), heightSpin_);
        positionLayout->addRow(QStringLiteral("快捷操作"), centerScreenButton);

        topMostCheck_ = new QCheckBox(QStringLiteral("置顶窗口"), statePanel);
        topMostCheck_->setEnabled(false);
        alphaSlider_ = new QSlider(Qt::Horizontal, statePanel);
        alphaSlider_->setRange(20, 255);
        alphaSlider_->setEnabled(false);
        alphaLabel_ = new QLabel(statePanel);
        stateLayout->addRow(QStringLiteral("置顶"), topMostCheck_);
        stateLayout->addRow(QStringLiteral("透明度"), alphaSlider_);
        stateLayout->addRow(QStringLiteral("当前 Alpha"), alphaLabel_);

        layoutStateLayout->addWidget(positionPanel, 1);
        layoutStateLayout->addWidget(statePanel, 1);
        basicLayout->addWidget(layoutStateGroup, 0);

        // Style group: left-side checkboxes edit style bits, right-side text displays current style details.
        QGroupBox* styleGroup = new QGroupBox(QStringLiteral("样式与外观"), basicPage);
        QHBoxLayout* styleLayout = new QHBoxLayout(styleGroup);
        styleLayout->setContentsMargins(6, 6, 6, 6);
        styleLayout->setSpacing(8);

        QWidget* styleEditorPanel = new QWidget(styleGroup);
        QVBoxLayout* styleEditorLayout = new QVBoxLayout(styleEditorPanel);
        styleEditorLayout->setContentsMargins(0, 0, 0, 0);
        styleEditorLayout->setSpacing(6);

        QHBoxLayout* styleActionLayout = new QHBoxLayout();
        QLabel* styleHintLabel = new QLabel(QStringLiteral("勾选样式位后点击应用"), styleEditorPanel);
        styleHintLabel->setToolTip(QStringLiteral("通过复选框直接调整 GWL_STYLE / GWL_EXSTYLE。"));
        styleRefreshButton_ = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), styleEditorPanel);
        styleApplyButton_ = new QPushButton(QIcon(":/Icon/process_start.svg"), QString(), styleEditorPanel);
        styleRefreshButton_->setToolTip(QStringLiteral("刷新窗口样式位"));
        styleApplyButton_->setToolTip(QStringLiteral("应用当前样式位勾选状态"));
        styleRefreshButton_->setStyleSheet(blueButtonStyle());
        styleApplyButton_->setStyleSheet(blueButtonStyle());
        styleRefreshButton_->setFixedWidth(34);
        styleApplyButton_->setFixedWidth(34);
        styleActionLayout->addWidget(styleHintLabel, 1);
        styleActionLayout->addWidget(styleRefreshButton_, 0);
        styleActionLayout->addWidget(styleApplyButton_, 0);
        styleEditorLayout->addLayout(styleActionLayout);

        QScrollArea* styleScrollArea = new QScrollArea(styleEditorPanel);
        styleScrollArea->setWidgetResizable(true);
        QWidget* styleCheckContainer = new QWidget(styleScrollArea);
        QVBoxLayout* styleCheckLayout = new QVBoxLayout(styleCheckContainer);
        styleCheckLayout->setContentsMargins(0, 0, 0, 0);
        styleCheckLayout->setSpacing(6);
        appendStyleCheckBoxGroup(
            styleCheckContainer,
            styleCheckLayout,
            QStringLiteral("窗口样式（GWL_STYLE）"),
            windowStyleFlagDefinitionList(),
            &styleCheckBindingList_);
        appendStyleCheckBoxGroup(
            styleCheckContainer,
            styleCheckLayout,
            QStringLiteral("扩展样式（GWL_EXSTYLE）"),
            windowExStyleFlagDefinitionList(),
            &exStyleCheckBindingList_);
        styleCheckLayout->addStretch(1);
        styleScrollArea->setWidget(styleCheckContainer);
        styleEditorLayout->addWidget(styleScrollArea, 1);

        styleText_ = new CodeEditorWidget(styleGroup);
        styleText_->setReadOnly(true);
        styleText_->setToolTip(QStringLiteral("显示实时样式值与每个位的解释状态。"));
        styleLayout->addWidget(styleEditorPanel, 1);
        styleLayout->addWidget(styleText_, 1);
        basicLayout->addWidget(styleGroup, 1);

        connect(centerScreenButton, &QPushButton::clicked, this, [this]() {
            QScreen* screen = QGuiApplication::primaryScreen();
            if (screen == nullptr)
            {
                return;
            }
            const QRect kScreenRect = screen->availableGeometry();
            const int kTargetX = kScreenRect.x() + (kScreenRect.width() - widthSpin_->value()) / 2;
            const int kTargetY = kScreenRect.y() + (kScreenRect.height() - heightSpin_->value()) / 2;
            xSpin_->setValue(kTargetX);
            ySpin_->setValue(kTargetY);
        });
        connect(alphaSlider_, &QSlider::valueChanged, this, [this](int value) {
            alphaLabel_->setText(QStringLiteral("%1").arg(value));
        });
        connect(styleRefreshButton_, &QPushButton::clicked, this, [this]() {
            refreshRuntimeInfo();
        });
        connect(styleApplyButton_, &QPushButton::clicked, this, [this]() {
            applyStyleCheckBoxChanges(true);
        });
        tabWidget_->addTab(basicPage, QStringLiteral("基础属性"));
        ks::i18n::LanguageManager::instance().bindTab(
            tabWidget_, basicPage, QStringLiteral("window.detail.tab.basic"), QStringLiteral("基础属性"));

        // ==================== 2. Process/Thread Tab ====================
        QWidget* processPage = new QWidget(tabWidget_);
        QVBoxLayout* processLayout = new QVBoxLayout(processPage);
        processThreadText_ = new CodeEditorWidget(processPage);
        processThreadText_->setReadOnly(true);
        processLayout->addWidget(processThreadText_, 1);
        tabWidget_->addTab(processPage, QStringLiteral("进程与线程"));
        ks::i18n::LanguageManager::instance().bindTab(
            tabWidget_, processPage, QStringLiteral("window.detail.tab.process"), QStringLiteral("进程与线程"));

        // ==================== 3. Class Info Tab ====================
        QWidget* classPage = new QWidget(tabWidget_);
        QVBoxLayout* classLayout = new QVBoxLayout(classPage);
        classText_ = new CodeEditorWidget(classPage);
        classText_->setReadOnly(true);
        classLayout->addWidget(classText_, 1);
        tabWidget_->addTab(classPage, QStringLiteral("类信息"));
        ks::i18n::LanguageManager::instance().bindTab(
            tabWidget_, classPage, QStringLiteral("window.detail.tab.class"), QStringLiteral("类信息"));

        // ==================== 4. Message Hook Tab ====================
        QWidget* hookPage = new QWidget(tabWidget_);
        QVBoxLayout* hookLayout = new QVBoxLayout(hookPage);

        // Overview text: Retain the original message queue state, focus, and other summaries to facilitate quick assessment of window activity.
        hookText_ = new CodeEditorWidget(hookPage);
        hookText_->setReadOnly(true);
        hookText_->setMaximumHeight(260);
        hookLayout->addWidget(hookText_, 0);

        // Control bar: Start/Stop/Clear/Auto-scroll/Max lines; style aligned with other buttons.
        QHBoxLayout* monitorControlLayout = new QHBoxLayout();
        messageStartButton_ = new QPushButton(QIcon(":/Icon/process_start.svg"), QString(), hookPage);
        messageStopButton_ = new QPushButton(QIcon(":/Icon/process_pause.svg"), QString(), hookPage);
        messageClearButton_ = new QPushButton(QIcon(":/Icon/log_clear.svg"), QString(), hookPage);
        messageStartButton_->setToolTip(QStringLiteral("开始消息监控"));
        messageStopButton_->setToolTip(QStringLiteral("停止消息监控"));
        messageClearButton_->setToolTip(QStringLiteral("清空当前消息列表"));
        messageStopButton_->setEnabled(false);
        for (QPushButton* controlButton : { messageStartButton_, messageStopButton_, messageClearButton_ })
        {
            controlButton->setStyleSheet(blueButtonStyle());
            controlButton->setFixedWidth(34);
            monitorControlLayout->addWidget(controlButton);
        }

        messageAutoScrollCheck_ = new QCheckBox(QStringLiteral("自动滚动到底部"), hookPage);
        messageAutoScrollCheck_->setChecked(true);
        monitorControlLayout->addWidget(messageAutoScrollCheck_, 0);

        monitorControlLayout->addWidget(new QLabel(QStringLiteral("最大保留行数"), hookPage), 0);
        messageMaxRowsSpin_ = new QSpinBox(hookPage);
        messageMaxRowsSpin_->setRange(200, 50000);
        messageMaxRowsSpin_->setValue(5000);
        messageMaxRowsSpin_->setStyleSheet(blueInputStyle());
        monitorControlLayout->addWidget(messageMaxRowsSpin_, 0);

        messageModeLabel_ = new QLabel(QStringLiteral("采集模式：未启动"), hookPage);
        messageCountLabel_ = new QLabel(QStringLiteral("已记录: 0, 丢弃: 0"), hookPage);
        monitorControlLayout->addWidget(messageModeLabel_, 0);
        monitorControlLayout->addWidget(messageCountLabel_, 0);
        monitorControlLayout->addStretch(1);
        hookLayout->addLayout(monitorControlLayout);

        // Message table: display captured data row-by-row, offering a message stream view similar to Spy++.
        messageTable_ = new ks::ui::VisibleTableWidget(hookPage);
        messageTable_->setColumnCount(8);
        messageTable_->setHorizontalHeaderLabels(QStringList{
            QStringLiteral("时间"),
            QStringLiteral("通道"),
            QStringLiteral("HWND"),
            QStringLiteral("消息ID"),
            QStringLiteral("消息名"),
            QStringLiteral("WPARAM"),
            QStringLiteral("LPARAM"),
            QStringLiteral("结果/附加")
        });
        messageTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
        messageTable_->setSelectionMode(QAbstractItemView::ExtendedSelection);
        messageTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
        messageTable_->setAlternatingRowColors(true);
        messageTable_->setSortingEnabled(false);
        messageTable_->verticalHeader()->setVisible(false);
        messageTable_->horizontalHeader()->setStretchLastSection(true);
        messageTable_->setContextMenuPolicy(Qt::CustomContextMenu);
        hookLayout->addWidget(messageTable_, 1);

        // Table right-click: supports copying the entire row for convenient comparison with logs or packet capture results.
        connect(messageTable_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& pos) {
            if (messageTable_ == nullptr)
            {
                return;
            }
            QMenu menu;
            // Explicitly fill the menu background to avoid a black background caused by inheriting a transparent style in light mode.
            menu.setStyleSheet(ksword_theme::contextMenuStyle());
            QAction* copyRowAction = menu.addAction(QStringLiteral("复制选中行"));
            QAction* selectedAction = menu.exec(messageTable_->viewport()->mapToGlobal(pos));
            if (selectedAction != copyRowAction)
            {
                return;
            }

            QStringList rowTexts;
            const QList<QTableWidgetSelectionRange> kSelectionRanges = messageTable_->selectedRanges();
            for (const QTableWidgetSelectionRange& range : kSelectionRanges)
            {
                for (int row = range.topRow(); row <= range.bottomRow(); ++row)
                {
                    QStringList singleRow;
                    for (int col = 0; col < messageTable_->columnCount(); ++col)
                    {
                        QTableWidgetItem* item = messageTable_->item(row, col);
                        singleRow << (item == nullptr ? QString() : item->text());
                    }
                    rowTexts << singleRow.join('\t');
                }
            }
            if (!rowTexts.isEmpty())
            {
                QApplication::clipboard()->setText(rowTexts.join('\n'));
            }
        });

        // Monitor control binding: Start/Stop/Clear actions.
        connect(messageStartButton_, &QPushButton::clicked, this, [this]() {
            startMessageMonitor();
        });
        connect(messageStopButton_, &QPushButton::clicked, this, [this]() {
            stopMessageMonitor();
        });
        connect(messageClearButton_, &QPushButton::clicked, this, [this]() {
            clearMessageTable();
        });

        tabWidget_->addTab(hookPage, QStringLiteral("消息钩子"));
        ks::i18n::LanguageManager::instance().bindTab(
            tabWidget_, hookPage, QStringLiteral("window.detail.tab.hooks"), QStringLiteral("消息钩子"));

        // ==================== 5. Advanced Properties Tab ====================
        QWidget* advancedPage = new QWidget(tabWidget_);
        QVBoxLayout* advancedLayout = new QVBoxLayout(advancedPage);
        advancedText_ = new CodeEditorWidget(advancedPage);
        advancedText_->setReadOnly(true);
        advancedLayout->addWidget(advancedText_, 1);
        tabWidget_->addTab(advancedPage, QStringLiteral("高级属性"));
        ks::i18n::LanguageManager::instance().bindTab(
            tabWidget_, advancedPage, QStringLiteral("window.detail.tab.advanced"), QStringLiteral("高级属性"));

        const ks::dwm_order::WindowIdentity kInputIdentity{info_.hwndValue,
            info_.processId, info_.threadId, info_.processCreationTime100ns};
        auto* inputPage = ks::window_input::createControl(kInputIdentity, tabWidget_);
        inputPage->setObjectName(QStringLiteral("ks_window_input_page"));
        tabWidget_->addTab(inputPage, QStringLiteral("窗口输入与顺序"));
        ks::i18n::LanguageManager::instance().bindTab(tabWidget_, inputPage,
            QStringLiteral("window.input.tab"), QStringLiteral("窗口输入与顺序"));

        // ==================== Bottom Buttons ====================
        QHBoxLayout* buttonLayout = new QHBoxLayout();
        rootLayout->addLayout(buttonLayout);
        buttonLayout->addStretch(1);
        refreshButton_ = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), this);
        applyButton_ = new QPushButton(QIcon(":/Icon/process_start.svg"), QString(), this);
        exportButton_ = new QPushButton(QIcon(":/Icon/log_export.svg"), QString(), this);
        closeButton_ = new QPushButton(QIcon(":/Icon/process_terminate.svg"), QString(), this);

        refreshButton_->setToolTip(QStringLiteral("刷新窗口属性"));
        applyButton_->setToolTip(QStringLiteral("应用修改"));
        applyButton_->setEnabled(false);
        exportButton_->setToolTip(QStringLiteral("导出信息"));
        closeButton_->setToolTip(QStringLiteral("关闭详情窗口"));

        for (QPushButton* button : { refreshButton_, applyButton_, exportButton_, closeButton_ })
        {
            button->setStyleSheet(blueButtonStyle());
            button->setFixedWidth(34);
            buttonLayout->addWidget(button, 0);
        }

        connect(refreshButton_, &QPushButton::clicked, this, [this]() {
            refreshRuntimeInfo();
        });
        connect(applyButton_, &QPushButton::clicked, this, [this]() {
            applyChanges();
        });
        connect(exportButton_, &QPushButton::clicked, this, [this]() {
            exportInfo();
        });
        connect(closeButton_, &QPushButton::clicked, this, &QDialog::close);
    }

    // Refresh runtime information: re-sample the handle to avoid displaying stale data.
    void refreshRuntimeInfo()
    {
        HWND windowHandle = toHwnd(info_.hwndValue);
        if (::IsWindow(windowHandle) == FALSE)
        {
            stateLabel_->setText(QStringLiteral("窗口已失效"));
            return;
        }

        // Handle and base status fields.
        handleLabel_->setText(hwndToText(info_.hwndValue));
        parentHandleLabel_->setText(hwndToText(static_cast<quint64>(reinterpret_cast<quintptr>(::GetParent(windowHandle)))));
        ownerHandleLabel_->setText(hwndToText(static_cast<quint64>(reinterpret_cast<quintptr>(::GetWindow(windowHandle, GW_OWNER)))));
        classNameLabel_->setText(info_.classNameText);
        titleEdit_->setText(info_.titleText);
        instanceLabel_->setText(hwndToText(static_cast<quint64>(::GetWindowLongPtrW(windowHandle, GWLP_HINSTANCE))));

        const bool kVisible = ::IsWindowVisible(windowHandle) != FALSE;
        const bool kEnabled = ::IsWindowEnabled(windowHandle) != FALSE;
        const bool kMinimized = ::IsIconic(windowHandle) != FALSE;
        const bool kMaximized = ::IsZoomed(windowHandle) != FALSE;

        stateLabel_->setText(QStringLiteral("可见:%1, 可用:%2, 状态:%3")
            .arg(boolText(kVisible), boolText(kEnabled), windowStateText(true, kMinimized, kMaximized)));
        relationLabel_->setText(QStringLiteral("PID=%1, TID=%2")
            .arg(info_.processId)
            .arg(info_.threadId));

        // Style information: output the hexadecimal style value and common marker judgment.
        const quint64 kStyleValue = static_cast<quint64>(::GetWindowLongPtrW(windowHandle, GWL_STYLE));
        const quint64 kExStyleValue = static_cast<quint64>(::GetWindowLongPtrW(windowHandle, GWL_EXSTYLE));
        syncStyleCheckBoxes(kStyleValue, kExStyleValue);
        styleText_->setText(buildStyleSummaryText(kStyleValue, kExStyleValue));

        // Write back the window position and size to the edit control.
        RECT rect{};
        const bool kWindowRectReady = (::GetWindowRect(windowHandle, &rect) != FALSE);
        if (kWindowRectReady)
        {
            xSpin_->setValue(rect.left);
            ySpin_->setValue(rect.top);
            widthSpin_->setValue(std::max<int>(1, static_cast<int>(rect.right - rect.left)));
            heightSpin_->setValue(std::max<int>(1, static_cast<int>(rect.bottom - rect.top)));
        }
        else
        {
            xSpin_->setValue(0);
            ySpin_->setValue(0);
            widthSpin_->setValue(1);
            heightSpin_->setValue(1);
        }

        // Status page: topmost and transparency.
        topMostCheck_->setChecked((kExStyleValue & WS_EX_TOPMOST) != 0);
        int alphaValue = 255;
        if ((kExStyleValue & WS_EX_LAYERED) != 0)
        {
            COLORREF colorKey = 0;
            BYTE alpha = 255;
            DWORD flags = 0;
            if (::GetLayeredWindowAttributes(windowHandle, &colorKey, &alpha, &flags) != FALSE)
            {
                Q_UNUSED(colorKey);
                Q_UNUSED(flags);
                alphaValue = static_cast<int>(alpha);
            }
        }
        alphaSlider_->setValue(alphaValue);
        alphaSlider_->setEnabled((kExStyleValue & WS_EX_LAYERED) != 0);
        alphaLabel_->setText(QString::number(alphaValue));

        // Process and thread information: complete with path, priority, handle count, start time, and module summary for troubleshooting and behavioral auditing.
        QString processText;
        processText += QStringLiteral("PID: %1\n").arg(info_.processId);
        processText += QStringLiteral("ProcessName: %1\n").arg(info_.processNameText);
        processText += QStringLiteral("TID: %1\n").arg(info_.threadId);
        if (kWindowRectReady)
        {
            processText += QStringLiteral("WindowRect: [%1,%2,%3,%4]\n")
                .arg(rect.left).arg(rect.top).arg(rect.right).arg(rect.bottom);
        }
        else
        {
            processText += QStringLiteral("WindowRect: <N/A>\n");
        }

        HANDLE processHandle = ::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            FALSE,
            info_.processId);
        if (processHandle != nullptr)
        {
            wchar_t processPathBuffer[MAX_PATH * 2] = {};
            DWORD processPathLength = static_cast<DWORD>(std::size(processPathBuffer));
            if (::QueryFullProcessImageNameW(processHandle, 0, processPathBuffer, &processPathLength) != FALSE)
            {
                processText += QStringLiteral("ProcessPath: %1\n")
                    .arg(QString::fromWCharArray(processPathBuffer, static_cast<int>(processPathLength)));
            }

            const DWORD kProcessPriority = ::GetPriorityClass(processHandle);
            processText += QStringLiteral("ProcessPriorityClass: 0x%1\n")
                .arg(static_cast<qulonglong>(kProcessPriority), 0, 16);

            DWORD handleCount = 0;
            if (::GetProcessHandleCount(processHandle, &handleCount) != FALSE)
            {
                processText += QStringLiteral("ProcessHandleCount: %1\n").arg(handleCount);
            }

            FILETIME createTime{};
            FILETIME exitTime{};
            FILETIME kernelTime{};
            FILETIME userTime{};
            if (::GetProcessTimes(processHandle, &createTime, &exitTime, &kernelTime, &userTime) != FALSE)
            {
                processText += QStringLiteral("StartTime: %1\n").arg(fileTimeToLocalText(createTime));
                const qulonglong kCpuTotal = fileTimeToUInt64(kernelTime) + fileTimeToUInt64(userTime);
                processText += QStringLiteral("CPUTime(Kernel+User): %1\n").arg(formatDurationFrom100ns(kCpuTotal));

                FILETIME nowFileTime{};
                ::GetSystemTimeAsFileTime(&nowFileTime);
                const qulonglong kNowTick = fileTimeToUInt64(nowFileTime);
                const qulonglong kStartTick = fileTimeToUInt64(createTime);
                if (kNowTick > kStartTick)
                {
                    processText += QStringLiteral("RunTime: %1\n").arg(formatDurationFrom100ns(kNowTick - kStartTick));
                }
            }

            ::CloseHandle(processHandle);
        }
        else
        {
            processText += QStringLiteral("ProcessOpen: 失败（权限不足或进程已退出）\n");
        }

        int moduleCount = 0;
        const QString kModuleSummaryText = buildModuleSummaryText(info_.processId, 8, &moduleCount);
        processText += QStringLiteral("ModuleCount: %1\n").arg(moduleCount);
        processText += QStringLiteral("ModulePreview:\n%1\n").arg(kModuleSummaryText);

        HANDLE threadHandle = ::OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, info_.threadId);
        if (threadHandle != nullptr)
        {
            const int kThreadPriority = ::GetThreadPriority(threadHandle);
            processText += QStringLiteral("ThreadPriority: %1\n").arg(kThreadPriority);

            BOOL priorityBoostDisabled = FALSE;
            if (::GetThreadPriorityBoost(threadHandle, &priorityBoostDisabled) != FALSE)
            {
                processText += QStringLiteral("ThreadPriorityBoostDisabled: %1\n")
                    .arg(boolText(priorityBoostDisabled != FALSE));
            }
            ::CloseHandle(threadHandle);
        }
        else
        {
            processText += QStringLiteral("ThreadOpen: 失败（线程可能已退出）\n");
        }
        processText += QStringLiteral("提示：可从右键菜单跳转到进程详细信息页。");
        processThreadText_->setText(processText);

        // Class information: displays the class name, class style, window procedure address, and class resource handle.
        QString classText;
        classText += QStringLiteral("ClassName: %1\n").arg(info_.classNameText);
        classText += QStringLiteral("ClassAtom: 0x%1\n").arg(static_cast<qulonglong>(::GetClassLongPtrW(windowHandle, GCW_ATOM)), 0, 16);
        classText += QStringLiteral("ClassStyle: 0x%1\n").arg(static_cast<qulonglong>(::GetClassLongPtrW(windowHandle, GCL_STYLE)), 0, 16);
        classText += QStringLiteral("ClassExtraBytes: %1\n")
            .arg(static_cast<qlonglong>(::GetClassLongPtrW(windowHandle, GCL_CBCLSEXTRA)));
        classText += QStringLiteral("WindowExtraBytes: %1\n")
            .arg(static_cast<qlonglong>(::GetClassLongPtrW(windowHandle, GCL_CBWNDEXTRA)));
        classText += QStringLiteral("WndProc: 0x%1\n").arg(static_cast<qulonglong>(::GetWindowLongPtrW(windowHandle, GWLP_WNDPROC)), 0, 16);
        classText += QStringLiteral("MenuHandle: 0x%1\n").arg(static_cast<qulonglong>(reinterpret_cast<quintptr>(::GetMenu(windowHandle))), 0, 16);
        classText += QStringLiteral("ClassHCursor: 0x%1\n")
            .arg(static_cast<qulonglong>(::GetClassLongPtrW(windowHandle, GCLP_HCURSOR)), 0, 16);
        classText += QStringLiteral("ClassHIcon: 0x%1\n")
            .arg(static_cast<qulonglong>(::GetClassLongPtrW(windowHandle, GCLP_HICON)), 0, 16);
        classText += QStringLiteral("ClassHIconSm: 0x%1\n")
            .arg(static_cast<qulonglong>(::GetClassLongPtrW(windowHandle, GCLP_HICONSM)), 0, 16);
        classText += QStringLiteral("ClassHbrBackground: 0x%1\n")
            .arg(static_cast<qulonglong>(::GetClassLongPtrW(windowHandle, GCLP_HBRBACKGROUND)), 0, 16);

        const HMODULE kClassModuleHandle = reinterpret_cast<HMODULE>(::GetClassLongPtrW(windowHandle, GCLP_HMODULE));
        classText += QStringLiteral("ClassModule: 0x%1\n")
            .arg(static_cast<qulonglong>(reinterpret_cast<quintptr>(kClassModuleHandle)), 0, 16);
        if (kClassModuleHandle != nullptr)
        {
            wchar_t modulePathBuffer[MAX_PATH * 2] = {};
            const DWORD kPathLength = ::GetModuleFileNameW(
                kClassModuleHandle,
                modulePathBuffer,
                static_cast<DWORD>(std::size(modulePathBuffer)));
            if (kPathLength > 0)
            {
                classText += QStringLiteral("ClassModulePath: %1\n")
                    .arg(QString::fromWCharArray(modulePathBuffer, static_cast<int>(kPathLength)));
            }
        }
        classText_->setText(classText);

        // Hook/message page: complete the message queue state and GUI thread focus handle, replacing the original placeholder text.
        int childWindowCount = 0;
        ::EnumChildWindows(
            windowHandle,
            [](HWND, LPARAM lParam) -> BOOL {
                int* countPtr = reinterpret_cast<int*>(lParam);
                if (countPtr != nullptr)
                {
                    *countPtr += 1;
                }
                return TRUE;
            },
            reinterpret_cast<LPARAM>(&childWindowCount));

        int siblingCount = 0;
        const HWND kParentWindowHandle = ::GetParent(windowHandle);
        if (kParentWindowHandle != nullptr)
        {
            std::pair<HWND, int*> siblingContext{ windowHandle, &siblingCount };
            ::EnumChildWindows(
                kParentWindowHandle,
                [](HWND childHandle, LPARAM lParam) -> BOOL {
                    auto* pairPtr = reinterpret_cast<std::pair<HWND, int*>*>(lParam);
                    if (pairPtr == nullptr || pairPtr->second == nullptr)
                    {
                        return TRUE;
                    }
                    if (childHandle != pairPtr->first)
                    {
                        *(pairPtr->second) += 1;
                    }
                    return TRUE;
                },
                reinterpret_cast<LPARAM>(&siblingContext));
        }

        GUITHREADINFO guiThreadInfo{};
        guiThreadInfo.cbSize = sizeof(guiThreadInfo);
        const bool kGuiInfoReady = (::GetGUIThreadInfo(info_.threadId, &guiThreadInfo) != FALSE);

        const DWORD kQueueStatus = ::GetQueueStatus(QS_ALLINPUT);
        QString hookText;
        hookText += QStringLiteral("IsHungAppWindow: %1\n")
            .arg(boolText(::IsHungAppWindow(windowHandle) != FALSE));
        hookText += QStringLiteral("ChildWindowCount: %1\n").arg(childWindowCount);
        hookText += QStringLiteral("SiblingWindowCount: %1\n").arg(siblingCount);
        hookText += QStringLiteral("Visible: %1\n").arg(boolText(::IsWindowVisible(windowHandle) != FALSE));
        hookText += QStringLiteral("Enabled: %1\n").arg(boolText(::IsWindowEnabled(windowHandle) != FALSE));
        hookText += QStringLiteral("QueueStatusRaw: 0x%1\n")
            .arg(static_cast<qulonglong>(kQueueStatus), 0, 16);
        hookText += QStringLiteral("QueueCurrentFlags(LOWORD): 0x%1\n")
            .arg(static_cast<unsigned int>(LOWORD(kQueueStatus)), 0, 16);
        hookText += QStringLiteral("QueueNewFlags(HIWORD): 0x%1\n")
            .arg(static_cast<unsigned int>(HIWORD(kQueueStatus)), 0, 16);
        hookText += QStringLiteral("GUIThreadInfoReady: %1\n").arg(boolText(kGuiInfoReady));
        if (kGuiInfoReady)
        {
            hookText += QStringLiteral("Focus: %1\n")
                .arg(hwndToText(static_cast<quint64>(reinterpret_cast<quintptr>(guiThreadInfo.hwndFocus))));
            hookText += QStringLiteral("Active: %1\n")
                .arg(hwndToText(static_cast<quint64>(reinterpret_cast<quintptr>(guiThreadInfo.hwndActive))));
            hookText += QStringLiteral("Capture: %1\n")
                .arg(hwndToText(static_cast<quint64>(reinterpret_cast<quintptr>(guiThreadInfo.hwndCapture))));
            hookText += QStringLiteral("Caret: %1\n")
                .arg(hwndToText(static_cast<quint64>(reinterpret_cast<quintptr>(guiThreadInfo.hwndCaret))));
            hookText += QStringLiteral("MenuOwner: %1\n")
                .arg(hwndToText(static_cast<quint64>(reinterpret_cast<quintptr>(guiThreadInfo.hwndMenuOwner))));
        }
        hookText += QStringLiteral("ForegroundWindow: %1\n")
            .arg(hwndToText(static_cast<quint64>(reinterpret_cast<quintptr>(::GetForegroundWindow()))));
        hookText += QStringLiteral("说明：系统级 Hook 链表不提供官方通用枚举接口，当前页聚焦可稳定获取的消息上下文。");
        hookText_->setText(hookText);

        // Advanced page: includes DPI, property table (GetProp/EnumPropsExW), and window extra bytes.
        QString advancedText;
        advancedText += QStringLiteral("UserData (GWLP_USERDATA): 0x%1\n")
            .arg(static_cast<qulonglong>(::GetWindowLongPtrW(windowHandle, GWLP_USERDATA)), 0, 16);
        advancedText += QStringLiteral("ID (GWLP_ID): 0x%1\n")
            .arg(static_cast<qulonglong>(::GetWindowLongPtrW(windowHandle, GWLP_ID)), 0, 16);
        advancedText += QStringLiteral("WndProc (GWLP_WNDPROC): 0x%1\n")
            .arg(static_cast<qulonglong>(::GetWindowLongPtrW(windowHandle, GWLP_WNDPROC)), 0, 16);
        advancedText += QStringLiteral("HINSTANCE (GWLP_HINSTANCE): 0x%1\n")
            .arg(static_cast<qulonglong>(::GetWindowLongPtrW(windowHandle, GWLP_HINSTANCE)), 0, 16);
        advancedText += QStringLiteral("Parent: %1\n").arg(hwndToText(static_cast<quint64>(reinterpret_cast<quintptr>(::GetParent(windowHandle)))));
        advancedText += QStringLiteral("Owner: %1\n").arg(hwndToText(static_cast<quint64>(reinterpret_cast<quintptr>(::GetWindow(windowHandle, GW_OWNER)))));

        DWORD displayAffinity = 0;
        if (::GetWindowDisplayAffinity(windowHandle, &displayAffinity) != FALSE)
        {
            advancedText += QStringLiteral("DisplayAffinity: 0x%1\n")
                .arg(static_cast<qulonglong>(displayAffinity), 0, 16);
        }

        RECT clientRect{};
        if (::GetClientRect(windowHandle, &clientRect) != FALSE)
        {
            advancedText += QStringLiteral("ClientRect: [%1,%2,%3,%4]\n")
                .arg(clientRect.left)
                .arg(clientRect.top)
                .arg(clientRect.right)
                .arg(clientRect.bottom);
        }

        // Compatibility with older systems: GetDpiForWindow is only available on newer systems; perform runtime dynamic check.
        using GetDpiForWindowFunc = UINT(WINAPI*)(HWND);
        const HMODULE kUser32Handle = ::GetModuleHandleW(L"user32.dll");
        GetDpiForWindowFunc getDpiForWindow = nullptr;
        if (kUser32Handle != nullptr)
        {
            getDpiForWindow = reinterpret_cast<GetDpiForWindowFunc>(::GetProcAddress(kUser32Handle, "GetDpiForWindow"));
        }
        if (getDpiForWindow != nullptr)
        {
            advancedText += QStringLiteral("DPI: %1\n").arg(getDpiForWindow(windowHandle));
        }

        // enumerate window property keys to detect subclassing frameworks, input method editors, and UI library attachments.
        QStringList propLines;
        WindowPropEnumContext propContext;
        propContext.lines = &propLines;
        propContext.maxCount = 200;
        ::EnumPropsExW(windowHandle, enumWindowPropProc, reinterpret_cast<LPARAM>(&propContext));
        advancedText += QStringLiteral("PropCount: %1\n").arg(propLines.size());
        if (!propLines.isEmpty())
        {
            advancedText += QStringLiteral("Properties:\n");
            for (const QString& line : propLines)
            {
                advancedText += QStringLiteral("  - %1\n").arg(line);
            }
        }
        else
        {
            advancedText += QStringLiteral("Properties: <none>\n");
        }
        advancedText_->setText(advancedText);

        // Synchronize the message monitor status label on refresh to avoid displaying stale mode text after page switching.
        updateMessageMonitorUiState();
    }

    // Clear message table: reset visible list and counter.
    void clearMessageTable()
    {
        deferredMessageRows_.clear();
        if (messageTable_ != nullptr)
        {
            messageTable_->setRowCount(0);
        }
        capturedMessageCount_ = 0;
        droppedMessageCount_ = 0;
        if (messageCountLabel_ != nullptr)
        {
            messageCountLabel_->setText(QStringLiteral("已记录: 0, 丢弃: 0"));
        }
    }

    // Start message monitor:
    // - For windows in the same process, prefer thread message hooks (WH_CALLWNDPROC/WH_GETMESSAGE/WH_CALLWNDPROCRET).
    // - Cross-process window fallback to WinEvent event stream (no DLL injection; stable but not equivalent to a full message queue).
    void startMessageMonitor()
    {
        if (messageMonitorRunning_.load())
        {
            return;
        }

        HWND windowHandle = toHwnd(info_.hwndValue);
        if (::IsWindow(windowHandle) == FALSE)
        {
            QMessageBox::warning(this, QStringLiteral("消息监控"), QStringLiteral("目标窗口句柄已失效，无法启动监控。"));
            return;
        }

        bool monitorStarted = false;
        messageMonitorMode_ = QStringLiteral("未启动");
        winEventHookSnapshot_ = nullptr;
        const DWORD kCurrentPid = ::GetCurrentProcessId();
        if (info_.processId == kCurrentPid && info_.threadId != 0)
        {
            const HINSTANCE kModuleHandle = ::GetModuleHandleW(nullptr);
            callWndHook_ = ::SetWindowsHookExW(
                WH_CALLWNDPROC,
                &WindowDetailDialog::callWndHookProc,
                kModuleHandle,
                static_cast<DWORD>(info_.threadId));
            getMessageHook_ = ::SetWindowsHookExW(
                WH_GETMESSAGE,
                &WindowDetailDialog::getMessageHookProc,
                kModuleHandle,
                static_cast<DWORD>(info_.threadId));
            callWndRetHook_ = ::SetWindowsHookExW(
                WH_CALLWNDPROCRET,
                &WindowDetailDialog::callWndRetHookProc,
                kModuleHandle,
                static_cast<DWORD>(info_.threadId));

            if (callWndHook_ != nullptr || getMessageHook_ != nullptr || callWndRetHook_ != nullptr)
            {
                registerThreadDialog(static_cast<DWORD>(info_.threadId), this);
                threadRegistered_ = true;
                messageMonitorMode_ = QStringLiteral("线程消息钩子（同进程）");
                monitorStarted = true;
            }
        }

        if (!monitorStarted)
        {
            winEventHook_ = ::SetWinEventHook(
                EVENT_MIN,
                EVENT_MAX,
                nullptr,
                &WindowDetailDialog::winEventHookProc,
                static_cast<DWORD>(info_.processId),
                static_cast<DWORD>(info_.threadId),
                WINEVENT_OUTOFCONTEXT);
            if (winEventHook_ != nullptr)
            {
                registerEventHookDialog(winEventHook_, this);
                eventRegistered_ = true;
                winEventHookSnapshot_ = winEventHook_;
                messageMonitorMode_ = QStringLiteral("WinEvent 回退（跨进程）");
                monitorStarted = true;
            }
        }

        if (!monitorStarted)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("消息监控"),
                QStringLiteral("启动失败：目标线程不允许安装消息钩子，且 WinEvent 回退也失败。"));
            return;
        }

        messageMonitorRunning_.store(true);
        updateMessageMonitorUiState();

        KLogEvent logEvent;
        info << logEvent
            << "[WindowDetailDialog] 消息监控已启动, hwnd="
            << hwndToText(info_.hwndValue).toStdString()
            << ", mode="
            << messageMonitorMode_.toStdString()
            << eol;
    }

    // Stop message monitoring: release all hooks and unregister callback mappings.
    void stopMessageMonitor()
    {
        const bool kWasRunning = messageMonitorRunning_.exchange(false);

        if (callWndHook_ != nullptr)
        {
            ::UnhookWindowsHookEx(callWndHook_);
            callWndHook_ = nullptr;
        }
        if (getMessageHook_ != nullptr)
        {
            ::UnhookWindowsHookEx(getMessageHook_);
            getMessageHook_ = nullptr;
        }
        if (callWndRetHook_ != nullptr)
        {
            ::UnhookWindowsHookEx(callWndRetHook_);
            callWndRetHook_ = nullptr;
        }
        if (winEventHook_ != nullptr)
        {
            ::UnhookWinEvent(winEventHook_);
            winEventHook_ = nullptr;
        }

        if (threadRegistered_)
        {
            unregisterThreadDialog(static_cast<DWORD>(info_.threadId), this);
            threadRegistered_ = false;
        }
        if (eventRegistered_)
        {
            unregisterEventHookDialog(winEventHookSnapshot_, this);
            eventRegistered_ = false;
            winEventHookSnapshot_ = nullptr;
        }

        if (kWasRunning)
        {
            KLogEvent logEvent;
            info << logEvent
                << "[WindowDetailDialog] 消息监控已停止, hwnd="
                << hwndToText(info_.hwndValue).toStdString()
                << eol;
        }

        messageMonitorMode_ = QStringLiteral("已停止");
        updateMessageMonitorUiState();
    }

    // updateMessageMonitorUiState:
    // - Unified update of button states and mode text to avoid scattered state refresh logic.
    // - Simultaneously refreshes the 'Recorded/Discarded' count labels.
    void updateMessageMonitorUiState()
    {
        const bool kRunning = messageMonitorRunning_.load();
        if (messageStartButton_ != nullptr)
        {
            messageStartButton_->setEnabled(!kRunning);
        }
        if (messageStopButton_ != nullptr)
        {
            messageStopButton_->setEnabled(kRunning);
        }
        if (messageModeLabel_ != nullptr)
        {
            messageModeLabel_->setText(
                kRunning
                ? QStringLiteral("采集模式：%1").arg(messageMonitorMode_)
                : QStringLiteral("采集模式：%1").arg(messageMonitorMode_));
        }
        if (messageCountLabel_ != nullptr)
        {
            messageCountLabel_->setText(
                QStringLiteral("已记录: %1, 丢弃: %2")
                .arg(capturedMessageCount_)
                .arg(droppedMessageCount_));
        }
    }

    // appendMessageRow:
    // - Appends a message row to the table only on the UI thread.
    // - When the maximum row count is exceeded, remove the oldest row and accumulate the discard count.
    void appendMessageRow(
        const QString& channelText,
        const quint64 hwndValue,
        const quint64 messageId,
        const quint64 wParamValue,
        const quint64 lParamValue,
        const quint64 resultValue,
        const QString& extraText)
    {
        if (messageTable_ == nullptr)
        {
            return;
        }

        if (ks::ui::isTableUiCommitBlockedByContextMenu({messageTable_}))
        {
            const int kMaxDeferredRows =
                (messageMaxRowsSpin_ == nullptr) ? 5000 : messageMaxRowsSpin_->value();
            while (static_cast<int>(deferredMessageRows_.size()) >= kMaxDeferredRows)
            {
                deferredMessageRows_.pop_front();
                ++droppedMessageCount_;
            }
            deferredMessageRows_.push_back({
                channelText,
                hwndValue,
                messageId,
                wParamValue,
                lParamValue,
                resultValue,
                extraText
            });

            const QPointer<WindowDetailDialog> kSafeThis(this);
            ks::ui::deferTableUiCommitIfContextMenuOpen(
                this,
                QStringLiteral("window-message-stream-flush"),
                {messageTable_},
                [kSafeThis]()
                {
                    if (!kSafeThis.isNull())
                    {
                        kSafeThis->flushDeferredMessageRows();
                    }
                });
            updateMessageMonitorUiState();
            return;
        }

        const int kMaxRows = (messageMaxRowsSpin_ == nullptr) ? 5000 : messageMaxRowsSpin_->value();
        while (messageTable_->rowCount() >= kMaxRows)
        {
            messageTable_->removeRow(0);
            ++droppedMessageCount_;
        }

        const int kRowIndex = messageTable_->rowCount();
        messageTable_->insertRow(kRowIndex);

        const QString kMessageNameText = (channelText.contains(QStringLiteral("WinEvent")))
            ? winEventName(static_cast<DWORD>(messageId))
            : windowMessageName(static_cast<UINT>(messageId));

        const QString kMessageIdText = channelText.contains(QStringLiteral("WinEvent"))
            ? QStringLiteral("0x%1").arg(static_cast<qulonglong>(messageId), 4, 16, QChar('0')).toUpper()
            : QStringLiteral("0x%1").arg(static_cast<qulonglong>(messageId), 4, 16, QChar('0')).toUpper();

        const QString kResultColumnText = extraText.trimmed().isEmpty()
            ? toHexText64(resultValue)
            : QStringLiteral("%1 | %2").arg(toHexText64(resultValue), extraText);

        messageTable_->setItem(kRowIndex, 0, new QTableWidgetItem(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss.zzz"))));
        messageTable_->setItem(kRowIndex, 1, new QTableWidgetItem(channelText));
        messageTable_->setItem(kRowIndex, 2, new QTableWidgetItem(hwndToText(hwndValue)));
        messageTable_->setItem(kRowIndex, 3, new QTableWidgetItem(kMessageIdText));
        messageTable_->setItem(kRowIndex, 4, new QTableWidgetItem(kMessageNameText));
        messageTable_->setItem(kRowIndex, 5, new QTableWidgetItem(toHexText64(wParamValue)));
        messageTable_->setItem(kRowIndex, 6, new QTableWidgetItem(toHexText64(lParamValue)));
        messageTable_->setItem(kRowIndex, 7, new QTableWidgetItem(kResultColumnText));

        ++capturedMessageCount_;
        updateMessageMonitorUiState();

        if (messageAutoScrollCheck_ != nullptr && messageAutoScrollCheck_->isChecked())
        {
            messageTable_->scrollToBottom();
        }
    }

    // flushDeferredMessageRows:
    // - After the menu closes, write back all deferred messages in their original order.
    // - If another menu is already open, keep the queue and wait for the next safe re-injection.
    void flushDeferredMessageRows()
    {
        if (deferredMessageRows_.empty())
        {
            return;
        }

        const QPointer<WindowDetailDialog> kSafeThis(this);
        if (ks::ui::deferTableUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("window-message-stream-flush"),
            {messageTable_},
            [kSafeThis]()
            {
                if (!kSafeThis.isNull())
                {
                    kSafeThis->flushDeferredMessageRows();
                }
            }))
        {
            return;
        }

        std::deque<PendingMessageRow> pendingRows;
        pendingRows.swap(deferredMessageRows_);
        for (const PendingMessageRow& pendingRow : pendingRows)
        {
            appendMessageRow(
                pendingRow.channelText,
                pendingRow.hwndValue,
                pendingRow.messageId,
                pendingRow.wParamValue,
                pendingRow.lParamValue,
                pendingRow.resultValue,
                pendingRow.extraText);
        }
    }

    // threadHookDispatch:
    // - Called by a static message hook callback.
    // - Find the corresponding details window by threadId and asynchronously forward the message to the UI thread.
    static void threadHookDispatch(
        const DWORD threadId,
        const QString& channelText,
        HWND targetHwnd,
        const UINT messageId,
        const WPARAM wParamValue,
        const LPARAM lParamValue,
        const LRESULT resultValue)
    {
        std::vector<WindowDetailDialog*> dialogList;
        {
            std::lock_guard<std::mutex> lockGuard(sMonitorRegistryMutex);
            const auto kIt = sThreadDialogMap.find(threadId);
            if (kIt != sThreadDialogMap.end())
            {
                dialogList = kIt->second;
            }
        }

        if (dialogList.empty() || targetHwnd == nullptr)
        {
            return;
        }

        for (WindowDetailDialog* dialog : dialogList)
        {
            if (dialog == nullptr || !dialog->messageMonitorRunning_.load())
            {
                continue;
            }
            if (targetHwnd != dialog->targetWindowHandle())
            {
                continue;
            }

            const QPointer<WindowDetailDialog> kGuardDialog(dialog);
            const quint64 kHwndValue = static_cast<quint64>(reinterpret_cast<quintptr>(targetHwnd));
            QMetaObject::invokeMethod(qApp, [kGuardDialog, channelText, kHwndValue, messageId, wParamValue, lParamValue, resultValue]() {
                if (kGuardDialog == nullptr)
                {
                    return;
                }
                kGuardDialog->appendMessageRow(
                    channelText,
                    kHwndValue,
                    static_cast<quint64>(messageId),
                    static_cast<quint64>(wParamValue),
                    static_cast<quint64>(lParamValue),
                    static_cast<quint64>(resultValue),
                    QString());
                }, Qt::QueuedConnection);
        }
    }

    // callWndHookProc: Captures inbound messages on the SendMessage path (before invocation).
    static LRESULT CALLBACK callWndHookProc(const int code, const WPARAM wParam, const LPARAM lParam)
    {
        if (code >= 0 && lParam != 0)
        {
            const CWPSTRUCT* callInfo = reinterpret_cast<const CWPSTRUCT*>(lParam);
            if (callInfo != nullptr)
            {
                threadHookDispatch(
                    ::GetCurrentThreadId(),
                    QStringLiteral("WH_CALLWNDPROC"),
                    callInfo->hwnd,
                    callInfo->message,
                    callInfo->wParam,
                    callInfo->lParam,
                    0);
            }
        }
        return ::CallNextHookEx(nullptr, code, wParam, lParam);
    }

    // getMessageHookProc: Captures messages from PostMessage and message queue paths.
    static LRESULT CALLBACK getMessageHookProc(const int code, const WPARAM wParam, const LPARAM lParam)
    {
        if (code >= 0 && lParam != 0)
        {
            const MSG* msgInfo = reinterpret_cast<const MSG*>(lParam);
            if (msgInfo != nullptr)
            {
                threadHookDispatch(
                    ::GetCurrentThreadId(),
                    QStringLiteral("WH_GETMESSAGE"),
                    msgInfo->hwnd,
                    msgInfo->message,
                    msgInfo->wParam,
                    msgInfo->lParam,
                    static_cast<LRESULT>(wParam));
            }
        }
        return ::CallNextHookEx(nullptr, code, wParam, lParam);
    }

    // callWndRetHookProc: Captures messages after SendMessage returns, allowing access to lResult.
    static LRESULT CALLBACK callWndRetHookProc(const int code, const WPARAM wParam, const LPARAM lParam)
    {
        if (code >= 0 && lParam != 0)
        {
            const CWPRETSTRUCT* retInfo = reinterpret_cast<const CWPRETSTRUCT*>(lParam);
            if (retInfo != nullptr)
            {
                threadHookDispatch(
                    ::GetCurrentThreadId(),
                    QStringLiteral("WH_CALLWNDPROCRET"),
                    retInfo->hwnd,
                    retInfo->message,
                    retInfo->wParam,
                    retInfo->lParam,
                    retInfo->lResult);
            }
        }
        return ::CallNextHookEx(nullptr, code, wParam, lParam);
    }

    // winEventHookProc: cross-process fallback mode callback (no DLL injection).
    static void CALLBACK winEventHookProc(
        HWINEVENTHOOK hookHandle,
        const DWORD eventId,
        HWND windowHandle,
        const LONG objectId,
        const LONG childId,
        const DWORD eventThreadId,
        const DWORD eventTimeMs)
    {
        WindowDetailDialog* dialog = nullptr;
        {
            std::lock_guard<std::mutex> lockGuard(sMonitorRegistryMutex);
            const auto kIt = sEventHookMap.find(hookHandle);
            if (kIt != sEventHookMap.end())
            {
                dialog = kIt->second;
            }
        }
        if (dialog == nullptr || !dialog->messageMonitorRunning_.load())
        {
            return;
        }
        if (windowHandle == nullptr || windowHandle != dialog->targetWindowHandle())
        {
            return;
        }

        const QPointer<WindowDetailDialog> kGuardDialog(dialog);
        const quint64 kHwndValue = static_cast<quint64>(reinterpret_cast<quintptr>(windowHandle));
        const QString kExtraText = QStringLiteral("obj=%1, child=%2, thread=%3, time=%4")
            .arg(objectId)
            .arg(childId)
            .arg(eventThreadId)
            .arg(eventTimeMs);
        QMetaObject::invokeMethod(qApp, [kGuardDialog, kHwndValue, eventId, objectId, childId, eventThreadId, eventTimeMs, kExtraText]() {
            if (kGuardDialog == nullptr)
            {
                return;
            }
            kGuardDialog->appendMessageRow(
                QStringLiteral("WinEvent"),
                kHwndValue,
                static_cast<quint64>(eventId),
                static_cast<quint64>(static_cast<qint64>(objectId)),
                static_cast<quint64>(static_cast<qint64>(childId)),
                static_cast<quint64>(eventThreadId),
                kExtraText + QStringLiteral(", tick=%1").arg(eventTimeMs));
            }, Qt::QueuedConnection);
    }

    // Register thread -> dialog mapping: supports multiple detail windows observing the same thread simultaneously.
    static void registerThreadDialog(const DWORD threadId, WindowDetailDialog* dialog)
    {
        if (threadId == 0 || dialog == nullptr)
        {
            return;
        }
        std::lock_guard<std::mutex> lockGuard(sMonitorRegistryMutex);
        std::vector<WindowDetailDialog*>& dialogList = sThreadDialogMap[threadId];
        const bool kExisted = std::find(dialogList.begin(), dialogList.end(), dialog) != dialogList.end();
        if (!kExisted)
        {
            dialogList.push_back(dialog);
        }
    }

    // Unregister the thread -> dialog mapping to prevent message delivery to closed windows.
    static void unregisterThreadDialog(const DWORD threadId, WindowDetailDialog* dialog)
    {
        if (threadId == 0 || dialog == nullptr)
        {
            return;
        }
        std::lock_guard<std::mutex> lockGuard(sMonitorRegistryMutex);
        const auto kIt = sThreadDialogMap.find(threadId);
        if (kIt == sThreadDialogMap.end())
        {
            return;
        }

        std::vector<WindowDetailDialog*>& dialogList = kIt->second;
        dialogList.erase(std::remove(dialogList.begin(), dialogList.end(), dialog), dialogList.end());
        if (dialogList.empty())
        {
            sThreadDialogMap.erase(kIt);
        }
    }

    // Register WinEvent hook -> dialog mapping for fast lookup of the target detail dialog in callbacks.
    static void registerEventHookDialog(HWINEVENTHOOK hookHandle, WindowDetailDialog* dialog)
    {
        if (hookHandle == nullptr || dialog == nullptr)
        {
            return;
        }
        std::lock_guard<std::mutex> lockGuard(sMonitorRegistryMutex);
        sEventHookMap[hookHandle] = dialog;
    }

    // Unregister WinEvent mapping: must be called when the window closes or monitoring stops.
    static void unregisterEventHookDialog(HWINEVENTHOOK hookHandle, WindowDetailDialog* dialog)
    {
        if (hookHandle == nullptr || dialog == nullptr)
        {
            return;
        }
        std::lock_guard<std::mutex> lockGuard(sMonitorRegistryMutex);
        const auto kIt = sEventHookMap.find(hookHandle);
        if (kIt != sEventHookMap.end() && kIt->second == dialog)
        {
            sEventHookMap.erase(kIt);
        }
    }

    // Target window handle accessor: restore the HWND uniformly from the cached snapshot.
    HWND targetWindowHandle() const
    {
        return toHwnd(info_.hwndValue);
    }

    // Apply changes: write back the title, position, and checkbox style bits to the target window.
    void applyChanges()
    {
        HWND windowHandle = toHwnd(info_.hwndValue);
        if (::IsWindow(windowHandle) == FALSE)
        {
            QMessageBox::warning(this, QStringLiteral("应用失败"), QStringLiteral("目标窗口句柄已失效。"));
            return;
        }

        // Title modification: supports direct editing and write-back.
        const QString kTitleText = titleEdit_->text();
        ::SetWindowTextW(windowHandle, reinterpret_cast<const wchar_t*>(kTitleText.utf16()));

        // Position and size modification: move the window based on the input box's coordinates and dimensions.
        ::MoveWindow(
            windowHandle,
            xSpin_->value(),
            ySpin_->value(),
            std::max(1, widthSpin_->value()),
            std::max(1, heightSpin_->value()),
            TRUE);

        // Style modification: target Style/ExStyle is uniformly calculated by the 'Style Checkbox' before application.
        const bool kStyleAppliedOk = applyStyleCheckBoxChanges(false);
        if (!kStyleAppliedOk)
        {
            return;
        }

        QMessageBox::information(this, QStringLiteral("窗口属性"), QStringLiteral("已应用修改。"));
    }

    // Export information: writes key content from all current tabs to a text file.
    void exportInfo()
    {
        const QString kDefaultName = QStringLiteral("window_detail_%1_%2.txt")
            .arg(QString::number(info_.processId))
            .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss")));

        const QString kOutputPath = QFileDialog::getSaveFileName(
            this,
            QStringLiteral("导出窗口详情"),
            kDefaultName,
            QStringLiteral("文本文件 (*.txt)"));
        if (kOutputPath.trimmed().isEmpty())
        {
            return;
        }

        QFile file(kOutputPath);
        if (!file.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate))
        {
            QMessageBox::warning(this, QStringLiteral("导出失败"), QStringLiteral("无法写入文件：%1").arg(kOutputPath));
            return;
        }

        QTextStream out(&file);
        out.setEncoding(QStringConverter::Utf8);
        out << buildReportText();
        file.close();

        QMessageBox::information(this, QStringLiteral("导出成功"), QStringLiteral("已保存到：%1").arg(kOutputPath));
    }

    // Assemble export text: consolidate core content from all pages for audit and archiving.
    QString buildReportText() const
    {
        QString text;
        text += QStringLiteral("[常规]\n");
        text += QStringLiteral("句柄: %1\n").arg(handleLabel_->text());
        text += QStringLiteral("父句柄: %1\n").arg(parentHandleLabel_->text());
        text += QStringLiteral("所有者句柄: %1\n").arg(ownerHandleLabel_->text());
        text += QStringLiteral("标题: %1\n").arg(titleEdit_->text());
        text += QStringLiteral("类名: %1\n").arg(classNameLabel_->text());
        text += QStringLiteral("实例句柄: %1\n").arg(instanceLabel_->text());
        text += QStringLiteral("状态摘要: %1\n").arg(stateLabel_->text());
        text += QStringLiteral("关系摘要: %1\n\n").arg(relationLabel_->text());

        text += QStringLiteral("[样式]\n%1\n\n").arg(styleText_->text());
        text += QStringLiteral("[位置]\nX=%1, Y=%2, W=%3, H=%4\n\n")
            .arg(xSpin_->value())
            .arg(ySpin_->value())
            .arg(widthSpin_->value())
            .arg(heightSpin_->value());
        text += QStringLiteral("[状态]\nTopMost=%1, Alpha=%2\n\n")
            .arg(boolText(topMostCheck_->isChecked()))
            .arg(alphaSlider_->value());
        text += QStringLiteral("[进程线程]\n%1\n\n").arg(processThreadText_->text());
        text += QStringLiteral("[类信息]\n%1\n\n").arg(classText_->text());
        text += QStringLiteral("[消息钩子]\n%1\n\n").arg(hookText_->text());
        text += QStringLiteral("[消息记录]\n");
        if (messageTable_ != nullptr)
        {
            QStringList headerList;
            for (int col = 0; col < messageTable_->columnCount(); ++col)
            {
                const QTableWidgetItem* headerItem = messageTable_->horizontalHeaderItem(col);
                headerList << (headerItem == nullptr ? QStringLiteral("Col%1").arg(col) : headerItem->text());
            }
            text += headerList.join('\t');
            text += QStringLiteral("\n");

            for (int row = 0; row < messageTable_->rowCount(); ++row)
            {
                QStringList rowTextList;
                for (int col = 0; col < messageTable_->columnCount(); ++col)
                {
                    QTableWidgetItem* item = messageTable_->item(row, col);
                    rowTextList << (item == nullptr ? QString() : item->text());
                }
                text += rowTextList.join('\t');
                text += QStringLiteral("\n");
            }
        }
        text += QStringLiteral("\n");
        text += QStringLiteral("[高级属性]\n%1\n").arg(advancedText_->text());
        return text;
    }

private:
    OtherDock::WindowInfo info_;          // Target window snapshot.

    QTabWidget* tabWidget_ = nullptr;     // Tab container.

    QLabel* handleLabel_ = nullptr;       // Handle display.
    QLabel* parentHandleLabel_ = nullptr; // Parent handle display.
    QLabel* ownerHandleLabel_ = nullptr;  // Displays the owner handle.
    QLineEdit* titleEdit_ = nullptr;      // Editable title input.
    QLabel* classNameLabel_ = nullptr;    // Class name display.
    QLabel* instanceLabel_ = nullptr;     // Instance handle display.
    QLabel* stateLabel_ = nullptr;        // Status summary display.
    QLabel* relationLabel_ = nullptr;     // Relationship summary display.

    CodeEditorWidget* styleText_ = nullptr;      // Style text area (unified text editor, read-only).
    std::vector<StyleCheckBinding> styleCheckBindingList_; // Standard style checkbox binding table (GWL_STYLE).
    std::vector<StyleCheckBinding> exStyleCheckBindingList_; // Extended style checkbox binding table (GWL_EXSTYLE).
    bool styleCheckSyncing_ = false;             // Set the backfill debounce flag to avoid triggering the 'user modification' chain during refresh.
    QPushButton* styleRefreshButton_ = nullptr;  // Style area refresh button.
    QPushButton* styleApplyButton_ = nullptr;    // Style area apply button.
    QSpinBox* xSpin_ = nullptr;                // X coordinate input.
    QSpinBox* ySpin_ = nullptr;                // Y coordinate input.
    QSpinBox* widthSpin_ = nullptr;            // Width input.
    QSpinBox* heightSpin_ = nullptr;           // Height input.
    QCheckBox* topMostCheck_ = nullptr;        // Top-most checkbox.
    QSlider* alphaSlider_ = nullptr;           // Transparency slider.
    QLabel* alphaLabel_ = nullptr;             // Transparency text.

    CodeEditorWidget* processThreadText_ = nullptr; // Process thread page text (unified text editor, read-only).
    CodeEditorWidget* classText_ = nullptr;         // Class information page text (unified text editor, read-only).
    CodeEditorWidget* hookText_ = nullptr;          // Hook page text (unified text editor, read-only).
    QPushButton* messageStartButton_ = nullptr;   // Message monitoring start button.
    QPushButton* messageStopButton_ = nullptr;    // Message monitoring stop button.
    QPushButton* messageClearButton_ = nullptr;   // Message list clear button.
    QCheckBox* messageAutoScrollCheck_ = nullptr; // Auto-scroll checkbox.
    QSpinBox* messageMaxRowsSpin_ = nullptr;      // Maximum number of rows retained in the message table.
    QLabel* messageModeLabel_ = nullptr;          // Current collection mode label.
    QLabel* messageCountLabel_ = nullptr;         // Record/discard count label.
    QTableWidget* messageTable_ = nullptr;        // Message list table.
    CodeEditorWidget* advancedText_ = nullptr;      // Advanced page text (unified text editor, read-only).

    QPushButton* refreshButton_ = nullptr;    // Refresh button.
    QPushButton* applyButton_ = nullptr;      // Apply button.
    QPushButton* exportButton_ = nullptr;     // Export button.
    QPushButton* closeButton_ = nullptr;      // Close button.

    HHOOK callWndHook_ = nullptr;             // WH_CALLWNDPROC handle.
    HHOOK getMessageHook_ = nullptr;          // WH_GETMESSAGE handle.
    HHOOK callWndRetHook_ = nullptr;          // WH_CALLWNDPROCRET handle.
    HWINEVENTHOOK winEventHook_ = nullptr;    // WinEvent fallback handle.
    HWINEVENTHOOK winEventHookSnapshot_ = nullptr; // Used to unregister the hook snapshot mapping.
    std::atomic_bool messageMonitorRunning_{ false }; // Message monitoring running status.
    bool threadRegistered_ = false;           // Whether the thread->dialog mapping has been registered.
    bool eventRegistered_ = false;            // Whether the eventHook->dialog mapping has been registered.
    int capturedMessageCount_ = 0;            // Number of messages written to the message table.
    int droppedMessageCount_ = 0;             // Count of messages dropped due to exceeding the maximum line limit.
    std::deque<PendingMessageRow> deferredMessageRows_; // Deferred messages to maintain order during menu operations.
    QString messageMonitorMode_ = QStringLiteral("未启动"); // Current monitoring mode text.

    static std::mutex sMonitorRegistryMutex;  // Mutex for the callback mapping table to prevent concurrent race conditions.
    static std::unordered_map<DWORD, std::vector<WindowDetailDialog*>> sThreadDialogMap; // threadId -> list of detail windows.
    static std::unordered_map<HWINEVENTHOOK, WindowDetailDialog*> sEventHookMap; // WinEvent hook -> detail window.
};

// Static member definition: centrally manages message callback dispatch mapping.
std::mutex WindowDetailDialog::sMonitorRegistryMutex;
std::unordered_map<DWORD, std::vector<WindowDetailDialog*>> WindowDetailDialog::sThreadDialogMap;
std::unordered_map<HWINEVENTHOOK, WindowDetailDialog*> WindowDetailDialog::sEventHookMap;

OtherDock::OtherDock(QWidget* parent)
    : QWidget(parent)
{
    KLogEvent event;
    info << event << "[OtherDock] 构造开始，初始化窗口管理页。" << eol;

    initializeUi();
    initializeConnections();
    applyViewMode();
    refreshWindowListAsync();
}

OtherDock::~OtherDock()
{
    if (autoRefreshTimer_ != nullptr)
    {
        autoRefreshTimer_->stop();
    }

    // Close the newly created desktop handles actively retained by this process to prevent orphaned references to desktop objects after the program exits.
    for (const CreatedDesktopRecord& desktopRecord : createdDesktopHandles_)
    {
        if (desktopRecord.desktopHandle != nullptr)
        {
            ::CloseDesktop(reinterpret_cast<HDESK>(desktopRecord.desktopHandle));
        }
    }
    createdDesktopHandles_.clear();
}

void OtherDock::focusProcessIds(const QVector<quint32>& processIds)
{
    externalProcessIdFilterSet_.clear();
    for (const quint32 kProcessId : processIds)
    {
        if (kProcessId != 0U)
        {
            externalProcessIdFilterSet_.insert(kProcessId);
        }
    }
    if (contentTabWidget_ != nullptr && windowListPage_ != nullptr)
    {
        contentTabWidget_->setCurrentWidget(windowListPage_);
    }
    if (clearExternalProcessFilterButton_ != nullptr)
    {
        clearExternalProcessFilterButton_->setEnabled(!externalProcessIdFilterSet_.isEmpty());
    }
    rebuildWindowTreeFromSnapshot();
}

void OtherDock::clearExternalProcessFilter()
{
    if (externalProcessIdFilterSet_.isEmpty())
    {
        return;
    }
    externalProcessIdFilterSet_.clear();
    if (clearExternalProcessFilterButton_ != nullptr)
    {
        clearExternalProcessFilterButton_->setEnabled(false);
    }
    rebuildWindowTreeFromSnapshot();
}

void OtherDock::setWindowListOnlyScope()
{
    if (contentTabWidget_ == nullptr)
    {
        return;
    }

    for (int tabIndex = 0; tabIndex < contentTabWidget_->count(); ++tabIndex)
    {
        contentTabWidget_->setTabVisible(
            tabIndex,
            contentTabWidget_->widget(tabIndex) == windowListPage_);
    }

    if (windowListPage_ != nullptr)
    {
        contentTabWidget_->setCurrentWidget(windowListPage_);
    }
}

void OtherDock::initializeUi()
{
    // The root layout holds the toolbar, main splitter area, and status bar.
    rootLayout_ = new QVBoxLayout(this);
    rootLayout_->setContentsMargins(4, 4, 4, 4);
    rootLayout_->setSpacing(6);

    // Top toolbar: controls for refresh, auto-refresh, filter, group, and export.
    toolBarWidget_ = new QWidget(this);
    toolBarLayout_ = new QHBoxLayout(toolBarWidget_);
    toolBarLayout_->setContentsMargins(0, 0, 0, 0);
    toolBarLayout_->setSpacing(4);
    rootLayout_->addWidget(toolBarWidget_, 0);

    refreshButton_ = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), toolBarWidget_);
    refreshButton_->setToolTip(QStringLiteral("刷新窗口列表"));
    refreshButton_->setStyleSheet(blueButtonStyle());
    refreshButton_->setFixedWidth(32);

    clearExternalProcessFilterButton_ = new QPushButton(QIcon(":/Icon/log_clear.svg"), QString(), toolBarWidget_);
    clearExternalProcessFilterButton_->setToolTip(QStringLiteral("清除进程页跳转带入的 PID 筛选"));
    clearExternalProcessFilterButton_->setStyleSheet(blueButtonStyle());
    clearExternalProcessFilterButton_->setFixedWidth(32);
    clearExternalProcessFilterButton_->setEnabled(false);

    autoRefreshCheck_ = new QCheckBox(QStringLiteral("自动"), toolBarWidget_);
    autoRefreshCheck_->setToolTip(QStringLiteral("启用自动刷新窗口列表"));

    autoRefreshIntervalSpin_ = new QSpinBox(toolBarWidget_);
    autoRefreshIntervalSpin_->setRange(300, 5000);
    autoRefreshIntervalSpin_->setSingleStep(100);
    autoRefreshIntervalSpin_->setValue(1000);
    autoRefreshIntervalSpin_->setSuffix(QStringLiteral(" ms"));
    autoRefreshIntervalSpin_->setToolTip(QStringLiteral("自动刷新间隔（毫秒）"));
    autoRefreshIntervalSpin_->setStyleSheet(blueInputStyle());

    filterEdit_ = new QLineEdit(toolBarWidget_);
    filterEdit_->setPlaceholderText(QStringLiteral("筛选：标题 / 进程名 / 类名 / HWND"));
    filterEdit_->setToolTip(QStringLiteral("输入关键字实时过滤窗口"));
    filterEdit_->setStyleSheet(blueInputStyle());

    filterModeCombo_ = new QComboBox(toolBarWidget_);
    filterModeCombo_->addItems({
        QStringLiteral("可见窗口"),
        QStringLiteral("隐藏窗口"),
        QStringLiteral("顶层窗口"),
        QStringLiteral("子窗口"),
        QStringLiteral("无效窗口")
        });
    filterModeCombo_->setToolTip(QStringLiteral("选择窗口过滤条件"));
    filterModeCombo_->setStyleSheet(blueInputStyle());

    enumModeCombo_ = new QComboBox(toolBarWidget_);
    enumModeCombo_->addItems({
        QStringLiteral("混合枚举"),
        QStringLiteral("EnumWindows"),
        QStringLiteral("EnumDesktopWindows"),
        QStringLiteral("EnumThreadWindows"),
        QStringLiteral("仅顶层")
        });
    enumModeCombo_->setToolTip(QStringLiteral("选择窗口枚举策略（用于减少漏项）"));
    enumModeCombo_->setStyleSheet(blueInputStyle());

    groupModeCombo_ = new QComboBox(toolBarWidget_);
    groupModeCombo_->addItems({
        QStringLiteral("按进程分组"),
        QStringLiteral("按Z序排列"),
        QStringLiteral("按窗口层级"),
        QStringLiteral("按显示器分组")
        });
    groupModeCombo_->setToolTip(QStringLiteral("选择窗口分组方式"));
    groupModeCombo_->setStyleSheet(blueInputStyle());

    viewModeCombo_ = new QComboBox(toolBarWidget_);
    viewModeCombo_->addItems({
        QStringLiteral("图标视图"),
        QStringLiteral("列表视图"),
        QStringLiteral("详细信息视图")
        });
    viewModeCombo_->setToolTip(QStringLiteral("切换列表显示样式"));
    viewModeCombo_->setStyleSheet(blueInputStyle());

    exportButton_ = new QPushButton(QIcon(":/Icon/log_export.svg"), QString(), toolBarWidget_);
    exportButton_->setToolTip(QStringLiteral("导出当前列表为 TSV"));
    exportButton_->setStyleSheet(blueButtonStyle());
    exportButton_->setFixedWidth(32);

    toolBarLayout_->addWidget(refreshButton_, 0);
    toolBarLayout_->addWidget(clearExternalProcessFilterButton_, 0);
    toolBarLayout_->addWidget(autoRefreshCheck_, 0);
    toolBarLayout_->addWidget(autoRefreshIntervalSpin_, 0);
    toolBarLayout_->addWidget(filterEdit_, 1);
    toolBarLayout_->addWidget(filterModeCombo_, 0);
    toolBarLayout_->addWidget(enumModeCombo_, 0);
    toolBarLayout_->addWidget(groupModeCombo_, 0);
    toolBarLayout_->addWidget(viewModeCombo_, 0);
    toolBarLayout_->addWidget(exportButton_, 0);

    // Note: Central main content: Tab1=Window List, Tab2=Desktop Management (SwitchDesktop).
    contentTabWidget_ = new QTabWidget(this);
    rootLayout_->addWidget(contentTabWidget_, 1);

    windowListPage_ = new QWidget(contentTabWidget_);
    windowListPageLayout_ = new QVBoxLayout(windowListPage_);
    windowListPageLayout_->setContentsMargins(0, 0, 0, 0);
    windowListPageLayout_->setSpacing(4);

    // Top toolbar of the window list page: Added a crosshair drag-and-drop entry point to support the scenario of dragging directly to a target window to view details.
    windowListToolWidget_ = new QWidget(windowListPage_);
    windowListToolLayout_ = new QHBoxLayout(windowListToolWidget_);
    windowListToolLayout_->setContentsMargins(0, 0, 0, 0);
    windowListToolLayout_->setSpacing(6);

    auto* pickerButton = new WindowPickerDragButton(windowListToolWidget_);
    windowPickerButton_ = pickerButton;
    windowPickerButton_->setIcon(QIcon(":/Icon/window_picker_target.svg"));
    windowPickerButton_->setToolTip(QStringLiteral("按住并拖拽准星，松开后打开鼠标下方窗口的详细信息"));
    windowPickerButton_->setStyleSheet(blueButtonStyle());
    windowPickerButton_->setFixedWidth(32);

    protectCaptureButton_ = new QPushButton(QIcon(":/Icon/titlebar_capture_protected.svg"), QString(), windowListToolWidget_);
    protectCaptureButton_->setToolTip(QStringLiteral("对选中窗口启用防截图保护：优先从截图/录屏中隐藏，失败时回退黑屏"));
    protectCaptureButton_->setStyleSheet(blueButtonStyle());
    protectCaptureButton_->setFixedWidth(32);

    unprotectCaptureButton_ = new QPushButton(QIcon(":/Icon/titlebar_capture_allowed.svg"), QString(), windowListToolWidget_);
    unprotectCaptureButton_->setToolTip(QStringLiteral("取消选中窗口的防截图保护，恢复普通截图/录屏捕获"));
    unprotectCaptureButton_->setStyleSheet(blueButtonStyle());
    unprotectCaptureButton_->setFixedWidth(32);

    windowPickerHintLabel_ = new QLabel(
        QStringLiteral("拖拽准星可定位窗口；选中窗口后可启用或取消防截图保护"),
        windowListToolWidget_);
    windowPickerHintLabel_->setToolTip(QStringLiteral("防截图保护会对顶层窗口写入 DisplayAffinity，外部进程窗口会尝试远程调用"));

    pickerButton->setReleaseCallback([this](const QPoint& globalPos) {
        handleWindowPickerRelease(globalPos);
    });

    windowListToolLayout_->addWidget(windowPickerButton_, 0);
    windowListToolLayout_->addWidget(protectCaptureButton_, 0);
    windowListToolLayout_->addWidget(unprotectCaptureButton_, 0);
    auto* inputButton = new QPushButton(windowListToolWidget_);
    ks::i18n::LanguageManager::instance().bindText(inputButton,
        QStringLiteral("window.input.tab"), QStringLiteral("窗口输入与顺序"));
    windowListToolLayout_->addWidget(inputButton);
    connect(inputButton, &QPushButton::clicked, this, [this]
    {
        const auto* item = windowTree_->currentItem();
        if (!item || item->data(0, Qt::UserRole + 1).toBool()) return;
        const auto* selected = findInfoByHwnd(item->data(0, Qt::UserRole).toULongLong());
        if (selected) openWindowDetailDialog(*selected, true);
    });
    windowListToolLayout_->addWidget(windowPickerHintLabel_, 0);
    windowListToolLayout_->addStretch(1);
    windowListPageLayout_->addWidget(windowListToolWidget_, 0);

    // Window list page: tree on the left, preview on the right.
    mainSplitter_ = new QSplitter(Qt::Horizontal, windowListPage_);
    windowListPageLayout_->addWidget(mainSplitter_, 1);

    windowTree_ = new QTreeWidget(mainSplitter_);
    windowTree_->setContextMenuPolicy(Qt::CustomContextMenu);
    windowTree_->setRootIsDecorated(true);
    windowTree_->setAlternatingRowColors(true);
    windowTree_->setSelectionMode(QAbstractItemView::SingleSelection);
    windowTree_->setUniformRowHeights(true);
    windowTree_->setSortingEnabled(false);
    windowTree_->header()->setStyleSheet(blueHeaderStyle());
    windowTree_->setColumnCount(13);
    windowTree_->setHeaderLabels({
        QStringLiteral("窗口标题"),
        QStringLiteral("句柄"),
        QStringLiteral("枚举API"),
        QStringLiteral("类名"),
        QStringLiteral("PID"),
        QStringLiteral("进程名"),
        QStringLiteral("TID"),
        QStringLiteral("大小"),
        QStringLiteral("可见"),
        QStringLiteral("可用"),
        QStringLiteral("顶层"),
        QStringLiteral("状态"),
        QStringLiteral("透明度")
        });
    windowTree_->header()->setStretchLastSection(false);
    windowTree_->header()->setSectionResizeMode(kWindowColumnTitle, QHeaderView::Interactive);
    windowTree_->header()->setSectionResizeMode(kWindowColumnHandle, QHeaderView::ResizeToContents);
    windowTree_->header()->setSectionResizeMode(kWindowColumnEnumApi, QHeaderView::ResizeToContents);
    windowTree_->header()->setSectionResizeMode(kWindowColumnClassName, QHeaderView::ResizeToContents);
    windowTree_->header()->setSectionResizeMode(kWindowColumnPid, QHeaderView::ResizeToContents);
    windowTree_->header()->setSectionResizeMode(kWindowColumnProcessName, QHeaderView::ResizeToContents);
    windowTree_->header()->setSectionResizeMode(kWindowColumnTid, QHeaderView::ResizeToContents);
    windowTree_->header()->setSectionResizeMode(kWindowColumnSize, QHeaderView::ResizeToContents);
    windowTree_->header()->setSectionResizeMode(kWindowColumnVisible, QHeaderView::ResizeToContents);
    windowTree_->header()->setSectionResizeMode(kWindowColumnEnabled, QHeaderView::ResizeToContents);
    windowTree_->header()->setSectionResizeMode(kWindowColumnTopMost, QHeaderView::ResizeToContents);
    windowTree_->header()->setSectionResizeMode(kWindowColumnState, QHeaderView::ResizeToContents);
    windowTree_->header()->setSectionResizeMode(kWindowColumnAlpha, QHeaderView::ResizeToContents);
    windowTree_->setColumnWidth(kWindowColumnTitle, 420);

    previewWidget_ = new QWidget(mainSplitter_);
    previewLayout_ = new QVBoxLayout(previewWidget_);
    previewLayout_->setContentsMargins(6, 6, 6, 6);
    previewLayout_->setSpacing(6);

    thumbnailLabel_ = new QLabel(previewWidget_);
    thumbnailLabel_->setMinimumSize(320, 220);
    thumbnailLabel_->setAlignment(Qt::AlignCenter);
    thumbnailLabel_->setStyleSheet(QStringLiteral(
        "border:1px solid %1;background:%2;")
        .arg(ksword_theme::borderHex(), ksword_theme::surfaceAltHex()));

    captureButton_ = new QPushButton(QIcon(":/Icon/process_details.svg"), QString(), previewWidget_);
    captureButton_->setToolTip(QStringLiteral("保存当前窗口截图"));
    captureButton_->setStyleSheet(blueButtonStyle());
    captureButton_->setFixedWidth(34);

    quickInfoText_ = new CodeEditorWidget(previewWidget_);
    quickInfoText_->setReadOnly(true);
    quickInfoText_->setStyleSheet(blueInputStyle());

    QHBoxLayout* captureLayout = new QHBoxLayout();
    captureLayout->addStretch(1);
    captureLayout->addWidget(captureButton_, 0);

    previewLayout_->addWidget(thumbnailLabel_, 0);
    previewLayout_->addLayout(captureLayout);
    previewLayout_->addWidget(quickInfoText_, 1);

    // By default, widen the left window list area to prevent window titles from being truncated.
    mainSplitter_->setStretchFactor(0, 4);
    mainSplitter_->setStretchFactor(1, 1);
    contentTabWidget_->addTab(windowListPage_, QStringLiteral("窗口列表"));
    ks::i18n::LanguageManager::instance().bindTab(
        contentTabWidget_, windowListPage_, QStringLiteral("window.tab.list"), QStringLiteral("窗口列表"));

    // Desktop management page: Lists window stations and desktops, supplementing context such as SessionId, SID, and permission status.
    desktopPage_ = new QWidget(contentTabWidget_);
    desktopPageLayout_ = new QVBoxLayout(desktopPage_);
    desktopPageLayout_->setContentsMargins(0, 0, 0, 0);
    desktopPageLayout_->setSpacing(6);

    desktopToolLayout_ = new QHBoxLayout();
    desktopToolLayout_->setContentsMargins(0, 0, 0, 0);
    desktopToolLayout_->setSpacing(6);

    desktopRefreshButton_ = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), desktopPage_);
    desktopRefreshButton_->setToolTip(QStringLiteral("刷新可用桌面列表"));
    desktopRefreshButton_->setStyleSheet(blueButtonStyle());
    desktopRefreshButton_->setFixedWidth(32);

    desktopSwitchButton_ = new QPushButton(QIcon(":/Icon/desktop_switch.svg"), QString(), desktopPage_);
    desktopSwitchButton_->setToolTip(QStringLiteral("切换到选中桌面（SwitchDesktop）"));
    desktopSwitchButton_->setStyleSheet(blueButtonStyle());
    desktopSwitchButton_->setFixedWidth(32);

    desktopCreateButton_ = new QPushButton(QIcon(":/Icon/desktop_create.svg"), QString(), desktopPage_);
    desktopCreateButton_->setToolTip(QStringLiteral("新建桌面：在弹出窗口中设置名称、权限、安全描述符和私有访问参数"));
    desktopCreateButton_->setStyleSheet(blueButtonStyle());
    desktopCreateButton_->setFixedWidth(32);

    desktopStatusLabel_ = new QLabel(
        QStringLiteral("支持枚举窗口站/桌面；切换会尝试“桌面名”和“窗口站\\\\桌面名”两种方式。"),
        desktopPage_);
    desktopStatusLabel_->setWordWrap(true);

    desktopToolLayout_->addWidget(desktopRefreshButton_, 0);
    desktopToolLayout_->addWidget(desktopSwitchButton_, 0);
    desktopToolLayout_->addWidget(desktopCreateButton_, 0);
    desktopToolLayout_->addWidget(desktopStatusLabel_, 1);
    desktopPageLayout_->addLayout(desktopToolLayout_, 0);

    desktopTable_ = new ks::ui::VisibleTableWidget(desktopPage_);
    desktopTable_->setColumnCount(13);
    desktopTable_->setHorizontalHeaderLabels({
        QStringLiteral("窗口站"),
        QStringLiteral("桌面名称"),
        QStringLiteral("当前站"),
        QStringLiteral("当前桌面"),
        QStringLiteral("交互式"),
        QStringLiteral("可读"),
        QStringLiteral("可切换"),
        QStringLiteral("SessionId"),
        QStringLiteral("所有者"),
        QStringLiteral("SID"),
        QStringLiteral("SID详情"),
        QStringLiteral("堆(KB)"),
        QStringLiteral("备注")
        });
    desktopTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    desktopTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    desktopTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    desktopTable_->setAlternatingRowColors(true);
    desktopTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    desktopTable_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    desktopTable_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    desktopTable_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    desktopTable_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    desktopTable_->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    desktopTable_->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);
    desktopTable_->horizontalHeader()->setSectionResizeMode(6, QHeaderView::ResizeToContents);
    desktopTable_->horizontalHeader()->setSectionResizeMode(7, QHeaderView::ResizeToContents);
    desktopTable_->horizontalHeader()->setSectionResizeMode(8, QHeaderView::ResizeToContents);
    desktopTable_->horizontalHeader()->setSectionResizeMode(9, QHeaderView::Stretch);
    desktopTable_->horizontalHeader()->setSectionResizeMode(10, QHeaderView::Stretch);
    desktopTable_->horizontalHeader()->setSectionResizeMode(11, QHeaderView::ResizeToContents);
    desktopTable_->horizontalHeader()->setSectionResizeMode(12, QHeaderView::Stretch);
    desktopTable_->horizontalHeader()->setStyleSheet(blueHeaderStyle());
    desktopPageLayout_->addWidget(desktopTable_, 1);

    contentTabWidget_->addTab(desktopPage_, QStringLiteral("桌面管理"));
    ks::i18n::LanguageManager::instance().bindTab(
        contentTabWidget_, desktopPage_, QStringLiteral("window.tab.desktop"), QStringLiteral("桌面管理"));

    // Bottom status bar: displays total count, visible count, system window count, and currently selected information.
    statusBar_ = new QStatusBar(this);
    totalLabel_ = new QLabel(QStringLiteral("总数: 0"), statusBar_);
    visibleLabel_ = new QLabel(QStringLiteral("可见: 0"), statusBar_);
    systemLabel_ = new QLabel(QStringLiteral("系统: 0"), statusBar_);
    selectedLabel_ = new QLabel(QStringLiteral("选中: -"), statusBar_);
    statusBar_->addWidget(totalLabel_, 0);
    statusBar_->addWidget(visibleLabel_, 0);
    statusBar_->addWidget(systemLabel_, 0);
    statusBar_->addPermanentWidget(selectedLabel_, 1);
    rootLayout_->addWidget(statusBar_, 0);

    // Auto-refresh timer: started and stopped based on the checkbox state.
    autoRefreshTimer_ = new QTimer(this);
    autoRefreshTimer_->setInterval(autoRefreshIntervalSpin_->value());

    // initialize the desktop list once to ensure it is immediately visible after opening the tab.
    refreshDesktopList();
}

void OtherDock::initializeConnections()
{
    // Manual refresh: triggers background enumeration.
    connect(refreshButton_, &QPushButton::clicked, this, [this]() {
        KLogEvent event;
        info << event
            << "[OtherDock] 用户点击刷新窗口列表。"
            << eol;
        refreshWindowListAsync();
    });
    connect(clearExternalProcessFilterButton_, &QPushButton::clicked, this, [this]() {
        clearExternalProcessFilter();
    });

    // Auto-refresh toggle: when checked, refreshes at the specified interval.
    connect(autoRefreshCheck_, &QCheckBox::toggled, this, [this](bool checked) {
        KLogEvent event;
        info << event
            << "[OtherDock] 自动刷新状态切换, enabled="
            << (checked ? "true" : "false")
            << ", intervalMs="
            << autoRefreshIntervalSpin_->value()
            << eol;
        if (checked)
        {
            autoRefreshTimer_->start(autoRefreshIntervalSpin_->value());
        }
        else
        {
            autoRefreshTimer_->stop();
        }
    });

    // Immediately update the running timer when the auto-refresh interval changes.
    connect(autoRefreshIntervalSpin_, &QSpinBox::valueChanged, this, [this](int value) {
        autoRefreshTimer_->setInterval(value);
        KLogEvent event;
        info << event
            << "[OtherDock] 自动刷新间隔更新, intervalMs="
            << value
            << ", timerActive="
            << (autoRefreshTimer_->isActive() ? "true" : "false")
            << eol;
        if (autoRefreshCheck_->isChecked())
        {
            autoRefreshTimer_->start(value);
        }
    });

    // Filtering, grouping, and view switching can directly repaint the current snapshot without re-enumeration.
    connect(filterEdit_, &QLineEdit::textChanged, this, [this](const QString& text) {
        KLogEvent event;
        dbg << event
            << "[OtherDock] 关键字过滤变更, keyword="
            << text.toStdString()
            << eol;
        rebuildWindowTreeFromSnapshot();
    });
    connect(filterModeCombo_, &QComboBox::currentIndexChanged, this, [this](int index) {
        KLogEvent event;
        info << event
            << "[OtherDock] 过滤模式切换, mode="
            << filterModeText(index).toStdString()
            << eol;
        rebuildWindowTreeFromSnapshot();
    });
    connect(enumModeCombo_, &QComboBox::currentIndexChanged, this, [this](int index) {
        KLogEvent event;
        info << event
            << "[OtherDock] 枚举模式切换, mode="
            << enumModeText(index).toStdString()
            << eol;
        refreshWindowListAsync();
    });
    connect(groupModeCombo_, &QComboBox::currentIndexChanged, this, [this](int index) {
        KLogEvent event;
        info << event
            << "[OtherDock] 分组模式切换, mode="
            << groupModeText(index).toStdString()
            << eol;
        rebuildWindowTreeFromSnapshot();
    });
    connect(viewModeCombo_, &QComboBox::currentIndexChanged, this, [this](int index) {
        KLogEvent event;
        info << event
            << "[OtherDock] 视图模式切换, mode="
            << viewModeText(index).toStdString()
            << eol;
        applyViewMode();
    });

    // Export currently visible rows.
    connect(exportButton_, &QPushButton::clicked, this, [this]() {
        KLogEvent event;
        info << event
            << "[OtherDock] 用户点击导出窗口列表。"
            << eol;
        exportVisibleRowsToTsv();
    });

    // Auto-refresh timer callback.
    connect(autoRefreshTimer_, &QTimer::timeout, this, [this]() {
        KLogEvent event;
        dbg << event
            << "[OtherDock] 自动刷新定时器触发。"
            << eol;
        refreshWindowListAsync();
    });

    // Right-click menu: window operation entry point.
    connect(windowTree_, &QTreeWidget::customContextMenuRequested, this, [this](const QPoint& pos) {
        showWindowContextMenu(pos);
    });

    // Screenshot protection button: enables or disables protection for the currently selected window.
    connect(protectCaptureButton_, &QPushButton::clicked, this, [this]() {
        setCaptureProtectionForSelectedWindow(true);
    });
    connect(unprotectCaptureButton_, &QPushButton::clicked, this, [this]() {
        setCaptureProtectionForSelectedWindow(false);
    });

    // Double-click row: Directly open window details.
    connect(windowTree_, &QTreeWidget::itemDoubleClicked, this, [this](QTreeWidgetItem* item, int) {
        if (item == nullptr || item->data(0, Qt::UserRole + 1).toBool())
        {
            return;
        }
        const quint64 kHwndValue = item->data(0, Qt::UserRole).toULongLong();
        const WindowInfo* windowInfo = findInfoByHwnd(kHwndValue);
        if (windowInfo != nullptr)
        {
            KLogEvent event;
            info << event
                << "[OtherDock] 双击窗口项，打开详情, hwnd="
                << hwndToText(windowInfo->hwndValue).toStdString()
                << ", pid="
                << windowInfo->processId
                << eol;
            openWindowDetailDialog(*windowInfo);
        }
    });

    // Selection change: update the right-side preview and the 'Selected' status bar text.
    connect(windowTree_, &QTreeWidget::currentItemChanged, this, [this](QTreeWidgetItem* current, QTreeWidgetItem*) {
        const bool kIsLeaf = current != nullptr && !current->data(0, Qt::UserRole + 1).toBool();
        if (!kIsLeaf)
        {
            updatePreviewPanel(nullptr);
            selectedLabel_->setText(QStringLiteral("选中: -"));
            return;
        }

        const quint64 kHwndValue = current->data(0, Qt::UserRole).toULongLong();
        const WindowInfo* windowInfo = findInfoByHwnd(kHwndValue);
        updatePreviewPanel(windowInfo);
        if (windowInfo != nullptr)
        {
            selectedLabel_->setText(QStringLiteral("选中: %1  %2")
                .arg(hwndToText(windowInfo->hwndValue), windowInfo->titleText));
            KLogEvent event;
            dbg << event
                << "[OtherDock] 选中窗口变更, hwnd="
                << hwndToText(windowInfo->hwndValue).toStdString()
                << ", title="
                << windowInfo->titleText.toStdString()
                << eol;
        }
    });

    // Screenshot button: capture the currently selected window and save it to a file.
    connect(captureButton_, &QPushButton::clicked, this, [this]() {
        QTreeWidgetItem* item = windowTree_->currentItem();
        if (item == nullptr || item->data(0, Qt::UserRole + 1).toBool())
        {
            KLogEvent event;
            warn << event
                << "[OtherDock] 截图失败：未选中有效窗口。"
                << eol;
            QMessageBox::information(this, QStringLiteral("窗口截图"), QStringLiteral("请先选中一个窗口。"));
            return;
        }

        const quint64 kHwndValue = item->data(0, Qt::UserRole).toULongLong();
        const QPixmap kPixmap = grabWindowPreviewPixmap(kHwndValue, QSize(900, 600));
        if (kPixmap.isNull())
        {
            KLogEvent event;
            err << event
                << "[OtherDock] 截图抓取失败, hwnd="
                << hwndToText(kHwndValue).toStdString()
                << eol;
            QMessageBox::warning(this, QStringLiteral("窗口截图"), QStringLiteral("抓图失败。"));
            return;
        }

        const QString kDefaultName = QStringLiteral("window_capture_%1_%2.png")
            .arg(QString::number(kHwndValue, 16).toUpper())
            .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss")));
        const QString kSavePath = QFileDialog::getSaveFileName(
            this,
            QStringLiteral("保存窗口截图"),
            kDefaultName,
            QStringLiteral("PNG 图片 (*.png)"));
        if (kSavePath.trimmed().isEmpty())
        {
            KLogEvent event;
            dbg << event
                << "[OtherDock] 截图保存取消, hwnd="
                << hwndToText(kHwndValue).toStdString()
                << eol;
            return;
        }

        if (!kPixmap.save(kSavePath))
        {
            KLogEvent event;
            err << event
                << "[OtherDock] 截图保存失败, hwnd="
                << hwndToText(kHwndValue).toStdString()
                << ", path="
                << kSavePath.toStdString()
                << eol;
            QMessageBox::warning(this, QStringLiteral("窗口截图"), QStringLiteral("保存失败：%1").arg(kSavePath));
            return;
        }
        KLogEvent event;
        info << event
            << "[OtherDock] 截图保存成功, hwnd="
            << hwndToText(kHwndValue).toStdString()
            << ", path="
            << kSavePath.toStdString()
            << eol;
        QMessageBox::information(this, QStringLiteral("窗口截图"), QStringLiteral("截图已保存：%1").arg(kSavePath));
    });

    // Desktop management page connections: refresh, switch, create, double-click, and right-click menu each trigger their corresponding desktop operation chain.
    connect(desktopRefreshButton_, &QPushButton::clicked, this, [this]() {
        KLogEvent event;
        info << event
            << "[OtherDock] 用户点击刷新桌面列表。"
            << eol;
        refreshDesktopList();
    });
    connect(desktopSwitchButton_, &QPushButton::clicked, this, [this]() {
        switchToSelectedDesktop();
    });
    connect(desktopCreateButton_, &QPushButton::clicked, this, [this]() {
        showCreateDesktopDialog();
    });
    connect(desktopTable_, &QTableWidget::cellDoubleClicked, this, [this](int, int) {
        switchToSelectedDesktop();
    });
    connect(desktopTable_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& pos) {
        showDesktopContextMenu(pos);
    });
}

void OtherDock::applyViewMode()
{
    // Icon, list, and details modes are implemented via column visibility toggling and decorative style changes.
    const int kMode = viewModeCombo_->currentIndex();
    if (kMode == 0)
    {
        // Icon view: retain key columns to reduce information density.
        for (int col = 0; col < windowTree_->columnCount(); ++col)
        {
            const bool kKeepVisible =
                (col == kWindowColumnTitle
                    || col == kWindowColumnHandle
                    || col == kWindowColumnProcessName);
            windowTree_->setColumnHidden(col, !kKeepVisible);
        }
        windowTree_->setIconSize(QSize(20, 20));
    }
    else if (kMode == 1)
    {
        // List view: retain more information than icon mode, including PID, status, and visibility.
        for (int col = 0; col < windowTree_->columnCount(); ++col)
        {
            const bool kKeepVisible =
                (col == kWindowColumnTitle
                    || col == kWindowColumnHandle
                    || col == kWindowColumnPid
                    || col == kWindowColumnProcessName
                    || col == kWindowColumnState);
            windowTree_->setColumnHidden(col, !kKeepVisible);
        }
        windowTree_->setIconSize(QSize(16, 16));
    }
    else
    {
        // Details view: display all columns to satisfy audit scenarios.
        for (int col = 0; col < windowTree_->columnCount(); ++col)
        {
            windowTree_->setColumnHidden(col, false);
        }
        windowTree_->setIconSize(QSize(16, 16));
    }

    // Log the current view policy: enables rapid localization when users report 'columns suddenly disappearing'.
    KLogEvent event;
    info << event
        << "[OtherDock] 应用视图模式, mode="
        << viewModeText(kMode).toStdString()
        << eol;
}

void OtherDock::refreshWindowListAsync()
{
    // Prevent concurrent refresh: Ignore the current request if the previous one is not yet complete.
    if (refreshRunning_.exchange(true))
    {
        KLogEvent event;
        dbg << event
            << "[OtherDock] 跳过刷新：已有枚举任务在执行。"
            << eol;
        return;
    }

    // The asynchronous refresh chain uniformly reuses refreshEvent to ensure 'start/complete' logs can be traced using the same GUID.
    KLogEvent refreshEvent;
    const int kEnumMode = enumModeCombo_ != nullptr ? enumModeCombo_->currentIndex() : 0;
    info << refreshEvent
        << "[OtherDock] 启动异步窗口枚举, filterMode="
        << filterModeText(filterModeCombo_->currentIndex()).toStdString()
        << ", groupMode="
        << groupModeText(groupModeCombo_->currentIndex()).toStdString()
        << ", enumMode="
        << enumModeText(kEnumMode).toStdString()
        << ", keyword="
        << filterEdit_->text().toStdString()
        << eol;

    if (refreshProgressPid_ == 0)
    {
        refreshProgressPid_ = kPro.addReusable(this, "窗口", "窗口枚举");
    }
    kPro.set(refreshProgressPid_, "开始枚举窗口", 0, 5.0f);

    QPointer<OtherDock> guardThis(this);
    std::thread([guardThis, refreshEvent, kEnumMode]() {
        std::vector<WindowInfo> snapshot;
        // collectWindowSnapshotByMode: Collects and deduplicates windows based on the user-selected strategy.
        collectWindowSnapshotByMode(kEnumMode, snapshot);

        if (guardThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(qApp, [guardThis, snapshot = std::move(snapshot), refreshEvent, kEnumMode]() mutable {
            if (guardThis == nullptr)
            {
                return;
            }

            kPro.set(guardThis->refreshProgressPid_, "合并窗口快照", 0, 70.0f);

            // Record the previous round of valid windows as the baseline for 'added/removed' comparison.
            std::vector<WindowInfo> previousValidList;
            previousValidList.reserve(guardThis->windowSnapshot_.size());
            for (const WindowInfo& info : guardThis->windowSnapshot_)
            {
                if (info.valid)
                {
                    previousValidList.push_back(info);
                }
            }

            std::unordered_set<quint64> currentHandleSet;
            currentHandleSet.reserve(snapshot.size());
            for (const WindowInfo& info : snapshot)
            {
                currentHandleSet.insert(info.hwndValue);
            }

            std::unordered_set<quint64> previousHandleSet;
            previousHandleSet.reserve(previousValidList.size());
            for (const WindowInfo& info : previousValidList)
            {
                previousHandleSet.insert(info.hwndValue);
            }

            // Calculate new windows for green highlighting.
            guardThis->newWindowHandles_.clear();
            for (const WindowInfo& info : snapshot)
            {
                if (previousHandleSet.find(info.hwndValue) == previousHandleSet.end())
                {
                    guardThis->newWindowHandles_.push_back(info.hwndValue);
                }
            }

            // Calculate exited windows: retain one round and display in gray.
            guardThis->exitedOneRound_.clear();
            for (const WindowInfo& oldInfo : previousValidList)
            {
                if (currentHandleSet.find(oldInfo.hwndValue) != currentHandleSet.end())
                {
                    continue;
                }

                WindowInfo exitedInfo = oldInfo;
                exitedInfo.valid = false;
                exitedInfo.visible = false;
                exitedInfo.enabled = false;
                exitedInfo.topMost = false;
                exitedInfo.minimized = false;
                exitedInfo.maximized = false;
                exitedInfo.titleText = QStringLiteral("[已退出] %1").arg(oldInfo.titleText);
                guardThis->exitedOneRound_.push_back(exitedInfo);
            }

            // Current display list = current snapshot + one round of retained exit.
            guardThis->previousSnapshot_ = snapshot;
            guardThis->windowSnapshot_ = snapshot;
            guardThis->windowSnapshot_.insert(
                guardThis->windowSnapshot_.end(),
                guardThis->exitedOneRound_.begin(),
                guardThis->exitedOneRound_.end());

            guardThis->rebuildWindowTreeFromSnapshot();
            guardThis->updateStatusBar();
            guardThis->refreshRunning_.store(false);
            kPro.set(guardThis->refreshProgressPid_, "窗口枚举完成", 0, 100.0f);

            info << refreshEvent
                << "[OtherDock] 枚举完成，当前窗口="
                << snapshot.size()
                << ", enumMode="
                << enumModeText(kEnumMode).toStdString()
                << ", 退出保留="
                << guardThis->exitedOneRound_.size()
                << eol;
        }, Qt::QueuedConnection);
    }).detach();
}

bool OtherDock::passFilter(const WindowInfo& info) const
{
    // External PID filter (set when jumping from the Process page's 'View Windows' action) is only an additional
    // narrowing layer and cannot replace the dropdown condition and keyword: previously, a direct return here
    // caused the 'Filter Mode' dropdown and keyword input to remain active and editable after the jump, yet have
    // no effect on results—the UI shows 'Visible Windows', but execution actually uses 'All Windows for that PID'.
    if (!externalProcessIdFilterSet_.isEmpty() &&
        !externalProcessIdFilterSet_.contains(static_cast<quint32>(info.processId)))
    {
        return false;
    }

    // Conditional filtering: first filter out non-matching items based on the dropdown selection.
    const int kMode = filterModeCombo_->currentIndex();
    switch (kMode)
    {
    case 0:
        if (!info.visible || !info.valid)
        {
            return false;
        }
        break;
    case 1:
        if (info.visible || !info.valid)
        {
            return false;
        }
        break;
    case 2:
        if (info.isChildWindow || !info.valid)
        {
            return false;
        }
        break;
    case 3:
        if (!info.isChildWindow || !info.valid)
        {
            return false;
        }
        break;
    case 4:
        if (info.valid)
        {
            return false;
        }
        break;
    default:
        break;
    }

    // Keyword filtering: supports title, class name, process name, and handle text.
    const QString kKeyword = filterEdit_->text().trimmed();
    if (kKeyword.isEmpty())
    {
        return true;
    }

    const QString kKeywordLower = kKeyword.toLower();
    const QString kJoinedText = QStringLiteral("%1 %2 %3 %4 %5")
        .arg(info.titleText)
        .arg(info.classNameText)
        .arg(info.processNameText)
        .arg(info.processId)
        .arg(hwndToText(info.hwndValue))
        .toLower();
    return kJoinedText.contains(kKeywordLower);
}

void OtherDock::rebuildWindowTreeFromSnapshot()
{
    // Rebuild the tree link by reusing rebuildEvent to ensure 'start/complete' logs can be traced by the same GUID.
    KLogEvent rebuildEvent;
    dbg << rebuildEvent
        << "[OtherDock] 重建窗口树开始, snapshotCount="
        << windowSnapshot_.size()
        << ", filterMode="
        << filterModeText(filterModeCombo_->currentIndex()).toStdString()
        << ", groupMode="
        << groupModeText(groupModeCombo_->currentIndex()).toStdString()
        << eol;

    windowTree_->clear();

    // Process icon cache:
    // - Use PID as key to avoid extracting the same process icon multiple times.
    // - Cache hits significantly reduce icon query overhead during refresh.
    std::unordered_map<std::uint32_t, QIcon> processLogoCache;
    auto resolveProcessLogo = [&processLogoCache](const WindowInfo& info) -> QIcon {
        const auto kFound = processLogoCache.find(info.processId);
        if (kFound != processLogoCache.end())
        {
            return kFound->second;
        }
        const QIcon kProcessLogo = queryProcessLogoIconByPath(info.processImagePathText);
        processLogoCache.emplace(info.processId, kProcessLogo);
        return kProcessLogo;
    };

    // Public leaf node generation function: unifies column filling and highlighting rules.
    auto appendLeafItem = [this, &resolveProcessLogo](QTreeWidgetItem* parent, const WindowInfo& info) {
        QTreeWidgetItem* item = nullptr;
        if (parent != nullptr)
        {
            item = new QTreeWidgetItem(parent);
        }
        else
        {
            item = new QTreeWidgetItem(windowTree_);
        }

        const QString kSizeText = QStringLiteral("%1 x %2")
            .arg(info.windowRect.width())
            .arg(info.windowRect.height());

        item->setText(kWindowColumnTitle, info.titleText.isEmpty() ? QStringLiteral("<无标题>") : info.titleText);
        item->setText(kWindowColumnHandle, hwndToText(info.hwndValue));
        item->setText(kWindowColumnEnumApi, info.enumApiName);
        item->setText(kWindowColumnClassName, info.classNameText);
        item->setText(kWindowColumnPid, QString::number(info.processId));
        item->setText(kWindowColumnProcessName, info.processNameText);
        item->setText(kWindowColumnTid, QString::number(info.threadId));
        item->setText(kWindowColumnSize, kSizeText);
        item->setText(kWindowColumnVisible, boolText(info.visible));
        item->setText(kWindowColumnEnabled, boolText(info.enabled));
        item->setText(kWindowColumnTopMost, boolText(info.topMost));
        item->setText(kWindowColumnState, windowStateText(info.valid, info.minimized, info.maximized));
        item->setText(kWindowColumnAlpha, QString::number(info.alphaValue));

        item->setData(kWindowColumnTitle, Qt::UserRole, QVariant::fromValue(static_cast<qulonglong>(info.hwndValue)));
        item->setData(kWindowColumnTitle, Qt::UserRole + 1, false);

        // Change leaf icons to display the 'process logo' and place them in the process column to avoid interfering with readability in the title column.
        item->setIcon(kWindowColumnProcessName, resolveProcessLogo(info));

        // New windows are highlighted in green; exited windows are grayed out.
        const bool kIsNew = std::find(
            newWindowHandles_.begin(),
            newWindowHandles_.end(),
            info.hwndValue) != newWindowHandles_.end();

        if (!info.valid)
        {
            for (int col = 0; col < windowTree_->columnCount(); ++col)
            {
                item->setForeground(col, QBrush(ksword_theme::exitedRowForegroundColor()));
                item->setBackground(col, QBrush(ksword_theme::exitedRowBackgroundColor()));
            }
        }
        else if (kIsNew)
        {
            for (int col = 0; col < windowTree_->columnCount(); ++col)
            {
                item->setBackground(col, QBrush(ksword_theme::newRowBackgroundColor()));
            }
        }
    };

    // Rebuild tree structure based on grouping options.
    const int kGroupMode = groupModeCombo_->currentIndex();

    if (kGroupMode == 0)
    {
        // Group by process: window child nodes attached under process nodes.
        std::map<QString, QTreeWidgetItem*> processMap;
        for (const WindowInfo& info : windowSnapshot_)
        {
            if (!passFilter(info))
            {
                continue;
            }

            const QString kProcessKey = QStringLiteral("%1 (PID:%2)")
                .arg(info.processNameText, QString::number(info.processId));
            QTreeWidgetItem* groupItem = nullptr;
            auto found = processMap.find(kProcessKey);
            if (found == processMap.end())
            {
                groupItem = new QTreeWidgetItem(windowTree_);
                groupItem->setText(0, kProcessKey);
                // Process group nodes also display the process logo to satisfy the requirement that 'all processes show an icon'.
                groupItem->setIcon(0, resolveProcessLogo(info));
                groupItem->setData(0, Qt::UserRole + 1, true);
                processMap.emplace(kProcessKey, groupItem);
            }
            else
            {
                groupItem = found->second;
            }
            appendLeafItem(groupItem, info);
        }
    }
    else if (kGroupMode == 1)
    {
        // Sort by Z-order: tiled display, sorted by enumeration order.
        std::vector<WindowInfo> orderedList = windowSnapshot_;
        std::sort(
            orderedList.begin(),
            orderedList.end(),
            [](const WindowInfo& left, const WindowInfo& right) {
                return left.zOrder < right.zOrder;
            });
        for (const WindowInfo& info : orderedList)
        {
            if (!passFilter(info))
            {
                continue;
            }
            appendLeafItem(nullptr, info);
        }
    }
    else if (kGroupMode == 2)
    {
        // Classify by hierarchy: desktop/top-level/sub-window/popup/window/tool-window.
        std::map<QString, QTreeWidgetItem*> levelGroupMap;
        auto getLevelGroup = [this, &levelGroupMap](const QString& key) -> QTreeWidgetItem* {
            auto found = levelGroupMap.find(key);
            if (found != levelGroupMap.end())
            {
                return found->second;
            }
            QTreeWidgetItem* item = new QTreeWidgetItem(windowTree_);
            item->setText(0, key);
            item->setIcon(0, QIcon(":/Icon/process_tree.svg"));
            item->setData(0, Qt::UserRole + 1, true);
            levelGroupMap.emplace(key, item);
            return item;
        };

        for (const WindowInfo& info : windowSnapshot_)
        {
            if (!passFilter(info))
            {
                continue;
            }

            QString groupKey = QStringLiteral("顶级窗口");
            if (info.hwndValue == static_cast<quint64>(reinterpret_cast<quintptr>(::GetDesktopWindow())))
            {
                groupKey = QStringLiteral("桌面窗口");
            }
            else if (info.isChildWindow)
            {
                groupKey = QStringLiteral("子窗口");
            }
            else if ((info.styleValue & WS_POPUP) != 0)
            {
                groupKey = QStringLiteral("弹出窗口");
            }
            else if ((info.exStyleValue & WS_EX_TOOLWINDOW) != 0)
            {
                groupKey = QStringLiteral("工具窗口");
            }

            appendLeafItem(getLevelGroup(groupKey), info);
        }
    }
    else
    {
        // Group by monitor: based on the screen containing the window's center point.
        std::map<QString, QTreeWidgetItem*> monitorGroupMap;
        const QList<QScreen*> kScreenList = QGuiApplication::screens();

        auto getMonitorGroup = [this, &monitorGroupMap](const QString& key) -> QTreeWidgetItem* {
            auto found = monitorGroupMap.find(key);
            if (found != monitorGroupMap.end())
            {
                return found->second;
            }
            QTreeWidgetItem* item = new QTreeWidgetItem(windowTree_);
            item->setText(0, key);
            item->setIcon(0, QIcon(":/Icon/process_list.svg"));
            item->setData(0, Qt::UserRole + 1, true);
            monitorGroupMap.emplace(key, item);
            return item;
        };

        for (const WindowInfo& info : windowSnapshot_)
        {
            if (!passFilter(info))
            {
                continue;
            }

            QString groupKey = QStringLiteral("未知显示器");
            const QPoint kCenterPoint = info.windowRect.center();
            for (int i = 0; i < kScreenList.size(); ++i)
            {
                QScreen* screen = kScreenList.at(i);
                if (screen != nullptr && screen->geometry().contains(kCenterPoint))
                {
                    groupKey = QStringLiteral("显示器%1: %2")
                        .arg(i + 1)
                        .arg(screen->name());
                    break;
                }
            }
            appendLeafItem(getMonitorGroup(groupKey), info);
        }
    }

    // Expand the first level of nodes uniformly to allow users to see data directly.
    for (int i = 0; i < windowTree_->topLevelItemCount(); ++i)
    {
        QTreeWidgetItem* topItem = windowTree_->topLevelItem(i);
        if (topItem != nullptr && topItem->data(0, Qt::UserRole + 1).toBool())
        {
            topItem->setExpanded(true);
        }
    }

    dbg << rebuildEvent
        << "[OtherDock] 重建窗口树完成, topLevelCount="
        << windowTree_->topLevelItemCount()
        << eol;
}

void OtherDock::updateStatusBar()
{
    int totalCount = 0;
    int visibleCount = 0;
    int systemCount = 0;
    for (const WindowInfo& info : windowSnapshot_)
    {
        if (!info.valid)
        {
            continue;
        }
        ++totalCount;
        if (info.visible)
        {
            ++visibleCount;
        }
        if (info.processId <= 4
            || info.processNameText.compare(QStringLiteral("System"), Qt::CaseInsensitive) == 0
            || info.processNameText.compare(QStringLiteral("csrss.exe"), Qt::CaseInsensitive) == 0)
        {
            ++systemCount;
        }
    }

    totalLabel_->setText(QStringLiteral("总数: %1").arg(totalCount));
    visibleLabel_->setText(QStringLiteral("可见: %1").arg(visibleCount));
    systemLabel_->setText(QStringLiteral("系统: %1").arg(systemCount));

    KLogEvent event;
    dbg << event
        << "[OtherDock] 状态栏更新, total="
        << totalCount
        << ", visible="
        << visibleCount
        << ", system="
        << systemCount
        << eol;
}

void OtherDock::updatePreviewPanel(const WindowInfo* info)
{
    // Clear the preview when no item is selected to prevent displaying stale information.
    if (info == nullptr)
    {
        thumbnailLabel_->setPixmap(QPixmap());
        quickInfoText_->setText(QStringLiteral("请选择左侧窗口项查看预览。"));
        KLogEvent event;
        dbg << event
            << "[OtherDock] 预览面板清空（无有效选中项）。"
            << eol;
        return;
    }

    // Grab the thumbnail and update the right-side key property summary.
    const QPixmap kPreviewPixmap = grabWindowPreviewPixmap(
        info->hwndValue,
        thumbnailLabel_->size());
    thumbnailLabel_->setPixmap(kPreviewPixmap);

    QString quickText;
    quickText += QStringLiteral("句柄: %1\n").arg(hwndToText(info->hwndValue));
    quickText += QStringLiteral("标题: %1\n").arg(info->titleText);
    quickText += QStringLiteral("类名: %1\n").arg(info->classNameText);
    quickText += QStringLiteral("PID/TID: %1 / %2\n").arg(info->processId).arg(info->threadId);
    quickText += QStringLiteral("进程名: %1\n").arg(info->processNameText);
    quickText += QStringLiteral("矩形: [%1,%2,%3,%4]\n")
        .arg(info->windowRect.left())
        .arg(info->windowRect.top())
        .arg(info->windowRect.right())
        .arg(info->windowRect.bottom());
    quickText += QStringLiteral("可见:%1  可用:%2  顶层:%3\n")
        .arg(boolText(info->visible))
        .arg(boolText(info->enabled))
        .arg(boolText(info->topMost));
    quickText += QStringLiteral("状态:%1  透明度:%2\n")
        .arg(windowStateText(info->valid, info->minimized, info->maximized))
        .arg(info->alphaValue);
    if (info->displayAffinityKnown)
    {
        const QString kAffinityHexText =
            QString::number(static_cast<qulonglong>(info->displayAffinityValue), 16).toUpper();
        quickText += QStringLiteral("DisplayAffinity: 0x%1 (%2)\n")
            .arg(kAffinityHexText)
            .arg(QString::fromStdString(ks::window::displayAffinityName(info->displayAffinityValue)));
    }
    else
    {
        quickText += QStringLiteral("DisplayAffinity: 未知（错误码=%1）\n")
            .arg(info->displayAffinityError);
    }
    quickInfoText_->setText(quickText);

    KLogEvent event;
    dbg << event
        << "[OtherDock] 预览面板刷新, hwnd="
        << hwndToText(info->hwndValue).toStdString()
        << ", pid="
        << info->processId
        << eol;
}

void OtherDock::handleWindowPickerRelease(const QPoint& globalPos)
{
    // The pick chain uniformly reuses pickEvent to ensure traceability from 'drag-and-drop release' to 'open details'.
    KLogEvent pickEvent;
    info << pickEvent
        << "[OtherDock] 准星拾取释放, x="
        << globalPos.x()
        << ", y="
        << globalPos.y()
        << eol;

    POINT nativePoint{};
    nativePoint.x = globalPos.x();
    nativePoint.y = globalPos.y();

    // rawWindowHandle directly corresponds to the finest-grained window under the mouse; rootWindowHandle serves as a fallback to the top-level window.
    HWND rawWindowHandle = ::WindowFromPoint(nativePoint);
    HWND rootWindowHandle = rawWindowHandle != nullptr ? ::GetAncestor(rawWindowHandle, GA_ROOT) : nullptr;
    HWND targetWindowHandle = rawWindowHandle != nullptr ? rawWindowHandle : rootWindowHandle;

    if (targetWindowHandle == nullptr || ::IsWindow(targetWindowHandle) == FALSE)
    {
        warn << pickEvent
            << "[OtherDock] 准星拾取失败：WindowFromPoint 未命中有效窗口。"
            << eol;
        QMessageBox::information(
            this,
            QStringLiteral("窗口拾取"),
            QStringLiteral("未命中可用窗口，请重试。"));
        return;
    }

    const quint64 kRawHwndValue = static_cast<quint64>(
        reinterpret_cast<quintptr>(rawWindowHandle));
    const quint64 kRootHwndValue = static_cast<quint64>(
        reinterpret_cast<quintptr>(rootWindowHandle));
    quint64 targetHwndValue = kRawHwndValue;

    // Prioritize matching against the 'original window under the mouse'; if that fails, fall back to matching the top-level window.
    const WindowInfo* pickedInfo = findInfoByHwnd(kRawHwndValue);
    if (pickedInfo == nullptr && kRootHwndValue != 0 && kRootHwndValue != kRawHwndValue)
    {
        pickedInfo = findInfoByHwnd(kRootHwndValue);
        targetWindowHandle = rootWindowHandle;
        targetHwndValue = kRootHwndValue;
    }
    else
    {
        targetWindowHandle = rawWindowHandle;
        targetHwndValue = kRawHwndValue;
    }

    // fallbackInfo is used to construct default detail data, avoiding the need to refresh the list before viewing the target window.
    WindowInfo fallbackInfo;
    if (pickedInfo == nullptr)
    {
        const bool kChildFlag = ::GetParent(targetWindowHandle) != nullptr;
        fillWindowInfo(
            targetWindowHandle,
            -1,
            kChildFlag,
            QStringLiteral("WindowPicker"),
            fallbackInfo);
        pickedInfo = &fallbackInfo;

        warn << pickEvent
            << "[OtherDock] 准星拾取命中窗口不在当前快照，已使用即时查询兜底, hwnd="
            << hwndToText(targetHwndValue).toStdString()
            << eol;
    }

    if (pickedInfo == nullptr)
    {
        err << pickEvent
            << "[OtherDock] 准星拾取失败：无法构造窗口详情。"
            << eol;
        QMessageBox::warning(
            this,
            QStringLiteral("窗口拾取"),
            QStringLiteral("读取目标窗口信息失败。"));
        return;
    }

    info << pickEvent
        << "[OtherDock] 准星拾取成功，打开窗口详情, hwnd="
        << hwndToText(pickedInfo->hwndValue).toStdString()
        << ", pid="
        << pickedInfo->processId
        << eol;
    openWindowDetailDialog(*pickedInfo);
}

void OtherDock::showWindowContextMenu(const QPoint& localPos)
{
    QTreeWidgetItem* item = windowTree_->itemAt(localPos);
    if (item == nullptr || item->data(0, Qt::UserRole + 1).toBool())
    {
        return;
    }

    const quint64 kHwndValue = item->data(0, Qt::UserRole).toULongLong();
    const WindowInfo* windowInfo = findInfoByHwnd(kHwndValue);
    if (windowInfo == nullptr)
    {
        return;
    }

    {
        KLogEvent event;
        dbg << event
            << "[OtherDock] 打开右键菜单, hwnd="
            << hwndToText(kHwndValue).toStdString()
            << ", pid="
            << windowInfo->processId
            << eol;
    }

    QMenu menu(this);
    // Explicitly fill the menu background to avoid a black background caused by inheriting a transparent style in light mode.
    menu.setStyleSheet(ksword_theme::contextMenuStyle());
    QAction* activateAction = menu.addAction(QIcon(":/Icon/process_start.svg"), QStringLiteral("激活窗口"));
    QAction* topMostAction = menu.addAction(QIcon(":/Icon/process_priority.svg"), QStringLiteral("置顶/取消置顶"));
    QAction* showHideAction = menu.addAction(QIcon(":/Icon/process_pause.svg"), QStringLiteral("显示/隐藏"));
    QAction* enableDisableAction = menu.addAction(QIcon(":/Icon/process_suspend.svg"), QStringLiteral("启用/禁用"));
    const WindowInfo kInputSnapshot = *windowInfo;
    QAction* inputAction = menu.addAction(ks::i18n::text(
        QStringLiteral("window.input.tab"), QStringLiteral("窗口输入与顺序")));
    QAction* flashAction = menu.addAction(QIcon(":/Icon/window_picker_target.svg"), QStringLiteral("闪烁窗口"));
    QAction* protectCaptureAction = menu.addAction(QIcon(":/Icon/titlebar_capture_protected.svg"), QStringLiteral("启用防截图保护"));
    QAction* unprotectCaptureAction = menu.addAction(QIcon(":/Icon/titlebar_capture_allowed.svg"), QStringLiteral("取消防截图保护"));
    menu.addSeparator();
    QAction* processDetailAction = menu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("转到进程详细信息"));
    QAction* windowDetailAction = menu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("在详细信息中打开"));
    QAction* sendMessageAction = menu.addAction(QIcon(":/Icon/log_track.svg"), QStringLiteral("发送测试消息"));
    QAction* uploadVirusTotalAction = ks::online_scan::addVirusTotalSandboxMenu(
        &menu,
        this,
        [windowInfo]() -> ks::online_scan::SandboxUploadTarget
        {
            // Input: Current right-clicked window snapshot from the window list.
            // Processing: Upload the corresponding process file based on the PID of the GUI thread; the window thread ID is for source identification only.
            // Returns: VT upload target; if PID is null or the process path cannot be resolved, delegate to a unified helper for prompting.
            ks::online_scan::SandboxUploadTarget uploadTarget;
            if (windowInfo == nullptr || windowInfo->processId == 0)
            {
                uploadTarget.errorText = QStringLiteral("当前窗口没有可解析的 GUI 线程进程 PID。");
                return uploadTarget;
            }
            uploadTarget.filePath = QString::fromStdString(ks::process::queryProcessPathByPid(windowInfo->processId));
            uploadTarget.sourceText = QStringLiteral("窗口 GUI 线程 PID=%1 TID=%2")
                .arg(windowInfo->processId)
                .arg(windowInfo->threadId);
            return uploadTarget;
        });
    menu.addSeparator();
    QAction* terminateAction = menu.addAction(QIcon(":/Icon/process_terminate.svg"), QStringLiteral("结束进程"));

    QAction* selectedAction = menu.exec(windowTree_->viewport()->mapToGlobal(localPos));
    if (selectedAction == nullptr)
    {
        KLogEvent event;
        dbg << event
            << "[OtherDock] 右键菜单取消, hwnd="
            << hwndToText(kHwndValue).toStdString()
            << eol;
        return;
    }

    if (selectedAction == inputAction)
    {
        openWindowDetailDialog(kInputSnapshot, true);
        return;
    }
    HWND windowHandle = toHwnd(windowInfo->hwndValue);
    if (selectedAction == activateAction)
    {
        KLogEvent event;
        info << event
            << "[OtherDock] 执行操作：激活窗口, hwnd="
            << hwndToText(kHwndValue).toStdString()
            << eol;
        ::ShowWindow(windowHandle, SW_SHOW);
        ::SetForegroundWindow(windowHandle);
    }
    else if (selectedAction == topMostAction)
    {
        KLogEvent event;
        info << event
            << "[OtherDock] 执行操作：切换置顶, hwnd="
            << hwndToText(kHwndValue).toStdString()
            << eol;
        const bool kCurrentTopMost = (::GetWindowLongPtrW(windowHandle, GWL_EXSTYLE) & WS_EX_TOPMOST) != 0;
        ::SetWindowPos(
            windowHandle,
            kCurrentTopMost ? HWND_NOTOPMOST : HWND_TOPMOST,
            0,
            0,
            0,
            0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    }
    else if (selectedAction == showHideAction)
    {
        KLogEvent event;
        info << event
            << "[OtherDock] 执行操作：显示/隐藏, hwnd="
            << hwndToText(kHwndValue).toStdString()
            << eol;
        const bool kCurrentlyVisible = ::IsWindowVisible(windowHandle) != FALSE;
        ::ShowWindow(windowHandle, kCurrentlyVisible ? SW_HIDE : SW_SHOW);
    }
    else if (selectedAction == enableDisableAction)
    {
        KLogEvent event;
        info << event
            << "[OtherDock] 执行操作：启用/禁用, hwnd="
            << hwndToText(kHwndValue).toStdString()
            << eol;
        const bool kCurrentlyEnabled = ::IsWindowEnabled(windowHandle) != FALSE;
        ::EnableWindow(windowHandle, kCurrentlyEnabled ? FALSE : TRUE);
    }
    else if (selectedAction == flashAction)
    {
        KLogEvent event;
        info << event
            << "[OtherDock] 执行操作：闪烁窗口, hwnd="
            << hwndToText(kHwndValue).toStdString()
            << eol;
        FLASHWINFO flashInfo{};
        flashInfo.cbSize = sizeof(flashInfo);
        flashInfo.hwnd = windowHandle;
        flashInfo.dwFlags = FLASHW_ALL | FLASHW_TIMERNOFG;
        flashInfo.uCount = 3;
        flashInfo.dwTimeout = 0;
        ::FlashWindowEx(&flashInfo);
    }
    else if (selectedAction == protectCaptureAction)
    {
        setCaptureProtectionForWindow(*windowInfo, true);
    }
    else if (selectedAction == unprotectCaptureAction)
    {
        setCaptureProtectionForWindow(*windowInfo, false);
    }
    else if (selectedAction == processDetailAction)
    {
        KLogEvent event;
        info << event
            << "[OtherDock] 执行操作：打开进程详情, pid="
            << windowInfo->processId
            << eol;
        openProcessDetailWindow(this, windowInfo->processId);
    }
    else if (selectedAction == windowDetailAction)
    {
        KLogEvent event;
        info << event
            << "[OtherDock] 执行操作：打开窗口详情, hwnd="
            << hwndToText(kHwndValue).toStdString()
            << eol;
        openWindowDetailDialog(*windowInfo);
    }
    else if (selectedAction == sendMessageAction)
    {
        KLogEvent event;
        dbg << event
            << "[OtherDock] 执行操作：发送测试消息, hwnd="
            << hwndToText(kHwndValue).toStdString()
            << eol;
        DWORD_PTR resultValue = 0;
        ::SendMessageTimeoutW(
            windowHandle,
            WM_NULL,
            0,
            0,
            SMTO_ABORTIFHUNG,
            1200,
            &resultValue);
        Q_UNUSED(resultValue);
    }
    else if (selectedAction == uploadVirusTotalAction)
    {
        return;
    }
    else if (selectedAction == terminateAction)
    {
        // The process termination action executes directly, and the result is recorded via unified logging.
        KLogEvent actionEvent;
        warn << actionEvent
            << "[OtherDock] 执行操作：结束进程, pid="
            << windowInfo->processId
            << eol;

        std::string terminateErrorText;
        const bool kTerminateOk = ks::process::terminateProcessByWin32IfCreationTimeMatches(
            static_cast<std::uint32_t>(windowInfo->processId),
            windowInfo->processCreationTime100ns,
            &terminateErrorText);
        if (!kTerminateOk)
        {
            err << actionEvent
                << "[OtherDock] 结束进程失败, pid="
                << windowInfo->processId
                << ", detail=" << terminateErrorText
                << eol;
        }
        else
        {
            warn << actionEvent
                << "[OtherDock] 结束进程成功, pid="
                << windowInfo->processId
                << eol;
        }
        dbg << actionEvent
            << "[OtherDock] 结束进程操作处理完毕, pid="
            << windowInfo->processId
            << ", processName="
            << windowInfo->processNameText.toStdString()
            << eol;
    }

    // Refresh the list after any state-related action to ensure consistency with the actual state.
    if (selectedAction != protectCaptureAction && selectedAction != unprotectCaptureAction)
    {
        refreshWindowListAsync();
    }
}

void OtherDock::exportVisibleRowsToTsv()
{
    // Traverse the current tree to export leaf nodes; group nodes are excluded from export.
    QStringList lines;

    QStringList header;
    for (int col = 0; col < windowTree_->columnCount(); ++col)
    {
        if (windowTree_->isColumnHidden(col))
        {
            continue;
        }
        header << windowTree_->headerItem()->text(col);
    }
    lines << header.join('\t');

    QTreeWidgetItemIterator iterator(windowTree_);
    while (*iterator != nullptr)
    {
        QTreeWidgetItem* item = *iterator;
        ++iterator;

        if (item->data(0, Qt::UserRole + 1).toBool())
        {
            continue;
        }

        QStringList rowValues;
        for (int col = 0; col < windowTree_->columnCount(); ++col)
        {
            if (windowTree_->isColumnHidden(col))
            {
                continue;
            }
            rowValues << item->text(col).replace('\t', ' ');
        }
        lines << rowValues.join('\t');
    }

    if (lines.size() <= 1)
    {
        KLogEvent event;
        dbg << event
            << "[OtherDock] 导出取消：当前无可见数据行。"
            << eol;
        QMessageBox::information(this, QStringLiteral("导出窗口列表"), QStringLiteral("没有可导出的行。"));
        return;
    }

    const QString kDefaultName = QStringLiteral("window_list_%1.tsv")
        .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss")));
    const QString kOutputPath = QFileDialog::getSaveFileName(
        this,
        QStringLiteral("导出窗口列表"),
        kDefaultName,
        QStringLiteral("TSV文件 (*.tsv);;文本文件 (*.txt)"));
    if (kOutputPath.trimmed().isEmpty())
    {
        KLogEvent event;
        dbg << event
            << "[OtherDock] 导出取消：用户未选择输出路径。"
            << eol;
        return;
    }

    QFile file(kOutputPath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate))
    {
        KLogEvent event;
        err << event
            << "[OtherDock] 导出失败：无法写入文件, path="
            << kOutputPath.toStdString()
            << eol;
        QMessageBox::warning(this, QStringLiteral("导出窗口列表"), QStringLiteral("无法写入文件：%1").arg(kOutputPath));
        return;
    }

    QTextStream out(&file);
    out.setEncoding(QStringConverter::Utf8);
    for (const QString& line : lines)
    {
        out << line << '\n';
    }
    file.close();

    KLogEvent event;
    info << event << "[OtherDock] 导出窗口列表成功:" << kOutputPath.toStdString() << eol;
    QMessageBox::information(this, QStringLiteral("导出窗口列表"), QStringLiteral("导出完成：%1").arg(kOutputPath));
}

void OtherDock::openWindowDetailDialog(const WindowInfo& windowInfo, bool inputSettings)
{
    KLogEvent event;
    info << event
        << "[OtherDock] 打开窗口详情对话框, hwnd="
        << hwndToText(windowInfo.hwndValue).toStdString()
        << ", pid="
        << windowInfo.processId
        << eol;

    WindowDetailDialog* dialog = new WindowDetailDialog(windowInfo, this);
    if (inputSettings)
    {
        auto* page = dialog->findChild<QWidget*>(QStringLiteral("ks_window_input_page"));
        for (auto* tabs : dialog->findChildren<QTabWidget*>())
            if (page && tabs->indexOf(page) >= 0) tabs->setCurrentWidget(page);
    }
    dialog->show();
    dialog->raise();
    dialog->activateWindow();
}

const OtherDock::WindowInfo* OtherDock::findInfoByHwnd(const quint64 hwndValue) const
{
    const auto kFinder = [hwndValue](const WindowInfo& info) {
        return info.hwndValue == hwndValue;
    };

    const auto kCurrentIt = std::find_if(
        windowSnapshot_.begin(),
        windowSnapshot_.end(),
        kFinder);
    if (kCurrentIt != windowSnapshot_.end())
    {
        return &(*kCurrentIt);
    }

    const auto kExitIt = std::find_if(
        exitedOneRound_.begin(),
        exitedOneRound_.end(),
        kFinder);
    if (kExitIt != exitedOneRound_.end())
    {
        return &(*kExitIt);
    }

    return nullptr;
}
