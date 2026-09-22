// ============================================================
// WindowDwmControl.cpp
// Purpose:
// 1) Add a DWM composition control page to the 'Window Properties' details dialog;
// 2) Read/write DWMWA_* attributes for any target window (non-client area rendering strategy,
//    transition animation, Flip3D strategy, Peek strategy, Cloak hiding, dark title bar, rounded
//    corner strategy, border/title/title text color scheme, Mica/Acrylic background material, etc.);
// 3) Provides control over three types of composition effects: DwmExtendFrameIntoClientArea,
//    DwmEnableBlurBehindWindow, and SetWindowCompositionAttribute(ACCENT_POLICY).
// 4) Embed a real-time thumbnail of the target window within the page via DwmRegisterThumbnail.
// 5) Aggregate system-level composition status (composition toggle, theme color, composition timing) and support report export.
// Design notes:
// - Consistent with WindowLayerDiagnostics: this page injects via an application-level event
//   filter into WindowDetailDialogRoot, requiring no changes to WindowDetailDialog itself.
// - DWM attribute calls are forwarded across processes to DWM; this page retains the HRESULT
//   for each call and displays the failure reason truthfully, without pretending success.
// ============================================================

#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QColor>
#include <QColorDialog>
#include <QComboBox>
#include <QCoreApplication>
#include <QDateTime>
#include <QDialog>
#include <QEvent>
#include <QFile>
#include <QFileDialog>
#include <QFontDatabase>
#include <QFrame>
#include <QGridLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QScrollArea>
#include <QScrollBar>
#include <QSlider>
#include <QSpinBox>
#include <QSplitter>
#include <QString>
#include <QStringList>
#include <QTabWidget>
#include <QTextCursor>
#include <QTextDocument>
#include <QTextStream>
#include <QTimer>
#include <QVariant>
#include <QVBoxLayout>
#include <QWidget>

#include "../internationalization/LanguageManager.h"
#include "../Theme.h"

#include <array>
#include <optional>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <uxtheme.h>
#include <dwmapi.h>

#pragma comment(lib, "Dwmapi.lib")

namespace ks::window::dwmctl
{
    // kAttachedProperty: Marks that a detail dialog has already been injected with a DWM tab to prevent duplicate additions.
    constexpr char kAttachedProperty[] = "ksword.windowDwmControl.attached";
    // kTargetHwndProperty: Metadata key for the target HWND published by WindowDetailDialog.
    constexpr char kTargetHwndProperty[] = "ksword.windowDetail.targetHwnd";

    // ============ DWMWINDOWATTRIBUTE IDs ============ Note: Do not
    // directly reference SDK enums to ensure compilation on older
    //       SDKs, and let runtime HRESULT determine system support.
    constexpr DWORD kAttrNcRenderingEnabled = 1;          // [Read] Whether the non-client area is currently being rendered by DWM.
    constexpr DWORD kAttrNcRenderingPolicy = 2;           // [Write] Non-client area rendering policy.
    constexpr DWORD kAttrTransitionsForceDisabled = 3;    // [Read/Write] Force disable window transition animations.
    constexpr DWORD kAttrAllowNcPaint = 4;                // [Write] Allow window to self-draw non-client area.
    constexpr DWORD kAttrCaptionButtonBounds = 5;         // [Read] Caption button bounds rectangle.
    constexpr DWORD kAttrNonClientRtlLayout = 6;          // [Write] Non-client area right-to-left layout.
    constexpr DWORD kAttrForceIconicRepresentation = 7;   // [Write] Force static thumbnail representation.
    constexpr DWORD kAttrFlip3DPolicy = 8;                // [Write] Display policy in Flip3D.
    constexpr DWORD kAttrExtendedFrameBounds = 9;         // [Read] Real frame rectangle with shadow correction.
    constexpr DWORD kAttrHasIconicBitmap = 10;            // [Write] Declares provision of iconic bitmap.
    constexpr DWORD kAttrDisallowPeek = 11;               // [Write] Prevent this window from triggering Aero Peek.
    constexpr DWORD kAttrExcludedFromPeek = 12;           // [Write] Exclude this window during Peek.
    constexpr DWORD kAttrCloak = 13;                      // [Write] Hide window from DWM (window still exists).
    constexpr DWORD kAttrCloaked = 14;                    // [Read] Current cloak source bit.
    constexpr DWORD kAttrFreezeRepresentation = 15;       // [Write] Freeze thumbnail representation.
    constexpr DWORD kAttrPassiveUpdateMode = 16;          // [Write] Passive update mode.
    constexpr DWORD kAttrUseHostBackdropBrush = 17;       // [Write] Use host backdrop brush.
    constexpr DWORD kAttrImmersiveDarkModeLegacy = 19;    // [Write] Dark title bar (1809~1903 legacy ID).
    constexpr DWORD kAttrImmersiveDarkMode = 20;          // [Write] Dark title bar (1909+ ID).
    constexpr DWORD kAttrWindowCornerPreference = 33;     // [Write] Window corner rounding policy (Win11).
    constexpr DWORD kAttrBorderColor = 34;                // [Write] Window border color (Win11).
    constexpr DWORD kAttrCaptionColor = 35;               // [Write] Title bar background color (Win11).
    constexpr DWORD kAttrTextColor = 36;                  // [Write] Title bar text color (Win11).
    constexpr DWORD kAttrVisibleFrameBorderThickness = 37;// [Read] Visible border thickness (Win11).
    constexpr DWORD kAttrSystemBackdropType = 38;         // [Read/Write] Background material Mica/Acrylic (Win11 22H2).

    // kColorDefault / kColorNone purpose: Two special values for DWMWA_*_COLOR.
    constexpr DWORD kColorDefault = 0xFFFFFFFFu;
    constexpr DWORD kColorNone = 0xFFFFFFFEu;

    // Build number threshold: used only for UI prompts; does not prevent users from actually attempting the call.
    constexpr DWORD kBuildWin10Dark = 17763;
    constexpr DWORD kBuildWin10DarkNew = 18362;
    constexpr DWORD kBuildWin11 = 22000;
    constexpr DWORD kBuildWin1122H2 = 22621;

    // Related to SetWindowCompositionAttribute (undocumented API, used for Acrylic/blur effects).
    constexpr DWORD kWcaAccentPolicy = 19;        // WCA_ACCENT_POLICY。
    constexpr DWORD kWcaUseDarkModeColors = 26;   // WCA_USEDARKMODECOLORS。

    // kThumbnailRefreshMs purpose: Ensures the thumbnail target rectangle refreshes in sync with the cycle, balancing responsiveness and overhead.
    constexpr int kThumbnailRefreshMs = 120;
    // kLogBlockLimit: Maximum number of lines retained in operation logs.
    constexpr int kLogBlockLimit = 2000;

    // AccentPolicyData description: Corresponds to the layout of the undocumented ACCENT_POLICY structure.
    struct AccentPolicyData
    {
        DWORD accentState = 0;     // accentState: ACCENT_STATE enumeration value.
        DWORD accentFlags = 0;     // accentFlags: Drawing flags.
        DWORD gradientColor = 0;   // gradientColor: Color value in 0xAABBGGRR order.
        DWORD animationId = 0;     // animationId: Animation identifier, typically set to 0.
    };

    // WindowCompositionAttributeData description: Corresponds to the undocumented WINDOWCOMPOSITIONATTRIBDATA.
    struct WindowCompositionAttributeData
    {
        DWORD attribute = 0;       // attribute: WCA_* feature identifier.
        void* data = nullptr;      // data: feature data buffer.
        SIZE_T dataSize = 0;       // dataSize: buffer size in bytes.
    };

    // ============ Common Widgets ============

    // uiText：
    // - Purpose: Retrieve translation by semantic key, falling back to built-in Chinese if missing;
    // - Input key: language pack semantic key; input fallback: Chinese fallback text.
    // - Output: text to display under the current language.
    QString uiText(const char* key, const char* fallback)
    {
        return ks::i18n::text(QString::fromLatin1(key), QString::fromUtf8(fallback));
    }

    // bindUiText：
    // - Purpose: Bind control text to semantic keys; automatically redraw when switching languages at runtime.
    // - Input object: target control; input key/fallback: same as uiText;
    void bindUiText(QObject* object, const char* key, const char* fallback)
    {
        ks::i18n::LanguageManager::instance().bindText(
            object, QString::fromLatin1(key), QString::fromUtf8(fallback));
    }

    // makeButton：
    // - Purpose: Create the button and perform language binding simultaneously to avoid repeating two lines at each location.
    // - Out: Text and bound button pointer are set.
    QPushButton* makeButton(QWidget* parent, const char* key, const char* label)
    {
        QPushButton* button = new QPushButton(uiText(key, label), parent);
        bindUiText(button, key, label);
        return button;
    }

    // makeGroup：
    // - Purpose: Create a group box and complete language binding.
    QGroupBox* makeGroup(QWidget* parent, const char* key, const char* label)
    {
        QGroupBox* group = new QGroupBox(uiText(key, label), parent);
        bindUiText(group, key, label);
        return group;
    }

    // makeLabel：
    // - Purpose: Create static text labels and complete language binding.
    QLabel* makeLabel(QWidget* parent, const char* key, const char* label)
    {
        QLabel* widget = new QLabel(uiText(key, label), parent);
        bindUiText(widget, key, label);
        return widget;
    }

    // hwndText: Format a window handle as uppercase hexadecimal text.
    QString hwndText(HWND hwnd)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(reinterpret_cast<quintptr>(hwnd)), 0, 16)
            .toUpper();
    }

    // hexText: Format an unsigned integer as uppercase hexadecimal text.
    QString hexText(quint64 value)
    {
        return QStringLiteral("0x%1").arg(value, 0, 16).toUpper();
    }

    // rectText: Formats a RECT as [l,t,r,b] and dimensions.
    QString rectText(const RECT& rect)
    {
        return QStringLiteral("[%1,%2,%3,%4] %5x%6")
            .arg(rect.left).arg(rect.top).arg(rect.right).arg(rect.bottom)
            .arg(rect.right - rect.left).arg(rect.bottom - rect.top);
    }

    // windowsBuild：
    // - Purpose: Use RtlGetVersion to read the actual build number, bypassing version misreporting caused by the compatibility manifest.
    // - Output: Build number; returns 0 if unavailable.
    DWORD windowsBuild()
    {
        static const DWORD kBuildNumber = []() -> DWORD {
            using RtlGetVersionFunction = LONG(WINAPI*)(OSVERSIONINFOW*);
            const HMODULE kNtdllModuleHandle = ::GetModuleHandleW(L"ntdll.dll");
            if (kNtdllModuleHandle == nullptr)
            {
                return 0;
            }
            const auto kRtlGetVersion = reinterpret_cast<RtlGetVersionFunction>(
                ::GetProcAddress(kNtdllModuleHandle, "RtlGetVersion"));
            if (kRtlGetVersion == nullptr)
            {
                return 0;
            }
            OSVERSIONINFOW versionInfo{};
            versionInfo.dwOSVersionInfoSize = sizeof(versionInfo);
            return kRtlGetVersion(&versionInfo) == 0 ? versionInfo.dwBuildNumber : 0;
        }();
        return kBuildNumber;
    }

    // darkModeAttribute：
    // - Purpose: Use value 19 for dark title bars between build 1809 and 1903, switch to 20 thereafter; select based on build number.
    // - Output: Attribute ID to use for the current system.
    DWORD darkModeAttribute()
    {
        const DWORD kBuild = windowsBuild();
        return (kBuild != 0 && kBuild < kBuildWin10DarkNew) ? kAttrImmersiveDarkModeLegacy : kAttrImmersiveDarkMode;
    }

    // hresultText：
    // - Purpose: Convert HRESULT to 'hex + common semantic explanation' for diagnosable failures;
    // - Input result: the return value of the DWM call;
    // - Output: short text suitable for status bar and logs.
    QString hresultText(HRESULT result)
    {
        if (SUCCEEDED(result))
        {
            return QStringLiteral("S_OK");
        }

        QString explanation;
        switch (static_cast<unsigned long>(result))
        {
        case 0x80070057ul:
            explanation = uiText("window.dwm.hr.invalid_arg", "当前系统不支持该属性，或数据长度不匹配");
            break;
        case 0x80070006ul:
            explanation = uiText("window.dwm.hr.invalid_handle", "窗口句柄无效或已销毁");
            break;
        case 0x80070005ul:
            explanation = uiText("window.dwm.hr.access_denied",
                "访问被拒绝：该属性只允许窗口所属进程设置，或目标完整性级别更高");
            break;
        case 0x80263001ul:
            explanation = uiText("window.dwm.hr.composition_disabled", "桌面窗口管理器合成当前处于关闭状态");
            break;
        case 0x80263002ul:
            explanation = uiText("window.dwm.hr.remoting", "远程会话不支持该合成能力");
            break;
        case 0x800706BAul:
            explanation = uiText("window.dwm.hr.rpc_unavailable", "DWM 服务不可用");
            break;
        case 0x80004001ul:
            explanation = uiText("window.dwm.hr.not_impl", "该接口在当前系统上未实现");
            break;
        default:
            break;
        }

        const QString kCode = hexText(static_cast<quint64>(static_cast<quint32>(result)));
        return explanation.isEmpty() ? kCode : QStringLiteral("%1 (%2)").arg(kCode, explanation);
    }

    // ============ DWM Read/Write Wrapper ============

    // DwordResult: complete result of a 4-byte property read.
    struct DwordResult
    {
        bool ok = false;              // ok: Whether HRESULT succeeded.
        HRESULT hr = S_OK;            // hr: Original return value.
        DWORD value = 0;              // value: read attribute value.
    };

    // readDwordAttribute：
    // - Purpose: Read a 4-byte DWMWA_* attribute.
    // - Input hwnd/attribute: target window and attribute ID.
    // - Out: DwordResult; on failure, ok=false and HRESULT is preserved.
    DwordResult readDwordAttribute(HWND hwnd, DWORD attribute)
    {
        DwordResult result;
        DWORD value = 0;
        result.hr = ::DwmGetWindowAttribute(hwnd, attribute, &value, sizeof(value));
        result.ok = SUCCEEDED(result.hr);
        result.value = result.ok ? value : 0;
        return result;
    }

    // writeDwordAttribute：
    // - Purpose: Write a 4-byte DWMWA_* attribute.
    // - Output: HRESULT returned by DWM; caller is responsible for displaying it.
    HRESULT writeDwordAttribute(HWND hwnd, DWORD attribute, DWORD value)
    {
        return ::DwmSetWindowAttribute(hwnd, attribute, &value, sizeof(value));
    }

    // RectResult: complete result of a single RECT attribute read.
    struct RectResult
    {
        bool ok = false;
        HRESULT hr = S_OK;
        RECT value{};
    };

    // readRectAttribute: Reads read-only RECT attributes (border rectangle, title button area).
    RectResult readRectAttribute(HWND hwnd, DWORD attribute)
    {
        RectResult result;
        RECT value{};
        result.hr = ::DwmGetWindowAttribute(hwnd, attribute, &value, sizeof(value));
        result.ok = SUCCEEDED(result.hr);
        result.value = result.ok ? value : RECT{};
        return result;
    }

    // resolveSetWindowCompositionAttribute：
    // - Purpose: Resolve the undocumented SetWindowCompositionAttribute in user32.
    // - Out: Function pointer; returns nullptr if the system does not provide it.
    using SetWindowCompositionAttributeFunction = BOOL(WINAPI*)(HWND, void*);
    SetWindowCompositionAttributeFunction resolveSetWindowCompositionAttribute()
    {
        static const SetWindowCompositionAttributeFunction kFunction =
            []() -> SetWindowCompositionAttributeFunction {
                const HMODULE kUser32ModuleHandle = ::GetModuleHandleW(L"user32.dll");
                if (kUser32ModuleHandle == nullptr)
                {
                    return nullptr;
                }
                return reinterpret_cast<SetWindowCompositionAttributeFunction>(
                    ::GetProcAddress(kUser32ModuleHandle, "SetWindowCompositionAttribute"));
            }();
        return kFunction;
    }

    // ============ Property Row Specification ============

    // RowKind purpose: determines which edit control to use for the attribute row.
    enum class RowKind
    {
        kBoolean,   // Boolean property: dropdown selection of TRUE/FALSE.
        kEnumerated,// Enumerated property: dropdown selection with named values.
        kColor      // Color scheme attributes: default, none, or custom modes.
    };

    // EnumOption purpose: A candidate option for an enumeration property.
    struct EnumOption
    {
        DWORD value = 0;         // value: Raw value written to DWM.
        const char* key = "";    // key: Language pack semantic key.
        const char* label = "";  // label: Chinese fallback text.
    };

    // RowSpec purpose: Describes all static information for a controllable DWM attribute.
    struct RowSpec
    {
        DWORD attribute = 0;              // attribute: DWMWA_* identifier.
        const char* apiName = "";         // apiName: Win32 constant name, mapped directly to documentation.
        const char* tipKey = "";          // tipKey: Semantic key for the description text.
        const char* tip = "";             // tip: fallback Chinese description text.
        RowKind kind = RowKind::kBoolean;  // kind: Control type.
        DWORD minimumBuild = 0;           // minimumBuild: Build number introduced by the official release; 0 indicates availability starting from Vista.
        bool destructive = false;         // destructive: Whether a secondary confirmation is required (e.g., window disappearance).
        std::vector<EnumOption> options;  // options: Enumerated candidate options.
    };

    // booleanRowSpecs：
    // - Purpose: Return the specification table for all boolean DWM properties.
    // - Note: The attribute ID for the dark title bar is determined at runtime based on the build number; this is a placeholder for now.
    const std::vector<RowSpec>& booleanRowSpecs()
    {
        static const std::vector<RowSpec> kSpecs = {
            { kAttrTransitionsForceDisabled, "DWMWA_TRANSITIONS_FORCEDISABLED",
              "window.dwm.attr.transitions", "强制关闭该窗口的最小化/最大化等过渡动画。",
              RowKind::kBoolean, 0, false, {} },
            { kAttrAllowNcPaint, "DWMWA_ALLOW_NCPAINT",
              "window.dwm.attr.allow_ncpaint", "允许窗口自己在非客户区绘制，通常配合自绘标题栏使用。",
              RowKind::kBoolean, 0, false, {} },
            { kAttrNonClientRtlLayout, "DWMWA_NONCLIENT_RTL_LAYOUT",
              "window.dwm.attr.rtl_layout", "把非客户区改为从右到左布局，标题栏按钮会镜像到左侧。",
              RowKind::kBoolean, 0, false, {} },
            { kAttrForceIconicRepresentation, "DWMWA_FORCE_ICONIC_REPRESENTATION",
              "window.dwm.attr.force_iconic", "强制任务栏使用窗口提供的静态缩略图，而不是实时画面。",
              RowKind::kBoolean, 0, false, {} },
            { kAttrHasIconicBitmap, "DWMWA_HAS_ICONIC_BITMAP",
              "window.dwm.attr.has_iconic_bitmap", "声明窗口会提供 iconic 位图，需与强制静态缩略图配合。",
              RowKind::kBoolean, 0, false, {} },
            { kAttrDisallowPeek, "DWMWA_DISALLOW_PEEK",
              "window.dwm.attr.disallow_peek", "禁止在该窗口上触发 Aero Peek 桌面透视。",
              RowKind::kBoolean, 0, false, {} },
            { kAttrExcludedFromPeek, "DWMWA_EXCLUDED_FROM_PEEK",
              "window.dwm.attr.excluded_from_peek", "执行桌面透视时把该窗口一并隐藏。",
              RowKind::kBoolean, 0, false, {} },
            { kAttrFreezeRepresentation, "DWMWA_FREEZE_REPRESENTATION",
              "window.dwm.attr.freeze_representation", "冻结缩略图内容，窗口后续变化不再反映到预览。",
              RowKind::kBoolean, 0, false, {} },
            { kAttrPassiveUpdateMode, "DWMWA_PASSIVE_UPDATE_MODE",
              "window.dwm.attr.passive_update", "被动更新模式：DWM 只在窗口重绘时同步内容。",
              RowKind::kBoolean, kBuildWin11, false, {} },
            { kAttrUseHostBackdropBrush, "DWMWA_USE_HOSTBACKDROPBRUSH",
              "window.dwm.attr.host_backdrop", "使用宿主背景画刷，让分层子窗口获得亚克力底色。",
              RowKind::kBoolean, kBuildWin11, false, {} },
            { kAttrImmersiveDarkMode, "DWMWA_USE_IMMERSIVE_DARK_MODE",
              "window.dwm.attr.dark_mode", "把系统标题栏切换为暗色。1809~1903 使用旧编号 19，本页已按构建号自动选择。",
              RowKind::kBoolean, kBuildWin10Dark, false, {} },
            { kAttrCloak, "DWMWA_CLOAK",
              "window.dwm.attr.cloak",
              "对 DWM 隐藏窗口：窗口仍然存在且可交互，但不再被合成显示。"
              "实测 DWM 只允许进程隐藏自己的窗口，对其他进程的窗口会返回 E_ACCESSDENIED。",
              RowKind::kBoolean, 0, true, {} },
        };
        return kSpecs;
    }

    // enumeratedRowSpecs: Returns the specification table for all enumerated DWM properties.
    const std::vector<RowSpec>& enumeratedRowSpecs()
    {
        static const std::vector<RowSpec> kSpecs = {
            { kAttrNcRenderingPolicy, "DWMWA_NCRENDERING_POLICY",
              "window.dwm.attr.nc_policy", "决定非客户区是否交给 DWM 渲染，关闭后窗口会退回经典边框。",
              RowKind::kEnumerated, 0, false,
              {
                  { 0, "window.dwm.enum.ncrp_usewindowstyle", "DWMNCRP_USEWINDOWSTYLE (随窗口样式)" },
                  { 1, "window.dwm.enum.ncrp_disabled", "DWMNCRP_DISABLED (禁用 DWM 渲染)" },
                  { 2, "window.dwm.enum.ncrp_enabled", "DWMNCRP_ENABLED (启用 DWM 渲染)" },
              } },
            { kAttrFlip3DPolicy, "DWMWA_FLIP3D_POLICY",
              "window.dwm.attr.flip3d", "Flip3D 切换器中该窗口的排布策略，Win8 之后大多无实际效果。",
              RowKind::kEnumerated, 0, false,
              {
                  { 0, "window.dwm.enum.flip3d_default", "DWMFLIP3D_DEFAULT (默认)" },
                  { 1, "window.dwm.enum.flip3d_excludebelow", "DWMFLIP3D_EXCLUDEBELOW (排在下方)" },
                  { 2, "window.dwm.enum.flip3d_excludeabove", "DWMFLIP3D_EXCLUDEABOVE (排在上方)" },
              } },
            { kAttrWindowCornerPreference, "DWMWA_WINDOW_CORNER_PREFERENCE",
              "window.dwm.attr.corner", "Windows 11 窗口圆角策略，可强制直角或小圆角。",
              RowKind::kEnumerated, kBuildWin11, false,
              {
                  { 0, "window.dwm.enum.corner_default", "DWMWCP_DEFAULT (系统决定)" },
                  { 1, "window.dwm.enum.corner_donotround", "DWMWCP_DONOTROUND (直角)" },
                  { 2, "window.dwm.enum.corner_round", "DWMWCP_ROUND (标准圆角)" },
                  { 3, "window.dwm.enum.corner_roundsmall", "DWMWCP_ROUNDSMALL (小圆角)" },
              } },
            { kAttrSystemBackdropType, "DWMWA_SYSTEMBACKDROP_TYPE",
              "window.dwm.attr.backdrop", "Windows 11 22H2 背景材质。目标窗口客户区必须允许透出，否则只有边框区域可见。",
              RowKind::kEnumerated, kBuildWin1122H2, false,
              {
                  { 0, "window.dwm.enum.backdrop_auto", "DWMSBT_AUTO (系统决定)" },
                  { 1, "window.dwm.enum.backdrop_none", "DWMSBT_NONE (无材质)" },
                  { 2, "window.dwm.enum.backdrop_mainwindow", "DWMSBT_MAINWINDOW (云母 Mica)" },
                  { 3, "window.dwm.enum.backdrop_transient", "DWMSBT_TRANSIENTWINDOW (亚克力 Acrylic)" },
                  { 4, "window.dwm.enum.backdrop_tabbed", "DWMSBT_TABBEDWINDOW (云母替代 Mica Alt)" },
              } },
        };
        return kSpecs;
    }

    // colorRowSpecs: Returns the specification table for all color-themed DWM properties.
    const std::vector<RowSpec>& colorRowSpecs()
    {
        static const std::vector<RowSpec> kSpecs = {
            { kAttrBorderColor, "DWMWA_BORDER_COLOR",
              "window.dwm.attr.border_color", "窗口外边框颜色。选择“无”可让边框完全不绘制。",
              RowKind::kColor, kBuildWin11, false, {} },
            { kAttrCaptionColor, "DWMWA_CAPTION_COLOR",
              "window.dwm.attr.caption_color", "系统标题栏背景色，仅对使用原生标题栏的窗口有效。",
              RowKind::kColor, kBuildWin11, false, {} },
            { kAttrTextColor, "DWMWA_TEXT_COLOR",
              "window.dwm.attr.text_color", "系统标题栏文字颜色，建议与标题栏背景色一起设置以保证对比度。",
              RowKind::kColor, kBuildWin11, false, {} },
        };
        return kSpecs;
    }

    // AttributeRow purpose: runtime state of a single attribute on the UI (control pointer and current selected color).
    struct AttributeRow
    {
        RowSpec spec;                        // spec: static specification.
        QComboBox* valueCombo = nullptr;     // valueCombo: Value selection control.
        QPushButton* colorButton = nullptr;  // colorButton: Color picker button for color scheme properties.
        QLabel* statusLabel = nullptr;       // statusLabel: Displays the returned value and HRESULT.
        QColor customColor{ 0, 120, 215 };   // customColor: Custom color for the color scheme property.
        bool touched = false;                // touched: Whether this property has been written on this page, used for restoring defaults.
    };

    // ============ DWM Control Page ============

    class Page final : public QWidget
    {
    public:
        // Constructor:
        // - Purpose: Lock the target window, construct the UI, and perform a full read.
        // - target: the window handle to check; parent: the Qt parent widget.
        explicit Page(HWND target, QWidget* parent = nullptr)
            : QWidget(parent)
            , target_(target)
        {
            buildUi();
            readAllAttributes(false);
            refreshDiagnostics();

            thumbnailTimer_ = new QTimer(this);
            thumbnailTimer_->setInterval(kThumbnailRefreshMs);
            connect(thumbnailTimer_, &QTimer::timeout, this, [this]() {
                updateThumbnailPlacement();
            });
        }

        // Destructor:
        // - Purpose: Unregister DWM thumbnails to prevent residual handles on the DWM side.
        ~Page() override
        {
            releaseThumbnail();
        }

    protected:
        // showEvent: Register thumbnails only when the page is visible to avoid wasting DWM resources in the background.
        void showEvent(QShowEvent* event) override
        {
            QWidget::showEvent(event);
            if (thumbnailEnableCheck_ != nullptr && thumbnailEnableCheck_->isChecked())
            {
                ensureThumbnail();
            }
            if (thumbnailTimer_ != nullptr)
            {
                thumbnailTimer_->start();
            }
            updateThumbnailPlacement();
        }

        // hideEvent: Immediately collapse thumbnails when the page is hidden (switching tabs or closing).
        void hideEvent(QHideEvent* event) override
        {
            QWidget::hideEvent(event);
            if (thumbnailTimer_ != nullptr)
            {
                thumbnailTimer_->stop();
            }
            updateThumbnailPlacement();
        }

        // resizeEvent: Size changes alter the thumbnail target rectangle, requiring immediate synchronization.
        void resizeEvent(QResizeEvent* event) override
        {
            QWidget::resizeEvent(event);
            updateThumbnailPlacement();
        }

    private:
        // ---------- UI Construction ----------

        // buildUi：
        // - Purpose: Build the overall layout with 'left-side property controls + right-side real-time preview and logs';
        // - Invocation: Only once in the constructor.
        void buildUi()
        {
            QVBoxLayout* rootLayout = new QVBoxLayout(this);
            rootLayout->setContentsMargins(8, 8, 8, 8);
            rootLayout->setSpacing(6);

            rootLayout->addLayout(buildHeaderRow());

            QSplitter* splitter = new QSplitter(Qt::Horizontal, this);
            splitter->addWidget(buildControlSide(splitter));
            splitter->addWidget(buildPreviewSide(splitter));
            splitter->setStretchFactor(0, 3);
            splitter->setStretchFactor(1, 2);
            rootLayout->addWidget(splitter, 1);
        }

        // buildHeaderRow：
        // - Purpose: Build the top information bar (target handle, system build number, global action buttons);
        // - Output: a horizontal layout that can be directly added to the root layout.
        QHBoxLayout* buildHeaderRow()
        {
            QHBoxLayout* headerLayout = new QHBoxLayout();

            QLabel* targetLabel = new QLabel(
                uiText("window.dwm.header.target", "目标 HWND: %1    系统构建号: %2")
                    .arg(hwndText(target_))
                    .arg(windowsBuild() == 0
                        ? uiText("window.dwm.header.build_unknown", "未知")
                        : QString::number(windowsBuild())),
                this);
            targetLabel->setWordWrap(true);
            headerLayout->addWidget(targetLabel, 1);

            frameChangeCheck_ = new QCheckBox(
                uiText("window.dwm.header.force_frame_change", "写入后强制重算边框"), this);
            frameChangeCheck_->setChecked(true);
            frameChangeCheck_->setToolTip(uiText(
                "window.dwm.header.force_frame_change_tip",
                "部分属性只有在窗口重新计算非客户区之后才会显示出来；使用异步 SetWindowPos，不会因目标线程卡死而挂起本程序。"));
            bindUiText(frameChangeCheck_, "window.dwm.header.force_frame_change", "写入后强制重算边框");
            headerLayout->addWidget(frameChangeCheck_, 0);

            QPushButton* readAllButton = makeButton(this, "window.dwm.action.read_all", "读取全部");
            QPushButton* restoreButton = makeButton(this, "window.dwm.action.restore_default", "恢复系统默认");
            QPushButton* copyButton = makeButton(this, "window.dwm.action.copy_report", "复制报告");
            QPushButton* exportButton = makeButton(this, "window.dwm.action.export_report", "导出报告");
            headerLayout->addWidget(readAllButton, 0);
            headerLayout->addWidget(restoreButton, 0);
            headerLayout->addWidget(copyButton, 0);
            headerLayout->addWidget(exportButton, 0);

            connect(readAllButton, &QPushButton::clicked, this, [this]() {
                readAllAttributes(true);
                refreshDiagnostics();
            });
            connect(restoreButton, &QPushButton::clicked, this, [this]() {
                restoreSystemDefaults();
            });
            connect(copyButton, &QPushButton::clicked, this, [this]() {
                QApplication::clipboard()->setText(buildReportText());
                appendLog(uiText("window.dwm.log.report_copied", "报告已复制到剪贴板。"));
            });
            connect(exportButton, &QPushButton::clicked, this, [this]() {
                exportReport();
            });

            return headerLayout;
        }

        // buildControlSide：
        // - Purpose: Build the left scroll area to contain all property groups.
        // - Output: Scroll area widget that can be added to the splitter.
        QWidget* buildControlSide(QWidget* parent)
        {
            QScrollArea* scrollArea = new QScrollArea(parent);
            scrollArea->setWidgetResizable(true);

            QWidget* container = new QWidget(scrollArea);
            QVBoxLayout* containerLayout = new QVBoxLayout(container);
            containerLayout->setContentsMargins(0, 0, 0, 0);
            containerLayout->setSpacing(8);

            containerLayout->addWidget(buildPresetGroup(container));
            containerLayout->addWidget(buildEnumeratedGroup(container));
            containerLayout->addWidget(buildColorGroup(container));
            containerLayout->addWidget(buildBooleanGroup(container));
            containerLayout->addWidget(buildFrameGroup(container));
            containerLayout->addWidget(buildAccentGroup(container));
            containerLayout->addStretch(1);

            scrollArea->setWidget(container);
            return scrollArea;
        }

        // buildPresetGroup：
        // - Purpose: Provides one-click presets for common combinations to reduce the operational cost of setting items one by one.
        QGroupBox* buildPresetGroup(QWidget* parent)
        {
            QGroupBox* group = makeGroup(parent, "window.dwm.group.preset", "一键预设");
            QHBoxLayout* layout = new QHBoxLayout(group);

            presetCombo_ = new QComboBox(group);
            presetCombo_->addItem(uiText("window.dwm.preset.dark_round", "暗色标题栏 + 标准圆角"));
            presetCombo_->addItem(uiText("window.dwm.preset.square", "强制直角、无边框色"));
            presetCombo_->addItem(uiText("window.dwm.preset.mica", "云母背景 + 暗色标题栏"));
            presetCombo_->addItem(uiText("window.dwm.preset.acrylic", "亚克力背景 + 系统圆角"));
            presetCombo_->addItem(uiText("window.dwm.preset.no_animation", "关闭过渡动画并排除桌面透视"));
            layout->addWidget(presetCombo_, 1);

            QPushButton* applyButton = makeButton(group, "window.dwm.action.apply_preset", "应用预设");
            layout->addWidget(applyButton, 0);
            connect(applyButton, &QPushButton::clicked, this, [this]() {
                applySelectedPreset();
            });
            return group;
        }

        // buildEnumeratedGroup / buildColorGroup / buildBooleanGroup：
        // - Purpose: Arrange three grids by attribute category, with one attribute per row;
        // - Note: All three share appendAttributeRow with identical behavior.
        QGroupBox* buildEnumeratedGroup(QWidget* parent)
        {
            QGroupBox* group = makeGroup(parent, "window.dwm.group.enum", "枚举属性（渲染策略 / 圆角 / 背景材质）");
            QGridLayout* grid = new QGridLayout(group);
            grid->setHorizontalSpacing(8);
            grid->setVerticalSpacing(4);
            for (const RowSpec& spec : enumeratedRowSpecs())
            {
                appendAttributeRow(group, grid, spec);
            }
            return group;
        }

        QGroupBox* buildColorGroup(QWidget* parent)
        {
            QGroupBox* group = makeGroup(parent, "window.dwm.group.color", "配色属性（边框 / 标题栏 / 标题文字）");
            QGridLayout* grid = new QGridLayout(group);
            grid->setHorizontalSpacing(8);
            grid->setVerticalSpacing(4);
            for (const RowSpec& spec : colorRowSpecs())
            {
                appendAttributeRow(group, grid, spec);
            }
            return group;
        }

        QGroupBox* buildBooleanGroup(QWidget* parent)
        {
            QGroupBox* group = makeGroup(parent, "window.dwm.group.boolean", "布尔属性（动画 / 缩略图 / 透视 / 隐藏）");
            QGridLayout* grid = new QGridLayout(group);
            grid->setHorizontalSpacing(8);
            grid->setVerticalSpacing(4);
            for (const RowSpec& spec : booleanRowSpecs())
            {
                appendAttributeRow(group, grid, spec);
            }
            return group;
        }

        // appendAttributeRow：
        // - Purpose: Instantiate a property specification as a row in the UI and register it in m_rows.
        // - Inputs group/grid: host group and grid; input spec: static attribute specification;
        void appendAttributeRow(QGroupBox* group, QGridLayout* grid, const RowSpec& spec)
        {
            const int kRowIndex = grid->rowCount();
            const std::size_t kRowSlot = rows_.size();
            rows_.push_back(AttributeRow{ spec, nullptr, nullptr, nullptr, QColor(0, 120, 215), false });
            AttributeRow& row = rows_.back();

            // Note: The attribute name column displays Win32 constant names directly for easy one-to-one comparison with Microsoft documentation.
            QLabel* nameLabel = new QLabel(
                QStringLiteral("%1 (%2)").arg(QString::fromLatin1(spec.apiName)).arg(spec.attribute), group);
            nameLabel->setToolTip(buildRowTip(spec));
            grid->addWidget(nameLabel, kRowIndex, 0);

            row.valueCombo = new QComboBox(group);
            row.valueCombo->setToolTip(buildRowTip(spec));
            if (spec.kind == RowKind::kBoolean)
            {
                row.valueCombo->addItem(uiText("window.dwm.value.true", "TRUE (1)"), QVariant(1u));
                row.valueCombo->addItem(uiText("window.dwm.value.false", "FALSE (0)"), QVariant(0u));
            }
            else if (spec.kind == RowKind::kEnumerated)
            {
                for (const EnumOption& option : spec.options)
                {
                    // DWORD is unsigned long; QVariant has no corresponding overload, so it must be narrowed to uint first.
                    row.valueCombo->addItem(
                        uiText(option.key, option.label), QVariant(static_cast<uint>(option.value)));
                }
            }
            else
            {
                row.valueCombo->addItem(
                    uiText("window.dwm.color.default", "系统默认"), QVariant(static_cast<uint>(kColorDefault)));
                row.valueCombo->addItem(
                    uiText("window.dwm.color.none", "无（不绘制）"), QVariant(static_cast<uint>(kColorNone)));
                row.valueCombo->addItem(uiText("window.dwm.color.custom", "自定义颜色"), QVariant(0u));
            }

            QWidget* valueHost = row.valueCombo;
            if (spec.kind == RowKind::kColor)
            {
                // The color row requires a color picker button next to the dropdown, so a container wrapper is added.
                QWidget* colorHost = new QWidget(group);
                QHBoxLayout* colorLayout = new QHBoxLayout(colorHost);
                colorLayout->setContentsMargins(0, 0, 0, 0);
                colorLayout->setSpacing(4);
                row.colorButton = new QPushButton(colorHost);
                row.colorButton->setFixedWidth(52);
                colorLayout->addWidget(row.valueCombo, 1);
                colorLayout->addWidget(row.colorButton, 0);
                valueHost = colorHost;

                updateColorButton(row);
                connect(row.colorButton, &QPushButton::clicked, this, [this, kRowSlot]() {
                    AttributeRow& target = rows_[kRowSlot];
                    const QColor kPicked = QColorDialog::getColor(
                        target.customColor,
                        this,
                        uiText("window.dwm.color.dialog_title", "选择 DWM 配色"));
                    if (!kPicked.isValid())
                    {
                        return;
                    }
                    target.customColor = kPicked;
                    updateColorButton(target);
                    // Automatically switch to custom mode after color selection to avoid user confusion that the setting didn't take effect.
                    target.valueCombo->setCurrentIndex(2);
                });
            }
            grid->addWidget(valueHost, kRowIndex, 1);

            QPushButton* readButton = makeButton(group, "window.dwm.action.read", "读取");
            QPushButton* writeButton = makeButton(group, "window.dwm.action.write", "写入");
            readButton->setFixedWidth(56);
            writeButton->setFixedWidth(56);
            grid->addWidget(readButton, kRowIndex, 2);
            grid->addWidget(writeButton, kRowIndex, 3);

            row.statusLabel = new QLabel(uiText("window.dwm.status.unread", "未读取"), group);
            row.statusLabel->setWordWrap(true);
            grid->addWidget(row.statusLabel, kRowIndex, 4);
            grid->setColumnStretch(4, 1);

            connect(readButton, &QPushButton::clicked, this, [this, kRowSlot]() {
                readAttributeRow(rows_[kRowSlot], true);
            });
            connect(writeButton, &QPushButton::clicked, this, [this, kRowSlot]() {
                writeAttributeRow(rows_[kRowSlot]);
            });
        }

        // buildRowTip：
        // - Purpose: Concatenate attribute descriptions with a 'current system may not support' warning.
        // - Out: Control ToolTip text.
        QString buildRowTip(const RowSpec& spec) const
        {
            QString tip = uiText(spec.tipKey, spec.tip);
            const DWORD kBuild = windowsBuild();
            if (spec.minimumBuild != 0 && kBuild != 0 && kBuild < spec.minimumBuild)
            {
                tip += QChar::LineFeed;
                tip += uiText("window.dwm.tip.build_required", "该属性需要构建号 %1 及以上，当前系统为 %2，调用大概率返回 E_INVALIDARG。")
                    .arg(spec.minimumBuild)
                    .arg(kBuild);
            }
            if (spec.destructive)
            {
                tip += QChar::LineFeed;
                tip += uiText("window.dwm.tip.destructive", "该操作会改变窗口的可见性，写入前会要求确认。");
            }
            return tip;
        }

        // buildFrameGroup：
        // - Purpose: Build the "Frame Extension and Blur" group (DwmExtendFrameIntoClientArea / DwmEnableBlurBehindWindow).
        QGroupBox* buildFrameGroup(QWidget* parent)
        {
            QGroupBox* group = makeGroup(
                parent, "window.dwm.group.frame", "框架扩展、模糊与过渡");
            QGridLayout* grid = new QGridLayout(group);
            grid->setHorizontalSpacing(8);
            grid->setVerticalSpacing(4);

            QLabel* marginHint = makeLabel(
                group, "window.dwm.frame.margin_hint",
                "DwmExtendFrameIntoClientArea 把玻璃边框向客户区延伸，四个边距填 -1 表示整窗玻璃。");
            marginHint->setWordWrap(true);
            grid->addWidget(marginHint, 0, 0, 1, 5);

            // Semantic keys and their corresponding text are written as pairs: i18n extraction identifies them as adjacent string literals; splitting them into two arrays would cause misalignment.
            struct MarginField
            {
                const char* key;
                const char* label;
            };
            const std::array<MarginField, 4> kMarginFields{ {
                { "window.dwm.frame.left", "左" },
                { "window.dwm.frame.top", "上" },
                { "window.dwm.frame.right", "右" },
                { "window.dwm.frame.bottom", "下" },
            } };
            for (int index = 0; index < 4; ++index)
            {
                grid->addWidget(
                    makeLabel(group, kMarginFields[index].key, kMarginFields[index].label), 1, index);
                marginSpins_[index] = new QSpinBox(group);
                marginSpins_[index]->setRange(-1, 4096);
                marginSpins_[index]->setValue(0);
                grid->addWidget(marginSpins_[index], 2, index);
            }

            QPushButton* applyMarginButton = makeButton(group, "window.dwm.action.apply_margin", "应用边距");
            QPushButton* fullGlassButton = makeButton(group, "window.dwm.action.full_glass", "整窗玻璃");
            QPushButton* resetMarginButton = makeButton(group, "window.dwm.action.reset_margin", "重置边距");
            grid->addWidget(applyMarginButton, 2, 4);
            grid->addWidget(fullGlassButton, 3, 4);

            QHBoxLayout* blurLayout = new QHBoxLayout();
            blurTransitionCheck_ = new QCheckBox(
                uiText("window.dwm.frame.blur_transition", "最大化时过渡"), group);
            bindUiText(blurTransitionCheck_, "window.dwm.frame.blur_transition", "最大化时过渡");
            QPushButton* blurOnButton = makeButton(group, "window.dwm.action.blur_on", "启用模糊");
            QPushButton* blurOffButton = makeButton(group, "window.dwm.action.blur_off", "关闭模糊");
            blurLayout->addWidget(blurTransitionCheck_, 0);
            blurLayout->addWidget(blurOnButton, 0);
            blurLayout->addWidget(blurOffButton, 0);
            blurLayout->addWidget(resetMarginButton, 0);
            blurLayout->addStretch(1);
            grid->addLayout(blurLayout, 3, 0, 1, 4);

            QHBoxLayout* transitionLayout = new QHBoxLayout();
            QPushButton* invalidateIconicButton =
                makeButton(group, "window.dwm.action.invalidate_iconic", "作废静态缩略图缓存");
            invalidateIconicButton->setToolTip(uiText(
                "window.dwm.action.invalidate_iconic_tip",
                "DwmInvalidateIconicBitmaps：丢弃 DWM 为该窗口缓存的静态缩略图与实时预览位图，强制下次重新采集。"
                "实测仅对本进程窗口有效，跨进程调用返回 E_INVALIDARG。"));
            QPushButton* transitionOwnedButton =
                makeButton(group, "window.dwm.action.transition_owned", "触发属主窗口重定位过渡");
            transitionOwnedButton->setToolTip(uiText(
                "window.dwm.action.transition_owned_tip",
                "DwmTransitionOwnedWindow：让 DWM 对该窗口播放一次 REPOSITION 过渡动画，可用于验证过渡是否被禁用。"
                "实测仅对本进程窗口有效，跨进程调用返回 E_INVALIDARG。"));
            transitionLayout->addWidget(invalidateIconicButton, 0);
            transitionLayout->addWidget(transitionOwnedButton, 0);
            transitionLayout->addStretch(1);
            grid->addLayout(transitionLayout, 4, 0, 1, 5);

            connect(invalidateIconicButton, &QPushButton::clicked, this, [this]() {
                if (!targetAlive())
                {
                    return;
                }
                const HRESULT kResult = ::DwmInvalidateIconicBitmaps(target_);
                appendLog(uiText("window.dwm.log.invalidate_iconic", "DwmInvalidateIconicBitmaps → %1")
                    .arg(hresultText(kResult)));
            });
            connect(transitionOwnedButton, &QPushButton::clicked, this, [this]() {
                if (!targetAlive())
                {
                    return;
                }
                const HRESULT kResult =
                    ::DwmTransitionOwnedWindow(target_, DWMTRANSITION_OWNEDWINDOW_REPOSITION);
                appendLog(uiText("window.dwm.log.transition_owned", "DwmTransitionOwnedWindow(REPOSITION) → %1")
                    .arg(hresultText(kResult)));
            });

            connect(applyMarginButton, &QPushButton::clicked, this, [this]() {
                applyFrameMargins(
                    marginSpins_[0]->value(), marginSpins_[1]->value(),
                    marginSpins_[2]->value(), marginSpins_[3]->value());
            });
            connect(fullGlassButton, &QPushButton::clicked, this, [this]() {
                for (QSpinBox* spinBox : marginSpins_)
                {
                    spinBox->setValue(-1);
                }
                applyFrameMargins(-1, -1, -1, -1);
            });
            connect(resetMarginButton, &QPushButton::clicked, this, [this]() {
                for (QSpinBox* spinBox : marginSpins_)
                {
                    spinBox->setValue(0);
                }
                applyFrameMargins(0, 0, 0, 0);
            });
            connect(blurOnButton, &QPushButton::clicked, this, [this]() {
                applyBlurBehind(true);
            });
            connect(blurOffButton, &QPushButton::clicked, this, [this]() {
                applyBlurBehind(false);
            });
            return group;
        }

        // buildAccentGroup：
        // - Purpose: Build a control group for the undocumented SetWindowCompositionAttribute.
        // - Note: This is the channel that truly enables acrylic/blur effects on arbitrary windows starting from Windows 10.
        QGroupBox* buildAccentGroup(QWidget* parent)
        {
            QGroupBox* group = makeGroup(
                parent, "window.dwm.group.accent", "窗口合成特性（SetWindowCompositionAttribute，未公开接口）");
            QGridLayout* grid = new QGridLayout(group);
            grid->setHorizontalSpacing(8);
            grid->setVerticalSpacing(4);

            QLabel* accentHint = makeLabel(
                group, "window.dwm.accent.hint",
                "该接口未被微软文档化，不同版本行为存在差异；亚克力状态在部分版本会造成拖动窗口时卡顿。");
            accentHint->setWordWrap(true);
            grid->addWidget(accentHint, 0, 0, 1, 4);

            grid->addWidget(makeLabel(group, "window.dwm.accent.state", "合成状态"), 1, 0);
            accentStateCombo_ = new QComboBox(group);
            accentStateCombo_->addItem(uiText("window.dwm.accent.disabled", "ACCENT_DISABLED (关闭)"), QVariant(0u));
            accentStateCombo_->addItem(uiText("window.dwm.accent.gradient", "ACCENT_ENABLE_GRADIENT (纯色)"), QVariant(1u));
            accentStateCombo_->addItem(uiText("window.dwm.accent.transparent_gradient", "ACCENT_ENABLE_TRANSPARENTGRADIENT (半透明)"), QVariant(2u));
            accentStateCombo_->addItem(uiText("window.dwm.accent.blur", "ACCENT_ENABLE_BLURBEHIND (模糊)"), QVariant(3u));
            accentStateCombo_->addItem(uiText("window.dwm.accent.acrylic", "ACCENT_ENABLE_ACRYLICBLURBEHIND (亚克力)"), QVariant(4u));
            accentStateCombo_->addItem(uiText("window.dwm.accent.host_backdrop", "ACCENT_ENABLE_HOSTBACKDROP (宿主背景)"), QVariant(5u));
            accentStateCombo_->setCurrentIndex(4);
            grid->addWidget(accentStateCombo_, 1, 1, 1, 3);

            grid->addWidget(makeLabel(group, "window.dwm.accent.tint", "着色"), 2, 0);
            accentColorButton_ = new QPushButton(group);
            accentColorButton_->setFixedWidth(52);
            grid->addWidget(accentColorButton_, 2, 1);
            grid->addWidget(makeLabel(group, "window.dwm.accent.alpha", "透明度"), 2, 2);
            accentAlphaSlider_ = new QSlider(Qt::Horizontal, group);
            accentAlphaSlider_->setRange(0, 255);
            accentAlphaSlider_->setValue(160);
            grid->addWidget(accentAlphaSlider_, 2, 3);

            grid->addWidget(makeLabel(group, "window.dwm.accent.flags", "标志位"), 3, 0);
            accentFlagsSpin_ = new QSpinBox(group);
            accentFlagsSpin_->setRange(0, 0x7FFFFFFF);
            accentFlagsSpin_->setValue(2);
            accentFlagsSpin_->setToolTip(uiText(
                "window.dwm.accent.flags_tip",
                "常见取值：0 不绘制边框，2 绘制全部边框。该字段同样没有公开文档。"));
            grid->addWidget(accentFlagsSpin_, 3, 1);

            QPushButton* applyAccentButton = makeButton(group, "window.dwm.action.apply_accent", "应用合成特性");
            QPushButton* darkColorsOnButton = makeButton(group, "window.dwm.action.dark_colors_on", "启用暗色配色");
            QPushButton* darkColorsOffButton = makeButton(group, "window.dwm.action.dark_colors_off", "关闭暗色配色");
            grid->addWidget(applyAccentButton, 3, 2);
            grid->addWidget(darkColorsOnButton, 4, 2);
            grid->addWidget(darkColorsOffButton, 4, 3);

            accentStatusLabel_ = new QLabel(uiText("window.dwm.status.unread", "未读取"), group);
            accentStatusLabel_->setWordWrap(true);
            grid->addWidget(accentStatusLabel_, 4, 0, 1, 2);

            updateAccentColorButton();
            connect(accentColorButton_, &QPushButton::clicked, this, [this]() {
                const QColor kPicked = QColorDialog::getColor(
                    accentColor_, this, uiText("window.dwm.color.dialog_title", "选择 DWM 配色"));
                if (kPicked.isValid())
                {
                    accentColor_ = kPicked;
                    updateAccentColorButton();
                }
            });
            connect(applyAccentButton, &QPushButton::clicked, this, [this]() {
                applyAccentPolicy();
            });
            connect(darkColorsOnButton, &QPushButton::clicked, this, [this]() {
                applyDarkModeColors(true);
            });
            connect(darkColorsOffButton, &QPushButton::clicked, this, [this]() {
                applyDarkModeColors(false);
            });
            return group;
        }

        // buildPreviewSide：
        // - Purpose: Build the right-side panel with 'real-time thumbnails + composition diagnostics + operation logs'.
        QWidget* buildPreviewSide(QWidget* parent)
        {
            QWidget* container = new QWidget(parent);
            QVBoxLayout* layout = new QVBoxLayout(container);
            layout->setContentsMargins(0, 0, 0, 0);
            layout->setSpacing(6);

            QGroupBox* thumbnailGroup = makeGroup(container, "window.dwm.group.thumbnail", "实时缩略图（DWM Thumbnail）");
            QVBoxLayout* thumbnailLayout = new QVBoxLayout(thumbnailGroup);

            QHBoxLayout* thumbnailControlLayout = new QHBoxLayout();
            thumbnailEnableCheck_ = new QCheckBox(uiText("window.dwm.thumbnail.enable", "启用预览"), thumbnailGroup);
            bindUiText(thumbnailEnableCheck_, "window.dwm.thumbnail.enable", "启用预览");
            thumbnailClientOnlyCheck_ = new QCheckBox(
                uiText("window.dwm.thumbnail.client_only", "仅客户区"), thumbnailGroup);
            bindUiText(thumbnailClientOnlyCheck_, "window.dwm.thumbnail.client_only", "仅客户区");
            thumbnailOpacitySlider_ = new QSlider(Qt::Horizontal, thumbnailGroup);
            thumbnailOpacitySlider_->setRange(0, 255);
            thumbnailOpacitySlider_->setValue(255);
            thumbnailControlLayout->addWidget(thumbnailEnableCheck_, 0);
            thumbnailControlLayout->addWidget(thumbnailClientOnlyCheck_, 0);
            thumbnailControlLayout->addWidget(
                makeLabel(thumbnailGroup, "window.dwm.thumbnail.opacity", "不透明度"), 0);
            thumbnailControlLayout->addWidget(thumbnailOpacitySlider_, 1);
            thumbnailLayout->addLayout(thumbnailControlLayout);

            // Thumbnails are composited directly by DWM above this dialog; here we only reserve a bordered
            // placeholder area so users can see where the preview will appear even when it is closed.
            QFrame* thumbnailHost = new QFrame(thumbnailGroup);
            thumbnailHost->setFrameShape(QFrame::StyledPanel);
            thumbnailHost->setMinimumHeight(180);
            thumbnailHost->setAutoFillBackground(false);
            thumbnailHost_ = thumbnailHost;
            thumbnailLayout->addWidget(thumbnailHost_, 1);

            thumbnailStatusLabel_ = new QLabel(
                uiText("window.dwm.thumbnail.idle", "勾选“启用预览”后在此实时显示目标窗口画面。"), thumbnailGroup);
            thumbnailStatusLabel_->setWordWrap(true);
            thumbnailLayout->addWidget(thumbnailStatusLabel_, 0);
            layout->addWidget(thumbnailGroup, 0);

            // If the system monospace font lacks Chinese glyphs, it falls back to SimSun; explicitly append Microsoft YaHei for Chinese text.
            QFont fixedFont = QFontDatabase::systemFont(QFontDatabase::FixedFont);
            fixedFont.setFamilies(QStringList{ fixedFont.family(), QStringLiteral("Microsoft YaHei UI") });

            QGroupBox* diagnosticsGroup = makeGroup(container, "window.dwm.group.diagnostics", "合成诊断（只读）");
            QVBoxLayout* diagnosticsLayout = new QVBoxLayout(diagnosticsGroup);
            diagnosticsText_ = new QPlainTextEdit(diagnosticsGroup);
            diagnosticsText_->setReadOnly(true);
            diagnosticsText_->setLineWrapMode(QPlainTextEdit::NoWrap);
            diagnosticsText_->setFont(fixedFont);
            diagnosticsLayout->addWidget(diagnosticsText_, 1);
            QHBoxLayout* diagnosticsActionLayout = new QHBoxLayout();
            QPushButton* refreshDiagnosticsButton =
                makeButton(diagnosticsGroup, "window.dwm.action.refresh_diagnostics", "刷新诊断");
            QPushButton* flushButton = makeButton(diagnosticsGroup, "window.dwm.action.flush", "DwmFlush");
            diagnosticsActionLayout->addWidget(refreshDiagnosticsButton, 0);
            diagnosticsActionLayout->addWidget(flushButton, 0);
            diagnosticsActionLayout->addStretch(1);
            diagnosticsLayout->addLayout(diagnosticsActionLayout);
            layout->addWidget(diagnosticsGroup, 1);

            QGroupBox* logGroup = makeGroup(container, "window.dwm.group.log", "操作日志");
            QVBoxLayout* logLayout = new QVBoxLayout(logGroup);
            logText_ = new QPlainTextEdit(logGroup);
            logText_->setReadOnly(true);
            logText_->setLineWrapMode(QPlainTextEdit::NoWrap);
            logText_->setFont(fixedFont);
            logLayout->addWidget(logText_, 1);
            QPushButton* clearLogButton = makeButton(logGroup, "window.dwm.action.clear_log", "清空日志");
            logLayout->addWidget(clearLogButton, 0, Qt::AlignRight);
            layout->addWidget(logGroup, 1);

            connect(refreshDiagnosticsButton, &QPushButton::clicked, this, [this]() {
                refreshDiagnostics();
            });
            connect(flushButton, &QPushButton::clicked, this, [this]() {
                const HRESULT kResult = ::DwmFlush();
                appendLog(uiText("window.dwm.log.flush", "DwmFlush → %1").arg(hresultText(kResult)));
            });
            connect(clearLogButton, &QPushButton::clicked, this, [this]() {
                logText_->clear();
            });
            connect(thumbnailEnableCheck_, &QCheckBox::toggled, this, [this](bool checked) {
                if (checked)
                {
                    ensureThumbnail();
                }
                else
                {
                    releaseThumbnail();
                    thumbnailStatusLabel_->setText(uiText("window.dwm.thumbnail.idle", "勾选“启用预览”后在此实时显示目标窗口画面。"));
                }
                updateThumbnailPlacement();
            });
            connect(thumbnailClientOnlyCheck_, &QCheckBox::toggled, this, [this](bool) {
                updateThumbnailPlacement();
            });
            connect(thumbnailOpacitySlider_, &QSlider::valueChanged, this, [this](int) {
                updateThumbnailPlacement();
            });
            return container;
        }

        // ---------- Property Read/Write ----------

        // targetAlive：
        // - Purpose: Uniformly validate the handle before all write operations to avoid repeated calls on destroyed windows.
        // - Returns true if the handle is valid; otherwise, logs an error and returns false.
        bool targetAlive()
        {
            if (::IsWindow(target_) != FALSE)
            {
                return true;
            }
            appendLog(uiText("window.dwm.log.target_invalid", "目标 HWND 已失效，操作被跳过。"));
            return false;
        }

        // readAttributeRow：
        // - Purpose: Read a row of attributes and write the results back to the status label and value control.
        // - Passes row: target row; passes syncControl: whether to sync read-back values to the combo box;
        // - Out: returns true on success (read failure for write-only attributes is normal).
        bool readAttributeRow(AttributeRow& row, bool syncControl)
        {
            if (::IsWindow(target_) == FALSE)
            {
                row.statusLabel->setText(uiText("window.dwm.status.invalid_target", "目标窗口已失效"));
                return false;
            }

            const DWORD kAttribute = effectiveAttribute(row.spec);
            const DwordResult kResult = readDwordAttribute(target_, kAttribute);
            if (!kResult.ok)
            {
                // Many DWMWA_* values are write-only; DWM always returns E_INVALIDARG for reads.
                // This case is not an error; use distinct wording to avoid misinterpretation as 'write is also unsupported'.
                row.statusLabel->setText(kResult.hr == E_INVALIDARG
                    ? uiText("window.dwm.status.write_only", "不可回读（只写属性，或当前系统不支持）")
                    : uiText("window.dwm.status.read_failed", "读取失败: %1").arg(hresultText(kResult.hr)));
                return false;
            }

            row.statusLabel->setText(
                uiText("window.dwm.status.current", "当前值: %1").arg(describeValue(row.spec, kResult.value)));
            if (syncControl)
            {
                syncRowControl(row, kResult.value);
            }
            return true;
        }

        // writeAttributeRow：
        // - Purpose: Writes the UI value of a single attribute row back to the target window.
        // - Input row: target row. Dangerous attributes trigger a confirmation dialog first.
        void writeAttributeRow(AttributeRow& row)
        {
            if (!targetAlive())
            {
                return;
            }

            const DWORD kValue = currentRowValue(row);
            if (row.spec.destructive && !confirmDestructiveWrite(row.spec, kValue))
            {
                return;
            }

            const DWORD kAttribute = effectiveAttribute(row.spec);
            const HRESULT kResult = ::DwmSetWindowAttribute(target_, kAttribute, &kValue, sizeof(kValue));
            row.touched = row.touched || SUCCEEDED(kResult);
            appendLog(uiText("window.dwm.log.write", "写入 %1 = %2 → %3")
                .arg(QString::fromLatin1(row.spec.apiName), describeValue(row.spec, kValue), hresultText(kResult)));

            if (frameChangeCheck_ != nullptr && frameChangeCheck_->isChecked())
            {
                requestFrameChange();
            }
            readAttributeRow(row, false);
            refreshDiagnostics();
        }

        // effectiveAttribute：
        // - Purpose: Convert static IDs in the spec to the actual IDs used by the current system.
        // - Note: Currently, only dark title bars have two sets of legacy and new identifiers.
        DWORD effectiveAttribute(const RowSpec& spec) const
        {
            return spec.attribute == kAttrImmersiveDarkMode ? darkModeAttribute() : spec.attribute;
        }

        // currentRowValue：
        // - Purpose: Convert UI control state to the raw DWORD value to be written to DWM.
        // - Out: Boolean/enum retrieves dropdown data; custom color mode retrieves COLORREF.
        DWORD currentRowValue(const AttributeRow& row) const
        {
            if (row.spec.kind == RowKind::kColor && row.valueCombo->currentIndex() == 2)
            {
                const QColor kColor = row.customColor;
                return static_cast<DWORD>(RGB(kColor.red(), kColor.green(), kColor.blue()));
            }
            return row.valueCombo->currentData().toUInt();
        }

        // syncRowControl：
        // - Purpose: Reflect the read-back raw value to the combo box (color values map to custom mode);
        // - Input row/value: Target row and read-back value.
        void syncRowControl(AttributeRow& row, DWORD value)
        {
            if (row.spec.kind == RowKind::kColor)
            {
                if (value == kColorDefault)
                {
                    row.valueCombo->setCurrentIndex(0);
                }
                else if (value == kColorNone)
                {
                    row.valueCombo->setCurrentIndex(1);
                }
                else
                {
                    row.customColor = QColor(GetRValue(value), GetGValue(value), GetBValue(value));
                    updateColorButton(row);
                    row.valueCombo->setCurrentIndex(2);
                }
                return;
            }

            for (int index = 0; index < row.valueCombo->count(); ++index)
            {
                if (row.valueCombo->itemData(index).toUInt() == value)
                {
                    row.valueCombo->setCurrentIndex(index);
                    return;
                }
            }
        }

        // describeValue：
        // - Purpose: Translate raw DWORD values into human-readable text (enum names / colors / booleans);
        // - Output: unified description for status labels, logs, and reports.
        QString describeValue(const RowSpec& spec, DWORD value) const
        {
            if (spec.kind == RowKind::kBoolean)
            {
                return value != 0
                    ? uiText("window.dwm.value.true", "TRUE (1)")
                    : uiText("window.dwm.value.false", "FALSE (0)");
            }
            if (spec.kind == RowKind::kEnumerated)
            {
                for (const EnumOption& option : spec.options)
                {
                    if (option.value == value)
                    {
                        return uiText(option.key, option.label);
                    }
                }
                return QStringLiteral("%1 (%2)").arg(value).arg(hexText(value));
            }
            if (value == kColorDefault)
            {
                return uiText("window.dwm.color.default", "系统默认");
            }
            if (value == kColorNone)
            {
                return uiText("window.dwm.color.none", "无（不绘制）");
            }
            return QStringLiteral("#%1%2%3 (COLORREF %4)")
                .arg(GetRValue(value), 2, 16, QChar('0'))
                .arg(GetGValue(value), 2, 16, QChar('0'))
                .arg(GetBValue(value), 2, 16, QChar('0'))
                .arg(hexText(value))
                .toUpper();
        }

        // confirmDestructiveWrite：
        // - Purpose: Require secondary confirmation for writes that would cause the window to disappear from the screen.
        // - Output: returns true if the user confirms.
        bool confirmDestructiveWrite(const RowSpec& spec, DWORD value)
        {
            if (value == 0)
            {
                // Cancelling Cloak is a recovery action and does not require interrupting the user.
                return true;
            }
            const QMessageBox::StandardButton kAnswer = QMessageBox::question(
                this,
                uiText("window.dwm.confirm.title", "确认 DWM 写入"),
                uiText("window.dwm.confirm.cloak",
                    "即将对窗口 %1 设置 %2。\n\n窗口会立刻从画面上消失，但进程与句柄仍然存在，可以在本页把该属性改回 FALSE 恢复显示。\n\n确定继续吗？")
                    .arg(hwndText(target_), QString::fromLatin1(spec.apiName)),
                QMessageBox::Yes | QMessageBox::No,
                QMessageBox::No);
            return kAnswer == QMessageBox::Yes;
        }

        // readAllAttributes：
        // - Purpose: Batch read all attribute rows;
        // - logSummary: whether to record the statistics of this read operation in the log.
        void readAllAttributes(bool logSummary)
        {
            int readableCount = 0;
            for (AttributeRow& row : rows_)
            {
                if (readAttributeRow(row, true))
                {
                    ++readableCount;
                }
            }
            if (logSummary)
            {
                appendLog(uiText("window.dwm.log.read_all", "已尝试 %1 项属性，其中 %2 项可回读。")
                    .arg(rows_.size()).arg(readableCount));
            }
        }

        // restoreSystemDefaults：
        // - Purpose: Write all modified properties on this page back to system defaults.
        // - Note: Most DWMWA_* values are not readable, so rely on 'document defaults' rather than snapshot values.
        void restoreSystemDefaults()
        {
            if (!targetAlive())
            {
                return;
            }

            const QMessageBox::StandardButton kAnswer = QMessageBox::question(
                this,
                uiText("window.dwm.confirm.title", "确认 DWM 写入"),
                uiText("window.dwm.confirm.restore",
                    "即将把本页涉及的全部 DWM 属性写回系统默认值，并清除框架扩展与合成特性。\n\n确定继续吗？"),
                QMessageBox::Yes | QMessageBox::No,
                QMessageBox::No);
            if (kAnswer != QMessageBox::Yes)
            {
                return;
            }

            for (AttributeRow& row : rows_)
            {
                const DWORD kDefaultValue = row.spec.kind == RowKind::kColor ? kColorDefault : 0u;
                const DWORD kAttribute = effectiveAttribute(row.spec);
                const HRESULT kResult = ::DwmSetWindowAttribute(target_, kAttribute, &kDefaultValue, sizeof(kDefaultValue));
                row.touched = false;
                appendLog(uiText("window.dwm.log.write", "写入 %1 = %2 → %3")
                    .arg(QString::fromLatin1(row.spec.apiName),
                        describeValue(row.spec, kDefaultValue),
                        hresultText(kResult)));
            }

            for (QSpinBox* spinBox : marginSpins_)
            {
                spinBox->setValue(0);
            }
            applyFrameMargins(0, 0, 0, 0);
            applyBlurBehind(false);
            if (accentStateCombo_ != nullptr)
            {
                accentStateCombo_->setCurrentIndex(0);
            }
            applyAccentState(0);
            requestFrameChange();
            readAllAttributes(false);
            refreshDiagnostics();
        }

        // applySelectedPreset：
        // - Purpose: Execute a set of preset writes upon selection from the dropdown.
        // - Note: Presets only invoke existing row write logic to ensure both logs and state are updated.
        void applySelectedPreset()
        {
            if (!targetAlive() || presetCombo_ == nullptr)
            {
                return;
            }

            switch (presetCombo_->currentIndex())
            {
            case 0:
                setRowValue(kAttrImmersiveDarkMode, 1);
                setRowValue(kAttrWindowCornerPreference, 2);
                break;
            case 1:
                setRowValue(kAttrWindowCornerPreference, 1);
                setRowValue(kAttrBorderColor, kColorNone);
                break;
            case 2:
                setRowValue(kAttrSystemBackdropType, 2);
                setRowValue(kAttrImmersiveDarkMode, 1);
                break;
            case 3:
                setRowValue(kAttrSystemBackdropType, 3);
                setRowValue(kAttrWindowCornerPreference, 0);
                break;
            case 4:
                setRowValue(kAttrTransitionsForceDisabled, 1);
                setRowValue(kAttrExcludedFromPeek, 1);
                break;
            default:
                return;
            }
            requestFrameChange();
            refreshDiagnostics();
        }

        // setRowValue：
        // - Purpose: Locate the UI row by attribute ID, synchronize controls, and write immediately.
        // - Input attribute/value: attribute ID and target value.
        void setRowValue(DWORD attribute, DWORD value)
        {
            for (AttributeRow& row : rows_)
            {
                if (row.spec.attribute != attribute)
                {
                    continue;
                }
                syncRowControl(row, value);
                const HRESULT kResult = ::DwmSetWindowAttribute(
                    target_, effectiveAttribute(row.spec), &value, sizeof(value));
                row.touched = row.touched || SUCCEEDED(kResult);
                appendLog(uiText("window.dwm.log.write", "写入 %1 = %2 → %3")
                    .arg(QString::fromLatin1(row.spec.apiName), describeValue(row.spec, value), hresultText(kResult)));
                readAttributeRow(row, false);
                return;
            }
        }

        // ---------- Frame extension / blur / composition features ----------

        // applyFrameMargins：
        // - Purpose: Call DwmExtendFrameIntoClientArea to set glass margins.
        // - Input left/top/right/bottom: pixel values for each edge; -1 indicates the entire window glass.
        void applyFrameMargins(int left, int top, int right, int bottom)
        {
            if (!targetAlive())
            {
                return;
            }
            MARGINS margins{ left, right, top, bottom };
            const HRESULT kResult = ::DwmExtendFrameIntoClientArea(target_, &margins);
            appendLog(uiText("window.dwm.log.margins", "DwmExtendFrameIntoClientArea(%1,%2,%3,%4) → %5")
                .arg(left).arg(top).arg(right).arg(bottom).arg(hresultText(kResult)));
        }

        // applyBlurBehind：
        // - Purpose: Call DwmEnableBlurBehindWindow to toggle window blur behind.
        // - Input enable: whether to enable.
        void applyBlurBehind(bool enable)
        {
            if (!targetAlive())
            {
                return;
            }
            DWM_BLURBEHIND blurBehind{};
            blurBehind.dwFlags = DWM_BB_ENABLE | DWM_BB_TRANSITIONONMAXIMIZED;
            blurBehind.fEnable = enable ? TRUE : FALSE;
            blurBehind.fTransitionOnMaximized =
                (blurTransitionCheck_ != nullptr && blurTransitionCheck_->isChecked()) ? TRUE : FALSE;
            const HRESULT kResult = ::DwmEnableBlurBehindWindow(target_, &blurBehind);
            appendLog(uiText("window.dwm.log.blur", "DwmEnableBlurBehindWindow(enable=%1) → %2")
                .arg(enable ? 1 : 0).arg(hresultText(kResult)));
        }

        // applyAccentPolicy：
        // - Purpose: Apply the ACCENT_POLICY based on interface parameters.
        // - Note: The color value is arranged as 0xAABBGGRR, which differs from the byte order of COLORREF.
        void applyAccentPolicy()
        {
            if (accentStateCombo_ == nullptr)
            {
                return;
            }
            applyAccentState(accentStateCombo_->currentData().toUInt());
        }

        // applyAccentState：
        // - Purpose: Calls SetWindowCompositionAttribute with the specified ACCENT_STATE.
        // - Input accentState: ACCENT_STATE enum value.
        void applyAccentState(DWORD accentState)
        {
            if (!targetAlive())
            {
                return;
            }
            const SetWindowCompositionAttributeFunction kFunction = resolveSetWindowCompositionAttribute();
            if (kFunction == nullptr)
            {
                const QString kMessage = uiText(
                    "window.dwm.log.accent_unavailable", "当前系统没有导出 SetWindowCompositionAttribute。");
                appendLog(kMessage);
                if (accentStatusLabel_ != nullptr)
                {
                    accentStatusLabel_->setText(kMessage);
                }
                return;
            }

            AccentPolicyData policy{};
            policy.accentState = accentState;
            policy.accentFlags = accentFlagsSpin_ != nullptr
                ? static_cast<DWORD>(accentFlagsSpin_->value())
                : 0u;
            const int kAlpha = accentAlphaSlider_ != nullptr ? accentAlphaSlider_->value() : 255;
            policy.gradientColor =
                (static_cast<DWORD>(kAlpha) << 24)
                | (static_cast<DWORD>(accentColor_.blue()) << 16)
                | (static_cast<DWORD>(accentColor_.green()) << 8)
                | static_cast<DWORD>(accentColor_.red());

            WindowCompositionAttributeData data{};
            data.attribute = kWcaAccentPolicy;
            data.data = &policy;
            data.dataSize = sizeof(policy);

            ::SetLastError(ERROR_SUCCESS);
            const BOOL kOk = kFunction(target_, &data);
            const DWORD kLastError = ::GetLastError();
            const QString kStatus = kOk != FALSE
                ? uiText("window.dwm.status.accent_ok", "已下发 ACCENT_STATE=%1，着色 %2")
                    .arg(accentState).arg(hexText(policy.gradientColor))
                : uiText("window.dwm.status.accent_failed", "下发失败，Win32 错误码 %1").arg(kLastError);
            if (accentStatusLabel_ != nullptr)
            {
                accentStatusLabel_->setText(kStatus);
            }
            appendLog(kStatus);
        }

        // applyDarkModeColors：
        // - Purpose: Switch the window's dark system theme using WCA_USEDARKMODECOLORS;
        // - Input enable: whether to enable dark mode.
        void applyDarkModeColors(bool enable)
        {
            if (!targetAlive())
            {
                return;
            }
            const SetWindowCompositionAttributeFunction kFunction = resolveSetWindowCompositionAttribute();
            if (kFunction == nullptr)
            {
                appendLog(uiText(
                    "window.dwm.log.accent_unavailable", "当前系统没有导出 SetWindowCompositionAttribute。"));
                return;
            }

            BOOL darkModeValue = enable ? TRUE : FALSE;
            WindowCompositionAttributeData data{};
            data.attribute = kWcaUseDarkModeColors;
            data.data = &darkModeValue;
            data.dataSize = sizeof(darkModeValue);

            ::SetLastError(ERROR_SUCCESS);
            const BOOL kOk = kFunction(target_, &data);
            const DWORD kLastError = ::GetLastError();
            appendLog(uiText("window.dwm.log.dark_colors", "WCA_USEDARKMODECOLORS(%1) → %2")
                .arg(enable ? 1 : 0)
                .arg(kOk != FALSE
                    ? uiText("window.dwm.log.ok", "成功")
                    : uiText("window.dwm.log.failed_error", "失败(%1)").arg(kLastError)));
            requestFrameChange();
        }

        // requestFrameChange：
        // - Purpose: Force the target window to recalculate its non-client area so that newly written attributes become visible immediately.
        // - Note: SWP_ASYNCWINDOWPOS must be used; otherwise, if the target thread is unresponsive, it will block this process.
        void requestFrameChange()
        {
            if (::IsWindow(target_) == FALSE)
            {
                return;
            }
            ::SetWindowPos(
                target_,
                nullptr,
                0, 0, 0, 0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED | SWP_ASYNCWINDOWPOS);
        }

        // ---------- Diagnostics and Report ----------

        // refreshDiagnostics：
        // - Purpose: Resample read-only diagnostic information and refresh the right-side text.
        // - Call: During initialization, after writing, and when the refresh button is clicked.
        void refreshDiagnostics()
        {
            if (diagnosticsText_ == nullptr)
            {
                return;
            }
            const int kScrollValue = diagnosticsText_->verticalScrollBar() != nullptr
                ? diagnosticsText_->verticalScrollBar()->value()
                : 0;
            diagnosticsText_->setPlainText(buildDiagnosticsText());
            if (diagnosticsText_->verticalScrollBar() != nullptr)
            {
                diagnosticsText_->verticalScrollBar()->setValue(kScrollValue);
            }
        }

        // buildDiagnosticsText：
        // - Purpose: Aggregate system-level composition status and read-only DWM attributes of the target window.
        // - Out: Multi-line diagnostic text.
        QString buildDiagnosticsText() const
        {
            QStringList lines;

            lines << uiText("window.dwm.diag.section_system", "[系统合成状态]");
            BOOL compositionEnabled = FALSE;
            const HRESULT kCompositionResult = ::DwmIsCompositionEnabled(&compositionEnabled);
            lines << QStringLiteral("DwmIsCompositionEnabled: %1")
                .arg(SUCCEEDED(kCompositionResult)
                    ? (compositionEnabled != FALSE
                        ? uiText("window.dwm.value.yes", "是")
                        : uiText("window.dwm.value.no", "否"))
                    : hresultText(kCompositionResult));

            DWORD colorization = 0;
            BOOL opaqueBlend = FALSE;
            const HRESULT kColorizationResult = ::DwmGetColorizationColor(&colorization, &opaqueBlend);
            lines << QStringLiteral("DwmGetColorizationColor: %1")
                .arg(SUCCEEDED(kColorizationResult)
                    ? QStringLiteral("%1 (%2 %3)")
                        .arg(hexText(colorization))
                        .arg(uiText("window.dwm.diag.opaque_blend", "不透明混合"))
                        .arg(opaqueBlend != FALSE
                            ? uiText("window.dwm.value.yes", "是")
                            : uiText("window.dwm.value.no", "否"))
                    : hresultText(kColorizationResult));

            DWM_TIMING_INFO timingInfo{};
            timingInfo.cbSize = sizeof(timingInfo);
            const HRESULT kTimingResult = ::DwmGetCompositionTimingInfo(nullptr, &timingInfo);
            if (SUCCEEDED(kTimingResult))
            {
                const double kRefreshRate = timingInfo.rateRefresh.uiDenominator != 0
                    ? static_cast<double>(timingInfo.rateRefresh.uiNumerator)
                        / static_cast<double>(timingInfo.rateRefresh.uiDenominator)
                    : 0.0;
                const double kComposeRate = timingInfo.rateCompose.uiDenominator != 0
                    ? static_cast<double>(timingInfo.rateCompose.uiNumerator)
                        / static_cast<double>(timingInfo.rateCompose.uiDenominator)
                    : 0.0;
                lines << QStringLiteral("MonitorRefreshRate: %1 Hz").arg(kRefreshRate, 0, 'f', 3);
                lines << QStringLiteral("CompositionRate: %1 Hz").arg(kComposeRate, 0, 'f', 3);
                lines << QStringLiteral("cRefresh / cFrame: %1 / %2")
                    .arg(static_cast<qulonglong>(timingInfo.cRefresh))
                    .arg(static_cast<qulonglong>(timingInfo.cFrame));
                lines << QStringLiteral("cFramesLate / cFramesDropped: %1 / %2")
                    .arg(static_cast<qulonglong>(timingInfo.cFramesLate))
                    .arg(static_cast<qulonglong>(timingInfo.cFramesDropped));
            }
            else
            {
                lines << QStringLiteral("DwmGetCompositionTimingInfo: %1").arg(hresultText(kTimingResult));
            }

            lines << QString() << uiText("window.dwm.diag.section_window", "[目标窗口只读属性]");
            if (::IsWindow(target_) == FALSE)
            {
                lines << uiText("window.dwm.status.invalid_target", "目标窗口已失效");
                return lines.join(QChar::LineFeed);
            }

            const DwordResult kNcRendering = readDwordAttribute(target_, kAttrNcRenderingEnabled);
            lines << QStringLiteral("DWMWA_NCRENDERING_ENABLED (1): %1")
                .arg(kNcRendering.ok
                    ? (kNcRendering.value != 0
                        ? uiText("window.dwm.value.yes", "是")
                        : uiText("window.dwm.value.no", "否"))
                    : hresultText(kNcRendering.hr));

            const DwordResult kCloaked = readDwordAttribute(target_, kAttrCloaked);
            lines << QStringLiteral("DWMWA_CLOAKED (14): %1")
                .arg(kCloaked.ok ? describeCloaked(kCloaked.value) : hresultText(kCloaked.hr));

            const DwordResult kBorderThickness = readDwordAttribute(target_, kAttrVisibleFrameBorderThickness);
            lines << QStringLiteral("DWMWA_VISIBLE_FRAME_BORDER_THICKNESS (37): %1")
                .arg(kBorderThickness.ok ? QString::number(kBorderThickness.value) : hresultText(kBorderThickness.hr));

            const RectResult kExtendedFrame = readRectAttribute(target_, kAttrExtendedFrameBounds);
            lines << QStringLiteral("DWMWA_EXTENDED_FRAME_BOUNDS (9): %1")
                .arg(kExtendedFrame.ok ? rectText(kExtendedFrame.value) : hresultText(kExtendedFrame.hr));

            const RectResult kCaptionButtons = readRectAttribute(target_, kAttrCaptionButtonBounds);
            lines << QStringLiteral("DWMWA_CAPTION_BUTTON_BOUNDS (5): %1")
                .arg(kCaptionButtons.ok ? rectText(kCaptionButtons.value) : hresultText(kCaptionButtons.hr));

            RECT windowRect{};
            if (::GetWindowRect(target_, &windowRect) != FALSE)
            {
                lines << QStringLiteral("GetWindowRect: %1").arg(rectText(windowRect));
                if (kExtendedFrame.ok)
                {
                    // The difference between the two rectangles is the invisible shadow margin reserved by DWM, a common source of layout issues.
                    lines << uiText("window.dwm.diag.shadow_inset", "阴影内缩(左/上/右/下): %1 / %2 / %3 / %4")
                        .arg(kExtendedFrame.value.left - windowRect.left)
                        .arg(kExtendedFrame.value.top - windowRect.top)
                        .arg(windowRect.right - kExtendedFrame.value.right)
                        .arg(windowRect.bottom - kExtendedFrame.value.bottom);
                }
            }

            return lines.join(QChar::LineFeed);
        }

        // describeCloaked：
        // - Purpose: Explain the source bit combination of DWMWA_CLOAKED.
        // - Output: Text in the format "0x2 (Shell Hidden)".
        QString describeCloaked(DWORD value) const
        {
            if (value == 0)
            {
                return uiText("window.dwm.cloak.visible", "0 (未隐藏)");
            }
            QStringList parts;
            if ((value & 0x1u) != 0)
            {
                parts << uiText("window.dwm.cloak.app", "应用自身隐藏");
            }
            if ((value & 0x2u) != 0)
            {
                parts << uiText("window.dwm.cloak.shell", "Shell 隐藏");
            }
            if ((value & 0x4u) != 0)
            {
                parts << uiText("window.dwm.cloak.inherited", "继承自属主窗口");
            }
            if (parts.isEmpty())
            {
                parts << uiText("window.dwm.cloak.unknown", "未知来源");
            }
            return QStringLiteral("%1 (%2)").arg(hexText(value), parts.join(QStringLiteral(", ")));
        }

        // buildReportText：
        // - Purpose: Aggregate diagnostic information and the current state of all attribute rows into an archivable text report;
        // - Output: Full report.
        QString buildReportText() const
        {
            QStringList lines;
            lines << uiText("window.dwm.report.title", "KSword DWM 合成报告");
            lines << uiText("window.dwm.report.time", "生成时间: %1")
                .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss")));
            lines << uiText("window.dwm.report.target", "目标 HWND: %1").arg(hwndText(target_));
            lines << uiText("window.dwm.report.build", "系统构建号: %1").arg(windowsBuild());
            lines << QString();
            lines << buildDiagnosticsText();
            lines << QString() << uiText("window.dwm.report.section_rows", "[可控属性当前状态]");
            for (const AttributeRow& row : rows_)
            {
                lines << QStringLiteral("%1 (%2): %3")
                    .arg(QString::fromLatin1(row.spec.apiName))
                    .arg(effectiveAttribute(row.spec))
                    .arg(row.statusLabel != nullptr ? row.statusLabel->text() : QString());
            }
            return lines.join(QChar::LineFeed);
        }

        // exportReport：
        // - Purpose: Write the report to a text file selected by the user.
        // - Note: On failure, provide a clear file path and reason; do not silently swallow the error.
        void exportReport()
        {
            const QString kFilePath = QFileDialog::getSaveFileName(
                this,
                uiText("window.dwm.export.title", "导出 DWM 报告"),
                QStringLiteral("dwm_%1.txt").arg(hwndText(target_)),
                uiText("window.dwm.export.filter", "文本文件 (*.txt);;所有文件 (*)"));
            if (kFilePath.isEmpty())
            {
                return;
            }

            QFile file(kFilePath);
            if (!file.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate))
            {
                QMessageBox::warning(
                    this,
                    uiText("window.dwm.export.failed_title", "导出失败"),
                    uiText("window.dwm.export.failed_text", "无法写入文件 %1：%2")
                        .arg(kFilePath, file.errorString()));
                return;
            }
            QTextStream stream(&file);
            stream << buildReportText();
            file.close();
            appendLog(uiText("window.dwm.log.exported", "报告已导出到 %1").arg(kFilePath));
        }

        // appendLog：
        // - Purpose: Append a timestamped log entry with line count capping.
        // - Input message: the localized text.
        void appendLog(const QString& message)
        {
            if (logText_ == nullptr)
            {
                return;
            }
            logText_->appendPlainText(QStringLiteral("[%1] %2")
                .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss.zzz")), message));
            while (logText_->document()->blockCount() > kLogBlockLimit)
            {
                QTextCursor cursor(logText_->document());
                cursor.movePosition(QTextCursor::Start);
                cursor.select(QTextCursor::BlockUnderCursor);
                cursor.removeSelectedText();
                cursor.deleteChar();
            }
        }

        // updateColorButton / updateAccentColorButton：
        // - Purpose: Apply the current color brush to the color picker button for intuitive color preview.
        void updateColorButton(AttributeRow& row)
        {
            if (row.colorButton == nullptr)
            {
                return;
            }
            // Use the palette's mid color for the border: a hardcoded semi-transparent black blends with the
            // background in dark themes, making the button border invisible when a dark color is selected.
            row.colorButton->setStyleSheet(
                QStringLiteral("QPushButton{background:%1;border:1px solid %2;border-radius:4px; }")
                    .arg(row.customColor.name(QColor::HexRgb), ksword_theme::borderHex()));
            row.colorButton->setToolTip(row.customColor.name(QColor::HexRgb).toUpper());
        }

        void updateAccentColorButton()
        {
            if (accentColorButton_ == nullptr)
            {
                return;
            }
            accentColorButton_->setStyleSheet(
                QStringLiteral("QPushButton{background:%1;border:1px solid %2;border-radius:4px; }")
                    .arg(accentColor_.name(QColor::HexRgb), ksword_theme::borderHex()));
            accentColorButton_->setToolTip(accentColor_.name(QColor::HexRgb).toUpper());
        }

        // ---------- DWM real-time thumbnails ----------

        // ensureThumbnail：
        // - Purpose: Register the target window as a DWM thumbnail source for this dialog;
        // - Note: The host must be a top-level window; if registration fails, display the HRESULT on the status label.
        void ensureThumbnail()
        {
            if (thumbnail_ != nullptr)
            {
                return;
            }
            if (::IsWindow(target_) == FALSE)
            {
                thumbnailStatusLabel_->setText(uiText("window.dwm.status.invalid_target", "目标窗口已失效"));
                return;
            }

            QWidget* topLevel = window();
            if (topLevel == nullptr)
            {
                return;
            }
            const HWND kDestination = reinterpret_cast<HWND>(topLevel->winId());
            if (kDestination == nullptr)
            {
                return;
            }

            HTHUMBNAIL thumbnail = nullptr;
            const HRESULT kResult = ::DwmRegisterThumbnail(kDestination, target_, &thumbnail);
            if (FAILED(kResult))
            {
                thumbnailStatusLabel_->setText(
                    uiText("window.dwm.thumbnail.register_failed", "注册缩略图失败: %1").arg(hresultText(kResult)));
                appendLog(uiText("window.dwm.thumbnail.register_failed", "注册缩略图失败: %1").arg(hresultText(kResult)));
                return;
            }
            thumbnail_ = thumbnail;
            thumbnailDestination_ = kDestination;
            appendLog(uiText("window.dwm.thumbnail.registered", "已注册 DWM 缩略图，宿主窗口 %1")
                .arg(hwndText(kDestination)));
        }

        // releaseThumbnail：
        // - Purpose: Unregister thumbnail handle;
        // - Usage: Called when closing previews, during page destruction, or when the host window handle changes.
        void releaseThumbnail()
        {
            if (thumbnail_ == nullptr)
            {
                return;
            }
            ::DwmUnregisterThumbnail(thumbnail_);
            thumbnail_ = nullptr;
            thumbnailDestination_ = nullptr;
        }

        // updateThumbnailPlacement：
        // - Purpose: Convert the placeholder control's position to the DWM target rectangle and submit it;
        // - Note: DWM uses physical pixels with the origin at the top-left of the host client area, so the device pixel ratio must be applied.
        void updateThumbnailPlacement()
        {
            if (thumbnailStatusLabel_ == nullptr || thumbnailHost_ == nullptr)
            {
                return;
            }

            const bool kWantVisible =
                thumbnailEnableCheck_ != nullptr
                && thumbnailEnableCheck_->isChecked()
                && isVisible()
                && thumbnailHost_->isVisible();

            if (!kWantVisible)
            {
                if (thumbnail_ != nullptr)
                {
                    DWM_THUMBNAIL_PROPERTIES properties{};
                    properties.dwFlags = DWM_TNP_VISIBLE;
                    properties.fVisible = FALSE;
                    ::DwmUpdateThumbnailProperties(thumbnail_, &properties);
                }
                return;
            }

            QWidget* topLevel = window();
            if (topLevel == nullptr)
            {
                return;
            }
            const HWND kDestination = reinterpret_cast<HWND>(topLevel->winId());
            if (thumbnail_ != nullptr && kDestination != thumbnailDestination_)
            {
                // After Qt rebuilds the native window, the old handle is invalid; it must be re-registered to continue displaying.
                releaseThumbnail();
            }
            if (thumbnail_ == nullptr)
            {
                ensureThumbnail();
                if (thumbnail_ == nullptr)
                {
                    return;
                }
            }

            SIZE sourceSize{};
            const HRESULT kSizeResult = ::DwmQueryThumbnailSourceSize(thumbnail_, &sourceSize);
            if (FAILED(kSizeResult) || sourceSize.cx <= 0 || sourceSize.cy <= 0)
            {
                thumbnailStatusLabel_->setText(
                    uiText("window.dwm.thumbnail.size_failed", "查询源尺寸失败: %1").arg(hresultText(kSizeResult)));
                return;
            }

            const qreal kPixelRatio = topLevel->devicePixelRatioF();
            const QPoint kHostOrigin = thumbnailHost_->mapTo(topLevel, QPoint(0, 0));
            const QSize kHostSize = thumbnailHost_->size();
            const int kHostLeft = qRound(kHostOrigin.x() * kPixelRatio);
            const int kHostTop = qRound(kHostOrigin.y() * kPixelRatio);
            const int kHostWidth = qRound(kHostSize.width() * kPixelRatio);
            const int kHostHeight = qRound(kHostSize.height() * kPixelRatio);
            if (kHostWidth <= 0 || kHostHeight <= 0)
            {
                return;
            }

            // Scale proportionally and center to avoid stretching or distorting the target window content.
            const double kScale = qMin(
                static_cast<double>(kHostWidth) / static_cast<double>(sourceSize.cx),
                static_cast<double>(kHostHeight) / static_cast<double>(sourceSize.cy));
            const int kDrawWidth = qMax(1, static_cast<int>(sourceSize.cx * kScale));
            const int kDrawHeight = qMax(1, static_cast<int>(sourceSize.cy * kScale));
            const int kOffsetX = kHostLeft + (kHostWidth - kDrawWidth) / 2;
            const int kOffsetY = kHostTop + (kHostHeight - kDrawHeight) / 2;

            DWM_THUMBNAIL_PROPERTIES properties{};
            properties.dwFlags =
                DWM_TNP_RECTDESTINATION | DWM_TNP_VISIBLE | DWM_TNP_OPACITY | DWM_TNP_SOURCECLIENTAREAONLY;
            properties.rcDestination = RECT{ kOffsetX, kOffsetY, kOffsetX + kDrawWidth, kOffsetY + kDrawHeight };
            properties.fVisible = TRUE;
            properties.opacity = static_cast<BYTE>(
                thumbnailOpacitySlider_ != nullptr ? thumbnailOpacitySlider_->value() : 255);
            properties.fSourceClientAreaOnly =
                (thumbnailClientOnlyCheck_ != nullptr && thumbnailClientOnlyCheck_->isChecked()) ? TRUE : FALSE;

            const HRESULT kUpdateResult = ::DwmUpdateThumbnailProperties(thumbnail_, &properties);
            if (FAILED(kUpdateResult))
            {
                thumbnailStatusLabel_->setText(
                    uiText("window.dwm.thumbnail.update_failed", "更新缩略图失败: %1").arg(hresultText(kUpdateResult)));
                return;
            }
            thumbnailStatusLabel_->setText(
                uiText("window.dwm.thumbnail.active", "源尺寸 %1x%2，显示 %3x%4")
                    .arg(sourceSize.cx).arg(sourceSize.cy).arg(kDrawWidth).arg(kDrawHeight));
        }

    private:
        HWND target_ = nullptr;                       // m_target: Target window to be controlled.
        std::vector<AttributeRow> rows_;              // m_rows: All controllable attribute rows.

        QCheckBox* frameChangeCheck_ = nullptr;       // Force recalculation of the border after writing.
        QComboBox* presetCombo_ = nullptr;            // One-click preset selection.

        std::array<QSpinBox*, 4> marginSpins_{ nullptr, nullptr, nullptr, nullptr }; // Glass margin for four sides.
        QCheckBox* blurTransitionCheck_ = nullptr;    // Whether blur transitions with maximization.

        QComboBox* accentStateCombo_ = nullptr;       // ACCENT_STATE selection.
        QPushButton* accentColorButton_ = nullptr;    // Composition color picker button.
        QSlider* accentAlphaSlider_ = nullptr;        // Composition color transparency.
        QSpinBox* accentFlagsSpin_ = nullptr;         // ACCENT_POLICY flags.
        QLabel* accentStatusLabel_ = nullptr;         // Composition feature status.
        QColor accentColor_{ 32, 32, 32 };            // Current composition color.

        QCheckBox* thumbnailEnableCheck_ = nullptr;   // Whether to enable real-time thumbnails.
        QCheckBox* thumbnailClientOnlyCheck_ = nullptr; // Whether to display only the client area.
        QSlider* thumbnailOpacitySlider_ = nullptr;   // Thumbnail opacity.
        QWidget* thumbnailHost_ = nullptr;            // Thumbnail placeholder area.
        QLabel* thumbnailStatusLabel_ = nullptr;      // Thumbnail status hint.
        QTimer* thumbnailTimer_ = nullptr;            // Target rectangle follows the timer.
        HTHUMBNAIL thumbnail_ = nullptr;              // DWM thumbnail handle.
        HWND thumbnailDestination_ = nullptr;         // Host window handle used during registration.

        QPlainTextEdit* diagnosticsText_ = nullptr;   // Read-only diagnostic output.
        QPlainTextEdit* logText_ = nullptr;           // Operation log output.
    };

    // ============ Inject into window details dialog ============

    // targetFromDialog：
    // - Purpose: Reads the structured target HWND from the details dialog.
    // - Out: Returns the handle on successful parsing, or null on failure.
    std::optional<HWND> targetFromDialog(const QDialog* dialog)
    {
        bool propertyOk = false;
        const qulonglong kPropertyValue = dialog->property(kTargetHwndProperty).toULongLong(&propertyOk);
        if (propertyOk && kPropertyValue != 0)
        {
            return reinterpret_cast<HWND>(static_cast<quintptr>(kPropertyValue));
        }
        return std::nullopt;
    }

    // hostTabs：
    // - Purpose: Find the QTabWidget hosting the tabs in the details dialog;
    // - Out: The most suitable QTabWidget; returns nullptr if not found.
    QTabWidget* hostTabs(QDialog* dialog)
    {
        QTabWidget* best = nullptr;
        int bestScore = -1;
        for (QTabWidget* tabs : dialog->findChildren<QTabWidget*>())
        {
            const int kScore = tabs->count() + (tabs->parentWidget() == dialog ? 1000 : 0);
            if (kScore > bestScore)
            {
                best = tabs;
                bestScore = kScore;
            }
        }
        return best;
    }

    // attach：
    // - Purpose: Append the DWM composition page to a window details dialog;
    // - Note: Uses an independent attachment flag to avoid interference with the hierarchy diagnostic page.
    void attach(QDialog* dialog)
    {
        if (dialog == nullptr || dialog->property(kAttachedProperty).toBool())
        {
            return;
        }
        const std::optional<HWND> kTarget = targetFromDialog(dialog);
        QTabWidget* tabs = hostTabs(dialog);
        if (!kTarget.has_value() || tabs == nullptr)
        {
            return;
        }
        Page* page = new Page(*kTarget, tabs);
        tabs->addTab(page, uiText("window.dwm.tab.title", "DWM 合成"));
        ks::i18n::LanguageManager::instance().bindTab(
            tabs, page, QStringLiteral("window.dwm.tab.title"), QStringLiteral("DWM 合成"));
        dialog->setProperty(kAttachedProperty, true);
    }

    // Injector：
    // - Purpose: Application-level event filter that injects this page when the window details dialog is first shown.
    class Injector final : public QObject
    {
    public:
        explicit Injector(QObject* parent) : QObject(parent) {}

    protected:
        bool eventFilter(QObject* watched, QEvent* event) override
        {
            if (event != nullptr && event->type() == QEvent::Show)
            {
                auto* dialog = qobject_cast<QDialog*>(watched);
                if (dialog != nullptr && dialog->objectName() == QStringLiteral("WindowDetailDialogRoot"))
                {
                    const QPointer<QDialog> kSafeDialog(dialog);
                    QTimer::singleShot(0, dialog, [kSafeDialog]() {
                        if (!kSafeDialog.isNull())
                        {
                            attach(kSafeDialog.data());
                        }
                    });
                }
            }
            return QObject::eventFilter(watched, event);
        }
    };

    // install: Install the injector when the process starts.
    void install()
    {
        QCoreApplication* app = QCoreApplication::instance();
        if (app == nullptr)
        {
            return;
        }
        auto* injector = new Injector(app);
        app->installEventFilter(injector);
    }
}

static void installKswordWindowDwmControl()
{
    ks::window::dwmctl::install();
}

Q_COREAPP_STARTUP_FUNCTION(installKswordWindowDwmControl)
