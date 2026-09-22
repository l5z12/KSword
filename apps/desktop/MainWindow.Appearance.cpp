#include "MainWindow.h"
#include "ui/ThemedMessageBox.h"
#include "internationalization/LanguageManager.h"
#include "ui/styles/UiStyleSheet.h"
#include "process_dock/ProcessDock.h"
#include "monitor_dock/MonitorDock.h"
#include "window_dock/WindowDock.h"
#include <QMenu>
#include <QTimer>
#include <QApplication>
#include <QCoreApplication>
#include <QCheckBox>
#include <QElapsedTimer>
#include <QFont>
#include <QGuiApplication>
#include <QList>
#include <QPalette>
#include <QToolTip>
#include <QStyleHints>
#include <QTableView>
#pragma warning(disable: 4996)
#include "Framework.h"
#include "framework/NotificationCardManager.h"
#include "framework/ProgressDockWidget.h"
#include "framework/CustomTitleBar.h"
#include "include/ads/FloatingDockContainer.h"
#include "ui/DetailLayoutRegistry.h"
#include "ui/DockTabInteraction.h"
#include "ui/GlobalDialogTheme.h"
#include "ui/GlobalUiBaseStyle.h"
#include "ui/WindowChrome.h"
#include "ui/SvgThemeIconManager.h"
#include "ui/SmoothScrollSupport.h"
#include "ui/ThemeColorRemap.h"
#include "Theme.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <shellapi.h>
#include <sddl.h>
#include <winternl.h>

#include <algorithm>
#include <TlHelp32.h>

#include "MainWindow.DockTabsSupport.h"
#include "MainWindow.WidgetBehaviorSupport.h"

namespace ksword::ui::main_window
{
    // RuntimeAppearanceProgress:
    // - Reuse the native kSplash before runtime theme, background, or font switching.
    // - kSplash uses a separate Win32 layered window for synchronized drawing, preserving visible progress even while the Qt main thread resets styles.
    // - Automatically hides the window during destruction to prevent the startup page from lingering due to abnormal paths or early returns.
    class RuntimeAppearanceProgress final
    {
    public:
        explicit RuntimeAppearanceProgress(const bool shouldShow)
        {
            if (!shouldShow)
            {
                return;
            }

            visible_ = kSplash.show(progressText(
                QStringLiteral("main.runtime_appearance.progress.start"),
                QStringLiteral("正在应用界面设置...")).toUtf8().toStdString());
        }

        ~RuntimeAppearanceProgress()
        {
            if (visible_)
            {
                kSplash.hide();
            }
        }

        RuntimeAppearanceProgress(const RuntimeAppearanceProgress&) = delete;
        RuntimeAppearanceProgress& operator=(const RuntimeAppearanceProgress&) = delete;

        void update(const int progressPercent, const QString& textKey, const QString& fallbackText) const
        {
            if (!visible_)
            {
                return;
            }

            kSplash.progress(
                progressText(textKey, fallbackText).toUtf8().toStdString(),
                progressPercent);
        }

    private:
        static QString progressText(const QString& textKey, const QString& fallbackText)
        {
            return ks::i18n::contextText(textKey, fallbackText);
        }

        bool visible_ = false;
    };

    // kTooltipStyleBeginMarker / kTooltipStyleEndMarker purpose:
    // - Mark the start and end positions of the "Tooltip theme fragment" in the QApplication stylesheet.
    // - Enables precise replacement of old Tooltip styles during theme switching, avoiding redundant concatenation.
    constexpr const char* kTooltipStyleBeginMarker = "/*KSWORD_TOOLTIP_STYLE_BEGIN*/";

    constexpr const char* kTooltipStyleEndMarker = "/*KSWORD_TOOLTIP_STYLE_END*/";

    // kContextMenuStyleBeginMarker / kContextMenuStyleEndMarker Purpose:
    // - Mark the start and end positions of the "right-click menu theme fragment" in the QApplication stylesheet.
    // - Facilitates replacing old menu styles during theme switching to avoid redundant concatenation and style pollution.
    constexpr const char* kContextMenuStyleBeginMarker = "/*KSWORD_CONTEXT_MENU_STYLE_BEGIN*/";

    constexpr const char* kContextMenuStyleEndMarker = "/*KSWORD_CONTEXT_MENU_STYLE_END*/";

    // kControlContrastStyleBeginMarker / kControlContrastStyleEndMarker purpose:
    // - Mark global high-contrast styles for checkboxes, radio buttons, and sliders.
    // - Replaces old fragments when theme or custom colors change to avoid duplicate appends.
    constexpr const char* kControlContrastStyleBeginMarker = "/*KSWORD_CONTROL_CONTRAST_STYLE_BEGIN*/";

    constexpr const char* kControlContrastStyleEndMarker = "/*KSWORD_CONTROL_CONTRAST_STYLE_END*/";

    // kComboBoxStyleBeginMarker / kComboBoxStyleEndMarker purpose:
    // - Mark global opaque theme styles for the combo box body, arrow area, and popup list;
    // - Replace old fragments when the main background or theme color changes to avoid duplicate QSS appends.
    constexpr const char* kComboBoxStyleBeginMarker = "/*KSWORD_COMBOBOX_STYLE_BEGIN*/";

    constexpr const char* kComboBoxStyleEndMarker = "/*KSWORD_COMBOBOX_STYLE_END*/";

    // buildGlobalTooltipStyleBlock:
    // - Generates a global tooltip style block;
    // - Fragment includes start/end markers for applyGlobalApplicationStyleBlocks to perform replacement updates.
    // Call site: invoked internally by applyAppearanceSettings.
    // Parameter darkModeEnabled: whether dark mode is currently enabled.
    // Return: Tooltip snippet ready to be concatenated directly into the QApplication stylesheet.
    QString buildGlobalTooltipStyleBlock(const bool darkModeEnabled)
    {
        Q_UNUSED(darkModeEnabled);
        // tooltipRule purpose: QToolTip rule body, unifying light and dark background and text colors.
        const QString kTooltipRule = QStringLiteral(
            "QToolTip{"
            "  background-color:%1 !important;"
            "  color:%2 !important;"
            "  border:1px solid %3 !important;"
            "  padding:4px 6px;"
            "  border-radius:3px;"
            "}")
            .arg(ksword_theme::surfaceColorHex())
            .arg(ksword_theme::textPrimaryColorHex())
            .arg(ksword_theme::borderColorHex());

        return QStringLiteral("\n%1\n%2\n%3\n")
            .arg(QString::fromLatin1(kTooltipStyleBeginMarker))
            .arg(kTooltipRule)
            .arg(QString::fromLatin1(kTooltipStyleEndMarker));
    }

    // buildGlobalContextMenuStyleBlock:
    // - Generate a global right-click menu style block to cover all standard input control right-click menus as a fallback;
    // - Fix inconsistent background in the right-click menu of input boxes for independent top-level windows after switching between light and dark modes.
    // Call site: invoked internally by applyAppearanceSettings.
    // Parameter darkModeEnabled: whether dark mode is currently enabled.
    // Returns: a QMenu snippet that can be directly appended to the QApplication stylesheet.
    QString buildGlobalContextMenuStyleBlock(const bool darkModeEnabled)
    {
        Q_UNUSED(darkModeEnabled);
        const QString kMenuBackgroundColor = ksword_theme::surfaceColorHex();
        const QString kMenuTextColor = ksword_theme::textPrimaryColorHex();
        const QString kMenuBorderColor = ksword_theme::borderColorHex();
        const QString kDisabledTextColor = ksword_theme::textDisabledColorHex();

        const QString kContextMenuRule = QStringLiteral(
            "QMenu{"
            "  background-color:%1 !important;"
            "  color:%2 !important;"
            "  border:1px solid %3 !important;"
            "  padding:3px;"
            "}"
            "QMenu::item{"
            "  color:%2 !important;"
            "  padding:5px 18px 5px 14px;"
            "  background-color:transparent !important;"
            "}"
            "QMenu::item:selected{"
            "  background-color:%4 !important;"
            "  color:%6 !important;"
            "}"
            "QMenu::item:disabled{"
            "  color:%5 !important;"
            "  background-color:transparent !important;"
            "}"
            "QMenu::separator{"
            "  height:1px;"
            "  background-color:%3;"
            "  margin:2px 6px;"
            "}")
            .arg(kMenuBackgroundColor)
            .arg(kMenuTextColor)
            .arg(kMenuBorderColor)
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(kDisabledTextColor)
            .arg(ksword_theme::onAccentHex());

        return QStringLiteral("\n%1\n%2\n%3\n")
            .arg(QString::fromLatin1(kContextMenuStyleBeginMarker))
            .arg(kContextMenuRule)
            .arg(QString::fromLatin1(kContextMenuStyleEndMarker));
    }

    // buildGlobalControlContrastStyleBlock:
    // - Provides complete state graphics for checkboxes, radio buttons, checkable view items, and sliders;
    // - All active borders maintain at least a 3:1 non-text contrast ratio relative to the control surface.
    // - Checkmarks, half-selected lines, and radio points use black/white graphics based on their actual fill color.
    QString buildGlobalControlContrastStyleBlock(const bool darkModeEnabled)
    {
        Q_UNUSED(darkModeEnabled);

        const QColor kAccentColor = ksword_theme::controlAccentColor();
        const QColor kAccentHoverColor = ksword_theme::controlAccentHoverColor();
        const QColor kAccentPressedColor = ksword_theme::controlAccentPressedColor();
        const QColor kDisabledFillColor = ksword_theme::controlDisabledFillColor();
        const auto kGlyphPath = [](const QColor& fillColor, const QString& whitePath, const QString& blackPath) {
            return ksword_theme::maximumContrastMonochromeColor(fillColor) == ksword_theme::whiteColor()
                ? whitePath
                : blackPath;
        };

        const QString kWhiteCheckPath = QStringLiteral(":/Icon/ks_control_check_white.svg");
        const QString kBlackCheckPath = QStringLiteral(":/Icon/ks_control_check_black.svg");
        const QString kWhiteDashPath = QStringLiteral(":/Icon/ks_control_dash_white.svg");
        const QString kBlackDashPath = QStringLiteral(":/Icon/ks_control_dash_black.svg");
        const QString kWhiteRadioPath = QStringLiteral(":/Icon/ks_control_radio_white.svg");
        const QString kBlackRadioPath = QStringLiteral(":/Icon/ks_control_radio_black.svg");

        QString controlStyle = QString::fromLatin1(
            "\n__BEGIN_MARKER__\n"
            "QCheckBox,QRadioButton{spacing:6px;}"
            "QCheckBox:disabled,QRadioButton:disabled{color:__DISABLED_TEXT__; }"
            "QCheckBox::indicator,QGroupBox::indicator,QListView::indicator,QTreeView::indicator,QTableView::indicator{"
            "  width:15px;height:15px;"
            "  border:2px solid __OUTLINE__;"
            "  border-radius:3px;"
            "  background:__SURFACE__;"
            "  image:none;"
            "}"
            "QCheckBox::indicator:unchecked:hover,QGroupBox::indicator:unchecked:hover,QListView::indicator:unchecked:hover,QTreeView::indicator:unchecked:hover,QTableView::indicator:unchecked:hover{"
            "  border-color:__ACCENT__;background:__SURFACE_ALT__;"
            "}"
            "QCheckBox::indicator:checked,QGroupBox::indicator:checked,QListView::indicator:checked,QTreeView::indicator:checked,QTableView::indicator:checked{"
            "  border-color:__ACCENT__;background:__ACCENT__;image:url(__CHECK_ICON__);"
            "}"
            "QCheckBox::indicator:indeterminate,QGroupBox::indicator:indeterminate,QListView::indicator:indeterminate,QTreeView::indicator:indeterminate,QTableView::indicator:indeterminate{"
            "  border-color:__ACCENT__;background:__ACCENT__;image:url(__DASH_ICON__);"
            "}"
            "QCheckBox::indicator:checked:hover,QGroupBox::indicator:checked:hover,QListView::indicator:checked:hover,QTreeView::indicator:checked:hover,QTableView::indicator:checked:hover{"
            "  border-color:__ACCENT_HOVER__;background:__ACCENT_HOVER__;image:url(__CHECK_HOVER_ICON__);"
            "}"
            "QCheckBox::indicator:indeterminate:hover,QGroupBox::indicator:indeterminate:hover,QListView::indicator:indeterminate:hover,QTreeView::indicator:indeterminate:hover,QTableView::indicator:indeterminate:hover{"
            "  border-color:__ACCENT_HOVER__;background:__ACCENT_HOVER__;image:url(__DASH_HOVER_ICON__);"
            "}"
            "QCheckBox::indicator:checked:pressed,QGroupBox::indicator:checked:pressed,QListView::indicator:checked:pressed,QTreeView::indicator:checked:pressed,QTableView::indicator:checked:pressed{"
            "  border-color:__ACCENT_PRESSED__;background:__ACCENT_PRESSED__;image:url(__CHECK_PRESSED_ICON__);"
            "}"
            "QCheckBox::indicator:indeterminate:pressed,QGroupBox::indicator:indeterminate:pressed,QListView::indicator:indeterminate:pressed,QTreeView::indicator:indeterminate:pressed,QTableView::indicator:indeterminate:pressed{"
            "  border-color:__ACCENT_PRESSED__;background:__ACCENT_PRESSED__;image:url(__DASH_PRESSED_ICON__);"
            "}"
            "QCheckBox::indicator:disabled,QGroupBox::indicator:disabled,QListView::indicator:disabled,QTreeView::indicator:disabled,QTableView::indicator:disabled{"
            "  border-color:__DISABLED_OUTLINE__;background:__SURFACE_MUTED__;image:none;"
            "}"
            "QCheckBox::indicator:checked:disabled,QGroupBox::indicator:checked:disabled,QListView::indicator:checked:disabled,QTreeView::indicator:checked:disabled,QTableView::indicator:checked:disabled{"
            "  border-color:__DISABLED_OUTLINE__;background:__DISABLED_FILL__;image:url(__CHECK_DISABLED_ICON__);"
            "}"
            "QCheckBox::indicator:indeterminate:disabled,QGroupBox::indicator:indeterminate:disabled,QListView::indicator:indeterminate:disabled,QTreeView::indicator:indeterminate:disabled,QTableView::indicator:indeterminate:disabled{"
            "  border-color:__DISABLED_OUTLINE__;background:__DISABLED_FILL__;image:url(__DASH_DISABLED_ICON__);"
            "}"
            "QRadioButton::indicator{"
            "  width:15px;height:15px;"
            "  border:2px solid __OUTLINE__;"
            "  border-radius:8px;"
            "  background:__SURFACE__;"
            "  image:none;"
            "}"
            "QRadioButton::indicator:unchecked:hover{border-color:__ACCENT__;background:__SURFACE_ALT__; }"
            "QRadioButton::indicator:checked{border-color:__ACCENT__;background:__ACCENT__;image:url(__RADIO_ICON__); }"
            "QRadioButton::indicator:checked:hover{border-color:__ACCENT_HOVER__;background:__ACCENT_HOVER__;image:url(__RADIO_HOVER_ICON__); }"
            "QRadioButton::indicator:checked:pressed{border-color:__ACCENT_PRESSED__;background:__ACCENT_PRESSED__;image:url(__RADIO_PRESSED_ICON__); }"
            "QRadioButton::indicator:disabled{border-color:__DISABLED_OUTLINE__;background:__SURFACE_MUTED__;image:none; }"
            "QRadioButton::indicator:checked:disabled{border-color:__DISABLED_OUTLINE__;background:__DISABLED_FILL__;image:url(__RADIO_DISABLED_ICON__); }"
            "QSlider::groove:horizontal{height:4px;border:1px solid __OUTLINE__;border-radius:2px;background:__SURFACE_MUTED__; }"
            "QSlider::groove:vertical{width:4px;border:1px solid __OUTLINE__;border-radius:2px;background:__SURFACE_MUTED__; }"
            "QSlider::handle:horizontal{width:14px;margin:-6px 0;border:2px solid __OUTLINE__;border-radius:8px;background:__ACCENT__; }"
            "QSlider::handle:vertical{height:14px;margin:0 -6px;border:2px solid __OUTLINE__;border-radius:8px;background:__ACCENT__; }"
            "QSlider::handle:horizontal:hover,QSlider::handle:vertical:hover{border-color:__ACCENT_HOVER__;background:__ACCENT_HOVER__; }"
            "QSlider::handle:horizontal:pressed,QSlider::handle:vertical:pressed{border-color:__ACCENT_PRESSED__;background:__ACCENT_PRESSED__; }"
            "QSlider::handle:horizontal:disabled,QSlider::handle:vertical:disabled{border-color:__DISABLED_OUTLINE__;background:__DISABLED_FILL__; }"
            "__END_MARKER__\n");

        controlStyle.replace(QStringLiteral("__BEGIN_MARKER__"), QString::fromLatin1(kControlContrastStyleBeginMarker));
        controlStyle.replace(QStringLiteral("__END_MARKER__"), QString::fromLatin1(kControlContrastStyleEndMarker));
        controlStyle.replace(QStringLiteral("__SURFACE__"), ksword_theme::surfaceColorHex());
        controlStyle.replace(QStringLiteral("__SURFACE_ALT__"), ksword_theme::surfaceAltColorHex());
        controlStyle.replace(QStringLiteral("__SURFACE_MUTED__"), ksword_theme::surfaceMutedColorHex());
        controlStyle.replace(QStringLiteral("__OUTLINE__"), ksword_theme::controlOutlineHex());
        controlStyle.replace(QStringLiteral("__ACCENT__"), ksword_theme::themeColorName(kAccentColor));
        controlStyle.replace(QStringLiteral("__ACCENT_HOVER__"), ksword_theme::themeColorName(kAccentHoverColor));
        controlStyle.replace(QStringLiteral("__ACCENT_PRESSED__"), ksword_theme::themeColorName(kAccentPressedColor));
        controlStyle.replace(QStringLiteral("__DISABLED_TEXT__"), ksword_theme::textDisabledColorHex());
        controlStyle.replace(QStringLiteral("__DISABLED_OUTLINE__"), ksword_theme::controlDisabledOutlineHex());
        controlStyle.replace(QStringLiteral("__DISABLED_FILL__"), ksword_theme::themeColorName(kDisabledFillColor));
        controlStyle.replace(QStringLiteral("__CHECK_ICON__"), kGlyphPath(kAccentColor, kWhiteCheckPath, kBlackCheckPath));
        controlStyle.replace(QStringLiteral("__CHECK_HOVER_ICON__"), kGlyphPath(kAccentHoverColor, kWhiteCheckPath, kBlackCheckPath));
        controlStyle.replace(QStringLiteral("__CHECK_PRESSED_ICON__"), kGlyphPath(kAccentPressedColor, kWhiteCheckPath, kBlackCheckPath));
        controlStyle.replace(QStringLiteral("__CHECK_DISABLED_ICON__"), kGlyphPath(kDisabledFillColor, kWhiteCheckPath, kBlackCheckPath));
        controlStyle.replace(QStringLiteral("__DASH_ICON__"), kGlyphPath(kAccentColor, kWhiteDashPath, kBlackDashPath));
        controlStyle.replace(QStringLiteral("__DASH_HOVER_ICON__"), kGlyphPath(kAccentHoverColor, kWhiteDashPath, kBlackDashPath));
        controlStyle.replace(QStringLiteral("__DASH_PRESSED_ICON__"), kGlyphPath(kAccentPressedColor, kWhiteDashPath, kBlackDashPath));
        controlStyle.replace(QStringLiteral("__DASH_DISABLED_ICON__"), kGlyphPath(kDisabledFillColor, kWhiteDashPath, kBlackDashPath));
        controlStyle.replace(QStringLiteral("__RADIO_ICON__"), kGlyphPath(kAccentColor, kWhiteRadioPath, kBlackRadioPath));
        controlStyle.replace(QStringLiteral("__RADIO_HOVER_ICON__"), kGlyphPath(kAccentHoverColor, kWhiteRadioPath, kBlackRadioPath));
        controlStyle.replace(QStringLiteral("__RADIO_PRESSED_ICON__"), kGlyphPath(kAccentPressedColor, kWhiteRadioPath, kBlackRadioPath));
        controlStyle.replace(QStringLiteral("__RADIO_DISABLED_ICON__"), kGlyphPath(kDisabledFillColor, kWhiteRadioPath, kBlackRadioPath));
        return controlStyle;
    }

    // buildGlobalComboBoxStyleBlock:
    // - Generates a QApplication-level combo box style to ensure the main window, independent docks, and dialogs share the same opaque control surface.
    // - Specific colors are provided uniformly by ksword_theme::themedComboBoxStyle; the main background color and theme color are refreshed together when they change.
    QString buildGlobalComboBoxStyleBlock(const bool darkModeEnabled)
    {
        Q_UNUSED(darkModeEnabled);
        return QStringLiteral("\n%1\n%2\n%3\n")
            .arg(QString::fromLatin1(kComboBoxStyleBeginMarker))
            .arg(ksword_theme::themedComboBoxStyle())
            .arg(QString::fromLatin1(kComboBoxStyleEndMarker));
    }

    // replaceMarkedStyleBlock:
    // - Replace a style block with start/end markers within the existing QApplication stylesheet text;
    // - If no old block exists, append the new block; if the old block is corrupted, also treat it as an append to avoid accidentally deleting other QSS.
    // - Return value: true indicates that styleSheetText was modified.
    bool replaceMarkedStyleBlock(
        QString& styleSheetText,
        const char* const beginMarker,
        const char* const endMarker,
        const QString& replacementBlock)
    {
        if (beginMarker == nullptr || endMarker == nullptr)
        {
            return false;
        }

        const QString kBeginMarkerText = QString::fromLatin1(beginMarker);
        const QString kEndMarkerText = QString::fromLatin1(endMarker);
        const int kBeginMarkerIndex = styleSheetText.indexOf(kBeginMarkerText);

        if (kBeginMarkerIndex >= 0)
        {
            const int kEndMarkerIndex = styleSheetText.indexOf(kEndMarkerText, kBeginMarkerIndex);
            if (kEndMarkerIndex >= 0)
            {
                const int kRemoveLength = (kEndMarkerIndex - kBeginMarkerIndex) + kEndMarkerText.length();
                const QString kOldBlock = styleSheetText.mid(kBeginMarkerIndex, kRemoveLength);
                if (kOldBlock == replacementBlock)
                {
                    return false;
                }
                styleSheetText.replace(kBeginMarkerIndex, kRemoveLength, replacementBlock);
                return true;
            }
        }

        if (!styleSheetText.endsWith(QLatin1Char('\n')))
        {
            styleSheetText += QLatin1Char('\n');
        }
        styleSheetText += replacementBlock;
        return true;
    }

    // applyGlobalApplicationStyleBlocks:
    // - Merge updates for QApplication-level Tooltip, QMenu, interactive controls, and combo box style blocks.
    // - Call QApplication::setStyleSheet only once when the final stylesheet content actually changes.
    // - Avoid the two global repolish passes at startup previously caused by separate setStyleSheet calls for Tooltip and QMenu.
    // Call site: invoked internally by applyAppearanceSettings.
    // Parameters `tooltipStyleBlock`, `contextMenuStyleBlock`, `controlContrastStyleBlock`, and `comboBoxStyleBlock`: QSS fragments already containing markers.
    // Returns: true if QApplication::setStyleSheet was actually triggered.
    bool applyGlobalApplicationStyleBlocks(
        const QString& baseControlStyleBlock,
        const QString& tooltipStyleBlock,
        const QString& contextMenuStyleBlock,
        const QString& controlContrastStyleBlock,
        const QString& comboBoxStyleBlock,
        qint64* elapsedMsOut = nullptr,
        int* widgetCountOut = nullptr,
        int* styleLengthOut = nullptr)
    {
        QApplication* appInstance = qobject_cast<QApplication*>(QCoreApplication::instance());
        if (appInstance == nullptr)
        {
            if (elapsedMsOut != nullptr)
            {
                *elapsedMsOut = 0;
            }
            if (widgetCountOut != nullptr)
            {
                *widgetCountOut = 0;
            }
            if (styleLengthOut != nullptr)
            {
                *styleLengthOut = 0;
            }
            return false;
        }

        QString appStyleSheetText = appInstance->styleSheet();
        const QString kOldStyleSheetText = appStyleSheetText;

        // The baseline block is replaced first: when appended initially, it appears at the beginning of the stylesheet, while dedicated style blocks and local styles can still override it.
        replaceMarkedStyleBlock(
            appStyleSheetText,
            ks::ui::kBaseControlStyleBeginMarker,
            ks::ui::kBaseControlStyleEndMarker,
            baseControlStyleBlock);
        replaceMarkedStyleBlock(
            appStyleSheetText,
            kTooltipStyleBeginMarker,
            kTooltipStyleEndMarker,
            tooltipStyleBlock);
        replaceMarkedStyleBlock(
            appStyleSheetText,
            kContextMenuStyleBeginMarker,
            kContextMenuStyleEndMarker,
            contextMenuStyleBlock);
        replaceMarkedStyleBlock(
            appStyleSheetText,
            kControlContrastStyleBeginMarker,
            kControlContrastStyleEndMarker,
            controlContrastStyleBlock);
        replaceMarkedStyleBlock(
            appStyleSheetText,
            kComboBoxStyleBeginMarker,
            kComboBoxStyleEndMarker,
            comboBoxStyleBlock);

        if (styleLengthOut != nullptr)
        {
            *styleLengthOut = appStyleSheetText.length();
        }
        if (widgetCountOut != nullptr)
        {
            *widgetCountOut = appInstance->allWidgets().size();
        }
        if (appStyleSheetText == kOldStyleSheetText)
        {
            if (elapsedMsOut != nullptr)
            {
                *elapsedMsOut = 0;
            }
            return false;
        }

        QElapsedTimer applyTimer;
        applyTimer.start();
        appInstance->setStyleSheet(appStyleSheetText);
        if (elapsedMsOut != nullptr)
        {
            *elapsedMsOut = applyTimer.elapsed();
        }
        return true;
    }
}

using namespace ksword::ui::main_window;

void MainWindow::initAppearanceSettings()
{
    // appearanceInitEvent purpose: Unified logging for tracking the appearance system initialization flow.
    KLogEvent appearanceInitEvent;
    info << appearanceInitEvent << "[MainWindow] 开始初始化外观设置系统。" << eol;

    // raiseStartupDockByKey:
    // - Activate the default startup tab based on the configuration key.
    // - automatically falls back to the welcome page if the key is invalid or the target Dock is unavailable
    const auto kRaiseStartupDockByKey = [this](const QString& startupDockKey, const QString& triggerReason) {
        const QString kNormalizedKey = startupDockKey.trimmed().toLower();
        ads::CDockWidget* targetDock = nullptr;
        QString targetName = QStringLiteral("欢迎");

        if (kNormalizedKey == QStringLiteral("process"))
        {
            targetDock = dockProcess_;
            targetName = QStringLiteral("进程");
        }
        else if (kNormalizedKey == QStringLiteral("network"))
        {
            targetDock = dockNetwork_;
            targetName = QStringLiteral("网络");
        }
        else if (kNormalizedKey == QStringLiteral("memory"))
        {
            targetDock = dockMemory_;
            targetName = QStringLiteral("内存");
        }
        else if (kNormalizedKey == QStringLiteral("file"))
        {
            targetDock = dockFile_;
            targetName = QStringLiteral("文件");
        }
        else if (kNormalizedKey == QStringLiteral("driver"))
        {
            targetDock = dockDriver_;
            targetName = QStringLiteral("驱动");
        }
        else if (kNormalizedKey == QStringLiteral("kernel"))
        {
            targetDock = dockKernel_;
            targetName = QStringLiteral("内核");
        }
        else if (kNormalizedKey == QStringLiteral("kvm"))
        {
            targetDock = dockKvm_;
            targetName = QStringLiteral("虚拟化 (KVM)");
        }
        else if (kNormalizedKey == QStringLiteral("monitor"))
        {
            targetDock = dockMonitorTab_;
            targetName = QStringLiteral("监控");
        }
        else if (kNormalizedKey == QStringLiteral("hardware"))
        {
            targetDock = dockHardware_;
            targetName = QStringLiteral("硬件");
        }
        else if (kNormalizedKey == QStringLiteral("privilege"))
        {
            targetDock = dockPrivilege_;
            targetName = QStringLiteral("权限");
        }
        else if (kNormalizedKey == QStringLiteral("settings"))
        {
            // Old configurations may still save settings; since the setting has moved to the top menu, revert to the welcome page at startup to avoid automatic popups.
            targetDock = dockWelcome_;
            targetName = QStringLiteral("欢迎");
        }
        else if (kNormalizedKey == QStringLiteral("window"))
        {
            targetDock = dockWindow_;
            targetName = QStringLiteral("窗口");
        }
        else if (kNormalizedKey == QStringLiteral("registry"))
        {
            targetDock = dockRegistry_;
            targetName = QStringLiteral("注册表");
        }
        else if (kNormalizedKey == QStringLiteral("handle"))
        {
            targetDock = dockHandle_;
            targetName = QStringLiteral("句柄");
        }
        else if (kNormalizedKey == QStringLiteral("startup"))
        {
            targetDock = dockStartup_;
            targetName = QStringLiteral("启动项");
        }
        else if (kNormalizedKey == QStringLiteral("service"))
        {
            targetDock = dockService_;
            targetName = QStringLiteral("服务");
        }
        else if (kNormalizedKey == QStringLiteral("misc"))
        {
            targetDock = dockMisc_;
            targetName = QStringLiteral("杂项");
        }
        else if (kNormalizedKey == QStringLiteral("winapi"))
        {
            targetDock = dockMonitorTab_;
            targetName = QStringLiteral("监控/WinAPI");
        }
        else
        {
            targetDock = dockWelcome_;
            targetName = QStringLiteral("欢迎");
        }

        if (targetDock == nullptr)
        {
            targetDock = dockWelcome_;
            targetName = QStringLiteral("欢迎");
        }

        if (targetDock != nullptr)
        {
            ensureDockContentInitialized(targetDock);
            if (kNormalizedKey == QStringLiteral("winapi") && monitorWidget_ != nullptr)
            {
                monitorWidget_->activateMonitorTab(QStringLiteral("winapi"));
            }
            withTemporaryNonTopMostForDockSwitch([targetDock]()
                {
                    targetDock->raise();
                });
            KLogEvent startupDockEvent;
            info << startupDockEvent
                << "[MainWindow] 已激活启动默认页签, trigger="
                << triggerReason.toStdString()
                << ", key="
                << kNormalizedKey.toStdString()
                << ", tab="
                << targetName.toStdString()
                << eol;
        }
    };

    // Startup phase breakdown:
    // - Settings page is now created on-demand via the top menu;
    // - On initialization, read the appearance configuration directly from JSON, then apply the initial theme style.
    reportStartupProgress(
        86,
        QStringLiteral("main.startup.progress.read_appearance"),
        QStringLiteral("正在应用界面设置..."));
    currentAppearanceSettings_ = ks::settings::loadAppearanceSettings();

    QStyleHints* styleHints = QGuiApplication::styleHints();
    if (styleHints != nullptr)
    {
        connect(styleHints, &QStyleHints::colorSchemeChanged, this, [this](Qt::ColorScheme /*newScheme*/) {
            if (currentAppearanceSettings_.themeMode == ks::settings::ThemeMode::kFollowSystem)
            {
                applyAppearanceSettings(currentAppearanceSettings_, QStringLiteral("系统颜色方案变化"));
            }
            });
    }

    reportStartupProgress(
        89,
        QStringLiteral("main.startup.progress.apply_main_style"),
        QStringLiteral("正在应用界面设置..."));
    applyAppearanceSettings(currentAppearanceSettings_, QStringLiteral("初始化加载"));
    if (!dockLayoutRestoredFromConfig_)
    {
        reportStartupProgress(
            92,
            QStringLiteral("main.startup.progress.activate_startup_tab"),
            QStringLiteral("正在恢复界面布局..."));
        kRaiseStartupDockByKey(currentAppearanceSettings_.startupDefaultTabKey, QStringLiteral("初始化加载"));
    }
    else
    {
        reportStartupProgress(
            92,
            QStringLiteral("main.startup.progress.reuse_dock_layout"),
            QStringLiteral("正在恢复界面布局..."));
        info << appearanceInitEvent << "[MainWindow] 已恢复 ADS 布局，跳过启动默认页签覆盖。" << eol;
    }
    info << appearanceInitEvent << "[MainWindow] 外观设置系统初始化完成。" << eol;
}

void MainWindow::applyAppearanceSettings(
    const ks::settings::AppearanceSettings& settings,
    const QString& triggerReason)
{
    KLogEvent appearanceApplyEvent;
    QElapsedTimer appearanceApplyTimer;
    appearanceApplyTimer.start();

    const ks::settings::AppearanceSettings kPreviousSettings = currentAppearanceSettings_;
    const bool kIsInitialAppearanceApply = (triggerReason == QStringLiteral("初始化加载"));
    const bool kDarkModeEnabled = isDarkModeEffective(settings);
    const bool kThemeColorChanged =
        kIsInitialAppearanceApply
        || kPreviousSettings.customThemeColor.compare(settings.customThemeColor, Qt::CaseInsensitive) != 0;
    const bool kMainBackgroundColorChanged =
        kIsInitialAppearanceApply
        || kPreviousSettings.customMainBackgroundColor.compare(
            settings.customMainBackgroundColor,
            Qt::CaseInsensitive) != 0;
    // When a system color scheme notification arrives, recalculating with previousSettings yields the new color scheme.
    // Directly read the theme module's current state to detect the actual light/dark switch of FollowSystem.
    // This check must remain before updating the theme seed: the seed affects only colors, not the dark/light flag, but
    // snapshot collection depends on it. Evaluating early ensures capturing the theme state before the color change.
    const bool kEffectiveThemeChanged =
        kIsInitialAppearanceApply || ksword_theme::isDarkModeEnabled() != kDarkModeEnabled;
    // themeVisualRefreshRequired: Used as the sole condition for rebuilding all dedicated theme controls.
    // Any change in light/dark theme, accent color, or independent main background color must trigger the same refresh entry point.
    const bool kThemeVisualRefreshRequired =
        kEffectiveThemeChanged || kThemeColorChanged || kMainBackgroundColorChanged;
    // staleThemeColorSnapshot usage: record the values of all static theme roles before the theme seed changes.
    // ColorHex()/accentHex()/semantic colors written to styleSheet during page construction are hardcoded as #RRGGBB at that moment
    // and do not update when the theme seed changes; the snapshot provides the 'old value -> new value' basis for rewriting.
    // On the first application, there are no existing controls, so capturing would only waste time.
    const ks::ui::ThemeColorSnapshot kStaleThemeColorSnapshot =
        (!kIsInitialAppearanceApply && kThemeVisualRefreshRequired)
        ? ks::ui::captureThemeColorSnapshot()
        : ks::ui::ThemeColorSnapshot();
    // The seed must be updated before reading any accentColor to ensure the palette, QSS, and drawing controls use the same theme color.
    ksword_theme::setPrimaryAccentColor(settings.customThemeColor);
    // The main background uses an independent seed and does not participate in accent color offset; null values continue to follow the current light/dark theme.
    ksword_theme::setMainBackgroundColor(settings.customMainBackgroundColor);
    const bool kBackgroundPathChanged =
        kIsInitialAppearanceApply
        || kPreviousSettings.backgroundImagePath.compare(
            settings.backgroundImagePath,
            Qt::CaseInsensitive) != 0;
    const bool kBackgroundChanged =
        kMainBackgroundColorChanged
        || kBackgroundPathChanged
        || kPreviousSettings.backgroundOpacityPercent != settings.backgroundOpacityPercent
        || kPreviousSettings.backgroundTranslucencyMaterial.compare(
            settings.backgroundTranslucencyMaterial,
            Qt::CaseInsensitive) != 0
        // All three glass effect settings take effect within the rebuildWindowBackgroundBrush chain (blur copy, system
        // tint gradientColor, root container custom tint), so they are merged into a single background refresh condition.
        || kPreviousSettings.backgroundBlurRadiusPercent != settings.backgroundBlurRadiusPercent
        || kPreviousSettings.acrylicTintOpacityPercent != settings.acrylicTintOpacityPercent
        || kPreviousSettings.desktopTintOpacityPercent != settings.desktopTintOpacityPercent;
    // Background transparency relies on the WA_TranslucentBackground declaration at startup; at runtime, it only prompts that a restart is required for the change to take effect.
    const bool kBackgroundTransparencyChanged =
        !kIsInitialAppearanceApply
        && kPreviousSettings.backgroundTransparencyEnabled != settings.backgroundTransparencyEnabled;
    if (kBackgroundTransparencyChanged)
    {
        KLogEvent transparencyNoticeEvent;
        warn << transparencyNoticeEvent
            << "[MainWindow] 背景穿透设置已保存，重启 Ksword 后生效。"
            << eol;
    }
    const bool kFontChanged =
        kIsInitialAppearanceApply
        || kPreviousSettings.fontFamily.compare(settings.fontFamily, Qt::CaseInsensitive) != 0
        || kPreviousSettings.textAntialiasingEnabled != settings.textAntialiasingEnabled;
    const bool kScrollBarStyleChanged =
        kIsInitialAppearanceApply
        || kPreviousSettings.useWideScrollBars != settings.useWideScrollBars
        || kPreviousSettings.scrollBarAutoHideEnabled != settings.scrollBarAutoHideEnabled;
    const bool kSliderWheelChanged =
        kIsInitialAppearanceApply
        || kPreviousSettings.sliderWheelAdjustEnabled != settings.sliderWheelAdjustEnabled;
    const bool kSmoothScrollingChanged =
        kIsInitialAppearanceApply
        || kPreviousSettings.smoothScrollingEnabled != settings.smoothScrollingEnabled;
    const bool kTopMostChanged =
        kIsInitialAppearanceApply
        || kPreviousSettings.startupTopMostEnabled != settings.startupTopMostEnabled;
    const bool kNotificationSettingsChanged =
        kIsInitialAppearanceApply
        || kPreviousSettings.notificationCardsEnabled != settings.notificationCardsEnabled
        || kPreviousSettings.notificationMinimumLevel != settings.notificationMinimumLevel
        || kPreviousSettings.notificationLogDisplaySeconds != settings.notificationLogDisplaySeconds
        || kPreviousSettings.notificationDisplayPlacement != settings.notificationDisplayPlacement
        || kPreviousSettings.notificationStackDirection != settings.notificationStackDirection;
    const bool kRuntimeProgressRequired =
        !kIsInitialAppearanceApply
        && (kThemeVisualRefreshRequired || kBackgroundChanged || kFontChanged);

    currentAppearanceSettings_ = settings;
    // The permission button visibility depends solely on this cached setting, so apply it immediately afterward.
    // Call unconditionally rather than only when changed: this is a pure property write with no reconstruction or
    // query, which is cheaper than 'checking which fields changed' and avoids a condition that could be missed.
    applyPrivilegeButtonVisibility();
    ks::ui::DetailLayoutRegistry::applyGlobalScheme(settings.detailDisplayScheme);
    if (kSmoothScrollingChanged)
    {
        ks::ui::setGlobalSmoothScrollingEnabled(settings.smoothScrollingEnabled);
    }
    RuntimeAppearanceProgress runtimeProgress(kRuntimeProgressRequired);

    // previousBackgroundImageReady purpose: Reads only from the memory cache before path switching to determine if the transparency policy has changed.
    const bool kPreviousBackgroundImageReady =
        isCachedBackgroundImageReady(kPreviousSettings.backgroundImagePath);
    // Purpose of backgroundReadinessChanged: Consume the async validation completion flag to trigger a single visual rebuild upon readiness.
    const bool kBackgroundReadinessChanged = backgroundReadinessRefreshPending_;
    backgroundReadinessRefreshPending_ = false;
    if (kIsInitialAppearanceApply || kBackgroundPathChanged)
    {
        runtimeProgress.update(
            8,
            QStringLiteral("main.runtime_appearance.progress.background"),
            QStringLiteral("正在应用界面设置..."));
        // Only asynchronously validate when the path is first loaded or genuinely changed; theme and scrollbar changes do not access the file system.
        queueBackgroundImageValidation(settings.backgroundImagePath);
    }
    // Purpose of windowTranslucencyActive: Whether the window declared per-pixel transparency at startup.
    // This state is fixed for the process lifetime; changing the configuration at runtime only prompts a restart.
    const bool kWindowTranslucencyActive = testAttribute(Qt::WA_TranslucentBackground);
    // enableDockContentTransparency: Determines whether the Dock content layer is transparent.
    // The background image must be visible when ready; when translucent window backgrounds are enabled, transparency is
    // also required, otherwise the opaque Dock surface would cover the Mica material, leaving only the menu bar visible.
    const bool kEnableDockContentTransparency =
        isCachedBackgroundImageReady(settings.backgroundImagePath) || kWindowTranslucencyActive;
    const bool kDockTransparencyChanged =
        kIsInitialAppearanceApply
        || kBackgroundReadinessChanged
        || (kPreviousBackgroundImageReady || kWindowTranslucencyActive) != kEnableDockContentTransparency;
    const bool kMainStyleRefreshRequired =
        kThemeVisualRefreshRequired
        || kDockTransparencyChanged
        || kScrollBarStyleChanged;
    const bool kBackgroundRefreshRequired =
        kIsInitialAppearanceApply
        || kEffectiveThemeChanged
        || kBackgroundChanged
        || kBackgroundReadinessChanged;
    const bool kFloatingDockRefreshRequired = kMainStyleRefreshRequired || kBackgroundRefreshRequired;
    qint64 globalAppStyleApplyMs = 0;
    int globalAppStyleWidgetCount = 0;
    int globalAppStyleLength = 0;
    qint64 styleSheetApplyElapsedMs = 0;
    ks::ui::SvgThemeIconApplyResult svgThemeIconApplyResult;
    ks::ui::ThemeColorRemapResult themeColorRemapResult;
    bool globalAppStyleChanged = false;
    bool mainStyleSheetChanged = false;

    if (kTopMostChanged)
    {
        setPinnedWindowState(currentAppearanceSettings_.startupTopMostEnabled, false);
    }

    if (kThemeVisualRefreshRequired)
    {
        runtimeProgress.update(
            16,
            QStringLiteral("main.runtime_appearance.progress.theme"),
            QStringLiteral("正在应用界面设置..."));

        ksword_theme::setDarkModeEnabled(kDarkModeEnabled);
        const QColor kWindowBackgroundColor = ksword_theme::mainBackgroundColor();
        const QColor kWindowTextColor = ksword_theme::mainBackgroundTextColor();
        const QColor kTextColor = ksword_theme::textPrimaryColor();
        const QColor kBaseColor = ksword_theme::surfaceColor();
        const QColor kAlternateBaseColor = ksword_theme::surfaceAltColor();
        const QColor kMidColor = ksword_theme::borderColor();

        // Windows 11 background control requirements:
        // Even for pure black or white, explicitly set the Window color to prevent the system from taking over the background.
        QPalette mainPalette = palette();
        mainPalette.setColor(QPalette::Window, kWindowBackgroundColor);
        mainPalette.setColor(QPalette::WindowText, kWindowTextColor);
        mainPalette.setColor(QPalette::Base, kBaseColor);
        mainPalette.setColor(QPalette::AlternateBase, kAlternateBaseColor);
        mainPalette.setColor(QPalette::Mid, kMidColor);
        mainPalette.setColor(QPalette::Midlight, ksword_theme::borderStrongColor());
        mainPalette.setColor(QPalette::Dark, ksword_theme::paletteDarkColor());
        mainPalette.setColor(QPalette::Text, kTextColor);
        mainPalette.setColor(QPalette::PlaceholderText, ksword_theme::textSecondaryColor());
        mainPalette.setColor(QPalette::Button, kAlternateBaseColor);
        mainPalette.setColor(QPalette::ButtonText, kTextColor);
        mainPalette.setColor(QPalette::ToolTipBase, kBaseColor);
        mainPalette.setColor(QPalette::ToolTipText, kTextColor);
        mainPalette.setColor(QPalette::Highlight, ksword_theme::primaryBlueColor);
        mainPalette.setColor(QPalette::HighlightedText, ksword_theme::onAccentColor());
        QApplication::setPalette(mainPalette);
        setPalette(mainPalette);
        // In background transparency mode, the main window cannot self-draw an opaque background, or else the transparent pixels will be covered by the palette's base color.
        setAutoFillBackground(!testAttribute(Qt::WA_TranslucentBackground));

        QPalette toolTipPalette = mainPalette;
        toolTipPalette.setColor(QPalette::ToolTipBase, kBaseColor);
        toolTipPalette.setColor(QPalette::ToolTipText, kTextColor);
        QToolTip::setPalette(toolTipPalette);

        globalAppStyleChanged = applyGlobalApplicationStyleBlocks(
            ks::ui::buildGlobalBaseControlStyleBlock(),
            buildGlobalTooltipStyleBlock(kDarkModeEnabled),
            buildGlobalContextMenuStyleBlock(kDarkModeEnabled),
            buildGlobalControlContrastStyleBlock(kDarkModeEnabled),
            buildGlobalComboBoxStyleBlock(kDarkModeEnabled),
            &globalAppStyleApplyMs,
            &globalAppStyleWidgetCount,
            &globalAppStyleLength);
        if (globalAppStyleChanged || kIsInitialAppearanceApply)
        {
            dbg << appearanceApplyEvent
                << "[MainWindow] QApplication 全局 Tooltip/QMenu 样式"
                << (globalAppStyleChanged ? "已应用" : "未变化跳过")
                << ", elapsedMs=" << globalAppStyleApplyMs
                << ", widgetCount=" << globalAppStyleWidgetCount
                << ", styleLength=" << globalAppStyleLength
                << eol;
        }

        // When the color theme changes, open standard and custom dialogs should also sync their themes.
        ks::ui::refreshGlobalMessageBoxTheme();
        ks::ui::refreshGlobalDialogTheme();
        // Synchronize chroming for opened native titlebar child windows to keep the titlebar integrated with the theme background.
        ks::ui::refreshAllWindowChrome();

        if (pDockManager_ != nullptr)
        {
            QPalette dockPalette = pDockManager_->palette();
            dockPalette.setColor(QPalette::Window, kWindowBackgroundColor);
            dockPalette.setColor(QPalette::WindowText, kWindowTextColor);
            dockPalette.setColor(QPalette::Text, kTextColor);
            pDockManager_->setPalette(dockPalette);
            // In transparent background mode, DockManager cannot self-draw an opaque background, or it will completely cover the mica material.
            pDockManager_->setAutoFillBackground(!testAttribute(Qt::WA_TranslucentBackground));
        }
    }

    if (kFontChanged)
    {
        runtimeProgress.update(
            46,
            QStringLiteral("main.runtime_appearance.progress.font"),
            QStringLiteral("正在应用界面设置..."));

        const QString kRequestedFontFamily = settings.fontFamily.trimmed();
        // applicationFont usage: restore the startup system baseline if the family is empty; otherwise, retain other font attributes for the specified family.
        QFont applicationFont = kRequestedFontFamily.isEmpty()
            ? startupSystemFont_
            : QApplication::font();
        if (!kRequestedFontFamily.isEmpty())
        {
            applicationFont.setFamily(kRequestedFontFamily);
        }
        const QFont::StyleStrategy kRequestedFontStyleStrategy = settings.textAntialiasingEnabled
            ? QFont::PreferAntialias
            : QFont::NoAntialias;
        applicationFont.setStyleStrategy(kRequestedFontStyleStrategy);
        // applicationFontChanged: Compare full fonts to ensure all system baseline attributes are restored from the custom font.
        const bool kApplicationFontChanged = QApplication::font() != applicationFont;
        if (kApplicationFontChanged)
        {
            QApplication::setFont(applicationFont);
        }
        applyApplicationFontToItemViews(applicationFont);
        QToolTip::setFont(QApplication::font());
    }

    // Write wheel and text rendering strategies to global properties. These properties are no longer written when saving unrelated configurations.
    if ((kSliderWheelChanged || kFontChanged)
        && qobject_cast<QApplication*>(QCoreApplication::instance()) != nullptr)
    {
        QApplication* const kAppInstance = qobject_cast<QApplication*>(QCoreApplication::instance());
        if (kSliderWheelChanged)
        {
            kAppInstance->setProperty("ksword_slider_wheel_adjust_enabled", settings.sliderWheelAdjustEnabled);
        }
        if (kFontChanged)
        {
            kAppInstance->setProperty("ksword_text_antialiasing_enabled", settings.textAntialiasingEnabled);
        }
    }

    if (kMainStyleRefreshRequired)
    {
        runtimeProgress.update(
            66,
            QStringLiteral("main.runtime_appearance.progress.refresh"),
            QStringLiteral("正在应用界面设置..."));

        const QString kAppearanceStyleSheet =
            kQssMainWindowTabWidget
            + kQssMainWindowDockStyle
            + buildAppearanceOverlayStyleSheet(
                currentAppearanceSettings_,
                kDarkModeEnabled,
                kEnableDockContentTransparency);

        QElapsedTimer styleSheetApplyTimer;
        styleSheetApplyTimer.start();
        mainStyleSheetChanged = (styleSheet() != kAppearanceStyleSheet);
        if (mainStyleSheetChanged)
        {
            setStyleSheet(kAppearanceStyleSheet);
        }
        ensureGlobalTableSelectionOutlineFilterInstalled();
        ensureGlobalComboPopupThemeFilterInstalled();
        applyResizeBorderOverlayStyle();
        updateResizeBorderOverlays();
        if (pDockManager_ != nullptr)
        {
            if (!pDockManager_->styleSheet().isEmpty())
            {
                pDockManager_->setStyleSheet(QString());
            }
            pDockManager_->setAttribute(Qt::WA_StyledBackground, false);
            refreshAdsDockTabVisualIdentities(pDockManager_);
        }
        styleSheetApplyElapsedMs = styleSheetApplyTimer.elapsed();
    }

    if (kIsInitialAppearanceApply)
    {
        reportStartupProgress(
            90,
            QStringLiteral("main.startup.progress.refresh_theme_widgets"),
            QStringLiteral("正在应用界面设置..."));
    }

    if (!kIsInitialAppearanceApply && kDockTransparencyChanged)
    {
        repairKernelDockAfterLayoutRestore(QStringLiteral("applyAppearanceSettings"));
    }

    if (customTitleBar_ != nullptr && kTopMostChanged && !kThemeVisualRefreshRequired)
    {
        customTitleBar_->setPinnedState(windowPinned_);
    }

    if (kBackgroundRefreshRequired)
    {
        runtimeProgress.update(
            78,
            QStringLiteral("main.runtime_appearance.progress.background"),
            QStringLiteral("正在应用界面设置..."));
        rebuildWindowBackgroundBrush(true);
    }
    if (kFloatingDockRefreshRequired && pDockManager_ != nullptr)
    {
        const QList<ads::CFloatingDockContainer*> kFloatingWidgets = pDockManager_->floatingWidgets();
        for (ads::CFloatingDockContainer* floatingWidget : kFloatingWidgets)
        {
            applyFloatingDockContainerAppearance(floatingWidget);
            if (floatingWidget != nullptr)
            {
                floatingWidget->update();
            }
        }
    }
    if (notificationCardManager_ != nullptr)
    {
        if (kNotificationSettingsChanged)
        {
            notificationCardManager_->applySettings(currentAppearanceSettings_);
        }
    }
    if (kThemeVisualRefreshRequired)
    {
        refreshThemeDependentVisuals(kDarkModeEnabled);

        // The dedicated refresh path covers only a few panels that provide refreshThemeVisuals. Other
        // pages store static theme colors in their own styleSheet, which takes precedence over global QSS.
        // Uniformly rewrite the existing stylesheets based on the snapshot to pull them back to the current theme.
        // Must be executed after each panel actively rebuilds to avoid rescanning newly rebuilt colors and performing useless work.
        themeColorRemapResult = ks::ui::remapStaleThemeColors(kStaleThemeColorSnapshot);
        if (themeColorRemapResult.rewrittenWidgetCount > 0
            || themeColorRemapResult.rewrittenPaletteWidgetCount > 0
            || themeColorRemapResult.ambiguousColorCount > 0)
        {
            dbg << appearanceApplyEvent
                << "[MainWindow] 存量样式表主题色重映射"
                << ", mappedColors=" << themeColorRemapResult.mappedColorCount
                << ", ambiguousColors=" << themeColorRemapResult.ambiguousColorCount
                << ", inspectedWidgets=" << themeColorRemapResult.inspectedWidgetCount
                << ", rewrittenWidgets=" << themeColorRemapResult.rewrittenWidgetCount
                << ", rewrittenPalettes=" << themeColorRemapResult.rewrittenPaletteWidgetCount
                << eol;
        }

        runtimeProgress.update(
            88,
            QStringLiteral("main.runtime_appearance.progress.svg_icons"),
            QStringLiteral("正在集中适配 SVG 图标..."));
        QApplication* const kApplicationPointer =
            qobject_cast<QApplication*>(QCoreApplication::instance());
        const bool kUsesDefaultThemeColor =
            ksword_theme::primaryBlueColor == ksword_theme::defaultPrimaryAccentColor();
        // SVG icon batch processing must occur after theme visual reconstruction in each panel to prevent subsequent refreshes from overwriting coloring results.
        // Callback only updates startup screen text and progress; does not change theme load order.
        const auto kSvgProgressCallback =
            [this, kIsInitialAppearanceApply](const int processedCount, const int totalCount)
            {
                if (!kIsInitialAppearanceApply)
                {
                    return;
                }
                const int kSvgProgressValue =
                    totalCount > 0
                    ? 88 + qBound(
                        0,
                        static_cast<int>(
                            (static_cast<qint64>(processedCount) * 3) /
                            totalCount),
                        3)
                    : 91;
                reportStartupProgress(
                    kSvgProgressValue,
                    totalCount > 0
                        ? QStringLiteral("main.startup.progress.recolor_svg_icons_count")
                        : QStringLiteral("main.startup.progress.recolor_svg_icons_skipped"),
                    totalCount > 0
                        ? QStringLiteral("正在集中适配 SVG 图标（%1/%2）...")
                            .arg(processedCount)
                            .arg(totalCount)
                        : QStringLiteral("默认主题色无需重新着色 SVG 图标。"));
            };
        svgThemeIconApplyResult =
            ks::ui::SvgThemeIconManager::instance().applyToApplication(
                kApplicationPointer,
                ksword_theme::primaryBlueColor,
                kUsesDefaultThemeColor,
                kSvgProgressCallback);
    }

    if (kIsInitialAppearanceApply)
    {
        reportStartupProgress(
            92,
            QStringLiteral("main.startup.progress.queue_kernel_dock_check"),
            QStringLiteral("即将完成..."));
        QTimer::singleShot(0, this, [this]()
            {
                repairKernelDockAfterLayoutRestore(QStringLiteral("applyAppearanceSettings-deferred-0"));
            });
    }

    runtimeProgress.update(
        100,
        QStringLiteral("main.runtime_appearance.progress.complete"),
        QStringLiteral("正在应用界面设置..."));

    const QString kEffectiveModeText = kDarkModeEnabled ? QStringLiteral("dark") : QStringLiteral("light");
    info << appearanceApplyEvent
        << "[MainWindow] 已应用外观设置，触发来源="
        << triggerReason.toStdString()
        << "，theme_mode="
        << ks::settings::themeModeToJsonText(settings.themeMode).toStdString()
        << "，effective_mode="
        << kEffectiveModeText.toStdString()
        << "，background_path="
        << settings.backgroundImagePath.toStdString()
        << "，opacity="
        << settings.backgroundOpacityPercent
        << "%, themeChanged="
        << (kEffectiveThemeChanged ? "true" : "false")
        << ", backgroundChanged="
        << (kBackgroundChanged ? "true" : "false")
        << ", mainBackgroundColorChanged="
        << (kMainBackgroundColorChanged ? "true" : "false")
        << ", fontChanged="
        << (kFontChanged ? "true" : "false")
        << ", mainStyleRefresh="
        << (kMainStyleRefreshRequired ? "true" : "false")
        << ", styleChanged="
        << (mainStyleSheetChanged ? "true" : "false")
        << ", svgIconVisited="
        << svgThemeIconApplyResult.visitedWidgetCount
        << ", svgIconChanged="
        << svgThemeIconApplyResult.recoloredIconCount
        << ", svgIconCacheHits="
        << svgThemeIconApplyResult.cacheHitCount
        << ", svgIconDefaultSkipped="
        << (svgThemeIconApplyResult.skippedDefaultTheme ? "true" : "false")
        << ", svgIconElapsedMs="
        << svgThemeIconApplyResult.elapsedMilliseconds
        << ", styleRemapWidgets="
        << themeColorRemapResult.rewrittenWidgetCount
        << ", styleRemapPalettes="
        << themeColorRemapResult.rewrittenPaletteWidgetCount
        << ", styleRemapAmbiguous="
        << themeColorRemapResult.ambiguousColorCount
        << "，styleElapsedMs="
        << styleSheetApplyElapsedMs
        << "，elapsedMs="
        << appearanceApplyTimer.elapsed()
        << eol;
}

void MainWindow::refreshThemeDependentVisuals(const bool darkModeEnabled)
{
    // Dedicated theme refresh is uniformly dispatched from here; the caller has already updated the ksword_theme seed and the main window QSS.
    // Each refresh function only rebuilds the visual state, without triggering background data enumeration or changing functional configuration.
    if (processWidget_ != nullptr)
    {
        processWidget_->refreshThemeVisuals();
    }
    if (windowWidget_ != nullptr)
    {
        windowWidget_->refreshThemeVisuals();
    }

    if (customTitleBar_ != nullptr)
    {
        // Even if the dark/light state hasn't changed, call this entry point to rebuild the title bar QSS dependent on the custom theme color.
        customTitleBar_->setDarkModeEnabled(darkModeEnabled);
        customTitleBar_->setPinnedState(windowPinned_);
        customTitleBar_->setCaptureProtectionState(captureProtectionEnabled_);
        syncCustomTitleBarMaximizedState();
    }

    // Native frame, privilege buttons, and title bar action buttons all read the current theme module state.
    applyNativeWindowFrameVisualStyle();
    refreshPrivilegeStatusButtons();
    refreshTitleActionButtonStyles();

    if (progressWidget_ != nullptr)
    {
        progressWidget_->refreshThemeVisuals();
    }
    if (notificationCardManager_ != nullptr)
    {
        notificationCardManager_->refreshVisuals();
    }
}

bool MainWindow::isDarkModeEffective(const ks::settings::AppearanceSettings& settings) const
{
    if (settings.themeMode == ks::settings::ThemeMode::kDark)
    {
        return true;
    }
    if (settings.themeMode == ks::settings::ThemeMode::kLight)
    {
        return false;
    }

    QStyleHints* styleHints = QGuiApplication::styleHints();
    if (styleHints == nullptr)
    {
        return false;
    }
    return styleHints->colorScheme() == Qt::ColorScheme::Dark;
}
