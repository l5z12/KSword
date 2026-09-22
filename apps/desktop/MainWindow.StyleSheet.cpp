#include "MainWindow.h"
#include "kernel_dock/KernelDock.h"
#include <QAbstractScrollArea>
#include <QTextEdit>
#include <QTabWidget>
#include <QTabBar>
#include <QToolButton>
#include <QHeaderView>
#include <QWidget>
#include <QLabel>
#include <QPushButton>
#include <QScrollBar>
#include <QScrollArea>
#include <QToolTip>
#include <QTableView>
#pragma warning(disable: 4996)
#include "Framework.h"
#include "include/ads/AutoHideTab.h"
#include "include/ads/DockAreaTitleBar.h"
#include "include/ads/DockAreaWidget.h"
#include "include/ads/DockWidgetTab.h"
#include "include/ads/FloatingDockContainer.h"
#include "PluginHost.h"
#include "ui/DockTabInteraction.h"
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

using namespace ksword::ui::main_window;

QString MainWindow::buildAppearanceOverlayStyleSheet(
    const ks::settings::AppearanceSettings& settings,
    const bool darkModeEnabled,
    const bool enableDockContentTransparency) const
{
    // tooltipStyle:
    // - Force global tooltips to use themed background and text;
    // - Fix the issue where tooltips remain white in dark mode.
    const int kScrollBarHoverExtentPx = settings.useWideScrollBars ? 12 : 7;
    const int kScrollBarExtentPx = settings.scrollBarAutoHideEnabled ? 3 : kScrollBarHoverExtentPx;
    const int kScrollBarRadiusPx = 0;
    const QString kWindowBackgroundText = ksword_theme::mainBackgroundColorHex();
    const QString kWindowTextColor = ksword_theme::mainBackgroundTextColorHex();
    const QString kSurfaceBackgroundText = ksword_theme::surfaceColorHex();
    const QString kSurfaceAltBackgroundText = ksword_theme::surfaceAltColorHex();
    const QString kSurfaceMutedBackgroundText = ksword_theme::surfaceMutedColorHex();
    const QString kBorderColorText = ksword_theme::borderColorHex();
    const QString kBorderStrongColorText = ksword_theme::borderStrongColorHex();
    const QString kPrimaryTextColor = ksword_theme::textPrimaryColorHex();
    const QString kDisabledTextColor = ksword_theme::textDisabledColorHex();
    const QString kSelectedTextColor = ksword_theme::onAccentHex();
    const QString kActiveThemeColor = ksword_theme::kPrimaryBlueHex;
    const QString kActiveThemeHoverColor = ksword_theme::controlAccentHoverHex();
    const QString kActiveThemePressedColor = ksword_theme::controlAccentPressedHex();
    const QString kControlAccentTextColor = ksword_theme::themeColorName(
        ksword_theme::maximumContrastMonochromeColor(ksword_theme::controlAccentColor()));
    const QString kSubtleThemeColor = ksword_theme::primaryBlueSubtleHex();
    const QColor kScrollBarBaseColor = settings.scrollBarAutoHideEnabled
        ? ksword_theme::ensureTextContrast(
            ksword_theme::blendColors(
                ksword_theme::surfaceColor(),
                ksword_theme::controlAccentColor(),
                160),
            ksword_theme::surfaceColor(),
            3.0)
        : ksword_theme::controlAccentColor();
    const QString kScrollBarHandleColor = ksword_theme::themeColorName(kScrollBarBaseColor);
    const QString kScrollBarHandleHoverColor = ksword_theme::controlAccentHoverHex();
    const QString kPanelBackgroundColor = ksword_theme::rgbaColorName(
        ksword_theme::surfaceColor(),
        darkModeEnabled ? 240 : 242);
    const QString kPanelBorderColor = kBorderColorText;
    const QString kInactiveTabColor = kSurfaceAltBackgroundText;
    const QString kInactiveTabTextColor = kPrimaryTextColor;
    const QString kActiveTabColor = ksword_theme::activeTabBackgroundHex();
    const QString kActiveTabTextColor = ksword_theme::activeTabTextHex();
    // normalTabHoverColor:
    // - Controls only the unselected hover state of a standard QTabBar;
    // - In light mode, use an explicit light gray to avoid inheriting or falling back to a black background;
    // - ADS Dock tabs continue to use the dockTabChildHoverColor below; do not modify it here.
    const QString kNormalTabHoverColor = ksword_theme::themeColorName(
        darkModeEnabled ? ksword_theme::primaryBlueSubtleColor() : ksword_theme::surfaceMutedColor());
    // dockActiveTabTextColor:
    // - Only control the text color of the selected ADS Dock tab.
    // - Use white text for both light and dark modes to fix low-contrast text on dark active backgrounds.
    // - Standard QTabBar still uses activeTabTextColor to avoid expanding the scope of style impact.
    const QString kDockActiveTabTextColor = ksword_theme::themeColorName(
        dockTabTextColor(true));
    const QString kTabHoverColor = darkModeEnabled
        ? ksword_theme::themeColorName(ksword_theme::primaryBlueSubtleColor())
        : kSubtleThemeColor;
    // dockTabChildHoverColor:
    // - ADS Dock tabs are often rendered by a combination of QLabel and QWidget:
    // - In dark mode, if child controls remain transparent or inherit an incorrect palette, a near-white background may show.
    // - Therefore, use an explicit background color for both parent and child on hover to avoid transparency or palette fallback.
    const QString kDockTabChildHoverColor = kTabHoverColor;
    const QString kTooltipStyle = QStringLiteral(
        "QToolTip{"
        "  background-color:%1 !important;"
        "  color:%2 !important;"
        "  border:1px solid %3 !important;"
        "  padding:4px 6px;"
        "  border-radius:3px;"
        "}")
        .arg(kSurfaceBackgroundText)
        .arg(kPrimaryTextColor)
        .arg(kBorderStrongColorText);

    // dockBackgroundPolicyStyle:
    // - When a background image is available: make all Dock-related containers transparent to fully reveal the background image.
    // - When the background image is unavailable, keep DockManager using palette(window) as the background color.
    const QString kDockBackgroundPolicyStyle = enableDockContentTransparency
        ? QStringLiteral(
            "QDockWidget,"
            "QDockWidget::title,"
            "QDockWidget > QWidget,"
            "ads--CDockManager,"
            "ads--CDockContainerWidget,"
            "ads--CDockAreaWidget,"
            "ads--CDockAreaTitleBar,"
            "ads--CFloatingDockContainer,"
            "ads--CDockAreaTabBar{"
            "  background:transparent !important;"
            "  background-color:transparent !important;"
            "  color:%1 !important;"
            "}")
        : QStringLiteral(
            "ads--CDockManager{"
            "  background-color:palette(window) !important;"
            "  color:%1 !important;"
            "}"
            "ads--CDockContainerWidget,"
            "ads--CDockAreaWidget,"
            "ads--CFloatingDockContainer{"
            "  background:transparent !important;"
            "  background-color:transparent !important;"
            "}"
            "ads--CDockAreaTitleBar{"
            "  background:transparent !important;"
            "  background-color:transparent !important;"
            "  color:%1 !important;"
            "}");

    // rootStyle:
    // - The main window continues to use palette(window) (including background image brushes) as the source for the background image;
    // - Overlay the Dock background policy style.
    const QString kRootStyle = QStringLiteral(
        "QMainWindow{"
        "  background-color:palette(window) !important;"
        "  color:%1;"
        "}")
        .arg(kWindowTextColor)
        + kDockBackgroundPolicyStyle.arg(
            kWindowTextColor);

    // depthOverlayStyle:
    // - Adds borders, rounded corners, and subtle shadows to Dock panels, groups, tables, and tabs.
    // - Apply a depth-based contrast color offset for the current Tab to prevent blue icons from becoming invisible on a blue background.
    const QString kDepthOverlayStyle = QStringLiteral(
        "ads--CDockAreaWidget{"
        "  border:1px solid %1 !important;"
        "  border-radius:8px;"
        "  background:%2 !important;"
        "}"
        "ads--CDockAreaTitleBar{"
        "  border-bottom:none !important;"
        "  padding:0px;"
        "}"
        "QGroupBox,QFrame#card,QWidget#card{"
        "  border:1px solid %1;"
        "  border-radius:8px;"
        "  background:%2;"
        "  margin-top:12px;"
        "}"
        "QGroupBox{"
        "  padding-top:6px;"
        "}"
        "QGroupBox::title{"
        "  subcontrol-origin:margin;"
        "  subcontrol-position:top left;"
        "  left:10px;"
        "  padding:0px 4px;"
        "  background:%2;"
        "  color:%3;"
        "}"
        "QTabWidget::pane{"
        "  border:none !important;"
        "  border-radius:0px;"
        "  background:%2 !important;"
        "  top:0px;"
        "}"
        "QHeaderView::section{"
        "  font-weight:600;"
        "  min-height:24px;"
        "}")
        .arg(kPanelBorderColor)
        .arg(kPanelBackgroundColor)
        .arg(kPrimaryTextColor);

    // scrollBarOverlayStyle:
    // - Change the global track to transparent to reduce occlusion.
    // - Switch between narrow and wide scrollbars based on settings, supporting default weak display and hover enhancement.
    const QString kScrollBarOverlayStyle = QStringLiteral(
        "QScrollBar:vertical{"
        "  background:transparent !important;"
        "  border:none !important;"
        "  width:%1px !important;"
        "  margin:0px;"
        "}"
        "QScrollBar:horizontal{"
        "  background:transparent !important;"
        "  border:none !important;"
        "  height:%1px !important;"
        "  margin:0px;"
        "}"
        "QScrollBar:vertical:hover{"
        "  width:%5px !important;"
        "}"
        "QScrollBar:horizontal:hover{"
        "  height:%5px !important;"
        "}"
        "QScrollBar::handle:vertical{"
        "  background-color:%3 !important;"
        "  min-height:24px;"
        "  border-radius:%2px;"
        "}"
        "QScrollBar::handle:horizontal{"
        "  background-color:%3 !important;"
        "  min-width:24px;"
        "  border-radius:%2px;"
        "}"
        "QScrollBar::handle:vertical:hover,QScrollBar::handle:horizontal:hover{"
        "  background-color:%4 !important;"
        "}"
        "QScrollBar::add-line,QScrollBar::sub-line,QScrollBar::add-page,QScrollBar::sub-page{"
        "  background:transparent !important;"
        "  border:none !important;"
        "  width:0px;"
        "  height:0px;"
        "}")
        .arg(kScrollBarExtentPx)
        .arg(kScrollBarRadiusPx)
        .arg(kScrollBarHandleColor)
        .arg(kScrollBarHandleHoverColor)
        .arg(kScrollBarHoverExtentPx);

    // sharedOverlayStyle:
    // - Unify hover/pressed and Tab highlight styles;
    // - The current tab uses a contrasting color to prevent icons from blending with the selected background.
    const QString kButtonInteractionStyle = QStringLiteral(
        "QPushButton,QToolButton{"
        "  background-color:%4 !important;"
        "  color:%5 !important;"
        "  border:1px solid %6 !important;"
        "}"
        "QPushButton:hover,QToolButton:hover{"
        "  background-color:%1 !important;"
        "  color:%3 !important;"
        "  border-color:%1 !important;"
        "}"
        "QPushButton:pressed,QToolButton:pressed{"
        "  background-color:%2 !important;"
        "  color:%3 !important;"
        "  border-color:%2 !important;"
        "}"
        "QPushButton:disabled,QToolButton:disabled{"
        "  background-color:%7 !important;"
        "  color:%8 !important;"
        "  border-color:%6 !important;"
        "}")
        .arg(kActiveThemeHoverColor)
        .arg(kActiveThemePressedColor)
        .arg(kControlAccentTextColor)
        .arg(darkModeEnabled ? kSurfaceAltBackgroundText : kSubtleThemeColor)
        .arg(kPrimaryTextColor)
        .arg(kBorderStrongColorText)
        .arg(kSurfaceMutedBackgroundText)
        .arg(kDisabledTextColor);

    // tabStyle purpose: Unify color, margins, and selected state for both standard Tabs and ADS Dock Tabs.
    // Do not set the font size here to ensure all Tab bars inherit the default system font size from Qt.
    const QString kTabStyle = QStringLiteral(
        "QTabBar{"
        "  border:none !important;"
        "}"
        "QTabBar::tab{"
        "  background-color:%1 !important;"
        "  color:%2 !important;"
        "  border:none !important;"
        "  border-radius:0px !important;"
        "  padding:3px 12px;"
        "  min-height:22px;"
        "  margin:0px;"
        "}"
        "QTabBar::tab:left,QTabBar::tab:right{"
        "  padding:5px 6px;"
        "}"
        "QTabBar::tab:selected{"
        "  background-color:%4 !important;"
        "  color:%5 !important;"
        "  font-weight:700;"
        "}"
        "QTabBar::tab:hover:!selected{"
        "  background-color:%9 !important;"
        "  background:%9 !important;"
        "  color:%2 !important;"
        "}"
        "QMainWindow QTabBar::tab:hover:!selected,"
        "QMainWindow QTabBar::tab:pressed:!selected{"
        "  background-color:%9 !important;"
        "  background:%9 !important;"
        "  color:%2 !important;"
        "}"
        "QMainWindow QTabBar::tab:selected:hover,"
        "QMainWindow QTabBar::tab:selected:pressed{"
        "  background-color:%4 !important;"
        "  background:%4 !important;"
        "  color:%5 !important;"
        "}"
        "ads--CDockAreaTabBar{"
        "  background:transparent !important;"
        "  border:none !important;"
        "  padding:0px;"
        "}"
        "ads--CDockWidgetTab,ads--CAutoHideTab{"
        "  background-color:%1 !important;"
        "  color:%2 !important;"
        "  border:none !important;"
        "  border-radius:0px !important;"
        "  padding:3px 12px;"
        "  margin:0px;"
        "  min-height:22px;"
        "}"
        "ads--CDockWidgetTab QLabel,ads--CAutoHideTab QLabel{"
        "  color:%2 !important;"
        "}"
        "ads--CDockWidgetTab[activeTab=\"true\"],ads--CAutoHideTab[activeTab=\"true\"]{"
        "  background-color:%4 !important;"
        "  background:%4 !important;"
        "  color:%8 !important;"
        "}"
        "ads--CDockWidgetTab[activeTab=\"true\"] QLabel,"
        "ads--CDockWidgetTab[activeTab=\"true\"] QWidget,"
        "ads--CAutoHideTab[activeTab=\"true\"] QLabel,"
        "ads--CAutoHideTab[activeTab=\"true\"] QWidget{"
        "  color:%8 !important;"
        "  background-color:transparent !important;"
        "  background:transparent !important;"
        "  font-weight:700;"
        "}"
        "ads--CDockWidgetTab:hover,"
        "ads--CDockWidgetTab[activeTab=\"true\"]:hover,"
        "ads--CDockWidgetTab[kswordDockTab=\"true\"]:hover,"
        "ads--CAutoHideTab:hover,"
        "ads--CAutoHideTab[activeTab=\"true\"]:hover,"
        "ads--CAutoHideTab[kswordAutoHideTab=\"true\"]:hover{"
        "  background-color:%6 !important;"
        "  background:%6 !important;"
        "  color:%2 !important;"
        "  border:none !important;"
        "}"
        "ads--CDockWidgetTab:hover[activeTab=\"false\"],"
        "ads--CDockWidgetTab[kswordDockTab=\"true\"]:hover[activeTab=\"false\"],"
        "ads--CAutoHideTab:hover[activeTab=\"false\"],"
        "ads--CAutoHideTab[kswordAutoHideTab=\"true\"]:hover[activeTab=\"false\"]{"
        "  background-color:%6 !important;"
        "  background:%6 !important;"
        "  color:%2 !important;"
        "}"
        "ads--CDockAreaWidget ads--CDockAreaTitleBar ads--CDockWidgetTab:hover,"
        "ads--CDockAreaWidget ads--CDockAreaTitleBar ads--CDockWidgetTab[kswordDockTab=\"true\"]:hover,"
        "ads--CDockAreaWidget ads--CDockAreaTitleBar ads--CAutoHideTab:hover,"
        "ads--CDockAreaWidget ads--CDockAreaTitleBar ads--CAutoHideTab[kswordAutoHideTab=\"true\"]:hover{"
        "  background-color:%6 !important;"
        "  background:%6 !important;"
        "  color:%2 !important;"
        "  border:none !important;"
        "}"
        "ads--CDockWidgetTab:hover QLabel,ads--CDockWidgetTab:hover QWidget,"
        "ads--CDockWidgetTab[kswordDockTab=\"true\"]:hover QLabel,"
        "ads--CDockWidgetTab[kswordDockTab=\"true\"]:hover QWidget,"
        "ads--CAutoHideTab:hover QLabel,ads--CAutoHideTab:hover QWidget,"
        "ads--CAutoHideTab[kswordAutoHideTab=\"true\"]:hover QLabel,"
        "ads--CAutoHideTab[kswordAutoHideTab=\"true\"]:hover QWidget,"
        "ads--CDockAreaWidget ads--CDockAreaTitleBar ads--CDockWidgetTab:hover QLabel,"
        "ads--CDockAreaWidget ads--CDockAreaTitleBar ads--CDockWidgetTab:hover QWidget,"
        "ads--CDockAreaWidget ads--CDockAreaTitleBar ads--CAutoHideTab:hover QLabel,"
        "ads--CDockAreaWidget ads--CDockAreaTitleBar ads--CAutoHideTab:hover QWidget{"
        "  color:%2 !important;"
        "  background-color:%7 !important;"
        "  background:%7 !important;"
        "}"
        "ads--CDockWidgetTab[activeTab=\"true\"]:hover,"
        "ads--CAutoHideTab[activeTab=\"true\"]:hover{"
        "  background-color:%4 !important;"
        "  background:%4 !important;"
        "  color:%8 !important;"
        "}"
        "ads--CDockWidgetTab[activeTab=\"true\"]:hover QLabel,"
        "ads--CDockWidgetTab[activeTab=\"true\"]:hover QWidget,"
        "ads--CAutoHideTab[activeTab=\"true\"]:hover QLabel,"
        "ads--CAutoHideTab[activeTab=\"true\"]:hover QWidget{"
        "  color:%8 !important;"
        "  background-color:transparent !important;"
        "  background:transparent !important;"
        "}"
        "ads--CDockAreaTitleBar QToolButton,ads--CDockAreaTitleBar QPushButton{"
        "  border:none !important;"
        "  background:transparent !important;"
        "}")
        .arg(kInactiveTabColor)
        .arg(kInactiveTabTextColor)
        .arg(kPanelBorderColor)
        .arg(kActiveTabColor)
        .arg(kActiveTabTextColor)
        .arg(kTabHoverColor)
        .arg(kDockTabChildHoverColor)
        .arg(kDockActiveTabTextColor)
        .arg(kNormalTabHoverColor);

    const QString kSharedOverlayStyle = kDepthOverlayStyle
        + kScrollBarOverlayStyle
        + kButtonInteractionStyle
        + kTabStyle;    // dockContentTransparentStyle:
    // - When a background image is available, change the background of common containers in the Dock content area to transparent;
    // - Fixes the issue where the Dock panel background remains black/white, with the background image only visible through gaps.
    // Note: This snippet applies only to ads--CDockWidget descendants, not to global areas like the menu bar.
    const QString kDockContentTransparentStyle = enableDockContentTransparency
        ? QStringLiteral(
            "ads--CDockWidget,"
            "ads--CDockWidget > QWidget,"
            "ads--CDockWidget QFrame,"
            "ads--CDockWidget QTabWidget::pane,"
            "ads--CDockWidget QStackedWidget,"
            "ads--CDockWidget QStackedWidget > QWidget,"
            "ads--CDockWidget QSplitter,"
            "ads--CDockWidget QSplitter::handle,"
            "ads--CDockWidget QScrollArea,"
            "ads--CDockWidget QAbstractScrollArea,"
            "ads--CDockWidget QAbstractScrollArea::viewport,"
            "ads--CDockWidget QTableView,"
            "ads--CDockWidget QTableWidget,"
            "ads--CDockWidget QTreeView,"
            "ads--CDockWidget QTreeWidget,"
            "ads--CDockWidget QListView,"
            "ads--CDockWidget QListWidget,"
            "ads--CDockWidget QTextEdit,"
            "ads--CDockWidget QPlainTextEdit,"
            "ads--CDockWidget QGroupBox{"
            "  background:transparent !important;"
            "  background-color:transparent !important;"
            "}"
            "ads--CDockWidget QTableView,"
            "ads--CDockWidget QTableWidget,"
            "ads--CDockWidget QTreeView,"
            "ads--CDockWidget QTreeWidget,"
            "ads--CDockWidget QListView,"
            "ads--CDockWidget QListWidget{"
            "  alternate-background-color:transparent !important;"
            "}")
        : QString();

    // finalDockAreaTransparentStyle:
    // - Final fallback rule for Dock area transparency in background image mode;
    // - Override the semi-transparent panel background color of ads--CDockAreaWidget in depthOverlayStyle;
    // - Prevent switching to certain Dock widgets from repainting the shared DockArea with a solid color and hiding the background image across the other docks;
    // - Do not override ads--CDockWidgetTab itself; preserve the theme color for the selected and hovered states of Dock tabs.
    const QString kFinalDockAreaTransparentStyle = enableDockContentTransparency
        ? QStringLiteral(
            "ads--CDockManager,"
            "ads--CDockContainerWidget,"
            "ads--CDockAreaWidget,"
            "ads--CDockAreaWidget > QWidget,"
            "ads--CDockAreaTitleBar,"
            "ads--CDockAreaTabBar,"
            "ads--CDockWidget,"
            "ads--CDockWidget > QWidget{"
            "  background:transparent !important;"
            "  background-color:transparent !important;"
            "}")
        : QString();

    // kernelDockContainerStyle:
    // - No background image: The kernel Dock root container maintains the theme's solid background to prevent the black parent container from showing after ADS restores the layout.
    // - With background images: make the root container, Tab pane, and StackedWidget transparent to reveal the main window's background image.
    // Returns: Controls only the background of the outer layer/page container of the Kernel Dock, without affecting content views such as tables, trees, or lists.
    const QString kKernelDockContainerStyle = enableDockContentTransparency
        ? QStringLiteral(
            "ads--CDockWidget#ksDock_kernel,"
            "ads--CDockWidget#ksDock_kernel > QWidget,"
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot,"
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot QTabWidget::pane,"
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot QStackedWidget,"
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot QStackedWidget > QWidget{"
            "  background:transparent !important;"
            "  background-color:transparent !important;"
            "  color:%1 !important;"
            "}")
            .arg(kPrimaryTextColor)
        : QStringLiteral(
            "ads--CDockWidget#ksDock_kernel,"
            "ads--CDockWidget#ksDock_kernel > QWidget,"
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot,"
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot QTabWidget::pane,"
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot QStackedWidget,"
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot QStackedWidget > QWidget{"
            "  background:%1 !important;"
            "  background-color:%1 !important;"
            "  color:%2 !important;"
            "}")
            .arg(kSurfaceBackgroundText)
            .arg(kPrimaryTextColor);

    // kernelDockContentStyle:
    // - In background image mode, tables, trees, and lists within the kernel Dock are also transparent to prevent obscuring the background image.
    // - Retains the solid theme background when no background image is present, maintaining the standard theme appearance.
    const QString kKernelDockContentStyle = enableDockContentTransparency
        ? QStringLiteral(
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot QTableView,"
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot QTableWidget,"
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot QTreeView,"
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot QTreeWidget,"
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot QListView,"
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot QListWidget,"
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot QAbstractScrollArea,"
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot QAbstractScrollArea > QWidget,"
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot QAbstractScrollArea::viewport{"
            "  background:transparent !important;"
            "  background-color:transparent !important;"
            "  alternate-background-color:transparent !important;"
            "  color:%1 !important;"
            "  gridline-color:%2 !important;"
            "}")
            .arg(kPrimaryTextColor)
            .arg(kBorderColorText)
        : QStringLiteral(
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot QTableView,"
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot QTableWidget,"
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot QTreeView,"
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot QTreeWidget,"
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot QListView,"
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot QListWidget{"
            "  background:%1 !important;"
            "  background-color:%1 !important;"
            "  alternate-background-color:%2 !important;"
            "  color:%3 !important;"
            "  gridline-color:%4 !important;"
            "}")
            .arg(kSurfaceBackgroundText)
            .arg(kSurfaceAltBackgroundText)
            .arg(kPrimaryTextColor)
            .arg(kBorderColorText);

    // The structured view at the bottom of the object namespace overview is a derived presentation of the detail text and should not be
    // overridden by the KernelDock's generic table solid rules; keep it transparent so it inherits the background color of the detail area.
    const QString kObjectNamespaceStructuredViewStyle = QStringLiteral(
        "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot "
        "#ks_object_namespace_detail_editor QScrollArea,"
        "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot "
        "#ks_object_namespace_detail_editor QScrollArea::viewport,"
        "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot "
        "#ks_object_namespace_detail_editor QScrollArea QWidget,"
        "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot "
        "#ks_object_namespace_detail_editor QTreeWidget,"
        "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot "
        "#ks_object_namespace_detail_editor QTreeWidget::viewport{"
        "  background:transparent !important;"
        "  background-color:transparent !important;"
        "  alternate-background-color:transparent !important;"
        "}");

    const QString kKernelDockStyle = kKernelDockContainerStyle
        + kKernelDockContentStyle
        + kObjectNamespaceStructuredViewStyle;

    // tabPluginOpaqueStyle:
    // - Keep the 'Plugins' page always opaque to the theme, excluding it from Dock content transparency.
    // Why exclusion is mandatory:
    // - Tab-type plugins are hosted via WA_NativeWindow native child windows (ksExternalPluginNativeSurface);
    //   the window of an external plugin process is set as a child of this surface using SetParent.
    // - Native child windows do not participate in Qt's layered composition; once the parent chain is made
    //   transparent, the plugin rendering becomes black blocks, artifacts, or fails to refresh entirely.
    // - PluginHost sets an opaque background itself (via createTabPluginContainer), but that is a standard
    //   declaration and is overridden by the preceding transparent rules marked with !important. Therefore, we use
    //   a selector with !important and higher specificity (including #objectName) here to restore the background.
    // Anchor description:
    // - The plugin page has been merged into the 'Misc' dock, so the independent ksDock_plugin no longer exists. The anchor
    //   is now set to the plugin host placeholder control ksMiscPluginHost within the Misc page and its entire subtree.
    // - Override only this subtree; other sub-pages in the Miscellaneous tab still participate normally in content transparency.
    const QString kTabPluginOpaqueStyle = QStringLiteral(
        "QWidget#ksMiscPluginHost,"
        "QWidget#ksMiscPluginHost QWidget,"
        "QWidget#ksTabPluginContainer,"
        "QWidget#ksTabPluginEmptyState,"
        "QWidget#ksExternalPluginNativeSurface,"
        "QTabWidget#ksTabPluginHost::pane{"
        "  background:%1 !important;"
        "  background-color:%1 !important;"
        "  color:%2 !important;"
        "}")
        .arg(kSurfaceBackgroundText)
        .arg(kPrimaryTextColor);
    // finalOrdinaryTabHoverStyle:
    // - Serves as the final fallback for hover/pressed states of ordinary QTabWidget/QTabBar;
    // - Use dark gray for dark mode and light gray for light mode to prevent fallback to the base QSS or platform palette in reverse;
    // - The selector deliberately avoids ads--CDockWidgetTab and ads--CAutoHideTab, so it does not affect ADS Dock tabs.
    const QString kOrdinaryTabHoverColor = darkModeEnabled
        ? ksword_theme::surfaceMutedColorHex()
        : ksword_theme::surfaceAltColorHex();
    const QString kFinalOrdinaryTabHoverStyle = QStringLiteral(
        "QMainWindow QTabWidget QTabBar::tab:hover:!selected,"
        "QMainWindow QTabWidget QTabBar::tab:pressed:!selected,"
        "QTabWidget QTabBar::tab:hover:!selected,"
        "QTabWidget QTabBar::tab:pressed:!selected{"
        "  background-color:%1 !important;"
        "  background:%1 !important;"
        "  color:%2 !important;"
        "}"
        "QMainWindow QTabWidget QTabBar::tab:selected:hover,"
        "QMainWindow QTabWidget QTabBar::tab:selected:pressed,"
        "QTabWidget QTabBar::tab:selected:hover,"
        "QTabWidget QTabBar::tab:selected:pressed{"
        "  background-color:%3 !important;"
        "  background:%3 !important;"
        "  color:%4 !important;"
        "}")
        .arg(kOrdinaryTabHoverColor)
        .arg(kPrimaryTextColor)
        .arg(kActiveTabColor)
        .arg(kActiveTabTextColor);

    if (!darkModeEnabled)
    {
        return kRootStyle
            + QStringLiteral(
                "QMenuBar{background-color:__WINDOW_BACKGROUND__;color:__WINDOW_TEXT__;}"
                "QMenuBar::item{background:transparent;color:__WINDOW_TEXT__;padding:2px 7px;}"
                "QMenuBar::item:selected{background:%2;color:__WINDOW_TEXT__;}"
                "QMenuBar::item:pressed{background:__LIGHT_MENUBAR_PRESSED__;color:__WINDOW_TEXT__;}"
                "QStatusBar{background-color:__WINDOW_BACKGROUND__;color:__WINDOW_TEXT__;}"
                "QLineEdit,QSpinBox,QDoubleSpinBox{"
                "  background:transparent !important;"
                "  background-color:transparent !important;"
                "  color:%3 !important;"
                "  border:1px solid %4;"
                "}"
                "QTextEdit,QPlainTextEdit,QTableWidget,QTreeWidget,QListWidget{"
                "  background-color:%1 !important;"
                "  color:%3 !important;"
                "  border:1px solid %4;"
                "}"
                "QPushButton,QToolButton{"
                "  background-color:%2 !important;"
                "  color:%3 !important;"
                "  border:1px solid %5 !important;"
                "}"
                "QTableView,QTableWidget,QTreeView,QTreeWidget,QListView,QListWidget{"
                "  background:%1 !important;"
                "  alternate-background-color:%6 !important;"
                "  color:%3 !important;"
                "  gridline-color:%4;"
                "}"
                "QTreeView::item:selected,QTreeWidget::item:selected{"
                "  background:%7 !important;"
                "  color:%8 !important;"
                "}"
                "QHeaderView::section{"
                "  background:transparent !important;"
                "  background-color:transparent !important;"
                "  color:%3 !important;"
                "  border:1px solid %4;"
                "}"
                "QTableCornerButton::section{"
                "  background:transparent !important;"
                "  background-color:transparent !important;"
                "  border:none !important;"
                "}"
                "QScrollBar:vertical,QScrollBar:horizontal{"
                "  background:%9 !important;"
                "  border:none !important;"
                "}")
                .arg(kSurfaceBackgroundText)
                .arg(kSubtleThemeColor)
                .arg(kPrimaryTextColor)
                .arg(kBorderColorText)
                .arg(kBorderStrongColorText)
                .arg(kSurfaceAltBackgroundText)
                .arg(kActiveThemeColor)
                .arg(kSelectedTextColor)
                .arg(kWindowBackgroundText)
                .replace(QStringLiteral("__WINDOW_BACKGROUND__"), kWindowBackgroundText)
                .replace(QStringLiteral("__WINDOW_TEXT__"), kWindowTextColor)
                .replace(QStringLiteral("__LIGHT_MENUBAR_PRESSED__"), kSurfaceMutedBackgroundText)
            + kSharedOverlayStyle
            + kTooltipStyle
            + kDockContentTransparentStyle
            + kFinalDockAreaTransparentStyle
            + kKernelDockStyle
            + kTabPluginOpaqueStyle
            + kFinalOrdinaryTabHoverStyle;
    }

    return kRootStyle
        + QStringLiteral(
            "QMenuBar{background-color:__WINDOW_BACKGROUND__;color:__WINDOW_TEXT__;}"
            "QMenuBar::item{background:transparent;color:__WINDOW_TEXT__;padding:2px 7px;}"
            "QMenuBar::item:selected{background:%9;color:__WINDOW_TEXT__;}"
            "QMenuBar::item:pressed{background:%10;color:%8;}"
            "QStatusBar{background-color:__WINDOW_BACKGROUND__;color:__WINDOW_TEXT__;}"
            "QLineEdit,QSpinBox,QDoubleSpinBox{"
            "  background:transparent !important;"
            "  background-color:transparent !important;"
            "  color:%3 !important;"
            "  border:1px solid %4;"
            "}"
            "QTextEdit,QPlainTextEdit,QTableWidget,QTreeWidget,QListWidget{"
            "  background-color:%2 !important;"
            "  color:%3 !important;"
            "  border:1px solid %4;"
            "}"
            "QPushButton,QToolButton{"
            "  background-color:%6 !important;"
            "  color:%3 !important;"
            "  border:1px solid %5 !important;"
            "}"
            "QTableView,QTableWidget,QTreeView,QTreeWidget,QListView,QListWidget{"
            "  background:%2 !important;"
            "  alternate-background-color:%6 !important;"
            "  color:%3 !important;"
            "  gridline-color:%4;"
            "}"
            "QTreeView::item:selected,QTreeWidget::item:selected{"
            "  background:%7 !important;"
            "  color:%8 !important;"
            "}"
            "QHeaderView::section{"
            "  background:transparent !important;"
            "  background-color:transparent !important;"
            "  color:%3 !important;"
            "  border:1px solid %4;"
            "}"
            "QTableCornerButton::section{"
            "  background:transparent !important;"
            "  background-color:transparent !important;"
            "  border:none !important;"
            "}"
            "QScrollBar:vertical,QScrollBar:horizontal{"
            "  background:%1 !important;"
            "  border:none !important;"
            "}")
            .arg(kWindowBackgroundText)
            .arg(kSurfaceBackgroundText)
            .arg(kPrimaryTextColor)
            .arg(kBorderColorText)
            .arg(kBorderStrongColorText)
            .arg(kSurfaceAltBackgroundText)
            .arg(kActiveThemeColor)
            .arg(kSelectedTextColor)
            .arg(ksword_theme::rgbaColorName(ksword_theme::primaryBlueColor, 71))
            .arg(ksword_theme::rgbaColorName(ksword_theme::primaryBlueColor, 97))
            .replace(QStringLiteral("__WINDOW_BACKGROUND__"), kWindowBackgroundText)
            .replace(QStringLiteral("__WINDOW_TEXT__"), kWindowTextColor)
        + kSharedOverlayStyle
        + kTooltipStyle
        + kDockContentTransparentStyle
        + kFinalDockAreaTransparentStyle
        + kKernelDockStyle
        + kTabPluginOpaqueStyle
        + kFinalOrdinaryTabHoverStyle;
}
