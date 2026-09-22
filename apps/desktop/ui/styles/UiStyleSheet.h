#pragma once
#include <QString>
#include <qstring.h>

// QSS_MainWindow_TabWidget:
// - Unify the base styles for all QTabWidget and QTabBar instances within the project.
// - Avoid default white background styles to ensure both light and dark themes are controlled by the palette.
// - Do not set font-size; let the Tab bar inherit the default application font size from Qt.
const QString kQssMainWindowTabWidget = R"(
    QTabWidget::pane {
        border: none;
        background-color: transparent;
        top: 0px;
    }

    QTabBar {
        background-color: palette(window);
        border: none;
    }

    QTabBar::tab {
        background-color: palette(alternate-base);
        color: palette(text);
        padding: 3px 12px;
        margin: 0px;
        min-height: 24px;
        border: none;
        border-radius: 0px;
    }

    QTabBar::tab:left,
    QTabBar::tab:right {
        padding: 5px 6px;
    }

    QTabBar::tab:selected {
        background-color: palette(highlight);
        color: palette(highlighted-text);
        font-weight: 700;
    }

    QTabBar::tab:selected:hover,
    QTabBar::tab:selected:pressed {
        background-color: palette(highlight) !important;
        background: palette(highlight) !important;
        color: palette(highlighted-text);
    }

    QTabBar::tab:hover:!selected,
    QTabBar::tab:pressed:!selected {
        background-color: palette(alternate-base) !important;
        background: palette(alternate-base) !important;
        color: palette(text);
    }
)";

// QSS_MainWindow_dockStyle:
// - Unify the styles for the main window Dock area, ADS docking system, and scrollbars;
// - Force the currently selected Tab to use the theme color background with white text to resolve residual white-background/black-text issues.
// - Do not set font-size; let the Dock bar and inner Tab bar inherit the default Qt application font size.
const QString kQssMainWindowDockStyle = R"(
    QDockWidget {
        border: none;
        margin: 1px;
        background-color: palette(window);
        color: palette(text);
    }

    QDockWidget::title {
        background-color: palette(window);
        color: palette(text);
        padding: 6px 10px;
        border-bottom: none;
    }

    QDockWidget > QWidget {
        background-color: palette(base);
        color: palette(text);
        border: none;
    }

    QMainWindow QTabBar {
        background-color: palette(window);
        border: none;
    }

    QMainWindow QTabBar::tab {
        background-color: palette(alternate-base);
        color: palette(text);
        border: none;
        border-radius: 0px;
        padding: 3px 12px;
        margin: 0px;
        min-height: 22px;
    }

    QMainWindow QTabBar::tab:left,
    QMainWindow QTabBar::tab:right {
        padding: 5px 6px;
    }

    QMainWindow QTabBar::tab:selected {
        background-color: palette(highlight);
        color: palette(highlighted-text);
        font-weight: 700;
    }

    QMainWindow QTabBar::tab:selected:hover,
    QMainWindow QTabBar::tab:selected:pressed {
        background-color: palette(highlight) !important;
        background: palette(highlight) !important;
        color: palette(highlighted-text);
    }

    QMainWindow QTabBar::tab:hover:!selected,
    QMainWindow QTabBar::tab:pressed:!selected {
        background-color: palette(alternate-base) !important;
        background: palette(alternate-base) !important;
        color: palette(text);
    }

    ads--CDockManager,
    ads--CDockContainerWidget,
    ads--CDockAreaWidget,
    ads--CDockAreaTitleBar,
    ads--CFloatingDockContainer {
        background-color: palette(window);
        color: palette(text);
    }

    ads--CDockAreaTabBar {
        background-color: palette(window);
        border: none;
        padding: 0px;
    }

    ads--CDockWidgetTab,
    ads--CAutoHideTab {
        background-color: palette(alternate-base);
        color: palette(text);
        border: none;
        border-radius: 0px;
        padding: 3px 12px;
        min-height: 24px;
    }

    ads--CDockWidgetTab QLabel,
    ads--CAutoHideTab QLabel {
        color: palette(text);
    }

    ads--CDockWidgetTab[activeTab="true"],
    ads--CAutoHideTab[activeTab="true"] {
        background-color: palette(highlight);
        background: palette(highlight);
        color: palette(highlighted-text);
    }

    ads--CDockWidgetTab[activeTab="true"] QLabel,
    ads--CAutoHideTab[activeTab="true"] QLabel {
        color: palette(highlighted-text);
        font-weight: 600;
    }

    ads--CDockWidgetTab:hover,
    ads--CDockWidgetTab[activeTab="true"]:hover,
    ads--CDockWidgetTab[kswordDockTab="true"]:hover,
    ads--CAutoHideTab:hover {
        background-color: palette(alternate-base) !important;
        background: palette(alternate-base) !important;
        color: palette(text);
        border: none !important;
    }

    ads--CDockWidgetTab:hover QLabel,
    ads--CDockWidgetTab:hover QWidget,
    ads--CDockWidgetTab[kswordDockTab="true"]:hover QLabel,
    ads--CDockWidgetTab[kswordDockTab="true"]:hover QWidget,
    ads--CAutoHideTab:hover QLabel,
    ads--CAutoHideTab:hover QWidget {
        background-color: palette(alternate-base) !important;
        background: palette(alternate-base) !important;
        color: palette(text);
    }

    ads--CDockAreaTitleBar QToolButton,
    ads--CDockAreaTitleBar QPushButton {
        background-color: transparent;
        color: palette(text);
        border: none;
        border-radius: 1px;
    }

    ads--CDockAreaTitleBar QToolButton:hover,
    ads--CDockAreaTitleBar QPushButton:hover {
        background-color: palette(highlight);
        color: palette(highlighted-text);
        border-color: palette(highlight);
    }

    QScrollBar:vertical {
        background-color: palette(window);
        width: 12px;
        margin: 0px;
        border: none;
    }

    QScrollBar::handle:vertical {
        background-color: palette(highlight);
        min-height: 20px;
        border-radius: 2px;
    }

    QScrollBar::handle:vertical:hover {
        background-color: palette(highlight);
    }

    QScrollBar:horizontal {
        background-color: palette(window);
        height: 12px;
        margin: 0px;
        border: none;
    }

    QScrollBar::handle:horizontal {
        background-color: palette(highlight);
        min-width: 20px;
        border-radius: 2px;
    }

    QScrollBar::handle:horizontal:hover {
        background-color: palette(highlight);
    }

    QScrollBar::add-line,
    QScrollBar::sub-line,
    QScrollBar::add-page,
    QScrollBar::sub-page {
        background: transparent;
        border: none;
    }

    QTableCornerButton::section {
        background-color: transparent;
        border: none;
    }
)";

// QSS_Buttons_Light:
// - Unify button styles for light-themed scenarios such as the welcome page.
// - Do not use a white background for default or hover states to prevent highlighting from appearing washed out.
const QString kQssButtonsLight = R"(
    QPushButton {
        background-color: palette(highlight) !important;
        color: palette(highlighted-text) !important;
        border: 1px solid palette(highlight) !important;
        padding: 6px 16px;
        border-radius: 1px;
        font-weight: 500;
        outline: none;
    }

    QPushButton:hover {
        background-color: palette(highlight) !important;
        color: palette(highlighted-text) !important;
        border-color: palette(highlight) !important;
    }

    QPushButton:pressed {
        background-color: palette(highlight) !important;
        color: palette(highlighted-text) !important;
        border-color: palette(highlight) !important;
    }

    QPushButton:disabled {
        background-color: palette(button) !important;
        color: palette(disabled, text) !important;
        border: 1px solid palette(mid) !important;
        font-weight: normal;
    }
)";

// QSS_Buttons_Dark:
// - Keep theme blue for dark-mode buttons; deepen on hover.
// - Prevents a white hover background from appearing.
const QString kQssButtonsDark = R"(
    QPushButton {
        background-color: palette(highlight) !important;
        color: palette(highlighted-text) !important;
        border: 1px solid palette(highlight) !important;
        padding: 6px 16px;
        border-radius: 1px;
        font-weight: 500;
        outline: none;
    }

    QPushButton:hover {
        background-color: palette(highlight) !important;
        color: palette(highlighted-text) !important;
        border-color: palette(highlight) !important;
    }

    QPushButton:pressed {
        background-color: palette(highlight) !important;
        color: palette(highlighted-text) !important;
        border-color: palette(highlight) !important;
    }

    QPushButton:disabled {
        background-color: palette(button) !important;
        color: palette(disabled, text) !important;
        border: 1px solid palette(mid) !important;
        font-weight: normal;
    }
)";
