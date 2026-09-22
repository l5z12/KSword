#include "GlobalUiBaseStyle.h"

#include "ThemeStatusRole.h"

#include "../Theme.h"

namespace ks::ui
{
    QString buildGlobalBaseControlStyleBlock()
    {
        // All colors come from dynamic roles in ksword_theme; the entire block is rebuilt when light/dark modes or custom theme colors change.
        QString baseControlStyle = QString::fromLatin1(
            "\n__BEGIN_MARKER__\n"

            // ---------- Button baseline ---------- Ordinary buttons not overridden by
            // local styles are unified to 'neutral surface + theme-color interaction'.
            // Baseline allows only color/border properties: geometric properties like min-height and padding are prohibited,
            // as they would leak into local styles and alter the size of compact layouts (e.g., title bar icon buttons).
            "QPushButton{"
            "  background-color:__SURFACE_ALT__;"
            "  color:__TEXT__;"
            "  border:1px solid __BORDER__;"
            "  border-radius:3px;"
            "}"
            "QPushButton:hover{"
            "  background-color:__SURFACE_MUTED__;"
            "  border-color:__ACCENT__;"
            "}"
            "QPushButton:pressed{"
            "  background-color:__ACCENT_PRESSED__;"
            "  color:__ON_ACCENT__;"
            "  border-color:__ACCENT_PRESSED__;"
            "}"
            "QPushButton:checked{"
            "  background-color:__ACCENT__;"
            "  color:__ON_ACCENT__;"
            "  border-color:__ACCENT__;"
            "}"
            "QPushButton:default{"
            "  border-color:__ACCENT__;"
            "}"
            "QPushButton:disabled{"
            "  background-color:__SURFACE_MUTED__;"
            "  color:__TEXT_DISABLED__;"
            "  border-color:__BORDER__;"
            "}"
            "QPushButton:flat{"
            "  background-color:transparent;"
            "  border:none;"
            "}"

            // ---------- Input control baseline ---------- Selector groups must be written in the same
            // string fragment as '{' so that i18n audits can recognize them as QSS rather than UI text.
            "QLineEdit,QPlainTextEdit,QTextEdit,QSpinBox,QDoubleSpinBox,QDateEdit,QTimeEdit,QDateTimeEdit{"
            "  background-color:__SURFACE__;"
            "  color:__TEXT__;"
            "  border:1px solid __BORDER__;"
            "  border-radius:3px;"
            "  selection-background-color:__ACCENT__;"
            "  selection-color:__ON_ACCENT__;"
            "}"
            "QLineEdit:hover,QPlainTextEdit:hover,QTextEdit:hover,QSpinBox:hover,QDoubleSpinBox:hover,QDateEdit:hover,QTimeEdit:hover,QDateTimeEdit:hover{"
            "  border-color:__BORDER_STRONG__;"
            "}"
            "QLineEdit:focus,QPlainTextEdit:focus,QTextEdit:focus,QSpinBox:focus,QDoubleSpinBox:focus,QDateEdit:focus,QTimeEdit:focus,QDateTimeEdit:focus{"
            "  border-color:__ACCENT__;"
            "}"
            "QLineEdit:disabled,QPlainTextEdit:disabled,QTextEdit:disabled,QSpinBox:disabled,QDoubleSpinBox:disabled,QDateEdit:disabled,QTimeEdit:disabled,QDateTimeEdit:disabled{"
            "  background-color:__SURFACE_MUTED__;"
            "  color:__TEXT_DISABLED__;"
            "}"
            // Read-only input fields must be visually distinct from editable ones: The project contains hundreds of display-only
            // input fields (e.g., paths and command lines in process details) using setReadOnly(true). Previously, they looked
            // identical to editable controls—having borders, accepting focus, and highlighting on hover—causing users to repeatedly
            // attempt modifications and assume the program was frozen. This change assigns a clear 'non-input' background color to
            // the read-only state while preserving text color and selectability, as the content still needs to be read and copied.
            "QLineEdit:read-only,QPlainTextEdit:read-only,QTextEdit:read-only,QSpinBox:read-only,QDoubleSpinBox:read-only,QDateEdit:read-only,QTimeEdit:read-only,QDateTimeEdit:read-only{"
            "  background-color:__SURFACE_MUTED__;"
            "}"
            "QLineEdit:read-only:hover,QPlainTextEdit:read-only:hover,QTextEdit:read-only:hover,QSpinBox:read-only:hover,QDoubleSpinBox:read-only:hover,QDateEdit:read-only:hover,QTimeEdit:read-only:hover,QDateTimeEdit:read-only:hover{"
            "  border-color:__BORDER__;"
            "}"
            "QLineEdit:read-only:focus,QPlainTextEdit:read-only:focus,QTextEdit:read-only:focus,QSpinBox:read-only:focus,QDoubleSpinBox:read-only:focus,QDateEdit:read-only:focus,QTimeEdit:read-only:focus,QDateTimeEdit:read-only:focus{"
            "  border-color:__BORDER__;"
            "}"

            // ---------- Stepper buttons for numeric/date input fields ---------- If any QSS rule matches
            // QSpinBox, Qt will use QStyleSheetStyle to render CC_SpinBox. In this case, if up-button/down-button
            // and arrow rules are not explicitly provided, the up/down buttons will render neither arrows nor a
            // complete background, leaving only fragmented edge lines on the right margin—users will see 'a dot',
            // unable to recognize it as increment/decrement or know where to click.
            // The type selector applies to subclasses as well; this group simultaneously
            // covers QSpinBox, QDoubleSpinBox, and QDateEdit/QTimeEdit/QDateTimeEdit.
            "QAbstractSpinBox::up-button{"
            "  subcontrol-origin:border;"
            "  subcontrol-position:top right;"
            "  width:18px;"
            "  margin:1px 1px 0px 0px;"
            "  border-left:1px solid __BORDER__;"
            "  border-top-right-radius:2px;"
            "  background-color:__SURFACE_ALT__;"
            "}"
            "QAbstractSpinBox::down-button{"
            "  subcontrol-origin:border;"
            "  subcontrol-position:bottom right;"
            "  width:18px;"
            "  margin:0px 1px 1px 0px;"
            "  border-left:1px solid __BORDER__;"
            "  border-top:1px solid __BORDER__;"
            "  border-bottom-right-radius:2px;"
            "  background-color:__SURFACE_ALT__;"
            "}"
            "QAbstractSpinBox::up-button:hover,QAbstractSpinBox::down-button:hover{"
            "  background-color:__SURFACE_MUTED__;"
            "  border-left-color:__BORDER_STRONG__;"
            "}"
            "QAbstractSpinBox::up-button:pressed,QAbstractSpinBox::down-button:pressed{"
            "  background-color:__ACCENT_PRESSED__;"
            "}"
            // :off indicates the upper or lower limit has been reached. Like :disabled, it
            // must provide visible feedback; otherwise, users may think the button is broken.
            "QAbstractSpinBox::up-button:off,QAbstractSpinBox::down-button:off,QAbstractSpinBox::up-button:disabled,QAbstractSpinBox::down-button:disabled{"
            "  background-color:__SURFACE_MUTED__;"
            "  border-left-color:__BORDER__;"
            "}"
            "QAbstractSpinBox::up-arrow{"
            "  image:url(__ARROW_UP__);"
            "  width:10px;"
            "  height:10px;"
            "}"
            "QAbstractSpinBox::down-arrow{"
            "  image:url(__ARROW_DOWN__);"
            "  width:10px;"
            "  height:10px;"
            "}"
            "QAbstractSpinBox::up-arrow:off,QAbstractSpinBox::up-arrow:disabled{"
            "  image:url(__ARROW_UP_OFF__);"
            "}"
            "QAbstractSpinBox::down-arrow:off,QAbstractSpinBox::down-arrow:disabled{"
            "  image:url(__ARROW_DOWN_OFF__);"
            "}"

            // ---------- Group Box Baseline ----------
            // margin-top is the minimum space required for the title row, consistent with the native Qt title height.
            "QGroupBox{"
            "  border:1px solid __BORDER__;"
            "  border-radius:4px;"
            "  margin-top:12px;"
            "}"
            "QGroupBox::title{"
            "  subcontrol-origin:margin;"
            "  subcontrol-position:top left;"
            "  left:8px;"
            "  padding:0px 4px;"
            "  color:__TEXT_SECONDARY__;"
            "  font-weight:600;"
            "}"

            // ---------- Table header baseline ---------- Unify table/tree headers
            // across all pages to 'neutral secondary surface + bottom separator line'.
            "QHeaderView{"
            "  background-color:transparent;"
            "  border:none;"
            "}"
            "QHeaderView::section{"
            "  background-color:__SURFACE_ALT__;"
            "  color:__TEXT__;"
            "  border:none;"
            "  border-right:1px solid __BORDER__;"
            "  border-bottom:1px solid __BORDER_STRONG__;"
            "}"
            "QHeaderView::section:hover{"
            "  background-color:__SURFACE_MUTED__;"
            "}"

            // ---------- Progress Bar Baseline ----------
            "QProgressBar{"
            "  background-color:__SURFACE_MUTED__;"
            "  color:__TEXT__;"
            "  border:1px solid __BORDER__;"
            "  border-radius:3px;"
            "  text-align:center;"
            "}"
            "QProgressBar::chunk{"
            "  background-color:__ACCENT__;"
            "  border-radius:2px;"
            "}"

            // ---------- Splitter baseline ----------
            "QSplitter::handle{"
            "  background-color:transparent;"
            "}"
            "QSplitter::handle:hover{"
            "  background-color:__ACCENT__;"
            "}"

            // ---------- Status Bar Baseline ----------
            "QStatusBar{"
            "  background-color:__WINDOW__;"
            "  color:__TEXT_SECONDARY__;"
            "}"
            "QStatusBar::item{"
            "  border:none;"
            "}"

            // ---------- Semantic Status Color Baseline ---------- Rule text is generated by
            // ThemeStatusRole; status labels only carry the ksword_status_role attribute and no longer hold
            // their own styleSheet. Colors are rebuilt along with this style block to follow the theme.
            "__STATUS_ROLE_RULES__"

            "__END_MARKER__\n");

        // Step arrows cannot be styled via QSS; instead, we select between black and white versions based on the 'maximum contrast monochrome color' of the button background.
        // Use the same logic as ksword_theme::themedComboBoxStyle for the dropdown arrow to ensure the arrow colors
        // in dropdowns and numeric boxes within the same interface do not appear with inconsistent brightness.
        const auto kArrowResourcePath = [](const QColor& backgroundColor, const bool pointingUp) {
            const bool kUseWhite =
                ksword_theme::maximumContrastMonochromeColor(backgroundColor) ==
                ksword_theme::whiteColor();
            if (pointingUp)
            {
                return kUseWhite
                    ? QStringLiteral(":/Icon/ks_control_up_white.svg")
                    : QStringLiteral(":/Icon/ks_control_up_black.svg");
            }
            return kUseWhite
                ? QStringLiteral(":/Icon/ks_control_down_white.svg")
                : QStringLiteral(":/Icon/ks_control_down_black.svg");
        };

        baseControlStyle.replace(QStringLiteral("__BEGIN_MARKER__"), QString::fromLatin1(kBaseControlStyleBeginMarker));
        baseControlStyle.replace(
            QStringLiteral("__ARROW_UP_OFF__"),
            QStringLiteral(":/Icon/ks_control_up_muted.svg"));
        baseControlStyle.replace(
            QStringLiteral("__ARROW_DOWN_OFF__"),
            QStringLiteral(":/Icon/ks_control_down_muted.svg"));
        baseControlStyle.replace(
            QStringLiteral("__ARROW_UP__"),
            kArrowResourcePath(ksword_theme::surfaceAltColor(), true));
        baseControlStyle.replace(
            QStringLiteral("__ARROW_DOWN__"),
            kArrowResourcePath(ksword_theme::surfaceAltColor(), false));
        baseControlStyle.replace(QStringLiteral("__STATUS_ROLE_RULES__"), buildStatusRoleStyleRules());
        baseControlStyle.replace(QStringLiteral("__END_MARKER__"), QString::fromLatin1(kBaseControlStyleEndMarker));
        baseControlStyle.replace(QStringLiteral("__WINDOW__"), ksword_theme::mainBackgroundColorHex());
        baseControlStyle.replace(QStringLiteral("__SURFACE__"), ksword_theme::surfaceColorHex());
        baseControlStyle.replace(QStringLiteral("__SURFACE_ALT__"), ksword_theme::surfaceAltColorHex());
        baseControlStyle.replace(QStringLiteral("__SURFACE_MUTED__"), ksword_theme::surfaceMutedColorHex());
        baseControlStyle.replace(QStringLiteral("__BORDER_STRONG__"), ksword_theme::borderStrongColorHex());
        baseControlStyle.replace(QStringLiteral("__BORDER__"), ksword_theme::borderColorHex());
        baseControlStyle.replace(QStringLiteral("__TEXT_SECONDARY__"), ksword_theme::textSecondaryColorHex());
        baseControlStyle.replace(QStringLiteral("__TEXT_DISABLED__"), ksword_theme::textDisabledColorHex());
        baseControlStyle.replace(QStringLiteral("__TEXT__"), ksword_theme::textPrimaryColorHex());
        baseControlStyle.replace(QStringLiteral("__ACCENT_PRESSED__"), ksword_theme::controlAccentPressedHex());
        baseControlStyle.replace(QStringLiteral("__ACCENT__"), ksword_theme::controlAccentHex());
        baseControlStyle.replace(
            QStringLiteral("__ON_ACCENT__"),
            ksword_theme::themeColorName(
                ksword_theme::maximumContrastMonochromeColor(ksword_theme::controlAccentColor())));
        return baseControlStyle;
    }
}
