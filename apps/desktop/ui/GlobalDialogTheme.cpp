#include "GlobalDialogTheme.h"

#include "../Theme.h"

#include <QApplication>
#include <QDialog>
#include <QEvent>
#include <QMessageBox>
#include <QPalette>
#include <QPointer>
#include <QPushButton>
#include <QStyle>
#include <QWidget>

namespace
{
    // kGlobalDialogThemePropertyName:
    // - Marks a QDialog as included in the global standard dialog theme.
    // - QSS uses this dynamic property as a selector to avoid polluting non-dialog controls.
    constexpr const char* kGlobalDialogThemePropertyName = "ksword_global_dialog_theme";

    // kGlobalDialogPolishingPropertyName:
    // - Marks that the current dialog is applying the theme;
    // - Prevent recursive entry into theme refresh after setStyleSheet triggers StyleChange.
    constexpr const char* kGlobalDialogPolishingPropertyName = "ksword_global_dialog_polishing";

    // kGlobalDialogDarkModePropertyName:
    // - Cache the last applied dark/light mode for pop-up dialogs.
    // - Reduces redundant style sheet refreshes under the same theme.
    constexpr const char* kGlobalDialogDarkModePropertyName = "ksword_global_dialog_dark_mode";

    // kOriginalDialogStyleSheetPropertyName:
    // - Save the original stylesheet of the business dialog.
    // - Global theme only appends fallback rules; it does not directly discard business-specific local styles.
    constexpr const char* kOriginalDialogStyleSheetPropertyName = "ksword_global_dialog_original_style_sheet";

    // kGlobalDialogStyleMarker:
    // - Write the separator marker in the merged stylesheet;
    // - During subsequent refreshes, uses this to distinguish between 'original business styles' and 'globally appended theme blocks'.
    constexpr const char* kGlobalDialogStyleMarker = "/* KSWORD_GLOBAL_DIALOG_THEME_BEGIN */";

    // dialogWindowColor purpose: Enables standard pop-up windows to use the global window background role.
    QColor dialogWindowColor(const bool darkModeEnabled)
    {
        Q_UNUSED(darkModeEnabled);
        return ksword_theme::windowColor();
    }

    // dialogSurfaceColor: Ensures the input area, list, and content panel use the derived surface role.
    QColor dialogSurfaceColor(const bool darkModeEnabled)
    {
        Q_UNUSED(darkModeEnabled);
        return ksword_theme::surfaceColor();
    }

    // dialogAlternateSurfaceColor: Returns the secondary surface color for dialog buttons and standard labels.
    QColor dialogAlternateSurfaceColor(const bool darkModeEnabled)
    {
        Q_UNUSED(darkModeEnabled);
        return ksword_theme::surfaceAltColor();
    }

    // dialogWindowTextColor purpose: Return adaptive text color for the window background.
    QColor dialogWindowTextColor(const bool darkModeEnabled)
    {
        Q_UNUSED(darkModeEnabled);
        return ksword_theme::mainBackgroundTextColor();
    }

    // dialogTextColor function: Returns the primary text color on the content surface.
    QColor dialogTextColor(const bool darkModeEnabled)
    {
        Q_UNUSED(darkModeEnabled);
        return ksword_theme::textPrimaryColor();
    }

    // dialogBorderColor function: Returns the border color derived from the main background seed.
    QColor dialogBorderColor(const bool darkModeEnabled)
    {
        Q_UNUSED(darkModeEnabled);
        return ksword_theme::borderColor();
    }

    // buildDialogPalette:
    // - Build the standard dialog palette.
    // - Works with QSS to handle native painting branches not covered by the stylesheet.
    QPalette buildDialogPalette(const QPalette& basePalette, const bool darkModeEnabled)
    {
        QPalette dialogPalette = basePalette;
        const QColor kWindowColor = dialogWindowColor(darkModeEnabled);
        const QColor kSurfaceColor = dialogSurfaceColor(darkModeEnabled);
        const QColor kAlternateSurfaceColor = dialogAlternateSurfaceColor(darkModeEnabled);
        const QColor kWindowTextColor = dialogWindowTextColor(darkModeEnabled);
        const QColor kTextColor = dialogTextColor(darkModeEnabled);
        const QColor kBorderColor = dialogBorderColor(darkModeEnabled);

        dialogPalette.setColor(QPalette::Window, kWindowColor);
        dialogPalette.setColor(QPalette::Base, kSurfaceColor);
        dialogPalette.setColor(QPalette::AlternateBase, kAlternateSurfaceColor);
        dialogPalette.setColor(QPalette::Text, kTextColor);
        dialogPalette.setColor(QPalette::WindowText, kWindowTextColor);
        dialogPalette.setColor(QPalette::Button, kAlternateSurfaceColor);
        dialogPalette.setColor(QPalette::ButtonText, kTextColor);
        dialogPalette.setColor(QPalette::Mid, kBorderColor);
        dialogPalette.setColor(QPalette::Highlight, ksword_theme::controlAccentColor());
        dialogPalette.setColor(
            QPalette::HighlightedText,
            ksword_theme::maximumContrastMonochromeColor(ksword_theme::controlAccentColor()));
        return dialogPalette;
    }

    // buildGlobalDialogStyleSheetBlock:
    // - Generates global appended styles for standard dialogs.
    // - Windows, input controls, lists, and labels use global neutral roles, fully following the custom main background color.
    QString buildGlobalDialogStyleSheetBlock(const bool darkModeEnabled)
    {
        const QString kWindowBackgroundText = ksword_theme::themeColorName(dialogWindowColor(darkModeEnabled));
        const QString kSurfaceBackgroundText = ksword_theme::themeColorName(dialogSurfaceColor(darkModeEnabled));
        const QString kAlternateSurfaceText = ksword_theme::themeColorName(dialogAlternateSurfaceColor(darkModeEnabled));
        const QString kWindowTextColorText = ksword_theme::themeColorName(dialogWindowTextColor(darkModeEnabled));
        const QString kTextColorText = ksword_theme::themeColorName(dialogTextColor(darkModeEnabled));
        const QString kBorderColorText = ksword_theme::themeColorName(dialogBorderColor(darkModeEnabled));

        QString styleSheetText = QString::fromLatin1(
            "\n__MARKER__\n"
            // Do not paint every descendant QWidget with the dialog Window layer here.
            // Group boxes and other nested content panes deliberately use the Surface layer.
            "QDialog[%2=\"true\"]{"
            "  background-color:__WINDOW_BACKGROUND__ !important;"
            "  color:__WINDOW_TEXT__ !important;"
            "}"
            "QDialog[%2=\"true\"] QLineEdit,"
            "QDialog[%2=\"true\"] QTextEdit,"
            "QDialog[%2=\"true\"] QPlainTextEdit,"
            "QDialog[%2=\"true\"] QSpinBox,"
            "QDialog[%2=\"true\"] QDoubleSpinBox{"
            "  background-color:__SURFACE_BACKGROUND__ !important;"
            "  color:__SURFACE_TEXT__ !important;"
            "  border:1px solid __BORDER__;"
            "  border-radius:3px;"
            "  padding:3px 6px;"
            "  selection-background-color:__ACCENT__;"
            "  selection-color:__ON_ACCENT__;"
            "}"
            "QDialog[%2=\"true\"] QAbstractScrollArea,"
            "QDialog[%2=\"true\"] QAbstractScrollArea::viewport{"
            "  background-color:__SURFACE_BACKGROUND__ !important;"
            "  color:__SURFACE_TEXT__ !important;"
            "  border:1px solid __BORDER__;"
            "  selection-background-color:__ACCENT__;"
            "  selection-color:__ON_ACCENT__;"
            "}"
            "QDialog[%2=\"true\"] QGroupBox{"
            "  background-color:__SURFACE_BACKGROUND__ !important;"
            "  color:__SURFACE_TEXT__ !important;"
            "  border:1px solid __BORDER__;"
            "  border-radius:4px;"
            "  margin-top:8px;"
            "}"
            "QDialog[%2=\"true\"] QGroupBox QLabel{"
            "  background-color:transparent !important;"
            "  color:__SURFACE_TEXT__ !important;"
            "}"
            "QDialog[%2=\"true\"] QCheckBox,"
            "QDialog[%2=\"true\"] QRadioButton{"
            "  background-color:transparent !important;"
            "  color:__SURFACE_TEXT__ !important;"
            "}"
            "QDialog[%2=\"true\"] QTabWidget::pane{"
            "  background-color:__SURFACE_BACKGROUND__ !important;"
            "  border:1px solid __BORDER__;"
            "}"
            "QDialog[%2=\"true\"] QTabBar::tab{"
            "  background-color:__SURFACE_ALT__ !important;"
            "  color:__SURFACE_TEXT__ !important;"
            "  border:1px solid __BORDER__;"
            "  padding:4px 10px;"
            "}"
            "QDialog[%2=\"true\"] QTabBar::tab:selected{"
            "  background-color:__ACCENT__ !important;"
            "  color:__ON_ACCENT__ !important;"
            "}"
            "QDialog[%2=\"true\"] QMenu{"
            "  background-color:__SURFACE_BACKGROUND__ !important;"
            "  color:__SURFACE_TEXT__ !important;"
            "  border:1px solid __BORDER__;"
            "}"
            "QDialog[%2=\"true\"] QMenu::item:selected{"
            "  background-color:__ACCENT__ !important;"
            "  color:__ON_ACCENT__ !important;"
            "}"
            "__COMBO_BOX_STYLE__"
            "__BUTTON_STYLE__");
        styleSheetText = styleSheetText.arg(QString::fromLatin1(kGlobalDialogThemePropertyName));
        styleSheetText.replace(QStringLiteral("__MARKER__"), QString::fromLatin1(kGlobalDialogStyleMarker));
        styleSheetText.replace(QStringLiteral("__WINDOW_BACKGROUND__"), kWindowBackgroundText);
        styleSheetText.replace(QStringLiteral("__SURFACE_BACKGROUND__"), kSurfaceBackgroundText);
        styleSheetText.replace(QStringLiteral("__SURFACE_ALT__"), kAlternateSurfaceText);
        styleSheetText.replace(QStringLiteral("__WINDOW_TEXT__"), kWindowTextColorText);
        styleSheetText.replace(QStringLiteral("__SURFACE_TEXT__"), kTextColorText);
        styleSheetText.replace(QStringLiteral("__BORDER__"), kBorderColorText);
        styleSheetText.replace(QStringLiteral("__ACCENT__"), ksword_theme::kPrimaryBlueHex);
        styleSheetText.replace(QStringLiteral("__ON_ACCENT__"), ksword_theme::onAccentHex());
        QString dialogComboBoxStyle = ksword_theme::themedComboBoxStyle();
        dialogComboBoxStyle.replace(
            QStringLiteral("QComboBox"),
            QStringLiteral("QDialog[%1=\"true\"] QComboBox")
                .arg(QString::fromLatin1(kGlobalDialogThemePropertyName)));
        styleSheetText.replace(QStringLiteral("__COMBO_BOX_STYLE__"), dialogComboBoxStyle);
        styleSheetText.replace(QStringLiteral("__BUTTON_STYLE__"), ksword_theme::themedButtonStyle());
        return styleSheetText;
    }

    // originalStyleSheetForDialog:
    // - Retrieve and cache the original style sheet for business dialog boxes.
    // - If the current style already contains the global marker, reuse the cached original style.
    QString originalStyleSheetForDialog(QDialog* dialog)
    {
        if (dialog == nullptr)
        {
            return QString();
        }

        const QString kCurrentStyleSheet = dialog->styleSheet();
        const bool kCurrentStyleHasThemeBlock = kCurrentStyleSheet.contains(QString::fromLatin1(kGlobalDialogStyleMarker));
        if (!kCurrentStyleHasThemeBlock)
        {
            dialog->setProperty(kOriginalDialogStyleSheetPropertyName, kCurrentStyleSheet);
            return kCurrentStyleSheet;
        }

        return dialog->property(kOriginalDialogStyleSheetPropertyName).toString();
    }

    // shouldThemeDialog:
    // - Determine whether a QDialog should be handled by the standard dialog theme handler.
    // - QMessageBox is handled by dedicated logic in UI/ThemedMessageBox and must be excluded.
    bool shouldThemeDialog(QDialog* dialog)
    {
        if (dialog == nullptr)
        {
            return false;
        }
        if (qobject_cast<QMessageBox*>(dialog) != nullptr)
        {
            return false;
        }
        return true;
    }

    // GlobalDialogStyler:
    // - QApplication-level event filter;
    // - Unify background and control color filling during normal dialog display, theme switching, and style changes.
    class GlobalDialogStyler final : public QObject
    {
    public:
        // Constructor:
        // - Parameter parentObject: Typically QApplication;
        // - Return value: None; QObject lifetime is managed by the parent object.
        explicit GlobalDialogStyler(QObject* parentObject)
            : QObject(parentObject)
        {
        }

        // eventFilter:
        // - Listens to display and style-related events for standard pop-up dialogs.
        // - Calls polishDialog on trigger to uniformly apply the theme.
        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override
        {
            QDialog* dialog = qobject_cast<QDialog*>(watchedObject);
            if (!shouldThemeDialog(dialog) || eventObject == nullptr)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            const QEvent::Type kEventType = eventObject->type();
            if (kEventType == QEvent::Polish ||
                kEventType == QEvent::Show ||
                kEventType == QEvent::PaletteChange ||
                kEventType == QEvent::ApplicationPaletteChange ||
                kEventType == QEvent::StyleChange)
            {
                if (!dialog->property(kGlobalDialogPolishingPropertyName).toBool())
                {
                    polishDialog(dialog);
                }
            }

            return QObject::eventFilter(watchedObject, eventObject);
        }

        // polishDialog:
        // - Apply the current theme to a single standard dialog;
        // - Does not return a value; only modifies the control's palette, properties, and stylesheets.
        void polishDialog(QDialog* dialog) const
        {
            if (!shouldThemeDialog(dialog))
            {
                return;
            }
            if (dialog->property(kGlobalDialogPolishingPropertyName).toBool())
            {
                return;
            }

            struct PolishingResetter
            {
                QDialog* targetDialog = nullptr; // targetDialog: the dialog requiring re-entry flag restoration.
                ~PolishingResetter()
                {
                    if (targetDialog != nullptr)
                    {
                        targetDialog->setProperty(kGlobalDialogPolishingPropertyName, false);
                    }
                }
            };

            dialog->setProperty(kGlobalDialogPolishingPropertyName, true);
            PolishingResetter resetter{ dialog };

            const bool kDarkModeEnabled = ksword_theme::isDarkModeEnabled();
            const QPalette kSourcePalette = (qApp != nullptr) ? qApp->palette() : dialog->palette();
            const QString kOriginalStyleSheet = originalStyleSheetForDialog(dialog);
            const QString kTargetStyleSheet = kOriginalStyleSheet + buildGlobalDialogStyleSheetBlock(kDarkModeEnabled);

            dialog->setProperty(kGlobalDialogThemePropertyName, QStringLiteral("true"));
            dialog->setProperty(kGlobalDialogDarkModePropertyName, kDarkModeEnabled);
            dialog->setAttribute(Qt::WA_StyledBackground, true);
            dialog->setAutoFillBackground(true);
            dialog->setPalette(buildDialogPalette(kSourcePalette, kDarkModeEnabled));

            if (dialog->styleSheet() != kTargetStyleSheet)
            {
                dialog->setStyleSheet(kTargetStyleSheet);
            }

            const QList<QPushButton*> kButtonList = dialog->findChildren<QPushButton*>();
            for (QPushButton* button : kButtonList)
            {
                if (button == nullptr)
                {
                    continue;
                }
                button->setCursor(Qt::PointingHandCursor);
                if (QStyle* buttonStyle = button->style())
                {
                    buttonStyle->unpolish(button);
                    buttonStyle->polish(button);
                }
            }
        }
    };

    // globalDialogStylerInstance:
    // - Returns the singleton instance of the global dialog styler for standard dialogs;
    // - Singleton parent object binds to QApplication to avoid manual release.
    GlobalDialogStyler* globalDialogStylerInstance()
    {
        static QPointer<GlobalDialogStyler> stylerInstance;
        if (stylerInstance == nullptr && qApp != nullptr)
        {
            stylerInstance = new GlobalDialogStyler(qApp);
        }
        return stylerInstance.data();
    }
}

namespace ks::ui
{
    void installGlobalDialogTheme(QApplication* appInstance)
    {
        if (appInstance == nullptr)
        {
            return;
        }

        GlobalDialogStyler* stylerInstance = globalDialogStylerInstance();
        if (stylerInstance == nullptr)
        {
            return;
        }

        appInstance->installEventFilter(stylerInstance);
        refreshGlobalDialogTheme();
    }

    void refreshGlobalDialogTheme()
    {
        GlobalDialogStyler* stylerInstance = globalDialogStylerInstance();
        if (stylerInstance == nullptr || qApp == nullptr)
        {
            return;
        }

        const QWidgetList kTopLevelWidgetList = qApp->topLevelWidgets();
        for (QWidget* topLevelWidget : kTopLevelWidgetList)
        {
            QDialog* dialog = qobject_cast<QDialog*>(topLevelWidget);
            if (!shouldThemeDialog(dialog))
            {
                continue;
            }

            stylerInstance->polishDialog(dialog);
        }
    }
}
