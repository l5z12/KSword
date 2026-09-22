#include "ProcessDock.Support.h"

namespace ksword::ui::process_dock
{
    // usageRatioToHighlightColor:
    // - Return theme blue transparent highlight based on usage ratio (0~1).
    // - Higher usage results in a larger alpha value, making the color appear visually 'darker'.
    QColor usageRatioToHighlightColor(double usageRatio)
    {
        usageRatio = std::clamp(usageRatio, 0.0, 1.0);
        const int kAlphaValue = static_cast<int>(24.0 + usageRatio * 146.0);
        QColor highlightColor = ksword_theme::primaryBlueColor;
        highlightColor.setAlpha(kAlphaValue);
        return highlightColor;
    }

    // hasDetailWindowSignificantChange:
    // - Determine if there are significant changes between two process records that require immediate synchronization to the detail window.
    // - Filters out minor fluctuations via a threshold to reduce UI lag during refreshes.
    bool hasDetailWindowSignificantChange(
        const ks::process::ProcessRecord& oldRecord,
        const ks::process::ProcessRecord& newRecord)
    {
        if (oldRecord.pid != newRecord.pid ||
            oldRecord.creationTime100ns != newRecord.creationTime100ns)
        {
            return true;
        }

        if (std::fabs(oldRecord.cpuPercent - newRecord.cpuPercent) >= 4.0)
        {
            return true;
        }
        if (std::fabs(oldRecord.ramMB - newRecord.ramMB) >= 16.0)
        {
            return true;
        }
        if (std::fabs(oldRecord.diskMBps - newRecord.diskMBps) >= 1.0)
        {
            return true;
        }
        if (std::fabs(oldRecord.netKBps - newRecord.netKBps) >= 8.0)
        {
            return true;
        }
        if (std::fabs(oldRecord.gpuPercent - newRecord.gpuPercent) >= 5.0)
        {
            return true;
        }
        if (oldRecord.protectionLevelKnown != newRecord.protectionLevelKnown ||
            oldRecord.protectionLevel != newRecord.protectionLevel ||
            oldRecord.protectionLevelText != newRecord.protectionLevelText)
        {
            return true;
        }
        if (oldRecord.injectionSurfaceState != newRecord.injectionSurfaceState ||
            oldRecord.injectionDynamicRegions != newRecord.injectionDynamicRegions ||
            oldRecord.injectionWritableExecRegions != newRecord.injectionWritableExecRegions)
        {
            return true;
        }

        if (oldRecord.threadCount != newRecord.threadCount ||
            oldRecord.handleCount != newRecord.handleCount ||
            oldRecord.parentPid != newRecord.parentPid ||
            oldRecord.isAdmin != newRecord.isAdmin ||
            oldRecord.signatureTrusted != newRecord.signatureTrusted)
        {
            return true;
        }

        if (oldRecord.imagePath != newRecord.imagePath ||
            oldRecord.commandLine != newRecord.commandLine ||
            oldRecord.userName != newRecord.userName ||
            oldRecord.signatureState != newRecord.signatureState ||
            oldRecord.signaturePublisher != newRecord.signaturePublisher ||
            oldRecord.startTimeText != newRecord.startTimeText)
        {
            return true;
        }

        return false;
    }

    // Unify button blue style to match the existing theme.
    QString buildBlueButtonStyle(const bool iconOnlyButton)
    {
        // Use tighter padding for icon-only buttons to avoid excessive whitespace.
        const QString kPaddingText = iconOnlyButton ? QStringLiteral("4px") : QStringLiteral("4px 10px");
        return QStringLiteral(
            "QPushButton {"
            "  color: %1;"
            "  background: %6;"
            "  border: 1px solid %2;"
            "  border-radius: 3px;"
            "  padding: %5;"
            "}"
            "QPushButton:hover {"
            "  background: %3;"
            "  color: %7;"
            "  border: 1px solid %3;"
            "}"
            "QPushButton:pressed {"
            "  background: %4;"
            "  color: %7;"
            "}")
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::kPrimaryBlueBorderHex)
            .arg(ksword_theme::kPrimaryBlueHoverHex)
            .arg(ksword_theme::kPrimaryBluePressedHex)
            .arg(kPaddingText)
            .arg(ksword_theme::surfaceHex())
            .arg(QStringLiteral("palette(highlighted-text)"));
    }

    // ComboBox theme stroke style, keeping the same color scheme as the button.
    QString buildBlueComboBoxStyle()
    {
        return ksword_theme::themedComboBoxStyle();
    }

    // buildBlueComboBoxPopupViewStyle:
    // - Directly sets the popup list style for QComboBox::view().
    // - QComboBox's popup is an independent item view; the parent selector cannot override the white background in some Qt/Windows themes.
    // - Return: QSS applied only to the popup view; the main box style is handled by buildBlueComboBoxStyle.
    QString buildBlueComboBoxPopupViewStyle()
    {
        return ksword_theme::themedComboBoxPopupViewStyle();
    }

    // applyBlueComboBoxRuntimeStyle:
    // - At runtime, set both the stylesheet and palette simultaneously.
    // - Input comboBoxPointer: the two dropdowns at the top of the Process page;
    // - Return: None. Directly correct the dark/light theme for the main box and popup view.
    void applyBlueComboBoxRuntimeStyle(QComboBox* comboBoxPointer)
    {
        if (comboBoxPointer == nullptr)
        {
            return;
        }

        const QString kComboBackgroundColor = ksword_theme::surfaceHex();
        const QString kComboTextColor = ksword_theme::textPrimaryHex();

        comboBoxPointer->setStyleSheet(buildBlueComboBoxStyle());

        QPalette comboPalette = comboBoxPointer->palette();
        comboPalette.setColor(QPalette::Base, QColor(kComboBackgroundColor));
        comboPalette.setColor(QPalette::Window, QColor(kComboBackgroundColor));
        comboPalette.setColor(QPalette::Button, QColor(kComboBackgroundColor));
        comboPalette.setColor(QPalette::Text, QColor(kComboTextColor));
        comboPalette.setColor(QPalette::ButtonText, QColor(kComboTextColor));
        comboPalette.setColor(QPalette::Highlight, ksword_theme::controlAccentColor());
        comboPalette.setColor(
            QPalette::HighlightedText,
            ksword_theme::maximumContrastMonochromeColor(ksword_theme::controlAccentColor()));
        comboBoxPointer->setPalette(comboPalette);

        QAbstractItemView* popupView = comboBoxPointer->view();
        if (popupView == nullptr)
        {
            return;
        }

        popupView->setPalette(comboPalette);
        popupView->setAutoFillBackground(true);
        popupView->setStyleSheet(buildBlueComboBoxPopupViewStyle());
        if (popupView->viewport() != nullptr)
        {
            popupView->viewport()->setAutoFillBackground(true);
            popupView->viewport()->setPalette(comboPalette);
            popupView->viewport()->setStyleSheet(QStringLiteral(
                "background:%1 !important;"
                "background-color:%1 !important;")
                .arg(kComboBackgroundColor));
        }
    }

    // Unifies the theme border for 'standard input boxes'.
    QString buildBlueLineEditStyle()
    {
        return QStringLiteral(
            "QLineEdit, QPlainTextEdit, QTextEdit {"
            "  border: 1px solid %2;"
            "  border-radius: 3px;"
            "  background: %3;"
            "  color: %4;"
            "  padding: 3px 5px;"
            "}"
            "QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus {"
            "  border: 1px solid %1;"
            "}")
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::textPrimaryHex());
    }

    // applyTransparentContainerStyle:
    // - Only changes the background of container controls in the 'Create Process' page to transparent.
    // - Does not affect existing theme styles for input boxes, buttons, etc.
    void applyTransparentContainerStyle(QWidget* widgetPointer)
    {
        if (widgetPointer == nullptr)
        {
            return;
        }

        widgetPointer->setAttribute(Qt::WA_StyledBackground, true);
        widgetPointer->setAutoFillBackground(false);
        widgetPointer->setStyleSheet(
            widgetPointer->styleSheet()
            + QStringLiteral("background:transparent;background-color:transparent;"));

        QAbstractScrollArea* scrollAreaPointer = qobject_cast<QAbstractScrollArea*>(widgetPointer);
        if (scrollAreaPointer == nullptr || scrollAreaPointer->viewport() == nullptr)
        {
            return;
        }

        scrollAreaPointer->viewport()->setAttribute(Qt::WA_StyledBackground, true);
        scrollAreaPointer->viewport()->setAutoFillBackground(false);
        scrollAreaPointer->viewport()->setStyleSheet(
            scrollAreaPointer->viewport()->styleSheet()
            + QStringLiteral("background:transparent;background-color:transparent;"));
    }

    // Complete token privilege list: reuses the Windows SDK Se*privilege directory maintained by the process module.
    QStringList tokenPrivilegeNames()
    {
        QStringList privilegeNames;
        privilegeNames.reserve(static_cast<qsizetype>(ks::process::knownTokenPrivilegeNames().size()));
        for (const std::string& privilegeName : ks::process::knownTokenPrivilegeNames())
        {
            privilegeNames.push_back(QString::fromLatin1(privilegeName.c_str()));
        }
        return privilegeNames;
    }
}
