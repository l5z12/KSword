#include "ThemedMessageBox.h"

#include "../internationalization/LanguageManager.h"
#include "../Theme.h"

#include <QAbstractButton>
#include <QApplication>
#include <QCoreApplication>
#include <QDialogButtonBox>
#include <QEvent>
#include <QFileIconProvider>
#include <QFileInfo>
#include <QFontMetrics>
#include <QGridLayout>
#include <QIcon>
#include <QLabel>
#include <QMessageBox>
#include <QMouseEvent>
#include <QMargins>
#include <QPointer>
#include <QPixmap>
#include <QPushButton>
#include <QResizeEvent>
#include <QScreen>
#include <QSize>
#include <QSizePolicy>
#include <QStyle>
#include <QTextEdit>
#include <QWidget>
#include <QWindow>

#include <algorithm>

namespace
{
    // kThemedMessageBoxObjectName:
    // - Serves as the unique object name anchor for the global message box stylesheet;
    // - Avoid accidentally affecting regular QDialog/QWidget.
    constexpr const char* kThemedMessageBoxObjectName = "KswordThemedMessageBox";

    // kThemePolishingPropertyName:
    // - Mark whether the current message box is currently undergoing theme rewriting.
    // - Used to prevent re-entrant crashes caused by recursive callbacks from StyleChange/Polish events.
    constexpr const char* kThemePolishingPropertyName = "ksword_theme_polishing";

    // kThemeModePropertyName:
    // - Cache the last applied light/dark mode for the message box;
    // - Avoids triggering extra style events by repeatedly calling setStyleSheet/setPalette under the same theme.
    constexpr const char* kThemeModePropertyName = "ksword_theme_dark_mode";

    // kMessageBoxTitleBarObjectName:
    // - Marks the internal custom-drawn title bar of QMessageBox.
    // - Used to locate existing title bars during repeated refreshes to avoid duplicate insertion.
    constexpr const char* kMessageBoxTitleBarObjectName = "KswordThemedMessageBoxTitleBar";

    // kMessageBoxTitleBarInstalledPropertyName:
    // - Marks that the QMessageBox root layout has already reserved top margin for the floating title bar;
    // - Prevents repeated accumulation of top margin after multiple Palette/StyleChange triggers.
    constexpr const char* kMessageBoxTitleBarInstalledPropertyName = "ksword_message_box_titlebar_margin_reserved";

    // kMessageBoxOriginalMarginPropertyName:
    // - Record the original layout margins of the QMessageBox;
    // - During subsequent theme refreshes, calculates the top margin offset using the original value to avoid repeated stacking.
    constexpr const char* kMessageBoxOriginalMarginLeftPropertyName = "ksword_message_box_original_margin_left";
    constexpr const char* kMessageBoxOriginalMarginTopPropertyName = "ksword_message_box_original_margin_top";
    constexpr const char* kMessageBoxOriginalMarginRightPropertyName = "ksword_message_box_original_margin_right";
    constexpr const char* kMessageBoxOriginalMarginBottomPropertyName = "ksword_message_box_original_margin_bottom";

    // kMessageBoxTitleLabelObjectName:
    // - Mark the title text control in the custom-drawn title bar;
    // - Synchronize the current QMessageBox windowTitle during each polish.
    constexpr const char* kMessageBoxTitleLabelObjectName = "KswordThemedMessageBoxTitleLabel";

    // Message box size constants:
    // - kMessageBoxMinWidth: minimum allowed width of the message box;
    // - kMessageBoxPreferredWidth: The default preferred readable width.
    // - kMessageBoxHardMaxWidth: hard upper limit for message box width to prevent excessive width.
    // - kMessageBoxScreenMargin: Safe margin from screen edges.
    // - kMessageLabelHorizontalReserve: Reserve horizontal space for the icon and padding in the text area.
    constexpr int kMessageBoxMinWidth = 360;
    constexpr int kMessageBoxPreferredWidth = 520;
    constexpr int kMessageBoxHardMaxWidth = 820;
    constexpr int kMessageBoxScreenMargin = 96;
    constexpr int kMessageLabelHorizontalReserve = 148;
    constexpr int kMessageBoxOuterBorderWidth = 1;
    constexpr int kMessageTitleBarHeight = 34;
    constexpr int kMessageLogoSize = 22;
    constexpr int kMessageTitleBarContentGap = 8;
    constexpr int kMessageTitleBarLeftMargin = 10;
    constexpr int kMessageTitleBarRightMargin = 4;
    constexpr int kMessageTitleBarItemSpacing = 8;

    // computeMessageBoxMaxWidth:
    // - Calculate safe maximum width based on the current message box's screen;
    // - Prevent message boxes from overflowing the screen's available area due to long text.
    int computeMessageBoxMaxWidth(const QMessageBox* messageBox)
    {
        QScreen* targetScreen = messageBox != nullptr ? messageBox->screen() : nullptr;
        if (targetScreen == nullptr && qApp != nullptr)
        {
            targetScreen = qApp->primaryScreen();
        }
        if (targetScreen == nullptr)
        {
            return kMessageBoxPreferredWidth;
        }

        const int kAvailableWidth = std::max(
            targetScreen->availableGeometry().width() - kMessageBoxScreenMargin,
            kMessageBoxMinWidth);
        const int kCappedAvailableWidth = std::min(kAvailableWidth, kMessageBoxHardMaxWidth);
        return std::max(kCappedAvailableWidth, kMessageBoxMinWidth);
    }

    // polishMessageTextLabel:
    // - Unify automatic line wrapping and width constraints for message box text labels.
    // - Solves the issue of long text forcibly widening the dialog box.
    void polishMessageTextLabel(QLabel* targetLabel, const int maxTextWidth)
    {
        if (targetLabel == nullptr)
        {
            return;
        }

        targetLabel->setWordWrap(true);
        targetLabel->setMinimumWidth(0);
        targetLabel->setMaximumWidth(std::max(maxTextWidth, 220));
        targetLabel->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
        targetLabel->setAlignment(Qt::AlignLeft | Qt::AlignTop);
        targetLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    }

    // resolveApplicationIcon:
    // - Prefer reading the Win32 native application icon from the current process EXE.
    // - Second, reuse the windowIcon already set by QApplication or the host window.
    // - Return value: A QIcon usable for the title bar and window icon; returns an empty icon if all sources fail.
    QIcon resolveApplicationIcon(const QMessageBox* messageBox)
    {
        // executablePathText usage: Locates the currently running Ksword5.1.exe.
        const QString kExecutablePathText = QCoreApplication::applicationFilePath();
        if (!kExecutablePathText.trimmed().isEmpty())
        {
            // executableFileInfo usage: Passed to QFileIconProvider to resolve the system application icon from EXE resources.
            const QFileInfo kExecutableFileInfo(kExecutablePathText);
            if (kExecutableFileInfo.exists())
            {
                // iconProvider: Use Windows Shell's same icon resolution for paths to avoid incorrectly using MainLogo.
                QFileIconProvider iconProvider;
                const QIcon kExecutableIcon = iconProvider.icon(kExecutableFileInfo);
                if (!kExecutableIcon.isNull())
                {
                    return kExecutableIcon;
                }
            }
        }

        if (qApp != nullptr)
        {
            // applicationIcon usage: compatible with future scenarios where main.cpp explicitly sets the default QApplication icon.
            const QIcon kApplicationIcon = QApplication::windowIcon();
            if (!kApplicationIcon.isNull())
            {
                return kApplicationIcon;
            }
        }

        // parentWidget usage: Traverses upward to find the business parent window, supporting scenarios where local windows have individually set icons.
        const QWidget* parentWidget = messageBox != nullptr ? messageBox->parentWidget() : nullptr;
        while (parentWidget != nullptr)
        {
            const QIcon kParentWindowIcon = parentWidget->windowIcon();
            if (!kParentWindowIcon.isNull())
            {
                return kParentWindowIcon;
            }
            parentWidget = parentWidget->parentWidget();
        }

        // messageBoxIcon: Preserves the QMessageBox's own windowIcon to avoid having no icon at all.
        const QIcon kMessageBoxIcon = messageBox != nullptr ? messageBox->windowIcon() : QIcon();
        if (!kMessageBoxIcon.isNull())
        {
            return kMessageBoxIcon;
        }

        return QIcon();
    }

    // MessageBoxTitleBar:
    // - Acts as a custom-drawn title bar for QMessageBox;
    // - Responsible for displaying the left-side logo/title and dragging the window via mouse.
    // - No minimize, maximize, or close entry points; the message box can only be closed via business buttons.
    class MessageBoxTitleBar final : public QWidget
    {
    public:
        // Constructor:
        // - Parameter ownerMessageBox: The QMessageBox to which this belongs.
        // - Handling logic: Create logo and title text; disable close/minimize/maximize entries uniformly.
        // - Return value: None.
        explicit MessageBoxTitleBar(QMessageBox* ownerMessageBox)
            : QWidget(ownerMessageBox),
              ownerMessageBox_(ownerMessageBox)
        {
            setObjectName(QString::fromLatin1(kMessageBoxTitleBarObjectName));
            setFixedHeight(kMessageTitleBarHeight);
            setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
            setAttribute(Qt::WA_StyledBackground, true);

            logoLabel_ = new QLabel(this);
            logoLabel_->setFixedSize(kMessageLogoSize, kMessageLogoSize);
            logoLabel_->setAlignment(Qt::AlignCenter);
            logoLabel_->setAttribute(Qt::WA_TransparentForMouseEvents, true);
            const QIcon kApplicationIcon = resolveApplicationIcon(ownerMessageBox);
            if (!kApplicationIcon.isNull())
            {
                // titlePixmap usage: Fetch image at fixed title bar dimensions to avoid using the startup page MainLogo as the window icon.
                const QPixmap kTitlePixmap = kApplicationIcon.pixmap(QSize(kMessageLogoSize, kMessageLogoSize));
                logoLabel_->setPixmap(kTitlePixmap);
            }

            titleLabel_ = new QLabel(this);
            titleLabel_->setObjectName(QString::fromLatin1(kMessageBoxTitleLabelObjectName));
            titleLabel_->setAlignment(Qt::AlignVCenter | Qt::AlignLeft);
            titleLabel_->setMinimumWidth(0);
            titleLabel_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
            titleLabel_->setTextFormat(Qt::PlainText);
            titleLabel_->setAttribute(Qt::WA_TransparentForMouseEvents, true);

            updateTitleText();
            syncChildGeometry();
        }

        // updateTitleText:
        // - Synchronize the current title text of QMessageBox.
        // - If the business logic has not set a title, fall back to using the application name.
        void updateTitleText()
        {
            QString titleText = ownerMessageBox_ != nullptr ? ownerMessageBox_->windowTitle().trimmed() : QString();
            if (titleText.isEmpty() && qApp != nullptr)
            {
                titleText = qApp->applicationDisplayName().trimmed();
                if (titleText.isEmpty())
                {
                    titleText = qApp->applicationName().trimmed();
                }
            }
            if (titleText.isEmpty())
            {
                titleText = QStringLiteral("Ksword");
            }
            if (titleLabel_ != nullptr)
            {
                fullTitleText_ = titleText;
                titleLabel_->setToolTip(titleText);
                syncChildGeometry();
            }
        }

        // syncChildGeometry:
        // - Manually calculate the logo and title positions;
        // - The title uses only the current visible title bar width to prevent long titles from pushing the control layout outside the window;
        // - Return value: None.
        void syncChildGeometry()
        {
            const int kTitleBarWidth = std::max(width(), 0);
            const int kTitleBarHeight = std::max(height(), kMessageTitleBarHeight);

            // logoVisible usage: In extremely narrow abnormal widths, prioritize title bar readability; Logo is allowed to be hidden.
            const int kMinimumWidthForLogo =
                kMessageTitleBarLeftMargin +
                kMessageLogoSize +
                kMessageTitleBarRightMargin;
            const bool kLogoVisible = kTitleBarWidth >= kMinimumWidthForLogo;
            const int kLogoX = kMessageTitleBarLeftMargin;
            const int kLogoY = std::max((kTitleBarHeight - kMessageLogoSize) / 2, 0);
            if (logoLabel_ != nullptr)
            {
                logoLabel_->setVisible(kLogoVisible);
                logoLabel_->setGeometry(kLogoX, kLogoY, kMessageLogoSize, kMessageLogoSize);
            }

            // titleX/titleRight usage: Title occupies only the remaining space within the title bar's safe area; omit if space is insufficient.
            const int kTitleX = kLogoVisible
                ? (kMessageTitleBarLeftMargin + kMessageLogoSize + kMessageTitleBarItemSpacing)
                : kMessageTitleBarLeftMargin;
            const int kTitleRight = std::max(kTitleBarWidth - kMessageTitleBarRightMargin, kTitleX);
            const int kTitleWidth = std::max(kTitleRight - kTitleX, 0);
            if (titleLabel_ != nullptr)
            {
                titleLabel_->setGeometry(kTitleX, 0, kTitleWidth, kTitleBarHeight);

                // elidedTitle usage: Under Qt6, QLabel may still report a large sizeHint based on the full text; manually eliding removes the source of squeezing.
                const QFontMetrics kTitleFontMetrics(titleLabel_->font());
                const QString kElidedTitle = kTitleWidth > 0
                    ? kTitleFontMetrics.elidedText(fullTitleText_, Qt::ElideRight, kTitleWidth)
                    : QString();
                titleLabel_->setText(kElidedTitle);
            }
        }

        // sizeHint action: Provide the Qt6 style system with a stable title bar suggested size.
        // Return value: A fixed height and minimum message box width.
        QSize sizeHint() const override
        {
            return QSize(kMessageBoxMinWidth, kMessageTitleBarHeight);
        }

        // minimumSizeHint purpose: Declares the minimum title bar size capable of holding the logo and safety margins.
        // Return value: Minimum size after adding the logo and left/right safe margins.
        QSize minimumSizeHint() const override
        {
            return QSize(
                kMessageTitleBarLeftMargin + kMessageLogoSize + kMessageTitleBarRightMargin,
                kMessageTitleBarHeight);
        }

    protected:
        // resizeEvent:
        // - Qt6 dialogs update child window sizes multiple times during adjustSize, show, or high-DPI switches.
        // - Re-truncate the title after each size change to avoid inheriting old layout results.
        // - Return value: None.
        void resizeEvent(QResizeEvent* resizeEventPointer) override
        {
            QWidget::resizeEvent(resizeEventPointer);
            syncChildGeometry();
        }

        // mousePressEvent:
        // - Records the starting point for dragging the title bar;
        // - Return value: None; only updates the drag state.
        void mousePressEvent(QMouseEvent* mouseEventPointer) override
        {
            if (mouseEventPointer != nullptr && mouseEventPointer->button() == Qt::LeftButton)
            {
                dragCandidateActive_ = true;
                dragInProgress_ = false;
                dragPressGlobalPos_ = mouseEventPointer->globalPosition().toPoint();
                if (QWidget* hostWidget = window())
                {
                    windowPressTopLeft_ = hostWidget->frameGeometry().topLeft();
                }
                mouseEventPointer->accept();
                return;
            }
            QWidget::mousePressEvent(mouseEventPointer);
        }

        // mouseMoveEvent:
        // - Initiates system window drag after reaching the drag threshold;
        // - If the platform does not support startSystemMove, fall back to manual move.
        void mouseMoveEvent(QMouseEvent* mouseEventPointer) override
        {
            if (mouseEventPointer != nullptr
                && dragCandidateActive_
                && (mouseEventPointer->buttons() & Qt::LeftButton))
            {
                const QPoint kCurrentGlobalPos = mouseEventPointer->globalPosition().toPoint();
                const int kDragDistance = (kCurrentGlobalPos - dragPressGlobalPos_).manhattanLength();
                QWidget* hostWidget = window();
                if (hostWidget != nullptr && kDragDistance >= QApplication::startDragDistance())
                {
                    if (!dragInProgress_)
                    {
                        dragInProgress_ = true;
                        QWindow* hostWindowHandle = hostWidget->windowHandle();
                        if (hostWindowHandle != nullptr && hostWindowHandle->startSystemMove())
                        {
                            mouseEventPointer->accept();
                            return;
                        }
                    }

                    hostWidget->move(windowPressTopLeft_ + kCurrentGlobalPos - dragPressGlobalPos_);
                    mouseEventPointer->accept();
                    return;
                }
            }
            QWidget::mouseMoveEvent(mouseEventPointer);
        }

        // mouseReleaseEvent:
        // - Clear drag candidate state.
        // - Return value: None.
        void mouseReleaseEvent(QMouseEvent* mouseEventPointer) override
        {
            dragCandidateActive_ = false;
            dragInProgress_ = false;
            QWidget::mouseReleaseEvent(mouseEventPointer);
        }

    private:
        QPointer<QMessageBox> ownerMessageBox_; // m_ownerMessageBox: Owner message box.
        QLabel* logoLabel_ = nullptr;           // m_logoLabel: Left application icon control.
        QLabel* titleLabel_ = nullptr;          // m_titleLabel: Title text control.
        QString fullTitleText_;                 // m_fullTitleText: The complete title text without ellipsis.
        bool dragCandidateActive_ = false;      // m_dragCandidateActive: Whether in drag candidate mode.
        bool dragInProgress_ = false;           // m_dragInProgress: Whether dragging has started.
        QPoint dragPressGlobalPos_;             // m_dragPressGlobalPos: Global coordinates on press.
        QPoint windowPressTopLeft_;             // m_windowPressTopLeft: Top-left corner of the window at press time.
    };

    // messageBoxWindowColor function: Returns the main background color of the message box.
    QColor messageBoxWindowColor(const bool darkModeEnabled)
    {
        Q_UNUSED(darkModeEnabled);
        return ksword_theme::windowColor();
    }

    // messageBoxSurfaceColor function: Returns the internal panel color of the message box.
    QColor messageBoxSurfaceColor(const bool darkModeEnabled)
    {
        Q_UNUSED(darkModeEnabled);
        return ksword_theme::surfaceColor();
    }

    // messageBoxBorderColor: Returns the color of the internal control separator line for the message box.
    QColor messageBoxBorderColor(const bool darkModeEnabled)
    {
        Q_UNUSED(darkModeEnabled);
        return ksword_theme::borderColor();
    }

    // messageBoxTextColor: Returns the main text color of the message box.
    QColor messageBoxTextColor(const bool darkModeEnabled)
    {
        Q_UNUSED(darkModeEnabled);
        return ksword_theme::textPrimaryColor();
    }

    // messageBoxSecondaryTextColor: Returns the color for descriptive text.
    QColor messageBoxSecondaryTextColor(const bool darkModeEnabled)
    {
        Q_UNUSED(darkModeEnabled);
        return ksword_theme::textSecondaryColor();
    }

    // messageBoxSecondaryButtonColor: Returns the secondary button background color.
    QColor messageBoxSecondaryButtonColor(const bool darkModeEnabled)
    {
        Q_UNUSED(darkModeEnabled);
        return ksword_theme::surfaceAltColor();
    }

    // messageBoxSecondaryButtonHoverColor: Returns the hover background color for the secondary button.
    QColor messageBoxSecondaryButtonHoverColor(const bool darkModeEnabled)
    {
        Q_UNUSED(darkModeEnabled);
        return ksword_theme::surfaceMutedColor();
    }

    // buildMessageBoxStyleSheet:
    // - Generate a QMessageBox-specific stylesheet.
    // - Unify the visual style for backgrounds, labels, detail text boxes, and buttons.
    QString buildMessageBoxStyleSheet(const bool darkModeEnabled)
    {
        const QString kWindowColorText = messageBoxWindowColor(darkModeEnabled).name(QColor::HexRgb);
        const QString kSurfaceColorText = messageBoxSurfaceColor(darkModeEnabled).name(QColor::HexRgb);
        const QString kBorderColorText = messageBoxBorderColor(darkModeEnabled).name(QColor::HexRgb);
        const QString kOuterBorderColorText = ksword_theme::kPrimaryBlueHex;
        const QString kTextColorText = messageBoxTextColor(darkModeEnabled).name(QColor::HexRgb);
        const QString kSecondaryTextColorText = messageBoxSecondaryTextColor(darkModeEnabled).name(QColor::HexRgb);
        const QString kSecondaryButtonColorText = messageBoxSecondaryButtonColor(darkModeEnabled).name(QColor::HexRgb);
        const QString kSecondaryButtonHoverColorText = messageBoxSecondaryButtonHoverColor(darkModeEnabled).name(QColor::HexRgb);

        return QStringLiteral(
            "QMessageBox#%1{"
            "  background-color:%2;"
            "  color:%3;"
            "  border:%13px solid %14;"
            "  border-radius:0px;"
            "}"
            "QMessageBox#%1 QWidget{"
            "  background:transparent;"
            "  color:%3;"
            "}"
            "QMessageBox#%1 QWidget#%10{"
            "  background-color:%11;"
            "  color:%3;"
            "  border-bottom:1px solid %4;"
            "}"
            "QMessageBox#%1 QLabel#%12{"
            "  color:%3;"
            "  font-size:13px;"
            "  font-weight:700;"
            "}"
            "QMessageBox#%1 QLabel#qt_msgbox_label{"
            "  font-size:14px;"
            "  font-weight:700;"
            "  min-width:0px;"
            "  padding:2px 6px 2px 6px;"
            "}"
            "QMessageBox#%1 QLabel#qt_msgbox_informativelabel{"
            "  color:%5;"
            "  font-size:13px;"
            "  min-width:0px;"
            "  padding:0 6px 4px 6px;"
            "}"
            "QMessageBox#%1 QLabel#qt_msgboxex_icon_label{"
            "  min-width:46px;"
            "  padding:6px 8px 0 2px;"
            "}"
            "QMessageBox#%1 QDialogButtonBox{"
            "  border-top:1px solid %4;"
            "  margin-top:6px;"
            "  padding-top:6px;"
            "}"
            "QMessageBox#%1 QPushButton{"
            "  background:%6;"
            "  color:%3;"
            "  border:1px solid %4;"
            "  border-radius:0px;"
            "  padding:4px 10px;"
            "  min-width:76px;"
            "  min-height:28px;"
            "  font-weight:600;"
            "}"
            "QMessageBox#%1 QPushButton:hover{"
            "  background:%7;"
            "  border-color:%4;"
            "}"
            "QMessageBox#%1 QPushButton:pressed{"
            "  background:%7;"
            "  border-color:%4;"
            "}"
            "QMessageBox#%1 QPushButton[ksword_primary=\"true\"]{"
            "  background:%8;"
            "  color:%15;"
            "  border:1px solid %8;"
            "  font-weight:700;"
            "}"
            "QMessageBox#%1 QPushButton[ksword_primary=\"true\"]:hover{"
            "  background:__MESSAGE_PRIMARY_HOVER__;"
            "  border-color:__MESSAGE_PRIMARY_HOVER__;"
            "}"
            "QMessageBox#%1 QPushButton[ksword_primary=\"true\"]:pressed{"
            "  background:%9;"
            "  border-color:%9;"
            "}"
            "QMessageBox#%1 QTextEdit{"
            "  background:__MESSAGE_SURFACE__;"
            "  color:%3;"
            "  border:1px solid %4;"
            "  border-radius:0px;"
            "  padding:8px;"
            "  selection-background-color:%8;"
            "  selection-color:%15;"
            "}")
            .arg(QString::fromLatin1(kThemedMessageBoxObjectName))
            .arg(kWindowColorText)
            .arg(kTextColorText)
            .arg(kBorderColorText)
            .arg(kSecondaryTextColorText)
            .arg(kSecondaryButtonColorText)
            .arg(kSecondaryButtonHoverColorText)
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::kPrimaryBluePressedHex)
            .arg(QString::fromLatin1(kMessageBoxTitleBarObjectName))
            .arg(kSurfaceColorText)
            .arg(QString::fromLatin1(kMessageBoxTitleLabelObjectName))
            .arg(kMessageBoxOuterBorderWidth)
            .arg(kOuterBorderColorText)
            .arg(ksword_theme::onAccentHex())
            .replace(QStringLiteral("__MESSAGE_SURFACE__"), kSurfaceColorText)
            .replace(QStringLiteral("__MESSAGE_PRIMARY_HOVER__"), ksword_theme::primaryBlueSolidHoverHex());
    }

    // buildMessageBoxPalette:
    // - Build a stable palette for message boxes to prevent certain child controls from falling back to the system white background;
    // - Works with stylesheets to resolve text and background color conflicts in dark mode.
    QPalette buildMessageBoxPalette(const QPalette& basePalette, const bool darkModeEnabled)
    {
        QPalette messageBoxPalette = basePalette;
        messageBoxPalette.setColor(QPalette::Window, messageBoxWindowColor(darkModeEnabled));
        messageBoxPalette.setColor(QPalette::Base, messageBoxSurfaceColor(darkModeEnabled));
        messageBoxPalette.setColor(QPalette::AlternateBase, messageBoxWindowColor(darkModeEnabled));
        messageBoxPalette.setColor(QPalette::Text, messageBoxTextColor(darkModeEnabled));
        messageBoxPalette.setColor(QPalette::WindowText, messageBoxTextColor(darkModeEnabled));
        messageBoxPalette.setColor(QPalette::Button, messageBoxSecondaryButtonColor(darkModeEnabled));
        messageBoxPalette.setColor(QPalette::ButtonText, messageBoxTextColor(darkModeEnabled));
        messageBoxPalette.setColor(QPalette::ToolTipBase, messageBoxSurfaceColor(darkModeEnabled));
        messageBoxPalette.setColor(QPalette::ToolTipText, messageBoxTextColor(darkModeEnabled));
        messageBoxPalette.setColor(QPalette::Highlight, ksword_theme::primaryBlueColor);
        messageBoxPalette.setColor(QPalette::HighlightedText, ksword_theme::onAccentColor());
        return messageBoxPalette;
    }

    // standardButtonIconPath: Selects a unified icon for standard buttons.
    QString standardButtonIconPath(const QMessageBox::StandardButton standardButton)
    {
        switch (standardButton)
        {
        case QMessageBox::Ok:
        case QMessageBox::Yes:
        case QMessageBox::Open:
        case QMessageBox::Save:
        case QMessageBox::SaveAll:
        case QMessageBox::Apply:
        case QMessageBox::YesToAll:
            return QStringLiteral(":/Icon/process_start.svg");
        case QMessageBox::Retry:
        case QMessageBox::Reset:
        case QMessageBox::RestoreDefaults:
            return QStringLiteral(":/Icon/process_refresh.svg");
        case QMessageBox::Close:
        case QMessageBox::Cancel:
        case QMessageBox::No:
        case QMessageBox::NoToAll:
        case QMessageBox::Abort:
        case QMessageBox::Discard:
            return QStringLiteral(":/Icon/log_cancel_track.svg");
        case QMessageBox::Help:
        case QMessageBox::Ignore:
            return QStringLiteral(":/Icon/process_details.svg");
        default:
            return QString();
        }
    }

    // Note: standardButtonText purpose: Make all QMessageBox standard buttons use the KSword language pack.
    QString standardButtonText(const QMessageBox::StandardButton standardButton)
    {
        switch (standardButton)
        {
        case QMessageBox::Ok: return ks::i18n::contextText(QStringLiteral("messagebox.button.ok"), QStringLiteral("确定"));
        case QMessageBox::Save: return ks::i18n::contextText(QStringLiteral("messagebox.button.save"), QStringLiteral("保存"));
        case QMessageBox::SaveAll: return ks::i18n::contextText(QStringLiteral("messagebox.button.save_all"), QStringLiteral("全部保存"));
        case QMessageBox::Open: return ks::i18n::contextText(QStringLiteral("messagebox.button.open"), QStringLiteral("打开"));
        case QMessageBox::Yes: return ks::i18n::contextText(QStringLiteral("messagebox.button.yes"), QStringLiteral("是"));
        case QMessageBox::YesToAll: return ks::i18n::contextText(QStringLiteral("messagebox.button.yes_to_all"), QStringLiteral("全部是"));
        case QMessageBox::No: return ks::i18n::contextText(QStringLiteral("messagebox.button.no"), QStringLiteral("否"));
        case QMessageBox::NoToAll: return ks::i18n::contextText(QStringLiteral("messagebox.button.no_to_all"), QStringLiteral("全部否"));
        case QMessageBox::Abort: return ks::i18n::contextText(QStringLiteral("messagebox.button.abort"), QStringLiteral("中止"));
        case QMessageBox::Retry: return ks::i18n::contextText(QStringLiteral("messagebox.button.retry"), QStringLiteral("重试"));
        case QMessageBox::Ignore: return ks::i18n::contextText(QStringLiteral("messagebox.button.ignore"), QStringLiteral("忽略"));
        case QMessageBox::Close: return ks::i18n::contextText(QStringLiteral("messagebox.button.close"), QStringLiteral("关闭"));
        case QMessageBox::Cancel: return ks::i18n::contextText(QStringLiteral("messagebox.button.cancel"), QStringLiteral("取消"));
        case QMessageBox::Discard: return ks::i18n::contextText(QStringLiteral("messagebox.button.discard"), QStringLiteral("放弃"));
        case QMessageBox::Help: return ks::i18n::contextText(QStringLiteral("messagebox.button.help"), QStringLiteral("帮助"));
        case QMessageBox::Apply: return ks::i18n::contextText(QStringLiteral("messagebox.button.apply"), QStringLiteral("应用"));
        case QMessageBox::Reset: return ks::i18n::contextText(QStringLiteral("messagebox.button.reset"), QStringLiteral("重置"));
        case QMessageBox::RestoreDefaults: return ks::i18n::contextText(QStringLiteral("messagebox.button.restore_defaults"), QStringLiteral("恢复默认值"));
        default: return QString();
        }
    }

    // standardButtonToolTip: Adds hover tooltips for standard buttons.
    QString standardButtonToolTip(const QMessageBox::StandardButton standardButton)
    {
        switch (standardButton)
        {
        case QMessageBox::Ok: return ks::i18n::contextText(QStringLiteral("messagebox.button.ok.tooltip"), QStringLiteral("确认当前提示并继续"));
        case QMessageBox::Yes: return ks::i18n::contextText(QStringLiteral("messagebox.button.yes.tooltip"), QStringLiteral("同意并继续执行当前操作"));
        case QMessageBox::YesToAll: return ks::i18n::contextText(QStringLiteral("messagebox.button.yes_to_all.tooltip"), QStringLiteral("对全部项目同意并继续"));
        case QMessageBox::No: return ks::i18n::contextText(QStringLiteral("messagebox.button.no.tooltip"), QStringLiteral("拒绝本次操作并返回"));
        case QMessageBox::NoToAll: return ks::i18n::contextText(QStringLiteral("messagebox.button.no_to_all.tooltip"), QStringLiteral("对全部项目拒绝并返回"));
        case QMessageBox::Cancel: return ks::i18n::contextText(QStringLiteral("messagebox.button.cancel.tooltip"), QStringLiteral("取消并关闭当前消息框"));
        case QMessageBox::Close: return ks::i18n::contextText(QStringLiteral("messagebox.button.close.tooltip"), QStringLiteral("关闭当前消息框"));
        case QMessageBox::Abort: return ks::i18n::contextText(QStringLiteral("messagebox.button.abort.tooltip"), QStringLiteral("立即中止当前流程"));
        case QMessageBox::Retry: return ks::i18n::contextText(QStringLiteral("messagebox.button.retry.tooltip"), QStringLiteral("重新尝试当前操作"));
        case QMessageBox::Ignore: return ks::i18n::contextText(QStringLiteral("messagebox.button.ignore.tooltip"), QStringLiteral("忽略本次问题并继续"));
        case QMessageBox::Open: return ks::i18n::contextText(QStringLiteral("messagebox.button.open.tooltip"), QStringLiteral("打开目标资源"));
        case QMessageBox::Save: return ks::i18n::contextText(QStringLiteral("messagebox.button.save.tooltip"), QStringLiteral("保存当前内容"));
        case QMessageBox::SaveAll: return ks::i18n::contextText(QStringLiteral("messagebox.button.save_all.tooltip"), QStringLiteral("保存全部内容"));
        case QMessageBox::Apply: return ks::i18n::contextText(QStringLiteral("messagebox.button.apply.tooltip"), QStringLiteral("应用当前改动"));
        case QMessageBox::Reset: return ks::i18n::contextText(QStringLiteral("messagebox.button.reset.tooltip"), QStringLiteral("恢复到初始状态"));
        case QMessageBox::RestoreDefaults: return ks::i18n::contextText(QStringLiteral("messagebox.button.restore_defaults.tooltip"), QStringLiteral("恢复产品默认设置"));
        case QMessageBox::Discard: return ks::i18n::contextText(QStringLiteral("messagebox.button.discard.tooltip"), QStringLiteral("丢弃当前未保存内容"));
        case QMessageBox::Help: return ks::i18n::contextText(QStringLiteral("messagebox.button.help.tooltip"), QStringLiteral("查看当前提示的帮助信息"));
        default: return ks::i18n::contextText(QStringLiteral("messagebox.button.custom.tooltip"), QStringLiteral("执行该按钮对应的消息框动作"));
        }
    }

    // findMessageBoxGridLayout:
    // - QMessageBox internally typically uses QGridLayout;
    // - Return the layout first to uniformly adjust content margins and reserve a safe area for the floating title bar.
    QGridLayout* findMessageBoxGridLayout(QMessageBox* messageBox)
    {
        if (messageBox == nullptr)
        {
            return nullptr;
        }
        return qobject_cast<QGridLayout*>(messageBox->layout());
    }

    // propertyIntOrFallback:
    // - Read an integer from a QObject dynamic property;
    // - Return fallbackValue if the property does not exist or cannot be converted.
    // - Return value: Parsed integer margin value.
    int propertyIntOrFallback(
        const QObject* objectPointer,
        const char* propertyName,
        const int fallbackValue)
    {
        if (objectPointer == nullptr || propertyName == nullptr)
        {
            return fallbackValue;
        }

        bool conversionOk = false;
        const int kPropertyValue = objectPointer->property(propertyName).toInt(&conversionOk);
        if (!conversionOk)
        {
            return fallbackValue;
        }
        return kPropertyValue;
    }

    // reserveMessageBoxTitleBarTopMargin:
    // - Do not treat the title bar as the 0th row item in the QGridLayout.
    // - Only adds a fixed margin offset to the top of the root layout to ensure the title bar does not obscure the body content.
    // - Parameter messageBox: the message box to adjust; gridLayout: the root grid layout of the message box.
    // - Return value: None.
    void reserveMessageBoxTitleBarTopMargin(QMessageBox* messageBox, QGridLayout* gridLayout)
    {
        if (messageBox == nullptr || gridLayout == nullptr)
        {
            return;
        }

        if (!messageBox->property(kMessageBoxTitleBarInstalledPropertyName).toBool())
        {
            // originalMargins usage: Save the native Qt QMessageBox content margins to avoid disrupting button/text layout.
            const QMargins kOriginalMargins = gridLayout->contentsMargins();
            messageBox->setProperty(kMessageBoxOriginalMarginLeftPropertyName, kOriginalMargins.left());
            messageBox->setProperty(kMessageBoxOriginalMarginTopPropertyName, kOriginalMargins.top());
            messageBox->setProperty(kMessageBoxOriginalMarginRightPropertyName, kOriginalMargins.right());
            messageBox->setProperty(kMessageBoxOriginalMarginBottomPropertyName, kOriginalMargins.bottom());
            messageBox->setProperty(kMessageBoxTitleBarInstalledPropertyName, true);
        }

        // currentMargins: Provides a fallback when the property is missing, typically occurring only during abnormal hot reload scenarios.
        const QMargins kCurrentMargins = gridLayout->contentsMargins();
        const int kOriginalLeft = propertyIntOrFallback(
            messageBox,
            kMessageBoxOriginalMarginLeftPropertyName,
            kCurrentMargins.left());
        const int kOriginalTop = propertyIntOrFallback(
            messageBox,
            kMessageBoxOriginalMarginTopPropertyName,
            kCurrentMargins.top());
        const int kOriginalRight = propertyIntOrFallback(
            messageBox,
            kMessageBoxOriginalMarginRightPropertyName,
            kCurrentMargins.right());
        const int kOriginalBottom = propertyIntOrFallback(
            messageBox,
            kMessageBoxOriginalMarginBottomPropertyName,
            kCurrentMargins.bottom());
        const int kReservedTop = kOriginalTop + kMessageTitleBarHeight + kMessageTitleBarContentGap;

        gridLayout->setContentsMargins(kOriginalLeft, kReservedTop, kOriginalRight, kOriginalBottom);
    }

    // syncMessageBoxTitleBarGeometry:
    // - Ensure the custom-drawn title bar always covers the full inner width of the QMessageBox top border;
    // - Fix the issue where the title bar shrinks to the top-left corner based only on the text sizeHint when the title is short.
    // - Also prevents the title bar from overlapping the 1px theme blue outer border.
    // - Parameter messageBox: the associated message box; titleBar: the custom-drawn title bar.
    // - Return value: None.
    void syncMessageBoxTitleBarGeometry(QMessageBox* messageBox, QWidget* titleBar)
    {
        if (messageBox == nullptr || titleBar == nullptr)
        {
            return;
        }

        // availableWidth usage: prefer the message box's current width; fall back to minimum width if insufficient before display.
        const int kAvailableWidth = std::max(messageBox->width(), messageBox->minimumWidth());
        // titleBarWidth usage: Subtract left and right outer borders to prevent the title bar from obscuring the blue window border.
        const int kTitleBarWidth = std::max(kAvailableWidth - (kMessageBoxOuterBorderWidth * 2), 0);
        titleBar->setGeometry(
            kMessageBoxOuterBorderWidth,
            kMessageBoxOuterBorderWidth,
            kTitleBarWidth,
            kMessageTitleBarHeight);
        titleBar->setMinimumWidth(0);
        titleBar->setMaximumWidth(QWIDGETSIZE_MAX);
        titleBar->raise();

        if (MessageBoxTitleBar* typedTitleBar = dynamic_cast<MessageBoxTitleBar*>(titleBar))
        {
            // syncChildGeometry usage: refreshes the title truncation immediately after geometry synchronization to prevent brief misalignment during Qt6's delayed resize.
            typedTitleBar->syncChildGeometry();
        }
    }

    // ensureCustomMessageBoxTitleBar:
    // - Install a custom-drawn title bar for QMessageBox.
    // - Hide the system title bar, display the application logo on the left, and do not provide minimize/maximize/close buttons.
    void ensureCustomMessageBoxTitleBar(QMessageBox* messageBox)
    {
        if (messageBox == nullptr)
        {
            return;
        }

        // windowFlags purpose: centrally write back window flags under Qt6 to avoid individual setWindowFlag calls being overwritten by platform styles before/after show.
        Qt::WindowFlags windowFlags = messageBox->windowFlags();
        windowFlags = (windowFlags & ~Qt::WindowType_Mask) | Qt::Dialog;
        windowFlags |= Qt::FramelessWindowHint;
        windowFlags &= ~Qt::WindowSystemMenuHint;
        windowFlags &= ~Qt::WindowMinimizeButtonHint;
        windowFlags &= ~Qt::WindowMaximizeButtonHint;
        windowFlags &= ~Qt::WindowMinMaxButtonsHint;
        windowFlags &= ~Qt::WindowCloseButtonHint;
        windowFlags &= ~Qt::WindowContextHelpButtonHint;
        if (messageBox->windowFlags() != windowFlags)
        {
            // setWindowFlags may hide an already visible window in Qt6; write back only if flags actually change, then restore visibility.
            const bool kMessageBoxWasVisible = messageBox->isVisible();
            messageBox->setWindowFlags(windowFlags);
            if (kMessageBoxWasVisible)
            {
                messageBox->show();
            }
        }

        QGridLayout* gridLayout = findMessageBoxGridLayout(messageBox);
        if (gridLayout == nullptr)
        {
            return;
        }

        reserveMessageBoxTitleBarTopMargin(messageBox, gridLayout);

        QWidget* titleBarWidget = messageBox->findChild<QWidget*>(
            QString::fromLatin1(kMessageBoxTitleBarObjectName),
            Qt::FindDirectChildrenOnly);
        MessageBoxTitleBar* titleBar = dynamic_cast<MessageBoxTitleBar*>(titleBarWidget);
        if (titleBar == nullptr)
        {
            titleBar = new MessageBoxTitleBar(messageBox);
        }
        titleBar->updateTitleText();
        syncMessageBoxTitleBarGeometry(messageBox, titleBar);
        titleBar->show();
    }

    // GlobalMessageBoxStyler:
    // - Acts as a global event filter for QApplication to intercept all QMessageBox instances;
    // - Uniformly apply style overrides when the message box is displayed or the theme changes;
    class GlobalMessageBoxStyler final : public QObject
    {
    public:
        // Constructor purpose: bind the QObject parent object to follow the QApplication lifecycle.
        explicit GlobalMessageBoxStyler(QObject* parentObject)
            : QObject(parentObject)
        {
        }

        // eventFilter purpose: Listen for QMessageBox display and style refresh timing.
        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override
        {
            QMessageBox* messageBox = qobject_cast<QMessageBox*>(watchedObject);
            if (messageBox == nullptr || eventObject == nullptr)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            const QEvent::Type kEventType = eventObject->type();
            if (kEventType == QEvent::Close)
            {
                // Close events cannot be intercepted in the global theme handler:
                // - Standard QMessageBox buttons are consolidated via QDialog::done()/accept()/reject().
                // - Qt6 may still dispatch a Close event during the shutdown process to terminate the current exec() call;
                // - If ignore() is called here, the button click has already occurred, but the window does not close, and the caller cannot retrieve the return value.
                // - The title bar close entry has been removed via FramelessWindowHint/WindowCloseButtonHint. The global
                //   theming engine is responsible only for appearance and no longer alters the message box close semantics.
                return QObject::eventFilter(watchedObject, eventObject);
            }

            if (kEventType == QEvent::Resize)
            {
                // Resize event only synchronizes the floating title bar geometry, without reapplying the full style.
                // This avoids triggering the polish flow again after adjustSize causes a Resize.
                QWidget* titleBarWidget = messageBox->findChild<QWidget*>(
                    QString::fromLatin1(kMessageBoxTitleBarObjectName),
                    Qt::FindDirectChildrenOnly);
                syncMessageBoxTitleBarGeometry(messageBox, titleBarWidget);
                return QObject::eventFilter(watchedObject, eventObject);
            }

            if (kEventType == QEvent::Polish ||
                kEventType == QEvent::Show ||
                kEventType == QEvent::LanguageChange ||
                kEventType == QEvent::PaletteChange ||
                kEventType == QEvent::ApplicationPaletteChange ||
                kEventType == QEvent::StyleChange)
            {
                // StyleChange/PaletteChange events are triggered synchronously during theme application;
                // If not short-circuited here, it would recursively re-enter polishMessageBox.
                if (messageBox->property(kThemePolishingPropertyName).toBool())
                {
                    return QObject::eventFilter(watchedObject, eventObject);
                }
                polishMessageBox(messageBox);
            }

            return QObject::eventFilter(watchedObject, eventObject);
        }

        // polishMessageBox: Applies the unified theme to a single QMessageBox.
        void polishMessageBox(QMessageBox* messageBox) const
        {
            if (messageBox == nullptr)
            {
                return;
            }

            if (messageBox->property(kThemePolishingPropertyName).toBool())
            {
                return;
            }

            const bool kDarkModeEnabled = ksword_theme::isDarkModeEnabled();
            const bool kThemeAlreadyApplied =
                messageBox->objectName() == QString::fromLatin1(kThemedMessageBoxObjectName) &&
                messageBox->property(kThemeModePropertyName).toBool() == kDarkModeEnabled;

            // currentPolishingStateResetter:
            // - Ensure the 'Applying Theme' flag is cleared for any early return or exception path.
            // - Prevent the message box from remaining permanently in the reentrancy-protected state.
            struct PolishingStateResetter
            {
                QMessageBox* targetMessageBox = nullptr; // targetMessageBox: MessageBox whose properties need cleanup during destruction.

                ~PolishingStateResetter()
                {
                    if (targetMessageBox != nullptr)
                    {
                        targetMessageBox->setProperty(kThemePolishingPropertyName, false);
                    }
                }
            };

            messageBox->setProperty(kThemePolishingPropertyName, true);
            PolishingStateResetter currentPolishingStateResetter{ messageBox };

            const QPalette kSourcePalette = (qApp != nullptr) ? qApp->palette() : messageBox->palette();
            const QString kTargetStyleSheet = buildMessageBoxStyleSheet(kDarkModeEnabled);
            // dialogMaxWidth: Limits the message box width based on available screen space to prevent visual crowding from excessive width.
            const int kDialogMaxWidth = computeMessageBoxMaxWidth(messageBox);
            // textMaxWidth: Constrains the width of the main text and description to ensure reliable automatic line wrapping.
            const int kTextMaxWidth = std::max(kDialogMaxWidth - kMessageLabelHorizontalReserve, 220);
            messageBox->setObjectName(QString::fromLatin1(kThemedMessageBoxObjectName));
            messageBox->setAttribute(Qt::WA_StyledBackground, true);
            messageBox->setAutoFillBackground(true);
            messageBox->setMinimumWidth(kMessageBoxMinWidth);
            messageBox->setMaximumWidth(kDialogMaxWidth);
            messageBox->setProperty(kThemeModePropertyName, kDarkModeEnabled);
            ensureCustomMessageBoxTitleBar(messageBox);

            // When re-entering the same theme, only refresh button and text optional properties to avoid style storms caused by repeated setStyleSheet calls.
            if (!kThemeAlreadyApplied)
            {
                messageBox->setPalette(buildMessageBoxPalette(kSourcePalette, kDarkModeEnabled));
                if (messageBox->styleSheet() != kTargetStyleSheet)
                {
                    messageBox->setStyleSheet(kTargetStyleSheet);
                }
            }

            QLabel* mainTextLabel = messageBox->findChild<QLabel*>(QStringLiteral("qt_msgbox_label"));
            polishMessageTextLabel(mainTextLabel, kTextMaxWidth);

            QLabel* informativeLabel = messageBox->findChild<QLabel*>(QStringLiteral("qt_msgbox_informativelabel"));
            polishMessageTextLabel(informativeLabel, kTextMaxWidth);

            QTextEdit* detailTextEdit = messageBox->findChild<QTextEdit*>();
            if (detailTextEdit != nullptr)
            {
                detailTextEdit->setReadOnly(true);
                detailTextEdit->setMinimumHeight(160);
            }

            polishButtons(messageBox);
            messageBox->adjustSize();
            QWidget* titleBarWidget = messageBox->findChild<QWidget*>(
                QString::fromLatin1(kMessageBoxTitleBarObjectName),
                Qt::FindDirectChildrenOnly);
            syncMessageBoxTitleBarGeometry(messageBox, titleBarWidget);
        }

    private:
        // polishButtons purpose: Uniformly handle message box button icons, hover tooltips, and primary/secondary button styles.
        void polishButtons(QMessageBox* messageBox) const
        {
            const QList<QAbstractButton*> kButtonList = messageBox->buttons();
            for (QAbstractButton* abstractButton : kButtonList)
            {
                QPushButton* pushButton = qobject_cast<QPushButton*>(abstractButton);
                if (pushButton == nullptr)
                {
                    continue;
                }

                const QMessageBox::StandardButton kStandardButton = messageBox->standardButton(pushButton);
                const QMessageBox::ButtonRole kButtonRole = messageBox->buttonRole(pushButton);
                const bool kPrimaryButton =
                    kButtonRole == QMessageBox::AcceptRole ||
                    kButtonRole == QMessageBox::YesRole ||
                    kButtonRole == QMessageBox::ApplyRole;

                pushButton->setProperty("ksword_primary", kPrimaryButton);
                pushButton->setCursor(Qt::PointingHandCursor);
                pushButton->setMinimumHeight(28);
                pushButton->setMaximumHeight(30);
                pushButton->setMinimumWidth(kPrimaryButton ? 86 : 76);
                pushButton->setSizePolicy(QSizePolicy::Minimum, QSizePolicy::Fixed);
                const QString kLocalizedButtonText = standardButtonText(kStandardButton);
                if (!kLocalizedButtonText.isEmpty())
                {
                    pushButton->setText(kLocalizedButtonText);
                }
                pushButton->setToolTip(standardButtonToolTip(kStandardButton));

                const QString kIconPath = standardButtonIconPath(kStandardButton);
                if (!kIconPath.isEmpty())
                {
                    pushButton->setIcon(QIcon(kIconPath));
                    pushButton->setIconSize(QSize(16, 16));
                }

                QStyle* widgetStyle = pushButton->style();
                if (widgetStyle != nullptr)
                {
                    widgetStyle->unpolish(pushButton);
                    widgetStyle->polish(pushButton);
                }
            }
        }
    };

    // globalMessageBoxStylerInstance purpose: Returns the unique global styler instance.
    GlobalMessageBoxStyler* globalMessageBoxStylerInstance()
    {
        static QPointer<GlobalMessageBoxStyler> stylerInstance;
        if (stylerInstance == nullptr && qApp != nullptr)
        {
            stylerInstance = new GlobalMessageBoxStyler(qApp);
        }
        return stylerInstance.data();
    }
}

namespace ks::ui
{
    void installGlobalMessageBoxTheme(QApplication* appInstance)
    {
        if (appInstance == nullptr)
        {
            return;
        }

        GlobalMessageBoxStyler* stylerInstance = globalMessageBoxStylerInstance();
        if (stylerInstance == nullptr)
        {
            return;
        }

        appInstance->installEventFilter(stylerInstance);
        refreshGlobalMessageBoxTheme();
    }

    void refreshGlobalMessageBoxTheme()
    {
        GlobalMessageBoxStyler* stylerInstance = globalMessageBoxStylerInstance();
        if (stylerInstance == nullptr || qApp == nullptr)
        {
            return;
        }

        const QWidgetList kTopLevelWidgetList = qApp->topLevelWidgets();
        for (QWidget* topLevelWidget : kTopLevelWidgetList)
        {
            QMessageBox* messageBox = qobject_cast<QMessageBox*>(topLevelWidget);
            if (messageBox == nullptr)
            {
                continue;
            }

            stylerInstance->polishMessageBox(messageBox);
        }
    }
}
