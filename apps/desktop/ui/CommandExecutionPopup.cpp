#include "CommandExecutionPopup.h"

#include "../internationalization/LanguageManager.h"
#include "../Theme.h"

#include <QAbstractItemView>
#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QDir>
#include <QEvent>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QIcon>
#include <QIntValidator>
#include <QKeyEvent>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QMouseEvent>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>
#include <QVariant>
#include <QWidget>

#include <algorithm>

namespace
{
    // Popup size constants: width matches the global search popup tier to avoid mode switching.
    constexpr int kPopupMinimumWidth = 460;
    constexpr int kPopupMaximumExtraWidth = 220;
    constexpr int kPopupMinimumHeight = 250;
    constexpr int kPopupHostMargin = 8;
    constexpr int kPopupAnchorGap = 6;
    constexpr int kSmallToolButtonSize = 28;

    // comboDataToInt: Reads the current enum value from the combo box and falls back to the default value if the control has not been created yet.
    int comboDataToInt(const QComboBox* comboBox, const int fallbackValue)
    {
        if (comboBox == nullptr)
        {
            return fallbackValue;
        }
        bool conversionOk = false;
        const int kValue = comboBox->currentData().toInt(&conversionOk);
        return conversionOk ? kValue : fallbackValue;
    }
}

namespace ks::ui
{
    CommandExecutionPopup::CommandExecutionPopup(
        QWidget* popupHostWindow,
        QWidget* popupAnchorWidget,
        QLineEdit* commandInputEdit,
        QObject* parentObject)
        : QFrame(popupHostWindow)
        , popupHostWindow_(popupHostWindow)
        , popupAnchorWidget_(popupAnchorWidget)
        , commandInputEdit_(commandInputEdit)
    {
        // popupHostWindow already holds both QWidget and QObject parent relationships; retaining the parentObject parameter maintains
        // consistency with the construction conventions of other UI controllers, avoiding redundant modification of the QWidget parent chain.
        Q_UNUSED(parentObject);

        initializeUi();
        if (commandInputEdit_ != nullptr)
        {
            commandInputEdit_->installEventFilter(this);
        }
        if (popupHostWindow_ != nullptr)
        {
            popupHostWindow_->installEventFilter(this);
        }
        if (popupAnchorWidget_ != nullptr)
        {
            popupAnchorWidget_->installEventFilter(this);
        }
        if (qApp != nullptr)
        {
            // Application-level filters are used only to hide the popup when clicking outside the popup layer and title bar input group.
            qApp->installEventFilter(this);
        }
        hide();
    }

    void CommandExecutionPopup::setCommandModeActive(const bool commandModeActive)
    {
        commandModeActive_ = commandModeActive;
        if (!commandModeActive_)
        {
            dismissPopup();
            return;
        }

        // Switch to CMD mode to immediately display options, so users do not need to guess about configurable parameters.
        showPopupPanel();
    }

    CommandExecutionOptions CommandExecutionPopup::currentOptions() const
    {
        CommandExecutionOptions options;
        options.workingDirectory = workingDirectoryEdit_ != nullptr
            ? workingDirectoryEdit_->text().trimmed()
            : QDir::currentPath();
        options.userMode = static_cast<CommandExecutionOptions::UserMode>(
            comboDataToInt(userModeCombo_, static_cast<int>(CommandExecutionOptions::UserMode::kCurrentUser)));
        options.tokenSourcePid = tokenPidEdit_ != nullptr
            ? tokenPidEdit_->text().trimmed().toUInt()
            : 0U;
        options.privilegeMode = static_cast<CommandExecutionOptions::PrivilegeMode>(
            comboDataToInt(privilegeCombo_, static_cast<int>(CommandExecutionOptions::PrivilegeMode::kCurrent)));
        options.openConsoleWindow = openConsoleCheckBox_ == nullptr
            || openConsoleCheckBox_->isChecked();
        return options;
    }

    bool CommandExecutionPopup::isPopupVisible() const
    {
        return isVisible();
    }

    void CommandExecutionPopup::dismissPopup()
    {
        if (isVisible())
        {
            hide();
        }
    }

    void CommandExecutionPopup::initializeUi()
    {
        // The popup layer itself is a child control of the host window; explicitly enabling the styled background prevents the transparent host window from revealing a black background.
        setObjectName(QStringLiteral("ksCommandExecutionPopup"));
        setAttribute(Qt::WA_StyledBackground, true);
        setFrameShape(QFrame::NoFrame);

        auto* rootLayout = new QVBoxLayout(this);
        rootLayout->setContentsMargins(10, 8, 10, 8);
        rootLayout->setSpacing(7);

        auto* headerLayout = new QHBoxLayout();
        headerLayout->setContentsMargins(0, 0, 0, 0);
        headerLayout->setSpacing(4);

        titleLabel_ = new QLabel(this);
        titleLabel_->setObjectName(QStringLiteral("ksCommandExecutionPopupTitle"));
        titleLabel_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

        closeButton_ = new QToolButton(this);
        closeButton_->setObjectName(QStringLiteral("ksCommandExecutionPopupCloseButton"));
        closeButton_->setAutoRaise(true);
        closeButton_->setIcon(QIcon(QStringLiteral(":/Icon/titlebar_close.svg")));
        closeButton_->setIconSize(QSize(14, 14));
        closeButton_->setFixedSize(kSmallToolButtonSize, kSmallToolButtonSize);

        headerLayout->addWidget(titleLabel_, 1);
        headerLayout->addWidget(closeButton_, 0);
        rootLayout->addLayout(headerLayout, 0);

        auto* formLayout = new QFormLayout();
        formLayout->setContentsMargins(0, 0, 0, 0);
        formLayout->setHorizontalSpacing(8);
        formLayout->setVerticalSpacing(6);
        formLayout->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);

        workingDirectoryLabel_ = new QLabel(this);
        workingDirectoryEdit_ = new QLineEdit(this);
        workingDirectoryEdit_->setClearButtonEnabled(true);
        workingDirectoryEdit_->setText(QDir::currentPath());
        browseDirectoryButton_ = new QToolButton(this);
        browseDirectoryButton_->setObjectName(QStringLiteral("ksCommandExecutionPopupBrowseButton"));
        browseDirectoryButton_->setAutoRaise(true);
        browseDirectoryButton_->setIcon(QIcon(QStringLiteral(":/Icon/settings_background_browse.svg")));
        browseDirectoryButton_->setIconSize(QSize(16, 16));
        browseDirectoryButton_->setFixedSize(kSmallToolButtonSize, kSmallToolButtonSize);

        auto* directoryRow = new QWidget(this);
        auto* directoryLayout = new QHBoxLayout(directoryRow);
        directoryLayout->setContentsMargins(0, 0, 0, 0);
        directoryLayout->setSpacing(4);
        directoryLayout->addWidget(workingDirectoryEdit_, 1);
        directoryLayout->addWidget(browseDirectoryButton_, 0);
        formLayout->addRow(workingDirectoryLabel_, directoryRow);

        userModeLabel_ = new QLabel(this);
        userModeCombo_ = new QComboBox(this);
        userModeCombo_->addItem(QString(), static_cast<int>(CommandExecutionOptions::UserMode::kCurrentUser));
        userModeCombo_->addItem(QString(), static_cast<int>(CommandExecutionOptions::UserMode::kSystem));
        userModeCombo_->addItem(QString(), static_cast<int>(CommandExecutionOptions::UserMode::kProcessToken));
        formLayout->addRow(userModeLabel_, userModeCombo_);

        tokenPidLabel_ = new QLabel(this);
        tokenPidEdit_ = new QLineEdit(this);
        tokenPidEdit_->setValidator(new QIntValidator(1, 0x7fffffff, tokenPidEdit_));
        formLayout->addRow(tokenPidLabel_, tokenPidEdit_);

        privilegeLabel_ = new QLabel(this);
        privilegeCombo_ = new QComboBox(this);
        privilegeCombo_->addItem(QString(), static_cast<int>(CommandExecutionOptions::PrivilegeMode::kCurrent));
        privilegeCombo_->addItem(QString(), static_cast<int>(CommandExecutionOptions::PrivilegeMode::kAdministrator));
        privilegeCombo_->addItem(QString(), static_cast<int>(CommandExecutionOptions::PrivilegeMode::kStandard));
        formLayout->addRow(privilegeLabel_, privilegeCombo_);

        rootLayout->addLayout(formLayout, 0);

        openConsoleCheckBox_ = new QCheckBox(this);
        openConsoleCheckBox_->setChecked(true);
        rootLayout->addWidget(openConsoleCheckBox_, 0);

        hintLabel_ = new QLabel(this);
        hintLabel_->setObjectName(QStringLiteral("ksCommandExecutionPopupHint"));
        hintLabel_->setWordWrap(true);
        rootLayout->addWidget(hintLabel_, 0);

        auto* actionLayout = new QHBoxLayout();
        actionLayout->setContentsMargins(0, 0, 0, 0);
        actionLayout->addStretch(1);

        executeButton_ = new QToolButton(this);
        executeButton_->setObjectName(QStringLiteral("ksCommandExecutionPopupExecuteButton"));
        executeButton_->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
        executeButton_->setIcon(QIcon(QStringLiteral(":/Icon/process_start.svg")));
        executeButton_->setIconSize(QSize(16, 16));
        executeButton_->setMinimumWidth(88);
        executeButton_->setMinimumHeight(28);
        actionLayout->addWidget(executeButton_, 0);
        rootLayout->addLayout(actionLayout, 0);

        connect(closeButton_, &QToolButton::clicked, this, [this]() {
            dismissPopup();
        });
        connect(browseDirectoryButton_, &QToolButton::clicked, this, [this]() {
            selectWorkingDirectory();
        });
        connect(userModeCombo_, qOverload<int>(&QComboBox::currentIndexChanged), this, [this](const int) {
            updateUserModeUi();
        });
        connect(executeButton_, &QToolButton::clicked, this, [this]() {
            requestExecution();
        });

        updateUserModeUi();
        refreshTextAndStyle();
    }

    void CommandExecutionPopup::refreshTextAndStyle()
    {
        if (titleLabel_ == nullptr)
        {
            return;
        }

        // Text is loaded from semantic keys; switching languages and reopening the popup refreshes all text.
        titleLabel_->setText(text(QStringLiteral("cmd.popup.title"), QStringLiteral("CMD 命令执行选项")));
        workingDirectoryLabel_->setText(
            text(QStringLiteral("cmd.popup.directory"), QStringLiteral("执行目录")));
        userModeLabel_->setText(text(QStringLiteral("cmd.popup.user"), QStringLiteral("用户")));
        tokenPidLabel_->setText(text(QStringLiteral("cmd.popup.token_pid"), QStringLiteral("令牌 PID")));
        privilegeLabel_->setText(text(QStringLiteral("cmd.popup.privilege"), QStringLiteral("权限")));
        userModeCombo_->setItemText(
            0,
            text(QStringLiteral("cmd.popup.user.current"), QStringLiteral("当前用户（跟随 KSword）")));
        userModeCombo_->setItemText(
            1,
            text(QStringLiteral("cmd.popup.user.system"), QStringLiteral("SYSTEM（PID 4）")));
        userModeCombo_->setItemText(
            2,
            text(QStringLiteral("cmd.popup.user.process"), QStringLiteral("指定进程令牌")));
        privilegeCombo_->setItemText(
            0,
            text(QStringLiteral("cmd.popup.privilege.current"), QStringLiteral("当前权限")));
        privilegeCombo_->setItemText(
            1,
            text(QStringLiteral("cmd.popup.privilege.admin"), QStringLiteral("管理员（UAC）")));
        privilegeCombo_->setItemText(
            2,
            text(QStringLiteral("cmd.popup.privilege.standard"), QStringLiteral("普通用户（Shell 令牌）")));
        tokenPidEdit_->setPlaceholderText(
            text(QStringLiteral("cmd.popup.token_pid.placeholder"), QStringLiteral("指定进程的 PID")));
        openConsoleCheckBox_->setText(
            text(QStringLiteral("cmd.popup.console"), QStringLiteral("打开 CMD 窗口（/K）")));
        hintLabel_->setText(
            text(QStringLiteral("cmd.popup.hint"), QStringLiteral("回车或点击执行按钮；关闭窗口时使用 /C 后台执行。")));
        executeButton_->setText(text(QStringLiteral("cmd.popup.execute"), QStringLiteral("执行")));

        closeButton_->setToolTip(
            text(QStringLiteral("cmd.popup.collapse"), QStringLiteral("收起命令执行选项")));
        browseDirectoryButton_->setToolTip(
            text(QStringLiteral("cmd.popup.directory.browse"), QStringLiteral("选择命令执行目录")));
        openConsoleCheckBox_->setToolTip(text(
            QStringLiteral("cmd.popup.console.tooltip"),
            QStringLiteral("勾选后在可见 CMD 窗口中执行并保持窗口；取消后使用 /C 后台执行。")));
        executeButton_->setToolTip(text(
            QStringLiteral("cmd.popup.execute.tooltip"),
            QStringLiteral("按当前目录、用户、权限和窗口设置执行命令")));

        const QString kBackgroundHex = ksword_theme::surfaceHex();
        const QString kAlternateBackgroundHex = ksword_theme::surfaceAltHex();
        const QString kBorderHex = ksword_theme::borderStrongHex();
        const QString kTextPrimaryHex = ksword_theme::textPrimaryHex();
        const QString kTextSecondaryHex = ksword_theme::textSecondaryHex();
        const QString kAccentHex = ksword_theme::accentHex(ksword_theme::AccentRole::kBlue);
        const QString kAccentHoverHex = ksword_theme::primaryBlueSolidHoverHex();
        const QString kAccentTextHex = ksword_theme::onAccentHex();

        // Explicitly set background colors for various controls in the popup to avoid inheriting the default black background under a transparent main window.
        setStyleSheet(QStringLiteral(
            "#ksCommandExecutionPopup{"
            "background:%1;"
            "border:1px solid %2;"
            "border-radius:6px;"
            "}"
            "#ksCommandExecutionPopup QLabel{"
            "color:%3;"
            "}"
            "#ksCommandExecutionPopup QLabel#ksCommandExecutionPopupTitle{"
            "color:%4;"
            "font-weight:600;"
            "}"
            "#ksCommandExecutionPopup QLineEdit,"
            "#ksCommandExecutionPopup QComboBox{"
            "background:%5;"
            "color:%4;"
            "border:1px solid %2;"
            "border-radius:3px;"
            "padding:3px 6px;"
            "min-height:22px;"
            "}"
            "#ksCommandExecutionPopup QLineEdit:focus,"
            "#ksCommandExecutionPopup QComboBox:focus{"
            "border:1px solid %6;"
            "}"
            "#ksCommandExecutionPopup QToolButton{"
            "color:%4;"
            "background:transparent;"
            "border:1px solid transparent;"
            "border-radius:3px;"
            "}"
            "#ksCommandExecutionPopup QToolButton:hover{"
            "background:%7;"
            "}"
            "#ksCommandExecutionPopup QToolButton#ksCommandExecutionPopupExecuteButton{"
            "background:%6;"
            "color:%8;"
            "border:1px solid %6;"
            "font-weight:600;"
            "padding:3px 10px;"
            "}"
            "#ksCommandExecutionPopup QToolButton#ksCommandExecutionPopupExecuteButton:hover{"
            "background:%7;"
            "border:1px solid %7;"
            "}"
            "#ksCommandExecutionPopup QLabel#ksCommandExecutionPopupHint{"
            "color:%3;"
            "}"
            "#ksCommandExecutionPopup QCheckBox{"
            "color:%4;"
            "}")
            .arg(
                kBackgroundHex,
                kBorderHex,
                kTextSecondaryHex,
                kTextPrimaryHex,
                kAlternateBackgroundHex,
                kAccentHex,
                kAccentHoverHex,
                kAccentTextHex));
    }

    void CommandExecutionPopup::showPopupPanel()
    {
        if (!commandModeActive_ || popupHostWindow_ == nullptr || popupAnchorWidget_ == nullptr)
        {
            return;
        }

        refreshTextAndStyle();
        updateUserModeUi();
        if (layout() != nullptr)
        {
            layout()->activate();
        }

        const int kHostWidth = std::max(320, popupHostWindow_->width() - 24);
        const int kMinimumWidth = std::min(kPopupMinimumWidth, kHostWidth);
        const int kPanelWidth = std::clamp(
            popupAnchorWidget_->width() + kPopupMaximumExtraWidth,
            kMinimumWidth,
            kHostWidth);
        const int kPanelHeight = std::max(
            kPopupMinimumHeight,
            layout() != nullptr ? layout()->sizeHint().height() + 4 : kPopupMinimumHeight);
        setFixedSize(kPanelWidth, kPanelHeight);

        repositionPopupPanel();
        show();
        raise();
        QTimer::singleShot(0, this, [this]()
        {
            if (isVisible())
            {
                repositionPopupPanel();
            }
        });
    }

    void CommandExecutionPopup::repositionPopupPanel()
    {
        if (popupHostWindow_ == nullptr || popupAnchorWidget_ == nullptr)
        {
            return;
        }

        const QPoint kAnchorBottomLeftGlobal = popupAnchorWidget_->mapToGlobal(
            QPoint(0, popupAnchorWidget_->height()));
        const QPoint kAnchorBottomLeftInHost = popupHostWindow_->mapFromGlobal(kAnchorBottomLeftGlobal);
        const int kMaxPanelLeft = std::max(
            kPopupHostMargin,
            popupHostWindow_->width() - width() - kPopupHostMargin);
        const int kPanelLeft = std::clamp(
            kAnchorBottomLeftInHost.x() + (popupAnchorWidget_->width() - width()) / 2,
            kPopupHostMargin,
            kMaxPanelLeft);
        const int kPanelTop = kAnchorBottomLeftInHost.y() + kPopupAnchorGap;
        move(kPanelLeft, kPanelTop);
    }

    void CommandExecutionPopup::updateUserModeUi()
    {
        if (userModeCombo_ == nullptr || tokenPidLabel_ == nullptr || tokenPidEdit_ == nullptr)
        {
            return;
        }

        const bool kCurrentUserSelected = comboDataToInt(
            userModeCombo_,
            static_cast<int>(CommandExecutionOptions::UserMode::kCurrentUser))
            == static_cast<int>(CommandExecutionOptions::UserMode::kCurrentUser);
        const bool kProcessTokenSelected = comboDataToInt(
            userModeCombo_,
            static_cast<int>(CommandExecutionOptions::UserMode::kCurrentUser))
            == static_cast<int>(CommandExecutionOptions::UserMode::kProcessToken);

        tokenPidLabel_->setVisible(kProcessTokenSelected);
        tokenPidEdit_->setVisible(kProcessTokenSelected);

        // SYSTEM and specified process token permissions are determined by the selected token; no additional UAC or privilege downgrade selection is applied.
        if (privilegeCombo_ != nullptr)
        {
            privilegeCombo_->setEnabled(kCurrentUserSelected);
            if (!kCurrentUserSelected && privilegeCombo_->currentIndex() != 0)
            {
                privilegeCombo_->setCurrentIndex(0);
            }
        }
    }

    void CommandExecutionPopup::selectWorkingDirectory()
    {
        const QString kCurrentPath = workingDirectoryEdit_ != nullptr
            ? workingDirectoryEdit_->text().trimmed()
            : QDir::currentPath();
        const QString kSelectedPath = QFileDialog::getExistingDirectory(
            popupHostWindow_ != nullptr ? popupHostWindow_.data() : this,
            text(QStringLiteral("cmd.popup.directory.dialog.title"), QStringLiteral("选择命令执行目录")),
            QFileInfo(kCurrentPath).isDir() ? kCurrentPath : QDir::currentPath());
        if (!kSelectedPath.isEmpty() && workingDirectoryEdit_ != nullptr)
        {
            workingDirectoryEdit_->setText(QDir::toNativeSeparators(kSelectedPath));
        }
    }

    void CommandExecutionPopup::requestExecution()
    {
        if (commandInputEdit_ == nullptr)
        {
            return;
        }

        const QString kCommandText = commandInputEdit_->text().trimmed();
        if (kCommandText.isEmpty())
        {
            commandInputEdit_->setFocus(Qt::OtherFocusReason);
            return;
        }

        const CommandExecutionOptions kOptions = currentOptions();
        if (kOptions.userMode == CommandExecutionOptions::UserMode::kProcessToken
            && kOptions.tokenSourcePid == 0U)
        {
            QMessageBox::warning(
                popupHostWindow_ != nullptr ? popupHostWindow_.data() : this,
                text(QStringLiteral("cmd.popup.token.invalid.title"), QStringLiteral("令牌 PID 无效")),
                text(
                    QStringLiteral("cmd.popup.token.invalid.message"),
                    QStringLiteral("请输入有效的进程 PID。")));
            return;
        }

        emit executeRequested(kCommandText, kOptions);
    }

    bool CommandExecutionPopup::widgetBelongsToBranch(QWidget* widget, QWidget* branchRoot)
    {
        if (widget == nullptr || branchRoot == nullptr)
        {
            return false;
        }
        QWidget* currentWidget = widget;
        while (currentWidget != nullptr)
        {
            if (currentWidget == branchRoot)
            {
                return true;
            }
            currentWidget = currentWidget->parentWidget();
        }
        return false;
    }

    bool CommandExecutionPopup::isComboPopupEvent(QObject* watchedObject) const
    {
        QWidget* watchedWidget = qobject_cast<QWidget*>(watchedObject);
        if (watchedWidget == nullptr || QApplication::activePopupWidget() == nullptr)
        {
            return false;
        }

        const QComboBox* comboBoxList[] = {userModeCombo_, privilegeCombo_};
        for (const QComboBox* comboBox : comboBoxList)
        {
            if (comboBox == nullptr || comboBox->view() == nullptr)
            {
                continue;
            }

            // QComboBox lists are typically in a separate Qt::Popup window; do not rely solely on parentWidget to determine ownership.
            QWidget* comboPopupWindow = comboBox->view()->window();
            if (comboPopupWindow == nullptr)
            {
                continue;
            }
            if (watchedWidget == comboPopupWindow
                || widgetBelongsToBranch(watchedWidget, comboPopupWindow))
            {
                return true;
            }
        }
        return false;
    }

    QString CommandExecutionPopup::text(const QString& key, const QString& fallbackText)
    {
        return ks::i18n::text(key, fallbackText);
    }

    bool CommandExecutionPopup::eventFilter(QObject* watchedObject, QEvent* eventObject)
    {
        if (eventObject == nullptr)
        {
            return false;
        }

        const QEvent::Type kEventType = eventObject->type();
        if (watchedObject == commandInputEdit_)
        {
            if (commandModeActive_
                && (kEventType == QEvent::FocusIn || kEventType == QEvent::MouseButtonPress))
            {
                showPopupPanel();
            }
            if (commandModeActive_ && kEventType == QEvent::KeyPress)
            {
                auto* keyEvent = static_cast<QKeyEvent*>(eventObject);
                if (keyEvent->key() == Qt::Key_Escape && isVisible())
                {
                    dismissPopup();
                    return true;
                }
                if (keyEvent->key() == Qt::Key_Return || keyEvent->key() == Qt::Key_Enter)
                {
                    // In CMD mode, the popup layer uniformly validates token input; permission confirmation is handled uniformly by the mainWindow execution entry point.
                    requestExecution();
                    return true;
                }
            }
            return false;
        }

        if (watchedObject == popupHostWindow_ || watchedObject == popupAnchorWidget_)
        {
            if (isVisible()
                && (kEventType == QEvent::Move
                    || kEventType == QEvent::Resize
                    || kEventType == QEvent::LayoutRequest
                    || kEventType == QEvent::Show))
            {
                QTimer::singleShot(0, this, [this]()
                {
                    if (isVisible())
                    {
                        repositionPopupPanel();
                    }
                });
            }
            else if (watchedObject == popupHostWindow_
                && isVisible()
                && kEventType == QEvent::WindowDeactivate)
            {
                dismissPopup();
            }
            return false;
        }

        if (kEventType == QEvent::MouseButtonPress && isVisible())
        {
            // The drop-down list is an independent Popup: allow its mouse events; do not hide this popup while an option is being clicked.
            if (isComboPopupEvent(watchedObject))
            {
                return false;
            }

            QWidget* clickedWidget = qobject_cast<QWidget*>(watchedObject);
            if (clickedWidget != nullptr
                && !widgetBelongsToBranch(clickedWidget, this)
                && !widgetBelongsToBranch(clickedWidget, popupAnchorWidget_))
            {
                dismissPopup();
            }
        }
        return false;
    }
}
