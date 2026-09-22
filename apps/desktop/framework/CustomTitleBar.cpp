#include "CustomTitleBar.h"

#include "../internationalization/LanguageManager.h"
#include "../Theme.h"

#include <QAction>
#include <QApplication>
#include <QCoreApplication>
#include <QFileIconProvider>
#include <QFileInfo>
#include <QGuiApplication>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMouseEvent>
#include <QPushButton>
#include <QResizeEvent>
#include <QScreen>
#include <QToolButton>
#include <QWidget>
#include <QWindow>

#include <Windows.h>

#include <algorithm>
#include <array>
#include <iterator>

namespace
{
    // Title bar size constants:
    // - kTitleBarHeight: fixed title bar height;
    // - kControlButtonWidth: fixed width for the control buttons in the top-right corner;
    // - kControlButtonHeight: fixed height for the top-right control buttons;
    // - kControlIconSize: Size of the control button icon in the top-right corner.
    // - kCommandLineMinWidth: minimum width of the command input box;
    // - kCommandLineMaxWidth: maximum width of the command input box;
    // - kAppIconSize: drawing size for the application icon on the left.
    constexpr int kTitleBarHeight = 30;
    constexpr int kControlButtonWidth = 32;
    constexpr int kControlButtonHeight = 24;
    constexpr int kControlIconSize = 16;
    constexpr int kCommandLineMinWidth = 210;
    constexpr int kCommandLineMaxWidth = 760;
    constexpr int kAppIconSize = 18;

#ifdef Q_OS_WIN
    // readWindowsCurrentVersionStringValue：
    // - Purpose: Read a string value from the CurrentVersion registry key;
    // - Call: Invoked by resolveWindowsVersionText when reading DisplayVersion/ReleaseId.
    // - Input valueName: registry value name to read;
    // - Output: Returns the text with whitespace removed on success; returns an empty string on failure.
    QString readWindowsCurrentVersionStringValue(const wchar_t* valueName)
    {
        constexpr wchar_t kCurrentVersionRegistryPath[] =
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
        HKEY currentVersionKeyHandle = nullptr;
        const LSTATUS kOpenStatus = ::RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            kCurrentVersionRegistryPath,
            0,
            KEY_QUERY_VALUE | KEY_WOW64_64KEY,
            &currentVersionKeyHandle);
        if (kOpenStatus != ERROR_SUCCESS)
        {
            return {};
        }

        wchar_t valueBuffer[128] = {};
        DWORD valueType = 0;
        DWORD valueSize = sizeof(valueBuffer);
        const LSTATUS kQueryStatus = ::RegQueryValueExW(
            currentVersionKeyHandle,
            valueName,
            nullptr,
            &valueType,
            reinterpret_cast<LPBYTE>(valueBuffer),
            &valueSize);
        ::RegCloseKey(currentVersionKeyHandle);
        if (kQueryStatus != ERROR_SUCCESS
            || (valueType != REG_SZ && valueType != REG_EXPAND_SZ))
        {
            return {};
        }

        return QString::fromWCharArray(valueBuffer).trimmed();
    }

    // readWindowsCurrentVersionDwordValue：
    // - Purpose: Read a DWORD value from the CurrentVersion registry key;
    // - Called: invoked by resolveWindowsVersionText when reading the UBR;
    // - Input valueName: registry value name to read.
    // - Output: returns the numeric value on success, or 0 on failure.
    DWORD readWindowsCurrentVersionDwordValue(const wchar_t* valueName)
    {
        constexpr wchar_t kCurrentVersionRegistryPath[] =
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
        HKEY currentVersionKeyHandle = nullptr;
        const LSTATUS kOpenStatus = ::RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            kCurrentVersionRegistryPath,
            0,
            KEY_QUERY_VALUE | KEY_WOW64_64KEY,
            &currentVersionKeyHandle);
        if (kOpenStatus != ERROR_SUCCESS)
        {
            return 0;
        }

        DWORD valueData = 0;
        DWORD valueType = 0;
        DWORD valueSize = sizeof(valueData);
        const LSTATUS kQueryStatus = ::RegQueryValueExW(
            currentVersionKeyHandle,
            valueName,
            nullptr,
            &valueType,
            reinterpret_cast<LPBYTE>(&valueData),
            &valueSize);
        ::RegCloseKey(currentVersionKeyHandle);
        if (kQueryStatus != ERROR_SUCCESS
            || valueType != REG_DWORD
            || valueSize != sizeof(valueData))
        {
            return 0;
        }

        return valueData;
    }
#endif

    // widgetBelongsTo：
    // - Purpose: Determine if a matched control belongs to the specified ancestor widget branch.
    // - Call: isPointInDraggableRegion is used internally to distinguish between draggable regions and interactive control regions.
    // - Input widgetObject: hit control.
    // - Passes expectedAncestor: the expected ancestor control.
    // - Output: true if belongs to the ancestor branch.
    bool widgetBelongsTo(const QWidget* widgetObject, const QWidget* expectedAncestor)
    {
        if (widgetObject == nullptr || expectedAncestor == nullptr)
        {
            return false;
        }

        const QWidget* cursorWidget = widgetObject;
        while (cursorWidget != nullptr)
        {
            if (cursorWidget == expectedAncestor)
            {
                return true;
            }
            cursorWidget = cursorWidget->parentWidget();
        }
        return false;
    }

#ifdef Q_OS_WIN
    // makeMouseScreenLParam：
    // - Input globalPoint: global screen coordinates from the Qt mouse event;
    // - Processing: Pack signed x/y into LPARAM per Windows mouse message convention;
    // - Returns: Coordinates directly usable as parameters for WM_NCLBUTTONDOWN.
    LPARAM makeMouseScreenLParam(const QPoint& globalPoint)
    {
        return MAKELPARAM(
            static_cast<SHORT>(globalPoint.x()),
            static_cast<SHORT>(globalPoint.y()));
    }

    // resolveTopLevelMoveResizeHitTest：
    // - Input hostWindowHandle: HWND of the top-level window to which the title bar belongs;
    // - Input globalPoint: Current mouse global coordinates;
    // - Processing: When actively bridging non-client area messages from title bar child controls, first check if the point falls within the window border or corner.
    // - Return: HTLEFT/HTTOP... for borders; HTCAPTION for the standard title bar.
    WPARAM resolveTopLevelMoveResizeHitTest(HWND hostWindowHandle, const QPoint& globalPoint)
    {
        if (hostWindowHandle == nullptr || ::IsWindow(hostWindowHandle) == FALSE)
        {
            return HTCAPTION;
        }
        if (::IsZoomed(hostWindowHandle) != FALSE)
        {
            return HTCAPTION;
        }

        RECT windowRectValue = {};
        if (::GetWindowRect(hostWindowHandle, &windowRectValue) == FALSE)
        {
            return HTCAPTION;
        }

        const int kFrameWidthValue = windowRectValue.right - windowRectValue.left;
        const int kFrameHeightValue = windowRectValue.bottom - windowRectValue.top;
        if (kFrameWidthValue <= 0 || kFrameHeightValue <= 0)
        {
            return HTCAPTION;
        }

        const int kBorderWidth = std::max(
            8,
            static_cast<int>(
                ::GetSystemMetrics(SM_CXSIZEFRAME)
                + ::GetSystemMetrics(SM_CXPADDEDBORDER)));
        const int kFrameLocalX = globalPoint.x() - windowRectValue.left;
        const int kFrameLocalY = globalPoint.y() - windowRectValue.top;

        const bool kHitLeft = kFrameLocalX >= 0 && kFrameLocalX < kBorderWidth;
        const bool kHitRight = kFrameLocalX <= kFrameWidthValue && kFrameLocalX > (kFrameWidthValue - kBorderWidth);
        const bool kHitTop = kFrameLocalY >= 0 && kFrameLocalY < kBorderWidth;
        const bool kHitBottom = kFrameLocalY <= kFrameHeightValue && kFrameLocalY > (kFrameHeightValue - kBorderWidth);

        if (kHitTop && kHitLeft)
        {
            return HTTOPLEFT;
        }
        if (kHitTop && kHitRight)
        {
            return HTTOPRIGHT;
        }
        if (kHitBottom && kHitLeft)
        {
            return HTBOTTOMLEFT;
        }
        if (kHitBottom && kHitRight)
        {
            return HTBOTTOMRIGHT;
        }
        if (kHitLeft)
        {
            return HTLEFT;
        }
        if (kHitRight)
        {
            return HTRIGHT;
        }
        if (kHitTop)
        {
            return HTTOP;
        }
        if (kHitBottom)
        {
            return HTBOTTOM;
        }

        return HTCAPTION;
    }
#endif

    // resolveApplicationPreviewIcon：
    // - Purpose: Preferably extract the system shell icon from the executable file path.
    // - Goal: Make the top-left icon consistent with file previews in File Explorer.
    // - Out: Returns the executable's icon on success, or an empty icon on failure.
    QIcon resolveApplicationPreviewIcon()
    {
        // executablePathText usage: Stores the absolute path of the current process executable.
        const QString kExecutablePathText = QCoreApplication::applicationFilePath();
        if (kExecutablePathText.trimmed().isEmpty())
        {
            return QIcon();
        }

        // executableFileInfo purpose: Describes the current executable file path for the shell icon provider to read.
        const QFileInfo kExecutableFileInfo(kExecutablePathText);
        if (!kExecutableFileInfo.exists())
        {
            return QIcon();
        }

        // iconProvider purpose: Queries the system shell for file icons consistent with the file explorer.
        QFileIconProvider iconProvider;
        return iconProvider.icon(kExecutableFileInfo);
    }
}

namespace ks::ui
{
    CustomTitleBar::CustomTitleBar(QWidget* parentWidget)
        : QWidget(parentWidget)
    {
        initializeUi();
        initializeConnections();
        updateVisualState();
    }

    void CustomTitleBar::setPinnedState(const bool pinnedState)
    {
        isPinned_ = pinnedState;
        updateVisualState();
    }

    void CustomTitleBar::setCaptureProtectionState(const bool protectedState)
    {
        captureProtectionEnabled_ = protectedState;
        updateVisualState();
    }

    void CustomTitleBar::setMaximizedState(const bool maximizedState)
    {
        isMaximized_ = maximizedState;
        updateVisualState();
    }

    void CustomTitleBar::setDarkModeEnabled(const bool darkModeEnabled)
    {
        darkModeEnabled_ = darkModeEnabled;
        updateVisualState();
    }

    void CustomTitleBar::setCustomLeftWidget(QWidget* customLeftWidget)
    {
        if (leftLayout_ == nullptr || leftWidget_ == nullptr)
        {
            return;
        }

        if (customLeftWidget_ == customLeftWidget)
        {
            return;
        }

        if (customLeftWidget_ != nullptr)
        {
            leftLayout_->removeWidget(customLeftWidget_);
            customLeftWidget_->hide();
        }

        // m_customLeftWidget usage: Container for function entry points after the title text, facilitating subsequent replacement or removal.
        customLeftWidget_ = customLeftWidget;
        if (customLeftWidget_ == nullptr)
        {
            return;
        }

        if (customLeftWidget_->parentWidget() != leftWidget_)
        {
            customLeftWidget_->setParent(leftWidget_);
        }
        customLeftWidget_->setVisible(true);
        leftLayout_->addWidget(customLeftWidget_, 0);
    }

    void CustomTitleBar::setCustomRightWidget(QWidget* customRightWidget)
    {
        if (rightLayout_ == nullptr)
        {
            return;
        }

        if (customRightWidget_ == customRightWidget)
        {
            return;
        }

        if (customRightWidget_ != nullptr)
        {
            rightLayout_->removeWidget(customRightWidget_);
            customRightWidget_->hide();
        }

        // m_customRightWidget usage: Stores the right-side extended control instance for subsequent replacement or removal.
        customRightWidget_ = customRightWidget;
        if (customRightWidget_ == nullptr)
        {
            return;
        }

        if (customRightWidget_->parentWidget() != rightWidget_)
        {
            customRightWidget_->setParent(rightWidget_);
        }
        customRightWidget_->setVisible(true);
        rightLayout_->insertWidget(0, customRightWidget_, 0, Qt::AlignVCenter);
    }

    bool CustomTitleBar::isPointInDraggableRegion(const QPoint& localPos) const
    {
        if (!rect().contains(localPos))
        {
            return false;
        }

        // hitWidget is used to identify the currently hit child widget, preventing interactive controls from being treated as drag areas.
        QWidget* hitWidget = childAt(localPos);
        if (hitWidget == nullptr)
        {
            return true;
        }

        if (widgetBelongsTo(hitWidget, centerInputGroup_))
        {
            return false;
        }
        if (widgetBelongsTo(hitWidget, customLeftWidget_))
        {
            return false;
        }
        if (widgetBelongsTo(hitWidget, systemVersionLabel_))
        {
            return true;
        }
        if (widgetBelongsTo(hitWidget, rightWidget_))
        {
            return false;
        }

        return true;
    }

    int CustomTitleBar::titleBarHeight() const
    {
        return kTitleBarHeight;
    }

    void CustomTitleBar::resizeEvent(QResizeEvent* resizeEventPointer)
    {
        QWidget::resizeEvent(resizeEventPointer);
        updateCommandLineWidth();
    }

    void CustomTitleBar::mousePressEvent(QMouseEvent* mouseEventPointer)
    {
#ifdef Q_OS_WIN
        // Title bar movement on Windows is handled by native non-client area messages.
        // Handling logic:
        // - Input: Left button pressed on the draggable title bar region;
        // - Processing: Actively dispatch WM_NCLBUTTONDOWN/HTCAPTION to the top-level HWND.
        // - Return: System takes over move, Aero Snap, and maximize drag-down restore; the function itself has no return value.
        // Background:
        // - Custom-drawn title bars are Qt child controls; standard mouse messages may not trigger the top-level window's WM_NCHITTEST first.
        // - Relying solely on HTCAPTION hit testing causes the window to become undraggable after maximizing.
        // - Explicitly bridges to the native non-client area here to avoid simulating drag operations using showNormal()+setGeometry().
        if (mouseEventPointer != nullptr
            && mouseEventPointer->button() == Qt::LeftButton
            && isPointInDraggableRegion(mouseEventPointer->position().toPoint()))
        {
            dragCandidateActive_ = false;
            dragInProgress_ = false;
            QWidget* hostWindowWidget = window();
            const HWND kHostWindowHandleValue =
                hostWindowWidget != nullptr
                ? reinterpret_cast<HWND>(hostWindowWidget->winId())
                : nullptr;
            if (kHostWindowHandleValue != nullptr && ::IsWindow(kHostWindowHandleValue) != FALSE)
            {
                const QPoint kGlobalPoint = mouseEventPointer->globalPosition().toPoint();
                const WPARAM kHitTestCode = resolveTopLevelMoveResizeHitTest(kHostWindowHandleValue, kGlobalPoint);
                ::ReleaseCapture();
                ::SendMessageW(
                    kHostWindowHandleValue,
                    WM_NCLBUTTONDOWN,
                    kHitTestCode,
                    makeMouseScreenLParam(kGlobalPoint));
                mouseEventPointer->accept();
                return;
            }

            QWidget::mousePressEvent(mouseEventPointer);
            return;
        }
#endif

        if (mouseEventPointer != nullptr
            && mouseEventPointer->button() == Qt::LeftButton
            && isPointInDraggableRegion(mouseEventPointer->position().toPoint()))
        {
            // m_dragCandidateActive: Marks that the current left-click allows entering the title bar drag candidate state.
            dragCandidateActive_ = true;
            // m_dragInProgress: Resets the 'system drag started' flag when a new press sequence begins.
            dragInProgress_ = false;
            // m_dragPressLocalPos: Stores the local coordinates at press time for calculating relative positions during window restoration.
            dragPressLocalPos_ = mouseEventPointer->position().toPoint();
            // m_dragPressGlobalPos: Stores the global coordinates at press time for drag threshold checks and position restoration.
            dragPressGlobalPos_ = mouseEventPointer->globalPosition().toPoint();
            mouseEventPointer->accept();
            return;
        }

        dragCandidateActive_ = false;
        dragInProgress_ = false;
        QWidget::mousePressEvent(mouseEventPointer);
    }

    void CustomTitleBar::mouseMoveEvent(QMouseEvent* mouseEventPointer)
    {
#ifdef Q_OS_WIN
        // On Windows, we no longer manually simulate title bar dragging using
        // showNormal()+setGeometry()+startSystemMove(). The old chain causes Qt::WindowMaximized to desynchronize
        // from Win32 IsZoomed, resulting in the window being treated as maximized after dragging down from
        // maximized, the maximize button becoming unresponsive, and abnormal hit testing on border scaling.
        QWidget::mouseMoveEvent(mouseEventPointer);
        return;
#endif

        if (mouseEventPointer != nullptr
            && dragCandidateActive_
            && !dragInProgress_
            && (mouseEventPointer->buttons() & Qt::LeftButton))
        {
            // currentLocalPos: Records the coordinates relative to the top-left corner of the title bar during the current move.
            const QPoint kCurrentLocalPos = mouseEventPointer->position().toPoint();
            // dragDistance usage: Determine if the current movement has reached the system drag threshold to prevent clicks from being misidentified as drags.
            const int kDragDistance = (kCurrentLocalPos - dragPressLocalPos_).manhattanLength();
            if (kDragDistance >= QApplication::startDragDistance())
            {
                // currentGlobalPos usage: Current mouse global coordinates, reused for restoring the window and initiating system drag operations.
                const QPoint kCurrentGlobalPos = mouseEventPointer->globalPosition().toPoint();
                QWidget* hostWindowWidget = window();
                if (hostWindowWidget != nullptr)
                {
                    const bool kHostWindowMaximized =
                        hostWindowWidget->isMaximized()
                        || ((hostWindowWidget->windowState() & Qt::WindowMaximized) != 0);
                    if (kHostWindowMaximized)
                    {
                        restoreWindowFromMaximizedForDrag(hostWindowWidget, kCurrentGlobalPos);
                    }

                    if (tryStartWindowSystemMove(kCurrentGlobalPos))
                    {
                        dragCandidateActive_ = false;
                        dragInProgress_ = true;
                        mouseEventPointer->accept();
                        return;
                    }
                }
            }
        }

        QWidget::mouseMoveEvent(mouseEventPointer);
    }

    void CustomTitleBar::mouseReleaseEvent(QMouseEvent* mouseEventPointer)
    {
        dragCandidateActive_ = false;
        dragInProgress_ = false;
        QWidget::mouseReleaseEvent(mouseEventPointer);
    }

    void CustomTitleBar::mouseDoubleClickEvent(QMouseEvent* mouseEventPointer)
    {
#ifdef Q_OS_WIN
        // On Windows, double-clicking the title bar is also handled via HTCAPTION -> WM_NCLBUTTONDBLCLK.
        // Do not send requestToggleMaximizeWindow here to prevent Qt double-click events and native non-client area
        // double-clicks from each toggling the state once, causing maximize and restore to cancel each other out.
        if (mouseEventPointer != nullptr
            && mouseEventPointer->button() == Qt::LeftButton
            && isPointInDraggableRegion(mouseEventPointer->position().toPoint()))
        {
            dragCandidateActive_ = false;
            dragInProgress_ = false;
            QWidget* hostWindowWidget = window();
            const HWND kHostWindowHandleValue =
                hostWindowWidget != nullptr
                ? reinterpret_cast<HWND>(hostWindowWidget->winId())
                : nullptr;
            if (kHostWindowHandleValue != nullptr && ::IsWindow(kHostWindowHandleValue) != FALSE)
            {
                ::SendMessageW(
                    kHostWindowHandleValue,
                    WM_NCLBUTTONDBLCLK,
                    static_cast<WPARAM>(HTCAPTION),
                    makeMouseScreenLParam(mouseEventPointer->globalPosition().toPoint()));
                mouseEventPointer->accept();
                return;
            }

            QWidget::mouseDoubleClickEvent(mouseEventPointer);
            return;
        }
#endif

        if (mouseEventPointer != nullptr
            && mouseEventPointer->button() == Qt::LeftButton
            && isPointInDraggableRegion(mouseEventPointer->position().toPoint()))
        {
            dragCandidateActive_ = false;
            dragInProgress_ = false;
            emit requestToggleMaximizeWindow();
            mouseEventPointer->accept();
            return;
        }

        QWidget::mouseDoubleClickEvent(mouseEventPointer);
    }

    void CustomTitleBar::initializeUi()
    {
        setObjectName(QStringLiteral("ksCustomTitleBar"));
        setFixedHeight(kTitleBarHeight);
        setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        setAttribute(Qt::WA_StyledBackground, true);

        rootLayout_ = new QGridLayout(this);
        rootLayout_->setContentsMargins(6, 1, 12, 1);
        rootLayout_->setHorizontalSpacing(6);
        rootLayout_->setVerticalSpacing(0);
        rootLayout_->setColumnStretch(0, 1);
        rootLayout_->setColumnStretch(1, 1);
        rootLayout_->setColumnStretch(2, 1);

        // Left info area: app icon + fixed title text + user badge.
        leftWidget_ = new QWidget(this);
        leftLayout_ = new QHBoxLayout(leftWidget_);
        leftLayout_->setContentsMargins(0, 0, 0, 0);
        leftLayout_->setSpacing(4);

        appIconLabel_ = new QLabel(leftWidget_);
        appIconLabel_->setFixedSize(kAppIconSize, kAppIconSize);
        appIconLabel_->setAlignment(Qt::AlignCenter);

        titleTextLabel_ = new QLabel(leftWidget_);
        titleTextLabel_->setText(ks::i18n::sourceText(QStringLiteral("Ksword")));
        titleTextLabel_->setAlignment(Qt::AlignVCenter | Qt::AlignLeft);

        leftLayout_->addWidget(appIconLabel_, 0);
        leftLayout_->addWidget(titleTextLabel_, 0);

        // Center input group: left-side mode buttons (Search/CMD) + input field, merged into a single visual unit.
        // The default 'Search' mode performs global page text search; switching to CMD mode executes the return key in a new console.
        centerInputGroup_ = new QWidget(this);
        centerInputGroup_->setObjectName(QStringLiteral("ksTitleInputGroup"));
        centerInputGroup_->setAttribute(Qt::WA_StyledBackground, true);
        centerInputGroup_->setFixedHeight(22);
        centerInputLayout_ = new QHBoxLayout(centerInputGroup_);
        centerInputLayout_->setContentsMargins(1, 1, 1, 1);
        centerInputLayout_->setSpacing(0);

        inputModeButton_ = new QToolButton(centerInputGroup_);
        inputModeButton_->setObjectName(QStringLiteral("ksTitleInputModeButton"));
        inputModeButton_->setPopupMode(QToolButton::InstantPopup);
        inputModeButton_->setToolButtonStyle(Qt::ToolButtonTextOnly);
        inputModeButton_->setCursor(Qt::PointingHandCursor);
        inputModeButton_->setFocusPolicy(Qt::NoFocus);
        inputModeButton_->setFixedHeight(20);
        inputModeButton_->setToolTip(QStringLiteral("切换输入模式：页面搜索或 CMD 命令执行"));

        inputModeMenu_ = new QMenu(inputModeButton_);
        searchModeAction_ = inputModeMenu_->addAction(QStringLiteral("搜索"));
        searchModeAction_->setCheckable(true);
        commandModeAction_ = inputModeMenu_->addAction(QStringLiteral("CMD 命令"));
        commandModeAction_->setCheckable(true);
        inputModeButton_->setMenu(inputModeMenu_);

        commandLineEdit_ = new QLineEdit(centerInputGroup_);
        commandLineEdit_->setProperty("ksword_global_ui_search_input", true);
        commandLineEdit_->setClearButtonEnabled(true);
        commandLineEdit_->setFixedHeight(20);

        centerInputLayout_->addWidget(inputModeButton_, 0);
        centerInputLayout_->addWidget(commandLineEdit_, 1);

        // Right control area: system version + current time/runtime + screenshot blocking + pin + window buttons.
        rightWidget_ = new QWidget(this);
        rightLayout_ = new QHBoxLayout(rightWidget_);
        rightLayout_->setContentsMargins(0, 0, 2, 0);
        rightLayout_->setSpacing(1);

        systemVersionLabel_ = new QLabel(rightWidget_);
        systemVersionLabel_->setObjectName(QStringLiteral("ksTitleSystemVersionLabel"));
        systemVersionLabel_->setText(resolveWindowsVersionText());
        systemVersionLabel_->setAlignment(Qt::AlignVCenter | Qt::AlignRight);
        systemVersionLabel_->setFixedHeight(kControlButtonHeight);
        systemVersionLabel_->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);

        captureProtectionButton_ = new QPushButton(rightWidget_);
        pinButton_ = new QPushButton(rightWidget_);
        minButton_ = new QPushButton(rightWidget_);
        maxButton_ = new QPushButton(rightWidget_);
        closeButton_ = new QPushButton(rightWidget_);

        captureProtectionButton_->setObjectName(QStringLiteral("ksTitleCaptureProtectionButton"));
        pinButton_->setObjectName(QStringLiteral("ksTitlePinButton"));
        minButton_->setObjectName(QStringLiteral("ksTitleMinButton"));
        maxButton_->setObjectName(QStringLiteral("ksTitleMaxButton"));
        closeButton_->setObjectName(QStringLiteral("ksTitleCloseButton"));

        rightLayout_->addWidget(systemVersionLabel_, 0, Qt::AlignVCenter);

        const std::array<QPushButton*, 5> kControlButtons = {
            captureProtectionButton_,
            pinButton_,
            minButton_,
            maxButton_,
            closeButton_
        };\
        for (QPushButton* buttonObject : kControlButtons)
        {
            if (buttonObject == nullptr)
            {
                continue;
            }

            buttonObject->setFixedSize(kControlButtonWidth, kControlButtonHeight);
            buttonObject->setCursor(Qt::PointingHandCursor);
            buttonObject->setFocusPolicy(Qt::NoFocus);
            rightLayout_->addWidget(buttonObject, 0);
        }

        captureProtectionButton_->setToolTip(QStringLiteral("切换截屏屏蔽"));
        pinButton_->setToolTip(QStringLiteral("切换窗口置顶状态"));
        minButton_->setToolTip(QStringLiteral("最小化主窗口"));
        maxButton_->setToolTip(QStringLiteral("最大化或还原主窗口"));
        closeButton_->setToolTip(QStringLiteral("关闭主窗口"));

        rootLayout_->addWidget(leftWidget_, 0, 0, Qt::AlignLeft | Qt::AlignVCenter);
        rootLayout_->addWidget(centerInputGroup_, 0, 1, Qt::AlignCenter);
        rootLayout_->addWidget(rightWidget_, 0, 2, Qt::AlignRight | Qt::AlignVCenter);
        updateCommandLineWidth();
    }

    void CustomTitleBar::initializeConnections()
    {
        connect(captureProtectionButton_, &QPushButton::clicked, this, [this]() {
            emit requestToggleCaptureProtection();
        });
        connect(pinButton_, &QPushButton::clicked, this, [this]() {
            emit requestTogglePinned();
        });
        connect(minButton_, &QPushButton::clicked, this, [this]() {
            emit requestMinimizeWindow();
        });
        connect(maxButton_, &QPushButton::clicked, this, [this]() {
            emit requestToggleMaximizeWindow();
        });
        connect(closeButton_, &QPushButton::clicked, this, [this]() {
            emit requestCloseWindow();
        });
        connect(commandLineEdit_, &QLineEdit::returnPressed, this, [this]() {
            // Enter key presses in search mode are consumed by GlobalUiSearchController's event filter
            // and never reach this handler; this code handles command submission only for CMD mode.
            if (searchInputModeActive_)
            {
                return;
            }
            const QString kCommandText = commandLineEdit_->text().trimmed();
            if (kCommandText.isEmpty())
            {
                return;
            }
            emit commandSubmitted(kCommandText);
        });
        connect(commandLineEdit_, &QLineEdit::textChanged, this, [this](const QString& changedText) {
            if (searchInputModeActive_)
            {
                emit searchTextEdited(changedText);
            }
        });
        connect(searchModeAction_, &QAction::triggered, this, [this]() {
            setTitleInputMode(true);
        });
        connect(commandModeAction_, &QAction::triggered, this, [this]() {
            setTitleInputMode(false);
        });
    }

    void CustomTitleBar::updateVisualState()
    {
        const QString kTitleBarBackgroundText = ksword_theme::mainBackgroundColorHex();
        const QString kTitleBarBorderText = ksword_theme::borderColorHex();
        const QString kTitleTextColorText = ksword_theme::mainBackgroundTextColorHex();
        const QString kCommandBackgroundText = ksword_theme::surfaceColorHex();
        const QString kCommandTextColorText = ksword_theme::textPrimaryColorHex();
        const QString kCommandBorderText = ksword_theme::borderStrongColorHex();

        const QString kTitleBarStyleSheetText = QStringLiteral(
            "#ksCustomTitleBar{"
            "  background:%1;"
            "  border-bottom:1px solid %2;"
            "}"
            "#ksCustomTitleBar QLabel{"
            "  color:%3;"
            "  font-weight:600;"
            "}"
            "#ksCustomTitleBar QLabel#ksTitleSystemVersionLabel{"
            "  color:%3;"
            "  font-weight:500;"
            "  padding:0 4px;"
            "}"
            "#ksCustomTitleBar #ksTitleInputGroup{"
            "  background:%4;"
            "  border:1px solid %6;"
            "  border-radius:3px;"
            "}"
            "#ksCustomTitleBar #ksTitleInputGroup QLineEdit{"
            "  background:transparent;"
            "  color:%5;"
            "  border:none;"
            "  padding:0 6px;"
            "}"
            "#ksCustomTitleBar QToolButton#ksTitleInputModeButton{"
            "  background:transparent;"
            "  color:%5;"
            "  border:none;"
            "  border-right:1px solid %6;"
            "  border-top-left-radius:2px;"
            "  border-bottom-left-radius:2px;"
            "  padding:0 7px;"
            "  font-weight:600;"
            "}"
            "#ksCustomTitleBar QToolButton#ksTitleInputModeButton::menu-indicator{"
            "  image:none;"
            "  width:0;"
            "}"
            "#ksCustomTitleBar QToolButton#ksTitleInputModeButton:hover{"
            "  background:__TITLE_BUTTON_HOVER__;"
            "  color:__TITLE_MODE_HOVER_TEXT__;"
            "}"
            "#ksCustomTitleBar QPushButton{"
            "  background:transparent;"
            "  color:%3;"
            "  border:none;"
            "  border-radius:3px;"
            "}"
            "#ksCustomTitleBar QPushButton#ksTitleCaptureProtectionButton:hover,"
            "#ksCustomTitleBar QPushButton#ksTitlePinButton:hover,"
            "#ksCustomTitleBar QPushButton#ksTitleMinButton:hover,"
            "#ksCustomTitleBar QPushButton#ksTitleMaxButton:hover{"
            "  background:__TITLE_BUTTON_HOVER__;"
            "}"
            "#ksCustomTitleBar QPushButton#ksTitleCaptureProtectionButton:pressed,"
            "#ksCustomTitleBar QPushButton#ksTitlePinButton:pressed,"
            "#ksCustomTitleBar QPushButton#ksTitleMinButton:pressed,"
            "#ksCustomTitleBar QPushButton#ksTitleMaxButton:pressed{"
            "  background:__TITLE_BUTTON_PRESSED__;"
            "}"
            "#ksCustomTitleBar QPushButton#ksTitleCloseButton:hover{"
            "  background:__TITLE_CLOSE_HOVER__;"
            "}"
            "#ksCustomTitleBar QPushButton#ksTitleCloseButton:pressed{"
            "  background:__TITLE_CLOSE_PRESSED__;"
            "}"
            "}")
            .arg(kTitleBarBackgroundText)
            .arg(kTitleBarBorderText)
            .arg(kTitleTextColorText)
            .arg(kCommandBackgroundText)
            .arg(kCommandTextColorText)
            .arg(kCommandBorderText)
            .replace(QStringLiteral("__TITLE_BUTTON_HOVER__"), ksword_theme::primaryBlueSolidHoverHex())
            .replace(QStringLiteral("__TITLE_MODE_HOVER_TEXT__"), ksword_theme::onAccentHex())
            .replace(QStringLiteral("__TITLE_BUTTON_PRESSED__"), ksword_theme::kPrimaryBluePressedHex)
            .replace(QStringLiteral("__TITLE_CLOSE_HOVER__"), ksword_theme::accentHex(ksword_theme::AccentRole::kRed, 53, 27))
            .replace(QStringLiteral("__TITLE_CLOSE_PRESSED__"), ksword_theme::accentHex(ksword_theme::AccentRole::kRed, 30, 4));
        setStyleSheet(kTitleBarStyleSheetText);

        // Synchronize the icon with the button text:
        // - Toggle the screenshot blocking button icon between open/closed eye based on protection status;
        // - The pin icon switches between hollow and solid based on the topmost state.
        // - The maximize button toggles between maximize and restore icons based on the window state.
        captureProtectionButton_->setIcon(QIcon(
            captureProtectionEnabled_
            ? QStringLiteral(":/Icon/titlebar_capture_protected.svg")
            : QStringLiteral(":/Icon/titlebar_capture_allowed.svg")));
        captureProtectionButton_->setToolTip(captureProtectionEnabled_
            ? QStringLiteral("截屏屏蔽已开启：点击后允许截屏")
            : QStringLiteral("截屏屏蔽已关闭：点击后在截图/录屏中隐藏或黑屏"));
        captureProtectionButton_->setIconSize(QSize(kControlIconSize, kControlIconSize));

        pinButton_->setIcon(QIcon(
            isPinned_
            ? QStringLiteral(":/Icon/titlebar_pin_fill.svg")
            : QStringLiteral(":/Icon/titlebar_pin_line.svg")));
        pinButton_->setToolTip(isPinned_
            ? QStringLiteral("取消窗口置顶")
            : QStringLiteral("置顶窗口"));
        pinButton_->setIconSize(QSize(kControlIconSize, kControlIconSize));

        minButton_->setIcon(QIcon(QStringLiteral(":/Icon/titlebar_minimize.svg")));
        minButton_->setIconSize(QSize(kControlIconSize, kControlIconSize));

        maxButton_->setIcon(QIcon(
            isMaximized_
            ? QStringLiteral(":/Icon/titlebar_restore.svg")
            : QStringLiteral(":/Icon/titlebar_maximize.svg")));
        maxButton_->setToolTip(isMaximized_
            ? QStringLiteral("还原主窗口")
            : QStringLiteral("最大化主窗口"));
        maxButton_->setIconSize(QSize(kControlIconSize, kControlIconSize));

        closeButton_->setIcon(QIcon(QStringLiteral(":/Icon/titlebar_close.svg")));
        closeButton_->setIconSize(QSize(kControlIconSize, kControlIconSize));

        updateTitleInputModeVisuals();

        QIcon appIcon = resolveApplicationPreviewIcon();
        if (appIcon.isNull() && window() != nullptr)
        {
            appIcon = window()->windowIcon();
        }
        if (appIcon.isNull())
        {
            appIcon = QApplication::windowIcon();
        }
        if (appIcon.isNull())
        {
            appIcon = QIcon(QStringLiteral(":/Image/Resource/Logo/MainLogo.png"));
        }
        appIconLabel_->setPixmap(appIcon.pixmap(kAppIconSize, kAppIconSize));
    }

    void CustomTitleBar::updateCommandLineWidth()
    {
        if (centerInputGroup_ == nullptr)
        {
            return;
        }

        const int kCommandLineWidth = std::clamp(width() / 3, kCommandLineMinWidth, kCommandLineMaxWidth);
        centerInputGroup_->setFixedWidth(kCommandLineWidth);
    }

    QLineEdit* CustomTitleBar::titleInputLineEdit() const
    {
        return commandLineEdit_;
    }

    QWidget* CustomTitleBar::titleInputAnchorWidget() const
    {
        return centerInputGroup_;
    }

    bool CustomTitleBar::isSearchInputModeActive() const
    {
        return searchInputModeActive_;
    }

    void CustomTitleBar::activateSearchInput(const bool focusInput)
    {
        setTitleInputMode(true, focusInput);
    }

    void CustomTitleBar::setSearchScopeDisplayText(const QString& displayText)
    {
        const QString kNormalizedText = displayText.trimmed();
        searchScopeDisplayText_ = kNormalizedText.isEmpty()
            ? ks::i18n::sourceText(QStringLiteral("全局"))
            : kNormalizedText;
        updateTitleInputModeVisuals();
    }

    void CustomTitleBar::setTitleInputMode(
        const bool searchModeActive,
        const bool focusInput)
    {
        if (searchInputModeActive_ == searchModeActive)
        {
            updateTitleInputModeVisuals();
            if (focusInput && commandLineEdit_ != nullptr)
            {
                commandLineEdit_->setFocus(Qt::OtherFocusReason);
            }
            return;
        }

        searchInputModeActive_ = searchModeActive;
        updateTitleInputModeVisuals();
        emit inputModeChanged(searchModeActive);
        if (searchModeActive && commandLineEdit_ != nullptr
            && !commandLineEdit_->text().trimmed().isEmpty())
        {
            // When switching back to search mode, re-submit existing text to the search controller to restore the result dropdown.
            emit searchTextEdited(commandLineEdit_->text());
        }
        if (focusInput && commandLineEdit_ != nullptr)
        {
            commandLineEdit_->setFocus(Qt::OtherFocusReason);
        }
    }

    void CustomTitleBar::updateTitleInputModeVisuals()
    {
        if (inputModeButton_ == nullptr
            || commandLineEdit_ == nullptr
            || searchModeAction_ == nullptr
            || commandModeAction_ == nullptr)
        {
            return;
        }

        searchModeAction_->setChecked(searchInputModeActive_);
        commandModeAction_->setChecked(!searchInputModeActive_);
        if (searchInputModeActive_)
        {
            inputModeButton_->setText(
                ks::i18n::sourceText(QStringLiteral("搜索")) + QStringLiteral(" ▾"));
            inputModeButton_->setToolTip(
                ks::i18n::sourceText(QStringLiteral("搜索范围：%1。聚焦输入框后按 Tab 切换范围。"))
                    .arg(searchScopeDisplayText_));
            commandLineEdit_->setPlaceholderText(
                ks::i18n::sourceText(QStringLiteral("搜索")));
        }
        else
        {
            inputModeButton_->setText(QStringLiteral("CMD ▾"));
            commandLineEdit_->setPlaceholderText(
                QStringLiteral("输入命令后回车：将使用 cmd /K 在新控制台执行"));
        }
    }

    bool CustomTitleBar::tryStartWindowSystemMove(const QPoint& globalPoint)
    {
        Q_UNUSED(globalPoint);

        // hostWindowWidget usage: retrieves the top-level window to which the title bar belongs, used to initiate window dragging with the system.
        QWidget* hostWindowWidget = window();
        if (hostWindowWidget == nullptr)
        {
            return false;
        }

        // hostWindowHandle purpose: Qt's wrapper for the top-level native window handle.
        QWindow* hostWindowHandle = hostWindowWidget->windowHandle();
        if (hostWindowHandle != nullptr && hostWindowHandle->startSystemMove())
        {
            return true;
        }

#ifdef Q_OS_WIN
        // hostWindowHandleValue usage: the window handle required for the Win32 fallback drag-and-drop chain.
        const HWND kHostWindowHandleValue = reinterpret_cast<HWND>(hostWindowWidget->winId());
        if (kHostWindowHandleValue != nullptr && ::IsWindow(kHostWindowHandleValue) != FALSE)
        {
            ::ReleaseCapture();
            ::SendMessageW(
                kHostWindowHandleValue,
                WM_SYSCOMMAND,
                static_cast<WPARAM>(SC_MOVE | HTCAPTION),
                0);
            return true;
        }
#endif

        return false;
    }

    void CustomTitleBar::restoreWindowFromMaximizedForDrag(
        QWidget* hostWindowWidget,
        const QPoint& globalPoint)
    {
        if (hostWindowWidget == nullptr)
        {
            return;
        }

        // restoredGeometry: Used to read the normal geometry before window maximization for reuse during drag-down restoration.
        QRect restoredGeometry = hostWindowWidget->normalGeometry();
        if (!restoredGeometry.isValid()
            || restoredGeometry.width() <= 0
            || restoredGeometry.height() <= 0)
        {
            restoredGeometry = hostWindowWidget->geometry();
        }

        const int kWindowWidth = std::max(1, hostWindowWidget->width());
        // Purpose of horizontalRatio: stores the ratio of the press position relative to the full window width, ensuring the mouse remains at a similar position after restoration.
        const double kHorizontalRatio = std::clamp(
            static_cast<double>(dragPressLocalPos_.x()) / static_cast<double>(kWindowWidth),
            0.0,
            1.0);
        // restoredLeft usage: calculates the X coordinate of the window's top-left corner after restoring to windowed mode.
        int restoredLeft = globalPoint.x() - static_cast<int>(restoredGeometry.width() * kHorizontalRatio);
        // restoredTopOffset usage: Ensure the title bar stays close to the mouse after window restoration, rather than jumping directly to the top of the screen.
        const int kRestoredTopOffset = std::clamp(dragPressLocalPos_.y(), 12, 24);
        // restoredTop purpose: Calculates the Y-coordinate of the window's top-left corner after restoring to windowed mode.
        int restoredTop = globalPoint.y() - kRestoredTopOffset;

        // screenObject purpose: Finds the screen currently under the mouse to prevent the window from moving outside the available work area after restoration.
        QScreen* screenObject = QGuiApplication::screenAt(globalPoint);
        if (screenObject == nullptr && hostWindowWidget->windowHandle() != nullptr)
        {
            screenObject = hostWindowWidget->windowHandle()->screen();
        }
        if (screenObject != nullptr)
        {
            const QRect kAvailableGeometry = screenObject->availableGeometry();
            restoredLeft = std::clamp(
                restoredLeft,
                kAvailableGeometry.left(),
                kAvailableGeometry.right() - restoredGeometry.width() + 1);
            restoredTop = std::clamp(
                restoredTop,
                kAvailableGeometry.top(),
                kAvailableGeometry.bottom() - restoredGeometry.height() + 1);
        }

        hostWindowWidget->showNormal();
        hostWindowWidget->setGeometry(
            restoredLeft,
            restoredTop,
            restoredGeometry.width(),
            restoredGeometry.height());
    }

    QString CustomTitleBar::resolveWindowsVersionText() const
    {
#ifdef Q_OS_WIN
        using RtlGetVersionFunction = LONG(WINAPI*)(OSVERSIONINFOW*);
        const HMODULE kNtdllModuleHandle = ::GetModuleHandleW(L"ntdll.dll");
        const auto kRtlGetVersion = kNtdllModuleHandle != nullptr
            ? reinterpret_cast<RtlGetVersionFunction>(
                ::GetProcAddress(kNtdllModuleHandle, "RtlGetVersion"))
            : nullptr;
        if (kRtlGetVersion == nullptr)
        {
            return {};
        }

        OSVERSIONINFOW versionInfo = {};
        versionInfo.dwOSVersionInfoSize = sizeof(versionInfo);
        if (kRtlGetVersion(&versionInfo) != 0)
        {
            return {};
        }

        QString releaseVersionText = readWindowsCurrentVersionStringValue(L"DisplayVersion");
        if (releaseVersionText.isEmpty())
        {
            releaseVersionText = readWindowsCurrentVersionStringValue(L"ReleaseId");
        }
        if (releaseVersionText.isEmpty())
        {
            releaseVersionText = QString::number(versionInfo.dwBuildNumber);
        }

        const DWORD kDisplayMajorVersion =
            versionInfo.dwMajorVersion == 10 && versionInfo.dwBuildNumber >= 22000
            ? 11
            : versionInfo.dwMajorVersion;
        const DWORD kUpdateBuildRevision = readWindowsCurrentVersionDwordValue(L"UBR");

        return QStringLiteral("Win")
            + QString::number(kDisplayMajorVersion)
            + QStringLiteral(" ")
            + releaseVersionText
            + QStringLiteral("[")
            + QString::number(versionInfo.dwMajorVersion)
            + QStringLiteral(".")
            + QString::number(versionInfo.dwMinorVersion)
            + QStringLiteral(".")
            + QString::number(versionInfo.dwBuildNumber)
            + QStringLiteral(".")
            + QString::number(kUpdateBuildRevision)
            + QStringLiteral("]");
#else
        return {};
#endif
    }
}
