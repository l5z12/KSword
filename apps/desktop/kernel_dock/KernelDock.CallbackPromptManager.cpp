#include "KernelDock.h"
#include "KernelDock.CallbackPromptManager.h"

#include "../Theme.h"

#include <Windows.h>

#include <QApplication>
#include <QCloseEvent>
#include <QDateTime>
#include <QEvent>
#include <QFileIconProvider>
#include <QFileInfo>
#include <QFontMetrics>
#include <QGuiApplication>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QMessageBox>
#include <QMetaObject>
#include <QPalette>
#include <QPushButton>
#include <QPixmap>
#include <QRegularExpression>
#include <QScreen>
#include <QTimer>
#include <QtGlobal>
#include <QVBoxLayout>
#include <QWindow>

#include <chrono>

using ksword::kernel_dock_internal::kernelText;

namespace
{
    constexpr int kWaitWorkerCount = 3;
    constexpr int kWaitRetrySleepMs = 350;
    constexpr int kPollTickMs = 200;

    std::mutex gCallbackPromptManagerMutex;
    CallbackPromptManager* gCallbackPromptManager = nullptr;

    QString fromWideBuffer(const wchar_t* wideText)
    {
        if (wideText == nullptr)
        {
            return QString();
        }
        return QString::fromWCharArray(wideText).trimmed();
    }

    QString operationToDisplayText(const KSWORD_ARK_CALLBACK_EVENT_PACKET& eventPacket)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(eventPacket.operationType), 8, 16, QChar('0'))
            .toUpper();
    }

    QString queryProcessImagePathByPid(const quint32 processId)
    {
        if (processId == 0)
        {
            return QString();
        }

        HANDLE processHandle = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
        if (processHandle == nullptr)
        {
            return QString();
        }

        wchar_t imagePathBuffer[MAX_PATH * 4] = {};
        DWORD imagePathLength = static_cast<DWORD>(sizeof(imagePathBuffer) / sizeof(imagePathBuffer[0]));
        const BOOL kQueryOk = ::QueryFullProcessImageNameW(
            processHandle,
            0,
            imagePathBuffer,
            &imagePathLength);
        ::CloseHandle(processHandle);
        if (kQueryOk == FALSE || imagePathLength == 0)
        {
            return QString();
        }

        return QString::fromWCharArray(imagePathBuffer, static_cast<int>(imagePathLength)).trimmed();
    }

    QIcon resolveInitiatorProcessIcon(const quint32 processId, const QString& fallbackPath)
    {
        static QFileIconProvider iconProvider;

        const auto kIconByPath = [](const QString& pathText) -> QIcon {
            const QString kNormalizedPath = pathText.trimmed();
            if (kNormalizedPath.isEmpty())
            {
                return QIcon();
            }
            const QFileInfo kFileInfo(kNormalizedPath);
            if (!kFileInfo.exists())
            {
                return QIcon();
            }
            return iconProvider.icon(kFileInfo);
        };

        const QString kResolvedPath = queryProcessImagePathByPid(processId);
        QIcon processIcon = kIconByPath(kResolvedPath);
        if (processIcon.isNull())
        {
            processIcon = kIconByPath(fallbackPath);
        }
        if (processIcon.isNull())
        {
            processIcon = QIcon(QStringLiteral(":/Icon/process_main.svg"));
        }
        return processIcon;
    }

    QColor resolveCurrentAccentColor()
    {
        if (qApp != nullptr)
        {
            const QColor kHighlightColor =
                qApp->palette().color(QPalette::Active, QPalette::Highlight);
            if (kHighlightColor.isValid())
            {
                return kHighlightColor;
            }
        }
        return ksword_theme::primaryBlueColor;
    }

    QString currentAccentColorHex()
    {
        return resolveCurrentAccentColor().name(QColor::HexRgb);
    }

    QString buildPopupThemeStyleSheet()
    {
        const bool kDarkModeEnabled = ksword_theme::isDarkModeEnabled();
        const QColor kAccentColor = resolveCurrentAccentColor();

        const QColor kAccentHoverColor = ksword_theme::themeLighterColor(kAccentColor);
        const QColor kAccentPressedColor = ksword_theme::themeDarkerColor(kAccentColor);
        const QColor kNeutralHoverColor = ksword_theme::surfaceAltColor();
        const QColor kNeutralPressedColor = ksword_theme::surfaceMutedColor();

        QColor denyBackgroundColor = ksword_theme::warningAccentColor();
        denyBackgroundColor.setAlpha(kDarkModeEnabled ? 58 : 36);
        QColor denyHoverColor = ksword_theme::warningAccentColor();
        denyHoverColor.setAlpha(kDarkModeEnabled ? 88 : 60);
        QColor denyPressedColor = ksword_theme::warningAccentColor();
        denyPressedColor.setAlpha(kDarkModeEnabled ? 118 : 78);
        const QColor kDenyBorderColor = ksword_theme::warningAccentColor();

        QColor detailBackgroundColor = kAccentColor;
        detailBackgroundColor.setAlpha(kDarkModeEnabled ? 56 : 30);
        QColor detailHoverColor = kAccentColor;
        detailHoverColor.setAlpha(kDarkModeEnabled ? 86 : 54);
        QColor detailPressedColor = kAccentColor;
        detailPressedColor.setAlpha(kDarkModeEnabled ? 114 : 76);

        return QStringLiteral(
            "QDialog#KswordCallbackDecisionPopup{"
            "  background-color:palette(window);"
            "  color:palette(text);"
            "  border:1px solid %1;"
            "  border-radius:10px;"
            "}"
            "QDialog#KswordCallbackDecisionPopup QLabel{"
            "  color:palette(text);"
            "}"
            "QDialog#KswordCallbackDecisionPopup QLabel#KswordCallbackTitleLabel{"
            "  color:%1;"
            "  font-size:15px;"
            "  font-weight:800;"
            "}"
            "QDialog#KswordCallbackDecisionPopup QLabel#KswordCallbackSectionLabel{"
            "  color:%1;"
            "  font-weight:700;"
            "}"
            "QDialog#KswordCallbackDecisionPopup QLabel#KswordCallbackInitiatorLink{"
            "  color:%1;"
            "}"
            "QDialog#KswordCallbackDecisionPopup QPushButton{"
            "  background-color:palette(base);"
            "  color:palette(text);"
            "  border:1px solid palette(mid);"
            "  border-radius:2px;"
            "  padding:6px 14px;"
            "  min-height:30px;"
            "}"
            "QDialog#KswordCallbackDecisionPopup QPushButton:hover{"
            "  background-color:%2;"
            "  border-color:%1;"
            "}"
            "QDialog#KswordCallbackDecisionPopup QPushButton:pressed{"
            "  background-color:%3;"
            "}"
            "QPushButton#KswordCallbackAllowButton{"
            "  background-color:%1;"
            "  color:palette(highlighted-text);"
            "  border:1px solid %1;"
            "}"
            "QPushButton#KswordCallbackAllowButton:hover{"
            "  background-color:%4;"
            "  border-color:%4;"
            "}"
            "QPushButton#KswordCallbackAllowButton:pressed{"
            "  background-color:%5;"
            "  border-color:%5;"
            "}"
            "QPushButton#KswordCallbackDenyButton{"
            "  background-color:%6;"
            "  border:1px solid %7;"
            "}"
            "QPushButton#KswordCallbackDenyButton:hover{"
            "  background-color:%8;"
            "  border-color:%7;"
            "}"
            "QPushButton#KswordCallbackDenyButton:pressed{"
            "  background-color:%9;"
            "  border-color:%7;"
            "}"
            "QPushButton#KswordCallbackDetailButton{"
            "  background-color:%10;"
            "  border:1px solid %1;"
            "}"
            "QPushButton#KswordCallbackDetailButton:hover{"
            "  background-color:%11;"
            "  border-color:%1;"
            "}"
            "QPushButton#KswordCallbackDetailButton:pressed{"
            "  background-color:%12;"
            "  border-color:%1;"
            "}")
            .arg(kAccentColor.name(QColor::HexRgb))
            .arg(kNeutralHoverColor.name(QColor::HexRgb))
            .arg(kNeutralPressedColor.name(QColor::HexRgb))
            .arg(kAccentHoverColor.name(QColor::HexRgb))
            .arg(kAccentPressedColor.name(QColor::HexRgb))
            .arg(denyBackgroundColor.name(QColor::HexArgb))
            .arg(kDenyBorderColor.name(QColor::HexRgb))
            .arg(denyHoverColor.name(QColor::HexArgb))
            .arg(denyPressedColor.name(QColor::HexArgb))
            .arg(detailBackgroundColor.name(QColor::HexArgb))
            .arg(detailHoverColor.name(QColor::HexArgb))
            .arg(detailPressedColor.name(QColor::HexArgb));
    }

    QString buildDecisionButtonText(
        const quint32 buttonDecision,
        const quint32 defaultDecision,
        const qint64 remainingTimeoutMs)
    {
        const QString kBaseText = (buttonDecision == KSWORD_ARK_DECISION_DENY)
            ? kernelText("kernel.callback.prompt.decision.deny", QStringLiteral("拒绝"))
            : kernelText("kernel.callback.prompt.decision.allow", QStringLiteral("允许"));
        if (buttonDecision != defaultDecision)
        {
            return kBaseText;
        }

        const qint64 kRemainingSeconds = qMax<qint64>(0, (remainingTimeoutMs + 999LL) / 1000LL);
        return kernelText("kernel.callback.prompt.decision.countdown", QStringLiteral("%1（%2）"))
            .arg(kBaseText)
            .arg(kRemainingSeconds);
    }
}

CallbackPromptManager* CallbackPromptManager::ensureGlobalManager(QWidget* hostWindow)
{
    std::lock_guard<std::mutex> lockGuard(gCallbackPromptManagerMutex);
    if (gCallbackPromptManager == nullptr)
    {
        gCallbackPromptManager = new CallbackPromptManager(hostWindow, qApp);
    }
    if (hostWindow != nullptr)
    {
        gCallbackPromptManager->setHostWindow(hostWindow);
    }
    return gCallbackPromptManager;
}

CallbackPromptManager* CallbackPromptManager::globalManager()
{
    std::lock_guard<std::mutex> lockGuard(gCallbackPromptManagerMutex);
    return gCallbackPromptManager;
}

void CallbackPromptManager::shutdownGlobalManager()
{
    CallbackPromptManager* manager = nullptr;
    {
        std::lock_guard<std::mutex> lockGuard(gCallbackPromptManagerMutex);
        manager = gCallbackPromptManager;
        gCallbackPromptManager = nullptr;
    }

    if (manager != nullptr)
    {
        manager->stop();
        delete manager;
    }
}

CallbackPromptManager::DecisionPopupDialog::DecisionPopupDialog(
    CallbackPromptManager* owner,
    QWidget* parent)
    : QDialog(parent)
    , owner_(owner)
{
}

void CallbackPromptManager::DecisionPopupDialog::closeEvent(QCloseEvent* event)
{
    // Event source closed: Alt+F4, system menu close, or window manager close all enter here.
    // Handling logic: driver callback decisions must be completed via the 'Allow/Reject' buttons or the timeout path; close requests do not trigger default decisions.
    // Return behavior: Ignore this close event; Qt will retain the current pending decision dialog.
    if (event != nullptr)
    {
        event->ignore();
    }
}

CallbackPromptManager::CallbackPromptManager(QWidget* hostWindow, QObject* parent)
    : QObject(parent)
    , hostWindow_(hostWindow)
{
    initializePopupUi();
    initializePopupConnections();
    if (qApp != nullptr)
    {
        qApp->installEventFilter(this);
    }
}

CallbackPromptManager::~CallbackPromptManager()
{
    if (qApp != nullptr)
    {
        qApp->removeEventFilter(this);
    }
    stop();
}

bool CallbackPromptManager::eventFilter(QObject* watched, QEvent* event)
{
    if (watched == qApp && event != nullptr)
    {
        const QEvent::Type kEventType = event->type();
        if (kEventType == QEvent::ApplicationPaletteChange ||
            kEventType == QEvent::PaletteChange ||
            kEventType == QEvent::StyleChange)
        {
            applyPopupTheme();
            if (hasCurrentEvent_)
            {
                updatePopupContent(currentEvent_);
            }
        }
    }
    return QObject::eventFilter(watched, event);
}

void CallbackPromptManager::applyPopupTheme()
{
    if (popupDialog_.isNull())
    {
        return;
    }
    popupDialog_->setStyleSheet(buildPopupThemeStyleSheet());
}

void CallbackPromptManager::setHostWindow(QWidget* hostWindow)
{
    hostWindow_ = hostWindow;
    movePopupToBottomRight();
}

void CallbackPromptManager::start()
{
    if (running_.exchange(true))
    {
        return;
    }

    appendManagerLog(kernelText("kernel.callback.prompt.log.manager_started", QStringLiteral("驱动回调全局弹窗管理器已启动。")));
    startWorkersIfNeeded();
}

void CallbackPromptManager::stop()
{
    if (!running_.exchange(false))
    {
        return;
    }

    stopWorkersIfNeeded();
    cancelAllPendingDecisionsBestEffort();

    {
        std::lock_guard<std::mutex> queueLock(queueMutex_);
        eventQueue_.clear();
        hasCurrentEvent_ = false;
        RtlZeroMemory(&currentEvent_, sizeof(currentEvent_));
        remainingTimeoutMs_ = 0;
    }

    if (countdownTimer_ != nullptr)
    {
        countdownTimer_->stop();
    }
    if (!popupDialog_.isNull())
    {
        popupDialog_->hide();
    }

    appendManagerLog(kernelText("kernel.callback.prompt.log.manager_stopped", QStringLiteral("驱动回调全局弹窗管理器已停止。")));
}

void CallbackPromptManager::initializePopupUi()
{
    auto* popupDialog = new DecisionPopupDialog(this);
    popupDialog->setObjectName(QStringLiteral("KswordCallbackDecisionPopup"));
    popupDialog->setWindowFlags(
        Qt::Tool |
        Qt::FramelessWindowHint |
        Qt::WindowStaysOnTopHint |
        Qt::NoDropShadowWindowHint);
    popupDialog->setModal(false);
    popupDialog->setAttribute(Qt::WA_ShowWithoutActivating, true);

    auto* rootLayout = new QVBoxLayout(popupDialog);
    rootLayout->setContentsMargins(14, 12, 14, 12);
    rootLayout->setSpacing(10);

    auto* headerLayout = new QHBoxLayout();
    headerLayout->setContentsMargins(0, 0, 0, 0);
    headerLayout->setSpacing(8);

    auto* logoLabel = new QLabel(popupDialog);
    logoLabel->setFixedSize(100, 28);
    logoLabel->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    const QPixmap kMainLogoPixmap(QStringLiteral(":/Image/Resource/Logo/MainLogo.png"));
    if (!kMainLogoPixmap.isNull())
    {
        logoLabel->setPixmap(kMainLogoPixmap.scaled(
            logoLabel->size(),
            Qt::KeepAspectRatio,
            Qt::SmoothTransformation));
    }

    auto* titleLabel = new QLabel(kernelText("kernel.callback.prompt.title", QStringLiteral("驱动回调决策")), popupDialog);
    titleLabel->setObjectName(QStringLiteral("KswordCallbackTitleLabel"));

    headerLayout->addWidget(logoLabel, 0, Qt::AlignVCenter);
    headerLayout->addWidget(titleLabel, 0, Qt::AlignVCenter);
    headerLayout->addStretch(1);
    rootLayout->addLayout(headerLayout, 0);

    auto* detailGrid = new QGridLayout();
    detailGrid->setHorizontalSpacing(8);
    detailGrid->setVerticalSpacing(6);

    int rowIndex = 0;
    auto appendRow = [popupDialog, detailGrid, &rowIndex](const QString& nameText, QLabel** valueLabelOut) {
        auto* nameLabel = new QLabel(nameText, popupDialog);
        nameLabel->setObjectName(QStringLiteral("KswordCallbackSectionLabel"));
        auto* valueLabel = new QLabel(QStringLiteral("-"), popupDialog);
        valueLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        valueLabel->setWordWrap(true);
        detailGrid->addWidget(nameLabel, rowIndex, 0, 1, 1);
        detailGrid->addWidget(valueLabel, rowIndex, 1, 1, 1);
        if (valueLabelOut != nullptr)
        {
            *valueLabelOut = valueLabel;
        }
        ++rowIndex;
    };

    appendRow(kernelText("kernel.callback.prompt.label.event_guid", QStringLiteral("事件GUID")), &eventGuidValueLabel_);
    appendRow(kernelText("kernel.callback.prompt.label.callback_type", QStringLiteral("回调类型")), &callbackTypeValueLabel_);
    appendRow(kernelText("kernel.callback.prompt.label.operation_type", QStringLiteral("操作类型")), &operationValueLabel_);
    appendRow(kernelText("kernel.callback.prompt.label.target", QStringLiteral("目标")), &targetValueLabel_);

    auto* initiatorNameLabel = new QLabel(kernelText("kernel.callback.prompt.label.initiator", QStringLiteral("发起进程")), popupDialog);
    initiatorNameLabel->setObjectName(QStringLiteral("KswordCallbackSectionLabel"));
    auto* initiatorRowWidget = new QWidget(popupDialog);
    auto* initiatorRowLayout = new QHBoxLayout(initiatorRowWidget);
    initiatorRowLayout->setContentsMargins(0, 0, 0, 0);
    initiatorRowLayout->setSpacing(6);
    initiatorIconLabel_ = new QLabel(initiatorRowWidget);
    initiatorIconLabel_->setFixedSize(18, 18);
    initiatorIconLabel_->setScaledContents(false);
    initiatorValueLabel_ = new QLabel(QStringLiteral("-"), initiatorRowWidget);
    initiatorValueLabel_->setObjectName(QStringLiteral("KswordCallbackInitiatorLink"));
    initiatorValueLabel_->setTextFormat(Qt::RichText);
    initiatorValueLabel_->setTextInteractionFlags(Qt::LinksAccessibleByMouse);
    initiatorValueLabel_->setOpenExternalLinks(false);
    initiatorValueLabel_->setWordWrap(false);
    initiatorValueLabel_->setCursor(Qt::PointingHandCursor);
    initiatorValueLabel_->setToolTip(kernelText("kernel.callback.prompt.initiator.tooltip", QStringLiteral("点击发起进程文本可打开进程详细信息")));
    initiatorRowLayout->addWidget(initiatorIconLabel_, 0, Qt::AlignVCenter);
    initiatorRowLayout->addWidget(initiatorValueLabel_, 1, Qt::AlignVCenter);
    detailGrid->addWidget(initiatorNameLabel, rowIndex, 0, 1, 1);
    detailGrid->addWidget(initiatorRowWidget, rowIndex, 1, 1, 1);
    ++rowIndex;

    appendRow(kernelText("kernel.callback.prompt.label.session_id", QStringLiteral("会话ID")), &sessionIdValueLabel_);
    appendRow(kernelText("kernel.callback.prompt.label.rule", QStringLiteral("规则")), &ruleValueLabel_);
    detailGrid->setColumnStretch(0, 0);
    detailGrid->setColumnStretch(1, 1);
    rootLayout->addLayout(detailGrid, 1);

    auto* actionLayout = new QHBoxLayout();
    actionLayout->setContentsMargins(0, 2, 0, 0);
    actionLayout->setSpacing(8);

    allowButton_ = new QPushButton(kernelText("kernel.callback.prompt.decision.allow", QStringLiteral("允许")), popupDialog);
    allowButton_->setObjectName(QStringLiteral("KswordCallbackAllowButton"));
    denyButton_ = new QPushButton(kernelText("kernel.callback.prompt.decision.deny", QStringLiteral("拒绝")), popupDialog);
    denyButton_->setObjectName(QStringLiteral("KswordCallbackDenyButton"));
    detailButton_ = new QPushButton(kernelText("kernel.callback.prompt.button.details", QStringLiteral("查看详情")), popupDialog);
    detailButton_->setObjectName(QStringLiteral("KswordCallbackDetailButton"));

    actionLayout->addStretch(1);
    actionLayout->addWidget(allowButton_, 0);
    actionLayout->addWidget(denyButton_, 0);
    actionLayout->addWidget(detailButton_, 0);
    rootLayout->addLayout(actionLayout, 0);

    popupDialog_ = popupDialog;
    applyPopupTheme();

    countdownTimer_ = new QTimer(this);
    countdownTimer_->setInterval(kPollTickMs);
}

void CallbackPromptManager::initializePopupConnections()
{
    if (countdownTimer_ != nullptr)
    {
        connect(countdownTimer_, &QTimer::timeout, this, [this]() {
            updateCountdownLabel();
        });
    }

    if (allowButton_ != nullptr)
    {
        connect(allowButton_, &QPushButton::clicked, this, [this]() {
            finishCurrentEventWithDecision(KSWORD_ARK_DECISION_ALLOW, false);
        });
    }

    if (denyButton_ != nullptr)
    {
        connect(denyButton_, &QPushButton::clicked, this, [this]() {
            finishCurrentEventWithDecision(KSWORD_ARK_DECISION_DENY, false);
        });
    }

    if (initiatorValueLabel_ != nullptr)
    {
        connect(initiatorValueLabel_, &QLabel::linkActivated, this, [this](const QString&) {
            if (!hasCurrentEvent_ || currentEvent_.originatingPid == 0)
            {
                return;
            }
            QWidget* invokeTarget = hostWindow_;
            if (invokeTarget == nullptr)
            {
                invokeTarget = qobject_cast<QWidget*>(qApp != nullptr ? qApp->activeWindow() : nullptr);
            }
            if (invokeTarget == nullptr)
            {
                appendManagerLog(kernelText("kernel.callback.prompt.log.process_detail_no_window", QStringLiteral("无法打开进程详情：主窗口对象为空。")));
                return;
            }

            const bool kInvokeOk = QMetaObject::invokeMethod(
                invokeTarget,
                "openProcessDetailByPid",
                Qt::QueuedConnection,
                Q_ARG(quint32, currentEvent_.originatingPid));
            appendManagerLog(
                kernelText("kernel.callback.prompt.log.process_link_clicked", QStringLiteral("发起进程超链接被点击: pid=%1, 跳转=%2。"))
                .arg(currentEvent_.originatingPid)
                .arg(kInvokeOk
                    ? kernelText("kernel.callback.prompt.result.success", QStringLiteral("成功"))
                    : kernelText("kernel.callback.prompt.result.failure", QStringLiteral("失败"))));
        });
    }

    if (detailButton_ != nullptr)
    {
        connect(detailButton_, &QPushButton::clicked, this, [this]() {
            if (!hasCurrentEvent_)
            {
                return;
            }

            const QString kDetailText = kernelText("kernel.callback.prompt.detail.full", QStringLiteral(
                "事件GUID: %1\n"
                "回调类型: %2\n"
                "操作类型: %3\n"
                "动作: %4\n"
                "匹配模式: %5\n"
                "发起进程: %6\n"
                "目标: %7\n"
                "PID: %8\n"
                "TID: %9\n"
                "会话ID: %10\n"
                "规则组: [%11] %12\n"
                "规则: [%13] %14\n"
                "规则发起匹配: %15\n"
                "规则目标匹配: %16\n"
                "默认决策: %17\n"
                "超时毫秒: %18"))
                .arg(callbackGuidToString(currentEvent_.eventGuid))
                .arg(callbackTypeToDisplayText(currentEvent_.callbackType))
                .arg(operationToDisplayText(currentEvent_))
                .arg(callbackActionToDisplayText(currentEvent_.action))
                .arg(callbackMatchModeToDisplayText(currentEvent_.matchMode))
                .arg(fromWideBuffer(currentEvent_.initiatorPath))
                .arg(fromWideBuffer(currentEvent_.targetPath))
                .arg(currentEvent_.originatingPid)
                .arg(currentEvent_.originatingTid)
                .arg(currentEvent_.sessionId)
                .arg(currentEvent_.groupId)
                .arg(fromWideBuffer(currentEvent_.groupName))
                .arg(currentEvent_.ruleId)
                .arg(fromWideBuffer(currentEvent_.ruleName))
                .arg(fromWideBuffer(currentEvent_.ruleInitiatorPattern))
                .arg(fromWideBuffer(currentEvent_.ruleTargetPattern))
                .arg(callbackDecisionToDisplayText(currentEvent_.defaultDecision))
                .arg(currentEvent_.timeoutMs);

            QMessageBox::information(
                popupDialog_,
                kernelText("kernel.callback.prompt.detail.title", QStringLiteral("驱动回调详情")),
                kDetailText);
        });
    }
}

void CallbackPromptManager::appendManagerLog(const QString& logText)
{
    const QString kLineText = QStringLiteral("[%1] %2")
        .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss.zzz")))
        .arg(logText);
    emit logLineGenerated(kLineText);
}

void CallbackPromptManager::startWorkersIfNeeded()
{
    if (!workerList_.empty())
    {
        return;
    }

    workerList_.reserve(kWaitWorkerCount);
    for (int workerIndex = 0; workerIndex < kWaitWorkerCount; ++workerIndex)
    {
        auto workerContext = std::make_unique<WaitWorkerContext>();
        workerContext->workerTag = workerIndex + 1;
        workerContext->running.store(true);
        workerContext->thread = std::make_unique<std::thread>(
            [this, tag = workerContext->workerTag]() {
                runWaitWorkerLoop(tag);
            });
        workerList_.push_back(std::move(workerContext));
    }
}

void CallbackPromptManager::stopWorkersIfNeeded()
{
    for (const std::unique_ptr<WaitWorkerContext>& workerContext : workerList_)
    {
        if (workerContext == nullptr)
        {
            continue;
        }

        workerContext->running.store(false);
        std::lock_guard<std::mutex> handleLock(workerContext->ioMutex);
        if (workerContext->deviceHandle.isValid())
        {
            (void)::CancelIoEx(workerContext->deviceHandle.native(), nullptr);
        }
    }

    for (const std::unique_ptr<WaitWorkerContext>& workerContext : workerList_)
    {
        if (workerContext == nullptr || workerContext->thread == nullptr)
        {
            continue;
        }
        if (workerContext->thread->joinable())
        {
            workerContext->thread->join();
        }
    }

    for (const std::unique_ptr<WaitWorkerContext>& workerContext : workerList_)
    {
        if (workerContext == nullptr)
        {
            continue;
        }
        std::lock_guard<std::mutex> handleLock(workerContext->ioMutex);
        workerContext->deviceHandle.reset();
    }

    workerList_.clear();
}

void CallbackPromptManager::runWaitWorkerLoop(int workerTag)
{
    WaitWorkerContext* workerContext = nullptr;
    for (const std::unique_ptr<WaitWorkerContext>& currentWorker : workerList_)
    {
        if (currentWorker != nullptr && currentWorker->workerTag == workerTag)
        {
            workerContext = currentWorker.get();
            break;
        }
    }
    if (workerContext == nullptr)
    {
        return;
    }

    auto resetDeviceHandle = [workerContext]() {
        std::lock_guard<std::mutex> handleLock(workerContext->ioMutex);
        workerContext->deviceHandle.reset();
    };

    while (workerContext->running.load())
    {
        HANDLE waitHandle = INVALID_HANDLE_VALUE;
        {
            std::lock_guard<std::mutex> handleLock(workerContext->ioMutex);
            waitHandle = workerContext->deviceHandle.native();
        }

        if (waitHandle == nullptr || waitHandle == INVALID_HANDLE_VALUE)
        {
            ksword::ark::DriverClient driverClient;
            ksword::ark::DriverHandle newHandle = driverClient.openOverlapped();
            if (!newHandle.isValid())
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(kWaitRetrySleepMs));
                continue;
            }

            {
                std::lock_guard<std::mutex> handleLock(workerContext->ioMutex);
                workerContext->deviceHandle = std::move(newHandle);
                waitHandle = workerContext->deviceHandle.native();
            }
        }

        KSWORD_ARK_CALLBACK_WAIT_REQUEST waitRequest{};
        waitRequest.size = sizeof(waitRequest);
        waitRequest.version = KSWORD_ARK_CALLBACK_PROTOCOL_VERSION;
        waitRequest.waiterTag = static_cast<unsigned long>(workerTag);

        KSWORD_ARK_CALLBACK_EVENT_PACKET eventPacket{};
        OVERLAPPED waitOverlapped{};
        waitOverlapped.hEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (waitOverlapped.hEvent == nullptr)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(kWaitRetrySleepMs));
            continue;
        }

        DWORD bytesReturned = 0;
        ksword::ark::DriverClient driverClient;
        const ksword::ark::AsyncIoResult kWaitIssueResult = driverClient.waitCallbackEventAsync(
            workerContext->deviceHandle,
            waitRequest,
            eventPacket,
            &waitOverlapped);
        bytesReturned = kWaitIssueResult.bytesReturned;

        if (!kWaitIssueResult.issued)
        {
            const DWORD kWaitError = kWaitIssueResult.win32Error;
            if (kWaitError == ERROR_IO_PENDING)
            {
                bool needCancel = false;
                while (workerContext->running.load())
                {
                    const DWORD kWaitResult = ::WaitForSingleObject(waitOverlapped.hEvent, kPollTickMs);
                    if (kWaitResult == WAIT_OBJECT_0)
                    {
                        break;
                    }
                    if (kWaitResult == WAIT_FAILED)
                    {
                        needCancel = true;
                        break;
                    }
                }

                if (!workerContext->running.load() || needCancel)
                {
                    (void)::CancelIoEx(waitHandle, &waitOverlapped);
                    // Cancellation is asynchronous: keep the stack-backed OVERLAPPED and
                    // output packet alive until the pending DeviceIoControl has completed.
                    (void)::GetOverlappedResult(
                        waitHandle,
                        &waitOverlapped,
                        &bytesReturned,
                        TRUE);
                }

                if (::GetOverlappedResult(waitHandle, &waitOverlapped, &bytesReturned, FALSE) == FALSE)
                {
                    const DWORD kOverlappedError = ::GetLastError();
                    ::CloseHandle(waitOverlapped.hEvent);

                    if (!workerContext->running.load())
                    {
                        break;
                    }

                    if (kOverlappedError == ERROR_OPERATION_ABORTED ||
                        kOverlappedError == ERROR_INVALID_HANDLE ||
                        kOverlappedError == ERROR_DEVICE_NOT_CONNECTED ||
                        kOverlappedError == ERROR_FILE_NOT_FOUND)
                    {
                        resetDeviceHandle();
                    }

                    std::this_thread::sleep_for(std::chrono::milliseconds(kWaitRetrySleepMs));
                    continue;
                }
            }
            else
            {
                ::CloseHandle(waitOverlapped.hEvent);
                if (!workerContext->running.load())
                {
                    break;
                }

                if (kWaitError == ERROR_INVALID_HANDLE ||
                    kWaitError == ERROR_DEVICE_NOT_CONNECTED ||
                    kWaitError == ERROR_FILE_NOT_FOUND)
                {
                    resetDeviceHandle();
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(kWaitRetrySleepMs));
                continue;
            }
        }

        ::CloseHandle(waitOverlapped.hEvent);

        if (!workerContext->running.load())
        {
            break;
        }

        if (bytesReturned < sizeof(KSWORD_ARK_CALLBACK_EVENT_PACKET))
        {
            continue;
        }
        if (eventPacket.size < sizeof(KSWORD_ARK_CALLBACK_EVENT_PACKET) ||
            eventPacket.version != KSWORD_ARK_CALLBACK_PROTOCOL_VERSION)
        {
            continue;
        }

        QMetaObject::invokeMethod(this, [this, eventPacket]() {
            onEventArrivedOnUiThread(eventPacket);
        }, Qt::QueuedConnection);
    }

    resetDeviceHandle();
}

void CallbackPromptManager::onEventArrivedOnUiThread(const KSWORD_ARK_CALLBACK_EVENT_PACKET& eventPacket)
{
    if (!running_.load())
    {
        return;
    }

    if (shouldAutoAllowByRegex(eventPacket))
    {
        const bool kAnswerOk = sendAnswerToDriver(eventPacket.eventGuid, KSWORD_ARK_DECISION_ALLOW);
        appendManagerLog(
            kernelText("kernel.callback.prompt.log.regex_auto_allow", QStringLiteral("事件 %1 触发 Regex 二次确认自动放行（%2）。"))
            .arg(callbackGuidToString(eventPacket.eventGuid))
            .arg(kAnswerOk
                ? kernelText("kernel.callback.prompt.result.reply_success", QStringLiteral("回传成功"))
                : kernelText("kernel.callback.prompt.result.reply_failure", QStringLiteral("回传失败"))));
        return;
    }

    enqueueEvent(eventPacket);
}

void CallbackPromptManager::enqueueEvent(const KSWORD_ARK_CALLBACK_EVENT_PACKET& eventPacket)
{
    {
        std::lock_guard<std::mutex> queueLock(queueMutex_);
        eventQueue_.push_back(eventPacket);
    }

    appendManagerLog(
        kernelText("kernel.callback.prompt.log.event_queued", QStringLiteral("收到待决策事件 %1，当前队列长度=%2。"))
        .arg(callbackGuidToString(eventPacket.eventGuid))
        .arg(static_cast<int>(eventQueue_.size())));
    tryShowNextEvent();
}

bool CallbackPromptManager::shouldAutoAllowByRegex(const KSWORD_ARK_CALLBACK_EVENT_PACKET& eventPacket) const
{
    // The R0 regex hot path performs only coarse matching; true regex confirmation occurs in R3.
    // Both registry and file system minifilters reuse this policy: automatically allow if no match or the expression is invalid.
    if ((eventPacket.callbackType != KSWORD_ARK_CALLBACK_TYPE_REGISTRY &&
        eventPacket.callbackType != KSWORD_ARK_CALLBACK_TYPE_MINIFILTER) ||
        eventPacket.action != KSWORD_ARK_RULE_ACTION_ASK_USER ||
        eventPacket.matchMode != KSWORD_ARK_MATCH_MODE_REGEX)
    {
        return false;
    }

    const QString kInitiatorPattern = fromWideBuffer(eventPacket.ruleInitiatorPattern);
    const QString kTargetPattern = fromWideBuffer(eventPacket.ruleTargetPattern);
    const QString kInitiatorPath = fromWideBuffer(eventPacket.initiatorPath);
    const QString kTargetPath = fromWideBuffer(eventPacket.targetPath);

    auto isMatched = [](const QString& patternText, const QString& sourceText, bool* validOut) -> bool {
        if (validOut != nullptr)
        {
            *validOut = true;
        }
        if (patternText.trimmed().isEmpty())
        {
            return true;
        }

        const QRegularExpression kRegexPattern(patternText);
        if (!kRegexPattern.isValid())
        {
            if (validOut != nullptr)
            {
                *validOut = false;
            }
            return false;
        }
        return kRegexPattern.match(sourceText).hasMatch();
    };

    bool initiatorValid = true;
    const bool kInitiatorMatched = isMatched(kInitiatorPattern, kInitiatorPath, &initiatorValid);
    bool targetValid = true;
    const bool kTargetMatched = isMatched(kTargetPattern, kTargetPath, &targetValid);

    if (!initiatorValid || !targetValid)
    {
        return true;
    }
    if (!kInitiatorMatched || !kTargetMatched)
    {
        return true;
    }
    return false;
}

void CallbackPromptManager::tryShowNextEvent()
{
    if (!running_.load())
    {
        return;
    }
    if (hasCurrentEvent_)
    {
        return;
    }
    if (popupDialog_.isNull())
    {
        return;
    }

    KSWORD_ARK_CALLBACK_EVENT_PACKET nextEvent{};
    bool hasEvent = false;
    {
        std::lock_guard<std::mutex> queueLock(queueMutex_);
        if (!eventQueue_.empty())
        {
            nextEvent = eventQueue_.front();
            eventQueue_.pop_front();
            hasEvent = true;
        }
    }

    if (!hasEvent)
    {
        return;
    }

    currentEvent_ = nextEvent;
    hasCurrentEvent_ = true;
    remainingTimeoutMs_ = static_cast<qint64>(currentEvent_.timeoutMs);
    if (remainingTimeoutMs_ <= 0)
    {
        remainingTimeoutMs_ = 5000;
    }

    applyPopupTheme();
    movePopupToBottomRight();

    popupDialog_->show();
    popupDialog_->raise();
    popupDialog_->activateWindow();

    updatePopupContent(currentEvent_);

    if (countdownTimer_ != nullptr)
    {
        countdownTimer_->start();
    }
    updateCountdownLabel();
}

void CallbackPromptManager::updatePopupContent(const KSWORD_ARK_CALLBACK_EVENT_PACKET& eventPacket)
{
    if (eventGuidValueLabel_ != nullptr)
    {
        eventGuidValueLabel_->setText(callbackGuidToString(eventPacket.eventGuid));
    }
    if (callbackTypeValueLabel_ != nullptr)
    {
        callbackTypeValueLabel_->setText(callbackTypeToDisplayText(eventPacket.callbackType));
    }
    if (operationValueLabel_ != nullptr)
    {
        operationValueLabel_->setText(operationToDisplayText(eventPacket));
    }
    if (targetValueLabel_ != nullptr)
    {
        targetValueLabel_->setText(fromWideBuffer(eventPacket.targetPath));
    }

    const QString kInitiatorPathText = fromWideBuffer(eventPacket.initiatorPath);
    const QString kInitiatorLineText = QStringLiteral("[%1]%2;")
        .arg(eventPacket.originatingPid)
        .arg(kInitiatorPathText.isEmpty() ? QStringLiteral("-") : kInitiatorPathText);
    if (initiatorValueLabel_ != nullptr)
    {
        int availableWidth = initiatorValueLabel_->width();
        if (availableWidth <= 24 && !popupDialog_.isNull())
        {
            availableWidth = qMax(180, popupDialog_->width() - 300);
        }
        if (availableWidth <= 24)
        {
            availableWidth = 280;
        }

        const QFontMetrics kFontMetrics(initiatorValueLabel_->font());
        const QString kElidedText = kFontMetrics.elidedText(
            kInitiatorLineText,
            Qt::ElideMiddle,
            availableWidth);

        initiatorValueLabel_->setToolTip(kInitiatorLineText);
        initiatorValueLabel_->setText(
            QStringLiteral("<a href=\"pid:%1\" style=\"color:%2;text-decoration:underline;\">%3</a>")
            .arg(eventPacket.originatingPid)
            .arg(currentAccentColorHex())
            .arg(kElidedText.toHtmlEscaped()));
    }
    if (initiatorIconLabel_ != nullptr)
    {
        const QIcon kProcessIcon = resolveInitiatorProcessIcon(
            eventPacket.originatingPid,
            kInitiatorPathText);
        initiatorIconLabel_->setPixmap(kProcessIcon.pixmap(16, 16));
    }

    if (sessionIdValueLabel_ != nullptr)
    {
        sessionIdValueLabel_->setText(QString::number(eventPacket.sessionId));
    }
    if (ruleValueLabel_ != nullptr)
    {
        ruleValueLabel_->setText(
            QStringLiteral("[%1] %2 / [%3] %4")
            .arg(eventPacket.groupId)
            .arg(fromWideBuffer(eventPacket.groupName))
            .arg(eventPacket.ruleId)
            .arg(fromWideBuffer(eventPacket.ruleName)));
    }
}

void CallbackPromptManager::updateCountdownLabel()
{
    if (!hasCurrentEvent_)
    {
        return;
    }

    qint64 remainingMs = remainingTimeoutMs_;
    if (currentEvent_.deadlineUtc100ns > 0ULL)
    {
        const qint64 kDeadline100ns = static_cast<qint64>(currentEvent_.deadlineUtc100ns);
        const qint64 kNow100ns = static_cast<qint64>(currentUtc100ns());
        remainingMs = (kDeadline100ns - kNow100ns) / 10000LL;
    }
    if (remainingMs < 0)
    {
        remainingMs = 0;
    }
    remainingTimeoutMs_ = remainingMs;

    const quint32 kDefaultDecision =
        (currentEvent_.defaultDecision == KSWORD_ARK_DECISION_DENY)
        ? KSWORD_ARK_DECISION_DENY
        : KSWORD_ARK_DECISION_ALLOW;
    if (allowButton_ != nullptr)
    {
        allowButton_->setText(buildDecisionButtonText(
            KSWORD_ARK_DECISION_ALLOW,
            kDefaultDecision,
            remainingTimeoutMs_));
    }
    if (denyButton_ != nullptr)
    {
        denyButton_->setText(buildDecisionButtonText(
            KSWORD_ARK_DECISION_DENY,
            kDefaultDecision,
            remainingTimeoutMs_));
    }

    if (remainingTimeoutMs_ <= 0)
    {
        finishCurrentEventWithDecision(kDefaultDecision, true);
    }
}

void CallbackPromptManager::finishCurrentEventWithDecision(quint32 decision, bool fromTimeoutOrClose)
{
    if (!hasCurrentEvent_)
    {
        return;
    }

    if (countdownTimer_ != nullptr)
    {
        countdownTimer_->stop();
    }

    quint32 finalDecision = decision;
    if (finalDecision != KSWORD_ARK_DECISION_ALLOW &&
        finalDecision != KSWORD_ARK_DECISION_DENY)
    {
        finalDecision =
            (currentEvent_.defaultDecision == KSWORD_ARK_DECISION_DENY)
            ? KSWORD_ARK_DECISION_DENY
            : KSWORD_ARK_DECISION_ALLOW;
    }

    const bool kAnswerOk = sendAnswerToDriver(currentEvent_.eventGuid, finalDecision);
    appendManagerLog(
        kernelText("kernel.callback.prompt.log.event_decided", QStringLiteral("事件 %1 已决策为“%2”（来源=%3，回传=%4）。"))
        .arg(callbackGuidToString(currentEvent_.eventGuid))
        .arg(callbackDecisionToDisplayText(finalDecision))
        .arg(fromTimeoutOrClose
            ? kernelText("kernel.callback.prompt.result.timeout_or_close", QStringLiteral("超时/关闭"))
            : kernelText("kernel.callback.prompt.result.user_click", QStringLiteral("用户点击")))
        .arg(kAnswerOk
            ? kernelText("kernel.callback.prompt.result.success", QStringLiteral("成功"))
            : kernelText("kernel.callback.prompt.result.failure", QStringLiteral("失败"))));

    hasCurrentEvent_ = false;
    remainingTimeoutMs_ = 0;
    RtlZeroMemory(&currentEvent_, sizeof(currentEvent_));

    if (!popupDialog_.isNull())
    {
        popupDialog_->hide();
    }

    QTimer::singleShot(0, this, [this]() {
        tryShowNextEvent();
    });
}

void CallbackPromptManager::onPopupClosedByUser()
{
    if (!hasCurrentEvent_)
    {
        if (!popupDialog_.isNull())
        {
            popupDialog_->hide();
        }
        return;
    }

    const quint32 kFallbackDecision =
        (currentEvent_.defaultDecision == KSWORD_ARK_DECISION_DENY)
        ? KSWORD_ARK_DECISION_DENY
        : KSWORD_ARK_DECISION_ALLOW;
    finishCurrentEventWithDecision(kFallbackDecision, true);
}

bool CallbackPromptManager::sendAnswerToDriver(const KSWORD_ARK_GUID128& eventGuid, quint32 decision)
{
    KSWORD_ARK_CALLBACK_ANSWER_REQUEST answerRequest{};
    answerRequest.size = sizeof(answerRequest);
    answerRequest.version = KSWORD_ARK_CALLBACK_PROTOCOL_VERSION;
    answerRequest.eventGuid = eventGuid;
    answerRequest.decision =
        (decision == KSWORD_ARK_DECISION_DENY)
        ? KSWORD_ARK_DECISION_DENY
        : KSWORD_ARK_DECISION_ALLOW;
    answerRequest.sourceSessionId = currentSessionId();
    answerRequest.answeredAtUtc100ns = currentUtc100ns();

    const ksword::ark::DriverClient kDriverClient;
    const ksword::ark::IoResult kResult = kDriverClient.answerCallbackEvent(answerRequest);
    return kResult.ok;
}

void CallbackPromptManager::cancelAllPendingDecisionsBestEffort()
{
    const ksword::ark::DriverClient kDriverClient;
    (void)kDriverClient.cancelAllPendingCallbackDecisions();
}

quint64 CallbackPromptManager::currentUtc100ns() const
{
    FILETIME utcFileTime{};
    ::GetSystemTimePreciseAsFileTime(&utcFileTime);

    ULARGE_INTEGER utcValue{};
    utcValue.HighPart = utcFileTime.dwHighDateTime;
    utcValue.LowPart = utcFileTime.dwLowDateTime;
    return utcValue.QuadPart;
}

quint32 CallbackPromptManager::currentSessionId() const
{
    DWORD sessionId = 0;
    if (::ProcessIdToSessionId(::GetCurrentProcessId(), &sessionId) == FALSE)
    {
        return 0;
    }
    return static_cast<quint32>(sessionId);
}

void CallbackPromptManager::movePopupToBottomRight()
{
    if (popupDialog_.isNull())
    {
        return;
    }

    QScreen* targetScreen = nullptr;
    if (hostWindow_ != nullptr &&
        hostWindow_->windowHandle() != nullptr &&
        hostWindow_->windowHandle()->screen() != nullptr)
    {
        targetScreen = hostWindow_->windowHandle()->screen();
    }
    if (targetScreen == nullptr)
    {
        targetScreen = QGuiApplication::primaryScreen();
    }
    if (targetScreen == nullptr)
    {
        return;
    }

    const QRect kAvailableRect = targetScreen->availableGeometry();
    const QSize kPopupSize = popupDialog_->sizeHint().expandedTo(QSize(680, 360));
    const int kPopupX = kAvailableRect.right() - kPopupSize.width() - 12;
    const int kPopupY = kAvailableRect.bottom() - kPopupSize.height() - 12;
    popupDialog_->resize(kPopupSize);
    popupDialog_->move(kPopupX, kPopupY);
}
