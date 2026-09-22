#include "ServiceDock.Internal.h"
#include "../Theme.h"

#include <QFileDialog>
#include <QSignalBlocker>
#include <QVariant>

using namespace service_dock_detail;

namespace
{
    // kDetailRenderDebounceMs:
    // - Debounce window for detail rendering when the main list selection changes continuously.
    // - Direction key scrolling triggers a single heavyweight tab rebuild only after stopping.
    constexpr int kDetailRenderDebounceMs = 150;

    // kDetailRenderTimerProperty:
    // - Stores the pointer to the single-shot timer for 'detail page delayed rendering'.
    // - This change does not extend the shared header ServiceDock.h, so dynamic properties are used to carry this state.
    constexpr const char* kDetailRenderTimerProperty = "service_detail_render_timer";

    // kRenderedServiceNameProperty:
    // - Record which service is currently displayed on a heavyweight tab.
    // - Use this to determine if content has expired when switching tabs, avoiding unnecessary re-queries and overwriting unsaved edits.
    constexpr const char* kRenderedServiceNameProperty = "service_detail_rendered_service";

    // detailRenderTimerOf purpose: Retrieve the deferred rendering timer attached to ServiceDock.
    // Input: ownerWidget is the ServiceDock instance.
    // Returns: timer pointer; returns nullptr if not yet initialized.
    QTimer* detailRenderTimerOf(const QWidget* ownerWidget)
    {
        if (ownerWidget == nullptr)
        {
            return nullptr;
        }
        return qobject_cast<QTimer*>(ownerWidget->property(kDetailRenderTimerProperty).value<QObject*>());
    }

    // markDetailPageRendered purpose: Record the short service name of the current heavyweight tab being rendered.
    // Args: detailPage is the root control of the tab; serviceNameText is the rendered short service name. An empty string indicates invalidation.
    // Returns: Nothing.
    void markDetailPageRendered(QWidget* detailPage, const QString& serviceNameText)
    {
        if (detailPage != nullptr)
        {
            detailPage->setProperty(kRenderedServiceNameProperty, serviceNameText);
        }
    }

    // isDetailPageRenderedFor: Checks if the content of a heavyweight tab is already associated with the specified service.
    // Input parameters: detailPage is the root control of the tab; serviceNameText is the currently selected short service name.
    // Returns: true if the content is already the latest rendered result for the service.
    bool isDetailPageRenderedFor(const QWidget* detailPage, const QString& serviceNameText)
    {
        if (detailPage == nullptr || serviceNameText.trimmed().isEmpty())
        {
            return false;
        }

        const QString kRenderedServiceNameText = detailPage->property(kRenderedServiceNameProperty).toString();
        return !kRenderedServiceNameText.isEmpty()
            && QString::compare(kRenderedServiceNameText, serviceNameText, Qt::CaseInsensitive) == 0;
    }

    // isLocalSystemAccountText:
    // - Determine if the account text represents LocalSystem;
    // - Reused when populating radio buttons on the login page.
    bool isLocalSystemAccountText(const QString& accountText)
    {
        const QString kNormalizedText = accountText.trimmed().toLower();
        return kNormalizedText == QStringLiteral("localsystem")
            || kNormalizedText == QStringLiteral("nt authority\\localsystem");
    }

    // buildPropertyActionButton:
    // - Build the action buttons at the top of the properties page;
    // - Unify icon, size, and tooltip rules.
    QToolButton* buildPropertyActionButton(
        QWidget* parentWidget,
        const char* iconPath,
        const QString& toolTipText)
    {
        QToolButton* button = new QToolButton(parentWidget);
        button->setIcon(createBlueIcon(iconPath, ksword_theme::compactIconSize()));
        ksword_theme::applyCompactIconButtonMetrics(button);
        button->setToolTip(toolTipText);
        return button;
    }

    // buildRecoveryActionCombo:
    // - Build the recovery action combo box and write action enumeration data;
    // - The three action groups on the recovery page share the same option set.
    QComboBox* buildRecoveryActionCombo(QWidget* parentWidget)
    {
        QComboBox* comboBox = new QComboBox(parentWidget);
        comboBox->addItem(QStringLiteral("无操作"), static_cast<int>(SC_ACTION_NONE));
        comboBox->addItem(QStringLiteral("重新启动服务"), static_cast<int>(SC_ACTION_RESTART));
        comboBox->addItem(QStringLiteral("运行程序"), static_cast<int>(SC_ACTION_RUN_COMMAND));
        comboBox->addItem(QStringLiteral("重新启动计算机"), static_cast<int>(SC_ACTION_REBOOT));
        return comboBox;
    }

    // splitRecoveryCommandText:
    // - Split the FailureActions command text into 'program + arguments';
    // - Simultaneously detect if the parameter ending with /fail=%1% is attached.
    void splitRecoveryCommandText(
        const QString& commandText,
        QString* programPathOut,
        QString* argumentsOut,
        bool* appendFailureCountOut)
    {
        if (programPathOut != nullptr)
        {
            *programPathOut = QString();
        }
        if (argumentsOut != nullptr)
        {
            *argumentsOut = QString();
        }
        if (appendFailureCountOut != nullptr)
        {
            *appendFailureCountOut = false;
        }

        QString workingText = commandText.trimmed();
        if (workingText.isEmpty())
        {
            return;
        }

        const QString kFailTokenText = QStringLiteral("/fail=%1%");
        if (workingText.contains(kFailTokenText, Qt::CaseInsensitive))
        {
            workingText.replace(kFailTokenText, QString(), Qt::CaseInsensitive);
            workingText = workingText.trimmed();
            if (appendFailureCountOut != nullptr)
            {
                *appendFailureCountOut = true;
            }
        }

        if (workingText.startsWith('\"'))
        {
            const int kEndQuoteIndex = workingText.indexOf('\"', 1);
            if (kEndQuoteIndex > 1)
            {
                if (programPathOut != nullptr)
                {
                    *programPathOut = workingText.mid(1, kEndQuoteIndex - 1).trimmed();
                }
                if (argumentsOut != nullptr)
                {
                    *argumentsOut = workingText.mid(kEndQuoteIndex + 1).trimmed();
                }
                return;
            }
        }

        const int kFirstSpaceIndex = workingText.indexOf(' ');
        if (kFirstSpaceIndex > 0)
        {
            if (programPathOut != nullptr)
            {
                *programPathOut = workingText.left(kFirstSpaceIndex).trimmed();
            }
            if (argumentsOut != nullptr)
            {
                *argumentsOut = workingText.mid(kFirstSpaceIndex + 1).trimmed();
            }
            return;
        }

        if (programPathOut != nullptr)
        {
            *programPathOut = workingText;
        }
    }

    // composeRecoveryCommandText:
    // - Compose recovery command using 'program + arguments + optional fail token';
    // - Saved for reuse during recovery configuration to avoid scattered string rules.
    QString composeRecoveryCommandText(
        const QString& programPathText,
        const QString& argumentsText,
        const bool appendFailureCount)
    {
        QStringList segmentList;
        const QString kNormalizedProgramPath = programPathText.trimmed();
        if (!kNormalizedProgramPath.isEmpty())
        {
            segmentList.push_back(kNormalizedProgramPath.contains(' ')
                ? QStringLiteral("\"%1\"").arg(kNormalizedProgramPath)
                : kNormalizedProgramPath);
        }

        const QString kNormalizedArguments = argumentsText.trimmed();
        if (!kNormalizedArguments.isEmpty())
        {
            segmentList.push_back(kNormalizedArguments);
        }
        if (appendFailureCount)
        {
            segmentList.push_back(QStringLiteral("/fail=%1%"));
        }

        return segmentList.join(QStringLiteral(" ")).trimmed();
    }
}

void ServiceDock::initializeDetailTabs()
{
    generalTabPage_ = new QWidget(detailTabWidget_);
    logonTabPage_ = new QWidget(detailTabWidget_);
    recoveryTabPage_ = new QWidget(detailTabWidget_);
    dependencyTabPage_ = new QWidget(detailTabWidget_);
    auditTabPage_ = new QWidget(detailTabWidget_);

    initializeGeneralTab();
    initializeLogonTab();
    initializeRecoveryTab();
    initializeDependencyTab();
    initializeAuditTab();

    detailTabWidget_->addTab(generalTabPage_, createBlueIcon(":/Icon/process_details.svg"), QStringLiteral("常规"));
    detailTabWidget_->addTab(logonTabPage_, createBlueIcon(":/Icon/process_main.svg"), QStringLiteral("登录"));
    detailTabWidget_->addTab(recoveryTabPage_, createBlueIcon(":/Icon/process_refresh.svg"), QStringLiteral("恢复"));
    detailTabWidget_->addTab(dependencyTabPage_, createBlueIcon(":/Icon/process_list.svg"), QStringLiteral("依存关系"));
    detailTabWidget_->addTab(auditTabPage_, createBlueIcon(":/Icon/process_critical.svg"), QStringLiteral("审计"));

    detailTabWidget_->setTabToolTip(0, QStringLiteral("常规属性与启动类型配置"));
    detailTabWidget_->setTabToolTip(1, QStringLiteral("服务登录身份与交互桌面配置"));
    detailTabWidget_->setTabToolTip(2, QStringLiteral("服务失败恢复动作配置"));
    detailTabWidget_->setTabToolTip(3, QStringLiteral("服务依赖与反向依赖信息"));
    detailTabWidget_->setTabToolTip(4, QStringLiteral("触发器、安全、风险与导出信息"));

    // The Restore, Dependency, and Audit tabs each require a full SCM traversal on every refresh (totaling over ten RPC calls to services.exe).
    // Previously, full rendering was synchronized in itemSelectionChanged, incurring this cost for every row during arrow-key scrolling.
    // Changed here to a single-shot timer for unified scheduling:
    // 1) Restart the timer only for the selected row; no SCM round-trips occur during scrolling;
    // 2) The timer renders only the currently visible page; hidden pages are rendered later when switched to.
    QTimer* const kDetailRenderTimer = new QTimer(this);
    kDetailRenderTimer->setSingleShot(true);
    setProperty(kDetailRenderTimerProperty, QVariant::fromValue<QObject*>(kDetailRenderTimer));

    connect(kDetailRenderTimer, &QTimer::timeout, this, [this]()
        {
            const int kSelectedIndex = findServiceIndexByName(selectedServiceName());
            if (kSelectedIndex < 0 || kSelectedIndex >= static_cast<int>(serviceList_.size()))
            {
                return;
            }

            const ServiceEntry& selectedEntry = serviceList_[static_cast<std::size_t>(kSelectedIndex)];
            QWidget* const kVisibleDetailPage = (detailTabWidget_ == nullptr)
                ? nullptr
                : detailTabWidget_->currentWidget();

            // During backfilling, use the same signal-blocking semantics as updateDetailViewsFromSelection.
            const bool kPreviousSyncFlag = detailUiSyncInProgress_;
            detailUiSyncInProgress_ = true;
            if (kVisibleDetailPage == recoveryTabPage_
                && !isDetailPageRenderedFor(recoveryTabPage_, selectedEntry.serviceNameText))
            {
                populateRecoveryTab(selectedEntry);
            }
            else if (kVisibleDetailPage == dependencyTabPage_
                && !isDetailPageRenderedFor(dependencyTabPage_, selectedEntry.serviceNameText))
            {
                populateDependencyTab(selectedEntry);
            }
            else if (kVisibleDetailPage == auditTabPage_
                && !isDetailPageRenderedFor(auditTabPage_, selectedEntry.serviceNameText))
            {
                populateAuditTab(selectedEntry);
            }
            detailUiSyncInProgress_ = kPreviousSyncFlag;
        });

    connect(detailTabWidget_, &QTabWidget::currentChanged, this, [this](const int)
        {
            // Immediately trigger rendering when switching tabs: no flags are invalidated here, so tabs
            // already matching the current service are skipped, and unsaved user edits are not overwritten.
            QTimer* const kRenderTimer = detailRenderTimerOf(this);
            if (kRenderTimer != nullptr)
            {
                kRenderTimer->start(0);
            }
        });
}

void ServiceDock::initializeGeneralTab()
{
    QVBoxLayout* rootLayout = new QVBoxLayout(generalTabPage_);
    rootLayout->setContentsMargins(8, 8, 8, 8);
    rootLayout->setSpacing(8);

    QWidget* actionRowWidget = new QWidget(generalTabPage_);
    QHBoxLayout* actionRowLayout = new QHBoxLayout(actionRowWidget);
    actionRowLayout->setContentsMargins(0, 0, 0, 0);
    actionRowLayout->setSpacing(6);

    generalStartButton_ = buildPropertyActionButton(actionRowWidget, ":/Icon/process_start.svg", QStringLiteral("启动当前服务"));
    generalStopButton_ = buildPropertyActionButton(actionRowWidget, ":/Icon/process_terminate.svg", QStringLiteral("停止当前服务"));
    generalPauseButton_ = buildPropertyActionButton(actionRowWidget, ":/Icon/process_pause.svg", QStringLiteral("暂停当前服务"));
    generalContinueButton_ = buildPropertyActionButton(actionRowWidget, ":/Icon/process_resume.svg", QStringLiteral("继续当前服务"));
    generalReloadButton_ = buildPropertyActionButton(actionRowWidget, ":/Icon/process_refresh.svg", QStringLiteral("重载当前服务属性"));
    generalApplyButton_ = buildPropertyActionButton(actionRowWidget, ":/Icon/codeeditor_save.svg", QStringLiteral("应用常规页修改"));

    actionRowLayout->addWidget(generalStartButton_);
    actionRowLayout->addWidget(generalStopButton_);
    actionRowLayout->addWidget(generalPauseButton_);
    actionRowLayout->addWidget(generalContinueButton_);
    actionRowLayout->addStretch(1);
    actionRowLayout->addWidget(generalReloadButton_);
    actionRowLayout->addWidget(generalApplyButton_);
    rootLayout->addWidget(actionRowWidget, 0);

    QFormLayout* formLayout = new QFormLayout();
    formLayout->setLabelAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    formLayout->setFormAlignment(Qt::AlignTop);
    formLayout->setHorizontalSpacing(10);
    formLayout->setVerticalSpacing(8);

    generalServiceNameEdit_ = new QLineEdit(generalTabPage_);
    generalServiceNameEdit_->setReadOnly(true);
    generalDisplayNameEdit_ = new QLineEdit(generalTabPage_);
    generalBinaryPathEdit_ = new QLineEdit(generalTabPage_);
    generalBinaryPathEdit_->setReadOnly(true);
    generalDescriptionEdit_ = new QPlainTextEdit(generalTabPage_);
    generalDescriptionEdit_->setFixedHeight(96);
    generalStartTypeCombo_ = new QComboBox(generalTabPage_);
    generalStartTypeCombo_->addItem(QStringLiteral("自动"), static_cast<qulonglong>(SERVICE_AUTO_START));
    generalStartTypeCombo_->addItem(QStringLiteral("手动"), static_cast<qulonglong>(SERVICE_DEMAND_START));
    generalStartTypeCombo_->addItem(QStringLiteral("禁用"), static_cast<qulonglong>(SERVICE_DISABLED));
    generalDelayedAutoCheck_ = new QCheckBox(QStringLiteral("延迟自动启动"), generalTabPage_);
    generalStartTypeCombo_->setToolTip(
        QStringLiteral("设置该服务的启动方式：自动=开机自启，手动=按需启动，禁用=禁止启动"));
    generalDelayedAutoCheck_->setToolTip(
        QStringLiteral("开机后延迟一段时间再启动该服务，可减轻开机瞬间的负载"));

    QWidget* startTypeRowWidget = new QWidget(generalTabPage_);
    QHBoxLayout* startTypeRowLayout = new QHBoxLayout(startTypeRowWidget);
    startTypeRowLayout->setContentsMargins(0, 0, 0, 0);
    startTypeRowLayout->setSpacing(8);
    startTypeRowLayout->addWidget(generalStartTypeCombo_, 1);
    startTypeRowLayout->addWidget(generalDelayedAutoCheck_, 0);

    generalStateValueLabel_ = new QLabel(QStringLiteral("-"), generalTabPage_);
    generalPidValueLabel_ = new QLabel(QStringLiteral("-"), generalTabPage_);
    generalAccountValueLabel_ = new QLabel(QStringLiteral("-"), generalTabPage_);
    generalTypeValueLabel_ = new QLabel(QStringLiteral("-"), generalTabPage_);
    generalErrorControlValueLabel_ = new QLabel(QStringLiteral("-"), generalTabPage_);

    formLayout->addRow(QStringLiteral("服务名"), generalServiceNameEdit_);
    formLayout->addRow(QStringLiteral("显示名"), generalDisplayNameEdit_);
    formLayout->addRow(QStringLiteral("路径"), generalBinaryPathEdit_);
    formLayout->addRow(QStringLiteral("描述"), generalDescriptionEdit_);
    formLayout->addRow(QStringLiteral("启动类型"), startTypeRowWidget);
    formLayout->addRow(QStringLiteral("状态"), generalStateValueLabel_);
    formLayout->addRow(QStringLiteral("PID"), generalPidValueLabel_);
    formLayout->addRow(QStringLiteral("账户"), generalAccountValueLabel_);
    formLayout->addRow(QStringLiteral("类型"), generalTypeValueLabel_);
    formLayout->addRow(QStringLiteral("错误控制"), generalErrorControlValueLabel_);
    rootLayout->addLayout(formLayout, 1);

    connect(generalStartButton_, &QToolButton::clicked, this, [this]() { startSelectedService(); });
    connect(generalStopButton_, &QToolButton::clicked, this, [this]() { stopSelectedService(); });
    connect(generalPauseButton_, &QToolButton::clicked, this, [this]() { pauseSelectedService(); });
    connect(generalContinueButton_, &QToolButton::clicked, this, [this]() { continueSelectedService(); });
    connect(generalReloadButton_, &QToolButton::clicked, this, [this]() { refreshSelectedService(); });
    connect(generalApplyButton_, &QToolButton::clicked, this, [this]() { applyGeneralTabChanges(); });
    connect(generalStartTypeCombo_, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int) { refreshGeneralTabUiState(); });
}

void ServiceDock::initializeLogonTab()
{
    QVBoxLayout* rootLayout = new QVBoxLayout(logonTabPage_);
    rootLayout->setContentsMargins(8, 8, 8, 8);
    rootLayout->setSpacing(8);

    QWidget* actionRowWidget = new QWidget(logonTabPage_);
    QHBoxLayout* actionRowLayout = new QHBoxLayout(actionRowWidget);
    actionRowLayout->setContentsMargins(0, 0, 0, 0);
    actionRowLayout->setSpacing(6);
    logonReloadButton_ = buildPropertyActionButton(actionRowWidget, ":/Icon/process_refresh.svg", QStringLiteral("重载登录页属性"));
    logonApplyButton_ = buildPropertyActionButton(actionRowWidget, ":/Icon/codeeditor_save.svg", QStringLiteral("应用登录页修改"));
    actionRowLayout->addStretch(1);
    actionRowLayout->addWidget(logonReloadButton_);
    actionRowLayout->addWidget(logonApplyButton_);
    rootLayout->addWidget(actionRowWidget, 0);

    logonLocalSystemRadio_ = new QRadioButton(QStringLiteral("本地系统帐户"), logonTabPage_);
    logonDesktopInteractCheck_ = new QCheckBox(QStringLiteral("允许服务与桌面交互"), logonTabPage_);
    logonAccountRadio_ = new QRadioButton(QStringLiteral("此帐户"), logonTabPage_);
    logonLocalSystemRadio_->setToolTip(
        QStringLiteral("以系统内置的高权限帐户运行该服务"));
    logonDesktopInteractCheck_->setToolTip(
        QStringLiteral("允许该服务在当前登录用户的桌面上显示窗口（较老的机制，现代系统通常无效）"));
    logonAccountRadio_->setToolTip(
        QStringLiteral("改用下方指定的用户帐户运行该服务"));
    logonAccountEdit_ = new QLineEdit(logonTabPage_);
    logonPasswordEdit_ = new QLineEdit(logonTabPage_);
    logonPasswordEdit_->setEchoMode(QLineEdit::Password);
    logonConfirmPasswordEdit_ = new QLineEdit(logonTabPage_);
    logonConfirmPasswordEdit_->setEchoMode(QLineEdit::Password);
    logonBrowseButton_ = buildPropertyActionButton(logonTabPage_, ":/Icon/process_open_folder.svg", QStringLiteral("输入或浏览服务登录帐户"));

    rootLayout->addWidget(logonLocalSystemRadio_, 0);
    rootLayout->addWidget(logonDesktopInteractCheck_, 0);
    rootLayout->addWidget(logonAccountRadio_, 0);

    QFormLayout* formLayout = new QFormLayout();
    formLayout->setLabelAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    formLayout->setHorizontalSpacing(10);
    formLayout->setVerticalSpacing(8);

    QWidget* accountRowWidget = new QWidget(logonTabPage_);
    QHBoxLayout* accountRowLayout = new QHBoxLayout(accountRowWidget);
    accountRowLayout->setContentsMargins(0, 0, 0, 0);
    accountRowLayout->setSpacing(6);
    accountRowLayout->addWidget(logonAccountEdit_, 1);
    accountRowLayout->addWidget(logonBrowseButton_, 0);

    formLayout->addRow(QStringLiteral("帐户"), accountRowWidget);
    formLayout->addRow(QStringLiteral("密码"), logonPasswordEdit_);
    formLayout->addRow(QStringLiteral("确认密码"), logonConfirmPasswordEdit_);
    rootLayout->addLayout(formLayout, 1);

    connect(logonLocalSystemRadio_, &QRadioButton::toggled, this, [this](bool) { refreshLogonTabUiState(); });
    connect(logonAccountRadio_, &QRadioButton::toggled, this, [this](bool) { refreshLogonTabUiState(); });
    connect(logonBrowseButton_, &QToolButton::clicked, this, [this]() { browseLogonAccount(); });
    connect(logonReloadButton_, &QToolButton::clicked, this, [this]() { refreshSelectedService(); });
    connect(logonApplyButton_, &QToolButton::clicked, this, [this]() { applyLogonTabChanges(); });
}

void ServiceDock::initializeRecoveryTab()
{
    QVBoxLayout* rootLayout = new QVBoxLayout(recoveryTabPage_);
    rootLayout->setContentsMargins(8, 8, 8, 8);
    rootLayout->setSpacing(8);

    QWidget* actionRowWidget = new QWidget(recoveryTabPage_);
    QHBoxLayout* actionRowLayout = new QHBoxLayout(actionRowWidget);
    actionRowLayout->setContentsMargins(0, 0, 0, 0);
    actionRowLayout->setSpacing(6);
    recoveryReloadButton_ = buildPropertyActionButton(actionRowWidget, ":/Icon/process_refresh.svg", QStringLiteral("重载恢复页属性"));
    recoveryApplyButton_ = buildPropertyActionButton(actionRowWidget, ":/Icon/codeeditor_save.svg", QStringLiteral("应用恢复页修改"));
    actionRowLayout->addStretch(1);
    actionRowLayout->addWidget(recoveryReloadButton_);
    actionRowLayout->addWidget(recoveryApplyButton_);
    rootLayout->addWidget(actionRowWidget, 0);

    QFormLayout* formLayout = new QFormLayout();
    formLayout->setLabelAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    formLayout->setHorizontalSpacing(10);
    formLayout->setVerticalSpacing(8);

    recoveryFirstActionCombo_ = buildRecoveryActionCombo(recoveryTabPage_);
    recoverySecondActionCombo_ = buildRecoveryActionCombo(recoveryTabPage_);
    recoverySubsequentActionCombo_ = buildRecoveryActionCombo(recoveryTabPage_);
    recoveryResetDaysSpin_ = new QSpinBox(recoveryTabPage_);
    recoveryResetDaysSpin_->setRange(0, 3650);
    recoveryResetDaysSpin_->setSuffix(QStringLiteral(" 天"));
    recoveryRestartMinutesSpin_ = new QSpinBox(recoveryTabPage_);
    recoveryRestartMinutesSpin_->setRange(0, 1440);
    recoveryRestartMinutesSpin_->setSuffix(QStringLiteral(" 分钟"));
    recoveryFirstActionCombo_->setToolTip(
        QStringLiteral("服务第一次失败时执行的操作"));
    recoverySecondActionCombo_->setToolTip(
        QStringLiteral("服务第二次失败时执行的操作"));
    recoverySubsequentActionCombo_->setToolTip(
        QStringLiteral("服务第三次及以后失败时执行的操作"));
    recoveryResetDaysSpin_->setToolTip(
        QStringLiteral("经过这些天没有再失败后，把失败计数清零重新计算"));
    recoveryRestartMinutesSpin_->setToolTip(
        QStringLiteral("选择“重新启动服务”时，等待多久再重启"));
    recoveryFailureActionsFlagCheck_ = new QCheckBox(QStringLiteral("启用发生错误便停止时的操作"), recoveryTabPage_);
    recoveryFailureActionsFlagCheck_->setToolTip(
        QStringLiteral("服务以错误码异常结束时也触发上面的恢复操作；不勾选则只在崩溃时触发"));
    recoveryRebootMessageEdit_ = new QLineEdit(recoveryTabPage_);
    recoveryProgramEdit_ = new QLineEdit(recoveryTabPage_);
    recoveryArgumentsEdit_ = new QLineEdit(recoveryTabPage_);
    recoveryAppendFailCountCheck_ = new QCheckBox(QStringLiteral("将失败计数附加到命令行结尾 (/fail=%1%)"), recoveryTabPage_);
    recoveryAppendFailCountCheck_->setToolTip(
        QStringLiteral("运行恢复程序时，在命令行末尾附加当前是第几次失败"));
    recoveryBrowseProgramButton_ = buildPropertyActionButton(recoveryTabPage_, ":/Icon/process_open_folder.svg", QStringLiteral("浏览恢复动作程序路径"));

    QWidget* programRowWidget = new QWidget(recoveryTabPage_);
    QHBoxLayout* programRowLayout = new QHBoxLayout(programRowWidget);
    programRowLayout->setContentsMargins(0, 0, 0, 0);
    programRowLayout->setSpacing(6);
    programRowLayout->addWidget(recoveryProgramEdit_, 1);
    programRowLayout->addWidget(recoveryBrowseProgramButton_, 0);

    formLayout->addRow(QStringLiteral("第一次失败"), recoveryFirstActionCombo_);
    formLayout->addRow(QStringLiteral("第二次失败"), recoverySecondActionCombo_);
    formLayout->addRow(QStringLiteral("后续失败"), recoverySubsequentActionCombo_);
    formLayout->addRow(QStringLiteral("重置失败计数"), recoveryResetDaysSpin_);
    formLayout->addRow(QStringLiteral("重新启动服务"), recoveryRestartMinutesSpin_);
    formLayout->addRow(QStringLiteral("错误停止"), recoveryFailureActionsFlagCheck_);
    formLayout->addRow(QStringLiteral("重启消息"), recoveryRebootMessageEdit_);
    formLayout->addRow(QStringLiteral("程序"), programRowWidget);
    formLayout->addRow(QStringLiteral("命令行参数"), recoveryArgumentsEdit_);
    formLayout->addRow(QStringLiteral("失败计数"), recoveryAppendFailCountCheck_);
    rootLayout->addLayout(formLayout, 1);

    connect(recoveryFirstActionCombo_, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int) { refreshRecoveryTabUiState(); });
    connect(recoverySecondActionCombo_, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int) { refreshRecoveryTabUiState(); });
    connect(recoverySubsequentActionCombo_, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int) { refreshRecoveryTabUiState(); });
    connect(recoveryBrowseProgramButton_, &QToolButton::clicked, this, [this]() { browseRecoveryProgramPath(); });
    connect(recoveryReloadButton_, &QToolButton::clicked, this, [this]() { refreshSelectedService(); });
    connect(recoveryApplyButton_, &QToolButton::clicked, this, [this]() { applyRecoveryTabChanges(); });
}

void ServiceDock::initializeDependencyTab()
{
    QVBoxLayout* rootLayout = new QVBoxLayout(dependencyTabPage_);
    rootLayout->setContentsMargins(4, 4, 4, 4);
    rootLayout->setSpacing(4);

    dependencyEditor_ = new CodeEditorWidget(dependencyTabPage_);
    dependencyEditor_->setReadOnly(true);
    dependencyEditor_->setLocalizedText(QStringLiteral("未选择服务"));
    rootLayout->addWidget(dependencyEditor_, 1);
}

void ServiceDock::initializeAuditTab()
{
    QVBoxLayout* rootLayout = new QVBoxLayout(auditTabPage_);
    rootLayout->setContentsMargins(4, 4, 4, 4);
    rootLayout->setSpacing(4);

    auditEditor_ = new CodeEditorWidget(auditTabPage_);
    auditEditor_->setReadOnly(true);
    auditEditor_->setLocalizedText(QStringLiteral("未选择服务"));
    rootLayout->addWidget(auditEditor_, 1);
}

void ServiceDock::refreshGeneralTabUiState()
{
    if (generalStartTypeCombo_ == nullptr || generalDelayedAutoCheck_ == nullptr)
    {
        return;
    }

    const DWORD kStartTypeValue = static_cast<DWORD>(generalStartTypeCombo_->currentData().toULongLong());
    const bool kAutoStartType = kStartTypeValue == SERVICE_AUTO_START;
    if (!kAutoStartType)
    {
        generalDelayedAutoCheck_->setChecked(false);
    }
    generalDelayedAutoCheck_->setEnabled(kAutoStartType);
}

void ServiceDock::refreshLogonTabUiState()
{
    if (logonLocalSystemRadio_ == nullptr || logonAccountRadio_ == nullptr)
    {
        return;
    }

    const bool kUseLocalSystem = logonLocalSystemRadio_->isChecked();
    const bool kUseCustomAccount = logonAccountRadio_->isChecked();
    logonDesktopInteractCheck_->setEnabled(kUseLocalSystem);
    if (!kUseLocalSystem)
    {
        logonDesktopInteractCheck_->setChecked(false);
    }

    logonAccountEdit_->setEnabled(kUseCustomAccount);
    logonPasswordEdit_->setEnabled(kUseCustomAccount);
    logonConfirmPasswordEdit_->setEnabled(kUseCustomAccount);
    logonBrowseButton_->setEnabled(kUseCustomAccount);
}

void ServiceDock::refreshRecoveryTabUiState()
{
    const auto kActionTypeFromCombo = [](QComboBox* comboBox) -> SC_ACTION_TYPE
        {
            if (comboBox == nullptr)
            {
                return SC_ACTION_NONE;
            }
            return static_cast<SC_ACTION_TYPE>(comboBox->currentData().toInt());
        };

    const SC_ACTION_TYPE kFirstActionType = kActionTypeFromCombo(recoveryFirstActionCombo_);
    const SC_ACTION_TYPE kSecondActionType = kActionTypeFromCombo(recoverySecondActionCombo_);
    const SC_ACTION_TYPE kSubsequentActionType = kActionTypeFromCombo(recoverySubsequentActionCombo_);

    const bool kHasRestartAction =
        kFirstActionType == SC_ACTION_RESTART
        || kSecondActionType == SC_ACTION_RESTART
        || kSubsequentActionType == SC_ACTION_RESTART;
    const bool kHasRunProgramAction =
        kFirstActionType == SC_ACTION_RUN_COMMAND
        || kSecondActionType == SC_ACTION_RUN_COMMAND
        || kSubsequentActionType == SC_ACTION_RUN_COMMAND;
    const bool kHasRebootAction =
        kFirstActionType == SC_ACTION_REBOOT
        || kSecondActionType == SC_ACTION_REBOOT
        || kSubsequentActionType == SC_ACTION_REBOOT;

    recoveryRestartMinutesSpin_->setEnabled(kHasRestartAction);
    recoveryProgramEdit_->setEnabled(kHasRunProgramAction);
    recoveryArgumentsEdit_->setEnabled(kHasRunProgramAction);
    recoveryAppendFailCountCheck_->setEnabled(kHasRunProgramAction);
    recoveryBrowseProgramButton_->setEnabled(kHasRunProgramAction);
    recoveryRebootMessageEdit_->setEnabled(kHasRebootAction);
}

void ServiceDock::populateGeneralTab(const ServiceEntry& entry)
{
    const QSignalBlocker kStartTypeBlocker(generalStartTypeCombo_);
    const QSignalBlocker kDelayedBlocker(generalDelayedAutoCheck_);

    generalServiceNameEdit_->setText(entry.serviceNameText);
    generalDisplayNameEdit_->setText(entry.displayNameText);
    generalBinaryPathEdit_->setText(entry.commandLineText);
    generalDescriptionEdit_->setPlainText(entry.descriptionText);
    generalStateValueLabel_->setText(entry.stateText);
    generalPidValueLabel_->setText(entry.processId == 0 ? QStringLiteral("-") : QString::number(entry.processId));
    generalAccountValueLabel_->setText(entry.accountText);
    generalTypeValueLabel_->setText(entry.serviceTypeText);
    generalErrorControlValueLabel_->setText(entry.errorControlText);

    const int kStartTypeIndex = generalStartTypeCombo_->findData(static_cast<qulonglong>(entry.startTypeValue));
    generalStartTypeCombo_->setCurrentIndex(kStartTypeIndex >= 0 ? kStartTypeIndex : 0);
    generalDelayedAutoCheck_->setChecked(entry.delayedAutoStart);
    refreshGeneralTabUiState();
}

void ServiceDock::populateLogonTab(const ServiceEntry& entry)
{
    const QSignalBlocker kLocalSystemBlocker(logonLocalSystemRadio_);
    const QSignalBlocker kAccountBlocker(logonAccountRadio_);
    const QSignalBlocker kDesktopBlocker(logonDesktopInteractCheck_);

    const bool kUseLocalSystem = isLocalSystemAccountText(entry.accountText);
    logonLocalSystemRadio_->setChecked(kUseLocalSystem);
    logonAccountRadio_->setChecked(!kUseLocalSystem);
    logonDesktopInteractCheck_->setChecked((entry.serviceTypeValue & SERVICE_INTERACTIVE_PROCESS) != 0);
    logonAccountEdit_->setText(kUseLocalSystem ? QString() : entry.accountText);
    logonPasswordEdit_->clear();
    logonConfirmPasswordEdit_->clear();
    refreshLogonTabUiState();
}

void ServiceDock::populateRecoveryTab(const ServiceEntry& entry)
{
    ServiceRecoverySettings settings;
    QString errorText;
    const bool kQueryOk = queryServiceFailureSettings(entry.serviceNameText, &settings, &errorText);

    const QSignalBlocker kFirstBlocker(recoveryFirstActionCombo_);
    const QSignalBlocker kSecondBlocker(recoverySecondActionCombo_);
    const QSignalBlocker kSubsequentBlocker(recoverySubsequentActionCombo_);
    const QSignalBlocker kResetBlocker(recoveryResetDaysSpin_);
    const QSignalBlocker kRestartBlocker(recoveryRestartMinutesSpin_);
    const QSignalBlocker kFlagBlocker(recoveryFailureActionsFlagCheck_);
    const QSignalBlocker kAppendBlocker(recoveryAppendFailCountCheck_);

    const auto kSetComboByActionType = [](QComboBox* comboBox, SC_ACTION_TYPE actionType)
        {
            if (comboBox == nullptr)
            {
                return;
            }
            const int kTargetIndex = comboBox->findData(static_cast<int>(actionType));
            comboBox->setCurrentIndex(kTargetIndex >= 0 ? kTargetIndex : 0);
        };

    kSetComboByActionType(recoveryFirstActionCombo_, settings.firstActionType);
    kSetComboByActionType(recoverySecondActionCombo_, settings.secondActionType);
    kSetComboByActionType(recoverySubsequentActionCombo_, settings.subsequentActionType);
    recoveryResetDaysSpin_->setValue(settings.resetPeriodDays);
    recoveryRestartMinutesSpin_->setValue(settings.restartDelayMinutes);
    recoveryFailureActionsFlagCheck_->setChecked(settings.failureActionsFlag);
    recoveryRebootMessageEdit_->setText(settings.rebootMessageText);
    recoveryProgramEdit_->setText(settings.programPathText);
    recoveryArgumentsEdit_->setText(settings.programArgumentsText);
    recoveryAppendFailCountCheck_->setChecked(settings.appendFailureCount);
    if (!kQueryOk)
    {
        recoveryProgramEdit_->setPlaceholderText(errorText);
    }
    else
    {
        recoveryProgramEdit_->setPlaceholderText(QString());
    }
    refreshRecoveryTabUiState();
    markDetailPageRendered(recoveryTabPage_, entry.serviceNameText);
}

void ServiceDock::populateDependencyTab(const ServiceEntry& entry)
{
    if (dependencyEditor_ != nullptr)
    {
        dependencyEditor_->setLocalizedText(buildDependencyDetailText(entry));
    }
    markDetailPageRendered(dependencyTabPage_, entry.serviceNameText);
}

void ServiceDock::populateAuditTab(const ServiceEntry& entry)
{
    if (auditEditor_ != nullptr)
    {
        auditEditor_->setLocalizedText(buildAuditTabText(entry));
    }
    markDetailPageRendered(auditTabPage_, entry.serviceNameText);
}

void ServiceDock::updateDetailViewsFromSelection()
{
    const int kSelectedIndex = findServiceIndexByName(selectedServiceName());
    const bool kHasSelection = kSelectedIndex >= 0 && kSelectedIndex < static_cast<int>(serviceList_.size());
    QTimer* const kDetailRenderTimer = detailRenderTimerOf(this);

    detailUiSyncInProgress_ = true;
    if (!kHasSelection)
    {
        generalServiceNameEdit_->clear();
        generalDisplayNameEdit_->clear();
        generalBinaryPathEdit_->clear();
        generalDescriptionEdit_->clear();
        generalStateValueLabel_->setText(QStringLiteral("-"));
        generalPidValueLabel_->setText(QStringLiteral("-"));
        generalAccountValueLabel_->setText(QStringLiteral("-"));
        generalTypeValueLabel_->setText(QStringLiteral("-"));
        generalErrorControlValueLabel_->setText(QStringLiteral("-"));

        logonLocalSystemRadio_->setChecked(true);
        logonAccountEdit_->clear();
        logonPasswordEdit_->clear();
        logonConfirmPasswordEdit_->clear();
        logonDesktopInteractCheck_->setChecked(false);

        recoveryFirstActionCombo_->setCurrentIndex(0);
        recoverySecondActionCombo_->setCurrentIndex(0);
        recoverySubsequentActionCombo_->setCurrentIndex(0);
        recoveryResetDaysSpin_->setValue(0);
        recoveryRestartMinutesSpin_->setValue(1);
        recoveryFailureActionsFlagCheck_->setChecked(false);
        recoveryRebootMessageEdit_->clear();
        recoveryProgramEdit_->clear();
        recoveryArgumentsEdit_->clear();
        recoveryAppendFailCountCheck_->setChecked(false);

        if (dependencyEditor_ != nullptr) { dependencyEditor_->setLocalizedText(QStringLiteral("未选择服务")); }
        if (auditEditor_ != nullptr) { auditEditor_->setLocalizedText(QStringLiteral("未选择服务")); }

        // When no item is selected, clear the render markers and cancel pending deferred renders.
        markDetailPageRendered(recoveryTabPage_, QString());
        markDetailPageRendered(dependencyTabPage_, QString());
        markDetailPageRendered(auditTabPage_, QString());
        if (kDetailRenderTimer != nullptr)
        {
            kDetailRenderTimer->stop();
        }
    }
    else
    {
        const ServiceEntry& entry = serviceList_[static_cast<std::size_t>(kSelectedIndex)];
        // The General and Logon tabs are populated entirely from memory cache without SCM round-trips; continue synchronous backfill.
        populateGeneralTab(entry);
        populateLogonTab(entry);

        // The Recovery, Dependencies, and Audit pages must re-query the SCM each time:
        // First invalidate all render markers (cached data may have been refreshed/overwritten),
        // then let the single-shot timer debounce and render only the currently visible page.
        markDetailPageRendered(recoveryTabPage_, QString());
        markDetailPageRendered(dependencyTabPage_, QString());
        markDetailPageRendered(auditTabPage_, QString());
        if (kDetailRenderTimer != nullptr)
        {
            kDetailRenderTimer->start(kDetailRenderDebounceMs);
        }
    }
    detailUiSyncInProgress_ = false;

    refreshGeneralTabUiState();
    refreshLogonTabUiState();
    refreshRecoveryTabUiState();

    const bool kEnableApplyButtons = kHasSelection
        && serviceList_[static_cast<std::size_t>(kSelectedIndex)].scmRecordPresent;
    if (generalApplyButton_ != nullptr) { generalApplyButton_->setEnabled(kEnableApplyButtons); }
    if (generalReloadButton_ != nullptr) { generalReloadButton_->setEnabled(kEnableApplyButtons); }
    if (logonApplyButton_ != nullptr) { logonApplyButton_->setEnabled(kEnableApplyButtons); }
    if (logonReloadButton_ != nullptr) { logonReloadButton_->setEnabled(kEnableApplyButtons); }
    if (recoveryApplyButton_ != nullptr) { recoveryApplyButton_->setEnabled(kEnableApplyButtons); }
    if (recoveryReloadButton_ != nullptr) { recoveryReloadButton_->setEnabled(kEnableApplyButtons); }
}

void ServiceDock::browseLogonAccount()
{
    bool ok = false;
    const QString kAccountText = QInputDialog::getText(
        this,
        QStringLiteral("输入服务登录帐户"),
        QStringLiteral("帐户名"),
        QLineEdit::Normal,
        logonAccountEdit_->text(),
        &ok);
    if (ok)
    {
        logonAccountEdit_->setText(kAccountText.trimmed());
    }
}

void ServiceDock::browseRecoveryProgramPath()
{
    const QString kFilePath = QFileDialog::getOpenFileName(
        this,
        QStringLiteral("选择恢复程序"),
        recoveryProgramEdit_->text(),
        QStringLiteral("可执行文件 (*.exe *.cmd *.bat *.com);;所有文件 (*.*)"));
    if (!kFilePath.trimmed().isEmpty())
    {
        recoveryProgramEdit_->setText(QDir::toNativeSeparators(kFilePath));
    }
}
