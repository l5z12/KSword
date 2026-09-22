#include "TaskbarSettingsDialog.h"

#include "TaskbarNotificationService.h"
#include "TaskbarRestartCoordinator.h"

#include <QCheckBox>
#include <QCoreApplication>
#include <QDialogButtonBox>
#include <QFont>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QPushButton>
#include <QSignalBlocker>
#include <QSpinBox>
#include <QTimer>
#include <QVBoxLayout>

TaskbarSettingsDialog::TaskbarSettingsDialog(TaskbarNotificationService* notificationService, QWidget* parent)
    : QDialog(parent)
    , notificationService_(notificationService)
    , clipboardCheckBox_(nullptr)
    , deviceCheckBox_(nullptr)
    , earthquakeCheckBox_(nullptr)
    , notificationDurationSpinBox_(nullptr)
    , sourceStatusLabel_(nullptr)
    , testEarthquakeButton_(nullptr)
    , restartTaskbarButton_(nullptr)
    , refreshTimer_(nullptr)
{
    // The dialog is a non-modal tool window that serves the Taskbar for all screens centrally, rather than saving per-screen settings individually.
    setWindowTitle(QStringLiteral("Taskbar 通知设置"));
    setWindowFlags(windowFlags() | Qt::Tool);
    setModal(false);
    setMinimumWidth(430);
    setStyleSheet(R"(
        QDialog { background: #111820; color: #dff8ff; }
        QGroupBox { border: 1px solid #31566a; margin-top: 12px; padding: 10px; color: #91dfff; }
        QGroupBox::title { subcontrol-origin: margin; left: 9px; padding: 0 4px; }
        QCheckBox { spacing: 7px; padding: 3px; color: #dff8ff; }
        QCheckBox:disabled { color: #6f8790; }
        QLabel { color: #dff8ff; }
        QSpinBox { background: #0b1015; border: 1px solid #4fbed9; border-radius: 3px; padding: 3px 6px; color: #e9fbff; }
        QSpinBox:focus { border-color: #91dfff; }
        QPushButton { background: #153542; border: 1px solid #4fbed9; border-radius: 3px; padding: 6px 10px; color: #e9fbff; }
        QPushButton:hover { background: #1b4a5d; }
        QLabel#sourceStatus { color: #a8c9d2; background: #0b1015; border: 1px solid #263e49; padding: 8px; }
    )");

    QVBoxLayout* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(14, 14, 14, 14);
    rootLayout->setSpacing(10);

    QGroupBox* notificationGroup = new QGroupBox(QStringLiteral("通知"), this);
    QVBoxLayout* notificationLayout = new QVBoxLayout(notificationGroup);
    notificationLayout->setSpacing(5);
    clipboardCheckBox_ = new QCheckBox(QStringLiteral("剪贴板文字变化"), notificationGroup);
    deviceCheckBox_ = new QCheckBox(QStringLiteral("设备接入、移除与拓扑变化"), notificationGroup);
    earthquakeCheckBox_ = new QCheckBox(QStringLiteral("地震预警"), notificationGroup);
    notificationLayout->addWidget(clipboardCheckBox_);
    notificationLayout->addWidget(deviceCheckBox_);
    notificationLayout->addWidget(earthquakeCheckBox_);

    // Message retention time is in seconds, consistent with the service layer range, and persisted in the configuration file.
    QHBoxLayout* durationLayout = new QHBoxLayout();
    QLabel* durationLabel = new QLabel(QStringLiteral("消息滞留时间"), notificationGroup);
    notificationDurationSpinBox_ = new QSpinBox(notificationGroup);
    notificationDurationSpinBox_->setRange(1, 60);
    notificationDurationSpinBox_->setSuffix(QStringLiteral(" 秒"));
    notificationDurationSpinBox_->setToolTip(QStringLiteral("设置每条普通消息正文完整显示的时间，范围为 1 到 60 秒。"));
    durationLayout->addWidget(durationLabel);
    durationLayout->addWidget(notificationDurationSpinBox_);
    durationLayout->addStretch(1);
    notificationLayout->addLayout(durationLayout);
    rootLayout->addWidget(notificationGroup);

    QGroupBox* earthquakeGroup = new QGroupBox(QStringLiteral("地震预警诊断"), this);
    QVBoxLayout* earthquakeLayout = new QVBoxLayout(earthquakeGroup);
    sourceStatusLabel_ = new QLabel(earthquakeGroup);
    sourceStatusLabel_->setObjectName(QStringLiteral("sourceStatus"));
    sourceStatusLabel_->setWordWrap(true);
    sourceStatusLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    earthquakeLayout->addWidget(sourceStatusLabel_);

    QHBoxLayout* testLayout = new QHBoxLayout();
    testLayout->addStretch(1);
    testEarthquakeButton_ = new QPushButton(QStringLiteral("插播测试地震预警"), earthquakeGroup);
    testEarthquakeButton_->setToolTip(QStringLiteral("立即显示十秒测试预警，用于验证红色闪烁主题和队列抢占。"));
    testLayout->addWidget(testEarthquakeButton_);
    earthquakeLayout->addLayout(testLayout);
    rootLayout->addWidget(earthquakeGroup);

    QGroupBox* taskbarGroup = new QGroupBox(QStringLiteral("Taskbar"), this);
    QVBoxLayout* taskbarLayout = new QVBoxLayout(taskbarGroup);
    QLabel* restartDescriptionLabel = new QLabel(
        QStringLiteral("切换系统输出设备后，可重启 Taskbar 重新建立音频采集。"),
        taskbarGroup);
    restartDescriptionLabel->setWordWrap(true);
    taskbarLayout->addWidget(restartDescriptionLabel);

    QHBoxLayout* restartLayout = new QHBoxLayout();
    restartLayout->addStretch(1);
    restartTaskbarButton_ = new QPushButton(QStringLiteral("重启 Taskbar"), taskbarGroup);
    restartTaskbarButton_->setIcon(QIcon(QStringLiteral(":/Icon/Resource/svg/system/refresh_1_line.svg")));
    restartTaskbarButton_->setToolTip(
        QStringLiteral("退出当前 Taskbar，等待一秒释放 AppBar 资源后自动重新启动。"));
    restartLayout->addWidget(restartTaskbarButton_);
    taskbarLayout->addLayout(restartLayout);
    rootLayout->addWidget(taskbarGroup);

    QDialogButtonBox* buttons = new QDialogButtonBox(QDialogButtonBox::Close, this);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::hide);
    rootLayout->addWidget(buttons);

    // Checkboxes directly drive a single global service; any changes made via the dialog on any screen are synchronized to all windows.
    connect(clipboardCheckBox_, &QCheckBox::toggled, this, &TaskbarSettingsDialog::applyClipboardSetting);
    connect(deviceCheckBox_, &QCheckBox::toggled, this, &TaskbarSettingsDialog::applyDeviceSetting);
    connect(earthquakeCheckBox_, &QCheckBox::toggled, this, &TaskbarSettingsDialog::applyEarthquakeSetting);
    connect(notificationDurationSpinBox_, qOverload<int>(&QSpinBox::valueChanged), this,
        &TaskbarSettingsDialog::applyNotificationDuration);
    connect(testEarthquakeButton_, &QPushButton::clicked, this, [this]() {
        if (notificationService_ != nullptr)
        {
            notificationService_->injectTestEarthquake();
        }
    });
    connect(restartTaskbarButton_, &QPushButton::clicked, this, &TaskbarSettingsDialog::restartTaskbar);

    if (notificationService_ != nullptr)
    {
        connect(notificationService_, &TaskbarNotificationService::settingsChanged, this,
            &TaskbarSettingsDialog::refreshFromService);
        connect(notificationService_, &TaskbarNotificationService::sourceStatusesChanged, this,
            &TaskbarSettingsDialog::refreshSourceDiagnostics);
    }

    // Refreshes the connection status once per second while the dialog is visible, providing real-time diagnostics without adding polling overhead to the WebSocket thread.
    refreshTimer_ = new QTimer(this);
    refreshTimer_->setInterval(1000);
    connect(refreshTimer_, &QTimer::timeout, this, &TaskbarSettingsDialog::refreshSourceDiagnostics);
    refreshTimer_->start();
    refreshFromService();
    refreshSourceDiagnostics();
}

void TaskbarSettingsDialog::applyClipboardSetting(bool enabled)
{
    // The checkbox state is written only to the global service; persistence details are handled uniformly by the service.
    if (notificationService_ != nullptr)
    {
        notificationService_->setClipboardNotificationsEnabled(enabled);
    }
}

void TaskbarSettingsDialog::applyDeviceSetting(bool enabled)
{
    // Device listening remains active, but events received after the switch is turned off are not added to the display queue.
    if (notificationService_ != nullptr)
    {
        notificationService_->setDeviceNotificationsEnabled(enabled);
    }
}

void TaskbarSettingsDialog::applyEarthquakeSetting(bool enabled)
{
    // Disabling the earthquake switch immediately exits the red alert display, but the receiving client maintains the connection to allow quick restoration when re-enabled.
    if (notificationService_ != nullptr)
    {
        notificationService_->setEarthquakeNotificationsEnabled(enabled);
    }
}

void TaskbarSettingsDialog::applyNotificationDuration(int seconds)
{
    // Only pass the setting value to the global service; configuration file writes and the current carousel timer are handled uniformly by the service.
    if (notificationService_ != nullptr)
    {
        notificationService_->setNotificationDurationSeconds(seconds);
    }
}

void TaskbarSettingsDialog::refreshFromService()
{
    // Block signals to prevent setChecked from writing the same QSettings value again during the refresh phase.
    if (notificationService_ == nullptr)
    {
        return;
    }
    const QSignalBlocker kClipboardBlocker(clipboardCheckBox_);
    const QSignalBlocker kDeviceBlocker(deviceCheckBox_);
    const QSignalBlocker kEarthquakeBlocker(earthquakeCheckBox_);
    const QSignalBlocker kDurationBlocker(notificationDurationSpinBox_);
    clipboardCheckBox_->setChecked(notificationService_->clipboardNotificationsEnabled());
    deviceCheckBox_->setChecked(notificationService_->deviceNotificationsEnabled());
    earthquakeCheckBox_->setChecked(notificationService_->earthquakeNotificationsEnabled());
    notificationDurationSpinBox_->setValue(notificationService_->notificationDurationSeconds());
}

void TaskbarSettingsDialog::refreshSourceDiagnostics()
{
    // Compress all source statuses into multi-line text; after connection succeeds, display the latest packet time and measured RTT.
    if (notificationService_ == nullptr)
    {
        sourceStatusLabel_->setText(QStringLiteral("地震预警服务不可用。"));
        return;
    }

    const QList<TaskbarEarthquakeSourceStatus> kStatuses = notificationService_->sourceStatuses();
    if (kStatuses.isEmpty())
    {
        sourceStatusLabel_->setText(QStringLiteral("正在初始化地震预警来源。"));
        return;
    }

    QStringList lines;
    for (const TaskbarEarthquakeSourceStatus& status : kStatuses)
    {
        QString state;
        if (!status.enabled)
        {
            state = QStringLiteral("未启用");
        }
        else if (!status.connected)
        {
            state = status.everConnected ? QStringLiteral("重连中") : QStringLiteral("未连接");
        }
        else if (status.lastMessageAgeMs == 0)
        {
            state = QStringLiteral("已连接，等待数据");
        }
        else
        {
            state = QStringLiteral("已连接，%1 秒前收到").arg(status.lastMessageAgeMs / 1000);
            if (status.latencyMs > 0)
            {
                state += QStringLiteral("，延迟 %1 ms").arg(status.latencyMs);
            }
        }
        lines.push_back(QStringLiteral("%1: %2").arg(status.name, state));
    }
    sourceStatusLabel_->setText(lines.join(QLatin1Char('\n')));
}

void TaskbarSettingsDialog::restartTaskbar()
{
    // Exit only if the replacement instance has started successfully; the replacement instance waits for this process to fully release the AppBar.
    if (!taskbar_restart_coordinator::scheduleAfterCurrentProcessExit())
    {
        return;
    }

    // Prevent users from triggering multiple new instances via repeated clicks, and provide text feedback indicating the restart has started.
    restartTaskbarButton_->setEnabled(false);
    restartTaskbarButton_->setText(QStringLiteral("正在重启..."));
    QCoreApplication::quit();
}
