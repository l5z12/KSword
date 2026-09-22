#include "MainWindow.h"
#include "kernel_dock/KernelDock.h"
#include "framework/PrivilegeElevationPrompt.h"
#include <QTimer>
#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QVBoxLayout>
#include <QLabel>
#include <QPointer>
#include <QPushButton>
#include <QSizePolicy>
#include <QDialog>
#include <QMessageBox>
#include <QProcess>
#pragma warning(disable: 4996)
#include "Framework.h"
#include "../../shared/ark_client/ArkDriverClient.h"
#include "kernel_dock/KernelDock.CallbackPromptManager.h"
#include "Theme.h"
#include "../../shared/KswordArkLogProtocol.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <shellapi.h>
#include <sddl.h>
#include <winternl.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <TlHelp32.h>

#include "MainWindow.DriverServiceBackendSupport.h"
#include "MainWindow.DriverServiceConstants.h"
#include "MainWindow.Win32PrivilegesSupport.h"

using namespace ksword::ui::main_window;

void MainWindow::startR0DriverLogPoller()
{
    if (r0DriverLogPollerRunning_.exchange(true))
    {
        return;
    }

    try
    {
        r0DriverLogPollerThread_ = std::make_unique<std::thread>([this]()
            {
                runR0DriverLogPollerLoop();
            });
    }
    catch (...)
    {
        r0DriverLogPollerRunning_.store(false);
        r0DriverLogPollerThread_.reset();

        KLogEvent& logEvent = sharedR0DriverLogEvent();
        err << logEvent << "[MainWindow][R0Log] 轮询线程创建失败。" << eol;
    }
}

void MainWindow::prepareR0DriverServiceStop()
{
    // Unified cleanup entry before driver unload:
    // Inputs: None.
    // Processing:
    // - Close log/callback wait handles held long-term by this process first.
    // - Then attempt to notify the driver to cancel pending decision callbacks, stop, and clear file monitoring runtime state.
    // - These IOCTL failures do not block SCM stop, as the service may already be stopping or the old driver may not support the corresponding capabilities.
    // Returns: No return value; cleanup results are logged only, while the actual driver stop result is applied after being re-injected by the background SCM task.
    stopR0RuntimeConsumersBeforeServiceStop();

    const auto kLogBestEffortCleanupResult =
        [](const char* operationName, const ksword::ark::IoResult& ioResult)
        {
            KLogEvent cleanupEvent;
            if (ioResult.ok)
            {
                info << cleanupEvent
                    << "[MainWindow][R0] 停驱前清理完成: "
                    << operationName
                    << ", "
                    << ioResult.message
                    << eol;
                return;
            }

            const DWORD kWin32Error = static_cast<DWORD>(ioResult.win32Error);
            if (kWin32Error == ERROR_FILE_NOT_FOUND ||
                kWin32Error == ERROR_PATH_NOT_FOUND ||
                kWin32Error == ERROR_INVALID_HANDLE ||
                kWin32Error == ERROR_DEVICE_NOT_CONNECTED ||
                kWin32Error == ERROR_SERVICE_NOT_ACTIVE)
            {
                dbg << cleanupEvent
                    << "[MainWindow][R0] 停驱前清理跳过: "
                    << operationName
                    << ", error="
                    << kWin32Error
                    << ", message="
                    << ioResult.message
                    << eol;
                return;
            }

            warn << cleanupEvent
                << "[MainWindow][R0] 停驱前清理失败但继续停驱: "
                << operationName
                << ", error="
                << kWin32Error
                << ", message="
                << ioResult.message
                << eol;
        };

    const ksword::ark::DriverClient kDriverClient;
    kLogBestEffortCleanupResult(
        "cancel-pending-callback-decisions",
        kDriverClient.cancelAllPendingCallbackDecisions());
    kLogBestEffortCleanupResult(
        "file-monitor-stop",
        kDriverClient.controlFileMonitor(KSWORD_ARK_FILE_MONITOR_ACTION_STOP));
    kLogBestEffortCleanupResult(
        "file-monitor-clear",
        kDriverClient.controlFileMonitor(KSWORD_ARK_FILE_MONITOR_ACTION_CLEAR));
}

void MainWindow::stopR0RuntimeConsumersBeforeServiceStop()
{
    // Before manually unloading the R0 driver, all driver device handles held by this process must be reconciled:
    // - The log polling thread keeps \\.\KswordARKLog open for an extended period.
    // - The worker of the callback prompt manager holds the overlapped wait handle for an extended period.
    // - If these handles are not closed first, the SCM may hang indefinitely in STOP_PENDING when stopping the kernel driver.
    // Inputs: None.
    // Processing: Stop R0 consumers following the window close resource release order, but do not delete the global manager object.
    // Return: None; all sub-module stop functions are idempotent best-effort.
    stopR0DriverLogPoller();

    if (CallbackPromptManager* callbackPromptManager = CallbackPromptManager::globalManager())
    {
        callbackPromptManager->stop();
    }
}

void MainWindow::startR0RuntimeConsumersAfterServiceStart()
{
    // Restores this process's runtime consumer after R0 startup or confirmation of running:
    // - The log polling thread is responsible for forwarding R0 logs to application logs.
    // - The callback popup manager is responsible for long-term waiting for the R0 callback decision event.
    // Inputs: None.
    // Processing: Reuse idempotent start semantics across modules to avoid redundant thread startup.
    // Return: No return value; startup failure only logs, does not affect main flow status query.
    if (!r0DriverServiceRunning_)
    {
        // During startup, background consumers such as log rotation or callback waiters must not repeatedly probe a disabled device.
        // ArkDriverClient provides a clear enablement prompt only when the user actually triggers the R0 feature.
        return;
    }

    // Blue screen diagnostics resources can only be uploaded after successful installation of diagnostics to avoid triggering uninitialized BGP paths during default startup.
    installBugcheckDiagnosticsAfterServiceStart();
    startR0DriverLogPoller();

    if (CallbackPromptManager* callbackPromptManager = CallbackPromptManager::ensureGlobalManager(this))
    {
        callbackPromptManager->setHostWindow(this);
        callbackPromptManager->start();
    }

    refreshR0DynDataAfterServiceStart();
}

void MainWindow::refreshR0DynDataAfterServiceStart()
{
    // Immediately after the R0 service starts, send the local PDB profile pack to the driver:
    // - Reuse KernelDock's existing profile matching, v3 typed item parsing, and APPLY_DYN_PROFILE_EX;
    // - No longer forcibly create the KernelDock UI for background refreshes to avoid heavy page loading during startup.
    // - When KernelDock is not yet initialized, only record the refresh flag; re-run after the kernel page is opened for the first time.
    // - Failure only logs to KernelDock; R0 functionality still has runtime offsets on the driver side as a fallback.
    QTimer::singleShot(0, this, [this]() {
        KLogEvent logEvent;
        if (dockKernel_ == nullptr || kernelWidget_ == nullptr)
        {
            pendingR0DynDataRefresh_ = true;
            info << logEvent
                << "[MainWindow][R0] DynData 自动刷新已延后：KernelDock UI 尚未初始化。"
                << eol;
            return;
        }
        if (!dockKernel_->property("ks_lazy_initialized").toBool() ||
            dockKernel_->property("ks_lazy_initializing").toBool())
        {
            pendingR0DynDataRefresh_ = true;
            info << logEvent
                << "[MainWindow][R0] DynData 自动刷新已延后：KernelDock 正在惰性初始化。"
                << eol;
            return;
        }

        info << logEvent
            << "[MainWindow][R0] 驱动已装载，开始自动刷新 DynData profile。"
            << eol;
        kernelWidget_->requestDynDataRefresh();
        });
}

void MainWindow::stopR0DriverLogPoller()
{
    r0DriverLogPollerRunning_.store(false);
    if (r0DriverLogPollerThread_ != nullptr && r0DriverLogPollerThread_->joinable())
    {
        // The worker owns a synchronous log-device ReadFile; cancel it before joining.
        (void)::CancelSynchronousIo(r0DriverLogPollerThread_->native_handle());
        r0DriverLogPollerThread_->join();
    }
    r0DriverLogPollerThread_.reset();
}

void MainWindow::runR0DriverLogPollerLoop()
{
    ksword::ark::DriverHandle logDeviceHandle;
    std::string pendingPayloadText;
    pendingPayloadText.reserve(2048);
    bool waitingDeviceLogged = false;
    static const std::string kEndMarkerText = KSWORD_ARK_LOG_END_MARKER;
    const ksword::ark::DriverClient kDriverClient;

    KLogEvent& logEvent = sharedR0DriverLogEvent();
    info << logEvent << "[MainWindow][R0Log] 轮询线程已启动。" << eol;

    while (r0DriverLogPollerRunning_.load())
    {
        if (!logDeviceHandle.isValid())
        {
            // Use `ArkDriverClient` to uniformly open the KswordARK log device, preventing `mainWindow` from
            // scattering direct `CreateFileW(\\.\KswordARKLog)` calls; the return value remains an RAII handle.
            logDeviceHandle = kDriverClient.open(GENERIC_READ);

            if (!logDeviceHandle.isValid())
            {
                if (!waitingDeviceLogged)
                {
                    waitingDeviceLogged = true;
                    dbg << logEvent << "[MainWindow][R0Log] 等待日志设备上线：" << "path=\\\\.\\KswordARKLog" << eol;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(kR0LogConnectRetrySleepMs));
                continue;
            }

            waitingDeviceLogged = false;
            info << logEvent << "[MainWindow][R0Log] 已连接驱动日志设备。" << eol;
        }

        char readBuffer[1024] = { 0 };
        DWORD bytesRead = 0;
        if (::ReadFile(logDeviceHandle.native(), readBuffer, static_cast<DWORD>(sizeof(readBuffer)), &bytesRead, nullptr) != FALSE)
        {
            if (bytesRead == 0U)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(kR0LogIdlePollSleepMs));
                continue;
            }

            pendingPayloadText.append(readBuffer, bytesRead);
            while (true)
            {
                const std::size_t kMarkerPosition = pendingPayloadText.find(kEndMarkerText);
                if (kMarkerPosition == std::string::npos)
                {
                    break;
                }

                const std::string kRecordText = pendingPayloadText.substr(0, kMarkerPosition);
                pendingPayloadText.erase(0, kMarkerPosition + kEndMarkerText.size());
                dispatchR0DriverLogRecord(kRecordText);
            }
            continue;
        }

        const DWORD kReadError = ::GetLastError();
        if (kReadError == ERROR_NO_MORE_ITEMS ||
            kReadError == ERROR_NO_DATA ||
            kReadError == ERROR_HANDLE_EOF)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(kR0LogIdlePollSleepMs));
            continue;
        }

        warn << logEvent
            << "[MainWindow][R0Log] 读取日志设备失败, error="
            << kReadError
            << ", 将重新连接。"
            << eol;
        logDeviceHandle.reset();
        std::this_thread::sleep_for(std::chrono::milliseconds(kR0LogConnectRetrySleepMs));
    }

    logDeviceHandle.reset();

    info << logEvent << "[MainWindow][R0Log] 轮询线程已退出。" << eol;
}

void MainWindow::dispatchR0DriverLogRecord(const std::string& logRecordText)
{
    if (logRecordText.empty())
    {
        return;
    }

    std::string payloadText = logRecordText;
    LogStream* outputStream = &info;
    std::size_t prefixLength = 0U;

    if (startsWithLiteral(payloadText, kR0LogPrefixDebug))
    {
        outputStream = &dbg;
        prefixLength = std::strlen(kR0LogPrefixDebug);
    }
    else if (startsWithLiteral(payloadText, kR0LogPrefixInfo))
    {
        outputStream = &info;
        prefixLength = std::strlen(kR0LogPrefixInfo);
    }
    else if (startsWithLiteral(payloadText, kR0LogPrefixWarn))
    {
        outputStream = &warn;
        prefixLength = std::strlen(kR0LogPrefixWarn);
    }
    else if (startsWithLiteral(payloadText, kR0LogPrefixError))
    {
        outputStream = &err;
        prefixLength = std::strlen(kR0LogPrefixError);
    }
    else if (startsWithLiteral(payloadText, kR0LogPrefixFatal))
    {
        outputStream = &fatal;
        prefixLength = std::strlen(kR0LogPrefixFatal);
    }

    if (prefixLength > 0U && payloadText.size() >= prefixLength)
    {
        payloadText.erase(0, prefixLength);
    }

    KLogEvent& logEvent = sharedR0DriverLogEvent();
    (*outputStream) << logEvent << "[R0] " << payloadText << eol;
}

void MainWindow::showR0FatalError(
    const QString& stageText,
    const unsigned long errorCode,
    const QString& detailText)
{
    const DWORD kWin32ErrorCode = static_cast<DWORD>(errorCode);
    QString messageText = stageText.trimmed();
    if (kWin32ErrorCode != ERROR_SUCCESS)
    {
        messageText += QStringLiteral("\n\n错误码：%1").arg(kWin32ErrorCode);
        messageText += QStringLiteral("\n系统信息：%1").arg(formatWin32ErrorText(kWin32ErrorCode));
    }
    if (!detailText.trimmed().isEmpty())
    {
        messageText += QStringLiteral("\n\n详细信息：\n%1").arg(detailText.trimmed());
    }

    KLogEvent logEvent;
    fatal << logEvent
        << "[MainWindow][R0][Fatal] stage=" << stageText.toStdString()
        << ", error=" << kWin32ErrorCode
        << ", detail=" << detailText.toStdString()
        << eol;

    QMessageBox::critical(this, QStringLiteral("R0 操作失败"), messageText);
}

bool MainWindow::isR0DriverSignatureFailure(const unsigned long errorCode) const
{
    return errorCode == ERROR_INVALID_IMAGE_HASH ||
        errorCode == ERROR_DRIVER_BLOCKED;
}

bool MainWindow::queryR0DriverServiceRunning(bool& runningOut, const bool fatalOnError)
{
    runningOut = false;

    ScopedServiceHandle scmHandle(::OpenSCManagerW(nullptr, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT));
    if (!scmHandle.isValid())
    {
        const DWORD kScmError = ::GetLastError();
        if (fatalOnError)
        {
            if (ks::ui::promptForPrivilegeFailure(this, QStringLiteral("查询 R0 服务状态"), kScmError))
            {
                return false;
            }
            showR0FatalError(
                QStringLiteral("查询 KswordARK 驱动服务状态失败：无法连接服务控制管理器。"),
                kScmError);
        }
        return false;
    }

    ScopedServiceHandle serviceHandle(::OpenServiceW(
        scmHandle.get(),
        kR0DriverServiceName,
        SERVICE_QUERY_STATUS));
    if (!serviceHandle.isValid())
    {
        const DWORD kOpenError = ::GetLastError();
        if (kOpenError == ERROR_SERVICE_DOES_NOT_EXIST)
        {
            runningOut = false;
            return true;
        }
        if (fatalOnError)
        {
            if (ks::ui::promptForPrivilegeFailure(this, QStringLiteral("查询 R0 服务状态"), kOpenError))
            {
                return false;
            }
            showR0FatalError(
                QStringLiteral("查询 KswordARK 驱动服务状态失败：无法打开服务。"),
                kOpenError,
                QStringLiteral("目标服务名：%1").arg(QString::fromWCharArray(kR0DriverServiceName)));
        }
        return false;
    }

    SERVICE_STATUS_PROCESS status{};
    DWORD queryError = ERROR_SUCCESS;
    if (!queryServiceStatus(serviceHandle.get(), status, queryError))
    {
        if (fatalOnError)
        {
            if (ks::ui::promptForPrivilegeFailure(this, QStringLiteral("查询 R0 服务状态"), queryError))
            {
                return false;
            }
            showR0FatalError(
                QStringLiteral("查询 KswordARK 驱动服务状态失败：读取服务状态失败。"),
                queryError);
        }
        return false;
    }

    runningOut = isRunningLikeServiceState(status.dwCurrentState);
    return true;
}

bool MainWindow::stopR0DriverService(const bool suppressErrorDialog)
{
    // Purpose:
    // - Input suppressErrorDialog: true indicates silent driver unload; on failure, only log without showing an error dialog;
    // - Handling: UI thread only performs 'converging driver handles held by this process + dispatching'; SCM stop/wait/delete of the entire segment is delegated to the thread pool.
    //         SCM can wait up to 30 seconds in STOP_PENDING; blocking the UI thread would freeze the interface, preventing even repainting.
    // - Return: true indicates the driver stop request has been dispatched; the actual stop conclusion is applied by the callback that returns to the UI thread.
    if (gR0ServiceOperationInFlight.exchange(true))
    {
        // An R0 start/stop operation is already executing in the background; duplicate requests are discarded to avoid concurrent operations on the same SCM service.
        return false;
    }

    // Handle convergence before driver unload must remain on the UI thread: it needs to stop the log polling thread and the
    // callback popup manager. These objects' lifetimes are held by the main window and must not be touched on a worker thread.
    prepareR0DriverServiceStop();
    if (r0StatusButton_ != nullptr)
    {
        r0StatusButton_->setEnabled(false);
    }

    // guardedSelf usage: Background tasks may outlive the main window; verify lifecycle before re-entrance.
    const QPointer<MainWindow> kGuardedSelf(this);
    dispatchR0ServiceStopToWorker(
        [kGuardedSelf, suppressErrorDialog](const R0ServiceOperationOutcome& operationOutcome)
        {
            gR0ServiceOperationInFlight.store(false);
            if (kGuardedSelf == nullptr)
            {
                return;
            }
            if (kGuardedSelf->r0StatusButton_ != nullptr)
            {
                kGuardedSelf->r0StatusButton_->setEnabled(true);
            }

            if (operationOutcome.succeeded)
            {
                kGuardedSelf->r0DriverServiceRunning_ = false;
                // This installation binds only to the current kernel driver image; the entry's configuration visibility is restored upon successful service unloading.
                kGuardedSelf->bugcheckDiagnosticsInstalledForSession_ = false;
                kGuardedSelf->bugcheckDiagnosticsEntryRequestedForSession_ = false;
                kGuardedSelf->updateBugcheckDiagnosticsEntryVisibility();
                KLogEvent logEvent;
                info << logEvent << "[MainWindow][R0] 已停止并删除 KswordARK 驱动服务。" << eol;
                kGuardedSelf->refreshPrivilegeStatusButtons();
                return;
            }

            if (suppressErrorDialog)
            {
                KLogEvent logEvent;
                err << logEvent
                    << "[MainWindow][R0][AutoStop] stage="
                    << operationOutcome.stageText.toStdString()
                    << ", error="
                    << operationOutcome.errorCode
                    << ", detail="
                    << operationOutcome.detailText.toStdString()
                    << eol;
            }
            else if (!ks::ui::promptForPrivilegeFailure(
                kGuardedSelf.data(),
                QStringLiteral("卸载 R0"),
                operationOutcome.errorCode))
            {
                kGuardedSelf->showR0FatalError(
                    operationOutcome.stageText,
                    operationOutcome.errorCode,
                    operationOutcome.detailText);
            }
            kGuardedSelf->refreshPrivilegeStatusButtons();
        });
    return true;
}

bool MainWindow::showUnsignedDriverFailureDialog(
    const unsigned long errorCode,
    const QString& operationText)
{
    const DWORD kWin32ErrorCode = static_cast<DWORD>(errorCode);
    const bool kDarkModeEnabled = ksword_theme::isDarkModeEnabled();
    const QString kAdaptiveTextColor = ksword_theme::onAccentHex();

    QDialog decisionDialog(this);
    decisionDialog.setModal(true);
    decisionDialog.setWindowTitle(QStringLiteral("KswordARK 驱动签名校验失败"));
    decisionDialog.setObjectName(QStringLiteral("ksUnsignedDriverFailureDialog"));
    decisionDialog.setMinimumWidth(680);
    decisionDialog.setStyleSheet(ksword_theme::opaqueDialogStyle(decisionDialog.objectName()));

    QVBoxLayout* rootLayout = new QVBoxLayout(&decisionDialog);
    rootLayout->setContentsMargins(16, 16, 16, 16);
    rootLayout->setSpacing(10);

    QLabel* failureReasonLabel = new QLabel(
        QStringLiteral(
            "驱动加载失败，失败原因是系统拒绝了未通过数字签名校验的内核驱动。\n\n"
            "操作阶段：%1\n错误码：%2\n系统信息：%3")
        .arg(operationText)
        .arg(kWin32ErrorCode)
        .arg(formatWin32ErrorText(kWin32ErrorCode)),
        &decisionDialog);
    failureReasonLabel->setWordWrap(true);
    failureReasonLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    rootLayout->addWidget(failureReasonLabel);

    QLabel* signatureMechanismLabel = new QLabel(
        QStringLiteral(
            "Windows 已阻止当前驱动。请改用可信签名的 KswordARK.sys；"
            "开发或测试环境也可以选择启用测试模式。"),
        &decisionDialog);
    signatureMechanismLabel->setWordWrap(true);
    rootLayout->addWidget(signatureMechanismLabel);

    QLabel* actionTitleLabel = new QLabel(QStringLiteral("我可以做什么？"), &decisionDialog);
    actionTitleLabel->setStyleSheet(QStringLiteral("font-size:16px;font-weight:700;"));
    rootLayout->addWidget(actionTitleLabel);

    QLabel* testModeDescriptionLabel = new QLabel(
        QStringLiteral(
            "测试模式仅用于开发或测试，会降低系统对内核驱动的保护，"
            "并可能与反作弊软件冲突。开启或关闭后都需要重启电脑。"),
        &decisionDialog);
    testModeDescriptionLabel->setWordWrap(true);
    rootLayout->addWidget(testModeDescriptionLabel);

    QPushButton* continueR3Button = new QPushButton(QStringLiteral("退出并继续使用R3功能"), &decisionDialog);
    continueR3Button->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    continueR3Button->setMinimumHeight(42);
    continueR3Button->setStyleSheet(QStringLiteral(
        "QPushButton{"
        "  background:%1;"
        "  color:%2;"
        "  border:1px solid %1;"
        "  border-radius:4px;"
        "  font-weight:700;"
        "}"
        "QPushButton:hover{"
        "  background:%4;"
        "}"
        "QPushButton:pressed{"
        "  background:%3;"
        "}")
        .arg(ksword_theme::kPrimaryBlueHex)
        .arg(kAdaptiveTextColor)
        .arg(ksword_theme::kPrimaryBluePressedHex)
        .arg(ksword_theme::primaryBlueSolidHoverHex()));
    rootLayout->addWidget(continueR3Button);

    QPushButton* enableTestModeButton = new QPushButton(QStringLiteral("开启测试模式"), &decisionDialog);
    enableTestModeButton->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    enableTestModeButton->setMinimumHeight(42);
    enableTestModeButton->setStyleSheet(QStringLiteral(
        "QPushButton{"
        "  background:%1;"
        "  color:%2;"
        "  border:1px solid %2;"
        "  border-radius:4px;"
        "  font-weight:700;"
        "}"
        "QPushButton:hover{"
        "  background:%3;"
        "}"
        "QPushButton:pressed{"
        "  background:%4;"
        "}")
        .arg(ksword_theme::surfaceHex())
        // Text color remains unchanged during hover/pressed states, while the background color progressively blends into the accent color.
        // Using PrimaryBlueHex directly causes button text to blend into the background color under high-brightness accent colors.
        .arg(ksword_theme::accentButtonTextHex())
        .arg(ksword_theme::primaryBlueSubtleHex())
        .arg(ksword_theme::themeColorName(ksword_theme::primaryBlueSurfacePressedColor())));
    rootLayout->addWidget(enableTestModeButton);

    bool enableTestMode = false;
    connect(continueR3Button, &QPushButton::clicked, &decisionDialog, [&decisionDialog]() {
        decisionDialog.done(QDialog::Rejected);
    });
    connect(enableTestModeButton, &QPushButton::clicked, &decisionDialog, [&decisionDialog, &enableTestMode]() {
        enableTestMode = true;
        decisionDialog.done(QDialog::Accepted);
    });

    decisionDialog.exec();
    if (!enableTestMode)
    {
        return true;
    }
    return enableWindowsTestModeAndPromptReboot();
}

bool MainWindow::enableWindowsTestModeAndPromptReboot()
{
    if (!hasAdminPrivilege())
    {
        (void)ks::ui::requestAdministratorRestartForFeature(
            this,
            QStringLiteral("开启 Windows 测试模式"));
        return false;
    }

    QProcess* bcdeditProcess = new QProcess(this);
    QTimer* timeoutTimer = new QTimer(bcdeditProcess);
    timeoutTimer->setSingleShot(true);
    timeoutTimer->setInterval(15000);
    connect(timeoutTimer, &QTimer::timeout, this, [bcdeditProcess]()
    {
        if (bcdeditProcess->state() != QProcess::NotRunning)
        {
            bcdeditProcess->setProperty("ksword_bcdedit_timed_out", true);
            bcdeditProcess->kill();
        }
    });
    connect(bcdeditProcess, &QProcess::errorOccurred, this, [this, bcdeditProcess](QProcess::ProcessError error)
    {
        if (error != QProcess::FailedToStart || bcdeditProcess->property("ksword_bcdedit_handled").toBool()) return;
        bcdeditProcess->setProperty("ksword_bcdedit_handled", true);
        showR0FatalError(
            QStringLiteral("开启测试模式失败：无法启动 bcdedit。"),
            ERROR_GEN_FAILURE,
            bcdeditProcess->errorString());
        bcdeditProcess->deleteLater();
    });
    connect(bcdeditProcess, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this,
        [this, bcdeditProcess, timeoutTimer](int exitCode, QProcess::ExitStatus exitStatus)
        {
            if (bcdeditProcess->property("ksword_bcdedit_handled").toBool()) return;
            bcdeditProcess->setProperty("ksword_bcdedit_handled", true);
            timeoutTimer->stop();
            if (bcdeditProcess->property("ksword_bcdedit_timed_out").toBool())
            {
                showR0FatalError(
                    QStringLiteral("开启测试模式失败：bcdedit 执行超时。"),
                    ERROR_TIMEOUT);
                bcdeditProcess->deleteLater();
                return;
            }

            const QString kStandardOutput = QString::fromLocal8Bit(bcdeditProcess->readAllStandardOutput()).trimmed();
            const QString kStandardError = QString::fromLocal8Bit(bcdeditProcess->readAllStandardError()).trimmed();
            if (exitStatus != QProcess::NormalExit || exitCode != 0)
            {
                QString detailText = QStringLiteral("退出码：%1").arg(exitCode);
                if (!kStandardOutput.isEmpty()) detailText += QStringLiteral("\nstdout：%1").arg(kStandardOutput);
                if (!kStandardError.isEmpty()) detailText += QStringLiteral("\nstderr：%1").arg(kStandardError);
                showR0FatalError(
                    QStringLiteral("开启测试模式失败：bcdedit 返回错误。"),
                    ERROR_GEN_FAILURE,
                    detailText);
                bcdeditProcess->deleteLater();
                return;
            }

            QMessageBox rebootDialog(this);
            rebootDialog.setIcon(QMessageBox::Question);
            rebootDialog.setWindowTitle(QStringLiteral("测试模式已设置"));
            rebootDialog.setText(QStringLiteral("已执行 bcdedit /set testsigning on。"));
            rebootDialog.setInformativeText(QStringLiteral("需要重启电脑后才会生效。你可以选择稍后重启或现在重启。"));
            QPushButton* rebootLaterButton = rebootDialog.addButton(QStringLiteral("稍后重启"), QMessageBox::RejectRole);
            QPushButton* rebootNowButton = rebootDialog.addButton(QStringLiteral("现在重启"), QMessageBox::AcceptRole);
            rebootDialog.exec();

            if (rebootDialog.clickedButton() == rebootNowButton)
            {
                if (!QProcess::startDetached(QStringLiteral("shutdown"), { QStringLiteral("/r"), QStringLiteral("/t"), QStringLiteral("0") }))
                {
                    showR0FatalError(
                        QStringLiteral("立即重启失败：无法调用 shutdown 命令。"),
                        ERROR_GEN_FAILURE);
                }
            }
            else if (rebootDialog.clickedButton() == rebootLaterButton)
            {
                KLogEvent logEvent;
                info << logEvent << "[MainWindow][R0] 用户选择稍后重启，测试模式将在下次重启后生效。" << eol;
            }
            bcdeditProcess->deleteLater();
        });
    bcdeditProcess->start(
        QStringLiteral("bcdedit"),
        { QStringLiteral("/set"), QStringLiteral("testsigning"), QStringLiteral("on") });
    timeoutTimer->start();
    return true;
}

bool MainWindow::startR0DriverService(const bool suppressPrivilegeElevationPrompt)
{
    // Purpose:
    // - Input: None; the driver is fixed to KswordARK.sys in the current exe directory.
    // - Processing: The UI thread only performs driver file validation and dispatch; SCM creation/configuration/startup/wait-for-running-state is entirely delegated to the thread pool;
    //         The 9-second startup wait limit would freeze the entire UI if executed on the UI thread.
    // - Return: true indicates the start request was successfully dispatched; the actual start outcome is applied by the callback that returns to the UI thread.
    if (gR0ServiceOperationInFlight.exchange(true))
    {
        // An R0 start/stop operation is already executing in the background; duplicate requests are discarded to avoid concurrent operations on the same SCM service.
        return false;
    }

    const QString kDriverPath = QDir(QCoreApplication::applicationDirPath()).absoluteFilePath(QStringLiteral("KswordARK.sys"));
    const QString kNativeDriverPath = QDir::toNativeSeparators(kDriverPath);
    const QFileInfo kDriverFileInfo(kDriverPath);
    if (!kDriverFileInfo.exists() || !kDriverFileInfo.isFile())
    {
        // Missing driver files are an immediately detectable failure; no background task needs to be dispatched for it.
        gR0ServiceOperationInFlight.store(false);
        r0DriverServiceRunning_ = false;
        showR0FatalError(
            QStringLiteral("R0 启动失败：当前程序目录下不存在 KswordARK.sys。"),
            ERROR_FILE_NOT_FOUND,
            QStringLiteral("期望路径：%1").arg(kNativeDriverPath));
        return false;
    }

    if (r0StatusButton_ != nullptr)
    {
        r0StatusButton_->setEnabled(false);
    }

    // guardedSelf usage: Background tasks may outlive the main window; verify lifecycle before re-entrance.
    const QPointer<MainWindow> kGuardedSelf(this);
    dispatchR0ServiceStartToWorker(
        kNativeDriverPath,
        [kGuardedSelf, suppressPrivilegeElevationPrompt](const R0ServiceOperationOutcome& operationOutcome)
        {
            gR0ServiceOperationInFlight.store(false);
            if (kGuardedSelf == nullptr)
            {
                return;
            }
            if (kGuardedSelf->r0StatusButton_ != nullptr)
            {
                kGuardedSelf->r0StatusButton_->setEnabled(true);
            }

            if (!operationOutcome.succeeded)
            {
                kGuardedSelf->r0DriverServiceRunning_ = false;
                if (operationOutcome.startServiceCallFailed
                    && kGuardedSelf->isR0DriverSignatureFailure(operationOutcome.errorCode))
                {
                    KLogEvent logEvent;
                    fatal << logEvent
                        << "[MainWindow][R0][Fatal] 驱动签名校验失败, error="
                        << operationOutcome.errorCode
                        << eol;
                    kGuardedSelf->showUnsignedDriverFailureDialog(
                        operationOutcome.errorCode,
                        QStringLiteral("启动 KswordARK 驱动服务"));
                }
                else if (suppressPrivilegeElevationPrompt
                    || !ks::ui::promptForPrivilegeFailure(
                        kGuardedSelf.data(),
                        QStringLiteral("启用 R0"),
                        operationOutcome.errorCode))
                {
                    kGuardedSelf->showR0FatalError(
                        operationOutcome.stageText,
                        operationOutcome.errorCode,
                        operationOutcome.detailText);
                }
                kGuardedSelf->refreshPrivilegeStatusButtons();
                return;
            }

            kGuardedSelf->r0DriverServiceRunning_ = true;
            kGuardedSelf->startR0RuntimeConsumersAfterServiceStart();
            emit kGuardedSelf->r0DriverServiceStarted();
            if (!operationOutcome.alreadyInTargetState)
            {
                KLogEvent logEvent;
                info << logEvent << "[MainWindow][R0] 已创建并启动 KswordARK 驱动服务。" << eol;
            }
            kGuardedSelf->refreshPrivilegeStatusButtons();
        });
    return true;
}

void MainWindow::handleR0StatusButtonClicked()
{
    // Purpose:
    // - Inputs: None;
    // - Processing: Perform a lightweight SCM status query first, then dispatch background start/stop tasks based on the current status;
    //         UI thread no longer waits for SCM; button availability and final state are refreshed uniformly by start/stop callbacks.
    // - Returns: Nothing.
    bool runningNow = false;
    if (!queryR0DriverServiceRunning(runningNow, true))
    {
        return;
    }
    r0DriverServiceRunning_ = runningNow;

    const bool kDispatchOk = runningNow
        ? stopR0DriverService()
        : startR0DriverService();
    if (!kDispatchOk)
    {
        refreshPrivilegeStatusButtons();
    }
}
