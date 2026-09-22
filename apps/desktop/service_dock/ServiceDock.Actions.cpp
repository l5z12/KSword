#include "ServiceDock.Internal.h"
#include "../framework/PrivilegeElevationPrompt.h"
#include "../Theme.h"

#include <chrono>
#include <QCoreApplication>
#include <QFileDialog>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRunnable>
#include <QSaveFile>
#include <QSet>
#include <QStringConverter>
#include <QTextStream>
#include <QThreadPool>

#include <Shellapi.h>

using namespace service_dock_detail;

namespace
{
    // kServiceActionTimeoutMs:
    // - Maximum milliseconds to wait for the target state during service start/stop/pause actions;
    // - This polling wait has been moved to a background thread; the UI thread is no longer blocked by it.
    constexpr std::uint32_t kServiceActionTimeoutMs = 6000;

    // pendingServiceOperationKeySet:
    // - Track service operations that have been dispatched to the background but have not yet returned results.
    // - ServiceDock.h is out of scope for modification; therefore, this in-flight state is converged at the file level.
    // - Read/write operations occur only on the UI thread (dispatch and re-injection points are both on the UI thread), so no additional locking is required.
    // Input: None.
    // Returns: A reference to the set of pending operation keys.
    QSet<QString>& pendingServiceOperationKeySet()
    {
        static QSet<QString> pendingKeySet;
        return pendingKeySet;
    }

    // buildServiceOperationKey purpose: Generate an in-flight deduplication key for 'operation type + service'.
    // Input parameters: operationTagText is the operation identifier; serviceNameText is the service short name.
    // Returns: A case-insensitive deduplicated key.
    QString buildServiceOperationKey(const QString& operationTagText, const QString& serviceNameText)
    {
        return operationTagText + QLatin1Char('|') + serviceNameText.trimmed().toLower();
    }

    // buildServiceRegistryPath purpose: Generates the registry path text corresponding to the service.
    QString buildServiceRegistryPath(const QString& serviceNameText)
    {
        return QStringLiteral("HKLM\\SYSTEM\\CurrentControlSet\\Services\\%1").arg(serviceNameText);
    }

    // openFilePropertiesByPath: Opens the file properties dialog.
    bool openFilePropertiesByPath(const QString& filePathText, QString* errorTextOut)
    {
        if (filePathText.trimmed().isEmpty())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("文件路径为空。");
            }
            return false;
        }

        const HINSTANCE kShellResult = ::ShellExecuteW(
            nullptr,
            L"properties",
            reinterpret_cast<LPCWSTR>(QDir::toNativeSeparators(filePathText).utf16()),
            nullptr,
            nullptr,
            SW_SHOW);
        if (reinterpret_cast<INT_PTR>(kShellResult) <= 32)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("ShellExecute(properties) 失败，返回值=%1")
                    .arg(reinterpret_cast<INT_PTR>(kShellResult));
            }
            return false;
        }
        return true;
    }
}



void ServiceDock::showServiceContextMenu(const QPoint& localPos)
{
    if (serviceTable_ == nullptr)
    {
        return;
    }

    QTableWidgetItem* clickedItem = serviceTable_->itemAt(localPos);
    if (clickedItem == nullptr)
    {
        return;
    }
    if (clickedItem->row() >= 0)
    {
        serviceTable_->selectRow(clickedItem->row());
    }

    QMenu contextMenu(this);
    // Explicitly fill the menu background to avoid a black background caused by inheriting a transparent style in light mode.
    contextMenu.setStyleSheet(ksword_theme::contextMenuStyle());
    QAction* refreshAction = contextMenu.addAction(createBlueIcon(":/Icon/process_refresh.svg"), QStringLiteral("刷新当前服务"));
    QAction* startAction = contextMenu.addAction(createBlueIcon(":/Icon/process_start.svg"), QStringLiteral("启动服务"));
    QAction* stopAction = contextMenu.addAction(createBlueIcon(":/Icon/process_terminate.svg"), QStringLiteral("停止服务"));
    QAction* pauseAction = contextMenu.addAction(createBlueIcon(":/Icon/process_pause.svg"), QStringLiteral("暂停服务"));
    QAction* continueAction = contextMenu.addAction(createBlueIcon(":/Icon/process_resume.svg"), QStringLiteral("继续服务"));
    contextMenu.addSeparator();
    QAction* deleteServiceAction = contextMenu.addAction(
        createBlueIcon(":/Icon/log_clear.svg"),
        QStringLiteral("删除服务"));
    QAction* deleteServiceAndFileAction = contextMenu.addAction(
        createBlueIcon(":/Icon/log_clear.svg"),
        QStringLiteral("删除服务并删除其文件"));
    deleteServiceAction->setToolTip(QStringLiteral("删除 SCM 服务注册；SCM 不可见时删除对应注册表服务键"));
    deleteServiceAndFileAction->setToolTip(QStringLiteral("复核停止状态和文件独占引用后，删除服务注册与服务文件"));
    contextMenu.addSeparator();
    QAction* jumpProcessAction = contextMenu.addAction(createBlueIcon(":/Icon/process_details.svg"), QStringLiteral("转到进程详细信息"));
    QAction* jumpHandleAction = contextMenu.addAction(createBlueIcon(":/Icon/process_list.svg"), QStringLiteral("跳转句柄筛选"));
    contextMenu.addSeparator();
    QAction* copyNameAction = contextMenu.addAction(createBlueIcon(":/Icon/log_copy.svg"), QStringLiteral("复制服务名"));
    QAction* openRegistryAction = contextMenu.addAction(createBlueIcon(":/Icon/file_find.svg"), QStringLiteral("打开服务注册表位置"));
    QAction* openBinaryLocationAction = contextMenu.addAction(createBlueIcon(":/Icon/process_open_folder.svg"), QStringLiteral("打开 BinaryPath 文件位置"));
    QAction* openServiceDllLocationAction = contextMenu.addAction(createBlueIcon(":/Icon/process_open_folder.svg"), QStringLiteral("打开 ServiceDll 文件位置"));
    QAction* openBinaryPropertiesAction = contextMenu.addAction(createBlueIcon(":/Icon/process_details.svg"), QStringLiteral("查看 BinaryPath 文件属性"));
    QAction* jumpFileDockBinaryAction = contextMenu.addAction(createBlueIcon(":/Icon/file_find.svg"), QStringLiteral("转到 FileDock 分析 BinaryPath"));
    QAction* jumpFileDockServiceDllAction = contextMenu.addAction(createBlueIcon(":/Icon/file_find.svg"), QStringLiteral("转到 FileDock 分析 ServiceDll"));
    contextMenu.addSeparator();
    QAction* exportListAction = contextMenu.addAction(createBlueIcon(":/Icon/log_export.svg"), QStringLiteral("导出当前列表 TSV"));
    QAction* exportServiceJsonAction = contextMenu.addAction(createBlueIcon(":/Icon/log_export.svg"), QStringLiteral("导出当前服务 JSON"));

    startAction->setEnabled(startButton_ != nullptr && startButton_->isEnabled());
    stopAction->setEnabled(stopButton_ != nullptr && stopButton_->isEnabled());
    pauseAction->setEnabled(pauseButton_ != nullptr && pauseButton_->isEnabled());
    continueAction->setEnabled(continueButton_ != nullptr && continueButton_->isEnabled());
    refreshAction->setEnabled(refreshCurrentButton_ != nullptr && refreshCurrentButton_->isEnabled());
    copyNameAction->setEnabled(!selectedServiceName().isEmpty());
    const int kSelectedIndex = findServiceIndexByName(selectedServiceName());
    const bool kHasSelectedEntry = kSelectedIndex >= 0
        && kSelectedIndex < static_cast<int>(serviceList_.size());
    deleteServiceAction->setEnabled(kHasSelectedEntry);
    deleteServiceAndFileAction->setEnabled(
        kHasSelectedEntry
        && !serviceList_[static_cast<std::size_t>(kSelectedIndex)].imagePathText.trimmed().isEmpty());
    openRegistryAction->setEnabled(!selectedServiceName().isEmpty());
    jumpProcessAction->setEnabled(!selectedServiceName().isEmpty());
    jumpHandleAction->setEnabled(!selectedServiceName().isEmpty());
    openBinaryLocationAction->setEnabled(!selectedServiceName().isEmpty());
    openServiceDllLocationAction->setEnabled(!selectedServiceName().isEmpty());
    openBinaryPropertiesAction->setEnabled(!selectedServiceName().isEmpty());
    jumpFileDockBinaryAction->setEnabled(!selectedServiceName().isEmpty());
    jumpFileDockServiceDllAction->setEnabled(!selectedServiceName().isEmpty());
    exportListAction->setEnabled(serviceTable_ != nullptr && serviceTable_->rowCount() > 0);
    exportServiceJsonAction->setEnabled(!selectedServiceName().isEmpty());

    QAction* selectedAction = contextMenu.exec(serviceTable_->viewport()->mapToGlobal(localPos));
    if (selectedAction == refreshAction)
    {
        refreshSelectedService();
    }
    else if (selectedAction == startAction)
    {
        startSelectedService();
    }
    else if (selectedAction == stopAction)
    {
        stopSelectedService();
    }
    else if (selectedAction == pauseAction)
    {
        pauseSelectedService();
    }
    else if (selectedAction == continueAction)
    {
        continueSelectedService();
    }
    else if (selectedAction == deleteServiceAction)
    {
        deleteSelectedService();
    }
    else if (selectedAction == deleteServiceAndFileAction)
    {
        deleteSelectedServiceAndFile();
    }
    else if (selectedAction == jumpProcessAction)
    {
        jumpToSelectedProcessDetail();
    }
    else if (selectedAction == jumpHandleAction)
    {
        jumpToSelectedHandleFilter();
    }
    else if (selectedAction == copyNameAction)
    {
        copySelectedServiceName();
    }
    else if (selectedAction == openRegistryAction)
    {
        openSelectedServiceRegistryPath();
    }
    else if (selectedAction == openBinaryLocationAction)
    {
        openSelectedBinaryLocation();
    }
    else if (selectedAction == openServiceDllLocationAction)
    {
        openSelectedServiceDllLocation();
    }
    else if (selectedAction == openBinaryPropertiesAction)
    {
        openSelectedBinaryProperties();
    }
    else if (selectedAction == jumpFileDockBinaryAction)
    {
        jumpToFileDockBinaryDetail();
    }
    else if (selectedAction == jumpFileDockServiceDllAction)
    {
        jumpToFileDockServiceDllDetail();
    }
    else if (selectedAction == exportListAction)
    {
        exportCurrentListAsTsv();
    }
    else if (selectedAction == exportServiceJsonAction)
    {
        exportSelectedServiceAsJson();
    }
}

void ServiceDock::refreshSelectedService()
{
    const QString kServiceNameText = selectedServiceName();
    if (kServiceNameText.isEmpty())
    {
        return;
    }

    // Single refresh performs WinVerifyTrust digital signature verification (directory signatures require searching CatRoot and
    // hashing files). Each file takes tens to hundreds of milliseconds, so it must run on a background thread just like full refresh.
    const QString kOperationKeyText = buildServiceOperationKey(QStringLiteral("refresh"), kServiceNameText);
    if (pendingServiceOperationKeySet().contains(kOperationKeyText))
    {
        return;
    }

    const KLogEvent kRefreshEvent;
    info << kRefreshEvent
        << "[ServiceDock] 刷新单服务详情, service="
        << kServiceNameText.toStdString()
        << eol;

    const int kProgressPid = kPro.add(this, "服务管理", "刷新单服务详情");
    kPro.set(kProgressPid, "读取服务配置", 0, 45.0f);
    pendingServiceOperationKeySet().insert(kOperationKeyText);

    const int kSelectedIndex = findServiceIndexByName(kServiceNameText);
    const bool kSourceScmRecordPresent = kSelectedIndex >= 0
        && kSelectedIndex < static_cast<int>(serviceList_.size())
        ? serviceList_[static_cast<std::size_t>(kSelectedIndex)].scmRecordPresent
        : true;
    const bool kSourceRegistryScanCompleted = kSelectedIndex >= 0
        && kSelectedIndex < static_cast<int>(serviceList_.size())
        ? serviceList_[static_cast<std::size_t>(kSelectedIndex)].registryScanCompleted
        : true;

    // guardedSelf usage: background collection may outlive the page; verify lifecycle before callback.
    const QPointer<ServiceDock> kGuardedSelf(this);
    QRunnable* const kRefreshTask = QRunnable::create(
        [kGuardedSelf,
            kServiceNameText,
            kOperationKeyText,
            kProgressPid,
            kRefreshEvent,
            kSourceScmRecordPresent,
            kSourceRegistryScanCompleted]()
        {
            // Background operations perform pure data collection, producing values of type ServiceEntry / QString.
            ServiceEntry updatedEntry;
            QString errorText;
            const bool kQuerySucceeded = service_dock_detail::querySingleServiceSnapshot(
                kServiceNameText,
                kSourceScmRecordPresent,
                kSourceRegistryScanCompleted,
                &updatedEntry,
                &errorText);

            QCoreApplication* const kAppInstance = QCoreApplication::instance();
            if (kAppInstance == nullptr)
            {
                return;
            }

            QMetaObject::invokeMethod(
                kAppInstance,
                [kGuardedSelf,
                    kServiceNameText,
                    kOperationKeyText,
                    kProgressPid,
                    kRefreshEvent,
                    kQuerySucceeded,
                    updatedEntry,
                    errorText]()
                {
                    // Regardless of whether the page is still alive, remove the in-flight marker first to prevent residual state from permanently rejecting subsequent refreshes.
                    pendingServiceOperationKeySet().remove(kOperationKeyText);
                    if (kGuardedSelf == nullptr)
                    {
                        return;
                    }

                    if (!kQuerySucceeded)
                    {
                        kPro.set(kProgressPid, "刷新失败", 0, 100.0f);
                        err << kRefreshEvent
                            << "[ServiceDock] 刷新单服务详情失败, service="
                            << kServiceNameText.toStdString()
                            << ", error="
                            << errorText.toStdString()
                            << eol;
                        QMessageBox::warning(
                            kGuardedSelf.data(),
                            QStringLiteral("服务管理"),
                            QStringLiteral("刷新服务详情失败：\n%1").arg(errorText));
                        return;
                    }

                    kGuardedSelf->applyServiceUpdateToCache(updatedEntry);
                    kGuardedSelf->rebuildServiceTable();
                    kPro.set(kProgressPid, "刷新完成", 0, 100.0f);
                },
                Qt::QueuedConnection);
        });
    kRefreshTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(kRefreshTask);
}

void ServiceDock::startSelectedService()
{
    controlSelectedService(
        SERVICE_START,
        QStringLiteral("启动服务"),
        0,
        true,
        SERVICE_RUNNING,
        false);
}

void ServiceDock::stopSelectedService()
{
    controlSelectedService(
        SERVICE_STOP,
        QStringLiteral("停止服务"),
        SERVICE_CONTROL_STOP,
        false,
        SERVICE_STOPPED,
        true);
}

void ServiceDock::pauseSelectedService()
{
    controlSelectedService(
        SERVICE_PAUSE_CONTINUE,
        QStringLiteral("暂停服务"),
        SERVICE_CONTROL_PAUSE,
        false,
        SERVICE_PAUSED,
        false);
}

void ServiceDock::continueSelectedService()
{
    controlSelectedService(
        SERVICE_PAUSE_CONTINUE,
        QStringLiteral("继续服务"),
        SERVICE_CONTROL_CONTINUE,
        false,
        SERVICE_RUNNING,
        false);
}

bool ServiceDock::controlSelectedService(
    const DWORD desiredAccess,
    const QString& actionText,
    const DWORD controlCode,
    const bool useStartService,
    const DWORD expectedState,
    const bool highRiskAction)
{
    const QString kServiceNameText = selectedServiceName();
    if (kServiceNameText.isEmpty())
    {
        return false;
    }

    const int kSelectedIndex = findServiceIndexByName(kServiceNameText);
    if (kSelectedIndex < 0 || kSelectedIndex >= static_cast<int>(serviceList_.size()))
    {
        return false;
    }

    const ServiceEntry& selectedEntry = serviceList_[static_cast<std::size_t>(kSelectedIndex)];
    if (isServiceStatePending(selectedEntry.currentState))
    {
        QMessageBox::information(
            this,
            QStringLiteral("服务管理"),
            QStringLiteral("当前服务处于状态切换中，请稍后再试。"));
        return false;
    }

    // Control actions now execute asynchronously; duplicate submissions for the same service are prohibited before the result is returned.
    const QString kOperationKeyText = buildServiceOperationKey(QStringLiteral("control"), kServiceNameText);
    if (pendingServiceOperationKeySet().contains(kOperationKeyText))
    {
        QMessageBox::information(
            this,
            QStringLiteral("服务管理"),
            QStringLiteral("当前服务处于状态切换中，请稍后再试。"));
        return false;
    }

    if (highRiskAction)
    {
        const QMessageBox::StandardButton kConfirmButton = QMessageBox::warning(
            this,
            QStringLiteral("高风险动作确认"),
            QStringLiteral("确认执行“%1”？\n\n服务：%2").arg(actionText).arg(kServiceNameText),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
        if (kConfirmButton != QMessageBox::Yes)
        {
            return false;
        }
    }

    const KLogEvent kActionEvent;
    info << kActionEvent
        << "[ServiceDock] 开始执行服务动作, action="
        << actionText.toStdString()
        << ", service="
        << kServiceNameText.toStdString()
        << eol;

    const int kProgressPid = kPro.add(this, "服务管理", actionText.toStdString() + std::string(" - ") + kServiceNameText.toStdString());
    kPro.set(kProgressPid, "下发服务控制指令", 0, 55.0f);
    pendingServiceOperationKeySet().insert(kOperationKeyText);

    // Disable control buttons during dispatch to provide intuitive feedback that an operation is in progress.
    // On result re-injection, syncToolbarStateWithSelection() is used uniformly to recalculate availability based on the latest state.
    if (startButton_ != nullptr) { startButton_->setEnabled(false); }
    if (stopButton_ != nullptr) { stopButton_->setEnabled(false); }
    if (pauseButton_ != nullptr) { pauseButton_->setEnabled(false); }
    if (continueButton_ != nullptr) { continueButton_->setEnabled(false); }
    if (generalStartButton_ != nullptr) { generalStartButton_->setEnabled(false); }
    if (generalStopButton_ != nullptr) { generalStopButton_->setEnabled(false); }
    if (generalPauseButton_ != nullptr) { generalPauseButton_->setEnabled(false); }
    if (generalContinueButton_ != nullptr) { generalContinueButton_->setEnabled(false); }

    // UI layer only selects the action; ks::service owns SCM handles and Start/ControlService calls.
    // ks::service polls internally at 180ms granularity until the expected state is reached or kServiceActionTimeoutMs expires. Stopping
    // services like spooler/WSearch often triggers timeouts, so the entire dispatch-and-wait sequence is moved to a background thread.
    // guardedSelf usage: background tasks may outlive the page; verify lifecycle before callback.
    const QPointer<ServiceDock> kGuardedSelf(this);
    const std::wstring kServiceNameWide = kServiceNameText.toStdWString();
    QRunnable* const kControlTask = QRunnable::create(
        [kGuardedSelf,
            kServiceNameText,
            kServiceNameWide,
            actionText,
            kOperationKeyText,
            kProgressPid,
            kActionEvent,
            desiredAccess,
            controlCode,
            useStartService,
            expectedState]()
        {
            // Background only handles SCM dispatch and status polling, producing value-type results.
            ks::service::ServiceStatus finalStatus;
            std::string errorText;
            std::uint32_t errorCode = 0;
            const bool kActionOk = useStartService
                ? ks::service::startServiceByName(
                    kServiceNameWide,
                    kServiceActionTimeoutMs,
                    expectedState,
                    &finalStatus,
                    &errorText,
                    &errorCode)
                : ks::service::controlServiceByName(
                    kServiceNameWide,
                    desiredAccess,
                    controlCode,
                    kServiceActionTimeoutMs,
                    expectedState,
                    &finalStatus,
                    &errorText,
                    &errorCode);

            const DWORD kFinalStateValue = static_cast<DWORD>(finalStatus.currentState);

            QCoreApplication* const kAppInstance = QCoreApplication::instance();
            if (kAppInstance == nullptr)
            {
                return;
            }

            QMetaObject::invokeMethod(
                kAppInstance,
                [kGuardedSelf,
                    kServiceNameText,
                    actionText,
                    kOperationKeyText,
                    kProgressPid,
                    kActionEvent,
                    expectedState,
                    kActionOk,
                    kFinalStateValue,
                    errorText,
                    errorCode]()
                {
                    // Remove the in-flight flag first regardless of whether the page is still alive to prevent residual state from permanently rejecting subsequent actions.
                    pendingServiceOperationKeySet().remove(kOperationKeyText);
                    if (kGuardedSelf == nullptr)
                    {
                        return;
                    }

                    if (!kActionOk)
                    {
                        // privilegePromptHandled: do not show the generic service failure dialog if the privilege recovery prompt has already been displayed.
                        const bool kPrivilegePromptHandled = ks::ui::promptForPrivilegeFailure(
                            kGuardedSelf.data(),
                            actionText,
                            errorCode);
                        err << kActionEvent
                            << "[ServiceDock] 服务动作执行失败, action="
                            << actionText.toStdString()
                            << ", service="
                            << kServiceNameText.toStdString()
                            << ", error="
                            << errorCode
                            << ", detail="
                            << errorText
                            << eol;
                        kPro.set(kProgressPid, "执行失败", 0, 100.0f);
                        kGuardedSelf->syncToolbarStateWithSelection();
                        if (!kPrivilegePromptHandled)
                        {
                            QMessageBox::warning(
                                kGuardedSelf.data(),
                                QStringLiteral("服务管理"),
                                QStringLiteral("操作失败：\n%1").arg(QString::fromUtf8(errorText.c_str())));
                        }
                        return;
                    }

                    kPro.set(kProgressPid, "等待状态稳定", 0, 80.0f);
                    const bool kWaitOk = (expectedState == 0) || (kFinalStateValue == expectedState);
                    if (!kWaitOk)
                    {
                        warn << kActionEvent
                            << "[ServiceDock] 服务动作已下发但状态未在超时内到达期望, action="
                            << actionText.toStdString()
                            << ", service="
                            << kServiceNameText.toStdString()
                            << ", finalState="
                            << kFinalStateValue
                            << eol;
                    }
                    else
                    {
                        info << kActionEvent
                            << "[ServiceDock] 服务动作执行成功, action="
                            << actionText.toStdString()
                            << ", service="
                            << kServiceNameText.toStdString()
                            << eol;
                    }

                    kPro.set(kProgressPid, "刷新列表", 0, 92.0f);
                    kGuardedSelf->syncToolbarStateWithSelection();
                    kGuardedSelf->requestAsyncRefresh(true);
                    kPro.set(kProgressPid, "执行完成", 0, 100.0f);
                },
                Qt::QueuedConnection);
        });
    kControlTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(kControlTask);

    // Return value semantics converge from 'action completed' to 'action accepted and dispatched to the background'.
    return true;
}


void ServiceDock::applySelectedStartType()
{
    const QString kServiceNameText = selectedServiceName();
    if (kServiceNameText.isEmpty())
    {
        return;
    }

    const int kSelectedIndex = findServiceIndexByName(kServiceNameText);
    if (kSelectedIndex < 0 || kSelectedIndex >= static_cast<int>(serviceList_.size()))
    {
        return;
    }

    const ServiceEntry& selectedEntry = serviceList_[static_cast<std::size_t>(kSelectedIndex)];
    if (isServiceStatePending(selectedEntry.currentState))
    {
        QMessageBox::information(this, QStringLiteral("服务管理"), QStringLiteral("当前服务处于过渡态，请稍后再改启动类型。"));
        return;
    }

    const DWORD kTargetStartType = static_cast<DWORD>(startTypeCombo_->currentData(Qt::UserRole).toULongLong());
    const bool kTargetDelayedAutoStart = startTypeCombo_->currentData(Qt::UserRole + 1).toBool();
    const QString kTargetStartTypeText = startTypeCombo_->currentText();

    if (kTargetStartType == SERVICE_DISABLED)
    {
        const QMessageBox::StandardButton kConfirmButton = QMessageBox::warning(
            this,
            QStringLiteral("高风险动作确认"),
            QStringLiteral("确认将服务“%1”设置为禁用吗？").arg(kServiceNameText),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
        if (kConfirmButton != QMessageBox::Yes)
        {
            return;
        }
    }

    const KLogEvent kChangeEvent;
    info << kChangeEvent
        << "[ServiceDock] 开始修改启动类型, service="
        << kServiceNameText.toStdString()
        << ", target="
        << kTargetStartTypeText.toStdString()
        << eol;

    const int kProgressPid = kPro.add(this, "服务管理", "修改启动类型");
    kPro.set(kProgressPid, "写入启动类型", 0, 60.0f);

    ks::service::ServiceConfigUpdate update;
    update.changeStartType = true;
    update.startType = kTargetStartType;

    std::string errorText;
    std::uint32_t errorCode = 0;
    if (!ks::service::changeServiceConfiguration(
        kServiceNameText.toStdWString(),
        update,
        &errorText,
        &errorCode))
    {
        // privilegePromptHandled: do not show the generic service failure dialog if the privilege recovery prompt has already been displayed.
        const bool kPrivilegePromptHandled = ks::ui::promptForPrivilegeFailure(
            this,
            QStringLiteral("修改服务启动类型"),
            errorCode);
        err << kChangeEvent
            << "[ServiceDock] 修改启动类型失败, error="
            << errorCode
            << ", detail="
            << errorText
            << eol;
        kPro.set(kProgressPid, "执行失败", 0, 100.0f);
        if (!kPrivilegePromptHandled)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("服务管理"),
                QStringLiteral("修改启动类型失败：\n%1").arg(QString::fromUtf8(errorText.c_str())));
        }
        return;
    }

    const bool kDelayedTarget = (kTargetStartType == SERVICE_AUTO_START && kTargetDelayedAutoStart);
    std::string delayedErrorText;
    std::uint32_t delayedErrorCode = 0;
    if (!ks::service::setDelayedAutoStart(
        kServiceNameText.toStdWString(),
        kDelayedTarget,
        &delayedErrorText,
        &delayedErrorCode))
    {
        (void)ks::ui::promptForPrivilegeFailure(
            this,
            QStringLiteral("修改服务延迟启动"),
            delayedErrorCode);
        warn << kChangeEvent
            << "[ServiceDock] 设置 DelayedAutoStart 失败，继续后续流程, error="
            << delayedErrorCode
            << ", detail="
            << delayedErrorText
            << eol;
    }

    kPro.set(kProgressPid, "刷新列表", 0, 90.0f);
    requestAsyncRefresh(true);
    kPro.set(kProgressPid, "修改完成", 0, 100.0f);
}


void ServiceDock::copySelectedServiceName()
{
    const QString kServiceNameText = selectedServiceName();
    if (kServiceNameText.isEmpty())
    {
        return;
    }

    QApplication::clipboard()->setText(kServiceNameText);
}

void ServiceDock::openSelectedServiceRegistryPath()
{
    const QString kServiceNameText = selectedServiceName();
    if (kServiceNameText.isEmpty())
    {
        return;
    }

    const QString kRegistryPathText = buildServiceRegistryPath(kServiceNameText);
    QApplication::clipboard()->setText(kRegistryPathText);
    QProcess::startDetached(QStringLiteral("regedit.exe"), {});
    QMessageBox::information(
        this,
        QStringLiteral("服务管理"),
        QStringLiteral("已复制注册表路径到剪贴板：\n%1\n\n并尝试打开 regedit。").arg(kRegistryPathText));
}

void ServiceDock::openSelectedBinaryLocation()
{
    const int kSelectedIndex = findServiceIndexByName(selectedServiceName());
    if (kSelectedIndex < 0 || kSelectedIndex >= static_cast<int>(serviceList_.size()))
    {
        return;
    }

    const QString kFilePathText = serviceList_[static_cast<std::size_t>(kSelectedIndex)].imagePathText.trimmed();
    if (kFilePathText.isEmpty())
    {
        QMessageBox::information(this, QStringLiteral("服务管理"), QStringLiteral("当前服务没有可定位的 BinaryPath 文件。"));
        return;
    }

    QProcess::startDetached(
        QStringLiteral("explorer.exe"),
        { QStringLiteral("/select,%1").arg(QDir::toNativeSeparators(kFilePathText)) });
}

void ServiceDock::openSelectedServiceDllLocation()
{
    const int kSelectedIndex = findServiceIndexByName(selectedServiceName());
    if (kSelectedIndex < 0 || kSelectedIndex >= static_cast<int>(serviceList_.size()))
    {
        return;
    }

    const QString kFilePathText = serviceList_[static_cast<std::size_t>(kSelectedIndex)].serviceDllPathText.trimmed();
    if (kFilePathText.isEmpty())
    {
        QMessageBox::information(this, QStringLiteral("服务管理"), QStringLiteral("当前服务未配置 ServiceDll。"));
        return;
    }

    QProcess::startDetached(
        QStringLiteral("explorer.exe"),
        { QStringLiteral("/select,%1").arg(QDir::toNativeSeparators(kFilePathText)) });
}

void ServiceDock::openSelectedBinaryProperties()
{
    const int kSelectedIndex = findServiceIndexByName(selectedServiceName());
    if (kSelectedIndex < 0 || kSelectedIndex >= static_cast<int>(serviceList_.size()))
    {
        return;
    }

    const QString kFilePathText = serviceList_[static_cast<std::size_t>(kSelectedIndex)].imagePathText.trimmed();
    if (kFilePathText.isEmpty())
    {
        QMessageBox::information(this, QStringLiteral("服务管理"), QStringLiteral("当前服务没有可查看属性的 BinaryPath 文件。"));
        return;
    }

    QString errorText;
    if (!openFilePropertiesByPath(kFilePathText, &errorText))
    {
        QMessageBox::warning(this, QStringLiteral("服务管理"), QStringLiteral("打开文件属性失败：\n%1").arg(errorText));
    }
}

void ServiceDock::jumpToSelectedProcessDetail()
{
    const int kSelectedIndex = findServiceIndexByName(selectedServiceName());
    if (kSelectedIndex < 0 || kSelectedIndex >= static_cast<int>(serviceList_.size()))
    {
        return;
    }

    const std::uint32_t kProcessIdValue = serviceList_[static_cast<std::size_t>(kSelectedIndex)].processId;
    if (kProcessIdValue == 0)
    {
        QMessageBox::information(this, QStringLiteral("服务管理"), QStringLiteral("当前服务没有关联运行中 PID。"));
        return;
    }

    QWidget* mainWindowWidget = window();
    if (mainWindowWidget == nullptr)
    {
        return;
    }

    QMetaObject::invokeMethod(
        mainWindowWidget,
        "openProcessDetailByPid",
        Qt::QueuedConnection,
        Q_ARG(quint32, static_cast<quint32>(kProcessIdValue)));
}

void ServiceDock::jumpToSelectedHandleFilter()
{
    const int kSelectedIndex = findServiceIndexByName(selectedServiceName());
    if (kSelectedIndex < 0 || kSelectedIndex >= static_cast<int>(serviceList_.size()))
    {
        return;
    }

    const std::uint32_t kProcessIdValue = serviceList_[static_cast<std::size_t>(kSelectedIndex)].processId;
    if (kProcessIdValue == 0)
    {
        QMessageBox::information(this, QStringLiteral("服务管理"), QStringLiteral("当前服务没有关联运行中 PID。"));
        return;
    }

    QWidget* mainWindowWidget = window();
    if (mainWindowWidget == nullptr)
    {
        return;
    }

    QMetaObject::invokeMethod(
        mainWindowWidget,
        "focusHandleDockByPid",
        Qt::QueuedConnection,
        Q_ARG(quint32, static_cast<quint32>(kProcessIdValue)));
}

void ServiceDock::exportCurrentListAsTsv()
{
    const QString kOutputPath = QFileDialog::getSaveFileName(
        this,
        QStringLiteral("导出服务列表"),
        QStringLiteral("ServiceList.tsv"),
        QStringLiteral("TSV Files (*.tsv);;All Files (*.*)"));
    if (kOutputPath.trimmed().isEmpty())
    {
        return;
    }

    QSaveFile outputFile(kOutputPath);
    if (!outputFile.open(QIODevice::WriteOnly | QIODevice::Text))
    {
        QMessageBox::warning(this, QStringLiteral("服务管理"), QStringLiteral("打开导出文件失败：\n%1").arg(outputFile.errorString()));
        return;
    }

    QTextStream outputStream(&outputFile);
    outputStream.setEncoding(QStringConverter::Utf8);
    outputStream << "服务名\t显示名\t状态\t启动类型\tPID\t账户\tBinaryPath\tServiceDll\t来源\t风险\n";

    for (int rowIndex = 0; rowIndex < serviceTable_->rowCount(); ++rowIndex)
    {
        QTableWidgetItem* nameItem = serviceTable_->item(rowIndex, toServiceColumn(ServiceColumn::kName));
        if (nameItem == nullptr)
        {
            continue;
        }

        const QString kServiceNameText = nameItem->data(kServiceNameRole).toString();
        const int kServiceIndex = findServiceIndexByName(kServiceNameText);
        if (kServiceIndex < 0 || kServiceIndex >= static_cast<int>(serviceList_.size()))
        {
            continue;
        }

        const ServiceEntry& entry = serviceList_[static_cast<std::size_t>(kServiceIndex)];
        outputStream
            << entry.serviceNameText << '\t'
            << entry.displayNameText << '\t'
            << entry.stateText << '\t'
            << entry.startTypeText << '\t'
            << entry.processId << '\t'
            << entry.accountText << '\t'
            << entry.commandLineText << '\t'
            << entry.serviceDllPathText << '\t'
            << entry.sourceStatusText << '\t'
            << entry.riskSummaryText << '\n';
    }

    if (!outputFile.commit())
    {
        QMessageBox::warning(this, QStringLiteral("服务管理"), QStringLiteral("写入导出文件失败。"));
        return;
    }
}

void ServiceDock::exportSelectedServiceAsJson()
{
    const int kSelectedIndex = findServiceIndexByName(selectedServiceName());
    if (kSelectedIndex < 0 || kSelectedIndex >= static_cast<int>(serviceList_.size()))
    {
        return;
    }

    const ServiceEntry& entry = serviceList_[static_cast<std::size_t>(kSelectedIndex)];
    const QString kOutputPath = QFileDialog::getSaveFileName(
        this,
        QStringLiteral("导出当前服务 JSON"),
        QStringLiteral("%1.json").arg(entry.serviceNameText),
        QStringLiteral("JSON Files (*.json);;All Files (*.*)"));
    if (kOutputPath.trimmed().isEmpty())
    {
        return;
    }

    QJsonObject rootObject;
    rootObject.insert(QStringLiteral("service_name"), entry.serviceNameText);
    rootObject.insert(QStringLiteral("display_name"), entry.displayNameText);
    rootObject.insert(QStringLiteral("description"), entry.descriptionText);
    rootObject.insert(QStringLiteral("state_text"), entry.stateText);
    rootObject.insert(QStringLiteral("start_type_text"), entry.startTypeText);
    rootObject.insert(QStringLiteral("service_type_text"), entry.serviceTypeText);
    rootObject.insert(QStringLiteral("error_control_text"), entry.errorControlText);
    rootObject.insert(QStringLiteral("binary_path"), entry.commandLineText);
    rootObject.insert(QStringLiteral("image_path"), entry.imagePathText);
    rootObject.insert(QStringLiteral("service_dll_path"), entry.serviceDllPathText);
    rootObject.insert(QStringLiteral("account"), entry.accountText);
    rootObject.insert(QStringLiteral("pid"), static_cast<int>(entry.processId));
    rootObject.insert(QStringLiteral("current_state"), static_cast<int>(entry.currentState));
    rootObject.insert(QStringLiteral("start_type"), static_cast<int>(entry.startTypeValue));
    rootObject.insert(QStringLiteral("service_type"), static_cast<int>(entry.serviceTypeValue));
    rootObject.insert(QStringLiteral("error_control"), static_cast<int>(entry.errorControlValue));
    rootObject.insert(QStringLiteral("delayed_auto_start"), entry.delayedAutoStart);
    rootObject.insert(QStringLiteral("source_status"), entry.sourceStatusText);
    rootObject.insert(QStringLiteral("scm_record_present"), entry.scmRecordPresent);
    rootObject.insert(QStringLiteral("registry_key_present"), entry.registryKeyPresent);
    rootObject.insert(QStringLiteral("registry_scan_completed"), entry.registryScanCompleted);
    rootObject.insert(QStringLiteral("risk_summary"), entry.riskSummaryText);

    QJsonArray riskArray;
    for (const QString& riskTagText : entry.riskTagList)
    {
        riskArray.push_back(riskTagText);
    }
    rootObject.insert(QStringLiteral("risk_tags"), riskArray);

    QSaveFile outputFile(kOutputPath);
    if (!outputFile.open(QIODevice::WriteOnly | QIODevice::Text))
    {
        QMessageBox::warning(this, QStringLiteral("服务管理"), QStringLiteral("打开导出文件失败：\n%1").arg(outputFile.errorString()));
        return;
    }

    const QJsonDocument kJsonDocument(rootObject);
    outputFile.write(kJsonDocument.toJson(QJsonDocument::Indented));
    if (!outputFile.commit())
    {
        QMessageBox::warning(this, QStringLiteral("服务管理"), QStringLiteral("写入导出文件失败。"));
    }
}

void ServiceDock::jumpToFileDockBinaryDetail()
{
    const int kSelectedIndex = findServiceIndexByName(selectedServiceName());
    if (kSelectedIndex < 0 || kSelectedIndex >= static_cast<int>(serviceList_.size()))
    {
        return;
    }

    const QString kFilePathText = serviceList_[static_cast<std::size_t>(kSelectedIndex)].imagePathText.trimmed();
    if (kFilePathText.isEmpty())
    {
        QMessageBox::information(this, QStringLiteral("服务管理"), QStringLiteral("当前服务没有可分析的 BinaryPath 文件。"));
        return;
    }

    QWidget* mainWindowWidget = window();
    if (mainWindowWidget == nullptr)
    {
        return;
    }

    QMetaObject::invokeMethod(
        mainWindowWidget,
        "openFileDetailDockByPath",
        Qt::QueuedConnection,
        Q_ARG(QString, kFilePathText));
}

void ServiceDock::jumpToFileDockServiceDllDetail()
{
    const int kSelectedIndex = findServiceIndexByName(selectedServiceName());
    if (kSelectedIndex < 0 || kSelectedIndex >= static_cast<int>(serviceList_.size()))
    {
        return;
    }

    const QString kFilePathText = serviceList_[static_cast<std::size_t>(kSelectedIndex)].serviceDllPathText.trimmed();
    if (kFilePathText.isEmpty())
    {
        QMessageBox::information(this, QStringLiteral("服务管理"), QStringLiteral("当前服务未配置 ServiceDll。"));
        return;
    }

    QWidget* mainWindowWidget = window();
    if (mainWindowWidget == nullptr)
    {
        return;
    }

    QMetaObject::invokeMethod(
        mainWindowWidget,
        "openFileDetailDockByPath",
        Qt::QueuedConnection,
        Q_ARG(QString, kFilePathText));
}
