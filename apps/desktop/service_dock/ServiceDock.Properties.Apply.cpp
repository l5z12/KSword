#include "ServiceDock.Internal.h"

#include <QSignalBlocker>

using namespace service_dock_detail;

namespace
{
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

bool ServiceDock::queryServiceFailureSettings(
    const QString& serviceNameText,
    ServiceRecoverySettings* settingsOut,
    QString* errorTextOut) const
{
    if (settingsOut == nullptr || serviceNameText.trimmed().isEmpty())
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("恢复配置读取参数无效");
        }
        return false;
    }

    *settingsOut = ServiceRecoverySettings{};

    ks::service::FailureSettings failureSettings;
    std::string errorText;
    if (!ks::service::queryServiceFailureSettings(
        serviceNameText.trimmed().toStdWString(),
        &failureSettings,
        &errorText))
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QString::fromUtf8(errorText.c_str());
        }
        return false;
    }

    settingsOut->resetPeriodDays = static_cast<int>(failureSettings.resetPeriodSeconds / (24u * 60u * 60u));
    settingsOut->rebootMessageText = QString::fromStdWString(failureSettings.rebootMessage).trimmed();

    const QString kCommandText = QString::fromStdWString(failureSettings.command).trimmed();
    splitRecoveryCommandText(
        kCommandText,
        &settingsOut->programPathText,
        &settingsOut->programArgumentsText,
        &settingsOut->appendFailureCount);


    if (!failureSettings.actions.empty())
    {
        settingsOut->firstActionType = static_cast<SC_ACTION_TYPE>(failureSettings.actions[0].type);
        if (settingsOut->firstActionType == SC_ACTION_RESTART)
        {
            settingsOut->restartDelayMinutes = static_cast<int>(failureSettings.actions[0].delayMs / (60u * 1000u));
        }
    }
    if (failureSettings.actions.size() > 1)
    {
        settingsOut->secondActionType = static_cast<SC_ACTION_TYPE>(failureSettings.actions[1].type);
        if (settingsOut->secondActionType == SC_ACTION_RESTART)
        {
            settingsOut->restartDelayMinutes = static_cast<int>(failureSettings.actions[1].delayMs / (60u * 1000u));
        }
    }
    if (failureSettings.actions.size() > 2)
    {
        settingsOut->subsequentActionType = static_cast<SC_ACTION_TYPE>(failureSettings.actions[2].type);
        if (settingsOut->subsequentActionType == SC_ACTION_RESTART)
        {
            settingsOut->restartDelayMinutes = static_cast<int>(failureSettings.actions[2].delayMs / (60u * 1000u));
        }
    }
    settingsOut->failureActionsFlag = failureSettings.failureActionsOnNonCrash;
    return true;
}


bool ServiceDock::applyServiceFailureSettings(
    const QString& serviceNameText,
    const ServiceRecoverySettings& settings,
    QString* errorTextOut) const
{
    if (serviceNameText.trimmed().isEmpty())
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("恢复配置写入参数无效");
        }
        return false;
    }

    const QString kCommandText = composeRecoveryCommandText(
        settings.programPathText,
        settings.programArgumentsText,
        settings.appendFailureCount);
    const DWORD kRestartDelayMs = static_cast<DWORD>(settings.restartDelayMinutes * 60 * 1000);
    const SC_ACTION_TYPE kActionTypeArray[3]{
        settings.firstActionType,
        settings.secondActionType,
        settings.subsequentActionType
    };

    ks::service::FailureSettings failureSettings;
    failureSettings.resetPeriodSeconds = static_cast<std::uint32_t>(settings.resetPeriodDays * 24 * 60 * 60);
    failureSettings.rebootMessage = settings.rebootMessageText.toStdWString();
    failureSettings.command = kCommandText.toStdWString();
    failureSettings.failureActionsOnNonCrash = settings.failureActionsFlag;
    failureSettings.actions.reserve(3);
    for (int actionIndex = 0; actionIndex < 3; ++actionIndex)
    {
        ks::service::FailureAction action;
        action.type = static_cast<std::uint32_t>(kActionTypeArray[actionIndex]);
        action.delayMs = (kActionTypeArray[actionIndex] == SC_ACTION_RESTART) ? kRestartDelayMs : 0u;
        failureSettings.actions.push_back(action);
    }

    std::string errorText;
    if (!ks::service::applyServiceFailureSettings(
        serviceNameText.trimmed().toStdWString(),
        failureSettings,
        &errorText))
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QString::fromUtf8(errorText.c_str());
        }
        return false;
    }
    return true;
}


void ServiceDock::applyGeneralTabChanges()
{
    const QString kServiceNameText = selectedServiceName();
    const int kServiceIndex = findServiceIndexByName(kServiceNameText);
    if (kServiceIndex < 0 || kServiceIndex >= static_cast<int>(serviceList_.size()))
    {
        return;
    }

    const DWORD kTargetStartType = static_cast<DWORD>(generalStartTypeCombo_->currentData().toULongLong());
    const bool kTargetDelayedAutoStart = generalDelayedAutoCheck_->isChecked();
    const QString kDisplayNameText = generalDisplayNameEdit_->text().trimmed();
    const QString kDescriptionText = generalDescriptionEdit_->toPlainText().trimmed();

    if (kDisplayNameText.isEmpty())
    {
        QMessageBox::warning(this, QStringLiteral("服务管理"), QStringLiteral("显示名不能为空。"));
        return;
    }
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

    ks::service::ServiceConfigUpdate update;
    update.changeStartType = true;
    update.startType = kTargetStartType;
    update.changeDisplayName = true;
    update.displayName = kDisplayNameText.toStdWString();

    std::string errorText;
    if (!ks::service::changeServiceConfiguration(
        kServiceNameText.toStdWString(),
        update,
        &errorText))
    {
        QMessageBox::warning(
            this,
            QStringLiteral("服务管理"),
            QStringLiteral("修改常规属性失败：\n%1").arg(QString::fromUtf8(errorText.c_str())));
        return;
    }

    // Description and delayed-auto writes remain best-effort to preserve prior UI behavior.
    (void)ks::service::setServiceDescription(kServiceNameText.toStdWString(), kDescriptionText.toStdWString());
    (void)ks::service::setDelayedAutoStart(
        kServiceNameText.toStdWString(),
        kTargetStartType == SERVICE_AUTO_START && kTargetDelayedAutoStart);

    refreshSelectedService();
}


void ServiceDock::applyLogonTabChanges()
{
    const QString kServiceNameText = selectedServiceName();
    const int kServiceIndex = findServiceIndexByName(kServiceNameText);
    if (kServiceIndex < 0 || kServiceIndex >= static_cast<int>(serviceList_.size()))
    {
        return;
    }

    const ServiceEntry& selectedEntry = serviceList_[static_cast<std::size_t>(kServiceIndex)];
    const bool kUseLocalSystem = logonLocalSystemRadio_->isChecked();
    const QString kAccountText = logonAccountEdit_->text().trimmed();
    const QString kPasswordText = logonPasswordEdit_->text();
    const QString kConfirmPasswordText = logonConfirmPasswordEdit_->text();

    if (!kUseLocalSystem && kAccountText.isEmpty())
    {
        QMessageBox::warning(this, QStringLiteral("服务管理"), QStringLiteral("登录帐户不能为空。"));
        return;
    }
    if (!kUseLocalSystem && kPasswordText != kConfirmPasswordText)
    {
        QMessageBox::warning(this, QStringLiteral("服务管理"), QStringLiteral("两次输入的密码不一致。"));
        return;
    }

    const DWORD kBaseServiceType = selectedEntry.serviceTypeValue & (~SERVICE_INTERACTIVE_PROCESS);
    const DWORD kTargetServiceType = (kUseLocalSystem && logonDesktopInteractCheck_->isChecked())
        ? (kBaseServiceType | SERVICE_INTERACTIVE_PROCESS)
        : kBaseServiceType;

    ks::service::ServiceConfigUpdate update;
    update.changeServiceType = true;
    update.serviceType = kTargetServiceType;
    update.changeAccount = true;
    update.accountName = kUseLocalSystem ? std::wstring(L"LocalSystem") : kAccountText.toStdWString();
    if (!kUseLocalSystem && (!kPasswordText.isEmpty() || QString::compare(kAccountText, selectedEntry.accountText, Qt::CaseInsensitive) != 0))
    {
        update.changePassword = true;
        update.password = kPasswordText.toStdWString();
    }

    std::string errorText;
    if (!ks::service::changeServiceConfiguration(
        kServiceNameText.toStdWString(),
        update,
        &errorText))
    {
        QMessageBox::warning(
            this,
            QStringLiteral("服务管理"),
            QStringLiteral("修改登录属性失败：\n%1").arg(QString::fromUtf8(errorText.c_str())));
        return;
    }

    refreshSelectedService();
}


void ServiceDock::applyRecoveryTabChanges()
{
    const QString kServiceNameText = selectedServiceName();
    if (kServiceNameText.isEmpty())
    {
        return;
    }

    ServiceRecoverySettings settings;
    settings.firstActionType = static_cast<SC_ACTION_TYPE>(recoveryFirstActionCombo_->currentData().toInt());
    settings.secondActionType = static_cast<SC_ACTION_TYPE>(recoverySecondActionCombo_->currentData().toInt());
    settings.subsequentActionType = static_cast<SC_ACTION_TYPE>(recoverySubsequentActionCombo_->currentData().toInt());
    settings.resetPeriodDays = recoveryResetDaysSpin_->value();
    settings.restartDelayMinutes = recoveryRestartMinutesSpin_->value();
    settings.failureActionsFlag = recoveryFailureActionsFlagCheck_->isChecked();
    settings.rebootMessageText = recoveryRebootMessageEdit_->text().trimmed();
    settings.programPathText = recoveryProgramEdit_->text().trimmed();
    settings.programArgumentsText = recoveryArgumentsEdit_->text().trimmed();
    settings.appendFailureCount = recoveryAppendFailCountCheck_->isChecked();

    QString errorText;
    if (!applyServiceFailureSettings(kServiceNameText, settings, &errorText))
    {
        QMessageBox::warning(this, QStringLiteral("服务管理"), QStringLiteral("修改恢复属性失败：\n%1").arg(errorText));
        return;
    }

    refreshSelectedService();
}
