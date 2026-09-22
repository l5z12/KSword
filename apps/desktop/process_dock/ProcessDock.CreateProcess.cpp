#include "ProcessDock.Support.h"
#include "ProcessActivityChartWidget.h"
#include "ProcessActivityTimelineSlider.h"

using namespace ksword::ui::process_dock;

void ProcessDock::appendCreateResultLine(const QString& lineText)
{
    if (createResultOutput_ == nullptr)
    {
        return;
    }

    // The result box mixes fixed prompts with backend raw details; only hit-able fixed prompts are converted, while original error content remains verbatim.
    const QString kTimeText = QDateTime::currentDateTime().toString("HH:mm:ss");
    createResultOutput_->append(QString("[%1] %2").arg(
        kTimeText,
        ks::i18n::sourceText(lineText)));
}

void ProcessDock::browseCreateProcessApplicationPath()
{
    const QString kFilePath = QFileDialog::getOpenFileName(
        this,
        "选择可执行文件",
        applicationNameEdit_ != nullptr ? applicationNameEdit_->text().trimmed() : QString(),
        "Executable (*.exe);;All Files (*.*)");
    if (kFilePath.isEmpty())
    {
        return;
    }

    if (applicationNameEdit_ != nullptr)
    {
        applicationNameEdit_->setText(kFilePath);
    }
    if (useApplicationNameCheck_ != nullptr)
    {
        useApplicationNameCheck_->setChecked(true);
    }
}

void ProcessDock::browseCreateProcessCurrentDirectory()
{
    const QString kStartPath = currentDirectoryEdit_ != nullptr
        ? currentDirectoryEdit_->text().trimmed()
        : QString();
    const QString kDirectoryPath = QFileDialog::getExistingDirectory(
        this,
        "选择工作目录",
        kStartPath);
    if (kDirectoryPath.isEmpty())
    {
        return;
    }

    if (currentDirectoryEdit_ != nullptr)
    {
        currentDirectoryEdit_->setText(kDirectoryPath);
    }
    if (useCurrentDirectoryCheck_ != nullptr)
    {
        useCurrentDirectoryCheck_->setChecked(true);
    }
}

void ProcessDock::resetCreateProcessForm()
{
    if (createMethodCombo_ != nullptr) createMethodCombo_->setCurrentIndex(0);
    if (useApplicationNameCheck_ != nullptr) useApplicationNameCheck_->setChecked(false);
    if (applicationNameEdit_ != nullptr) applicationNameEdit_->clear();
    if (useCommandLineCheck_ != nullptr) useCommandLineCheck_->setChecked(false);
    if (commandLineEdit_ != nullptr) commandLineEdit_->clear();
    if (useCurrentDirectoryCheck_ != nullptr) useCurrentDirectoryCheck_->setChecked(false);
    if (currentDirectoryEdit_ != nullptr) currentDirectoryEdit_->clear();
    if (useEnvironmentCheck_ != nullptr) useEnvironmentCheck_->setChecked(false);
    if (environmentUnicodeCheck_ != nullptr) environmentUnicodeCheck_->setChecked(true);
    if (environmentEditor_ != nullptr) environmentEditor_->clear();
    if (inheritHandleCheck_ != nullptr) inheritHandleCheck_->setChecked(false);
    if (creationFlagsEdit_ != nullptr) creationFlagsEdit_->setText("0x00000000");

    if (useProcessSecurityCheck_ != nullptr) useProcessSecurityCheck_->setChecked(false);
    if (processSecurityLengthEdit_ != nullptr) processSecurityLengthEdit_->setText("0");
    if (processSecurityDescriptorEdit_ != nullptr) processSecurityDescriptorEdit_->setText("0");
    if (processSecurityInheritCheck_ != nullptr) processSecurityInheritCheck_->setChecked(false);
    if (useThreadSecurityCheck_ != nullptr) useThreadSecurityCheck_->setChecked(false);
    if (threadSecurityLengthEdit_ != nullptr) threadSecurityLengthEdit_->setText("0");
    if (threadSecurityDescriptorEdit_ != nullptr) threadSecurityDescriptorEdit_->setText("0");
    if (threadSecurityInheritCheck_ != nullptr) threadSecurityInheritCheck_->setChecked(false);

    if (useStartupInfoCheck_ != nullptr) useStartupInfoCheck_->setChecked(true);
    if (siCbEdit_ != nullptr) siCbEdit_->setText("0");
    if (siReservedEdit_ != nullptr) siReservedEdit_->clear();
    if (siDesktopEdit_ != nullptr) siDesktopEdit_->clear();
    if (siTitleEdit_ != nullptr) siTitleEdit_->clear();
    if (siXEdit_ != nullptr) siXEdit_->setText("0");
    if (siYEdit_ != nullptr) siYEdit_->setText("0");
    if (siXSizeEdit_ != nullptr) siXSizeEdit_->setText("0");
    if (siYSizeEdit_ != nullptr) siYSizeEdit_->setText("0");
    if (siXCountCharsEdit_ != nullptr) siXCountCharsEdit_->setText("0");
    if (siYCountCharsEdit_ != nullptr) siYCountCharsEdit_->setText("0");
    if (siFillAttributeEdit_ != nullptr) siFillAttributeEdit_->setText("0x00000000");
    if (siFlagsEdit_ != nullptr) siFlagsEdit_->setText("0x00000000");
    if (siShowWindowEdit_ != nullptr) siShowWindowEdit_->setText("0");
    if (siCbReserved2Edit_ != nullptr) siCbReserved2Edit_->setText("0");
    if (siReserved2PtrEdit_ != nullptr) siReserved2PtrEdit_->setText("0");
    if (siStdInputEdit_ != nullptr) siStdInputEdit_->setText("0");
    if (siStdOutputEdit_ != nullptr) siStdOutputEdit_->setText("0");
    if (siStdErrorEdit_ != nullptr) siStdErrorEdit_->setText("0");

    if (useProcessInfoCheck_ != nullptr) useProcessInfoCheck_->setChecked(true);
    if (piProcessHandleEdit_ != nullptr) piProcessHandleEdit_->setText("0");
    if (piThreadHandleEdit_ != nullptr) piThreadHandleEdit_->setText("0");
    if (piPidEdit_ != nullptr) piPidEdit_->setText("0");
    if (piTidEdit_ != nullptr) piTidEdit_->setText("0");

    if (tokenSourcePidEdit_ != nullptr) tokenSourcePidEdit_->setText("0");
    if (tokenDesiredAccessEdit_ != nullptr) tokenDesiredAccessEdit_->setText("0x00000FAB");
    if (tokenDuplicatePrimaryCheck_ != nullptr) tokenDuplicatePrimaryCheck_->setChecked(true);

    if (tokenPrivilegeTable_ != nullptr)
    {
        for (int row = 0; row < tokenPrivilegeTable_->rowCount(); ++row)
        {
            QComboBox* actionCombo = qobject_cast<QComboBox*>(tokenPrivilegeTable_->cellWidget(row, 1));
            if (actionCombo != nullptr)
            {
                actionCombo->setCurrentIndex(0);
            }
        }
    }

    if (createResultOutput_ != nullptr)
    {
        createResultOutput_->clear();
    }
    appendCreateResultLine("已恢复创建进程表单默认值。");
}

ks::process::CreateProcessRequest ProcessDock::buildCreateProcessRequestFromUi(
    bool* const buildOk,
    QString* const errorTextOut) const
{
    ks::process::CreateProcessRequest request;
    if (buildOk != nullptr)
    {
        *buildOk = false;
    }

    const auto kFailBuild = [errorTextOut](const QString& textValue) {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = textValue;
        }
        };

    request.useApplicationName = (useApplicationNameCheck_ != nullptr && useApplicationNameCheck_->isChecked());
    request.applicationName = (applicationNameEdit_ != nullptr) ? applicationNameEdit_->text().trimmed().toStdString() : std::string();

    request.useCommandLine = (useCommandLineCheck_ != nullptr && useCommandLineCheck_->isChecked());
    request.commandLine = (commandLineEdit_ != nullptr) ? commandLineEdit_->text().trimmed().toStdString() : std::string();

    request.useCurrentDirectory = (useCurrentDirectoryCheck_ != nullptr && useCurrentDirectoryCheck_->isChecked());
    request.currentDirectory = (currentDirectoryEdit_ != nullptr) ? currentDirectoryEdit_->text().trimmed().toStdString() : std::string();

    request.useEnvironment = (useEnvironmentCheck_ != nullptr && useEnvironmentCheck_->isChecked());
    request.environmentUnicode = (environmentUnicodeCheck_ != nullptr && environmentUnicodeCheck_->isChecked());
    if (request.useEnvironment && environmentEditor_ != nullptr)
    {
        // lpEnvironment semantics:
        // - When at least one KEY=VALUE line is checked and filled, the backend constructs the environment block according to the Unicode/ANSI option;
        // - If checked but empty, pass nullptr as per the UI hint to indicate inheriting the parent process environment;
        // - This avoids converting an empty editor into an "empty environment block," which would cause child processes to miss base variables like PATH.
        const QStringList kEnvLines = environmentEditor_->toPlainText().split('\n');
        for (const QString& lineText : kEnvLines)
        {
            const QString kTrimmedText = lineText.trimmed();
            if (!kTrimmedText.isEmpty())
            {
                request.environmentEntries.push_back(kTrimmedText.toStdString());
            }
        }
        if (request.environmentEntries.empty())
        {
            request.useEnvironment = false;
        }
    }

    request.inheritHandles = (inheritHandleCheck_ != nullptr && inheritHandleCheck_->isChecked());

    bool parseOk = false;
    request.creationFlags = parseUInt32WithDefault(
        creationFlagsEdit_ != nullptr ? creationFlagsEdit_->text() : QString(),
        0,
        &parseOk);
    if (!parseOk)
    {
        kFailBuild("dwCreationFlags 解析失败，请输入十进制或 0x 十六进制。");
        return request;
    }
    // CREATE_UNICODE_ENVIRONMENT can be expressed via a dedicated checkbox or manually combined via the dwCreationFlags bit flag.
    // Here, merge backwards based on the final flags to prevent a mismatch where UI flags already contain the Unicode bit but the environment block is constructed as ANSI.
    if ((request.creationFlags & 0x00000400U) != 0U)
    {
        request.environmentUnicode = true;
    }

    request.processAttributes.useValue = (useProcessSecurityCheck_ != nullptr && useProcessSecurityCheck_->isChecked());
    if (request.processAttributes.useValue)
    {
        request.processAttributes.nLength = parseUInt32WithDefault(
            processSecurityLengthEdit_ != nullptr ? processSecurityLengthEdit_->text() : QString(),
            0,
            &parseOk);
        if (!parseOk)
        {
            kFailBuild("Process SECURITY_ATTRIBUTES.nLength 解析失败。");
            return request;
        }
        request.processAttributes.securityDescriptor = parseUInt64WithDefault(
            processSecurityDescriptorEdit_ != nullptr ? processSecurityDescriptorEdit_->text() : QString(),
            0,
            &parseOk);
        if (!parseOk)
        {
            kFailBuild("Process SECURITY_ATTRIBUTES.lpSecurityDescriptor 解析失败。");
            return request;
        }
        request.processAttributes.inheritHandle = (processSecurityInheritCheck_ != nullptr && processSecurityInheritCheck_->isChecked());
    }

    request.threadAttributes.useValue = (useThreadSecurityCheck_ != nullptr && useThreadSecurityCheck_->isChecked());
    if (request.threadAttributes.useValue)
    {
        request.threadAttributes.nLength = parseUInt32WithDefault(
            threadSecurityLengthEdit_ != nullptr ? threadSecurityLengthEdit_->text() : QString(),
            0,
            &parseOk);
        if (!parseOk)
        {
            kFailBuild("Thread SECURITY_ATTRIBUTES.nLength 解析失败。");
            return request;
        }
        request.threadAttributes.securityDescriptor = parseUInt64WithDefault(
            threadSecurityDescriptorEdit_ != nullptr ? threadSecurityDescriptorEdit_->text() : QString(),
            0,
            &parseOk);
        if (!parseOk)
        {
            kFailBuild("Thread SECURITY_ATTRIBUTES.lpSecurityDescriptor 解析失败。");
            return request;
        }
        request.threadAttributes.inheritHandle = (threadSecurityInheritCheck_ != nullptr && threadSecurityInheritCheck_->isChecked());
    }

    request.startupInfo.useValue = (useStartupInfoCheck_ != nullptr && useStartupInfoCheck_->isChecked());
    if (request.startupInfo.useValue)
    {
        request.startupInfo.cb = parseUInt32WithDefault(siCbEdit_ != nullptr ? siCbEdit_->text() : QString(), 0, &parseOk);
        if (!parseOk) { kFailBuild("STARTUPINFO.cb 解析失败。"); return request; }
        request.startupInfo.lpReserved = (siReservedEdit_ != nullptr ? siReservedEdit_->text() : QString()).toStdString();
        request.startupInfo.lpDesktop = (siDesktopEdit_ != nullptr ? siDesktopEdit_->text() : QString()).toStdString();
        request.startupInfo.lpTitle = (siTitleEdit_ != nullptr ? siTitleEdit_->text() : QString()).toStdString();
        request.startupInfo.dwX = parseUInt32WithDefault(siXEdit_ != nullptr ? siXEdit_->text() : QString(), 0, &parseOk);
        if (!parseOk) { kFailBuild("STARTUPINFO.dwX 解析失败。"); return request; }
        request.startupInfo.dwY = parseUInt32WithDefault(siYEdit_ != nullptr ? siYEdit_->text() : QString(), 0, &parseOk);
        if (!parseOk) { kFailBuild("STARTUPINFO.dwY 解析失败。"); return request; }
        request.startupInfo.dwXSize = parseUInt32WithDefault(siXSizeEdit_ != nullptr ? siXSizeEdit_->text() : QString(), 0, &parseOk);
        if (!parseOk) { kFailBuild("STARTUPINFO.dwXSize 解析失败。"); return request; }
        request.startupInfo.dwYSize = parseUInt32WithDefault(siYSizeEdit_ != nullptr ? siYSizeEdit_->text() : QString(), 0, &parseOk);
        if (!parseOk) { kFailBuild("STARTUPINFO.dwYSize 解析失败。"); return request; }
        request.startupInfo.dwXCountChars = parseUInt32WithDefault(siXCountCharsEdit_ != nullptr ? siXCountCharsEdit_->text() : QString(), 0, &parseOk);
        if (!parseOk) { kFailBuild("STARTUPINFO.dwXCountChars 解析失败。"); return request; }
        request.startupInfo.dwYCountChars = parseUInt32WithDefault(siYCountCharsEdit_ != nullptr ? siYCountCharsEdit_->text() : QString(), 0, &parseOk);
        if (!parseOk) { kFailBuild("STARTUPINFO.dwYCountChars 解析失败。"); return request; }
        request.startupInfo.dwFillAttribute = parseUInt32WithDefault(siFillAttributeEdit_ != nullptr ? siFillAttributeEdit_->text() : QString(), 0, &parseOk);
        if (!parseOk) { kFailBuild("STARTUPINFO.dwFillAttribute 解析失败。"); return request; }
        request.startupInfo.dwFlags = parseUInt32WithDefault(siFlagsEdit_ != nullptr ? siFlagsEdit_->text() : QString(), 0, &parseOk);
        if (!parseOk) { kFailBuild("STARTUPINFO.dwFlags 解析失败。"); return request; }
        request.startupInfo.wShowWindow = static_cast<std::uint16_t>(
            parseUInt32WithDefault(siShowWindowEdit_ != nullptr ? siShowWindowEdit_->text() : QString(), 0, &parseOk));
        if (!parseOk) { kFailBuild("STARTUPINFO.wShowWindow 解析失败。"); return request; }
        request.startupInfo.cbReserved2 = static_cast<std::uint16_t>(
            parseUInt32WithDefault(siCbReserved2Edit_ != nullptr ? siCbReserved2Edit_->text() : QString(), 0, &parseOk));
        if (!parseOk) { kFailBuild("STARTUPINFO.cbReserved2 解析失败。"); return request; }
        request.startupInfo.lpReserved2 = parseUInt64WithDefault(siReserved2PtrEdit_ != nullptr ? siReserved2PtrEdit_->text() : QString(), 0, &parseOk);
        if (!parseOk) { kFailBuild("STARTUPINFO.lpReserved2 解析失败。"); return request; }
        request.startupInfo.hStdInput = parseUInt64WithDefault(siStdInputEdit_ != nullptr ? siStdInputEdit_->text() : QString(), 0, &parseOk);
        if (!parseOk) { kFailBuild("STARTUPINFO.hStdInput 解析失败。"); return request; }
        request.startupInfo.hStdOutput = parseUInt64WithDefault(siStdOutputEdit_ != nullptr ? siStdOutputEdit_->text() : QString(), 0, &parseOk);
        if (!parseOk) { kFailBuild("STARTUPINFO.hStdOutput 解析失败。"); return request; }
        request.startupInfo.hStdError = parseUInt64WithDefault(siStdErrorEdit_ != nullptr ? siStdErrorEdit_->text() : QString(), 0, &parseOk);
        if (!parseOk) { kFailBuild("STARTUPINFO.hStdError 解析失败。"); return request; }
    }

    request.processInfo.useValue = (useProcessInfoCheck_ != nullptr && useProcessInfoCheck_->isChecked());
    if (request.processInfo.useValue)
    {
        request.processInfo.hProcess = parseUInt64WithDefault(piProcessHandleEdit_ != nullptr ? piProcessHandleEdit_->text() : QString(), 0, &parseOk);
        if (!parseOk) { kFailBuild("PROCESS_INFORMATION.hProcess 解析失败。"); return request; }
        request.processInfo.hThread = parseUInt64WithDefault(piThreadHandleEdit_ != nullptr ? piThreadHandleEdit_->text() : QString(), 0, &parseOk);
        if (!parseOk) { kFailBuild("PROCESS_INFORMATION.hThread 解析失败。"); return request; }
        request.processInfo.dwProcessId = parseUInt32WithDefault(piPidEdit_ != nullptr ? piPidEdit_->text() : QString(), 0, &parseOk);
        if (!parseOk) { kFailBuild("PROCESS_INFORMATION.dwProcessId 解析失败。"); return request; }
        request.processInfo.dwThreadId = parseUInt32WithDefault(piTidEdit_ != nullptr ? piTidEdit_->text() : QString(), 0, &parseOk);
        if (!parseOk) { kFailBuild("PROCESS_INFORMATION.dwThreadId 解析失败。"); return request; }
    }

    request.tokenModeEnabled = (createMethodCombo_ != nullptr && createMethodCombo_->currentIndex() == 1);
    if (request.tokenModeEnabled)
    {
        request.tokenSourcePid = parseUInt32WithDefault(
            tokenSourcePidEdit_ != nullptr ? tokenSourcePidEdit_->text() : QString(),
            0,
            &parseOk);
        if (!parseOk)
        {
            kFailBuild("Token 模式 source PID 解析失败。");
            return request;
        }
        request.tokenDesiredAccess = parseUInt32WithDefault(
            tokenDesiredAccessEdit_ != nullptr ? tokenDesiredAccessEdit_->text() : QString(),
            0,
            &parseOk);
        if (!parseOk)
        {
            kFailBuild("Token 模式 desired access 解析失败。");
            return request;
        }
        request.duplicatePrimaryToken = (tokenDuplicatePrimaryCheck_ != nullptr && tokenDuplicatePrimaryCheck_->isChecked());

        if (tokenPrivilegeTable_ != nullptr)
        {
            for (int row = 0; row < tokenPrivilegeTable_->rowCount(); ++row)
            {
                QTableWidgetItem* privilegeItem = tokenPrivilegeTable_->item(row, 0);
                QComboBox* actionCombo = qobject_cast<QComboBox*>(tokenPrivilegeTable_->cellWidget(row, 1));
                if (privilegeItem == nullptr || actionCombo == nullptr)
                {
                    continue;
                }

                const auto kActionValue = static_cast<ks::process::TokenPrivilegeAction>(
                    actionCombo->currentData().toInt());
                if (kActionValue == ks::process::TokenPrivilegeAction::kKeep)
                {
                    continue;
                }

                ks::process::TokenPrivilegeEdit editItem{};
                editItem.privilegeName = privilegeItem->text().trimmed().toStdString();
                editItem.action = kActionValue;
                request.tokenPrivilegeEdits.push_back(std::move(editItem));
            }
        }
    }

    if (buildOk != nullptr)
    {
        *buildOk = true;
    }
    if (errorTextOut != nullptr)
    {
        errorTextOut->clear();
    }
    return request;
}

bool ProcessDock::buildTokenPrivilegeEditRequestFromUi(
    ks::process::CreateProcessRequest* const requestOut,
    QString* const errorTextOut) const
{
    // Note: When applying token adjustments only, parameters such as path, environment, and STARTUPINFO for CreateProcessW are not required.
    // Input: requestOut receives the Token field; errorTextOut receives the reason for parsing failure.
    // Handling: Validate only Token mode, source PID, DesiredAccess, and privilege table actions.
    // Returns: true indicates applyTokenPrivilegeEditsByPid can be called; false indicates UI parameters do not meet privilege adjustment requirements.
    if (requestOut == nullptr)
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = "内部错误：requestOut 为空。";
        }
        return false;
    }

    ks::process::CreateProcessRequest request;
    request.tokenModeEnabled = (createMethodCombo_ != nullptr && createMethodCombo_->currentIndex() == 1);
    if (!request.tokenModeEnabled)
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = "当前不是 Token 模式，无法仅应用令牌调整。";
        }
        return false;
    }

    bool parseOk = false;
    request.tokenSourcePid = parseUInt32WithDefault(
        tokenSourcePidEdit_ != nullptr ? tokenSourcePidEdit_->text() : QString(),
        0,
        &parseOk);
    if (!parseOk)
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = "Token 模式 source PID 解析失败。";
        }
        return false;
    }

    request.tokenDesiredAccess = parseUInt32WithDefault(
        tokenDesiredAccessEdit_ != nullptr ? tokenDesiredAccessEdit_->text() : QString(),
        0,
        &parseOk);
    if (!parseOk)
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = "Token 模式 desired access 解析失败。";
        }
        return false;
    }

    request.duplicatePrimaryToken = (tokenDuplicatePrimaryCheck_ != nullptr && tokenDuplicatePrimaryCheck_->isChecked());
    if (tokenPrivilegeTable_ != nullptr)
    {
        for (int row = 0; row < tokenPrivilegeTable_->rowCount(); ++row)
        {
            QTableWidgetItem* privilegeItem = tokenPrivilegeTable_->item(row, 0);
            QComboBox* actionCombo = qobject_cast<QComboBox*>(tokenPrivilegeTable_->cellWidget(row, 1));
            if (privilegeItem == nullptr || actionCombo == nullptr)
            {
                continue;
            }

            const auto kActionValue = static_cast<ks::process::TokenPrivilegeAction>(
                actionCombo->currentData().toInt());
            if (kActionValue == ks::process::TokenPrivilegeAction::kKeep)
            {
                continue;
            }

            ks::process::TokenPrivilegeEdit editItem{};
            editItem.privilegeName = privilegeItem->text().trimmed().toStdString();
            editItem.action = kActionValue;
            request.tokenPrivilegeEdits.push_back(std::move(editItem));
        }
    }

    *requestOut = std::move(request);
    if (errorTextOut != nullptr)
    {
        errorTextOut->clear();
    }
    return true;
}

void ProcessDock::executeApplyTokenPrivilegeEditsOnly()
{
    // Token adjustment action log: the entire flow reuses the same KLogEvent to avoid fragmented call chains.
    KLogEvent actionEvent;
    QString errorText;
    ks::process::CreateProcessRequest request;
    if (!buildTokenPrivilegeEditRequestFromUi(&request, &errorText))
    {
        appendCreateResultLine(ks::i18n::sourceText(QStringLiteral("参数解析失败: ")) + errorText);
        err << actionEvent
            << "[ProcessDock] 令牌调整参数解析失败, error="
            << errorText.toStdString()
            << eol;
        return;
    }

    std::string detailText;
    const bool kAdjustOk = ks::process::applyTokenPrivilegeEditsByPid(
        request.tokenSourcePid,
        request.tokenDesiredAccess,
        request.duplicatePrimaryToken,
        request.tokenPrivilegeEdits,
        &detailText);
    std::ostringstream desiredAccessStream;
    desiredAccessStream << "0x" << std::uppercase << std::hex << request.tokenDesiredAccess;

    appendCreateResultLine(ks::i18n::sourceText(QStringLiteral("令牌调整结果: %1")).arg(
        ks::i18n::sourceText(kAdjustOk ? QStringLiteral("成功") : QStringLiteral("失败"))));
    appendCreateResultLine(detailText.empty()
        ? ks::i18n::sourceText(QStringLiteral("无附加信息"))
        : QString::fromStdString(detailText));
    (kAdjustOk ? info : err) << actionEvent
        << "[ProcessDock] 令牌调整完成, ok=" << (kAdjustOk ? "true" : "false")
        << ", sourcePid=" << request.tokenSourcePid
        << ", desiredAccess=" << desiredAccessStream.str()
        << ", duplicatePrimary=" << (request.duplicatePrimaryToken ? "true" : "false")
        << ", editCount=" << request.tokenPrivilegeEdits.size()
        << ", detail=" << (detailText.empty() ? "无附加信息" : detailText)
        << eol;
}

void ProcessDock::executeCreateProcessRequest()
{
    // Create process action log: the entire flow reuses the same KLogEvent to avoid discrete call chains.
    KLogEvent createProcessEvent;
    bool buildOk = false;
    QString errorText;
    const ks::process::CreateProcessRequest kRequest = buildCreateProcessRequestFromUi(&buildOk, &errorText);
    if (!buildOk)
    {
        appendCreateResultLine(ks::i18n::sourceText(QStringLiteral("参数解析失败: ")) + errorText);
        err << createProcessEvent
            << "[ProcessDock] CreateProcess 参数解析失败, error="
            << errorText.toStdString()
            << eol;
        return;
    }

    ks::process::CreateProcessResult createResult{};
    const bool kLaunchOk = ks::process::launchProcess(kRequest, &createResult);
    appendCreateResultLine(ks::i18n::sourceText(QStringLiteral("调用结果: %1")).arg(
        ks::i18n::sourceText(kLaunchOk ? QStringLiteral("成功") : QStringLiteral("失败"))));
    appendCreateResultLine(ks::i18n::sourceText(QStringLiteral("路径模式: %1")).arg(
        createResult.usedTokenPath ? QStringLiteral("Token") : QStringLiteral("CreateProcessW")));
    appendCreateResultLine(ks::i18n::sourceText(QStringLiteral("错误码: %1")).arg(createResult.win32Error));
    appendCreateResultLine(QString::fromStdString(createResult.detailText));
    if (createResult.processInfoAvailable)
    {
        appendCreateResultLine(
            ks::i18n::sourceText(QStringLiteral(
                "输出 PI: pid=%1 tid=%2（后端已关闭返回的 hProcess/hThread 句柄快照: 0x%3 / 0x%4）"))
            .arg(createResult.dwProcessId)
            .arg(createResult.dwThreadId)
            .arg(QString::number(createResult.hProcess, 16))
            .arg(QString::number(createResult.hThread, 16)));
    }

    (kLaunchOk ? info : err) << createProcessEvent
        << "[ProcessDock] CreateProcess 请求完成, ok=" << (kLaunchOk ? "true" : "false")
        << ", tokenMode=" << (kRequest.tokenModeEnabled ? "true" : "false")
        << ", error=" << createResult.win32Error
        << ", detail=" << createResult.detailText
        << eol;

    if (kLaunchOk)
    {
        requestAsyncRefresh(true);
    }
}
