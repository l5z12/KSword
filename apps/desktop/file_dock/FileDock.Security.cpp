#include "FileDock.Support.h"

using namespace ksword::ui::file_dock;

void FileDock::takeOwnershipSelectedItems(FilePanelWidgets& panel)
{
    const std::vector<QString> kPaths = selectedPaths(panel);
    if (kPaths.empty())
    {
        return;
    }

    if (!ks::ui::isCurrentProcessElevated())
    {
        (void)ks::ui::requestAdministratorRestartForFeature(
            this,
            QStringLiteral("取得文件所有权并授予完全控制"));
        return;
    }

    KLogEvent startEvent;
    info << startEvent
        << "[FileDock] 取得所有权请求, panel="
        << panel.panelNameText.toStdString()
        << ", count="
        << kPaths.size()
        << eol;

    const QMessageBox::StandardButton kUserChoice = QMessageBox::question(
        this,
        QStringLiteral("取得所有权"),
        QStringLiteral("将对选中的 %1 项执行“取得所有权 + 完全控制授权”。\n此操作可能需要管理员权限，是否继续？")
        .arg(kPaths.size()),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kUserChoice != QMessageBox::Yes)
    {
        return;
    }

    const int kProgressPid = kPro.add(this, "文件", "取得所有权");
    kPro.set(kProgressPid, "准备执行", 0, 5.0f);

    const bool kLeftPanelRequest = (&panel == &leftPanel_);
    const QString kPanelNameText = panel.panelNameText;
    QPointer<FileDock> safeThis(this);
    std::thread([safeThis, kPaths, kProgressPid, kLeftPanelRequest, kPanelNameText]()
    {
        QStringList errorDetails;
        for (std::size_t index = 0; index < kPaths.size(); ++index)
        {
            const QString& targetPath = kPaths[index];
            QString detailText;
            const bool kItemOk = takeOwnershipBySystemCommand(targetPath, detailText);
            if (!kItemOk)
            {
                errorDetails.push_back(detailText);
            }

            const float kProgress = 5.0f + (static_cast<float>(index + 1) / static_cast<float>(kPaths.size())) * 90.0f;
            kPro.set(kProgressPid, "处理中", 0, kProgress);
        }
        kPro.set(kProgressPid, "完成", 0, 100.0f);

        if (safeThis.isNull())
        {
            kPro.set(kProgressPid, "界面已关闭", 0, 100.0f);
            return;
        }

        const bool kInvokeOk = QMetaObject::invokeMethod(
            safeThis.data(),
            [safeThis, kProgressPid, kLeftPanelRequest, kPanelNameText, kPaths, errorDetails]()
            {
                if (safeThis.isNull())
                {
                    kPro.set(kProgressPid, "界面已关闭", 0, 100.0f);
                    return;
                }

                FilePanelWidgets& targetPanel = kLeftPanelRequest ? safeThis->leftPanel_ : safeThis->rightPanel_;
                const auto kRefreshTargetPanel = [safeThis, kLeftPanelRequest]()
                {
                    if (!safeThis.isNull())
                    {
                        FilePanelWidgets& commitPanel =
                            kLeftPanelRequest ? safeThis->leftPanel_ : safeThis->rightPanel_;
                        safeThis->refreshPanel(commitPanel);
                    }
                };
                const QString kRefreshKey = kLeftPanelRequest
                    ? QStringLiteral("file-ownership-refresh-left")
                    : QStringLiteral("file-ownership-refresh-right");
                if (!ks::ui::deferItemViewUiCommitIfContextMenuOpen(
                    safeThis.data(),
                    kRefreshKey,
                    { targetPanel.fileView },
                    kRefreshTargetPanel))
                {
                    kRefreshTargetPanel();
                }
                if (!errorDetails.isEmpty())
                {
                    KLogEvent failEvent;
                    warn << failEvent
                        << "[FileDock] 取得所有权部分失败, panel="
                        << kPanelNameText.toStdString()
                        << ", failCount="
                        << errorDetails.size()
                        << ", detailPreview=\n"
                        << buildLogPreviewText(errorDetails).toStdString()
                        << eol;
                    return;
                }

                KLogEvent finishEvent;
                info << finishEvent
                    << "[FileDock] 取得所有权完成, panel="
                    << kPanelNameText.toStdString()
                    << ", successCount="
                    << kPaths.size()
                    << eol;
            },
            Qt::QueuedConnection);
        if (!kInvokeOk)
        {
            kPro.set(kProgressPid, "回调失败", 0, 100.0f);
        }
    }).detach();
}

void FileDock::setSelectedFileIntegrityLevel(
    FilePanelWidgets& panel,
    const unsigned long integrityRid,
    const QString& levelDisplayText)
{
    // Input: Currently selected items in the panel, target integrity RID, and display text.
    // Processing: Call R0 kernel APIs to write LABEL_SECURITY_INFORMATION one by one; fall back to R3 if the driver is unavailable or outdated, and aggregate failed items.
    // Return: No return value; success/failure feedback via logs, progress bar, and message box.
    const std::vector<QString> kPaths = selectedPaths(panel);
    if (kPaths.empty())
    {
        KLogEvent emptyEvent;
        warn << emptyEvent
            << "[FileDock] 设置文件完整性被忽略：未选中路径, panel="
            << panel.panelNameText.toStdString()
            << eol;
        return;
    }

    const QMessageBox::StandardButton kUserChoice = QMessageBox::question(
        this,
        QStringLiteral("设置文件完整性"),
        QStringLiteral("将对选中的 %1 项写入文件 Mandatory Label：%2。\n"
            "该操作会影响低/中/高完整性进程对对象的写入权限，可能需要管理员权限。是否继续？")
            .arg(kPaths.size())
            .arg(levelDisplayText),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kUserChoice != QMessageBox::Yes)
    {
        return;
    }

    const DWORD kTargetIntegrityRid = static_cast<DWORD>(integrityRid);
    const int kProgressPid = kPro.add(this, "文件", "设置文件完整性");
    kPro.set(kProgressPid, "准备执行", 0, 5.0f);

    QStringList failureDetails;
    std::size_t successCount = 0U;
    // privilegePromptHandled: Shows the privilege restoration prompt at most once when multiple targets fail, suppressing duplicate popups at the end.
    bool privilegePromptHandled = false;
    for (std::size_t index = 0; index < kPaths.size(); ++index)
    {
        const QString& targetPath = kPaths[index];
        QString detailText;
        const DWORD kResult = setFileIntegrityLevelByR0ThenR3(
            targetPath,
            kTargetIntegrityRid,
            &detailText);
        if (kResult == ERROR_SUCCESS)
        {
            successCount += 1U;
            KLogEvent itemEvent;
            info << itemEvent
                << "[FileDock] 设置文件完整性成功, panel="
                << panel.panelNameText.toStdString()
                << ", path="
                << QDir::toNativeSeparators(targetPath).toStdString()
                << ", rid=0x"
                << QString::number(kTargetIntegrityRid, 16).toStdString()
                << ", detail="
                << detailText.toStdString()
                << eol;
        }
        else
        {
            if (!privilegePromptHandled)
            {
                privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
                    this,
                    QStringLiteral("设置文件完整性级别"),
                    kResult);
            }
            failureDetails.push_back(QStringLiteral("%1 | code=%2 | %3")
                .arg(QDir::toNativeSeparators(targetPath))
                .arg(kResult)
                .arg(detailText));
        }

        const float kProgress = 5.0f + (static_cast<float>(index + 1) / static_cast<float>(kPaths.size())) * 90.0f;
        kPro.set(kProgressPid, "处理中", 0, kProgress);
    }

    refreshPanel(panel);
    kPro.set(kProgressPid, "完成", 0, 100.0f);

    const QString kSummaryText = QStringLiteral("文件完整性设置完成：成功 %1，失败 %2，目标=%3。")
        .arg(successCount)
        .arg(failureDetails.size())
        .arg(levelDisplayText);
    if (!failureDetails.isEmpty())
    {
        KLogEvent failEvent;
        warn << failEvent
            << "[FileDock] 设置文件完整性部分失败, panel="
            << panel.panelNameText.toStdString()
            << ", successCount="
            << successCount
            << ", failCount="
            << failureDetails.size()
            << ", detailPreview=\n"
            << buildLogPreviewText(failureDetails).toStdString()
            << eol;
        if (!privilegePromptHandled)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("设置文件完整性"),
                kSummaryText + QStringLiteral("\n\n失败明细：\n") + failureDetails.join('\n'));
        }
        return;
    }

    KLogEvent finishEvent;
    info << finishEvent
        << "[FileDock] 设置文件完整性完成, panel="
        << panel.panelNameText.toStdString()
        << ", successCount="
        << successCount
        << ", target="
        << levelDisplayText.toStdString()
        << eol;
    QMessageBox::information(this, QStringLiteral("设置文件完整性"), kSummaryText);
}
