#include "FileDock.Support.h"

using namespace ksword::ui::file_dock;

void FileDock::openSelectedItems(FilePanelWidgets& panel)
{
    // Open logic supports multi-selection: directories and files are handled separately to avoid incorrectly switching the current panel path when multiple directories are selected.
    const std::vector<QString> kPaths = selectedPaths(panel);
    if (kPaths.empty())
    {
        return;
    }

    {
        KLogEvent event;
        info << event
            << "[FileDock] 打开选中项, panel="
            << panel.panelNameText.toStdString()
            << ", count="
            << kPaths.size()
            << eol;
    }

    int successCount = 0;
    int failCount = 0;
    QStringList failedPaths;
    for (const QString& path : kPaths)
    {
        QFileInfo info(path);
        if (info.isDir())
        {
            if (kPaths.size() == 1)
            {
                navigateToPath(panel, path, true);
                successCount += 1;
            }
            else
            {
                const bool kOpenOk = QDesktopServices::openUrl(QUrl::fromLocalFile(path));
                if (kOpenOk)
                {
                    successCount += 1;
                }
                else
                {
                    failCount += 1;
                    failedPaths.push_back(QDir::toNativeSeparators(path));
                }
            }
            continue;
        }

        const bool kOpenOk = QDesktopServices::openUrl(QUrl::fromLocalFile(path));
        if (kOpenOk)
        {
            successCount += 1;
        }
        else
        {
            failCount += 1;
            failedPaths.push_back(QDir::toNativeSeparators(path));
        }
    }

    KLogEvent resultEvent;
    if (failCount > 0)
    {
        warn << resultEvent
            << "[FileDock] 打开选中项部分失败, panel="
            << panel.panelNameText.toStdString()
            << ", successCount="
            << successCount
            << ", failCount="
            << failCount
            << ", failedPreview=\n"
            << buildLogPreviewText(failedPaths).toStdString()
            << eol;
        return;
    }

    info << resultEvent
        << "[FileDock] 打开选中项完成, panel="
        << panel.panelNameText.toStdString()
        << ", successCount="
        << successCount
        << eol;
}

void FileDock::copySelectedItemPath(FilePanelWidgets& panel)
{
    const std::vector<QString> kPaths = selectedPaths(panel);
    if (kPaths.empty())
    {
        return;
    }

    QStringList lines;
    for (const QString& path : kPaths)
    {
        lines << QDir::toNativeSeparators(path);
    }
    QApplication::clipboard()->setText(lines.join('\n'));

    KLogEvent event;
    info << event
        << "[FileDock] 复制路径到剪贴板, panel="
        << panel.panelNameText.toStdString()
        << ", count="
        << kPaths.size()
        << eol;
}

void FileDock::copySelectedItemKernelPath(FilePanelWidgets& panel)
{
    const std::vector<QString> kPaths = selectedPaths(panel);
    if (kPaths.empty())
    {
        return;
    }

    QStringList lines;
    lines.reserve(static_cast<int>(kPaths.size()));
    for (const QString& path : kPaths)
    {
        const QString kKernelPath = buildDriverNtPath(path);
        lines << (kKernelPath.isEmpty() ? QDir::toNativeSeparators(path) : kKernelPath);
    }
    QApplication::clipboard()->setText(lines.join('\n'));

    KLogEvent event;
    info << event
        << "[FileDock] 复制内核模式地址到剪贴板, panel="
        << panel.panelNameText.toStdString()
        << ", count="
        << kPaths.size()
        << eol;
}

void FileDock::copySelectedItemShortName(FilePanelWidgets& panel)
{
    const std::vector<QString> kPaths = selectedPaths(panel);
    if (kPaths.empty())
    {
        return;
    }

    QStringList shortNameLines;
    shortNameLines.reserve(static_cast<int>(kPaths.size()));

    int shortNameHitCount = 0;
    int fallbackCount = 0;
    for (const QString& path : kPaths)
    {
        const QString kShortPathText = queryShortPathText(path);
        QString shortNameText;
        if (!kShortPathText.isEmpty())
        {
            shortNameText = QFileInfo(kShortPathText).fileName().trimmed();
            if (shortNameText.isEmpty())
            {
                shortNameText = QDir::toNativeSeparators(kShortPathText);
            }
            shortNameHitCount += 1;
        }
        else
        {
            shortNameText = QFileInfo(path).fileName().trimmed();
            if (shortNameText.isEmpty())
            {
                shortNameText = QDir::toNativeSeparators(path);
            }
            fallbackCount += 1;
        }

        shortNameLines << shortNameText;
    }

    QApplication::clipboard()->setText(shortNameLines.join('\n'));

    KLogEvent event;
    info << event
        << "[FileDock] 复制短文件名到剪贴板, panel="
        << panel.panelNameText.toStdString()
        << ", count="
        << kPaths.size()
        << ", shortNameHitCount="
        << shortNameHitCount
        << ", fallbackCount="
        << fallbackCount
        << eol;
}

void FileDock::copySelectedItems(FilePanelWidgets& panel)
{
    transferSelectedItemsToOppositePanel(panel, false);
}

void FileDock::cutSelectedItems(FilePanelWidgets& panel)
{
    transferSelectedItemsToOppositePanel(panel, true);
}

FileDock::FilePanelWidgets* FileDock::oppositePanelFor(FilePanelWidgets& sourcePanel)
{
    if (&sourcePanel == &leftPanel_)
    {
        return &rightPanel_;
    }
    if (&sourcePanel == &rightPanel_)
    {
        return &leftPanel_;
    }
    return nullptr;
}

void FileDock::transferSelectedItemsToOppositePanel(FilePanelWidgets& sourcePanel, bool moveItems)
{
    if (transferInProgress_)
    {
        return;
    }

    const std::vector<QString> kSelectedItemPaths = selectedPaths(sourcePanel);
    if (kSelectedItemPaths.empty())
    {
        return;
    }

    FilePanelWidgets* const kTargetPanel = oppositePanelFor(sourcePanel);
    if (kTargetPanel == nullptr || kTargetPanel->currentPath.trimmed().isEmpty())
    {
        KLogEvent event;
        warn << event
            << "[FileDock] 跨面板文件传输取消：无法解析目标面板, sourcePanel="
            << sourcePanel.panelNameText.toStdString()
            << eol;
        return;
    }

    const QDir kTargetDir(kTargetPanel->currentPath);
    if (!kTargetDir.exists())
    {
        KLogEvent event;
        warn << event
            << "[FileDock] 跨面板文件传输取消：目标目录不存在, sourcePanel="
            << sourcePanel.panelNameText.toStdString()
            << ", targetPanel="
            << kTargetPanel->panelNameText.toStdString()
            << ", targetPath="
            << QDir::toNativeSeparators(kTargetPanel->currentPath).toStdString()
            << eol;
        return;
    }

    {
        KLogEvent event;
        info << event
            << "[FileDock] 跨面板文件传输请求, sourcePanel="
            << sourcePanel.panelNameText.toStdString()
            << ", targetPanel="
            << kTargetPanel->panelNameText.toStdString()
            << ", targetPath="
            << QDir::toNativeSeparators(kTargetPanel->currentPath).toStdString()
            << ", count="
            << kSelectedItemPaths.size()
            << ", mode="
            << (moveItems ? "move" : "copy")
            << eol;
    }

    // Copy/Cut operations in the dual-pane view now act directly as 'Source Panel -> Current Directory of Opposite Panel', bypassing the internal paste cache.
    // The progress title reuses the target panel text from the right-click menu to avoid the easily misunderstood 'Cut to opposite side'.
    const QString kLocalizedTargetPanelText = ks::i18n::displayText(kTargetPanel->panelNameText);
    const QString kProgressTitle = moveItems
        ? ks::i18n::displayText(QStringLiteral("移动到%1")).arg(kLocalizedTargetPanelText)
        : ks::i18n::displayText(QStringLiteral("复制到%1")).arg(kLocalizedTargetPanelText);
    const int kProgressPid = kPro.add(this, "文件", kProgressTitle.toStdString());
    kPro.set(kProgressPid, moveItems ? "准备移动" : "准备复制", 0, 5.0f);
    transferInProgress_ = true;

    const bool kSourceWasLeftPanel = &sourcePanel == &leftPanel_;
    const QString kTargetDirectoryPath = kTargetPanel->currentPath;
    const QString kSourcePanelNameText = sourcePanel.panelNameText;
    const QString kTargetPanelNameText = kTargetPanel->panelNameText;
    const QPointer<FileDock> kSafeThis(this);
    const QPointer<QApplication> kApplicationGuard(qApp);

    QThreadPool::globalInstance()->start(
        [kSafeThis,
            kApplicationGuard,
            kSelectedItemPaths,
            kTargetDirectoryPath,
            kSourcePanelNameText,
            kTargetPanelNameText,
            kSourceWasLeftPanel,
            moveItems,
            kProgressPid]()
        {
            QStringList errorLines;
            const QDir kWorkerTargetDir(kTargetDirectoryPath);
            const std::size_t kTotalCount = kSelectedItemPaths.size();

            for (std::size_t i = 0; i < kTotalCount; ++i)
            {
                const QString kSourcePath = kSelectedItemPaths[i];
                QFileInfo sourceInfo(kSourcePath);
                if (isPathReparsePoint(kSourcePath))
                {
                    errorLines << ks::i18n::displayText(
                        QStringLiteral("为避免越界递归，不复制符号链接或重解析点: %1"))
                        .arg(QDir::toNativeSeparators(kSourcePath));
                    continue;
                }
                if (!sourceInfo.exists())
                {
                    errorLines << QStringLiteral("源不存在：%1").arg(kSourcePath);
                    continue;
                }

                const QString kTargetPath = kWorkerTargetDir.filePath(sourceInfo.fileName());
                if (QDir::cleanPath(kSourcePath).compare(QDir::cleanPath(kTargetPath), Qt::CaseInsensitive) == 0)
                {
                    errorLines << QStringLiteral("源和目标相同，已跳过：%1").arg(kSourcePath);
                    continue;
                }
                if (sourceInfo.isDir())
                {
                    const QString kCleanSourceDirPath = QDir::cleanPath(sourceInfo.absoluteFilePath());
                    const QString kCleanTargetPath = QDir::cleanPath(kTargetPath);
                    const QString kSourcePrefix = kCleanSourceDirPath.endsWith(QLatin1Char('/'))
                        ? kCleanSourceDirPath
                        : kCleanSourceDirPath + QLatin1Char('/');
                    if (kCleanTargetPath.startsWith(kSourcePrefix, Qt::CaseInsensitive))
                    {
                        errorLines << QStringLiteral("不能把目录复制或移动到自身子目录：%1 -> %2")
                            .arg(kSourcePath, kTargetPath);
                        continue;
                    }
                }

                bool itemOk = false;
                QString copyErrorText;
                if (moveItems)
                {
                    // Prioritize same-volume rename for cut operations; fall back to transactional copy and source deletion on failure.
                    itemOk = QFile::rename(kSourcePath, kTargetPath);
                    if (!itemOk && sourceInfo.isDir())
                    {
                        itemOk = copyDirectoryTransactionally(kSourcePath, kTargetPath, copyErrorText);
                        if (itemOk && !QDir(kSourcePath).removeRecursively())
                        {
                            itemOk = false;
                            copyErrorText = ks::i18n::displayText(
                                QStringLiteral("目标已写入，但删除源目录失败: %1"))
                                .arg(kSourcePath);
                        }
                    }
                    else if (!itemOk)
                    {
                        itemOk = copyFileTransactionally(kSourcePath, kTargetPath, copyErrorText);
                        if (itemOk && !QFile::remove(kSourcePath))
                        {
                            itemOk = false;
                            copyErrorText = ks::i18n::displayText(
                                QStringLiteral("目标已写入，但删除源文件失败: %1"))
                                .arg(kSourcePath);
                        }
                    }
                }
                else if (sourceInfo.isDir())
                {
                    itemOk = copyDirectoryTransactionally(kSourcePath, kTargetPath, copyErrorText);
                }
                else
                {
                    itemOk = copyFileTransactionally(kSourcePath, kTargetPath, copyErrorText);
                }

                if (!itemOk)
                {
                    errorLines << copyErrorText;
                }

                if (!kApplicationGuard.isNull())
                {
                    const float kProgress = 5.0f +
                        (static_cast<float>(i + 1) / static_cast<float>(kTotalCount)) * 90.0f;
                    QMetaObject::invokeMethod(
                        kApplicationGuard.data(),
                        [kProgressPid, moveItems, kProgress]()
                        {
                            kPro.set(kProgressPid, moveItems ? "移动处理中" : "复制处理中", 0, kProgress);
                        },
                        Qt::QueuedConnection);
                }
            }

            if (kApplicationGuard.isNull())
            {
                return;
            }

            QMetaObject::invokeMethod(
                kApplicationGuard.data(),
                [kSafeThis,
                    errorLines = std::move(errorLines),
                    kSourcePanelNameText,
                    kTargetPanelNameText,
                    kSourceWasLeftPanel,
                    moveItems,
                    kProgressPid,
                    kTotalCount]()
                {
                    kPro.set(kProgressPid, moveItems ? "移动完成" : "复制完成", 0, 100.0f);
                    if (kSafeThis.isNull())
                    {
                        return;
                    }

                    FileDock* const kDock = kSafeThis.data();
                    kDock->transferInProgress_ = false;
                    FilePanelWidgets& completedSourcePanel = kSourceWasLeftPanel
                        ? kDock->leftPanel_
                        : kDock->rightPanel_;
                    FilePanelWidgets& completedTargetPanel = kSourceWasLeftPanel
                        ? kDock->rightPanel_
                        : kDock->leftPanel_;
                    kDock->refreshPanel(completedSourcePanel);
                    kDock->refreshPanel(completedTargetPanel);

                    if (!errorLines.isEmpty())
                    {
                        KLogEvent event;
                        warn << event
                            << "[FileDock] 跨面板文件传输部分失败, sourcePanel="
                            << kSourcePanelNameText.toStdString()
                            << ", targetPanel="
                            << kTargetPanelNameText.toStdString()
                            << ", errorCount="
                            << errorLines.size()
                            << ", errorPreview=\n"
                            << buildLogPreviewText(errorLines).toStdString()
                            << eol;
                        return;
                    }

                    KLogEvent event;
                    info << event
                        << "[FileDock] 跨面板文件传输完成, sourcePanel="
                        << kSourcePanelNameText.toStdString()
                        << ", targetPanel="
                        << kTargetPanelNameText.toStdString()
                        << ", totalCount="
                        << kTotalCount
                        << ", mode="
                        << (moveItems ? "move" : "copy")
                        << eol;
                },
                Qt::QueuedConnection);
        });
}
