#include "FileDock.Support.h"

using namespace ksword::ui::file_dock;

void FileDock::navigateToPath(FilePanelWidgets& panel, const QString& pathText, bool recordHistory)
{
    {
        KLogEvent event;
        info << event
            << "[FileDock] 导航请求, panel="
            << panel.panelNameText.toStdString()
            << ", input="
            << QDir::toNativeSeparators(pathText).toStdString()
            << ", recordHistory="
            << (recordHistory ? "true" : "false")
            << eol;
    }

    // Trim whitespace and normalize path format to avoid duplicate entries in history.
    const QString kTrimmedPath = pathText.trimmed();
    if (kTrimmedPath.isEmpty())
    {
        KLogEvent event;
        warn << event
            << "[FileDock] 导航取消：输入路径为空, panel="
            << panel.panelNameText.toStdString()
            << eol;
        return;
    }

    QString normalizedPath = QDir::cleanPath(QDir::fromNativeSeparators(kTrimmedPath));

    // Allow users to directly input a bare drive letter (e.g., D:) to jump to the drive root directory.
    if (normalizedPath.size() == 2
        && normalizedPath.at(1) == QChar(':')
        && normalizedPath.at(0).isLetter())
    {
        normalizedPath += QDir::separator();
    }

    QDir targetDir(normalizedPath);
    if (!targetDir.exists())
    {
        KLogEvent event;
        warn << event << "[FileDock] 导航失败，目录不存在: " << normalizedPath.toStdString() << eol;
        QMessageBox::warning(this, QStringLiteral("路径无效"), QStringLiteral("目录不存在：%1").arg(normalizedPath));
        return;
    }

    // Update the model root path based on the current read mode.
    if (currentModeIsManual(panel))
    {
        // Manual resolution mode uses a tiled model with the root index fixed to an invalid index.
        panel.fileView->setRootIndex(QModelIndex());
        panel.compactFileView->setRootIndex(QModelIndex());
    }
    else
    {
        const QModelIndex kSourceRootIndex = panel.fsModel->setRootPath(normalizedPath);
        const QModelIndex kProxyRootIndex = panel.proxyModel->mapFromSource(kSourceRootIndex);
        panel.fileView->setRootIndex(kProxyRootIndex);
        panel.compactFileView->setRootIndex(kProxyRootIndex);
    }
    panel.currentPath = normalizedPath;
    panel.pathEdit->setText(QDir::toNativeSeparators(normalizedPath));
    refreshDriveCombo(panel);

    // Record history: clear the 'forward' branch and append when the user navigates manually.
    if (recordHistory)
    {
        if (panel.historyIndex + 1 < static_cast<int>(panel.history.size()))
        {
            panel.history.erase(
                panel.history.begin() + panel.historyIndex + 1,
                panel.history.end());
        }

        if (panel.history.empty() || panel.history.back() != normalizedPath)
        {
            panel.history.push_back(normalizedPath);
            panel.historyIndex = static_cast<int>(panel.history.size()) - 1;
        }
        else
        {
            panel.historyIndex = static_cast<int>(panel.history.size()) - 1;
        }
    }

    // Synchronize button availability state.
    const bool kCanGoBack = panel.historyIndex > 0;
    const bool kCanGoForward = panel.historyIndex >= 0
        && (panel.historyIndex + 1) < static_cast<int>(panel.history.size());
    panel.backButton->setEnabled(kCanGoBack);
    panel.forwardButton->setEnabled(kCanGoForward);

    // Update breadcrumbs, filtering/sorting, and status bar after navigation.
    rebuildBreadcrumb(panel);
    setPathEditMode(panel, false);
    applyPanelFilterAndSort(panel);
    updatePanelStatus(panel);

    {
        KLogEvent event;
        info << event
            << "[FileDock] 导航成功, panel="
            << panel.panelNameText.toStdString()
            << ", normalizedPath="
            << QDir::toNativeSeparators(normalizedPath).toStdString()
            << ", historySize="
            << panel.history.size()
            << ", historyIndex="
            << panel.historyIndex
            << eol;
    }
}

void FileDock::refreshPanel(FilePanelWidgets& panel)
{
    {
        KLogEvent event;
        dbg << event
            << "[FileDock] 刷新面板, panel="
            << panel.panelNameText.toStdString()
            << ", currentPath="
            << QDir::toNativeSeparators(panel.currentPath).toStdString()
            << eol;
    }

    // When no current directory exists, navigate to the system root path to ensure the panel remains usable.
    if (panel.currentPath.isEmpty())
    {
        navigateToPath(panel, QDir::rootPath(), true);
        return;
    }

    // Reuse navigation logic to trigger model reload; avoid writing history to prevent pollution.
    if (currentModeIsManual(panel))
    {
        panel.manualLoadedPath.clear();
    }
    else
    {
        recreateFileSystemModel(panel);
    }
    navigateToPath(panel, panel.currentPath, false);
}

void FileDock::rebuildBreadcrumb(FilePanelWidgets& panel)
{
    if (panel.breadcrumbLayout == nullptr)
    {
        return;
    }

    {
        KLogEvent event;
        dbg << event
            << "[FileDock] 重建面包屑, panel="
            << panel.panelNameText.toStdString()
            << ", path="
            << QDir::toNativeSeparators(panel.currentPath).toStdString()
            << eol;
    }

    // Clean up old breadcrumb buttons and separators to prevent layout stacking.
    while (QLayoutItem* item = panel.breadcrumbLayout->takeAt(0))
    {
        if (QWidget* widget = item->widget())
        {
            widget->deleteLater();
        }
        delete item;
    }

    const QString kNativePath = QDir::toNativeSeparators(panel.currentPath);
    if (kNativePath.isEmpty())
    {
        return;
    }

    int crumbButtonCount = 0;
    QStringList pathParts = kNativePath.split(QDir::separator(), Qt::SkipEmptyParts);
    QString runningPath;

    // Handle Windows drive paths (e.g., C:\) separately to ensure the first segment is clickable.
    if (kNativePath.contains(':'))
    {
        const int kColonIndex = kNativePath.indexOf(':');
        if (kColonIndex >= 0)
        {
            runningPath = kNativePath.left(kColonIndex + 1) + QDir::separator();
            QString driveText = runningPath;
            driveText.chop(1);

            QToolButton* driveButton = new QToolButton(panel.breadcrumbWidget);
            driveButton->setText(driveText);
            driveButton->setStyleSheet(buildBreadcrumbButtonStyle());
            driveButton->setToolTip(QStringLiteral("跳转到 %1").arg(driveText));
            panel.breadcrumbLayout->addWidget(driveButton, 0);
            crumbButtonCount += 1;
            connect(driveButton, &QToolButton::clicked, this, [this, &panel, runningPath]() {
                KLogEvent event;
                info << event
                    << "[FileDock] 面包屑跳转(盘符), panel="
                    << panel.panelNameText.toStdString()
                    << ", targetPath="
                    << QDir::toNativeSeparators(runningPath).toStdString()
                    << eol;
                navigateToPath(panel, runningPath, true);
            });

            if (!pathParts.isEmpty() && pathParts.front().contains(':'))
            {
                pathParts.removeFirst();
            }
        }
    }
    else if (kNativePath.startsWith(QDir::separator()))
    {
        runningPath = QString(QDir::separator());
        QToolButton* rootButton = new QToolButton(panel.breadcrumbWidget);
        rootButton->setText(QStringLiteral("/"));
        rootButton->setStyleSheet(buildBreadcrumbButtonStyle());
        rootButton->setToolTip(QStringLiteral("跳转到根目录"));
        panel.breadcrumbLayout->addWidget(rootButton, 0);
        crumbButtonCount += 1;
        connect(rootButton, &QToolButton::clicked, this, [this, &panel]() {
            KLogEvent event;
            info << event
                << "[FileDock] 面包屑跳转(根目录), panel="
                << panel.panelNameText.toStdString()
                << eol;
            navigateToPath(panel, QString(QDir::separator()), true);
        });
    }

    // Create path buttons segment by segment, supporting jumps to any level on click.
    for (int i = 0; i < pathParts.size(); ++i)
    {
        const QString& part = pathParts.at(i);
        if (part.isEmpty())
        {
            continue;
        }

        if (!runningPath.isEmpty() && !runningPath.endsWith(QDir::separator()))
        {
            runningPath += QDir::separator();
        }
        runningPath += part;

        QLabel* sepLabel = new QLabel(QStringLiteral(">"), panel.breadcrumbWidget);
        sepLabel->setStyleSheet(QStringLiteral("color:%1;").arg(ksword_theme::kPrimaryBlueHex));
        panel.breadcrumbLayout->addWidget(sepLabel, 0);

        const QString kCapturePath = runningPath;
        QToolButton* partButton = new QToolButton(panel.breadcrumbWidget);
        partButton->setText(part);
        partButton->setStyleSheet(buildBreadcrumbButtonStyle());
        partButton->setToolTip(QStringLiteral("跳转到 %1").arg(kCapturePath));
        panel.breadcrumbLayout->addWidget(partButton, 0);
        crumbButtonCount += 1;
        connect(partButton, &QToolButton::clicked, this, [this, &panel, kCapturePath]() {
            KLogEvent event;
            info << event
                << "[FileDock] 面包屑跳转(路径段), panel="
                << panel.panelNameText.toStdString()
                << ", targetPath="
                << QDir::toNativeSeparators(kCapturePath).toStdString()
                << eol;
            navigateToPath(panel, kCapturePath, true);
        });
    }

    // Add a 'transparent hotspot' at the end of the breadcrumb:
    // - Clicking the path button triggers segment-by-segment backtracking;
    // - Clicking an empty area switches to text editing mode.
    panel.breadcrumbEditTriggerButton = new QPushButton(panel.breadcrumbWidget);
    panel.breadcrumbEditTriggerButton->setFlat(true);
    panel.breadcrumbEditTriggerButton->setCursor(Qt::IBeamCursor);
    panel.breadcrumbEditTriggerButton->setToolTip(QStringLiteral("点击空白区域编辑路径"));
    panel.breadcrumbEditTriggerButton->setStyleSheet(QStringLiteral(
        "QPushButton{border:none;background:transparent;color:%1;}"
        "QPushButton:hover{background:%2;color:%1;}")
        .arg(ksword_theme::textPrimaryHex())
        .arg(ksword_theme::isDarkModeEnabled() ? ksword_theme::surfaceMutedColorHex() : ksword_theme::primaryBlueSubtleHex()));
    panel.breadcrumbLayout->addWidget(panel.breadcrumbEditTriggerButton, 1);
    connect(panel.breadcrumbEditTriggerButton, &QPushButton::clicked, this, [this, &panel]() {
        KLogEvent event;
        info << event
            << "[FileDock] 点击面包屑空白区进入路径编辑, panel="
            << panel.panelNameText.toStdString()
            << eol;
        setPathEditMode(panel, true);
    });

    {
        KLogEvent event;
        dbg << event
            << "[FileDock] 面包屑重建完成, panel="
            << panel.panelNameText.toStdString()
            << ", breadcrumbButtonCount="
            << crumbButtonCount
            << eol;
    }
}

void FileDock::setPathEditMode(FilePanelWidgets& panel, bool editMode)
{
    if (panel.pathStack == nullptr || panel.pathEdit == nullptr || panel.breadcrumbWidget == nullptr)
    {
        return;
    }

    if (panel.pathEditMode == editMode)
    {
        return;
    }

    panel.pathEditMode = editMode;
    if (editMode)
    {
        panel.pathStack->setCurrentWidget(panel.pathEdit);
        panel.pathEdit->setText(QDir::toNativeSeparators(panel.currentPath));
        panel.pathEdit->setFocus();
        panel.pathEdit->selectAll();
    }
    else
    {
        panel.pathStack->setCurrentWidget(panel.breadcrumbWidget);
        panel.pathEdit->clearFocus();
    }

    KLogEvent event;
    dbg << event
        << "[FileDock] 地址栏显示模式切换, panel="
        << panel.panelNameText.toStdString()
        << ", mode="
        << (editMode ? "edit" : "breadcrumb")
        << eol;
}

void FileDock::updatePanelStatus(FilePanelWidgets& panel)
{
    // Status: Display the current directory directly.
    panel.pathStatusLabel->setText(QStringLiteral("路径: %1").arg(QDir::toNativeSeparators(panel.currentPath)));

    // Count selected items and total size (folder sizes are not recursively calculated to avoid lag).
    const std::vector<QString> kSelectedItemPaths = selectedPaths(panel);
    std::uint64_t totalSize = 0;
    for (const QString& path : kSelectedItemPaths)
    {
        QFileInfo info(path);
        if (info.isFile())
        {
            totalSize += static_cast<std::uint64_t>(std::max<qint64>(0, info.size()));
        }
    }

    QString attributeHint;
    if (kSelectedItemPaths.size() == 1)
    {
        QFileInfo info(kSelectedItemPaths.front());
        QStringList attrs;
        if (!info.isWritable())
        {
            attrs.push_back(QStringLiteral("只读"));
        }
        if (info.isHidden())
        {
            attrs.push_back(QStringLiteral("隐藏"));
        }
        if (info.isSymLink())
        {
            attrs.push_back(QStringLiteral("链接"));
        }
        if (!attrs.isEmpty())
        {
            attributeHint = QStringLiteral(" [%1]").arg(attrs.join(','));
        }
    }

    panel.selectionStatusLabel->setText(
        QStringLiteral("选中: %1  大小: %2%3")
        .arg(kSelectedItemPaths.size())
        .arg(formatSizeText(totalSize))
        .arg(attributeHint));

    // Disk status: display remaining space on the current partition.
    const QStorageInfo kStorageInfo(panel.currentPath);
    if (kStorageInfo.isValid() && kStorageInfo.isReady())
    {
        panel.diskStatusLabel->setText(
            QStringLiteral("剩余: %1 / 总计: %2")
            .arg(formatSizeText(static_cast<std::uint64_t>(kStorageInfo.bytesAvailable())))
            .arg(formatSizeText(static_cast<std::uint64_t>(kStorageInfo.bytesTotal()))));
    }
    else
    {
        panel.diskStatusLabel->setText(QStringLiteral("磁盘: -"));
    }

    // Deduplicate status logs: output only when content changes to prevent log storms caused by selection jitter.
    const QString kStatusSignature = QStringLiteral("%1|%2|%3|%4")
        .arg(panel.currentPath)
        .arg(kSelectedItemPaths.size())
        .arg(static_cast<qulonglong>(totalSize))
        .arg(panel.diskStatusLabel->text());
    if (kStatusSignature != panel.lastStatusLogSignature)
    {
        panel.lastStatusLogSignature = kStatusSignature;
        KLogEvent event;
        dbg << event
            << "[FileDock] 状态栏更新, panel="
            << panel.panelNameText.toStdString()
            << ", selectedCount="
            << kSelectedItemPaths.size()
            << ", selectedBytes="
            << static_cast<qulonglong>(totalSize)
            << ", path="
            << QDir::toNativeSeparators(panel.currentPath).toStdString()
            << eol;
    }
}

void FileDock::applyPanelFilterAndSort(FilePanelWidgets& panel)
{
    const bool kManualMode = currentModeIsManual(panel);
    const int kModeIndex = panel.viewModeCombo->currentIndex();
    const QString kFilterText = panel.filterEdit->text().trimmed();

    // Icons/List use QListView's actual layout; Details/Tree retain QTreeView's multi-column and hierarchical capabilities.
    const bool kCompactMode = (kModeIndex == 0 || kModeIndex == 1);
    if (kCompactMode)
    {
        panel.fileViewStack->setCurrentWidget(panel.compactFileView);
        panel.compactFileView->setTextElideMode(Qt::ElideMiddle);
        if (kModeIndex == 0)
        {
            panel.compactFileView->setViewMode(QListView::IconMode);
            panel.compactFileView->setResizeMode(QListView::Adjust);
            panel.compactFileView->setMovement(QListView::Static);
            panel.compactFileView->setFlow(QListView::LeftToRight);
            panel.compactFileView->setWrapping(true);
            panel.compactFileView->setGridSize(QSize(128, 96));
            panel.compactFileView->setSpacing(6);
            panel.compactFileView->setWordWrap(true);
            panel.compactFileView->setUniformItemSizes(true);
            panel.compactFileView->setIconSize(QSize(48, 48));
        }
        else
        {
            panel.compactFileView->setViewMode(QListView::ListMode);
            panel.compactFileView->setResizeMode(QListView::Adjust);
            panel.compactFileView->setMovement(QListView::Static);
            panel.compactFileView->setFlow(QListView::TopToBottom);
            panel.compactFileView->setWrapping(false);
            panel.compactFileView->setGridSize(QSize());
            panel.compactFileView->setSpacing(2);
            panel.compactFileView->setWordWrap(false);
            panel.compactFileView->setUniformItemSizes(true);
            panel.compactFileView->setIconSize(QSize(20, 20));
        }
    }
    else
    {
        panel.fileViewStack->setCurrentWidget(panel.fileView);
    }

    if (kManualMode)
    {
        // In manual mode, only launch a new task when the current path is not loaded and not being
        // parsed, to avoid triggering a full re-scan of the same path due to filter/sort changes.
        const bool kLoadedMatchesCurrentPath =
            (panel.manualLoadedPath.compare(panel.currentPath, Qt::CaseInsensitive) == 0);
        const bool kSamePathParsing =
            panel.manualParseInProgress
            && (panel.manualParsingPath.compare(panel.currentPath, Qt::CaseInsensitive) == 0);
        if (!kLoadedMatchesCurrentPath && !kSamePathParsing)
        {
            requestAsyncManualReload(panel, false);
        }

        if (kFilterText.isEmpty())
        {
            panel.manualProxyModel->setFilterRegularExpression(QRegularExpression());
        }
        else
        {
            const QString kPattern = QStringLiteral(".*%1.*").arg(QRegularExpression::escape(kFilterText));
            panel.manualProxyModel->setFilterRegularExpression(
                QRegularExpression(kPattern, QRegularExpression::CaseInsensitiveOption));
        }

        int sortColumn = static_cast<int>(ManualModelColumn::kName);
        switch (panel.sortModeCombo->currentIndex())
        {
        case 1:
            sortColumn = static_cast<int>(ManualModelColumn::kSize);
            break;
        case 2:
            sortColumn = static_cast<int>(ManualModelColumn::kModifiedTime);
            break;
        case 3:
            sortColumn = static_cast<int>(ManualModelColumn::kType);
            break;
        default:
            sortColumn = static_cast<int>(ManualModelColumn::kName);
            break;
        }
        panel.fileView->sortByColumn(sortColumn, Qt::AscendingOrder);

        const bool kShowDetailColumns = (kModeIndex == 2 || kModeIndex == 3);
        panel.fileView->setIconSize(kModeIndex == 0 ? QSize(32, 32) : QSize(18, 18));
        panel.fileView->setRootIsDecorated(false);
        panel.fileView->setItemsExpandable(false);
        panel.fileView->setIndentation(10);

        panel.fileView->setColumnHidden(static_cast<int>(ManualModelColumn::kSize), !kShowDetailColumns);
        panel.fileView->setColumnHidden(static_cast<int>(ManualModelColumn::kType), !kShowDetailColumns);
        panel.fileView->setColumnHidden(static_cast<int>(ManualModelColumn::kModifiedTime), !kShowDetailColumns);
        panel.fileView->setColumnHidden(static_cast<int>(ManualModelColumn::kFullPath), true);
        panel.fileView->setColumnHidden(static_cast<int>(ManualModelColumn::kIsDirectory), true);
    }
    else
    {
        // Composite model filter flags: Show hidden/system files based on user selection.
        QDir::Filters filters = QDir::AllEntries | QDir::NoDotAndDotDot;
        if (panel.showHiddenCheck->isChecked())
        {
            filters |= QDir::Hidden;
        }
        if (panel.showSystemCheck->isChecked())
        {
            filters |= QDir::System;
        }
        panel.fsModel->setFilter(filters);

        if (kFilterText.isEmpty())
        {
            panel.fsModel->setNameFilters(QStringList());
        }
        else
        {
            panel.fsModel->setNameFilters(QStringList{
                buildLiteralNameFilterPattern(kFilterText)
                });
        }
        // Windows API mode now performs name filtering via QFileSystemModel; the proxy layer retains only sorting responsibilities.
        panel.proxyModel->setFilterRegularExpression(QRegularExpression());

        int sortColumn = 0;
        switch (panel.sortModeCombo->currentIndex())
        {
        case 1:
            sortColumn = 1;
            break;
        case 2:
            sortColumn = 3;
            break;
        case 3:
            sortColumn = 2;
            break;
        default:
            sortColumn = 0;
            break;
        }
        panel.fileView->sortByColumn(sortColumn, Qt::AscendingOrder);

        const bool kShowDetailColumns = (kModeIndex == 2 || kModeIndex == 3);
        panel.fileView->setIconSize(kModeIndex == 0 ? QSize(32, 32) : QSize(18, 18));
        panel.fileView->setRootIsDecorated(kModeIndex == 3);
        panel.fileView->setItemsExpandable(kModeIndex == 3);
        panel.fileView->setIndentation(kModeIndex == 3 ? 18 : 10);
        for (int column = 1; column < panel.fsModel->columnCount(); ++column)
        {
            panel.fileView->setColumnHidden(column, !kShowDetailColumns);
        }
        if (kModeIndex == 1)
        {
            panel.fileView->setRootIsDecorated(false);
            panel.fileView->setItemsExpandable(false);
        }
        if (panel.parserStatusLabel != nullptr)
        {
            panel.parserStatusLabel->setText(QStringLiteral("解析器: Windows API"));
        }
    }

    // Filter parameter log deduplication: output detailed parameters only when the user actually adjusts conditions.
    const QString kFilterSignature = QStringLiteral("%1|%2|%3|%4|%5|%6")
        .arg(panel.showHiddenCheck->isChecked() ? 1 : 0)
        .arg(panel.showSystemCheck->isChecked() ? 1 : 0)
        .arg(panel.sortModeCombo->currentIndex())
        .arg(panel.viewModeCombo->currentIndex())
        .arg(panel.readModeCombo->currentIndex())
        .arg(panel.filterEdit->text());
    if (kFilterSignature != panel.lastFilterLogSignature)
    {
        panel.lastFilterLogSignature = kFilterSignature;
        KLogEvent event;
        info << event
            << "[FileDock] 过滤/排序参数变更, panel="
            << panel.panelNameText.toStdString()
            << ", showHidden="
            << (panel.showHiddenCheck->isChecked() ? "true" : "false")
            << ", showSystem="
            << (panel.showSystemCheck->isChecked() ? "true" : "false")
            << ", sortModeIndex="
            << panel.sortModeCombo->currentIndex()
            << ", viewModeIndex="
            << panel.viewModeCombo->currentIndex()
            << ", readModeIndex="
            << panel.readModeCombo->currentIndex()
            << ", keyword="
            << panel.filterEdit->text().toStdString()
            << eol;
    }

    updatePanelStatus(panel);
}
