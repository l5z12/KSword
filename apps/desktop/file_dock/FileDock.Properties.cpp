#include "FileDetailDialog.h"

using namespace ksword::ui::file_dock;

void FileDock::showColumnManagerDialog(FilePanelWidgets& panel)
{
    {
        KLogEvent event;
        info << event
            << "[FileDock] 打开列管理器, panel="
            << panel.panelNameText.toStdString()
            << eol;
    }

    QDialog dialog(this);
    dialog.setWindowTitle(QStringLiteral("列管理器"));
    dialog.resize(340, 260);

    QVBoxLayout* rootLayout = new QVBoxLayout(&dialog);
    QLabel* tipLabel = new QLabel(QStringLiteral("勾选表示显示该列，可拖拽表头调整顺序。"), &dialog);
    tipLabel->setWordWrap(true);
    rootLayout->addWidget(tipLabel, 0);

    const bool kManualMode = currentModeIsManual(panel);
    const int kColumnCount = kManualMode
        ? (panel.manualModel == nullptr ? 0 : panel.manualModel->columnCount())
        : (panel.fsModel == nullptr ? 0 : panel.fsModel->columnCount());
    std::vector<QCheckBox*> columnChecks;
    columnChecks.reserve(static_cast<std::size_t>(kColumnCount));
    for (int column = 0; column < kColumnCount; ++column)
    {
        const QString kColumnName = kManualMode
            ? panel.manualModel->headerData(column, Qt::Horizontal).toString()
            : panel.fsModel->headerData(column, Qt::Horizontal).toString();
        QCheckBox* checkBox = new QCheckBox(kColumnName, &dialog);
        checkBox->setChecked(!panel.fileView->isColumnHidden(column));
        checkBox->setToolTip(QStringLiteral("切换列“%1”显示状态").arg(kColumnName));
        rootLayout->addWidget(checkBox, 0);
        columnChecks.push_back(checkBox);
    }
    rootLayout->addStretch(1);

    QDialogButtonBox* buttonBox = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel,
        &dialog);
    rootLayout->addWidget(buttonBox, 0);
    connect(buttonBox, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);

    if (dialog.exec() != QDialog::Accepted)
    {
        return;
    }

    for (int column = 0; column < static_cast<int>(columnChecks.size()); ++column)
    {
        const bool kVisible = columnChecks[static_cast<std::size_t>(column)]->isChecked();
        panel.fileView->setColumnHidden(column, !kVisible);
    }

    KLogEvent event;
    info << event
        << "[FileDock] 列管理器应用完成, panel="
        << panel.panelNameText.toStdString()
        << eol;
}

void FileDock::showFileDetailDialog(const QString& filePath, const QString& initialTabKey)
{
    showFileDetailDialog(QStringList{ filePath }, initialTabKey);
}

void FileDock::showFileDetailDialog(const QStringList& filePaths, const QString& initialTabKey)
{
    QStringList existingPaths;
    QSet<QString> seenPaths;
    for (const QString& candidatePath : filePaths)
    {
        const QString kNormalizedPath = QDir::cleanPath(
            QDir::toNativeSeparators(candidatePath.trimmed()));
        const QString kIdentityKey = kNormalizedPath.toLower();
        if (!kNormalizedPath.isEmpty() && !seenPaths.contains(kIdentityKey) &&
            QFileInfo::exists(kNormalizedPath))
        {
            seenPaths.insert(kIdentityKey);
            existingPaths.push_back(kNormalizedPath);
        }
    }
    if (existingPaths.isEmpty())
    {
        KLogEvent event;
        warn << event << "[FileDock] 打开文件详情失败：没有可访问目标" << eol;
        return;
    }

    FileDetailDialog* dialog = new FileDetailDialog(existingPaths, this, initialTabKey);
    dialog->setWindowFlag(Qt::WindowStaysOnTopHint, false);
    dialog->show();
    dialog->raise();
    dialog->activateWindow();

    KLogEvent event;
    info << event
        << "[FileDock] 打开文件详情窗口, targetCount="
        << existingPaths.size()
        << eol;
}

void FileDock::openFileDetailByPath(const QString& filePath)
{
    showFileDetailDialog(filePath);
}

QString FileDock::currentIndexPath(const FilePanelWidgets& panel) const
{
    if (panel.fileView == nullptr)
    {
        return QString();
    }

    const QModelIndex kProxyIndex = panel.fileView->currentIndex();
    if (!kProxyIndex.isValid())
    {
        return QString();
    }

    if (currentModeIsManual(panel))
    {
        if (panel.manualProxyModel == nullptr || panel.manualModel == nullptr)
        {
            return QString();
        }

        const QModelIndex kSourceIndex = panel.manualProxyModel->mapToSource(kProxyIndex);
        if (!kSourceIndex.isValid())
        {
            return QString();
        }

        const QStandardItem* fullPathItem = panel.manualModel->item(
            kSourceIndex.row(),
            static_cast<int>(ManualModelColumn::kFullPath));
        if (fullPathItem == nullptr)
        {
            return QString();
        }
        return fullPathItem->text();
    }

    if (panel.proxyModel == nullptr || panel.fsModel == nullptr)
    {
        return QString();
    }
    const QModelIndex kSourceIndex = panel.proxyModel->mapToSource(kProxyIndex);
    return kSourceIndex.isValid() ? panel.fsModel->filePath(kSourceIndex) : QString();
}

std::vector<QString> FileDock::selectedPaths(const FilePanelWidgets& panel) const
{
    std::vector<QString> result;
    if (panel.fileView == nullptr || panel.fileView->selectionModel() == nullptr)
    {
        return result;
    }

    const QModelIndexList kSelectedRows = panel.fileView->selectionModel()->selectedRows(0);
    result.reserve(static_cast<std::size_t>(kSelectedRows.size()));

    if (currentModeIsManual(panel))
    {
        if (panel.manualProxyModel == nullptr || panel.manualModel == nullptr)
        {
            return result;
        }
        for (const QModelIndex& proxyIndex : kSelectedRows)
        {
            const QModelIndex kSourceIndex = panel.manualProxyModel->mapToSource(proxyIndex);
            if (!kSourceIndex.isValid())
            {
                continue;
            }
            const QStandardItem* fullPathItem = panel.manualModel->item(
                kSourceIndex.row(),
                static_cast<int>(ManualModelColumn::kFullPath));
            if (fullPathItem == nullptr)
            {
                continue;
            }
            const QString kPathText = fullPathItem->text();
            if (kPathText.isEmpty())
            {
                continue;
            }
            if (std::find(result.begin(), result.end(), kPathText) == result.end())
            {
                result.push_back(kPathText);
            }
        }
    }
    else
    {
        if (panel.proxyModel == nullptr || panel.fsModel == nullptr)
        {
            return result;
        }
        for (const QModelIndex& proxyIndex : kSelectedRows)
        {
            const QModelIndex kSourceIndex = panel.proxyModel->mapToSource(proxyIndex);
            if (!kSourceIndex.isValid())
            {
                continue;
            }
            const QString kPath = panel.fsModel->filePath(kSourceIndex);
            if (kPath.isEmpty())
            {
                continue;
            }
            if (std::find(result.begin(), result.end(), kPath) == result.end())
            {
                result.push_back(kPath);
            }
        }
    }

    // If multi-selection is empty but a current row exists, fall back to the current row's path to facilitate right-click single-item operations.
    if (result.empty())
    {
        const QString kCurrentPath = currentIndexPath(panel);
        if (!kCurrentPath.isEmpty())
        {
            result.push_back(kCurrentPath);
        }
    }
    return result;
}

QString FileDock::formatSizeText(std::uint64_t sizeBytes)
{
    static const std::array<const char*, 5> kUnits{ "B", "KB", "MB", "GB", "TB" };
    double value = static_cast<double>(sizeBytes);
    std::size_t unitIndex = 0;
    while (value >= 1024.0 && (unitIndex + 1) < kUnits.size())
    {
        value /= 1024.0;
        ++unitIndex;
    }

    if (unitIndex == 0)
    {
        return QStringLiteral("%1 %2").arg(static_cast<qulonglong>(sizeBytes)).arg(kUnits[unitIndex]);
    }
    return QStringLiteral("%1 %2").arg(QString::number(value, 'f', 2)).arg(kUnits[unitIndex]);
}
