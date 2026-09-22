#include "FileDock.Support.h"

using namespace ksword::ui::file_dock;

void FileDock::initializeRecoveryPage()
{
    fileRecoveryPage_ = new QWidget(rootTabWidget_);
    QVBoxLayout* recoveryLayout = new QVBoxLayout(fileRecoveryPage_);
    recoveryLayout->setContentsMargins(6, 6, 6, 6);
    recoveryLayout->setSpacing(6);

    QWidget* toolWidget = new QWidget(fileRecoveryPage_);
    QHBoxLayout* toolLayout = new QHBoxLayout(toolWidget);
    toolLayout->setContentsMargins(0, 0, 0, 0);
    toolLayout->setSpacing(6);

    recoveryVolumeCombo_ = new QComboBox(toolWidget);
    recoveryVolumeCombo_->setStyleSheet(buildBlueInputStyle());
    recoveryVolumeCombo_->setToolTip(QStringLiteral("选择要扫描误删文件的 NTFS 卷。"));

    recoveryRefreshButton_ = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), toolWidget);
    recoveryRefreshButton_->setToolTip(QStringLiteral("刷新可扫描卷列表"));
    recoveryRefreshButton_->setStyleSheet(buildBlueButtonStyle());
    ksword_theme::applyCompactIconButtonMetrics(recoveryRefreshButton_);

    recoveryScanButton_ = new QPushButton(QIcon(":/Icon/log_track.svg"), QStringLiteral("扫描误删"), toolWidget);
    recoveryScanButton_->setToolTip(QStringLiteral("解析 NTFS MFT，扫描删除项"));
    recoveryScanButton_->setStyleSheet(buildBlueButtonStyle());

    recoveryExportButton_ = new QPushButton(QIcon(":/Icon/log_export.svg"), QStringLiteral("恢复选中"), toolWidget);
    recoveryExportButton_->setToolTip(QStringLiteral(
        "支持 Resident 与完整非驻留数据；非驻留文件必须导出到其它卷，恢复前后都会复核卷位图。"));
    recoveryExportButton_->setStyleSheet(buildBlueButtonStyle());

    // Scan results can easily reach tens of thousands of entries; an in-place search is mandatory, otherwise users would be forced to rely on scrolling.
    recoveryFilterEdit_ = new QLineEdit(toolWidget);
    recoveryFilterEdit_->setPlaceholderText(QStringLiteral("查找结果（文件名/路径/恢复能力）"));
    recoveryFilterEdit_->setClearButtonEnabled(true);
    recoveryFilterEdit_->setStyleSheet(buildBlueInputStyle());
    recoveryFilterEdit_->setToolTip(QStringLiteral(
        "按输入内容实时筛选扫描结果，匹配行以外的条目会被隐藏。"));

    recoveryFilterRegexButton_ = new QToolButton(toolWidget);
    recoveryFilterRegexButton_->setText(QStringLiteral(".*"));
    recoveryFilterRegexButton_->setCheckable(true);
    recoveryFilterRegexButton_->setToolTip(QStringLiteral(
        "按正则表达式筛选，例如 \\.docx?$ 只看 doc/docx"));

    toolLayout->addWidget(new QLabel(QStringLiteral("卷: "), toolWidget), 0);
    toolLayout->addWidget(recoveryVolumeCombo_, 1);
    toolLayout->addWidget(recoveryRefreshButton_, 0);
    toolLayout->addWidget(recoveryScanButton_, 0);
    toolLayout->addWidget(recoveryFilterEdit_, 1);
    toolLayout->addWidget(recoveryFilterRegexButton_, 0);
    toolLayout->addWidget(recoveryExportButton_, 0);
    recoveryLayout->addWidget(toolWidget, 0);

    recoveryTable_ = new ks::ui::VisibleTableWidget(fileRecoveryPage_);
    recoveryTable_->setColumnCount(7);
    recoveryTable_->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("文件名"),
        QStringLiteral("路径提示"),
        QStringLiteral("大小"),
        QStringLiteral("修改时间"),
        QStringLiteral("记录号"),
        QStringLiteral("完整度"),
        QStringLiteral("恢复能力")
        });
    recoveryTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    recoveryTable_->setSelectionMode(QAbstractItemView::ExtendedSelection);
    recoveryTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    recoveryTable_->verticalHeader()->setVisible(false);
    recoveryTable_->horizontalHeader()->setStretchLastSection(true);
    recoveryTable_->setAlternatingRowColors(true);
    installRecoveryTableMenu();

    // Use a stacked container for the results area: display a centered guide page when there are no results, otherwise the
    // 'Scan for Accidental Deletion' button at the far right of the toolbar is hard to notice next to the empty table.
    recoveryViewStack_ = new QStackedWidget(fileRecoveryPage_);

    recoveryEmptyPage_ = new QWidget(recoveryViewStack_);
    QVBoxLayout* emptyLayout = new QVBoxLayout(recoveryEmptyPage_);
    emptyLayout->setContentsMargins(24, 24, 24, 24);
    emptyLayout->setSpacing(12);
    emptyLayout->addStretch(1);

    recoveryEmptyHintLabel_ = new QLabel(
        QStringLiteral("选择 NTFS 卷后开始扫描，可在此列出仍可恢复的误删文件。"),
        recoveryEmptyPage_);
    recoveryEmptyHintLabel_->setAlignment(Qt::AlignCenter);
    recoveryEmptyHintLabel_->setWordWrap(true);
    emptyLayout->addWidget(recoveryEmptyHintLabel_, 0);

    recoveryEmptyScanButton_ = new QPushButton(
        QIcon(":/Icon/log_track.svg"),
        QStringLiteral("开始扫描误删文件"),
        recoveryEmptyPage_);
    recoveryEmptyScanButton_->setStyleSheet(buildBlueButtonStyle());
    recoveryEmptyScanButton_->setMinimumHeight(38);
    recoveryEmptyScanButton_->setMinimumWidth(200);
    recoveryEmptyScanButton_->setToolTip(QStringLiteral("解析 NTFS MFT，扫描删除项"));

    QHBoxLayout* emptyButtonLayout = new QHBoxLayout();
    emptyButtonLayout->addStretch(1);
    emptyButtonLayout->addWidget(recoveryEmptyScanButton_, 0);
    emptyButtonLayout->addStretch(1);
    emptyLayout->addLayout(emptyButtonLayout, 0);
    emptyLayout->addStretch(1);

    recoveryViewStack_->addWidget(recoveryEmptyPage_);
    recoveryViewStack_->addWidget(recoveryTable_);
    recoveryViewStack_->setCurrentWidget(recoveryEmptyPage_);
    recoveryLayout->addWidget(recoveryViewStack_, 1);

    recoveryStatusLabel_ = new QLabel(QStringLiteral("请选择NTFS卷并开始扫描。"), fileRecoveryPage_);
    recoveryLayout->addWidget(recoveryStatusLabel_, 0);

    connect(recoveryRefreshButton_, &QPushButton::clicked, this, [this]() {
        refreshRecoveryVolumeList();
    });
    connect(recoveryScanButton_, &QPushButton::clicked, this, [this]() {
        scanDeletedFilesForRecovery();
    });
    connect(recoveryEmptyScanButton_, &QPushButton::clicked, this, [this]() {
        scanDeletedFilesForRecovery();
    });
    connect(recoveryExportButton_, &QPushButton::clicked, this, [this]() {
        recoverSelectedDeletedFiles();
    });
    connect(recoveryFilterEdit_, &QLineEdit::textChanged, this, [this](const QString&) {
        applyRecoveryFilter();
    });
    connect(recoveryFilterRegexButton_, &QToolButton::toggled, this, [this](bool) {
        applyRecoveryFilter();
    });

    refreshRecoveryVolumeList();
}

void FileDock::applyRecoveryFilter()
{
    // applyRecoveryFilter：
    // - Input: Search box text and regex toggle.
    // - Processing: Compare cached deleted item fields line by line and hide non-matching rows in-place using setRowHidden;
    // - Return: None. Only affects visibility without modifying m_deletedRecoveryItems or the row mapping, so the row
    //   numbers retrieved via right-click properties or restore selection still directly correspond to the cache indices.
    if (recoveryTable_ == nullptr || recoveryFilterEdit_ == nullptr)
    {
        return;
    }

    const QString kQueryText = recoveryFilterEdit_->text().trimmed();
    const bool kUseRegex =
        recoveryFilterRegexButton_ != nullptr && recoveryFilterRegexButton_->isChecked();

    QRegularExpression regexValue;
    bool regexUsable = false;
    if (!kQueryText.isEmpty() && kUseRegex)
    {
        regexValue = QRegularExpression(
            kQueryText,
            QRegularExpression::CaseInsensitiveOption);
        regexUsable = regexValue.isValid();
        // A regex written halfway is necessarily invalid; do not clear the entire table here to maintain the previous visible state.
        if (!regexUsable)
        {
            recoveryFilterEdit_->setToolTip(QStringLiteral("正则表达式无效，已暂不筛选。"));
            return;
        }
    }
    recoveryFilterEdit_->setToolTip(QStringLiteral(
        "按输入内容实时筛选扫描结果，匹配行以外的条目会被隐藏。"));

    const int kRowCount = recoveryTable_->rowCount();
    int visibleCount = 0;
    // Changing visibility line-by-line for tens of thousands of rows triggers massive reflows; disable updates first, then restore them all at once.
    recoveryTable_->setUpdatesEnabled(false);
    for (int row = 0; row < kRowCount; ++row)
    {
        bool matched = kQueryText.isEmpty();
        if (!matched && row < static_cast<int>(deletedRecoveryItems_.size()))
        {
            const ks::file::NtfsDeletedFileEntry& itemValue =
                deletedRecoveryItems_[static_cast<std::size_t>(row)];
            // Only compare the three fields users actually search to avoid false positives caused by file size or timestamp numbers.
            const QStringList kSearchFields{
                itemValue.fileName,
                itemValue.pathHint,
                deletedFileRecoveryCapabilityText(itemValue) };
            for (const QString& fieldText : kSearchFields)
            {
                if (kUseRegex)
                {
                    if (regexUsable && regexValue.match(fieldText).hasMatch())
                    {
                        matched = true;
                        break;
                    }
                }
                else if (fieldText.contains(kQueryText, Qt::CaseInsensitive))
                {
                    matched = true;
                    break;
                }
            }
        }

        recoveryTable_->setRowHidden(row, !matched);
        if (matched)
        {
            ++visibleCount;
        }
    }
    recoveryTable_->setUpdatesEnabled(true);

    if (recoveryStatusLabel_ != nullptr && !deletedRecoveryItems_.empty())
    {
        recoveryStatusLabel_->setText(
            kQueryText.isEmpty()
            ? recoveryBaseStatusText_
            : QStringLiteral("%1｜筛选出 %2 / %3 项")
                .arg(recoveryBaseStatusText_)
                .arg(visibleCount)
                .arg(kRowCount));
    }
}

void FileDock::updateRecoveryViewState(const bool hasResults, const QString& emptyHintText)
{
    if (recoveryViewStack_ == nullptr)
    {
        return;
    }
    if (recoveryEmptyHintLabel_ != nullptr && !emptyHintText.isEmpty())
    {
        recoveryEmptyHintLabel_->setText(emptyHintText);
    }
    recoveryViewStack_->setCurrentWidget(
        hasResults
        ? static_cast<QWidget*>(recoveryTable_)
        : static_cast<QWidget*>(recoveryEmptyPage_));
}

void FileDock::installRecoveryTableMenu()
{
    // installRecoveryTableMenu：
    // - Input: Right-click on the deletion result table;
    // - Processing: In addition to the generic 'Copy Current Row', add 'File Attributes' and 'Restore Selection'
    //   so these two main operations do not need to search for buttons at the far right of the toolbar.
    // - Return: None. Attributes are displayed as read-only; recovery uses the exact same entry point as the toolbar button.
    if (recoveryTable_ == nullptr)
    {
        return;
    }

    recoveryTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(recoveryTable_, &QTableWidget::customContextMenuRequested, this,
        [this](const QPoint& localPosition)
    {
        if (recoveryTable_ == nullptr)
        {
            return;
        }
        const QModelIndex kClickedIndex = recoveryTable_->indexAt(localPosition);
        // Right-clicking empty space does not change existing multi-selection; only clicking a row switches the current selection to that row.
        if (kClickedIndex.isValid() && !recoveryTable_->selectionModel()->isSelected(kClickedIndex))
        {
            recoveryTable_->selectRow(kClickedIndex.row());
        }

        const int kCurrentRow = kClickedIndex.isValid()
            ? kClickedIndex.row()
            : recoveryTable_->currentRow();
        const bool kHasRow = kCurrentRow >= 0
            && kCurrentRow < static_cast<int>(deletedRecoveryItems_.size());
        const bool kHasSelection =
            !recoveryTable_->selectionModel()->selectedRows().isEmpty();

        QMenu menu(recoveryTable_);
        menu.setStyleSheet(buildContextMenuStyle());

        QAction* propertyAction = menu.addAction(
            QIcon(QStringLiteral(":/Icon/process_details.svg")),
            QStringLiteral("文件属性"));
        propertyAction->setEnabled(kHasRow);

        QAction* recoverAction = menu.addAction(
            QIcon(QStringLiteral(":/Icon/log_export.svg")),
            QStringLiteral("恢复选中"));
        recoverAction->setEnabled(kHasSelection && !recoveryRecoverInProgress_);

        menu.addSeparator();
        QAction* copyRowAction = menu.addAction(
            QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
            QStringLiteral("复制当前行"));
        copyRowAction->setEnabled(kCurrentRow >= 0);

        QAction* selectedAction =
            menu.exec(recoveryTable_->viewport()->mapToGlobal(localPosition));
        if (selectedAction == nullptr)
        {
            return;
        }
        if (selectedAction == propertyAction)
        {
            showDeletedFilePropertiesDialog(kCurrentRow);
            return;
        }
        if (selectedAction == recoverAction)
        {
            recoverSelectedDeletedFiles();
            return;
        }
        if (selectedAction != copyRowAction)
        {
            return;
        }

        QClipboard* clipboardObject = QApplication::clipboard();
        if (clipboardObject == nullptr
            || kCurrentRow < 0
            || kCurrentRow >= recoveryTable_->rowCount())
        {
            return;
        }
        QStringList fields;
        fields.reserve(recoveryTable_->columnCount());
        for (int columnIndex = 0; columnIndex < recoveryTable_->columnCount(); ++columnIndex)
        {
            const QTableWidgetItem* item = recoveryTable_->item(kCurrentRow, columnIndex);
            fields.push_back(item != nullptr ? item->text() : QString());
        }
        clipboardObject->setText(fields.join(QLatin1Char('\t')));
    });
}

void FileDock::showDeletedFilePropertiesDialog(const int rowIndex)
{
    if (rowIndex < 0 || rowIndex >= static_cast<int>(deletedRecoveryItems_.size()))
    {
        return;
    }
    const ks::file::NtfsDeletedFileEntry& itemValue =
        deletedRecoveryItems_[static_cast<std::size_t>(rowIndex)];

    QDialog dialog(this);
    dialog.setObjectName(QStringLiteral("DeletedFilePropertyDialog"));
    dialog.setStyleSheet(buildOpaqueStandaloneDialogStyle(dialog.objectName()));
    dialog.setWindowTitle(QStringLiteral("删除项属性"));
    dialog.resize(620, 460);

    QVBoxLayout* rootLayout = new QVBoxLayout(&dialog);

    // Properties are displayed in a read-only table: more practical than QFormLayout when fields are numerous and full-line copying is needed.
    QTableWidget* propertyTable = new ks::ui::VisibleTableWidget(&dialog);
    propertyTable->setColumnCount(2);
    propertyTable->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("属性"),
        QStringLiteral("值") });
    propertyTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    propertyTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    propertyTable->verticalHeader()->setVisible(false);
    propertyTable->horizontalHeader()->setStretchLastSection(true);
    propertyTable->setAlternatingRowColors(true);
    installFileTableCopyMenu(propertyTable);

    const QString kIntegrityText = (itemValue.estimatedIntegrityPercent >= 0)
        ? QStringLiteral("%1%").arg(itemValue.estimatedIntegrityPercent)
        : QStringLiteral("未知");
    const QString kModifiedText = itemValue.modifiedTime.isValid()
        ? itemValue.modifiedTime.toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"))
        : QStringLiteral("-");

    const QVector<QPair<QString, QString>> kPropertyRows{
        { QStringLiteral("文件名"), itemValue.fileName },
        { QStringLiteral("原始文件名是否保留"),
          itemValue.hasOriginalName
          ? QStringLiteral("是")
          : QStringLiteral("否（当前为系统生成的占位名）") },
        { QStringLiteral("路径提示"), itemValue.pathHint },
        { QStringLiteral("大小"),
          QStringLiteral("%1 (%2 字节)")
              .arg(formatSizeText(itemValue.sizeBytes))
              .arg(static_cast<qulonglong>(itemValue.sizeBytes)) },
        { QStringLiteral("修改时间"), kModifiedText },
        { QStringLiteral("MFT 记录号"),
          QString::number(static_cast<qulonglong>(itemValue.fileReference)) },
        { QStringLiteral("MFT 序列号"), QString::number(itemValue.sequenceNumber) },
        { QStringLiteral("完整度"), kIntegrityText },
        { QStringLiteral("恢复能力"), deletedFileRecoveryCapabilityText(itemValue) },
        { QStringLiteral("驻留数据已就绪"),
          itemValue.residentDataReady ? QStringLiteral("是") : QStringLiteral("否") },
        { QStringLiteral("是否可安全恢复"),
          isDeletedFileSafelyRecoverable(itemValue)
          ? QStringLiteral("是")
          : QStringLiteral("否（恢复入口会拒绝此项）") },
    };

    propertyTable->setRowCount(kPropertyRows.size());
    for (int row = 0; row < kPropertyRows.size(); ++row)
    {
        propertyTable->setItem(row, 0, new QTableWidgetItem(kPropertyRows[row].first));
        propertyTable->setItem(row, 1, new QTableWidgetItem(kPropertyRows[row].second));
    }
    propertyTable->resizeColumnToContents(0);
    rootLayout->addWidget(propertyTable, 1);

    QLabel* noteLabel = new QLabel(
        QStringLiteral("以上为扫描时刻的 MFT 快照；恢复前会按记录号和序列号重新校验，不依赖此处的旧数据。"),
        &dialog);
    noteLabel->setWordWrap(true);
    rootLayout->addWidget(noteLabel, 0);

    QDialogButtonBox* buttonBox = new QDialogButtonBox(QDialogButtonBox::Close, &dialog);
    buttonBox->button(QDialogButtonBox::Close)->setText(QStringLiteral("关闭"));
    connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    rootLayout->addWidget(buttonBox, 0);

    dialog.exec();
}

void FileDock::refreshRecoveryVolumeList()
{
    if (recoveryVolumeCombo_ == nullptr)
    {
        return;
    }

    // Volume probing (GetDriveTypeW + GetVolumeInformationW) can block for several seconds to tens of seconds on empty optical drives or disconnected mapped network
    // drives. Since this function is called during the initial construction of the "Files" page, executing it on the UI thread would cause the entire window to
    // freeze when the tab is first opened. Here, we only perform "clear the list + disable the entry"; the actual probing is moved to a background thread.
    const quint64 kRequestGeneration =
        recoveryVolumeCombo_->property(kRecoveryVolumeProbeGenerationProperty).toULongLong() + 1U;
    recoveryVolumeCombo_->setProperty(
        kRecoveryVolumeProbeGenerationProperty, static_cast<qulonglong>(kRequestGeneration));

    recoveryVolumeCombo_->clear();
    recoveryVolumeCombo_->setEnabled(false);
    if (recoveryRefreshButton_ != nullptr)
    {
        recoveryRefreshButton_->setEnabled(false);
    }
    if (recoveryScanButton_ != nullptr)
    {
        recoveryScanButton_->setEnabled(false);
        if (recoveryEmptyScanButton_ != nullptr) { recoveryEmptyScanButton_->setEnabled(false); }
    }
    if (recoveryStatusLabel_ != nullptr)
    {
        recoveryStatusLabel_->setText(QStringLiteral("正在刷新..."));
    }

    const QPointer<FileDock> kGuardedSelf(this);
    QThreadPool::globalInstance()->start(
        [kGuardedSelf, kRequestGeneration]()
        {
            // The background only produces value types (volume root string lists) and touches no QWidget.
            const QVector<QString> kNtfsVolumeRootList = collectNtfsVolumeRootList();

            FileDock* const kTargetDock = kGuardedSelf.data();
            if (kTargetDock == nullptr)
            {
                return;
            }

            QMetaObject::invokeMethod(
                kTargetDock,
                [kGuardedSelf, kRequestGeneration, kNtfsVolumeRootList]()
                {
                    if (kGuardedSelf.isNull())
                    {
                        return;
                    }

                    FileDock* const kDock = kGuardedSelf.data();
                    if (kDock->recoveryVolumeCombo_ == nullptr)
                    {
                        return;
                    }
                    // generation: Only accept the result of the latest refresh request; discard replaced older probes.
                    const quint64 kCurrentGeneration = kDock->recoveryVolumeCombo_
                        ->property(kRecoveryVolumeProbeGenerationProperty)
                        .toULongLong();
                    if (kCurrentGeneration != kRequestGeneration)
                    {
                        return;
                    }

                    // commitVolumeList: The volume list persistence action; shares the same implementation for direct commits and re-injection after the popup is dismissed.
                    auto commitVolumeList = [kGuardedSelf, kRequestGeneration, kNtfsVolumeRootList]()
                    {
                        if (kGuardedSelf.isNull())
                        {
                            return;
                        }
                        FileDock* const kCommitDock = kGuardedSelf.data();
                        if (kCommitDock->recoveryVolumeCombo_ == nullptr)
                        {
                            return;
                        }
                        // During the delayed rollback, a new probe may have been initiated; re-verify the generation before committing.
                        const quint64 kLatestGeneration = kCommitDock->recoveryVolumeCombo_
                            ->property(kRecoveryVolumeProbeGenerationProperty)
                            .toULongLong();
                        if (kLatestGeneration != kRequestGeneration)
                        {
                            return;
                        }

                        kCommitDock->recoveryVolumeCombo_->clear();
                        for (const QString& volumeRootPath : kNtfsVolumeRootList)
                        {
                            const QString kDisplayText = QStringLiteral("%1 (NTFS)").arg(volumeRootPath);
                            kCommitDock->recoveryVolumeCombo_->addItem(kDisplayText, volumeRootPath);
                        }
                        kCommitDock->recoveryVolumeCombo_->setEnabled(true);

                        if (kCommitDock->recoveryRefreshButton_ != nullptr)
                        {
                            kCommitDock->recoveryRefreshButton_->setEnabled(true);
                        }
                        // The disable authority for the scan button belongs to the accidental deletion scan/recovery task: do not revert the disabled state after the probe ends.
                        if (kCommitDock->recoveryScanButton_ != nullptr
                            && !kCommitDock->recoveryScanInProgress_
                            && !kCommitDock->recoveryRecoverInProgress_)
                        {
                            kCommitDock->recoveryScanButton_->setEnabled(true);
                            if (kCommitDock->recoveryEmptyScanButton_ != nullptr) { kCommitDock->recoveryEmptyScanButton_->setEnabled(true); }
                        }

                        if (kCommitDock->recoveryStatusLabel_ != nullptr)
                        {
                            if (kCommitDock->recoveryVolumeCombo_->count() == 0)
                            {
                                kCommitDock->recoveryStatusLabel_->setText(
                                    QStringLiteral("未检测到可扫描的 NTFS 卷。"));
                            }
                            else
                            {
                                kCommitDock->recoveryStatusLabel_->setText(
                                    QStringLiteral("已刷新卷列表，可执行误删扫描。"));
                            }
                        }

                        KLogEvent event;
                        info << event
                            << "[FileDock] 刷新文件恢复卷列表, count="
                            << kCommitDock->recoveryVolumeCombo_->count()
                            << eol;
                    };

                    // Clearing and repopulating the volume dropdown while the popup is open causes the layer to retain mouse/keyboard focus
                    // while content becomes invalid, resulting in an unresponsive UI. This defers the update until after the popup closes.
                    if (ks::ui::deferUiCommitIfComboBoxPopupOpen(
                            kDock,
                            QStringLiteral("file-recovery-volume-combo-apply"),
                            commitVolumeList))
                    {
                        return;
                    }
                    commitVolumeList();
                },
                Qt::QueuedConnection);
        });
}

void FileDock::scanDeletedFilesForRecovery()
{
    // Retain the synchronous entry name externally, but implement it asynchronously internally to avoid blocking the UI.
    scanDeletedFilesForRecoveryAsync();
}

void FileDock::scanDeletedFilesForRecoveryAsync()
{
    if (recoveryVolumeCombo_ == nullptr || recoveryTable_ == nullptr || recoveryStatusLabel_ == nullptr)
    {
        return;
    }
    if (recoveryScanInProgress_)
    {
        return;
    }
    if (recoveryVolumeCombo_->currentIndex() < 0)
    {
        QMessageBox::warning(this, QStringLiteral("文件恢复"), QStringLiteral("请先选择 NTFS 卷。"));
        return;
    }

    const QString kRootPath = recoveryVolumeCombo_->currentData().toString();
    recoveryStatusLabel_->setText(QStringLiteral("正在扫描：%1").arg(kRootPath));
    recoveryScanInProgress_ = true;
    if (recoveryScanButton_ != nullptr)
    {
        recoveryScanButton_->setEnabled(false);
        if (recoveryEmptyScanButton_ != nullptr) { recoveryEmptyScanButton_->setEnabled(false); }
    }
    if (recoveryExportButton_ != nullptr)
    {
        recoveryExportButton_->setEnabled(false);
    }

    {
        KLogEvent event;
        info << event
            << "[FileDock] 开始扫描误删文件, volume="
            << QDir::toNativeSeparators(kRootPath).toStdString()
            << eol;
    }

    const int kProgressPid = kPro.add(this, "文件恢复", "扫描误删");
    kPro.set(kProgressPid, "准备扫描卷", 0, 5.0f);

    QPointer<FileDock> safeThis(this);
    std::thread([safeThis, kRootPath, kProgressPid]() {
        QString errorText;
        std::vector<ks::file::NtfsDeletedFileEntry> deletedItems;

        kPro.set(kProgressPid, "准备读取 NTFS 元数据", 0, 3.0f);
        const bool kScanOk = ks::file::ManualFileSystemParser::enumerateNtfsDeletedFiles(
            kRootPath,
            deletedItems,
            errorText,
            [kProgressPid](const int percentValue, const QString& stageText) {
                const int kBoundedPercent = std::clamp(percentValue, 0, 100);
                kPro.set(kProgressPid, stageText.toStdString(), 0, static_cast<float>(kBoundedPercent));
            });
        if (!kScanOk)
        {
            kPro.set(kProgressPid, "扫描失败，整理错误信息", 0, 82.0f);
        }

        if (safeThis.isNull())
        {
            kPro.set(kProgressPid, "界面已关闭", 0, 100.0f);
            return;
        }

        QMetaObject::invokeMethod(
            safeThis.data(),
            [safeThis,
             kRootPath,
             kProgressPid,
             kScanOk,
             deletedItems = std::move(deletedItems),
             errorText]() mutable {
                if (safeThis.isNull())
                {
                    kPro.set(kProgressPid, "界面已关闭", 0, 100.0f);
                    return;
                }

                const auto kDeletedItemsSnapshot =
                    std::make_shared<std::vector<ks::file::NtfsDeletedFileEntry>>(
                        std::move(deletedItems));
                const auto kCommitSnapshot =
                    [safeThis,
                     kRootPath,
                     kProgressPid,
                     kScanOk,
                     kDeletedItemsSnapshot,
                     errorText]()
                {
                    if (safeThis.isNull())
                    {
                        kPro.set(kProgressPid, "界面已关闭", 0, 100.0f);
                        return;
                    }

                    safeThis->recoveryScanInProgress_ = false;
                    if (safeThis->recoveryScanButton_ != nullptr)
                    {
                        safeThis->recoveryScanButton_->setEnabled(true);
                        if (safeThis->recoveryEmptyScanButton_ != nullptr) { safeThis->recoveryEmptyScanButton_->setEnabled(true); }
                    }
                    if (safeThis->recoveryExportButton_ != nullptr)
                    {
                        safeThis->recoveryExportButton_->setEnabled(true);
                    }

                    if (!kScanOk)
                    {
                        safeThis->recoveryStatusLabel_->setText(
                            QStringLiteral("扫描失败：%1").arg(errorText));
                        KLogEvent event;
                        err << event
                            << "[FileDock] 扫描误删失败, volume="
                            << QDir::toNativeSeparators(kRootPath).toStdString()
                            << ", error="
                            << errorText.toStdString()
                            << eol;
                        safeThis->updateRecoveryViewState(
                            false,
                            QStringLiteral("扫描未能完成，可更换卷或确认程序以管理员权限运行后重试。"));
                        QMessageBox::warning(safeThis.data(), QStringLiteral("扫描失败"), errorText);
                        kPro.set(kProgressPid, "扫描失败", 0, 100.0f);
                        return;
                    }

                    safeThis->deletedRecoveryItems_ = std::move(*kDeletedItemsSnapshot);
                    safeThis->recoveryTable_->setUpdatesEnabled(false);
                    safeThis->recoveryTable_->setSortingEnabled(false);
                    safeThis->recoveryTable_->clearContents();
                    safeThis->recoveryTable_->setRowCount(
                        static_cast<int>(safeThis->deletedRecoveryItems_.size()));
                    for (int row = 0;
                         row < static_cast<int>(safeThis->deletedRecoveryItems_.size());
                         ++row)
                    {
                        const ks::file::NtfsDeletedFileEntry& itemValue =
                            safeThis->deletedRecoveryItems_[static_cast<std::size_t>(row)];
                        // Integrity text: prefer displaying the estimated percentage; explicitly mark as unknown if evaluation is not possible.
                        const QString kIntegrityText =
                            (itemValue.estimatedIntegrityPercent >= 0)
                            ? QStringLiteral("%1%").arg(itemValue.estimatedIntegrityPercent)
                            : QStringLiteral("未知");

                        // Recoverability text: clearly distinguish between resident, complete non-resident, reused, and unsupported layouts.
                        QString recoverabilityText =
                            deletedFileRecoveryCapabilityText(itemValue);
                        if (!itemValue.hasOriginalName)
                        {
                            recoverabilityText += QStringLiteral(" / 缺名");
                        }

                        QTableWidgetItem* nameItem = new QTableWidgetItem(itemValue.fileName);
                        if (!itemValue.hasOriginalName)
                        {
                            nameItem->setToolTip(
                                QStringLiteral("该条目原始文件名已丢失，当前名称为系统生成的占位名。"));
                        }
                        safeThis->recoveryTable_->setItem(row, 0, nameItem);
                        safeThis->recoveryTable_->setItem(
                            row, 1, new QTableWidgetItem(itemValue.pathHint));
                        safeThis->recoveryTable_->setItem(
                            row, 2, new QTableWidgetItem(formatSizeText(itemValue.sizeBytes)));
                        safeThis->recoveryTable_->setItem(row, 3, new QTableWidgetItem(
                            itemValue.modifiedTime.isValid()
                            ? itemValue.modifiedTime.toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"))
                            : QStringLiteral("-")));
                        safeThis->recoveryTable_->setItem(
                            row,
                            4,
                            new QTableWidgetItem(
                                QStringLiteral("%1 / seq %2")
                                    .arg(static_cast<qulonglong>(itemValue.fileReference))
                                    .arg(itemValue.sequenceNumber)));
                        safeThis->recoveryTable_->setItem(
                            row, 5, new QTableWidgetItem(kIntegrityText));
                        safeThis->recoveryTable_->setItem(
                            row, 6, new QTableWidgetItem(recoverabilityText));
                    }
                    safeThis->recoveryTable_->setUpdatesEnabled(true);

                    const int kResidentReadyCount = static_cast<int>(std::count_if(
                        safeThis->deletedRecoveryItems_.begin(),
                        safeThis->deletedRecoveryItems_.end(),
                        [](const ks::file::NtfsDeletedFileEntry& item) {
                            return item.recoveryCapability ==
                                ks::file::NtfsRecoveryCapability::kResident;
                        }));
                    const int kNonResidentReadyCount = static_cast<int>(std::count_if(
                        safeThis->deletedRecoveryItems_.begin(),
                        safeThis->deletedRecoveryItems_.end(),
                        [](const ks::file::NtfsDeletedFileEntry& item) {
                            return item.recoveryCapability ==
                                ks::file::NtfsRecoveryCapability::kNonResidentIntact;
                        }));
                    const int kSafelyRecoverableCount = static_cast<int>(std::count_if(
                        safeThis->deletedRecoveryItems_.begin(),
                        safeThis->deletedRecoveryItems_.end(),
                        [](const ks::file::NtfsDeletedFileEntry& item) {
                            return isDeletedFileSafelyRecoverable(item);
                        }));
                    const int kHighIntegrityCount = static_cast<int>(std::count_if(
                        safeThis->deletedRecoveryItems_.begin(),
                        safeThis->deletedRecoveryItems_.end(),
                        [](const ks::file::NtfsDeletedFileEntry& item) {
                            return item.estimatedIntegrityPercent >= 80;
                        }));

                    // Keep the base text separate: when filtering, append "Filtered N / M items"
                    // after it, and ensure it can be restored exactly after clearing the search box.
                    safeThis->recoveryBaseStatusText_ =
                        QStringLiteral(
                            "扫描完成：%1 项（可安全恢复 %2 项：Resident %3，完整非驻留 %4；完整度≥80%% %5 项）")
                        .arg(safeThis->deletedRecoveryItems_.size())
                        .arg(kSafelyRecoverableCount)
                        .arg(kResidentReadyCount)
                        .arg(kNonResidentReadyCount)
                        .arg(kHighIntegrityCount);
                    safeThis->recoveryStatusLabel_->setText(safeThis->recoveryBaseStatusText_);

                    safeThis->updateRecoveryViewState(
                        !safeThis->deletedRecoveryItems_.empty(),
                        QStringLiteral("本次扫描未发现仍可恢复的删除项，可更换卷后重新扫描。"));

                    // After rescanning, retain the current search criteria to avoid requiring the user to re-enter them.
                    safeThis->applyRecoveryFilter();

                    KLogEvent event;
                    info << event
                        << "[FileDock] 扫描误删完成, volume="
                        << QDir::toNativeSeparators(kRootPath).toStdString()
                        << ", total="
                        << safeThis->deletedRecoveryItems_.size()
                        << eol;
                    kPro.set(kProgressPid, "扫描完成", 0, 100.0f);
                };

                if (ks::ui::deferTableUiCommitIfContextMenuOpen(
                    safeThis.data(),
                    QStringLiteral("file-recovery-scan-snapshot"),
                    { safeThis->recoveryTable_ },
                    kCommitSnapshot))
                {
                    return;
                }
                kCommitSnapshot();
            },
            Qt::QueuedConnection);
    }).detach();
}

void FileDock::recoverSelectedDeletedFiles()
{
    // Retain the synchronous entry name externally, but implement it asynchronously internally to avoid blocking the UI.
    recoverSelectedDeletedFilesAsync();
}

void FileDock::recoverSelectedDeletedFilesAsync()
{
    if (recoveryTable_ == nullptr || recoveryVolumeCombo_ == nullptr)
    {
        return;
    }
    if (recoveryRecoverInProgress_)
    {
        return;
    }
    const QModelIndexList kSelectedRows = recoveryTable_->selectionModel()->selectedRows();
    if (kSelectedRows.empty())
    {
        QMessageBox::information(this, QStringLiteral("文件恢复"), QStringLiteral("请先在列表中选择要恢复的条目。"));
        return;
    }

    const QString kExportDir = QFileDialog::getExistingDirectory(
        this,
        QStringLiteral("选择恢复输出目录"),
        QDir::homePath());
    if (kExportDir.isEmpty())
    {
        return;
    }

    const QString kVolumeRoot = recoveryVolumeCombo_->currentData().toString();
    std::vector<ks::file::NtfsDeletedFileEntry> selectedItems;
    selectedItems.reserve(static_cast<std::size_t>(kSelectedRows.size()));
    for (const QModelIndex& rowIndex : kSelectedRows)
    {
        const int kRowValue = rowIndex.row();
        if (kRowValue < 0 || kRowValue >= static_cast<int>(deletedRecoveryItems_.size()))
        {
            continue;
        }
        selectedItems.push_back(deletedRecoveryItems_[static_cast<std::size_t>(kRowValue)]);
    }
    if (selectedItems.empty())
    {
        QMessageBox::information(this, QStringLiteral("文件恢复"), QStringLiteral("未读取到有效恢复条目。"));
        return;
    }
    const bool kHasSafelyRecoverableItem = std::any_of(
        selectedItems.begin(),
        selectedItems.end(),
        [](const ks::file::NtfsDeletedFileEntry& item) {
            return isDeletedFileSafelyRecoverable(item);
        });
    if (!kHasSafelyRecoverableItem)
    {
        QMessageBox::warning(
            this,
            QStringLiteral("文件恢复"),
            QStringLiteral("选中项均不满足安全恢复条件；请查看“恢复能力”和“完整度”列。"));
        return;
    }

    const bool kHasIntactNonResidentItem = std::any_of(
        selectedItems.begin(),
        selectedItems.end(),
        [](const ks::file::NtfsDeletedFileEntry& item) {
            return item.recoveryCapability ==
                ks::file::NtfsRecoveryCapability::kNonResidentIntact;
        });
    const QString kSourceVolumeRoot = localVolumeRootForPath(kVolumeRoot);
    const QString kOutputVolumeRoot = localVolumeRootForPath(kExportDir);
    if (kHasIntactNonResidentItem &&
        !kSourceVolumeRoot.isEmpty() &&
        kSourceVolumeRoot.compare(kOutputVolumeRoot, Qt::CaseInsensitive) == 0)
    {
        QMessageBox::warning(
            this,
            QStringLiteral("非驻留恢复需要其它卷"),
            QStringLiteral(
                "选中项包含非驻留文件。不能把恢复结果写回源卷 %1，"
                "因为输出文件分配空间时可能直接覆盖待恢复簇。\n\n"
                "请重新选择其它本地卷或网络目录。")
                .arg(kSourceVolumeRoot));
        return;
    }

    recoveryRecoverInProgress_ = true;
    if (recoveryScanButton_ != nullptr)
    {
        recoveryScanButton_->setEnabled(false);
        if (recoveryEmptyScanButton_ != nullptr) { recoveryEmptyScanButton_->setEnabled(false); }
    }
    if (recoveryExportButton_ != nullptr)
    {
        recoveryExportButton_->setEnabled(false);
    }

    {
        KLogEvent event;
        info << event
            << "[FileDock] 开始恢复选中误删项, volume="
            << QDir::toNativeSeparators(kVolumeRoot).toStdString()
            << ", selectedRows="
            << selectedItems.size()
            << eol;
    }

    const int kProgressPid = kPro.add(this, "文件恢复", "恢复选中");
    kPro.set(kProgressPid, "准备恢复", 0, 5.0f);

    QPointer<FileDock> safeThis(this);
    std::thread([safeThis, kProgressPid, kVolumeRoot, kExportDir, selectedItems]() {
        int successCount = 0;
        QStringList failTextList;
        QSet<QString> reservedTargetPathSet;

        for (std::size_t index = 0; index < selectedItems.size(); ++index)
        {
            const ks::file::NtfsDeletedFileEntry& deletedItem = selectedItems[index];
            QString exportName = deletedItem.fileName.trimmed();
            if (exportName.isEmpty())
            {
                exportName = QStringLiteral("deleted_%1.bin").arg(deletedItem.fileReference);
            }
            const QString kTargetPath = uniqueRecoveryTargetPath(
                kExportDir,
                exportName,
                deletedItem.fileReference,
                reservedTargetPathSet);
            QString errorText;
            const bool kOk = ks::file::ManualFileSystemParser::recoverNtfsDeletedFile(
                kVolumeRoot,
                deletedItem,
                kTargetPath,
                errorText,
                [kProgressPid, index, itemCount = selectedItems.size()](
                    const int itemPercent,
                    const QString& stageText) {
                    const float kCompletedItemRatio =
                        static_cast<float>(index) /
                        static_cast<float>(std::max<std::size_t>(itemCount, 1));
                    const float kCurrentItemRatio =
                        (static_cast<float>(std::clamp(itemPercent, 0, 100)) / 100.0f) /
                        static_cast<float>(std::max<std::size_t>(itemCount, 1));
                    const float kMappedProgress =
                        5.0f + (kCompletedItemRatio + kCurrentItemRatio) * 90.0f;
                    kPro.set(
                        kProgressPid,
                        stageText.toStdString(),
                        0,
                        kMappedProgress);
                });
            if (kOk)
            {
                ++successCount;
            }
            else
            {
                failTextList.push_back(QStringLiteral("%1: %2").arg(exportName, errorText));
            }

            const float kProgress = 5.0f
                + (static_cast<float>(index + 1) / static_cast<float>(selectedItems.size())) * 90.0f;
            kPro.set(kProgressPid, "恢复处理中", 0, kProgress);
        }

        if (safeThis.isNull())
        {
            kPro.set(kProgressPid, "界面已关闭", 0, 100.0f);
            return;
        }

        QMetaObject::invokeMethod(
            safeThis.data(),
            [safeThis, kProgressPid, successCount, failTextList]() {
                if (safeThis.isNull())
                {
                    kPro.set(kProgressPid, "界面已关闭", 0, 100.0f);
                    return;
                }

                safeThis->recoveryRecoverInProgress_ = false;
                if (safeThis->recoveryScanButton_ != nullptr)
                {
                    safeThis->recoveryScanButton_->setEnabled(true);
                    if (safeThis->recoveryEmptyScanButton_ != nullptr) { safeThis->recoveryEmptyScanButton_->setEnabled(true); }
                }
                if (safeThis->recoveryExportButton_ != nullptr)
                {
                    safeThis->recoveryExportButton_->setEnabled(true);
                }

                const QString kSummaryText = QStringLiteral("恢复完成：成功 %1，失败 %2。")
                    .arg(successCount)
                    .arg(failTextList.size());
                safeThis->recoveryStatusLabel_->setText(kSummaryText);

                if (failTextList.empty())
                {
                    KLogEvent event;
                    info << event
                        << "[FileDock] 恢复完成, success="
                        << successCount
                        << ", failed=0"
                        << eol;
                    QMessageBox::information(safeThis.data(), QStringLiteral("文件恢复"), kSummaryText);
                }
                else
                {
                    KLogEvent event;
                    warn << event
                        << "[FileDock] 恢复部分失败, success="
                        << successCount
                        << ", failed="
                        << failTextList.size()
                        << eol;
                    QMessageBox::warning(
                        safeThis.data(),
                        QStringLiteral("文件恢复"),
                        kSummaryText + QStringLiteral("\n\n失败明细：\n") + failTextList.join('\n'));
                }

                kPro.set(kProgressPid, "恢复完成", 0, 100.0f);
            },
            Qt::QueuedConnection);
    }).detach();
}
