#include "FileDetailDialog.h"

namespace ksword::ui::file_dock
{
        bool FileDetailDialog::readUsageSelection(QTreeWidget* table, UsageSelection& selectionOut)
        {
            // Purpose: Retrieve the PID, creation time, and handle identity from the current row at the time of scanning.
            // These hidden fields must be saved along with visible rows to reject PID reuse or stale handles before operations.
            if (table == nullptr || table->currentItem() == nullptr)
            {
                return false;
            }

            QTreeWidgetItem* const kItem = table->currentItem();
            selectionOut.processId = kItem->data(0, kUsageProcessIdRole).toUInt();
            selectionOut.processCreationTime =
                kItem->data(0, kUsageProcessCreationTimeRole).toULongLong();
            selectionOut.handleValue = kItem->data(0, kUsageHandleValueRole).toULongLong();
            selectionOut.processName = kItem->text(1);
            selectionOut.matchedTargetPath = kItem->data(0, kUsageMatchedTargetPathRole).toString();
            selectionOut.matchedByDirectoryRule = kItem->data(0, kUsageDirectoryMatchRole).toBool();
            return selectionOut.processId != 0U;
        }

        void FileDetailDialog::closeSelectedUsageHandle(
            QTreeWidget* table,
            QLabel* statusLabel,
            QPushButton* refreshButton)
        {
            UsageSelection selection;
            if (!readUsageSelection(table, selection))
            {
                return;
            }
            if (selection.processId <= 4U ||
                selection.processId == static_cast<std::uint32_t>(::GetCurrentProcessId()) ||
                selection.processCreationTime == 0U || selection.handleValue == 0U ||
                isCriticalProcessName(selection.processName))
            {
                return;
            }

            std::string detailText;
            const bool kCloseOk = ks::file::closeRemoteHandle(
                selection.processId,
                selection.handleValue,
                selection.processCreationTime,
                selection.matchedTargetPath.toStdWString(),
                selection.matchedByDirectoryRule,
                detailText);
            if (!kCloseOk)
            {
                if (statusLabel != nullptr)
                {
                    statusLabel->setText(QString::fromStdString(detailText));
                }
                return;
            }

            statusLabel->setText(QStringLiteral("● 句柄已关闭，正在重新扫描占用状态..."));
            refreshUsageTable(table, statusLabel, refreshButton);
        }

        void FileDetailDialog::terminateSelectedUsageProcess(
            QTreeWidget* table,
            QLabel* statusLabel,
            QPushButton* refreshButton,
            const bool useKernelDriver)
        {
            UsageSelection selection;
            if (!readUsageSelection(table, selection))
            {
                return;
            }
            if (selection.processId <= 4U ||
                selection.processId == static_cast<std::uint32_t>(::GetCurrentProcessId()) ||
                selection.processCreationTime == 0U ||
                isCriticalProcessName(selection.processName))
            {
                return;
            }

            std::string detailText;
            bool terminateOk = false;
            if (useKernelDriver)
            {
                // First, hold a process handle with a verified creation time to prevent the driver from matching a reused new process when looking up by PID.
                HANDLE verifiedProcessHandle = nullptr;
                if (ks::file::openProcessForVerifiedAction(
                        selection.processId,
                        selection.processCreationTime,
                        SYNCHRONIZE,
                        verifiedProcessHandle,
                        detailText))
                {
                    ksword::ark::DriverHandle driverHandle = openKswordArkDriverHandle(&detailText);
                    if (driverHandle.isValid())
                    {
                        terminateOk = terminateProcessByR0Driver(driverHandle, selection.processId, &detailText);
                    }
                    ::CloseHandle(verifiedProcessHandle);
                }
            }
            else
            {
                terminateOk = terminateProcessByR3(
                    selection.processId,
                    selection.processCreationTime,
                    &detailText);
            }

            if (!terminateOk)
            {
                if (statusLabel != nullptr)
                {
                    statusLabel->setText(QString::fromStdString(detailText));
                }
                return;
            }

            statusLabel->setText(QStringLiteral("● 进程已结束，正在重新扫描占用状态..."));
            refreshUsageTable(table, statusLabel, refreshButton);
        }

        void FileDetailDialog::refreshUsageTable(QTreeWidget* table, QLabel* statusLabel, QPushButton* refreshButton)
        {
            // Purpose: Asynchronously refresh the file usage list within the properties page.
            // Processing: Invokes FileHandleUsageScanner; results display PID/Handle/GrantedAccess/Source.
            // Returns: Nothing.
            if (table == nullptr || statusLabel == nullptr || refreshButton == nullptr)
            {
                return;
            }

            QFileInfo info(filePath_);
            if (!info.exists())
            {
                statusLabel->setText(QStringLiteral("● 目标不存在，无法扫描占用。"));
                return;
            }

            refreshButton->setEnabled(false);
            table->clear();
            statusLabel->setText(QStringLiteral("● 正在扫描文件占用..."));
            if (usageScanProgressBar_ != nullptr)
            {
                usageScanProgressBar_->setRange(0, 100);
                usageScanProgressBar_->setValue(0);
                usageScanProgressBar_->setFormat(QStringLiteral("%p%"));
            }
            usageScanInProgress_ = true;
            usageRetryAfterR0Start_ = false;
            usageR0StartedDuringScan_ = false;
            usageScanCancelRequested_->store(false);

            const std::vector<QString> kTargetPaths{ info.absoluteFilePath() };
            const std::shared_ptr<std::atomic_bool> kCancelRequested =
                usageScanCancelRequested_;
            QPointer<FileDetailDialog> guardThis(this);
            QPointer<QTreeWidget> tableGuard(table);
            QPointer<QLabel> statusGuard(statusLabel);
            QPointer<QPushButton> refreshGuard(refreshButton);
            QPointer<QProgressBar> progressGuard(usageScanProgressBar_);
            QPointer<QObject> uiDispatcher(QCoreApplication::instance());

            auto* task = QRunnable::create([guardThis, tableGuard, statusGuard, refreshGuard,
                                             progressGuard, uiDispatcher, kTargetPaths, kCancelRequested]()
                {
                    const filedock::handleusage::HandleUsageScanResult kScanResult =
                        filedock::handleusage::scanHandleUsageByPaths(
                            kTargetPaths,
                            0,
                            true,
                            [kCancelRequested]()
                            {
                                return kCancelRequested->load();
                            },
                            [guardThis, progressGuard, uiDispatcher, kCancelRequested](
                                const QString&,
                                const float progressValue)
                            {
                                QObject* const kDispatcher = uiDispatcher.data();
                                if (kCancelRequested->load() || guardThis == nullptr ||
                                    progressGuard == nullptr || kDispatcher == nullptr)
                                {
                                    return;
                                }
                                const int kPercentage = static_cast<int>(std::clamp(progressValue, 0.0f, 100.0f));
                                QMetaObject::invokeMethod(
                                    kDispatcher,
                                    [guardThis, progressGuard, kCancelRequested, kPercentage]()
                                    {
                                        if (!kCancelRequested->load() && guardThis != nullptr &&
                                            progressGuard != nullptr)
                                        {
                                            progressGuard->setValue(kPercentage);
                                        }
                                    },
                                    Qt::QueuedConnection);
                            });
                    QObject* dispatcher = uiDispatcher.data();
                    if (kCancelRequested->load() || dispatcher == nullptr)
                    {
                        return;
                    }

                    QMetaObject::invokeMethod(
                        dispatcher,
                        [guardThis, tableGuard, statusGuard, refreshGuard,
                         progressGuard, kCancelRequested, kScanResult]()
                        {
                            if (kCancelRequested->load() || guardThis == nullptr || tableGuard == nullptr ||
                                statusGuard == nullptr || refreshGuard == nullptr)
                            {
                                return;
                            }

                            const auto kScanSnapshot =
                                std::make_shared<filedock::handleusage::HandleUsageScanResult>(kScanResult);
                            const auto kCommitSnapshot =
                                [guardThis, tableGuard, statusGuard, refreshGuard, progressGuard, kScanSnapshot]()
                            {
                                if (guardThis == nullptr || tableGuard == nullptr || statusGuard == nullptr ||
                                    refreshGuard == nullptr)
                                {
                                    return;
                                }

                                tableGuard->setSortingEnabled(false);
                                tableGuard->clear();
                                for (const filedock::handleusage::HandleUsageEntry& entry : kScanSnapshot->entries)
                                {
                                    auto* item = new QTreeWidgetItem();
                                    item->setText(0, QString::number(entry.processId));
                                    item->setText(1, entry.processName);
                                    item->setText(2, entry.handleValue == 0
                                        ? QStringLiteral("-")
                                        : formatHex64(entry.handleValue));
                                    item->setText(3, entry.grantedAccess == 0
                                        ? QStringLiteral("-")
                                        : QStringLiteral("0x%1").arg(entry.grantedAccess, 8, 16, QChar('0')).toUpper());
                                    item->setText(4, entry.objectName);
                                    item->setText(5, entry.matchedTargetPath);
                                    const QString kSourceText = entry.enumerationSource.trimmed().isEmpty()
                                        ? QStringLiteral("R3 DuplicateHandle")
                                        : entry.enumerationSource;
                                    const QString kRuleText = entry.matchRuleText.trimmed().isEmpty()
                                        ? (entry.matchedByDirectoryRule ? QStringLiteral("目录前缀") : QStringLiteral("精确"))
                                        : entry.matchRuleText;
                                    item->setText(6, QStringLiteral("%1 | %2").arg(kSourceText, kRuleText));
                                    item->setData(0, kUsageProcessIdRole, static_cast<qulonglong>(entry.processId));
                                    item->setData(0, kUsageProcessCreationTimeRole, static_cast<qulonglong>(entry.processCreationTime));
                                    item->setData(0, kUsageHandleValueRole, static_cast<qulonglong>(entry.handleValue));
                                    item->setData(0, kUsageMatchedTargetPathRole, entry.matchedTargetPath);
                                    item->setData(0, kUsageDirectoryMatchRole, entry.matchedByDirectoryRule);
                                    tableGuard->addTopLevelItem(item);
                                }
                                tableGuard->setSortingEnabled(true);
                                if (tableGuard->header() != nullptr)
                                {
                                    tableGuard->resizeColumnToContents(0);
                                    tableGuard->resizeColumnToContents(1);
                                    tableGuard->resizeColumnToContents(2);
                                    tableGuard->resizeColumnToContents(3);
                                }
                                if (tableGuard->topLevelItemCount() > 0)
                                {
                                    tableGuard->setCurrentItem(tableGuard->topLevelItem(0));
                                }

                                QString statusText = QStringLiteral("● 扫描完成 %1 ms | 总句柄:%2 | 文件句柄:%3 | 命中:%4")
                                    .arg(kScanSnapshot->elapsedMs)
                                    .arg(kScanSnapshot->totalHandleCount)
                                    .arg(kScanSnapshot->fileLikeHandleCount)
                                    .arg(kScanSnapshot->matchedHandleCount);
                                if (!kScanSnapshot->diagnosticText.trimmed().isEmpty())
                                {
                                    statusText += QStringLiteral(
                                        " | 存在诊断；详情已写入日志。");
                                    KLogEvent diagnosticEvent;
                                    warn << diagnosticEvent
                                        << "[FileDetailDialog] usage scan completed with diagnostics, matchedHandleCount="
                                        << kScanSnapshot->matchedHandleCount
                                        << ", diagnostic="
                                        << kScanSnapshot->diagnosticText.toStdString()
                                        << eol;
                                }
                                statusGuard->setText(statusText);
                                if (progressGuard != nullptr)
                                {
                                    progressGuard->setValue(100);
                                }
                                refreshGuard->setEnabled(true);

                                guardThis->usageScanInProgress_ = false;
                                if (!kScanSnapshot->r3HandleFallbackUsed)
                                {
                                    guardThis->usageRetryAfterR0Start_ = false;
                                    guardThis->usageR0StartedDuringScan_ = false;
                                    return;
                                }

                                // DriverClient already invoked R0 in this round, and mainWindow prompts to enable it on the UI thread.
                                // If the service started during R3 fallback, submit the current R3 result and then automatically rescan only once.
                                // Otherwise, retain the R3 result and wait for the subsequent R0 start success notification.
                                if (guardThis->usageR0StartedDuringScan_)
                                {
                                    guardThis->usageR0StartedDuringScan_ = false;
                                    QMetaObject::invokeMethod(
                                        guardThis.data(),
                                        [guardThis, tableGuard, statusGuard, refreshGuard]()
                                        {
                                            if (guardThis != nullptr && tableGuard != nullptr &&
                                                statusGuard != nullptr && refreshGuard != nullptr)
                                            {
                                                guardThis->refreshUsageTable(
                                                    tableGuard.data(),
                                                    statusGuard.data(),
                                                    refreshGuard.data());
                                            }
                                        },
                                        Qt::QueuedConnection);
                                    return;
                                }
                                guardThis->usageRetryAfterR0Start_ = true;
                            };

                            if (ks::ui::deferItemViewUiCommitIfContextMenuOpen(
                                guardThis.data(),
                                QStringLiteral("file-detail-usage-snapshot"),
                                { tableGuard.data() },
                                kCommitSnapshot))
                            {
                                return;
                            }
                            kCommitSnapshot();
                        },
                        Qt::QueuedConnection);
                });
            task->setAutoDelete(true);
            QThreadPool::globalInstance()->start(task);
        }

        QWidget* FileDetailDialog::buildUsageTab()
        {
            // Purpose: Phase-10 embeds existing file usage scan results directly into the properties window.
            // Note: Only create a lightweight UI here; do not auto-scan on the first tab switch to avoid blocking the property window
            //       due to system handle enumeration and result backfilling. The user triggers a background scan by clicking 'Refresh Usage'.
            //       Scanner first calls the R0 HandleTable; if R0 is disabled, a global entry prompts the user. This round falls
            //       back to R3, and after the service is successfully enabled, the property page automatically rescans once.
            QWidget* page = new QWidget(this);
            QVBoxLayout* layout = new QVBoxLayout(page);

            QHBoxLayout* toolbarLayout = new QHBoxLayout();
            QPushButton* refreshButton = new QPushButton(QStringLiteral("刷新占用"), page);
            refreshButton->setIcon(QIcon(QStringLiteral(":/Icon/handle_refresh.svg")));
            refreshButton->setIconSize(QSize(16, 16));
            refreshButton->setToolTip(QStringLiteral("重新扫描当前文件或目录的占用句柄"));

            QPushButton* closeHandleButton = new QPushButton(QStringLiteral("关闭句柄（R3）"), page);
            closeHandleButton->setIcon(QIcon(QStringLiteral(":/Icon/handle_close.svg")));
            closeHandleButton->setIconSize(QSize(16, 16));
            closeHandleButton->setToolTip(QStringLiteral("校验选中记录后，从用户态关闭该远程文件句柄"));
            closeHandleButton->setEnabled(false);

            QPushButton* terminateR3Button = new QPushButton(QStringLiteral("结束进程（R3）"), page);
            terminateR3Button->setIcon(QIcon(QStringLiteral(":/Icon/process_terminate.svg")));
            terminateR3Button->setIconSize(QSize(16, 16));
            terminateR3Button->setToolTip(QStringLiteral("校验 PID 和进程创建时间后，从用户态结束占用进程"));
            terminateR3Button->setEnabled(false);

            QPushButton* terminateR0Button = new QPushButton(QStringLiteral("结束进程（R0）"), page);
            terminateR0Button->setIcon(QIcon(QStringLiteral(":/Icon/process_terminate.svg")));
            terminateR0Button->setIconSize(QSize(16, 16));
            terminateR0Button->setToolTip(QStringLiteral("校验 PID 和进程创建时间后，由 KswordARK 驱动结束占用进程"));
            terminateR0Button->setEnabled(false);

            QLabel* statusLabel = new QLabel(QStringLiteral("● 未扫描，点击“刷新占用”开始枚举文件占用。"), page);
            statusLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
            toolbarLayout->addWidget(refreshButton, 0);
            toolbarLayout->addWidget(closeHandleButton, 0);
            toolbarLayout->addWidget(terminateR3Button, 0);
            toolbarLayout->addWidget(terminateR0Button, 0);
            toolbarLayout->addStretch(1);
            layout->addLayout(toolbarLayout);
            layout->addWidget(statusLabel, 0);

            QProgressBar* usageProgressBar = new QProgressBar(page);
            usageProgressBar->setRange(0, 100);
            usageProgressBar->setValue(0);
            usageProgressBar->setFormat(QStringLiteral("%p%"));
            usageScanProgressBar_ = usageProgressBar;
            layout->addWidget(usageProgressBar, 0);

            QTreeWidget* table = new QTreeWidget(page);
            table->setColumnCount(7);
            table->setHeaderLabels(QStringList{
                QStringLiteral("PID"),
                QStringLiteral("进程名"),
                QStringLiteral("Handle"),
                QStringLiteral("GrantedAccess"),
                QStringLiteral("对象/路径"),
                QStringLiteral("命中目标"),
                QStringLiteral("枚举来源")
                });
            table->setRootIsDecorated(false);
            table->setAlternatingRowColors(true);
            table->setSelectionBehavior(QAbstractItemView::SelectRows);
            table->setSelectionMode(QAbstractItemView::SingleSelection);
            table->setEditTriggers(QAbstractItemView::NoEditTriggers);
            table->setSortingEnabled(true);
            if (table->header() != nullptr)
            {
                table->header()->setStretchLastSection(true);
            }
            installFileTreeCopyMenu(table, 0);
            layout->addWidget(table, 1);

            connect(refreshButton, &QPushButton::clicked, this, [this, table, statusLabel, refreshButton]()
                {
                    refreshUsageTable(table, statusLabel, refreshButton);
                });
            connect(table, &QTreeWidget::currentItemChanged, this,
                [closeHandleButton, terminateR3Button, terminateR0Button](QTreeWidgetItem* currentItem)
                {
                    const std::uint32_t kProcessId = currentItem == nullptr
                        ? 0U
                        : currentItem->data(0, kUsageProcessIdRole).toUInt();
                    const std::uint64_t kCreationTime = currentItem == nullptr
                        ? 0U
                        : currentItem->data(0, kUsageProcessCreationTimeRole).toULongLong();
                    const std::uint64_t kHandleValue = currentItem == nullptr
                        ? 0U
                        : currentItem->data(0, kUsageHandleValueRole).toULongLong();
                    const QString kProcessName = currentItem == nullptr ? QString() : currentItem->text(1);
                    const bool kProcessActionAllowed = kProcessId > 4U &&
                        kProcessId != static_cast<std::uint32_t>(::GetCurrentProcessId()) &&
                        kCreationTime != 0U && !isCriticalProcessName(kProcessName);
                    closeHandleButton->setEnabled(kProcessActionAllowed && kHandleValue != 0U);
                    terminateR3Button->setEnabled(kProcessActionAllowed);
                    terminateR0Button->setEnabled(kProcessActionAllowed);
                });
            connect(closeHandleButton, &QPushButton::clicked, this,
                [this, table, statusLabel, refreshButton]()
                {
                    closeSelectedUsageHandle(table, statusLabel, refreshButton);
                });
            connect(terminateR3Button, &QPushButton::clicked, this,
                [this, table, statusLabel, refreshButton]()
                {
                    terminateSelectedUsageProcess(table, statusLabel, refreshButton, false);
                });
            connect(terminateR0Button, &QPushButton::clicked, this,
                [this, table, statusLabel, refreshButton]()
                {
                    terminateSelectedUsageProcess(table, statusLabel, refreshButton, true);
                });

            MainWindow* const kMainWindow = qobject_cast<MainWindow*>(parentWidget() != nullptr
                ? parentWidget()->window()
                : nullptr);
            if (kMainWindow != nullptr)
            {
                connect(kMainWindow, &MainWindow::r0DriverServiceStarted, this,
                    [this, table, statusLabel, refreshButton]()
                    {
                        if (usageScanInProgress_)
                        {
                            usageR0StartedDuringScan_ = true;
                            return;
                        }
                        if (!usageRetryAfterR0Start_)
                        {
                            return;
                        }
                        usageRetryAfterR0Start_ = false;
                        refreshUsageTable(table, statusLabel, refreshButton);
                    });
            }

            if (initialTabKey_ == QStringLiteral("usage"))
            {
                // Scan directly when entering from the "File Usage and Unlock" entry.
                // Keep manual tab switching in the standard properties window on-demand to avoid meaningless full-system enumeration.
                QMetaObject::invokeMethod(
                    this,
                    [this, table, statusLabel, refreshButton]()
                    {
                        refreshUsageTable(table, statusLabel, refreshButton);
                    },
                    Qt::QueuedConnection);
            }
            return page;
        }
}
