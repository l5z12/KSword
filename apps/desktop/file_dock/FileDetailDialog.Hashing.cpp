#include "FileDetailDialog.h"

namespace ksword::ui::file_dock
{
        void FileDetailDialog::startHashCalculation(
            CodeEditorWidget* textEditorWidget,
            QProgressBar* progressBar,
            QPushButton* startButton,
            QPushButton* cancelButton)
        {
            // Purpose: Start background streaming SHA256 calculation.
            // Processing: Check cancellation flag and update progress asynchronously after each read block.
            // Returns: None; results are propagated back to the UI via QueuedConnection.
            if (textEditorWidget == nullptr || progressBar == nullptr ||
                startButton == nullptr || cancelButton == nullptr)
            {
                return;
            }

            if (hashCancelRequested_ == nullptr)
            {
                hashCancelRequested_ = std::make_shared<std::atomic_bool>(false);
            }
            hashCancelRequested_->store(false);

            startButton->setEnabled(false);
            cancelButton->setEnabled(true);
            cancelButton->setText(QStringLiteral("取消"));
            progressBar->setValue(0);
            textEditorWidget->setLocalizedText(QStringLiteral("正在计算 SHA256，请等待...\n目标: %1")
                .arg(QDir::toNativeSeparators(filePath_)));

            const QString kFilePathSnapshot = filePath_;
            const auto kCancelFlag = hashCancelRequested_;
            QPointer<FileDetailDialog> guardThis(this);
            QPointer<CodeEditorWidget> editorGuard(textEditorWidget);
            QPointer<QProgressBar> progressGuard(progressBar);
            QPointer<QPushButton> startGuard(startButton);
            QPointer<QPushButton> cancelGuard(cancelButton);

            auto* task = QRunnable::create([guardThis, editorGuard, progressGuard, startGuard, cancelGuard, kFilePathSnapshot, kCancelFlag]()
                {
                    HashCalculationResult result{};
                    const auto kBeginTime = std::chrono::steady_clock::now();
                    QFile file(kFilePathSnapshot);
                    result.totalBytes = QFileInfo(kFilePathSnapshot).size();

                    if (!file.open(QIODevice::ReadOnly))
                    {
                        result.fileError = file.error();
                    }
                    else
                    {
                        result.openOk = true;
                        QCryptographicHash sha256(QCryptographicHash::Sha256);
                        constexpr qint64 kChunkBytes = 1024 * 1024;
                        auto lastProgressTime = std::chrono::steady_clock::now();

                        while (!file.atEnd())
                        {
                            if (kCancelFlag != nullptr && kCancelFlag->load())
                            {
                                result.cancelled = true;
                                break;
                            }

                            const QByteArray kChunk = file.read(kChunkBytes);
                            if (kChunk.isEmpty())
                            {
                                if (file.error() != QFileDevice::NoError)
                                {
                                    result.fileError = file.error();
                                }
                                break;
                            }

                            sha256.addData(kChunk);
                            result.readBytes += kChunk.size();

                            const auto kNowTime = std::chrono::steady_clock::now();
                            const bool kShouldReport =
                                std::chrono::duration_cast<std::chrono::milliseconds>(kNowTime - lastProgressTime).count() >= 100;
                            if (kShouldReport && guardThis != nullptr && progressGuard != nullptr)
                            {
                                lastProgressTime = kNowTime;
                                const int kProgressValue = result.totalBytes > 0
                                    ? static_cast<int>((result.readBytes * 1000LL) / result.totalBytes)
                                    : 1000;
                                FileDetailDialog* targetDialog = guardThis.data();
                                if (targetDialog == nullptr)
                                {
                                    continue;
                                }
                                QMetaObject::invokeMethod(
                                    targetDialog,
                                    [progressGuard, kProgressValue]()
                                    {
                                        if (progressGuard != nullptr)
                                        {
                                            progressGuard->setValue(std::min(kProgressValue, 1000));
                                        }
                                    },
                                    Qt::QueuedConnection);
                            }
                        }

                        if (!result.cancelled && result.fileError == QFileDevice::NoError)
                        {
                            result.sha256Text = QString::fromLatin1(sha256.result().toHex());
                        }
                        file.close();
                    }

                    result.elapsedMs = static_cast<qint64>(
                        std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - kBeginTime).count());

                    FileDetailDialog* targetDialog = guardThis.data();
                    if (targetDialog == nullptr)
                    {
                        return;
                    }

                    QMetaObject::invokeMethod(
                        targetDialog,
                        [guardThis, editorGuard, progressGuard, startGuard, cancelGuard, result]()
                        {
                            if (guardThis == nullptr || editorGuard == nullptr ||
                                progressGuard == nullptr || startGuard == nullptr ||
                                cancelGuard == nullptr)
                            {
                                return;
                            }

                            startGuard->setEnabled(true);
                            cancelGuard->setEnabled(false);
                            cancelGuard->setText(QStringLiteral("取消"));
                            progressGuard->setValue(result.totalBytes > 0
                                ? static_cast<int>((result.readBytes * 1000LL) / result.totalBytes)
                                : 1000);

                            const double kElapsedSeconds = std::max(0.001, static_cast<double>(result.elapsedMs) / 1000.0);
                            const double kSpeedMiB = (static_cast<double>(result.readBytes) / (1024.0 * 1024.0)) / kElapsedSeconds;

                            QString content;
                            content += QStringLiteral("算法: SHA256\n");
                            content += QStringLiteral("来源: 用户态流式读取(QCryptographicHash)\n");
                            content += QStringLiteral("文件: %1\n").arg(QDir::toNativeSeparators(guardThis->filePath_));
                            content += QStringLiteral("总大小: %1 字节\n").arg(result.totalBytes);
                            content += QStringLiteral("已读取: %1 字节\n").arg(result.readBytes);
                            content += QStringLiteral("耗时: %1 ms\n").arg(result.elapsedMs);
                            content += QStringLiteral("速度: %1 MiB/s\n").arg(QString::number(kSpeedMiB, 'f', 2));
                            content += QStringLiteral("是否取消: %1\n").arg(result.cancelled ? QStringLiteral("是") : QStringLiteral("否"));
                            if (result.fileError != QFileDevice::NoError)
                            {
                                content += QStringLiteral("QFile错误码: %1\n")
                                    .arg(static_cast<int>(result.fileError));
                            }
                            if (!result.sha256Text.isEmpty())
                            {
                                content += QStringLiteral("SHA256: %1\n").arg(result.sha256Text);
                            }
                            editorGuard->setLocalizedText(content);
                        },
                        Qt::QueuedConnection);
                });
            task->setAutoDelete(true);
            QThreadPool::globalInstance()->start(task);
        }

        void FileDetailDialog::requestHashCancel(QPushButton* cancelButton)
        {
            // Purpose: Set the hash cancellation flag.
            // Return: None; the background thread checks this flag at the next block boundary.
            if (hashCancelRequested_ != nullptr)
            {
                hashCancelRequested_->store(true);
            }
            if (cancelButton != nullptr)
            {
                cancelButton->setEnabled(false);
                cancelButton->setText(QStringLiteral("正在取消..."));
            }
        }

        QWidget* FileDetailDialog::buildHashTab()
        {
            if (batchMode_)
            {
                QWidget* page = new QWidget(this);
                QVBoxLayout* layout = new QVBoxLayout(page);
                QHBoxLayout* toolbar = new QHBoxLayout();
                QPushButton* startButton = new QPushButton(QStringLiteral("批量计算 SHA256"), page);
                QPushButton* cancelButton = new QPushButton(QStringLiteral("取消"), page);
                cancelButton->setEnabled(false);
                QLabel* statusLabel = new QLabel(QStringLiteral("● 等待开始批量哈希"), page);
                toolbar->addWidget(startButton);
                toolbar->addWidget(cancelButton);
                toolbar->addWidget(statusLabel, 1);
                layout->addLayout(toolbar);
                QProgressBar* progress = new QProgressBar(page);
                progress->setRange(0, filePaths_.size());
                progress->setValue(0);
                layout->addWidget(progress);
                QTableWidget* table = new ks::ui::VisibleTableWidget(page);
                table->setColumnCount(4);
                table->setHorizontalHeaderLabels(QStringList{
                    QStringLiteral("目标"), QStringLiteral("状态"),
                    QStringLiteral("SHA256"), QStringLiteral("错误") });
                table->setRowCount(filePaths_.size());
                table->setSelectionBehavior(QAbstractItemView::SelectRows);
                table->setSelectionMode(QAbstractItemView::ExtendedSelection);
                table->setEditTriggers(QAbstractItemView::NoEditTriggers);
                table->setAlternatingRowColors(true);
                for (qsizetype row = 0; row < filePaths_.size(); ++row)
                {
                    table->setItem(static_cast<int>(row), 0,
                        new QTableWidgetItem(QDir::toNativeSeparators(filePaths_.at(row))));
                    table->setItem(static_cast<int>(row), 1,
                        new QTableWidgetItem(QStringLiteral("等待")));
                    table->setItem(static_cast<int>(row), 2, new QTableWidgetItem());
                    table->setItem(static_cast<int>(row), 3, new QTableWidgetItem());
                }
                installFileTableCopyMenu(table);
                if (table->horizontalHeader() != nullptr)
                    table->horizontalHeader()->setStretchLastSection(true);
                layout->addWidget(table, 1);
                connect(cancelButton, &QPushButton::clicked, this, [this, cancelButton]()
                    {
                        if (hashCancelRequested_ != nullptr)
                            hashCancelRequested_->store(true);
                        cancelButton->setEnabled(false);
                    });
                connect(startButton, &QPushButton::clicked, this,
                    [this, table, progress, statusLabel, startButton, cancelButton]()
                    {
                        hashCancelRequested_ = std::make_shared<std::atomic_bool>(false);
                        const auto kCancelRequested = hashCancelRequested_;
                        const QStringList kPaths = filePaths_;
                        startButton->setEnabled(false);
                        cancelButton->setEnabled(true);
                        progress->setValue(0);
                        statusLabel->setText(QStringLiteral("● 正在后台计算批量 SHA256..."));
                        QPointer<QTableWidget> tableGuard(table);
                        QPointer<QProgressBar> progressGuard(progress);
                        QPointer<QLabel> statusGuard(statusLabel);
                        QPointer<QPushButton> startGuard(startButton);
                        QPointer<QPushButton> cancelGuard(cancelButton);
                        auto* task = QRunnable::create(
                            [tableGuard, progressGuard, statusGuard, startGuard, cancelGuard,
                             kCancelRequested, kPaths]()
                            {
                                int completed = 0;
                                for (qsizetype row = 0; row < kPaths.size(); ++row)
                                {
                                    if (kCancelRequested->load()) break;
                                    QString stateText;
                                    QString hashText;
                                    QString errorText;
                                    const QFileInfo kInfo(kPaths.at(row));
                                    if (!kInfo.isFile())
                                    {
                                        stateText = QStringLiteral("已跳过");
                                        errorText = QStringLiteral("不是普通文件");
                                    }
                                    else
                                    {
                                        QFile file(kPaths.at(row));
                                        if (!file.open(QIODevice::ReadOnly))
                                        {
                                            stateText = QStringLiteral("失败");
                                            errorText = file.errorString();
                                        }
                                        else
                                        {
                                            QCryptographicHash hash(QCryptographicHash::Sha256);
                                            while (!file.atEnd() && !kCancelRequested->load())
                                            {
                                                const QByteArray kBlock = file.read(1024 * 1024);
                                                if (kBlock.isEmpty() && file.error() != QFileDevice::NoError) break;
                                                hash.addData(kBlock);
                                            }
                                            if (kCancelRequested->load())
                                            {
                                                stateText = QStringLiteral("已取消");
                                            }
                                            else if (file.error() != QFileDevice::NoError)
                                            {
                                                stateText = QStringLiteral("失败");
                                                errorText = file.errorString();
                                            }
                                            else
                                            {
                                                stateText = QStringLiteral("完成");
                                                hashText = QString::fromLatin1(hash.result().toHex().toUpper());
                                            }
                                        }
                                    }
                                    ++completed;
                                    if (tableGuard == nullptr) return;
                                    QMetaObject::invokeMethod(tableGuard.data(),
                                        [tableGuard, progressGuard, row, completed, stateText, hashText, errorText]()
                                        {
                                            if (tableGuard == nullptr) return;
                                            tableGuard->item(static_cast<int>(row), 1)->setText(stateText);
                                            tableGuard->item(static_cast<int>(row), 2)->setText(hashText);
                                            tableGuard->item(static_cast<int>(row), 3)->setText(errorText);
                                            if (progressGuard != nullptr) progressGuard->setValue(completed);
                                        }, Qt::QueuedConnection);
                                }
                                if (statusGuard == nullptr) return;
                                QMetaObject::invokeMethod(statusGuard.data(),
                                    [statusGuard, startGuard, cancelGuard, kCancelRequested, completed, kPaths]()
                                    {
                                        if (statusGuard == nullptr) return;
                                        statusGuard->setText(kCancelRequested->load()
                                            ? QStringLiteral("● 批量哈希已取消，完成 %1 / %2。")
                                                .arg(completed).arg(kPaths.size())
                                            : QStringLiteral("● 批量哈希完成，共处理 %1 项。")
                                                .arg(completed));
                                        if (startGuard != nullptr) startGuard->setEnabled(true);
                                        if (cancelGuard != nullptr) cancelGuard->setEnabled(false);
                                    }, Qt::QueuedConnection);
                            });
                        task->setAutoDelete(true);
                        QThreadPool::globalInstance()->start(task);
                    });
                return page;
            }

            QWidget* page = new QWidget(this);
            QVBoxLayout* layout = new QVBoxLayout(page);

            QHBoxLayout* toolbarLayout = new QHBoxLayout();
            QPushButton* startButton = new QPushButton(QStringLiteral("计算 SHA256"), page);
            QPushButton* cancelButton = new QPushButton(QStringLiteral("取消"), page);
            cancelButton->setEnabled(false);
            toolbarLayout->addWidget(startButton, 0);
            toolbarLayout->addWidget(cancelButton, 0);
            toolbarLayout->addStretch(1);
            layout->addLayout(toolbarLayout);

            QProgressBar* progressBar = new QProgressBar(page);
            progressBar->setRange(0, 1000);
            progressBar->setValue(0);
            layout->addWidget(progressBar, 0);

            CodeEditorWidget* textEditorWidget = new CodeEditorWidget(page);
            textEditorWidget->setReadOnly(true);
            layout->addWidget(textEditorWidget, 1);

            textEditorWidget->setLocalizedText(QStringLiteral(
                "Phase 10 哈希页：\n"
                "- SHA256 使用用户态流式读取，避免一次性读入大文件。\n"
                "- 点击“取消”会在下一个块读取边界停止。\n"
                "- 可用 PowerShell Get-FileHash -Algorithm SHA256 进行对比。\n"));

            connect(startButton, &QPushButton::clicked, this, [this, textEditorWidget, progressBar, startButton, cancelButton]()
                {
                    startHashCalculation(textEditorWidget, progressBar, startButton, cancelButton);
                });
            connect(cancelButton, &QPushButton::clicked, this, [this, cancelButton]()
                {
                    requestHashCancel(cancelButton);
                });
            return page;
        }
}
