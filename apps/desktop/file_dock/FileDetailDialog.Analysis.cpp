#include "FileDetailDialog.h"

namespace ksword::ui::file_dock
{
        void FileDetailDialog::startSignatureLoad(CodeEditorWidget* textEditorWidget)
        {
            // Purpose: Perform background validation using R3 WinVerifyTrust, certificate chain, and Catalog APIs, then supplement
            // with KswordARK PE Security Directory, WIN_CERTIFICATE outer structure, and kernel CI cache signature level.
            // Input: textEditorWidget is the target for the signature page display.
            // Handling: Display R3 and R0 evidence side-by-side without invoking PowerShell.
            // Returns: Nothing.
            if (textEditorWidget == nullptr)
            {
                return;
            }

            textEditorWidget->setLocalizedText(
                QStringLiteral("正在通过 R3 WinVerifyTrust 与 KswordARK R0 读取签名证据...\n目标: %1")
                    .arg(QDir::toNativeSeparators(filePath_)));

            const QString kFilePathSnapshot = filePath_;
            const QString kNtPathSnapshot = buildDriverNtPath(kFilePathSnapshot);
            QPointer<FileDetailDialog> guardThis(this);
            QPointer<CodeEditorWidget> editorGuard(textEditorWidget);
            auto* task = QRunnable::create([guardThis, editorGuard, kFilePathSnapshot, kNtPathSnapshot]()
                {
                    QString finalText;
                    const ks::file::metadata::SignatureInspection kR3Signature =
                        ks::file::metadata::inspectSignature(kFilePathSnapshot);
                    finalText += QStringLiteral("[R3 WinVerifyTrust / 证书链]\n");
                    finalText += QStringLiteral("WinVerifyTrust: 0x%1\n")
                        .arg(static_cast<quint32>(kR3Signature.trustStatus), 8, 16, QLatin1Char('0'));
                    finalText += QStringLiteral("嵌入式签名: %1\n")
                        .arg(kR3Signature.embedded ? QStringLiteral("是") : QStringLiteral("否"));
                    finalText += QStringLiteral("Catalog 签名: %1\n")
                        .arg(kR3Signature.catalog ? QStringLiteral("是") : QStringLiteral("否"));
                    finalText += QStringLiteral("Catalog 路径: %1\n")
                        .arg(kR3Signature.catalogPath.isEmpty() ? QStringLiteral("-") : kR3Signature.catalogPath);
                    finalText += QStringLiteral("签名者: %1\n")
                        .arg(kR3Signature.signer.isEmpty() ? QStringLiteral("-") : kR3Signature.signer);
                    finalText += QStringLiteral("颁发者: %1\n")
                        .arg(kR3Signature.issuer.isEmpty() ? QStringLiteral("-") : kR3Signature.issuer);
                    finalText += QStringLiteral("证书 SHA-256: %1\n")
                        .arg(kR3Signature.sha256Fingerprint.isEmpty()
                            ? QStringLiteral("-") : kR3Signature.sha256Fingerprint);
                    finalText += QStringLiteral("有效期: %1 → %2\n")
                        .arg(kR3Signature.validFrom.isEmpty() ? QStringLiteral("-") : kR3Signature.validFrom)
                        .arg(kR3Signature.validUntil.isEmpty() ? QStringLiteral("-") : kR3Signature.validUntil);
                    finalText += QStringLiteral("时间戳签名者: %1\n")
                        .arg(kR3Signature.timestampSigner.isEmpty()
                            ? QStringLiteral("-") : kR3Signature.timestampSigner);
                    finalText += QStringLiteral("链状态: %1\n\n")
                        .arg(kR3Signature.chainStatus.isEmpty() ? QStringLiteral("-") : kR3Signature.chainStatus);
                    if (kNtPathSnapshot.isEmpty())
                    {
                        finalText += QStringLiteral("无法生成供内核使用的 NT 路径。\n");
                        finalText += QStringLiteral("目标: %1")
                            .arg(QDir::toNativeSeparators(kFilePathSnapshot));
                    }
                    else
                    {
                        const ksword::ark::ImageSignatureQueryResult kSignatureResult =
                            ksword::ark::DriverClient().queryImageSignature(kNtPathSnapshot.toStdWString());
                        finalText += QStringLiteral("[R0 内核签名证据]\n");
                        finalText += QStringLiteral("目标: %1\n")
                            .arg(QDir::toNativeSeparators(kFilePathSnapshot));
                        finalText += QStringLiteral("NT 路径: %1\n\n").arg(kNtPathSnapshot);
                        finalText += QString::fromStdString(
                            ksword::ark::formatImageSignatureEvidence(kSignatureResult));
                        finalText += QStringLiteral("\n");
                        finalText += QStringLiteral(
                            "结论边界：WinVerifyTrust 负责 R3 信任验证；PE 证书表及 WIN_CERTIFICATE 是磁盘结构证据；CI cached signing level 是独立的内核缓存结果。Catalog 签名不能从目标文件本身删除。");
                    }

                    FileDetailDialog* targetDialog = guardThis.data();
                    if (targetDialog == nullptr)
                    {
                        return;
                    }
                    QMetaObject::invokeMethod(
                        targetDialog,
                        [editorGuard, finalText]()
                        {
                            if (editorGuard != nullptr)
                            {
                                editorGuard->setLocalizedText(finalText);
                            }
                        },
                        Qt::QueuedConnection);
                });
            task->setAutoDelete(true);
            QThreadPool::globalInstance()->start(task);
        }

        void FileDetailDialog::startPeAnalysisLoad(CodeEditorWidget* textEditorWidget)
        {
            // Purpose: Perform background deep PE analysis text generation.
            // Input: textEditorWidget is the display target for the PE Info tab.
            // Handling: Call FilePropertyPeAnalyzer to prevent Import/Export/Directory parsing from freezing the UI.
            // Returns: Nothing.
            if (textEditorWidget == nullptr)
            {
                return;
            }

            textEditorWidget->setLocalizedText(QStringLiteral("PE 信息加载中...\n目标: %1")
                .arg(QDir::toNativeSeparators(filePath_)));
            const QString kFilePathSnapshot = filePath_;
            QPointer<FileDetailDialog> guardThis(this);
            QPointer<CodeEditorWidget> editorGuard(textEditorWidget);
            auto* task = QRunnable::create([guardThis, editorGuard, kFilePathSnapshot]()
                {
                    const QString kPeText = file_dock_detail::buildPeAnalysisText(kFilePathSnapshot);
                    FileDetailDialog* targetDialog = guardThis.data();
                    if (targetDialog == nullptr)
                    {
                        return;
                    }
                    QMetaObject::invokeMethod(
                        targetDialog,
                        [editorGuard, kPeText]()
                        {
                            if (editorGuard != nullptr)
                            {
                                editorGuard->setLocalizedText(kPeText);
                            }
                        },
                        Qt::QueuedConnection);
                });
            task->setAutoDelete(true);
            QThreadPool::globalInstance()->start(task);
        }

        FileDetailDialog::PrintableStringsPreview FileDetailDialog::extractPrintableStringsPreview(const QString& filePath)
        {
            // Purpose: Extract printable ASCII strings in chunks, replacing readAll.
            // Input: filePath is the target file path.
            // Processing: Output at most 2000 strings and scan at most 128 MiB to prevent large files from occupying threads for extended periods.
            // Returns: Separates translatable program descriptions from file strings that must be preserved verbatim.
            PrintableStringsPreview preview{};
            QFile file(filePath);
            if (!file.open(QIODevice::ReadOnly))
            {
                preview.sourcePrefixText = QStringLiteral("无法读取文件，无法提取字符串。\nQFile错误码: %1")
                    .arg(static_cast<int>(file.error()));
                return preview;
            }

            constexpr qint64 kChunkBytes = 1024 * 1024;
            constexpr qint64 kMaxScanBytes = 128LL * 1024LL * 1024LL;
            QString current;
            QStringList result;
            qint64 scannedBytes = 0;
            while (!file.atEnd() && result.size() < 2000 && scannedBytes < kMaxScanBytes)
            {
                const QByteArray kBytes = file.read(std::min(kChunkBytes, kMaxScanBytes - scannedBytes));
                if (kBytes.isEmpty())
                {
                    break;
                }
                scannedBytes += kBytes.size();
                for (char ch : kBytes)
                {
                    const unsigned char kC = static_cast<unsigned char>(ch);
                    if (std::isprint(kC) != 0)
                    {
                        current.append(QChar::fromLatin1(ch));
                    }
                    else
                    {
                        if (current.length() >= 4)
                        {
                            result.append(current);
                            if (result.size() >= 2000)
                            {
                                break;
                            }
                        }
                        current.clear();
                    }
                }
            }
            if (current.length() >= 4 && result.size() < 2000)
            {
                result.append(current);
            }

            preview.rawStringText = result.join('\n');
            if (preview.rawStringText.trimmed().isEmpty())
            {
                preview.sourcePrefixText = QStringLiteral("<未提取到可打印字符串，或文件内容全部为二进制不可见字符。>");
            }
            if (!file.atEnd())
            {
                if (!preview.sourcePrefixText.isEmpty())
                {
                    preview.sourcePrefixText += QStringLiteral("\n\n");
                }
                preview.sourcePrefixText += QStringLiteral("[提示] 已达到扫描/显示上限：扫描 %1 字节，显示 %2 条。\n\n")
                    .arg(scannedBytes)
                    .arg(result.size());
            }
            return preview;
        }

        void FileDetailDialog::startStringsLoad(CodeEditorWidget* textEditorWidget)
        {
            // Purpose: Extract string page content in the background.
            // Input: textEditorWidget is the target string page display.
            // Handling: scan the file in chunks; populate the UI after results are complete.
            // Returns: Nothing.
            if (textEditorWidget == nullptr)
            {
                return;
            }

            textEditorWidget->setLocalizedText(QStringLiteral("字符串扫描中...\n目标: %1")
                .arg(QDir::toNativeSeparators(filePath_)));
            const QString kFilePathSnapshot = filePath_;
            QPointer<FileDetailDialog> guardThis(this);
            QPointer<CodeEditorWidget> editorGuard(textEditorWidget);
            auto* task = QRunnable::create([guardThis, editorGuard, kFilePathSnapshot]()
                {
                    const PrintableStringsPreview kPreview = FileDetailDialog::extractPrintableStringsPreview(kFilePathSnapshot);
                    FileDetailDialog* targetDialog = guardThis.data();
                    if (targetDialog == nullptr)
                    {
                        return;
                    }
                    QMetaObject::invokeMethod(
                        targetDialog,
                        [editorGuard, kPreview]()
                        {
                            if (editorGuard != nullptr)
                            {
                                editorGuard->setLocalizedTextWithRawSuffix(
                                    kPreview.sourcePrefixText,
                                    kPreview.rawStringText);
                            }
                        },
                        Qt::QueuedConnection);
                });
            task->setAutoDelete(true);
            QThreadPool::globalInstance()->start(task);
        }

        QString FileDetailDialog::dependencyRowsToClipboardText(QTableWidget* table, const bool dllOnly)
        {
            // Purpose: Convert the selected row in the dependency DLL table to clipboard text.
            // Input: table is the dependency page table; dllOnly controls whether to copy only DLL names or entire rows.
            // Returns: text separated by newlines; returns an empty string if no row is selected.
            if (table == nullptr)
            {
                return QString();
            }

            std::set<int> selectedRows;
            if (table->selectionModel() != nullptr)
            {
                const QModelIndexList kRowIndexes = table->selectionModel()->selectedRows();
                for (const QModelIndex& index : kRowIndexes)
                {
                    selectedRows.insert(index.row());
                }
            }
            if (selectedRows.empty() && table->currentRow() >= 0)
            {
                selectedRows.insert(table->currentRow());
            }

            QStringList lines;
            QStringList seenDllNames;
            for (const int kRowIndex : selectedRows)
            {
                if (kRowIndex < 0 || kRowIndex >= table->rowCount())
                {
                    continue;
                }
                if (dllOnly)
                {
                    const QTableWidgetItem* dllItem = table->item(kRowIndex, 0);
                    const QString kDllName = dllItem != nullptr ? dllItem->text().trimmed() : QString();
                    if (!kDllName.isEmpty() && !seenDllNames.contains(kDllName, Qt::CaseInsensitive))
                    {
                        seenDllNames.push_back(kDllName);
                        lines.push_back(kDllName);
                    }
                    continue;
                }

                QStringList columns;
                for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
                {
                    const QTableWidgetItem* item = table->item(kRowIndex, columnIndex);
                    columns.push_back(item != nullptr ? item->text() : QString());
                }
                lines.push_back(columns.join('\t'));
            }
            return lines.join('\n');
        }

        void FileDetailDialog::populateDependencyTable(QTableWidget* table, QLabel* statusLabel, const file_dock_detail::PeDependencyResult& result, const qint64 elapsedMs)
        {
            // Purpose: Populate the table with dependency DLL results parsed in the background.
            // Input: table/statusLabel are UI controls, result is a structured import table, elapsedMs is the parsing duration.
            // Processing: Batch-disable sorting and refresh to reduce UI jitter during large imports.
            // Returns: Nothing.
            if (table == nullptr || statusLabel == nullptr)
            {
                return;
            }

            table->setSortingEnabled(false);
            table->setUpdatesEnabled(false);
            table->clearContents();
            constexpr int kMaxDisplayedDependencyRows = 20000;
            const int kTotalRowCount = static_cast<int>(result.rows.size());
            const int kDisplayedRowCount = std::min(kTotalRowCount, kMaxDisplayedDependencyRows);
            table->setRowCount(kDisplayedRowCount);
            for (int rowIndex = 0; rowIndex < kDisplayedRowCount; ++rowIndex)
            {
                const file_dock_detail::PeDependencyRow& row = result.rows[rowIndex];
                const QString kFunctionText = row.importMode == QStringLiteral("Ordinal")
                    ? QStringLiteral("#%1").arg(row.ordinalText)
                    : (row.functionName.trimmed().isEmpty() ? QStringLiteral("-") : row.functionName);

                table->setItem(rowIndex, 0, new QTableWidgetItem(row.dllName));
                table->setItem(rowIndex, 1, new QTableWidgetItem(kFunctionText));
                table->setItem(rowIndex, 2, new QTableWidgetItem(row.hintText));
                table->setItem(rowIndex, 3, new QTableWidgetItem(row.importMode));
                table->setItem(rowIndex, 4, new QTableWidgetItem(row.thunkRvaText));
                table->setItem(rowIndex, 5, new QTableWidgetItem(row.diagnosticText));
            }
            table->setUpdatesEnabled(true);
            table->setSortingEnabled(true);
            if (table->horizontalHeader() != nullptr)
            {
                table->resizeColumnToContents(0);
                table->resizeColumnToContents(1);
                table->resizeColumnToContents(2);
                table->resizeColumnToContents(3);
            }

            if (!result.success)
            {
                statusLabel->setText(result.isPe
                    ? QStringLiteral("● PE 解析失败，未能读取依赖 DLL。耗时 %1 ms").arg(elapsedMs)
                    : QStringLiteral("● 不适用：目标不是 PE 文件。耗时 %1 ms").arg(elapsedMs));
                return;
            }
            if (!result.errorText.trimmed().isEmpty() && result.rows.isEmpty())
            {
                statusLabel->setText(QStringLiteral("● %1 耗时 %2 ms").arg(result.errorText.trimmed()).arg(elapsedMs));
                return;
            }
            QString statusText = QStringLiteral("● 加载完成 %1 ms | DLL:%2 | 导入项:%3")
                .arg(elapsedMs)
                .arg(result.dllNames.size())
                .arg(result.rows.size());
            if (kDisplayedRowCount < kTotalRowCount)
            {
                statusText += QStringLiteral(" | 表格仅显示前 %1 行").arg(kDisplayedRowCount);
            }
            statusLabel->setText(statusText);
        }

        void FileDetailDialog::startDependencyLoad(QTableWidget* table, QLabel* statusLabel, CodeEditorWidget* detailEditor)
        {
            // Purpose: Read the EXE/DLL Import Directory in the background and display dependent DLLs.
            // Input: table, statusLabel, and detailEditor are dependent UI controls.
            // Processing: Parse PE in the worker thread; populate the table and display error details in the UI thread. Failures do not block or crash.
            // Returns: Nothing.
            if (table == nullptr || statusLabel == nullptr || detailEditor == nullptr)
            {
                return;
            }

            statusLabel->setText(QStringLiteral("● 正在后台读取 Import Directory..."));
            detailEditor->setLocalizedText(QStringLiteral("依赖 DLL 加载中...\n目标: %1")
                .arg(QDir::toNativeSeparators(filePath_)));

            const QString kFilePathSnapshot = filePath_;
            QPointer<FileDetailDialog> guardThis(this);
            QPointer<QTableWidget> tableGuard(table);
            QPointer<QLabel> statusGuard(statusLabel);
            QPointer<CodeEditorWidget> detailGuard(detailEditor);
            auto* task = QRunnable::create([guardThis, tableGuard, statusGuard, detailGuard, kFilePathSnapshot]()
                {
                    const auto kBeginTime = std::chrono::steady_clock::now();
                    const file_dock_detail::PeDependencyResult kResult =
                        file_dock_detail::analyzePeDependencies(kFilePathSnapshot);
                    const qint64 kElapsedMs = static_cast<qint64>(
                        std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - kBeginTime).count());

                    FileDetailDialog* targetDialog = guardThis.data();
                    if (targetDialog == nullptr)
                    {
                        return;
                    }
                    QMetaObject::invokeMethod(
                        targetDialog,
                        [guardThis, tableGuard, statusGuard, detailGuard, kResult, kElapsedMs]()
                        {
                            if (guardThis == nullptr || tableGuard == nullptr ||
                                statusGuard == nullptr || detailGuard == nullptr)
                            {
                                return;
                            }

                            const auto kResultSnapshot =
                                std::make_shared<file_dock_detail::PeDependencyResult>(kResult);
                            const auto kCommitSnapshot =
                                [guardThis, tableGuard, statusGuard, detailGuard, kResultSnapshot, kElapsedMs]()
                            {
                                if (guardThis == nullptr || tableGuard == nullptr ||
                                    statusGuard == nullptr || detailGuard == nullptr)
                                {
                                    return;
                                }

                                guardThis->populateDependencyTable(
                                    tableGuard,
                                    statusGuard,
                                    *kResultSnapshot,
                                    kElapsedMs);
                                QString detailText;
                                detailText += QStringLiteral("目标: %1\n")
                                    .arg(QDir::toNativeSeparators(guardThis->filePath_));
                                if (!kResultSnapshot->success ||
                                    !kResultSnapshot->errorText.trimmed().isEmpty())
                                {
                                    detailText += QStringLiteral("%1\n")
                                        .arg(kResultSnapshot->errorText.trimmed());
                                }
                                else
                                {
                                    detailText += QStringLiteral("依赖 DLL 名称:\n");
                                    for (const QString& dllName : kResultSnapshot->dllNames)
                                    {
                                        detailText += QStringLiteral("  - %1\n").arg(dllName);
                                    }
                                }
                                detailGuard->setLocalizedText(detailText);
                            };

                            if (ks::ui::deferTableUiCommitIfContextMenuOpen(
                                guardThis.data(),
                                QStringLiteral("file-detail-dependency-snapshot"),
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
}
