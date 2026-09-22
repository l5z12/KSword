#include "FileDetailDialog.h"

namespace ksword::ui::file_dock
{
        QWidget* FileDetailDialog::buildDeferredTab(const QString& lazyKey)
        {
            // Purpose: Create a lightweight placeholder page for the file properties window.
            // Processing: Save only the lazyKey and prompt text; do not read the file or launch external processes.
            // Return: The real page replaces this placeholder when first switched to, via activateDeferredTab.
            QWidget* page = new QWidget(this);
            page->setProperty("ks_file_detail_lazy_key", lazyKey);
            QVBoxLayout* layout = new QVBoxLayout(page);
            QLabel* loadingLabel = new QLabel(page);
            loadingLabel->setWordWrap(true);
            loadingLabel->setText(QStringLiteral(
                "该页面将在首次打开时加载。\n"
                "这样文件属性窗口可以先快速弹出，PE/签名/字符串等重型分析不会阻塞首屏。"));
            layout->addWidget(loadingLabel, 0);
            layout->addStretch(1);
            return page;
        }

        void FileDetailDialog::activateDeferredTab(QTabWidget* tabWidget, const int tabIndex)
        {
            // Purpose: When a lazy-loaded page is selected for the first time, replace the placeholder page with the actual page.
            // Input: tabWidget/tabIndex representing the current property window tab container and the active index.
            // Processing: Create corresponding pages based on lazyKey; heavy pages continue on the background thread internally.
            // Returns: None; loaded pages are not replaced redundantly.
            if (tabWidget == nullptr || tabIndex < 0)
            {
                return;
            }

            QWidget* placeholderPage = tabWidget->widget(tabIndex);
            if (placeholderPage == nullptr)
            {
                return;
            }
            const QString kLazyKey = placeholderPage
                ->property("ks_file_detail_lazy_key")
                .toString()
                .trimmed()
                .toLower();
            if (kLazyKey.isEmpty())
            {
                return;
            }

            const QPointer<QTabWidget> kTabGuard(tabWidget);
            const QPointer<QWidget> kPlaceholderGuard(placeholderPage);
            ks::ui::scheduleDeferredTabActivation(
                this,
                tabWidget,
                tabIndex,
                placeholderPage,
                [this, kTabGuard, kPlaceholderGuard, tabIndex, kLazyKey]()
                {
                    if (kTabGuard.isNull() || kPlaceholderGuard.isNull() ||
                        kTabGuard->currentIndex() != tabIndex ||
                        kTabGuard->widget(tabIndex) != kPlaceholderGuard.data())
                    {
                        return;
                    }

                    QWidget* realPage = nullptr;
                    if (kLazyKey == QStringLiteral("metadata"))
                    {
                        realPage = buildMetadataTab();
                    }
                    else if (kLazyKey == QStringLiteral("security"))
                    {
                        realPage = buildSecurityTab();
                    }
                    else if (kLazyKey == QStringLiteral("reparse"))
                    {
                        realPage = buildReparseTab();
                    }
                    else if (kLazyKey == QStringLiteral("usage"))
                    {
                        realPage = buildUsageTab();
                    }
                    else if (kLazyKey == QStringLiteral("fileobject"))
                    {
                        realPage = buildFileObjectTab();
                    }
                    else if (kLazyKey == QStringLiteral("storage"))
                    {
                        realPage = buildStorageTab();
                    }
                    else if (kLazyKey == QStringLiteral("filters"))
                    {
                        realPage = buildFilterTopologyTab();
                    }
                    else if (kLazyKey == QStringLiteral("signature"))
                    {
                        realPage = buildSignatureTab();
                    }
                    else if (kLazyKey == QStringLiteral("pe"))
                    {
                        realPage = buildPeTab();
                    }
                    else if (kLazyKey == QStringLiteral("dependencies"))
                    {
                        realPage = buildDependencyTab();
                    }
                    else if (kLazyKey == QStringLiteral("strings"))
                    {
                        realPage = buildStringsTab();
                    }
                    else if (kLazyKey == QStringLiteral("hex"))
                    {
                        realPage = buildHexTab();
                    }

                    if (realPage == nullptr || kTabGuard.isNull() || kPlaceholderGuard.isNull() ||
                        kTabGuard->widget(tabIndex) != kPlaceholderGuard.data())
                    {
                        if (realPage != nullptr)
                        {
                            realPage->deleteLater();
                        }
                        return;
                    }

                    const QString kTitleText = kTabGuard->tabText(tabIndex);
                    kTabGuard->removeTab(tabIndex);
                    kTabGuard->insertTab(tabIndex, realPage, kTitleText);
                    // New lazy-loaded pages must immediately obtain the Surface palette and cannot fall back to the system Base.
                    applyThemeStyle();
                    kTabGuard->setCurrentIndex(tabIndex);
                    kPlaceholderGuard->deleteLater();
                });
        }

        QWidget* FileDetailDialog::buildReparseTab()
        {
            QWidget* page = new QWidget(this);
            QVBoxLayout* layout = new QVBoxLayout(page);
            QString content;
            if (!isPathReparsePoint(filePath_))
            {
                content += QStringLiteral("目标路径: %1\n").arg(QDir::toNativeSeparators(filePath_));
                content += QStringLiteral("状态: 当前目标不是 FILE_ATTRIBUTE_REPARSE_POINT。\n");
            }
            else
            {
                content += formatReparsePointText(filePath_);
            }

            layout->addWidget(buildReportView(page, content), 1);
            return page;
        }

        QWidget* FileDetailDialog::buildFilterTopologyTab()
        {
            QWidget* page = new QWidget(this);
            QVBoxLayout* layout = new QVBoxLayout(page);
            // Minifilter topology is also an audit detail in the format "group + name: value":
            // - Uses a property tree to display fields for each filter/instance/volume, allowing them to be copied item by item.
            // - The page only displays enumerations and R0 inventory, without providing detach/bypass/remove capabilities.

            QString content;
            content += QStringLiteral("目标路径: %1\n").arg(QDir::toNativeSeparators(filePath_));
            content += QStringLiteral("说明: 本页只展示 FilterManager 公开枚举接口与字段定义，不做卸载、绕过或拦截修改。\n\n");
            content += enumerateMinifilterText();
            content += QStringLiteral("\n");
            content += enumerateInstanceText();
            content += QStringLiteral("\n");
            content += enumerateVolumeText();

            // R0 audit supplement:
            // - queryMinifilterInventory accesses the driver uniformly via ArkDriverClient.
            // Appends results after the FilterManager public enumeration to preserve existing R3 logic.
            // - No unload, detach, bypass, callback modification, or similar actions are provided.
            const ksword::ark::MinifilterInventoryResult kMinifilterAudit =
                ksword::ark::DriverClient().queryMinifilterInventory();
            content += QStringLiteral("\n");
            content += formatAuditResultHeader(
                QStringLiteral("R0 审计补充 / MinifilterInventory"),
                kMinifilterAudit,
                kMinifilterAudit.responseFlags,
                (kMinifilterAudit.responseFlags & KSWORD_ARK_MINIFILTER_INVENTORY_RESPONSE_FLAG_TRUNCATED) != 0U);
            content += formatMinifilterInventoryRows(kMinifilterAudit);
            layout->addWidget(buildReportView(page, content), 1);
            return page;
        }

        QWidget* FileDetailDialog::buildSignatureTab()
        {
            QWidget* page = new QWidget(this);
            QVBoxLayout* layout = new QVBoxLayout(page);
            CodeEditorWidget* textEditorWidget = new CodeEditorWidget(page);
            textEditorWidget->setReadOnly(true);
            layout->addWidget(textEditorWidget, 1);
            startSignatureLoad(textEditorWidget);
            return page;
        }

        QWidget* FileDetailDialog::buildPeTab()
        {
            QWidget* page = new QWidget(this);
            QVBoxLayout* layout = new QVBoxLayout(page);
            CodeEditorWidget* textEditorWidget = new CodeEditorWidget(page);
            textEditorWidget->setReadOnly(true);

            layout->addWidget(textEditorWidget, 1);
            startPeAnalysisLoad(textEditorWidget);
            return page;
        }

        QWidget* FileDetailDialog::buildDependencyTab()
        {
            // Purpose: Create the 'Dependency DLL' page UI.
            // Processing: Display DLL/Function/Ordinal/Hint/IAT RVA in the table; show summary or error in the bottom text.
            //      Real PE Import Directory parsing is performed by a background thread.
            // Returns: a QWidget that can be embedded in a property window.
            QWidget* page = new QWidget(this);
            QVBoxLayout* layout = new QVBoxLayout(page);

            QLabel* statusLabel = new QLabel(QStringLiteral("● 等待加载依赖 DLL"), page);
            statusLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
            layout->addWidget(statusLabel, 0);

            QTableWidget* table = new ks::ui::VisibleTableWidget(page);
            table->setColumnCount(6);
            table->setHorizontalHeaderLabels(QStringList{
                QStringLiteral("DLL 名称"),
                QStringLiteral("函数名 / Ordinal"),
                QStringLiteral("Hint"),
                QStringLiteral("导入方式"),
                QStringLiteral("Thunk/IAT RVA"),
                QStringLiteral("诊断")
                });
            table->setAlternatingRowColors(true);
            table->setSelectionBehavior(QAbstractItemView::SelectRows);
            table->setSelectionMode(QAbstractItemView::ExtendedSelection);
            table->setEditTriggers(QAbstractItemView::NoEditTriggers);
            table->setSortingEnabled(true);
            table->setContextMenuPolicy(Qt::CustomContextMenu);
            if (table->horizontalHeader() != nullptr)
            {
                table->horizontalHeader()->setStretchLastSection(true);
            }
            layout->addWidget(table, 3);

            CodeEditorWidget* detailEditor = new CodeEditorWidget(page);
            detailEditor->setReadOnly(true);
            layout->addWidget(detailEditor, 1);

            connect(table, &QTableWidget::customContextMenuRequested, this, [table](const QPoint& position)
                {
                    if (table == nullptr)
                    {
                        return;
                    }

                    QMenu menu(table);
                    menu.setStyleSheet(buildContextMenuStyle());
                    QAction* copyRowsAction = menu.addAction(QStringLiteral("复制选中行"));
                    QAction* copyDllAction = menu.addAction(QStringLiteral("复制 DLL 名称"));
                    QAction* selectedAction = menu.exec(table->viewport()->mapToGlobal(position));
                    if (selectedAction == nullptr)
                    {
                        return;
                    }
                    if (selectedAction != copyRowsAction && selectedAction != copyDllAction)
                    {
                        return;
                    }

                    const bool kDllOnly = selectedAction == copyDllAction;
                    const QString kClipboardText = dependencyRowsToClipboardText(table, kDllOnly);
                    if (!kClipboardText.isEmpty() && QApplication::clipboard() != nullptr)
                    {
                        QApplication::clipboard()->setText(kClipboardText);
                    }
                });

            startDependencyLoad(table, statusLabel, detailEditor);
            return page;
        }

        QWidget* FileDetailDialog::buildStringsTab()
        {
            QWidget* page = new QWidget(this);
            QVBoxLayout* layout = new QVBoxLayout(page);
            CodeEditorWidget* textEditorWidget = new CodeEditorWidget(page);
            textEditorWidget->setReadOnly(true);
            layout->addWidget(textEditorWidget, 1);
            startStringsLoad(textEditorWidget);

            return page;
        }

        QWidget* FileDetailDialog::buildHexTab()
        {
            QWidget* page = new QWidget(this);
            QVBoxLayout* layout = new QVBoxLayout(page);

            // Unified reuse of HexEditorWidget to avoid duplicating hex dump logic in multiple places.
            HexEditorWidget* hexEditorWidget = new HexEditorWidget(page);
            hexEditorWidget->setEditable(false);
            hexEditorWidget->setBytesPerRow(16);
            layout->addWidget(hexEditorWidget, 1);

            // hexHintLabel purpose: Informs the user that this page previews only the initial bytes of the file by default.
            QLabel* hexHintLabel = new QLabel(page);
            hexHintLabel->setWordWrap(true);
            layout->addWidget(hexHintLabel, 0);

            // The file detail page reads only the first 2MB to prevent the property window from freezing on large files.
            constexpr qint64 kMaxPreviewBytes = 2 * 1024 * 1024;
            QFile file(filePath_);
            if (!file.open(QIODevice::ReadOnly))
            {
                hexHintLabel->setText(QStringLiteral("无法读取文件，无法显示十六进制。"));
                hexEditorWidget->clearData();
                return page;
            }

            const qint64 kTotalBytes = file.size();
            const QByteArray kBytes = file.read(kMaxPreviewBytes);
            file.close();

            if (kBytes.isEmpty())
            {
                hexHintLabel->setText(QStringLiteral("文件为空。"));
                hexEditorWidget->clearData();
                return page;
            }

            // Directly pass the preview bytes to HexEditorWidget to utilize unified scrolling, searching, and jumping capabilities.
            hexEditorWidget->setByteArray(kBytes, 0);

            if (kTotalBytes > kBytes.size())
            {
                hexHintLabel->setText(
                    QStringLiteral("当前仅预览文件前 %1 字节，总大小 %2 字节。")
                    .arg(kBytes.size())
                    .arg(kTotalBytes));
            }
            else
            {
                hexHintLabel->setText(
                    QStringLiteral("已加载完整文件，共 %1 字节。")
                    .arg(kTotalBytes));
            }

            return page;
        }
}
