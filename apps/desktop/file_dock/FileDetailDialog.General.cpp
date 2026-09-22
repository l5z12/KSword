#include "FileDetailDialog.h"

namespace ksword::ui::file_dock
{
        // formatFileSizeText:
        // - Display file size with both a human-readable unit and the exact byte count, avoiding a raw number that requires the user to count digits;
        // - No conversion value for sizes under 1KB; display only bytes.
        // Parameter sizeBytes: size in bytes.
        // Returns: e.g., "1.21 MB (1268736 bytes)".
        QString FileDetailDialog::formatFileSizeText(const qulonglong sizeBytes)
        {
            static const std::array<const char*, 5> kUnitNames{ "B", "KB", "MB", "GB", "TB" };
            double scaledValue = static_cast<double>(sizeBytes);
            std::size_t unitIndex = 0;
            while (scaledValue >= 1024.0 && (unitIndex + 1) < kUnitNames.size())
            {
                scaledValue /= 1024.0;
                ++unitIndex;
            }
            if (unitIndex == 0)
            {
                return ks::i18n::displayText(QStringLiteral("%1 字节")).arg(sizeBytes);
            }
            return ks::i18n::displayText(QStringLiteral("%1 %2（%3 字节）"))
                .arg(QString::number(scaledValue, 'f', 2))
                .arg(QString::fromLatin1(kUnitNames[unitIndex]))
                .arg(sizeBytes);
        }

        // fileAttributeFlagRows:
        // - Input attributes: FILE_ATTRIBUTE_* bit set;
        // - Processing: Expand only set attributes, providing the Win32 constant name and Chinese meaning for each bit.
        //   Previously, these bits were compressed into an A|B|C string, readable only by those who remember the constant names.
        // - Return: List of constant name/meaning pairs; returns an empty list if no bits are set, with the caller adding a description row.
        QList<QPair<QString, QString>> FileDetailDialog::fileAttributeFlagRows(const std::uint32_t attributes)
        {
            QList<QPair<QString, QString>> flagRows;
            const auto kAppendFlag =
                [&flagRows, attributes](
                    const std::uint32_t mask,
                    const QString& nameText,
                    const QString& descriptionText)
                {
                    if ((attributes & mask) != 0U)
                    {
                        flagRows.append(QPair<QString, QString>(nameText, descriptionText));
                    }
                };

            kAppendFlag(FILE_ATTRIBUTE_READONLY, QStringLiteral("READONLY"), QStringLiteral("只读，写入前要先去掉该属性"));
            kAppendFlag(FILE_ATTRIBUTE_HIDDEN, QStringLiteral("HIDDEN"), QStringLiteral("隐藏，资源管理器默认不显示"));
            kAppendFlag(FILE_ATTRIBUTE_SYSTEM, QStringLiteral("SYSTEM"), QStringLiteral("系统文件，属于操作系统的一部分"));
            kAppendFlag(FILE_ATTRIBUTE_DIRECTORY, QStringLiteral("DIRECTORY"), QStringLiteral("目录"));
            kAppendFlag(FILE_ATTRIBUTE_ARCHIVE, QStringLiteral("ARCHIVE"), QStringLiteral("存档位，备份程序据此判断是否需要重新备份"));
            kAppendFlag(FILE_ATTRIBUTE_DEVICE, QStringLiteral("DEVICE"), QStringLiteral("设备，保留给系统使用"));
            kAppendFlag(FILE_ATTRIBUTE_NORMAL, QStringLiteral("NORMAL"), QStringLiteral("没有其它属性"));
            kAppendFlag(FILE_ATTRIBUTE_TEMPORARY, QStringLiteral("TEMPORARY"), QStringLiteral("临时文件，系统会尽量把内容留在内存里"));
            kAppendFlag(FILE_ATTRIBUTE_SPARSE_FILE, QStringLiteral("SPARSE_FILE"), QStringLiteral("稀疏文件，全零区段不实际占用磁盘"));
            kAppendFlag(FILE_ATTRIBUTE_REPARSE_POINT, QStringLiteral("REPARSE_POINT"), QStringLiteral("重解析点，符号链接和装载点由它实现"));
            kAppendFlag(FILE_ATTRIBUTE_COMPRESSED, QStringLiteral("COMPRESSED"), QStringLiteral("NTFS 压缩"));
            kAppendFlag(FILE_ATTRIBUTE_OFFLINE, QStringLiteral("OFFLINE"), QStringLiteral("内容已转到离线存储，访问会明显变慢"));
            kAppendFlag(FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, QStringLiteral("NOT_CONTENT_INDEXED"), QStringLiteral("不建内容索引，Windows 搜索不检索正文"));
            kAppendFlag(FILE_ATTRIBUTE_ENCRYPTED, QStringLiteral("ENCRYPTED"), QStringLiteral("EFS 加密"));
            kAppendFlag(FILE_ATTRIBUTE_INTEGRITY_STREAM, QStringLiteral("INTEGRITY_STREAM"), QStringLiteral("ReFS 完整性流，写入时带校验和"));
            kAppendFlag(FILE_ATTRIBUTE_NO_SCRUB_DATA, QStringLiteral("NO_SCRUB_DATA"), QStringLiteral("排除在 ReFS 数据完整性扫描之外"));
            return flagRows;
        }

        void FileDetailDialog::refreshGeneralTab()
        {
            // Purpose: Rebuild the General page property tree based on the current language and loaded R0 data.
            // Note: clear the entire tree and rebuild; language switching and R0 asynchronous returns follow the same path.
            // Returns: Nothing.
            if (generalPropertyTree_ == nullptr)
            {
                return;
            }

            const auto kTranslated = [](const QString& sourceText)
                {
                    return ks::i18n::displayText(sourceText);
                };
            auto& languageManager = ks::i18n::LanguageManager::instance();
            const QFileInfo kInfo(filePath_);
            const QString kNativePath = QDir::toNativeSeparators(kInfo.absoluteFilePath());
            const QString kNtPathText = generalNtPathText_.isEmpty()
                ? kTranslated(QStringLiteral("<转换失败>"))
                : generalNtPathText_;
            const QString kYesText = languageManager.contextText(
                QStringLiteral("file.detail.value.yes"), QStringLiteral("是"));
            const QString kNoText = languageManager.contextText(
                QStringLiteral("file.detail.value.no"), QStringLiteral("否"));
            const QString kTimeFormat = QStringLiteral("yyyy-MM-dd HH:mm:ss");

            generalPropertyTree_->clear();
            generalPropertyTree_->setHeaderLabels(QStringList{
                kTranslated(QStringLiteral("属性")),
                kTranslated(QStringLiteral("值"))
                });

            QTreeWidgetItem* pathGroup = appendPropertyGroup(
                generalPropertyTree_, kTranslated(QStringLiteral("路径")));
            appendPropertyRow(pathGroup, kTranslated(QStringLiteral("Win32 路径")), kNativePath);
            appendPropertyRow(pathGroup, kTranslated(QStringLiteral("NT 路径")), kNtPathText);
            appendPropertyRow(
                pathGroup,
                kTranslated(QStringLiteral("查询来源")),
                !generalR0Loaded_
                    ? kTranslated(QStringLiteral("R3 QFileInfo（R0 信息正在后台加载）"))
                    : (generalR0Info_.io.ok
                        ? kTranslated(QStringLiteral("R3 QFileInfo + R0 KswordARK"))
                        : kTranslated(QStringLiteral("R3 QFileInfo（R0 不可用）"))));

            QTreeWidgetItem* basicGroup = appendPropertyGroup(
                generalPropertyTree_, kTranslated(QStringLiteral("基本信息")));
            appendPropertyRow(basicGroup, kTranslated(QStringLiteral("文件名")), kInfo.fileName());
            appendPropertyRow(basicGroup, kTranslated(QStringLiteral("扩展名")), kInfo.suffix());
            appendPropertyRow(
                basicGroup,
                kTranslated(QStringLiteral("大小")),
                formatFileSizeText(static_cast<qulonglong>(std::max<qint64>(0, kInfo.size()))));
            appendPropertyRow(
                basicGroup,
                kTranslated(QStringLiteral("创建时间")),
                kInfo.birthTime().toString(kTimeFormat));
            appendPropertyRow(
                basicGroup,
                kTranslated(QStringLiteral("修改时间")),
                kInfo.lastModified().toString(kTimeFormat));
            appendPropertyRow(
                basicGroup,
                kTranslated(QStringLiteral("访问时间")),
                kInfo.lastRead().toString(kTimeFormat));
            appendPropertyRow(
                basicGroup,
                kTranslated(QStringLiteral("可执行")),
                kInfo.isExecutable() ? kYesText : kNoText);
            appendPropertyRow(
                basicGroup,
                kTranslated(QStringLiteral("隐藏")),
                kInfo.isHidden() ? kYesText : kNoText);
            appendPropertyRow(
                basicGroup,
                kTranslated(QStringLiteral("可写")),
                kInfo.isWritable() ? kYesText : kNoText);
            appendPropertyRow(
                basicGroup,
                kTranslated(QStringLiteral("重解析点")),
                isPathReparsePoint(kInfo.absoluteFilePath())
                    ? kTranslated(QStringLiteral("是（首屏只判断属性位，不追踪链接目标）"))
                    : kNoText);

            QTreeWidgetItem* kernelGroup = appendPropertyGroup(
                generalPropertyTree_, kTranslated(QStringLiteral("内核视图（R0）")));
            if (!generalR0Loaded_)
            {
                appendPropertyRow(
                    kernelGroup,
                    kTranslated(QStringLiteral("状态")),
                    kTranslated(QStringLiteral("正在后台查询，属性窗口不会等待驱动返回")));
                syncGeneralTextView();
                return;
            }
            if (!generalR0Info_.io.ok)
            {
                appendPropertyRow(
                    kernelGroup,
                    kTranslated(QStringLiteral("状态")),
                    kTranslated(QStringLiteral("不可用")));
                appendPropertyRow(
                    kernelGroup,
                    kTranslated(QStringLiteral("原因")),
                    kTranslated(friendlyFileIoMessage(generalR0Info_.io.message)));
                appendPropertyRow(
                    kernelGroup,
                    kTranslated(QStringLiteral("Win32 错误码")),
                    QString::number(generalR0Info_.io.win32Error));
                syncGeneralTextView();
                return;
            }

            if (!generalR0Info_.objectName.empty())
            {
                appendPropertyRow(
                    kernelGroup,
                    kTranslated(QStringLiteral("R0 对象名")),
                    QString::fromStdWString(generalR0Info_.objectName));
            }
            appendPropertyRow(
                kernelGroup,
                kTranslated(QStringLiteral("大小（EndOfFile）")),
                formatFileSizeText(static_cast<qulonglong>(generalR0Info_.endOfFile)));
            appendPropertyRow(
                kernelGroup,
                kTranslated(QStringLiteral("磁盘占用（分配大小）")),
                formatFileSizeText(static_cast<qulonglong>(generalR0Info_.allocationSize)));
            appendPropertyRow(
                kernelGroup,
                kTranslated(QStringLiteral("创建时间")),
                fileTimeToText(generalR0Info_.creationTime));
            appendPropertyRow(
                kernelGroup,
                kTranslated(QStringLiteral("最后访问")),
                fileTimeToText(generalR0Info_.lastAccessTime));
            appendPropertyRow(
                kernelGroup,
                kTranslated(QStringLiteral("最后写入")),
                fileTimeToText(generalR0Info_.lastWriteTime));
            appendPropertyRow(
                kernelGroup,
                kTranslated(QStringLiteral("元数据变更（ChangeTime）")),
                fileTimeToText(generalR0Info_.changeTime));
            appendPropertyRow(
                kernelGroup,
                kTranslated(QStringLiteral("R0 说明")),
                kTranslated(friendlyFileIoMessage(generalR0Info_.io.message)));

            QTreeWidgetItem* attributeGroup = appendPropertyGroup(
                generalPropertyTree_, kTranslated(QStringLiteral("文件属性位")));
            attributeGroup->setText(1, formatHexValue(generalR0Info_.fileAttributes, 8));
            const QList<QPair<QString, QString>> kAttributeRows =
                fileAttributeFlagRows(generalR0Info_.fileAttributes);
            if (kAttributeRows.isEmpty())
            {
                appendPropertyRow(
                    attributeGroup,
                    kTranslated(QStringLiteral("无置位属性")),
                    QString());
            }
            for (const QPair<QString, QString>& attributeRow : kAttributeRows)
            {
                appendPropertyRow(attributeGroup, attributeRow.first, kTranslated(attributeRow.second));
            }

            // Driver diagnostic addresses are meaningless to ordinary users; collapse by default and expand only when needed.
            QTreeWidgetItem* diagnosticGroup = appendPropertyGroup(
                generalPropertyTree_, kTranslated(QStringLiteral("驱动诊断")));
            diagnosticGroup->setExpanded(false);
            appendPropertyRow(
                diagnosticGroup,
                kTranslated(QStringLiteral("协议版本")),
                QString::number(generalR0Info_.version));
            appendPropertyRow(
                diagnosticGroup,
                kTranslated(QStringLiteral("查询状态")),
                QStringLiteral("%1 (%2)")
                    .arg(fileInfoStatusText(generalR0Info_.queryStatus))
                    .arg(generalR0Info_.queryStatus));
            appendPropertyRow(
                diagnosticGroup,
                kTranslated(QStringLiteral("字段标志")),
                formatHexValue(generalR0Info_.fieldFlags, 8));
            appendPropertyRow(diagnosticGroup, QStringLiteral("OpenStatus"), formatNtStatus(generalR0Info_.openStatus));
            appendPropertyRow(diagnosticGroup, QStringLiteral("BasicStatus"), formatNtStatus(generalR0Info_.basicStatus));
            appendPropertyRow(diagnosticGroup, QStringLiteral("StandardStatus"), formatNtStatus(generalR0Info_.standardStatus));
            appendPropertyRow(diagnosticGroup, QStringLiteral("ObjectStatus"), formatNtStatus(generalR0Info_.objectStatus));
            appendPropertyRow(diagnosticGroup, QStringLiteral("NameStatus"), formatNtStatus(generalR0Info_.nameStatus));
            appendPropertyRow(diagnosticGroup, QStringLiteral("FileObject"), formatHex64(generalR0Info_.fileObjectAddress));
            appendPropertyRow(diagnosticGroup, QStringLiteral("SectionObjectPointers"), formatHex64(generalR0Info_.sectionObjectPointersAddress));
            appendPropertyRow(diagnosticGroup, QStringLiteral("DataSectionObject"), formatHex64(generalR0Info_.dataSectionObjectAddress));
            appendPropertyRow(diagnosticGroup, QStringLiteral("ImageSectionObject"), formatHex64(generalR0Info_.imageSectionObjectAddress));

            syncGeneralTextView();
        }

        // syncGeneralTextView:
        // - Export the current property tree as indented text and populate the text view on the General page;
        // - The text view no longer builds a separate content copy: both views share the same translated data, preventing
        //   inconsistencies where the tree updates but the text remains stale after language switching or R0 results arrive.
        // Returns: Nothing.
        void FileDetailDialog::syncGeneralTextView()
        {
            if (generalTextEditor_ == nullptr)
            {
                return;
            }

            // The tree content is already translated; use setRawText here to avoid double translation.
            generalTextEditor_->setRawText(propertyTreeToPlainText(generalPropertyTree_));
        }

        QWidget* FileDetailDialog::buildGeneralTab()
        {
            if (batchMode_)
            {
                QWidget* page = new QWidget(this);
                QVBoxLayout* layout = new QVBoxLayout(page);
                quint64 totalSize = 0U;
                int fileCount = 0;
                int directoryCount = 0;
                QTableWidget* table = new ks::ui::VisibleTableWidget(page);
                table->setColumnCount(6);
                table->setHorizontalHeaderLabels(QStringList{
                    QStringLiteral("路径"),
                    QStringLiteral("类型"),
                    QStringLiteral("大小"),
                    QStringLiteral("属性"),
                    QStringLiteral("最后修改"),
                    QStringLiteral("状态") });
                table->setRowCount(filePaths_.size());
                table->setSelectionBehavior(QAbstractItemView::SelectRows);
                table->setSelectionMode(QAbstractItemView::ExtendedSelection);
                table->setEditTriggers(QAbstractItemView::NoEditTriggers);
                table->setAlternatingRowColors(true);
                for (qsizetype row = 0; row < filePaths_.size(); ++row)
                {
                    const QString kPath = filePaths_.at(row);
                    const QFileInfo kInfo(kPath);
                    const bool kExists = kInfo.exists();
                    if (kExists && kInfo.isDir()) ++directoryCount;
                    if (kExists && kInfo.isFile())
                    {
                        ++fileCount;
                        totalSize += static_cast<quint64>(std::max<qint64>(0, kInfo.size()));
                    }
                    const std::wstring kNativePathText = QDir::toNativeSeparators(kPath).toStdWString();
                    const DWORD kAttributes = ::GetFileAttributesW(kNativePathText.c_str());
                    table->setItem(static_cast<int>(row), 0,
                        new QTableWidgetItem(QDir::toNativeSeparators(kPath)));
                    table->setItem(static_cast<int>(row), 1,
                        new QTableWidgetItem(kInfo.isDir()
                            ? QStringLiteral("目录")
                            : (kInfo.isFile() ? QStringLiteral("文件") : QStringLiteral("其它"))));
                    table->setItem(static_cast<int>(row), 2,
                        new QTableWidgetItem(kInfo.isFile()
                            ? formatFileSizeText(static_cast<qulonglong>(std::max<qint64>(0, kInfo.size())))
                            : QStringLiteral("-")));
                    table->setItem(static_cast<int>(row), 3,
                        new QTableWidgetItem(kAttributes == INVALID_FILE_ATTRIBUTES
                            ? QStringLiteral("-")
                            : fileAttributesToText(kAttributes)));
                    table->setItem(static_cast<int>(row), 4,
                        new QTableWidgetItem(kInfo.lastModified().isValid()
                            ? kInfo.lastModified().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"))
                            : QStringLiteral("-")));
                    table->setItem(static_cast<int>(row), 5,
                        new QTableWidgetItem(kExists ? QStringLiteral("可访问") : QStringLiteral("不存在或不可访问")));
                }
                QLabel* summary = new QLabel(
                    ks::i18n::sourceText(QStringLiteral(
                        "已选择 %1 项：文件 %2，目录 %3，文件总大小 %4。"))
                        .arg(filePaths_.size())
                        .arg(fileCount)
                        .arg(directoryCount)
                        .arg(formatFileSizeText(totalSize)),
                    page);
                summary->setTextInteractionFlags(Qt::TextSelectableByMouse);
                layout->addWidget(summary);
                installFileTableCopyMenu(table);
                if (table->horizontalHeader() != nullptr)
                {
                    table->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
                    table->horizontalHeader()->setStretchLastSection(true);
                }
                layout->addWidget(table, 1);
                return page;
            }

            QWidget* page = new QWidget(this);
            QVBoxLayout* layout = new QVBoxLayout(page);

            // The General page was originally a single read-only text block: property names and values aligned by colons, requiring manual selection to
            // copy a path, horizontal scrolling for long values, and properties compressed into an A|B|C string. After converting to a two-column property
            // tree, each property is on its own line, can be copied individually, groups are collapsible, and values support hover-to-view-full-text.
            // The text view is not deprecated; it is merely moved behind the top-right switch box, but full copy and search functionality still require it.
            generalPropertyTree_ = new QTreeWidget(page);
            configurePropertyTree(generalPropertyTree_);
            generalTextEditor_ = new CodeEditorWidget(page);
            generalTextEditor_->setReadOnly(true);
            // The attribute tree on the General tab is constructed field-by-field from the structure returned by R0: with grouping, hexadecimal
            // formatting, and attribute bit expansion, yielding more accurate results than parsing plain text. Therefore, this tab retains its own
            // toggle to disable the text control's built-in structured view, avoiding two entry points and two parsing methods on the same page.
            generalTextEditor_->setStructuredReportViewEnabled(false);

            const QFileInfo kInfo(filePath_);
            generalNtPathText_ = buildDriverNtPath(kInfo.absoluteFilePath());
            generalR0Loaded_ = false;
            generalR0Info_ = {};
            refreshGeneralTab();

            layout->addWidget(
                buildSwitchableView(page, generalPropertyTree_, generalTextEditor_), 1);
            startR0FileInfoLoad(kInfo, generalNtPathText_);
            return page;
        }
}
