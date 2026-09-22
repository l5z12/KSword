#include "DiskFileSystemForensicsPanel.h"

#include "../../../../shared/ark_client/ArkDriverTypes.h"
#include "../../ui/CodeEditorWidget.h"
#include "../../ui/KernelDisassemblyDialog.h"
#include "../../../../shared/platform/file/PeAnalyzer.h"
#include "../../Theme.h"
#include "../../ui/VisibleTableWidget.h"

#include <QAbstractItemView>
#include <QAction>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QGridLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QMenu>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QToolButton>
#include <QVBoxLayout>

#include <algorithm>
#include <limits>
#include <thread>
#include <utility>

namespace
{
    QString hexOffset(const std::uint64_t value)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(value), 16, 16, QChar('0'))
            .toUpper();
    }

    QTableWidgetItem* readOnlyItem(const QString& text)
    {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }

    QTableWidget* createTable(
        QWidget* parent,
        const QStringList& headers)
    {
        auto* table = new ks::ui::VisibleTableWidget(parent);
        table->setColumnCount(headers.size());
        table->setHorizontalHeaderLabels(headers);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setAlternatingRowColors(true);
        table->horizontalHeader()->setStretchLastSection(true);
        table->setStyleSheet(QStringLiteral(
            "QTableWidget{border:1px solid %1;border-radius:6px;"
            "background:%2;alternate-background-color:%3;color:%4;}"
            "QHeaderView::section{border:none;border-bottom:1px solid %1;"
            "background:transparent;color:%5;padding:5px;font-weight:700;}")
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::surfaceAltHex())
            .arg(ksword_theme::textPrimaryHex())
            .arg(ksword_theme::kPrimaryBlueHex));
        return table;
    }

    bool parseUnsignedAddress(
        const QString& text,
        std::uint64_t& valueOut)
    {
        QString normalized = text.trimmed();
        int base = 10;
        if (normalized.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
        {
            normalized = normalized.mid(2);
            base = 16;
        }
        bool ok = false;
        const qulonglong kParsed = normalized.toULongLong(&ok, base);
        if (!ok)
        {
            return false;
        }
        valueOut = kParsed;
        return true;
    }

    bool supportsRawBrowser(
        const ks::misc::ForensicFileSystemKind kind)
    {
        switch (kind)
        {
        case ks::misc::ForensicFileSystemKind::kNtfs:
        case ks::misc::ForensicFileSystemKind::kFat12:
        case ks::misc::ForensicFileSystemKind::kFat16:
        case ks::misc::ForensicFileSystemKind::kFat32:
        case ks::misc::ForensicFileSystemKind::kExFat:
        case ks::misc::ForensicFileSystemKind::kReFs:
        case ks::misc::ForensicFileSystemKind::kExt2:
        case ks::misc::ForensicFileSystemKind::kExt3:
        case ks::misc::ForensicFileSystemKind::kExt4:
        case ks::misc::ForensicFileSystemKind::kBtrfs:
        case ks::misc::ForensicFileSystemKind::kApfs:
        case ks::misc::ForensicFileSystemKind::kHfs:
        case ks::misc::ForensicFileSystemKind::kHfsPlus:
            return true;
        default:
            return false;
        }
    }

    QString bytePreview(const QByteArray& bytes)
    {
        QString text;
        for (qsizetype row = 0; row < bytes.size(); row += 16)
        {
            const qsizetype kRowLength =
                std::min<qsizetype>(16, bytes.size() - row);
            text += QStringLiteral("%1  ")
                .arg(static_cast<qulonglong>(row), 8, 16, QChar('0'))
                .toUpper();
            QString characters;
            for (qsizetype column = 0; column < 16; ++column)
            {
                if (column < kRowLength)
                {
                    const unsigned char kValue =
                        static_cast<unsigned char>(bytes[row + column]);
                    text += QStringLiteral("%1 ")
                        .arg(kValue, 2, 16, QChar('0'))
                        .toUpper();
                    characters += kValue >= 0x20U && kValue <= 0x7EU
                        ? QChar(kValue)
                        : QChar('.');
                }
                else
                {
                    text += QStringLiteral("   ");
                    characters += QChar(' ');
                }
            }
            text += QStringLiteral(" |%1|\n").arg(characters);
        }
        return text;
    }
}

namespace ks::misc
{
    DiskFileSystemForensicsPanel::DiskFileSystemForensicsPanel(
        SelectionProvider selectionProvider,
        JumpCallback jumpCallback,
        QWidget* parent)
        : QWidget(parent)
        , selectionProvider_(std::move(selectionProvider))
        , jumpCallback_(std::move(jumpCallback))
    {
        initializeUi();
        initializeConnections();
    }

    void DiskFileSystemForensicsPanel::initializeUi()
    {
        auto* rootLayout = new QVBoxLayout(this);
        rootLayout->setContentsMargins(4, 4, 4, 4);
        rootLayout->setSpacing(6);

        auto* probeGroup = new QGroupBox(
            QStringLiteral("分区文件系统原始探测"),
            this);
        auto* probeLayout = new QVBoxLayout(probeGroup);
        auto* probeToolbar = new QGridLayout();
        probeButton_ = new QPushButton(
            QStringLiteral("探测当前分区"),
            probeGroup);
        probeButton_->setStyleSheet(ksword_theme::themedButtonStyle());
        probeSummaryLabel_ = new QLabel(
            QStringLiteral(
                "支持 NTFS、FAT12/16/32、exFAT、ReFS、Ext2/3/4、"
                "BtrFS、APFS、HFS/HFS+ 的原始只读元数据探测。"),
            probeGroup);
        probeSummaryLabel_->setWordWrap(true);
        probeToolbar->addWidget(probeButton_, 0, 0);
        probeToolbar->addWidget(probeSummaryLabel_, 0, 1);
        probeLayout->addLayout(probeToolbar);
        probeTable_ = createTable(probeGroup, {
            QStringLiteral("字段"),
            QStringLiteral("值"),
            QStringLiteral("绝对偏移"),
            QStringLiteral("长度"),
            QStringLiteral("说明")
            });
        probeLayout->addWidget(probeTable_, 1);
        rootLayout->addWidget(probeGroup, 2);

        auto* rawGroup = new QGroupBox(
            QStringLiteral("未挂载分区原始目录与文件浏览"),
            this);
        auto* rawLayout = new QVBoxLayout(rawGroup);
        auto* rawToolbar = new QGridLayout();
        rawPathEdit_ = new QLineEdit(
            QStringLiteral("\\"),
            rawGroup);
        rawPathEdit_->setPlaceholderText(
            QStringLiteral("分区内路径，例如 \\ 或 \\Users"));
        rawUpButton_ = new QPushButton(
            QStringLiteral("上级目录"),
            rawGroup);
        rawListButton_ = new QPushButton(
            QStringLiteral("列出目录"),
            rawGroup);
        rawPreviewButton_ = new QPushButton(
            QStringLiteral("预览前 4 KiB"),
            rawGroup);
        rawExportButton_ = new QPushButton(
            QStringLiteral("导出选中文件"),
            rawGroup);
        rawMoreButton_ = new QToolButton(rawGroup);
        rawMoreButton_->setText(QStringLiteral("更多操作"));
        rawMoreButton_->setPopupMode(
            QToolButton::InstantPopup);
        auto* rawMoreMenu = new QMenu(rawMoreButton_);
        auto* rawAdvancedMenu = rawMoreMenu->addMenu(
            QStringLiteral("高级分析"));
        rawPeAction_ = rawAdvancedMenu->addAction(
            QStringLiteral("分析并反汇编原始 PE…"));
        rawMoreButton_->setMenu(rawMoreMenu);
        rawUpButton_->setEnabled(false);
        rawListButton_->setEnabled(false);
        rawPreviewButton_->setEnabled(false);
        rawExportButton_->setEnabled(false);
        rawPeAction_->setEnabled(false);
        rawUpButton_->setStyleSheet(ksword_theme::themedButtonStyle());
        rawListButton_->setStyleSheet(ksword_theme::themedButtonStyle());
        rawPreviewButton_->setStyleSheet(ksword_theme::themedButtonStyle());
        rawExportButton_->setStyleSheet(ksword_theme::themedButtonStyle());
        rawMoreButton_->setStyleSheet(
            ksword_theme::themedButtonStyle());
        rawSummaryLabel_ = new QLabel(
            QStringLiteral(
                "先探测当前分区；NTFS（含命名流/ADS）、FAT12/16/32、"
                "exFAT、ReFS、Ext2/3/4、BtrFS、APFS、HFS/HFS+ "
                "可直接浏览目录、查看物理区段并导出文件。"),
            rawGroup);
        rawSummaryLabel_->setWordWrap(true);
        rawToolbar->addWidget(rawPathEdit_, 0, 0);
        rawToolbar->addWidget(rawUpButton_, 0, 1);
        rawToolbar->addWidget(rawListButton_, 0, 2);
        rawToolbar->addWidget(rawPreviewButton_, 0, 3);
        rawToolbar->addWidget(rawExportButton_, 0, 4);
        rawToolbar->addWidget(rawMoreButton_, 0, 5);
        rawToolbar->addWidget(rawSummaryLabel_, 1, 0, 1, 6);
        rawLayout->addLayout(rawToolbar);
        rawTable_ = createTable(rawGroup, {
            QStringLiteral("名称"),
            QStringLiteral("类型"),
            QStringLiteral("逻辑大小"),
            QStringLiteral("分配大小"),
            QStringLiteral("对象 ID"),
            QStringLiteral("元数据偏移"),
            QStringLiteral("首个物理偏移"),
            QStringLiteral("区段")
            });
        rawLayout->addWidget(rawTable_, 1);
        rootLayout->addWidget(rawGroup, 2);

        auto* deletedGroup = new QGroupBox(
            QStringLiteral("删除目录项取证与精确区间擦除"),
            this);
        auto* deletedLayout = new QVBoxLayout(deletedGroup);
        auto* deletedToolbar = new QGridLayout();
        deletedScanButton_ = new QPushButton(
            QStringLiteral("扫描 FAT/exFAT 删除项"),
            deletedGroup);
        deletedEraseButton_ = new QPushButton(
            QStringLiteral("安全擦除选中精确区间"),
            deletedGroup);
        deletedEraseButton_->setEnabled(false);
        deletedScanButton_->setStyleSheet(ksword_theme::themedButtonStyle());
        deletedEraseButton_->setStyleSheet(ksword_theme::themedButtonStyle());
        deletedSummaryLabel_ = new QLabel(
            QStringLiteral(
                "NTFS 删除项由“文件管理 → 文件恢复”扫描；"
                "此处补充 FAT12/16/32 与 exFAT，并只允许擦除已证明精确且当前空闲的离线磁盘区间。"),
            deletedGroup);
        deletedSummaryLabel_->setWordWrap(true);
        deletedToolbar->addWidget(deletedScanButton_, 0, 0);
        deletedToolbar->addWidget(deletedEraseButton_, 0, 1);
        deletedToolbar->addWidget(deletedSummaryLabel_, 0, 2);
        deletedLayout->addLayout(deletedToolbar);
        deletedTable_ = createTable(deletedGroup, {
            QStringLiteral("名称"),
            QStringLiteral("原目录"),
            QStringLiteral("大小"),
            QStringLiteral("首簇"),
            QStringLiteral("目录项偏移"),
            QStringLiteral("精确区间"),
            QStringLiteral("擦除资格"),
            QStringLiteral("证据")
            });
        deletedLayout->addWidget(deletedTable_, 1);
        rootLayout->addWidget(deletedGroup, 2);

        auto* extentGroup = new QGroupBox(
            QStringLiteral("文件物理区间与磁盘定位"),
            this);
        auto* extentLayout = new QVBoxLayout(extentGroup);
        auto* extentToolbar = new QGridLayout();
        filePathEdit_ = new QLineEdit(extentGroup);
        filePathEdit_->setPlaceholderText(
            QStringLiteral("选择 Windows 已挂载卷中的文件或目录"));
        fileBrowseButton_ = new QPushButton(
            QStringLiteral("选择文件"),
            extentGroup);
        extentButton_ = new QPushButton(
            QStringLiteral("解析物理区间"),
            extentGroup);
        extentButton_->setToolTip(QStringLiteral("解析所选文件在磁盘上的物理区段（扇区）位置"));
        fileBrowseButton_->setStyleSheet(ksword_theme::themedButtonStyle());
        extentButton_->setStyleSheet(ksword_theme::themedButtonStyle());
        extentToolbar->addWidget(filePathEdit_, 0, 0);
        extentToolbar->addWidget(fileBrowseButton_, 0, 1);
        extentToolbar->addWidget(extentButton_, 0, 2);
        extentLayout->addLayout(extentToolbar);
        extentTable_ = createTable(extentGroup, {
            QStringLiteral("磁盘"),
            QStringLiteral("文件偏移"),
            QStringLiteral("VCN"),
            QStringLiteral("LCN"),
            QStringLiteral("物理偏移"),
            QStringLiteral("长度"),
            QStringLiteral("状态")
            });
        extentLayout->addWidget(extentTable_, 1);
        rootLayout->addWidget(extentGroup, 2);

        auto* reverseGroup = new QGroupBox(
            QStringLiteral("按卷簇号反查文件流"),
            this);
        auto* reverseLayout = new QVBoxLayout(reverseGroup);
        auto* reverseToolbar = new QGridLayout();
        volumePathEdit_ = new QLineEdit(
            QStringLiteral("C:"),
            reverseGroup);
        volumePathEdit_->setPlaceholderText(
            QStringLiteral("卷路径，例如 C: 或 \\\\?\\Volume{GUID}\\"));
        clusterEdit_ = new QLineEdit(
            QStringLiteral("0"),
            reverseGroup);
        clusterEdit_->setPlaceholderText(
            QStringLiteral("LCN，支持十进制或 0x"));
        reverseButton_ = new QPushButton(
            QStringLiteral("反查占用文件"),
            reverseGroup);
        reverseButton_->setToolTip(QStringLiteral("根据卷簇号（LCN）反查是哪个文件占用了该簇"));
        reverseButton_->setStyleSheet(ksword_theme::themedButtonStyle());
        reverseToolbar->addWidget(
            new QLabel(QStringLiteral("卷"), reverseGroup),
            0,
            0);
        reverseToolbar->addWidget(volumePathEdit_, 0, 1);
        reverseToolbar->addWidget(
            new QLabel(QStringLiteral("簇号"), reverseGroup),
            0,
            2);
        reverseToolbar->addWidget(clusterEdit_, 0, 3);
        reverseToolbar->addWidget(reverseButton_, 0, 4);
        reverseLayout->addLayout(reverseToolbar);
        reverseTable_ = createTable(reverseGroup, {
            QStringLiteral("簇号"),
            QStringLiteral("簇数量"),
            QStringLiteral("文件流路径")
            });
        reverseLayout->addWidget(reverseTable_, 1);
        rootLayout->addWidget(reverseGroup, 1);
    }

    void DiskFileSystemForensicsPanel::initializeConnections()
    {
        connect(probeButton_, &QPushButton::clicked, this, [this]()
        {
            probeCurrentPartition();
        });
        connect(rawListButton_, &QPushButton::clicked, this, [this]()
        {
            browseRawDirectory();
        });
        connect(rawUpButton_, &QPushButton::clicked, this, [this]()
        {
            QString path = rawPathEdit_->text().trimmed();
            path.replace(QChar('/'), QChar('\\'));
            while (path.contains(QStringLiteral("\\\\")))
            {
                path.replace(QStringLiteral("\\\\"), QStringLiteral("\\"));
            }
            if (!path.startsWith(QChar('\\')))
            {
                path.prepend(QChar('\\'));
            }
            if (path.size() > 1 && path.endsWith(QChar('\\')))
            {
                path.chop(1);
            }
            if (path != QStringLiteral("\\"))
            {
                const qsizetype kSeparator = path.lastIndexOf(QChar('\\'));
                path = kSeparator <= 0
                    ? QStringLiteral("\\")
                    : path.left(kSeparator);
                rawPathEdit_->setText(path);
                browseRawDirectory();
            }
        });
        connect(rawPreviewButton_, &QPushButton::clicked, this, [this]()
        {
            previewSelectedRawFile();
        });
        connect(rawExportButton_, &QPushButton::clicked, this, [this]()
        {
            exportSelectedRawFile();
        });
        connect(rawPeAction_, &QAction::triggered, this, [this]()
        {
            analyzeSelectedRawPe();
        });
        connect(
            rawTable_,
            &QTableWidget::itemSelectionChanged,
            this,
            [this]()
            {
                const int kRow = rawTable_->currentRow();
                const bool kFileSelected =
                    kRow >= 0
                    && kRow < static_cast<int>(rawEntries_.size())
                    && rawEntries_[static_cast<std::size_t>(kRow)].type
                        != RawFileObjectType::kDirectory;
                rawPreviewButton_->setEnabled(
                    !busy_ && kFileSelected);
                rawExportButton_->setEnabled(
                    !busy_ && kFileSelected);
                rawPeAction_->setEnabled(
                    !busy_ && kFileSelected);
            });
        connect(
            rawTable_,
            &QTableWidget::cellDoubleClicked,
            this,
            [this](const int row, const int column)
            {
                if (row < 0
                    || row >= static_cast<int>(rawEntries_.size()))
                {
                    return;
                }
                if (column == 6)
                {
                    const QTableWidgetItem* item =
                        rawTable_->item(row, column);
                    if (item != nullptr
                        && item->data(Qt::UserRole + 1).toBool()
                        && jumpCallback_)
                    {
                        jumpCallback_(
                            item->data(Qt::UserRole).toULongLong());
                    }
                    return;
                }
                const RawFileEntry& entry =
                    rawEntries_[static_cast<std::size_t>(row)];
                if (entry.type == RawFileObjectType::kDirectory)
                {
                    rawPathEdit_->setText(entry.fullPath);
                    browseRawDirectory();
                    return;
                }
                previewSelectedRawFile();
            });
        connect(fileBrowseButton_, &QPushButton::clicked, this, [this]()
        {
            const QString kSelected = QFileDialog::getOpenFileName(
                this,
                QStringLiteral("选择要解析物理区间的文件"),
                filePathEdit_->text());
            if (!kSelected.isEmpty())
            {
                filePathEdit_->setText(kSelected);
            }
        });
        connect(extentButton_, &QPushButton::clicked, this, [this]()
        {
            resolveCurrentFile();
        });
        connect(reverseButton_, &QPushButton::clicked, this, [this]()
        {
            reverseLookupCurrentCluster();
        });
        connect(deletedScanButton_, &QPushButton::clicked, this, [this]()
        {
            scanDeletedEntries();
        });
        connect(deletedEraseButton_, &QPushButton::clicked, this, [this]()
        {
            eraseSelectedDeletedEntry();
        });
        connect(probeTable_, &QTableWidget::cellDoubleClicked, this,
            [this](const int row, const int column)
        {
            Q_UNUSED(column);
            const QTableWidgetItem* item = probeTable_->item(row, 2);
            if (item != nullptr && jumpCallback_)
            {
                jumpCallback_(item->data(Qt::UserRole).toULongLong());
            }
        });
        connect(extentTable_, &QTableWidget::cellDoubleClicked, this,
            [this](const int row, const int column)
        {
            Q_UNUSED(column);
            const QTableWidgetItem* item = extentTable_->item(row, 4);
            if (item != nullptr
                && item->data(Qt::UserRole + 1).toBool()
                && jumpCallback_)
            {
                jumpCallback_(item->data(Qt::UserRole).toULongLong());
            }
        });
        connect(
            deletedTable_,
            &QTableWidget::itemSelectionChanged,
            this,
            [this]()
            {
                const int kRow = deletedTable_->currentRow();
                const bool kEligible =
                    kRow >= 0
                    && kRow < static_cast<int>(deletedEntries_.size())
                    && deletedEntries_[static_cast<std::size_t>(kRow)]
                        .exactExtents
                    && deletedEntries_[static_cast<std::size_t>(kRow)]
                        .clustersCurrentlyFree;
                deletedEraseButton_->setEnabled(!busy_ && kEligible);
            });
        connect(
            deletedTable_,
            &QTableWidget::cellDoubleClicked,
            this,
            [this](const int row, const int column)
            {
                Q_UNUSED(column);
                if (row < 0
                    || row >= static_cast<int>(deletedEntries_.size())
                    || !jumpCallback_)
                {
                    return;
                }
                const DeletedDirectoryEntry& entry =
                    deletedEntries_[static_cast<std::size_t>(row)];
                const std::uint64_t kOffset = !entry.extents.empty()
                    ? entry.extents.front().physicalOffset
                    : entry.directoryEntryOffset;
                jumpCallback_(kOffset);
            });
    }

    void DiskFileSystemForensicsPanel::probeCurrentPartition()
    {
        if (busy_)
        {
            return;
        }
        const std::optional<DiskForensicsSelection> kSelection =
            selectionProvider_ ? selectionProvider_() : std::nullopt;
        if (!kSelection.has_value())
        {
            QMessageBox::information(
                this,
                QStringLiteral("文件系统取证"),
                QStringLiteral("请先在磁盘图或分区表中选择一个有效分区。"));
            return;
        }

        busy_ = true;
        probeButton_->setEnabled(false);
        probeSummaryLabel_->setText(
            QStringLiteral("正在探测 %1 ...").arg(kSelection->displayText));
        QPointer<DiskFileSystemForensicsPanel> safeThis(this);
        std::thread([safeThis, selectionValue = *kSelection]()
        {
            FileSystemProbeResult result =
                DiskFileSystemForensics::probePartition(
                    selectionValue.diskIndex,
                    selectionValue.backend,
                    selectionValue.partitionOffset,
                    selectionValue.partitionLength,
                    selectionValue.logicalSectorSize);
            if (safeThis.isNull())
            {
                return;
            }
            QMetaObject::invokeMethod(
                safeThis.data(),
                [safeThis,
                    selectionValue,
                    result = std::move(result)]() mutable
                {
                    if (!safeThis.isNull())
                    {
                        safeThis->applyProbeResult(
                            selectionValue,
                            std::move(result));
                    }
                },
                Qt::QueuedConnection);
        }).detach();
    }

    void DiskFileSystemForensicsPanel::browseRawDirectory()
    {
        if (busy_
            || !rawSelection_.has_value()
            || !supportsRawBrowser(rawFileSystem_))
        {
            return;
        }
        const QString kPath = rawPathEdit_->text().trimmed();
        const DiskForensicsSelection kSelection = *rawSelection_;
        const ForensicFileSystemKind kFileSystem = rawFileSystem_;
        busy_ = true;
        rawUpButton_->setEnabled(false);
        rawListButton_->setEnabled(false);
        rawPreviewButton_->setEnabled(false);
        rawExportButton_->setEnabled(false);
        rawPeAction_->setEnabled(false);
        rawSummaryLabel_->setText(
            QStringLiteral("正在解析 %1 的原始目录 %2 ...")
                .arg(kSelection.displayText)
                .arg(kPath));
        QPointer<DiskFileSystemForensicsPanel> safeThis(this);
        std::thread(
            [safeThis, kSelection, kFileSystem, kPath]()
            {
                RawDirectoryResult result =
                    DiskRawFileSystemBrowser::listDirectory(
                        kSelection.diskIndex,
                        kSelection.backend,
                        kSelection.partitionOffset,
                        kSelection.partitionLength,
                        kSelection.logicalSectorSize,
                        kFileSystem,
                        kPath,
                        4096U);
                if (safeThis.isNull())
                {
                    return;
                }
                QMetaObject::invokeMethod(
                    safeThis.data(),
                    [safeThis,
                        kSelection,
                        result = std::move(result)]() mutable
                    {
                        if (!safeThis.isNull())
                        {
                            safeThis->applyRawDirectoryResult(
                                kSelection,
                                std::move(result));
                        }
                    },
                    Qt::QueuedConnection);
            }).detach();
    }

    void DiskFileSystemForensicsPanel::previewSelectedRawFile()
    {
        if (busy_ || !rawSelection_.has_value())
        {
            return;
        }
        const int kRow = rawTable_->currentRow();
        if (kRow < 0 || kRow >= static_cast<int>(rawEntries_.size()))
        {
            return;
        }
        const RawFileEntry kEntry =
            rawEntries_[static_cast<std::size_t>(kRow)];
        if (kEntry.type == RawFileObjectType::kDirectory)
        {
            return;
        }
        if (kEntry.fileSizeBytes == 0U)
        {
            QMessageBox::information(
                this,
                QStringLiteral("原始文件预览"),
                QStringLiteral("该文件长度为 0 字节。"));
            return;
        }
        const DiskForensicsSelection kSelection = *rawSelection_;
        const ForensicFileSystemKind kFileSystem = rawFileSystem_;
        const std::uint32_t kPreviewLength =
            static_cast<std::uint32_t>(
                std::min<std::uint64_t>(
                    kEntry.fileSizeBytes,
                    4096U));
        busy_ = true;
        rawListButton_->setEnabled(false);
        rawPreviewButton_->setEnabled(false);
        rawExportButton_->setEnabled(false);
        rawPeAction_->setEnabled(false);
        rawSummaryLabel_->setText(
            QStringLiteral("正在读取 %1 的前 %2 字节 ...")
                .arg(kEntry.fullPath)
                .arg(kPreviewLength));
        QPointer<DiskFileSystemForensicsPanel> safeThis(this);
        std::thread(
            [safeThis,
                kSelection,
                kFileSystem,
                filePath = kEntry.fullPath,
                kPreviewLength]()
            {
                RawFileReadResult result =
                    DiskRawFileSystemBrowser::readFile(
                        kSelection.diskIndex,
                        kSelection.backend,
                        kSelection.partitionOffset,
                        kSelection.partitionLength,
                        kSelection.logicalSectorSize,
                        kFileSystem,
                        filePath,
                        0U,
                        kPreviewLength);
                if (safeThis.isNull())
                {
                    return;
                }
                QMetaObject::invokeMethod(
                    safeThis.data(),
                    [safeThis, result = std::move(result)]() mutable
                    {
                        if (!safeThis.isNull())
                        {
                            safeThis->applyRawReadResult(
                                std::move(result));
                        }
                    },
                    Qt::QueuedConnection);
            }).detach();
    }

    void DiskFileSystemForensicsPanel::exportSelectedRawFile()
    {
        if (busy_ || !rawSelection_.has_value())
        {
            return;
        }
        const int kRow = rawTable_->currentRow();
        if (kRow < 0 || kRow >= static_cast<int>(rawEntries_.size()))
        {
            return;
        }
        const RawFileEntry kEntry =
            rawEntries_[static_cast<std::size_t>(kRow)];
        if (kEntry.type == RawFileObjectType::kDirectory)
        {
            return;
        }
        const QString kDestination = QFileDialog::getSaveFileName(
            this,
            QStringLiteral("导出原始文件"),
            kEntry.name);
        if (kDestination.isEmpty())
        {
            return;
        }
        const DiskForensicsSelection kSelection = *rawSelection_;
        const ForensicFileSystemKind kFileSystem = rawFileSystem_;
        busy_ = true;
        rawListButton_->setEnabled(false);
        rawPreviewButton_->setEnabled(false);
        rawExportButton_->setEnabled(false);
        rawPeAction_->setEnabled(false);
        rawSummaryLabel_->setText(
            QStringLiteral("正在导出 %1 ...").arg(kEntry.fullPath));
        QPointer<DiskFileSystemForensicsPanel> safeThis(this);
        std::thread(
            [safeThis,
                kSelection,
                kFileSystem,
                source = kEntry.fullPath,
                kDestination]()
            {
                RawFileExportResult result =
                    DiskRawFileSystemBrowser::exportFile(
                        kSelection.diskIndex,
                        kSelection.backend,
                        kSelection.partitionOffset,
                        kSelection.partitionLength,
                        kSelection.logicalSectorSize,
                        kFileSystem,
                        source,
                        kDestination);
                if (safeThis.isNull())
                {
                    return;
                }
                QMetaObject::invokeMethod(
                    safeThis.data(),
                    [safeThis, result = std::move(result)]() mutable
                    {
                        if (!safeThis.isNull())
                        {
                            safeThis->applyRawExportResult(
                                std::move(result));
                        }
                    },
                    Qt::QueuedConnection);
            }).detach();
    }

    void DiskFileSystemForensicsPanel::analyzeSelectedRawPe()
    {
        if (busy_ || !rawSelection_.has_value())
        {
            return;
        }
        const int kRow = rawTable_->currentRow();
        if (kRow < 0 || kRow >= static_cast<int>(rawEntries_.size()))
        {
            return;
        }
        const RawFileEntry kEntry =
            rawEntries_[static_cast<std::size_t>(kRow)];
        if (kEntry.type == RawFileObjectType::kDirectory)
        {
            return;
        }
        constexpr std::uint64_t kMaximumPeBytes =
            512ULL * 1024ULL * 1024ULL;
        constexpr std::uint32_t kReadChunkBytes =
            4U * 1024U * 1024U;
        if (kEntry.fileSizeBytes == 0U
            || kEntry.fileSizeBytes > kMaximumPeBytes
            || kEntry.fileSizeBytes
                > static_cast<std::uint64_t>(
                    std::numeric_limits<int>::max()))
        {
            QMessageBox::warning(
                this,
                QStringLiteral("原始 PE 分析"),
                QStringLiteral(
                    "PE 字节长度必须在 1 字节到 512 MiB 之间。"));
            return;
        }

        const DiskForensicsSelection kSelection = *rawSelection_;
        const ForensicFileSystemKind kFileSystem = rawFileSystem_;
        busy_ = true;
        rawListButton_->setEnabled(false);
        rawPreviewButton_->setEnabled(false);
        rawExportButton_->setEnabled(false);
        rawPeAction_->setEnabled(false);
        rawSummaryLabel_->setText(
            QStringLiteral("正在读取并分析原始 PE：%1 ...")
                .arg(kEntry.fullPath));
        QPointer<DiskFileSystemForensicsPanel> safeThis(this);
        std::thread(
            [safeThis,
                kSelection,
                kFileSystem,
                kEntry]()
            {
                std::vector<std::uint8_t> fileBytes;
                fileBytes.reserve(
                    static_cast<std::size_t>(
                        kEntry.fileSizeBytes));
                QString readError;
                std::uint64_t offset = 0U;
                while (offset < kEntry.fileSizeBytes)
                {
                    const std::uint32_t kLength =
                        static_cast<std::uint32_t>(
                            std::min<std::uint64_t>(
                                kReadChunkBytes,
                                kEntry.fileSizeBytes - offset));
                    RawFileReadResult chunk =
                        DiskRawFileSystemBrowser::readFile(
                            kSelection.diskIndex,
                            kSelection.backend,
                            kSelection.partitionOffset,
                            kSelection.partitionLength,
                            kSelection.logicalSectorSize,
                            kFileSystem,
                            kEntry.fullPath,
                            offset,
                            kLength);
                    if (!chunk.success
                        || chunk.bytes.size()
                            != static_cast<qsizetype>(kLength))
                    {
                        readError = chunk.errorText.isEmpty()
                            ? QStringLiteral(
                                "原始文件读取在 0x%1 处被截断。")
                                .arg(
                                    static_cast<qulonglong>(offset),
                                    0,
                                    16)
                            : chunk.errorText;
                        break;
                    }
                    const auto* chunkBegin =
                        reinterpret_cast<
                            const std::uint8_t*>(
                            chunk.bytes.constData());
                    fileBytes.insert(
                        fileBytes.end(),
                        chunkBegin,
                        chunkBegin
                            + static_cast<std::size_t>(
                                chunk.bytes.size()));
                    offset += kLength;
                }

                ks::file::PeAnalysisResult analysis;
                if (readError.isEmpty())
                {
                    analysis =
                        ks::file::analyzePeBytes(fileBytes);
                }
                if (safeThis.isNull())
                {
                    return;
                }
                QMetaObject::invokeMethod(
                    safeThis.data(),
                    [safeThis,
                        sourcePath = kEntry.fullPath,
                        readError,
                        fileBytes = std::move(fileBytes),
                        analysis = std::move(analysis)]() mutable
                    {
                        if (safeThis.isNull())
                        {
                            return;
                        }
                        safeThis->busy_ = false;
                        safeThis->rawListButton_->setEnabled(
                            safeThis->rawSelection_.has_value());
                        const int kSelectedRow =
                            safeThis->rawTable_->currentRow();
                        const bool kFileSelected =
                            kSelectedRow >= 0
                            && kSelectedRow
                                < static_cast<int>(
                                    safeThis->rawEntries_.size())
                            && safeThis->rawEntries_[
                                static_cast<std::size_t>(
                                    kSelectedRow)].type
                                != RawFileObjectType::kDirectory;
                        safeThis->rawPreviewButton_->setEnabled(
                            kFileSelected);
                        safeThis->rawExportButton_->setEnabled(
                            kFileSelected);
                        safeThis->rawPeAction_->setEnabled(
                            kFileSelected);
                        if (!readError.isEmpty())
                        {
                            safeThis->rawSummaryLabel_->setText(
                                QStringLiteral(
                                    "原始 PE 读取失败：%1")
                                    .arg(readError));
                            QMessageBox::warning(
                                safeThis.data(),
                                QStringLiteral("原始 PE 分析"),
                                readError);
                            return;
                        }

                        safeThis->rawSummaryLabel_->setText(
                            analysis.success
                                ? QStringLiteral(
                                    "原始 PE 分析完成：%1")
                                    .arg(sourcePath)
                                : QStringLiteral(
                                    "原始 PE 解析失败：%1")
                                    .arg(sourcePath));
                        QDialog dialog(safeThis.data());
                        dialog.setWindowTitle(
                            QStringLiteral("原始 PE 分析"));
                        dialog.resize(980, 700);
                        auto* layout = new QVBoxLayout(&dialog);
                        auto* editor =
                            new CodeEditorWidget(&dialog);
                        editor->setReadOnly(true);
                        editor->setLocalizedText(
                            QString::fromStdWString(
                                analysis.reportText));
                        layout->addWidget(editor, 1);
                        auto* buttons = new QDialogButtonBox(
                            QDialogButtonBox::Close,
                            &dialog);
                        auto* disassembleButton =
                            buttons->addButton(
                                QStringLiteral("反汇编入口点"),
                                QDialogButtonBox::ActionRole);
                        disassembleButton->setEnabled(
                            analysis.success
                            && analysis.entryPointFileOffsetValid
                            && analysis.imageBase
                                <= std::numeric_limits<
                                    std::uint64_t>::max()
                                    - analysis.entryPointRva
                            && analysis.entryPointFileOffset
                                < static_cast<std::uint64_t>(
                                    fileBytes.size()));
                        QObject::connect(
                            buttons,
                            &QDialogButtonBox::rejected,
                            &dialog,
                            &QDialog::reject);
                        QObject::connect(
                            disassembleButton,
                            &QPushButton::clicked,
                            &dialog,
                            [&dialog,
                                sourcePath,
                                &fileBytes,
                                &analysis]()
                            {
                                const qsizetype kEntryOffset =
                                    static_cast<qsizetype>(
                                        analysis
                                            .entryPointFileOffset);
                                const qsizetype kCodeLength =
                                    std::min<qsizetype>(
                                        64 * 1024,
                                        static_cast<qsizetype>(
                                            fileBytes.size())
                                            - kEntryOffset);
                                const QByteArray kCodeBytes(
                                    reinterpret_cast<const char*>(
                                        fileBytes.data()
                                        + static_cast<std::size_t>(
                                            kEntryOffset)),
                                    kCodeLength);
                                ks::ui::KernelDisassemblyDialog
                                    disassembly(&dialog);
                                disassembly.setSnapshot(
                                    kCodeBytes,
                                    analysis.imageBase
                                        + analysis.entryPointRva,
                                    analysis.isPe64
                                        ? ks::ui::
                                            DisassemblyArchitecture::
                                                kX64
                                        : ks::ui::
                                            DisassemblyArchitecture::
                                                kX86,
                                    QStringLiteral(
                                        "原始文件 %1 的 PE 入口点")
                                        .arg(sourcePath));
                                disassembly.exec();
                            });
                        layout->addWidget(buttons);
                        dialog.exec();
                    },
                    Qt::QueuedConnection);
            }).detach();
    }

    void DiskFileSystemForensicsPanel::resolveCurrentFile()
    {
        if (busy_)
        {
            return;
        }
        const QString kFilePath = filePathEdit_->text().trimmed();
        if (kFilePath.isEmpty())
        {
            QMessageBox::information(
                this,
                QStringLiteral("文件物理区间"),
                QStringLiteral("请先选择一个文件。"));
            return;
        }

        busy_ = true;
        extentButton_->setEnabled(false);
        QPointer<DiskFileSystemForensicsPanel> safeThis(this);
        std::thread([safeThis, kFilePath]()
        {
            FileExtentResult result =
                DiskFileSystemForensics::resolveFileExtents(kFilePath);
            if (safeThis.isNull())
            {
                return;
            }
            QMetaObject::invokeMethod(
                safeThis.data(),
                [safeThis, result = std::move(result)]() mutable
                {
                    if (!safeThis.isNull())
                    {
                        safeThis->applyExtentResult(std::move(result));
                    }
                },
                Qt::QueuedConnection);
        }).detach();
    }

    void DiskFileSystemForensicsPanel::reverseLookupCurrentCluster()
    {
        if (busy_)
        {
            return;
        }
        std::uint64_t cluster = 0;
        if (!parseUnsignedAddress(clusterEdit_->text(), cluster))
        {
            QMessageBox::warning(
                this,
                QStringLiteral("簇号反查"),
                QStringLiteral("簇号格式无效。"));
            return;
        }

        const QString kVolumePath = volumePathEdit_->text().trimmed();
        busy_ = true;
        reverseButton_->setEnabled(false);
        QPointer<DiskFileSystemForensicsPanel> safeThis(this);
        std::thread([safeThis, kVolumePath, cluster]()
        {
            ReverseClusterResult result =
                DiskFileSystemForensics::reverseLookupCluster(
                    kVolumePath,
                    cluster);
            if (safeThis.isNull())
            {
                return;
            }
            QMetaObject::invokeMethod(
                safeThis.data(),
                [safeThis, result = std::move(result)]() mutable
                {
                    if (!safeThis.isNull())
                    {
                        safeThis->applyReverseResult(std::move(result));
                    }
                },
                Qt::QueuedConnection);
        }).detach();
    }

    void DiskFileSystemForensicsPanel::scanDeletedEntries()
    {
        if (busy_)
        {
            return;
        }
        const std::optional<DiskForensicsSelection> kSelection =
            selectionProvider_ ? selectionProvider_() : std::nullopt;
        if (!kSelection.has_value())
        {
            QMessageBox::information(
                this,
                QStringLiteral("删除目录项取证"),
                QStringLiteral("请先在磁盘图或分区表中选择一个有效分区。"));
            return;
        }

        busy_ = true;
        deletedScanButton_->setEnabled(false);
        deletedEraseButton_->setEnabled(false);
        deletedSummaryLabel_->setText(
            QStringLiteral("正在扫描 %1 的原始目录项 ...")
                .arg(kSelection->displayText));
        QPointer<DiskFileSystemForensicsPanel> safeThis(this);
        std::thread([safeThis, selectionValue = *kSelection]()
        {
            DeletedEntryScanResult result =
                DiskDeletedEntryForensics::scan(
                    selectionValue.diskIndex,
                    selectionValue.backend,
                    selectionValue.partitionOffset,
                    selectionValue.partitionLength,
                    selectionValue.logicalSectorSize);
            if (safeThis.isNull())
            {
                return;
            }
            QMetaObject::invokeMethod(
                safeThis.data(),
                [safeThis,
                    selectionValue,
                    result = std::move(result)]() mutable
                {
                    if (!safeThis.isNull())
                    {
                        safeThis->applyDeletedResult(
                            selectionValue,
                            std::move(result));
                    }
                },
                Qt::QueuedConnection);
        }).detach();
    }

    void DiskFileSystemForensicsPanel::eraseSelectedDeletedEntry()
    {
        if (busy_ || !deletedSelection_.has_value())
        {
            return;
        }
        const int kRow = deletedTable_->currentRow();
        if (kRow < 0 || kRow >= static_cast<int>(deletedEntries_.size()))
        {
            return;
        }
        const DeletedDirectoryEntry kEntry =
            deletedEntries_[static_cast<std::size_t>(kRow)];
        const DiskForensicsSelection kSelection = *deletedSelection_;
        if (!kEntry.exactExtents || !kEntry.clustersCurrentlyFree)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("精确区间擦除"),
                QStringLiteral(
                    "该条目没有同时通过簇链/连续标志、分区边界和当前空闲状态校验，不能擦除。"));
            return;
        }
        if ((kSelection.capabilityFlags
                & KSWORD_ARK_RAW_DISK_CAP_SYSTEM_DISK) != 0U)
        {
            QMessageBox::critical(
                this,
                QStringLiteral("精确区间擦除"),
                QStringLiteral("系统磁盘上的删除区间擦除被永久阻止。"));
            return;
        }
        if ((kSelection.capabilityFlags
                & KSWORD_ARK_RAW_DISK_CAP_OFFLINE) == 0U)
        {
            QMessageBox::critical(
                this,
                QStringLiteral("精确区间擦除"),
                QStringLiteral(
                    "目标磁盘必须先在 Windows 磁盘管理中切换为“脱机”。"
                    "这样可以避免文件系统缓存或重新分配与原始写入竞争。"));
            return;
        }

        std::uint64_t totalBytes = 0;
        for (const DeletedFileExtent& extent : kEntry.extents)
        {
            totalBytes += extent.lengthBytes;
        }
        const QMessageBox::StandardButton kWarningResult =
            QMessageBox::warning(
                this,
                QStringLiteral("不可逆精确区间擦除"),
                QStringLiteral(
                    "即将对离线磁盘中的 %1 个精确物理区间写零并逐块回读校验，"
                    "共 %2 字节。该操作不可撤销，且删除文件数据将无法恢复。\n\n"
                    "条目：%3/%4\n证据：%5")
                    .arg(kEntry.extents.size())
                    .arg(static_cast<qulonglong>(totalBytes))
                    .arg(kEntry.directoryPath)
                    .arg(kEntry.name)
                    .arg(kEntry.evidenceText),
                QMessageBox::Yes | QMessageBox::No,
                QMessageBox::No);
        if (kWarningResult != QMessageBox::Yes)
        {
            return;
        }

        // Final confirmation changed to direct click: no longer requires entering a confirmation phrase; defaults to focusing 'No' to prevent accidental triggers.
        const auto kConfirmation = QMessageBox::warning(
            this,
            QStringLiteral("精确区间擦除"),
            QStringLiteral("确认对该文件的物理区间写零？数据将被永久抹除且无法恢复。"),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
        if (kConfirmation != QMessageBox::Yes)
        {
            return;
        }

        busy_ = true;
        deletedScanButton_->setEnabled(false);
        deletedEraseButton_->setEnabled(false);
        deletedSummaryLabel_->setText(
            QStringLiteral("正在写零并回读校验 %1/%2 ...")
                .arg(kEntry.directoryPath)
                .arg(kEntry.name));
        QPointer<DiskFileSystemForensicsPanel> safeThis(this);
        std::thread([safeThis, kSelection, kEntry]()
        {
            ExtentEraseResult result =
                DiskDeletedEntryForensics::eraseExactFreeExtents(
                    kSelection.diskIndex,
                    kSelection.backend,
                    kSelection.logicalSectorSize,
                    KSWORD_ARK_RAW_DISK_FLAG_UI_CONFIRMED_WRITE |
                        KSWORD_ARK_RAW_DISK_FLAG_FUA,
                    kEntry);
            if (safeThis.isNull())
            {
                return;
            }
            QMetaObject::invokeMethod(
                safeThis.data(),
                [safeThis, result = std::move(result)]() mutable
                {
                    if (!safeThis.isNull())
                    {
                        safeThis->applyEraseResult(std::move(result));
                    }
                },
                Qt::QueuedConnection);
        }).detach();
    }

    void DiskFileSystemForensicsPanel::applyProbeResult(
        DiskForensicsSelection selection,
        FileSystemProbeResult result)
    {
        busy_ = false;
        probeButton_->setEnabled(true);
        probeTable_->setRowCount(0);
        rawTable_->setRowCount(0);
        rawEntries_.clear();
        rawSelection_.reset();
        rawFileSystem_ = ForensicFileSystemKind::kUnknown;
        rawUpButton_->setEnabled(false);
        rawListButton_->setEnabled(false);
        rawPreviewButton_->setEnabled(false);
        rawExportButton_->setEnabled(false);
        rawPeAction_->setEnabled(false);
        if (!result.success)
        {
            probeSummaryLabel_->setText(
                QStringLiteral("探测失败：%1").arg(result.errorText));
            rawSummaryLabel_->setText(
                QStringLiteral("原始目录浏览不可用：分区探测未成功。"));
            return;
        }

        probeSummaryLabel_->setText(
            QStringLiteral(
                "%1 | 扇区=%2 B | 块/簇=%3 B | 容量=%4 B | 能力：%5")
                .arg(result.name)
                .arg(result.logicalSectorSize)
                .arg(result.blockSize)
                .arg(static_cast<qulonglong>(result.totalBytes))
                .arg(result.capabilityText));
        probeTable_->setRowCount(
            static_cast<int>(result.fields.size()));
        for (int row = 0; row < static_cast<int>(result.fields.size()); ++row)
        {
            const FileSystemProbeField& field =
                result.fields[static_cast<std::size_t>(row)];
            probeTable_->setItem(row, 0, readOnlyItem(field.name));
            probeTable_->setItem(row, 1, readOnlyItem(field.value));
            auto* offsetItem = readOnlyItem(hexOffset(field.absoluteOffset));
            offsetItem->setData(
                Qt::UserRole,
                static_cast<qulonglong>(field.absoluteOffset));
            probeTable_->setItem(row, 2, offsetItem);
            probeTable_->setItem(
                row,
                3,
                readOnlyItem(QString::number(field.sizeBytes)));
            probeTable_->setItem(row, 4, readOnlyItem(field.detail));
        }
        probeTable_->resizeColumnsToContents();

        if (supportsRawBrowser(result.kind))
        {
            rawSelection_ = std::move(selection);
            rawFileSystem_ = result.kind;
            rawPathEdit_->setText(QStringLiteral("\\"));
            rawListButton_->setEnabled(true);
            rawSummaryLabel_->setText(
                QStringLiteral(
                    "%1 已就绪：可直接读取未挂载分区的目录树、文件数据和物理区段。")
                    .arg(result.name));
        }
        else
        {
            rawSummaryLabel_->setText(
                QStringLiteral(
                    "%1 使用现有专用取证入口；此浏览器面向 ReFS、Ext、"
                    "BtrFS、APFS 与 HFS/HFS+。")
                    .arg(result.name));
        }
    }

    void DiskFileSystemForensicsPanel::applyRawDirectoryResult(
        DiskForensicsSelection selection,
        RawDirectoryResult result)
    {
        busy_ = false;
        rawTable_->setRowCount(0);
        rawEntries_.clear();
        rawPreviewButton_->setEnabled(false);
        rawExportButton_->setEnabled(false);
        rawPeAction_->setEnabled(false);
        if (!result.success)
        {
            rawUpButton_->setEnabled(
                rawPathEdit_->text().trimmed() != QStringLiteral("\\"));
            rawListButton_->setEnabled(
                rawSelection_.has_value()
                && supportsRawBrowser(rawFileSystem_));
            rawSummaryLabel_->setText(
                QStringLiteral("原始目录解析失败：%1")
                    .arg(result.errorText));
            return;
        }

        rawSelection_ = std::move(selection);
        rawFileSystem_ = result.fileSystem;
        rawPathEdit_->setText(result.canonicalPath);
        rawEntries_ = std::move(result.entries);
        rawUpButton_->setEnabled(
            result.canonicalPath != QStringLiteral("\\"));
        rawListButton_->setEnabled(true);
        rawSummaryLabel_->setText(
            QStringLiteral(
                "%1 | 目录对象=%2 | 扫描记录=%3 | 返回=%4%5")
                .arg(result.fileSystemName)
                .arg(static_cast<qulonglong>(
                    result.directoryObjectId))
                .arg(static_cast<qulonglong>(
                    result.scannedRecords))
                .arg(rawEntries_.size())
                .arg(result.truncated
                    ? QStringLiteral("（已达到显示上限）")
                    : QString()));
        rawTable_->setRowCount(
            static_cast<int>(rawEntries_.size()));
        for (int row = 0;
             row < static_cast<int>(rawEntries_.size());
             ++row)
        {
            const RawFileEntry& entry =
                rawEntries_[static_cast<std::size_t>(row)];
            rawTable_->setItem(row, 0, readOnlyItem(entry.name));
            rawTable_->setItem(
                row,
                1,
                readOnlyItem(
                    DiskRawFileSystemBrowser::objectTypeText(
                        entry.type)));
            rawTable_->setItem(
                row,
                2,
                readOnlyItem(QString::number(entry.fileSizeBytes)));
            rawTable_->setItem(
                row,
                3,
                readOnlyItem(
                    QString::number(entry.allocatedSizeBytes)));
            rawTable_->setItem(
                row,
                4,
                readOnlyItem(QString::number(entry.objectId)));
            auto* metadataItem =
                readOnlyItem(hexOffset(entry.metadataOffset));
            metadataItem->setData(
                Qt::UserRole,
                static_cast<qulonglong>(entry.metadataOffset));
            rawTable_->setItem(row, 5, metadataItem);

            QStringList extentTexts;
            std::uint64_t firstPhysical = 0;
            bool firstPhysicalExact = false;
            for (const RawFileExtent& extent : entry.extents)
            {
                if (!firstPhysicalExact
                    && extent.physicalMappingExact
                    && !extent.sparse)
                {
                    firstPhysical = extent.absoluteOffset;
                    firstPhysicalExact = true;
                }
                QString state;
                if (extent.sparse)
                {
                    state = QStringLiteral("稀疏");
                }
                else if (extent.unwritten)
                {
                    state = QStringLiteral("未写入");
                }
                else if (extent.compressed)
                {
                    state = QStringLiteral("压缩");
                }
                extentTexts.push_back(
                    QStringLiteral("%1:%2+%3%4")
                        .arg(hexOffset(extent.logicalOffset))
                        .arg(extent.physicalMappingExact
                            ? hexOffset(extent.absoluteOffset)
                            : QStringLiteral("-"))
                        .arg(static_cast<qulonglong>(
                            extent.lengthBytes))
                        .arg(state.isEmpty()
                            ? QString()
                            : QStringLiteral("[%1]").arg(state)));
            }
            if (entry.extentsTruncated)
            {
                extentTexts.push_back(
                    QStringLiteral("…[物理映射未完整展开]"));
            }
            auto* physicalItem = readOnlyItem(
                firstPhysicalExact
                    ? hexOffset(firstPhysical)
                    : QStringLiteral("-"));
            physicalItem->setData(
                Qt::UserRole,
                static_cast<qulonglong>(firstPhysical));
            physicalItem->setData(
                Qt::UserRole + 1,
                firstPhysicalExact);
            rawTable_->setItem(row, 6, physicalItem);
            rawTable_->setItem(
                row,
                7,
                readOnlyItem(extentTexts.isEmpty()
                    ? QStringLiteral("-")
                    : extentTexts.join(QStringLiteral("; "))));
        }
        rawTable_->resizeColumnsToContents();
    }

    void DiskFileSystemForensicsPanel::applyRawReadResult(
        RawFileReadResult result)
    {
        busy_ = false;
        rawListButton_->setEnabled(rawSelection_.has_value());
        rawUpButton_->setEnabled(
            rawPathEdit_->text().trimmed() != QStringLiteral("\\"));
        const int kRow = rawTable_->currentRow();
        const bool kFileSelected =
            kRow >= 0
            && kRow < static_cast<int>(rawEntries_.size())
            && rawEntries_[static_cast<std::size_t>(kRow)].type
                != RawFileObjectType::kDirectory;
        rawPreviewButton_->setEnabled(kFileSelected);
        rawExportButton_->setEnabled(kFileSelected);
        rawPeAction_->setEnabled(kFileSelected);
        if (!result.success)
        {
            rawSummaryLabel_->setText(
                QStringLiteral("原始文件读取失败：%1")
                    .arg(result.errorText));
            QMessageBox::warning(
                this,
                QStringLiteral("原始文件预览"),
                result.errorText);
            return;
        }

        rawSummaryLabel_->setText(
            QStringLiteral(
                "已读取 %1：%2 字节，文件总长 %3 字节。")
                .arg(result.filePath)
                .arg(result.bytes.size())
                .arg(static_cast<qulonglong>(
                    result.fileSizeBytes)));
        QMessageBox preview(this);
        preview.setIcon(QMessageBox::Information);
        preview.setWindowTitle(QStringLiteral("原始文件预览"));
        preview.setText(
            QStringLiteral("%1\n读取 %2 字节；十六进制内容见详细信息。")
                .arg(result.filePath)
                .arg(result.bytes.size()));
        preview.setDetailedText(bytePreview(result.bytes));
        preview.exec();
    }

    void DiskFileSystemForensicsPanel::applyRawExportResult(
        RawFileExportResult result)
    {
        busy_ = false;
        rawListButton_->setEnabled(rawSelection_.has_value());
        rawUpButton_->setEnabled(
            rawPathEdit_->text().trimmed() != QStringLiteral("\\"));
        const int kRow = rawTable_->currentRow();
        const bool kFileSelected =
            kRow >= 0
            && kRow < static_cast<int>(rawEntries_.size())
            && rawEntries_[static_cast<std::size_t>(kRow)].type
                != RawFileObjectType::kDirectory;
        rawPreviewButton_->setEnabled(kFileSelected);
        rawExportButton_->setEnabled(kFileSelected);
        rawPeAction_->setEnabled(kFileSelected);
        if (!result.success)
        {
            rawSummaryLabel_->setText(
                QStringLiteral("原始文件导出失败：%1")
                    .arg(result.errorText));
            QMessageBox::warning(
                this,
                QStringLiteral("导出原始文件"),
                result.errorText);
            return;
        }
        rawSummaryLabel_->setText(
            QStringLiteral(
                "导出完成：%1 → %2（%3 字节）")
                .arg(result.filePath)
                .arg(result.destinationPath)
                .arg(static_cast<qulonglong>(
                    result.bytesWritten)));
        QMessageBox::information(
            this,
            QStringLiteral("导出原始文件"),
            rawSummaryLabel_->text());
    }

    void DiskFileSystemForensicsPanel::applyExtentResult(
        FileExtentResult result)
    {
        busy_ = false;
        extentButton_->setEnabled(true);
        extentTable_->setRowCount(0);
        if (!result.success)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("文件物理区间"),
                result.errorText);
            return;
        }

        extentTable_->setRowCount(
            static_cast<int>(result.extents.size()));
        for (int row = 0; row < static_cast<int>(result.extents.size()); ++row)
        {
            const PhysicalFileExtent& extent =
                result.extents[static_cast<std::size_t>(row)];
            extentTable_->setItem(
                row,
                0,
                readOnlyItem(extent.diskNumber >= 0
                    ? QStringLiteral("PhysicalDrive%1").arg(extent.diskNumber)
                    : QStringLiteral("-")));
            extentTable_->setItem(row, 1, readOnlyItem(hexOffset(extent.fileOffset)));
            extentTable_->setItem(row, 2, readOnlyItem(QString::number(extent.startingVcn)));
            extentTable_->setItem(row, 3, readOnlyItem(extent.sparse ? QStringLiteral("Sparse") : QString::number(extent.startingLcn)));
            auto* physicalItem = readOnlyItem(extent.physicalMappingExact
                ? hexOffset(extent.physicalOffset)
                : QStringLiteral("-"));
            physicalItem->setData(
                Qt::UserRole,
                static_cast<qulonglong>(extent.physicalOffset));
            physicalItem->setData(
                Qt::UserRole + 1,
                extent.physicalMappingExact);
            extentTable_->setItem(row, 4, physicalItem);
            extentTable_->setItem(row, 5, readOnlyItem(QString::number(extent.lengthBytes)));
            extentTable_->setItem(
                row,
                6,
                readOnlyItem(extent.sparse
                    ? QStringLiteral("稀疏区间")
                    : (extent.physicalMappingExact
                        ? QStringLiteral("可跳转")
                        : QStringLiteral("多区间卷，仅返回卷内 LCN"))));
        }
        extentTable_->resizeColumnsToContents();
    }

    void DiskFileSystemForensicsPanel::applyReverseResult(
        ReverseClusterResult result)
    {
        busy_ = false;
        reverseButton_->setEnabled(true);
        reverseTable_->setRowCount(0);
        if (!result.success)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("簇号反查"),
                result.errorText);
            return;
        }

        reverseTable_->setRowCount(
            static_cast<int>(result.entries.size()));
        for (int row = 0; row < static_cast<int>(result.entries.size()); ++row)
        {
            const ReverseClusterEntry& entry =
                result.entries[static_cast<std::size_t>(row)];
            reverseTable_->setItem(row, 0, readOnlyItem(QString::number(entry.cluster)));
            reverseTable_->setItem(row, 1, readOnlyItem(QString::number(entry.clusterCount)));
            reverseTable_->setItem(row, 2, readOnlyItem(entry.streamPath));
        }
        reverseTable_->resizeColumnsToContents();
    }

    void DiskFileSystemForensicsPanel::applyDeletedResult(
        DiskForensicsSelection selection,
        DeletedEntryScanResult result)
    {
        busy_ = false;
        deletedScanButton_->setEnabled(true);
        deletedEraseButton_->setEnabled(false);
        deletedTable_->setRowCount(0);
        deletedEntries_.clear();
        deletedSelection_.reset();
        if (!result.success)
        {
            deletedSummaryLabel_->setText(
                QStringLiteral("删除项扫描失败：%1").arg(result.errorText));
            return;
        }

        deletedSummaryLabel_->setText(result.summaryText);
        deletedSelection_ = std::move(selection);
        deletedEntries_ = std::move(result.entries);
        deletedTable_->setRowCount(
            static_cast<int>(deletedEntries_.size()));
        for (int row = 0;
             row < static_cast<int>(deletedEntries_.size());
             ++row)
        {
            const DeletedDirectoryEntry& entry =
                deletedEntries_[static_cast<std::size_t>(row)];
            deletedTable_->setItem(row, 0, readOnlyItem(entry.name));
            deletedTable_->setItem(
                row,
                1,
                readOnlyItem(entry.directoryPath));
            deletedTable_->setItem(
                row,
                2,
                readOnlyItem(QString::number(entry.fileSizeBytes)));
            deletedTable_->setItem(
                row,
                3,
                readOnlyItem(QString::number(entry.firstCluster)));
            deletedTable_->setItem(
                row,
                4,
                readOnlyItem(hexOffset(entry.directoryEntryOffset)));

            QStringList extentTexts;
            for (const DeletedFileExtent& extent : entry.extents)
            {
                extentTexts.push_back(
                    QStringLiteral("%1+%2")
                        .arg(hexOffset(extent.physicalOffset))
                        .arg(static_cast<qulonglong>(extent.lengthBytes)));
            }
            deletedTable_->setItem(
                row,
                5,
                readOnlyItem(extentTexts.isEmpty()
                    ? QStringLiteral("-")
                    : extentTexts.join(QStringLiteral("; "))));
            deletedTable_->setItem(
                row,
                6,
                readOnlyItem(entry.exactExtents
                        && entry.clustersCurrentlyFree
                        && !entry.directory
                    ? QStringLiteral("离线磁盘可擦除")
                    : QStringLiteral("只读取证")));
            deletedTable_->setItem(
                row,
                7,
                readOnlyItem(entry.evidenceText));
        }
        deletedTable_->resizeColumnsToContents();
    }

    void DiskFileSystemForensicsPanel::applyEraseResult(
        ExtentEraseResult result)
    {
        busy_ = false;
        deletedScanButton_->setEnabled(true);
        deletedEraseButton_->setEnabled(false);
        if (!result.success)
        {
            deletedSummaryLabel_->setText(
                QStringLiteral("精确区间擦除失败：%1")
                    .arg(result.errorText));
            QMessageBox::critical(
                this,
                QStringLiteral("精确区间擦除"),
                result.errorText);
            return;
        }

        deletedSummaryLabel_->setText(
            QStringLiteral(
                "精确区间擦除完成：%1 个区间，%2 字节均已写零并回读验证。请重新扫描刷新分配状态。")
                .arg(result.extentsErased)
                .arg(static_cast<qulonglong>(result.bytesErased)));
        QMessageBox::information(
            this,
            QStringLiteral("精确区间擦除"),
            deletedSummaryLabel_->text());
    }
}
