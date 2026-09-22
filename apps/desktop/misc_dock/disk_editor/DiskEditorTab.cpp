#include "DiskEditorTab.h"
#include "../../../../shared/evidence/NumericTextParse.h"
#include "../../settings_dock/AppearanceSettings.h"
#include "../../framework/PrivilegeElevationPrompt.h"
#include "../../ui/TableInteractionSupport.h"
#include "../../ui/VisibleTableWidget.h"

// ============================================================
// DiskEditorTab.cpp
// Purpose:
// 1) Implement the disk editor page within the Misc Dock;
// 2) Combine disk enumeration, horizontal bar charts, partition tables, and HEX sector editing.
// 3) Control disk write risks via read-only default values, explicit confirmation, and sector alignment limits.
// ============================================================

#include "DiskEditorBackend.h"
#include "DiskFileSystemForensicsPanel.h"
#include "DiskRangeTools.h"
#include "DiskMapWidget.h"
#include "DiskStructureParser.h"

#include "../../Theme.h"
#include "../../ui/HexEditorWidget.h"
#include "../../../../shared/driver/KswordArkStorageForensicsIoctl.h"

#include <QAbstractItemView>
#include <QAction>
#include <QBrush>
#include <QClipboard>
#include <QCheckBox>
#include <QComboBox>
#include <QCryptographicHash>
#include <QDateTime>
#include <QFileDialog>
#include <QGridLayout>
#include <QGroupBox>
#include <QGuiApplication>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QModelIndex>
#include <QSignalBlocker>
#include <QMetaObject>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QSpinBox>
#include <QSplitter>
#include <QStringList>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

#include <algorithm>
#include <thread>

namespace
{
    // Partition table column indices:
    // - Unify column order.
    // - Avoid magic numbers in future maintenance.
    constexpr int kPartitionColumnNumber = 0;
    constexpr int kPartitionColumnName = 1;
    constexpr int kPartitionColumnType = 2;
    constexpr int kPartitionColumnVolume = 3;
    constexpr int kPartitionColumnOffset = 4;
    constexpr int kPartitionColumnLength = 5;
    constexpr int kPartitionColumnFlags = 6;

    // Structure field table column indices:
    // - Saves MBR/GPT/BootSector parsing fields;
    // - The offset column carries a Qt::UserRole jump address.
    constexpr int kStructureColumnGroup = 0;
    constexpr int kStructureColumnName = 1;
    constexpr int kStructureColumnValue = 2;
    constexpr int kStructureColumnOffset = 3;
    constexpr int kStructureColumnSize = 4;
    constexpr int kStructureColumnSeverity = 5;
    constexpr int kStructureColumnDetail = 6;

    // Index of the search result table column:
    // - offset column carries the absolute address;
    // - The preview column displays the nearby HEX for matches.
    constexpr int kSearchColumnIndex = 0;
    constexpr int kSearchColumnOffset = 1;
    constexpr int kSearchColumnPreview = 2;

    // buildToolButtonStyle：
    // - Returns the page's common button style;
    // - Consistent with the project's blue theme.
    QString buildToolButtonStyle()
    {
        return ksword_theme::themedButtonStyle();
    }

    // buildInputStyle：
    // - Returns the input box and dropdown style;
    // - Ensure readability in both light and dark modes.
    QString buildInputStyle()
    {
        return QStringLiteral(
            "QLineEdit,QSpinBox{"
            "  border:1px solid %1;"
            "  border-radius:4px;"
            "  padding:3px 6px;"
            "  background:%2;"
            "  color:%3;"
            "}"
            "QLineEdit:focus,QSpinBox:focus{"
            "  border:1px solid %4;"
            "}")
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::textPrimaryHex())
            .arg(ksword_theme::kPrimaryBlueHex)
            + ksword_theme::themedComboBoxStyle();
    }

    // buildTableStyle：
    // - Returns partition table style;
    // - Use the theme color to draw the selection and header.
    QString buildTableStyle()
    {
        return QStringLiteral(
            "QTableWidget{"
            "  border:1px solid %1;"
            "  border-radius:6px;"
            "  background:%2;"
            "  alternate-background-color:%3;"
            "  color:%4;"
            "  gridline-color:%1;"
            "}"
            "QHeaderView::section{"
            "  border:none;"
            "  border-bottom:1px solid %1;"
            "  background:transparent; /* %3 */"
            "  color:%5;"
            "  padding:5px;"
            "  font-weight:700;"
            "}")
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::surfaceAltHex())
            .arg(ksword_theme::textPrimaryHex())
            .arg(ksword_theme::kPrimaryBlueHex);
    }

    // buildInfoCardStyle：
    // - Returns the style for the summary card and log box.
    // - Responsible for visual display only.
    QString buildInfoCardStyle()
    {
        return QStringLiteral(
            "QGroupBox{"
            "  border:1px solid %1;"
            "  border-radius:8px;"
            "  margin-top:10px;"
            "  padding:8px;"
            "  color:%2;"
            "  font-weight:700;"
            "}"
            "QGroupBox::title{"
            "  subcontrol-origin:margin;"
            "  left:10px;"
            "  padding:0 4px;"
            "}")
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::textPrimaryHex());
    }

    // setReadOnlyItem：
    // - Create a read-only table cell.
    // - text: display text
    // - Returns a QTableWidgetItem pointer; ownership is transferred to the table.
    QTableWidgetItem* makeReadOnlyItem(const QString& text)
    {
        QTableWidgetItem* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }

    // hexOffsetText：
    // - Format the offset as 16-bit HEX;
    // - value is the byte offset.
    // - Returns '0x0000...' text.
    QString hexOffsetText(const std::uint64_t value)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(value), 16, 16, QChar('0'))
            .toUpper();
    }

    void installDiskEditorTableCopyMenu(QTableWidget* table)
    {
        // installDiskEditorTableCopyMenu：
        // - Input: Partition/structure/search result table in the disk editor;
        // - Processing: Right-click to select a row and copy its visible columns as TSV.
        // - Returns: None. The menu only copies analysis results and does not perform read/write sector operations.
        if (table == nullptr)
        {
            return;
        }

        table->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(table, &QTableWidget::customContextMenuRequested, table, [table](const QPoint& localPosition)
        {
            const QModelIndex kClickedIndex = table->indexAt(localPosition);
            if (kClickedIndex.isValid())
            {
                table->setCurrentCell(kClickedIndex.row(), kClickedIndex.column());
            }

            QMenu contextMenu(table);
            contextMenu.setStyleSheet(ksword_theme::contextMenuStyle());
            QAction* copyRowAction = contextMenu.addAction(
                QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
                QStringLiteral("复制当前行"));
            copyRowAction->setEnabled(table->currentRow() >= 0);
            if (contextMenu.exec(table->viewport()->mapToGlobal(localPosition)) != copyRowAction)
            {
                return;
            }

            QClipboard* clipboardObject = QGuiApplication::clipboard();
            const int kRowIndex = table->currentRow();
            if (clipboardObject == nullptr || kRowIndex < 0 || kRowIndex >= table->rowCount())
            {
                return;
            }

            QStringList rowFields;
            rowFields.reserve(table->columnCount());
            for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
            {
                const QTableWidgetItem* item = table->item(kRowIndex, columnIndex);
                rowFields.push_back(item != nullptr ? item->text() : QString());
            }
            clipboardObject->setText(rowFields.join(QLatin1Char('\t')));
        });
    }

    // bytesToPreviewText：
    // - Convert search result preview bytes to short HEX text;
    // - bytes are raw bytes.
    // - Returns space-separated uppercase HEX.
    QString bytesToPreviewText(const QByteArray& bytes)
    {
        return QString::fromLatin1(bytes.toHex(' ')).toUpper();
    }

    // createReadOnlyTable：
    // - Create a read-only table with a unified style.
    // - parent is the Qt parent widget; headers are the table headers.
    // - Returns a QTableWidget pointer; ownership transferred to parent.
    QTableWidget* createReadOnlyTable(QWidget* parent, const QStringList& headers)
    {
        QTableWidget* table = new ks::ui::VisibleTableWidget(parent);
        table->setColumnCount(headers.size());
        table->setHorizontalHeaderLabels(headers);
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setSelectionMode(QAbstractItemView::SingleSelection);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table->setAlternatingRowColors(true);
        table->verticalHeader()->setVisible(false);
        table->horizontalHeader()->setStretchLastSection(true);
        table->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
        table->setStyleSheet(buildTableStyle());
        installDiskEditorTableCopyMenu(table);
        return table;
    }

    // applySeverityToItem：
    // - Set table text color based on severity;
    // - item is the cell to be modified.
    // - Severity indicates the severity of structural/health items.
    // - No return value.
    void applySeverityToItem(QTableWidgetItem* item, const ks::misc::DiskStructureSeverity severity)
    {
        if (item == nullptr)
        {
            return;
        }
        if (severity == ks::misc::DiskStructureSeverity::kError)
        {
            item->setForeground(QBrush(ksword_theme::errorColor()));
        }
        else if (severity == ks::misc::DiskStructureSeverity::kWarning)
        {
            item->setForeground(QBrush(ksword_theme::warningColor()));
        }
    }

    // findVolumeHintForPartition：
    // - Find volume/disk hint for partition by interval overlap;
    // - partition is the partition;
    // - volumes: list of volume extents;
    // - Returns the merged hint text.
    QString findVolumeHintForPartition(
        const ks::misc::DiskPartitionInfo& partition,
        const std::vector<ks::misc::DiskVolumeInfo>& volumes)
    {
        QStringList hints;
        const std::uint64_t kPartitionEnd = partition.offsetBytes + partition.lengthBytes;
        for (const ks::misc::DiskVolumeInfo& volume : volumes)
        {
            const std::uint64_t kVolumeEnd = volume.offsetBytes + volume.lengthBytes;
            const bool kOverlap = partition.offsetBytes < kVolumeEnd && volume.offsetBytes < kPartitionEnd;
            if (!kOverlap)
            {
                continue;
            }
            QString hint = volume.mountPoints.isEmpty() ? volume.volumeName : volume.mountPoints;
            if (!volume.label.isEmpty())
            {
                hint += QStringLiteral(" [%1]").arg(volume.label);
            }
            if (!volume.fileSystem.isEmpty())
            {
                hint += QStringLiteral(" %1").arg(volume.fileSystem);
            }
            hints << hint;
        }
        return hints.join(QStringLiteral("; "));
    }
}

namespace ks::misc
{
    DiskEditorTab::DiskEditorTab(QWidget* parent)
        : QWidget(parent)
    {
        initializeUi();
        initializeConnections();
        refreshDiskListAsync(false);
    }

    void DiskEditorTab::initializeUi()
    {
        // Root layout: top toolbar + main splitter + bottom status.
        rootLayout_ = new QVBoxLayout(this);
        rootLayout_->setContentsMargins(6, 6, 6, 6);
        rootLayout_->setSpacing(6);

        initializeToolbar();
        initializeLayoutPanels();

        statusLabel_ = new QLabel(QStringLiteral("状态：正在枚举磁盘..."), this);
        statusLabel_->setWordWrap(true);
        statusLabel_->setStyleSheet(QStringLiteral("color:%1;").arg(ksword_theme::textSecondaryHex()));
        rootLayout_->addWidget(statusLabel_, 0);
    }

    void DiskEditorTab::initializeToolbar()
    {
        // The top toolbar aggregates disk selection, read range, and write protection.
        toolbarWidget_ = new QWidget(this);
        toolbarLayout_ = new QHBoxLayout(toolbarWidget_);
        toolbarLayout_->setContentsMargins(0, 0, 0, 0);
        toolbarLayout_->setSpacing(6);
        rootLayout_->addWidget(toolbarWidget_, 0);

        diskCombo_ = new QComboBox(toolbarWidget_);
        diskCombo_->setMinimumWidth(300);
        diskCombo_->setStyleSheet(buildInputStyle());
        diskCombo_->setToolTip(QStringLiteral("选择要查看的物理磁盘"));

        backendCombo_ = new QComboBox(toolbarWidget_);
        backendCombo_->setMinimumWidth(170);
        backendCombo_->setStyleSheet(buildInputStyle());
        backendCombo_->setToolTip(QStringLiteral("选择实际磁盘访问层；端口直达绕过上层磁盘对象，控制器直达仅允许离线磁盘"));

        refreshButton_ = new QPushButton(QStringLiteral("刷新磁盘"), toolbarWidget_);
        readButton_ = new QPushButton(QStringLiteral("读取"), toolbarWidget_);
        writeButton_ = new QPushButton(QStringLiteral("写回"), toolbarWidget_);
        partitionStartButton_ = new QPushButton(QStringLiteral("跳到分区起点"), toolbarWidget_);
        readButton_->setToolTip(QStringLiteral("读取当前偏移/长度处的磁盘数据到十六进制视图"));
        writeButton_->setToolTip(QStringLiteral("把十六进制视图中修改过的数据写回磁盘原位置（会覆盖原数据，操作危险）"));
        partitionStartButton_->setToolTip(QStringLiteral("把读取偏移跳转到所选分区的起始扇区"));
        refreshButton_->setIcon(QIcon(QStringLiteral(":/Icon/process_refresh.svg")));
        readButton_->setIcon(QIcon(QStringLiteral(":/Icon/disk_storage.svg")));
        writeButton_->setIcon(QIcon(QStringLiteral(":/Icon/disk_save.svg")));
        refreshButton_->setStyleSheet(buildToolButtonStyle());
        readButton_->setStyleSheet(buildToolButtonStyle());
        writeButton_->setStyleSheet(buildToolButtonStyle());
        partitionStartButton_->setStyleSheet(buildToolButtonStyle());

        offsetEdit_ = new QLineEdit(toolbarWidget_);
        offsetEdit_->setPlaceholderText(QStringLiteral("偏移，例如 0x0000000000000000"));
        offsetEdit_->setText(QStringLiteral("0x0000000000000000"));
        offsetEdit_->setMinimumWidth(190);
        offsetEdit_->setStyleSheet(buildInputStyle());

        lengthSpin_ = new QSpinBox(toolbarWidget_);
        lengthSpin_->setRange(512, 1024 * 1024);
        lengthSpin_->setSingleStep(512);
        lengthSpin_->setValue(4096);
        lengthSpin_->setSuffix(QStringLiteral(" B"));
        lengthSpin_->setStyleSheet(buildInputStyle());

        readOnlyCheck_ = new QCheckBox(QStringLiteral("只读保护"), toolbarWidget_);
        readOnlyCheck_->setChecked(true);
        readOnlyCheck_->setToolTip(QStringLiteral("开启时禁用 HEX 编辑和写回按钮"));

        requireAlignedCheck_ = new QCheckBox(QStringLiteral("R0 强制扇区对齐"), toolbarWidget_);
        requireAlignedCheck_->setChecked(true);
        requireAlignedCheck_->setEnabled(false);
        requireAlignedCheck_->setToolTip(QStringLiteral("所有访问层都由 R0 强制按逻辑扇区对齐，界面不能关闭此保护"));

        toolbarLayout_->addWidget(new QLabel(QStringLiteral("磁盘"), toolbarWidget_), 0);
        toolbarLayout_->addWidget(diskCombo_, 2);
        toolbarLayout_->addWidget(new QLabel(QStringLiteral("访问层"), toolbarWidget_), 0);
        toolbarLayout_->addWidget(backendCombo_, 0);
        toolbarLayout_->addWidget(refreshButton_, 0);
        toolbarLayout_->addWidget(new QLabel(QStringLiteral("偏移"), toolbarWidget_), 0);
        toolbarLayout_->addWidget(offsetEdit_, 1);
        toolbarLayout_->addWidget(new QLabel(QStringLiteral("长度"), toolbarWidget_), 0);
        toolbarLayout_->addWidget(lengthSpin_, 0);
        toolbarLayout_->addWidget(partitionStartButton_, 0);
        toolbarLayout_->addWidget(readButton_, 0);
        toolbarLayout_->addWidget(readOnlyCheck_, 0);
        toolbarLayout_->addWidget(requireAlignedCheck_, 0);
        toolbarLayout_->addWidget(writeButton_, 0);
    }

    void DiskEditorTab::initializeLayoutPanels()
    {
        mainSplitter_ = new QSplitter(Qt::Horizontal, this);
        rootLayout_->addWidget(mainSplitter_, 1);

        QWidget* leftPanel = new QWidget(mainSplitter_);
        QVBoxLayout* leftLayout = new QVBoxLayout(leftPanel);
        leftLayout->setContentsMargins(0, 0, 0, 0);
        leftLayout->setSpacing(6);

        diskMapWidget_ = new DiskMapWidget(leftPanel);
        leftLayout->addWidget(diskMapWidget_, 0);

        partitionTable_ = new ks::ui::VisibleTableWidget(leftPanel);
        partitionTable_->setColumnCount(7);
        partitionTable_->setHorizontalHeaderLabels({
            QStringLiteral("#"),
            QStringLiteral("名称"),
            QStringLiteral("类型"),
            QStringLiteral("卷/盘符"),
            QStringLiteral("起始偏移"),
            QStringLiteral("容量"),
            QStringLiteral("标记")
            });
        partitionTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
        partitionTable_->setSelectionMode(QAbstractItemView::SingleSelection);
        partitionTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
        partitionTable_->setAlternatingRowColors(true);
        partitionTable_->verticalHeader()->setVisible(false);
        partitionTable_->horizontalHeader()->setStretchLastSection(true);
        partitionTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
        partitionTable_->setStyleSheet(buildTableStyle());
        installDiskEditorTableCopyMenu(partitionTable_);
        leftLayout->addWidget(partitionTable_, 0);

        hexEditor_ = new HexEditorWidget(leftPanel);
        hexEditor_->setEditable(false);
        hexEditor_->setBytesPerRow(16);
        leftLayout->addWidget(hexEditor_, 1);

        advancedTabs_ = new QTabWidget(leftPanel);
        advancedTabs_->setDocumentMode(true);
        initializeAdvancedPanels(advancedTabs_);
        leftLayout->addWidget(advancedTabs_, 1);

        QWidget* rightPanel = new QWidget(mainSplitter_);
        QVBoxLayout* rightLayout = new QVBoxLayout(rightPanel);
        rightLayout->setContentsMargins(0, 0, 0, 0);
        rightLayout->setSpacing(6);

        QGroupBox* diskSummaryGroup = new QGroupBox(QStringLiteral("磁盘摘要"), rightPanel);
        diskSummaryGroup->setStyleSheet(buildInfoCardStyle());
        QVBoxLayout* diskSummaryLayout = new QVBoxLayout(diskSummaryGroup);
        diskSummaryLabel_ = new QLabel(QStringLiteral("等待磁盘枚举..."), diskSummaryGroup);
        diskSummaryLabel_->setWordWrap(true);
        diskSummaryLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
        diskSummaryLayout->addWidget(diskSummaryLabel_);
        rightLayout->addWidget(diskSummaryGroup, 0);

        QGroupBox* partitionDetailGroup = new QGroupBox(QStringLiteral("分区详情"), rightPanel);
        partitionDetailGroup->setStyleSheet(buildInfoCardStyle());
        QVBoxLayout* partitionDetailLayout = new QVBoxLayout(partitionDetailGroup);
        partitionDetailLabel_ = new QLabel(QStringLiteral("尚未选择分区。"), partitionDetailGroup);
        partitionDetailLabel_->setWordWrap(true);
        partitionDetailLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
        partitionDetailLayout->addWidget(partitionDetailLabel_);
        rightLayout->addWidget(partitionDetailGroup, 0);

        QGroupBox* logGroup = new QGroupBox(QStringLiteral("操作日志"), rightPanel);
        logGroup->setStyleSheet(buildInfoCardStyle());
        QVBoxLayout* logLayout = new QVBoxLayout(logGroup);
        logEdit_ = new QPlainTextEdit(logGroup);
        logEdit_->setReadOnly(true);
        logEdit_->setStyleSheet(
            QStringLiteral("QPlainTextEdit{border:none;background:%1;color:%2;}")
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::textPrimaryHex()));
        logLayout->addWidget(logEdit_, 1);
        rightLayout->addWidget(logGroup, 1);

        mainSplitter_->addWidget(leftPanel);
        mainSplitter_->addWidget(rightPanel);
        mainSplitter_->setStretchFactor(0, 4);
        mainSplitter_->setStretchFactor(1, 1);
        mainSplitter_->setSizes({ 980, 300 });
    }

    void DiskEditorTab::initializeAdvancedPanels(QWidget* parent)
    {
        // The Advanced tab maintains read-only analysis and tool operations separately to reduce the risk of accidental disk writes.
        QWidget* structurePage = new QWidget(parent);
        QVBoxLayout* structureLayout = new QVBoxLayout(structurePage);
        structureLayout->setContentsMargins(4, 4, 4, 4);
        structureLayout->setSpacing(6);

        QHBoxLayout* structureToolbar = new QHBoxLayout();
        analyzeButton_ = new QPushButton(QStringLiteral("刷新结构解析"), structurePage);
        analyzeButton_->setIcon(QIcon(QStringLiteral(":/Icon/disk_analyze.svg")));
        analyzeButton_->setStyleSheet(buildToolButtonStyle());
        structureToolbar->addWidget(analyzeButton_, 0);
        structureToolbar->addWidget(new QLabel(QStringLiteral("解析 MBR/GPT/启动扇区，校验 CRC，并映射卷/盘符。"), structurePage), 1);
        structureLayout->addLayout(structureToolbar);

        structureTable_ = createReadOnlyTable(structurePage, {
            QStringLiteral("分组"),
            QStringLiteral("字段"),
            QStringLiteral("值"),
            QStringLiteral("偏移"),
            QStringLiteral("长度"),
            QStringLiteral("等级"),
            QStringLiteral("说明")
            });
        structureLayout->addWidget(structureTable_, 1);
        advancedTabs_->addTab(structurePage, QIcon(QStringLiteral(":/Icon/disk_analyze.svg")), QStringLiteral("结构解析"));

        QWidget* volumePage = new QWidget(parent);
        QVBoxLayout* volumeLayout = new QVBoxLayout(volumePage);
        volumeLayout->setContentsMargins(4, 4, 4, 4);
        volumeTable_ = createReadOnlyTable(volumePage, {
            QStringLiteral("卷"),
            QStringLiteral("盘符/挂载点"),
            QStringLiteral("设备路径"),
            QStringLiteral("文件系统"),
            QStringLiteral("卷标"),
            QStringLiteral("起始偏移"),
            QStringLiteral("长度")
            });
        volumeLayout->addWidget(volumeTable_, 1);
        advancedTabs_->addTab(volumePage, QIcon(QStringLiteral(":/Icon/disk_volume.svg")), QStringLiteral("卷映射"));

        QWidget* healthPage = new QWidget(parent);
        QVBoxLayout* healthLayout = new QVBoxLayout(healthPage);
        healthLayout->setContentsMargins(4, 4, 4, 4);
        healthTable_ = createReadOnlyTable(healthPage, {
            QStringLiteral("类别"),
            QStringLiteral("项目"),
            QStringLiteral("值"),
            QStringLiteral("等级"),
            QStringLiteral("说明")
            });
        healthLayout->addWidget(healthTable_, 1);
        advancedTabs_->addTab(healthPage, QIcon(QStringLiteral(":/Icon/disk_health.svg")), QStringLiteral("健康/能力"));

        auto* fileSystemForensicsPanel = new DiskFileSystemForensicsPanel(
            [this]() -> std::optional<DiskForensicsSelection>
            {
                const DiskDeviceInfo* disk = currentDisk();
                const DiskPartitionInfo* partition = currentPartition();
                if (disk == nullptr
                    || partition == nullptr
                    || partition->lengthBytes == 0U
                    || partition->kind == DiskPartitionKind::kUnallocated)
                {
                    return std::nullopt;
                }
                DiskForensicsSelection selection;
                selection.diskIndex = disk->diskIndex;
                selection.backend = currentRawBackend();
                selection.partitionOffset = partition->offsetBytes;
                selection.partitionLength = partition->lengthBytes;
                selection.logicalSectorSize = disk->bytesPerSector;
                selection.backendMask = disk->rawBackendMask;
                selection.capabilityFlags = disk->rawCapabilityFlags;
                selection.displayText = QStringLiteral("%1 / %2")
                    .arg(disk->devicePath)
                    .arg(partition->name);
                return selection;
            },
            [this](const std::uint64_t absoluteOffset)
            {
                offsetEdit_->setText(hexOffsetText(absoluteOffset));
                readCurrentRangeAsync(QStringLiteral("文件系统取证跳转读取"));
            },
            parent);
        advancedTabs_->addTab(
            fileSystemForensicsPanel,
            QIcon(QStringLiteral(":/Icon/disk_volume.svg")),
            QStringLiteral("文件系统取证"));

        QWidget* toolPage = new QWidget(parent);
        QVBoxLayout* toolLayout = new QVBoxLayout(toolPage);
        toolLayout->setContentsMargins(4, 4, 4, 4);
        toolLayout->setSpacing(6);

        QGroupBox* rangeGroup = new QGroupBox(QStringLiteral("范围与文件"), toolPage);
        rangeGroup->setStyleSheet(buildInfoCardStyle());
        QGridLayout* rangeLayout = new QGridLayout(rangeGroup);
        toolOffsetEdit_ = new QLineEdit(rangeGroup);
        toolOffsetEdit_->setText(QStringLiteral("0x0000000000000000"));
        toolOffsetEdit_->setStyleSheet(buildInputStyle());
        toolLengthEdit_ = new QLineEdit(rangeGroup);
        toolLengthEdit_->setText(QStringLiteral("0x100000"));
        toolLengthEdit_->setStyleSheet(buildInputStyle());
        toolFileEdit_ = new QLineEdit(rangeGroup);
        toolFileEdit_->setPlaceholderText(QStringLiteral("镜像导出/导入/对比文件路径"));
        toolFileEdit_->setStyleSheet(buildInputStyle());
        toolUseSelectionButton_ = new QPushButton(QStringLiteral("填入当前范围"), rangeGroup);
        toolUsePartitionButton_ = new QPushButton(QStringLiteral("填入所选分区"), rangeGroup);
        toolUseSelectionButton_->setToolTip(QStringLiteral("用当前读取/选中的范围填入下方工具的偏移和长度"));
        toolUsePartitionButton_->setToolTip(QStringLiteral("用当前所选分区的范围填入下方工具的偏移和长度"));
        toolBrowseOpenButton_ = new QPushButton(QStringLiteral("选择输入文件…"), rangeGroup);
        toolBrowseSaveButton_ = new QPushButton(QStringLiteral("选择保存位置…"), rangeGroup);
        for (QPushButton* button : { toolUseSelectionButton_, toolUsePartitionButton_, toolBrowseOpenButton_, toolBrowseSaveButton_ })
        {
            button->setStyleSheet(buildToolButtonStyle());
        }
        rangeLayout->addWidget(new QLabel(QStringLiteral("偏移"), rangeGroup), 0, 0);
        rangeLayout->addWidget(toolOffsetEdit_, 0, 1);
        rangeLayout->addWidget(new QLabel(QStringLiteral("长度"), rangeGroup), 0, 2);
        rangeLayout->addWidget(toolLengthEdit_, 0, 3);
        rangeLayout->addWidget(toolUseSelectionButton_, 0, 4);
        rangeLayout->addWidget(toolUsePartitionButton_, 0, 5);
        rangeLayout->addWidget(new QLabel(QStringLiteral("文件"), rangeGroup), 1, 0);
        rangeLayout->addWidget(toolFileEdit_, 1, 1, 1, 3);
        rangeLayout->addWidget(toolBrowseOpenButton_, 1, 4);
        rangeLayout->addWidget(toolBrowseSaveButton_, 1, 5);
        toolLayout->addWidget(rangeGroup, 0);

        QGroupBox* actionGroup = new QGroupBox(QStringLiteral("范围操作"), toolPage);
        actionGroup->setStyleSheet(buildInfoCardStyle());
        QGridLayout* actionLayout = new QGridLayout(actionGroup);
        searchPatternEdit_ = new QLineEdit(actionGroup);
        searchPatternEdit_->setPlaceholderText(QStringLiteral("搜索：AA BB ?? 或 ASCII/UTF-16 文本"));
        searchPatternEdit_->setStyleSheet(buildInputStyle());
        searchModeCombo_ = new QComboBox(actionGroup);
        searchModeCombo_->addItem(QStringLiteral("HEX 字节/??通配"), static_cast<int>(DiskSearchPatternMode::kHexBytes));
        searchModeCombo_->addItem(QStringLiteral("ASCII 文本"), static_cast<int>(DiskSearchPatternMode::kAsciiText));
        searchModeCombo_->addItem(QStringLiteral("UTF-16 文本"), static_cast<int>(DiskSearchPatternMode::kUtf16Text));
        searchModeCombo_->setStyleSheet(buildInputStyle());
        hashAlgorithmCombo_ = new QComboBox(actionGroup);
        hashAlgorithmCombo_->addItem(QStringLiteral("SHA-256"), static_cast<int>(QCryptographicHash::Sha256));
        hashAlgorithmCombo_->addItem(QStringLiteral("SHA-1"), static_cast<int>(QCryptographicHash::Sha1));
        hashAlgorithmCombo_->addItem(QStringLiteral("MD5"), static_cast<int>(QCryptographicHash::Md5));
        hashAlgorithmCombo_->setStyleSheet(buildInputStyle());
        maxResultSpin_ = new QSpinBox(actionGroup);
        maxResultSpin_->setRange(1, 10000);
        maxResultSpin_->setValue(512);
        maxResultSpin_->setStyleSheet(buildInputStyle());
        scanBlockSpin_ = new QSpinBox(actionGroup);
        scanBlockSpin_->setRange(512, 8 * 1024 * 1024);
        scanBlockSpin_->setSingleStep(4096);
        scanBlockSpin_->setValue(1024 * 1024);
        scanBlockSpin_->setSuffix(QStringLiteral(" B"));
        scanBlockSpin_->setStyleSheet(buildInputStyle());
        searchButton_ = new QPushButton(QStringLiteral("搜索"), actionGroup);
        hashButton_ = new QPushButton(QStringLiteral("计算哈希"), actionGroup);
        exportButton_ = new QPushButton(QStringLiteral("导出镜像"), actionGroup);
        importButton_ = new QPushButton(QStringLiteral("导入写盘"), actionGroup);
        compareButton_ = new QPushButton(QStringLiteral("对比文件"), actionGroup);
        scanButton_ = new QPushButton(QStringLiteral("坏道扫描"), actionGroup);
        hashButton_->setToolTip(QStringLiteral("计算所选磁盘区间的哈希值，用于校验数据一致性"));
        importButton_->setToolTip(QStringLiteral("把外部文件的内容写入磁盘指定位置（会覆盖原有数据，操作危险）"));
        scanButton_->setToolTip(QStringLiteral("按块顺序读取所选磁盘范围，检测可读性与坏道"));
        maxResultSpin_->setToolTip(QStringLiteral("搜索结果最多保留的条数，超出后停止记录"));
        scanBlockSpin_->setToolTip(QStringLiteral("每次读取的块大小；块越大速度越快，定位坏道的位置越粗"));
        for (QPushButton* button : { searchButton_, hashButton_, exportButton_, importButton_, compareButton_, scanButton_ })
        {
            button->setStyleSheet(buildToolButtonStyle());
        }
        importButton_->setIcon(QIcon(QStringLiteral(":/Icon/disk_warning.svg")));
        actionLayout->addWidget(new QLabel(QStringLiteral("搜索"), actionGroup), 0, 0);
        actionLayout->addWidget(searchPatternEdit_, 0, 1, 1, 3);
        actionLayout->addWidget(searchModeCombo_, 0, 4);
        actionLayout->addWidget(searchButton_, 0, 5);
        actionLayout->addWidget(new QLabel(QStringLiteral("哈希"), actionGroup), 1, 0);
        actionLayout->addWidget(hashAlgorithmCombo_, 1, 1);
        actionLayout->addWidget(hashButton_, 1, 2);
        actionLayout->addWidget(exportButton_, 1, 3);
        actionLayout->addWidget(compareButton_, 1, 4);
        actionLayout->addWidget(importButton_, 1, 5);
        actionLayout->addWidget(new QLabel(QStringLiteral("结果上限/块大小"), actionGroup), 2, 0);
        actionLayout->addWidget(maxResultSpin_, 2, 1);
        actionLayout->addWidget(scanBlockSpin_, 2, 2);
        actionLayout->addWidget(scanButton_, 2, 3);
        toolLayout->addWidget(actionGroup, 0);

        searchResultTable_ = createReadOnlyTable(toolPage, {
            QStringLiteral("#"),
            QStringLiteral("命中偏移"),
            QStringLiteral("预览 HEX")
            });
        toolLayout->addWidget(searchResultTable_, 1);
        advancedTabs_->addTab(toolPage, QIcon(QStringLiteral(":/Icon/disk_tools.svg")), QStringLiteral("搜索/镜像/扫描"));

    }

    void DiskEditorTab::initializeConnections()
    {
        connect(refreshButton_, &QPushButton::clicked, this, [this]()
        {
            refreshDiskListAsync(true);
        });

        connect(diskCombo_, &QComboBox::currentIndexChanged, this, [this](const int index)
        {
            Q_UNUSED(index);
            updateDirtyState(false);
            structureReport_ = DiskStructureReport{};
            updateDiskSummary();
            rebuildRawBackendSelector();
            rebuildPartitionTable();
            rebuildStructureTable();
            rebuildVolumeTable();
            rebuildHealthTable();
            const DiskDeviceInfo* disk = currentDisk();
            if (disk != nullptr)
            {
                diskMapWidget_->setDisk(*disk);
                if (!disk->partitions.empty())
                {
                    diskMapWidget_->setSelectedPartitionIndex(disk->partitions.front().tableIndex);
                }
                appendLog(QStringLiteral("切换到 %1。").arg(disk->devicePath));
                refreshStructureReportAsync(QStringLiteral("切换磁盘自动解析"));
            }
            else
            {
                diskMapWidget_->clearDisk();
            }
        });

        connect(diskMapWidget_, &DiskMapWidget::partitionActivated, this, [this](const int partitionIndex)
        {
            syncPartitionSelection(partitionIndex, true);
        });

        connect(partitionTable_, &QTableWidget::currentCellChanged, this,
            [this](const int currentRow, const int currentColumn, const int previousRow, const int previousColumn)
        {
            Q_UNUSED(currentColumn);
            Q_UNUSED(previousRow);
            Q_UNUSED(previousColumn);
            if (currentRow < 0)
            {
                return;
            }
            QTableWidgetItem* item = partitionTable_->item(currentRow, kPartitionColumnNumber);
            if (item == nullptr)
            {
                return;
            }
            syncPartitionSelection(item->data(Qt::UserRole).toInt(), false);
        });

        connect(partitionStartButton_, &QPushButton::clicked, this, [this]()
        {
            const DiskPartitionInfo* partition = currentPartition();
            if (partition == nullptr)
            {
                appendLog(QStringLiteral("未选择分区，无法跳转到分区起点。"));
                return;
            }
            offsetEdit_->setText(hexOffsetText(partition->offsetBytes));
            readCurrentRangeAsync(QStringLiteral("读取当前分区起点"));
        });

        connect(readButton_, &QPushButton::clicked, this, [this]()
        {
            readCurrentRangeAsync(QStringLiteral("手动读取"));
        });

        connect(backendCombo_, &QComboBox::currentIndexChanged, this, [this](const int index)
        {
            Q_UNUSED(index);
            appendLog(QStringLiteral("磁盘访问层切换为：%1。")
                .arg(backendCombo_->currentText()));
        });

        connect(writeButton_, &QPushButton::clicked, this, [this]()
        {
            writeCurrentBuffer();
        });

        connect(readOnlyCheck_, &QCheckBox::toggled, this, [this](const bool checked)
        {
            if (hexEditor_ != nullptr)
            {
                hexEditor_->setEditable(!checked);
            }
            if (writeButton_ != nullptr)
            {
                writeButton_->setEnabled(!checked && !busy_ && !loadedBytes_.isEmpty());
            }
            if (importButton_ != nullptr)
            {
                importButton_->setEnabled(!checked && !busy_);
            }
            appendLog(checked
                ? QStringLiteral("只读保护已开启，HEX 编辑和写回被禁用。")
                : QStringLiteral("只读保护已关闭，允许编辑当前缓冲；写盘仍需要二次确认。"));
        });

        connect(hexEditor_, &HexEditorWidget::byteEdited, this,
            [this](const std::uint64_t absoluteAddress, const std::uint8_t oldValue, const std::uint8_t newValue)
        {
            updateDirtyState(true);
            appendLog(QStringLiteral("编辑字节 %1: %2 -> %3")
                .arg(hexOffsetText(absoluteAddress))
                .arg(oldValue, 2, 16, QChar('0'))
                .arg(newValue, 2, 16, QChar('0'))
                .toUpper());
        });

        connect(analyzeButton_, &QPushButton::clicked, this, [this]()
        {
            refreshStructureReportAsync(QStringLiteral("手动刷新结构解析"));
        });

        connect(structureTable_, &QTableWidget::cellDoubleClicked, this,
            [this](const int row, const int column)
        {
            Q_UNUSED(column);
            QTableWidgetItem* item = structureTable_->item(row, kStructureColumnOffset);
            if (item == nullptr)
            {
                return;
            }
            const std::uint64_t kOffset = item->data(Qt::UserRole).toULongLong();
            offsetEdit_->setText(hexOffsetText(kOffset));
            readCurrentRangeAsync(QStringLiteral("结构字段跳转读取"));
        });

        connect(volumeTable_, &QTableWidget::cellDoubleClicked, this,
            [this](const int row, const int column)
        {
            Q_UNUSED(column);
            QTableWidgetItem* item = volumeTable_->item(row, 5);
            if (item == nullptr)
            {
                return;
            }
            const std::uint64_t kOffset = item->data(Qt::UserRole).toULongLong();
            offsetEdit_->setText(hexOffsetText(kOffset));
            readCurrentRangeAsync(QStringLiteral("卷映射跳转读取"));
        });

        connect(searchResultTable_, &QTableWidget::cellDoubleClicked, this,
            [this](const int row, const int column)
        {
            Q_UNUSED(column);
            QTableWidgetItem* item = searchResultTable_->item(row, kSearchColumnOffset);
            if (item == nullptr)
            {
                return;
            }
            const std::uint64_t kOffset = item->data(Qt::UserRole).toULongLong();
            offsetEdit_->setText(hexOffsetText(kOffset));
            readCurrentRangeAsync(QStringLiteral("搜索结果跳转读取"));
        });

        connect(toolUseSelectionButton_, &QPushButton::clicked, this, [this]()
        {
            updateToolRangeFromSelection(false);
        });

        connect(toolUsePartitionButton_, &QPushButton::clicked, this, [this]()
        {
            updateToolRangeFromSelection(true);
        });

        connect(toolBrowseOpenButton_, &QPushButton::clicked, this, [this]()
        {
            browseToolFile(false);
        });

        connect(toolBrowseSaveButton_, &QPushButton::clicked, this, [this]()
        {
            browseToolFile(true);
        });

        connect(searchButton_, &QPushButton::clicked, this, [this]()
        {
            runSearchAsync();
        });

        connect(hashButton_, &QPushButton::clicked, this, [this]()
        {
            runHashAsync();
        });

        connect(exportButton_, &QPushButton::clicked, this, [this]()
        {
            runExportAsync();
        });

        connect(importButton_, &QPushButton::clicked, this, [this]()
        {
            runImportAsync();
        });

        connect(compareButton_, &QPushButton::clicked, this, [this]()
        {
            runCompareAsync();
        });

        connect(scanButton_, &QPushButton::clicked, this, [this]()
        {
            runScanAsync();
        });
    }

    void DiskEditorTab::refreshDiskListAsync(const bool forceRefresh)
    {
        if (busy_)
        {
            appendLog(QStringLiteral("当前已有后台任务，刷新请求被忽略。"));
            return;
        }

        busy_ = true;
        setControlsEnabledForBusy(true);
        if (statusLabel_ != nullptr)
        {
            statusLabel_->setText(forceRefresh ? QStringLiteral("状态：正在刷新磁盘列表...") : QStringLiteral("状态：正在枚举磁盘..."));
        }

        QPointer<DiskEditorTab> safeThis(this);
        std::thread([safeThis]()
        {
            std::vector<DiskDeviceInfo> disks;
            QString errorText;
            DiskEditorBackend::enumerateDisks(disks, errorText);

            if (safeThis.isNull())
            {
                return;
            }

            const bool kInvokeOk = QMetaObject::invokeMethod(
                safeThis.data(),
                [safeThis, disks = std::move(disks), errorText]() mutable
                {
                    if (safeThis.isNull())
                    {
                        return;
                    }
                    safeThis->applyDiskList(std::move(disks), errorText);
                },
                Qt::QueuedConnection);
            if (!kInvokeOk && !safeThis.isNull())
            {
                QMetaObject::invokeMethod(
                    safeThis.data(),
                    [safeThis]()
                    {
                        if (!safeThis.isNull())
                        {
                            safeThis->busy_ = false;
                            safeThis->setControlsEnabledForBusy(false);
                        }
                    },
                    Qt::QueuedConnection);
            }
        }).detach();
    }

    void DiskEditorTab::applyDiskList(std::vector<DiskDeviceInfo> disks, const QString& errorText)
    {
        const QList<QTableView*> kDiskEditorTables = {
            partitionTable_,
            structureTable_,
            volumeTable_,
            healthTable_
        };
        if (ks::ui::isTableUiCommitBlockedByContextMenu(kDiskEditorTables))
        {
            const QPointer<DiskEditorTab> kSafeThis(this);
            ks::ui::deferTableUiCommitIfContextMenuOpen(
                this,
                QStringLiteral("disk-editor-device-list-apply"),
                kDiskEditorTables,
                [kSafeThis, disks = std::move(disks), errorText]() mutable
                {
                    if (!kSafeThis.isNull())
                    {
                        kSafeThis->applyDiskList(
                            std::move(disks),
                            errorText);
                    }
                });
            return;
        }

        disks_ = std::move(disks);
        diskCombo_->blockSignals(true);
        diskCombo_->clear();
        for (int index = 0; index < static_cast<int>(disks_.size()); ++index)
        {
            const DiskDeviceInfo& disk = disks_[static_cast<std::size_t>(index)];
            diskCombo_->addItem(disk.displayName.isEmpty() ? disk.devicePath : disk.displayName, index);
        }
        diskCombo_->blockSignals(false);

        if (!disks_.empty())
        {
            diskCombo_->setCurrentIndex(0);
            updateDiskSummary();
            rebuildRawBackendSelector();
            rebuildPartitionTable();
            diskMapWidget_->setDisk(disks_.front());
            if (!disks_.front().partitions.empty())
            {
                diskMapWidget_->setSelectedPartitionIndex(disks_.front().partitions.front().tableIndex);
            }
            statusLabel_->setText(QStringLiteral("状态：已枚举 %1 个磁盘。").arg(static_cast<int>(disks_.size())));
            appendLog(QStringLiteral("磁盘枚举完成，共 %1 个条目。").arg(static_cast<int>(disks_.size())));
        }
        else
        {
            diskMapWidget_->clearDisk();
            partitionTable_->setRowCount(0);
            hexEditor_->clearData();
            structureReport_ = DiskStructureReport{};
            rebuildStructureTable();
            rebuildVolumeTable();
            rebuildHealthTable();
            (void)ks::ui::promptForPrivilegeFailure(this, QStringLiteral("枚举物理磁盘"), errorText);
            statusLabel_->setText(QStringLiteral("状态：磁盘枚举失败：%1").arg(errorText));
            appendLog(QStringLiteral("磁盘枚举失败：%1").arg(errorText));
        }

        busy_ = false;
        setControlsEnabledForBusy(false);

        if (!disks_.empty())
        {
            refreshStructureReportAsync(QStringLiteral("枚举完成自动解析"));
        }
    }

    const DiskDeviceInfo* DiskEditorTab::currentDisk() const
    {
        if (diskCombo_ == nullptr)
        {
            return nullptr;
        }
        if (!diskCombo_->currentData().isValid())
        {
            return nullptr;
        }
        const int kDiskVectorIndex = diskCombo_->currentData().toInt();
        if (kDiskVectorIndex < 0 || kDiskVectorIndex >= static_cast<int>(disks_.size()))
        {
            return nullptr;
        }
        return &disks_[static_cast<std::size_t>(kDiskVectorIndex)];
    }

    const DiskPartitionInfo* DiskEditorTab::currentPartition() const
    {
        const DiskDeviceInfo* disk = currentDisk();
        if (disk == nullptr || selectedPartitionIndex_ < 0)
        {
            return nullptr;
        }

        for (const DiskPartitionInfo& partition : disk->partitions)
        {
            if (partition.tableIndex == selectedPartitionIndex_)
            {
                return &partition;
            }
        }
        return nullptr;
    }

    void DiskEditorTab::rebuildRawBackendSelector()
    {
        if (backendCombo_ == nullptr)
        {
            return;
        }

        const QSignalBlocker kBlocker(backendCombo_);
        backendCombo_->clear();
        const DiskDeviceInfo* disk = currentDisk();
        const std::uint32_t kBackendMask = disk == nullptr ? 1U : disk->rawBackendMask;
        if ((kBackendMask & 0x1U) != 0U)
        {
            backendCombo_->addItem(
                QStringLiteral("Windows 存储栈"),
                static_cast<int>(KSWORD_ARK_RAW_DISK_BACKEND_WINDOWS_STACK));
        }
        if ((kBackendMask & 0x2U) != 0U)
        {
            backendCombo_->addItem(
                QStringLiteral("存储端口直达"),
                static_cast<int>(KSWORD_ARK_RAW_DISK_BACKEND_STORAGE_PORT));
        }
        if ((kBackendMask & 0x4U) != 0U)
        {
            backendCombo_->addItem(
                QStringLiteral("离线控制器直达"),
                static_cast<int>(KSWORD_ARK_RAW_DISK_BACKEND_CONTROLLER));
        }
        if (backendCombo_->count() == 0)
        {
            backendCombo_->addItem(
                QStringLiteral("Windows 存储栈"),
                static_cast<int>(KSWORD_ARK_RAW_DISK_BACKEND_WINDOWS_STACK));
        }
        backendCombo_->setCurrentIndex(0);
        if (disk != nullptr)
        {
            backendCombo_->setToolTip(disk->rawBackendDetail);
        }
    }

    unsigned long DiskEditorTab::currentRawBackend() const
    {
        if (backendCombo_ == nullptr
            || !backendCombo_->currentData().isValid())
        {
            return KSWORD_ARK_RAW_DISK_BACKEND_WINDOWS_STACK;
        }
        return static_cast<unsigned long>(
            backendCombo_->currentData().toULongLong());
    }

    void DiskEditorTab::updateDiskSummary()
    {
        const DiskDeviceInfo* disk = currentDisk();
        if (disk == nullptr)
        {
            diskSummaryLabel_->setText(QStringLiteral("未选择磁盘。"));
            return;
        }

        diskSummaryLabel_->setText(
            QStringLiteral(
                "设备：%1\n"
                "型号：%2\n"
                "厂商：%3\n"
                "序列号：%4\n"
                "总线：%5\n"
                "介质：%6\n"
                "容量：%7 (%8 字节)\n"
                "分区表：%9\n"
                "逻辑扇区：%10 B\n"
                "物理扇区：%11 B\n"
                "打开状态：%12\n"
                "访问层预检：%13")
            .arg(disk->devicePath)
            .arg(disk->model.isEmpty() ? QStringLiteral("<未知>") : disk->model)
            .arg(disk->vendor.isEmpty() ? QStringLiteral("<未知>") : disk->vendor)
            .arg(disk->serial.isEmpty() ? QStringLiteral("<未知>") : disk->serial)
            .arg(disk->busType.isEmpty() ? QStringLiteral("<未知>") : disk->busType)
            .arg(disk->mediaType.isEmpty() ? QStringLiteral("<未知>") : disk->mediaType)
            .arg(DiskEditorBackend::formatBytes(disk->sizeBytes))
            .arg(static_cast<qulonglong>(disk->sizeBytes))
            .arg(DiskEditorBackend::partitionStyleText(disk->partitionStyle))
            .arg(disk->bytesPerSector)
            .arg(disk->physicalBytesPerSector == 0 ? disk->bytesPerSector : disk->physicalBytesPerSector)
            .arg(disk->openErrorText.isEmpty() ? QStringLiteral("可读") : disk->openErrorText)
            .arg(disk->rawBackendDetail.isEmpty()
                ? QStringLiteral("未返回 R0 预检")
                : disk->rawBackendDetail));
    }

    void DiskEditorTab::rebuildPartitionTable()
    {
        const DiskDeviceInfo* disk = currentDisk();
        partitionTable_->setRowCount(0);
        selectedPartitionIndex_ = -1;
        partitionDetailLabel_->setText(QStringLiteral("尚未选择分区。"));

        if (disk == nullptr)
        {
            return;
        }

        partitionTable_->setRowCount(static_cast<int>(disk->partitions.size()));
        for (int row = 0; row < static_cast<int>(disk->partitions.size()); ++row)
        {
            const DiskPartitionInfo& partition = disk->partitions[static_cast<std::size_t>(row)];

            QTableWidgetItem* numberItem = makeReadOnlyItem(partition.partitionNumber == 0
                ? QStringLiteral("-")
                : QString::number(partition.partitionNumber));
            numberItem->setData(Qt::UserRole, partition.tableIndex);
            partitionTable_->setItem(row, kPartitionColumnNumber, numberItem);
            partitionTable_->setItem(row, kPartitionColumnName, makeReadOnlyItem(partition.name));
            partitionTable_->setItem(row, kPartitionColumnType, makeReadOnlyItem(partition.typeText));
            partitionTable_->setItem(row, kPartitionColumnVolume, makeReadOnlyItem(partition.volumeHint));
            partitionTable_->setItem(row, kPartitionColumnOffset, makeReadOnlyItem(hexOffsetText(partition.offsetBytes)));
            partitionTable_->setItem(row, kPartitionColumnLength, makeReadOnlyItem(DiskEditorBackend::formatBytes(partition.lengthBytes)));
            partitionTable_->setItem(row, kPartitionColumnFlags, makeReadOnlyItem(partition.flagsText));
        }

        partitionTable_->resizeColumnsToContents();
        if (!disk->partitions.empty())
        {
            syncPartitionSelection(disk->partitions.front().tableIndex, false);
        }
    }

    void DiskEditorTab::rebuildVolumeHints()
    {
        // Partition cache in m_disks is used for UI display; volume mapping only backfills the current disk.
        const int kDiskVectorIndex = (diskCombo_ == nullptr || !diskCombo_->currentData().isValid())
            ? -1
            : diskCombo_->currentData().toInt();
        if (kDiskVectorIndex < 0 || kDiskVectorIndex >= static_cast<int>(disks_.size()))
        {
            return;
        }

        DiskDeviceInfo& disk = disks_[static_cast<std::size_t>(kDiskVectorIndex)];
        const int kPreviousSelection = selectedPartitionIndex_;
        for (DiskPartitionInfo& partition : disk.partitions)
        {
            partition.volumeHint = findVolumeHintForPartition(partition, structureReport_.volumes);
        }

        rebuildPartitionTable();
        if (kPreviousSelection >= 0)
        {
            syncPartitionSelection(kPreviousSelection, false);
        }
    }

    void DiskEditorTab::syncPartitionSelection(const int partitionIndex, const bool focusHex)
    {
        const DiskDeviceInfo* disk = currentDisk();
        if (disk == nullptr)
        {
            return;
        }

        const DiskPartitionInfo* selected = nullptr;
        for (const DiskPartitionInfo& partition : disk->partitions)
        {
            if (partition.tableIndex == partitionIndex)
            {
                selected = &partition;
                break;
            }
        }
        if (selected == nullptr)
        {
            return;
        }

        selectedPartitionIndex_ = partitionIndex;
        diskMapWidget_->setSelectedPartitionIndex(partitionIndex);

        for (int row = 0; row < partitionTable_->rowCount(); ++row)
        {
            QTableWidgetItem* item = partitionTable_->item(row, kPartitionColumnNumber);
            if (item != nullptr && item->data(Qt::UserRole).toInt() == partitionIndex)
            {
                if (partitionTable_->currentRow() != row)
                {
                    QSignalBlocker tableSignalBlocker(partitionTable_);
                    partitionTable_->setCurrentCell(row, 0);
                }
                break;
            }
        }

        offsetEdit_->setText(hexOffsetText(selected->offsetBytes));
        partitionDetailLabel_->setText(
            QStringLiteral(
                "名称：%1\n"
                "类型：%2\n"
                "分区号：%3\n"
                "起始偏移：%4 (%5)\n"
                "长度：%6 (%7 字节)\n"
                "结束偏移：%8\n"
                "样式：%9\n"
                "唯一标识：%10\n"
                "卷提示：%11\n"
                "标记：%12")
            .arg(selected->name.isEmpty() ? QStringLiteral("<未命名>") : selected->name)
            .arg(selected->typeText.isEmpty() ? QStringLiteral("<未知>") : selected->typeText)
            .arg(selected->partitionNumber == 0 ? QStringLiteral("-") : QString::number(selected->partitionNumber))
            .arg(hexOffsetText(selected->offsetBytes))
            .arg(static_cast<qulonglong>(selected->offsetBytes))
            .arg(DiskEditorBackend::formatBytes(selected->lengthBytes))
            .arg(static_cast<qulonglong>(selected->lengthBytes))
            .arg(hexOffsetText(selected->offsetBytes + selected->lengthBytes))
            .arg(DiskEditorBackend::partitionStyleText(selected->style))
            .arg(selected->uniqueIdText.isEmpty() ? QStringLiteral("-") : selected->uniqueIdText)
            .arg(selected->volumeHint.isEmpty() ? QStringLiteral("-") : selected->volumeHint)
            .arg(selected->flagsText.isEmpty() ? QStringLiteral("-") : selected->flagsText));

        if (focusHex)
        {
            readCurrentRangeAsync(QStringLiteral("点击分区读取起点"));
        }
    }

    void DiskEditorTab::readCurrentRangeAsync(const QString& reasonText)
    {
        const DiskDeviceInfo* disk = currentDisk();
        if (disk == nullptr)
        {
            appendLog(QStringLiteral("读取失败：未选择磁盘。"));
            return;
        }
        if (busy_)
        {
            appendLog(QStringLiteral("读取请求被忽略：当前已有后台任务。"));
            return;
        }

        std::uint64_t offsetValue = 0;
        if (!parseAddressText(offsetEdit_->text(), offsetValue))
        {
            appendLog(QStringLiteral("读取失败：偏移格式无效。"));
            QMessageBox::warning(this, QStringLiteral("磁盘编辑"), QStringLiteral("偏移格式无效，请输入十进制或 0x 十六进制。"));
            return;
        }

        const std::uint32_t kBytesToRead = static_cast<std::uint32_t>(lengthSpin_->value());
        const QString kDevicePath = disk->devicePath;
        const int kDiskIndex = disk->diskIndex;
        const unsigned long kBackend = currentRawBackend();
        const QString kBackendText = backendCombo_ == nullptr
            ? QStringLiteral("Windows 存储栈")
            : backendCombo_->currentText();
        if (kBackend != KSWORD_ARK_RAW_DISK_BACKEND_WINDOWS_STACK
            && (disk->rawCapabilityFlags & KSWORD_ARK_RAW_DISK_CAP_SYSTEM_DISK) != 0U)
        {
            const QMessageBox::StandardButton kDecision = QMessageBox::warning(
                this,
                QStringLiteral("确认系统盘绕过读取"),
                QStringLiteral(
                    "当前目标是系统盘，所选“%1”会绕过部分上层存储对象。"
                    "异常硬件、过滤驱动或休眠状态可能导致系统不稳定。\n\n"
                    "本次只读取 %2 字节，不会写盘。是否继续？")
                    .arg(kBackendText)
                    .arg(kBytesToRead),
                QMessageBox::Yes | QMessageBox::No,
                QMessageBox::No);
            if (kDecision != QMessageBox::Yes)
            {
                appendLog(QStringLiteral("已取消系统盘绕过读取。"));
                return;
            }
        }
        busy_ = true;
        setControlsEnabledForBusy(true);
        statusLabel_->setText(QStringLiteral("状态：正在读取 %1 @ %2 ...")
            .arg(DiskEditorBackend::formatBytes(kBytesToRead))
            .arg(hexOffsetText(offsetValue)));
        appendLog(QStringLiteral("%1：%2 access=%3 offset=%4 length=%5")
            .arg(reasonText)
            .arg(kDevicePath)
            .arg(kBackendText)
            .arg(hexOffsetText(offsetValue))
            .arg(kBytesToRead));

        QPointer<DiskEditorTab> safeThis(this);
        std::thread([safeThis, kDiskIndex, kBackend, offsetValue, kBytesToRead]()
        {
            QByteArray bytes;
            QString errorText;
            DiskEditorBackend::readBytesWithBackend(
                kDiskIndex,
                kBackend,
                offsetValue,
                kBytesToRead,
                bytes,
                errorText);

            if (safeThis.isNull())
            {
                return;
            }

            const bool kInvokeOk = QMetaObject::invokeMethod(
                safeThis.data(),
                [safeThis, offsetValue, bytes, errorText]() mutable
                {
                    if (safeThis.isNull())
                    {
                        return;
                    }
                    safeThis->applyReadResult(offsetValue, bytes, errorText);
                },
                Qt::QueuedConnection);
            if (!kInvokeOk && !safeThis.isNull())
            {
                QMetaObject::invokeMethod(
                    safeThis.data(),
                    [safeThis]()
                    {
                        if (!safeThis.isNull())
                        {
                            safeThis->busy_ = false;
                            safeThis->setControlsEnabledForBusy(false);
                        }
                    },
                    Qt::QueuedConnection);
            }
        }).detach();
    }

    void DiskEditorTab::applyReadResult(
        const std::uint64_t baseOffset,
        const QByteArray& bytes,
        const QString& errorText)
    {
        if (!errorText.isEmpty())
        {
            // privilegePromptHandled: Marks whether the user has been informed about the failure during the privilege recovery path.
            const bool kPrivilegePromptHandled =
                ks::ui::promptForPrivilegeFailure(this, QStringLiteral("读取物理磁盘扇区"), errorText);
            statusLabel_->setText(QStringLiteral("状态：读取失败：%1").arg(errorText));
            appendLog(QStringLiteral("读取失败：%1").arg(errorText));
            if (!kPrivilegePromptHandled)
            {
                QMessageBox::warning(
                    this,
                    QStringLiteral("磁盘编辑"),
                    QStringLiteral("读取失败：%1").arg(errorText));
            }
        }
        else
        {
            loadedBaseOffset_ = baseOffset;
            loadedBytes_ = bytes;
            hexEditor_->setByteArray(bytes, baseOffset);
            hexEditor_->setEditable(!readOnlyCheck_->isChecked());
            updateDirtyState(false);
            statusLabel_->setText(QStringLiteral("状态：读取完成，%1 字节 @ %2。")
                .arg(bytes.size())
                .arg(hexOffsetText(baseOffset)));
            appendLog(QStringLiteral("读取完成：%1 字节 @ %2。").arg(bytes.size()).arg(hexOffsetText(baseOffset)));
        }

        busy_ = false;
        setControlsEnabledForBusy(false);
    }

    void DiskEditorTab::writeCurrentBuffer()
    {
        if (!ks::ui::isCurrentProcessElevated())
        {
            (void)ks::ui::requestAdministratorRestartForFeature(this, QStringLiteral("写入物理磁盘扇区"));
            return;
        }
        const DiskDeviceInfo* disk = currentDisk();
        if (disk == nullptr)
        {
            appendLog(QStringLiteral("写回失败：未选择磁盘。"));
            return;
        }
        if (readOnlyCheck_->isChecked())
        {
            QMessageBox::information(this, QStringLiteral("磁盘编辑"), QStringLiteral("只读保护已开启，请先关闭只读保护。"));
            return;
        }
        if (hexEditor_ == nullptr || hexEditor_->regionSize() == 0)
        {
            appendLog(QStringLiteral("写回失败：当前没有已读取缓冲。"));
            return;
        }

        const QByteArray kCurrentBytes = hexEditor_->data();
        const unsigned long kBackend = currentRawBackend();
        const QString kBackendText = backendCombo_ == nullptr
            ? QStringLiteral("Windows 存储栈")
            : backendCombo_->currentText();
        const bool kSystemDisk =
            (disk->rawCapabilityFlags & KSWORD_ARK_RAW_DISK_CAP_SYSTEM_DISK) != 0U;
        const bool kSuppressDangerousConfirmation =
            ks::settings::dangerousActionConfirmationsSuppressed();
        if (!kSuppressDangerousConfirmation)
        {
            const QMessageBox::StandardButton kRiskDecision = QMessageBox::warning(
                this,
                QStringLiteral("高风险：即将写入物理磁盘"),
                QStringLiteral(
                    "目标：%1\n访问层：%2\n偏移：%3\n长度：%4 字节\n\n"
                    "物理写入可能立即破坏分区表、文件系统或启动数据。"
                    "断电、控制器异常或选错磁盘都可能导致不可恢复的数据损坏。"
                    "%5\n\n是否继续？")
                    .arg(disk->devicePath)
                    .arg(kBackendText)
                    .arg(hexOffsetText(loadedBaseOffset_))
                    .arg(kCurrentBytes.size())
                    .arg(kSystemDisk
                        ? QStringLiteral("\n该磁盘包含当前启动或系统分区，风险等级为最高。")
                        : QString()),
                QMessageBox::Yes | QMessageBox::No,
                QMessageBox::No);
            if (kRiskDecision != QMessageBox::Yes)
            {
                appendLog(QStringLiteral("写回已取消：用户未通过风险预检。"));
                return;
            }

            // Final confirmation changed to direct click: no longer requires entering a confirmation phrase; defaults to focusing 'No' to prevent accidental triggers.
            const auto kConfirmDecision = QMessageBox::warning(
                this,
                QStringLiteral("确认写回物理磁盘"),
                QStringLiteral("该操作会通过“%1”直接写入 %2 @ %3，长度 %4 字节。%5\n\n确认写入？")
                    .arg(kBackendText)
                    .arg(disk->devicePath)
                    .arg(hexOffsetText(loadedBaseOffset_))
                    .arg(kCurrentBytes.size())
                    .arg(kSystemDisk
                        ? QStringLiteral("\n该磁盘包含当前启动或系统分区，写入可能导致系统无法启动。")
                        : QString()),
                QMessageBox::Yes | QMessageBox::No,
                QMessageBox::No);
            if (kConfirmDecision != QMessageBox::Yes)
            {
                appendLog(QStringLiteral("写回已取消：用户在最终确认中选择了否。"));
                return;
            }
        }
        else
        {
            appendLog(QStringLiteral(
                "高风险提示：重复危险确认已关闭；仍将执行驱动确认令牌、目标边界检查、FUA 和写入审计。"
                "物理磁盘写入可能造成永久数据损坏、无法启动、设备掉线或蓝屏。"));
        }

        QString errorText;
        unsigned long writeFlags =
            KSWORD_ARK_RAW_DISK_FLAG_UI_CONFIRMED_WRITE |
            KSWORD_ARK_RAW_DISK_FLAG_FUA;
        if (kSystemDisk)
        {
            writeFlags |= KSWORD_ARK_RAW_DISK_FLAG_ALLOW_SYSTEM_DISK_WRITE;
        }
        const bool kWriteOk = DiskEditorBackend::writeBytesWithBackend(
            disk->diskIndex,
            kBackend,
            loadedBaseOffset_,
            kCurrentBytes,
            writeFlags,
            errorText);
        if (!kWriteOk)
        {
            appendLog(QStringLiteral("写回失败：%1").arg(errorText));
            QMessageBox::critical(this, QStringLiteral("磁盘编辑"), QStringLiteral("写回失败：%1").arg(errorText));
            return;
        }

        loadedBytes_ = kCurrentBytes;
        updateDirtyState(false);
        appendLog(QStringLiteral("写回完成：访问层=%1，%2 字节 @ %3。")
            .arg(kBackendText)
            .arg(kCurrentBytes.size())
            .arg(hexOffsetText(loadedBaseOffset_)));
        QMessageBox::information(this, QStringLiteral("磁盘编辑"), QStringLiteral("写回完成。"));
        refreshStructureReportAsync(QStringLiteral("写回后刷新结构解析"));
    }

    void DiskEditorTab::refreshStructureReportAsync(const QString& reasonText)
    {
        const DiskDeviceInfo* disk = currentDisk();
        if (disk == nullptr)
        {
            appendLog(QStringLiteral("结构解析失败：未选择磁盘。"));
            return;
        }
        if (busy_)
        {
            appendLog(QStringLiteral("结构解析请求被忽略：当前已有后台任务。"));
            return;
        }

        const DiskDeviceInfo kDiskSnapshot = *disk;
        const unsigned long kBackend = currentRawBackend();
        const std::uint64_t kDiskLimit = kDiskSnapshot.sizeBytes == 0
            ? 16ULL * 1024ULL * 1024ULL
            : kDiskSnapshot.sizeBytes;
        const std::uint64_t kBytesToRead64 = std::min<std::uint64_t>(
            std::max<std::uint64_t>(1024ULL * 1024ULL, static_cast<std::uint64_t>(kDiskSnapshot.bytesPerSector) * 4096ULL),
            kDiskLimit);
        const std::uint32_t kBytesToRead = static_cast<std::uint32_t>(std::min<std::uint64_t>(
            kBytesToRead64,
            16ULL * 1024ULL * 1024ULL));

        busy_ = true;
        setControlsEnabledForBusy(true);
        statusLabel_->setText(QStringLiteral("状态：正在解析磁盘结构..."));
        appendLog(QStringLiteral("%1：读取前部 %2 用于结构解析。")
            .arg(reasonText)
            .arg(DiskEditorBackend::formatBytes(kBytesToRead)));

        QPointer<DiskEditorTab> safeThis(this);
        std::thread([safeThis, kDiskSnapshot, kBackend, kBytesToRead]()
        {
            QByteArray leadingBytes;
            QString readError;
            DiskEditorBackend::readBytesWithBackend(
                kDiskSnapshot.diskIndex,
                kBackend,
                0,
                kBytesToRead,
                leadingBytes,
                readError);

            DiskStructureReport report;
            QString parseError;
            if (readError.isEmpty())
            {
                report = DiskStructureParser::buildReport(kDiskSnapshot, leadingBytes, parseError);
            }
            else
            {
                parseError = readError;
            }

            if (safeThis.isNull())
            {
                return;
            }

            QMetaObject::invokeMethod(
                safeThis.data(),
                [safeThis, report = std::move(report), parseError]() mutable
                {
                    if (safeThis.isNull())
                    {
                        return;
                    }
                    safeThis->applyStructureReport(std::move(report), parseError);
                },
                Qt::QueuedConnection);
        }).detach();
    }

    void DiskEditorTab::applyStructureReport(DiskStructureReport report, const QString& errorText)
    {
        const QList<QTableView*> kStructureTables = {
            structureTable_,
            volumeTable_,
            healthTable_
        };
        if (ks::ui::isTableUiCommitBlockedByContextMenu(kStructureTables))
        {
            const QPointer<DiskEditorTab> kSafeThis(this);
            ks::ui::deferTableUiCommitIfContextMenuOpen(
                this,
                QStringLiteral("disk-editor-structure-report-apply"),
                kStructureTables,
                [kSafeThis, report = std::move(report), errorText]() mutable
                {
                    if (!kSafeThis.isNull())
                    {
                        kSafeThis->applyStructureReport(
                            std::move(report),
                            errorText);
                    }
                });
            return;
        }

        if (!errorText.isEmpty())
        {
            (void)ks::ui::promptForPrivilegeFailure(this, QStringLiteral("解析物理磁盘结构"), errorText);
            appendLog(QStringLiteral("结构解析失败：%1").arg(errorText));
            statusLabel_->setText(QStringLiteral("状态：结构解析失败：%1").arg(errorText));
        }
        else
        {
            structureReport_ = std::move(report);
            rebuildStructureTable();
            rebuildVolumeTable();
            rebuildHealthTable();
            rebuildVolumeHints();
            for (const QString& warning : structureReport_.warnings)
            {
                appendLog(QStringLiteral("结构解析提示：%1").arg(warning));
            }
            appendLog(QStringLiteral("结构解析完成：字段 %1，卷映射 %2，健康项 %3。")
                .arg(static_cast<int>(structureReport_.fields.size()))
                .arg(static_cast<int>(structureReport_.volumes.size()))
                .arg(static_cast<int>(structureReport_.healthItems.size())));
            statusLabel_->setText(QStringLiteral("状态：结构解析完成。"));
        }

        busy_ = false;
        setControlsEnabledForBusy(false);
    }

    void DiskEditorTab::rebuildStructureTable()
    {
        if (structureTable_ == nullptr)
        {
            return;
        }
        structureTable_->setRowCount(static_cast<int>(structureReport_.fields.size()));
        for (int row = 0; row < static_cast<int>(structureReport_.fields.size()); ++row)
        {
            const DiskStructureField& field = structureReport_.fields[static_cast<std::size_t>(row)];
            QTableWidgetItem* offsetItem = makeReadOnlyItem(hexOffsetText(field.offsetBytes));
            offsetItem->setData(Qt::UserRole, static_cast<qulonglong>(field.offsetBytes));
            structureTable_->setItem(row, kStructureColumnGroup, makeReadOnlyItem(field.group));
            structureTable_->setItem(row, kStructureColumnName, makeReadOnlyItem(field.name));
            structureTable_->setItem(row, kStructureColumnValue, makeReadOnlyItem(field.value));
            structureTable_->setItem(row, kStructureColumnOffset, offsetItem);
            structureTable_->setItem(row, kStructureColumnSize, makeReadOnlyItem(QString::number(field.sizeBytes)));
            structureTable_->setItem(row, kStructureColumnSeverity, makeReadOnlyItem(severityText(field.severity)));
            structureTable_->setItem(row, kStructureColumnDetail, makeReadOnlyItem(field.detail));
            for (int column = 0; column < structureTable_->columnCount(); ++column)
            {
                applySeverityToItem(structureTable_->item(row, column), field.severity);
            }
        }
        structureTable_->resizeColumnsToContents();
    }

    void DiskEditorTab::rebuildVolumeTable()
    {
        if (volumeTable_ == nullptr)
        {
            return;
        }
        volumeTable_->setRowCount(static_cast<int>(structureReport_.volumes.size()));
        for (int row = 0; row < static_cast<int>(structureReport_.volumes.size()); ++row)
        {
            const DiskVolumeInfo& volume = structureReport_.volumes[static_cast<std::size_t>(row)];
            QTableWidgetItem* offsetItem = makeReadOnlyItem(hexOffsetText(volume.offsetBytes));
            offsetItem->setData(Qt::UserRole, static_cast<qulonglong>(volume.offsetBytes));
            volumeTable_->setItem(row, 0, makeReadOnlyItem(volume.volumeName));
            volumeTable_->setItem(row, 1, makeReadOnlyItem(volume.mountPoints));
            volumeTable_->setItem(row, 2, makeReadOnlyItem(volume.devicePath));
            volumeTable_->setItem(row, 3, makeReadOnlyItem(volume.fileSystem));
            volumeTable_->setItem(row, 4, makeReadOnlyItem(volume.label));
            volumeTable_->setItem(row, 5, offsetItem);
            volumeTable_->setItem(row, 6, makeReadOnlyItem(DiskEditorBackend::formatBytes(volume.lengthBytes)));
        }
        volumeTable_->resizeColumnsToContents();
    }

    void DiskEditorTab::rebuildHealthTable()
    {
        if (healthTable_ == nullptr)
        {
            return;
        }
        healthTable_->setRowCount(static_cast<int>(structureReport_.healthItems.size()));
        for (int row = 0; row < static_cast<int>(structureReport_.healthItems.size()); ++row)
        {
            const DiskHealthItem& item = structureReport_.healthItems[static_cast<std::size_t>(row)];
            healthTable_->setItem(row, 0, makeReadOnlyItem(item.category));
            healthTable_->setItem(row, 1, makeReadOnlyItem(item.name));
            healthTable_->setItem(row, 2, makeReadOnlyItem(item.value));
            healthTable_->setItem(row, 3, makeReadOnlyItem(severityText(item.severity)));
            healthTable_->setItem(row, 4, makeReadOnlyItem(item.detail));
            for (int column = 0; column < healthTable_->columnCount(); ++column)
            {
                applySeverityToItem(healthTable_->item(row, column), item.severity);
            }
        }
        healthTable_->resizeColumnsToContents();
    }

    void DiskEditorTab::runSearchAsync()
    {
        const DiskDeviceInfo* disk = currentDisk();
        if (disk == nullptr)
        {
            appendLog(QStringLiteral("搜索失败：未选择磁盘。"));
            return;
        }
        if (busy_)
        {
            appendLog(QStringLiteral("搜索请求被忽略：当前已有后台任务。"));
            return;
        }

        std::uint64_t offset = 0;
        std::uint64_t length = 0;
        if (!parseToolRange(offset, length))
        {
            return;
        }
        if (searchPatternEdit_->text().trimmed().isEmpty())
        {
            QMessageBox::warning(this, QStringLiteral("磁盘搜索"), QStringLiteral("搜索模式为空。"));
            return;
        }

        const QString kDevicePath = disk->devicePath;
        const QString kPatternText = searchPatternEdit_->text();
        const auto kMode = static_cast<DiskSearchPatternMode>(searchModeCombo_->currentData().toInt());
        const int kMaxResults = maxResultSpin_->value();
        busy_ = true;
        setControlsEnabledForBusy(true);
        searchResultTable_->setRowCount(0);
        statusLabel_->setText(QStringLiteral("状态：正在搜索磁盘范围..."));
        appendLog(QStringLiteral("开始搜索：offset=%1 length=%2 pattern=%3")
            .arg(hexOffsetText(offset))
            .arg(DiskEditorBackend::formatBytes(length))
            .arg(kPatternText));

        QPointer<DiskEditorTab> safeThis(this);
        std::thread([safeThis, kDevicePath, offset, length, kPatternText, kMode, kMaxResults]()
        {
            DiskRangeTaskResult result = DiskRangeTools::searchRange(
                kDevicePath,
                offset,
                length,
                kPatternText,
                kMode,
                kMaxResults);
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
                        safeThis->applyRangeTaskResult(QStringLiteral("搜索"), std::move(result));
                    }
                },
                Qt::QueuedConnection);
        }).detach();
    }

    void DiskEditorTab::runHashAsync()
    {
        const DiskDeviceInfo* disk = currentDisk();
        if (disk == nullptr)
        {
            appendLog(QStringLiteral("哈希失败：未选择磁盘。"));
            return;
        }
        if (busy_)
        {
            appendLog(QStringLiteral("哈希请求被忽略：当前已有后台任务。"));
            return;
        }

        std::uint64_t offset = 0;
        std::uint64_t length = 0;
        if (!parseToolRange(offset, length))
        {
            return;
        }

        const QString kDevicePath = disk->devicePath;
        const auto kAlgorithm = static_cast<QCryptographicHash::Algorithm>(hashAlgorithmCombo_->currentData().toInt());
        busy_ = true;
        setControlsEnabledForBusy(true);
        statusLabel_->setText(QStringLiteral("状态：正在计算范围哈希..."));
        appendLog(QStringLiteral("开始哈希：offset=%1 length=%2 algorithm=%3")
            .arg(hexOffsetText(offset))
            .arg(DiskEditorBackend::formatBytes(length))
            .arg(hashAlgorithmCombo_->currentText()));

        QPointer<DiskEditorTab> safeThis(this);
        std::thread([safeThis, kDevicePath, offset, length, kAlgorithm]()
        {
            DiskRangeTaskResult result = DiskRangeTools::hashRange(kDevicePath, offset, length, kAlgorithm);
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
                        safeThis->applyRangeTaskResult(QStringLiteral("哈希"), std::move(result));
                    }
                },
                Qt::QueuedConnection);
        }).detach();
    }

    void DiskEditorTab::runExportAsync()
    {
        const DiskDeviceInfo* disk = currentDisk();
        if (disk == nullptr)
        {
            appendLog(QStringLiteral("导出失败：未选择磁盘。"));
            return;
        }
        if (busy_)
        {
            appendLog(QStringLiteral("导出请求被忽略：当前已有后台任务。"));
            return;
        }

        std::uint64_t offset = 0;
        std::uint64_t length = 0;
        if (!parseToolRange(offset, length))
        {
            return;
        }
        const QString kFilePath = toolFileEdit_->text().trimmed();
        if (kFilePath.isEmpty())
        {
            QMessageBox::warning(this, QStringLiteral("镜像导出"), QStringLiteral("请先选择导出文件路径。"));
            return;
        }

        const QString kDevicePath = disk->devicePath;
        busy_ = true;
        setControlsEnabledForBusy(true);
        statusLabel_->setText(QStringLiteral("状态：正在导出镜像片段..."));
        appendLog(QStringLiteral("开始导出：offset=%1 length=%2 file=%3")
            .arg(hexOffsetText(offset))
            .arg(DiskEditorBackend::formatBytes(length))
            .arg(kFilePath));

        QPointer<DiskEditorTab> safeThis(this);
        std::thread([safeThis, kDevicePath, offset, length, kFilePath]()
        {
            DiskRangeTaskResult result = DiskRangeTools::exportRangeToFile(kDevicePath, offset, length, kFilePath);
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
                        safeThis->applyRangeTaskResult(QStringLiteral("导出"), std::move(result));
                    }
                },
                Qt::QueuedConnection);
        }).detach();
    }

    void DiskEditorTab::runImportAsync()
    {
        const DiskDeviceInfo* disk = currentDisk();
        if (disk == nullptr)
        {
            appendLog(QStringLiteral("导入失败：未选择磁盘。"));
            return;
        }
        if (busy_)
        {
            appendLog(QStringLiteral("导入请求被忽略：当前已有后台任务。"));
            return;
        }
        if (readOnlyCheck_->isChecked())
        {
            QMessageBox::information(this, QStringLiteral("镜像导入"), QStringLiteral("只读保护已开启，请先关闭只读保护。"));
            return;
        }

        std::uint64_t offset = 0;
        std::uint64_t ignoredLength = 0;
        if (!parseToolRange(offset, ignoredLength))
        {
            return;
        }
        const QString kFilePath = toolFileEdit_->text().trimmed();
        if (kFilePath.isEmpty())
        {
            QMessageBox::warning(this, QStringLiteral("镜像导入"), QStringLiteral("请先选择导入文件。"));
            return;
        }

        if (!ks::settings::dangerousActionConfirmationsSuppressed())
        {
            // Confirmation changed to direct click: no longer requires entering a confirmation phrase; default focus is on 'No' to prevent accidental triggers.
            const auto kImportDecision = QMessageBox::warning(
                this,
                QStringLiteral("确认导入写盘"),
                QStringLiteral("该操作会把文件直接写入 %1 @ %2，覆盖原有数据且不可撤销。\n文件：%3\n\n确认写入？")
                    .arg(disk->devicePath)
                    .arg(hexOffsetText(offset))
                    .arg(kFilePath),
                QMessageBox::Yes | QMessageBox::No,
                QMessageBox::No);
            if (kImportDecision != QMessageBox::Yes)
            {
                appendLog(QStringLiteral("导入已取消：用户在确认中选择了否。"));
                return;
            }
        }
        else
        {
            appendLog(QStringLiteral(
                "高风险提示：重复危险确认已关闭；镜像导入仍可能破坏分区表、文件系统或启动数据。"));
        }

        const QString kDevicePath = disk->devicePath;
        const std::uint32_t kBytesPerSector = disk->bytesPerSector;
        const bool kRequireAligned = requireAlignedCheck_->isChecked();
        busy_ = true;
        setControlsEnabledForBusy(true);
        statusLabel_->setText(QStringLiteral("状态：正在导入文件到磁盘..."));
        appendLog(QStringLiteral("开始导入：offset=%1 file=%2").arg(hexOffsetText(offset), kFilePath));

        QPointer<DiskEditorTab> safeThis(this);
        std::thread([safeThis, kDevicePath, offset, kFilePath, kBytesPerSector, kRequireAligned]()
        {
            DiskRangeTaskResult result = DiskRangeTools::importFileToRange(
                kDevicePath,
                offset,
                kFilePath,
                kBytesPerSector,
                kRequireAligned);
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
                        safeThis->applyRangeTaskResult(QStringLiteral("导入"), std::move(result));
                    }
                },
                Qt::QueuedConnection);
        }).detach();
    }

    void DiskEditorTab::runCompareAsync()
    {
        const DiskDeviceInfo* disk = currentDisk();
        if (disk == nullptr)
        {
            appendLog(QStringLiteral("对比失败：未选择磁盘。"));
            return;
        }
        if (busy_)
        {
            appendLog(QStringLiteral("对比请求被忽略：当前已有后台任务。"));
            return;
        }

        std::uint64_t offset = 0;
        std::uint64_t length = 0;
        if (!parseToolRange(offset, length))
        {
            return;
        }
        const QString kFilePath = toolFileEdit_->text().trimmed();
        if (kFilePath.isEmpty())
        {
            QMessageBox::warning(this, QStringLiteral("文件对比"), QStringLiteral("请先选择对比文件。"));
            return;
        }

        const QString kDevicePath = disk->devicePath;
        const int kMaxDifferences = maxResultSpin_->value();
        busy_ = true;
        setControlsEnabledForBusy(true);
        statusLabel_->setText(QStringLiteral("状态：正在对比磁盘范围和文件..."));
        appendLog(QStringLiteral("开始对比：offset=%1 length=%2 file=%3")
            .arg(hexOffsetText(offset))
            .arg(DiskEditorBackend::formatBytes(length))
            .arg(kFilePath));

        QPointer<DiskEditorTab> safeThis(this);
        std::thread([safeThis, kDevicePath, offset, length, kFilePath, kMaxDifferences]()
        {
            DiskRangeTaskResult result = DiskRangeTools::compareRangeWithFile(
                kDevicePath,
                offset,
                length,
                kFilePath,
                kMaxDifferences);
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
                        safeThis->applyRangeTaskResult(QStringLiteral("对比"), std::move(result));
                    }
                },
                Qt::QueuedConnection);
        }).detach();
    }

    void DiskEditorTab::runScanAsync()
    {
        const DiskDeviceInfo* disk = currentDisk();
        if (disk == nullptr)
        {
            appendLog(QStringLiteral("坏道扫描失败：未选择磁盘。"));
            return;
        }
        if (busy_)
        {
            appendLog(QStringLiteral("坏道扫描请求被忽略：当前已有后台任务。"));
            return;
        }

        std::uint64_t offset = 0;
        std::uint64_t length = 0;
        if (!parseToolRange(offset, length))
        {
            return;
        }

        const QString kDevicePath = disk->devicePath;
        const std::uint32_t kBlockBytes = static_cast<std::uint32_t>(scanBlockSpin_->value());
        busy_ = true;
        setControlsEnabledForBusy(true);
        statusLabel_->setText(QStringLiteral("状态：正在坏道扫描..."));
        appendLog(QStringLiteral("开始坏道扫描：offset=%1 length=%2 block=%3")
            .arg(hexOffsetText(offset))
            .arg(DiskEditorBackend::formatBytes(length))
            .arg(kBlockBytes));

        QPointer<DiskEditorTab> safeThis(this);
        std::thread([safeThis, kDevicePath, offset, length, kBlockBytes]()
        {
            DiskRangeTaskResult result = DiskRangeTools::scanReadableBlocks(
                kDevicePath,
                offset,
                length,
                kBlockBytes);
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
                        safeThis->applyRangeTaskResult(QStringLiteral("坏道扫描"), std::move(result));
                    }
                },
                Qt::QueuedConnection);
        }).detach();
    }

    void DiskEditorTab::applyRangeTaskResult(const QString& taskName, DiskRangeTaskResult result)
    {
        if (taskName == QStringLiteral("搜索") &&
            ks::ui::isTableUiCommitBlockedByContextMenu({searchResultTable_}))
        {
            const QPointer<DiskEditorTab> kSafeThis(this);
            ks::ui::deferTableUiCommitIfContextMenuOpen(
                this,
                QStringLiteral("disk-editor-search-result-apply"),
                {searchResultTable_},
                [kSafeThis, taskName, result = std::move(result)]() mutable
                {
                    if (!kSafeThis.isNull())
                    {
                        kSafeThis->applyRangeTaskResult(
                            taskName,
                            std::move(result));
                    }
                });
            return;
        }

        if (!result.errorText.isEmpty())
        {
            // privilegePromptHandled: Prevents a conflicting old failure dialog from appearing immediately after the privilege prompt.
            const bool kPrivilegePromptHandled =
                ks::ui::promptForPrivilegeFailure(this, taskName, result.errorText);
            appendLog(QStringLiteral("%1失败：%2").arg(taskName, result.errorText));
            statusLabel_->setText(QStringLiteral("状态：%1失败：%2").arg(taskName, result.errorText));
            if (!kPrivilegePromptHandled)
            {
                QMessageBox::warning(
                    this,
                    QStringLiteral("磁盘工具"),
                    QStringLiteral("%1失败：%2").arg(taskName, result.errorText));
            }
        }
        else
        {
            appendLog(QStringLiteral("%1：%2").arg(taskName, result.summary));
            for (const QString& line : result.detailLines)
            {
                appendLog(QStringLiteral("%1明细：%2").arg(taskName, line));
            }
            statusLabel_->setText(QStringLiteral("状态：%1").arg(result.summary));
        }

        if (taskName == QStringLiteral("搜索") && searchResultTable_ != nullptr)
        {
            searchResultTable_->setRowCount(static_cast<int>(result.searchResults.size()));
            for (int row = 0; row < static_cast<int>(result.searchResults.size()); ++row)
            {
                const DiskSearchResult& hit = result.searchResults[static_cast<std::size_t>(row)];
                QTableWidgetItem* offsetItem = makeReadOnlyItem(hexOffsetText(hit.offsetBytes));
                offsetItem->setData(Qt::UserRole, static_cast<qulonglong>(hit.offsetBytes));
                searchResultTable_->setItem(row, kSearchColumnIndex, makeReadOnlyItem(QString::number(row + 1)));
                searchResultTable_->setItem(row, kSearchColumnOffset, offsetItem);
                searchResultTable_->setItem(row, kSearchColumnPreview, makeReadOnlyItem(bytesToPreviewText(hit.preview)));
            }
            searchResultTable_->resizeColumnsToContents();
        }

        if (taskName == QStringLiteral("导入") && result.success)
        {
            busy_ = false;
            setControlsEnabledForBusy(false);
            refreshStructureReportAsync(QStringLiteral("导入后刷新结构解析"));
            return;
        }

        busy_ = false;
        setControlsEnabledForBusy(false);
    }

    void DiskEditorTab::updateDirtyState(const bool dirty)
    {
        dirty_ = dirty;
        if (writeButton_ != nullptr)
        {
            writeButton_->setEnabled(!readOnlyCheck_->isChecked() && !busy_ && !loadedBytes_.isEmpty());
            writeButton_->setText(dirty_ ? QStringLiteral("写回*") : QStringLiteral("写回"));
            writeButton_->setIcon(QIcon(dirty_
                ? QStringLiteral(":/Icon/disk_warning.svg")
                : QStringLiteral(":/Icon/disk_save.svg")));
        }
    }

    void DiskEditorTab::appendLog(const QString& message)
    {
        if (logEdit_ == nullptr)
        {
            return;
        }
        const QString kLine = QStringLiteral("[%1] %2")
            .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss")))
            .arg(message);
        logEdit_->appendPlainText(kLine);
    }

    QString DiskEditorTab::severityText(const DiskStructureSeverity severity)
    {
        switch (severity)
        {
        case DiskStructureSeverity::kError: return QStringLiteral("错误");
        case DiskStructureSeverity::kWarning: return QStringLiteral("警告");
        case DiskStructureSeverity::kInfo: break;
        }
        return QStringLiteral("信息");
    }

    void DiskEditorTab::updateToolRangeFromSelection(const bool usePartitionRange)
    {
        if (usePartitionRange)
        {
            const DiskPartitionInfo* partition = currentPartition();
            if (partition == nullptr)
            {
                appendLog(QStringLiteral("无法同步工具范围：未选择分区。"));
                return;
            }
            toolOffsetEdit_->setText(hexOffsetText(partition->offsetBytes));
            toolLengthEdit_->setText(hexOffsetText(partition->lengthBytes));
            appendLog(QStringLiteral("工具范围已设置为当前分区：%1 + %2。")
                .arg(hexOffsetText(partition->offsetBytes))
                .arg(DiskEditorBackend::formatBytes(partition->lengthBytes)));
            return;
        }

        std::uint64_t offset = 0;
        if (!parseAddressText(offsetEdit_->text(), offset))
        {
            offset = loadedBaseOffset_;
        }
        toolOffsetEdit_->setText(hexOffsetText(offset));
        toolLengthEdit_->setText(hexOffsetText(static_cast<std::uint64_t>(lengthSpin_->value())));
        appendLog(QStringLiteral("工具范围已设置为当前读取范围。"));
    }

    void DiskEditorTab::browseToolFile(const bool saveMode)
    {
        const QString kFilePath = saveMode
            ? QFileDialog::getSaveFileName(this, QStringLiteral("选择镜像保存路径"), QString(), QStringLiteral("镜像文件 (*.bin *.img *.dd);;所有文件 (*.*)"))
            : QFileDialog::getOpenFileName(this, QStringLiteral("选择输入文件"), QString(), QStringLiteral("镜像/二进制文件 (*.bin *.img *.dd);;所有文件 (*.*)"));
        if (!kFilePath.isEmpty())
        {
            toolFileEdit_->setText(kFilePath);
        }
    }

    bool DiskEditorTab::parseToolRange(std::uint64_t& offsetOut, std::uint64_t& lengthOut) const
    {
        if (!parseAddressText(toolOffsetEdit_->text(), offsetOut))
        {
            QMessageBox::warning(const_cast<DiskEditorTab*>(this), QStringLiteral("磁盘工具"), QStringLiteral("工具偏移格式无效。"));
            return false;
        }
        if (!parseAddressText(toolLengthEdit_->text(), lengthOut))
        {
            QMessageBox::warning(const_cast<DiskEditorTab*>(this), QStringLiteral("磁盘工具"), QStringLiteral("工具长度格式无效。"));
            return false;
        }
        if (lengthOut == 0)
        {
            QMessageBox::warning(const_cast<DiskEditorTab*>(this), QStringLiteral("磁盘工具"), QStringLiteral("工具长度不能为 0。"));
            return false;
        }

        const DiskDeviceInfo* disk = currentDisk();
        if (disk != nullptr && disk->sizeBytes != 0)
        {
            if (offsetOut >= disk->sizeBytes)
            {
                QMessageBox::warning(const_cast<DiskEditorTab*>(this), QStringLiteral("磁盘工具"), QStringLiteral("工具偏移超出磁盘容量。"));
                return false;
            }
            const std::uint64_t kMaxLength = disk->sizeBytes - offsetOut;
            if (lengthOut > kMaxLength)
            {
                lengthOut = kMaxLength;
            }
        }
        return true;
    }

    bool DiskEditorTab::parseAddressText(const QString& text, std::uint64_t& valueOut)
    {
        // The default values and all backfilling for the three input fields on this page (offset, range start, range length) are
        // generated by hexOffsetText in the format 0x0000000000000000; the entire UI displays only hexadecimal. Therefore, when no
        // prefix is provided, the input must still be interpreted as hexadecimal: clearing and re-entering 100000 exactly as it
        // appears in the box would be read as decimal 0x186A0, causing the operation to target a different disk location. Since this
        // page **writes to disk**, misreading the location only shows wrong data, but writing to the wrong location destroys data.
        // Originally, this used the same 'try decimal first, then fall back to hexadecimal' logic as MemoryDock.
        // That fallback only applies to strings containing a–f; pure numeric strings never reach it.
        valueOut = 0ULL;
        const auto kParsed = ksword::evidence::parseNumericText(
            text.trimmed().toStdString(),
            ksword::evidence::NumericTextDefaultRadix::kHexadecimal);
        if (!kParsed.ok)
        {
            return false;
        }
        valueOut = kParsed.value;
        return true;
    }

    void DiskEditorTab::setControlsEnabledForBusy(const bool busy)
    {
        if (refreshButton_ != nullptr)
        {
            refreshButton_->setEnabled(!busy);
        }
        if (readButton_ != nullptr)
        {
            readButton_->setEnabled(!busy);
        }
        if (partitionStartButton_ != nullptr)
        {
            partitionStartButton_->setEnabled(!busy);
        }
        if (diskCombo_ != nullptr)
        {
            diskCombo_->setEnabled(!busy);
        }
        if (backendCombo_ != nullptr)
        {
            backendCombo_->setEnabled(!busy);
        }
        if (writeButton_ != nullptr)
        {
            writeButton_->setEnabled(!busy && !readOnlyCheck_->isChecked() && !loadedBytes_.isEmpty());
        }
        for (QPushButton* button : {
            analyzeButton_,
            toolUseSelectionButton_,
            toolUsePartitionButton_,
            toolBrowseOpenButton_,
            toolBrowseSaveButton_,
            searchButton_,
            hashButton_,
            exportButton_,
            importButton_,
            compareButton_,
            scanButton_ })
        {
            if (button != nullptr)
            {
                button->setEnabled(!busy);
            }
        }
        if (importButton_ != nullptr)
        {
            importButton_->setEnabled(!busy && !readOnlyCheck_->isChecked());
        }
    }
}
