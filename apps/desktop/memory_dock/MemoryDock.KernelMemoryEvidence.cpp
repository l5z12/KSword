#include "MemoryDock.Internal.h"
#include "../ui/TableInteractionSupport.h"
#include "../ui/VisibleTableWidget.h"
#include "../ui/DetailLayoutRegistry.h"
#include "../ui/TableColumnAutoFit.h"

#include <memory>

using namespace ksword::memory_dock_internal;

namespace
{
    enum class EvidenceColumn : int
    {
        kAddress = 0,
        kSize,
        kKind,
        kOwner,
        kPermissions,
        kRisk,
        kTextHash,
        kDetail,
        kCount
    };

    int evidenceColumnIndex(const EvidenceColumn column)
    {
        // Input: Kernel memory evidence column enumeration.
        // Processing: Convert to int column index used by Qt tables.
        // Returns: corresponding column index.
        return static_cast<int>(column);
    }

    QString wideToQString(const std::wstring& value)
    {
        // Input: Wide string returned by ArkDriverClient.
        // Processing: Convert to QString; empty strings remain empty.
        // Returns: Qt-displayable text.
        return value.empty() ? QString() : QString::fromStdWString(value);
    }

    QString memoryEvidenceIoMessageText(const std::string& messageText)
    {
        // Input: raw io.message returned by ArkDriverClient.
        // Handling: Converts low-level strings such as DeviceIoControl/unsupported/empty messages into user-readable descriptions.
        // Returns: Chinese text suitable for the status bar and details area.
        if (messageText.empty())
        {
            return QStringLiteral("无额外驱动消息");
        }

        const QString kRawText = QString::fromStdString(messageText).trimmed();
        if (kRawText.isEmpty())
        {
            return QStringLiteral("无额外驱动消息");
        }
        if (kRawText.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动接口调用失败或当前驱动版本不支持该内存证据入口");
        }
        if (kRawText.contains(QStringLiteral("unsupported"), Qt::CaseInsensitive) ||
            kRawText.contains(QStringLiteral("not implemented"), Qt::CaseInsensitive))
        {
            return QStringLiteral("当前驱动版本尚未提供该内存证据入口");
        }
        if (kRawText.contains(QStringLiteral("too small"), Qt::CaseInsensitive) ||
            kRawText.contains(QStringLiteral("invalid"), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动返回数据格式不完整，当前证据表已清空等待下次刷新");
        }
        return kRawText;
    }

    QString bytesToHex(const std::vector<std::uint8_t>& bytes)
    {
        // Input: Sample byte array.
        // Handling: Display as space-separated uppercase hexadecimal, guaranteed by the R0 protocol.
        // Returns: Copyable hexadecimal text.
        QStringList parts;
        parts.reserve(static_cast<int>(bytes.size()));
        for (const std::uint8_t kByteValue : bytes)
        {
            parts << QStringLiteral("%1").arg(kByteValue, 2, 16, QChar('0')).toUpper();
        }
        return parts.join(QStringLiteral(" "));
    }

    QString hex64(const std::uint64_t value)
    {
        // Input: 64-bit address or hash value.
        // Handling: Format as fixed-width hexadecimal.
        // Returns: an uppercase string with the 0x prefix.
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(value), 16, 16, QChar('0'))
            .toUpper();
    }

    QString sizeText(const std::uint64_t bytes)
    {
        // Input: byte count.
        // Processing: Select between compact display in KB/MB/GB and raw byte values.
        // Return: human-readable size string.
        if (bytes >= 1024ULL * 1024ULL * 1024ULL)
        {
            return QStringLiteral("%1 GB").arg(static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0), 0, 'f', 2);
        }
        if (bytes >= 1024ULL * 1024ULL)
        {
            return QStringLiteral("%1 MB").arg(static_cast<double>(bytes) / (1024.0 * 1024.0), 0, 'f', 2);
        }
        if (bytes >= 1024ULL)
        {
            return QStringLiteral("%1 KB").arg(static_cast<double>(bytes) / 1024.0, 0, 'f', 2);
        }
        return QStringLiteral("%1 B").arg(static_cast<qulonglong>(bytes));
    }

    QString evidenceKindText(const std::uint32_t kind)
    {
        // Input: KSWORD_ARK_MEMORY_EVIDENCE_KIND_*.
        // Action: Map to UI group text.
        // Returns: Chinese evidence type.
        switch (kind)
        {
        case KSWORD_ARK_MEMORY_EVIDENCE_KIND_EXECUTABLE_RANGE:
            return QStringLiteral("执行页");
        case KSWORD_ARK_MEMORY_EVIDENCE_KIND_BIGPOOL:
            return QStringLiteral("BigPool");
        case KSWORD_ARK_MEMORY_EVIDENCE_KIND_TEXT_SECTION_MEMORY:
            return QStringLiteral("text hash");
        case KSWORD_ARK_MEMORY_EVIDENCE_KIND_UNKNOWN:
        default:
            return QStringLiteral("未知(%1)").arg(kind);
        }
    }

    QString ownerKindText(const std::uint32_t ownerKind)
    {
        // Input: KSWORD_ARK_MEMORY_EVIDENCE_OWNER_*.
        // Processing: Map to owner classification tag.
        // Returns: Chinese owner type.
        switch (ownerKind)
        {
        case KSWORD_ARK_MEMORY_EVIDENCE_OWNER_LOADED_MODULE:
            return QStringLiteral("LoadedModule");
        case KSWORD_ARK_MEMORY_EVIDENCE_OWNER_NONMODULE:
            return QStringLiteral("NonModule");
        case KSWORD_ARK_MEMORY_EVIDENCE_OWNER_BIGPOOL:
            return QStringLiteral("BigPool");
        case KSWORD_ARK_MEMORY_EVIDENCE_OWNER_SYSTEM_PTE:
            return QStringLiteral("SystemPte");
        case KSWORD_ARK_MEMORY_EVIDENCE_OWNER_MDL_LIKE:
            return QStringLiteral("MdlLike");
        case KSWORD_ARK_MEMORY_EVIDENCE_OWNER_UNKNOWN:
        default:
            return QStringLiteral("Unknown(%1)").arg(ownerKind);
        }
    }

    QString permissionText(const std::uint32_t flags)
    {
        // Input: Bitmask of KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_*.
        // Processing: Convert to compact text such as R/W/X/NX/Large.
        // Return: Permission text.
        QStringList parts;
        QString rwx;
        rwx += (flags & KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_READ) ? QChar('R') : QChar('-');
        rwx += (flags & KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_WRITE) ? QChar('W') : QChar('-');
        rwx += (flags & KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_EXECUTE) ? QChar('X') : QChar('-');
        parts << rwx;
        if (flags & KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_PRESENT) parts << QStringLiteral("Present");
        if (flags & KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_NX) parts << QStringLiteral("NX");
        if (flags & KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_LARGE) parts << QStringLiteral("Large");
        if (flags & KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_GLOBAL) parts << QStringLiteral("Global");
        if (flags & KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_USER) parts << QStringLiteral("User");
        return parts.join(QStringLiteral(" | "));
    }

    QString riskText(const std::uint32_t flags)
    {
        // Input: KSWORD_ARK_MEMORY_EVIDENCE_RISK_* bitset.
        // Processing: Convert to risk tag; return 'Normal' for 0.
        // Returns: Risk description text.
        if (flags == 0U)
        {
            return QStringLiteral("正常");
        }
        QStringList parts;
        if (flags & KSWORD_ARK_MEMORY_EVIDENCE_RISK_RWX) parts << QStringLiteral("RWX");
        if (flags & KSWORD_ARK_MEMORY_EVIDENCE_RISK_NONMODULE_EXECUTABLE) parts << QStringLiteral("非模块执行");
        if (flags & KSWORD_ARK_MEMORY_EVIDENCE_RISK_MODULE_NON_TEXT_EXECUTABLE) parts << QStringLiteral("模块非text执行");
        if (flags & KSWORD_ARK_MEMORY_EVIDENCE_RISK_EXECUTABLE_POOL) parts << QStringLiteral("执行池");
        if (flags & KSWORD_ARK_MEMORY_EVIDENCE_RISK_LARGE_EXECUTABLE) parts << QStringLiteral("大页执行");
        if (flags & KSWORD_ARK_MEMORY_EVIDENCE_RISK_OWNER_MISSING) parts << QStringLiteral("Owner缺失");
        return parts.join(QStringLiteral(" | "));
    }

    QString hashText(const ksword::ark::KernelMemoryEvidenceEntry& entry)
    {
        // Input: Kernel memory evidence row.
        // Note: Generate text hash status based on hashAlgorithm/contentHash/section fields.
        // Returns: "None" if no hash is present.
        if (entry.hashAlgorithm == KSWORD_ARK_MEMORY_EVIDENCE_HASH_NONE || entry.contentHash == 0ULL)
        {
            return QStringLiteral("无");
        }
        const QString kAlgorithm = entry.hashAlgorithm == KSWORD_ARK_MEMORY_EVIDENCE_HASH_FNV1A64
            ? QStringLiteral("FNV1A64")
            : QStringLiteral("Hash(%1)").arg(entry.hashAlgorithm);
        const QString kSection = QString::fromStdString(entry.sectionName).trimmed();
        return QStringLiteral("%1 %2 %3").arg(kAlgorithm, kSection.isEmpty() ? QStringLiteral(".text?") : kSection, hex64(entry.contentHash));
    }

    QTableWidgetItem* textItem(const QString& text)
    {
        // Input: display text.
        // Processing: Create a read-only table item.
        // Returns: An item handed over to QTableWidget for lifecycle management.
        QTableWidgetItem* item = new QTableWidgetItem(text);
        item->setTextAlignment(Qt::AlignVCenter | Qt::AlignLeft);
        return item;
    }

    QString evidenceCopyMenuStyle()
    {
        // Inputs: None.
        // Processing: Generate an opaque context menu style to prevent inheriting a transparent background.
        // Returns: a string suitable for use with QMenu::setStyleSheet.
        // Right-click menus always use the global theme implementation to avoid each page having its own drifting QSS fragments.
        return ksword_theme::contextMenuStyle();
    }

    QString evidenceRowText(QTableWidget* table, const int rowIndex)
    {
        // Input: Kernel memory evidence table and target row index.
        // Note: Read all columns of the current row and separate them with tabs.
        // Returns: Copyable TSV text; returns an empty string if the row is invalid.
        if (table == nullptr || rowIndex < 0 || rowIndex >= table->rowCount())
        {
            return QString();
        }

        QStringList fields;
        fields.reserve(table->columnCount());
        for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
        {
            const QTableWidgetItem* item = table->item(rowIndex, columnIndex);
            fields.push_back(item != nullptr ? item->text() : QString());
        }
        return fields.join(QLatin1Char('\t'));
    }

    void installEvidenceCopyMenu(QTableWidget* table)
    {
        // Input: Kernel memory evidence table.
        // Processing: Install the 'Copy Current Row' right-click menu.
        // Returns: None; only copies UI evidence without triggering any write operations.
        if (table == nullptr)
        {
            return;
        }

        table->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(table, &QTableWidget::customContextMenuRequested, table, [table](const QPoint& localPosition)
        {
            const QModelIndex kClickedIndex = table->indexAt(localPosition);
            const int kRowIndex = kClickedIndex.isValid() ? kClickedIndex.row() : table->currentRow();
            if (kClickedIndex.isValid())
            {
                table->setCurrentCell(kClickedIndex.row(), kClickedIndex.column());
                table->selectRow(kClickedIndex.row());
            }

            QMenu menu(table);
            menu.setStyleSheet(evidenceCopyMenuStyle());
            QAction* copyRowAction = menu.addAction(
                QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
                QStringLiteral("复制当前行"));
            copyRowAction->setEnabled(kRowIndex >= 0 && kRowIndex < table->rowCount());
            if (menu.exec(table->viewport()->mapToGlobal(localPosition)) == copyRowAction)
            {
                QClipboard* clipboard = QApplication::clipboard();
                if (clipboard != nullptr)
                {
                    clipboard->setText(evidenceRowText(table, kRowIndex));
                }
            }
        });
    }

    void setEvidenceDiagnosticRow(
        QTableWidget* table,
        const QString& addressText,
        const QString& detailText)
    {
        // setEvidenceDiagnosticRow：
        // - Input: target table, first column hint, and detail text;
        // - Processing: Added a copyable diagnostic line to prevent the table from being completely blank due to empty cache or filter conditions.
        // - Return: None; the complete diagnosis is saved to UserRole+2 for the details section to read.
        if (table == nullptr)
        {
            return;
        }

        table->setRowCount(1);
        QTableWidgetItem* addressItem = textItem(addressText);
        addressItem->setData(Qt::UserRole + 2, detailText);
        table->setItem(0, evidenceColumnIndex(EvidenceColumn::kAddress), addressItem);
        table->setItem(0, evidenceColumnIndex(EvidenceColumn::kSize), textItem(QStringLiteral("N/A")));
        table->setItem(0, evidenceColumnIndex(EvidenceColumn::kKind), textItem(QStringLiteral("诊断")));
        table->setItem(0, evidenceColumnIndex(EvidenceColumn::kOwner), textItem(QStringLiteral("N/A")));
        table->setItem(0, evidenceColumnIndex(EvidenceColumn::kPermissions), textItem(QStringLiteral("N/A")));
        table->setItem(0, evidenceColumnIndex(EvidenceColumn::kRisk), textItem(QStringLiteral("提示")));
        table->setItem(0, evidenceColumnIndex(EvidenceColumn::kTextHash), textItem(QStringLiteral("N/A")));
        table->setItem(0, evidenceColumnIndex(EvidenceColumn::kDetail), textItem(detailText));
        table->setCurrentCell(0, evidenceColumnIndex(EvidenceColumn::kAddress));
    }

    QTableWidgetItem* numericItem(const QString& text, const qulonglong value)
    {
        // Input: display text (hexadecimal address or KB/MB size) and the actual numeric value used for sorting.
        // Processing: Uniformly use the global ks::ui::NumericTableItem, sorting via NumericSortRole. No longer
        //       create private items, avoiding conflicts with the address column's custom Qt::UserRole+1 cached index role.
        // Returns: An item handed over to QTableWidget for lifecycle management.
        ks::ui::NumericTableItem* item = new ks::ui::NumericTableItem(text, value);
        item->setTextAlignment(Qt::AlignVCenter | Qt::AlignLeft);
        return item;
    }

    QString evidenceTableDetailText(const ksword::ark::KernelMemoryEvidenceEntry& entry)
    {
        // Input: Kernel memory evidence row.
        // Handling: generate a Chinese summary for the table's last column to avoid displaying the raw R0 detail string directly.
        // Return: Single-line summary; the full raw detail remains in the detail editor.
        const QString kRawDetail = wideToQString(entry.detail).trimmed();
        const QString kRiskSummary = riskText(entry.riskFlags);
        const QString kDetailSummary = kRawDetail.isEmpty()
            ? QStringLiteral("驱动未返回额外说明")
            : kRawDetail.left(160);
        return QStringLiteral("%1；Owner=%2；%3")
            .arg(kRiskSummary)
            .arg(ownerKindText(entry.ownerKind))
            .arg(kDetailSummary);
    }

    bool entryMatchesFilter(const ksword::ark::KernelMemoryEvidenceEntry& entry, const QString& filter)
    {
        // Input: Evidence row and filter text.
        // Processing: Perform case-insensitive substring matching in owner/detail/risk/address/hash.
        // Returns: true if this row should be displayed.
        if (filter.isEmpty())
        {
            return true;
        }
        const QStringList kFields{
            hex64(entry.virtualAddress),
            wideToQString(entry.ownerName),
            wideToQString(entry.detail),
            ownerKindText(entry.ownerKind),
            evidenceKindText(entry.evidenceKind),
            riskText(entry.riskFlags),
            hashText(entry)
        };
        for (const QString& field : kFields)
        {
            if (field.contains(filter, Qt::CaseInsensitive))
            {
                return true;
            }
        }
        return false;
    }

    QString detailText(const ksword::ark::KernelMemoryEvidenceEntry& entry)
    {
        // Input: Current kernel memory evidence row.
        // Processing: expand all key diagnostic fields for the details editor to copy.
        // Returns: Multi-line detail text.
        QString text;
        text += QStringLiteral("内核内存证据详情\n");
        text += QStringLiteral("Address: %1\n").arg(hex64(entry.virtualAddress));
        text += QStringLiteral("RegionSize: %1 (%2)\n").arg(hex64(entry.regionSize), sizeText(entry.regionSize));
        text += QStringLiteral("EvidenceKind: %1\n").arg(evidenceKindText(entry.evidenceKind));
        text += QStringLiteral("OwnerKind: %1\n").arg(ownerKindText(entry.ownerKind));
        text += QStringLiteral("OwnerName: %1\n").arg(wideToQString(entry.ownerName));
        text += QStringLiteral("OwnerAddress: %1\n").arg(hex64(entry.ownerAddress));
        text += QStringLiteral("ModuleBase: %1\n").arg(hex64(entry.moduleBase));
        text += QStringLiteral("ModuleSize: %1\n").arg(sizeText(entry.moduleSize));
        text += QStringLiteral("PermissionFlags: %1 (0x%2)\n").arg(permissionText(entry.permissionFlags)).arg(entry.permissionFlags, 8, 16, QChar('0'));
        text += QStringLiteral("RiskFlags: %1 (0x%2)\n").arg(riskText(entry.riskFlags)).arg(entry.riskFlags, 8, 16, QChar('0'));
        text += QStringLiteral("BigPoolTag: 0x%1\n").arg(entry.bigPoolTag, 8, 16, QChar('0'));
        text += QStringLiteral("BigPoolFlags: 0x%1\n").arg(entry.bigPoolFlags, 8, 16, QChar('0'));
        text += QStringLiteral("Section: %1 RVA=0x%2 Size=%3\n")
            .arg(QString::fromStdString(entry.sectionName).trimmed())
            .arg(entry.sectionRva, 8, 16, QChar('0'))
            .arg(sizeText(entry.sectionSize));
        text += QStringLiteral("Hash: %1\n").arg(hashText(entry));
        text += QStringLiteral("SampleSize: %1\n").arg(entry.sampleSize);
        if (!entry.sample.empty())
        {
            text += QStringLiteral("Sample: %1\n").arg(bytesToHex(entry.sample));
        }
        text += QStringLiteral("Confidence: %1\n").arg(entry.confidence);
        text += QStringLiteral("LastStatus: 0x%1\n")
            .arg(static_cast<qulonglong>(static_cast<unsigned long>(entry.lastStatus)), 8, 16, QChar('0'));
        text += QStringLiteral("Detail: %1\n").arg(wideToQString(entry.detail));
        return text;
    }

    QString statusStyle(const QString& color)
    {
        // Input: CSS color.
        // Processing: Uniformly generate status label styles.
        // Returns: stylesheet text.
        return QStringLiteral("color:%1; font-weight:700;").arg(color);
    }
}

void MemoryDock::initializeKernelMemoryEvidenceTab()
{
    // Input: None; called by initializeTabs.
    // Processing: Create read-only pages for kernel memory evidence. Module execution range scanning is disabled by default; must specify a range to explicitly enable.
    // Returns: Nothing.
    tabKernelMemoryEvidence_ = new QWidget(tabWidget_);
    QVBoxLayout* tabLayout = new QVBoxLayout(tabKernelMemoryEvidence_);
    tabLayout->setContentsMargins(6, 6, 6, 6);
    tabLayout->setSpacing(6);

    // First-level action row: retain only 'Refresh + Filter + Status'; scan parameters are moved to the second-level group
    // box. Otherwise, with 8 controls on a single toolbar, input fields get compressed to a few pixels in narrow windows.
    QHBoxLayout* toolLayout = new QHBoxLayout();
    toolLayout->setContentsMargins(0, 0, 0, 0);
    toolLayout->setSpacing(8);

    kernelMemoryEvidenceRefreshButton_ = new QPushButton(QIcon(QStringLiteral(":/Icon/process_refresh.svg")), QStringLiteral("刷新证据"), tabKernelMemoryEvidence_);
    kernelMemoryEvidenceRefreshButton_->setToolTip(QStringLiteral("刷新内核内存证据"));
    kernelMemoryEvidenceRefreshButton_->setStyleSheet(buildBlueButtonStyle());

    // The vertical line separator visually separates the 'Refresh' write query action from the local filtering on the right.
    QFrame* evidenceActionSeparator = new QFrame(tabKernelMemoryEvidence_);
    evidenceActionSeparator->setFrameShape(QFrame::VLine);
    evidenceActionSeparator->setFrameShadow(QFrame::Sunken);

    kernelMemoryEvidenceFilterEdit_ = new QLineEdit(tabKernelMemoryEvidence_);
    kernelMemoryEvidenceFilterEdit_->setClearButtonEnabled(true);
    kernelMemoryEvidenceFilterEdit_->setPlaceholderText(QStringLiteral("过滤 owner / detail / risk / hash"));
    kernelMemoryEvidenceFilterEdit_->setToolTip(QStringLiteral("输入关键字后只显示匹配的证据行"));
    kernelMemoryEvidenceFilterEdit_->setStyleSheet(buildBlueInputStyle());

    kernelMemoryEvidenceStatusLabel_ = new QLabel(QStringLiteral("状态：等待刷新"), tabKernelMemoryEvidence_);
    kernelMemoryEvidenceStatusLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    kernelMemoryEvidenceStatusLabel_->setStyleSheet(statusStyle(ksword_theme::textSecondaryHex()));

    toolLayout->addWidget(kernelMemoryEvidenceRefreshButton_);
    toolLayout->addWidget(evidenceActionSeparator);
    toolLayout->addWidget(kernelMemoryEvidenceFilterEdit_, 1);
    toolLayout->addWidget(kernelMemoryEvidenceStatusLabel_);
    tabLayout->addLayout(toolLayout);

    // Second-level scan parameter group: two switches per row, three rows of 'label + input', grid ensures labels and inputs always pair up.
    QGroupBox* evidenceScanParamGroup = new QGroupBox(QStringLiteral("扫描参数"), tabKernelMemoryEvidence_);
    QGridLayout* evidenceScanParamLayout = new QGridLayout(evidenceScanParamGroup);
    evidenceScanParamLayout->setContentsMargins(8, 6, 8, 6);
    evidenceScanParamLayout->setHorizontalSpacing(8);
    evidenceScanParamLayout->setVerticalSpacing(6);

    kernelMemoryEvidenceRiskOnlyCheck_ = new QCheckBox(QStringLiteral("仅显示风险项"), evidenceScanParamGroup);
    kernelMemoryEvidenceRiskOnlyCheck_->setChecked(true);
    kernelMemoryEvidenceRiskOnlyCheck_->setToolTip(QStringLiteral("只显示驱动判定 riskFlags 非零的证据行"));

    kernelMemoryEvidenceIncludeNonModuleCheck_ = new QCheckBox(QStringLiteral("包含非模块执行范围"), evidenceScanParamGroup);
    kernelMemoryEvidenceIncludeNonModuleCheck_->setToolTip(QStringLiteral("需要填写起止地址；不会默认扫描全内核地址空间。"));

    // Start and end VA are only used in the query when 'Include non-module execution ranges' is checked; the placeholder shows a typical kernel address format.
    kernelMemoryEvidenceStartEdit_ = new QLineEdit(evidenceScanParamGroup);
    kernelMemoryEvidenceStartEdit_->setPlaceholderText(QStringLiteral("0xFFFFF80000000000"));
    kernelMemoryEvidenceStartEdit_->setToolTip(QStringLiteral("非模块执行范围扫描的起始虚拟地址，勾选后必填"));
    kernelMemoryEvidenceStartEdit_->setMinimumWidth(150);
    kernelMemoryEvidenceStartEdit_->setStyleSheet(buildBlueInputStyle());

    kernelMemoryEvidenceEndEdit_ = new QLineEdit(evidenceScanParamGroup);
    kernelMemoryEvidenceEndEdit_->setPlaceholderText(QStringLiteral("0xFFFFF80001000000"));
    kernelMemoryEvidenceEndEdit_->setToolTip(QStringLiteral("非模块执行范围扫描的结束虚拟地址，必须大于起始地址"));
    kernelMemoryEvidenceEndEdit_->setMinimumWidth(150);
    kernelMemoryEvidenceEndEdit_->setStyleSheet(buildBlueInputStyle());

    kernelMemoryEvidenceMaxRowsSpin_ = new QSpinBox(evidenceScanParamGroup);
    kernelMemoryEvidenceMaxRowsSpin_->setRange(16, static_cast<int>(KSWORD_ARK_MEMORY_EVIDENCE_HARD_MAX_ROWS));
    kernelMemoryEvidenceMaxRowsSpin_->setValue(static_cast<int>(KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_MAX_ROWS));
    kernelMemoryEvidenceMaxRowsSpin_->setToolTip(QStringLiteral("最大返回行数"));

    // The two switches in row 0 each occupy two columns; row 1 has three groups of labels/inputs, with the last column left as a stretchable area to absorb excess window width.
    evidenceScanParamLayout->addWidget(kernelMemoryEvidenceRiskOnlyCheck_, 0, 0, 1, 2);
    evidenceScanParamLayout->addWidget(kernelMemoryEvidenceIncludeNonModuleCheck_, 0, 2, 1, 4);
    evidenceScanParamLayout->addWidget(new QLabel(QStringLiteral("起始 VA"), evidenceScanParamGroup), 1, 0);
    evidenceScanParamLayout->addWidget(kernelMemoryEvidenceStartEdit_, 1, 1);
    evidenceScanParamLayout->addWidget(new QLabel(QStringLiteral("结束 VA"), evidenceScanParamGroup), 1, 2);
    evidenceScanParamLayout->addWidget(kernelMemoryEvidenceEndEdit_, 1, 3);
    evidenceScanParamLayout->addWidget(new QLabel(QStringLiteral("最大行数"), evidenceScanParamGroup), 1, 4);
    evidenceScanParamLayout->addWidget(kernelMemoryEvidenceMaxRowsSpin_, 1, 5);
    evidenceScanParamLayout->setColumnStretch(6, 1);
    tabLayout->addWidget(evidenceScanParamGroup);

    QSplitter* splitter = new QSplitter(Qt::Vertical, tabKernelMemoryEvidence_);
    tabLayout->addWidget(splitter, 1);

    kernelMemoryEvidenceTable_ = new ks::ui::VisibleTableWidget(splitter);
    kernelMemoryEvidenceTable_->setColumnCount(evidenceColumnIndex(EvidenceColumn::kCount));
    kernelMemoryEvidenceTable_->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("VA"),
        QStringLiteral("大小"),
        QStringLiteral("类型"),
        QStringLiteral("Owner"),
        QStringLiteral("PTE权限"),
        QStringLiteral("风险"),
        QStringLiteral("text hash/diff"),
        QStringLiteral("Detail")
        });
    kernelMemoryEvidenceTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    kernelMemoryEvidenceTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    kernelMemoryEvidenceTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    kernelMemoryEvidenceTable_->setAlternatingRowColors(true);
    kernelMemoryEvidenceTable_->setSortingEnabled(true);
    kernelMemoryEvidenceTable_->verticalHeader()->setVisible(false);
    installEvidenceCopyMenu(kernelMemoryEvidenceTable_);
    splitter->addWidget(kernelMemoryEvidenceTable_);

    kernelMemoryEvidenceDetailEditor_ = new CodeEditorWidget(splitter);
    kernelMemoryEvidenceDetailEditor_->setReadOnly(true);
    kernelMemoryEvidenceDetailEditor_->setText(QStringLiteral(
        "请选择一条内核内存证据记录查看详情。\n"
        "说明：text diff 的磁盘对比由 R3 后续阶段完成，本页当前展示 R0 内存 hash/sample 状态。"));
    splitter->addWidget(kernelMemoryEvidenceDetailEditor_);

    ks::ui::DetailLayoutRegistry::registerHost(
        kernelMemoryEvidenceTable_,
        kernelMemoryEvidenceDetailEditor_,
        tabKernelMemoryEvidence_);
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);

    tabWidget_->addTab(tabKernelMemoryEvidence_, QStringLiteral("内核内存证据"));
}

void MemoryDock::refreshKernelMemoryEvidenceAsync()
{
    // Input: Triggered by the refresh button or a global refresh.
    // Processing: Validate non-module range boundaries; call ArkDriverClient in the background; update cache and status on the main thread.
    // Returns: Nothing.
    if (kernelMemoryEvidenceRefreshInProgress_.exchange(true))
    {
        return;
    }

    std::uint64_t startAddress = 0;
    std::uint64_t endAddress = 0;
    unsigned long flags =
        KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_LOADED_MODULE_EXECUTABLE |
        KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_BIGPOOL |
        KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_TEXT_SECTION_SAMPLES |
        KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_SUSPECTED_BIGPOOL;

    if (kernelMemoryEvidenceIncludeNonModuleCheck_ != nullptr &&
        kernelMemoryEvidenceIncludeNonModuleCheck_->isChecked())
    {
        const bool kStartOk = parseAddressText(kernelMemoryEvidenceStartEdit_ != nullptr ? kernelMemoryEvidenceStartEdit_->text().trimmed() : QString(), startAddress);
        const bool kEndOk = parseAddressText(kernelMemoryEvidenceEndEdit_ != nullptr ? kernelMemoryEvidenceEndEdit_->text().trimmed() : QString(), endAddress);
        if (!kStartOk || !kEndOk || startAddress >= endAddress)
        {
            // Exit the collection state immediately upon parameter validation failure: Since the button is not yet grayed out, simply restore the busy flag and display a notification.
            kernelMemoryEvidenceRefreshInProgress_.store(false);
            KLogEvent invalidRangeEvent;
            info << invalidRangeEvent
                << "[MemoryDock] refreshKernelMemoryEvidenceAsync: 非模块执行范围起止 VA 无效，已放弃本次采集。"
                << eol;
            if (kernelMemoryEvidenceStatusLabel_ != nullptr)
            {
                kernelMemoryEvidenceStatusLabel_->setText(QStringLiteral("状态：非模块执行范围需要有效的起始/结束 VA。"));
                kernelMemoryEvidenceStatusLabel_->setStyleSheet(
                    statusStyle(ksword_theme::errorColor().name(QColor::HexRgb)));
            }
            return;
        }
        flags |= KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_NONMODULE_EXECUTABLE_RANGES;
    }

    const unsigned long kMaxRows = static_cast<unsigned long>(
        kernelMemoryEvidenceMaxRowsSpin_ != nullptr
            ? kernelMemoryEvidenceMaxRowsSpin_->value()
            : static_cast<int>(KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_MAX_ROWS));

    // Entering collection state: the button is disabled and the prompt is updated; the status label shows
    // 'Collecting'. Both are restored by commitSnapshot after the result returns to the main thread.
    if (kernelMemoryEvidenceRefreshButton_ != nullptr)
    {
        kernelMemoryEvidenceRefreshButton_->setEnabled(false);
        kernelMemoryEvidenceRefreshButton_->setToolTip(QStringLiteral("正在采集内核内存证据，请等待本轮查询结束"));
    }
    if (kernelMemoryEvidenceStatusLabel_ != nullptr)
    {
        kernelMemoryEvidenceStatusLabel_->setText(QStringLiteral("状态：正在采集内核内存证据…"));
        kernelMemoryEvidenceStatusLabel_->setStyleSheet(statusStyle(ksword_theme::kPrimaryBlueHex));
    }

    const std::uint64_t kTicket = kernelMemoryEvidenceRefreshTicket_.fetch_add(1U) + 1U;
    const QPointer<MemoryDock> kGuardThis(this);

    std::thread([kGuardThis, kTicket, flags, kMaxRows, startAddress, endAddress]() {
        const ksword::ark::DriverClient kClient;
        ksword::ark::KernelMemoryEvidenceResult result = kClient.queryKernelMemoryEvidence(
            flags,
            kMaxRows,
            startAddress,
            endAddress,
            KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_MAX_BYTES,
            KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_BIGPOOL_ROWS,
            KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_SAMPLE_BYTES);

        QMetaObject::invokeMethod(
            kGuardThis.data(),
            [kGuardThis, kTicket, result = std::move(result)]() mutable {
                auto resultSnapshot =
                    std::make_shared<ksword::ark::KernelMemoryEvidenceResult>(std::move(result));
                auto commitSnapshot = [kGuardThis, kTicket, resultSnapshot]()
                {
                    if (kGuardThis == nullptr ||
                        kTicket < kGuardThis->kernelMemoryEvidenceRefreshTicket_.load())
                    {
                        return;
                    }

                    kGuardThis->kernelMemoryEvidenceRefreshInProgress_.store(false);
                    // Exit collection mode: restore the button to enabled state and revert the tooltip to normal text; both success and failure paths share this logic.
                    if (kGuardThis->kernelMemoryEvidenceRefreshButton_ != nullptr)
                    {
                        kGuardThis->kernelMemoryEvidenceRefreshButton_->setEnabled(true);
                        kGuardThis->kernelMemoryEvidenceRefreshButton_->setToolTip(
                            QStringLiteral("刷新内核内存证据"));
                    }

                    const ksword::ark::KernelMemoryEvidenceResult& snapshot = *resultSnapshot;
                    if (!snapshot.io.ok)
                    {
                        kGuardThis->kernelMemoryEvidenceCache_.clear();
                        kGuardThis->kernelMemoryEvidenceVisibleCount_ = 0U;
                        kGuardThis->rebuildKernelMemoryEvidenceTable();
                        const QString kMessage = snapshot.unsupported
                            ? QStringLiteral("未集成/驱动过旧，等待 R0 支持")
                            : QStringLiteral("查询失败: %1").arg(
                                memoryEvidenceIoMessageText(snapshot.io.message));
                        if (kGuardThis->kernelMemoryEvidenceStatusLabel_ != nullptr)
                        {
                            kGuardThis->kernelMemoryEvidenceStatusLabel_->setText(
                                QStringLiteral("状态：%1").arg(kMessage));
                            kGuardThis->kernelMemoryEvidenceStatusLabel_->setStyleSheet(
                                statusStyle(ksword_theme::errorColor().name(QColor::HexRgb)));
                        }
                        if (kGuardThis->kernelMemoryEvidenceDetailEditor_ != nullptr)
                        {
                            kGuardThis->kernelMemoryEvidenceDetailEditor_->setText(kMessage);
                        }
                        return;
                    }

                    kGuardThis->kernelMemoryEvidenceCache_ = snapshot.entries;
                    kGuardThis->rebuildKernelMemoryEvidenceTable();
                    kGuardThis->showKernelMemoryEvidenceDetailByCurrentRow();
                    if (kGuardThis->kernelMemoryEvidenceStatusLabel_ != nullptr)
                    {
                        kGuardThis->kernelMemoryEvidenceStatusLabel_->setText(
                            QStringLiteral("状态：总计 %1，返回 %2，显示 %3，模块 %4，BigPool seen %5")
                            .arg(snapshot.totalRows)
                            .arg(snapshot.returnedRows)
                            .arg(kGuardThis->kernelMemoryEvidenceVisibleCount_)
                            .arg(snapshot.moduleCount)
                            .arg(snapshot.bigPoolRowsSeen));
                        kGuardThis->kernelMemoryEvidenceStatusLabel_->setStyleSheet(
                            statusStyle(ksword_theme::successColor().name(QColor::HexRgb)));
                    }
                };

                if (ks::ui::deferTableUiCommitIfContextMenuOpen(
                    kGuardThis.data(),
                    QStringLiteral("memory-kernel-evidence-snapshot"),
                    { kGuardThis->kernelMemoryEvidenceTable_ },
                    commitSnapshot))
                {
                    return;
                }
                commitSnapshot();
            },
            Qt::QueuedConnection);
    }).detach();
}

void MemoryDock::rebuildKernelMemoryEvidenceTable()
{
    ks::ui::DetailLayoutRegistry::prepareDataRebuild(kernelMemoryEvidenceDetailEditor_);
    // Input: none; reads m_kernelMemoryEvidenceCache and filter controls.
    // Processing: Project cache into a table; risk filtering executes only locally in R3.
    // Returns: Nothing.
    if (kernelMemoryEvidenceTable_ == nullptr)
    {
        return;
    }

    const QString kFilter = kernelMemoryEvidenceFilterEdit_ != nullptr
        ? kernelMemoryEvidenceFilterEdit_->text().trimmed()
        : QString();
    const bool kRiskOnly = kernelMemoryEvidenceRiskOnlyCheck_ != nullptr && kernelMemoryEvidenceRiskOnlyCheck_->isChecked();

    std::vector<std::size_t> visibleIndexes;
    visibleIndexes.reserve(kernelMemoryEvidenceCache_.size());
    for (std::size_t index = 0; index < kernelMemoryEvidenceCache_.size(); ++index)
    {
        const auto& entry = kernelMemoryEvidenceCache_[index];
        if (kRiskOnly && entry.riskFlags == 0U)
        {
            continue;
        }
        if (!entryMatchesFilter(entry, kFilter))
        {
            continue;
        }
        visibleIndexes.push_back(index);
    }

    kernelMemoryEvidenceVisibleCount_ = visibleIndexes.size();
    const QSignalBlocker kBlocker(kernelMemoryEvidenceTable_);
    kernelMemoryEvidenceTable_->setSortingEnabled(false);
    kernelMemoryEvidenceTable_->setRowCount(static_cast<int>(visibleIndexes.size()));
    for (int row = 0; row < static_cast<int>(visibleIndexes.size()); ++row)
    {
        const std::size_t kCacheIndex = visibleIndexes[static_cast<std::size_t>(row)];
        const auto& entry = kernelMemoryEvidenceCache_[kCacheIndex];
        // Virtual address column: displays 0x hex; sorts using the 64-bit raw value to prevent header clicks from degrading to string order.
        QTableWidgetItem* addressItem = numericItem(hex64(entry.virtualAddress), static_cast<qulonglong>(entry.virtualAddress));
        addressItem->setData(Qt::UserRole + 1, QVariant::fromValue<qulonglong>(static_cast<qulonglong>(kCacheIndex)));
        kernelMemoryEvidenceTable_->setItem(row, evidenceColumnIndex(EvidenceColumn::kAddress), addressItem);
        // Region size column: displays KB/MB/GB, but sorts by byte count to prevent 512 KB from appearing after 2.50 MB.
        kernelMemoryEvidenceTable_->setItem(row, evidenceColumnIndex(EvidenceColumn::kSize), numericItem(sizeText(entry.regionSize), static_cast<qulonglong>(entry.regionSize)));
        kernelMemoryEvidenceTable_->setItem(row, evidenceColumnIndex(EvidenceColumn::kKind), textItem(evidenceKindText(entry.evidenceKind)));
        kernelMemoryEvidenceTable_->setItem(row, evidenceColumnIndex(EvidenceColumn::kOwner),
            textItem(QStringLiteral("%1 %2").arg(ownerKindText(entry.ownerKind), wideToQString(entry.ownerName))));
        kernelMemoryEvidenceTable_->setItem(row, evidenceColumnIndex(EvidenceColumn::kPermissions), textItem(permissionText(entry.permissionFlags)));
        kernelMemoryEvidenceTable_->setItem(row, evidenceColumnIndex(EvidenceColumn::kRisk), textItem(riskText(entry.riskFlags)));
        kernelMemoryEvidenceTable_->setItem(row, evidenceColumnIndex(EvidenceColumn::kTextHash), textItem(hashText(entry)));
        kernelMemoryEvidenceTable_->setItem(row, evidenceColumnIndex(EvidenceColumn::kDetail), textItem(evidenceTableDetailText(entry)));
    }
    if (visibleIndexes.empty())
    {
        const QString kDetailText = kernelMemoryEvidenceCache_.empty()
            ? QStringLiteral("内核内存证据当前没有缓存行；可能是驱动未返回结果、查询失败或尚未刷新。")
            : QStringLiteral("当前过滤条件隐藏了全部 %1 条内核内存证据；请清空过滤或关闭“仅显示风险项”。")
                .arg(static_cast<qulonglong>(kernelMemoryEvidenceCache_.size()));
        setEvidenceDiagnosticRow(
            kernelMemoryEvidenceTable_,
            QStringLiteral("<无内核内存证据>"),
            kDetailText);
    }
    if (kernelMemoryEvidenceTable_->rowCount() > 0 && kernelMemoryEvidenceTable_->currentRow() < 0)
    {
        kernelMemoryEvidenceTable_->setCurrentCell(0, evidenceColumnIndex(EvidenceColumn::kAddress));
    }
    kernelMemoryEvidenceTable_->setSortingEnabled(true);
    ks::ui::requestTableColumnAutoFit(kernelMemoryEvidenceTable_);
}

void MemoryDock::showKernelMemoryEvidenceDetailByCurrentRow()
{
    // Input: None; read the current table row.
    // Processing: Write to the detail editor via the cached index.
    // Returns: Nothing.
    if (kernelMemoryEvidenceDetailEditor_ == nullptr || kernelMemoryEvidenceTable_ == nullptr)
    {
        return;
    }
    const int kRow = kernelMemoryEvidenceTable_->currentRow();
    if (kRow < 0)
    {
        kernelMemoryEvidenceDetailEditor_->setText(QStringLiteral("请选择一条内核内存证据记录查看详情。"));
        return;
    }
    const QTableWidgetItem* addressItem = kernelMemoryEvidenceTable_->item(kRow, evidenceColumnIndex(EvidenceColumn::kAddress));
    if (addressItem == nullptr)
    {
        return;
    }
    const QString kDiagnosticText = addressItem->data(Qt::UserRole + 2).toString();
    if (!kDiagnosticText.isEmpty())
    {
        kernelMemoryEvidenceDetailEditor_->setText(QStringLiteral("内核内存证据诊断\n%1").arg(kDiagnosticText));
        return;
    }

    bool ok = false;
    const qulonglong kCacheIndex = addressItem->data(Qt::UserRole + 1).toULongLong(&ok);
    if (!ok || kCacheIndex >= static_cast<qulonglong>(kernelMemoryEvidenceCache_.size()))
    {
        return;
    }
    kernelMemoryEvidenceDetailEditor_->setText(detailText(kernelMemoryEvidenceCache_[static_cast<std::size_t>(kCacheIndex)]));
}
