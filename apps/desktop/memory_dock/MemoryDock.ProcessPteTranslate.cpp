#include "MemoryDock.Internal.h"
#include "../ui/TableInteractionSupport.h"
#include "../ui/VisibleTableWidget.h"
#include "../ui/DetailLayoutRegistry.h"
#include "../ui/TableColumnAutoFit.h"

// Explicitly include Qt controls used by the layered toolbar here: Internal.h already aggregates headers with the same names, but that aggregate
// header is shared by multiple people. This file does not depend on its inclusion list to avoid being affected when entries are added or removed.
#include <QFrame>
#include <QGridLayout>
#include <QGroupBox>
#include <QLabel>

#include <memory>

using namespace ksword::memory_dock_internal;

namespace
{
    // PTE/VA translation page column definition: Maintain stable column indices for sorting, filtering, and reverse lookup of details.
    enum class PteTranslateColumn : int
    {
        kVirtualAddress = 0,
        kRegionBase,
        kValid,
        kShared,
        kLocked,
        kLargePage,
        kBad,
        kShareCount,
        kWin32Protection,
        kNode,
        kMappedFile,
        kRisk,
        kCount
    };

    // Converts the column enumeration to a Qt column index.
    int pteTranslateColumnIndex(const PteTranslateColumn column)
    {
        return static_cast<int>(column);
    }

    // Safely convert a wide string from the `QWidget` side to `QString`.
    QString wideToQString(const std::wstring& value)
    {
        return value.empty() ? QString() : QString::fromStdWString(value);
    }

    // Format the address as a stable base-16 string.
    QString hex64(const std::uint64_t value)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(value), 16, 16, QChar('0'))
            .toUpper();
    }

    // Combine a read-only risk text.
    QString buildPteRiskText(
        const std::uint32_t protect,
        const bool valid,
        const bool bad,
        const bool largePage)
    {
        QStringList parts;
        if (!valid)
        {
            parts << QStringLiteral("无效页");
        }
        if ((protect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE ||
            (protect & PAGE_EXECUTE_WRITECOPY) == PAGE_EXECUTE_WRITECOPY)
        {
            parts << QStringLiteral("可写可执行");
        }
        if (bad)
        {
            parts << QStringLiteral("Bad 页");
        }
        if (largePage)
        {
            parts << QStringLiteral("大页");
        }
        return parts.isEmpty() ? QStringLiteral("正常") : parts.join(QStringLiteral(" | "));
    }

    // Construct a read-only table item.
    QTableWidgetItem* makeReadOnlyItem(const QString& text)
    {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled);
        return item;
    }

    QString pteMenuStyle()
    {
        // pteMenuStyle：
        // - Inputs: None;
        // - Processing: generate opaque context menu styles.
        // - Returns: QMenu style text.
        // Right-click menus always use the global theme implementation to avoid each page having its own drifting QSS fragments.
        return ksword_theme::contextMenuStyle();
    }

    void copyPteCurrentRow(QTableWidget* table)
    {
        // copyPteCurrentRow：
        // - Input: PTE/VA translation table;
        // - Processing: Copy all columns of the current row;
        // - Return: None, silently returns on failure.
        if (table == nullptr || QApplication::clipboard() == nullptr)
        {
            return;
        }

        const int kRowIndex = table->currentRow();
        if (kRowIndex < 0 || kRowIndex >= table->rowCount())
        {
            return;
        }

        QStringList fields;
        fields.reserve(table->columnCount());
        for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
        {
            const QTableWidgetItem* item = table->item(kRowIndex, columnIndex);
            fields.push_back(item != nullptr ? item->text() : QString());
        }
        QApplication::clipboard()->setText(fields.join('\t'));
    }

    void installPteCopyMenu(QTableWidget* table)
    {
        // installPteCopyMenu：
        // - Input: PTE/VA translation table;
        // - Processing: Install read-only copy menu.
        // - Returns: Nothing; does not read or modify extra memory.
        if (table == nullptr)
        {
            return;
        }

        table->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(table, &QTableWidget::customContextMenuRequested, table, [table](const QPoint& localPosition) {
            const QModelIndex kClickedIndex = table->indexAt(localPosition);
            if (kClickedIndex.isValid())
            {
                table->setCurrentCell(kClickedIndex.row(), kClickedIndex.column());
            }

            QMenu menu(table);
            menu.setStyleSheet(pteMenuStyle());
            QAction* copyRowAction = menu.addAction(QIcon(QStringLiteral(":/Icon/process_copy_row.svg")), QStringLiteral("复制当前行"));
            // Add a tooltip to the menu item to maintain discoverability consistent with other buttons on the page.
            copyRowAction->setToolTip(QStringLiteral("把选中行的全部列以制表符分隔复制到剪贴板"));
            copyRowAction->setEnabled(table->currentRow() >= 0);
            if (menu.exec(table->viewport()->mapToGlobal(localPosition)) == copyRowAction)
            {
                copyPteCurrentRow(table);
            }
        });
    }

    void setPteDiagnosticRow(
        QTableWidget* table,
        const QString& detailText)
    {
        // setPteDiagnosticRow：
        // - Input: target PTE table and diagnostic description;
        // - Processing: Write a copyable diagnostic line; store full text in UserRole+2.
        // - Return: None. Prevents null table issues when not yet attached, when the query is empty, or when risk filtering clears the data.
        if (table == nullptr)
        {
            return;
        }

        table->setRowCount(1);
        QTableWidgetItem* vaItem = makeReadOnlyItem(QStringLiteral("<无PTE证据>"));
        vaItem->setData(Qt::UserRole + 2, detailText);
        table->setItem(0, pteTranslateColumnIndex(PteTranslateColumn::kVirtualAddress), vaItem);
        table->setItem(0, pteTranslateColumnIndex(PteTranslateColumn::kRegionBase), makeReadOnlyItem(QStringLiteral("N/A")));
        table->setItem(0, pteTranslateColumnIndex(PteTranslateColumn::kValid), makeReadOnlyItem(QStringLiteral("-")));
        table->setItem(0, pteTranslateColumnIndex(PteTranslateColumn::kShared), makeReadOnlyItem(QStringLiteral("-")));
        table->setItem(0, pteTranslateColumnIndex(PteTranslateColumn::kLocked), makeReadOnlyItem(QStringLiteral("-")));
        table->setItem(0, pteTranslateColumnIndex(PteTranslateColumn::kLargePage), makeReadOnlyItem(QStringLiteral("-")));
        table->setItem(0, pteTranslateColumnIndex(PteTranslateColumn::kBad), makeReadOnlyItem(QStringLiteral("-")));
        table->setItem(0, pteTranslateColumnIndex(PteTranslateColumn::kShareCount), makeReadOnlyItem(QStringLiteral("0")));
        table->setItem(0, pteTranslateColumnIndex(PteTranslateColumn::kWin32Protection), makeReadOnlyItem(QStringLiteral("N/A")));
        table->setItem(0, pteTranslateColumnIndex(PteTranslateColumn::kNode), makeReadOnlyItem(QStringLiteral("0")));
        table->setItem(0, pteTranslateColumnIndex(PteTranslateColumn::kMappedFile), makeReadOnlyItem(QStringLiteral("N/A")));
        table->setItem(0, pteTranslateColumnIndex(PteTranslateColumn::kRisk), makeReadOnlyItem(detailText));
        table->setCurrentCell(0, pteTranslateColumnIndex(PteTranslateColumn::kVirtualAddress));
    }

    // All numeric columns now use ks::ui::NumericTableItem: sort values are written to NumericSortRole; the local
    // page-specific NumericItem with values in Qt::UserRole has been removed to avoid conflicts with UserRole
    // conventions on other pages and to eliminate the need for maintaining separate operator< implementations.

    // Generates multi-line text for the details window.
    QString buildPteDetailText(const MemoryDock::ProcessMemoryEvidenceEntry& entry)
    {
        QString text;
        text += QStringLiteral("PTE / VA 翻译详情\n");
        text += QStringLiteral("VirtualAddress: %1\n").arg(hex64(entry.virtualAddress));
        text += QStringLiteral("RegionBaseAddress: %1\n").arg(hex64(entry.regionBaseAddress));
        text += QStringLiteral("RegionSize: %1\n").arg(hex64(entry.regionSize));
        text += QStringLiteral("Protect: 0x%1\n").arg(entry.protect, 8, 16, QChar('0'));
        text += QStringLiteral("State: 0x%1\n").arg(entry.state, 8, 16, QChar('0'));
        text += QStringLiteral("Type: 0x%1\n").arg(entry.type, 8, 16, QChar('0'));
        text += QStringLiteral("Win32Protection: 0x%1\n").arg(entry.win32Protection, 8, 16, QChar('0'));
        text += QStringLiteral("ShareCount: %1\n").arg(entry.shareCount);
        text += QStringLiteral("Node: %1\n").arg(entry.node);
        text += QStringLiteral("Valid: %1\n").arg(entry.valid ? QStringLiteral("true") : QStringLiteral("false"));
        text += QStringLiteral("Shared: %1\n").arg(entry.shared ? QStringLiteral("true") : QStringLiteral("false"));
        text += QStringLiteral("Locked: %1\n").arg(entry.locked ? QStringLiteral("true") : QStringLiteral("false"));
        text += QStringLiteral("LargePage: %1\n").arg(entry.largePage ? QStringLiteral("true") : QStringLiteral("false"));
        text += QStringLiteral("Bad: %1\n").arg(entry.bad ? QStringLiteral("true") : QStringLiteral("false"));
        text += QStringLiteral("MappedFile: %1\n").arg(entry.mappedFilePath.isEmpty() ? QStringLiteral("—") : entry.mappedFilePath);
        text += QStringLiteral("Risk: %1\n").arg(entry.riskText);
        text += QStringLiteral("Detail: %1\n").arg(entry.detailText.isEmpty() ? QStringLiteral("—") : entry.detailText);
        return text;
    }
}

void MemoryDock::initializeProcessPteTranslateTab()
{
    // Input: None; called by initializeTabs.
    // Processing: Build the PTE/VA translation page, displaying only the read-only working set view of the currently attached process.
    // Returns: Nothing.
    KLogEvent initEvent;
    info << initEvent
        << "[MemoryDock] initializeProcessPteTranslateTab: 构建 PTE / VA 翻译页面。"
        << eol;

    tabProcessPteTranslate_ = new QWidget(tabWidget_);
    QVBoxLayout* tabLayout = new QVBoxLayout(tabProcessPteTranslate_);
    tabLayout->setContentsMargins(6, 6, 6, 6);
    tabLayout->setSpacing(6);

    // First layer (action row): contains only actions that provide immediate feedback upon clicking and status
    // echoes; all sampling granularity is delegated to the second layer's 'translation parameters' group.
    QHBoxLayout* actionLayout = new QHBoxLayout();
    actionLayout->setContentsMargins(0, 0, 0, 0);
    actionLayout->setSpacing(8);

    processPteTranslateRefreshButton_ = new QPushButton(QIcon(QStringLiteral(":/Icon/process_refresh.svg")), QStringLiteral("刷新"), tabProcessPteTranslate_);
    processPteTranslateRefreshButton_->setToolTip(QStringLiteral("基于当前附加进程采集 PTE / VA 翻译证据"));
    processPteTranslateRefreshButton_->setStyleSheet(buildBlueButtonStyle());

    // Vertical line separator: visually separates 'Execute Action' from 'View Filter' instead of cluttering them into a single row.
    QFrame* actionSeparator = new QFrame(tabProcessPteTranslate_);
    actionSeparator->setFrameShape(QFrame::VLine);
    actionSeparator->setFrameShadow(QFrame::Sunken);

    processPteTranslateRiskOnlyCheck_ = new QCheckBox(QStringLiteral("仅风险项"), tabProcessPteTranslate_);
    processPteTranslateRiskOnlyCheck_->setChecked(true);
    processPteTranslateRiskOnlyCheck_->setToolTip(QStringLiteral("只保留风险判定不为正常的页记录"));
    processPteTranslateRiskOnlyCheck_->setStyleSheet(QStringLiteral(
        "QCheckBox { color:%1; font-weight:600; }")
        .arg(ksword_theme::textPrimaryHex()));

    processPteTranslateStatusLabel_ = new QLabel(QStringLiteral("状态：等待刷新"), tabProcessPteTranslate_);
    processPteTranslateStatusLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    processPteTranslateStatusLabel_->setStyleSheet(QStringLiteral("color:%1; font-weight:600;").arg(ksword_theme::textSecondaryHex()));

    // Status label consumes remaining width (stretch=1); long status text won't push left-side actions away.
    actionLayout->addWidget(processPteTranslateRefreshButton_);
    actionLayout->addWidget(actionSeparator);
    actionLayout->addWidget(processPteTranslateRiskOnlyCheck_);
    actionLayout->addWidget(processPteTranslateStatusLabel_, 1);
    tabLayout->addLayout(actionLayout);

    // Second layer: sample parameter grouping, with separate text labels for the starting VA and
    // sample page count to avoid users guessing the meaning of an isolated "VA" abbreviation.
    QGroupBox* translateParameterGroup = new QGroupBox(QStringLiteral("翻译参数"), tabProcessPteTranslate_);
    QGridLayout* translateParameterLayout = new QGridLayout(translateParameterGroup);
    translateParameterLayout->setContentsMargins(10, 8, 10, 8);
    translateParameterLayout->setHorizontalSpacing(8);
    translateParameterLayout->setVerticalSpacing(6);

    // Parameter names use the secondary text color (dynamic token) to follow theme switches, creating a clear visual hierarchy against the input content.
    const QString kParameterCaptionStyle =
        QStringLiteral("color:%1;").arg(ksword_theme::textSecondaryHex());

    QLabel* addressCaption = new QLabel(QStringLiteral("起始虚拟地址"), translateParameterGroup);
    addressCaption->setStyleSheet(kParameterCaptionStyle);

    processPteTranslateAddressEdit_ = new QLineEdit(translateParameterGroup);
    processPteTranslateAddressEdit_->setClearButtonEnabled(true);
    processPteTranslateAddressEdit_->setPlaceholderText(QStringLiteral("输入 VA，例如 0x7FF6..."));
    processPteTranslateAddressEdit_->setToolTip(QStringLiteral("采样起点虚拟地址，留空则沿用查看器当前地址"));
    processPteTranslateAddressEdit_->setStyleSheet(buildBlueInputStyle());

    QLabel* pageCountCaption = new QLabel(QStringLiteral("采样页数"), translateParameterGroup);
    pageCountCaption->setStyleSheet(kParameterCaptionStyle);

    processPteTranslatePageCountSpin_ = new QSpinBox(translateParameterGroup);
    processPteTranslatePageCountSpin_->setRange(1, 256);
    processPteTranslatePageCountSpin_->setValue(16);
    processPteTranslatePageCountSpin_->setToolTip(QStringLiteral("每次采样的页数上限"));

    // Grid layout: Column 1 is reserved for the stretchable VA input field; the page count control retains its natural width and sticks to the right.
    translateParameterLayout->addWidget(addressCaption, 0, 0);
    translateParameterLayout->addWidget(processPteTranslateAddressEdit_, 0, 1);
    translateParameterLayout->addWidget(pageCountCaption, 0, 2);
    translateParameterLayout->addWidget(processPteTranslatePageCountSpin_, 0, 3);
    translateParameterLayout->setColumnStretch(1, 1);
    tabLayout->addWidget(translateParameterGroup);

    QSplitter* splitter = new QSplitter(Qt::Vertical, tabProcessPteTranslate_);
    tabLayout->addWidget(splitter, 1);

    processPteTranslateTable_ = new ks::ui::VisibleTableWidget(splitter);
    processPteTranslateTable_->setColumnCount(pteTranslateColumnIndex(PteTranslateColumn::kCount));
    processPteTranslateTable_->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("VA"),
        QStringLiteral("区域基址"),
        QStringLiteral("有效"),
        QStringLiteral("共享"),
        QStringLiteral("锁定"),
        QStringLiteral("大页"),
        QStringLiteral("坏页"),
        QStringLiteral("ShareCount"),
        QStringLiteral("Win32Prot"),
        QStringLiteral("Node"),
        QStringLiteral("映射文件"),
        QStringLiteral("风险")
    });
    processPteTranslateTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    processPteTranslateTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    processPteTranslateTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    processPteTranslateTable_->setAlternatingRowColors(true);
    processPteTranslateTable_->setSortingEnabled(true);
    processPteTranslateTable_->verticalHeader()->setVisible(false);
    processPteTranslateTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    processPteTranslateTable_->horizontalHeader()->setSectionResizeMode(pteTranslateColumnIndex(PteTranslateColumn::kMappedFile), QHeaderView::Stretch);
    installPteCopyMenu(processPteTranslateTable_);
    splitter->addWidget(processPteTranslateTable_);

    processPteTranslateDetailEditor_ = new CodeEditorWidget(splitter);
    processPteTranslateDetailEditor_->setReadOnly(true);
    processPteTranslateDetailEditor_->setText(QStringLiteral("请选择一条 PTE / VA 翻译记录查看详情。"));
    splitter->addWidget(processPteTranslateDetailEditor_);

    ks::ui::DetailLayoutRegistry::registerHost(
        processPteTranslateTable_,
        processPteTranslateDetailEditor_,
        tabProcessPteTranslate_);
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);

    tabWidget_->addTab(tabProcessPteTranslate_, QStringLiteral("PTE / VA 翻译"));
}

void MemoryDock::refreshProcessPteTranslateAsync()
{
    // Input: None; triggered by the refresh button or tab routing.
    // Handling: Sample QueryWorkingSetEx / VirtualQueryEx results based on the currently attached process and input VA.
    // Returns: Nothing.
    if (processPteTranslateRefreshInProgress_.exchange(true))
    {
        return;
    }

    KLogEvent refreshEvent;
    info << refreshEvent
        << "[MemoryDock] refreshProcessPteTranslateAsync: 开始解析页表，刷新按钮已置灰。"
        << eol;

    // Before starting collection, provide immediate feedback: disable the button to prevent repeated clicks and set the status label to 'Parsing page tables...'.
    if (processPteTranslateRefreshButton_ != nullptr)
    {
        processPteTranslateRefreshButton_->setEnabled(false);
    }
    if (processPteTranslateStatusLabel_ != nullptr)
    {
        processPteTranslateStatusLabel_->setText(QStringLiteral("状态：正在解析页表…"));
        processPteTranslateStatusLabel_->setStyleSheet(
            QStringLiteral("color:%1; font-weight:600;").arg(ksword_theme::kPrimaryBlueHex));
    }

    if (attachedProcessHandle_ == nullptr || attachedPid_ == 0U)
    {
        // Exit immediately if not attached: the button was grayed out above; it must be restored here, otherwise the page becomes permanently unclickable.
        processPteTranslateRefreshInProgress_.store(false);
        if (processPteTranslateRefreshButton_ != nullptr)
        {
            processPteTranslateRefreshButton_->setEnabled(true);
        }
        if (processPteTranslateStatusLabel_ != nullptr)
        {
            processPteTranslateStatusLabel_->setText(QStringLiteral("状态：请先附加进程。"));
            processPteTranslateStatusLabel_->setStyleSheet(
                QStringLiteral("color:%1; font-weight:600;")
                    .arg(ksword_theme::errorColor().name(QColor::HexRgb)));
        }
        return;
    }

    std::uint32_t duplicateError = ERROR_SUCCESS;
    const std::shared_ptr<void> kProcessHandleLease =
        duplicateAttachedProcessHandleForWorker(&duplicateError);
    if (!kProcessHandleLease)
    {
        processPteTranslateRefreshInProgress_.store(false);
        if (processPteTranslateRefreshButton_ != nullptr)
        {
            processPteTranslateRefreshButton_->setEnabled(true);
        }
        if (processPteTranslateStatusLabel_ != nullptr)
        {
            processPteTranslateStatusLabel_->setText(
                QStringLiteral("状态：复制进程句柄失败（Win32=%1）。").arg(duplicateError));
            processPteTranslateStatusLabel_->setStyleSheet(
                QStringLiteral("color:%1; font-weight:600;")
                    .arg(ksword_theme::errorColor().name(QColor::HexRgb)));
        }
        return;
    }

    // The button and status are set uniformly at the function entry; no need to reissue here, directly retrieve the sampling parameters.
    std::uint64_t baseAddress = 0ULL;
    if (processPteTranslateAddressEdit_ != nullptr)
    {
        const QString kInputText = processPteTranslateAddressEdit_->text().trimmed();
        if (!kInputText.isEmpty())
        {
            parseAddressText(kInputText, baseAddress);
        }
    }
    if (baseAddress == 0ULL)
    {
        baseAddress = currentViewerAddress_;
    }
    const std::uint32_t kPageCount = processPteTranslatePageCountSpin_ != nullptr
        ? static_cast<std::uint32_t>(processPteTranslatePageCountSpin_->value())
        : 16U;

    const std::uint64_t kTicket = processPteTranslateRefreshTicket_.fetch_add(1U) + 1U;
    const std::uint64_t kAttachmentGeneration = processAttachmentGeneration_.load();
    const std::uint32_t kPid = attachedPid_;
    const QPointer<MemoryDock> kGuardThis(this);

    std::thread([kGuardThis,
                 kProcessHandleLease,
                 kTicket,
                 kAttachmentGeneration,
                 kPid,
                 baseAddress,
                 kPageCount]() {
        const HANDLE kWorkerProcessHandle = static_cast<HANDLE>(kProcessHandleLease.get());
        std::vector<ProcessMemoryEvidenceEntry> entries;
        entries.reserve(kPageCount);

        MEMORY_BASIC_INFORMATION mbi{};
        SYSTEM_INFO systemInfo{};
        ::GetSystemInfo(&systemInfo);
        const std::uint64_t kPageSize = static_cast<std::uint64_t>(systemInfo.dwPageSize);
        const std::uint64_t kAlignedBase = kPageSize == 0ULL ? baseAddress : (baseAddress / kPageSize) * kPageSize;

        for (std::uint32_t index = 0; index < kPageCount; ++index)
        {
            const std::uint64_t kVa = kAlignedBase + (static_cast<std::uint64_t>(index) * kPageSize);
            if (kVa < kAlignedBase)
            {
                break;
            }

            if (::VirtualQueryEx(
                    kWorkerProcessHandle,
                    reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(kVa)),
                    &mbi,
                    sizeof(mbi)) != sizeof(mbi))
            {
                break;
            }

            PSAPI_WORKING_SET_EX_INFORMATION wsInfo{};
            wsInfo.VirtualAddress = reinterpret_cast<PVOID>(static_cast<std::uintptr_t>(kVa));
            const BOOL kQueryOk = ::QueryWorkingSetEx(
                kWorkerProcessHandle,
                &wsInfo,
                static_cast<DWORD>(sizeof(wsInfo)));

            ProcessMemoryEvidenceEntry entry{};
            entry.virtualAddress = kVa;
            entry.regionBaseAddress = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            entry.regionSize = static_cast<std::uint64_t>(mbi.RegionSize);
            entry.protect = static_cast<std::uint32_t>(mbi.Protect);
            entry.state = static_cast<std::uint32_t>(mbi.State);
            entry.type = static_cast<std::uint32_t>(mbi.Type);
            entry.mappedFilePath = mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED
                ? QStringLiteral("")
                : QString();

            if (kQueryOk != FALSE)
            {
                const auto kFlags = wsInfo.VirtualAttributes.Flags;
                entry.valid = wsInfo.VirtualAttributes.Valid != 0;
                entry.shareCount = static_cast<std::uint32_t>(wsInfo.VirtualAttributes.ShareCount);
                entry.win32Protection = static_cast<std::uint32_t>(wsInfo.VirtualAttributes.Win32Protection);
                entry.shared = wsInfo.VirtualAttributes.Shared != 0;
                entry.node = static_cast<std::uint32_t>(wsInfo.VirtualAttributes.Node);
                entry.locked = wsInfo.VirtualAttributes.Locked != 0;
                entry.largePage = wsInfo.VirtualAttributes.LargePage != 0;
                entry.bad = wsInfo.VirtualAttributes.Bad != 0;
                Q_UNUSED(kFlags);
            }

            entry.riskText = buildPteRiskText(entry.protect, entry.valid, entry.bad, entry.largePage);
            entry.detailText = QStringLiteral("PID=%1 | VA=%2 | Base=%3 | Size=%4")
                .arg(kPid)
                .arg(hex64(entry.virtualAddress))
                .arg(hex64(entry.regionBaseAddress))
                .arg(hex64(entry.regionSize));
            entries.push_back(std::move(entry));
        }

        QMetaObject::invokeMethod(
            kGuardThis.data(),
            [kGuardThis, kTicket, kAttachmentGeneration, entries = std::move(entries)]() mutable {
                auto entriesSnapshot =
                    std::make_shared<std::vector<ProcessMemoryEvidenceEntry>>(std::move(entries));
                auto commitSnapshot = [kGuardThis, kTicket, kAttachmentGeneration, entriesSnapshot]() mutable
                {
                    if (kGuardThis == nullptr)
                    {
                        return;
                    }

                    // Regardless of snapshot expiration, once back on the main thread, remove the 'refresh in progress' state first.
                    // The old implementation placed recovery after ticket validation; re-attaching the process would permanently disable the button.
                    kGuardThis->processPteTranslateRefreshInProgress_.store(false);
                    if (kGuardThis->processPteTranslateRefreshButton_ != nullptr)
                    {
                        kGuardThis->processPteTranslateRefreshButton_->setEnabled(true);
                    }

                    if (kTicket != kGuardThis->processPteTranslateRefreshTicket_.load() ||
                        kAttachmentGeneration != kGuardThis->processAttachmentGeneration_.load())
                    {
                        return;
                    }

                    kGuardThis->processPteTranslateCache_ = std::move(*entriesSnapshot);
                    kGuardThis->rebuildProcessPteTranslateTable();
                    kGuardThis->showProcessPteTranslateDetailByCurrentRow();

                    if (kGuardThis->processPteTranslateStatusLabel_ != nullptr)
                    {
                        kGuardThis->processPteTranslateStatusLabel_->setText(
                            QStringLiteral("状态：采样 %1 行").arg(kGuardThis->processPteTranslateCache_.size()));
                        kGuardThis->processPteTranslateStatusLabel_->setStyleSheet(QStringLiteral(
                            "color:%1; font-weight:600;")
                            .arg(kGuardThis->processPteTranslateCache_.empty()
                                ? ksword_theme::errorColor().name(QColor::HexRgb)
                                : ksword_theme::successColor().name(QColor::HexRgb)));
                    }
                };

                if (ks::ui::deferTableUiCommitIfContextMenuOpen(
                    kGuardThis.data(),
                    QStringLiteral("memory-process-pte-snapshot"),
                    { kGuardThis->processPteTranslateTable_ },
                    commitSnapshot))
                {
                    return;
                }
                commitSnapshot();
            },
            Qt::QueuedConnection);
    }).detach();
}

void MemoryDock::rebuildProcessPteTranslateTable()
{
    ks::ui::DetailLayoutRegistry::prepareDataRebuild(processPteTranslateDetailEditor_);
    // Input: Read the current cache and risk filter switch.
    // Processing: Project the Tab9 cache into the table and retain sort-friendly numeric columns.
    // Returns: Nothing.
    if (processPteTranslateTable_ == nullptr)
    {
        return;
    }

    const bool kRiskOnly = processPteTranslateRiskOnlyCheck_ != nullptr && processPteTranslateRiskOnlyCheck_->isChecked();
    std::vector<const ProcessMemoryEvidenceEntry*> visibleEntries;
    visibleEntries.reserve(processPteTranslateCache_.size());
    for (const ProcessMemoryEvidenceEntry& entry : processPteTranslateCache_)
    {
        if (kRiskOnly && entry.riskText == QStringLiteral("正常"))
        {
            continue;
        }
        visibleEntries.push_back(&entry);
    }

    // Disable sorting before bulk-filling the table: otherwise, Qt re-sorts after every cell write, which is slow and scrambles row indices.
    processPteTranslateVisibleCount_ = visibleEntries.size();
    const QSignalBlocker kBlocker(processPteTranslateTable_);
    processPteTranslateTable_->setSortingEnabled(false);
    processPteTranslateTable_->setRowCount(static_cast<int>(visibleEntries.size()));
    for (int row = 0; row < static_cast<int>(visibleEntries.size()); ++row)
    {
        const ProcessMemoryEvidenceEntry& entry = *visibleEntries[static_cast<std::size_t>(row)];
        // Address column: displays 16-hex text, sorts by actual 64-bit numeric value, avoiding degradation to string order.
        processPteTranslateTable_->setItem(row, pteTranslateColumnIndex(PteTranslateColumn::kVirtualAddress), new ks::ui::NumericTableItem(hex64(entry.virtualAddress), static_cast<qulonglong>(entry.virtualAddress)));
        processPteTranslateTable_->setItem(row, pteTranslateColumnIndex(PteTranslateColumn::kRegionBase), new ks::ui::NumericTableItem(hex64(entry.regionBaseAddress), static_cast<qulonglong>(entry.regionBaseAddress)));
        processPteTranslateTable_->setItem(row, pteTranslateColumnIndex(PteTranslateColumn::kValid), makeReadOnlyItem(entry.valid ? QStringLiteral("Yes") : QStringLiteral("No")));
        processPteTranslateTable_->setItem(row, pteTranslateColumnIndex(PteTranslateColumn::kShared), makeReadOnlyItem(entry.shared ? QStringLiteral("Yes") : QStringLiteral("No")));
        processPteTranslateTable_->setItem(row, pteTranslateColumnIndex(PteTranslateColumn::kLocked), makeReadOnlyItem(entry.locked ? QStringLiteral("Yes") : QStringLiteral("No")));
        processPteTranslateTable_->setItem(row, pteTranslateColumnIndex(PteTranslateColumn::kLargePage), makeReadOnlyItem(entry.largePage ? QStringLiteral("Yes") : QStringLiteral("No")));
        processPteTranslateTable_->setItem(row, pteTranslateColumnIndex(PteTranslateColumn::kBad), makeReadOnlyItem(entry.bad ? QStringLiteral("Yes") : QStringLiteral("No")));
        // Reference counts, protection attribute bitmaps, and NUMA nodes are also numeric columns, all assigned NumericSortRole.
        processPteTranslateTable_->setItem(row, pteTranslateColumnIndex(PteTranslateColumn::kShareCount), new ks::ui::NumericTableItem(QString::number(entry.shareCount), static_cast<qulonglong>(entry.shareCount)));
        processPteTranslateTable_->setItem(row, pteTranslateColumnIndex(PteTranslateColumn::kWin32Protection), new ks::ui::NumericTableItem(QStringLiteral("0x%1").arg(entry.win32Protection, 8, 16, QChar('0')).toUpper(), static_cast<qulonglong>(entry.win32Protection)));
        processPteTranslateTable_->setItem(row, pteTranslateColumnIndex(PteTranslateColumn::kNode), new ks::ui::NumericTableItem(QString::number(entry.node), static_cast<qulonglong>(entry.node)));
        processPteTranslateTable_->setItem(row, pteTranslateColumnIndex(PteTranslateColumn::kMappedFile), makeReadOnlyItem(entry.mappedFilePath.isEmpty() ? QStringLiteral("—") : entry.mappedFilePath));
        processPteTranslateTable_->setItem(row, pteTranslateColumnIndex(PteTranslateColumn::kRisk), makeReadOnlyItem(entry.riskText));
    }
    if (visibleEntries.empty())
    {
        const QString kDetailText = processPteTranslateCache_.empty()
            ? QStringLiteral("PTE / VA 翻译当前没有缓存行；请先附加进程、输入或定位 VA 后刷新。")
            : QStringLiteral("当前风险过滤隐藏了全部 %1 条 PTE / VA 翻译记录；请关闭“仅风险项”。")
                .arg(static_cast<qulonglong>(processPteTranslateCache_.size()));
        setPteDiagnosticRow(processPteTranslateTable_, kDetailText);
    }

    if (processPteTranslateTable_->rowCount() > 0 && processPteTranslateTable_->currentRow() < 0)
    {
        processPteTranslateTable_->setCurrentCell(0, pteTranslateColumnIndex(PteTranslateColumn::kVirtualAddress));
    }
    // Enable sorting only after the table is filled, paired with the earlier setSortingEnabled(false) to bracket the operation.
    processPteTranslateTable_->setSortingEnabled(true);
    ks::ui::requestTableColumnAutoFit(processPteTranslateTable_);
}

void MemoryDock::showProcessPteTranslateDetailByCurrentRow()
{
    // Input: None. Reads the currently selected row in the table.
    // Note: Unwind the current record from the cache into the CodeEditorWidget.
    // Returns: Nothing.
    if (processPteTranslateDetailEditor_ == nullptr || processPteTranslateTable_ == nullptr)
    {
        return;
    }

    const int kRow = processPteTranslateTable_->currentRow();
    if (kRow < 0 || kRow >= processPteTranslateTable_->rowCount())
    {
        processPteTranslateDetailEditor_->setText(QStringLiteral("请选择一条 PTE / VA 翻译记录查看详情。"));
        return;
    }

    const QTableWidgetItem* addressItem = processPteTranslateTable_->item(kRow, pteTranslateColumnIndex(PteTranslateColumn::kVirtualAddress));
    if (addressItem == nullptr)
    {
        return;
    }
    const QString kDiagnosticText = addressItem->data(Qt::UserRole + 2).toString();
    if (!kDiagnosticText.isEmpty())
    {
        processPteTranslateDetailEditor_->setText(QStringLiteral("PTE / VA 翻译诊断\n%1").arg(kDiagnosticText));
        return;
    }

    // The reverse lookup key is migrated along with the table-filling side to NumericSortRole:
    // NumericTableItem stores the actual numeric value in Qt::UserRole + 900; reading from Qt::UserRole will never retrieve the value.
    bool ok = false;
    const qulonglong kAddressValue = addressItem->data(ks::ui::kNumericSortRole).toULongLong(&ok);
    if (!ok)
    {
        return;
    }

    for (const ProcessMemoryEvidenceEntry& entry : processPteTranslateCache_)
    {
        if (entry.virtualAddress == static_cast<std::uint64_t>(kAddressValue))
        {
            processPteTranslateDetailEditor_->setText(buildPteDetailText(entry));
            return;
        }
    }
}
