#include "ProcessDock.h"
#include "../internationalization/LanguageManager.h"
#include "../ui/VisibleTableWidget.h"

#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../ui/CodeEditorWidget.h"
#include "../ui/TableColumnAutoFit.h"
#include "../ui/TableInteractionSupport.h"
#include "../Theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QCheckBox>
#include <QClipboard>
#include <QGuiApplication>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMetaObject>
#include <QModelIndex>
#include <QPointer>
#include <QPushButton>
#include <QSignalBlocker>
#include <QSplitter>
#include <QTabWidget>
#include <QSize>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QThreadPool>
#include <QVBoxLayout>

#include <algorithm>
#include <cstdint>
#include <functional>
#include <limits>
#include <sstream>

namespace
{
    enum class CrossViewColumn : int
    {
        kId = 0,
        kObject,
        kProcess,
        kPublic,
        kActiveOrThreadList,
        kAnomaly,
        kConfidence,
        kDetail,
        kCount
    };

    int columnIndex(const CrossViewColumn column)
    {
        // Input: Cross-View table column enumeration.
        // Handling: Convert to Qt table column index.
        // Return: column index.
        return static_cast<int>(column);
    }

    QString hex64(const std::uint64_t value)
    {
        // Input: Address or capability value.
        // Processing: Format as uppercase hexadecimal with 0x prefix.
        // Return: Display text.
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(value), 16, 16, QChar('0'))
            .toUpper();
    }

    QString sourceYesNo(const std::uint32_t sourceMask, const std::uint32_t bit)
    {
        // Input: Source matrix sourceMask and target bit.
        // Processing: Map to checkmark text.
        // Return: Yes/No.
        return (sourceMask & bit) ? QStringLiteral("是") : QStringLiteral("-");
    }

    QString anomalyText(const std::uint32_t flags)
    {
        // Input: KSWORD_ARK_CROSSVIEW_ANOMALY_* bitset.
        // Processing: Convert to short labels for consistent semantics in ProcessDock/MonitorDock.
        // Returns: exception text; returns "Normal" if no exception.
        if (flags == 0U)
        {
            return QStringLiteral("正常");
        }
        QStringList parts;
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_CID_ONLY) parts << QStringLiteral("仅单源");
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_ACTIVE_ONLY) parts << QStringLiteral("Active-only");
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_MISSING_FROM_ACTIVE_LIST) parts << QStringLiteral("缺活跃源");
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_MISSING_FROM_CID_TABLE) parts << QStringLiteral("缺辅助源");
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_THREAD_ORPHAN) parts << QStringLiteral("孤儿线程");
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_THREAD_NOT_IN_PROCESS_LIST) parts << QStringLiteral("线程进程缺失");
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_START_ADDRESS_OUTSIDE_MODULE) parts << QStringLiteral("入口出模块");
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_DANGLING_OBJECT) parts << QStringLiteral("悬空对象");
        return parts.join(QStringLiteral(" | "));
    }

    // friendlyDriverDetail：
    // - Input rawDetail: raw detail field returned by R0;
    // - Processing: Convert common protocol/IO strings into human-readable descriptions.
    // - Returns: The short description ready for display in the last column of the table.
    QString friendlyDriverDetail(const QString& rawDetail)
    {
        const QString kTrimmedText = rawDetail.trimmed();
        if (kTrimmedText.isEmpty())
        {
            return QStringLiteral("驱动未返回额外说明");
        }
        if (kTrimmedText.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动调用失败或协议版本不匹配");
        }
        if (kTrimmedText.contains(QStringLiteral("unsupported"), Qt::CaseInsensitive) ||
            kTrimmedText.contains(QStringLiteral("not supported"), Qt::CaseInsensitive))
        {
            return QStringLiteral("当前驱动不支持该 cross-view 查询");
        }
        if (kTrimmedText.contains(QStringLiteral("capability"), Qt::CaseInsensitive) ||
            kTrimmedText.contains(QStringLiteral("DynData"), Qt::CaseInsensitive))
        {
            return QStringLiteral("动态偏移能力未完全满足，请查看详情区的 capability/DynData 信息");
        }
        return kTrimmedText.left(180);
    }

    // crossViewTableDetail：
    // - Input: isThread/sourceMask/anomalyFlags/confidence/rawDetail represent key information for the current cross-view row;
    // - Processing: Generate summary for the last column of the table to avoid inserting raw R0 strings directly.
    // - Returns: a line of Chinese description; the original detail remains fully displayed in the detail area.
    QString crossViewTableDetail(
        const bool isThread,
        const std::uint32_t sourceMask,
        const std::uint32_t anomalyFlags,
        const std::uint32_t confidence,
        const QString& rawDetail)
    {
        const std::uint32_t kListBit = isThread
            ? KSWORD_ARK_CROSSVIEW_SOURCE_THREAD_LIST
            : KSWORD_ARK_CROSSVIEW_SOURCE_ACTIVE_LIST;
        const QString kObjectKindText = isThread ? QStringLiteral("线程") : QStringLiteral("进程");
        const QString kSourceText = QStringLiteral("PublicWalk=%1，%2=%3")
            .arg(sourceYesNo(sourceMask, KSWORD_ARK_CROSSVIEW_SOURCE_PUBLIC_WALK))
            .arg(isThread ? QStringLiteral("ThreadList") : QStringLiteral("ActiveList"))
            .arg(sourceYesNo(sourceMask, kListBit));
        const QString kAnomalySummaryText = anomalyFlags == 0U
            ? QStringLiteral("未发现 cross-view 异常")
            : QStringLiteral("异常：%1").arg(anomalyText(anomalyFlags));

        return QStringLiteral("%1；%2；%3；置信度 %4；%5")
            .arg(kObjectKindText)
            .arg(kSourceText)
            .arg(kAnomalySummaryText)
            .arg(confidence)
            .arg(friendlyDriverDetail(rawDetail));
    }

    QString narrowToQString(const std::string& value)
    {
        // Input: narrow string from ArkDriverClient.
        // Processing: Convert using UTF-8; in failure scenarios, Qt retains displayable replacement characters.
        // Return: QString.
        return QString::fromStdString(value);
    }

    class NumericItem final : public QTableWidgetItem
    {
    public:
        NumericItem(const QString& text, const qulonglong value)
            : QTableWidgetItem(text)
        {
            // Input: display text and sort value.
            // Processing: Write numeric value to UserRole, keep text as is.
            // Returns: Constructor has no return value.
            setData(Qt::UserRole, QVariant::fromValue<qulonglong>(value));
            setTextAlignment(Qt::AlignVCenter | Qt::AlignLeft);
        }

        bool operator<(const QTableWidgetItem& other) const override
        {
            // Input: the other cell.
            // Handling: prioritize sorting by UserRole values.
            // Returns: true if the current item is smaller.
            bool leftOk = false;
            bool rightOk = false;
            const qulonglong kLeftValue = data(Qt::UserRole).toULongLong(&leftOk);
            const qulonglong kRightValue = other.data(Qt::UserRole).toULongLong(&rightOk);
            if (leftOk && rightOk)
            {
                return kLeftValue < kRightValue;
            }
            return QTableWidgetItem::operator<(other);
        }
    };

    QTableWidgetItem* textItem(const QString& value)
    {
        // Input: display text.
        // Processing: Create a read-only cell item.
        // Returns: An item handed over to QTableWidget for lifecycle management.
        QTableWidgetItem* item = new QTableWidgetItem(value);
        item->setTextAlignment(Qt::AlignVCenter | Qt::AlignLeft);
        return item;
    }

    QTableWidgetItem* numericItem(const QString& text, const qulonglong value)
    {
        // Input: Display text and sort value.
        // Processing: Create a cell sortable by numeric value.
        // Returns: An item handed over to QTableWidget for lifecycle management.
        return new NumericItem(text, value);
    }

    QString crossViewTableCellText(QTableWidget* table, const int rowIndex, const int columnIndex)
    {
        // crossViewTableCellText：
        // - Input: Cross-View table, row index, column index;
        // - Processing: Safely read cell text;
        // - Return: empty string if the cell does not exist.
        if (table == nullptr)
        {
            return QString();
        }
        const QTableWidgetItem* item = table->item(rowIndex, columnIndex);
        return item != nullptr ? item->text() : QString();
    }

    QString crossViewEmptyStateDetail(
        const QString& titleText,
        const bool ioOk,
        const bool unsupported,
        const std::size_t cacheCount,
        const std::uint32_t returnedCount,
        const std::uint32_t totalCount,
        const std::uint64_t missingCapabilityMask,
        const QString& rawMessageText)
    {
        // crossViewEmptyStateDetail：
        // - Input: IO status, count, and original message for a single cross-view wrapper;
        // - Processing: Generate full description for the table empty-state diagnostic row;
        // - Returns: human-readable text suitable for the details area or the last column of a table.
        if (cacheCount > 0U)
        {
            return QStringLiteral("%1：当前过滤条件隐藏了全部 %2 条缓存记录；请清空过滤或关闭“仅异常”。")
                .arg(titleText)
                .arg(static_cast<qulonglong>(cacheCount));
        }

        QString stateText;
        if (ioOk)
        {
            stateText = QStringLiteral("驱动接口可用，但本次没有返回结构化行");
        }
        else if (unsupported)
        {
            stateText = QStringLiteral("当前驱动/协议暂不支持该 Cross-View 查询");
        }
        else
        {
            stateText = QStringLiteral("驱动查询暂不可用");
        }

        return QStringLiteral("%1：%2；驱动报告 %3/%4 行；missingCapability=%5；说明=%6")
            .arg(titleText)
            .arg(stateText)
            .arg(returnedCount)
            .arg(totalCount)
            .arg(hex64(missingCapabilityMask))
            .arg(friendlyDriverDetail(rawMessageText));
    }

    void setCrossViewDiagnosticRow(
        QTableWidget* table,
        const QString& idText,
        const QString& anomalyText,
        const QString& detailText)
    {
        // setCrossViewDiagnosticRow：
        // - Input: Target table, first column hint, exception column hint, and detail text;
        // - Processing: Write a single non-editable diagnostic row; save full details at UserRole + 2.
        // - Returns: None. Used to prevent the table from becoming completely empty due to null results or filtered null results from R0.
        if (table == nullptr)
        {
            return;
        }

        table->setRowCount(1);
        QTableWidgetItem* idItem = textItem(idText);
        idItem->setData(Qt::UserRole + 2, detailText);
        table->setItem(0, columnIndex(CrossViewColumn::kId), idItem);
        table->setItem(0, columnIndex(CrossViewColumn::kObject), textItem(QStringLiteral("N/A")));
        table->setItem(0, columnIndex(CrossViewColumn::kProcess), textItem(QStringLiteral("N/A")));
        table->setItem(0, columnIndex(CrossViewColumn::kPublic), textItem(QStringLiteral("-")));
        table->setItem(0, columnIndex(CrossViewColumn::kActiveOrThreadList), textItem(QStringLiteral("-")));
        table->setItem(0, columnIndex(CrossViewColumn::kAnomaly), textItem(anomalyText));
        table->setItem(0, columnIndex(CrossViewColumn::kConfidence), numericItem(QStringLiteral("0"), 0));
        table->setItem(0, columnIndex(CrossViewColumn::kDetail), textItem(detailText));
        table->setCurrentCell(0, columnIndex(CrossViewColumn::kId));
    }

    void copyCrossViewCurrentRow(QTableWidget* table)
    {
        // copyCrossViewCurrentRow：
        // - Input: Process/Thread Cross-View table;
        // - Processing: Copy the current row as TSV;
        // - Return: None. Only writes to the clipboard; no R0 operations are triggered.
        if (table == nullptr || QGuiApplication::clipboard() == nullptr)
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
            fields.push_back(crossViewTableCellText(table, kRowIndex, columnIndex));
        }
        QGuiApplication::clipboard()->setText(fields.join(QLatin1Char('\t')));
    }

    void installCrossViewContextMenu(
        QTableWidget* table,
        const std::function<quint32(const QTableWidget*, int)>& processIdForRow)
    {
        // installCrossViewContextMenu：
        // - Input: Cross-View table.
        // - Processing: Install right-click menu for copying current row and jumping to details by PID from the table.
        // - Returns: Nothing.
        if (table == nullptr)
        {
            return;
        }

        table->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(table, &QTableWidget::customContextMenuRequested, table, [table, processIdForRow](const QPoint& localPosition) {
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
            const quint32 kProcessId = processIdForRow != nullptr
                ? processIdForRow(table, table->currentRow())
                : 0U;
            QAction* openProcessAction = contextMenu.addAction(
                QIcon(QStringLiteral(":/Icon/process_details.svg")),
                QStringLiteral("转到进程详细信息"));
            openProcessAction->setEnabled(kProcessId != 0U);

            QAction* selectedAction = contextMenu.exec(table->viewport()->mapToGlobal(localPosition));
            if (selectedAction == copyRowAction)
            {
                copyCrossViewCurrentRow(table);
            }
            else if (selectedAction == openProcessAction)
            {
                ks::ui::openProcessDetailByPid(kProcessId);
            }
        });
    }

    bool textContainsFilter(const QStringList& fields, const QString& filter)
    {
        // Input: Field set to match and filter text.
        // Handling: Case-insensitive contains.
        // Returns: true if the filter matches.
        if (filter.isEmpty())
        {
            return true;
        }
        for (const QString& field : fields)
        {
            if (field.contains(filter, Qt::CaseInsensitive))
            {
                return true;
            }
        }
        return false;
    }

    QString offsetsText(const ksword::ark::CrossViewFieldOffsets& offsets)
    {
        // Input: Snapshot of DynData offsets returned by R0.
        // Processing: Expand into multi-line diagnostic text.
        // Returns: Copyable offset descriptions.
        QString text;
        text += QStringLiteral("EPROCESS.UniqueProcessId: 0x%1\n").arg(offsets.epUniqueProcessId, 8, 16, QChar('0'));
        text += QStringLiteral("EPROCESS.ActiveProcessLinks: 0x%1\n").arg(offsets.epActiveProcessLinks, 8, 16, QChar('0'));
        text += QStringLiteral("EPROCESS.ThreadListHead: 0x%1\n").arg(offsets.epThreadListHead, 8, 16, QChar('0'));
        text += QStringLiteral("EPROCESS.ImageFileName: 0x%1\n").arg(offsets.epImageFileName, 8, 16, QChar('0'));
        text += QStringLiteral("ETHREAD.ThreadListEntry: 0x%1\n").arg(offsets.etThreadListEntry, 8, 16, QChar('0'));
        text += QStringLiteral("ETHREAD.StartAddress: 0x%1\n").arg(offsets.etStartAddress, 8, 16, QChar('0'));
        text += QStringLiteral("KTHREAD.Process: 0x%1\n").arg(offsets.ktProcess, 8, 16, QChar('0'));
        return text;
    }
}

void ProcessDock::initializeCrossViewPage()
{
    // Input: None; called by initializeUi.
    // Note: create the Cross-View page to display the process and thread origin matrix.
    // Returns: Nothing.
    crossViewPage_ = new QWidget(this);
    crossViewPageLayout_ = new QVBoxLayout(crossViewPage_);
    crossViewPageLayout_->setContentsMargins(6, 6, 6, 6);
    crossViewPageLayout_->setSpacing(6);

    crossViewTopLayout_ = new QHBoxLayout();
    crossViewTopLayout_->setContentsMargins(0, 0, 0, 0);
    crossViewTopLayout_->setSpacing(8);

    crossViewRefreshButton_ = new QPushButton(QIcon(QStringLiteral(":/Icon/process_refresh.svg")), QString(), crossViewPage_);
    ksword_theme::applyStandardIconButtonMetrics(crossViewRefreshButton_);
    crossViewRefreshButton_->setToolTip(QStringLiteral("查询 R0 Process/Thread Cross-View 证据"));

    crossViewSearchEdit_ = new QLineEdit(crossViewPage_);
    crossViewSearchEdit_->setClearButtonEnabled(true);
    crossViewSearchEdit_->setPlaceholderText(QStringLiteral("过滤 PID/TID/进程名/异常/详情"));

    crossViewAnomalyOnlyCheck_ = new QCheckBox(QStringLiteral("仅异常"), crossViewPage_);
    crossViewAnomalyOnlyCheck_->setChecked(true);

    crossViewStatusLabel_ = new QLabel(QStringLiteral("状态：等待刷新"), crossViewPage_);
    crossViewStatusLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    crossViewStatusLabel_->setStyleSheet(QStringLiteral("color:%1; font-weight:600;").arg(ksword_theme::textSecondaryHex()));

    crossViewTopLayout_->addWidget(crossViewRefreshButton_);
    crossViewTopLayout_->addWidget(crossViewAnomalyOnlyCheck_);
    crossViewTopLayout_->addWidget(crossViewSearchEdit_, 1);
    crossViewTopLayout_->addWidget(crossViewStatusLabel_);
    crossViewPageLayout_->addLayout(crossViewTopLayout_);

    QSplitter* splitter = new QSplitter(Qt::Vertical, crossViewPage_);
    crossViewPageLayout_->addWidget(splitter, 1);

    QTabWidget* innerTabs = new QTabWidget(splitter);
    processCrossViewTable_ = new ks::ui::VisibleTableWidget(innerTabs);
    threadCrossViewTable_ = new ks::ui::VisibleTableWidget(innerTabs);
    for (QTableWidget* table : { processCrossViewTable_, threadCrossViewTable_ })
    {
        table->setColumnCount(columnIndex(CrossViewColumn::kCount));
        table->setHorizontalHeaderLabels(QStringList{
            QStringLiteral("ID"),
            QStringLiteral("对象"),
            QStringLiteral("进程"),
            QStringLiteral("PublicWalk"),
            QStringLiteral("Active/ThreadList"),
            QStringLiteral("异常"),
            QStringLiteral("置信度"),
            QStringLiteral("说明")
            });
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setSelectionMode(QAbstractItemView::SingleSelection);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table->setAlternatingRowColors(true);
        table->setSortingEnabled(true);
        table->verticalHeader()->setVisible(false);
        table->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
        table->horizontalHeader()->setSectionResizeMode(columnIndex(CrossViewColumn::kDetail), QHeaderView::Stretch);
    }
    installCrossViewContextMenu(
        processCrossViewTable_,
        [](const QTableWidget* table, const int rowIndex)
        {
            const QTableWidgetItem* processIdItem = table != nullptr
                ? table->item(rowIndex, columnIndex(CrossViewColumn::kId))
                : nullptr;
            bool ok = false;
            const qulonglong kProcessId = processIdItem != nullptr
                ? processIdItem->data(Qt::UserRole).toULongLong(&ok)
                : 0ULL;
            return ok && kProcessId <= std::numeric_limits<quint32>::max()
                ? static_cast<quint32>(kProcessId)
                : 0U;
        });
    installCrossViewContextMenu(
        threadCrossViewTable_,
        [this](const QTableWidget* table, const int rowIndex)
        {
            const QTableWidgetItem* threadIdItem = table != nullptr
                ? table->item(rowIndex, columnIndex(CrossViewColumn::kId))
                : nullptr;
            bool ok = false;
            const qulonglong kCacheIndex = threadIdItem != nullptr
                ? threadIdItem->data(Qt::UserRole + 1).toULongLong(&ok)
                : 0ULL;
            if (!ok || kCacheIndex >= static_cast<qulonglong>(threadCrossViewCache_.size()))
            {
                return 0U;
            }
            return static_cast<quint32>(threadCrossViewCache_[static_cast<std::size_t>(kCacheIndex)].processId);
        });
    innerTabs->addTab(processCrossViewTable_, QStringLiteral("Process Cross-View"));
    innerTabs->addTab(threadCrossViewTable_, QStringLiteral("Thread Cross-View"));
    ks::i18n::LanguageManager::instance().bindTab(
        innerTabs,
        processCrossViewTable_,
        QStringLiteral("process.cross_view.process_tab"),
        QStringLiteral("Process Cross-View"));
    ks::i18n::LanguageManager::instance().bindTab(
        innerTabs,
        threadCrossViewTable_,
        QStringLiteral("process.cross_view.thread_tab"),
        QStringLiteral("Thread Cross-View"));
    splitter->addWidget(innerTabs);

    // The Cross-View detail area uses the project's unified CodeEditorWidget to preserve find/copy capabilities and avoid style drift from standard text boxes.
    crossViewDetailEdit_ = new CodeEditorWidget(splitter);
    crossViewDetailEdit_->setReadOnly(true);
    crossViewDetailEdit_->setText(QStringLiteral("选择一条记录查看进程来源、异常标记和内核详情。"));
    splitter->addWidget(crossViewDetailEdit_);
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);

    sideTabWidget_->addTab(crossViewPage_, blueTintedIcon(":/Icon/process_tree.svg"), QStringLiteral("Process Cross-View"));
    ks::i18n::LanguageManager::instance().bindTab(
        sideTabWidget_,
        crossViewPage_,
        QStringLiteral("process.tab.cross_view"),
        QStringLiteral("Process Cross-View"));
}

void ProcessDock::initializeCrossViewConnections()
{
    // Input: None, called by initializeConnections.
    // Processing: Connect refresh, filter, and selection changes.
    // Returns: Nothing.
    connect(crossViewRefreshButton_, &QPushButton::clicked, this, [this]() {
        refreshCrossViewAsync();
    });
    connect(crossViewSearchEdit_, &QLineEdit::textChanged, this, [this]() {
        rebuildCrossViewTables();
    });
    connect(crossViewAnomalyOnlyCheck_, &QCheckBox::toggled, this, [this]() {
        rebuildCrossViewTables();
    });
    connect(processCrossViewTable_, &QTableWidget::currentCellChanged, this, [this](int, int, int, int) {
        showCrossViewDetailForCurrentRow(false);
    });
    connect(threadCrossViewTable_, &QTableWidget::currentCellChanged, this, [this](int, int, int, int) {
        showCrossViewDetailForCurrentRow(true);
    });
}

void ProcessDock::refreshCrossViewAsync()
{
    // Input: User refresh action.
    // Processing: Background requests for process and thread cross-view occur simultaneously; main thread populates the cache.
    // Returns: Nothing.
    if (crossViewRefreshInProgress_)
    {
        return;
    }
    crossViewRefreshInProgress_ = true;
    const std::uint64_t kTicket = ++crossViewRefreshTicket_;
    if (crossViewRefreshButton_ != nullptr)
    {
        crossViewRefreshButton_->setEnabled(false);
    }
    if (crossViewStatusLabel_ != nullptr)
    {
        crossViewStatusLabel_->setText(QStringLiteral("状态：查询中..."));
        crossViewStatusLabel_->setStyleSheet(QStringLiteral("color:%1; font-weight:700;").arg(ksword_theme::kPrimaryBlueHex));
    }

    QPointer<ProcessDock> guardThis(this);
    QRunnable* task = QRunnable::create([guardThis, kTicket]() {
        const ksword::ark::DriverClient kClient;
        ksword::ark::ProcessCrossViewResult processResult = kClient.queryProcessCrossView();
        ksword::ark::ThreadCrossViewResult threadResult = kClient.queryThreadCrossView();

        ProcessDock* const kContextObject = guardThis.data();
        if (kContextObject == nullptr)
        {
            // Page may be destroyed when background query completes:
            // - Input: Context object extracted from QPointer;
            // - Processing: Do not dispatch queued lambda when null to avoid invokeMethod using a null QObject;
            // - Returns: Immediately terminates the background task without touching the UI state.
            return;
        }

        QMetaObject::invokeMethod(kContextObject, [guardThis, kTicket, processResult = std::move(processResult), threadResult = std::move(threadResult)]() mutable {
            if (guardThis == nullptr || guardThis->crossViewRefreshTicket_ != kTicket)
            {
                return;
            }
            auto applySnapshot = [
                guardThis,
                kTicket,
                processSnapshot = std::move(processResult),
                threadSnapshot = std::move(threadResult)]() mutable
            {
                if (guardThis == nullptr || guardThis->crossViewRefreshTicket_ != kTicket)
                {
                    return;
                }

                guardThis->crossViewRefreshInProgress_ = false;
                if (guardThis->crossViewRefreshButton_ != nullptr)
                {
                    guardThis->crossViewRefreshButton_->setEnabled(true);
                }

                guardThis->lastProcessCrossViewResult_ = processSnapshot;
                guardThis->lastThreadCrossViewResult_ = threadSnapshot;
                guardThis->processCrossViewCache_ = processSnapshot.entries;
                guardThis->threadCrossViewCache_ = threadSnapshot.entries;
                guardThis->rebuildCrossViewTables();

                QString statusText;
                if (!processSnapshot.io.ok || !threadSnapshot.io.ok)
                {
                    // Convert low-level IO diagnostics into user-readable descriptions:
                    // - Input: ArkDriverClient's unsupported flag and io.message;
                    // - Handling: Preserve the explicit semantics of 'Not integrated/Driver too old'; normalize the rest via friendlyDriverDetail;
                    // - Returns: short status bar text; does not directly expose low-level strings like DeviceIoControl.
                    const QString kProcessMessageText = processSnapshot.unsupported
                        ? QStringLiteral("进程未集成/驱动过旧")
                        : friendlyDriverDetail(narrowToQString(processSnapshot.io.message));
                    const QString kThreadMessageText = threadSnapshot.unsupported
                        ? QStringLiteral("线程未集成/驱动过旧")
                        : friendlyDriverDetail(narrowToQString(threadSnapshot.io.message));
                    statusText = QStringLiteral("状态：%1 / %2")
                        .arg(kProcessMessageText)
                        .arg(kThreadMessageText);
                    guardThis->crossViewStatusLabel_->setStyleSheet(
                        QStringLiteral("color:%1; font-weight:700;")
                            .arg(ksword_theme::errorColor().name(QColor::HexRgb)));
                }
                else
                {
                    statusText = QStringLiteral("状态：进程 %1/%2，线程 %3/%4，missingCaps=0x%5/0x%6")
                        .arg(processSnapshot.entries.size())
                        .arg(processSnapshot.totalCount)
                        .arg(threadSnapshot.entries.size())
                        .arg(threadSnapshot.totalCount)
                        .arg(static_cast<qulonglong>(processSnapshot.missingCapabilityMask), 0, 16)
                        .arg(static_cast<qulonglong>(threadSnapshot.missingCapabilityMask), 0, 16);
                    guardThis->crossViewStatusLabel_->setStyleSheet(
                        QStringLiteral("color:%1; font-weight:700;")
                            .arg(ksword_theme::successColor().name(QColor::HexRgb)));
                }
                guardThis->crossViewStatusLabel_->setText(statusText);
                guardThis->showCrossViewDetailForCurrentRow(false);
            };

            if (ks::ui::deferTableUiCommitIfContextMenuOpen(
                    guardThis.data(),
                    QStringLiteral("process-cross-view-snapshot-apply"),
                    {guardThis->processCrossViewTable_, guardThis->threadCrossViewTable_},
                    applySnapshot))
            {
                return;
            }
            applySnapshot();
        }, Qt::QueuedConnection);
    });
    task->setAutoDelete(true);
    QThreadPool::globalInstance()->start(task);
}

void ProcessDock::rebuildCrossViewTables()
{
    const QPointer<ProcessDock> kSafeThis(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("process-cross-view-tables-rebuild"),
        {processCrossViewTable_, threadCrossViewTable_},
        [kSafeThis]()
        {
            if (!kSafeThis.isNull())
            {
                kSafeThis->rebuildCrossViewTables();
            }
        }))
    {
        return;
    }

    // Input: None; reads cross-view cache and filter controls.
    // Handling: Redraw process/thread source matrices separately.
    // Returns: Nothing.
    const QString kFilter = crossViewSearchEdit_ != nullptr ? crossViewSearchEdit_->text().trimmed() : QString();
    const bool kAnomalyOnly = crossViewAnomalyOnlyCheck_ != nullptr && crossViewAnomalyOnlyCheck_->isChecked();

    if (processCrossViewTable_ != nullptr)
    {
        QSignalBlocker blocker(processCrossViewTable_);
        processCrossViewTable_->setSortingEnabled(false);
        std::vector<std::size_t> indexes;
        for (std::size_t index = 0; index < processCrossViewCache_.size(); ++index)
        {
            const auto& row = processCrossViewCache_[index];
            if (kAnomalyOnly && row.anomalyFlags == 0U)
            {
                continue;
            }
            if (!textContainsFilter({
                QString::number(row.processId),
                narrowToQString(row.imageName),
                hex64(row.objectAddress),
                anomalyText(row.anomalyFlags),
                narrowToQString(row.detail)
                }, kFilter))
            {
                continue;
            }
            indexes.push_back(index);
        }
        processCrossViewTable_->setRowCount(static_cast<int>(indexes.size()));
        for (int tableRow = 0; tableRow < static_cast<int>(indexes.size()); ++tableRow)
        {
            const std::size_t kCacheIndex = indexes[static_cast<std::size_t>(tableRow)];
            const auto& row = processCrossViewCache_[kCacheIndex];
            QTableWidgetItem* idItem = numericItem(QString::number(row.processId), row.processId);
            idItem->setData(Qt::UserRole + 1, QVariant::fromValue<qulonglong>(static_cast<qulonglong>(kCacheIndex)));
            processCrossViewTable_->setItem(tableRow, columnIndex(CrossViewColumn::kId), idItem);
            processCrossViewTable_->setItem(tableRow, columnIndex(CrossViewColumn::kObject), numericItem(hex64(row.objectAddress), row.objectAddress));
            processCrossViewTable_->setItem(tableRow, columnIndex(CrossViewColumn::kProcess), textItem(narrowToQString(row.imageName)));
            processCrossViewTable_->setItem(tableRow, columnIndex(CrossViewColumn::kPublic), textItem(sourceYesNo(row.sourceMask, KSWORD_ARK_CROSSVIEW_SOURCE_PUBLIC_WALK)));
            processCrossViewTable_->setItem(tableRow, columnIndex(CrossViewColumn::kActiveOrThreadList), textItem(sourceYesNo(row.sourceMask, KSWORD_ARK_CROSSVIEW_SOURCE_ACTIVE_LIST)));
            processCrossViewTable_->setItem(tableRow, columnIndex(CrossViewColumn::kAnomaly), textItem(anomalyText(row.anomalyFlags)));
            processCrossViewTable_->setItem(tableRow, columnIndex(CrossViewColumn::kConfidence), numericItem(QString::number(row.confidence), row.confidence));
            processCrossViewTable_->setItem(
                tableRow,
                columnIndex(CrossViewColumn::kDetail),
                textItem(crossViewTableDetail(false, row.sourceMask, row.anomalyFlags, row.confidence, narrowToQString(row.detail))));
        }
        if (processCrossViewTable_->rowCount() > 0 && processCrossViewTable_->currentRow() < 0)
        {
            processCrossViewTable_->setCurrentCell(0, columnIndex(CrossViewColumn::kId));
        }
        if (processCrossViewTable_->rowCount() == 0)
        {
            const QString kDetailText = crossViewEmptyStateDetail(
                QStringLiteral("进程 Cross-View"),
                lastProcessCrossViewResult_.io.ok,
                lastProcessCrossViewResult_.unsupported,
                processCrossViewCache_.size(),
                lastProcessCrossViewResult_.returnedCount,
                lastProcessCrossViewResult_.totalCount,
                lastProcessCrossViewResult_.missingCapabilityMask,
                narrowToQString(lastProcessCrossViewResult_.io.message));
            setCrossViewDiagnosticRow(
                processCrossViewTable_,
                QStringLiteral("<无进程证据>"),
                QStringLiteral("诊断"),
                kDetailText);
        }
        processCrossViewTable_->setSortingEnabled(true);
        ks::ui::requestTableColumnAutoFit(processCrossViewTable_);
    }

    if (threadCrossViewTable_ != nullptr)
    {
        QSignalBlocker blocker(threadCrossViewTable_);
        threadCrossViewTable_->setSortingEnabled(false);
        std::vector<std::size_t> indexes;
        for (std::size_t index = 0; index < threadCrossViewCache_.size(); ++index)
        {
            const auto& row = threadCrossViewCache_[index];
            if (kAnomalyOnly && row.anomalyFlags == 0U)
            {
                continue;
            }
            if (!textContainsFilter({
                QString::number(row.threadId),
                QString::number(row.processId),
                narrowToQString(row.imageName),
                hex64(row.objectAddress),
                anomalyText(row.anomalyFlags),
                narrowToQString(row.detail)
                }, kFilter))
            {
                continue;
            }
            indexes.push_back(index);
        }
        threadCrossViewTable_->setRowCount(static_cast<int>(indexes.size()));
        for (int tableRow = 0; tableRow < static_cast<int>(indexes.size()); ++tableRow)
        {
            const std::size_t kCacheIndex = indexes[static_cast<std::size_t>(tableRow)];
            const auto& row = threadCrossViewCache_[kCacheIndex];
            QTableWidgetItem* idItem = numericItem(QString::number(row.threadId), row.threadId);
            idItem->setData(Qt::UserRole + 1, QVariant::fromValue<qulonglong>(static_cast<qulonglong>(kCacheIndex)));
            threadCrossViewTable_->setItem(tableRow, columnIndex(CrossViewColumn::kId), idItem);
            threadCrossViewTable_->setItem(tableRow, columnIndex(CrossViewColumn::kObject), numericItem(hex64(row.objectAddress), row.objectAddress));
            threadCrossViewTable_->setItem(tableRow, columnIndex(CrossViewColumn::kProcess), textItem(QStringLiteral("%1 %2").arg(row.processId).arg(narrowToQString(row.imageName))));
            threadCrossViewTable_->setItem(tableRow, columnIndex(CrossViewColumn::kPublic), textItem(sourceYesNo(row.sourceMask, KSWORD_ARK_CROSSVIEW_SOURCE_PUBLIC_WALK)));
            threadCrossViewTable_->setItem(tableRow, columnIndex(CrossViewColumn::kActiveOrThreadList), textItem(sourceYesNo(row.sourceMask, KSWORD_ARK_CROSSVIEW_SOURCE_THREAD_LIST)));
            threadCrossViewTable_->setItem(tableRow, columnIndex(CrossViewColumn::kAnomaly), textItem(anomalyText(row.anomalyFlags)));
            threadCrossViewTable_->setItem(tableRow, columnIndex(CrossViewColumn::kConfidence), numericItem(QString::number(row.confidence), row.confidence));
            threadCrossViewTable_->setItem(
                tableRow,
                columnIndex(CrossViewColumn::kDetail),
                textItem(crossViewTableDetail(true, row.sourceMask, row.anomalyFlags, row.confidence, narrowToQString(row.detail))));
        }
        if (threadCrossViewTable_->rowCount() > 0 && threadCrossViewTable_->currentRow() < 0)
        {
            threadCrossViewTable_->setCurrentCell(0, columnIndex(CrossViewColumn::kId));
        }
        if (threadCrossViewTable_->rowCount() == 0)
        {
            const QString kDetailText = crossViewEmptyStateDetail(
                QStringLiteral("线程 Cross-View"),
                lastThreadCrossViewResult_.io.ok,
                lastThreadCrossViewResult_.unsupported,
                threadCrossViewCache_.size(),
                lastThreadCrossViewResult_.returnedCount,
                lastThreadCrossViewResult_.totalCount,
                lastThreadCrossViewResult_.missingCapabilityMask,
                narrowToQString(lastThreadCrossViewResult_.io.message));
            setCrossViewDiagnosticRow(
                threadCrossViewTable_,
                QStringLiteral("<无线程证据>"),
                QStringLiteral("诊断"),
                kDetailText);
        }
        threadCrossViewTable_->setSortingEnabled(true);
        ks::ui::requestTableColumnAutoFit(threadCrossViewTable_);
    }
}

void ProcessDock::showCrossViewDetailForCurrentRow(const bool preferThreadTable)
{
    // Input: preferThreadTable indicates whether to prioritize reading the thread table or the process table.
    // Processing: Expand the source/anomaly/DynData details of the current row into a read-only text box.
    // Returns: Nothing.
    if (crossViewDetailEdit_ == nullptr)
    {
        return;
    }

    if (preferThreadTable && threadCrossViewTable_ != nullptr && threadCrossViewTable_->currentRow() >= 0)
    {
        const QTableWidgetItem* item = threadCrossViewTable_->item(threadCrossViewTable_->currentRow(), columnIndex(CrossViewColumn::kId));
        const QString kDiagnosticText = item != nullptr
            ? item->data(Qt::UserRole + 2).toString()
            : QString();
        if (!kDiagnosticText.isEmpty())
        {
            crossViewDetailEdit_->setText(QStringLiteral("线程 Cross-View 诊断\n%1").arg(kDiagnosticText));
            return;
        }

        bool ok = false;
        const qulonglong kCacheIndex = item != nullptr ? item->data(Qt::UserRole + 1).toULongLong(&ok) : 0ULL;
        if (ok && kCacheIndex < static_cast<qulonglong>(threadCrossViewCache_.size()))
        {
            const auto& row = threadCrossViewCache_[static_cast<std::size_t>(kCacheIndex)];
            const QString kRawDetailText = narrowToQString(row.detail);
            const QString kReadableDetailText = friendlyDriverDetail(kRawDetailText);
            QString text;
            text += QStringLiteral("线程 Cross-View 详情\n");
            text += QStringLiteral("TID: %1 PID: %2 Image: %3\n").arg(row.threadId).arg(row.processId).arg(narrowToQString(row.imageName));
            text += QStringLiteral("ThreadObject: %1\nProcessObject: %2\nStartAddress: %3\n")
                .arg(hex64(row.objectAddress), hex64(row.processObjectAddress), hex64(row.startAddress));
            text += QStringLiteral("SourceMask: 0x%1\nAnomalyFlags: %2 (0x%3)\n")
                .arg(row.sourceMask, 8, 16, QChar('0'))
                .arg(anomalyText(row.anomalyFlags))
                .arg(row.anomalyFlags, 8, 16, QChar('0'));
            text += QStringLiteral("DynDataCapabilityMask: %1\n").arg(hex64(row.dynDataCapabilityMask));
            text += offsetsText(row.fieldOffsets);
            text += QStringLiteral("LastStatus: 0x%1\nConfidence: %2\n驱动说明: %3\n驱动原始说明: %4\n")
                .arg(static_cast<qulonglong>(static_cast<unsigned long>(row.lastStatus)), 8, 16, QChar('0'))
                .arg(row.confidence)
                .arg(kReadableDetailText)
                .arg(kRawDetailText);
            crossViewDetailEdit_->setText(text);
            return;
        }
    }

    if (processCrossViewTable_ != nullptr && processCrossViewTable_->currentRow() >= 0)
    {
        const QTableWidgetItem* item = processCrossViewTable_->item(processCrossViewTable_->currentRow(), columnIndex(CrossViewColumn::kId));
        const QString kDiagnosticText = item != nullptr
            ? item->data(Qt::UserRole + 2).toString()
            : QString();
        if (!kDiagnosticText.isEmpty())
        {
            crossViewDetailEdit_->setText(QStringLiteral("进程 Cross-View 诊断\n%1").arg(kDiagnosticText));
            return;
        }

        bool ok = false;
        const qulonglong kCacheIndex = item != nullptr ? item->data(Qt::UserRole + 1).toULongLong(&ok) : 0ULL;
        if (ok && kCacheIndex < static_cast<qulonglong>(processCrossViewCache_.size()))
        {
            const auto& row = processCrossViewCache_[static_cast<std::size_t>(kCacheIndex)];
            const QString kRawDetailText = narrowToQString(row.detail);
            const QString kReadableDetailText = friendlyDriverDetail(kRawDetailText);
            QString text;
            text += QStringLiteral("进程 Cross-View 详情\n");
            text += QStringLiteral("PID: %1 PPID: %2 Image: %3\n").arg(row.processId).arg(row.parentProcessId).arg(narrowToQString(row.imageName));
            text += QStringLiteral("ProcessObject: %1\nStartAddress: %2\n")
                .arg(hex64(row.objectAddress), hex64(row.startAddress));
            text += QStringLiteral("SourceMask: 0x%1\nAnomalyFlags: %2 (0x%3)\n")
                .arg(row.sourceMask, 8, 16, QChar('0'))
                .arg(anomalyText(row.anomalyFlags))
                .arg(row.anomalyFlags, 8, 16, QChar('0'));
            text += QStringLiteral("DynDataCapabilityMask: %1\n").arg(hex64(row.dynDataCapabilityMask));
            text += offsetsText(row.fieldOffsets);
            text += QStringLiteral("LastStatus: 0x%1\nConfidence: %2\n驱动说明: %3\n驱动原始说明: %4\n")
                .arg(static_cast<qulonglong>(static_cast<unsigned long>(row.lastStatus)), 8, 16, QChar('0'))
                .arg(row.confidence)
                .arg(kReadableDetailText)
                .arg(kRawDetailText);
            crossViewDetailEdit_->setText(text);
            return;
        }
    }

    crossViewDetailEdit_->setText(QStringLiteral("请选择一条 Cross-View 记录查看详情。"));
}
