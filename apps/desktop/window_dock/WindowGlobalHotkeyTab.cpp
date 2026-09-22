#include "WindowGlobalHotkeyTab.h"

#include "../Framework.h"
#include "../internationalization/LanguageManager.h"
#include "../process_dock/ProcessHotkeyEnumerator.h"
#include "../ui/TableInteractionSupport.h"
#include "../ui/VisibleTableWidget.h"
#include "../../../shared/platform/process/Process.h"
#include "../Theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QShowEvent>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTimer>
#include <QVBoxLayout>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_set>
#include <utility>
#include <vector>

namespace
{
    // MaxRowsPerUiFlush: Create at most 128 table rows per flush to ensure extreme result sets never form a single excessively long UI task.
    constexpr qsizetype kMaxRowsPerUiFlush = 128;

    enum AllHotkeyColumn : int
    {
        kColumnHotkey = 0,
        kColumnProcess,
        kColumnPid,
        kColumnTid,
        kColumnSource,
        kColumnHotkeyId,
        kColumnVkModifiers,
        kColumnObject,
        kColumnDetail,
        kColumnCount
    };

    QString allHotkeyText(const char* contextKey, const QString& sourceText)
    {
        return ks::i18n::contextText(QString::fromLatin1(contextKey), sourceText);
    }

    QString hex32(const std::uint32_t value, const int width = 0)
    {
        return QStringLiteral("0x%1")
            .arg(value, width, 16, QLatin1Char('0'))
            .toUpper();
    }

    QVector<QStringList> formatRows(const std::vector<ks::process::UserModeHotkeyRecord>& records)
    {
        QVector<QStringList> rows;
        rows.reserve(static_cast<qsizetype>(records.size()));
        for (const ks::process::UserModeHotkeyRecord& record : records)
        {
            rows.push_back(QStringList{
                record.hotkeyText,
                record.processName,
                QString::number(record.processId),
                record.threadId == 0U ? QStringLiteral("-") : QString::number(record.threadId),
                record.sourceText,
                record.hotkeyId == 0U ? QStringLiteral("0") : hex32(record.hotkeyId),
                QStringLiteral("VK=0x%1 MOD=0x%2")
                    .arg(record.virtualKey, 2, 16, QLatin1Char('0'))
                    .arg(record.modifiers, 4, 16, QLatin1Char('0'))
                    .toUpper(),
                record.objectText,
                record.detailText });
        }
        return rows;
    }

    std::vector<ks::process::UserModeHotkeyProcessTarget> collectProcessTargets()
    {
        const std::vector<ks::process::ProcessRecord> kProcessRecords =
            ks::process::enumerateProcesses(ks::process::ProcessEnumStrategy::kAuto);

        std::unordered_set<std::uint32_t> processIds;
        std::vector<ks::process::UserModeHotkeyProcessTarget> targets;
        targets.reserve(kProcessRecords.size());
        for (const ks::process::ProcessRecord& processRecord : kProcessRecords)
        {
            if (processRecord.pid == 0U || !processIds.insert(processRecord.pid).second)
            {
                continue;
            }

            targets.push_back(ks::process::UserModeHotkeyProcessTarget{
                processRecord.pid,
                QString::fromStdString(processRecord.processName),
                QString::fromStdString(processRecord.imagePath) });
        }
        return targets;
    }

    QTableWidgetItem* readOnlyItem(const QString& text)
    {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        item->setToolTip(text);
        return item;
    }
}

// PendingRefreshState: Worker thread writes only to this buffer; UI thread periodically fetches results in batches to avoid flooding the main thread with per-process events.
struct WindowGlobalHotkeyTab::PendingRefreshState
{
    // mutex: Protects the following cross-thread shared fields; callers must hold it only within short critical sections.
    std::mutex mutex;
    // pendingRows: Data rows not yet merged into the table, consumed in batches by the UI refresh timer.
    std::deque<QStringList> pendingRows;
    // currentProcessName: The process name from the most recently completed scan, used to display real-time progress.
    QString currentProcessName;
    // ticket: ID of the initiator for this refresh round, preventing old task results from polluting new tasks.
    std::uint64_t ticket = 0;
    // revision: increments with each background state change to prevent the UI from reprocessing the same snapshot.
    std::uint64_t revision = 0;
    // completedProcessCount: Total number of processes that have completed scanning in the background.
    std::uint32_t completedProcessCount = 0;
    // totalProcessCount: Total number of processes enumerated in this round.
    std::uint32_t totalProcessCount = 0;
    // diagnosticProcessCount: Cumulative count of processes containing diagnostic information.
    std::uint32_t diagnosticProcessCount = 0;
    // enumerationReady: indicates that process enumeration is complete and the total progress can be displayed.
    bool enumerationReady = false;
    // completed: Indicates that all scanning threads have exited, allowing the UI to perform final cleanup.
    bool completed = false;
    // elapsedMs: Duration of the full background scan, valid only when completed is true.
    qint64 elapsedMs = 0;
};

WindowGlobalHotkeyTab::WindowGlobalHotkeyTab(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
}

void WindowGlobalHotkeyTab::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    if (!firstRefreshStarted_)
    {
        firstRefreshStarted_ = true;
        QMetaObject::invokeMethod(this, [this]() { refreshAsync(); }, Qt::QueuedConnection);
    }
}

void WindowGlobalHotkeyTab::initializeUi()
{
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(6, 6, 6, 6);
    rootLayout->setSpacing(5);

    auto* toolbar = new QHBoxLayout();
    refreshButton_ = new QPushButton(
        allHotkeyText("window.global_hotkey.refresh", QStringLiteral("刷新全部热键")),
        this);
    refreshButton_->setStyleSheet(ksword_theme::themedButtonStyle());
    filterEdit_ = new QLineEdit(this);
    filterEdit_->setClearButtonEnabled(true);
    filterEdit_->setPlaceholderText(allHotkeyText(
        "window.global_hotkey.filter.placeholder",
        QStringLiteral("按热键、进程、PID/TID、来源、对象或详情筛选")));
    toolbar->addWidget(refreshButton_);
    toolbar->addWidget(filterEdit_, 1);
    rootLayout->addLayout(toolbar);

    statusLabel_ = new QLabel(
        allHotkeyText("window.global_hotkey.summary.waiting", QStringLiteral("状态：等待刷新")),
        this);
    statusLabel_->setWordWrap(true);
    statusLabel_->setStyleSheet(QStringLiteral("color:%1;font-weight:600;").arg(ksword_theme::textSecondaryHex()));
    rootLayout->addWidget(statusLabel_);

    table_ = new ks::ui::VisibleTableWidget(this);
    table_->setColumnCount(kColumnCount);
    table_->setHorizontalHeaderLabels({
        allHotkeyText("window.global_hotkey.header.hotkey", QStringLiteral("热键")),
        allHotkeyText("window.global_hotkey.header.process", QStringLiteral("进程")),
        allHotkeyText("window.global_hotkey.header.pid", QStringLiteral("PID")),
        allHotkeyText("window.global_hotkey.header.tid", QStringLiteral("TID")),
        allHotkeyText("window.global_hotkey.header.source", QStringLiteral("来源")),
        allHotkeyText("window.global_hotkey.header.id", QStringLiteral("热键 ID")),
        allHotkeyText("window.global_hotkey.header.vk_mod", QStringLiteral("VK / Mod")),
        allHotkeyText("window.global_hotkey.header.object", QStringLiteral("热键对象")),
        allHotkeyText("window.global_hotkey.header.detail", QStringLiteral("详情")) });
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::ExtendedSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setAlternatingRowColors(true);
    table_->setSortingEnabled(true);
    table_->setContextMenuPolicy(Qt::CustomContextMenu);
    table_->verticalHeader()->setVisible(false);
    table_->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    table_->horizontalHeader()->setStretchLastSection(true);
    // Limit automatic column width calculation to sampling a small number of rows to avoid long UI blocking when scanning large result sets.
    table_->horizontalHeader()->setResizeContentsPrecision(100);
    table_->setStyleSheet(QStringLiteral(
        "QTableWidget{background:transparent;color:%1;}"
        "QHeaderView::section{color:%2;background:transparent;border:1px solid %3;font-weight:600;}")
        .arg(ksword_theme::textPrimaryHex())
        .arg(ksword_theme::kPrimaryBlueHex)
        .arg(ksword_theme::borderHex()));
    rootLayout->addWidget(table_, 1);

    // m_flushTimer: Merges background results at a fixed interval to keep the main thread's per-iteration workload bounded.
    flushTimer_ = new QTimer(this);
    flushTimer_->setInterval(100);
    flushTimer_->setTimerType(Qt::CoarseTimer);

    connect(refreshButton_, &QPushButton::clicked, this, [this]() { refreshAsync(); });
    connect(filterEdit_, &QLineEdit::textChanged, this, [this](const QString&) { rebuildTable(); });
    connect(table_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& position) { showCopyMenu(position); });
    connect(flushTimer_, &QTimer::timeout, this, [this]() { flushPendingSnapshot(); });
}

void WindowGlobalHotkeyTab::refreshAsync()
{
    if (refreshing_)
    {
        return;
    }

    // A refresh immediately clears the cache and rebuilds the table; when the menu is open, even the startup phase is deferred.
    const QPointer<WindowGlobalHotkeyTab> kSafeThis(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("window-global-hotkey-refresh-start"),
        { table_ },
        [kSafeThis]()
        {
            if (!kSafeThis.isNull())
            {
                kSafeThis->refreshAsync();
            }
        }))
    {
        return;
    }

    refreshing_ = true;
    firstRefreshStarted_ = true;
    const std::uint64_t kTicket = ++refreshTicket_;
    rows_.clear();
    scannedProcessCount_ = 0U;
    totalProcessCount_ = 0U;
    diagnosticProcessCount_ = 0U;
    appliedRefreshRevision_ = 0U;
    // Pause auto-sorting during scanning to avoid triggering a full table re-sort for every batch of incremental inserts.
    sortingEnabledBeforeRefresh_ = table_->isSortingEnabled();
    table_->setSortingEnabled(false);
    refreshButton_->setEnabled(false);
    statusLabel_->setText(allHotkeyText(
        "window.global_hotkey.summary.refreshing",
        QStringLiteral("状态：正在扫描全部进程的热键...")));
    rebuildTable();

    progressTaskId_ = kPro.add(
        this,
        allHotkeyText("window.global_hotkey.tab", QStringLiteral("全部热键")).toStdString(),
        allHotkeyText(
            "window.global_hotkey.progress.enumerating",
            QStringLiteral("正在枚举进程")).toStdString());
    kPro.set(progressTaskId_, allHotkeyText(
        "window.global_hotkey.progress.enumerating",
        QStringLiteral("正在枚举进程")).toStdString(), 0, 0.0f);

    // refreshState: The background holds only an independent shared state; QWidget will not be accessed after the page is destroyed.
    const std::shared_ptr<PendingRefreshState> kRefreshState = std::make_shared<PendingRefreshState>();
    kRefreshState->ticket = kTicket;
    refreshState_ = kRefreshState;
    flushTimer_->start();

    std::thread([kRefreshState]()
    {
        // beginTime: Records the total time for process enumeration, shortcut indexing, and hotkey scanning.
        const auto kBeginTime = std::chrono::steady_clock::now();
        const std::vector<ks::process::UserModeHotkeyProcessTarget> kTargets = collectProcessTargets();

        {
            // stateLock: Publishes the total process count; the UI will read it during the next scheduled refresh.
            const std::lock_guard<std::mutex> kStateLock(kRefreshState->mutex);
            kRefreshState->totalProcessCount = static_cast<std::uint32_t>(kTargets.size());
            kRefreshState->enumerationReady = true;
            ++kRefreshState->revision;
        }

        ks::process::enumerateUserModeHotkeysForProcesses(
            kTargets,
            [kRefreshState](ks::process::UserModeHotkeyBatchProgress progress)
            {
                // rows: Perform string formatting in the worker thread to avoid shifting conversion costs to the UI.
                QVector<QStringList> rows = formatRows(progress.records);
                const bool kHasDiagnostic = progress.diagnosticText.contains(QLatin1Char('|'));

                // stateLock: Merge results and progress for this process in one go; perform no UI operations within the critical section.
                const std::lock_guard<std::mutex> kStateLock(kRefreshState->mutex);
                for (QStringList& row : rows)
                {
                    kRefreshState->pendingRows.push_back(std::move(row));
                }
                kRefreshState->completedProcessCount = std::max(
                    kRefreshState->completedProcessCount,
                    progress.completedProcessCount);
                kRefreshState->totalProcessCount = std::max(
                    kRefreshState->totalProcessCount,
                    progress.totalProcessCount);
                kRefreshState->currentProcessName = std::move(progress.processName);
                if (kHasDiagnostic)
                {
                    ++kRefreshState->diagnosticProcessCount;
                }
                ++kRefreshState->revision;
            });

        // elapsedMs: Recorded only after all scanning worker threads exit to ensure the completion status corresponds to the complete result.
        const qint64 kElapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - kBeginTime).count();
        {
            // stateLock: final state and remaining results are read together by the UI timer, ensuring completion events do not overtake result events.
            const std::lock_guard<std::mutex> kStateLock(kRefreshState->mutex);
            kRefreshState->completed = true;
            kRefreshState->elapsedMs = kElapsedMs;
            ++kRefreshState->revision;
        }
    }).detach();
}

void WindowGlobalHotkeyTab::flushPendingSnapshot()
{
    // refreshState: Retains shared state outside the lock to prevent premature object destruction after finishRefresh releases the member.
    const std::shared_ptr<PendingRefreshState> kRefreshState = refreshState_;
    if (!refreshing_ || kRefreshState == nullptr)
    {
        flushTimer_->stop();
        return;
    }

    // Must be deferred before pendingRows.pop_front() under stateLock; after merging keys with the same timeout, background
    // results remain fully intact in the shared queue and are flushed in bounded batches only after the menu closes.
    const QPointer<WindowGlobalHotkeyTab> kSafeThis(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("window-global-hotkey-stream-flush"),
        { table_ },
        [kSafeThis]()
        {
            if (!kSafeThis.isNull())
            {
                kSafeThis->flushPendingSnapshot();
            }
        }))
    {
        return;
    }

    QVector<QStringList> rows;
    QString currentProcessName;
    std::uint64_t ticket = 0;
    std::uint64_t revision = 0;
    std::uint32_t completedProcessCount = 0;
    std::uint32_t totalProcessCount = 0;
    std::uint32_t diagnosticProcessCount = 0;
    bool enumerationReady = false;
    bool completed = false;
    qint64 elapsedMs = 0;

    {
        // stateLock: Reads a consistent snapshot and retrieves rows pending display, allowing the background to immediately continue writing the next batch.
        const std::lock_guard<std::mutex> kStateLock(kRefreshState->mutex);
        ticket = kRefreshState->ticket;
        revision = kRefreshState->revision;
        const bool kHasPendingRows = !kRefreshState->pendingRows.empty();
        if (ticket != refreshTicket_ ||
            (revision == appliedRefreshRevision_ && !kHasPendingRows))
        {
            return;
        }

        // batchRowCount: Fetches only a bounded number of rows; remaining data is processed by the next scheduled refresh.
        const qsizetype kBatchRowCount = std::min(
            kMaxRowsPerUiFlush,
            static_cast<qsizetype>(kRefreshState->pendingRows.size()));
        rows.reserve(kBatchRowCount);
        for (qsizetype rowIndex = 0; rowIndex < kBatchRowCount; ++rowIndex)
        {
            rows.push_back(std::move(kRefreshState->pendingRows.front()));
            kRefreshState->pendingRows.pop_front();
        }
        currentProcessName = kRefreshState->currentProcessName;
        completedProcessCount = kRefreshState->completedProcessCount;
        totalProcessCount = kRefreshState->totalProcessCount;
        diagnosticProcessCount = kRefreshState->diagnosticProcessCount;
        enumerationReady = kRefreshState->enumerationReady;
        // Finish only when the background is complete and the buffer is empty, to avoid the final state skipping results that haven't been displayed yet.
        completed = kRefreshState->completed && kRefreshState->pendingRows.empty();
        elapsedMs = kRefreshState->elapsedMs;
    }

    appliedRefreshRevision_ = revision;
    if (enumerationReady && completedProcessCount == 0U)
    {
        totalProcessCount_ = totalProcessCount;
        statusLabel_->setText(allHotkeyText(
            "window.global_hotkey.summary.indexing_shortcuts",
            QStringLiteral("状态：已找到 %1 个进程，正在读取快捷方式索引...")).arg(totalProcessCount));
        if (progressTaskId_ != 0)
        {
            kPro.set(
                progressTaskId_,
                allHotkeyText(
                    "window.global_hotkey.progress.indexing_shortcuts",
                    QStringLiteral("正在读取快捷方式索引")).toStdString(),
                0,
                0.0f);
        }
    }

    if (completedProcessCount > 0U || !rows.isEmpty())
    {
        appendSnapshotRows(
            ticket,
            std::move(rows),
            completedProcessCount,
            totalProcessCount,
            currentProcessName,
            diagnosticProcessCount);
    }
    if (completed)
    {
        finishRefresh(ticket, elapsedMs);
    }
}

void WindowGlobalHotkeyTab::appendSnapshotRows(
    const std::uint64_t ticket,
    QVector<QStringList> rows,
    const std::uint32_t completedProcessCount,
    const std::uint32_t totalProcessCount,
    const QString& processName,
    const std::uint32_t diagnosticProcessCount)
{
    if (ticket != refreshTicket_ || !refreshing_)
    {
        return;
    }

    scannedProcessCount_ = std::max(scannedProcessCount_, completedProcessCount);
    totalProcessCount_ = std::max(totalProcessCount_, totalProcessCount);
    diagnosticProcessCount_ = std::max(diagnosticProcessCount_, diagnosticProcessCount);

    if (!rows.isEmpty())
    {
        // New data is only appended to the current view; filtering changes can still reconstruct the full result based on m_rows.
        appendVisibleRows(rows);
        rows_ += std::move(rows);
    }

    const QString kCurrentProcessName = processName.trimmed().isEmpty()
        ? allHotkeyText("window.global_hotkey.process.unknown", QStringLiteral("<未知进程>"))
        : processName;
    statusLabel_->setText(allHotkeyText(
        "window.global_hotkey.summary.progress",
        QStringLiteral("状态：已扫描 %1 / %2 个进程，已发现 %3 条热键。"))
        .arg(scannedProcessCount_)
        .arg(totalProcessCount_)
        .arg(rows_.size()));
    if (progressTaskId_ != 0)
    {
        const float kRawProgress = totalProcessCount_ == 0U
            ? 0.0f
            : static_cast<float>(scannedProcessCount_) / static_cast<float>(totalProcessCount_);
        // KProgress hides the task at 1.0; report at most 99% before the final batch of UI data is written.
        const float kProgress = std::min(kRawProgress, 0.99f);
        kPro.set(
            progressTaskId_,
            allHotkeyText(
                "window.global_hotkey.progress.scanning",
                QStringLiteral("正在扫描 %1（%2/%3）"))
                .arg(kCurrentProcessName)
                .arg(scannedProcessCount_)
                .arg(totalProcessCount_)
                .toStdString(),
            static_cast<int>(scannedProcessCount_),
            kProgress);
    }
}

void WindowGlobalHotkeyTab::finishRefresh(const std::uint64_t ticket, const qint64 elapsedMs)
{
    if (ticket != refreshTicket_)
    {
        return;
    }

    refreshing_ = false;
    flushTimer_->stop();
    refreshButton_->setEnabled(true);
    // Restore user's original sort state after scan; trigger full table sort only once.
    table_->setSortingEnabled(sortingEnabledBeforeRefresh_);
    // Do not repeatedly measure column widths during scanning; after completion, adjust once based on a bounded sample.
    table_->resizeColumnsToContents();
    statusLabel_->setText(allHotkeyText(
        "window.global_hotkey.summary.completed",
        QStringLiteral("状态：已扫描 %1 个进程，发现 %2 条热键，耗时 %3 ms。%4"))
        .arg(scannedProcessCount_)
        .arg(rows_.size())
        .arg(elapsedMs)
        .arg(diagnosticProcessCount_ == 0U
            ? QString()
            : allHotkeyText(
                "window.global_hotkey.summary.diagnostics",
                QStringLiteral("%1 个进程的扫描包含诊断信息。")).arg(diagnosticProcessCount_)));

    const int kProgressTaskId = progressTaskId_;
    progressTaskId_ = 0;
    if (kProgressTaskId != 0)
    {
        kPro.set(
            kProgressTaskId,
            allHotkeyText(
                "window.global_hotkey.progress.completed",
                QStringLiteral("全部热键扫描完成")).toStdString(),
            100,
            1.0f);
    }
    refreshState_.reset();
}

void WindowGlobalHotkeyTab::appendVisibleRows(const QVector<QStringList>& rows)
{
    // keyword: Retain current filter conditions; incrementally insert only matching new rows into the table.
    const QString kKeyword = filterEdit_->text().trimmed();
    const bool kSortingEnabled = table_->isSortingEnabled();
    table_->setUpdatesEnabled(false);
    table_->setSortingEnabled(false);

    for (const QStringList& sourceRow : rows)
    {
        if (sourceRow.size() < kColumnCount ||
            (!kKeyword.isEmpty() && !sourceRow.join(QLatin1Char(' ')).contains(kKeyword, Qt::CaseInsensitive)))
        {
            continue;
        }

        const int kTableRow = table_->rowCount();
        table_->insertRow(kTableRow);
        for (int column = 0; column < kColumnCount; ++column)
        {
            table_->setItem(kTableRow, column, readOnlyItem(sourceRow.at(column)));
        }
    }

    table_->setSortingEnabled(kSortingEnabled);
    table_->setUpdatesEnabled(true);
    table_->viewport()->update();
}

void WindowGlobalHotkeyTab::rebuildTable()
{
    const QString kKeyword = filterEdit_->text().trimmed();
    const bool kSortingEnabled = table_->isSortingEnabled();
    table_->setUpdatesEnabled(false);
    table_->setSortingEnabled(false);
    table_->setRowCount(0);
    for (const QStringList& sourceRow : rows_)
    {
        if (sourceRow.size() < kColumnCount ||
            (!kKeyword.isEmpty() && !sourceRow.join(QLatin1Char(' ')).contains(kKeyword, Qt::CaseInsensitive)))
        {
            continue;
        }

        const int kTableRow = table_->rowCount();
        table_->insertRow(kTableRow);
        for (int column = 0; column < kColumnCount; ++column)
        {
            table_->setItem(kTableRow, column, readOnlyItem(sourceRow.at(column)));
        }
    }
    table_->setSortingEnabled(kSortingEnabled);
    table_->resizeColumnsToContents();
    table_->setUpdatesEnabled(true);
    table_->viewport()->update();
}

QString WindowGlobalHotkeyTab::rowClipboardText(
    QTableWidget* table,
    const int row,
    const bool includeHeader)
{
    if (table == nullptr || row < 0 || row >= table->rowCount())
    {
        return {};
    }

    QStringList lines;
    if (includeHeader)
    {
        QStringList headers;
        for (int column = 0; column < table->columnCount(); ++column)
        {
            headers << (table->horizontalHeaderItem(column) == nullptr
                ? QString()
                : table->horizontalHeaderItem(column)->text());
        }
        lines << headers.join(QLatin1Char('\t'));
    }

    QStringList values;
    for (int column = 0; column < table->columnCount(); ++column)
    {
        values << (table->item(row, column) == nullptr ? QString() : table->item(row, column)->text());
    }
    lines << values.join(QLatin1Char('\t'));
    return lines.join(QLatin1Char('\n'));
}

void WindowGlobalHotkeyTab::showCopyMenu(const QPoint& position)
{
    const QModelIndex kIndex = table_->indexAt(position);
    const int kRow = kIndex.isValid() ? kIndex.row() : table_->currentRow();
    QMenu menu(this);
    QAction* copyCell = menu.addAction(allHotkeyText("window.global_hotkey.copy.cell", QStringLiteral("复制单元格")));
    QAction* copyRow = menu.addAction(allHotkeyText("window.global_hotkey.copy.row", QStringLiteral("复制当前行")));
    QAction* copyAll = menu.addAction(allHotkeyText("window.global_hotkey.copy.all", QStringLiteral("复制全部行")));
    const QTableWidgetItem* processIdItem = kRow >= 0 ? table_->item(kRow, kColumnPid) : nullptr;
    bool processIdOk = false;
    const quint32 kProcessId = processIdItem != nullptr
        ? processIdItem->text().trimmed().toUInt(&processIdOk, 10)
        : 0U;
    QAction* openProcessAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_details.svg")),
        allHotkeyText("window.global_hotkey.open_process", QStringLiteral("转到进程详细信息")));
    copyCell->setEnabled(kIndex.isValid());
    copyRow->setEnabled(kRow >= 0);
    copyAll->setEnabled(table_->rowCount() > 0);
    openProcessAction->setEnabled(processIdOk && kProcessId != 0U);

    QAction* selected = menu.exec(table_->viewport()->mapToGlobal(position));
    if (selected == copyCell && kIndex.isValid())
    {
        const QTableWidgetItem* item = table_->item(kIndex.row(), kIndex.column());
        QApplication::clipboard()->setText(item == nullptr ? QString() : item->text());
    }
    else if (selected == copyRow)
    {
        QApplication::clipboard()->setText(rowClipboardText(table_, kRow, true));
    }
    else if (selected == copyAll)
    {
        QStringList lines;
        for (int tableRow = 0; tableRow < table_->rowCount(); ++tableRow)
        {
            lines << rowClipboardText(table_, tableRow, tableRow == 0);
        }
        QApplication::clipboard()->setText(lines.join(QLatin1Char('\n')));
    }
    else if (selected == openProcessAction)
    {
        ks::ui::openProcessDetailByPid(kProcessId);
    }
}
