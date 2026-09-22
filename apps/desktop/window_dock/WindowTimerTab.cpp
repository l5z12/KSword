#include "WindowTimerTab.h"

#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../internationalization/LanguageManager.h"
#include "../ui/TableInteractionSupport.h"
#include "../ui/VisibleTableWidget.h"
#include "../Theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QFileInfo>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QShowEvent>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

#include <cstdint>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <TlHelp32.h>

namespace
{
    enum TimerColumn : int
    {
        kColumnObject = 0,
        kColumnInterval,
        kColumnFlags,
        kColumnCallback,
        kColumnModule,
        kColumnPid,
        kColumnTid,
        kColumnPath,
        kColumnTimerId,
        kColumnWindow,
        kColumnThreadInfo,
        kColumnSession,
        kColumnCountdown,
        kColumnTolerance,
        kColumnStatus,
        kColumnCount
    };

    struct ModuleRange
    {
        std::uint64_t baseAddress = 0;
        std::uint64_t size = 0;
        QString moduleName;
        QString modulePath;
    };

    struct ProcessMetadata
    {
        QString imagePath;
        std::vector<ModuleRange> modules;
    };

    struct TimerSnapshot
    {
        QVector<QStringList> rows;
        QString statusText;
    };

    QString timerText(const char* contextKey, const QString& sourceText)
    {
        return ks::i18n::contextText(QString::fromLatin1(contextKey), sourceText);
    }

    QString hex64(const std::uint64_t value)
    {
        return QStringLiteral("0x%1").arg(value, 16, 16, QLatin1Char('0')).toUpper();
    }

    QString hex32(const std::uint32_t value)
    {
        return QStringLiteral("0x%1").arg(value, 8, 16, QLatin1Char('0')).toUpper();
    }

    QString layoutSourceText(const std::uint32_t source)
    {
        switch (source)
        {
        case KSWORD_ARK_WIN32K_TIMER_LAYOUT_SOURCE_VALIDATED_DISASSEMBLY:
            return timerText("window.timer.layout.exact", QStringLiteral("精确 PE 身份"));
        case KSWORD_ARK_WIN32K_TIMER_LAYOUT_SOURCE_NEAREST_PREVIOUS:
            return timerText("window.timer.layout.previous", QStringLiteral("最近旧版回退"));
        default:
            return timerText("window.timer.layout.unknown", QStringLiteral("未知"));
        }
    }

    QString intervalText(const std::uint32_t value)
    {
        if (value == 0x7FFFFFFFU)
        {
            return QStringLiteral("0x7FFFFFFF");
        }
        return QString::number(value);
    }

    ProcessMetadata queryProcessMetadata(const DWORD processId)
    {
        ProcessMetadata metadata;
        if (processId == 0U)
        {
            return metadata;
        }

        const HANDLE kProcessHandle = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
        if (kProcessHandle != nullptr)
        {
            std::wstring pathBuffer(32768U, L'\0');
            DWORD pathChars = static_cast<DWORD>(pathBuffer.size());
            if (::QueryFullProcessImageNameW(kProcessHandle, 0U, pathBuffer.data(), &pathChars) != FALSE)
            {
                pathBuffer.resize(pathChars);
                metadata.imagePath = QString::fromStdWString(pathBuffer);
            }
            ::CloseHandle(kProcessHandle);
        }

        const HANDLE kSnapshotHandle = ::CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
            processId);
        if (kSnapshotHandle == INVALID_HANDLE_VALUE)
        {
            return metadata;
        }

        MODULEENTRY32W moduleEntry{};
        moduleEntry.dwSize = sizeof(moduleEntry);
        if (::Module32FirstW(kSnapshotHandle, &moduleEntry) != FALSE)
        {
            do
            {
                ModuleRange range;
                range.baseAddress = static_cast<std::uint64_t>(
                    reinterpret_cast<std::uintptr_t>(moduleEntry.modBaseAddr));
                range.size = moduleEntry.modBaseSize;
                range.moduleName = QString::fromWCharArray(moduleEntry.szModule);
                range.modulePath = QString::fromWCharArray(moduleEntry.szExePath);
                metadata.modules.push_back(std::move(range));
                moduleEntry.dwSize = sizeof(moduleEntry);
            } while (::Module32NextW(kSnapshotHandle, &moduleEntry) != FALSE);
        }
        ::CloseHandle(kSnapshotHandle);
        return metadata;
    }

    const ModuleRange* findModuleForAddress(
        const ProcessMetadata& metadata,
        const std::uint64_t address)
    {
        if (address == 0U)
        {
            return nullptr;
        }
        for (const ModuleRange& range : metadata.modules)
        {
            if (range.baseAddress <= address &&
                address - range.baseAddress < range.size)
            {
                return &range;
            }
        }
        return nullptr;
    }

    QString statusName(const std::uint32_t status)
    {
        switch (status)
        {
        case KSWORD_ARK_WIN32K_STATUS_OK:
            return timerText("window.timer.row.ok", QStringLiteral("完整"));
        case KSWORD_ARK_WIN32K_STATUS_PARTIAL:
            return timerText("window.timer.row.partial", QStringLiteral("部分"));
        case KSWORD_ARK_WIN32K_STATUS_BUFFER_TRUNCATED:
            return timerText("window.timer.row.truncated", QStringLiteral("截断"));
        default:
            return timerText("window.timer.row.status_code", QStringLiteral("状态 %1")).arg(status);
        }
    }

    TimerSnapshot collectTimers()
    {
        TimerSnapshot snapshot;
        const ksword::ark::Win32kTimersResult kResult =
            ksword::ark::DriverClient().queryWin32kTimers();
        if (!kResult.io.ok)
        {
            snapshot.statusText = timerText(
                "window.timer.status.io_failed",
                QStringLiteral("状态：窗口定时器查询失败，Win32=%1，%2"))
                .arg(kResult.io.win32Error)
                .arg(QString::fromStdString(kResult.io.message));
            return snapshot;
        }

        const QString kDetailText = QString::fromStdWString(kResult.detail);
        if (kResult.status == KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED || kResult.unsupported)
        {
            snapshot.statusText = timerText(
                "window.timer.status.unsupported",
                QStringLiteral("状态：当前 win32k 版本没有精确或可用的最近旧版 tagTIMER 布局；base=%1/%2，full=%3/%4。%5"))
                .arg(hex32(kResult.win32kbaseTimeDateStamp))
                .arg(hex32(kResult.win32kbaseImageSize))
                .arg(hex32(kResult.win32kfullTimeDateStamp))
                .arg(hex32(kResult.win32kfullImageSize))
                .arg(kDetailText);
            return snapshot;
        }
        if (kResult.status == KSWORD_ARK_WIN32K_STATUS_WIN32K_NOT_FOUND)
        {
            snapshot.statusText = timerText(
                "window.timer.status.win32k_missing",
                QStringLiteral("状态：未定位 win32kbase/win32kfull，无法读取窗口定时器。%1"))
                .arg(kDetailText);
            return snapshot;
        }

        std::unordered_map<DWORD, ProcessMetadata> processCache;
        snapshot.rows.reserve(static_cast<qsizetype>(kResult.entries.size()));
        for (const KSWORD_ARK_WIN32K_TIMER_ENTRY& entry : kResult.entries)
        {
            auto processIterator = processCache.find(entry.processId);
            if (processIterator == processCache.end())
            {
                processIterator = processCache.emplace(
                    entry.processId,
                    queryProcessMetadata(entry.processId)).first;
            }
            const ProcessMetadata& metadata = processIterator->second;
            const ModuleRange* module = findModuleForAddress(metadata, entry.callbackAddress);
            QString processPath = metadata.imagePath;
            if (processPath.isEmpty() && module != nullptr)
            {
                processPath = module->modulePath;
            }

            const QString kEntryDetail = QString::fromWCharArray(entry.detail);
            snapshot.rows.push_back(QStringList{
                hex64(entry.timerObject),
                intervalText(entry.intervalMs),
                hex32(entry.flags),
                hex64(entry.callbackAddress),
                module == nullptr ? QString() : module->moduleName,
                entry.processId == 0U ? QString() : QString::number(entry.processId),
                entry.threadId == 0U ? QString() : QString::number(entry.threadId),
                processPath,
                hex64(entry.timerId),
                hex64(entry.windowObject),
                hex64(entry.primaryThreadInfo),
                entry.sessionId == 0U ? QStringLiteral("0") : QString::number(entry.sessionId),
                intervalText(entry.countdownMs),
                intervalText(entry.toleranceMs),
                QStringLiteral("%1 | %2").arg(statusName(entry.status), kEntryDetail) });
        }

        snapshot.statusText = timerText(
            "window.timer.status.completed",
            QStringLiteral("状态：Timer %1/%2，访问节点 %3，读取失败 %4，损坏桶 %5，重复 %6；gTimerHashTable=%7，tagTIMER=0x%8，布局来源=%9。%10"))
            .arg(kResult.returnedCount)
            .arg(kResult.totalCount)
            .arg(kResult.visitedNodeCount)
            .arg(kResult.readFailureCount)
            .arg(kResult.corruptBucketCount)
            .arg(kResult.duplicateCount)
            .arg(hex64(kResult.timerHashTable))
            .arg(kResult.layout.objectSize, 0, 16)
            .arg(layoutSourceText(kResult.layout.source))
            .arg(kDetailText);
        return snapshot;
    }

    QTableWidgetItem* readOnlyItem(const QString& text)
    {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }
}

WindowTimerTab::WindowTimerTab(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
}

void WindowTimerTab::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    if (!firstRefreshStarted_)
    {
        firstRefreshStarted_ = true;
        QMetaObject::invokeMethod(this, [this]() { refreshAsync(); }, Qt::QueuedConnection);
    }
}

void WindowTimerTab::initializeUi()
{
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(6, 6, 6, 6);
    rootLayout->setSpacing(5);

    auto* toolbar = new QHBoxLayout();
    refreshButton_ = new QPushButton(
        timerText("window.timer.refresh", QStringLiteral("刷新窗口定时器")),
        this);
    refreshButton_->setStyleSheet(ksword_theme::themedButtonStyle());
    filterEdit_ = new QLineEdit(this);
    filterEdit_->setClearButtonEnabled(true);
    filterEdit_->setPlaceholderText(timerText(
        "window.timer.filter.placeholder",
        QStringLiteral("按对象、间隔、Flags、回调、模块、PID/TID 或路径筛选")));
    toolbar->addWidget(refreshButton_);
    toolbar->addWidget(filterEdit_, 1);
    rootLayout->addLayout(toolbar);

    statusLabel_ = new QLabel(
        timerText("window.timer.status.waiting", QStringLiteral("状态：等待刷新")),
        this);
    statusLabel_->setWordWrap(true);
    statusLabel_->setStyleSheet(QStringLiteral("color:%1;font-weight:600;").arg(ksword_theme::textSecondaryHex()));
    rootLayout->addWidget(statusLabel_);

    table_ = new ks::ui::VisibleTableWidget(this);
    table_->setColumnCount(kColumnCount);
    table_->setHorizontalHeaderLabels({
        timerText("window.timer.header.object", QStringLiteral("定时器对象")),
        timerText("window.timer.header.interval", QStringLiteral("间隔时间")),
        timerText("window.timer.header.flags", QStringLiteral("Flag")),
        timerText("window.timer.header.callback", QStringLiteral("函数地址")),
        timerText("window.timer.header.module", QStringLiteral("模块名")),
        timerText("window.timer.header.pid", QStringLiteral("PID")),
        timerText("window.timer.header.tid", QStringLiteral("TID")),
        timerText("window.timer.header.path", QStringLiteral("路径")),
        timerText("window.timer.header.timer_id", QStringLiteral("Timer ID")),
        timerText("window.timer.header.window", QStringLiteral("窗口对象")),
        timerText("window.timer.header.thread_info", QStringLiteral("ThreadInfo")),
        timerText("window.timer.header.session", QStringLiteral("Session")),
        timerText("window.timer.header.countdown", QStringLiteral("剩余时间")),
        timerText("window.timer.header.tolerance", QStringLiteral("容差")),
        timerText("window.timer.header.status", QStringLiteral("状态")) });
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::ExtendedSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setAlternatingRowColors(true);
    table_->setSortingEnabled(true);
    table_->setContextMenuPolicy(Qt::CustomContextMenu);
    table_->verticalHeader()->setVisible(false);
    table_->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->setStyleSheet(QStringLiteral(
        "QTableWidget{background:transparent;color:%1;}"
        "QHeaderView::section{color:%2;background:transparent;border:1px solid %3;font-weight:600;}")
        .arg(ksword_theme::textPrimaryHex())
        .arg(ksword_theme::kPrimaryBlueHex)
        .arg(ksword_theme::borderHex()));
    rootLayout->addWidget(table_, 1);

    connect(refreshButton_, &QPushButton::clicked, this, [this]() { refreshAsync(); });
    connect(filterEdit_, &QLineEdit::textChanged, this, [this](const QString&) { rebuildTable(); });
    connect(table_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& position) { showCopyMenu(position); });
}

void WindowTimerTab::refreshAsync()
{
    if (refreshing_)
    {
        return;
    }
    refreshing_ = true;
    firstRefreshStarted_ = true;
    refreshButton_->setEnabled(false);
    statusLabel_->setText(timerText(
        "window.timer.status.refreshing",
        QStringLiteral("状态：正在通过 R0 读取 gTimerHashTable...")));
    QPointer<WindowTimerTab> safeThis(this);
    std::thread([safeThis]() {
        TimerSnapshot snapshot = collectTimers();
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(safeThis, [safeThis, snapshot = std::move(snapshot)]() mutable {
            if (safeThis != nullptr)
            {
                safeThis->applySnapshot(std::move(snapshot.rows), snapshot.statusText);
            }
        }, Qt::QueuedConnection);
    }).detach();
}

void WindowTimerTab::applySnapshot(QVector<QStringList> rows, const QString& statusText)
{
    // Protect the cache and table first when a background snapshot arrives; QVector and QString use implicit sharing.
    // latest-wins: The deferred path does not create deep copies for the common case where the menu is not open.
    const QPointer<WindowTimerTab> kSafeThis(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("window-timer-snapshot-apply"),
        { table_ },
        [kSafeThis, rows, statusText]() mutable
        {
            if (!kSafeThis.isNull())
            {
                kSafeThis->applySnapshot(std::move(rows), statusText);
            }
        }))
    {
        return;
    }

    refreshing_ = false;
    refreshButton_->setEnabled(true);
    rows_ = std::move(rows);
    statusLabel_->setText(statusText);
    rebuildTable();
}

void WindowTimerTab::rebuildTable()
{
    const QString kKeyword = filterEdit_->text().trimmed();
    table_->setSortingEnabled(false);
    table_->setRowCount(0);
    for (const QStringList& sourceRow : rows_)
    {
        if (sourceRow.size() < kColumnCount)
        {
            continue;
        }
        if (!kKeyword.isEmpty() && !sourceRow.join(QLatin1Char(' ')).contains(kKeyword, Qt::CaseInsensitive))
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
    table_->setSortingEnabled(true);
    table_->resizeColumnsToContents();
}

QString WindowTimerTab::rowClipboardText(QTableWidget* table, const int row, const bool includeHeader)
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
            headers << (table->horizontalHeaderItem(column) == nullptr ? QString() : table->horizontalHeaderItem(column)->text());
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

void WindowTimerTab::showCopyMenu(const QPoint& position)
{
    const QModelIndex kIndex = table_->indexAt(position);
    const int kRow = kIndex.isValid() ? kIndex.row() : table_->currentRow();
    QMenu menu(this);
    QAction* copyCell = menu.addAction(timerText("window.timer.copy.cell", QStringLiteral("复制单元格")));
    QAction* copyRow = menu.addAction(timerText("window.timer.copy.row", QStringLiteral("复制当前行")));
    QAction* copyAll = menu.addAction(timerText("window.timer.copy.all", QStringLiteral("复制全部行")));
    const QTableWidgetItem* processIdItem = kRow >= 0 ? table_->item(kRow, kColumnPid) : nullptr;
    bool processIdOk = false;
    const quint32 kProcessId = processIdItem != nullptr
        ? processIdItem->text().trimmed().toUInt(&processIdOk, 10)
        : 0U;
    QAction* openProcessAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_details.svg")),
        QStringLiteral("转到进程详细信息"));
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
