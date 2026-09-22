#include "WindowEventHookTab.h"

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
#include <iterator>
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
    enum EventHookColumn : int
    {
        kColumnHandle = 0,
        kColumnObject,
        kColumnEventMin,
        kColumnEventMax,
        kColumnFlags,
        kColumnCallback,
        kColumnModule,
        kColumnPid,
        kColumnTid,
        kColumnPath,
        kColumnTarget,
        kColumnModuleAtom,
        kColumnCallbackOffset,
        kColumnThreadInfo,
        kColumnNext,
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

    struct EventHookSnapshot
    {
        QVector<QStringList> rows;
        QString statusText;
    };

    QString eventHookText(const char* contextKey, const QString& sourceText)
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
        case KSWORD_ARK_WIN32K_EVENT_HOOK_LAYOUT_SOURCE_VALIDATED_DISASSEMBLY:
            return eventHookText("window.event_hook.layout.exact", QStringLiteral("精确 PE 身份"));
        case KSWORD_ARK_WIN32K_EVENT_HOOK_LAYOUT_SOURCE_NEAREST_PREVIOUS:
            return eventHookText("window.event_hook.layout.previous", QStringLiteral("最近旧版回退"));
        default:
            return eventHookText("window.event_hook.layout.unknown", QStringLiteral("未知"));
        }
    }

    QString handleText(const std::uint64_t value)
    {
        return value <= 0xFFFFFFFFULL ? hex32(static_cast<std::uint32_t>(value)) : hex64(value);
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
        for (const ModuleRange& module : metadata.modules)
        {
            if (module.baseAddress <= address && address - module.baseAddress < module.size)
            {
                return &module;
            }
        }
        return nullptr;
    }

    const ModuleRange* findModuleByName(
        const ProcessMetadata& metadata,
        const QString& atomName)
    {
        const QString kFileName = QFileInfo(atomName).fileName();
        for (const ModuleRange& module : metadata.modules)
        {
            if (module.moduleName.compare(kFileName, Qt::CaseInsensitive) == 0 ||
                QFileInfo(module.modulePath).fileName().compare(kFileName, Qt::CaseInsensitive) == 0)
            {
                return &module;
            }
        }
        return nullptr;
    }

    QString globalAtomName(const std::uint32_t atomValue)
    {
        if (atomValue == 0U || atomValue > 0xFFFFU)
        {
            return {};
        }
        wchar_t buffer[512]{};
        const UINT kChars = ::GlobalGetAtomNameW(
            static_cast<ATOM>(atomValue),
            buffer,
            static_cast<int>(std::size(buffer)));
        return kChars == 0U ? QString() : QString::fromWCharArray(buffer, static_cast<qsizetype>(kChars));
    }

    QString flagsText(const std::uint32_t flags)
    {
        QStringList names;
        names << ((flags & KSWORD_ARK_WIN32K_EVENT_HOOK_FLAG_IN_CONTEXT) != 0U
            ? QStringLiteral("INCONTEXT")
            : QStringLiteral("OUTOFCONTEXT"));
        if ((flags & KSWORD_ARK_WIN32K_EVENT_HOOK_FLAG_SKIP_OWN_THREAD) != 0U)
        {
            names << QStringLiteral("SKIPOWNTHREAD");
        }
        if ((flags & KSWORD_ARK_WIN32K_EVENT_HOOK_FLAG_SKIP_OWN_PROCESS) != 0U)
        {
            names << QStringLiteral("SKIPOWNPROCESS");
        }
        const std::uint32_t kUnknown = flags & ~0x7U;
        if (kUnknown != 0U)
        {
            names << hex32(kUnknown);
        }
        return names.join(QStringLiteral(" | "));
    }

    QString statusName(const std::uint32_t status)
    {
        switch (status)
        {
        case KSWORD_ARK_WIN32K_STATUS_OK:
            return eventHookText("window.event_hook.row.ok", QStringLiteral("完整"));
        case KSWORD_ARK_WIN32K_STATUS_PARTIAL:
            return eventHookText("window.event_hook.row.partial", QStringLiteral("部分"));
        default:
            return eventHookText("window.event_hook.row.status_code", QStringLiteral("状态 %1")).arg(status);
        }
    }

    EventHookSnapshot collectEventHooks()
    {
        EventHookSnapshot snapshot;
        const ksword::ark::Win32kEventHooksResult kResult =
            ksword::ark::DriverClient().queryWin32kEventHooks();
        if (!kResult.io.ok)
        {
            snapshot.statusText = eventHookText(
                "window.event_hook.status.io_failed",
                QStringLiteral("状态：事件 Hook 查询失败，Win32=%1，%2"))
                .arg(kResult.io.win32Error)
                .arg(QString::fromStdString(kResult.io.message));
            return snapshot;
        }

        const QString kDetailText = QString::fromStdWString(kResult.detail);
        if (kResult.status == KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED || kResult.unsupported)
        {
            snapshot.statusText = eventHookText(
                "window.event_hook.status.unsupported",
                QStringLiteral("状态：当前 win32k 版本没有精确或可用的最近旧版 tagEVENTHOOK 布局；base=%1/%2，full=%3/%4。%5"))
                .arg(hex32(kResult.win32kbaseTimeDateStamp))
                .arg(hex32(kResult.win32kbaseImageSize))
                .arg(hex32(kResult.win32kfullTimeDateStamp))
                .arg(hex32(kResult.win32kfullImageSize))
                .arg(kDetailText);
            return snapshot;
        }
        if (kResult.status == KSWORD_ARK_WIN32K_STATUS_WIN32K_NOT_FOUND)
        {
            snapshot.statusText = eventHookText(
                "window.event_hook.status.win32k_missing",
                QStringLiteral("状态：未定位 win32kbase/win32kfull，无法读取事件 Hook。%1"))
                .arg(kDetailText);
            return snapshot;
        }

        std::unordered_map<DWORD, ProcessMetadata> processCache;
        snapshot.rows.reserve(static_cast<qsizetype>(kResult.entries.size()));
        for (const KSWORD_ARK_WIN32K_EVENT_HOOK_ENTRY& entry : kResult.entries)
        {
            auto processIterator = processCache.find(entry.processId);
            if (processIterator == processCache.end())
            {
                processIterator = processCache.emplace(
                    entry.processId,
                    queryProcessMetadata(entry.processId)).first;
            }
            const ProcessMetadata& metadata = processIterator->second;
            const QString kAtomName = globalAtomName(entry.moduleAtom);
            std::uint64_t callbackAddress = entry.callbackAddress;
            const ModuleRange* module = nullptr;
            if ((entry.flags & KSWORD_ARK_WIN32K_EVENT_HOOK_FLAG_IN_CONTEXT) != 0U)
            {
                module = findModuleByName(metadata, kAtomName);
                if (module != nullptr && entry.callbackOffset < module->size)
                {
                    callbackAddress = module->baseAddress + entry.callbackOffset;
                }
            }
            else
            {
                module = findModuleForAddress(metadata, callbackAddress);
            }

            const QString kModuleName = module != nullptr
                ? module->moduleName
                : kAtomName;
            const QString kTargetText = QStringLiteral("%1 / %2")
                .arg(entry.targetProcessId == 0U ? QStringLiteral("*") : QString::number(entry.targetProcessId))
                .arg(entry.targetThreadId == 0U ? QStringLiteral("*") : QString::number(entry.targetThreadId));
            snapshot.rows.push_back(QStringList{
                handleText(entry.hookHandle),
                hex64(entry.hookObject),
                hex32(entry.eventMin),
                hex32(entry.eventMax),
                flagsText(entry.flags),
                hex64(callbackAddress),
                kModuleName,
                entry.processId == 0U ? QString() : QString::number(entry.processId),
                entry.threadId == 0U ? QString() : QString::number(entry.threadId),
                metadata.imagePath,
                kTargetText,
                entry.moduleAtom == 0U ? QString() : QStringLiteral("%1 (%2)").arg(hex32(entry.moduleAtom), kAtomName),
                hex64(entry.callbackOffset),
                hex64(entry.ownerThreadInfo),
                hex64(entry.nextHookObject),
                QStringLiteral("%1 | %2").arg(statusName(entry.status), QString::fromWCharArray(entry.detail)) });
        }

        snapshot.statusText = eventHookText(
            "window.event_hook.status.completed",
            QStringLiteral("状态：Event Hook %1/%2，访问节点 %3，读取失败 %4，损坏链 %5，重复 %6；gpWinEventHooks=%7 -> %8，tagEVENTHOOK=0x%9，布局来源=%10。%11"))
            .arg(kResult.returnedCount)
            .arg(kResult.totalCount)
            .arg(kResult.visitedNodeCount)
            .arg(kResult.readFailureCount)
            .arg(kResult.corruptLinkCount)
            .arg(kResult.duplicateCount)
            .arg(hex64(kResult.hookListPointer))
            .arg(hex64(kResult.hookListHead))
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

WindowEventHookTab::WindowEventHookTab(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
}

void WindowEventHookTab::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    if (!firstRefreshStarted_)
    {
        firstRefreshStarted_ = true;
        QMetaObject::invokeMethod(this, [this]() { refreshAsync(); }, Qt::QueuedConnection);
    }
}

void WindowEventHookTab::initializeUi()
{
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(6, 6, 6, 6);
    rootLayout->setSpacing(5);

    auto* toolbar = new QHBoxLayout();
    refreshButton_ = new QPushButton(
        eventHookText("window.event_hook.refresh", QStringLiteral("刷新事件 Hook")),
        this);
    refreshButton_->setStyleSheet(ksword_theme::themedButtonStyle());
    filterEdit_ = new QLineEdit(this);
    filterEdit_->setClearButtonEnabled(true);
    filterEdit_->setPlaceholderText(eventHookText(
        "window.event_hook.filter.placeholder",
        QStringLiteral("按句柄、事件范围、Flags、回调、模块、PID/TID 或路径筛选")));
    toolbar->addWidget(refreshButton_);
    toolbar->addWidget(filterEdit_, 1);
    rootLayout->addLayout(toolbar);

    statusLabel_ = new QLabel(
        eventHookText("window.event_hook.status.waiting", QStringLiteral("状态：等待刷新")),
        this);
    statusLabel_->setWordWrap(true);
    statusLabel_->setStyleSheet(QStringLiteral("color:%1;font-weight:600;").arg(ksword_theme::textSecondaryHex()));
    rootLayout->addWidget(statusLabel_);

    table_ = new ks::ui::VisibleTableWidget(this);
    table_->setColumnCount(kColumnCount);
    table_->setHorizontalHeaderLabels({
        eventHookText("window.event_hook.header.handle", QStringLiteral("句柄")),
        eventHookText("window.event_hook.header.object", QStringLiteral("Hook 对象")),
        eventHookText("window.event_hook.header.event_min", QStringLiteral("EventMin")),
        eventHookText("window.event_hook.header.event_max", QStringLiteral("EventMax")),
        eventHookText("window.event_hook.header.flags", QStringLiteral("Flag")),
        eventHookText("window.event_hook.header.callback", QStringLiteral("函数地址")),
        eventHookText("window.event_hook.header.module", QStringLiteral("模块名")),
        eventHookText("window.event_hook.header.pid", QStringLiteral("PID")),
        eventHookText("window.event_hook.header.tid", QStringLiteral("TID")),
        eventHookText("window.event_hook.header.path", QStringLiteral("进程路径")),
        eventHookText("window.event_hook.header.target", QStringLiteral("目标 PID / TID")),
        eventHookText("window.event_hook.header.module_atom", QStringLiteral("模块 Atom")),
        eventHookText("window.event_hook.header.callback_offset", QStringLiteral("回调偏移")),
        eventHookText("window.event_hook.header.thread_info", QStringLiteral("ThreadInfo")),
        eventHookText("window.event_hook.header.next", QStringLiteral("下一个 Hook")),
        eventHookText("window.event_hook.header.status", QStringLiteral("状态")) });
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

void WindowEventHookTab::refreshAsync()
{
    if (refreshing_)
    {
        return;
    }
    refreshing_ = true;
    firstRefreshStarted_ = true;
    refreshButton_->setEnabled(false);
    statusLabel_->setText(eventHookText(
        "window.event_hook.status.refreshing",
        QStringLiteral("状态：正在通过 R0 读取 gpWinEventHooks...")));
    QPointer<WindowEventHookTab> safeThis(this);
    std::thread([safeThis]() {
        EventHookSnapshot snapshot = collectEventHooks();
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

void WindowEventHookTab::applySnapshot(QVector<QStringList> rows, const QString& statusText)
{
    const QPointer<WindowEventHookTab> kSafeThis(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("window-event-hook-snapshot-apply"),
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

void WindowEventHookTab::rebuildTable()
{
    const QString kKeyword = filterEdit_->text().trimmed();
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
    table_->setSortingEnabled(true);
    table_->resizeColumnsToContents();
}

QString WindowEventHookTab::rowClipboardText(QTableWidget* table, const int row, const bool includeHeader)
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

void WindowEventHookTab::showCopyMenu(const QPoint& position)
{
    const QModelIndex kIndex = table_->indexAt(position);
    const int kRow = kIndex.isValid() ? kIndex.row() : table_->currentRow();
    QMenu menu(this);
    QAction* copyCell = menu.addAction(eventHookText("window.event_hook.copy.cell", QStringLiteral("复制单元格")));
    QAction* copyRow = menu.addAction(eventHookText("window.event_hook.copy.row", QStringLiteral("复制当前行")));
    QAction* copyAll = menu.addAction(eventHookText("window.event_hook.copy.all", QStringLiteral("复制全部行")));
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
