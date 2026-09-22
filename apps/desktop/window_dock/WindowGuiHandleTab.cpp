#include "WindowGuiHandleTab.h"

#include "../internationalization/LanguageManager.h"
#include "../ui/TableInteractionSupport.h"
#include "../ui/VisibleTableWidget.h"
#include "../Theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QComboBox>
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
#include <QVariant>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

namespace
{
    constexpr std::uint32_t kMaxUserHandles = 0x10000U;
    constexpr std::uint32_t kMaximumKnownUserType = 21U;

    enum GuiHandleColumn : int
    {
        kColumnHandle = 0,
        kColumnType,
        kColumnTypeId,
        kColumnFlags,
        kColumnUnique,
        kColumnObjectRaw,
        kColumnObjectMapped,
        kColumnOwnerRaw,
        kColumnOwnerMapped,
        kColumnPid,
        kColumnTid,
        kColumnProcess,
        kColumnPath,
        kColumnLayout,
        kColumnStatus,
        kColumnCount
    };

    struct SharedInfoPrefix
    {
        std::uintptr_t serverInfo = 0U;
        std::uintptr_t handleEntries = 0U;
        std::uint32_t handleEntrySize = 0U;
        std::uint32_t reserved = 0U;
        std::uintptr_t displayInfo = 0U;
        std::uintptr_t sharedDelta = 0U;
    };

    struct HandleEntryLayout
    {
        std::size_t typeOffset = 0U;
        std::size_t flagsOffset = 0U;
        std::size_t uniqueOffset = 0U;
        QString name;
    };

    struct GuiHandleSnapshot
    {
        QVector<QStringList> rows;
        QString statusText;
    };

    QString guiHandleText(const char* contextKey, const QString& sourceText)
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

    bool readCurrentProcessMemory(const std::uintptr_t address, void* const destination, const std::size_t bytes)
    {
        if (address == 0U || destination == nullptr || bytes == 0U)
        {
            return false;
        }
        SIZE_T bytesRead = 0U;
        return ReadProcessMemory(
            GetCurrentProcess(),
            reinterpret_cast<LPCVOID>(address),
            destination,
            bytes,
            &bytesRead) != FALSE && bytesRead == bytes;
    }

    bool addressIsReadable(const std::uintptr_t address)
    {
        if (address == 0U)
        {
            return false;
        }
        MEMORY_BASIC_INFORMATION information{};
        if (VirtualQuery(reinterpret_cast<LPCVOID>(address), &information, sizeof(information)) != sizeof(information))
        {
            return false;
        }
        const DWORD kBlockedProtection = PAGE_NOACCESS | PAGE_GUARD;
        return information.State == MEM_COMMIT && (information.Protect & kBlockedProtection) == 0U;
    }

    template <typename ValueType>
    ValueType readValue(const std::uint8_t* const entryBytes, const std::size_t entrySize, const std::size_t offset)
    {
        ValueType value{};
        if (entryBytes != nullptr && offset <= entrySize && sizeof(value) <= entrySize - offset)
        {
            std::memcpy(&value, entryBytes + offset, sizeof(value));
        }
        return value;
    }

    QString guiObjectTypeText(const std::uint8_t type)
    {
        switch (type)
        {
        case 1U: return QStringLiteral("Window");
        case 2U: return QStringLiteral("Menu");
        case 3U: return QStringLiteral("Cursor/Icon");
        case 4U: return QStringLiteral("SetWindowPos");
        case 5U: return QStringLiteral("Hook");
        case 6U: return QStringLiteral("ClipData");
        case 7U: return QStringLiteral("CallProc");
        case 8U: return QStringLiteral("AccelTable");
        case 9U: return QStringLiteral("DDEAccess");
        case 10U: return QStringLiteral("DDEConv");
        case 11U: return QStringLiteral("DDEExact");
        case 12U: return QStringLiteral("Monitor");
        case 13U: return QStringLiteral("KbdLayout");
        case 14U: return QStringLiteral("KbdFile");
        case 15U: return QStringLiteral("WinEventHook");
        case 16U: return QStringLiteral("Timer");
        case 17U: return QStringLiteral("InputContext");
        case 18U: return QStringLiteral("HidData");
        case 19U: return QStringLiteral("DeviceInfo");
        case 20U: return QStringLiteral("Touch");
        case 21U: return QStringLiteral("Gesture");
        default:
            return guiHandleText("window.gui_handle.type.unknown", QStringLiteral("未知类型 %1")).arg(type);
        }
    }

    BOOL CALLBACK collectWindowHandle(HWND windowHandle, LPARAM contextValue)
    {
        auto* handles = reinterpret_cast<std::vector<std::uint32_t>*>(contextValue);
        if (handles == nullptr)
        {
            return FALSE;
        }
        handles->push_back(static_cast<std::uint32_t>(reinterpret_cast<ULONG_PTR>(windowHandle)));
        return handles->size() < 64U ? TRUE : FALSE;
    }

    std::vector<std::uint32_t> knownWindowHandles()
    {
        std::vector<std::uint32_t> handles;
        handles.reserve(66U);
        const HWND kForegroundWindow = GetForegroundWindow();
        const HWND kDesktopWindow = GetDesktopWindow();
        if (kForegroundWindow != nullptr)
        {
            handles.push_back(static_cast<std::uint32_t>(reinterpret_cast<ULONG_PTR>(kForegroundWindow)));
        }
        if (kDesktopWindow != nullptr)
        {
            handles.push_back(static_cast<std::uint32_t>(reinterpret_cast<ULONG_PTR>(kDesktopWindow)));
        }
        (VOID)EnumWindows(collectWindowHandle, reinterpret_cast<LPARAM>(&handles));
        std::sort(handles.begin(), handles.end());
        handles.erase(std::unique(handles.begin(), handles.end()), handles.end());
        return handles;
    }

    std::uint32_t selectHandleCount(
        const std::array<std::uint32_t, 2U>& candidates,
        const std::vector<std::uint32_t>& windowHandles)
    {
        std::uint32_t largestKnownIndex = 0U;
        for (const std::uint32_t kHandleValue : windowHandles)
        {
            largestKnownIndex = (std::max)(largestKnownIndex, kHandleValue & 0xFFFFU);
        }
        std::uint32_t selected = 0U;
        for (const std::uint32_t kCandidate : candidates)
        {
            if (kCandidate == 0U || kCandidate > kMaxUserHandles || kCandidate <= largestKnownIndex)
            {
                continue;
            }
            // SERVERINFO has used both the first and second DWORD for the
            // handle count across Windows generations. If both look numeric,
            // prefer the smaller safe bound instead of mistaking flags for a
            // larger table length and crossing the shared mapping boundary.
            if (selected == 0U || kCandidate < selected)
            {
                selected = kCandidate;
            }
        }
        return selected;
    }

    HandleEntryLayout detectHandleEntryLayout(
        const std::vector<std::uint8_t>& tableBytes,
        const std::uint32_t handleCount,
        const std::uint32_t entrySize,
        const std::vector<std::uint32_t>& windowHandles)
    {
        std::vector<HandleEntryLayout> candidates;
        if (entrySize >= 28U)
        {
            candidates.push_back({ 24U, 25U, 26U, QStringLiteral("Win10+ / 32-byte") });
        }
        if (entrySize >= 20U)
        {
            candidates.push_back({ 16U, 17U, 18U, QStringLiteral("Legacy / pointer") });
        }
        int bestScore = std::numeric_limits<int>::min();
        HandleEntryLayout bestLayout{};
        for (const HandleEntryLayout& candidate : candidates)
        {
            int score = 0;
            for (const std::uint32_t kHandleValue : windowHandles)
            {
                const std::uint32_t kIndex = kHandleValue & 0xFFFFU;
                if (kIndex >= handleCount)
                {
                    continue;
                }
                const std::size_t kEntryOffset = static_cast<std::size_t>(kIndex) * entrySize;
                const std::uint8_t* entry = tableBytes.data() + kEntryOffset;
                const std::uint8_t kType = readValue<std::uint8_t>(entry, entrySize, candidate.typeOffset);
                const std::uint16_t kUnique = readValue<std::uint16_t>(entry, entrySize, candidate.uniqueOffset);
                if (kType == 1U)
                {
                    score += 4;
                }
                if (kUnique == static_cast<std::uint16_t>((kHandleValue >> 16U) & 0xFFFFU))
                {
                    score += 5;
                }
                if (readValue<std::uintptr_t>(entry, entrySize, 0U) != 0U)
                {
                    score += 1;
                }
            }
            if (score > bestScore)
            {
                bestScore = score;
                bestLayout = candidate;
            }
        }
        return bestLayout;
    }

    std::uintptr_t mapSharedObjectAddress(const std::uintptr_t rawAddress, const std::uintptr_t sharedDelta)
    {
        if (rawAddress == 0U)
        {
            return 0U;
        }
        if (rawAddress < 0x100000000ULL && sharedDelta >= 0x100000000ULL &&
            rawAddress <= (std::numeric_limits<std::uintptr_t>::max)() - sharedDelta)
        {
            const std::uintptr_t kMappedAddress = sharedDelta + rawAddress;
            return addressIsReadable(kMappedAddress) ? kMappedAddress : 0U;
        }
        if (addressIsReadable(rawAddress))
        {
            return rawAddress;
        }
        if (sharedDelta != 0U && rawAddress > sharedDelta)
        {
            const std::uintptr_t kMappedAddress = rawAddress - sharedDelta;
            return addressIsReadable(kMappedAddress) ? kMappedAddress : 0U;
        }
        return 0U;
    }

    std::pair<QString, QString> queryProcessIdentity(const DWORD processId)
    {
        HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
        if (processHandle == nullptr)
        {
            return {};
        }
        std::wstring pathBuffer(32768U, L'\0');
        DWORD pathChars = static_cast<DWORD>(pathBuffer.size());
        QString pathText;
        if (QueryFullProcessImageNameW(processHandle, 0U, pathBuffer.data(), &pathChars) != FALSE)
        {
            pathBuffer.resize(pathChars);
            pathText = QString::fromStdWString(pathBuffer);
        }
        CloseHandle(processHandle);
        return { QFileInfo(pathText).fileName(), pathText };
    }

    GuiHandleSnapshot collectGuiHandles()
    {
        GuiHandleSnapshot snapshot;
#if !defined(_WIN64)
        snapshot.statusText = guiHandleText(
            "window.gui_handle.status.x64_only",
            QStringLiteral("状态：当前 GUI Handle 枚举仅支持 x64 构建"));
        return snapshot;
#else
        HMODULE user32Module = GetModuleHandleW(L"user32.dll");
        if (user32Module == nullptr)
        {
            snapshot.statusText = guiHandleText(
                "window.gui_handle.status.user32_missing",
                QStringLiteral("状态：user32.dll 未加载"));
            return snapshot;
        }
        const FARPROC kSharedInfoExport = GetProcAddress(user32Module, "gSharedInfo");
        if (kSharedInfoExport == nullptr)
        {
            snapshot.statusText = guiHandleText(
                "window.gui_handle.status.export_missing",
                QStringLiteral("状态：当前 user32.dll 未导出 gSharedInfo"));
            return snapshot;
        }
        SharedInfoPrefix sharedInfo{};
        if (!readCurrentProcessMemory(
                reinterpret_cast<std::uintptr_t>(kSharedInfoExport),
                &sharedInfo,
                sizeof(sharedInfo)))
        {
            snapshot.statusText = guiHandleText(
                "window.gui_handle.status.shared_read_failed",
                QStringLiteral("状态：读取 gSharedInfo 失败"));
            return snapshot;
        }
        if (sharedInfo.serverInfo == 0U || sharedInfo.handleEntries == 0U ||
            sharedInfo.handleEntrySize < 20U || sharedInfo.handleEntrySize > 0x100U)
        {
            snapshot.statusText = guiHandleText(
                "window.gui_handle.status.shared_invalid",
                QStringLiteral("状态：gSharedInfo 指针或 HandleEntrySize 无效"));
            return snapshot;
        }
        std::array<std::uint32_t, 2U> serverInfoPrefix{};
        if (!readCurrentProcessMemory(
                sharedInfo.serverInfo,
                serverInfoPrefix.data(),
                sizeof(serverInfoPrefix)))
        {
            snapshot.statusText = guiHandleText(
                "window.gui_handle.status.server_read_failed",
                QStringLiteral("状态：读取 SERVERINFO 失败"));
            return snapshot;
        }
        const std::vector<std::uint32_t> kWindowHandles = knownWindowHandles();
        const std::uint32_t kHandleCount = selectHandleCount(serverInfoPrefix, kWindowHandles);
        if (kHandleCount == 0U)
        {
            snapshot.statusText = guiHandleText(
                "window.gui_handle.status.count_invalid",
                QStringLiteral("状态：SERVERINFO Handle 数量无效"));
            return snapshot;
        }
        const std::size_t kTotalBytes = static_cast<std::size_t>(kHandleCount) * sharedInfo.handleEntrySize;
        std::vector<std::uint8_t> handleTable(kTotalBytes, 0U);
        std::uint32_t readableEntryCount = 0U;
        for (std::uint32_t index = 0U; index < kHandleCount; ++index)
        {
            const std::size_t kEntryOffset = static_cast<std::size_t>(index) * sharedInfo.handleEntrySize;
            if (kEntryOffset > (std::numeric_limits<std::uintptr_t>::max)() - sharedInfo.handleEntries)
            {
                break;
            }
            if (readCurrentProcessMemory(
                    sharedInfo.handleEntries + kEntryOffset,
                    handleTable.data() + kEntryOffset,
                    sharedInfo.handleEntrySize))
            {
                ++readableEntryCount;
            }
        }
        if (readableEntryCount == 0U)
        {
            snapshot.statusText = guiHandleText(
                "window.gui_handle.status.table_read_failed",
                QStringLiteral("状态：读取 USER Handle 共享表失败"));
            return snapshot;
        }
        const HandleEntryLayout kLayout = detectHandleEntryLayout(
            handleTable,
            kHandleCount,
            sharedInfo.handleEntrySize,
            kWindowHandles);
        if (kLayout.name.isEmpty())
        {
            snapshot.statusText = guiHandleText(
                "window.gui_handle.status.layout_failed",
                QStringLiteral("状态：无法识别 USER HandleEntry 布局"));
            return snapshot;
        }

        std::unordered_map<DWORD, std::pair<QString, QString>> processCache;
        snapshot.rows.reserve(static_cast<qsizetype>(kHandleCount));
        std::uint32_t visibleCount = 0U;
        for (std::uint32_t index = 0U; index < kHandleCount; ++index)
        {
            const std::size_t kEntryOffset = static_cast<std::size_t>(index) * sharedInfo.handleEntrySize;
            const std::uint8_t* entry = handleTable.data() + kEntryOffset;
            const std::uintptr_t kRawObject = readValue<std::uintptr_t>(entry, sharedInfo.handleEntrySize, 0U);
            const std::uintptr_t kRawOwner = readValue<std::uintptr_t>(entry, sharedInfo.handleEntrySize, sizeof(std::uintptr_t));
            const std::uint8_t kType = readValue<std::uint8_t>(entry, sharedInfo.handleEntrySize, kLayout.typeOffset);
            const std::uint8_t kFlags = readValue<std::uint8_t>(entry, sharedInfo.handleEntrySize, kLayout.flagsOffset);
            const std::uint16_t kUnique = readValue<std::uint16_t>(entry, sharedInfo.handleEntrySize, kLayout.uniqueOffset);
            if (kType == 0U && kRawObject == 0U)
            {
                continue;
            }
            const std::uint32_t kHandleValue = (static_cast<std::uint32_t>(kUnique) << 16U) | index;
            const std::uintptr_t kMappedObject = mapSharedObjectAddress(kRawObject, sharedInfo.sharedDelta);
            const std::uintptr_t kMappedOwner = mapSharedObjectAddress(kRawOwner, sharedInfo.sharedDelta);
            DWORD processId = 0U;
            DWORD threadId = 0U;
            QString processName;
            QString processPath;
            QString rowStatus = guiHandleText(
                "window.gui_handle.status.shared_entry",
                QStringLiteral("共享 USER Handle"));
            if (kType == 1U)
            {
                const HWND kWindowHandle = reinterpret_cast<HWND>(static_cast<ULONG_PTR>(kHandleValue));
                if (IsWindow(kWindowHandle) != FALSE)
                {
                    threadId = GetWindowThreadProcessId(kWindowHandle, &processId);
                    auto cacheIterator = processCache.find(processId);
                    if (cacheIterator == processCache.end())
                    {
                        cacheIterator = processCache.emplace(processId, queryProcessIdentity(processId)).first;
                    }
                    processName = cacheIterator->second.first;
                    processPath = cacheIterator->second.second;
                    rowStatus = guiHandleText(
                        "window.gui_handle.status.hwnd_verified",
                        QStringLiteral("HWND 已验证"));
                }
            }
            if (kType > kMaximumKnownUserType)
            {
                rowStatus = guiHandleText(
                    "window.gui_handle.status.unknown_type",
                    QStringLiteral("未知 USER 类型"));
            }
            if (kRawObject != 0U && kMappedObject == 0U)
            {
                rowStatus += guiHandleText(
                    "window.gui_handle.status.raw_only",
                    QStringLiteral("；对象仅有原始值"));
            }
            snapshot.rows.push_back(QStringList{
                hex32(kHandleValue),
                guiObjectTypeText(kType),
                QString::number(kType),
                QStringLiteral("0x%1").arg(kFlags, 2, 16, QLatin1Char('0')).toUpper(),
                QStringLiteral("0x%1").arg(kUnique, 4, 16, QLatin1Char('0')).toUpper(),
                hex64(kRawObject),
                hex64(kMappedObject),
                hex64(kRawOwner),
                hex64(kMappedOwner),
                processId == 0U ? QString() : QString::number(processId),
                threadId == 0U ? QString() : QString::number(threadId),
                processName,
                processPath,
                kLayout.name,
                rowStatus });
            ++visibleCount;
        }
        snapshot.statusText = guiHandleText(
            "window.gui_handle.status.completed",
            QStringLiteral("状态：USER Handle %1，非空对象 %2，EntrySize %3，布局 %4，gSharedInfo %5，aheList %6"))
            .arg(kHandleCount)
            .arg(visibleCount)
            .arg(sharedInfo.handleEntrySize)
            .arg(kLayout.name)
            .arg(hex64(reinterpret_cast<std::uintptr_t>(kSharedInfoExport)))
            .arg(hex64(sharedInfo.handleEntries));
        return snapshot;
#endif
    }

    QTableWidgetItem* readOnlyItem(const QString& text)
    {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }
}

WindowGuiHandleTab::WindowGuiHandleTab(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
}

void WindowGuiHandleTab::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    if (!firstRefreshStarted_)
    {
        firstRefreshStarted_ = true;
        QMetaObject::invokeMethod(this, [this]() { refreshAsync(); }, Qt::QueuedConnection);
    }
}

void WindowGuiHandleTab::initializeUi()
{
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(6, 6, 6, 6);
    rootLayout->setSpacing(5);

    auto* toolbar = new QHBoxLayout();
    refreshButton_ = new QPushButton(
        guiHandleText("window.gui_handle.refresh", QStringLiteral("刷新 GUI 句柄")),
        this);
    refreshButton_->setStyleSheet(ksword_theme::themedButtonStyle());
    typeFilterCombo_ = new QComboBox(this);
    typeFilterCombo_->addItem(guiHandleText("window.gui_handle.filter.all", QStringLiteral("全部类型")), -1);
    typeFilterCombo_->addItem(QStringLiteral("Window"), 1);
    typeFilterCombo_->addItem(QStringLiteral("Menu"), 2);
    typeFilterCombo_->addItem(QStringLiteral("Cursor/Icon"), 3);
    typeFilterCombo_->addItem(QStringLiteral("Hook"), 5);
    typeFilterCombo_->addItem(QStringLiteral("WinEventHook"), 15);
    typeFilterCombo_->addItem(QStringLiteral("Timer"), 16);
    typeFilterCombo_->addItem(QStringLiteral("InputContext"), 17);
    filterEdit_ = new QLineEdit(this);
    filterEdit_->setClearButtonEnabled(true);
    filterEdit_->setPlaceholderText(guiHandleText(
        "window.gui_handle.filter.placeholder",
        QStringLiteral("按句柄、类型、对象、PID/TID、进程和路径筛选")));
    toolbar->addWidget(refreshButton_);
    toolbar->addWidget(typeFilterCombo_);
    toolbar->addWidget(filterEdit_, 1);
    rootLayout->addLayout(toolbar);

    statusLabel_ = new QLabel(
        guiHandleText("window.gui_handle.status.waiting", QStringLiteral("状态：等待刷新")),
        this);
    statusLabel_->setWordWrap(true);
    statusLabel_->setStyleSheet(QStringLiteral("color:%1;font-weight:600;").arg(ksword_theme::textSecondaryHex()));
    rootLayout->addWidget(statusLabel_);

    table_ = new ks::ui::VisibleTableWidget(this);
    table_->setColumnCount(kColumnCount);
    table_->setHorizontalHeaderLabels({
        guiHandleText("window.gui_handle.header.handle", QStringLiteral("句柄")),
        guiHandleText("window.gui_handle.header.type", QStringLiteral("类型")),
        QStringLiteral("TypeId"),
        QStringLiteral("Flags"),
        QStringLiteral("Uniq"),
        guiHandleText("window.gui_handle.header.object_raw", QStringLiteral("对象原始值")),
        guiHandleText("window.gui_handle.header.object_mapped", QStringLiteral("对象共享映射")),
        guiHandleText("window.gui_handle.header.owner_raw", QStringLiteral("所有者原始值")),
        guiHandleText("window.gui_handle.header.owner_mapped", QStringLiteral("所有者共享映射")),
        QStringLiteral("PID"),
        QStringLiteral("TID"),
        guiHandleText("window.gui_handle.header.process", QStringLiteral("进程")),
        guiHandleText("window.gui_handle.header.path", QStringLiteral("路径")),
        guiHandleText("window.gui_handle.header.layout", QStringLiteral("布局")),
        guiHandleText("window.gui_handle.header.status", QStringLiteral("状态")) });
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
    connect(typeFilterCombo_, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int) { rebuildTable(); });
    connect(filterEdit_, &QLineEdit::textChanged, this, [this](const QString&) { rebuildTable(); });
    connect(table_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& position) { showCopyMenu(position); });
}

void WindowGuiHandleTab::refreshAsync()
{
    if (refreshing_)
    {
        return;
    }
    refreshing_ = true;
    firstRefreshStarted_ = true;
    refreshButton_->setEnabled(false);
    statusLabel_->setText(guiHandleText(
        "window.gui_handle.status.refreshing",
        QStringLiteral("状态：正在读取 gSharedInfo 与 USER Handle 共享表...")));
    QPointer<WindowGuiHandleTab> safeThis(this);
    std::thread([safeThis]() {
        GuiHandleSnapshot snapshot = collectGuiHandles();
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

void WindowGuiHandleTab::applySnapshot(QVector<QStringList> rows, const QString& statusText)
{
    const QPointer<WindowGuiHandleTab> kSafeThis(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("window-gui-handle-snapshot-apply"),
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

void WindowGuiHandleTab::rebuildTable()
{
    const int kSelectedType = typeFilterCombo_->currentData().toInt();
    const QString kKeyword = filterEdit_->text().trimmed();
    table_->setSortingEnabled(false);
    table_->setRowCount(0);
    for (const QStringList& sourceRow : rows_)
    {
        if (sourceRow.size() < kColumnCount)
        {
            continue;
        }
        if (kSelectedType >= 0 && sourceRow.at(kColumnTypeId).toInt() != kSelectedType)
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

QString WindowGuiHandleTab::rowClipboardText(QTableWidget* table, const int row, const bool includeHeader)
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

void WindowGuiHandleTab::showCopyMenu(const QPoint& position)
{
    const QModelIndex kIndex = table_->indexAt(position);
    const int kRow = kIndex.isValid() ? kIndex.row() : table_->currentRow();
    QMenu menu(this);
    QAction* copyCell = menu.addAction(guiHandleText("window.gui_handle.copy.cell", QStringLiteral("复制单元格")));
    QAction* copyRow = menu.addAction(guiHandleText("window.gui_handle.copy.row", QStringLiteral("复制当前行")));
    QAction* copyAll = menu.addAction(guiHandleText("window.gui_handle.copy.all", QStringLiteral("复制全部行")));
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
