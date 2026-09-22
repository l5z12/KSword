#include "ProcessMessageHookWindow.h"

#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../internationalization/LanguageManager.h"
#include "../ui/UiSupport.h"
#include "../Theme.h"

#include <QAbstractItemView>
#include <QApplication>
#include <QClipboard>
#include <QColor>
#include <QComboBox>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QMenu>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QRunnable>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QThreadPool>
#include <QVBoxLayout>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace
{
    class ScopedHookIdentityHandle final
    {
    public:
        explicit ScopedHookIdentityHandle(const HANDLE handleValue)
            : handle_(handleValue)
        {
        }

        ~ScopedHookIdentityHandle()
        {
            if (handle_ != nullptr)
            {
                ::CloseHandle(handle_);
            }
        }

        ScopedHookIdentityHandle(const ScopedHookIdentityHandle&) = delete;
        ScopedHookIdentityHandle& operator=(const ScopedHookIdentityHandle&) = delete;

    private:
        HANDLE handle_ = nullptr;
    };

    // hookWindowText: Translates the short text of this standalone window via source_translations.
    QString hookWindowText(const QString& sourceText)
    {
        return ks::i18n::sourceText(sourceText);
    }

    // formatHex: Unify formatting for Hook addresses, handles, and object fields.
    QString formatHex(const std::uint64_t value)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(value), 0, 16)
            .toUpper();
    }

    // formatNtStatus: Retains the original NTSTATUS hexadecimal value.
    QString formatNtStatus(const long status)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<quint32>(status), 8, 16, QChar('0'))
            .toUpper();
    }

    // fixedWideText: Safely reads a fixed wchar_t buffer from the shared protocol.
    QString fixedWideText(const wchar_t* buffer, const std::size_t capacity)
    {
        if (buffer == nullptr || capacity == 0U)
        {
            return {};
        }

        std::size_t length = 0U;
        while (length < capacity && buffer[length] != L'\0')
        {
            ++length;
        }
        return length == 0U
            ? QString()
            : QString::fromWCharArray(buffer, static_cast<qsizetype>(length));
    }

    // hookTypeText: Converts Win32 Hook type numbers to WH_* names.
    QString hookTypeText(const std::uint32_t hookType)
    {
        switch (hookType)
        {
        case 0xFFFFFFFFUL: return QStringLiteral("WH_MSGFILTER(-1)");
        case 0UL: return QStringLiteral("WH_JOURNALRECORD");
        case 1UL: return QStringLiteral("WH_JOURNALPLAYBACK");
        case 2UL: return QStringLiteral("WH_KEYBOARD");
        case 3UL: return QStringLiteral("WH_GETMESSAGE");
        case 4UL: return QStringLiteral("WH_CALLWNDPROC");
        case 5UL: return QStringLiteral("WH_CBT");
        case 6UL: return QStringLiteral("WH_SYSMSGFILTER");
        case 7UL: return QStringLiteral("WH_MOUSE");
        case 8UL: return QStringLiteral("WH_HARDWARE");
        case 9UL: return QStringLiteral("WH_DEBUG");
        case 10UL: return QStringLiteral("WH_SHELL");
        case 11UL: return QStringLiteral("WH_FOREGROUNDIDLE");
        case 12UL: return QStringLiteral("WH_CALLWNDPROCRET");
        case 13UL: return QStringLiteral("WH_KEYBOARD_LL");
        case 14UL: return QStringLiteral("WH_MOUSE_LL");
        default: return QStringLiteral("WH_TYPE(%1)").arg(hookType);
        }
    }

    // hookFlagsText: Expands message hook flags while preserving the original bitmask.
    QString hookFlagsText(const std::uint32_t flags)
    {
        QStringList names;
        if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_GLOBAL) != 0U) names << QStringLiteral("GLOBAL");
        if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_ANSI) != 0U) names << QStringLiteral("ANSI");
        if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_NEED_SKIP) != 0U) names << QStringLiteral("NEED_SKIP");
        if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_HUNG) != 0U) names << QStringLiteral("HUNG");
        if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_FAULTED) != 0U) names << QStringLiteral("FAULTED");
        if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_NO_DELAY) != 0U) names << QStringLiteral("NO_DELAY");
        if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_WOW64_DLL) != 0U) names << QStringLiteral("WOW64_DLL");
        if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_DESTROYED) != 0U) names << QStringLiteral("DESTROYED");
        if (names.isEmpty())
        {
            names << QStringLiteral("0");
        }
        return QStringLiteral("%1 (%2)").arg(names.join(QStringLiteral(" | ")), formatHex(flags));
    }

    // hookStatusText: Converts Win32k audit status to stable short text.
    QString hookStatusText(const std::uint32_t status)
    {
        switch (status)
        {
        case KSWORD_ARK_WIN32K_STATUS_OK: return QStringLiteral("OK");
        case KSWORD_ARK_WIN32K_STATUS_PARTIAL: return QStringLiteral("Partial");
        case KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED: return QStringLiteral("Unsupported");
        case KSWORD_ARK_WIN32K_STATUS_PROFILE_MISSING: return QStringLiteral("ProfileMissing");
        case KSWORD_ARK_WIN32K_STATUS_WIN32K_NOT_FOUND: return QStringLiteral("Win32kNotFound");
        case KSWORD_ARK_WIN32K_STATUS_BUFFER_TRUNCATED: return QStringLiteral("BufferTruncated");
        case KSWORD_ARK_WIN32K_STATUS_READ_FAILED: return QStringLiteral("ReadFailed");
        case KSWORD_ARK_WIN32K_STATUS_ENUM_FAILED: return QStringLiteral("EnumFailed");
        default: return QStringLiteral("Status(%1)").arg(status);
        }
    }

    // hookSourceText: indicates whether the evidence comes from the thread hook chain or the global hook chain.
    QString hookSourceText(const std::uint32_t source)
    {
        switch (source)
        {
        case KSWORD_ARK_WIN32K_MESSAGE_HOOK_SOURCE_THREAD: return QStringLiteral("ThreadHookChain");
        case KSWORD_ARK_WIN32K_MESSAGE_HOOK_SOURCE_GLOBAL: return QStringLiteral("GlobalHookChain");
        default: return QStringLiteral("Source(%1)").arg(source);
        }
    }

    // queryScopeFlags: Maps the window scope to the owner/target selection bits of the shared protocol.
    std::uint32_t queryScopeFlags(const ProcessMessageHookWindow::QueryScope scope)
    {
        switch (scope)
        {
        case ProcessMessageHookWindow::QueryScope::kInstalledByProcess:
            return KSWORD_ARK_WIN32K_MESSAGE_HOOK_QUERY_FLAG_MATCH_OWNER;
        case ProcessMessageHookWindow::QueryScope::kRelatedToProcess:
            return KSWORD_ARK_WIN32K_MESSAGE_HOOK_QUERY_FLAG_MATCH_OWNER |
                KSWORD_ARK_WIN32K_MESSAGE_HOOK_QUERY_FLAG_MATCH_TARGET;
        case ProcessMessageHookWindow::QueryScope::kTargetThreads:
        default:
            return KSWORD_ARK_WIN32K_MESSAGE_HOOK_QUERY_FLAG_MATCH_TARGET;
        }
    }

    // queryScopeText: Provides consistent user-visible text for the status bar and query scope dropdown.
    QString queryScopeText(const ProcessMessageHookWindow::QueryScope scope)
    {
        switch (scope)
        {
        case ProcessMessageHookWindow::QueryScope::kInstalledByProcess:
            return hookWindowText(QStringLiteral("由该进程安装"));
        case ProcessMessageHookWindow::QueryScope::kRelatedToProcess:
            return hookWindowText(QStringLiteral("与该进程相关（目标或所有者）"));
        case ProcessMessageHookWindow::QueryScope::kTargetThreads:
        default:
            return hookWindowText(QStringLiteral("作用于该进程线程"));
        }
    }

    // entryMatchesProcessScope: Defensive check R0 return, compatible with ignoring new flags in older drivers.
    bool entryMatchesProcessScope(
        const KSWORD_ARK_WIN32K_HOOK_ENTRY& entry,
        const ProcessMessageHookTarget& target,
        const ProcessMessageHookWindow::QueryScope scope)
    {
        const bool kTargetSessionMatches = target.sessionId == 0U ||
            entry.targetSessionId == 0U ||
            entry.targetSessionId == target.sessionId;
        const bool kOwnerSessionMatches = target.sessionId == 0U ||
            entry.sessionId == 0U ||
            entry.sessionId == target.sessionId;
        const bool kTargetMatches =
            entry.hookScope == KSWORD_ARK_WIN32K_MESSAGE_HOOK_SCOPE_THREAD &&
            entry.targetProcessId == target.processId &&
            kTargetSessionMatches;
        const bool kOwnerMatches = entry.processId == target.processId &&
            kOwnerSessionMatches;

        switch (scope)
        {
        case ProcessMessageHookWindow::QueryScope::kInstalledByProcess:
            return kOwnerMatches;
        case ProcessMessageHookWindow::QueryScope::kRelatedToProcess:
            return kTargetMatches || kOwnerMatches;
        case ProcessMessageHookWindow::QueryScope::kTargetThreads:
        default:
            return kTargetMatches;
        }
    }

    // moduleText: Prioritizes resolving the module atom name; retains moduleId/atom evidence even if resolution fails.
    QString moduleText(const KSWORD_ARK_WIN32K_HOOK_ENTRY& entry)
    {
        QString atomName;
        if (entry.moduleAtom != 0U && entry.moduleAtom <= 0xFFFFU)
        {
            std::array<wchar_t, 512> buffer{};
            const UINT kLength = ::GlobalGetAtomNameW(
                static_cast<ATOM>(entry.moduleAtom),
                buffer.data(),
                static_cast<int>(buffer.size()));
            if (kLength != 0U)
            {
                atomName = QString::fromWCharArray(buffer.data(), static_cast<qsizetype>(kLength));
            }
        }

        QStringList evidence;
        if (!atomName.trimmed().isEmpty()) evidence << atomName;
        if (entry.moduleId != 0U) evidence << QStringLiteral("moduleId=%1").arg(entry.moduleId);
        if (entry.moduleAtom != 0U) evidence << QStringLiteral("atom=%1").arg(formatHex(entry.moduleAtom));
        return evidence.isEmpty() ? QStringLiteral("-") : evidence.join(QStringLiteral(" | "));
    }

    // columnIndex: Convert column enum to integer used by QTableWidget.
    int columnIndex(const ProcessMessageHookWindow::Column column)
    {
        return static_cast<int>(column);
    }

    // presetButtonStyle: Render A/B column group buttons based on the selected state.
    QString presetButtonStyle(const bool selected)
    {
        const QString kBackground = selected
            ? ksword_theme::accentHex(ksword_theme::AccentRole::kBlue)
            : QStringLiteral("transparent");
        const QString kBorder = selected
            ? ksword_theme::accentHex(ksword_theme::AccentRole::kBlue)
            : ksword_theme::borderHex();
        const QString kTextColor = selected
            ? ksword_theme::onAccentHex()
            : ksword_theme::textPrimaryHex();
        return QStringLiteral(
            "QPushButton{min-width:26px;max-width:26px;padding:3px 0;border:1px solid %1;"
            "border-radius:0;color:%2;background:%3;font-weight:700;}"
            "QPushButton:hover{border-color:%4;}")
            .arg(kBorder, kTextColor, kBackground, ksword_theme::accentHex(ksword_theme::AccentRole::kBlue));
    }
}

ProcessMessageHookWindow::ProcessMessageHookWindow(
    const ProcessMessageHookTarget& target,
    QWidget* parent)
    : QDialog(parent)
    , target_(target)
{
    // Independent top-level, non-modal, and released on close, allowing multiple processes to be viewed simultaneously.
    setWindowFlag(Qt::Window, true);
    setWindowModality(Qt::NonModal);
    setAttribute(Qt::WA_DeleteOnClose, true);
    initializeUi();
    initializeConnections();
    requestRefresh();
}

void ProcessMessageHookWindow::initializeUi()
{
    setObjectName(QStringLiteral("ProcessMessageHookWindowRoot"));
    setAttribute(Qt::WA_StyledBackground, true);
    setAutoFillBackground(true);
    setStyleSheet(ksword_theme::opaqueDialogStyle(objectName()));
    ks::i18n::LanguageManager::instance().bindWindowTitle(
        this,
        QStringLiteral("process.message_hook.title"),
        QStringLiteral("进程消息 Hook"));
    ks::ui::applyResponsiveWindowGeometry(
        this,
        parentWidget(),
        QSize(1180, 680),
        QSize(720, 480));

    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(10, 10, 10, 10);
    rootLayout->setSpacing(7);

    auto* toolbarLayout = new QHBoxLayout();
    toolbarLayout->setContentsMargins(0, 0, 0, 0);
    toolbarLayout->setSpacing(6);

    refreshButton_ = new QPushButton(
        QIcon(QStringLiteral(":/Icon/process_refresh.svg")),
        hookWindowText(QStringLiteral("刷新")),
        this);
    refreshButton_->setStyleSheet(ksword_theme::themedButtonStyle());

    auto* scopeLabel = new QLabel(hookWindowText(QStringLiteral("范围：")), this);
    scopeCombo_ = new QComboBox(this);
    scopeCombo_->addItem(
        queryScopeText(QueryScope::kTargetThreads),
        static_cast<int>(QueryScope::kTargetThreads));
    scopeCombo_->addItem(
        queryScopeText(QueryScope::kInstalledByProcess),
        static_cast<int>(QueryScope::kInstalledByProcess));
    scopeCombo_->addItem(
        queryScopeText(QueryScope::kRelatedToProcess),
        static_cast<int>(QueryScope::kRelatedToProcess));
    scopeCombo_->setToolTip(hookWindowText(QStringLiteral(
        "选择按目标线程、Hook 安装者或两者查询；筛选同时在 R0 和 R3 生效。")));
    scopeCombo_->setStyleSheet(ksword_theme::themedComboBoxStyle());
    scopeCombo_->setMinimumContentsLength(18);
    scopeLabel->setBuddy(scopeCombo_);

    columnAButton_ = new QPushButton(QStringLiteral("A"), this);
    columnAButton_->setToolTip(hookWindowText(
        QStringLiteral("显示 A 组精简列：目标线程、Hook 类型、所有者、回调、模块和状态。")));
    columnAButton_->setCursor(Qt::PointingHandCursor);

    columnBButton_ = new QPushButton(QStringLiteral("B"), this);
    columnBButton_->setToolTip(hookWindowText(
        QStringLiteral("显示 B 组精简列：对象地址、来源、NTSTATUS 和诊断证据。")));
    columnBButton_->setCursor(Qt::PointingHandCursor);

    const QString kProcessName = target_.processName.trimmed().isEmpty()
        ? QStringLiteral("-")
        : target_.processName.trimmed();
    targetLabel_ = new QLabel(
        hookWindowText(QStringLiteral("目标：%1  PID=%2  Session=%3"))
            .arg(kProcessName)
            .arg(target_.processId)
            .arg(target_.sessionId),
        this);
    targetLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    targetLabel_->setStyleSheet(
        QStringLiteral("font-weight:600;color:%1;").arg(ksword_theme::textPrimaryHex()));

    toolbarLayout->addWidget(refreshButton_, 0);
    toolbarLayout->addWidget(scopeLabel, 0);
    toolbarLayout->addWidget(scopeCombo_, 0);
    toolbarLayout->addSpacing(4);
    toolbarLayout->addWidget(columnAButton_, 0);
    toolbarLayout->addWidget(columnBButton_, 0);
    toolbarLayout->addWidget(targetLabel_, 1);
    rootLayout->addLayout(toolbarLayout);

    statusLabel_ = new QLabel(hookWindowText(QStringLiteral("等待查询消息 Hook。")), this);
    statusLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    statusLabel_->setWordWrap(true);
    statusLabel_->setStyleSheet(
        QStringLiteral("color:%1;").arg(ksword_theme::textSecondaryHex()));
    rootLayout->addWidget(statusLabel_, 0);

    table_ = new QTableWidget(this);
    table_->setColumnCount(columnIndex(Column::kCount));
    table_->setHorizontalHeaderLabels(QStringList{
        hookWindowText(QStringLiteral("目标 PID")),
        hookWindowText(QStringLiteral("目标 TID")),
        hookWindowText(QStringLiteral("Hook 类型")),
        hookWindowText(QStringLiteral("所有者 PID")),
        hookWindowText(QStringLiteral("所有者 TID")),
        hookWindowText(QStringLiteral("回调地址")),
        hookWindowText(QStringLiteral("模块")),
        hookWindowText(QStringLiteral("Flags")),
        hookWindowText(QStringLiteral("状态")),
        hookWindowText(QStringLiteral("Session")),
        hookWindowText(QStringLiteral("Hook 句柄")),
        hookWindowText(QStringLiteral("Hook 对象")),
        hookWindowText(QStringLiteral("模块基址")),
        hookWindowText(QStringLiteral("过程偏移")),
        hookWindowText(QStringLiteral("来源")),
        hookWindowText(QStringLiteral("NTSTATUS")),
        hookWindowText(QStringLiteral("诊断")) });
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setAlternatingRowColors(true);
    table_->setSortingEnabled(true);
    table_->setWordWrap(false);
    table_->setTextElideMode(Qt::ElideRight);
    table_->setContextMenuPolicy(Qt::CustomContextMenu);
    table_->verticalHeader()->setVisible(false);
    table_->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->horizontalHeader()->setContextMenuPolicy(Qt::CustomContextMenu);
    rootLayout->addWidget(table_, 1);

    applyColumnPreset(QStringLiteral("A"));
}

void ProcessMessageHookWindow::initializeConnections()
{
    connect(refreshButton_, &QPushButton::clicked, this, [this]()
        {
            requestRefresh();
        });
    connect(scopeCombo_, QOverload<int>::of(&QComboBox::currentIndexChanged), this,
        [this](const int)
        {
            requestRefresh();
        });
    connect(columnAButton_, &QPushButton::clicked, this, [this]()
        {
            applyColumnPreset(QStringLiteral("A"));
        });
    connect(columnBButton_, &QPushButton::clicked, this, [this]()
        {
            applyColumnPreset(QStringLiteral("B"));
        });
    connect(table_, &QTableWidget::customContextMenuRequested, this,
        [this](const QPoint& position)
        {
            showTableContextMenu(position);
        });
    connect(table_->horizontalHeader(), &QHeaderView::customContextMenuRequested, this,
        [this](const QPoint& position)
        {
            showHeaderContextMenu(position);
        });
}

ProcessMessageHookWindow::QueryScope ProcessMessageHookWindow::currentQueryScope() const
{
    if (scopeCombo_ == nullptr)
    {
        return QueryScope::kTargetThreads;
    }

    bool conversionOk = false;
    const int kScopeValue = scopeCombo_->currentData().toInt(&conversionOk);
    if (!conversionOk ||
        kScopeValue < static_cast<int>(QueryScope::kTargetThreads) ||
        kScopeValue > static_cast<int>(QueryScope::kRelatedToProcess))
    {
        return QueryScope::kTargetThreads;
    }
    return static_cast<QueryScope>(kScopeValue);
}

void ProcessMessageHookWindow::requestRefresh()
{
    if (refreshInProgress_)
    {
        refreshPending_ = true;
        return;
    }

    refreshInProgress_ = true;
    const std::uint64_t kTicket = ++refreshTicket_;
    const QueryScope kQueryScope = currentQueryScope();
    refreshButton_->setEnabled(false);
    // During the query, retain the previous table as a visual reference but disable interaction to avoid mistaking the old range for current results.
    table_->setEnabled(false);
    statusLabel_->setText(
        hookWindowText(QStringLiteral("正在查询：%1…"))
            .arg(queryScopeText(kQueryScope)));
    statusLabel_->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;").arg(ksword_theme::kPrimaryBlueHex));

    const ProcessMessageHookTarget kTarget = target_;
    QPointer<ProcessMessageHookWindow> guardThis(this);
    auto* task = QRunnable::create([guardThis, kTicket, kTarget, kQueryScope]()
        {
            QueryResult queryResult;
            queryResult.queryScope = kQueryScope;
            HANDLE rawIdentityHandle = nullptr;
            DWORD identityError = ERROR_INVALID_PARAMETER;
            if (kTarget.processId != 0U && kTarget.creationTime100ns != 0U)
            {
                rawIdentityHandle = ::OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION,
                    FALSE,
                    kTarget.processId);
                identityError = rawIdentityHandle != nullptr
                    ? ERROR_SUCCESS
                    : ::GetLastError();
            }
            const ScopedHookIdentityHandle kIdentityHandle(rawIdentityHandle);

            FILETIME creationTime{};
            FILETIME exitTime{};
            FILETIME kernelTime{};
            FILETIME userTime{};
            const bool kIdentityReadable = rawIdentityHandle != nullptr
                && ::GetProcessTimes(
                    rawIdentityHandle,
                    &creationTime,
                    &exitTime,
                    &kernelTime,
                    &userTime) != FALSE;
            if (!kIdentityReadable && rawIdentityHandle != nullptr)
            {
                identityError = ::GetLastError();
            }
            const std::uint64_t kActualCreationTime100ns = kIdentityReadable
                ? (static_cast<std::uint64_t>(creationTime.dwHighDateTime) << 32U)
                    | static_cast<std::uint64_t>(creationTime.dwLowDateTime)
                : 0U;
            if (!kIdentityReadable
                || kActualCreationTime100ns != kTarget.creationTime100ns)
            {
                queryResult.ioMessage = hookWindowText(QStringLiteral(
                    "进程身份已变化（PID 可能已被复用），已拒绝操作。"));
                queryResult.detail = QStringLiteral(
                    "expectedCreateTime100ns=%1; actualCreateTime100ns=%2; error=%3")
                    .arg(static_cast<qulonglong>(kTarget.creationTime100ns))
                    .arg(static_cast<qulonglong>(kActualCreationTime100ns))
                    .arg(identityError);
            }
            else
            {
                const ksword::ark::Win32kHooksPdbResult kDriverResult =
                    ksword::ark::DriverClient().queryWin32kHooksPdb(
                        KSWORD_ARK_WIN32K_QUERY_FLAG_INCLUDE_ALL |
                            queryScopeFlags(kQueryScope),
                        kTarget.sessionId,
                        kTarget.processId,
                        0UL,
                        KSWORD_ARK_WIN32K_MESSAGE_HOOK_DEFAULT_MAX_ENTRIES);

                queryResult.ioOk = kDriverResult.io.ok;
                queryResult.unsupported = kDriverResult.unsupported;
                queryResult.status = kDriverResult.status;
                queryResult.totalCount = kDriverResult.totalCount;
                queryResult.returnedCount = kDriverResult.returnedCount;
                queryResult.discoveredChainCount = kDriverResult.discoveredChainCount;
                queryResult.visitedNodeCount = kDriverResult.visitedNodeCount;
                queryResult.readFailureCount = kDriverResult.readFailureCount;
                queryResult.corruptLinkCount = kDriverResult.corruptLinkCount;
                queryResult.duplicateCount = kDriverResult.duplicateCount;
                queryResult.lastStatus = kDriverResult.lastStatus;
                queryResult.ioMessage = QString::fromStdString(kDriverResult.io.message);
                queryResult.detail = kDriverResult.detail.empty()
                    ? QString()
                    : QString::fromWCharArray(
                        kDriverResult.detail.c_str(),
                        static_cast<qsizetype>(kDriverResult.detail.size()));

                queryResult.rows.reserve(kDriverResult.entries.size());
                for (const KSWORD_ARK_WIN32K_HOOK_ENTRY& entry : kDriverResult.entries)
                {
                    if (!entryMatchesProcessScope(entry, kTarget, kQueryScope))
                    {
                        continue;
                    }

                    QStringList diagnosticParts;
                    diagnosticParts << QStringLiteral("fieldFlags=%1").arg(formatHex(entry.fieldFlags));
                    diagnosticParts << QStringLiteral("ownerSession=%1").arg(entry.sessionId);
                    diagnosticParts << QStringLiteral("targetSession=%1").arg(entry.targetSessionId);
                    diagnosticParts << QStringLiteral("threadInfo=%1").arg(formatHex(entry.threadInfo));
                    diagnosticParts << QStringLiteral("targetThreadInfo=%1").arg(formatHex(entry.targetThreadInfo));
                    diagnosticParts << QStringLiteral("desktop=%1").arg(formatHex(entry.desktopObject));
                    const QString kEntryDetail = fixedWideText(
                        entry.detail,
                        KSWORD_ARK_WIN32K_DETAIL_CHARS).trimmed();
                    if (!kEntryDetail.isEmpty()) diagnosticParts << kEntryDetail;

                    queryResult.rows.push_back(QStringList{
                        QString::number(entry.targetProcessId),
                        QString::number(entry.targetThreadId),
                        hookTypeText(entry.hookType),
                        QString::number(entry.processId),
                        QString::number(entry.threadId),
                        formatHex(entry.procedureAddress),
                        moduleText(entry),
                        hookFlagsText(entry.flags),
                        hookStatusText(entry.status),
                        QString::number(entry.targetSessionId != 0U ? entry.targetSessionId : entry.sessionId),
                        formatHex(entry.hookHandle),
                        formatHex(entry.hookObject),
                        formatHex(entry.moduleBase),
                        formatHex(entry.procedureOffset),
                        hookSourceText(entry.source),
                        formatNtStatus(entry.lastStatus),
                        diagnosticParts.join(QStringLiteral("; ")) });
                }
                queryResult.matchedCount = static_cast<std::uint32_t>(queryResult.rows.size());
            }

            if (guardThis == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                guardThis,
                [guardThis, kTicket, queryResult]()
                {
                    if (guardThis != nullptr)
                    {
                        guardThis->applyQueryResult(kTicket, queryResult);
                    }
                },
                Qt::QueuedConnection);
        });
    task->setAutoDelete(true);
    QThreadPool::globalInstance()->start(task);
}

void ProcessMessageHookWindow::applyQueryResult(
    const std::uint64_t ticket,
    const QueryResult& result)
{
    if (ticket < refreshTicket_)
    {
        return;
    }

    refreshInProgress_ = false;

    // When a scope switch occurs during an asynchronous query, prevent old results from briefly overwriting the new selection.
    if (result.queryScope != currentQueryScope())
    {
        refreshPending_ = false;
        QMetaObject::invokeMethod(this, [this]()
            {
                requestRefresh();
            }, Qt::QueuedConnection);
        return;
    }

    refreshButton_->setEnabled(true);
    rebuildTable(result);
    table_->setEnabled(true);

    const QString kOverallStatus = hookStatusText(result.status);
    QString statusText;
    const QString kScopeText = queryScopeText(result.queryScope);
    const bool kStatusOk = result.ioOk &&
        result.status == KSWORD_ARK_WIN32K_STATUS_OK &&
        result.readFailureCount == 0U &&
        result.corruptLinkCount == 0U &&
        result.returnedCount >= result.totalCount;
    if (!result.ioOk)
    {
        statusText = hookWindowText(QStringLiteral("查询失败：%1"))
            .arg(result.ioMessage.trimmed().isEmpty()
                ? hookWindowText(QStringLiteral("驱动接口不可用或版本不匹配。"))
                : result.ioMessage.trimmed());
    }
    else if (result.rows.empty())
    {
        statusText = hookWindowText(
            QStringLiteral("查询完成：驱动返回 %1 行，按“%2”复核后没有可显示的 Hook。总体状态：%3。"))
            .arg(result.returnedCount)
            .arg(kScopeText)
            .arg(kOverallStatus);
    }
    else
    {
        statusText = hookWindowText(
            QStringLiteral("查询完成：按“%1”显示 %2 条 Hook，驱动返回 %3/%4 行。总体状态：%5。"))
            .arg(kScopeText)
            .arg(result.matchedCount)
            .arg(result.returnedCount)
            .arg(result.totalCount)
            .arg(kOverallStatus);
    }
    if (result.ioOk)
    {
        statusText += QLatin1Char(' ') + hookWindowText(QStringLiteral(
            "遍历：链 %1，节点 %2，读取失败 %3，损坏链接 %4，重复 %5。"))
            .arg(result.discoveredChainCount)
            .arg(result.visitedNodeCount)
            .arg(result.readFailureCount)
            .arg(result.corruptLinkCount)
            .arg(result.duplicateCount);
    }
    statusLabel_->setText(statusText);
    statusLabel_->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;")
            .arg((kStatusOk ? ksword_theme::successColor() : ksword_theme::warningColor())
                .name(QColor::HexRgb)));

    if (refreshPending_)
    {
        refreshPending_ = false;
        QMetaObject::invokeMethod(this, [this]()
            {
                requestRefresh();
            }, Qt::QueuedConnection);
    }
}

void ProcessMessageHookWindow::rebuildTable(const QueryResult& result)
{
    table_->setSortingEnabled(false);
    table_->clearContents();

    if (!result.rows.empty())
    {
        table_->setRowCount(static_cast<int>(result.rows.size()));
        for (int row = 0; row < static_cast<int>(result.rows.size()); ++row)
        {
            const QStringList& cells = result.rows[static_cast<std::size_t>(row)];
            for (int column = 0; column < columnIndex(Column::kCount); ++column)
            {
                auto* item = new QTableWidgetItem(column < cells.size() ? cells[column] : QString());
                item->setToolTip(item->text());
                table_->setItem(row, column, item);
            }
        }
    }
    else
    {
        table_->setRowCount(1);
        QStringList detailParts;
        detailParts << QStringLiteral("io=%1").arg(result.ioOk ? QStringLiteral("ok") : QStringLiteral("failed"));
        detailParts << QStringLiteral("status=%1").arg(hookStatusText(result.status));
        detailParts << QStringLiteral("returned=%1/%2").arg(result.returnedCount).arg(result.totalCount);
        detailParts << QStringLiteral("scope=%1").arg(queryScopeText(result.queryScope));
        detailParts << QStringLiteral("chains=%1").arg(result.discoveredChainCount);
        detailParts << QStringLiteral("visited=%1").arg(result.visitedNodeCount);
        detailParts << QStringLiteral("readFailures=%1").arg(result.readFailureCount);
        detailParts << QStringLiteral("corruptLinks=%1").arg(result.corruptLinkCount);
        detailParts << QStringLiteral("duplicates=%1").arg(result.duplicateCount);
        detailParts << QStringLiteral("lastStatus=%1").arg(formatNtStatus(result.lastStatus));
        if (!result.ioMessage.trimmed().isEmpty()) detailParts << result.ioMessage.trimmed();
        if (!result.detail.trimmed().isEmpty()) detailParts << result.detail.trimmed();

        for (int column = 0; column < columnIndex(Column::kCount); ++column)
        {
            table_->setItem(0, column, new QTableWidgetItem(QStringLiteral("-")));
        }
        table_->item(0, columnIndex(Column::kHookType))->setText(
            hookWindowText(QStringLiteral("<无可显示的消息 Hook>")));
        table_->item(0, columnIndex(Column::kStatus))->setText(hookStatusText(result.status));
        table_->item(0, columnIndex(Column::kLastStatus))->setText(formatNtStatus(result.lastStatus));
        table_->item(0, columnIndex(Column::kDiagnostic))->setText(detailParts.join(QStringLiteral("; ")));
        for (int column = 0; column < columnIndex(Column::kCount); ++column)
        {
            table_->item(0, column)->setToolTip(table_->item(0, column)->text());
        }
    }

    table_->setSortingEnabled(true);
    if (table_->rowCount() > 0)
    {
        table_->selectRow(0);
    }
    table_->resizeRowsToContents();
}

void ProcessMessageHookWindow::applyColumnPreset(const QString& presetName)
{
    static const std::array<Column, 9> kGroupA{
        Column::kTargetProcessId,
        Column::kTargetThreadId,
        Column::kHookType,
        Column::kOwnerProcessId,
        Column::kOwnerThreadId,
        Column::kCallbackAddress,
        Column::kModule,
        Column::kFlags,
        Column::kStatus };
    static const std::array<Column, 11> kGroupB{
        Column::kTargetProcessId,
        Column::kTargetThreadId,
        Column::kHookType,
        Column::kSessionId,
        Column::kHookHandle,
        Column::kHookObject,
        Column::kModuleBase,
        Column::kProcedureOffset,
        Column::kSource,
        Column::kLastStatus,
        Column::kDiagnostic };

    for (int column = 0; column < columnIndex(Column::kCount); ++column)
    {
        const auto kMatchesColumn = [column](const Column candidate)
        {
            return columnIndex(candidate) == column;
        };
        const bool kVisible = presetName == QStringLiteral("B")
            ? std::any_of(kGroupB.begin(), kGroupB.end(), kMatchesColumn)
            : std::any_of(kGroupA.begin(), kGroupA.end(), kMatchesColumn);
        table_->setColumnHidden(column, !kVisible);
    }
    table_->setProperty("kswordColumnPreset", presetName == QStringLiteral("B")
        ? QStringLiteral("B")
        : QStringLiteral("A"));
    updateColumnPresetButtons();
}

void ProcessMessageHookWindow::updateColumnPresetButtons()
{
    const QString kPreset = table_->property("kswordColumnPreset").toString();
    columnAButton_->setStyleSheet(presetButtonStyle(kPreset == QStringLiteral("A")));
    columnBButton_->setStyleSheet(presetButtonStyle(kPreset == QStringLiteral("B")));
}

void ProcessMessageHookWindow::showHeaderContextMenu(const QPoint& localPosition)
{
    QMenu menu(this);
    QAction* titleAction = menu.addAction(hookWindowText(QStringLiteral("显示的列")));
    titleAction->setEnabled(false);
    menu.addSeparator();

    for (int column = 0; column < columnIndex(Column::kCount); ++column)
    {
        const QTableWidgetItem* headerItem = table_->horizontalHeaderItem(column);
        QAction* action = menu.addAction(headerItem != nullptr ? headerItem->text() : QString::number(column));
        action->setCheckable(true);
        action->setChecked(!table_->isColumnHidden(column));
        action->setData(column);
    }
    menu.addSeparator();
    QAction* showAllAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/filter_funnel.svg")),
        hookWindowText(QStringLiteral("显示全部列")));

    QAction* selectedAction = menu.exec(
        table_->horizontalHeader()->viewport()->mapToGlobal(localPosition));
    if (selectedAction == nullptr)
    {
        return;
    }
    if (selectedAction == showAllAction)
    {
        for (int column = 0; column < columnIndex(Column::kCount); ++column)
        {
            table_->setColumnHidden(column, false);
        }
        table_->setProperty("kswordColumnPreset", QStringLiteral("Custom"));
        updateColumnPresetButtons();
        return;
    }

    const int kColumn = selectedAction->data().toInt();
    if (!selectedAction->isChecked() && visibleColumnCount() <= 1)
    {
        table_->setColumnHidden(kColumn, false);
        return;
    }
    table_->setColumnHidden(kColumn, !selectedAction->isChecked());
    table_->setProperty("kswordColumnPreset", QStringLiteral("Custom"));
    updateColumnPresetButtons();
}

void ProcessMessageHookWindow::showTableContextMenu(const QPoint& localPosition)
{
    const QModelIndex kIndex = table_->indexAt(localPosition);
    if (kIndex.isValid())
    {
        table_->setCurrentCell(kIndex.row(), kIndex.column());
        table_->selectRow(kIndex.row());
    }

    QMenu menu(this);
    QAction* copyCellAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_copy_cell.svg")),
        hookWindowText(QStringLiteral("复制单元格")));
    QAction* copyRowAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
        hookWindowText(QStringLiteral("复制当前行")));
    QAction* copyAllAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
        hookWindowText(QStringLiteral("复制全部行")));
    copyCellAction->setEnabled(table_->currentItem() != nullptr);
    copyRowAction->setEnabled(table_->currentRow() >= 0);
    copyAllAction->setEnabled(table_->rowCount() > 0);

    QAction* selectedAction = menu.exec(table_->viewport()->mapToGlobal(localPosition));
    if (selectedAction == copyCellAction) copyCurrentCell();
    else if (selectedAction == copyRowAction) copyCurrentRow();
    else if (selectedAction == copyAllAction) copyAllRows();
}

void ProcessMessageHookWindow::copyCurrentCell() const
{
    if (table_->currentItem() != nullptr)
    {
        QApplication::clipboard()->setText(table_->currentItem()->text());
    }
}

void ProcessMessageHookWindow::copyCurrentRow() const
{
    if (table_->currentRow() >= 0)
    {
        QApplication::clipboard()->setText(
            tableHeaderText() + QLatin1Char('\n') + tableRowText(table_->currentRow()));
    }
}

void ProcessMessageHookWindow::copyAllRows() const
{
    QStringList lines;
    lines << tableHeaderText();
    for (int row = 0; row < table_->rowCount(); ++row)
    {
        lines << tableRowText(row);
    }
    QApplication::clipboard()->setText(lines.join(QLatin1Char('\n')));
}

QString ProcessMessageHookWindow::tableRowText(const int row) const
{
    QStringList fields;
    for (int column = 0; column < columnIndex(Column::kCount); ++column)
    {
        const QTableWidgetItem* item = table_->item(row, column);
        fields << (item != nullptr ? item->text() : QString());
    }
    return fields.join(QLatin1Char('\t'));
}

QString ProcessMessageHookWindow::tableHeaderText() const
{
    QStringList headers;
    for (int column = 0; column < columnIndex(Column::kCount); ++column)
    {
        const QTableWidgetItem* item = table_->horizontalHeaderItem(column);
        headers << (item != nullptr ? item->text() : QString());
    }
    return headers.join(QLatin1Char('\t'));
}

int ProcessMessageHookWindow::visibleColumnCount() const
{
    int count = 0;
    for (int column = 0; column < columnIndex(Column::kCount); ++column)
    {
        if (!table_->isColumnHidden(column))
        {
            ++count;
        }
    }
    return count;
}
