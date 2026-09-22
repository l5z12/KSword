#include "HudProcessListPanel.h"

#include <QAbstractItemView>
#include <QApplication>
#include <QDateTime>
#include <QDir>
#include <QFileIconProvider>
#include <QFileInfo>
#include <QFrame>
#include <QFont>
#include <QHeaderView>
#include <QHideEvent>
#include <QMenu>
#include <QPainter>
#include <QShowEvent>
#include <QStyledItemDelegate>
#include <QTimer>
#include <QTreeWidget>
#include <QVBoxLayout>

#include <QtConcurrent/QtConcurrentRun>

#ifndef WINVER
#define WINVER 0x0601
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <Pdh.h>
#include <pdhmsg.h>
#include <iphlpapi.h>
#include <tcpestats.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <mutex>
#include <vector>

#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Pdh.lib")
#pragma comment(lib, "Iphlpapi.lib")

namespace
{
    constexpr int kNameColumn = 0;
    constexpr int kUsageRatioRole = Qt::UserRole + 2;
    constexpr int kExpansionKeyRole = Qt::UserRole + 3;
    constexpr int kTerminateProcessIdentityListRole = Qt::UserRole + 4;
    constexpr int kMetricColumnFirst = 2;
    constexpr int kMetricColumnLast = 6;

    struct VisibleWindowEnumContext
    {
        QSet<quint32>* pidSet = nullptr;
    };

    QStringList processHeaders()
    {
        return {
            QStringLiteral("进程名"),
            QStringLiteral("PID"),
            QStringLiteral("CPU"),
            QStringLiteral("RAM"),
            QStringLiteral("DISK"),
            QStringLiteral("GPU"),
            QStringLiteral("Net")
        };
    }

    quint64 fileTimeToUint64(const FILETIME& fileTimeValue)
    {
        ULARGE_INTEGER unsignedValue{};
        unsignedValue.LowPart = fileTimeValue.dwLowDateTime;
        unsignedValue.HighPart = fileTimeValue.dwHighDateTime;
        return unsignedValue.QuadPart;
    }

    quint32 extractPidFromGpuEngineInstanceName(const QString& instanceNameText)
    {
        // Inputs: a PDH GPU Engine wildcard instance name such as "pid_1234_luid_..._engtype_3D".
        // Processing: find the "pid_" marker and parse the following decimal digits only.
        // Return: the owning process ID, or 0 when the counter instance does not expose a PID.
        const QString kLowerText = instanceNameText.toLower();
        const int kPidMarkerIndex = kLowerText.indexOf(QStringLiteral("pid_"));
        if (kPidMarkerIndex < 0)
        {
            return 0;
        }

        QString pidText;
        int characterIndex = kPidMarkerIndex + 4;
        while (characterIndex < kLowerText.size() && kLowerText.at(characterIndex).isDigit())
        {
            pidText.append(kLowerText.at(characterIndex));
            ++characterIndex;
        }

        bool parseOk = false;
        const uint kPidValue = pidText.toUInt(&parseOk);
        return parseOk ? static_cast<quint32>(kPidValue) : 0;
    }

    QHash<quint32, double> sampleProcessGpuUsagePercentByPid()
    {
        // Inputs: none; the Windows PDH "GPU Engine(*)\\Utilization Percentage" counter is sampled.
        // Processing: keep one process-wide PDH wildcard query, parse PID-bearing GPU engine instances,
        //             and add all active engine usage for the same PID with a 100% display cap.
        // Return: PID -> current GPU utilization percent; an empty map is valid on first sample or PDH failure.
        static std::mutex samplerMutex;
        static PDH_HQUERY queryHandle = nullptr;
        static PDH_HCOUNTER counterHandle = nullptr;

        std::lock_guard<std::mutex> lockGuard(samplerMutex);
        QHash<quint32, double> usagePercentByPid;

        if (queryHandle == nullptr)
        {
            PDH_HQUERY newQueryHandle = nullptr;
            if (::PdhOpenQueryW(nullptr, 0, &newQueryHandle) != ERROR_SUCCESS || newQueryHandle == nullptr)
            {
                return usagePercentByPid;
            }

            PDH_HCOUNTER newCounterHandle = nullptr;
            const PDH_STATUS kAddStatus = ::PdhAddEnglishCounterW(
                newQueryHandle,
                L"\\GPU Engine(*)\\Utilization Percentage",
                0,
                &newCounterHandle);
            if (kAddStatus != ERROR_SUCCESS || newCounterHandle == nullptr)
            {
                ::PdhCloseQuery(newQueryHandle);
                return usagePercentByPid;
            }

            queryHandle = newQueryHandle;
            counterHandle = newCounterHandle;
            ::PdhCollectQueryData(queryHandle);
            return usagePercentByPid;
        }

        if (::PdhCollectQueryData(queryHandle) != ERROR_SUCCESS)
        {
            ::PdhCloseQuery(queryHandle);
            queryHandle = nullptr;
            counterHandle = nullptr;
            return usagePercentByPid;
        }

        DWORD bufferSize = 0;
        DWORD itemCount = 0;
        PDH_STATUS queryStatus = ::PdhGetFormattedCounterArrayW(
            counterHandle,
            PDH_FMT_DOUBLE,
            &bufferSize,
            &itemCount,
            nullptr);
        if (queryStatus != PDH_MORE_DATA || bufferSize == 0 || itemCount == 0)
        {
            return usagePercentByPid;
        }

        std::vector<unsigned char> rawBuffer(bufferSize);
        auto* itemPointer = reinterpret_cast<PDH_FMT_COUNTERVALUE_ITEM_W*>(rawBuffer.data());
        queryStatus = ::PdhGetFormattedCounterArrayW(
            counterHandle,
            PDH_FMT_DOUBLE,
            &bufferSize,
            &itemCount,
            itemPointer);
        if (queryStatus != ERROR_SUCCESS)
        {
            return usagePercentByPid;
        }

        for (DWORD itemIndex = 0; itemIndex < itemCount; ++itemIndex)
        {
            const PDH_FMT_COUNTERVALUE_ITEM_W& itemValue = itemPointer[itemIndex];
            if (itemValue.FmtValue.CStatus != ERROR_SUCCESS)
            {
                continue;
            }

            const QString kInstanceNameText = QString::fromWCharArray(
                itemValue.szName != nullptr ? itemValue.szName : L"");
            const quint32 kPidValue = extractPidFromGpuEngineInstanceName(kInstanceNameText);
            if (kPidValue == 0)
            {
                continue;
            }

            const double kBoundedUsagePercent = qBound(0.0, itemValue.FmtValue.doubleValue, 100.0);
            const double kAccumulatedUsagePercent =
                usagePercentByPid.value(kPidValue, 0.0) + kBoundedUsagePercent;
            usagePercentByPid.insert(kPidValue, qBound(0.0, kAccumulatedUsagePercent, 100.0));
        }

        return usagePercentByPid;
    }

    bool tcpStateCanCarryData(const DWORD stateValue)
    {
        // Inputs: a MIB_TCP_STATE numeric value from the TCP owner-PID tables.
        // Processing: skip passive/terminal rows that cannot produce meaningful byte deltas.
        // Return: true when querying TCP EStats data counters is worthwhile for this connection.
        return stateValue != static_cast<DWORD>(MIB_TCP_STATE_CLOSED)
            && stateValue != static_cast<DWORD>(MIB_TCP_STATE_LISTEN)
            && stateValue != static_cast<DWORD>(MIB_TCP_STATE_TIME_WAIT)
            && stateValue != static_cast<DWORD>(MIB_TCP_STATE_DELETE_TCB);
    }

    quint64 cumulativeTcpDataBytes(const TCP_ESTATS_DATA_ROD_v0& dataStats)
    {
        // Inputs: one TCP EStats data snapshot for a live connection.
        // Processing: prefer direct data-byte counters, while tolerating systems that populate throughput counters.
        // Return: cumulative inbound plus outbound bytes for later per-PID rate delta calculation.
        const quint64 kDirectDataBytes =
            static_cast<quint64>(dataStats.DataBytesIn)
            + static_cast<quint64>(dataStats.DataBytesOut);
        const quint64 kThroughputBytes =
            static_cast<quint64>(dataStats.ThruBytesReceived)
            + static_cast<quint64>(dataStats.ThruBytesAcked);
        return std::max(kDirectDataBytes, kThroughputBytes);
    }

    bool queryTcp4DataStats(const MIB_TCPROW_OWNER_PID& ownerRow, TCP_ESTATS_DATA_ROD_v0* dataStatsOut)
    {
        // Inputs: one IPv4 TCP owner-PID row and an output buffer.
        // Processing: enable TCP EStats collection for the row, then read the read-only data counters.
        // Return: true when dataStatsOut receives a valid cumulative byte snapshot.
        if (dataStatsOut == nullptr)
        {
            return false;
        }

        MIB_TCPROW tcpRow{};
        tcpRow.dwState = ownerRow.dwState;
        tcpRow.dwLocalAddr = ownerRow.dwLocalAddr;
        tcpRow.dwLocalPort = ownerRow.dwLocalPort;
        tcpRow.dwRemoteAddr = ownerRow.dwRemoteAddr;
        tcpRow.dwRemotePort = ownerRow.dwRemotePort;

        TCP_ESTATS_DATA_RW_v0 rwStats{};
        rwStats.EnableCollection = TRUE;
        ::SetPerTcpConnectionEStats(
            &tcpRow,
            TcpConnectionEstatsData,
            reinterpret_cast<PUCHAR>(&rwStats),
            0,
            sizeof(rwStats),
            0);

        TCP_ESTATS_DATA_ROD_v0 rodStats{};
        const ULONG kQueryStatus = ::GetPerTcpConnectionEStats(
            &tcpRow,
            TcpConnectionEstatsData,
            nullptr,
            0,
            0,
            nullptr,
            0,
            0,
            reinterpret_cast<PUCHAR>(&rodStats),
            0,
            sizeof(rodStats));
        if (kQueryStatus != NO_ERROR)
        {
            return false;
        }

        *dataStatsOut = rodStats;
        return true;
    }

    bool queryTcp6DataStats(const MIB_TCP6ROW_OWNER_PID& ownerRow, TCP_ESTATS_DATA_ROD_v0* dataStatsOut)
    {
        // Inputs: one IPv6 TCP owner-PID row and an output buffer.
        // Processing: build the plain MIB_TCP6ROW key required by IP Helper EStats APIs.
        // Return: true when dataStatsOut receives a valid cumulative byte snapshot.
        if (dataStatsOut == nullptr)
        {
            return false;
        }

        MIB_TCP6ROW tcpRow{};
        std::memcpy(&tcpRow.LocalAddr, ownerRow.ucLocalAddr, sizeof(tcpRow.LocalAddr));
        tcpRow.dwLocalScopeId = ownerRow.dwLocalScopeId;
        tcpRow.dwLocalPort = ownerRow.dwLocalPort;
        std::memcpy(&tcpRow.RemoteAddr, ownerRow.ucRemoteAddr, sizeof(tcpRow.RemoteAddr));
        tcpRow.dwRemoteScopeId = ownerRow.dwRemoteScopeId;
        tcpRow.dwRemotePort = ownerRow.dwRemotePort;
        tcpRow.State = static_cast<MIB_TCP_STATE>(ownerRow.dwState);

        TCP_ESTATS_DATA_RW_v0 rwStats{};
        rwStats.EnableCollection = TRUE;
        ::SetPerTcp6ConnectionEStats(
            &tcpRow,
            TcpConnectionEstatsData,
            reinterpret_cast<PUCHAR>(&rwStats),
            0,
            sizeof(rwStats),
            0);

        TCP_ESTATS_DATA_ROD_v0 rodStats{};
        const ULONG kQueryStatus = ::GetPerTcp6ConnectionEStats(
            &tcpRow,
            TcpConnectionEstatsData,
            nullptr,
            0,
            0,
            nullptr,
            0,
            0,
            reinterpret_cast<PUCHAR>(&rodStats),
            0,
            sizeof(rodStats));
        if (kQueryStatus != NO_ERROR)
        {
            return false;
        }

        *dataStatsOut = rodStats;
        return true;
    }

    void collectTcp4NetworkBytesByPid(QHash<quint32, quint64>* networkBytesByPid)
    {
        // Inputs: mutable PID -> bytes map.
        // Processing: enumerate IPv4 TCP connections with owner PIDs and aggregate cumulative EStats bytes.
        // Return behavior: no value is returned; unsupported or denied rows are skipped.
        if (networkBytesByPid == nullptr)
        {
            return;
        }

        ULONG tableSize = 0;
        ULONG tableStatus = ::GetExtendedTcpTable(
            nullptr,
            &tableSize,
            FALSE,
            AF_INET,
            TCP_TABLE_OWNER_PID_ALL,
            0);
        if ((tableStatus != ERROR_INSUFFICIENT_BUFFER && tableStatus != NO_ERROR) || tableSize == 0)
        {
            return;
        }

        std::vector<unsigned char> tableBuffer(tableSize);
        auto* tablePointer = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(tableBuffer.data());
        tableStatus = ::GetExtendedTcpTable(
            tablePointer,
            &tableSize,
            FALSE,
            AF_INET,
            TCP_TABLE_OWNER_PID_ALL,
            0);
        if (tableStatus != NO_ERROR)
        {
            return;
        }

        for (DWORD rowIndex = 0; rowIndex < tablePointer->dwNumEntries; ++rowIndex)
        {
            const MIB_TCPROW_OWNER_PID& rowValue = tablePointer->table[rowIndex];
            const quint32 kPidValue = static_cast<quint32>(rowValue.dwOwningPid);
            if (kPidValue == 0 || !tcpStateCanCarryData(rowValue.dwState))
            {
                continue;
            }

            TCP_ESTATS_DATA_ROD_v0 dataStats{};
            if (queryTcp4DataStats(rowValue, &dataStats))
            {
                (*networkBytesByPid)[kPidValue] += cumulativeTcpDataBytes(dataStats);
            }
        }
    }

    void collectTcp6NetworkBytesByPid(QHash<quint32, quint64>* networkBytesByPid)
    {
        // Inputs: mutable PID -> bytes map.
        // Processing: enumerate IPv6 TCP connections with owner PIDs and aggregate cumulative EStats bytes.
        // Return behavior: no value is returned; unsupported or denied rows are skipped.
        if (networkBytesByPid == nullptr)
        {
            return;
        }

        ULONG tableSize = 0;
        ULONG tableStatus = ::GetExtendedTcpTable(
            nullptr,
            &tableSize,
            FALSE,
            AF_INET6,
            TCP_TABLE_OWNER_PID_ALL,
            0);
        if ((tableStatus != ERROR_INSUFFICIENT_BUFFER && tableStatus != NO_ERROR) || tableSize == 0)
        {
            return;
        }

        std::vector<unsigned char> tableBuffer(tableSize);
        auto* tablePointer = reinterpret_cast<PMIB_TCP6TABLE_OWNER_PID>(tableBuffer.data());
        tableStatus = ::GetExtendedTcpTable(
            tablePointer,
            &tableSize,
            FALSE,
            AF_INET6,
            TCP_TABLE_OWNER_PID_ALL,
            0);
        if (tableStatus != NO_ERROR)
        {
            return;
        }

        for (DWORD rowIndex = 0; rowIndex < tablePointer->dwNumEntries; ++rowIndex)
        {
            const MIB_TCP6ROW_OWNER_PID& rowValue = tablePointer->table[rowIndex];
            const quint32 kPidValue = static_cast<quint32>(rowValue.dwOwningPid);
            if (kPidValue == 0 || !tcpStateCanCarryData(rowValue.dwState))
            {
                continue;
            }

            TCP_ESTATS_DATA_ROD_v0 dataStats{};
            if (queryTcp6DataStats(rowValue, &dataStats))
            {
                (*networkBytesByPid)[kPidValue] += cumulativeTcpDataBytes(dataStats);
            }
        }
    }

    QHash<quint32, quint64> sampleTcpNetworkBytesByPid()
    {
        // Inputs: none; Windows IP Helper owner-PID TCP tables are sampled.
        // Processing: collect IPv4 and IPv6 TCP EStats byte counters keyed by owning PID.
        // Return: PID -> cumulative TCP bytes. UDP and driver-attributed traffic are intentionally absent.
        QHash<quint32, quint64> networkBytesByPid;
        collectTcp4NetworkBytesByPid(&networkBytesByPid);
        collectTcp6NetworkBytesByPid(&networkBytesByPid);
        return networkBytesByPid;
    }

    // EnumWindows callback used by collectVisibleWindowPidSet().
    // Input: hwndValue is a candidate top-level window, lParamValue points to VisibleWindowEnumContext.
    // Processing: keep normal visible owner/root windows with a non-empty title and record their owning PID.
    // Return: TRUE keeps enumeration running; FALSE is never used because one bad window must not stop refresh.
    BOOL CALLBACK collectVisibleWindowProc(HWND hwndValue, LPARAM lParamValue)
    {
        auto* contextPointer = reinterpret_cast<VisibleWindowEnumContext*>(lParamValue);
        if (contextPointer == nullptr || contextPointer->pidSet == nullptr)
        {
            return TRUE;
        }

        if (hwndValue == nullptr || ::IsWindowVisible(hwndValue) == FALSE)
        {
            return TRUE;
        }

        if (::GetAncestor(hwndValue, GA_ROOTOWNER) != hwndValue)
        {
            return TRUE;
        }

        const LONG_PTR kExtendedStyle = ::GetWindowLongPtrW(hwndValue, GWL_EXSTYLE);
        if ((kExtendedStyle & WS_EX_TOOLWINDOW) != 0)
        {
            return TRUE;
        }

        if (::GetWindowTextLengthW(hwndValue) <= 0)
        {
            return TRUE;
        }

        DWORD processIdValue = 0;
        ::GetWindowThreadProcessId(hwndValue, &processIdValue);
        if (processIdValue != 0)
        {
            contextPointer->pidSet->insert(static_cast<quint32>(processIdValue));
        }

        return TRUE;
    }

    // Collects process IDs that own normal visible top-level windows.
    // Input: none; the current desktop window list is read through user32.
    // Processing: EnumWindows filters out invisible/tool/owned/titleless windows to approximate Task Manager apps.
    // Return: a PID set used as application roots; an empty set is valid when no window can be enumerated.
    QSet<quint32> collectVisibleWindowPidSet()
    {
        QSet<quint32> visibleWindowPidSet;
        VisibleWindowEnumContext context{ &visibleWindowPidSet };
        ::EnumWindows(collectVisibleWindowProc, reinterpret_cast<LPARAM>(&context));
        return visibleWindowPidSet;
    }

    // Reads the Windows installation directory in normalized lower-case form.
    // Input: none; GetWindowsDirectoryW supplies the local Windows path.
    // Processing: convert backslashes to forward slashes so path-prefix checks are stable.
    // Return: lower-case Windows directory path, or "c:/windows" as a defensive fallback.
    QString normalizedWindowsDirectoryPath()
    {
        std::array<wchar_t, MAX_PATH> windowsPathBuffer{};
        const UINT kPathLength = ::GetWindowsDirectoryW(
            windowsPathBuffer.data(),
            static_cast<UINT>(windowsPathBuffer.size()));
        QString windowsDirectoryPath =
            kPathLength > 0
            ? QString::fromWCharArray(windowsPathBuffer.data(), static_cast<int>(kPathLength))
            : QStringLiteral("C:\\Windows");
        return QDir::fromNativeSeparators(windowsDirectoryPath).toLower();
    }

    QColor usageRatioToHighlightColor(double usageRatio)
    {
        usageRatio = std::clamp(usageRatio, 0.0, 1.0);
        const int kAlphaValue = static_cast<int>(24.0 + usageRatio * 146.0);
        QColor highlightColor(46, 139, 255);
        highlightColor.setAlpha(kAlphaValue);
        return highlightColor;
    }

    class HudProcessMetricDelegate final : public QStyledItemDelegate
    {
    public:
        explicit HudProcessMetricDelegate(QObject* parent = nullptr)
            : QStyledItemDelegate(parent)
        {
        }

        void setTextColor(const QColor& colorValue)
        {
            textColor_ = colorValue;
        }

    protected:
        void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const override
        {
            if (painter == nullptr)
            {
                return;
            }

            QStyleOptionViewItem viewOption(option);
            initStyleOption(&viewOption, index);
            viewOption.text.clear();

            painter->save();
            painter->setRenderHint(QPainter::Antialiasing, true);

            const bool kSelected = (option.state & QStyle::State_Selected) != 0;
            if (kSelected)
            {
                painter->fillRect(option.rect, QColor(89, 139, 214, 88));
            }

            const QVariant kUsageRatioVariant = index.data(kUsageRatioRole);
            if (kUsageRatioVariant.isValid())
            {
                const double kUsageRatio = std::clamp(kUsageRatioVariant.toDouble(), 0.0, 1.0);
                const QRectF kTrackRect = QRectF(option.rect.adjusted(6, 5, -6, -5));
                if (kTrackRect.width() > 2.0 && kTrackRect.height() > 2.0)
                {
                    painter->setPen(Qt::NoPen);
                    painter->setBrush(QColor(255, 255, 255, 18));
                    painter->drawRoundedRect(kTrackRect, 8.0, 8.0);

                    QRectF fillRect = kTrackRect;
                    fillRect.setWidth(std::max(2.0, kTrackRect.width() * kUsageRatio));
                    painter->setBrush(usageRatioToHighlightColor(kUsageRatio));
                    painter->drawRoundedRect(fillRect, 8.0, 8.0);
                }
            }

            QColor textColor = textColor_;
            if (kSelected)
            {
                textColor = QColor(255, 255, 255);
            }
            painter->setPen(textColor);

            const int kColumnIndex = index.column();
            QRect textRect = option.rect.adjusted(10, 0, -10, 0);
            if (kColumnIndex == kNameColumn)
            {
                const QVariant kDecorationVariant = index.data(Qt::DecorationRole);
                if (kDecorationVariant.canConvert<QIcon>())
                {
                    const QIcon kIconValue = qvariant_cast<QIcon>(kDecorationVariant);
                    if (!kIconValue.isNull())
                    {
                        const int kIconSize = std::min(18, std::max(14, option.rect.height() - 8));
                        const QRect kIconRect(
                            option.rect.left() + 8,
                            option.rect.top() + (option.rect.height() - kIconSize) / 2,
                            kIconSize,
                            kIconSize);
                        kIconValue.paint(painter, kIconRect, Qt::AlignCenter, QIcon::Normal, QIcon::On);
                        textRect.adjust(kIconSize + 8, 0, 0, 0);
                    }
                }
            }
            const int kTextFlags =
                (kColumnIndex >= kMetricColumnFirst ? Qt::AlignRight : Qt::AlignLeft)
                | Qt::AlignVCenter
                | Qt::TextSingleLine;
            painter->drawText(textRect, kTextFlags, index.data(Qt::DisplayRole).toString());
            painter->restore();
        }

    private:
        QColor textColor_ = QColor(255, 255, 255);
    };
}

HudProcessListPanel::HudProcessListPanel(QWidget* parent)
    : QWidget(parent)
{
    logicalCpuCount_ = static_cast<int>(std::max<DWORD>(
        1,
        ::GetActiveProcessorCount(ALL_PROCESSOR_GROUPS)));

    fileIconProvider_ = new QFileIconProvider();
    initializeUi();

    refreshWatcher_ = new QFutureWatcher<RefreshResult>(this);
    connect(refreshWatcher_, &QFutureWatcher<RefreshResult>::finished, this, [this]() {
        refreshInProgress_ = false;
        applyRefreshResult(refreshWatcher_->result());
        });

    refreshTimer_ = new QTimer(this);
    refreshTimer_->setInterval(1000);
    connect(refreshTimer_, &QTimer::timeout, this, [this]() {
        requestRefresh();
        });
}

HudProcessListPanel::~HudProcessListPanel()
{
    stopRefreshing();
    delete fileIconProvider_;
    fileIconProvider_ = nullptr;
}

void HudProcessListPanel::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    startRefreshing();
}

void HudProcessListPanel::hideEvent(QHideEvent* event)
{
    QWidget::hideEvent(event);
    stopRefreshing();
}

void HudProcessListPanel::initializeUi()
{
    setAttribute(Qt::WA_StyledBackground, true);
    setStyleSheet(QStringLiteral("background:transparent;"));

    QVBoxLayout* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(0, 0, 0, 0);
    rootLayout->setSpacing(0);

    treeWidget_ = new QTreeWidget(this);
    treeWidget_->setColumnCount(kColumnCount);
    treeWidget_->setHeaderLabels(processHeaders());
    treeWidget_->setRootIsDecorated(true);
    treeWidget_->setItemsExpandable(true);
    treeWidget_->setSelectionBehavior(QAbstractItemView::SelectRows);
    treeWidget_->setSelectionMode(QAbstractItemView::SingleSelection);
    treeWidget_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    treeWidget_->setUniformRowHeights(true);
    treeWidget_->setSortingEnabled(false);
    treeWidget_->setAlternatingRowColors(false);
    treeWidget_->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    treeWidget_->setFrameShape(QFrame::NoFrame);
    treeWidget_->setContextMenuPolicy(Qt::CustomContextMenu);
    applyTreeWidgetStyle();

    auto* delegate = new HudProcessMetricDelegate(treeWidget_);
    delegate->setTextColor(tableTextColor_);
    metricDelegate_ = delegate;
    treeWidget_->setItemDelegate(delegate);

    QHeaderView* headerView = treeWidget_->header();
    if (headerView != nullptr)
    {
        headerView->setStretchLastSection(false);
        headerView->setSectionResizeMode(kNameColumn, QHeaderView::Stretch);
        headerView->setSectionResizeMode(kPidColumn, QHeaderView::Fixed);
        headerView->setSectionResizeMode(kCpuColumn, QHeaderView::Fixed);
        headerView->setSectionResizeMode(kRamColumn, QHeaderView::Fixed);
        headerView->setSectionResizeMode(kDiskColumn, QHeaderView::Fixed);
        headerView->setSectionResizeMode(kGpuColumn, QHeaderView::Fixed);
        headerView->setSectionResizeMode(kNetColumn, QHeaderView::Fixed);
        treeWidget_->setColumnWidth(kPidColumn, 80);
        treeWidget_->setColumnWidth(kCpuColumn, 80);
        treeWidget_->setColumnWidth(kRamColumn, 90);
        treeWidget_->setColumnWidth(kDiskColumn, 95);
        treeWidget_->setColumnWidth(kGpuColumn, 80);
        treeWidget_->setColumnWidth(kNetColumn, 95);
    }

    connect(treeWidget_, &QTreeWidget::customContextMenuRequested, this, [this](const QPoint& localPosition) {
        showContextMenu(localPosition);
        });

    rootLayout->addWidget(treeWidget_, 1);
}

void HudProcessListPanel::applyTreeWidgetStyle()
{
    // Inputs: current process-table text color.
    // Processing: applies the full tree, header, item, and custom scrollbar stylesheet in one place.
    // Return behavior: no value is returned; the QTreeWidget visual style is updated when the widget exists.
    if (treeWidget_ == nullptr)
    {
        return;
    }

    treeWidget_->setStyleSheet(QStringLiteral(
        "QTreeWidget{"
        "background:transparent;"
        "color:rgba(%1,%2,%3,%4);"
        "border:none;"
        "font:10pt \"Segoe UI\";"
        "outline:0;"
        "}"
        "QTreeWidget::item{height:28px;}"
        "QTreeWidget::item:selected{"
        "background:rgba(89,139,214,88);"
        "color:rgba(255,255,255,245);"
        "}"
        "QHeaderView::section{"
        "background:transparent;"
        "color:rgba(%1,%2,%3,225);"
        "border-right:1px solid rgba(255,255,255,28);"
        "border-bottom:1px solid rgba(255,255,255,28);"
        "padding:4px 6px;"
        "}"
        "QScrollBar:vertical{"
        "background:rgba(255,255,255,10);"
        "width:10px;"
        "margin:4px 2px 4px 2px;"
        "border-radius:5px;"
        "}"
        "QScrollBar::handle:vertical{"
        "background:rgba(96,165,250,150);"
        "min-height:32px;"
        "border-radius:5px;"
        "}"
        "QScrollBar::handle:vertical:hover{"
        "background:rgba(125,185,255,210);"
        "}"
        "QScrollBar::add-line:vertical,"
        "QScrollBar::sub-line:vertical{"
        "height:0px;"
        "background:transparent;"
        "border:none;"
        "}"
        "QScrollBar::add-page:vertical,"
        "QScrollBar::sub-page:vertical{"
        "background:transparent;"
        "}"
        "QScrollBar:horizontal{"
        "height:0px;"
        "background:transparent;"
        "}").arg(tableTextColor_.red()).arg(tableTextColor_.green()).arg(tableTextColor_.blue()).arg(tableTextColor_.alpha()));
}

void HudProcessListPanel::setTableTextColor(const QColor& colorValue)
{
    tableTextColor_ = colorValue;
    auto* metricDelegate = dynamic_cast<HudProcessMetricDelegate*>(metricDelegate_);
    if (metricDelegate != nullptr)
    {
        metricDelegate->setTextColor(colorValue);
    }

    if (treeWidget_ != nullptr)
    {
        applyTreeWidgetStyle();
        treeWidget_->viewport()->update();
    }
}

void HudProcessListPanel::showContextMenu(const QPoint& localPosition)
{
    if (treeWidget_ == nullptr)
    {
        return;
    }

    QTreeWidgetItem* itemPointer = treeWidget_->itemAt(localPosition);
    if (itemPointer == nullptr)
    {
        return;
    }

    QVector<ProcessIdentity> terminateIdentityList;
    const QVariant kTerminateIdentityListVariant =
        itemPointer->data(kNameColumn, kTerminateProcessIdentityListRole);
    if (kTerminateIdentityListVariant.canConvert<QVariantList>())
    {
        const QVariantList kVariantList = kTerminateIdentityListVariant.toList();
        terminateIdentityList.reserve(kVariantList.size());
        for (const QVariant& identityVariant : kVariantList)
        {
            if (!identityVariant.canConvert<QVariantList>())
            {
                continue;
            }

            const QVariantList kIdentityValues = identityVariant.toList();
            if (kIdentityValues.size() != 2)
            {
                continue;
            }

            bool childPidOk = false;
            bool creationTimeOk = false;
            const quint32 kChildPidValue = kIdentityValues.at(0).toUInt(&childPidOk);
            const quint64 kChildCreationTime100ns = kIdentityValues.at(1).toULongLong(&creationTimeOk);
            if (childPidOk && creationTimeOk
                && kChildPidValue != 0 && kChildCreationTime100ns != 0)
            {
                terminateIdentityList.push_back({ kChildPidValue, kChildCreationTime100ns });
            }
        }
    }
    if (terminateIdentityList.isEmpty())
    {
        return;
    }

    QMenu menu(treeWidget_);
    menu.setAttribute(Qt::WA_TranslucentBackground, true);
    menu.setStyleSheet(QStringLiteral(
        "QMenu{"
        "background-color: rgba(24,28,34,236);"
        "border: 1px solid rgba(255,255,255,28);"
        "border-radius: 12px;"
        "padding: 6px;"
        "color: rgba(248,250,255,245);"
        "}"
        "QMenu::item{"
        "padding: 8px 28px 8px 12px;"
        "border-radius: 8px;"
        "background: transparent;"
        "}"
        "QMenu::item:selected{"
        "background-color: rgba(59,130,246,140);"
        "}"
        "QMenu::separator{"
        "height: 1px;"
        "background: rgba(255,255,255,18);"
        "margin: 4px 8px;"
        "}"));

    QAction* terminateAction = menu.addAction(
        terminateIdentityList.size() > 1
        ? QStringLiteral("结束此应用")
        : QStringLiteral("结束进程"));
    QAction* selectedAction =
        menu.exec(treeWidget_->viewport()->mapToGlobal(localPosition));
    if (selectedAction == terminateAction)
    {
        terminateProcessesByIdentityList(terminateIdentityList);
        requestRefresh();
    }
}

bool HudProcessListPanel::terminateProcessByIdentity(const ProcessIdentity& processIdentity)
{
    if (processIdentity.pid == 0 || processIdentity.creationTime100ns == 0)
    {
        return false;
    }

    const HANDLE kProcessHandle = ::OpenProcess(
        PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        processIdentity.pid);
    if (kProcessHandle == nullptr)
    {
        return false;
    }

    FILETIME creationTime{};
    FILETIME exitTime{};
    FILETIME kernelTime{};
    FILETIME userTime{};
    const bool kIdentityMatches =
        ::GetProcessTimes(kProcessHandle, &creationTime, &exitTime, &kernelTime, &userTime) != FALSE
        && fileTimeToUint64(creationTime) == processIdentity.creationTime100ns;
    const BOOL kTerminateOk = kIdentityMatches ? ::TerminateProcess(kProcessHandle, 1) : FALSE;
    ::CloseHandle(kProcessHandle);
    return kTerminateOk != FALSE;
}

int HudProcessListPanel::terminateProcessesByIdentityList(
    const QVector<ProcessIdentity>& processIdentityList)
{
    // Inputs: process identities from one refresh snapshot, usually one process row or all children of one application row.
    // Processing: reopen each PID, verify its creation time on that handle, then terminate verified children/helpers first.
    // Return: the number of identities for which TerminateProcess returned success.
    int terminatedCount = 0;
    for (auto reverseIterator = processIdentityList.crbegin();
        reverseIterator != processIdentityList.crend();
        ++reverseIterator)
    {
        if (terminateProcessByIdentity(*reverseIterator))
        {
            ++terminatedCount;
        }
    }
    return terminatedCount;
}

void HudProcessListPanel::startRefreshing()
{
    if (refreshTimer_ != nullptr && !refreshTimer_->isActive())
    {
        refreshTimer_->start();
    }
    requestRefresh();
}

void HudProcessListPanel::stopRefreshing()
{
    if (refreshTimer_ != nullptr)
    {
        refreshTimer_->stop();
    }
}

void HudProcessListPanel::requestRefresh()
{
    if (refreshInProgress_ || refreshWatcher_ == nullptr)
    {
        return;
    }

    if ((::GetAsyncKeyState(VK_LCONTROL) & 0x8000) != 0)
    {
        return;
    }

    const QHash<QString, CounterSample> kPreviousSamples = previousSamples_;
    const QHash<QString, QString> kCachedImagePathByIdentity = imagePathByIdentity_;
    const int kLogicalCpuCount = logicalCpuCount_;

    refreshInProgress_ = true;
    refreshWatcher_->setFuture(QtConcurrent::run([kPreviousSamples, kCachedImagePathByIdentity, kLogicalCpuCount]() {
        return collectRefreshResult(kPreviousSamples, kCachedImagePathByIdentity, kLogicalCpuCount);
        }));
}

void HudProcessListPanel::captureExpandedState()
{
    // Inputs: current QTreeWidget state before the refresh rebuild clears all items.
    // Processing: recursively records expansion for every row that carries a stable expansion key.
    // Return behavior: no value is returned; m_expandedStateByKey is updated in place.
    if (treeWidget_ == nullptr)
    {
        return;
    }

    expandedStateByKey_.clear();
    for (int itemIndex = 0; itemIndex < treeWidget_->topLevelItemCount(); ++itemIndex)
    {
        captureExpandedStateForItem(treeWidget_->topLevelItem(itemIndex));
    }
}

void HudProcessListPanel::captureExpandedStateForItem(QTreeWidgetItem* itemPointer)
{
    // Inputs: one tree item from the pre-refresh tree.
    // Processing: saves this item's expanded state by key, then processes child rows.
    // Return behavior: no value is returned; invalid or unkeyed rows are skipped.
    if (itemPointer == nullptr)
    {
        return;
    }

    const QString kStateKey = itemPointer->data(kNameColumn, kExpansionKeyRole).toString();
    if (!kStateKey.isEmpty())
    {
        expandedStateByKey_.insert(kStateKey, itemPointer->isExpanded());
    }

    for (int childIndex = 0; childIndex < itemPointer->childCount(); ++childIndex)
    {
        captureExpandedStateForItem(itemPointer->child(childIndex));
    }
}

void HudProcessListPanel::restoreExpandedState(
    QTreeWidgetItem* itemPointer,
    const QString& stateKey,
    const bool defaultExpanded)
{
    // Inputs: a newly-created tree item, its stable expansion key, and the default state for first appearance.
    // Processing: stores the key on the row and applies a previously captured state when present.
    // Return behavior: no value is returned; null rows are ignored.
    if (itemPointer == nullptr)
    {
        return;
    }

    itemPointer->setData(kNameColumn, kExpansionKeyRole, stateKey);
    itemPointer->setExpanded(expandedStateByKey_.value(stateKey, defaultExpanded));
}

HudProcessListPanel::RefreshResult HudProcessListPanel::collectRefreshResult(
    const QHash<QString, CounterSample>& previousSamples,
    const QHash<QString, QString>& cachedImagePathByIdentity,
    const int logicalCpuCount)
{
    RefreshResult result;
    const qint64 kNowMs = QDateTime::currentMSecsSinceEpoch();
    const QSet<quint32> kVisibleWindowPidSet = collectVisibleWindowPidSet();
    const QString kWindowsDirectoryPath = normalizedWindowsDirectoryPath();
    const QHash<quint32, double> kGpuUsagePercentByPid = sampleProcessGpuUsagePercentByPid();
    const QHash<quint32, quint64> kNetworkBytesByPid = sampleTcpNetworkBytesByPid();

    HANDLE snapshotHandle = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshotHandle == INVALID_HANDLE_VALUE)
    {
        return result;
    }

    PROCESSENTRY32W processEntryNative{};
    processEntryNative.dwSize = sizeof(processEntryNative);
    if (::Process32FirstW(snapshotHandle, &processEntryNative) == FALSE)
    {
        ::CloseHandle(snapshotHandle);
        return result;
    }

    do
    {
        ProcessEntry entry{};
        entry.pid = static_cast<quint32>(processEntryNative.th32ProcessID);
        entry.parentPid = static_cast<quint32>(processEntryNative.th32ParentProcessID);
        entry.processName = QString::fromWCharArray(processEntryNative.szExeFile);

        CounterSample nextSample{};
        nextSample.sampleMs = kNowMs;
        nextSample.networkBytes = kNetworkBytesByPid.value(entry.pid, 0);

        HANDLE processHandle = ::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            FALSE,
            static_cast<DWORD>(entry.pid));
        if (processHandle == nullptr)
        {
            processHandle = ::OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                FALSE,
                static_cast<DWORD>(entry.pid));
        }

        QString processInstanceKey;
        if (processHandle != nullptr)
        {
            FILETIME creationTime{};
            FILETIME exitTime{};
            FILETIME kernelTime{};
            FILETIME userTime{};
            if (::GetProcessTimes(
                processHandle,
                &creationTime,
                &exitTime,
                &kernelTime,
                &userTime) != FALSE)
            {
                entry.creationTime100ns = fileTimeToUint64(creationTime);
                nextSample.cpuTime100ns =
                    fileTimeToUint64(kernelTime) + fileTimeToUint64(userTime);
            }

            processInstanceKey =
                buildProcessInstanceKey(entry.pid, entry.creationTime100ns);
            if (!processInstanceKey.isEmpty())
            {
                entry.imagePath = cachedImagePathByIdentity.value(processInstanceKey);
            }

            if (entry.imagePath.isEmpty())
            {
                std::array<wchar_t, 32768> imagePathBuffer{};
                DWORD imagePathLength = static_cast<DWORD>(imagePathBuffer.size());
                if (::QueryFullProcessImageNameW(
                    processHandle,
                    0,
                    imagePathBuffer.data(),
                    &imagePathLength) != FALSE
                    && imagePathLength > 0)
                {
                    entry.imagePath = QString::fromWCharArray(
                        imagePathBuffer.data(),
                        static_cast<int>(imagePathLength));
                }
            }

            PROCESS_MEMORY_COUNTERS_EX memoryInfo{};
            if (::GetProcessMemoryInfo(
                processHandle,
                reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&memoryInfo),
                sizeof(memoryInfo)) != FALSE)
            {
                entry.ramMB = static_cast<double>(memoryInfo.WorkingSetSize) / (1024.0 * 1024.0);
            }

            IO_COUNTERS ioCounters{};
            if (::GetProcessIoCounters(processHandle, &ioCounters) != FALSE)
            {
                nextSample.ioBytes =
                    static_cast<quint64>(ioCounters.ReadTransferCount + ioCounters.WriteTransferCount);
            }

            ::CloseHandle(processHandle);
        }

        entry.groupType = isWindowsSystemProcess(entry, kWindowsDirectoryPath)
            ? ProcessGroupType::kWindowsSystem
            : ProcessGroupType::kBackground;

        const auto kPreviousIterator = processInstanceKey.isEmpty()
            ? previousSamples.cend()
            : previousSamples.constFind(processInstanceKey);
        if (kPreviousIterator != previousSamples.cend())
        {
            const qint64 kElapsedMs = kNowMs - kPreviousIterator->sampleMs;
            if (kElapsedMs > 0)
            {
                const double kElapsedSeconds = static_cast<double>(kElapsedMs) / 1000.0;
                const quint64 kCpuDelta100ns =
                    nextSample.cpuTime100ns >= kPreviousIterator->cpuTime100ns
                    ? (nextSample.cpuTime100ns - kPreviousIterator->cpuTime100ns)
                    : 0;
                if (kElapsedSeconds > 0.0 && logicalCpuCount > 0)
                {
                    entry.cpuPercent = std::clamp(
                        (static_cast<double>(kCpuDelta100ns)
                            / (kElapsedSeconds * 10000000.0 * static_cast<double>(logicalCpuCount))) * 100.0,
                        0.0,
                        100.0);
                }

                const quint64 kIoDeltaBytes =
                    nextSample.ioBytes >= kPreviousIterator->ioBytes
                    ? (nextSample.ioBytes - kPreviousIterator->ioBytes)
                    : 0;
                entry.diskMBps =
                    (static_cast<double>(kIoDeltaBytes) / std::max(0.001, kElapsedSeconds)) / (1024.0 * 1024.0);

                const quint64 kNetworkDeltaBytes =
                    nextSample.networkBytes >= kPreviousIterator->networkBytes
                    ? (nextSample.networkBytes - kPreviousIterator->networkBytes)
                    : 0;
                entry.netKBps =
                    (static_cast<double>(kNetworkDeltaBytes) / std::max(0.001, kElapsedSeconds)) / 1024.0;
            }
        }

        entry.gpuPercent = kGpuUsagePercentByPid.value(entry.pid, 0.0);

        result.entries.push_back(entry);
        if (!processInstanceKey.isEmpty())
        {
            result.nextSamples.insert(processInstanceKey, nextSample);
        }
        result.totalCpuPercent += entry.cpuPercent;
        result.totalRamMB += entry.ramMB;
        result.totalDiskMBps += entry.diskMBps;
        result.totalGpuPercent += entry.gpuPercent;
        result.totalNetKBps += entry.netKBps;
        result.maxRamMB = std::max(result.maxRamMB, entry.ramMB);
        result.maxDiskMBps = std::max(result.maxDiskMBps, entry.diskMBps);
        result.maxNetKBps = std::max(result.maxNetKBps, entry.netKBps);
    } while (::Process32NextW(snapshotHandle, &processEntryNative) != FALSE);

    ::CloseHandle(snapshotHandle);
    classifyProcessGroups(&result.entries, kVisibleWindowPidSet);
    return result;
}

void HudProcessListPanel::applyRefreshResult(const RefreshResult& result)
{
    if (treeWidget_ == nullptr)
    {
        return;
    }

    if ((::GetAsyncKeyState(VK_LCONTROL) & 0x8000) != 0)
    {
        return;
    }

    captureExpandedState();
    previousSamples_ = result.nextSamples;
    updateHeaderSummary(result);
    imagePathByIdentity_.clear();
    itemByPid_.clear();

    treeWidget_->setUpdatesEnabled(false);
    treeWidget_->setSortingEnabled(false);
    treeWidget_->clear();

    const QVector<ProcessEntry> kEntries = result.entries;
    QVector<ProcessEntry> applicationEntries;
    QVector<ProcessEntry> backgroundEntries;
    QVector<ProcessEntry> systemEntries;
    applicationEntries.reserve(kEntries.size());
    backgroundEntries.reserve(kEntries.size());
    systemEntries.reserve(kEntries.size());

    for (const ProcessEntry& entry : kEntries)
    {
        const QString kProcessInstanceKey =
            buildProcessInstanceKey(entry.pid, entry.creationTime100ns);
        if (!kProcessInstanceKey.isEmpty() && !entry.imagePath.isEmpty())
        {
            imagePathByIdentity_.insert(kProcessInstanceKey, entry.imagePath);
        }
        switch (entry.groupType)
        {
        case ProcessGroupType::kApplication:
            applicationEntries.push_back(entry);
            break;
        case ProcessGroupType::kWindowsSystem:
            systemEntries.push_back(entry);
            break;
        case ProcessGroupType::kBackground:
        default:
            backgroundEntries.push_back(entry);
            break;
        }
    }

    const auto kProcessSorter = [](const ProcessEntry& left, const ProcessEntry& right)
    {
        // Inputs: two rows from the same visual group.
        // Processing: sort by process/application name first so the default tree is alphabetic.
        // Return: true when the left entry should appear before the right entry.
        if (left.processName.compare(right.processName, Qt::CaseInsensitive) != 0)
        {
            return left.processName.compare(right.processName, Qt::CaseInsensitive) < 0;
        }
        return left.pid < right.pid;
    };

    std::sort(applicationEntries.begin(), applicationEntries.end(), kProcessSorter);
    std::sort(backgroundEntries.begin(), backgroundEntries.end(), kProcessSorter);
    std::sort(systemEntries.begin(), systemEntries.end(), kProcessSorter);

    QHash<quint32, QVector<ProcessEntry>> applicationEntriesByRootPid;
    applicationEntriesByRootPid.reserve(applicationEntries.size());
    for (const ProcessEntry& entry : applicationEntries)
    {
        const quint32 kRootPidValue = entry.applicationRootPid != 0 ? entry.applicationRootPid : entry.pid;
        applicationEntriesByRootPid[kRootPidValue].push_back(entry);
    }

    QVector<QVector<ProcessEntry>> applicationBuckets;
    applicationBuckets.reserve(applicationEntriesByRootPid.size());
    for (auto bucketIterator = applicationEntriesByRootPid.cbegin();
        bucketIterator != applicationEntriesByRootPid.cend();
        ++bucketIterator)
    {
        applicationBuckets.push_back(bucketIterator.value());
    }
    std::sort(applicationBuckets.begin(), applicationBuckets.end(), [kProcessSorter](const QVector<ProcessEntry>& left, const QVector<ProcessEntry>& right)
        {
            const ProcessEntry kLeftAggregate = aggregateApplicationEntry(left);
            const ProcessEntry kRightAggregate = aggregateApplicationEntry(right);
            return kProcessSorter(kLeftAggregate, kRightAggregate);
        });

    QTreeWidgetItem* applicationGroupItem =
        createProcessGroupItem(ProcessGroupType::kApplication, applicationBuckets.size());
    if (applicationGroupItem != nullptr)
    {
        treeWidget_->addTopLevelItem(applicationGroupItem);
        restoreExpandedState(
            applicationGroupItem,
            expansionKeyForGroup(ProcessGroupType::kApplication),
            true);
        const bool kExpandApplicationSubtreeByDefault = applicationGroupItem->isExpanded();

        for (QVector<ProcessEntry>& applicationBucket : applicationBuckets)
        {
            std::sort(applicationBucket.begin(), applicationBucket.end(), kProcessSorter);
            const ProcessEntry kAggregateEntry = aggregateApplicationEntry(applicationBucket);
            QTreeWidgetItem* applicationRootItem = createApplicationRootItem(
                kAggregateEntry,
                applicationBucket,
                applicationBucket.size(),
                result.maxRamMB,
                result.maxDiskMBps,
                result.maxNetKBps);
            if (applicationRootItem == nullptr)
            {
                continue;
            }

            applicationGroupItem->addChild(applicationRootItem);
            restoreExpandedState(
                applicationRootItem,
                expansionKeyForApplication(kAggregateEntry.pid),
                kExpandApplicationSubtreeByDefault);
            applicationRootItem->setExpanded(kExpandApplicationSubtreeByDefault);

            QHash<quint32, QTreeWidgetItem*> childItemByPid;
            childItemByPid.reserve(applicationBucket.size());
            QHash<quint32, QVector<ProcessEntry>> childrenByParentPid;
            childrenByParentPid.reserve(applicationBucket.size());
            for (const ProcessEntry& childEntry : applicationBucket)
            {
                childrenByParentPid[childEntry.parentPid].push_back(childEntry);
            }

            const auto kAppendChildrenRecursive =
                [&](const auto& self, const quint32 parentPidValue, QTreeWidgetItem* parentTreeItem) -> void
            {
                QVector<ProcessEntry> childEntries = childrenByParentPid.value(parentPidValue);
                std::sort(childEntries.begin(), childEntries.end(), kProcessSorter);
                for (const ProcessEntry& childEntry : childEntries)
                {
                    if (childItemByPid.contains(childEntry.pid))
                    {
                        continue;
                    }

                    QTreeWidgetItem* childTreeItem = updateOrCreateRow(
                        childEntry,
                        parentTreeItem,
                        result.maxRamMB,
                        result.maxDiskMBps,
                        result.maxNetKBps);
                    if (childTreeItem == nullptr)
                    {
                        continue;
                    }

                    restoreExpandedState(
                        childTreeItem,
                        expansionKeyForProcess(childEntry.pid),
                        kExpandApplicationSubtreeByDefault);
                    childTreeItem->setExpanded(kExpandApplicationSubtreeByDefault);
                    childItemByPid.insert(childEntry.pid, childTreeItem);
                    self(self, childEntry.pid, childTreeItem);
                }
            };

            const auto kRootEntryIterator = std::find_if(
                applicationBucket.cbegin(),
                applicationBucket.cend(),
                [&kAggregateEntry](const ProcessEntry& childEntry)
                {
                    return childEntry.pid == kAggregateEntry.pid;
                });
            if (kRootEntryIterator != applicationBucket.cend())
            {
                QTreeWidgetItem* rootProcessItem = updateOrCreateRow(
                    *kRootEntryIterator,
                    applicationRootItem,
                    result.maxRamMB,
                    result.maxDiskMBps,
                    result.maxNetKBps);
                if (rootProcessItem != nullptr)
                {
                    restoreExpandedState(
                        rootProcessItem,
                        expansionKeyForProcess(kRootEntryIterator->pid),
                        kExpandApplicationSubtreeByDefault);
                    rootProcessItem->setExpanded(kExpandApplicationSubtreeByDefault);
                    childItemByPid.insert(kRootEntryIterator->pid, rootProcessItem);
                    kAppendChildrenRecursive(kAppendChildrenRecursive, kRootEntryIterator->pid, rootProcessItem);
                }
            }

            for (const ProcessEntry& childEntry : applicationBucket)
            {
                if (childItemByPid.contains(childEntry.pid))
                {
                    continue;
                }

                QTreeWidgetItem* childTreeItem = updateOrCreateRow(
                    childEntry,
                    applicationRootItem,
                    result.maxRamMB,
                    result.maxDiskMBps,
                    result.maxNetKBps);
                if (childTreeItem == nullptr)
                {
                    continue;
                }

                restoreExpandedState(
                    childTreeItem,
                    expansionKeyForProcess(childEntry.pid),
                    kExpandApplicationSubtreeByDefault);
                childTreeItem->setExpanded(kExpandApplicationSubtreeByDefault);
                childItemByPid.insert(childEntry.pid, childTreeItem);
                kAppendChildrenRecursive(kAppendChildrenRecursive, childEntry.pid, childTreeItem);
            }
        }
    }

    const struct GroupBucket
    {
        ProcessGroupType type;
        const QVector<ProcessEntry>* entries;
    } kGroupBuckets[] = {
        { ProcessGroupType::kBackground, &backgroundEntries },
        { ProcessGroupType::kWindowsSystem, &systemEntries }
    };

    for (const GroupBucket& bucket : kGroupBuckets)
    {
        QTreeWidgetItem* groupItem = createProcessGroupItem(bucket.type, bucket.entries->size());
        if (groupItem == nullptr)
        {
            continue;
        }
        treeWidget_->addTopLevelItem(groupItem);
        restoreExpandedState(
            groupItem,
            expansionKeyForGroup(bucket.type),
            true);

        for (const ProcessEntry& entry : *bucket.entries)
        {
            updateOrCreateRow(entry, groupItem, result.maxRamMB, result.maxDiskMBps, result.maxNetKBps);
        }
    }

    treeWidget_->setSortingEnabled(false);
    treeWidget_->setUpdatesEnabled(true);
    treeWidget_->viewport()->update();
}

void HudProcessListPanel::updateHeaderSummary(const RefreshResult& result)
{
    if (treeWidget_ == nullptr || treeWidget_->headerItem() == nullptr)
    {
        return;
    }

    QTreeWidgetItem* headerItem = treeWidget_->headerItem();
    headerItem->setText(kNameColumn, processHeaders().at(kNameColumn));
    headerItem->setText(kPidColumn, processHeaders().at(kPidColumn));
    headerItem->setText(kCpuColumn, QStringLiteral("CPU %1").arg(formatPercent(result.totalCpuPercent, 2)));
    headerItem->setText(kRamColumn, QStringLiteral("RAM %1 MB").arg(QString::number(result.totalRamMB, 'f', 1)));
    headerItem->setText(kDiskColumn, QStringLiteral("DISK %1 MB/s").arg(QString::number(result.totalDiskMBps, 'f', 2)));
    headerItem->setText(kGpuColumn, QStringLiteral("GPU %1").arg(formatPercent(result.totalGpuPercent, 1)));
    headerItem->setText(kNetColumn, QStringLiteral("Net %1 KB/s").arg(QString::number(result.totalNetKBps, 'f', 2)));
}

void HudProcessListPanel::classifyProcessGroups(
    QVector<ProcessEntry>* entries,
    const QSet<quint32>& visibleWindowPidSet)
{
    // Inputs: collected process entries and PIDs that own visible top-level windows.
    // Processing: build a PID -> parent PID index, then mark visible-window owners and their descendants as apps.
    // Return behavior: no value is returned; each ProcessEntry::groupType is updated in place.
    if (entries == nullptr)
    {
        return;
    }

    QHash<quint32, quint32> parentPidByPid;
    parentPidByPid.reserve(entries->size());
    for (const ProcessEntry& entry : *entries)
    {
        parentPidByPid.insert(entry.pid, entry.parentPid);
    }

    for (ProcessEntry& entry : *entries)
    {
        const quint32 kApplicationRootPidValue =
            findApplicationRootPid(entry.pid, parentPidByPid, visibleWindowPidSet);
        if (kApplicationRootPidValue != 0)
        {
            entry.groupType = ProcessGroupType::kApplication;
            entry.applicationRootPid = kApplicationRootPidValue;
        }
    }
}

quint32 HudProcessListPanel::findApplicationRootPid(
    const quint32 pidValue,
    const QHash<quint32, quint32>& parentPidByPid,
    const QSet<quint32>& visibleWindowPidSet)
{
    // Inputs: a PID, parent map collected from ToolHelp, and visible-window application root PIDs.
    // Processing: walk the parent chain defensively and stop on cycles, missing parents, or PID zero.
    // Return: the visible-window root PID when the PID belongs to an application tree; otherwise 0.
    QSet<quint32> visitedPidSet;
    quint32 currentPidValue = pidValue;

    while (currentPidValue != 0 && !visitedPidSet.contains(currentPidValue))
    {
        if (visibleWindowPidSet.contains(currentPidValue))
        {
            return currentPidValue;
        }

        visitedPidSet.insert(currentPidValue);
        const auto kParentIterator = parentPidByPid.constFind(currentPidValue);
        if (kParentIterator == parentPidByPid.cend())
        {
            break;
        }

        const quint32 kParentPidValue = kParentIterator.value();
        if (kParentPidValue == currentPidValue)
        {
            break;
        }
        currentPidValue = kParentPidValue;
    }

    return 0;
}

bool HudProcessListPanel::isWindowsSystemProcess(
    const ProcessEntry& entry,
    const QString& windowsDirectoryPath)
{
    // Inputs: one process entry and the normalized Windows directory path.
    // Processing: classify kernel/session-manager/core-service names and Windows-directory images as system.
    // Return: true when the process should appear under the Windows system group before app overrides.
    if (entry.pid == 0 || entry.pid == 4)
    {
        return true;
    }

    const QString kProcessName = entry.processName.trimmed().toLower();
    static const QSet<QString> kSystemProcessNames = {
        QStringLiteral("system"),
        QStringLiteral("registry"),
        QStringLiteral("smss.exe"),
        QStringLiteral("csrss.exe"),
        QStringLiteral("wininit.exe"),
        QStringLiteral("winlogon.exe"),
        QStringLiteral("services.exe"),
        QStringLiteral("lsass.exe"),
        QStringLiteral("lsaiso.exe"),
        QStringLiteral("fontdrvhost.exe"),
        QStringLiteral("dwm.exe"),
        QStringLiteral("wudfhost.exe"),
        QStringLiteral("audiodg.exe"),
        QStringLiteral("memory compression")
    };
    if (kSystemProcessNames.contains(kProcessName))
    {
        return true;
    }

    if (entry.imagePath.isEmpty() || windowsDirectoryPath.isEmpty())
    {
        return false;
    }

    const QString kNormalizedImagePath = QDir::fromNativeSeparators(entry.imagePath).toLower();
    return kNormalizedImagePath.startsWith(windowsDirectoryPath + QStringLiteral("/"));
}

HudProcessListPanel::ProcessEntry HudProcessListPanel::aggregateApplicationEntry(
    const QVector<ProcessEntry>& applicationEntries)
{
    // Inputs: all ProcessEntry objects belonging to one visible application root.
    // Processing: choose the root process as the display identity and sum metrics across all child processes.
    // Return: an aggregate ProcessEntry used only for the application parent row.
    ProcessEntry aggregateEntry{};
    if (applicationEntries.isEmpty())
    {
        return aggregateEntry;
    }

    aggregateEntry = applicationEntries.first();
    const quint32 kRootPidValue =
        aggregateEntry.applicationRootPid != 0 ? aggregateEntry.applicationRootPid : aggregateEntry.pid;
    for (const ProcessEntry& entry : applicationEntries)
    {
        if (entry.pid == kRootPidValue)
        {
            aggregateEntry = entry;
            break;
        }
    }

    aggregateEntry.pid = kRootPidValue;
    aggregateEntry.parentPid = 0;
    aggregateEntry.applicationRootPid = kRootPidValue;
    aggregateEntry.groupType = ProcessGroupType::kApplication;
    aggregateEntry.cpuPercent = 0.0;
    aggregateEntry.ramMB = 0.0;
    aggregateEntry.diskMBps = 0.0;
    aggregateEntry.gpuPercent = 0.0;
    aggregateEntry.netKBps = 0.0;
    for (const ProcessEntry& entry : applicationEntries)
    {
        aggregateEntry.cpuPercent += entry.cpuPercent;
        aggregateEntry.ramMB += entry.ramMB;
        aggregateEntry.diskMBps += entry.diskMBps;
        aggregateEntry.gpuPercent += entry.gpuPercent;
        aggregateEntry.netKBps += entry.netKBps;
    }

    return aggregateEntry;
}

QString HudProcessListPanel::expansionKeyForGroup(const ProcessGroupType groupType)
{
    // Inputs: one top-level process group type.
    // Processing: map the enum to a stable string that survives full refresh rebuilds.
    // Return: expansion-state key for the group row.
    switch (groupType)
    {
    case ProcessGroupType::kApplication:
        return QStringLiteral("group:application");
    case ProcessGroupType::kWindowsSystem:
        return QStringLiteral("group:system");
    case ProcessGroupType::kBackground:
    default:
        return QStringLiteral("group:background");
    }
}

QString HudProcessListPanel::expansionKeyForApplication(const quint32 rootPidValue)
{
    // Inputs: an application root PID.
    // Processing: format a stable key for one Task-Manager-style application row.
    // Return: expansion-state key for that application aggregate node.
    return QStringLiteral("app:%1").arg(rootPidValue);
}

QString HudProcessListPanel::expansionKeyForProcess(const quint32 pidValue)
{
    // Inputs: a concrete process PID.
    // Processing: format a stable key for process rows that may own child rows.
    // Return: expansion-state key for that process node.
    return QStringLiteral("pid:%1").arg(pidValue);
}

QString HudProcessListPanel::processGroupTitle(const ProcessGroupType groupType, const int entryCount)
{
    // Inputs: process group type and number of processes currently assigned to that group.
    // Processing: format the localized group caption used by the left process tree.
    // Return: display text for the collapsible group row.
    switch (groupType)
    {
    case ProcessGroupType::kApplication:
        return QStringLiteral("应用 (%1)").arg(entryCount);
    case ProcessGroupType::kWindowsSystem:
        return QStringLiteral("系统 (%1)").arg(entryCount);
    case ProcessGroupType::kBackground:
    default:
        return QStringLiteral("后台进程 (%1)").arg(entryCount);
    }
}

int HudProcessListPanel::processGroupOrder(const ProcessGroupType groupType)
{
    // Inputs: a group type enum.
    // Processing: mirror Task Manager ordering so apps stay above background and system rows.
    // Return: a stable numeric order for possible future sorting or diagnostics.
    switch (groupType)
    {
    case ProcessGroupType::kApplication:
        return 0;
    case ProcessGroupType::kBackground:
        return 1;
    case ProcessGroupType::kWindowsSystem:
    default:
        return 2;
    }
}

QTreeWidgetItem* HudProcessListPanel::createProcessGroupItem(
    const ProcessGroupType groupType,
    const int entryCount)
{
    // Inputs: process group type and group size.
    // Processing: create a non-process parent row with a bold blue caption and no PID role.
    // Return: a heap-allocated tree item owned by QTreeWidget after insertion, or nullptr only on allocation failure.
    auto* groupItem = new QTreeWidgetItem();
    groupItem->setText(kNameColumn, processGroupTitle(groupType, entryCount));
    groupItem->setData(kNameColumn, Qt::UserRole + 8, processGroupOrder(groupType));
    groupItem->setFirstColumnSpanned(true);
    groupItem->setFlags((groupItem->flags() | Qt::ItemIsEnabled) & ~Qt::ItemIsSelectable);

    QFont groupFont = groupItem->font(kNameColumn);
    groupFont.setBold(true);
    groupItem->setFont(kNameColumn, groupFont);
    groupItem->setForeground(kNameColumn, QColor(96, 165, 250));
    groupItem->setBackground(kNameColumn, QColor(255, 255, 255, 12));
    return groupItem;
}

QTreeWidgetItem* HudProcessListPanel::createApplicationRootItem(
    const ProcessEntry& aggregateEntry,
    const QVector<ProcessEntry>& applicationEntries,
    const int childProcessCount,
    const double maxRamMB,
    const double maxDiskMBps,
    const double maxNetKBps)
{
    // Inputs: aggregate metrics for one application tree, child count, and metric normalization maxima.
    // Processing: create a virtual parent row that mirrors Task Manager's "App name (N)" row.
    // Return: a heap-allocated tree item that the caller inserts under the Applications group.
    auto* itemPointer = new QTreeWidgetItem();
    itemPointer->setTextAlignment(kPidColumn, Qt::AlignRight | Qt::AlignVCenter);
    itemPointer->setTextAlignment(kCpuColumn, Qt::AlignRight | Qt::AlignVCenter);
    itemPointer->setTextAlignment(kRamColumn, Qt::AlignRight | Qt::AlignVCenter);
    itemPointer->setTextAlignment(kDiskColumn, Qt::AlignRight | Qt::AlignVCenter);
    itemPointer->setTextAlignment(kGpuColumn, Qt::AlignRight | Qt::AlignVCenter);
    itemPointer->setTextAlignment(kNetColumn, Qt::AlignRight | Qt::AlignVCenter);

    itemPointer->setText(
        kNameColumn,
        childProcessCount > 1
        ? QStringLiteral("%1 (%2)").arg(aggregateEntry.processName).arg(childProcessCount)
        : aggregateEntry.processName);
    itemPointer->setText(kPidColumn, QString::number(aggregateEntry.pid));
    itemPointer->setIcon(kNameColumn, resolveProcessIcon(aggregateEntry));
    itemPointer->setText(kCpuColumn, formatPercent(aggregateEntry.cpuPercent, 2));
    itemPointer->setText(kRamColumn, formatRamMB(aggregateEntry.ramMB));
    itemPointer->setText(kDiskColumn, formatDiskMBps(aggregateEntry.diskMBps));
    itemPointer->setText(kGpuColumn, formatPercent(aggregateEntry.gpuPercent, 1));
    itemPointer->setText(kNetColumn, formatNetKBps(aggregateEntry.netKBps));
    QVariantList terminateIdentityVariantList;
    terminateIdentityVariantList.reserve(applicationEntries.size());
    for (const ProcessEntry& entry : applicationEntries)
    {
        if (entry.pid != 0 && entry.creationTime100ns != 0)
        {
            QVariantList identityValues;
            identityValues.push_back(entry.pid);
            identityValues.push_back(entry.creationTime100ns);
            terminateIdentityVariantList.push_back(identityValues);
        }
    }
    itemPointer->setData(
        kNameColumn,
        kTerminateProcessIdentityListRole,
        terminateIdentityVariantList);
    itemPointer->setData(kCpuColumn, kUsageRatioRole, usageRatioForEntry(aggregateEntry, kCpuColumn, maxRamMB, maxDiskMBps, maxNetKBps));
    itemPointer->setData(kRamColumn, kUsageRatioRole, usageRatioForEntry(aggregateEntry, kRamColumn, maxRamMB, maxDiskMBps, maxNetKBps));
    itemPointer->setData(kDiskColumn, kUsageRatioRole, usageRatioForEntry(aggregateEntry, kDiskColumn, maxRamMB, maxDiskMBps, maxNetKBps));
    itemPointer->setData(kGpuColumn, kUsageRatioRole, usageRatioForEntry(aggregateEntry, kGpuColumn, maxRamMB, maxDiskMBps, maxNetKBps));
    itemPointer->setData(kNetColumn, kUsageRatioRole, usageRatioForEntry(aggregateEntry, kNetColumn, maxRamMB, maxDiskMBps, maxNetKBps));

    QFont appFont = itemPointer->font(kNameColumn);
    appFont.setBold(true);
    itemPointer->setFont(kNameColumn, appFont);
    return itemPointer;
}

QTreeWidgetItem* HudProcessListPanel::updateOrCreateRow(
    const ProcessEntry& entry,
    QTreeWidgetItem* parentItem,
    const double maxRamMB,
    const double maxDiskMBps,
    const double maxNetKBps)
{
    QTreeWidgetItem* itemPointer = itemByPid_.value(entry.pid, nullptr);
    if (itemPointer == nullptr)
    {
        itemPointer = new QTreeWidgetItem();
        itemPointer->setTextAlignment(kPidColumn, Qt::AlignRight | Qt::AlignVCenter);
        itemPointer->setTextAlignment(kCpuColumn, Qt::AlignRight | Qt::AlignVCenter);
        itemPointer->setTextAlignment(kRamColumn, Qt::AlignRight | Qt::AlignVCenter);
        itemPointer->setTextAlignment(kDiskColumn, Qt::AlignRight | Qt::AlignVCenter);
        itemPointer->setTextAlignment(kGpuColumn, Qt::AlignRight | Qt::AlignVCenter);
        itemPointer->setTextAlignment(kNetColumn, Qt::AlignRight | Qt::AlignVCenter);
        if (parentItem != nullptr)
        {
            parentItem->addChild(itemPointer);
        }
        else
        {
            treeWidget_->addTopLevelItem(itemPointer);
        }
        itemByPid_.insert(entry.pid, itemPointer);
    }

    itemPointer->setText(kNameColumn, entry.processName);
    itemPointer->setText(kPidColumn, QString::number(entry.pid));
    itemPointer->setIcon(kNameColumn, resolveProcessIcon(entry));
    itemPointer->setText(kCpuColumn, formatPercent(entry.cpuPercent, 2));
    itemPointer->setText(kRamColumn, formatRamMB(entry.ramMB));
    itemPointer->setText(kDiskColumn, formatDiskMBps(entry.diskMBps));
    itemPointer->setText(kGpuColumn, formatPercent(entry.gpuPercent, 1));
    itemPointer->setText(kNetColumn, formatNetKBps(entry.netKBps));
    QVariantList terminateIdentityVariantList;
    if (entry.pid != 0 && entry.creationTime100ns != 0)
    {
        QVariantList identityValues;
        identityValues.push_back(entry.pid);
        identityValues.push_back(entry.creationTime100ns);
        terminateIdentityVariantList.push_back(identityValues);
    }
    itemPointer->setData(
        kNameColumn,
        kTerminateProcessIdentityListRole,
        terminateIdentityVariantList);
    itemPointer->setData(kCpuColumn, kUsageRatioRole, usageRatioForEntry(entry, kCpuColumn, maxRamMB, maxDiskMBps, maxNetKBps));
    itemPointer->setData(kRamColumn, kUsageRatioRole, usageRatioForEntry(entry, kRamColumn, maxRamMB, maxDiskMBps, maxNetKBps));
    itemPointer->setData(kDiskColumn, kUsageRatioRole, usageRatioForEntry(entry, kDiskColumn, maxRamMB, maxDiskMBps, maxNetKBps));
    itemPointer->setData(kGpuColumn, kUsageRatioRole, usageRatioForEntry(entry, kGpuColumn, maxRamMB, maxDiskMBps, maxNetKBps));
    itemPointer->setData(kNetColumn, kUsageRatioRole, usageRatioForEntry(entry, kNetColumn, maxRamMB, maxDiskMBps, maxNetKBps));
    return itemPointer;
}

QString HudProcessListPanel::buildProcessInstanceKey(
    const quint32 pidValue,
    const quint64 creationTime100ns)
{
    if (pidValue == 0 || creationTime100ns == 0)
    {
        return {};
    }

    return QStringLiteral("%1|%2").arg(pidValue).arg(creationTime100ns);
}

QIcon HudProcessListPanel::resolveProcessIcon(const ProcessEntry& entry)
{
    const QString kProcessInstanceKey =
        buildProcessInstanceKey(entry.pid, entry.creationTime100ns);
    if (!kProcessInstanceKey.isEmpty())
    {
        const auto kIdentityCacheIterator = iconCacheByIdentity_.constFind(kProcessInstanceKey);
        if (kIdentityCacheIterator != iconCacheByIdentity_.cend())
        {
            return kIdentityCacheIterator.value();
        }
    }

    if (!entry.imagePath.isEmpty())
    {
        const auto kPathCacheIterator = iconCacheByPath_.constFind(entry.imagePath);
        if (kPathCacheIterator != iconCacheByPath_.cend())
        {
            if (!kProcessInstanceKey.isEmpty())
            {
                iconCacheByIdentity_.insert(kProcessInstanceKey, kPathCacheIterator.value());
            }
            return kPathCacheIterator.value();
        }

        if (fileIconProvider_ != nullptr)
        {
            const QFileInfo kFileInfo(entry.imagePath);
            if (kFileInfo.exists())
            {
                const QIcon kResolvedIcon = fileIconProvider_->icon(kFileInfo);
                if (!kResolvedIcon.isNull())
                {
                    iconCacheByPath_.insert(entry.imagePath, kResolvedIcon);
                    if (!kProcessInstanceKey.isEmpty())
                    {
                        iconCacheByIdentity_.insert(kProcessInstanceKey, kResolvedIcon);
                    }
                    return kResolvedIcon;
                }
            }
        }
    }

    const QIcon kFallbackIcon = QApplication::style()->standardIcon(QStyle::SP_FileIcon);
    if (!kProcessInstanceKey.isEmpty())
    {
        iconCacheByIdentity_.insert(kProcessInstanceKey, kFallbackIcon);
    }
    return kFallbackIcon;
}

double HudProcessListPanel::usageRatioForEntry(
    const ProcessEntry& entry,
    const int columnIndex,
    const double maxRamMB,
    const double maxDiskMBps,
    const double maxNetKBps)
{
    switch (columnIndex)
    {
    case kCpuColumn:
        return std::clamp(entry.cpuPercent / 100.0, 0.0, 1.0);
    case kRamColumn:
        return maxRamMB > 0.0 ? std::clamp(entry.ramMB / maxRamMB, 0.0, 1.0) : 0.0;
    case kDiskColumn:
        return maxDiskMBps > 0.0 ? std::clamp(entry.diskMBps / maxDiskMBps, 0.0, 1.0) : 0.0;
    case kGpuColumn:
        return std::clamp(entry.gpuPercent / 100.0, 0.0, 1.0);
    case kNetColumn:
        return maxNetKBps > 0.0 ? std::clamp(entry.netKBps / maxNetKBps, 0.0, 1.0) : 0.0;
    default:
        return 0.0;
    }
}

QString HudProcessListPanel::formatPercent(const double value, const int decimals)
{
    return QStringLiteral("%1%").arg(QString::number(value, 'f', decimals));
}

QString HudProcessListPanel::formatRamMB(const double value)
{
    return QStringLiteral("%1 MB").arg(QString::number(value, 'f', 1));
}

QString HudProcessListPanel::formatDiskMBps(const double value)
{
    return QStringLiteral("%1 MB/s").arg(QString::number(value, 'f', 2));
}

QString HudProcessListPanel::formatNetKBps(const double value)
{
    return QStringLiteral("%1 KB/s").arg(QString::number(value, 'f', 2));
}
