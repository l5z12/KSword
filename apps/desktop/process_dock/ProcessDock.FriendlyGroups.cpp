#include "ProcessDock.Support.h"
#include "ProcessActivityChartWidget.h"
#include "ProcessActivityTimelineSlider.h"

using namespace ksword::ui::process_dock;

QSet<std::uint32_t> ProcessDock::collectVisibleWindowPidSet()
{
    // Inputs: current desktop top-level window list.
    // Processing: EnumWindows collects visible, non-tool, non-owned windows and maps them to owner PIDs.
    // Return: PID set used as application roots for friendly process grouping.
    QSet<std::uint32_t> visibleWindowPidSet;
    ::EnumWindows(
        [](HWND windowHandle, LPARAM parameter) -> BOOL
        {
            auto* pidSet = reinterpret_cast<QSet<std::uint32_t>*>(parameter);
            if (pidSet == nullptr ||
                windowHandle == nullptr ||
                ::IsWindowVisible(windowHandle) == FALSE)
            {
                return TRUE;
            }

            if (::GetWindow(windowHandle, GW_OWNER) != nullptr)
            {
                return TRUE;
            }

            const LONG_PTR kExtendedStyle = ::GetWindowLongPtrW(windowHandle, GWL_EXSTYLE);
            if ((kExtendedStyle & WS_EX_TOOLWINDOW) != 0)
            {
                return TRUE;
            }

            wchar_t titleBuffer[2]{};
            if (::GetWindowTextW(windowHandle, titleBuffer, 2) <= 0)
            {
                return TRUE;
            }

            DWORD pidValue = 0;
            ::GetWindowThreadProcessId(windowHandle, &pidValue);
            if (pidValue != 0U)
            {
                pidSet->insert(static_cast<std::uint32_t>(pidValue));
            }
            return TRUE;
        },
        reinterpret_cast<LPARAM>(&visibleWindowPidSet));
    return visibleWindowPidSet;
}

std::uint32_t ProcessDock::findFriendlyApplicationRootPid(
    const std::uint32_t pid,
    const std::unordered_map<std::uint32_t, std::uint32_t>& parentPidByPid,
    const QSet<std::uint32_t>& visibleWindowPidSet)
{
    // Inputs: one PID, the PID->parent index, and visible-window root candidates.
    // Processing: walk ancestors defensively and stop on missing parents, cycles, or PID zero.
    // Return: the first visible-window PID in the ancestor chain, or 0 when the process is not an app tree.
    std::unordered_set<std::uint32_t> visitedPidSet;
    std::uint32_t currentPid = pid;
    while (currentPid != 0U && visitedPidSet.insert(currentPid).second)
    {
        if (visibleWindowPidSet.contains(currentPid))
        {
            return currentPid;
        }

        const auto kParentIt = parentPidByPid.find(currentPid);
        if (kParentIt == parentPidByPid.end() || kParentIt->second == currentPid)
        {
            break;
        }
        currentPid = kParentIt->second;
    }
    return 0U;
}

bool ProcessDock::isFriendlyWindowsSystemProcess(
    const ks::process::ProcessRecord& processRecord,
    const QString& normalizedWindowsDirectoryPath)
{
    // Inputs: a process snapshot and normalized Windows directory path.
    // Processing: classify kernel/session-manager/core Windows names or Windows-directory images as system.
    // Return: true when the row belongs under the friendly "System" group.
    if (processRecord.pid == 0U || processRecord.pid == 4U)
    {
        return true;
    }

    const QString kProcessName = QString::fromStdString(processRecord.processName).trimmed().toLower();
    static const QSet<QString> kSystemProcessNames = {
        QStringLiteral("system"),
        QStringLiteral("system idle process"),
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

    const QString kImagePath = QString::fromStdString(
        !processRecord.imagePath.empty() ? processRecord.imagePath : processRecord.r0ImagePath).trimmed();
    if (kImagePath.isEmpty() || normalizedWindowsDirectoryPath.isEmpty())
    {
        return false;
    }

    const QString kNormalizedImagePath = QDir::fromNativeSeparators(kImagePath).toLower();
    return kNormalizedImagePath.startsWith(normalizedWindowsDirectoryPath + QStringLiteral("/"));
}

QString ProcessDock::friendlyGroupTitle(const FriendlyProcessGroupType groupType, const int entryCount)
{
    // Inputs: friendly group type and current member count.
    // Processing: format localized group names shared by headers and synthetic records.
    // Return: user-visible title text.
    switch (groupType)
    {
    case FriendlyProcessGroupType::kApplication:
        return processContextText("process.group.application", QStringLiteral("应用 (%1)")).arg(entryCount);
    case FriendlyProcessGroupType::kWindowsSystem:
        return processContextText("process.group.system", QStringLiteral("系统 (%1)")).arg(entryCount);
    case FriendlyProcessGroupType::kBackground:
    default:
        return processContextText("process.group.background", QStringLiteral("后台进程 (%1)")).arg(entryCount);
    }
}

QString ProcessDock::friendlyGroupTypeName(const FriendlyProcessGroupType groupType)
{
    // Input: Friendly view group type.
    // Processing: Return the short name without member count for per-row display in the 'Type' column.
    // Returns: Text for the 'Type' column in Task Manager, matching application / background process / Windows process categories.
    switch (groupType)
    {
    case FriendlyProcessGroupType::kApplication:
        return processContextText("process.type.application", QStringLiteral("应用"));
    case FriendlyProcessGroupType::kWindowsSystem:
        return processContextText("process.type.windows", QStringLiteral("Windows 进程"));
    case FriendlyProcessGroupType::kBackground:
    default:
        return processContextText("process.type.background", QStringLiteral("后台进程"));
    }
}

QString ProcessDock::friendlyExpansionKeyForGroup(const FriendlyProcessGroupType groupType)
{
    // Inputs: friendly group type.
    // Processing: convert enum to stable state key.
    // Return: key used by m_friendlyExpandedStateByKey.
    switch (groupType)
    {
    case FriendlyProcessGroupType::kApplication:
        return QStringLiteral("friendly:group:application");
    case FriendlyProcessGroupType::kWindowsSystem:
        return QStringLiteral("friendly:group:system");
    case FriendlyProcessGroupType::kBackground:
    default:
        return QStringLiteral("friendly:group:background");
    }
}

QString ProcessDock::friendlyExpansionKeyForApplication(const std::uint32_t rootPid)
{
    // Inputs: an application root PID.
    // Processing: format a stable key that survives refreshes while PID remains alive.
    // Return: key used to persist aggregate expansion state.
    return QStringLiteral("friendly:app:%1").arg(static_cast<qulonglong>(rootPid));
}

ks::process::ProcessRecord ProcessDock::aggregateFriendlyApplicationRecord(
    const std::vector<const CacheEntry*>& applicationEntries,
    const std::uint32_t rootPid)
{
    // Inputs: all cache entries assigned to one application root and that root PID.
    // Processing: choose the root process as display identity and sum per-process metrics.
    // Return: synthetic ProcessRecord for the non-actionable application aggregate row.
    ks::process::ProcessRecord aggregateRecord{};
    if (applicationEntries.empty())
    {
        aggregateRecord.pid = rootPid;
        aggregateRecord.processName = "Application";
        return aggregateRecord;
    }

    const CacheEntry* identityEntry = applicationEntries.front();
    for (const CacheEntry* entry : applicationEntries)
    {
        if (entry != nullptr && entry->record.pid == rootPid)
        {
            identityEntry = entry;
            break;
        }
    }
    if (identityEntry != nullptr)
    {
        aggregateRecord = identityEntry->record;
    }

    aggregateRecord.pid = rootPid;
    aggregateRecord.parentPid = 0U;
    aggregateRecord.threadCount = 0U;
    aggregateRecord.handleCount = 0U;
    aggregateRecord.cpuPercent = 0.0;
    aggregateRecord.cpuCorePercent = 0.0;
    aggregateRecord.ramMB = 0.0;
    aggregateRecord.workingSetMB = 0.0;
    aggregateRecord.diskMBps = 0.0;
    aggregateRecord.gpuPercent = 0.0;
    aggregateRecord.netKBps = 0.0;
    aggregateRecord.netRxKBps = 0.0;
    aggregateRecord.netTxKBps = 0.0;

    // Task Manager aligned columns also require the aggregate row to show the total for the entire application; otherwise, in collapsed
    // state, these columns would only display the root process's numbers, inconsistent with the semantics of CPU/memory columns.
    aggregateRecord.rawWorkingSetBytes = 0;
    aggregateRecord.rawCpuTime100ns = 0;
    aggregateRecord.cycleTime = 0;
    aggregateRecord.peakWorkingSetBytes = 0;
    aggregateRecord.privateWorkingSetBytes = 0;
    aggregateRecord.activePrivateWorkingSetBytes = 0;
    aggregateRecord.sharedWorkingSetBytes = 0;
    aggregateRecord.commitSizeBytes = 0;
    aggregateRecord.pagedPoolBytes = 0;
    aggregateRecord.nonPagedPoolBytes = 0;
    aggregateRecord.pageFaultCount = 0;
    aggregateRecord.workingSetDeltaBytes = 0;
    aggregateRecord.pageFaultDeltaCount = 0;
    aggregateRecord.ioReadOperationCount = 0;
    aggregateRecord.ioWriteOperationCount = 0;
    aggregateRecord.ioOtherOperationCount = 0;
    aggregateRecord.ioReadTransferBytes = 0;
    aggregateRecord.ioWriteTransferBytes = 0;
    aggregateRecord.ioOtherTransferBytes = 0;
    aggregateRecord.gdiObjectCount = 0;
    aggregateRecord.userObjectCount = 0;
    aggregateRecord.gpuDedicatedMemoryBytes = 0;
    aggregateRecord.gpuSharedMemoryBytes = 0;
    aggregateRecord.suspendedThreadCount = 0;

    // Clear availability flags first, then perform an "OR" merge on members:
    // If any member process has the group field, the aggregate row displays the sum instead of a placeholder.
    aggregateRecord.memoryDetailKnown = false;
    aggregateRecord.privateWorkingSetKnown = false;
    aggregateRecord.ioDetailKnown = false;
    aggregateRecord.guiResourceKnown = false;
    aggregateRecord.gpuMemoryKnown = false;
    aggregateRecord.cycleTimeKnown = false;

    // The application is considered 'suspended' only when all member threads are in a suspended state.
    std::uint32_t aggregateStateKnownCount = 0;
    std::uint32_t aggregateSuspendedCount = 0;
    std::uint32_t aggregateMemberCount = 0;

    for (const CacheEntry* entry : applicationEntries)
    {
        if (entry == nullptr)
        {
            continue;
        }
        const ks::process::ProcessRecord& memberRecord = entry->record;
        ++aggregateMemberCount;

        aggregateRecord.threadCount += memberRecord.threadCount;
        aggregateRecord.handleCount += memberRecord.handleCount;
        aggregateRecord.cpuPercent += memberRecord.cpuPercent;
        aggregateRecord.cpuCorePercent += memberRecord.cpuCorePercent;
        aggregateRecord.ramMB += memberRecord.ramMB;
        aggregateRecord.workingSetMB += memberRecord.workingSetMB;
        aggregateRecord.diskMBps += memberRecord.diskMBps;
        aggregateRecord.gpuPercent += memberRecord.gpuPercent;
        aggregateRecord.netKBps += memberRecord.netKBps;
        aggregateRecord.netRxKBps += memberRecord.netRxKBps;
        aggregateRecord.netTxKBps += memberRecord.netTxKBps;

        aggregateRecord.rawWorkingSetBytes += memberRecord.rawWorkingSetBytes;
        aggregateRecord.rawCpuTime100ns += memberRecord.rawCpuTime100ns;
        aggregateRecord.cycleTime += memberRecord.cycleTime;
        aggregateRecord.peakWorkingSetBytes += memberRecord.peakWorkingSetBytes;
        aggregateRecord.privateWorkingSetBytes += memberRecord.privateWorkingSetBytes;
        aggregateRecord.activePrivateWorkingSetBytes += memberRecord.activePrivateWorkingSetBytes;
        aggregateRecord.sharedWorkingSetBytes += memberRecord.sharedWorkingSetBytes;
        aggregateRecord.commitSizeBytes += memberRecord.commitSizeBytes;
        aggregateRecord.pagedPoolBytes += memberRecord.pagedPoolBytes;
        aggregateRecord.nonPagedPoolBytes += memberRecord.nonPagedPoolBytes;
        aggregateRecord.pageFaultCount += memberRecord.pageFaultCount;
        aggregateRecord.workingSetDeltaBytes += memberRecord.workingSetDeltaBytes;
        aggregateRecord.pageFaultDeltaCount += memberRecord.pageFaultDeltaCount;
        aggregateRecord.ioReadOperationCount += memberRecord.ioReadOperationCount;
        aggregateRecord.ioWriteOperationCount += memberRecord.ioWriteOperationCount;
        aggregateRecord.ioOtherOperationCount += memberRecord.ioOtherOperationCount;
        aggregateRecord.ioReadTransferBytes += memberRecord.ioReadTransferBytes;
        aggregateRecord.ioWriteTransferBytes += memberRecord.ioWriteTransferBytes;
        aggregateRecord.ioOtherTransferBytes += memberRecord.ioOtherTransferBytes;
        aggregateRecord.gdiObjectCount += memberRecord.gdiObjectCount;
        aggregateRecord.userObjectCount += memberRecord.userObjectCount;
        aggregateRecord.gpuDedicatedMemoryBytes += memberRecord.gpuDedicatedMemoryBytes;
        aggregateRecord.gpuSharedMemoryBytes += memberRecord.gpuSharedMemoryBytes;
        aggregateRecord.suspendedThreadCount += memberRecord.suspendedThreadCount;

        aggregateRecord.memoryDetailKnown |= memberRecord.memoryDetailKnown;
        aggregateRecord.privateWorkingSetKnown |= memberRecord.privateWorkingSetKnown;
        aggregateRecord.ioDetailKnown |= memberRecord.ioDetailKnown;
        aggregateRecord.guiResourceKnown |= memberRecord.guiResourceKnown;
        aggregateRecord.gpuMemoryKnown |= memberRecord.gpuMemoryKnown;
        aggregateRecord.cycleTimeKnown |= memberRecord.cycleTimeKnown;

        if (memberRecord.processStateKnown)
        {
            ++aggregateStateKnownCount;
            if (memberRecord.processSuspended)
            {
                ++aggregateSuspendedCount;
            }
        }
    }

    aggregateRecord.processStateKnown =
        (aggregateMemberCount > 0U && aggregateStateKnownCount == aggregateMemberCount);
    aggregateRecord.processSuspended =
        (aggregateRecord.processStateKnown && aggregateSuspendedCount == aggregateMemberCount);
    return aggregateRecord;
}
