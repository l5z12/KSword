#include "KernelThreadAuditTab.h"

#include "../../../shared/ark_client/ArkDriverClient.h"

#include <Windows.h>

#include <QByteArray>

#include <algorithm>
#include <cstddef>
#include <limits>
#include <unordered_map>
#include <utility>
#include <vector>

namespace
{
    using NtQuerySystemInformationFunction = LONG(NTAPI*)(
        unsigned long,
        void*,
        unsigned long,
        unsigned long*);

    struct RawModuleEntry
    {
        HANDLE section;
        void* mappedBase;
        void* imageBase;
        unsigned long imageSize;
        unsigned long flags;
        unsigned short loadOrderIndex;
        unsigned short initOrderIndex;
        unsigned short loadCount;
        unsigned short fileNameOffset;
        unsigned char fullPathName[256];
    };

    struct RawModuleInformation
    {
        unsigned long moduleCount;
        RawModuleEntry modules[1];
    };

    constexpr unsigned long kSystemModuleInformationClass = 11UL;
    constexpr LONG kStatusInfoLengthMismatch = static_cast<LONG>(0xC0000004UL);
    constexpr std::size_t kMaximumModuleSnapshotBytes = 16U * 1024U * 1024U;
    constexpr std::uint32_t kSystemProcessId = 4U;

    std::size_t boundedAnsiLength(
        const unsigned char* const text,
        const std::size_t capacity)
    {
        if (text == nullptr)
        {
            return 0U;
        }
        for (std::size_t index = 0U; index < capacity; ++index)
        {
            if (text[index] == 0U)
            {
                return index;
            }
        }
        return capacity;
    }

    std::uint64_t checkedAddressEnd(
        const std::uint64_t baseAddress,
        const std::uint32_t imageSize)
    {
        const std::uint64_t kSizeValue = static_cast<std::uint64_t>(imageSize);
        if (baseAddress > (std::numeric_limits<std::uint64_t>::max)() - kSizeValue)
        {
            return (std::numeric_limits<std::uint64_t>::max)();
        }
        return baseAddress + kSizeValue;
    }
}

KernelThreadAuditTab::Snapshot KernelThreadAuditTab::collectSnapshot(const Mode mode)
{
    Snapshot snapshot;
    const ksword::ark::DriverClient kDriverClient;

    if (mode == Mode::kWorkQueueThreads)
    {
        const ksword::ark::WorkQueueEnumResult kResult =
            kDriverClient.enumerateWorkQueues();
        snapshot.r0Available = kResult.io.ok;
        snapshot.r0Win32Error = kResult.io.win32Error;
        snapshot.workQueueQueryStatus = kResult.queryStatus;
        snapshot.workQueueStatusFlags = kResult.statusFlags;
        snapshot.workQueueTotalCount = kResult.totalCount;
        snapshot.workQueueNodeCount = kResult.nodeCount;
        snapshot.workQueueQueuesVisited = kResult.queuesVisited;
        snapshot.workQueueCorruptCount = kResult.corruptListCount;
        snapshot.workQueueReadFailureCount = kResult.readFailureCount;
        snapshot.workQueueReferenceFailureCount = kResult.referenceFailureCount;
        snapshot.workQueueLastStatus = kResult.lastStatus;

        if (!kResult.io.ok)
        {
            snapshot.diagnosticFlags |= kDiagnosticWorkQueueTransportFailed;
            if (kResult.unsupported)
            {
                snapshot.diagnosticFlags |= kDiagnosticWorkQueueUnsupported;
            }
            return snapshot;
        }
        if (kResult.unsupported ||
            kResult.queryStatus == KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_UNSUPPORTED ||
            kResult.queryStatus == KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_INVALID_LAYOUT ||
            kResult.queryStatus == KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_IDENTITY_MISMATCH)
        {
            snapshot.diagnosticFlags |= kDiagnosticWorkQueueUnsupported;
        }
        if (kResult.queryStatus == KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_PARTIAL)
        {
            snapshot.diagnosticFlags |= kDiagnosticWorkQueuePartial;
        }

        snapshot.rows.reserve(kResult.entries.size());
        for (const ksword::ark::WorkQueueEntry& source : kResult.entries)
        {
            ThreadRow row;
            row.threadId = source.threadId;
            row.createTime100ns = source.threadCreateTime100ns;
            row.startAddress = source.routineAddress;
            row.queueAddress = source.queueAddress;
            row.workItemAddress = source.workItemAddress;
            row.parameterAddress = source.parameterAddress;
            row.threadObject = source.threadObject;
            row.workQueueRowKind = source.rowKind;
            row.queueType = source.queueType;
            row.queuePriorityIndex = source.priorityIndex;
            row.nodeIndex = source.nodeIndex;
            row.workQueueFlags = source.flags;
            row.workQueueStatus = source.status;
            row.module.name = QString::fromLocal8Bit(
                source.moduleName.data(),
                static_cast<int>(source.moduleName.size()));
            row.module.path = QString::fromLocal8Bit(
                source.modulePath.data(),
                static_cast<int>(source.modulePath.size()));
            row.module.baseAddress = source.moduleBase;
            row.module.imageSize = source.moduleSize;
            row.moduleResolved =
                (source.flags & KSWORD_ARK_WORK_QUEUE_ENTRY_MODULE_RESOLVED) != 0U;
            row.protectedTarget = true;
            row.protectionKind = ProtectionKind::kReadOnlyWorkQueueEvidence;
            snapshot.rows.push_back(std::move(row));
        }

        std::sort(
            snapshot.rows.begin(),
            snapshot.rows.end(),
            [](const ThreadRow& left, const ThreadRow& right) {
                if (left.nodeIndex != right.nodeIndex)
                {
                    return left.nodeIndex < right.nodeIndex;
                }
                if (left.queueType != right.queueType)
                {
                    return left.queueType < right.queueType;
                }
                if (left.workQueueRowKind != right.workQueueRowKind)
                {
                    return left.workQueueRowKind < right.workQueueRowKind;
                }
                const std::uint64_t kLeftIdentity =
                    left.workItemAddress != 0U ? left.workItemAddress : left.threadObject;
                const std::uint64_t kRightIdentity =
                    right.workItemAddress != 0U ? right.workItemAddress : right.threadObject;
                return kLeftIdentity < kRightIdentity;
            });
        return snapshot;
    }

    bool usedNtQuery = false;
    std::string ignoredR3Diagnostic;
    const std::vector<ks::process::SystemThreadRecord> kSystemThreads =
        ks::process::enumerateSystemThreads(&usedNtQuery, &ignoredR3Diagnostic);
    snapshot.usedNtQuery = usedNtQuery;
    if (kSystemThreads.empty())
    {
        snapshot.diagnosticFlags |= kDiagnosticR3EnumerationEmpty;
    }

    const ksword::ark::ThreadEnumResult kR0Result = kDriverClient.enumerateThreads(
        KSWORD_ARK_ENUM_THREAD_FLAG_INCLUDE_WORKER_STATE,
        kSystemProcessId);
    snapshot.r0Available = kR0Result.io.ok;
    snapshot.r0Win32Error = kR0Result.io.win32Error;
    if (!kR0Result.io.ok)
    {
        snapshot.diagnosticFlags |= kDiagnosticR0ThreadUnavailable;
    }

    std::unordered_map<std::uint32_t, const ksword::ark::ThreadEntry*> r0ByTid;
    for (const ksword::ark::ThreadEntry& r0Entry : kR0Result.entries)
    {
        if (r0Entry.processId == kSystemProcessId && r0Entry.threadId != 0U)
        {
            r0ByTid.insert_or_assign(r0Entry.threadId, &r0Entry);
        }
    }

    const std::vector<ModuleRecord> kModules = queryKernelModules(
        &snapshot.moduleQueryStatus,
        &snapshot.moduleNativeStatus,
        &snapshot.moduleRequiredBytes);
    if (snapshot.moduleQueryStatus != ModuleQueryStatus::kOk)
    {
        snapshot.diagnosticFlags |= kDiagnosticModuleUnavailable;
    }

    for (const ks::process::SystemThreadRecord& sourceThread : kSystemThreads)
    {
        if (sourceThread.ownerPid != kSystemProcessId || sourceThread.threadId == 0U)
        {
            continue;
        }

        ThreadRow row;
        row.threadId = sourceThread.threadId;
        row.createTime100ns = sourceThread.createTime100ns;
        row.startAddress = sourceThread.startAddress != 0U
            ? sourceThread.startAddress
            : sourceThread.win32StartAddress;
        row.priority = sourceThread.priority;
        row.basePriority = sourceThread.basePriority;
        row.state = sourceThread.threadState;
        row.waitReason = sourceThread.waitReason;

        const auto kR0Iterator = r0ByTid.find(row.threadId);
        if (kR0Iterator != r0ByTid.end() && kR0Iterator->second != nullptr)
        {
            const ksword::ark::ThreadEntry& r0Entry = *(kR0Iterator->second);
            row.r0Flags = r0Entry.flags;
            row.r0FieldFlags = r0Entry.fieldFlags;
            row.r0Status = r0Entry.r0Status;
            row.workerKnown =
                (r0Entry.fieldFlags & KSWORD_ARK_THREAD_FIELD_ACTIVE_EX_WORKER_PRESENT) != 0U;
            row.activeWorker =
                (r0Entry.flags & KSWORD_ARK_THREAD_FLAG_ACTIVE_EX_WORKER) != 0U;
        }

        row.module = findOwnerModule(
            kModules,
            row.startAddress,
            &row.moduleResolved);
        // System thread pages are no longer disabled for operations based on kernel ownership, unknown modules, startup address, or missing creation time.
        // In R0-only recheck requests, only the actually available identity fields are used; TID is always a necessary identifier for the action entry.
        row.protectedTarget = false;
        row.protectionKind = ProtectionKind::kBestEffortR0Recheck;
        snapshot.rows.push_back(std::move(row));
    }

    std::sort(
        snapshot.rows.begin(),
        snapshot.rows.end(),
        [](const ThreadRow& left, const ThreadRow& right) {
            return left.threadId < right.threadId;
        });
    return snapshot;
}

std::vector<KernelThreadAuditTab::ModuleRecord>
KernelThreadAuditTab::queryKernelModules(
    ModuleQueryStatus* const queryStatusOut,
    long* const nativeStatusOut,
    unsigned long* const requiredBytesOut)
{
    if (queryStatusOut != nullptr)
    {
        *queryStatusOut = ModuleQueryStatus::kOk;
    }
    if (nativeStatusOut != nullptr)
    {
        *nativeStatusOut = 0L;
    }
    if (requiredBytesOut != nullptr)
    {
        *requiredBytesOut = 0UL;
    }

    HMODULE ntdllModule = ::GetModuleHandleW(L"ntdll.dll");
    const auto kQuerySystemInformation = ntdllModule != nullptr
        ? reinterpret_cast<NtQuerySystemInformationFunction>(
            ::GetProcAddress(ntdllModule, "NtQuerySystemInformation"))
        : nullptr;
    if (kQuerySystemInformation == nullptr)
    {
        if (queryStatusOut != nullptr)
        {
            *queryStatusOut = ModuleQueryStatus::kApiUnavailable;
        }
        return {};
    }

    unsigned long requiredBytes = 0UL;
    LONG status = kQuerySystemInformation(
        kSystemModuleInformationClass,
        nullptr,
        0UL,
        &requiredBytes);
    if (requiredBytesOut != nullptr)
    {
        *requiredBytesOut = requiredBytes;
    }
    if (nativeStatusOut != nullptr)
    {
        *nativeStatusOut = status;
    }
    if (status != kStatusInfoLengthMismatch ||
        requiredBytes < sizeof(RawModuleInformation) ||
        requiredBytes > kMaximumModuleSnapshotBytes)
    {
        if (queryStatusOut != nullptr)
        {
            *queryStatusOut = ModuleQueryStatus::kLengthQueryFailed;
        }
        return {};
    }

    std::vector<unsigned char> buffer(
        static_cast<std::size_t>(requiredBytes) + 4096U);
    unsigned long returnedBytes = 0UL;
    status = kQuerySystemInformation(
        kSystemModuleInformationClass,
        buffer.data(),
        static_cast<unsigned long>(buffer.size()),
        &returnedBytes);
    if (nativeStatusOut != nullptr)
    {
        *nativeStatusOut = status;
    }
    if (status != 0L ||
        returnedBytes < offsetof(RawModuleInformation, modules))
    {
        if (queryStatusOut != nullptr)
        {
            *queryStatusOut = ModuleQueryStatus::kSnapshotFailed;
        }
        return {};
    }

    const auto* const kRawInformation =
        reinterpret_cast<const RawModuleInformation*>(buffer.data());
    const std::size_t kHeaderBytes = offsetof(RawModuleInformation, modules);
    const std::size_t kAvailableEntries =
        (static_cast<std::size_t>(returnedBytes) - kHeaderBytes) /
        sizeof(RawModuleEntry);
    const std::size_t kSafeEntryCount = (std::min)(
        static_cast<std::size_t>(kRawInformation->moduleCount),
        kAvailableEntries);

    std::vector<ModuleRecord> modules;
    modules.reserve(kSafeEntryCount);
    for (std::size_t moduleIndex = 0U;
         moduleIndex < kSafeEntryCount;
         ++moduleIndex)
    {
        const RawModuleEntry& rawModule = kRawInformation->modules[moduleIndex];
        const std::size_t kPathLength = boundedAnsiLength(
            rawModule.fullPathName,
            sizeof(rawModule.fullPathName));
        const QByteArray kPathBytes(
            reinterpret_cast<const char*>(rawModule.fullPathName),
            static_cast<int>(kPathLength));

        ModuleRecord module;
        module.path = QString::fromLocal8Bit(kPathBytes);
        module.baseAddress = static_cast<std::uint64_t>(
            reinterpret_cast<std::uintptr_t>(rawModule.imageBase));
        module.imageSize = rawModule.imageSize;
        module.kernelImage = moduleIndex == 0U;
        if (rawModule.fileNameOffset < kPathLength)
        {
            module.name = QString::fromLocal8Bit(
                kPathBytes.constData() + rawModule.fileNameOffset,
                static_cast<int>(kPathLength - rawModule.fileNameOffset));
        }
        if (module.name.isEmpty())
        {
            module.name = module.path.section(QLatin1Char('\\'), -1);
        }
        modules.push_back(std::move(module));
    }
    return modules;
}

KernelThreadAuditTab::ModuleRecord KernelThreadAuditTab::findOwnerModule(
    const std::vector<ModuleRecord>& modules,
    const std::uint64_t address,
    bool* const matchedOut)
{
    if (matchedOut != nullptr)
    {
        *matchedOut = false;
    }
    if (address == 0U)
    {
        return {};
    }

    for (const ModuleRecord& module : modules)
    {
        const std::uint64_t kModuleEnd =
            checkedAddressEnd(module.baseAddress, module.imageSize);
        if (module.baseAddress != 0U &&
            address >= module.baseAddress &&
            address < kModuleEnd)
        {
            if (matchedOut != nullptr)
            {
                *matchedOut = true;
            }
            return module;
        }
    }
    return {};
}
