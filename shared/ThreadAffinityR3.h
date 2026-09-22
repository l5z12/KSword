#pragma once

// ============================================================
// ThreadAffinityR3.h
//
// Purpose:
// - Provides a unified pure R3 thread affinity query/set interface for both Ksword5.1 and KswordARKLight.
// - Prefer the Windows CPU Sets API to display and set thread affinity
//   using stable processor group and logical-index coordinates.
// - Fallback to Get/SetThreadGroupAffinity when CPU Sets are unavailable, and always validate TID, owning
//   PID, and creation time on the same thread handle to prevent erroneous writes after thread ID reuse.
//
// This file does not include R0 protocol, ArkDriverClient, or DeviceIoControl.
// ============================================================

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <set>
#include <string>
#include <utility>
#include <vector>

#ifndef THREAD_QUERY_LIMITED_INFORMATION
#define THREAD_QUERY_LIMITED_INFORMATION 0x0800
#endif

#ifndef THREAD_SET_LIMITED_INFORMATION
#define THREAD_SET_LIMITED_INFORMATION 0x0400
#endif

namespace ksword::thread_affinity_r3
{
    struct LogicalProcessorCoordinate
    {
        std::uint16_t group = 0U;
        std::uint16_t logicalIndex = 0U;
    };

    inline bool operator==(
        const LogicalProcessorCoordinate& left,
        const LogicalProcessorCoordinate& right)
    {
        return left.group == right.group &&
            left.logicalIndex == right.logicalIndex;
    }

    inline bool operator<(
        const LogicalProcessorCoordinate& left,
        const LogicalProcessorCoordinate& right)
    {
        return left.group < right.group ||
            (left.group == right.group && left.logicalIndex < right.logicalIndex);
    }

    struct LogicalProcessorState
    {
        LogicalProcessorCoordinate coordinate;
        std::uint32_t cpuSetId = 0U;
        std::uint16_t coreIndex = 0U;
        std::uint8_t efficiencyClass = 0U;
        bool available = false;
        bool selected = false;
        bool parked = false;
        bool constrainedByThreadOrProcessAffinity = false;
        std::string topologyLabel;
    };

    struct Snapshot
    {
        std::vector<LogicalProcessorState> processors;
        bool usesCpuSets = false;
        // true indicates the thread has no dedicated CPU Set selection, so scheduling continues to follow the CPU Set rules of its parent process.
        bool followsProcessCpuSets = false;
    };

    struct Rule
    {
        bool followProcessCpuSets = false;
        std::vector<LogicalProcessorCoordinate> processors;
    };

    inline void normalizeCoordinates(
        std::vector<LogicalProcessorCoordinate>* const coordinates)
    {
        if (coordinates == nullptr)
        {
            return;
        }
        std::sort(coordinates->begin(), coordinates->end());
        coordinates->erase(
            std::unique(coordinates->begin(), coordinates->end()),
            coordinates->end());
    }

    inline std::string processorIdentityText(const LogicalProcessorCoordinate& coordinate)
    {
        return "G" + std::to_string(coordinate.group) +
            ":L" + std::to_string(coordinate.logicalIndex);
    }

    namespace detail
    {
        using GetSystemCpuSetInformationFunction = BOOL(WINAPI*)(
            PSYSTEM_CPU_SET_INFORMATION,
            ULONG,
            PULONG,
            HANDLE,
            ULONG);
        using GetProcessDefaultCpuSetsFunction = BOOL(WINAPI*)(
            HANDLE,
            PULONG,
            ULONG,
            PULONG);
        using GetThreadSelectedCpuSetsFunction = BOOL(WINAPI*)(
            HANDLE,
            PULONG,
            ULONG,
            PULONG);
        using SetThreadSelectedCpuSetsFunction = BOOL(WINAPI*)(
            HANDLE,
            const ULONG*,
            ULONG);

        struct CpuSetApiFunctions
        {
            GetSystemCpuSetInformationFunction getSystemCpuSetInformation = nullptr;
            GetProcessDefaultCpuSetsFunction getProcessDefaultCpuSets = nullptr;
            GetThreadSelectedCpuSetsFunction getThreadSelectedCpuSets = nullptr;
            SetThreadSelectedCpuSetsFunction setThreadSelectedCpuSets = nullptr;
        };

        inline const CpuSetApiFunctions& cpuSetApiFunctions()
        {
            static const CpuSetApiFunctions kFunctions = []()
            {
                CpuSetApiFunctions resolved;
                const HMODULE kKernel32 = ::GetModuleHandleW(L"kernel32.dll");
                if (kKernel32 == nullptr)
                {
                    return resolved;
                }
                resolved.getSystemCpuSetInformation =
                    reinterpret_cast<GetSystemCpuSetInformationFunction>(
                        ::GetProcAddress(kKernel32, "GetSystemCpuSetInformation"));
                resolved.getProcessDefaultCpuSets =
                    reinterpret_cast<GetProcessDefaultCpuSetsFunction>(
                        ::GetProcAddress(kKernel32, "GetProcessDefaultCpuSets"));
                resolved.getThreadSelectedCpuSets =
                    reinterpret_cast<GetThreadSelectedCpuSetsFunction>(
                        ::GetProcAddress(kKernel32, "GetThreadSelectedCpuSets"));
                resolved.setThreadSelectedCpuSets =
                    reinterpret_cast<SetThreadSelectedCpuSetsFunction>(
                        ::GetProcAddress(kKernel32, "SetThreadSelectedCpuSets"));
                return resolved;
            }();
            return kFunctions;
        }

        class ScopedHandle
        {
        public:
            ScopedHandle() = default;
            explicit ScopedHandle(const HANDLE value) : value_(value) {}
            ~ScopedHandle()
            {
                reset();
            }

            ScopedHandle(const ScopedHandle&) = delete;
            ScopedHandle& operator=(const ScopedHandle&) = delete;

            HANDLE get() const noexcept
            {
                return value_;
            }

            bool valid() const noexcept
            {
                return value_ != nullptr && value_ != INVALID_HANDLE_VALUE;
            }

            void reset(const HANDLE nextValue = nullptr) noexcept
            {
                if (valid())
                {
                    ::CloseHandle(value_);
                }
                value_ = nextValue;
            }

        private:
            HANDLE value_ = nullptr;
        };

        inline std::uint64_t fileTimeToUint64(const FILETIME& fileTime)
        {
            return (static_cast<std::uint64_t>(fileTime.dwHighDateTime) << 32U) |
                static_cast<std::uint64_t>(fileTime.dwLowDateTime);
        }

        // activeProcessorMask converts the number of active processors in the group returned by Windows to a KAFFINITY.
        // Processor group logical indices are contiguous starting from 0; avoid shifting 64 bits when the count reaches the KAFFINITY bit width.
        inline KAFFINITY activeProcessorMask(const USHORT processorGroup)
        {
            const DWORD kActiveProcessorCount = ::GetActiveProcessorCount(processorGroup);
            if (kActiveProcessorCount == 0U)
            {
                return 0U;
            }
            if (kActiveProcessorCount >= sizeof(KAFFINITY) * 8U)
            {
                return ~static_cast<KAFFINITY>(0U);
            }
            return (static_cast<KAFFINITY>(1) << kActiveProcessorCount) - 1U;
        }

        inline bool openVerifiedThread(
            const DWORD threadId,
            const DWORD expectedOwnerProcessId,
            const std::uint64_t expectedCreationTime100ns,
            const DWORD requestedThreadAccess,
            ScopedHandle* const threadOut,
            std::string* const detailTextOut)
        {
            if (threadOut == nullptr || threadId == 0U || expectedOwnerProcessId == 0U ||
                expectedCreationTime100ns == 0U)
            {
                if (detailTextOut != nullptr)
                {
                    *detailTextOut = "thread affinity target identity is unavailable";
                }
                return false;
            }

            threadOut->reset(::OpenThread(
                THREAD_QUERY_LIMITED_INFORMATION | requestedThreadAccess,
                FALSE,
                threadId));
            if (!threadOut->valid())
            {
                if (detailTextOut != nullptr)
                {
                    *detailTextOut = "OpenThread failed(" +
                        std::to_string(::GetLastError()) + ")";
                }
                return false;
            }

            const DWORD kActualOwnerProcessId = ::GetProcessIdOfThread(threadOut->get());
            if (kActualOwnerProcessId == 0U)
            {
                if (detailTextOut != nullptr)
                {
                    *detailTextOut = "GetProcessIdOfThread failed(" +
                        std::to_string(::GetLastError()) + ")";
                }
                return false;
            }
            if (kActualOwnerProcessId != expectedOwnerProcessId)
            {
                if (detailTextOut != nullptr)
                {
                    *detailTextOut = "thread owner process identity changed";
                }
                return false;
            }

            FILETIME creationTime{};
            FILETIME exitTime{};
            FILETIME kernelTime{};
            FILETIME userTime{};
            if (::GetThreadTimes(
                    threadOut->get(),
                    &creationTime,
                    &exitTime,
                    &kernelTime,
                    &userTime) == FALSE)
            {
                if (detailTextOut != nullptr)
                {
                    *detailTextOut = "GetThreadTimes failed(" +
                        std::to_string(::GetLastError()) + ")";
                }
                return false;
            }
            if (fileTimeToUint64(creationTime) != expectedCreationTime100ns)
            {
                if (detailTextOut != nullptr)
                {
                    *detailTextOut = "thread creation time identity changed";
                }
                return false;
            }
            return true;
        }

        template <typename QueryFunction>
        inline bool queryCpuSetIds(
            const HANDLE targetHandle,
            const QueryFunction queryFunction,
            std::vector<std::uint32_t>* const cpuSetIdsOut,
            std::string* const detailTextOut,
            const char* const operationName)
        {
            if (targetHandle == nullptr || queryFunction == nullptr || cpuSetIdsOut == nullptr)
            {
                return false;
            }
            ULONG requiredCount = 0U;
            const BOOL kSizeQueryOk = queryFunction(targetHandle, nullptr, 0U, &requiredCount);
            const DWORD kSizeQueryError = kSizeQueryOk != FALSE ? ERROR_SUCCESS : ::GetLastError();
            if (kSizeQueryOk == FALSE && kSizeQueryError != ERROR_INSUFFICIENT_BUFFER)
            {
                if (detailTextOut != nullptr)
                {
                    *detailTextOut = std::string(operationName) + " size query failed(" +
                        std::to_string(kSizeQueryError) + ")";
                }
                return false;
            }

            cpuSetIdsOut->clear();
            if (requiredCount == 0U)
            {
                return true;
            }
            std::vector<ULONG> nativeIds(requiredCount, 0U);
            ULONG returnedCount = requiredCount;
            if (queryFunction(
                    targetHandle,
                    nativeIds.data(),
                    static_cast<ULONG>(nativeIds.size()),
                    &returnedCount) == FALSE)
            {
                if (detailTextOut != nullptr)
                {
                    *detailTextOut = std::string(operationName) + " failed(" +
                        std::to_string(::GetLastError()) + ")";
                }
                return false;
            }
            nativeIds.resize(std::min<std::size_t>(returnedCount, nativeIds.size()));
            cpuSetIdsOut->assign(nativeIds.begin(), nativeIds.end());
            std::sort(cpuSetIdsOut->begin(), cpuSetIdsOut->end());
            cpuSetIdsOut->erase(
                std::unique(cpuSetIdsOut->begin(), cpuSetIdsOut->end()),
                cpuSetIdsOut->end());
            return true;
        }

        inline bool queryProcessCpuSetIds(
            const HANDLE processHandle,
            const GetProcessDefaultCpuSetsFunction queryFunction,
            std::vector<std::uint32_t>* const cpuSetIdsOut,
            std::string* const detailTextOut)
        {
            return queryCpuSetIds(
                processHandle,
                queryFunction,
                cpuSetIdsOut,
                detailTextOut,
                "GetProcessDefaultCpuSets");
        }

        inline bool querySystemCpuSetStates(
            const HANDLE processHandle,
            const GetSystemCpuSetInformationFunction queryFunction,
            std::vector<LogicalProcessorState>* const processorsOut,
            std::string* const detailTextOut)
        {
            if (queryFunction == nullptr || processorsOut == nullptr)
            {
                return false;
            }
            ULONG requiredBytes = 0U;
            const BOOL kSizeQueryOk = queryFunction(
                nullptr,
                0U,
                &requiredBytes,
                processHandle,
                0U);
            const DWORD kSizeQueryError = kSizeQueryOk != FALSE ? ERROR_SUCCESS : ::GetLastError();
            if (requiredBytes == 0U ||
                (kSizeQueryOk == FALSE && kSizeQueryError != ERROR_INSUFFICIENT_BUFFER))
            {
                if (detailTextOut != nullptr)
                {
                    *detailTextOut = "GetSystemCpuSetInformation size query failed(" +
                        std::to_string(kSizeQueryError) + ")";
                }
                return false;
            }

            std::vector<BYTE> buffer(requiredBytes);
            ULONG returnedBytes = requiredBytes;
            if (queryFunction(
                    reinterpret_cast<PSYSTEM_CPU_SET_INFORMATION>(buffer.data()),
                    static_cast<ULONG>(buffer.size()),
                    &returnedBytes,
                    processHandle,
                    0U) == FALSE)
            {
                if (detailTextOut != nullptr)
                {
                    *detailTextOut = "GetSystemCpuSetInformation failed(" +
                        std::to_string(::GetLastError()) + ")";
                }
                return false;
            }

            processorsOut->clear();
            const BYTE* cursor = buffer.data();
            const BYTE* const kEnd = buffer.data() +
                std::min<std::size_t>(returnedBytes, buffer.size());
            while (cursor < kEnd)
            {
                if (static_cast<std::size_t>(kEnd - cursor) < sizeof(SYSTEM_CPU_SET_INFORMATION))
                {
                    if (detailTextOut != nullptr)
                    {
                        *detailTextOut = "CPU Set information record is truncated";
                    }
                    return false;
                }
                const auto* const kRecord =
                    reinterpret_cast<const SYSTEM_CPU_SET_INFORMATION*>(cursor);
                if (kRecord->Size < sizeof(SYSTEM_CPU_SET_INFORMATION) ||
                    kRecord->Size > static_cast<DWORD>(kEnd - cursor))
                {
                    if (detailTextOut != nullptr)
                    {
                        *detailTextOut = "CPU Set information record size is invalid";
                    }
                    return false;
                }
                if (kRecord->Type == CpuSetInformation)
                {
                    const BYTE kFlags = kRecord->CpuSet.AllFlags;
                    LogicalProcessorState processor;
                    processor.coordinate.group = kRecord->CpuSet.Group;
                    processor.coordinate.logicalIndex = kRecord->CpuSet.LogicalProcessorIndex;
                    processor.cpuSetId = kRecord->CpuSet.Id;
                    processor.coreIndex = kRecord->CpuSet.CoreIndex;
                    processor.efficiencyClass = kRecord->CpuSet.EfficiencyClass;
                    processor.parked =
                        (kFlags & SYSTEM_CPU_SET_INFORMATION_PARKED) != 0U;
                    processor.available =
                        (kFlags & SYSTEM_CPU_SET_INFORMATION_ALLOCATED) == 0U ||
                        (kFlags & SYSTEM_CPU_SET_INFORMATION_ALLOCATED_TO_TARGET_PROCESS) != 0U;
                    processorsOut->push_back(std::move(processor));
                }
                cursor += kRecord->Size;
            }
            std::sort(
                processorsOut->begin(),
                processorsOut->end(),
                [](const LogicalProcessorState& left, const LogicalProcessorState& right)
                {
                    return left.coordinate < right.coordinate;
                });
            if (processorsOut->empty())
            {
                if (detailTextOut != nullptr)
                {
                    *detailTextOut = "GetSystemCpuSetInformation returned no CPU Sets";
                }
                return false;
            }
            return true;
        }

        inline void populateTopologyLabels(std::vector<LogicalProcessorState>* const processors)
        {
            if (processors == nullptr)
            {
                return;
            }
            for (LogicalProcessorState& processor : *processors)
            {
                processor.topologyLabel = "C" + std::to_string(processor.coreIndex);
            }
        }

        inline bool queryCpuSetSnapshot(
            const DWORD expectedOwnerProcessId,
            const HANDLE threadHandle,
            const CpuSetApiFunctions& functions,
            Snapshot* const snapshotOut,
            std::string* const detailTextOut)
        {
            ScopedHandle processHandle(::OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                FALSE,
                expectedOwnerProcessId));
            if (!processHandle.valid())
            {
                if (detailTextOut != nullptr)
                {
                    *detailTextOut = "OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) failed(" +
                        std::to_string(::GetLastError()) + ")";
                }
                return false;
            }

            GROUP_AFFINITY threadGroupAffinity{};
            if (::GetThreadGroupAffinity(threadHandle, &threadGroupAffinity) == FALSE ||
                threadGroupAffinity.Mask == 0U)
            {
                if (detailTextOut != nullptr)
                {
                    *detailTextOut = "GetThreadGroupAffinity failed(" +
                        std::to_string(::GetLastError()) + ")";
                }
                return false;
            }

            std::vector<LogicalProcessorState> processors;
            if (!querySystemCpuSetStates(
                    processHandle.get(),
                    functions.getSystemCpuSetInformation,
                    &processors,
                    detailTextOut))
            {
                return false;
            }
            std::vector<std::uint32_t> processCpuSetIds;
            if (!queryProcessCpuSetIds(
                    processHandle.get(),
                    functions.getProcessDefaultCpuSets,
                    &processCpuSetIds,
                    detailTextOut))
            {
                return false;
            }
            std::vector<std::uint32_t> threadCpuSetIds;
            if (!queryCpuSetIds(
                    threadHandle,
                    functions.getThreadSelectedCpuSets,
                    &threadCpuSetIds,
                    detailTextOut,
                    "GetThreadSelectedCpuSets"))
            {
                return false;
            }

            const std::set<std::uint32_t> kProcessCpuSetIdSet(
                processCpuSetIds.begin(), processCpuSetIds.end());
            const std::set<std::uint32_t> kThreadCpuSetIdSet(
                threadCpuSetIds.begin(), threadCpuSetIds.end());
            for (LogicalProcessorState& processor : processors)
            {
                const bool kInThreadGroup = processor.coordinate.group == threadGroupAffinity.Group &&
                    processor.coordinate.logicalIndex < sizeof(KAFFINITY) * 8U &&
                    (threadGroupAffinity.Mask &
                        (static_cast<KAFFINITY>(1) << processor.coordinate.logicalIndex)) != 0U;
                const bool kInProcessCpuSets = processCpuSetIds.empty() ||
                    kProcessCpuSetIdSet.find(processor.cpuSetId) != kProcessCpuSetIdSet.end();
                processor.constrainedByThreadOrProcessAffinity =
                    !kInThreadGroup || !kInProcessCpuSets;
                processor.available = processor.available && kInThreadGroup && kInProcessCpuSets;
                processor.selected = processor.available &&
                    (threadCpuSetIds.empty() ||
                        kThreadCpuSetIdSet.find(processor.cpuSetId) != kThreadCpuSetIdSet.end());
            }
            populateTopologyLabels(&processors);
            snapshotOut->processors = std::move(processors);
            snapshotOut->usesCpuSets = true;
            snapshotOut->followsProcessCpuSets = threadCpuSetIds.empty();
            return true;
        }

        inline bool queryLegacySnapshot(
            const HANDLE threadHandle,
            Snapshot* const snapshotOut,
            std::string* const detailTextOut)
        {
            GROUP_AFFINITY threadGroupAffinity{};
            if (::GetThreadGroupAffinity(threadHandle, &threadGroupAffinity) == FALSE ||
                threadGroupAffinity.Mask == 0U)
            {
                if (detailTextOut != nullptr)
                {
                    *detailTextOut = "GetThreadGroupAffinity failed(" +
                        std::to_string(::GetLastError()) + ")";
                }
                return false;
            }
            const KAFFINITY kActiveMask = activeProcessorMask(threadGroupAffinity.Group);
            if (kActiveMask == 0U)
            {
                if (detailTextOut != nullptr)
                {
                    *detailTextOut = "GetActiveProcessorMask returned no active processor";
                }
                return false;
            }

            Snapshot snapshot;
            snapshot.usesCpuSets = false;
            snapshot.followsProcessCpuSets = threadGroupAffinity.Mask == kActiveMask;
            for (std::uint16_t logicalIndex = 0U;
                 logicalIndex < static_cast<std::uint16_t>(sizeof(KAFFINITY) * 8U);
                 ++logicalIndex)
            {
                const KAFFINITY kProcessorBit = static_cast<KAFFINITY>(1) << logicalIndex;
                if ((kActiveMask & kProcessorBit) == 0U)
                {
                    continue;
                }
                LogicalProcessorState processor;
                processor.coordinate = LogicalProcessorCoordinate{
                    threadGroupAffinity.Group,
                    logicalIndex
                };
                processor.cpuSetId = logicalIndex;
                processor.coreIndex = logicalIndex;
                processor.available = true;
                processor.selected = (threadGroupAffinity.Mask & kProcessorBit) != 0U;
                processor.topologyLabel = "C" + std::to_string(logicalIndex);
                snapshot.processors.push_back(std::move(processor));
            }
            *snapshotOut = std::move(snapshot);
            return true;
        }

        inline bool setLegacyAffinity(
            const HANDLE threadHandle,
            const Rule& requestedRule,
            std::string* const detailTextOut)
        {
            GROUP_AFFINITY currentAffinity{};
            if (::GetThreadGroupAffinity(threadHandle, &currentAffinity) == FALSE ||
                currentAffinity.Mask == 0U)
            {
                if (detailTextOut != nullptr)
                {
                    *detailTextOut = "GetThreadGroupAffinity failed(" +
                        std::to_string(::GetLastError()) + ")";
                }
                return false;
            }
            const KAFFINITY kActiveMask = activeProcessorMask(currentAffinity.Group);
            KAFFINITY requestedMask = requestedRule.followProcessCpuSets ? kActiveMask : 0U;
            if (!requestedRule.followProcessCpuSets)
            {
                for (const LogicalProcessorCoordinate& coordinate : requestedRule.processors)
                {
                    if (coordinate.group != currentAffinity.Group ||
                        coordinate.logicalIndex >= sizeof(KAFFINITY) * 8U)
                    {
                        if (detailTextOut != nullptr)
                        {
                            *detailTextOut = "legacy thread affinity cannot cross processor groups";
                        }
                        return false;
                    }
                    requestedMask |= static_cast<KAFFINITY>(1) << coordinate.logicalIndex;
                }
                requestedMask &= kActiveMask;
            }
            if (requestedMask == 0U)
            {
                if (detailTextOut != nullptr)
                {
                    *detailTextOut = "requested thread affinity has no available logical processor";
                }
                return false;
            }

            GROUP_AFFINITY requestedAffinity = currentAffinity;
            requestedAffinity.Mask = requestedMask;
            if (currentAffinity.Mask != requestedMask &&
                ::SetThreadGroupAffinity(threadHandle, &requestedAffinity, nullptr) == FALSE)
            {
                if (detailTextOut != nullptr)
                {
                    *detailTextOut = "SetThreadGroupAffinity failed(" +
                        std::to_string(::GetLastError()) + ")";
                }
                return false;
            }
            if (detailTextOut != nullptr)
            {
                detailTextOut->clear();
            }
            return true;
        }
    }

    inline bool queryThreadAffinityState(
        const DWORD threadId,
        const DWORD expectedOwnerProcessId,
        const std::uint64_t expectedCreationTime100ns,
        Snapshot* const snapshotOut,
        std::string* const detailTextOut)
    {
        if (snapshotOut == nullptr)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "thread affinity snapshot output is null";
            }
            return false;
        }
        *snapshotOut = Snapshot{};

        detail::ScopedHandle threadHandle;
        if (!detail::openVerifiedThread(
                threadId,
                expectedOwnerProcessId,
                expectedCreationTime100ns,
                0U,
                &threadHandle,
                detailTextOut))
        {
            return false;
        }

        const detail::CpuSetApiFunctions& functions = detail::cpuSetApiFunctions();
        const bool kCpuSetsAvailable = functions.getSystemCpuSetInformation != nullptr &&
            functions.getProcessDefaultCpuSets != nullptr &&
            functions.getThreadSelectedCpuSets != nullptr;
        const bool kQueryOk = kCpuSetsAvailable
            ? detail::queryCpuSetSnapshot(
                expectedOwnerProcessId,
                threadHandle.get(),
                functions,
                snapshotOut,
                detailTextOut)
            : detail::queryLegacySnapshot(threadHandle.get(), snapshotOut, detailTextOut);
        if (kQueryOk && detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }
        return kQueryOk;
    }

    inline bool setThreadAffinityRule(
        const DWORD threadId,
        const DWORD expectedOwnerProcessId,
        const std::uint64_t expectedCreationTime100ns,
        const Rule& sourceRule,
        std::string* const detailTextOut)
    {
        Rule rule = sourceRule;
        normalizeCoordinates(&rule.processors);
        if (!rule.followProcessCpuSets && rule.processors.empty())
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "thread affinity rule must retain at least one logical processor";
            }
            return false;
        }

        detail::ScopedHandle threadHandle;
        if (!detail::openVerifiedThread(
                threadId,
                expectedOwnerProcessId,
                expectedCreationTime100ns,
                THREAD_SET_LIMITED_INFORMATION,
                &threadHandle,
                detailTextOut))
        {
            return false;
        }

        const detail::CpuSetApiFunctions& functions = detail::cpuSetApiFunctions();
        const bool kCpuSetsAvailable = functions.getSystemCpuSetInformation != nullptr &&
            functions.getProcessDefaultCpuSets != nullptr &&
            functions.getThreadSelectedCpuSets != nullptr &&
            functions.setThreadSelectedCpuSets != nullptr;
        if (!kCpuSetsAvailable)
        {
            return detail::setLegacyAffinity(threadHandle.get(), rule, detailTextOut);
        }

        Snapshot currentSnapshot;
        if (!detail::queryCpuSetSnapshot(
                expectedOwnerProcessId,
                threadHandle.get(),
                functions,
                &currentSnapshot,
                detailTextOut))
        {
            return false;
        }

        std::vector<ULONG> requestedCpuSetIds;
        if (!rule.followProcessCpuSets)
        {
            for (const LogicalProcessorCoordinate& coordinate : rule.processors)
            {
                const auto kProcessorIt = std::find_if(
                    currentSnapshot.processors.begin(),
                    currentSnapshot.processors.end(),
                    [&coordinate](const LogicalProcessorState& processor)
                    {
                        return processor.coordinate == coordinate && processor.available;
                    });
                if (kProcessorIt == currentSnapshot.processors.end())
                {
                    if (detailTextOut != nullptr)
                    {
                        *detailTextOut = "requested thread CPU Set is unavailable: " +
                            processorIdentityText(coordinate);
                    }
                    return false;
                }
                requestedCpuSetIds.push_back(static_cast<ULONG>(kProcessorIt->cpuSetId));
            }
            std::sort(requestedCpuSetIds.begin(), requestedCpuSetIds.end());
            requestedCpuSetIds.erase(
                std::unique(requestedCpuSetIds.begin(), requestedCpuSetIds.end()),
                requestedCpuSetIds.end());
        }

        std::vector<std::uint32_t> previousCpuSetIds;
        if (!detail::queryCpuSetIds(
                threadHandle.get(),
                functions.getThreadSelectedCpuSets,
                &previousCpuSetIds,
                detailTextOut,
                "GetThreadSelectedCpuSets"))
        {
            return false;
        }

        const BOOL kSetOk = functions.setThreadSelectedCpuSets(
            threadHandle.get(),
            rule.followProcessCpuSets ? nullptr : requestedCpuSetIds.data(),
            rule.followProcessCpuSets ? 0U : static_cast<ULONG>(requestedCpuSetIds.size()));
        if (kSetOk == FALSE)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "SetThreadSelectedCpuSets failed(" +
                    std::to_string(::GetLastError()) + ")";
            }
            return false;
        }

        std::vector<std::uint32_t> verifiedCpuSetIds;
        std::string verificationDetail;
        const bool kVerifyOk = detail::queryCpuSetIds(
            threadHandle.get(),
            functions.getThreadSelectedCpuSets,
            &verifiedCpuSetIds,
            &verificationDetail,
            "GetThreadSelectedCpuSets");
        std::vector<std::uint32_t> expectedCpuSetIds(
            requestedCpuSetIds.begin(), requestedCpuSetIds.end());
        const bool kVerifyMatches = kVerifyOk && verifiedCpuSetIds == expectedCpuSetIds;
        if (!kVerifyMatches)
        {
            const std::vector<ULONG> kRollbackCpuSetIds(
                previousCpuSetIds.begin(), previousCpuSetIds.end());
            const BOOL kRollbackOk = functions.setThreadSelectedCpuSets(
                threadHandle.get(),
                kRollbackCpuSetIds.empty() ? nullptr : kRollbackCpuSetIds.data(),
                static_cast<ULONG>(kRollbackCpuSetIds.size()));
            if (detailTextOut != nullptr)
            {
                *detailTextOut = kVerifyOk
                    ? "thread CPU Set verification did not match the requested selection; rollback " +
                        std::string(kRollbackOk != FALSE ? "succeeded" : "failed")
                    : "thread CPU Set verification failed(" + verificationDetail + "); rollback " +
                        std::string(kRollbackOk != FALSE ? "succeeded" : "failed");
            }
            return false;
        }

        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }
        return true;
    }
}
