#pragma once

// ============================================================
// ProcessAffinityUtils.h
// Purpose:
// - Provide processor-group-aware CPU affinity query and set entry points for the process list and details windows.
// - Prioritizes dynamic resolution of the Windows 10 CPU Sets API to ensure stable group/index coordinate selection across groups;
// - Fall back to single processor group Get/SetProcessAffinityMask APIs on older systems or when APIs are missing.
// ============================================================

#include "ProcessAffinityModel.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

namespace ks::process
{
    namespace affinity_detail
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
        using SetProcessDefaultCpuSetsFunction = BOOL(WINAPI*)(
            HANDLE,
            const ULONG*,
            ULONG);

        // CpuSetApiFunctions: caches Kernel32 dynamic entry points to avoid binding failures during the loading phase on older systems.
        struct CpuSetApiFunctions
        {
            GetSystemCpuSetInformationFunction getSystemCpuSetInformation = nullptr;
            GetProcessDefaultCpuSetsFunction getProcessDefaultCpuSets = nullptr;
            SetProcessDefaultCpuSetsFunction setProcessDefaultCpuSets = nullptr;
        };

        // cpuSetApiFunctions purpose: Parse the Windows 10 CPU Sets API only once; callers check for the existence of required entries.
        inline const CpuSetApiFunctions& cpuSetApiFunctions()
        {
            static const CpuSetApiFunctions kFunctions = []()
            {
                CpuSetApiFunctions resolvedFunctions;
                const HMODULE kKernel32Module = ::GetModuleHandleW(L"kernel32.dll");
                if (kKernel32Module == nullptr)
                {
                    return resolvedFunctions;
                }
                resolvedFunctions.getSystemCpuSetInformation =
                    reinterpret_cast<GetSystemCpuSetInformationFunction>(
                        ::GetProcAddress(kKernel32Module, "GetSystemCpuSetInformation"));
                resolvedFunctions.getProcessDefaultCpuSets =
                    reinterpret_cast<GetProcessDefaultCpuSetsFunction>(
                        ::GetProcAddress(kKernel32Module, "GetProcessDefaultCpuSets"));
                resolvedFunctions.setProcessDefaultCpuSets =
                    reinterpret_cast<SetProcessDefaultCpuSetsFunction>(
                        ::GetProcAddress(kKernel32Module, "SetProcessDefaultCpuSets"));
                return resolvedFunctions;
            }();
            return kFunctions;
        }

        // closeProcessHandle purpose: Uniformly close the real process handles opened in this file.
        inline void closeProcessHandle(HANDLE* const processHandle)
        {
            if (processHandle != nullptr && *processHandle != nullptr)
            {
                ::CloseHandle(*processHandle);
                *processHandle = nullptr;
            }
        }

        // querySingleProcessGroup:
        // - Returns the group only if the target is explicitly confined to a single processor group;
        // - Return false for multi-group processes to prevent misinterpreting ULONG_PTR as a full-system mask.
        inline bool querySingleProcessGroup(
            const HANDLE processHandle,
            USHORT* const processorGroupOut)
        {
            if (processHandle == nullptr || processorGroupOut == nullptr)
            {
                return false;
            }

            USHORT groupCount = 1U;
            USHORT processorGroup = 0U;
            if (::GetProcessGroupAffinity(
                    processHandle,
                    &groupCount,
                    &processorGroup) == FALSE ||
                groupCount != 1U)
            {
                return false;
            }
            *processorGroupOut = processorGroup;
            return true;
        }

        // querySystemCpuSetStates:
        // - enumerate system CPU sets and map temporary IDs to stable group/index values;
        // - processHandle is used to distinguish between CPU Sets allocated to other processes and those allocated to the current target.
        inline bool querySystemCpuSetStates(
            const HANDLE processHandle,
            const CpuSetApiFunctions& functions,
            std::vector<LogicalProcessorState>* const processorsOut,
            std::string* const detailTextOut)
        {
            if (processHandle == nullptr || processorsOut == nullptr ||
                functions.getSystemCpuSetInformation == nullptr)
            {
                return false;
            }

            ULONG requiredBytes = 0U;
            const BOOL kSizeQueryOk = functions.getSystemCpuSetInformation(
                nullptr,
                0U,
                &requiredBytes,
                processHandle,
                0U);
            const DWORD kSizeQueryError =
                kSizeQueryOk != FALSE ? ERROR_SUCCESS : ::GetLastError();
            if (requiredBytes == 0U ||
                (kSizeQueryOk == FALSE && kSizeQueryError != ERROR_INSUFFICIENT_BUFFER))
            {
                if (detailTextOut != nullptr)
                {
                    *detailTextOut =
                        "GetSystemCpuSetInformation size query failed(" +
                        std::to_string(kSizeQueryError) + ")";
                }
                return false;
            }

            std::vector<BYTE> cpuSetBuffer(requiredBytes);
            ULONG returnedBytes = requiredBytes;
            if (functions.getSystemCpuSetInformation(
                    reinterpret_cast<PSYSTEM_CPU_SET_INFORMATION>(cpuSetBuffer.data()),
                    static_cast<ULONG>(cpuSetBuffer.size()),
                    &returnedBytes,
                    processHandle,
                    0U) == FALSE)
            {
                if (detailTextOut != nullptr)
                {
                    *detailTextOut =
                        "GetSystemCpuSetInformation failed(" +
                        std::to_string(::GetLastError()) + ")";
                }
                return false;
            }

            processorsOut->clear();
            const BYTE* cpuSetCursor = cpuSetBuffer.data();
            const BYTE* const kCpuSetEnd =
                cpuSetBuffer.data() +
                std::min<std::size_t>(returnedBytes, cpuSetBuffer.size());
            while (cpuSetCursor < kCpuSetEnd)
            {
                if (static_cast<std::size_t>(kCpuSetEnd - cpuSetCursor) <
                    sizeof(SYSTEM_CPU_SET_INFORMATION))
                {
                    if (detailTextOut != nullptr)
                    {
                        *detailTextOut = "CPU Set information record is truncated";
                    }
                    return false;
                }

                const auto* const kCpuSetRecord =
                    reinterpret_cast<const SYSTEM_CPU_SET_INFORMATION*>(cpuSetCursor);
                if (kCpuSetRecord->Size < sizeof(SYSTEM_CPU_SET_INFORMATION) ||
                    kCpuSetRecord->Size >
                        static_cast<DWORD>(kCpuSetEnd - cpuSetCursor))
                {
                    if (detailTextOut != nullptr)
                    {
                        *detailTextOut = "CPU Set information record size is invalid";
                    }
                    return false;
                }
                if (kCpuSetRecord->Type == CpuSetInformation)
                {
                    const BYTE kCpuSetFlags = kCpuSetRecord->CpuSet.AllFlags;
                    LogicalProcessorState processor;
                    processor.coordinate.group = kCpuSetRecord->CpuSet.Group;
                    processor.coordinate.logicalIndex =
                        kCpuSetRecord->CpuSet.LogicalProcessorIndex;
                    processor.cpuSetId = kCpuSetRecord->CpuSet.Id;
                    processor.coreIndex = kCpuSetRecord->CpuSet.CoreIndex;
                    processor.efficiencyClass =
                        kCpuSetRecord->CpuSet.EfficiencyClass;
                    processor.parked =
                        (kCpuSetFlags & SYSTEM_CPU_SET_INFORMATION_PARKED) != 0U;
                    processor.allocated =
                        (kCpuSetFlags & SYSTEM_CPU_SET_INFORMATION_ALLOCATED) != 0U;
                    processor.allocatedToTargetProcess =
                        (kCpuSetFlags &
                            SYSTEM_CPU_SET_INFORMATION_ALLOCATED_TO_TARGET_PROCESS) != 0U;
                    processor.available =
                        !processor.allocated || processor.allocatedToTargetProcess;
                    processorsOut->push_back(std::move(processor));
                }
                cpuSetCursor += kCpuSetRecord->Size;
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

        // queryProcessDefaultCpuSetIds function: Read the process's default CPU Set ID list; an empty list indicates no CPU Set restriction is set.
        inline bool queryProcessDefaultCpuSetIds(
            const HANDLE processHandle,
            const CpuSetApiFunctions& functions,
            std::vector<std::uint32_t>* const cpuSetIdsOut,
            std::string* const detailTextOut)
        {
            if (processHandle == nullptr || cpuSetIdsOut == nullptr ||
                functions.getProcessDefaultCpuSets == nullptr)
            {
                return false;
            }

            ULONG requiredIdCount = 0U;
            const BOOL kSizeQueryOk = functions.getProcessDefaultCpuSets(
                processHandle,
                nullptr,
                0U,
                &requiredIdCount);
            const DWORD kSizeQueryError =
                kSizeQueryOk != FALSE ? ERROR_SUCCESS : ::GetLastError();
            if (kSizeQueryOk == FALSE &&
                kSizeQueryError != ERROR_INSUFFICIENT_BUFFER)
            {
                if (detailTextOut != nullptr)
                {
                    *detailTextOut =
                        "GetProcessDefaultCpuSets size query failed(" +
                        std::to_string(kSizeQueryError) + ")";
                }
                return false;
            }

            cpuSetIdsOut->clear();
            if (requiredIdCount == 0U)
            {
                return true;
            }

            std::vector<ULONG> nativeCpuSetIds(requiredIdCount, 0U);
            ULONG returnedIdCount = requiredIdCount;
            if (functions.getProcessDefaultCpuSets(
                    processHandle,
                    nativeCpuSetIds.data(),
                    static_cast<ULONG>(nativeCpuSetIds.size()),
                    &returnedIdCount) == FALSE)
            {
                if (detailTextOut != nullptr)
                {
                    *detailTextOut =
                        "GetProcessDefaultCpuSets failed(" +
                        std::to_string(::GetLastError()) + ")";
                }
                cpuSetIdsOut->clear();
                return false;
            }

            nativeCpuSetIds.resize(
                std::min<std::size_t>(
                    returnedIdCount,
                    nativeCpuSetIds.size()));
            cpuSetIdsOut->assign(
                nativeCpuSetIds.begin(),
                nativeCpuSetIds.end());
            std::sort(cpuSetIdsOut->begin(), cpuSetIdsOut->end());
            cpuSetIdsOut->erase(
                std::unique(cpuSetIdsOut->begin(), cpuSetIdsOut->end()),
                cpuSetIdsOut->end());
            return true;
        }

        // populateProcessorTopologyLabels:
        // - Check hybrid architecture per group and generate P/E/C labels;
        // - The final identity is appended with Gx:Ly by the UI to avoid confusion of logical indices across groups.
        inline void populateProcessorTopologyLabels(
            std::vector<LogicalProcessorState>* const processors)
        {
            if (processors == nullptr)
            {
                return;
            }

            std::map<std::uint16_t, bool> groupHasPerformanceClass;
            std::map<std::uint16_t, bool> groupHasEfficiencyClass;
            for (const LogicalProcessorState& processor : *processors)
            {
                const std::uint16_t kGroup = processor.coordinate.group;
                groupHasPerformanceClass[kGroup] =
                    groupHasPerformanceClass[kGroup] ||
                    processor.efficiencyClass > 0U;
                groupHasEfficiencyClass[kGroup] =
                    groupHasEfficiencyClass[kGroup] ||
                    processor.efficiencyClass == 0U;
            }

            using CoreKey = std::pair<std::uint16_t, std::uint16_t>;
            std::map<CoreKey, std::vector<std::size_t>> processorIndexesByCore;
            for (std::size_t processorIndex = 0U;
                 processorIndex < processors->size();
                 ++processorIndex)
            {
                const LogicalProcessorState& processor =
                    (*processors)[processorIndex];
                processorIndexesByCore[
                    CoreKey{ processor.coordinate.group, processor.coreIndex }]
                    .push_back(processorIndex);
            }

            std::map<std::uint16_t, std::size_t> performanceCoreIndexByGroup;
            std::map<std::uint16_t, std::size_t> efficiencyCoreIndexByGroup;
            std::map<std::uint16_t, std::size_t> unifiedCoreIndexByGroup;
            for (const auto& corePair : processorIndexesByCore)
            {
                const std::uint16_t kGroup = corePair.first.first;
                const std::vector<std::size_t>& logicalProcessorIndexes =
                    corePair.second;
                if (logicalProcessorIndexes.empty())
                {
                    continue;
                }

                const LogicalProcessorState& firstProcessor =
                    (*processors)[logicalProcessorIndexes.front()];
                const bool kHybridArchitecture =
                    groupHasPerformanceClass[kGroup] &&
                    groupHasEfficiencyClass[kGroup];
                const bool kPerformanceCore =
                    kHybridArchitecture && firstProcessor.efficiencyClass > 0U;
                const bool kEfficiencyCore =
                    kHybridArchitecture && firstProcessor.efficiencyClass == 0U;

                std::string corePrefix;
                std::size_t coreIndex = 0U;
                if (kPerformanceCore)
                {
                    corePrefix = "P";
                    coreIndex = performanceCoreIndexByGroup[kGroup]++;
                }
                else if (kEfficiencyCore)
                {
                    corePrefix = "E";
                    coreIndex = efficiencyCoreIndexByGroup[kGroup];
                    efficiencyCoreIndexByGroup[kGroup] +=
                        logicalProcessorIndexes.size();
                }
                else
                {
                    corePrefix = "C";
                    coreIndex = unifiedCoreIndexByGroup[kGroup]++;
                }

                for (std::size_t threadIndex = 0U;
                     threadIndex < logicalProcessorIndexes.size();
                     ++threadIndex)
                {
                    LogicalProcessorState& processor =
                        (*processors)[logicalProcessorIndexes[threadIndex]];
                    const std::size_t kDisplayedCoreIndex =
                        kEfficiencyCore ? coreIndex + threadIndex : coreIndex;
                    processor.topologyLabel =
                        corePrefix + std::to_string(kDisplayedCoreIndex);
                    if (!kEfficiencyCore && logicalProcessorIndexes.size() > 1U)
                    {
                        processor.topologyLabel +=
                            "T" + std::to_string(threadIndex);
                    }
                }
            }
        }

        // queryCpuSetProcessAffinity purpose: Query cross-node topology and the process's current default selection using Windows 10 CPU Sets.
        inline bool queryCpuSetProcessAffinity(
            const HANDLE processHandle,
            const CpuSetApiFunctions& functions,
            ProcessAffinitySnapshot* const snapshotOut,
            std::string* const detailTextOut)
        {
            std::vector<LogicalProcessorState> processors;
            if (!querySystemCpuSetStates(
                    processHandle,
                    functions,
                    &processors,
                    detailTextOut))
            {
                return false;
            }

            std::vector<std::uint32_t> defaultCpuSetIds;
            if (!queryProcessDefaultCpuSetIds(
                    processHandle,
                    functions,
                    &defaultCpuSetIds,
                    detailTextOut))
            {
                return false;
            }
            const std::set<std::uint32_t> kSelectedCpuSetIds(
                defaultCpuSetIds.begin(),
                defaultCpuSetIds.end());

            // legacyConstraintAvailable: The single-group legacy affinity still intersects with the CPU Set selection; the UI must reflect the actual constraints.
            USHORT legacyProcessorGroup = 0U;
            ULONG_PTR legacyProcessMask = 0U;
            ULONG_PTR legacySystemMask = 0U;
            const bool kSingleProcessGroup = querySingleProcessGroup(
                processHandle,
                &legacyProcessorGroup);
            const bool kLegacyMaskReadable = kSingleProcessGroup &&
                ::GetProcessAffinityMask(
                    processHandle,
                    &legacyProcessMask,
                    &legacySystemMask) != FALSE;
            const bool kLegacyConstraintAvailable =
                kLegacyMaskReadable &&
                (::GetActiveProcessorGroupCount() > 1U ||
                    legacyProcessMask != legacySystemMask);

            for (LogicalProcessorState& processor : processors)
            {
                const bool kSelectedByCpuSet =
                    defaultCpuSetIds.empty() ||
                    kSelectedCpuSetIds.find(processor.cpuSetId) !=
                        kSelectedCpuSetIds.end();
                const bool kSelectedByLegacyConstraint =
                    processorCoordinateAllowedByLegacyAffinity(
                        processor.coordinate,
                        kLegacyConstraintAvailable,
                        legacyProcessorGroup,
                        static_cast<std::uint64_t>(
                            legacyProcessMask));
                processor.constrainedByHardAffinity =
                    !kSelectedByLegacyConstraint;
                processor.available =
                    processor.available &&
                    kSelectedByLegacyConstraint;
                processor.selected =
                    processor.available &&
                    kSelectedByCpuSet;
            }
            populateProcessorTopologyLabels(&processors);

            snapshotOut->processors = std::move(processors);
            snapshotOut->usesCpuSets = true;
            snapshotOut->unrestricted =
                defaultCpuSetIds.empty() && !kLegacyConstraintAvailable;
            return true;
        }

        // queryLegacyProcessAffinity: Provides a single-group compatibility path when CPU Sets API is unavailable.
        inline bool queryLegacyProcessAffinity(
            const DWORD processId,
            ProcessAffinitySnapshot* const snapshotOut,
            std::string* const detailTextOut)
        {
            HANDLE processHandle = ::OpenProcess(
                PROCESS_QUERY_INFORMATION,
                FALSE,
                processId);
            if (processHandle == nullptr)
            {
                if (detailTextOut != nullptr)
                {
                    *detailTextOut =
                        "OpenProcess(PROCESS_QUERY_INFORMATION) failed(" +
                        std::to_string(::GetLastError()) + ")";
                }
                return false;
            }

            USHORT processorGroup = 0U;
            ULONG_PTR processMask = 0U;
            ULONG_PTR systemMask = 0U;
            const bool kGroupOk =
                querySingleProcessGroup(processHandle, &processorGroup);
            const BOOL kMaskOk = kGroupOk
                ? ::GetProcessAffinityMask(
                    processHandle,
                    &processMask,
                    &systemMask)
                : FALSE;
            const DWORD kErrorCode =
                kMaskOk != FALSE ? ERROR_SUCCESS : ::GetLastError();
            closeProcessHandle(&processHandle);
            if (!kGroupOk || kMaskOk == FALSE || systemMask == 0U)
            {
                if (detailTextOut != nullptr)
                {
                    *detailTextOut = !kGroupOk
                        ? "CPU Set APIs are unavailable and the process spans multiple processor groups"
                        : "GetProcessAffinityMask failed(" +
                            std::to_string(kErrorCode) + ")";
                }
                return false;
            }

            ProcessAffinitySnapshot snapshot;
            snapshot.usesCpuSets = false;
            snapshot.unrestricted = processMask == systemMask;
            for (std::uint16_t logicalIndex = 0U;
                 logicalIndex < static_cast<std::uint16_t>(sizeof(ULONG_PTR) * 8U);
                 ++logicalIndex)
            {
                const ULONG_PTR kProcessorBit =
                    static_cast<ULONG_PTR>(1ULL) << logicalIndex;
                if ((systemMask & kProcessorBit) == 0U)
                {
                    continue;
                }

                LogicalProcessorState processor;
                processor.coordinate = LogicalProcessorCoordinate{
                    processorGroup,
                    logicalIndex
                };
                processor.cpuSetId = logicalIndex;
                processor.coreIndex = logicalIndex;
                processor.available = true;
                processor.selected = (processMask & kProcessorBit) != 0U;
                processor.topologyLabel = "C" + std::to_string(logicalIndex);
                snapshot.processors.push_back(std::move(processor));
            }
            *snapshotOut = std::move(snapshot);
            return true;
        }

        // setLegacyProcessAffinity: Applies the conversion of a single-group stable coordinate back to ULONG_PTR on legacy systems.
        inline bool setLegacyProcessAffinity(
            const DWORD processId,
            const ProcessAffinityRule& rule,
            std::string* const detailTextOut)
        {
            HANDLE processHandle = ::OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION,
                FALSE,
                processId);
            if (processHandle == nullptr)
            {
                if (detailTextOut != nullptr)
                {
                    *detailTextOut =
                        "OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_SET_INFORMATION) failed(" +
                        std::to_string(::GetLastError()) + ")";
                }
                return false;
            }

            USHORT processorGroup = 0U;
            ULONG_PTR currentMask = 0U;
            ULONG_PTR systemMask = 0U;
            if (!querySingleProcessGroup(processHandle, &processorGroup) ||
                ::GetProcessAffinityMask(
                    processHandle,
                    &currentMask,
                    &systemMask) == FALSE)
            {
                const DWORD kErrorCode = ::GetLastError();
                closeProcessHandle(&processHandle);
                if (detailTextOut != nullptr)
                {
                    *detailTextOut =
                        "legacy process affinity query failed(" +
                        std::to_string(kErrorCode) + ")";
                }
                return false;
            }

            ULONG_PTR requestedMask = rule.selectAllAvailable
                ? systemMask
                : 0U;
            if (!rule.selectAllAvailable)
            {
                for (const LogicalProcessorCoordinate& coordinate :
                     rule.processors)
                {
                    if (coordinate.group != processorGroup ||
                        coordinate.logicalIndex >=
                            static_cast<std::uint16_t>(sizeof(ULONG_PTR) * 8U))
                    {
                        closeProcessHandle(&processHandle);
                        if (detailTextOut != nullptr)
                        {
                            *detailTextOut =
                                "CPU Set APIs are unavailable for the requested processor group";
                        }
                        return false;
                    }
                    requestedMask |=
                        static_cast<ULONG_PTR>(1ULL) <<
                        coordinate.logicalIndex;
                }
                requestedMask &= systemMask;
            }
            if (requestedMask == 0U)
            {
                closeProcessHandle(&processHandle);
                if (detailTextOut != nullptr)
                {
                    *detailTextOut =
                        "requested affinity has no available logical processor";
                }
                return false;
            }

            const BOOL kSetOk = currentMask == requestedMask
                ? TRUE
                : ::SetProcessAffinityMask(processHandle, requestedMask);
            const DWORD kErrorCode =
                kSetOk != FALSE ? ERROR_SUCCESS : ::GetLastError();
            closeProcessHandle(&processHandle);
            if (kSetOk == FALSE)
            {
                if (detailTextOut != nullptr)
                {
                    *detailTextOut =
                        "SetProcessAffinityMask failed(" +
                        std::to_string(kErrorCode) + ")";
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

    // queryProcessAffinityState:
    // - Prioritize returning CPU Set topology and current selection for all processor groups.
    // - Fallback to legacy mask API on a single group target only when CPU Sets are unavailable.
    inline bool queryProcessAffinityState(
        const DWORD processId,
        ProcessAffinitySnapshot* const snapshotOut,
        std::string* const detailTextOut)
    {
        if (processId == 0U || snapshotOut == nullptr)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "invalid process affinity query input";
            }
            return false;
        }
        *snapshotOut = ProcessAffinitySnapshot{};

        const affinity_detail::CpuSetApiFunctions& functions =
            affinity_detail::cpuSetApiFunctions();
        if (functions.getSystemCpuSetInformation != nullptr &&
            functions.getProcessDefaultCpuSets != nullptr)
        {
            HANDLE processHandle = ::OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                FALSE,
                processId);
            if (processHandle != nullptr)
            {
                const bool kQueryOk =
                    affinity_detail::queryCpuSetProcessAffinity(
                        processHandle,
                        functions,
                        snapshotOut,
                        detailTextOut);
                affinity_detail::closeProcessHandle(&processHandle);
                if (kQueryOk)
                {
                    if (detailTextOut != nullptr)
                    {
                        detailTextOut->clear();
                    }
                    return true;
                }
            }
        }
        return affinity_detail::queryLegacyProcessAffinity(
            processId,
            snapshotOut,
            detailTextOut);
    }

    // setProcessAffinityRuleByPid:
    // - Map stable group/index rules to the CPU Set IDs for this startup and apply them.
    // - selectAllAvailable clears the default CPU Set allocation; older systems fall back to a single group mask.
    inline bool setProcessAffinityRuleByPid(
        const DWORD processId,
        const ProcessAffinityRule& rule,
        std::string* const detailTextOut)
    {
        if (processId == 0U ||
            (!rule.selectAllAvailable && rule.processors.empty()))
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "invalid process affinity update input";
            }
            return false;
        }

        const affinity_detail::CpuSetApiFunctions& functions =
            affinity_detail::cpuSetApiFunctions();
        if (functions.getSystemCpuSetInformation == nullptr ||
            functions.getProcessDefaultCpuSets == nullptr ||
            functions.setProcessDefaultCpuSets == nullptr)
        {
            return affinity_detail::setLegacyProcessAffinity(
                processId,
                rule,
                detailTextOut);
        }

        HANDLE processHandle = ::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION |
                PROCESS_SET_LIMITED_INFORMATION,
            FALSE,
            processId);
        if (processHandle == nullptr)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut =
                    "OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_SET_LIMITED_INFORMATION) failed(" +
                    std::to_string(::GetLastError()) + ")";
            }
            return false;
        }

        std::vector<LogicalProcessorState> currentTopology;
        if (!affinity_detail::querySystemCpuSetStates(
                processHandle,
                functions,
                &currentTopology,
                detailTextOut))
        {
            affinity_detail::closeProcessHandle(&processHandle);
            return false;
        }

        std::vector<std::uint32_t> cpuSetIds;
        std::vector<LogicalProcessorCoordinate> missingCoordinates;
        if (!remapAffinityRuleToCpuSetIds(
                rule,
                currentTopology,
                &cpuSetIds,
                &missingCoordinates))
        {
            affinity_detail::closeProcessHandle(&processHandle);
            if (detailTextOut != nullptr)
            {
                *detailTextOut =
                    "saved affinity has no logical processor in the current topology";
            }
            return false;
        }
        if (!missingCoordinates.empty())
        {
            affinity_detail::closeProcessHandle(&processHandle);
            if (detailTextOut != nullptr)
            {
                *detailTextOut =
                    "requested affinity topology changed; refusing partial apply because " +
                    std::to_string(missingCoordinates.size()) +
                    " processor coordinate(s) are unavailable";
            }
            return false;
        }

        // previousCpuSetIds is used to restore the default CPU set selection prior to the call if write-back verification fails.
        std::vector<std::uint32_t> previousCpuSetIds;
        if (!affinity_detail::queryProcessDefaultCpuSetIds(
                processHandle,
                functions,
                &previousCpuSetIds,
                detailTextOut))
        {
            affinity_detail::closeProcessHandle(&processHandle);
            return false;
        }

        const std::vector<ULONG> kNativeCpuSetIds(
            cpuSetIds.begin(),
            cpuSetIds.end());
        const ULONG* cpuSetIdData = rule.selectAllAvailable
            ? nullptr
            : kNativeCpuSetIds.data();
        const ULONG kCpuSetIdCount = rule.selectAllAvailable
            ? 0U
            : static_cast<ULONG>(cpuSetIds.size());
        const BOOL kSetOk = functions.setProcessDefaultCpuSets(
            processHandle,
            cpuSetIdData,
            kCpuSetIdCount);
        const DWORD kErrorCode =
            kSetOk != FALSE ? ERROR_SUCCESS : ::GetLastError();
        if (kSetOk == FALSE)
        {
            affinity_detail::closeProcessHandle(&processHandle);
            if (detailTextOut != nullptr)
            {
                *detailTextOut =
                    "SetProcessDefaultCpuSets failed(" +
                    std::to_string(kErrorCode) + ")";
            }
            return false;
        }

        // Computes the intersection of the CPU Set with existing thread/process group affinity and Job constraints. Must re-read
        // and verify; cannot report 'API returned success but requested coordinates are unschedulable' as a complete success.
        std::string verificationDetailText;
        bool verificationQueryOk = false;
        bool verificationMatches = false;
        if (rule.selectAllAvailable)
        {
            std::vector<std::uint32_t> verifiedDefaultCpuSetIds;
            verificationQueryOk =
                affinity_detail::queryProcessDefaultCpuSetIds(
                    processHandle,
                    functions,
                    &verifiedDefaultCpuSetIds,
                    &verificationDetailText);
            verificationMatches =
                verificationQueryOk &&
                selectAllCpuSetSelectionMatches(
                    rule,
                    verifiedDefaultCpuSetIds);
        }
        else
        {
            ProcessAffinitySnapshot verifiedSnapshot;
            verificationQueryOk =
                affinity_detail::queryCpuSetProcessAffinity(
                    processHandle,
                    functions,
                    &verifiedSnapshot,
                    &verificationDetailText);
            verificationMatches = verificationQueryOk;
            std::vector<LogicalProcessorCoordinate> requestedCoordinates =
                rule.processors;
            std::vector<LogicalProcessorCoordinate> selectedCoordinates;
            normalizeLogicalProcessorCoordinates(&requestedCoordinates);
            for (const LogicalProcessorState& processor :
                 verifiedSnapshot.processors)
            {
                if (processor.available && processor.selected)
                {
                    selectedCoordinates.push_back(processor.coordinate);
                }
            }
            normalizeLogicalProcessorCoordinates(&selectedCoordinates);
            verificationMatches = verificationMatches &&
                requestedCoordinates == selectedCoordinates;
        }
        if (!verificationMatches)
        {
            const std::vector<ULONG> kNativePreviousCpuSetIds(
                previousCpuSetIds.begin(),
                previousCpuSetIds.end());
            const BOOL kRollbackOk = functions.setProcessDefaultCpuSets(
                processHandle,
                kNativePreviousCpuSetIds.empty()
                    ? nullptr
                    : kNativePreviousCpuSetIds.data(),
                static_cast<ULONG>(kNativePreviousCpuSetIds.size()));
            const DWORD kRollbackError =
                kRollbackOk != FALSE ? ERROR_SUCCESS : ::GetLastError();
            affinity_detail::closeProcessHandle(&processHandle);
            if (detailTextOut != nullptr)
            {
                const std::string kRollbackText = kRollbackOk != FALSE
                    ? "succeeded"
                    : "failed(" +
                        std::to_string(kRollbackError) + ")";
                *detailTextOut =
                    verificationQueryOk
                        ? (rule.selectAllAvailable
                            ? "CPU Set verification did not confirm an empty process default CPU Set list; rollback " +
                                kRollbackText
                            : "CPU Set verification did not match the requested group/index coordinates; existing thread/process group or Job constraints may intersect; rollback " +
                                kRollbackText)
                        : "CPU Set verification query failed(" +
                            verificationDetailText +
                            "); rollback " +
                            kRollbackText;
            }
            return false;
        }
        affinity_detail::closeProcessHandle(&processHandle);

        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }
        return true;
    }

    // processorIdentityText: Generates a stable 'Gx:Ly' processor identity suitable for both logging and UI.
    inline std::string processorIdentityText(
        const LogicalProcessorCoordinate& coordinate)
    {
        return "G" + std::to_string(coordinate.group) +
            ":L" + std::to_string(coordinate.logicalIndex);
    }
}
