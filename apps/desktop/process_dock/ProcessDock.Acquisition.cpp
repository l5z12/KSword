#include "ProcessDock.Support.h"
#include "ProcessActivityChartWidget.h"
#include "ProcessActivityTimelineSlider.h"

using namespace ksword::ui::process_dock;

ProcessDock::RefreshResult ProcessDock::buildRefreshResult(
    const int strategyIndex,
    const bool detailModeEnabled,
    const bool queryKernelProcessList,
    const int staticDetailFillBudget,
    const std::uint32_t detailDemandFlags,
    const std::uint64_t refreshTicket,
    const std::unordered_map<std::string, CacheEntry>& previousCache,
    const std::unordered_map<std::string, ks::process::CounterSample>& previousCounters,
    const std::unordered_map<std::uint32_t, ProcessDock::NetworkTrafficCounters>& networkTrafficSnapshot,
    const std::uint32_t logicalCpuCount)
{
    const auto kWorkerStartTime = std::chrono::steady_clock::now();

    RefreshResult refreshResult;
    refreshResult.nextCache.clear();
    refreshResult.nextCounters.clear();
    refreshResult.selectedStrategyIndex = strategyIndex;
    refreshResult.selectedStrategy = toStrategy(strategyIndex);
    refreshResult.actualStrategy = refreshResult.selectedStrategy;
    refreshResult.detailModeEnabled = detailModeEnabled;
    refreshResult.kernelCompareEnabled = queryKernelProcessList;

    const ks::process::ProcessEnumStrategy kStrategy = toStrategy(strategyIndex);
    std::vector<ks::process::ProcessRecord> latestProcessList = ks::process::enumerateProcesses(
        kStrategy,
        &refreshResult.actualStrategy,
        detailDemandFlags & ks::process::process_detail_demand::kGpuMask);
    const std::uint64_t kSampleTick = steadyNow100ns();
    std::unordered_set<std::uint32_t> kernelOnlyPidSet;
    std::unordered_map<std::uint32_t, KernelProcessSnapshotEntry> kernelProcessByPid;

    // Optional phase: request kernel process list from R0 and append "kernel-only visible" records.
    if (queryKernelProcessList)
    {
        std::vector<KernelProcessSnapshotEntry> kernelProcessList;
        std::string kernelQueryDetailText;
        const bool kQueryKernelOk = enumerateProcessesByR0Driver(&kernelProcessList, &kernelQueryDetailText);
        refreshResult.kernelQuerySucceeded = kQueryKernelOk;
        refreshResult.kernelQueryDetailText = kernelQueryDetailText;
        refreshResult.kernelEnumeratedCount = kernelProcessList.size();

        if (kQueryKernelOk)
        {
            std::unordered_set<std::uint32_t> userPidSet;
            userPidSet.reserve(latestProcessList.size() * 2 + 1);
            kernelProcessByPid.reserve(kernelProcessList.size() * 2 + 1);
            for (const KernelProcessSnapshotEntry& kernelProcess : kernelProcessList)
            {
                kernelProcessByPid[kernelProcess.processId] = kernelProcess;
            }
            for (const ks::process::ProcessRecord& processRecord : latestProcessList)
            {
                userPidSet.insert(processRecord.pid);
            }

            for (const KernelProcessSnapshotEntry& kernelProcess : kernelProcessList)
            {
                if (userPidSet.find(kernelProcess.processId) != userPidSet.end())
                {
                    continue;
                }
                userPidSet.insert(kernelProcess.processId);

                ks::process::ProcessRecord kernelOnlyRecord{};
                kernelOnlyRecord.pid = kernelProcess.processId;
                kernelOnlyRecord.parentPid = kernelProcess.parentProcessId;
                mergeKernelProcessExtension(kernelOnlyRecord, kernelProcess);
                // Weak evidence is categorized into two types; both descriptions must explicitly state 'possible false positive'.
                // - TERMINATING_OR_EXITED: EPROCESS has exited but is still referenced by a handle; after being removed from
                //   the active list, it remains in PspCidTable, mostly as remnants of short-lived processes like conhost;
                // - CID_TABLE_REFERENCE_FAILED: The CID slot resolved the process object type, but failed to acquire a reference.
                // Both types are retained for reporting (true hiding may also fall under the same criterion), with only a degraded UI hint.
                const bool kTerminatingRemnantEvidence =
                    (kernelProcess.flags & KSWORD_ARK_PROCESS_FLAG_TERMINATING_OR_EXITED) != 0U;
                const bool kCidReferenceFailedEvidence =
                    (kernelProcess.flags & KSWORD_ARK_PROCESS_FLAG_CID_TABLE_REFERENCE_FAILED) != 0U;
                const bool kCidTableWeakEvidence =
                    kTerminatingRemnantEvidence || kCidReferenceFailedEvidence;
                kernelOnlyRecord.creationTime100ns = kernelProcess.creationTime100ns != 0ULL
                    ? kernelProcess.creationTime100ns
                    : kKernelOnlyCreationTimeSeed + static_cast<std::uint64_t>(kernelProcess.processId);
                const std::string kKernelOnlyBaseName = kernelProcess.imageName.empty()
                    ? std::string("Unknown")
                    : kernelProcess.imageName;
                kernelOnlyRecord.processName = kCidTableWeakEvidence
                    ? std::string("[R0?] ") + kKernelOnlyBaseName + "（可能为误报）"
                    : std::string("[R0] ") + kKernelOnlyBaseName;
                kernelOnlyRecord.imagePath = kTerminatingRemnantEvidence
                    ? "[可能为误报：进程已退出，EPROCESS 仍被句柄引用]"
                    : (kCidReferenceFailedEvidence
                        ? "[可能为误报：CID Table命中但对象引用失败]"
                        : "[仅内核枚举可见]");
                kernelOnlyRecord.commandLine = kCidTableWeakEvidence
                    ? "[可能为误报：CID Table残留，保留显示，可尝试R0结束]"
                    : "[仅内核枚举可见]";
                kernelOnlyRecord.userName = "-";
                kernelOnlyRecord.signatureState = kCidTableWeakEvidence
                    ? "CIDTable(可能为误报)"
                    : "KernelOnly(Hidden?)";
                kernelOnlyRecord.signaturePublisher.clear();
                kernelOnlyRecord.signatureTrusted = false;
                kernelOnlyRecord.startTimeText = "-";
                kernelOnlyRecord.architectureText = "Unknown";
                kernelOnlyRecord.priorityText = "-";
                kernelOnlyRecord.isAdmin = false;
                kernelOnlyRecord.dynamicCountersReady = true;
                kernelOnlyRecord.staticDetailsReady = true;

                latestProcessList.push_back(std::move(kernelOnlyRecord));
                kernelOnlyPidSet.insert(kernelProcess.processId);
                ++refreshResult.kernelOnlyCount;
            }
        }
        else if (refreshResult.kernelQueryDetailText.empty())
        {
            refreshResult.kernelQueryDetailText = "query kernel process list failed";
        }
    }

    refreshResult.enumeratedCount = latestProcessList.size();

    // Static detail budget control:
    // - Budget limits slow operations like 'path/command line/user/signature' to avoid excessive latency during the first refresh.
    // - Monitoring mode has a lower budget, while detailed mode has a higher budget.
    const std::size_t kStaticFillBudget = static_cast<std::size_t>(std::max(0, staticDetailFillBudget));

    // Phase 1: Preprocess identities, reuse existing fields, and filter the PID list requiring static details.
    std::vector<std::string> identityKeys(latestProcessList.size());
    std::vector<bool> isNewProcess(latestProcessList.size(), false);
    std::vector<bool> shouldFillStatic(latestProcessList.size(), false);
    std::vector<bool> includeSignatureList(latestProcessList.size(), false);
    std::vector<bool> isStaticFillCandidate(latestProcessList.size(), false);
    std::vector<char> staticFillSucceeded(latestProcessList.size(), 0);

    for (std::size_t recordIndex = 0; recordIndex < latestProcessList.size(); ++recordIndex)
    {
        ks::process::ProcessRecord& processRecord = latestProcessList[recordIndex];

        // If creationTime is unavailable, 0 can still be used in the key (stable but with reduced discrimination).
        const std::string kIdentityKey = ks::process::buildProcessIdentityKey(
            processRecord.pid,
            processRecord.creationTime100ns);
        identityKeys[recordIndex] = kIdentityKey;

        const auto kOldCacheIt = previousCache.find(kIdentityKey);
        const bool kIsKernelOnlyRecord =
            (kernelOnlyPidSet.find(processRecord.pid) != kernelOnlyPidSet.end());
        bool needsStaticFill = false;
        bool includeSignatureCheck = false;
        if (kOldCacheIt != previousCache.end())
        {
            // Reuse rule: If PID and creation time match, reuse old static fields (except performance counters).
            const ks::process::ProcessRecord& oldRecord = kOldCacheIt->second.record;
            if (processRecord.imagePath.empty()) processRecord.imagePath = oldRecord.imagePath;
            if (processRecord.commandLine.empty()) processRecord.commandLine = oldRecord.commandLine;
            if (processRecord.userName.empty()) processRecord.userName = oldRecord.userName;
            if (processRecord.signatureState.empty()) processRecord.signatureState = oldRecord.signatureState;
            if (processRecord.signaturePublisher.empty()) processRecord.signaturePublisher = oldRecord.signaturePublisher;
            if (processRecord.r0FieldFlags == 0U) processRecord.r0FieldFlags = oldRecord.r0FieldFlags;
            if (processRecord.r0ImagePath.empty()) processRecord.r0ImagePath = oldRecord.r0ImagePath;
            if (processRecord.r0Status == KSWORD_ARK_PROCESS_R0_STATUS_UNAVAILABLE) processRecord.r0Status = oldRecord.r0Status;
            // PPL protection level enumeration is a manually refreshed field and cannot be inherited from the previous round's cache.
            processRecord.protectionLevelKnown = false;
            processRecord.protectionLevel = 0;
            processRecord.protectionLevelText.clear();
            /*
             * Injection surface is opposite to PPL: manually filtered but **must persist across rounds**.
             * The process table refreshes once per second; clearing it each round means this column will always be empty.
             * Cache keys by process identity; PID reuse creates a new entry, preventing old counts from carrying over to the new process.
             */
            processRecord.injectionSurfaceState = oldRecord.injectionSurfaceState;
            processRecord.injectionDynamicRegions = oldRecord.injectionDynamicRegions;
            processRecord.injectionWritableExecRegions = oldRecord.injectionWritableExecRegions;
            processRecord.injectionDynamicBytes = oldRecord.injectionDynamicBytes;
            processRecord.r0Flags = oldRecord.r0Flags;
            processRecord.r0DynDataCapabilityMask = oldRecord.r0DynDataCapabilityMask;
            processRecord.r0Protection = oldRecord.r0Protection;
            processRecord.r0SignatureLevel = oldRecord.r0SignatureLevel;
            processRecord.r0SectionSignatureLevel = oldRecord.r0SectionSignatureLevel;
            processRecord.r0SessionSource = oldRecord.r0SessionSource;
            processRecord.r0ImagePathSource = oldRecord.r0ImagePathSource;
            processRecord.r0ProtectionSource = oldRecord.r0ProtectionSource;
            processRecord.r0SignatureLevelSource = oldRecord.r0SignatureLevelSource;
            processRecord.r0SectionSignatureLevelSource = oldRecord.r0SectionSignatureLevelSource;
            processRecord.r0ObjectTableSource = oldRecord.r0ObjectTableSource;
            processRecord.r0SectionObjectSource = oldRecord.r0SectionObjectSource;
            processRecord.r0ProtectionOffset = oldRecord.r0ProtectionOffset;
            processRecord.r0SignatureLevelOffset = oldRecord.r0SignatureLevelOffset;
            processRecord.r0SectionSignatureLevelOffset = oldRecord.r0SectionSignatureLevelOffset;
            processRecord.r0ObjectTableOffset = oldRecord.r0ObjectTableOffset;
            processRecord.r0SectionObjectOffset = oldRecord.r0SectionObjectOffset;
            processRecord.r0ObjectTableAddress = oldRecord.r0ObjectTableAddress;
            processRecord.r0SectionObjectAddress = oldRecord.r0SectionObjectAddress;
            processRecord.signatureTrusted = oldRecord.signatureTrusted;
            if (processRecord.startTimeText.empty()) processRecord.startTimeText = oldRecord.startTimeText;
            processRecord.isAdmin = oldRecord.isAdmin;
            processRecord.staticDetailsReady = oldRecord.staticDetailsReady;

            // Fields in the Task Manager aligned column that remain invariant during the process lifecycle also follow the reuse
            // path, meaning they are collected only when the process first appears, incurring zero cost for subsequent refreshes.
            processRecord.inJobObject = oldRecord.inJobObject;
            processRecord.jobObjectKnown = oldRecord.jobObjectKnown;
            processRecord.uacVirtualizationState = oldRecord.uacVirtualizationState;
            processRecord.dataExecutionPreventionState = oldRecord.dataExecutionPreventionState;
            processRecord.controlFlowGuardState = oldRecord.controlFlowGuardState;
            processRecord.hardwareStackProtectionState = oldRecord.hardwareStackProtectionState;
            processRecord.dpiAwarenessLevel = oldRecord.dpiAwarenessLevel;
            processRecord.packageNameKnown = oldRecord.packageNameKnown;
            if (processRecord.packageFullName.empty()) processRecord.packageFullName = oldRecord.packageFullName;
            if (processRecord.fileDescription.empty()) processRecord.fileDescription = oldRecord.fileDescription;
            if (processRecord.osContextText.empty()) processRecord.osContextText = oldRecord.osContextText;
            if (processRecord.enterpriseContextText.empty()) processRecord.enterpriseContextText = oldRecord.enterpriseContextText;
            if (processRecord.architectureText.empty()) processRecord.architectureText = oldRecord.architectureText;

            // GUI resource counts are dynamic values: inherit old values here to avoid flickering between rounds;
            // if requested again in this round, they are immediately overwritten with the latest numbers.
            processRecord.gdiObjectCount = oldRecord.gdiObjectCount;
            processRecord.userObjectCount = oldRecord.userObjectCount;
            processRecord.guiResourceKnown = oldRecord.guiResourceKnown;
            ++refreshResult.reusedProcessCount;

            // If an old process has incomplete static fields or a pending signature, it enters the 'pending completion candidate' state.
            // Apply backoff for persistently failing processes to avoid repeatedly exhausting the budget, which would cause other processes to remain Pending for too long.
            const bool kSignaturePending = (processRecord.signatureState.empty() || processRecord.signatureState == "Pending");
            const bool kBaseNeedsStaticFill = !processRecord.staticDetailsReady || (detailModeEnabled && kSignaturePending);
            const std::uint32_t kOldFailureCount = kOldCacheIt->second.staticFillFailureCount;
            if (kBaseNeedsStaticFill && kOldFailureCount >= 3)
            {
                // Use "sparse retry" when failure count is high to reduce sustained consumption of the main budget.
                // Introduce PID offset in the formula to avoid retrying the same batch of processes in the same round.
                constexpr std::uint64_t kRetryBackoffPeriod = 8;
                const bool kShouldRetryThisRound =
                    ((refreshTicket + static_cast<std::uint64_t>(processRecord.pid)) % kRetryBackoffPeriod) == 0;
                needsStaticFill = kShouldRetryThisRound;
            }
            else
            {
                needsStaticFill = kBaseNeedsStaticFill;
            }
            includeSignatureCheck = detailModeEnabled;
        }
        else
        {
            if (kIsKernelOnlyRecord)
            {
                // Kernel-only records do not follow the 'new green' path by default to avoid conflict with red hidden highlighting.
                isNewProcess[recordIndex] = false;
                needsStaticFill = false;
                includeSignatureCheck = false;
            }
            else
            {
                // New process detected: increment count and decide whether to fill static details based on the budget.
                ++refreshResult.newProcessCount;
                isNewProcess[recordIndex] = true;
                needsStaticFill = true;
                includeSignatureCheck = detailModeEnabled;
            }
        }
        const auto kKernelProcessIt = kernelProcessByPid.find(processRecord.pid);
        if (kKernelProcessIt != kernelProcessByPid.end())
        {
            mergeKernelProcessExtension(processRecord, kKernelProcessIt->second);
        }

        if (kIsKernelOnlyRecord)
        {
            processRecord.staticDetailsReady = true;
            processRecord.dynamicCountersReady = true;
            if (processRecord.signatureState.empty())
            {
                processRecord.signatureState = "KernelOnly(Hidden?)";
            }
        }

        if (needsStaticFill)
        {
            isStaticFillCandidate[recordIndex] = true;
            includeSignatureList[recordIndex] = includeSignatureCheck;
        }
    }

    // Budget selection strategy:
    // - Collect all candidates first, then perform "round-robin selection".
    // - Avoid always selecting from the beginning to prevent processes at the tail from remaining pending for too long.
    std::vector<std::size_t> staticFillCandidateIndices;
    staticFillCandidateIndices.reserve(latestProcessList.size());
    for (std::size_t recordIndex = 0; recordIndex < isStaticFillCandidate.size(); ++recordIndex)
    {
        if (isStaticFillCandidate[recordIndex])
        {
            staticFillCandidateIndices.push_back(recordIndex);
        }
    }

    if (!staticFillCandidateIndices.empty() && kStaticFillBudget > 0)
    {
        const std::size_t kCandidateCount = staticFillCandidateIndices.size();
        const std::size_t kAllowCount = std::min(kStaticFillBudget, kCandidateCount);
        const std::size_t kRotationOffset =
            static_cast<std::size_t>(
                (refreshTicket * static_cast<std::uint64_t>(std::max(1, staticDetailFillBudget)))
                % static_cast<std::uint64_t>(kCandidateCount));
        for (std::size_t offset = 0; offset < kAllowCount; ++offset)
        {
            const std::size_t kCandidateOrder = (kRotationOffset + offset) % kCandidateCount;
            const std::size_t kSelectedIndex = staticFillCandidateIndices[kCandidateOrder];
            shouldFillStatic[kSelectedIndex] = true;
        }
    }

    // Candidates that miss the budget remain Pending to be filled in subsequent rounds.
    for (const std::size_t kRecordIndex : staticFillCandidateIndices)
    {
        if (shouldFillStatic[kRecordIndex])
        {
            continue;
        }
        ks::process::ProcessRecord& processRecord = latestProcessList[kRecordIndex];
        if (processRecord.signatureState.empty())
        {
            processRecord.signatureState = "Pending";
        }
        processRecord.signaturePublisher.clear();
        processRecord.signatureTrusted = false;
        ++refreshResult.staticDeferredCount;
    }

    // Phase 2: Parallelize slow static operations like 'path/signature/parameters' to reduce detailed view lag.
    std::vector<std::size_t> staticFillIndices;
    staticFillIndices.reserve(latestProcessList.size());
    for (std::size_t recordIndex = 0; recordIndex < shouldFillStatic.size(); ++recordIndex)
    {
        if (shouldFillStatic[recordIndex])
        {
            staticFillIndices.push_back(recordIndex);
        }
    }

    if (!staticFillIndices.empty())
    {
        // Thread count strategy:
        // - Detailed view: Use higher parallelism to accelerate signature verification.
        // - Monitor view: uses low concurrency to avoid excessive CPU usage.
        const unsigned int kHardwareThreads = std::max(1u, std::thread::hardware_concurrency());
        const unsigned int kWantedThreads = detailModeEnabled
            ? std::max(4u, std::min(12u, kHardwareThreads))
            : 2u;
        const unsigned int kWorkerCount = std::max(
            1u,
            std::min<unsigned int>(kWantedThreads, static_cast<unsigned int>(staticFillIndices.size())));

        std::atomic<std::size_t> nextTaskIndex{ 0 };
        std::vector<std::thread> workerThreads;
        workerThreads.reserve(kWorkerCount);

        // Each thread loops to fetch PID tasks and calls fillProcessStaticDetails.
        for (unsigned int workerId = 0; workerId < kWorkerCount; ++workerId)
        {
            workerThreads.emplace_back([&]() {
                for (;;)
                {
                    const std::size_t kTaskOrder = nextTaskIndex.fetch_add(1);
                    if (kTaskOrder >= staticFillIndices.size())
                    {
                        break;
                    }

                    const std::size_t kRecordIndex = staticFillIndices[kTaskOrder];
                    const bool kFillOk = ks::process::fillProcessStaticDetails(
                        latestProcessList[kRecordIndex],
                        includeSignatureList[kRecordIndex]);
                    staticFillSucceeded[kRecordIndex] = kFillOk ? 1 : 0;

                    // Failure fallback strategy:
                    // - Prevent the signature list from remaining Pending for an extended period.
                    // - Directly marks No Access for permission-restricted scenarios.
                    if (!kFillOk && includeSignatureList[kRecordIndex])
                    {
                        ks::process::ProcessRecord& processRecord = latestProcessList[kRecordIndex];
                        if (processRecord.signatureState.empty() || processRecord.signatureState == "Pending")
                        {
                            processRecord.signatureState = "No Access";
                            processRecord.signaturePublisher.clear();
                            processRecord.signatureTrusted = false;
                        }
                    }
                }
                });
        }

        for (std::thread& workerThread : workerThreads)
        {
            if (workerThread.joinable())
            {
                workerThread.join();
            }
        }
        refreshResult.staticFilledCount += staticFillIndices.size();
    }

    // Phase 2 supplement: individually and fully complete the imagePath.
    // Notes:
    // 1) Icon display depends solely on imagePath, and path lookup is lighter than 'command line/signature'.
    // 2) Not subject to static detail budget limits; ensures all enumerated processes in each round are included in background icon collection.
    std::vector<std::size_t> imagePathFillIndices;
    imagePathFillIndices.reserve(latestProcessList.size());
    for (std::size_t recordIndex = 0; recordIndex < latestProcessList.size(); ++recordIndex)
    {
        const ks::process::ProcessRecord& processRecord = latestProcessList[recordIndex];
        if (processRecord.pid == 0 || !processRecord.imagePath.empty())
        {
            continue;
        }
        imagePathFillIndices.push_back(recordIndex);
    }

    if (!imagePathFillIndices.empty())
    {
        // Independent path to complete the thread pool: execute only queryProcessPathByPid to avoid UI thread fallback queries causing lag.
        const unsigned int kHardwareThreads = std::max(1u, std::thread::hardware_concurrency());
        const unsigned int kWantedThreads = detailModeEnabled ? std::min(8u, kHardwareThreads) : std::min(4u, kHardwareThreads);
        const unsigned int kWorkerCount = std::max(
            1u,
            std::min<unsigned int>(kWantedThreads, static_cast<unsigned int>(imagePathFillIndices.size())));
        std::atomic<std::size_t> nextTaskIndex{ 0 };
        std::atomic<std::size_t> filledCount{ 0 };
        std::vector<std::thread> workerThreads;
        workerThreads.reserve(kWorkerCount);
        for (unsigned int workerId = 0; workerId < kWorkerCount; ++workerId)
        {
            workerThreads.emplace_back([&]() {
                for (;;)
                {
                    const std::size_t kTaskOrder = nextTaskIndex.fetch_add(1);
                    if (kTaskOrder >= imagePathFillIndices.size())
                    {
                        break;
                    }

                    const std::size_t kRecordIndex = imagePathFillIndices[kTaskOrder];
                    ks::process::ProcessRecord& processRecord = latestProcessList[kRecordIndex];
                    const std::string kPathText = ks::process::queryProcessPathByPid(processRecord.pid);
                    if (!kPathText.empty())
                    {
                        processRecord.imagePath = kPathText;
                        filledCount.fetch_add(1);
                    }
                }
                });
        }
        for (std::thread& workerThread : workerThreads)
        {
            if (workerThread.joinable())
            {
                workerThread.join();
            }
        }
        refreshResult.imagePathFilledCount = filledCount.load();
    }

    // Phase 2 Supplement 2: On-demand field acquisition aligned with Task Manager columns.
    // Layered Strategy:
    // - Static bits (job membership, mitigation policies, UAC virtualization, image description, OS context, enterprise context) remain
    //   unchanged during the process lifecycle; retry repeatedly until the first successful resolution, then record and permanently skip.
    // - Dynamic flags (GDI and User Object counts) must be re-read every iteration; otherwise, the values remain stuck at the initial sample.
    // - The GPU bit is covered by a single PDH sampling pass over the entire table internally by enumerateProcesses; per-process handling is not performed here.
    // This stage must occur after imagePath is resolved: both the explanation and the OS context depend on the image path.
    std::vector<std::uint32_t> onDemandResolvedFlagsByRecord(latestProcessList.size(), 0U);
    if (detailDemandFlags != ks::process::process_detail_demand::kNone)
    {
        constexpr std::uint32_t kDynamicDemandMask = ks::process::process_detail_demand::kGuiResources;
        const std::uint32_t kRequestedDynamicFlags = detailDemandFlags & kDynamicDemandMask;
        const std::uint32_t kRequestedStaticFlags =
            detailDemandFlags & ~(kDynamicDemandMask | ks::process::process_detail_demand::kGpuMask);

        std::vector<std::uint32_t> onDemandRoundFlagsByRecord(latestProcessList.size(), 0U);
        std::vector<std::size_t> onDemandIndices;
        onDemandIndices.reserve(latestProcessList.size());

        for (std::size_t recordIndex = 0; recordIndex < latestProcessList.size(); ++recordIndex)
        {
            const ks::process::ProcessRecord& processRecord = latestProcessList[recordIndex];

            const auto kOldCacheIt = previousCache.find(identityKeys[recordIndex]);
            const std::uint32_t kAlreadyResolvedFlags =
                (kOldCacheIt == previousCache.end()) ? 0U : kOldCacheIt->second.onDemandResolvedFlags;
            onDemandResolvedFlagsByRecord[recordIndex] = kAlreadyResolvedFlags;

            // PID 0 and records marked 'kernel-only visible' have no user-mode handles to open;
            // skipping them avoids wastefully executing OpenProcess for them in every iteration.
            if (processRecord.pid == 0 ||
                kernelOnlyPidSet.find(processRecord.pid) != kernelOnlyPidSet.end())
            {
                continue;
            }

            std::uint32_t pendingStaticFlags = kRequestedStaticFlags & ~kAlreadyResolvedFlags;
            if (processRecord.imagePath.empty())
            {
                // If the image path is not yet available, the manifest cannot be resolved; skip this round and wait for the next.
                pendingStaticFlags &= ~ks::process::process_detail_demand::kImageFileMask;
            }

            const std::uint32_t kRoundFlags = kRequestedDynamicFlags | pendingStaticFlags;
            if (kRoundFlags == 0U)
            {
                continue;
            }

            onDemandRoundFlagsByRecord[recordIndex] = kRoundFlags;
            onDemandIndices.push_back(recordIndex);
        }

        if (!onDemandIndices.empty())
        {
            // These queries primarily use OpenProcess plus several lightweight information classes; concurrency matches the icon path completion.
            // Since the default column layout does not trigger this phase, the cost here is incurred only after the user explicitly enables the relevant columns.
            const unsigned int kHardwareThreads = std::max(1u, std::thread::hardware_concurrency());
            const unsigned int kWantedThreads = std::min(8u, kHardwareThreads);
            const unsigned int kWorkerCount = std::max(
                1u,
                std::min<unsigned int>(kWantedThreads, static_cast<unsigned int>(onDemandIndices.size())));

            std::atomic<std::size_t> nextTaskIndex{ 0 };
            std::vector<std::thread> workerThreads;
            workerThreads.reserve(kWorkerCount);
            for (unsigned int workerId = 0; workerId < kWorkerCount; ++workerId)
            {
                workerThreads.emplace_back([&]() {
                    for (;;)
                    {
                        const std::size_t kTaskOrder = nextTaskIndex.fetch_add(1);
                        if (kTaskOrder >= onDemandIndices.size())
                        {
                            break;
                        }

                        const std::size_t kRecordIndex = onDemandIndices[kTaskOrder];
                        std::uint32_t resolvedFlags = 0U;
                        (void)ks::process::fillProcessOnDemandDetails(
                            latestProcessList[kRecordIndex],
                            onDemandRoundFlagsByRecord[kRecordIndex],
                            &resolvedFlags);

                        // Only mark static bits that are 'truly successful' as completed:
                        // Processes denied access will retry in subsequent rounds instead of permanently showing placeholders.
                        onDemandResolvedFlagsByRecord[kRecordIndex] |=
                            (resolvedFlags & ~kDynamicDemandMask);
                    }
                    });
            }
            for (std::thread& workerThread : workerThreads)
            {
                if (workerThread.joinable())
                {
                    workerThread.join();
                }
            }
        }
    }

    // Phase 3: Calculate performance deltas and write back to cache (this phase remains serial to ensure simple and stable logic).
    for (std::size_t recordIndex = 0; recordIndex < latestProcessList.size(); ++recordIndex)
    {
        ks::process::ProcessRecord& processRecord = latestProcessList[recordIndex];
        const std::string& identityKey = identityKeys[recordIndex];

        // If the current policy does not specify dynamic counters, explicitly refresh them once.
        if (!processRecord.dynamicCountersReady)
        {
            ks::process::refreshProcessDynamicCounters(processRecord);
        }

        // Calculate derived CPU/DISK counters and write to the next sample.
        ks::process::CounterSample nextSample{};
        const auto kOldCounterIt = previousCounters.find(identityKey);
        const ks::process::CounterSample* oldSample =
            (kOldCounterIt == previousCounters.end()) ? nullptr : &kOldCounterIt->second;
        ks::process::updateDerivedCounters(
            processRecord,
            oldSample,
            nextSample,
            logicalCpuCount,
            kSampleTick);

        // Network throughput calculation:
        // - Input: TCP/UDP downlink and uplink byte counts accumulated by the packet capture thread per PID;
        // - Handling: Compute difference with the previous CounterSample, then divide by the same refresh interval.
        // - Returns: Writes down/up/total KB/s to the ProcessRecord, while also saving the cumulative values for the next sample.
        const auto kNetworkCounterIt = networkTrafficSnapshot.find(processRecord.pid);
        if (kNetworkCounterIt != networkTrafficSnapshot.end())
        {
            nextSample.networkRxBytes = kNetworkCounterIt->second.rxBytes;
            nextSample.networkTxBytes = kNetworkCounterIt->second.txBytes;
        }
        if (oldSample != nullptr && kSampleTick > oldSample->sampleTick100ns)
        {
            const double kDeltaSeconds = static_cast<double>(kSampleTick - oldSample->sampleTick100ns) / 10000000.0;
            if (kDeltaSeconds > 0.0)
            {
                const std::uint64_t kDeltaRxBytes =
                    (nextSample.networkRxBytes >= oldSample->networkRxBytes)
                    ? (nextSample.networkRxBytes - oldSample->networkRxBytes)
                    : 0ULL;
                const std::uint64_t kDeltaTxBytes =
                    (nextSample.networkTxBytes >= oldSample->networkTxBytes)
                    ? (nextSample.networkTxBytes - oldSample->networkTxBytes)
                    : 0ULL;
                processRecord.netRxKBps = (static_cast<double>(kDeltaRxBytes) / kDeltaSeconds) / 1024.0;
                processRecord.netTxKBps = (static_cast<double>(kDeltaTxBytes) / kDeltaSeconds) / 1024.0;
                processRecord.netKBps = processRecord.netRxKBps + processRecord.netTxKBps;
            }
        }
        refreshResult.nextCounters[identityKey] = nextSample;

        CacheEntry cacheEntry{};
        cacheEntry.record = std::move(processRecord);
        cacheEntry.onDemandResolvedFlags = onDemandResolvedFlagsByRecord[recordIndex];
        cacheEntry.missingRounds = 0;
        cacheEntry.isNewInLatestRound = isNewProcess[recordIndex];
        cacheEntry.isExitedInLatestRound = false;
        cacheEntry.isKernelOnlyInLatestRound =
            (kernelOnlyPidSet.find(cacheEntry.record.pid) != kernelOnlyPidSet.end());
        {
            // Purpose of staticFillAttemptCount/staticFillFailureCount:
            // - Record the fill attempt history for the current identity;
            // - Used in the next round for "continuous failure backoff" to reduce long-term budget occupation by failed processes.
            const auto kOldCacheIt = previousCache.find(identityKey);
            const std::uint32_t kOldAttemptCount =
                (kOldCacheIt == previousCache.end()) ? 0U : kOldCacheIt->second.staticFillAttemptCount;
            const std::uint32_t kOldFailureCount =
                (kOldCacheIt == previousCache.end()) ? 0U : kOldCacheIt->second.staticFillFailureCount;
            const bool kAttemptedThisRound = shouldFillStatic[recordIndex];
            const bool kFillOkThisRound = (staticFillSucceeded[recordIndex] != 0);

            cacheEntry.staticFillAttemptCount = kAttemptedThisRound
                ? (kOldAttemptCount + 1U)
                : kOldAttemptCount;
            cacheEntry.staticFillFailureCount = kAttemptedThisRound
                ? (kFillOkThisRound ? 0U : (kOldFailureCount + 1U))
                : kOldFailureCount;

            // If the current record already has available static details, proactively clear the failure count.
            if (cacheEntry.record.staticDetailsReady && cacheEntry.record.signatureState != "Pending")
            {
                cacheEntry.staticFillFailureCount = 0;
            }
        }
        refreshResult.nextCache.emplace(identityKey, std::move(cacheEntry));

    }

    // Handle exited processes: if a process existed in the previous round but not in the current round, retain it with a 1-round gray background.
    for (const auto& oldPair : previousCache)
    {
        if (refreshResult.nextCache.find(oldPair.first) != refreshResult.nextCache.end())
        {
            continue;
        }

        const CacheEntry& oldEntry = oldPair.second;
        if (oldEntry.isKernelOnlyInLatestRound)
        {
            // Kernel-only records do not retain 'exit preservation' to avoid leaving a residual gray row after closing the kernel comparison.
            continue;
        }
        if (oldEntry.missingRounds >= 1)
        {
            // Already retained for one round; now permanently removed.
            continue;
        }

        CacheEntry exitedEntry = oldEntry;
        exitedEntry.missingRounds = oldEntry.missingRounds + 1;
        exitedEntry.isNewInLatestRound = false;
        exitedEntry.isExitedInLatestRound = true;
        // Do not carry over the previous round's manual PPL enumeration in exited reserved rows to avoid displaying stale protection levels in grayed-out rows.
        exitedEntry.record.protectionLevelKnown = false;
        exitedEntry.record.protectionLevel = 0;
        exitedEntry.record.protectionLevelText.clear();
        // Similarly, the exit entry no longer carries the injection surface count: since the process
        // is gone, that column's number would misleadingly imply it is still being observed.
        exitedEntry.record.injectionSurfaceState = 0U;
        exitedEntry.record.injectionDynamicRegions = 0U;
        exitedEntry.record.injectionWritableExecRegions = 0U;
        exitedEntry.record.injectionDynamicBytes = 0ULL;
        refreshResult.nextCache.emplace(oldPair.first, std::move(exitedEntry));
        ++refreshResult.exitedProcessCount;

        const auto kOldCounterIt = previousCounters.find(oldPair.first);
        if (kOldCounterIt != previousCounters.end())
        {
            refreshResult.nextCounters.emplace(oldPair.first, kOldCounterIt->second);
        }
    }

    refreshResult.workerElapsedMs = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - kWorkerStartTime).count());

    return refreshResult;
}
