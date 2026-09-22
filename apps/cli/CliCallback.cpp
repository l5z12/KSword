#include "CliSupport.h"

namespace ksword::cli
{
    // printCallbackEventPacket renders one callback wait-event response.
    // Inputs: fixed event packet and returned byte count.
    // Processing: prints rule identity, decision metadata, paths and patterns.
    // Returns: no value.
    void printCallbackEventPacket(const KSWORD_ARK_CALLBACK_EVENT_PACKET& packet, DWORD bytesReturned)
    {
        std::wcout << L"size=" << packet.size
                   << L" version=" << packet.version
                   << L" bytesReturned=" << bytesReturned
                   << L" eventGuid=" << formatGuid128(packet.eventGuid) << L"\n";
        std::wcout << L"callbackType=" << packet.callbackType
                   << L" operationType=" << packet.operationType
                   << L" action=" << packet.action
                   << L" matchMode=" << packet.matchMode
                   << L" defaultDecision=" << packet.defaultDecision
                   << L" timeoutMs=" << packet.timeoutMs
                   << L" groupId=" << packet.groupId
                   << L" ruleId=" << packet.ruleId
                   << L" pid=" << packet.originatingPid
                   << L" tid=" << packet.originatingTid
                   << L" sessionId=" << packet.sessionId
                   << L" pathUnavailable=" << packet.pathUnavailable << L"\n";
        std::wcout << L"createdAtUtc100ns=" << packet.createdAtUtc100ns
                   << L" deadlineUtc100ns=" << packet.deadlineUtc100ns << L"\n";
        dumpWideText(L"initiatorPath", fixedWide(packet.initiatorPath, KSWORD_ARK_CALLBACK_EVENT_MAX_INITIATOR_CHARS));
        dumpWideText(L"targetPath", fixedWide(packet.targetPath, KSWORD_ARK_CALLBACK_EVENT_MAX_TARGET_CHARS));
        dumpWideText(L"ruleInitiatorPattern", fixedWide(packet.ruleInitiatorPattern, KSWORD_ARK_CALLBACK_EVENT_MAX_PATTERN_CHARS));
        dumpWideText(L"ruleTargetPattern", fixedWide(packet.ruleTargetPattern, KSWORD_ARK_CALLBACK_EVENT_MAX_PATTERN_CHARS));
        dumpWideText(L"groupName", fixedWide(packet.groupName, KSWORD_ARK_CALLBACK_EVENT_MAX_NAME_CHARS));
        dumpWideText(L"ruleName", fixedWide(packet.ruleName, KSWORD_ARK_CALLBACK_EVENT_MAX_NAME_CHARS));
    }

    // queryCallbackInventory: Paginates and prints read-only callback/hook/filter evidence; never invokes removal controls.
    // Input: flags, maximum entries per page, and the upper limit for console-visible entries.
    // Handling: Continuously request based on nextIndex until the visible limit is reached or the driver explicitly returns the last page.
    // Returns: 0 on success; returns corresponding CLI error code if protocol or IOCTL fails.
    int queryCallbackInventory(const NamedArgs& args)
    {
        KSWORD_ARK_ENUM_CALLBACKS_REQUEST request{};
        request.size = sizeof(request);
        request.version = KSWORD_ARK_CALLBACK_ENUM_PROTOCOL_VERSION;
        request.flags = getOptionU32(args, L"--flags", KSWORD_ARK_ENUM_CALLBACK_FLAG_INCLUDE_ALL);
        request.maxEntries = getOptionU32(args, L"--max-entries", 512U);
        const std::size_t kVisibleLimit = getOptionU32(args, L"--limit", 128U);
        std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
        constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_ENUM_CALLBACKS_RESPONSE) - sizeof(KSWORD_ARK_CALLBACK_ENUM_ENTRY);
        std::size_t printedCount = 0U;
        std::uint32_t pageCount = 0U;
        std::uint32_t startIndex = 0U;
        std::uint64_t snapshotHash = 0U;
        std::uint32_t snapshotTotalCount = 0U;

        while (printedCount < kVisibleLimit)
        {
            IoctlResult io{};
            std::fill(buffer.begin(), buffer.end(), 0U);
            request.startIndex = startIndex;
            request.expectedSnapshotHash = snapshotHash;
            request.expectedTotalCount = snapshotTotalCount;
            request.snapshotPolicy = snapshotHash == 0U
                ? KSWORD_ARK_CALLBACK_SNAPSHOT_POLICY_NONE
                : KSWORD_ARK_CALLBACK_SNAPSHOT_POLICY_REQUIRE_MATCH;

            const int kRc = sendRawIoctl(
                L"IOCTL_KSWORD_ARK_ENUM_CALLBACKS",
                IOCTL_KSWORD_ARK_ENUM_CALLBACKS,
                &request,
                sizeof(request),
                buffer,
                io);
            if (kRc != 0)
            {
                return normalizeIoctlRc(L"callback inventory", io, kRc);
            }

            const auto* response = reinterpret_cast<const KSWORD_ARK_ENUM_CALLBACKS_RESPONSE*>(buffer.data());
            if ((response->flags & KSWORD_ARK_ENUM_CALLBACK_RESPONSE_FLAG_SNAPSHOT_CHANGED) != 0UL)
            {
                std::wcerr << L"error: callback inventory changed during pagination; rerun the command\n";
                return 4;
            }
            if ((response->flags & KSWORD_ARK_ENUM_CALLBACK_RESPONSE_FLAG_SNAPSHOT_HASH_VALID) == 0UL ||
                response->snapshotHash == 0ULL)
            {
                std::wcerr << L"error: callback enum v3 response omitted snapshot metadata\n";
                return 4;
            }
            if (snapshotHash == 0U)
            {
                snapshotHash = response->snapshotHash;
                snapshotTotalCount = response->totalCount;
            }
            else if (snapshotHash != response->snapshotHash ||
                snapshotTotalCount != response->totalCount)
            {
                std::wcerr << L"error: callback inventory snapshot metadata is inconsistent\n";
                return 4;
            }
            std::size_t available = 0U;
            try
            {
                available = validateVariable(
                    io.bytesReturned,
                    kHeaderSize,
                    response->entrySize,
                    sizeof(KSWORD_ARK_CALLBACK_ENUM_ENTRY),
                    L"callback enum");
            }
            catch (...)
            {
                return 4;
            }

            if (pageCount == 0U)
            {
                printResponseBanner(response->version, response->flags, response->lastStatus, io.bytesReturned);
                printCountHeader(
                    response->version,
                    response->totalCount,
                    response->returnedCount,
                    response->entrySize,
                    io.bytesReturned);
                std::wcout << L"snapshotGeneration=" << hex64(response->enumerationGeneration)
                           << L" snapshotHash=" << hex64(response->snapshotHash)
                           << L" snapshotHashValid=1 identityHashValid="
                           << (((response->flags & KSWORD_ARK_ENUM_CALLBACK_RESPONSE_FLAG_IDENTITY_HASH_VALID) != 0UL) ? 1 : 0)
                           << L"\n";
            }

            const std::size_t kRemainingVisible = kVisibleLimit - printedCount;
            const std::size_t kParsed = responseCountLimit(
                response->returnedCount,
                available,
                kRemainingVisible);
            for (std::size_t i = 0U; i < kParsed; ++i)
            {
                const auto* entry = reinterpret_cast<const KSWORD_ARK_CALLBACK_ENUM_ENTRY*>(
                    buffer.data() + kHeaderSize + (i * response->entrySize));
                std::wcout << L"  [" << (static_cast<std::size_t>(startIndex) + i)
                           << L"] class=" << entry->callbackClass
                           << L" registrationType=" << entry->registrationType
                           << L" source=" << entry->source
                           << L" status=" << entry->status
                           << L" fields=0x" << std::hex << entry->fieldFlags
                           << L" callback=" << hex64(entry->callbackAddress)
                           << L" context=" << hex64(entry->contextAddress)
                           << L" registration=" << hex64(entry->registrationAddress)
                           << L" rawStorage=" << hex64(entry->rawStorageValue)
                           << L" generation=" << hex64(entry->enumerationGeneration)
                           << L" identityHash=" << hex64(entry->identityHash)
                           << L" moduleBase=" << hex64(entry->moduleBase)
                           << std::dec << L" operationMask=0x" << std::hex << entry->operationMask
                           << L" objectTypeMask=0x" << entry->objectTypeMask
                           << std::dec << L" name='" << fixedWide(entry->name, KSWORD_ARK_CALLBACK_ENUM_NAME_CHARS)
                           << L"' altitude='" << fixedWide(entry->altitude, KSWORD_ARK_CALLBACK_ENUM_ALTITUDE_CHARS)
                           << L"' detail='" << fixedWide(entry->detail, KSWORD_ARK_CALLBACK_ENUM_DETAIL_CHARS) << L"'\n";
            }
            printedCount += kParsed;
            ++pageCount;

            const bool kHasMore = (response->flags & KSWORD_ARK_ENUM_CALLBACK_RESPONSE_FLAG_MORE_DATA) != 0UL;
            if (!kHasMore || printedCount >= kVisibleLimit)
            {
                break;
            }
            if (response->returnedCount == 0UL || response->nextIndex <= startIndex || pageCount >= 128U)
            {
                std::wcerr << L"error: callback enum pagination did not make forward progress\n";
                return 4;
            }
            startIndex = response->nextIndex;
        }
        std::wcout << L"pages=" << pageCount
                   << L" snapshotHash=" << hex64(snapshotHash)
                   << L" rowsPrinted=" << printedCount << L"\n";
        return 0;
    }

    // commandCallbackFamily implements callback rule/control IOCTLs.
    // Inputs: argc/argv from wmain.
    // Processing: handles blob rule loading, event wait/answer and external callback removal.
    // Returns: process exit code.
    int commandCallbackFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: callback requires a subcommand\n"; return 1; }
        const std::wstring kSub = argv[2];
        if (kSub == L"monitor-start" || kSub == L"monitor-stop" ||
            kSub == L"monitor-status" || kSub == L"monitor-read")
        {
            return commandArkDriverCallbackMonitor(argc, argv);
        }
        const NamedArgs kArgs = parseNamedArgs(argc, argv, 3);
        IoctlResult io{};

        if (kSub == L"set-rules")
        {
            std::vector<std::uint8_t> blob = readRequiredBlobOption(kArgs, L"--blob", kMaxCommandBytes);
            return runNoOutputIoctl(L"IOCTL_KSWORD_ARK_SET_CALLBACK_RULES", IOCTL_KSWORD_ARK_SET_CALLBACK_RULES, blob.data(), checkedDwordSize(blob.size()), GENERIC_READ | GENERIC_WRITE);
        }
        if (kSub == L"runtime-state")
        {
            KSWORD_ARK_CALLBACK_RUNTIME_STATE response{};
            if (!sendFixedNoInput(IOCTL_KSWORD_ARK_GET_CALLBACK_RUNTIME_STATE, L"IOCTL_KSWORD_ARK_GET_CALLBACK_RUNTIME_STATE", response, io)) return 3;
            printResponseBanner(response.version, response.driverOnline, 0, io.bytesReturned);
            std::wcout << L"size=" << response.size
                       << L" callbacksRegisteredMask=0x" << std::hex << response.callbacksRegisteredMask
                       << std::dec << L" globalEnabled=" << response.globalEnabled
                       << L" rulesApplied=" << response.rulesApplied
                       << L" groupCount=" << response.groupCount
                       << L" ruleCount=" << response.ruleCount
                       << L" pendingDecisionCount=" << response.pendingDecisionCount
                       << L" waitingReceiverCount=" << response.waitingReceiverCount
                       << L" appliedRuleVersion=" << response.appliedRuleVersion
                       << L" appliedAtUtc100ns=" << response.appliedAtUtc100ns << L"\n";
            // During degraded startup, the original NTSTATUS for each callback type; 0 indicates successful registration.
            std::wcout << std::hex
                       << L"waitQueueStatus=0x" << static_cast<std::uint32_t>(response.waitQueueStatus)
                       << L" registryCallbackStatus=0x" << static_cast<std::uint32_t>(response.registryCallbackStatus)
                       << L" processCallbackStatus=0x" << static_cast<std::uint32_t>(response.processCallbackStatus)
                       << L" threadCallbackStatus=0x" << static_cast<std::uint32_t>(response.threadCallbackStatus)
                       << L" imageCallbackStatus=0x" << static_cast<std::uint32_t>(response.imageCallbackStatus)
                       << L" objectCallbackStatus=0x" << static_cast<std::uint32_t>(response.objectCallbackStatus)
                       << std::dec << L"\n";
            return 0;
        }
        if (kSub == L"wait-event")
        {
            KSWORD_ARK_CALLBACK_WAIT_REQUEST request{};
            request.size = sizeof(request);
            request.version = KSWORD_ARK_CALLBACK_PROTOCOL_VERSION;
            request.waiterTag = getOptionU32(kArgs, L"--waiter-tag", 0U);
            KSWORD_ARK_CALLBACK_EVENT_PACKET response{};
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_WAIT_CALLBACK_EVENT, L"IOCTL_KSWORD_ARK_WAIT_CALLBACK_EVENT", request, response, io)) return 3;
            printCallbackEventPacket(response, io.bytesReturned);
            return 0;
        }
        if (kSub == L"answer-event")
        {
            KSWORD_ARK_CALLBACK_ANSWER_REQUEST request{};
            request.size = sizeof(request);
            request.version = KSWORD_ARK_CALLBACK_PROTOCOL_VERSION;
            request.eventGuid = parseGuid128(requireOptionText(kArgs, L"--event-guid"));
            request.decision = requireOptionU32(kArgs, L"--decision");
            request.sourceSessionId = requireOptionU32(kArgs, L"--source-session-id");
            request.answeredAtUtc100ns = getOptionU64(kArgs, L"--answered-at", currentUtc100ns());
            return runNoOutputIoctl(L"IOCTL_KSWORD_ARK_ANSWER_CALLBACK_EVENT", IOCTL_KSWORD_ARK_ANSWER_CALLBACK_EVENT, &request, sizeof(request));
        }
        if (kSub == L"cancel-pending")
        {
            return runNoOutputIoctl(L"IOCTL_KSWORD_ARK_CANCEL_ALL_PENDING_DECISIONS", IOCTL_KSWORD_ARK_CANCEL_ALL_PENDING_DECISIONS, nullptr, 0U);
        }
        if (kSub == L"remove")
        {
            KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_REQUEST request{};
            KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_RESPONSE response{};
            request.size = sizeof(request);
            request.version = KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_PROTOCOL_VERSION;
            request.callbackClass = requireOptionU32(kArgs, L"--class");
            request.flags = getOptionU32(kArgs, L"--flags", 0U);
            request.callbackAddress = requireOptionU64(kArgs, L"--callback");
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK, L"IOCTL_KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK", request, response, io, GENERIC_READ | GENERIC_WRITE)) return 3;
            printResponseBanner(response.version, response.callbackClass, response.ntstatus, io.bytesReturned);
            std::wcout << L"size=" << response.size
                       << L" callback=" << hex64(response.callbackAddress)
                       << L" moduleBase=" << hex64(response.moduleBase)
                       << L" moduleSize=" << response.moduleSize
                       << L" mappingFlags=0x" << std::hex << response.mappingFlags << std::dec << L"\n";
            dumpWideText(L"modulePath", fixedWide(response.modulePath, KSWORD_ARK_EXTERNAL_CALLBACK_MODULE_NAME_MAX_CHARS));
            dumpWideText(L"serviceName", fixedWide(response.serviceName, KSWORD_ARK_EXTERNAL_CALLBACK_SERVICE_NAME_MAX_CHARS));
            return 0;
        }
        if (kSub == L"remove-ex")
        {
            KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_REQUEST request{};
            KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_RESPONSE response{};
            request.size = sizeof(request);
            request.version = KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_PROTOCOL_VERSION;
            request.callbackClass = requireOptionU32(kArgs, L"--class");
            request.flags = getOptionU32(kArgs, L"--flags", 0U);
            request.callbackAddress = requireOptionU64(kArgs, L"--callback");
            request.registrationAddress = getOptionU64(kArgs, L"--registration", 0ULL);
            request.rawStorageValue = getOptionU64(kArgs, L"--raw-storage", 0ULL);
            request.enumerationGeneration = getOptionU64(kArgs, L"--generation", 0ULL);
            request.identityHash = getOptionU64(kArgs, L"--identity-hash", 0ULL);
            request.source = getOptionU32(kArgs, L"--source", 0U);
            request.operationMask = getOptionU32(kArgs, L"--operation-mask", 0U);
            request.objectTypeMask = getOptionU32(kArgs, L"--object-type-mask", 0U);
            request.trustFlags = getOptionU32(kArgs, L"--trust-flags", 0U);
            request.removeBehavior = getOptionU32(kArgs, L"--remove-behavior", 0U);
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX, L"IOCTL_KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX", request, response, io, GENERIC_READ | GENERIC_WRITE)) return 3;
            printResponseBanner(response.version, response.callbackClass, response.ntstatus, io.bytesReturned);
            std::wcout << L"size=" << response.size
                       << L" source=" << response.source
                       << L" callback=" << hex64(response.callbackAddress)
                       << L" registration=" << hex64(response.registrationAddress)
                       << L" rawStorage=" << hex64(response.rawStorageValue)
                       << L" generation=" << response.enumerationGeneration
                       << L" identityHash=" << hex64(response.identityHash)
                       << L" revalidationStatus=0x" << std::hex << static_cast<unsigned long>(response.revalidationStatus)
                       << L" trustFlags=0x" << response.trustFlags
                       << L" removeBehavior=0x" << response.removeBehavior
                       << L" mappingFlags=0x" << response.mappingFlags
                       << L" moduleBase=" << hex64(response.moduleBase)
                       << std::dec << L" moduleSize=" << response.moduleSize << L"\n";
            dumpWideText(L"modulePath", fixedWide(response.modulePath, KSWORD_ARK_EXTERNAL_CALLBACK_MODULE_NAME_MAX_CHARS));
            dumpWideText(L"serviceName", fixedWide(response.serviceName, KSWORD_ARK_EXTERNAL_CALLBACK_SERVICE_NAME_MAX_CHARS));
            dumpWideText(L"message", fixedWide(response.message, KSWORD_ARK_CALLBACK_ENUM_DETAIL_CHARS));
            return 0;
        }
        if (kSub == L"set-minifilter-bypass-pids")
        {
            const std::vector<std::uint32_t> kProcessIds = parsePidListText(requireOptionText(kArgs, L"--pids"));
            KSWORD_ARK_MINIFILTER_BYPASS_PID_REQUEST request{};
            request.size = sizeof(request);
            request.version = KSWORD_ARK_CALLBACK_PROTOCOL_VERSION;
            request.flags = getOptionU32(kArgs, L"--flags", 0U);
            request.pidCount = static_cast<unsigned long>(kProcessIds.size());
            for (std::size_t index = 0U; index < kProcessIds.size(); ++index)
            {
                request.processIds[index] = static_cast<unsigned long>(kProcessIds[index]);
            }
            return runNoOutputIoctl(
                L"IOCTL_KSWORD_ARK_SET_MINIFILTER_BYPASS_PIDS",
                IOCTL_KSWORD_ARK_SET_MINIFILTER_BYPASS_PIDS,
                &request,
                sizeof(request));
        }
        if (kSub == L"query-minifilter-bypass-pids")
        {
            KSWORD_ARK_MINIFILTER_BYPASS_PID_RESPONSE response{};
            if (!sendFixedNoInput(
                IOCTL_KSWORD_ARK_QUERY_MINIFILTER_BYPASS_PIDS,
                L"IOCTL_KSWORD_ARK_QUERY_MINIFILTER_BYPASS_PIDS",
                response,
                io))
            {
                return 3;
            }
            if (response.size < sizeof(response) ||
                response.version != KSWORD_ARK_CALLBACK_PROTOCOL_VERSION ||
                response.pidCount > KSWORD_ARK_MINIFILTER_BYPASS_PID_MAX_COUNT)
            {
                std::wcerr << L"error: minifilter bypass PID response header invalid\n";
                return 4;
            }
            printResponseBanner(response.version, response.pidCount, 0, io.bytesReturned);
            std::wcout << L"size=" << response.size
                       << L" flags=0x" << std::hex << response.flags
                       << std::dec << L" pidCount=" << response.pidCount << L" pids=";
            for (unsigned long index = 0UL; index < response.pidCount; ++index)
            {
                if (index != 0UL)
                {
                    std::wcout << L",";
                }
                std::wcout << response.processIds[index];
            }
            std::wcout << L"\n";
            return 0;
        }
        if (kSub == L"enum")
        {
            return queryCallbackInventory(kArgs);
        }
        std::wcerr << L"error: unknown callback subcommand '" << kSub << L"'\n";
        return 1;
    }
}
