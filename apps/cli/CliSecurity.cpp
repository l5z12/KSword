#include "CliSupport.h"

namespace ksword::cli
{
    // querySecurityStatus prints CI/VBS/SKCI/test-signing posture.
    // Inputs: parsed args with optional flags.
    // Processing: sends the fixed read-only security status IOCTL.
    // Returns: CLI exit code.
    int querySecurityStatus(const NamedArgs& args)
    {
        KSWORD_ARK_QUERY_SECURITY_STATUS_REQUEST request{};
        KSWORD_ARK_QUERY_SECURITY_STATUS_RESPONSE response{};
        request.size = sizeof(request);
        request.version = KSWORD_ARK_SECURITY_AUDIT_PROTOCOL_VERSION;
        request.flags = getOptionU32(args, L"--flags", 0U);
        IoctlResult io{};
        if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_QUERY_SECURITY_STATUS, L"IOCTL_KSWORD_ARK_QUERY_SECURITY_STATUS", request, response, io))
        {
            return normalizeIoctlRc(L"misc security", io, 3);
        }
        printResponseBanner(response.version, static_cast<std::uint32_t>(response.queryStatus), response.codeIntegrityStatus, io.bytesReturned);
        std::wcout << L"fields=0x" << std::hex << response.fieldFlags
                   << L" source=0x" << response.sourceMask
                   << L" ciOptions=0x" << response.codeIntegrityOptions
                   << std::dec << L" secureBoot=" << response.secureBootEnabled
                   << L" secureBootCapable=" << response.secureBootCapable
                   << L" ciEnabled=" << response.ciEnabled
                   << L" umci=" << response.umciEnabled
                   << L" hvciKmci=" << response.hvciKmciEnabled
                   << L" hvciAudit=" << response.hvciAuditMode
                   << L" hvciStrict=" << response.hvciStrictMode
                   << L" vbsPresent=" << response.vbsPresent
                   << L" testSigning=" << response.testSigningEnabled
                   << L" ciDebug=" << response.ciDebugModeEnabled
                   << L" kernelDebuggerEnabled=" << response.kernelDebuggerEnabled
                   << L" kernelDebuggerNotPresent=" << response.kernelDebuggerNotPresent
                   << L" ciModuleLoaded=" << response.ciModuleLoaded
                   << L" secureKernelLoaded=" << response.secureKernelModuleLoaded
                   << L" skciLoaded=" << response.skciModuleLoaded << L"\n";
        return 0;
    }

    // queryDriverTrustView prints bounded loaded-driver signing posture rows.
    // Inputs: parsed args with flags/max rows/limit.
    // Processing: validates variable trust rows and prints conflict flags.
    // Returns: CLI exit code.
    int queryDriverTrustView(const NamedArgs& args)
    {
        KSWORD_ARK_QUERY_DRIVER_TRUST_VIEW_REQUEST request{};
        request.size = sizeof(request);
        request.version = KSWORD_ARK_SECURITY_AUDIT_PROTOCOL_VERSION;
        request.flags = getOptionU32(args, L"--flags", KSWORD_ARK_DRIVER_TRUST_QUERY_FLAG_DEFAULT);
        request.maxEntries = getOptionU32(args, L"--max-entries", KSWORD_ARK_SECURITY_AUDIT_DEFAULT_DRIVER_ROWS);
        IoctlResult io{};
        std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
        const int kRc = sendRawIoctl(L"IOCTL_KSWORD_ARK_QUERY_DRIVER_TRUST_VIEW", IOCTL_KSWORD_ARK_QUERY_DRIVER_TRUST_VIEW, &request, sizeof(request), buffer, io);
        if (kRc != 0) return normalizeIoctlRc(L"misc security driver trust", io, kRc);
        constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_QUERY_DRIVER_TRUST_VIEW_RESPONSE) - sizeof(KSWORD_ARK_DRIVER_TRUST_VIEW_ENTRY);
        const auto* response = reinterpret_cast<const KSWORD_ARK_QUERY_DRIVER_TRUST_VIEW_RESPONSE*>(buffer.data());
        const std::uint32_t kEntrySize = sizeof(KSWORD_ARK_DRIVER_TRUST_VIEW_ENTRY);
        const std::size_t kAvailable = (io.bytesReturned < kHeaderSize) ? 0U : ((io.bytesReturned - kHeaderSize) / kEntrySize);
        if (io.bytesReturned < kHeaderSize) { std::wcerr << L"error: driver trust response too small\n"; return 4; }
        printResponseBanner(response->version, static_cast<std::uint32_t>(response->queryStatus), response->moduleQueryStatus, io.bytesReturned);
        printCountHeader(response->version, response->totalModuleCount, response->entryCount, kEntrySize, io.bytesReturned);
        std::wcout << L"fields=0x" << std::hex << response->fieldFlags
                   << L" source=0x" << response->sourceMask
                   << std::dec << L" maxEntriesAccepted=" << response->maxEntriesAccepted
                   << L" truncated=" << response->truncated << L"\n";
        const std::size_t kParsed = responseCountLimit(response->entryCount, kAvailable, getOptionU32(args, L"--limit", 128U));
        for (std::size_t i = 0; i < kParsed; ++i)
        {
            const auto* row = reinterpret_cast<const KSWORD_ARK_DRIVER_TRUST_VIEW_ENTRY*>(buffer.data() + kHeaderSize + (i * kEntrySize));
            std::wcout << L"  [" << i << L"] base=" << hex64(row->imageBase)
                       << L" size=" << row->imageSize
                       << L" fields=0x" << std::hex << row->fieldFlags
                       << L" source=0x" << row->sourceMask
                       << L" conflict=0x" << row->conflictFlags
                       << L" pathHash=0x" << row->pathHash
                       << std::dec << L" signingLevel=" << row->signingLevel
                       << L" signingStatus=0x" << std::hex << static_cast<unsigned long>(row->signingStatus)
                       << std::dec << L" module='" << fixedWide(row->moduleName, KSWORD_ARK_SECURITY_AUDIT_NAME_CHARS) << L"'\n";
        }
        return 0;
    }

    // queryHypervSummary prints fixed Hyper-V/VBS module availability posture.
    // Inputs: none beyond parsed args for future compatibility.
    // Processing: sends a no-input fixed response IOCTL.
    // Returns: CLI exit code.
    int queryHypervSummary(const NamedArgs&)
    {
        KSWORD_ARK_QUERY_HYPERV_SUMMARY_RESPONSE response{};
        IoctlResult io{};
        if (!sendFixedNoInput(IOCTL_KSWORD_ARK_QUERY_HYPERV_SUMMARY, L"IOCTL_KSWORD_ARK_QUERY_HYPERV_SUMMARY", response, io))
        {
            return normalizeIoctlRc(L"misc hyperv", io, 3);
        }
        printResponseBanner(response.version, static_cast<std::uint32_t>(response.queryStatus), response.moduleQueryStatus, io.bytesReturned);
        std::wcout << L"fields=0x" << std::hex << response.fieldFlags
                   << L" source=0x" << response.sourceMask
                   << std::dec << L" hypervisorPresent=" << response.hypervisorPresent
                   << L" rootPartition=" << response.rootPartitionStatus
                   << L" vmbus=" << response.vmbusStatus
                   << L" vSwitch=" << response.vSwitchStatus
                   << L" vPci=" << response.vPciStatus
                   << L" hvSocket=" << response.hvSocketStatus
                   << L" winHv=" << response.winHvStatus
                   << L" vendor='" << fixedWide(response.hypervisorVendor, KSWORD_ARK_SECURITY_AUDIT_VENDOR_CHARS) << L"'\n";
        return 0;
    }

    // queryAppControlStatus prints AppID/AppLocker/mssecflt/BAM summary posture.
    // Inputs: none beyond parsed args for future compatibility.
    // Processing: sends fixed app-control status IOCTL.
    // Returns: CLI exit code.
    int queryAppControlStatus(const NamedArgs&)
    {
        KSWORD_ARK_QUERY_APP_CONTROL_STATUS_RESPONSE response{};
        IoctlResult io{};
        if (!sendFixedNoInput(IOCTL_KSWORD_ARK_QUERY_APP_CONTROL_STATUS, L"IOCTL_KSWORD_ARK_QUERY_APP_CONTROL_STATUS", response, io))
        {
            return normalizeIoctlRc(L"misc applocker", io, 3);
        }
        printResponseBanner(response.version, static_cast<std::uint32_t>(response.queryStatus), response.moduleQueryStatus, io.bytesReturned);
        std::wcout << L"fields=0x" << std::hex << response.fieldFlags
                   << L" source=0x" << response.sourceMask
                   << std::dec << L" appid=" << response.appidStatus
                   << L" appidPolicy=" << response.appidPolicyStatus
                   << L" applockerFilter=" << response.appLockerFilterStatus
                   << L" applockerOwner=" << response.appLockerCallbackOwnerStatus
                   << L" mssecflt=" << response.mssecfltStatus
                   << L" mssecfltOwner=" << response.mssecfltCallbackOwnerStatus
                   << L" ahcache=" << response.ahcacheStatus
                   << L" bam=" << response.bamStatus
                   << L" applockerOwnerModule='" << fixedWide(response.appLockerOwnerModule, KSWORD_ARK_SECURITY_AUDIT_NAME_CHARS)
                   << L"' mssecfltOwnerModule='" << fixedWide(response.mssecfltOwnerModule, KSWORD_ARK_SECURITY_AUDIT_NAME_CHARS) << L"'\n";
        return 0;
    }

    // commandTrustFamily implements image trust diagnostics.
    // Inputs: argc/argv from wmain.
    // Processing: sends a path-based trust query and prints CI/signing fields.
    // Returns: process exit code.
    int commandTrustFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: trust requires a subcommand\n"; return 1; }
        const std::wstring kSub = argv[2];
        const NamedArgs kArgs = parseNamedArgs(argc, argv, 3);
        if (kSub != L"query-image")
        {
            std::wcerr << L"error: unknown trust subcommand '" << kSub << L"'\n";
            return 1;
        }
        KSWORD_ARK_QUERY_IMAGE_TRUST_REQUEST request{};
        KSWORD_ARK_QUERY_IMAGE_TRUST_RESPONSE response{};
        request.flags = getOptionU32(kArgs, L"--flags", KSWORD_ARK_TRUST_QUERY_FLAG_INCLUDE_ALL);
        const std::wstring& path = requireOptionText(kArgs, L"--path");
        request.pathLengthChars = boundedPathLength(path, KSWORD_ARK_TRUST_PATH_MAX_CHARS);
        copyWideToFixed(request.path, KSWORD_ARK_TRUST_PATH_MAX_CHARS, path);
        IoctlResult io{};
        if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_QUERY_IMAGE_TRUST, L"IOCTL_KSWORD_ARK_QUERY_IMAGE_TRUST", request, response, io)) return 3;
        printResponseBanner(response.version, response.queryStatus, response.openStatus, io.bytesReturned);
        std::wcout << L"size=" << response.size
                   << L" fieldFlags=0x" << std::hex << response.fieldFlags
                   << L" ciOptions=0x" << response.codeIntegrityOptions
                   << L" fileObject=" << hex64(response.fileObjectAddress)
                   << L" ciStatus=0x" << static_cast<unsigned long>(response.codeIntegrityStatus)
                   << L" secureBootStatus=0x" << static_cast<unsigned long>(response.secureBootStatus)
                   << L" objectStatus=0x" << static_cast<unsigned long>(response.objectStatus)
                   << L" signingStatus=0x" << static_cast<unsigned long>(response.signingLevelStatus)
                   << std::dec << L" trustSource=" << response.trustSource
                   << L" signingLevel=" << response.signingLevel
                   << L" signingLevelFlags=" << response.signingLevelFlags
                   << L" secureBootEnabled=" << response.secureBootEnabled
                   << L" secureBootCapable=" << response.secureBootCapable
                   << L" thumbprintAlgorithm=" << response.thumbprintAlgorithm
                   << L" thumbprintSize=" << response.thumbprintSize << L"\n";
        printBytesInline(L"thumbprint", response.thumbprint, std::min<std::size_t>(response.thumbprintSize, KSWORD_ARK_TRUST_THUMBPRINT_MAX_BYTES), KSWORD_ARK_TRUST_THUMBPRINT_MAX_BYTES);
        dumpWideText(L"ntPath", fixedWide(response.ntPath, KSWORD_ARK_TRUST_PATH_MAX_CHARS));
        return 0;
    }

    // commandSafetyFamily implements safety policy query/update IOCTLs.
    // Inputs: argc/argv from wmain.
    // Processing: sends fixed request/response policy packets.
    // Returns: process exit code.
    int commandSafetyFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: safety requires a subcommand\n"; return 1; }
        const std::wstring kSub = argv[2];
        const NamedArgs kArgs = parseNamedArgs(argc, argv, 3);
        IoctlResult io{};
        if (kSub == L"query-policy")
        {
            KSWORD_ARK_QUERY_SAFETY_POLICY_REQUEST request{};
            KSWORD_ARK_QUERY_SAFETY_POLICY_RESPONSE response{};
            request.size = sizeof(request);
            request.version = KSWORD_ARK_SAFETY_PROTOCOL_VERSION;
            request.flags = getOptionU32(kArgs, L"--flags", 0U);
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_QUERY_SAFETY_POLICY, L"IOCTL_KSWORD_ARK_QUERY_SAFETY_POLICY", request, response, io)) return 3;
            printResponseBanner(response.version, response.policyFlags, response.lastStatus, io.bytesReturned);
            std::wcout << L"size=" << response.size
                       << L" defaultPolicyFlags=0x" << std::hex << response.defaultPolicyFlags
                       << std::dec << L" generation=" << response.policyGeneration
                       << L" lastOperation=" << response.lastOperation
                       << L" lastDecision=" << response.lastDecision
                       << L" lastReason=" << response.lastReason
                       << L" lastRiskLevel=" << response.lastRiskLevel
                       << L" lastTargetPid=" << response.lastTargetProcessId
                       << L" allowed=" << response.allowedCount
                       << L" denied=" << response.deniedCount
                       << L" auditOnly=" << response.auditOnlyCount
                       << L" lastTargetText='" << fixedWide(response.lastTargetText, KSWORD_ARK_SAFETY_TEXT_MAX_CHARS) << L"'\n";
            return 0;
        }
        if (kSub == L"set-policy")
        {
            KSWORD_ARK_SET_SAFETY_POLICY_REQUEST request{};
            KSWORD_ARK_SET_SAFETY_POLICY_RESPONSE response{};
            request.size = sizeof(request);
            request.version = KSWORD_ARK_SAFETY_PROTOCOL_VERSION;
            request.setFlags = getOptionU32(kArgs, L"--set-flags", 0U);
            request.clearFlags = getOptionU32(kArgs, L"--clear-flags", 0U);
            request.expectedGeneration = getOptionU32(kArgs, L"--expected-generation", 0U);
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_SET_SAFETY_POLICY, L"IOCTL_KSWORD_ARK_SET_SAFETY_POLICY", request, response, io, GENERIC_READ | GENERIC_WRITE)) return 3;
            printResponseBanner(response.version, static_cast<std::uint32_t>(response.status), response.status, io.bytesReturned);
            std::wcout << L"size=" << response.size
                       << L" oldPolicyFlags=0x" << std::hex << response.oldPolicyFlags
                       << L" newPolicyFlags=0x" << response.newPolicyFlags
                       << std::dec << L" oldGeneration=" << response.oldGeneration
                       << L" newGeneration=" << response.newGeneration << L"\n";
            return 0;
        }
        std::wcerr << L"error: unknown safety subcommand '" << kSub << L"'\n";
        return 1;
    }

    // commandPreflightFamily implements the release-readiness preflight query.
    // Inputs: argc/argv from wmain.
    // Processing: sends a bounded variable response and prints check rows.
    // Returns: process exit code.
    int commandPreflightFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: preflight requires a subcommand\n"; return 1; }
        const std::wstring kSub = argv[2];
        const NamedArgs kArgs = parseNamedArgs(argc, argv, 3);
        if (kSub != L"query")
        {
            std::wcerr << L"error: unknown preflight subcommand '" << kSub << L"'\n";
            return 1;
        }
        KSWORD_ARK_QUERY_PREFLIGHT_REQUEST request{};
        request.size = sizeof(request);
        request.version = KSWORD_ARK_PREFLIGHT_PROTOCOL_VERSION;
        request.flags = getOptionU32(kArgs, L"--flags", KSWORD_ARK_PREFLIGHT_QUERY_FLAG_INCLUDE_ALL);
        std::vector<std::uint8_t> buffer(kSmallResponseBytes, 0U);
        IoctlResult io{};
        const int kRc = sendRawIoctl(L"IOCTL_KSWORD_ARK_QUERY_PREFLIGHT", IOCTL_KSWORD_ARK_QUERY_PREFLIGHT, &request, sizeof(request), buffer, io);
        if (kRc != 0) return kRc;
        constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_QUERY_PREFLIGHT_RESPONSE) - sizeof(KSWORD_ARK_PREFLIGHT_CHECK_ENTRY);
        const auto* response = reinterpret_cast<const KSWORD_ARK_QUERY_PREFLIGHT_RESPONSE*>(buffer.data());
        std::size_t available = 0U;
        try { available = validateVariable(io.bytesReturned, kHeaderSize, response->entrySize, sizeof(KSWORD_ARK_PREFLIGHT_CHECK_ENTRY), L"preflight"); }
        catch (...) { return 4; }
        printResponseBanner(response->version, response->overallStatus, response->dynDataLastStatus, io.bytesReturned);
        printCountHeader(response->version, response->totalCheckCount, response->returnedCheckCount, response->entrySize, io.bytesReturned);
        std::wcout << L"size=" << response->size
                   << L" fieldFlags=0x" << std::hex << response->fieldFlags
                   << L" dynDataStatusFlags=0x" << response->dynDataStatusFlags
                   << L" dynDataCapabilityMask=0x" << response->dynDataCapabilityMask
                   << L" safetyPolicyFlags=0x" << response->safetyPolicyFlags
                   << L" fileMonitorRuntimeFlags=0x" << response->fileMonitorRuntimeFlags
                   << L" trustFieldFlags=0x" << response->trustFieldFlags
                   << L" codeIntegrityOptions=0x" << response->codeIntegrityOptions
                   << std::dec << L" buildConfiguration=" << response->buildConfiguration
                   << L" targetArchitecture=" << response->targetArchitecture
                   << L" ioctlRegistryCount=" << response->ioctlRegistryCount
                   << L" ioctlDuplicateCount=" << response->ioctlDuplicateCount
                   << L" safetyGeneration=" << response->safetyPolicyGeneration
                   << L" fileMonitorQueued=" << response->fileMonitorQueuedCount
                   << L" fileMonitorDropped=" << response->fileMonitorDroppedCount
                   << L" secureBootEnabled=" << response->secureBootEnabled
                   << L" secureBootCapable=" << response->secureBootCapable << L"\n";
        const std::size_t kParsed = responseCountLimit(response->returnedCheckCount, available, getOptionU32(kArgs, L"--limit", 64U));
        for (std::size_t i = 0; i < kParsed; ++i)
        {
            const auto* check = reinterpret_cast<const KSWORD_ARK_PREFLIGHT_CHECK_ENTRY*>(buffer.data() + kHeaderSize + (i * response->entrySize));
            std::wcout << L"  [" << i << L"] id=" << check->checkId
                       << L" status=" << check->status
                       << L" ntstatus=0x" << std::hex << static_cast<unsigned long>(check->ntstatus)
                       << std::dec << L" name='" << fixedAnsiWide(check->checkName, KSWORD_ARK_PREFLIGHT_CHECK_NAME_CHARS)
                       << L"' detail='" << fixedAnsiWide(check->detail, KSWORD_ARK_PREFLIGHT_CHECK_DETAIL_CHARS) << L"'\n";
        }
        return 0;
    }

    // commandMiscFamily exposes security/CI/VBS/Hyper-V/AppLocker/BAM posture.
    // Inputs: argc/argv from wmain.
    // Processing: routes to fixed read-only security audit queries.
    // Returns: process exit code.
    int commandMiscFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: misc requires a subcommand\n"; return 1; }
        const std::wstring kSub = argv[2];
        const NamedArgs kArgs = parseNamedArgs(argc, argv, 3);
        if (kSub == L"security" || kSub == L"ci" || kSub == L"vbs")
        {
            return querySecurityStatus(kArgs);
        }
        if (kSub == L"hyperv")
        {
            return queryHypervSummary(kArgs);
        }
        if (kSub == L"applocker" || kSub == L"bam")
        {
            return queryAppControlStatus(kArgs);
        }
        if (kSub == L"driver-trust")
        {
            return queryDriverTrustView(kArgs);
        }
        std::wcerr << L"error: unknown misc subcommand '" << kSub << L"'\n";
        return 1;
    }
}
