#include "CliSupport.h"

namespace ksword::cli
{
    // commandNetworkFamily implements network rule load and status query.
    // Inputs: argc/argv from wmain.
    // Processing: accepts a blob for rules and prints runtime snapshot state.
    // Returns: process exit code.
    int commandNetworkFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: network requires a subcommand\n"; return 1; }
        const std::wstring kSub = argv[2];
        const NamedArgs kArgs = parseNamedArgs(argc, argv, 3);
        IoctlResult io{};
        if (kSub == L"set-rules")
        {
            std::vector<std::uint8_t> blob = readRequiredBlobOption(kArgs, L"--blob", kMaxCommandBytes);
            KSWORD_ARK_NETWORK_SET_RULES_RESPONSE response{};
            if (!sendBlobFixedResponse(IOCTL_KSWORD_ARK_NETWORK_SET_RULES, L"IOCTL_KSWORD_ARK_NETWORK_SET_RULES", blob, response, io, GENERIC_READ | GENERIC_WRITE)) return 3;
            printResponseBanner(response.version, response.status, response.lastStatus, io.bytesReturned);
            std::wcout << L"runtimeFlags=0x" << std::hex << response.runtimeFlags
                       << std::dec << L" appliedCount=" << response.appliedCount
                       << L" blockedRuleCount=" << response.blockedRuleCount
                       << L" hiddenPortRuleCount=" << response.hiddenPortRuleCount
                       << L" rejectedIndex=" << response.rejectedIndex
                       << L" generation=" << response.generation << L"\n";
            return 0;
        }
        if (kSub == L"query-status")
        {
            KSWORD_ARK_NETWORK_STATUS_RESPONSE response{};
            if (!sendFixedNoInput(IOCTL_KSWORD_ARK_NETWORK_QUERY_STATUS, L"IOCTL_KSWORD_ARK_NETWORK_QUERY_STATUS", response, io))
            {
                return normalizeIoctlRc(L"network status", io, 3);
            }
            printResponseBanner(response.version, response.status, response.registerStatus, io.bytesReturned);
            std::wcout << L"runtimeFlags=0x" << std::hex << response.runtimeFlags
                       << std::dec << L" ruleCount=" << response.ruleCount
                       << L" blockedRuleCount=" << response.blockedRuleCount
                       << L" hiddenPortRuleCount=" << response.hiddenPortRuleCount
                       << L" generation=" << response.generation
                       << L" classifyCount=" << response.classifyCount
                       << L" blockedCount=" << response.blockedCount
                       << L" registerStatus=0x" << std::hex << static_cast<unsigned long>(response.registerStatus)
                       << L" engineStatus=0x" << static_cast<unsigned long>(response.engineStatus) << std::dec << L"\n";
            const std::size_t kLimit = getOptionU32(kArgs, L"--limit", 16U);
            for (std::size_t i = 0; i < std::min<std::size_t>(KSWORD_ARK_NETWORK_MAX_RULES, kLimit); ++i)
            {
                const auto& rule = response.rules[i];
                if (rule.ruleId == 0U && rule.localPort == 0U && rule.remotePort == 0U && rule.processId == 0U)
                {
                    continue;
                }
                std::wcout << L"  rule[" << i << L"] id=" << rule.ruleId
                           << L" action=" << rule.action
                           << L" dir=0x" << std::hex << rule.directionMask
                           << L" proto=" << std::dec << rule.protocol
                           << L" pid=" << rule.processId
                           << L" flags=0x" << std::hex << rule.flags
                           << std::dec << L" localPort=" << rule.localPort
                           << L" remotePort=" << rule.remotePort << L"\n";
            }
            return 0;
        }
        if (kSub == L"audit")
        {
            std::wcout << L"network audit: querying TCP endpoint audit first; use wfp/ndis for chain-specific views\n";
            return queryNetworkEndpoints(kArgs, IOCTL_KSWORD_ARK_NETWORK_QUERY_TCP_ENDPOINTS, L"IOCTL_KSWORD_ARK_NETWORK_QUERY_TCP_ENDPOINTS", L"network audit");
        }
        if (kSub == L"tcp")
        {
            return queryNetworkEndpoints(kArgs, IOCTL_KSWORD_ARK_NETWORK_QUERY_TCP_ENDPOINTS, L"IOCTL_KSWORD_ARK_NETWORK_QUERY_TCP_ENDPOINTS", L"network tcp");
        }
        if (kSub == L"udp")
        {
            return queryNetworkEndpoints(kArgs, IOCTL_KSWORD_ARK_NETWORK_QUERY_UDP_ENDPOINTS, L"IOCTL_KSWORD_ARK_NETWORK_QUERY_UDP_ENDPOINTS", L"network udp");
        }
        if (kSub == L"wfp")
        {
            return queryNetworkWfp(kArgs);
        }
        if (kSub == L"ndis")
        {
            return queryNetworkNdis(kArgs);
        }
        if (kSub == L"afd")
        {
            return commandNetworkAfdFallback(kArgs);
        }
        if (kSub == L"nsi")
        {
            return commandNetworkNsiFallback(kArgs);
        }
        std::wcerr << L"error: unknown network subcommand '" << kSub << L"'\n";
        return 1;
    }
}
