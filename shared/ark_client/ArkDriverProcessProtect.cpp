#include "ArkDriverClient.h"

#include <cstddef>
#include <string>
#include <vector>

namespace ksword::ark
{
    IoResult DriverClient::setProcessProtectConfig(
        const unsigned long globalFlags,
        const std::vector<KSWORD_ARK_PROCESS_PROTECT_RULE>& rules,
        const std::vector<KSWORD_ARK_PROCESS_PROTECT_TRUSTED>& trustedEntries,
        const unsigned long scanIntervalMs) const
    {
        // Input: protection rules and trusted whitelist after UI organization; both may be empty.
        // Processing: Assemble fixed-length shared packets and issue them exclusively via DriverClient's unified DeviceIoControl.
        //       Report an error on the R3 side if the limit is exceeded; do not send half the table to the kernel.
        // Return: IoResult describes the Win32 transfer result; R0 semantic validation failure is reflected as
        //       ERROR_INVALID_PARAMETER。
        if (rules.size() > KSWORD_ARK_PROCESS_PROTECT_MAX_RULES)
        {
            IoResult errorResult{};
            errorResult.ok = false;
            errorResult.win32Error = ERROR_INVALID_PARAMETER;
            errorResult.message = "too many process protect rules, max=" +
                std::to_string(KSWORD_ARK_PROCESS_PROTECT_MAX_RULES);
            return errorResult;
        }
        if (trustedEntries.size() > KSWORD_ARK_PROCESS_PROTECT_MAX_TRUSTED)
        {
            IoResult errorResult{};
            errorResult.ok = false;
            errorResult.win32Error = ERROR_INVALID_PARAMETER;
            errorResult.message = "too many process protect trusted entries, max=" +
                std::to_string(KSWORD_ARK_PROCESS_PROTECT_MAX_TRUSTED);
            return errorResult;
        }

        KSWORD_ARK_PROCESS_PROTECT_CONFIG_REQUEST request{};
        request.size = sizeof(request);
        request.version = KSWORD_ARK_PROCESS_PROTECT_PROTOCOL_VERSION;
        request.globalFlags = globalFlags;
        request.ruleCount = static_cast<unsigned long>(rules.size());
        request.trustedCount = static_cast<unsigned long>(trustedEntries.size());
        // Let R0 map out-of-range values to the default interval; do not modify the user's input here.
        request.scanIntervalMs = scanIntervalMs;

        for (std::size_t ruleIndex = 0U; ruleIndex < rules.size(); ++ruleIndex)
        {
            request.rules[ruleIndex] = rules[ruleIndex];
            // The kernel compares strings only up to the NUL terminator; this ensures the terminator is present here to avoid relying on the caller.
            request.rules[ruleIndex].targetImage[KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS - 1U] = L'\0';
            request.rules[ruleIndex].ruleName[KSWORD_ARK_PROCESS_PROTECT_NAME_CHARS - 1U] = L'\0';
        }
        for (std::size_t trustedIndex = 0U; trustedIndex < trustedEntries.size(); ++trustedIndex)
        {
            request.trusted[trustedIndex] = trustedEntries[trustedIndex];
            request.trusted[trustedIndex].image[KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS - 1U] = L'\0';
        }

        return deviceIoControl(
            IOCTL_KSWORD_ARK_SET_PROCESS_PROTECT_CONFIG,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            nullptr,
            0);
    }

    ProcessProtectStateResult DriverClient::queryProcessProtectState() const
    {
        // Inputs: None.
        // Processing: Retrieve the fixed-length status packet and verify the kernel has fully written the structure for the current protocol version.
        // Return: response carries full configuration and counters; set io.ok to false on short read or version mismatch.
        ProcessProtectStateResult result{};
        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_PROCESS_PROTECT_STATE,
            nullptr,
            0,
            &result.response,
            static_cast<unsigned long>(sizeof(result.response)));
        if (result.io.ok && result.io.bytesReturned < sizeof(result.response))
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INSUFFICIENT_BUFFER;
            result.io.message = "process protect state response too small, bytesReturned=" +
                std::to_string(result.io.bytesReturned);
            return result;
        }
        if (result.io.ok &&
            (result.response.size < sizeof(result.response) ||
                result.response.version != KSWORD_ARK_PROCESS_PROTECT_PROTOCOL_VERSION))
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_PARAMETER;
            result.io.message = "process protect state protocol mismatch, size=" +
                std::to_string(result.response.size) +
                ", version=" + std::to_string(result.response.version);
        }
        return result;
    }
}
