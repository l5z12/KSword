#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>

#include "ArkDriverIoTypes.h"
#include "../driver/KswordArkDeviceAuditIoctl.h"
#include "../driver/KswordArkPlatformAuditIoctl.h"
#include "../driver/KswordArkI8042AuditIoctl.h"
#include "../driver/KswordArkHwidIoctl.h"
#include "../driver/KswordArkCpuPowerIoctl.h"
#include "../driver/KswordArkBugcheckIoctl.h"
#include "../driver/KswordArkSystemTimeIoctl.h"
#include "../driver/KswordArkResearchIoctl.h"

namespace ksword::ark
{
    // ResearchTopicQueryResult: Retains the R0 context snapshot for the 'Second Plan'
    // topic and the business IOCTL evidence rows verified by the central registry.
    struct ResearchTopicQueryResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_QUERY_RESEARCH_TOPIC_RESPONSE response{};
        std::vector<KSWORD_ARK_RESEARCH_EVIDENCE_ENTRY> entries;
    };

    // HwidDispatchResult：
    // - Input: Filled by the HWID Dispatch IOCTL wrapper in DriverClient;
    // - Processing: Preserve the R0 raw response; the UI is responsible for interpreting the target driver's status and risk warnings.
    // - Return behavior: The struct has no member functions; io.ok indicates whether DeviceIoControl succeeded.
    struct HwidDispatchResult
    {
        IoResult io;                                  // io: Underlying DeviceIoControl status.
        bool unsupported = false;                     // unsupported: true if the old driver has not registered the new IOCTL.
        KSWORD_ARK_HWID_DISPATCH_RESPONSE response{}; // response: Fixed R0 response packet.
    };

    // CpuPowerResult: Retains fixed R0 CPU power responses and legacy driver compatibility status.
    struct CpuPowerResult
    {
        IoResult io;                                   // io: Underlying DeviceIoControl status.
        bool unsupported = false;                      // unsupported: Driver loaded but new IOCTLs not yet registered.
        KSWORD_ARK_CPU_POWER_RESPONSE response{};      // response: capabilities, raw MSR, and decoded value.
    };

    // SystemTimeQueryResult：
    // - Input: Read by DriverClient::querySystemTime.
    // - Processing: Preserve R0 multiplier, takeover, conflict, and build parsing evidence;
    // - Return behavior: 'unsupported' allows older drivers to degrade gracefully in the UI.
    struct SystemTimeQueryResult
    {
        IoResult io; // io: underlying DeviceIoControl and fixed response validation status.
        bool unsupported = false; // unsupported: Old driver did not register the system speed-change IOCTL.
        KSWORD_ARK_QUERY_SYSTEM_TIME_RESPONSE response{}; // response: R0 state snapshot.
    };

    // SystemTimeControlResult：
    // - Input: populated by DriverClient::controlSystemTime;
    // - Processing: Save generation numbers and takeover status before and after the action;
    // - Return behavior: The UI determines business success or a security rejection based on response.status.
    struct SystemTimeControlResult
    {
        IoResult io; // io: underlying control IOCTL status.
        bool unsupported = false; // unsupported: The current driver does not support this protocol.
        KSWORD_ARK_CONTROL_SYSTEM_TIME_RESPONSE response{}; // response: Control result.
    };

    // BugcheckDiagnosticsResult: Reserved for transport results of on-demand blue screen diagnostics installation and R0 preparation summary.
    // The UI displays only callback/BGP status, without rescanning private kernel functions or inferring the cause of the failure.
    struct BugcheckDiagnosticsResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_BUGCHECK_DIAGNOSTICS_RESPONSE response{};
    };

    // BugcheckGuardResult keeps the transport result independent from the R0
    // state snapshot, allowing an older driver to degrade safely in the UI.
    struct BugcheckGuardResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_BUGCHECK_GUARD_RESPONSE response{};
    };

    // DeviceAuditResult carries unified read-only device audit results for Device, Input, USB, and GPU.
    // Input: returned by queryDeviceStackAudit/queryInputStackAudit/queryUsbTopologyAudit/queryGpuDisplayWatchdogAudit.
    // Processing: entries store DriverObject, DeviceObject, attached/next chains, and risk flags.
    // Return behavior: Does not disable the device, does not unload the driver, and does not detach the stack.
    struct DeviceAuditResult : VariableAuditResultBase
    {
        std::uint32_t profileFlags = 0;
        std::uint32_t responseFlags = 0;
        std::uint32_t targetCount = 0;
        std::uint32_t driverCount = 0;
        std::uint32_t deviceCount = 0;
        std::vector<KSWORD_ARK_DEVICE_AUDIT_ENTRY> entries;
    };

    // PlatformAuditResult: Carries unified audit results for HAL/WDF.
    // Input: return value of queryPlatformAudit. scopeMask specifies the HAL table or WDF table/callback.
    // Note: entries preserve address, module, structure/owner evidence, and localized detailCode parameters.
    // Return behavior: The query itself is read-only; editing HAL slots and KMDF binding table slots requires separate calls.
    // editPlatformAuditEntry。
    struct PlatformAuditResult : VariableAuditResultBase
    {
        std::uint32_t scopeMask = 0;
        std::uint32_t responseFlags = 0;
        std::uint32_t buildNumber = 0;
        std::uint32_t signaturePolicyFlags = 0;
        std::vector<KSWORD_ARK_PLATFORM_AUDIT_ENTRY> entries;
    };

    // PlatformAuditControlResult: Carries the complete evidence for a single Controlled Action Slot (CAS).
    // The ALIAS_WRITE bit in responseFlags indicates the slot is in a read-only section, with R0 submitting via a writable MDL alias.
    struct PlatformAuditControlResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_CONTROL_PLATFORM_AUDIT_RESPONSE response{};
    };

    // I8042AuditResult carries dedicated i8042prt descriptor and endpoint evidence.
    // Input: returned by queryI8042Audit. Contains endpoint lines only when there is an exact match on PE/RSDS/opcode/DriverObject.
    // Return behavior: Read-only; does not read input packets, does not replay internal IOCTLs, and does not write to device extensions.
    struct I8042AuditResult : VariableAuditResultBase
    {
        std::uint32_t responseFlags = 0;
        std::uint32_t descriptorId = 0;
        std::uint32_t imageTimeDateStamp = 0;
        std::uint32_t imageSize = 0;
        std::uint32_t imageChecksum = 0;
        std::uint32_t pdbAge = 0;
        std::uint64_t imageBase = 0;
        std::uint8_t pdbGuid[KSWORD_ARK_I8042_PDB_GUID_BYTES]{};
        std::vector<KSWORD_ARK_I8042_AUDIT_ENTRY> entries;
    };
}
