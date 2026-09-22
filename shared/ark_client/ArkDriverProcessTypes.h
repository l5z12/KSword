#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>

#include "ArkDriverIoTypes.h"
#include "ArkDriverMemoryTypes.h"
#include "../driver/KswordArkDynDataIoctl.h"
#include "../driver/KswordArkProcessIoctl.h"
#include "../driver/KswordArkThreadIoctl.h"
#include "../driver/KswordArkSectionIoctl.h"
#include "../driver/KswordArkInjectionScanIoctl.h"

namespace ksword::ark
{
    // ProcessEntry is a normalized, UI-friendly view of one R0 process row.
    struct ProcessEntry
    {
        std::uint32_t processId = 0;
        std::uint32_t parentProcessId = 0;
        std::uint32_t flags = 0;
        std::uint32_t sessionId = 0;
        std::uint32_t fieldFlags = 0;
        std::uint32_t r0Status = KSWORD_ARK_PROCESS_R0_STATUS_UNAVAILABLE;
        std::uint32_t sessionSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE;
        std::uint8_t protection = 0;
        std::uint8_t signatureLevel = 0;
        std::uint8_t sectionSignatureLevel = 0;
        std::uint32_t protectionSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE;
        std::uint32_t signatureLevelSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE;
        std::uint32_t sectionSignatureLevelSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE;
        std::uint32_t objectTableSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE;
        std::uint32_t sectionObjectSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE;
        std::uint32_t imagePathSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE;
        std::uint32_t protectionOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t signatureLevelOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t sectionSignatureLevelOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t objectTableOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t sectionObjectOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint64_t objectTableAddress = 0;
        std::uint64_t sectionObjectAddress = 0;
        std::uint64_t dynDataCapabilityMask = 0;
        std::uint64_t creationTime100ns = 0;
        std::string imageName;
        std::string imagePath;
    };

    // ProcessEnumResult carries both the parsed rows and protocol metadata.
    struct ProcessEnumResult
    {
        IoResult io;
        std::uint32_t version = 0;
        std::uint32_t totalCount = 0;
        std::uint32_t returnedCount = 0;
        std::vector<ProcessEntry> entries;
    };

    // ProcessVisibilityResult: Carries the update result for R0-recoverable hidden flags.
    struct ProcessVisibilityResult
    {
        IoResult io;
        std::uint32_t version = 0;
        std::uint32_t processId = 0;
        std::uint32_t status = KSWORD_ARK_PROCESS_VISIBILITY_STATUS_UNKNOWN;
        std::uint32_t hiddenCount = 0;
        long lastStatus = 0;
    };

    // ProcessIntegrityResult carries the R0 process integrity write response.
    // Input: filled by DriverClient::setProcessIntegrity; processId/integrityRid echo the target.
    // Handling: io.ok only indicates successful driver communication and fixed response parsing; status/lastStatus represent the result of the R0 kernel API execution.
    // Return behavior: unsupported=true indicates the old driver lacks the IOCTL, allowing the caller to fall back to R3 based on policy.
    struct ProcessIntegrityResult
    {
        IoResult io;                         // io: status and response NTSTATUS from the underlying DeviceIoControl.
        bool unsupported = false;            // unsupported: the old driver has not registered the IOCTL or returns unsupported.
        std::uint32_t version = 0;           // version: protocol version.
        std::uint32_t processId = 0;         // processId: Target PID.
        std::uint32_t integrityRid = 0;      // integrityRid：S-1-16-* mandatory label RID。
        std::uint32_t status = KSWORD_ARK_PROCESS_INTEGRITY_STATUS_UNKNOWN; // status: R0 aggregated status.
        long lastStatus = 0;                 // lastStatus: Fallback path NTSTATUS for Zw* token APIs or R0 DynData Token.
    };

    // ProcessTokenPrivilegeEntry is shared by both unified and legacy token privilege flows.
    struct ProcessTokenPrivilegeEntry
    {
        std::uint32_t luidLowPart = 0;
        std::int32_t luidHighPart = 0;
        std::uint32_t attributes = 0;
        std::uint32_t action = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_KEEP;
    };

    struct ProcessTokenPrivilegeResult
    {
        IoResult io;
        bool unsupported = false;
        std::uint32_t version = 0;
        std::uint32_t operation = 0;
        std::uint32_t processId = 0;
        std::uint32_t status = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_UNKNOWN;
        std::uint32_t requestedCount = 0;
        std::uint32_t appliedCount = 0;
        std::uint32_t failedIndex = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_FAILED_INDEX_NONE;
        long lastStatus = 0;
        std::uint64_t processCreateTime100ns = 0;
        std::vector<ProcessTokenPrivilegeEntry> entries;
    };

    struct ProcessTokenPrivilegeQueryResult
    {
        IoResult io;
        bool unsupported = false;
        std::uint32_t version = 0;
        std::uint32_t processId = 0;
        std::uint32_t status = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_UNKNOWN;
        std::uint32_t totalCount = 0;
        std::uint32_t returnedCount = 0;
        long lastStatus = 0;
        std::vector<ProcessTokenPrivilegeEntry> entries;
    };

    struct ProcessTokenPrivilegeAdjustResult
    {
        IoResult io;
        bool unsupported = false;
        std::uint32_t version = 0;
        std::uint32_t processId = 0;
        std::uint32_t luidLowPart = 0;
        std::int32_t luidHighPart = 0;
        std::uint32_t action = 0;
        std::uint32_t status = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_UNKNOWN;
        long lastStatus = 0;
    };

    // ProcessSpecialFlagsResult carries the response for BreakOnTermination/APC insertion control.
    struct ProcessSpecialFlagsResult
    {
        IoResult io;                         // io: DeviceIoControl call status.
        std::uint32_t version = 0;           // version: protocol version.
        std::uint32_t processId = 0;         // processId: Target PID.
        std::uint32_t action = 0;            // action: Requested action.
        std::uint32_t status = KSWORD_ARK_PROCESS_SPECIAL_STATUS_UNKNOWN; // status: R0 aggregated status.
        std::uint32_t appliedFlags = 0;      // appliedFlags: Applied flags.
        std::uint32_t touchedThreadCount = 0;// touchedThreadCount: Number of threads modified when APCs are disabled.
        long lastStatus = 0;                 // lastStatus: underlying NTSTATUS.
    };

    // ProcessDkomResult: Carries the PspCidTable DKOM deletion response.
    struct ProcessDkomResult
    {
        IoResult io;                         // io: DeviceIoControl call status.
        std::uint32_t version = 0;           // version: protocol version.
        std::uint32_t processId = 0;         // processId: Target PID.
        std::uint32_t action = 0;            // action: Requested action.
        std::uint32_t status = KSWORD_ARK_PROCESS_DKOM_STATUS_UNKNOWN; // status: R0 aggregated status.
        std::uint32_t removedEntries = 0;    // removedEntries: Number of cleared CID table entries.
        long lastStatus = 0;                 // lastStatus: underlying NTSTATUS.
        std::uint64_t pspCidTableAddress = 0;// pspCidTableAddress: Diagnostic address.
        std::uint64_t processObjectAddress = 0; // processObjectAddress: The diagnostic address.
    };

    // ProcessInjectResult: Carries the response for R0 DLL/Shellcode injection.
    struct ProcessInjectResult
    {
        IoResult io;                         // io: DeviceIoControl call status.
        std::uint32_t version = 0;           // version: protocol version.
        std::uint32_t processId = 0;         // processId: Target PID.
        std::uint32_t injectType = 0;        // injectType: DLL path or shellcode.
        std::uint32_t status = KSWORD_ARK_PROCESS_INJECT_STATUS_UNKNOWN; // status: R0 aggregated status.
        std::uint32_t flags = 0;             // flags: request flag echo.
        std::uint32_t bytesWritten = 0;      // bytesWritten: Number of payload bytes written to the target process.
        long lastStatus = 0;                 // lastStatus: underlying NTSTATUS.
        long waitStatus = 0;                 // waitStatus: Optional wait status for the remote thread.
        std::uint64_t entryPointAddress = 0; // entryPointAddress: Remote thread entry point.
        std::uint64_t parameterAddress = 0;  // parameterAddress: Remote thread parameter.
        std::uint64_t remoteBaseAddress = 0; // remoteBaseAddress: Remote payload region.
        std::uint64_t remoteRegionSize = 0;  // remoteRegionSize: Size of the remote allocated region.
    };

    // ThreadEntry is the R3-side model of the R0 KTHREAD extended field.
    // Input: ArkDriverProcess.cpp, copy field-by-field from KSWORD_ARK_THREAD_ENTRY.
    // Note: flags retains KSWORD_ARK_THREAD_FLAG_* cross-view results; fieldFlags retains field availability.
    // Return: Pure data structure with no member function return values.
    struct ThreadEntry
    {
        std::uint32_t threadId = 0;
        std::uint32_t processId = 0;
        std::uint32_t flags = 0;      // KSWORD_ARK_THREAD_FLAG_*: Cross-view markers for R0 active walk / CID scan.
        std::uint32_t fieldFlags = 0;
        std::uint32_t r0Status = KSWORD_ARK_THREAD_R0_STATUS_UNAVAILABLE;
        std::uint32_t stackFieldSource = KSW_DYN_FIELD_SOURCE_UNAVAILABLE;
        std::uint32_t ioFieldSource = KSW_DYN_FIELD_SOURCE_UNAVAILABLE;
        std::uint64_t initialStack = 0;
        std::uint64_t stackLimit = 0;
        std::uint64_t stackBase = 0;
        std::uint64_t kernelStack = 0;
        std::uint64_t readOperationCount = 0;
        std::uint64_t writeOperationCount = 0;
        std::uint64_t otherOperationCount = 0;
        std::uint64_t readTransferCount = 0;
        std::uint64_t writeTransferCount = 0;
        std::uint64_t otherTransferCount = 0;
        std::uint32_t ktInitialStackOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t ktStackLimitOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t ktStackBaseOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t ktKernelStackOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t ktReadOperationCountOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t ktWriteOperationCountOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t ktOtherOperationCountOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t ktReadTransferCountOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t ktWriteTransferCountOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t ktOtherTransferCountOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint64_t dynDataCapabilityMask = 0;
    };

    // ThreadEnumResult carries the R0 thread extension enumeration response.
    struct ThreadEnumResult
    {
        IoResult io;
        std::uint32_t version = 0;
        std::uint32_t totalCount = 0;
        std::uint32_t returnedCount = 0;
        std::vector<ThreadEntry> entries;
    };

    // ---------------------------------------------------------------------
    // R0 scan backend for injection trace detection (issue #196 §5).
    // ---------------------------------------------------------------------

    // A VAD entry. When protection/vadType includes FLAGS_LAYOUT_ASSUMED, it is for display only and
    // cannot participate in "contradiction" checks—the bit layout has not been verified by build.
    struct ProcessVadEntry
    {
        std::uint64_t startVa = 0;
        std::uint64_t endVaExclusive = 0;
        std::uint64_t vadNodeAddress = 0;
        // Subsection pointer, **not** ControlArea (they differ by one level of indirection).
        // The actual ControlArea is provided by readImageSectionPages.
        std::uint64_t subsection = 0;
        std::uint64_t firstPrototypePte = 0;
        std::uint32_t vadFlagsRaw = 0;
        std::uint32_t protection = 0;
        std::uint32_t vadType = KSWORD_ARK_INJECTION_VAD_TYPE_UNKNOWN;
        std::uint32_t entryFlags = 0;
    };

    struct ProcessVadEnumResult
    {
        IoResult io;
        std::uint32_t version = 0;
        std::uint32_t processId = 0;
        std::uint32_t fieldFlags = 0;
        std::uint32_t status = KSWORD_ARK_INJECTION_SCAN_STATUS_UNAVAILABLE;
        long lastStatus = 0;
        std::uint32_t returnedCount = 0;
        std::uint32_t visitedCount = 0;
        std::uint32_t unreadableNodeCount = 0;
        // 0 indicates DynData has not verified the VadRoot offset for the current build. When 0,
        // this result lacks eligibility for 'missing-field inference', and the caller must degrade.
        std::uint32_t profileVerified = 0;
        std::uint32_t vadRootOffset = 0;
        std::uint64_t vadRootAddress = 0;
        std::uint64_t nextCursorVpn = 0;
        // Readings for chain-break checks. integrityValid is a hard gate: when false, the following items must
        // not participate in any judgment—during partial traversal, visitedCount is naturally less than vadCount.
        bool integrityValid = false;
        bool vadCountKnown = false;
        bool vadHintKnown = false;
        std::uint32_t vadCount = 0;
        std::uint32_t parentMismatchNodes = 0;
        bool vadHintVisited = false;
        std::uint64_t vadHintAddress = 0;
        std::vector<ProcessVadEntry> entries;
    };

    // A contiguous range of executable leaf pages with identical attributes.
    struct ProcessExecutablePteEntry
    {
        std::uint64_t startVa = 0;
        std::uint64_t byteLength = 0;
        std::uint64_t firstPhysicalAddress = 0;
        std::uint64_t firstEntryValue = 0;
        std::uint32_t pageSize = 0;
        std::uint32_t pageCount = 0;
        std::uint32_t effectiveFlags = 0;
        std::uint32_t entryFlags = 0;
    };

    struct ProcessExecutablePteScanResult
    {
        IoResult io;
        std::uint32_t version = 0;
        std::uint32_t processId = 0;
        std::uint32_t fieldFlags = 0;
        std::uint32_t status = KSWORD_ARK_INJECTION_SCAN_STATUS_UNAVAILABLE;
        long lastStatus = 0;
        std::uint32_t returnedCount = 0;
        std::uint32_t tableReads = 0;
        std::uint32_t failedTableReads = 0;
        std::uint32_t executablePageCount = 0;
        std::uint64_t scannedBegin = 0;
        std::uint64_t scannedEnd = 0;
        std::uint64_t nextCursorAddress = 0;
        std::uint64_t cr3PhysicalAddress = 0;
        std::vector<ProcessExecutablePteEntry> entries;
    };

    // ProcessSectionQueryResult carries the Phase-7 Process SectionObject / ControlArea query response.
    struct ProcessSectionQueryResult
    {
        IoResult io;
        std::uint32_t version = 0;
        std::uint32_t totalCount = 0;
        std::uint32_t returnedCount = 0;
        std::uint32_t processId = 0;
        std::uint32_t fieldFlags = 0;
        std::uint32_t queryStatus = KSWORD_ARK_SECTION_QUERY_STATUS_UNAVAILABLE;
        long lastStatus = 0;
        std::uint64_t sectionObjectAddress = 0;
        std::uint64_t controlAreaAddress = 0;
        std::uint64_t dynDataCapabilityMask = 0;
        std::uint32_t epSectionObjectOffset = KSWORD_ARK_SECTION_OFFSET_UNAVAILABLE;
        std::uint32_t mmSectionControlAreaOffset = KSWORD_ARK_SECTION_OFFSET_UNAVAILABLE;
        std::uint32_t mmControlAreaListHeadOffset = KSWORD_ARK_SECTION_OFFSET_UNAVAILABLE;
        std::uint32_t mmControlAreaLockOffset = KSWORD_ARK_SECTION_OFFSET_UNAVAILABLE;
        std::vector<SectionMappingEntry> mappings;
    };

    // CrossViewFieldOffsets mirrors the shared R0 offset packet.
    // Input: copied from process/thread cross-view response headers or rows.
    // Processing: UI uses it only for diagnostics and capability explanations.
    // Return behavior: plain data object with no member function return.
    struct CrossViewFieldOffsets
    {
        std::uint32_t epUniqueProcessId = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t epActiveProcessLinks = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t epThreadListHead = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t epImageFileName = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t etCid = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t etThreadListEntry = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t etStartAddress = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t etWin32StartAddress = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t ktProcess = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t htTableCode = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t hteLowValue = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t pspCidTableRva = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint64_t pspCidTableAddress = 0;
        std::uint32_t epUniqueProcessIdSource = 0;
        std::uint32_t epActiveProcessLinksSource = 0;
        std::uint32_t epThreadListHeadSource = 0;
        std::uint32_t epImageFileNameSource = 0;
        std::uint32_t etCidSource = 0;
        std::uint32_t etThreadListEntrySource = 0;
        std::uint32_t etStartAddressSource = 0;
        std::uint32_t etWin32StartAddressSource = 0;
        std::uint32_t ktProcessSource = 0;
        std::uint32_t htTableCodeSource = 0;
        std::uint32_t hteLowValueSource = 0;
        std::uint32_t pspCidTableSource = 0;
    };

    // ProcessCrossViewEntry is one EPROCESS cross-view evidence row.
    // Input: copied from KSWORD_ARK_PROCESS_CROSSVIEW_ROW.
    // Processing: sourceMask and anomalyFlags remain raw protocol bits so multiple
    // Dock pages can render consistent DKOM diagnostics.
    // Return behavior: data only; no return value.
    struct ProcessCrossViewEntry
    {
        std::uint64_t objectAddress = 0;
        std::uint64_t startAddress = 0;
        std::uint32_t processId = 0;
        std::uint32_t parentProcessId = 0;
        std::uint32_t sourceMask = 0;
        std::uint32_t anomalyFlags = 0;
        std::uint64_t dynDataCapabilityMask = 0;
        CrossViewFieldOffsets fieldOffsets;
        long lastStatus = 0;
        std::uint32_t confidence = 0;
        std::uint32_t publicProcessId = 0;
        std::uint32_t activeListProcessId = 0;
        std::uint32_t cidTableProcessId = 0;
        long publicWalkStatus = 0;
        long activeListStatus = 0;
        long cidTableStatus = 0;
        std::uint32_t detailStatus = 0;
        std::uint32_t denoiseFlags = 0;
        std::string imageName;
        std::string detail;
    };

    // ProcessCrossViewResult carries a complete process cross-view query.
    // Input: produced by DriverClient::queryProcessCrossView.
    // Processing: missingCapabilityMask explains DynData gaps without hiding rows.
    // Return behavior: returned by value; unsupported flags old drivers.
    struct ProcessCrossViewResult
    {
        IoResult io;
        bool unsupported = false;
        std::uint32_t version = 0;
        std::uint32_t status = KSWORD_ARK_CROSSVIEW_STATUS_UNKNOWN;
        std::uint32_t totalCount = 0;
        std::uint32_t returnedCount = 0;
        std::uint64_t dynDataCapabilityMask = 0;
        std::uint64_t missingCapabilityMask = 0;
        long lastStatus = 0;
        CrossViewFieldOffsets fieldOffsets;
        std::vector<ProcessCrossViewEntry> entries;
    };

    // ProcessRuntimeDetailResult carries runtime details for a single process's PDB/DynData.
    // Input: queryProcessRuntimeDetail response.
    // Note: response directly stores the fixed shared driver response to avoid UI redefining offset fields.
    // Return behavior: Read-only display of EPROCESS fields; does not modify the process object.
    struct ProcessRuntimeDetailResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_PROCESS_DETAIL_RESPONSE response{};
    };

    // RuntimeFieldSampleRequestItem is a request from the deep PDB runtime catalog to the R0 sampler.
    // Input: runtimeItemId/offset/size from profiles\pdb_deep_offsets JSON.
    // Handling: R0 safely reads up to 16 bytes using the object base address plus offset.
    // Return behavior: This structure serves only as an R3 request model and does not store object addresses.
    struct RuntimeFieldSampleRequestItem
    {
        std::uint32_t runtimeItemId = 0;
        std::uint32_t offset = 0;
        std::uint32_t size = 0;
        std::uint32_t flags = 0;
        std::string name;
        std::string type;
    };

    // RuntimeFieldSampleEntry is a small field sample result returned by R0.
    // Input: queryProcessRuntimeFieldSamples/queryThreadRuntimeFieldSamples return.
    // Note: sampleBytes preserves raw bytes; valueU64 is used only for summary display of fields <= 8 bytes.
    // Return behavior: Read-only evidence row; cannot be used as write or patch credentials.
    struct RuntimeFieldSampleEntry
    {
        std::uint32_t runtimeItemId = 0;
        std::uint32_t offset = 0;
        std::uint32_t size = 0;
        std::uint32_t status = KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW_STATUS_UNKNOWN;
        std::uint32_t bytesRead = 0;
        std::uint32_t flags = 0;
        long lastStatus = 0;
        std::uint64_t valueU64 = 0;
        std::vector<std::uint8_t> sampleBytes;
        std::string name;
        std::string type;
    };

    // RuntimeFieldSampleResult carries the response for generic process/thread deep PDB field sampling.
    // Input: Parse result of ArkDriverClient's read-only IOCTLs 0x83E/0x83F.
    // Handling: objectAddress is used only to display the object actually looked up by R0, with no write-back operations.
    // Return behavior: unsupported=true indicates the old driver lacks the sampler IOCTL.
    struct RuntimeFieldSampleResult
    {
        IoResult io;
        bool unsupported = false;
        std::uint32_t version = 0;
        std::uint32_t status = KSWORD_ARK_RUNTIME_FIELD_SAMPLE_STATUS_UNKNOWN;
        std::uint32_t totalCount = 0;
        std::uint32_t returnedCount = 0;
        std::uint32_t entrySize = 0;
        std::uint32_t flags = 0;
        long lastStatus = 0;
        std::uint64_t objectAddress = 0;
        std::uint64_t dynDataCapabilityMask = 0;
        std::vector<RuntimeFieldSampleEntry> entries;
    };

    // ThreadCrossViewEntry is one ETHREAD/KTHREAD cross-view evidence row.
    // Input: copied from KSWORD_ARK_THREAD_CROSSVIEW_ROW.
    // Processing: target addresses are diagnostic-only and never used as operation credentials.
    // Return behavior: data-only row.
    struct ThreadCrossViewEntry
    {
        std::uint64_t objectAddress = 0;
        std::uint64_t processObjectAddress = 0;
        std::uint64_t startAddress = 0;
        std::uint32_t processId = 0;
        std::uint32_t threadId = 0;
        std::uint32_t sourceMask = 0;
        std::uint32_t anomalyFlags = 0;
        std::uint64_t dynDataCapabilityMask = 0;
        CrossViewFieldOffsets fieldOffsets;
        long lastStatus = 0;
        std::uint32_t confidence = 0;
        std::uint32_t publicThreadId = 0;
        std::uint32_t threadListThreadId = 0;
        std::uint32_t cidTableThreadId = 0;
        std::uint32_t publicProcessId = 0;
        std::uint32_t threadListProcessId = 0;
        std::uint32_t cidTableProcessId = 0;
        long publicWalkStatus = 0;
        long threadListStatus = 0;
        long cidTableStatus = 0;
        long startAddressStatus = 0;
        std::uint32_t detailStatus = 0;
        std::uint32_t denoiseFlags = 0;
        std::string imageName;
        std::string detail;
    };

    // ThreadCrossViewResult carries a complete thread cross-view query.
    // Input: produced by DriverClient::queryThreadCrossView.
    // Processing: rows may include orphan/CID-only evidence and remain read-only in UI.
    // Return behavior: returned by value; io.ok indicates parseable response.
    struct ThreadCrossViewResult
    {
        IoResult io;
        bool unsupported = false;
        std::uint32_t version = 0;
        std::uint32_t status = KSWORD_ARK_CROSSVIEW_STATUS_UNKNOWN;
        std::uint32_t totalCount = 0;
        std::uint32_t returnedCount = 0;
        std::uint64_t dynDataCapabilityMask = 0;
        std::uint64_t missingCapabilityMask = 0;
        long lastStatus = 0;
        CrossViewFieldOffsets fieldOffsets;
        std::vector<ThreadCrossViewEntry> entries;
    };

    // ThreadRuntimeDetailResult carries single-thread PDB/DynData runtime details.
    // Input: queryThreadRuntimeDetail return.
    // Handling: response stores the ETHREAD/KTHREAD Cid, linked list, stack, and I/O counter fields.
    // Return behavior: read-only display of thread object; does not suspend, terminate, or modify linked lists.
    struct ThreadRuntimeDetailResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_THREAD_DETAIL_RESPONSE response{};
    };
}
