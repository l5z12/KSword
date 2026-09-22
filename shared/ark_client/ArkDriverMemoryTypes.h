#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>

#include "ArkDriverIoTypes.h"
#include "../driver/KswordArkMemoryIoctl.h"
#include "../driver/KswordArkDdmaIoctl.h"
#include "../driver/KswordArkSectionIoctl.h"
#include "../driver/KswordArkInjectionScanIoctl.h"

namespace ksword::ark
{
    // SectionMappingEntry is an R3 model row representing the R0 ControlArea mapping relationship.
    struct SectionMappingEntry
    {
        std::uint32_t viewMapType = KSWORD_ARK_SECTION_MAP_TYPE_UNKNOWN;
        std::uint32_t processId = 0;
        std::uint64_t startVa = 0;
        std::uint64_t endVa = 0;
    };

    // Image section object references a page: the prototype PTE state for one page.
    struct ImageSectionPageEntry
    {
        std::uint64_t va = 0;
        std::uint64_t prototypePteAddress = 0;
        std::uint64_t prototypePteValue = 0;
        std::uint64_t physicalAddress = 0;   // Valid only when valid.
        std::uint32_t entryFlags = 0;

        bool valid() const noexcept
        {
            return (entryFlags & KSWORD_ARK_INJECTION_SECTION_ENTRY_FLAG_VALID) != 0U;
        }
        bool bytesPresent() const noexcept
        {
            return (entryFlags & KSWORD_ARK_INJECTION_SECTION_ENTRY_FLAG_BYTES_PRESENT) != 0U;
        }
    };

    struct ImageSectionPagesResult
    {
        IoResult io;
        std::uint32_t version = 0;
        std::uint32_t processId = 0;
        std::uint32_t fieldFlags = 0;
        std::uint32_t status = KSWORD_ARK_INJECTION_SCAN_STATUS_UNAVAILABLE;
        long lastStatus = 0;
        std::uint32_t returnedCount = 0;
        std::uint32_t validPageCount = 0;
        std::uint32_t notResidentPageCount = 0;
        std::uint32_t unreadablePteCount = 0;
        std::uint32_t bytesPerPage = 0;
        std::uint64_t controlArea = 0;
        std::uint64_t segment = 0;
        std::uint64_t prototypePteArray = 0;
        std::uint64_t nextCursorVa = 0;
        std::vector<ImageSectionPageEntry> entries;
        // With bytes: ordered by valid pages, with bytesPerPage bytes per page.
        std::vector<std::uint8_t> pageBytes;
    };

    // VirtualMemoryReadResult is the R3 model for reading the target process's virtual memory from R0.
    struct VirtualMemoryQueryResult
    {
        IoResult io;                    // io: DeviceIoControl call status.
        std::uint32_t version = 0;      // version: protocol version.
        std::uint32_t processId = 0;    // processId: Target PID.
        std::uint32_t fieldFlags = 0;   // fieldFlags：KSWORD_ARK_MEMORY_FIELD_*。
        std::uint32_t queryStatus = KSWORD_ARK_MEMORY_QUERY_STATUS_UNAVAILABLE; // queryStatus: R0 aggregated status query.
        long openStatus = 0;            // openStatus: The NTSTATUS from R0 opening the target process.
        long basicStatus = 0;           // basicStatus: NTSTATUS from ZwQueryVirtualMemory.
        long mappedFileNameStatus = 0;  // mappedFileNameStatus: Mapped file name query status.
        std::uint32_t source = 0;       // source: Data source.
        std::uint64_t requestedBaseAddress = 0; // requestedBaseAddress: Requested address.
        std::uint64_t baseAddress = 0;          // baseAddress: Region start address.
        std::uint64_t allocationBase = 0;       // allocationBase: Original allocation base address.
        std::uint64_t regionSize = 0;           // regionSize: Region size.
        std::uint32_t allocationProtect = 0;    // allocationProtect: Initial protection attributes.
        std::uint32_t state = 0;                // state：MEM_COMMIT/MEM_RESERVE/MEM_FREE。
        std::uint32_t protect = 0;              // protect: Current page protection attributes.
        std::uint32_t type = 0;                 // type：MEM_IMAGE/MEM_MAPPED/MEM_PRIVATE。
        std::wstring mappedFileName;            // mappedFileName: Optional mapped file path.
    };

    struct VirtualMemoryReadResult
    {
        IoResult io;                    // io: DeviceIoControl call status.
        std::uint32_t version = 0;      // version: protocol version.
        std::uint32_t headerSize = 0;   // headerSize: Fixed R0 response header size.
        std::uint32_t processId = 0;    // processId: Target PID.
        std::uint32_t fieldFlags = 0;   // fieldFlags：KSWORD_ARK_MEMORY_FIELD_*。
        std::uint32_t readStatus = KSWORD_ARK_MEMORY_READ_STATUS_UNAVAILABLE; // readStatus: R0 read aggregation status.
        long lookupStatus = 0;          // lookupStatus: PsLookupProcessByProcessId status.
        long copyStatus = 0;            // copyStatus: Status of MmCopyVirtualMemory.
        std::uint32_t source = 0;       // source: Data source.
        std::uint64_t requestedBaseAddress = 0; // requestedBaseAddress: Requested base address.
        std::uint32_t requestedBytes = 0;       // requestedBytes: Requested length.
        std::uint32_t bytesRead = 0;            // bytesRead: Valid length returned from R0.
        std::uint32_t maxBytesPerRequest = 0;   // maxBytesPerRequest: Driver-imposed limit.
        std::vector<std::uint8_t> data;         // data: Data read back; failed regions are set to 00 per R0 policy.
    };

    // VirtualMemoryWriteResult is the R3 model for R0 writes to a target process's virtual memory.
    struct VirtualMemoryWriteResult
    {
        IoResult io;                    // io: DeviceIoControl call status.
        std::uint32_t version = 0;      // version: protocol version.
        std::uint32_t processId = 0;    // processId: Target PID.
        std::uint32_t fieldFlags = 0;   // fieldFlags：KSWORD_ARK_MEMORY_FIELD_*。
        std::uint32_t writeStatus = KSWORD_ARK_MEMORY_WRITE_STATUS_UNAVAILABLE; // writeStatus: R0 write aggregation status.
        long lookupStatus = 0;          // lookupStatus: PsLookupProcessByProcessId status.
        long copyStatus = 0;            // copyStatus: Status of MmCopyVirtualMemory.
        std::uint32_t source = 0;       // source: Write source.
        std::uint64_t requestedBaseAddress = 0; // requestedBaseAddress: Requested base address.
        std::uint32_t requestedBytes = 0;       // requestedBytes: Length requested to write.
        std::uint32_t bytesWritten = 0;         // bytesWritten: Actual length written.
        std::uint32_t maxBytesPerRequest = 0;   // maxBytesPerRequest: Driver-imposed limit.
    };

    // PhysicalMemoryReadResult: R3 model for R0 physical memory reads.
    // The physical protocol does not carry processId and has no process lookup step, so it lacks lookupStatus.
    struct PhysicalMemoryReadResult
    {
        IoResult io;                    // io: DeviceIoControl call status.
        std::uint32_t version = 0;      // version: protocol version.
        std::uint32_t headerSize = 0;   // headerSize: The response header size self-reported by R0, for diagnostic purposes only and not used to locate data.
        std::uint32_t fieldFlags = 0;   // fieldFlags：KSWORD_ARK_MEMORY_FIELD_*。
        std::uint32_t readStatus = KSWORD_ARK_MEMORY_PHYSICAL_READ_STATUS_UNAVAILABLE; // readStatus: R0 physical read aggregated status.
        long copyStatus = 0;            // copyStatus: NTSTATUS of MmCopyMemory.
        std::uint32_t source = 0;       // source: Data source; physical read is fixed to MM_COPY_PHYSICAL_MEMORY.
        std::uint64_t requestedPhysicalAddress = 0; // requestedPhysicalAddress: Requested physical address.
        std::uint32_t requestedBytes = 0;       // requestedBytes: Requested length.
        std::uint32_t bytesRead = 0;            // bytesRead: Valid length returned from R0.
        std::uint32_t maxBytesPerRequest = 0;   // maxBytesPerRequest: Maximum bytes per driver read request.
        std::vector<std::uint8_t> data;         // data: Read back physical bytes; length may be less than requested on partial success.
    };

    // PhysicalMemoryWriteResult is the R3 model for R0-controlled physical memory writes.
    // Physical writes use MmMapIoSpaceEx mapping followed by a copy, so they include an additional mapStatus compared to virtual writes.
    struct PhysicalMemoryWriteResult
    {
        IoResult io;                    // io: DeviceIoControl call status.
        std::uint32_t version = 0;      // version: protocol version.
        std::uint32_t fieldFlags = 0;   // fieldFlags: KSWORD_ARK_MEMORY_FIELD_*, including FORCE_WRITE_REQUIRED/USED.
        std::uint32_t writeStatus = KSWORD_ARK_MEMORY_PHYSICAL_WRITE_STATUS_UNAVAILABLE; // writeStatus: R0 physical write aggregation status.
        long mapStatus = 0;             // mapStatus: NTSTATUS during the MmMapIoSpaceEx mapping phase.
        long copyStatus = 0;            // copyStatus: NTSTATUS from the RtlCopyMemory phase after mapping.
        std::uint32_t source = 0;       // source: Write source; physical writes are fixed to MM_MAP_PHYSICAL_MEMORY.
        std::uint64_t requestedPhysicalAddress = 0; // requestedPhysicalAddress: Requested physical address.
        std::uint32_t requestedBytes = 0;       // requestedBytes: Length requested to write.
        std::uint32_t bytesWritten = 0;         // bytesWritten: Actual length written.
        std::uint32_t maxBytesPerRequest = 0;   // maxBytesPerRequest: Maximum bytes per driver write request.
    };

    // ========================================================
    // VA → PA translation (reuses R0 page table walk backend)
    // ========================================================

    // VirtualAddressTranslateResult is the R3 model for IOCTL_KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS. Previously,
    // only KswordCLI sent this IOCTL directly without C++ wrappers; since DDMA's virtual address channel requires
    // fetching physical addresses page-by-page, this is added here for both sides to share the same backend.
    struct VirtualAddressTranslateResult
    {
        IoResult io;                    // io: DeviceIoControl call status.
        std::uint32_t version = 0;      // version: protocol version.
        std::uint32_t processId = 0;    // processId: The target PID echoed back from R0.
        std::uint32_t fieldFlags = 0;   // fieldFlags：KSWORD_ARK_MEMORY_FIELD_*。
        std::uint32_t queryStatus = KSWORD_ARK_MEMORY_TRANSLATE_STATUS_UNAVAILABLE; // queryStatus: translation aggregation status
        long lookupStatus = 0;          // lookupStatus: Process lookup NTSTATUS.
        long walkStatus = 0;            // walkStatus: page walk NTSTATUS.
        std::uint64_t virtualAddress = 0;   // virtualAddress: Requested virtual address.
        std::uint64_t physicalAddress = 0;  // physicalAddress: Translation result; meaningless if resolved is false.
        std::uint64_t cr3PhysicalAddress = 0; // cr3PhysicalAddress: Root of the target process page table.
        std::uint32_t pageSize = 0;     // pageSize: Terminal mapping page size (4KB/2MB/1GB).
        std::uint32_t largePageType = 0; // largePageType：KSWORD_ARK_PAGE_TABLE_LARGE_PAGE_*。
        std::uint32_t protection = 0;   // protection: KSWORD_ARK_MEMORY_PROTECTION_* summary bits.
        std::uint32_t confidence = 0;   // confidence: R0 self-assessed trust level.
        bool resolved = false;          // resolved: Whether a valid terminal mapping was reached.
    };

    // ========================================================
    // DDMA (Direct Disk Memory Access) backend
    // ========================================================

    // DdmaDiskEntry: A disk that can serve as a DDMA channel.
    struct DdmaDiskEntry
    {
        std::uint32_t deviceIndex = 0;  // deviceIndex: Index in the \Driver\Disk device list; used to locate read/write requests.
        std::uint32_t diskFlags = 0;    // diskFlags：KSWORD_ARK_DDMA_DISK_FLAG_*。
        long probeStatus = 0;           // probeStatus: NTSTATUS for ATA passthrough probing.
        long scsiProbeStatus = 0;       // scsiProbeStatus: The NTSTATUS for SCSI passthrough probing.
        std::uint32_t sectorSize = 0;   // sectorSize: actual logical sector size in bytes.
        std::wstring deviceName;        // deviceName: Device object name, e.g., \Device\Harddisk0\DR0.

        // ready: This disk has completed at least one direct DMA transfer.
        // The criterion is deliberately not 'ATA available'—DDMA requires a channel capable of using a specific physical page as a DMA target.
        // Since modern machines are mostly NVMe, relying solely on ATA would incorrectly mark the vast majority of machines as unusable.
        bool ready() const
        {
            return (diskFlags & KSWORD_ARK_DDMA_DISK_FLAG_ANY_DMA_READY) != 0UL;
        }

        // ataReady / scsiReady: Indicate which channel is active, for the UI to explain "which path is being used".
        bool ataReady() const
        {
            return (diskFlags & KSWORD_ARK_DDMA_DISK_FLAG_ATA_DMA_READY) != 0UL;
        }
        bool scsiReady() const
        {
            return (diskFlags & KSWORD_ARK_DDMA_DISK_FLAG_SCSI_DMA_READY) != 0UL;
        }
    };

    // DdmaCapabilityResult is the result of a DDMA capability query.
    struct DdmaCapabilityResult
    {
        IoResult io;                    // io: DeviceIoControl call status.
        bool unsupported = false;       // unsupported: The driver does not recognize this IOCTL (older driver).
        std::uint32_t version = 0;      // version: protocol version.
        std::uint32_t status = KSWORD_ARK_DDMA_QUERY_STATUS_UNAVAILABLE; // status: Aggregated query status.
        std::uint32_t capabilityFlags = 0; // capabilityFlags：KSWORD_ARK_DDMA_CAP_FLAG_*。
        std::uint32_t totalDisks = 0;   // totalDisks: Total number of disks enumerated.
        std::uint32_t readyDisks = 0;   // readyDisks: Number of disks that passed detection.
        std::uint32_t transferBytes = 0;    // transferBytes: Length of a single DMA transfer, fixed to one page.
        std::uint32_t scratchSectorCount = 0; // scratchSectorCount: Number of sectors occupied by the scratch area.
        long lastStatus = 0;            // lastStatus: Most recent underlying NTSTATUS.
        std::vector<DdmaDiskEntry> disks; // disks: Disk entries.

        // kernelDebuggerEnabled: kernel debugging is enabled on the host. DDMA uses MmMapIoSpace to map regular
        // RAM; on such machines, this triggers a MiShowBadMapper BSOD, so the UI must disable accordingly.
        bool kernelDebuggerEnabled() const
        {
            return (capabilityFlags & KSWORD_ARK_DDMA_CAP_FLAG_KERNEL_DEBUGGER_ENABLED) != 0UL;
        }
    };

    // DdmaReadResult is the result of a single DDMA physical read.
    struct DdmaReadResult
    {
        IoResult io;                    // io: DeviceIoControl call status.
        bool unsupported = false;       // unsupported: driver does not recognize this IOCTL.
        std::uint32_t version = 0;      // version: protocol version.
        std::uint32_t fieldFlags = 0;   // fieldFlags：KSWORD_ARK_DDMA_FIELD_*。
        std::uint32_t readStatus = KSWORD_ARK_DDMA_READ_STATUS_UNAVAILABLE; // readStatus: Aggregated read status.
        long mapStatus = 0;             // mapStatus: MmMapIoSpace stage.
        long backupStatus = 0;          // backupStatus: Temporary sector backup phase.
        long stageOutStatus = 0;        // stageOutStatus: Target page → Disk staging sector.
        long stageInStatus = 0;         // stageInStatus: Disk staging sectors → working buffer.
        long restoreStatus = 0;         // restoreStatus: Sector restore phase for the staging area.
        std::uint64_t requestedPhysicalAddress = 0; // requestedPhysicalAddress: Requested physical address.
        std::uint64_t scratchLba = 0;   // scratchLba: The temporary sector LBA used in this operation.
        std::uint32_t diskIndex = 0;    // diskIndex: The disk index used in this operation.
        std::uint32_t requestedBytes = 0;   // requestedBytes: Requested length.
        std::uint32_t bytesRead = 0;        // bytesRead: The actual length read back.
        std::uint32_t maxBytesPerRequest = 0; // maxBytesPerRequest: Single-request limit.
        std::wstring deviceName;        // deviceName: The actual device name used in this session, for R3 comparison.
        std::vector<std::uint8_t> data; // data: physical bytes read back.

        // scratchRestored: The scratch sector has been restored. If false, dirty sectors remain on the disk.
        bool scratchRestored() const
        {
            return (fieldFlags & KSWORD_ARK_DDMA_FIELD_SCRATCH_RESTORED) != 0UL;
        }
    };

    // DdmaWriteResult: Represents a single DDMA physical write result.
    struct DdmaWriteResult
    {
        IoResult io;                    // io: DeviceIoControl call status.
        bool unsupported = false;       // unsupported: driver does not recognize this IOCTL.
        std::uint32_t version = 0;      // version: protocol version.
        std::uint32_t fieldFlags = 0;   // fieldFlags：KSWORD_ARK_DDMA_FIELD_*。
        std::uint32_t writeStatus = KSWORD_ARK_DDMA_WRITE_STATUS_UNAVAILABLE; // writeStatus: Write aggregation status.
        long mapStatus = 0;             // mapStatus: MmMapIoSpace stage.
        long backupStatus = 0;          // backupStatus: Temporary sector backup phase.
        long stageOutStatus = 0;        // stageOutStatus: Working buffer → Disk staging sectors.
        long stageInStatus = 0;         // stageInStatus: Disk staging sector → target page.
        long restoreStatus = 0;         // restoreStatus: Sector restore phase for the staging area.
        long readbackStatus = 0;        // readbackStatus: The read-back phase of the read-modify-write operation.
        std::uint64_t requestedPhysicalAddress = 0; // requestedPhysicalAddress: Requested physical address.
        std::uint64_t scratchLba = 0;   // scratchLba: The temporary sector LBA used in this operation.
        std::uint32_t diskIndex = 0;    // diskIndex: The disk index used in this operation.
        std::uint32_t requestedBytes = 0;   // requestedBytes: Requested length.
        std::uint32_t bytesWritten = 0;     // bytesWritten: Actual length written.
        std::uint32_t maxBytesPerRequest = 0; // maxBytesPerRequest: Single-request limit.
        std::wstring deviceName;        // deviceName: Device name actually used in this session.

        bool scratchRestored() const
        {
            return (fieldFlags & KSWORD_ARK_DDMA_FIELD_SCRATCH_RESTORED) != 0UL;
        }

        // readModifyWriteUsed: The write is not a full page overwrite; the driver performs a read-modify-write.
        // This implies a 4KB-granularity lost update window exists for other bytes in the same page.
        bool readModifyWriteUsed() const
        {
            return (fieldFlags & KSWORD_ARK_DDMA_FIELD_READ_MODIFY_WRITE_USED) != 0UL;
        }
    };

    // Kernel executable-memory permission bits used by the R3 display model.
    // Input: values parsed from the kernel executable page scan response.
    // Processing: MemoryDock maps these bits to readable R/W/X/NX/Large labels.
    // Return behavior: constants are consumed directly and do not return data.
    inline constexpr std::uint32_t kKernelExecutableMemoryPermissionPresent = KSWORD_ARK_PAGE_TABLE_FLAG_PRESENT;

    inline constexpr std::uint32_t kKernelExecutableMemoryPermissionWritable = KSWORD_ARK_PAGE_TABLE_FLAG_WRITABLE;

    inline constexpr std::uint32_t kKernelExecutableMemoryPermissionUser = KSWORD_ARK_PAGE_TABLE_FLAG_USER;

    inline constexpr std::uint32_t kKernelExecutableMemoryPermissionNoExecute = KSWORD_ARK_PAGE_TABLE_FLAG_NX;

    inline constexpr std::uint32_t kKernelExecutableMemoryPermissionLargePage = KSWORD_ARK_PAGE_TABLE_FLAG_LARGE_PAGE;

    inline constexpr std::uint32_t kKernelExecutableMemoryPermissionGlobal = KSWORD_ARK_PAGE_TABLE_FLAG_GLOBAL;

    // Kernel executable-memory risk bits used by the R3 display model.
    // Input: values parsed from R0 scan entries.
    // Processing: UI uses these stable bits for filtering and risk text.
    // Return behavior: constants are values only; no function return is involved.
    inline constexpr std::uint32_t kKernelExecutableMemoryRiskWritableExecutable = KSWORD_ARK_KERNEL_EXEC_RISK_WRITABLE_EXECUTABLE;

    inline constexpr std::uint32_t kKernelExecutableMemoryRiskModuleNonTextExecutable = KSWORD_ARK_KERNEL_EXEC_RISK_MODULE_NON_TEXT_EXECUTABLE;

    inline constexpr std::uint32_t kKernelExecutableMemoryRiskSectionWritable = KSWORD_ARK_KERNEL_EXEC_RISK_SECTION_WRITABLE;

    inline constexpr std::uint32_t kKernelExecutableMemoryRiskLargePage = KSWORD_ARK_KERNEL_EXEC_RISK_LARGE_PAGE;

    inline constexpr std::uint32_t kKernelExecutableMemoryRiskCodePageNotExecutable = KSWORD_ARK_KERNEL_EXEC_RISK_CODE_PAGE_NOT_EXECUTABLE;

    inline constexpr std::uint32_t kKernelExecutableMemoryRiskCodePageWritable = KSWORD_ARK_KERNEL_EXEC_RISK_CODE_PAGE_WRITABLE;

    // KernelExecutableMemoryPageEntry is the R3 model for one executable kernel
    // memory range. Input fields are copied from the Prompt-1 scan response.
    // Processing keeps kernel addresses diagnostic-only and stores owner/path
    // strings for filtering and details. Return behavior: plain data object.
    struct KernelExecutableMemoryPageEntry
    {
        std::uint32_t status = 0;              // status：R0 row status.
        std::uint32_t riskFlags = 0;           // riskFlags：KernelExecutableMemoryRisk* bits.
        std::uint32_t permissionFlags = 0;     // permissionFlags：KernelExecutableMemoryPermission* bits.
        std::uint32_t ownerKind = 0;           // ownerKind：R0 owner classifier, shown diagnostically.
        std::uint32_t pageCount = 0;           // pageCount：contiguous executable pages.
        std::uint32_t pageSize = 0;            // pageSize：4KB/2MB/1GB or R0 effective size.
        long lastStatus = 0;                   // lastStatus：row-level backend status.
        std::uint64_t virtualAddress = 0;      // virtualAddress：range start VA, display only.
        std::uint64_t ownerAddress = 0;        // ownerAddress：diagnostic owner object/address.
        std::uint64_t moduleBase = 0;          // moduleBase：matched module base when available.
        std::uint32_t moduleSize = 0;          // moduleSize：matched module image size when available.
        std::uint64_t regionSize = 0;          // regionSize：pageCount * pageSize or R0 range size.
        std::wstring owner;                    // owner：R0 owner text.
        std::wstring modulePath;               // modulePath：matched module image path.
        std::wstring detail;                   // detail：R0 diagnostic detail for CodeEditorWidget.
    };

    // KernelExecutableMemoryScanResult carries the parsed Prompt-1 response.
    // Input: returned by DriverClient::scanKernelExecutableMemory.
    // Processing: io.ok indicates transport/protocol success; unsupported tells
    // UI to show "not supported / driver too old" instead of crashing.
    // Return behavior: returned by value from DriverClient.
    struct KernelExecutableMemoryScanResult
    {
        IoResult io;                           // io：DeviceIoControl and parse status.
        bool unsupported = false;              // unsupported：true when IOCTL is absent/old.
        std::uint32_t version = 0;             // version：scan protocol version.
        std::uint32_t status = 0;              // status：R0 aggregate status.
        std::uint32_t totalCount = 0;          // totalCount：R0 observed ranges.
        std::uint32_t returnedCount = 0;       // returnedCount：R0 returned ranges.
        std::uint32_t moduleCount = 0;         // moduleCount：R0 module owner set size.
        long lastStatus = 0;                   // lastStatus：R0 aggregate backend status.
        std::vector<KernelExecutableMemoryPageEntry> entries; // entries：parsed scan rows.
    };

    // KernelMemoryEvidenceEntry is the unified R3 model for memory evidence rows.
    // Input: fields are copied from KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW.
    // Processing: keeps addresses and samples diagnostic-only; UI scoring uses
    // riskFlags/permissionFlags without issuing write or repair actions.
    // Return behavior: plain data carrier returned inside KernelMemoryEvidenceResult.
    struct KernelMemoryEvidenceEntry
    {
        std::uint32_t evidenceKind = KSWORD_ARK_MEMORY_EVIDENCE_KIND_UNKNOWN;
        std::uint32_t pageSize = 0;
        std::uint32_t permissionFlags = 0;
        std::uint32_t ownerKind = KSWORD_ARK_MEMORY_EVIDENCE_OWNER_UNKNOWN;
        std::uint32_t riskFlags = 0;
        std::uint32_t moduleSize = 0;
        std::uint32_t confidence = 0;
        std::uint32_t bigPoolTag = 0;
        std::uint32_t bigPoolFlags = 0;
        std::uint32_t sectionRva = 0;
        std::uint32_t sectionSize = 0;
        std::uint32_t hashAlgorithm = KSWORD_ARK_MEMORY_EVIDENCE_HASH_NONE;
        std::uint32_t sampleSize = 0;
        long lastStatus = 0;
        std::uint64_t virtualAddress = 0;
        std::uint64_t regionSize = 0;
        std::uint64_t moduleBase = 0;
        std::uint64_t ownerAddress = 0;
        std::uint64_t contentHash = 0;
        std::string sectionName;
        std::vector<std::uint8_t> sample;
        std::wstring ownerName;
        std::wstring detail;
    };

    // KernelMemoryEvidenceResult carries the variable-length memory evidence response.
    // Input: produced by DriverClient::queryKernelMemoryEvidence.
    // Processing: unsupported distinguishes old drivers from parse failures so UI can
    // render a graceful capability message.
    // Return behavior: returned by value; io.ok reports transport/protocol success.
    struct KernelMemoryEvidenceResult
    {
        IoResult io;
        bool unsupported = false;
        std::uint32_t version = 0;
        std::uint32_t status = KSWORD_ARK_MEMORY_EVIDENCE_STATUS_UNAVAILABLE;
        std::uint32_t responseFlags = 0;
        std::uint32_t sourceFlags = 0;
        std::uint32_t totalRows = 0;
        std::uint32_t returnedRows = 0;
        std::uint32_t maxRows = 0;
        std::uint64_t maxBytes = 0;
        std::uint64_t bytesScanned = 0;
        std::uint32_t moduleCount = 0;
        std::uint32_t bigPoolRowsSeen = 0;
        long lastStatus = 0;
        std::vector<KernelMemoryEvidenceEntry> entries;
    };

    // PhysicalMemoryLayoutResult is the R3 view of the R0 physical memory map summary.
    // Input: produced by DriverClient::queryPhysicalMemoryLayout.
    // Processing: stores aggregate ranges only; no physical memory bytes or per-page
    // content are returned to the UI.
    // Return behavior: returned by value; unsupported=true means the loaded driver is old.
    struct PhysicalMemoryLayoutResult
    {
        IoResult io;
        bool unsupported = false;
        std::uint32_t version = 0;
        std::uint32_t fieldFlags = 0;
        std::uint32_t rangeCount = 0;
        std::uint32_t zeroLengthRangeCount = 0;
        std::uint32_t truncated = 0;
        long lastStatus = 0;
        std::uint64_t totalPhysicalBytes = 0;
        std::uint64_t highestPhysicalAddress = 0;
        std::uint64_t largestRangeBytes = 0;
        std::uint64_t smallestRangeBytes = 0;
        std::uint64_t firstBaseAddress = 0;
        std::uint64_t lastEndAddress = 0;
        std::uint64_t estimatedAddressSpaceGapBytes = 0;
    };
}
