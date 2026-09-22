#pragma once

#include "ArkDriverCapabilities.h"
#include "ArkDriverTypes.h"

#include <functional>

namespace ksword::ark
{
    struct BugcheckVerdictBitmap
    {
        std::uint32_t language = 0;
        std::uint32_t classification = 0;
        std::uint32_t width = 0;
        std::uint32_t height = 0;
        std::uint32_t stride = 0;
        std::vector<std::uint8_t> bgraPixels;
    };

    // Format the immutable R0 evidence packet as a stable diagnostic block.
    // UI layers may prepend localized context, but should not reinterpret a
    // present certificate table as a successful trust-chain validation.
    std::string formatImageSignatureEvidence(const ImageSignatureQueryResult& result);

    // DriverClient centralizes all KswordARK control-device access. Docks should
    // call this class instead of opening \\.\KswordARKLog or invoking
    // DeviceIoControl directly.
    class DriverClient
    {
    public:
        WindowBandResult controlWindowBand(KSWORD_ARK_WINDOW_BAND_REQUEST request) const;
        // setR0UnavailableHandler：
        // - Registers a UI notification entry for the entire R0 client to handle 'control device not found' events;
        // - The handler may be invoked from a worker thread; the receiver must manually switch back to the UI thread.
        // - Only used when the driver is not enabled, to avoid misreporting old driver/business IOCTL failures as 'Please enable R0'.
        using R0UnavailableHandler = std::function<void(unsigned long win32Error)>;
        static void setR0UnavailableHandler(R0UnavailableHandler handler);

        // setR0PermissionRequiredHandler：
        // - Uniformly notify the case where 'the driver already exists, but the current user lacks permission to execute this R0 IOCTL'.
        // - The handler may be invoked from a worker thread; the receiver must manually switch back to the UI thread.
        using R0PermissionRequiredHandler = std::function<void(unsigned long win32Error)>;
        static void setR0PermissionRequiredHandler(R0PermissionRequiredHandler handler);

        // clearR0NotificationHandlersAndWait：
        // - Stops both types of R0 global notifications and waits for callbacks already copied to the worker thread to complete execution.
        // - The main window destructor must call this function first to ensure no callbacks dispatch events to this window after return;
        // - Do not call from within the above handlers, otherwise the calling thread will wait for itself to finish.
        static void clearR0NotificationHandlersAndWait();

        DriverClient() = default;

        // Best-effort branding upload for the VMware-only bugcheck panel.
        // The driver silently discards a valid packet when that feature is inactive.
        IoResult setBugcheckBitmap(
            std::uint32_t width,
            std::uint32_t height,
            std::uint32_t stride,
            std::uint32_t brandColorRgb,
            const std::vector<std::uint8_t>& bgraPixels) const;

        // Install the complete bilingual BGP verdict-card resource set.
        IoResult setBugcheckVerdictResources(
            const std::vector<BugcheckVerdictBitmap>& resources) const;
        // Install and query the BGP Blue Screen diagnostic callback as needed, based on the settings file or the user's explicit action.
        BugcheckDiagnosticsResult configureBugcheckDiagnostics(
            unsigned long action) const;

        // Confirmation-gated control/status path for the one-shot KeBugCheckEx delay guard.
        BugcheckGuardResult configureBugcheckGuard(
            unsigned long action,
            unsigned long delaySeconds = 0UL,
            bool uiConfirmed = false,
            bool tryIgnoreError = false,
            DriverHandle* existingHandle = nullptr) const;
        // Open one synchronous control handle. The returned handle owns CloseHandle.
        DriverHandle open(unsigned long desiredAccess = GENERIC_READ | GENERIC_WRITE) const;

        // Open a synchronous control handle without invoking the global R0 UI
        // notification handlers.  Passive polling paths use this to determine
        // whether the driver is ready before issuing an optional IOCTL.
        DriverHandle openSilently(unsigned long desiredAccess = GENERIC_READ | GENERIC_WRITE) const;

        // Open one overlapped control handle for wait-style callback receivers.
        DriverHandle openOverlapped(unsigned long desiredAccess = GENERIC_READ | GENERIC_WRITE) const;

        // Low-level synchronous IOCTL helper used by narrow advanced UI paths.
        IoResult deviceIoControl(
            unsigned long ioControlCode,
            void* inputBuffer,
            unsigned long inputBytes,
            void* outputBuffer,
            unsigned long outputBytes,
            DriverHandle* existingHandle = nullptr) const;

        // Low-level overlapped IOCTL helper for callback event waiting.
        AsyncIoResult deviceIoControlAsync(
            DriverHandle& handle,
            unsigned long ioControlCode,
            void* inputBuffer,
            unsigned long inputBytes,
            void* outputBuffer,
            unsigned long outputBytes,
            OVERLAPPED* overlapped) const;

        IoResult terminateProcess(
            std::uint32_t processId,
            long exitStatus,
            std::uint64_t expectedCreateTime100ns = 0) const;
        IoResult terminateProcess(
            DriverHandle& handle,
            std::uint32_t processId,
            long exitStatus,
            std::uint64_t expectedCreateTime100ns = 0) const;
        IoResult terminateThread(std::uint32_t threadId, std::uint32_t processId, long exitStatus) const;
        IoResult terminateThread(DriverHandle& handle, std::uint32_t threadId, std::uint32_t processId, long exitStatus) const;
        IoResult setThreadSuspended(std::uint32_t threadId, std::uint32_t processId, bool suspended) const;
        IoResult setThreadSuspended(DriverHandle& handle, std::uint32_t threadId, std::uint32_t processId, bool suspended) const;
        IoResult controlDriverThread(std::uint32_t threadId, std::uint64_t expectedStartAddress, std::uint64_t expectedCreateTime100ns, unsigned long action, unsigned long terminateMethod, bool uiConfirmed) const;
        IoResult controlDriverThread(DriverHandle& handle, std::uint32_t threadId, std::uint64_t expectedStartAddress, std::uint64_t expectedCreateTime100ns, unsigned long action, unsigned long terminateMethod, bool uiConfirmed) const;
        IoResult experimentalReturnToFirmware() const;
        IoResult suspendProcess(std::uint32_t processId) const;
        // resumeProcess: The inverse operation of suspend, paired with it.
        // Without it, after R0 suspends, recovery must rely on R3—but R3 recovery often fails
        // on targets where R0 suspension succeeds, leaving the target permanently suspended.
        IoResult resumeProcess(std::uint32_t processId) const;
        IoResult setProcessProtection(std::uint32_t processId, std::uint8_t protectionLevel) const;
        ProcessVisibilityResult setProcessVisibility(std::uint32_t processId, unsigned long action, unsigned long flags = 0UL) const;
        // setProcessIntegrity：
        // - Input: PID and S-1-16-* mandatory label RID;
        // - Processing: Encapsulate R0 process integrity IOCTL; the driver first uses Zw*
        //   token APIs, with fallback to R0 DynData/PDB private Token fields if necessary.
        // - Return: ProcessIntegrityResult; io.ok and status/lastStatus indicate communication and semantic results, respectively.
        ProcessIntegrityResult setProcessIntegrity(std::uint32_t processId, unsigned long integrityRid) const;
        // queryProcessTokenPrivileges: Queries the complete LUID/attribute list of the target primary token via R0.
        ProcessTokenPrivilegeResult queryProcessTokenPrivileges(
            std::uint32_t processId,
            std::uint64_t expectedCreateTime100ns = 0) const;
        // adjustProcessTokenPrivileges: batch-adjust target primary token privileges in order via R0.
        ProcessTokenPrivilegeResult adjustProcessTokenPrivileges(
            std::uint32_t processId,
            std::uint64_t expectedCreateTime100ns,
            const std::vector<ProcessTokenPrivilegeEntry>& edits,
            bool allowRemove) const;

        // legacy compatibility entry points for old query/adjust IOCTLs.
        ProcessTokenPrivilegeQueryResult queryProcessTokenPrivileges(
            std::uint32_t processId,
            DriverHandle* existingHandle) const;
        ProcessTokenPrivilegeAdjustResult adjustProcessTokenPrivilege(
            std::uint32_t processId,
            std::uint32_t luidLowPart,
            std::int32_t luidHighPart,
            bool enabled,
            DriverHandle* existingHandle = nullptr) const;
        ProcessSpecialFlagsResult setProcessSpecialFlags(
            std::uint32_t processId,
            unsigned long action,
            unsigned long flags = 0UL,
            std::uint64_t expectedCreateTime100ns = 0) const;
        ProcessDkomResult dkomProcess(std::uint32_t processId, unsigned long action, unsigned long flags = 0UL) const;
        ProcessInjectResult injectProcessDll(
            std::uint32_t processId,
            const std::wstring& dllPath,
            unsigned long flags = KSWORD_ARK_PROCESS_INJECT_FLAG_UI_CONFIRMED | KSWORD_ARK_PROCESS_INJECT_FLAG_WAIT_THREAD) const;
        ProcessInjectResult injectProcessShellcode(
            std::uint32_t processId,
            const std::vector<std::uint8_t>& shellcode,
            unsigned long flags = KSWORD_ARK_PROCESS_INJECT_FLAG_UI_CONFIRMED) const;

        ProcessEnumResult enumerateProcesses(unsigned long flags) const;
        ProcessEnumResult enumerateProcesses(unsigned long flags, DriverHandle* existingHandle) const;
        ThreadEnumResult enumerateThreads(unsigned long flags, std::uint32_t processId = 0) const;
        WorkQueueEnumResult enumerateWorkQueues(
            unsigned long flags = KSWORD_ARK_WORK_QUEUE_FLAG_INCLUDE_ALL,
            unsigned long maxEntries = KSWORD_ARK_WORK_QUEUE_DEFAULT_MAX_ENTRIES) const;
        HandleEnumResult enumerateProcessHandles(std::uint32_t processId, unsigned long flags = KSWORD_ARK_ENUM_HANDLE_FLAG_INCLUDE_ALL) const;
        HandleObjectQueryResult queryHandleObject(std::uint32_t processId, std::uint64_t handleValue, unsigned long flags = KSWORD_ARK_QUERY_OBJECT_FLAG_INCLUDE_ALL, unsigned long requestedAccess = 0) const;
        AlpcPortQueryResult queryAlpcPort(std::uint32_t processId, std::uint64_t handleValue, unsigned long flags = KSWORD_ARK_ALPC_QUERY_FLAG_INCLUDE_ALL) const;
        ProcessSectionQueryResult queryProcessSection(std::uint32_t processId, unsigned long flags = KSWORD_ARK_SECTION_QUERY_FLAG_INCLUDE_ALL, unsigned long maxMappings = KSWORD_ARK_SECTION_MAPPING_LIMIT_DEFAULT) const;
        // R0 scan backend for injection trace checks. Both are read-only, resumable, independent views.
        ProcessVadEnumResult enumerateProcessVad(
            std::uint32_t processId,
            std::uint64_t startAddress = 0,
            std::uint64_t endAddress = 0,
            std::uint64_t cursorVpn = 0,
            unsigned long maxEntries = KSWORD_ARK_INJECTION_VAD_LIMIT_DEFAULT,
            unsigned long flags = 0) const;
        ProcessExecutablePteScanResult scanProcessExecutablePte(
            std::uint32_t processId,
            std::uint64_t startAddress = 0,
            std::uint64_t endAddress = 0,
            std::uint64_t cursorAddress = 0,
            unsigned long maxEntries = KSWORD_ARK_INJECTION_PTE_LIMIT_DEFAULT,
            unsigned long maxTableReads = KSWORD_ARK_INJECTION_PTE_TABLE_READS_DEFAULT,
            unsigned long flags = 0) const;
        // Image section object reference pages: a second source for 'what this image should look like' (not the disk file).
        ImageSectionPagesResult readImageSectionPages(
            std::uint32_t processId,
            std::uint64_t rangeStart,
            std::uint64_t rangeEnd,
            std::uint64_t cursorVa = 0,
            unsigned long maxPages = KSWORD_ARK_INJECTION_SECTION_PAGES_DEFAULT,
            unsigned long flags = 0) const;
        FileSectionMappingsQueryResult queryFileSectionMappings(const std::wstring& ntPath, unsigned long flags = KSWORD_ARK_FILE_SECTION_QUERY_FLAG_INCLUDE_ALL, unsigned long maxMappings = KSWORD_ARK_SECTION_MAPPING_LIMIT_DEFAULT) const;
        VirtualMemoryQueryResult queryVirtualMemory(
            std::uint32_t processId,
            std::uint64_t baseAddress,
            unsigned long flags = 0UL,
            DriverHandle* existingHandle = nullptr) const;
        VirtualMemoryReadResult readVirtualMemory(
            std::uint32_t processId,
            std::uint64_t baseAddress,
            std::uint32_t bytesToRead,
            unsigned long flags = KSWORD_ARK_MEMORY_READ_FLAG_ZERO_FILL_UNREADABLE,
            DriverHandle* existingHandle = nullptr) const;
        VirtualMemoryWriteResult writeVirtualMemory(
            std::uint32_t processId,
            std::uint64_t baseAddress,
            const std::vector<std::uint8_t>& bytes,
            unsigned long flags = 0UL,
            DriverHandle* existingHandle = nullptr) const;
        // readPhysicalMemory：
        // - Input: physicalAddress is the starting physical address, with an upper limit of 0x000FFFFFFFFFFFFF and no wrap-around allowed in the range.
        //   bytesToRead is the length for this read operation, with an upper limit of KSWORD_ARK_MEMORY_PHYSICAL_READ_MAX_BYTES (64KB);
        //   flags must be 0; the driver returns STATUS_INVALID_PARAMETER for any non-zero bits. This function rejects
        //   such requests locally before issuing the IOCTL. existingHandle can reuse an already opened control handle.
        // - Handling: Allocate output buffer based on "driver-recognized response header length + bytesToRead", issue
        //   IOCTL_KSWORD_ARK_READ_PHYSICAL_MEMORY, and parse the payload from the actual offset of the data member.
        //   The driver calculates available space using sizeof - sizeof(data), but the write load uses offsetof(data). Since these two
        //   values are not equal, the allocation length and parsing offset must be taken separately and cannot substitute for each other.
        // - Return: PhysicalMemoryReadResult. io.ok only indicates successful IOCTL
        //   communication; data validity must be verified against readStatus and bytesRead.
        PhysicalMemoryReadResult readPhysicalMemory(
            std::uint64_t physicalAddress,
            std::uint32_t bytesToRead,
            unsigned long flags = 0UL,
            DriverHandle* existingHandle = nullptr) const;
        // writePhysicalMemory：
        // - Input: physicalAddress is the starting physical address, with an upper limit of 0x000FFFFFFFFFFFFF and no wrap-around allowed in the range.
        //   bytes is the payload to be written; its length must be non-0 and not exceed
        //   KSWORD_ARK_MEMORY_PHYSICAL_WRITE_MAX_BYTES (4KB). flags must be a combination of
        //   KSWORD_ARK_PHYSICAL_WRITE_FLAG_UI_CONFIRMED and KSWORD_ARK_PHYSICAL_WRITE_FLAG_FORCE only; all other
        //   bits are rejected locally by this function. existingHandle can reuse an already opened control handle.
        // - Handling: Allocate an input buffer based on 'Physical Write Request Header + bytes.size()', copy the payload via
        //   the request->data member, and issue IOCTL_KSWORD_ARK_WRITE_PHYSICAL_MEMORY; on the R0 side, first map the target page
        //   using MmMapIoSpaceEx, then perform the copy within __try, with mapping and copying maintaining independent status.
        // - Returns: PhysicalMemoryWriteResult; io.ok only indicates successful IOCTL communication.
        //   Note: Without KSWORD_ARK_PHYSICAL_WRITE_FLAG_FORCE, the driver writes no bytes and returns
        //   writeStatus=KSWORD_ARK_MEMORY_PHYSICAL_WRITE_STATUS_FORCE_REQUIRED while io.ok remains
        //   true; the caller must check writeStatus to determine if the write actually succeeded.
        PhysicalMemoryWriteResult writePhysicalMemory(
            std::uint64_t physicalAddress,
            const std::vector<std::uint8_t>& bytes,
            unsigned long flags = KSWORD_ARK_PHYSICAL_WRITE_FLAG_UI_CONFIRMED,
            DriverHandle* existingHandle = nullptr) const;
        // ====================================================
        // VA to PA translation and DDMA (Direct Disk Memory Access) backend.
        // ====================================================

        // translateVirtualAddress：
        // - Input: target PID and virtual address; when processId is 0, resolve using the kernel address space.
        // - Implementation: Wraps IOCTL_KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS and reuses the existing read-only
        //   page table walker backend (memory_pagetable.c) in R0, without adding any new page table parsing logic.
        // - Return: VirtualAddressTranslateResult. The physicalAddress field is only meaningful when
        //   resolved is true; when encountering a not-present table entry, this field contains residual data.
        //   Relying solely on io.ok yields a physical address that appears valid but is actually meaningless.
        VirtualAddressTranslateResult translateVirtualAddress(
            std::uint32_t processId,
            std::uint64_t virtualAddress,
            DriverHandle* existingHandle = nullptr) const;

        // queryDdmaCapability：
        // - Input: probeTransfer determines whether to issue an ATA DMA read command for each disk.
        //   scratchLba/scratchLbaValid provide a temporary sector for probing; if not declared, only device
        //   enumeration occurs without sending commands; maxDisks limits the number of returned entries.
        // - Processing: Encapsulate IOCTL_KSWORD_ARK_DDMA_QUERY_CAPABILITY.
        // - Returns: DdmaCapabilityResult. The caller must first check kernelDebuggerEnabled():
        //   On machines with kernel debugging enabled, DDMA triggers a MiShowBadMapper
        //   BSOD; in this case, no DDMA read/write operations should be allowed.
        DdmaCapabilityResult queryDdmaCapability(
            bool probeTransfer,
            std::uint64_t scratchLba,
            bool scratchLbaValid,
            unsigned long maxDisks = KSWORD_ARK_DDMA_DISK_LIMIT_DEFAULT,
            DriverHandle* existingHandle = nullptr) const;

        // ddmaReadPhysicalMemory：
        // - Input: diskIndex is obtained from capability query; physicalAddress and bytesToRead must fall within the
        //   same 4KB physical page (DMA transfer granularity is one page; cross-page slicing is handled by the caller).
        //   scratchLba is the starting LBA of the temporary sector; flags must include both
        //   SCRATCH_LBA_VALID and SCRATCH_ACKNOWLEDGED. This function intercepts locally.
        // - Processing: R0 side DMA-writes the target physical page to a temporary sector, DMA-reads it back to the working buffer,
        //   and finally restores the temporary sector. The CPU never dereferences the target physical page along the entire path.
        // - Return: DdmaReadResult; io.ok only indicates successful IOCTL round-trip. Data
        //   validity depends on readStatus, and disk cleanliness depends on scratchRestored().
        DdmaReadResult ddmaReadPhysicalMemory(
            std::uint32_t diskIndex,
            std::uint64_t physicalAddress,
            std::uint32_t bytesToRead,
            std::uint64_t scratchLba,
            unsigned long flags,
            DriverHandle* existingHandle = nullptr) const;

        // ddmaWritePhysicalMemory：
        // - Input: Same as above, plus KSWORD_ARK_DDMA_FLAG_FORCE. If
        //   missing, the driver returns FORCE_REQUIRED and writes zero bytes.
        // - Handling: When the request is not 'page-aligned and exactly one page', R0 first performs a DMA read
        //   of the entire page, then writes it back entirely (read-modify-write). A 4KB granularity lost-update
        //   window exists during this process, and the result's readModifyWriteUsed() reports this accurately.
        // - Return: DdmaWriteResult; writeStatus must be checked to determine if the write actually succeeded.
        DdmaWriteResult ddmaWritePhysicalMemory(
            std::uint32_t diskIndex,
            std::uint64_t physicalAddress,
            const std::vector<std::uint8_t>& bytes,
            std::uint64_t scratchLba,
            unsigned long flags,
            DriverHandle* existingHandle = nullptr) const;

        // queryKernelMemoryEvidence：
        // - Input: Read-only collection flags, row/byte budget, and optional address half-open interval.
        // - Processing: Wraps IOCTL_KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE and parses variable-length evidence rows.
        // - Returns: KernelMemoryEvidenceResult. For old drivers or missing capabilities, unsupported=true, and the caller displays a graceful message.
        KernelMemoryEvidenceResult queryKernelMemoryEvidence(
            unsigned long flags = KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_ALL,
            unsigned long maxRows = KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_MAX_ROWS,
            std::uint64_t startAddress = 0,
            std::uint64_t endAddress = 0,
            std::uint64_t maxBytes = KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_MAX_BYTES,
            unsigned long maxBigPoolRows = KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_BIGPOOL_ROWS,
            unsigned long sampleBytes = KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_SAMPLE_BYTES) const;
        FileInfoQueryResult queryFileInfo(const std::wstring& ntPath, unsigned long flags = KSWORD_ARK_QUERY_FILE_INFO_FLAG_INCLUDE_ALL) const;
        FileInfoQueryResult queryFileInfo(DriverHandle& handle, const std::wstring& ntPath, unsigned long flags = KSWORD_ARK_QUERY_FILE_INFO_FLAG_INCLUDE_ALL) const;
        // enumerateDirectory: Paginates R0 ZwQueryDirectoryFile calls and merges them into a read-only snapshot with a defined total row budget.
        DirectoryEnumerationResult enumerateDirectory(
            const std::wstring& ntPath,
            unsigned long maxEntries = 16384UL) const;
        // enumerateDirectoryByIrp：
        // - Input: NT directory path accessible by the driver, target stack layer, and R3 total row budget;
        // - Handling: R0 creates a custom IRP_MJ_DIRECTORY_CONTROL and sends it directly to the specified layer, merging results for paging.
        // - Return: Row format consistent with enumerateDirectory, additionally containing the actual effective layer and
        //   the receiving driver name, allowing the caller to determine if the filter layer was truly bypassed in this call.
        FileIrpDirectoryResult enumerateDirectoryByIrp(
            const std::wstring& ntPath,
            unsigned long targetLayer = KSWORD_ARK_FILE_IRP_LAYER_BASE_FS,
            unsigned long maxEntries = 16384UL) const;
        // submitFileIrp：
        // - Input: Complete IRP construction parameters; write semantics and dangerous major codes must be set by the caller
        //   via uiConfirmed/allowDangerous, while the client is only responsible for completing the confirmation token;
        // - Handling: A single IOCTL completes 'open → send target major → finalize'.
        // - Returns: NTSTATUS for each stage, target device stack information, and output data.
        FileIrpSubmitResult submitFileIrp(
            const FileIrpSubmitRequestParams& params) const;
        // Read Authenticode PE certificate-table structure and cached Code
        // Integrity state through the driver. No WinTrust API is used.
        ImageSignatureQueryResult queryImageSignature(
            const std::wstring& ntPath,
            std::uint64_t expectedModuleBase = 0,
            unsigned long flags = KSWORD_ARK_IMAGE_SIGNATURE_QUERY_FLAG_DEFAULT) const;
        // setFileIntegrity：
        // - Input: NT path, directory flag, and S-1-16-* mandatory label RID accessible by the driver;
        // - Handling: Encapsulates the R0 file Mandatory Label IOCTL; the driver side only calls `ZwCreateFile`/`ZwSetSecurityObject`.
        // - Returns: FileIntegrityResult; io.ok and status/lastStatus represent communication and semantic results, respectively.
        FileIntegrityResult setFileIntegrity(const std::wstring& ntPath, bool isDirectory, unsigned long integrityRid) const;
        IoResult controlFileMonitor(unsigned long action, unsigned long operationMask = KSWORD_ARK_FILE_MONITOR_OPERATION_ALL, unsigned long processId = 0UL, unsigned long flags = 0UL) const;
        FileMonitorStatusResult queryFileMonitorStatus() const;
        FileMonitorDrainResult drainFileMonitor(unsigned long maxEvents = 128UL, unsigned long flags = 0UL) const;
        // controlDebugOutput: Register, unregister, or query the DbgSetDebugPrintCallback capture status.
        DebugOutputControlResult controlDebugOutput(unsigned long action) const;
        DebugOutputControlResult controlDebugOutput(DriverHandle& handle, unsigned long action) const;
        // drainDebugOutput: Read the R0 fixed ring buffer using a monotonic cursor increment.
        DebugOutputDrainResult drainDebugOutput(std::uint64_t afterSequence, unsigned long maxRecords = KSWORD_ARK_DEBUG_OUTPUT_DEFAULT_DRAIN_RECORDS) const;
        DebugOutputDrainResult drainDebugOutput(DriverHandle& handle, std::uint64_t afterSequence, unsigned long maxRecords = KSWORD_ARK_DEBUG_OUTPUT_DEFAULT_DRAIN_RECORDS) const;
        // callback monitor: global control status; readers use their own afterSequence cursors.
        CallbackMonitorStatusResult controlCallbackMonitor(unsigned long action, unsigned long categoryMask) const;
        CallbackMonitorStatusResult controlCallbackMonitor(DriverHandle& handle, unsigned long action, unsigned long categoryMask) const;
        CallbackMonitorStatusResult queryCallbackMonitorStatus() const;
        CallbackMonitorStatusResult queryCallbackMonitorStatus(DriverHandle& handle) const;
        CallbackMonitorReadResult readCallbackMonitor(std::uint64_t afterSequence, unsigned long maxRecords = KSWORD_ARK_CALLBACK_MONITOR_DEFAULT_READ_RECORDS) const;
        CallbackMonitorReadResult readCallbackMonitor(DriverHandle& handle, std::uint64_t afterSequence, unsigned long maxRecords = KSWORD_ARK_CALLBACK_MONITOR_DEFAULT_READ_RECORDS) const;
        RegistryReadResult readRegistryValue(const std::wstring& kernelKeyPath, const std::wstring& valueName, unsigned long maxDataBytes = KSWORD_ARK_REGISTRY_DATA_MAX_BYTES) const;
        RegistryEnumResult enumerateRegistryKey(const std::wstring& kernelKeyPath, unsigned long flags = KSWORD_ARK_REGISTRY_ENUM_FLAG_INCLUDE_SUBKEYS | KSWORD_ARK_REGISTRY_ENUM_FLAG_INCLUDE_VALUES) const;
        RegistryOperationResult setRegistryValue(const std::wstring& kernelKeyPath, const std::wstring& valueName, std::uint32_t valueType, const std::vector<std::uint8_t>& data) const;
        RegistryOperationResult deleteRegistryValue(const std::wstring& kernelKeyPath, const std::wstring& valueName) const;
        RegistryOperationResult createRegistryKey(const std::wstring& kernelKeyPath) const;
        RegistryOperationResult deleteRegistryKey(const std::wstring& kernelKeyPath) const;
        RegistryOperationResult renameRegistryValue(const std::wstring& kernelKeyPath, const std::wstring& oldValueName, const std::wstring& newValueName) const;
        RegistryOperationResult renameRegistryKey(const std::wstring& kernelKeyPath, const std::wstring& newKeyName) const;
        IoResult deletePath(const std::wstring& ntPath, bool isDirectory) const;
        IoResult deletePath(DriverHandle& handle, const std::wstring& ntPath, bool isDirectory) const;
        // deletePathEx：
        // - Input: NT path accessible by the driver, directory flag, whether to recursively expand within R0, whether to
        //   continue on single-point failure, and explicit backend selection of underlying Zw*, IRP, or POSIX deletion.
        // - Handling: Wraps a delete IOCTL with a response packet. When recursive=true, the directory tree is fully deleted by R0 post-processing,
        //   eliminating reliance on R3 enumeration; thus, even if the directory DACL denies enumeration, it can still be completely cleaned up.
        // - Returns: DeletePathResult; unsupported=true indicates an old driver, requiring the caller to fall back to R3 unwind.
        DeletePathResult deletePathEx(
            const std::wstring& ntPath,
            bool isDirectory,
            bool recursive,
            bool continueOnError = true,
            FileDeleteBackend backend = FileDeleteBackend::kNative) const;
        DeletePathResult deletePathEx(
            DriverHandle& handle,
            const std::wstring& ntPath,
            bool isDirectory,
            bool recursive,
            bool continueOnError = true,
            FileDeleteBackend backend = FileDeleteBackend::kNative) const;

        SsdtEnumResult enumerateSsdt(unsigned long flags) const;
        SsdtEnumResult enumerateShadowSsdt(unsigned long flags = KSWORD_ARK_ENUM_SSDT_FLAG_INCLUDE_UNRESOLVED) const;
        // queryProcessCrossView：
        // - Input: Process cross-view collection flags, PID half-open/closed filtering, and node budget.
        // - Processing: Invoke R0 exclusively via ArkDriverClient; prevent Dock from calling DeviceIoControl directly.
        // - existingHandle: Reuse an already opened device handle to avoid repeatedly opening the driver during batch read-only queries.
        // - Returns: ProcessCrossViewResult, containing source matrix, anomaly flags, and DynData gaps.
        ProcessCrossViewResult queryProcessCrossView(
            unsigned long flags = KSWORD_ARK_PROCESS_CROSSVIEW_FLAG_INCLUDE_ALL,
            std::uint32_t startPid = 0,
            std::uint32_t endPid = 0,
            unsigned long maxNodes = KSWORD_ARK_CROSSVIEW_DEFAULT_MAX_NODES,
            DriverHandle* existingHandle = nullptr) const;
        // queryThreadCrossView：
        // - Input: Thread cross-view collection flags, optional PID/TID filtering, and node budget.
        // - Processing: Parse the ETHREAD/KTHREAD source matrix to read-only display thread DKOM evidence.
        // - Returns: ThreadCrossViewResult; does not return object credentials usable for write operations.
        ThreadCrossViewResult queryThreadCrossView(
            unsigned long flags = KSWORD_ARK_THREAD_CROSSVIEW_FLAG_INCLUDE_ALL,
            std::uint32_t processId = 0,
            std::uint32_t startTid = 0,
            std::uint32_t endTid = 0,
            unsigned long maxNodes = KSWORD_ARK_CROSSVIEW_DEFAULT_MAX_NODES) const;
        // query*RuntimeDetail：
        // - Input: PID/TID and read-only field group flags.
        // - Processing: Wraps R0 PDB/DynData detail IOCTL; returns unsupported/unavailable on failure.
        // - existingHandle: optional shared device handle; if null, retain the original open behavior per call.
        // - Returns: A fixed response structure; object addresses are not used as credentials for subsequent write operations.
        ProcessRuntimeDetailResult queryProcessRuntimeDetail(
            std::uint32_t processId,
            unsigned long flags = KSWORD_ARK_PROCESS_DETAIL_FLAG_INCLUDE_ALL,
            DriverHandle* existingHandle = nullptr) const;
        ThreadRuntimeDetailResult queryThreadRuntimeDetail(std::uint32_t threadId, std::uint32_t processId = 0, unsigned long flags = KSWORD_ARK_THREAD_DETAIL_FLAG_INCLUDE_ALL) const;
        // query*RuntimeFieldSamples：
        // - Input: List of field offsets/sizes selected from the deep PDB catalog.
        // - Processing: Encapsulate read-only small field sampling IOCTL; R0 does not accept object addresses.
        // - Return: Per-field status, byte samples, and U64 summary; older drivers return unsupported.
        RuntimeFieldSampleResult queryProcessRuntimeFieldSamples(std::uint32_t processId, const std::vector<RuntimeFieldSampleRequestItem>& items, unsigned long flags = 0UL) const;
        RuntimeFieldSampleResult queryThreadRuntimeFieldSamples(std::uint32_t threadId, std::uint32_t processId, const std::vector<RuntimeFieldSampleRequestItem>& items, unsigned long flags = 0UL) const;
        KernelInlineHookScanResult scanInlineHooks(unsigned long flags = 0UL, unsigned long maxEntries = KSWORD_ARK_KERNEL_HOOK_DEFAULT_MAX_ENTRIES, const std::wstring& moduleName = std::wstring()) const;
        // scanKernelExecutableMemory：
        // - Purpose: Invoke the IOCTL defined in Prompt 1 to scan kernel executable pages and parse the variable-length response into an R3 model.
        // - Parameter flags: Scan switch bits, typically passed as INCLUDE_ALL by the UI.
        // - Parameter maxEntries: maximum number of entries returned per call; 0 indicates using the default value.
        // - Parameter modulePathFilter: Reserved R3 filter parameter; currently filtered locally by the UI.
        // - Return: KernelExecutableMemoryScanResult; io.ok indicates successful transmission and protocol parsing.
        KernelExecutableMemoryScanResult scanKernelExecutableMemory(unsigned long flags = 0UL, unsigned long maxEntries = 4096UL, const std::wstring& modulePathFilter = std::wstring()) const;
        KernelInlinePatchResult patchInlineHook(std::uint64_t functionAddress, unsigned long mode, unsigned long patchBytes, const std::vector<std::uint8_t>& expectedCurrentBytes, const std::vector<std::uint8_t>& restoreBytes = std::vector<std::uint8_t>(), unsigned long flags = 0UL) const;
        KernelIatEatHookScanResult enumerateIatEatHooks(unsigned long flags = KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_IMPORTS | KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_EXPORTS, unsigned long maxEntries = KSWORD_ARK_KERNEL_HOOK_DEFAULT_MAX_ENTRIES, const std::wstring& moduleName = std::wstring()) const;
        // enumerateKernelTimerDpc: Read-only query of per-CPU TimerTable, returning KTIMER/KDPC snapshots and partial/corrupt diagnostics.
        KernelTimerDpcEnumResult enumerateKernelTimerDpc(
            unsigned long maxEntries = KSWORD_ARK_TIMER_DPC_DEFAULT_MAX_ENTRIES,
            unsigned long maxEntriesPerBucket = KSWORD_ARK_TIMER_DPC_DEFAULT_BUCKET_BUDGET) const;
        DriverObjectQueryResult queryDriverObject(const std::wstring& driverName, unsigned long flags = KSWORD_ARK_DRIVER_OBJECT_QUERY_FLAG_INCLUDE_ALL, unsigned long maxDevices = KSWORD_ARK_DRIVER_DEVICE_LIMIT_DEFAULT, unsigned long maxAttachedDevices = KSWORD_ARK_DRIVER_ATTACHED_LIMIT_DEFAULT) const;
        // controlIoTimer: R0 re-refs the DriverObject by name, verifies the DriverObject/DeviceObject/PIO_TIMER
        // triple identity against a device snapshot, then calls the public IoStartTimer/IoStopTimer.
        IoTimerControlResult controlIoTimer(
            unsigned long action,
            const std::wstring& driverName,
            std::uint64_t expectedDriverObjectAddress,
            std::uint64_t expectedDeviceObjectAddress,
            std::uint64_t expectedTimerAddress,
            bool uiConfirmed) const;
        // queryIoctlRegistry: Query the KswordARK unified dispatch registry, read-only return of metadata.
        IoctlRegistryQueryResult queryIoctlRegistry(unsigned long flags = KSWORD_ARK_IOCTL_REGISTRY_FLAG_INCLUDE_HANDLER, unsigned long maxEntries = KSWORD_ARK_IOCTL_REGISTRY_MAX_ENTRIES) const;

        // queryResearchTopic: Queries the versioned R0 runtime evidence and source mapping for a kernel knowledge topic.
        ResearchTopicQueryResult queryResearchTopic(
            unsigned long topicId,
            unsigned long maxEntries = KSWORD_ARK_RESEARCH_DEFAULT_MAX_ENTRIES) const;
        // queryDriverIntegrity：
        // - Input: Optional DriverObject name, module base address, and collection budget.
        // - Processing: Invoke unified driver integrity IOCTL to aggregate DriverObject/LDR/FastIo/CPU/IDT evidence.
        // - Return: DriverIntegrityResult; unsupported=true indicates R0 is not yet integrated or the driver is too old.
        DriverIntegrityResult queryDriverIntegrity(
            const std::wstring& driverName = std::wstring(),
            std::uint64_t targetModuleBase = 0,
            unsigned long flags = KSWORD_ARK_DRIVER_INTEGRITY_FLAG_DEFAULT,
            unsigned long maxRows = KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_MAX_ROWS,
            unsigned long maxIdtVectorsPerCpu = KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_IDT_VECTORS) const;
        // queryUnloadedDrivers：
        // - Input: MmUnloadedDrivers, PiDDBCacheTable, or g_KernelHashBucketList source and row budget;
        // - Processing: Call the unified read-only IOCTL and retain columns actually supported by each source based on HAS_* flags.
        // - Returns: UnloadedDriverQueryResult; does not delete, clean, or modify any kernel cache.
        UnloadedDriverQueryResult queryUnloadedDrivers(
            std::uint32_t source,
            unsigned long maxRows = KSWORD_ARK_UNLOADED_DRIVER_DEFAULT_ROWS) const;
        // queryKernelCpuIntegrity：
        // - Input: CPU/IDT collection flags and budget.
        // - Processing: Reuse the protocol from queryDriverIntegrity, requesting only CPU entry evidence.
        // - Return: DriverIntegrityResult; no MSR/IDT/GDT write operations are performed.
        DriverIntegrityResult queryKernelCpuIntegrity(
            unsigned long flags = KSWORD_ARK_DRIVER_INTEGRITY_FLAG_CPU | KSWORD_ARK_DRIVER_INTEGRITY_FLAG_IDT_ENTRIES,
            unsigned long maxRows = KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_MAX_ROWS,
            unsigned long maxIdtVectorsPerCpu = KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_IDT_VECTORS) const;
        // restoreIdtBaseline: Performs a read-only pre-check or atomic restoration of the immutable boot-time baseline for the specified CPU/vector.
        // force=false returns only FORCE_REQUIRED/current state; when force=true, the caller must explicitly pass uiConfirmed.
        IdtBaselineRestoreResult restoreIdtBaseline(
            std::uint16_t processorGroup,
            std::uint8_t processorNumber,
            std::uint8_t vector,
            std::uint64_t expectedRawLow,
            std::uint64_t expectedRawHigh,
            bool force,
            bool uiConfirmed) const;
        PiDdbQueryResult queryPiDdb(
            unsigned long maxRows = KSWORD_ARK_PIDDB_DEFAULT_ROWS) const;
        PiDdbDeleteResult deletePiDdbEntry(
            const PiDdbEntry& expectedEntry,
            bool force,
            bool uiConfirmed) const;
        // queryHvmStatus/controlHvm: Read VT-x/EPT capabilities and perform preparation,
        // self-check, one-time VMCALL to guest, VM-exit collection, or resource release.
        HvmStatusResult queryHvmStatus() const;
        HvmMetricsResult queryHvmMetrics() const;
        HvmControlResult controlHvm(
            unsigned long command,
            unsigned long expectedGeneration,
            bool force,
            bool allowNested,
            bool uiConfirmed,
            bool enableEptEvents = false,
            bool enableNestedVmx = false,
            bool enableEvmcs = false,
            // enableVe: Reflect EPT violations as guest #VE (vector 20).
            // Dangerous and disabled by default: the guest is the running Windows, which lacks a #VE handler.
            // The driver has two safety mechanisms (suppress-#VE for all leaf items, and the info region marked busy at
            // factory), and if hardware is unsupported, the driver rejects startup directly rather than silently downgrading.
            bool enableVe = false,
            // enableVmFunc: Enable VMFUNC and EPTP switching. Disabled by default.
            // VMFUNC performs no CPL check, so enabling it exposes every domain in the EPTP list to
            // arbitrary Ring 3 code. Since domains can only be de-privileged, this is not an escalation
            // path, but it is a switch interface visible to the guest that the driver cannot observe.
            bool enableVmFunc = false,
            // enableLocalEpt: Provides each processor with a private EPT hierarchy.
            // It does not expose any new capabilities but ensures existing EPT views are safe with allow-once
            // authorization across multiple cores. The flip occurs only on the processor that retrieves the
            // exit. The cost is several pages per core and mutual exclusion with VMFUNC and nested VMX.
            bool enableLocalEpt = false,
            // enableEptpSwitch: Switch to the EPTP switching backend to install separated views. Disabled by default;
            // when disabled, behavior is byte-for-byte identical to the default backend (write-leaf + Monitor Trap Flag).
            // It introduces no new capabilities; it swaps the required hardware conditions: the default backend
            // requires MTF, which nested Hyper-V guests cannot obtain; this set only requires execute-only EPT leaves.
            // Thus, on machines missing MTF, only this can install the view—this is the sole reason to select it.
            // [Only allowed with PREPARE]: The driver decides on armament during prepare; the START_RESIDENT
            // whitelist does not accept this flag, and sending it will result in INVALID_REQUEST.
            // Intentionally do not filter by command here, so that incorrect commands fail loudly instead of
            // being silently dropped, which would mislead the caller into thinking the backend was switched.
            // Mutually exclusive with enableLocalEpt and enableVmFunc; the driver rejects any allocation before this point.
            bool enableEptpSwitch = false,
            // soakMilliseconds: Read-only for KSWORD_ARK_HVM_CONTROL_SOAK, indicating the duration
            // to remain resident; the driver clamps this value within the protocol-defined bounds.
            unsigned long soakMilliseconds = 0,
            bool hideHypervisor = false) const;
        HvmEptRuleResult controlHvmEptRule(
            unsigned long operation,
            unsigned long expectedGeneration,
            unsigned long ruleId,
            unsigned long deniedAccess,
            std::uint64_t physicalAddress,
            std::uint64_t pageCount,
            bool log,
            bool allowOnce,
            bool uiConfirmed,
            // enforce: Persistent denial (triggers injected #PF and continues resident); mutually exclusive with allowOnce.
            // On the driver side, allowOnce is discarded when storing storage rules.
            bool enforce = false) const;

        // HvmEptWatchRequest: Represents a single R-1 first-access attribution (Memory Watch) operation.
        //
        // Separating this from controlHvmEptRule avoids adding six additional parameters: watch uses the same IOCTL and the same rule
        // table (the handling semantics involve the newly added WATCH_ONCE flag), but its input consists of a different set—user-requested
        // address and length, and address type. The three parameters for the other handling types are meaningless for this case. Packing
        // everything into a single ten-parameter function would require every call site to pass a string of zeros for parameters it
        // doesn't use, and determining 'which zero corresponds to which parameter' is the most error-prone and hardest-to-notice aspect.
        struct HvmEptWatchRequest
        {
            // KSWORD_ARK_HVM_EPT_RULE_ADD / _REARM / _REMOVE / _WATCH_QUERY。
            unsigned long operation = 0;
            unsigned long expectedGeneration = 0;
            // Used for REARM / REMOVE; allocated and filled back by the driver during ADD.
            unsigned long watchId = 0;
            // User-selected access type, not yet normalized by architecture.
            unsigned long requestedAccess = 0;
            // KSWORD_ARK_HVM_WATCH_ADDRESS_*: for echo-back only.
            unsigned long addressKind = 0;
            // The actual 4 KiB physical page being monitored must be page-aligned.
            std::uint64_t physicalPage = 0;
            // The segment the user actually cares about, used to determine if a hit falls within the range.
            std::uint64_t requestedAddress = 0;
            std::uint64_t requestedLength = 0;
        };

        // controlHvmEptWatch: Executes a single watch operation.
        // Queries do not require a confirmation token; all other operations must include one, passing through the same rule path.
        HvmEptRuleResult controlHvmEptWatch(
            const HvmEptWatchRequest& request) const;
        // controlHvmCrPolicy: Configure, clear, or query control register policies.
        // The mask and CR3/DR interception switches are consumed during VMCS construction, so they must be set before the resident startup.
        HvmCrPolicyResult controlHvmCrPolicy(
            unsigned long operation,
            std::uint64_t cr0PinnedMask,
            std::uint64_t cr4PinnedMask,
            bool trackCr3,
            bool interceptDr,
            bool log,
            bool uiConfirmed) const;
        // controlHvmMsrPolicy: Install, remove, or query MSR policies.
        // - When action is LOG, write direction is not allowed; the driver will reject it (replaying WRMSR in the root has no fallback).
        // - Only the two index ranges covered by the bitmap can have policies set.
        HvmMsrPolicyResult controlHvmMsrPolicy(
            unsigned long operation,
            unsigned long policyId,
            unsigned long msrIndex,
            unsigned long access,
            unsigned long action,
            std::uint64_t fakeValue,
            bool uiConfirmed) const;
        // controlHvmDomain: Create, restrict, reset, or query EPT execution domains.
        // - Domains are published in the EPTP list; a guest can switch to one via a single VMFUNC instruction, which performs
        //   no CPL check—any ring 3 thread can switch. Thus, this interface provides only the 'privilege reduction' direction: a
        //   domain starts with full permissions identical to the default view, and can only have permissions removed afterward.
        // - RESTRICT uses EPT_ACCESS bits for deniedAccess; removing read permission requires processor support for
        //   translate execute-only, otherwise the driver rejects it.
        // - The domain cannot be modified while resident: running VCPUs may be in these tables.
        HvmDomainResult controlHvmDomain(
            unsigned long operation,
            unsigned long domainIndex,
            unsigned long expectedGeneration,
            std::uint64_t physicalAddress,
            std::uint64_t byteCount,
            unsigned long deniedAccess,
            bool uiConfirmed) const;
        // controlHvmView: Installs, removes, or queries EPT split views.
        // - shadow is used only when ADD is specified without the seed flag and must be page-aligned;
        // - Views and EPT rules cannot cover the same page; the driver rejects conflicting installations.
        HvmViewResult controlHvmView(
            unsigned long operation,
            unsigned long kind,
            unsigned long viewId,
            unsigned long expectedGeneration,
            std::uint64_t physicalAddress,
            const unsigned char* shadow,
            bool seedFromTarget,
            bool seedZero,
            bool log,
            bool uiConfirmed) const;
        // controlHvmProcess: R-1 level process handling—deny execution in the target address space.
        // - Freeze notes #PF, End notes #UD; freezing is reversible, ending is irreversible.
        // - guestLinearAddress specifies the page to be denied execution; it cannot be 0. The
        //   driver does not guess which page represents this process. A wrong guess results in denial
        //   on a page that never executes, which appears identical to success from the outside.
        // - Three prerequisites: CR3 tracking is enabled, the EPTP-switch backend is armed, and **the resident hypervisor is stopped during installation**.
        //   Revoke is not subject to the last restriction (it only modifies one field in the record).
        HvmProcessResult controlHvmProcess(
            unsigned long operation,
            unsigned long processId,
            std::uint64_t guestLinearAddress,
            bool uiConfirmed) const;
        // resolveHvmDirectoryBase: Maps an observed CR3 value to a specific PID.
        // - The sole source is guestCr3 from the memory monitor hit context;
        //   the UI uses it to translate "which address space" to "which process".
        // - The criterion is the register value the driver reads after
        //   attach. User mode cannot query it, so this must be done in R0;
        // The result is necessarily best-effort: the PID may be recycled, the address space may disappear between the hit
        //   and the query, kernel worker threads may run using someone else's address space, and under KVA Shadow, user mode
        //   and kernel mode do not use the same CR3. The resolvedScannedProcesses in the response distinguishes between
        //   'scanned but not found' and 'failed to scan any', so the UI must use distinct wording for these two cases.
        HvmProcessResult resolveHvmDirectoryBase(
            std::uint64_t directoryBase) const;
        // controlHvmInject: R-1 layer process injection — separated view + thread hijacking.
        // - This path is distinct from R0 injection (ZwAllocateVirtualMemory + ZwCreateThreadEx):
        //   it invokes no kernel APIs and adds no threads or memory regions to the target.
        // - guestLinearAddress is mandatory and must point to an address that **will be executed**. The driver
        //   searches backward from the page containing it for a gap; if none is found, it returns NO_CAVE.
        // - loadLibraryAddress is only used for DLL types. Within the same startup session, kernel32 has the same
        //   base address for all processes, so the value resolved in this process holds true for the target as well.
        // - Payload runs on a borrowed thread; must be position-independent, reentrant, and short.
        HvmInjectResult controlHvmInject(
            unsigned long operation,
            unsigned long processId,
            unsigned long injectType,
            std::uint64_t guestLinearAddress,
            std::uint64_t loadLibraryAddress,
            const unsigned char* payload,
            unsigned long payloadBytes,
            bool uiConfirmed) const;
        // hvmPlatform: Read-only platform calibration (CR4.CET / IA32_S_CET / IA32_U_CET /
        // FS/GS/KERNEL_GS base / EFER / CPUID.(7,0)）。
        //
        // The driver already had this IOCTL, but the client had no corresponding function. As a
        // result, CET, KVA shadow, and GS base were not visible in the GUI, even though each can
        // **Independent veto** on the path of "returning to user mode after exiting virtualization".
        //
        // Zero risk: does not enter VMX, allocate, or lock; callable in any lifecycle state.
        // Always check response.validMask first; if not all eight bits are set, the data is not fully initialized.
        HvmPlatformResult hvmPlatform() const;
        // hvmMemory: Executes a single R-1 memory operation (physical/virtual read-write, translation, or window query).
        // - payload is used only for write operations and must match the length of length.
        // - When processId is non-zero, the page table of that process is used and directoryBase is
        //   ignored. The driver internally attaches to the process to read CR3 and never returns CR3
        //   to user mode, as doing so would expose page table traversal capabilities to user space.
        // - When processId is 0 and directoryBase is 0, resolve using the current process page table;
        // - Reject fallback to MmCopyMemory path when requireWindow is true;
        // - Append processId and existingHandle to the end of the parameter list with default values: inserting parameters
        //   in the middle causes existing call sites to silently misalign (unsigned long can implicitly convert to bool).
        HvmMemoryResult hvmMemory(
            unsigned long operation,
            std::uint64_t address,
            std::uint64_t directoryBase,
            unsigned long length,
            const unsigned char* payload,
            bool requireWindow,
            bool uiConfirmed,
            unsigned long processId = 0UL,
            DriverHandle* existingHandle = nullptr) const;
        // querySlatIommuAudit: Read-only collection of evidence from EPT/NPT cross-views, DMAR/IVRS,
        // and public IOMMU interfaces. The includeMmio parameter only adds read-only register sampling.
        SlatIommuAuditResult querySlatIommuAudit(bool includeMmio) const;
        // querySystemTime/controlSystemTime：
        // - Query or control the continuous rate mapping of performance counters for the entire system.
        // - The UI passes only the command, multiplier, timing backend, parsing mode, expected generation, and confirmation status; it does not access the device directly.
        SystemTimeQueryResult querySystemTime() const;
        SystemTimeControlResult controlSystemTime(
            unsigned long command,
            unsigned long factor,
            unsigned long backend,
            unsigned long resolutionMode,
            unsigned long expectedGeneration,
            bool uiConfirmed) const;
        HvmEventResult queryHvmEvents(
            std::uint64_t afterSequence = 0,
            unsigned long maxRows = KSWORD_ARK_HVM_MAX_EVENT_ROWS,
            bool clear = false) const;
        // queryCpuHardwareSnapshot：
        // - Input: None; R0 executes only CPUID and processor count queries.
        // - Handling: Wraps IOCTL_KSWORD_ARK_QUERY_CPU_HARDWARE, parsing vendor/brand/family/model/feature mask.
        // - Returns: CpuHardwareSnapshotResult; unsupported=true if the old driver has not registered the IOCTL.
        CpuHardwareSnapshotResult queryCpuHardwareSnapshot() const;
        // queryPhysicalMemoryLayout：
        // - Input: None; R0 only reads the aggregated result of MmGetPhysicalMemoryRanges.
        // - Processing: Encapsulate IOCTL_KSWORD_ARK_QUERY_PHYSICAL_MEMORY_LAYOUT and parse physical memory range statistics.
        // - Returns: PhysicalMemoryLayoutResult; does not return any memory content.
        PhysicalMemoryLayoutResult queryPhysicalMemoryLayout() const;
        DriverForceUnloadResult forceUnloadDriver(const std::wstring& driverName, unsigned long flags = 0UL, unsigned long timeoutMilliseconds = 3000UL) const;
        DriverForceUnloadResult forceUnloadDriverByModuleBase(std::uint64_t moduleBase, const std::wstring& fallbackDriverName = std::wstring(), unsigned long flags = 0UL, unsigned long timeoutMilliseconds = 3000UL) const;
        // controlDriverCommunication：
        // - Input: Exact module base address, canonical name, DriverObject address returned by evidence scan, and action;
        // - Processing: Uniformly encapsulate independent communication control IOCTL; Dock UI does not directly access KswordARK device.
        // - Return: Status, MajorFunction mask, conflict information, and canonical DriverObject name.
        DriverCommunicationControlResult controlDriverCommunication(
            std::uint64_t moduleBase,
            const std::wstring& canonicalDriverName,
            unsigned long action,
            std::uint64_t expectedDriverObjectAddress = 0U) const;
        DriverCommunicationControlResult queryDriverCommunication(
            std::uint64_t moduleBase,
            const std::wstring& displayName = std::wstring()) const;
        DriverCommunicationControlResult blindDriverCommunication(
            std::uint64_t moduleBase,
            const std::wstring& canonicalDriverName,
            std::uint64_t expectedDriverObjectAddress) const;
        DriverCommunicationControlResult restoreDriverCommunication(
            std::uint64_t moduleBase,
            const std::wstring& displayName = std::wstring()) const;
        // Generic MajorFunction edits only encapsulate identity/CAS protocols, without imposing target or address policies.
        DriverDispatchControlResult controlDriverDispatch(
            std::uint64_t moduleBase,
            const std::wstring& canonicalDriverName,
            unsigned long action,
            unsigned long majorFunction,
            std::uint64_t expectedDriverObjectAddress = 0U,
            std::uint64_t expectedCurrentDispatchAddress = 0U,
            std::uint64_t desiredDispatchAddress = 0U,
            std::uint32_t expectedGeneration = 0U,
            bool uiConfirmed = false) const;
        DriverDispatchControlResult queryDriverDispatch(
            std::uint64_t moduleBase,
            const std::wstring& canonicalDriverName,
            unsigned long majorFunction,
            std::uint64_t expectedDriverObjectAddress = 0U) const;
        DriverDispatchControlResult applyDriverDispatch(
            std::uint64_t moduleBase,
            const std::wstring& canonicalDriverName,
            unsigned long majorFunction,
            std::uint64_t expectedDriverObjectAddress,
            std::uint64_t expectedCurrentDispatchAddress,
            std::uint64_t desiredDispatchAddress,
            std::uint32_t expectedGeneration) const;
        DriverDispatchControlResult restoreDriverDispatch(
            std::uint64_t moduleBase,
            const std::wstring& canonicalDriverName,
            unsigned long majorFunction,
            std::uint64_t expectedDriverObjectAddress,
            std::uint32_t expectedGeneration) const;
        DriverDispatchControlResult abandonDriverDispatch(
            std::uint64_t moduleBase,
            const std::wstring& canonicalDriverName,
            unsigned long majorFunction,
            std::uint64_t expectedDriverObjectAddress,
            std::uint32_t expectedGeneration) const;
        // Driver image control transmits only explicit identity, expected snapshot, and user confirmation; it does not restrict driver categories or address values.
        DriverImageControlResult controlDriverImage(
            std::uint64_t moduleBase,
            const std::wstring& canonicalDriverName,
            unsigned long action,
            unsigned long fieldMask,
            std::uint64_t expectedDriverObjectAddress,
            std::uint32_t expectedGeneration,
            const DriverImageValues& expectedValues,
            const DriverImageValues& desiredValues,
            std::uint64_t expectedLinkFlink = 0U,
            std::uint64_t expectedLinkBlink = 0U,
            bool restoreLink = false,
            bool uiConfirmed = false) const;
        // queryDriverImage: Retrieve a snapshot of five fields, loader chain, ownership records, and conflict locks.
        DriverImageControlResult queryDriverImage(
            std::uint64_t moduleBase,
            const std::wstring& canonicalDriverName,
            std::uint64_t expectedDriverObjectAddress = 0U) const;
        // applyDriverImageFields: Perform atomic CAS batch updates on expected values according to fieldMask.
        DriverImageControlResult applyDriverImageFields(
            std::uint64_t moduleBase,
            const std::wstring& canonicalDriverName,
            unsigned long fieldMask,
            std::uint64_t expectedDriverObjectAddress,
            std::uint32_t expectedGeneration,
            const DriverImageValues& expectedValues,
            const DriverImageValues& desiredValues) const;
        // hideDriverImage: unlinks only when Flink/Blink exact match occurs from PsLoadedModuleList.
        DriverImageControlResult hideDriverImage(
            std::uint64_t moduleBase,
            const std::wstring& canonicalDriverName,
            std::uint64_t expectedDriverObjectAddress,
            std::uint32_t expectedGeneration,
            std::uint64_t expectedLinkFlink,
            std::uint64_t expectedLinkBlink) const;
        // restoreDriverImage: Restores selected fields and can re-insert the load chain based on the original neighbor or current tail.
        DriverImageControlResult restoreDriverImage(
            std::uint64_t moduleBase,
            const std::wstring& canonicalDriverName,
            unsigned long fieldMask,
            bool restoreLink,
            std::uint64_t expectedDriverObjectAddress,
            std::uint32_t expectedGeneration) const;
        // abandonDriverImage: Retains all current dangerous values/chain states, permanently discarding only recovery records.
        DriverImageControlResult abandonDriverImage(
            std::uint64_t moduleBase,
            const std::wstring& canonicalDriverName,
            std::uint64_t expectedDriverObjectAddress,
            std::uint32_t expectedGeneration) const;
        // prepareMutation / commitMutation / rollbackMutation / queryMutationAudit：
        // - Input: Controlled transaction parameters or read-only audit query parameters.
        // - Handling: mutation IOCTLs are encapsulated only within ArkDriverClient; Dock UI does not call DeviceIoControl directly.
        // - Return: Fixed response or audit rows; UI can only display dry-run/audit/rollback, not expose arbitrary write buttons.
        MutationResponseResult prepareMutation(const MutationPrepareInput& input) const;
        MutationResponseResult commitMutation(std::uint64_t transactionId, unsigned long flags = KSWORD_ARK_MUTATION_FLAG_DRY_RUN) const;
        MutationResponseResult rollbackMutation(std::uint64_t transactionId, unsigned long flags = KSWORD_ARK_MUTATION_FLAG_DRY_RUN) const;
        MutationAuditResult queryMutationAudit(unsigned long flags = 0, unsigned long maxEntries = KSWORD_ARK_MUTATION_AUDIT_RING_CAPACITY, std::uint64_t startSequence = 0) const;
        IoResult setCallbackRules(const void* blobBytes, unsigned long blobSize) const;
        AsyncIoResult waitCallbackEventAsync(
            DriverHandle& handle,
            KSWORD_ARK_CALLBACK_WAIT_REQUEST& request,
            KSWORD_ARK_CALLBACK_EVENT_PACKET& eventPacket,
            OVERLAPPED* overlapped) const;
        CallbackRuntimeResult queryCallbackRuntimeState() const;
        IoResult setMinifilterBypassPids(const std::vector<std::uint32_t>& processIds) const;
        MinifilterBypassPidResult queryMinifilterBypassPids() const;
        // Process protection based on object manager handle callbacks: configuration is a
        // one-time full replacement; processes not in 'rules' immediately lose protection.
        IoResult setProcessProtectConfig(
            unsigned long globalFlags,
            const std::vector<KSWORD_ARK_PROCESS_PROTECT_RULE>& rules,
            const std::vector<KSWORD_ARK_PROCESS_PROTECT_TRUSTED>& trustedEntries,
            unsigned long scanIntervalMs = KSWORD_ARK_PROCESS_PROTECT_SCAN_INTERVAL_DEFAULT_MS) const;
        ProcessProtectStateResult queryProcessProtectState() const;
        IoResult answerCallbackEvent(const KSWORD_ARK_CALLBACK_ANSWER_REQUEST& request) const;
        IoResult cancelAllPendingCallbackDecisions() const;
        CallbackRemoveResult removeExternalCallback(const KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_REQUEST& request) const;
        CallbackRemoveExResult removeExternalCallbackEx(const KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_REQUEST& request) const;
        bool supportsExternalCallbackExperimentalUnlink() const;
        CallbackEnumResult enumerateCallbacks(unsigned long flags = KSWORD_ARK_ENUM_CALLBACK_FLAG_INCLUDE_ALL) const;
        KeyboardHotkeyEnumResult enumerateKeyboardHotkeys(std::uint32_t processId = 0, unsigned long flags = KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_SYSTEM | KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_DIAGNOSTICS, unsigned long maxEntries = 2048UL) const;
        KeyboardHotkeyMutationResult mutateKeyboardHotkey(
            const KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY& entry,
            unsigned long operation,
            unsigned long newModifiers = 0UL,
            unsigned long newVirtualKey = 0UL) const;

        KeyboardHookEnumResult enumerateKeyboardHooks(std::uint32_t processId = 0, unsigned long flags = KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_THREAD_HOOKS | KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_GLOBAL_HOOKS | KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_DIAGNOSTICS, unsigned long maxEntries = 2048UL) const;
        DriverCapabilitiesQueryResult queryDriverCapabilities() const;
        DynDataStatusResult queryDynDataStatus() const;
        DynDataFieldsResult queryDynDataFields() const;
        DynDataCapabilitiesResult queryDynDataCapabilities() const;
        DynDataProfileApplyResult applyDynDataProfile(const DynDataProfileApplyInput& profile) const;
        DynDataProfileApplyExResult applyDynDataProfileEx(const DynDataProfileApplyExInput& profile) const;
        // applyDynDataProfileV4 / queryDynDataV4*：
        // - Input: v4 profile generated by PDB extractor or a read-only query budget.
        // - Processing: Encapsulate DynData v4 IOCTL, validating fixed/variable-length response headers.
        // - Return: R3-friendly result; unsupported=true indicates the old driver has not registered the v4 IOCTL.
        DynDataV4ApplyResult applyDynDataProfileV4(const DynDataV4ApplyInput& profile) const;
        DynDataV4ModulesResult queryDynDataV4Modules(unsigned long maxRows = KSW_DYN_V4_MAX_MODULES) const;
        DynDataV4CapabilityGroupsResult queryDynDataV4CapabilityGroups(unsigned long maxRows = KSW_DYN_V4_MAX_MODULES * KSW_DYN_V4_MAX_CAPABILITY_GROUPS_PER_MODULE) const;
        DynDataV4MissingItemsResult queryDynDataV4MissingItems(unsigned long maxRows = KSW_DYN_V4_MAX_MISSING_SUMMARY) const;
        DynDataV4ItemsResult queryDynDataV4Items(unsigned long maxRows = KSW_DYN_V4_MAX_MODULES * KSW_DYN_V4_MAX_ITEMS_PER_MODULE) const;
        // queryNetwork*：
        // - Input: read-only network audit flags and maximum row count;
        // - Processing: Encapsulate TCP/UDP/WFP/NDIS PDB-backed audit IOCTLs.
        // - Return: variable-length audit rows; no disconnect, disable, detach, or rule modification performed.
        NetworkEndpointAuditResult queryNetworkTcpEndpoints(unsigned long flags = KSWORD_ARK_NETWORK_AUDIT_QUERY_FLAG_INCLUDE_ALL, unsigned long maxRows = KSWORD_ARK_NETWORK_AUDIT_MAX_REQUESTED_ROWS) const;
        NetworkEndpointAuditResult queryNetworkUdpEndpoints(unsigned long flags = KSWORD_ARK_NETWORK_AUDIT_QUERY_FLAG_INCLUDE_ALL, unsigned long maxRows = KSWORD_ARK_NETWORK_AUDIT_MAX_REQUESTED_ROWS) const;
        NetworkWfpInventoryResult queryNetworkWfpInventory(unsigned long flags = KSWORD_ARK_NETWORK_AUDIT_QUERY_FLAG_INCLUDE_ALL, unsigned long maxRows = KSWORD_ARK_NETWORK_AUDIT_MAX_REQUESTED_ROWS) const;
        NetworkWfpEventResult queryNetworkWfpEvents(std::uint64_t afterSequence, unsigned long maxRows = KSWORD_ARK_NETWORK_WFP_EVENT_DEFAULT_REQUESTED_ROWS) const;
        NetworkTrafficCaptureControlResult controlNetworkTrafficCapture(bool enabled) const;
        NetworkTrafficPacketResult queryNetworkTrafficPackets(std::uint64_t afterSequence, unsigned long maxRows = KSWORD_ARK_NETWORK_TRAFFIC_DEFAULT_REQUESTED_ROWS) const;
        NetworkNdisChainResult queryNetworkNdisChain(unsigned long flags = KSWORD_ARK_NETWORK_AUDIT_QUERY_FLAG_INCLUDE_ALL, unsigned long maxRows = KSWORD_ARK_NETWORK_AUDIT_MAX_REQUESTED_ROWS) const;
        // File/filter/storage audit wrappers：
        // - Input: read-only flags, budget, and optional volume path;
        // - Processing: Encapsulate Minifilter/Storage/BitLocker/MountMgr/Filesystem integrity IOCTLs;
        // - Return: An array of protocol rows; BitLocker wrapper does not return key material.
        MinifilterInventoryResult queryMinifilterInventory(unsigned long flags = KSWORD_ARK_MINIFILTER_INVENTORY_FLAG_INCLUDE_ALL, unsigned long maxRows = 256UL) const;
        StorageVolumeStackAuditResult queryVolumeStackAudit(const std::wstring& volumePath = std::wstring(), unsigned long flags = KSWORD_ARK_STORAGE_AUDIT_FLAG_INCLUDE_DEFAULT, unsigned long maxRows = KSWORD_ARK_STORAGE_DEFAULT_MAX_ROWS, unsigned long maxDepth = KSWORD_ARK_STORAGE_DEFAULT_STACK_DEPTH) const;
        StorageBitlockerFveAuditResult queryBitlockerFveAudit(const std::wstring& volumePath = std::wstring(), unsigned long flags = KSWORD_ARK_STORAGE_AUDIT_FLAG_INCLUDE_DEFAULT, unsigned long maxRows = KSWORD_ARK_STORAGE_DEFAULT_MAX_ROWS, unsigned long maxDepth = KSWORD_ARK_STORAGE_DEFAULT_STACK_DEPTH) const;
        StorageMountMgrMappingAuditResult queryMountMgrMappingAudit(const std::wstring& volumePath = std::wstring(), unsigned long flags = KSWORD_ARK_STORAGE_AUDIT_FLAG_INCLUDE_DEFAULT, unsigned long maxRows = KSWORD_ARK_STORAGE_DEFAULT_MAX_ROWS, unsigned long maxDepth = KSWORD_ARK_STORAGE_DEFAULT_STACK_DEPTH) const;
        StorageFilesystemIntegrityAuditResult queryFilesystemIntegrityAudit(const std::wstring& volumePath = std::wstring(), unsigned long flags = KSWORD_ARK_STORAGE_AUDIT_FLAG_INCLUDE_DEFAULT, unsigned long maxRows = KSWORD_ARK_STORAGE_DEFAULT_MAX_ROWS, unsigned long maxDepth = KSWORD_ARK_STORAGE_DEFAULT_STACK_DEPTH) const;
        // query/read/writeRawDisk：
        // - Input: Physical disk number, explicit backend, alignment offset/length, and safety confirmation flag;
        // - Processing: Encapsulate three layers of disk IOCTLs only within ArkDriverClient; do not access control devices directly in Dock.
        // - Returns: R0 capabilities, bytes read, or write results after security policy auditing.
        RawDiskBackendResult queryRawDiskBackend(
            unsigned long diskNumber,
            unsigned long requestedBackend = 0UL,
            unsigned long flags = 0UL) const;
        RawDiskReadResult readRawDisk(
            unsigned long diskNumber,
            unsigned long backend,
            std::uint64_t offset,
            unsigned long length,
            unsigned long flags = 0UL) const;
        RawDiskWriteResult writeRawDisk(
            unsigned long diskNumber,
            unsigned long backend,
            std::uint64_t offset,
            const std::vector<std::uint8_t>& bytes,
            unsigned long flags) const;
        // Security audit wrappers：
        // - Input: Read-only flags or row budget;
        // - Processing: Encapsulate Security/CI/VBS/Hyper-V/AppControl IOCTLs.
        // - Returns: fixed or variable-length result without modifying any security policies.
        SecurityStatusAuditResult querySecurityStatus(unsigned long flags = 0UL) const;
        DriverTrustViewAuditResult queryDriverTrustView(unsigned long flags = KSWORD_ARK_DRIVER_TRUST_QUERY_FLAG_DEFAULT, unsigned long maxEntries = KSWORD_ARK_SECURITY_AUDIT_DEFAULT_DRIVER_ROWS) const;
        HyperVSummaryAuditResult queryHyperVSummary() const;
        AppControlStatusAuditResult queryAppControlStatus() const;
        // Win32K GUI audit wrappers：
        // - Input: session/pid/tid filters and maximum row count.
        // - Processing: Encapsulate the win32k PDB read-only snapshot IOCTL.
        // - Returns: Window, GUI thread, hotkey, and hook diagnostic lines; does not install or remove hooks.
        Win32kProfileStatusResult queryWin32kProfileStatus(unsigned long flags = KSWORD_ARK_WIN32K_QUERY_FLAG_INCLUDE_ALL, unsigned long sessionId = 0UL, unsigned long maxEntries = KSWORD_ARK_WIN32K_DEFAULT_MAX_ENTRIES) const;
        Win32kWindowsResult queryWin32kWindows(unsigned long flags = KSWORD_ARK_WIN32K_QUERY_FLAG_INCLUDE_ALL, unsigned long sessionId = 0UL, unsigned long processId = 0UL, unsigned long threadId = 0UL, unsigned long maxEntries = KSWORD_ARK_WIN32K_DEFAULT_MAX_ENTRIES) const;
        Win32kGuiThreadsResult queryWin32kGuiThreads(unsigned long flags = KSWORD_ARK_WIN32K_QUERY_FLAG_INCLUDE_ALL, unsigned long sessionId = 0UL, unsigned long processId = 0UL, unsigned long threadId = 0UL, unsigned long maxEntries = KSWORD_ARK_WIN32K_DEFAULT_MAX_ENTRIES) const;
        Win32kHotkeysPdbResult queryWin32kHotkeysPdb(unsigned long flags = KSWORD_ARK_WIN32K_QUERY_FLAG_INCLUDE_ALL, unsigned long sessionId = 0UL, unsigned long processId = 0UL, unsigned long threadId = 0UL, unsigned long maxEntries = KSWORD_ARK_WIN32K_DEFAULT_MAX_ENTRIES) const;
        Win32kHooksPdbResult queryWin32kHooksPdb(unsigned long flags = KSWORD_ARK_WIN32K_QUERY_FLAG_INCLUDE_ALL, unsigned long sessionId = 0UL, unsigned long processId = 0UL, unsigned long threadId = 0UL, unsigned long maxEntries = KSWORD_ARK_WIN32K_MESSAGE_HOOK_DEFAULT_MAX_ENTRIES) const;
        Win32kTimersResult queryWin32kTimers(unsigned long flags = KSWORD_ARK_WIN32K_QUERY_FLAG_INCLUDE_ALL, unsigned long sessionId = 0UL, unsigned long processId = 0UL, unsigned long threadId = 0UL, unsigned long maxEntries = KSWORD_ARK_WIN32K_DEFAULT_MAX_ENTRIES) const;
        Win32kEventHooksResult queryWin32kEventHooks(unsigned long flags = KSWORD_ARK_WIN32K_QUERY_FLAG_INCLUDE_ALL, unsigned long sessionId = 0UL, unsigned long processId = 0UL, unsigned long threadId = 0UL, unsigned long maxEntries = KSWORD_ARK_WIN32K_DEFAULT_MAX_ENTRIES) const;
        Win32kWindowRuntimeDetailResult queryWin32kWindowDetail(std::uint64_t hwnd, unsigned long processId = 0UL, unsigned long threadId = 0UL, unsigned long flags = KSWORD_ARK_WIN32K_QUERY_FLAG_INCLUDE_DIAGNOSTICS) const;
        // Device/kernel-object audit wrappers：
        // - Input: Read-only profile, target name, or CID/IPC parameters;
        // - Handling: Encapsulate DeviceAudit, CID, KernelObjectSummary, and IPCSummary IOCTLs.
        // - Returns: Diagnostic lines or a fixed summary; does not perform DKOM, unloading, or unbinding.
        DeviceAuditResult queryDeviceStackAudit(const std::wstring& targetName = std::wstring(), unsigned long maxRows = KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ROWS, unsigned long maxAttachedDepth = KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ATTACHED_DEPTH) const;
        DeviceAuditResult queryInputStackAudit(const std::wstring& targetName = std::wstring(), unsigned long maxRows = KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ROWS, unsigned long maxAttachedDepth = KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ATTACHED_DEPTH) const;
        DeviceAuditResult queryUsbTopologyAudit(const std::wstring& targetName = std::wstring(), unsigned long maxRows = KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ROWS, unsigned long maxAttachedDepth = KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ATTACHED_DEPTH) const;
        DeviceAuditResult queryGpuDisplayWatchdogAudit(const std::wstring& targetName = std::wstring(), unsigned long maxRows = KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ROWS, unsigned long maxAttachedDepth = KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ATTACHED_DEPTH) const;
        // queryPlatformAudit：
        // - Input: HAL/WDF scope and maximum row count;
        // - Processing: Retrieve evidence only via controlled IOCTLs after structure signature and module boundary validation.
        // - Returns: Explicitly unsupported or partial for unknown system layouts; does not attempt raw offset scanning.
        PlatformAuditResult queryPlatformAudit(unsigned long scopeMask = KSWORD_ARK_PLATFORM_AUDIT_SCOPE_ALL, unsigned long maxRows = KSWORD_ARK_PLATFORM_DEFAULT_MAX_ROWS) const;
        // editPlatformAuditEntry：
        // - Input: scope/index/table/current from the snapshot and the new non-zero function address.
        //   scope accepts only four HAL sub-tables and WDF_FUNCTIONS; WDF_CALLBACKS has no writable slots.
        // - Processing: Only use FILE_WRITE_ACCESS control protocol requests to reposition and atomically replace in R0.
        // - Return: Evidence for table/slot/previous value/current value; does not expose arbitrary kernel address writes.
        PlatformAuditControlResult editPlatformAuditEntry(unsigned long scope, unsigned long entryIndex, std::uint64_t tableAddress, std::uint64_t expectedValue, std::uint64_t newValue, bool uiConfirmed) const;
        // queryI8042Audit：
        // - Input: Maximum row budget;
        // - Processing: Obtain the verified key-mouse endpoint via a dedicated read-only IOCTL to get the precise version descriptor.
        // - Return: Unknown i8042prt image explicitly unsupported; do not fall back to CallbackEnum.
        I8042AuditResult queryI8042Audit(unsigned long maxRows = KSWORD_ARK_I8042_DEFAULT_MAX_ROWS) const;
        // queryHwidDispatchState / controlHwidDispatch：
        // - Input: No input for query, or a complete HWID Dispatch control packet;
        // - Handling: Only access new IOCTLs via ArkDriverClient; Dock does not directly call DeviceIoControl.
        // - Returns: HwidDispatchResult, preserving the original R0 state and unsupported flag.
        HwidDispatchResult queryHwidDispatchState() const;
        HwidDispatchResult controlHwidDispatch(const KSWORD_ARK_HWID_DISPATCH_CONTROL_REQUEST& request) const;
        // queryCpuPowerState / controlCpuPower：
        // - Query Intel RAPL/HWP/Turbo whitelist capabilities, or submit a structured control packet with an expected snapshot.
        // - Dock does not open devices directly and does not expose arbitrary MSR write entries.
        CpuPowerResult queryCpuPowerState() const;
        CpuPowerResult controlCpuPower(const KSWORD_ARK_CPU_POWER_CONTROL_REQUEST& request) const;
        CidTableAuditResult enumCidTable(unsigned long flags = KSWORD_ARK_CID_ENUM_FLAG_INCLUDE_ALL, unsigned long maxEntries = 4096UL, unsigned long maxVisitCount = 65536UL, unsigned long startCid = 0UL, unsigned long endCid = 0UL) const;
        ObjectTypeTableAuditResult enumObjectTypeTable(unsigned long flags = KSWORD_ARK_OBJECT_TYPE_TABLE_FLAG_INCLUDE_ALL, unsigned long maxEntries = KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS, unsigned long startIndex = 0UL) const;
        KernelObjectSummaryAuditResult queryKernelObjectSummary(unsigned long targetKind, unsigned long cidValue = 0UL, std::uint64_t expectedObjectAddress = 0ULL, unsigned long flags = KSWORD_ARK_OBJECT_SUMMARY_FLAG_INCLUDE_ALL) const;
        IpcSummaryAuditResult queryIpcSummary(unsigned long processId = 0UL, std::uint64_t handleValue = 0ULL, unsigned long flags = KSWORD_ARK_IPC_QUERY_FLAG_INCLUDE_ALL, unsigned long maxEntries = 64UL) const;
    };
}
