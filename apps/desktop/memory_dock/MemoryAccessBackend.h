#pragma once

// ============================================================
// MemoryAccessBackend.h
// Purpose:
// - Provide a unified backend selection layer for all read/write entry points of "memory" pages.
// - The standard backend uses the driver's existing MmCopyMemory / MmMapIoSpaceEx channels;
// - The DDMA backend uses bus mastering DMA via the disk controller, bypassing CPU page tables and SLAT/EPT.
//
// Why is this centralized in this single file:
// - All four pages (memory search, memory viewer, driver memory read/write, system memory audit) must support switching backends.
//   If each page independently checks DDMA availability, the criteria will diverge. Missing scratch-sector
//   confirmation or the kernel-debugging state in even one path can cause a bugcheck or a dirty sector.
//   Therefore, availability criteria, slicing rules, and error messages are implemented only here.
//
// How virtual address channels work:
// - DDMA itself can only read/write by physical address, so virtual address requests invoke the existing VA
//   → PA translation (IOCTL_KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS) page-by-page in R0 to obtain the physical
//   page before performing DMA. The translation backend is shared; this file implements no page table parsing.
// ============================================================

#include <QByteArray>
#include <QString>

#include <cstdint>
#include <string>

namespace ksword::memory_backend
{
    // MemoryAccessBackend：
    // - Identify which channel a memory access operation takes;
    // - The order of enumeration values must match the order of entries in the "Access Backend" dropdown for each page; the UI converts based on index.
    enum class MemoryAccessBackend : int
    {
        kUserMode = 0,       // R3: ReadProcessMemory / WriteProcessMemory, without going through the driver.
        kStandardDriver,     // R0: Driver channel uses MmCopyVirtualMemory / MmMapIoSpaceEx.
        kHvm,                // R0 private page table window: rewrite page table entries to point to target frames without invoking the memory manager.
        kDdma                // Direct Disk Memory Access: ATA / SCSI PASS_THROUGH_DIRECT + DMA.
    };

    // The HVM entry is independent in this specific way: **not** "bypassing EPT".
    //
    // Named 'ring -1', but the implementation (drivers/ark/src/features/hvm/hvm_memory.c)
    // runs in a PASSIVE_LEVEL driver context without entering VMX root. It reserves a private
    // page, rewrites its page table entry to point to the target frame, accesses it, then
    // restores it—so it **remains subject to SLAT/EPT constraints**, grouping with R3/R0.
    //
    // Its independence is a separate matter: the entire path calls no documented memory manager routines
    // (MmCopyMemory / MmCopyVirtualMemory), so **other drivers hooking those routines cannot hook it**. R0
    // and HVM returning different answers for the same address indicates the memory manager has been hooked;
    // This is unrelated to the SLAT redirection described in the divergence between DDMA and the CPU side; do not conflate the two.
    //
    // A state that must be passed to the caller: when self-mapped base address discovery fails (window falls into
    // large-page mapping, layout unrecognized), the driver **falls back to MmCopyMemory** and sets usedDirectWindow to 0.
    // That read was exactly the path we wanted to avoid; comparing it with R0 proves nothing.

    // Why must R3 and R0 be two parallel options instead of a single 'standard channel' entry:
    // The failure modes of the two are entirely different. R3 is constrained by handle permissions, process protection, and VAD
    //   readability; R0 uses MmCopyVirtualMemory, bypassing the first two but still subject to page table constraints. The fact that the
    //   same address can be read via one method but not the other serves as a criterion—synthesizing a single entry erases this criterion.
    // - The original viewer's 'standard driver channel' is nominally R0 but implemented via ReadProcessMemory,
    //   whereas the same enum value uses the actual driver on the other three pages. When names and behaviors
    //   are inconsistent, the failure reason reported to the user does not point to the root cause.

    // DdmaSession：
    // - A single DDMA configuration, produced by the "DDMA" sub-page, is shared across four pages.
    // - DDMA access is only allowed when all fields are ready; see isDdmaUsable for the criteria.
    struct DdmaSession
    {
        bool configured = false;            // Successfully completed one capability detection.
        std::uint32_t diskIndex = 0;        // The index of the target disk in the \Driver\Disk device list.
        std::wstring deviceName;            // Device name recorded during probing, used to verify later that the same disk is being used.
        std::uint64_t scratchLba = 0;       // Temporary sector start LBA.
        bool scratchLbaValid = false;       // The user explicitly filled in an LBA. Note that LBA 0 is valid, so 0 cannot be used as a sentinel.
        bool scratchAcknowledged = false;   // User confirmation that these sectors can be temporarily overwritten.
        bool kernelDebuggerEnabled = false; // Kernel debugging is enabled on this host; DDMA will cause a BSOD on such machines.
        std::uint32_t transferBytes = 0;    // R0 reports a single DMA transfer length, typically one page.
        std::uint32_t scratchSectorCount = 0; // R0 reported scratch sector count.
    };

    // AccessOutcome：
    // - unified result model for a single read or write operation;
    // - ok must be true to indicate data availability or write completion; other fields are for status bar and alert display.
    struct AccessOutcome
    {
        bool ok = false;                    // Overall success.
        QString failureText;                // Failure reason; already user-facing text.
        QByteArray data;                    // Read result; write path is empty.
        std::uint64_t bytesDone = 0;        // Actual bytes completed; on failure, indicates the amount completed before the failure.
        bool forceRequired = false;         // R0 mode requires the force flag; caller should obtain user consent before retrying.

        // scratchDirty: The scratch sector could not be restored, leaving a dirty sector on the disk.
        // This is the only state that requires an alert even when the operation succeeds; do not check only in the failure branch.
        bool scratchDirty = false;
        // lostUpdateWindow: The write operation used read-modify-write, leaving
        // a 4KB-granularity overwrite window for other bytes in the same page.
        bool lostUpdateWindow = false;
        // partial: Only partially completed; when reading, the data length will be less than the requested length.
        bool partial = false;
    };

    // ========================================================
    // Process-level DDMA session ("resident virtual sector").
    // ========================================================
    //
    // Why process-level instead of attached to the DDMA page:
    // - The meaning of "resident" is that this configuration is valid for the entire program, not a private state of a single page;
    // - The permission indicator in the top-right corner is owned by mainWindow, while the four backend dropdowns for memory
    //   pages are owned by MemoryDock. Both must read the same facts. If each asks the other for the state of its control,
    //   they may receive inconsistent answers during events like Dock layout restoration or before pages are constructed.
    //
    // There is only one writer: the DDMA sub-page. All other locations are read-only only.

    // currentDdmaSession：
    // - Purpose: Read the current process-level DDMA session.
    // - Returns: a const reference; returns an empty 'unconfigured' session if no session is configured.
    const DdmaSession& currentDdmaSession();

    // setCurrentDdmaSession：
    // - Purpose: Configure sessions for DDMA sub-page writes.
    // - Parameter session: The new session.
    // - Note: This is the sole write entry point; no other pages may call it.
    void setCurrentDdmaSession(const DdmaSession& session);

    // ddmaSessionGeneration：
    // - Purpose: Return the session generation, which increments with each write.
    // - Note: The polling caller (the top-right indicator) uses this to decide whether to redraw, avoiding a field-by-field comparison.
    std::uint64_t ddmaSessionGeneration();

    // backendDisplayName：
    // - Input: backend enumeration
    // - Return: short name used for the combo box and status bar.
    QString backendDisplayName(MemoryAccessBackend backend);

    // ddmaTransferBytes：
    // - Purpose: Return the number of bytes transferred per DDMA DMA operation, defining the slice and verification granularity.
    // - Note: The caller should align addresses and lengths according to this value; there is no
    //   need to include the driver protocol header file in their compilation unit just for a constant.
    std::uint32_t ddmaTransferBytes();

    // isDdmaUsable：
    // - Input: Current DDMA session configuration;
    // - Handling: Check sequentially in the order of "detected → kernel debugging not enabled → LBA
    //   filled → overwrite confirmed", providing a directly displayable Chinese reason for each step.
    // - Return: true indicates a DDMA access can be initiated; if false, reasonOut explains the missing step.
    bool isDdmaUsable(const DdmaSession& session, QString* reasonOut);

    // isHvmMemoryUsable：
    // - Processing: Send a single QUERY_WINDOW request; it does not access any memory and only answers whether the private window exists.
    // - Return: true indicates the HVM channel is usable; if false, reasonOut explains the blocking step.
    // - Note: Returning true only means "this channel is usable," not that every access uses the private window;
    //   when the window isn't marked, the driver falls back, and that specific access has usedDirectWindow = 0.
    bool isHvmMemoryUsable(QString* reasonOut);

    // readPhysical：
    // - Input: Backend, DDMA session, physical start address, and length;
    // - Processing: Standard backend performs direct driver calls up to 64KB per operation; DDMA backend slices by page and performs DMA per page.
    // - Return: AccessOutcome, where data contains the read bytes.
    AccessOutcome readPhysical(
        MemoryAccessBackend backend,
        const DdmaSession& session,
        std::uint64_t physicalAddress,
        std::uint64_t lengthBytes);

    // writePhysical：
    // - Input: backend, DDMA session, physical start address, bytes to write, and whether mandatory write consent is obtained;
    // - Handling: Both backends slice according to their respective single-operation limits; non-page-aligned DDMA writes trigger R0.
    //   read-modify-write; the lostUpdateWindow in the result is reported accurately;
    // - Return: AccessOutcome; if forceRequired is true, the caller should prompt for confirmation and retry with force.
    AccessOutcome writePhysical(
        MemoryAccessBackend backend,
        const DdmaSession& session,
        std::uint64_t physicalAddress,
        const QByteArray& bytes,
        bool forceApproved);

    // readVirtual：
    // - Input: backend, DDMA session, target PID (0 indicates kernel address space), virtual address, and length;
    // - Handling: The standard backend directly invokes R0 virtual reads. The DDMA backend translates VA to PA
    //   page-by-page for DMA; pages that fail translation are treated as unreadable, zero-filled, and marked as partial.
    // - Return: AccessOutcome, where data length equals the request length (zero for unreadable pages).
    AccessOutcome readVirtual(
        MemoryAccessBackend backend,
        const DdmaSession& session,
        std::uint32_t processId,
        std::uint64_t virtualAddress,
        std::uint64_t lengthBytes);

    // writeVirtual：
    // - Input: backend, DDMA session, target PID (0 indicates kernel address space),
    //   virtual address, bytes to write, and whether forced write consent has been obtained.
    // - Processing: DDMA backend performs page-by-page translation followed by DMA write; if any page fails to translate to a physical
    //   address, the operation fails immediately without silent fallback to skip that page and continue writing subsequent pages.
    // - Return: AccessOutcome.
    AccessOutcome writeVirtual(
        MemoryAccessBackend backend,
        const DdmaSession& session,
        std::uint32_t processId,
        std::uint64_t virtualAddress,
        const QByteArray& bytes,
        bool forceApproved);

    // isKernelVirtualAddress：
    // - Input: virtual address;
    // - Return: Whether the address falls within the x64 kernel high half. Both backends use this check to decide whether
    //   to attach the KERNEL_ADDRESS flag to R0 requests, avoiding the need to write thresholds for each page individually.
    bool isKernelVirtualAddress(std::uint64_t virtualAddress);
}
