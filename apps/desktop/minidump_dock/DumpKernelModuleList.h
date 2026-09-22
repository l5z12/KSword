#pragma once

// ============================================================
// DumpKernelModuleList.h
// Purpose:
// - Traverse the KLDR_DATA_TABLE_ENTRY doubly linked list via PsLoadedModuleList from
//   the dump header to reconstruct the "loaded driver list" for full/kernel memory dumps.
// - Small dumps (DumpType 4) include the TRIAGE driver table natively and do not need to traverse this path; full/kernel dumps
//   lack this table, so without traversing the linked list, no driver names can be retrieved, making attribution impossible.
// Why PDB is not needed:
// - The address of `PsLoadedModuleList` is provided directly by the dump header (offset 0x20 in
//   `DUMP_HEADER64`). The field layout of `KLDR_DATA_TABLE_ENTRY` has remained stable on x64 since
//   Vista. Consequently, the entire chain relies solely on public layouts and requires no symbol files.
// Reliability policy:
// - Perform per-item structural self-validation (base address page alignment, location in kernel space, reasonable
//   image size, valid UNICODE_STRING name). Skip entries that fail validation; abort and report truthfully on
//   consecutive failures or cycles, preferring to omit data rather than output seemingly reasonable garbage.
// Call method:
// - After constructing the PageTableWalker, KernelDumpParser calls enumerateLoadedDrivers.
// ============================================================

#include "DumpPageTable.h"

namespace ks::minidump
{
    // KernelModuleScanResult: statistics from a single driver list traversal.
    struct KernelModuleScanResult
    {
        bool listReadable = false;      // listReadable: Whether the list head was successfully read.
        int acceptedCount = 0;          // acceptedCount: Number of entries that passed validation and were produced.
        int rejectedCount = 0;          // rejectedCount: Count of entries discarded due to structure validation failure.
        bool truncated = false;         // truncated: Whether the operation was prematurely terminated due to a limit or a cycle.
        QString stopReason;             // stopReason: Chinese reason for premature termination; empty if completed normally.
    };

    // enumerateLoadedDrivers traverses PsLoadedModuleList to produce a driver list.
    // Accepts walker (virtual address translator), listHeadAddress (dump header field 0x20), and
    // modulesOut (appended module table; existing entries are preserved and deduplicated by base address).
    // Return: traversal statistics. Function performs read-only dump; does not modify walker.
    KernelModuleScanResult enumerateLoadedDrivers(
        const PageTableWalker& walker,
        std::uint64_t listHeadAddress,
        std::vector<ModuleEntry>& modulesOut);
}
