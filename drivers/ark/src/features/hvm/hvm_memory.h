/*++

Module Name:

    hvm_memory.h

Abstract:

    Declares ring -1 memory access: a private page-table window that reaches
    physical memory without calling the documented memory-manager routines.

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL entry.

--*/

#pragma once

#include "hvm_runtime.h"

EXTERN_C_START

/*
 * Reserve the private window and discover the page-table self-map.  Failure is
 * not fatal: every access falls back to MmCopyMemory and reports that the
 * hook-free path was unavailable.
 */
VOID
kswordArkHvmMemoryInitialize(
    VOID
    );

/* Release the private window and restore its original page-table entry. */
VOID
kswordArkHvmMemoryShutdown(
    VOID
    );

/*
 * Publish the page-table self-map base this module discovered.
 *
 * Returns FALSE when discovery never succeeded, in which case no caller may
 * derive a page-table entry address.
 *
 * Exposed so the VM-exit-safe windows do not repeat the discovery.  The slot
 * is randomized per boot but the same for every address space, and finding it
 * costs a probe of up to 512 candidates plus MmIsAddressValid on each - work
 * that belongs on an initialization path exactly once.  Having a second copy
 * of the search would also mean a second chance to get the sign-extension
 * masking wrong, and that mistake does not fault: it silently edits an entry
 * that maps nothing.
 */
BOOLEAN
kswordArkHvmMemorySelfMapBase(
    _Out_ ULONGLONG* selfMapBase
    );

/* Execute one versioned ring -1 memory request. */
NTSTATUS
kswordArkHvmMemoryExecute(
    _In_ const KSWORD_ARK_HVM_MEMORY_REQUEST* request,
    _Out_ KSWORD_ARK_HVM_MEMORY_RESPONSE* response
    );

/*
 * Resolve the current active hierarchical base address for a process.
 *
 * Attach to the process to read registers instead of reading EPROCESS's DirectoryTableBase:
 * that offset is not public in Windows; hardcoding it will cause **silent** misreads after
 * the next update—a wrong CR3 can still traverse the table and produce a physical address.
 *
 * Exported for use by hvm_process. Having it write its own walker would create a redundant and divergent implementation.
 */
NTSTATUS
kswordArkHvmMemoryResolveProcessDirectoryBase(
    _In_ ULONG processId,
    _Out_ ULONGLONG* directoryBase
    );

/*
 * Translate a virtual address using the given hierarchy base. Large pages are resolved at the terminating level of
 * the page walk, so the physical addresses derived from 2 MiB and 1 GiB mappings match the processor's calculation.
 */
/*
 * LeafEntry receives the entry that terminated this table walk; pass NULL to omit this output.
 *
 * R-1: When injecting across pages to find a gap, this must be checked: candidate pages must be executable (NX bit clear) and
 * user-mode (U/S bit set). Determining this from a physical address alone is impossible. Placing the payload in non-executable
 * memory causes the injection to appear successful but never trigger—indistinguishable from a successful injection from the outside.
 */
NTSTATUS
kswordArkHvmMemoryTranslate(
    _In_ ULONGLONG directoryBase,
    _In_ ULONGLONG virtualAddress,
    _Out_ ULONGLONG* physicalAddress,
    _Out_opt_ ULONGLONG* leafEntry
    );

EXTERN_C_END
