/*++

Module Name:

    hvm_ept_local.h

Abstract:

    Declares per-processor private EPT hierarchies.  A private hierarchy is
    the shared one with the few tables on the path to a flippable leaf
    replaced by private copies, so that writing that leaf reaches only the
    processor walking it.

Environment:

    Kernel-mode Driver Framework.

--*/

#pragma once

#include "hvm_internal.h"

#if defined(_M_AMD64)

/*
 * Bound the flippable leaves one private hierarchy mirrors.
 *
 * Every leaf costs one private page table per processor, so this bound is
 * what keeps a 128-way machine affordable.  It is deliberately small: the
 * mechanism exists for a handful of hooked or cloaked pages, not for a
 * general-purpose second address space.
 */
#define KSW_HVM_MAX_LOCAL_LEAVES 8UL
/*
 * Bound the paging structures one processor may fork.
 *
 * Worst case per processor is one PDPT and one page directory per leaf plus
 * the leaf tables themselves, which for eight leaves that share no parent is
 * 8 + 8 + 8 = 24.  A set that needs more is refused rather than truncated.
 */
#define KSW_HVM_MAX_LOCAL_TABLES 24UL
/*
 * Bound the total pages every processor together may consume.
 *
 * This is checked against KswordArkHvmEptLocalPageCost before the first
 * allocation, so an inadmissible topology is refused while nothing has been
 * allocated rather than half-way through.
 */
#define KSW_HVM_MAX_LOCAL_EPT_PAGES 2048ULL

/* Tag which level of the hierarchy a forked table sits at. */
#define KSW_HVM_LOCAL_LEVEL_PDPT 1UL
#define KSW_HVM_LOCAL_LEVEL_PD   2UL
#define KSW_HVM_LOCAL_LEVEL_PT   3UL

/* Track one paging structure this processor forked from the shared tree. */
typedef struct KswHvmEptLocalTable
{
    /* Retain the shared table this one was copied from. */
    PVOID sharedVirtual;
    /* Retain the private copy this processor walks instead. */
    PVOID privateVirtual;
    /* Retain the private physical address published into the parent entry. */
    PHYSICAL_ADDRESS privatePhysical;
    /* Record the level, which decides how the entry is rebased. */
    ULONG level;
    /* Keep the structure explicitly initialized across architectures. */
    ULONG reserved0;
} KswHvmEptLocalTable;

/* Own one processor's private view of the EPT hierarchy. */
typedef struct KswHvmEptLocal
{
    /* Record whether this record describes a built hierarchy. */
    BOOLEAN active;
    /* Keep the 64-bit members naturally aligned. */
    UCHAR reserved0[7];
    /*
     * Retain the EPT pointer this processor loads.  It is the shared pointer
     * with only the root address replaced, so it is accepted by VM entry
     * exactly when the shared one is.
     */
    ULONGLONG eptPointer;
    /* Retain this processor's own root table. */
    PVOID pml4Virtual;
    /* Retain the root physical address encoded into EptPointer. */
    PHYSICAL_ADDRESS pml4Physical;
    /*
     * Retain the single allocation backing every private table.
     *
     * One nonpaged allocation per processor rather than one per table: the
     * teardown path runs from a power callback where MmFreeContiguousMemory
     * would be illegal, and a fragmented machine should not be able to fail
     * a start half-way through.
     */
    PVOID pageBlock;
    /* Retain how many pages the block holds, for the release path. */
    ULONG pageCount;
    /* Retain how many forked tables are recorded. */
    ULONG tableCount;
    /* Own every forked paging structure on this processor. */
    KswHvmEptLocalTable tables[KSW_HVM_MAX_LOCAL_TABLES];
} KswHvmEptLocal;

EXTERN_C_START

/*
 * Collect the two-MiB bases whose leaves any mechanism may flip.
 *
 * Reads the rule and view tables, which the caller must already have frozen.
 * Pure read: allocates nothing and publishes nothing.
 */
NTSTATUS
kswordArkHvmEptLocalCollectLeaves(
    _In_ const KswHvmRuntime* runtime,
    _Out_writes_to_(capacity, *count) ULONGLONG* bases,
    _In_ ULONG capacity,
    _Out_ ULONG* count
    );

/*
 * Build one processor's private hierarchy over the collected bases.
 *
 * PASSIVE_LEVEL, caller holds the runtime lock exclusive.  On failure the
 * record is released before returning, so a caller never sees a half-built
 * hierarchy.
 */
NTSTATUS
kswordArkHvmEptLocalBuild(
    _Inout_ KswHvmRuntime* runtime,
    _In_reads_(count) const ULONGLONG* bases,
    _In_ ULONG count,
    _Out_ KswHvmEptLocal* local
    );

/*
 * Prove the built hierarchies independently of how they were built.
 *
 * Deliberately not a replay: it walks each private root from the top and
 * checks the postcondition, so a bug shared between build and check cannot
 * hide.  Returns STATUS_SUCCESS only when every processor passes.
 */
NTSTATUS
kswordArkHvmEptLocalVerify(
    _In_ const KswHvmRuntime* runtime,
    _In_reads_(processorCount) const KswHvmEptLocal* localArray,
    _In_ ULONG processorCount,
    _In_reads_(count) const ULONGLONG* bases,
    _In_ ULONG count
    );

/*
 * Decide whether one more protected range would still fit.
 *
 * Called from the add paths rather than only from start, so an inadmissible
 * rule or view is refused where the caller can still do something about it -
 * with the numbers in hand - instead of at the end of a lifecycle preamble.
 * Returns STATUS_SUCCESS when the feature is not armed, because then nothing
 * is mirrored and no limit applies.
 */
NTSTATUS
kswordArkHvmEptLocalCheckAdmission(
    _In_ const KswHvmRuntime* runtime,
    _In_ ULONGLONG physicalAddress,
    _In_ ULONGLONG byteCount
    );

/* Release one private hierarchy.  Idempotent on a zeroed record. */
VOID
kswordArkHvmEptLocalRelease(
    _Inout_ KswHvmEptLocal* local
    );

/*
 * Translate a shared leaf pointer into this processor's private one.
 *
 * The only entry point reachable from VMX root.  Returns NULL when Local is
 * NULL - the feature-off case, where the caller keeps using the shared
 * pointer it already has - and also when the address belongs to no mirrored
 * table, which is a build error and must fail closed.
 */
volatile ULONGLONG*
kswordArkHvmEptLocalTranslate(
    _In_opt_ const KswHvmEptLocal* local,
    _In_opt_ volatile ULONGLONG* sharedEntry
    );

EXTERN_C_END

#endif /* defined(_M_AMD64) */
