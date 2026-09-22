/*++

Module Name:

    hvm_ept_builder.c

Abstract:

    Builds a continuous MTRR-aware EPT identity window.  Installed RAM uses
    captured MTRR precedence, while firmware, PCI, and other physical holes use
    the conservative uncacheable type so resident guests can reach ordinary
    MMIO without creating cache aliases.

Environment:

    Kernel-mode Driver Framework.

--*/

#include "hvm_ept.h"
#include "hvm_ept_domain.h"
#include "hvm_mtrr.h"

#if defined(_M_AMD64)
#include <intrin.h>
#endif

/* Ensure the paging-structure pages that own one two-MiB EPT leaf. */
static NTSTATUS
kswordArkHvmEnsureEptTablesLocked(
    _Inout_ KswHvmRuntime* runtime,
    _In_ ULONG pml4Index,
    _In_ ULONG pdptIndex,
    _Outptr_ ULONGLONG** pdEntries
    )
{
    PHYSICAL_ADDRESS physicalAddress = { 0 };
    ULONGLONG* pml4 = NULL;
    ULONGLONG* pdpt = NULL;

    /* Reject GPAs outside this backend's explicit, documented mapping window. */
    if (pml4Index >= KSW_HVM_MAX_PML4_ENTRIES ||
        pdptIndex >= 512UL ||
        pdEntries == NULL ||
        runtime->eptPml4 == NULL) {
        /* Return the exact hierarchy-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Bind the writable root table after validating its allocation. */
    pml4 = (ULONGLONG*)runtime->eptPml4;
    /* Allocate a PDPT lazily for each populated PML4 slot. */
    if (runtime->eptPdpt[pml4Index] == NULL) {
        /* Allocate and ledger one zeroed PDPT page. */
        runtime->eptPdpt[pml4Index] =
            kswordArkHvmAllocateEptPageLocked(
                runtime,
                &physicalAddress);
        /* Stop before publishing a parent entry on allocation failure. */
        if (runtime->eptPdpt[pml4Index] == NULL) {
            /* Return the exact nonpaged-resource failure. */
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        /* Publish the R/W/X paging-structure pointer in the EPT root. */
        pml4[pml4Index] =
            (physicalAddress.QuadPart & KSW_EPT_PHYSICAL_MASK) |
            KSW_EPT_READ |
            KSW_EPT_WRITE |
            KSW_EPT_EXECUTE;
        /* Count the populated root slot for protocol evidence. */
        runtime->eptPml4Entries += 1UL;
    }
    /* Bind the writable PDPT page selected by the physical address. */
    pdpt = (ULONGLONG*)runtime->eptPdpt[pml4Index];
    /* Allocate a page directory lazily for each populated one-GiB window. */
    if (runtime->eptPd[pml4Index][pdptIndex] == NULL) {
        /* Allocate and ledger one zeroed page-directory page. */
        runtime->eptPd[pml4Index][pdptIndex] =
            kswordArkHvmAllocateEptPageLocked(
                runtime,
                &physicalAddress);
        /* Stop before publishing a parent entry on allocation failure. */
        if (runtime->eptPd[pml4Index][pdptIndex] == NULL) {
            /* Return the exact nonpaged-resource failure. */
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        /* Publish the R/W/X paging-structure pointer in the PDPT. */
        pdpt[pdptIndex] =
            (physicalAddress.QuadPart & KSW_EPT_PHYSICAL_MASK) |
            KSW_EPT_READ |
            KSW_EPT_WRITE |
            KSW_EPT_EXECUTE;
        /* Count the populated one-GiB slot for protocol evidence. */
        runtime->eptPdptEntries += 1UL;
    }
    /* Return the writable 512-entry page-directory view. */
    *pdEntries =
        (ULONGLONG*)runtime->eptPd[pml4Index][pdptIndex];
    /* Complete the hierarchy request successfully. */
    return STATUS_SUCCESS;
}

/*
 * Ensure only the PDPT that owns one one-GiB window, without a page directory.
 *
 * Separate from kswordArkHvmEnsureEptTablesLocked because the whole point is
 * *not* allocating the directory: a one-GiB window with no installed RAM in it
 * is uniformly UC and is published as a single PDPT leaf.  Reusing the other
 * helper and then overwriting the PDPT entry would allocate the directory
 * first and leak it into the ledger - 32768 pages of it across the window.
 */
static NTSTATUS
kswordArkHvmEnsureEptPdptLocked(
    _Inout_ KswHvmRuntime* runtime,
    _In_ ULONG pml4Index,
    _Outptr_ ULONGLONG** pdptEntries
    )
{
    PHYSICAL_ADDRESS physicalAddress = { 0 };
    ULONGLONG* pml4 = NULL;

    /* Reject GPAs outside this backend's explicit, documented mapping window. */
    if (pml4Index >= KSW_HVM_MAX_PML4_ENTRIES ||
        pdptEntries == NULL ||
        runtime->eptPml4 == NULL) {
        /* Return the exact hierarchy-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Bind the writable root table after validating its allocation. */
    pml4 = (ULONGLONG*)runtime->eptPml4;
    /* Allocate a PDPT lazily for each populated PML4 slot. */
    if (runtime->eptPdpt[pml4Index] == NULL) {
        /* Allocate and ledger one zeroed PDPT page. */
        runtime->eptPdpt[pml4Index] =
            kswordArkHvmAllocateEptPageLocked(
                runtime,
                &physicalAddress);
        /* Stop before publishing a parent entry on allocation failure. */
        if (runtime->eptPdpt[pml4Index] == NULL) {
            /* Return the exact nonpaged-resource failure. */
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        /* Publish the R/W/X paging-structure pointer in the EPT root. */
        pml4[pml4Index] =
            (physicalAddress.QuadPart & KSW_EPT_PHYSICAL_MASK) |
            KSW_EPT_READ |
            KSW_EPT_WRITE |
            KSW_EPT_EXECUTE;
        /* Count the populated root slot for protocol evidence. */
        runtime->eptPml4Entries += 1UL;
    }
    /* Return the writable 512-entry page-directory-pointer view. */
    *pdptEntries = (ULONGLONG*)runtime->eptPdpt[pml4Index];
    /* Complete the hierarchy request successfully. */
    return STATUS_SUCCESS;
}

/*
 * Determine whether any installed RAM falls inside one physical range.
 *
 * The inverse question from kswordArkHvmIsInstalledRamRange, and it has to be
 * asked separately: that one answers "is every byte RAM" (which decides the
 * cache type), this one answers "is any byte RAM" (which decides whether the
 * window needs two-MiB granularity at all).  Neither implies the other for a
 * window that straddles a boundary, and getting it backwards would publish a
 * one-GiB UC leaf over real RAM - the whole GiB would still translate, so
 * nothing would fail; the guest would just run that memory uncached.
 */
static BOOLEAN
kswordArkHvmRangeContainsInstalledRam(
    _In_ const PHYSICAL_MEMORY_RANGE* ranges,
    _In_ ULONGLONG physicalAddress,
    _In_ ULONGLONG byteCount
    )
{
    ULONGLONG rangeEnd = 0ULL;
    ULONG rangeIndex = 0UL;

    /* Reject malformed ranges before performing the overlap walk. */
    if (ranges == NULL ||
        byteCount == 0ULL ||
        physicalAddress > MAXULONGLONG - byteCount) {
        /* Treat malformed input as "may contain RAM" and keep granularity. */
        return TRUE;
    }
    /* Preserve the exclusive window end after overflow validation. */
    rangeEnd = physicalAddress + byteCount;
    for (rangeIndex = 0UL;
         ranges[rangeIndex].NumberOfBytes.QuadPart != 0;
         ++rangeIndex) {
        ULONGLONG installedStart = 0ULL;
        ULONGLONG installedBytes = 0ULL;
        ULONGLONG installedEnd = 0ULL;

        /* Reject impossible signed physical records conservatively. */
        if (ranges[rangeIndex].BaseAddress.QuadPart < 0 ||
            ranges[rangeIndex].NumberOfBytes.QuadPart < 0) {
            /* Ignore the malformed record instead of trusting its cast. */
            continue;
        }
        /* Decode the nonnegative installed-memory record. */
        installedStart =
            (ULONGLONG)ranges[rangeIndex].BaseAddress.QuadPart;
        /* Decode the nonnegative installed-memory byte count. */
        installedBytes =
            (ULONGLONG)ranges[rangeIndex].NumberOfBytes.QuadPart;
        /* Ignore an overflowing record during defensive classification. */
        if (installedBytes > MAXULONGLONG - installedStart) {
            /* Keep granularity rather than trusting wrapped coverage. */
            return TRUE;
        }
        /* Compute the exclusive installed-memory record end. */
        installedEnd = installedStart + installedBytes;
        /* Report the first record that overlaps the window at all. */
        if (installedStart < rangeEnd &&
            installedEnd > physicalAddress) {
            /* This window owns installed RAM and needs a page directory. */
            return TRUE;
        }
    }
    /* No installed RAM here: the window may be published as one UC leaf. */
    return FALSE;
}

/*
 * Determine whether one complete EPT large leaf is backed by installed RAM.
 *
 * A leaf that crosses any firmware, PCI, or other reserved hole must not inherit
 * the ordinary RAM cache type.  Such leaves are still identity mapped so that
 * a resident Windows guest can reach MMIO, but the builder assigns UC below.
 */
static BOOLEAN
kswordArkHvmIsInstalledRamRange(
    _In_ const PHYSICAL_MEMORY_RANGE* ranges,
    _In_ ULONGLONG physicalAddress,
    _In_ ULONGLONG byteCount
    )
{
    ULONGLONG cursor = physicalAddress;
    ULONGLONG rangeEnd = 0ULL;

    /* Reject malformed ranges before performing the coverage walk. */
    if (ranges == NULL ||
        byteCount == 0ULL ||
        physicalAddress > MAXULONGLONG - byteCount) {
        /* Treat malformed coverage as a non-RAM hole. */
        return FALSE;
    }
    /* Preserve the exclusive leaf end after overflow validation. */
    rangeEnd = physicalAddress + byteCount;
    /* Extend coverage until the complete leaf is proven to be installed RAM. */
    while (cursor < rangeEnd) {
        ULONGLONG bestEnd = cursor;
        ULONG rangeIndex = 0UL;

        /*
         * Find the farthest range covering the current cursor.  Re-scanning
         * avoids depending on undocumented range ordering and joins adjacent
         * physical-memory records without treating their boundary as a hole.
         */
        for (rangeIndex = 0UL;
             ranges[rangeIndex].NumberOfBytes.QuadPart != 0;
             ++rangeIndex) {
            ULONGLONG installedStart = 0ULL;
            ULONGLONG installedBytes = 0ULL;
            ULONGLONG installedEnd = 0ULL;

            /* Reject impossible signed physical records conservatively. */
            if (ranges[rangeIndex].BaseAddress.QuadPart < 0 ||
                ranges[rangeIndex].NumberOfBytes.QuadPart < 0) {
                /* Ignore the malformed record instead of trusting its cast. */
                continue;
            }
            /* Decode the nonnegative installed-memory record. */
            installedStart =
                (ULONGLONG)ranges[rangeIndex].BaseAddress.QuadPart;
            /* Decode the nonnegative installed-memory byte count. */
            installedBytes =
                (ULONGLONG)ranges[rangeIndex].NumberOfBytes.QuadPart;
            /* Ignore an overflowing record during defensive classification. */
            if (installedBytes >
                MAXULONGLONG - installedStart) {
                /* Continue without treating wrapped coverage as RAM. */
                continue;
            }
            /* Compute the exclusive installed-memory record end. */
            installedEnd = installedStart + installedBytes;
            /* Extend coverage only with a range containing the cursor. */
            if (installedStart <= cursor &&
                installedEnd > bestEnd) {
                /* Retain the farthest proven installed-memory endpoint. */
                bestEnd = installedEnd;
            }
        }
        /* Stop when no installed-memory record covers the next byte. */
        if (bestEnd == cursor) {
            /* Classify the complete large leaf as containing a hole. */
            return FALSE;
        }
        /* Advance through the proven installed-memory coverage. */
        cursor = bestEnd;
    }
    /* Report that every byte in the large leaf is installed RAM. */
    return TRUE;
}

NTSTATUS
kswordArkHvmBuildEptLocked(
    _Inout_ KswHvmRuntime* runtime
    )
{
    PHYSICAL_ADDRESS rootPhysical = { 0 };
    PPHYSICAL_MEMORY_RANGE ranges = NULL;
    ULONG rangeIndex = 0UL;
    NTSTATUS status = STATUS_SUCCESS;
    ULONGLONG mappingLimit = 0ULL;
    ULONGLONG address = 0ULL;
    BOOLEAN useGiantLeaves = FALSE;
#if defined(_M_AMD64)
    int cpuInfo[4] = { 0 };
    ULONG physicalAddressBits = 0UL;
    ULONGLONG architecturalLimit = 0ULL;
#endif

    /* EPT setup requires four-level, WB, and two-MiB leaf support. */
    if ((runtime->featureFlags &
            (KSWORD_ARK_HVM_FEATURE_EPT |
             KSWORD_ARK_HVM_FEATURE_EPT_WB |
             KSWORD_ARK_HVM_FEATURE_EPT_4_LEVEL |
             KSWORD_ARK_HVM_FEATURE_EPT_2MB)) !=
        (KSWORD_ARK_HVM_FEATURE_EPT |
         KSWORD_ARK_HVM_FEATURE_EPT_WB |
         KSWORD_ARK_HVM_FEATURE_EPT_4_LEVEL |
         KSWORD_ARK_HVM_FEATURE_EPT_2MB)) {
        /* Reject processors lacking the required baseline EPT capabilities. */
        return STATUS_NOT_SUPPORTED;
    }
#if defined(_M_AMD64)
    /*
     * Map the complete CPUID-addressable guest-physical space, clipped only by
     * the existing eight-TiB backend budget.  Highest installed RAM is not a
     * valid upper bound for 64-bit PCI/ReBAR MMIO.
     */
    __cpuid(cpuInfo, (int)0x80000000UL);
    /* Require the architectural MAXPHYADDR discovery leaf. */
    if ((ULONG)cpuInfo[0] < 0x80000008UL) {
        /* Refuse to guess a guest-physical address boundary. */
        return STATUS_NOT_SUPPORTED;
    }
    /* Read MAXPHYADDR from CPUID.80000008H:EAX[7:0]. */
    __cpuid(cpuInfo, (int)0x80000008UL);
    physicalAddressBits = (ULONG)cpuInfo[0] & 0xFFUL;
    /* Accept only architecturally meaningful widths representable in 64 bits. */
    if (physicalAddressBits < 32UL ||
        physicalAddressBits > 52UL) {
        /* Reject malformed or unsupported physical-address evidence. */
        return STATUS_DATA_ERROR;
    }
    /* Convert the physical-address width to one exclusive address boundary. */
    architecturalLimit = 1ULL << physicalAddressBits;
    /* Clip only to the explicit hierarchy/allocation budget. */
    mappingLimit = architecturalLimit >
        KSW_HVM_MAX_MAPPED_PHYSICAL
        ? KSW_HVM_MAX_MAPPED_PHYSICAL
        : architecturalLimit;
    /* Publish that resident coverage cannot be proven beyond the budget. */
    if (architecturalLimit >
        KSW_HVM_MAX_MAPPED_PHYSICAL) {
        /* Preserve explicit incomplete-coverage evidence for lifecycle gates. */
        kswordArkHvmStateSet(runtime, KSWORD_ARK_HVM_STATE_EPT_TRUNCATED);
    }
    /*
     * One-GiB EPT leaves, IA32_VMX_EPT_VPID_CAP bit 17.
     *
     * Read here rather than turned into a KSWORD_ARK_HVM_FEATURE_* bit: this
     * is the only place that uses it, and a published capability bit is a
     * promise to every other caller that the backend can do something with
     * one-GiB leaves in general - it cannot.  Splits, rules, views and watches
     * all start from a PDE and stay two-MiB.
     */
    useGiantLeaves =
        (runtime->vmxEptVpidCapabilities & KSW_EPT_CAP_1GB) != 0ULL;
#else
    /* This EPT builder is defined only for the AMD64 VMX backend. */
    return STATUS_NOT_SUPPORTED;
#endif
    /* Allocate and record the root table before walking physical ranges. */
    runtime->eptPml4 =
        kswordArkHvmAllocateEptPageLocked(
            runtime,
            &rootPhysical);
    /* Stop before requesting a physical-memory snapshot on root failure. */
    if (runtime->eptPml4 == NULL) {
        /* Return the exact nonpaged-resource failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* MmGetPhysicalMemoryRanges returns a pool-backed, zero-terminated list. */
    ranges = MmGetPhysicalMemoryRanges();
    /* Stop before inventory when Windows cannot provide a snapshot. */
    if (ranges == NULL) {
        /* Return the exact snapshot-resource failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /*
     * Inventory installed RAM for cache typing and accounting.  The identity
     * map itself is continuous through MAXPHYADDR (within the fixed backend
     * budget), so RAM inventory never hides high PCI/ReBAR MMIO windows.
     */
    for (rangeIndex = 0UL;
         ranges[rangeIndex].NumberOfBytes.QuadPart != 0;
         ++rangeIndex) {
        ULONGLONG rangeStart = 0ULL;
        ULONGLONG rangeBytes = 0ULL;
        ULONGLONG rangeEnd = 0ULL;
        ULONGLONG clippedEnd = 0ULL;
        ULONGLONG clippedBytes = 0ULL;

        /* Reject impossible signed physical-memory records. */
        if (ranges[rangeIndex].BaseAddress.QuadPart < 0 ||
            ranges[rangeIndex].NumberOfBytes.QuadPart < 0) {
            /* Return a deterministic snapshot-integrity failure. */
            status = STATUS_DATA_ERROR;
            break;
        }
        /* Decode the nonnegative physical-memory record. */
        rangeStart =
            (ULONGLONG)ranges[rangeIndex].BaseAddress.QuadPart;
        /* Decode the nonnegative physical-memory byte count. */
        rangeBytes =
            (ULONGLONG)ranges[rangeIndex].NumberOfBytes.QuadPart;
        /* Guard the range addition before aligning the end upward. */
        if (rangeBytes > MAXULONGLONG - rangeStart) {
            /* Stop rather than accepting a wrapped physical-memory record. */
            status = STATUS_INTEGER_OVERFLOW;
            break;
        }
        /* Compute the exclusive installed-memory record end. */
        rangeEnd = rangeStart + rangeBytes;
        /* Mark records outside the proven architectural/backend boundary. */
        if (rangeStart >= mappingLimit) {
            /* Preserve that installed RAM exists beyond the mapped window. */
            kswordArkHvmStateSet(runtime, KSWORD_ARK_HVM_STATE_EPT_TRUNCATED);
            /* Continue in case a later record remains representable. */
            continue;
        }
        /* Clip only the backend accounting boundary, never the source record. */
        clippedEnd = rangeEnd;
        /* Clamp a record crossing the deliberate backend boundary. */
        if (rangeEnd > mappingLimit) {
            /* Retain only the representable portion for EPT accounting. */
            clippedEnd = mappingLimit;
            /* Publish that the physical map is intentionally incomplete. */
            kswordArkHvmStateSet(runtime, KSWORD_ARK_HVM_STATE_EPT_TRUNCATED);
        }
        /* Count exact installed bytes instead of rounded large-leaf capacity. */
        clippedBytes = clippedEnd - rangeStart;
        /* Guard the protocol-visible accounting sum defensively. */
        if (runtime->mappedRamBytes >
            MAXULONGLONG - clippedBytes) {
            /* Stop rather than publishing wrapped installed-RAM accounting. */
            status = STATUS_INTEGER_OVERFLOW;
            break;
        }
        /* Publish exact installed RAM within the backend physical window. */
        runtime->mappedRamBytes += clippedBytes;
    }
    /* Stop before allocating the hierarchy when the inventory was malformed. */
    if (!NT_SUCCESS(status)) {
        /* Release the pool-backed physical-memory snapshot. */
        ExFreePool(ranges);
        /* Return the authoritative inventory failure. */
        return status;
    }
    /*
     * Architectural power-of-two limits and the eight-TiB backend limit are
     * already two-MiB aligned; no RAM-derived rounding may narrow or extend it.
     */
    /*
     * Build the continuous RAM-plus-MMIO identity window, one GiB at a time.
     *
     * Two granularities, and which one a GiB gets is decided by one question:
     * does any installed RAM live in it?
     *
     * - **Yes** -> a page directory with 512 two-MiB leaves.  RAM leaves carry
     *   an MTRR-resolved cache type, and every EPT rule, split view and memory
     *   watch splits a leaf down to 4 KiB starting from a PDE, so this is the
     *   granularity the rest of the backend is written against.
     * - **No** -> one one-GiB PDPT leaf, UC.  MMIO and reserved windows are
     *   uniformly UC already, so 512 two-MiB UC leaves and one one-GiB UC leaf
     *   translate identically - the only difference is a page directory.
     *
     * The difference is not an optimisation.  At MAXPHYADDR 45 the window is
     * thirty-two TiB; a directory per GiB is 32768 pages, 128 MiB of nonpaged
     * pool, and sixteen million loop iterations, on every machine at prepare.
     * That cost is what kept KSW_HVM_MAX_PML4_ENTRIES at 16 and left modern
     * processors being told they were unsupported.
     *
     * Without the one-GiB capability there is no second granularity, so the
     * fallback is what this loop always did - and the page-directory budget
     * then genuinely binds, which the caller reports rather than clips.
     */
    while (address < mappingLimit) {
        const ULONG kPml4Index =
            (ULONG)((address >> 39) & 0x1FFULL);
        const ULONG kPdptIndex =
            (ULONG)((address >> 30) & 0x1FFULL);
        ULONGLONG gibEnd = address + KSW_HVM_ONE_GIB;
        ULONGLONG* pdEntries = NULL;

        /* Never let the last window run past the deliberate mapping limit. */
        if (gibEnd > mappingLimit) {
            /* Clamp so the final partial GiB is still built at 2 MiB. */
            gibEnd = mappingLimit;
        }
        /*
         * A whole GiB with no installed RAM becomes one UC leaf.
         *
         * Requires the full GiB to be inside the limit: a one-GiB leaf covers
         * the whole GiB whether we wanted it to or not, so publishing one for
         * a clamped tail would map past the boundary this backend promised to
         * stay within.
         */
        if (useGiantLeaves &&
            gibEnd == address + KSW_HVM_ONE_GIB &&
            !kswordArkHvmRangeContainsInstalledRam(
                ranges,
                address,
                KSW_HVM_ONE_GIB)) {
            ULONGLONG* pdptEntries = NULL;

            /* Allocate only the PDPT; the whole point is to skip the PD. */
            status = kswordArkHvmEnsureEptPdptLocked(
                runtime,
                kPml4Index,
                &pdptEntries);
            /* Stop before publishing an incomplete EPT pointer. */
            if (!NT_SUCCESS(status)) {
                /* Leave cleanup to the shared resource ledger. */
                break;
            }
            /* Publish one identity-mapped one-GiB EPT leaf, uncacheable. */
            pdptEntries[kPdptIndex] =
                (address & KSW_EPT_PHYSICAL_MASK) |
                KSW_EPT_READ |
                KSW_EPT_WRITE |
                KSW_EPT_EXECUTE |
                KSW_EPT_LARGE_PAGE |
                /* Never leave a leaf convertible; see the macro's comment. */
                KSW_EPT_SUPPRESS_VE;
            /* Count the populated one-GiB slot for protocol evidence. */
            runtime->eptPdptEntries += 1UL;
            /* Advance a whole GiB; this window needs nothing further. */
            address += KSW_HVM_ONE_GIB;
            continue;
        }
        /* Allocate the sparse hierarchy pages owning this one-GiB window. */
        status = kswordArkHvmEnsureEptTablesLocked(
            runtime,
            kPml4Index,
            kPdptIndex,
            &pdEntries);
        /* Stop before publishing an incomplete EPT pointer. */
        if (!NT_SUCCESS(status)) {
            /* Leave cleanup to the shared resource ledger. */
            break;
        }
        /* Fill this window's two-MiB leaves without re-walking the hierarchy. */
        while (address < gibEnd) {
            const ULONG kPdIndex =
                (ULONG)((address >> 21) & 0x1FFULL);
            UCHAR memoryType = 0U;

            /*
             * Use captured MTRR precedence only for leaves proven entirely RAM.
             * Reserved and MMIO leaves are deliberately UC to avoid cache
             * aliases.
             */
            if (kswordArkHvmIsInstalledRamRange(
                    ranges,
                    address,
                    KSW_HVM_LARGE_PAGE_BYTES)) {
                /* Resolve one uniform Intel-compatible cache type for RAM. */
                memoryType =
                    kswordArkHvmMtrrResolveRangeType(
                        &runtime->mtrr,
                        address,
                        KSW_HVM_LARGE_PAGE_BYTES);
            }
            /* Publish one identity-mapped two-MiB EPT leaf. */
            pdEntries[kPdIndex] =
                (address & KSW_EPT_PHYSICAL_MASK) |
                KSW_EPT_READ |
                KSW_EPT_WRITE |
                KSW_EPT_EXECUTE |
                ((ULONGLONG)memoryType <<
                    KSW_EPT_MEMORY_TYPE_SHIFT) |
                KSW_EPT_LARGE_PAGE |
                /* Never leave a leaf convertible; see the macro's comment. */
                KSW_EPT_SUPPRESS_VE;
            /* Count the complete large-leaf identity window. */
            runtime->eptLargePageEntries += 1UL;
            /* Advance to the next two-MiB physical range. */
            address += KSW_HVM_LARGE_PAGE_BYTES;
        }
    }
    /* Release the immutable physical-memory snapshot after table creation. */
    ExFreePool(ranges);
    /* Return the exact hierarchy-allocation failure when one occurred. */
    if (!NT_SUCCESS(status)) {
        /* Return before publishing an EPT pointer to incomplete tables. */
        return status;
    }
    /* Publish the exclusive end of the continuous identity map. */
    runtime->highestMappedPhysicalAddress = mappingLimit;
    /* EPTP encodes WB memory, a four-level walk, and optional A/D tracking. */
    runtime->eptPointer =
        (rootPhysical.QuadPart & KSW_EPT_PHYSICAL_MASK) |
        6ULL |
        (3ULL << 3);
    /* Enable EPT accessed/dirty tracking only when advertised by the CPU. */
    if ((runtime->featureFlags &
            KSWORD_ARK_HVM_FEATURE_EPT_AD) != 0ULL) {
        /* Set the architecturally defined EPTP accessed/dirty enable bit. */
        runtime->eptPointer |= (1ULL << 6);
    }
    /* Publish EPT readiness only after the complete hierarchy exists. */
    kswordArkHvmStateSet(runtime, KSWORD_ARK_HVM_STATE_EPT_READY);
    /*
     * Build the EPTP list now that a default view exists to occupy slot zero.
     * Failure here is not fatal to the identity map: without a list, VMFUNC is
     * simply never armed, and every other capability still works.
     */
    (VOID)kswordArkHvmEptDomainPrepareLocked(runtime);
    /* Complete the identity-map build successfully. */
    return STATUS_SUCCESS;
}
