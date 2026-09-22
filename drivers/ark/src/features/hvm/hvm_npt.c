/* Immutable AMD identity NPT; no allocation or page-table edits in VMEXIT. */
#include "hvm_svm.h"
#include "../../platform/pool_compat.h"

/* Cache indices must refer to the existing host PAT; never rewrite it. */
static ULONG kswNptPatIndex(ULONGLONG pat, ULONG type)
{
    /* Scan eight architectural PAT slots. */
    ULONG index;
    /* Return an explicit invalid sentinel when no slot matches. */
    for (index = 0; index < 8; ++index) {
        /* Ignore reserved high bits by requiring the complete byte. */
        if (((pat >> (index * 8)) & 0xffULL) == type) { return index; }
    }
    /* Absence cannot be treated as WB. */
    return 8;
}

/* Classify an entire leaf: WB RAM, UC holes/MMIO, or mixed requiring split. */
static LONG kswNptCacheRange(const KswNpt* npt, ULONGLONG start, ULONGLONG bytes)
{
    /* Ranges are page-aligned and validated by the builder. */
    ULONG index;
    /* End cannot overflow because coverage is bounded to 48 bits. */
    ULONGLONG end = start + bytes;
    /* An overlap which does not cover the whole leaf requires finer pages. */
    for (index = 0; npt->ranges[index].NumberOfBytes.QuadPart; ++index) {
        /* Decode the validated physical RAM interval. */
        ULONGLONG low = (ULONGLONG)npt->ranges[index].BaseAddress.QuadPart;
        /* Decode the validated exclusive end. */
        ULONGLONG high = low + (ULONGLONG)npt->ranges[index].NumberOfBytes.QuadPart;
        /* An entire RAM interval can use WB; hardware MTRRs still participate. */
        if (start >= low && end <= high) { return (LONG)npt->wbIndex; }
        /* Split any interval touching only part of RAM. */
        if (start < high && end > low) { return -1; }
    }
    /* Unknown physical holes, including MMIO, use UC rather than guessed WB. */
    return (LONG)npt->ucIndex;
}

/* Allocate a page and record ownership before returning its physical address. */
static PULONGLONG kswNptAllocate(KswNpt* npt, ULONGLONG* pa)
{
    /* Constrain hardware page allocations to the supported address mask. */
    PHYSICAL_ADDRESS highest;
    /* Keep the local ownership pointer. */
    PVOID page;
    /* Enforce the explicit 64-MiB table budget. */
    if (npt->pageCount == KSW_NPT_MAX_PAGES) { return NULL; }
    /* Limit allocations to representable physical addresses. */
    highest.QuadPart = (LONGLONG)(npt->limit - 1);
    /* A single hardware page is physically contiguous by construction. */
    page = MmAllocateContiguousMemory(PAGE_SIZE, highest);
    /* Return without publishing a parent entry on failure. */
    if (page == NULL) { return NULL; }
    /* initialize reserved fields and unused entries. */
    RtlZeroMemory(page, PAGE_SIZE);
    /* Record the allocation before the caller can publish it. */
    npt->pages[npt->pageCount++] = page;
    /* Resolve its hardware address once in preparation. */
    *pa = (ULONGLONG)MmGetPhysicalAddress(page).QuadPart;
    /* Return the writeable kernel mapping. */
    return (PULONGLONG)page;
}

/* Build one table recursively; recursion depth never exceeds four. */
static NTSTATUS kswNptFill(KswNpt* npt, PULONGLONG table, ULONG level, ULONGLONG base, PULONG required)
{
    /* Each level covers 512 entries of a power-of-two span. */
    ULONGLONG span = 1ULL << (12 + 9 * (level - 1));
    /* Loop index does not depend on untrusted guest state. */
    ULONG index;
    /* Dry traversal computes the exact split-table budget before allocating hardware tables. */
    if (required != NULL && ++*required > KSW_NPT_MAX_PAGES) { return STATUS_INSUFFICIENT_RESOURCES; }
    /* Fill only the range advertised by the guest physical-address width. */
    for (index = 0; index < 512 && base + index * span < npt->limit; ++index) {
        /* Address translation is an identity mapping. */
        ULONGLONG address = base + index * span;
        /* PAT indices cannot be chosen until the entire range is classified. */
        LONG cache = kswNptCacheRange(npt, address, span);
        /* Large pages require a homogeneous range and enumerated page size. */
        if (level == 1 || (cache >= 0 && (level == 2 || (level == 3 && npt->page1Gb)))) {
            /* A mixed 4-KiB leaf would imply a malformed RAM inventory. */
            ULONGLONG flags;
            /* Refuse an impossible subpage cache conflict. */
            if (cache < 0) { return STATUS_DATA_ERROR; }
            /* Cache/permission encoding is shared with exhaustive host-side tests. */
            flags = kswNptLeafFlags(level, (ULONG)cache);
            /* Leave NX clear for this baseline identity map. */
            if (table != NULL) { table[index] = (address & npt->addressMask) | flags; }
        } else {
            /* Intermediate entries never contain leaf cache attributes. */
            ULONGLONG pa = 0;
            /* Allocate the next-level table. */
            PULONGLONG child = required != NULL ? NULL : kswNptAllocate(npt, &pa);
            /* Preserve the complete allocation ledger on any failure. */
            NTSTATUS status;
            /* Stop before publishing an absent table. */
            if (child == NULL && required == NULL) { return STATUS_INSUFFICIENT_RESOURCES; }
            /* Fully populate children before linking their parent. */
            status = kswNptFill(npt, child, level - 1, address, required);
            /* Propagate failure without creating a partially valid root. */
            if (!NT_SUCCESS(status)) { return status; }
            /* Publish the completed lower level. */
            if (table != NULL) { table[index] = pa | 7ULL; }
        }
    }
    /* Every advertised address now has an identity translation. */
    return STATUS_SUCCESS;
}

/* Called only after all SVM CPUs have stopped, or before any CPU entered. */
VOID kswordNptRelease(KswNpt* npt)
{
    /* Free reverse allocation order without walking untrusted table entries. */
    while (npt->pageCount != 0) { MmFreeContiguousMemory(npt->pages[--npt->pageCount]); }
    /* RAM inventory is preparation-only. */
    if (npt->ranges != NULL) { ExFreePool(npt->ranges); }
    /* The bookkeeping array is ordinary NX pool. */
    if (npt->pages != NULL) { ExFreePoolWithTag(npt->pages, 'nSvK'); }
    /* Clear all address and ownership evidence. */
    RtlZeroMemory(npt, sizeof(*npt));
}

/* Construct the entire immutable NPT before any SVM entry. */
NTSTATUS kswordNptBuild(KswNpt* npt, const KswSvmCaps* caps)
{
    /* Root mapping and status stay private until construction completes. */
    PULONGLONG root;
    /* Retain the exact failure from allocation or inventory validation. */
    NTSTATUS status;
    /* Bound resource estimation independently of installed RAM. */
    ULONGLONG minimumPages;
    /* Exact dry-walk table count including RAM-boundary splits. */
    ULONG required = 0;
    /* Inventory iterator. */
    ULONG index;
    /* Never replace live page tables. */
    if (npt->pages != NULL) { return STATUS_ALREADY_REGISTERED; }
    /* Four-level AMD NPT is explicitly limited to the supported width. */
    npt->addressMask = kswNptAddressMask(caps->physicalBits);
    /* Reject malformed/unsupported CPUID before a shift or allocation. */
    if (npt->addressMask == 0) { return STATUS_NOT_SUPPORTED; }
    /* Establish exact coverage. */
    npt->limit = 1ULL << caps->physicalBits;
    /* Preserve enumerated one-GiB support. */
    npt->page1Gb = caps->page1Gb;
    /* Find WB and UC in the existing hardware PAT. */
    npt->wbIndex = kswNptPatIndex(caps->pat, 6);
    /* Holes/MMIO cannot default to WB. */
    npt->ucIndex = kswNptPatIndex(caps->pat, 0);
    /* Every leaf must have a representable cache policy. */
    if (npt->wbIndex == 8 || npt->ucIndex == 8) { return STATUS_NOT_SUPPORTED; }
    /* Estimate structural pages before doing a potentially enormous walk. */
    minimumPages = 1 + ((npt->limit + (1ULL << 39) - 1) >> 39);
    /* Without one-GiB leaves every GiB additionally requires one PD. */
    if (!npt->page1Gb) { minimumPages += npt->limit >> 30; }
    /* Reject incomplete coverage rather than silently clipping it. */
    if (minimumPages > KSW_NPT_MAX_PAGES) { return STATUS_INSUFFICIENT_RESOURCES; }
    /* Allocate a bounded ownership ledger. */
    npt->pages = kswordArkAllocateNonPagedPool(KSW_NPT_MAX_PAGES * sizeof(PVOID), 'nSvK');
    /* Leave no partial success on allocation failure. */
    if (npt->pages == NULL) { return STATUS_INSUFFICIENT_RESOURCES; }
    /* Snapshot RAM only for cache classification, not for coverage. */
    npt->ranges = MmGetPhysicalMemoryRanges();
    /* Clean up partial ownership if Windows cannot supply the inventory. */
    if (npt->ranges == NULL) { kswordNptRelease(npt); return STATUS_INSUFFICIENT_RESOURCES; }
    /* Validate RAM inventory before using any interval arithmetic. */
    for (index = 0; npt->ranges[index].NumberOfBytes.QuadPart; ++index) {
        /* Require nonnegative, page-aligned intervals within exact coverage. */
        ULONGLONG start = (ULONGLONG)npt->ranges[index].BaseAddress.QuadPart;
        /* Retain unsigned length after checking through the range bound. */
        ULONGLONG bytes = (ULONGLONG)npt->ranges[index].NumberOfBytes.QuadPart;
        /* Reject wraparound, partial pages and inventory beyond CPUID. */
        if (start >= npt->limit || bytes > npt->limit - start || ((start | bytes) & 0xfffULL)) {
            /* Do not leave a usable root after failed coverage validation. */
            kswordNptRelease(npt); return STATUS_DATA_ERROR;
        }
    }
    /* Count every necessary split using the same traversal as construction. */
    status = kswNptFill(npt, NULL, 4, 0, &required);
    /* An over-budget map is refused before any hardware table is allocated. */
    if (!NT_SUCCESS(status)) { kswordNptRelease(npt); return status; }
    /* Allocate the PML4 and recursively construct all lower levels. */
    root = kswNptAllocate(npt, &npt->rootPa);
    /* Preserve the first construction failure. */
    status = root != NULL ? kswNptFill(npt, root, 4, 0, NULL) : STATUS_INSUFFICIENT_RESOURCES;
    /* An incomplete hierarchy must never survive as ready. */
    if (!NT_SUCCESS(status)) { kswordNptRelease(npt); return status; }
    /* Retain the validated inventory for VMEXIT-safe nested table RAM admission. */
    /* Complete identity coverage is ready. */
    return STATUS_SUCCESS;
}
