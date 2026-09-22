/* AMD nested-NPT translation primitives; shared by the driver and host tests.
   APM vol. 2 sections 5.3 and 15.25. These routines never execute virtualization. */
#pragma once
#include "hvm_svm_arch.h"

/* Distinguish a guest translation fault from an inaccessible host operand. */
#define KSW_NNPT_OK 0U
#define KSW_NNPT_FAULT 1U
#define KSW_NNPT_UNREADABLE 2U
#define KSW_NNPT_UNSUPPORTED 3U
#define KSW_NNPT_RETRY 4U
/* Request bits use the architectural nested-fault write and instruction bits. */
#define KSW_NNPT_WRITE 2U
#define KSW_NNPT_EXECUTE 16U
/* AMD always treats guest accesses as user accesses at the nested level. */
#define KSW_NNPT_USER 4ULL
/* Preserve the architectural frame field before applying MAXPHYADDR. */
#define KSW_NNPT_FRAME 0x000ffffffffff000ULL
/* NX restrictions accumulate through every parent entry. */
#define KSW_NNPT_NX (1ULL << 63)
/* Reads must validate RAM ownership before mapping an untrusted table page. */
typedef int (*KswNnptRead)(void* context, KswSvmU64 address, KswSvmU64* value);
/* Atomically OR A/D only if the entry still equals Expected; never clobber a remap. */
typedef int (*KswNnptCompareOr)(void* context, KswSvmU64 address,
    KswSvmU64 expected, KswSvmU64 bits);

/* Retain the complete source path for revalidation and hardware A/D propagation. */
typedef struct KswNnptWalk {
    /* Bind the result to its input; equal page offsets alone do not prove a chain. */
    KswSvmU64 inputAddress, root;
    /* Address at the next physical level, including the original page offset. */
    KswSvmU64 address;
    /* Effective Present/RW/US/NX flags after intersecting all levels. */
    KswSvmU64 permissions;
    /* Architectural low fault bits; the caller preserves EXITINFO1[33:32]. */
    KswSvmU64 fault;
    /* Physical source locations, not pointers into a temporary window. */
    KswSvmU64 entryAddress[4];
    /* Exact source words at translation time, including software and A/D bits. */
    KswSvmU64 entryValue[4];
    /* Number of complete reads and the final leaf's address offset width. */
    unsigned int count, leafShift;
    /* PAT index decoded according to the final AMD leaf size. */
    unsigned int patIndex;
    /* Only a successful walk may later publish A/D updates. */
    unsigned int complete;
    /* A read-only translation cannot later authorize a dirty-bit update. */
    unsigned int access;
} KswNnptWalk;

/* Read-only four-level AMD walk. No guessed mappings or synthetic successful reads. */
static __inline unsigned int kswSvmNestedNptWalk(KswSvmU64 root,
    KswSvmU64 gpa, unsigned int physicalBits, unsigned int page1Gb,
    unsigned int nxEnabled, unsigned int access, KswNnptRead read,
    void* context, KswNnptWalk* walk)
{
    /* Four-level NPT is the deliberately bounded current address-space contract. */
    const KswSvmU64 kMask = kswNptAddressMask(physicalBits);
    /* initialize all fields even when the first operand fails validation. */
    const KswNnptWalk kEmpty = {0};
    /* Start the permission intersection with Present/RW/US and executable. */
    KswSvmU64 permissions = 7ULL, table = root;
    /* The walk visits at most four entries. */
    unsigned int level;
    /* Publish deterministic failure output before checking input. */
    if (!walk) { return KSW_NNPT_UNSUPPORTED; }
    /* Publish deterministic output even for invalid operands. */
    *walk = kEmpty;
    /* Unknown request types or unsupported addresses are host admission failures. */
    if (!kMask || !read || (root & ~kMask) || (gpa & ~(kMask | 0xfffULL)) ||
        (access & ~(KSW_NNPT_WRITE | KSW_NNPT_EXECUTE))) { return KSW_NNPT_UNSUPPORTED; }
    /* Retain the exact guest address used to locate this mapping. */
    walk->inputAddress = gpa;
    /* Retain the virtual NPT identity for invalidation and diagnostics. */
    walk->root = root;
    /* Retain the access that passed the permission check. */
    walk->access = access;
    /* Nested faults always name a user access, even for an inner ring-zero CPU. */
    walk->fault = KSW_NNPT_USER | access;
    /* Keep the loop bounded without allocating or retaining physical mappings. */
    for (level = 0; level < 4; ++level) {
        /* AMD four-level page-table index: PML4, PDPT, PD, PT. */
        unsigned int shift = 39U - level * 9U;
        /* Record the source slot before reading through the caller's RAM guard. */
        KswSvmU64 location = table + (((gpa >> shift) & 511ULL) * 8ULL);
        /* Never inspect uninitialized bits after a failed physical read. */
        KswSvmU64 entry = 0;
        /* Identify leaves only after the source word has been read. */
        unsigned int leaf;
        /* A failed physical read is not an architectural not-present fault. */
        if (!read(context, location, &entry)) { return KSW_NNPT_UNREADABLE; }
        /* Retain source addresses for atomic A/D updates and stale-path detection. */
        walk->entryAddress[level] = location;
        /* Retain every bit, including guest software bits. */
        walk->entryValue[level] = entry;
        /* Publish only initialized path elements. */
        walk->count = level + 1;
        /* Nonpresent entries ignore their remaining bits architecturally. */
        if (!(entry & 1ULL)) { return KSW_NNPT_FAULT; }
        /* PS is illegal at PML4; at PT bit 7 is PAT, not PS. */
        leaf = level == 3U || (level != 0U && (entry & 0x80ULL) != 0);
        /* MAXPHYADDR and NX enablement apply at every present level. */
        if ((entry & KSW_NNPT_FRAME & ~kMask) || (!nxEnabled && (entry & KSW_NNPT_NX)) ||
            (level == 0U && (entry & 0x80ULL)) || (level == 1U && leaf && !page1Gb)) {
            /* P=1/RSV=1 distinguishes an invalid present entry from a missing page. */
            walk->fault |= 9ULL;
            /* Reflect a real reserved-bit violation instead of hiding it. */
            return KSW_NNPT_FAULT;
        }
        /* Writes/user access require permission at all traversed levels. */
        permissions = (permissions & (entry & 7ULL)) | ((permissions | entry) & KSW_NNPT_NX);
        /* Final-page translation retains the complete large-page offset. */
        if (leaf) {
            /* Bits below a large leaf's boundary are reserved, except PAT at bit 12. */
            KswSvmU64 offsetMask = (1ULL << shift) - 1ULL;
            /* A large leaf never treats its PAT bit as physical address bit 12. */
            KswSvmU64 reserved = shift == 12U ? 0ULL : offsetMask & KSW_NNPT_FRAME & ~0x1000ULL;
            /* Reject misaligned large pages rather than silently rounding the frame. */
            if (entry & reserved) { walk->fault |= 9ULL; return KSW_NNPT_FAULT; }
            /* Every nested access needs US; writes and fetches add restrictions. */
            if (!(permissions & 4ULL) || ((access & KSW_NNPT_WRITE) && !(permissions & 2ULL)) ||
                ((access & KSW_NNPT_EXECUTE) && (permissions & KSW_NNPT_NX))) {
                /* A protection violation has a present source mapping. */
                walk->fault |= 1ULL;
                /* Do not publish a usable translation for a denied access. */
                return KSW_NNPT_FAULT;
            }
            /* Combine the aligned physical base with the full guest page offset. */
            walk->address = (entry & kMask & ~offsetMask) | (gpa & offsetMask);
            /* Preserve effective restrictions for composition with the outer map. */
            walk->permissions = permissions;
            /* Preserve leaf size for A/D and cache diagnostics. */
            walk->leafShift = shift;
            /* AMD uses PWT/PCD plus PAT at bit 7 or bit 12, unlike Intel EPT types. */
            walk->patIndex = (unsigned int)((entry >> 3) & 3ULL) |
                (unsigned int)(((entry >> (shift == 12U ? 7U : 12U)) & 1ULL) << 2);
            /* No NPF is pending for a successful translation. */
            walk->fault = 0;
            /* Only a completed walk can participate in composition or A/D updates. */
            walk->complete = 1;
            /* Return the actual mapped result. */
            return KSW_NNPT_OK;
        }
        /* Interior entries always point at a 4-KiB table. */
        table = entry & kMask;
    }
    /* The fourth level is always a leaf; never accept malformed loop fallthrough. */
    return KSW_NNPT_UNSUPPORTED;
}

/* Validate first, then publish A/D using compare-and-OR on the exact source slots. */
static __inline unsigned int kswSvmNestedNptCommitAd(KswNnptWalk* walk,
    unsigned int written, KswNnptRead read, KswNnptCompareOr update, void* context)
{
    /* A partial walk must never dirty an unrelated source entry. */
    unsigned int index;
    /* Require both the read and atomic update contracts. */
    if (!walk || !walk->complete || walk->count == 0U || walk->count > 4U || !read || !update ||
        (written && !(walk->access & KSW_NNPT_WRITE))) { return KSW_NNPT_UNSUPPORTED; }
    /* A failed commit must not leave a publishable translation behind. */
    walk->complete = 0;
    /* Revalidate the entire path before the first software-maintained A/D write. */
    for (index = 0; index < walk->count; ++index) {
        /* Each read starts from a defined sentinel. */
        KswSvmU64 value = 0;
        /* Failed access must not become a guest page fault. */
        if (!read(context, walk->entryAddress[index], &value)) { return KSW_NNPT_UNREADABLE; }
        /* Concurrent remapping, including A/D changes, requires a fresh walk. */
        if (value != walk->entryValue[index]) { return KSW_NNPT_RETRY; }
    }
    /* Partial accessed-bit progress on a retry is legal; frame updates are never lost. */
    for (index = 0; index < walk->count; ++index) {
        /* Only the final leaf receives Dirty for an actually performed write. */
        KswSvmU64 bits = 0x20ULL | ((written && index + 1U == walk->count) ? 0x40ULL : 0ULL);
        /* Never write a stale cached entry back over a concurrent source mutation. */
        if (!update(context, walk->entryAddress[index], walk->entryValue[index], bits)) { return KSW_NNPT_RETRY; }
        /* Keep the snapshot consistent with this successful update. */
        walk->entryValue[index] |= bits;
    }
    /* The caller still owns invalidation/epoch serialization before hardware publication. */
    walk->complete = 1;
    /* Every source word still referred to the walked mapping at its atomic update. */
    return KSW_NNPT_OK;
}

/* Compose a 4-KiB WB/UC leaf; unsupported cache types require explicit admission refusal. */
static __inline unsigned int kswSvmNestedNptCompose4k(const KswNnptWalk* inner,
    const KswNnptWalk* outer, KswSvmU64 innerPat, KswSvmU64 outerPat,
    KswSvmU64 hardwarePat, KswSvmU64* leaf)
{
    /* Resolve both source leaf cache indices without rewriting the host PAT. */
    unsigned int innerType, outerType, type, index;
    /* A rejected composition must not leave a stale valid leaf behind. */
    if (!leaf) { return KSW_NNPT_UNSUPPORTED; }
    /* Clear output before validating either input. */
    *leaf = 0;
    /* Do not compose unrelated or incomplete physical translations. */
    if (!inner || !outer || !inner->complete || !outer->complete ||
        inner->address != outer->inputAddress || inner->access != outer->access ||
        inner->patIndex > 7U || outer->patIndex > 7U ||
        (inner->address & 0xfffULL) != (outer->address & 0xfffULL)) { return KSW_NNPT_UNSUPPORTED; }
    /* Guest NPT cache semantics use the corresponding hypervisor's PAT. */
    innerType = (unsigned int)((innerPat >> (inner->patIndex * 8U)) & 0xffULL);
    /* Outer source NPT has its own cache selection. */
    outerType = (unsigned int)((outerPat >> (outer->patIndex * 8U)) & 0xffULL);
    /* Initial composition deliberately accepts only the unambiguous WB/UC subset. */
    if ((innerType != 0U && innerType != 6U) || (outerType != 0U && outerType != 6U)) { return KSW_NNPT_UNSUPPORTED; }
    /* UC dominates WB; an unknown memory type is never promoted to WB. */
    type = innerType == 0U || outerType == 0U ? 0U : 6U;
    /* Select an existing host PAT slot with exactly the required effective type. */
    for (index = 0; index < 8U; ++index) {
        /* Preserve all permission intersections and propagate either NX restriction. */
        if (((hardwarePat >> (index * 8U)) & 0xffULL) == type) {
            /* Hardware A/D begins clear and must later be propagated through both paths. */
            *leaf = (outer->address & KSW_NNPT_FRAME) | (inner->permissions & outer->permissions & 7ULL) |
                ((inner->permissions | outer->permissions) & KSW_NNPT_NX) | (kswNptLeafFlags(1U, index) & ~7ULL);
            /* Return the actual encoding selected for the host's PAT layout. */
            return KSW_NNPT_OK;
        }
    }
    /* No compatible PAT slot is an unsupported mapping, not a reason to write PAT. */
    return KSW_NNPT_UNSUPPORTED;
}
