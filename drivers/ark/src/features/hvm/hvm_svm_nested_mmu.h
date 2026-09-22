/* Bounded software composition of NPT12 and NPT01; no Windows or hardware calls. */
#pragma once
#include "hvm_svm_nested_npt.h"

/* Fault ownership is separate from the architectural NPF error bits. */
#define KSW_NMMU_INNER 1U
/* NPT01 rejected an access to an NPT12 table, not to the final data page. */
#define KSW_NMMU_OUTER_TABLE 2U
/* NPT01 rejected the translated final data page. */
#define KSW_NMMU_OUTER_DATA 3U
/* Physical window / RAM admission failure must not be reflected as a guest NPF. */
#define KSW_NMMU_PHYSICAL 4U
/* Preserve the original hardware NPF context when reflecting an NPT12 fault. */
#define KSW_NMMU_FINAL (1ULL << 32)
/* A guest page-table access is always a nested-level user write. */
#define KSW_NMMU_TABLE (1ULL << 33)

/* Captured by the future entry owner; immutable throughout one resolution. */
typedef struct KswNmmuConfig {
    /* Inner addresses refer to L1 physical memory; outer addresses are host physical. */
    KswSvmU64 innerRoot, outerRoot;
    /* These PATs belong to the two page-table owners, not to the final L2 guest. */
    KswSvmU64 innerPat, outerPat, hardwarePat;
    /* Stamp each result; hardware publication must hold the same invalidation epoch. */
    KswSvmU64 epoch;
    /* The current backend admits only four-level, at most 48-bit paging. */
    unsigned int innerBits, outerBits, innerPage1Gb, outerPage1Gb;
    /* NX reserved-bit checks follow the corresponding page-table owner's EFER. */
    unsigned int innerNx, outerNx;
} KswNmmuConfig;

/* Callbacks operate on host physical RAM, validate ownership, and never allocate. */
typedef struct KswNmmuIo {
    /* Every successful read returns one aligned, complete source word. */
    KswNnptRead read;
    /* The update must be an atomic compare-exchange, not a read followed by a write. */
    KswNnptCompareOr compareOr;
    /* Per-CPU physical window and immutable RAM inventory are supplied by the owner. */
    void* context;
} KswNmmuIo;

/* Preserve both walks for diagnostics; no pointer to a temporary mapping escapes. */
typedef struct KswNmmuResult {
    /* Zero unless all translations, cache checks and A/D commits succeeded. */
    KswSvmU64 leaf;
    /* Original input and epoch allow a caller to reject unrelated/stale results. */
    KswSvmU64 gpa, epoch;
    /* Only Inner faults are candidates for reflection into the inner VMM. */
    KswSvmU64 faultAddress, faultInfo;
    /* Raw software outcome, ownership, and successful physical read count. */
    unsigned int status, faultOwner, reads;
    /* Inner slots are guest physical; outer slots are host physical. */
    KswNnptWalk inner, outer;
} KswNmmuResult;

/* Produces one 4-KiB leaf; does not install it or claim a hardware TLB flush. */
unsigned int kswSvmNestedMmuResolve(const KswNmmuConfig* config,
    const KswNmmuIo* io, KswSvmU64 gpa, unsigned int access,
    KswSvmU64 faultContext, KswNmmuResult* result);
