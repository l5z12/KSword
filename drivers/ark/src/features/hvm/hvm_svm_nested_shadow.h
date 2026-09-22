/* CPU-owned sparse NPT02 using only pages allocated before residency. */
#pragma once
#include "hvm_svm_nested_mmu.h"

/* Distinguish budget exhaustion from corrupt ownership and stale translation. */
#define KSW_NSHADOW_OK 0U
/* The caller may recycle only while the owning CPU is outside its nested guest. */
#define KSW_NSHADOW_FULL 1U
/* Invalid input or ownership must never produce a hardware table pointer. */
#define KSW_NSHADOW_INVALID 2U
/* A changed epoch requires resolving the source paths again. */
#define KSW_NSHADOW_STALE 3U
/* Bound lookup cost and table memory to one MiB per prepared CPU. */
#define KSW_NSHADOW_MAX_PAGES 256U

/* The allocator owns these pages; this module neither allocates nor frees them. */
typedef struct KswNshadowPage {
    /* Nonpaged, 4-KiB aligned kernel mapping. */
    KswSvmU64* words;
    /* Validated physical address within the CPU's physical-width contract. */
    KswSvmU64 physical;
} KswNshadowPage;

/* Access is serialized by CPU ownership, never by waiting on an exit-path lock. */
typedef struct KswNshadow {
    /* Stable allocation ledger captured during prepare. */
    KswNshadowPage* pages;
    /* No published entry may refer beyond Used. */
    unsigned int capacity, used;
    /* Nonzero means the next hardware VMRUN must flush its TLB. */
    unsigned int flushPending;
    /* Candidate leaves must name exactly this generation. */
    KswSvmU64 epoch;
    /* Physical and GPA widths are deliberately limited to four-level NPT. */
    KswSvmU64 addressMask;
} KswNshadow;

/* Preparation only: verifies all mappings/physical frames and creates an empty root. */
unsigned int kswSvmNestedShadowInitialize(KswNshadow* shadow,
    KswNshadowPage* pages, unsigned int count, unsigned int physicalBits);
/* Owning CPU must be outside VMRUN, and must request a hardware flush before reentry. */
unsigned int kswSvmNestedShadowReset(KswNshadow* shadow);
/* Installs a fully committed MMU result; a full pool leaves the tables unchanged. */
unsigned int kswSvmNestedShadowInstall(KswNshadow* shadow, const KswNmmuResult* result);
