/*
 * KswordArkHvmEptSwitch.h
 *
 * In the 'Switch EPTP' separated-view backend, bit operations and state machines that calculate incorrectly without raising
 * errors—only silently producing wrong results—are centralized here. The inclusion criteria match KswordArkHvmControls.h
 * exactly: pure input-to-output transformations with no side effects, where errors are difficult to detect immediately.
 *
 * ------------------------------------------------------------------
 * What is this mechanism, and why is its arithmetic so prone to silent errors?
 * ------------------------------------------------------------------
 *
 * Today's separation view uses 'write leaf + monitor-trap': the primary value denies the access type requiring redirection,
 * the EPT violation changes the leaf to the secondary value, and armed MTF forces the guest to retire one instruction.
 * Then, in the MTF exit handler, the leaf is changed back to the primary value. Each redirected access incurs two VM exits,
 * and since the leaf is immediately restored each time, N consecutive accesses of the same type result in 2N exits.
 *
 * This backend is redesigned to place 'primary' and 'secondary' values into two distinct, complete hierarchical layers.
 * At runtime, it performs a single VMWRITE to the EPT_POINTER field of its own VMCS to swap the tree currently traversed
 * by the processor, without writing any leaf nodes, without enabling MTF, and without issuing INVEPT. Consequently, 2N
 * exits are reduced to 1, and there is 'no software write to the EPT table at runtime.' The fact that a flip on one
 * processor is invisible to others is guaranteed by construction, not by squeezing the window into a single instruction.
 *
 * The correctness of this backend relies almost entirely on **bitfield layout and index
 * encoding**; errors of this type share the common characteristic of having no diagnostic surface.
 *
 *   - If reserved bits in leaf entries are not cleared, or if 2MiB leaf page frames are not aligned to 2MiB
 *     boundaries, the symptom is an EPT misconfiguration (exit reason 49) triggered by a memory access after
 *     VM entry. That exit does not specify which bit is incorrect; it only indicates that one bit is wrong.
 *   - The page traversal level field in EPTP stores 'level minus one'. Writing 4 instead of
 *     3 causes VM entry to fail directly, with the error code containing only a single value.
 *   - The hierarchy index and leaf number differ by one. The recovery criterion applies to an unrelated
 *     page, leaving the protected page completely unprotected while all self-checks report green.
 *   - A single branch error in the decision state machine leads to either: a page permanently stuck at the shadow level (with no error reported),
 *     or a combination that should fail-closed is allowed through, forming a non-progressing loop, manifesting as **system-wide silent deadlock**:
 *     No BSOD, no events, no logs; every exit appears completely normal when viewed individually.
 *
 * These are not errors that can be discovered by a single run, so they must be proven on the build machine. This header file is
 * shared by kernel-mode C and host-mode C++ unit tests with a single implementation (not copied), ensuring they never drift.
 *
 * ------------------------------------------------------------------
 * Layer numbering: Why 1 + L sets instead of 2 sets?
 * ------------------------------------------------------------------
 *
 * The reference implementation only has two levels: 'all primary values' and 'all secondary values', which is correct when there is only one set of unified hook states.
 * This driver allows multiple views to be installed simultaneously, but EPTP is a **single** value per
 * processor — a processor can only be in one hierarchy at a time. Using the "full-level" values to serve a read
 * for a specific page will inadvertently replace other view pages with level values, causing an untouched CLOAK
 * page to expose a shadow to readers during this period. This is a semantic change, not a performance change.
 *
 * Thus the indices are: index 0 = base (take the primary value for every leaf, i.e., today's steady state), index k =
 * "only leaf k-1 takes the secondary value, all others take the primary value". This immediately yields three properties:
 *   - At any moment, at most one leaf is relaxed; the impact scope is identical to today's MTF mechanism on a per-byte basis;
 *   Switching from level c to level f automatically retracts the c leaf to the main value without extra actions;
 *   - "Whether the leaf is relaxed" means "whether the index is 0"; no second boolean is needed for synchronization.
 *
 * ------------------------------------------------------------------
 * Unsupported combinations: why the rejection criteria are as critical as the state machine.
 * ------------------------------------------------------------------
 *
 * If the hierarchy depth is less than 2^L, there must exist a combination where a single instruction requires leaf values from two different
 * nodes (e.g., instruction fetch lands in a HOOK page while the operand read lands in a CLOAK page; or an RIP-relative data reference within a
 * CLOAK code page points to itself). Such a combination cannot hold within any single hierarchy set. Under the MTF mechanism, the outcome is
 * fail-closed: exit virtualization. If EPTP switching is not detected, it causes a silent deadlock.
 *
 * **Here it is mandatory to precisely specify which half is responsible by whom, because the previous version's documentation was
 * incorrect here, and the consequence of that error was that integrators assumed the rejection was already complete.** The two halves are:
 *
 *   - Single leaf cannot represent the condition (a single violation simultaneously requires both the
 *     primary and secondary values of the same leaf, e.g., 'Read + Fetch' on a CLOAK page): Determined
 *     by KswordArkHvmEptSwDecide, returning REASON_UNREPRESENTABLE. This half is purely functional and
 *     determinable because all information for a single violation is contained in the parameters.
 *   - **Cross-leaf** access cannot be represented when instruction fetch is on a HOOK page and an operand read is on a CLOAK page:
 *     KswordArkHvmEptSwDecide **cannot see this**, because it receives one violation at a time,
 *     and each half of that violation can be serviced in isolation. The result is an endless
 *     SWITCH k -> SWITCH j -> SWITCH k -> ... loop at the same RIP, with every individual exit
 *     appearing normal. Only the cross-exit **forward-progress ledger**,
 *     KswordArkHvmEptSwProgressAdmit (in the latter part of this file), can detect this case.
 *     Calling it is a **precondition** for KswordArkHvmEptSwPlanSwitch, not optional hardening:
 *     The caller must have the ledger acknowledge that this switch is progressing before actually writing to the VMCS. If
 *     the ledger indicates it is not progressing, follow the fail-closed path, which is the same path as a flip failure.
 *
 * Therefore, every REFUSE in this file, and every rejection by ProgressAdmit, is a **signal that
 * must be routed to a fail-closed sink** by the upper layer, not a hint that can be ignored.
 *
 * ------------------------------------------------------------------
 * Dependency
 * ------------------------------------------------------------------
 *
 * Includes only the same-family KswordArkHvmControls.h (also header-only, also not referencing WDK, CRT,
 * or Windows headers). **No longer includes <stdint.h>**: The other two headers in this family (Controls
 * and EptpSwitch) use only unsigned long long / unsigned long and static __inline. All three headers must
 * adhere to the same portability contract; otherwise, if this file is later added to tools/hvm_unit_tests/
 * as a C translation unit (TU), changing the compiler version will cause compilation to fail.
 *
 * Includes Controls.h for a second reason: the bit layout for EPT/EPTP originally existed in three
 * copies in this repository (KSW_EPT_* in hvm_internal.h, Controls.h, and this file). For any constants
 * already defined in Controls.h, this file uses **aliases** instead of redefining the values. Redefining
 * them would create a second source of truth, which is exactly what this file exists to eliminate.
 *
 * ------------------------------------------------------------------
 * Relationship with the deleted KswordArkHvmEptpSwitch.h (merge record)
 * ------------------------------------------------------------------
 *
 * shared/driver/KswordArkHvmEptpSwitch.h was another implementation of the same design (prefix
 * KswordArkHvmEptp*); both files were written on the same day but never integrated. This file is the
 * superset. After merging, that header and its tools/hvm_unit_tests/hvm_eptp_switch_tests.c were
 * deleted (neither had any production code or CI references; copies remain in this round's scratchpad).
 * Keep this mapping table for future reference to track where EptpXxx moved to in older commits:
 * The only items in that header not originally in this file are the progress ledger (ProgressReset /
 * ProgressAdmit / MAX_SAME_RIP_SWITCHES / PROGRESS structure), which have been merged into the end of this file
 * according to its naming and limits. Every other item has a corresponding, stricter version in this file:
 *
 *   EptpAccessToLeafBits -> EptSwAccessToLeafBits (with additional numeric assertions)
 *   EptpLeafGrants -> EptSwGrants (with additional PERM_MASK masking)
 *   EptpLeafIsLegal -> EptSwPermissionsAreLegal (a component of LeafIsWellFormed)
 *   EptpBuildPair          -> EptSwKindPermissions + EptSwComposeLeaf
 *   EptpPairIsTotal -> EptSwPairIsTotal (bitwise identical); EptpIndexFromLeaf/LeafFromIndex/IndexIsBase
 *   -> corresponding EptSw* versions (with additional boundary rejection).
 *   EptpDecide -> EptSwDecide (adds reason code and null pointer rejection)
 *   EptpViewPageCost/TotalPageCost -> EptSwBaseCount + EptSwSecondaryPageCost
 *                                     (Additionally includes the MAX_LEAVES upper bound)
 *   ACTION_PASS -> No corresponding mapping, as that constant is never returned in its own file.
 *
 * In other words, the merged header is purely redundant and has been deleted.
 * The only intentionally preserved difference is the leaf count limit; see the comment for MAX_LEAVES for the rationale.
 */

#pragma once

#include "KswordArkHvmControls.h"

/* ------------------------------------------------------------------ */
/* Compile-time assertion                                                           */
/* ------------------------------------------------------------------ */

/*
 * Relationships between constants are enforced via compile-time assertions, not comments.
 * Uses the old negative-length array trick because it behaves consistently
 * in C89 MSVC and C++, requiring neither /std:c11 nor <assert.h>.
 */
#define KSWORD_ARK_HVM_EPTSW_CAT_(a, b) a##b
#define KSWORD_ARK_HVM_EPTSW_CAT(a, b) KSWORD_ARK_HVM_EPTSW_CAT_(a, b)
#define KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(expr) \
    typedef char KSWORD_ARK_HVM_EPTSW_CAT(KswordArkHvmEptSwAssert_, __LINE__)[(expr) ? 1 : -1]

/* ------------------------------------------------------------------ */
/* Bit layout of EPT leaf entries.                                                     */
/* ------------------------------------------------------------------ */

/*
 * Three permission bits. Values come from the architecture (SDM Vol.3C, Table 29-6 "Format of an EPT")
 * Page-Table Entry bit 0 = read, bit 1 = write, bit 2 = execute. This
 * is not a convention of this driver; never renumber these bits.
 *
 * Alias to Controls.h instead of rewriting values: rewriting creates a second source of truth. Once
 * positions are renumbered, hardware won't error but will apply permissions differently—CLOAK's 'unreadable'
 * becomes 'unwritable', shadow pages permanently expose to all readers, and all self-checks pass.
 */
#define KSWORD_ARK_HVM_EPTSW_READ    KSWORD_ARK_HVM_EPT_READ
#define KSWORD_ARK_HVM_EPTSW_WRITE   KSWORD_ARK_HVM_EPT_WRITE
#define KSWORD_ARK_HVM_EPTSW_EXECUTE KSWORD_ARK_HVM_EPT_EXECUTE
/* Union of the three permission bits, repeatedly used for the inverse mask of "everything except permissions". */
#define KSWORD_ARK_HVM_EPTSW_PERM_MASK          \
    (KSWORD_ARK_HVM_EPTSW_READ |                \
     KSWORD_ARK_HVM_EPTSW_WRITE |               \
     KSWORD_ARK_HVM_EPTSW_EXECUTE)

/* Aliased bits must remain the same three architectural bits. This is a numeric assertion, not a symbol self-equality check. */
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(KSWORD_ARK_HVM_EPTSW_READ == 0x1ULL);
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(KSWORD_ARK_HVM_EPTSW_WRITE == 0x2ULL);
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(KSWORD_ARK_HVM_EPTSW_EXECUTE == 0x4ULL);
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(KSWORD_ARK_HVM_EPTSW_PERM_MASK == 0x7ULL);

/* Leaf memory type field: bits 5:3 (SDM Table 29-6, EPT memory type). */
#define KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_SHIFT 3
#define KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_MASK 0x7ULL

/*
 * bit 6 = ignore PAT; bit 7 = large page flag (only meaningful on PDPTE/PDE).
 *
 * Only a numeric assertion can pin these two bits: moving IGNORE_PAT to bit 5 places it in the memory type field,
 * causing a WB page to be treated as a WP page; moving LARGE_PAGE by one bit causes the processor to treat a 2MiB
 * leaf as a pointer to the next-level table, directly accessing page content. Neither case triggers an error.
 */
#define KSWORD_ARK_HVM_EPTSW_IGNORE_PAT 0x0000000000000040ULL
#define KSWORD_ARK_HVM_EPTSW_LARGE_PAGE 0x0000000000000080ULL
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_IGNORE_PAT == (1ULL << 6));
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_LARGE_PAGE == (1ULL << 7));
/* Neither ignore-PAT nor the large-page bit may overlap the memory-type field; otherwise, one assignment would change the cache type. */
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    ((KSWORD_ARK_HVM_EPTSW_IGNORE_PAT | KSWORD_ARK_HVM_EPTSW_LARGE_PAGE) &
     (KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_MASK <<
      KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_SHIFT)) == 0ULL);

/*
 * bits 9:8 = accessed / dirty (written by hardware only if EPTP A/D is enabled).
 * Bit 8 is accessed, bit 9 is dirty; their order must not be swapped. Swapping them causes "this page was written" to
 * be misinterpreted as "this page was accessed," causing any A/D-based forensic criteria to yield inverted conclusions.
 */
#define KSWORD_ARK_HVM_EPTSW_ACCESSED 0x0000000000000100ULL
#define KSWORD_ARK_HVM_EPTSW_DIRTY    0x0000000000000200ULL
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_ACCESSED == (1ULL << 8));
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_DIRTY == (1ULL << 9));

/* bit 10 = User-mode executable (only meaningful under mode-based execute control). */
#define KSWORD_ARK_HVM_EPTSW_USER_EXECUTE 0x0000000000000400ULL
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_USER_EXECUTE == (1ULL << 10));

/*
 * bit 63 = suppress-#VE. The architecture default is inverted: leafs with this bit as 0 are "convertible",
 * so once EPT-violation #VE is enabled, every violation on such a leaf is reflected into the guest. Here,
 * the guest is the running Windows, whose IDT[20] is not prepared for our invented #VE, resulting in
 * #GP -> #DF -> triple fault。
 *
 * Therefore, 'attribute inheritance' must carry this bit. Dropping it causes no error during installation or in any
 * driver self-check — only when #VE is enabled and that page is actually accessed does it crash the machine in one shot.
 */
#define KSWORD_ARK_HVM_EPTSW_SUPPRESS_VE 0x8000000000000000ULL

/* Physical address field shared by leaf entries and EPTP: bits 51:12. Alias, for the same reason as permission bits. */
#define KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK KSWORD_ARK_HVM_EPT_PHYSICAL_MASK
/* 2MiB leaf page frame field: bits 51:21. Bits 20:12 are **reserved and must be zero** on large page leaves. */
#define KSWORD_ARK_HVM_EPTSW_LARGE_FRAME_MASK 0x000FFFFFFFE00000ULL
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK == 0x000FFFFFFFFFF000ULL);

/*
 * bits 62:52. Architecturally, this segment is partially 'ignored' and partially handled by verify-guest-paging /
 * Features such as paging-write-access and supervisor shadow stack, which this driver never enables.
 * This driver's policy requires this segment to be all zeros: any non-zero bits here indicate either memory corruption or a
 * misplaced bitwise OR with a shifted value; both cases warrant immediate rejection rather than proceeding to the machine.
 *
 * Note that this covers only bits 62:52, excluding bit 63: bit 63 of the leaf is the suppress-#VE flag, which
 * is valid in the leaf and must be set. Bit 63 of the EPTP is reserved and must be zero; therefore, a wider
 * mask, KSWORD_ARK_HVM_EPTSW_EPTP_RESERVED_HIGH, is used separately. The two masks are not interchangeable.
 */
#define KSWORD_ARK_HVM_EPTSW_RESERVED_HIGH 0x7FF0000000000000ULL

/* Byte counts for pages and large pages, entries per table, and entry width. The first two are aliases to Controls.h. */
#define KSWORD_ARK_HVM_EPTSW_PAGE_BYTES KSWORD_ARK_HVM_PAGE_BYTES
#define KSWORD_ARK_HVM_EPTSW_LARGE_BYTES KSWORD_ARK_HVM_LARGE_PAGE_BYTES
#define KSWORD_ARK_HVM_EPTSW_TABLE_ENTRIES 512UL
#define KSWORD_ARK_HVM_EPTSW_ENTRY_BYTES 8ULL
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_PAGE_BYTES == 0x1000ULL);
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_LARGE_BYTES == 0x200000ULL);

/* suppress-#VE is bit 63, while bits 62:52 are the segment that this driver requires to be all zeros. */
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_SUPPRESS_VE == (1ULL << 63));
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_RESERVED_HIGH == 0x7FF0000000000000ULL);
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    (KSWORD_ARK_HVM_EPTSW_RESERVED_HIGH &
     KSWORD_ARK_HVM_EPTSW_SUPPRESS_VE) == 0ULL);
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_LARGE_FRAME_MASK ==
    (KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK &
     ~(KSWORD_ARK_HVM_EPTSW_LARGE_BYTES - 1ULL)));
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    (KSWORD_ARK_HVM_EPTSW_TABLE_ENTRIES * KSWORD_ARK_HVM_EPTSW_ENTRY_BYTES) ==
    KSWORD_ARK_HVM_EPTSW_PAGE_BYTES);

/*
 * EPT memory type encodings defined by the architecture (SDM Vol.3C, 29.3.7 "EPT and Memory Typing").
 * 0 = UC, 1 = WC, 4 = WT, 5 = WP, 6 = WB; 2, 3, and 7 are reserved. Writing them into a leaf causes an EPT
 * misconfiguration. UC and WB are aliased to Controls.h, which uses the same encoding on the EPTP side.
 */
#define KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_UC KSWORD_ARK_HVM_EPTP_MEMORY_TYPE_UC
#define KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_WC 1ULL
#define KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_WT 4ULL
#define KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_WP 5ULL
#define KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_WB KSWORD_ARK_HVM_EPTP_MEMORY_TYPE_WB
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_UC == 0ULL);
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_WC == 1ULL);
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_WT == 4ULL);
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_WP == 5ULL);
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_WB == 6ULL);

/*
 * Capabilities used in this file from IA32_VMX_EPT_VPID_CAP.
 * （SDM Vol.3D, Appendix A.10「VPID and EPT Capabilities」）。
 *
 * These values are bitwise-ANDed with a real MSR value. A single-bit offset error manifests as either 'hardware supports
 * it but is incorrectly judged as unsupported' (causing an unnecessary, visible downgrade) or worse, 'hardware does not
 * support it but is incorrectly judged as supported'. If the execute-only bit is misread, CLOAK's main value is treated as
 * available, while the actual --x leaf written to the machine is a misconfiguration on hardware lacking this capability.
 * Existing four-bit aliases are in Controls.h; all four-bit values have separate assertions.
 */
#define KSWORD_ARK_HVM_EPTSW_CAP_EXECUTE_ONLY  0x0000000000000001ULL /* bit 0  */
#define KSWORD_ARK_HVM_EPTSW_CAP_PAGE_WALK_4   KSWORD_ARK_HVM_EPT_CAP_PAGE_WALK_4
#define KSWORD_ARK_HVM_EPTSW_CAP_MEMORY_TYPE_UC KSWORD_ARK_HVM_EPT_CAP_MEMORY_TYPE_UC
#define KSWORD_ARK_HVM_EPTSW_CAP_MEMORY_TYPE_WB KSWORD_ARK_HVM_EPT_CAP_MEMORY_TYPE_WB
#define KSWORD_ARK_HVM_EPTSW_CAP_INVEPT        0x0000000000100000ULL /* bit 20 */
#define KSWORD_ARK_HVM_EPTSW_CAP_ACCESSED_DIRTY KSWORD_ARK_HVM_EPT_CAP_ACCESSED_DIRTY
#define KSWORD_ARK_HVM_EPTSW_CAP_INVEPT_SINGLE 0x0000000002000000ULL /* bit 25 */
#define KSWORD_ARK_HVM_EPTSW_CAP_INVEPT_ALL    0x0000000004000000ULL /* bit 26 */

KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_CAP_EXECUTE_ONLY == (1ULL << 0));
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_CAP_PAGE_WALK_4 == (1ULL << 6));
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_CAP_MEMORY_TYPE_UC == (1ULL << 8));
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_CAP_MEMORY_TYPE_WB == (1ULL << 14));
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_CAP_INVEPT == (1ULL << 20));
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_CAP_ACCESSED_DIRTY == (1ULL << 21));
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_CAP_INVEPT_SINGLE == (1ULL << 25));
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_CAP_INVEPT_ALL == (1ULL << 26));

/*
 * Read from the capability MSR whether execute-only is available.
 *
 * The previous version defined CAP_EXECUTE_ONLY but no function read it, so the macro could be moved to any bit position
 * without affecting unit tests (the reviewer's mutation M16 survived this way). Additionally, each caller independently
 * decoded bit 0, creating N distinct truth sources for the same check. This function consolidates that logic.
 * The consequences of the check are asymmetric: if it incorrectly reports 'supported' when hardware does not support it, writing
 * the --x leaf results in an EPT misconfiguration; if it incorrectly reports 'not supported', it only incurs an extra downgrade.
 */
static __inline int
KswordArkHvmEptSwExecuteOnlySupported(
    unsigned long long EptVpidCapability
    )
{
    return (EptVpidCapability & KSWORD_ARK_HVM_EPTSW_CAP_EXECUTE_ONLY) != 0ULL
        ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* Protocol scale limit                                                         */
/* ------------------------------------------------------------------ */

/*
 * Maximum number of swappable leaves, consistent with the capacity of the view
 * table in the protocol (KSWORD_ARK_HVM_MAX_VIEWS = 32 in KswordArkHvmIoctl.h).
 *
 * Defined this early because **every** function consuming LeafCount must use it as an upper bound,
 * including the one at the very top of this file (PreEntryInvalidationCount). In the previous
 * version, it was defined in the page overhead section, so the earlier function had no upper bound
 * available, becoming the sole consumer that could overflow LeafCount = 0xFFFFFFFF into 0.
 *
 * Intentionally different from KSW_HVM_MAX_LOCAL_LEAVES (= 8) in hvm_ept_local.h: these two values represent different
 * quantities. The 8 is the maximum number of leaves supported per-processor private hierarchy, while the 32 here aligns with the
 * number of views the protocol can install simultaneously. If both mechanisms are combined during integration, the effective
 * limit is the **smaller** of the two. This must be explicitly handled by the integration owner at the integration point by
 * taking the min; do not rely on the two headers to align themselves—they describe fundamentally different constraints.
 */
#define KSWORD_ARK_HVM_EPTSW_MAX_LEAVES 32UL
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(KSWORD_ARK_HVM_EPTSW_MAX_LEAVES == 32UL);

/* ------------------------------------------------------------------ */
/* Leaf entry parsing                                                           */
/* ------------------------------------------------------------------ */

/* Extract the three permission bits from the leaf entry. */
static __inline unsigned long long
KswordArkHvmEptSwLeafPermissions(
    unsigned long long LeafEntry
    )
{
    return LeafEntry & KSWORD_ARK_HVM_EPTSW_PERM_MASK;
}

/* Extract the page frame from the leaf entry encoding (bits 51:12). */
static __inline unsigned long long
KswordArkHvmEptSwLeafFrame(
    unsigned long long LeafEntry
    )
{
    return LeafEntry & KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK;
}

/* Extract the memory type code from the leaf entry. */
static __inline unsigned long long
KswordArkHvmEptSwLeafMemoryType(
    unsigned long long LeafEntry
    )
{
    return (LeafEntry >> KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_SHIFT) &
        KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_MASK;
}

/*
 * Extract everything except permissions and page frame.
 *
 * This is the source of attribute inheritance in the view construction: memory type, ignore-PAT, large page flags, A/D,
 * Suppress-#VE is entirely contained here. Implementing this function by 'keeping a whitelist' rather than
 * 'subtracting two fields' is dangerous: if the whitelist misses a single bit, that bit silently becomes zero in
 * both primary and secondary values. The most critical of these are suppress-#VE (see its macro comment) and memory
 * type (changing MMIO pages from UC to WB causes random device behavior errors that no one would attribute to EPT).
 */
static __inline unsigned long long
KswordArkHvmEptSwLeafAttributes(
    unsigned long long LeafEntry
    )
{
    return LeafEntry &
        ~(KSWORD_ARK_HVM_EPTSW_PERM_MASK | KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK);
}

/*
 * Compose a leaf entry from attributes, page frame, and permissions.
 *
 * All three inputs must be masked; this is not defensive programming but a strict requirement.
 *   - If the page frame is not masked, an unaligned shadow physical address spills its lower 12 bits into the permission bits and memory
 *     type field, resulting in a leaf with wider-than-expected permissions and a modified cache type, yet appearing completely valid;
 *   - If permissions are not masked, any extra bits in the protocol access mask passed by the caller will fall into the memory type.
 *   - If attributes are not masked and the caller passes a complete original leaf entry (rather than the result of Attributes),
 *     the old and new page frames are bitwise ORed together, pointing to a location that is neither a real page nor a shadow page.
 *     Once CLOAK's main value points to the wrong frame, the wrong bytes are executed, and no anomaly is visible during installation.
 */
static __inline unsigned long long
KswordArkHvmEptSwComposeLeaf(
    unsigned long long Attributes,
    unsigned long long Frame,
    unsigned long long Permissions
    )
{
    return (Attributes &
                ~(KSWORD_ARK_HVM_EPTSW_PERM_MASK |
                  KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK)) |
        (Frame & KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK) |
        (Permissions & KSWORD_ARK_HVM_EPTSW_PERM_MASK);
}

/* ------------------------------------------------------------------ */
/* Well-formedness criteria for leaf entries                                                       */
/* ------------------------------------------------------------------ */

/* Result code for the well-formedness criteria of a leaf node. 0 = valid; other values indicate **which** specific criterion failed. */
#define KSWORD_ARK_HVM_EPTSW_LEAF_OK              0UL
#define KSWORD_ARK_HVM_EPTSW_LEAF_BAD_PARAMETER   1UL
#define KSWORD_ARK_HVM_EPTSW_LEAF_BAD_PERMISSIONS 2UL
#define KSWORD_ARK_HVM_EPTSW_LEAF_BAD_MEMORY_TYPE 3UL
#define KSWORD_ARK_HVM_EPTSW_LEAF_BAD_LARGE_BIT   4UL
#define KSWORD_ARK_HVM_EPTSW_LEAF_BAD_ALIGNMENT   5UL
#define KSWORD_ARK_HVM_EPTSW_LEAF_BAD_PHYS_WIDTH  6UL
#define KSWORD_ARK_HVM_EPTSW_LEAF_BAD_RESERVED    7UL

/* Valid range for physical address width, derived from the architectural lower and upper bounds in CPUID.80000008H:EAX[7:0]. */
#define KSWORD_ARK_HVM_EPTSW_MIN_PHYS_BITS 32UL
#define KSWORD_ARK_HVM_EPTSW_MAX_PHYS_BITS 52UL

/* Check if a memory type code is one of the five types defined by the architecture. */
static __inline int
KswordArkHvmEptSwMemoryTypeIsLegal(
    unsigned long long MemoryType
    )
{
    switch (MemoryType) {
    case KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_UC:
    case KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_WC:
    case KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_WT:
    case KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_WP:
    case KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_WB:
        /* Report the architecture-acknowledged encoding. */
        return 1;
    default:
        /* 2, 3, 7 are reserved: writing to a leaf entry constitutes an EPT misconfiguration. */
        return 0;
    }
}

/*
 * Check if a set of permission bits is valid under this mechanism.
 *
 * Three criteria: if any are not met, it becomes exit reason 49, and that exit does not tell you which bit failed:
 *   - Write requires read. EPT has no encoding for 'write-only'.
 *   Execution without read is legal only when hardware reports execute-only. Without this
 *     capability, writing X separately into the leaf causes the entire page to be misconfigured.
 *   - On architectures where all permissions are zero, this signifies 'non-existent' rather than an error, but this
 *     mechanism rejects it: a leaf granting no access of any kind will violate regardless of the hierarchy level, creating
 *     a non-progressing loop that manifests as a system-wide silent deadlock. Therefore, it is treated as illegal here.
 */
static __inline int
KswordArkHvmEptSwPermissionsAreLegal(
    unsigned long long Permissions,
    int ExecuteOnlySupported
    )
{
    const unsigned long long bits = Permissions & KSWORD_ARK_HVM_EPTSW_PERM_MASK;

    /* Reject 'non-existent' leaves: this mechanism can never find a hierarchy capable of serving them. */
    if (bits == 0ULL) {
        return 0;
    }
    /* Write access must include read access. */
    if ((bits & KSWORD_ARK_HVM_EPTSW_WRITE) != 0ULL &&
        (bits & KSWORD_ARK_HVM_EPTSW_READ) == 0ULL) {
        return 0;
    }
    /* Execute-only is allowed only if hardware supports it. */
    if ((bits & KSWORD_ARK_HVM_EPTSW_EXECUTE) != 0ULL &&
        (bits & KSWORD_ARK_HVM_EPTSW_READ) == 0ULL &&
        !ExecuteOnlySupported) {
        return 0;
    }
    /* Report that this set of permissions can be accepted by the hardware. */
    return 1;
}

/*
 * Check if the page frame is aligned according to its level.
 *
 * 4KiB leaves cannot be misaligned (physical domain starts at bit 12, lower 12 bits are other fields), so this function
 * is always true for non-large pages. This branch is retained so callers read it as 'check alignment by hierarchy' rather
 * than 'only check large pages'; if 1GiB leaves are introduced later, only one additional case needs to be added here.
 * For large page leaves, bits 20:12 must be zero (reserved). Writing a shadow frame aligned only to 4KiB into
 * a 2MiB leaf entry appears normal during installation but triggers a misconfiguration on the first access.
 */
static __inline int
KswordArkHvmEptSwFrameIsAligned(
    unsigned long long Frame,
    int IsLargePage
    )
{
    if (IsLargePage) {
        /* Large page leaves require 2 MiB alignment. */
        return (Frame & (KSWORD_ARK_HVM_EPTSW_LARGE_BYTES - 1ULL)) == 0ULL
            ? 1 : 0;
    }
    /* 4KiB leaf requires page alignment. */
    return (Frame & (KSWORD_ARK_HVM_EPTSW_PAGE_BYTES - 1ULL)) == 0ULL ? 1 : 0;
}

/*
 * Comprehensively validate a leaf entry, returning the **specific** failed item rather than a boolean.
 *
 * Check order is fixed: parameters, permissions, memory type, large page flag, page frame alignment, physical width, and reserved high bits.
 * The fixed order is required to allow unit tests to construct samples that fail on a single item at a time. If the order were
 * variable, tests could only assert 'non-zero', which would inadvertently allow regressions where a different item is incorrect.
 *
 * MaxPhysicalAddressBits comes from CPUID.80000008H:EAX[7:0]. Physical bits beyond
 * this width must be zero: an extra bit is not ignored; it causes a misconfiguration.
 */
static __inline unsigned long
KswordArkHvmEptSwLeafIsWellFormed(
    unsigned long long LeafEntry,
    int IsLargePage,
    unsigned long MaxPhysicalAddressBits,
    int ExecuteOnlySupported
    )
{
    unsigned long long widthMask = 0ULL;

    /* Reject a physical width impossible to come from CPUID to prevent undefined behavior in subsequent shifts. */
    if (MaxPhysicalAddressBits < KSWORD_ARK_HVM_EPTSW_MIN_PHYS_BITS ||
        MaxPhysicalAddressBits > KSWORD_ARK_HVM_EPTSW_MAX_PHYS_BITS) {
        return KSWORD_ARK_HVM_EPTSW_LEAF_BAD_PARAMETER;
    }
    /* The permission combination must be acceptable to the hardware. */
    if (!KswordArkHvmEptSwPermissionsAreLegal(
            KswordArkHvmEptSwLeafPermissions(LeafEntry),
            ExecuteOnlySupported)) {
        return KSWORD_ARK_HVM_EPTSW_LEAF_BAD_PERMISSIONS;
    }
    /* The memory type must be one of the five architectural encodings. */
    if (!KswordArkHvmEptSwMemoryTypeIsLegal(
            KswordArkHvmEptSwLeafMemoryType(LeafEntry))) {
        return KSWORD_ARK_HVM_EPTSW_LEAF_BAD_MEMORY_TYPE;
    }
    /*
     * The large page marker must match the level declared by the caller. Both types of inconsistency are extremely difficult to debug:
     * If this bit is not set, the processor will treat this entry as a pointer to the next-level table, causing page content to be interpreted as a page table.
     * Should not be set but was set; a 4KiB page table entry will be treated as a 2MiB leaf.
     */
    if (IsLargePage) {
        if ((LeafEntry & KSWORD_ARK_HVM_EPTSW_LARGE_PAGE) == 0ULL) {
            return KSWORD_ARK_HVM_EPTSW_LEAF_BAD_LARGE_BIT;
        }
    } else {
        if ((LeafEntry & KSWORD_ARK_HVM_EPTSW_LARGE_PAGE) != 0ULL) {
            return KSWORD_ARK_HVM_EPTSW_LEAF_BAD_LARGE_BIT;
        }
    }
    /* Page frames must be aligned to the hierarchy level. */
    if (!KswordArkHvmEptSwFrameIsAligned(
            KswordArkHvmEptSwLeafFrame(LeafEntry),
            IsLargePage)) {
        return KSWORD_ARK_HVM_EPTSW_LEAF_BAD_ALIGNMENT;
    }
    /* High bits exceeding the implementation width in the physical domain must be zero. */
    widthMask = KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK &
        ~((1ULL << MaxPhysicalAddressBits) - 1ULL);
    if ((LeafEntry & widthMask) != 0ULL) {
        return KSWORD_ARK_HVM_EPTSW_LEAF_BAD_PHYS_WIDTH;
    }
    /* High-order bits unused by this driver must be zero. */
    if ((LeafEntry & KSWORD_ARK_HVM_EPTSW_RESERVED_HIGH) != 0ULL) {
        return KSWORD_ARK_HVM_EPTSW_LEAF_BAD_RESERVED;
    }
    /* Report that this item is acceptable to the hardware. */
    return KSWORD_ARK_HVM_EPTSW_LEAF_OK;
}

/* ------------------------------------------------------------------ */
/* EPTP field.                                                            */
/* ------------------------------------------------------------------ */

/*
 * EPTP field layout: bits 2:0 memory type, bits 5:3 page walk level minus one, bit 6 A/D
 * （SDM Vol.3C, Table 25-9「Format of Extended-Page-Table Pointer」）。
 * All four fields are aliased to Controls.h for the same reason as permission bits: writing the value in two places means that if
 * someone changes one of them later, the VM entry will return a single error code instead of indicating which bit is inconsistent.
 */
#define KSWORD_ARK_HVM_EPTSW_EPTP_MEMORY_TYPE_MASK \
    KSWORD_ARK_HVM_EPTP_MEMORY_TYPE_MASK
#define KSWORD_ARK_HVM_EPTSW_EPTP_WALK_SHIFT \
    KSWORD_ARK_HVM_EPTP_WALK_LENGTH_SHIFT
#define KSWORD_ARK_HVM_EPTSW_EPTP_WALK_MASK KSWORD_ARK_HVM_EPTP_WALK_LENGTH_MASK
#define KSWORD_ARK_HVM_EPTSW_EPTP_ACCESSED_DIRTY KSWORD_ARK_HVM_EPTP_ACCESSED_DIRTY
/*
 * Bits 11:7 must be zero (bit 7 is used for supervisor shadow stack in newer SDM
 * versions; since this driver does not enable that control, it must still be zero for
 * us). This is not 'ignored'; a non-zero value will cause the VM entry to fail directly.
 */
#define KSWORD_ARK_HVM_EPTSW_EPTP_RESERVED_LOW KSWORD_ARK_HVM_EPTP_RESERVED_LOW

/*
 * Bits 63:52 are reserved and must be zero.
 *
 * The previous version had no separate check for these bits and relied on the side effect of widthMask
 * = ~((1 << MAXPHYADDR) - 1). On machines with MAXPHYADDR < 52, that mask also covers 63:52, so the
 * behavior was correct. The leaf path, however, uses the narrower PHYSICAL_MASK & ~(...) with a
 * separate RESERVED_HIGH check. These different forms invite a future cleanup to copy the leaf logic
 * here, leaving bits 63:52 unchecked. An EPTP with bit 55 set would then be accepted and written to the
 * VMCS, causing VM entry to fail with a numeric error code that does not identify the offending bit.
 * The mutation M15 reviewed does exactly this, and at that time none of the 344 assertions triggered.
 *
 * Thus, this segment now has its own mask, its own result code, and its own numeric assertions.
 * It is one bit wider than the leaf entry: the leaf's bit 63 is suppress-#VE
 * (valid and must be set), while EPTP's bit 63 is reserved and must be zero.
 */
#define KSWORD_ARK_HVM_EPTSW_EPTP_RESERVED_HIGH 0xFFF0000000000000ULL
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_EPTP_RESERVED_HIGH ==
    (KSWORD_ARK_HVM_EPTSW_RESERVED_HIGH | KSWORD_ARK_HVM_EPTSW_SUPPRESS_VE));
/* The reserved high bits and the physical address field must not overlap; otherwise, a valid root address could be misinterpreted as having non-zero reserved bits. */
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    (KSWORD_ARK_HVM_EPTSW_EPTP_RESERVED_HIGH &
     KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK) == 0ULL);
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_EPTP_MEMORY_TYPE_MASK == 0x7ULL);
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(KSWORD_ARK_HVM_EPTSW_EPTP_WALK_SHIFT == 3);
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(KSWORD_ARK_HVM_EPTSW_EPTP_WALK_MASK == 0x7ULL);
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_EPTP_ACCESSED_DIRTY == (1ULL << 6));
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_EPTP_RESERVED_LOW == 0x0000000000000F80ULL);

/* Four-level page-table walk used by this driver. */
#define KSWORD_ARK_HVM_EPTSW_EPTP_WALK_LEVELS 4UL

/* Result codes for EPTP well-formedness checks. */
#define KSWORD_ARK_HVM_EPTSW_EPTP_OK              0UL
#define KSWORD_ARK_HVM_EPTSW_EPTP_BAD_PARAMETER   1UL
#define KSWORD_ARK_HVM_EPTSW_EPTP_BAD_ROOT        2UL
#define KSWORD_ARK_HVM_EPTSW_EPTP_BAD_MEMORY_TYPE 3UL
#define KSWORD_ARK_HVM_EPTSW_EPTP_BAD_WALK        4UL
#define KSWORD_ARK_HVM_EPTSW_EPTP_BAD_AD          5UL
#define KSWORD_ARK_HVM_EPTSW_EPTP_BAD_RESERVED    6UL
#define KSWORD_ARK_HVM_EPTSW_EPTP_BAD_PHYS_WIDTH  7UL
/* Bits 63:52 non-zero: architecture reserved, independent of native implementation width. */
#define KSWORD_ARK_HVM_EPTSW_EPTP_BAD_RESERVED_HIGH 8UL

/*
 * Compose an EPTP from the root table physical address and three control fields.
 *
 * The only truly error-prone part is that the page traversal level field stores the level minus one: a 4-level walk writes
 * 3. Writing 4 causes VM entry failure, and the failure returns only an error code without indicating which field caused
 * it—on a target machine without a kernel debugger, this results in an immediate reboot with no way to determine the cause.
 *
 * The root address must also be masked: an unaligned root would spill lower bits into the memory type and level
 * fields, resulting in a pointer that appears merely "slightly wrong" but has completely scrambled fields.
 *
 * Returns 0 when the level is invalid. Since 0 is never a valid EPTP (the level field is
 * 0), it serves as a failure value that cannot be confused with any successful result.
 */
static __inline unsigned long long
KswordArkHvmEptSwComposeEptp(
    unsigned long long RootPhysical,
    unsigned long long MemoryType,
    unsigned long WalkLevels,
    int EnableAccessedDirty
    )
{
    unsigned long long eptp = 0ULL;

    /* The level field is only 3 bits, representing levels 1..8; other values cannot be encoded. */
    if (WalkLevels == 0UL || WalkLevels > 8UL) {
        return 0ULL;
    }
    /* Page-frame aligned to table boundary. */
    eptp = RootPhysical & KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK;
    /* The memory type occupies bits 2:0. */
    eptp |= MemoryType & KSWORD_ARK_HVM_EPTSW_EPTP_MEMORY_TYPE_MASK;
    /* The level field stores the level minus one. */
    eptp |= ((unsigned long long)(WalkLevels - 1UL) &
        KSWORD_ARK_HVM_EPTSW_EPTP_WALK_MASK) <<
        KSWORD_ARK_HVM_EPTSW_EPTP_WALK_SHIFT;
    /* A/D is set only if hardware supports it and the caller requests it. */
    if (EnableAccessedDirty) {
        eptp |= KSWORD_ARK_HVM_EPTSW_EPTP_ACCESSED_DIRTY;
    }
    /* Return the complete EPT pointer value. */
    return eptp;
}

/* Extract the physical address of the root table pointed to by EPTP. */
static __inline unsigned long long
KswordArkHvmEptSwEptpRoot(
    unsigned long long Eptp
    )
{
    return Eptp & KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK;
}

/* Extract the memory type encoding from EPTP. */
static __inline unsigned long long
KswordArkHvmEptSwEptpMemoryType(
    unsigned long long Eptp
    )
{
    return Eptp & KSWORD_ARK_HVM_EPTSW_EPTP_MEMORY_TYPE_MASK;
}

/*
 * Extract the page walk level from EPTP (not the raw field value).
 * Forgetting to add one during parsing and forgetting to subtract one during synthesis are two sides of the same error; both must be explicitly written.
 */
static __inline unsigned long
KswordArkHvmEptSwEptpWalkLevels(
    unsigned long long Eptp
    )
{
    return (unsigned long)(((Eptp >> KSWORD_ARK_HVM_EPTSW_EPTP_WALK_SHIFT) &
        KSWORD_ARK_HVM_EPTSW_EPTP_WALK_MASK) + 1ULL);
}

/* Report whether EPTP has accessed/dirty tracking enabled. */
static __inline int
KswordArkHvmEptSwEptpHasAccessedDirty(
    unsigned long long Eptp
    )
{
    return (Eptp & KSWORD_ARK_HVM_EPTSW_EPTP_ACCESSED_DIRTY) != 0ULL ? 1 : 0;
}

/*
 * Extract the EPT cache tag EP4TA (bits 51:12 of EPTP).
 *
 * This value is the pivot of the argument that no INVEPT is needed after switching EPTP: both guest-physical and
 * combined mappings are tagged by EP4TA; if the root addresses of the two layers differ, the tags differ, so cache
 * entries are not aliased. Conversely, if a construction bug causes the two "different" layers to share the same root,
 * switching changes no tags—the processor continues using the old translation, the same instruction faults again, and
 * we get a non-progressing loop. Thus, this value must be independently checkable, as in SwitchNeedsInvalidation below.
 */
static __inline unsigned long long
KswordArkHvmEptSwEp4ta(
    unsigned long long Eptp
    )
{
    return Eptp & KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK;
}

/*
 * Comprehensively validate an EPTP and return the specific failure item.
 *
 * Fixed criterion order: parameters, root address, memory type, level count,
 * A/D bits, reserved low bits, reserved high bits, and physical width.
 *
 * Relationship with KswordArkHvmControls.h's KswordArkHvmEptpIsValid (must be explicit; otherwise, the
 * same EPTP in a single driver could yield two different answers depending on which helper is called):
 * This function is **strictly stronger**: it rejects three additional cases—root address is
 * zero, MaxPhysicalAddressBits outside [32,52], and bits 63:52 non-zero. Thus, 'this function
 * returns EPTP_OK' implies 'KswordArkHvmEptpIsValid returns non-zero', but not vice versa.
 * Every EPTP switched to the backend must pass this function: the three additional rejections correspond to
 * construction errors that only cause silent traversal down the wrong tree: "slot not filled", "width parameter is
 * garbage", and "reserved bits injected by other code". A unit test assertion fixes this implication direction.
 *
 * Root address zero is listed separately: the field criteria do not cover it (0 is "valid" at the field level), but an EPTP with a root of zero
 * can only come from "a slot was left unfilled," and its consequence is the processor walking the page table starting from physical page 0.
 * Treating it as invalid converts a silent bug where execution drifts down the wrong tree into an explicit denial.
 */
static __inline unsigned long
KswordArkHvmEptSwEptpIsWellFormed(
    unsigned long long Eptp,
    unsigned long long EptVpidCapability,
    unsigned long MaxPhysicalAddressBits
    )
{
    const unsigned long long memoryType = KswordArkHvmEptSwEptpMemoryType(Eptp);
    unsigned long long widthMask = 0ULL;

    /* Reject a physical width that cannot come from CPUID. */
    if (MaxPhysicalAddressBits < KSWORD_ARK_HVM_EPTSW_MIN_PHYS_BITS ||
        MaxPhysicalAddressBits > KSWORD_ARK_HVM_EPTSW_MAX_PHYS_BITS) {
        return KSWORD_ARK_HVM_EPTSW_EPTP_BAD_PARAMETER;
    }
    /* A root address of zero means this slot has never been filled. */
    if (KswordArkHvmEptSwEptpRoot(Eptp) == 0ULL) {
        return KSWORD_ARK_HVM_EPTSW_EPTP_BAD_ROOT;
    }
    /* The memory type must be one supported by the hardware report. */
    if (memoryType == KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_UC) {
        if ((EptVpidCapability &
                KSWORD_ARK_HVM_EPTSW_CAP_MEMORY_TYPE_UC) == 0ULL) {
            return KSWORD_ARK_HVM_EPTSW_EPTP_BAD_MEMORY_TYPE;
        }
    } else if (memoryType == KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_WB) {
        if ((EptVpidCapability &
                KSWORD_ARK_HVM_EPTSW_CAP_MEMORY_TYPE_WB) == 0ULL) {
            return KSWORD_ARK_HVM_EPTSW_EPTP_BAD_MEMORY_TYPE;
        }
    } else {
        /* EPTP only accepts UC and WB; this is not the same encoding scheme as the five types of leaf entries. */
        return KSWORD_ARK_HVM_EPTSW_EPTP_BAD_MEMORY_TYPE;
    }
    /* The level must be exactly four, and the hardware must report support for a four-level walk. */
    if (KswordArkHvmEptSwEptpWalkLevels(Eptp) !=
            KSWORD_ARK_HVM_EPTSW_EPTP_WALK_LEVELS ||
        (EptVpidCapability &
            KSWORD_ARK_HVM_EPTSW_CAP_PAGE_WALK_4) == 0ULL) {
        return KSWORD_ARK_HVM_EPTSW_EPTP_BAD_WALK;
    }
    /* Only allow enabling accessed/dirty if the hardware supports it. */
    if (KswordArkHvmEptSwEptpHasAccessedDirty(Eptp) &&
        (EptVpidCapability &
            KSWORD_ARK_HVM_EPTSW_CAP_ACCESSED_DIRTY) == 0ULL) {
        return KSWORD_ARK_HVM_EPTSW_EPTP_BAD_AD;
    }
    /* Low-order reserved bits must be zero. */
    if ((Eptp & KSWORD_ARK_HVM_EPTSW_EPTP_RESERVED_LOW) != 0ULL) {
        return KSWORD_ARK_HVM_EPTSW_EPTP_BAD_RESERVED;
    }
    /*
     * The high reserved bits (63:52) must be zero. This check comes **before** the width criterion and does not depend on it.
     * MaxPhysicalAddressBits: It is an architectural constant that holds on any machine.
     * Writing it separately is not redundant—merging it into the width mask appears
     * equivalent (indeed equivalent when MAXPHYADDR <= 52), but then this section loses its
     * independent check. If someone narrows the width mask to the leaf shape PHYSICAL_MASK &
     * ~(...), bits 63:52 go unchecked, leading to VM entry failure with only an error code.
     */
    if ((Eptp & KSWORD_ARK_HVM_EPTSW_EPTP_RESERVED_HIGH) != 0ULL) {
        return KSWORD_ARK_HVM_EPTSW_EPTP_BAD_RESERVED_HIGH;
    }
    /* High bits exceeding the implemented physical width must be zero. */
    widthMask = ~((1ULL << MaxPhysicalAddressBits) - 1ULL);
    if ((Eptp & widthMask) != 0ULL) {
        return KSWORD_ARK_HVM_EPTSW_EPTP_BAD_PHYS_WIDTH;
    }
    /* Report that this pointer is acceptable for VM entry. */
    return KSWORD_ARK_HVM_EPTSW_EPTP_OK;
}

/*
 * Derive an EPTP pointing to another hierarchy root table from the currently active EPTP.
 *
 * **Must derive rather than resynthesize.** Resynthesis introduces a second source of truth for memory
 * type, page traversal levels, and A/D bits: if the base layer changes any of these later (e.g.,
 * enabling/disabling A/D based on CPUID), the secondary layer will not update, and VM entry will only
 * return an error code without indicating which pointer set or bit is inconsistent. A derived pointer
 * has a directly statable property: VM entry accepts it if and only if it accepts the base pointer.
 */
static __inline unsigned long long
KswordArkHvmEptSwRebaseEptp(
    unsigned long long SourceEptp,
    unsigned long long NewRootPhysical
    )
{
    /*
     * Directly reuse the implementation from Controls.h instead of rewriting the same expression: this formula is required in
     * three places in this repository (private-level entries, private EPTP, and the secondary-level EPTP here). Writing it three
     * times introduces three independent points of potential error, where a miscalculation leads to accessing an unrelated table.
     */
    return KswordArkHvmEptRebaseEntry(SourceEptp, NewRootPhysical);
}

/*
 * Report whether an EPTP switch requires explicit invalidation.
 *
 * Normally always false. See the Ep4ta comment: switching roots is switching tags; the processor won't use
 * another set's cached translations. This function exists to turn that argument into a **violatable** predicate:
 * when two levels erroneously share a root (e.g., the 'sub-level' is created by flipping only A/D bits), the tag
 * remains unchanged, the switch becomes a no-op in hardware, and the same instruction will always re-violate. In
 * that case, return true here so the caller can reject it rather than bringing a silent deadlock to the machine.
 */
static __inline int
KswordArkHvmEptSwSwitchNeedsInvalidation(
    unsigned long long FromEptp,
    unsigned long long ToEptp
    )
{
    return KswordArkHvmEptSwEp4ta(FromEptp) == KswordArkHvmEptSwEp4ta(ToEptp)
        ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* INVEPT descriptor                                                    */
/* ------------------------------------------------------------------ */

/*
 * Two INVEPT types defined by the architecture (SDM Vol.3C, 30.3 "INVEPT": type 1 =
 * single-context, type 2 = all-context; 0 and 3 are reserved.
 *
 * **These two values are passed directly to the INVEPT instruction via registers.** They are not internal identifiers for this
 * file; changing a value changes the instruction's semantics. In the previous version, all assertions referenced them only by
 * symbol, so swapping 1 and 2 caused all 344 assertions to pass (review mutation M06), but the real-world consequence was:
 * When a single-context request is made, an all-context (entire machine flushed, still visible) request is issued
 * instead; or conversely, when an all-context request is made, a single-context descriptor with all zeros is issued
 * once. That single invalidation flushes nothing, the guest continues using stale translations, and no symptoms appear.
 * Therefore, **numeric** assertions must be present here and in the unit tests.
 */
#define KSWORD_ARK_HVM_EPTSW_INVEPT_SINGLE 1UL
#define KSWORD_ARK_HVM_EPTSW_INVEPT_ALL    2UL
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(KSWORD_ARK_HVM_EPTSW_INVEPT_SINGLE == 1UL);
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(KSWORD_ARK_HVM_EPTSW_INVEPT_ALL == 2UL);

/* 16-byte memory operand for INVEPT. */
typedef struct _KSWORD_ARK_HVM_EPTSW_INVEPT_DESCRIPTOR
{
    /* qword 0: The complete EPT pointer value in single-context mode. */
    unsigned long long Eptp;
    /* qword 1: Must be zero as per architecture specification. */
    unsigned long long Reserved;
} KSWORD_ARK_HVM_EPTSW_INVEPT_DESCRIPTOR;

/* Report whether the hardware supports a specific INVEPT type. */
static __inline int
KswordArkHvmEptSwInveptTypeSupported(
    unsigned long Type,
    unsigned long long EptVpidCapability
    )
{
    /* Without the INVEPT instruction itself, discussing the type is meaningless. */
    if ((EptVpidCapability & KSWORD_ARK_HVM_EPTSW_CAP_INVEPT) == 0ULL) {
        return 0;
    }
    if (Type == KSWORD_ARK_HVM_EPTSW_INVEPT_SINGLE) {
        return (EptVpidCapability &
            KSWORD_ARK_HVM_EPTSW_CAP_INVEPT_SINGLE) != 0ULL ? 1 : 0;
    }
    if (Type == KSWORD_ARK_HVM_EPTSW_INVEPT_ALL) {
        return (EptVpidCapability &
            KSWORD_ARK_HVM_EPTSW_CAP_INVEPT_ALL) != 0ULL ? 1 : 0;
    }
    /* 0 and 3 are reserved types: executing them will only result in VMfail. */
    return 0;
}

/*
 * Construct an INVEPT descriptor.
 *
 * Three cases of "error without reporting":
 *
 *  1. qword 0 stores the **complete EPT pointer**, not the root address. Existing processors only use bits
 *     51:12, so masking the lower bits 'works' for now—until it doesn't, at which point the failure manifests
 *     as the instruction not taking effect and the guest reading stale translations. 'It runs on this chip'
 *     is not a decision the driver should make for the architecture; therefore, pass the EPTP as-is here.
 *  2. When Type is ALL_CONTEXT, the descriptor is ignored by the architecture, but we explicitly zero it
 *     here. Passing a non-zero value won't cause an error, yet it would hide a bug where the caller intended
 *     SINGLE but passed the wrong type. Zeroing ensures that if 'all' is mistakenly used to invalidate a
 *     specific hierarchy, no misleadingly valid EPTP remains in the descriptor to confuse code readers.
 *  3. Zero the descriptor on failure. Callers ignoring the return value that execute INVEPT in-place may
 *     treat residual stack values as a valid EPTP to invalidate—potentially invalidating an arbitrary hierarchy.
 *
 * Returns non-zero if the descriptor is valid.
 */
static __inline int
KswordArkHvmEptSwBuildInveptDescriptor(
    unsigned long Type,
    unsigned long long Eptp,
    unsigned long long EptVpidCapability,
    KSWORD_ARK_HVM_EPTSW_INVEPT_DESCRIPTOR* Descriptor
    )
{
    /* Nothing can be constructed without an output location. */
    if (Descriptor == 0) {
        return 0;
    }
    /* Zero out first so any subsequent failure path leaves no executable residue. */
    Descriptor->Eptp = 0ULL;
    Descriptor->Reserved = 0ULL;
    /* Hardware must support this type. */
    if (!KswordArkHvmEptSwInveptTypeSupported(Type, EptVpidCapability)) {
        return 0;
    }
    if (Type == KSWORD_ARK_HVM_EPTSW_INVEPT_SINGLE) {
        /* single-context must specify a real, existing hierarchy. */
        if (KswordArkHvmEptSwEptpRoot(Eptp) == 0ULL) {
            return 0;
        }
        /* Pass the complete EPT pointer value as-is. */
        Descriptor->Eptp = Eptp;
    }
    /* All-context remains all zeros. */
    return 1;
}

/*
 * Calculates the number of single-context INVEPT operations that must be issued before entering the guest.
 *
 * Each sub-hierarchy is constructed from reclaimed non-paged memory, potentially carrying stale tags left from previous residency.
 * During this residency period, INVEPT will never be issued again (the table is not written at runtime; isolation relies on tags).
 * Therefore, this is its only opportunity before entry. Missing this set results in reading stale translations from another owner
 * for that page during early startup, followed by self-healing—a non-reproducible error confined to the cold-start window.
 *
 * The base is a shared layer already running, so do not invalidate it again; this also ensures that when
 * this feature is not requested, the path remains identical to the current byte-by-byte implementation.
 *
 * **Returning 0 means that no secondary hierarchy needs invalidation.** This function must never produce 0 through
 * integer wraparound. Previously, it was the only LeafCount consumer in this file that neither enforced MAX_LEAVES nor
 * widened the calculation: for 0xFFFFFFFF, LeafCount + 1 wrapped to 0 in uint32. The caller then assumed no INVEPT was
 * needed and entered the guest with stale EP4TA tags for every hierarchy in reclaimed memory. During cold startup, some
 * pages would use translations from the previous resident session before recovering, making the issue hard to reproduce.
 * Both safeguards are now required: reject counts above the protocol limit first, then compute the sum in 64 bits.
 */
static __inline unsigned long long
KswordArkHvmEptSwPreEntryInvalidationCount(
    unsigned long LeafCount,
    int SharedBaseAlreadyLive
    )
{
    /* If there are no leaves, there is no sub-level and nothing to invalidate. */
    if (LeafCount == 0UL) {
        return 0ULL;
    }
    /*
     * Out-of-bounds leaf count is rejected, just like every other LeafCount consumer in the file:
     * SecondaryPageCost, HierarchyCount, IndexFromLeaf, and Decide all reject values
     * greater than MAX_LEAVES; allowing them here creates a loophole in the upper bound.
     */
    if (LeafCount > KSWORD_ARK_HVM_EPTSW_MAX_LEAVES) {
        return 0ULL;
    }
    /* Each leaf has a separate sub-level, invalidated once; carried in 64-bit, no wraparound is possible. */
    return (unsigned long long)LeafCount +
        (SharedBaseAlreadyLive ? 0ULL : 1ULL);
}

/* ------------------------------------------------------------------ */
/* Index arithmetic                                                             */
/* ------------------------------------------------------------------ */

/* Each level index is 9 bits. */
#define KSWORD_ARK_HVM_EPTSW_INDEX_MASK 0x1FFULL
#define KSWORD_ARK_HVM_EPTSW_PML4_SHIFT 39
#define KSWORD_ARK_HVM_EPTSW_PDPT_SHIFT 30
#define KSWORD_ARK_HVM_EPTSW_PD_SHIFT 21
#define KSWORD_ARK_HVM_EPTSW_PT_SHIFT 12

/*
 * Extracts the level-4 index from the guest physical address.
 *
 * An off-by-one shift error does not fault: it accesses a table that is **present and writable**, but describes a different
 * physical memory region. Consequently, the secondary level modifies permissions for the adjacent GiB window, leaving
 * protected pages unprotected, with no symptoms on either side. The 9-bit mask is also mandatory: without masking, the PML4
 * index grows into a huge number based on high-order address bits, writing past the table tail into adjacent pages.
 */
static __inline unsigned long
KswordArkHvmEptSwPml4Index(
    unsigned long long GuestPhysical
    )
{
    return (unsigned long)((GuestPhysical >> KSWORD_ARK_HVM_EPTSW_PML4_SHIFT) &
        KSWORD_ARK_HVM_EPTSW_INDEX_MASK);
}

/* Retrieve the index for the 1GiB window. */
static __inline unsigned long
KswordArkHvmEptSwPdptIndex(
    unsigned long long GuestPhysical
    )
{
    return (unsigned long)((GuestPhysical >> KSWORD_ARK_HVM_EPTSW_PDPT_SHIFT) &
        KSWORD_ARK_HVM_EPTSW_INDEX_MASK);
}

/* Extract the index for a 2MiB leaf. */
static __inline unsigned long
KswordArkHvmEptSwPdIndex(
    unsigned long long GuestPhysical
    )
{
    return (unsigned long)((GuestPhysical >> KSWORD_ARK_HVM_EPTSW_PD_SHIFT) &
        KSWORD_ARK_HVM_EPTSW_INDEX_MASK);
}

/* Get the index of the 4KiB page within the split 2MiB region. */
static __inline unsigned long
KswordArkHvmEptSwPtIndex(
    unsigned long long GuestPhysical
    )
{
    return (unsigned long)((GuestPhysical >> KSWORD_ARK_HVM_EPTSW_PT_SHIFT) &
        KSWORD_ARK_HVM_EPTSW_INDEX_MASK);
}

/*
 * Recover page base address from four-level index.
 *
 * Not for driver use; intended for self-checks and unit tests: The fact that decomposition and restoration are inverse operations is the sole
 * evidence that the decisions of 'which cell to modify' and 'which table to copy' are self-consistent. If these two values are misaligned by even
 * one cell, the secondary value is written to the adjacent page—redirecting that page while leaving the protected page completely unprotected.
 */
static __inline unsigned long long
KswordArkHvmEptSwComposeGuestPhysical(
    unsigned long Pml4Index,
    unsigned long PdptIndex,
    unsigned long PdIndex,
    unsigned long PtIndex
    )
{
    return (((unsigned long long)Pml4Index & KSWORD_ARK_HVM_EPTSW_INDEX_MASK) <<
                KSWORD_ARK_HVM_EPTSW_PML4_SHIFT) |
        (((unsigned long long)PdptIndex & KSWORD_ARK_HVM_EPTSW_INDEX_MASK) <<
                KSWORD_ARK_HVM_EPTSW_PDPT_SHIFT) |
        (((unsigned long long)PdIndex & KSWORD_ARK_HVM_EPTSW_INDEX_MASK) <<
                KSWORD_ARK_HVM_EPTSW_PD_SHIFT) |
        (((unsigned long long)PtIndex & KSWORD_ARK_HVM_EPTSW_INDEX_MASK) <<
                KSWORD_ARK_HVM_EPTSW_PT_SHIFT);
}

/* Round the address down to the 2MiB leaf containing it. */
static __inline unsigned long long
KswordArkHvmEptSwLeafBase(
    unsigned long long GuestPhysical
    )
{
    return GuestPhysical & ~(KSWORD_ARK_HVM_EPTSW_LARGE_BYTES - 1ULL);
}

/* Round the address down to the 4KiB page containing it. */
static __inline unsigned long long
KswordArkHvmEptSwPageBase(
    unsigned long long GuestPhysical
    )
{
    return GuestPhysical & ~(KSWORD_ARK_HVM_EPTSW_PAGE_BYTES - 1ULL);
}

/*
 * Calculate the physical address of a specific entry in a table.
 *
 * The table base must be masked: the caller typically receives an entry value with field bits set, not a clean
 * address; failing to mask would add those bits to the address. Index out-of-bounds must be rejected, not
 * wrapped: index 512 falls into the first slot of the next page, which might be a different table; writing there
 * would not trigger an error. Return 0 to indicate rejection—an EPT table can never reside at physical address 0.
 *
 * **The mask must be PHYSICAL_MASK (bits 51:12), not ~(PAGE_BYTES - 1).** The previous version used the
 * latter, which only clears bits 11:0, leaving bit 63 and bits 62:52 unchanged in the return value.
 * This file explains in detail that every leaf entry constructed by the driver has bit 63 set to suppress #VE.
 * In other words, passing a raw entry value as documented results in a returned "physical address" with bit 63
 * set: empirically, (0x8000000023456007, 3) returns 0x8000000023456018, not 0x0000000023456018. If the driver
 * writes this value to the EPT table, it writes an astronomically large physical address. On x64, this either
 * causes an unpredictable write or an MMU rejection, both of which are far removed from the actual scenario.
 * This uses PHYSICAL_MASK, consistent with the family of
 * KswordArkHvmEptTablePointer and KswordArkHvmEptRebaseEntry.
 */
static __inline unsigned long long
KswordArkHvmEptSwEntryAddress(
    unsigned long long TablePhysical,
    unsigned long EntryIndex
    )
{
    /* Reject out-of-bounds index; do not wrap around. */
    if (EntryIndex >= KSWORD_ARK_HVM_EPTSW_TABLE_ENTRIES) {
        return 0ULL;
    }
    /* Extract only the page frame field; do not include any field bits (including bit 63) in the address. */
    return (TablePhysical & KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK) +
        ((unsigned long long)EntryIndex * KSWORD_ARK_HVM_EPTSW_ENTRY_BYTES);
}

/* ------------------------------------------------------------------ */
/* Size of the hierarchy set and page overhead                                               */
/* ------------------------------------------------------------------ */

/*
 * A set of fixed page counts for a hierarchical structure: private root + private PDPT + private PD + private leaf table.
 *
 * Depth is independent of leaf position: a leaf resides in exactly one PML4 slot and one GiB window, while every table
 * outside the path continues to share the base. Thus, it is a constant four, not "calculated by distributing per leaf".
 */
#define KSWORD_ARK_HVM_EPTSW_PATH_PAGES 4ULL

/* The upper limit for flip-able leaves is defined in the 'Protocol Image Constants' section above
 * this file, as it is already used by KswordArkHvmEptSwPreEntryInvalidationCount before this section. */

/*
 * Base count.
 *
 * This is the switch for the economic viability of the entire solution and the most prone to silent corruption: after the runtime stops writing
 * to any EPT tables, the sub-layer can be shared by all processors, making the base count 1. Consequently, the total page count becomes
 * completely independent of the processor count. If someone carelessly changes it to charge per core, functionality remains normal, but on a
 * 256-core machine, the page count jumps from 32 to 8192. There are no symptoms; only the budget check fails to start on large machines.
 *
 * Charge per core only when combined with 'per-processor private base': at that time, each processor's
 * second-level must derive from its own private base; otherwise, switching would lose the private path.
 */
static __inline unsigned long
KswordArkHvmEptSwBaseCount(
    int UsePrivateBase,
    unsigned long ProcessorCount
    )
{
    /* One base per processor in composite mode. */
    if (UsePrivateBase) {
        return ProcessorCount;
    }
    /* In shared base mode, there is only one set, independent of the number of processors. */
    return 1UL;
}

/*
 * Calculate the total number of pages occupied by all secondary levels.
 *
 * If calculated too low, it writes past the block end and crashes at a random, distant moment; if too high, it just wastes resources.
 * Return 0 for both leaf count out-of-bounds and zero base count, allowing the caller to reject the operation before any page is allocated.
 */
static __inline unsigned long long
KswordArkHvmEptSwSecondaryPageCost(
    unsigned long BaseCount,
    unsigned long LeafCount
    )
{
    /* No base means no derived sub-layers. */
    if (BaseCount == 0UL) {
        return 0ULL;
    }
    /* Reject if leaf count exceeds the protocol limit, also preventing multiplication overflow. */
    if (LeafCount == 0UL || LeafCount > KSWORD_ARK_HVM_EPTSW_MAX_LEAVES) {
        return 0ULL;
    }
    /* Each base set has a sub-level per leaf, with four pages per set. */
    return (unsigned long long)BaseCount * (unsigned long long)LeafCount *
        KSWORD_ARK_HVM_EPTSW_PATH_PAGES;
}

/*
 * Total hierarchy count under a single base: the base itself plus one set per leaf.
 * This number is the length of the EPTP ledger; if the ledger is one entry short, the runtime will read out of bounds by index.
 */
static __inline unsigned long
KswordArkHvmEptSwHierarchyCount(
    unsigned long LeafCount
    )
{
    /* If there are no leaves, this mechanism has nothing to do and constructs no hierarchy. */
    if (LeafCount == 0UL || LeafCount > KSWORD_ARK_HVM_EPTSW_MAX_LEAVES) {
        return 0UL;
    }
    /* Index 0 is the base; indices 1..L each correspond to a leaf. */
    return LeafCount + 1UL;
}

/* Report whether a calculated page cost fits within the reserved budget. */
static __inline int
KswordArkHvmEptSwFitsBudget(
    unsigned long long PageCost,
    unsigned long long Cap
    )
{
    return (PageCost != 0ULL && PageCost <= Cap) ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* Encoding of hierarchical index and leaf number.                                                 */
/* ------------------------------------------------------------------ */

/* Base index. */
#define KSWORD_ARK_HVM_EPTSW_INDEX_BASE 0UL

/* Report whether a hierarchical index is a base. */
static __inline int
KswordArkHvmEptSwIndexIsBase(
    unsigned long Index
    )
{
    return Index == KSWORD_ARK_HVM_EPTSW_INDEX_BASE ? 1 : 0;
}

/*
 * Convert a leaf number to a hierarchy index. **Always add one to the leaf number.**
 *
 * Note: Setting the index equal to the leaf number causes 'the 0th leaf taking the next value' and 'no relaxation at all' to become the same
 * value. Consequently, once the 0th leaf is cut in, it can never be cut out—the page permanently stays in shadow with no error reported: the
 * view remains, the driver keeps running, and self-checks pass, but the protected page is forever shadow content for all readers.
 *
 * Return non-zero on success.
 */
static __inline int
KswordArkHvmEptSwIndexFromLeaf(
    unsigned long LeafIndex,
    unsigned long LeafCount,
    unsigned long* Index
    )
{
    /* Nothing can be encoded without an output location. */
    if (Index == 0) {
        return 0;
    }
    /* Reject out-of-bounds leaf indices and leaf counts. */
    if (LeafCount == 0UL || LeafCount > KSWORD_ARK_HVM_EPTSW_MAX_LEAVES ||
        LeafIndex >= LeafCount) {
        return 0;
    }
    /* Index 0 is reserved for the base, so leaf numbers are shifted by one. */
    *Index = LeafIndex + 1UL;
    return 1;
}

/*
 * Map hierarchy index to leaf number. An off-by-one error in the reverse mapping causes the recovery criterion to apply to an unrelated page:
 * That page is reclaimed to the primary value (it was already primary, so nothing happens), while the page that was truly relaxed remains on the secondary value.
 *
 * Since the base has no corresponding leaf, return failure for index 0 instead of a
 * sentinel value; a sentinel value would be treated as a valid leaf index and used further.
 */
static __inline int
KswordArkHvmEptSwLeafFromIndex(
    unsigned long Index,
    unsigned long LeafCount,
    unsigned long* LeafIndex
    )
{
    /* Nothing can be decoded without an output location. */
    if (LeafIndex == 0) {
        return 0;
    }
    /* Reject out-of-bounds leaf count. */
    if (LeafCount == 0UL || LeafCount > KSWORD_ARK_HVM_EPTSW_MAX_LEAVES) {
        return 0;
    }
    /* The base does not correspond to any leaf. */
    if (KswordArkHvmEptSwIndexIsBase(Index)) {
        return 0;
    }
    /* Reject indices exceeding the hierarchy set size. */
    if (Index > LeafCount) {
        return 0;
    }
    /* Strictly inverse to the encoding. */
    *LeafIndex = Index - 1UL;
    return 1;
}

/* ------------------------------------------------------------------ */
/* Access type and view kind                                                   */
/* ------------------------------------------------------------------ */

/*
 * Local mirror of protocol access bits; must match KSWORD_ARK_HVM_EPT_ACCESS_* in
 * KswordArkHvmIoctl.h:336-338 bit-for-bit. We do not directly include that header
 * because it requires CTL_CODE and Windows types, which would prevent host-side testing.
 *
 * Mirroring requires both of the following checks:
 *   1. This file, along with the **numeric** assertions in the unit tests (located below), ensures this local copy is not renumbered;
 *   2. A C_ASSERT in a driver-side .c file that includes both headers ensures the counterpart cannot be renumbered.
 *
 * The integration owner must implement rule 2; this header cannot enforce it. These are the five required lines:
 *   C_ASSERT(KSWORD_ARK_HVM_EPTSW_ACCESS_READ    == KSWORD_ARK_HVM_EPT_ACCESS_READ);
 *   C_ASSERT(KSWORD_ARK_HVM_EPTSW_ACCESS_WRITE   == KSWORD_ARK_HVM_EPT_ACCESS_WRITE);
 *   C_ASSERT(KSWORD_ARK_HVM_EPTSW_ACCESS_EXECUTE == KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE);
 *   C_ASSERT(KSWORD_ARK_HVM_EPTSW_KIND_CLOAK     == KSWORD_ARK_HVM_VIEW_KIND_CLOAK);
 *   C_ASSERT(KSWORD_ARK_HVM_EPTSW_KIND_HOOK      == KSWORD_ARK_HVM_VIEW_KIND_HOOK);
 *
 * The previous version here stated that 'the existence of these three explicit if branches is to ensure that any renumbering on either side is caught by unit tests'.
 * That statement is false and refuted by actual testing: swapping READ with WRITE and CLOAK with
 * HOOK causes all 344 original assertions to pass (the reviewed mutations M27 and M26), because
 * all assertions use only symbols, and R and W are symmetric in both views. Explicit branches
 * only guarantee "not a direct assignment"; the assertions, not the branches, fix the values.
 */
#define KSWORD_ARK_HVM_EPTSW_ACCESS_READ    0x00000001UL
#define KSWORD_ARK_HVM_EPTSW_ACCESS_WRITE   0x00000002UL
#define KSWORD_ARK_HVM_EPTSW_ACCESS_EXECUTE 0x00000004UL
/* Union of the three defined access bits, used to identify access categories not yet in the protocol. */
#define KSWORD_ARK_HVM_EPTSW_ACCESS_MASK    0x00000007UL
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(KSWORD_ARK_HVM_EPTSW_ACCESS_READ == 1UL);
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(KSWORD_ARK_HVM_EPTSW_ACCESS_WRITE == 2UL);
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(KSWORD_ARK_HVM_EPTSW_ACCESS_EXECUTE == 4UL);
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_ACCESS_MASK ==
    (KSWORD_ARK_HVM_EPTSW_ACCESS_READ | KSWORD_ARK_HVM_EPTSW_ACCESS_WRITE |
     KSWORD_ARK_HVM_EPTSW_ACCESS_EXECUTE));
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(KSWORD_ARK_HVM_EPTSW_ACCESS_MASK == 7UL);

/*
 * Local mirror of the protocol view kind; values match KSWORD_ARK_HVM_VIEW_KIND_*
 * in KswordArkHvmIoctl.h:754/756. Swapping these two values causes no symptoms:
 * The kind = 1 (CLOAK) sent via IOCTL is served as HOOK permissions, so the main value becomes
 * rw- true frame: That page is always readable by all readers; 'hidden'
 * becomes 'exposed', while hooks and the view list appear normal.
 */
#define KSWORD_ARK_HVM_EPTSW_KIND_CLOAK 1UL
#define KSWORD_ARK_HVM_EPTSW_KIND_HOOK  2UL
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(KSWORD_ARK_HVM_EPTSW_KIND_CLOAK == 1UL);
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(KSWORD_ARK_HVM_EPTSW_KIND_HOOK == 2UL);

/*
 * Translate the protocol access mask into permission bits in the leaf entry.
 *
 * The two sets of constants currently share the same values (1/2/4), which is precisely the danger: writing direct assignments
 * produces no errors until one side is renumbered, causing flips to make decisions based on incorrect permissions—manifesting
 * as either access never obtaining the required hierarchy (ring) or obtaining an unauthorized one (information leak).
 *
 * Three explicit checks only do half the job: they ensure this isn't 'using the protocol mask directly as leaf permissions',
 * but they **cannot catch renumbering**—when both sides are renumbered simultaneously, the three branches still map one-to-one.
 * The true constraints are the five numeric assertions above and the literal-based cross-references in unit tests
 * (e.g., s.expect(AccessToLeafBits(0x1) == 0x1)). Do not rewrite this comment as 'the existence of branches is to
 * let unit tests detect renumbering'—the previous version stated this, but it was proven false by actual testing.
 */
static __inline unsigned long long
KswordArkHvmEptSwAccessToLeafBits(
    unsigned long Access
    )
{
    unsigned long long bits = 0ULL;

    /* Retrieve the leaf permission bit corresponding to data read. */
    if ((Access & KSWORD_ARK_HVM_EPTSW_ACCESS_READ) != 0UL) {
        bits |= KSWORD_ARK_HVM_EPTSW_READ;
    }
    /* Retrieve the leaf permission bit corresponding to data write. */
    if ((Access & KSWORD_ARK_HVM_EPTSW_ACCESS_WRITE) != 0UL) {
        bits |= KSWORD_ARK_HVM_EPTSW_WRITE;
    }
    /* Retrieve the leaf permission bit corresponding to instruction fetch. */
    if ((Access & KSWORD_ARK_HVM_EPTSW_ACCESS_EXECUTE) != 0UL) {
        bits |= KSWORD_ARK_HVM_EPTSW_EXECUTE;
    }
    /* Returns the full permissions required for this access. */
    return bits;
}

/*
 * Check if a set of leaf permissions grants **all** permission bits required for this access.
 *
 * An empty access mask must return "not granted." A bare (Entry & needed) == needed check incorrectly treats any leaf
 * as "granted" when needed is zero, causing the violation to be treated as "sufficient at the current level" and
 * allowing it through. This leads to a non-reporting infinite loop after a VMRESUME followed by another violation.
 */
static __inline int
KswordArkHvmEptSwGrants(
    unsigned long long LeafPermissions,
    unsigned long Access
    )
{
    const unsigned long long needed = KswordArkHvmEptSwAccessToLeafBits(Access);

    /* A zero requirement is never considered satisfied. */
    if (needed == 0ULL) {
        return 0;
    }
    /* All bits must be granted; missing even a single bit causes a violation. */
    return ((LeafPermissions & KSWORD_ARK_HVM_EPTSW_PERM_MASK) & needed) ==
        needed ? 1 : 0;
}

/*
 * Note: Permissions for primary/secondary values are derived from the view kind.
 *
 * CLOAK: Execution uses real pages, while read/write uses shadow pages. Primary value --x (real frame), secondary value rw- (shadow frame).
 * HOOK: Read/Write goes to true pages, Execute goes to shadow pages. Primary value rw- (true frame), secondary value --x (shadow frame).
 *
 * **Both kinds must have execute-only under this mechanism.** Today's MTF path degrades the HOOK sub-value to r-x when this
 * capability is missing, arguing that "the window contains only one instruction, so the reader must land exactly within it."
 * EPTP switch without MTF: the sub-layer remains active until a reverse access occurs. During this period, any code
 * running on this processor (including interrupt handlers) reading that page will see the shadow. An r-x sub-layer
 * value exposes the patched bytes, which has no symptoms—the hook still works, but it is no longer hidden. Therefore,
 * both kinds require execute-only here; the caller decides whether to reject or downgrade to the MTF path.
 *
 * Returns non-zero if this pair is available.
 */
static __inline int
KswordArkHvmEptSwKindPermissions(
    unsigned long Kind,
    int ExecuteOnlySupported,
    unsigned long long* PrimaryPermissions,
    unsigned long long* SecondaryPermissions
    )
{
    /* Nothing can be provided as a pair without an output location. */
    if (PrimaryPermissions == 0 || SecondaryPermissions == 0) {
        return 0;
    }
    /* Each of the two kinds has an X value without R; without execute-only, it cannot be represented. */
    if (!ExecuteOnlySupported) {
        return 0;
    }
    if (Kind == KSWORD_ARK_HVM_EPTSW_KIND_CLOAK) {
        /* Primary value: Execute real pages. */
        *PrimaryPermissions = KSWORD_ARK_HVM_EPTSW_EXECUTE;
        /* Secondary value: read/write shadow. */
        *SecondaryPermissions =
            KSWORD_ARK_HVM_EPTSW_READ | KSWORD_ARK_HVM_EPTSW_WRITE;
        return 1;
    }
    if (Kind == KSWORD_ARK_HVM_EPTSW_KIND_HOOK) {
        /* Primary value: Read/write real pages. */
        *PrimaryPermissions =
            KSWORD_ARK_HVM_EPTSW_READ | KSWORD_ARK_HVM_EPTSW_WRITE;
        /* Secondary value: execute shadow. */
        *SecondaryPermissions = KSWORD_ARK_HVM_EPTSW_EXECUTE;
        return 1;
    }
    /* Unknown type; no pair is provided. */
    return 0;
}

/*
 * Check if the union of primary/secondary values covers read, write, and execute access.
 *
 * If an access is not granted on either side, the runtime will never find a valid target to switch to, forcing a fail-closed
 * exit from virtualization. This issue only manifests on the target machine when the guest actually performs that access:
 * installation succeeds, but virtualization exits hours later. This criterion moves the detection to installation time.
 */
static __inline int
KswordArkHvmEptSwPairIsTotal(
    unsigned long long PrimaryPermissions,
    unsigned long long SecondaryPermissions
    )
{
    return ((PrimaryPermissions | SecondaryPermissions) &
        KSWORD_ARK_HVM_EPTSW_PERM_MASK) == KSWORD_ARK_HVM_EPTSW_PERM_MASK
        ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* Switch decision state machine.                                                       */
/* ------------------------------------------------------------------ */

/*
 * There are only two outcomes.
 *
 * There is no third case of 'no switch needed, just resume': if an EPT violation does not require a hierarchy switch,
 * it means the current hierarchy already granted access, which contradicts the occurrence of a violation. Treating
 * such input as 'resume' won't error but will cause a non-progressing loop. Thus, such input must be REFUSE here.
 */
#define KSWORD_ARK_HVM_EPTSW_OUTCOME_REFUSE 0UL
#define KSWORD_ARK_HVM_EPTSW_OUTCOME_SWITCH 1UL

/* Rejection reason. Every entry must be connected to a fail-closed sink by the upper layer and cannot be ignored. */
#define KSWORD_ARK_HVM_EPTSW_REASON_NONE            0UL
/* Leaf index / leaf count / current index out of bounds. */
#define KSWORD_ARK_HVM_EPTSW_REASON_BOUNDS          1UL
/* Access mask is empty: no level can 'satisfy' an empty requirement. */
#define KSWORD_ARK_HVM_EPTSW_REASON_EMPTY_ACCESS    2UL
/* The access mask contains bits not defined by the protocol; treating it as a read would select the wrong hierarchy. */
#define KSWORD_ARK_HVM_EPTSW_REASON_UNKNOWN_ACCESS  3UL
/* View kind unknown. */
#define KSWORD_ARK_HVM_EPTSW_REASON_KIND            4UL
/* Missing execute-only: this mechanism cannot represent this pair without leaking the shadow. */
#define KSWORD_ARK_HVM_EPTSW_REASON_NO_EXECUTE_ONLY 5UL
/* Access was already granted at the current level but still violated: a mismatch between cognition and hardware. */
#define KSWORD_ARK_HVM_EPTSW_REASON_SPURIOUS        6UL
/* Neither side grants access: this access is invalid in any single hierarchy level. */
#define KSWORD_ARK_HVM_EPTSW_REASON_UNREPRESENTABLE 7UL
/* EPTP ledger length is incorrect, or the slot is not filled. */
#define KSWORD_ARK_HVM_EPTSW_REASON_LEDGER          8UL
/* Source and target share EP4TA: switching is equivalent to no switch. */
#define KSWORD_ARK_HVM_EPTSW_REASON_ALIASED         9UL

/* Complete result of a single switch decision. */
typedef struct _KSWORD_ARK_HVM_EPTSW_TRANSITION
{
    /* Value to write to the VMCS EPT_POINTER field; zero when REFUSE. */
    unsigned long long TargetEptp;
    /* OUTCOME_REFUSE or OUTCOME_SWITCH. */
    unsigned long Outcome;
    /* The hierarchy index of the processor after the switch; zero when REFUSE. */
    unsigned long NextIndex;
    /* Specific reason when REFUSE. */
    unsigned long Reason;
    /*
     * There was once an Invalidate field; the documentation stated that a non-zero value indicated an explicit
     * INVEPT was required for this switch. It was removed because it could **never be non-zero**: the only
     * condition that would set it (source and target sharing EP4TA) is converted by KswordArkHvmEptSwPlanSwitch
     * into a REFUSE with REASON_ALIASED. Keeping it was genuinely harmful: the unit test assertion checking the
     * Invalidate flag for each group is tautologically true by construction, appearing as a coverage line but
     * conveying zero actual information, allowing any still-refused alias logic mutation to pass underneath it.
     * The only scenario requiring explicit INVEPT is the batch invalidation before entering the
     * guest, counted by KswordArkHvmEptSwPreEntryInvalidationCount, which bypasses this structure.
     */
} KSWORD_ARK_HVM_EPTSW_TRANSITION;

/*
 * Set the result to a rejection with a reason.
 *
 * Null pointers must be blocked here rather than dereferenced: this is a public static __inline function;
 * driver-side .c files call it directly to construct a single refusal, and it runs at DISPATCH_LEVEL.
 * On the VM-exit handling path—a single null dereference there causes a BSOD, and the
 * location is far from the actual error (who failed to populate Transition). Every other
 * pointer-fetching function in this file performs a check, but this one missed it.
 */
static __inline unsigned long
KswordArkHvmEptSwRefuse(
    KSWORD_ARK_HVM_EPTSW_TRANSITION* Transition,
    unsigned long Reason
    )
{
    /* Report refusal even without an output location; never dereference. */
    if (Transition == 0) {
        return KSWORD_ARK_HVM_EPTSW_OUTCOME_REFUSE;
    }
    Transition->TargetEptp = 0ULL;
    Transition->Outcome = KSWORD_ARK_HVM_EPTSW_OUTCOME_REFUSE;
    Transition->NextIndex = 0UL;
    Transition->Reason = Reason;
    return KSWORD_ARK_HVM_EPTSW_OUTCOME_REFUSE;
}

/*
 * Decides which hierarchy set to switch to based on (current level index × violation leaf × access type × view type).
 *
 * The state is an index: 0 = base (take primary value from every leaf); k = take secondary value only from leaf k-1.
 * Thus, the only criterion for determining whether 'this leaf is currently the primary or secondary value' is whether the current index equals this leaf's index.
 * Note that 'in another leaf's hierarchy' and 'in the base' represent the same state for this leaf—both take the
 * primary value—but with different targets: the former, when switching to this leaf's hierarchy, also reclaims the
 * other leaf to its primary value. This is the source of the invariant 'at most one leaf is relaxed at any time'.
 *
 * Each REFUSE corresponds to an input that would otherwise cause a silent deadlock or silent leak; reasons are
 * documented in the respective reason code comments. The return value is also written to Transition->Outcome.
 */
static __inline unsigned long
KswordArkHvmEptSwDecide(
    unsigned long ActiveIndex,
    unsigned long FaultLeafIndex,
    unsigned long LeafCount,
    unsigned long Access,
    unsigned long Kind,
    int ExecuteOnlySupported,
    KSWORD_ARK_HVM_EPTSW_TRANSITION* Transition
    )
{
    unsigned long long primary = 0ULL;
    unsigned long long secondary = 0ULL;
    unsigned long faultIndex = 0UL;

    /* No output location means no decision can be made. */
    if (Transition == 0) {
        return KSWORD_ARK_HVM_EPTSW_OUTCOME_REFUSE;
    }
    /* Set to refused first so that any early return does not leave a result that looks successful. */
    (void)KswordArkHvmEptSwRefuse(
        Transition, KSWORD_ARK_HVM_EPTSW_REASON_NONE);
    /* Leaf count must be within the protocol limit. */
    if (LeafCount == 0UL || LeafCount > KSWORD_ARK_HVM_EPTSW_MAX_LEAVES) {
        return KswordArkHvmEptSwRefuse(
            Transition, KSWORD_ARK_HVM_EPTSW_REASON_BOUNDS);
    }
    /* The invalid leaf must be one of the leaves in the set. */
    if (FaultLeafIndex >= LeafCount) {
        return KswordArkHvmEptSwRefuse(
            Transition, KSWORD_ARK_HVM_EPTSW_REASON_BOUNDS);
    }
    /* The current index must fall within [0, LeafCount]; otherwise, the ledger and VMCS are already inconsistent. */
    if (ActiveIndex > LeafCount) {
        return KswordArkHvmEptSwRefuse(
            Transition, KSWORD_ARK_HVM_EPTSW_REASON_BOUNDS);
    }
    /*
     * Access bits outside the protocol must be explicitly rejected. Treating unknown bits as zero does not trigger an error, but
     * it would use the "read" criterion to service an access type we do not yet understand, thereby selecting the wrong layer.
     */
    if ((Access & ~KSWORD_ARK_HVM_EPTSW_ACCESS_MASK) != 0UL) {
        return KswordArkHvmEptSwRefuse(
            Transition, KSWORD_ARK_HVM_EPTSW_REASON_UNKNOWN_ACCESS);
    }
    /* Empty access mask has no satisfiable targets. */
    if (KswordArkHvmEptSwAccessToLeafBits(Access) == 0ULL) {
        return KswordArkHvmEptSwRefuse(
            Transition, KSWORD_ARK_HVM_EPTSW_REASON_EMPTY_ACCESS);
    }
    /* Without execute-only support, this mechanism cannot represent any view. */
    if (!ExecuteOnlySupported) {
        return KswordArkHvmEptSwRefuse(
            Transition, KSWORD_ARK_HVM_EPTSW_REASON_NO_EXECUTE_ONLY);
    }
    /* Extract the primary/secondary permissions for this view. */
    if (!KswordArkHvmEptSwKindPermissions(
            Kind, ExecuteOnlySupported, &primary, &secondary)) {
        return KswordArkHvmEptSwRefuse(
            Transition, KSWORD_ARK_HVM_EPTSW_REASON_KIND);
    }
    /* The sub-level index of this leaf. */
    faultIndex = FaultLeafIndex + 1UL;
    if (ActiveIndex == faultIndex) {
        /* This leaf takes the next value at this moment. */
        if (KswordArkHvmEptSwGrants(secondary, Access)) {
            /* Spurious violation despite granted secondary value: our understanding of the hardware state is incorrect. */
            return KswordArkHvmEptSwRefuse(
                Transition, KSWORD_ARK_HVM_EPTSW_REASON_SPURIOUS);
        }
        if (!KswordArkHvmEptSwGrants(primary, Access)) {
            /* Returning to the base still causes a violation; that is a ring. */
            return KswordArkHvmEptSwRefuse(
                Transition, KSWORD_ARK_HVM_EPTSW_REASON_UNREPRESENTABLE);
        }
        /* Reverse access: Return to base; this leaf reclaims the main value. */
        Transition->Outcome = KSWORD_ARK_HVM_EPTSW_OUTCOME_SWITCH;
        Transition->NextIndex = KSWORD_ARK_HVM_EPTSW_INDEX_BASE;
        Transition->Reason = KSWORD_ARK_HVM_EPTSW_REASON_NONE;
        return KSWORD_ARK_HVM_EPTSW_OUTCOME_SWITCH;
    }
    /* This leaf takes the primary value at this moment, regardless of whether we are in the base or in another leaf hierarchy. */
    if (KswordArkHvmEptSwGrants(primary, Access)) {
        /* Note: Violation occurs despite the primary value being granted; our understanding of the hardware state is incorrect. */
        return KswordArkHvmEptSwRefuse(
            Transition, KSWORD_ARK_HVM_EPTSW_REASON_SPURIOUS);
    }
    if (!KswordArkHvmEptSwGrants(secondary, Access)) {
        /* Neither side grants access: this access cannot be represented in any single hierarchy. */
        return KswordArkHvmEptSwRefuse(
            Transition, KSWORD_ARK_HVM_EPTSW_REASON_UNREPRESENTABLE);
    }
    /* Switch to this leaf level; the previously relaxed leaf automatically retracts its primary value. */
    Transition->Outcome = KSWORD_ARK_HVM_EPTSW_OUTCOME_SWITCH;
    Transition->NextIndex = faultIndex;
    Transition->Reason = KSWORD_ARK_HVM_EPTSW_REASON_NONE;
    return KSWORD_ARK_HVM_EPTSW_OUTCOME_SWITCH;
}

/*
 * Complete the value to be written to VMCS based on the decision.
 *
 * Split into two steps rather than one because the decision depends only on index and permissions, allowing exhaustive testing;
 * whereas the ledger lookup depends on a block of runtime memory, allowing only sampling. Mixing them would force exhaustive
 * testing to construct the EPTP table, which is precisely where implementations are most likely to be copied verbatim in tests.
 *
 * This additionally guards against two types of construction errors, which share the characteristic of having no runtime symptoms other than stalling:
 *   - If ledger length != 1 + leaf count, indexing reads out of
 *     bounds, potentially retrieving a seemingly valid old pointer.
 *   - Source and target share EP4TA: the switch does not change cache tags; it is a hardware no-op.
 *
 * **Precondition (mandatory, not advisory):** After this function returns OUTCOME_SWITCH but before the actual
 * VMWRITE EPT_POINTER, the caller must first ensure the processor's progress ledger acknowledges this transition
 * by calling KswordArkHvmEptSwProgressAdmit(&progress, rip, gpa, transition.NextIndex), which must return
 * non-zero. If it returns zero, the flow proceeds to the fail-closed path, identical to the 'flip failure' path.
 *
 * Why this rule cannot be merged into this function: This function is pure, and the only violation observed is this single instance.
 * Even if a single instruction requires two leaf values (fetch from a HOOK page, operand read from a CLOAK page),
 * each half individually can be serviced. This function will correctly return SWITCH repeatedly without advancing
 * RIP. This is not a logic error in the function; the necessary information is simply not present in the parameters.
 * Skipping the ledger step causes the machine to silently deadlock: no BSOD, no events, and no logs.
 */
static __inline unsigned long
KswordArkHvmEptSwPlanSwitch(
    const unsigned long long* EptpTable,
    unsigned long EptpCount,
    unsigned long ActiveIndex,
    unsigned long FaultLeafIndex,
    unsigned long LeafCount,
    unsigned long Access,
    unsigned long Kind,
    int ExecuteOnlySupported,
    KSWORD_ARK_HVM_EPTSW_TRANSITION* Transition
    )
{
    unsigned long long target = 0ULL;
    unsigned long long source = 0ULL;

    /* No output location means no plan can be made. */
    if (Transition == 0) {
        return KSWORD_ARK_HVM_EPTSW_OUTCOME_REFUSE;
    }
    /* Perform a pure index decision first; it will set the rejection state itself. */
    if (KswordArkHvmEptSwDecide(
            ActiveIndex,
            FaultLeafIndex,
            LeafCount,
            Access,
            Kind,
            ExecuteOnlySupported,
            Transition) != KSWORD_ARK_HVM_EPTSW_OUTCOME_SWITCH) {
        /* Pass the refusal reason to the caller as-is. */
        return KSWORD_ARK_HVM_EPTSW_OUTCOME_REFUSE;
    }
    /* The ledger must exactly match 'base + one set per leaf'. */
    if (EptpTable == 0 ||
        EptpCount != KswordArkHvmEptSwHierarchyCount(LeafCount)) {
        return KswordArkHvmEptSwRefuse(
            Transition, KSWORD_ARK_HVM_EPTSW_REASON_LEDGER);
    }
    /* The index has already been validated by the decision logic to fall within [0, LeafCount]. */
    source = EptpTable[ActiveIndex];
    target = EptpTable[Transition->NextIndex];
    /* Both slots must be genuinely filled. */
    if (KswordArkHvmEptSwEptpRoot(source) == 0ULL ||
        KswordArkHvmEptSwEptpRoot(target) == 0ULL) {
        return KswordArkHvmEptSwRefuse(
            Transition, KSWORD_ARK_HVM_EPTSW_REASON_LEDGER);
    }
    /* Switching between the two layers of shared tags is a no-op. */
    if (KswordArkHvmEptSwSwitchNeedsInvalidation(source, target)) {
        return KswordArkHvmEptSwRefuse(
            Transition, KSWORD_ARK_HVM_EPTSW_REASON_ALIASED);
    }
    /* Return the exact value to be written to the VMCS EPT_POINTER field. */
    Transition->TargetEptp = target;
    return KSWORD_ARK_HVM_EPTSW_OUTCOME_SWITCH;
}

/* ------------------------------------------------------------------ */
/* Progressive ledger: The half of Decide that cannot be represented is invisible.                            */
/* ------------------------------------------------------------------ */

/*
 * This section was merged from the deleted shared/driver/KswordArkHvmEptpSwitch.h, which was another implementation of the same
 * design (prefixed with KswordArkHvmEptp*). The only criterion in this section that was originally absent from this file is the one
 * being moved here; all other parts of this file are a superset. Thus, only this section was transferred and rewritten to match this
 * file's naming and limits. The reason for merging is not "code reuse" but "ensuring a single source of truth for the same judgment":
 * Each header reserves one ring detection; in the future, one side will change while the other does not.
 *
 * This section handles the **cross-leaf** case of the combinations described as unrepresentable at the start of this file:
 *
 *   A single instruction requires two leaf values simultaneously: the instruction fetch falls in a HOOK page (requiring a switch to the
 *   HOOK leaf level), while the same instruction's operand read falls in a CLOAK page (requiring a switch to the CLOAK leaf level).
 *   Each hierarchy level relaxes only one leaf, so no single hierarchy level can serve both halves simultaneously.
 *
 * KswordArkHvmEptSwDecide is powerless here, and it is not a bug: it receives only one violation
 * at a time. Each half of that violation is individually servable, so it honestly returns SWITCH
 * k -> SWITCH j -> SWITCH k -> ..., with the RIP advancing by zero steps. Each exit appears
 * completely normal in isolation. This is the silent deadlock of the entire machine mentioned
 * repeatedly in this file: no BSOD, no events, no logs, because no 'error' ever occurred.
 *
 * The predicate must be cross-exit, requiring per-VCPU history. This does not violate 'no second
 * truth source for the same judgment': Decide judges 'whether this violation can be resolved by
 * a single switch', while the ledger judges 'whether this sequence of switches is progressing'.
 */

/*
 * Maximum number of consecutive switches allowed on the same RIP.
 *
 * A single instruction can legitimately violate the rule multiple times in a row: once for the instruction fetch, and once for each memory operand.
 * Four is the maximum value conceivable on this path (fetch + three accesses); eight leaves a two-fold margin. Exceeding it must indicate a loop.
 * This upper limit is only a fallback for long loops; loops in cycle 1 and cycle 2 are caught by the precise criteria below.
 *
 * Increasing it does not improve safety: it only determines "when to give up," and the cost of giving
 * up is a fail-closed de-virtualization, which is far less severe than a machine silently deadlocking.
 */
#define KSWORD_ARK_HVM_EPTSW_MAX_SAME_RIP_SWITCHES 8UL

/*
 * Per-processor progress ledger.
 *
 * Only record two generations of history, as the two types of rings to capture are within two generations:
 *   Cycle 1: After switching, if the same instruction, same page, and same target appear again, the switch has no effect.
 *   Phase 2: A needs the X value, B needs the Y value, but a single instruction requires both, causing it to jump
 *           back and forth between the two hierarchy levels. This is exactly the cross-page combination described above.
 *
 * This structure must be **per-processor private**: if two processors share one instance, A's RIP will clear B's count, causing B's
 * ring counter to never reach its threshold. The check fails silently on multi-core systems while passing all tests on single-core.
 */
typedef struct _KSWORD_ARK_HVM_EPTSW_PROGRESS
{
    /* Guest RIP at the last switch. */
    unsigned long long LastRip;
    /* The guest physical address of the last violation during the previous switch. */
    unsigned long long LastGuestPhysical;
    /* Guest RIP at the second-to-last switch. */
    unsigned long long PreviousRip;
    /* Guest physical address from the second-to-last switch. */
    unsigned long long PreviousGuestPhysical;
    /* Target level index of the last switch. */
    unsigned long LastTarget;
    /* Target level index of the second-to-last switch. */
    unsigned long PreviousTarget;
    /* Number of consecutive switches on the same RIP. */
    unsigned long SameRipSwitches;
    /* Maintain natural alignment for 64-bit members. */
    unsigned long Reserved0;
} KSWORD_ARK_HVM_EPTSW_PROGRESS;

/*
 * Reset the ledger to 'not yet switched'.
 *
 * Call after entering resident state, after each VMCS reconfiguration, and after each view set change: if not cleared,
 * the (RIP, page, target) left by the previous view set will cause the first valid switch of the new view set to be
 * judged as a loop, resulting in a fail-closed exit from virtualization immediately after the view is installed.
 */
static __inline void
KswordArkHvmEptSwProgressReset(
    KSWORD_ARK_HVM_EPTSW_PROGRESS* Progress
    )
{
    /* Ignore a null ledger instead of dereferencing it. */
    if (Progress == 0) {
        return;
    }
    Progress->LastRip = 0ULL;
    Progress->LastGuestPhysical = 0ULL;
    Progress->PreviousRip = 0ULL;
    Progress->PreviousGuestPhysical = 0ULL;
    Progress->LastTarget = KSWORD_ARK_HVM_EPTSW_INDEX_BASE;
    Progress->PreviousTarget = KSWORD_ARK_HVM_EPTSW_INDEX_BASE;
    Progress->SameRipSwitches = 0UL;
    Progress->Reserved0 = 0UL;
}

/*
 * Check if this switch is progressing and record it in the ledger.
 *
 * Returns non-zero to indicate the switch is allowed; returns zero to indicate this switch yields no progress. The caller
 * must fail-closed (following the same path as today's 'flip failure') rather than switching and waiting to return.
 *
 * The ledger is **not updated** upon rejection: the outcome of this exit is leaving the virtualization environment,
 * so the ledger has no next serviceable state. Preserving the context is more useful for post-event analysis.
 *
 * Note: Reset the counter when RIP changes; this is intentional: a changed RIP indicates the previous instruction retired,
 * meaning the previous switch took effect. Conversely, an unchanged RIP does not necessarily imply a loop—the fetch and operands
 * of the same instruction may each require a switch—so a loop is only detected when 'same RIP AND (page, target) exactly matches
 * one of the previous two generations'. Writing it as 'reject on same RIP' would cause every normal instruction crossing two
 * view pages to exit virtualization; writing it as 'check target only, ignore page' would allow period-2 loops to pass.
 */
static __inline int
KswordArkHvmEptSwProgressAdmit(
    KSWORD_ARK_HVM_EPTSW_PROGRESS* Progress,
    unsigned long long Rip,
    unsigned long long GuestPhysical,
    unsigned long TargetIndex
    )
{
    /* No ledger means progress cannot be proven; treat as no progress. */
    if (Progress == 0) {
        return 0;
    }
    if (Rip != Progress->LastRip) {
        /* Another instruction: unrelated to history; reset counter and accept. */
        Progress->PreviousRip = Progress->LastRip;
        Progress->PreviousGuestPhysical = Progress->LastGuestPhysical;
        Progress->PreviousTarget = Progress->LastTarget;
        Progress->LastRip = Rip;
        Progress->LastGuestPhysical = GuestPhysical;
        Progress->LastTarget = TargetIndex;
        Progress->SameRipSwitches = 1UL;
        return 1;
    }
    /* Cycle 1: The same instruction, same page, and same target are encountered again. */
    if (GuestPhysical == Progress->LastGuestPhysical &&
        TargetIndex == Progress->LastTarget) {
        return 0;
    }
    /* Cycle 2: Completely identical to the previous-to-last state, indicating a toggle between two hierarchy levels. */
    if (Rip == Progress->PreviousRip &&
        GuestPhysical == Progress->PreviousGuestPhysical &&
        TargetIndex == Progress->PreviousTarget) {
        return 0;
    }
    /* Long-loop fallback: switching too many times on the same RIP indicates an abnormal instruction. */
    if (Progress->SameRipSwitches >=
        KSWORD_ARK_HVM_EPTSW_MAX_SAME_RIP_SWITCHES) {
        return 0;
    }
    /* Record this generation and accept. */
    Progress->PreviousRip = Progress->LastRip;
    Progress->PreviousGuestPhysical = Progress->LastGuestPhysical;
    Progress->PreviousTarget = Progress->LastTarget;
    Progress->LastGuestPhysical = GuestPhysical;
    Progress->LastTarget = TargetIndex;
    Progress->SameRipSwitches += 1UL;
    return 1;
}
