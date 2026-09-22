#pragma once

// KvmEptLeafProbe: Read back a guest physical address's fourth-level page table entry in the EPT.
//
// Reason for existence:
// - This line repeatedly misses the same reading: 'View/Rules installed' and 'That leaf is actually restricted' are two
//   different things, and the protocol only answers the former. The deniedAccess in the ADD response is a **normalized
//   request**, not the leaf's current value; addView returning success only proves the driver accepted the request.
// - The worst class of failures encountered in this project is exactly 'leaf write succeeded but has no effect, while all self-checks pass'.
//   Any indirect criterion will lie under such a fault; only reading the leaf item itself remains reliable.
//
// Why user-mode can read: EPT page tables are ordinary guest physical memory allocated by the driver
// and identity-mapped as RWX, so existing OP_READ_PHYSICAL can be used to read level-by-level. No
// driver changes or write permission gates are needed; this layer is purely read-only observation.
//
// ---------------------------------------------------------------------------
// [Known blind spot, must be presented alongside the reading.]
//
// It reads the **base** layer (the ept-leaf command in hvm_ctl.c is annotated this way at lines 2396 and
// 2517): the root address is taken from the eptPointer returned by QUERY_HVM, traversing down that tree.
//
// **The two backends have different blind spots; previously writing them as the same was incorrect.**
//
// * **Per-processor private EPT (localEptArmed)**: Each processor has its own tree branching
//   from the base, and the loaded tree is not the base. Reading "what the base allows" here
//   does not equal "what that processor sees," so the value must be recorded as invalid.
//
// * **EPTP Switching (eptpSwitchArmed)**: **The base is the steady state**. The design document (section on hierarchy
//   numbering in shared/driver/KswordArkHvmEptSwitch.h) hardcodes that "index 0 = base, where every leaf takes the primary
//   value, i.e., today's steady state". Index k only relaxes the (k-1)-th leaf. Therefore, reading the base leaf is exactly
//   reading the steady-state primary value, making it a valid criterion. The only thing it cannot read is "the relaxed leaf
//   at index k", which belongs to the flip state and is not the question the steady-state criterion needs to answer.
//
//   Testing on the target on 2026-09-07 confirmed that installing a CLOAK makes the base leaf read back
//   `0x80000000F1353034  R=0 W=0 X=1`: the CLOAK primary value, pointing execute-only access at the real page.
//   Disable this backend to read-only, effectively disabling the only falsifiable criterion on the sole machine where it can be used.
//
// Both localEptArmed and eptpSwitchArmed are retained in the result structure, but **the caller must handle them differently**: the
// former is checked for missing readings, while the latter is checked normally and the conclusion notes that the base was read.
// ---------------------------------------------------------------------------
//
// All calls are blocking IOCTLs (one QUERY_HVM plus up to four READ_PHYSICAL); the caller
// must run on a background thread. This layer does not interact with any controls.

#include <QString>

#include <array>

namespace ks::ui
{
    // EptLeafEntryRecord: Read-back result at a specific level during EPT table walk.
    //
    // Leave one slot at all four levels; the levels not traversed have read=false, allowing
    // the caller to see where the walk stopped instead of just receiving a 'failure'.
    struct EptLeafEntryRecord
    {
        // read: The 8 bytes at this level have been read. If false, either execution never reached this point (stopped at the
        // previous level) or the READ_PHYSICAL operation failed; these two cases are distinguished by whether failure is null.
        bool read = false;
        // index: Slot index within the current level table (0..511).
        quint32 index = 0;
        // tableBase: physical base address of the current-level page table (page-aligned).
        quint64 tableBase = 0;
        // entryAddress: The physical address of this entry itself, calculated as tableBase + index * 8.
        // Kept so users can use this address to verify the same byte elsewhere.
        quint64 entryAddress = 0;
        // entry: The 64-bit raw value of the entry. A value of 0 indicates no mapping at this level.
        quint64 entry = 0;
        // Access permissions are three bits (bit0/1/2). In EPT, these are the only permissions; there is no U/S distinction.
        bool readable = false;
        bool writable = false;
        bool executable = false;
        // largePage: bit7 (PS). Only meaningful in PDPT (1 GiB) and PD
        // (2 MiB); when set, this level is a leaf and traversal stops.
        bool largePage = false;
        // failure: reason for read failure at this level, localized. Empty on success.
        QString failure;
    };

    // EptLeafProbeResult: Complete result of a base EPT table walk.
    struct EptLeafProbeResult
    {
        // ok: No read failures occurred during the table walk, so the following conclusion is reliable.
        // Note that 'not mapped' is not a failure: it is itself a definitive conclusion, so ok remains true.
        bool ok = false;
        // targetGpa: The original address passed by the caller (page offset preserved for display).
        quint64 targetGpa = 0;
        // pageBaseGpa: The 4 KiB page base address where targetGpa resides; this is the value actually used when walking the table.
        quint64 pageBaseGpa = 0;
        // eptPointer: The original value returned by QUERY_HVM; the lower 12 bits encode memory type, levels, and AD.
        quint64 eptPointer = 0;
        // eptRoot: The PML4 physical base address extracted from eptPointer, serving as the starting point for table walking.
        quint64 eptRoot = 0;
        // The following two fields are not used in table traversal; they only mark blind spots (see file header): if
        // either is true, this result describes the base, while the running processor may be attached to a different tree.
        bool localEptArmed = false;
        bool eptpSwitchArmed = false;
        // levels: Four levels (PML4 / PDPT / PD / PT); index equals level number.
        std::array<EptLeafEntryRecord, 4> levels{};
        // walkedLevels: Actual number of levels that initiated a read (1..4).
        int walkedLevels = 0;
        // reachedLeaf: Indicates a leaf entry describing this page was found (PT entry is non-zero, or a large page entry exists on the PDPT/PD).
        bool reachedLeaf = false;
        // largePage: Leaf falls on PDPT (1 GiB) or PD (2 MiB).
        // When this bit is set, the leaf entry manages more than just the target page; modifying it affects the entire range.
        bool largePage = false;
        // unmapped: the table is truncated by a zero entry; this page is unmapped in the base.
        bool unmapped = false;
        // leafLevel: The level number of the leaf (0..3); -1 if the leaf has not been reached.
        int leafLevel = -1;
        // leafEntry: The original 64-bit value of the leaf entry.
        quint64 leafEntry = 0;
        // leafFrameAddress: The physical frame base address pointed to by the leaf entry, aligned to the page size at this level.
        quint64 leafFrameAddress = 0;
        // The three access permission bits of the leaf entry — these three booleans are the readings this probe needs to obtain.
        // All three are false if the leaf is not reached, so 'restricted' must be checked only after verifying reachedLeaf.
        bool readable = false;
        bool writable = false;
        bool executable = false;
        // memoryType: EPT memory type in leaf-entry bit5..3 (0=UC, 6=WB).
        // Only meaningful when reachedLeaf is true.
        quint32 memoryType = 0;
        // ignorePat: Leaf bit6.
        bool ignorePat = false;
        // suppressVe: Leaf bit63. The driver attaches this bit to every leaf; it is one of two #VE safeguards.
        // If reading it back shows it has been cleared, it is a signal to stop immediately for inspection.
        bool suppressVe = false;
        // message: A localized conclusion or failure reason that can be displayed directly.
        QString message;
    };

    // eptLeafLevelName: Maps level numbers to mnemonics (PML4 / PDPT / PD / PT).
    // This is an architecture mnemonic, not a translation, so it is not included in the glossary.
    QString eptLeafLevelName(int level);

    // readBaseEptLeaf: Traverses the base EPT to read the level-4 entry for the page at targetGpa.
    //
    // - Blocking (one QUERY_HVM + up to four READ_PHYSICAL calls); must be called from a background thread;
    // - Read-only; does not require write access gates and does not alter any driver-side state.
    // - If eptPointer is 0 (resources not ready or driver not running),
    //   returns ok=false with a message explaining the failure; does not crash.
    // - Result describes only the base level; blind spots are documented in the file header.
    EptLeafProbeResult readBaseEptLeaf(quint64 targetGpa);
}
