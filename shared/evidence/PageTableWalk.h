#pragma once

// M Module: Offline-testable x64 four-level page table parsing core.
//
// This layer is unaware of Windows or drivers; it only requires 'a physical page read callback,' then parses layer-by-layer according
// to Intel SDM's 4-level paging rules. The same validation logic can therefore be used by offline fixture drivers (using a block
// std::vector<uint8_t> (spoofed physical memory) can also be read by the real R0 path driver.
//
// Corresponding acceptance criteria.
//   M-03 VA translation context (process instance + page table root source + timestamp + paging mode; invalid contexts disabled).
//   M-04 Page boundaries and large pages (4KiB / 2MiB / 1GiB, canonical, page faults, reserved bit exceptions).
//   M-05: Non-resident and observation side effects (distinguishing transient states, prototypes, and PageFile software PTEs).
//
// Hard rule: never relax this under any circumstances:
//   * Non-canonical, missing entries, reserved-bit exceptions, or read failures — never produce a physical address.
//     "Do not forge physical addresses" (M-04) means physicalAddress remains unset, not set to 0.
//   For entries with present=0, the remaining bits are software-defined and cannot be interpreted
//     as hardware fields; therefore, reserved bit validation applies only to entries with present=1.
//   * Level-5 paging (LA57) is not supported by this implementation. Unsupported means UnsupportedMode;
//     it never degrades to "guessing based on Level-4" (M-04: unsupported modes are explicitly rejected).

#include "LiveNavigation.h"
#include "LosslessValue.h"
#include "ObjectIdentity.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace ksword::evidence {

// Physical memory read callback. Returns false if the physical address is unreadable (unmapped, out of bounds, or access denied).
// Offline stubs and the real driver share this signature, so the kernel parser doesn't need to know which side it's running on.
using PhysicalReader =
    std::function<bool(std::uint64_t physAddr, std::uint8_t* out, std::size_t bytes)>;

// ---------------------------------------------------------------------------
// M-04: Paging mode. Only x64 4-level paging is declared as supported.
// ---------------------------------------------------------------------------
enum class PagingMode {
    kLongMode4Level,  // IA-32e 4-level paging (PML4 -> PDPT -> PD -> PT)
    kUnsupported,     // All other cases: LA57 five-level, PAE, 32-bit non-PAE, and unknown hardware.
};

const char* pagingModeName(PagingMode mode) noexcept;

enum class PageTableLevel {
    kNone,   // Has not entered any level (non-canonical / mode unsupported / inherently invalid).
    kPml4,
    kPdpt,
    kPd,
    kPt,
};

const char* pageTableLevelName(PageTableLevel level) noexcept;

enum class TranslationStatus {
    kTranslated,          // The walk succeeded through every level; physicalAddress is valid.
    kNotCanonical,        // VA does not satisfy the 48-bit sign-extension rule.
    kEntryNotPresent,     // P=0 at a certain level; failedLevel indicates which level.
    kReservedBitSet,      // A reserved bit is set in a present entry at a certain level; reservedBitsSet specifies the exact bits.
    kPhysicalReadFailed,  // Failed to read physical address of a table entry at a certain level.
    kUnsupportedMode,     // Paging mode is not LongMode4Level.
    // M-03: Context invalid; translation was never initiated. The actual reason is in TranslateResult::contextRefusal.
    // This case must be separated from UnsupportedMode: rendering "process exited"
    // as "page table mode unsupported" gives the user a false denial reason.
    kContextRejected,
};

const char* translationStatusName(TranslationStatus status) noexcept;

// M-05: When present=0, the remaining bits of the entry are OS-defined. This classification follows the
// public encoding for Windows software PTEs; if it cannot be determined, it is Unknown—no guessing.
enum class SoftwarePteKind {
    kTransition,  // bit11=1 and bit10=0: The page is still in the transition list (standby/modified) and has not been reclaimed.
    kPrototype,   // bit10=1: Points to a prototype PTE.
    // If neither bit above is set and PageFileHigh(bit32..63) is nonzero, the page is in the page file.
    // Only then interpret the page-file number (bit1..4) and page-file offset (bit32..63).
    kPageFile,
    // Not all zeros, neither of the upper two bits set, but `PageFileHigh == 0`: only fields like Protection are filled
    // in `MMPTE_SOFTWARE` (e.g., entry=0x20), indicating a demand-zero page that is committed but has never been touched.
    // It has no location in the paging file — never fabricate a page file number or offset for it (M-05).
    kDemandZero,
    kZero,        // Table entry is all zeros: no mapping has been established (not committed).
    kUnknown,     // Handle cases where mutually exclusive bits are set simultaneously; do not force a single classification.
};

const char* softwarePteKindName(SoftwarePteKind kind) noexcept;

enum class PageSizeClass {
    kSize4KiB,
    kSize2MiB,  // PDE.PS=1
    kSize1GiB,  // PDPTE.PS=1
};

const char* pageSizeClassName(PageSizeClass size) noexcept;
std::uint64_t pageSizeBytes(PageSizeClass size) noexcept;

// ---------------------------------------------------------------------------
// Per-level evidence. The UI must be able to expand 'which physical address was read at this level,
// what was read, and which index was used', so all three must be retained, not just the final result.
// ---------------------------------------------------------------------------
struct PageTableEntryEvidence final {
    PageTableLevel level = PageTableLevel::kNone;
    std::uint32_t index = 0;                    // The 9-bit index at this level (0..511).
    std::uint64_t entryPhysicalAddress = 0;     // The physical address where the entry itself resides.
    std::uint64_t rawValue = 0;                 // Raw 64-bit value; meaningful only when read is true.
    bool read = false;                          // Whether rawValue was actually read.
    bool present = false;                       // bit0
    bool largePage = false;                     // bit7 (interpreted as large page only on PDPTE/PDE)
    std::uint64_t reservedBitsSet = 0;          // Bitmask of bits violating reserved bit rules; 0 indicates none.
};

// M-05: Decoding result for non-resident entries. No field produces a physical address.
struct SoftwarePteDecode final {
    SoftwarePteKind kind = SoftwarePteKind::kUnknown;
    bool transitionBit = false;     // bit11
    bool prototypeBit = false;      // bit10
    // Values are valid only under the PageFile classification. All other classifications must remain unset; setting
    // present=1 with value=0 would fabricate a "page file location" out of thin air, which is explicitly prohibited by M-05.
    OptionalU64 pageFileNumber;     // bit1..4
    OptionalU64 pageFileOffset;     // bit32..63, in pages.
};

// Effective permissions after bitwise AND operations across all levels. This is only meaningful when Translated.
struct EffectivePermissions final {
    bool writable = false;        // AND of bit1 at each level.
    bool userAccessible = false;  // AND of bit2 at each level.
    bool executeDisable = false;  // OR of bit63 at each level.
};

struct TranslateOptions final {
    PagingMode mode = PagingMode::kLongMode4Level;
    // MAXPHYADDR (CPUID.80000008H:EAX[7:0]). Bits above the physical address field and
    // below bit51 must be 0 in hardware; exceeding this triggers a reserved-bit exception.
    // 0 indicates "caller did not provide": this check is explicitly disabled and marked as unset in TranslateResult. Previously, the
    // default was 52, and the reserved mask for 52 happened to be 0, causing this criterion to silently fail under default
    // configuration while appearing to have run. The default is now changed to "unknown" to avoid pretending the check was performed.
    std::uint32_t maxPhysAddrBits = 0;
    // CPUID.80000001H:EDX[26] (Page1GB). When false, bit7 of the PDPTE is a **reserved bit**; setting it triggers a
    // reserved-bit #PF. Therefore, when parsing machines (or their offline dumps) that do not support 1GiB pages, this bit must
    // never be interpreted as a large page to translate to a physical address (M-04). Default is false: prefer to reject more.
    bool supports1GiBPages = false;
};

// ---------------------------------------------------------------------------
// M-03: Context validity.
// TranslateResult must propagate the reason 'why the context was rejected' as-is, so this set of criteria must
// be defined before TranslateResult; the actual context structure is in Section M-03 at the end of this file.
// ---------------------------------------------------------------------------
enum class ContextValidity {
    kUsable,                      // Context identity confirmed consistent; translation can proceed.
    kRejectProcessExited,         // Process exited: only historical observations are available.
    kRejectIdentityMismatch,      // Same PID, different instance (PID reuse).
    kRejectIdentityUnverifiable,  // Identity information is insufficient to verify; do not treat as the same process.
    kRejectNoPageTableRoot,       // No page table root in the context.
    kRejectUnsupportedMode,       // Page table mode is not supported by this implementation (4-level).
};

const char* contextValidityName(ContextValidity validity) noexcept;

struct TranslateResult final {
    TranslationStatus status = TranslationStatus::kUnsupportedMode;
    PagingMode mode = PagingMode::kUnsupported;
    std::uint64_t virtualAddress = 0;
    OptionalU64 pageTableRootPhysical;

    // Include only the levels actually traversed, in PML4E -> PDPTE -> PDE -> PTE order.
    std::vector<PageTableEntryEvidence> levels;

    PageTableLevel failedLevel = PageTableLevel::kNone;
    std::uint64_t reservedBitsSet = 0;   // Specific bits when status == ReservedBitSet.

    PageSizeClass pageSize = PageSizeClass::kSize4KiB;
    OptionalU64 pageFrameBase;   // Physical base address of the page frame; present only if Translated.
    OptionalU64 pageOffset;      // Offset within the page; bit width varies with page size.
    OptionalU64 physicalAddress; // Only Translated states are present; all other states are unset.

    bool softwarePteDecoded = false;  // True when status == EntryNotPresent.
    SoftwarePteDecode softwarePte;

    EffectivePermissions permissions;

    // The actually effective MAXPHYADDR for this operation. If unset, the caller did not provide it, and the reserved bit check is **not effective**.
    // Export and verification know that "this check did not run this time" rather than assuming it ran and passed (M-04).
    OptionalU64 effectiveMaxPhysAddrBits;
    // How to interpret PDPTE.bit7 regarding 1GiB capability in this context: when false, this bit is treated as reserved.
    bool supports1GiBPages = false;

    // Actual rejection reason when status==ContextRejected (M-03); otherwise, leave it Usable.
    ContextValidity contextRefusal = ContextValidity::kUsable;
};

// Core entry point. An empty reader, invalid root address, or any level failure yields a definite status rather than a guessed result.
TranslateResult translateVirtualAddress(std::uint64_t virtualAddress,
                                        std::uint64_t pageTableRootPhysical,
                                        const PhysicalReader& reader,
                                        const TranslateOptions& options = TranslateOptions{});

// 48-bit canonical check, exposed separately to allow the UI to provide a reason before initiating translation.
bool isCanonicalAddress48(std::uint64_t virtualAddress) noexcept;

// M-05: Decode a single entry with present=0. The UI uses this directly when explaining 'why there is no physical address'.
SoftwarePteDecode decodeSoftwarePte(std::uint64_t rawEntry) noexcept;

// ---------------------------------------------------------------------------
// M-03: Translation context.
// A translation result is only meaningful under the same 'process instance + page table root + paging mode'.
// After a process exits or its PID is reused, the saved context can only be displayed as historical observation.
// ---------------------------------------------------------------------------
struct TranslationContext final {
    ProcessInstanceId process;
    OptionalU64 pageTableRootPhysical;  // CR3 / DirectoryTableBase / dump header
    OptionalU64 observedUtc100ns;       // Collection timestamp; missing means unset, do not fill with current time.
    PagingMode mode = PagingMode::kUnsupported;
    std::string rootSource;             // Where the root comes from, e.g., "KPROCESS.DirectoryTableBase"
};

// Reuse the process identity criteria from LiveNavigation instead of creating a separate PID comparison.
ContextValidity checkContextUsable(const TranslationContext& saved,
                                   const LiveResolution& live) noexcept;

// Only Usable contexts are allowed for new context translations.
bool contextAllowsLiveReuse(ContextValidity validity) noexcept;

// M-03: Translation is prohibited when the context is invalid. When returning false, set out.status
// = ContextRejected, out.contextRefusal = the actual reason, and leave no physical address; the
// caller must mark any saved old result as a historical observation. options.mode is overridden by
// context.mode; other options (MAXPHYADDR, 1GiB capability) use the values provided by the caller.
bool translateUsingContext(const TranslationContext& context,
                           ContextValidity validity,
                           std::uint64_t virtualAddress,
                           const PhysicalReader& reader,
                           const TranslateOptions& options,
                           TranslateResult& out);

} // namespace ksword::evidence
