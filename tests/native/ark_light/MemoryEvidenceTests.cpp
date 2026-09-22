// Offline automated test for Module M (Memory Evidence and Address Translation Deepening).
//
// Coverage IDs: M-01 M-02 M-03 M-04 M-05 M-07 M-09 M-10 (along with the accounting requirements for F-05 / F-06).
//
// Page table fixtures are entirely constructed by code in this file: a 256 KiB simulated "physical memory" block with PML4/PDPT/PD/PT
// entries manually filled one by one; PhysicalReader reads from this memory. All expected physical addresses are constants calculated
// by hand in comments, not computed by the code under test—otherwise the test would merely be stamping the implementation.

#include "TestSupport.h"

#include "../../../shared/evidence/MemoryRegionEvidence.h"
#include "../../../shared/evidence/PageTableWalk.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace {

using namespace ksword::evidence;

// ---------------------------------------------------------------------------
// Offline page table fixture
// ---------------------------------------------------------------------------
//
// Simulate physical memory overwrite in [0x00000000, 0x00040000), totaling 64 4KiB pages. Layout:
//   0x1000 PML4-A   0x2000 PDPT-A   0x3000 PD-A   0x4000 PT-A    frame 0x00010000
//   0x5000 PML4-B   0x6000 PDPT-B   0x7000 PD-B   0x8000 PT-B    frame 0x00011000
//   0x9000 PML4-C   0xA000 PDPT-C   0xB000 PD-C(PS=1, 2MiB)     frame 0x00C00000
//   0xC000 PML4-D   0xD000 PDPT-D(PS=1, 1GiB)                  frame 0x180000000
//
// The translated virtual address is fixed to kVa, with its four-level indices being 1 / 2 / 3 / 4:
//   kVa = (1<<39) | (2<<30) | (3<<21) | (4<<12) | 0x678 = 0x0000008080604678
// Manually calculated page offset:
//   4KiB -> kVa & 0x00000FFF = 0x678
//   2MiB -> kVa & 0x001FFFFF = 0x4678 (3<<21 is the PD index, not part of the offset).
//   1GiB -> kVa & 0x3FFFFFFF = 0x604678 (2<<30 is the PDPT index, not part of the offset).

constexpr std::uint64_t kVa = 0x0000008080604678ULL;

constexpr std::uint64_t kRootA = 0x1000ULL;
constexpr std::uint64_t kRootB = 0x5000ULL;
constexpr std::uint64_t kRootC = 0x9000ULL;
constexpr std::uint64_t kRootD = 0xC000ULL;

// Physical addresses of entries at each level: Table base address + index * 8.
constexpr std::uint64_t kEntryPml4A = 0x1000ULL + 1ULL * 8ULL;   // 0x1008
constexpr std::uint64_t kEntryPdptA = 0x2000ULL + 2ULL * 8ULL;   // 0x2010
constexpr std::uint64_t kEntryPdA   = 0x3000ULL + 3ULL * 8ULL;   // 0x3018
constexpr std::uint64_t kEntryPtA   = 0x4000ULL + 4ULL * 8ULL;   // 0x4020
constexpr std::uint64_t kEntryPml4B = 0x5000ULL + 1ULL * 8ULL;   // 0x5008
constexpr std::uint64_t kEntryPdptB = 0x6000ULL + 2ULL * 8ULL;   // 0x6010
constexpr std::uint64_t kEntryPdB   = 0x7000ULL + 3ULL * 8ULL;   // 0x7018
constexpr std::uint64_t kEntryPtB   = 0x8000ULL + 4ULL * 8ULL;   // 0x8020
constexpr std::uint64_t kEntryPml4C = 0x9000ULL + 1ULL * 8ULL;   // 0x9008
constexpr std::uint64_t kEntryPdptC = 0xA000ULL + 2ULL * 8ULL;   // 0xA010
constexpr std::uint64_t kEntryPdC   = 0xB000ULL + 3ULL * 8ULL;   // 0xB018
constexpr std::uint64_t kEntryPml4D = 0xC000ULL + 1ULL * 8ULL;   // 0xC008
constexpr std::uint64_t kEntryPdptD = 0xD000ULL + 2ULL * 8ULL;   // 0xD010

// P|RW|US = 0x7; PS bit is 0x80.
constexpr std::uint64_t kLeafA = 0x00010007ULL;   // Frame 0x00010000
constexpr std::uint64_t kLeafB = 0x00011007ULL;   // Frame 0x00011000
constexpr std::uint64_t kLeaf2M = 0x00C00087ULL;  // Frame 0x00C00000, PS=1.
constexpr std::uint64_t kLeaf1G = 0x180000087ULL; // Frame 0x180000000, PS=1

// Manually calculated final physical address.
constexpr std::uint64_t kExpectedPaA = 0x00010678ULL;   // 0x00010000 | 0x678
constexpr std::uint64_t kExpectedPaB = 0x00011678ULL;   // 0x00011000 | 0x678
constexpr std::uint64_t kExpectedPa2M = 0x00C04678ULL;  // 0x00C00000 | 0x4678
constexpr std::uint64_t kExpectedPa1G = 0x180604678ULL; // 0x180000000 | 0x604678

// M-04: MAXPHYADDR no longer has a default value that 'looks like a check but isn't'. TranslateOptions default 0 means
// caller didn't provide it = this check is explicitly disabled, so tests uniformly pass a real width explicitly.
// 48 bits is the common value for desktop CPUs; all entries in the fixture fall within 48 bits, so it will not cause false positives.
constexpr std::uint32_t kMaxPhys = 48U;

// Default options: 4-level paging + MAXPHYADDR=48 + **1GiB large pages not supported**.
// 1GiB is disabled by default as a hard rule: Intel SDM specifies that when
// CPUID.80000001H:EDX.Page1GB==0, bit7 of the PDPTE is reserved; setting it triggers a reserved-bit #PF.
TranslateOptions makeOptions() {
    TranslateOptions options;
    options.mode = PagingMode::kLongMode4Level;
    options.maxPhysAddrBits = kMaxPhys;
    options.supports1GiBPages = false;
    return options;
}

// Only allow using this if CPUID.80000001H:EDX[26] has been confirmed.
TranslateOptions makeOptions1GiB() {
    TranslateOptions options = makeOptions();
    options.supports1GiBPages = true;
    return options;
}

using PhysMemory = std::vector<std::uint8_t>;

void putEntry(PhysMemory& memory, std::uint64_t physicalAddress, std::uint64_t value) {
    for (std::size_t i = 0; i < 8U; ++i) {
        memory[static_cast<std::size_t>(physicalAddress) + i] =
            static_cast<std::uint8_t>((value >> (8U * i)) & 0xFFULL);
    }
}

PhysMemory buildFixture() {
    PhysMemory memory(0x40000U, 0U);
    // Root A: standard 4KiB mapping.
    putEntry(memory, kEntryPml4A, 0x2007ULL);
    putEntry(memory, kEntryPdptA, 0x3007ULL);
    putEntry(memory, kEntryPdA, 0x4007ULL);
    putEntry(memory, kEntryPtA, kLeafA);
    // Root B: same VA, another page table, another frame.
    putEntry(memory, kEntryPml4B, 0x6007ULL);
    putEntry(memory, kEntryPdptB, 0x7007ULL);
    putEntry(memory, kEntryPdB, 0x8007ULL);
    putEntry(memory, kEntryPtB, kLeafB);
    // Root C: PDE.PS=1, 2MiB large page.
    putEntry(memory, kEntryPml4C, 0xA007ULL);
    putEntry(memory, kEntryPdptC, 0xB007ULL);
    putEntry(memory, kEntryPdC, kLeaf2M);
    // Root D: PDPTE.PS=1, 1GiB large page.
    putEntry(memory, kEntryPml4D, 0xD007ULL);
    putEntry(memory, kEntryPdptD, kLeaf1G);
    return memory;
}

// Fixture read callback: out-of-bounds reads return nothing, exactly simulating the real driver's 'cannot read this page' scenario.
PhysicalReader makeReader(const PhysMemory& memory) {
    return [&memory](std::uint64_t physAddr, std::uint8_t* out, std::size_t bytes) -> bool {
        const std::uint64_t kSize = static_cast<std::uint64_t>(memory.size());
        if (physAddr >= kSize || static_cast<std::uint64_t>(bytes) > kSize - physAddr) {
            return false;
        }
        for (std::size_t i = 0; i < bytes; ++i) {
            out[i] = memory[static_cast<std::size_t>(physAddr) + i];
        }
        return true;
    };
}

bool noPhysicalAddress(const TranslateResult& result) {
    return !result.physicalAddress.present && !result.pageFrameBase.present;
}

// ---------------------------------------------------------------------------
// M-04: 4KiB multi-level indexing and final physical address.
// ---------------------------------------------------------------------------
void testFourKiBTranslation(ksword_tests::Suite& s) {
    const PhysMemory kMemory = buildFixture();
    const TranslateResult kResult =
        translateVirtualAddress(kVa, kRootA, makeReader(kMemory), makeOptions());

    s.expect(kResult.status == TranslationStatus::kTranslated,
             L"M-04 a fully mapped 4KiB address translates");
    s.expect(kResult.pageSize == PageSizeClass::kSize4KiB, L"M-04 the page size class is 4KiB");
    s.expect(kResult.levels.size() == 4U, L"M-04 all four levels are kept as evidence");
    if (kResult.levels.size() == 4U) {
        s.expect(kResult.levels[0].level == PageTableLevel::kPml4 && kResult.levels[0].index == 1U &&
                     kResult.levels[0].entryPhysicalAddress == kEntryPml4A &&
                     kResult.levels[0].rawValue == 0x2007ULL,
                 L"M-04 PML4E index, entry address and raw value are recorded");
        s.expect(kResult.levels[1].level == PageTableLevel::kPdpt && kResult.levels[1].index == 2U &&
                     kResult.levels[1].entryPhysicalAddress == kEntryPdptA &&
                     kResult.levels[1].rawValue == 0x3007ULL,
                 L"M-04 PDPTE index, entry address and raw value are recorded");
        s.expect(kResult.levels[2].level == PageTableLevel::kPd && kResult.levels[2].index == 3U &&
                     kResult.levels[2].entryPhysicalAddress == kEntryPdA &&
                     kResult.levels[2].rawValue == 0x4007ULL,
                 L"M-04 PDE index, entry address and raw value are recorded");
        s.expect(kResult.levels[3].level == PageTableLevel::kPt && kResult.levels[3].index == 4U &&
                     kResult.levels[3].entryPhysicalAddress == kEntryPtA &&
                     kResult.levels[3].rawValue == kLeafA,
                 L"M-04 PTE index, entry address and raw value are recorded");
    }
    s.expect(kResult.physicalAddress == OptionalU64::of(kExpectedPaA),
             L"M-04 the 4KiB physical address matches the hand-computed value");
    s.expect(kResult.pageOffset == OptionalU64::of(0x678ULL),
             L"M-04 the 4KiB page offset is 12 bits wide");
    s.expect(kResult.permissions.writable && kResult.permissions.userAccessible &&
                 !kResult.permissions.executeDisable,
             L"M-04 effective permissions are merged across levels");
    // The criterion must be verifiable: the result must specify which MAXPHYADDR was actually used.
    s.expect(kResult.effectiveMaxPhysAddrBits == OptionalU64::of(kMaxPhys),
             L"M-04 the MAXPHYADDR that was actually in effect travels with the result");
}

// ---------------------------------------------------------------------------
// M-04: Offset bit width for large pages, and the 1GiB hardware capability prerequisite.
// ---------------------------------------------------------------------------
void testLargePages(ksword_tests::Suite& s) {
    const PhysMemory kMemory = buildFixture();
    const PhysicalReader kReader = makeReader(kMemory);

    // 2MiB pages require no additional CPUID prerequisites under IA-32e; default options suffice.
    const TranslateResult kTwoMiB = translateVirtualAddress(kVa, kRootC, kReader, makeOptions());
    s.expect(kTwoMiB.status == TranslationStatus::kTranslated && kTwoMiB.levels.size() == 3U,
             L"M-04 a PDE with PS=1 stops the walk after three levels");
    s.expect(kTwoMiB.pageSize == PageSizeClass::kSize2MiB,
             L"M-04 the 2MiB page size class is reported");
    s.expect(!kTwoMiB.levels.empty() && kTwoMiB.levels.back().largePage,
             L"M-04 the PDE is flagged as a large page");
    s.expect(kTwoMiB.pageOffset == OptionalU64::of(0x4678ULL),
             L"M-04 the 2MiB page offset is 21 bits wide");
    s.expect(kTwoMiB.physicalAddress == OptionalU64::of(kExpectedPa2M),
             L"M-04 the 2MiB physical address matches the hand-computed value");

    // 1GiB requires CPUID.80000001H:EDX.Page1GB. Only allow translation to physical addresses after confirming support.
    const TranslateResult kOneGiB = translateVirtualAddress(kVa, kRootD, kReader, makeOptions1GiB());
    s.expect(kOneGiB.status == TranslationStatus::kTranslated && kOneGiB.levels.size() == 2U,
             L"M-04 a PDPTE with PS=1 stops the walk after two levels when 1GiB pages are supported");
    s.expect(kOneGiB.pageSize == PageSizeClass::kSize1GiB,
             L"M-04 the 1GiB page size class is reported");
    s.expect(kOneGiB.pageOffset == OptionalU64::of(0x604678ULL),
             L"M-04 the 1GiB page offset is 30 bits wide");
    s.expect(kOneGiB.physicalAddress == OptionalU64::of(kExpectedPa1G),
             L"M-04 the 1GiB physical address matches the hand-computed value");
    s.expect(kOneGiB.supports1GiBPages,
             L"M-04 the result records that it interpreted PDPTE.bit7 as a 1GiB page size bit");

    // Negative case: The same fixture runs on a machine that does not support 1GiB pages. In this case, bit7 of the PDPTE is a reserved
    // bit; setting this bit triggers a reserved-bit #PF on hardware. Therefore, the result must be ReservedBitSet rather than a
    // successful translation; otherwise, we would fabricate a physical address for a table entry that hardware fundamentally rejects.
    const TranslateResult kNoOneGiB = translateVirtualAddress(kVa, kRootD, kReader, makeOptions());
    s.expect(kNoOneGiB.status == TranslationStatus::kReservedBitSet &&
                 kNoOneGiB.failedLevel == PageTableLevel::kPdpt,
             L"M-04 without the Page1GB capability a PDPTE with PS=1 is a reserved-bit violation");
    s.expect(kNoOneGiB.reservedBitsSet == (1ULL << 7U),
             L"M-04 the offending bit is exactly PDPTE bit7, the PS bit that is reserved here");
    s.expect(noPhysicalAddress(kNoOneGiB),
             L"M-04 a 1GiB entry on a machine without 1GiB pages never yields a physical address");
}

// ---------------------------------------------------------------------------
// M-04: Non-canonical, page fault, or unsupported mode
// ---------------------------------------------------------------------------
void testRejectedAddresses(ksword_tests::Suite& s) {
    PhysMemory memory = buildFixture();
    const PhysicalReader kReader = makeReader(memory);

    const TranslateResult kNonCanonical =
        translateVirtualAddress(0x0000800000000000ULL, kRootA, kReader, makeOptions());
    s.expect(kNonCanonical.status == TranslationStatus::kNotCanonical,
             L"M-04 a non-canonical address is rejected before any table read");
    s.expect(kNonCanonical.levels.empty() && noPhysicalAddress(kNonCanonical),
             L"M-04 a rejected address produces no physical address at all");

    // 0xFFFF800000000000 is a valid kernel-side canonical address; PML4 index 256 is an empty entry in the fixture.
    const TranslateResult kEmptyEntry =
        translateVirtualAddress(0xFFFF800000000000ULL, kRootA, kReader, makeOptions());
    s.expect(kEmptyEntry.status == TranslationStatus::kEntryNotPresent &&
                 kEmptyEntry.failedLevel == PageTableLevel::kPml4,
             L"M-04 a canonical kernel address with an empty PML4E stops at PML4");
    s.expect(noPhysicalAddress(kEmptyEntry),
             L"M-04 a missing PML4E never yields a physical address");

    // Clear the present bit of PD-A: a page fault must stop at the PDE level.
    putEntry(memory, kEntryPdA, 0x4007ULL & ~1ULL);
    const TranslateResult kMissingPde =
        translateVirtualAddress(kVa, kRootA, makeReader(memory), makeOptions());
    s.expect(kMissingPde.status == TranslationStatus::kEntryNotPresent &&
                 kMissingPde.failedLevel == PageTableLevel::kPd,
             L"M-04 a PDE with P=0 reports EntryNotPresent at the PDE level");
    s.expect(kMissingPde.levels.size() == 3U && noPhysicalAddress(kMissingPde),
             L"M-04 a missing PDE keeps three levels of evidence and no physical address");

    TranslateOptions unsupported = makeOptions();
    unsupported.mode = PagingMode::kUnsupported;
    const TranslateResult kLa57 =
        translateVirtualAddress(kVa, kRootA, makeReader(memory), unsupported);
    s.expect(kLa57.status == TranslationStatus::kUnsupportedMode && noPhysicalAddress(kLa57),
             L"M-04 an unsupported paging mode is refused instead of guessed");

    // Root falls outside the fixture: the first layer cannot be read, and the PML4E address and index remain preserved.
    const TranslateResult kReadFail =
        translateVirtualAddress(kVa, 0x100000ULL, makeReader(memory), makeOptions());
    s.expect(kReadFail.status == TranslationStatus::kPhysicalReadFailed &&
                 kReadFail.failedLevel == PageTableLevel::kPml4,
             L"M-04 an unreadable table page reports PhysicalReadFailed at that level");
    s.expect(kReadFail.levels.size() == 1U && !kReadFail.levels[0].read &&
                 kReadFail.levels[0].entryPhysicalAddress == 0x100008ULL,
             L"M-04 the unreadable level still records its entry address and index");
    s.expect(noPhysicalAddress(kReadFail),
             L"M-04 a read failure never yields a physical address");
}

// ---------------------------------------------------------------------------
// M-04: Reserved bit anomaly
// ---------------------------------------------------------------------------
void testReservedBits(ksword_tests::Suite& s) {
    // bit13 of the 2MiB entry is reserved (bits 13..20 must be 0).
    PhysMemory twoMiB = buildFixture();
    putEntry(twoMiB, kEntryPdC, kLeaf2M | (1ULL << 13U));
    const TranslateResult kBad2M =
        translateVirtualAddress(kVa, kRootC, makeReader(twoMiB), makeOptions());
    s.expect(kBad2M.status == TranslationStatus::kReservedBitSet &&
                 kBad2M.failedLevel == PageTableLevel::kPd,
             L"M-04 a reserved low bit in a 2MiB PDE is reported at the PDE level");
    s.expect(kBad2M.reservedBitsSet == (1ULL << 13U),
             L"M-04 the offending reserved bits are reported exactly");
    s.expect(noPhysicalAddress(kBad2M),
             L"M-04 a reserved-bit violation never yields a physical address");

    // bit20 of a 1GiB entry also lies in the bit13..29 reserved range. This check matters only when the
    // machine **supports** 1GiB pages; otherwise bit7 is already rejected as reserved (see testLargePages).
    PhysMemory oneGiB = buildFixture();
    putEntry(oneGiB, kEntryPdptD, kLeaf1G | (1ULL << 20U));
    const TranslateResult kBad1G =
        translateVirtualAddress(kVa, kRootD, makeReader(oneGiB), makeOptions1GiB());
    s.expect(kBad1G.status == TranslationStatus::kReservedBitSet &&
                 kBad1G.failedLevel == PageTableLevel::kPdpt &&
                 kBad1G.reservedBitsSet == (1ULL << 20U),
             L"M-04 a reserved low bit in a 1GiB PDPTE is reported at the PDPTE level");
    s.expect(noPhysicalAddress(kBad1G),
             L"M-04 a bad 1GiB entry produces no physical address");

    // When MAXPHYADDR=40, bit44 is a reserved bit beyond the physical address width.
    TranslateOptions narrow = makeOptions();
    narrow.maxPhysAddrBits = 40U;
    const PhysMemory kClean = buildFixture();
    const TranslateResult kStillOk = translateVirtualAddress(kVa, kRootA, makeReader(kClean), narrow);
    s.expect(kStillOk.status == TranslationStatus::kTranslated &&
                 kStillOk.physicalAddress == OptionalU64::of(kExpectedPaA),
             L"M-04 a narrow MAXPHYADDR does not reject legitimate entries");

    PhysMemory wide = buildFixture();
    putEntry(wide, kEntryPtA, kLeafA | (1ULL << 44U));
    const TranslateResult kTooWide = translateVirtualAddress(kVa, kRootA, makeReader(wide), narrow);
    s.expect(kTooWide.status == TranslationStatus::kReservedBitSet &&
                 kTooWide.failedLevel == PageTableLevel::kPt &&
                 kTooWide.reservedBitsSet == (1ULL << 44U),
             L"M-04 an address bit above MAXPHYADDR is a reserved-bit violation");
    s.expect(noPhysicalAddress(kTooWide),
             L"M-04 an over-wide physical address is never emitted");
    s.expect(kTooWide.effectiveMaxPhysAddrBits == OptionalU64::of(40U),
             L"M-04 the MAXPHYADDR that produced the rejection is carried in the result");

    // The same bit is not reserved when MAXPHYADDR=52 — the criterion depends on parameters, not hardcoded values.
    TranslateOptions archMax = makeOptions();
    archMax.maxPhysAddrBits = 52U;
    const TranslateResult kWideOk = translateVirtualAddress(kVa, kRootA, makeReader(wide), archMax);
    s.expect(kWideOk.status == TranslationStatus::kTranslated,
             L"M-04 the same bit is legal when MAXPHYADDR allows it");

    // MAXPHYADDR is not provided (default 0): this check is ineffective, and the result must **explicitly state** that it was
    // ineffective. Previously, when the default was 52, it was also ineffective but undetectable—this was a silent-failing assertion.
    const TranslateResult kNoMaxPhys = translateVirtualAddress(kVa, kRootA, makeReader(wide));
    s.expect(kNoMaxPhys.status == TranslationStatus::kTranslated,
             L"M-04 an unsupplied MAXPHYADDR reserves no bits");
    s.expect(!kNoMaxPhys.effectiveMaxPhysAddrBits.present,
             L"M-04 an unsupplied MAXPHYADDR is reported as an inactive check, not as a silent pass");
    s.expect(!kNoMaxPhys.supports1GiBPages,
             L"M-04 the 1GiB capability defaults to absent, so PDPTE.bit7 defaults to reserved");
}

// ---------------------------------------------------------------------------
// M-05: Decoding software PTEs for non-resident entries.
// ---------------------------------------------------------------------------
void testSoftwarePte(ksword_tests::Suite& s) {
    struct Case final {
        std::uint64_t entry;
        SoftwarePteKind expected;
        const wchar_t* label;
    };
    // bit0=0 indicates non-resident; bit11=Transition, bit10=Prototype. The rest are classified based on whether
    // PageFileHigh (bit32..63) is non-zero: either "truly in the page file" or "never-touched demand-zero".
    const Case kCases[] = {
        {0x00010800ULL, SoftwarePteKind::kTransition, L"M-05 a transition PTE is recognised"},
        {0x0000ABCD00000400ULL, SoftwarePteKind::kPrototype, L"M-05 a prototype PTE is recognised"},
        {0x0000123400000006ULL, SoftwarePteKind::kPageFile, L"M-05 a page-file PTE is recognised"},
        {0x0000000000000020ULL, SoftwarePteKind::kDemandZero,
         L"M-05 a software PTE with only protection bits set is demand-zero, not a page-file PTE"},
        {0x0000000000000000ULL, SoftwarePteKind::kZero, L"M-05 an all-zero PTE is not a page-file PTE"},
    };

    for (const Case& item : kCases) {
        PhysMemory memory = buildFixture();
        putEntry(memory, kEntryPtA, item.entry);
        const TranslateResult kResult =
            translateVirtualAddress(kVa, kRootA, makeReader(memory), makeOptions());
        s.expect(kResult.status == TranslationStatus::kEntryNotPresent &&
                     kResult.failedLevel == PageTableLevel::kPt && kResult.softwarePteDecoded &&
                     kResult.softwarePte.kind == item.expected,
                 item.label);
        s.expect(noPhysicalAddress(kResult),
                 L"M-05 a non-resident PTE never yields a physical address");
    }

    const SoftwarePteDecode kPageFile = decodeSoftwarePte(0x0000123400000006ULL);
    s.expect(kPageFile.pageFileNumber == OptionalU64::of(3ULL),
             L"M-05 the page file number is decoded from bits 1..4");
    s.expect(kPageFile.pageFileOffset == OptionalU64::of(0x1234ULL),
             L"M-05 the page file offset is decoded from bits 32..63");

    // Negative case: entry=0x20 sets only the Protection field (bit5..9) of MMPTE_SOFTWARE; PageFileHigh
    // (bit32..63) is 0. This represents a committed page that has never been touched and has no location
    // in the paging file. Classifying it as a PageFile entry and filling present=1 with a value=0 number
    // and offset would fabricate a paging file location, which is explicitly prohibited by M-05.
    const SoftwarePteDecode kDemandZero = decodeSoftwarePte(0x20ULL);
    s.expect(kDemandZero.kind == SoftwarePteKind::kDemandZero,
             L"M-05 an entry whose PageFileHigh is zero is classified as demand-zero");
    s.expect(!kDemandZero.pageFileNumber.present && !kDemandZero.pageFileOffset.present,
             L"M-05 a demand-zero PTE fabricates neither a page file number nor an offset");
    s.expect(!kDemandZero.transitionBit && !kDemandZero.prototypeBit,
             L"M-05 the demand-zero classification is not driven by the transition or prototype bit");

    const SoftwarePteDecode kTransition = decodeSoftwarePte(0x00010800ULL);
    s.expect(kTransition.transitionBit && !kTransition.prototypeBit,
             L"M-05 the transition bit is reported separately from the classification");
    s.expect(!kTransition.pageFileNumber.present && !kTransition.pageFileOffset.present,
             L"M-05 a transition PTE carries no page file location either");

    // Two mutually exclusive encoding bits are set simultaneously: do not force a classification.
    const SoftwarePteDecode kAmbiguous = decodeSoftwarePte(0x0000000000000C00ULL);
    s.expect(kAmbiguous.kind == SoftwarePteKind::kUnknown,
             L"M-05 an unrecognised software PTE encoding stays Unknown");
}

// ---------------------------------------------------------------------------
// M-03: Translation context
// ---------------------------------------------------------------------------
ProcessInstanceId makeProcess(std::uint64_t pid, std::uint64_t createTime) {
    ProcessInstanceId id;
    id.bootId = "boot-M";
    id.pid = OptionalU64::of(pid);
    id.createTime100ns = OptionalU64::of(createTime);
    id.imageName = "target.exe";
    return id;
}

TranslationContext makeContext(const ProcessInstanceId& process, std::uint64_t root) {
    TranslationContext context;
    context.process = process;
    context.pageTableRootPhysical = OptionalU64::of(root);
    context.observedUtc100ns = OptionalU64::of(133000000000000000ULL);
    context.mode = PagingMode::kLongMode4Level;
    context.rootSource = "KPROCESS.DirectoryTableBase";
    return context;
}

void testTranslationContext(ksword_tests::Suite& s) {
    const PhysMemory kMemory = buildFixture();
    const PhysicalReader kReader = makeReader(kMemory);

    const ProcessInstanceId kProcA = makeProcess(4321ULL, 133000000000000000ULL);
    const ProcessInstanceId kProcB = makeProcess(5555ULL, 133000000000900000ULL);
    const TranslationContext kCtxA = makeContext(kProcA, kRootA);
    const TranslationContext kCtxB = makeContext(kProcB, kRootB);

    LiveResolution liveA;
    liveA.found = true;
    liveA.liveProcess = kProcA;
    LiveResolution liveB;
    liveB.found = true;
    liveB.liveProcess = kProcB;

    const ContextValidity kValidA = checkContextUsable(kCtxA, liveA);
    const ContextValidity kValidB = checkContextUsable(kCtxB, liveB);
    s.expect(kValidA == ContextValidity::kUsable && kValidB == ContextValidity::kUsable,
             L"M-03 a live, identity-confirmed context is usable");

    TranslateResult resultA;
    TranslateResult resultB;
    const bool kOkA = translateUsingContext(kCtxA, kValidA, kVa, kReader, makeOptions(), resultA);
    const bool kOkB = translateUsingContext(kCtxB, kValidB, kVa, kReader, makeOptions(), resultB);
    s.expect(kOkA && kOkB, L"M-03 both usable contexts are allowed to translate");
    s.expect(resultA.physicalAddress == OptionalU64::of(kExpectedPaA) &&
                 resultB.physicalAddress == OptionalU64::of(kExpectedPaB),
             L"M-03 the same VA under two page table roots yields two different physical addresses");
    s.expect(resultA.physicalAddress != resultB.physicalAddress,
             L"M-03 translation contexts are not mixed up between processes");

    // Process exited: context is invalid and can only be displayed as historical observation.
    LiveResolution exited;
    exited.found = false;
    const ContextValidity kAfterExit = checkContextUsable(kCtxA, exited);
    s.expect(kAfterExit == ContextValidity::kRejectProcessExited,
             L"M-03 a context whose process exited is rejected");
    s.expect(!contextAllowsLiveReuse(kAfterExit),
             L"M-03 an invalid context may not be reused for a live translation");
    TranslateResult stale;
    const bool kRefused = translateUsingContext(kCtxA, kAfterExit, kVa, kReader, makeOptions(), stale);
    s.expect(!kRefused && !stale.physicalAddress.present,
             L"M-03 a refused translation produces no physical address");
    // The rejection reason must be the actual reason. Previously, the result was left at the default value, and the default
    // status was UnsupportedMode, causing 'Process exited' to be rendered by the UI as 'Paging mode not supported'.
    s.expect(stale.status == TranslationStatus::kContextRejected,
             L"M-03 a context refusal is its own status, not the unsupported-paging-mode default");
    s.expect(stale.contextRefusal == ContextValidity::kRejectProcessExited,
             L"M-03 the refusal reason handed to the UI is exactly RejectProcessExited");

    // Another rejection reason is also propagated as-is, allowing the two rejection types to be distinguished in the result.
    TranslationContext noRootCtx = kCtxA;
    noRootCtx.pageTableRootPhysical = OptionalU64::unset();
    const ContextValidity kNoRootValidity = checkContextUsable(noRootCtx, liveA);
    TranslateResult noRootResult;
    const bool kNoRootRefused =
        translateUsingContext(noRootCtx, kNoRootValidity, kVa, kReader, makeOptions(), noRootResult);
    s.expect(!kNoRootRefused &&
                 noRootResult.contextRefusal == ContextValidity::kRejectNoPageTableRoot &&
                 noRootResult.contextRefusal != stale.contextRefusal,
             L"M-03 two different refusal reasons stay distinguishable in the result");

    // PID reuse: Same PID, different creation time.
    LiveResolution reused;
    reused.found = true;
    reused.liveProcess = makeProcess(4321ULL, 133000000000777000ULL);
    s.expect(checkContextUsable(kCtxA, reused) == ContextValidity::kRejectIdentityMismatch,
             L"M-03 a reused PID is an identity mismatch, not the same context");

    // Insufficient identity: the saved creation time is missing.
    TranslationContext weak = kCtxA;
    weak.process.createTime100ns = OptionalU64::unset();
    LiveResolution weakLive;
    weakLive.found = true;
    weakLive.liveProcess = kProcA;
    weakLive.liveProcess.createTime100ns = OptionalU64::unset();
    s.expect(checkContextUsable(weak, weakLive) == ContextValidity::kRejectIdentityUnverifiable,
             L"M-03 an unverifiable identity is not silently upgraded to usable");

    s.expect(kNoRootValidity == ContextValidity::kRejectNoPageTableRoot,
             L"M-03 a context without a page table root is rejected");

    TranslationContext badMode = kCtxA;
    badMode.mode = PagingMode::kUnsupported;
    s.expect(checkContextUsable(badMode, liveA) == ContextValidity::kRejectUnsupportedMode,
             L"M-03 a context with an unsupported paging mode is rejected");
}

// ---------------------------------------------------------------------------
// M-02: Partial read across page boundaries.
// ---------------------------------------------------------------------------
void testPartialRead(ksword_tests::Suite& s) {
    // 0x1000..0x1FFF is readable; from 0x2000 onward, it is completely unreadable. Byte values are fixed to the low 8 bits of the address.
    // Return the driver's own NTSTATUS when the read fails (F-05).
    const ChunkReader kReader = [](std::uint64_t address, std::uint8_t* out, std::size_t bytes,
                                  ChunkReadResult& outcome) {
        const std::uint64_t kAvailable = (address < 0x2000ULL) ? (0x2000ULL - address) : 0ULL;
        const std::size_t kCount = (static_cast<std::uint64_t>(bytes) < kAvailable)
                                      ? bytes
                                      : static_cast<std::size_t>(kAvailable);
        for (std::size_t i = 0; i < kCount; ++i) {
            out[i] = static_cast<std::uint8_t>((address + i) & 0xFFULL);
        }
        outcome.copied = kCount;
        if (kCount == bytes) {
            outcome.status = CollectionStatus::kSuccess;
            return;
        }
        outcome.status = (kCount == 0U) ? CollectionStatus::kAccessDenied : CollectionStatus::kPartial;
        outcome.nativeCodeDomain = "NTSTATUS";
        outcome.nativeCode = OptionalU64::of((kCount == 0U) ? 0xC0000022ULL : 0x8000000DULL);
        outcome.message = (kCount == 0U) ? "STATUS_ACCESS_DENIED" : "STATUS_PARTIAL_COPY";
    };

    BoundedReadRequest request;
    request.requested.begin = 0x1FF0ULL;
    request.requested.length = 0x20ULL;   // Note: Crossed the 0x2000 page boundary.
    request.budget.maxBytes = OptionalU64::of(0x1000ULL);
    request.chunkSize = 0x1000ULL;

    const BoundedReadResult kResult = readRangeBounded(request, kReader);
    s.expect(kResult.validation == RangeValidation::kOk &&
                 kResult.rejection == BoundedReadRejection::kNone &&
                 kResult.stop == BudgetStop::kContinue,
             L"M-02 a legal cross-page range runs to completion without hitting a budget");
    s.expect(kResult.span.outcome.status == CollectionStatus::kPartial,
             L"M-02 a read with holes is Partial, never Success");
    s.expect(kResult.span.presentCount() == 16ULL,
             L"M-02 exactly the readable half of the range is marked present");

    bool firstPageExact = true;
    for (std::uint64_t address = 0x1FF0ULL; address < 0x2000ULL; ++address) {
        std::uint8_t value = 0U;
        if (!byteAt(kResult.span, address, value) ||
            value != static_cast<std::uint8_t>(address & 0xFFULL)) {
            firstPageExact = false;
        }
    }
    s.expect(firstPageExact, L"M-02 every byte of the readable page matches the source exactly");

    bool secondPageIsHole = true;
    for (std::uint64_t address = 0x2000ULL; address < 0x2010ULL; ++address) {
        std::uint8_t value = 0U;
        if (byteAt(kResult.span, address, value)) {
            secondPageIsHole = false;
        }
    }
    s.expect(secondPageIsHole, L"M-02 the unreadable page stays a hole and yields no bytes");

    const std::vector<AddressRange> kHoles = describeHoles(kResult.span);
    s.expect(kHoles.size() == 1U && kHoles[0].begin == 0x2000ULL && kHoles[0].length == 0x10ULL,
             L"M-02 the hole range is reported exactly");
    s.expect(kResult.coverage.succeeded == 16ULL && kResult.coverage.failed == 16ULL &&
                 kResult.coverage.truncated == 0ULL,
             L"M-02 the coverage account separates read bytes from unreadable bytes");
    s.expect(!kResult.coverage.fullyCovered(),
             L"M-02 a range with holes is never reported as fully covered");
    s.expect(kResult.span.outcome.nativeCode == OptionalU64::of(0xC0000022ULL) &&
                 kResult.span.outcome.nativeCodeDomain == "NTSTATUS" &&
                 kResult.span.outcome.message == "STATUS_ACCESS_DENIED",
             L"F-05 the first underlying failure's own status code and text survive into the result");

    // Only fully readable ranges are allowed to succeed.
    BoundedReadRequest whole = request;
    whole.requested.begin = 0x1000ULL;
    whole.requested.length = 0x10ULL;
    const BoundedReadResult kFull = readRangeBounded(whole, kReader);
    s.expect(kFull.span.outcome.status == CollectionStatus::kSuccess && !kFull.span.hasHole() &&
                 describeHoles(kFull.span).empty(),
             L"M-02 a fully readable range is Success with no holes");
    s.expect(kFull.coverage.fullyCovered(),
             L"M-02 a fully readable range reports full coverage");
    s.expect(!kFull.span.outcome.nativeCode.present,
             L"F-05 a fully successful read leaves the native code unset instead of writing 0");

    // M-02: The most common path in real drivers is 'the first half of a block is copied, but the second half is not'
    // (0 < copied < length). The two test cases above either read fully or read zero, so they do not trigger this path.
    // When chunkSize=0x4000, 0x1000 % 0x4000 = 0x1000, so the entire request falls within the same block:
    // The callback was requested for 0x1010 bytes, but it could only copy the first 0x1000 bytes (reading from 0x2000 onwards fails).
    BoundedReadRequest straddling;
    straddling.requested.begin = 0x1000ULL;
    straddling.requested.length = 0x1010ULL;
    straddling.chunkSize = 0x4000ULL;
    straddling.budget.maxItems = OptionalU64::of(4ULL);
    int straddleCalls = 0;
    std::size_t straddleAsked = 0U;
    const ChunkReader kStraddleReader = [&straddleCalls, &straddleAsked](
                                           std::uint64_t address, std::uint8_t* out,
                                           std::size_t bytes, ChunkReadResult& outcome) {
        ++straddleCalls;
        straddleAsked = bytes;
        const std::uint64_t kAvailable = (address < 0x2000ULL) ? (0x2000ULL - address) : 0ULL;
        const std::size_t kCount = (static_cast<std::uint64_t>(bytes) < kAvailable)
                                      ? bytes
                                      : static_cast<std::size_t>(kAvailable);
        for (std::size_t i = 0; i < kCount; ++i) {
            out[i] = static_cast<std::uint8_t>((address + i) & 0xFFULL);
        }
        outcome.copied = kCount;
        outcome.status = (kCount == bytes) ? CollectionStatus::kSuccess : CollectionStatus::kPartial;
        if (kCount < bytes) {
            outcome.nativeCodeDomain = "NTSTATUS";
            outcome.nativeCode = OptionalU64::of(0x8000000DULL);  // STATUS_PARTIAL_COPY
            outcome.message = "STATUS_PARTIAL_COPY";
        }
    };
    const BoundedReadResult kStraddled = readRangeBounded(straddling, kStraddleReader);
    s.expect(straddleCalls == 1 && straddleAsked == static_cast<std::size_t>(0x1010),
             L"M-02 the whole request lands in one chunk, so the reader sees a single 0x1010-byte call");
    s.expect(kStraddled.span.presentCount() == 0x1000ULL,
             L"M-02 a chunk reporting 0 < copied < length marks exactly the copied bytes present");

    bool straddlePrefixExact = true;
    for (std::uint64_t address = 0x1000ULL; address < 0x2000ULL; ++address) {
        std::uint8_t value = 0U;
        if (!byteAt(kStraddled.span, address, value) ||
            value != static_cast<std::uint8_t>(address & 0xFFULL)) {
            straddlePrefixExact = false;
        }
    }
    s.expect(straddlePrefixExact,
             L"M-02 the copied prefix of a partially copied chunk is byte-exact");
    bool straddleTailIsHole = true;
    for (std::uint64_t address = 0x2000ULL; address < 0x2010ULL; ++address) {
        std::uint8_t value = 0U;
        if (byteAt(kStraddled.span, address, value)) {
            straddleTailIsHole = false;
        }
    }
    s.expect(straddleTailIsHole,
             L"M-02 the uncopied tail of a partially copied chunk stays a hole");
    const std::vector<AddressRange> kStraddleHoles = describeHoles(kStraddled.span);
    s.expect(kStraddleHoles.size() == 1U && kStraddleHoles[0].begin == 0x2000ULL &&
                 kStraddleHoles[0].length == 0x10ULL,
             L"M-02 DescribeHoles reports the uncopied tail of the chunk as exactly [0x2000,0x2010)");
    s.expect(kStraddled.span.outcome.status == CollectionStatus::kPartial &&
                 kStraddled.span.outcome.nativeCode == OptionalU64::of(0x8000000DULL),
             L"M-02 a partial copy is Partial and keeps the driver's own partial-copy status");
    s.expect(kStraddled.coverage.succeeded == 0x1000ULL && kStraddled.coverage.failed == 0x10ULL &&
                 kStraddled.coverage.truncated == 0ULL,
             L"M-02 a partial copy is accounted as copied bytes plus a hole, not as truncation");
}

// ---------------------------------------------------------------------------
// M-02 / M-05: Merge multiple reads
// ---------------------------------------------------------------------------

// Two collection timestamps, 5 minutes apart (3e9 units of 100ns). Since the M-05 criterion is based on
// timestamps, the fixture must be able to generate inputs for both "same timestamp" and "different timestamps".
constexpr std::uint64_t kObserveT0 = 133000000000000000ULL;
constexpr std::uint64_t kObserveT1 = 133000003000000000ULL;

ReadSpan makeFilledSpan(std::uint64_t begin,
                        std::size_t length,
                        std::uint8_t seed,
                        const OptionalU64& observedUtc100ns) {
    AddressRange range;
    range.begin = begin;
    range.length = static_cast<std::uint64_t>(length);
    ReadSpan span = makeEmptyReadSpan(range);
    std::vector<std::uint8_t> data(length, 0U);
    for (std::size_t i = 0; i < length; ++i) {
        data[i] = static_cast<std::uint8_t>(seed + static_cast<std::uint8_t>(i));
    }
    (void)applyReadChunk(span, begin, data.data(), data.size());
    span.outcome.status = CollectionStatus::kSuccess;
    span.observedUtc100ns = observedUtc100ns;
    return span;
}

void testMergeReadSpans(ksword_tests::Suite& s) {
    const OptionalU64 kT0 = OptionalU64::of(kObserveT0);
    const OptionalU64 kT1 = OptionalU64::of(kObserveT1);

    const ReadSpan kFirst = makeFilledSpan(0x1000ULL, 16U, 0U, kT0);
    const ReadSpan kSecond = makeFilledSpan(0x1010ULL, 16U, 0x80U, kT0);
    const MergedReadSpan kMerged = mergeReadSpans({kFirst, kSecond});
    s.expect(kMerged.span.range.begin == 0x1000ULL && kMerged.span.range.length == 32ULL,
             L"M-02 adjacent spans merge into one contiguous range");
    s.expect(kMerged.timing == MergeObservationTiming::kSingleObservation &&
                 kMerged.conflictingRanges.empty() &&
                 kMerged.span.outcome.status == CollectionStatus::kSuccess,
             L"M-02 a gap-free merge of spans that carry the same recorded instant is Success");
    std::uint8_t value = 0U;
    s.expect(byteAt(kMerged.span, 0x1010ULL, value) && value == 0x80U,
             L"M-02 the merged buffer keeps each span's own bytes");
    s.expect(kMerged.byteObservedUtc100ns.size() == 32U && kMerged.byteObservedUtc100ns[0] == kT0 &&
                 kMerged.byteObservedUtc100ns[31] == kT0,
             L"M-05 every merged byte keeps the instant its source span was observed at");

    // M-05 passes if "two observations at different times are not wrapped into a single atomic snapshot". The criterion must be the collection
    // timestamp, not the byte values: even if the same data is treated as a second observation 5 minutes later (with identical bytes), it must
    // still be downgraded. Identical bytes only indicate the data wasn't modified, not that the two reads occurred at the same time.
    const ReadSpan kSameBytesLater = makeFilledSpan(0x1000ULL, 16U, 0U, kT1);
    const MergedReadSpan kTwoTimes = mergeReadSpans({kFirst, kSameBytesLater});
    s.expect(kTwoTimes.timing == MergeObservationTiming::kMultipleObservations,
             L"M-05 two spans carrying different observation instants are flagged as multi-time");
    s.expect(kTwoTimes.span.outcome.status != CollectionStatus::kSuccess,
             L"M-05 a merge spanning two instants is never Success, even when the bytes are identical");
    s.expect(kTwoTimes.conflictingRanges.empty(),
             L"M-05 identical bytes yield no byte conflict - the downgrade comes from the timing alone");
    s.expect(kTwoTimes.byteObservedUtc100ns.size() == 16U &&
                 kTwoTimes.byteObservedUtc100ns[0] == kT1,
             L"M-05 the later observation's instant is kept for the bytes it supplied");
    s.expect(!kTwoTimes.span.observedUtc100ns.present,
             L"M-05 a multi-time merge has no single observation instant to claim");

    // Timestamps not recorded: cannot prove simultaneity across multiple input segments; Success is disallowed.
    const ReadSpan kUntimedA = makeFilledSpan(0x1000ULL, 16U, 0U, OptionalU64::unset());
    const ReadSpan kUntimedB = makeFilledSpan(0x1010ULL, 16U, 0x80U, OptionalU64::unset());
    const MergedReadSpan kUntimed = mergeReadSpans({kUntimedA, kUntimedB});
    s.expect(kUntimed.timing == MergeObservationTiming::kObservationTimeUnknown &&
                 kUntimed.span.outcome.status != CollectionStatus::kSuccess,
             L"M-05 spans without a recorded instant cannot be claimed to be one atomic snapshot");

    // Reading different values at the same address twice: report both reasons—different timestamps and content conflict.
    ReadSpan conflicting = makeFilledSpan(0x1000ULL, 16U, 0U, kT1);
    conflicting.bytes[5] = 0xAAU;
    const MergedReadSpan kConflicted = mergeReadSpans({kFirst, conflicting});
    s.expect(kConflicted.conflictingRanges.size() == 1U &&
                 kConflicted.conflictingRanges[0].begin == 0x1005ULL &&
                 kConflicted.conflictingRanges[0].length == 1ULL,
             L"M-02 a byte that changed between reads is reported as a conflicting range");
    s.expect(kConflicted.span.outcome.status == CollectionStatus::kPartial,
             L"M-05 two observations taken at different times are not packaged as one snapshot");

    // BLOCKER negative case: a begin + length overflow of a 64-bit span — consistent() is true, endAddress()
    // is false. It was filtered out in the first pass; the second pass must apply the exact same criteria.
    // Otherwise, base = begin - lowest would calculate an enormous value,
    // causing out-of-bounds reads/writes for present[target] / bytes[target].
    ReadSpan overflowing;
    overflowing.range.begin = 0xFFFFFFFFFFFFFFF0ULL;
    overflowing.range.length = 32ULL;
    overflowing.bytes.assign(32U, 0xEEU);
    overflowing.present.assign(32U, true);
    overflowing.outcome.status = CollectionStatus::kSuccess;
    overflowing.observedUtc100ns = kT0;
    std::uint64_t unusedEnd = 0ULL;
    s.expect(overflowing.consistent() && !overflowing.range.endAddress(unusedEnd),
             L"M-02 the hostile fixture really is self-consistent and really does overflow its end address");

    const MergedReadSpan kGuarded = mergeReadSpans({kFirst, overflowing, kSecond});
    s.expect(kGuarded.span.range.begin == 0x1000ULL && kGuarded.span.range.length == 32ULL,
             L"M-02 an overflowing span is excluded from the merged range instead of widening it");
    s.expect(kGuarded.span.presentCount() == 32ULL,
             L"M-02 the merge still completes over the two well-formed spans");
    bool noStrayBytes = true;
    for (std::uint64_t address = 0x1000ULL; address < 0x1020ULL; ++address) {
        const std::uint64_t kOffset = address - 0x1000ULL;
        // Manual calculation: The first 16 bytes come from the seed=0 segment (0x00..0x0F), and the next 16 come from the
        // seed=0x80 segment (0x80..0x8F). The excluded overflow segment is filled with 0xEE, which should never appear.
        const std::uint8_t kExpected =
            (kOffset < 16ULL) ? static_cast<std::uint8_t>(kOffset)
                             : static_cast<std::uint8_t>(0x80ULL + (kOffset - 16ULL));
        std::uint8_t byte = 0U;
        if (!byteAt(kGuarded.span, address, byte) || byte != kExpected) {
            noStrayBytes = false;
        }
    }
    s.expect(noStrayBytes,
             L"M-02 not one byte of the excluded overflowing span leaks into the merged buffer");
}

// ---------------------------------------------------------------------------
// M-10: Range validation and scan budget.
// ---------------------------------------------------------------------------
void testScanBudget(ksword_tests::Suite& s) {
    int readerCalls = 0;
    const ChunkReader kCounting = [&readerCalls](std::uint64_t address, std::uint8_t* out,
                                                std::size_t bytes, ChunkReadResult& outcome) {
        ++readerCalls;
        for (std::size_t i = 0; i < bytes; ++i) {
            out[i] = static_cast<std::uint8_t>((address + i) & 0xFFULL);
        }
        outcome.copied = bytes;
        outcome.status = CollectionStatus::kSuccess;
    };

    // Empty range, overflow range, or range outside the approved scope: read zero bytes.
    // All three requests include a budget so that each test case verifies only one thing.
    BoundedReadRequest empty;
    empty.requested.begin = 0x1000ULL;
    empty.requested.length = 0ULL;
    empty.budget.maxBytes = OptionalU64::of(0x1000ULL);
    const BoundedReadResult kEmptyResult = readRangeBounded(empty, kCounting);
    s.expect(kEmptyResult.validation == RangeValidation::kEmptyRange &&
                 kEmptyResult.rejection == BoundedReadRejection::kInvalidRange &&
                 kEmptyResult.span.outcome.status == CollectionStatus::kError,
             L"M-10 an empty range is rejected");

    BoundedReadRequest overflow;
    overflow.requested.begin = 0xFFFFFFFFFFFFFFF0ULL;
    overflow.requested.length = 0x100ULL;
    overflow.budget.maxBytes = OptionalU64::of(0x1000ULL);
    const BoundedReadResult kOverflowResult = readRangeBounded(overflow, kCounting);
    s.expect(kOverflowResult.validation == RangeValidation::kOverflow &&
                 kOverflowResult.rejection == BoundedReadRejection::kInvalidRange &&
                 kOverflowResult.span.outcome.status == CollectionStatus::kError,
             L"M-10 a range that overflows 64 bits is rejected");

    BoundedReadRequest outside;
    outside.requested.begin = 0x1000ULL;
    outside.requested.length = 0x4000ULL;
    outside.approved.begin = 0x1000ULL;
    outside.approved.length = 0x1000ULL;
    outside.budget.maxBytes = OptionalU64::of(0x4000ULL);
    const BoundedReadResult kOutsideResult = readRangeBounded(outside, kCounting);
    s.expect(kOutsideResult.validation == RangeValidation::kExceedsApproved &&
                 kOutsideResult.rejection == BoundedReadRejection::kInvalidRange,
             L"M-10 a range outside the approved window is rejected");

    // M-10: Request with no budget. The check must not only apply when a budget is set; otherwise, a
    // call point that forgets to set a budget could read kMaxReadSpanBytes of kernel memory in one go.
    BoundedReadRequest unbounded;
    unbounded.requested.begin = 0x1000ULL;
    unbounded.requested.length = 0x1000ULL;
    s.expect(!unbounded.budget.bounded(),
             L"M-10 the no-budget fixture really does carry no limit at all");
    const BoundedReadResult kUnboundedResult = readRangeBounded(unbounded, kCounting);
    s.expect(kUnboundedResult.rejection == BoundedReadRejection::kNoBudget &&
                 kUnboundedResult.span.outcome.status == CollectionStatus::kError,
             L"M-10 a request with no budget at all is refused outright");
    s.expect(kUnboundedResult.span.presentCount() == 0ULL &&
                 kUnboundedResult.span.range.length == 0ULL,
             L"M-10 a request with no budget produces no span content whatsoever");

    // M-10: Exceeds the single-span limit. Previously, validation=Ok, stop=Continue, and coverage=0 caused
    // callers to interpret this as 'valid range, budget not hit, completed normally, but with no data'.
    BoundedReadRequest tooBig;
    tooBig.requested.begin = 0x10000ULL;
    tooBig.requested.length = kMaxReadSpanBytes + 1ULL;
    tooBig.budget.maxBytes = OptionalU64::of(kMaxReadSpanBytes + 1ULL);
    const BoundedReadResult kTooBigResult = readRangeBounded(tooBig, kCounting);
    s.expect(kTooBigResult.rejection == BoundedReadRejection::kExceedsMaxSpan &&
                 kTooBigResult.span.outcome.status == CollectionStatus::kError,
             L"M-10 a span above kMaxReadSpanBytes is an explicit refusal, not a quiet empty success");
    s.expect(kTooBigResult.coverage.requestedEnd ==
                     OptionalU64::of(0x10000ULL + kMaxReadSpanBytes + 1ULL) &&
                 kTooBigResult.coverage.truncated == kMaxReadSpanBytes + 1ULL,
             L"F-06 a refused over-sized span still reports the requested end and the whole length as untouched");

    // M-10: Reverse range. AddressRange is expressed as (begin, length); if endAddress() succeeds, end is guaranteed to be >=
    // begin, making this predicate unreachable under that representation—only the entry point accepting 'end' can test it.
    BoundedReadRequest endpointTemplate;
    endpointTemplate.budget.maxBytes = OptionalU64::of(0x1000ULL);
    const BoundedReadResult kReversedResult =
        readRangeBoundedFromEndpoints(0x4000ULL, 0x1000ULL, endpointTemplate, kCounting);
    s.expect(kReversedResult.rejection == BoundedReadRejection::kReversedRange &&
                 kReversedResult.validation == RangeValidation::kReversed,
             L"M-10 an end < begin range is refused as a reversed range");
    s.expect(kReversedResult.span.presentCount() == 0ULL &&
                 kReversedResult.span.outcome.status == CollectionStatus::kError,
             L"M-10 a reversed range produces no span content");

    s.expect(readerCalls == 0,
             L"M-10 no bytes are read at all for any of the five refusal cases");

    // Same-entry forward test case: proves rejection is not implemented by 'doing nothing' at this entry.
    const BoundedReadResult kForwardResult =
        readRangeBoundedFromEndpoints(0x1000ULL, 0x1010ULL, endpointTemplate, kCounting);
    s.expect(kForwardResult.rejection == BoundedReadRejection::kNone &&
                 kForwardResult.span.range.length == 0x10ULL &&
                 kForwardResult.span.presentCount() == 0x10ULL,
             L"M-10 the (begin,end) entry point reads the whole range when end > begin");

    // Very small byte budget: stop precisely at the upper limit, retaining the completed portion.
    BoundedReadRequest budgeted;
    budgeted.requested.begin = 0x1000ULL;
    budgeted.requested.length = 0x3000ULL;
    budgeted.budget.maxBytes = OptionalU64::of(16ULL);
    budgeted.chunkSize = 0x1000ULL;
    const BoundedReadResult kBudgetResult = readRangeBounded(budgeted, kCounting);
    s.expect(kBudgetResult.stop == BudgetStop::kBytesExhausted,
             L"M-10 the byte budget stops the scan");
    s.expect(kBudgetResult.span.presentCount() == 16ULL,
             L"M-10 the scan stops exactly at the byte budget rather than finishing the chunk");
    s.expect(kBudgetResult.span.outcome.status == CollectionStatus::kPartial &&
                 kBudgetResult.coverage.limitHit &&
                 kBudgetResult.coverage.limit == OptionalU64::of(16ULL),
             L"M-10 hitting a limit yields a partial result with the limit recorded");
    s.expect(kBudgetResult.coverage.truncated == 0x3000ULL - 16ULL &&
                 kBudgetResult.coverage.failed == 0ULL,
             L"M-10 untouched bytes are truncated, not counted as failed reads");

    // Cancelled midway.
    BoundedReadRequest cancelled = budgeted;
    cancelled.budget.maxBytes = OptionalU64::of(0x3000ULL);
    cancelled.cancelRequested = []() -> bool { return true; };
    const BoundedReadResult kCancelResult = readRangeBounded(cancelled, kCounting);
    s.expect(kCancelResult.stop == BudgetStop::kCancelled &&
                 kCancelResult.span.outcome.status == CollectionStatus::kPartial,
             L"M-10 a cancelled scan reports Cancelled and keeps a partial result");
    s.expect(kCancelResult.coverage.truncated == 0x3000ULL,
             L"M-10 a scan cancelled before the first chunk truncates the whole range");

    // Page budget and entry budget: the three upper limits apply independently.
    BoundedReadRequest paged = budgeted;
    paged.budget.maxBytes = OptionalU64::unset();
    paged.budget.maxPages = OptionalU64::of(2ULL);
    const BoundedReadResult kPageResult = readRangeBounded(paged, kCounting);
    s.expect(kPageResult.stop == BudgetStop::kPagesExhausted &&
                 kPageResult.span.presentCount() == 0x2000ULL &&
                 kPageResult.coverage.truncated == 0x1000ULL,
             L"M-10 the page budget stops after the allowed number of pages");

    BoundedReadRequest itemised = budgeted;
    itemised.budget.maxBytes = OptionalU64::unset();
    itemised.budget.maxItems = OptionalU64::of(1ULL);
    const BoundedReadResult kItemResult = readRangeBounded(itemised, kCounting);
    s.expect(kItemResult.stop == BudgetStop::kItemsExhausted &&
                 kItemResult.coverage.truncated == 0x2000ULL,
             L"M-10 the item budget stops after the allowed number of chunks");

    // Time budget.
    BoundedReadRequest timed = budgeted;
    timed.budget.maxBytes = OptionalU64::of(0x3000ULL);
    timed.budget.maxDurationNanos = OptionalU64::of(1000ULL);
    timed.elapsedNanos = []() -> std::uint64_t { return 5000ULL; };
    const BoundedReadResult kTimedResult = readRangeBounded(timed, kCounting);
    s.expect(kTimedResult.stop == BudgetStop::kTimeExhausted,
             L"M-10 the time budget stops the scan");
}

// ---------------------------------------------------------------------------
// F-05: Different read failures must be distinct in the result.
// ---------------------------------------------------------------------------
void testReadFailureCodes(ksword_tests::Suite& s) {
    auto makeFailingReader = [](CollectionStatus status, std::uint64_t code,
                                const char* text) -> ChunkReader {
        return [status, code, text](std::uint64_t, std::uint8_t*, std::size_t,
                                    ChunkReadResult& outcome) {
            outcome.copied = 0U;
            outcome.status = status;
            outcome.nativeCodeDomain = "NTSTATUS";
            outcome.nativeCode = OptionalU64::of(code);
            outcome.message = text;
        };
    };

    BoundedReadRequest failing;
    failing.requested.begin = 0x1000ULL;
    failing.requested.length = 0x1000ULL;
    failing.budget.maxBytes = OptionalU64::of(0x1000ULL);

    // Same range, same byte not read — only the underlying cause differs.
    const BoundedReadResult kDenied = readRangeBounded(
        failing,
        makeFailingReader(CollectionStatus::kAccessDenied, 0xC0000022ULL, "STATUS_ACCESS_DENIED"));
    const BoundedReadResult kTerminating = readRangeBounded(
        failing,
        makeFailingReader(CollectionStatus::kError, 0xC000010AULL, "STATUS_PROCESS_IS_TERMINATING"));

    s.expect(kDenied.span.outcome.status == CollectionStatus::kAccessDenied &&
                 kDenied.span.outcome.nativeCode == OptionalU64::of(0xC0000022ULL) &&
                 kDenied.span.outcome.nativeCodeDomain == "NTSTATUS" &&
                 kDenied.span.outcome.message == "STATUS_ACCESS_DENIED",
             L"F-05 a denied read keeps its own NTSTATUS, its domain and the source's own text");
    s.expect(kTerminating.span.outcome.nativeCode == OptionalU64::of(0xC000010AULL) &&
                 kTerminating.span.outcome.message == "STATUS_PROCESS_IS_TERMINATING",
             L"F-05 a read against an exiting process keeps its own NTSTATUS, not a generic error");
    s.expect(kDenied.span.outcome.nativeCode != kTerminating.span.outcome.nativeCode &&
                 kDenied.span.outcome.status != kTerminating.span.outcome.status &&
                 kDenied.span.outcome.message != kTerminating.span.outcome.message,
             L"F-05 two different underlying failures stay distinguishable in the result");
    s.expect(kDenied.span.presentCount() == 0ULL && kTerminating.span.presentCount() == 0ULL,
             L"M-02 a read that copied nothing marks nothing present");

    // Callback was not provided: must be an explicit error, not "empty but success".
    const BoundedReadResult kNoReader = readRangeBounded(failing, ChunkReader{});
    s.expect(kNoReader.span.outcome.status == CollectionStatus::kError &&
                 !kNoReader.span.outcome.message.empty(),
             L"F-05 a missing chunk reader is an error with a stated reason, not an empty success");
}

// ---------------------------------------------------------------------------
// M-01: Region information semantics.
// ---------------------------------------------------------------------------
RegionRecord makeRegion(RegionEvidenceSource source, RegionType type) {
    RegionRecord record;
    record.base = OptionalU64::of(0x00000001A0000000ULL);
    record.size = OptionalU64::of(0x10000ULL);
    record.state = RegionState::kCommit;
    record.type = type;
    record.protection.readable = true;
    record.protection.executable = true;
    record.protection.rawValue = OptionalU64::of(0x20ULL);  // PAGE_EXECUTE_READ
    record.allocationBase = OptionalU64::of(0x00000001A0000000ULL);
    record.allocationProtect.readable = true;
    record.allocationProtect.writable = true;
    record.source = source;
    record.owner = makeProcess(4321ULL, 133000000000000000ULL);
    return record;
}

VadEvidence makeVad(bool verified) {
    VadEvidence vad;
    vad.vadNodeAddress = OptionalU64::of(0xFFFFA00012345678ULL);
    vad.startingVpn = OptionalU64::of(0x1A0000ULL);
    vad.endingVpn = OptionalU64::of(0x1A000FULL);
    vad.vadFlagsRaw = OptionalU64::of(0x7ULL);
    vad.profileId = "ntoskrnl-10.0.26300.9022";
    vad.profileVerified = verified;
    return vad;
}

void testRegionSemantics(ksword_tests::Suite& s) {
    // Even if the VAD field is populated for an R3 source, "VAD verified" must not be displayed.
    RegionRecord fromR3 = makeRegion(RegionEvidenceSource::kR3VirtualQuery, RegionType::kPrivate);
    fromR3.vad = makeVad(true);
    s.expect(!vadVerified(fromR3),
             L"M-01 a region that came from VirtualQuery is never marked VAD-verified");

    RegionRecord fromVad = makeRegion(RegionEvidenceSource::kR0VadWalk, RegionType::kPrivate);
    fromVad.vad = makeVad(true);
    s.expect(vadVerified(fromVad),
             L"M-01 a complete VAD walk with a verified profile is marked VAD-verified");

    RegionRecord unverifiedProfile = fromVad;
    unverifiedProfile.vad.profileVerified = false;
    s.expect(!vadVerified(unverifiedProfile),
             L"M-01 an unverified profile does not produce VAD-verified");

    RegionRecord brokenInterval = fromVad;
    brokenInterval.vad.endingVpn = OptionalU64::of(0x100000ULL);  // Ends before start.
    s.expect(!vadVerified(brokenInterval),
             L"M-01 an inverted VAD interval is treated as broken data, not as evidence");

    RegionRecord offline = makeRegion(RegionEvidenceSource::kOfflineSnapshot, RegionType::kImage);
    offline.vad = makeVad(true);
    s.expect(!vadVerified(offline),
             L"M-01 an offline snapshot row is not itself a VAD walk");

    AddressRange range;
    s.expect(regionRange(fromR3, range) && range.begin == 0x00000001A0000000ULL &&
                 range.length == 0x10000ULL,
             L"M-01 a region with base and size yields its address range");
    RegionRecord noSize = fromR3;
    noSize.size = OptionalU64::unset();
    s.expect(!regionRange(noSize, range),
             L"M-01 a region without a size does not fall back to zero");
}

// ---------------------------------------------------------------------------
// M-01: Testing the three states outside Commit and two mapping types is equivalent to
// testing only one path: Reserved, Free, Mapped, and Image each have distinct field
// semantics, especially that fields without a source must remain unset, not zero-filled.
// ---------------------------------------------------------------------------
void testRegionStateVariants(ksword_tests::Suite& s) {
    // Reserved: only address space is reserved; pages are not committed. VirtualQuery does not provide
    // Protect for MEM_RESERVE, so protection.rawValue must remain unset. Setting it to 0 would be read
    // downstream as "we checked and the protection value is 0", which is a fabricated observation.
    RegionRecord reserved;
    reserved.base = OptionalU64::of(0x00000001B0000000ULL);
    reserved.size = OptionalU64::of(0x100000ULL);
    reserved.state = RegionState::kReserved;
    reserved.type = RegionType::kPrivate;
    reserved.allocationBase = OptionalU64::of(0x00000001B0000000ULL);
    reserved.allocationProtect.rawValue = OptionalU64::of(0x04ULL);  // PAGE_READWRITE
    reserved.source = RegionEvidenceSource::kR3VirtualQuery;
    s.expect(reserved.state == RegionState::kReserved &&
                 std::string(regionStateName(reserved.state)) == "Reserved",
             L"M-01 a reserved region keeps the Reserved state instead of being folded into Commit");
    s.expect(!reserved.protection.rawValue.present && !reserved.protection.readable &&
                 !reserved.protection.writable && !reserved.protection.executable,
             L"M-01 a reserved region has no current page protection - rawValue stays unset, not 0");
    s.expect(reserved.allocationProtect.rawValue == OptionalU64::of(0x04ULL),
             L"M-01 the allocation protection is a field of its own, separate from the current one");
    AddressRange reservedRange;
    s.expect(regionRange(reserved, reservedRange) &&
                 reservedRange.begin == 0x00000001B0000000ULL &&
                 reservedRange.length == 0x100000ULL,
             L"M-01 a reserved region still has a real address range");

    // Free: a hole in the address space. No type, no allocation base, no protection, and no mapped path.
    RegionRecord freeRegion;
    freeRegion.base = OptionalU64::of(0x00000001C0000000ULL);
    freeRegion.size = OptionalU64::of(0x10000ULL);
    freeRegion.state = RegionState::kFree;
    freeRegion.type = RegionType::kUnknown;
    freeRegion.source = RegionEvidenceSource::kR3VirtualQuery;
    s.expect(freeRegion.state == RegionState::kFree &&
                 freeRegion.type == RegionType::kUnknown &&
                 std::string(regionTypeName(freeRegion.type)) == "Unknown",
             L"M-01 a free region has no memory type and the unknown type is spelled out as such");
    s.expect(!freeRegion.allocationBase.present && !freeRegion.protection.rawValue.present,
             L"M-01 a free region fakes neither an allocation base nor a protection value");
    s.expect(freeRegion.mappedPath.empty() && !vadVerified(freeRegion),
             L"M-01 a free region carries no mapping path and is never VAD-verified");

    // Mapped: File mapping (not image). The path comes from the section object, sourced from R0 VAD traversal,
    // and the profile is verified. Only when this entire set is complete is it allowed to display 'VAD verified'.
    RegionRecord mapped;
    mapped.base = OptionalU64::of(0x00000001D0000000ULL);
    mapped.size = OptionalU64::of(0x8000ULL);
    mapped.state = RegionState::kCommit;
    mapped.type = RegionType::kMapped;
    mapped.protection.readable = true;
    mapped.protection.rawValue = OptionalU64::of(0x02ULL);  // PAGE_READONLY
    mapped.allocationBase = OptionalU64::of(0x00000001D0000000ULL);
    mapped.mappedPath = "\\Device\\HarddiskVolume3\\data\\catalog.bin";
    mapped.source = RegionEvidenceSource::kR0VadWalk;
    // Manual calculation: VPN = base >> 12 = 0x1D0000; 0x8000 bytes = 8 pages, last page VPN = 0x1D0007.
    mapped.vad.vadNodeAddress = OptionalU64::of(0xFFFFA000ABCDEF00ULL);
    mapped.vad.startingVpn = OptionalU64::of(0x1D0000ULL);
    mapped.vad.endingVpn = OptionalU64::of(0x1D0007ULL);
    mapped.vad.vadFlagsRaw = OptionalU64::of(0x1ULL);
    mapped.vad.profileId = "ntoskrnl-10.0.26300.9022";
    mapped.vad.profileVerified = true;
    s.expect(mapped.type == RegionType::kMapped &&
                 std::string(regionTypeName(mapped.type)) == "Mapped",
             L"M-01 a mapped file region reports the Mapped type, distinct from Image and Private");
    s.expect(!mapped.mappedPath.empty() && mapped.protection.readable &&
                 !mapped.protection.executable &&
                 mapped.protection.rawValue == OptionalU64::of(0x02ULL),
             L"M-01 the mapped region's decoded flags agree with the raw PAGE_* value they came from");
    s.expect(vadVerified(mapped) &&
                 std::string(regionEvidenceSourceName(mapped.source)) == "R0VadWalk",
             L"M-01 only a VAD walk with a verified profile and a complete interval is VAD-verified");

    // Image: Image mapping. Same fields, but sourced from an offline snapshot; snapshot rows are not a single VAD traversal.
    RegionRecord image;
    image.base = OptionalU64::of(0x00007FFAB0000000ULL);
    image.size = OptionalU64::of(0x1F0000ULL);
    image.state = RegionState::kCommit;
    image.type = RegionType::kImage;
    image.protection.readable = true;
    image.protection.executable = true;
    image.protection.rawValue = OptionalU64::of(0x20ULL);  // PAGE_EXECUTE_READ
    image.allocationBase = OptionalU64::of(0x00007FFAB0000000ULL);
    image.mappedPath = "\\Device\\HarddiskVolume3\\Windows\\System32\\ntdll.dll";
    image.source = RegionEvidenceSource::kOfflineSnapshot;
    image.vad = makeVad(true);
    s.expect(image.type == RegionType::kImage && std::string(regionTypeName(image.type)) == "Image",
             L"M-01 an image region reports the Image type");
    s.expect(!vadVerified(image) &&
                 std::string(regionEvidenceSourceName(image.source)) == "OfflineSnapshot",
             L"M-01 an offline snapshot row keeps its own source and is never VAD-verified");
    s.expect(image.protection.executable && image.protection.rawValue == OptionalU64::of(0x20ULL),
             L"M-01 the image region's executable flag matches the raw PAGE_EXECUTE_READ it came from");

    // base + size wraps 64-bit: No available address range. Manual calculation:
    // 0xFFFFFFFFFFFF0000 + 0x20000 = 0x1_0000_0000_0000_0000, which exceeds 64 bits.
    RegionRecord wrapping;
    wrapping.base = OptionalU64::of(0xFFFFFFFFFFFF0000ULL);
    wrapping.size = OptionalU64::of(0x20000ULL);
    wrapping.state = RegionState::kCommit;
    wrapping.type = RegionType::kPrivate;
    AddressRange wrapped;
    s.expect(!regionRange(wrapping, wrapped),
             L"M-01 a region whose base plus size overflows 64 bits yields no address range at all");
}

// ---------------------------------------------------------------------------
// M-07: Executable region clues.
// ---------------------------------------------------------------------------
const ExecutableRegionFinding* findRule(const ExecutableRegionReport& report, const char* ruleId) {
    for (const ExecutableRegionFinding& finding : report.findings) {
        if (finding.ruleId == ruleId) {
            return &finding;
        }
    }
    return nullptr;
}

bool hasFact(const ExecutableRegionFinding& finding, const std::string& fact) {
    return std::find(finding.facts.begin(), finding.facts.end(), fact) != finding.facts.end();
}

bool hasOwner(const ExecutableRegionFinding& finding, const std::string& owner) {
    return std::find(finding.candidateOwners.begin(), finding.candidateOwners.end(), owner) !=
           finding.candidateOwners.end();
}

void testExecutableRegionRules(ksword_tests::Suite& s) {
    const std::string kNtdll = "\\Device\\HarddiskVolume3\\Windows\\System32\\ntdll.dll";
    const std::string kKernelBase = "\\Device\\HarddiskVolume3\\Windows\\System32\\kernelbase.dll";

    // Native JIT style: private RX, no mapped path, and no comparison performed.
    ExecutableRegionInput jit;
    jit.region = makeRegion(RegionEvidenceSource::kR3VirtualQuery, RegionType::kPrivate);
    const ExecutableRegionReport kJitReport = evaluateExecutableRegion(jit);
    const ExecutableRegionFinding* privateRule = findRule(kJitReport, kRuleIdPrivateExecutable);
    s.expect(privateRule != nullptr, L"M-07 a private executable region produces a private-exec clue");
    if (privateRule != nullptr) {
        s.expect(!privateRule->facts.empty(),
                 L"M-07 the rule lists the facts it relied on");
        s.expect(hasFact(*privateRule, "vadVerified=false") &&
                     hasFact(*privateRule, "region.type=Private") &&
                     hasFact(*privateRule, "region.mappedPath=unknown"),
                 L"M-07 the facts include source, type and the missing mapping path");
        s.expect(privateRule->attribution == OwnerAttribution::kUnknown &&
                     privateRule->candidateOwners.empty(),
                 L"M-07 an unknown owner stays unknown for a private region");
    }
    s.expect(kJitReport.conclusion == AnalysisConclusion::kIndeterminate,
             L"M-07 RX plus private alone is a clue, never a difference or a verdict");
    s.expect(kJitReport.attribution == OwnerAttribution::kUnknown,
             L"M-07 the report-level attribution is unknown without mapping evidence");

    // Known tampered image region: precise difference.
    ExecutableRegionInput tampered;
    tampered.region = makeRegion(RegionEvidenceSource::kR0VadWalk, RegionType::kImage);
    tampered.region.mappedPath = kNtdll;
    tampered.region.vad = makeVad(true);
    tampered.regionOwnerKnown = true;
    tampered.imageComparison.compared = true;
    tampered.imageComparison.outcome = CollectionOutcome::success();
    tampered.imageComparison.onDiskPath = "C:\\Windows\\System32\\ntdll.dll";
    tampered.imageComparison.relocationsApplied = true;
    AddressRange diff;
    diff.begin = 0x00007FFAB0001000ULL;
    diff.length = 0x20ULL;
    tampered.imageComparison.differingRanges.push_back(diff);

    const ExecutableRegionReport kTamperReport = evaluateExecutableRegion(tampered);
    const ExecutableRegionFinding* imageRule = findRule(kTamperReport, kRuleIdImageBytesDiffer);
    s.expect(imageRule != nullptr, L"M-07 a differing image region produces an image-diff clue");
    if (imageRule != nullptr) {
        s.expect(hasFact(*imageRule, "image.differingRange=0x00007FFAB0001000+32"),
                 L"M-07 the differing range is reported precisely");
        s.expect(hasFact(*imageRule, "image.differingRangeCount=1"),
                 L"M-07 the number of differing ranges is a listed fact");
        s.expect(imageRule->attribution == OwnerAttribution::kDirectEvidence,
                 L"M-09 a mapped image with a known owner is direct evidence");
    }
    s.expect(kTamperReport.conclusion == AnalysisConclusion::kDifferenceObserved,
             L"M-07 a normalised byte difference against disk is a difference observed");

    // Comparison performed but no differences found.
    ExecutableRegionInput clean = tampered;
    clean.imageComparison.differingRanges.clear();
    s.expect(evaluateExecutableRegion(clean).conclusion == AnalysisConclusion::kNoDifferenceObserved,
             L"M-07 a completed comparison without differences is NoDifferenceObserved");

    // A difference exists but relocation normalization was not applied: this is only a clue.
    ExecutableRegionInput unnormalised = tampered;
    unnormalised.imageComparison.relocationsApplied = false;
    s.expect(evaluateExecutableRegion(unnormalised).conclusion == AnalysisConclusion::kIndeterminate,
             L"M-07 differences without relocation normalisation stay indeterminate");

    // Comparison was never performed: do not substitute 'no difference' for actual verification.
    ExecutableRegionInput notCompared;
    notCompared.region = makeRegion(RegionEvidenceSource::kR0VadWalk, RegionType::kImage);
    notCompared.region.mappedPath = kNtdll;
    const ExecutableRegionReport kNotComparedReport = evaluateExecutableRegion(notCompared);
    s.expect(kNotComparedReport.conclusion == AnalysisConclusion::kNoEvidence,
             L"M-07 a comparison that never ran does not become NoDifferenceObserved");

    // Thread start address falls within a private region with unknown ownership.
    ExecutableRegionInput threadCase;
    threadCase.region = makeRegion(RegionEvidenceSource::kR3VirtualQuery, RegionType::kPrivate);
    ThreadStartFact thread;
    thread.thread.process = makeProcess(4321ULL, 133000000000000000ULL);
    thread.thread.tid = OptionalU64::of(8888ULL);
    thread.thread.createTime100ns = OptionalU64::of(133000000000100000ULL);
    thread.startAddress = OptionalU64::of(0x00000001A0001000ULL);
    thread.startAddressInsideRegion = true;
    threadCase.threads.push_back(thread);
    const ExecutableRegionReport kThreadReport = evaluateExecutableRegion(threadCase);
    const ExecutableRegionFinding* threadRule = findRule(kThreadReport, kRuleIdThreadOriginMismatch);
    s.expect(threadRule != nullptr,
             L"M-07 a thread starting inside an unbacked region produces a clue");
    if (threadRule != nullptr) {
        s.expect(threadRule->attribution == OwnerAttribution::kUnknown &&
                     hasFact(*threadRule, "thread.startMappedPath=unknown"),
                 L"M-07 an unmapped thread start address keeps the owner unknown");
        s.expect(hasFact(*threadRule, "thread.startAddress=0x00000001A0001000"),
                 L"M-07 the thread start address is reported losslessly");
    }
    s.expect(kThreadReport.findings.size() == 2U,
             L"M-07 each rule contributes its own finding rather than one merged verdict");

    // Branch M-07: Thread start address falls within the same mapped region as the source — ownership is consistent, so there is no reportable fact.
    ExecutableRegionInput sameOrigin;
    sameOrigin.region = makeRegion(RegionEvidenceSource::kR0VadWalk, RegionType::kImage);
    sameOrigin.region.mappedPath = kNtdll;
    sameOrigin.region.vad = makeVad(true);
    ThreadStartFact insider;
    insider.thread.process = makeProcess(4321ULL, 133000000000000000ULL);
    insider.thread.tid = OptionalU64::of(7777ULL);
    insider.thread.createTime100ns = OptionalU64::of(133000000000200000ULL);
    insider.startAddress = OptionalU64::of(0x00000001A0002000ULL);
    insider.startAddressInsideRegion = true;
    insider.startAddressMappedPath = kNtdll;
    sameOrigin.threads.push_back(insider);
    const ExecutableRegionReport kSameOriginReport = evaluateExecutableRegion(sameOrigin);
    s.expect(findRule(kSameOriginReport, kRuleIdThreadOriginMismatch) == nullptr,
             L"M-07 a thread whose start address maps to the same module as the region raises no mismatch clue");
    s.expect(kSameOriginReport.findings.empty() &&
                 kSameOriginReport.conclusion == AnalysisConclusion::kNoEvidence,
             L"M-07 an agreeing thread origin leaves no finding and no conclusion to draw");

    // M-07 branch: Both paths are non-empty and distinct. Since there is no evidence to determine
    // true ownership, both sides must be listed as candidates; do not retain only the thread side.
    ExecutableRegionInput crossModule = sameOrigin;
    crossModule.threads[0].startAddressMappedPath = kKernelBase;
    const ExecutableRegionReport kCrossReport = evaluateExecutableRegion(crossModule);
    const ExecutableRegionFinding* crossRule = findRule(kCrossReport, kRuleIdThreadOriginMismatch);
    s.expect(crossRule != nullptr,
             L"M-07 a thread starting in a different module than the region produces a mismatch clue");
    if (crossRule != nullptr) {
        s.expect(crossRule->attribution == OwnerAttribution::kCandidate,
                 L"M-09 a start address mapped to another module is a candidate attribution, never direct");
        s.expect(crossRule->candidateOwners.size() == 2U && hasOwner(*crossRule, kKernelBase) &&
                     hasOwner(*crossRule, kNtdll),
                 L"M-09 both the thread's module and the region's module are listed as candidates");
        s.expect(hasFact(*crossRule, "thread.startMappedPath=" + kKernelBase) &&
                     hasFact(*crossRule, "region.mappedPath=" + kNtdll),
                 L"M-07 both mapping paths are listed as facts so a reader can recheck the mismatch");
    }

    // If the start address cannot be obtained, it cannot be obtained — and that represents 'no observation', not 'ownership mismatch'.
    ExecutableRegionInput unknownStart;
    unknownStart.region = makeRegion(RegionEvidenceSource::kR3VirtualQuery, RegionType::kMapped);
    unknownStart.region.protection.executable = false;
    ThreadStartFact blind;
    blind.thread.process = makeProcess(4321ULL, 133000000000000000ULL);
    blind.thread.tid = OptionalU64::of(9999ULL);
    unknownStart.threads.push_back(blind);
    const ExecutableRegionReport kBlindReport = evaluateExecutableRegion(unknownStart);
    const ExecutableRegionFinding* blindRule = findRule(kBlindReport, kRuleIdThreadOriginUnknown);
    s.expect(blindRule != nullptr && blindRule->attribution == OwnerAttribution::kUnknown &&
                 hasFact(*blindRule, "thread.startAddress=unknown"),
             L"M-07 a missing thread start address is reported as unknown, not as the region base");
    s.expect(findRule(kBlindReport, kRuleIdThreadOriginMismatch) == nullptr,
             L"M-07 a start address that was never collected is not reported as an origin mismatch");
    s.expect(blindRule != nullptr &&
                 blindRule->inputOutcome.status == CollectionStatus::kNotCollected,
             L"F-05 the not-collected input status travels with the finding");
    s.expect(kBlindReport.conclusion == AnalysisConclusion::kNoEvidence,
             L"F-05 findings built only on not-collected inputs leave the conclusion at NoEvidence, not Indeterminate");
}

// ---------------------------------------------------------------------------
// M-09: Pool attribution tiers.
// ---------------------------------------------------------------------------
void testPoolAttribution(ksword_tests::Suite& s) {
    std::vector<PoolTagOwnerEntry> table;
    table.push_back({"Ntfx", "\\SystemRoot\\System32\\drivers\\ntfs.sys", "kb-2026.01"});
    table.push_back({"Ntfx", "\\SystemRoot\\System32\\drivers\\thirdparty.sys", "kb-2026.01"});
    table.push_back({"Ntfx", "\\SystemRoot\\System32\\drivers\\another.sys", "kb-2026.01"});
    table.push_back({"Solo", "\\SystemRoot\\System32\\drivers\\solo.sys", "kb-2026.01"});

    const PoolAttributionResult kShared = attributeByTag("Ntfx", table);
    s.expect(kShared.attribution == OwnerAttribution::kCandidate,
             L"M-09 a tag shared by several components is only a candidate");
    s.expect(kShared.candidateOwners.size() == 3U,
             L"M-09 every candidate owner is listed, not just the first one");
    s.expect(!kShared.allocationStackAvailable,
             L"M-09 tag attribution never claims an allocation stack");

    const PoolAttributionResult kSingle = attributeByTag("Solo", table);
    s.expect(kSingle.attribution == OwnerAttribution::kCandidate &&
                 kSingle.candidateOwners.size() == 1U,
             L"M-09 a tag with one known owner is still only a candidate");

    const PoolAttributionResult kNoTag = attributeByTag("", table);
    s.expect(kNoTag.attribution == OwnerAttribution::kUnknown && kNoTag.candidateOwners.empty(),
             L"M-09 an allocation without a tag stays unknown");

    const PoolAttributionResult kUnknownTag = attributeByTag("Zzzz", table);
    s.expect(kUnknownTag.attribution == OwnerAttribution::kUnknown &&
                 kUnknownTag.candidateOwners.empty(),
             L"M-09 a tag that is not in the table stays unknown");

    PoolAllocationEvent absent;
    absent.captured = false;
    const PoolAttributionResult kWithoutEvent = attributeByAllocationEvent(absent, kShared);
    s.expect(kWithoutEvent.attribution == OwnerAttribution::kCandidate &&
                 !kWithoutEvent.allocationStackAvailable,
             L"M-09 without a pre-captured allocation event the answer falls back to candidate");

    PoolAllocationEvent captured;
    captured.captured = true;
    captured.allocator.bootId = "boot-M";
    captured.allocator.imagePath = "\\SystemRoot\\System32\\drivers\\ntfs.sys";
    captured.allocator.pdbSignature = "RSDS-1111-2222-1";
    captured.eventUtc100ns = OptionalU64::of(133000000000500000ULL);
    captured.eventSourceId = "etw.pool.alloc";
    const PoolAttributionResult kWithEvent = attributeByAllocationEvent(captured, kShared);
    s.expect(kWithEvent.attribution == OwnerAttribution::kDirectEvidence,
             L"M-09 a pre-captured allocation event with a strong identity is direct evidence");
    s.expect(kWithEvent.candidateOwners.size() == 1U,
             L"M-09 direct evidence names exactly the allocator it observed");

    PoolAllocationEvent weakAllocator = captured;
    weakAllocator.allocator.pdbSignature.clear();
    weakAllocator.allocator.imagePath = "unknown.sys";
    weakAllocator.allocator.timeDateStamp = OptionalU64::unset();
    weakAllocator.allocator.imageSize = OptionalU64::unset();
    const PoolAttributionResult kWeakEvent = attributeByAllocationEvent(weakAllocator, kShared);
    s.expect(kWeakEvent.attribution == OwnerAttribution::kCandidate,
             L"M-09 an event whose allocator identity is too weak is not upgraded to direct evidence");
}

} // namespace

int runMemoryEvidenceTests() {
    ksword_tests::Suite suite(L"M memory evidence");
    testFourKiBTranslation(suite);
    testLargePages(suite);
    testRejectedAddresses(suite);
    testReservedBits(suite);
    testSoftwarePte(suite);
    testTranslationContext(suite);
    testPartialRead(suite);
    testMergeReadSpans(suite);
    testScanBudget(suite);
    testReadFailureCodes(suite);
    testRegionSemantics(suite);
    testRegionStateVariants(suite);
    testExecutableRegionRules(suite);
    testPoolAttribution(suite);
    suite.report();
    return suite.failures();
}
