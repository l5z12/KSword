// Offline automated test for the EPTP switch backend (shared/driver/KswordArkHvmEptSwitch.h).
//
// The item under test shares a common characteristic: **calculation errors do not trigger exceptions**. Uncleared
// reserved bits in leaf entries only result in an exit reason 49; writing 4 to the EPTP level field causes VM entry
// to return a numeric value; an off-by-one error in the hierarchy index leaves a page permanently shadowed while all
// self-tests pass green; a single branch error in the state machine leads to a silent system-wide deadlock. These
// are not errors that can be detected by simply installing and running once, so they must be proven at compile time.
//
// Assertion principle (consistent with CrossViewTests.cpp):
//   * Expected values must be **independently calculated and hardcoded**, never derived by reversing the function
//     under test — a test that derives expected values from the code under test only proves that the code equals itself.
//   * Well-formedness assertions must specify **the exact failure item** rather than "non-zero";
//     otherwise, regressions where the wrong item fails will escape the entire test class;
//   * The state machine performs **exhaustive** enumeration: (current level × access type × view type) combinations are fully
//     enumerated to fix outcomes, target indices, and rejection reasons; transitions that should not occur must be explicitly rejected.
//   * Test boundaries on both sides (maximum physical address, valid and invalid level encodings, indices 511 and 512, budget
//     exactly at limit and just over). Testing only one side of a boundary is equivalent to not testing the boundary at all.

#include "TestSupport.h"

#include "../../../shared/driver/KswordArkHvmEptSwitch.h"

#include <cstdint>
#include <initializer_list>

namespace {

// ---------------------------------------------------------------------------
// Manually calculated sample values. Each bit origin is explicitly documented so that if the layout
// changes, the mismatch appears in the documented formula rather than an unexplained magic number.
// ---------------------------------------------------------------------------

// 2MiB identity leaf: Frame = 1GiB (0x40000000), RWX (0x7), WB (6<<3 = 0x30),
// large page (0x80), suppress-#VE (bit 63). Low byte = 0x7|0x30|0x80 = 0xB7.
constexpr std::uint64_t kLargeLeaf = 0x80000000400000B7ULL;
// Attributes part of the same leaf: remove RWX and page frame, leaving suppress-#VE | 0xB0.
constexpr std::uint64_t kLargeAttributes = 0x80000000000000B0ULL;

// 4KiB leaf: Frame 0x12345000, RWX, WB, no large page bit. Low byte = 0x7|0x30 = 0x37.
constexpr std::uint64_t kSmallLeaf = 0x8000000012345037ULL;
// 4KiB leaf attribute section: suppress-#VE | WB(0x30).
constexpr std::uint64_t kSmallAttributes = 0x8000000000000030ULL;
constexpr std::uint64_t kSmallFrame = 0x0000000012345000ULL;

// Typical implementation of physical width. 39 bits are sufficient to make 'frame bit 40' an out-of-bounds sample.
constexpr std::uint32_t kPhysBits39 = 39U;

// Base EPTP: Root 0x01000000, WB(6), 4-level walk (3<<3 = 0x18). 0x6|0x18 = 0x1E.
constexpr std::uint64_t kBaseEptp = 0x0100001EULL;
// Open A/D (bit 6 = 0x40) on the same base.
constexpr std::uint64_t kBaseEptpAd = 0x0100005EULL;

// EPT/VPID capabilities: 4-level walk (bit 6) + WB (bit 14) + A/D (bit 21).
constexpr std::uint64_t kCapWb = 0x0000000000204040ULL;
// Additionally include UC (bit 8).
constexpr std::uint64_t kCapWbUc = 0x0000000000204140ULL;
// INVEPT(bit 20) + single(bit 25) + all(bit 26)。
constexpr std::uint64_t kCapInvept = 0x0000000006100000ULL;

// ---------------------------------------------------------------------------
// Leaf node parsing and synthesis
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Values of architectural constants
// ---------------------------------------------------------------------------

// The sole reason this section exists is: **symbolic references cannot capture renumbering**.
//
// Note: The previous review injected six mutations that moved a specific architectural constant to a different symbol. None of the 344 assertions
// triggered because each assertion was written as f(SYMBOL) == SYMBOL, causing both sides to change simultaneously and the equality to always hold.
// The specific surviving changes are: INVEPT 1/2 swap, leaf accessed/dirty swap,
// ignore-PAT moved to bit 5, user-execute moved to bit 11, EPT capability bit execute-only
// moved away from bit 0, and protocol mirror CLOAK/HOOK swapped with READ/WRITE.
//
// Therefore, write each literal on the right side of the equals sign below, and in the comment specify exactly where in the
// SDM this value comes from, as well as how the machine would silently produce incorrect results if written incorrectly.
// Another set of identical compile-time assertions exists in the header file: one protects the driver build, the other protects the unit tests themselves.

void testArchitecturalConstants(ksword_tests::Suite& s) {
    // --- EPT leaf: SDM Vol.3C, Table 29-6 --- Permission bit misalignment: CLOAK's "read-not-allowed"
    // becomes "write-not-allowed"; shadow pages are permanently exposed to all readers.
    s.expect(KSWORD_ARK_HVM_EPTSW_READ == 0x1ULL,
             L"the EPT read bit is bit 0");
    s.expect(KSWORD_ARK_HVM_EPTSW_WRITE == 0x2ULL,
             L"the EPT write bit is bit 1");
    s.expect(KSWORD_ARK_HVM_EPTSW_EXECUTE == 0x4ULL,
             L"the EPT execute bit is bit 2");
    s.expect(KSWORD_ARK_HVM_EPTSW_PERM_MASK == 0x7ULL,
             L"the permission mask is exactly bits 2:0");
    // Shifting the memory type field by one bit changes MMIO pages from UC to WB, causing random device errors that no one would suspect are caused by EPT.
    s.expect(KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_SHIFT == 3,
             L"the leaf memory type field starts at bit 3");
    s.expect(KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_MASK == 0x7ULL,
             L"the leaf memory type field is three bits wide");
    // Moving ignore-PAT to bit 5 places it inside the memory type field: a WB page would be read as a WP page.
    s.expect(KSWORD_ARK_HVM_EPTSW_IGNORE_PAT == 0x40ULL,
             L"ignore-PAT is bit 6, not anywhere inside the memory type field");
    // Shifting the large-page bit by one means the processor treats a 2MiB leaf as a pointer to the next-level table, following page content.
    s.expect(KSWORD_ARK_HVM_EPTSW_LARGE_PAGE == 0x80ULL,
             L"the large-page bit is bit 7");
    // A/D swap: "This page was written" becomes "This page was accessed"; forensic conclusions are exactly reversed.
    s.expect(KSWORD_ARK_HVM_EPTSW_ACCESSED == 0x100ULL,
             L"the accessed bit is bit 8");
    s.expect(KSWORD_ARK_HVM_EPTSW_DIRTY == 0x200ULL,
             L"the dirty bit is bit 9");
    s.expect(KSWORD_ARK_HVM_EPTSW_USER_EXECUTE == 0x400ULL,
             L"user-mode execute is bit 10");
    // suppress-#VE bit drop: Once #VE is enabled, a single access triggers #GP -> #DF -> triple fault.
    s.expect(KSWORD_ARK_HVM_EPTSW_SUPPRESS_VE == 0x8000000000000000ULL,
             L"suppress-#VE is bit 63");
    s.expect(KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK == 0x000FFFFFFFFFF000ULL,
             L"the physical address field is bits 51:12");
    s.expect(KSWORD_ARK_HVM_EPTSW_LARGE_FRAME_MASK == 0x000FFFFFFFE00000ULL,
             L"the two-MiB frame field is bits 51:21");
    s.expect(KSWORD_ARK_HVM_EPTSW_PAGE_BYTES == 0x1000ULL &&
                 KSWORD_ARK_HVM_EPTSW_LARGE_BYTES == 0x200000ULL &&
                 KSWORD_ARK_HVM_EPTSW_TABLE_ENTRIES == 512U &&
                 KSWORD_ARK_HVM_EPTSW_ENTRY_BYTES == 8ULL,
             L"page geometry is four KiB, two MiB, 512 entries of eight bytes");
    // Encodings for the five valid memory types; 2, 3, and 7 are reserved.
    s.expect(KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_UC == 0ULL &&
                 KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_WC == 1ULL &&
                 KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_WT == 4ULL &&
                 KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_WP == 5ULL &&
                 KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_WB == 6ULL,
             L"the five architectural EPT memory type encodings are 0, 1, 4, 5 and 6");

    // --- EPTP fields: SDM Vol.3C, Table 25-9
    s.expect(KSWORD_ARK_HVM_EPTSW_EPTP_MEMORY_TYPE_MASK == 0x7ULL,
             L"the EPTP memory type field is bits 2:0");
    s.expect(KSWORD_ARK_HVM_EPTSW_EPTP_WALK_SHIFT == 3,
             L"the EPTP walk-length field starts at bit 3");
    s.expect(KSWORD_ARK_HVM_EPTSW_EPTP_WALK_MASK == 0x7ULL,
             L"the EPTP walk-length field is three bits wide");
    s.expect(KSWORD_ARK_HVM_EPTSW_EPTP_ACCESSED_DIRTY == 0x40ULL,
             L"the EPTP accessed/dirty enable is bit 6");
    s.expect(KSWORD_ARK_HVM_EPTSW_EPTP_RESERVED_LOW == 0xF80ULL,
             L"EPTP bits 11:7 are reserved");
    s.expect(KSWORD_ARK_HVM_EPTSW_EPTP_WALK_LEVELS == 4U,
             L"this driver uses a four-level walk, which the field encodes as three");

    // --- IA32_VMX_EPT_VPID_CAP:SDM Vol.3D, Appendix A.10 ---
    // Asymmetric consequence of reading the execute-only bit incorrectly: it is misinterpreted as 'supported'
    // when the hardware does not support it, causing a write of --x leaf to trigger an EPT misconfiguration.
    s.expect(KSWORD_ARK_HVM_EPTSW_CAP_EXECUTE_ONLY == 0x1ULL,
             L"execute-only support is capability bit 0");
    s.expect(KSWORD_ARK_HVM_EPTSW_CAP_PAGE_WALK_4 == 0x40ULL,
             L"four-level page walk support is capability bit 6");
    s.expect(KSWORD_ARK_HVM_EPTSW_CAP_MEMORY_TYPE_UC == 0x100ULL,
             L"UC EPTP support is capability bit 8");
    s.expect(KSWORD_ARK_HVM_EPTSW_CAP_MEMORY_TYPE_WB == 0x4000ULL,
             L"WB EPTP support is capability bit 14");
    s.expect(KSWORD_ARK_HVM_EPTSW_CAP_INVEPT == 0x100000ULL,
             L"the INVEPT instruction itself is capability bit 20");
    s.expect(KSWORD_ARK_HVM_EPTSW_CAP_ACCESSED_DIRTY == 0x200000ULL,
             L"accessed/dirty support is capability bit 21");
    s.expect(KSWORD_ARK_HVM_EPTSW_CAP_INVEPT_SINGLE == 0x2000000ULL,
             L"single-context INVEPT support is capability bit 25");
    s.expect(KSWORD_ARK_HVM_EPTSW_CAP_INVEPT_ALL == 0x4000000ULL,
             L"all-context INVEPT support is capability bit 26");

    // --- INVEPT type: SDM Vol.3C, 30.3 --- These two values are passed directly to
    // the register for INVEPT. If swapped, requesting 'all' would issue a 'single'
    // with a zero descriptor, which fails to flush anything and produces no symptoms.
    s.expect(KSWORD_ARK_HVM_EPTSW_INVEPT_SINGLE == 1U,
             L"INVEPT type one is single-context");
    s.expect(KSWORD_ARK_HVM_EPTSW_INVEPT_ALL == 2U,
             L"INVEPT type two is all-context");

    // --- Protocol mirror: KswordArkHvmIoctl.h:336-338 and :754/756 --- The values in this local
    // copy are fixed by the code below; the counterpart is fixed by C_ASSERT in the driver .c
    // file (the five lines to be written are listed line-by-line in the header file comment).
    s.expect(KSWORD_ARK_HVM_EPTSW_ACCESS_READ == 1U,
             L"protocol access read is bit 0, mirroring KSWORD_ARK_HVM_EPT_ACCESS_READ");
    s.expect(KSWORD_ARK_HVM_EPTSW_ACCESS_WRITE == 2U,
             L"protocol access write is bit 1, mirroring KSWORD_ARK_HVM_EPT_ACCESS_WRITE");
    s.expect(KSWORD_ARK_HVM_EPTSW_ACCESS_EXECUTE == 4U,
             L"protocol access execute is bit 2, mirroring KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE");
    s.expect(KSWORD_ARK_HVM_EPTSW_ACCESS_MASK == 7U,
             L"the protocol access mask is exactly the three defined bits");
    // KIND swap: An IOCTL request for CLOAK is served as HOOK permissions, changing the primary value to a true frame with rw-
    // access. This page becomes permanently readable for all readers—hiding becomes exposing, yet everything appears normal.
    s.expect(KSWORD_ARK_HVM_EPTSW_KIND_CLOAK == 1U,
             L"view kind CLOAK is one, mirroring KSWORD_ARK_HVM_VIEW_KIND_CLOAK");
    s.expect(KSWORD_ARK_HVM_EPTSW_KIND_HOOK == 2U,
             L"view kind HOOK is two, mirroring KSWORD_ARK_HVM_VIEW_KIND_HOOK");

    // --- Scale limit ---
    s.expect(KSWORD_ARK_HVM_EPTSW_MAX_LEAVES == 32U,
             L"the leaf limit mirrors KSWORD_ARK_HVM_MAX_VIEWS, which is thirty-two");
    s.expect(KSWORD_ARK_HVM_EPTSW_PATH_PAGES == 4ULL,
             L"one private path is root plus PDPT plus PD plus PT");
    s.expect(KSWORD_ARK_HVM_EPTSW_MAX_SAME_RIP_SWITCHES == 8U,
             L"eight is twice the largest number of legitimate faults one instruction can take");

    // --- Cross-header consistency with KswordArkHvmControls.h --- Aliased legacy constants must still equal
    // their counterparts in the sibling header: if these two sets diverge at any point, the same driver will
    // contain two different bit layouts, and the hardware will not indicate which one was used incorrectly.
    s.expect(KSWORD_ARK_HVM_EPTSW_READ == KSWORD_ARK_HVM_EPT_READ &&
                 KSWORD_ARK_HVM_EPTSW_WRITE == KSWORD_ARK_HVM_EPT_WRITE &&
                 KSWORD_ARK_HVM_EPTSW_EXECUTE == KSWORD_ARK_HVM_EPT_EXECUTE,
             L"the permission bits are the same objects the shared controls header defines");
    s.expect(KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK == KSWORD_ARK_HVM_EPT_PHYSICAL_MASK,
             L"the physical mask agrees with the shared controls header");
    s.expect(KSWORD_ARK_HVM_EPTSW_PAGE_BYTES == KSWORD_ARK_HVM_PAGE_BYTES &&
                 KSWORD_ARK_HVM_EPTSW_LARGE_BYTES == KSWORD_ARK_HVM_LARGE_PAGE_BYTES,
             L"page geometry agrees with the shared controls header");
    s.expect(KSWORD_ARK_HVM_EPTSW_EPTP_MEMORY_TYPE_MASK ==
                     KSWORD_ARK_HVM_EPTP_MEMORY_TYPE_MASK &&
                 KSWORD_ARK_HVM_EPTSW_EPTP_WALK_SHIFT ==
                     KSWORD_ARK_HVM_EPTP_WALK_LENGTH_SHIFT &&
                 KSWORD_ARK_HVM_EPTSW_EPTP_WALK_MASK ==
                     KSWORD_ARK_HVM_EPTP_WALK_LENGTH_MASK &&
                 KSWORD_ARK_HVM_EPTSW_EPTP_ACCESSED_DIRTY ==
                     KSWORD_ARK_HVM_EPTP_ACCESSED_DIRTY &&
                 KSWORD_ARK_HVM_EPTSW_EPTP_RESERVED_LOW ==
                     KSWORD_ARK_HVM_EPTP_RESERVED_LOW,
             L"every EPTP field agrees with the shared controls header");
    s.expect(KSWORD_ARK_HVM_EPTSW_CAP_PAGE_WALK_4 == KSWORD_ARK_HVM_EPT_CAP_PAGE_WALK_4 &&
                 KSWORD_ARK_HVM_EPTSW_CAP_MEMORY_TYPE_UC ==
                     KSWORD_ARK_HVM_EPT_CAP_MEMORY_TYPE_UC &&
                 KSWORD_ARK_HVM_EPTSW_CAP_MEMORY_TYPE_WB ==
                     KSWORD_ARK_HVM_EPT_CAP_MEMORY_TYPE_WB &&
                 KSWORD_ARK_HVM_EPTSW_CAP_ACCESSED_DIRTY ==
                     KSWORD_ARK_HVM_EPT_CAP_ACCESSED_DIRTY,
             L"every capability bit agrees with the shared controls header");
    // Index decomposition: This file uses bit-shift plus a 9-bit mask, while Controls.h uses division and modulo. Both must match
    // value-by-value within 48 bits—that is the only range where both formulas are representable. Beyond 48 bits, the Controls path can
    // produce PML4 indices greater than 511, so the assertion is restricted to the representable range without relaxing either side.
    {
        bool decompositionAgrees = true;
        const std::uint64_t kProbes[] = {
            0ULL, 0x1000ULL, 0x200000ULL, 0x40000000ULL,
            0x000002CB02390123ULL, 0x0000123456789ABCULL,
            0x0000FFFFFFFFFFFFULL,
        };
        for (const std::uint64_t kProbe : kProbes) {
            if (KswordArkHvmEptSwPml4Index(kProbe) != KswordArkHvmEptPml4Index(kProbe) ||
                KswordArkHvmEptSwPdptIndex(kProbe) != KswordArkHvmEptPdptIndex(kProbe) ||
                KswordArkHvmEptSwPdIndex(kProbe) != KswordArkHvmEptPdIndex(kProbe) ||
                KswordArkHvmEptSwPtIndex(kProbe) != KswordArkHvmEptPtIndex(kProbe)) {
                decompositionAgrees = false;
            }
        }
        s.expect(decompositionAgrees,
                 L"index decomposition agrees with the shared controls header below 2^48");
    }
    // Rebasing uses the same formula, so directly assert the same result rather than writing the expression twice.
    s.expect(KswordArkHvmEptSwRebaseEptp(kBaseEptpAd, 0x02000000ULL) ==
                 KswordArkHvmEptRebaseEntry(kBaseEptpAd, 0x02000000ULL),
             L"rebasing an EPT pointer is the shared rebase, not a second copy of it");
}

void testExecuteOnlyCapability(ksword_tests::Suite& s) {
    // The previous version of CAP_EXECUTE_ONLY was defined but never read by any function, so it could be moved to any bit
    // without triggering any unit tests. Now it has a single reader; these assertions are the criteria for that reader.
    s.expect(KswordArkHvmEptSwExecuteOnlySupported(0x1ULL) == 1,
             L"bit 0 alone reports execute-only support");
    s.expect(KswordArkHvmEptSwExecuteOnlySupported(0ULL) == 0,
             L"an all-zero capability reports no execute-only support");
    // No bit other than bit 0 must be mistakenly read as execute-only.
    {
        bool onlyBitZero = true;
        for (std::uint32_t bit = 1U; bit < 64U; ++bit) {
            if (KswordArkHvmEptSwExecuteOnlySupported(1ULL << bit) != 0) {
                onlyBitZero = false;
            }
        }
        s.expect(onlyBitZero,
                 L"no capability bit other than bit zero is read as execute-only");
    }
    // Actual capability masks: kCapInvept lacks bit 0, and kCapWb does as well.
    s.expect(KswordArkHvmEptSwExecuteOnlySupported(kCapWb) == 0 &&
                 KswordArkHvmEptSwExecuteOnlySupported(kCapInvept) == 0,
             L"the sample capability masks in this file advertise no execute-only");
    s.expect(KswordArkHvmEptSwExecuteOnlySupported(kCapWb | 0x1ULL) == 1,
             L"adding bit zero to a real capability mask turns execute-only on");
}

void testLeafDecomposition(ksword_tests::Suite& s) {
    s.expect(KswordArkHvmEptSwLeafPermissions(kLargeLeaf) == 0x7ULL,
             L"leaf permissions are bits 2:0");
    s.expect(KswordArkHvmEptSwLeafFrame(kLargeLeaf) == 0x40000000ULL,
             L"leaf frame is bits 51:12");
    s.expect(KswordArkHvmEptSwLeafMemoryType(kLargeLeaf) == 6ULL,
             L"leaf memory type is bits 5:3 and decodes to write-back");
    // Attributes must retain suppress-#VE: Without this bit, after #VE is enabled, page violations are
    // reflected into an IDT that Windows has not prepared [20], resulting in no exceptions during installation.
    s.expect(KswordArkHvmEptSwLeafAttributes(kLargeLeaf) == kLargeAttributes,
             L"leaf attributes keep suppress-#VE, memory type and the large-page bit");
    s.expect((KswordArkHvmEptSwLeafAttributes(kLargeLeaf) &
              KSWORD_ARK_HVM_EPTSW_SUPPRESS_VE) != 0ULL,
             L"leaf attributes never drop suppress-#VE");
    s.expect((KswordArkHvmEptSwLeafAttributes(kLargeLeaf) & 0x7ULL) == 0ULL,
             L"leaf attributes carry no permission bits");
    s.expect((KswordArkHvmEptSwLeafAttributes(kLargeLeaf) &
              KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK) == 0ULL,
             L"leaf attributes carry no page frame");

    s.expect(KswordArkHvmEptSwLeafMemoryType(kSmallLeaf) == 6ULL,
             L"four-KiB leaf memory type decodes to write-back");
    s.expect(KswordArkHvmEptSwLeafAttributes(kSmallLeaf) == kSmallAttributes,
             L"four-KiB leaf attributes are suppress-#VE plus write-back");
}

void testLeafComposition(ksword_tests::Suite& s) {
    // 0x80000000000000B0 | 0x0000007654321000 | 0x3 = 0x80000076543210B3。
    constexpr std::uint64_t kExpected = 0x80000076543210B3ULL;
    s.expect(KswordArkHvmEptSwComposeLeaf(
                 kLargeAttributes, 0x0000007654321000ULL, 0x3ULL) == kExpected,
             L"composing a leaf ors attributes, frame and permissions");
    // Unaligned shadow frames must be masked; otherwise, the lower 12 bits will bleed into the permission and memory-type
    // fields, producing a leaf with overly broad permissions and altered cache type that appears completely valid.
    s.expect(KswordArkHvmEptSwComposeLeaf(
                 kLargeAttributes, 0x0000007654321FFFULL, 0x3ULL) == kExpected,
             L"an unaligned frame cannot bleed into the permission or memory-type field");
    // Extra bits in the protocol access mask must not bleed into the memory type field.
    s.expect(KswordArkHvmEptSwComposeLeaf(
                 kLargeAttributes, 0x0000007654321000ULL, 0xF3ULL) == kExpected,
             L"permission bits outside 2:0 cannot bleed into the memory-type field");
    // If the caller mistakenly passes a complete original leaf entry as attributes, the old page frame must
    // not be combined with the new page frame—that would point to a location that is neither a real page nor
    // a shadow page. If the CLOAK primary value points to the wrong frame, the wrong bytes will be executed.
    s.expect(KswordArkHvmEptSwComposeLeaf(
                 kLargeLeaf, 0x0000007654321000ULL, 0x3ULL) == kExpected,
             L"a full entry passed as attributes cannot leak its old frame or permissions");

    // The two values in the view: attributes are inherited bitwise, differing only in frame and permissions.
    const std::uint64_t kCloakPrimary = KswordArkHvmEptSwComposeLeaf(
        kSmallAttributes, kSmallFrame, KSWORD_ARK_HVM_EPTSW_EXECUTE);
    const std::uint64_t kCloakSecondary = KswordArkHvmEptSwComposeLeaf(
        kSmallAttributes, 0x0000000099999000ULL,
        KSWORD_ARK_HVM_EPTSW_READ | KSWORD_ARK_HVM_EPTSW_WRITE);
    s.expect(kCloakPrimary == 0x8000000012345034ULL,
             L"CLOAK primary is execute-only on the real frame");
    s.expect(kCloakSecondary == 0x8000000099999033ULL,
             L"CLOAK secondary is read-write on the shadow frame");
    s.expect(KswordArkHvmEptSwLeafMemoryType(kCloakPrimary) ==
                 KswordArkHvmEptSwLeafMemoryType(kCloakSecondary),
             L"both view values keep the identity leaf's memory type");
    s.expect((kCloakPrimary & KSWORD_ARK_HVM_EPTSW_SUPPRESS_VE) != 0ULL &&
                 (kCloakSecondary & KSWORD_ARK_HVM_EPTSW_SUPPRESS_VE) != 0ULL,
             L"both view values keep suppress-#VE");
    s.expect(KswordArkHvmEptSwLeafFrame(kCloakPrimary) == kSmallFrame,
             L"CLOAK primary points at the real frame, not the shadow");
    s.expect(KswordArkHvmEptSwLeafFrame(kCloakSecondary) == 0x0000000099999000ULL,
             L"CLOAK secondary points at the shadow frame, not the real page");
}

// ---------------------------------------------------------------------------
// Leaf node well-formedness predicate
// ---------------------------------------------------------------------------

void testPermissionLegality(ksword_tests::Suite& s) {
    s.expect(KswordArkHvmEptSwPermissionsAreLegal(0x1ULL, 1) == 1,
             L"read-only is legal");
    s.expect(KswordArkHvmEptSwPermissionsAreLegal(0x3ULL, 1) == 1,
             L"read-write is legal");
    s.expect(KswordArkHvmEptSwPermissionsAreLegal(0x5ULL, 1) == 1,
             L"read-execute is legal");
    s.expect(KswordArkHvmEptSwPermissionsAreLegal(0x7ULL, 1) == 1,
             L"read-write-execute is legal");
    // Write without read is not encoded in EPT; writing to a leaf constitutes a misconfiguration.
    s.expect(KswordArkHvmEptSwPermissionsAreLegal(0x2ULL, 1) == 0,
             L"write without read is refused");
    s.expect(KswordArkHvmEptSwPermissionsAreLegal(0x6ULL, 1) == 0,
             L"write-execute without read is refused");
    // execute-only is legal only when the hardware reports it.
    s.expect(KswordArkHvmEptSwPermissionsAreLegal(0x4ULL, 1) == 1,
             L"execute-only is legal when the processor advertises it");
    s.expect(KswordArkHvmEptSwPermissionsAreLegal(0x4ULL, 0) == 0,
             L"execute-only is refused when the processor cannot encode it");
    // An all-zero permission leaf can never find a serving hierarchy under this mechanism — it is a non-progressing loop.
    s.expect(KswordArkHvmEptSwPermissionsAreLegal(0x0ULL, 1) == 0,
             L"an all-zero permission leaf is refused because no hierarchy can serve it");
    // Bits outside the permission domain do not participate in the judgment.
    s.expect(KswordArkHvmEptSwPermissionsAreLegal(0xF3ULL, 1) == 1,
             L"only bits 2:0 take part in the permission judgement");
}

void testMemoryTypeLegality(ksword_tests::Suite& s) {
    s.expect(KswordArkHvmEptSwMemoryTypeIsLegal(0ULL) == 1, L"UC is a legal leaf memory type");
    s.expect(KswordArkHvmEptSwMemoryTypeIsLegal(1ULL) == 1, L"WC is a legal leaf memory type");
    s.expect(KswordArkHvmEptSwMemoryTypeIsLegal(4ULL) == 1, L"WT is a legal leaf memory type");
    s.expect(KswordArkHvmEptSwMemoryTypeIsLegal(5ULL) == 1, L"WP is a legal leaf memory type");
    s.expect(KswordArkHvmEptSwMemoryTypeIsLegal(6ULL) == 1, L"WB is a legal leaf memory type");
    s.expect(KswordArkHvmEptSwMemoryTypeIsLegal(2ULL) == 0, L"encoding 2 is reserved");
    s.expect(KswordArkHvmEptSwMemoryTypeIsLegal(3ULL) == 0, L"encoding 3 is reserved");
    s.expect(KswordArkHvmEptSwMemoryTypeIsLegal(7ULL) == 0, L"encoding 7 is reserved");
}

void testFrameAlignment(ksword_tests::Suite& s) {
    s.expect(KswordArkHvmEptSwFrameIsAligned(0x40000000ULL, 1) == 1,
             L"a two-MiB aligned frame fits a large leaf");
    // Writing shadow frames aligned only to 4KiB into a 2MiB leaf: installation succeeds, but the first access triggers a misconfiguration.
    s.expect(KswordArkHvmEptSwFrameIsAligned(0x40100000ULL, 1) == 0,
             L"a merely page-aligned frame does not fit a large leaf");
    s.expect(KswordArkHvmEptSwFrameIsAligned(0x40001000ULL, 1) == 0,
             L"bits 20:12 must be zero in a large leaf frame");
    s.expect(KswordArkHvmEptSwFrameIsAligned(0x40100000ULL, 0) == 1,
             L"the same frame is fine for a four-KiB leaf");
    s.expect(KswordArkHvmEptSwFrameIsAligned(0x40000FFFULL, 0) == 0,
             L"a sub-page offset is not a legal four-KiB frame");
}

void testLeafWellFormed(ksword_tests::Suite& s) {
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(kLargeLeaf, 1, kPhysBits39, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_OK,
             L"the identity two-MiB leaf is well formed");
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(kSmallLeaf, 0, kPhysBits39, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_OK,
             L"the four-KiB leaf is well formed");

    // Both directions of mismatch between the large-page bit and the level must be caught: setting it when it shouldn't be causes the processor
    // to treat page content as a page table, while not setting it when it should be causes a page table entry to be treated as a 2MiB leaf.
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(kLargeLeaf, 0, kPhysBits39, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_BAD_LARGE_BIT,
             L"a large-page bit on a four-KiB leaf is refused");
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(kSmallLeaf, 1, kPhysBits39, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_BAD_LARGE_BIT,
             L"a missing large-page bit on a two-MiB leaf is refused");

    // Permissions: write without read / all zeros / missing execute-only.
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(
                 0x8000000012345032ULL, 0, kPhysBits39, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_BAD_PERMISSIONS,
             L"a write-without-read leaf is refused");
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(
                 0x8000000012345030ULL, 0, kPhysBits39, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_BAD_PERMISSIONS,
             L"a leaf granting nothing is refused");
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(
                 0x8000000012345034ULL, 0, kPhysBits39, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_OK,
             L"an execute-only leaf is accepted where the encoding exists");
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(
                 0x8000000012345034ULL, 0, kPhysBits39, 0) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_BAD_PERMISSIONS,
             L"an execute-only leaf is refused where the encoding does not exist");

    // Memory type: 0x10 = (2<<3), 0x38 = (7<<3).
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(
                 0x8000000012345017ULL, 0, kPhysBits39, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_BAD_MEMORY_TYPE,
             L"leaf memory type 2 is refused");
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(
                 0x800000001234503FULL, 0, kPhysBits39, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_BAD_MEMORY_TYPE,
             L"leaf memory type 7 is refused");

    // Alignment: The frame for 0x80000000401000B7 is 0x40100000, aligned only to 1 MiB.
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(
                 0x80000000401000B7ULL, 1, kPhysBits39, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_BAD_ALIGNMENT,
             L"a two-MiB leaf whose frame is not two-MiB aligned is refused");

    // Physical width: frame 0x10000000000 corresponds to bit 40.
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(
                 0x8000010000000037ULL, 0, kPhysBits39, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_BAD_PHYS_WIDTH,
             L"a frame bit above MAXPHYADDR is refused");
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(
                 0x8000010000000037ULL, 0, 41U, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_OK,
             L"the same frame is accepted on a wider implementation");

    // Maximum physical address boundaries: 0x000FFFFFFFFFF000 is the highest 4KiB frame under a 52-bit implementation.
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(
                 0x800FFFFFFFFFF037ULL, 0, 52U, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_OK,
             L"the highest four-KiB frame is accepted at 52 physical bits");
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(
                 0x800FFFFFFFFFF037ULL, 0, 51U, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_BAD_PHYS_WIDTH,
             L"the same frame is refused at 51 physical bits");

    // Bits 62:52, which this driver never uses (bit 57 is placed here).
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(
                 kSmallLeaf | (1ULL << 57), 0, kPhysBits39, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_BAD_RESERVED,
             L"a bit in the unused 62:52 range is refused");
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(
                 kSmallLeaf | (1ULL << 52), 0, kPhysBits39, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_BAD_RESERVED,
             L"bit 52 is inside the refused range");
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(
                 kSmallLeaf | (1ULL << 62), 0, kPhysBits39, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_BAD_RESERVED,
             L"bit 62 is inside the refused range");
    // Bit 63 is suppress-#VE and must still be accepted.
    s.expect((kSmallLeaf & (1ULL << 63)) != 0ULL &&
                 KswordArkHvmEptSwLeafIsWellFormed(
                     kSmallLeaf, 0, kPhysBits39, 1) ==
                     KSWORD_ARK_HVM_EPTSW_LEAF_OK,
             L"bit 63 is suppress-#VE and stays outside the refused range");

    // Physical width that cannot come from CPUID.
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(kSmallLeaf, 0, 0U, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_BAD_PARAMETER,
             L"a zero physical width is a parameter error");
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(kSmallLeaf, 0, 31U, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_BAD_PARAMETER,
             L"a physical width below the architectural floor is a parameter error");
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(kSmallLeaf, 0, 53U, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_BAD_PARAMETER,
             L"a physical width above 52 is a parameter error");
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(kSmallLeaf, 0, 32U, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_OK,
             L"32 physical bits is the architectural floor and is a legal width");
    // 32-bit implementation: bit 32's frame is just out of bounds; in the 33-bit implementation, the same frame is valid.
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(
                 0x8000000100000037ULL, 0, 32U, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_BAD_PHYS_WIDTH,
             L"a frame needing bit 32 is refused on a 32-bit implementation");
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(
                 0x8000000100000037ULL, 0, 33U, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_OK,
             L"the same frame is accepted once the implementation has 33 bits");
}

// ---------------------------------------------------------------------------
// EPTP field.
// ---------------------------------------------------------------------------

void testEptpComposition(ksword_tests::Suite& s) {
    // 0x01000000 | 6 | (3 << 3) = 0x0100001E。
    s.expect(KswordArkHvmEptSwComposeEptp(0x01000000ULL, 6ULL, 4U, 0) == kBaseEptp,
             L"a four-level write-back EPTP encodes walk length three");
    s.expect(KswordArkHvmEptSwComposeEptp(0x01000000ULL, 6ULL, 4U, 1) == kBaseEptpAd,
             L"the accessed/dirty enable is bit 6");
    // The level field stores level minus one: writing 4 yields 0x20 instead of 0x18.
    s.expect(KswordArkHvmEptSwComposeEptp(0x01000000ULL, 6ULL, 5U, 0) == 0x01000026ULL,
             L"five levels encode as field value four");
    s.expect(KswordArkHvmEptSwComposeEptp(0x01000000ULL, 6ULL, 0U, 0) == 0ULL,
             L"zero levels cannot be encoded and returns the never-legal value zero");
    s.expect(KswordArkHvmEptSwComposeEptp(0x01000000ULL, 6ULL, 9U, 0) == 0ULL,
             L"nine levels exceed the three-bit field and are refused");
    s.expect(KswordArkHvmEptSwComposeEptp(0x01000000ULL, 6ULL, 8U, 0) == 0x0100003EULL,
             L"eight levels is the largest encodable value");
    // An unaligned root spills lower bits into the memory type and walk length fields.
    s.expect(KswordArkHvmEptSwComposeEptp(0x01000FFFULL, 6ULL, 4U, 0) == kBaseEptp,
             L"an unaligned root cannot corrupt the memory type or walk length");
    // Memory type uses only 3 bits: the lower 3 bits of 0xFF are 7, and the lower 3 bits of 0xF6 are 6 (equal to the base).
    // Excess high bits must be masked; otherwise, they would fall into the level field and A/D bits.
    s.expect(KswordArkHvmEptSwComposeEptp(0x01000000ULL, 0xFFULL, 4U, 0) == 0x0100001FULL,
             L"only bits 2:0 of the memory type reach the pointer");
    s.expect(KswordArkHvmEptSwComposeEptp(0x01000000ULL, 0xF6ULL, 4U, 0) == kBaseEptp,
             L"memory type bits above 2:0 cannot reach the walk-length field or the A/D bit");
}

void testEptpDecomposition(ksword_tests::Suite& s) {
    s.expect(KswordArkHvmEptSwEptpRoot(kBaseEptpAd) == 0x01000000ULL,
             L"the EPTP root is bits 51:12");
    s.expect(KswordArkHvmEptSwEptpMemoryType(kBaseEptpAd) == 6ULL,
             L"the EPTP memory type is bits 2:0");
    // Forgetting to add one during parsing and forgetting to subtract one during synthesis are two sides of the same error.
    s.expect(KswordArkHvmEptSwEptpWalkLevels(kBaseEptp) == 4U,
             L"walk field three decodes back to four levels");
    s.expect(KswordArkHvmEptSwEptpWalkLevels(0x01000026ULL) == 5U,
             L"walk field four decodes back to five levels");
    s.expect(KswordArkHvmEptSwEptpWalkLevels(0x01000006ULL) == 1U,
             L"walk field zero decodes back to one level, never to zero");
    s.expect(KswordArkHvmEptSwEptpHasAccessedDirty(kBaseEptpAd) == 1,
             L"accessed/dirty is reported when bit 6 is set");
    s.expect(KswordArkHvmEptSwEptpHasAccessedDirty(kBaseEptp) == 0,
             L"accessed/dirty is not reported when bit 6 is clear");
    s.expect(KswordArkHvmEptSwEp4ta(kBaseEptpAd) == 0x01000000ULL,
             L"EP4TA is the root address and ignores the control bits");
}

void testEptpWellFormed(ksword_tests::Suite& s) {
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(kBaseEptp, kCapWb, kPhysBits39) ==
                 KSWORD_ARK_HVM_EPTSW_EPTP_OK,
             L"the base pointer is accepted on a write-back four-level machine");
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(kBaseEptpAd, kCapWb, kPhysBits39) ==
                 KSWORD_ARK_HVM_EPTSW_EPTP_OK,
             L"accessed/dirty is accepted when the capability advertises it");
    // A/D bit is set despite lacking support capability — VM entry will fail with only one error code.
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(
                 kBaseEptpAd, kCapWb & ~0x0000000000200000ULL, kPhysBits39) ==
                 KSWORD_ARK_HVM_EPTSW_EPTP_BAD_AD,
             L"accessed/dirty without the capability is refused");
    // Note: UC is unavailable without the UC capability bit.
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(0x01000018ULL, kCapWb, kPhysBits39) ==
                 KSWORD_ARK_HVM_EPTSW_EPTP_BAD_MEMORY_TYPE,
             L"an uncacheable EPTP is refused without the UC capability");
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(0x01000018ULL, kCapWbUc, kPhysBits39) ==
                 KSWORD_ARK_HVM_EPTSW_EPTP_OK,
             L"an uncacheable EPTP is accepted with the UC capability");
    // EPTP only accepts UC and WB; this is not the same encoding scheme as the five types of leaf entries.
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(0x0100001CULL, kCapWbUc, kPhysBits39) ==
                 KSWORD_ARK_HVM_EPTSW_EPTP_BAD_MEMORY_TYPE,
             L"write-through is a legal leaf type but never a legal EPTP type");
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(0x0100001BULL, kCapWbUc, kPhysBits39) ==
                 KSWORD_ARK_HVM_EPTSW_EPTP_BAD_MEMORY_TYPE,
             L"EPTP memory type three is reserved");
    // Level count.
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(0x01000026ULL, kCapWb, kPhysBits39) ==
                 KSWORD_ARK_HVM_EPTSW_EPTP_BAD_WALK,
             L"a five-level walk is refused");
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(
                 kBaseEptp, kCapWb & ~0x0000000000000040ULL, kPhysBits39) ==
                 KSWORD_ARK_HVM_EPTSW_EPTP_BAD_WALK,
             L"a four-level walk is refused when the capability does not advertise it");
    // Reserved bits 11:7 in the lower bits.
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(kBaseEptp | 0x80ULL, kCapWb, kPhysBits39) ==
                 KSWORD_ARK_HVM_EPTSW_EPTP_BAD_RESERVED,
             L"bit 7 is reserved in the EPT pointer");
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(kBaseEptp | 0x800ULL, kCapWb, kPhysBits39) ==
                 KSWORD_ARK_HVM_EPTSW_EPTP_BAD_RESERVED,
             L"bit 11 is reserved in the EPT pointer");
    // Root is zero: the field predicate doesn't cover it, but it can only come from 'slot not filled'.
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(0x0000001EULL, kCapWb, kPhysBits39) ==
                 KSWORD_ARK_HVM_EPTSW_EPTP_BAD_ROOT,
             L"a pointer whose root is zero is refused rather than walked");
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(0ULL, kCapWb, kPhysBits39) ==
                 KSWORD_ARK_HVM_EPTSW_EPTP_BAD_ROOT,
             L"an all-zero EPT pointer is never legal");
    // Physical width.
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(
                 0x000001000000001EULL, kCapWb, kPhysBits39) ==
                 KSWORD_ARK_HVM_EPTSW_EPTP_BAD_PHYS_WIDTH,
             L"a root bit above MAXPHYADDR is refused");
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(
                 0x000001000000001EULL, kCapWb, 41U) ==
                 KSWORD_ARK_HVM_EPTSW_EPTP_OK,
             L"the same root is accepted on a wider implementation");
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(kBaseEptp, kCapWb, 0U) ==
                 KSWORD_ARK_HVM_EPTSW_EPTP_BAD_PARAMETER,
             L"a zero physical width is a parameter error for the pointer too");
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(kBaseEptp, kCapWb, 53U) ==
                 KSWORD_ARK_HVM_EPTSW_EPTP_BAD_PARAMETER,
             L"a physical width above 52 is a parameter error for the pointer too");

    // --- Bits 63:52 are architecture-reserved and must be zero, regardless of native implementation width. The previous
    // version lacked an independent check for this, relying solely on the side effect of widthMask; the leaf path used a
    // narrower PHYSICAL_MASK & ~(...) combined with a separate check. Since the two paths have different shapes, if either path
    // unifies the EPTP to the leaf-style writing, bits 63:52 will be completely unchecked, causing VM entry to fail directly
    // with only an error code. Therefore, on the **widest machine** (MAXPHYADDR = 52), every bit is strictly enforced here:
    // On a 52-bit machine, `widthMask` is exactly `0xFFF0000000000000`. If the check relied solely on the width
    // mask, the following three cases would return `BAD_PHYS_WIDTH` instead of `BAD_RESERVED_HIGH`. Conversely,
    // if someone narrows the width mask to a leaf-like shape, they would directly return `EPTP_OK`.
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(
                 kBaseEptp | 0x0010000000000000ULL, kCapWb, 52U) ==
                 KSWORD_ARK_HVM_EPTSW_EPTP_BAD_RESERVED_HIGH,
             L"bit 52 of an EPT pointer is reserved on a 52-bit machine");
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(
                 kBaseEptp | 0x0080000000000000ULL, kCapWb, 52U) ==
                 KSWORD_ARK_HVM_EPTSW_EPTP_BAD_RESERVED_HIGH,
             L"bit 55 of an EPT pointer is reserved on a 52-bit machine");
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(
                 kBaseEptp | 0x8000000000000000ULL, kCapWb, 52U) ==
                 KSWORD_ARK_HVM_EPTSW_EPTP_BAD_RESERVED_HIGH,
             L"bit 63 of an EPT pointer is reserved even though it is legal in a leaf");
    // On narrow machines, the reserved-bit check also triggers first, not the width check. The order of these
    // two checks is fixed; otherwise, regressions where 'the other item is wrong' could escape the entire class.
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(
                 kBaseEptp | 0x8000000000000000ULL, kCapWb, kPhysBits39) ==
                 KSWORD_ARK_HVM_EPTSW_EPTP_BAD_RESERVED_HIGH,
             L"the reserved-high verdict wins over the width verdict on a narrow machine");
    // Preserve high bits to avoid overlap with the valid root address: on a 52-bit machine, the root at bit 51 remains valid.
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(
                 0x0008000000000000ULL | 0x1EULL, kCapWb, 52U) ==
                 KSWORD_ARK_HVM_EPTSW_EPTP_OK,
             L"bit 51 is the top of the root field and stays legal on a 52-bit machine");
    // The mask value itself: bits 63:52 = 0xFFF0000000000000, with no extra or missing bits.
    s.expect(KSWORD_ARK_HVM_EPTSW_EPTP_RESERVED_HIGH == 0xFFF0000000000000ULL,
             L"the EPTP reserved-high mask is exactly bits 63:52");
    s.expect(KSWORD_ARK_HVM_EPTSW_RESERVED_HIGH == 0x7FF0000000000000ULL,
             L"the leaf reserved-high mask is bits 62:52 because bit 63 is suppress-#VE");

    // --- Relationship with the criteria in KswordArkHvmControls.h (cross-header consistency, finding 8) --- The
    // same EPTP must never yield two different answers within a single driver depending on which helper is called.
    // The criterion for this file is the **strictly stronger** one, so the implication direction must be fixed.
    // EptSw says OK => Controls says valid. The reverse does not hold; that is precisely why this file has three distinct value categories.
    {
        const std::uint64_t kImplicationSamples[] = {
            kBaseEptp,                       // Typical base
            kBaseEptpAd,                     // Enable A/D
            0x01000018ULL,                   // UC type
            0x000001000000001EULL,           // Valid high-order root on wide machines.
            0x0008000000000000ULL | 0x1EULL, // Root at bit 51
        };
        bool implicationHolds = true;
        for (const std::uint64_t kSample : kImplicationSamples) {
            for (std::uint32_t bits = 32U; bits <= 52U; ++bits) {
                if (KswordArkHvmEptSwEptpIsWellFormed(kSample, kCapWbUc, bits) ==
                        KSWORD_ARK_HVM_EPTSW_EPTP_OK &&
                    KswordArkHvmEptpIsValid(kSample, kCapWbUc, bits) == 0) {
                    implicationHolds = false;
                }
            }
        }
        s.expect(implicationHolds,
                 L"every pointer this file accepts is also accepted by the shared validator");
        // Each of the three reversed differences is explicitly tested to prevent someone from later 'simplifying' this file into the Controls variant.
        s.expect(KswordArkHvmEptSwEptpIsWellFormed(0x0000001EULL, kCapWb, 39U) ==
                     KSWORD_ARK_HVM_EPTSW_EPTP_BAD_ROOT &&
                     KswordArkHvmEptpIsValid(0x0000001EULL, kCapWb, 39UL) != 0,
                 L"a zero root is refused here although the shared validator accepts it");
        // Root 0xFF000 fits in 20 bits, so the Controls check passes; this file rejects based on the CPUID
        // architecture lower bound of 32—a 20-bit MAXPHYADDR can only result from reading the register incorrectly.
        s.expect(KswordArkHvmEptSwEptpIsWellFormed(0x000FF01EULL, kCapWb, 20U) ==
                     KSWORD_ARK_HVM_EPTSW_EPTP_BAD_PARAMETER &&
                     KswordArkHvmEptpIsValid(0x000FF01EULL, kCapWb, 20UL) != 0,
                 L"a physical width below 32 is refused here although the shared one allows it");
        s.expect(KswordArkHvmEptSwEptpIsWellFormed(
                     kBaseEptp | 0x8000000000000000ULL, kCapWb, 52U) ==
                     KSWORD_ARK_HVM_EPTSW_EPTP_BAD_RESERVED_HIGH,
                 L"bit 63 is refused here by a dedicated verdict, not by a side effect");
    }
}

void testEptpRebase(ksword_tests::Suite& s) {
    // 0x02000000 | (0x0100005E & ~PHYS) = 0x0200005E。
    const std::uint64_t kDerived =
        KswordArkHvmEptSwRebaseEptp(kBaseEptpAd, 0x02000000ULL);
    s.expect(kDerived == 0x0200005EULL,
             L"rebasing replaces only the root address");
    // Derived, not synthesized: control bits must match the base bitwise; otherwise, memory type/level/A-D
    // would have a second source of truth, while VM entry returns only a single error code.
    s.expect((kDerived & ~KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK) ==
                 (kBaseEptpAd & ~KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK),
             L"a derived pointer keeps every control bit of its source");
    s.expect(KswordArkHvmEptSwEptpMemoryType(kDerived) ==
                 KswordArkHvmEptSwEptpMemoryType(kBaseEptpAd) &&
                 KswordArkHvmEptSwEptpWalkLevels(kDerived) ==
                     KswordArkHvmEptSwEptpWalkLevels(kBaseEptpAd) &&
                 KswordArkHvmEptSwEptpHasAccessedDirty(kDerived) ==
                     KswordArkHvmEptSwEptpHasAccessedDirty(kBaseEptpAd),
             L"memory type, walk length and accessed/dirty survive the rebase");
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(kDerived, kCapWb, kPhysBits39) ==
                 KswordArkHvmEptSwEptpIsWellFormed(kBaseEptpAd, kCapWb, kPhysBits39),
             L"a derived pointer is accepted exactly when its source is");
    s.expect(KswordArkHvmEptSwRebaseEptp(kBaseEptpAd, 0x02000FFFULL) == kDerived,
             L"an unaligned new root cannot corrupt the control bits");
    s.expect(KswordArkHvmEptSwEptpRoot(kDerived) == 0x02000000ULL,
             L"the derived pointer walks the new root");
}

void testSwitchInvalidation(ksword_tests::Suite& s) {
    const std::uint64_t kSecondary =
        KswordArkHvmEptSwRebaseEptp(kBaseEptp, 0x02000000ULL);
    // Switching roots changes EP4TA; cache entries are non-aliasing.
    // This is the sole basis for 'no INVEPT after switching EPTP'.
    s.expect(KswordArkHvmEptSwSwitchNeedsInvalidation(kBaseEptp, kSecondary) == 0,
             L"switching between two roots needs no explicit invalidation");
    s.expect(KswordArkHvmEptSwSwitchNeedsInvalidation(kSecondary, kBaseEptp) == 0,
             L"the reverse switch needs no explicit invalidation either");
    // Same root: the switch is a hardware no-op, and the same instruction will always re-fault.
    s.expect(KswordArkHvmEptSwSwitchNeedsInvalidation(kBaseEptp, kBaseEptp) == 1,
             L"switching to the same root changes no tag and is flagged");
    // Only flip the 'sub-level' shared tag created by A/D modification — this is the most plausible yet completely invalid construction error.
    s.expect(KswordArkHvmEptSwSwitchNeedsInvalidation(kBaseEptp, kBaseEptpAd) == 1,
             L"two pointers differing only in control bits share a tag and are flagged");
}

// ---------------------------------------------------------------------------
// INVEPT descriptor
// ---------------------------------------------------------------------------

void testInveptTypeSupport(ksword_tests::Suite& s) {
    s.expect(KswordArkHvmEptSwInveptTypeSupported(
                 KSWORD_ARK_HVM_EPTSW_INVEPT_SINGLE, kCapInvept) == 1,
             L"single-context INVEPT is reported when bits 20 and 25 are set");
    s.expect(KswordArkHvmEptSwInveptTypeSupported(
                 KSWORD_ARK_HVM_EPTSW_INVEPT_ALL, kCapInvept) == 1,
             L"all-context INVEPT is reported when bits 20 and 26 are set");
    // Without the INVEPT instruction itself, discussing the type is meaningless.
    s.expect(KswordArkHvmEptSwInveptTypeSupported(
                 KSWORD_ARK_HVM_EPTSW_INVEPT_SINGLE,
                 kCapInvept & ~0x0000000000100000ULL) == 0,
             L"no type is supported without the INVEPT instruction bit");
    s.expect(KswordArkHvmEptSwInveptTypeSupported(
                 KSWORD_ARK_HVM_EPTSW_INVEPT_SINGLE,
                 kCapInvept & ~0x0000000002000000ULL) == 0,
             L"single-context is refused when only all-context is advertised");
    s.expect(KswordArkHvmEptSwInveptTypeSupported(
                 KSWORD_ARK_HVM_EPTSW_INVEPT_ALL,
                 kCapInvept & ~0x0000000002000000ULL) == 1,
             L"all-context still works when single-context is missing");
    s.expect(KswordArkHvmEptSwInveptTypeSupported(0U, kCapInvept) == 0,
             L"type zero is reserved");
    s.expect(KswordArkHvmEptSwInveptTypeSupported(3U, kCapInvept) == 0,
             L"type three is reserved");

    // Same criterion, but the type number is written as a literal. Since all the previous lines used
    // symbols, swapping the values of INVEPT_SINGLE and INVEPT_ALL would still make them all
    // pass—including the one named 'Reject single-context when only advertising all-context'. Here, 1
    // and 2 are values to be loaded into registers for INVEPT, not internal identifiers in this file.
    s.expect(KswordArkHvmEptSwInveptTypeSupported(
                 1U, kCapInvept & ~0x0000000002000000ULL) == 0,
             L"type one is refused when capability bit 25 (single-context) is clear");
    s.expect(KswordArkHvmEptSwInveptTypeSupported(
                 2U, kCapInvept & ~0x0000000002000000ULL) == 1,
             L"type two still works when capability bit 25 is clear");
    s.expect(KswordArkHvmEptSwInveptTypeSupported(
                 2U, kCapInvept & ~0x0000000004000000ULL) == 0,
             L"type two is refused when capability bit 26 (all-context) is clear");
    s.expect(KswordArkHvmEptSwInveptTypeSupported(
                 1U, kCapInvept & ~0x0000000004000000ULL) == 1,
             L"type one still works when capability bit 26 is clear");
}

void testInveptDescriptor(ksword_tests::Suite& s) {
    KSWORD_ARK_HVM_EPTSW_INVEPT_DESCRIPTOR descriptor;

    descriptor.Eptp = 0xDEADBEEFDEADBEEFULL;
    descriptor.Reserved = 0xDEADBEEFDEADBEEFULL;
    s.expect(KswordArkHvmEptSwBuildInveptDescriptor(
                 KSWORD_ARK_HVM_EPTSW_INVEPT_SINGLE, kBaseEptp,
                 kCapInvept, &descriptor) == 1,
             L"a single-context descriptor is built for a real hierarchy");
    // qword 0 is the **full** EPT pointer, not the root address. Masking the lower bits 'works' until it no longer
    // does, at which point the failure manifests as an ineffective update where the guest reads stale translations.
    s.expect(descriptor.Eptp == kBaseEptp,
             L"the descriptor carries the full EPT pointer, not just the root");
    s.expect(descriptor.Eptp != KswordArkHvmEptSwEptpRoot(kBaseEptp),
             L"the descriptor is distinguishable from a root-only encoding");
    s.expect(descriptor.Reserved == 0ULL,
             L"descriptor qword one is architecturally zero");

    descriptor.Eptp = 0xDEADBEEFDEADBEEFULL;
    descriptor.Reserved = 0xDEADBEEFDEADBEEFULL;
    s.expect(KswordArkHvmEptSwBuildInveptDescriptor(
                 KSWORD_ARK_HVM_EPTSW_INVEPT_ALL, kBaseEptp,
                 kCapInvept, &descriptor) == 1,
             L"an all-context descriptor is built");
    s.expect(descriptor.Eptp == 0ULL && descriptor.Reserved == 0ULL,
             L"an all-context descriptor is fully zeroed rather than left misleading");

    // Must zero on failure: callers ignoring the return value that execute INVEPT in-place may
    // treat residual stack data as a valid EPTP to invalidate, which could belong to any hierarchy.
    descriptor.Eptp = 0xDEADBEEFDEADBEEFULL;
    descriptor.Reserved = 0xDEADBEEFDEADBEEFULL;
    s.expect(KswordArkHvmEptSwBuildInveptDescriptor(
                 3U, kBaseEptp, kCapInvept, &descriptor) == 0,
             L"a reserved INVEPT type is refused");
    s.expect(descriptor.Eptp == 0ULL && descriptor.Reserved == 0ULL,
             L"a refused build leaves no executable residue in the descriptor");

    descriptor.Eptp = 0xDEADBEEFDEADBEEFULL;
    descriptor.Reserved = 0xDEADBEEFDEADBEEFULL;
    s.expect(KswordArkHvmEptSwBuildInveptDescriptor(
                 KSWORD_ARK_HVM_EPTSW_INVEPT_SINGLE, 0ULL,
                 kCapInvept, &descriptor) == 0,
             L"single-context with an all-zero pointer is refused");
    s.expect(descriptor.Eptp == 0ULL,
             L"the refused zero-pointer build also clears the descriptor");
    s.expect(KswordArkHvmEptSwBuildInveptDescriptor(
                 KSWORD_ARK_HVM_EPTSW_INVEPT_SINGLE, 0x0000001EULL,
                 kCapInvept, &descriptor) == 0,
             L"single-context with a rootless pointer is refused");
    s.expect(KswordArkHvmEptSwBuildInveptDescriptor(
                 KSWORD_ARK_HVM_EPTSW_INVEPT_SINGLE, kBaseEptp,
                 kCapInvept & ~0x0000000000100000ULL, &descriptor) == 0,
             L"a descriptor is refused when INVEPT is not advertised");
    s.expect(KswordArkHvmEptSwBuildInveptDescriptor(
                 KSWORD_ARK_HVM_EPTSW_INVEPT_SINGLE, kBaseEptp,
                 kCapInvept, nullptr) == 0,
             L"a null descriptor pointer is refused rather than dereferenced");

    // Reiterate the two most critical differences using literal type numbers: Type 1 must specify EPTP; Type 2 must be all zeros.
    // After swapping the two values, requesting all-context triggers a single descriptor with all zeros. That single
    // request fails and clears nothing, leaving the guest to continue using stale translations with no symptoms.
    descriptor.Eptp = 0xDEADBEEFDEADBEEFULL;
    descriptor.Reserved = 0xDEADBEEFDEADBEEFULL;
    s.expect(KswordArkHvmEptSwBuildInveptDescriptor(
                 1U, kBaseEptp, kCapInvept, &descriptor) == 1 &&
                 descriptor.Eptp == kBaseEptp,
             L"INVEPT type one fills the descriptor with the full pointer");
    descriptor.Eptp = 0xDEADBEEFDEADBEEFULL;
    descriptor.Reserved = 0xDEADBEEFDEADBEEFULL;
    s.expect(KswordArkHvmEptSwBuildInveptDescriptor(
                 2U, kBaseEptp, kCapInvept, &descriptor) == 1 &&
                 descriptor.Eptp == 0ULL && descriptor.Reserved == 0ULL,
             L"INVEPT type two leaves the descriptor fully zeroed");
    // Type 1 must reject a pointer with a root of zero; Type 2 ignores the pointer and succeeds regardless.
    s.expect(KswordArkHvmEptSwBuildInveptDescriptor(
                 1U, 0ULL, kCapInvept, &descriptor) == 0,
             L"INVEPT type one refuses a pointer that names no hierarchy");
    s.expect(KswordArkHvmEptSwBuildInveptDescriptor(
                 2U, 0ULL, kCapInvept, &descriptor) == 1,
             L"INVEPT type two ignores the pointer because it invalidates everything");
}

void testPreEntryInvalidation(ksword_tests::Suite& s) {
    // Each second-level structure is reclaimed non-paged memory, potentially carrying stale tags from its previous
    // residency. During this residency, no INVEPT will ever be issued again; this pre-entry is its only opportunity.
    s.expect(KswordArkHvmEptSwPreEntryInvalidationCount(8U, 1) == 8U,
             L"eight leaves need eight pre-entry invalidations when the base is already live");
    s.expect(KswordArkHvmEptSwPreEntryInvalidationCount(8U, 0) == 9U,
             L"a base that is not already live adds one more");
    s.expect(KswordArkHvmEptSwPreEntryInvalidationCount(1U, 1) == 1U,
             L"one leaf needs one pre-entry invalidation");
    s.expect(KswordArkHvmEptSwPreEntryInvalidationCount(0U, 1) == 0U,
             L"no leaves means no secondary hierarchies and nothing to invalidate");
    s.expect(KswordArkHvmEptSwPreEntryInvalidationCount(0U, 0) == 0U,
             L"the feature-off path issues no invalidation at all");
    // On both sides of the protocol limit: 32 leaves are valid -> 32 (base already running) or 33 (base also needs flushing).
    s.expect(KswordArkHvmEptSwPreEntryInvalidationCount(32U, 1) == 32ULL,
             L"a full leaf set at the protocol limit is counted, not refused");
    s.expect(KswordArkHvmEptSwPreEntryInvalidationCount(32U, 0) == 33ULL,
             L"a full leaf set plus a cold base is thirty-three invalidations");
    // 33 leaf out of bounds: rejected like SecondaryPageCost, HierarchyCount,
    // IndexFromLeaf, and Decide; otherwise, the same upper limit would have a gap.
    s.expect(KswordArkHvmEptSwPreEntryInvalidationCount(33U, 1) == 0ULL,
             L"a leaf count above the protocol limit is refused here as everywhere else");
    // **0xFFFFFFFF must return 0 because it is rejected, not because of wrapping.** In the previous version,
    // LeafCount + 1 wrapped to 0 in uint32, and 0 happens to be the valid answer for 'no sub-levels to
    // flush': the caller would then carry stale EP4TA tags from every set of reclaimed memory into the guest.
    s.expect(KswordArkHvmEptSwPreEntryInvalidationCount(0xFFFFFFFFU, 0) == 0ULL,
             L"a wildly out-of-range leaf count is refused instead of wrapping to zero");
    s.expect(KswordArkHvmEptSwPreEntryInvalidationCount(0xFFFFFFFFU, 1) == 0ULL,
             L"the same holds when the base is already live");
    // The return type must be wider than 32 bits; otherwise, the wrap-around mentioned above can occur at any time.
    s.expect(sizeof(KswordArkHvmEptSwPreEntryInvalidationCount(1U, 0)) >= 8U,
             L"the count is carried in a 64-bit type so the sum cannot wrap");
    // The relationship with HierarchyCount is a manually verified identity, not derived from the implementation:
    // Number of sets to flush when the base is not ready = total hierarchy count = 1 + leaf count.
    s.expect(KswordArkHvmEptSwPreEntryInvalidationCount(8U, 0) ==
                 (unsigned long long)KswordArkHvmEptSwHierarchyCount(8U),
             L"a cold base needs exactly one invalidation per hierarchy");
}

// ---------------------------------------------------------------------------
// Index arithmetic
// ---------------------------------------------------------------------------

void testIndexArithmetic(ksword_tests::Suite& s) {
    // Construct manually from the selected four-level indices:
    //   5   << 39 = 0x00028000000000
    //   300 << 30 = 0x000004B00000000
    //   17  << 21 = 0x00000002200000
    //   400 << 12 = 0x00000000190000
    //   Offset 0x00000000000123
    constexpr std::uint64_t kGpa = 0x000002CB02390123ULL;

    s.expect(KswordArkHvmEptSwPml4Index(kGpa) == 5U,
             L"bits 47:39 select the PML4 slot");
    s.expect(KswordArkHvmEptSwPdptIndex(kGpa) == 300U,
             L"bits 38:30 select the one-GiB window");
    s.expect(KswordArkHvmEptSwPdIndex(kGpa) == 17U,
             L"bits 29:21 select the two-MiB leaf");
    s.expect(KswordArkHvmEptSwPtIndex(kGpa) == 400U,
             L"bits 20:12 select the four-KiB page inside a split");
    s.expect(KswordArkHvmEptSwLeafBase(kGpa) == 0x000002CB02200000ULL,
             L"the two-MiB leaf base clears bits 20:0");
    s.expect(KswordArkHvmEptSwPageBase(kGpa) == 0x000002CB02390000ULL,
             L"the page base clears bits 11:0");
    // Decomposition and reconstruction are inverse operations: this is the sole evidence that "which leaf table to copy" and "which cell to modify" are self-consistent.
    s.expect(KswordArkHvmEptSwComposeGuestPhysical(5U, 300U, 17U, 400U) ==
                 0x000002CB02390000ULL,
             L"the four indices recompose the page base");
    s.expect(KswordArkHvmEptSwComposeGuestPhysical(
                 KswordArkHvmEptSwPml4Index(kGpa),
                 KswordArkHvmEptSwPdptIndex(kGpa),
                 KswordArkHvmEptSwPdIndex(kGpa),
                 KswordArkHvmEptSwPtIndex(kGpa)) ==
                 KswordArkHvmEptSwPageBase(kGpa),
             L"decomposition and recomposition are inverse on the four-KiB grid");

    // All 1s: Without masking the 9 bits, the PML4 index would become a huge number and exceed the table bounds.
    s.expect(KswordArkHvmEptSwPml4Index(0xFFFFFFFFFFFFFFFFULL) == 511U &&
                 KswordArkHvmEptSwPdptIndex(0xFFFFFFFFFFFFFFFFULL) == 511U &&
                 KswordArkHvmEptSwPdIndex(0xFFFFFFFFFFFFFFFFULL) == 511U &&
                 KswordArkHvmEptSwPtIndex(0xFFFFFFFFFFFFFFFFULL) == 511U,
             L"every index is masked to nine bits even for an all-ones address");
    // Upper bound of 52-bit physical address.
    s.expect(KswordArkHvmEptSwPml4Index(0x000FFFFFFFFFFFFFULL) == 511U &&
                 KswordArkHvmEptSwPtIndex(0x000FFFFFFFFFFFFFULL) == 511U,
             L"the highest 52-bit address decomposes to the last slots");
    // Zero and the first 2 MiB boundary.
    s.expect(KswordArkHvmEptSwPml4Index(0ULL) == 0U &&
                 KswordArkHvmEptSwPdptIndex(0ULL) == 0U &&
                 KswordArkHvmEptSwPdIndex(0ULL) == 0U &&
                 KswordArkHvmEptSwPtIndex(0ULL) == 0U,
             L"address zero decomposes to slot zero at every level");
    s.expect(KswordArkHvmEptSwPdIndex(0x1FFFFFULL) == 0U &&
                 KswordArkHvmEptSwPdIndex(0x200000ULL) == 1U,
             L"the two-MiB index steps exactly at the leaf boundary");
    s.expect(KswordArkHvmEptSwPtIndex(0xFFFULL) == 0U &&
                 KswordArkHvmEptSwPtIndex(0x1000ULL) == 1U,
             L"the four-KiB index steps exactly at the page boundary");
    s.expect(KswordArkHvmEptSwLeafBase(0x1FFFFFULL) == 0ULL &&
                 KswordArkHvmEptSwLeafBase(0x200000ULL) == 0x200000ULL,
             L"the leaf base rounds down on both sides of the boundary");
}

void testEntryAddress(ksword_tests::Suite& s) {
    // 511 * 8 = 4088 = 0xFF8: The last entry in the table.
    s.expect(KswordArkHvmEptSwEntryAddress(0x23456000ULL, 511U) == 0x23456FF8ULL,
             L"entry 511 is the last eight bytes of the table page");
    s.expect(KswordArkHvmEptSwEntryAddress(0x23456000ULL, 0U) == 0x23456000ULL,
             L"entry zero is the table base");
    s.expect(KswordArkHvmEptSwEntryAddress(0x23456000ULL, 1U) == 0x23456008ULL,
             L"entries are eight bytes apart");
    // Cell 512 falls on byte 0 of the next page, which might be a different table; wrapping does not trigger an error.
    s.expect(KswordArkHvmEptSwEntryAddress(0x23456000ULL, 512U) == 0ULL,
             L"entry 512 is refused instead of wrapping into the next table");
    s.expect(KswordArkHvmEptSwEntryAddress(0x23456000ULL, 0xFFFFFFFFU) == 0ULL,
             L"a wildly out-of-range index is refused");
    // Callers often receive entry values with field bits set rather than clean addresses. Low-order field bits.
    s.expect(KswordArkHvmEptSwEntryAddress(0x23456037ULL, 3U) == 0x23456018ULL,
             L"the table base is masked so low entry bits cannot become address bits");
    // **The high-order field bit must also be masked.** Every leaf item constructed in this file includes bit 63:
    // suppress-#VE. The function's documentation states that the caller can pass the entry value directly.
    // The previous version used ~(PAGE_BYTES-1), which only cleared bits 11:0, leaving bit 63 unchanged in
    // the "physical address". The driver then wrote this astronomical physical address into the table.
    // Manual calculation: Page frame field of 0x8000000023456007 is
    //       0x0000000023456000; offset for entry 3 is 3 * 8 = 24 = 0x18; sum is 0x23456018.
    s.expect(KswordArkHvmEptSwEntryAddress(0x8000000023456007ULL, 3U) ==
                 0x0000000023456018ULL,
             L"suppress-#VE in bit 63 of an entry value never leaks into the address");
    // bits 62:52 similarly: 0x00A0000000000000 falls within the reserved high-order segment.
    // Manual calculation: The page frame field of 0x00A0000023456037 is 0x0000000023456000, and slot 1 adds +8.
    s.expect(KswordArkHvmEptSwEntryAddress(0x00A0000023456037ULL, 1U) ==
                 0x0000000023456008ULL,
             L"reserved bits 62:52 of an entry value never leak into the address either");
    // All-ones: The page frame field is bits 51:12, leaving only 0x000FFFFFFFFFF000; entry 511 equals +0xFF8.
    s.expect(KswordArkHvmEptSwEntryAddress(0xFFFFFFFFFFFFFFFFULL, 511U) ==
                 0x000FFFFFFFFFFFF8ULL,
             L"an all-ones entry value still yields an address inside the physical field");
    // Refusal still wins over masking: out-of-range index returns 0, not a 'masked-clean' error address.
    s.expect(KswordArkHvmEptSwEntryAddress(0x8000000023456007ULL, 512U) == 0ULL,
             L"the out-of-range refusal still wins over the masking");
}

// ---------------------------------------------------------------------------
// Size of the hierarchy set and page overhead
// ---------------------------------------------------------------------------

void testPageCost(ksword_tests::Suite& s) {
    s.expect(KSWORD_ARK_HVM_EPTSW_PATH_PAGES == 4ULL,
             L"one secondary hierarchy is root plus PDPT plus PD plus PT");
    // Shared base mode: 8 leaves = 8 sets of secondary levels × 4 pages = 32 pages = 128 KiB.
    s.expect(KswordArkHvmEptSwSecondaryPageCost(1U, 8U) == 32ULL,
             L"eight leaves on a shared base cost thirty-two pages");
    s.expect(KswordArkHvmEptSwSecondaryPageCost(1U, 1U) == 4ULL,
             L"one leaf on a shared base costs four pages");
    s.expect(KswordArkHvmEptSwSecondaryPageCost(1U, 32U) == 128ULL,
             L"the protocol maximum of thirty-two leaves costs 128 pages");
    // Composite private base: 128 cores x 8 leaves x 4 pages = 4096 pages (excluding the base itself).
    s.expect(KswordArkHvmEptSwSecondaryPageCost(128U, 8U) == 4096ULL,
             L"a private base per processor multiplies the secondary cost by the core count");
    // Out-of-bounds and zero values are rejected before allocation.
    s.expect(KswordArkHvmEptSwSecondaryPageCost(1U, 33U) == 0ULL,
             L"more leaves than the protocol allows is refused before any allocation");
    s.expect(KswordArkHvmEptSwSecondaryPageCost(1U, 0U) == 0ULL,
             L"zero leaves costs nothing and is reported as a refusal");
    s.expect(KswordArkHvmEptSwSecondaryPageCost(0U, 8U) == 0ULL,
             L"zero bases is refused");

    // Base count: This is the switch for the economic viability of the entire solution.
    s.expect(KswordArkHvmEptSwBaseCount(0, 1U) == 1U &&
                 KswordArkHvmEptSwBaseCount(0, 256U) == 1U,
             L"the shared base is one hierarchy no matter how many processors exist");
    s.expect(KswordArkHvmEptSwBaseCount(1, 128U) == 128U,
             L"a private base is one hierarchy per processor");
    s.expect(KswordArkHvmEptSwBaseCount(1, 0U) == 0U,
             L"a private base on zero processors is zero hierarchies");

    // Explicitly pin the invariant that 'the total number of pages under the shared base is independent of the processor count': if someone changes it
    // to 'per-core billing', functionality remains correct, but on a 256-core machine, 32 pages would silently become 8192 pages without detection.
    const std::uint32_t kProcessorCounts[] = { 1U, 2U, 4U, 16U, 64U, 128U, 256U };
    for (const std::uint32_t kProcessorCount : kProcessorCounts) {
        s.expect(KswordArkHvmEptSwSecondaryPageCost(
                     KswordArkHvmEptSwBaseCount(0, kProcessorCount), 8U) == 32ULL,
                 L"the shared-base cost is independent of the processor count");
    }

    // Hierarchy table length: if one short, runtime will read out of bounds by index.
    s.expect(KswordArkHvmEptSwHierarchyCount(8U) == 9U,
             L"eight leaves need nine hierarchies counting the base");
    s.expect(KswordArkHvmEptSwHierarchyCount(1U) == 2U,
             L"one leaf needs the base plus one");
    s.expect(KswordArkHvmEptSwHierarchyCount(32U) == 33U,
             L"the protocol maximum needs thirty-three hierarchies");
    s.expect(KswordArkHvmEptSwHierarchyCount(0U) == 0U,
             L"no leaves means no hierarchy set is built at all");
    s.expect(KswordArkHvmEptSwHierarchyCount(33U) == 0U,
             L"more leaves than the protocol allows builds nothing");

    // On both sides of the budget boundary.
    s.expect(KswordArkHvmEptSwFitsBudget(32ULL, 2048ULL) == 1,
             L"the shared-base cost fits the ledger with room to spare");
    s.expect(KswordArkHvmEptSwFitsBudget(2048ULL, 2048ULL) == 1,
             L"a cost exactly equal to the cap fits");
    s.expect(KswordArkHvmEptSwFitsBudget(2049ULL, 2048ULL) == 0,
             L"one page over the cap does not fit");
    s.expect(KswordArkHvmEptSwFitsBudget(0ULL, 2048ULL) == 0,
             L"a zero cost is a refusal, not a free fit");
    // In composite mode, rejection begins around 47 cores under a 2048-page budget—that is exactly where it should be rejected.
    s.expect(KswordArkHvmEptSwFitsBudget(
                 KswordArkHvmEptSwSecondaryPageCost(64U, 8U), 2048ULL) == 1,
             L"64 processors with a private base still fits at 2048 pages");
    s.expect(KswordArkHvmEptSwFitsBudget(
                 KswordArkHvmEptSwSecondaryPageCost(65U, 8U), 2048ULL) == 0,
             L"65 processors with a private base is refused at 2048 pages");
}

// ---------------------------------------------------------------------------
// Encoding of hierarchical index and leaf number.
// ---------------------------------------------------------------------------

void testIndexEncoding(ksword_tests::Suite& s) {
    // Output parameter type follows the header file (unsigned long), not std::uint32_t:
    // All three shared HVM headers in this family use fundamental types without including <stdint.h>.
    unsigned long index = 0xFFFFFFFFUL;
    unsigned long leaf = 0xFFFFFFFFUL;

    s.expect(KswordArkHvmEptSwIndexIsBase(0U) == 1,
             L"index zero is the base hierarchy");
    s.expect(KswordArkHvmEptSwIndexIsBase(1U) == 0,
             L"index one is already a secondary hierarchy");

    // Must add one to the whole: setting the index equal to the leaf number would make 'the 0th leaf taking the next value' and 'no
    // relaxation at all' resolve to the same value, causing the 0th leaf to be cut in but never cut back out—without any error.
    s.expect(KswordArkHvmEptSwIndexFromLeaf(0U, 8U, &index) == 1 && index == 1U,
             L"leaf zero maps to index one, never to the base index");
    s.expect(KswordArkHvmEptSwIndexFromLeaf(7U, 8U, &index) == 1 && index == 8U,
             L"the last leaf maps to the last index");
    s.expect(KswordArkHvmEptSwIndexFromLeaf(8U, 8U, &index) == 0,
             L"a leaf index equal to the count is refused");
    s.expect(KswordArkHvmEptSwIndexFromLeaf(0U, 0U, &index) == 0,
             L"a zero leaf count has no encodable index");
    s.expect(KswordArkHvmEptSwIndexFromLeaf(0U, 33U, &index) == 0,
             L"a leaf count above the protocol maximum is refused");
    s.expect(KswordArkHvmEptSwIndexFromLeaf(0U, 8U, nullptr) == 0,
             L"a null output pointer is refused rather than dereferenced");

    // Decoding an index with an off-by-one error applies the recovery predicate to an unrelated page.
    s.expect(KswordArkHvmEptSwLeafFromIndex(1U, 8U, &leaf) == 1 && leaf == 0U,
             L"index one decodes back to leaf zero");
    s.expect(KswordArkHvmEptSwLeafFromIndex(8U, 8U, &leaf) == 1 && leaf == 7U,
             L"the last index decodes back to the last leaf");
    s.expect(KswordArkHvmEptSwLeafFromIndex(0U, 8U, &leaf) == 0,
             L"the base index has no leaf and is refused rather than given a sentinel");
    s.expect(KswordArkHvmEptSwLeafFromIndex(9U, 8U, &leaf) == 0,
             L"an index past the hierarchy set is refused");
    s.expect(KswordArkHvmEptSwLeafFromIndex(1U, 0U, &leaf) == 0,
             L"a zero leaf count has no decodable index");
    s.expect(KswordArkHvmEptSwLeafFromIndex(1U, 8U, nullptr) == 0,
             L"a null output pointer is refused on the decode side too");

    // Full round-trip.
    bool roundTripHolds = true;
    for (std::uint32_t candidate = 0U; candidate < 32U; ++candidate) {
        unsigned long encoded = 0UL;
        unsigned long decoded = 0xFFFFFFFFUL;
        if (KswordArkHvmEptSwIndexFromLeaf(candidate, 32U, &encoded) != 1 ||
            encoded != candidate + 1U ||
            KswordArkHvmEptSwIndexIsBase(encoded) != 0 ||
            KswordArkHvmEptSwLeafFromIndex(encoded, 32U, &decoded) != 1 ||
            decoded != candidate) {
            roundTripHolds = false;
        }
    }
    s.expect(roundTripHolds,
             L"every leaf round-trips through a non-base index for the full protocol range");
}

// ---------------------------------------------------------------------------
// Access bits, permission pairs, and grant criteria
// ---------------------------------------------------------------------------

void testAccessMapping(ksword_tests::Suite& s) {
    // The two sets of constants currently have the same values, which is precisely
    // the danger: direct assignment won't error until one side is renumbered.
    s.expect(KswordArkHvmEptSwAccessToLeafBits(
                 KSWORD_ARK_HVM_EPTSW_ACCESS_READ) == KSWORD_ARK_HVM_EPTSW_READ,
             L"protocol read maps to the leaf read bit");
    s.expect(KswordArkHvmEptSwAccessToLeafBits(
                 KSWORD_ARK_HVM_EPTSW_ACCESS_WRITE) == KSWORD_ARK_HVM_EPTSW_WRITE,
             L"protocol write maps to the leaf write bit");
    s.expect(KswordArkHvmEptSwAccessToLeafBits(
                 KSWORD_ARK_HVM_EPTSW_ACCESS_EXECUTE) == KSWORD_ARK_HVM_EPTSW_EXECUTE,
             L"protocol execute maps to the leaf execute bit");
    s.expect(KswordArkHvmEptSwAccessToLeafBits(0x3U) == 0x3ULL,
             L"read plus write maps to both leaf bits");
    s.expect(KswordArkHvmEptSwAccessToLeafBits(0x7U) == 0x7ULL,
             L"all three access classes map to all three leaf bits");
    s.expect(KswordArkHvmEptSwAccessToLeafBits(0U) == 0ULL,
             L"an empty access mask needs no leaf bits");
    s.expect(KswordArkHvmEptSwAccessToLeafBits(0x8U) == 0ULL,
             L"an undefined access bit contributes no leaf permission");

    // The previous assertions are all written as f(SYMBOL) == SYMBOL, ensuring the equality holds even when both sides
    // are renumbered simultaneously—swapping ACCESS_READ and ACCESS_WRITE causes none of them to trigger. Below, both
    // sides are written as literals: protocol bit 0 must map to leaf bit 0, and protocol bit 1 must map to leaf bit 1.
    // The consequence of swapping is not as harmless as 'mixing read and write': CLOAK's secondary value is rw-, and HOOK's primary value is also
    // rw- and R are symmetric in the state machine, so any behavioral assertion
    // cannot detect this error; only numeric assertions can detect it.
    s.expect(KswordArkHvmEptSwAccessToLeafBits(0x1U) == 0x1ULL,
             L"protocol bit 0 maps to leaf bit 0 by value, not merely by symbol");
    s.expect(KswordArkHvmEptSwAccessToLeafBits(0x2U) == 0x2ULL,
             L"protocol bit 1 maps to leaf bit 1 by value");
    s.expect(KswordArkHvmEptSwAccessToLeafBits(0x4U) == 0x4ULL,
             L"protocol bit 2 maps to leaf bit 2 by value");
    s.expect(KswordArkHvmEptSwAccessToLeafBits(0x5U) == 0x5ULL,
             L"a read-execute request maps to leaf bits 0 and 2 by value");
    s.expect(KswordArkHvmEptSwAccessToLeafBits(0x6U) == 0x6ULL,
             L"a write-execute request maps to leaf bits 1 and 2 by value");
    // The grant criteria also use literals: a read-only leaf grants read access but refuses write access.
    s.expect(KswordArkHvmEptSwGrants(0x1ULL, 0x1U) == 1 &&
                 KswordArkHvmEptSwGrants(0x1ULL, 0x2U) == 0,
             L"a read-only leaf grants access bit 0 and refuses access bit 1");
    s.expect(KswordArkHvmEptSwGrants(0x2ULL, 0x2U) == 1 &&
                 KswordArkHvmEptSwGrants(0x2ULL, 0x1U) == 0,
             L"a write-only leaf grants access bit 1 and refuses access bit 0");

    // An empty requirement is never considered satisfied; otherwise, a violation would be treated as 'sufficient at the
    // current level' and allowed, leading to a silent infinite loop after a VMRESUME followed by another violation.
    s.expect(KswordArkHvmEptSwGrants(0x7ULL, 0U) == 0,
             L"a fully permissive leaf still does not grant an empty access");
    s.expect(KswordArkHvmEptSwGrants(0x3ULL, 0x1U) == 1,
             L"read-write grants a read");
    s.expect(KswordArkHvmEptSwGrants(0x3ULL, 0x2U) == 1,
             L"read-write grants a write");
    s.expect(KswordArkHvmEptSwGrants(0x3ULL, 0x4U) == 0,
             L"read-write does not grant an execute");
    s.expect(KswordArkHvmEptSwGrants(0x3ULL, 0x3U) == 1,
             L"read-write grants a combined read and write");
    // All bits must be granted: partial satisfaction still results in a violation.
    s.expect(KswordArkHvmEptSwGrants(0x3ULL, 0x7U) == 0,
             L"a partially satisfying leaf does not grant a combined access");
    s.expect(KswordArkHvmEptSwGrants(0x4ULL, 0x4U) == 1,
             L"execute-only grants an execute");
    s.expect(KswordArkHvmEptSwGrants(0x4ULL, 0x1U) == 0,
             L"execute-only does not grant a read");
    s.expect(KswordArkHvmEptSwGrants(0x4ULL, 0x5U) == 0,
             L"execute-only does not grant a combined read and execute");
    s.expect(KswordArkHvmEptSwGrants(0ULL, 0x1U) == 0,
             L"a leaf granting nothing grants nothing");
}

void testKindPermissions(ksword_tests::Suite& s) {
    std::uint64_t primary = 0ULL;
    std::uint64_t secondary = 0ULL;

    s.expect(KswordArkHvmEptSwKindPermissions(
                 KSWORD_ARK_HVM_EPTSW_KIND_CLOAK, 1, &primary, &secondary) == 1 &&
                 primary == KSWORD_ARK_HVM_EPTSW_EXECUTE &&
                 secondary == (KSWORD_ARK_HVM_EPTSW_READ | KSWORD_ARK_HVM_EPTSW_WRITE),
             L"CLOAK executes the real page and redirects reads and writes");
    s.expect(KswordArkHvmEptSwKindPermissions(
                 KSWORD_ARK_HVM_EPTSW_KIND_HOOK, 1, &primary, &secondary) == 1 &&
                 primary == (KSWORD_ARK_HVM_EPTSW_READ | KSWORD_ARK_HVM_EPTSW_WRITE) &&
                 secondary == KSWORD_ARK_HVM_EPTSW_EXECUTE,
             L"HOOK reads the real page and redirects execution");
    // Unlike the current MTF path, where the secondary value for HOOK degrades to r-x when execute-only is missing (justified by
    // "the window contains only one instruction"), EPTP switching lacks MTF. The secondary level remains effective until reverse
    // access occurs. Using r-x would expose the patch bytes while the hook continues to function normally, producing no symptoms.
    s.expect(KswordArkHvmEptSwKindPermissions(
                 KSWORD_ARK_HVM_EPTSW_KIND_HOOK, 0, &primary, &secondary) == 0,
             L"HOOK is refused without execute-only because r-x would publish the patch");
    s.expect(KswordArkHvmEptSwKindPermissions(
                 KSWORD_ARK_HVM_EPTSW_KIND_CLOAK, 0, &primary, &secondary) == 0,
             L"CLOAK is refused without execute-only because nothing would be hidden");
    s.expect(KswordArkHvmEptSwKindPermissions(0U, 1, &primary, &secondary) == 0,
             L"view kind zero is unknown");
    s.expect(KswordArkHvmEptSwKindPermissions(3U, 1, &primary, &secondary) == 0,
             L"view kind three is unknown");

    // The two lines above use KIND_CLOAK / KIND_HOOK symbols, so swapping the two values still passes all checks.
    // Here, both the kind number and permission value are written as **literals**: the protocol's 1 denotes CLOAK, and
    // CLOAK's primary value must be --x (0x4). Swapping them causes kind = 1 to be served as a true rw- frame; that page
    // becomes permanently readable by all readers—hiding turns into exposure, while hooks and view lists show no anomalies.
    primary = 0ULL;
    secondary = 0ULL;
    s.expect(KswordArkHvmEptSwKindPermissions(1U, 1, &primary, &secondary) == 1 &&
                 primary == 0x4ULL && secondary == 0x3ULL,
             L"protocol kind one is CLOAK: primary --x on the real frame, secondary rw-");
    primary = 0ULL;
    secondary = 0ULL;
    s.expect(KswordArkHvmEptSwKindPermissions(2U, 1, &primary, &secondary) == 1 &&
                 primary == 0x3ULL && secondary == 0x4ULL,
             L"protocol kind two is HOOK: primary rw- on the real frame, secondary --x");
    s.expect(KswordArkHvmEptSwKindPermissions(
                 KSWORD_ARK_HVM_EPTSW_KIND_CLOAK, 1, nullptr, &secondary) == 0 &&
                 KswordArkHvmEptSwKindPermissions(
                     KSWORD_ARK_HVM_EPTSW_KIND_CLOAK, 1, &primary, nullptr) == 0,
             L"a null output pointer is refused rather than dereferenced");

    // The union must cover all three access types; otherwise, a specific access type will never find a
    // valid target, causing a virtualization exit only after running for hours on the target machine.
    s.expect(KswordArkHvmEptSwPairIsTotal(
                 KSWORD_ARK_HVM_EPTSW_EXECUTE,
                 KSWORD_ARK_HVM_EPTSW_READ | KSWORD_ARK_HVM_EPTSW_WRITE) == 1,
             L"the CLOAK pair covers read, write and execute");
    s.expect(KswordArkHvmEptSwPairIsTotal(
                 KSWORD_ARK_HVM_EPTSW_READ | KSWORD_ARK_HVM_EPTSW_WRITE,
                 KSWORD_ARK_HVM_EPTSW_EXECUTE) == 1,
             L"the HOOK pair covers read, write and execute");
    s.expect(KswordArkHvmEptSwPairIsTotal(0x3ULL, 0x3ULL) == 0,
             L"a pair that never grants execute is not total");
    s.expect(KswordArkHvmEptSwPairIsTotal(0x4ULL, 0x4ULL) == 0,
             L"a pair that never grants read or write is not total");
    s.expect(KswordArkHvmEptSwPairIsTotal(0x1ULL, 0x6ULL) == 1,
             L"totality only asks for the union, not for either side alone");
}

// ---------------------------------------------------------------------------
// Exhaustive state machine cases.
// ---------------------------------------------------------------------------

// enumerate the three 'current levels' in exhaustive cases. For the current leaf, 'base' and 'other' represent the same state (the leaf
// takes its primary value), but their targets differ: switching from 'other' to the current leaf also reverts that other leaf to its
// primary value. This is the source of the invariant 'at most one leaf is relaxed at any time', so they must be asserted separately.
enum class ActiveKind { kBase, kThisLeaf, kOtherLeaf };

struct ExhaustiveCase {
    ActiveKind active;
    std::uint32_t viewKind;
    std::uint32_t access;
    std::uint32_t expectedOutcome;
    std::uint32_t expectedNextIndex;   // Meaningful only when SWITCH.
    std::uint32_t expectedReason;      // Meaningful only when REFUSE.
    const wchar_t* label;
};

constexpr std::uint32_t kLeafCount = 4U;
constexpr std::uint32_t kFaultLeaf = 1U;
constexpr std::uint32_t kFaultIndex = 2U;   // kFaultLeaf + 1
constexpr std::uint32_t kOtherIndex = 3U;   // Level of the other leaf: valid and not equal to kFaultIndex.

constexpr std::uint32_t kR = 0x1U;
constexpr std::uint32_t kW = 0x2U;
constexpr std::uint32_t kX = 0x4U;
constexpr std::uint32_t kSwitch = KSWORD_ARK_HVM_EPTSW_OUTCOME_SWITCH;
constexpr std::uint32_t kRefuse = KSWORD_ARK_HVM_EPTSW_OUTCOME_REFUSE;
constexpr std::uint32_t kSpurious = KSWORD_ARK_HVM_EPTSW_REASON_SPURIOUS;
constexpr std::uint32_t kUnrep = KSWORD_ARK_HVM_EPTSW_REASON_UNREPRESENTABLE;
constexpr std::uint32_t kNone = KSWORD_ARK_HVM_EPTSW_REASON_NONE;
constexpr std::uint32_t kCloak = KSWORD_ARK_HVM_EPTSW_KIND_CLOAK;
constexpr std::uint32_t kHook = KSWORD_ARK_HVM_EPTSW_KIND_HOOK;

// Expected values are all manually calculated independently:
//   CLOAK: primary value = --x (0x4), secondary value = rw- (0x3); HOOK: primary value = rw-
//   (0x3), secondary value = --x (0x4). When this leaf selects the primary value (base / other):
// primary value grants -> SPURIOUS; secondary value does not grant -> UNREPRESENTABLE.
// Otherwise, switch to this leaf index. When the leaf takes the secondary value: secondary value granted -> SPURIOUS; primary value not granted -> UNREPRESENTABLE;
// Otherwise, fall back to the base.
const ExhaustiveCase kExhaustive[] = {
    // --- Base, CLOAK ---
    { ActiveKind::kBase, kCloak, kR,           kSwitch, kFaultIndex, kNone,
      L"base + CLOAK + read switches to the leaf hierarchy" },
    { ActiveKind::kBase, kCloak, kW,           kSwitch, kFaultIndex, kNone,
      L"base + CLOAK + write switches to the leaf hierarchy" },
    { ActiveKind::kBase, kCloak, kX,           kRefuse, 0U,          kSpurious,
      L"base + CLOAK + execute cannot fault because the primary grants X" },
    { ActiveKind::kBase, kCloak, kR | kW,      kSwitch, kFaultIndex, kNone,
      L"base + CLOAK + read-write switches once for both" },
    { ActiveKind::kBase, kCloak, kR | kX,      kRefuse, 0U,          kUnrep,
      L"base + CLOAK + read-execute is unrepresentable in any single hierarchy" },
    { ActiveKind::kBase, kCloak, kW | kX,      kRefuse, 0U,          kUnrep,
      L"base + CLOAK + write-execute is unrepresentable" },
    { ActiveKind::kBase, kCloak, kR | kW | kX, kRefuse, 0U,          kUnrep,
      L"base + CLOAK + read-write-execute is unrepresentable" },
    // --- Base, HOOK ---
    { ActiveKind::kBase, kHook,  kR,           kRefuse, 0U,          kSpurious,
      L"base + HOOK + read cannot fault because the primary grants R" },
    { ActiveKind::kBase, kHook,  kW,           kRefuse, 0U,          kSpurious,
      L"base + HOOK + write cannot fault because the primary grants W" },
    { ActiveKind::kBase, kHook,  kX,           kSwitch, kFaultIndex, kNone,
      L"base + HOOK + execute switches to the leaf hierarchy" },
    { ActiveKind::kBase, kHook,  kR | kW,      kRefuse, 0U,          kSpurious,
      L"base + HOOK + read-write cannot fault" },
    { ActiveKind::kBase, kHook,  kR | kX,      kRefuse, 0U,          kUnrep,
      L"base + HOOK + read-execute is unrepresentable" },
    { ActiveKind::kBase, kHook,  kW | kX,      kRefuse, 0U,          kUnrep,
      L"base + HOOK + write-execute is unrepresentable" },
    { ActiveKind::kBase, kHook,  kR | kW | kX, kRefuse, 0U,          kUnrep,
      L"base + HOOK + read-write-execute is unrepresentable" },
    // --- This leaf level, CLOAK ---
    { ActiveKind::kThisLeaf, kCloak, kR,           kRefuse, 0U, kSpurious,
      L"leaf hierarchy + CLOAK + read no longer faults, so a fault here is spurious" },
    { ActiveKind::kThisLeaf, kCloak, kW,           kRefuse, 0U, kSpurious,
      L"leaf hierarchy + CLOAK + write is spurious" },
    { ActiveKind::kThisLeaf, kCloak, kX,           kSwitch, 0U, kNone,
      L"leaf hierarchy + CLOAK + execute returns to the base" },
    { ActiveKind::kThisLeaf, kCloak, kR | kW,      kRefuse, 0U, kSpurious,
      L"leaf hierarchy + CLOAK + read-write is spurious" },
    { ActiveKind::kThisLeaf, kCloak, kR | kX,      kRefuse, 0U, kUnrep,
      L"leaf hierarchy + CLOAK + read-execute is unrepresentable" },
    { ActiveKind::kThisLeaf, kCloak, kW | kX,      kRefuse, 0U, kUnrep,
      L"leaf hierarchy + CLOAK + write-execute is unrepresentable" },
    { ActiveKind::kThisLeaf, kCloak, kR | kW | kX, kRefuse, 0U, kUnrep,
      L"leaf hierarchy + CLOAK + read-write-execute is unrepresentable" },
    // --- This leaf hierarchy + HOOK
    { ActiveKind::kThisLeaf, kHook,  kR,           kSwitch, 0U, kNone,
      L"leaf hierarchy + HOOK + read returns to the base so the reader sees the real page" },
    { ActiveKind::kThisLeaf, kHook,  kW,           kSwitch, 0U, kNone,
      L"leaf hierarchy + HOOK + write returns to the base so the write lands on the real page" },
    { ActiveKind::kThisLeaf, kHook,  kX,           kRefuse, 0U, kSpurious,
      L"leaf hierarchy + HOOK + execute no longer faults, so a fault here is spurious" },
    { ActiveKind::kThisLeaf, kHook,  kR | kW,      kSwitch, 0U, kNone,
      L"leaf hierarchy + HOOK + read-write returns to the base" },
    { ActiveKind::kThisLeaf, kHook,  kR | kX,      kRefuse, 0U, kUnrep,
      L"leaf hierarchy + HOOK + read-execute is unrepresentable" },
    { ActiveKind::kThisLeaf, kHook,  kW | kX,      kRefuse, 0U, kUnrep,
      L"leaf hierarchy + HOOK + write-execute is unrepresentable" },
    { ActiveKind::kThisLeaf, kHook,  kR | kW | kX, kRefuse, 0U, kUnrep,
      L"leaf hierarchy + HOOK + read-write-execute is unrepresentable" },
    // --- Hierarchy of another leaf + CLOAK ---
    { ActiveKind::kOtherLeaf, kCloak, kR,           kSwitch, kFaultIndex, kNone,
      L"another leaf's hierarchy + CLOAK + read switches over and retightens that leaf" },
    { ActiveKind::kOtherLeaf, kCloak, kW,           kSwitch, kFaultIndex, kNone,
      L"another leaf's hierarchy + CLOAK + write switches over" },
    { ActiveKind::kOtherLeaf, kCloak, kX,           kRefuse, 0U,          kSpurious,
      L"another leaf's hierarchy + CLOAK + execute cannot fault on this leaf" },
    { ActiveKind::kOtherLeaf, kCloak, kR | kW,      kSwitch, kFaultIndex, kNone,
      L"another leaf's hierarchy + CLOAK + read-write switches over" },
    { ActiveKind::kOtherLeaf, kCloak, kR | kX,      kRefuse, 0U,          kUnrep,
      L"another leaf's hierarchy + CLOAK + read-execute is unrepresentable" },
    { ActiveKind::kOtherLeaf, kCloak, kW | kX,      kRefuse, 0U,          kUnrep,
      L"another leaf's hierarchy + CLOAK + write-execute is unrepresentable" },
    { ActiveKind::kOtherLeaf, kCloak, kR | kW | kX, kRefuse, 0U,          kUnrep,
      L"another leaf's hierarchy + CLOAK + read-write-execute is unrepresentable" },
    // --- Other leaf hierarchy + HOOK ---
    { ActiveKind::kOtherLeaf, kHook,  kR,           kRefuse, 0U,          kSpurious,
      L"another leaf's hierarchy + HOOK + read cannot fault on this leaf" },
    { ActiveKind::kOtherLeaf, kHook,  kW,           kRefuse, 0U,          kSpurious,
      L"another leaf's hierarchy + HOOK + write cannot fault on this leaf" },
    { ActiveKind::kOtherLeaf, kHook,  kX,           kSwitch, kFaultIndex, kNone,
      L"another leaf's hierarchy + HOOK + execute switches over and retightens that leaf" },
    { ActiveKind::kOtherLeaf, kHook,  kR | kW,      kRefuse, 0U,          kSpurious,
      L"another leaf's hierarchy + HOOK + read-write cannot fault on this leaf" },
    { ActiveKind::kOtherLeaf, kHook,  kR | kX,      kRefuse, 0U,          kUnrep,
      L"another leaf's hierarchy + HOOK + read-execute is unrepresentable" },
    { ActiveKind::kOtherLeaf, kHook,  kW | kX,      kRefuse, 0U,          kUnrep,
      L"another leaf's hierarchy + HOOK + write-execute is unrepresentable" },
    { ActiveKind::kOtherLeaf, kHook,  kR | kW | kX, kRefuse, 0U,          kUnrep,
      L"another leaf's hierarchy + HOOK + read-write-execute is unrepresentable" },
};

std::uint32_t activeIndexOf(ActiveKind kind) {
    switch (kind) {
    case ActiveKind::kBase:
        return 0U;
    case ActiveKind::kThisLeaf:
        return kFaultIndex;
    default:
        return kOtherIndex;
    }
}

void testDecideExhaustive(ksword_tests::Suite& s) {
    // 3 current levels × 2 views × 7 non-empty accesses = 42 groups, with no missing combinations.
    s.expect(sizeof(kExhaustive) / sizeof(kExhaustive[0]) == 42U,
             L"the exhaustive table covers all three-by-two-by-seven combinations");

    for (const ExhaustiveCase& item : kExhaustive) {
        KSWORD_ARK_HVM_EPTSW_TRANSITION transition;
        const std::uint32_t kOutcome = KswordArkHvmEptSwDecide(
            activeIndexOf(item.active),
            kFaultLeaf,
            kLeafCount,
            item.access,
            item.viewKind,
            1,
            &transition);
        const bool kOutcomeMatches =
            kOutcome == item.expectedOutcome &&
            transition.Outcome == item.expectedOutcome;
        const bool kDetailMatches =
            item.expectedOutcome == kSwitch
                ? (transition.NextIndex == item.expectedNextIndex &&
                   transition.Reason == KSWORD_ARK_HVM_EPTSW_REASON_NONE)
                : (transition.Reason == item.expectedReason &&
                   transition.NextIndex == 0U &&
                   transition.TargetEptp == 0ULL);
        s.expect(kOutcomeMatches, item.label);
        s.expect(kDetailMatches, item.label);
    }
}

void testDecideRejections(ksword_tests::Suite& s) {
    KSWORD_ARK_HVM_EPTSW_TRANSITION transition;

    // Out of bounds: zero leaf count, exceeding the upper limit, invalid leaf index, or invalid current index.
    s.expect(KswordArkHvmEptSwDecide(0U, 0U, 0U, kR, kCloak, 1, &transition) == kRefuse &&
                 transition.Reason == KSWORD_ARK_HVM_EPTSW_REASON_BOUNDS,
             L"a zero leaf count is refused as out of bounds");
    s.expect(KswordArkHvmEptSwDecide(0U, 0U, 33U, kR, kCloak, 1, &transition) == kRefuse &&
                 transition.Reason == KSWORD_ARK_HVM_EPTSW_REASON_BOUNDS,
             L"a leaf count above the protocol maximum is refused");
    s.expect(KswordArkHvmEptSwDecide(0U, 4U, 4U, kR, kCloak, 1, &transition) == kRefuse &&
                 transition.Reason == KSWORD_ARK_HVM_EPTSW_REASON_BOUNDS,
             L"a fault leaf equal to the leaf count is refused");
    // The upper bound of the current index is exactly the leaf count: index 4 is valid with 4 leaves (level of the 3rd leaf), while 5 is invalid.
    s.expect(KswordArkHvmEptSwDecide(4U, 1U, 4U, kR, kCloak, 1, &transition) == kSwitch,
             L"an active index equal to the leaf count is the last legal hierarchy");
    s.expect(KswordArkHvmEptSwDecide(5U, 1U, 4U, kR, kCloak, 1, &transition) == kRefuse &&
                 transition.Reason == KSWORD_ARK_HVM_EPTSW_REASON_BOUNDS,
             L"an active index past the hierarchy set means the ledger already disagrees");

    // Empty access and unknown access bits.
    s.expect(KswordArkHvmEptSwDecide(0U, 1U, 4U, 0U, kCloak, 1, &transition) == kRefuse &&
                 transition.Reason == KSWORD_ARK_HVM_EPTSW_REASON_EMPTY_ACCESS,
             L"an empty access mask is refused instead of resuming into a loop");
    s.expect(KswordArkHvmEptSwDecide(0U, 1U, 4U, 0x8U, kCloak, 1, &transition) == kRefuse &&
                 transition.Reason == KSWORD_ARK_HVM_EPTSW_REASON_UNKNOWN_ACCESS,
             L"an access bit the protocol does not define is refused, not treated as a read");
    s.expect(KswordArkHvmEptSwDecide(0U, 1U, 4U, 0x9U, kCloak, 1, &transition) == kRefuse &&
                 transition.Reason == KSWORD_ARK_HVM_EPTSW_REASON_UNKNOWN_ACCESS,
             L"an undefined bit alongside a defined one is still refused");

    // Capabilities and types. The check for execute-only capability precedes the type check, so when both are false,
    // the reported reason is capability missing—the exact information the caller needs to make a downgrade decision.
    s.expect(KswordArkHvmEptSwDecide(0U, 1U, 4U, kR, kCloak, 0, &transition) == kRefuse &&
                 transition.Reason == KSWORD_ARK_HVM_EPTSW_REASON_NO_EXECUTE_ONLY,
             L"without execute-only the mechanism refuses before looking at the kind");
    s.expect(KswordArkHvmEptSwDecide(0U, 1U, 4U, kR, 3U, 0, &transition) == kRefuse &&
                 transition.Reason == KSWORD_ARK_HVM_EPTSW_REASON_NO_EXECUTE_ONLY,
             L"the capability failure is reported ahead of an unknown kind");
    s.expect(KswordArkHvmEptSwDecide(0U, 1U, 4U, kR, 3U, 1, &transition) == kRefuse &&
                 transition.Reason == KSWORD_ARK_HVM_EPTSW_REASON_KIND,
             L"an unknown view kind is refused");
    s.expect(KswordArkHvmEptSwDecide(0U, 1U, 4U, kR, 0U, 1, &transition) == kRefuse &&
                 transition.Reason == KSWORD_ARK_HVM_EPTSW_REASON_KIND,
             L"view kind zero is refused");

    // Null pointer.
    s.expect(KswordArkHvmEptSwDecide(0U, 1U, 4U, kR, kCloak, 1, nullptr) == kRefuse,
             L"a null transition pointer is refused rather than dereferenced");

    // On rejection, the result structure must be fully cleared: even if the caller
    // ignores the return value, they must not read a target that looks successful.
    transition.TargetEptp = 0xDEADBEEFULL;
    transition.NextIndex = 7U;
    transition.Reason = 0xEEU;
    (void)KswordArkHvmEptSwDecide(0U, 1U, 4U, 0U, kCloak, 1, &transition);
    s.expect(transition.TargetEptp == 0ULL && transition.NextIndex == 0U &&
                 transition.Reason == KSWORD_ARK_HVM_EPTSW_REASON_EMPTY_ACCESS,
             L"a refusal clears the target and the next index and states its reason");

    // Single-leaf set: the only leaf is index 1, with transitions back and forth between the base and it.
    s.expect(KswordArkHvmEptSwDecide(0U, 0U, 1U, kR, kCloak, 1, &transition) == kSwitch &&
                 transition.NextIndex == 1U,
             L"the only leaf of a single-leaf set is index one, not index zero");
    s.expect(KswordArkHvmEptSwDecide(1U, 0U, 1U, kX, kCloak, 1, &transition) == kSwitch &&
                 transition.NextIndex == 0U,
             L"a single-leaf set returns to the base on the reverse access");

    // Leaf set at the protocol limit.
    s.expect(KswordArkHvmEptSwDecide(0U, 31U, 32U, kX, kHook, 1, &transition) == kSwitch &&
                 transition.NextIndex == 32U,
             L"the last leaf of a full set maps to the last hierarchy index");

    // Two asymmetric outcomes written with literal kind numbers. Since every cell in the exhaustive table uses kCloak
    // / kHook symbols, swapping the two kinds still passes the entire table—because after swapping, it is merely
    // "another equally self-consistent table." These two lines pin the binding between protocol numbers and semantics:
    //   kind = 1 (CLOAK) should not switch on a base execute fault because --x is already granted.
    //   kind = 2 (HOOK) must switch on a base execute fault because rw- does not grant X.
    s.expect(KswordArkHvmEptSwDecide(0U, 1U, 4U, kX, 1U, 1, &transition) == kRefuse &&
                 transition.Reason == kSpurious,
             L"protocol kind one on a base execute fault is spurious, because CLOAK grants X");
    s.expect(KswordArkHvmEptSwDecide(0U, 1U, 4U, kX, 2U, 1, &transition) == kSwitch &&
                 transition.NextIndex == 2U,
             L"protocol kind two on a base execute fault switches, because HOOK denies X");
    s.expect(KswordArkHvmEptSwDecide(0U, 1U, 4U, kR, 1U, 1, &transition) == kSwitch &&
                 transition.NextIndex == 2U,
             L"protocol kind one on a base read fault switches, because CLOAK denies R");
    s.expect(KswordArkHvmEptSwDecide(0U, 1U, 4U, kR, 2U, 1, &transition) == kRefuse &&
                 transition.Reason == kSpurious,
             L"protocol kind two on a base read fault is spurious, because HOOK grants R");
}

// ---------------------------------------------------------------------------
// Ledger table lookup
// ---------------------------------------------------------------------------

void testPlanSwitch(ksword_tests::Suite& s) {
    // Ledger: index 0 is the base; index k is derived from the base; root = 0x02000000 + k * 0x1000.
    std::uint64_t table[5];
    table[0] = kBaseEptp;
    for (std::uint32_t index = 1U; index < 5U; ++index) {
        table[index] = KswordArkHvmEptSwRebaseEptp(
            kBaseEptp, 0x02000000ULL + (std::uint64_t)index * 0x1000ULL);
    }
    // Manual calculation: root 0x02002000 | 0x1E.
    s.expect(table[2] == 0x0200201EULL,
             L"the ledger entry for leaf one is the base pointer rebased onto its own root");

    KSWORD_ARK_HVM_EPTSW_TRANSITION transition;
    s.expect(KswordArkHvmEptSwPlanSwitch(
                 table, 5U, 0U, kFaultLeaf, kLeafCount, kR, kCloak, 1, &transition) ==
                 kSwitch &&
                 transition.NextIndex == kFaultIndex &&
                 transition.TargetEptp == 0x0200201EULL,
             L"a planned switch hands back the exact EPT pointer to write into the VMCS");
    s.expect(KswordArkHvmEptSwPlanSwitch(
                 table, 5U, kFaultIndex, kFaultLeaf, kLeafCount, kX, kCloak, 1,
                 &transition) == kSwitch &&
                 transition.NextIndex == 0U &&
                 transition.TargetEptp == kBaseEptp,
             L"the reverse plan hands back the base pointer");

    // The ledger length must be exactly 1 + leaf count: being short by one causes an
    // out-of-bounds read by index, potentially retrieving a seemingly valid stale pointer.
    s.expect(KswordArkHvmEptSwPlanSwitch(
                 table, 4U, 0U, kFaultLeaf, kLeafCount, kR, kCloak, 1, &transition) ==
                 kRefuse &&
                 transition.Reason == KSWORD_ARK_HVM_EPTSW_REASON_LEDGER,
             L"a ledger shorter than one plus the leaf count is refused");
    s.expect(KswordArkHvmEptSwPlanSwitch(
                 table, 6U, 0U, kFaultLeaf, kLeafCount, kR, kCloak, 1, &transition) ==
                 kRefuse &&
                 transition.Reason == KSWORD_ARK_HVM_EPTSW_REASON_LEDGER,
             L"a ledger longer than one plus the leaf count is refused too");
    s.expect(KswordArkHvmEptSwPlanSwitch(
                 nullptr, 5U, 0U, kFaultLeaf, kLeafCount, kR, kCloak, 1, &transition) ==
                 kRefuse &&
                 transition.Reason == KSWORD_ARK_HVM_EPTSW_REASON_LEDGER,
             L"a null ledger is refused");

    // Slot not filled.
    {
        std::uint64_t holed[5];
        for (std::uint32_t index = 0U; index < 5U; ++index) {
            holed[index] = table[index];
        }
        holed[kFaultIndex] = 0ULL;
        s.expect(KswordArkHvmEptSwPlanSwitch(
                     holed, 5U, 0U, kFaultLeaf, kLeafCount, kR, kCloak, 1, &transition) ==
                     kRefuse &&
                     transition.Reason == KSWORD_ARK_HVM_EPTSW_REASON_LEDGER,
                 L"an unfilled target slot is refused rather than walked from physical zero");
        holed[kFaultIndex] = table[kFaultIndex];
        holed[0] = 0ULL;
        s.expect(KswordArkHvmEptSwPlanSwitch(
                     holed, 5U, 0U, kFaultLeaf, kLeafCount, kR, kCloak, 1, &transition) ==
                     kRefuse &&
                     transition.Reason == KSWORD_ARK_HVM_EPTSW_REASON_LEDGER,
                 L"an unfilled source slot is refused as well");
    }

    // Shared EP4TA: The switch is a no-op in hardware, and the same instruction will always re-trigger a
    // fault. This is the only construction error in this scheme that can cause a system-wide silent deadlock.
    {
        std::uint64_t aliased[5];
        for (std::uint32_t index = 0U; index < 5U; ++index) {
            aliased[index] = table[index];
        }
        aliased[kFaultIndex] = kBaseEptpAd;   // Same root as the base, differing only in A/D bits.
        s.expect(KswordArkHvmEptSwPlanSwitch(
                     aliased, 5U, 0U, kFaultLeaf, kLeafCount, kR, kCloak, 1,
                     &transition) == kRefuse &&
                     transition.Reason == KSWORD_ARK_HVM_EPTSW_REASON_ALIASED,
                 L"a target sharing the source's EP4TA is refused instead of looping forever");
    }

    // Rejections from the decision layer must be propagated as-is, not overwritten by ledger checks into LEDGER.
    s.expect(KswordArkHvmEptSwPlanSwitch(
                 table, 5U, 0U, kFaultLeaf, kLeafCount, kX, kCloak, 1, &transition) ==
                 kRefuse &&
                 transition.Reason == KSWORD_ARK_HVM_EPTSW_REASON_SPURIOUS &&
                 transition.TargetEptp == 0ULL,
             L"a decision-level refusal keeps its own reason and hands back no pointer");
    s.expect(KswordArkHvmEptSwPlanSwitch(
                 table, 5U, 0U, kFaultLeaf, kLeafCount, kR | kX, kCloak, 1, &transition) ==
                 kRefuse &&
                 transition.Reason == KSWORD_ARK_HVM_EPTSW_REASON_UNREPRESENTABLE,
             L"an unrepresentable access keeps its reason through the ledger stage");
    s.expect(KswordArkHvmEptSwPlanSwitch(
                 table, 5U, 0U, kFaultLeaf, kLeafCount, kR, kCloak, 1, nullptr) == kRefuse,
             L"a null transition pointer is refused by the planner too");

    // Each sub-hierarchy must be accepted by VM entry just like the base, and they must not share tags.
    bool ledgerHealthy = true;
    for (std::uint32_t index = 0U; index < 5U; ++index) {
        if (KswordArkHvmEptSwEptpIsWellFormed(table[index], kCapWb, kPhysBits39) !=
            KSWORD_ARK_HVM_EPTSW_EPTP_OK) {
            ledgerHealthy = false;
        }
        for (std::uint32_t other = 0U; other < 5U; ++other) {
            if (other != index &&
                KswordArkHvmEptSwSwitchNeedsInvalidation(table[index], table[other]) != 0) {
                ledgerHealthy = false;
            }
        }
    }
    s.expect(ledgerHealthy,
             L"every derived hierarchy is VM-entry legal and carries its own cache tag");
}

// ---------------------------------------------------------------------------
// Refuse the constructor itself.
// ---------------------------------------------------------------------------

void testRefuseHelper(ksword_tests::Suite& s) {
    KSWORD_ARK_HVM_EPTSW_TRANSITION transition;

    transition.TargetEptp = 0xDEADBEEFULL;
    transition.Outcome = KSWORD_ARK_HVM_EPTSW_OUTCOME_SWITCH;
    transition.NextIndex = 7U;
    transition.Reason = 0xEEU;
    s.expect(KswordArkHvmEptSwRefuse(
                 &transition, KSWORD_ARK_HVM_EPTSW_REASON_ALIASED) ==
                 KSWORD_ARK_HVM_EPTSW_OUTCOME_REFUSE,
             L"the refusal helper reports a refusal");
    s.expect(transition.TargetEptp == 0ULL &&
                 transition.Outcome == KSWORD_ARK_HVM_EPTSW_OUTCOME_REFUSE &&
                 transition.NextIndex == 0U &&
                 transition.Reason == KSWORD_ARK_HVM_EPTSW_REASON_ALIASED,
             L"the refusal helper clears the target and index and keeps the reason");
    // This is a public static __inline function. The driver calls it directly to construct a refusal.
    // It runs on the DISPATCH_LEVEL VM-exit path, where a single null dereference causes a BSOD. The
    // context is far from 'who failed to fill the Transition'. Every other pointer-fetching function
    // in this file performs checks; this one in the previous version did not.
    s.expect(KswordArkHvmEptSwRefuse(
                 nullptr, KSWORD_ARK_HVM_EPTSW_REASON_BOUNDS) ==
                 KSWORD_ARK_HVM_EPTSW_OUTCOME_REFUSE,
             L"a null transition is refused rather than dereferenced by the helper");
}

// ---------------------------------------------------------------------------
// Progress ledger (the section merged from the deleted KswordArkHvmEptpSwitch.h)
// ---------------------------------------------------------------------------

void testProgressLedger(ksword_tests::Suite& s) {
    KSWORD_ARK_HVM_EPTSW_PROGRESS progress;

    // Manually calculated context values. RIP and page addresses only need to be distinct; their specific values do not participate in any arithmetic.
    constexpr std::uint64_t kRipA = 0xFFFFF80100001000ULL;
    constexpr std::uint64_t kRipB = 0xFFFFF80100001007ULL;
    constexpr std::uint64_t kPageCloak = 0x0000000012340000ULL;
    constexpr std::uint64_t kPageHook = 0x0000000056780000ULL;

    // After reset, the ledger must indicate 'no switch has occurred yet'. Without a reset, the (RIP, page,
    // target) left by the previous view would cause the first valid switch of the new batch to be incorrectly
    // flagged as a loop, resulting in a fail-closed exit from virtualization immediately after loading the view.
    progress.LastRip = 0x1111ULL;
    progress.LastGuestPhysical = 0x2222ULL;
    progress.PreviousRip = 0x3333ULL;
    progress.PreviousGuestPhysical = 0x4444ULL;
    progress.LastTarget = 5U;
    progress.PreviousTarget = 6U;
    progress.SameRipSwitches = 7U;
    progress.Reserved0 = 8U;
    KswordArkHvmEptSwProgressReset(&progress);
    s.expect(progress.LastRip == 0ULL && progress.LastGuestPhysical == 0ULL &&
                 progress.PreviousRip == 0ULL &&
                 progress.PreviousGuestPhysical == 0ULL &&
                 progress.LastTarget == 0U && progress.PreviousTarget == 0U &&
                 progress.SameRipSwitches == 0U && progress.Reserved0 == 0U,
             L"a reset ledger records no history and points at the base hierarchy");
    // Two rules for a null ledger: reset ignores it; admission rejects it based on 'cannot prove progress.'
    // Without a ledger, there is no evidence, and the default for this path must be fail-closed.
    KswordArkHvmEptSwProgressReset(nullptr);
    s.expect(KswordArkHvmEptSwProgressAdmit(nullptr, kRipA, kPageCloak, 1U) == 0,
             L"a null ledger cannot prove progress and therefore admits nothing");

    // --- Normal progress ---
    KswordArkHvmEptSwProgressReset(&progress);
    s.expect(KswordArkHvmEptSwProgressAdmit(&progress, kRipA, kPageCloak, 1U) == 1,
             L"the first switch of an instruction is always progress");
    s.expect(progress.LastRip == kRipA && progress.LastGuestPhysical == kPageCloak &&
                 progress.LastTarget == 1U && progress.SameRipSwitches == 1U,
             L"the accepted switch is recorded as this instruction's first");
    // A second fault of the same instruction (one fetch, one operand access) is valid as long as it is not a repeat.
    s.expect(KswordArkHvmEptSwProgressAdmit(&progress, kRipA, kPageHook, 2U) == 1,
             L"a second fault of the same instruction on another page is still progress");
    s.expect(progress.SameRipSwitches == 2U &&
                 progress.PreviousGuestPhysical == kPageCloak &&
                 progress.PreviousTarget == 1U,
             L"the previous generation is what the earlier switch left behind");

    // --- Period 1: Same instruction, same page, same target again ---
    KswordArkHvmEptSwProgressReset(&progress);
    s.expect(KswordArkHvmEptSwProgressAdmit(&progress, kRipA, kPageCloak, 1U) == 1,
             L"the first switch is admitted before the period-one probe");
    s.expect(KswordArkHvmEptSwProgressAdmit(&progress, kRipA, kPageCloak, 1U) == 0,
             L"switching to the same target for the same page and RIP is not progress");
    // No ledger update on refusal: exiting virtualization preserves the state, which is more useful for post-event analysis.
    s.expect(progress.SameRipSwitches == 1U && progress.PreviousRip == 0ULL,
             L"a refused switch leaves the ledger exactly as it was");

    // --- Cycle 2: This is the 'cross-leaf unrepresentable' combination mentioned at the file's beginning: the
    // instruction fetch lands on a HOOK page (requiring the HOOK leaf's sub-level), while the same instruction's
    // operand read lands on a CLOAK page (requiring the CLOAK leaf's sub-level). Since each hierarchy level relaxes
    // only one leaf, no single hierarchy level can serve both halves simultaneously. KswordArkHvmEptSwDecide cannot
    // handle this—it sees only one violation at a time, and each half is individually servable—so it honestly keeps
    // returning SWITCH with the RIP unchanged. Only the ledger can identify this case.
    KswordArkHvmEptSwProgressReset(&progress);
    s.expect(KswordArkHvmEptSwProgressAdmit(&progress, kRipA, kPageHook, 2U) == 1,
             L"the cross-leaf livelock's first switch looks perfectly normal");
    s.expect(KswordArkHvmEptSwProgressAdmit(&progress, kRipA, kPageCloak, 1U) == 1,
             L"its second switch also looks perfectly normal on its own");
    s.expect(KswordArkHvmEptSwProgressAdmit(&progress, kRipA, kPageHook, 2U) == 0,
             L"the third exit repeats generation two and is caught as a two-cycle");

    // --- Long Loop Fallback: Too many switches on the same RIP; (Page, Target) pairs differ
    // each time, so Period 1 and Period 2 do not trigger; only the counter increments.
    // Manual calculation: Set the count to 1 the first time, then increment it each subsequent time. On the ninth entry, the count is already 8, triggering the upper limit.
    KswordArkHvmEptSwProgressReset(&progress);
    {
        bool firstEightAdmitted = true;
        for (std::uint32_t step = 0U; step < 8U; ++step) {
            if (KswordArkHvmEptSwProgressAdmit(
                    &progress, kRipA,
                    kPageCloak + ((std::uint64_t)step << 12),
                    step + 1U) != 1) {
                firstEightAdmitted = false;
            }
        }
        s.expect(firstEightAdmitted,
                 L"eight distinct switches at one RIP are all admitted");
        s.expect(progress.SameRipSwitches == 8U,
                 L"the counter reaches exactly the limit after eight switches");
        s.expect(KswordArkHvmEptSwProgressAdmit(
                     &progress, kRipA, kPageCloak + 0x8000ULL, 9U) == 0,
                 L"the ninth distinct switch at one RIP is refused by the long-cycle bound");
    }

    // --- Re-count if RIP changes. A changed RIP indicates the previous
    // instruction retired, meaning the previous switch took effect.
    KswordArkHvmEptSwProgressReset(&progress);
    s.expect(KswordArkHvmEptSwProgressAdmit(&progress, kRipA, kPageCloak, 1U) == 1 &&
                 KswordArkHvmEptSwProgressAdmit(&progress, kRipA, kPageCloak, 1U) == 0,
             L"the same instruction repeating itself is refused");
    s.expect(KswordArkHvmEptSwProgressAdmit(&progress, kRipB, kPageCloak, 1U) == 1 &&
                 progress.SameRipSwitches == 1U,
             L"the next instruction starts a fresh count even on the same page and target");
    // Conversely: the same RIP is not necessarily a ring, the same page is not necessarily a ring, and the same target is not necessarily a ring — only when all
    // three completely coincide with one of the previous two generations is it valid. Each of these three conditions relaxed by one step must still be accepted.
    KswordArkHvmEptSwProgressReset(&progress);
    s.expect(KswordArkHvmEptSwProgressAdmit(&progress, kRipA, kPageCloak, 1U) == 1 &&
                 KswordArkHvmEptSwProgressAdmit(&progress, kRipA, kPageCloak, 2U) == 1,
             L"the same page with a different target is progress");
    KswordArkHvmEptSwProgressReset(&progress);
    s.expect(KswordArkHvmEptSwProgressAdmit(&progress, kRipA, kPageCloak, 1U) == 1 &&
                 KswordArkHvmEptSwProgressAdmit(&progress, kRipA, kPageHook, 1U) == 1,
             L"the same target on a different page is progress");

    // --- Connect to the state machine: The combination at the file start traverses the entire path. Leaf 0 = CLOAK
    // page, Leaf 1 = HOOK page. Fetching the same instruction lands in Leaf 1, while operand reads land in Leaf 0.
    // Decide: All three calls honestly returned SWITCH (it cannot see the cross-leaf event), and the ledger rejected it on the third call.
    // This is the executable evidence for the precondition: 'Decide cannot refuse; the ledger must cover it.'
    {
        KSWORD_ARK_HVM_EPTSW_TRANSITION transition;
        std::uint32_t active = 0U;
        std::uint32_t outcomes[3] = { 0U, 0U, 0U };
        std::uint32_t targets[3] = { 0U, 0U, 0U };
        int admitted[3] = { 0, 0, 0 };
        const std::uint32_t kFaultLeaves[3] = { 1U, 0U, 1U };
        const std::uint32_t kFaultKind[3] = { kHook, kCloak, kHook };
        const std::uint32_t kFaultAccess[3] = { kX, kR, kX };
        const std::uint64_t kFaultPage[3] = { kPageHook, kPageCloak, kPageHook };

        KswordArkHvmEptSwProgressReset(&progress);
        for (std::uint32_t step = 0U; step < 3U; ++step) {
            outcomes[step] = KswordArkHvmEptSwDecide(
                active, kFaultLeaves[step], 2U, kFaultAccess[step], kFaultKind[step],
                1, &transition);
            targets[step] = transition.NextIndex;
            admitted[step] = KswordArkHvmEptSwProgressAdmit(
                &progress, kRipA, kFaultPage[step], transition.NextIndex);
            if (admitted[step] != 0) {
                active = transition.NextIndex;
            }
        }
        // All three decisions are SWITCH; target index transitions 2 -> 1 -> 2, and RIP does not move a single step.
        s.expect(outcomes[0] == kSwitch && outcomes[1] == kSwitch &&
                     outcomes[2] == kSwitch,
                 L"the decision function never refuses the cross-leaf combination");
        s.expect(targets[0] == 2U && targets[1] == 1U && targets[2] == 2U,
                 L"the targets alternate between the two leaf hierarchies");
        // The ledger breaks this loop on the third exit, allowing the caller to fail-closed based on this.
        s.expect(admitted[0] == 1 && admitted[1] == 1 && admitted[2] == 0,
                 L"the ledger, not the decision function, is what stops the livelock");
    }

    // --- Ledger boundary: all-zero context --- After reset, LastRip and LastGuestPhysical
    // are both 0, targeting base 0. A "switch" with RIP=0, page=0, and target=base
    // therefore completely coincides with the reset state and is rejected per cycle 1.
    // This is a conservative approach: guest kernel code will not run at RIP 0, and the cost of refusal is just one
    // fail-closed; far less risky than allowing a ring through.
    KswordArkHvmEptSwProgressReset(&progress);
    s.expect(KswordArkHvmEptSwProgressAdmit(&progress, 0ULL, 0ULL, 0U) == 0,
             L"an all-zero switch coincides with the reset state and is refused");
    s.expect(KswordArkHvmEptSwProgressAdmit(&progress, 0ULL, 0ULL, 1U) == 1,
             L"the same all-zero site switching to a real hierarchy is still progress");
}

// ---------------------------------------------------------------------------
// VMX capability MSR filtering (KswordArkHvmControls.h)
//
// This group contains the most 'magic number'-like constants in the file: five hand-crafted 32-bit allow masks plus one 64-bit mask.
// They missed once: the PROC mask was written as 0xF6DFCD84 due to a manual calculation error where two nibbles were
// swapped. Compilation, deployment, and self-checks all passed silently; the real consequence would only surface when
// a hypervisor used this capability to compute control values and failed on an error code pointing to **itself**.
//
// Therefore, the expected value here must always be recalculated from the recorded bit numbers (OR of `1UL <<
// n`), not copied as a hexadecimal constant. If they don't match, either the constant is wrong or the bit number
// in the comment is wrong; both must be visible. A copied expected value would fail to detect either error.
//
// Another criterion not in the bit position: this whitelist must be a superset of the bits **we ourselves use in the guest**.
// Once resident, the driver runs inside the guest, and reading these MSRs returns the filtered values.
// Masking out the capabilities we need produces behavior identical to 'nested virtualization broken'.
// ---------------------------------------------------------------------------

// OR a list of bit indices into a mask. Implemented as a function rather than a macro to avoid pitfalls with shift operator precedence in expected values.
constexpr std::uint64_t bitsOf(std::initializer_list<unsigned> bits) {
    std::uint64_t value = 0ULL;
    for (unsigned b : bits) {
        value |= (1ULL << b);
    }
    return value;
}

void testVmxCapabilityMasks(ksword_tests::Suite& s) {
    // --- pin-based: external interrupt exit / NMI exit / virtual NMI ---
    s.expect(KSWORD_ARK_HVM_VMX_PIN_ALLOWED == bitsOf({0, 3, 5}),
             L"the pin-based allow mask is exactly external-interrupt, NMI and virtual-NMI exiting");
    s.expect((KSWORD_ARK_HVM_VMX_PIN_ALLOWED & bitsOf({6, 7})) == 0ULL,
             L"the preemption timer and posted interrupts stay unadvertised: their fields are not copied");

    // --- primary processor-based ---
    // Bit 2: Interrupt window / 3: TSC offset / 7: HLT / 9: INVLPG / 10: MWAIT / 11:
    // RDPMC / 12: RDTSC / 15: CR3 load / 16: CR3 store / 19: CR8 load / 20: CR8 store
    // / 21: TPR shadow / 22: NMI window / 23: MOV-DR / 24: Unconditional I/O / 25:
    // I/O bitmap / 28: MSR bitmap / 29: MONITOR / 30: PAUSE / 31: Activate secondary.
    s.expect(KSWORD_ARK_HVM_VMX_PROC_ALLOWED ==
                 bitsOf({2, 3, 7, 9, 10, 11, 12, 15, 16, 19, 20, 21, 22, 23, 24, 25, 28, 29, 30, 31}),
             L"the primary processor-based allow mask matches the bit list its comment names");
    s.expect((KSWORD_ARK_HVM_VMX_PROC_ALLOWED & (1ULL << 3)) != 0ULL,
             L"TSC offsetting stays advertised: 0x2010 is in the copied control field table");
    // This bit requires that 0x2012 and 0x401C both appear in the vmcs02 copy field table. If advertised but only one is
    // copied, the processor will treat physical page 0 as the virtual-APIC page, leaving no trace in the status bits.
    s.expect((KSWORD_ARK_HVM_VMX_PROC_ALLOWED & (1ULL << 21)) != 0ULL,
             L"the TPR shadow stays advertised: both the threshold and the page address are copied now");
    s.expect((KSWORD_ARK_HVM_VMX_PROC_ALLOWED & (1ULL << 27)) == 0ULL,
             L"the monitor trap flag stays unadvertised: it is not implemented for L2");
    s.expect((KSWORD_ARK_HVM_VMX_PROC_ALLOWED & (1ULL << 31)) != 0ULL,
             L"activating secondary controls stays advertised, or EPT could never be offered");

    // --- Secondary: EPT (bit 1) and unrestricted guest (bit 7)---
    s.expect(KSWORD_ARK_HVM_VMX_PROC2_ALLOWED == bitsOf({1, 7}),
             L"the secondary allow mask offers EPT and unrestricted guest, and nothing else");
    // This bit is explicitly required by VMware and is the only one among its four missing features that cannot be
    // bypassed: its guest boots in real mode. Unlike other secondary bits, it **requires no new vmcs02 fields**.
    s.expect((KSWORD_ARK_HVM_VMX_PROC2_ALLOWED & (1ULL << 7)) != 0ULL,
             L"unrestricted guest stays advertised: a guest that boots in real mode cannot start without it");
    // Announcing it implies EPT is present, as Intel does not allow enabling only one. This assertion verifies that **the two bits we
    // advertise are self-consistent**; whether the pair is self-consistent at runtime is handled by the merge logic in hvm_nested_l2.c.
    s.expect((KSWORD_ARK_HVM_VMX_PROC2_ALLOWED & (1ULL << 7)) == 0ULL ||
                 (KSWORD_ARK_HVM_VMX_PROC2_ALLOWED & (1ULL << 1)) != 0ULL,
             L"advertising unrestricted guest without EPT would promise a pair the processor refuses");
    s.expect((KSWORD_ARK_HVM_VMX_PROC2_ALLOWED & (1ULL << 5)) == 0ULL,
             L"VPID stays unadvertised: INVVPID is not implemented, whatever else is added here");

    // --- VM-exit controls ---
    s.expect(KSWORD_ARK_HVM_VMX_EXIT_ALLOWED == bitsOf({2, 9, 15, 18, 19, 20, 21}),
             L"the exit-control allow mask matches the bit list its comment names");
    s.expect((KSWORD_ARK_HVM_VMX_EXIT_ALLOWED & bitsOf({12, 22})) == 0ULL,
             L"PERF_GLOBAL_CTRL and the preemption timer stay unadvertised: neither field is copied");
    // This bit cannot be cleared and must not be stripped during merge; both behaviors are verified on real hardware: removing the advertisement
    //is a no-op (bits that must be one are restored by the filter), while stripping it in the merge causes VMware's monitor to...
    // Fails immediately on the VERIFY at irq.c:111 — once L1 requests this bit, it unconditionally reads that vector.
    s.expect((KSWORD_ARK_HVM_VMX_EXIT_ALLOWED & (1ULL << 15)) != 0ULL,
             L"acknowledge interrupt on exit is advertised: L1 reads the vector unconditionally once it asks");

    // --- VM-entry control ---
    s.expect(KSWORD_ARK_HVM_VMX_ENTRY_ALLOWED == bitsOf({2, 9, 14, 15}),
             L"the entry-control allow mask matches the bit list its comment names");
    s.expect((KSWORD_ARK_HVM_VMX_ENTRY_ALLOWED & (1ULL << 9)) != 0ULL,
             L"IA-32e mode guest stays advertised, or a 64-bit L2 could not be entered at all");
    s.expect((KSWORD_ARK_HVM_VMX_ENTRY_ALLOWED & bitsOf({13, 16, 17, 18, 20, 21, 22})) == 0ULL,
             L"PERF_GLOBAL_CTRL, BNDCFGS, PT, RTIT, CET, LBR and PKRS stay unadvertised");

    // --- EPT/VPID capabilities
    s.expect(KSWORD_ARK_HVM_VMX_EPT_CAP_ALLOWED ==
                 bitsOf({6, 8, 14, 16, 17, 20, 21, 25, 26, 32, 40, 41, 42}),
             L"the EPT capability allow mask matches the bit list its comment names");
    // These two bits are not 'optional to keep' but **must be kept**: the driver reads them directly within the guest.
    s.expect((KSWORD_ARK_HVM_VMX_EPT_CAP_ALLOWED & (1ULL << 17)) != 0ULL,
             L"one-GiB leaves stay advertised: the nested probe builds its EPT12 out of them");
    s.expect((KSWORD_ARK_HVM_VMX_EPT_CAP_ALLOWED & (1ULL << 21)) != 0ULL,
             L"accessed and dirty stays advertised: the nested EPT code reads it to decide whether to maintain A/D");
    s.expect((KSWORD_ARK_HVM_VMX_EPT_CAP_ALLOWED & (1ULL << 0)) == 0ULL,
             L"execute-only stays unadvertised: shadow synthesis has never been shown to preserve it");
    // INVVPID and enable-VPID are distinct operations: declaring the former does not equate to declaring the latter; VMware specifically requires the former.
    s.expect((KSWORD_ARK_HVM_VMX_EPT_CAP_ALLOWED & (1ULL << 32)) != 0ULL &&
                 (KSWORD_ARK_HVM_VMX_EPT_CAP_ALLOWED & bitsOf({40, 41, 42})) ==
                     bitsOf({40, 41, 42}),
             L"INVVPID and its types zero, one and two stay advertised: a guest hypervisor names exactly these");
    // Type 3 is not advertised, so dispatch must also reject it — and vice versa. If one side changes while the other
    // doesn't, it's either "advertised but not implemented" or "implemented but not usable"; neither case triggers an error.
    s.expect((KSWORD_ARK_HVM_VMX_EPT_CAP_ALLOWED & (1ULL << 43)) == 0ULL,
             L"INVVPID type three stays unadvertised: nothing asked for that granularity");
    s.expect((KSWORD_ARK_HVM_VMX_PROC2_ALLOWED & (1ULL << 5)) == 0ULL,
             L"enable-VPID stays unadvertised even though INVVPID is: L2 runs under VPID zero");
    s.expect((KSWORD_ARK_HVM_VMX_EPT_CAP_ALLOWED & (1ULL << 6)) != 0ULL &&
                 (KSWORD_ARK_HVM_VMX_EPT_CAP_ALLOWED & (1ULL << 20)) != 0ULL,
             L"a four-level walk and INVEPT stay advertised: the shadow tables are four-level and are invalidated");

    // --- MISC CR3-target field spans bits 24:16 (9 bits) ---
    s.expect(KSWORD_ARK_HVM_VMX_MISC_CR3_TARGET_MASK ==
                 bitsOf({16, 17, 18, 19, 20, 21, 22, 23, 24}),
             L"the CR3-target count field is bits 24 through 16");

    // --- Index range ---
    s.expect(KSWORD_ARK_HVM_VMX_MSR_BASIC == 0x480UL &&
                 KSWORD_ARK_HVM_VMX_MSR_VMFUNC == 0x491UL,
             L"the capability MSR block runs from 0x480 to 0x491");
    s.expect(KswordArkHvmIsVmxCapabilityMsr(0x480UL) == 1 &&
                 KswordArkHvmIsVmxCapabilityMsr(0x491UL) == 1,
             L"both ends of the block are inside it");
    s.expect(KswordArkHvmIsVmxCapabilityMsr(0x47FUL) == 0 &&
                 KswordArkHvmIsVmxCapabilityMsr(0x492UL) == 0,
             L"neither neighbour of the block is inside it");
    s.expect(KswordArkHvmIsVmxCapabilityMsr(0x3AUL) == 0 &&
                 KswordArkHvmIsVmxCapabilityMsr(0xC0000080UL) == 0,
             L"FEATURE_CONTROL and EFER are not capability MSRs: narrowing them would be a different bug");
}

void testVmxCapabilityFilter(ksword_tests::Suite& s) {
    // Paired format: lower half allowed-0 (must be 1), upper half allowed-1 (can be 1).
    // Well-formed input satisfies low ⊆ high — bits forced to 1 by hardware must also be allowed to be 1.
    {
        const std::uint64_t kLow = bitsOf({0, 3});                 // Forced: External interrupt exit, NMI exit.
        const std::uint64_t kHigh = bitsOf({0, 1, 3, 5, 6, 7});    // The host additionally allows 1/6/7.
        const std::uint64_t kHost = (kHigh << 32) | kLow;
        const std::uint64_t kGot =
            KswordArkHvmFilterVmxCapabilityMsr(KSWORD_ARK_HVM_VMX_MSR_PINBASED, kHost);

        s.expect((kGot & 0xFFFFFFFFULL) == kLow,
                 L"the mandatory half of a paired capability comes back untouched");
        // Expected high half: host allow list intersected with the whitelist, then ORed back with mandatory bits. The bit was 1 but not in the whitelist, so it was dropped.
        // 6/7 are dropped even if not in the allow list; 0/3/5 are retained.
        s.expect((kGot >> 32) == bitsOf({0, 3, 5}),
                 L"the optional half is the host value intersected with the allow list");
        s.expect(((kGot >> 32) & ~(kHost >> 32)) == 0ULL,
                 L"narrowing never advertises a bit the host itself does not offer");
    }
    {
        // The cell where the forced bit is not in the whitelist. This is the sole reason for `high |= low`:
        // Removing a bit that hardware forces to 1 from the set of bits that 'can be 1' creates a **contradictory** capability. L1
        // calculates control values based on this, which the processor will flag as illegal, with the error code pointing to L1.
        const std::uint64_t kLow = bitsOf({0, 6});   // 6 is forced to 1 but is not in the whitelist.
        const std::uint64_t kHigh = bitsOf({0, 3, 5, 6});
        const std::uint64_t kHost = (kHigh << 32) | kLow;
        const std::uint64_t kGot =
            KswordArkHvmFilterVmxCapabilityMsr(KSWORD_ARK_HVM_VMX_MSR_PINBASED, kHost);

        s.expect(((kGot >> 32) & (1ULL << 6)) != 0ULL,
                 L"a bit the hardware forces to one survives narrowing even when it is not on the allow list");
        s.expect(((kGot >> 32) & (kGot & 0xFFFFFFFFULL)) == (kGot & 0xFFFFFFFFULL),
                 L"the result is self-consistent: everything mandatory is also permitted");
    }
    {
        // TRUE_* variants must follow the same path as non-TRUE variants. If they diverge, read-only TRUE_*
        // hypervisors (the vast majority of modern implementations) will receive a different capability set.
        const std::uint64_t kHost = (bitsOf({0, 1, 3, 5, 7}) << 32) | bitsOf({0});
        s.expect(KswordArkHvmFilterVmxCapabilityMsr(KSWORD_ARK_HVM_VMX_MSR_PINBASED, kHost) ==
                     KswordArkHvmFilterVmxCapabilityMsr(KSWORD_ARK_HVM_VMX_MSR_TRUE_PINBASED, kHost),
                 L"the TRUE pin-based variant narrows exactly like the legacy one");
        s.expect(KswordArkHvmFilterVmxCapabilityMsr(KSWORD_ARK_HVM_VMX_MSR_PROCBASED, kHost) ==
                     KswordArkHvmFilterVmxCapabilityMsr(KSWORD_ARK_HVM_VMX_MSR_TRUE_PROCBASED, kHost),
                 L"the TRUE primary variant narrows exactly like the legacy one");
        s.expect(KswordArkHvmFilterVmxCapabilityMsr(KSWORD_ARK_HVM_VMX_MSR_EXIT_CTLS, kHost) ==
                     KswordArkHvmFilterVmxCapabilityMsr(KSWORD_ARK_HVM_VMX_MSR_TRUE_EXIT_CTLS, kHost),
                 L"the TRUE exit variant narrows exactly like the legacy one");
        s.expect(KswordArkHvmFilterVmxCapabilityMsr(KSWORD_ARK_HVM_VMX_MSR_ENTRY_CTLS, kHost) ==
                     KswordArkHvmFilterVmxCapabilityMsr(KSWORD_ARK_HVM_VMX_MSR_TRUE_ENTRY_CTLS, kHost),
                 L"the TRUE entry variant narrows exactly like the legacy one");
    }
    {
        // EPT/VPID capabilities are in a **single-value** format, not paired. Treating them as paired would misinterpret the
        // lower 32 bits as mandatory bits and shift them to the upper half, falsely declaring numerous VPID capabilities.
        const std::uint64_t kHost = 0x00000F0106F34041ULL;  // Target machine measured value.
        const std::uint64_t kGot =
            KswordArkHvmFilterVmxCapabilityMsr(KSWORD_ARK_HVM_VMX_MSR_EPT_VPID_CAP, kHost);
        s.expect(kGot == (kHost & KSWORD_ARK_HVM_VMX_EPT_CAP_ALLOWED),
                 L"the EPT capability is a plain intersection with the allow list");
        // High half contains only INVVPID support bits and types 0/1/2; host-provided type 3 is discarded.
        s.expect((kGot >> 32) == 0x00000701ULL,
                 L"exactly INVVPID and its three advertised types survive out of everything the host offers");
        s.expect((kGot & (1ULL << 43)) == 0ULL,
                 L"the host's INVVPID type three is dropped, because nothing promised it");
        s.expect((kGot & ~kHost) == 0ULL,
                 L"narrowing the EPT capability never adds a bit the host lacks");
    }
    {
        // VMFUNC reports 'no functions at all'. The corresponding bit in the secondary control is also cleared;
        // clearing both intentionally prevents L1 from mistaking this for a configuration error and retrying.
        s.expect(KswordArkHvmFilterVmxCapabilityMsr(
                     KSWORD_ARK_HVM_VMX_MSR_VMFUNC, 0xFFFFFFFFFFFFFFFFULL) == 0ULL,
                 L"VMFUNC reports no functions at all, whatever the host offers");
    }
    {
        // MISC: Only clear the CR3-target count; the remaining bits are descriptive, and modifying them lacks justification.
        const std::uint64_t kHost = 0x00000000007004C1ULL | KSWORD_ARK_HVM_VMX_MISC_CR3_TARGET_MASK;
        const std::uint64_t kGot =
            KswordArkHvmFilterVmxCapabilityMsr(KSWORD_ARK_HVM_VMX_MSR_MISC, kHost);
        s.expect((kGot & KSWORD_ARK_HVM_VMX_MISC_CR3_TARGET_MASK) == 0ULL,
                 L"the CR3-target count is reported as zero, because no CR3-target field is copied");
        s.expect((kGot | KSWORD_ARK_HVM_VMX_MISC_CR3_TARGET_MASK) ==
                     (kHost | KSWORD_ARK_HVM_VMX_MISC_CR3_TARGET_MASK),
                 L"every other MISC bit passes through: they describe, they do not promise");
    }
    {
        // For the passed-through fields: BASIC must not be modified. The lower 31 bits contain the VMCS revision
        // ID; altering it causes VMXON and VMPTRLD to fail due to header mismatch. This is an unrelated
        // capability failure that would be incorrectly attributed to nested virtualization corruption.
        const std::uint64_t kHost = 0x00DA0400000000FFULL;
        s.expect(KswordArkHvmFilterVmxCapabilityMsr(KSWORD_ARK_HVM_VMX_MSR_BASIC, kHost) == kHost,
                 L"VMX_BASIC passes through untouched, revision identifier included");
        s.expect(KswordArkHvmFilterVmxCapabilityMsr(KSWORD_ARK_HVM_VMX_MSR_CR0_FIXED0, kHost) == kHost &&
                     KswordArkHvmFilterVmxCapabilityMsr(KSWORD_ARK_HVM_VMX_MSR_CR0_FIXED1, kHost) == kHost &&
                     KswordArkHvmFilterVmxCapabilityMsr(KSWORD_ARK_HVM_VMX_MSR_CR4_FIXED0, kHost) == kHost &&
                     KswordArkHvmFilterVmxCapabilityMsr(KSWORD_ARK_HVM_VMX_MSR_CR4_FIXED1, kHost) == kHost,
                 L"the fixed CR0 and CR4 bits pass through: they are architectural, not ours to narrow");
        s.expect(KswordArkHvmFilterVmxCapabilityMsr(KSWORD_ARK_HVM_VMX_MSR_VMCS_ENUM, kHost) == kHost,
                 L"the VMCS field enumeration passes through");
    }
    {
        // Idempotent. Once resident, the driver runs inside the guest; reading these MSRs yields
        // already-filtered values. Adding another layer of nesting filters a second time. If the deeper
        // layer modifies anything, it sees fewer capabilities, and no errors are reported anywhere.
        const std::uint64_t kSamples[] = {
            0x00000F0106F34041ULL,
            (bitsOf({0, 1, 3, 5, 6, 7}) << 32) | bitsOf({0, 3}),
            0xFFFFFFFFFFFFFFFFULL,
            0ULL,
        };
        const unsigned long kIndices[] = {
            KSWORD_ARK_HVM_VMX_MSR_PINBASED, KSWORD_ARK_HVM_VMX_MSR_PROCBASED,
            KSWORD_ARK_HVM_VMX_MSR_EXIT_CTLS, KSWORD_ARK_HVM_VMX_MSR_ENTRY_CTLS,
            KSWORD_ARK_HVM_VMX_MSR_PROCBASED2, KSWORD_ARK_HVM_VMX_MSR_EPT_VPID_CAP,
            KSWORD_ARK_HVM_VMX_MSR_MISC, KSWORD_ARK_HVM_VMX_MSR_VMFUNC,
            KSWORD_ARK_HVM_VMX_MSR_BASIC,
        };
        bool idempotent = true;
        for (unsigned long index : kIndices) {
            for (std::uint64_t sample : kSamples) {
                const std::uint64_t kOnce = KswordArkHvmFilterVmxCapabilityMsr(index, sample);
                if (KswordArkHvmFilterVmxCapabilityMsr(index, kOnce) != kOnce) {
                    idempotent = false;
                }
            }
        }
        s.expect(idempotent,
                 L"narrowing twice equals narrowing once, so a second nesting level sees the same capability");
    }
    {
        // Indices outside the range are returned unchanged. The caller already bounds the range; this additional check ensures
        // the function remains correct when extracted standalone, as it appears before the policy engine in hvm_exit.c.
        s.expect(KswordArkHvmFilterVmxCapabilityMsr(0x1B0UL, 0x1234567890ABCDEFULL) ==
                     0x1234567890ABCDEFULL,
                 L"an index outside the capability block is returned unchanged");
    }
}

} // namespace

int runHvmEptSwitchTests() {
    ksword_tests::Suite suite(L"HVM ept switch");
    testArchitecturalConstants(suite);
    testExecuteOnlyCapability(suite);
    testLeafDecomposition(suite);
    testLeafComposition(suite);
    testPermissionLegality(suite);
    testMemoryTypeLegality(suite);
    testFrameAlignment(suite);
    testLeafWellFormed(suite);
    testEptpComposition(suite);
    testEptpDecomposition(suite);
    testEptpWellFormed(suite);
    testEptpRebase(suite);
    testSwitchInvalidation(suite);
    testInveptTypeSupport(suite);
    testInveptDescriptor(suite);
    testPreEntryInvalidation(suite);
    testIndexArithmetic(suite);
    testEntryAddress(suite);
    testPageCost(suite);
    testIndexEncoding(suite);
    testAccessMapping(suite);
    testKindPermissions(suite);
    testDecideExhaustive(suite);
    testDecideRejections(suite);
    testRefuseHelper(suite);
    testPlanSwitch(suite);
    testProgressLedger(suite);
    testVmxCapabilityMasks(suite);
    testVmxCapabilityFilter(suite);
    suite.report();
    return suite.failures();
}
