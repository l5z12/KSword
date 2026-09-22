// Offline test for DDMA (Direct Disk Memory Access, shared/driver/KswordArkDdmaPlan.h).
//
// The four items under test share a common characteristic: **calculation errors do not trigger exceptions, and the consequences are irreversible**.
//
//   * The LBA encoding layout for ATA task files differs completely between 28-bit and 48-bit modes. A bit
//     calculation error produces no error code—the disk simply reads/writes another sector. DDMA must back up the
//     target sector before each operation and restore it afterward. Consequently, a single-bit encoding error causes
//     a backup read from location A while writing back to location B, permanently erasing the original data at B.
//   * The physical interval criterion determines whether to cross page boundaries to access adjacent physical pages. Since DMA granularity
//     is one page, relaxing the criterion by even one byte causes writes to overflow into the next page, which could contain anything.
//   * A miscalculated slice length causes the loop to either miss the tail or write the same segment twice.
//   * The gate sequence itself is the criterion: The kernel debug path isn't 'unusable' but 'causes a BSOD if
//     used'. A prompt saying 'Please fill in LBA first' masks this, leading users to fill LBA and trigger a BSOD.
//
// These four operations cannot be safely tested on real hardware; they must be proven
// on the build machine. The assertion principle is consistent with HvmWatchTests.cpp:
//   * Expected values are hardcoded via manual calculation, never reverse-calculated from the function under test;
//   * Test both sides of the boundary; testing only one side is equivalent to not testing at all;
//   * Rejected inputs must be explicitly rejected; do not only test the success path.

#include "TestSupport.h"

#include "../../../shared/driver/KswordArkDdmaPlan.h"
#include "../../../shared/evidence/DdmaScratchPlan.h"

#include <cstdint>
#include <vector>

namespace {

// A single DDMA transfer is fixed at 4096 bytes = 8 sectors of 512 bytes each.
constexpr unsigned long kSectors = KSWORD_ARK_DDMA_TRANSFER_BYTES / KSWORD_ARK_DDMA_SECTOR_SIZE;

// Readable aliases for register indices to avoid bare numeric indices in tests.
constexpr int kCount = KSWORD_ARK_ATA_TASKFILE_SECTOR_COUNT;
constexpr int kLow = KSWORD_ARK_ATA_TASKFILE_LBA_LOW;
constexpr int kMid = KSWORD_ARK_ATA_TASKFILE_LBA_MID;
constexpr int kHigh = KSWORD_ARK_ATA_TASKFILE_LBA_HIGH;
constexpr int kDevice = KSWORD_ARK_ATA_TASKFILE_DEVICE;
constexpr int kCommand = KSWORD_ARK_ATA_TASKFILE_COMMAND;

// ---------------------------------------------------------------------------
// 28-bit LBA encoding
// ---------------------------------------------------------------------------
void testLba28Encoding(ksword_tests::Suite& suite) {
    // Manual calculation for LBA 0x0ABBCCDD:
    //   LBA Low = 0xDD，LBA Mid = 0xCC，LBA High = 0xBB，
    //   Device = 0x40 | ((0x0ABBCCDD >> 24) & 0x0F) = 0x40 | 0x0A = 0x4A。
    const KSWORD_ARK_DDMA_TASKFILE kRead =
        KswordArkDdmaEncodeTaskFile(0x0ABBCCDDULL, kSectors, 0);
    suite.expect(kRead.valid == 1, L"ddma lba28: a representative read encodes");
    suite.expect(kRead.usesLba48 == 0, L"ddma lba28: stays in 28-bit mode");
    suite.expect(kRead.extraAtaFlags == 0, L"ddma lba28: adds no 48-bit ATA flag");
    suite.expect(kRead.currentTaskFile[kLow] == 0xDD, L"ddma lba28: LBA low byte");
    suite.expect(kRead.currentTaskFile[kMid] == 0xCC, L"ddma lba28: LBA mid byte");
    suite.expect(kRead.currentTaskFile[kHigh] == 0xBB, L"ddma lba28: LBA high byte");
    suite.expect(kRead.currentTaskFile[kDevice] == 0x4A,
        L"ddma lba28: device register carries LBA mode plus the top four LBA bits");
    suite.expect(kRead.currentTaskFile[kCount] == 8, L"ddma lba28: sector count is 8");
    suite.expect(kRead.currentTaskFile[kCommand] == KSWORD_ARK_ATA_CMD_READ_SECTORS,
        L"ddma lba28: read uses command 0x20");

    // previousTaskFile must remain entirely zero in 28-bit mode; any residual bits
    // would be interpreted by hardware as the high-order LBA bits in 48-bit mode.
    bool previousAllZero = true;
    for (int index = 0; index < KSWORD_ARK_ATA_TASKFILE_BYTES; ++index) {
        if (kRead.previousTaskFile[index] != 0) {
            previousAllZero = false;
        }
    }
    suite.expect(previousAllZero, L"ddma lba28: previous task file stays all zero");

    const KSWORD_ARK_DDMA_TASKFILE kWrite =
        KswordArkDdmaEncodeTaskFile(0x0ABBCCDDULL, kSectors, 1);
    suite.expect(kWrite.currentTaskFile[kCommand] == KSWORD_ARK_ATA_CMD_WRITE_SECTORS,
        L"ddma lba28: write uses command 0x30");
    suite.expect(kWrite.currentTaskFile[kDevice] == 0x4A,
        L"ddma lba28: write keeps the same device register as read");

    // LBA 0: All LBA bytes are zero; the Device has only the mode bits remaining.
    const KSWORD_ARK_DDMA_TASKFILE kZero = KswordArkDdmaEncodeTaskFile(0ULL, kSectors, 0);
    suite.expect(kZero.valid == 1, L"ddma lba28: LBA 0 is a legal value, not a sentinel");
    suite.expect(kZero.currentTaskFile[kLow] == 0x00, L"ddma lba28: LBA 0 low byte");
    suite.expect(kZero.currentTaskFile[kMid] == 0x00, L"ddma lba28: LBA 0 mid byte");
    suite.expect(kZero.currentTaskFile[kHigh] == 0x00, L"ddma lba28: LBA 0 high byte");
    suite.expect(kZero.currentTaskFile[kDevice] == 0x40,
        L"ddma lba28: LBA 0 device register is the bare LBA mode bit");
}

// ---------------------------------------------------------------------------
// Boundary between 28-bit and 48-bit modes
// ---------------------------------------------------------------------------
void testLbaModeBoundary(ksword_tests::Suite& suite) {
    // 0x0FFFFFFF is the maximum LBA representable in 28 bits: Device = 0x40 | 0x0F = 0x4F.
    const KSWORD_ARK_DDMA_TASKFILE kLast28 =
        KswordArkDdmaEncodeTaskFile(0x0FFFFFFFULL, kSectors, 0);
    suite.expect(kLast28.usesLba48 == 0, L"ddma boundary: 0x0FFFFFFF is still 28-bit");
    suite.expect(kLast28.currentTaskFile[kDevice] == 0x4F,
        L"ddma boundary: 0x0FFFFFFF fills all four device LBA bits");
    suite.expect(kLast28.currentTaskFile[kCommand] == KSWORD_ARK_ATA_CMD_READ_SECTORS,
        L"ddma boundary: 0x0FFFFFFF uses the 28-bit read command");

    // Adding one more requires switching to 48-bit mode. This is the most error-prone field in the entire
    // encoding: the command codes, Device register, and previousTaskFile differ on both sides of the boundary.
    const KSWORD_ARK_DDMA_TASKFILE kFirst48 =
        KswordArkDdmaEncodeTaskFile(0x10000000ULL, kSectors, 0);
    suite.expect(kFirst48.usesLba48 == 1, L"ddma boundary: 0x10000000 switches to 48-bit");
    suite.expect(kFirst48.extraAtaFlags == ATA_FLAGS_48BIT_COMMAND,
        L"ddma boundary: 48-bit mode sets the 48-bit ATA flag");
    suite.expect(kFirst48.currentTaskFile[kCommand] == KSWORD_ARK_ATA_CMD_READ_SECTORS_EXT,
        L"ddma boundary: 48-bit read uses command 0x24");
    suite.expect(kFirst48.currentTaskFile[kDevice] == 0x40,
        L"ddma boundary: 48-bit device register carries no LBA bits at all");
    suite.expect(kFirst48.currentTaskFile[kLow] == 0x00,
        L"ddma boundary: 0x10000000 low byte");
    suite.expect(kFirst48.currentTaskFile[kMid] == 0x00,
        L"ddma boundary: 0x10000000 mid byte");
    suite.expect(kFirst48.currentTaskFile[kHigh] == 0x00,
        L"ddma boundary: 0x10000000 high byte");
    suite.expect(kFirst48.previousTaskFile[kLow] == 0x10,
        L"ddma boundary: 0x10000000 spills 0x10 into the previous LBA low byte");
    suite.expect(kFirst48.previousTaskFile[kMid] == 0x00,
        L"ddma boundary: 0x10000000 previous mid byte");
    suite.expect(kFirst48.previousTaskFile[kHigh] == 0x00,
        L"ddma boundary: 0x10000000 previous high byte");

    const KSWORD_ARK_DDMA_TASKFILE kWrite48 =
        KswordArkDdmaEncodeTaskFile(0x10000000ULL, kSectors, 1);
    suite.expect(kWrite48.currentTaskFile[kCommand] == KSWORD_ARK_ATA_CMD_WRITE_SECTORS_EXT,
        L"ddma boundary: 48-bit write uses command 0x34");
}

// ---------------------------------------------------------------------------
// 48-bit LBA encoding and upper limit
// ---------------------------------------------------------------------------
void testLba48Encoding(ksword_tests::Suite& suite) {
    // LBA 0x0000FFFFFFFFFFF0 manual calculation: low three bytes F0 FF FF, high three bytes FF FF FF.
    const KSWORD_ARK_DDMA_TASKFILE kHighValue =
        KswordArkDdmaEncodeTaskFile(0x0000FFFFFFFFFFF0ULL, kSectors, 0);
    suite.expect(kHighValue.valid == 1, L"ddma lba48: a near-maximum LBA encodes");
    suite.expect(kHighValue.usesLba48 == 1, L"ddma lba48: near-maximum LBA is 48-bit");
    suite.expect(kHighValue.currentTaskFile[kLow] == 0xF0, L"ddma lba48: current low byte");
    suite.expect(kHighValue.currentTaskFile[kMid] == 0xFF, L"ddma lba48: current mid byte");
    suite.expect(kHighValue.currentTaskFile[kHigh] == 0xFF, L"ddma lba48: current high byte");
    suite.expect(kHighValue.previousTaskFile[kLow] == 0xFF, L"ddma lba48: previous low byte");
    suite.expect(kHighValue.previousTaskFile[kMid] == 0xFF, L"ddma lba48: previous mid byte");
    suite.expect(kHighValue.previousTaskFile[kHigh] == 0xFF, L"ddma lba48: previous high byte");

    // Exactly at the 48-bit limit: LBA + sector count would exceed 2^48, so it must be rejected rather than wrapped.
    // 0x0000FFFFFFFFFFFF + 8 > 0x0001000000000000。
    const KSWORD_ARK_DDMA_TASKFILE kOverflow =
        KswordArkDdmaEncodeTaskFile(0x0000FFFFFFFFFFFFULL, kSectors, 0);
    suite.expect(kOverflow.valid == 0,
        L"ddma lba48: a range running past 2^48 is rejected, not wrapped");

    // The LBA itself exceeds the 48-bit limit.
    const KSWORD_ARK_DDMA_TASKFILE kBeyond =
        KswordArkDdmaEncodeTaskFile(KSWORD_ARK_DDMA_LBA48_LIMIT, 1UL, 0);
    suite.expect(kBeyond.valid == 0, L"ddma lba48: an LBA at the 2^48 limit is rejected");

    // The last single-sector request within the limit must be accepted; otherwise, the criterion rejects one extra slot.
    const KSWORD_ARK_DDMA_TASKFILE kLastSector =
        KswordArkDdmaEncodeTaskFile(KSWORD_ARK_DDMA_LBA48_LIMIT - 1ULL, 1UL, 0);
    suite.expect(kLastSector.valid == 1,
        L"ddma lba48: the last single sector below 2^48 is accepted");
}

// ---------------------------------------------------------------------------
// Sector count encoding
// ---------------------------------------------------------------------------
void testSectorCountEncoding(ksword_tests::Suite& suite) {
    // Zero sectors is meaningless and must be rejected—on ATA, 0 has a different meaning
    // (256). Allowing it would silently convert a no-op into a 256-sector operation.
    suite.expect(KswordArkDdmaEncodeTaskFile(0ULL, 0UL, 0).valid == 0,
        L"ddma count: zero sectors is rejected");

    // In 28-bit mode, the sector count is 8 bits; 256 is represented as 0 per ATA convention.
    const KSWORD_ARK_DDMA_TASKFILE kCount256 = KswordArkDdmaEncodeTaskFile(0ULL, 256UL, 0);
    suite.expect(kCount256.valid == 1, L"ddma count: 256 sectors is legal");
    suite.expect(kCount256.usesLba48 == 0, L"ddma count: 256 sectors still fits 28-bit mode");
    suite.expect(kCount256.currentTaskFile[kCount] == 0x00,
        L"ddma count: 256 sectors is encoded as 0 in 28-bit mode");

    // 257 sectors exceed 8 bits, so the 16-bit sector count in 48-bit mode must be used to represent it, even if the LBA is small.
    const KSWORD_ARK_DDMA_TASKFILE kCount257 = KswordArkDdmaEncodeTaskFile(0ULL, 257UL, 0);
    suite.expect(kCount257.valid == 1, L"ddma count: 257 sectors is legal");
    suite.expect(kCount257.usesLba48 == 1,
        L"ddma count: 257 sectors forces 48-bit mode even at LBA 0");
    suite.expect(kCount257.currentTaskFile[kCount] == 0x01,
        L"ddma count: 257 low byte is 0x01");
    suite.expect(kCount257.previousTaskFile[kCount] == 0x01,
        L"ddma count: 257 high byte is 0x01");

    // 65536 is the upper limit in 48-bit mode, also represented as 0.
    const KSWORD_ARK_DDMA_TASKFILE kCount65536 = KswordArkDdmaEncodeTaskFile(0ULL, 65536UL, 0);
    suite.expect(kCount65536.valid == 1, L"ddma count: 65536 sectors is legal");
    suite.expect(kCount65536.currentTaskFile[kCount] == 0x00,
        L"ddma count: 65536 low byte is 0");
    suite.expect(kCount65536.previousTaskFile[kCount] == 0x00,
        L"ddma count: 65536 high byte is 0");

    suite.expect(KswordArkDdmaEncodeTaskFile(0ULL, 65537UL, 0).valid == 0,
        L"ddma count: 65537 sectors is rejected");
}

// ---------------------------------------------------------------------------
// Physical range predicate
// ---------------------------------------------------------------------------
void testPhysicalRange(ksword_tests::Suite& suite) {
    constexpr unsigned long long kPage = KSWORD_ARK_DDMA_TRANSFER_BYTES;

    suite.expect(KswordArkDdmaIsPhysicalRangeValid(0x1000ULL, KSWORD_ARK_DDMA_TRANSFER_BYTES) == 1,
        L"ddma range: an aligned whole page is accepted");
    // The last byte within a page can be read individually; adding one more byte crosses the page boundary. Test both boundaries.
    suite.expect(KswordArkDdmaIsPhysicalRangeValid(0x1000ULL + kPage - 1ULL, 1UL) == 1,
        L"ddma range: the last byte of a page is accepted");
    suite.expect(KswordArkDdmaIsPhysicalRangeValid(0x1000ULL + kPage - 1ULL, 2UL) == 0,
        L"ddma range: two bytes straddling the page boundary are rejected");
    suite.expect(KswordArkDdmaIsPhysicalRangeValid(0x1001ULL, KSWORD_ARK_DDMA_TRANSFER_BYTES) == 0,
        L"ddma range: a full page starting one byte in is rejected");

    suite.expect(KswordArkDdmaIsPhysicalRangeValid(0x1000ULL, 0UL) == 0,
        L"ddma range: zero length is rejected");
    suite.expect(
        KswordArkDdmaIsPhysicalRangeValid(0x1000ULL, KSWORD_ARK_DDMA_TRANSFER_BYTES + 1UL) == 0,
        L"ddma range: longer than one transfer is rejected");

    // At the boundaries of the 52-bit physical address limit. The last page exactly reaches the limit and must be accepted.
    constexpr unsigned long long kLastPage =
        (KSWORD_ARK_DDMA_PHYSICAL_ADDRESS_MAX + 1ULL) - KSWORD_ARK_DDMA_TRANSFER_BYTES;
    suite.expect(
        KswordArkDdmaIsPhysicalRangeValid(kLastPage, KSWORD_ARK_DDMA_TRANSFER_BYTES) == 1,
        L"ddma range: the last page below the 52-bit limit is accepted");
    suite.expect(
        KswordArkDdmaIsPhysicalRangeValid(KSWORD_ARK_DDMA_PHYSICAL_ADDRESS_MAX + 1ULL, 1UL) == 0,
        L"ddma range: one byte past the 52-bit limit is rejected");
    suite.expect(KswordArkDdmaIsPhysicalRangeValid(0ULL, 1UL) == 1,
        L"ddma range: physical address 0 is a legal target");
}

// ---------------------------------------------------------------------------
// Chunk length
// ---------------------------------------------------------------------------
void testChunkLength(ksword_tests::Suite& suite) {
    constexpr unsigned long long kPage = KSWORD_ARK_DDMA_TRANSFER_BYTES;

    suite.expect(KswordArkDdmaChunkLength(0x1000ULL, kPage * 2ULL) == kPage,
        L"ddma chunk: an aligned cursor takes a whole page");
    // Starting in the middle of a page can only reach the page end: 0x2000 - 0x1800 = 0x800.
    suite.expect(KswordArkDdmaChunkLength(0x1800ULL, kPage * 2ULL) == 0x800UL,
        L"ddma chunk: an unaligned cursor stops at the page boundary");
    suite.expect(KswordArkDdmaChunkLength(0x1800ULL, 100ULL) == 100UL,
        L"ddma chunk: a short remainder is not padded up to the page boundary");
    suite.expect(KswordArkDdmaChunkLength(0x1FFFULL, 10ULL) == 1UL,
        L"ddma chunk: the last byte of a page yields exactly one byte");
    suite.expect(KswordArkDdmaChunkLength(0x1000ULL, 0ULL) == 0UL,
        L"ddma chunk: nothing remaining yields zero");

    // Walk through a complete loop: cross three pages from a non-aligned address; the cumulative total must exactly equal the
    // requested length, and no step may cross a page boundary. Any calculation error will immediately break this invariant.
    unsigned long long cursor = 0x1800ULL;
    unsigned long long remaining = kPage * 2ULL + 0x100ULL;
    unsigned long long consumed = 0ULL;
    int steps = 0;
    bool everCrossedPage = false;
    while (remaining > 0ULL && steps < 16) {
        const unsigned long kChunk = KswordArkDdmaChunkLength(cursor, remaining);
        if (kChunk == 0UL) {
            break;
        }
        const unsigned long long kPageBase = cursor & ~(kPage - 1ULL);
        if ((cursor + kChunk - 1ULL) >= (kPageBase + kPage)) {
            everCrossedPage = true;
        }
        cursor += kChunk;
        remaining -= kChunk;
        consumed += kChunk;
        ++steps;
    }
    suite.expect(remaining == 0ULL, L"ddma chunk: the walk consumes the whole range");
    suite.expect(consumed == kPage * 2ULL + 0x100ULL,
        L"ddma chunk: the walk consumes exactly the requested byte count");
    suite.expect(!everCrossedPage, L"ddma chunk: no single step ever crosses a page boundary");
    // Manual step count: 0x1800 first pads to the page end to get 0x800 (2048), then takes a full page of
    // 0x1000 (4096), and finally takes the remaining 8448 - 2048 - 4096 = 2304 in one go, totaling three steps.
    suite.expect(steps == 3, L"ddma chunk: 0x1800 plus 0x2100 bytes takes exactly three steps");
}

// ---------------------------------------------------------------------------
// Gate order
// ---------------------------------------------------------------------------
void testGateOrder(ksword_tests::Suite& suite) {
    // Only allow when fully prepared.
    suite.expect(KswordArkDdmaEvaluateGate(1, 0, 1, 1) == KSWORD_ARK_DDMA_GATE_ALLOWED,
        L"ddma gate: a fully prepared session is allowed");

    // Unconfigured takes precedence over all: without disk probing, other states are meaningless.
    suite.expect(KswordArkDdmaEvaluateGate(0, 0, 1, 1) == KSWORD_ARK_DDMA_GATE_NOT_CONFIGURED,
        L"ddma gate: an unconfigured session reports not-configured");
    suite.expect(KswordArkDdmaEvaluateGate(0, 1, 0, 0) == KSWORD_ARK_DDMA_GATE_NOT_CONFIGURED,
        L"ddma gate: not-configured outranks every later reason");

    // Kernel debugging must be checked before LBA and confirmation. This is not a 'not yet configured' case but a 'will cause a BSOD even
    // if configured' case; if covered by the following two checks, users will follow the prompts to add configuration and then hit a BSOD.
    suite.expect(KswordArkDdmaEvaluateGate(1, 1, 1, 1) == KSWORD_ARK_DDMA_GATE_KERNEL_DEBUGGER,
        L"ddma gate: kernel debugging blocks an otherwise complete session");
    suite.expect(KswordArkDdmaEvaluateGate(1, 1, 0, 0) == KSWORD_ARK_DDMA_GATE_KERNEL_DEBUGGER,
        L"ddma gate: kernel debugging outranks a missing scratch LBA");
    suite.expect(KswordArkDdmaEvaluateGate(1, 1, 1, 0) == KSWORD_ARK_DDMA_GATE_KERNEL_DEBUGGER,
        L"ddma gate: kernel debugging outranks a missing acknowledgement");

    // Missing LBA takes precedence over acknowledgment: an address must exist before confirming it can be overwritten.
    suite.expect(
        KswordArkDdmaEvaluateGate(1, 0, 0, 1) == KSWORD_ARK_DDMA_GATE_SCRATCH_LBA_MISSING,
        L"ddma gate: a missing scratch LBA is reported even when acknowledged");
    suite.expect(
        KswordArkDdmaEvaluateGate(1, 0, 0, 0) == KSWORD_ARK_DDMA_GATE_SCRATCH_LBA_MISSING,
        L"ddma gate: a missing scratch LBA outranks a missing acknowledgement");
    suite.expect(
        KswordArkDdmaEvaluateGate(1, 0, 1, 0) == KSWORD_ARK_DDMA_GATE_SCRATCH_NOT_ACKNOWLEDGED,
        L"ddma gate: an unacknowledged scratch sector is the last blocker");

    // enumerate all 16 combinations: only one unique combination is allowed; all others must provide a rejection reason.
    int allowedCount = 0;
    bool everUnclassified = false;
    for (int mask = 0; mask < 16; ++mask) {
        const int kConfigured = (mask & 1) ? 1 : 0;
        const int kDebugger = (mask & 2) ? 1 : 0;
        const int kLba = (mask & 4) ? 1 : 0;
        const int kAck = (mask & 8) ? 1 : 0;
        const int kGate = KswordArkDdmaEvaluateGate(kConfigured, kDebugger, kLba, kAck);
        if (kGate == KSWORD_ARK_DDMA_GATE_ALLOWED) {
            ++allowedCount;
            // Allowance can only occur when [configured + no kernel debugging + LBA present + acknowledged].
            if (!(kConfigured == 1 && kDebugger == 0 && kLba == 1 && kAck == 1)) {
                everUnclassified = true;
            }
        }
        else if (kGate < KSWORD_ARK_DDMA_GATE_NOT_CONFIGURED ||
                 kGate > KSWORD_ARK_DDMA_GATE_SCRATCH_NOT_ACKNOWLEDGED) {
            everUnclassified = true;
        }
    }
    suite.expect(allowedCount == 1,
        L"ddma gate: exactly one of the sixteen state combinations is allowed");
    suite.expect(!everUnclassified,
        L"ddma gate: every rejected combination carries a classified reason");
}

// ---------------------------------------------------------------------------
// flags bitfield and allowed mask
// ---------------------------------------------------------------------------
//
// This set of assertions was derived from a real hardware failure. Originally, QUERY_FLAG_PROBE_TRANSFER took
// 0x1, colliding with the same bit as the generic UI_CONFIRMED; additionally, QUERY_FLAG_ALLOWED omitted reading
// SCRATCH_LBA_VALID during the backend's probeRequested check. The combined effect of these two errors was:
// The transport probe path is **never reached**—the request is rejected at the handler's
// flags validation with win32=87, so the backend judgment logic is never executed.
//
// Compilation, offline unit tests, and code reviews cannot catch this: the bit value is a valid constant, the mask is a valid
// expression, but the contradiction only becomes apparent when comparing the two. Therefore, the check must be written as an assertion.
void testFlagLayout(ksword_tests::Suite& suite) {
    // Common bitfields and query-specific bitfields must be completely disjoint.
    constexpr unsigned long kCommonFlags =
        KSWORD_ARK_DDMA_FLAG_UI_CONFIRMED |
        KSWORD_ARK_DDMA_FLAG_FORCE |
        KSWORD_ARK_DDMA_FLAG_SCRATCH_LBA_VALID |
        KSWORD_ARK_DDMA_FLAG_SCRATCH_ACKNOWLEDGED;
    suite.expect((kCommonFlags & KSWORD_ARK_DDMA_QUERY_FLAG_PROBE_TRANSFER) == 0UL,
        L"ddma flags: the query-only flag does not collide with any common flag");

    // The four general-purpose bits are pairwise distinct.
    suite.expect(KSWORD_ARK_DDMA_FLAG_UI_CONFIRMED != KSWORD_ARK_DDMA_FLAG_FORCE,
        L"ddma flags: UI_CONFIRMED and FORCE are distinct bits");
    suite.expect(KSWORD_ARK_DDMA_FLAG_SCRATCH_LBA_VALID !=
                 KSWORD_ARK_DDMA_FLAG_SCRATCH_ACKNOWLEDGED,
        L"ddma flags: SCRATCH_LBA_VALID and SCRATCH_ACKNOWLEDGED are distinct bits");
    suite.expect((KSWORD_ARK_DDMA_FLAG_UI_CONFIRMED |
                  KSWORD_ARK_DDMA_FLAG_FORCE |
                  KSWORD_ARK_DDMA_FLAG_SCRATCH_LBA_VALID |
                  KSWORD_ARK_DDMA_FLAG_SCRATCH_ACKNOWLEDGED) == 0x0000000FUL,
        L"ddma flags: the four common bits occupy exactly the low nibble");

    // The allowed mask must be a superset of the bits that the backend actually reads on this path.
    // Query: backend reads PROBE_TRANSFER and SCRATCH_LBA_VALID.
    suite.expect(
        (KSWORD_ARK_DDMA_QUERY_FLAG_ALLOWED & KSWORD_ARK_DDMA_QUERY_FLAG_PROBE_TRANSFER) != 0UL,
        L"ddma flags: query allow-mask permits PROBE_TRANSFER");
    suite.expect(
        (KSWORD_ARK_DDMA_QUERY_FLAG_ALLOWED & KSWORD_ARK_DDMA_FLAG_SCRATCH_LBA_VALID) != 0UL,
        L"ddma flags: query allow-mask permits SCRATCH_LBA_VALID, so the transfer probe is reachable");

    // Read: Backend reads SCRATCH_LBA_VALID and SCRATCH_ACKNOWLEDGED.
    suite.expect(
        (KSWORD_ARK_DDMA_READ_FLAG_ALLOWED & KSWORD_ARK_DDMA_FLAG_SCRATCH_LBA_VALID) != 0UL,
        L"ddma flags: read allow-mask permits SCRATCH_LBA_VALID");
    suite.expect(
        (KSWORD_ARK_DDMA_READ_FLAG_ALLOWED & KSWORD_ARK_DDMA_FLAG_SCRATCH_ACKNOWLEDGED) != 0UL,
        L"ddma flags: read allow-mask permits SCRATCH_ACKNOWLEDGED");
    // Read path must not allow FORCE: reads have no force semantics; allowing it equates to an unexplained bit.
    suite.expect((KSWORD_ARK_DDMA_READ_FLAG_ALLOWED & KSWORD_ARK_DDMA_FLAG_FORCE) == 0UL,
        L"ddma flags: read allow-mask does not permit FORCE");

    // Write: all read flags plus FORCE.
    suite.expect(
        (KSWORD_ARK_DDMA_WRITE_FLAG_ALLOWED & KSWORD_ARK_DDMA_FLAG_FORCE) != 0UL,
        L"ddma flags: write allow-mask permits FORCE");
    suite.expect(
        (KSWORD_ARK_DDMA_WRITE_FLAG_ALLOWED & KSWORD_ARK_DDMA_READ_FLAG_ALLOWED) ==
            KSWORD_ARK_DDMA_READ_FLAG_ALLOWED,
        L"ddma flags: write allow-mask is a superset of the read allow-mask");

    // Gate status codes must be pairwise distinct. The three rejection reasons correspond to three
    // completely different user actions; if any two collide, the UI cannot provide the correct next step.
    suite.expect(
        KSWORD_ARK_DDMA_READ_STATUS_SCRATCH_LBA_REQUIRED !=
            KSWORD_ARK_DDMA_READ_STATUS_SCRATCH_NOT_ACKNOWLEDGED,
        L"ddma status: read LBA-required and not-acknowledged are distinct");
    suite.expect(
        KSWORD_ARK_DDMA_WRITE_STATUS_FORCE_REQUIRED !=
            KSWORD_ARK_DDMA_WRITE_STATUS_SCRATCH_NOT_ACKNOWLEDGED,
        L"ddma status: write force-required and not-acknowledged are distinct");
    suite.expect(
        KSWORD_ARK_DDMA_WRITE_STATUS_FORCE_REQUIRED !=
            KSWORD_ARK_DDMA_WRITE_STATUS_SCRATCH_LBA_REQUIRED,
        L"ddma status: write force-required and LBA-required are distinct");
}

// ---------------------------------------------------------------------------
// SCSI CDB encoding (NVMe / SAS / SATA / synthetic SCSI transfer)
// ---------------------------------------------------------------------------
//
// Neither error type triggers here; instead, it reads/writes another sector:
//   * CDB multi-byte fields are **big-endian**, opposite to x86; writing LBA incorrectly points to a different location.
//   * The transfer length unit is **blocks**, not bytes; treating 4096 as a block count would cause the controller to operate over a range 800 times larger.
void testScsiCdb(ksword_tests::Suite& suite) {
    constexpr unsigned long kBytes = KSWORD_ARK_DDMA_TRANSFER_BYTES;  // 4096

    // 512-byte sector: 4096 / 512 = 8 blocks. LBA 0x01020304 in big-endian layout is 01 02 03 04.
    {
        const KSWORD_ARK_DDMA_CDB kRead =
            KswordArkDdmaEncodeCdb(0x01020304ULL, kBytes, 512UL, 0);
        suite.expect(kRead.valid == 1, L"ddma cdb: a representative 512-byte-sector read encodes");
        suite.expect(kRead.cdbLength == 10, L"ddma cdb: a 32-bit LBA uses the 10-byte CDB");
        suite.expect(kRead.cdb[0] == KSWORD_ARK_SCSI_CMD_READ_10,
            L"ddma cdb: read uses opcode 0x28");
        suite.expect(kRead.cdb[2] == 0x01, L"ddma cdb: LBA byte 0 is the most significant (big endian)");
        suite.expect(kRead.cdb[3] == 0x02, L"ddma cdb: LBA byte 1");
        suite.expect(kRead.cdb[4] == 0x03, L"ddma cdb: LBA byte 2");
        suite.expect(kRead.cdb[5] == 0x04, L"ddma cdb: LBA byte 3 is the least significant");
        suite.expect(kRead.cdb[7] == 0x00, L"ddma cdb: block count high byte");
        suite.expect(kRead.cdb[8] == 0x08,
            L"ddma cdb: the transfer length is 8 BLOCKS, not 4096 bytes");

        const KSWORD_ARK_DDMA_CDB kWrite =
            KswordArkDdmaEncodeCdb(0x01020304ULL, kBytes, 512UL, 1);
        suite.expect(kWrite.cdb[0] == KSWORD_ARK_SCSI_CMD_WRITE_10,
            L"ddma cdb: write uses opcode 0x2A");
        suite.expect(kWrite.cdb[5] == 0x04, L"ddma cdb: write keeps the same LBA encoding as read");
    }

    // 4Kn disk: 4096 / 4096 = 1 block. Using 512 would yield 8, which is an eightfold range.
    {
        const KSWORD_ARK_DDMA_CDB kRead = KswordArkDdmaEncodeCdb(100ULL, kBytes, 4096UL, 0);
        suite.expect(kRead.valid == 1, L"ddma cdb: a 4Kn sector size encodes");
        suite.expect(kRead.cdb[8] == 0x01,
            L"ddma cdb: on a 4Kn disk one transfer is exactly one block");
    }

    // Sector size does not divide evenly: This indicates the caller used bytes as block counts; it must be rejected rather than rounded.
    suite.expect(KswordArkDdmaEncodeCdb(0ULL, 4096UL, 3000UL, 0).valid == 0,
        L"ddma cdb: a transfer size that is not a multiple of the sector size is refused");
    suite.expect(KswordArkDdmaEncodeCdb(0ULL, 4096UL, 0UL, 0).valid == 0,
        L"ddma cdb: a zero sector size is refused");
    suite.expect(KswordArkDdmaEncodeCdb(0ULL, 0UL, 512UL, 0).valid == 0,
        L"ddma cdb: a zero transfer size is refused");

    // 32-bit boundary: exactly fits a 10-byte CDB; adding one more requires switching to a 16-byte CDB.
    {
        const KSWORD_ARK_DDMA_CDB kLast32 =
            KswordArkDdmaEncodeCdb(KSWORD_ARK_DDMA_LBA32_LIMIT - 1ULL, kBytes, 512UL, 0);
        suite.expect(kLast32.cdbLength == 10,
            L"ddma cdb: the last 32-bit LBA still uses the 10-byte CDB");
        suite.expect(kLast32.cdb[2] == 0xFF && kLast32.cdb[5] == 0xFF,
            L"ddma cdb: the last 32-bit LBA fills all four LBA bytes");

        const KSWORD_ARK_DDMA_CDB kFirst64 =
            KswordArkDdmaEncodeCdb(KSWORD_ARK_DDMA_LBA32_LIMIT, kBytes, 512UL, 0);
        suite.expect(kFirst64.cdbLength == 16,
            L"ddma cdb: one past the 32-bit limit switches to the 16-byte CDB");
        suite.expect(kFirst64.cdb[0] == KSWORD_ARK_SCSI_CMD_READ_16,
            L"ddma cdb: the 16-byte read uses opcode 0x88");
        // 0x0000000100000000 Big-endian expansion: 00 00 00 01 00 00 00 00
        suite.expect(kFirst64.cdb[5] == 0x01,
            L"ddma cdb: the 16-byte CDB places the 33rd bit in LBA byte 3");
        suite.expect(kFirst64.cdb[9] == 0x00, L"ddma cdb: the 16-byte CDB low LBA byte");
        suite.expect(kFirst64.cdb[13] == 0x08,
            L"ddma cdb: the 16-byte CDB block count is also in blocks");

        const KSWORD_ARK_DDMA_CDB kWrite64 =
            KswordArkDdmaEncodeCdb(KSWORD_ARK_DDMA_LBA32_LIMIT, kBytes, 512UL, 1);
        suite.expect(kWrite64.cdb[0] == KSWORD_ARK_SCSI_CMD_WRITE_16,
            L"ddma cdb: the 16-byte write uses opcode 0x8A");
    }

    // The CDB tail must remain zero: residual bytes would be interpreted as control bits.
    {
        const KSWORD_ARK_DDMA_CDB kRead = KswordArkDdmaEncodeCdb(1ULL, kBytes, 512UL, 0);
        bool tailZero = true;
        for (int index = 10; index < KSWORD_ARK_SCSI_CDB_BYTES; ++index) {
            if (kRead.cdb[index] != 0) { tailZero = false; }
        }
        suite.expect(tailZero, L"ddma cdb: bytes past a 10-byte CDB stay zero");
        suite.expect(kRead.cdb[1] == 0 && kRead.cdb[6] == 0 && kRead.cdb[9] == 0,
            L"ddma cdb: the reserved and control bytes stay zero");
    }
}

// ---------------------------------------------------------------------------
// Scratch sector candidate selection.
// ---------------------------------------------------------------------------
//
// This logic determines which sectors will be overwritten. The consequence of a wrong selection is not an error, but corruption of the user's
// bootloader or partition table backup, which is only discovered on the next boot. Therefore, the criteria must cover the boundaries on both sides.
//
// Three invariants:
//   * Candidates intersecting the disk header reserved area can never be auto-selected — on MBR disks,
//     GRUB's core image is embedded in LBA 1..2047, with no corresponding partition table entries.
//   * Candidates intersecting the GPT backup partition table are always unavailable.
//   * Alignment consumes the first few sectors at the gap start; availability must be re-checked after alignment.
void testScratchPlan(ksword_tests::Suite& suite) {
    using ksword::evidence::DdmaScratchOccupiedRange;
    using ksword::evidence::DdmaScratchRisk;
    using ksword::evidence::ddmaScratchRiskIsSelectable;
    using ksword::evidence::planDdmaScratchCandidates;

    constexpr std::uint32_t kNeed = 8U;  // One transfer = 8 × 512-byte sectors.

    // Physical layout (dev machine disk 0, GPT 1863 GB): header gap 34..2047 is blocked by
    // partition 1 start at 2048; 1872 sectors are left between partition 3 and partition 4.
    {
        const std::vector<DdmaScratchOccupiedRange> kOccupied{
            { 2048ULL, 204800ULL },
            { 206848ULL, 32768ULL },
            { 239616ULL, 3904846000ULL },
            { 3905087488ULL, 1941647ULL },
        };
        const auto kCandidates = planDdmaScratchCandidates(3907029168ULL, kOccupied, kNeed);
        suite.expect(!kCandidates.empty(), L"ddma scratch: a real GPT layout yields candidates");
        const auto& best = kCandidates.front();
        suite.expect(best.usable, L"ddma scratch: the top candidate on a real layout is usable");
        suite.expect(best.risk == DdmaScratchRisk::kInteriorGap,
            L"ddma scratch: the inter-partition gap outranks the head gap");
        // Gap range: 3905085616..3905087487; aligning upward to a multiple of 8
        // yields 3905085616 itself (3905085616 / 8 = 488135702, exact division).
        suite.expect(best.startSector == 3905085616ULL,
            L"ddma scratch: the top candidate starts at the aligned inter-partition gap");
        suite.expect(best.gapSectorCount == 1872ULL,
            L"ddma scratch: the inter-partition gap length is reported as evidence");

        // The head gap must still appear in the list (so the user can see
        // why it wasn't selected), but it must never be placed first.
        bool sawHead = false;
        for (std::size_t i = 0; i < kCandidates.size(); ++i) {
            if (kCandidates[i].risk == DdmaScratchRisk::kHeadReserved) {
                sawHead = true;
                suite.expect(i != 0, L"ddma scratch: a head-reserved gap is never ranked first");
            }
        }
        suite.expect(sawHead, L"ddma scratch: the head gap is still listed, not silently dropped");
    }

    // Only when a header gap is available: still listed, but not auto-selectable.
    {
        const std::vector<DdmaScratchOccupiedRange> kOccupied{
            { 2048ULL, 1000000ULL - 2048ULL },
        };
        const auto kCandidates = planDdmaScratchCandidates(1000000ULL, kOccupied, kNeed);
        suite.expect(!kCandidates.empty(), L"ddma scratch: a head-only layout still yields a listing");
        suite.expect(kCandidates.front().risk == DdmaScratchRisk::kHeadReserved,
            L"ddma scratch: the head gap is the only candidate here");
        suite.expect(!ddmaScratchRiskIsSelectable(kCandidates.front().risk),
            L"ddma scratch: a head-reserved candidate is not auto-selectable");
    }

    // Grading logic: Only two gap types are selectable automatically.
    suite.expect(ddmaScratchRiskIsSelectable(DdmaScratchRisk::kInteriorGap),
        L"ddma scratch: an interior gap is selectable");
    suite.expect(ddmaScratchRiskIsSelectable(DdmaScratchRisk::kTailGap),
        L"ddma scratch: a tail gap is selectable");
    suite.expect(!ddmaScratchRiskIsSelectable(DdmaScratchRisk::kHeadReserved),
        L"ddma scratch: a head-reserved region is not selectable");
    suite.expect(!ddmaScratchRiskIsSelectable(DdmaScratchRisk::kTailReserved),
        L"ddma scratch: a tail-reserved region is not selectable");

    // Tail reservation: Space next to the backup partition table must be unavailable. A disk with 10000 sectors and a
    // 64-sector tail reservation excludes sectors from 9936 onward. The partition occupies 2048..9930, leaving 9930..10000.
    {
        const std::vector<DdmaScratchOccupiedRange> kOccupied{
            { 2048ULL, 9930ULL - 2048ULL },
        };
        const auto kCandidates = planDdmaScratchCandidates(10000ULL, kOccupied, kNeed);
        bool tailRejected = false;
        for (const auto& candidate : kCandidates) {
            if (candidate.gapStartSector == 9930ULL) {
                // After alignment, start is 9936; 9936+8=9944 > 9936 (=10000-64), so it does not fit.
                suite.expect(!candidate.usable,
                    L"ddma scratch: a gap running into the backup GPT is rejected");
                tailRejected = true;
            }
        }
        suite.expect(tailRejected, L"ddma scratch: the tail gap was evaluated at all");
    }

    // Align and consume the start: the gap 2049..2059 (11 sectors) appears sufficient for 8 items, but after aligning
    // to 2056, only 4 remain. Comparing against the original length would yield an out-of-bounds suggestion.
    {
        const std::vector<DdmaScratchOccupiedRange> kOccupied{
            { 0ULL, 2049ULL },
            { 2060ULL, 100000ULL - 2060ULL },
        };
        const auto kCandidates = planDdmaScratchCandidates(100000ULL, kOccupied, kNeed);
        bool found = false;
        for (const auto& candidate : kCandidates) {
            if (candidate.gapStartSector == 2049ULL) {
                found = true;
                suite.expect(candidate.startSector == 2056ULL,
                    L"ddma scratch: the candidate start is aligned up to the transfer granularity");
                suite.expect(!candidate.usable,
                    L"ddma scratch: alignment shrinking a gap below one transfer makes it unusable");
            }
        }
        suite.expect(found, L"ddma scratch: the alignment-shrunk gap is still reported");
    }

    // Overlapping or out-of-order occupied ranges must be merged first. Without merging, false gaps are calculated,
    // and a false gap implies suggesting the user overwrite sectors that actually belong to a partition.
    {
        const std::vector<DdmaScratchOccupiedRange> kOccupied{
            { 50000ULL, 10000ULL },
            { 2048ULL, 50000ULL },   // Overlaps with the previous entry, but in reverse order.
        };
        const auto kCandidates = planDdmaScratchCandidates(100000ULL, kOccupied, kNeed);
        for (const auto& candidate : kCandidates) {
            const std::uint64_t kEnd = candidate.gapStartSector + candidate.gapSectorCount;
            const bool kOverlapsOccupied =
                (candidate.gapStartSector < 60000ULL) && (kEnd > 2048ULL);
            suite.expect(!kOverlapsOccupied,
                L"ddma scratch: overlapping and unsorted ranges are merged before gaps are computed");
        }
    }

    // Degenerate inputs must safely return without calculating a candidate that implies the entire disk is available.
    suite.expect(planDdmaScratchCandidates(0ULL, {}, kNeed).empty(),
        L"ddma scratch: a zero-sector disk yields no candidates");
    suite.expect(planDdmaScratchCandidates(100000ULL, {}, 0U).empty(),
        L"ddma scratch: a zero-sector requirement yields no candidates");

    // A completely unpartitioned disk: the entire space is a gap, but the reserved header area still blocks the primary choice.
    {
        const auto kCandidates = planDdmaScratchCandidates(100000ULL, {}, kNeed);
        suite.expect(kCandidates.size() == 1U,
            L"ddma scratch: an unpartitioned disk is one single gap");
        suite.expect(kCandidates.front().risk == DdmaScratchRisk::kHeadReserved,
            L"ddma scratch: an unpartitioned disk's gap still starts inside the head reserve");
        suite.expect(!ddmaScratchRiskIsSelectable(kCandidates.front().risk),
            L"ddma scratch: an unpartitioned disk offers nothing auto-selectable");
    }
}

} // namespace

int runDdmaPlanTests() {
    ksword_tests::Suite suite(L"DDMA plan");
    testFlagLayout(suite);
    testScsiCdb(suite);
    testScratchPlan(suite);
    testLba28Encoding(suite);
    testLbaModeBoundary(suite);
    testLba48Encoding(suite);
    testSectorCountEncoding(suite);
    testPhysicalRange(suite);
    testChunkLength(suite);
    testGateOrder(suite);
    suite.report();
    return suite.failures();
}
