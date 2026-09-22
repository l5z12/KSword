// ============================================================
// KswordFsDecodeTests.cpp
// Purpose: Perform offline unit tests for file system structure decoding.
//
// These tests feed only byte arrays without opening volumes, loading drivers, or requiring admin privileges,
// enabling coverage of extremely hard-to-construct branches on real disks: out-of-bounds length fields, increments
// causing negative LCNs, INT64_MIN increments, and combinations of sparse segments with terminators. Runlists
// originate from disks and constitute untrusted input; these are precisely the areas that must be strictly enforced.
// ============================================================

#include "../../../apps/desktop/file_dock/NtfsRunListDecode.h"

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <iostream>
#include <vector>

namespace {

int failures = 0;

void expect(const bool condition, const char* const label)
{
    if (!condition) {
        ++failures;
        std::cerr << "FAIL: " << label << '\n';
    }
}

// Bytes function: Converts a readable hexadecimal sequence into a runlist byte buffer.
std::vector<std::byte> bytes(const std::initializer_list<int> values)
{
    std::vector<std::byte> buffer;
    buffer.reserve(values.size());
    for (const int kValue : values) {
        buffer.push_back(static_cast<std::byte>(static_cast<unsigned char>(kValue)));
    }
    return buffer;
}

// Parse function: Calls the target function using a left-closed, right-open interval, eliminating the need to repeatedly fetch start/end pointers for each test case.
bool parse(const std::vector<std::byte>& buffer, std::vector<ks::file::NtfsDataRun>& runsOut)
{
    return ks::file::parseNtfsRunList(buffer.data(), buffer.data() + buffer.size(), runsOut);
}

void testReadSignedLittleEndian()
{
    using ks::file::readSignedLittleEndian;

    const std::vector<std::byte> kPositive = bytes({0x7F});
    expect(readSignedLittleEndian(kPositive.data(), 1) == 127, "read: 1-byte positive");

    // If the most significant bit is 1, it must be sign-extended to a negative number; otherwise, a forward jump run would be calculated as a huge positive LCN.
    const std::vector<std::byte> kNegative = bytes({0x80});
    expect(readSignedLittleEndian(kNegative.data(), 1) == -128, "read: 1-byte sign extension");

    const std::vector<std::byte> kMinusOne = bytes({0xFF, 0xFF});
    expect(readSignedLittleEndian(kMinusOne.data(), 2) == -1, "read: 2-byte -1");

    const std::vector<std::byte> kMinShort = bytes({0x00, 0x80});
    expect(readSignedLittleEndian(kMinShort.data(), 2) == -32768, "read: 2-byte minimum");

    const std::vector<std::byte> kThreeByte = bytes({0x00, 0x00, 0xFF});
    expect(readSignedLittleEndian(kThreeByte.data(), 3) == -65536, "read: 3-byte sign extension");

    // When 8 bytes are full, there are no extendable high bits; interpret as two's complement directly.
    const std::vector<std::byte> kFullWidth = bytes({0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF});
    expect(readSignedLittleEndian(kFullWidth.data(), 8) == -1, "read: 8-byte no extension");

    const std::vector<std::byte> kIgnored = bytes({0x11, 0x22});
    expect(readSignedLittleEndian(kIgnored.data(), 0) == 0, "read: zero width rejected");
    expect(readSignedLittleEndian(kIgnored.data(), 9) == 0, "read: width over 8 rejected");
    expect(readSignedLittleEndian(nullptr, 4) == 0, "read: null pointer rejected");
}

void testRunListHappyPath()
{
    std::vector<ks::file::NtfsDataRun> runs;

    // 0x21 = length field (1 byte), offset field (2 bytes); followed by 0x00 as the terminator.
    expect(parse(bytes({0x21, 0x08, 0x34, 0x12, 0x00}), runs), "single: parsed");
    expect(runs.size() == 1, "single: one run");
    if (runs.size() == 1) {
        expect(runs[0].clusterCount == 8, "single: cluster count");
        expect(runs[0].startLcn == 0x1234, "single: start lcn");
        expect(!runs[0].isSparse, "single: not sparse");
    }

    // The offset of the second segment is an increment relative to the start of the previous segment, not an absolute LCN.
    expect(parse(bytes({0x21, 0x08, 0x34, 0x12, 0x21, 0x04, 0x10, 0x00, 0x00}), runs),
           "chained: parsed");
    expect(runs.size() == 2, "chained: two runs");
    if (runs.size() == 2) {
        expect(runs[0].startLcn == 0x1234, "chained: first lcn");
        expect(runs[1].startLcn == 0x1234 + 0x10, "chained: second lcn accumulates");
        expect(runs[1].clusterCount == 4, "chained: second cluster count");
    }

    // Negative increments indicate a jump toward the volume start, which is typical for fragmented files.
    expect(parse(bytes({0x21, 0x08, 0x34, 0x12, 0x21, 0x04, 0xF0, 0xFF, 0x00}), runs),
           "backward: parsed");
    expect(runs.size() == 2, "backward: two runs");
    if (runs.size() == 2) {
        expect(runs[1].startLcn == 0x1234 - 0x10, "backward: second lcn moves back");
    }

    // Parsing is considered complete even without a terminator if bytes are exactly exhausted.
    expect(parse(bytes({0x21, 0x08, 0x34, 0x12}), runs), "unterminated: parsed");
    expect(runs.size() == 1, "unterminated: one run");
}

void testRunListSparse()
{
    std::vector<ks::file::NtfsDataRun> runs;

    // 0x01 = length field is 1 byte, offset field is 0 bytes, indicating a sparse segment.
    expect(parse(bytes({0x01, 0x05, 0x00}), runs), "sparse: parsed");
    expect(runs.size() == 1, "sparse: one run");
    if (runs.size() == 1) {
        expect(runs[0].isSparse, "sparse: flagged");
        expect(runs[0].clusterCount == 5, "sparse: cluster count");
        expect(runs[0].startLcn == 0, "sparse: lcn stays zero");
    }

    // Sparse segments do not carry offsets, so the LCN base cannot be advanced: the subsequent segment is still calculated with 0 as the base, yielding 0x1234.
    // If the implementation incorrectly counts sparse segments in the accumulator, this will yield a different address, leading to a wrong cluster read.
    expect(parse(bytes({0x01, 0x05, 0x21, 0x08, 0x34, 0x12, 0x00}), runs),
           "sparse: followed by real run");
    expect(runs.size() == 2, "sparse: two runs");
    if (runs.size() == 2) {
        expect(runs[0].isSparse, "sparse: first is sparse");
        expect(!runs[1].isSparse, "sparse: second is real");
        expect(runs[1].startLcn == 0x1234, "sparse: does not advance lcn base");
    }
}

void testRunListRejects()
{
    std::vector<ks::file::NtfsDataRun> runs;

    expect(!ks::file::parseNtfsRunList(nullptr, nullptr, runs), "reject: null pointers");

    const std::vector<std::byte> kSingle = bytes({0x21});
    expect(!ks::file::parseNtfsRunList(kSingle.data(), kSingle.data(), runs), "reject: empty range");

    // If the first byte is a terminator: a non-resident attribute must have at least one run; an empty runlist is considered invalid.
    expect(!parse(bytes({0x00}), runs), "reject: empty run list");

    // The length field 0x20 is 0, making the cluster count indeterminable.
    expect(!parse(bytes({0x20, 0x34, 0x12, 0x00}), runs), "reject: zero length field");

    // The length/offset field declaration exceeds 8 bytes, surpassing the representation range for LCN and cluster count.
    expect(!parse(bytes({0x29, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00}), runs),
           "reject: length field over 8 bytes");
    expect(!parse(bytes({0x91, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00}), runs),
           "reject: offset field over 8 bytes");

    // Declared fields cross the buffer end. Out-of-bounds reads are the most common cause of crashes in such parsers.
    expect(!parse(bytes({0x21, 0x08, 0x34}), runs), "reject: fields cross the end");

    // A range with 0 clusters is meaningless and makes the caller's range traversal loop without advancing.
    expect(!parse(bytes({0x21, 0x00, 0x34, 0x12, 0x00}), runs), "reject: zero cluster count");

    // Negative increment pushes LCN below 0: negative cluster numbers do not exist on the volume.
    expect(!parse(bytes({0x21, 0x08, 0x34, 0x12, 0x21, 0x04, 0x00, 0xD0, 0x00}), runs),
           "reject: lcn driven negative");

    // Increment is INT64_MIN: negating it causes signed overflow, so it must be caught before negation.
    expect(!parse(bytes({0x81, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00}), runs),
           "reject: int64 min delta");

    // Positive integer overflow for int64.
    expect(!parse(bytes({0x81, 0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F,
                         0x81, 0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0x00}), runs),
           "reject: positive overflow");

    // Every failure path must clear the output; the caller must not treat partial results as valid ranges.
    expect(runs.empty(), "reject: output cleared on failure");
}

} // namespace

int main()
{
    testReadSignedLittleEndian();
    testRunListHappyPath();
    testRunListSparse();
    testRunListRejects();

    if (failures != 0) {
        std::cerr << "KswordFsDecodeTests: " << failures << " assertion(s) failed\n";
        return 1;
    }
    std::cout << "KswordFsDecodeTests: all assertions passed\n";
    return 0;
}
