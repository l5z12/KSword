#pragma once

// ============================================================
// NtfsRunListDecode.h
// Purpose:
// 1) Decode the NTFS non-resident attribute runlist to obtain the LCN range or sparse marker for each segment;
// 2) Isolate this pure byte parsing from ManualFileSystemParser to enable offline testing.
//
// Why is this a separate file? The runlist comes from the disk and is untrusted input: length fields, signed LCN increments, sparse
// segments, and terminators can all be crafted to cause out-of-bounds access or overflow. The original implementation was hidden in
// an anonymous namespace within ManualFileSystemParser.cpp, triggerable only indirectly via 'real volumes + real file deletions',
// making boundary branches nearly impossible to cover. After extraction, it can be fed directly with a constructed byte array.
//
// This file depends only on the standard library, without including Qt or Windows headers, so test projects can compile it directly.
// ============================================================

#include <cstdint>
#include <cstddef>
#include <vector>

namespace ks::file
{
    // NtfsDataRun role: A segment within the runlist.
    struct NtfsDataRun
    {
        std::uint64_t startLcn = 0;            // Start LCN of the data segment; 0 for sparse segments.
        std::uint64_t clusterCount = 0;        // Number of clusters occupied by the current data segment.
        bool isSparse = false;                 // Whether this is a sparse segment; true means the segment is logically filled with 0.
    };

    // readSignedLittleEndian: Reads a signed little-endian integer of 1 to 8 bytes.
    // Input: start pointer and byte count; returns 0 if the pointer is null or the byte count is not in the range 1–8.
    // Processing: assemble in little-endian; if the sign bit of the most significant byte is 1, perform manual
    //       sign extension. LCN increments in the runlist are relative values, becoming negative when jumping forward.
    std::int64_t readSignedLittleEndian(const std::byte* ptr, std::uint8_t byteCount);

    // parseNtfsRunList: Parse the runlist of a non-resident attribute.
    // Input: Start and end pointers of the runlist (inclusive start, exclusive end).
    // Output: dataRunsOut receives each segment sequentially; cleared on failure.
    // Returns: true if at least one segment is parsed and no out-of-bounds access occurs. All of the following cases are treated as failures with output cleared:
    //       Invalid pointer or empty range; length field is 0 or exceeds 8 bytes; offset field exceeds 8 bytes.
    //       Field crosses runListEnd; cluster count is 0; LCN increment causes overflow or makes LCN negative.
    //       The first byte being a terminator (empty runlist) also returns false—a non-resident attribute must have at least one run.
    bool parseNtfsRunList(
        const std::byte* runListPtr,
        const std::byte* runListEnd,
        std::vector<NtfsDataRun>& dataRunsOut);
}
