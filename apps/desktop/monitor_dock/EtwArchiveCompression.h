#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace ksword_etw_archive_compression
{
    enum class BlockMethod : std::uint32_t
    {
        kStored = 0,
        kZstandard = 1
    };

    struct EncodedBlock
    {
        BlockMethod method = BlockMethod::kStored;
        std::vector<char> payload;
    };

    // ETW archives compressed in ~1 MiB cross-record blocks. Zstandard level 3 provides a stable balance between
    // real-time write throughput and compression ratio for repetitive text/JSON; incompressible data is stored as-is.
    bool compressBlock(std::span<const char> source, EncodedBlock* encodedOut);

    // expectedSize must come from an archive block header that has undergone upper-layer boundary validation to prevent unbounded allocation triggered by corrupted files.
    bool decompressBlock(
        BlockMethod method,
        std::span<const char> encoded,
        std::size_t expectedSize,
        std::vector<char>* decodedOut);
}
