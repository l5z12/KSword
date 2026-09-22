// ============================================================
// DumpMemoryReader.cpp
// Purpose:
// - Implements the virtual address memory index declared in DumpMemoryReader.h;
// - After finalizing and sorting, use upper_bound to locate the covering block; all reads
//   require the entire segment to reside within a single block (adjacent virtual addresses in the
//   dump may not be adjacent in the file, and stitching across blocks would read unrelated bytes).
// - The segment's file range is validated by DumpFileView during the finalize phase; out-of-bounds
//   segments in malformed dumps are discarded immediately and do not persist to the query phase.
// ============================================================

#include "DumpMemoryReader.h"

#include "DumpPageTable.h"

#include <algorithm>
#include <cstring>

namespace ks::minidump
{
    namespace
    {
        // kMaxRanges: Upper limit for memory block indices to prevent malformed dumps with excessive ranges from crashing the parser.
        constexpr std::size_t kMaxRanges = 200000;
    }

    void DumpMemoryReader::addRange(
        const std::uint64_t virtualAddress,
        const std::uint64_t fileOffset,
        const std::uint64_t bytes,
        const QString& source)
    {
        if (bytes == 0 || virtualAddress == 0 || ranges_.size() >= kMaxRanges)
        {
            return;
        }
        // Discard all segments with virtual address addition overflow: such segments cannot participate in interval comparisons.
        if (virtualAddress + bytes < virtualAddress)
        {
            return;
        }
        Range range{};
        range.virtualAddress = virtualAddress;
        range.fileOffset = fileOffset;
        range.bytes = bytes;
        range.source = source;
        ranges_.push_back(range);
    }

    void DumpMemoryReader::finalize(const DumpFileView& view)
    {
        // First remove out-of-bounds segments within the file to avoid redundant validation during queries.
        ranges_.erase(
            std::remove_if(
                ranges_.begin(),
                ranges_.end(),
                [&view](const Range& range)
                {
                    return !view.contains(range.fileOffset, range.bytes);
                }),
            ranges_.end());
        std::sort(
            ranges_.begin(),
            ranges_.end(),
            [](const Range& left, const Range& right)
            {
                if (left.virtualAddress != right.virtualAddress)
                {
                    return left.virtualAddress < right.virtualAddress;
                }
                // Blocks with the same start point are sorted first so that a find hit can cover longer requests.
                return left.bytes > right.bytes;
            });
        finalized_ = true;
    }

    const DumpMemoryReader::Range* DumpMemoryReader::find(
        const std::uint64_t virtualAddress,
        const std::uint64_t bytes) const
    {
        if (!finalized_ || ranges_.empty() || bytes == 0)
        {
            return nullptr;
        }
        if (virtualAddress + bytes < virtualAddress)
        {
            return nullptr;
        }
        // position: The first block whose start is greater than the target address; the candidate can only be the one immediately preceding it.
        const auto kPosition = std::upper_bound(
            ranges_.begin(),
            ranges_.end(),
            virtualAddress,
            [](const std::uint64_t value, const Range& range)
            {
                return value < range.virtualAddress;
            });
        // Block start points before 'position' are all <= target address; backtracking from the nearest item, sorting places
        // longer blocks with the same start point first, so a hit is typically found within one or two steps in real dumps.
        // kProbeDepth: Fallback for numerous overlapping blocks in malformed dumps to avoid degrading into linear scanning.
        constexpr int kProbeDepth = 8;
        auto candidate = kPosition;
        for (int step = 0; step < kProbeDepth && candidate != ranges_.begin(); ++step)
        {
            --candidate;
            const std::uint64_t kOffsetInRange = virtualAddress - candidate->virtualAddress;
            if (kOffsetInRange < candidate->bytes &&
                candidate->bytes - kOffsetInRange >= bytes)
            {
                return &(*candidate);
            }
        }
        return nullptr;
    }

    bool DumpMemoryReader::contains(
        const std::uint64_t virtualAddress,
        const std::uint64_t bytes) const
    {
        if (find(virtualAddress, bytes) != nullptr)
        {
            return true;
        }
        // Query the page table on block index miss; this path handles all memory in full/kernel dumps.
        if (pageTable_ != nullptr && bytes != 0 && bytes - 1 <= (~0ull) - virtualAddress)
        {
            std::uint64_t physicalAddress = 0;
            // Verifying reachability of the first and last pages is sufficient to determine 'this memory is not in the dump'.
            // Page-by-page verification would degrade every candidate check during stack scanning into a full translation.
            if (!pageTable_->translate(virtualAddress, &physicalAddress))
            {
                return false;
            }
            return pageTable_->translate(virtualAddress + bytes - 1, &physicalAddress);
        }
        return false;
    }

    bool DumpMemoryReader::read(
        const DumpFileView& view,
        const std::uint64_t virtualAddress,
        const std::uint64_t bytes,
        void* const buffer) const
    {
        if (buffer == nullptr)
        {
            return false;
        }
        const Range* const kRange = find(virtualAddress, bytes);
        if (kRange == nullptr)
        {
            // The page table backend provides its own real file view and does not use the view passed here. Under a full dump path, the
            // caller may pass a temporary view constructed from a stack buffer; using it to look up file offsets would read incorrect bytes.
            if (pageTable_ != nullptr)
            {
                return pageTable_->readVirtual(virtualAddress, bytes, buffer);
            }
            return false;
        }
        const std::uint64_t kFileOffset =
            kRange->fileOffset + (virtualAddress - kRange->virtualAddress);
        const unsigned char* const kSource = view.at(kFileOffset, bytes);
        if (kSource == nullptr)
        {
            return false;
        }
        std::memcpy(buffer, kSource, static_cast<std::size_t>(bytes));
        return true;
    }

    void DumpMemoryReader::appendCapturedRanges(
        std::vector<DumpMemoryRange>* const rangesOut) const
    {
        if (!finalized_ || rangesOut == nullptr)
        {
            return;
        }
        rangesOut->reserve(rangesOut->size() + ranges_.size());
        for (const Range& range : ranges_)
        {
            DumpMemoryRange entry{};
            entry.virtualAddress = range.virtualAddress;
            entry.fileOffset = range.fileOffset;
            entry.bytes = range.bytes;
            entry.source = range.source;
            rangesOut->push_back(std::move(entry));
        }
    }

}
