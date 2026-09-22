#include "DumpPhysicalMemory.h"

// ============================================================
// DumpPhysicalMemory.cpp
// Notes:
// - Both layouts share the characteristic that "physical pages are compactly arranged in the file in some order," allowing them
//   to be reduced to a set of Runs (continuous physical pages ↔ continuous file bytes); binary search can then be used for lookup.
// - The key to the bitmap layout is that the Nth set bit corresponds to the Nth position in the file. Therefore, each
//   contiguous set interval in the bitmap must be converted into a Run, accumulating the file offset during the conversion.
// - All length/offset conversions perform overflow checks first: malformed dump page count fields can be arbitrary
//   values; multiplying directly by 0x1000 may wrap to a small value, bypassing subsequent boundary checks.
// ============================================================

#include <algorithm>
#include <cstring>

namespace ks::minidump
{
    namespace
    {
        // kPageSize: Base page size for x86/x64; both layouts use this page granularity.
        constexpr std::uint64_t kPageSize = 0x1000ull;

        // kMaxClassicRuns: The union region in the header of PHYSICAL_MEMORY_DESCRIPTOR is approximately 700
        // bytes and can hold at most 42 segments; exceeding this indicates the field is not a valid descriptor.
        constexpr std::uint32_t kMaxClassicRuns = 42;

        // kMaxBitmapPages: Maximum number of pages covered by the bitmap, corresponding to a 64 TB physical address space.
        // If it is any larger, the field must have been misinterpreted as other data.
        constexpr std::uint64_t kMaxBitmapPages = 1ull << 34;

        // kMaxRuns: Maximum number of segments allowed after merging to prevent pathological bitmaps from generating millions of fragmented segments.
        constexpr std::size_t kMaxRuns = 1u << 20;

        // kBmpSignature/kBmpValidFull/kBmpValidKernel: Signatures of _BMP_DUMP_HEADER.
        // 'SDMP' is a fixed signature; the second field distinguishes between full and kernel active dumps.
        constexpr std::uint32_t kBmpSignature = 0x504D4453u;   // 'SDMP'
        constexpr std::uint32_t kBmpValidDump = 0x504D5544u;   // 'DUMP'
        constexpr std::uint32_t kBmpValidFull = 0x4C4C5546u;   // 'FULL'

        // multiplyOverflows: Check if a*b overflows 64 bits.
        bool multiplyOverflows(const std::uint64_t a, const std::uint64_t b)
        {
            return a != 0 && b > (~0ull) / a;
        }

        // addOverflows purpose: check if a+b overflows 64 bits.
        bool addOverflows(const std::uint64_t a, const std::uint64_t b)
        {
            return b > (~0ull) - a;
        }
    }

    bool PhysicalMemoryMap::buildClassic(
        const DumpFileView& view,
        const std::uint64_t descriptorOffset,
        const std::uint64_t dataStartOffset)
    {
        runs_.clear();
        pageCount_ = 0;
        layout_ = PhysicalMemoryLayout::kNone;

        // PHYSICAL_MEMORY_DESCRIPTOR64 layout:
        // 0x00 NumberOfRuns / 0x08 NumberOfPages / 0x10 starts Run[] {BasePage, PageCount}.
        std::uint32_t numberOfRuns = 0;
        std::uint64_t numberOfPages = 0;
        if (!view.readStruct(descriptorOffset, &numberOfRuns) ||
            !view.readStruct(descriptorOffset + 8, &numberOfPages))
        {
            return false;
        }
        if (numberOfRuns == 0 || numberOfRuns > kMaxClassicRuns)
        {
            return false;
        }

        std::uint64_t cumulativePages = 0; // cumulativePages: Number of pages already processed, determining the file offset.
        for (std::uint32_t index = 0; index < numberOfRuns; ++index)
        {
            const std::uint64_t kRunOffset = descriptorOffset + 16 + static_cast<std::uint64_t>(index) * 16;
            std::uint64_t basePage = 0;
            std::uint64_t pageCount = 0;
            if (!view.readStruct(kRunOffset, &basePage) ||
                !view.readStruct(kRunOffset + 8, &pageCount))
            {
                break;
            }
            if (pageCount == 0)
            {
                continue;
            }
            // Both the segment's own address range and the file range must be computable without overflow.
            if (multiplyOverflows(basePage, kPageSize) ||
                multiplyOverflows(cumulativePages, kPageSize) ||
                multiplyOverflows(pageCount, kPageSize))
            {
                break;
            }
            const std::uint64_t kRunFileOffset = dataStartOffset + cumulativePages * kPageSize;
            if (addOverflows(dataStartOffset, cumulativePages * kPageSize) ||
                !view.contains(kRunFileOffset, pageCount * kPageSize))
            {
                // Data declared in the segment exceeds the file: truncating the dump is common; retain the successfully established portion.
                break;
            }

            Run run{};
            run.basePage = basePage;
            run.pageCount = pageCount;
            run.fileOffset = kRunFileOffset;
            runs_.push_back(run);

            cumulativePages += pageCount;
            pageCount_ += pageCount;
        }

        if (runs_.empty())
        {
            return false;
        }
        std::sort(
            runs_.begin(),
            runs_.end(),
            [](const Run& left, const Run& right) { return left.basePage < right.basePage; });
        layout_ = PhysicalMemoryLayout::kClassic;
        return true;
    }

    bool PhysicalMemoryMap::buildBitmap(
        const DumpFileView& view,
        const std::uint64_t headerOffset)
    {
        runs_.clear();
        pageCount_ = 0;
        layout_ = PhysicalMemoryLayout::kNone;

        // Fixed part of _BMP_DUMP_HEADER:
        // 0x00 Signature 'SDMP' / 0x04 ValidDump 'DUMP' or 'FULL'.
        std::uint32_t signature = 0;
        std::uint32_t validDump = 0;
        if (!view.readStruct(headerOffset, &signature) ||
            !view.readStruct(headerOffset + 4, &validDump))
        {
            return false;
        }
        if (signature != kBmpSignature ||
            (validDump != kBmpValidDump && validDump != kBmpValidFull))
        {
            return false;
        }

        /*
         * The starting offsets for the triplet (FirstPage / TotalPresentPages / Pages) are documented as either 0x10 or
         * 0x20, but no authoritative definition exists for this machine. Rather than guessing, we let the data prove itself:
         * the bit count in the bitmap must exactly equal TotalPresentPages, and all fields must pass range and file-boundary
         * checks. This equality is virtually impossible to be accidentally satisfied by misaligned reads, uniquely selecting
         * the correct layout; if neither candidate satisfies the condition, the format is deemed unparseable.
         */
        constexpr std::uint64_t kTripletOffsetCandidates[] = { 0x10ull, 0x20ull };
        std::uint64_t firstPageOffset = 0;
        std::uint64_t totalPresentPages = 0;
        std::uint64_t totalPages = 0;
        std::uint64_t bitmapOffset = 0;
        std::uint64_t bitmapBytes = 0;
        const unsigned char* bitmap = nullptr;

        for (const std::uint64_t kTripletOffset : kTripletOffsetCandidates)
        {
            std::uint64_t candidateFirstPage = 0;
            std::uint64_t candidatePresent = 0;
            std::uint64_t candidatePages = 0;
            if (!view.readStruct(headerOffset + kTripletOffset, &candidateFirstPage) ||
                !view.readStruct(headerOffset + kTripletOffset + 8, &candidatePresent) ||
                !view.readStruct(headerOffset + kTripletOffset + 16, &candidatePages))
            {
                continue;
            }
            if (candidatePages == 0 || candidatePages > kMaxBitmapPages ||
                candidatePresent == 0 || candidatePresent > candidatePages)
            {
                continue;
            }

            const std::uint64_t kCandidateBitmapOffset = headerOffset + kTripletOffset + 24;
            const std::uint64_t kCandidateBitmapBytes = (candidatePages + 7) / 8;
            if (!view.contains(kCandidateBitmapOffset, kCandidateBitmapBytes))
            {
                continue;
            }
            // Page data must follow the bitmap, and the first page offset must fall within the file.
            if (candidateFirstPage < kCandidateBitmapOffset + kCandidateBitmapBytes ||
                candidateFirstPage >= view.size)
            {
                continue;
            }

            const unsigned char* const kCandidateBitmap =
                view.at(kCandidateBitmapOffset, kCandidateBitmapBytes);
            if (kCandidateBitmap == nullptr)
            {
                continue;
            }

            // Definitive validation: verify that the bit count equals TotalPresentPages.
            std::uint64_t setBits = 0;
            for (std::uint64_t byteIndex = 0; byteIndex < kCandidateBitmapBytes; ++byteIndex)
            {
                unsigned char byteValue = kCandidateBitmap[byteIndex];
                while (byteValue != 0)
                {
                    setBits += (byteValue & 1u);
                    byteValue = static_cast<unsigned char>(byteValue >> 1);
                }
            }
            if (setBits != candidatePresent)
            {
                continue;
            }

            firstPageOffset = candidateFirstPage;
            totalPresentPages = candidatePresent;
            totalPages = candidatePages;
            bitmapOffset = kCandidateBitmapOffset;
            bitmapBytes = kCandidateBitmapBytes;
            bitmap = kCandidateBitmap;
            break;
        }

        if (bitmap == nullptr)
        {
            return false;
        }
        (void)totalPresentPages;
        (void)bitmapBytes;

        // Convert each contiguous set-bit interval in the bitmap into a Run. Since page data in the file is ordered
        // by page number, the cumulative count of set bits directly corresponds to the page's index in the file.
        std::uint64_t presentIndex = 0; // presentIndex: Number of set pages skipped.
        std::uint64_t pageIndex = 0;
        while (pageIndex < totalPages && runs_.size() < kMaxRuns)
        {
            const std::uint64_t kByteIndex = pageIndex >> 3;
            const unsigned char kBitMask = static_cast<unsigned char>(1u << (pageIndex & 7));
            if ((bitmap[kByteIndex] & kBitMask) == 0)
            {
                ++pageIndex;
                continue;
            }

            const std::uint64_t kRunStartPage = pageIndex;
            const std::uint64_t kRunStartPresent = presentIndex;
            while (pageIndex < totalPages)
            {
                const std::uint64_t kCurrentByte = pageIndex >> 3;
                const unsigned char kCurrentMask = static_cast<unsigned char>(1u << (pageIndex & 7));
                if ((bitmap[kCurrentByte] & kCurrentMask) == 0)
                {
                    break;
                }
                ++pageIndex;
                ++presentIndex;
            }

            const std::uint64_t kRunPages = pageIndex - kRunStartPage;
            if (multiplyOverflows(kRunStartPresent, kPageSize) ||
                multiplyOverflows(kRunPages, kPageSize) ||
                addOverflows(firstPageOffset, kRunStartPresent * kPageSize))
            {
                break;
            }
            const std::uint64_t kRunFileOffset = firstPageOffset + kRunStartPresent * kPageSize;
            if (!view.contains(kRunFileOffset, kRunPages * kPageSize))
            {
                // Truncate the sample: retain established segments so subsequent queries naturally return empty rather than reading invalid pages.
                break;
            }

            Run run{};
            run.basePage = kRunStartPage;
            run.pageCount = kRunPages;
            run.fileOffset = kRunFileOffset;
            runs_.push_back(run);
            pageCount_ += kRunPages;
        }

        if (runs_.empty())
        {
            return false;
        }
        layout_ = PhysicalMemoryLayout::kBitmap;
        return true;
    }

    bool PhysicalMemoryMap::translate(
        const std::uint64_t physicalAddress,
        std::uint64_t* const fileOffsetOut) const
    {
        if (fileOffsetOut == nullptr || runs_.empty())
        {
            return false;
        }

        const std::uint64_t kPage = physicalAddress / kPageSize;
        const std::uint64_t kPageOffset = physicalAddress % kPageSize;

        // Binary search to find the last segment where basePage <= page.
        std::size_t low = 0;
        std::size_t high = runs_.size();
        while (low < high)
        {
            const std::size_t kMiddle = low + (high - low) / 2;
            if (runs_[kMiddle].basePage <= kPage)
            {
                low = kMiddle + 1;
            }
            else
            {
                high = kMiddle;
            }
        }
        if (low == 0)
        {
            return false;
        }

        const Run& run = runs_[low - 1];
        if (kPage - run.basePage >= run.pageCount)
        {
            return false;
        }
        const std::uint64_t kPageIndexInRun = kPage - run.basePage;
        if (multiplyOverflows(kPageIndexInRun, kPageSize))
        {
            return false;
        }
        *fileOffsetOut = run.fileOffset + kPageIndexInRun * kPageSize + kPageOffset;
        return true;
    }

    bool PhysicalMemoryMap::readPhysical(
        const DumpFileView& view,
        const std::uint64_t physicalAddress,
        const std::uint64_t bytes,
        void* const buffer) const
    {
        if (buffer == nullptr || bytes == 0)
        {
            return false;
        }
        if (addOverflows(physicalAddress, bytes))
        {
            return false;
        }

        unsigned char* const kOutput = static_cast<unsigned char*>(buffer);
        std::uint64_t copied = 0;
        while (copied < bytes)
        {
            const std::uint64_t kCurrentAddress = physicalAddress + copied;
            std::uint64_t fileOffset = 0;
            if (!translate(kCurrentAddress, &fileOffset))
            {
                return false;
            }
            // Copy at most to the end of the current page; crossing pages requires re-translation, as adjacent
            // physical pages are not necessarily adjacent in the file (especially under bitmap layout).
            const std::uint64_t kPageRemaining = kPageSize - (kCurrentAddress % kPageSize);
            const std::uint64_t kChunk = std::min<std::uint64_t>(kPageRemaining, bytes - copied);
            const unsigned char* const kSource = view.at(fileOffset, kChunk);
            if (kSource == nullptr)
            {
                return false;
            }
            std::memcpy(kOutput + copied, kSource, static_cast<std::size_t>(kChunk));
            copied += kChunk;
        }
        return true;
    }

    QString PhysicalMemoryMap::layoutText() const
    {
        switch (layout_)
        {
        case PhysicalMemoryLayout::kClassic:
            return QStringLiteral("经典物理内存布局（按内存段顺序排列）");
        case PhysicalMemoryLayout::kBitmap:
            return QStringLiteral("位图物理内存布局（活动内存转储）");
        case PhysicalMemoryLayout::kNone:
        default:
            return QStringLiteral("未建立物理内存映射");
        }
    }

    void PhysicalMemoryMap::appendRegions(DumpParseResult& result) const
    {
        const QString kSourceText = (layout_ == PhysicalMemoryLayout::kBitmap)
            ? QStringLiteral("物理内存段（位图）")
            : QStringLiteral("物理内存段");
        for (const Run& run : runs_)
        {
            MemoryRegionEntry entry{};
            entry.base = run.basePage * kPageSize;
            entry.size = run.pageCount * kPageSize;
            entry.source = kSourceText;
            ++result.memoryRegionTotal;
            ++result.memoryRegionShown;
            result.memoryRegions.push_back(std::move(entry));
        }
    }
}
