#include "DumpPageTable.h"

// ============================================================
// DumpPageTable.cpp
// Notes:
// - x64 4-level page table address breakdown (9-bit index per level + 12-bit page offset):
//   [47:39] PML4 index / [38:30] PDPT index / [29:21] PD
//   index / [20:12] PT index / [11:0] offset within the page;
// - If bit0 (P) of any level's entry is 0, it indicates unmapped; if bit7 (PS) of a PDPTE/PDE
//   is 1, it indicates direct mapping at this level (1GB/2MB large pages), and traversal stops.
// - The physical frame number in the table entry occupies bits [51:12]; the upper bits are NX and other attribute flags, which must be masked before using as an address.
// ============================================================

#include <algorithm>
#include <vector>

namespace ks::minidump
{
    namespace
    {
        // kPageSize: Base page size.
        constexpr std::uint64_t kPageSize = 0x1000ull;

        // kPhysicalFrameMask: Bits [51:12] in the page table entry representing the physical frame number.
        constexpr std::uint64_t kPhysicalFrameMask = 0x000FFFFFFFFFF000ull;

        // kPresentBit / kLargePageBit: P bit and PS bit of the entry.
        constexpr std::uint64_t kPresentBit = 1ull << 0;
        constexpr std::uint64_t kLargePageBit = 1ull << 7;

        // kMaxUnicodeBytes: Upper limit on bytes read for a single UNICODE_STRING.
        // Driver paths will not exceed this magnitude; larger values likely indicate misread structures.
        constexpr std::uint16_t kMaxUnicodeBytes = 1024;

        // canonicalAddressInvalid: Checks if the address violates the x64 canonical form specification.
        // In 4-level paging, bits [63:48] must be the sign extension of bit47; otherwise, the hardware rejects it.
        bool canonicalAddressInvalid(const std::uint64_t address)
        {
            const std::uint64_t kHigh = address >> 47;
            return kHigh != 0 && kHigh != 0x1FFFFull;
        }
    }

    PageTableWalker::PageTableWalker(
        const DumpFileView& view,
        const PhysicalMemoryMap& physical,
        const std::uint64_t directoryTableBase)
        : view_(view)
        , physical_(physical)
    {
        // The lower 12 bits of CR3 contain attributes like PCID; only the physical frame portion is needed.
        directoryTableBase_ = directoryTableBase & kPhysicalFrameMask;
        // A page directory base address of 0 indicates that this field in the header was not populated (which can happen in some
        // trimmed samples). In this case, any translation is meaningless, so mark it as unusable rather than returning an error result.
        usable_ = physical.valid() && directoryTableBase_ != 0;
    }

    bool PageTableWalker::translate(
        const std::uint64_t virtualAddress,
        std::uint64_t* const physicalOut,
        bool* const largePageOut) const
    {
        if (largePageOut != nullptr)
        {
            *largePageOut = false;
        }
        if (!usable_ || physicalOut == nullptr)
        {
            return false;
        }
        if (canonicalAddressInvalid(virtualAddress))
        {
            return false;
        }

        // Progressive indexing: take 9 bits per level; each table entry is 8 bytes.
        const std::uint64_t kIndices[4] = {
            (virtualAddress >> 39) & 0x1FFull, // PML4
            (virtualAddress >> 30) & 0x1FFull, // PDPT
            (virtualAddress >> 21) & 0x1FFull, // PD
            (virtualAddress >> 12) & 0x1FFull, // PT
        };

        std::uint64_t tableBase = directoryTableBase_;
        for (int level = 0; level < 4; ++level)
        {
            const std::uint64_t kEntryAddress = tableBase + kIndices[level] * 8ull;
            std::uint64_t entry = 0;
            if (!physical_.readPhysical(view_, kEntryAddress, sizeof(entry), &entry))
            {
                // The page table page itself is not paged out: the kernel dump skips many physical pages, resulting in missing information.
                return false;
            }
            if ((entry & kPresentBit) == 0)
            {
                return false;
            }

            const std::uint64_t kFrame = entry & kPhysicalFrameMask;
            if (level == 1 && (entry & kLargePageBit) != 0)
            {
                // 1GB large page: Frame number is 1GB-aligned; page offset uses the lower 30 bits.
                if (largePageOut != nullptr)
                {
                    *largePageOut = true;
                }
                *physicalOut = (kFrame & ~0x3FFFFFFFull) | (virtualAddress & 0x3FFFFFFFull);
                return true;
            }
            if (level == 2 && (entry & kLargePageBit) != 0)
            {
                // 2MB large pages: frame numbers are 2MB-aligned, and the page offset uses the lower 21 bits.
                if (largePageOut != nullptr)
                {
                    *largePageOut = true;
                }
                *physicalOut = (kFrame & ~0x1FFFFFull) | (virtualAddress & 0x1FFFFFull);
                return true;
            }
            if (level == 3)
            {
                *physicalOut = kFrame | (virtualAddress & 0xFFFull);
                return true;
            }
            tableBase = kFrame;
        }
        return false;
    }

    bool PageTableWalker::readVirtual(
        const std::uint64_t virtualAddress,
        const std::uint64_t bytes,
        void* const buffer) const
    {
        if (!usable_ || buffer == nullptr || bytes == 0)
        {
            return false;
        }
        if (bytes > (~0ull) - virtualAddress)
        {
            return false;
        }

        unsigned char* const kOutput = static_cast<unsigned char*>(buffer);
        std::uint64_t copied = 0;
        while (copied < bytes)
        {
            const std::uint64_t kCurrentAddress = virtualAddress + copied;
            std::uint64_t physicalAddress = 0;
            if (!translate(kCurrentAddress, &physicalAddress))
            {
                return false;
            }
            // Read at most to the end of the current base page. Under large page mappings, adjacent virtual pages have contiguous physical
            // addresses; splitting by base pages is also correct, incurring extra translations but eliminating a conditional branch logically.
            const std::uint64_t kPageRemaining = kPageSize - (kCurrentAddress % kPageSize);
            const std::uint64_t kChunk = std::min<std::uint64_t>(kPageRemaining, bytes - copied);
            if (!physical_.readPhysical(view_, physicalAddress, kChunk, kOutput + copied))
            {
                return false;
            }
            copied += kChunk;
        }
        return true;
    }

    bool PageTableWalker::readPointer(
        const std::uint64_t virtualAddress,
        std::uint64_t* const valueOut) const
    {
        if (valueOut == nullptr)
        {
            return false;
        }
        std::uint64_t value = 0;
        if (!readVirtual(virtualAddress, sizeof(value), &value))
        {
            return false;
        }
        *valueOut = value;
        return true;
    }

    QString PageTableWalker::readUnicodeString(
        const std::uint64_t bufferAddress,
        const std::uint16_t lengthBytes) const
    {
        if (bufferAddress == 0 || lengthBytes == 0 || lengthBytes > kMaxUnicodeBytes)
        {
            return QString();
        }
        if ((lengthBytes % sizeof(char16_t)) != 0)
        {
            // Length is not a multiple of wide character size: likely not reading a real UNICODE_STRING.
            return QString();
        }

        std::vector<char16_t> characters(lengthBytes / sizeof(char16_t), u'\0');
        if (!readVirtual(bufferAddress, lengthBytes, characters.data()))
        {
            return QString();
        }
        return QString::fromUtf16(
            reinterpret_cast<const char16_t*>(characters.data()),
            static_cast<qsizetype>(characters.size()));
    }
}
