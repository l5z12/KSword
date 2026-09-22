#pragma once

// ============================================================
// DumpMemoryReader.h
// Purpose:
// - Organize the "memory blocks actually captured" from the dump file into an ordered
//   mapping of virtual address → file offset, providing read-only access by virtual address.
// - User-mode MDMP sources are MemoryListStream / Memory64ListStream;
//   kernel minidump sources are TRIAGE data blocks and call stack blocks.
// - Enables validation such as 'is there a call instruction before the
//   return address', significantly reducing false positives in stack scanning.
// - Full and kernel memory dumps contain no memory streams organized by virtual address; page data is arranged only by physical
//   address. Therefore, this class supports attaching a PageTableWalker backend: when a block index misses, translation is performed
//   via the page table. This ensures that stack scanning capabilities like call validation use the same code path for both dump types.
// Call method:
// - Parser adds ranges via addRange() while parsing the memory stream, then calls finalize() after all ranges are added.
// - Full/kernel dumps additionally call attachPageTable() to attach the translator.
// - Subsequently, use contains()/read() to fetch bytes by the target machine's virtual address.
// ============================================================

#include "MinidumpFormat.h"

namespace ks::minidump
{
    class PageTableWalker;

    // DumpMemoryReader purpose: index of virtual addresses for memory captured within the dump.
    // After finalize(), the internal state is read-only and safe for concurrent access.
    class DumpMemoryReader
    {
    public:
        // addRange purpose: register a mapping between a virtual address and a file offset.
        // Accepts virtualAddress (target machine address), fileOffset
        // (file offset), bytes (length), and source (capture source);
        // Segments with length 0 or out of bounds are ignored.
        void addRange(
            std::uint64_t virtualAddress,
            std::uint64_t fileOffset,
            std::uint64_t bytes,
            const QString& source = QString());

        // finalize: Removes out-of-bounds segments in the file and sorts them by virtual address for querying.
        // Do not perform overlapping merges—memory blocks in real dumps do not overlap; find() already handles the rare overlapping cases via backtracking.
        // Accepts a read-only file view (used to exclude invalid segments outside the file); returns void.
        void finalize(const DumpFileView& view);

        // read: Reads bytes from the target machine's virtual address into the caller's buffer.
        // Takes a view file view, virtualAddress start address, bytes length, and an output buffer;
        // Require the entire block to be within a single captured chunk; return false for cross-chunk requests.
        bool read(
            const DumpFileView& view,
            std::uint64_t virtualAddress,
            std::uint64_t bytes,
            void* buffer) const;

        // contains: Check if the bytes at a given virtual address are present in the dump.
        bool contains(std::uint64_t virtualAddress, std::uint64_t bytes) const;

        // attachPageTable: Attach the page table backend for fallback translation when block index misses.
        // Parameter: walker pointer. The caller must ensure the walker's lifetime exceeds the object's usage period.
        // Passing nullptr detaches the walker.
        void attachPageTable(const PageTableWalker* walker) { pageTable_ = walker; }

        // hasPageTable: Whether the page table backend is attached.
        bool hasPageTable() const { return pageTable_ != nullptr; }

        // rangeCount: Returns the number of registered memory blocks.
        std::size_t rangeCount() const { return ranges_.size(); }

        // appendCapturedRanges purpose: Export block indices that have completed file boundary validation.
        // Export only data registered via real addRange(), not temporary results translated by the page-table backend.
        // Retain the source registered for each segment so the viewer can distinguish evidence like thread stacks and TRIAGE blocks.
        void appendCapturedRanges(std::vector<DumpMemoryRange>* rangesOut) const;

    private:
        // Range: a captured memory segment.
        struct Range
        {
            std::uint64_t virtualAddress = 0; // virtualAddress: Starting address of the block in the target machine.
            std::uint64_t fileOffset = 0;     // fileOffset: Offset of the block within the dump file.
            std::uint64_t bytes = 0;          // bytes: Block length.
            QString source;                   // source: The source of the captured memory.
        };

        // find purpose: locate the block covering [virtualAddress, +bytes); returns nullptr if not found.
        const Range* find(std::uint64_t virtualAddress, std::uint64_t bytes) const;

        std::vector<Range> ranges_; // m_ranges: Memory blocks sorted in ascending order by virtualAddress.
        bool finalized_ = false;    // m_finalized: Whether the data is sorted; queries are disabled if not sorted.
        const PageTableWalker* pageTable_ = nullptr; // m_pageTable: Optional page table backend; does not own the object.
    };
}
