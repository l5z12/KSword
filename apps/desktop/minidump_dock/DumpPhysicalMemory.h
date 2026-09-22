#pragma once

// ============================================================
// DumpPhysicalMemory.h
// Purpose:
// - Organize physical pages from full/kernel memory dumps into a physical address → file offset mapping;
// - Covers two distinct disk layout formats:
//   Classic layout (DumpType 1/2/7): Page data follows the header, arranged
//   consecutively in the order of PHYSICAL_MEMORY_DESCRIPTOR runs.
//   Bitmap layout (DumpType 5/6, active memory dump since Win8): File offset 0x2000 is _BMP_DUMP_HEADER;
//   each bit in the page bitmap indicates whether a page was dumped, with page data arranged compactly.
// - Small dumps (DumpType 4) do not go through here; they have no physical memory regions, only TRIAGE blocks.
// Call method:
// - After KernelDumpParser determines DumpType, it calls build(), then uses readPhysical()
//   to fetch bytes; page table traversal (DumpPageTable) is built on top of this module.
// ============================================================

#include "MinidumpFormat.h"

namespace ks::minidump
{
    // PhysicalMemoryLayout: layout of dumped physical pages on disk.
    enum class PhysicalMemoryLayout
    {
        kNone,    // None: Not established or not applicable (e.g., mini-dump).
        kClassic, // Classic: Arranged consecutively by physical memory segment order.
        kBitmap,  // Bitmap: Page bitmap + compact page data.
    };

    // PhysicalMemoryMap purpose: Physical page index for full/kernel dumps.
    // Read-only internally after build; safe for concurrent queries.
    class PhysicalMemoryMap
    {
    public:
        // buildClassic: Builds an index according to the classic layout.
        // Accepts a file view, descriptorOffset as the offset of PHYSICAL_MEMORY_DESCRIPTOR
        // within the dump header (0x88 for DUMP_HEADER64), and dataStartOffset as the file
        // offset of the first page data (fixed at 0x2000 for kernel dumps).
        // Returns whether at least one valid segment was created.
        bool buildClassic(
            const DumpFileView& view,
            std::uint64_t descriptorOffset,
            std::uint64_t dataStartOffset);

        // buildBitmap: Builds an index based on bitmap layout.
        // Accepts view and headerOffset (file offset of _BMP_DUMP_HEADER, fixed at 0x2000);
        // Returns whether the signature and bitmap are trustworthy.
        // Note: There are two conflicting descriptions in public documentation regarding the offset of the triplet
        // (FirstPage/TotalPresentPages/Pages) within the header. The implementation does not bet on either; instead, it self-validates
        // the candidate layout using the equality 'bit count == TotalPresentPages'. If neither holds, the layout is deemed unresolvable.
        bool buildBitmap(const DumpFileView& view, std::uint64_t headerOffset);

        // translate purpose: Convert a physical address to a file offset.
        // Pass physicalAddress and output fileOffsetOut.
        // Returns false if the page has not been written to disk (bitmap bit not set or beyond all segments).
        bool translate(std::uint64_t physicalAddress, std::uint64_t* fileOffsetOut) const;

        // readPhysical: Reads bytes by physical address with automatic page-spanning concatenation.
        // Accepts view, physicalAddress (starting physical address), bytes (length), and an output buffer;
        // Return false if any page is missing; do not perform partial fills—corrupted data is more dangerous than no data.
        bool readPhysical(
            const DumpFileView& view,
            std::uint64_t physicalAddress,
            std::uint64_t bytes,
            void* buffer) const;

        // layout / valid / pageCount / describedPageCount: status queries.
        PhysicalMemoryLayout layout() const { return layout_; }
        bool valid() const { return layout_ != PhysicalMemoryLayout::kNone; }
        std::uint64_t pageCount() const { return pageCount_; }

        // layoutText: Returns a Chinese description of the layout for the overview page and diagnostic information.
        QString layoutText() const;

        // regionCount: Returns the number of physical regions in the index (bitmap layout counts merged contiguous set-bit segments).
        std::size_t regionCount() const { return runs_.size(); }

        // appendRegions: Appends physical segments to the result's memory region table for UI display.
        // Accepts result (modified in-place); writes only the base, size, and source fields.
        void appendRegions(DumpParseResult& result) const;

    private:
        // Run: a contiguous block of physical pages, also stored contiguously in the file.
        struct Run
        {
            std::uint64_t basePage = 0;   // basePage: Starting physical page number.
            std::uint64_t pageCount = 0;  // pageCount: Number of pages.
            std::uint64_t fileOffset = 0; // fileOffset: Offset of the first page in the file.
        };

        std::vector<Run> runs_;   // m_runs: Physical segments sorted by basePage in ascending order.
        std::uint64_t pageCount_ = 0; // m_pageCount: Total number of pages covered by the index.
        PhysicalMemoryLayout layout_ = PhysicalMemoryLayout::kNone; // m_layout: Actual layout.
    };
}
