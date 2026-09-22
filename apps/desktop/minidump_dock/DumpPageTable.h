#pragma once

// ============================================================
// DumpPageTable.h
// Purpose:
// - Traverse the x64 four-level page table using the DirectoryTableBase from the dump header (CR3 at the moment of crash)
//   to translate kernel virtual addresses to physical addresses, then map them to file offsets via PhysicalMemoryMap.
// This is the only way to read memory by virtual address for full/kernel memory dumps: such dumps lack a TRIAGE
//   block and do not have a virtual-address memory stream like MDMP; page data is arranged solely by physical address.
// - Required to enumerate drivers along PsLoadedModuleList and scan the kernel stack.
// Limitation:
// - Only 4-level paging (PML4) is implemented. 5-level paging (LA57) and 32-bit PAE are not
//   covered; translation always fails instead of returning an invalid address when encountered;
// - Also fails when a page table entry is marked present but the physical page was not dumped (kernel
//   dumps skip many pages); this is missing information in the dump itself, not a translation error.
// Call method:
// - After KernelDumpParser constructs the PhysicalMemoryMap, this class is
//   constructed, then readVirtual() is used to fetch bytes by kernel virtual address.
// ============================================================

#include "DumpPhysicalMemory.h"

namespace ks::minidump
{
    // PageTableWalker purpose: x64 virtual address translator based on dump physical page indices.
    // Internally read-only after construction; safe for concurrent queries.
    class PageTableWalker
    {
    public:
        // Constructor purpose: bind file view, physical page index, and page directory base address.
        // Passes in the view file mapping, physical page index, and directoryTableBase (CR3 at crash time).
        PageTableWalker(
            const DumpFileView& view,
            const PhysicalMemoryMap& physical,
            std::uint64_t directoryTableBase);

        // usable: determines if the translator has valid working conditions (physical index is valid and CR3 is trusted).
        bool usable() const { return usable_; }

        // translate purpose: Translate a virtual address to a physical address.
        // Accepts virtualAddress and output physicalOut;
        // Return false if the page table entry is missing at any level, not paged out, or marked as not-present.
        // largePageOut: Optional; returns whether the address is mapped by 1GB/2MB large pages.
        bool translate(
            std::uint64_t virtualAddress,
            std::uint64_t* physicalOut,
            bool* largePageOut = nullptr) const;

        // readVirtual: Reads bytes at a virtual address, automatically handling page translation and concatenation.
        // Input: virtualAddress is the start address, bytes is the length, and the output buffer receives the data;
        // Return false if any page translation fails; do not perform partial filling.
        bool readVirtual(std::uint64_t virtualAddress, std::uint64_t bytes, void* buffer) const;

        // readPointer: Read a 64-bit pointer; do not modify the output on failure.
        bool readPointer(std::uint64_t virtualAddress, std::uint64_t* valueOut) const;

        // readUnicodeString: Read the content of the target machine's UNICODE_STRING.
        // Input: bufferAddress (character buffer address) and lengthBytes (byte count);
        // Returns the read text; returns an empty string if the length is invalid or memory is unavailable.
        QString readUnicodeString(std::uint64_t bufferAddress, std::uint16_t lengthBytes) const;

        // directoryTableBase purpose: Returns the actual physical base address of the page directory in use.
        std::uint64_t directoryTableBase() const { return directoryTableBase_; }

    private:
        const DumpFileView& view_;             // m_view: Read-only file view.
        const PhysicalMemoryMap& physical_;    // m_physical: Physical page index.
        std::uint64_t directoryTableBase_ = 0; // m_directoryTableBase: Physical page base address of CR3.
        bool usable_ = false;                  // m_usable: Whether translation conditions are met.
    };
}
