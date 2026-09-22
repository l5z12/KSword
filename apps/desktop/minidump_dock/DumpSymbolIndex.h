#pragma once

// ============================================================
// DumpSymbolIndex.h
// Purpose:
// - Provides an address-to-module interval index: translates a raw address into 'module name
//   + offset' and determines whether the address falls within a loaded or unloaded module.
// - Provides address type classification: NULL page, user space, kernel space,
//   or allocator sentinel values (uninitialized, use-after-free), to add Chinese
//   annotations to BugCheck parameters, exception parameters, and register values.
// - This module does not load any symbol files (PDB), only performs image-level
//   attribution; therefore, it can never provide function names, only module+offset.
// Call method:
// - After populating modules/unloadedModules, the parser constructs
//   ModuleIndex, then resolve()/symbolText() can be called for any address.
// ============================================================

#include "MinidumpFormat.h"

namespace ks::minidump
{
    // ModuleIndex purpose: A module interval table sorted by base address, supporting O(log n) address ownership queries.
    // Internal data is read-only after construction and can be freely copied within the parsing thread.
    class ModuleIndex
    {
    public:
        // build: Constructs an index from the module table and unloaded module table in the parsed results.
        // Input: modules contains loaded modules, unloaded contains unloaded modules, and pointerSize is the pointer width (4/8).
        void build(
            const std::vector<ModuleEntry>& modules,
            const std::vector<UnloadedModuleEntry>& unloaded,
            std::uint32_t pointerSize);

        // resolve purpose: Interprets a value as an address and provides module ownership and property annotations.
        // Input address to be resolved; returns the complete resolution result (always valid, with empty fields on miss).
        AddressNote resolve(std::uint64_t address) const;

        // symbolText purpose: Extract only the 'module name + 0x offset' text.
        // Takes an address; if a module is found, returns a string like nvlddmkm.sys+0x1A2B3, otherwise returns an empty string.
        QString symbolText(std::uint64_t address) const;

        // annotate: Generates a Chinese description for the 'Annotation' column of a table based on a given numeric value.
        // Input address value; returns "module name + offset (unloaded driver)" or address property description.
        // Return an empty string when the value is too small (not resembling an address) to avoid displaying meaningless annotations in the register table.
        QString annotate(std::uint64_t address) const;

    private:
        // Range: An address interval [base, base+size) occupied by a module.
        struct Range
        {
            std::uint64_t base = 0;  // base: Image base address.
            std::uint64_t end = 0;   // end: Image end address (exclusive).
            QString name;            // name: Module name (directory part removed).
            bool unloaded = false;   // unloaded: Indicates whether the module is from the unloaded module table.
        };

        std::vector<Range> ranges_;      // m_ranges: Module ranges sorted by base in ascending order.
        std::uint32_t pointerSize_ = 8;  // m_pointerSize: Target machine pointer width, determines kernel space lower bound.
    };

    // poisonValueText: Identifies allocator/compiler sentinel padding values.
    // Takes a value and pointerSize; returns the Chinese meaning if matched, otherwise returns an empty string.
    // For example, 0xCCCCCCCC indicates uninitialized stack memory (MSVC /RTC padding).
    QString poisonValueText(std::uint64_t value, std::uint32_t pointerSize);

    // classifyAddress: Determines address nature solely by numeric range, without consulting the module table.
    // Input: address value and pointerSize width; Output: address classification.
    AddressKind classifyAddress(std::uint64_t address, std::uint32_t pointerSize);

    // addressKindText purpose: convert address type classification into Chinese description.
    // Accepts the kind classification; returns Chinese text, or an empty string if Unknown.
    QString addressKindText(AddressKind kind);

    // baseModuleName purpose: extract the filename from the full path.
    // Takes a module path (e.g., \SystemRoot\System32\drivers\x.sys) as input; returns the module name (e.g., x.sys).
    QString baseModuleName(const QString& path);
}
