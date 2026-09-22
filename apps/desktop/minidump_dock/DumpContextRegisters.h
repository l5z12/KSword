#pragma once

// ============================================================
// DumpContextRegisters.h
// Purpose:
// - Extract a complete register snapshot from the CONTEXT structure in the dump based on the CPU architecture.
// - In user-mode MDMPs, the CONTEXT is pointed to by MINIDUMP_LOCATION_DESCRIPTOR, while in kernel
//   dumps, the CONTEXT is located at a fixed offset within DUMP_HEADER64; both share this module.
// Each register value is checked against the ModuleIndex. When a module match is found, it is labeled with "module name +
//   offset". When a sentinel value is matched, it is labeled as "uninitialized/freed". This is a key clue for determining
//   the root cause of the crash (e.g., Rcx being 0xFFFFFFFFFFFFFFFF often indicates a dereferenced invalid object pointer).
// Layout source:
// - Offsets for CONTEXT structures across architectures are taken from official public definitions
//   in winnt.h, with static_assert self-checks for the local architecture in the implementation file.
// Call method:
// - After the parser obtains the file offset and length of the CONTEXT, it calls readContextRegisters.
// ============================================================

#include "DumpSymbolIndex.h"
#include "MinidumpFormat.h"

namespace ks::minidump
{
    // ContextArch: The CONTEXT layout categories supported by this module.
    enum class ContextArch
    {
        kUnknown, // Unknown: Unsupported architecture; all reads will fail.
        kX86,     // X86: 32-bit x86 CONTEXT (0x2CC bytes).
        kAmd64,   // Amd64: x64 CONTEXT (0x4D0 bytes).
        kArm64,   // Arm64: ARM64 CONTEXT (0x390 bytes).
    };

    // contextArchFromProcessorArchitecture purpose: maps SYSTEM_INFO's
    // PROCESSOR_ARCHITECTURE_* IDs to this module's ContextArch.
    // Accepts an architecture ID; returns Unknown if unrecognized.
    ContextArch contextArchFromProcessorArchitecture(std::uint16_t architecture);

    // contextArchFromMachineImageType: Maps the PE machine type (the
    // MachineImageType field in the kernel dump header) to the module's ContextArch.
    // Note: Pass machineType (0x014C/0x8664/0xAA64); return Unknown if unrecognized.
    ContextArch contextArchFromMachineImageType(std::uint32_t machineType);

    // contextPointerSize purpose: Returns the pointer width (4 or 8) for the given architecture.
    // Takes arch; returns 8 if Unknown.
    std::uint32_t contextPointerSize(ContextArch arch);

    // contextMinimumBytes: Returns the minimum CONTEXT length required to read general-purpose registers.
    // Pass arch; return 0 if Unknown. Used to validate stream length before parsing.
    std::uint64_t contextMinimumBytes(ContextArch arch);

    // readContextPointers purpose: Retrieve only the instruction pointer, stack pointer, and frame pointer.
    // Accepts view, contextOffset (offset of CONTEXT within the file), contextBytes (available length), arch
    // (architecture), and three output pointers (which may be nullptr); returns true only if all reads succeed.
    bool readContextPointers(
        const DumpFileView& view,
        std::uint64_t contextOffset,
        std::uint64_t contextBytes,
        ContextArch arch,
        std::uint64_t* instructionPointerOut,
        std::uint64_t* stackPointerOut,
        std::uint64_t* framePointerOut);

    // readContextRegisters purpose: Extract a complete register snapshot and annotate each entry individually.
    // Accepts view, contextOffset, contextBytes, arch, threadId (the thread owning the context),
    // and modules (module index used to translate register values into 'module name + offset').
    // Returns: an array of registers ordered by architecture natural order; returns an empty array if the length is insufficient.
    std::vector<RegisterEntry> readContextRegisters(
        const DumpFileView& view,
        std::uint64_t contextOffset,
        std::uint64_t contextBytes,
        ContextArch arch,
        std::uint32_t threadId,
        const ModuleIndex& modules);

    // eFlagsText purpose: Splits x86/x64 EFlags into a list of set flag names.
    // Accepts eflags value; returns text like "0x10246 (PF ZF IF)".
    QString eFlagsText(std::uint32_t eflags);
}
