#pragma once

// ============================================================
// DumpStackWalker.h
// Purpose:
// - Reconstruct a "suspected call stack" without PDB symbols and without performing unwind operations;
//   Scan thread stack memory pointer-by-pointer, treat values falling within a module image
//   range as candidate return addresses, and filter false positives using several rules;
// - User-mode MDMP and kernel small dumps share the same scanner: the former's stack comes
//   from MINIDUMP_THREAD.Stack, while the latter's comes from the TRIAGE_DUMP64 CallStack block.
// Limitations (must be honestly disclosed to users):
// - Stack scanning is not true stack unwinding: residual old frames may be treated as valid frames (false positives),
//   inline and FPO functions will not appear (false negatives), and frame indices only reflect their relative order on
//   the stack, not the exact call hierarchy. The UI uniformly labels this as "Suspected Call Stack (Stack Scan)".
// Call method:
// - After the parser prepares StackScanInput and ModuleIndex, it calls scanStackFrames.
// ============================================================

#include "DumpMemoryReader.h"
#include "DumpSymbolIndex.h"
#include "MinidumpFormat.h"

namespace ks::minidump
{
    // StackScanInput: All inputs required for a single stack scan.
    struct StackScanInput
    {
        std::uint64_t stackFileOffset = 0;   // stackFileOffset: Offset of stack bytes in the dump file.
        std::uint64_t stackBytes = 0;        // stackBytes: Number of stack bytes.
        std::uint64_t stackBaseAddress = 0;  // stackBaseAddress: Virtual address of the target machine corresponding to the first byte of the stack.
        std::uint64_t stackPointer = 0;      // stackPointer: Stack pointer (SP) at crash time, used to determine the scan start point; 0 indicates scanning from the beginning.
        std::uint64_t instructionPointer = 0; // instructionPointer: The IP at the time of the crash, used as frame 0.
        std::uint32_t pointerSize = 8;       // pointerSize: Pointer width (4 or 8), i.e., the scan step size.
        std::uint32_t threadId = 0;          // threadId: ID of the owning thread, written to every frame in the output.
    };

    // scanStackFrames purpose: Scan stack memory and produce a suspected call stack.
    // Accepts view file view, input scan input, modules module interval index, memory captured memory index (used to
    // verify if the instruction before the return address is a call instruction; index may be null), and maxFrames
    // maximum number of frames to produce; returns an array of frames sorted by stack address from low to high.
    // Frame 0 is fixed from the CONTEXT IP (fromContext=true); the rest are obtained via scanning.
    std::vector<StackFrameEntry> scanStackFrames(
        const DumpFileView& view,
        const StackScanInput& input,
        const ModuleIndex& modules,
        const DumpMemoryReader& memory,
        int maxFrames);

    // looksLikeReturnAddress purpose: Checks if several bytes preceding the address form a call instruction.
    // Input: view, the memory index memory, the candidate return address address, and the pointer width pointerSize;
    // Returns false when the target bytes cannot be read (allowing the caller to degrade to 'unchecked' rather than discarding immediately).
    bool looksLikeReturnAddress(
        const DumpFileView& view,
        const DumpMemoryReader& memory,
        std::uint64_t address,
        std::uint32_t pointerSize);
}
