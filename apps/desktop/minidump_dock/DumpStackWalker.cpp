// ============================================================
// DumpStackWalker.cpp
// Purpose:
// - Implements the stack-scan-based call stack reconstruction declared in DumpStackWalker.h;
// - Filtering strategy (from highest to lowest false positive cost):
//   1) The value must fall within a module image range.
//   2) Offsets relative to the module base must skip the PE header (>= 0x1000); otherwise, numerous
//      'data pointers pointing to the image header' will be misinterpreted as return addresses.
//   3) If the dump happens to capture the code page containing that address, require that the
//      preceding 2–7 bytes form a valid call instruction to filter out most residual values.
//   4) Merge adjacent duplicate values to avoid listing the same frame multiple times.
// - Prefer the CONTEXT's SP as the scan start point: data below SP is
//   already unwound garbage; scanning it would only cause false positives.
// ============================================================

#include "DumpStackWalker.h"

#include <algorithm>
#include <cstring>

namespace ks::minidump
{
    namespace
    {
        // kPeHeaderBytes: Lower bound of the offset to skip the image header; code sections always follow this.
        constexpr std::uint64_t kPeHeaderBytes = 0x1000;
        // kMaxScanBytes: Maximum stack bytes to scan per thread to prevent massive stacks from crashing the parser.
        constexpr std::uint64_t kMaxScanBytes = 1024ull * 1024ull;
        // kCallMinBytes/kCallMaxBytes: Length range of x86/x64 call instructions.
        constexpr int kCallMinBytes = 2;
        constexpr int kCallMaxBytes = 7;
    }

    bool looksLikeReturnAddress(
        const DumpFileView& view,
        const DumpMemoryReader& memory,
        const std::uint64_t address,
        const std::uint32_t pointerSize)
    {
        if (address <= static_cast<std::uint64_t>(kCallMaxBytes))
        {
            return false;
        }
        // prefix: Up to 7 bytes before the return address; the call instruction is guaranteed to be fully contained within this range.
        unsigned char prefix[kCallMaxBytes] = {};
        if (!memory.read(
                view,
                address - static_cast<std::uint64_t>(kCallMaxBytes),
                static_cast<std::uint64_t>(kCallMaxBytes),
                prefix))
        {
            return false;
        }
        for (int length = kCallMinBytes; length <= kCallMaxBytes; ++length)
        {
            // opcodeIndex: The index of the first byte of the instruction of length 'length' in 'prefix'.
            const int kOpcodeIndex = kCallMaxBytes - length;
            const unsigned char kOpcode = prefix[kOpcodeIndex];
            // E8 rel32: Direct near call, fixed 5 bytes.
            if (kOpcode == 0xE8 && length == 5)
            {
                return true;
            }
            // FF /2, FF /3: Indirect call (register/memory operand), variable
            // length. Condition: ModRM reg field equals 2 (call) or 3 (call far).
            if (kOpcode == 0xFF && kOpcodeIndex + 1 < kCallMaxBytes)
            {
                const unsigned char kModrm = prefix[kOpcodeIndex + 1];
                const unsigned char kReg = static_cast<unsigned char>((kModrm >> 3) & 0x07);
                if (kReg == 2 || kReg == 3)
                {
                    return true;
                }
            }
            // 9A ptr16:32: Far call, exists only in 32-bit targets.
            if (pointerSize == 4 && kOpcode == 0x9A && length == 7)
            {
                return true;
            }
        }
        return false;
    }

    std::vector<StackFrameEntry> scanStackFrames(
        const DumpFileView& view,
        const StackScanInput& input,
        const ModuleIndex& modules,
        const DumpMemoryReader& memory,
        const int maxFrames)
    {
        // frames: The produced suspected call stack; frame 0 comes from CONTEXT, others appended in ascending stack address order.
        std::vector<StackFrameEntry> frames;
        if (maxFrames <= 0)
        {
            return frames;
        }
        // pointerSize: Scan step size; invalid values are treated as 8 bytes.
        const std::uint32_t kPointerSize = input.pointerSize == 4 ? 4u : 8u;

        // Frame 0: The instruction pointer from the CONTEXT itself is the only fully trusted address in the entire stack.
        if (input.instructionPointer != 0)
        {
            const AddressNote kNote = modules.resolve(input.instructionPointer);
            StackFrameEntry frame{};
            frame.threadId = input.threadId;
            frame.index = 0;
            frame.stackAddress = input.stackPointer;
            frame.address = input.instructionPointer;
            frame.symbolText = kNote.symbolText;
            frame.moduleName = kNote.moduleName;
            frame.unloadedModule = kNote.unloadedModule;
            frame.fromContext = true;
            frames.push_back(std::move(frame));
        }

        if (input.stackBytes == 0 || !view.contains(input.stackFileOffset, input.stackBytes))
        {
            return frames;
        }

        // scanStart: Start scanning from SP first; data below SP consists of previously popped old data.
        // If SP is outside this stack memory segment, fall back to scanning from the start of the segment.
        std::uint64_t scanStart = 0;
        if (input.stackPointer >= input.stackBaseAddress &&
            input.stackPointer < input.stackBaseAddress + input.stackBytes)
        {
            scanStart = input.stackPointer - input.stackBaseAddress;
        }
        // Align to pointer width: return addresses are always aligned; skipping misaligned positions reduces false positives by half.
        scanStart -= scanStart % kPointerSize;
        const std::uint64_t kScanEnd =
            std::min<std::uint64_t>(input.stackBytes, scanStart + kMaxScanBytes);

        // lastAddress: Address of the previous frame, used to merge adjacent duplicate values (same frame written to multiple slots).
        std::uint64_t lastAddress = 0;
        int frameIndex = static_cast<int>(frames.size());
        for (std::uint64_t offset = scanStart;
             offset + kPointerSize <= kScanEnd && frameIndex < maxFrames;
             offset += kPointerSize)
        {
            // candidate: value of the current stack slot, read according to the target machine's pointer width.
            std::uint64_t candidate = 0;
            const unsigned char* const kSlot =
                view.at(input.stackFileOffset + offset, kPointerSize);
            if (kSlot == nullptr)
            {
                break;
            }
            if (kPointerSize == 4)
            {
                std::uint32_t value32 = 0;
                std::memcpy(&value32, kSlot, sizeof(value32));
                candidate = value32;
            }
            else
            {
                std::memcpy(&candidate, kSlot, sizeof(candidate));
            }
            if (candidate == 0 || candidate == lastAddress)
            {
                continue;
            }

            const AddressNote kNote = modules.resolve(candidate);
            // Rules 1 and 2: Must hit a module and skip the PE header region.
            if (kNote.symbolText.isEmpty() || kNote.offset < kPeHeaderBytes)
            {
                continue;
            }
            // Rule 3: When this code segment is captured in the dump, the preceding instruction must be a call.
            // If not found (small dumps typically lack code pages), verification is impossible; retain the candidate.
            if (memory.contains(candidate - kCallMaxBytes, kCallMaxBytes) &&
                !looksLikeReturnAddress(view, memory, candidate, kPointerSize))
            {
                continue;
            }

            StackFrameEntry frame{};
            frame.threadId = input.threadId;
            frame.index = frameIndex;
            frame.stackAddress = input.stackBaseAddress + offset;
            frame.address = candidate;
            frame.symbolText = kNote.symbolText;
            frame.moduleName = kNote.moduleName;
            frame.unloadedModule = kNote.unloadedModule;
            frame.fromContext = false;
            frames.push_back(std::move(frame));
            lastAddress = candidate;
            ++frameIndex;
        }
        return frames;
    }
}
