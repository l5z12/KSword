// ============================================================
// DumpContextRegisters.cpp
// Purpose:
// - Implement CONTEXT register extraction declared in DumpContextRegisters.h;
// - Describe the layout for each architecture using a static table of { register name, offset, width };
//   the read logic is architecture-agnostic, and adding a new architecture only requires adding a new table.
// - Offsets are taken from the official winnt.h, with a static_assert self-check for the compilation
//   target architecture in this file: on native x64, it validates the key offsets of the x64 table.
// ============================================================

#include "DumpContextRegisters.h"

#include <windows.h>

#include <cstddef>
#include <cstring>

namespace ks::minidump
{
    namespace
    {
        // RegisterSlot: location description of a register in CONTEXT.
        struct RegisterSlot
        {
            const char* name;      // name: Register name (original English text, do not translate).
            std::uint32_t offset;  // offset: Byte offset within the CONTEXT structure.
            std::uint32_t width;   // width: Byte width (2/4/8).
        };

        // kAmd64Registers: General-purpose registers and critical status fields for x64 CONTEXT.
        // Ordered by debugging convention: first Rip/Rsp/Rbp, then general-purpose registers, finally status bits.
        constexpr RegisterSlot kAmd64Registers[] = {
            { "Rip", 0xF8, 8 },
            { "Rsp", 0x98, 8 },
            { "Rbp", 0xA0, 8 },
            { "Rax", 0x78, 8 },
            { "Rbx", 0x90, 8 },
            { "Rcx", 0x80, 8 },
            { "Rdx", 0x88, 8 },
            { "Rsi", 0xA8, 8 },
            { "Rdi", 0xB0, 8 },
            { "R8",  0xB8, 8 },
            { "R9",  0xC0, 8 },
            { "R10", 0xC8, 8 },
            { "R11", 0xD0, 8 },
            { "R12", 0xD8, 8 },
            { "R13", 0xE0, 8 },
            { "R14", 0xE8, 8 },
            { "R15", 0xF0, 8 },
            { "EFlags", 0x44, 4 },
            { "SegCs", 0x38, 2 },
            { "SegSs", 0x42, 2 },
            { "SegDs", 0x3A, 2 },
            { "SegEs", 0x3C, 2 },
            { "SegFs", 0x3E, 2 },
            { "SegGs", 0x40, 2 },
            { "MxCsr", 0x34, 4 },
            { "ContextFlags", 0x30, 4 },
        };

        // kX86Registers: General-purpose registers and critical state fields for 32-bit x86 CONTEXT.
        constexpr RegisterSlot kX86Registers[] = {
            { "Eip", 0xB8, 4 },
            { "Esp", 0xC4, 4 },
            { "Ebp", 0xB4, 4 },
            { "Eax", 0xB0, 4 },
            { "Ebx", 0xA4, 4 },
            { "Ecx", 0xAC, 4 },
            { "Edx", 0xA8, 4 },
            { "Esi", 0xA0, 4 },
            { "Edi", 0x9C, 4 },
            { "EFlags", 0xC0, 4 },
            { "SegCs", 0xBC, 4 },
            { "SegSs", 0xC8, 4 },
            { "SegDs", 0x98, 4 },
            { "SegEs", 0x94, 4 },
            { "SegFs", 0x90, 4 },
            { "SegGs", 0x8C, 4 },
            { "ContextFlags", 0x00, 4 },
        };

        // kArm64Registers: General-purpose registers for ARM64 CONTEXT.
        // X0..X28 are arranged contiguously; X29/X30 have separate Fp/Lr aliases in the structure.
        constexpr RegisterSlot kArm64Registers[] = {
            { "Pc",  0x108, 8 },
            { "Sp",  0x100, 8 },
            { "Fp",  0x0F0, 8 },
            { "Lr",  0x0F8, 8 },
            { "X0",  0x008, 8 },
            { "X1",  0x010, 8 },
            { "X2",  0x018, 8 },
            { "X3",  0x020, 8 },
            { "X4",  0x028, 8 },
            { "X5",  0x030, 8 },
            { "X6",  0x038, 8 },
            { "X7",  0x040, 8 },
            { "X8",  0x048, 8 },
            { "X9",  0x050, 8 },
            { "X10", 0x058, 8 },
            { "X11", 0x060, 8 },
            { "X12", 0x068, 8 },
            { "X13", 0x070, 8 },
            { "X14", 0x078, 8 },
            { "X15", 0x080, 8 },
            { "X16", 0x088, 8 },
            { "X17", 0x090, 8 },
            { "X18", 0x098, 8 },
            { "X19", 0x0A0, 8 },
            { "X20", 0x0A8, 8 },
            { "X21", 0x0B0, 8 },
            { "X22", 0x0B8, 8 },
            { "X23", 0x0C0, 8 },
            { "X24", 0x0C8, 8 },
            { "X25", 0x0D0, 8 },
            { "X26", 0x0D8, 8 },
            { "X27", 0x0E0, 8 },
            { "X28", 0x0E8, 8 },
            { "Cpsr", 0x004, 4 },
            { "ContextFlags", 0x000, 4 },
        };

#if defined(_M_X64)
        // The host is x64: directly use the compiler's CONTEXT definition to verify the key offsets in the table.
        static_assert(offsetof(CONTEXT, Rip) == 0xF8, "x64 CONTEXT.Rip 偏移必须是 0xF8");
        static_assert(offsetof(CONTEXT, Rsp) == 0x98, "x64 CONTEXT.Rsp 偏移必须是 0x98");
        static_assert(offsetof(CONTEXT, Rbp) == 0xA0, "x64 CONTEXT.Rbp 偏移必须是 0xA0");
        static_assert(offsetof(CONTEXT, Rax) == 0x78, "x64 CONTEXT.Rax 偏移必须是 0x78");
        static_assert(offsetof(CONTEXT, R15) == 0xF0, "x64 CONTEXT.R15 偏移必须是 0xF0");
        static_assert(offsetof(CONTEXT, EFlags) == 0x44, "x64 CONTEXT.EFlags 偏移必须是 0x44");
        static_assert(offsetof(CONTEXT, SegCs) == 0x38, "x64 CONTEXT.SegCs 偏移必须是 0x38");
        static_assert(offsetof(CONTEXT, MxCsr) == 0x34, "x64 CONTEXT.MxCsr 偏移必须是 0x34");
#elif defined(_M_IX86)
        // Native architecture is x86: validate the x86 table.
        static_assert(offsetof(CONTEXT, Eip) == 0xB8, "x86 CONTEXT.Eip 偏移必须是 0xB8");
        static_assert(offsetof(CONTEXT, Esp) == 0xC4, "x86 CONTEXT.Esp 偏移必须是 0xC4");
        static_assert(offsetof(CONTEXT, Ebp) == 0xB4, "x86 CONTEXT.Ebp 偏移必须是 0xB4");
        static_assert(offsetof(CONTEXT, Eax) == 0xB0, "x86 CONTEXT.Eax 偏移必须是 0xB0");
        static_assert(offsetof(CONTEXT, EFlags) == 0xC0, "x86 CONTEXT.EFlags 偏移必须是 0xC0");
#elif defined(_M_ARM64)
        // Native platform is ARM64: validate the ARM64 table.
        static_assert(offsetof(CONTEXT, Pc) == 0x108, "ARM64 CONTEXT.Pc 偏移必须是 0x108");
        static_assert(offsetof(CONTEXT, Sp) == 0x100, "ARM64 CONTEXT.Sp 偏移必须是 0x100");
        static_assert(offsetof(CONTEXT, Cpsr) == 0x04, "ARM64 CONTEXT.Cpsr 偏移必须是 0x04");
#endif

        // FlagBit: A flag bit in EFlags and its mnemonic.
        struct FlagBit
        {
            std::uint32_t bit;  // bit: Flag bit mask.
            const char* name;   // name: Mnemonic from the Intel manual.
        };

        // kEFlagsBits: common EFlags bits; only lists the few actually useful for troubleshooting.
        constexpr FlagBit kEFlagsBits[] = {
            { 0x00000001u, "CF" }, // Carry
            { 0x00000004u, "PF" }, // parity
            { 0x00000010u, "AF" }, // Auxiliary carry
            { 0x00000040u, "ZF" }, // Zero result
            { 0x00000080u, "SF" }, // Sign
            { 0x00000100u, "TF" }, // Single-step trap
            { 0x00000200u, "IF" }, // Interrupt enable
            { 0x00000400u, "DF" }, // Direction
            { 0x00000800u, "OF" }, // Overflow
            { 0x00010000u, "RF" }, // restore
            { 0x00020000u, "VM" }, // Virtual 8086.
            { 0x00040000u, "AC" }, // Alignment check
        };

        // ReadSlot: Reads a register value as described by RegisterSlot.
        // Accepts view, contextOffset, slot, and an output pointer; returns false on out-of-bounds access.
        bool readSlot(
            const DumpFileView& view,
            const std::uint64_t contextOffset,
            const RegisterSlot& slot,
            std::uint64_t* const valueOut)
        {
            const std::uint64_t kOffset = contextOffset + slot.offset;
            switch (slot.width)
            {
            case 2:
            {
                std::uint16_t value16 = 0;
                if (!view.readStruct(kOffset, &value16))
                {
                    return false;
                }
                *valueOut = value16;
                return true;
            }
            case 4:
            {
                std::uint32_t value32 = 0;
                if (!view.readStruct(kOffset, &value32))
                {
                    return false;
                }
                *valueOut = value32;
                return true;
            }
            default:
                return view.readStruct(kOffset, valueOut);
            }
        }

        // slotTable purpose: Returns the register table and its length for the target architecture.
        // Input arch and output table length; return nullptr for unsupported architectures.
        // Note: Local variables receiving return values in this file must not be named 'slots'—Qt defines 'slots' as an
        // empty macro in qobjectdefs.h, which would cause the identifier to be silently removed during preprocessing.
        const RegisterSlot* slotTable(const ContextArch arch, std::size_t* const countOut)
        {
            switch (arch)
            {
            case ContextArch::kAmd64:
                *countOut = sizeof(kAmd64Registers) / sizeof(kAmd64Registers[0]);
                return kAmd64Registers;
            case ContextArch::kX86:
                *countOut = sizeof(kX86Registers) / sizeof(kX86Registers[0]);
                return kX86Registers;
            case ContextArch::kArm64:
                *countOut = sizeof(kArm64Registers) / sizeof(kArm64Registers[0]);
                return kArm64Registers;
            default:
                *countOut = 0;
                return nullptr;
            }
        }

        // pointerSlots purpose: Return the names of the IP, SP, and FP registers for the target architecture.
        // Accept arch and three output pointers; set all to null for unsupported architectures.
        void pointerSlots(
            const ContextArch arch,
            const char** const ipName,
            const char** const spName,
            const char** const fpName)
        {
            switch (arch)
            {
            case ContextArch::kAmd64: *ipName = "Rip"; *spName = "Rsp"; *fpName = "Rbp"; break;
            case ContextArch::kX86:   *ipName = "Eip"; *spName = "Esp"; *fpName = "Ebp"; break;
            case ContextArch::kArm64: *ipName = "Pc";  *spName = "Sp";  *fpName = "Fp";  break;
            default:                 *ipName = nullptr; *spName = nullptr; *fpName = nullptr; break;
            }
        }
    }

    ContextArch contextArchFromProcessorArchitecture(const std::uint16_t architecture)
    {
        // The IDs come from the PROCESSOR_ARCHITECTURE_* constant family.
        switch (architecture)
        {
        case 0:  return ContextArch::kX86;   // PROCESSOR_ARCHITECTURE_INTEL
        case 9:  return ContextArch::kAmd64; // PROCESSOR_ARCHITECTURE_AMD64
        case 12: return ContextArch::kArm64; // PROCESSOR_ARCHITECTURE_ARM64
        default: return ContextArch::kUnknown;
        }
    }

    ContextArch contextArchFromMachineImageType(const std::uint32_t machineType)
    {
        switch (machineType)
        {
        case 0x014C: return ContextArch::kX86;
        case 0x8664: return ContextArch::kAmd64;
        case 0xAA64: return ContextArch::kArm64;
        default:     return ContextArch::kUnknown;
        }
    }

    std::uint32_t contextPointerSize(const ContextArch arch)
    {
        return arch == ContextArch::kX86 ? 4u : 8u;
    }

    std::uint64_t contextMinimumBytes(const ContextArch arch)
    {
        // Only requires covering up to the end of the general-purpose register area, not the entire CONTEXT.
        switch (arch)
        {
        case ContextArch::kAmd64: return 0x100; // Overwrites up to Rip (0xF8) + 8
        case ContextArch::kX86:   return 0x0CC; // Overwrite up to SegSs (0xC8) + 4.
        case ContextArch::kArm64: return 0x110; // Overwrites up to Pc (0x108) + 8
        default:                 return 0;
        }
    }

    QString eFlagsText(const std::uint32_t eflags)
    {
        // names: mnemonic names for set flags, ordered according to the Intel manual.
        QStringList names;
        for (const FlagBit& flag : kEFlagsBits)
        {
            if ((eflags & flag.bit) != 0)
            {
                names.append(QString::fromLatin1(flag.name));
            }
        }
        // iopl: I/O privilege Level (bits 12-13), occasionally useful for kernel-level troubleshooting.
        const std::uint32_t kIopl = (eflags >> 12) & 0x3u;
        QString text = QStringLiteral("0x%1").arg(QString::number(eflags, 16).toUpper());
        if (!names.isEmpty())
        {
            text += QStringLiteral(" (%1)").arg(names.join(QLatin1Char(' ')));
        }
        if (kIopl != 0)
        {
            text += QStringLiteral(" IOPL=%1").arg(kIopl);
        }
        return text;
    }

    bool readContextPointers(
        const DumpFileView& view,
        const std::uint64_t contextOffset,
        const std::uint64_t contextBytes,
        const ContextArch arch,
        std::uint64_t* const instructionPointerOut,
        std::uint64_t* const stackPointerOut,
        std::uint64_t* const framePointerOut)
    {
        std::size_t slotCount = 0;
        const RegisterSlot* const kSlotTable = slotTable(arch, &slotCount);
        if (kSlotTable == nullptr || contextBytes < contextMinimumBytes(arch))
        {
            return false;
        }
        // ipName/spName/fpName: names of the three key registers in the target architecture.
        const char* ipName = nullptr;
        const char* spName = nullptr;
        const char* fpName = nullptr;
        pointerSlots(arch, &ipName, &spName, &fpName);

        bool allRead = true;
        for (std::size_t index = 0; index < slotCount; ++index)
        {
            const RegisterSlot& slot = kSlotTable[index];
            std::uint64_t* target = nullptr;
            if (ipName != nullptr && std::strcmp(slot.name, ipName) == 0)
            {
                target = instructionPointerOut;
            }
            else if (spName != nullptr && std::strcmp(slot.name, spName) == 0)
            {
                target = stackPointerOut;
            }
            else if (fpName != nullptr && std::strcmp(slot.name, fpName) == 0)
            {
                target = framePointerOut;
            }
            if (target == nullptr)
            {
                continue;
            }
            if (!readSlot(view, contextOffset, slot, target))
            {
                allRead = false;
            }
        }
        return allRead;
    }

    std::vector<RegisterEntry> readContextRegisters(
        const DumpFileView& view,
        const std::uint64_t contextOffset,
        const std::uint64_t contextBytes,
        const ContextArch arch,
        const std::uint32_t threadId,
        const ModuleIndex& modules)
    {
        // registers: Produced register snapshot; empty if the architecture is unsupported or the length is insufficient.
        std::vector<RegisterEntry> registers;
        std::size_t slotCount = 0;
        const RegisterSlot* const kSlotTable = slotTable(arch, &slotCount);
        if (kSlotTable == nullptr || contextBytes < contextMinimumBytes(arch))
        {
            return registers;
        }
        registers.reserve(slotCount);
        for (std::size_t index = 0; index < slotCount; ++index)
        {
            const RegisterSlot& slot = kSlotTable[index];
            std::uint64_t value = 0;
            if (!readSlot(view, contextOffset, slot, &value))
            {
                continue;
            }
            RegisterEntry entry{};
            entry.threadId = threadId;
            entry.name = QString::fromLatin1(slot.name);
            entry.value = value;
            // EFlags expanded using mnemonic flags; other registers interpreted by address with annotations.
            // The criterion must use the architecture's pointer width, not the slot width being 8. For x86, all
            // general-purpose registers are 4 bytes; using the latter would result in zero annotations for the register
            // table in 32-bit dumps, violating the header's commitment that every register value passes through ModuleIndex.
            // Segment registers (2 or 4 bytes, not general-purpose) must not be interpreted
            // as addresses; therefore, the slot width must exactly match the pointer width.
            const std::uint32_t kPointerSize = contextPointerSize(arch);
            if (entry.name == QLatin1String("EFlags"))
            {
                entry.note = eFlagsText(static_cast<std::uint32_t>(value));
            }
            else if (slot.width == kPointerSize && value != 0 &&
                     entry.name != QLatin1String("ContextFlags"))
            {
                entry.note = modules.annotate(value);
            }
            registers.push_back(std::move(entry));
        }
        return registers;
    }
}
