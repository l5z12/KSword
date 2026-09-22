#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <algorithm>
#include <cstring>
#include "RuntimeResolver.h"
#include "RuntimeSignatures.h"
#include "RuntimeWin10Signatures.h"

namespace ks::dwm_order::runtime
{
    namespace
    {
        constexpr unsigned kNodes = static_cast<unsigned>(Node::kCount);
        constexpr unsigned kMaxFragments = 64;
        struct Model
        {
            std::uint32_t id;
            Layout layout;
            const Pattern* patterns;
            std::size_t patternCount;
            bool fragmented;
        };
        const Model kModels[] = {
            {1, signatures::kLayout, signatures::kPatterns, std::size(signatures::kPatterns), false},
            {2, win10_signatures::kLayout, win10_signatures::kPatterns, std::size(win10_signatures::kPatterns), true}
        };

        bool accessible(const void* memory, std::size_t bytes)
        {
            auto address = reinterpret_cast<std::uintptr_t>(memory);
            if (!address || bytes > UINTPTR_MAX - address) return false;
            const auto kEnd = address + bytes;
            while (address < kEnd)
            {
                MEMORY_BASIC_INFORMATION info{};
                if (!VirtualQuery(reinterpret_cast<const void*>(address), &info, sizeof(info))
                    || info.State != MEM_COMMIT || (info.Protect & (PAGE_GUARD | PAGE_NOACCESS))) return false;
                const auto kNext = reinterpret_cast<std::uintptr_t>(info.BaseAddress) + info.RegionSize;
                if (kNext <= address) return false;
                address = kNext;
            }
            return true;
        }

        struct Image
        {
            const unsigned char* data;
            std::size_t bytes;
            std::uintptr_t base;
            IMAGE_NT_HEADERS64 nt{};
            IMAGE_SECTION_HEADER sections[96]{};
            bool available[96]{};
            const RUNTIME_FUNCTION* functions = nullptr;
            std::uint32_t functionCount = 0;

            bool range(std::uint64_t rva, std::uint64_t count) const
            { return rva <= bytes && count <= bytes - rva; }

            template<class T> T read(std::uint32_t rva) const
            {
                T value{};
                if (range(rva, sizeof(T))) std::memcpy(&value, data + rva, sizeof(T));
                return value;
            }

            bool in(std::uint32_t rva, std::size_t count, Section kind) const
            {
                if (!range(rva, count)) return false;
                for (unsigned i = 0; i < nt.FileHeader.NumberOfSections; ++i)
                {
                    const auto& s = sections[i];
                    const auto kSize = s.Misc.VirtualSize;
                    if (!available[i] || rva < s.VirtualAddress || rva - s.VirtualAddress > kSize
                        || count > kSize - (rva - s.VirtualAddress)) continue;
                    const auto kActual = (s.Characteristics & IMAGE_SCN_MEM_EXECUTE) ? Section::kCode
                        : (s.Characteristics & IMAGE_SCN_MEM_WRITE) ? Section::kWritable : Section::kReadOnly;
                    return kind == kActual;
                }
                return false;
            }

            bool open()
            {
                if (!data || bytes < sizeof(IMAGE_DOS_HEADER) || bytes > 128 * 1024 * 1024
                    || !accessible(data, sizeof(IMAGE_DOS_HEADER))) return false;
                const auto kDos = read<IMAGE_DOS_HEADER>(0);
                if (kDos.e_magic != IMAGE_DOS_SIGNATURE || kDos.e_lfanew < 0
                    || kDos.e_lfanew > 0x1000 || !range(kDos.e_lfanew, sizeof(nt))
                    || !accessible(data + kDos.e_lfanew, sizeof(nt))) return false;
                nt = read<IMAGE_NT_HEADERS64>(kDos.e_lfanew);
                if (nt.Signature != IMAGE_NT_SIGNATURE || nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64
                    || nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC
                    || nt.OptionalHeader.SizeOfImage != bytes || nt.FileHeader.NumberOfSections == 0
                    || nt.FileHeader.NumberOfSections > 96
                    || nt.FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER64)
                    || nt.OptionalHeader.NumberOfRvaAndSizes < IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return false;
                const auto kAt = static_cast<std::uint32_t>(kDos.e_lfanew) + sizeof(nt);
                const auto kSectionBytes = nt.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
                if (!range(kAt, kSectionBytes) || !accessible(data + kAt, kSectionBytes)) return false;
                std::memcpy(sections, data + kAt, kSectionBytes);
                std::uint32_t previousEnd = nt.OptionalHeader.SizeOfHeaders;
                for (unsigned i = 0; i < nt.FileHeader.NumberOfSections; ++i)
                {
                    const auto& s = sections[i];
                    if (!range(s.VirtualAddress, s.Misc.VirtualSize) || s.VirtualAddress < previousEnd
                        || ((s.Characteristics & IMAGE_SCN_MEM_EXECUTE) && (s.Characteristics & IMAGE_SCN_MEM_WRITE))) return false;
                    previousEnd = s.VirtualAddress + s.Misc.VirtualSize;
                    // Discarded relocation/debug sections are not needed for matching.
                    available[i] = (s.Characteristics & IMAGE_SCN_MEM_READ)
                        && !(s.Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
                        && accessible(data + s.VirtualAddress, s.Misc.VirtualSize);
                }
                const auto& exception = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
                if (!exception.Size || exception.Size % sizeof(RUNTIME_FUNCTION)
                    || !in(exception.VirtualAddress, exception.Size, Section::kReadOnly)) return false;
                functions = reinterpret_cast<const RUNTIME_FUNCTION*>(data + exception.VirtualAddress);
                functionCount = exception.Size / sizeof(RUNTIME_FUNCTION);
                if (functionCount > 65536) return false;
                std::uint32_t last = 0;
                for (unsigned i = 0; i < functionCount; ++i)
                {
                    const auto& f = functions[i];
                    if (f.BeginAddress <= last || f.EndAddress <= f.BeginAddress
                        || !in(f.BeginAddress, f.EndAddress - f.BeginAddress, Section::kCode)) return false;
                    last = f.BeginAddress;
                }
                return true;
            }

            bool import(std::uint32_t iat, const char* name) const
            {
                const auto& dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
                if (!in(dir.VirtualAddress, dir.Size, Section::kReadOnly)) return false;
                for (std::uint32_t offset = 0; offset + sizeof(IMAGE_IMPORT_DESCRIPTOR) <= dir.Size;
                    offset += sizeof(IMAGE_IMPORT_DESCRIPTOR))
                {
                    const auto kDesc = read<IMAGE_IMPORT_DESCRIPTOR>(dir.VirtualAddress + offset);
                    if (!kDesc.Name) break;
                    if (iat < kDesc.FirstThunk || (iat - kDesc.FirstThunk) % 8 || !kDesc.OriginalFirstThunk) continue;
                    const auto kThunk = static_cast<std::uint64_t>(kDesc.OriginalFirstThunk) + iat - kDesc.FirstThunk;
                    if (kThunk > UINT32_MAX || !in(static_cast<std::uint32_t>(kThunk), 8, Section::kReadOnly)) continue;
                    const auto kNameRva = read<std::uint64_t>(static_cast<std::uint32_t>(kThunk));
                    const auto kLength = std::strlen(name) + 1;
                    if (kNameRva > UINT32_MAX - 2 || !in(static_cast<std::uint32_t>(kNameRva), kLength + 2, Section::kReadOnly)) continue;
                    if (!std::memcmp(data + kNameRva + 2, name, kLength)) return true;
                }
                return false;
            }

            bool relative(std::uint32_t start, const Reference& ref, std::uint32_t& target) const
            {
                if ((ref.width != 1 && ref.width != 4) || !in(start + ref.displacement, ref.width, Section::kCode)) return false;
                const auto kAddress = static_cast<std::int64_t>(start) + ref.nextInstruction
                    + (ref.width == 1 ? read<std::int8_t>(start + ref.displacement)
                        : read<std::int32_t>(start + ref.displacement));
                if (kAddress < 0 || kAddress > UINT32_MAX) return false;
                target = static_cast<std::uint32_t>(kAddress);
                return in(target, 1, ref.section) && (!ref.importName || import(target, ref.importName));
            }

            const RUNTIME_FUNCTION* function(std::uint32_t start) const
            {
                const auto* found = std::lower_bound(functions, functions + functionCount, start,
                    [](const RUNTIME_FUNCTION& f, std::uint32_t at) { return f.BeginAddress < at; });
                return found != functions + functionCount && found->BeginAddress == start ? found : nullptr;
            }

            bool owner(RUNTIME_FUNCTION entry, std::uint32_t& root) const
            {
                for (unsigned depth = 0; depth < 16; ++depth)
                {
                    if (!in(entry.UnwindData, 4, Section::kReadOnly)) return false;
                    const auto kVersionFlags = read<unsigned char>(entry.UnwindData);
                    if ((kVersionFlags & 7) != 1 && (kVersionFlags & 7) != 2) return false;
                    const auto kCodes = read<unsigned char>(entry.UnwindData + 2);
                    const auto kLength = 4u + ((kCodes + 1u) & ~1u) * 2u;
                    if (!in(entry.UnwindData, kLength, Section::kReadOnly)) return false;
                    if (!(kVersionFlags & (UNW_FLAG_CHAININFO << 3)))
                    { root = entry.BeginAddress; return true; }
                    if (kVersionFlags & ((UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) << 3)
                        || !in(entry.UnwindData + kLength, sizeof(entry), Section::kReadOnly)) return false;
                    entry = read<RUNTIME_FUNCTION>(entry.UnwindData + kLength);
                    const auto* parent = function(entry.BeginAddress);
                    if (!parent || parent->EndAddress != entry.EndAddress || parent->UnwindData != entry.UnwindData)
                        return false;
                }
                return false; // Cyclic or unbounded chained unwind records.
            }

            bool fragments(std::uint32_t start, const Pattern& pattern, std::uint32_t* starts) const
            {
                if (pattern.fragmentCount >= kMaxFragments) return false;
                const auto* first = function(start);
                std::uint32_t root = 0;
                if (!first || !owner(*first, root) || root != start
                    || pattern.length > first->EndAddress - start) return false;
                starts[0] = start;
                unsigned count = 0;
                for (unsigned i = 0; i < functionCount; ++i)
                {
                    const auto& f = functions[i];
                    if (f.BeginAddress == start) continue;
                    if (!owner(f, root)) return false;
                    if (root != start) continue;
                    if (count >= pattern.fragmentCount
                        || pattern.fragments[count].length > f.EndAddress - f.BeginAddress) return false;
                    starts[++count] = f.BeginAddress;
                }
                return count == pattern.fragmentCount;
            }
        };

        template<class T> bool match(const Image& image, std::uint32_t start, const T& pattern)
        {
            if (!image.in(start, pattern.length, Section::kCode)) return false;
            const auto* bytes = image.data + start;
            for (unsigned i = 0; i < pattern.length; ++i)
                if ((bytes[i] & pattern.mask[i]) != pattern.bytes[i]) return false;
            return true;
        }

        bool bind(std::uint32_t& binding, std::uint32_t value)
        {
            if (!value || (binding && binding != value)) return false;
            binding = value;
            return true;
        }

        bool windowListOffset(const Image& image, Resolved& result)
        {
            // mov rax,[rip+manager]; mov rcx,[rax+field]; call FindWindowDataByHwnd
            // There can be several equivalent call sites. Every qualified site
            // must agree on the field. No fallback to a build-specific offset.
            constexpr unsigned char kFirst[] = {0x48,0x8b,0x05};
            constexpr unsigned char kSecond[] = {0x48,0x8b,0x88};
            unsigned matches = 0;
            for (unsigned s = 0; s < image.nt.FileHeader.NumberOfSections; ++s)
            {
                const auto& section = image.sections[s];
                if (!image.available[s] || !(section.Characteristics & IMAGE_SCN_MEM_EXECUTE)
                    || section.Misc.VirtualSize < 19) continue;
                const auto kEnd = section.VirtualAddress + section.Misc.VirtualSize - 19;
                for (auto rva = section.VirtualAddress; rva <= kEnd; ++rva)
                {
                    const auto* p = image.data + rva;
                    if (std::memcmp(p, kFirst, 3) || std::memcmp(p + 7, kSecond, 3) || p[14] != 0xe8) continue;
                    std::uint32_t manager = 0, find = 0;
                    if (!image.relative(rva, {3,7,Section::kWritable,Node::kCount,Binding::kNone,nullptr}, manager)
                        || !image.relative(rva, {15,19,Section::kCode,Node::kCount,Binding::kNone,nullptr}, find)
                        || manager != result.desktopManager || find != result.functions[static_cast<unsigned>(Node::FindWindow)]) continue;
                    const auto kField = image.read<std::uint32_t>(rva + 10);
                    if (kField < 8 || kField > 0x1000 || kField % 8 || !bind(result.windowListOffset, kField)) return false;
                    ++matches;
                }
            }
            return matches >= 2;
        }

        bool vtable(const Image& image, Resolved& result)
        {
            unsigned hits[3]{};
            const Node kRoles[] = {Node::kDestroyWindow, Node::kZOrder, Node::kUpdateScene};
            std::uint32_t* slots[] = {&result.destroySlot, &result.zOrderSlot, &result.updateSlot};
            for (unsigned i = 0; i < 128; ++i)
            {
                const auto kEntry = result.vtable + i * 8;
                if (!image.in(kEntry, 8, Section::kReadOnly)) break;
                const auto kAddress = image.read<std::uint64_t>(kEntry);
                if (kAddress < image.base || kAddress - image.base > UINT32_MAX
                    || !image.in(static_cast<std::uint32_t>(kAddress - image.base), 1, Section::kCode)) break;
                for (unsigned role = 0; role < 3; ++role)
                    if (kAddress - image.base == result.functions[static_cast<unsigned>(kRoles[role])])
                    { ++hits[role]; *slots[role] = i; }
                ++result.tableSlots;
            }
            // MSVC may place unrelated vtables directly after this one without
            // a null/RTTI delimiter. Only the prefix through our last hook is
            // published; never infer a table's length from a null terminator.
            result.tableSlots = (std::max)({result.destroySlot, result.zOrderSlot, result.updateSlot}) + 1;
            return hits[0] == 1 && hits[1] == 1 && hits[2] == 1;
        }

        bool cfg(const Image& image, const Resolved& result)
        {
            const auto& dir = image.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
            if (dir.Size < 148 || !image.in(dir.VirtualAddress, 148, Section::kReadOnly)
                || image.read<std::uint32_t>(dir.VirtualAddress) < 148) return false;
            const auto kTable = image.read<std::uint64_t>(dir.VirtualAddress + 128);
            const auto kCount = image.read<std::uint64_t>(dir.VirtualAddress + 136);
            const auto kFlags = image.read<std::uint32_t>(dir.VirtualAddress + 144);
            const auto kStride = 4 + ((kFlags >> 28) & 15);
            if ((kFlags & 0x500) != 0x500 || kTable < image.base || kTable - image.base > UINT32_MAX
                || !kCount || kCount > 65536 || !image.in(static_cast<std::uint32_t>(kTable - image.base),
                    static_cast<std::size_t>(kCount * kStride), Section::kReadOnly)) return false;
            unsigned valid = 0;
            const Node kRoles[] = {Node::kDestroyWindow, Node::kZOrder, Node::kUpdateScene};
            std::uint32_t previous = 0;
            for (std::uint64_t i = 0; i < kCount; ++i)
            {
                const auto kEntry = static_cast<std::uint32_t>(kTable - image.base + i * kStride);
                const auto kRva = image.read<std::uint32_t>(kEntry);
                if (kRva <= previous || !image.in(kRva, 1, Section::kCode)) return false;
                previous = kRva;
                for (auto role : kRoles)
                    if (kRva == result.functions[static_cast<unsigned>(role)])
                    {
                        if (kStride > 4 && (image.read<unsigned char>(kEntry + 4) & 1)) return false;
                        ++valid;
                    }
            }
            // The two private helpers stay behind the reviewed nocf bridge;
            // their presence/absence in GFIDS may vary across serviced images.
            return valid == 3;
        }

        Failure resolveModel(const Image& image, const Model& model, Resolved& result,
            Node* failedNode, unsigned& progress)
        {
            const Pattern* chosen[kNodes]{};
            std::uint32_t fragmentStarts[kNodes][kMaxFragments]{};
            for (unsigned node = 0; node < kNodes; ++node)
            {
                bool required = false;
                for (std::size_t p = 0; p < model.patternCount; ++p)
                    required |= static_cast<unsigned>(model.patterns[p].node) == node;
                if (!required) continue;
                if (failedNode) *failedNode = static_cast<Node>(node);
                for (std::size_t p = 0; p < model.patternCount; ++p)
                {
                    const auto& pattern = model.patterns[p];
                    if (static_cast<unsigned>(pattern.node) != node) continue;
                    for (unsigned i = 0; i < image.functionCount; ++i)
                    {
                        const auto kRva = image.functions[i].BeginAddress;
                        if (!match(image, kRva, pattern)) continue;
                        std::uint32_t starts[kMaxFragments]{kRva};
                        if (model.fragmented)
                        {
                            if (!image.fragments(kRva, pattern, starts)) return Failure::kInvalidFragments;
                            bool matches = true;
                            for (unsigned f = 0; f < pattern.fragmentCount; ++f)
                                matches &= match(image, starts[f + 1], pattern.fragments[f]);
                            if (!matches) continue;
                        }
                        if (result.functions[node] && result.functions[node] != kRva) return Failure::kAmbiguousPattern;
                        // Even variants sharing byte masks must agree on all
                        // reference roles; the generator deduplicates those.
                        if (chosen[node] && chosen[node] != &pattern) return Failure::kAmbiguousPattern;
                        result.functions[node] = kRva;
                        chosen[node] = &pattern;
                        std::memcpy(fragmentStarts[node], starts, sizeof(starts));
                    }
                }
                if (!chosen[node]) return Failure::kMissingPattern;
                ++progress;
            }
            for (unsigned node = 0; node < kNodes; ++node)
            {
                if (!chosen[node]) continue;
                if (failedNode) *failedNode = static_cast<Node>(node);
                const auto& pattern = *chosen[node];
                for (unsigned f = 0; f <= pattern.fragmentCount; ++f)
                {
                    const auto* refs = f ? pattern.fragments[f - 1].references : pattern.references;
                    const auto kCount = f ? pattern.fragments[f - 1].referenceCount : pattern.referenceCount;
                    for (unsigned i = 0; i < kCount; ++i)
                    {
                        const auto& ref = refs[i];
                        std::uint32_t target = 0;
                        if (!image.relative(fragmentStarts[node][f], ref, target)
                            || (ref.node != Node::kCount && target != result.functions[static_cast<unsigned>(ref.node)]))
                            return Failure::kReferenceMismatch;
                        if (ref.targetFragment != UINT16_MAX)
                        {
                            if (ref.targetFragment > pattern.fragmentCount) return Failure::kReferenceMismatch;
                            const auto kLength = ref.targetFragment ? pattern.fragments[ref.targetFragment - 1].length : pattern.length;
                            if (ref.targetOffset >= kLength
                                || target != fragmentStarts[node][ref.targetFragment] + ref.targetOffset)
                                return Failure::kReferenceMismatch;
                        }
                        std::uint32_t* slot = ref.binding == Binding::kDesktopManager ? &result.desktopManager
                            : ref.binding == Binding::kCriticalSection ? &result.criticalSection
                            : ref.binding == Binding::kVtable ? &result.vtable : nullptr;
                        if (slot && !bind(*slot, target)) return Failure::kReferenceMismatch;
                    }
                }
            }
            if (failedNode) *failedNode = Node::kCount;
            if (!image.in(result.desktopManager, 8, Section::kWritable)
                || !image.in(result.criticalSection, sizeof(CRITICAL_SECTION), Section::kWritable)
                || result.desktopManager % 8 || result.criticalSection % 8) return Failure::kReferenceMismatch;
            if (!vtable(image, result)) return Failure::kInvalidVtable;
            if (!cfg(image, result)) return Failure::kInvalidCfg;
            if (!windowListOffset(image, result)) return Failure::kInvalidWindowList;
            result.layout = model.layout;
            result.model = model.id;
            return Failure::kNone;
        }
    }

    Failure resolve(const void* image, std::size_t bytes, std::uintptr_t loadBase,
        Resolved& result, Node* failedNode)
    {
        result = {};
        if (failedNode) *failedNode = Node::kCount;
        Image input{static_cast<const unsigned char*>(image), bytes, loadBase};
        if (!input.open()) return Failure::kInvalidImage;
        Failure bestFailure = Failure::kMissingPattern;
        unsigned bestProgress = 0;
        Node bestNode = Node::kCount;
        Resolved selected{};
        for (const auto& model : kModels)
        {
            Resolved candidate{};
            unsigned progress = 0;
            Node node = Node::kCount;
            const auto kFailure = resolveModel(input, model, candidate, &node, progress);
            if (kFailure == Failure::kNone)
            {
                if (selected.model) return Failure::kAmbiguousPattern;
                selected = candidate;
            }
            else if (progress >= bestProgress)
            { bestFailure = kFailure; bestProgress = progress; bestNode = node; }
        }
        if (selected.model) { result = selected; return Failure::kNone; }
        if (failedNode) *failedNode = bestNode;
        return bestFailure;
    }
}
