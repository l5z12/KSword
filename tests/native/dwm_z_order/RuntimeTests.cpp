#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>
#include "../../../integrations/dwm_z_order/RuntimeResolver.h"
#include "../../../integrations/dwm_z_order/RuntimeSignatures.h"
#include "../../../integrations/dwm_z_order/RuntimeWin10Signatures.h"

namespace
{
    using namespace ks::dwm_order::runtime;
    unsigned checks = 0, failures = 0;
    void check(bool condition, const char* label)
    {
        ++checks;
        if (!condition) { ++failures; std::cout << "FAIL=" << label << '\n'; }
    }

    struct Fixture
    {
        std::vector<unsigned char> bytes;
        std::uint32_t ntOffset = 0;
        std::uintptr_t base = 0;
        template<class T> T read(std::uint32_t at) const
        {
            T value{};
            if (at <= bytes.size() && sizeof(T) <= bytes.size() - at)
                std::memcpy(&value, bytes.data() + at, sizeof(T));
            return value;
        }
        template<class T> void write(std::uint32_t at, T value)
        { std::memcpy(bytes.data() + at, &value, sizeof(T)); }

        Failure resolve(Resolved& result, Node* node = nullptr) const
        { return ks::dwm_order::runtime::resolve(bytes.data(), bytes.size(), base, result, node); }

        bool load(const wchar_t* path)
        {
            std::ifstream file(std::filesystem::path(path), std::ios::binary | std::ios::ate);
            if (!file || file.tellg() < 0 || file.tellg() > 128 * 1024 * 1024) return false;
            std::vector<unsigned char> raw(static_cast<std::size_t>(file.tellg()));
            file.seekg(0);
            if (!file.read(reinterpret_cast<char*>(raw.data()), static_cast<std::streamsize>(raw.size()))) return false;
            if (raw.size() < sizeof(IMAGE_DOS_HEADER)) return false;
            IMAGE_DOS_HEADER dos{};
            std::memcpy(&dos, raw.data(), sizeof(dos));
            if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0 || dos.e_lfanew > 0x1000
                || static_cast<std::size_t>(dos.e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > raw.size()) return false;
            ntOffset = dos.e_lfanew;
            IMAGE_NT_HEADERS64 nt{};
            std::memcpy(&nt, raw.data() + ntOffset, sizeof(nt));
            if (nt.Signature != IMAGE_NT_SIGNATURE || nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC
                || nt.OptionalHeader.SizeOfImage > 128 * 1024 * 1024
                || nt.OptionalHeader.SizeOfHeaders > raw.size()
                || nt.OptionalHeader.SizeOfHeaders > nt.OptionalHeader.SizeOfImage) return false;
            const auto kSectionAt = ntOffset + sizeof(nt);
            if (kSectionAt + nt.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER) > raw.size()) return false;
            bytes.resize(nt.OptionalHeader.SizeOfImage);
            std::memcpy(bytes.data(), raw.data(), nt.OptionalHeader.SizeOfHeaders);
            base = nt.OptionalHeader.ImageBase;
            for (unsigned i = 0; i < nt.FileHeader.NumberOfSections; ++i)
            {
                const auto kS = read<IMAGE_SECTION_HEADER>(static_cast<std::uint32_t>(kSectionAt + i * sizeof(IMAGE_SECTION_HEADER)));
                if (kS.PointerToRawData > raw.size() || kS.SizeOfRawData > raw.size() - kS.PointerToRawData
                    || kS.VirtualAddress > bytes.size() || kS.SizeOfRawData > bytes.size() - kS.VirtualAddress) return false;
                std::memcpy(bytes.data() + kS.VirtualAddress, raw.data() + kS.PointerToRawData, kS.SizeOfRawData);
            }
            return true;
        }

        std::uint32_t addSection(std::size_t length, DWORD flags)
        {
            auto nt = read<IMAGE_NT_HEADERS64>(ntOffset);
            const auto kHeader = ntOffset + static_cast<std::uint32_t>(sizeof(nt)
                + nt.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
            if (kHeader + sizeof(IMAGE_SECTION_HEADER) > nt.OptionalHeader.SizeOfHeaders) return 0;
            const auto kRva = static_cast<std::uint32_t>((bytes.size() + 0xfff) & ~std::size_t(0xfff));
            bytes.resize((kRva + length + 0xfff) & ~std::size_t(0xfff));
            IMAGE_SECTION_HEADER s{};
            std::memcpy(s.Name, ".fixture", 8);
            s.VirtualAddress = kRva;
            s.Misc.VirtualSize = static_cast<DWORD>(length);
            s.Characteristics = flags;
            write(kHeader, s);
            ++nt.FileHeader.NumberOfSections;
            nt.OptionalHeader.SizeOfImage = static_cast<DWORD>(bytes.size());
            write(ntOffset, nt);
            return kRva;
        }

        std::vector<RUNTIME_FUNCTION> fragments(std::uint32_t root) const
        {
            std::vector<RUNTIME_FUNCTION> parts;
            const auto kNt = read<IMAGE_NT_HEADERS64>(ntOffset);
            const auto kDir = kNt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
            for (unsigned at = 0; at + sizeof(RUNTIME_FUNCTION) <= kDir.Size; at += sizeof(RUNTIME_FUNCTION))
            {
                const auto kF = read<RUNTIME_FUNCTION>(kDir.VirtualAddress + at);
                auto owner = kF;
                for (unsigned depth = 0; depth < 16; ++depth)
                {
                    if (!(read<unsigned char>(owner.UnwindData) & (UNW_FLAG_CHAININFO << 3))) break;
                    const auto kCount = read<unsigned char>(owner.UnwindData + 2);
                    owner = read<RUNTIME_FUNCTION>(owner.UnwindData + 4 + ((kCount + 1u) & ~1u) * 2);
                }
                if (owner.BeginAddress == root) parts.push_back(kF);
            }
            std::stable_sort(parts.begin(), parts.end(), [root](const auto& a, const auto& b) {
                if ((a.BeginAddress == root) != (b.BeginAddress == root)) return a.BeginAddress == root;
                return a.BeginAddress < b.BeginAddress;
            });
            return parts;
        }
    };

    const Pattern* selected(const Fixture& image, const Resolved& result, Node node)
    {
        const auto kStart = result.functions[static_cast<unsigned>(node)];
        const auto* patterns = result.model == 2 ? win10_signatures::kPatterns : signatures::kPatterns;
        const auto kCount = result.model == 2 ? std::size(win10_signatures::kPatterns) : std::size(signatures::kPatterns);
        for (std::size_t at = 0; at < kCount; ++at)
        {
            const auto& p = patterns[at];
            if (p.node != node || kStart + p.length > image.bytes.size()) continue;
            bool match = true;
            for (unsigned i = 0; i < p.length; ++i)
                if ((image.bytes[kStart + i] & p.mask[i]) != p.bytes[i]) { match = false; break; }
            if (match) return &p;
        }
        return nullptr;
    }

    void reject(const Fixture& image, Failure expected, const char* name)
    {
        Resolved result{};
        result.model = 99;
        const auto kStatus = image.resolve(result);
        if (kStatus != expected) std::cout << "REJECTION_STATUS=" << static_cast<unsigned>(kStatus)
            << " EXPECTED=" << static_cast<unsigned>(expected) << '\n';
        check(kStatus == expected, name);
        check(result.model == 0 && result.functions[0] == 0 && result.criticalSection == 0,
            "rejected model never publishes partial callable addresses");
    }

    void regression(const Fixture& image, const Resolved& original)
    {
        const bool kWin10 = original.model == 2;
        check(original.model == 1 || kWin10, "exactly one supported ABI family is selected");
        check(original.layout.dataDwmWindow == 0x18 && original.layout.dataHwnd == 0x28
            && original.layout.dataBand == (kWin10 ? 0x70u : 0x80u)
            && original.layout.dataDesktop == (kWin10 ? 0x78u : 0x88u)
            && original.layout.dataVisual == (kWin10 ? 0x180u : 0x1b8u)
            && original.windowListOffset == (kWin10 ? 0x1e8u : 0x1a8u)
            && original.destroySlot == 1 && original.zOrderSlot == 6
            && original.updateSlot == (kWin10 ? 44u : 47u),
            "resolved layout and hook slots agree with independently reviewed family values");
        auto changed = image;
        auto nt = changed.read<IMAGE_NT_HEADERS64>(changed.ntOffset);
        nt.FileHeader.TimeDateStamp ^= 0x12345678;
        changed.write(changed.ntOffset, nt);
        const auto kDebug = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
        for (unsigned at = 0; at + sizeof(IMAGE_DEBUG_DIRECTORY) <= kDebug.Size; at += sizeof(IMAGE_DEBUG_DIRECTORY))
        {
            const auto kEntry = changed.read<IMAGE_DEBUG_DIRECTORY>(kDebug.VirtualAddress + at);
            if (kEntry.Type == IMAGE_DEBUG_TYPE_CODEVIEW && kEntry.SizeOfData >= 24
                && kEntry.AddressOfRawData + 24 <= changed.bytes.size()) changed.bytes[kEntry.AddressOfRawData + 4] ^= 0x55;
        }
        Resolved result{};
        check(changed.resolve(result) == Failure::kNone && result.vtable == original.vtable,
            "timestamp and PDB GUID drift alone does not block an intact ABI model");

        // Simulate ASLR by applying only PE DIR64 relocations; no image execution.
        changed = image;
        const auto kReloc = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        const std::uint64_t kDelta = 0x170000000ull;
        for (unsigned at = 0; at + sizeof(IMAGE_BASE_RELOCATION) <= kReloc.Size;)
        {
            const auto kBlock = changed.read<IMAGE_BASE_RELOCATION>(kReloc.VirtualAddress + at);
            if (kBlock.SizeOfBlock < 8 || kBlock.SizeOfBlock > kReloc.Size - at) break;
            for (unsigned offset = 8; offset + 2 <= kBlock.SizeOfBlock; offset += 2)
            {
                const auto kEntry = changed.read<WORD>(kReloc.VirtualAddress + at + offset);
                if ((kEntry >> 12) == IMAGE_REL_BASED_DIR64)
                {
                    const auto kRva = kBlock.VirtualAddress + (kEntry & 0xfff);
                    changed.write(kRva, changed.read<std::uint64_t>(kRva) + kDelta);
                }
            }
            at += kBlock.SizeOfBlock;
        }
        changed.base += kDelta;
        check(changed.resolve(result) == Failure::kNone && result.vtable == original.vtable,
            "relocated absolute vtable and GFIDS pointers resolve at a different load base");

        changed = image;
        changed.bytes[0] = 0;
        reject(changed, Failure::kInvalidImage, "invalid PE rejected");
        changed = image;
        changed.bytes.resize(512);
        reject(changed, Failure::kInvalidImage, "truncated mapped image rejected");
        changed = image;
        auto wrong = nt;
        wrong.FileHeader.Machine = IMAGE_FILE_MACHINE_ARM64;
        changed.write(changed.ntOffset, wrong);
        reject(changed, Failure::kInvalidImage, "foreign instruction-set model rejected");

        const auto kOrder = original.functions[static_cast<unsigned>(Node::kZOrder)];
        const auto* pattern = selected(image, original, Node::kZOrder);
        check(pattern != nullptr, "find the resolved ordering signature for negative fixtures");
        if (!pattern) return;
        changed = image;
        changed.bytes[kOrder] = 0xe9;
        reject(changed, Failure::kMissingPattern, "patched entry rejected");

        const auto kSplice = kWin10 ? std::vector<unsigned char>{0x48,0x89,0x41,0x08,0x48,0x89}
            : std::vector<unsigned char>{0x4c,0x89,0x01,0x48,0x89,0x41,0x08,0x49,0x89,0x48,0x08};
        auto begin = image.bytes.begin() + kOrder;
        auto end = begin + pattern->length;
        auto found = std::search(begin, end, std::begin(kSplice), std::end(kSplice));
        check(found != end, "locate native list direction evidence");
        if (found != end)
        {
            changed = image;
            changed.bytes[static_cast<std::size_t>(found - image.bytes.begin()) + (kWin10 ? 3 : 6)] = 0;
            reject(changed, Failure::kMissingPattern, "changed insertion direction rejected");
        }
        const auto kDesktop = kWin10 ? std::vector<unsigned char>{0x48,0x8b,0x42,0x78}
            : std::vector<unsigned char>{0x48,0x8b,0x92,0x88,0x00,0x00,0x00};
        found = std::search(begin, end, std::begin(kDesktop), std::end(kDesktop));
        check(found != end, "locate layout evidence");
        if (found != end)
        {
            changed = image;
            changed.bytes[static_cast<std::size_t>(found - image.bytes.begin()) + 3] += 8;
            reject(changed, Failure::kMissingPattern, "different CWindowData layout cannot reuse old offsets");
        }
        for (unsigned i = 0; i < pattern->referenceCount; ++i)
        {
            const auto& ref = pattern->references[i];
            if (ref.node == Node::kDesktopList || (kWin10 && ref.node == Node::kSyncedData))
            {
                changed = image;
                changed.write(kOrder + ref.displacement, static_cast<std::int32_t>(
                    original.functions[static_cast<unsigned>(Node::FindWindow)] - kOrder - ref.nextInstruction));
                reject(changed, Failure::kReferenceMismatch, "masked rel32 still requires the correct call graph");
            }
            if (ref.binding == Binding::kCriticalSection)
            {
                changed = image;
                changed.write(kOrder + ref.displacement, changed.read<std::int32_t>(kOrder + ref.displacement) + 8);
                reject(changed, Failure::kReferenceMismatch, "lock references must agree across methods");
            }
        }
        if (kWin10)
        {
            const auto kParts = image.fragments(kOrder);
            check(kParts.size() == pattern->fragmentCount + 1u && kParts.size() > 1,
                "Win10 ordering function includes all reviewed hot and cold fragments");
            if (kParts.size() > 1)
            {
                changed = image;
                changed.bytes[kParts[1].BeginAddress] ^= 1;
                reject(changed, Failure::kMissingPattern, "modified cold fragment cannot reuse the hot signature");
                changed = image;
                changed.bytes[kParts[1].UnwindData] = 0;
                reject(changed, Failure::kInvalidFragments, "invalid cold-fragment ownership rejected");
            }
            bool testedBranch = false;
            for (unsigned i = 0; i < pattern->referenceCount; ++i)
            {
                const auto& ref = pattern->references[i];
                if (ref.targetFragment == UINT16_MAX || ref.width != 4) continue;
                changed = image;
                changed.write(kOrder + ref.displacement, static_cast<std::int32_t>(
                    original.functions[static_cast<unsigned>(Node::FindWindow)] - kOrder - ref.nextInstruction));
                reject(changed, Failure::kReferenceMismatch, "masked hot-to-cold branch must retain its exact destination role");
                testedBranch = true;
                break;
            }
            check(testedBranch, "exercise Win10 cross-fragment branch validation");
        }
        changed = image;
        changed.write(original.vtable + original.zOrderSlot * 8, image.base + original.functions[static_cast<unsigned>(Node::FindWindow)]);
        reject(changed, Failure::kInvalidVtable, "vtable replacement rejected");

        changed = image;
        const auto kConfig = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
        const auto kCfg = static_cast<std::uint32_t>(changed.read<std::uint64_t>(kConfig + 128) - image.base);
        const auto kCount = changed.read<std::uint64_t>(kConfig + 136);
        const auto kStride = 4 + ((changed.read<std::uint32_t>(kConfig + 144) >> 28) & 15);
        for (unsigned i = 0; i < kCount; ++i)
            if (changed.read<std::uint32_t>(kCfg + i * kStride) == kOrder && kStride > 4)
                changed.bytes[kCfg + i * kStride + 4] |= 1;
        reject(changed, Failure::kInvalidCfg, "CFG-suppressed virtual method rejected");

        // A second exact byte signature at another valid function start must not
        // silently become the selected target, even before call-graph checking.
        changed = image;
        const auto kDuplicateRole = kWin10 ? Node::FindWindow : Node::kZOrder;
        const auto kDuplicateSource = original.functions[static_cast<unsigned>(kDuplicateRole)];
        const auto* duplicatePattern = selected(image, original, kDuplicateRole);
        check(duplicatePattern != nullptr, "select a reviewed duplicate candidate");
        if (!duplicatePattern) return;
        const auto kCopy = changed.addSection(duplicatePattern->length, IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE);
        const auto kException = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        const auto kFunctions = changed.addSection(kException.Size + sizeof(RUNTIME_FUNCTION), IMAGE_SCN_MEM_READ);
        check(kCopy != 0 && kFunctions != 0, "duplicate fixture has bounded additional sections");
        if (kCopy && kFunctions)
        {
            std::memcpy(changed.bytes.data() + kCopy, image.bytes.data() + kDuplicateSource, duplicatePattern->length);
            std::memcpy(changed.bytes.data() + kFunctions, image.bytes.data() + kException.VirtualAddress, kException.Size);
            const auto kParts = image.fragments(kDuplicateSource);
            RUNTIME_FUNCTION duplicate{kCopy, kCopy + duplicatePattern->length, kWin10 && !kParts.empty() ? kParts[0].UnwindData : 0};
            changed.write(kFunctions + kException.Size, duplicate);
            auto header = changed.read<IMAGE_NT_HEADERS64>(changed.ntOffset);
            header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION] = {kFunctions, kException.Size + sizeof(RUNTIME_FUNCTION)};
            changed.write(changed.ntOffset, header);
            reject(changed, Failure::kAmbiguousPattern, "duplicate executable candidate rejected");
        }
    }
}

int runRuntimeTests(int argc, wchar_t** argv)
{
    using namespace ks::dwm_order::runtime;
    for (int i = 0; i < argc; ++i)
    {
        Fixture image;
        if (!image.load(argv[i])) { check(false, "offline image mapping"); continue; }
        Resolved result{};
        Node node = Node::kCount;
        const auto kFailure = image.resolve(result, &node);
        std::wcout << L"IMAGE=" << argv[i] << L'\n';
        std::cout << "RESOLVE_FAILURE=" << static_cast<unsigned>(kFailure) << " NODE=" << static_cast<unsigned>(node)
            << " MODEL=" << result.model << " FIND_RVA=" << std::hex << result.functions[0]
            << " ZORDER_RVA=" << result.functions[2] << " WINDOW_LIST_OFFSET=" << result.windowListOffset << std::dec
            << " HOOK_SLOTS=" << result.destroySlot << ',' << result.zOrderSlot << ',' << result.updateSlot << '\n';
        check(kFailure == Failure::kNone, "reviewed real Windows image resolves without PDB or fixed RVAs");
        if (kFailure == Failure::kNone) regression(image, result);
    }
    std::cout << "RUNTIME_CHECKS=" << checks << " FAILURES=" << failures << '\n';
    return failures ? 1 : 0;
}
