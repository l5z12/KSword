// ============================================================
// DumpSymbolIndex.cpp
// Purpose:
// - Implements the module interval index and address property determination declared in DumpSymbolIndex.h.
// - The interval table is sorted by base address in ascending order; upper_bound locates candidates, which are then validated to fall
//   within [base, end). For overlapping intervals (where addresses of unloaded modules are reused), the loaded module is returned first.
// - Sentinel value table covers common fill patterns in MSVC debug runtime, Windows heap debugging,
//   driver verifier, and kernel pool; a hit is a strong signal of 'uninitialized / use-after-free'.
// ============================================================

#include "DumpSymbolIndex.h"

#include <algorithm>

namespace ks::minidump
{
    namespace
    {
        // kUserSpaceLimit64: Upper bound for x64 user-mode addresses (lower half of canonical addresses).
        constexpr std::uint64_t kUserSpaceLimit64 = 0x0000800000000000ull;
        // kKernelSpaceStart64: x64 kernel address lower bound (canonical high half).
        constexpr std::uint64_t kKernelSpaceStart64 = 0xFFFF800000000000ull;
        // kKernelSpaceStart32: Lower bound of x86 kernel address space (default 2GB boundary).
        constexpr std::uint64_t kKernelSpaceStart32 = 0x0000000080000000ull;
        // kNullPageLimit: CPU-reserved NULL page range; hitting it indicates a null pointer dereference.
        constexpr std::uint64_t kNullPageLimit = 0x10000ull;

        // PoisonPair: A sentinel value and its meaning.
        struct PoisonPair
        {
            std::uint32_t value; // value: 32-bit mode; 64-bit mode matches by repeating high and low bits.
            const char* meaning; // meaning: Chinese meaning (UTF-8).
        };

        // kPoisonValues: Official fill values for MSVC debug runtime and Windows debug heap.
        // A match indicates the value is not a valid pointer but a marker written by the
        // allocator/compiler; this directly classifies the issue as 'uninitialized' or 'use-after-free'.
        // Only include fill values with a clear source; arbitrarily adding values based on memory would
        // cause 'suspected sentinel' false positives on actually valid addresses, which is harmful.
        constexpr PoisonPair kPoisonValues[] = {
            { 0xCCCCCCCCu, "未初始化的栈内存（MSVC /RTC 调试填充）" },
            { 0xCDCDCDCDu, "未初始化的堆内存（MSVC 调试堆新分配填充）" },
            { 0xDDDDDDDDu, "已释放的堆内存（MSVC 调试堆释放填充），典型释放后使用" },
            { 0xFDFDFDFDu, "堆块守卫区（MSVC 调试堆 no-man's-land），典型越界读写" },
            { 0xABABABABu, "HeapAlloc 分配块尾部守卫区（Windows 调试堆）" },
            { 0xBAADF00Du, "LocalAlloc/HeapAlloc 未初始化内存（Windows 调试堆填充）" },
            { 0xFEEEFEEEu, "HeapFree 已释放内存（Windows 调试堆填充），典型释放后使用" },
            { 0xDEADBEEFu, "人为哨兵值（常见于驱动/内核代码的显式标记）" },
        };
    }

    QString baseModuleName(const QString& path)
    {
        if (path.isEmpty())
        {
            return QString();
        }
        // separator: Position of the last separator in the path; consider both separator types.
        const qsizetype kSeparator = std::max(
            path.lastIndexOf(QLatin1Char('\\')),
            path.lastIndexOf(QLatin1Char('/')));
        return kSeparator >= 0 ? path.mid(kSeparator + 1) : path;
    }

    AddressKind classifyAddress(const std::uint64_t address, const std::uint32_t pointerSize)
    {
        if (address < kNullPageLimit)
        {
            // The entire NULL-page range cannot be mapped: 0 is a bare null pointer, while small offsets
            // represent a null pointer plus a structure-member offset. Both have the same root cause.
            return AddressKind::kNullPage;
        }
        if (pointerSize == 4)
        {
            return address >= kKernelSpaceStart32
                ? AddressKind::kKernelSpace
                : AddressKind::kUserSpace;
        }
        if (address >= kKernelSpaceStart64)
        {
            return AddressKind::kKernelSpace;
        }
        if (address < kUserSpaceLimit64)
        {
            return AddressKind::kUserSpace;
        }
        // Falls within a non-canonical address hole in x64: not a valid virtual address, typically data being used as a pointer.
        return AddressKind::kUnknown;
    }

    QString addressKindText(const AddressKind kind)
    {
        switch (kind)
        {
        case AddressKind::kNullPage:
            // This text is used in contexts like registers and stop code parameters where the value is not necessarily an
            // address; therefore, one cannot directly assert it is a null pointer—registers commonly hold values like 1 or 0x100.
            // Cases where the address is definitively determined (e.g., the faulting address in an access violation) are provided separately by the caller.
            return QStringLiteral("落在 NULL 页范围（作计数/标志更常见；若确为地址则是空指针加偏移）");
        case AddressKind::kUserSpace:
            return QStringLiteral("用户态地址区间");
        case AddressKind::kKernelSpace:
            return QStringLiteral("内核地址区间");
        case AddressKind::kPoison:
            return QStringLiteral("分配器哨兵值");
        default:
            return QString();
        }
    }

    QString poisonValueText(const std::uint64_t value, const std::uint32_t pointerSize)
    {
        // low/high: In 64-bit contexts, sentinels often repeat across both halves (e.g., 0xCCCCCCCCCCCCCCCC).
        const std::uint32_t kLow = static_cast<std::uint32_t>(value & 0xFFFFFFFFull);
        const std::uint32_t kHigh = static_cast<std::uint32_t>(value >> 32);
        for (const PoisonPair& pair : kPoisonValues)
        {
            if (kLow != pair.value)
            {
                continue;
            }
            // For 32-bit targets, only the low half is checked; for 64-bit targets, the high half must also be
            // the same sentinel or 0, otherwise normal addresses like 0x00007FFCCCCCCCCC would be misidentified.
            if (pointerSize == 4 || kHigh == pair.value || kHigh == 0)
            {
                return QString::fromUtf8(pair.meaning);
            }
        }
        // All Fs are common 'invalid' markers for page table entries or invalid handles; list as a single entry.
        if (value == 0xFFFFFFFFFFFFFFFFull || (pointerSize == 4 && kLow == 0xFFFFFFFFu))
        {
            return QStringLiteral("全 1 无效值（常见于未设置或已失效的指针/句柄）");
        }
        return QString();
    }

    void ModuleIndex::build(
        const std::vector<ModuleEntry>& modules,
        const std::vector<UnloadedModuleEntry>& unloaded,
        const std::uint32_t pointerSize)
    {
        pointerSize_ = pointerSize == 4 ? 4u : 8u;
        ranges_.clear();
        ranges_.reserve(modules.size() + unloaded.size());

        for (const ModuleEntry& module : modules)
        {
            // Modules with size 0 cannot form an interval; skip to avoid zero-width hits.
            if (module.base == 0 || module.size == 0)
            {
                continue;
            }
            Range range{};
            range.base = module.base;
            range.end = module.base + module.size;
            range.name = baseModuleName(module.name);
            range.unloaded = false;
            ranges_.push_back(std::move(range));
        }
        for (const UnloadedModuleEntry& module : unloaded)
        {
            // The kernel unloaded driver table provides the end address directly; user-mode streams only provide size.
            const std::uint64_t kEnd = module.endAddress != 0
                ? module.endAddress
                : module.base + module.size;
            if (module.base == 0 || kEnd <= module.base)
            {
                continue;
            }
            Range range{};
            range.base = module.base;
            range.end = kEnd;
            range.name = baseModuleName(module.name);
            range.unloaded = true;
            ranges_.push_back(std::move(range));
        }

        // Sort key: ascending base address; for the same base address, sort by name to ensure reproducible results.
        // 「Loaded Priority First」cannot be achieved by sorting alone—lookups traverse backwards from upper_bound,
        // so items sorted earlier appear later during backtracking. Priority is handled uniformly in resolve().
        std::sort(
            ranges_.begin(),
            ranges_.end(),
            [](const Range& left, const Range& right)
            {
                if (left.base != right.base)
                {
                    return left.base < right.base;
                }
                return left.name < right.name;
            });
    }

    AddressNote ModuleIndex::resolve(const std::uint64_t address) const
    {
        AddressNote note{};
        note.kind = classifyAddress(address, pointerSize_);

        // Sentinel values take precedence over range classification: 0xCCCCCCCCCCCCCCCC would be classified
        // as an invalid address, but the valuable information is 'this is uninitialized memory'.
        const QString kPoison = poisonValueText(address, pointerSize_);
        if (!kPoison.isEmpty())
        {
            note.kind = AddressKind::kPoison;
            note.description = kPoison;
            return note;
        }

        // upper_bound finds the first interval where base > address; candidates are all before it.
        // Do not rely solely on the immediately preceding entry: module ranges may overlap (addresses of unloaded drivers reused by new drivers, or malformed
        // dumps containing nested ranges). In such cases, the range covering the target address is not necessarily the one with the largest base address.
        // Therefore, backtrack several entries, with **loaded modules taking precedence over unloaded modules**:
        // when an address falls within both an active module and a historical interval of an old module, the
        // active one is clearly the one executing; reporting the old one would lead to an unrelated driver.
        const auto kPosition = std::upper_bound(
            ranges_.begin(),
            ranges_.end(),
            address,
            [](const std::uint64_t value, const Range& range) { return value < range.base; });
        // kProbeDepth: Backtrace limit to prevent degeneration into linear scan due to excessive overlapping intervals in malformed dumps.
        constexpr int kProbeDepth = 8;
        const Range* loadedHit = nullptr;   // loadedHit: Hit loaded module.
        const Range* unloadedHit = nullptr; // unloadedHit: Hit on an unloaded module (secondary choice).
        auto candidate = kPosition;
        for (int step = 0; step < kProbeDepth && candidate != ranges_.begin(); ++step)
        {
            --candidate;
            if (address < candidate->base || address >= candidate->end)
            {
                continue;
            }
            if (candidate->unloaded)
            {
                if (unloadedHit == nullptr)
                {
                    unloadedHit = &(*candidate);
                }
            }
            else
            {
                loadedHit = &(*candidate);
                break;
            }
        }
        const Range* const kHit = loadedHit != nullptr ? loadedHit : unloadedHit;
        if (kHit != nullptr)
        {
            note.moduleName = kHit->name;
            note.moduleBase = kHit->base;
            note.offset = address - kHit->base;
            note.unloadedModule = kHit->unloaded;
            note.symbolText = QStringLiteral("%1+0x%2")
                .arg(kHit->name)
                .arg(QString::number(note.offset, 16).toUpper());
        }

        if (note.description.isEmpty())
        {
            note.description = addressKindText(note.kind);
        }
        return note;
    }

    QString ModuleIndex::symbolText(const std::uint64_t address) const
    {
        return resolve(address).symbolText;
    }

    QString ModuleIndex::annotate(const std::uint64_t address) const
    {
        const AddressNote kNote = resolve(address);
        if (!kNote.symbolText.isEmpty())
        {
            return kNote.unloadedModule
                ? QStringLiteral("%1（已卸载模块，高度可疑）").arg(kNote.symbolText)
                : kNote.symbolText;
        }
        // Values smaller than a page size are mostly counters, flags, or enumerations, not addresses.
        // Attaching a 'NULL page' annotation to them only creates noise in the register and parameter tables; true null pointer
        // scenarios are determined and explained separately by the caller (e.g., via the faulting address of an access violation).
        if (kNote.kind == AddressKind::kNullPage && address < 0x1000ull)
        {
            return QString();
        }
        return kNote.description;
    }
}
