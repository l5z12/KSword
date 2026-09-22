#include "DumpKernelModuleList.h"

// ============================================================
// DumpKernelModuleList.cpp
// Notes:
// - PsLoadedModuleList is a LIST_ENTRY head; its Flink points to the InLoadOrderLinks field of the
//   first KLDR_DATA_TABLE_ENTRY. Since this field is at structure offset 0, the linked list node
//   address is the structure address itself, requiring no additional CONTAINING_RECORD conversion.
// - The traversal termination condition is returning to the head of the linked list. To prevent malformed or tampered
//   lists from causing infinite loops, two safeguards are implemented: a maximum entry limit and a set of 'visited nodes'.
// ============================================================

#include <QDateTime>

#include <algorithm>
#include <unordered_set>

namespace ks::minidump
{
    namespace
    {
        // kMaxModules: Maximum number of entries produced in a single traversal. Real systems have hundreds of
        // drivers; 4096 is sufficient to cover them, and anything more likely indicates a corrupted linked list.
        constexpr int kMaxModules = 4096;

        // kMaxRejectedInARow: Tolerated count of consecutive validation failures. Occasional unreadable nodes
        // in the middle of the list can be skipped; consecutive failures indicate traversal into non-list data.
        constexpr int kMaxRejectedInARow = 16;

        // kMinImageSize/kMaxImageSize: Reasonable range for image size.
        // The lower bound is one page, and the upper bound is 512 MB—one order of magnitude looser than the largest valid driver image.
        constexpr std::uint32_t kMinImageSize = 0x1000u;
        constexpr std::uint32_t kMaxImageSize = 512u * 1024u * 1024u;

        // kKernelSpaceLowerBound: x64 kernel address lower bound. Driver base addresses must reside in the high half.
        constexpr std::uint64_t kKernelSpaceLowerBound = 0xFFFF800000000000ull;

#pragma pack(push, 8)
        // LdrEntry64: The first half of KLDR_DATA_TABLE_ENTRY required for this module.
        // Shares the same source as KldrDataTableEntry64 used for triage in KernelDumpParser.cpp; here we
        // only declare fields required for traversal to avoid copying a full structure for just a few fields.
        struct LdrEntry64
        {
            std::uint64_t inLoadOrderFlink;  // 0x00: Next node.
            std::uint64_t inLoadOrderBlink;  // 0x08: Previous node.
            std::uint64_t reserved1;         // 0x10。
            std::uint64_t reserved2;         // 0x18。
            std::uint64_t reserved3;         // 0x20。
            std::uint64_t nonPagedDebugInfo; // 0x28。
            std::uint64_t dllBase;           // 0x30: Image base address.
            std::uint64_t entryPoint;        // 0x38: Entry point.
            std::uint32_t sizeOfImage;       // 0x40: Image size.
            std::uint32_t sizePad;           // 0x44。
            std::uint16_t fullDllNameLength;    // 0x48: Full path length in bytes.
            std::uint16_t fullDllNameMaximum;   // 0x4A。
            std::uint32_t fullDllNamePad;       // 0x4C。
            std::uint64_t fullDllNameBuffer;    // 0x50: Address of the full path buffer.
            std::uint16_t baseDllNameLength;    // 0x58: Base DLL name length in bytes.
            std::uint16_t baseDllNameMaximum;   // 0x5A。
            std::uint32_t baseDllNamePad;       // 0x5C。
            std::uint64_t baseDllNameBuffer;    // 0x60: Address of the base name buffer.
            std::uint32_t flags;             // 0x68。
            std::uint16_t loadCount;         // 0x6C。
            std::uint16_t reserved5;         // 0x6E。
            std::uint64_t reserved6;         // 0x70。
            std::uint32_t checkSum;          // 0x78：PE CheckSum。
            std::uint32_t padding1;          // 0x7C。
            std::uint32_t timeDateStamp;     // 0x80: PE timestamp.
            std::uint32_t padding2;          // 0x84。
        };
        static_assert(sizeof(LdrEntry64) == 0x88,
            "KLDR_DATA_TABLE_ENTRY(64) 必须是 0x88 字节");
        static_assert(offsetof(LdrEntry64, dllBase) == 0x30,
            "DllBase 必须位于 0x30");
        static_assert(offsetof(LdrEntry64, sizeOfImage) == 0x40,
            "SizeOfImage 必须位于 0x40");
        static_assert(offsetof(LdrEntry64, baseDllNameBuffer) == 0x60,
            "BaseDllName.Buffer 必须位于 0x60");
#pragma pack(pop)

        // timestampToText purpose: Convert PE timestamp to local time text; return an empty string if the timestamp is 0.
        QString timestampToText(const std::uint32_t timeDateStamp)
        {
            if (timeDateStamp == 0)
            {
                return QString();
            }
            return QDateTime::fromSecsSinceEpoch(static_cast<qint64>(timeDateStamp))
                .toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
        }

        // entryLooksValid purpose: Determines if a read LDR entry resembles a valid driver record.
        // Base address must be page-aligned and in the kernel high half; image size must be within a reasonable range;
        // name length must be a multiple of wide characters. If any condition is not met, the read structure is invalid.
        bool entryLooksValid(const LdrEntry64& entry)
        {
            if (entry.dllBase < kKernelSpaceLowerBound)
            {
                return false;
            }
            if ((entry.dllBase % 0x1000ull) != 0)
            {
                return false;
            }
            if (entry.sizeOfImage < kMinImageSize || entry.sizeOfImage > kMaxImageSize)
            {
                return false;
            }
            if ((entry.baseDllNameLength % sizeof(char16_t)) != 0 ||
                (entry.fullDllNameLength % sizeof(char16_t)) != 0)
            {
                return false;
            }
            if (entry.baseDllNameLength > entry.baseDllNameMaximum ||
                entry.fullDllNameLength > entry.fullDllNameMaximum)
            {
                return false;
            }
            return true;
        }
    }

    KernelModuleScanResult enumerateLoadedDrivers(
        const PageTableWalker& walker,
        const std::uint64_t listHeadAddress,
        std::vector<ModuleEntry>& modulesOut)
    {
        KernelModuleScanResult scan{};
        if (!walker.usable() || listHeadAddress == 0)
        {
            scan.stopReason = QStringLiteral("页表不可用或链表头地址为空");
            return scan;
        }

        // The list head itself is a LIST_ENTRY; Flink points to the first entry.
        std::uint64_t firstNode = 0;
        if (!walker.readPointer(listHeadAddress, &firstNode))
        {
            scan.stopReason = QStringLiteral("链表头所在内存页不在转储中");
            return scan;
        }
        scan.listReadable = true;
        if (firstNode == 0 || firstNode == listHeadAddress)
        {
            scan.stopReason = QStringLiteral("驱动链表为空");
            return scan;
        }

        // existingBases: Set of base addresses for existing entries to avoid duplicate registration with the triage table.
        std::unordered_set<std::uint64_t> existingBases;
        existingBases.reserve(modulesOut.size() * 2 + 16);
        for (const ModuleEntry& moduleEntry : modulesOut)
        {
            existingBases.insert(moduleEntry.base);
        }

        // visited: List nodes already traversed; detects cycles immediately.
        std::unordered_set<std::uint64_t> visited;
        visited.reserve(1024);

        std::uint64_t node = firstNode;
        int rejectedInARow = 0;
        while (node != 0 && node != listHeadAddress)
        {
            if (scan.acceptedCount >= kMaxModules)
            {
                scan.truncated = true;
                scan.stopReason = QStringLiteral("达到条目上限 %1，剩余部分未展开")
                    .arg(kMaxModules);
                break;
            }
            if (!visited.insert(node).second)
            {
                scan.truncated = true;
                scan.stopReason = QStringLiteral("驱动链表出现环，已在重复节点处停止");
                break;
            }

            LdrEntry64 entry{};
            if (!walker.readVirtual(node, sizeof(entry), &entry))
            {
                // Node's page not paged out: Kernel dumps skip large amounts of paged memory, which is expected missing data.
                scan.truncated = true;
                scan.stopReason = QStringLiteral("链表在第 %1 项处进入未落盘内存")
                    .arg(scan.acceptedCount + 1);
                break;
            }

            if (!entryLooksValid(entry))
            {
                ++scan.rejectedCount;
                ++rejectedInARow;
                if (rejectedInARow >= kMaxRejectedInARow)
                {
                    scan.truncated = true;
                    scan.stopReason = QStringLiteral("连续 %1 项结构校验失败，已停止遍历")
                        .arg(kMaxRejectedInARow);
                    break;
                }
                node = entry.inLoadOrderFlink;
                continue;
            }
            rejectedInARow = 0;

            // Prefer BaseDllName; fall back to FullDllName if reading fails.
            QString baseName = walker.readUnicodeString(
                entry.baseDllNameBuffer, entry.baseDllNameLength);
            QString fullName = walker.readUnicodeString(
                entry.fullDllNameBuffer, entry.fullDllNameLength);
            if (baseName.isEmpty() && fullName.isEmpty())
            {
                // The structure itself is valid, but the name buffer was not written to disk: still register it, using the base
                // address as a placeholder, because the address range is valuable for attribution; only the readable name is missing.
                baseName = QStringLiteral("(未落盘名称) 0x%1")
                    .arg(QString::number(entry.dllBase, 16).toUpper());
            }

            if (existingBases.insert(entry.dllBase).second)
            {
                ModuleEntry moduleEntry{};
                moduleEntry.name = !fullName.isEmpty() ? fullName : baseName;
                moduleEntry.base = entry.dllBase;
                moduleEntry.size = entry.sizeOfImage;
                moduleEntry.checksum = entry.checkSum;
                moduleEntry.timeDateStamp = entry.timeDateStamp;
                moduleEntry.timestampText = timestampToText(entry.timeDateStamp);
                modulesOut.push_back(std::move(moduleEntry));
                ++scan.acceptedCount;
            }

            node = entry.inLoadOrderFlink;
        }

        return scan;
    }
}
