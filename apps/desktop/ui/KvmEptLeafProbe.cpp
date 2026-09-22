#include "KvmEptLeafProbe.h"

#include "KvmControl.h"

#include "../internationalization/LanguageManager.h"

#include <QByteArray>

namespace ks::ui
{
    namespace
    {
        // Physical frame field in the EPT entry. The lower 12 bits are for permissions/memory type/AD, etc.; the upper bits are reserved.
        constexpr quint64 kFrameMask = 0x000FFFFFFFFFF000ULL;
        // Large page frame masks: 2 MiB alignment in PD, 1 GiB alignment in PDPT.
        constexpr quint64 kFrameMask2Mib = 0x000FFFFFFFE00000ULL;
        constexpr quint64 kFrameMask1Gib = 0x000FFFFFC0000000ULL;

        constexpr quint64 kAccessRead = 0x1ULL;
        constexpr quint64 kAccessWrite = 0x2ULL;
        constexpr quint64 kAccessExecute = 0x4ULL;
        constexpr quint64 kIgnorePat = 0x40ULL;
        constexpr quint64 kLargePage = 0x80ULL;
        constexpr quint64 kSuppressVe = 0x8000000000000000ULL;

        constexpr int kLevelCount = 4;
        // A 4-level EPT translates only 48-bit guest physical addresses; bits beyond that do not
        // participate in table indexing at all. Without this check, an out-of-bounds address would be
        // silently truncated to read from another page — precisely the error this check must prevent.
        constexpr quint64 kAddressLimit = 0x0001000000000000ULL;

        // levelIndex: Slot index within the table for the level-th level.
        // PML4 takes bits 47..39, PDPT takes 38..30, PD takes 29..21, PT takes 20..12.
        quint32 levelIndex(const quint64 address, const int level)
        {
            const int kShift = 39 - (level * 9);
            return static_cast<quint32>((address >> kShift) & 0x1FFULL);
        }

        // decodeLittleEndian: Assembles the 8-byte value returned by the driver.
        // The driver returns physical memory as-is; since x86 is little-endian, reconstruct from high bytes downward.
        quint64 decodeLittleEndian(const QByteArray& payload)
        {
            quint64 value = 0;
            for (int index = 7; index >= 0; --index)
            {
                value = (value << 8) |
                    static_cast<quint64>(
                        static_cast<unsigned char>(payload.at(index)));
            }
            return value;
        }

        // fillAccessBits: maps the three permission bits from the leaf entry's associated field onto the record.
        void fillAccessBits(EptLeafEntryRecord& record)
        {
            record.readable = (record.entry & kAccessRead) != 0ULL;
            record.writable = (record.entry & kAccessWrite) != 0ULL;
            record.executable = (record.entry & kAccessExecute) != 0ULL;
        }
    }

    QString eptLeafLevelName(const int level)
    {
        switch (level)
        {
        case 0:
            return QStringLiteral("PML4");
        case 1:
            return QStringLiteral("PDPT");
        case 2:
            return QStringLiteral("PD");
        case 3:
            return QStringLiteral("PT");
        default:
            break;
        }
        return QStringLiteral("?");
    }

    EptLeafProbeResult readBaseEptLeaf(const quint64 targetGpa)
    {
        EptLeafProbeResult result;
        result.targetGpa = targetGpa;
        result.pageBaseGpa = targetGpa & kFrameMask;

        if (targetGpa >= kAddressLimit)
        {
            result.message = ks::i18n::sourceText(QStringLiteral("目标地址超出四级 EPT 能翻译的 48 位客户机物理地址范围，走表会静默落到另一页上，因此直接拒绝。"));
            return result;
        }

        // The root address and both blind-spot markers come from the same snapshot to prevent the backend from being swapped out between two queries.
        const auto kState = ksword::kvm::queryState();
        result.eptPointer = kState.eptPointer;
        result.localEptArmed = kState.localEptArmed;
        result.eptpSwitchArmed = kState.eptpSwitchArmed;

        if (kState.eptPointer == 0ULL)
        {
            // No root means no table to traverse. However, "why there is no root" falls into two categories with completely different
            // user actions: either the machine lacks the prerequisites (switch machines, modify firmware, disable VBS), or it simply
            // needs one-time preparation. Merging these into "read failure" would misdirect users to the wrong debugging path.
            switch (kState.availability)
            {
            case ksword::kvm::KvmAvailability::kDriverNotRunning:
            case ksword::kvm::KvmAvailability::kUnsupportedCpu:
            case ksword::kvm::KvmAvailability::kFirmwareDisabled:
            case ksword::kvm::KvmAvailability::kHypervisorConflict:
            case ksword::kvm::KvmAvailability::kBackendNotImplemented:
            case ksword::kvm::KvmAvailability::kNestedNotAllowed:
            case ksword::kvm::KvmAvailability::kFaulted:
                result.message = ksword::kvm::describeAvailability(
                    kState.availability);
                break;
            case ksword::kvm::KvmAvailability::kAvailable:
            case ksword::kvm::KvmAvailability::kNotPrepared:
            default:
                result.message = kState.resourcesReady
                    ? ks::i18n::sourceText(QStringLiteral("驱动已准备资源但尚未建立 EPT 层次（eptPointer 为零），没有可以走的表。"))
                    : ks::i18n::sourceText(QStringLiteral("驱动尚未准备资源（eptPointer 为零），没有可以走的表。先准备资源再回读。"));
                break;
            }
            return result;
        }

        // Extract only the root address: the lower 12 bits represent memory type, page table walk level, and AD enablement, not physical bits.
        result.eptRoot = kState.eptPointer & kFrameMask;

        quint64 tableBase = result.eptRoot;
        for (int level = 0; level < kLevelCount; ++level)
        {
            EptLeafEntryRecord& record = result.levels[level];
            record.index = levelIndex(result.pageBaseGpa, level);
            record.tableBase = tableBase;
            record.entryAddress =
                tableBase + (static_cast<quint64>(record.index) * 8ULL);
            result.walkedLevels = level + 1;

            const auto kMemory = ksword::kvm::readPhysical(
                record.entryAddress,
                8UL);
            if (!kMemory.ok || kMemory.data.size() < 8)
            {
                record.failure = kMemory.message.isEmpty()
                    ? ks::i18n::sourceText(QStringLiteral("读取该页表项失败。"))
                    : kMemory.message;
                result.message = ks::i18n::sourceText(QStringLiteral("走到 %1 级时读取页表项失败：%2"))
                    .arg(eptLeafLevelName(level))
                    .arg(record.failure);
                return result;
            }

            record.read = true;
            record.entry = decodeLittleEndian(kMemory.data);
            fillAccessBits(record);
            record.largePage = level >= 1 && level <= 2 &&
                (record.entry & kLargePage) != 0ULL;

            // A zero entry indicates no mapping at this level; reading further down will retrieve unrelated data.
            if (record.entry == 0ULL)
            {
                result.ok = true;
                result.unmapped = true;
                result.message = ks::i18n::sourceText(QStringLiteral("这一页在基座 EPT 层次里没有映射：%1 级的项为零，走表到此为止。"))
                    .arg(eptLeafLevelName(level));
                return result;
            }

            // Large pages are marked with bit7 in PD/PDPT; a hit indicates this level is already a leaf.
            if (record.largePage)
            {
                result.ok = true;
                result.reachedLeaf = true;
                result.largePage = true;
                result.leafLevel = level;
                result.leafEntry = record.entry;
                result.leafFrameAddress = record.entry &
                    (level == 1 ? kFrameMask1Gib : kFrameMask2Mib);
                break;
            }

            if (level == kLevelCount - 1)
            {
                result.ok = true;
                result.reachedLeaf = true;
                result.leafLevel = level;
                result.leafEntry = record.entry;
                result.leafFrameAddress = record.entry & kFrameMask;
                break;
            }

            tableBase = record.entry & kFrameMask;
        }

        if (!result.reachedLeaf)
        {
            // Traversing all four levels without identifying a leaf indicates a missing shape in the upper branches. It is better
            // to state this explicitly than to let the caller infer 'no page permission' from a default all-zero conclusion.
            result.message = ks::i18n::sourceText(QStringLiteral("走满四级仍未认定叶项，读回的层次形状超出本探针的预期。"));
            result.ok = false;
            return result;
        }

        result.readable = (result.leafEntry & kAccessRead) != 0ULL;
        result.writable = (result.leafEntry & kAccessWrite) != 0ULL;
        result.executable = (result.leafEntry & kAccessExecute) != 0ULL;
        result.memoryType =
            static_cast<quint32>((result.leafEntry >> 3) & 0x7ULL);
        result.ignorePat = (result.leafEntry & kIgnorePat) != 0ULL;
        result.suppressVe = (result.leafEntry & kSuppressVe) != 0ULL;

        result.message = result.largePage
            ? ks::i18n::sourceText(QStringLiteral("叶落在 %1 级的大页上：这一项管的是整段范围而不止目标这一页。"))
                .arg(eptLeafLevelName(result.leafLevel))
            : ks::i18n::sourceText(QStringLiteral("已读回基座 EPT 层次里这一页的叶项。"));
        return result;
    }
}
