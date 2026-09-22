#include "DdmaScratchPlan.h"

#include <algorithm>

// ============================================================
// DdmaScratchPlan.cpp
// Purpose: Calculate unallocated gaps from the partition table and rank candidates based on 'who would live there'.
// ============================================================

namespace ksword::evidence
{
    namespace
    {
        // mergeOccupied: Sorts occupied ranges and merges overlapping or adjacent parts.
        // Without merging, overlapping partitions (or duplicate reports) would calculate a bunch of negative-length fake gaps.
        std::vector<DdmaScratchOccupiedRange> mergeOccupied(
            const std::vector<DdmaScratchOccupiedRange>& occupied,
            const std::uint64_t diskSectorCount)
        {
            std::vector<DdmaScratchOccupiedRange> ranges;
            ranges.reserve(occupied.size());
            for (const DdmaScratchOccupiedRange& range : occupied)
            {
                if (range.sectorCount == 0ULL || range.startSector >= diskSectorCount)
                {
                    continue;
                }
                DdmaScratchOccupiedRange clamped = range;
                // Truncate at the disk end if the interval end exceeds the disk; check for overflow before adding.
                const std::uint64_t kAvailable = diskSectorCount - clamped.startSector;
                if (clamped.sectorCount > kAvailable)
                {
                    clamped.sectorCount = kAvailable;
                }
                ranges.push_back(clamped);
            }

            std::sort(
                ranges.begin(),
                ranges.end(),
                [](const DdmaScratchOccupiedRange& left, const DdmaScratchOccupiedRange& right) {
                    if (left.startSector != right.startSector)
                    {
                        return left.startSector < right.startSector;
                    }
                    return left.sectorCount < right.sectorCount;
                });

            std::vector<DdmaScratchOccupiedRange> merged;
            for (const DdmaScratchOccupiedRange& range : ranges)
            {
                if (merged.empty())
                {
                    merged.push_back(range);
                    continue;
                }
                DdmaScratchOccupiedRange& last = merged.back();
                const std::uint64_t kLastEnd = last.startSector + last.sectorCount;
                if (range.startSector <= kLastEnd)
                {
                    const std::uint64_t kRangeEnd = range.startSector + range.sectorCount;
                    if (kRangeEnd > kLastEnd)
                    {
                        last.sectorCount = kRangeEnd - last.startSector;
                    }
                    continue;
                }
                merged.push_back(range);
            }
            return merged;
        }

        // alignUp: Aligns the start address upward to the transfer granularity so that a single DMA operation falls on an aligned boundary.
        std::uint64_t alignUp(const std::uint64_t value, const std::uint64_t alignment)
        {
            if (alignment <= 1ULL)
            {
                return value;
            }
            const std::uint64_t kRemainder = value % alignment;
            if (kRemainder == 0ULL)
            {
                return value;
            }
            // Overflow protection: if alignment causes the value to exceed the 64-bit limit, return the original value and let subsequent availability checks reject it.
            const std::uint64_t kDelta = alignment - kRemainder;
            if (value > (UINT64_MAX - kDelta))
            {
                return value;
            }
            return value + kDelta;
        }

        // classifyGap: Classify based on the relationship between the gap and the head/tail reserved regions.
        DdmaScratchRisk classifyGap(
            const std::uint64_t gapStart,
            const std::uint64_t gapEnd,          // Half-open interval end.
            const std::uint64_t headReservedEnd,
            const std::uint64_t tailReservedStart,
            const bool isTailGap)
        {
            if (gapStart < headReservedEnd)
            {
                // Intersection with the head reserved region: the bootloader is embedded in this segment.
                return DdmaScratchRisk::kHeadReserved;
            }
            if (gapEnd > tailReservedStart)
            {
                // Intersects with the backup partition table: overwriting it would cause the partition table to lose redundancy.
                return DdmaScratchRisk::kTailReserved;
            }
            return isTailGap ? DdmaScratchRisk::kTailGap : DdmaScratchRisk::kInteriorGap;
        }
    }

    bool ddmaScratchRiskIsSelectable(const DdmaScratchRisk risk)
    {
        return risk == DdmaScratchRisk::kInteriorGap || risk == DdmaScratchRisk::kTailGap;
    }

    std::vector<DdmaScratchCandidate> planDdmaScratchCandidates(
        const std::uint64_t diskSectorCount,
        const std::vector<DdmaScratchOccupiedRange>& occupied,
        const std::uint32_t requiredSectors)
    {
        std::vector<DdmaScratchCandidate> candidates;
        if (diskSectorCount == 0ULL || requiredSectors == 0UL)
        {
            return candidates;
        }

        const std::uint64_t kRequired = static_cast<std::uint64_t>(requiredSectors);
        const std::uint64_t kHeadReservedEnd =
            std::min<std::uint64_t>(kDdmaScratchHeadReservedSectors, diskSectorCount);
        const std::uint64_t kTailReservedStart =
            (diskSectorCount > kDdmaScratchTailReservedSectors)
                ? (diskSectorCount - kDdmaScratchTailReservedSectors)
                : 0ULL;

        const std::vector<DdmaScratchOccupiedRange> kMerged =
            mergeOccupied(occupied, diskSectorCount);

        // Compute the complement: gaps between each occupied range, plus the gap after the last one up to the end of the disk.
        std::uint64_t cursor = 0ULL;
        std::vector<std::pair<std::uint64_t, std::uint64_t>> gaps; // (start, end) half-open
        for (const DdmaScratchOccupiedRange& range : kMerged)
        {
            if (range.startSector > cursor)
            {
                gaps.emplace_back(cursor, range.startSector);
            }
            const std::uint64_t kEnd = range.startSector + range.sectorCount;
            if (kEnd > cursor)
            {
                cursor = kEnd;
            }
        }
        const bool kHasTailGap = (cursor < diskSectorCount);
        if (kHasTailGap)
        {
            gaps.emplace_back(cursor, diskSectorCount);
        }

        for (std::size_t index = 0U; index < gaps.size(); ++index)
        {
            const std::uint64_t kGapStart = gaps[index].first;
            const std::uint64_t kGapEnd = gaps[index].second;
            const bool kIsTailGap = kHasTailGap && (index + 1U == gaps.size());

            DdmaScratchCandidate candidate;
            candidate.gapStartSector = kGapStart;
            candidate.gapSectorCount = kGapEnd - kGapStart;
            candidate.risk =
                classifyGap(kGapStart, kGapEnd, kHeadReservedEnd, kTailReservedStart, kIsTailGap);

            // Align the start upward to the transfer granularity; alignment consumes a few sectors at the beginning
            // of the gap, so availability must be re-checked after alignment, not using the original gap length.
            const std::uint64_t kAlignedStart = alignUp(kGapStart, kRequired);
            candidate.startSector = kAlignedStart;
            candidate.sectorCount =
                (kAlignedStart < kGapEnd) ? (kGapEnd - kAlignedStart) : 0ULL;

            // Condition for availability: After alignment, a full transfer fits, and the entire range does not intersect with the tail reserved region.
            // Candidates intersecting the head are still marked as usable—they are usable, just risky; marking them
            // as unusable would leave machines with 'only this one candidate' unable to explain the reason in the UI.
            const bool kFits = (candidate.sectorCount >= kRequired);
            const bool kClearsTail =
                (kAlignedStart + kRequired) <= kTailReservedStart || kTailReservedStart == 0ULL;
            candidate.usable =
                kFits && kClearsTail && candidate.risk != DdmaScratchRisk::kTailReserved;

            candidates.push_back(candidate);
        }

        std::sort(
            candidates.begin(),
            candidates.end(),
            [](const DdmaScratchCandidate& left, const DdmaScratchCandidate& right) {
                // Sort available entries before unavailable ones, then by increasing risk, then by decreasing gap size;
                // Finally sort by LBA ascending to ensure the same preferred disk is selected each time for the same drive.
                if (left.usable != right.usable)
                {
                    return left.usable;
                }
                if (left.risk != right.risk)
                {
                    return static_cast<int>(left.risk) < static_cast<int>(right.risk);
                }
                if (left.sectorCount != right.sectorCount)
                {
                    return left.sectorCount > right.sectorCount;
                }
                return left.startSector < right.startSector;
            });

        return candidates;
    }
}
