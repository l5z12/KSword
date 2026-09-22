#pragma once

// ============================================================
// DdmaScratchPlan.h
// Purpose:
// - Calculate candidate intervals for DDMA scratch sectors from the disk partition table and assign risk levels.
//
// Why this module is needed:
// - DDMA must borrow a disk sector as a transit buffer, and determining "which sector can be temporarily overwritten" is a problem where **a single
//   calculation error destroys data**. Hard-coding the LBA to the user is equivalent to requiring every user to read the partition table themselves;
//   Automatically picking one hides responsibility. The role here is to **compute candidates and attach
//   evidence**, with final confirmation by the user—criteria are visible, and responsibility is not transferred.
//
// Key facts (determine the classification method):
// - A partition table reporting "unallocated" does not mean "nothing is there". The gap at the **head** of the
//   disk is exactly where bootloaders reside: on MBR disks, GRUB embeds the core image directly in LBA 1..2047
//   without any partition table entries; on GPT disks, the same segment is an aligned gap that may also be
//   occupied by tools. Therefore, the head gap must be graded separately and never used as the primary choice.
// - The last several sectors at the disk tail contain the GPT backup header and backup partition table;
//   overwriting them compromises partition table redundancy, so the entire segment must be excluded.
// - Gaps between partitions and after the last partition have no structural residents, making them relatively safe candidates.
//
// This file is pure arithmetic: it does not touch Qt, Win32, or perform any I/O. Reading the partition table and sector
// contents is handled by the caller; evidence such as whether the content is all zeros is passed in as parameters.
// ============================================================

#include <cstdint>
#include <vector>

namespace ksword::evidence
{
    // DdmaScratchOccupiedRange: A sector range that is already occupied (typically a partition).
    struct DdmaScratchOccupiedRange
    {
        std::uint64_t startSector = 0;
        std::uint64_t sectorCount = 0;
    };

    // DdmaScratchRisk: Risk classification for candidate intervals.
    enum class DdmaScratchRisk : int
    {
        // InteriorGap: unallocated gap between two partitions. No structural residents; highest priority.
        kInteriorGap = 0,
        // TailGap: Unallocated space after the last partition and before the backup partition table. It also has no structural
        // occupants; it is placed after InteriorGap only because some tools habitually append data to the end of the disk.
        kTailGap,
        // HeadReserved: Intersects with the disk header reserved area. The bootloader is embedded in this region.
        // **Never selected as the primary choice**; only listed with a prominent alert when no other candidates exist.
        kHeadReserved,
        // TailReserved: Intersects with the backup partition table and is directly unavailable.
        kTailReserved
    };

    // DdmaScratchCandidate: A candidate scratch region.
    struct DdmaScratchCandidate
    {
        std::uint64_t startSector = 0;  // Suggested starting LBA, already aligned to transfer granularity.
        std::uint64_t sectorCount = 0;  // Number of available sectors in this gap (not the quantity to be used in this operation).
        std::uint64_t gapStartSector = 0; // The original start of the gap it belongs to, for evidence display in the UI.
        std::uint64_t gapSectorCount = 0; // Original length of the associated gap.
        DdmaScratchRisk risk = DdmaScratchRisk::kHeadReserved;
        bool usable = false;            // Whether a transfer can fit without landing in an unusable region.
    };

    // kDdmaScratchHeadReservedSectors：
    // - Length of the disk header reserved area. Set to 2048 sectors (1 MiB): Windows aligns the first
    //   partition to 2048 sectors to reserve this space, where the GRUB embedded area on MBR disks resides.
    inline constexpr std::uint64_t kDdmaScratchHeadReservedSectors = 2048ULL;

    // kDdmaScratchTailReservedSectors：
    // - Reserved space at the disk end: the GPT backup header uses the last 1 sector and its
    //   partition table uses the preceding 32, totaling 33. Reserve 64 here to leave a margin.
    inline constexpr std::uint64_t kDdmaScratchTailReservedSectors = 64ULL;

    // planDdmaScratchCandidates：
    // - Input: Total disk sector count, occupied ranges (order arbitrary, overlaps allowed), and sectors required per transfer;
    // - Processing: Merge occupied ranges, compute the complement to find gaps, align start points to transfer granularity, then grade and sort.
    // - Returns: Candidates sorted by "risk from low to high, then by gap size from large to small, then by LBA from small to large".
    //   Gaps that cannot fit a single transfer are reserved with usable=false so the
    //   UI can explain 'why it wasn't selected' instead of disappearing silently.
    std::vector<DdmaScratchCandidate> planDdmaScratchCandidates(
        std::uint64_t diskSectorCount,
        const std::vector<DdmaScratchOccupiedRange>& occupied,
        std::uint32_t requiredSectors);

    // ddmaScratchRiskIsSelectable：
    // - Input: risk level;
    // - Returns: whether this risk level is selectable as the default automatically. HeadReserved and TailReserved are always false:
    //   The former is where the bootloader resides; the latter would corrupt partition table redundancy. Both must be explicitly selected by the user.
    bool ddmaScratchRiskIsSelectable(DdmaScratchRisk risk);
}
