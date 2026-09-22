#pragma once

// ============================================================
// DiskStructureParser.h
// Purpose:
// 1) Parse the disk's front structure, including MBR, GPT Header, GPT Entry, and common boot sectors;
// 2) Provide entry points for volume mapping and device health information collection;
// 3) Perform read-only analysis only; no disk write operations are executed.
// ============================================================

#include "DiskAdvancedModels.h"
#include "DiskEditorModels.h"

#include <QString>

namespace ks::misc
{
    // DiskStructureParser:
    // - Input: DiskDeviceInfo and optional leading sector bytes;
    // - Processing logic: Parse structure fields according to public disk formats and perform lightweight consistency checks.
    // - Return behavior: Returns fields via DiskStructureReport, volume mappings, health probes, and alerts.
    class DiskStructureParser final
    {
    public:
        // buildReport：
        // - disk is the current disk snapshot;
        // - leadingBytes: the leading bytes read from offset 0 of the disk; at least 1 MiB is recommended.
        // - errorTextOut returns a fatal failure description;
        // - Returns a complete structure report.
        static DiskStructureReport buildReport(
            const DiskDeviceInfo& disk,
            const QByteArray& leadingBytes,
            QString& errorTextOut);

        // collectVolumeMapping：
        // - Enumerates Windows volumes and matches them to the specified physical disk.
        // - diskIndex is N in PhysicalDriveN;
        // - errorTextOut returns non-fatal diagnostics
        // - Returns the list of matched volume extents.
        static std::vector<DiskVolumeInfo> collectVolumeMapping(
            int diskIndex,
            QString& errorTextOut);

        // collectHealthItems：
        // - Query read-only status such as device capabilities, cache, TRIM, and SMART/NVMe availability.
        // - disk is the current disk snapshot;
        // - errorTextOut returns non-fatal diagnostics
        // - Returns health and capability items.
        static std::vector<DiskHealthItem> collectHealthItems(
            const DiskDeviceInfo& disk,
            QString& errorTextOut);
    };
}
