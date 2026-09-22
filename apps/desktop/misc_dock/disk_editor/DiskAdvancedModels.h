#pragma once

// ============================================================
// DiskAdvancedModels.h
// Purpose:
// 1) Define shared models for advanced disk analysis, volume mapping, health information, search, and imaging tasks;
// 2) Allow the parser, Win32 capability detection, and UI table to share the same lightweight structure;
// 3) All fields remain Qt basic types to avoid leaking Win32 structures to the UI layer.
// ============================================================

#include "DiskEditorModels.h"

#include <QByteArray>
#include <QString>
#include <QStringList>

#include <cstdint>
#include <vector>

namespace ks::misc
{
    // DiskStructureSeverity:
    // - Mark severity for structure parsing, health detection, and tool tasks.
    // - UI can use this to color or sort rows.
    enum class DiskStructureSeverity : int
    {
        kInfo = 0,
        kWarning,
        kError
    };

    // DiskStructureField:
    // - Represents a locatable disk structure field.
    // - offsetBytes/sizeBytes use absolute physical disk offsets to facilitate double-click jumps to HEX.
    struct DiskStructureField
    {
        QString group;                                // group: Groups such as MBR, GPT Header, Boot Sector, etc.
        QString name;                                 // name: Field name.
        QString value;                                // value: Parsed field value.
        QString detail;                               // detail: Validation description or risk warning.
        std::uint64_t offsetBytes = 0;                // offsetBytes: Field start absolute offset.
        std::uint32_t sizeBytes = 0;                  // sizeBytes: Field length; 0 if unknown.
        DiskStructureSeverity severity = DiskStructureSeverity::kInfo; // severity: Field severity.
    };

    // DiskVolumeInfo:
    // - Describes the mapping relationship between Windows volumes and physical disk partitions.
    // - A volume can have multiple extents; multi-extent volumes generate multiple records.
    struct DiskVolumeInfo
    {
        QString volumeName;                           // volumeName: In the format \\?\Volume{GUID}\.
        QString mountPoints;                          // mountPoints: List of drive letters or mount points.
        QString devicePath;                           // devicePath: Kernel device path, e.g., \Device\HarddiskVolumeX.
        QString fileSystem;                           // fileSystem: NTFS/FAT32/exFAT/ReFS, etc.
        QString label;                                // label: Volume label.
        int diskNumber = -1;                          // diskNumber: N in PhysicalDriveN.
        std::uint64_t offsetBytes = 0;                // offsetBytes: Starting offset of this extent on the physical disk.
        std::uint64_t lengthBytes = 0;                // lengthBytes: Length of this extent.
    };

    // DiskHealthItem:
    // - Stores the result of a single device capability or health status query;
    // - Display failed items as Warning/Error rows to avoid users mistakenly assuming no detection occurred.
    struct DiskHealthItem
    {
        QString category;                             // category: Categories such as capabilities, cache, SMART, and hot-plug.
        QString name;                                 // name: Project name.
        QString value;                                // value: detected value.
        QString detail;                               // detail: supplementary explanation or Win32 error code.
        DiskStructureSeverity severity = DiskStructureSeverity::kInfo; // severity: Display severity.
    };

    // DiskStructureReport:
    // - Aggregate all content obtained from a single refresh of the advanced analysis page;
    // - fields, volumes, and healthItems correspond to the three tables respectively.
    struct DiskStructureReport
    {
        std::vector<DiskStructureField> fields;       // fields: MBR/GPT/boot sector fields.
        std::vector<DiskVolumeInfo> volumes;          // volumes: volume mapping results.
        std::vector<DiskHealthItem> healthItems;      // healthItems: Device capabilities and health detection results.
        QStringList warnings;                         // warnings: Overall level alerts.
    };

    // DiskSearchResult:
    // - Describe the absolute offset of a byte search hit and the nearby preview.
    // - preview stores a small number of bytes; the UI displays them in a mixed HEX/ASCII format.
    struct DiskSearchResult
    {
        std::uint64_t offsetBytes = 0;                // offsetBytes: Absolute byte offset of the hit.
        QByteArray preview;                           // preview: Bytes window hit.
    };

    // DiskRangeTaskResult:
    // - Unify the completion result representation for search, hash, export, import, and read-scan tasks;
    // - Have the background thread return only a single structure to reduce UI state branches.
    struct DiskRangeTaskResult
    {
        bool success = false;                         // success: Whether the task completed successfully.
        QString summary;                              // summary: Brief summary for the status bar.
        QString errorText;                            // errorText: Reason for failure; empty on success.
        QStringList detailLines;                      // detailLines: Log or diagnostic details.
        std::vector<DiskSearchResult> searchResults;  // searchResults: list of search hits.
        QByteArray digestBytes;                       // digestBytes: Original digest of the hash task.
        double mibPerSecond = 0.0;                    // mibPerSecond: Throughput estimate for read scans/exports, etc.
        std::uint64_t bytesProcessed = 0;             // bytesProcessed: Actual number of bytes processed.
        int failureCount = 0;                         // failureCount: Number of blocks failed during read scan.
    };
}
