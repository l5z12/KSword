#pragma once

// ============================================================
// DiskEditorModels.h
// Purpose:
// 1) Define disk, partition, and display models used by the Miscellaneous Dock 'Disk Editor' page.
// 2) Enable the Win32 collection layer, bar chart control, and page UI to share a single lightweight data contract.
// 3) Avoid directly exposing Windows structures in UI files to reduce coupling when integrating driver capabilities later.
// ============================================================

#include <QColor>
#include <QString>

#include <cstdint>
#include <vector>

namespace ks::misc
{
    // DiskPartitionStyle:
    // - Unifies the description of disk or partition table styles;
    // - The UI layer recognizes only this enum and does not directly depend on Win32 PARTITION_STYLE.
    enum class DiskPartitionStyle : int
    {
        kUnknown = 0,
        kRaw,
        kMbr,
        kGpt
    };

    // DiskPartitionKind:
    // - Provide semantic color classification for the bar chart of disk.
    // - Not an exact file system type; serves only for 'first-glance identification'.
    enum class DiskPartitionKind : int
    {
        kUnknown = 0,
        kBasicData,
        kSystem,
        kReserved,
        kRecovery,
        kLinux,
        kUnallocated
    };

    // DiskPartitionInfo:
    // - Describe a partition on a physical disk.
    // - offsetBytes and lengthBytes are both absolute byte offsets on the physical disk.
    struct DiskPartitionInfo
    {
        int tableIndex = -1;                         // tableIndex: Zero-based index used by the UI table and bar chart.
        int partitionNumber = 0;                     // partitionNumber: Windows partition number; 0 indicates unallocated space.
        DiskPartitionStyle style = DiskPartitionStyle::kUnknown; // style: Partition style source.
        DiskPartitionKind kind = DiskPartitionKind::kUnknown;    // kind: semantic classification for display.
        QString name;                                // name: GPT name or UI-generated name.
        QString typeText;                            // typeText: MBR or GPT type description.
        QString uniqueIdText;                        // uniqueIdText: GPT PartitionId or MBR signature-related text.
        QString volumeHint;                          // volumeHint: Hit drive letter/volume mount hint; may be null.
        QString flagsText;                           // flagsText: Short markers for boot, hidden, attributes, etc.
        std::uint64_t offsetBytes = 0;               // offsetBytes: Partition start byte offset.
        std::uint64_t lengthBytes = 0;               // lengthBytes: Partition length in bytes.
        bool bootIndicator = false;                  // bootIndicator: MBR active partition flag.
        bool recognized = false;                     // recognized: Whether Windows recognizes this partition.
        QColor color;                                // color: bar chart fill color.
    };

    // DiskDeviceInfo:
    // - Describe a PhysicalDrive device and its partition table snapshot;
    // - Retains openErrorText even on enumeration failure to allow the UI to provide diagnostics.
    struct DiskDeviceInfo
    {
        int diskIndex = -1;                          // diskIndex: The N in PhysicalDriveN.
        QString devicePath;                          // devicePath: Format like \\.\PhysicalDrive0.
        QString displayName;                         // displayName: Combined friendly name.
        QString vendor;                              // vendor: storage device manufacturer.
        QString model;                               // model: Product model.
        QString serial;                              // serial: Serial number; the driver may return null.
        QString busType;                             // busType: Bus type hints such as SATA/NVMe/USB.
        QString mediaType;                           // mediaType: Fixed disk, removable disk, etc.
        QString openErrorText;                       // openErrorText: Open failure diagnosis.
        DiskPartitionStyle partitionStyle = DiskPartitionStyle::kUnknown; // partitionStyle: disk partition table type.
        std::uint64_t sizeBytes = 0;                 // sizeBytes: Total disk capacity.
        std::uint32_t bytesPerSector = 512;          // bytesPerSector: Logical sector size.
        std::uint32_t physicalBytesPerSector = 0;    // physicalBytesPerSector: Physical sector size; 0 if unknown.
        bool canRead = false;                        // canRead: Whether opened with read permissions successfully during enumeration.
        bool removable = false;                      // removable: Whether the device reports as removable media.
        std::uint32_t rawBackendMask = 0;             // rawBackendMask: R0 three-layer disk access backend available bits.
        std::uint32_t rawCapabilityFlags = 0;         // rawCapabilityFlags: System disk, offline, bus, and read/write capability bits.
        QString rawBackendDetail;                     // rawBackendDetail: R0 backend pre-check summary or compatibility fallback reason.
        std::vector<DiskPartitionInfo> partitions;   // partitions: List of valid partitions, excluding empty slots.
    };
}
