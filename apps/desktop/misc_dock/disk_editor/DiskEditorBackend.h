#pragma once

// ============================================================
// DiskEditorBackend.h
// Purpose:
// 1) Encapsulates disk enumeration, partition layout reading, sector reading, and sector write-back.
// 2) Prevent DiskEditorTab from directly scattering CreateFile/DeviceIoControl calls;
// 3) If switching to KswordARK driver read/write is needed later, this file's implementation can be centrally replaced.
// ============================================================

#include "DiskEditorModels.h"

#include <QByteArray>
#include <QString>
#include <QVariantMap>

#include <cstdint>
#include <vector>

namespace ks::misc
{
    // DiskEditorBackend:
    // - Input: Physical disk path, offset, length, and byte buffer;
    // - Handling logic: use Win32 APIs to read the layout and specified range.
    // - Return behavior: All failures are reported via bool=false and errorTextOut.
    class DiskEditorBackend final
    {
    public:
        // enumerateDisks：
        // - Enumerates PhysicalDrive0..N and supplements partition layout information;
        // - disksOut receives the disk snapshot;
        // - errorTextOut provides diagnostics on complete failure;
        // - Returns true if at least one disk was successfully enumerated or an error disk item is available for display.
        static bool enumerateDisks(
            std::vector<DiskDeviceInfo>& disksOut,
            QString& errorTextOut);

        // readBytes：
        // - Read bytes from a physical disk at the specified offset.
        // - devicePath is \\.\PhysicalDriveN;
        // - offsetBytes is the absolute byte offset.
        // - bytesToRead is the read length;
        // - bytesOut receives the read result;
        // - errorTextOut returns the failure reason.
        // - Returns true if the read was successful.
        static bool readBytes(
            const QString& devicePath,
            std::uint64_t offsetBytes,
            std::uint32_t bytesToRead,
            QByteArray& bytesOut,
            QString& errorTextOut);

        // readBytesWithBackend：
        // - Purpose: Use the selected R0 disk backend for reading; `backend` corresponds to the three-layer protocol value.
        // - Backend 1 allows falling back to the existing Windows storage stack when the old driver is unavailable;
        // Backends 2 and 3 never implicitly downgrade, ensuring the access layer seen by users matches reality.
        static bool readBytesWithBackend(
            int diskIndex,
            unsigned long backend,
            std::uint64_t offsetBytes,
            std::uint32_t bytesToRead,
            QByteArray& bytesOut,
            QString& errorTextOut);

        // writeBytes：
        // - Write bytes to a specified offset on the physical disk;
        // - When requireSectorAligned is true, forces both offset and length to be sector-aligned.
        // - bytesPerSector is the logical sector size.
        // - errorTextOut returns the failure reason.
        // - Returns true if the write was successful.
        static bool writeBytes(
            const QString& devicePath,
            std::uint64_t offsetBytes,
            const QByteArray& bytes,
            std::uint32_t bytesPerSector,
            bool requireSectorAligned,
            QString& errorTextOut);

        // writeBytesWithBackend：
        // - Writes to the selected backend via ArkDriverClient.
        // - callerFlags must come from a completed UI risk confirmation.
        // - All backends enforce R0 security policies, system disk checks, and sector boundary validation.
        static bool writeBytesWithBackend(
            int diskIndex,
            unsigned long backend,
            std::uint64_t offsetBytes,
            const QByteArray& bytes,
            unsigned long callerFlags,
            QString& errorTextOut);

        // queryVolumeMappings：
        // - Enumerates Windows volumes and matches them to the current disk using extents;
        // - diskIndex is N in PhysicalDriveN;
        // - Return value uses QVariantMap to avoid dependency of the basic backend on advanced UI models.
        // - errorTextOut returns non-fatal diagnostics
        static std::vector<QVariantMap> queryVolumeMappings(
            int diskIndex,
            QString& errorTextOut);

        // queryHealthItems：
        // - Query device basic capabilities, cache, TRIM, SMART/NVMe availability, and other read-only information;
        // - devicePath is the physical disk path;
        // - Return value uses QVariantMap; keys include category, name, value, detail, and severity.
        // - errorTextOut returns non-fatal diagnostics
        static std::vector<QVariantMap> queryHealthItems(
            const QString& devicePath,
            QString& errorTextOut);

        // formatBytes：
        // - Format byte count into user-readable capacity;
        // - bytes is the raw byte count;
        // - Returns capacity text.
        static QString formatBytes(std::uint64_t bytes);

        // partitionStyleText：
        // - Converts DiskPartitionStyle to UI text.
        // - style: style enum
        // - Returns RAW/MBR/GPT/Unknown.
        static QString partitionStyleText(DiskPartitionStyle style);
    };
}
