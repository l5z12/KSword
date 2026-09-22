#pragma once

// ============================================================
// ManualFileSystemParser.h
// Purpose:
// 1) Provides "manual file system parsing" capability, supporting NTFS/FAT32/exFAT;
// 2) Provide a directory entry enumeration interface for direct display in FileDock manual mode.
// 3) Provides NTFS deleted item scanning and data recovery capabilities for resident and complete non-resident data.
// ============================================================

#include "../Framework.h"

#include <QByteArray>
#include <QDateTime>
#include <QString>
#include <QStringList>

#include <cstdint>
#include <functional>
#include <vector>

namespace ks::file
{
    // ManualFsType:
    // - Represents the volume file system type identified by the parser.
    // - Unknown indicates the current path does not support manual parsing.
    enum class ManualFsType : int
    {
        kUnknown = 0,
        kNtfs = 1,
        kFat32 = 2,
        kExFat = 3
    };

    // ManualDirectoryEntry:
    // - Represents a directory entry obtained via manual parsing.
    // - FileDock maps this structure to each row of the table.
    struct ManualDirectoryEntry
    {
        QString name;                      // Entry name (file name or directory name).
        QString absolutePath;              // The absolute path of this entry.
        bool isDirectory = false;          // Whether a directory.
        std::uint64_t sizeBytes = 0;       // File size (directories are typically 0).
        QDateTime modifiedTime;            // Last modified time (empty if invalid).
        QString typeText;                  // Type hint text (directory/file extension).
        std::uint64_t ntfsFileReference = 0; // File reference number in NTFS scenarios (used for recovery).
    };

    // MftScanDiagnostics:
    // - Record the differences between the "pure $MFT view" and the "Windows API view";
    // - The mftOnly set is the core output of this feature: entries visible only through direct $MFT parsing (and
    //   invisible to FindFirstFile or directory indexing) are the typical signature of files hidden by the filter layer.
    // - The winApiOnly set is used for reverse troubleshooting, typically resulting from insufficient scan windows or directory changes during scanning.
    struct MftScanDiagnostics
    {
        bool comparisonAvailable = false;  // Whether the Windows API comparison executed successfully.
        int mftEntryCount = 0;             // Count of entries in the pure MFT view.
        int winApiEntryCount = 0;          // Windows API view entry count.
        QStringList mftOnlyNames;          // Names appearing only in the MFT view.
        QStringList winApiOnlyNames;       // Names that appear only in the Windows API view.
    };

    // NtfsRecoveryCapability:
    // - Clearly distinguish between data types that can be safely exported and metadata that is only locatable.
    // - Non-resident streams are marked recoverable only when the data segment is complete and the volume bitmap confirms they have not been reused.
    enum class NtfsRecoveryCapability : int
    {
        kMetadataOnly = 0,          // Contains only MFT metadata, no usable main data streams.
        kResident = 1,              // The main data stream resides in the MFT record and can be recovered directly.
        kNonResidentIntact = 2,     // Non-resident data segment is intact and all clusters were free during scanning.
        kNonResidentAtRisk = 3,     // Non-resident data cluster has been reused or completeness is unknown; automatic export is prohibited.
        kUnsupportedStream = 4      // Compression, encryption, or multi-segment attribute layouts cannot currently be safely reconstructed.
    };

    // NtfsDeletedFileEntry:
    // - Represents a candidate NTFS deleted file found during scanning.
    // - Save the MFT sequence number and recovery capability required for secondary validation before recovery.
    struct NtfsDeletedFileEntry
    {
        QString fileName;                  // Deleted item file name.
        QString pathHint;                  // Path hint before deletion (best-effort reconstruction).
        std::uint64_t sizeBytes = 0;       // File size (in bytes).
        QDateTime modifiedTime;            // File last modified time.
        std::uint64_t fileReference = 0;   // MFT record number (for secondary lookup).
        std::uint16_t sequenceNumber = 0;  // MFT sequence number (prevents reuse after record deletion).
        int estimatedIntegrityPercent = -1; // Estimated integrity percentage; -1 indicates current evaluation is unavailable.
        bool hasOriginalName = true;       // Whether the original filename is preserved; false indicates only placeholder names can be generated.
        bool residentDataReady = false;    // Whether resident data has been extracted.
        QByteArray residentData;           // Resident data content (may be empty during scan phase; re-read on demand during restore).
        NtfsRecoveryCapability recoveryCapability =
            NtfsRecoveryCapability::kMetadataOnly; // Recovery capability evaluated during scanning.
    };

    // ManualFileSystemParser:
    // - Encapsulates low-level reading and parsing for NTFS/FAT32/exFAT;
    // - Outputs a unified structure externally to prevent the UI layer from directly handling low-level formats.
    class ManualFileSystemParser final
    {
    public:
        // detectFileSystemType:
        // - Identifies the file system type (NTFS/FAT32/exFAT) of the volume containing the path.
        // Call method:
        // - Called when the UI switches directories or changes read modes.
        // Input parameter pathText:
        // - Any local path (e.g., C:\Windows).
        // Return value:
        // - ManualFsType enumeration values.
        static ManualFsType detectFileSystemType(const QString& pathText);

        // enumerateDirectory:
        // - Lists sub-items of the specified directory using 'manual parsing'.
        // Call method:
        // - Called in FileDock manual mode.
        // Input parameter pathText:
        // - Target directory path.
        // Output parameter entriesOut:
        // - Returns the collection of directory entries.
        // Output parameter fsTypeOut:
        // - Returns the file system type actually parsed in this operation.
        // Output parameter errorTextOut:
        // - On failure, return a readable error description.
        // Output parameter usedWinApiFallbackOut:
        // - true indicates that NTFS results have fallen back to or been supplemented by Windows API;
        // - false indicates the result is still entirely from the manual parsing flow.
        // Return value:
        // - Return true on success; return false on failure.
        // Input parameter strictMftOnly:
        // - When true, all Windows API / FSCTL fallbacks and completions are disabled; results must come
        //   entirely from raw `$MFT` bytes. This applies only to NTFS; other file systems ignore this parameter.
        static bool enumerateDirectory(
            const QString& pathText,
            std::vector<ManualDirectoryEntry>& entriesOut,
            ManualFsType& fsTypeOut,
            QString& errorTextOut,
            bool* usedWinApiFallbackOut = nullptr,
            ManualFsType requestedFsType = ManualFsType::kUnknown,
            bool strictMftOnly = false);

        // enumerateDirectoryByMft:
        // - Only use raw $MFT parsing for directories; never pass through the file system driver or Windows APIs.
        //   Directly read $MFT by volume offset; disable FSCTL_GET_NTFS_FILE_RECORD and any WinAPI fallbacks.
        // - Run a Windows API enumeration once more for **comparison** (not merged into results); write the set
        //   difference between the two views to diagnosticsOut for the UI to mark entries suspected of being hidden.
        // Call method:
        // - Called in a background thread after FileDock selects "MFT parsing".
        // Input parameter pathText:
        // - Target directory path on an NTFS volume.
        // Output parameter entriesOut:
        // - Directory entries in a pure MFT view.
        // Output parameter errorTextOut:
        // - Returns the reason on failure; non-NTFS volumes explicitly report unsupported.
        // Output parameter diagnosticsOut:
        // - Optional; receives statistics on differences from the Windows API view.
        // Return value:
        // - Return true on success; return false on failure.
        static bool enumerateDirectoryByMft(
            const QString& pathText,
            std::vector<ManualDirectoryEntry>& entriesOut,
            QString& errorTextOut,
            MftScanDiagnostics* diagnosticsOut = nullptr);

        // enumerateNtfsDeletedFiles:
        // - Scan for 'deleted' file candidates within the specified NTFS volume.
        // Call method:
        // - Called when clicking Scan on the FileDock "File Recovery" page.
        // Input parameter volumeRootPath:
        // - Volume root path (e.g., C:\).
        // Output parameter deletedOut:
        // - Returns the list of candidates for mistakenly deleted files.
        // Output parameter errorTextOut:
        // - Returns the error text on failure.
        // Input parameter progressCallback:
        // - Optional progress callback; percent range is agreed to be 0~100.
        // - stageText: Used to display the current stage description to the UI.
        // Return value:
        // - Return true on success; return false on failure.
        static bool enumerateNtfsDeletedFiles(
            const QString& volumeRootPath,
            std::vector<NtfsDeletedFileEntry>& deletedOut,
            QString& errorTextOut,
            const std::function<void(int, const QString&)>& progressCallback = {});

        // recoverNtfsDeletedFile:
        // - Perform safe recovery for a single mistakenly deleted item.
        // - Supports resident data, as well as complete non-resident data where both pre- and post-volume bitmap checks pass.
        // Call method:
        // - Invoked after selecting a row on the FileDock "File Recovery" page.
        // Input parameter volumeRootPath:
        // - Volume root path (e.g., C:\), used for logging and path ownership validation.
        // Input parameter deletedEntry:
        // - Entry to be recovered; the function re-reads the MFT by record number and sequence number, ignoring old scan snapshots.
        // Input parameter targetFilePath:
        // - The target file path for export.
        // Output parameter errorTextOut:
        // - Returns the reason text on failure.
        // Input parameter progressCallback:
        // - Optional recovery progress callback; percent range is 0~100.
        // Return value:
        // - Return true on success; return false on failure.
        static bool recoverNtfsDeletedFile(
            const QString& volumeRootPath,
            const NtfsDeletedFileEntry& deletedEntry,
            const QString& targetFilePath,
            QString& errorTextOut,
            const std::function<void(int, const QString&)>& progressCallback = {});

        // recoverNtfsResidentFile:
        // - Wrapper entry for backward compatibility with old callers; internally delegates to recoverNtfsDeletedFile.
        static bool recoverNtfsResidentFile(
            const QString& volumeRootPath,
            const NtfsDeletedFileEntry& deletedEntry,
            const QString& targetFilePath,
            QString& errorTextOut);
    };
}
